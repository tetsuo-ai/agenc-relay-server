#![forbid(unsafe_code)]

//! The four-phase shutdown driver and the supervisor tree (spec 21.2 lines
//! 4064-4069, spec 21.8 lines 4254-4267): budgets, the second-signal skip,
//! reload signals that do not interrupt a phase, critical versus connection
//! exits, panic containment, and churn without leaked children.

use std::error::Error;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agenc_ircd_runtime::RuntimeError;
use agenc_ircd_runtime::state_core::inbox::SignalEvent;
use agenc_ircd_runtime::supervisor::{
    ChildFailure, ChildKind, ChildName, PhaseOutcome, ShutdownFailure, ShutdownHooks,
    ShutdownPhase, ShutdownPlan, ShutdownProblem, ShutdownProblemKind, Supervisor, run_shutdown,
};
use tokio::sync::mpsc;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

struct RecordingHooks {
    phases: Arc<Mutex<Vec<ShutdownPhase>>>,
    delay: Option<(ShutdownPhase, Duration)>,
    release: Option<(ShutdownPhase, mpsc::Sender<()>)>,
    failure: Option<(ShutdownPhase, ShutdownFailure)>,
}

impl ShutdownHooks for RecordingHooks {
    fn run(
        &mut self,
        phase: ShutdownPhase,
    ) -> impl Future<Output = Result<(), ShutdownFailure>> + Send {
        let phases = Arc::clone(&self.phases);
        let delay = self
            .delay
            .filter(|(slow, _)| *slow == phase)
            .map(|(_, delay)| delay);
        let release = self
            .release
            .as_ref()
            .filter(|(gated, _)| *gated == phase)
            .map(|(_, sender)| sender.clone());
        let failure = self
            .failure
            .filter(|(failed, _)| *failed == phase)
            .map(|(_, failure)| failure);
        async move {
            if let Ok(mut recorded) = phases.lock() {
                recorded.push(phase);
            }
            if let Some(sender) = release {
                let _ = sender.send(()).await;
            }
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            failure.map_or(Ok(()), Err)
        }
    }
}

fn hooks() -> (RecordingHooks, Arc<Mutex<Vec<ShutdownPhase>>>) {
    let phases = Arc::new(Mutex::new(Vec::new()));
    (
        RecordingHooks {
            phases: Arc::clone(&phases),
            delay: None,
            release: None,
            failure: None,
        },
        phases,
    )
}

fn recorded(phases: &Arc<Mutex<Vec<ShutdownPhase>>>) -> Vec<ShutdownPhase> {
    phases
        .lock()
        .map(|phases| phases.clone())
        .unwrap_or_default()
}

#[tokio::test]
async fn every_phase_completes_in_order_within_its_budget() -> TestResult {
    let (mut hooks, phases) = hooks();
    let (_signals, mut receiver) = mpsc::channel(4);
    let report = run_shutdown(ShutdownPlan::DEFAULT, &mut hooks, &mut receiver).await;
    assert_eq!(recorded(&phases), ShutdownPhase::ALL.to_vec());
    for phase in ShutdownPhase::ALL {
        assert_eq!(report.outcome(phase), PhaseOutcome::Completed);
    }
    assert!(!report.interrupted());
    assert_eq!(report.first_problem(), None);
    Ok(())
}

#[tokio::test]
async fn a_phase_over_budget_times_out_and_the_rest_still_run() -> TestResult {
    let (mut hooks, phases) = hooks();
    hooks.delay = Some((ShutdownPhase::Drain, Duration::from_secs(5)));
    let plan = ShutdownPlan::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )?;
    let (_signals, mut receiver) = mpsc::channel(4);
    let started = tokio::time::Instant::now();
    let report = run_shutdown(plan, &mut hooks, &mut receiver).await;
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(
        report.outcome(ShutdownPhase::Quiesce),
        PhaseOutcome::Completed
    );
    assert_eq!(report.outcome(ShutdownPhase::Drain), PhaseOutcome::TimedOut);
    assert_eq!(
        report.outcome(ShutdownPhase::Flush),
        PhaseOutcome::Completed
    );
    assert_eq!(report.outcome(ShutdownPhase::Stop), PhaseOutcome::Completed);
    assert_eq!(recorded(&phases), ShutdownPhase::ALL.to_vec());
    assert!(!report.interrupted());
    assert_eq!(
        report.first_problem(),
        Some(ShutdownProblem {
            phase: ShutdownPhase::Drain,
            kind: ShutdownProblemKind::TimedOut,
        })
    );
    Ok(())
}

#[tokio::test]
async fn the_first_hook_failure_is_retained_while_later_phases_still_run() -> TestResult {
    let (mut hooks, phases) = hooks();
    hooks.failure = Some((ShutdownPhase::Drain, ShutdownFailure::Storage));
    let (_signals, mut receiver) = mpsc::channel(4);
    let report = run_shutdown(ShutdownPlan::DEFAULT, &mut hooks, &mut receiver).await;
    assert_eq!(recorded(&phases), ShutdownPhase::ALL.to_vec());
    assert_eq!(
        report.outcome(ShutdownPhase::Drain),
        PhaseOutcome::Failed(ShutdownFailure::Storage)
    );
    assert_eq!(
        report.first_problem(),
        Some(ShutdownProblem {
            phase: ShutdownPhase::Drain,
            kind: ShutdownProblemKind::Failed(ShutdownFailure::Storage),
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_second_termination_signal_skips_to_stop() -> TestResult {
    let (mut hooks, phases) = hooks();
    let (entered, mut entered_receiver) = mpsc::channel(1);
    hooks.release = Some((ShutdownPhase::Drain, entered));
    hooks.delay = Some((ShutdownPhase::Drain, Duration::from_secs(30)));
    let (signals, mut receiver) = mpsc::channel(4);
    let driver = tokio::spawn(async move {
        run_shutdown(ShutdownPlan::DEFAULT, &mut hooks, &mut receiver).await
    });
    entered_receiver.recv().await.ok_or("drain never started")?;
    signals.send(SignalEvent::Reload).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !driver.is_finished(),
        "a reload signal does not interrupt a phase"
    );
    signals.send(SignalEvent::Interrupt).await?;
    let report = tokio::time::timeout(Duration::from_secs(5), driver).await??;
    assert_eq!(
        report.outcome(ShutdownPhase::Quiesce),
        PhaseOutcome::Completed
    );
    assert_eq!(report.outcome(ShutdownPhase::Drain), PhaseOutcome::Skipped);
    assert_eq!(report.outcome(ShutdownPhase::Flush), PhaseOutcome::Skipped);
    assert_eq!(report.outcome(ShutdownPhase::Stop), PhaseOutcome::Completed);
    assert!(report.interrupted());
    assert_eq!(
        recorded(&phases),
        vec![
            ShutdownPhase::Quiesce,
            ShutdownPhase::Drain,
            ShutdownPhase::Stop
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_closed_signal_channel_does_not_stall_the_driver() -> TestResult {
    let (mut hooks, _) = hooks();
    let (signals, mut receiver) = mpsc::channel::<SignalEvent>(1);
    drop(signals);
    let report = run_shutdown(ShutdownPlan::DEFAULT, &mut hooks, &mut receiver).await;
    assert!(!report.interrupted());
    Ok(())
}

#[tokio::test]
async fn a_panicking_child_is_contained_and_cancels_the_tree_when_critical() -> TestResult {
    let mut supervisor = Supervisor::new();
    let root = supervisor.root_token();
    let survivor = supervisor.spawn(
        ChildName::MaintenanceTask,
        ChildKind::Critical,
        |token| async move {
            token.cancelled().await;
            Ok(())
        },
    )?;
    supervisor.spawn(ChildName::StateCoreTask, ChildKind::Critical, |_| async {
        let boom: Option<()> = None;
        boom.ok_or(RuntimeError::InvalidValue)?;
        let _ = std::panic::catch_unwind(|| ());
        Ok(())
    })?;
    supervisor.spawn(ChildName::Connection, ChildKind::Connection, |_| async {
        tokio::task::spawn(async {
            // Division by zero is a defined panic in every build profile; it
            // stands in for a bug inside a supervised task.
            let zero = std::hint::black_box(0_u32);
            let _ = std::hint::black_box(1_u32 / zero);
        })
        .await
        .map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    })?;
    let mut exits = Vec::new();
    while let Some(exit) = supervisor.next_exit().await {
        exits.push(exit);
    }
    assert!(root.is_cancelled());
    assert!(survivor.is_cancelled());
    assert!(
        exits
            .iter()
            .any(|exit| exit.name == ChildName::StateCoreTask
                && exit.outcome == Err(ChildFailure::Failed(RuntimeError::InvalidValue)))
    );
    assert!(exits.iter().any(|exit| exit.name == ChildName::Connection
        && exit.outcome == Err(ChildFailure::Failed(RuntimeError::Cancelled))));
    assert!(
        exits
            .iter()
            .any(|exit| exit.name == ChildName::MaintenanceTask && exit.outcome == Ok(()))
    );
    Ok(())
}

#[tokio::test]
async fn connection_children_churn_without_leaking_registrations() -> TestResult {
    let mut supervisor = Supervisor::new();
    let root = supervisor.root_token();
    for _ in 0..200 {
        supervisor.spawn(
            ChildName::Connection,
            ChildKind::Connection,
            |token| async move {
                tokio::task::yield_now().await;
                drop(token);
                Ok(())
            },
        )?;
    }
    let report = supervisor.join_all(Duration::from_secs(10)).await;
    assert_eq!(report.exits.len(), 200);
    assert_eq!(report.unfinished, 0);
    assert_eq!(supervisor.live_children(), 0);
    assert!(!root.is_cancelled());
    assert_eq!(root.live_children(), 0, "every child token was dropped");
    Ok(())
}
