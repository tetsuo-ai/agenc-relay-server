//! The running actor: cancellation, quiescence, lifecycle ordering and the
//! reload activation barrier.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use super::support::{account_plan, empty_fanout};
use super::*;
use crate::runtime_config::{
    PreparedReload, ReloadOutcome, ReloadPort, ReloadRejection, RuntimeConfigHandle,
};
use crate::state_core::inbox::LifecycleFailure;
use crate::state_core::{CommandObservation, CommandRouter, RouteOutcome, StateCoreContext};
use crate::test_support::{golden_config, golden_parts, golden_snapshot};

fn varied_entropy() -> Vec<u8> {
    (0_u32..65_536)
        .map(|index| u8::try_from((index * 7 + 3) % 256).unwrap_or_default())
        .collect()
}

struct Controls {
    inbox: mpsc::Sender<StateCoreMessage>,
    lifecycle: LifecycleControl,
    token: CancellationToken,
}

/// Runs `fixture` under a root token the driver may cancel and hands the
/// stopped core back for inspection.
async fn run_fixture<Driver, Output>(
    fixture: &mut StateCoreFixture,
    driver: impl FnOnce(Controls) -> Driver,
) -> TestResult<(StateCoreExit, Output, crate::state_core::StateCore)>
where
    Driver: Future<Output = TestResult<Output>>,
{
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let token = CancellationToken::root();
    let driven = driver(Controls {
        inbox,
        lifecycle,
        token: token.clone(),
    });
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        token,
    );
    let (exit, output) = tokio::join!(run, driven);
    Ok((exit, output?, parts.state))
}

#[tokio::test]
async fn cancellation_waits_for_the_gathering_batch_to_become_durable() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(varied_entropy())?;
    let context = fixture.context_mut()?;
    let plan = account_plan(context, 7)?;
    context
        .stage_durable(plan, empty_fanout()?, None, 0)
        .map_err(|refused| format!("{refused:?}"))?;
    let (exit, _inbox, state) = run_fixture(&mut fixture, |controls| async move {
        controls.token.cancel();
        Ok(controls.inbox)
    })
    .await?;
    assert!(matches!(exit, StateCoreExit::Cancelled), "{exit:?}");
    assert!(
        state
            .context
            .domain()
            .account(agenc_ircd_testkit::account_id(7))
            .is_some(),
        "the staged account committed before the core stopped"
    );
    assert_eq!(state.context.counters.batches_committed, 1);
    assert_eq!(state.context.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn an_idle_core_stops_at_once_when_cancelled() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let (exit, _inbox, state) = run_fixture(&mut fixture, |controls| async move {
        controls.token.cancel();
        Ok(controls.inbox)
    })
    .await?;
    assert!(matches!(exit, StateCoreExit::Cancelled), "{exit:?}");
    assert!(state.context.quiescing);
    Ok(())
}

#[tokio::test]
async fn a_connection_opened_after_quiescence_is_never_acknowledged() -> TestResult {
    let (exit, (_inbox, acknowledged)) = run_core(false, |inbox, lifecycle, _token| async move {
        lifecycle
            .request(LifecyclePhase::Quiesce)
            .await
            .map_err(|_| "quiesce")?;
        let (acknowledgement, accepted) = oneshot::channel();
        send(
            &inbox,
            StateCoreMessage::Opened {
                generation: ConnectionGeneration::new(1),
                purpose: ListenerPurpose::ClientOnion,
                source: SourceAddressKey::onion_listener(),
                sink: FrameSink::new(ConnectionGeneration::new(1), true),
                acknowledgement,
            },
        )
        .await?;
        let acknowledged = accepted.await.is_ok();
        lifecycle
            .request(LifecyclePhase::Stop)
            .await
            .map_err(|_| "stop")?;
        Ok((inbox, acknowledged))
    })
    .await?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    assert!(!acknowledged, "a quiescing core admits no connection");
    Ok(())
}

#[tokio::test]
async fn a_repeated_flush_is_busy_while_the_first_waits_and_stop_supersedes_it() -> TestResult {
    let (exit, (_inbox, replies)) = run_core(false, |inbox, lifecycle, _token| async move {
        let sinks = [FrameSink::new(ConnectionGeneration::new(1), true)];
        open_connections(&inbox, &sinks).await?;
        let drained = lifecycle.request(LifecyclePhase::Drain).await;
        let mut flushing = Box::pin(lifecycle.request(LifecyclePhase::Flush));
        let early = tokio::time::timeout(Duration::from_millis(100), &mut flushing).await;
        let repeated = lifecycle.request(LifecyclePhase::Flush).await;
        let earlier_phase = lifecycle.request(LifecyclePhase::Drain).await;
        let stopped = lifecycle.request(LifecyclePhase::Stop).await;
        let superseded = flushing.await;
        Ok((
            inbox,
            (
                drained,
                early.is_err(),
                repeated,
                earlier_phase,
                stopped,
                superseded,
            ),
        ))
    })
    .await?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    assert_eq!(
        replies,
        (
            Ok(()),
            true,
            Err(LifecycleFailure::Busy),
            Ok(()),
            Ok(()),
            Err(LifecycleFailure::Superseded),
        )
    );
    Ok(())
}

/// A router that reports itself unready for reloads until told otherwise and
/// declines to begin its shutdown a fixed number of times.
struct GateRouter {
    reload_ready: Arc<AtomicBool>,
    shutdown_refusals: usize,
    shutdown_calls: Arc<AtomicUsize>,
}

impl CommandRouter for GateRouter {
    fn route(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: agenc_ircd_client_wire::ParsedMessage,
        observation: CommandObservation,
    ) -> RouteOutcome {
        crate::state_core::DefaultRouter.route(context, generation, message, observation)
    }

    fn begin_shutdown(&mut self, _context: &mut StateCoreContext) -> bool {
        let calls = self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        calls >= self.shutdown_refusals
    }

    fn reload_ready(&self) -> bool {
        self.reload_ready.load(Ordering::SeqCst)
    }
}

struct Gate {
    fixture: StateCoreFixture,
    handle: RuntimeConfigHandle,
    port: ReloadPort,
    reload_ready: Arc<AtomicBool>,
    shutdown_calls: Arc<AtomicUsize>,
    _federation: mpsc::Sender<crate::federation::FederationInbound>,
}

fn gated(reload_ready: bool, shutdown_refusals: usize) -> TestResult<Gate> {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let handle = RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?);
    let (port, _admission) = fixture.install_reload_port(handle.clone())?;
    let reload_ready = Arc::new(AtomicBool::new(reload_ready));
    let shutdown_calls = Arc::new(AtomicUsize::new(0));
    let (federation, federation_inbox) = mpsc::channel(1);
    let state = fixture.state_mut()?;
    state.install_federation_inbox(federation_inbox)?;
    state.router = Box::new(GateRouter {
        reload_ready: Arc::clone(&reload_ready),
        shutdown_refusals,
        shutdown_calls: Arc::clone(&shutdown_calls),
    });
    Ok(Gate {
        fixture,
        handle,
        port,
        reload_ready,
        shutdown_calls,
        _federation: federation,
    })
}

fn motd_reload(handle: &RuntimeConfigHandle, motd: &str) -> TestResult<PreparedReload> {
    let mut prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some(motd))?,
    )?;
    if let Ok(lease) = handle.begin_reload() {
        prepared.attach_lease(lease);
    }
    Ok(prepared)
}

/// Opens the router's reload gate and wakes the actor with a request the
/// pending activation answers as busy.
async fn open_gate(gate_ready: &AtomicBool, port: &ReloadPort, nudge: PreparedReload) -> bool {
    gate_ready.store(true, Ordering::SeqCst);
    port.activate_signal(nudge).await == ReloadOutcome::Rejected(ReloadRejection::Busy)
}

#[tokio::test]
async fn a_pending_reload_holds_client_input_until_the_router_is_ready() -> TestResult {
    let Gate {
        mut fixture,
        handle,
        port,
        reload_ready,
        ..
    } = gated(false, 0)?;
    let first = motd_reload(&handle, "Held")?;
    let nudge = motd_reload(&handle, "Nudge")?;
    let (exit, (_inbox, held, nudged, outcome, opened), _state) =
        run_fixture(&mut fixture, |controls| async move {
            let activation = port.activate_signal(first);
            let script = async {
                let (acknowledgement, mut accepted) = oneshot::channel();
                send(
                    &controls.inbox,
                    StateCoreMessage::Opened {
                        generation: ConnectionGeneration::new(1),
                        purpose: ListenerPurpose::ClientOnion,
                        source: SourceAddressKey::onion_listener(),
                        sink: FrameSink::new(ConnectionGeneration::new(1), true),
                        acknowledgement,
                    },
                )
                .await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
                let held = accepted.try_recv().is_err();
                let nudged = open_gate(&reload_ready, &port, nudge).await;
                let opened = tokio::time::timeout(Duration::from_secs(5), accepted).await??;
                TestResult::Ok((held, nudged, opened))
            };
            let (outcome, script) = tokio::join!(activation, script);
            let (held, nudged, opened) = script?;
            controls
                .lifecycle
                .request(LifecyclePhase::Stop)
                .await
                .map_err(|_| "stop")?;
            Ok((controls.inbox, held, nudged, outcome, opened))
        })
        .await?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    assert!(held, "the open waited behind the activation barrier");
    assert!(nudged, "a second activation is busy behind the first");
    assert!(matches!(outcome, ReloadOutcome::Applied(_)), "{outcome:?}");
    assert!(matches!(opened, ConnectionOpenOutcome::Accepted));
    assert_eq!(handle.load().motd_arc().as_deref(), Some("Held"));
    Ok(())
}

#[tokio::test]
async fn drain_waits_for_a_pending_reload_to_activate_first() -> TestResult {
    let Gate {
        mut fixture,
        handle,
        port,
        reload_ready,
        shutdown_calls,
        ..
    } = gated(false, 0)?;
    let first = motd_reload(&handle, "BeforeDrain")?;
    let nudge = motd_reload(&handle, "Nudge")?;
    let calls = Arc::clone(&shutdown_calls);
    let (exit, (_inbox, outcome, waited, drained), _state) =
        run_fixture(&mut fixture, |controls| async move {
            let activation = port.activate_signal(first);
            let script = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let mut draining = Box::pin(controls.lifecycle.request(LifecyclePhase::Drain));
                let early = tokio::time::timeout(Duration::from_millis(100), &mut draining).await;
                let waited = early.is_err() && calls.load(Ordering::SeqCst) == 0;
                let _nudged = open_gate(&reload_ready, &port, nudge).await;
                let drained = tokio::time::timeout(Duration::from_secs(5), draining).await?;
                TestResult::Ok((waited, drained))
            };
            let (outcome, script) = tokio::join!(activation, script);
            let (waited, drained) = script?;
            controls
                .lifecycle
                .request(LifecyclePhase::Stop)
                .await
                .map_err(|_| "stop")?;
            Ok((controls.inbox, outcome, waited, drained))
        })
        .await?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    assert!(
        waited,
        "neither drain nor router shutdown passed the barrier"
    );
    assert!(matches!(outcome, ReloadOutcome::Applied(_)), "{outcome:?}");
    assert_eq!(drained, Ok(()));
    assert_eq!(handle.load().motd_arc().as_deref(), Some("BeforeDrain"));
    Ok(())
}

#[tokio::test]
async fn cancellation_waits_for_a_pending_reload_to_activate_first() -> TestResult {
    let Gate {
        mut fixture,
        handle,
        port,
        reload_ready,
        ..
    } = gated(false, 0)?;
    let first = motd_reload(&handle, "BeforeCancel")?;
    let nudge = motd_reload(&handle, "Nudge")?;
    let (exit, (_inbox, outcome), _state) = run_fixture(&mut fixture, |controls| async move {
        let activation = port.activate_signal(first);
        let script = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            controls.token.cancel();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _nudged = open_gate(&reload_ready, &port, nudge).await;
        };
        let (outcome, ()) = tokio::join!(activation, script);
        Ok((controls.inbox, outcome))
    })
    .await?;
    assert!(matches!(exit, StateCoreExit::Cancelled), "{exit:?}");
    assert!(matches!(outcome, ReloadOutcome::Applied(_)), "{outcome:?}");
    assert_eq!(handle.load().motd_arc().as_deref(), Some("BeforeCancel"));
    Ok(())
}

#[tokio::test]
async fn drain_completes_even_when_the_router_declines_to_begin_shutdown() -> TestResult {
    let Gate {
        mut fixture,
        shutdown_calls,
        ..
    } = gated(true, 2)?;
    let (exit, (_inbox, drained), _state) = run_fixture(&mut fixture, |controls| async move {
        let drained = controls.lifecycle.request(LifecyclePhase::Drain).await;
        let flushed = controls.lifecycle.request(LifecyclePhase::Flush).await;
        controls
            .lifecycle
            .request(LifecyclePhase::Stop)
            .await
            .map_err(|_| "stop")?;
        Ok((controls.inbox, (drained, flushed)))
    })
    .await?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    assert_eq!(drained, (Ok(()), Ok(())));
    assert!(
        shutdown_calls.load(Ordering::SeqCst) >= 3,
        "the router is asked again until it begins its shutdown"
    );
    Ok(())
}
