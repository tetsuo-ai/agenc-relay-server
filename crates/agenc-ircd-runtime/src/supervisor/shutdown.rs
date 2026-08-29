//! The four-phase shutdown driver (spec 21.8, lines 4254-4267; Appendix
//! C.2, lines 8915).
//!
//! Quiesce closes listeners and rejects new mutations, drain finishes
//! accepted durable batches, flush persists cursors and writer queues, and
//! stop cancels what remains. Each phase has its own budget, the sum is at
//! most 120 seconds, and a second termination signal skips straight to
//! stop. A reload signal during shutdown is ignored without interrupting
//! the running phase.

use std::future::Future;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::RuntimeError;
use crate::state_core::inbox::SignalEvent;

/// Default quiesce budget (spec line 4256).
pub const DEFAULT_QUIESCE: Duration = Duration::from_secs(5);
/// Default drain budget (spec line 4257).
pub const DEFAULT_DRAIN: Duration = Duration::from_secs(20);
/// Default flush budget (spec line 4259).
pub const DEFAULT_FLUSH: Duration = Duration::from_secs(10);
/// Default stop budget (spec line 4260).
pub const DEFAULT_STOP: Duration = Duration::from_secs(5);
/// Maximum quiesce budget (Appendix C.2).
pub const MAX_QUIESCE: Duration = Duration::from_secs(30);
/// Maximum drain budget (Appendix C.2).
pub const MAX_DRAIN: Duration = Duration::from_secs(60);
/// Maximum flush budget (Appendix C.2).
pub const MAX_FLUSH: Duration = Duration::from_secs(30);
/// Maximum stop budget (Appendix C.2).
pub const MAX_STOP: Duration = Duration::from_secs(30);
/// Hard maximum of all four budgets together (spec line 4263).
pub const MAX_TOTAL: Duration = Duration::from_secs(120);

/// The four ordered phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownPhase {
    /// Close listeners, reject new mutations, notify links.
    Quiesce,
    /// Finish accepted durable batches and enqueue final QUIT events.
    Drain,
    /// Persist cursors and the audit checkpoint; flush writer queues.
    Flush,
    /// Cancel remaining tasks, join threads, close databases and TLS.
    Stop,
}

impl ShutdownPhase {
    /// The phases in execution order.
    pub const ALL: [Self; 4] = [Self::Quiesce, Self::Drain, Self::Flush, Self::Stop];

    /// Returns the fixed log label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Quiesce => "quiesce",
            Self::Drain => "drain",
            Self::Flush => "flush",
            Self::Stop => "stop",
        }
    }
}

/// Validated per-phase budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownPlan {
    quiesce: Duration,
    drain: Duration,
    flush: Duration,
    stop: Duration,
}

impl ShutdownPlan {
    /// The spec defaults: 5, 20, 10, and 5 seconds.
    pub const DEFAULT: Self = Self {
        quiesce: DEFAULT_QUIESCE,
        drain: DEFAULT_DRAIN,
        flush: DEFAULT_FLUSH,
        stop: DEFAULT_STOP,
    };

    /// Validates each budget within its range and the total within 120 s.
    pub fn new(
        quiesce: Duration,
        drain: Duration,
        flush: Duration,
        stop: Duration,
    ) -> Result<Self, RuntimeError> {
        let one = Duration::from_secs(1);
        let in_range = |value: Duration, maximum: Duration| value >= one && value <= maximum;
        if !in_range(quiesce, MAX_QUIESCE)
            || !in_range(drain, MAX_DRAIN)
            || !in_range(flush, MAX_FLUSH)
            || !in_range(stop, MAX_STOP)
        {
            return Err(RuntimeError::InvalidValue);
        }
        let total = quiesce
            .checked_add(drain)
            .and_then(|sum| sum.checked_add(flush))
            .and_then(|sum| sum.checked_add(stop))
            .ok_or(RuntimeError::Overflow)?;
        if total > MAX_TOTAL {
            return Err(RuntimeError::LimitExceeded);
        }
        Ok(Self {
            quiesce,
            drain,
            flush,
            stop,
        })
    }

    /// Returns the budget of one phase.
    #[must_use]
    pub const fn budget(self, phase: ShutdownPhase) -> Duration {
        match phase {
            ShutdownPhase::Quiesce => self.quiesce,
            ShutdownPhase::Drain => self.drain,
            ShutdownPhase::Flush => self.flush,
            ShutdownPhase::Stop => self.stop,
        }
    }

    /// Returns the sum of every budget.
    #[must_use]
    pub fn total(self) -> Duration {
        self.quiesce + self.drain + self.flush + self.stop
    }
}

/// How one phase ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseOutcome {
    /// The hook finished within its budget.
    Completed,
    /// The budget expired; the driver moved on.
    TimedOut,
    /// A second termination signal skipped the phase.
    Skipped,
}

/// The record of one shutdown run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    outcomes: [PhaseOutcome; 4],
    interrupted: bool,
}

impl ShutdownReport {
    /// Returns the outcome of one phase.
    #[must_use]
    pub const fn outcome(&self, phase: ShutdownPhase) -> PhaseOutcome {
        match phase {
            ShutdownPhase::Quiesce => self.outcomes[0],
            ShutdownPhase::Drain => self.outcomes[1],
            ShutdownPhase::Flush => self.outcomes[2],
            ShutdownPhase::Stop => self.outcomes[3],
        }
    }

    /// Returns whether a second termination signal shortened the run.
    #[must_use]
    pub const fn interrupted(&self) -> bool {
        self.interrupted
    }
}

/// The work each phase performs; the runtime composes it from its owners.
pub trait ShutdownHooks {
    /// Runs one phase to completion; the driver applies the budget.
    fn run(&mut self, phase: ShutdownPhase) -> impl Future<Output = ()> + Send;
}

/// Drives the four phases, honoring budgets and the second-signal skip.
pub async fn run_shutdown<H: ShutdownHooks>(
    plan: ShutdownPlan,
    hooks: &mut H,
    signals: &mut mpsc::Receiver<SignalEvent>,
) -> ShutdownReport {
    let mut outcomes = [PhaseOutcome::Skipped; 4];
    let mut skip_to_stop = false;
    for (slot, phase) in outcomes.iter_mut().zip(ShutdownPhase::ALL) {
        if skip_to_stop && phase != ShutdownPhase::Stop {
            *slot = PhaseOutcome::Skipped;
            continue;
        }
        let outcome = run_phase(plan.budget(phase), hooks.run(phase), signals).await;
        if outcome == PhaseOutcome::Skipped {
            skip_to_stop = true;
        }
        *slot = outcome;
    }
    ShutdownReport {
        outcomes,
        interrupted: skip_to_stop,
    }
}

/// Runs one phase under its budget; a termination signal skips it, a
/// reload signal is ignored without dropping the phase future.
async fn run_phase<F: Future<Output = ()>>(
    budget: Duration,
    phase: F,
    signals: &mut mpsc::Receiver<SignalEvent>,
) -> PhaseOutcome {
    let bounded = tokio::time::timeout(budget, phase);
    tokio::pin!(bounded);
    loop {
        let event = tokio::select! {
            result = &mut bounded => PhaseEvent::Finished(result.is_ok()),
            signal = signals.recv() => PhaseEvent::Signal(signal),
        };
        match event {
            PhaseEvent::Finished(true) => return PhaseOutcome::Completed,
            PhaseEvent::Finished(false) => return PhaseOutcome::TimedOut,
            PhaseEvent::Signal(Some(SignalEvent::Terminate | SignalEvent::Interrupt)) => {
                return PhaseOutcome::Skipped;
            }
            PhaseEvent::Signal(_) => {}
        }
    }
}

enum PhaseEvent {
    Finished(bool),
    Signal(Option<SignalEvent>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_follow_the_ranges_and_the_120_second_total() -> Result<(), RuntimeError> {
        let plan = ShutdownPlan::DEFAULT;
        assert_eq!(plan.total(), Duration::from_secs(40));
        assert_eq!(plan.budget(ShutdownPhase::Quiesce), Duration::from_secs(5));
        assert_eq!(plan.budget(ShutdownPhase::Drain), Duration::from_secs(20));
        assert_eq!(plan.budget(ShutdownPhase::Flush), Duration::from_secs(10));
        assert_eq!(plan.budget(ShutdownPhase::Stop), Duration::from_secs(5));
        let s = Duration::from_secs;
        assert_eq!(
            ShutdownPlan::new(s(0), s(1), s(1), s(1)).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            ShutdownPlan::new(s(31), s(1), s(1), s(1)).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            ShutdownPlan::new(s(1), s(61), s(1), s(1)).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            ShutdownPlan::new(s(1), s(1), s(31), s(1)).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            ShutdownPlan::new(s(1), s(1), s(1), s(31)).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            ShutdownPlan::new(s(30), s(60), s(30), s(30)).err(),
            Some(RuntimeError::LimitExceeded)
        );
        assert_eq!(
            ShutdownPlan::new(s(30), s(60), s(20), s(10))?.total(),
            MAX_TOTAL
        );
        for phase in ShutdownPhase::ALL {
            assert!(phase.label().is_ascii());
        }
        Ok(())
    }
}
