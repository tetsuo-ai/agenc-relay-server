//! Root supervisor, signal handling, panic containment, and the four-phase
//! shutdown (spec 21.2 and 21.8, lines 4048-4073 and 4254-4267).
//!
//! Every spawn goes through the supervisor: it owns a child token, a
//! registration in the join set, and a bounded completion. A failed
//! critical task cancels the whole tree; a failed connection task affects
//! only itself. Nothing is detached, and the supervisor joins every child
//! explicitly.

pub mod panic;
pub mod shutdown;
pub mod signal;

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::time::Duration;

use tokio::task::JoinSet;

pub use panic::{CRASH_EXIT_CODE, CrashReporter, exit_process};
pub use shutdown::{
    DEFAULT_DRAIN, DEFAULT_FLUSH, DEFAULT_QUIESCE, DEFAULT_STOP, MAX_DRAIN, MAX_FLUSH, MAX_QUIESCE,
    MAX_STOP, MAX_TOTAL, PhaseOutcome, ShutdownFailure, ShutdownHooks, ShutdownPhase, ShutdownPlan,
    ShutdownProblem, ShutdownProblemKind, ShutdownReport, run_shutdown,
};
pub use signal::{ReceivedSignal, SignalClassifier, run_signal_task};

use crate::RuntimeError;
use crate::cancel::{CancellationToken, MAX_CHILD_TOKENS};

/// Maximum tasks one supervisor tracks; the cancellation tree's bound.
pub const MAX_SUPERVISED_TASKS: usize = MAX_CHILD_TOKENS;

/// The fixed names of supervised tasks (spec lines 4048-4062).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildName {
    /// The signal task.
    SignalTask,
    /// The StateCore actor.
    StateCoreTask,
    /// The storage bridge thread's async owner.
    StorageBridge,
    /// The crypto bridge.
    CryptoBridge,
    /// The listener set.
    ListenerSet,
    /// The maintenance task.
    MaintenanceTask,
    /// The administrative owner.
    AdminOwner,
    /// One connection supervisor.
    Connection,
    /// The federation link owner (accept or dial).
    FederationLinks,
}

impl ChildName {
    /// Returns the fixed log label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SignalTask => "signal_task",
            Self::StateCoreTask => "state_core_task",
            Self::StorageBridge => "storage_bridge",
            Self::CryptoBridge => "crypto_bridge",
            Self::ListenerSet => "listener_set",
            Self::MaintenanceTask => "maintenance_task",
            Self::AdminOwner => "admin_owner",
            Self::Connection => "connection",
            Self::FederationLinks => "federation_links",
        }
    }
}

/// What a child's failure means for the tree (spec lines 4066-4068).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildKind {
    /// Failure cancels the whole tree.
    Critical,
    /// Failure affects only this child.
    Connection,
}

/// Why a child did not complete normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildFailure {
    /// The child returned a runtime error.
    Failed(RuntimeError),
    /// The child panicked; the panic hook has already reported it.
    Panicked,
    /// The child was cancelled by the runtime before it finished.
    Cancelled,
}

impl fmt::Display for ChildFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(error) => write!(formatter, "child failed: {error}"),
            Self::Panicked => formatter.write_str("child panicked"),
            Self::Cancelled => formatter.write_str("child was cancelled"),
        }
    }
}

impl Error for ChildFailure {}

/// One joined child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildExit {
    /// The child's name.
    pub name: ChildName,
    /// The child's failure policy.
    pub kind: ChildKind,
    /// How it ended.
    pub outcome: Result<(), ChildFailure>,
}

struct RawExit {
    name: ChildName,
    kind: ChildKind,
    outcome: Result<(), RuntimeError>,
}

/// The record of a bounded join.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JoinReport {
    /// Children joined within the deadline, in completion order.
    pub exits: Vec<ChildExit>,
    /// Children still running when the deadline expired.
    pub unfinished: usize,
}

/// The root of the owned task tree.
pub struct Supervisor {
    root: CancellationToken,
    children: JoinSet<RawExit>,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    /// Creates a supervisor with a fresh root token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: CancellationToken::root(),
            children: JoinSet::new(),
        }
    }

    /// Returns a handle to the root token.
    #[must_use]
    pub fn root_token(&self) -> CancellationToken {
        self.root.clone()
    }

    /// Spawns one child with its own token and registration.
    ///
    /// `make` receives the child's token and returns the task future.
    pub fn spawn<F, Fut>(
        &mut self,
        name: ChildName,
        kind: ChildKind,
        make: F,
    ) -> Result<CancellationToken, RuntimeError>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Result<(), RuntimeError>> + Send + 'static,
    {
        if self.children.len() >= MAX_SUPERVISED_TASKS {
            return Err(RuntimeError::LimitExceeded);
        }
        let token = self.root.child()?;
        let task = make(token.clone());
        self.children.spawn(async move {
            RawExit {
                name,
                kind,
                outcome: task.await,
            }
        });
        Ok(token)
    }

    /// Returns how many children have not been joined.
    #[must_use]
    pub fn live_children(&self) -> usize {
        self.children.len()
    }

    /// Cancels every child through the root token.
    pub fn cancel(&self) {
        self.root.cancel();
    }

    /// Aborts every child that did not honor cooperative cancellation.
    pub fn abort_all(&mut self) {
        self.children.abort_all();
    }

    /// Joins the next child, applying the failure policy; `None` when no
    /// child remains.
    pub async fn next_exit(&mut self) -> Option<ChildExit> {
        let joined = self.children.join_next().await?;
        let exit = match joined {
            Ok(raw) => ChildExit {
                name: raw.name,
                kind: raw.kind,
                outcome: raw.outcome.map_err(ChildFailure::Failed),
            },
            Err(error) => ChildExit {
                name: ChildName::Connection,
                kind: ChildKind::Critical,
                outcome: Err(if error.is_cancelled() {
                    ChildFailure::Cancelled
                } else {
                    ChildFailure::Panicked
                }),
            },
        };
        if exit.kind == ChildKind::Critical && exit.outcome.is_err() {
            self.root.cancel();
        }
        Some(exit)
    }

    /// Joins every child within `deadline`, reporting how many remain.
    pub async fn join_all(&mut self, deadline: Duration) -> JoinReport {
        let mut report = JoinReport::default();
        let collect = async {
            while let Some(exit) = self.next_exit().await {
                report.exits.push(exit);
            }
        };
        let _ = tokio::time::timeout(deadline, collect).await;
        report.unfinished = self.children.len();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_critical_failure_cancels_the_tree_and_a_connection_failure_does_not()
    -> Result<(), RuntimeError> {
        let mut supervisor = Supervisor::new();
        let root = supervisor.root_token();
        let listener = supervisor.spawn(
            ChildName::ListenerSet,
            ChildKind::Critical,
            |token| async move {
                token.cancelled().await;
                Ok(())
            },
        )?;
        supervisor.spawn(ChildName::Connection, ChildKind::Connection, |_| async {
            Err(RuntimeError::Cancelled)
        })?;
        assert_eq!(supervisor.live_children(), 2);
        let first = supervisor
            .next_exit()
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(first.name, ChildName::Connection);
        assert_eq!(
            first.outcome,
            Err(ChildFailure::Failed(RuntimeError::Cancelled))
        );
        assert!(
            !root.is_cancelled(),
            "a connection failure leaves the tree running"
        );
        assert!(!listener.is_cancelled());

        supervisor.spawn(ChildName::StateCoreTask, ChildKind::Critical, |_| async {
            Err(RuntimeError::InvalidValue)
        })?;
        let critical = supervisor
            .next_exit()
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(critical.name, ChildName::StateCoreTask);
        assert!(root.is_cancelled(), "a critical failure cancels the tree");
        let joined = supervisor
            .next_exit()
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(joined.name, ChildName::ListenerSet);
        assert_eq!(joined.outcome, Ok(()));
        assert!(supervisor.next_exit().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn join_all_reports_unfinished_children_after_the_deadline() -> Result<(), RuntimeError> {
        let mut supervisor = Supervisor::new();
        supervisor.spawn(
            ChildName::MaintenanceTask,
            ChildKind::Critical,
            |token| async move {
                token.cancelled().await;
                Ok(())
            },
        )?;
        supervisor.spawn(ChildName::SignalTask, ChildKind::Critical, |_| async {
            Ok(())
        })?;
        let report = supervisor.join_all(Duration::from_millis(50)).await;
        assert_eq!(report.exits.len(), 1);
        assert_eq!(report.unfinished, 1);
        supervisor.cancel();
        let report = supervisor.join_all(Duration::from_secs(5)).await;
        assert_eq!(report.exits.len(), 1);
        assert_eq!(report.unfinished, 0);
        for name in [
            ChildName::SignalTask,
            ChildName::StateCoreTask,
            ChildName::StorageBridge,
            ChildName::CryptoBridge,
            ChildName::ListenerSet,
            ChildName::MaintenanceTask,
            ChildName::AdminOwner,
            ChildName::Connection,
        ] {
            assert!(name.label().is_ascii());
        }
        for failure in [
            ChildFailure::Failed(RuntimeError::Overflow),
            ChildFailure::Panicked,
            ChildFailure::Cancelled,
        ] {
            assert!(failure.to_string().is_ascii());
        }
        assert_eq!(Supervisor::default().live_children(), 0);
        Ok(())
    }
}
