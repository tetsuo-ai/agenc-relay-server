//! Private administrative persistence channel into the single state owner.

use agenc_ircd_admin::{AdminAuditEvent, StatsSelector};
use tokio::sync::{mpsc, oneshot};

use crate::cancel::CancellationToken;

/// Administrative requests waiting for StateCore.
const ADMIN_CORE_CAPACITY: usize = 16;

/// Closed failure classes visible to the administrative owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminCoreFailure {
    Busy,
    Quiescing,
    StorageUnavailable,
}

pub(crate) type AdminCoreResult = Result<(), AdminCoreFailure>;

/// One committed-state statistics view copied without exposing any mutable
/// StateCore authority to the administrative owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdminCoreSnapshot {
    runtime: [u64; 9],
    storage: [u64; 14],
    federation: [u64; 7],
    queues: [u64; 10],
    rates: [u64; 8],
    e2ee: [u64; 9],
}

impl AdminCoreSnapshot {
    pub(crate) const fn new(
        runtime: [u64; 9],
        storage: [u64; 14],
        queues: [u64; 10],
        rates: [u64; 8],
    ) -> Self {
        Self {
            runtime,
            storage,
            federation: [0; 7],
            queues,
            rates,
            e2ee: [0; 9],
        }
    }

    pub(crate) const fn values(&self, selector: StatsSelector) -> &[u64] {
        match selector {
            StatsSelector::Runtime => &self.runtime,
            StatsSelector::Storage => &self.storage,
            StatsSelector::Federation => &self.federation,
            StatsSelector::Queues => &self.queues,
            StatsSelector::Rates => &self.rates,
            StatsSelector::E2ee => &self.e2ee,
        }
    }
}

/// Cloneable sending half held only by `AdminOwner`.
#[derive(Clone)]
pub(crate) struct AdminCorePort {
    sender: mpsc::Sender<AdminCoreRequest>,
}

impl AdminCorePort {
    /// Commits one already signed audit event through StateCore's sole
    /// durable writer path. Cancellation may abandon the reply only while
    /// the whole daemon is stopping; startup reconstruction then owns the
    /// durable outcome.
    pub(crate) async fn commit_audit(
        &self,
        event: AdminAuditEvent,
        token: &CancellationToken,
    ) -> AdminCoreResult {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(AdminCoreRequest::CommitAudit {
                event: Box::new(event),
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => AdminCoreFailure::Busy,
                mpsc::error::TrySendError::Closed(_) => AdminCoreFailure::StorageUnavailable,
            })?;
        tokio::select! {
            () = token.cancelled() => Err(AdminCoreFailure::StorageUnavailable),
            outcome = response => outcome.unwrap_or(Err(AdminCoreFailure::StorageUnavailable)),
        }
    }

    /// Copies one bounded, input-free view of committed runtime state.
    pub(crate) async fn snapshot(
        &self,
        token: &CancellationToken,
    ) -> Result<AdminCoreSnapshot, AdminCoreFailure> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(AdminCoreRequest::Snapshot { reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => AdminCoreFailure::Busy,
                mpsc::error::TrySendError::Closed(_) => AdminCoreFailure::StorageUnavailable,
            })?;
        tokio::select! {
            () = token.cancelled() => Err(AdminCoreFailure::StorageUnavailable),
            outcome = response => outcome.unwrap_or(Err(AdminCoreFailure::StorageUnavailable)),
        }
    }
}

/// Receiving half installed exactly once into StateCore.
pub(crate) struct AdminCoreInbox {
    receiver: mpsc::Receiver<AdminCoreRequest>,
}

impl AdminCoreInbox {
    pub(super) fn into_receiver(self) -> mpsc::Receiver<AdminCoreRequest> {
        self.receiver
    }

    #[cfg(test)]
    pub(crate) async fn complete_next_for_test(
        &mut self,
        outcome: AdminCoreResult,
    ) -> Option<AdminAuditEvent> {
        let request = self.receiver.recv().await?;
        match request {
            AdminCoreRequest::CommitAudit { event, reply } => {
                let _sent = reply.send(outcome);
                Some(*event)
            }
            AdminCoreRequest::Snapshot { reply } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                None
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn complete_snapshot_for_test(&mut self, snapshot: AdminCoreSnapshot) -> bool {
        let Some(request) = self.receiver.recv().await else {
            return false;
        };
        match request {
            AdminCoreRequest::Snapshot { reply } => reply.send(Ok(snapshot)).is_ok(),
            AdminCoreRequest::CommitAudit { reply, .. } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                false
            }
        }
    }
}

pub(super) enum AdminCoreRequest {
    CommitAudit {
        event: Box<AdminAuditEvent>,
        reply: oneshot::Sender<AdminCoreResult>,
    },
    Snapshot {
        reply: oneshot::Sender<Result<AdminCoreSnapshot, AdminCoreFailure>>,
    },
}

/// Creates the one bounded administrative persistence channel.
pub(crate) fn admin_core_channel() -> (AdminCorePort, AdminCoreInbox) {
    let (sender, receiver) = mpsc::channel(ADMIN_CORE_CAPACITY);
    (AdminCorePort { sender }, AdminCoreInbox { receiver })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_core_capacity_is_small_and_nonzero() {
        assert_eq!(ADMIN_CORE_CAPACITY, 16);
    }

    #[test]
    fn snapshot_shapes_match_the_closed_stats_registry() {
        let snapshot = AdminCoreSnapshot::new([1; 9], [2; 14], [3; 10], [4; 8]);
        for selector in StatsSelector::ALL {
            assert_eq!(snapshot.values(selector).len(), selector.field_count());
        }
        assert!(
            snapshot
                .values(StatsSelector::Federation)
                .iter()
                .all(|value| *value == 0)
        );
        assert!(
            snapshot
                .values(StatsSelector::E2ee)
                .iter()
                .all(|value| *value == 0)
        );
    }
}
