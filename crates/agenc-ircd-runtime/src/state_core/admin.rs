//! Private administrative persistence channel into the single state owner.

use agenc_ircd_admin::{
    AdminAuditCheckpoint, AdminAuditEvent, AdminAuditPhase, AdminCommand, CanonicalCommand,
    StatsSelector,
};
use agenc_ircd_types::{AccountId, ChannelInstanceId, Revision, ServerId, UserId, UtcSecond};
use tokio::sync::{mpsc, oneshot};

use crate::cancel::CancellationToken;

/// Administrative requests waiting for StateCore.
const ADMIN_CORE_CAPACITY: usize = 16;

/// Closed failure classes visible to the administrative owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminCoreFailure {
    Busy,
    InvalidTarget,
    Quiescing,
    StaleRevision,
    StorageUnavailable,
}

pub(crate) type AdminCoreResult = Result<(), AdminCoreFailure>;

/// A durable target whose current revision binds a confirmation token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminTarget {
    Account(AccountId),
    Channel(ChannelInstanceId),
    Process,
}

/// State represented durably by a committed-mutation audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminMutation {
    SuspendAccount {
        account_id: AccountId,
        expires_at: UtcSecond,
    },
    RestoreAccount(AccountId),
    QuarantineChannel(ChannelInstanceId),
}

impl AdminMutation {
    pub(super) fn matches_event(self, event: &AdminAuditEvent) -> bool {
        if event.tbs().phase != AdminAuditPhase::CommittedMutation {
            return false;
        }
        let Ok(canonical) = CanonicalCommand::check(event.tbs().command_tbs.canonical_command())
        else {
            return false;
        };
        let Ok(command) = AdminCommand::parse(canonical) else {
            return false;
        };
        match (self, command) {
            (
                Self::SuspendAccount {
                    account_id,
                    expires_at,
                },
                AdminCommand::AccountSuspend {
                    account, seconds, ..
                },
            ) => event
                .tbs()
                .created_at
                .checked_add(seconds.get())
                .is_some_and(|expected| account_id == account && expires_at.get() == expected),
            (Self::RestoreAccount(account_id), AdminCommand::AccountRestore { account, .. }) => {
                account_id == account
            }
            (
                Self::QuarantineChannel(channel_id),
                AdminCommand::ChannelQuarantine { channel, .. },
            ) => channel_id == channel,
            _ => false,
        }
    }
}

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

    pub(crate) fn with_observed_runtime(
        mut self,
        runtime_prefix: [u64; 3],
        rates: [u64; 8],
    ) -> Self {
        let [new_uptime, new_clients, new_tls] = runtime_prefix;
        let [uptime, clients, tls, ..] = &mut self.runtime;
        *uptime = new_uptime;
        *clients = new_clients;
        *tls = new_tls;
        self.rates = rates;
        self
    }

    pub(crate) fn with_federation(mut self, federation: [u64; 7]) -> Self {
        self.federation = federation;
        self
    }

    pub(crate) fn with_storage(mut self, storage: [u64; 14]) -> Self {
        self.storage = storage;
        self
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

    /// Captures the current durable revision after validating the typed
    /// confirmation target.
    pub(crate) async fn target_revision(
        &self,
        target: AdminTarget,
        token: &CancellationToken,
    ) -> Result<Revision, AdminCoreFailure> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(AdminCoreRequest::TargetRevision { target, reply })
            .map_err(map_send_failure)?;
        tokio::select! {
            () = token.cancelled() => Err(AdminCoreFailure::StorageUnavailable),
            outcome = response => outcome.unwrap_or(Err(AdminCoreFailure::StorageUnavailable)),
        }
    }

    /// Commits the audit record and its derived administrative policy change
    /// in one storage transaction, then applies the in-memory view.
    pub(crate) async fn commit_mutation(
        &self,
        event: AdminAuditEvent,
        mutation: AdminMutation,
        expected_revision: Revision,
        token: &CancellationToken,
    ) -> AdminCoreResult {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(AdminCoreRequest::CommitMutation {
                event: Box::new(event),
                mutation,
                expected_revision,
                reply,
            })
            .map_err(map_send_failure)?;
        tokio::select! {
            () = token.cancelled() => Err(AdminCoreFailure::StorageUnavailable),
            outcome = response => outcome.unwrap_or(Err(AdminCoreFailure::StorageUnavailable)),
        }
    }

    /// Terminates one exact live user session through StateCore ownership.
    pub(crate) async fn kill(&self, user_id: UserId, token: &CancellationToken) -> AdminCoreResult {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(AdminCoreRequest::Kill { user_id, reply })
            .map_err(map_send_failure)?;
        tokio::select! {
            () = token.cancelled() => Err(AdminCoreFailure::StorageUnavailable),
            outcome = response => outcome.unwrap_or(Err(AdminCoreFailure::StorageUnavailable)),
        }
    }

    /// Durably quarantines one configured federation peer.
    pub(crate) async fn peer_quarantine(
        &self,
        server: ServerId,
        token: &CancellationToken,
    ) -> AdminCoreResult {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(AdminCoreRequest::PeerQuarantine { server, reply })
            .map_err(map_send_failure)?;
        tokio::select! {
            () = token.cancelled() => Err(AdminCoreFailure::StorageUnavailable),
            outcome = response => outcome.unwrap_or(Err(AdminCoreFailure::StorageUnavailable)),
        }
    }

    /// Replaces one verified expired audit prefix with its signed checkpoint.
    pub(crate) async fn commit_retention(
        &self,
        checkpoint: AdminAuditCheckpoint,
        token: &CancellationToken,
    ) -> AdminCoreResult {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(AdminCoreRequest::CommitRetention {
                checkpoint: Box::new(checkpoint),
                reply,
            })
            .map_err(map_send_failure)?;
        tokio::select! {
            () = token.cancelled() => Err(AdminCoreFailure::StorageUnavailable),
            outcome = response => outcome.unwrap_or(Err(AdminCoreFailure::StorageUnavailable)),
        }
    }
}

fn map_send_failure(error: mpsc::error::TrySendError<AdminCoreRequest>) -> AdminCoreFailure {
    match error {
        mpsc::error::TrySendError::Full(_) => AdminCoreFailure::Busy,
        mpsc::error::TrySendError::Closed(_) => AdminCoreFailure::StorageUnavailable,
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
            AdminCoreRequest::CommitMutation { reply, .. }
            | AdminCoreRequest::Kill { reply, .. }
            | AdminCoreRequest::PeerQuarantine { reply, .. }
            | AdminCoreRequest::CommitRetention { reply, .. } => {
                let _sent = reply.send(outcome);
                None
            }
            AdminCoreRequest::TargetRevision { reply, .. } => {
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
            AdminCoreRequest::CommitMutation { reply, .. }
            | AdminCoreRequest::Kill { reply, .. }
            | AdminCoreRequest::PeerQuarantine { reply, .. }
            | AdminCoreRequest::CommitRetention { reply, .. } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                false
            }
            AdminCoreRequest::TargetRevision { reply, .. } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                false
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn complete_target_revision_for_test(
        &mut self,
        revision: Revision,
    ) -> Option<AdminTarget> {
        let request = self.receiver.recv().await?;
        match request {
            AdminCoreRequest::TargetRevision { target, reply } => {
                let _sent = reply.send(Ok(revision));
                Some(target)
            }
            AdminCoreRequest::CommitAudit { reply, .. }
            | AdminCoreRequest::CommitMutation { reply, .. }
            | AdminCoreRequest::Kill { reply, .. }
            | AdminCoreRequest::PeerQuarantine { reply, .. }
            | AdminCoreRequest::CommitRetention { reply, .. } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                None
            }
            AdminCoreRequest::Snapshot { reply } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                None
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn complete_mutation_for_test(
        &mut self,
        outcome: AdminCoreResult,
    ) -> Option<(AdminAuditEvent, AdminMutation, Revision)> {
        let request = self.receiver.recv().await?;
        match request {
            AdminCoreRequest::CommitMutation {
                event,
                mutation,
                expected_revision,
                reply,
            } => {
                let _sent = reply.send(outcome);
                Some((*event, mutation, expected_revision))
            }
            AdminCoreRequest::CommitAudit { reply, .. }
            | AdminCoreRequest::Kill { reply, .. }
            | AdminCoreRequest::PeerQuarantine { reply, .. } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                None
            }
            AdminCoreRequest::CommitRetention { reply, .. } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                None
            }
            AdminCoreRequest::Snapshot { reply } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                None
            }
            AdminCoreRequest::TargetRevision { reply, .. } => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                None
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
    TargetRevision {
        target: AdminTarget,
        reply: oneshot::Sender<Result<Revision, AdminCoreFailure>>,
    },
    CommitMutation {
        event: Box<AdminAuditEvent>,
        mutation: AdminMutation,
        expected_revision: Revision,
        reply: oneshot::Sender<AdminCoreResult>,
    },
    Kill {
        user_id: UserId,
        reply: oneshot::Sender<AdminCoreResult>,
    },
    PeerQuarantine {
        server: ServerId,
        reply: oneshot::Sender<AdminCoreResult>,
    },
    CommitRetention {
        checkpoint: Box<AdminAuditCheckpoint>,
        reply: oneshot::Sender<AdminCoreResult>,
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
