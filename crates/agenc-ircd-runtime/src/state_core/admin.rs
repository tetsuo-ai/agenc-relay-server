//! Private administrative persistence channel into the single state owner.

use agenc_ircd_admin::AdminAuditEvent;
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
            .try_send(AdminCoreRequest { event, reply })
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
        let (event, reply) = request.into_parts();
        let _sent = reply.send(outcome);
        Some(event)
    }
}

pub(super) struct AdminCoreRequest {
    event: AdminAuditEvent,
    reply: oneshot::Sender<AdminCoreResult>,
}

impl AdminCoreRequest {
    pub(super) fn into_parts(self) -> (AdminAuditEvent, oneshot::Sender<AdminCoreResult>) {
        (self.event, self.reply)
    }
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
}
