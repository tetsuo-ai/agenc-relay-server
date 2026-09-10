//! Shared dispatch preserves each maintenance job's exact receipt and rejection owner.
#![forbid(unsafe_code)]
use super::{
    FederationCoordinator, PendingCommit, mailbox_expiry, replay_maintenance, request_expiry,
};
use crate::state_core::StateCoreContext;

impl PendingCommit {
    pub(super) fn staged_after(&self) -> Option<u64> {
        match self {
            Self::Request { staged_after, .. } => Some(*staged_after),
            Self::ResumeAcknowledged(receipt) => Some(receipt.staged_after),
            Self::CompanionRestore(receipt) => Some(receipt.staged_after),
            Self::CompanionReplayMaintenance(receipt) => Some(receipt.staged_after),
            Self::CompanionMailboxExpiry(receipt) => Some(receipt.staged_after),
            Self::CompanionRequestExpiry(receipt) => Some(receipt.staged_after),
            _ => None,
        }
    }
}

pub(super) fn committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    pending: PendingCommit,
) {
    match pending {
        PendingCommit::CompanionMailboxExpiry(receipt) => {
            mailbox_expiry::committed(coordinator, context, *receipt)
        }
        PendingCommit::CompanionRequestExpiry(receipt) => {
            request_expiry::committed(coordinator, context, *receipt)
        }
        PendingCommit::CompanionReplayMaintenance(receipt) => {
            replay_maintenance::committed(coordinator, context, *receipt)
        }
        _ => super::startup::fail_restore(coordinator),
    }
}
pub(super) fn rejected(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    pending: PendingCommit,
) {
    match pending {
        PendingCommit::CompanionMailboxExpiry(receipt) => {
            mailbox_expiry::rejected(coordinator, context, *receipt)
        }
        PendingCommit::CompanionRequestExpiry(receipt) => {
            request_expiry::rejected(coordinator, context, *receipt)
        }
        PendingCommit::CompanionReplayMaintenance(receipt) => {
            replay_maintenance::rejected(coordinator, context, *receipt)
        }
        _ => super::startup::fail_restore(coordinator),
    }
}
