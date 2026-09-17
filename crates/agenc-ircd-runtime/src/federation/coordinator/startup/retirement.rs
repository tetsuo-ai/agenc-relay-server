//! Startup-only owner retirement has no client or link publication authority.
#![forbid(unsafe_code)]

use super::super::{FederationCoordinator, PendingCommit, Violation};
use crate::budget::MemoryPermit;
use crate::e2ee::coordinator::sync::RestoredRetirement;
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::{StageAccepted, StageRefused, StateCoreContext};
use agenc_ircd_storage::StorageError;

const RETRY_MILLIS: u64 = 100;
const WRITE_BACKING_BYTES: usize = 8_192;

#[derive(Default)]
pub(super) struct Loader {
    candidate: Option<RestoredRetirement>,
    retry_at: u64,
}

/// The exact accepted stage owns the fixed candidate until disposition.
pub(in super::super) struct Receipt {
    pub(in super::super) staged_after: u64,
    revision: u64,
    candidate: RestoredRetirement,
    owners: crate::e2ee::coordinator::owners::Staged,
    _backing: MemoryPermit,
}

/// Returns true only when no Pending owner needs durable retirement.
pub(super) fn advance(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
) -> bool {
    if coordinator.pending.is_some()
        || context.in_flight()
        || context.pending_len() != 0
        || context.is_quiescing()
        || context.now().get() < coordinator.loader.retirement.retry_at
    {
        return false;
    }
    match choose(coordinator) {
        Ok(false) => return true,
        Ok(true) => {}
        Err(_) => {
            super::fail_restore(coordinator);
            return false;
        }
    }
    match stage(coordinator, context) {
        Ok(receipt) => {
            coordinator.pending = Some(PendingCommit::CompanionRestore(Box::new(receipt)))
        }
        Err(Violation::Ceiling) => retry(coordinator, context),
        Err(_) => super::fail_restore(coordinator),
    }
    false
}

fn choose(coordinator: &mut FederationCoordinator) -> Result<bool, Violation> {
    if coordinator.loader.retirement.candidate.is_none() {
        coordinator.loader.retirement.candidate = coordinator
            .companion_exec
            .as_ref()
            .map(|executor| executor.next_restored_retirement())
            .transpose()
            .map_err(|_| Violation::Codec)?
            .flatten();
    }
    Ok(coordinator.loader.retirement.candidate.is_some())
}

fn stage(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
) -> Result<Receipt, Violation> {
    let staged_after = context.head().storage_commit_sequence;
    if coordinator.loader.pinned_commit != Some(staged_after) {
        return Err(Violation::Codec);
    }
    let candidate = coordinator
        .loader
        .retirement
        .candidate
        .as_ref()
        .ok_or(Violation::Codec)?;
    candidate
        .validate(
            coordinator
                .companion_exec
                .as_ref()
                .ok_or(Violation::Codec)?,
        )
        .map_err(|_| Violation::Codec)?;
    let backing = context
        .reserve_output_backing(WRITE_BACKING_BYTES)
        .map_err(|_| Violation::Ceiling)?;
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Codec)?;
    let revision = plan.resulting_revision().get();
    let (writes, owners) = retirement_writes(coordinator, context, candidate, revision)?;
    let fanout = FanoutRequest::new(Vec::new(), Vec::new()).map_err(|_| Violation::Codec)?;
    let accepted = context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|error| match error {
            StageRefused::Busy | StageRefused::Quiescing | StageRefused::Fanout(_) => {
                Violation::Ceiling
            }
            StageRefused::Domain(_) => Violation::Codec,
        })?;
    if !matches!(accepted, StageAccepted::Staged { .. }) {
        return Err(Violation::Codec);
    }
    let candidate = coordinator
        .loader
        .retirement
        .candidate
        .take()
        .ok_or(Violation::Codec)?;
    Ok(Receipt {
        staged_after,
        revision,
        candidate,
        owners,
        _backing: backing,
    })
}

/// The retirement row at the batch revision with its ownership accounts.
fn retirement_writes(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    candidate: &RestoredRetirement,
    revision: u64,
) -> Result<
    (
        Vec<crate::state_core::durable::AccountServiceDurableWrite>,
        crate::e2ee::coordinator::owners::Staged,
    ),
    Violation,
> {
    let mut writes = vec![
        candidate
            .write()
            .map_err(|_| Violation::Codec)?
            .at_revision(revision)
            .map_err(|_| Violation::Codec)?,
    ];
    let owners = coordinator
        .companion_exec
        .as_ref()
        .ok_or(Violation::Codec)?
        .stage_owners(
            &mut writes,
            super::super::trusted_unix_now(context).unwrap_or(0),
            false,
            revision,
        )
        .map_err(|_| Violation::Ceiling)?;
    Ok((writes, owners))
}

pub(in super::super) fn committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    receipt: Receipt,
) {
    let matches = receipt.staged_after.checked_add(1)
        == Some(context.head().storage_commit_sequence)
        && receipt.revision == context.domain().revision().get()
        && coordinator.loader.pinned_commit == Some(receipt.staged_after)
        && coordinator.loader.retirement.candidate.is_none()
        && !coordinator.loader.failed
        && !coordinator.loader.complete;
    if !matches {
        super::fail_restore(coordinator);
        return;
    }
    let applied = coordinator
        .companion_exec
        .as_mut()
        .ok_or(Violation::Codec)
        .and_then(|executor| {
            receipt
                .candidate
                .apply(executor)
                .map_err(|_| Violation::Codec)?;
            receipt.owners.apply(&mut executor.state);
            Ok(())
        });
    if applied.is_err() {
        super::fail_restore(coordinator);
        return;
    }
    coordinator.loader.pinned_commit = Some(context.head().storage_commit_sequence);
    // The run loop's maintenance resumes after receipt/index callback drain.
    retry(coordinator, context);
}

pub(in super::super) fn rejected(
    coordinator: &mut FederationCoordinator,
    context: &StateCoreContext,
    receipt: Receipt,
    error: StorageError,
) {
    let valid = context.head().storage_commit_sequence == receipt.staged_after
        && coordinator.loader.pinned_commit == Some(receipt.staged_after)
        && coordinator.loader.retirement.candidate.is_none()
        && coordinator
            .companion_exec
            .as_ref()
            .is_some_and(|executor| receipt.candidate.validate(executor).is_ok());
    if !valid || !retryable(error) {
        super::fail_restore(coordinator);
        return;
    }
    coordinator.loader.retirement.candidate = Some(receipt.candidate);
    retry(coordinator, context);
}

fn retryable(error: StorageError) -> bool {
    matches!(
        error,
        StorageError::AllocationFailed
            | StorageError::QueueFull
            | StorageError::LimitExceeded
            | StorageError::FilesystemRejected(_)
            | StorageError::DatabaseRejected
    )
}

fn retry(coordinator: &mut FederationCoordinator, context: &StateCoreContext) {
    let Some(next) = context.now().get().checked_add(RETRY_MILLIS) else {
        super::fail_restore(coordinator);
        return;
    };
    coordinator.loader.retirement.retry_at = next;
}
