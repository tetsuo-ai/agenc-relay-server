//! Idle expired-object collection runs without peers and waits for its own receipt.
#![forbid(unsafe_code)]

use super::{FederationCoordinator, PendingCommit};
use crate::budget::MemoryPermit;
use crate::e2ee::coordinator::object_expiry::{MAX_EXPIRY_ACCOUNTS, Prepared};
use crate::e2ee::coordinator::{CompanionFault, owners};
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use crate::state_core::{StageAccepted, StageRefused, StateCoreContext};
use agenc_relay_types::MonotonicTick;

const RETRY_MILLIS: u64 = 1_000;
const IDLE_MILLIS: u64 = 60_000;

/// The collector keeps no cursor of its own: the continuation is the
/// durable `object-expiry/v1` row the executor restored.
#[derive(Default)]
pub(super) struct Worker {
    retry_at: u64,
}

pub(super) struct Receipt {
    pub(super) staged_after: u64,
    revision: u64,
    prepared: Prepared,
    owners: owners::Staged,
    _backing: MemoryPermit,
}

pub(super) fn restored(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    if coordinator.companion_exec.is_some() {
        schedule(coordinator, context, 0);
    }
}

pub(super) fn timer_fired(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    entry: TimerEntry,
) -> bool {
    if entry.kind != TimerKind::CompanionObjectMaintenance || entry.id != TimedId::Global {
        return false;
    }
    advance(coordinator, context);
    true
}

pub(super) fn advance(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    if coordinator.companion_exec.is_none()
        || context.now().get() < coordinator.object_expiry.retry_at
    {
        return;
    }
    if unavailable(coordinator, context) {
        schedule(coordinator, context, RETRY_MILLIS);
        return;
    }
    // Physical deletion is decided from the trusted retention state alone;
    // without a trusted clock nothing is chosen and nothing is staged.
    let Some(now) = trusted_now(context) else {
        schedule(coordinator, context, RETRY_MILLIS);
        return;
    };
    match prepare(coordinator, context, now) {
        Ok(Some(receipt)) => {
            coordinator.pending = Some(PendingCommit::CompanionObjectExpiry(Box::new(receipt)));
        }
        Ok(None) => {}
        Err(CompanionFault::Ceiling | CompanionFault::Protocol) => {
            schedule(coordinator, context, RETRY_MILLIS);
        }
        Err(_) => super::startup::fail_restore(coordinator),
    }
}

fn unavailable(coordinator: &FederationCoordinator, context: &StateCoreContext) -> bool {
    coordinator.loader.blocks_admission()
        || coordinator.pending.is_some()
        || coordinator.replay_io_busy()
        || context.in_flight()
        || context.pending_len() != 0
        || context.is_quiescing()
        || coordinator
            .companion_exec
            .as_ref()
            .is_some_and(|executor| executor.has_pending())
}

fn trusted_now(context: &StateCoreContext) -> Option<u64> {
    context
        .utc_now()
        .ok()
        .filter(|wall| context.drift().accepts_wall(context.now(), *wall))
        .map(|wall| wall.get())
}

fn prepare(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    now: u64,
) -> Result<Option<Receipt>, CompanionFault> {
    let executor = coordinator
        .companion_exec
        .as_ref()
        .ok_or(CompanionFault::Storage)?;
    let progress = executor.expiry_progress();
    let prepared = Prepared::capture(executor, progress, now, &context.backing_reservations())?;
    if prepared.is_empty() {
        return advanced(coordinator, context, &prepared);
    }
    // Two deletes per object, the progress row, their encoded values, keys
    // and the staging copies of one page.
    let backing = context
        .reserve_output_backing(MAX_EXPIRY_ACCOUNTS * 1024 + 16_384)
        .map_err(|_| CompanionFault::Ceiling)?;
    let staged_after = context.head().storage_commit_sequence;
    let checkpoint = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| CompanionFault::Storage)?;
    let revision = checkpoint.resulting_revision().get();
    let mut writes = prepared
        .writes(revision)
        .map_err(|_| CompanionFault::Storage)?;
    // The batch retires accounts and names no new owner, so the ledger adds
    // no row; staging it here still refuses a batch that touched one.
    let owners = executor
        .stage_owners(&mut writes, now, false, revision)
        .map_err(|_| CompanionFault::Storage)?;
    let fanout = FanoutRequest::new(Vec::new(), Vec::new()).map_err(|_| CompanionFault::Storage)?;
    let accepted = context
        .stage_durable_with_account_service(checkpoint, fanout, None, 0, writes)
        .map_err(|error| match error {
            StageRefused::Busy | StageRefused::Quiescing | StageRefused::Fanout(_) => {
                CompanionFault::Ceiling
            }
            StageRefused::Domain(_) => CompanionFault::Storage,
        })?;
    if !matches!(accepted, StageAccepted::Staged { .. }) {
        return Err(CompanionFault::Storage);
    }
    Ok(Some(Receipt {
        staged_after,
        revision,
        prepared,
        owners,
        _backing: backing,
    }))
}

/// A page that deletes nothing changes no accounting, so it stages no
/// batch: only the live continuation moves. The durable row therefore
/// always names the page of the last committed deletion, and a restart
/// re-reads the pages after it without skipping an undeleted account.
fn advanced(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    prepared: &Prepared,
) -> Result<Option<Receipt>, CompanionFault> {
    let delay = if prepared.completes_cycle() {
        IDLE_MILLIS
    } else {
        RETRY_MILLIS
    };
    coordinator
        .companion_exec
        .as_mut()
        .ok_or(CompanionFault::Storage)
        .and_then(|executor| prepared.apply(executor))?;
    schedule(coordinator, context, delay);
    Ok(None)
}

pub(super) fn committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    receipt: Receipt,
) {
    if receipt.staged_after.checked_add(1) != Some(context.head().storage_commit_sequence)
        || receipt.revision != context.domain().revision().get()
    {
        super::startup::fail_restore(coordinator);
        return;
    }
    // The resident bodies and their backing are released only here, against
    // the committed batch, and only for candidates that still match.
    let result = coordinator
        .companion_exec
        .as_mut()
        .ok_or(CompanionFault::Storage)
        .and_then(|executor| {
            receipt.prepared.apply(executor)?;
            receipt.owners.apply(&mut executor.state);
            Ok(())
        });
    if result.is_err() {
        super::startup::fail_restore(coordinator);
        return;
    }
    let delay = if receipt.prepared.completes_cycle() {
        IDLE_MILLIS
    } else {
        RETRY_MILLIS
    };
    schedule(coordinator, context, delay);
}

pub(super) fn rejected(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    _receipt: Receipt,
) {
    // A determinate refusal publishes nothing: the durable continuation is
    // unchanged, so the same page is chosen again.
    schedule(coordinator, context, RETRY_MILLIS);
}

fn schedule(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext, delay: u64) {
    let Some(deadline) = context.now().get().checked_add(delay) else {
        return;
    };
    coordinator.object_expiry.retry_at = deadline;
    // The existing retention sweep calls advance if the timer heap refuses admission.
    let _scheduled = context.timers_mut().schedule(
        MonotonicTick::from_ticks(deadline),
        TimerKind::CompanionObjectMaintenance,
        TimedId::Global,
    );
}
