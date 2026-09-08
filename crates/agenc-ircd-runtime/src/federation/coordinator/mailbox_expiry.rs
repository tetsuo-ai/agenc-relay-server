//! Idle mailbox expiry is independent of peer connectivity and waits for its own receipt.
#![forbid(unsafe_code)]

use super::{FederationCoordinator, PendingCommit};
use crate::budget::MemoryPermit;
use crate::e2ee::coordinator::{CompanionFault, mailbox_expiry::Prepared};
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use crate::state_core::{StageAccepted, StageRefused, StateCoreContext};
use agenc_ircd_domain::e2ee::mailbox::expiry::{Cursor, MAX_EXPIRY_ENTRIES};
use agenc_ircd_types::MonotonicTick;

const RETRY_MILLIS: u64 = 1_000;
const IDLE_MILLIS: u64 = 60_000;

impl PendingCommit {
    pub(super) fn staged_after(&self) -> Option<u64> {
        match self {
            Self::Request { staged_after, .. } => Some(*staged_after),
            Self::ResumeAcknowledged(receipt) => Some(receipt.staged_after),
            Self::CompanionRestore(receipt) => Some(receipt.staged_after),
            Self::CompanionReplayMaintenance(receipt) => Some(receipt.staged_after),
            Self::CompanionMailboxExpiry(receipt) => Some(receipt.staged_after),
            _ => None,
        }
    }
}

#[derive(Default)]
pub(super) struct Worker {
    cursor: Cursor,
    retry_at: u64,
}

pub(super) struct Receipt {
    pub(super) staged_after: u64,
    revision: u64,
    prepared: Prepared,
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
    if entry.kind != TimerKind::CompanionMailboxMaintenance || entry.id != TimedId::Global {
        return false;
    }
    advance(coordinator, context);
    true
}

pub(super) fn advance(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    if coordinator.companion_exec.is_none()
        || context.now().get() < coordinator.mailbox_expiry.retry_at
    {
        return;
    }
    if unavailable(coordinator, context) {
        schedule(coordinator, context, RETRY_MILLIS);
        return;
    }
    let Some(now) = trusted_now(context) else {
        schedule(coordinator, context, RETRY_MILLIS);
        return;
    };
    let result = prepare(coordinator, context, now);
    match result {
        Ok(Some(receipt)) => {
            coordinator.pending = Some(PendingCommit::CompanionMailboxExpiry(Box::new(receipt)))
        }
        Ok(None) => {}
        Err(CompanionFault::Ceiling | CompanionFault::Protocol) => {
            schedule(coordinator, context, RETRY_MILLIS)
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
    let prepared = Prepared::capture(
        executor,
        coordinator.mailbox_expiry.cursor,
        now,
        &context.backing_reservations(),
    )?;
    if prepared.is_empty() {
        advance_cursor(coordinator, context, &prepared);
        return Ok(None);
    }
    // Covers two writes per entry, encoded values, keys, vector capacities and staging copies.
    let backing = context
        .reserve_output_backing(MAX_EXPIRY_ENTRIES * 4096 + 16_384)
        .map_err(|_| CompanionFault::Ceiling)?;
    let staged_after = context.head().storage_commit_sequence;
    let checkpoint = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| CompanionFault::Storage)?;
    let revision = checkpoint.resulting_revision().get();
    let writes = prepared
        .writes(revision)
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
        _backing: backing,
    }))
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
    // The trusted clock at staging authorized the persisted deletion. Publication must agree
    // with that receipt even if wall time changes while storage is committing.
    let result = coordinator
        .companion_exec
        .as_mut()
        .ok_or(CompanionFault::Storage)
        .and_then(|executor| receipt.prepared.apply(executor));
    if result.is_err() {
        super::startup::fail_restore(coordinator);
        return;
    }
    advance_cursor(coordinator, context, &receipt.prepared);
}

pub(super) fn rejected(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    _receipt: Receipt,
) {
    schedule(coordinator, context, RETRY_MILLIS);
}

fn advance_cursor(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    prepared: &Prepared,
) {
    coordinator.mailbox_expiry.cursor = prepared.next_cursor();
    let delay = if prepared.completes_cycle() {
        IDLE_MILLIS
    } else {
        RETRY_MILLIS
    };
    schedule(coordinator, context, delay);
}

fn schedule(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext, delay: u64) {
    let Some(deadline) = context.now().get().checked_add(delay) else {
        return;
    };
    coordinator.mailbox_expiry.retry_at = deadline;
    // The existing retention sweep calls advance if the timer heap refuses admission.
    let _scheduled = context.timers_mut().schedule(
        MonotonicTick::from_ticks(deadline),
        TimerKind::CompanionMailboxMaintenance,
        TimedId::Global,
    );
}
