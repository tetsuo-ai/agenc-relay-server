//! A timer drives offline replay expiry through bounded reads and an exact receipt.
#![forbid(unsafe_code)]

mod io;
mod receipt;
mod task;

use super::{FederationCoordinator, PendingCommit};
use crate::bridge::StorageReadId;
use crate::budget::MemoryPermit;
use crate::e2ee::coordinator::replay_cleanup;
use crate::e2ee::coordinator::{CompanionFault, ReplayMaintenanceCandidate, ReplayMaintenanceJob};
use crate::state_core::StateCoreContext;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use agenc_relay_types::{MonotonicTick, ServerId};
use std::collections::BTreeMap;

pub(super) use io::completed;
pub(super) use receipt::{Receipt, committed, rejected};

const RETRY_MILLIS: u64 = 1_000;
const IDLE_MILLIS: u64 = 60_000;

pub(super) fn restored(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    if coordinator.companion_exec.is_some() {
        schedule(coordinator, context, 0);
    }
}

#[derive(Default)]
pub(super) struct Worker {
    read: Option<Box<io::ReadOwner>>,
    retry_at: u64,
    cursor: Option<ServerId>,
    cleaned: BTreeMap<ServerId, Cleaned>,
}

struct Cleaned {
    stamp: replay_cleanup::Stamp,
    _backing: MemoryPermit,
}

impl Worker {
    pub(super) fn busy(&self) -> bool {
        self.read.is_some()
    }
    pub(super) fn owns(&self, id: StorageReadId) -> bool {
        self.read.as_ref().is_some_and(|read| read.id == id)
    }
}

pub(super) fn timer_fired(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    entry: TimerEntry,
) -> bool {
    if entry.kind != TimerKind::CompanionReplayMaintenance || entry.id != TimedId::Global {
        return false;
    }
    advance(coordinator, context);
    true
}

pub(super) fn advance(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    if coordinator.companion_exec.is_none() {
        return;
    }
    if context.now().get() < coordinator.replay_maintenance.retry_at {
        return;
    }
    if unavailable(coordinator, context) {
        schedule(coordinator, context, RETRY_MILLIS);
        return;
    }
    match choose(coordinator, trusted_now(context)) {
        Ok(Some(candidate)) => {
            coordinator.replay_maintenance.cursor = Some(candidate.peer());
            if let Err(error) = start(coordinator, context, candidate) {
                refused(coordinator, context, error);
            }
        }
        Ok(None) => schedule(coordinator, context, IDLE_MILLIS),
        Err(error) => refused(coordinator, context, error),
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

fn choose(
    coordinator: &FederationCoordinator,
    now: Option<u64>,
) -> Result<Option<task::Candidate>, CompanionFault> {
    let Some(executor) = coordinator.companion_exec.as_ref() else {
        return Ok(None);
    };
    let cursor = coordinator.replay_maintenance.cursor;
    let after = coordinator
        .peers
        .keys()
        .filter(|peer| cursor.is_none_or(|cursor| **peer > cursor));
    let before = coordinator
        .peers
        .keys()
        .filter(|peer| cursor.is_some_and(|cursor| **peer <= cursor));
    for peer in after.chain(before) {
        // An open gate's retained proof is independent of the replay-age target.
        if coordinator.barriers.contains_key(peer) {
            continue;
        }
        if let Some(now) = now
            && let Some(candidate) = ReplayMaintenanceCandidate::due(executor, *peer, now)?
        {
            return Ok(Some(task::Candidate::Expire(Box::new(candidate))));
        }
        if let Some(candidate) = replay_cleanup::Candidate::current(executor, *peer)?
            && coordinator
                .replay_maintenance
                .cleaned
                .get(peer)
                .is_none_or(|cleaned| cleaned.stamp != candidate.stamp())
        {
            return Ok(Some(task::Candidate::Cleanup(Box::new(candidate))));
        }
    }
    Ok(None)
}

fn start(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    candidate: task::Candidate,
) -> Result<(), CompanionFault> {
    if !matches_peer(coordinator, candidate.peer(), candidate.scope()) {
        return Err(CompanionFault::Protocol);
    }
    let executor = coordinator
        .companion_exec
        .as_ref()
        .ok_or(CompanionFault::Storage)?;
    let commit = context.head().storage_commit_sequence;
    let mut job = candidate.begin(executor, commit, &context.backing_reservations())?;
    let plan = job.next()?.ok_or(CompanionFault::Storage)?;
    coordinator.replay_maintenance.read = Some(io::prepare(context, job, plan, commit)?);
    Ok(())
}

fn validate_source(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    job: &task::Job,
) -> Result<(), CompanionFault> {
    if coordinator.pending.is_some()
        || coordinator.loader.blocks_admission()
        || context.is_quiescing()
        || job.requires_clock() && trusted_now(context).is_none()
        || coordinator.barriers.contains_key(&job.peer())
        || !matches_peer(coordinator, job.peer(), job.scope())
    {
        return Err(CompanionFault::Protocol);
    }
    job.validate(
        coordinator
            .companion_exec
            .as_ref()
            .ok_or(CompanionFault::Protocol)?,
    )
}

fn matches_peer(
    coordinator: &FederationCoordinator,
    peer: ServerId,
    scope: &agenc_relay_storage::e2ee_records::delivery_recovery::DeliveryScope,
) -> bool {
    coordinator.peers.get(&peer).is_some_and(|state| {
        !state.quarantined
            && !state.outbox.snapshot_required
            && state
                .incarnation
                .is_some_and(|incarnation| *incarnation.as_bytes() == scope.target_incarnation())
            && state.client_resync_epoch == scope.covered_base_client_resync_epoch()
    })
}

fn mark_clean(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    stamp: replay_cleanup::Stamp,
    commit: u64,
) -> Result<(), CompanionFault> {
    if context.head().storage_commit_sequence != commit
        || context.in_flight()
        || context.pending_len() != 0
        || coordinator.pending.is_some()
        || !coordinator.peers.contains_key(&stamp.peer())
    {
        return Err(CompanionFault::Protocol);
    }
    let backing = context
        .reserve_output_backing(1_024)
        .map_err(|_| CompanionFault::Ceiling)?;
    coordinator.replay_maintenance.cleaned.insert(
        stamp.peer(),
        Cleaned {
            stamp,
            _backing: backing,
        },
    );
    schedule(coordinator, context, RETRY_MILLIS);
    Ok(())
}

fn schedule(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext, delay: u64) {
    let Some(deadline) = context.now().get().checked_add(delay) else {
        return;
    };
    coordinator.replay_maintenance.retry_at = deadline;
    // If the heap is full, the daemon's existing retention sweep retries without a parked job.
    let _scheduled = context.timers_mut().schedule(
        MonotonicTick::from_ticks(deadline),
        TimerKind::CompanionReplayMaintenance,
        TimedId::Global,
    );
}

fn refused(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    error: CompanionFault,
) {
    match error {
        CompanionFault::Ceiling | CompanionFault::Protocol => {
            schedule(coordinator, context, RETRY_MILLIS)
        }
        _ => super::startup::fail_restore(coordinator),
    }
}
