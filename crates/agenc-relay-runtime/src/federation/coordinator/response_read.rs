//! An authenticated response read retains its buffers until exact completion or cancellation.
#![forbid(unsafe_code)]

mod io;

use super::{FederationCoordinator, SendFailure, Violation, companion};
use crate::bridge::StorageReadId;
use crate::budget::MemoryPermit;
use crate::e2ee::coordinator::response_read::{Candidate, Identity, Job, Output};
use crate::federation::LinkId;
use crate::state_core::StateCoreContext;
use agenc_relay_storage::ReadPlan;
use agenc_relay_types::ServerId;

pub(super) use io::completed;

pub(super) struct Pending {
    id: StorageReadId,
    commit: u64,
    link: LinkId,
    base_epoch: u64,
    job: Job,
    _raw: MemoryPermit,
    _decode: MemoryPermit,
}

pub(super) fn owns(coordinator: &FederationCoordinator, id: StorageReadId) -> bool {
    coordinator
        .companion_response_read
        .as_ref()
        .is_some_and(|read| read.id == id)
}

pub(super) fn submit(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    identity: Identity,
) -> Result<(), Violation> {
    if identity.peer != peer
        || coordinator.replay_io_busy()
        || coordinator.pending.is_some()
        || coordinator.loader.blocks_admission()
        || context.in_flight()
        || context.pending_len() != 0
        || context.is_quiescing()
    {
        return Err(Violation::Ceiling);
    }
    let state = coordinator.peers.get(&peer).ok_or(Violation::Phase)?;
    let base_epoch = state.client_resync_epoch;
    validate_link(coordinator, context, link, identity, base_epoch)?;
    let executor = coordinator
        .companion_exec
        .as_ref()
        .ok_or(Violation::Codec)?;
    if executor.has_pending() {
        return Err(Violation::Ceiling);
    }
    let candidate = Candidate::capture(executor, identity, &context.backing_reservations())
        .map_err(companion::fault_violation)?;
    let commit = context.head().storage_commit_sequence;
    let mut job = candidate
        .begin(commit, &context.backing_reservations())
        .map_err(companion::fault_violation)?;
    let plan = job.next().map_err(companion::fault_violation)?;
    advance(coordinator, context, job, plan, commit, link, base_epoch)
}

pub(super) fn validate_link(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    link: LinkId,
    identity: Identity,
    base_epoch: u64,
) -> Result<(), Violation> {
    if context.is_quiescing()
        || coordinator.pending.is_some()
        || coordinator.loader.blocks_admission()
    {
        return Err(Violation::Phase);
    }
    let peer = coordinator
        .peers
        .get(&identity.peer)
        .ok_or(Violation::Phase)?;
    let live = peer
        .live
        .as_ref()
        .filter(|live| live.link == link)
        .ok_or(Violation::Phase)?;
    if *live.incarnation.as_bytes() != identity.correlation.server_incarnation
        || peer.client_resync_epoch != base_epoch
        || peer.quarantined
    {
        return Err(Violation::Phase);
    }
    validate_sync(coordinator, identity, link, base_epoch)?;
    Ok(())
}

fn validate_sync(
    coordinator: &FederationCoordinator,
    identity: Identity,
    link: LinkId,
    base_epoch: u64,
) -> Result<(), Violation> {
    let executor = coordinator
        .companion_exec
        .as_ref()
        .ok_or(Violation::Phase)?;
    let sync = executor.peer_sync(identity.peer).ok_or(Violation::Phase)?;
    if !executor.accepting_requests(identity.peer)
        || sync.link != Some(link)
        || sync.incarnation != Some(identity.correlation.server_incarnation)
        || sync.resync_epoch != base_epoch
    {
        return Err(Violation::Phase);
    }
    Ok(())
}

fn advance(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    job: Job,
    plan: Option<ReadPlan>,
    commit: u64,
    link: LinkId,
    base_epoch: u64,
) -> Result<(), Violation> {
    let identity = job.candidate().identity();
    validate_link(coordinator, context, link, identity, base_epoch)?;
    if context.head().storage_commit_sequence != commit
        || context.in_flight()
        || context.pending_len() != 0
    {
        return Err(Violation::Phase);
    }
    if let Some(plan) = plan {
        coordinator.companion_response_read =
            Some(io::prepare(context, job, plan, commit, link, base_epoch)?);
        return Ok(());
    }
    let executor = coordinator
        .companion_exec
        .as_ref()
        .ok_or(Violation::Codec)?;
    let output = job.finish(executor).map_err(companion::fault_violation)?;
    coordinator.counters.requests_replayed =
        coordinator.counters.requests_replayed.saturating_add(1);
    send(coordinator, context, link, identity.peer, output);
    Ok(())
}

fn send(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    mut output: Output,
) {
    let backing = output.backing();
    for line in output.drain() {
        let Some(live) = coordinator
            .peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .filter(|live| live.link == link)
        else {
            return;
        };
        if let Err(refusal) = live
            .handle
            .try_send_backed(line, std::sync::Arc::clone(&backing))
        {
            coordinator.send_failed(context, link, peer, SendFailure::from(refusal));
            return;
        }
    }
}
