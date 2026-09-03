//! Companion traffic on the coordinator owner: admitted `E*` frames feed
//! the executor with the base facts it mirrors, each complete request runs
//! against the state core as one batch, snapshot READY records stage their
//! own batch, and committed lines go out over the live links.

use std::collections::BTreeMap;

use agenc_ircd_domain::federation::{OriginKey, OriginStatus, OriginTable};
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_federation_wire::FederationLineText;
use agenc_ircd_storage::federation_records::PeerPhase;
use agenc_ircd_types::{MonotonicTick, OriginId, ServerId, ServerIncarnation};

use super::{FederationCoordinator, OpenBarrier, PeerState, PendingCommit, SendFailure, Violation};
use crate::e2ee::coordinator::execute::{
    self, BarrierPlanned, BaseView, CommittedLine, OriginFacts, Staged,
};
use crate::e2ee::coordinator::sync::{
    Action, BaseOriginView, Committed, CompanionHost, PendingWork,
};
use crate::e2ee::coordinator::{CompanionFault, CompanionOriginKey, CompleteRequest};
use crate::e2ee::link::{CompanionViolation, tick_millis};
use crate::federation::LinkId;
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::projector::OutboundEvent;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};

fn fault_violation(fault: CompanionFault) -> Violation {
    match fault {
        CompanionFault::Protocol | CompanionFault::Assembly(_) => {
            Violation::Companion(CompanionViolation::Request)
        }
        CompanionFault::Ceiling => Violation::Ceiling,
        CompanionFault::Storage => Violation::Companion(CompanionViolation::Executor),
    }
}

fn code_violation(code: E2eeReplyCode) -> Violation {
    match code {
        E2eeReplyCode::RateLimited => Violation::Companion(CompanionViolation::Executor),
        _ => Violation::Companion(CompanionViolation::Request),
    }
}

/// The base facts the executor mirrors, borrowed from the owner's tables.
struct HostView<'a> {
    origins: &'a OriginTable,
    peers: &'a BTreeMap<ServerId, PeerState>,
    revision: u64,
}

impl CompanionHost for HostView<'_> {
    fn live_incarnation(&self, peer: ServerId) -> Option<[u8; 16]> {
        self.peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .map(|live| *live.incarnation.as_bytes())
    }

    fn base_origin(&self, key: &CompanionOriginKey) -> Option<BaseOriginView> {
        let base = OriginKey {
            home_server_id: ServerId::from_bytes(key.home_server_id),
            server_incarnation: ServerIncarnation::from_bytes(key.server_incarnation),
            origin_id: OriginId::from_bytes(key.origin_id),
        };
        let entry = self.origins.origin(&base)?;
        if entry.status != OriginStatus::Live {
            return None;
        }
        let account = entry.principal.account.and_then(|(account, generation)| {
            let text = account.to_text();
            let bytes: [u8; 24] = text.as_bytes().try_into().ok()?;
            Some((bytes, generation.get()))
        });
        if entry.principal.account.is_some() && account.is_none() {
            return None;
        }
        Some(BaseOriginView {
            generation: entry.generation,
            connection_id: *entry.binding.connection_id.as_bytes(),
            connection_nonce: entry.binding.connection_nonce,
            session: entry
                .principal
                .session
                .map(|(session, user)| (*session.as_bytes(), *user.as_bytes())),
            account,
        })
    }

    fn base_origins_ready(&self, peer: ServerId) -> bool {
        self.peers
            .get(&peer)
            .is_some_and(|state| state.phase == PeerPhase::Ready)
    }

    fn base_resync_epoch(&self, peer: ServerId) -> u64 {
        self.peers
            .get(&peer)
            .map_or(0, |state| state.client_resync_epoch)
    }

    fn state_generation(&self) -> u64 {
        self.revision
    }
}

/// Feeds one admitted frame to the executor and applies what it asks for.
pub(super) fn admitted(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    frame: CompanionFrame,
) -> Result<(), Violation> {
    let now = tick_millis(context.now());
    let revision = context.domain().revision().get();
    let host = HostView {
        origins: &coordinator.origins,
        peers: &coordinator.peers,
        revision,
    };
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return Err(Violation::Companion(CompanionViolation::Unsupported));
    };
    let actions = executor
        .on_frame(link, peer, frame, now, &host, context.entropy_mut())
        .map_err(fault_violation)?;
    for action in actions {
        apply(coordinator, context, link, peer, action)?;
    }
    companion_acknowledged(coordinator, context, peer);
    Ok(())
}

/// Marks the companion half of an open barrier acknowledged once the
/// stream's cumulative ACK reached its last part, and releases the barrier
/// when the base half is acknowledged too.
fn companion_acknowledged(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let acked = coordinator
        .companion_exec
        .as_ref()
        .and_then(|executor| executor.acked_through(peer));
    let Some(barrier) = coordinator.barriers.get_mut(&peer) else {
        return;
    };
    if barrier.companion_acked || acked.is_none_or(|acked| acked < barrier.companion_last) {
        return;
    }
    barrier.companion_acked = true;
    try_close_barrier(coordinator, context, peer);
}

/// Closes a barrier once both streams acknowledged it: the base outbox
/// replays from the row after the barrier and the companion stream resends
/// its later rows.
pub(super) fn try_close_barrier(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let Some(barrier) = coordinator.barriers.get(&peer).copied() else {
        return;
    };
    if !(barrier.base_acked && barrier.companion_acked) {
        return;
    }
    coordinator.barriers.remove(&peer);
    let resumable = coordinator
        .peers
        .get(&peer)
        .is_some_and(|state| state.live.is_some() && state.active && state.resend.is_none());
    if resumable {
        super::snapshot::start_resend(
            coordinator,
            context,
            peer,
            barrier.base_last.saturating_add(1),
        );
    }
    let lines = coordinator
        .companion_exec
        .as_ref()
        .filter(|executor| executor.delivering(peer))
        .map(|executor| executor.retransmit_after(peer, barrier.companion_last));
    let Some(target_link) = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.live.as_ref())
        .map(|live| live.link)
    else {
        return;
    };
    match lines {
        Some(Ok(lines)) => send_lines(coordinator, context, target_link, peer, lines),
        Some(Err(_)) => coordinator.fail_link(
            context,
            target_link,
            peer,
            Violation::Companion(CompanionViolation::Executor),
        ),
        None => {}
    }
}

/// Records the barriers a committed batch opened, reading each target's
/// last base part from the batch's outbound events.
fn open_barriers(
    coordinator: &mut FederationCoordinator,
    planned: &[BarrierPlanned],
    events: &[OutboundEvent],
) -> Result<(), CompanionFault> {
    for barrier in planned {
        let sequences: Vec<u64> = events
            .iter()
            .filter(|event| event.target == barrier.target)
            .map(|event| event.delivery_sequence)
            .collect();
        let base_last = sequences.iter().copied().max();
        let consistent = sequences.len() == usize::from(barrier.base_parts)
            && !coordinator.barriers.contains_key(&barrier.target);
        let (true, Some(base_last)) = (consistent, base_last) else {
            return Err(CompanionFault::Storage);
        };
        coordinator.barriers.insert(
            barrier.target,
            OpenBarrier {
                mutation_id: barrier.mutation_id,
                base_last,
                base_acked: false,
                companion_last: barrier.companion_last,
                companion_acked: false,
            },
        );
    }
    Ok(())
}

fn apply(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    action: Action,
) -> Result<(), Violation> {
    match action {
        Action::Execute(complete) => execute_or_queue(coordinator, context, link, peer, complete),
        Action::Send(lines) => {
            send_lines(coordinator, context, link, peer, lines);
            Ok(())
        }
        Action::Stage { writes, work } => stage(coordinator, context, link, peer, writes, work),
        Action::ScheduleExpiry { at_millis } => {
            let _ = context.timers_mut().schedule(
                MonotonicTick::from_ticks(at_millis),
                TimerKind::CompanionSnapshotExpiry,
                TimedId::Peer(peer),
            );
            Ok(())
        }
    }
}

fn execute_or_queue(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    complete: CompleteRequest,
) -> Result<(), Violation> {
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return Err(Violation::Companion(CompanionViolation::Unsupported));
    };
    if !executor.accepting_requests(peer) {
        return Err(Violation::Companion(CompanionViolation::Request));
    }
    if coordinator.pending.is_some() || executor.has_pending() {
        return executor
            .enqueue(link, peer, complete)
            .map_err(fault_violation);
    }
    run(coordinator, context, link, peer, complete)
}

/// Stages one executor batch beside a checkpoint plan.
fn stage(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    writes: Vec<AccountServiceDurableWrite>,
    work: PendingWork,
) -> Result<(), Violation> {
    if coordinator.pending.is_some() {
        return Err(Violation::Ceiling);
    }
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let writes = writes
        .into_iter()
        .map(|write| write.at_revision(revision))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Violation::Ceiling)?;
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|_| Violation::Ceiling)?;
    if let Some(executor) = coordinator.companion_exec.as_mut() {
        executor.set_pending(work);
    }
    coordinator.pending = Some(PendingCommit::Companion { peer, link });
    Ok(())
}

fn run(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    complete: CompleteRequest,
) -> Result<(), Violation> {
    let peers: Vec<ServerId> = coordinator.peers.keys().copied().collect();
    let origins = &coordinator.origins;
    let facts_for = |key: OriginKey| OriginFacts {
        user_id: origins
            .origin(&key)
            .and_then(|entry| entry.principal.session)
            .map(|(_, user_id)| user_id),
    };
    let peer_states = &coordinator.peers;
    let config = &coordinator.config;
    let base_capacity = Box::new(move |target: ServerId, count: usize, bytes: u64| {
        peer_states.get(&target).is_none_or(|state| {
            let objects = u64::try_from(state.outbox.unacked.len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            objects <= config.outbox_objects_per_edge
                && state.outbox.unacked_bytes.saturating_add(bytes) <= config.outbox_bytes_per_edge
        })
    });
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return Err(Violation::Companion(CompanionViolation::Unsupported));
    };
    let view = BaseView {
        context,
        peers,
        base_capacity,
    };
    let staged =
        execute::run(executor, view, link, peer, complete, &facts_for).map_err(code_violation)?;
    match staged {
        Staged::Batch => {
            coordinator.pending = Some(PendingCommit::Companion { peer, link });
            Ok(())
        }
        Staged::Replay(lines) => {
            coordinator.counters.requests_replayed =
                coordinator.counters.requests_replayed.saturating_add(1);
            send_lines(coordinator, context, link, peer, lines);
            Ok(())
        }
    }
}

/// Sends `lines` to the live link of `peer`, retiring the link on refusal.
fn send_lines(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    lines: Vec<FederationLineText>,
) {
    for line in lines {
        let Some(live) = coordinator
            .peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .filter(|live| live.link == link)
        else {
            return;
        };
        if let Err(refusal) = live.handle.try_send(line) {
            coordinator.send_failed(context, link, peer, SendFailure::from(refusal));
            return;
        }
    }
}

/// Sends one event copy to `target`'s live link when its companion
/// delivery is active and no open barrier holds it; a target that is not
/// delivering keeps the durable row for its resume.
fn send_to_target(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    target: ServerId,
    sequence: Option<u64>,
    line: FederationLineText,
) {
    let held = coordinator
        .barriers
        .get(&target)
        .zip(sequence)
        .is_some_and(|(barrier, sequence)| sequence > barrier.companion_last);
    let delivering = coordinator
        .companion_exec
        .as_ref()
        .is_some_and(|executor| executor.delivering(target));
    if held {
        return;
    }
    let Some(target_link) = coordinator
        .peers
        .get(&target)
        .and_then(|state| state.live.as_ref())
        .map(|live| live.link)
    else {
        return;
    };
    if !delivering || !coordinator.companion.profile_active(target_link) {
        return;
    }
    coordinator.counters.events_sent = coordinator.counters.events_sent.saturating_add(1);
    send_lines(coordinator, context, target_link, target, vec![line]);
}

/// Finishes the companion batch that just committed.
pub(super) fn committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    events: &[OutboundEvent],
) {
    let epoch = coordinator
        .peers
        .get(&peer)
        .map(|state| state.client_resync_epoch);
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return;
    };
    let committed = match executor.batch_applied(epoch) {
        Ok(Some(committed)) => committed,
        Ok(None) => return,
        Err(_) => {
            coordinator.fail_link(
                context,
                link,
                peer,
                Violation::Companion(CompanionViolation::Executor),
            );
            return;
        }
    };
    match committed {
        Committed::Lines(lines) => {
            for (target, line) in lines {
                send_to_target(coordinator, context, target, None, line);
            }
        }
        Committed::Request(pending) => {
            let lines = execute::committed_lines(&*executor, &pending);
            let lines = match open_barriers(coordinator, &pending.barriers, events) {
                Ok(()) => lines,
                Err(_) => Err(E2eeReplyCode::RateLimited),
            };
            request_committed(coordinator, context, link, peer, lines);
        }
    }
}

/// Answers the requester and delivers the event copies of one committed
/// request.
fn request_committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    lines: Result<Vec<CommittedLine>, E2eeReplyCode>,
) {
    coordinator.counters.requests_committed =
        coordinator.counters.requests_committed.saturating_add(1);
    let Ok(lines) = lines else {
        coordinator.fail_link(
            context,
            link,
            peer,
            Violation::Companion(CompanionViolation::Executor),
        );
        return;
    };
    for committed in lines {
        match committed.sequence {
            None => send_lines(coordinator, context, link, peer, vec![committed.line]),
            Some(sequence) => send_to_target(
                coordinator,
                context,
                committed.target,
                Some(sequence),
                committed.line,
            ),
        }
    }
}

/// The base origin set of `peer` became ready: the companion READY goes
/// out if its RESET was already accepted.
pub(super) fn base_ready(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    incarnation: ServerIncarnation,
) {
    let Some(link) = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.live.as_ref())
        .map(|live| live.link)
    else {
        return;
    };
    let ready = coordinator
        .companion_exec
        .as_mut()
        .map(|executor| executor.origins_ready(peer, *incarnation.as_bytes()));
    match ready {
        Some(Ok(Some(line))) => send_lines(coordinator, context, link, peer, vec![line]),
        Some(Err(_)) => coordinator.fail_link(
            context,
            link,
            peer,
            Violation::Companion(CompanionViolation::Executor),
        ),
        Some(Ok(None)) | None => {}
    }
}

/// Fails the link whose ESTATE token expired.
pub(super) fn snapshot_timer_fired(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    entry: TimerEntry,
) -> bool {
    let (TimerKind::CompanionSnapshotExpiry, TimedId::Peer(peer)) = (entry.kind, entry.id) else {
        return false;
    };
    let expired = coordinator
        .companion_exec
        .as_mut()
        .is_some_and(|executor| executor.snapshot_expired(peer, tick_millis(entry.deadline)));
    let live_link = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.live.as_ref())
        .map(|live| live.link);
    if let (true, Some(link)) = (expired, live_link) {
        coordinator.fail_link(
            context,
            link,
            peer,
            Violation::Companion(CompanionViolation::SnapshotExpired),
        );
    }
    true
}

/// Runs queued companion requests while no batch is in flight.
pub(super) fn drain_queued(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
) {
    while coordinator.pending.is_none() {
        let Some(queued) = coordinator
            .companion_exec
            .as_mut()
            .and_then(|executor| executor.dequeue())
        else {
            return;
        };
        if !coordinator.link_is_live(queued.link, queued.peer) {
            continue;
        }
        let complete = CompleteRequest {
            correlation: queued.correlation,
            request: queued.request,
            payload: queued.payload,
        };
        if let Err(violation) = run(coordinator, context, queued.link, queued.peer, complete) {
            coordinator.fail_link(context, queued.link, queued.peer, violation);
        }
    }
}
