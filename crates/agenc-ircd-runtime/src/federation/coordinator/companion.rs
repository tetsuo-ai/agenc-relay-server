//! Companion traffic on the coordinator owner: admitted `E*` frames feed
//! the executor with the base facts it mirrors, each complete request runs
//! against the state core as one batch, snapshot READY records stage their
//! own batch, and committed lines go out over the live links.

pub(super) mod ack_read;
#[cfg(test)]
#[path = "companion/tests/page_output.rs"]
mod page_output_tests;
pub(super) mod page_read;

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_domain::federation::{OriginKey, OriginStatus, OriginTable};
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_federation_wire::FederationLineText;
use agenc_ircd_storage::federation_records::PeerPhase;
use agenc_ircd_types::{MonotonicTick, OriginId, ServerId, ServerIncarnation};

use super::barriers;
use super::{FederationCoordinator, PeerState, PendingCommit, SendFailure, Violation};
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

pub(super) fn fault_violation(fault: CompanionFault) -> Violation {
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
    trusted_ack_unix_seconds: Option<u64>,
    backing: crate::budget::BackingReservationPort,
    origins: &'a OriginTable,
    peers: &'a BTreeMap<ServerId, PeerState>,
    revision: u64,
    /// The peer the frame came from.
    peer: ServerId,
    /// The channel instances of bound routes the frame's peer holds.
    held_channels: BTreeSet<[u8; 16]>,
}

impl CompanionHost for HostView<'_> {
    fn trusted_ack_unix_seconds(&self) -> Option<u64> {
        self.trusted_ack_unix_seconds
    }
    fn reserve_cut_backing(
        &self,
        capacity: usize,
    ) -> Result<crate::budget::MemoryPermit, CompanionFault> {
        self.backing
            .reserve(capacity)
            .map_err(|_| CompanionFault::Ceiling)
    }

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

    fn holds_channel(&self, instance: [u8; 16]) -> bool {
        self.held_channels.contains(&instance)
    }

    fn hosts_account(&self, account: &[u8; 24]) -> bool {
        let Some(incarnation) = self
            .peers
            .get(&self.peer)
            .and_then(|state| state.live.as_ref())
            .map(|live| live.incarnation)
        else {
            return false;
        };
        self.origins
            .origins_of(self.peer, incarnation)
            .filter(|(_, entry)| entry.status == OriginStatus::Live)
            .filter_map(|(_, entry)| entry.principal.account)
            .any(|(held, _)| held.to_text().as_bytes() == account)
    }
}

/// The channel instances of bound routes that `peer` holds in the base
/// projection, computed before the executor is borrowed.
fn held_channels(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    peer: ServerId,
) -> BTreeSet<[u8; 16]> {
    let Some(standing) = context
        .federation()
        .and_then(|projector| projector.index().edge(peer))
    else {
        return BTreeSet::new();
    };
    coordinator
        .companion_exec
        .as_ref()
        .map(|executor| executor.state.routes.routes())
        .into_iter()
        .flatten()
        .filter_map(|route| match route.target {
            agenc_ircd_domain::e2ee::RouteTarget::Channel(instance) => Some(instance),
            agenc_ircd_domain::e2ee::RouteTarget::Direct(_) => None,
        })
        .filter(|instance| standing.holds_channel(*instance))
        .map(|instance| *instance.as_bytes())
        .collect()
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
        trusted_ack_unix_seconds: context
            .utc_now()
            .ok()
            .filter(|wall| context.drift().accepts_wall(context.now(), *wall))
            .map(|wall| wall.get()),
        backing: context.backing_reservations(),
        origins: &coordinator.origins,
        peers: &coordinator.peers,
        revision,
        peer,
        held_channels: held_channels(coordinator, context, peer),
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
    Ok(())
}

/// Closes a barrier once both streams acknowledged it: the base outbox
/// replays from the row after the barrier and the companion stream resends
/// its later rows.
pub(super) fn try_close_barrier(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let Some(barrier) = coordinator.barriers.get(&peer).cloned() else {
        return;
    };
    if !(barrier.base_acked() && barrier.companion_acked()) {
        return;
    }
    coordinator.barriers.remove(&peer);
    if let Some(stream) = coordinator
        .companion_exec
        .as_mut()
        .and_then(|executor| executor.state.streams.get_mut(&peer))
    {
        stream.hold_after = None;
    }
    let resumable = coordinator
        .peers
        .get(&peer)
        .is_some_and(|state| state.live.is_some() && state.active && state.resend.is_none());
    if resumable {
        super::snapshot::start_resend(
            coordinator,
            context,
            peer,
            barrier.base().last().saturating_add(1),
        );
    }
    let lines = coordinator
        .companion_exec
        .as_ref()
        .filter(|executor| executor.delivering(peer))
        .map(|executor| executor.retransmit_after(peer, barrier.companion().last()));
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

/// Adopts only the exact gate carried by the committed projection.
fn open_barriers(
    coordinator: &mut FederationCoordinator,
    planned: &[BarrierPlanned],
    events: &[OutboundEvent],
) -> Result<(), CompanionFault> {
    for planned in planned {
        let mut gates = events
            .iter()
            .filter(|event| event.target == planned.target)
            .filter_map(|event| event.combined_barrier.as_deref())
            .filter(|gate| gate.mutation_id() == planned.mutation_id);
        let gate = gates.next().ok_or(CompanionFault::Storage)?;
        if gates.next().is_some()
            || coordinator.barriers.contains_key(&planned.target)
            || !matches_planned(gate, planned)
        {
            return Err(CompanionFault::Storage);
        }
        let stream = coordinator
            .companion_exec
            .as_mut()
            .and_then(|executor| executor.state.streams.get_mut(&planned.target))
            .ok_or(CompanionFault::Storage)?;
        stream.hold_after = Some(gate.companion().last());
        coordinator.barriers.insert(planned.target, gate.clone());
    }
    Ok(())
}

fn matches_planned(gate: &super::OpenBarrier, planned: &BarrierPlanned) -> bool {
    gate.scope() == &planned.companion_scope
        && gate.companion() == &planned.companion
        && gate.state_generation() == planned.state_generation
        && gate.part_count() == planned.part_count
        && gate
            .base()
            .last()
            .checked_sub(gate.base().first())
            .and_then(|n| n.checked_add(1))
            == Some(u64::from(planned.base_parts))
        && !gate.base_acked()
        && !gate.companion_acked()
}

pub(super) fn apply(
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
        Action::SendPage(output) => {
            send_page(coordinator, context, link, peer, output);
            Ok(())
        }
        Action::ReadSnapshotPage(request) => page_read::submit(coordinator, context, request),
        Action::ReadAcknowledgement(request) => ack_read::submit(coordinator, context, *request),
        Action::ReadResponses(identity) => {
            super::response_read::submit(coordinator, context, link, peer, identity)
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
    let replay_busy = coordinator.replay_io_busy();
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return Err(Violation::Companion(CompanionViolation::Unsupported));
    };
    if !executor.accepting_requests(peer) {
        return Err(Violation::Companion(CompanionViolation::Request));
    }
    if coordinator.pending.is_some() || replay_busy || executor.has_pending() {
        return executor
            .enqueue(link, peer, complete)
            .map_err(fault_violation);
    }
    run(coordinator, context, link, peer, complete)
}

/// Raw writes must drop before the work's backing reservations on every refusal.
struct StagedCompanion {
    writes: Vec<AccountServiceDurableWrite>,
    work: PendingWork,
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
    let staged = StagedCompanion { writes, work };
    if coordinator.pending.is_some() {
        return Err(Violation::Ceiling);
    }
    let resume = matches!(&staged.work, PendingWork::Acknowledgement(ack) if ack.resumes());
    let barrier = match &staged.work {
        PendingWork::Acknowledgement(ack) => {
            let position = ack.position();
            if ack.peer() != peer {
                return Err(Violation::Codec);
            }
            barriers::prepare(
                coordinator,
                peer,
                barriers::Side::Companion,
                position.delivery_sequence,
                position.event_id,
            )?
        }
        _ => None,
    };
    if resume && barrier.is_none() {
        return Err(Violation::Acknowledgement);
    }
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let (mut writes, owners) = revised_writes(coordinator, context, staged.writes, revision)?;
    if let Some(update) = &barrier {
        writes.push(update.write(revision)?);
    }
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|_| Violation::Ceiling)?;
    if let Some(executor) = coordinator.companion_exec.as_mut() {
        executor.set_pending(staged.work);
        if let Some(owners) = owners {
            executor.set_pending_owners(owners);
        }
    }
    coordinator.pending = Some(PendingCommit::Companion {
        peer,
        link,
        barrier,
        resume,
    });
    Ok(())
}

/// Stages the batch's ownership accounts and restamps every row at the
/// batch revision.
fn revised_writes(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    writes: Vec<AccountServiceDurableWrite>,
    revision: u64,
) -> Result<
    (
        Vec<AccountServiceDurableWrite>,
        Option<crate::e2ee::coordinator::owners::Staged>,
    ),
    Violation,
> {
    let mut writes = writes;
    let owners = coordinator
        .companion_exec
        .as_ref()
        .map(|executor| {
            executor.stage_owners(
                &mut writes,
                super::trusted_unix_now(context).unwrap_or(0),
                false,
                revision,
            )
        })
        .transpose()
        .map_err(|_| Violation::Ceiling)?;
    let writes = writes
        .into_iter()
        .map(|write| write.at_revision(revision))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Violation::Ceiling)?;
    Ok((writes, owners))
}

fn run(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    complete: CompleteRequest,
) -> Result<(), Violation> {
    run_with_object(coordinator, context, link, peer, complete, None)
}

pub(super) fn run_with_object(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    complete: CompleteRequest,
    resolved: Option<&crate::e2ee::coordinator::object_read::Resolved>,
) -> Result<(), Violation> {
    let peers: Vec<ServerId> = coordinator.peers.keys().copied().collect();
    let origins = &coordinator.origins;
    let facts_for = |key: OriginKey| OriginFacts {
        user_id: origins
            .origin(&key)
            .and_then(|entry| entry.principal.session)
            .map(|(_, user_id)| user_id),
    };
    let open = &coordinator.barriers;
    let peer_states = &coordinator.peers;
    let config = &coordinator.config;
    let base_capacity = Box::new(move |target: ServerId, count: usize, bytes: u64| {
        !open.contains_key(&target)
            && peer_states.get(&target).is_none_or(|state| {
                let objects = u64::try_from(state.outbox.unacked.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
                objects <= config.outbox_objects_per_edge
                    && state.outbox.unacked_bytes.saturating_add(bytes)
                        <= config.outbox_bytes_per_edge
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
    let staged = match resolved {
        Some(resolved) => execute::run_with_object(
            executor,
            view,
            link,
            peer,
            complete,
            &facts_for,
            Some(resolved),
        ),
        None => execute::run(executor, view, link, peer, complete, &facts_for),
    }
    .map_err(code_violation)?;
    match staged {
        Staged::ReadObject(request) => {
            super::object_read::submit(coordinator, context, link, peer, request)
        }
        Staged::ReadResponses(identity) => {
            super::response_read::submit(coordinator, context, link, peer, identity)
        }
        Staged::Batch => {
            coordinator.pending = Some(PendingCommit::Companion {
                peer,
                link,
                barrier: None,
                resume: false,
            });
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
        .is_some_and(|(barrier, sequence)| sequence > barrier.companion().last());
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
    barrier: Option<Box<barriers::Prepared>>,
    resume: bool,
) {
    let epoch = coordinator
        .peers
        .get(&peer)
        .map(|state| state.client_resync_epoch);
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return;
    };
    executor.state.mailbox_snapshot_now = executor
        .state
        .mailbox_snapshot_now
        .max(tick_millis(context.now()));
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
    if (barrier.is_some() || resume)
        && !matches!(committed, Committed::Acknowledged(target) if target == peer)
    {
        super::startup::fail_restore(coordinator);
        return;
    }
    match committed {
        Committed::Lines(lines) => {
            for (target, line) in lines {
                send_lines(coordinator, context, link, target, vec![line]);
            }
        }
        Committed::Snapshot(publication) => {
            continue_snapshot(coordinator, context, publication);
        }
        Committed::Fetch(publication) => continue_fetch(coordinator, context, publication),
        Committed::Acknowledged(target) => {
            committed_ack(coordinator, context, link, target, barrier, resume)
        }
        Committed::Request(pending) => {
            let lines = execute::committed_lines(&*executor, &pending);
            if open_barriers(coordinator, &pending.barriers, events).is_err() {
                super::startup::fail_restore(coordinator);
                return;
            }
            request_committed(coordinator, context, link, peer, lines);
        }
    }
}

fn committed_ack(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    target: ServerId,
    barrier: Option<Box<barriers::Prepared>>,
    resume: bool,
) {
    if barrier.is_some_and(|update| update.apply(coordinator).is_err()) {
        super::startup::fail_restore(coordinator);
        return;
    }
    if resume {
        let lines = coordinator
            .companion_exec
            .as_mut()
            .ok_or(CompanionFault::Storage)
            .and_then(|executor| executor.resume_ack_committed(target, link));
        match lines {
            Ok(lines) => send_lines(coordinator, context, link, target, lines),
            Err(_) => {
                super::startup::fail_restore(coordinator);
                return;
            }
        }
    }
    try_close_barrier(coordinator, context, target);
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
    schedule_mailbox_expiry(coordinator, context);
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
            None => send_response(coordinator, context, link, peer, committed),
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

fn send_response(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    committed: CommittedLine,
) {
    let Some(backing) = committed.backing else {
        send_lines(coordinator, context, link, peer, vec![committed.line]);
        return;
    };
    let Some(live) = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.live.as_ref())
        .filter(|live| live.link == link)
    else {
        return;
    };
    if let Err(refusal) = live.handle.try_send_backed(committed.line, backing) {
        coordinator.send_failed(context, link, peer, SendFailure::from(refusal));
    }
}

fn schedule_mailbox_expiry(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
) {
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return;
    };
    let snapshots = &mut executor.state.mailbox_snapshots;
    snapshots.expire(tick_millis(context.now()));
    let Some(deadline) = snapshots.next_expiry() else {
        executor.state.mailbox_expiry_armed = None;
        context
            .timers_mut()
            .cancel(TimerKind::MailboxSnapshotExpiry, TimedId::Global);
        return;
    };
    if crate::e2ee::coordinator::ops::mailbox_snapshot::reserve_expiry(
        context.timers_mut(),
        deadline,
        &mut executor.state.mailbox_expiry_armed,
    )
    .is_err()
    {
        // A timer refusal cannot invalidate a durable plan or leave unbounded retention.
        *snapshots = Default::default();
    }
}

pub(super) fn mailbox_timer_fired(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    entry: TimerEntry,
) -> bool {
    if (entry.kind, entry.id) != (TimerKind::MailboxSnapshotExpiry, TimedId::Global) {
        return false;
    }
    if let Some(executor) = coordinator.companion_exec.as_mut() {
        executor.state.mailbox_expiry_armed = None;
    }
    schedule_mailbox_expiry(coordinator, context);
    true
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
    while coordinator.pending.is_none() && !coordinator.replay_io_busy() {
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

/// Reserves the next bounded page only after its predecessor's exact receipt.
fn continue_snapshot(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    publication: Box<crate::e2ee::coordinator::sync::SnapshotPublication>,
) {
    let peer = publication.peer();
    let link = publication.link();
    let host = HostView {
        trusted_ack_unix_seconds: None,
        backing: context.backing_reservations(),
        origins: &coordinator.origins,
        peers: &coordinator.peers,
        revision: context.domain().revision().get(),
        peer,
        held_channels: BTreeSet::new(),
    };
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return;
    };
    let actions =
        executor.continue_snapshot_publication(*publication, tick_millis(context.now()), &host);
    let result = actions.map_err(fault_violation).and_then(|actions| {
        for action in actions {
            apply(coordinator, context, link, peer, action)?;
        }
        Ok(())
    });
    if let Err(error) = result {
        coordinator.fail_link(context, link, peer, error);
    }
}

/// The output lease lives through the final queue transfer or refused-line drop.
fn send_page(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    mut output: crate::e2ee::coordinator::sync::SnapshotPageOutput,
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

fn continue_fetch(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    publication: Box<crate::e2ee::coordinator::sync::FetchPublication>,
) {
    let peer = publication.peer();
    let link = publication.link();
    let host = HostView {
        trusted_ack_unix_seconds: None,
        backing: context.backing_reservations(),
        origins: &coordinator.origins,
        peers: &coordinator.peers,
        revision: context.domain().revision().get(),
        peer,
        held_channels: BTreeSet::new(),
    };
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return;
    };
    let result = publication
        .committed(executor, tick_millis(context.now()), &host)
        .map_err(fault_violation)
        .and_then(|actions| {
            for action in actions {
                apply(coordinator, context, link, peer, action)?;
            }
            Ok(())
        });
    if let Err(error) = result
        && coordinator.link_is_live(link, peer)
    {
        coordinator.fail_link(context, link, peer, error);
    }
}

#[cfg(test)]
#[path = "companion/tests/transfer.rs"]
mod transfer_tests;

#[cfg(test)]
#[path = "companion/tests/host_view.rs"]
mod host_view_tests;
