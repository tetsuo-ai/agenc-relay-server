//! The execution glue: one complete companion request runs against the
//! committed state, its result, response objects, replay row, and ordered
//! event copies are staged as one durable batch beside a checkpoint plan,
//! and after commit the effects apply and the lines go out.

use agenc_ircd_domain::e2ee::projection::{
    Completion, EventKind, EventPlan, Opcode, PlannedEvent, completion_for, plan_barriers,
};
use agenc_ircd_domain::federation::OriginKey as BaseOriginKey;
use agenc_ircd_domain::federation::{MutationContext, session_record_from};
use agenc_ircd_e2ee::federation::frames::{CompanionFrame, Correlation};
use std::collections::BTreeMap;

use agenc_ircd_e2ee::limits::S2S_IDEMPOTENCY_RETENTION_SECONDS;
use agenc_ircd_e2ee::wire::fragment::fragment_object;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_federation_wire::CanonicalEncode;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{BarrierEndpoint, DeliveryScope};
use agenc_ircd_types::{ChannelInstanceId, OriginId, ServerId, ServerIncarnation, UserId};

use super::ConversationState;
use super::events::{self, BarrierAssignment, EventContent};
use super::ops::{self, Exec, Fail};
use super::request::{self, Classified, Decoded, Outcome, ResponseObject};
use super::{
    CompanionCoordinator, CompanionOrigin, CompanionOriginKey, CompleteRequest, PendingCompanion,
    StoredResult,
};
use crate::federation::LinkId;
use crate::federation::codec::source_view_object;
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::projector::CrossProfileAssignment;

/// A security-state mutation stays replayable for seven days (companion
/// 12.5).
pub const SECURITY_MUTATION_REPLAY_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Random blocks drawn before a handler runs, so handlers never touch the
/// state core while the base view is borrowed.
const ENTROPY_POOL_BLOCKS: usize = 64;

#[cfg(test)]
#[path = "tests/origin_replay.rs"]
mod origin_replay;

#[cfg(test)]
#[path = "tests/successor_authority.rs"]
mod successor_authority;

/// A bounded pool of random bytes drawn from the state core up front.
struct EntropyPool {
    blocks: Vec<[u8; 32]>,
}

impl EntropyPool {
    fn fill(source: &mut dyn agenc_ircd_types::EntropySource) -> Result<Self, E2eeReplyCode> {
        let mut blocks = Vec::with_capacity(ENTROPY_POOL_BLOCKS);
        for _ in 0..ENTROPY_POOL_BLOCKS {
            let mut block = [0; 32];
            source
                .fill_exact(&mut block)
                .map_err(|_| E2eeReplyCode::RateLimited)?;
            blocks.push(block);
        }
        Ok(Self { blocks })
    }
}

impl agenc_ircd_types::EntropySource for EntropyPool {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), agenc_ircd_types::EntropyError> {
        let mut offset = 0;
        while offset < destination.len() {
            let block = self
                .blocks
                .pop()
                .ok_or(agenc_ircd_types::EntropyError::Unavailable)?;
            let take = (destination.len() - offset).min(block.len());
            if let (Some(target), Some(source)) = (
                destination.get_mut(offset..offset + take),
                block.get(..take),
            ) {
                target.copy_from_slice(source);
            }
            offset += take;
        }
        Ok(())
    }
}

/// What the owner must do with an executed request.
pub enum Staged {
    /// The batch is staged; the owner marks its pending commit.
    Batch,
    /// An exact replay; the lines to resend immediately.
    Replay(Vec<agenc_ircd_federation_wire::FederationLineText>),
    /// A retained response set needs exact object reads before any output.
    ReadResponses(super::response_read::Identity),
    /// A fresh authorized object lookup must complete before its result is staged.
    ReadObject(super::object_read::PendingRequest),
}

/// Everything the owner supplies about the base state for one execution.
pub struct BaseView<'a> {
    /// The state core context.
    pub context: &'a mut StateCoreContext,
    /// Every configured edge.
    pub peers: Vec<ServerId>,
    /// Whether `target`'s base outbox admits `count` more events of
    /// `bytes` under its unacknowledged ceilings (spec 20.8).
    pub base_capacity: Box<dyn Fn(ServerId, usize, u64) -> bool + 'a>,
}

/// One cross-profile barrier the batch opens at one target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierPlanned {
    /// The target edge.
    pub target: ServerId,
    /// The per-target mutation identity.
    pub mutation_id: [u8; 16],
    /// Base parts, indices `0..base_parts`.
    pub base_parts: u16,
    /// Base plus companion parts.
    pub part_count: u16,
    /// The transaction's shared state generation.
    pub state_generation: u64,
    /// The full accepted companion delivery scope.
    pub companion_scope: DeliveryScope,
    /// The complete companion endpoint, including its final event identity.
    pub companion: BarrierEndpoint,
}

/// The base origin principal the companion origin mirrors.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OriginFacts {
    /// The base session user identity, if the origin has a session.
    pub user_id: Option<UserId>,
}

fn source_view_bytes(context: &StateCoreContext, facts: OriginFacts) -> Vec<u8> {
    let Some(user_id) = facts.user_id else {
        return Vec::new();
    };
    let domain = context.domain();
    let Some(session) = domain.durable_session(user_id) else {
        return Vec::new();
    };
    let label = session
        .account_id
        .and_then(|account| domain.durable_account(account))
        .and_then(|account| account.label);
    let record = session_record_from(&session, label);
    source_view_object(&record.source_view())
        .ok()
        .and_then(|object| object.encode_canonical().ok())
        .map(|bytes| bytes.as_slice().to_vec())
        .unwrap_or_default()
}

/// The base origin facts of a companion origin, read from the base origin
/// table the owner holds.
#[must_use]
pub fn base_origin_key(origin: &CompanionOrigin) -> BaseOriginKey {
    BaseOriginKey {
        home_server_id: ServerId::from_bytes(origin.home_server_id),
        server_incarnation: ServerIncarnation::from_bytes(origin.server_incarnation),
        origin_id: OriginId::from_bytes(origin.origin_id),
    }
}

/// Executes one complete request and stages its batch. Returns the exact
/// replay lines when the request was a duplicate.
pub fn run(
    coordinator: &mut CompanionCoordinator,
    view: BaseView<'_>,
    link: LinkId,
    peer: ServerId,
    complete: CompleteRequest,
    facts_for: &dyn Fn(BaseOriginKey) -> OriginFacts,
) -> Result<Staged, E2eeReplyCode> {
    run_with_object(coordinator, view, link, peer, complete, facts_for, None)
}

// agenc-review: focus owner=runtime reviewed=2026-09-08 reason=one request preserves ordered decode, replay admission, optional object-read suspension, authorization, sequencing, and atomic staging
pub(crate) fn run_with_object(
    coordinator: &mut CompanionCoordinator,
    view: BaseView<'_>,
    link: LinkId,
    peer: ServerId,
    complete: CompleteRequest,
    facts_for: &dyn Fn(BaseOriginKey) -> OriginFacts,
    resolved: Option<&super::object_read::Resolved>,
) -> Result<Staged, E2eeReplyCode> {
    let home = *peer.as_bytes();
    let decoded = request::decode(coordinator, &complete)?;
    if decoded.request.home_server_id != home {
        return Err(E2eeReplyCode::InvalidFragment);
    }
    let classified = request::classify(&coordinator.state, home, &decoded);
    if resolved.is_some() && !matches!(classified, Classified::Fresh) {
        return Err(E2eeReplyCode::OperationConflict);
    }
    match classified {
        Classified::Fresh => {}
        Classified::Replay(result, responses) => {
            return Ok(Staged::Replay(replay_lines(
                coordinator,
                &complete.correlation,
                home,
                &result,
                &responses,
            )?));
        }
        Classified::Violation => {
            let identity = super::response_read::Identity {
                peer,
                correlation: complete.correlation,
                request_object_id: decoded.request_object_id,
            };
            return if identity.missing(coordinator) {
                Ok(Staged::ReadResponses(identity))
            } else {
                Err(E2eeReplyCode::OperationConflict)
            };
        }
    }
    let origin_key = CompanionOriginKey {
        home_server_id: home,
        server_incarnation: decoded.request.server_incarnation,
        origin_id: decoded.request.origin_id,
    };
    let origin = coordinator
        .state
        .origins
        .get(&origin_key)
        .cloned()
        .ok_or(E2eeReplyCode::OperationConflict)?;
    let facts = facts_for(base_origin_key(&origin));
    let now = view
        .context
        .utc_now()
        .map(|second| second.get())
        .map_err(|_| E2eeReplyCode::RateLimited)?;
    let plan = view
        .context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| E2eeReplyCode::RateLimited)?;
    let state_generation = plan.resulting_revision().get();
    let source_view = source_view_bytes(view.context, facts);
    let mut pool = EntropyPool::fill(view.context.entropy_mut())?;
    let prepared = execute(
        coordinator,
        view.context,
        &view.peers,
        peer,
        &origin,
        &decoded,
        now,
        state_generation,
        facts.user_id,
        source_view,
        &mut pool,
        resolved,
    );
    let mut outcome = match prepared {
        ops::Prepared::Complete(outcome) => *outcome,
        ops::Prepared::Read(request) => {
            return Ok(Staged::ReadObject(super::object_read::PendingRequest {
                complete,
                request,
            }));
        }
    };
    let base_plan = outcome.base_plan.take();
    if let Some(deadline) = outcome.mailbox_expiry {
        ops::mailbox_snapshot::reserve_expiry(
            view.context.timers_mut(),
            deadline,
            &mut coordinator.state.mailbox_expiry_armed,
        )?;
    }
    let base_counts = match &base_plan {
        Some(plan) if plan.resulting_revision().get() == state_generation => Some(
            view.context
                .preview_projection(plan)
                .map_err(|_| E2eeReplyCode::RateLimited)?,
        ),
        Some(_) => return Err(E2eeReplyCode::RateLimited),
        None => None,
    };
    let assembled = assemble(
        coordinator,
        home,
        peer,
        &decoded,
        outcome,
        state_generation,
        now,
        resolved.and_then(super::object_read::Resolved::uncached_id),
        BarrierInputs {
            backing: view.context.backing_reservations(),
            base_counts: base_counts.as_ref(),
            base_capacity: &*view.base_capacity,
            entropy: &mut pool,
        },
    )?;
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| E2eeReplyCode::RateLimited)?;
    let staged_plan = match base_plan {
        Some(base_plan) => {
            view.context.set_mutation_context(MutationContext {
                actor: facts.user_id,
                ..MutationContext::default()
            });
            view.context.set_cross_profile(
                assembled
                    .barriers
                    .iter()
                    .map(|barrier| {
                        (
                            barrier.target,
                            CrossProfileAssignment {
                                mutation_id: barrier.mutation_id,
                                part_count: barrier.part_count,
                                companion_scope: barrier.companion_scope,
                                companion: barrier.companion,
                            },
                        )
                    })
                    .collect(),
            );
            base_plan
        }
        None => plan,
    };
    let writes = assembled
        .writes
        .into_iter()
        .map(|write| write.at_revision(state_generation))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| E2eeReplyCode::RateLimited)?;
    view.context
        .stage_durable_with_account_service(staged_plan, fanout, None, 0, writes)
        .map_err(|_| E2eeReplyCode::RateLimited)?;
    coordinator.pending = Some(super::sync::PendingWork::Request(Box::new(
        PendingCompanion {
            link,
            peer,
            correlation: complete.correlation,
            request_object_id: decoded.request_object_id,
            result: assembled.result,
            responses: assembled.responses,
            events: assembled.copies,
            effects: assembled.effects,
            barriers: assembled.barriers,
            object_backing: resolved.map(super::object_read::Resolved::backing),
        },
    )));
    Ok(Staged::Batch)
}

// agenc-review: allow owner=runtime reviewed=2026-09-03 reason=the executor context carries every base fact one handler may consult
#[allow(clippy::too_many_arguments)]
fn execute(
    coordinator: &CompanionCoordinator,
    context: &StateCoreContext,
    peers: &[ServerId],
    home: ServerId,
    origin: &CompanionOrigin,
    decoded: &Decoded,
    now: u64,
    state_generation: u64,
    user_id: Option<UserId>,
    source_view: Vec<u8>,
    entropy: &mut dyn agenc_ircd_types::EntropySource,
    resolved: Option<&super::object_read::Resolved>,
) -> ops::Prepared {
    let domain = context.domain();
    let holds_channel = |edge: ServerId, channel: ChannelInstanceId| {
        context
            .federation()
            .and_then(|projector| projector.index().edge(edge))
            .is_some_and(|standing| standing.holds_channel(channel))
    };
    let hosting = |channel: ChannelInstanceId| -> Vec<ServerId> {
        peers
            .iter()
            .copied()
            .filter(|edge| holds_channel(*edge, channel))
            .collect()
    };
    let attached_edges = |digest: &[u8; 32]| attached_origin_edges(coordinator, digest);
    let channel_member = |channel: ChannelInstanceId| {
        user_id.is_some_and(|user| {
            domain
                .channel(channel)
                .is_some_and(|state| state.members().any(|member| member == user))
        })
    };
    let plan_binding = |channel: ChannelInstanceId, principals: &[[u8; 24]]| {
        binding_plan(domain, user_id, channel, principals)
    };
    let mut exec = Exec {
        object_source: resolved.map_or(
            super::object_read::Source::Unread,
            super::object_read::Source::Resolved,
        ),
        queries: user_id.map(|user| context.query_reservations(user)),
        backing: context.backing_reservations(),
        monotonic_millis: crate::e2ee::link::tick_millis(context.now()),
        coordinator,
        home,
        origin,
        decoded,
        now,
        entropy,
        peers,
        holds_channel: &holds_channel,
        hosting: &hosting,
        attached_edges: &attached_edges,
        channel_member: &channel_member,
        plan_binding: &plan_binding,
        state_generation,
        source_view,
    };
    match ops::execute(&mut exec) {
        Ok(ops::Prepared::Complete(mut outcome)) => {
            project_routes(&exec, &mut outcome);
            ops::Prepared::Complete(outcome)
        }
        Ok(ops::Prepared::Read(request)) => ops::Prepared::Read(request),
        Err(Fail { code, context }) => {
            ops::Prepared::Complete(Box::new(Outcome::failed(code, context)))
        }
    }
}

fn attached_origin_edges(coordinator: &CompanionCoordinator, digest: &[u8; 32]) -> Vec<ServerId> {
    let mut edges: Vec<ServerId> = coordinator
        .state
        .origins
        .values()
        .filter(|origin| origin.account_digest == Some(*digest) && origin.device.is_some())
        .map(|origin| ServerId::from_bytes(origin.home_server_id))
        .collect();
    edges.sort();
    edges.dedup();
    edges
}

/// Route projection entitlement (companion 12.5): every target of a
/// route-state copy becomes entitled to that route when the batch commits,
/// and a copy of any other event for a target not yet entitled is preceded
/// by a route-state copy of the retained route object, so the edge holds
/// the route before it renders the event. Channel hosts stay entitled;
/// direct routes count the event as one reference.
fn project_routes(exec: &Exec<'_>, outcome: &mut Outcome) {
    use agenc_ircd_domain::e2ee::projection::EntitlementReason;
    let state = &exec.coordinator.state;
    let mut entitled: Vec<(ServerId, [u8; 32], bool)> = Vec::new();
    let mut projected = Vec::new();
    for content in &outcome.events {
        let Some(conversation) = content.planned.conversation_id.filter(|id| {
            state
                .routes
                .is_current(&agenc_ircd_domain::e2ee::ConversationId(*id))
        }) else {
            continue;
        };
        let target = content.planned.target;
        let Some(known) = state.conversations.get(&conversation) else {
            continue;
        };
        let direct = known.direct_accounts.is_some();
        let already = state.entitlements.entitled(target, &conversation)
            || entitled
                .iter()
                .any(|(edge, id, _)| *edge == target && *id == conversation);
        let kind = content.planned.kind;
        if kind == EventKind::RouteStateChanged {
            entitled.push((target, conversation, direct));
            continue;
        }
        if kind == EventKind::RouteStateHidden || already {
            continue;
        }
        let Some(copy) = route_copy(exec, target, conversation, known) else {
            continue;
        };
        projected.push(copy);
        entitled.push((target, conversation, direct));
    }
    outcome.events.extend(projected);
    if entitled.is_empty() {
        return;
    }
    outcome.effects.push(Box::new(move |companion| {
        for (target, conversation, direct) in entitled {
            if direct {
                let _ = companion.entitlements.require_direct(
                    target,
                    conversation,
                    EntitlementReason::Event,
                );
            } else {
                companion
                    .entitlements
                    .set_channel(target, conversation, true);
            }
        }
    }));
}

/// The route-state copy that projects `conversation`'s retained route
/// object to `target`, at the sequencer head.
fn route_copy(
    exec: &Exec<'_>,
    target: ServerId,
    conversation: [u8; 32],
    known: &ConversationState,
) -> Option<EventContent> {
    let state = &exec.coordinator.state;
    let route_object = state.objects.get(&known.route_object_id).cloned()?;
    let sequence = state
        .logs
        .get(&conversation)
        .map_or(0, |log| log.head().sequence);
    Some(exec.event(
        EventKind::RouteStateChanged,
        Some(conversation),
        target,
        sequence,
        Vec::new(),
        Some(route_object),
    ))
}

/// The base binding plan of a channel whose member accounts are exactly
/// the binding principals; the actor is the requesting origin's session.
fn binding_plan(
    domain: &agenc_ircd_domain::DomainState,
    user_id: Option<UserId>,
    channel: ChannelInstanceId,
    principals: &[[u8; 24]],
) -> Result<Option<agenc_ircd_domain::MutationPlan>, E2eeReplyCode> {
    let actor = user_id.ok_or(E2eeReplyCode::AccountRequired)?;
    let state = domain.channel(channel).ok_or(E2eeReplyCode::RouteInvalid)?;
    if state.role_of(actor) != Some(agenc_ircd_domain::Role::Owner) {
        return Err(E2eeReplyCode::BindingAuthInvalid);
    }
    let mut roster = Vec::new();
    let mut accounts: Vec<[u8; 24]> = Vec::new();
    for member in state.members() {
        let account = domain
            .session(member)
            .and_then(|session| session.account_id())
            .ok_or(E2eeReplyCode::BindingAuthInvalid)?;
        let text: [u8; 24] = account
            .to_text()
            .as_bytes()
            .try_into()
            .map_err(|_| E2eeReplyCode::BindingAuthInvalid)?;
        accounts.push(text);
        roster.push((member, account));
    }
    accounts.sort_unstable();
    accounts.dedup();
    let mut expected = principals.to_vec();
    expected.sort_unstable();
    if accounts != expected {
        return Err(E2eeReplyCode::BindingAuthInvalid);
    }
    if state.content_policy() == agenc_ircd_domain::ContentPolicy::E2eeBound {
        return Ok(None);
    }
    let proof = agenc_ircd_domain::E2eeBindingProof::new(channel, state.revision(), roster)
        .map_err(|_| E2eeReplyCode::BindingAuthInvalid)?;
    domain
        .plan_e2ee_binding(actor, proof)
        .map(Some)
        .map_err(|_| E2eeReplyCode::BindingAuthInvalid)
}

/// One assembled batch.
struct Assembled {
    result: Vec<u8>,
    responses: Vec<Vec<u8>>,
    copies: Vec<events::CopyToSend>,
    writes: Vec<AccountServiceDurableWrite>,
    effects: Vec<super::Effect>,
    barriers: Vec<BarrierPlanned>,
}

/// What barrier planning needs from the base side.
struct BarrierInputs<'a> {
    backing: crate::budget::BackingReservationPort,
    base_counts: Option<&'a BTreeMap<ServerId, (usize, u64)>>,
    base_capacity: &'a dyn Fn(ServerId, usize, u64) -> bool,
    entropy: &'a mut dyn agenc_ircd_types::EntropySource,
}

fn complete_barriers(
    assignments: &BTreeMap<ServerId, BarrierAssignment>,
    sequenced: &events::Sequenced,
    state_generation: u64,
) -> Result<Vec<BarrierPlanned>, E2eeReplyCode> {
    assignments
        .iter()
        .map(|(target, assignment)| {
            let (_, stream) = sequenced
                .streams
                .iter()
                .find(|(peer, _)| peer == target)
                .ok_or(E2eeReplyCode::Syncing)?;
            let owner = stream.owner.as_ref().ok_or(E2eeReplyCode::Syncing)?;
            let (first, last) = stream.barrier.ok_or(E2eeReplyCode::Syncing)?;
            let copy = sequenced
                .copies
                .iter()
                .find(|copy| copy.target == *target && copy.row.sequence == last)
                .ok_or(E2eeReplyCode::Syncing)?;
            if sequenced.barrier_last.get(target) != Some(&last)
                || copy.generation != stream.generation
                || last >= stream.next_sequence
            {
                return Err(E2eeReplyCode::Syncing);
            }
            Ok(BarrierPlanned {
                target: *target,
                mutation_id: assignment.mutation_id,
                base_parts: assignment.base_parts,
                part_count: assignment.part_count,
                state_generation,
                companion_scope: *owner.scope(),
                companion: BarrierEndpoint::new(stream.generation, first, last, copy.row.event_id)
                    .map_err(|_| E2eeReplyCode::Syncing)?,
            })
        })
        .collect()
}

/// Plans one barrier per target that receives both base and companion
/// events, sampling its mutation identity (spec 20.8).
fn plan_barrier_assignments(
    base_counts: Option<&BTreeMap<ServerId, (usize, u64)>>,
    plan: &EventPlan,
    base_capacity: &dyn Fn(ServerId, usize, u64) -> bool,
    entropy: &mut dyn agenc_ircd_types::EntropySource,
) -> Result<BTreeMap<ServerId, BarrierAssignment>, E2eeReplyCode> {
    let Some(base_counts) = base_counts else {
        return Ok(BTreeMap::new());
    };
    let mut assignments = BTreeMap::new();
    for barrier in plan_barriers(base_counts, plan).map_err(|_| E2eeReplyCode::InvalidFragment)? {
        let base_bytes = base_counts
            .get(&barrier.target)
            .map_or(0, |(_, bytes)| *bytes);
        if !base_capacity(barrier.target, barrier.base_parts, base_bytes) {
            return Err(E2eeReplyCode::Syncing);
        }
        let mut mutation_id = [0; 16];
        entropy
            .fill_exact(&mut mutation_id)
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        let base_parts =
            u16::try_from(barrier.base_parts).map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let part_count =
            u16::try_from(barrier.part_count()).map_err(|_| E2eeReplyCode::InvalidFragment)?;
        assignments.insert(
            barrier.target,
            BarrierAssignment {
                mutation_id,
                base_parts,
                part_count,
            },
        );
    }
    Ok(assignments)
}

// agenc-review: allow owner=runtime reviewed=2026-09-03 reason=assembling a batch needs the coordinator context home peer decoded request outcome generation and time together
#[allow(clippy::too_many_arguments)]
fn assemble(
    coordinator: &CompanionCoordinator,
    home: [u8; 16],
    peer: ServerId,
    decoded: &Decoded,
    mut outcome: Outcome,
    state_generation: u64,
    now: u64,
    uncached_response: Option<[u8; 32]>,
    barrier_inputs: BarrierInputs<'_>,
) -> Result<Assembled, E2eeReplyCode> {
    let opcode = Opcode(decoded.request.opcode.value());
    let completion = completion_for(opcode, outcome.result.kind())
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    let correlation = Correlation {
        peer_server_id: home,
        server_incarnation: decoded.request.server_incarnation,
        origin_id: decoded.request.origin_id,
        origin_generation: decoded.request.origin_generation,
        operation_sequence: decoded.request.operation_sequence,
        request_id: decoded.request.request_id,
    };
    mark_completion(
        &mut outcome.events,
        completion,
        peer,
        &correlation,
        state_generation,
        decoded,
    )?;
    let plan = EventPlan::order(
        outcome
            .events
            .iter()
            .map(|content| content.planned.clone())
            .collect(),
    )
    .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    outcome.events.sort_by_key(|content| {
        plan.events()
            .iter()
            .position(|planned| *planned == content.planned)
    });
    let assignments = plan_barrier_assignments(
        barrier_inputs.base_counts,
        &plan,
        barrier_inputs.base_capacity,
        barrier_inputs.entropy,
    )?;
    let sequenced = events::sequence_copies(
        coordinator,
        &plan,
        &outcome.events,
        state_generation,
        barrier_inputs.entropy,
        &assignments,
        &barrier_inputs.backing,
    )?;
    let barriers = complete_barriers(&assignments, &sequenced, state_generation)?;
    let (copies, mut writes, streams) = (sequenced.copies, sequenced.writes, sequenced.streams);
    let completion_event_id = copies
        .iter()
        .zip(plan.events())
        .find(|(_, planned)| planned.completion)
        .map(|(copy, _)| copy.row.event_id);
    let result = request::encode_result(
        coordinator,
        home,
        decoded,
        &outcome,
        state_generation,
        completion_event_id,
    )?;
    let responses: Vec<Vec<u8>> = outcome
        .responses
        .iter()
        .map(|response| response.bytes.clone())
        .collect();
    for response in &outcome.responses {
        super::delivery_owner::append_object(&mut writes, &response.bytes)?;
    }
    super::delivery_owner::append_object(&mut writes, &result)?;
    let retain_until = now.saturating_add(if outcome.security_mutation {
        SECURITY_MUTATION_REPLAY_SECONDS
    } else {
        S2S_IDEMPOTENCY_RETENTION_SECONDS
    });
    let key = request::replay_key(home, &decoded.request);
    let (row, replay_write) = request::replay_write(
        &key,
        decoded,
        &result,
        &outcome.responses,
        outcome.security_mutation,
        retain_until,
    )?;
    writes.push(replay_write);
    let origin_key = CompanionOriginKey {
        home_server_id: home,
        server_incarnation: decoded.request.server_incarnation,
        origin_id: decoded.request.origin_id,
    };
    let sequence = agenc_ircd_storage::e2ee_records::origin::OriginSequenceRow {
        origin_generation: decoded.request.origin_generation,
        next_sequence: decoded
            .request
            .operation_sequence
            .checked_add(1)
            .ok_or(E2eeReplyCode::InvalidFragment)?,
    };
    writes.push(request::origin_sequence_write(&origin_key, sequence)?);
    // An operation may retain the same object it also returns as a
    // response (an attach challenge, a delivered mailbox item); one batch
    // puts each object row once.
    for write in outcome.writes.drain(..) {
        if !writes.iter().any(|existing| existing.same_put(&write)) {
            writes.push(write);
        }
    }
    let mut effects = outcome.effects;
    let request_object_id = decoded.request_object_id;
    let stored = StoredResult {
        result: result.clone(),
        responses: outcome
            .responses
            .iter()
            .map(|response: &ResponseObject| {
                *agenc_ircd_e2ee::ObjectId::compute(&response.bytes).as_bytes()
            })
            .collect(),
    };
    let response_bytes = responses.clone();
    let result_bytes = result.clone();
    effects.push(Box::new(move |state| {
        state.replays.insert(key, row);
        state.origin_sequences.insert(origin_key, sequence);
        state.results.insert(request_object_id, stored);
        for bytes in response_bytes {
            if uncached_response != Some(*agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes()) {
                let _ = CompanionCoordinator::retain_object(state, bytes);
            }
        }
        let _ = CompanionCoordinator::retain_object(state, result_bytes);
        if let Some(origin) = state.origins.get_mut(&origin_key) {
            origin.next_sequence = sequence.next_sequence;
        }
        for (target, stream) in streams {
            state.streams.insert(target, stream);
        }
    }));
    Ok(Assembled {
        result,
        responses,
        copies,
        writes,
        effects,
        barriers,
    })
}

/// Applies the completion table: a semantic completion marks the home copy
/// of the named kind, a generic completion appends `request_completed`.
fn mark_completion(
    contents: &mut Vec<EventContent>,
    completion: Completion,
    home: ServerId,
    correlation: &Correlation,
    state_generation: u64,
    decoded: &Decoded,
) -> Result<(), E2eeReplyCode> {
    match completion {
        Completion::None => Ok(()),
        Completion::Semantic(kind) => {
            let copy = contents
                .iter_mut()
                .find(|content| content.planned.kind == kind && content.planned.target == home)
                .ok_or(E2eeReplyCode::InvalidFragment)?;
            copy.planned.completion = true;
            copy.correlation = Some(*correlation);
            Ok(())
        }
        Completion::Generic => {
            contents.push(generic_completion(
                home,
                correlation,
                state_generation,
                decoded,
            ));
            Ok(())
        }
    }
}

/// The `request_completed` copy a generic completion appends.
fn generic_completion(
    home: ServerId,
    correlation: &Correlation,
    state_generation: u64,
    decoded: &Decoded,
) -> EventContent {
    EventContent {
        planned: PlannedEvent {
            kind: EventKind::RequestCompleted,
            conversation_id: request_conversation(decoded),
            target: home,
            payload_object_id: None,
            completion: true,
            route_sequence: 0,
            bytes: 1_024,
        },
        origin: None,
        source_view: Vec::new(),
        correlation: Some(*correlation),
        encoded_result: state_generation.to_be_bytes().to_vec(),
        payload: None,
    }
}

/// The conversation a request names, when its first parameter is one.
fn request_conversation(decoded: &Decoded) -> Option<[u8; 32]> {
    use agenc_ircd_e2ee::objects::federation::IrcFederationOpcode as Op;
    let names_conversation = matches!(
        decoded.request.opcode,
        Op::ApplicationChannel
            | Op::ApplicationDirect
            | Op::CloseGroup
            | Op::SubmitCandidate
            | Op::SubmitAuthorization
            | Op::SubmitCommitAck
            | Op::SubmitFinalization
            | Op::SubmitAbort
            | Op::SubmitReinitAttempt
            | Op::SubmitReinitAck
            | Op::SubmitReinitActivate
            | Op::SubmitReinitAbort
            | Op::SubmitPolicy
            | Op::FetchObject
            | Op::FetchAuthorizations
            | Op::FetchAcks
            | Op::FetchReceipts
    );
    if !names_conversation {
        return None;
    }
    decoded
        .request
        .encoded_parameters
        .as_slice()
        .get(..32)
        .and_then(|bytes| bytes.try_into().ok())
}

/// The `ERESULT` and `ERESPONSE` lines of one stored result.
pub fn replay_lines(
    coordinator: &CompanionCoordinator,
    correlation: &Correlation,
    home: [u8; 16],
    result: &[u8],
    responses: &[Vec<u8>],
) -> Result<Vec<agenc_ircd_federation_wire::FederationLineText>, E2eeReplyCode> {
    let correlation = Correlation {
        peer_server_id: home,
        ..*correlation
    };
    let mut lines = Vec::new();
    let result_id = *agenc_ircd_e2ee::ObjectId::compute(result).as_bytes();
    for fragment in fragment_object(result).map_err(|_| E2eeReplyCode::InvalidFragment)? {
        lines.push(events::line(
            &coordinator.server_name,
            &CompanionFrame::Result {
                correlation,
                object_id: result_id,
                fragment,
            },
        )?);
    }
    for (index, response) in responses.iter().enumerate() {
        let object_id = *agenc_ircd_e2ee::ObjectId::compute(response).as_bytes();
        for fragment in fragment_object(response).map_err(|_| E2eeReplyCode::InvalidFragment)? {
            lines.push(events::line(
                &coordinator.server_name,
                &CompanionFrame::Response {
                    correlation,
                    response_index: u16::try_from(index)
                        .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                    object_id,
                    fragment,
                },
            )?);
        }
    }
    Ok(lines)
}

/// The lines a committed batch sends: the result and responses to the home
/// edge and every event copy to its target, keyed by target.
pub fn committed_lines(
    coordinator: &CompanionCoordinator,
    pending: &PendingCompanion,
) -> Result<Vec<CommittedLine>, E2eeReplyCode> {
    let mut lines = Vec::new();
    for line in replay_lines(
        coordinator,
        &pending.correlation,
        *pending.peer.as_bytes(),
        &pending.result,
        &pending.responses,
    )? {
        lines.push(CommittedLine {
            target: pending.peer,
            sequence: None,
            line,
            backing: pending.object_backing.clone(),
        });
    }
    for copy in &pending.events {
        for line in events::render_copy(&coordinator.server_name, copy)? {
            lines.push(CommittedLine {
                target: copy.target,
                sequence: Some(copy.row.sequence),
                line,
                backing: None,
            });
        }
    }
    Ok(lines)
}

/// One line a committed request sends: the answer to the requester, or an
/// event copy at its delivery sequence.
pub struct CommittedLine {
    /// The target edge.
    pub target: ServerId,
    /// The delivery sequence of an event copy; `None` for the answer.
    pub sequence: Option<u64>,
    /// The line.
    pub line: agenc_ircd_federation_wire::FederationLineText,
    /// Keeps a cold response charged while the link writer owns its lines.
    pub(crate) backing: Option<std::sync::Arc<crate::budget::MemoryPermit>>,
}
