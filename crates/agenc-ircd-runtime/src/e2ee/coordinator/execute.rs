//! The execution glue: one complete companion request runs against the
//! committed state, its result, response objects, replay row, and ordered
//! event copies are staged as one durable batch beside a checkpoint plan,
//! and after commit the effects apply and the lines go out.

use agenc_ircd_domain::e2ee::projection::{
    Completion, EventKind, EventPlan, Opcode, PlannedEvent, completion_for,
};
use agenc_ircd_domain::federation::OriginKey as BaseOriginKey;
use agenc_ircd_domain::federation::session_record_from;
use agenc_ircd_e2ee::federation::frames::{CompanionFrame, Correlation};
use agenc_ircd_e2ee::limits::S2S_IDEMPOTENCY_RETENTION_SECONDS;
use agenc_ircd_e2ee::wire::fragment::fragment_object;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_federation_wire::CanonicalEncode;
use agenc_ircd_types::{ChannelInstanceId, OriginId, ServerId, ServerIncarnation, UserId};

use super::events::{self, EventContent};
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

/// A security-state mutation stays replayable for seven days (companion
/// 12.5).
pub const SECURITY_MUTATION_REPLAY_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Random blocks drawn before a handler runs, so handlers never touch the
/// state core while the base view is borrowed.
const ENTROPY_POOL_BLOCKS: usize = 64;

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
}

/// Everything the owner supplies about the base state for one execution.
pub struct BaseView<'a> {
    /// The state core context.
    pub context: &'a mut StateCoreContext,
    /// Every configured edge.
    pub peers: Vec<ServerId>,
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
// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one companion request flows through decode, replay classification, execution, event sequencing, result encoding, and staging in order
pub fn run(
    coordinator: &mut CompanionCoordinator,
    view: BaseView<'_>,
    link: LinkId,
    peer: ServerId,
    complete: CompleteRequest,
    facts_for: &dyn Fn(BaseOriginKey) -> OriginFacts,
) -> Result<Staged, E2eeReplyCode> {
    let home = *peer.as_bytes();
    let decoded = request::decode(coordinator, &complete)?;
    if decoded.request.home_server_id != home {
        return Err(E2eeReplyCode::InvalidFragment);
    }
    match request::classify(&coordinator.state, home, &decoded) {
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
        Classified::Violation => return Err(E2eeReplyCode::OperationConflict),
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
    let outcome = execute(
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
    );
    let (result, responses, copies, writes, effects) = assemble(
        coordinator,
        view.context,
        home,
        peer,
        &decoded,
        outcome,
        state_generation,
        now,
    )?;
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| E2eeReplyCode::RateLimited)?;
    view.context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|_| E2eeReplyCode::RateLimited)?;
    coordinator.pending = Some(PendingCompanion {
        link,
        peer,
        correlation: complete.correlation,
        request_object_id: decoded.request_object_id,
        result,
        responses,
        events: copies,
        effects,
    });
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
) -> Outcome {
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
    let attached_edges = |digest: &[u8; 32]| -> Vec<ServerId> {
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
    };
    let channel_member = |channel: ChannelInstanceId| {
        user_id.is_some_and(|user| {
            domain
                .channel(channel)
                .is_some_and(|state| state.members().any(|member| member == user))
        })
    };
    let mut exec = Exec {
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
        state_generation,
        source_view,
    };
    match ops::execute(&mut exec) {
        Ok(outcome) => outcome,
        Err(Fail { code, context }) => Outcome::failed(code, context),
    }
}

type Assembled = (
    Vec<u8>,
    Vec<Vec<u8>>,
    Vec<events::CopyToSend>,
    Vec<AccountServiceDurableWrite>,
    Vec<super::Effect>,
);

// agenc-review: allow owner=runtime reviewed=2026-09-03 reason=assembling a batch needs the coordinator context home peer decoded request outcome generation and time together
#[allow(clippy::too_many_arguments)]
fn assemble(
    coordinator: &CompanionCoordinator,
    context: &mut StateCoreContext,
    home: [u8; 16],
    peer: ServerId,
    decoded: &Decoded,
    mut outcome: Outcome,
    state_generation: u64,
    now: u64,
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
    let (copies, mut writes, streams) = events::sequence_copies(
        coordinator,
        &plan,
        &outcome.events,
        state_generation,
        context.entropy_mut(),
    )?;
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
        writes.push(CompanionCoordinator::object_write(&response.bytes)?);
    }
    writes.push(CompanionCoordinator::object_write(&result)?);
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
    writes.append(&mut outcome.writes);
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
    let origin_key = CompanionOriginKey {
        home_server_id: home,
        server_incarnation: decoded.request.server_incarnation,
        origin_id: decoded.request.origin_id,
    };
    effects.push(Box::new(move |state| {
        state.replays.insert(key, row);
        state.results.insert(request_object_id, stored);
        for bytes in response_bytes {
            let _ = CompanionCoordinator::retain_object(state, bytes);
        }
        let _ = CompanionCoordinator::retain_object(state, result_bytes);
        if let Some(origin) = state.origins.get_mut(&origin_key) {
            origin.next_sequence = origin.next_sequence.saturating_add(1);
        }
        for (target, stream) in streams {
            state.streams.insert(target, stream);
        }
    }));
    Ok((result, responses, copies, writes, effects))
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
) -> Result<Vec<(ServerId, agenc_ircd_federation_wire::FederationLineText)>, E2eeReplyCode> {
    let mut lines = Vec::new();
    for line in replay_lines(
        coordinator,
        &pending.correlation,
        *pending.peer.as_bytes(),
        &pending.result,
        &pending.responses,
    )? {
        lines.push((pending.peer, line));
    }
    for copy in &pending.events {
        for line in events::render_copy(&coordinator.server_name, copy)? {
            lines.push((copy.target, line));
        }
    }
    Ok(lines)
}
