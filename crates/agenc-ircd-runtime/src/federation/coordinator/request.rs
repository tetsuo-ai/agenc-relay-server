//! FREQUEST execution: replay classification, conversion into a domain
//! plan, and the single batch that carries the result (spec 20.4, 20.5).

use agenc_ircd_domain::federation::{
    MutationContext, OperationKey, OriginKey, ReplayDecision, SessionHideKind,
};
use agenc_ircd_domain::{CanonicalCommand, DomainError, PlanDecision, SessionSeed};
use agenc_ircd_federation_wire::{
    AssembledObject, DecodeBudget, FederationHash32, OperationDescriptor, RequestCorrelation,
    RequestHeader, ResultHeader, SchemaObject, decode_request_operation, federation_object_id,
    result_kind_permitted,
};
use agenc_ircd_storage::federation_records::{
    COORDINATOR_RESULT_KIND, CoordinatorResultRecord, request_result_key,
};
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, TableId};
use agenc_ircd_types::{EventId, ServerId, UserId};

use super::convert::{self, ConvertedRequest, convert_operation};
use super::{FederationCoordinator, PendingCommit, QueuedRequest, Violation, encode_object};
use crate::bridge::CryptoJobId;
use crate::channels::{FederatedDeferred, FederatedPlan, FederatedRefusal, plan_federated_command};
use crate::federation::codec::operations::FederatedOperation;
use crate::federation::codec::results::{ResultArm, SessionRegistered, failure_code};
use crate::federation::{IngressCharge, LinkId};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::projector::RequestBinding;
use crate::state_core::session::BoundSession;

/// The decode ceiling for one request object: the base object bound plus
/// the nested value allowance of the generic codec.
const REQUEST_DECODE_BYTES: usize = 262_144;
const REQUEST_DECODE_VALUES: usize = 4_096;

/// A federated request whose plan waits on channel-key crypto jobs.
pub(crate) struct PendingCrypto {
    pub(super) link: LinkId,
    pub(super) peer: ServerId,
    pub(super) job_id: CryptoJobId,
    pub(super) deferred: FederatedDeferred,
    pub(super) request: FreshRequest,
}

/// The identity of one fresh request being executed.
pub(crate) struct FreshRequest {
    pub(super) key: OperationKey,
    pub(super) header: RequestHeader,
    pub(super) descriptor: OperationDescriptor,
    pub(super) request_object_id: FederationHash32,
    pub(super) bound: Option<BoundSession>,
    pub(super) command: Option<CanonicalCommand>,
    pub(super) mutation: MutationContext,
    pub(super) charge: Option<IngressCharge>,
}

/// Receives one complete request object from a live link.
pub(super) fn receive(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    descriptor: OperationDescriptor,
    object: AssembledObject,
    charge: Option<IngressCharge>,
) -> Result<(), Violation> {
    // A request plans against the current state and stages its own batch.
    // It waits while this link's crypto job, the coordinator's own batch, a
    // history read, or a batch any other router staged is still open, so
    // the plan is never refused as busy and answered with SERVER_BUSY for
    // a slot that frees a few milliseconds later.
    // It also waits behind requests already queued for its peer, so one
    // origin's operations keep their sequence order.
    let queued_ahead = coordinator
        .peers
        .get(&peer)
        .ok_or(Violation::Misaddressed)?
        .queued
        .iter()
        .any(|queued| queued.link == link);
    let busy = queued_ahead
        || coordinator
            .crypto
            .as_ref()
            .is_some_and(|pending| pending.link == link)
        || coordinator.pending.is_some()
        || coordinator.history.busy()
        || context.in_flight()
        || context.pending_len() != 0;
    if busy {
        let state = coordinator
            .peers
            .get_mut(&peer)
            .ok_or(Violation::Misaddressed)?;
        if state.queued.len() >= super::MAX_QUEUED_REQUESTS {
            return Err(Violation::Ceiling);
        }
        state.queued.push_back(QueuedRequest {
            link,
            descriptor,
            object,
            charge,
        });
        return Ok(());
    }
    execute(coordinator, context, link, peer, descriptor, object, charge)
}

/// Executes queued requests while the coordinator can take one: until a
/// request stages a batch, starts a crypto job, or the queues are empty.
/// Peers take turns, starting after the peer drained last, so one busy
/// edge cannot starve another.
pub(super) fn drain_queued(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
) {
    loop {
        if coordinator.pending.is_some()
            || coordinator.history.busy()
            || context.in_flight()
            || context.pending_len() != 0
        {
            return;
        }
        let Some((peer, queued)) = next_queued(coordinator) else {
            return;
        };
        coordinator.drain_cursor = Some(peer);
        if let Err(violation) = execute(
            coordinator,
            context,
            queued.link,
            peer,
            queued.descriptor,
            queued.object,
            queued.charge,
        ) {
            coordinator.fail_link(context, queued.link, peer, violation);
        }
    }
}

/// Takes the next drainable queued request, visiting peers in key order
/// from the one after the last drained. A queue whose front belongs to a
/// link that is gone, or whose link waits on crypto, is pruned or skipped.
pub(super) fn next_queued(
    coordinator: &mut FederationCoordinator,
) -> Option<(ServerId, QueuedRequest)> {
    let peers: Vec<ServerId> = match coordinator.drain_cursor {
        Some(cursor) => coordinator
            .peers
            .range((
                std::ops::Bound::Excluded(cursor),
                std::ops::Bound::Unbounded,
            ))
            .map(|(peer, _)| *peer)
            .chain(coordinator.peers.range(..=cursor).map(|(peer, _)| *peer))
            .collect(),
        None => coordinator.peers.keys().copied().collect(),
    };
    for peer in peers {
        let crypto_here = coordinator
            .crypto
            .as_ref()
            .is_some_and(|pending| pending.peer == peer);
        let Some(state) = coordinator.peers.get_mut(&peer) else {
            continue;
        };
        let live = state.live.as_ref().map(|live| live.link);
        state.queued.retain(|queued| Some(queued.link) == live);
        if crypto_here {
            continue;
        }
        if let Some(queued) = state.queued.pop_front() {
            return Some((peer, queued));
        }
    }
    None
}

fn execute(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    descriptor: OperationDescriptor,
    object: AssembledObject,
    charge: Option<IngressCharge>,
) -> Result<(), Violation> {
    let mut budget = DecodeBudget::new(REQUEST_DECODE_BYTES, REQUEST_DECODE_VALUES);
    let request = SchemaObject::decode_exact("FederationRequest", object.as_slice(), &mut budget)
        .map_err(|_| Violation::Codec)?;
    let header = RequestHeader::from_object(&request).map_err(|_| Violation::Codec)?;
    check_descriptor(coordinator, peer, &descriptor, &header, object.object_id())?;
    let key = OperationKey {
        origin: OriginKey {
            home_server_id: peer,
            server_incarnation: header.replay_key.server_incarnation,
            origin_id: header.replay_key.origin_id,
        },
        generation: header.replay_key.origin_generation,
        sequence: header.replay_key.operation_sequence,
    };
    match classify(coordinator, &key, &header, object.object_id())? {
        Classified::Fresh => {}
        Classified::Replay => {
            return replay(coordinator, context, link, peer, descriptor, &header);
        }
        Classified::Expired => {
            let fresh = FreshRequest {
                key,
                header,
                descriptor,
                request_object_id: object.object_id(),
                bound: None,
                command: None,
                mutation: MutationContext::default(),
                charge,
            };
            return expire_request(coordinator, context, link, peer, fresh);
        }
    }
    let operation = decode_request_operation(&request, &mut budget)
        .and_then(|arm| FederatedOperation::from_object(header.opcode, &arm))
        .map_err(|_| Violation::Codec)?;
    let fresh = FreshRequest {
        key,
        header,
        descriptor,
        request_object_id: object.object_id(),
        bound: None,
        command: None,
        mutation: MutationContext::default(),
        charge,
    };
    run_operation(coordinator, context, link, peer, fresh, operation)
}

/// An expired replay ends its origin without advancing or rewriting its
/// committed sequence. The refusal follows the durable fence checkpoint.
fn expire_request(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
) -> Result<(), Violation> {
    coordinator
        .origins
        .fence(&fresh.key.origin)
        .map_err(|_| Violation::Origin)?;
    let entry = coordinator
        .origins
        .origin(&fresh.key.origin)
        .ok_or(Violation::Origin)?;
    let result = encode_result(
        coordinator,
        &fresh,
        &ResultArm::Failed {
            code: "ORIGIN_EXPIRED".to_owned(),
            context: String::new(),
        },
        None,
        Vec::new(),
    )?;
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let write = super::origin::origin_row(
        coordinator,
        fresh.key.origin,
        entry.next_sequence,
        plan.resulting_revision().get(),
    )?;
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, vec![write])
        .map_err(|_| Violation::Ceiling)?;
    coordinator.pending = Some(PendingCommit::OriginExpired {
        peer,
        link,
        descriptor: fresh.descriptor,
        result,
        _charge: fresh.charge,
    });
    Ok(())
}

/// The exact committed registration result owns its session even before
/// FORIGIN UPDATE binds that session into the next declared principal.
pub(super) fn remember_registration(
    coordinator: &mut FederationCoordinator,
    context: &StateCoreContext,
    origin: OriginKey,
    result: &[u8],
) -> Result<(), Violation> {
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let object = SchemaObject::decode_exact("FederationResult", result, &mut budget)
        .map_err(|_| Violation::Codec)?;
    let header = ResultHeader::from_object(&object).map_err(|_| Violation::Codec)?;
    if header.result_kind != agenc_ircd_types::FederationResultKind::SessionRegistered {
        return Ok(());
    }
    let arm = agenc_ircd_federation_wire::decode_result_arm(&object, &mut budget)
        .map_err(|_| Violation::Codec)?;
    let ResultArm::SessionRegistered(registered) =
        ResultArm::from_object(header.result_kind, &arm).map_err(|_| Violation::Codec)?
    else {
        return Err(Violation::Codec);
    };
    if context
        .domain()
        .session(registered.user_id)
        .is_none_or(|session| {
            session.session_id() != registered.session_id
                || session.home_server_id() != origin.home_server_id
        })
    {
        return Ok(());
    }
    coordinator
        .registered_sessions
        .entry(origin)
        .or_default()
        .insert(registered.user_id);
    if coordinator.origins.origin(&origin).is_some_and(|entry| {
        matches!(
            entry.status,
            agenc_ircd_domain::federation::OriginStatus::Deleted
                | agenc_ircd_domain::federation::OriginStatus::Fenced
        )
    }) && let Some(state) = coordinator.peers.get_mut(&origin.home_server_id)
    {
        state.cleanup.push_back(registered.user_id);
    }
    Ok(())
}

/// What the replay classifier decided for a request.
enum Classified {
    Fresh,
    Replay,
    Expired,
}

/// Classifies one request against the origin table; a conflict, request
/// identity reuse, or gap blocks the origin and fails the link.
fn classify(
    coordinator: &mut FederationCoordinator,
    key: &OperationKey,
    header: &RequestHeader,
    object_id: FederationHash32,
) -> Result<Classified, Violation> {
    let retained = coordinator.retained.get(key).copied();
    let decision = coordinator
        .origins
        .classify_request(*key, header.request_id, *object_id.as_bytes(), retained)
        .map_err(|_| Violation::Origin)?;
    match decision {
        ReplayDecision::Fresh => Ok(Classified::Fresh),
        ReplayDecision::ExactDuplicate => Ok(Classified::Replay),
        ReplayDecision::Conflict | ReplayDecision::RequestIdReuse | ReplayDecision::Gap => {
            let _ = coordinator.origins.block(&key.origin);
            Err(Violation::Origin)
        }
        ReplayDecision::Expired => Ok(Classified::Expired),
    }
}

pub(super) fn check_descriptor(
    coordinator: &FederationCoordinator,
    peer: ServerId,
    descriptor: &OperationDescriptor,
    header: &RequestHeader,
    object_id: FederationHash32,
) -> Result<(), Violation> {
    let key = &header.replay_key;
    let matches = header.network_id == coordinator.config.network_id
        && key.home_server_id == peer
        && descriptor.addressed_server_id == coordinator.config.server_id
        && descriptor.server_incarnation == key.server_incarnation
        && descriptor.origin_id == key.origin_id
        && descriptor.origin_generation == key.origin_generation
        && descriptor.operation_sequence == key.operation_sequence
        && descriptor.request_id == header.request_id
        && descriptor.object_id == object_id;
    if matches {
        Ok(())
    } else {
        Err(Violation::Misaddressed)
    }
}

/// Answers an exact duplicate with the durable result, read back from
/// storage so the bytes are identical to the first answer.
fn replay(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    descriptor: OperationDescriptor,
    header: &RequestHeader,
) -> Result<(), Violation> {
    let key = request_result_key(header.replay_key.to_bytes()).map_err(|_| Violation::Codec)?;
    let read_id = context
        .submit_storage_read(ReadPlan::exact(TableId::RequestResult, key))
        .map_err(|_| Violation::Ceiling)?;
    if header.opcode == agenc_ircd_types::FederationOpcode::HistoryQuery {
        coordinator.history.metadata_read = Some(read_id);
    }
    coordinator
        .replays
        .insert(read_id, (link, peer, descriptor));
    coordinator.counters.requests_replayed =
        coordinator.counters.requests_replayed.saturating_add(1);
    Ok(())
}

/// Completes a replay once its durable result row is read back.
pub(super) fn replay_completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: crate::bridge::StorageReadCompletionMessage,
) -> bool {
    let Some((link, peer, descriptor)) = coordinator.replays.remove(&message.read_id) else {
        return false;
    };
    if coordinator.history.metadata_read == Some(message.read_id) {
        coordinator.history.metadata_read = None;
    }
    let result = message.result.ok().and_then(|result| {
        let record = result.records.into_iter().next()?;
        let opened = context
            .open_storage_plaintext(TableId::RequestResult, &record.key, &record.sealed_record)
            .ok()?;
        let value = PersistentRecordValue::decode(
            TableId::RequestResult,
            opened.expose_for_storage_codec(),
        )
        .ok()?;
        Some(value)
    });
    match result {
        Some(value)
            if value.record_kind()
                == agenc_ircd_storage::history_records::HISTORY_COORDINATOR_RESULT_KIND =>
        {
            let replay =
                agenc_ircd_storage::history_records::HistoryCoordinatorResultRecord::decode(
                    value.body(),
                )
                .map_err(|_| Violation::Codec)
                .and_then(|record| {
                    super::history::restore(coordinator, context, link, peer, descriptor, record)
                });
            if let Err(error) = replay {
                coordinator.fail_link(context, link, peer, error);
            }
        }
        Some(value) => match CoordinatorResultRecord::decode(value.body()) {
            Ok(record) => {
                coordinator.send_result(context, link, peer, descriptor, &record.result_object)
            }
            Err(_) => coordinator.fail_link(context, link, peer, Violation::Origin),
        },
        None => coordinator.fail_link(context, link, peer, Violation::Origin),
    }
    true
}

fn run_operation(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    mut fresh: FreshRequest,
    operation: FederatedOperation,
) -> Result<(), Violation> {
    let converted = match convert_operation(context, peer, &operation) {
        Ok(converted) => converted,
        Err(error) => return finish_failed(coordinator, context, link, peer, fresh, error),
    };
    match converted {
        ConvertedRequest::SessionOpen(seed) => {
            open_session(coordinator, context, link, peer, fresh, *seed)
        }
        ConvertedRequest::SessionOpenWithGrant(seed, grant_id) => {
            coordinator.queue_remote_session_open(link, peer, fresh, *seed, grant_id);
            Ok(())
        }
        ConvertedRequest::AccountService { opcode, envelope } => {
            coordinator.queue_remote_carrier(link, peer, fresh, opcode, envelope)
        }
        ConvertedRequest::SessionClose { user_id, kind } => {
            close_session(coordinator, context, link, peer, fresh, user_id, kind)
        }
        ConvertedRequest::Command(request) => {
            fresh.bound = Some(request.bound);
            fresh.mutation = request.mutation;
            plan_command(
                coordinator,
                context,
                link,
                peer,
                fresh,
                request.command,
                &operation,
            )
        }
        ConvertedRequest::Query(query) => {
            fresh.bound = Some(query.bound);
            run_query(coordinator, context, link, peer, fresh, *query)
        }
        ConvertedRequest::History(query) => {
            fresh.bound = Some(query.bound);
            super::history::begin(coordinator, context, link, peer, fresh, *query, operation)
        }
        ConvertedRequest::Unavailable => {
            let arm = ResultArm::Failed {
                code: "UNAVAILABLE".to_owned(),
                context: String::new(),
            };
            finish_without_plan(coordinator, context, link, peer, fresh, arm, Vec::new())
        }
    }
}

/// Executes one directory query: a continuation answers from the retained
/// pages, a fresh query plans and renders its first page, and a monitor
/// mutation commits as `no_content`.
fn run_query(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    mut fresh: FreshRequest,
    query: convert::QueryRequest,
) -> Result<(), Violation> {
    let scope = super::query::CursorScope {
        coordinator: coordinator.config.server_id,
        network_id: coordinator.config.network_id,
    };
    coordinator.queries.expire(context.now());
    if let Some(cursor) = query.cursor {
        let page = coordinator
            .queries
            .next_page(context, &scope, &query.identity, cursor)?;
        return finish_without_plan(
            coordinator,
            context,
            link,
            peer,
            fresh,
            page.arm,
            page.replies,
        );
    }
    let rebuild =
        |domain: &agenc_ircd_domain::DomainState| convert::rebuild_query(domain, &query.identity);
    let key_for = |_: &agenc_ircd_domain::ExternalInputRequest| None;
    let planned = plan_federated_command(
        context,
        query.bound,
        &rebuild,
        &key_for,
        &coordinator.verifier,
        coordinator.dummy,
    );
    fresh.command = Some(query.command);
    match planned {
        Ok(FederatedPlan::Ready(decision)) => finish_query_decision(
            coordinator,
            context,
            link,
            peer,
            fresh,
            &scope,
            &query.identity,
            decision,
        ),
        Ok(FederatedPlan::Crypto(_)) => Err(Violation::Codec),
        Err(FederatedRefusal::Public(error)) => {
            finish_failed(coordinator, context, link, peer, fresh, error)
        }
        Err(FederatedRefusal::Internal(error)) => Err(internal_violation(error)),
    }
}

/// Commits a rendered page, or the failure the renderer reported.
fn answer_page(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    page: Result<super::query::Page, DomainError>,
) -> Result<(), Violation> {
    match page {
        Ok(page) => finish_without_plan(
            coordinator,
            context,
            link,
            peer,
            fresh,
            page.arm,
            page.replies,
        ),
        Err(error) => finish_failed(coordinator, context, link, peer, fresh, error),
    }
}

// agenc-review: allow owner=runtime reviewed=2026-09-02 reason=a query decision carries its link peer request cursor scope identity and decision to one result boundary
#[allow(clippy::too_many_arguments)]
fn finish_query_decision(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    scope: &super::query::CursorScope,
    identity: &super::query::QueryIdentity,
    decision: PlanDecision,
) -> Result<(), Violation> {
    match decision {
        PlanDecision::Query(plan) => {
            let page = coordinator
                .queries
                .first_page(context, scope, identity, &plan);
            answer_page(coordinator, context, link, peer, fresh, page)
        }
        PlanDecision::Mutation(plan) => {
            let (Some(bound), Some(command)) = (fresh.bound, fresh.command.as_ref()) else {
                return Err(Violation::Codec);
            };
            let Ok(fanout) =
                crate::mutation_render::render_mutation(context, bound, None, command, &plan)
            else {
                return finish_failed(
                    coordinator,
                    context,
                    link,
                    peer,
                    fresh,
                    DomainError::ServerBusy,
                );
            };
            stage_with_plan(
                coordinator,
                context,
                link,
                peer,
                fresh,
                ResultArm::NoContent,
                plan,
                fanout,
            )
        }
        other => finish_decision(coordinator, context, link, peer, fresh, other),
    }
}

fn open_session(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    seed: SessionSeed,
) -> Result<(), Violation> {
    open_session_with_writes(coordinator, context, link, peer, fresh, seed, Vec::new())
}

/// Opens a session; `writes` are the account-service rows that join the
/// transaction, the consumed pre-registration grant of a remote client.
pub(super) fn open_session_with_writes(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    seed: SessionSeed,
    writes: Vec<AccountServiceDurableWrite>,
) -> Result<(), Violation> {
    // The result names the account's current revision; the edge's decoder
    // requires it alongside the session generation (result.session_registered).
    let account = seed.account_id.map(|account| {
        let revision = context
            .domain()
            .account(account)
            .map_or(0, |state| state.revision().get());
        (account, seed.account_session_generation.get(), revision)
    });
    let registered = SessionRegistered {
        session_id: seed.session_id,
        user_id: seed.user_id,
        session_revision: seed.revision.get(),
        account,
        resulting_state_generation: 0,
    };
    let plan = match context.domain().plan_session_opened(seed) {
        Ok(plan) => plan,
        Err(error) => return finish_failed(coordinator, context, link, peer, fresh, error),
    };
    let generation = plan.resulting_revision().get();
    let arm = ResultArm::SessionRegistered(SessionRegistered {
        session_revision: generation,
        resulting_state_generation: generation,
        ..registered
    });
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    stage_with_plan_and_writes(
        coordinator,
        context,
        link,
        peer,
        fresh,
        arm,
        plan,
        fanout,
        writes,
    )
}

fn close_session(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    mut fresh: FreshRequest,
    user_id: UserId,
    kind: SessionHideKind,
) -> Result<(), Violation> {
    let plan = match context.domain().plan_session_disconnected(user_id) {
        Ok(plan) => plan,
        Err(error) => return finish_failed(coordinator, context, link, peer, fresh, error),
    };
    fresh.mutation = MutationContext {
        hide_kind: Some(kind),
        reason: kind.generic_reason().to_owned(),
        ..MutationContext::default()
    };
    let Some(bound) = bound_for(context, user_id) else {
        return finish_failed(
            coordinator,
            context,
            link,
            peer,
            fresh,
            DomainError::NotFound,
        );
    };
    let command = CanonicalCommand::quit(None);
    let Ok(fanout) = crate::mutation_render::render_mutation(context, bound, None, &command, &plan)
    else {
        return finish_failed(
            coordinator,
            context,
            link,
            peer,
            fresh,
            DomainError::ServerBusy,
        );
    };
    let arm = ResultArm::Committed {
        resulting_state_generation: plan.resulting_revision().get(),
    };
    stage_with_plan(coordinator, context, link, peer, fresh, arm, plan, fanout)
}

/// Builds the session binding the domain executor expects for a remote user.
pub(super) fn bound_for(context: &StateCoreContext, user_id: UserId) -> Option<BoundSession> {
    let session = context.domain().session(user_id)?;
    Some(BoundSession {
        session_id: session.session_id(),
        user_id,
        capability_hash: *session.negotiated_capability_hash(),
    })
}

fn plan_command(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    mut fresh: FreshRequest,
    command: CanonicalCommand,
    operation: &FederatedOperation,
) -> Result<(), Violation> {
    let Some(bound) = fresh.bound else {
        return Err(Violation::Codec);
    };
    let rebuild =
        |domain: &agenc_ircd_domain::DomainState| convert::rebuild_command(domain, operation);
    let key_for =
        |request: &agenc_ircd_domain::ExternalInputRequest| convert::key_for(operation, request);
    let planned = plan_federated_command(
        context,
        bound,
        &rebuild,
        &key_for,
        &coordinator.verifier,
        coordinator.dummy,
    );
    fresh.command = Some(command);
    match planned {
        Ok(FederatedPlan::Ready(decision)) => {
            finish_decision(coordinator, context, link, peer, fresh, decision)
        }
        Ok(FederatedPlan::Crypto(deferred)) => {
            start_crypto(coordinator, context, link, peer, fresh, *deferred)
        }
        Err(FederatedRefusal::Public(error)) => {
            finish_failed(coordinator, context, link, peer, fresh, error)
        }
        Err(FederatedRefusal::Internal(error)) => Err(internal_violation(error)),
    }
}

/// An internal planning failure is reported as a codec violation: the edge
/// sent something the coordinator could decode but not execute.
fn internal_violation(error: crate::RuntimeError) -> Violation {
    match error {
        crate::RuntimeError::MemoryExhausted | crate::RuntimeError::LimitExceeded => {
            Violation::Ceiling
        }
        _ => Violation::Codec,
    }
}

fn start_crypto(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    mut deferred: FederatedDeferred,
) -> Result<(), Violation> {
    match deferred.submit_next(context) {
        Ok(Some(job_id)) => {
            coordinator.crypto = Some(PendingCrypto {
                link,
                peer,
                job_id,
                deferred,
                request: fresh,
            });
            Ok(())
        }
        Ok(None) => Err(Violation::Codec),
        Err(_) => finish_failed(
            coordinator,
            context,
            link,
            peer,
            fresh,
            DomainError::ServerBusy,
        ),
    }
}

/// Resumes the deferred request whose crypto job completed.
pub(super) fn crypto_completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
) {
    let Some(mut pending) = coordinator.crypto.take() else {
        return;
    };
    if pending.job_id != message.job_id {
        coordinator.crypto = Some(pending);
        return;
    }
    let (link, peer) = (pending.link, pending.peer);
    if !coordinator.link_is_live(link, peer) {
        return;
    }
    let outcome = match pending.deferred.complete(message.output) {
        Ok(()) => match pending.deferred.submit_next(context) {
            Ok(Some(job_id)) => {
                pending.job_id = job_id;
                coordinator.crypto = Some(pending);
                return;
            }
            Ok(None) => pending.deferred.finish(context),
            Err(_) => Err(FederatedRefusal::Public(DomainError::ServerBusy)),
        },
        Err(error) => Err(error),
    };
    let outcome = match outcome {
        Ok(decision) => {
            finish_decision(coordinator, context, link, peer, pending.request, decision)
        }
        Err(FederatedRefusal::Public(error)) => {
            finish_failed(coordinator, context, link, peer, pending.request, error)
        }
        Err(FederatedRefusal::Internal(error)) => Err(internal_violation(error)),
    };
    if let Err(violation) = outcome {
        coordinator.fail_link(context, link, peer, violation);
    }
}

/// Drops the crypto continuation of a link that ended.
pub(super) fn abandon_crypto(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
) {
    if let Some(pending) = coordinator.crypto.take() {
        let _cancelled = context.crypto_mut().cancel(pending.job_id);
    }
}

fn finish_decision(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    decision: PlanDecision,
) -> Result<(), Violation> {
    match decision {
        PlanDecision::Mutation(plan) => {
            let (Some(bound), Some(command)) = (fresh.bound, fresh.command.as_ref()) else {
                return Err(Violation::Codec);
            };
            let Ok(fanout) =
                crate::mutation_render::render_mutation(context, bound, None, command, &plan)
            else {
                return finish_failed(
                    coordinator,
                    context,
                    link,
                    peer,
                    fresh,
                    DomainError::ServerBusy,
                );
            };
            let arm = ResultArm::Committed {
                resulting_state_generation: plan.resulting_revision().get(),
            };
            stage_with_plan(coordinator, context, link, peer, fresh, arm, plan, fanout)
        }
        PlanDecision::Rejected(rejected) => {
            let error = rejected
                .failures()
                .first()
                .map_or(DomainError::BadState, |failure| failure.error());
            finish_failed(coordinator, context, link, peer, fresh, error)
        }
        // Query pages are the next slice; until then a query answers busy so
        // the client retries rather than waiting on a silent link.
        PlanDecision::Query(_) | PlanDecision::NeedsExternal(_) => finish_failed(
            coordinator,
            context,
            link,
            peer,
            fresh,
            DomainError::ServerBusy,
        ),
    }
}

/// Stages one mutation plan with its result, origin, and projection rows.
// agenc-review: allow owner=runtime reviewed=2026-09-02 reason=a request outcome carries its link peer replay key header descriptor object identity error and charge to one durable staging boundary
#[allow(clippy::too_many_arguments)]
fn stage_with_plan(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    arm: ResultArm,
    plan: agenc_ircd_domain::MutationPlan,
    fanout: crate::state_core::fanout::FanoutRequest,
) -> Result<(), Violation> {
    stage_with_plan_and_writes(
        coordinator,
        context,
        link,
        peer,
        fresh,
        arm,
        plan,
        fanout,
        Vec::new(),
    )
}

// agenc-review: allow owner=runtime reviewed=2026-09-03 reason=a staged request carries its link peer request result plan fanout and joined account rows to one durable staging boundary
#[allow(clippy::too_many_arguments)]
fn stage_with_plan_and_writes(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    arm: ResultArm,
    plan: agenc_ircd_domain::MutationPlan,
    fanout: crate::state_core::fanout::FanoutRequest,
    extra_writes: Vec<AccountServiceDurableWrite>,
) -> Result<(), Violation> {
    let completion_event_id = fresh_event_id(context)?;
    let generation = plan.resulting_revision().get();
    let encoded = encode_result(
        coordinator,
        &fresh,
        &arm,
        Some(completion_event_id),
        Vec::new(),
    )?;
    let mut writes = request_rows(
        coordinator,
        &fresh,
        &encoded,
        Some(completion_event_id),
        generation,
        generation,
    )?;
    writes.extend(extra_writes);
    context.set_mutation_context(fresh.mutation.clone());
    context.set_request_binding(RequestBinding {
        home: peer,
        correlation: RequestCorrelation {
            replay_key: fresh.header.replay_key,
            request_id: fresh.header.request_id,
        },
        completion_event_id,
    });
    match context.stage_durable_with_account_service(plan, fanout, None, 0, writes) {
        Ok(crate::state_core::StageAccepted::Staged { .. }) => {
            coordinator.pending = Some(PendingCommit::Request {
                staged_after: context.head().storage_commit_sequence,
                peer,
                link,
                key: fresh.key,
                request_id: fresh.header.request_id,
                request_object_id: fresh.request_object_id,
                result: encoded,
                descriptor: fresh.descriptor,
                header: fresh.header,
                _charge: fresh.charge,
            });
            Ok(())
        }
        Ok(crate::state_core::StageAccepted::AppliedInStep(_)) => Err(Violation::Codec),
        Err(_) => {
            // Staging refused: the mutation context was consumed, so answer
            // busy without a plan and let the edge retry.
            let mutation = MutationContext::default();
            let fresh = FreshRequest { mutation, ..fresh };
            finish_failed(
                coordinator,
                context,
                link,
                peer,
                fresh,
                DomainError::ServerBusy,
            )
        }
    }
}

/// Answers a request that produced no plan with a durable `failed` result.
pub(super) fn finish_failed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    error: DomainError,
) -> Result<(), Violation> {
    let arm = ResultArm::Failed {
        code: failure_code(error).to_owned(),
        context: String::new(),
    };
    finish_without_plan(coordinator, context, link, peer, fresh, arm, Vec::new())
}

/// Answers a request that produced no plan with a durable result carrying
/// `arm` and `replies`, staged behind a checkpoint plan.
pub(super) fn finish_without_plan(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
    arm: ResultArm,
    replies: Vec<agenc_ircd_federation_wire::SchemaObject>,
) -> Result<(), Violation> {
    let FreshRequest {
        key,
        header,
        descriptor,
        request_object_id,
        charge,
        ..
    } = fresh;
    fail_without_plan(
        coordinator,
        context,
        link,
        peer,
        key,
        &header,
        descriptor,
        request_object_id,
        (arm, replies),
        charge,
    )
}

// agenc-review: allow owner=runtime reviewed=2026-09-02 reason=a request outcome carries its link peer replay key header descriptor object identity result and charge to one durable staging boundary
#[allow(clippy::too_many_arguments)]
fn fail_without_plan(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    key: OperationKey,
    header: &RequestHeader,
    descriptor: OperationDescriptor,
    request_object_id: FederationHash32,
    result: (ResultArm, Vec<agenc_ircd_federation_wire::SchemaObject>),
    charge: Option<IngressCharge>,
) -> Result<(), Violation> {
    let (arm, replies) = result;
    if matches!(arm, ResultArm::Failed { .. }) {
        coordinator.counters.requests_failed =
            coordinator.counters.requests_failed.saturating_add(1);
    }
    let fresh = FreshRequest {
        key,
        header: *header,
        descriptor,
        request_object_id,
        bound: None,
        command: None,
        mutation: MutationContext::default(),
        charge,
    };
    let encoded = encode_result(coordinator, &fresh, &arm, None, replies)?;
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let writes = request_rows(
        coordinator,
        &fresh,
        &encoded,
        None,
        revision,
        context.domain().revision().get(),
    )?;
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|_| Violation::Ceiling)?;
    coordinator.pending = Some(PendingCommit::Request {
        staged_after: context.head().storage_commit_sequence,
        peer,
        link,
        key: fresh.key,
        request_id: fresh.header.request_id,
        request_object_id: fresh.request_object_id,
        result: encoded,
        descriptor: fresh.descriptor,
        header: fresh.header,
        _charge: fresh.charge,
    });
    Ok(())
}

/// Retires a link whose request batch was refused. No result or sequence was
/// committed, so the edge must retain and resend the exact request after RESET.
/// A non-durable busy result would be indistinguishable from a durable failure
/// that consumed the sequence, and would make the next edge request a gap.
pub(super) fn rejected(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    fresh: FreshRequest,
) {
    drop(fresh);
    if coordinator.link_is_live(link, peer) {
        coordinator.fail_link(context, link, peer, Violation::Ceiling);
    }
}

fn fresh_event_id(context: &mut StateCoreContext) -> Result<EventId, Violation> {
    let mut id = [0_u8; 16];
    context
        .entropy_mut()
        .fill_exact(&mut id)
        .map_err(|_| Violation::Ceiling)?;
    Ok(EventId::from_bytes(id))
}

/// Builds the complete `FederationResult` bytes for one request.
pub(super) fn encode_result(
    coordinator: &FederationCoordinator,
    fresh: &FreshRequest,
    arm: &ResultArm,
    completion_event_id: Option<EventId>,
    replies: Vec<agenc_ircd_federation_wire::SchemaObject>,
) -> Result<Vec<u8>, Violation> {
    if !result_kind_permitted(fresh.header.opcode, arm.kind()) {
        return Err(Violation::Codec);
    }
    let header = ResultHeader {
        network_id: coordinator.config.network_id,
        replay_key: fresh.header.replay_key,
        request_id: fresh.header.request_id,
        request_object_id: fresh.request_object_id,
        completion_event_id,
        result_kind: arm.kind(),
    };
    let object = arm
        .to_object()
        .and_then(|object| header.build(&object, replies))
        .map_err(|_| Violation::Codec)?;
    encode_object(&object).map_err(|_| Violation::Codec)
}

/// The result row and origin row every fresh request commits.
fn request_rows(
    coordinator: &FederationCoordinator,
    fresh: &FreshRequest,
    encoded: &[u8],
    completion_event_id: Option<EventId>,
    row_revision: u64,
    resulting_state_generation: u64,
) -> Result<Vec<AccountServiceDurableWrite>, Violation> {
    let result_body = CoordinatorResultRecord {
        request_id: *fresh.header.request_id.as_bytes(),
        request_object_id: *fresh.request_object_id.as_bytes(),
        result_object_id: *federation_object_id(encoded).as_bytes(),
        result_object: encoded.to_vec(),
        completion_event_id: completion_event_id.map(|id| *id.as_bytes()),
        resulting_state_generation,
    }
    .encode()
    .map_err(|_| Violation::Codec)?;
    let result_key =
        request_result_key(fresh.header.replay_key.to_bytes()).map_err(|_| Violation::Codec)?;
    let result_write = row(
        TableId::RequestResult,
        COORDINATOR_RESULT_KIND,
        result_key,
        row_revision,
        result_body,
    )?;
    let next_sequence = fresh
        .key
        .sequence
        .checked_add(1)
        .ok_or(Violation::Ceiling)?;
    let origin_write =
        super::origin::origin_row(coordinator, fresh.key.origin, next_sequence, row_revision)?;
    Ok(vec![result_write, origin_write])
}

pub(super) fn row(
    table: TableId,
    kind: u16,
    key: agenc_ircd_storage::StoredKey,
    revision: u64,
    body: Vec<u8>,
) -> Result<AccountServiceDurableWrite, Violation> {
    let plaintext = PersistentRecordValue::new(table, kind, revision, 0, None, Vec::new(), body)
        .and_then(|value| value.encode())
        .map_err(|_| Violation::Codec)?;
    AccountServiceDurableWrite::put(table, key, plaintext).map_err(|_| Violation::Codec)
}
