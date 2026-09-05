//! Metadata-only history receipts and connection-bound output behind durable admission.

#[cfg(all(test, feature = "history"))]
#[path = "history/tests/history.rs"]
mod tests;

use std::collections::BTreeMap;

use agenc_ircd_client_wire::{ParsedMessage, WireMessage};
use agenc_ircd_domain::{
    ContentPolicy, DomainError, HistoryPolicy, HistoryQuery, PersistencePolicy, Visibility,
};
use agenc_ircd_federation_wire::{
    FederationHash32, HistoryPage, RequestHeader, ResultHeader, federation_object_id,
};
use agenc_ircd_storage::history_records::{
    HISTORY_EDGE_REQUEST_KIND, HistoryAuthorizationBinding, HistoryEdgePhase,
    HistoryEdgeRequestRecord, HistoryRequestIdentity,
};
use agenc_ircd_storage::{PersistentRecordValue, TableId};
use agenc_ircd_types::{ChannelInstanceId, RequestId, UserId};

use super::request::{self, EdgeCompletion, PendingKind};
use super::{EdgeFederation, PendingCommit, Phase, Violation};
use crate::connection::ConnectionGeneration;
use crate::federation::codec::{
    history as codec, operations::FederatedOperation, results::ResultArm,
};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::fanout::{FanoutRequest, FanoutReservation};

const MAX_ACTIVE: usize = 256;
const QUERY_MILLISECONDS: u64 = 600_000;
const PAGE_BACKING: usize = 524_288;

#[derive(Default)]
pub(super) struct HistoryRequests {
    records: BTreeMap<RequestId, HistoryEdgeRequestRecord>,
    batches: BTreeMap<ConnectionGeneration, Batch>,
    retention: crate::federation::history_retention::Retention,
}

struct Batch {
    channel: ChannelInstanceId,
    query: HistoryQuery,
    id: String,
    token: Option<[u8; 32]>,
    authorization: Option<HistoryAuthorizationBinding>,
    page: u32,
    count: usize,
    last_sequence: u64,
    deadline: u64,
}

pub(super) struct Prepared {
    generation: ConnectionGeneration,
    record: HistoryEdgeRequestRecord,
    action: Action,
}

enum Action {
    Send {
        header: RequestHeader,
        bytes: Vec<u8>,
        message: Box<ParsedMessage>,
    },
    Page(PageOutput),
    Expired {
        reservation: FanoutReservation,
    },
}

struct PageOutput {
    reservation: FanoutReservation,
    channel: ChannelInstanceId,
    token: [u8; 32],
    next: Option<[u8; 32]>,
    count: usize,
    last_sequence: u64,
    expires: u64,
}

pub(super) fn begin(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    message: Box<ParsedMessage>,
    operation: FederatedOperation,
) -> Result<(), (Box<ParsedMessage>, DomainError)> {
    if !available(edge, context, generation) {
        return unavailable(edge, context, generation, message);
    }
    if edge.history.batches.len() >= MAX_ACTIVE
        || edge.history.batches.contains_key(&generation)
        || edge.commit.is_some()
    {
        return Err((message, DomainError::ServerBusy));
    }
    let FederatedOperation::HistoryQuery {
        channel_id,
        selector,
        limit,
        ..
    } = &operation
    else {
        return Err((message, DomainError::InvalidArgument));
    };
    let Ok(query) = codec::query_of(selector, *limit) else {
        return Err((message, DomainError::InvalidArgument));
    };
    let Ok((id, header, bytes)) = request::prepare_request(edge, context, generation, &operation)
    else {
        return Err((message, DomainError::ServerBusy));
    };
    let deadline = context.now().get().saturating_add(QUERY_MILLISECONDS);
    let batch = Batch {
        channel: *channel_id,
        query,
        id: id.to_base64url(),
        token: None,
        authorization: None,
        page: 0,
        count: 0,
        last_sequence: 0,
        deadline,
    };
    edge.history.batches.insert(generation, batch);
    match stage_send(edge, context, generation, header, bytes, message) {
        Ok(()) => Ok(()),
        Err((message, _)) => {
            rollback_sequence(edge, generation, header.replay_key.operation_sequence);
            edge.history.batches.remove(&generation);
            Err((message, DomainError::ServerBusy))
        }
    }
}

fn stage_send(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    header: RequestHeader,
    bytes: Vec<u8>,
    message: Box<ParsedMessage>,
) -> Result<(), (Box<ParsedMessage>, Violation)> {
    let deadline = match wall_now(context).and_then(|now| {
        now.checked_add(QUERY_MILLISECONDS)
            .ok_or(Violation::Ceiling)
    }) {
        Ok(deadline) => deadline,
        Err(error) => return Err((message, error)),
    };
    let record = HistoryEdgeRequestRecord {
        request: HistoryRequestIdentity {
            replay_key: header.replay_key.to_bytes(),
            request_id: *header.request_id.as_bytes(),
            request_object_id: *federation_object_id(&bytes).as_bytes(),
            request_object: bytes.clone(),
        },
        original_result_object_id: None,
        expired_result_object_id: None,
        authorization: None,
        deadline_unix_milliseconds: deadline,
        phase: HistoryEdgePhase::Pending,
        sink_gone: false,
    };
    if let Err(error) = stage_record(edge, context, &record) {
        return Err((message, error));
    }
    edge.commit = Some(PendingCommit::History(Box::new(Prepared {
        generation,
        record,
        action: Action::Send {
            header,
            bytes,
            message,
        },
    })));
    Ok(())
}

pub(super) fn receive(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    header: ResultHeader,
    object_id: FederationHash32,
    arm: ResultArm,
) -> Result<Vec<EdgeCompletion>, Violation> {
    let pending = edge
        .pending
        .get(&header.request_id)
        .ok_or(Violation::Consistency)?;
    let generation = pending.generation;
    let record = edge
        .history
        .records
        .get(&header.request_id)
        .cloned()
        .ok_or(Violation::Consistency)?;
    if header.completion_event_id.is_some() || edge.commit.is_some() {
        return Err(Violation::Consistency);
    }
    match arm {
        ResultArm::HistoryPage(page) => {
            let prepared = prepare_page(edge, context, generation, record, object_id, &page)?;
            stage(edge, context, prepared).map_err(|(_, error)| error)?;
            Ok(Vec::new())
        }
        ResultArm::HistoryExpired {
            original_result_object_id,
        } => {
            let prepared = prepare_expired(
                edge,
                context,
                generation,
                record,
                object_id,
                original_result_object_id,
            )?;
            stage(edge, context, prepared).map_err(|(_, error)| error)?;
            Ok(Vec::new())
        }
        arm @ ResultArm::Failed { .. } => failed(edge, context, header.request_id, generation, arm),
        _ => Err(Violation::Consistency),
    }
}

fn prepare_page(
    edge: &EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    mut record: HistoryEdgeRequestRecord,
    object_id: FederationHash32,
    page: &HistoryPage,
) -> Result<Prepared, Violation> {
    let PageBinding {
        auth,
        channel,
        token,
        next,
    } = validate_page(edge, generation, &record, object_id, page)?;
    record.authorization = Some(auth);
    record.original_result_object_id = Some(*object_id.as_bytes());
    record.phase = HistoryEdgePhase::Received;
    match authorize(edge, context, generation, channel, auth) {
        Ok(()) => {}
        Err(Violation::Phase) => return cancelled_page(edge, context, generation, record),
        Err(error) => return Err(error),
    }
    prepare_authorized_page(
        edge,
        context,
        generation,
        record,
        page,
        PageBinding {
            auth,
            channel,
            token,
            next,
        },
    )
}

fn prepare_authorized_page(
    edge: &EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    record: HistoryEdgeRequestRecord,
    page: &HistoryPage,
    binding: PageBinding,
) -> Result<Prepared, Violation> {
    let PageBinding {
        auth: _,
        channel,
        token,
        next,
    } = binding;
    let batch = edge
        .history
        .batches
        .get(&generation)
        .ok_or(Violation::Consistency)?;
    let prepared_snapshot = context
        .prepare_query_snapshot(generation, 7, PAGE_BACKING)
        .map_err(|_| Violation::Ceiling)?;
    let channel_name = crate::federation::codec::channel_name_of(
        agenc_ircd_federation_wire::access::structure(page.as_object(), "channel_name")
            .map_err(|_| Violation::Codec)?,
    )
    .map_err(|_| Violation::Codec)?;
    let messages = checked_messages(page, &channel_name, batch)?;
    let expires = messages
        .iter()
        .map(|message| message.expires_unix_milliseconds)
        .min()
        .unwrap_or(record.deadline_unix_milliseconds);
    if !wall_now(context).is_ok_and(|now| now < expires) {
        return cancelled_page(edge, context, generation, record);
    }
    let frames = render_page(
        edge,
        context,
        generation,
        &record,
        &channel_name,
        &messages,
        next.is_none(),
    )?;
    let request = context
        .fanout_request_to(generation, frames)
        .map_err(|_| Violation::Ceiling)?;
    let permit = prepared_snapshot
        .finish(messages.len(), PAGE_BACKING)
        .map_err(|_| Violation::Ceiling)?;
    let reservation = context
        .reserve_query_fanout(&request, permit)
        .map_err(|_| Violation::Ceiling)?;
    Ok(Prepared {
        generation,
        record,
        action: Action::Page(PageOutput {
            reservation,
            channel,
            token,
            next,
            count: messages.len(),
            last_sequence: messages
                .last()
                .map_or(batch.last_sequence, |message| message.channel_sequence),
            expires,
        }),
    })
}

fn render_page(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    generation: ConnectionGeneration,
    record: &HistoryEdgeRequestRecord,
    channel_name: &agenc_ircd_domain::ChannelNameValue,
    messages: &[agenc_ircd_storage::history_records::HistoryMessageRecord],
    last: bool,
) -> Result<Vec<WireMessage>, Violation> {
    let batch = edge
        .history
        .batches
        .get(&generation)
        .ok_or(Violation::Consistency)?;
    let auth = record.authorization.ok_or(Violation::Consistency)?;
    let capabilities = context
        .sessions()
        .capabilities_for_user(UserId::from_bytes(auth.user_id))
        .ok_or(Violation::Phase)?;
    let pending = edge
        .pending
        .get(&RequestId::from_bytes(record.request.request_id))
        .ok_or(Violation::Consistency)?;
    let PendingKind::Command { message } = &pending.kind else {
        return Err(Violation::Consistency);
    };
    let label = message
        .tags()
        .iter()
        .find(|tag| tag.key() == "label")
        .and_then(|tag| tag.value());
    crate::history_render::page(crate::history_render::PageInput {
        prefix: &edge.config.server_name,
        capabilities,
        batch_id: &batch.id,
        channel: channel_name,
        messages,
        first: batch.page == 0,
        last,
        label,
    })
    .map_err(|_| Violation::Codec)
}

fn authorize(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    generation: ConnectionGeneration,
    channel: ChannelInstanceId,
    auth: HistoryAuthorizationBinding,
) -> Result<(), Violation> {
    if edge.phase != Phase::Active
        || !context.history_enabled()
        || !context.history_clock_safe()
        || context.sessions().sink_for_generation(generation).is_none()
    {
        return Err(Violation::Phase);
    }
    let batch = edge
        .history
        .batches
        .get(&generation)
        .ok_or(Violation::Consistency)?;
    if context.now().get() >= batch.deadline {
        return Err(Violation::Phase);
    }
    let origin = edge
        .origins
        .get(&generation)
        .ok_or(Violation::Consistency)?;
    let (session_id, user_id) = origin.session.ok_or(Violation::Consistency)?;
    if session_id.as_bytes() != &auth.session_id || user_id.as_bytes() != &auth.user_id {
        return Err(Violation::Consistency);
    }
    authorize_account(edge, user_id, auth)?;
    authorize_membership(edge, user_id, channel, auth.membership_revision)
}

fn authorize_account(
    edge: &EdgeFederation,
    user_id: UserId,
    auth: HistoryAuthorizationBinding,
) -> Result<(), Violation> {
    let session = edge.replica.session(user_id).ok_or(Violation::Phase)?;
    let account = session
        .account
        .map(|(account, generation)| (account, generation.get()));
    let expected = auth
        .account_id
        .map(|account| {
            agenc_ircd_types::AccountId::parse_wire_bytes(&account)
                .map(|id| (id, auth.account_session_generation))
        })
        .transpose()
        .map_err(|_| Violation::Consistency)?;
    if account != expected {
        return Err(Violation::Phase);
    }
    Ok(())
}

fn authorize_membership(
    edge: &EdgeFederation,
    user_id: UserId,
    channel: ChannelInstanceId,
    revision: u64,
) -> Result<(), Violation> {
    let membership = edge
        .replica
        .membership(channel, user_id)
        .ok_or(Violation::Phase)?;
    let detail = edge.replica.channel(channel).ok_or(Violation::Phase)?;
    if membership.membership_revision.get() != revision
        || detail.content_policy != ContentPolicy::Plaintext
        || detail.visibility != Visibility::Listed
        || detail.persistence != PersistencePolicy::Registered
        || detail.history == HistoryPolicy::Off
        || detail.e2ee_route_binding.is_some()
    {
        return Err(Violation::Phase);
    }
    Ok(())
}

fn stage(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    prepared: Prepared,
) -> Result<(), (Box<Prepared>, Violation)> {
    let result = stage_record(edge, context, &prepared.record);
    if let Err(error) = result {
        return Err((Box::new(prepared), error));
    }
    edge.commit = Some(PendingCommit::History(Box::new(prepared)));
    Ok(())
}

fn stage_record(
    edge: &EdgeFederation,
    context: &mut StateCoreContext,
    record: &HistoryEdgeRequestRecord,
) -> Result<(), Violation> {
    if edge.commit.is_some() {
        return Err(Violation::Ceiling);
    }
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let body = record.encode().map_err(|_| Violation::Codec)?;
    let key = agenc_ircd_storage::federation_records::request_result_key(record.request.replay_key)
        .map_err(|_| Violation::Codec)?;
    let plaintext = PersistentRecordValue::new(
        TableId::RequestResult,
        HISTORY_EDGE_REQUEST_KIND,
        plan.resulting_revision().get(),
        0,
        None,
        Vec::new(),
        body,
    )
    .and_then(|record| record.encode())
    .map_err(|_| Violation::Codec)?;
    let write = AccountServiceDurableWrite::put(TableId::RequestResult, key, plaintext)
        .map_err(|_| Violation::Codec)?;
    let fanout = FanoutRequest::new(Vec::new(), Vec::new()).map_err(|_| Violation::Ceiling)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, vec![write])
        .map(|_| ())
        .map_err(|_| Violation::Ceiling)
}

pub(super) fn committed(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    mut prepared: Prepared,
) -> Vec<EdgeCompletion> {
    let id = RequestId::from_bytes(prepared.record.request.request_id);
    edge.history.records.insert(id, prepared.record.clone());
    if prepared.record.phase == HistoryEdgePhase::Received && !prepared.record.sink_gone {
        prepared.record.phase = HistoryEdgePhase::Rendered;
        if let Err((prepared, _)) = stage(edge, context, prepared) {
            rejected(edge, context, *prepared);
        }
        return Vec::new();
    }
    match prepared.action {
        Action::Send {
            header,
            bytes,
            message,
        } => {
            if prepared.record.sink_gone {
                edge.history.records.remove(&id);
                return Vec::new();
            }
            request::register_request(
                edge,
                context,
                prepared.generation,
                (id, header, bytes),
                PendingKind::Command { message },
            );
            Vec::new()
        }
        Action::Page(output) => {
            committed_page(edge, context, prepared.generation, prepared.record, output)
        }
        Action::Expired { reservation } => {
            context.commit_fanout(reservation);
            finish_page(edge, context, id, prepared.generation, None)
        }
    }
}

fn finish_page(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    id: RequestId,
    generation: ConnectionGeneration,
    next: Option<[u8; 32]>,
) -> Vec<EdgeCompletion> {
    edge.history.records.remove(&id);
    let Some(pending) = edge.pending.remove(&id) else {
        return Vec::new();
    };
    let PendingKind::Command { message } = pending.kind else {
        return Vec::new();
    };
    let Some(cursor) = next else {
        edge.history.batches.remove(&generation);
        return request::dispatch_deferred(edge, context, generation);
    };
    let Some(batch) = edge.history.batches.get(&generation) else {
        return Vec::new();
    };
    let Some((session_id, _)) = edge
        .origins
        .get(&generation)
        .and_then(|origin| origin.session)
    else {
        return Vec::new();
    };
    let Ok(selector) = codec::selector_object(batch.query.selector()) else {
        return Vec::new();
    };
    let operation = FederatedOperation::HistoryQuery {
        session_id,
        channel_id: batch.channel,
        selector,
        limit: batch.query.limit(),
        cursor: Some(cursor),
    };
    let Ok((_, header, bytes)) = request::prepare_request(edge, context, generation, &operation)
    else {
        return Vec::new();
    };
    if stage_send(edge, context, generation, header, bytes, message).is_err() {
        rollback_sequence(edge, generation, header.replay_key.operation_sequence);
        edge.fail_link(context, Violation::Ceiling);
    }
    Vec::new()
}

pub(super) fn rejected(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    prepared: Prepared,
) {
    if let Action::Send { header, .. } = prepared.action {
        edge.history.batches.remove(&prepared.generation);
        rollback_sequence(
            edge,
            prepared.generation,
            header.replay_key.operation_sequence,
        );
    }
    edge.fail_link(context, Violation::Ceiling);
}

fn rollback_sequence(edge: &mut EdgeFederation, generation: ConnectionGeneration, sequence: u64) {
    if let Some(origin) = edge.origins.get_mut(&generation)
        && origin.sequence == sequence.saturating_add(1)
    {
        origin.sequence = sequence;
    }
}

fn expired_output(
    edge: &EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
) -> Result<FanoutReservation, Violation> {
    let batch = edge
        .history
        .batches
        .get(&generation)
        .ok_or(Violation::Consistency)?;
    let mut frames = Vec::new();
    if batch.page > 0 {
        frames.push(
            WireMessage::new(
                &edge.config.server_name,
                "BATCH",
                &[&format!("-{}", batch.id)],
                None,
            )
            .map_err(|_| Violation::Codec)?,
        );
    }
    frames.push(
        WireMessage::new(
            &edge.config.server_name,
            "FAIL",
            &["CHATHISTORY", "QUERY_EXPIRED"],
            Some("History query expired"),
        )
        .map_err(|_| Violation::Codec)?,
    );
    let permit = context
        .prepare_query_snapshot(generation, 0, 4_096)
        .and_then(|prepared| prepared.finish(0, 4_096))
        .map_err(|_| Violation::Ceiling)?;
    let request = context
        .fanout_request_to(generation, frames)
        .map_err(|_| Violation::Ceiling)?;
    context
        .reserve_query_fanout(&request, permit)
        .map_err(|_| Violation::Ceiling)
}

fn wall_now(context: &StateCoreContext) -> Result<u64, Violation> {
    if !context.history_clock_safe() {
        return Err(Violation::Phase);
    }
    context
        .utc_now()
        .map_err(|_| Violation::Ceiling)?
        .get()
        .checked_mul(1_000)
        .ok_or(Violation::Ceiling)
}

pub(super) fn connection_closed(edge: &mut EdgeFederation, generation: ConnectionGeneration) {
    let sequence = mark_pending_sink_gone(edge.commit.as_mut(), generation);
    if let Some(sequence) = sequence {
        rollback_sequence(edge, generation, sequence);
    }
    edge.history.batches.remove(&generation);
    let stale: Vec<_> = edge
        .pending
        .iter()
        .filter(|(_, pending)| pending.generation == generation)
        .map(|(id, _)| *id)
        .collect();
    for id in stale {
        edge.history.records.remove(&id);
    }
}

impl EdgeFederation {
    pub(crate) fn retain_history(&mut self, context: &mut StateCoreContext) {
        if self.commit.is_none() {
            self.history.retention.begin(context);
        }
    }

    pub(crate) fn owns_history_read(&self, id: crate::bridge::StorageReadId) -> bool {
        self.history.retention.owns(id)
    }

    pub(crate) fn history_read_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: crate::bridge::StorageReadCompletionMessage,
    ) {
        self.history.retention.completed();
        if self.commit.is_some() || context.pending_len() != 0 {
            return;
        }
        let Ok(result) = message.result else {
            return;
        };
        let Ok(plan) = context.domain().plan_account_service_checkpoint() else {
            return;
        };
        let cleanup = self.history.retention.prepare(
            context,
            &result,
            plan.resulting_revision().get(),
            HISTORY_EDGE_REQUEST_KIND,
            |key| {
                !self
                    .pending
                    .values()
                    .any(|pending| pending.header.replay_key.to_bytes() == *key)
                    && !self.origins.values().any(|origin| {
                        !origin.deleted
                            && origin.origin_id.as_bytes() == &key[32..48]
                            && self.config.incarnation.as_bytes() == &key[16..32]
                    })
            },
        );
        let Ok(mut cleanup) = cleanup else {
            return;
        };
        if cleanup.writes.is_empty() {
            self.history.retention.committed(&cleanup);
            return;
        }
        let Ok(fanout) = FanoutRequest::new(Vec::new(), Vec::new()) else {
            return;
        };
        if context
            .stage_durable_with_account_service(
                plan,
                fanout,
                None,
                0,
                std::mem::take(&mut cleanup.writes),
            )
            .is_ok()
        {
            self.commit = Some(PendingCommit::HistoryCleanup(cleanup));
        }
    }
}

pub(super) fn cleanup_committed(
    edge: &mut EdgeFederation,
    cleanup: crate::federation::history_retention::Cleanup,
) {
    edge.history.retention.committed(&cleanup);
}

fn mark_pending_sink_gone(
    pending: Option<&mut PendingCommit>,
    generation: ConnectionGeneration,
) -> Option<u64> {
    let Some(PendingCommit::History(prepared)) = pending else {
        return None;
    };
    if prepared.generation != generation {
        return None;
    }
    prepared.record.sink_gone = true;
    match prepared.action {
        Action::Send { header, .. } => Some(header.replay_key.operation_sequence),
        _ => None,
    }
}

fn failed(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    id: RequestId,
    generation: ConnectionGeneration,
    arm: ResultArm,
) -> Result<Vec<EdgeCompletion>, Violation> {
    edge.history.records.remove(&id);
    if let Some(batch) = edge
        .history
        .batches
        .get(&generation)
        .filter(|batch| batch.page > 0)
    {
        let frame = WireMessage::new(
            &edge.config.server_name,
            "BATCH",
            &[&format!("-{}", batch.id)],
            None,
        )
        .map_err(|_| Violation::Codec)?;
        context
            .send_to(generation, vec![frame])
            .map_err(|_| Violation::Ceiling)?;
    }
    edge.history.batches.remove(&generation);
    if let Some(pending) = edge.pending.get_mut(&id) {
        pending.result = Some(arm);
    }
    Ok(request::completed(edge, context, id))
}

struct PageBinding {
    auth: HistoryAuthorizationBinding,
    channel: ChannelInstanceId,
    token: [u8; 32],
    next: Option<[u8; 32]>,
}

fn validate_page(
    edge: &EdgeFederation,
    generation: ConnectionGeneration,
    record: &HistoryEdgeRequestRecord,
    object_id: FederationHash32,
    page: &HistoryPage,
) -> Result<PageBinding, Violation> {
    let auth = codec::authorization_of(
        page.authorization()
            .map_err(|_| Violation::Codec)?
            .as_object(),
    )
    .map_err(|_| Violation::Codec)?;
    let channel = page.channel_id().map_err(|_| Violation::Codec)?;
    let token = page.snapshot_token().map_err(|_| Violation::Codec)?;
    let batch = edge
        .history
        .batches
        .get(&generation)
        .ok_or(Violation::Consistency)?;
    if batch.channel != channel
        || page.page_sequence().map_err(|_| Violation::Codec)? != batch.page
        || batch.token.is_some_and(|original| original != token)
        || batch.authorization.is_some_and(|original| original != auth)
        || record
            .original_result_object_id
            .is_some_and(|original| original != *object_id.as_bytes())
    {
        return Err(Violation::Consistency);
    }
    Ok(PageBinding {
        auth,
        channel,
        token,
        next: page.next_cursor().map_err(|_| Violation::Codec)?,
    })
}

fn cancelled_page(
    edge: &EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    mut record: HistoryEdgeRequestRecord,
) -> Result<Prepared, Violation> {
    record.sink_gone = true;
    let reservation = expired_output(edge, context, generation)?;
    Ok(Prepared {
        generation,
        record,
        action: Action::Expired { reservation },
    })
}

fn prepare_expired(
    edge: &EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    mut record: HistoryEdgeRequestRecord,
    object_id: FederationHash32,
    original: [u8; 32],
) -> Result<Prepared, Violation> {
    if record
        .original_result_object_id
        .is_some_and(|saved| saved != original)
    {
        return Err(Violation::Consistency);
    }
    record.original_result_object_id = Some(original);
    record.expired_result_object_id = Some(*object_id.as_bytes());
    record.phase = HistoryEdgePhase::Expired;
    cancelled_page(edge, context, generation, record)
}

fn committed_page(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    record: HistoryEdgeRequestRecord,
    output: PageOutput,
) -> Vec<EdgeCompletion> {
    let PageOutput {
        reservation,
        channel,
        token,
        next,
        count,
        last_sequence,
        expires,
    } = output;
    let id = RequestId::from_bytes(record.request.request_id);

    let valid = record
        .authorization
        .is_some_and(|auth| authorize(edge, context, generation, channel, auth).is_ok())
        && wall_now(context).is_ok_and(|now| now < expires);
    if !valid {
        if let Ok(reservation) = expired_output(edge, context, generation) {
            context.commit_fanout(reservation);
        }
        return finish_page(edge, context, id, generation, None);
    }
    let report = context.commit_fanout(reservation);
    if report.committed_sinks != 1 {
        edge.pending.remove(&id);
        edge.history.records.remove(&id);
        edge.history.batches.remove(&generation);
        return Vec::new();
    }
    if let Some(batch) = edge.history.batches.get_mut(&generation) {
        batch.token = Some(token);
        batch.authorization = record.authorization;
        batch.page = batch.page.saturating_add(1);
        batch.count = batch.count.saturating_add(count);
        batch.last_sequence = last_sequence;
    }
    finish_page(edge, context, id, generation, next)
}

fn checked_messages(
    page: &HistoryPage,
    channel: &agenc_ircd_domain::ChannelNameValue,
    batch: &Batch,
) -> Result<Vec<agenc_ircd_storage::history_records::HistoryMessageRecord>, Violation> {
    let messages = codec::messages_of(page, channel).map_err(|_| Violation::Codec)?;
    if messages.len() > 7
        || batch.count.saturating_add(messages.len()) > usize::from(batch.query.limit())
        || messages
            .first()
            .is_some_and(|message| message.channel_sequence <= batch.last_sequence)
    {
        return Err(Violation::Consistency);
    }
    Ok(messages)
}

/// Restored requests have no live connection. Validate their exact identity and leave
/// them unattached; retention durably records sink loss before eventual deletion.
pub(super) fn validate_restored(
    edge: &EdgeFederation,
    key: &agenc_ircd_storage::StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), crate::RuntimeError> {
    if value.record_kind() != HISTORY_EDGE_REQUEST_KIND {
        return Ok(());
    }
    let record = HistoryEdgeRequestRecord::decode(value.body())?;
    let mut budget = agenc_ircd_federation_wire::DecodeBudget::new(2048, 64);
    let object = agenc_ircd_federation_wire::SchemaObject::decode_exact(
        "FederationRequest",
        &record.request.request_object,
        &mut budget,
    )
    .map_err(|_| super::startup::invalid())?;
    let header = RequestHeader::from_object(&object).map_err(|_| super::startup::invalid())?;
    if key.as_bytes() != record.request.replay_key
        || header.replay_key.to_bytes() != record.request.replay_key
        || header.network_id != edge.config.network_id
        || header.replay_key.home_server_id != edge.config.server_id
        || header.request_id.as_bytes() != &record.request.request_id
        || header.opcode != agenc_ircd_types::FederationOpcode::HistoryQuery
        || federation_object_id(&record.request.request_object).as_bytes()
            != &record.request.request_object_id
    {
        return Err(super::startup::invalid());
    }
    Ok(())
}

fn available(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    generation: ConnectionGeneration,
) -> bool {
    context.history_enabled()
        && edge
            .origins
            .get(&generation)
            .and_then(|origin| origin.session)
            .and_then(|(_, user)| context.sessions().capabilities_for_user(user))
            .is_some_and(|caps| caps.enabled("draft/chathistory") && caps.enabled("batch"))
}

fn unavailable(
    edge: &EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    message: Box<ParsedMessage>,
) -> Result<(), (Box<ParsedMessage>, DomainError)> {
    let frame = WireMessage::new(
        &edge.config.server_name,
        "FAIL",
        &["CHATHISTORY", "UNAVAILABLE"],
        Some("History is unavailable"),
    );
    let fallback = agenc_ircd_client_wire::CapabilityState::default();
    let caps = edge
        .origins
        .get(&generation)
        .and_then(|origin| origin.session)
        .and_then(|(_, user)| context.sessions().capabilities_for_user(user))
        .unwrap_or(&fallback);
    let label = message
        .tags()
        .iter()
        .find(|tag| tag.key() == "label")
        .and_then(|tag| tag.value());
    let frames = frame
        .and_then(|frame| {
            agenc_ircd_client_wire::labeled_response(
                caps,
                &edge.config.server_name,
                label,
                None,
                vec![frame],
            )
        })
        .map(|reply| reply.into_messages());
    let result = frames.map_err(|_| ()).and_then(|frames| {
        context
            .send_to(generation, frames)
            .map(|_| ())
            .map_err(|_| ())
    });
    result.map_err(|()| (message, DomainError::ServerBusy))
}
