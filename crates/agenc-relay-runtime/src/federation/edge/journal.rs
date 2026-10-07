//! Durable ordinary request and origin ownership across link and process loss.

use std::collections::{BTreeMap, BTreeSet};

use agenc_relay_federation_wire::{
    CanonicalEncode, DecodeBudget, OriginRecord, RequestHeader, ResultHeader, SchemaObject,
    federation_object_id,
};
use agenc_relay_storage::federation_records::{
    EDGE_REQUEST_KIND, EdgeRequestPhase, EdgeRequestRecord, FederationOriginRecord,
    ORIGIN_FLAG_PENDING_DEL, ORIGIN_FLAG_SINK_GONE, ORIGIN_RECORD_KIND, OriginRowStatus,
    origin_key, request_result_key,
};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_relay_types::RequestId;

use super::{
    ConnectionOrigin, EdgeCompletion, EdgeFederation, PendingCommit, Phase, Violation,
    journal_retry, request,
};
use crate::RuntimeError;
use crate::connection::ConnectionGeneration;
use crate::state_core::{StageRefused, StateCoreContext};

const BATCH_ROWS: usize = 64;

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Identity {
    Origin(ConnectionGeneration),
    Request(RequestId),
}

/// One exact body owned by a staged checkpoint. Later changes stay dirty.
pub(super) struct Version {
    identity: Identity,
    body: Vec<u8>,
}

#[derive(Default)]
pub(super) struct Journal {
    dirty: BTreeSet<Identity>,
    durable: BTreeMap<Identity, Vec<u8>>,
    pub(super) retry: journal_retry::Retry,
}

enum StageFailure {
    Preparation(Violation),
    Admission(StageRefused),
}

impl From<Violation> for StageFailure {
    fn from(violation: Violation) -> Self {
        Self::Preparation(violation)
    }
}

pub(super) fn origin_record(
    edge: &EdgeFederation,
    generation: ConnectionGeneration,
) -> Result<FederationOriginRecord, Violation> {
    let origin = edge.origins.get(&generation).ok_or(Violation::Phase)?;
    let record = origin
        .pending_updates
        .front()
        .copied()
        .unwrap_or(OriginRecord {
            network_id: edge.config.network_id,
            home_server_id: edge.config.server_id,
            server_incarnation: edge.config.incarnation,
            origin_id: origin.origin_id,
            generation: origin.generation,
            previous_origin_object_id: origin.previous_object_id,
            connection_id: origin.connection_id,
            session: origin.session.map(|(session_id, user_id)| {
                agenc_relay_federation_wire::OriginSession {
                    session_id,
                    user_id,
                }
            }),
            account: origin
                .account
                .map(|(account_id, account_session_generation)| {
                    agenc_relay_federation_wire::OriginAccount {
                        account_id,
                        account_session_generation,
                    }
                }),
            connection_nonce: origin.connection_nonce,
        });
    let object = record
        .to_object()
        .and_then(|object| object.encode_canonical())
        .map_err(|_| Violation::Codec)?;
    Ok(FederationOriginRecord {
        origin_object_id: *federation_object_id(object.as_slice()).as_bytes(),
        origin_object: object.as_slice().to_vec(),
        next_sequence: if origin.pending_updates.is_empty() {
            origin.sequence
        } else {
            0
        },
        status: if origin.deleted {
            OriginRowStatus::Deleted
        } else {
            OriginRowStatus::Live
        },
        flags: if origin.deleted {
            ORIGIN_FLAG_SINK_GONE
                | if origin.del_acked {
                    0
                } else {
                    ORIGIN_FLAG_PENDING_DEL
                }
        } else {
            0
        },
    })
}

fn request_record(edge: &EdgeFederation, id: RequestId) -> Result<EdgeRequestRecord, Violation> {
    let pending = edge.pending.get(&id).ok_or(Violation::Phase)?;
    let covered = pending.completion_generation.is_some();
    let phase = if pending.result.is_some() && (pending.completion.is_none() || covered) {
        EdgeRequestPhase::Rendered
    } else if covered {
        if pending.completion_coverage.is_some() {
            EdgeRequestPhase::EventCovered
        } else {
            EdgeRequestPhase::SnapshotCovered
        }
    } else if pending.result.is_some() {
        EdgeRequestPhase::ResultPending
    } else {
        EdgeRequestPhase::Sent
    };
    Ok(EdgeRequestRecord {
        completion_coverage: pending.completion_coverage,
        request_id: *id.as_bytes(),
        request_object_id: *federation_object_id(&pending.bytes).as_bytes(),
        request_object: pending.bytes.clone(),
        phase,
        sink_gone: pending.sink_gone,
        result_object_id: (!pending.result_bytes.is_empty())
            .then(|| *federation_object_id(&pending.result_bytes).as_bytes()),
        result_object: pending.result_bytes.clone(),
        completion_event_id: pending.completion.map(|id| *id.as_bytes()),
        resulting_state_generation: pending
            .result
            .as_ref()
            .and_then(request::result_generation)
            .or(pending.completion_generation)
            .unwrap_or(0),
    })
}

fn body(edge: &EdgeFederation, identity: Identity) -> Result<Vec<u8>, Violation> {
    match identity {
        Identity::Origin(generation) => origin_record(edge, generation)?.encode(),
        Identity::Request(id) => request_record(edge, id)?.encode(),
    }
    .map_err(|_| Violation::Codec)
}

pub(super) fn is_durable(edge: &EdgeFederation, identity: Identity) -> bool {
    body(edge, identity).is_ok_and(|body| edge.journal.durable.get(&identity) == Some(&body))
}

pub(super) fn retain(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    identity: Identity,
) {
    edge.journal.dirty.insert(identity);
    continue_write(edge, context);
}

pub(super) fn retain_request(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    id: RequestId,
    generation: ConnectionGeneration,
) {
    edge.journal.dirty.insert(Identity::Origin(generation));
    edge.journal.dirty.insert(Identity::Request(id));
    continue_write(edge, context);
}

impl EdgeFederation {
    pub(crate) fn continue_request_journal(&mut self, context: &mut StateCoreContext) {
        continue_write(self, context);
    }
}

pub(super) fn continue_write(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    continue_write_inner(edge, context, false);
}

pub(super) fn retry_write(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    continue_write_inner(edge, context, true);
}

fn continue_write_inner(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    retry_authorized: bool,
) {
    if context.is_quiescing() {
        journal_retry::cancel(edge, context);
        return;
    }
    if edge.journal.dirty.is_empty() && edge.commit.is_none() {
        journal_retry::recovered(edge, context);
        return;
    }
    if edge.journal.retry.waiting.is_some() {
        return;
    }
    if edge.journal.retry.recovering && !retry_authorized {
        journal_retry::defer(edge, context);
        return;
    }
    if storage_occupied(edge, context) {
        if edge.journal.retry.recovering {
            journal_retry::defer(edge, context);
        }
        return;
    }
    attempt_write(edge, context);
}

fn storage_occupied(edge: &EdgeFederation, context: &StateCoreContext) -> bool {
    edge.commit.is_some() || context.in_flight() || context.pending_len() != 0
}

fn attempt_write(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    match stage(edge, context) {
        Ok(()) => {}
        Err(StageFailure::Admission(error)) if journal_retry::stage_retryable(&error) => {
            journal_retry::defer(edge, context);
        }
        Err(StageFailure::Admission(StageRefused::Quiescing)) => {
            journal_retry::cancel(edge, context);
        }
        Err(StageFailure::Admission(_)) => edge.fail_link(context, Violation::Ceiling),
        Err(StageFailure::Preparation(violation)) => edge.fail_link(context, violation),
    }
}

fn stage(edge: &mut EdgeFederation, context: &mut StateCoreContext) -> Result<(), StageFailure> {
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|error| StageFailure::Admission(StageRefused::Domain(error)))?;
    let revision = plan.resulting_revision().get();
    let mut versions = Vec::new();
    let mut writes = Vec::new();
    for identity in edge.journal.dirty.iter().take(BATCH_ROWS).copied() {
        let body = body(edge, identity)?;
        let (table, kind, key) = match identity {
            Identity::Origin(generation) => {
                let origin = edge.origins.get(&generation).ok_or(Violation::Phase)?;
                (
                    TableId::FederationOrigin,
                    ORIGIN_RECORD_KIND,
                    origin_key(
                        edge.config.server_id,
                        edge.config.incarnation,
                        *origin.origin_id.as_bytes(),
                        origin
                            .pending_updates
                            .front()
                            .map_or(origin.generation, |update| update.generation),
                    )
                    .map_err(|_| Violation::Codec)?,
                )
            }
            Identity::Request(id) => {
                let pending = edge.pending.get(&id).ok_or(Violation::Phase)?;
                (
                    TableId::RequestResult,
                    EDGE_REQUEST_KIND,
                    request_result_key(pending.header.replay_key.to_bytes())
                        .map_err(|_| Violation::Codec)?,
                )
            }
        };
        writes.push(
            edge.row_write(table, kind, key, revision, 0, body.clone())
                .map_err(|_| Violation::Codec)?,
        );
        versions.push(Version { identity, body });
    }
    let fanout = super::render::EventFanout::default()
        .finish()
        .map_err(Violation::from)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(StageFailure::Admission)?;
    edge.commit = Some(PendingCommit::Journal {
        staged_after: context.head().storage_commit_sequence,
        versions,
    });
    Ok(())
}

pub(super) fn committed(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    versions: Vec<Version>,
) -> Vec<EdgeCompletion> {
    let mut origins = Vec::new();
    let mut requests = Vec::new();
    for version in versions {
        let matches = body(edge, version.identity).is_ok_and(|body| body == version.body);
        edge.journal.durable.insert(version.identity, version.body);
        if !matches {
            continue;
        }
        edge.journal.dirty.remove(&version.identity);
        match version.identity {
            Identity::Origin(generation) => origins.push(generation),
            Identity::Request(id) => requests.push(id),
        }
    }
    if matches!(edge.phase, Phase::Origins | Phase::Active) {
        for generation in origins {
            request::replay_origin(edge, context, generation);
        }
    }
    super::sync::activate_origins(edge, context);
    let mut completions = Vec::new();
    requests.sort_by_key(|id| {
        edge.pending
            .get(id)
            .map(|pending| pending.header.replay_key.to_bytes())
    });
    for id in requests {
        if edge.pending.get(&id).is_some_and(|pending| {
            pending.result.is_some()
                && (pending.completion.is_none() || pending.completion_generation.is_some())
        }) {
            completions.extend(request::completed(edge, context, id));
        } else {
            request::transmit(edge, context, id);
        }
    }
    continue_write(edge, context);
    super::sync::continue_install(edge, context);
    completions
}

pub(super) fn forget(edge: &mut EdgeFederation, id: RequestId) {
    edge.journal.dirty.remove(&Identity::Request(id));
    edge.journal.durable.remove(&Identity::Request(id));
}

pub(super) fn forget_origin(edge: &mut EdgeFederation, connection: ConnectionGeneration) {
    edge.journal.dirty.remove(&Identity::Origin(connection));
    edge.journal.durable.remove(&Identity::Origin(connection));
}

/// Retains each predecessor until its exact successor ACK advances execution.
pub(super) fn queue_update(
    edge: &mut EdgeFederation,
    connection: ConnectionGeneration,
) -> Result<(), Violation> {
    let origin = edge.origins.get_mut(&connection).ok_or(Violation::Phase)?;
    let session =
        origin.session.map(
            |(session_id, user_id)| agenc_relay_federation_wire::OriginSession {
                session_id,
                user_id,
            },
        );
    let account = origin
        .account
        .map(|(account_id, account_session_generation)| {
            agenc_relay_federation_wire::OriginAccount {
                account_id,
                account_session_generation,
            }
        });
    if origin
        .pending_updates
        .back()
        .is_some_and(|update| update.session == session && update.account == account)
    {
        return Ok(());
    }
    if origin.pending_updates.len() >= super::MAX_DEFERRED_COMMANDS {
        return Err(Violation::Ceiling);
    }
    let (previous_generation, previous_origin_object_id) = match origin.pending_updates.back() {
        Some(previous) => {
            let bytes = previous
                .to_object()
                .and_then(|object| object.encode_canonical())
                .map_err(|_| Violation::Codec)?;
            (
                previous.generation,
                *federation_object_id(bytes.as_slice()).as_bytes(),
            )
        }
        None => (origin.generation, origin.object_id),
    };
    let generation = previous_generation
        .checked_add(1)
        .ok_or(Violation::Ceiling)?;
    origin.pending_updates.push_back(OriginRecord {
        network_id: edge.config.network_id,
        home_server_id: edge.config.server_id,
        server_incarnation: edge.config.incarnation,
        origin_id: origin.origin_id,
        generation,
        previous_origin_object_id,
        connection_id: origin.connection_id,
        session,
        account,
        connection_nonce: origin.connection_nonce,
    });
    origin.acked_generation = None;
    Ok(())
}

/// Joins the exact completion proof to the same batch as the delivery cursor.
pub(super) fn completion_write(
    edge: &EdgeFederation,
    header: &agenc_relay_federation_wire::EventHeader,
    projected: &agenc_relay_domain::federation::ProjectedEvent,
    revision: u64,
) -> Result<
    (
        Version,
        crate::state_core::durable::AccountServiceDurableWrite,
    ),
    Violation,
> {
    let correlation = header.correlation.ok_or(Violation::Consistency)?;
    let mut row = request_record(edge, correlation.request_id)?;
    let arm = crate::federation::codec::events::event_arm_object(projected)
        .map_err(|_| Violation::Codec)?;
    let object = header
        .build(&arm)
        .and_then(|object| object.encode_canonical())
        .map_err(|_| Violation::Codec)?;
    row.phase = EdgeRequestPhase::EventCovered;
    row.completion_event_id = Some(*header.event_id.as_bytes());
    row.resulting_state_generation = header.coordinator_state_generation;
    row.completion_coverage = Some(
        agenc_relay_storage::federation_records::CompletionCoverageRecord {
            request_object_id: row.request_object_id,
            completion_event_id: *header.event_id.as_bytes(),
            completion_object_id: *federation_object_id(object.as_slice()).as_bytes(),
            projection_generation: header.projection_generation,
            delivery_sequence: header.delivery_sequence,
            coordinator_state_generation: header.coordinator_state_generation,
        },
    );
    let body = row.encode().map_err(|_| Violation::Codec)?;
    let key =
        request_result_key(correlation.replay_key.to_bytes()).map_err(|_| Violation::Codec)?;
    let write = edge
        .row_write(
            TableId::RequestResult,
            EDGE_REQUEST_KIND,
            key,
            revision,
            0,
            body.clone(),
        )
        .map_err(|_| Violation::Codec)?;
    Ok((
        Version {
            identity: Identity::Request(correlation.request_id),
            body,
        },
        write,
    ))
}

pub(super) fn completion_committed(
    edge: &mut EdgeFederation,
    version: Version,
) -> Result<(), Violation> {
    let Identity::Request(id) = version.identity else {
        return Err(Violation::Consistency);
    };
    let row = EdgeRequestRecord::decode(&version.body).map_err(|_| Violation::Codec)?;
    if let Some(pending) = edge.pending.get_mut(&id) {
        pending.completion_coverage = row.completion_coverage;
        if row.phase == EdgeRequestPhase::SnapshotCovered {
            pending.completion_generation = Some(row.resulting_state_generation);
        }
    }
    edge.journal.durable.insert(version.identity, version.body);
    Ok(())
}

pub(super) fn restore_origin(
    edge: &mut EdgeFederation,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), RuntimeError> {
    let invalid = super::startup::invalid;
    let row = FederationOriginRecord::decode(value.body())?;
    let mut budget = DecodeBudget::new(4_096, 64);
    let record = SchemaObject::decode_exact("FederationOrigin", &row.origin_object, &mut budget)
        .and_then(|object| OriginRecord::from_object(&object))
        .map_err(|_| invalid())?;
    if record.network_id != edge.config.network_id
        || record.home_server_id != edge.config.server_id
        || key
            != &origin_key(
                record.home_server_id,
                record.server_incarnation,
                *record.origin_id.as_bytes(),
                record.generation,
            )?
        || federation_object_id(&row.origin_object).as_bytes() != &row.origin_object_id
    {
        return Err(invalid());
    }
    if record.server_incarnation != edge.config.incarnation {
        return Ok(());
    }
    let existing = edge
        .origins
        .iter()
        .find(|(_, origin)| origin.origin_id == record.origin_id)
        .map(|(generation, origin)| (*generation, origin.generation));
    if existing.is_some_and(|(_, generation)| generation > record.generation) {
        return Ok(());
    }
    let generation =
        existing
            .map(|(generation, _)| generation)
            .unwrap_or(ConnectionGeneration::new(
                u64::MAX
                    .checked_sub(u64::try_from(edge.origins.len()).map_err(|_| invalid())?)
                    .ok_or_else(invalid)?,
            ));
    edge.origins
        .insert(generation, restored_origin(record, &row));
    edge.journal
        .durable
        .insert(Identity::Origin(generation), value.body().to_vec());
    if edge
        .origins
        .get(&generation)
        .is_some_and(|origin| !origin.del_acked)
    {
        edge.journal.dirty.insert(Identity::Origin(generation));
    }
    Ok(())
}

fn restored_origin(record: OriginRecord, row: &FederationOriginRecord) -> ConnectionOrigin {
    ConnectionOrigin {
        revoked: false,
        pending_updates: std::collections::VecDeque::new(),
        update_sent: false,
        origin_id: record.origin_id,
        connection_id: record.connection_id,
        connection_nonce: record.connection_nonce,
        generation: record.generation,
        sequence: row.next_sequence,
        object_id: row.origin_object_id,
        previous_object_id: record.previous_origin_object_id,
        session: record
            .session
            .map(|session| (session.session_id, session.user_id)),
        account: record
            .account
            .map(|account| (account.account_id, account.account_session_generation)),
        acked_generation: None,
        ever_acked: false,
        join_names_pending: false,
        del_acked: row.status == OriginRowStatus::Deleted
            && row.flags & ORIGIN_FLAG_PENDING_DEL == 0,
        deleted: true,
    }
}

pub(super) fn restore_request(
    edge: &mut EdgeFederation,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), RuntimeError> {
    let invalid = super::startup::invalid;
    let row = EdgeRequestRecord::decode(value.body())?;
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let object = SchemaObject::decode_exact("FederationRequest", &row.request_object, &mut budget)
        .map_err(|_| invalid())?;
    let header = RequestHeader::from_object(&object).map_err(|_| invalid())?;
    if header.network_id != edge.config.network_id
        || header.replay_key.home_server_id != edge.config.server_id
        || key != &request_result_key(header.replay_key.to_bytes())?
        || header.request_id.as_bytes() != &row.request_id
        || federation_object_id(&row.request_object).as_bytes() != &row.request_object_id
    {
        return Err(invalid());
    }
    if header.replay_key.server_incarnation != edge.config.incarnation
        || row.phase == EdgeRequestPhase::Rendered
    {
        return Ok(());
    }
    check_restored_coverage(edge, &row)?;
    let generation = edge
        .origins
        .iter()
        .find(|(_, origin)| origin.origin_id == header.replay_key.origin_id)
        .map(|(generation, _)| *generation)
        .ok_or_else(invalid)?;
    let result = restored_result(&row, &header)?;
    if restored_snapshot_covered(edge, &row, &result)? {
        return Ok(());
    }
    let covered = matches!(
        row.phase,
        EdgeRequestPhase::EventCovered | EdgeRequestPhase::SnapshotCovered
    );
    edge.pending.insert(
        header.request_id,
        request::PendingRequest {
            completion_coverage: row.completion_coverage,
            generation,
            sink_gone: true,
            kind: request::PendingKind::Close,
            header,
            bytes: row.request_object,
            sent: false,
            result,
            result_bytes: row.result_object,
            replies: Vec::new(),
            join_echoes: Vec::new(),
            message_echoes: Vec::new(),
            completion: row
                .completion_event_id
                .map(agenc_relay_types::EventId::from_bytes),
            completion_generation: covered.then_some(row.resulting_state_generation),
        },
    );
    edge.journal
        .durable
        .insert(Identity::Request(header.request_id), value.body().to_vec());
    edge.journal
        .dirty
        .insert(Identity::Request(header.request_id));
    Ok(())
}

fn restored_snapshot_covered(
    edge: &EdgeFederation,
    row: &EdgeRequestRecord,
    result: &Option<crate::federation::codec::results::ResultArm>,
) -> Result<bool, RuntimeError> {
    let invalid = super::startup::invalid;
    if row.phase == EdgeRequestPhase::SnapshotCovered {
        if edge.snapshot_cut.is_none_or(|(generation, cut)| {
            generation != edge.replica.projection_generation()
                || cut < row.resulting_state_generation
        }) || !matches!(
            result,
            Some(
                crate::federation::codec::results::ResultArm::Committed { .. }
                    | crate::federation::codec::results::ResultArm::SessionRegistered(_)
            )
        ) {
            return Err(invalid());
        }
        if row.sink_gone {
            return Ok(true);
        }
    }
    Ok(false)
}

fn restored_result(
    row: &EdgeRequestRecord,
    header: &RequestHeader,
) -> Result<Option<crate::federation::codec::results::ResultArm>, RuntimeError> {
    let invalid = super::startup::invalid;
    if row.result_object.is_empty() {
        return Ok(None);
    }
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let object = SchemaObject::decode_exact("FederationResult", &row.result_object, &mut budget)
        .map_err(|_| invalid())?;
    let result_header = ResultHeader::from_object(&object).map_err(|_| invalid())?;
    if result_header.replay_key != header.replay_key
        || result_header.request_id != header.request_id
        || result_header.request_object_id.as_bytes() != &row.request_object_id
        || Some(*federation_object_id(&row.result_object).as_bytes()) != row.result_object_id
        || result_header.completion_event_id.map(|id| *id.as_bytes()) != row.completion_event_id
    {
        return Err(invalid());
    }
    let arm = agenc_relay_federation_wire::decode_result_arm(&object, &mut budget)
        .map_err(|_| invalid())?;
    Ok(Some(
        crate::federation::codec::results::ResultArm::from_object(result_header.result_kind, &arm)
            .map_err(|_| invalid())?,
    ))
}

fn check_restored_coverage(
    edge: &EdgeFederation,
    row: &EdgeRequestRecord,
) -> Result<(), RuntimeError> {
    let invalid = super::startup::invalid;
    if let Some(coverage) = row.completion_coverage {
        if coverage.request_object_id != row.request_object_id
            || Some(coverage.completion_event_id) != row.completion_event_id
            || coverage.coordinator_state_generation != row.resulting_state_generation
            || coverage.projection_generation > edge.replica.projection_generation()
            || (coverage.projection_generation == edge.replica.projection_generation()
                && edge
                    .cursor
                    .is_none_or(|(sequence, _)| sequence < coverage.delivery_sequence))
        {
            return Err(invalid());
        }
    } else if row.phase == EdgeRequestPhase::EventCovered {
        return Err(invalid());
    }
    Ok(())
}

/// Marks a current state for persistence without taking the batch slot yet.
pub(super) fn mark_dirty(edge: &mut EdgeFederation, identity: Identity) {
    edge.journal.dirty.insert(identity);
}

pub(super) fn has_dirty(edge: &EdgeFederation) -> bool {
    !edge.journal.dirty.is_empty()
}

/// Covers exact committed results in the same checkpoint as ACTIVE.
fn snapshot_eligible(edge: &EdgeFederation, pending: &request::PendingRequest, cut: u64) -> bool {
    !(pending.completion_generation.is_some()
        || pending.completion.is_none()
        || pending
            .result
            .as_ref()
            .and_then(request::result_generation)
            .is_some_and(|generation| incomplete_generation(edge, generation))
        || !matches!(
            pending.result,
            Some(
                crate::federation::codec::results::ResultArm::Committed { .. }
                    | crate::federation::codec::results::ResultArm::SessionRegistered(_)
            )
        )
        || pending
            .result
            .as_ref()
            .and_then(request::result_generation)
            .is_none_or(|generation| generation > cut))
}

pub(super) fn snapshot_writes(
    edge: &EdgeFederation,
    cut: u64,
    revision: u64,
) -> Result<
    (
        Vec<Version>,
        Vec<crate::state_core::durable::AccountServiceDurableWrite>,
    ),
    Violation,
> {
    let mut ordered: Vec<_> = edge.pending.values().collect();
    ordered.sort_by_key(|pending| pending.header.replay_key.to_bytes());
    let mut versions = Vec::new();
    let mut writes = Vec::new();
    for pending in ordered {
        if !snapshot_eligible(edge, pending, cut) {
            continue;
        }
        let id = pending.header.request_id;
        if !is_durable(edge, Identity::Request(id)) {
            return Err(Violation::Phase);
        }
        let mut row = request_record(edge, id)?;
        let mut budget = DecodeBudget::new(1 << 20, 4096);
        let header =
            SchemaObject::decode_exact("FederationResult", &row.result_object, &mut budget)
                .and_then(|object| ResultHeader::from_object(&object))
                .map_err(|_| Violation::Codec)?;
        if header.replay_key != pending.header.replay_key
            || header.request_id != id
            || header.request_object_id.as_bytes() != &row.request_object_id
            || header.completion_event_id != pending.completion
        {
            return Err(Violation::Consistency);
        }
        row.phase = EdgeRequestPhase::SnapshotCovered;
        let body = row.encode().map_err(|_| Violation::Codec)?;
        writes.push(
            edge.row_write(
                TableId::RequestResult,
                EDGE_REQUEST_KIND,
                request_result_key(header.replay_key.to_bytes()).map_err(|_| Violation::Codec)?,
                revision,
                0,
                body.clone(),
            )
            .map_err(|_| Violation::Codec)?,
        );
        versions.push(Version {
            identity: Identity::Request(id),
            body,
        });
    }
    Ok((versions, writes))
}

pub(super) fn snapshot_committed(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    versions: Vec<Version>,
) -> Vec<EdgeCompletion> {
    let mut outputs = Vec::new();
    for version in versions {
        let Identity::Request(id) = version.identity else {
            continue;
        };
        if let Err(violation) = completion_committed(edge, version) {
            edge.fail_link(context, violation);
            return outputs;
        }
        outputs.extend(request::completed(edge, context, id));
    }
    outputs
}

/// Retires only a durably acknowledged DEL whose request ownership is settled.
pub(super) fn retire_origin(edge: &mut EdgeFederation, connection: ConnectionGeneration) {
    let acknowledged = edge
        .origins
        .get(&connection)
        .is_some_and(|origin| origin.deleted && origin.del_acked)
        && is_durable(edge, Identity::Origin(connection));
    if !acknowledged {
        return;
    }
    // The coordinator has dropped this origin. Any request still bound to it
    // that never produced a result can never complete: its sink is gone and a
    // replay would be refused. Abandon those requests so they neither replay
    // nor pin the origin against retirement.
    let abandoned: Vec<RequestId> = edge
        .pending
        .iter()
        .filter(|(_, pending)| pending.generation == connection && pending.result.is_none())
        .map(|(id, _)| *id)
        .collect();
    for id in abandoned {
        if let Some(pending) = edge.pending.remove(&id) {
            pending.sink_gone(edge);
        }
        forget(edge, id);
    }
    // A request that already carries a result still renders on retirement, so
    // it keeps the origin until its completion drains.
    if edge
        .pending
        .values()
        .any(|pending| pending.generation == connection)
    {
        return;
    }
    edge.origins.remove(&connection);
    forget_origin(edge, connection);
}

pub(super) fn finish_restore(edge: &mut EdgeFederation) {
    let connections: Vec<_> = edge.origins.keys().copied().collect();
    for connection in connections {
        retire_origin(edge, connection);
    }
}

/// A base snapshot cannot stand in for a missing combined barrier receipt.
fn incomplete_generation(edge: &EdgeFederation, generation: u64) -> bool {
    edge.barrier
        .open
        .as_ref()
        .is_some_and(|open| open.assembly.identity().coordinator_state_generation == generation)
        || edge
            .barrier
            .fenced
            .values()
            .any(|barrier| barrier.stage.identity.coordinator_state_generation == generation)
}

/// A fenced head remains evidence while an unresolved request may name its completion.
pub(super) fn needs_fenced_evidence(edge: &EdgeFederation, generation: u64) -> bool {
    edge.pending.values().any(|pending| {
        pending.completion_generation.is_none()
            && pending
                .result
                .as_ref()
                .and_then(request::result_generation)
                .is_none_or(|expected| expected == generation)
    })
}
