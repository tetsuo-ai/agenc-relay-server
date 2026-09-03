//! FEVENT application on the edge: replica apply, client rendering, the
//! durable projection rows, and the cumulative ACK (spec 20.6, B.5, B.7).

use agenc_ircd_domain::federation::{ProjectedEvent, ProjectionKey};
use agenc_ircd_federation_wire::{
    AssembledObject, DecodeBudget, EventDescriptor, EventHeader, SchemaObject, decode_event_arm,
};
use agenc_ircd_storage::federation_records::{
    FederationPeerRecord, PEER_RECORD_KIND, PROJECTION_ENTRY_KIND, PeerPhase,
    ProjectionEntryRecord, peer_key, projection_entry_key,
};
use agenc_ircd_storage::{PersistentRecordValue, TableId};
use agenc_ircd_types::{EventId, RequestId};

use super::{EdgeCompletion, EdgeFederation, MAX_QUEUED_EVENTS, PendingCommit, Phase, Violation};
use crate::RuntimeError;
use crate::federation::codec::events::projected_event_of;
use crate::federation::codec::projection::{projection_arm_object, projection_kind};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;

/// Receives one event object.
pub(super) fn receive(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    descriptor: EventDescriptor,
    object: &AssembledObject,
) -> Result<Vec<EdgeCompletion>, Violation> {
    if edge.phase != Phase::Active {
        return Err(Violation::Phase);
    }
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let event = SchemaObject::decode_exact("FederationEvent", object.as_slice(), &mut budget)
        .map_err(|_| Violation::Codec)?;
    let header = EventHeader::from_object(&event).map_err(|_| Violation::Codec)?;
    check_header(edge, &header, &descriptor, object)?;
    let arm = decode_event_arm(&event, &mut budget).map_err(|_| Violation::Codec)?;
    let projected =
        projected_event_of(header.event_kind, &arm, &mut budget).map_err(|_| Violation::Codec)?;
    if edge.commit.is_some() {
        if edge.queued_events.len() >= MAX_QUEUED_EVENTS {
            return Err(Violation::Ceiling);
        }
        edge.queued_events.push_back((header, projected));
        // The cursor advances only after the durable ACK; queued events are
        // sequenced by their headers when they drain.
        return Ok(Vec::new());
    }
    apply(edge, context, header, projected)
}

/// Checks the event header against its carrier, the link, the replica
/// generation, and the next expected delivery sequence (spec B.7).
fn check_header(
    edge: &EdgeFederation,
    header: &EventHeader,
    descriptor: &EventDescriptor,
    object: &AssembledObject,
) -> Result<(), Violation> {
    let matches = header.target_server_id == edge.config.server_id
        && header.network_id == edge.config.network_id
        && header.delivery_sequence == descriptor.delivery_sequence
        && header.event_id == descriptor.event_id
        && descriptor.object_id == object.object_id()
        && header.projection_generation == edge.replica.projection_generation()
        && header.cross_profile.is_none();
    let expected = edge
        .cursor
        .map_or(0, |(sequence, _)| sequence.saturating_add(1));
    if !matches || header.delivery_sequence != expected {
        return Err(Violation::Consistency);
    }
    Ok(())
}

/// Applies queued events once the batch slot is free.
pub(super) fn drain_queued(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> Vec<EdgeCompletion> {
    let mut completions = Vec::new();
    while edge.commit.is_none() {
        let Some((header, projected)) = edge.queued_events.pop_front() else {
            break;
        };
        match apply(edge, context, header, projected) {
            Ok(more) => completions.extend(more),
            Err(violation) => {
                edge.fail_link(context, violation);
                break;
            }
        }
    }
    completions
}

/// Applies one event to the replica, renders it, and stages its rows.
fn apply(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    header: EventHeader,
    projected: ProjectedEvent,
) -> Result<Vec<EdgeCompletion>, Violation> {
    let outcome = edge
        .replica
        .apply(&projected, header.coordinator_state_generation)
        .map_err(|_| Violation::Consistency)?;
    edge.counters.events_applied = edge.counters.events_applied.saturating_add(1);
    super::render::remember_nicknames(edge, &projected);
    super::render::render_event(edge, context, &projected, &outcome);
    let completion = match &projected {
        ProjectedEvent::RequestCompleted { .. } => completion_of(edge, &header)?,
        _ => None,
    };
    let upserted = outcome.upserted.clone();
    let removed = outcome.removed.clone();
    let cursor = Some((header.delivery_sequence, header.event_id));
    let pending = PendingCommit::Event {
        header: Box::new(header),
        completion,
    };
    stage_rows(edge, context, cursor, pending, |edge, context, revision| {
        let mut writes = Vec::new();
        for key in &upserted {
            if let Some(write) = entry_row(edge, key, revision) {
                writes.push(write);
            }
        }
        for key in &removed {
            if let Some(write) = removal_write(edge, context, key) {
                writes.push(write);
            }
        }
        writes
    })?;
    Ok(Vec::new())
}

/// Matches a `request_completed` event to its pending request, or records
/// it for a result that has not arrived yet.
fn completion_of(
    edge: &mut EdgeFederation,
    header: &EventHeader,
) -> Result<Option<RequestId>, Violation> {
    let correlation = header.correlation.ok_or(Violation::Consistency)?;
    match edge.by_completion.get(&header.event_id).copied() {
        Some(request_id) if request_id == correlation.request_id => Ok(Some(request_id)),
        Some(_) => Err(Violation::Consistency),
        None => {
            edge.applied_completions.insert(header.event_id);
            Ok(None)
        }
    }
}

/// The delete of one replica entry, only when its row exists.
fn removal_write(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    key: &ProjectionKey,
) -> Option<AccountServiceDurableWrite> {
    let generation = edge.replica.projection_generation();
    let stored =
        projection_entry_key(edge.config.server_id, generation, key.kind(), key.primary()).ok()?;
    let exists = context
        .index()
        .existing(TableId::EdgeProjection, &stored)
        .is_ok_and(|existing| existing.is_some());
    if !exists {
        return None;
    }
    AccountServiceDurableWrite::delete(TableId::EdgeProjection, stored).ok()
}

/// The durable row of one replica entry under the active generation.
fn entry_row(
    edge: &EdgeFederation,
    key: &ProjectionKey,
    revision: u64,
) -> Option<AccountServiceDurableWrite> {
    let record = edge.replica.record(key)?;
    let generation = edge.replica.projection_generation();
    let arm = projection_arm_object(&record).ok()?;
    let entry = agenc_ircd_federation_wire::ProjectionEntryHeader {
        network_id: edge.config.network_id,
        target_server_id: edge.config.server_id,
        projection_generation: generation,
        projection_kind: projection_kind(&record),
    }
    .build(&arm)
    .ok()?;
    let encoded = agenc_ircd_federation_wire::CanonicalEncode::encode_canonical(&entry).ok()?;
    let body = ProjectionEntryRecord {
        entry_object_id: *agenc_ircd_federation_wire::federation_object_id(encoded.as_slice())
            .as_bytes(),
        entry_object: encoded.as_slice().to_vec(),
    }
    .encode()
    .ok()?;
    let stored =
        projection_entry_key(edge.config.server_id, generation, key.kind(), key.primary()).ok()?;
    edge.row_write(
        TableId::EdgeProjection,
        PROJECTION_ENTRY_KIND,
        stored,
        revision,
        generation,
        body,
    )
    .ok()
}

/// Stages rows plus the peer row behind a checkpoint plan. `cursor` names
/// the delivery position the batch makes durable; `build` produces the rows
/// at the plan's resulting revision.
pub(super) fn stage_rows(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    cursor: Option<(u64, EventId)>,
    pending: PendingCommit,
    build: impl FnOnce(&EdgeFederation, &StateCoreContext, u64) -> Vec<AccountServiceDurableWrite>,
) -> Result<(), Violation> {
    if edge.commit.is_some() {
        return Err(Violation::Ceiling);
    }
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let mut writes = build(edge, context, revision);
    writes.push(edge.peer_row(cursor.or(edge.cursor), revision)?);
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|_| Violation::Ceiling)?;
    edge.commit = Some(pending);
    Ok(())
}

impl EdgeFederation {
    /// Wraps one body in the domain record envelope for the edge's tables.
    pub(super) fn row_write(
        &self,
        table: TableId,
        kind: u16,
        key: agenc_ircd_storage::StoredKey,
        revision: u64,
        generation: u64,
        body: Vec<u8>,
    ) -> Result<AccountServiceDurableWrite, RuntimeError> {
        let _ = self;
        let plaintext =
            PersistentRecordValue::new(table, kind, revision, generation, None, Vec::new(), body)?
                .encode()?;
        AccountServiceDurableWrite::put(table, key, plaintext)
    }

    /// The durable coordinator row: cursor, generation, and installed epoch.
    pub(super) fn peer_row(
        &self,
        cursor: Option<(u64, EventId)>,
        revision: u64,
    ) -> Result<AccountServiceDurableWrite, Violation> {
        let record = FederationPeerRecord {
            server_incarnation: [0; 16],
            recovery_epoch: self
                .installed_epoch
                .map_or([0; 16], |epoch| *epoch.as_bytes()),
            accepted_epochs: Vec::new(),
            phase: if self.phase == Phase::Active {
                PeerPhase::Ready
            } else {
                PeerPhase::Suspended
            },
            projection_generation: self.replica.projection_generation(),
            next_delivery_sequence: cursor.map_or(0, |(sequence, _)| sequence.saturating_add(1)),
            cursor: cursor.map(|(delivery_sequence, event_id)| {
                agenc_ircd_storage::federation_records::DeliveryCursorRecord {
                    delivery_sequence,
                    event_id: *event_id.as_bytes(),
                }
            }),
            active_entry_count: u64::try_from(self.replica.entry_count()).unwrap_or(u64::MAX),
            active_entry_bytes: 0,
            pending_generation: None,
            snapshot_required: false,
            cleanup_cursor: None,
            quarantined: false,
            client_resync_epoch: self.client_resync_epoch,
        }
        .encode()
        .map_err(|_| Violation::Codec)?;
        let plaintext = PersistentRecordValue::new(
            TableId::FederationPeer,
            PEER_RECORD_KIND,
            revision,
            0,
            None,
            Vec::new(),
            record,
        )
        .and_then(|value| value.encode())
        .map_err(|_| Violation::Codec)?;
        let key = peer_key(self.config.coordinator.server_id()).map_err(|_| Violation::Codec)?;
        AccountServiceDurableWrite::put(TableId::FederationPeer, key, plaintext)
            .map_err(|_| Violation::Codec)
    }
}
