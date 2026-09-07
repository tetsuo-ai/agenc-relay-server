//! FEVENT application on the edge: replica apply, client rendering, the
//! durable projection rows, and the ordered event ACK (spec 20.6, B.5, B.7).

use agenc_ircd_domain::federation::{EdgeReplica, ProjectedEvent, ProjectionKey};
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

/// Projection state retained until an ordinary event's storage batch commits.
pub(super) struct ProjectionBefore {
    pub(super) replica: EdgeReplica,
    pub(super) nicknames:
        std::collections::BTreeMap<agenc_ircd_types::UserId, agenc_ircd_domain::NicknameValue>,
}

pub(super) fn restore_projection(edge: &mut EdgeFederation) {
    if let Some(previous) = edge.event_before.take() {
        edge.replica = previous.replica;
        edge.nicknames = previous.nicknames;
    }
}

/// Receives one event object.
pub(super) fn receive(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    descriptor: EventDescriptor,
    object: &AssembledObject,
) -> Result<Vec<EdgeCompletion>, Violation> {
    if !matches!(edge.phase, Phase::Active | Phase::Origins) {
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
    if let ProjectedEvent::RequestCompleted {
        resulting_state_generation,
    } = &projected
    {
        completion_of(edge, &header, *resulting_state_generation)?;
    }
    let queued = if header.cross_profile.is_some() {
        QueuedEvent::BarrierPart {
            header,
            projected,
            object_id: *object.object_id().as_bytes(),
            bytes: object.as_slice().to_vec(),
        }
    } else {
        QueuedEvent::Base {
            header,
            projected,
            encoded_bytes: object.as_slice().len(),
        }
    };
    // The edge's own slot or a batch of the encrypted profile in flight
    // holds the event; both profiles drain after every commit.
    if edge.commit.is_some() || context.in_flight() {
        if edge.queued_events.len() >= MAX_QUEUED_EVENTS {
            return Err(Violation::Ceiling);
        }
        edge.queued_events.push_back(queued);
        // The cursor advances only after the durable ACK; queued events are
        // sequenced by their headers when they drain.
        return Ok(Vec::new());
    }
    apply_queued(edge, context, queued)
}

/// One event waiting behind the batch in flight.
pub(super) enum QueuedEvent {
    /// An ordinary base event.
    Base {
        header: EventHeader,
        projected: ProjectedEvent,
        encoded_bytes: usize,
    },
    /// A base part of a cross-profile barrier, with its exact bytes.
    BarrierPart {
        header: EventHeader,
        projected: ProjectedEvent,
        object_id: [u8; 32],
        bytes: Vec<u8>,
    },
}

fn apply_queued(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    queued: QueuedEvent,
) -> Result<Vec<EdgeCompletion>, Violation> {
    if let QueuedEvent::Base { header, .. } = &queued {
        let expected = edge
            .cursor
            .map_or(Some(0), |(sequence, _)| sequence.checked_add(1));
        if expected != Some(header.delivery_sequence) || edge.barrier.is_open() {
            return Err(Violation::Consistency);
        }
    }
    match queued {
        QueuedEvent::Base {
            header, projected, ..
        } => apply(edge, context, header, projected),
        QueuedEvent::BarrierPart {
            header,
            projected,
            object_id,
            bytes,
        } => super::barrier::base_part(edge, context, header, projected, object_id, bytes)
            .map(|()| Vec::new()),
    }
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
        && header.projection_generation == edge.replica.projection_generation();
    if !matches {
        return Err(Violation::Consistency);
    }
    // A barrier part is checked against the cursor when the set completes;
    // an ordinary event must follow the cursor and may not interleave with
    // an open barrier (spec 20.8).
    if header.cross_profile.is_some() {
        return Ok(());
    }
    let expected = next_received_sequence(edge);
    if edge.barrier.is_open() || Some(header.delivery_sequence) != expected {
        return Err(Violation::Consistency);
    }
    Ok(())
}

fn next_received_sequence(edge: &EdgeFederation) -> Option<u64> {
    let staged = match edge.commit.as_ref() {
        Some(PendingCommit::Event { header, .. }) => Some(header.delivery_sequence),
        Some(PendingCommit::OrdinaryBatch(pending)) => pending
            .receipts
            .last()
            .map(|receipt| receipt.header.delivery_sequence),
        _ => edge.cursor.map(|(sequence, _)| sequence),
    };
    let last_received = edge
        .queued_events
        .back()
        .map(|queued| match queued {
            QueuedEvent::Base { header, .. } | QueuedEvent::BarrierPart { header, .. } => {
                header.delivery_sequence
            }
        })
        .or(staged);
    last_received.map_or(Some(0), |sequence| sequence.checked_add(1))
}

/// Applies queued events once the batch slot is free.
pub(super) fn drain_queued(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> Vec<EdgeCompletion> {
    let mut completions = Vec::new();
    while edge.commit.is_none() && context.edge_checkpoint_ready() {
        match super::ordinary_batch::try_stage(edge, context) {
            Ok(true) => break,
            Ok(false) => {}
            Err(violation) => {
                edge.fail_link(context, violation);
                break;
            }
        }
        let Some(queued) = edge.queued_events.pop_front() else {
            break;
        };
        match apply_queued(edge, context, queued) {
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
    if edge.event_before.is_some() || edge.commit.is_some() {
        return Err(Violation::Phase);
    }
    edge.event_before = Some(ProjectionBefore {
        replica: edge.replica.clone(),
        nicknames: edge.nicknames.clone(),
    });
    let result = apply_projection(edge, context, header, projected);
    if result.is_err() {
        restore_projection(edge);
    }
    result
}

fn apply_projection(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    header: EventHeader,
    projected: ProjectedEvent,
) -> Result<Vec<EdgeCompletion>, Violation> {
    let label = super::render::event_channel_label(edge, &projected);
    let outcome = edge
        .replica
        .apply(&projected, header.coordinator_state_generation)
        .map_err(|_| Violation::Consistency)?;
    super::render::remember_nicknames(edge, &projected);
    let mut fanout = super::render::EventFanout::default();
    let join_echo = super::render::render_event(
        edge,
        context,
        &header,
        &projected,
        &outcome,
        label.as_deref(),
        &mut fanout,
    )?;
    let completion = match &projected {
        ProjectedEvent::RequestCompleted {
            resulting_state_generation,
        } => completion_of(edge, &header, *resulting_state_generation)?,
        _ => None,
    };
    let upserted = outcome.upserted.clone();
    let removed = outcome.removed.clone();
    let cursor = Some((header.delivery_sequence, header.event_id));
    let coverage = if completion.is_some() {
        let revision = context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| Violation::Ceiling)?
            .resulting_revision()
            .get();
        Some(super::journal::completion_write(
            edge, &header, &projected, revision,
        )?)
    } else {
        None
    };
    let (coverage, coverage_write) = match coverage {
        Some((version, write)) => (Some(version), Some(write)),
        None => (None, None),
    };
    let pending = PendingCommit::Event {
        header: Box::new(header),
        completion,
        coverage,
        join_echo: join_echo.map(Box::new),
    };
    stage_rows(
        edge,
        context,
        cursor,
        pending,
        fanout.finish()?,
        |edge, context, revision| {
            projection_writes(edge, context, revision, &upserted, &removed, coverage_write)
        },
    )?;
    Ok(Vec::new())
}

fn projection_writes(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    revision: u64,
    upserted: &[ProjectionKey],
    removed: &[ProjectionKey],
    coverage_write: Option<AccountServiceDurableWrite>,
) -> Result<Vec<AccountServiceDurableWrite>, Violation> {
    let mut writes = Vec::new();
    if let Some(write) = coverage_write {
        writes.push(write);
    }
    for key in upserted {
        writes.push(entry_row(edge, key, revision)?);
    }
    for key in removed {
        if let Some(write) = removal_write(edge, context, key)? {
            writes.push(write);
        }
    }
    Ok(writes)
}

/// Validates a completion's correlation without publishing its application.
pub(super) fn completion_of(
    edge: &EdgeFederation,
    header: &EventHeader,
    arm_generation: u64,
) -> Result<Option<RequestId>, Violation> {
    if arm_generation != header.coordinator_state_generation {
        return Err(Violation::Consistency);
    }
    let correlation = header.correlation.ok_or(Violation::Consistency)?;
    if edge
        .by_completion
        .get(&header.event_id)
        .is_some_and(|request_id| *request_id != correlation.request_id)
        || edge
            .pending
            .get(&correlation.request_id)
            .is_some_and(|pending| {
                pending.header.replay_key != correlation.replay_key
                    || pending
                        .result
                        .as_ref()
                        .and_then(super::request::result_generation)
                        .is_some_and(|generation| generation != arm_generation)
                    || pending
                        .completion
                        .is_some_and(|event_id| event_id != header.event_id)
            })
    {
        return Err(Violation::Consistency);
    }
    // A durable origin DEL can retire a sink-gone request before its old
    // completion finishes replaying. The event still advances the durable
    // stream, but has no request coverage or client reply left to release.
    if !edge.pending.contains_key(&correlation.request_id) {
        return Ok(None);
    }
    super::join_echo::validate_completion(edge, &[], header)?;
    Ok(Some(correlation.request_id))
}

/// Meets a durable completion with a result, including one received during
/// the storage batch. An absent result keeps a marker only for a live request.
pub(super) fn committed_completion(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    event_id: EventId,
    request_id: RequestId,
    state_generation: u64,
) -> Vec<EdgeCompletion> {
    let Some(pending) = edge.pending.get_mut(&request_id) else {
        return Vec::new();
    };
    if pending
        .completion
        .is_some_and(|completion| completion != event_id)
        || edge
            .by_completion
            .get(&event_id)
            .is_some_and(|owner| *owner != request_id)
        || pending
            .result
            .as_ref()
            .and_then(super::request::result_generation)
            .is_some_and(|generation| generation != state_generation)
    {
        edge.fail_link(context, Violation::Consistency);
        return Vec::new();
    }
    pending.completion = Some(event_id);
    pending.completion_generation = Some(state_generation);
    if pending.result.is_some() {
        super::request::completed(edge, context, request_id)
    } else {
        edge.applied_completions.insert(event_id);
        Vec::new()
    }
}

/// A result arriving during storage must match the already staged event.
pub(super) fn staged_completion_generation(
    edge: &EdgeFederation,
    request_id: RequestId,
) -> Option<u64> {
    match edge.commit.as_ref()? {
        PendingCommit::Event {
            header,
            completion: Some(owner),
            ..
        } if *owner == request_id => Some(header.coordinator_state_generation),
        PendingCommit::OrdinaryBatch(pending) => pending
            .receipts
            .iter()
            .find(|receipt| receipt.completion == Some(request_id))
            .map(|receipt| receipt.header.coordinator_state_generation),
        PendingCommit::BarrierApplied { .. } => edge
            .barrier
            .open
            .as_ref()?
            .base_events
            .values()
            .find_map(|(header, projected)| {
                (matches!(projected, ProjectedEvent::RequestCompleted { .. })
                    && header
                        .correlation
                        .is_some_and(|correlation| correlation.request_id == request_id))
                .then_some(header.coordinator_state_generation)
            }),
        _ => None,
    }
}

/// The delete of one replica entry, only when its row exists.
pub(super) fn removal_write(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    key: &ProjectionKey,
) -> Result<Option<AccountServiceDurableWrite>, Violation> {
    let generation = edge.replica.projection_generation();
    let stored = projection_entry_key(edge.config.server_id, generation, key.kind(), key.primary())
        .map_err(|_| Violation::Codec)?;
    let exists = context
        .index()
        .existing(TableId::EdgeProjection, &stored)
        .map_err(|_| Violation::Consistency)?
        .is_some();
    if !exists {
        return Ok(None);
    }
    AccountServiceDurableWrite::delete(TableId::EdgeProjection, stored)
        .map(Some)
        .map_err(|_| Violation::Codec)
}

/// The durable row of one replica entry under the active generation.
pub(super) fn entry_row(
    edge: &EdgeFederation,
    key: &ProjectionKey,
    revision: u64,
) -> Result<AccountServiceDurableWrite, Violation> {
    let record = edge.replica.record(key).ok_or(Violation::Consistency)?;
    let generation = edge.replica.projection_generation();
    let arm = projection_arm_object(&record).map_err(|_| Violation::Codec)?;
    let entry = agenc_ircd_federation_wire::ProjectionEntryHeader {
        network_id: edge.config.network_id,
        target_server_id: edge.config.server_id,
        projection_generation: generation,
        projection_kind: projection_kind(&record),
    }
    .build(&arm)
    .map_err(|_| Violation::Codec)?;
    let encoded = agenc_ircd_federation_wire::CanonicalEncode::encode_canonical(&entry)
        .map_err(|_| Violation::Codec)?;
    let body = ProjectionEntryRecord {
        entry_object_id: *agenc_ircd_federation_wire::federation_object_id(encoded.as_slice())
            .as_bytes(),
        entry_object: encoded.as_slice().to_vec(),
    }
    .encode()
    .map_err(|_| Violation::Codec)?;
    let stored = projection_entry_key(edge.config.server_id, generation, key.kind(), key.primary())
        .map_err(|_| Violation::Codec)?;
    edge.row_write(
        TableId::EdgeProjection,
        PROJECTION_ENTRY_KIND,
        stored,
        revision,
        generation,
        body,
    )
    .map_err(|_| Violation::Codec)
}

/// Stages rows plus the peer row behind a checkpoint plan. `cursor` names
/// the delivery position the batch makes durable; `build` produces the rows
/// at the plan's resulting revision.
pub(super) fn stage_rows(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    cursor: Option<(u64, EventId)>,
    pending: PendingCommit,
    fanout: crate::state_core::fanout::FanoutRequest,
    build: impl FnOnce(
        &EdgeFederation,
        &StateCoreContext,
        u64,
    ) -> Result<Vec<AccountServiceDurableWrite>, Violation>,
) -> Result<(), Violation> {
    if edge.commit.is_some() {
        return Err(Violation::Ceiling);
    }
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let mut writes = build(edge, context, revision)?;
    writes.push(edge.peer_row(cursor.or(edge.cursor), revision)?);
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
        let record = self
            .peer_record(cursor)
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
    pub(super) fn peer_record(&self, cursor: Option<(u64, EventId)>) -> FederationPeerRecord {
        FederationPeerRecord {
            fenced_incarnations: Vec::new(),
            server_incarnation: self
                .live
                .as_ref()
                .map(|live| live.coordinator_incarnation)
                .or(self.installed_incarnation)
                .map_or([0; 16], |id| *id.as_bytes()),
            recovery_epoch: self
                .live
                .as_ref()
                .map(|live| live.coordinator_epoch)
                .or(self.accepted_epoch)
                .or(self.installed_epoch)
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
            pending_generation: super::sync::pending_generation(self),
            snapshot_required: self
                .live
                .as_ref()
                .map(|live| live.coordinator_epoch)
                .or(self.accepted_epoch)
                .is_some_and(|accepted| self.installed_epoch != Some(accepted))
                || self.live.as_ref().is_some_and(|live| {
                    self.installed_incarnation != Some(live.coordinator_incarnation)
                })
                || self.snapshot.is_some(),
            cleanup_cursor: None,
            quarantined: false,
            client_resync_epoch: self.client_resync_epoch,
        }
    }
}
