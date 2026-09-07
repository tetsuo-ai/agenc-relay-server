//! The cross-profile barrier on the edge (architecture 20.8): base parts
//! arrive as FEVENT objects carrying the tuple and companion parts arrive
//! from the E2EE router; each part is staged as an immutable row as it
//! arrives, and the complete set applies in one transaction that advances
//! both cursors, writes the receipt, and sends both final acknowledgements.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_domain::federation::{ProjectedEvent, ProjectionKey};
use agenc_ircd_e2ee::federation::frames::{CompanionFrame, DeliveryPosition};
use agenc_ircd_federation_wire::{
    CrossProfilePart, EventHeader, FederationFrame, FederationLineText,
};
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::BARRIER_ROW_KIND;
use agenc_ircd_storage::e2ee_records::barrier::{
    BARRIER_RETENTION_SECONDS, BarrierHead, BarrierIdentity, BarrierPart, BarrierReceipt,
    CrossProfileStream,
};
use agenc_ircd_types::EventId;

use super::{EdgeFederation, PendingCommit, Violation};
use crate::e2ee::barrier::{BarrierAssembly, Staged, StreamCursor, replay_matches};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;

/// The open barrier with the decoded base events it will apply.
#[derive(Clone)]
pub(super) struct OpenBarrier {
    pub(super) assembly: BarrierAssembly,
    pub(super) base_events: BTreeMap<u16, (EventHeader, ProjectedEvent)>,
}

/// The barrier state the edge keeps beside its replica.
#[derive(Default)]
pub(super) struct BarrierState {
    /// The barrier being assembled.
    pub(super) open: Option<OpenBarrier>,
    /// Receipts of applied barriers by mutation identity.
    pub(super) applied: BTreeMap<[u8; 16], BarrierReceipt>,
    /// Parts of an applied barrier seen again since its receipt.
    pub(super) replayed: BTreeMap<[u8; 16], BTreeSet<u16>>,
    /// The companion delivery generation in use.
    pub(super) companion_generation: u64,
    /// The last companion position acknowledged.
    pub(super) companion_cursor: Option<(u64, [u8; 16])>,
    /// A complete assembly whose parts are all durable, awaiting the apply
    /// transaction the E2EE router joins with its companion writes.
    pub(super) ready: bool,
    rollback: Option<ProjectionBackup>,
    /// Collecting heads superseded by a durably accepted coordinator identity.
    pub(super) fenced: BTreeMap<[u8; 16], super::fence::FencedBarrier>,
}

struct ProjectionBackup {
    replica: agenc_ircd_domain::federation::EdgeReplica,
    nicknames: BTreeMap<agenc_ircd_types::UserId, agenc_ircd_domain::NicknameValue>,
}

impl BarrierState {
    /// Whether a barrier is being assembled.
    pub(super) fn is_open(&self) -> bool {
        self.open.is_some()
    }
}

/// The identity every part of a barrier must carry, from the link and the
/// event header.
fn identity(
    edge: &EdgeFederation,
    tuple: CrossProfilePart,
    state_generation: u64,
) -> Result<BarrierIdentity, Violation> {
    let live = edge.live.as_ref().ok_or(Violation::Phase)?;
    Ok(BarrierIdentity {
        network_id: *edge.config.network_id.as_bytes(),
        coordinator_server_id: *edge.config.coordinator.server_id().as_bytes(),
        coordinator_server_incarnation: *live.coordinator_incarnation.as_bytes(),
        coordinator_recovery_epoch: *live.coordinator_epoch.as_bytes(),
        target_server_id: *edge.config.server_id.as_bytes(),
        target_server_incarnation: *edge.config.incarnation.as_bytes(),
        mutation_id: tuple.mutation_id,
        coordinator_state_generation: state_generation,
        part_count: tuple.part_count,
    })
}

/// A base FEVENT carrying the tuple: one base part of the barrier.
pub(super) fn base_part(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    header: EventHeader,
    projected: ProjectedEvent,
    object_id: [u8; 32],
    bytes: Vec<u8>,
) -> Result<(), Violation> {
    let tuple = header.cross_profile.ok_or(Violation::Consistency)?;
    let part = BarrierPart {
        identity: identity(edge, tuple, header.coordinator_state_generation)?,
        stream: CrossProfileStream::Base,
        part_index: tuple.part_index,
        delivery_generation: header.projection_generation,
        delivery_sequence: header.delivery_sequence,
        event_id: *header.event_id.as_bytes(),
        event_object_id: object_id,
        encoded_event_object: bytes,
        payload_object_id: None,
        payload_object_bytes: 0,
    };
    stage_part(edge, context, part, Some((header, projected)), None)
}

/// A companion EEVENT part handed over by the E2EE router.
pub(super) fn companion_part(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    part: BarrierPart,
    payload: Option<Vec<u8>>,
) -> Result<(), Violation> {
    let expected = identity(
        edge,
        CrossProfilePart {
            mutation_id: part.identity.mutation_id,
            part_index: part.part_index,
            part_count: part.identity.part_count,
        },
        part.identity.coordinator_state_generation,
    )?;
    if part.identity != expected || part.stream != CrossProfileStream::Companion {
        return Err(Violation::Consistency);
    }
    stage_part(edge, context, part, None, payload)
}

/// Stages one part: a replay of an applied barrier is answered from its
/// receipt, a new part opens or continues the assembly and is written as
/// an immutable row before anything else happens.
fn stage_part(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    part: BarrierPart,
    base_event: Option<(EventHeader, ProjectedEvent)>,
    payload: Option<Vec<u8>>,
) -> Result<(), Violation> {
    let mutation_id = part.identity.mutation_id;
    if edge.barrier.applied.contains_key(&mutation_id) {
        return replayed_part(edge, context, &part);
    }
    let mut open = match edge.barrier.open.as_ref() {
        Some(open) if open.assembly.identity().mutation_id == mutation_id => open.clone(),
        Some(_) => return Err(Violation::Consistency),
        None => OpenBarrier {
            assembly: BarrierAssembly::open(part.identity).map_err(|_| Violation::Consistency)?,
            base_events: BTreeMap::new(),
        },
    };
    match open.assembly.stage(part.clone()) {
        Ok(Staged::Duplicate) => return Ok(()),
        Ok(Staged::Recorded { .. }) => {}
        Err(_) => return Err(Violation::Consistency),
    }
    if let Some(event) = base_event {
        open.base_events.insert(part.part_index, event);
    }
    let head = BarrierHead::Stage(open.assembly.head().clone());
    let revision = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?
        .resulting_revision()
        .get();
    let mut writes = vec![
        barrier_row(edge, revision, part.identity.head_key(), head.encode())?,
        barrier_row(
            edge,
            revision,
            part.identity.part_key(part.part_index),
            part.encode(),
        )?,
    ];
    if let Some(write) = payload_row(edge, context, &part, payload, revision)? {
        writes.push(write);
    }
    super::events::stage_rows(
        edge,
        context,
        None,
        PendingCommit::BarrierPart(Box::new(open)),
        super::render::EventFanout::default().finish()?,
        |_, _, _| Ok(writes),
    )
}

fn payload_row(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    part: &BarrierPart,
    payload: Option<Vec<u8>>,
    revision: u64,
) -> Result<Option<AccountServiceDurableWrite>, Violation> {
    use agenc_ircd_storage::e2ee_records::{OBJECT_RECORD_KIND, ObjectRow};
    let Some(bytes) = payload else {
        return if part.payload_object_id.is_none() {
            Ok(None)
        } else {
            Err(Violation::Consistency)
        };
    };
    if part.payload_object_id != Some(*agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes())
        || usize::try_from(part.payload_object_bytes).ok() != Some(bytes.len())
    {
        return Err(Violation::Consistency);
    }
    let row = ObjectRow::new(bytes).map_err(|_| Violation::Codec)?;
    let key = row.key().map_err(|_| Violation::Codec)?;
    if context
        .index()
        .existing(TableId::E2eeObject, &key)
        .map_err(|_| Violation::Ceiling)?
        .is_some()
    {
        return Ok(None);
    }
    edge.row_write(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        key,
        revision,
        0,
        row.encode().map_err(|_| Violation::Codec)?,
    )
    .map(Some)
    .map_err(|_| Violation::Codec)
}

fn barrier_row(
    edge: &EdgeFederation,
    revision: u64,
    key: Result<agenc_ircd_storage::StoredKey, agenc_ircd_storage::StorageError>,
    body: Result<Vec<u8>, agenc_ircd_storage::StorageError>,
) -> Result<AccountServiceDurableWrite, Violation> {
    edge.row_write(
        TableId::E2eeState,
        BARRIER_ROW_KIND,
        key.map_err(|_| Violation::Codec)?,
        revision,
        0,
        body.map_err(|_| Violation::Codec)?,
    )
    .map_err(|_| Violation::Codec)
}

/// A part of an already applied barrier: it must match the receipt, and
/// once every part was seen again both final acknowledgements repeat.
fn replayed_part(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    part: &BarrierPart,
) -> Result<(), Violation> {
    let mutation_id = part.identity.mutation_id;
    let receipt = edge
        .barrier
        .applied
        .get(&mutation_id)
        .ok_or(Violation::Consistency)?;
    if !replay_matches(receipt, part) {
        return Err(Violation::Consistency);
    }
    let seen = edge.barrier.replayed.entry(mutation_id).or_default();
    seen.insert(part.part_index);
    if seen.len() != usize::from(receipt.identity.part_count) {
        return Ok(());
    }
    edge.barrier.replayed.remove(&mutation_id);
    let receipt = receipt.clone();
    acknowledge(edge, context, &receipt);
    Ok(())
}

/// The last base position and the last companion position of a receipt.
type LastEntries = ((u64, [u8; 16]), (u64, u64, [u8; 16]));

/// The last base and companion entries of a receipt.
pub(super) fn last_entries(receipt: &BarrierReceipt) -> Option<LastEntries> {
    let base = receipt
        .entries
        .iter()
        .filter(|entry| entry.stream == CrossProfileStream::Base)
        .max_by_key(|entry| entry.delivery_sequence)?;
    let companion = receipt
        .entries
        .iter()
        .filter(|entry| entry.stream == CrossProfileStream::Companion)
        .max_by_key(|entry| entry.delivery_sequence)?;
    Some((
        (base.delivery_sequence, base.event_id),
        (
            companion.delivery_generation,
            companion.delivery_sequence,
            companion.event_id,
        ),
    ))
}

/// Sends the two final cumulative acknowledgements of an applied barrier.
fn acknowledge(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    receipt: &BarrierReceipt,
) {
    let Some(((base_sequence, base_event), (generation, sequence, event))) = last_entries(receipt)
    else {
        return;
    };
    let sent = edge.send_frame(
        context,
        &FederationFrame::Ack {
            coordinator_server_id: edge.config.coordinator.server_id(),
            delivery_sequence: base_sequence,
            event_id: EventId::from_bytes(base_event),
        },
    );
    if sent {
        send_companion_ack(edge, context, generation, sequence, event);
    }
}

/// Sends one EACK on the companion stream.
pub(super) fn send_companion_ack(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    delivery_generation: u64,
    delivery_sequence: u64,
    event_id: [u8; 16],
) {
    let frame = CompanionFrame::Ack(DeliveryPosition {
        server_id: *edge.config.coordinator.server_id().as_bytes(),
        delivery_generation,
        delivery_sequence,
        event_id,
    });
    let line = frame
        .render(&edge.config.server_name)
        .ok()
        .and_then(|text| FederationLineText::from_rendered(text).ok());
    let Some(line) = line else {
        edge.fail_link(context, Violation::Codec);
        return;
    };
    let Some(live) = edge.live.as_ref() else {
        return;
    };
    if let Err(refusal) = live.handle.try_send(line) {
        edge.send_failed(context, super::SendFailure::from(refusal));
    }
}

/// A staged part committed: a complete set is ready to apply once the E2EE
/// router has produced the writes of its companion parts.
pub(super) fn part_committed(edge: &mut EdgeFederation, open: OpenBarrier) {
    edge.barrier.open = Some(open);
    let complete = edge
        .barrier
        .open
        .as_ref()
        .is_some_and(|open| open.assembly.is_complete());
    if complete {
        edge.barrier.ready = true;
    }
}

/// The mutation identity of a complete barrier awaiting its apply, when
/// the batch slot is free to take it.
pub(super) fn ready_mutation(edge: &EdgeFederation) -> Option<[u8; 16]> {
    if !edge.barrier.ready || edge.commit.is_some() || edge.phase != super::Phase::Active {
        return None;
    }
    edge.barrier
        .open
        .as_ref()
        .map(|open| open.assembly.identity().mutation_id)
}

fn verified_partition(
    edge: &EdgeFederation,
    open: &OpenBarrier,
) -> Result<crate::e2ee::barrier::Partition, Violation> {
    let base_cursor = StreamCursor {
        generation: edge.replica.projection_generation(),
        next_sequence: edge
            .cursor
            .map_or(0, |(sequence, _)| sequence.saturating_add(1)),
    };
    let companion_cursor = StreamCursor {
        generation: edge.barrier.companion_generation,
        next_sequence: edge
            .barrier
            .companion_cursor
            .map_or(0, |(sequence, _)| sequence.saturating_add(1)),
    };
    let partition = open
        .assembly
        .verify(base_cursor, companion_cursor)
        .map_err(|_| Violation::Consistency)?;
    if open.base_events.len() != usize::from(partition.base_parts) {
        return Err(Violation::Consistency);
    }
    Ok(partition)
}

/// Applies the complete barrier in one transaction: every base event to
/// the replica in index order, the E2EE router's rows for the companion
/// parts, the receipt, both cursors, retaining the immutable parts for replay.
pub(super) fn apply(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    companion_writes: Vec<AccountServiceDurableWrite>,
    companion_outputs: Vec<crate::e2ee::edge::ClientOutput>,
) -> Result<(), Violation> {
    if context.pending_len() != 0 || context.in_flight() || edge.commit.is_some() {
        return Err(Violation::Ceiling);
    }
    edge.barrier.rollback = Some(ProjectionBackup {
        replica: edge.replica.clone(),
        nicknames: edge.nicknames.clone(),
    });
    let outcome = apply_complete(edge, context, companion_writes, companion_outputs);
    if outcome.is_err() {
        rejected(edge);
    }
    outcome
}

fn apply_complete(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    companion_writes: Vec<AccountServiceDurableWrite>,
    companion_outputs: Vec<crate::e2ee::edge::ClientOutput>,
) -> Result<(), Violation> {
    let open = edge
        .barrier
        .open
        .as_ref()
        .cloned()
        .ok_or(Violation::Consistency)?;
    let partition = verified_partition(edge, &open)?;
    let mut fanout = super::render::EventFanout::default();
    let mut join_echoes = Vec::new();
    let (upserted, removed) =
        apply_base_events(edge, context, &open, &mut fanout, &mut join_echoes)?;
    for output in companion_outputs {
        fanout.append(context, output.generation, output.frames)?;
    }
    let receipt = applied_receipt(context, &open)?;
    let identity = *open.assembly.identity();
    // A stream position is (generation, sequence, event); the base cursor
    // keeps the sequence and the event.
    let (_, base_sequence, base_event) = partition.base_last;
    let cursor = Some((base_sequence, EventId::from_bytes(base_event)));
    let receipt_write = barrier_row(
        edge,
        receipt.applied_local_state_generation,
        identity.head_key(),
        BarrierHead::Receipt(receipt.clone()).encode(),
    )?;
    let revision = receipt.applied_local_state_generation;
    let mut writes = apply_rows(edge, context, revision, &upserted, &removed)?;
    let mut coverage = Vec::new();
    for (header, projected) in open.base_events.values() {
        if matches!(projected, ProjectedEvent::RequestCompleted { .. }) {
            let (version, write) =
                super::journal::completion_write(edge, header, projected, revision)?;
            coverage.push(version);
            writes.push(write);
        }
    }
    let pending = PendingCommit::BarrierApplied {
        receipt: Box::new(receipt.clone()),
        base_last: (base_sequence, EventId::from_bytes(base_event)),
        companion_last: partition.companion_last,
        coverage,
        join_echoes,
    };
    writes.push(receipt_write);
    for write in companion_writes {
        writes.push(write.at_revision(revision).map_err(|_| Violation::Codec)?);
    }
    super::events::stage_rows(
        edge,
        context,
        cursor,
        pending,
        fanout.finish()?,
        |_, _, _| Ok(writes),
    )
}

fn applied_receipt(
    context: &StateCoreContext,
    open: &OpenBarrier,
) -> Result<BarrierReceipt, Violation> {
    let now = context
        .utc_now()
        .map(|second| second.get())
        .map_err(|_| Violation::Ceiling)?;
    Ok(open.assembly.receipt(
        context
            .head()
            .storage_commit_sequence
            .checked_add(1)
            .ok_or(Violation::Ceiling)?,
        context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| Violation::Ceiling)?
            .resulting_revision()
            .get(),
        now,
        now.checked_add(BARRIER_RETENTION_SECONDS)
            .ok_or(Violation::Ceiling)?,
    ))
}

/// The rows of the apply transaction: standing entries, the receipt in
/// place of the stage head. Immutable parts remain until bounded retention.
// agenc-review: allow owner=runtime reviewed=2026-09-03 reason=the apply rows need the edge the context the revision the identity the receipt and both entry lists together
#[allow(clippy::too_many_arguments)]
fn apply_rows(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    revision: u64,
    upserted: &[ProjectionKey],
    removed: &[ProjectionKey],
) -> Result<Vec<AccountServiceDurableWrite>, Violation> {
    let mut writes = Vec::new();
    for key in upserted {
        writes.push(super::events::entry_row(edge, key, revision)?);
    }
    for key in removed {
        if let Some(write) = super::events::removal_write(edge, context, key)? {
            writes.push(write);
        }
    }
    Ok(writes)
}

/// Applies every base part to the replica in index order and renders it;
/// returns the standing entries the transaction must write and erase.
fn apply_base_events(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    open: &OpenBarrier,
    fanout: &mut super::render::EventFanout,
    join_echoes: &mut Vec<super::join_echo::JoinEcho>,
) -> Result<(Vec<ProjectionKey>, Vec<ProjectionKey>), Violation> {
    let mut upserted = Vec::new();
    let mut removed = Vec::new();
    for (header, projected) in open.base_events.values() {
        if let ProjectedEvent::RequestCompleted {
            resulting_state_generation,
        } = projected
        {
            super::events::completion_of(edge, header, *resulting_state_generation)?;
        }
        let label = super::render::event_channel_label(edge, projected);
        let outcome = edge
            .replica
            .apply(projected, header.coordinator_state_generation)
            .map_err(|_| Violation::Consistency)?;
        super::render::remember_nicknames(edge, projected);
        if let Some(echo) = super::render::render_event(
            edge,
            context,
            header,
            projected,
            &outcome,
            label.as_deref(),
            fanout,
        )? {
            if join_echoes.len() >= super::join_echo::MAX_JOIN_ECHOES {
                return Err(Violation::Ceiling);
            }
            join_echoes.try_reserve(1).map_err(|_| Violation::Ceiling)?;
            join_echoes.push(echo);
        }
        upserted.extend(outcome.upserted);
        removed.extend(outcome.removed);
    }
    Ok((upserted, removed))
}

/// The apply transaction committed: both cursors advance, the receipt is
/// retained, and both final acknowledgements go out.
pub(super) fn applied(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    receipt: BarrierReceipt,
    base_last: (u64, EventId),
    companion_last: (u64, u64, [u8; 16]),
) -> Vec<super::EdgeCompletion> {
    let open = edge.barrier.open.take();
    edge.barrier.ready = false;
    edge.barrier.rollback = None;
    edge.cursor = Some(base_last);
    edge.barrier.companion_cursor = Some((companion_last.1, companion_last.2));
    edge.counters.barriers_applied = edge.counters.barriers_applied.saturating_add(1);
    edge.barrier
        .applied
        .insert(receipt.identity.mutation_id, receipt.clone());
    acknowledge(edge, context, &receipt);
    let mut completions = Vec::new();
    if let Some(open) = open {
        for (header, projected) in open.base_events.values() {
            edge.counters.events_applied = edge.counters.events_applied.saturating_add(1);
            if matches!(projected, ProjectedEvent::RequestCompleted { .. })
                && let Some(correlation) = header.correlation
            {
                completions.extend(super::events::committed_completion(
                    edge,
                    context,
                    header.event_id,
                    correlation.request_id,
                    header.coordinator_state_generation,
                ));
            }
        }
    }
    completions
}

/// Restores the committed projection when durable apply admission is cancelled.
pub(super) fn rejected(edge: &mut EdgeFederation) {
    if let Some(previous) = edge.barrier.rollback.take() {
        edge.replica = previous.replica;
        edge.nicknames = previous.nicknames;
    }
}
