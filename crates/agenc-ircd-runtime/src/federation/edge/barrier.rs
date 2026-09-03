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
pub(super) struct OpenBarrier {
    assembly: BarrierAssembly,
    base_events: BTreeMap<u16, (EventHeader, ProjectedEvent)>,
}

/// The barrier state the edge keeps beside its replica.
#[derive(Default)]
pub(super) struct BarrierState {
    /// The barrier being assembled.
    pub(super) open: Option<OpenBarrier>,
    /// Receipts of applied barriers by mutation identity.
    pub(super) applied: BTreeMap<[u8; 16], BarrierReceipt>,
    /// Parts of an applied barrier seen again since its receipt.
    replayed: BTreeMap<[u8; 16], BTreeSet<u16>>,
    /// The companion delivery generation in use.
    pub(super) companion_generation: u64,
    /// The last companion position acknowledged.
    pub(super) companion_cursor: Option<(u64, [u8; 16])>,
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
    stage_part(edge, context, part, Some((header, projected)))
}

/// A companion EEVENT part handed over by the E2EE router.
pub(super) fn companion_part(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    part: BarrierPart,
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
    stage_part(edge, context, part, None)
}

/// Stages one part: a replay of an applied barrier is answered from its
/// receipt, a new part opens or continues the assembly and is written as
/// an immutable row before anything else happens.
fn stage_part(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    part: BarrierPart,
    base_event: Option<(EventHeader, ProjectedEvent)>,
) -> Result<(), Violation> {
    let mutation_id = part.identity.mutation_id;
    if edge.barrier.applied.contains_key(&mutation_id) {
        return replayed_part(edge, context, &part);
    }
    let open = match edge.barrier.open.as_mut() {
        Some(open) if open.assembly.identity().mutation_id == mutation_id => open,
        Some(_) => return Err(Violation::Consistency),
        None => edge.barrier.open.insert(OpenBarrier {
            assembly: BarrierAssembly::open(part.identity).map_err(|_| Violation::Consistency)?,
            base_events: BTreeMap::new(),
        }),
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
    let identity = part.identity;
    super::events::stage_rows(
        edge,
        context,
        None,
        PendingCommit::BarrierPart,
        |edge, _, revision| {
            let mut writes = Vec::new();
            if let Some(write) = barrier_row(edge, revision, identity.head_key(), head.encode()) {
                writes.push(write);
            }
            if let Some(write) = barrier_row(
                edge,
                revision,
                identity.part_key(part.part_index),
                part.encode(),
            ) {
                writes.push(write);
            }
            writes
        },
    )
}

fn barrier_row(
    edge: &EdgeFederation,
    revision: u64,
    key: Result<agenc_ircd_storage::StoredKey, agenc_ircd_storage::StorageError>,
    body: Result<Vec<u8>, agenc_ircd_storage::StorageError>,
) -> Option<AccountServiceDurableWrite> {
    edge.row_write(
        TableId::E2eeState,
        BARRIER_ROW_KIND,
        key.ok()?,
        revision,
        0,
        body.ok()?,
    )
    .ok()
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
fn last_entries(receipt: &BarrierReceipt) -> Option<LastEntries> {
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

/// A staged part committed: a complete set applies now.
pub(super) fn part_committed(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    let complete = edge
        .barrier
        .open
        .as_ref()
        .is_some_and(|open| open.assembly.is_complete());
    if !complete {
        return;
    }
    if let Err(violation) = apply(edge, context) {
        edge.fail_link(context, violation);
    }
}

/// Applies the complete barrier in one transaction: every base event to
/// the replica in index order, every companion part through the E2EE
/// router, the receipt, both cursors, and the removal of the staged rows.
fn apply(edge: &mut EdgeFederation, context: &mut StateCoreContext) -> Result<(), Violation> {
    let open = edge.barrier.open.take().ok_or(Violation::Consistency)?;
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
    let (upserted, removed) = apply_base_events(edge, context, &open)?;
    let now = context
        .utc_now()
        .map(|second| second.get())
        .map_err(|_| Violation::Ceiling)?;
    let receipt = open.assembly.receipt(
        0,
        edge.replica.projection_generation(),
        now,
        now.saturating_add(BARRIER_RETENTION_SECONDS),
    );
    let identity = *open.assembly.identity();
    let (base_sequence, _, base_event) = partition.base_last;
    let cursor = Some((base_sequence, EventId::from_bytes(base_event)));
    let pending = PendingCommit::BarrierApplied {
        receipt: Box::new(receipt.clone()),
        base_last: (base_sequence, EventId::from_bytes(base_event)),
        companion_last: partition.companion_last,
    };
    super::events::stage_rows(edge, context, cursor, pending, |edge, context, revision| {
        apply_rows(
            edge, context, revision, &identity, &receipt, &upserted, &removed,
        )
    })
}

/// The rows of the apply transaction: standing entries, the receipt in
/// place of the stage head, and the removal of every part row.
// agenc-review: allow owner=runtime reviewed=2026-09-03 reason=the apply rows need the edge the context the revision the identity the receipt and both entry lists together
#[allow(clippy::too_many_arguments)]
fn apply_rows(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    revision: u64,
    identity: &BarrierIdentity,
    receipt: &BarrierReceipt,
    upserted: &[ProjectionKey],
    removed: &[ProjectionKey],
) -> Vec<AccountServiceDurableWrite> {
    let mut writes = Vec::new();
    for key in upserted {
        if let Some(write) = super::events::entry_row(edge, key, revision) {
            writes.push(write);
        }
    }
    for key in removed {
        if let Some(write) = super::events::removal_write(edge, context, key) {
            writes.push(write);
        }
    }
    if let Some(write) = barrier_row(
        edge,
        revision,
        identity.head_key(),
        BarrierHead::Receipt(receipt.clone()).encode(),
    ) {
        writes.push(write);
    }
    for index in 0..identity.part_count {
        if let Some(write) = identity
            .part_key(index)
            .ok()
            .and_then(|key| AccountServiceDurableWrite::delete(TableId::E2eeState, key).ok())
        {
            writes.push(write);
        }
    }
    writes
}

/// Applies every base part to the replica in index order and renders it;
/// returns the standing entries the transaction must write and erase.
fn apply_base_events(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    open: &OpenBarrier,
) -> Result<(Vec<ProjectionKey>, Vec<ProjectionKey>), Violation> {
    let mut upserted = Vec::new();
    let mut removed = Vec::new();
    for (header, projected) in open.base_events.values() {
        let label = super::render::event_channel_label(edge, projected);
        let outcome = edge
            .replica
            .apply(projected, header.coordinator_state_generation)
            .map_err(|_| Violation::Consistency)?;
        edge.counters.events_applied = edge.counters.events_applied.saturating_add(1);
        super::render::remember_nicknames(edge, projected);
        super::render::render_event(edge, context, projected, &outcome, label.as_deref());
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
) {
    edge.cursor = Some(base_last);
    edge.barrier.companion_cursor = Some((companion_last.1, companion_last.2));
    edge.counters.barriers_applied = edge.counters.barriers_applied.saturating_add(1);
    edge.barrier
        .applied
        .insert(receipt.identity.mutation_id, receipt.clone());
    acknowledge(edge, context, &receipt);
}
