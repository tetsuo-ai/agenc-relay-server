//! FRESUME and the base snapshot protocol on the coordinator (spec 20.9).
//!
//! A resume that names the retained cursor replays the durable outbox from
//! storage and then hands the link to live delivery. Anything else opens a
//! new projection generation: the cut is derived from the live state at one
//! safe point, every later event is reserved under the new generation from
//! sequence zero, the cut rows are written behind bounded batches, and the
//! edge receives BEGIN, the entries, END, and after READY the ACTIVE line.

use std::collections::BTreeSet;

use agenc_ircd_domain::federation::{CoordinatorProjection, ProjectionKey, ProjectionRecord};
use agenc_ircd_federation_wire::{
    CanonicalEncode, DeliveryCursor, EventDescriptor, FederationFrame, FederationHash32,
    ProjectionEntryHeader, SnapshotIdentity, federation_object_id, snapshot_digest,
};
use agenc_ircd_storage::federation_records::{
    OutboxEventRecord, PROJECTION_ENTRY_KIND, PROJECTION_MARKER_KIND, ProjectionEntryRecord,
    ProjectionGenerationState, ProjectionMarkerRecord, outbox_range, parse_outbox_key,
    projection_entry_key, projection_marker_key,
};
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, TableId};
use agenc_ircd_types::{EventId, MonotonicTick, ServerId};

use super::{FederationCoordinator, PendingCommit, Violation, send_object};
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::federation::LinkId;
use crate::federation::codec::projection::{projection_arm_object, projection_kind};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::projector::EdgeDelivery;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};

/// Outbox rows replayed per storage read.
const RESEND_PAGE_ROWS: u16 = 64;
/// Cut rows written per checkpoint batch.
const WRITE_BATCH_ROWS: usize = 256;
/// Entry lines handed to the link writer per pacing step.
const SEND_STEP_ENTRIES: usize = 64;
/// The pacing interval between entry steps.
const SEND_STEP_MILLIS: u64 = 20;
/// The fixed snapshot token lifetime (spec 20.9).
const SNAPSHOT_TOKEN_MILLIS: u64 = 15 * 60 * 1_000;
/// The fixed standing-projection ceilings (spec 20.8).
const MAX_SNAPSHOT_ENTRIES: usize = 1_000_000;
const MAX_SNAPSHOT_BYTES: u64 = 536_870_912;

/// One snapshot in progress or awaiting READY.
pub(super) struct Snapshot {
    pub(super) identity: SnapshotIdentity,
    pub(super) entries: Vec<Vec<u8>>,
    pub(super) records: Vec<ProjectionRecord>,
    pub(super) next_send: usize,
    pub(super) next_write: usize,
    pub(super) end_sent: bool,
    pub(super) ready: bool,
    pub(super) link: LinkId,
}

/// Replay of the durable outbox after FRESUME OK or ACTIVE.
pub(super) struct Resend {
    next: u64,
    read: Option<StorageReadId>,
}

/// Handles FRESUME.
pub(super) fn resume(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    generation: u64,
    cursor: DeliveryCursor,
) -> Result<(), Violation> {
    if coordinator.pending.is_some() {
        return Err(Violation::Ceiling);
    }
    let state = coordinator
        .peers
        .get_mut(&peer)
        .ok_or(Violation::Misaddressed)?;
    if state.active || state.resend.is_some() {
        return Err(Violation::Phase);
    }
    let retained = generation == state.projection_generation
        && state.snapshot.is_none()
        && !state.outbox.snapshot_required
        && cursor_retained(state, cursor);
    if !retained {
        return begin_snapshot(coordinator, context, link, peer);
    }
    let next = match cursor {
        DeliveryCursor::Empty => 0,
        DeliveryCursor::At {
            delivery_sequence, ..
        } => delivery_sequence.checked_add(1).ok_or(Violation::Ceiling)?,
    };
    // The retained window also owns the append budget while replay runs.
    let frame = FederationFrame::ResumeOk {
        edge_server_id: peer,
        projection_generation: generation,
        next_delivery_sequence: next,
    };
    if coordinator.send_frame(context, link, peer, &frame) {
        start_resend(coordinator, context, peer, next);
    }
    Ok(())
}

/// Whether the edge's cursor is exactly the coordinator's durable cursor.
fn cursor_retained(state: &super::PeerState, cursor: DeliveryCursor) -> bool {
    match (cursor, state.outbox.cursor) {
        (DeliveryCursor::Empty, None) => true,
        (
            DeliveryCursor::At {
                delivery_sequence,
                event_id,
            },
            Some((retained_sequence, retained_id)),
        ) => delivery_sequence == retained_sequence && event_id == retained_id,
        _ => false,
    }
}

/// Starts replaying the durable outbox from `from`.
pub(super) fn start_resend(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    from: u64,
) {
    if let Some(state) = coordinator.peers.get_mut(&peer) {
        state.resend = Some(Resend {
            next: from,
            read: None,
        });
    }
    continue_resend(coordinator, context, peer);
}

/// Issues the next replay page, or activates the link once the replay has
/// caught up with every reserved sequence.
pub(super) fn continue_resend(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let reserved = context
        .federation()
        .and_then(|projector| projector.edge(peer))
        .map_or(0, |delivery| delivery.next_delivery_sequence);
    // A replay stops at the last part of an open cross-profile barrier;
    // the release replays the rest (spec 20.8).
    let reserved = coordinator.barriers.get(&peer).map_or(reserved, |barrier| {
        reserved.min(barrier.base_last.saturating_add(1))
    });
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    let Some(resend) = state.resend.as_mut() else {
        return;
    };
    if resend.read.is_some() {
        return;
    }
    if resend.next >= reserved {
        state.resend = None;
        state.active = true;
        return;
    }
    let last = resend
        .next
        .saturating_add(u64::from(RESEND_PAGE_ROWS))
        .saturating_sub(1);
    let plan = outbox_range(peer, state.projection_generation, resend.next, last)
        .ok()
        .and_then(|(start, end)| {
            ReadPlan::range(TableId::EdgeOutbox, start, end, RESEND_PAGE_ROWS).ok()
        });
    match plan.and_then(|plan| context.submit_storage_read(plan).ok()) {
        Some(read_id) => resend.read = Some(read_id),
        None => fail_resend(coordinator, context, peer, Violation::Ceiling),
    }
}

/// Reports whether a read belongs to a replay.
pub(super) fn owns_read(coordinator: &FederationCoordinator, read_id: StorageReadId) -> bool {
    coordinator.peers.values().any(|state| {
        state
            .resend
            .as_ref()
            .is_some_and(|resend| resend.read == Some(read_id))
    })
}

/// Consumes one replay page: every row is rendered in sequence order.
pub(super) fn resend_completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    let Some(peer) = coordinator.peers.iter().find_map(|(peer, state)| {
        state
            .resend
            .as_ref()
            .filter(|resend| resend.read == Some(message.read_id))
            .map(|_| *peer)
    }) else {
        return;
    };
    let Ok(result) = message.result else {
        fail_resend(coordinator, context, peer, Violation::Ceiling);
        return;
    };
    let Some(state) = coordinator.peers.get(&peer) else {
        return;
    };
    let Some(resend) = state.resend.as_ref() else {
        return;
    };
    let mut expected = resend.next;
    let generation = state.projection_generation;
    let mut rows = Vec::new();
    for record in result.records {
        let decoded = context
            .open_storage_plaintext(TableId::EdgeOutbox, &record.key, &record.sealed_record)
            .and_then(|opened| {
                PersistentRecordValue::decode(
                    TableId::EdgeOutbox,
                    opened.expose_for_storage_codec(),
                )
                .map_err(crate::RuntimeError::from)
            })
            .map_err(|_| Violation::Codec)
            .and_then(|value| decode_outbox_record(&record.key, &value));
        let Ok((parts, event)) = decoded else {
            fail_resend(coordinator, context, peer, Violation::Codec);
            return;
        };
        if parts.target != peer
            || parts.projection_generation != generation
            || parts.delivery_sequence != expected
        {
            fail_resend(coordinator, context, peer, Violation::Acknowledgement);
            return;
        }
        let Some(next) = expected.checked_add(1) else {
            fail_resend(coordinator, context, peer, Violation::Ceiling);
            return;
        };
        expected = next;
        rows.push((parts.delivery_sequence, event));
    }
    if rows.is_empty() {
        // A read is issued only below the committed delivery head. The edge
        // has not acknowledged this position, so its absence is not coverage.
        fail_resend(coordinator, context, peer, Violation::Acknowledgement);
        return;
    }
    for (sequence, event) in rows {
        if !replay_row(coordinator, context, peer, sequence, &event) {
            return;
        }
    }
    advance_resend(coordinator, context, peer, expected);
}

fn advance_resend(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    expected: u64,
) {
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    let Some(resend) = state.resend.as_mut() else {
        return;
    };
    resend.read = None;
    resend.next = expected;
    continue_resend(coordinator, context, peer);
}

/// Checks the immutable event against its durable key and envelope.
pub(super) fn decode_outbox_record(
    key: &agenc_ircd_storage::StoredKey,
    value: &PersistentRecordValue,
) -> Result<
    (
        agenc_ircd_storage::federation_records::OutboxKeyParts,
        OutboxEventRecord,
    ),
    Violation,
> {
    let parts = parse_outbox_key(key).map_err(|_| Violation::Codec)?;
    let event = OutboxEventRecord::decode(value.body()).map_err(|_| Violation::Codec)?;
    let mut budget = agenc_ircd_federation_wire::DecodeBudget::new(1 << 20, 4_096);
    let object = agenc_ircd_federation_wire::SchemaObject::decode_exact(
        "FederationEvent",
        &event.event_object,
        &mut budget,
    )
    .map_err(|_| Violation::Codec)?;
    let header = agenc_ircd_federation_wire::EventHeader::from_object(&object)
        .map_err(|_| Violation::Codec)?;
    if header.target_server_id != parts.target
        || header.projection_generation != parts.projection_generation
        || header.delivery_sequence != parts.delivery_sequence
        || header.event_id.as_bytes() != &event.event_id
        || header.coordinator_state_generation != event.coordinator_state_generation
        || federation_object_id(&event.event_object).as_bytes() != &event.event_object_id
        || header
            .correlation
            .map(|correlation| correlation.replay_key.to_bytes())
            != event.completion_replay_key
    {
        return Err(Violation::Codec);
    }
    Ok((parts, event))
}

fn fail_resend(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    violation: Violation,
) {
    let link = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.live.as_ref())
        .map(|live| live.link);
    if let Some(link) = link {
        coordinator.fail_link(context, link, peer, violation);
    }
}

fn replay_row(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    sequence: u64,
    event: &OutboxEventRecord,
) -> bool {
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return false;
    };
    let Some(live) = state.live.as_ref() else {
        state.resend = None;
        return false;
    };
    let bytes = u64::try_from(event.event_object.len()).unwrap_or(u64::MAX);
    let event_id = EventId::from_bytes(event.event_id);
    if let Some((_, known_id, known_bytes)) = state
        .outbox
        .unacked
        .iter()
        .find(|(known, _, _)| *known == sequence)
    {
        if *known_id != event_id || *known_bytes != bytes {
            fail_resend(coordinator, context, peer, Violation::Codec);
            return false;
        }
    } else {
        state.outbox.unacked.push_back((sequence, event_id, bytes));
        state.outbox.unacked_bytes = state.outbox.unacked_bytes.saturating_add(bytes);
    }
    let frame = |fragment| FederationFrame::Event {
        descriptor: EventDescriptor {
            target_server_id: peer,
            delivery_sequence: sequence,
            event_id,
            object_id: FederationHash32::from_bytes(event.event_object_id),
        },
        fragment,
    };
    let link = live.link;
    match send_object(
        &live.handle,
        &coordinator.config.server_name,
        &event.event_object,
        frame,
    ) {
        Ok(()) => {
            coordinator.counters.events_sent = coordinator.counters.events_sent.saturating_add(1);
            true
        }
        Err(failure) => {
            coordinator.send_failed(context, link, peer, failure);
            false
        }
    }
}

/// The derived cut of one edge before it becomes a generation.
struct Cut {
    records: Vec<ProjectionRecord>,
    entries: Vec<Vec<u8>>,
    digest: FederationHash32,
    state_generation: u64,
}

/// Derives and bounds the cut for a new generation at the current state.
fn build_cut(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    peer: ServerId,
    generation: u64,
) -> Result<Cut, Violation> {
    let records = CoordinatorProjection::standing_of(context.domain(), peer);
    let state_generation = context.domain().revision().get();
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(records.len())
        .map_err(|_| Violation::Ceiling)?;
    let mut ids = Vec::new();
    ids.try_reserve_exact(records.len())
        .map_err(|_| Violation::Ceiling)?;
    let mut total_bytes = 0_u64;
    for record in &records {
        let encoded = encode_entry(coordinator.config.network_id, peer, generation, record)?;
        total_bytes = total_bytes.saturating_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX));
        ids.push(federation_object_id(&encoded));
        entries.push(encoded);
    }
    if entries.len() > MAX_SNAPSHOT_ENTRIES || total_bytes > MAX_SNAPSHOT_BYTES {
        return Err(Violation::Ceiling);
    }
    let digest = snapshot_digest(
        &coordinator.config.recovery_epoch,
        generation,
        state_generation,
        &ids,
    )
    .map_err(|_| Violation::Codec)?;
    Ok(Cut {
        records,
        entries,
        digest,
        state_generation,
    })
}

/// Opens a new projection generation for the edge and starts sending it.
fn begin_snapshot(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
) -> Result<(), Violation> {
    let generation = coordinator
        .peers
        .get(&peer)
        .ok_or(Violation::Misaddressed)?
        .projection_generation
        .checked_add(1)
        .ok_or(Violation::Ceiling)?;
    let cut = build_cut(coordinator, context, peer, generation)?;
    let mut token = [0_u8; 32];
    context
        .entropy_mut()
        .fill_exact(&mut token)
        .map_err(|_| Violation::Ceiling)?;
    let identity = SnapshotIdentity {
        snapshot_token: FederationHash32::from_bytes(token),
        recovery_epoch: coordinator.config.recovery_epoch,
        projection_generation: generation,
        state_generation: cut.state_generation,
        snapshot_digest: cut.digest,
    };
    open_generation(coordinator, context, peer, link, identity, cut);
    let deadline = context
        .now()
        .checked_add(SNAPSHOT_TOKEN_MILLIS)
        .map_err(|_| Violation::Ceiling)?;
    context
        .timers_mut()
        .schedule(
            deadline,
            TimerKind::FederationSnapshotExpiry,
            TimedId::Peer(peer),
        )
        .map_err(|_| Violation::Ceiling)?;
    if !announce(coordinator, context, link, peer, identity) {
        // The link ended under the announcement; its loss already dropped
        // the opened generation.
        return Ok(());
    }
    stage_marker(
        coordinator,
        context,
        peer,
        ProjectionGenerationState::Pending,
    )?;
    continue_send(coordinator, context, peer);
    Ok(())
}

/// Sends FRESUME SNAPSHOT and FSNAPSHOT BEGIN for the opened generation;
/// returns whether the link is still live afterwards.
fn announce(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    identity: SnapshotIdentity,
) -> bool {
    let entry_count = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.snapshot.as_ref())
        .map_or(0, |snapshot| {
            u64::try_from(snapshot.entries.len()).unwrap_or(u64::MAX)
        });
    coordinator.send_frame(
        context,
        link,
        peer,
        &FederationFrame::ResumeSnapshot {
            edge_server_id: peer,
        },
    ) && coordinator.send_frame(
        context,
        link,
        peer,
        &FederationFrame::SnapshotBegin {
            edge_server_id: peer,
            identity,
            entry_count,
        },
    )
}

/// From this safe point every event and standing delta for the edge is
/// reserved under the new generation from sequence zero.
fn open_generation(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    link: LinkId,
    identity: SnapshotIdentity,
    cut: Cut,
) {
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    state.projection_generation = identity.projection_generation;
    state.outbox.unacked.clear();
    state.outbox.unacked_bytes = 0;
    state.outbox.cursor = None;
    state.outbox.snapshot_required = false;
    state.outbox.dirty = false;
    state.outbox.reserved_next = 0;
    state.ready_identity = None;
    if let Some(projector) = context.federation_mut() {
        projector.set_edge(
            peer,
            EdgeDelivery {
                projection_generation: identity.projection_generation,
                next_delivery_sequence: 0,
            },
        );
        projector.install_edge(peer, &cut.records);
    }
    state.snapshot = Some(Snapshot {
        identity,
        entries: cut.entries,
        records: cut.records,
        next_send: 0,
        next_write: 0,
        end_sent: false,
        ready: false,
        link,
    });
    coordinator.sync_outbox_budget(context, peer);
}

fn encode_entry(
    network_id: agenc_ircd_types::NetworkId,
    peer: ServerId,
    generation: u64,
    record: &ProjectionRecord,
) -> Result<Vec<u8>, Violation> {
    let filled;
    let record = match record {
        ProjectionRecord::ChannelDetail(detail) => {
            let mut detail = detail.clone();
            crate::federation::codec::fill_route_binding(&network_id, &mut detail);
            filled = ProjectionRecord::ChannelDetail(detail);
            &filled
        }
        other => other,
    };
    let arm = projection_arm_object(record).map_err(|_| Violation::Codec)?;
    let entry = ProjectionEntryHeader {
        network_id,
        target_server_id: peer,
        projection_generation: generation,
        projection_kind: projection_kind(record),
    }
    .build(&arm)
    .map_err(|_| Violation::Codec)?;
    entry
        .encode_canonical()
        .map(|bytes| bytes.as_slice().to_vec())
        .map_err(|_| Violation::Codec)
}

/// Hands the next entry lines to the link writer while its queue has room,
/// then END once every entry left.
pub(super) fn continue_send(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    let (Some(snapshot), Some(live)) = (state.snapshot.as_mut(), state.live.as_ref()) else {
        return;
    };
    if snapshot.end_sent || live.link != snapshot.link {
        return;
    }
    let watermark = coordinator.config.outbox_bytes_per_edge / 2;
    let mut sent = 0;
    while snapshot.next_send < snapshot.entries.len() && sent < SEND_STEP_ENTRIES {
        if live.handle.queued_bytes() > watermark {
            break;
        }
        let Some(encoded) = snapshot.entries.get(snapshot.next_send) else {
            break;
        };
        let Ok(entry_index) = u32::try_from(snapshot.next_send) else {
            break;
        };
        let token = snapshot.identity.snapshot_token;
        let frame = |fragment| FederationFrame::SnapshotEntry {
            edge_server_id: peer,
            snapshot_token: token,
            entry_index,
            object_id: federation_object_id(encoded),
            fragment,
        };
        if let Err(failure) = send_object(
            &live.handle,
            &coordinator.config.server_name,
            encoded,
            frame,
        ) {
            let link = live.link;
            coordinator.send_failed(context, link, peer, failure);
            return;
        }
        snapshot.next_send = snapshot.next_send.saturating_add(1);
        sent = sent.saturating_add(1);
    }
    if snapshot.next_send < snapshot.entries.len() {
        let deadline = context.now().checked_add(SEND_STEP_MILLIS);
        if let Ok(deadline) = deadline {
            let _scheduled = context.timers_mut().schedule(
                deadline,
                TimerKind::FederationSnapshotSend,
                TimedId::Peer(peer),
            );
        }
        return;
    }
    snapshot.end_sent = true;
    let token = snapshot.identity.snapshot_token;
    let link = live.link;
    coordinator.send_frame(
        context,
        link,
        peer,
        &FederationFrame::SnapshotEnd {
            edge_server_id: peer,
            snapshot_token: token,
            cursor: DeliveryCursor::Empty,
        },
    );
}

/// Writes the next batch of cut rows that no later mutation replaced.
pub(super) fn continue_write(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    while coordinator.pending.is_none() {
        match write_batch(coordinator, context, peer) {
            WriteStep::Staged | WriteStep::Done => return,
            WriteStep::Skipped => {}
        }
    }
}

pub(super) enum WriteStep {
    Staged,
    Skipped,
    Done,
}

/// Stages the next page of cut rows. A page whose staging is refused stays
/// queued at the same position: `continue_background` writes it once the
/// batch slot is free, so no row of the generation is skipped.
pub(super) fn write_batch(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) -> WriteStep {
    let Some((generation, records, start)) = coordinator.peers.get(&peer).and_then(|state| {
        state.snapshot.as_ref().map(|snapshot| {
            (
                state.projection_generation,
                &snapshot.records,
                snapshot.next_write,
            )
        })
    }) else {
        return WriteStep::Done;
    };
    if start >= records.len() {
        return WriteStep::Done;
    }
    let end = start.saturating_add(WRITE_BATCH_ROWS).min(records.len());
    let standing: BTreeSet<ProjectionKey> = context
        .federation()
        .and_then(|projector| projector.index().edge(peer))
        .map(|standing| standing.keys().collect())
        .unwrap_or_default();
    let Ok(plan) = context.domain().plan_account_service_checkpoint() else {
        return WriteStep::Done;
    };
    let revision = plan.resulting_revision().get();
    let mut writes = Vec::new();
    for record in records.get(start..end).unwrap_or(&[]) {
        if let Some(write) = cut_row(
            coordinator,
            context,
            &standing,
            peer,
            generation,
            record,
            revision,
        ) {
            writes.push(write);
        }
    }
    if writes.is_empty() {
        advance_write(coordinator, peer, end);
        return WriteStep::Skipped;
    }
    let Ok(fanout) = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new()) else {
        return WriteStep::Done;
    };
    if context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .is_err()
    {
        return WriteStep::Done;
    }
    advance_write(coordinator, peer, end);
    coordinator.pending = Some(PendingCommit::SnapshotRows { peer });
    WriteStep::Staged
}

fn advance_write(coordinator: &mut FederationCoordinator, peer: ServerId, end: usize) {
    if let Some(snapshot) = coordinator
        .peers
        .get_mut(&peer)
        .and_then(|state| state.snapshot.as_mut())
    {
        snapshot.next_write = end;
    }
}

/// The row for one cut record, or `None` when a later mutation already
/// wrote or removed the key under this generation.
fn cut_row(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    standing: &BTreeSet<ProjectionKey>,
    peer: ServerId,
    generation: u64,
    record: &ProjectionRecord,
    revision: u64,
) -> Option<AccountServiceDurableWrite> {
    let key = record.key();
    let stored = projection_entry_key(peer, generation, key.kind(), key.primary()).ok()?;
    let replaced = !standing.contains(&key)
        || context
            .index()
            .existing(TableId::EdgeProjection, &stored)
            .is_ok_and(|existing| existing.is_some());
    if replaced {
        return None;
    }
    entry_row(
        coordinator.config.network_id,
        peer,
        generation,
        record,
        revision,
        stored,
    )
    .ok()
}

fn entry_row(
    network_id: agenc_ircd_types::NetworkId,
    peer: ServerId,
    generation: u64,
    record: &ProjectionRecord,
    revision: u64,
    stored: agenc_ircd_storage::StoredKey,
) -> Result<AccountServiceDurableWrite, Violation> {
    let encoded = encode_entry(network_id, peer, generation, record)?;
    let body = ProjectionEntryRecord {
        entry_object_id: *federation_object_id(&encoded).as_bytes(),
        entry_object: encoded,
    }
    .encode()
    .map_err(|_| Violation::Codec)?;
    let plaintext = PersistentRecordValue::new(
        TableId::EdgeProjection,
        PROJECTION_ENTRY_KIND,
        revision,
        generation,
        None,
        Vec::new(),
        body,
    )
    .and_then(|value| value.encode())
    .map_err(|_| Violation::Codec)?;
    AccountServiceDurableWrite::put(TableId::EdgeProjection, stored, plaintext)
        .map_err(|_| Violation::Codec)
}

/// Encodes the marker row that heads the peer's current generation.
fn marker_row(
    state: &super::PeerState,
    identity: SnapshotIdentity,
    marker_state: ProjectionGenerationState,
    revision: u64,
) -> Result<AccountServiceDurableWrite, Violation> {
    let (entry_count, entry_bytes) = state.snapshot.as_ref().map_or((0, 0), |snapshot| {
        (
            u64::try_from(snapshot.entries.len()).unwrap_or(u64::MAX),
            snapshot.entries.iter().fold(0_u64, |total, entry| {
                total.saturating_add(u64::try_from(entry.len()).unwrap_or(u64::MAX))
            }),
        )
    });
    let body = ProjectionMarkerRecord {
        state: marker_state,
        state_generation: identity.state_generation,
        entry_count,
        entry_bytes,
        digest: *identity.snapshot_digest.as_bytes(),
        snapshot_token: Some(*identity.snapshot_token.as_bytes()),
        cut_cursor: None,
        recovery_epoch: *identity.recovery_epoch.as_bytes(),
    }
    .encode()
    .map_err(|_| Violation::Codec)?;
    let plaintext = PersistentRecordValue::new(
        TableId::EdgeProjection,
        PROJECTION_MARKER_KIND,
        revision,
        state.projection_generation,
        None,
        Vec::new(),
        body,
    )
    .and_then(|value| value.encode())
    .map_err(|_| Violation::Codec)?;
    let key = projection_marker_key(state.identity.server_id(), state.projection_generation)
        .map_err(|_| Violation::Codec)?;
    AccountServiceDurableWrite::put(TableId::EdgeProjection, key, plaintext)
        .map_err(|_| Violation::Codec)
}

/// Persists the generation marker with the peer row in one batch.
fn stage_marker(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    marker_state: ProjectionGenerationState,
) -> Result<(), Violation> {
    let state = coordinator
        .peers
        .get(&peer)
        .ok_or(Violation::Misaddressed)?;
    let identity = state
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.identity)
        .or(state.ready_identity)
        .ok_or(Violation::Phase)?;
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let writes = vec![
        marker_row(state, identity, marker_state, revision)?,
        coordinator
            .peer_row(peer, revision)
            .map_err(|_| Violation::Codec)?,
    ];
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|_| Violation::Ceiling)?;
    coordinator.pending = Some(match marker_state {
        ProjectionGenerationState::Pending => PendingCommit::SnapshotRows { peer },
        _ => PendingCommit::SnapshotReady { peer },
    });
    Ok(())
}

/// Handles FSNAPSHOT READY: the identity must match the pending snapshot or
/// the durably recorded one, and ACTIVE follows the durable READY record.
pub(super) fn ready(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    identity: SnapshotIdentity,
) -> Result<(), Violation> {
    if coordinator.pending.is_some() {
        return Err(Violation::Ceiling);
    }
    let state = coordinator
        .peers
        .get_mut(&peer)
        .ok_or(Violation::Misaddressed)?;
    if state.ready_identity == Some(identity) {
        // A re-sent READY after reconnect gets the byte-identical ACTIVE.
        let frame = FederationFrame::SnapshotActive {
            edge_server_id: peer,
            identity,
        };
        if coordinator.send_frame(context, link, peer, &frame) {
            start_resend(coordinator, context, peer, 0);
        }
        return Ok(());
    }
    let Some(snapshot) = state.snapshot.as_mut() else {
        return Err(Violation::Phase);
    };
    if snapshot.identity != identity || !snapshot.end_sent || snapshot.ready {
        return Err(Violation::Origin);
    }
    snapshot.ready = true;
    stage_marker(
        coordinator,
        context,
        peer,
        ProjectionGenerationState::Active,
    )
}

/// Finishes READY once its marker is durable: ACTIVE is sent and the edge
/// receives the events reserved since the cut.
pub(super) fn ready_committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    let Some(snapshot) = state.snapshot.take() else {
        return;
    };
    let _cancelled = context
        .timers_mut()
        .cancel(TimerKind::FederationSnapshotExpiry, TimedId::Peer(peer));
    state.ready_identity = Some(snapshot.identity);
    // Projection activation preserves origin authority. A replacement RESET
    // still needs the durable Clean phase; origin replay alone advances Ready.
    let frame = FederationFrame::SnapshotActive {
        edge_server_id: peer,
        identity: snapshot.identity,
    };
    let link = snapshot.link;
    if coordinator.send_frame(context, link, peer, &frame) {
        start_resend(coordinator, context, peer, 0);
    }
}

/// Drops a generation whose marker or READY row did not persist and retires
/// its link. Storage refused the batch (disk pressure, most often), and no
/// later event re-stages the marker, so the edge would otherwise sit in the
/// snapshot phase until the token expired. Reconnecting resumes from the
/// edge's committed projection once storage accepts writes again.
pub(super) fn rejected(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    let Some(snapshot) = state.snapshot.take() else {
        return;
    };
    let _cancelled = context
        .timers_mut()
        .cancel(TimerKind::FederationSnapshotExpiry, TimedId::Peer(peer));
    let link = snapshot.link;
    let live = state.live.as_ref().is_some_and(|live| live.link == link);
    if live {
        coordinator.fail_link(context, link, peer, Violation::Ceiling);
    }
}

/// Handles the pacing and expiry timers; returns whether one was federation's.
pub(super) fn timer_fired(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    entry: TimerEntry,
) -> bool {
    let TimedId::Peer(peer) = entry.id else {
        return false;
    };
    match entry.kind {
        TimerKind::FederationSnapshotSend => {
            continue_send(coordinator, context, peer);
            true
        }
        TimerKind::FederationSnapshotExpiry => {
            expire(coordinator, context, peer, entry.deadline);
            true
        }
        _ => false,
    }
}

/// Discards a snapshot whose READY never arrived within the token lifetime.
fn expire(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    _now: MonotonicTick,
) {
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    let Some(snapshot) = state.snapshot.as_ref() else {
        return;
    };
    if snapshot.ready {
        return;
    }
    let link = snapshot.link;
    state.snapshot = None;
    if state.live.as_ref().is_some_and(|live| live.link == link) {
        coordinator.fail_link(context, link, peer, Violation::Phase);
    }
}
