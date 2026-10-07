//! Companion event delivery (companion Section 12.5): one durable
//! contiguous stream per target edge, event copies built from the ordered
//! plan, `EEVENT` and `EDATA` lines from durable rows, cumulative `EACK`
//! handling, the per-edge unacknowledged ceilings, and replay trimming.

use std::collections::{BTreeMap, VecDeque};

#[cfg(test)]
#[path = "events/tests/barrier_resume.rs"]
mod barrier_resume_tests;
#[cfg(test)]
#[path = "events/cache/tests/mod.rs"]
mod cache_tests;
#[cfg(test)]
#[path = "events/tests/resume_cursor.rs"]
mod resume_cursor_tests;
mod row_storage;
mod shared_bytes;
pub use shared_bytes::SharedBytes;

use agenc_relay_domain::e2ee::limits::{
    MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE, MAX_UNACKED_E2EE_EVENTS_PER_EDGE,
};
use agenc_relay_domain::e2ee::projection::{EventKind, EventPlan, PlannedEvent};
use agenc_relay_e2ee::federation::frames::{CompanionFrame, Correlation, DeliveryPosition};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{ArcFederationEvent, ArcFederationEventKind};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
use agenc_relay_e2ee::wire::fragment::fragment_object;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_federation_wire::FederationLineText;
use agenc_relay_storage::e2ee_records::delivery_recovery::{
    Acknowledgement, DeliveryOwner, DeliveryRecoveryRow, DeliveryScope, ScopedOutbox,
    ScopedOutboxFields,
};
use agenc_relay_types::ServerId;

use super::{CompanionCoordinator, CompanionFault};
use crate::state_core::durable::AccountServiceDurableWrite;

/// Acknowledged bodies retained in each edge's hot cache; durable history has separate limits.
pub const MAX_ACKED_REPLAY_ROWS: usize = 4_096;
pub(super) const MAX_ACKED_CACHE_BYTES: u64 = 16 * 1024 * 1024;

/// One queued event row of a delivery stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamRow {
    /// Delivery sequence.
    pub sequence: u64,
    /// Event identity.
    pub event_id: [u8; 16],
    /// The encoded `federation_event` wire object.
    pub event: SharedBytes,
    /// The referenced payload object identifier and bytes, if any.
    pub payload: Option<([u8; 32], SharedBytes)>,
    /// Durable ACK state and original accepted retention-time metadata.
    pub acknowledgement: Acknowledgement,
}

impl StreamRow {
    /// Whether the exact row is covered by a committed acknowledgement.
    #[must_use]
    pub const fn acked(&self) -> bool {
        self.acknowledgement.is_acknowledged()
    }
}

/// The delivery stream of one target edge.
#[derive(Debug, Default)]
pub struct DeliveryStream {
    /// Exact durable scope and cursor; absent only before READY is committed.
    pub owner: Option<DeliveryOwner>,
    /// Delivery generation.
    pub generation: u64,
    /// The next sequence to assign.
    pub next_sequence: u64,
    /// The highest acknowledged sequence and its event.
    pub acked: Option<(u64, [u8; 16])>,
    /// Rows from the oldest retained to the newest.
    pub rows: VecDeque<StreamRow>,
    /// Whether the edge is `EVENT_BLOCKED`.
    pub blocked: bool,
    /// The first and last sequence of an open cross-profile barrier; the
    /// edge acknowledges the last one cumulatively.
    pub barrier: Option<(u64, u64)>,
    /// Later copies remain held until both profiles acknowledge their endpoints.
    pub(crate) hold_after: Option<u64>,
    /// Complete durable replay inventory; cached bodies may cover only its tail.
    pub(crate) replay: Option<super::delivery_owner::restore::replay::State>,
    // Rows and their body handles must drop before their container reservation.
    pub(crate) row_backing: Option<row_storage::Backing>,
}

impl DeliveryStream {
    fn unacked(&self) -> (u64, u64) {
        self.rows
            .iter()
            .filter(|row| !row.acked())
            .fold((0, 0), |(count, bytes), row| {
                let row_bytes =
                    row.event.len() + row.payload.as_ref().map_or(0, |(_, bytes)| bytes.len());
                (
                    count + 1,
                    bytes.saturating_add(u64::try_from(row_bytes).unwrap_or(u64::MAX)),
                )
            })
    }

    /// Whether appending `count` rows of `bytes` would cross a ceiling.
    #[must_use]
    pub fn would_block(&self, count: u64, bytes: u64) -> bool {
        let (unacked_count, unacked_bytes) = self.unacked();
        unacked_count.saturating_add(count) > MAX_UNACKED_E2EE_EVENTS_PER_EDGE
            || unacked_bytes.saturating_add(bytes) > MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE
    }

    /// Acknowledges cumulatively through `sequence` with `event_id`.
    pub fn acknowledge(
        &mut self,
        sequence: u64,
        event_id: [u8; 16],
        acknowledgement: Acknowledgement,
    ) -> Result<(), CompanionFault> {
        if !acknowledgement.is_acknowledged() {
            return Err(CompanionFault::Protocol);
        }
        if self.acked == Some((sequence, event_id)) {
            return Ok(());
        }
        let Some(row) = self.rows.iter_mut().find(|row| row.sequence == sequence) else {
            return Err(CompanionFault::Protocol);
        };
        if row.event_id != event_id {
            return Err(CompanionFault::Protocol);
        }
        if row.acked() {
            return Ok(());
        }
        let expected = self.acked.map_or(0, |(acked, _)| acked.saturating_add(1));
        let within_barrier = self
            .barrier
            .is_some_and(|(first, last)| sequence == last && expected >= first);
        if sequence != expected && !within_barrier {
            return Err(CompanionFault::Protocol);
        }
        self.record_acknowledgement(sequence, event_id, acknowledgement);
        Ok(())
    }

    /// A resume cursor past the committed acknowledgement (companion 12.5)
    /// names the last row the edge acknowledged: a row this stream delivered
    /// and still retains unacknowledged, with its exact event ID, at the end
    /// of a contiguous unacknowledged prefix. It acknowledges that prefix
    /// cumulatively. Inside an open barrier only the barrier's end
    /// qualifies, and never a row the barrier still holds back.
    pub(super) fn validate_resume(
        &self,
        sequence: u64,
        event_id: [u8; 16],
    ) -> Result<(), CompanionFault> {
        if self.hold_after.is_some_and(|last| sequence > last) {
            return Err(CompanionFault::Protocol);
        }
        match self.barrier {
            Some((first, _)) if sequence >= first => {
                self.validate_barrier_resume(sequence, event_id)
            }
            _ => self.validate_prefix(sequence, event_id),
        }
    }

    /// A resume may recover a lost ordinary prefix only through the exact gate end.
    pub(super) fn validate_barrier_resume(
        &self,
        sequence: u64,
        event_id: [u8; 16],
    ) -> Result<(), CompanionFault> {
        if self.barrier.is_none_or(|(_, last)| sequence != last) {
            return Err(CompanionFault::Protocol);
        }
        self.validate_prefix(sequence, event_id)
    }

    /// The unacknowledged rows after the committed acknowledgement run
    /// contiguously to `sequence`, whose row carries `event_id`.
    fn validate_prefix(&self, sequence: u64, event_id: [u8; 16]) -> Result<(), CompanionFault> {
        let mut expected = self
            .acked
            .map_or(Some(0), |(acked, _)| acked.checked_add(1))
            .ok_or(CompanionFault::Protocol)?;
        for row in self
            .rows
            .iter()
            .filter(|row| !row.acked() && row.sequence <= sequence)
        {
            if row.sequence != expected {
                return Err(CompanionFault::Protocol);
            }
            if row.sequence == sequence {
                return if row.event_id == event_id {
                    Ok(())
                } else {
                    Err(CompanionFault::Protocol)
                };
            }
            expected = expected.checked_add(1).ok_or(CompanionFault::Protocol)?;
        }
        Err(CompanionFault::Protocol)
    }

    /// Records the cumulative acknowledgement a resume cursor carries
    /// ([`Self::validate_resume`]).
    pub(super) fn acknowledge_resume(
        &mut self,
        sequence: u64,
        event_id: [u8; 16],
        acknowledgement: Acknowledgement,
    ) -> Result<(), CompanionFault> {
        if !acknowledgement.is_acknowledged() {
            return Err(CompanionFault::Protocol);
        }
        self.validate_resume(sequence, event_id)?;
        self.record_acknowledgement(sequence, event_id, acknowledgement);
        Ok(())
    }

    fn record_acknowledgement(
        &mut self,
        sequence: u64,
        event_id: [u8; 16],
        acknowledgement: Acknowledgement,
    ) {
        for row in self
            .rows
            .iter_mut()
            .filter(|row| row.sequence <= sequence && !row.acked())
        {
            row.acknowledgement = acknowledgement;
        }
        self.acked = Some((sequence, event_id));
        if self.barrier.is_some_and(|(_, last)| sequence >= last) {
            self.barrier = None;
        }
        self.trim_acknowledged_cache();
    }

    fn trim_acknowledged_cache(&mut self) {
        let mut bytes = 0_u64;
        let mut first = None;
        for (count, row) in self.rows.iter().rev().filter(|row| row.acked()).enumerate() {
            let row_bytes = row
                .event
                .len()
                .saturating_add(row.payload.as_ref().map_or(0, |(_, body)| body.len()));
            bytes = bytes.saturating_add(u64::try_from(row_bytes).unwrap_or(u64::MAX));
            if count >= MAX_ACKED_REPLAY_ROWS || bytes > MAX_ACKED_CACHE_BYTES {
                break;
            }
            first = Some(row.sequence);
        }
        while self
            .rows
            .front()
            .is_some_and(|row| row.acked() && first.is_none_or(|first| row.sequence < first))
        {
            self.rows.pop_front();
        }
    }

    /// Unacknowledged rows in order, for retransmission.
    #[must_use]
    pub fn unacked_rows(&self) -> Vec<&StreamRow> {
        self.rows.iter().filter(|row| !row.acked()).collect()
    }
}

/// One event copy ready to send after commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyToSend {
    /// Target edge.
    pub target: ServerId,
    /// The row.
    pub row: StreamRow,
    /// Delivery generation.
    pub generation: u64,
}

/// The semantic content of one event copy before framing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventContent {
    /// The planned copy.
    pub planned: PlannedEvent,
    /// Origin identity and generation for source-bearing events.
    pub origin: Option<([u8; 16], u64)>,
    /// The encoded source view for source-bearing events.
    pub source_view: Vec<u8>,
    /// The request correlation on the home completion copy.
    pub correlation: Option<Correlation>,
    /// The encoded event result tuple.
    pub encoded_result: Vec<u8>,
    /// The payload object bytes, if any.
    pub payload: Option<Vec<u8>>,
}

fn wire_kind(kind: EventKind) -> ArcFederationEventKind {
    match kind {
        EventKind::ChannelApplication => ArcFederationEventKind::ChannelApplication,
        EventKind::DirectApplication => ArcFederationEventKind::DirectApplication,
        EventKind::Candidate => ArcFederationEventKind::CandidateEvent,
        EventKind::CommitAck => ArcFederationEventKind::CommitAckEvent,
        EventKind::Finalized => ArcFederationEventKind::FinalizedEvent,
        EventKind::Aborted => ArcFederationEventKind::AbortedEvent,
        EventKind::ReinitActivated => ArcFederationEventKind::ReinitActivatedEvent,
        EventKind::ReinitAborted => ArcFederationEventKind::ReinitAbortedEvent,
        EventKind::Closed => ArcFederationEventKind::ClosedEvent,
        EventKind::RouteStateChanged => ArcFederationEventKind::RouteStateChanged,
        EventKind::RequestCompleted => ArcFederationEventKind::RequestCompleted,
        EventKind::RouteStateHidden => ArcFederationEventKind::RouteStateHidden,
        EventKind::ReinitStaged => ArcFederationEventKind::ReinitStagedEvent,
        EventKind::ReinitAck => ArcFederationEventKind::ReinitAckEvent,
    }
}

fn optional<const N: usize>(value: Option<[u8; N]>) -> Result<Opaque<0, N>, E2eeReplyCode> {
    Opaque::new(value.map_or_else(Vec::new, |bytes| bytes.to_vec()))
        .map_err(|_| E2eeReplyCode::InvalidFragment)
}

/// Builds and sequences every copy of one mutation: identifiers are drawn
/// from `entropy` after the plan is ordered, sequences are assigned per
/// target stream, and the rows to write and copies to send are returned.
/// The streams are not mutated until the effects apply.
/// The companion half of one cross-profile barrier at one target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierAssignment {
    /// The per-target mutation identity.
    pub mutation_id: [u8; 16],
    /// Base parts, indices `0..base_parts`.
    pub base_parts: u16,
    /// Base plus companion parts.
    pub part_count: u16,
}

/// The copies, durable rows, advanced streams, and the last barrier
/// sequence per target of one sequenced plan.
pub(crate) struct Sequenced {
    /// Copies to send after commit.
    pub copies: Vec<CopyToSend>,
    /// Durable rows.
    pub writes: Vec<AccountServiceDurableWrite>,
    /// The advanced streams.
    pub streams: Vec<(ServerId, DeliveryStream)>,
    /// The last companion sequence of each barrier target.
    pub barrier_last: BTreeMap<ServerId, u64>,
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one pass assigns every planned copy its delivery position and outbox row so the per-target stream advances exactly once per batch
pub(crate) fn sequence_copies(
    coordinator: &CompanionCoordinator,
    plan: &EventPlan,
    contents: &[EventContent],
    state_generation: u64,
    entropy: &mut dyn agenc_relay_types::EntropySource,
    barriers: &BTreeMap<ServerId, BarrierAssignment>,
    backing: &crate::budget::BackingReservationPort,
) -> Result<Sequenced, E2eeReplyCode> {
    let mut copies = Vec::new();
    let mut writes = Vec::new();
    let mut streams: Vec<(ServerId, DeliveryStream)> = Vec::new();
    let mut part_indices: BTreeMap<ServerId, u16> = BTreeMap::new();
    let mut barrier_last = BTreeMap::new();
    for (index, planned) in plan.events().iter().enumerate() {
        let content = contents
            .get(index)
            .filter(|content| content.planned == *planned)
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        let stream = match streams
            .iter_mut()
            .find(|(target, _)| *target == planned.target)
        {
            Some((_, stream)) => stream,
            None => {
                let additional = plan
                    .events()
                    .iter()
                    .filter(|event| event.target == planned.target)
                    .count();
                if coordinator
                    .state
                    .streams
                    .get(&planned.target)
                    .is_some_and(|stream| {
                        stream.would_block(u64::try_from(additional).unwrap_or(u64::MAX), 0)
                    })
                {
                    return Err(E2eeReplyCode::Syncing);
                }
                let stream = match coordinator.state.streams.get(&planned.target) {
                    Some(stream) => stream.try_clone(additional, backing),
                    None => DeliveryStream::with_row_capacity(additional, backing),
                }
                .map_err(|_| E2eeReplyCode::RateLimited)?;
                streams.push((planned.target, stream));
                streams
                    .last_mut()
                    .map(|(_, stream)| stream)
                    .ok_or(E2eeReplyCode::InvalidFragment)?
            }
        };
        let payload_bytes = content
            .payload
            .as_ref()
            .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if stream.blocked || stream.would_block(1, payload_bytes.saturating_add(1_024)) {
            return Err(E2eeReplyCode::Syncing);
        }
        let mut event_id = [0_u8; 16];
        entropy
            .fill_exact(&mut event_id)
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        let sequence = stream.next_sequence;
        stream.next_sequence = sequence.checked_add(1).ok_or(E2eeReplyCode::RateLimited)?;
        let payload_id = content
            .payload
            .as_ref()
            .map(|bytes| *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes());
        let cross_profile = match barriers.get(&planned.target) {
            None => None,
            Some(assignment) => {
                let next = part_indices.entry(planned.target).or_insert(0);
                let part_index = assignment
                    .base_parts
                    .checked_add(*next)
                    .filter(|index| *index < assignment.part_count)
                    .ok_or(E2eeReplyCode::InvalidFragment)?;
                *next = next.saturating_add(1);
                let first = stream.barrier.map_or(sequence, |(first, _)| first);
                stream.barrier = Some((first, sequence));
                barrier_last.insert(planned.target, sequence);
                Some((assignment.mutation_id, part_index, assignment.part_count))
            }
        };
        let event = encode_event(
            coordinator,
            content,
            EventPosition {
                delivery_generation: stream.generation,
                state_generation,
                sequence,
                event_id,
                payload_id,
                cross_profile,
            },
        )?;
        let row = StreamRow {
            sequence,
            event_id,
            event: SharedBytes::from_owned(event, backing)
                .map_err(|_| E2eeReplyCode::RateLimited)?,
            payload: payload_id
                .zip(content.payload.as_ref())
                .map(|(id, bytes)| SharedBytes::copy_from(bytes, backing).map(|bytes| (id, bytes)))
                .transpose()
                .map_err(|_| E2eeReplyCode::RateLimited)?,
            acknowledgement: Acknowledgement::Unacknowledged,
        };
        writes.push(outbox_write(
            stream.owner.as_ref().ok_or(E2eeReplyCode::Syncing)?.scope(),
            stream.generation,
            &row,
            Acknowledgement::Unacknowledged,
        )?);
        super::delivery_owner::append_object(&mut writes, &row.event)?;
        if let Some((_, bytes)) = &row.payload {
            super::delivery_owner::append_object(&mut writes, bytes)?;
        }
        stream.rows.push_back(row.clone());
        copies.push(CopyToSend {
            target: planned.target,
            row,
            generation: stream.generation,
        });
    }
    for (target, stream) in &mut streams {
        stream.owner =
            Some(super::delivery_owner::refreshed(stream).map_err(|_| E2eeReplyCode::Syncing)?);
        writes.push(cursor_write(*target, stream)?);
    }
    let barrier_targets_missing = barriers
        .keys()
        .any(|target| !barrier_last.contains_key(target));
    if barrier_targets_missing {
        return Err(E2eeReplyCode::InvalidFragment);
    }
    Ok(Sequenced {
        copies,
        writes,
        streams,
        barrier_last,
    })
}

/// Where one event copy sits in its stream and barrier.
struct EventPosition {
    delivery_generation: u64,
    state_generation: u64,
    sequence: u64,
    event_id: [u8; 16],
    payload_id: Option<[u8; 32]>,
    cross_profile: Option<([u8; 16], u16, u16)>,
}

fn encode_event(
    coordinator: &CompanionCoordinator,
    content: &EventContent,
    position: EventPosition,
) -> Result<Vec<u8>, E2eeReplyCode> {
    let planned = &content.planned;
    let correlation = content.correlation.as_ref();
    let EventPosition {
        delivery_generation,
        state_generation,
        sequence,
        event_id,
        payload_id,
        cross_profile,
    } = position;
    let event = ArcFederationEvent {
        profile_version: 1,
        network_id: coordinator.network_id,
        target_server_id: *planned.target.as_bytes(),
        delivery_generation,
        coordinator_state_generation: state_generation,
        delivery_sequence: sequence,
        event_id,
        event_kind: wire_kind(planned.kind),
        cross_profile_mutation_id: optional::<16>(cross_profile.map(|(id, _, _)| id))?,
        cross_profile_part_index: cross_profile.map_or(0, |(_, index, _)| index),
        cross_profile_part_count: cross_profile.map_or(0, |(_, _, count)| count),
        conversation_id: optional(planned.conversation_id)?,
        route_sequence: planned.route_sequence,
        origin_id: optional(content.origin.map(|(id, _)| id))?,
        origin_generation: content.origin.map_or(0, |(_, generation)| generation),
        source_view: Opaque::new(content.source_view.clone())
            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
        request_home_server_id: optional(correlation.map(|c| c.peer_server_id))?,
        request_server_incarnation: optional(correlation.map(|c| c.server_incarnation))?,
        request_origin_id: optional(correlation.map(|c| c.origin_id))?,
        request_origin_generation: correlation.map_or(0, |c| c.origin_generation),
        request_operation_sequence: correlation.map_or(0, |c| c.operation_sequence),
        request_id: optional(correlation.map(|c| c.request_id))?,
        payload_object_id: optional(payload_id)?,
        encoded_event_result: Opaque::new(content.encoded_result.clone())
            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
    };
    let body = event.encode().map_err(|_| E2eeReplyCode::InvalidFragment)?;
    ArcWireObject::new(ArcWireObjectKind::FederationEvent, body)
        .and_then(|object| object.encode())
        .map_err(|_| E2eeReplyCode::InvalidFragment)
}

pub(super) fn outbox_write(
    scope: &DeliveryScope,
    generation: u64,
    row: &StreamRow,
    acknowledgement: Acknowledgement,
) -> Result<AccountServiceDurableWrite, E2eeReplyCode> {
    let event = super::delivery_owner::restore::decode_event(&row.event)
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    let cross_profile = super::delivery_owner::restore::cross_profile(&event)
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    let outbox = ScopedOutbox::new(ScopedOutboxFields {
        scope: *scope,
        generation,
        sequence: row.sequence,
        event_id: row.event_id,
        event_object_id: *agenc_relay_e2ee::ObjectId::compute(&row.event).as_bytes(),
        event_bytes: u32::try_from(row.event.len()).map_err(|_| E2eeReplyCode::InvalidFragment)?,
        payload_object_id: row.payload.as_ref().map(|(id, _)| *id),
        payload_bytes: row.payload.as_ref().map_or(0, |(_, bytes)| {
            u32::try_from(bytes.len()).unwrap_or(u32::MAX)
        }),
        acknowledgement,
        cross_profile,
    })
    .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    let key = outbox.key().map_err(|_| E2eeReplyCode::InvalidFragment)?;
    let body = DeliveryRecoveryRow::Outbox(outbox)
        .encode()
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    super::request::state_row(
        agenc_relay_storage::TableId::E2eeState,
        agenc_relay_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND,
        key,
        body,
    )
}

/// The durable cursor row of one stream.
pub(crate) fn cursor_write(
    target: ServerId,
    stream: &DeliveryStream,
) -> Result<AccountServiceDurableWrite, E2eeReplyCode> {
    let owner = stream.owner.as_ref().ok_or(E2eeReplyCode::Syncing)?;
    if owner.scope().target_server_id() != *target.as_bytes() {
        return Err(E2eeReplyCode::InvalidFragment);
    }
    super::delivery_owner::write(owner).map_err(|_| E2eeReplyCode::InvalidFragment)
}

/// The `EEVENT` and optional `EDATA` lines of one row.
pub fn render_copy(
    server_name: &str,
    copy: &CopyToSend,
) -> Result<Vec<FederationLineText>, E2eeReplyCode> {
    let mut lines = Vec::new();
    let position = DeliveryPosition {
        server_id: *copy.target.as_bytes(),
        delivery_generation: copy.generation,
        delivery_sequence: copy.row.sequence,
        event_id: copy.row.event_id,
    };
    let event_id = *agenc_relay_e2ee::ObjectId::compute(&copy.row.event).as_bytes();
    for fragment in fragment_object(&copy.row.event).map_err(|_| E2eeReplyCode::InvalidFragment)? {
        let frame = CompanionFrame::Event {
            position,
            object_id: event_id,
            fragment,
        };
        lines.push(line(server_name, &frame)?);
    }
    if let Some((payload_id, bytes)) = &copy.row.payload {
        for fragment in fragment_object(bytes).map_err(|_| E2eeReplyCode::InvalidFragment)? {
            let frame = CompanionFrame::Data {
                position,
                object_id: *payload_id,
                fragment,
            };
            lines.push(line(server_name, &frame)?);
        }
    }
    Ok(lines)
}

/// Renders one companion frame under the local name.
pub fn line(
    server_name: &str,
    frame: &CompanionFrame,
) -> Result<FederationLineText, E2eeReplyCode> {
    let text = frame
        .render(server_name)
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    FederationLineText::from_rendered(text).map_err(|_| E2eeReplyCode::InvalidFragment)
}

/// Handles an `EACK` from `peer`.
pub(crate) fn on_ack(
    coordinator: &mut CompanionCoordinator,
    link: crate::federation::LinkId,
    peer: ServerId,
    position: DeliveryPosition,
    trusted_ack_unix_seconds: Option<u64>,
) -> Result<Vec<super::sync::Action>, CompanionFault> {
    super::delivery_owner::acknowledgement::prepare(
        coordinator,
        link,
        peer,
        position,
        trusted_ack_unix_seconds,
    )
}
