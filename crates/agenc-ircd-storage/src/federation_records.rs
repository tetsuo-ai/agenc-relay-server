//! Durable federation rows for tables 11, 12, 13, 17, and 18 (spec 20.5 to
//! 20.9, 23.2).
//!
//! Every arm is a hand-written versioned codec wrapped in the table- and
//! kind-bound [`ProtocolRecordBody`] envelope, so a value accepted for one
//! table cannot be replayed as another. Keys are exact byte concatenations
//! whose layouts are documented on each builder. Protocol semantics stay in
//! the domain and federation crates; this module only fixes bytes.

use agenc_ircd_types::{ServerId, ServerIncarnation};

use crate::codec::{Decoder, Encoder};
use crate::records::ProtocolRecordBody;
use crate::schema::{MAX_STORED_KEY_BYTES, StoredKey, TableId};
use crate::{MAX_PROTOCOL_BODY_BYTES, StorageError};

/// Record kind of the one live `federation_peer` arm.
pub const PEER_RECORD_KIND: u16 = 1;
/// Record kind of the one live `federation_origin` arm.
pub const ORIGIN_RECORD_KIND: u16 = 1;
/// Coordinator-side exact request result.
pub const COORDINATOR_RESULT_KIND: u16 = 1;
/// Edge-side retained request with its rendering state.
pub const EDGE_REQUEST_KIND: u16 = 2;
/// Edge-side completion-coverage arm written when the event precedes the result.
pub const COMPLETION_COVERAGE_KIND: u16 = 3;
/// The one live `edge_outbox` arm.
pub const OUTBOX_EVENT_KIND: u16 = 1;
/// One standing projection entry.
pub const PROJECTION_ENTRY_KIND: u16 = 1;
/// The per-generation marker row of a projection.
pub const PROJECTION_MARKER_KIND: u16 = 2;

/// Version prefix shared by every federation body codec.
const FEDERATION_BODY_VERSION: u16 = 1;
/// Peers retain at most this many accepted recovery epochs.
pub const MAX_ACCEPTED_EPOCHS: usize = 64;
/// A canonical `FederationOrigin` is at most this many bytes.
const MAX_ORIGIN_OBJECT_BYTES: usize = 512;
/// A canonical request or result object is at most this many bytes.
const MAX_OPERATION_OBJECT_BYTES: usize = 262_144;
/// A canonical `FederationEvent` is at most this many bytes.
const MAX_EVENT_OBJECT_BYTES: usize = 262_344;
/// A canonical `FederationProjectionEntry` is at most this many bytes.
const MAX_PROJECTION_ENTRY_BYTES: usize = 8_320;
const ID_BYTES: usize = 16;
const HASH_BYTES: usize = 32;
const REPLAY_KEY_BYTES: usize = 64;
const ORIGIN_KEY_BYTES: usize = 56;
const OUTBOX_KEY_BYTES: usize = 32;
const PROJECTION_KEY_PREFIX_BYTES: usize = 26;
/// The projection marker sorts before every entry of its generation.
const PROJECTION_MARKER_KIND_FIELD: u16 = 0;

/// The synchronization phase persisted for one peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerPhase {
    /// The link completed READY and executes.
    Ready,
    /// The link was lost; a fresh grace interval starts at the next boot.
    Suspended,
    /// The grace interval passed and the expiry fence is committed.
    Expired,
    /// Cleanup after expiry finished; a new incarnation is required.
    Clean,
}

impl PeerPhase {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Ready => 1,
            Self::Suspended => 2,
            Self::Expired => 3,
            Self::Clean => 4,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::Suspended),
            3 => Ok(Self::Expired),
            4 => Ok(Self::Clean),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// The durable cursor of one delivery stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryCursorRecord {
    /// The last acknowledged or applied delivery sequence.
    pub delivery_sequence: u64,
    /// The event identity at that sequence.
    pub event_id: [u8; ID_BYTES],
}

/// The one live `federation_peer` row.
///
/// A coordinator writes one per edge; an edge writes one for its coordinator.
/// Fields unused by a role are zero or absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationPeerRecord {
    /// The accepted peer incarnation.
    pub server_incarnation: [u8; ID_BYTES],
    /// The accepted peer recovery epoch.
    pub recovery_epoch: [u8; ID_BYTES],
    /// Every recovery epoch ever accepted from this peer, oldest first.
    pub accepted_epochs: Vec<[u8; ID_BYTES]>,
    /// The link phase.
    pub phase: PeerPhase,
    /// The current projection generation, nonzero once one exists.
    pub projection_generation: u64,
    /// The next delivery sequence the coordinator will send.
    pub next_delivery_sequence: u64,
    /// The acknowledged (coordinator) or applied (edge) cursor.
    pub cursor: Option<DeliveryCursorRecord>,
    /// Standing entries in the active generation.
    pub active_entry_count: u64,
    /// Encoded bytes of the active generation's entries.
    pub active_entry_bytes: u64,
    /// A pending successor generation, if one is being built or installed.
    pub pending_generation: Option<u64>,
    /// Whether the active generation was fenced pending a snapshot.
    pub snapshot_required: bool,
    /// The next Session ID expiry cleanup must hide, if cleanup is running.
    pub cleanup_cursor: Option<[u8; ID_BYTES]>,
    /// Whether an operator quarantined the peer.
    pub quarantined: bool,
    /// The edge's client resynchronization epoch.
    pub client_resync_epoch: u64,
}

impl FederationPeerRecord {
    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.accepted_epochs.len() > MAX_ACCEPTED_EPOCHS {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoder = Encoder::with_capacity(256, MAX_PROTOCOL_BODY_BYTES)?;
        encoder.put_u16(FEDERATION_BODY_VERSION)?;
        encoder.put_fixed(&self.server_incarnation)?;
        encoder.put_fixed(&self.recovery_epoch)?;
        let count =
            u16::try_from(self.accepted_epochs.len()).map_err(|_| StorageError::Overflow)?;
        encoder.put_u16(count)?;
        for epoch in &self.accepted_epochs {
            encoder.put_fixed(epoch)?;
        }
        encoder.put_u16(self.phase.wire_value())?;
        encoder.put_u64(self.projection_generation)?;
        encoder.put_u64(self.next_delivery_sequence)?;
        put_cursor(&mut encoder, self.cursor)?;
        encoder.put_u64(self.active_entry_count)?;
        encoder.put_u64(self.active_entry_bytes)?;
        put_optional_u64(&mut encoder, self.pending_generation)?;
        put_bool(&mut encoder, self.snapshot_required)?;
        put_optional_fixed(&mut encoder, self.cleanup_cursor.as_ref().map(|id| &id[..]))?;
        put_bool(&mut encoder, self.quarantined)?;
        encoder.put_u64(self.client_resync_epoch)?;
        wrap(TableId::FederationPeer, PEER_RECORD_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(TableId::FederationPeer, PEER_RECORD_KIND, body)?;
        let mut decoder = Decoder::new(&inner);
        expect_version(&mut decoder)?;
        let server_incarnation = decoder.array::<ID_BYTES>()?;
        let recovery_epoch = decoder.array::<ID_BYTES>()?;
        let count = usize::from(decoder.u16()?);
        if count > MAX_ACCEPTED_EPOCHS {
            return Err(StorageError::LimitExceeded);
        }
        let mut accepted_epochs = Vec::with_capacity(count);
        for _ in 0..count {
            accepted_epochs.push(decoder.array::<ID_BYTES>()?);
        }
        let record = Self {
            server_incarnation,
            recovery_epoch,
            accepted_epochs,
            phase: PeerPhase::from_wire(decoder.u16()?)?,
            projection_generation: decoder.u64()?,
            next_delivery_sequence: decoder.u64()?,
            cursor: take_cursor(&mut decoder)?,
            active_entry_count: decoder.u64()?,
            active_entry_bytes: decoder.u64()?,
            pending_generation: take_optional_u64(&mut decoder)?,
            snapshot_required: take_bool(&mut decoder)?,
            cleanup_cursor: take_optional_fixed::<ID_BYTES>(&mut decoder)?,
            quarantined: take_bool(&mut decoder)?,
            client_resync_epoch: decoder.u64()?,
        };
        decoder.finish()?;
        Ok(record)
    }
}

/// The durable lifecycle status of one origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginRowStatus {
    /// Requests execute.
    Live,
    /// The edge link is down.
    Suspended,
    /// A sequence gap blocked the origin.
    Blocked,
    /// FORIGIN DEL was accepted; the row is a tombstone with its next sequence.
    Deleted,
    /// The incarnation, epoch, or grace fence ended the origin.
    Fenced,
}

impl OriginRowStatus {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Live => 1,
            Self::Suspended => 2,
            Self::Blocked => 3,
            Self::Deleted => 4,
            Self::Fenced => 5,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Live),
            2 => Ok(Self::Suspended),
            3 => Ok(Self::Blocked),
            4 => Ok(Self::Deleted),
            5 => Ok(Self::Fenced),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// Edge-only flag: the origin's client connection is gone.
pub const ORIGIN_FLAG_SINK_GONE: u16 = 1;
/// Edge-only flag: a FORIGIN DEL is still owed to the coordinator.
pub const ORIGIN_FLAG_PENDING_DEL: u16 = 1 << 1;

/// The one live `federation_origin` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationOriginRecord {
    /// The exact canonical `FederationOrigin` object of this generation.
    pub origin_object: Vec<u8>,
    /// The Section-20.4 identity of that object.
    pub origin_object_id: [u8; HASH_BYTES],
    /// The next expected operation sequence.
    pub next_sequence: u64,
    /// The lifecycle status.
    pub status: OriginRowStatus,
    /// Edge-side flags.
    pub flags: u16,
}

impl FederationOriginRecord {
    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.origin_object.is_empty() || self.origin_object.len() > MAX_ORIGIN_OBJECT_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        if self.flags & !(ORIGIN_FLAG_SINK_GONE | ORIGIN_FLAG_PENDING_DEL) != 0 {
            return Err(StorageError::InvalidEncoding);
        }
        let mut encoder = Encoder::with_capacity(
            self.origin_object.len().saturating_add(64),
            MAX_PROTOCOL_BODY_BYTES,
        )?;
        encoder.put_u16(FEDERATION_BODY_VERSION)?;
        encoder.put_vector_u32(&self.origin_object)?;
        encoder.put_fixed(&self.origin_object_id)?;
        encoder.put_u64(self.next_sequence)?;
        encoder.put_u16(self.status.wire_value())?;
        encoder.put_u16(self.flags)?;
        wrap(
            TableId::FederationOrigin,
            ORIGIN_RECORD_KIND,
            encoder.finish(),
        )
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(TableId::FederationOrigin, ORIGIN_RECORD_KIND, body)?;
        let mut decoder = Decoder::new(&inner);
        expect_version(&mut decoder)?;
        let origin_object = decoder.vector_u32(MAX_ORIGIN_OBJECT_BYTES)?.to_vec();
        if origin_object.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        let record = Self {
            origin_object,
            origin_object_id: decoder.array::<HASH_BYTES>()?,
            next_sequence: decoder.u64()?,
            status: OriginRowStatus::from_wire(decoder.u16()?)?,
            flags: decoder.u16()?,
        };
        decoder.finish()?;
        if record.flags & !(ORIGIN_FLAG_SINK_GONE | ORIGIN_FLAG_PENDING_DEL) != 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(record)
    }
}

/// The coordinator's exact stored outcome of one accepted request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorResultRecord {
    /// The accepted request identity.
    pub request_id: [u8; ID_BYTES],
    /// The accepted request object identity.
    pub request_object_id: [u8; HASH_BYTES],
    /// The identity of the stored result object.
    pub result_object_id: [u8; HASH_BYTES],
    /// The exact canonical `FederationResult` bytes replayed on retry.
    pub result_object: Vec<u8>,
    /// The completion event for a committed or registered result.
    pub completion_event_id: Option<[u8; ID_BYTES]>,
    /// The resulting global state generation, zero for a failed result.
    pub resulting_state_generation: u64,
}

impl CoordinatorResultRecord {
    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.result_object.is_empty() || self.result_object.len() > MAX_OPERATION_OBJECT_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoder = Encoder::with_capacity(
            self.result_object.len().saturating_add(128),
            MAX_PROTOCOL_BODY_BYTES,
        )?;
        encoder.put_u16(FEDERATION_BODY_VERSION)?;
        encoder.put_fixed(&self.request_id)?;
        encoder.put_fixed(&self.request_object_id)?;
        encoder.put_fixed(&self.result_object_id)?;
        encoder.put_vector_u32(&self.result_object)?;
        put_optional_fixed(
            &mut encoder,
            self.completion_event_id.as_ref().map(|id| &id[..]),
        )?;
        encoder.put_u64(self.resulting_state_generation)?;
        wrap(
            TableId::RequestResult,
            COORDINATOR_RESULT_KIND,
            encoder.finish(),
        )
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(TableId::RequestResult, COORDINATOR_RESULT_KIND, body)?;
        let mut decoder = Decoder::new(&inner);
        expect_version(&mut decoder)?;
        let request_id = decoder.array::<ID_BYTES>()?;
        let request_object_id = decoder.array::<HASH_BYTES>()?;
        let result_object_id = decoder.array::<HASH_BYTES>()?;
        let result_object = decoder.vector_u32(MAX_OPERATION_OBJECT_BYTES)?.to_vec();
        if result_object.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        let record = Self {
            request_id,
            request_object_id,
            result_object_id,
            result_object,
            completion_event_id: take_optional_fixed::<ID_BYTES>(&mut decoder)?,
            resulting_state_generation: decoder.u64()?,
        };
        decoder.finish()?;
        Ok(record)
    }
}

/// Where an edge's retained request stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeRequestPhase {
    /// The request was sent and no result is stored.
    Sent,
    /// A result is stored but its completion is not yet covered.
    ResultPending,
    /// The completion event was durably applied.
    EventCovered,
    /// A successor snapshot cut covered the result.
    SnapshotCovered,
    /// The semantic replies were rendered to the still-live sink.
    Rendered,
}

impl EdgeRequestPhase {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Sent => 1,
            Self::ResultPending => 2,
            Self::EventCovered => 3,
            Self::SnapshotCovered => 4,
            Self::Rendered => 5,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Sent),
            2 => Ok(Self::ResultPending),
            3 => Ok(Self::EventCovered),
            4 => Ok(Self::SnapshotCovered),
            5 => Ok(Self::Rendered),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// The edge's retained request, exact result, and rendering state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeRequestRecord {
    /// The request identity.
    pub request_id: [u8; ID_BYTES],
    /// The request object identity.
    pub request_object_id: [u8; HASH_BYTES],
    /// The exact canonical request bytes resent after reconnect.
    pub request_object: Vec<u8>,
    /// The rendering state.
    pub phase: EdgeRequestPhase,
    /// Whether the originating connection is gone.
    pub sink_gone: bool,
    /// The stored result object identity, once a result arrived.
    pub result_object_id: Option<[u8; HASH_BYTES]>,
    /// The exact stored result bytes, empty until a result arrived.
    pub result_object: Vec<u8>,
    /// The completion event named by the result.
    pub completion_event_id: Option<[u8; ID_BYTES]>,
    /// The resulting global state generation named by the result.
    pub resulting_state_generation: u64,
}

impl EdgeRequestRecord {
    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.request_object.is_empty()
            || self.request_object.len() > MAX_OPERATION_OBJECT_BYTES
            || self.result_object.len() > MAX_OPERATION_OBJECT_BYTES
            || self.result_object.is_empty() != self.result_object_id.is_none()
        {
            return Err(StorageError::InvalidEncoding);
        }
        let capacity = self
            .request_object
            .len()
            .saturating_add(self.result_object.len())
            .saturating_add(160);
        let mut encoder = Encoder::with_capacity(capacity, MAX_PROTOCOL_BODY_BYTES)?;
        encoder.put_u16(FEDERATION_BODY_VERSION)?;
        encoder.put_fixed(&self.request_id)?;
        encoder.put_fixed(&self.request_object_id)?;
        encoder.put_vector_u32(&self.request_object)?;
        encoder.put_u16(self.phase.wire_value())?;
        put_bool(&mut encoder, self.sink_gone)?;
        put_optional_fixed(
            &mut encoder,
            self.result_object_id.as_ref().map(|id| &id[..]),
        )?;
        encoder.put_vector_u32(&self.result_object)?;
        put_optional_fixed(
            &mut encoder,
            self.completion_event_id.as_ref().map(|id| &id[..]),
        )?;
        encoder.put_u64(self.resulting_state_generation)?;
        wrap(TableId::RequestResult, EDGE_REQUEST_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(TableId::RequestResult, EDGE_REQUEST_KIND, body)?;
        let mut decoder = Decoder::new(&inner);
        expect_version(&mut decoder)?;
        let request_id = decoder.array::<ID_BYTES>()?;
        let request_object_id = decoder.array::<HASH_BYTES>()?;
        let request_object = decoder.vector_u32(MAX_OPERATION_OBJECT_BYTES)?.to_vec();
        let phase = EdgeRequestPhase::from_wire(decoder.u16()?)?;
        let sink_gone = take_bool(&mut decoder)?;
        let result_object_id = take_optional_fixed::<HASH_BYTES>(&mut decoder)?;
        let result_object = decoder.vector_u32(MAX_OPERATION_OBJECT_BYTES)?.to_vec();
        let completion_event_id = take_optional_fixed::<ID_BYTES>(&mut decoder)?;
        let resulting_state_generation = decoder.u64()?;
        decoder.finish()?;
        if request_object.is_empty() || result_object.is_empty() != result_object_id.is_none() {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            request_id,
            request_object_id,
            request_object,
            phase,
            sink_gone,
            result_object_id,
            result_object,
            completion_event_id,
            resulting_state_generation,
        })
    }
}

/// Evidence that a `request_completed` event was applied before its result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionCoverageRecord {
    /// The retained request object identity.
    pub request_object_id: [u8; HASH_BYTES],
    /// The completion event identity.
    pub completion_event_id: [u8; ID_BYTES],
    /// The completion event object identity.
    pub completion_object_id: [u8; HASH_BYTES],
    /// The projection generation the event arrived under.
    pub projection_generation: u64,
    /// The event's delivery sequence.
    pub delivery_sequence: u64,
    /// The event's coordinator state generation.
    pub coordinator_state_generation: u64,
}

impl CompletionCoverageRecord {
    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(128, MAX_PROTOCOL_BODY_BYTES)?;
        encoder.put_u16(FEDERATION_BODY_VERSION)?;
        encoder.put_fixed(&self.request_object_id)?;
        encoder.put_fixed(&self.completion_event_id)?;
        encoder.put_fixed(&self.completion_object_id)?;
        encoder.put_u64(self.projection_generation)?;
        encoder.put_u64(self.delivery_sequence)?;
        encoder.put_u64(self.coordinator_state_generation)?;
        wrap(
            TableId::RequestResult,
            COMPLETION_COVERAGE_KIND,
            encoder.finish(),
        )
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(TableId::RequestResult, COMPLETION_COVERAGE_KIND, body)?;
        let mut decoder = Decoder::new(&inner);
        expect_version(&mut decoder)?;
        let record = Self {
            request_object_id: decoder.array::<HASH_BYTES>()?,
            completion_event_id: decoder.array::<ID_BYTES>()?,
            completion_object_id: decoder.array::<HASH_BYTES>()?,
            projection_generation: decoder.u64()?,
            delivery_sequence: decoder.u64()?,
            coordinator_state_generation: decoder.u64()?,
        };
        decoder.finish()?;
        Ok(record)
    }
}

/// One durable outbox event awaiting or holding its acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxEventRecord {
    /// The event identity.
    pub event_id: [u8; ID_BYTES],
    /// The event object identity.
    pub event_object_id: [u8; HASH_BYTES],
    /// The exact canonical `FederationEvent` bytes.
    pub event_object: Vec<u8>,
    /// The coordinator state generation that produced the event.
    pub coordinator_state_generation: u64,
    /// Whether the edge acknowledged through this sequence.
    pub acknowledged: bool,
    /// For a completion event, the replay key of the completed request.
    pub completion_replay_key: Option<[u8; REPLAY_KEY_BYTES]>,
}

impl OutboxEventRecord {
    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.event_object.is_empty() || self.event_object.len() > MAX_EVENT_OBJECT_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoder = Encoder::with_capacity(
            self.event_object.len().saturating_add(160),
            MAX_PROTOCOL_BODY_BYTES,
        )?;
        encoder.put_u16(FEDERATION_BODY_VERSION)?;
        encoder.put_fixed(&self.event_id)?;
        encoder.put_fixed(&self.event_object_id)?;
        encoder.put_vector_u32(&self.event_object)?;
        encoder.put_u64(self.coordinator_state_generation)?;
        put_bool(&mut encoder, self.acknowledged)?;
        put_optional_fixed(
            &mut encoder,
            self.completion_replay_key.as_ref().map(|key| &key[..]),
        )?;
        wrap(TableId::EdgeOutbox, OUTBOX_EVENT_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(TableId::EdgeOutbox, OUTBOX_EVENT_KIND, body)?;
        let mut decoder = Decoder::new(&inner);
        expect_version(&mut decoder)?;
        let event_id = decoder.array::<ID_BYTES>()?;
        let event_object_id = decoder.array::<HASH_BYTES>()?;
        let event_object = decoder.vector_u32(MAX_EVENT_OBJECT_BYTES)?.to_vec();
        if event_object.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        let record = Self {
            event_id,
            event_object_id,
            event_object,
            coordinator_state_generation: decoder.u64()?,
            acknowledged: take_bool(&mut decoder)?,
            completion_replay_key: take_optional_fixed::<REPLAY_KEY_BYTES>(&mut decoder)?,
        };
        decoder.finish()?;
        Ok(record)
    }
}

/// One standing projection entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEntryRecord {
    /// The entry object identity.
    pub entry_object_id: [u8; HASH_BYTES],
    /// The exact canonical `FederationProjectionEntry` bytes.
    pub entry_object: Vec<u8>,
}

impl ProjectionEntryRecord {
    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.entry_object.is_empty() || self.entry_object.len() > MAX_PROJECTION_ENTRY_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoder = Encoder::with_capacity(
            self.entry_object.len().saturating_add(64),
            MAX_PROTOCOL_BODY_BYTES,
        )?;
        encoder.put_u16(FEDERATION_BODY_VERSION)?;
        encoder.put_fixed(&self.entry_object_id)?;
        encoder.put_vector_u32(&self.entry_object)?;
        wrap(
            TableId::EdgeProjection,
            PROJECTION_ENTRY_KIND,
            encoder.finish(),
        )
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(TableId::EdgeProjection, PROJECTION_ENTRY_KIND, body)?;
        let mut decoder = Decoder::new(&inner);
        expect_version(&mut decoder)?;
        let entry_object_id = decoder.array::<HASH_BYTES>()?;
        let entry_object = decoder.vector_u32(MAX_PROJECTION_ENTRY_BYTES)?.to_vec();
        decoder.finish()?;
        if entry_object.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            entry_object_id,
            entry_object,
        })
    }
}

/// The lifecycle state of one projection generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionGenerationState {
    /// Being built or verified; not readable by clients.
    Pending,
    /// The active generation.
    Active,
    /// A superseded generation awaiting bounded deletion.
    Quarantined,
}

impl ProjectionGenerationState {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Pending => 1,
            Self::Active => 2,
            Self::Quarantined => 3,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Active),
            3 => Ok(Self::Quarantined),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// The marker row that heads one projection generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionMarkerRecord {
    /// The generation state.
    pub state: ProjectionGenerationState,
    /// The coordinator state generation of the cut.
    pub state_generation: u64,
    /// The exact entry count.
    pub entry_count: u64,
    /// The checked sum of encoded entry bytes.
    pub entry_bytes: u64,
    /// The Appendix-B.7 digest.
    pub digest: [u8; HASH_BYTES],
    /// The snapshot token while a transfer is live.
    pub snapshot_token: Option<[u8; HASH_BYTES]>,
    /// The delivery cursor immediately preceding the first post-cut event.
    pub cut_cursor: Option<DeliveryCursorRecord>,
    /// The coordinator recovery epoch the generation was cut under.
    pub recovery_epoch: [u8; ID_BYTES],
}

impl ProjectionMarkerRecord {
    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(192, MAX_PROTOCOL_BODY_BYTES)?;
        encoder.put_u16(FEDERATION_BODY_VERSION)?;
        encoder.put_u16(self.state.wire_value())?;
        encoder.put_u64(self.state_generation)?;
        encoder.put_u64(self.entry_count)?;
        encoder.put_u64(self.entry_bytes)?;
        encoder.put_fixed(&self.digest)?;
        put_optional_fixed(&mut encoder, self.snapshot_token.as_ref().map(|t| &t[..]))?;
        put_cursor(&mut encoder, self.cut_cursor)?;
        encoder.put_fixed(&self.recovery_epoch)?;
        wrap(
            TableId::EdgeProjection,
            PROJECTION_MARKER_KIND,
            encoder.finish(),
        )
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(TableId::EdgeProjection, PROJECTION_MARKER_KIND, body)?;
        let mut decoder = Decoder::new(&inner);
        expect_version(&mut decoder)?;
        let record = Self {
            state: ProjectionGenerationState::from_wire(decoder.u16()?)?,
            state_generation: decoder.u64()?,
            entry_count: decoder.u64()?,
            entry_bytes: decoder.u64()?,
            digest: decoder.array::<HASH_BYTES>()?,
            snapshot_token: take_optional_fixed::<HASH_BYTES>(&mut decoder)?,
            cut_cursor: take_cursor(&mut decoder)?,
            recovery_epoch: decoder.array::<ID_BYTES>()?,
        };
        decoder.finish()?;
        Ok(record)
    }
}

/// Builds the `federation_peer` key: the peer Server ID (16 bytes).
pub fn peer_key(peer: ServerId) -> Result<StoredKey, StorageError> {
    StoredKey::new(peer.as_bytes().to_vec())
}

/// Builds the `federation_origin` key:
/// `peer || incarnation || origin || generation` (56 bytes).
pub fn origin_key(
    peer: ServerId,
    incarnation: ServerIncarnation,
    origin_id: [u8; ID_BYTES],
    generation: u64,
) -> Result<StoredKey, StorageError> {
    let mut key = Vec::with_capacity(ORIGIN_KEY_BYTES);
    key.extend_from_slice(peer.as_bytes());
    key.extend_from_slice(incarnation.as_bytes());
    key.extend_from_slice(&origin_id);
    key.extend_from_slice(&generation.to_be_bytes());
    StoredKey::new(key)
}

/// The parsed components of one origin key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginKeyParts {
    /// The owning peer.
    pub peer: ServerId,
    /// The owning incarnation.
    pub incarnation: ServerIncarnation,
    /// The origin identity.
    pub origin_id: [u8; ID_BYTES],
    /// The generation.
    pub generation: u64,
}

/// Splits one origin key.
pub fn parse_origin_key(key: &StoredKey) -> Result<OriginKeyParts, StorageError> {
    let bytes = key.as_bytes();
    if bytes.len() != ORIGIN_KEY_BYTES {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(OriginKeyParts {
        peer: ServerId::from_bytes(slice_array(bytes, 0)?),
        incarnation: ServerIncarnation::from_bytes(slice_array(bytes, 16)?),
        origin_id: slice_array(bytes, 32)?,
        generation: u64::from_be_bytes(slice_array(bytes, 48)?),
    })
}

/// Builds the `request_result` key from the complete 64-byte replay key.
pub fn request_result_key(replay_key: [u8; REPLAY_KEY_BYTES]) -> Result<StoredKey, StorageError> {
    StoredKey::new(replay_key.to_vec())
}

/// Builds the `edge_outbox` key: `target || projection_generation ||
/// delivery_sequence` (32 bytes).
pub fn outbox_key(
    target: ServerId,
    projection_generation: u64,
    delivery_sequence: u64,
) -> Result<StoredKey, StorageError> {
    let mut key = Vec::with_capacity(OUTBOX_KEY_BYTES);
    key.extend_from_slice(target.as_bytes());
    key.extend_from_slice(&projection_generation.to_be_bytes());
    key.extend_from_slice(&delivery_sequence.to_be_bytes());
    StoredKey::new(key)
}

/// The parsed components of one outbox key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxKeyParts {
    /// The target edge.
    pub target: ServerId,
    /// The projection generation.
    pub projection_generation: u64,
    /// The delivery sequence.
    pub delivery_sequence: u64,
}

/// Splits one outbox key.
pub fn parse_outbox_key(key: &StoredKey) -> Result<OutboxKeyParts, StorageError> {
    let bytes = key.as_bytes();
    if bytes.len() != OUTBOX_KEY_BYTES {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(OutboxKeyParts {
        target: ServerId::from_bytes(slice_array(bytes, 0)?),
        projection_generation: u64::from_be_bytes(slice_array(bytes, 16)?),
        delivery_sequence: u64::from_be_bytes(slice_array(bytes, 24)?),
    })
}

/// The inclusive-start, exclusive-end key pair covering outbox sequences
/// `first..=last` of one target generation.
pub fn outbox_range(
    target: ServerId,
    projection_generation: u64,
    first: u64,
    last: u64,
) -> Result<(StoredKey, StoredKey), StorageError> {
    if first > last {
        return Err(StorageError::LimitExceeded);
    }
    let start = outbox_key(target, projection_generation, first)?;
    let end = match last.checked_add(1) {
        Some(next) => outbox_key(target, projection_generation, next)?,
        None => successor_key(&outbox_key(target, projection_generation, last)?)?,
    };
    Ok((start, end))
}

/// Builds the `edge_projection` entry key:
/// `target || generation || kind || primary` (26 + primary bytes).
pub fn projection_entry_key(
    target: ServerId,
    projection_generation: u64,
    kind: u16,
    primary: &[u8],
) -> Result<StoredKey, StorageError> {
    if kind == PROJECTION_MARKER_KIND_FIELD || primary.is_empty() {
        return Err(StorageError::InvalidEncoding);
    }
    let mut key = Vec::with_capacity(PROJECTION_KEY_PREFIX_BYTES.saturating_add(primary.len()));
    key.extend_from_slice(target.as_bytes());
    key.extend_from_slice(&projection_generation.to_be_bytes());
    key.extend_from_slice(&kind.to_be_bytes());
    key.extend_from_slice(primary);
    StoredKey::new(key)
}

/// Builds the marker key that sorts first within one projection generation.
pub fn projection_marker_key(
    target: ServerId,
    projection_generation: u64,
) -> Result<StoredKey, StorageError> {
    let mut key = Vec::with_capacity(PROJECTION_KEY_PREFIX_BYTES);
    key.extend_from_slice(target.as_bytes());
    key.extend_from_slice(&projection_generation.to_be_bytes());
    key.extend_from_slice(&PROJECTION_MARKER_KIND_FIELD.to_be_bytes());
    StoredKey::new(key)
}

/// The parsed components of one projection key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionKeyParts {
    /// The target edge.
    pub target: ServerId,
    /// The projection generation.
    pub projection_generation: u64,
    /// The projection kind, or zero for the marker.
    pub kind: u16,
    /// The primary identity bytes, empty for the marker.
    pub primary: Vec<u8>,
}

/// Splits one projection key.
pub fn parse_projection_key(key: &StoredKey) -> Result<ProjectionKeyParts, StorageError> {
    let bytes = key.as_bytes();
    if bytes.len() < PROJECTION_KEY_PREFIX_BYTES {
        return Err(StorageError::InvalidEncoding);
    }
    let kind = u16::from_be_bytes(slice_array(bytes, 24)?);
    let primary = bytes
        .get(PROJECTION_KEY_PREFIX_BYTES..)
        .ok_or(StorageError::InvalidEncoding)?
        .to_vec();
    if (kind == PROJECTION_MARKER_KIND_FIELD) != primary.is_empty() {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(ProjectionKeyParts {
        target: ServerId::from_bytes(slice_array(bytes, 0)?),
        projection_generation: u64::from_be_bytes(slice_array(bytes, 16)?),
        kind,
        primary,
    })
}

/// The key pair covering the marker and every entry of one generation.
pub fn projection_range(
    target: ServerId,
    projection_generation: u64,
) -> Result<(StoredKey, StoredKey), StorageError> {
    let start = projection_marker_key(target, projection_generation)?;
    let end = match projection_generation.checked_add(1) {
        Some(next) => projection_marker_key(target, next)?,
        None => successor_key(&StoredKey::new({
            let mut key = target.as_bytes().to_vec();
            key.extend_from_slice(&[0xff; 8]);
            key.extend_from_slice(&[0xff; 2]);
            key
        })?)?,
    };
    Ok((start, end))
}

/// The smallest key strictly greater than every key with `key` as prefix.
fn successor_key(key: &StoredKey) -> Result<StoredKey, StorageError> {
    let mut bytes = key.as_bytes().to_vec();
    if bytes.len() >= MAX_STORED_KEY_BYTES {
        return Err(StorageError::LimitExceeded);
    }
    bytes.push(0xff);
    StoredKey::new(bytes)
}

fn slice_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], StorageError> {
    let end = offset.checked_add(N).ok_or(StorageError::Overflow)?;
    bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(StorageError::InvalidEncoding)
}

fn wrap(table: TableId, kind: u16, inner: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    ProtocolRecordBody::new(table, kind, 1, inner)?.encode()
}

fn unwrap(table: TableId, kind: u16, body: &[u8]) -> Result<Vec<u8>, StorageError> {
    Ok(ProtocolRecordBody::decode(table, kind, body)?
        .canonical_object()
        .to_vec())
}

fn expect_version(decoder: &mut Decoder<'_>) -> Result<(), StorageError> {
    if decoder.u16()? != FEDERATION_BODY_VERSION {
        return Err(StorageError::UnsupportedVersion);
    }
    Ok(())
}

fn put_bool(encoder: &mut Encoder, value: bool) -> Result<(), StorageError> {
    encoder.put_u16(u16::from(value))
}

fn take_bool(decoder: &mut Decoder<'_>) -> Result<bool, StorageError> {
    match decoder.u16()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn put_optional_u64(encoder: &mut Encoder, value: Option<u64>) -> Result<(), StorageError> {
    put_bool(encoder, value.is_some())?;
    encoder.put_u64(value.unwrap_or(0))
}

fn take_optional_u64(decoder: &mut Decoder<'_>) -> Result<Option<u64>, StorageError> {
    let present = take_bool(decoder)?;
    let value = decoder.u64()?;
    if !present && value != 0 {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(present.then_some(value))
}

fn put_optional_fixed(encoder: &mut Encoder, value: Option<&[u8]>) -> Result<(), StorageError> {
    encoder.put_vector_u32(value.unwrap_or(&[]))
}

fn take_optional_fixed<const N: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<Option<[u8; N]>, StorageError> {
    let bytes = decoder.vector_u32(N)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    bytes
        .try_into()
        .map(Some)
        .map_err(|_| StorageError::InvalidEncoding)
}

fn put_cursor(
    encoder: &mut Encoder,
    cursor: Option<DeliveryCursorRecord>,
) -> Result<(), StorageError> {
    put_bool(encoder, cursor.is_some())?;
    let cursor = cursor.unwrap_or(DeliveryCursorRecord {
        delivery_sequence: 0,
        event_id: [0; ID_BYTES],
    });
    encoder.put_u64(cursor.delivery_sequence)?;
    encoder.put_fixed(&cursor.event_id)
}

fn take_cursor(decoder: &mut Decoder<'_>) -> Result<Option<DeliveryCursorRecord>, StorageError> {
    let present = take_bool(decoder)?;
    let delivery_sequence = decoder.u64()?;
    let event_id = decoder.array::<ID_BYTES>()?;
    if !present && (delivery_sequence != 0 || event_id != [0; ID_BYTES]) {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(present.then_some(DeliveryCursorRecord {
        delivery_sequence,
        event_id,
    }))
}
