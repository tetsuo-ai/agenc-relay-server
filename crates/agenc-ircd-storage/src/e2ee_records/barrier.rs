//! Cross-profile barrier rows (spec 20.8) with the exact Appendix B.1
//! encodings of `CrossProfileBarrierStage`, `CrossProfileBarrierPart`, and
//! `CrossProfileBarrierReceipt`, stored as record kind 12 of table 23.
//!
//! A head row holds either a collecting stage or an applied receipt; the
//! two are told apart by a leading `uint16` arm in the stored body, which
//! is a storage detail outside the Appendix B structure bytes.

use crate::codec::{Decoder, Encoder};
use crate::e2ee_records::{
    BARRIER_ROW_KIND, HASH_BYTES, ID_BYTES, key_of, prefix, slice_array, suffix,
};
use crate::records::ProtocolRecordBody;
use crate::schema::{StoredKey, TableId};
use crate::{MAX_PROTOCOL_BODY_BYTES, StorageError};

/// `barrier_storage_version`.
pub const BARRIER_STORAGE_VERSION: u16 = 1;
/// The smallest legal part count.
pub const MIN_PART_COUNT: u16 = 2;
/// The largest legal part count.
pub const MAX_PART_COUNT: u16 = 2_048;
/// The largest encoded event object (the base `FederationEvent` bound).
pub const MAX_ENCODED_EVENT_BYTES: usize = 262_344;
/// The largest companion payload.
pub const MAX_PAYLOAD_BYTES: u32 = 4_194_304;
/// The barrier retention window, seconds.
pub const BARRIER_RETENTION_SECONDS: u64 = 604_800;
/// The head key length.
pub const HEAD_KEY_BYTES: usize = 70;
/// The part key length.
pub const PART_KEY_BYTES: usize = 72;
const MAX_BITMAP_BYTES: usize = 256;
const STAGE_ARM: u16 = 1;
const RECEIPT_ARM: u16 = 2;

/// `CrossProfileStream`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CrossProfileStream {
    /// `cross_profile_base(1)`.
    Base,
    /// `cross_profile_companion(2)`.
    Companion,
}

impl CrossProfileStream {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Base => 1,
            Self::Companion => 2,
        }
    }

    const fn from_wire(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::Base),
            2 => Ok(Self::Companion),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// `CrossProfileBarrierIdentity`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierIdentity {
    /// Network identity.
    pub network_id: [u8; HASH_BYTES],
    /// Coordinator server.
    pub coordinator_server_id: [u8; ID_BYTES],
    /// Coordinator incarnation.
    pub coordinator_server_incarnation: [u8; ID_BYTES],
    /// Coordinator recovery epoch.
    pub coordinator_recovery_epoch: [u8; ID_BYTES],
    /// Target server.
    pub target_server_id: [u8; ID_BYTES],
    /// Target incarnation.
    pub target_server_incarnation: [u8; ID_BYTES],
    /// Mutation identifier.
    pub mutation_id: [u8; ID_BYTES],
    /// Coordinator state generation.
    pub coordinator_state_generation: u64,
    /// Part count.
    pub part_count: u16,
}

impl BarrierIdentity {
    fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        if !(MIN_PART_COUNT..=MAX_PART_COUNT).contains(&self.part_count) {
            return Err(StorageError::InvalidEncoding);
        }
        encoder.put_u16(BARRIER_STORAGE_VERSION)?;
        encoder.put_fixed(&self.network_id)?;
        encoder.put_fixed(&self.coordinator_server_id)?;
        encoder.put_fixed(&self.coordinator_server_incarnation)?;
        encoder.put_fixed(&self.coordinator_recovery_epoch)?;
        encoder.put_fixed(&self.target_server_id)?;
        encoder.put_fixed(&self.target_server_incarnation)?;
        encoder.put_fixed(&self.mutation_id)?;
        encoder.put_u64(self.coordinator_state_generation)?;
        encoder.put_u16(self.part_count)
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        if decoder.u16()? != BARRIER_STORAGE_VERSION {
            return Err(StorageError::UnsupportedVersion);
        }
        let identity = Self {
            network_id: decoder.array()?,
            coordinator_server_id: decoder.array()?,
            coordinator_server_incarnation: decoder.array()?,
            coordinator_recovery_epoch: decoder.array()?,
            target_server_id: decoder.array()?,
            target_server_incarnation: decoder.array()?,
            mutation_id: decoder.array()?,
            coordinator_state_generation: decoder.u64()?,
            part_count: decoder.u16()?,
        };
        if !(MIN_PART_COUNT..=MAX_PART_COUNT).contains(&identity.part_count) {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(identity)
    }

    /// The 70-byte head key.
    pub fn head_key(&self) -> Result<StoredKey, StorageError> {
        key_of(&[
            prefix::BARRIER_HEAD,
            &self.coordinator_server_id,
            &self.coordinator_server_incarnation,
            &self.mutation_id,
        ])
    }

    /// The 72-byte part key.
    pub fn part_key(&self, part_index: u16) -> Result<StoredKey, StorageError> {
        if part_index >= self.part_count {
            return Err(StorageError::InvalidEncoding);
        }
        key_of(&[
            prefix::BARRIER_PART,
            &self.coordinator_server_id,
            &self.coordinator_server_incarnation,
            &self.mutation_id,
            &part_index.to_be_bytes(),
        ])
    }

    /// The bitmap length for this part count.
    #[must_use]
    pub fn bitmap_bytes(&self) -> usize {
        usize::from(self.part_count).div_ceil(8)
    }
}

/// The parsed components of a head or part key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierKeyParts {
    /// Coordinator server.
    pub coordinator_server_id: [u8; ID_BYTES],
    /// Coordinator incarnation.
    pub coordinator_server_incarnation: [u8; ID_BYTES],
    /// Mutation identifier.
    pub mutation_id: [u8; ID_BYTES],
    /// Part index, absent for a head key.
    pub part_index: Option<u16>,
}

/// Splits a head or part key.
pub fn parse_key(key: &StoredKey) -> Result<BarrierKeyParts, StorageError> {
    let bytes = key.as_bytes();
    let (rest, part_index) = if bytes.starts_with(prefix::BARRIER_HEAD) {
        (suffix(key, prefix::BARRIER_HEAD, 3 * ID_BYTES)?, None)
    } else {
        let rest = suffix(key, prefix::BARRIER_PART, 3 * ID_BYTES + 2)?;
        (
            rest,
            Some(u16::from_be_bytes(slice_array(rest, 3 * ID_BYTES)?)),
        )
    };
    Ok(BarrierKeyParts {
        coordinator_server_id: slice_array(rest, 0)?,
        coordinator_server_incarnation: slice_array(rest, ID_BYTES)?,
        mutation_id: slice_array(rest, 2 * ID_BYTES)?,
        part_index,
    })
}

/// `CrossProfileBarrierStage`: the collecting head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BarrierStage {
    /// Identity.
    pub identity: BarrierIdentity,
    /// The received bitmap, exactly `ceil(part_count / 8)` bytes.
    pub received_bitmap: Vec<u8>,
    /// Checked sum of received event and payload bytes.
    pub aggregate_event_payload_bytes: u64,
}

impl BarrierStage {
    /// An empty stage for `identity`.
    pub fn empty(identity: BarrierIdentity) -> Self {
        Self {
            received_bitmap: vec![0; identity.bitmap_bytes()],
            identity,
            aggregate_event_payload_bytes: 0,
        }
    }

    /// Whether part `index` is received.
    #[must_use]
    pub fn is_received(&self, index: u16) -> bool {
        self.received_bitmap
            .get(usize::from(index / 8))
            .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
    }

    /// Marks part `index` received, adding its bytes to the aggregate.
    pub fn mark_received(&mut self, index: u16, bytes: u64) -> Result<(), StorageError> {
        if index >= self.identity.part_count || self.is_received(index) {
            return Err(StorageError::InvalidEncoding);
        }
        let byte = self
            .received_bitmap
            .get_mut(usize::from(index / 8))
            .ok_or(StorageError::InvalidEncoding)?;
        *byte |= 1 << (index % 8);
        self.aggregate_event_payload_bytes = self
            .aggregate_event_payload_bytes
            .checked_add(bytes)
            .ok_or(StorageError::Overflow)?;
        Ok(())
    }

    /// The population count of the bitmap.
    #[must_use]
    pub fn received_count(&self) -> u16 {
        let count: u32 = self
            .received_bitmap
            .iter()
            .map(|byte| byte.count_ones())
            .sum();
        u16::try_from(count).unwrap_or(u16::MAX)
    }

    /// Whether every part is present.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received_count() == self.identity.part_count
    }

    fn check_bitmap(&self) -> Result<(), StorageError> {
        let expected = self.identity.bitmap_bytes();
        if self.received_bitmap.len() != expected {
            return Err(StorageError::InvalidEncoding);
        }
        let unused = expected * 8 - usize::from(self.identity.part_count);
        let last = self.received_bitmap.last().copied().unwrap_or(0);
        if unused > 0 && last >> (8 - unused) != 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        self.check_bitmap()?;
        self.identity.put(encoder)?;
        encoder.put_u16(self.received_count())?;
        encoder.put_u16(
            u16::try_from(self.received_bitmap.len()).map_err(|_| StorageError::Overflow)?,
        )?;
        encoder.put_fixed(&self.received_bitmap)?;
        encoder.put_u64(self.aggregate_event_payload_bytes)
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let identity = BarrierIdentity::take(decoder)?;
        let received_count = decoder.u16()?;
        let length = usize::from(decoder.u16()?);
        if length == 0 || length > MAX_BITMAP_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let stage = Self {
            identity,
            received_bitmap: decoder.take(length)?.to_vec(),
            aggregate_event_payload_bytes: decoder.u64()?,
        };
        stage.check_bitmap()?;
        if stage.received_count() != received_count {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(stage)
    }

    /// Encodes the wrapped head body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(512, MAX_PROTOCOL_BODY_BYTES)?;
        encoder.put_u16(STAGE_ARM)?;
        self.put(&mut encoder)?;
        wrap(encoder.finish())
    }
}

/// `CrossProfileBarrierPart`: one immutable staged event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BarrierPart {
    /// Identity.
    pub identity: BarrierIdentity,
    /// Stream.
    pub stream: CrossProfileStream,
    /// Part index.
    pub part_index: u16,
    /// Delivery generation on that stream.
    pub delivery_generation: u64,
    /// Delivery sequence on that stream.
    pub delivery_sequence: u64,
    /// Event identity.
    pub event_id: [u8; ID_BYTES],
    /// Event object identifier.
    pub event_object_id: [u8; HASH_BYTES],
    /// The complete encoded event object.
    pub encoded_event_object: Vec<u8>,
    /// The payload object identifier, empty without a payload.
    pub payload_object_id: Option<[u8; HASH_BYTES]>,
    /// Payload bytes, zero without a payload.
    pub payload_object_bytes: u32,
}

impl BarrierPart {
    fn check(&self) -> Result<(), StorageError> {
        let event_ok = !self.encoded_event_object.is_empty()
            && self.encoded_event_object.len() <= MAX_ENCODED_EVENT_BYTES;
        let payload_ok = match (self.payload_object_id, self.payload_object_bytes) {
            (None, 0) => true,
            (Some(_), bytes) => (1..=MAX_PAYLOAD_BYTES).contains(&bytes),
            (None, _) => false,
        };
        let base_ok =
            self.stream == CrossProfileStream::Companion || self.payload_object_id.is_none();
        if event_ok && payload_ok && base_ok && self.part_index < self.identity.part_count {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }

    /// The staged bytes this part contributes to the aggregate.
    pub fn contributed_bytes(&self) -> Result<u64, StorageError> {
        u64::try_from(self.encoded_event_object.len())
            .ok()
            .and_then(|event| event.checked_add(u64::from(self.payload_object_bytes)))
            .ok_or(StorageError::Overflow)
    }

    /// Encodes the wrapped part body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.check()?;
        let mut encoder = Encoder::with_capacity(1_024, MAX_PROTOCOL_BODY_BYTES)?;
        self.identity.put(&mut encoder)?;
        encoder.put_u16(self.stream.wire_value())?;
        encoder.put_u16(self.part_index)?;
        encoder.put_u64(self.delivery_generation)?;
        encoder.put_u64(self.delivery_sequence)?;
        encoder.put_fixed(&self.event_id)?;
        encoder.put_fixed(&self.event_object_id)?;
        encoder.put_vector_u32(&self.encoded_event_object)?;
        put_payload_id(&mut encoder, self.payload_object_id.as_ref())?;
        encoder.put_u32(self.payload_object_bytes)?;
        wrap(encoder.finish())
    }

    /// Decodes one wrapped part body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(body)?;
        let mut decoder = Decoder::new(&inner);
        let part = Self {
            identity: BarrierIdentity::take(&mut decoder)?,
            stream: CrossProfileStream::from_wire(decoder.u16()?)?,
            part_index: decoder.u16()?,
            delivery_generation: decoder.u64()?,
            delivery_sequence: decoder.u64()?,
            event_id: decoder.array()?,
            event_object_id: decoder.array()?,
            encoded_event_object: decoder.vector_u32(MAX_ENCODED_EVENT_BYTES)?.to_vec(),
            payload_object_id: take_payload_id(&mut decoder)?,
            payload_object_bytes: decoder.u32()?,
        };
        decoder.finish()?;
        part.check()?;
        Ok(part)
    }

    /// The receipt entry describing this part.
    #[must_use]
    pub fn receipt_entry(&self) -> BarrierReceiptEntry {
        BarrierReceiptEntry {
            stream: self.stream,
            part_index: self.part_index,
            delivery_generation: self.delivery_generation,
            delivery_sequence: self.delivery_sequence,
            event_id: self.event_id,
            event_object_id: self.event_object_id,
            payload_object_id: self.payload_object_id,
        }
    }
}

/// `CrossProfileBarrierReceiptEntry`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierReceiptEntry {
    /// Stream.
    pub stream: CrossProfileStream,
    /// Part index.
    pub part_index: u16,
    /// Delivery generation.
    pub delivery_generation: u64,
    /// Delivery sequence.
    pub delivery_sequence: u64,
    /// Event identity.
    pub event_id: [u8; ID_BYTES],
    /// Event object identifier.
    pub event_object_id: [u8; HASH_BYTES],
    /// Payload object identifier.
    pub payload_object_id: Option<[u8; HASH_BYTES]>,
}

impl BarrierReceiptEntry {
    fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_u16(self.stream.wire_value())?;
        encoder.put_u16(self.part_index)?;
        encoder.put_u64(self.delivery_generation)?;
        encoder.put_u64(self.delivery_sequence)?;
        encoder.put_fixed(&self.event_id)?;
        encoder.put_fixed(&self.event_object_id)?;
        put_payload_id(encoder, self.payload_object_id.as_ref())
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Ok(Self {
            stream: CrossProfileStream::from_wire(decoder.u16()?)?,
            part_index: decoder.u16()?,
            delivery_generation: decoder.u64()?,
            delivery_sequence: decoder.u64()?,
            event_id: decoder.array()?,
            event_object_id: decoder.array()?,
            payload_object_id: take_payload_id(decoder)?,
        })
    }
}

/// `CrossProfileBarrierReceipt`: the applied head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BarrierReceipt {
    /// Identity.
    pub identity: BarrierIdentity,
    /// The storage commit sequence of the apply transaction.
    pub applied_storage_commit_sequence: u64,
    /// The local state generation written by the apply transaction.
    pub applied_local_state_generation: u64,
    /// Apply second.
    pub applied_at: u64,
    /// `applied_at + 604800`.
    pub retain_until: u64,
    /// The complete aggregate.
    pub aggregate_event_payload_bytes: u64,
    /// Entries covering exactly `0..part_count`.
    pub entries: Vec<BarrierReceiptEntry>,
}

impl BarrierReceipt {
    fn check(&self) -> Result<(), StorageError> {
        let count = usize::from(self.identity.part_count);
        let indices_ok = self.entries.len() == count
            && self
                .entries
                .iter()
                .enumerate()
                .all(|(index, entry)| usize::from(entry.part_index) == index);
        let retention_ok = self
            .applied_at
            .checked_add(BARRIER_RETENTION_SECONDS)
            .is_some_and(|until| until == self.retain_until);
        if indices_ok && retention_ok {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }

    /// Encodes the wrapped head body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.check()?;
        let mut encoder = Encoder::with_capacity(4_096, MAX_PROTOCOL_BODY_BYTES)?;
        encoder.put_u16(RECEIPT_ARM)?;
        self.identity.put(&mut encoder)?;
        encoder.put_u64(self.applied_storage_commit_sequence)?;
        encoder.put_u64(self.applied_local_state_generation)?;
        encoder.put_u64(self.applied_at)?;
        encoder.put_u64(self.retain_until)?;
        encoder.put_u64(self.aggregate_event_payload_bytes)?;
        encoder.put_u16(u16::try_from(self.entries.len()).map_err(|_| StorageError::Overflow)?)?;
        for entry in &self.entries {
            entry.put(&mut encoder)?;
        }
        wrap(encoder.finish())
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let identity = BarrierIdentity::take(decoder)?;
        let applied_storage_commit_sequence = decoder.u64()?;
        let applied_local_state_generation = decoder.u64()?;
        let applied_at = decoder.u64()?;
        let retain_until = decoder.u64()?;
        let aggregate_event_payload_bytes = decoder.u64()?;
        let count = decoder.u16()?;
        if !(MIN_PART_COUNT..=MAX_PART_COUNT).contains(&count) {
            return Err(StorageError::InvalidEncoding);
        }
        let mut entries = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            entries.push(BarrierReceiptEntry::take(decoder)?);
        }
        let receipt = Self {
            identity,
            applied_storage_commit_sequence,
            applied_local_state_generation,
            applied_at,
            retain_until,
            aggregate_event_payload_bytes,
            entries,
        };
        receipt.check()?;
        Ok(receipt)
    }
}

/// The head row: a collecting stage or an applied receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BarrierHead {
    /// Collecting.
    Stage(BarrierStage),
    /// Applied.
    Receipt(BarrierReceipt),
}

impl BarrierHead {
    /// Encodes the wrapped head body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        match self {
            Self::Stage(stage) => stage.encode(),
            Self::Receipt(receipt) => receipt.encode(),
        }
    }

    /// Decodes one wrapped head body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(body)?;
        let mut decoder = Decoder::new(&inner);
        let head = match decoder.u16()? {
            STAGE_ARM => Self::Stage(BarrierStage::take(&mut decoder)?),
            RECEIPT_ARM => Self::Receipt(BarrierReceipt::take(&mut decoder)?),
            _ => return Err(StorageError::InvalidEncoding),
        };
        decoder.finish()?;
        Ok(head)
    }

    /// The identity.
    #[must_use]
    pub const fn identity(&self) -> &BarrierIdentity {
        match self {
            Self::Stage(stage) => &stage.identity,
            Self::Receipt(receipt) => &receipt.identity,
        }
    }
}

/// Decodes a kind-12 body as a head or, failing that, as a part.
pub fn validate_body(body: &[u8]) -> Result<(), StorageError> {
    if BarrierHead::decode(body).is_ok() {
        return Ok(());
    }
    BarrierPart::decode(body).map(|_| ())
}

fn put_payload_id(
    encoder: &mut Encoder,
    id: Option<&[u8; HASH_BYTES]>,
) -> Result<(), StorageError> {
    // `opaque payload_object_id<0..32>` carries a one-byte length.
    match id {
        Some(id) => {
            encoder.put_fixed(&[HASH_BYTES as u8])?;
            encoder.put_fixed(id)
        }
        None => encoder.put_fixed(&[0]),
    }
}

fn take_payload_id(decoder: &mut Decoder<'_>) -> Result<Option<[u8; HASH_BYTES]>, StorageError> {
    match decoder.array::<1>()? {
        [0] => Ok(None),
        [32] => decoder.array::<HASH_BYTES>().map(Some),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn wrap(inner: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    ProtocolRecordBody::new(TableId::E2eeState, BARRIER_ROW_KIND, 1, inner)?.encode()
}

fn unwrap(body: &[u8]) -> Result<Vec<u8>, StorageError> {
    Ok(
        ProtocolRecordBody::decode(TableId::E2eeState, BARRIER_ROW_KIND, body)?
            .canonical_object()
            .to_vec(),
    )
}
