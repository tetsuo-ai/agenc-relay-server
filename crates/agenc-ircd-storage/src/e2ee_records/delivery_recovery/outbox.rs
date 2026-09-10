//! Complete delivery scope and durable replay-retention facts for one event.
#![forbid(unsafe_code)]

use super::DeliveryScope;
use crate::codec::{Decoder, Encoder};
use crate::e2ee_records::CrossProfileTuple;
use crate::e2ee_records::barrier::{MAX_PART_COUNT, MIN_PART_COUNT};
use crate::{ReadPlan, StorageError, StoredKey};

mod acknowledgement;
pub mod replay;
#[cfg(test)]
mod tests;

pub use acknowledgement::Acknowledgement;

/// Exact scoped outbox prefix.
pub const OUTBOX_PREFIX: &[u8] = b"delivery-outbox/v1/";
/// Maximum complete event envelope bytes.
pub const MAX_EVENT_BYTES: u32 = 65_536;
/// Maximum complete payload envelope bytes for the largest event selector.
pub const MAX_PAYLOAD_BYTES: u32 = 4_194_304;
/// Maximum inner arm size, including version and arm tag.
pub const MAX_OUTBOX_BODY_BYTES: usize = 270;
const SCOPE_BYTES: usize = 120;
const KEY_SUFFIX_BYTES: usize = SCOPE_BYTES + 16;

/// Construction facts; validation does not grant stream authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedOutboxFields {
    /// Full historical owner scope.
    pub scope: DeliveryScope,
    /// Delivery generation; zero is valid in a new incarnation.
    pub generation: u64,
    /// Assigned sequence within the generation.
    pub sequence: u64,
    /// Exact opaque event identity.
    pub event_id: [u8; 16],
    /// Digest of the complete event envelope.
    pub event_object_id: [u8; 32],
    /// Complete event envelope length.
    pub event_bytes: u32,
    /// Optional required payload digest.
    pub payload_object_id: Option<[u8; 32]>,
    /// Complete payload envelope length, zero only when absent.
    pub payload_bytes: u32,
    /// Durable acknowledgement and original retention-time facts.
    pub acknowledgement: Acknowledgement,
    /// Exact cross-profile membership when this is a barrier part.
    pub cross_profile: Option<CrossProfileTuple>,
}

/// One scoped outbox reference, with no inferred identity or ACK timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedOutbox {
    fields: ScopedOutboxFields,
}

impl ScopedOutbox {
    /// Validates lengths, acknowledgement facts, and optional part membership.
    pub fn new(fields: ScopedOutboxFields) -> Result<Self, StorageError> {
        if !(1..=MAX_EVENT_BYTES).contains(&fields.event_bytes) {
            return Err(StorageError::InvalidEncoding);
        }
        let payload_valid = match fields.payload_object_id {
            None => fields.payload_bytes == 0,
            Some(_) => (1..=MAX_PAYLOAD_BYTES).contains(&fields.payload_bytes),
        };
        if !payload_valid {
            return Err(StorageError::InvalidEncoding);
        }
        validate_tuple(fields.cross_profile)?;
        fields.acknowledgement.validate()?;
        Ok(Self { fields })
    }

    /// Returns the full historical scope.
    #[must_use]
    pub const fn scope(&self) -> &DeliveryScope {
        &self.fields.scope
    }
    /// Returns the exact generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.fields.generation
    }
    /// Returns the exact assigned sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.fields.sequence
    }
    /// Returns the event identity.
    #[must_use]
    pub const fn event_id(&self) -> [u8; 16] {
        self.fields.event_id
    }
    /// Returns the complete event digest.
    #[must_use]
    pub const fn event_object_id(&self) -> [u8; 32] {
        self.fields.event_object_id
    }
    /// Returns the complete event length.
    #[must_use]
    pub const fn event_bytes(&self) -> u32 {
        self.fields.event_bytes
    }
    /// Returns the optional payload digest.
    #[must_use]
    pub const fn payload_object_id(&self) -> Option<[u8; 32]> {
        self.fields.payload_object_id
    }
    /// Returns the complete payload length.
    #[must_use]
    pub const fn payload_bytes(&self) -> u32 {
        self.fields.payload_bytes
    }
    /// Returns the original durable ACK facts.
    #[must_use]
    pub const fn acknowledgement(&self) -> Acknowledgement {
        self.fields.acknowledgement
    }
    /// Returns the exact optional combined-barrier membership.
    #[must_use]
    pub const fn cross_profile(&self) -> Option<CrossProfileTuple> {
        self.fields.cross_profile
    }

    /// Replaces ACK facts while preserving every scope and object field.
    pub fn with_acknowledgement(
        self,
        acknowledgement: Acknowledgement,
    ) -> Result<Self, StorageError> {
        Self::new(ScopedOutboxFields {
            acknowledgement,
            ..self.fields
        })
    }

    /// Returns the exact full-scope key repeated by this body.
    pub fn key(&self) -> Result<StoredKey, StorageError> {
        outbox_key(self.scope(), self.generation(), self.sequence())
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        self.scope().put(encoder)?;
        encoder.put_u64(self.generation())?;
        encoder.put_u64(self.sequence())?;
        encoder.put_fixed(&self.event_id())?;
        encoder.put_fixed(&self.event_object_id())?;
        encoder.put_u32(self.event_bytes())?;
        encoder.put_u16(u16::from(self.payload_object_id().is_some()))?;
        if let Some(id) = self.payload_object_id() {
            encoder.put_fixed(&id)?;
        }
        encoder.put_u32(self.payload_bytes())?;
        self.acknowledgement().put(encoder)?;
        encoder.put_u16(u16::from(self.cross_profile().is_some()))?;
        if let Some(tuple) = self.cross_profile() {
            encoder.put_fixed(&tuple.mutation_id)?;
            encoder.put_u16(tuple.part_index)?;
            encoder.put_u16(tuple.part_count)?;
        }
        Ok(())
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let scope = DeliveryScope::take(decoder)?;
        let generation = decoder.u64()?;
        let sequence = decoder.u64()?;
        let event_id = decoder.array()?;
        let event_object_id = decoder.array()?;
        let event_bytes = decoder.u32()?;
        let payload_object_id = match decoder.u16()? {
            0 => None,
            1 => Some(decoder.array()?),
            _ => return Err(StorageError::InvalidEncoding),
        };
        Self::new(ScopedOutboxFields {
            scope,
            generation,
            sequence,
            event_id,
            event_object_id,
            event_bytes,
            payload_object_id,
            payload_bytes: decoder.u32()?,
            acknowledgement: Acknowledgement::take(decoder)?,
            cross_profile: take_tuple(decoder)?,
        })
    }
}

/// Builds one exact scope, generation, and sequence key.
pub fn outbox_key(
    scope: &DeliveryScope,
    generation: u64,
    sequence: u64,
) -> Result<StoredKey, StorageError> {
    let scope = scope_bytes(scope)?;
    super::key_of(&[
        OUTBOX_PREFIX,
        &scope,
        &generation.to_be_bytes(),
        &sequence.to_be_bytes(),
    ])
}

/// Parses every field and rejects shortened or extended keys.
pub fn parse_outbox_key(key: &StoredKey) -> Result<(DeliveryScope, u64, u64), StorageError> {
    let rest = super::suffix(key, OUTBOX_PREFIX, KEY_SUFFIX_BYTES)?;
    let mut decoder = Decoder::new(rest);
    let scope = DeliveryScope::take(&mut decoder)?;
    let generation = decoder.u64()?;
    let sequence = decoder.u64()?;
    decoder.finish()?;
    Ok((scope, generation, sequence))
}

/// Reads only a bounded range of one exact historical scope and generation.
pub fn outbox_from(
    scope: &DeliveryScope,
    generation: u64,
    first_sequence: u64,
    limit: u16,
) -> Result<ReadPlan, StorageError> {
    let bytes = scope_bytes(scope)?;
    let prefix = super::key_of(&[OUTBOX_PREFIX, &bytes, &generation.to_be_bytes()])?;
    super::prefix_range_from(
        prefix.as_bytes(),
        &outbox_key(scope, generation, first_sequence)?,
        limit,
    )
}

fn scope_bytes(scope: &DeliveryScope) -> Result<Vec<u8>, StorageError> {
    let mut encoder = Encoder::with_capacity(SCOPE_BYTES, SCOPE_BYTES)?;
    scope.put(&mut encoder)?;
    Ok(encoder.finish())
}

fn validate_tuple(tuple: Option<CrossProfileTuple>) -> Result<(), StorageError> {
    if tuple.is_some_and(|tuple| {
        !(MIN_PART_COUNT..=MAX_PART_COUNT).contains(&tuple.part_count)
            || tuple.part_index >= tuple.part_count
    }) {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(())
}

fn take_tuple(decoder: &mut Decoder<'_>) -> Result<Option<CrossProfileTuple>, StorageError> {
    match decoder.u16()? {
        0 => Ok(None),
        1 => Ok(Some(CrossProfileTuple {
            mutation_id: decoder.array()?,
            part_index: decoder.u16()?,
            part_count: decoder.u16()?,
        })),
        _ => Err(StorageError::InvalidEncoding),
    }
}
