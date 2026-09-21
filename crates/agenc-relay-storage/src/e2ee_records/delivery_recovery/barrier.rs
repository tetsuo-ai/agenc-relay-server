//! Combined barrier endpoints and their separately committed cursor coverage.
#![forbid(unsafe_code)]

use super::{DeliveryOwner, DeliveryScope, LastAcknowledged};
use crate::StorageError;
use crate::codec::{Decoder, Encoder};
use crate::e2ee_records::barrier::{MAX_PART_COUNT, MIN_PART_COUNT};

/// One stream's contiguous nonempty slice of a combined barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierEndpoint {
    generation: u64,
    first: u64,
    last: u64,
    final_event_id: [u8; 16],
}

impl BarrierEndpoint {
    /// Refuses an empty, overflowing, or oversized endpoint range.
    pub fn new(
        generation: u64,
        first: u64,
        last: u64,
        final_event_id: [u8; 16],
    ) -> Result<Self, StorageError> {
        let count = last
            .checked_sub(first)
            .and_then(|count| count.checked_add(1))
            .ok_or(StorageError::InvalidEncoding)?;
        if count > u64::from(MAX_PART_COUNT) {
            return Err(StorageError::LimitExceeded);
        }
        Ok(Self {
            generation,
            first,
            last,
            final_event_id,
        })
    }

    /// Returns the exact stream generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Returns the first delivery sequence of the barrier slice.
    #[must_use]
    pub const fn first(&self) -> u64 {
        self.first
    }
    /// Returns the final delivery sequence acknowledged atomically.
    #[must_use]
    pub const fn last(&self) -> u64 {
        self.last
    }
    /// Returns the final event identity carried by the cumulative ACK.
    #[must_use]
    pub const fn final_event_id(&self) -> [u8; 16] {
        self.final_event_id
    }

    fn count(&self) -> Result<u64, StorageError> {
        self.last
            .checked_sub(self.first)
            .and_then(|value| value.checked_add(1))
            .ok_or(StorageError::Overflow)
    }

    fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_u64(self.generation)?;
        encoder.put_u64(self.first)?;
        encoder.put_u64(self.last)?;
        encoder.put_fixed(&self.final_event_id)
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(
            decoder.u64()?,
            decoder.u64()?,
            decoder.u64()?,
            decoder.array()?,
        )
    }
}

/// Exact combined-barrier construction facts, before validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryBarrierFields {
    /// Historical accepted delivery scope.
    pub scope: DeliveryScope,
    /// Shared mutation identity.
    pub mutation_id: [u8; 16],
    /// Nonzero coordinator state generation of the mutation.
    pub state_generation: u64,
    /// Complete number of base and companion parts.
    pub part_count: u16,
    /// Base stream endpoint.
    pub base: BarrierEndpoint,
    /// Companion stream endpoint.
    pub companion: BarrierEndpoint,
    /// Whether the base endpoint's exact cursor coverage is committed.
    pub base_acked: bool,
    /// Whether the companion endpoint's exact cursor coverage is committed.
    pub companion_acked: bool,
}

/// Durable combined barrier gate, which has no time-based expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryBarrier {
    fields: DeliveryBarrierFields,
}

impl DeliveryBarrier {
    /// Validates the complete nonempty part split and state generation.
    pub fn new(fields: DeliveryBarrierFields) -> Result<Self, StorageError> {
        if fields.state_generation == 0
            || !(MIN_PART_COUNT..=MAX_PART_COUNT).contains(&fields.part_count)
        {
            return Err(StorageError::InvalidEncoding);
        }
        let count = fields
            .base
            .count()?
            .checked_add(fields.companion.count()?)
            .ok_or(StorageError::Overflow)?;
        if count != u64::from(fields.part_count) {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self { fields })
    }

    /// Returns the full accepted historical scope.
    #[must_use]
    pub const fn scope(&self) -> &DeliveryScope {
        &self.fields.scope
    }
    /// Returns the shared mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> [u8; 16] {
        self.fields.mutation_id
    }
    /// Returns the exact nonzero coordinator state generation.
    #[must_use]
    pub const fn state_generation(&self) -> u64 {
        self.fields.state_generation
    }
    /// Returns the complete part count.
    #[must_use]
    pub const fn part_count(&self) -> u16 {
        self.fields.part_count
    }
    /// Returns the base stream's endpoint.
    #[must_use]
    pub const fn base(&self) -> &BarrierEndpoint {
        &self.fields.base
    }
    /// Returns the companion stream's endpoint.
    #[must_use]
    pub const fn companion(&self) -> &BarrierEndpoint {
        &self.fields.companion
    }
    /// Returns the independently committed base coverage flag.
    #[must_use]
    pub const fn base_acked(&self) -> bool {
        self.fields.base_acked
    }
    /// Returns the independently committed companion coverage flag.
    #[must_use]
    pub const fn companion_acked(&self) -> bool {
        self.fields.companion_acked
    }

    /// Binds this gate to the exact owner and companion cursor coverage.
    /// Base cursor coverage and complete event/payload sets remain runtime checks.
    pub fn validate_for(
        &self,
        owner: &DeliveryOwner,
        base_generation: u64,
    ) -> Result<(), StorageError> {
        if self.scope() != owner.scope()
            || self.base().generation() != base_generation
            || self.companion().generation() != owner.cursor().generation()
            || self.companion().last() >= owner.cursor().next_sequence()
        {
            return Err(StorageError::StaleState);
        }
        let covered = self.companion_coverage(owner.cursor().last_ack())?;
        if covered != self.companion_acked() {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    fn companion_coverage(&self, ack: LastAcknowledged) -> Result<bool, StorageError> {
        let LastAcknowledged::At { sequence, event_id } = ack else {
            return Ok(false);
        };
        let endpoint = self.companion();
        if sequence >= endpoint.first() && sequence < endpoint.last() {
            return Err(StorageError::StaleState);
        }
        if sequence == endpoint.last() && event_id != endpoint.final_event_id() {
            return Err(StorageError::StaleState);
        }
        Ok(sequence >= endpoint.last())
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        self.fields.scope.put(encoder)?;
        encoder.put_fixed(&self.fields.mutation_id)?;
        encoder.put_u64(self.fields.state_generation)?;
        encoder.put_u16(self.fields.part_count)?;
        self.fields.base.put(encoder)?;
        self.fields.companion.put(encoder)?;
        encoder.put_u16(u16::from(self.fields.base_acked))?;
        encoder.put_u16(u16::from(self.fields.companion_acked))
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(DeliveryBarrierFields {
            scope: DeliveryScope::take(decoder)?,
            mutation_id: decoder.array()?,
            state_generation: decoder.u64()?,
            part_count: decoder.u16()?,
            base: BarrierEndpoint::take(decoder)?,
            companion: BarrierEndpoint::take(decoder)?,
            base_acked: boolean(decoder.u16()?)?,
            companion_acked: boolean(decoder.u16()?)?,
        })
    }
}

fn boolean(value: u16) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::InvalidEncoding),
    }
}
