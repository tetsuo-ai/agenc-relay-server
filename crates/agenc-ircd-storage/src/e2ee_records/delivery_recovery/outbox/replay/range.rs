//! One receipt records a complete interval without rewriting every event row.
#![forbid(unsafe_code)]

use super::{Decoder, DeliveryScope, Encoder, StorageError};
use crate::e2ee_records::delivery_recovery::Acknowledgement;
use agenc_ircd_e2ee::limits::MAX_UNACKED_E2EE_EVENTS_PER_EDGE;

/// Facts of one newly acknowledged contiguous interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRangeFields {
    /// Complete historical owner scope.
    pub scope: DeliveryScope,
    /// Exact delivery generation.
    pub generation: u64,
    /// First newly acknowledged sequence.
    pub first: u64,
    /// Final newly acknowledged sequence.
    pub last: u64,
    /// Exact final event identity, including an ordinary all-zero ID.
    pub event_id: [u8; 16],
    /// Original accepted ACK time or explicit uncertainty.
    pub acknowledgement: Acknowledgement,
}

/// A range must still be contiguous with its owner and match every covered row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRange {
    fields: AckRangeFields,
}

impl AckRange {
    /// Rejects reversed, unassigned, oversized, and unacknowledged intervals.
    pub fn new(fields: AckRangeFields) -> Result<Self, StorageError> {
        let count = fields
            .last
            .checked_sub(fields.first)
            .and_then(|n| n.checked_add(1))
            .ok_or(StorageError::InvalidEncoding)?;
        if count > MAX_UNACKED_E2EE_EVENTS_PER_EDGE
            || fields.last == u64::MAX
            || !fields.acknowledgement.is_acknowledged()
        {
            return Err(StorageError::InvalidEncoding);
        }
        fields.acknowledgement.validate()?;
        Ok(Self { fields })
    }
    /// Returns the validated range facts.
    #[must_use]
    pub const fn fields(&self) -> &AckRangeFields {
        &self.fields
    }
    /// Returns the complete historical scope.
    #[must_use]
    pub const fn scope(&self) -> &DeliveryScope {
        &self.fields.scope
    }
    /// Returns the delivery generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.fields.generation
    }
    /// Returns the final sequence used in the exact range key.
    #[must_use]
    pub const fn last(&self) -> u64 {
        self.fields.last
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        self.scope().put(encoder)?;
        encoder.put_u64(self.generation())?;
        encoder.put_u64(self.fields.first)?;
        encoder.put_u64(self.fields.last)?;
        encoder.put_fixed(&self.fields.event_id)?;
        self.fields.acknowledgement.put(encoder)
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(AckRangeFields {
            scope: DeliveryScope::take(decoder)?,
            generation: decoder.u64()?,
            first: decoder.u64()?,
            last: decoder.u64()?,
            event_id: decoder.array()?,
            acknowledgement: Acknowledgement::take(decoder)?,
        })
    }
}
