//! Persistent logical retention survives interrupted physical deletion.
#![forbid(unsafe_code)]

use super::{Decoder, DeliveryScope, Encoder, StorageError};
use crate::e2ee_records::delivery_recovery::Acknowledgement;
use agenc_relay_e2ee::limits::{
    MAX_ACKED_E2EE_EVENT_REPLAY_BYTES_PER_EDGE, MAX_ACKED_E2EE_EVENT_REPLAY_ROWS_PER_EDGE,
};

/// Exact facts proposed by a cursor-owned retention transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayOwnerFields {
    /// Complete accepted delivery scope.
    pub scope: DeliveryScope,
    /// Delivery generation; zero is ordinary.
    pub generation: u64,
    /// Exact latest acknowledged sequence.
    pub through: u64,
    /// Opaque identity of that sequence, including an ordinary all-zero ID.
    pub event_id: [u8; 16],
    /// First retained ACKed sequence; through plus one denotes an empty suffix.
    pub first_retained: u64,
    /// Number of rows in that complete contiguous suffix.
    pub retained_rows: u64,
    /// Complete event-plus-required-payload bytes, counted per retained copy.
    pub retained_bytes: u64,
    /// Greatest accepted ACK time used for retention, never inferred from uncertainty.
    pub trusted_unix_seconds: Option<u64>,
}

/// A validated owner still requires matched scope, cursor, and storage receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayOwner {
    fields: ReplayOwnerFields,
}

impl ReplayOwner {
    /// Validates the exact suffix, byte bounds, and clock representation.
    pub fn new(fields: ReplayOwnerFields) -> Result<Self, StorageError> {
        validate_suffix(&fields)?;
        if let Some(time) = fields.trusted_unix_seconds
            && !matches!(
                Acknowledgement::received_at(Some(time)),
                Acknowledgement::AcknowledgedAt { .. }
            )
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self { fields })
    }

    /// Returns validated facts without granting mutation authority.
    #[must_use]
    pub const fn fields(&self) -> &ReplayOwnerFields {
        &self.fields
    }
    /// Returns the complete delivery scope.
    #[must_use]
    pub const fn scope(&self) -> &DeliveryScope {
        &self.fields.scope
    }
    /// Returns the exact delivery generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.fields.generation
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        self.scope().put(encoder)?;
        encoder.put_u64(self.generation())?;
        encoder.put_u64(self.fields.through)?;
        encoder.put_fixed(&self.fields.event_id)?;
        encoder.put_u64(self.fields.first_retained)?;
        encoder.put_u64(self.fields.retained_rows)?;
        encoder.put_u64(self.fields.retained_bytes)?;
        encoder.put_u16(u16::from(self.fields.trusted_unix_seconds.is_some()))?;
        if let Some(time) = self.fields.trusted_unix_seconds {
            encoder.put_u64(time)?;
        }
        Ok(())
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(ReplayOwnerFields {
            scope: DeliveryScope::take(decoder)?,
            generation: decoder.u64()?,
            through: decoder.u64()?,
            event_id: decoder.array()?,
            first_retained: decoder.u64()?,
            retained_rows: decoder.u64()?,
            retained_bytes: decoder.u64()?,
            trusted_unix_seconds: match decoder.u16()? {
                0 => None,
                1 => Some(decoder.u64()?),
                _ => return Err(StorageError::InvalidEncoding),
            },
        })
    }
}

fn validate_suffix(fields: &ReplayOwnerFields) -> Result<(), StorageError> {
    let end = fields
        .through
        .checked_add(1)
        .ok_or(StorageError::InvalidEncoding)?;
    if end.checked_sub(fields.first_retained) != Some(fields.retained_rows)
        || fields.retained_rows > MAX_ACKED_E2EE_EVENT_REPLAY_ROWS_PER_EDGE
        || fields.retained_bytes > MAX_ACKED_E2EE_EVENT_REPLAY_BYTES_PER_EDGE
        || (fields.retained_rows == 0) != (fields.retained_bytes == 0)
        || fields.retained_bytes < fields.retained_rows
    {
        return Err(StorageError::InvalidEncoding);
    }
    let maximum_copy_bytes =
        u64::from(super::super::MAX_EVENT_BYTES) + u64::from(super::super::MAX_PAYLOAD_BYTES);
    let maximum_bytes = fields
        .retained_rows
        .checked_mul(maximum_copy_bytes)
        .ok_or(StorageError::InvalidEncoding)?;
    if fields.retained_bytes > maximum_bytes {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(())
}
