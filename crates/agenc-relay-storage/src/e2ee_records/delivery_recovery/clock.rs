//! Nonextendable pending-cut clock coordinates, independent of actor ticks.
#![forbid(unsafe_code)]

use crate::StorageError;
use crate::codec::{Decoder, Encoder};

const TOKEN_LIFETIME_SECONDS: u64 = 900;

/// Linux monotonic pending-token deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingDeadlineFields {
    /// Kernel boot identity.
    pub boot_id: [u8; 16],
    /// Exact monotonic namespace offset seconds.
    pub offset_seconds: i64,
    /// Normalized monotonic namespace offset nanoseconds.
    pub offset_nanoseconds: u32,
    /// Original absolute monotonic deadline seconds.
    pub deadline_seconds: u64,
    /// Original absolute monotonic deadline nanoseconds.
    pub deadline_nanoseconds: u32,
    /// Latest durable observed monotonic seconds.
    pub observed_seconds: u64,
    /// Latest durable observed monotonic nanoseconds.
    pub observed_nanoseconds: u32,
}

/// Validated linux monotonic pending-token deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingDeadline {
    fields: PendingDeadlineFields,
}

impl PendingDeadline {
    /// Validates one complete set of fields.
    pub fn new(fields: PendingDeadlineFields) -> Result<Self, StorageError> {
        let nanos = [
            fields.offset_nanoseconds,
            fields.deadline_nanoseconds,
            fields.observed_nanoseconds,
        ];
        if nanos.into_iter().any(|value| value >= 1_000_000_000) {
            return Err(StorageError::InvalidEncoding);
        }
        let issued_seconds = fields
            .deadline_seconds
            .checked_sub(TOKEN_LIFETIME_SECONDS)
            .ok_or(StorageError::InvalidEncoding)?;
        let observed = (fields.observed_seconds, fields.observed_nanoseconds);
        let issued = (issued_seconds, fields.deadline_nanoseconds);
        let deadline = (fields.deadline_seconds, fields.deadline_nanoseconds);
        if observed < issued || observed >= deadline {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self { fields })
    }

    /// Returns kernel boot identity.
    #[must_use]
    pub const fn boot_id(&self) -> [u8; 16] {
        self.fields.boot_id
    }

    /// Returns exact monotonic namespace offset seconds.
    #[must_use]
    pub const fn offset_seconds(&self) -> i64 {
        self.fields.offset_seconds
    }

    /// Returns normalized monotonic namespace offset nanoseconds.
    #[must_use]
    pub const fn offset_nanoseconds(&self) -> u32 {
        self.fields.offset_nanoseconds
    }

    /// Returns original absolute monotonic deadline seconds.
    #[must_use]
    pub const fn deadline_seconds(&self) -> u64 {
        self.fields.deadline_seconds
    }

    /// Returns original absolute monotonic deadline nanoseconds.
    #[must_use]
    pub const fn deadline_nanoseconds(&self) -> u32 {
        self.fields.deadline_nanoseconds
    }

    /// Returns latest durable observed monotonic seconds.
    #[must_use]
    pub const fn observed_seconds(&self) -> u64 {
        self.fields.observed_seconds
    }

    /// Returns latest durable observed monotonic nanoseconds.
    #[must_use]
    pub const fn observed_nanoseconds(&self) -> u32 {
        self.fields.observed_nanoseconds
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_u16(1)?;
        encoder.put_fixed(&self.fields.boot_id)?;
        encoder.put_fixed(&self.fields.offset_seconds.to_be_bytes())?;
        encoder.put_u32(self.fields.offset_nanoseconds)?;
        encoder.put_u64(self.fields.deadline_seconds)?;
        encoder.put_u32(self.fields.deadline_nanoseconds)?;
        encoder.put_u64(self.fields.observed_seconds)?;
        encoder.put_u32(self.fields.observed_nanoseconds)?;
        Ok(())
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        Self::new(PendingDeadlineFields {
            boot_id: decoder.array()?,
            offset_seconds: i64::from_be_bytes(decoder.array()?),
            offset_nanoseconds: decoder.u32()?,
            deadline_seconds: decoder.u64()?,
            deadline_nanoseconds: decoder.u32()?,
            observed_seconds: decoder.u64()?,
            observed_nanoseconds: decoder.u32()?,
        })
    }
}
