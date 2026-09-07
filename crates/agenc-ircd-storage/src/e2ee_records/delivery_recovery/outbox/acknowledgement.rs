//! ACK metadata never interprets uncertain time as permission to expire a row.
#![forbid(unsafe_code)]

use crate::StorageError;
use crate::codec::{Decoder, Encoder};

/// Published acknowledged replay retention target in wall-clock seconds.
const ACK_RETENTION_SECONDS: u64 = 86_400;

/// Closed durable ACK facts; zero Unix time remains an ordinary timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acknowledgement {
    /// This event still requires acknowledgement.
    Unacknowledged,
    /// ACK committed while accepted wall time could not be established.
    AcknowledgedTimeUnknown,
    /// Original accepted UTC time and its checked retention target.
    AcknowledgedAt {
        /// First valid ACK preparation time.
        received_unix_seconds: u64,
        /// Exactly one published retention interval after receipt.
        retain_until_unix_seconds: u64,
    },
}

impl Acknowledgement {
    /// Captures trusted UTC, retaining conservatively on absence or overflow.
    #[must_use]
    pub fn received_at(trusted_unix_seconds: Option<u64>) -> Self {
        let Some((received, until)) = trusted_unix_seconds.and_then(|received| {
            received
                .checked_add(ACK_RETENTION_SECONDS)
                .map(|until| (received, until))
        }) else {
            return Self::AcknowledgedTimeUnknown;
        };
        Self::AcknowledgedAt {
            received_unix_seconds: received,
            retain_until_unix_seconds: until,
        }
    }

    /// Whether this row's ACK was durably accepted.
    #[must_use]
    pub const fn is_acknowledged(self) -> bool {
        !matches!(self, Self::Unacknowledged)
    }

    pub(super) fn validate(self) -> Result<(), StorageError> {
        if let Self::AcknowledgedAt {
            received_unix_seconds,
            retain_until_unix_seconds,
        } = self
            && received_unix_seconds.checked_add(ACK_RETENTION_SECONDS)
                != Some(retain_until_unix_seconds)
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    pub(super) fn put(self, encoder: &mut Encoder) -> Result<(), StorageError> {
        match self {
            Self::Unacknowledged => encoder.put_u16(0),
            Self::AcknowledgedTimeUnknown => encoder.put_u16(1),
            Self::AcknowledgedAt {
                received_unix_seconds,
                retain_until_unix_seconds,
            } => {
                encoder.put_u16(2)?;
                encoder.put_u64(received_unix_seconds)?;
                encoder.put_u64(retain_until_unix_seconds)
            }
        }
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let value = match decoder.u16()? {
            0 => Self::Unacknowledged,
            1 => Self::AcknowledgedTimeUnknown,
            2 => Self::AcknowledgedAt {
                received_unix_seconds: decoder.u64()?,
                retain_until_unix_seconds: decoder.u64()?,
            },
            _ => return Err(StorageError::InvalidEncoding),
        };
        value.validate()?;
        Ok(value)
    }
}
