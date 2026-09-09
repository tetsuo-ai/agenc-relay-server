//! Scoped ACK journals and retained replay ownership.
#![forbid(unsafe_code)]

mod owner;
mod range;
#[cfg(test)]
mod tests;

pub use owner::{ReplayOwner, ReplayOwnerFields};
pub use range::{AckRange, AckRangeFields};

use crate::codec::{Decoder, Encoder};
use crate::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;
use crate::e2ee_records::delivery_recovery::DeliveryScope;
use crate::{ProtocolRecordBody, StorageError, StoredKey, TableId};

/// Exact current replay-journal body version.
pub const REPLAY_BODY_VERSION: u16 = 3;
/// Exact full-scope replay owner prefix.
pub const REPLAY_OWNER_PREFIX: &[u8] = b"delivery-replay-owner/v1/";
/// Exact full-scope ACK range prefix, ordered by final sequence.
pub const ACK_RANGE_PREFIX: &[u8] = b"delivery-ack-range/v1/";
const OWNER_ARM: u16 = 1;
const RANGE_ARM: u16 = 2;
const SCOPE_BYTES: usize = 120;
const MAX_BODY_BYTES: usize = 190;
const ENVELOPE_BYTES: usize = crate::MAX_DOMAIN_RECORD_BODY_BYTES - crate::MAX_PROTOCOL_BODY_BYTES;

/// A typed range journal; construction grants no delivery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayLedgerRow {
    /// Exact ACK authority and retained suffix boundary.
    Owner(ReplayOwner),
    /// One complete newly acknowledged interval.
    Range(AckRange),
}

impl ReplayLedgerRow {
    /// Encodes the versioned body under the existing delivery record family.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(MAX_BODY_BYTES, MAX_BODY_BYTES)?;
        encoder.put_u16(REPLAY_BODY_VERSION)?;
        match self {
            Self::Owner(owner) => {
                encoder.put_u16(OWNER_ARM)?;
                owner.put(&mut encoder)?;
            }
            Self::Range(range) => {
                encoder.put_u16(RANGE_ARM)?;
                range.put(&mut encoder)?;
            }
        }
        ProtocolRecordBody::new(
            TableId::E2eeState,
            DELIVERY_RECOVERY_ROW_KIND,
            1,
            encoder.finish(),
        )?
        .encode()
    }

    /// Decodes the exact version, arm, field bounds, and complete envelope.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        if body.len() > MAX_BODY_BYTES + ENVELOPE_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let envelope =
            ProtocolRecordBody::decode(TableId::E2eeState, DELIVERY_RECOVERY_ROW_KIND, body)?;
        let mut decoder = Decoder::new(envelope.canonical_object());
        if decoder.u16()? != REPLAY_BODY_VERSION {
            return Err(StorageError::UnsupportedVersion);
        }
        let row = match decoder.u16()? {
            OWNER_ARM => Self::Owner(ReplayOwner::take(&mut decoder)?),
            RANGE_ARM => Self::Range(AckRange::take(&mut decoder)?),
            _ => return Err(StorageError::InvalidEncoding),
        };
        decoder.finish()?;
        Ok(row)
    }

    /// Binds the complete historical key to the decoded record identity.
    pub fn decode_at(key: &StoredKey, body: &[u8]) -> Result<Self, StorageError> {
        let row = Self::decode(body)?;
        if row.key()? != *key {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(row)
    }

    /// Derives the exact full-scope key without inferring an incarnation.
    pub fn key(&self) -> Result<StoredKey, StorageError> {
        match self {
            Self::Owner(owner) => key(REPLAY_OWNER_PREFIX, owner.scope(), owner.generation(), None),
            Self::Range(range) => key(
                ACK_RANGE_PREFIX,
                range.scope(),
                range.generation(),
                Some(range.last()),
            ),
        }
    }
}

fn key(
    prefix: &[u8],
    scope: &DeliveryScope,
    generation: u64,
    last: Option<u64>,
) -> Result<StoredKey, StorageError> {
    let mut encoder = Encoder::with_capacity(SCOPE_BYTES + 16, SCOPE_BYTES + 16)?;
    scope.put(&mut encoder)?;
    encoder.put_u64(generation)?;
    if let Some(last) = last {
        encoder.put_u64(last)?;
    }
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(&encoder.finish());
    StoredKey::new(bytes)
}

/// Builds the exact replay owner key without constructing authority from a cursor.
pub fn replay_owner_key(scope: &DeliveryScope, generation: u64) -> Result<StoredKey, StorageError> {
    key(REPLAY_OWNER_PREFIX, scope, generation, None)
}

/// Reads ACK intervals by final position within one complete scope and generation.
pub fn ack_ranges_from(
    scope: &DeliveryScope,
    generation: u64,
    first_final_sequence: u64,
    limit: u16,
) -> Result<crate::ReadPlan, StorageError> {
    let prefix = key(ACK_RANGE_PREFIX, scope, generation, None)?;
    let start = key(
        ACK_RANGE_PREFIX,
        scope,
        generation,
        Some(first_final_sequence),
    )?;
    super::super::prefix_range_from(prefix.as_bytes(), &start, limit)
}
