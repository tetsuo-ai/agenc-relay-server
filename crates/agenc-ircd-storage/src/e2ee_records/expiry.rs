//! Table 23 object-expiry progress (companion 15 and 16).
//!
//! The bounded collector that deletes expired unowned table-22 bodies owns
//! exactly one `object-expiry/v1` row. It persists where the last committed
//! pass stopped, so a restart resumes at the next `owner/v1/` account
//! instead of skipping the rest of a page or replaying one, and the running
//! totals the pass charged, so the accounting is never applied twice. The
//! row carries no retention decision of its own: what may be deleted is read
//! from the ownership accounts alone.

#![forbid(unsafe_code)]

use super::{
    HASH_BYTES, decoder, encoder, key_of, prefix, put_optional_hash, take_optional_hash, unwrap,
    wrap,
};
use crate::{StorageError, StoredKey};

/// The E2eeState object-expiry progress kind.
pub const EXPIRY_PROGRESS_ROW_KIND: u16 = 22;

/// The durable continuation of the object collector.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObjectExpiryProgressRow {
    /// The last account identifier a committed pass examined; the next pass
    /// resumes strictly after it. `None` restarts at the first account.
    pub cursor: Option<[u8; HASH_BYTES]>,
    /// Sweeps that reached the last account and wrapped.
    pub passes: u64,
    /// Objects deleted since the store was created.
    pub deleted_objects: u64,
    /// Object bytes deleted since the store was created.
    pub deleted_bytes: u64,
}

impl ObjectExpiryProgressRow {
    /// The single `object-expiry/v1` key.
    pub fn key() -> Result<StoredKey, StorageError> {
        key_of(&[prefix::OBJECT_EXPIRY])
    }

    /// Whether `key` is the progress key.
    #[must_use]
    pub fn matches_key(key: &StoredKey) -> bool {
        key.as_bytes() == prefix::OBJECT_EXPIRY
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.check()?;
        let mut encoder = encoder()?;
        put_optional_hash(&mut encoder, self.cursor.as_ref())?;
        encoder.put_u64(self.passes)?;
        encoder.put_u64(self.deleted_objects)?;
        encoder.put_u64(self.deleted_bytes)?;
        wrap(EXPIRY_PROGRESS_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(EXPIRY_PROGRESS_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = Self {
            cursor: take_optional_hash(&mut decoder)?,
            passes: decoder.u64()?,
            deleted_objects: decoder.u64()?,
            deleted_bytes: decoder.u64()?,
        };
        decoder.finish()?;
        row.check()?;
        Ok(row)
    }

    /// A deletion always charges at least one byte, so a count and a byte
    /// total disagree only in a forged or truncated row.
    fn check(&self) -> Result<(), StorageError> {
        ((self.deleted_objects == 0) == (self.deleted_bytes == 0)
            && self.deleted_bytes >= self.deleted_objects)
            .then_some(())
            .ok_or(StorageError::InvalidEncoding)
    }
}
