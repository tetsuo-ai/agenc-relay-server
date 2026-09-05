//! Companion operation sequence floors that outlive request replay retention.

use super::{ID_BYTES, REPLAY_ROW_KIND, key_of, prefix, slice_array, suffix, unwrap, wrap};
use crate::codec::{Decoder, Encoder};
use crate::{StorageError, StoredKey};

/// A distinct body version keeps sequence floors separate from version-one
/// request replay bodies within the existing replay record kind.
const SEQUENCE_BODY_VERSION: u16 = 2;
const BODY_BYTES: usize = 18;

/// The origin whose last committed operation sequence is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct OriginSequenceKey {
    /// Home server.
    pub home_server_id: [u8; ID_BYTES],
    /// Home server incarnation.
    pub server_incarnation: [u8; ID_BYTES],
    /// Origin identity.
    pub origin_id: [u8; ID_BYTES],
}

/// The latest generation and its next unused operation sequence. This row
/// has no expiry and is replaced atomically with every committed request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginSequenceRow {
    /// Latest origin generation that committed a request.
    pub origin_generation: u64,
    /// Next unused operation sequence of that generation.
    pub next_sequence: u64,
}

impl OriginSequenceRow {
    /// The stable per-origin key; later generations replace the same row.
    pub fn key(parts: &OriginSequenceKey) -> Result<StoredKey, StorageError> {
        key_of(&[
            prefix::ORIGIN_SEQUENCE,
            &parts.home_server_id,
            &parts.server_incarnation,
            &parts.origin_id,
        ])
    }

    /// Splits the exact origin key, rejecting shortened or extended suffixes.
    pub fn parse_key(key: &StoredKey) -> Result<OriginSequenceKey, StorageError> {
        let rest = suffix(key, prefix::ORIGIN_SEQUENCE, 3 * ID_BYTES)?;
        Ok(OriginSequenceKey {
            home_server_id: slice_array(rest, 0)?,
            server_incarnation: slice_array(rest, ID_BYTES)?,
            origin_id: slice_array(rest, 2 * ID_BYTES)?,
        })
    }

    /// Encodes the fixed-size floor under the replay record kind.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.next_sequence == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        let mut encoder = Encoder::with_capacity(BODY_BYTES, BODY_BYTES)?;
        encoder.put_u16(SEQUENCE_BODY_VERSION)?;
        encoder.put_u64(self.origin_generation)?;
        encoder.put_u64(self.next_sequence)?;
        wrap(REPLAY_ROW_KIND, encoder.finish())
    }

    /// Decodes one floor, rejecting ordinary replay rows and trailing bytes.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(REPLAY_ROW_KIND, body)?;
        let mut decoder = Decoder::new(&inner);
        if decoder.u16()? != SEQUENCE_BODY_VERSION {
            return Err(StorageError::UnsupportedVersion);
        }
        let row = Self {
            origin_generation: decoder.u64()?,
            next_sequence: decoder.u64()?,
        };
        decoder.finish()?;
        if row.next_sequence == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(row)
    }
}
