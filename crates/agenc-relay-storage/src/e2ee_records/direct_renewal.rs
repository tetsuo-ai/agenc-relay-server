//! The concrete Direct target selected for the next binding of an active group.
//! This hint permits another signed reservation for the same target. It is
//! never a grant and confers no right to BIND.
#![forbid(unsafe_code)]

use crate::codec::{Decoder, Encoder};
use crate::{StorageError, StoredKey};

/// Table-23 record kind for a renewable same-group Direct target.
pub const KIND: u16 = 25;
/// At most one target per conversation.
pub const PREFIX: &[u8] = b"direct-binding-renewal/v1/";
const BODY: usize = 2 + 4 * 32;

/// Public facts staged atomically with the first signed migration grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectRenewal {
    /// Existing conversation and stable storage key.
    pub conversation: [u8; 32],
    /// Admitted binding for which the creator is preparing a replacement.
    pub previous: [u8; 32],
    /// The chosen Direct nonce, stable when later grants replace an expired one.
    pub nonce: [u8; 32],
    /// Commitment to that nonce, network and ordered account pair.
    pub route: [u8; 32],
}

impl DirectRenewal {
    /// The stable storage key for this group's pending concrete target.
    pub fn key(conversation: &[u8; 32]) -> Result<StoredKey, StorageError> {
        super::key_of(&[PREFIX, conversation])
    }
    /// Encodes one fixed-size, versioned, typed row.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut out = Encoder::with_capacity(BODY, BODY)?;
        out.put_u16(1)?;
        for id in [&self.conversation, &self.previous, &self.nonce, &self.route] {
            out.put_fixed(id)?;
        }
        super::wrap(KIND, out.finish())
    }
    /// Decodes one exact value without accepting trailing or oversized bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != BODY + 12 {
            return Err(StorageError::InvalidEncoding);
        }
        let inner = super::unwrap(KIND, bytes)?;
        let mut input = Decoder::new(&inner);
        if input.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let value = Self {
            conversation: input.array()?,
            previous: input.array()?,
            nonce: input.array()?,
            route: input.array()?,
        };
        input.finish()?;
        Ok(value)
    }
    /// Verifies that the key and stored conversation agree.
    pub fn decode_keyed(key: &StoredKey, bytes: &[u8]) -> Result<Self, StorageError> {
        let value = Self::decode(bytes)?;
        if Self::key(&value.conversation)? != *key {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_renewal_requires_the_exact_value_and_key() -> Result<(), StorageError> {
        let row = DirectRenewal {
            conversation: [1; 32],
            previous: [2; 32],
            nonce: [3; 32],
            route: [4; 32],
        };
        let key = DirectRenewal::key(&row.conversation)?;
        let bytes = row.encode()?;
        assert_eq!(DirectRenewal::decode_keyed(&key, &bytes)?, row);
        assert_eq!(super::super::record_kind_for_key(&key)?, KIND);
        assert!(DirectRenewal::decode_keyed(&DirectRenewal::key(&[5; 32])?, &bytes).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(DirectRenewal::decode(&extra).is_err());
        let mut short = bytes;
        short.pop();
        assert!(DirectRenewal::decode(&short).is_err());
        Ok(())
    }
}
