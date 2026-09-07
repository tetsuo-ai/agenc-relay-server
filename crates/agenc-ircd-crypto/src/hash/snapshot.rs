//! Bounded streaming hash for the federation snapshot's canonical encoding.

use sha2::{Digest as _, Sha256};

use super::{Digest32, SemanticHashDomain};
use crate::CryptoError;

const SNAPSHOT_HEADER_BYTES: usize = 20;
const SNAPSHOT_ID_BYTES: usize = 32;
const MAX_SNAPSHOT_CANONICAL_BYTES: usize = SNAPSHOT_HEADER_BYTES + 1_000_000 * SNAPSHOT_ID_BYTES;

/// Hashes exactly one declared snapshot encoding without retaining its bytes.
///
/// The caller supplies the canonical framing and ordered IDs. This adapter
/// bounds the total input independently of the generic semantic-hash limit.
pub struct FederationSnapshotHash {
    hasher: Sha256,
    remaining: usize,
}

impl FederationSnapshotHash {
    /// Starts the registered digest for a header and at most one million IDs.
    pub fn new(canonical_bytes: usize) -> Result<Self, CryptoError> {
        if !(SNAPSHOT_HEADER_BYTES..=MAX_SNAPSHOT_CANONICAL_BYTES).contains(&canonical_bytes)
            || !(canonical_bytes - SNAPSHOT_HEADER_BYTES).is_multiple_of(SNAPSHOT_ID_BYTES)
        {
            return Err(CryptoError::LimitExceeded);
        }
        let mut hasher = Sha256::new();
        hasher.update(SemanticHashDomain::FederationSnapshot.label());
        Ok(Self {
            hasher,
            remaining: canonical_bytes,
        })
    }

    /// Absorbs a chunk only if it fits within the declared remaining input.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        let remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or(CryptoError::LimitExceeded)?;
        self.hasher.update(bytes);
        self.remaining = remaining;
        Ok(())
    }

    /// Finishes only after every declared byte has been supplied.
    pub fn finish(self) -> Result<Digest32, CryptoError> {
        if self.remaining != 0 {
            return Err(CryptoError::InvalidEncoding);
        }
        Ok(Digest32(self.hasher.finalize().into()))
    }
}

#[cfg(test)]
#[path = "tests/snapshot.rs"]
mod tests;
