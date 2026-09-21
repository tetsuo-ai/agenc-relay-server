//! Semantic identifiers and digests (companion Section 2.2).
//!
//! A protocol-state ID hashes the canonical TLS encoding of the named TBS
//! under its registered label; it never covers a signature, approval vector,
//! vote vector, or proof wrapper. The transport `object-id` is the one
//! exception and lives in [`crate::object`] as a plain content address.

use agenc_relay_crypto::{FederationSnapshotHash, SemanticHashDomain, semantic_digest};

use crate::error::E2eeError;
use crate::tls::{TlsEncode, Writer};

/// One 32-byte semantic identifier or digest.
pub type SemanticId = [u8; 32];

/// Hashes the canonical encoding of `value` under `domain`.
pub fn semantic_id_of(
    domain: SemanticHashDomain,
    value: &impl TlsEncode,
) -> Result<SemanticId, E2eeError> {
    semantic_id_over(domain, &value.encode()?)
}

/// Hashes already-canonical bytes under `domain`.
pub fn semantic_id_over(
    domain: SemanticHashDomain,
    encoding: &[u8],
) -> Result<SemanticId, E2eeError> {
    semantic_digest(domain, encoding)
        .map(|digest| *digest.as_bytes())
        .map_err(|_| E2eeError::LimitExceeded)
}

/// `account_id_digest` over `TLS-encode(network_id, account_id)`.
pub fn account_id_digest(
    network_id: &[u8; 32],
    account_id: &[u8],
) -> Result<SemanticId, E2eeError> {
    let mut writer = Writer::new();
    writer.fixed(network_id)?;
    writer.opaque(account_id, 1, 255)?;
    semantic_id_over(SemanticHashDomain::AccountId, &writer.into_bytes())
}

/// `conversation_id` over `TLS-encode(network_id, group_id)`.
pub fn conversation_id(network_id: &[u8; 32], group_id: &[u8]) -> Result<SemanticId, E2eeError> {
    let mut writer = Writer::new();
    writer.fixed(network_id)?;
    writer.opaque(group_id, 1, 255)?;
    semantic_id_over(SemanticHashDomain::Conversation, &writer.into_bytes())
}

/// `leaf_signature_key_digest` over `TLS-encode(scheme, key)`.
pub fn leaf_signature_key_digest(scheme: u16, key: &[u8]) -> Result<SemanticId, E2eeError> {
    let mut writer = Writer::new();
    writer.u16(scheme)?;
    writer.opaque(key, 1, 255)?;
    semantic_id_over(SemanticHashDomain::LeafSignatureKey, &writer.into_bytes())
}

/// `leaf_capabilities_digest` over the encoded LeafNode capabilities.
pub fn leaf_capabilities_digest(encoded_capabilities: &[u8]) -> Result<SemanticId, E2eeError> {
    semantic_id_over(SemanticHashDomain::LeafCapabilities, encoded_capabilities)
}

/// `resulting_leaf_credential_hash` over `TLS-encode(index, credential)`.
pub fn resulting_leaf_credential_hash(
    leaf_index: u32,
    encoded_basic_credential: &[u8],
) -> Result<SemanticId, E2eeError> {
    let mut writer = Writer::new();
    writer.u32(leaf_index)?;
    writer.fixed(encoded_basic_credential)?;
    semantic_id_over(
        SemanticHashDomain::ResultingLeafCredential,
        &writer.into_bytes(),
    )
}

/// `old_credential_hash` over the encoded BasicCredential.
pub fn old_credential_hash(encoded_basic_credential: &[u8]) -> Result<SemanticId, E2eeError> {
    semantic_id_over(
        SemanticHashDomain::OldCredentialHash,
        encoded_basic_credential,
    )
}

/// `initial_commit_digest` over the complete MLS message bytes.
pub fn initial_commit_digest(initial_commit_bytes: &[u8]) -> Result<SemanticId, E2eeError> {
    semantic_id_over(
        SemanticHashDomain::ReinitInitialCommit,
        initial_commit_bytes,
    )
}

/// `canonical_channel_name_hash` over `TLS-encode(canonical_irc_name)`.
pub fn canonical_channel_name_hash(canonical_name: &[u8]) -> Result<SemanticId, E2eeError> {
    let mut writer = Writer::new();
    writer.opaque(canonical_name, 1, 255)?;
    semantic_id_over(
        SemanticHashDomain::CanonicalChannelName,
        &writer.into_bytes(),
    )
}

/// `sequencer_key_set_digest` over `TLS-encode(credential_ids)`.
pub fn sequencer_key_set_digest(credential_ids: &[SemanticId]) -> Result<SemanticId, E2eeError> {
    let mut writer = Writer::new();
    writer.vector(credential_ids, 0, 65_535)?;
    semantic_id_over(SemanticHashDomain::SequencerKeySet, &writer.into_bytes())
}

/// `federation_snapshot_digest` over
/// `TLS-encode(state_generation, delivery_generation, ordered_state_object_ids)`.
pub fn federation_snapshot_digest(
    state_generation: u64,
    delivery_generation: u64,
    ordered_state_object_ids: &[SemanticId],
) -> Result<SemanticId, E2eeError> {
    federation_snapshot_digest_iter(
        state_generation,
        delivery_generation,
        ordered_state_object_ids.len(),
        ordered_state_object_ids,
    )
}

/// Hashes an exact count of IDs in canonical conversation order without copying
/// the IDs. The snapshot owner must establish that order before calling this.
pub fn federation_snapshot_digest_iter<'a>(
    state_generation: u64,
    delivery_generation: u64,
    count: usize,
    ordered_state_object_ids: impl IntoIterator<Item = &'a SemanticId>,
) -> Result<SemanticId, E2eeError> {
    let mut digest = FederationSnapshotDigest::new(state_generation, delivery_generation, count)?;
    for id in ordered_state_object_ids {
        digest.push(id)?;
    }
    digest.finish()
}

/// A fixed-size snapshot digest owner that can survive bounded storage reads.
/// The caller verifies conversation order and row ownership before each push.
pub struct FederationSnapshotDigest {
    digest: FederationSnapshotHash,
}

impl FederationSnapshotDigest {
    /// Writes the exact version-one framing for the declared bounded ID count.
    pub fn new(
        state_generation: u64,
        delivery_generation: u64,
        count: usize,
    ) -> Result<Self, E2eeError> {
        if u64::try_from(count).map_err(|_| E2eeError::LimitExceeded)?
            > crate::limits::MAX_FEDERATION_STATE_ENTRIES_PER_EDGE
        {
            return Err(E2eeError::LimitExceeded);
        }
        let id_bytes = count.checked_mul(32).ok_or(E2eeError::LimitExceeded)?;
        let canonical_bytes = id_bytes.checked_add(20).ok_or(E2eeError::LimitExceeded)?;
        let mut digest =
            FederationSnapshotHash::new(canonical_bytes).map_err(|_| E2eeError::LimitExceeded)?;
        digest
            .update(&state_generation.to_be_bytes())
            .map_err(|_| E2eeError::LimitExceeded)?;
        digest
            .update(&delivery_generation.to_be_bytes())
            .map_err(|_| E2eeError::LimitExceeded)?;
        digest
            .update(
                &u32::try_from(id_bytes)
                    .map_err(|_| E2eeError::LimitExceeded)?
                    .to_be_bytes(),
            )
            .map_err(|_| E2eeError::LimitExceeded)?;
        Ok(Self { digest })
    }

    /// Absorbs one ordered ID without permitting more than the declared count.
    pub fn push(&mut self, id: &SemanticId) -> Result<(), E2eeError> {
        self.digest.update(id).map_err(|_| E2eeError::LimitExceeded)
    }

    /// Finishes only when the exact declared ID count has been supplied.
    pub fn finish(self) -> Result<SemanticId, E2eeError> {
        self.digest
            .finish()
            .map(|value| *value.as_bytes())
            .map_err(|_| E2eeError::LimitExceeded)
    }
}

/// A proof-set digest over a canonical vector of TBS values.
pub fn proof_set_digest<T: TlsEncode>(
    domain: SemanticHashDomain,
    canonical_tbs_values: &[T],
) -> Result<SemanticId, E2eeError> {
    let mut writer = Writer::new();
    writer.vector(canonical_tbs_values, 0, 0xffff_ffff)?;
    semantic_id_over(domain, &writer.into_bytes())
}

#[cfg(test)]
#[path = "tests/ids.rs"]
mod tests;
