//! Purpose-separated authentication for durable storage control records.

use agenc_ircd_types::{DatabaseId, NetworkId, ServerId};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::CryptoError;
use crate::secret::SecretBytes;

const GUARD_SALT_LABEL: &[u8] = b"agenc-chat rollback guard salt v1";
const STATE_META_KEY_LABEL: &[u8] = b"agenc-chat state meta authorization key v1";
const RESERVATION_KEY_LABEL: &[u8] = b"agenc-chat nonce reservation mac key v1";
const GUARD_KEY_LABEL: &[u8] = b"agenc-chat rollback guard file mac key v1";
const STATE_META_MAC_LABEL: &[u8] = b"agenc-chat state meta commit authorization v1";
const RESERVATION_MAC_LABEL: &[u8] = b"agenc-chat nonce reservation state mac v1";
const GUARD_MAC_LABEL: &[u8] = b"agenc-chat rollback guard mac v1";
const HEADER_HASH_LABEL: &[u8] = b"agenc-chat complete database header v1";
const KEY_CHECK_LABEL: &[u8] = b"agenc-chat database header v1";
const RESERVATION_HASH_LABEL: &[u8] = b"agenc-chat nonce reservation state hash v1";
const GUARD_HASH_LABEL: &[u8] = b"agenc-chat rollback guard hash v1";
const SEALED_RECORD_ID_LABEL: &[u8] = b"agenc-chat sealed record id v1";
const MANIFEST_HASH_LABEL: &[u8] = b"agenc-chat integrity manifest v1";
const CHECKPOINT_HASH_LABEL: &[u8] = b"agenc-chat integrity checkpoint v1";
const RECORD_COMMITMENT_LABEL: &[u8] = b"agenc-chat tracked record commitment v1";
const TRACKED_STATE_LABEL: &[u8] = b"agenc-chat tracked state digest v1";
const BACKUP_SIGNING_KEY_LABEL: &[u8] = b"agenc-chat backup signing key v1";
const CONSTRUCTION_PLAN_LABEL: &[u8] = b"agenc-chat storage construction plan v1";
const STORAGE_OPERATION_ID_LABEL: &[u8] = b"agenc-chat completed storage operation id v1";
const STORAGE_OPERATION_KEY_ID_LABEL: &[u8] = b"agenc-chat storage operation key id v1";
const STORAGE_OUTPUT_PATH_LABEL: &[u8] = b"agenc-chat storage output path v1";
const RESTORE_PROFILE_LABEL: &[u8] = b"agenc-chat RecoveryTransformV1 profile v1";
const REKEY_PROFILE_LABEL: &[u8] = b"agenc-chat storage rekey transform profile v1";
const MAX_CONTROL_INPUT_BYTES: usize = 16_777_256;

/// An independently provisioned rollback-guard root key.
pub struct RollbackGuardRootKey(SecretBytes<32>);

impl RollbackGuardRootKey {
    /// Takes ownership of an exact external root key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// Compares two guard roots without exposing either key or exiting early.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.0.as_bytes().ct_eq(other.0.as_bytes()))
    }

    /// Derives the source-role resumability ID without exposing this key.
    pub fn source_operation_key_id(&self) -> Result<StorageDigest, CryptoError> {
        storage_operation_key_id(b"source-guard-root", self.0.as_bytes())
    }

    /// Derives the target-role resumability ID without exposing this key.
    pub fn target_operation_key_id(&self) -> Result<StorageDigest, CryptoError> {
        storage_operation_key_id(b"target-guard-root", self.0.as_bytes())
    }
}

/// The immutable context used to derive one database's guard subkeys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageIntegrityContext {
    network_id: NetworkId,
    server_id: ServerId,
    database_instance_id: DatabaseId,
}

impl StorageIntegrityContext {
    /// Creates the complete database-specific derivation context.
    #[must_use]
    pub const fn new(
        network_id: NetworkId,
        server_id: ServerId,
        database_instance_id: DatabaseId,
    ) -> Self {
        Self {
            network_id,
            server_id,
            database_instance_id,
        }
    }
}

/// Three purpose-separated keys derived from one guard root.
pub struct StorageIntegrityKeys {
    state_meta: SecretBytes<32>,
    reservation: SecretBytes<32>,
    guard: SecretBytes<32>,
}

/// A fixed SHA-256 commitment to canonical storage bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StorageDigest([u8; 32]);

impl StorageDigest {
    /// Constructs a digest read from a canonical authenticated object.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A fixed HMAC-SHA-256 authenticator.
#[derive(Clone, Copy)]
pub struct StorageAuthenticator([u8; 32]);

impl StorageAuthenticator {
    /// Constructs an authenticator read from a fixed canonical object.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the bytes only for canonical storage encoding.
    #[must_use]
    pub const fn expose_for_storage(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compares authenticators without data-dependent early exit.
    #[must_use]
    pub fn matches(&self, candidate: &Self) -> bool {
        bool::from(self.0.ct_eq(&candidate.0))
    }
}

/// Derives the three exact guard keys for one candidate database instance.
pub fn derive_storage_integrity_keys(
    root: &RollbackGuardRootKey,
    context: StorageIntegrityContext,
) -> Result<StorageIntegrityKeys, CryptoError> {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(GUARD_SALT_LABEL);
    salt_hasher.update(context.network_id.as_bytes());
    salt_hasher.update(context.server_id.as_bytes());
    salt_hasher.update(context.database_instance_id.as_bytes());
    let salt = salt_hasher.finalize();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), root.0.as_bytes());
    Ok(StorageIntegrityKeys {
        state_meta: expand_key(&hkdf, STATE_META_KEY_LABEL)?,
        reservation: expand_key(&hkdf, RESERVATION_KEY_LABEL)?,
        guard: expand_key(&hkdf, GUARD_KEY_LABEL)?,
    })
}

fn expand_key(hkdf: &Hkdf<Sha256>, label: &[u8]) -> Result<SecretBytes<32>, CryptoError> {
    let mut output = SecretBytes::new([0_u8; 32]);
    hkdf.expand(label, output.as_mut_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    Ok(output)
}

/// Authenticates a fixed StateMeta TBS value and its complete header hash.
pub fn authenticate_state_meta(
    keys: &StorageIntegrityKeys,
    database_header_hash: StorageDigest,
    encoded_tbs: &[u8],
) -> Result<StorageAuthenticator, CryptoError> {
    keyed_authenticator(
        &keys.state_meta,
        STATE_META_MAC_LABEL,
        &[database_header_hash.as_bytes(), encoded_tbs],
    )
}

/// Authenticates one canonical nonce-reservation TBS value.
pub fn authenticate_nonce_reservation(
    keys: &StorageIntegrityKeys,
    encoded_tbs: &[u8],
) -> Result<StorageAuthenticator, CryptoError> {
    keyed_authenticator(&keys.reservation, RESERVATION_MAC_LABEL, &[encoded_tbs])
}

/// Authenticates one canonical external rollback-guard TBS value.
pub fn authenticate_rollback_guard(
    keys: &StorageIntegrityKeys,
    encoded_tbs: &[u8],
) -> Result<StorageAuthenticator, CryptoError> {
    keyed_authenticator(&keys.guard, GUARD_MAC_LABEL, &[encoded_tbs])
}

fn keyed_authenticator(
    key: &SecretBytes<32>,
    label: &[u8],
    parts: &[&[u8]],
) -> Result<StorageAuthenticator, CryptoError> {
    let length = parts.iter().try_fold(label.len(), |total, part| {
        total.checked_add(part.len()).ok_or(CryptoError::Overflow)
    })?;
    if length > MAX_CONTROL_INPUT_BYTES {
        return Err(CryptoError::LimitExceeded);
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidEncoding)?;
    mac.update(label);
    for part in parts {
        mac.update(part);
    }
    Ok(StorageAuthenticator(mac.finalize().into_bytes().into()))
}

fn labeled_digest(label: &[u8], parts: &[&[u8]]) -> Result<StorageDigest, CryptoError> {
    let length = parts.iter().try_fold(label.len(), |total, part| {
        total.checked_add(part.len()).ok_or(CryptoError::Overflow)
    })?;
    if length > MAX_CONTROL_INPUT_BYTES {
        return Err(CryptoError::LimitExceeded);
    }
    let mut hasher = Sha256::new();
    hasher.update(label);
    for part in parts {
        hasher.update(part);
    }
    Ok(StorageDigest(hasher.finalize().into()))
}

/// Hashes a complete canonical database header.
pub fn database_header_hash(encoded: &[u8]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(HEADER_HASH_LABEL, &[encoded])
}

/// Computes the exact key-check plaintext from a canonical header TBS value.
pub fn database_key_check(encoded_header_tbs: &[u8]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(KEY_CHECK_LABEL, &[encoded_header_tbs])
}

/// Hashes a complete canonical nonce-reservation object.
pub fn nonce_reservation_hash(encoded: &[u8]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(RESERVATION_HASH_LABEL, &[encoded])
}

/// Hashes a complete canonical rollback guard.
pub fn rollback_guard_hash(encoded: &[u8]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(GUARD_HASH_LABEL, &[encoded])
}

/// Computes the stable identifier of one complete SealedRecord envelope.
pub fn sealed_record_id(encoded: &[u8]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(SEALED_RECORD_ID_LABEL, &[encoded])
}

/// Hashes one canonical integrity-manifest TBS value.
pub fn integrity_manifest_hash(encoded_tbs: &[u8]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(MANIFEST_HASH_LABEL, &[encoded_tbs])
}

/// Hashes one canonical integrity-checkpoint TBS value.
pub fn integrity_checkpoint_hash(encoded_tbs: &[u8]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(CHECKPOINT_HASH_LABEL, &[encoded_tbs])
}

/// Commits to one integrity-tracked record tuple.
pub fn tracked_record_commitment(encoded_tuple: &[u8]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(RECORD_COMMITMENT_LABEL, &[encoded_tuple])
}

/// Commits to an ordered complete record set and its exact count.
pub fn tracked_state_digest(
    record_count: u64,
    commitments: &[StorageDigest],
) -> Result<StorageDigest, CryptoError> {
    if usize::try_from(record_count).ok() != Some(commitments.len()) {
        return Err(CryptoError::InvalidEncoding);
    }
    let mut hasher = TrackedStateHasher::new(record_count);
    for commitment in commitments {
        hasher.update(*commitment)?;
    }
    hasher.finalize()
}

/// Incremental digest of one canonically ordered tracked record set.
pub struct TrackedStateHasher {
    hasher: Sha256,
    records_seen: u64,
    expected_records: u64,
}

impl TrackedStateHasher {
    /// Starts a digest bound to the exact record count.
    #[must_use]
    pub fn new(expected_records: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(TRACKED_STATE_LABEL);
        hasher.update(expected_records.to_be_bytes());
        Self {
            hasher,
            records_seen: 0,
            expected_records,
        }
    }

    /// Adds the next canonical record commitment.
    pub fn update(&mut self, commitment: StorageDigest) -> Result<(), CryptoError> {
        if self.records_seen == self.expected_records {
            return Err(CryptoError::LimitExceeded);
        }
        self.hasher.update(commitment.as_bytes());
        self.records_seen = self
            .records_seen
            .checked_add(1)
            .ok_or(CryptoError::Overflow)?;
        Ok(())
    }

    /// Finishes only after the declared count was supplied.
    pub fn finalize(self) -> Result<StorageDigest, CryptoError> {
        if self.records_seen != self.expected_records {
            return Err(CryptoError::InvalidEncoding);
        }
        Ok(StorageDigest(self.hasher.finalize().into()))
    }
}

/// Computes the trusted identifier of a backup signing public key.
pub fn backup_signing_key_id(public_key: &[u8; 32]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(BACKUP_SIGNING_KEY_LABEL, &[public_key])
}

/// Hashes one bounded release-qualification component under an explicit label.
pub fn storage_qualification_component_hash(
    label: &[u8],
    bytes: &[u8],
) -> Result<StorageDigest, CryptoError> {
    if label.is_empty()
        || label.len() > 128
        || !label.iter().all(u8::is_ascii_graphic)
        || bytes.len() > MAX_CONTROL_INPUT_BYTES
    {
        return Err(CryptoError::LimitExceeded);
    }
    labeled_digest(
        b"agenc-chat storage qualification component v1",
        &[label, bytes],
    )
}

/// Incremental hash of a canonically ordered bounded construction plan.
pub struct ConstructionPlanHasher {
    hasher: Sha256,
    entries_seen: u64,
    expected_entries: u64,
    bytes_seen: u64,
    maximum_bytes: u64,
}

impl ConstructionPlanHasher {
    /// Starts a plan hash with its exact entry count and byte ceiling.
    pub fn new(expected_entries: u64, maximum_bytes: u64) -> Result<Self, CryptoError> {
        if maximum_bytes == 0 {
            return Err(CryptoError::LimitExceeded);
        }
        let mut hasher = Sha256::new();
        hasher.update(CONSTRUCTION_PLAN_LABEL);
        hasher.update(expected_entries.to_be_bytes());
        Ok(Self {
            hasher,
            entries_seen: 0,
            expected_entries,
            bytes_seen: 0,
            maximum_bytes,
        })
    }

    /// Adds one complete canonical plan entry.
    pub fn update_entry(&mut self, encoded_entry: &[u8]) -> Result<(), CryptoError> {
        if self.entries_seen == self.expected_entries {
            return Err(CryptoError::LimitExceeded);
        }
        let entry_bytes = u64::try_from(encoded_entry.len()).map_err(|_| CryptoError::Overflow)?;
        let next_bytes = self
            .bytes_seen
            .checked_add(entry_bytes)
            .ok_or(CryptoError::Overflow)?;
        if next_bytes > self.maximum_bytes {
            return Err(CryptoError::LimitExceeded);
        }
        self.hasher.update(encoded_entry);
        self.bytes_seen = next_bytes;
        self.entries_seen = self
            .entries_seen
            .checked_add(1)
            .ok_or(CryptoError::Overflow)?;
        Ok(())
    }

    /// Finishes only after the declared number of entries was supplied.
    pub fn finalize(self) -> Result<StorageDigest, CryptoError> {
        if self.entries_seen != self.expected_entries {
            return Err(CryptoError::InvalidEncoding);
        }
        Ok(StorageDigest(self.hasher.finalize().into()))
    }
}

/// Hashes the canonical completed-operation identity TBS value.
pub fn storage_operation_id(encoded_identity_tbs: &[u8]) -> Result<StorageDigest, CryptoError> {
    labeled_digest(STORAGE_OPERATION_ID_LABEL, &[encoded_identity_tbs])
}

/// Produces a purpose-separated resumability ID for one 32-byte construction key.
pub fn storage_operation_key_id(
    purpose_label: &[u8],
    secret_key: &[u8; 32],
) -> Result<StorageDigest, CryptoError> {
    if purpose_label.is_empty() || purpose_label.len() > 32 {
        return Err(CryptoError::InvalidEncoding);
    }
    let length = u8::try_from(purpose_label.len()).map_err(|_| CryptoError::Overflow)?;
    labeled_digest(
        STORAGE_OPERATION_KEY_ID_LABEL,
        &[&[length], purpose_label, secret_key],
    )
}

/// Hashes one canonical absolute UTF-8 construction output path.
pub fn storage_output_path_hash(path: &str) -> Result<StorageDigest, CryptoError> {
    if path.is_empty() || path.len() > 4_096 {
        return Err(CryptoError::LimitExceeded);
    }
    labeled_digest(STORAGE_OUTPUT_PATH_LABEL, &[path.as_bytes()])
}

/// Returns the fixed version-one restore transform profile hash.
pub fn restore_transform_profile_hash() -> Result<StorageDigest, CryptoError> {
    labeled_digest(RESTORE_PROFILE_LABEL, &[])
}

/// Returns the fixed version-one rekey transform profile hash.
pub fn rekey_transform_profile_hash() -> Result<StorageDigest, CryptoError> {
    labeled_digest(REKEY_PROFILE_LABEL, &[])
}

/// Incremental SHA-256 state for an explicitly bounded backup stream.
pub struct BackupStreamHasher {
    hasher: Sha256,
    bytes_seen: u64,
    maximum_bytes: u64,
}

impl BackupStreamHasher {
    /// Starts a stream digest with a caller-enforced nonzero ceiling.
    pub fn new(maximum_bytes: u64) -> Result<Self, CryptoError> {
        if maximum_bytes == 0 {
            return Err(CryptoError::LimitExceeded);
        }
        Ok(Self {
            hasher: Sha256::new(),
            bytes_seen: 0,
            maximum_bytes,
        })
    }

    /// Adds one bounded chunk without retaining the stream in memory.
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        let chunk_bytes = u64::try_from(chunk.len()).map_err(|_| CryptoError::Overflow)?;
        let next = self
            .bytes_seen
            .checked_add(chunk_bytes)
            .ok_or(CryptoError::Overflow)?;
        if next > self.maximum_bytes {
            return Err(CryptoError::LimitExceeded);
        }
        self.hasher.update(chunk);
        self.bytes_seen = next;
        Ok(())
    }

    /// Finishes the unprefixed SHA-256 stream digest.
    #[must_use]
    pub fn finalize(self) -> StorageDigest {
        StorageDigest(self.hasher.finalize().into())
    }

    /// Returns the exact number of bytes incorporated so far.
    #[must_use]
    pub const fn bytes_seen(&self) -> u64 {
        self.bytes_seen
    }
}
