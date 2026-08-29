//! XChaCha20-Poly1305 storage-record adapter.

use agenc_ircd_types::{DatabaseId, NetworkId, ServerId, ServerIncarnation};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::secret::SecretBytes;

const DATABASE_MAGIC: &[u8; 16] = b"AGENC-IRCD-DB\0\0\0";
const DATABASE_FORMAT: u16 = 1;
const STORAGE_SALT_LABEL: &[u8] = b"agenc-chat storage salt v1";
const STORAGE_RECORD_KEY_LABEL: &[u8] = b"agenc-chat storage record key v1";
const STORAGE_INDEX_KEY_LABEL: &[u8] = b"agenc-chat storage table index key v1";
const SEALED_RECORD_LABEL: &[u8] = b"agenc-chat sealed record v1";

/// Exact encoded size of a version-one immutable database binding.
pub const DATABASE_BINDING_BYTES: usize = 98;
/// Maximum semantic database key admitted to keyed indexing.
pub const MAX_STORAGE_KEY_BYTES: usize = 4_096;
/// Maximum plaintext that leaves room for the complete authentication tag.
pub const MAX_STORAGE_PLAINTEXT_BYTES: usize = 16_777_200;
/// Maximum stored ciphertext, including the 16-byte authentication tag.
pub const MAX_STORAGE_CIPHERTEXT_BYTES: usize = 16_777_216;

/// Immutable identity bound into every encrypted database record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseBinding {
    network_id: NetworkId,
    server_id: ServerId,
    server_incarnation: ServerIncarnation,
    database_instance_id: DatabaseId,
}

impl DatabaseBinding {
    /// Constructs the fixed version-one database binding.
    #[must_use]
    pub const fn new(
        network_id: NetworkId,
        server_id: ServerId,
        server_incarnation: ServerIncarnation,
        database_instance_id: DatabaseId,
    ) -> Self {
        Self {
            network_id,
            server_id,
            server_incarnation,
            database_instance_id,
        }
    }

    /// Encodes the exact fixed-width TLS structure.
    pub fn encode(self) -> Result<[u8; DATABASE_BINDING_BYTES], CryptoError> {
        let mut encoded = [0_u8; DATABASE_BINDING_BYTES];
        let mut cursor = 0_usize;
        put_fixed(&mut encoded, &mut cursor, DATABASE_MAGIC)?;
        put_fixed(&mut encoded, &mut cursor, &DATABASE_FORMAT.to_be_bytes())?;
        put_fixed(&mut encoded, &mut cursor, self.network_id.as_bytes())?;
        put_fixed(&mut encoded, &mut cursor, self.server_id.as_bytes())?;
        put_fixed(
            &mut encoded,
            &mut cursor,
            self.server_incarnation.as_bytes(),
        )?;
        put_fixed(
            &mut encoded,
            &mut cursor,
            self.database_instance_id.as_bytes(),
        )?;
        if cursor != DATABASE_BINDING_BYTES {
            return Err(CryptoError::InvalidEncoding);
        }
        Ok(encoded)
    }
}

fn put_fixed(output: &mut [u8], cursor: &mut usize, bytes: &[u8]) -> Result<(), CryptoError> {
    let end = cursor
        .checked_add(bytes.len())
        .ok_or(CryptoError::Overflow)?;
    let destination = output
        .get_mut(*cursor..end)
        .ok_or(CryptoError::InvalidEncoding)?;
    destination.copy_from_slice(bytes);
    *cursor = end;
    Ok(())
}

/// A validated version-one storage table identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageTable(u16);

impl StorageTable {
    /// Validates the closed table-ID registry, including key-check table zero.
    pub const fn new(table_id: u16) -> Result<Self, CryptoError> {
        if table_id <= 26 {
            Ok(Self(table_id))
        } else {
            Err(CryptoError::InvalidEncoding)
        }
    }

    /// Returns the registered numeric table ID.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// An externally provisioned storage master key.
///
/// ```compile_fail
/// use agenc_ircd_crypto::StorageMasterKey;
/// fn require_clone<T: Clone>() {}
/// require_clone::<StorageMasterKey>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_crypto::StorageMasterKey;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<StorageMasterKey>();
/// ```
pub struct StorageMasterKey(SecretBytes<32>);

impl StorageMasterKey {
    /// Takes ownership of the exact 32-byte master key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// Compares two master keys without exposing either key or exiting early.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.0.as_bytes().ct_eq(other.0.as_bytes()))
    }

    /// Derives the source-role resumability ID without exposing this key.
    pub fn source_operation_key_id(
        &self,
    ) -> Result<crate::storage_integrity::StorageDigest, CryptoError> {
        crate::storage_integrity::storage_operation_key_id(b"source-master", self.0.as_bytes())
    }

    /// Derives the target-role resumability ID without exposing this key.
    pub fn target_operation_key_id(
        &self,
    ) -> Result<crate::storage_integrity::StorageDigest, CryptoError> {
        crate::storage_integrity::storage_operation_key_id(b"target-master", self.0.as_bytes())
    }
}

/// One table- and generation-specific storage-record key.
pub struct StorageRecordKey {
    bytes: SecretBytes<32>,
    binding: DatabaseBinding,
    table: StorageTable,
    key_generation: u32,
}

/// One independently reserved, uniformly random storage nonce.
pub struct StorageNonce(SecretBytes<24>);

impl StorageNonce {
    /// Takes ownership of bytes already reserved by the Stage 05 nonce ledger.
    #[must_use]
    pub fn from_reserved_bytes(bytes: [u8; 24]) -> Self {
        Self(SecretBytes::new(bytes))
    }
}

/// A full keyed database lookup digest.
///
/// The stored lookup key deliberately has no formatting or cloning surface.
///
/// ```compile_fail
/// use agenc_ircd_crypto::StorageIndex;
/// fn require_clone<T: Clone>() {}
/// require_clone::<StorageIndex>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_crypto::StorageIndex;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<StorageIndex>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_crypto::StorageIndex;
/// fn require_hash<T: core::hash::Hash>() {}
/// require_hash::<StorageIndex>();
/// ```
pub struct StorageIndex(Zeroizing<[u8; 32]>);

impl StorageIndex {
    /// Borrows the complete keyed digest only for the stored database key.
    #[must_use]
    pub fn expose_for_storage_key(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compares two private storage indices without data-dependent early exit.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.0.as_ref().ct_eq(other.0.as_ref()))
    }
}

impl PartialEq for StorageIndex {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl Eq for StorageIndex {}

/// Authenticated storage ciphertext with its full Poly1305 tag.
pub struct SealedStorageRecord(Vec<u8>);

impl SealedStorageRecord {
    /// Constructs a ciphertext read from a bounded storage envelope.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if !(16..=MAX_STORAGE_CIPHERTEXT_BYTES).contains(&bytes.len()) {
            return Err(CryptoError::InvalidEncoding);
        }
        Ok(Self(bytes))
    }

    /// Borrows the complete ciphertext and tag.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Opened storage plaintext zeroized on drop.
pub struct OpenedStoragePlaintext(Zeroizing<Vec<u8>>);

impl OpenedStoragePlaintext {
    /// Borrows the plaintext at the storage codec boundary.
    #[must_use]
    pub fn expose_for_storage_codec(&self) -> &[u8] {
        &self.0
    }
}

/// Derives the exact table- and generation-scoped record key.
pub fn derive_storage_record_key(
    master_key: &StorageMasterKey,
    binding: DatabaseBinding,
    table: StorageTable,
    key_generation: u32,
) -> Result<StorageRecordKey, CryptoError> {
    if key_generation == 0 {
        return Err(CryptoError::InvalidEncoding);
    }
    let key = derive_storage_subkey(
        master_key,
        binding,
        table,
        key_generation,
        STORAGE_RECORD_KEY_LABEL,
    )?;
    Ok(StorageRecordKey {
        bytes: key,
        binding,
        table,
        key_generation,
    })
}

/// Derives and applies the exact table-index HMAC to a semantic key.
pub fn derive_storage_index(
    master_key: &StorageMasterKey,
    binding: DatabaseBinding,
    table: StorageTable,
    key_generation: u32,
    canonical_semantic_key: &[u8],
) -> Result<StorageIndex, CryptoError> {
    if key_generation == 0 || canonical_semantic_key.len() > MAX_STORAGE_KEY_BYTES {
        return Err(CryptoError::LimitExceeded);
    }
    let index_key = derive_storage_subkey(
        master_key,
        binding,
        table,
        key_generation,
        STORAGE_INDEX_KEY_LABEL,
    )?;
    let mut mac = Hmac::<Sha256>::new_from_slice(index_key.as_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    mac.update(canonical_semantic_key);
    Ok(StorageIndex(Zeroizing::new(
        mac.finalize().into_bytes().into(),
    )))
}

fn derive_storage_subkey(
    master_key: &StorageMasterKey,
    binding: DatabaseBinding,
    table: StorageTable,
    key_generation: u32,
    label: &[u8],
) -> Result<SecretBytes<32>, CryptoError> {
    let binding_bytes = binding.encode()?;
    let mut salt_hash = Sha256::new();
    salt_hash.update(STORAGE_SALT_LABEL);
    salt_hash.update(binding_bytes);
    let salt: [u8; 32] = salt_hash.finalize().into();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), master_key.0.as_bytes());
    let mut info = [0_u8; 47];
    let needed = label.len().checked_add(6).ok_or(CryptoError::Overflow)?;
    let Some(info) = info.get_mut(..needed) else {
        return Err(CryptoError::InvalidEncoding);
    };
    let mut cursor = 0_usize;
    put_fixed(info, &mut cursor, label)?;
    put_fixed(info, &mut cursor, &table.value().to_be_bytes())?;
    put_fixed(info, &mut cursor, &key_generation.to_be_bytes())?;
    let mut output = SecretBytes::new([0_u8; 32]);
    hkdf.expand(info, output.as_mut_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    Ok(output)
}

/// Seals one bounded plaintext using the nonce reserved for this operation.
pub fn seal_storage_record(
    key: &StorageRecordKey,
    nonce: StorageNonce,
    record_schema: u32,
    stored_database_key: &[u8],
    plaintext: &[u8],
) -> Result<SealedStorageRecord, CryptoError> {
    validate_record_input(record_schema, stored_database_key, plaintext.len())?;
    let aad = record_aad(key, record_schema, stored_database_key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes.as_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let nonce_array = XNonce::try_from(nonce.0.as_bytes().as_slice())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let ciphertext = cipher
        .encrypt(
            &nonce_array,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    SealedStorageRecord::from_bytes(ciphertext)
}

/// Opens one record only after validating its complete authentication tag.
pub fn open_storage_record(
    key: &StorageRecordKey,
    nonce: &StorageNonce,
    record_schema: u32,
    stored_database_key: &[u8],
    ciphertext: &SealedStorageRecord,
) -> Result<OpenedStoragePlaintext, CryptoError> {
    let plaintext_len = ciphertext
        .as_bytes()
        .len()
        .checked_sub(16)
        .ok_or(CryptoError::InvalidEncoding)?;
    validate_record_input(record_schema, stored_database_key, plaintext_len)?;
    let aad = record_aad(key, record_schema, stored_database_key)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes.as_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let nonce_array = XNonce::try_from(nonce.0.as_bytes().as_slice())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce_array,
                Payload {
                    msg: ciphertext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    Ok(OpenedStoragePlaintext(plaintext))
}

fn validate_record_input(
    record_schema: u32,
    stored_database_key: &[u8],
    plaintext_len: usize,
) -> Result<(), CryptoError> {
    if record_schema == 0 || stored_database_key.len() > MAX_STORAGE_KEY_BYTES {
        return Err(CryptoError::InvalidEncoding);
    }
    if plaintext_len > MAX_STORAGE_PLAINTEXT_BYTES {
        return Err(CryptoError::LimitExceeded);
    }
    Ok(())
}

fn record_aad(
    key: &StorageRecordKey,
    record_schema: u32,
    stored_database_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let stored_key_digest: [u8; 32] = Sha256::digest(stored_database_key).into();
    let capacity = SEALED_RECORD_LABEL
        .len()
        .checked_add(DATABASE_BINDING_BYTES)
        .and_then(|length| length.checked_add(42))
        .ok_or(CryptoError::Overflow)?;
    let mut aad = Vec::new();
    aad.try_reserve_exact(capacity)
        .map_err(|_| CryptoError::AllocationFailed)?;
    aad.extend_from_slice(SEALED_RECORD_LABEL);
    aad.extend_from_slice(&key.binding.encode()?);
    aad.extend_from_slice(&key.table.value().to_be_bytes());
    aad.extend_from_slice(&record_schema.to_be_bytes());
    aad.extend_from_slice(&key.key_generation.to_be_bytes());
    aad.extend_from_slice(&stored_key_digest);
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use agenc_ircd_types::{DatabaseId, NetworkId, ServerId, ServerIncarnation};

    use super::{
        CryptoError, DatabaseBinding, MAX_STORAGE_CIPHERTEXT_BYTES, MAX_STORAGE_PLAINTEXT_BYTES,
        SealedStorageRecord, StorageMasterKey, StorageNonce, StorageTable,
        derive_storage_record_key, derive_storage_subkey, open_storage_record, put_fixed,
        seal_storage_record, validate_record_input,
    };

    fn binding() -> DatabaseBinding {
        DatabaseBinding::new(
            NetworkId::from_bytes([1_u8; 32]),
            ServerId::from_bytes([2_u8; 16]),
            ServerIncarnation::from_bytes([3_u8; 16]),
            DatabaseId::from_bytes([4_u8; 16]),
        )
    }

    #[test]
    fn rejects_changed_aad_and_tampering() -> Result<(), Box<dyn core::error::Error>> {
        let table = StorageTable::new(3)?;
        let key = derive_storage_record_key(
            &StorageMasterKey::from_bytes([7_u8; 32]),
            binding(),
            table,
            1,
        )?;
        let nonce = StorageNonce::from_reserved_bytes([9_u8; 24]);
        let sealed = seal_storage_record(&key, nonce, 1, b"record-key", b"secret value")?;
        let opening_nonce = StorageNonce::from_reserved_bytes([9_u8; 24]);
        let opened = open_storage_record(&key, &opening_nonce, 1, b"record-key", &sealed)?;
        assert_eq!(opened.expose_for_storage_codec(), b"secret value");
        assert!(open_storage_record(&key, &opening_nonce, 1, b"other-key", &sealed).is_err());
        Ok(())
    }

    #[test]
    fn fixed_buffer_and_plaintext_limits_fail_closed() {
        let mut output = [9_u8; 1];
        let mut overflowing_cursor = usize::MAX;
        assert_eq!(
            put_fixed(&mut output, &mut overflowing_cursor, &[1]),
            Err(CryptoError::Overflow)
        );
        assert_eq!(output, [9]);
        assert_eq!(overflowing_cursor, usize::MAX);

        let mut short_cursor = 1_usize;
        assert_eq!(
            put_fixed(&mut output, &mut short_cursor, &[1]),
            Err(CryptoError::InvalidEncoding)
        );
        assert_eq!(output, [9]);
        assert_eq!(short_cursor, 1);

        assert_eq!(
            validate_record_input(1, b"key", MAX_STORAGE_PLAINTEXT_BYTES + 1),
            Err(CryptoError::LimitExceeded)
        );
        assert_eq!(
            derive_storage_subkey(
                &StorageMasterKey::from_bytes([7_u8; 32]),
                binding(),
                StorageTable(3),
                1,
                &[0_u8; 42],
            )
            .err(),
            Some(CryptoError::InvalidEncoding)
        );
    }

    #[test]
    fn stored_ciphertext_requires_a_full_tag_and_bounded_body() {
        assert_eq!(
            SealedStorageRecord::from_bytes(vec![0_u8; 15]).err(),
            Some(CryptoError::InvalidEncoding)
        );
        assert_eq!(
            SealedStorageRecord::from_bytes(vec![0_u8; MAX_STORAGE_CIPHERTEXT_BYTES + 1]).err(),
            Some(CryptoError::InvalidEncoding)
        );
        assert!(SealedStorageRecord::from_bytes(vec![0_u8; 16]).is_ok());
    }
}
