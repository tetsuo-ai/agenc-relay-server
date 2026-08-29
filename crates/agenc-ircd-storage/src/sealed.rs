//! Canonical SealedRecord envelope and authenticated opening boundary.

use agenc_ircd_crypto::{
    MAX_STORAGE_CIPHERTEXT_BYTES, MAX_STORAGE_PLAINTEXT_BYTES, OpenedStoragePlaintext,
    SealedStorageRecord, StorageDigest, StorageMasterKey, StorageNonce, StorageTable,
    derive_storage_record_key, open_storage_record, seal_storage_record, sealed_record_id,
};

use crate::codec::{Decoder, Encoder};
use crate::{StorageError, StoredKey, TableId};

const ENVELOPE_VERSION: u16 = 1;
const FIXED_ENVELOPE_BYTES: usize = 40;
/// Smallest complete envelope: fixed fields plus one authentication tag.
pub const MIN_SEALED_RECORD_BYTES: usize = 56;
/// Largest complete version-one SealedRecord.
pub const MAX_SEALED_RECORD_BYTES: usize = 16_777_256;

/// Borrowed secret and immutable binding reused for one sealing generation.
pub struct StorageSealContext<'a> {
    master_key: &'a StorageMasterKey,
    binding: agenc_ircd_crypto::DatabaseBinding,
    key_generation: u32,
}

impl<'a> StorageSealContext<'a> {
    /// Creates a sealing context for one nonzero header key generation.
    pub fn new(
        master_key: &'a StorageMasterKey,
        binding: agenc_ircd_crypto::DatabaseBinding,
        key_generation: u32,
    ) -> Result<Self, StorageError> {
        if key_generation == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            master_key,
            binding,
            key_generation,
        })
    }

    /// Seals one bounded plaintext under its table/key/schema binding.
    pub fn seal(
        &self,
        table: TableId,
        record_schema: u32,
        nonce_bytes: [u8; 24],
        stored_key: &StoredKey,
        plaintext: &[u8],
    ) -> Result<SealedRecord, StorageError> {
        if plaintext.len() > MAX_STORAGE_PLAINTEXT_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let crypto_table = StorageTable::new(table.as_u16())?;
        let record_key = derive_storage_record_key(
            self.master_key,
            self.binding,
            crypto_table,
            self.key_generation,
        )?;
        let nonce = StorageNonce::from_reserved_bytes(nonce_bytes);
        let sealed = seal_storage_record(
            &record_key,
            nonce,
            record_schema,
            stored_key.as_bytes(),
            plaintext,
        )?;
        Ok(SealedRecord {
            table,
            record_schema,
            key_generation: self.key_generation,
            nonce: nonce_bytes,
            ciphertext: sealed.as_bytes().to_vec(),
        })
    }
}

/// A complete authenticated persistent envelope.
pub struct SealedRecord {
    table: TableId,
    record_schema: u32,
    key_generation: u32,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl SealedRecord {
    /// Parses a complete envelope without authenticating its plaintext.
    pub fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        if !(MIN_SEALED_RECORD_BYTES..=MAX_SEALED_RECORD_BYTES).contains(&encoded.len()) {
            return Err(StorageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != ENVELOPE_VERSION {
            return Err(StorageError::UnsupportedVersion);
        }
        let table = TableId::from_u16(decoder.u16()?)?;
        let record_schema = decoder.u32()?;
        let key_generation = decoder.u32()?;
        if record_schema == 0 || key_generation == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        let nonce = decoder.array()?;
        let ciphertext = decoder.vector_u32(MAX_STORAGE_CIPHERTEXT_BYTES)?.to_vec();
        decoder.finish()?;
        if ciphertext.len() < 16 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            table,
            record_schema,
            key_generation,
            nonce,
            ciphertext,
        })
    }

    /// Authenticates the envelope before exposing plaintext to a record codec.
    pub fn open(
        &self,
        master_key: &StorageMasterKey,
        binding: agenc_ircd_crypto::DatabaseBinding,
        expected_table: TableId,
        expected_schema: u32,
        expected_key_generation: u32,
        stored_key: &StoredKey,
    ) -> Result<OpenedStoragePlaintext, StorageError> {
        if self.table != expected_table
            || self.record_schema != expected_schema
            || self.key_generation != expected_key_generation
        {
            return Err(StorageError::AuthenticationFailed);
        }
        let table = StorageTable::new(self.table.as_u16())?;
        let key = derive_storage_record_key(master_key, binding, table, self.key_generation)?;
        let nonce = StorageNonce::from_reserved_bytes(self.nonce);
        let ciphertext = SealedStorageRecord::from_bytes(self.ciphertext.clone())?;
        open_storage_record(
            &key,
            &nonce,
            self.record_schema,
            stored_key.as_bytes(),
            &ciphertext,
        )
        .map_err(StorageError::from)
    }

    /// Encodes the exact canonical SealedRecord bytes.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let capacity = FIXED_ENVELOPE_BYTES
            .checked_add(self.ciphertext.len())
            .ok_or(StorageError::Overflow)?;
        let mut encoder = Encoder::with_capacity(capacity, MAX_SEALED_RECORD_BYTES)?;
        encoder.put_u16(ENVELOPE_VERSION)?;
        encoder.put_u16(self.table.as_u16())?;
        encoder.put_u32(self.record_schema)?;
        encoder.put_u32(self.key_generation)?;
        encoder.put_fixed(&self.nonce)?;
        encoder.put_vector_u32(&self.ciphertext)?;
        Ok(encoder.finish())
    }

    /// Computes the stable commitment to the complete encoded envelope.
    pub fn record_id(&self) -> Result<StorageDigest, StorageError> {
        sealed_record_id(&self.encode()?).map_err(StorageError::from)
    }

    /// Returns the registered table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Returns the record schema repeated by backup and integrity entries.
    #[must_use]
    pub const fn record_schema(&self) -> u32 {
        self.record_schema
    }

    /// Returns the active storage-key generation.
    #[must_use]
    pub const fn key_generation(&self) -> u32 {
        self.key_generation
    }
}
