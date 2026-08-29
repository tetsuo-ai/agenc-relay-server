//! Authenticated, bounded, streaming backup format and verification.

use std::io::{BufReader, Read, Write};

use agenc_ircd_crypto::{
    BackupStreamHasher, DatabaseBinding, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature,
    RollbackGuardRootKey, SignatureDomain, StorageDigest, StorageIntegrityContext,
    StorageIntegrityKeys, StorageMasterKey, backup_signing_key_id, derive_storage_integrity_keys,
    sign_canonical, verify_canonical,
};

use crate::codec::{Decoder, Encoder};
use crate::{
    DATABASE_HEADER_BYTES, DatabaseHeader, IntegrityCheckpoint, IntegrityManifest,
    LoginIndexKeyState, LoginIndexStoredKey, NONCE_RESERVATION_BYTES, NonceReservationState,
    ROLLBACK_GUARD_BYTES, RollbackGuard, SealedRecord, StateMeta, StorageConstruction,
    StorageError, StorageOperationCompletion, StoredKey, TableId, logical_record_charge,
    validate_record_plaintext, verify_guard_pair,
};

const BACKUP_MAGIC: &[u8; 21] = b"AGENC-IRCD-BACKUP-V1\0";
const BACKUP_FORMAT: u16 = 1;
const BACKUP_HEADER_BYTES: usize = 736;
const BACKUP_TRAILER_BYTES: usize = 104;
pub(crate) const BACKUP_RECORDS_OFFSET: u64 = 21 + 4 + BACKUP_HEADER_BYTES as u64;
pub(crate) const BACKUP_TRAILER_FRAME_BYTES: u64 = 4 + BACKUP_TRAILER_BYTES as u64;
/// Exact version-one stream bytes excluding numbered records.
pub const BACKUP_FIXED_STREAM_BYTES: u64 = 869;
pub(crate) const MAX_BACKUP_RECORD_BYTES: usize = 16_781_364;
const STATE_META_KEY: &[u8] = b"agenc-chat/state-meta/v1";
const KEY_CHECK_KEY: &[u8] = b"agenc-chat/key-check/v1";

/// Complete signed-backup boundary metadata.
pub struct BackupHeader {
    source_header: DatabaseHeader,
    source_nonce_reservation: NonceReservationState,
    source_rollback_guard: RollbackGuard,
    created_at: u64,
    backup_id: [u8; 16],
    signing_key_id: StorageDigest,
}

impl BackupHeader {
    /// Constructs one verified source boundary and signing identity.
    pub fn new(
        source_header: DatabaseHeader,
        source_nonce_reservation: NonceReservationState,
        source_rollback_guard: RollbackGuard,
        created_at: u64,
        backup_id: [u8; 16],
        signing_public_key: Ed25519PublicKey,
    ) -> Result<Self, StorageError> {
        verify_guard_pair(
            &source_header,
            &source_nonce_reservation,
            &source_rollback_guard,
        )?;
        Ok(Self {
            source_header,
            source_nonce_reservation,
            source_rollback_guard,
            created_at,
            backup_id,
            signing_key_id: backup_signing_key_id(signing_public_key.as_bytes())?,
        })
    }

    /// Encodes the exact fixed backup header.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(BACKUP_HEADER_BYTES, BACKUP_HEADER_BYTES)?;
        encoder.put_u16(BACKUP_FORMAT)?;
        encoder.put_fixed(&self.source_header.encode()?)?;
        encoder.put_fixed(&self.source_nonce_reservation.encode()?)?;
        encoder.put_fixed(&self.source_rollback_guard.encode()?)?;
        encoder.put_u64(self.created_at)?;
        encoder.put_fixed(&self.backup_id)?;
        encoder.put_fixed(self.signing_key_id.as_bytes())?;
        Ok(encoder.finish())
    }

    fn decode(encoded: &[u8], guard_root: &RollbackGuardRootKey) -> Result<Self, StorageError> {
        if encoded.len() != BACKUP_HEADER_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != BACKUP_FORMAT {
            return Err(StorageError::UnsupportedVersion);
        }
        let source_header = DatabaseHeader::decode(decoder.take(DATABASE_HEADER_BYTES)?)?;
        let keys = derive_storage_integrity_keys(
            guard_root,
            StorageIntegrityContext::new(
                source_header.tbs().network_id,
                source_header.tbs().server_id,
                source_header.tbs().database_instance_id,
            ),
        )?;
        let source_nonce_reservation = NonceReservationState::decode_and_verify(
            decoder.take(NONCE_RESERVATION_BYTES)?,
            &keys,
        )?;
        let source_rollback_guard =
            RollbackGuard::decode_and_verify(decoder.take(ROLLBACK_GUARD_BYTES)?, &keys)?;
        let created_at = decoder.u64()?;
        let backup_id = decoder.array()?;
        let signing_key_id = StorageDigest::from_bytes(decoder.array()?);
        decoder.finish()?;
        verify_guard_pair(
            &source_header,
            &source_nonce_reservation,
            &source_rollback_guard,
        )?;
        Ok(Self {
            source_header,
            source_nonce_reservation,
            source_rollback_guard,
            created_at,
            backup_id,
            signing_key_id,
        })
    }

    /// Returns the source database header.
    #[must_use]
    pub const fn source_header(&self) -> &DatabaseHeader {
        &self.source_header
    }

    /// Returns the source reservation boundary.
    #[must_use]
    pub const fn source_nonce_reservation(&self) -> &NonceReservationState {
        &self.source_nonce_reservation
    }

    /// Returns the embedded rollback guard.
    #[must_use]
    pub const fn source_rollback_guard(&self) -> &RollbackGuard {
        &self.source_rollback_guard
    }

    /// Returns the trusted signing-key identifier.
    #[must_use]
    pub const fn signing_key_id(&self) -> StorageDigest {
        self.signing_key_id
    }

    /// Returns the authenticated backup creation second.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }
}

/// One numbered-table record in canonical backup order.
pub struct BackupRecord {
    table: TableId,
    stored_key: StoredKey,
    record_schema: u32,
    sealed_record: Vec<u8>,
}

impl BackupRecord {
    /// Validates duplicated envelope fields and owns one complete row.
    pub fn new(
        table: TableId,
        stored_key: StoredKey,
        record_schema: u32,
        sealed_record: Vec<u8>,
    ) -> Result<Self, StorageError> {
        let sealed = SealedRecord::decode(&sealed_record)?;
        if record_schema == 0 || sealed.table() != table || sealed.record_schema() != record_schema
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            table,
            stored_key,
            record_schema,
            sealed_record,
        })
    }

    /// Parses one full-consumption record body.
    pub fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        if encoded.len() > MAX_BACKUP_RECORD_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(encoded);
        let table = TableId::from_u16(decoder.u16()?)?;
        let stored_key = StoredKey::new(decoder.vector_u32(crate::MAX_STORED_KEY_BYTES)?.to_vec())?;
        let record_schema = decoder.u32()?;
        let sealed_record = decoder.vector_u32(crate::MAX_SEALED_RECORD_BYTES)?.to_vec();
        decoder.finish()?;
        Self::new(table, stored_key, record_schema, sealed_record)
    }

    /// Encodes one canonical record body, excluding its outer length.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let capacity = 14_usize
            .checked_add(self.stored_key.as_bytes().len())
            .and_then(|bytes| bytes.checked_add(self.sealed_record.len()))
            .ok_or(StorageError::Overflow)?;
        let mut encoder = Encoder::with_capacity(capacity, MAX_BACKUP_RECORD_BYTES)?;
        encoder.put_u16(self.table.as_u16())?;
        encoder.put_vector_u32(self.stored_key.as_bytes())?;
        encoder.put_u32(self.record_schema)?;
        encoder.put_vector_u32(&self.sealed_record)?;
        Ok(encoder.finish())
    }

    /// Returns the registered table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Borrows the exact redb key.
    #[must_use]
    pub const fn stored_key(&self) -> &StoredKey {
        &self.stored_key
    }

    /// Returns the repeated record schema.
    #[must_use]
    pub const fn record_schema(&self) -> u32 {
        self.record_schema
    }

    /// Borrows the complete sealed envelope.
    #[must_use]
    pub fn sealed_record(&self) -> &[u8] {
        &self.sealed_record
    }
}

/// Final record count, prefix digest, and dedicated backup signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupTrailer {
    /// Exact number of numbered rows.
    pub record_count: u64,
    /// SHA-256 of all bytes before the trailer length.
    pub stream_digest: StorageDigest,
    /// Signature under the dedicated backup key.
    pub signature: Ed25519Signature,
}

impl BackupTrailer {
    fn encode(self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(BACKUP_TRAILER_BYTES, BACKUP_TRAILER_BYTES)?;
        encoder.put_u64(self.record_count)?;
        encoder.put_fixed(self.stream_digest.as_bytes())?;
        encoder.put_fixed(self.signature.as_bytes())?;
        Ok(encoder.finish())
    }

    fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        if encoded.len() != BACKUP_TRAILER_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let mut decoder = Decoder::new(encoded);
        let value = Self {
            record_count: decoder.u64()?,
            stream_digest: StorageDigest::from_bytes(decoder.array()?),
            signature: Ed25519Signature::from_bytes(decoder.array()?),
        };
        decoder.finish()?;
        Ok(value)
    }
}

/// Streaming writer that never retains record bodies after they are emitted.
pub struct BackupStreamWriter<W: Write> {
    output: W,
    hasher: BackupStreamHasher,
    record_count: u64,
    previous: Option<(TableId, Vec<u8>)>,
    maximum_bytes: u64,
    signing_key_id: StorageDigest,
}

impl<W: Write> BackupStreamWriter<W> {
    /// Writes the magic and fixed verified header.
    pub fn start(
        mut output: W,
        header: &BackupHeader,
        maximum_bytes: u64,
    ) -> Result<Self, StorageError> {
        if maximum_bytes < BACKUP_FIXED_STREAM_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut hasher = BackupStreamHasher::new(maximum_bytes)?;
        write_hashed(&mut output, &mut hasher, BACKUP_MAGIC)?;
        let header_bytes = header.encode()?;
        write_hashed(
            &mut output,
            &mut hasher,
            &u32::try_from(header_bytes.len())
                .map_err(|_| StorageError::Overflow)?
                .to_be_bytes(),
        )?;
        write_hashed(&mut output, &mut hasher, &header_bytes)?;
        Ok(Self {
            output,
            hasher,
            record_count: 0,
            previous: None,
            maximum_bytes,
            signing_key_id: header.signing_key_id(),
        })
    }

    /// Appends one strictly increasing table/key record.
    pub fn write_record(&mut self, record: &BackupRecord) -> Result<(), StorageError> {
        let identity = (record.table(), record.stored_key().as_bytes());
        if self
            .previous
            .as_ref()
            .is_some_and(|(table, key)| (*table, key.as_slice()) >= identity)
        {
            return Err(StorageError::InvalidEncoding);
        }
        let encoded = record.encode()?;
        let length = u32::try_from(encoded.len()).map_err(|_| StorageError::Overflow)?;
        write_hashed(&mut self.output, &mut self.hasher, &length.to_be_bytes())?;
        write_hashed(&mut self.output, &mut self.hasher, &encoded)?;
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        self.previous = Some((record.table(), record.stored_key().as_bytes().to_vec()));
        Ok(())
    }

    /// Signs the complete prefix and writes the fixed trailer outside the digest.
    pub fn finish(
        mut self,
        signing_key: &Ed25519SecretKey,
    ) -> Result<(W, BackupTrailer), StorageError> {
        if backup_signing_key_id(signing_key.public_key().as_bytes())? != self.signing_key_id {
            return Err(StorageError::AuthenticationFailed);
        }
        let prefix_bytes = self.hasher.bytes_seen();
        let final_bytes = prefix_bytes
            .checked_add(4)
            .and_then(|bytes| bytes.checked_add(BACKUP_TRAILER_BYTES as u64))
            .ok_or(StorageError::Overflow)?;
        if final_bytes > self.maximum_bytes {
            return Err(StorageError::LimitExceeded);
        }
        let stream_digest = self.hasher.finalize();
        let signature = sign_canonical(
            signing_key,
            SignatureDomain::BackupSignature,
            stream_digest.as_bytes(),
        )?;
        let trailer = BackupTrailer {
            record_count: self.record_count,
            stream_digest,
            signature,
        };
        self.output
            .write_all(&(BACKUP_TRAILER_BYTES as u32).to_be_bytes())
            .map_err(io_rejected)?;
        self.output
            .write_all(&trailer.encode()?)
            .map_err(io_rejected)?;
        self.output.flush().map_err(io_rejected)?;
        Ok((self.output, trailer))
    }
}

/// One public key allowed by the offline backup trust manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupTrustKey {
    /// Trusted key identifier.
    pub key_id: StorageDigest,
    /// Strict Ed25519 verification key.
    pub public_key: Ed25519PublicKey,
    not_before: u64,
    not_after: u64,
}

impl BackupTrustKey {
    /// Creates an unrestricted test or in-memory trust entry.
    pub fn new(public_key: Ed25519PublicKey) -> Result<Self, StorageError> {
        Ok(Self {
            key_id: backup_signing_key_id(public_key.as_bytes())?,
            public_key,
            not_before: 0,
            not_after: u64::MAX,
        })
    }

    /// Validates one exact offline trust-manifest row.
    pub fn with_validity(
        key_id: StorageDigest,
        public_key: Ed25519PublicKey,
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, StorageError> {
        if not_before >= not_after || backup_signing_key_id(public_key.as_bytes())? != key_id {
            return Err(StorageError::AuthenticationFailed);
        }
        Ok(Self {
            key_id,
            public_key,
            not_before,
            not_after,
        })
    }

    const fn accepts_creation_time(&self, created_at: u64) -> bool {
        created_at >= self.not_before && created_at < self.not_after
    }
}

/// Authenticated facts returned after a complete backup verification pass.
pub struct VerifiedBackup {
    /// Embedded source boundary.
    pub header: BackupHeader,
    /// Verified trailer.
    pub trailer: BackupTrailer,
    /// Exact stream byte length.
    pub stream_bytes: u64,
    /// Recomputed logical database charge.
    pub logical_database_bytes: u64,
    /// Authenticated source StateMeta.
    pub state_meta: StateMeta,
}

struct BackupReconstruction {
    key_check_count: u8,
    state_meta_count: u8,
    login_key_state: Option<LoginIndexKeyState>,
    login_generations: [Option<(u32, u64)>; 2],
    construction_count: u8,
    manifest_count: u64,
    first_manifest_sequence: Option<u64>,
    first_manifest_previous_hash: Option<StorageDigest>,
    last_manifest_sequence: Option<u64>,
    last_manifest_hash: Option<StorageDigest>,
    last_manifest_state_generation: Option<u64>,
    last_manifest_response_count: Option<u64>,
    checkpoints: Vec<CheckpointFacts>,
}

#[derive(Clone, Copy)]
struct CheckpointFacts {
    cut_manifest_sequence: u64,
    checkpoint_hash: StorageDigest,
    previous_checkpoint_hash: StorageDigest,
    cut_manifest_hash: StorageDigest,
}

impl BackupReconstruction {
    fn new() -> Self {
        Self {
            key_check_count: 0,
            state_meta_count: 0,
            login_key_state: None,
            login_generations: [None, None],
            construction_count: 0,
            manifest_count: 0,
            first_manifest_sequence: None,
            first_manifest_previous_hash: None,
            last_manifest_sequence: None,
            last_manifest_hash: None,
            last_manifest_state_generation: None,
            last_manifest_response_count: None,
            checkpoints: Vec::with_capacity(2),
        }
    }

    // agenc-review: focus owner=storage reviewed=2026-08-28 reason=closed reconstruction table matrix keeps singleton and chain accumulators in one pass
    fn observe(
        &mut self,
        record: &BackupRecord,
        plaintext: &[u8],
        database_instance_id: agenc_ircd_types::DatabaseId,
    ) -> Result<(), StorageError> {
        match record.table() {
            TableId::KeyCheck => {
                self.key_check_count = self
                    .key_check_count
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?;
            }
            TableId::LoginIndex => {
                let key = LoginIndexStoredKey::decode(record.stored_key().as_bytes())?;
                let _value = crate::LoginIndexValue::decode(plaintext, &key)?;
                self.observe_login_generation(key.generation())?;
            }
            TableId::StateMeta => {
                self.state_meta_count = self
                    .state_meta_count
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?;
            }
            TableId::IntegrityManifest => {
                let manifest = IntegrityManifest::decode(plaintext)?;
                let fields = manifest.tbs();
                if fields.database_instance_id != database_instance_id
                    || record.stored_key().as_bytes() != fields.manifest_sequence.to_be_bytes()
                {
                    return Err(StorageError::StaleState);
                }
                if let Some(previous_sequence) = self.last_manifest_sequence {
                    if fields.manifest_sequence
                        != previous_sequence
                            .checked_add(1)
                            .ok_or(StorageError::Overflow)?
                        || Some(fields.previous_manifest_hash) != self.last_manifest_hash
                    {
                        return Err(StorageError::StaleState);
                    }
                } else {
                    self.first_manifest_sequence = Some(fields.manifest_sequence);
                    self.first_manifest_previous_hash = Some(fields.previous_manifest_hash);
                }
                self.manifest_count = self
                    .manifest_count
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?;
                self.last_manifest_sequence = Some(fields.manifest_sequence);
                self.last_manifest_hash = Some(manifest.manifest_hash());
                self.last_manifest_state_generation = Some(fields.resulting_state_generation);
                self.last_manifest_response_count =
                    Some(fields.resulting_account_service_response_count);
            }
            TableId::IntegrityCheckpoint => {
                if self.checkpoints.len() == 2 {
                    return Err(StorageError::LimitExceeded);
                }
                let checkpoint = IntegrityCheckpoint::decode(plaintext)?;
                let fields = checkpoint.tbs();
                if fields.database_instance_id != database_instance_id
                    || record.stored_key().as_bytes() != fields.cut_manifest_sequence.to_be_bytes()
                {
                    return Err(StorageError::StaleState);
                }
                self.checkpoints.push(CheckpointFacts {
                    cut_manifest_sequence: fields.cut_manifest_sequence,
                    checkpoint_hash: checkpoint.checkpoint_hash(),
                    previous_checkpoint_hash: fields.previous_checkpoint_hash,
                    cut_manifest_hash: fields.cut_manifest_hash,
                });
            }
            TableId::LoginIndexKeyState => {
                if self.login_key_state.is_some() {
                    return Err(StorageError::StaleState);
                }
                self.login_key_state = Some(LoginIndexKeyState::decode(plaintext)?);
            }
            TableId::StorageConstruction => {
                let _marker = StorageConstruction::decode(plaintext)?;
                self.construction_count = self
                    .construction_count
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?;
            }
            TableId::StorageOperation => {
                let completion = StorageOperationCompletion::decode(plaintext)?;
                if record.stored_key().as_bytes() != completion.storage_operation_id.as_bytes() {
                    return Err(StorageError::StaleState);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn observe_login_generation(&mut self, generation: u32) -> Result<(), StorageError> {
        for entry in &mut self.login_generations {
            match entry {
                Some((known, count)) if *known == generation => {
                    *count = count.checked_add(1).ok_or(StorageError::Overflow)?;
                    return Ok(());
                }
                None => {
                    *entry = Some((generation, 1));
                    return Ok(());
                }
                Some(_) => {}
            }
        }
        Err(StorageError::StaleState)
    }

    // agenc-review: focus owner=storage reviewed=2026-08-28 reason=closed backup completion matrix binds login manifest and checkpoint invariants together
    fn finish(self, state_meta: &StateMeta) -> Result<(), StorageError> {
        if self.key_check_count != 1 || self.state_meta_count != 1 || self.construction_count != 0 {
            return Err(StorageError::StaleState);
        }
        let login_state = self.login_key_state.ok_or(StorageError::StaleState)?;
        let mut previous_count = 0_u64;
        for (generation, count) in self.login_generations.into_iter().flatten() {
            if generation == login_state.current_generation() {
                continue;
            }
            if login_state
                .previous()
                .is_some_and(|(previous, _)| previous == generation)
            {
                previous_count = count;
            } else {
                return Err(StorageError::StaleState);
            }
        }
        if login_state
            .previous()
            .map_or(previous_count != 0, |(_, expected)| {
                expected != previous_count
            })
        {
            return Err(StorageError::StaleState);
        }
        let state = state_meta.tbs();
        let expected_manifest_count = state
            .manifest_sequence
            .checked_sub(state.checkpoint_manifest_sequence)
            .ok_or(StorageError::StaleState)?;
        if self.manifest_count != expected_manifest_count {
            return Err(StorageError::StaleState);
        }
        if expected_manifest_count == 0 {
            if self.last_manifest_sequence.is_some() {
                return Err(StorageError::StaleState);
            }
        } else if self.first_manifest_sequence
            != Some(
                state
                    .checkpoint_manifest_sequence
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?,
            )
            || self.last_manifest_sequence != Some(state.manifest_sequence)
            || self.last_manifest_hash != Some(state.latest_manifest_hash)
            || self.last_manifest_state_generation != Some(state.state_generation)
            || self.last_manifest_response_count != Some(state.account_service_response_count)
        {
            return Err(StorageError::StaleState);
        }
        let active = self
            .checkpoints
            .iter()
            .find(|checkpoint| {
                checkpoint.cut_manifest_sequence == state.checkpoint_manifest_sequence
                    && checkpoint.checkpoint_hash == state.checkpoint_hash
            })
            .ok_or(StorageError::StaleState)?;
        let zero = StorageDigest::from_bytes([0_u8; 32]);
        if state.checkpoint_manifest_sequence == 0 {
            if self.checkpoints.len() != 1 || active.previous_checkpoint_hash != zero {
                return Err(StorageError::StaleState);
            }
        } else if self.checkpoints.len() != 2
            || !self
                .checkpoints
                .iter()
                .any(|checkpoint| checkpoint.checkpoint_hash == active.previous_checkpoint_hash)
        {
            return Err(StorageError::StaleState);
        }
        let expected_head = self
            .first_manifest_previous_hash
            .unwrap_or(state.latest_manifest_hash);
        if active.cut_manifest_hash != expected_head {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }
}

/// Durable, post-write-verified backup completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupReceipt {
    /// Exact verified stream length.
    pub stream_bytes: u64,
    /// Exact verified numbered-row count.
    pub record_count: u64,
    /// Complete signed stream digest.
    pub stream_digest: StorageDigest,
}

/// Fully streams, decrypts, authenticates, and size-checks one backup.
// agenc-review: focus owner=storage reviewed=2026-08-27 reason=single-pass backup grammar keeps digest and EOF state co-located
pub fn verify_backup<R: Read>(
    mut input: R,
    source_master_key: &StorageMasterKey,
    source_guard_root: &RollbackGuardRootKey,
    trusted_keys: &[BackupTrustKey],
    maximum_bytes: u64,
) -> Result<VerifiedBackup, StorageError> {
    verify_backup_reader(
        &mut input,
        source_master_key,
        source_guard_root,
        trusted_keys,
        maximum_bytes,
    )
}

fn verify_backup_reader(
    input: &mut dyn Read,
    source_master_key: &StorageMasterKey,
    source_guard_root: &RollbackGuardRootKey,
    trusted_keys: &[BackupTrustKey],
    maximum_bytes: u64,
) -> Result<VerifiedBackup, StorageError> {
    if trusted_keys.is_empty() || trusted_keys.len() > 1_024 {
        return Err(StorageError::LimitExceeded);
    }
    let mut input = BufReader::new(input);
    let mut hasher = BackupStreamHasher::new(maximum_bytes)?;
    let header = read_backup_header(&mut input, &mut hasher, source_guard_root)?;
    let trusted_public_key = trusted_backup_key(&header, trusted_keys)?;
    let mut verification =
        BackupRecordVerification::new(&header, source_master_key, source_guard_root)?;
    let trailer_bytes = read_backup_records(&mut input, &mut hasher, &mut verification)?;
    let prefix_bytes = hasher.bytes_seen();
    let stream_bytes = prefix_bytes
        .checked_add(4)
        .and_then(|bytes| bytes.checked_add(BACKUP_TRAILER_BYTES as u64))
        .ok_or(StorageError::Overflow)?;
    if stream_bytes > maximum_bytes {
        return Err(StorageError::LimitExceeded);
    }
    let prefix_digest = hasher.finalize();
    let trailer = BackupTrailer::decode(&trailer_bytes)?;
    if trailer.record_count != verification.record_count || trailer.stream_digest != prefix_digest {
        return Err(StorageError::AuthenticationFailed);
    }
    verify_canonical(
        trusted_public_key,
        SignatureDomain::BackupSignature,
        trailer.stream_digest.as_bytes(),
        trailer.signature,
    )?;
    let (logical_database_bytes, state_meta) = verification.finish(stream_bytes)?;
    Ok(VerifiedBackup {
        header,
        trailer,
        stream_bytes,
        logical_database_bytes,
        state_meta,
    })
}

fn read_backup_header<R: Read>(
    input: &mut R,
    hasher: &mut BackupStreamHasher,
    source_guard_root: &RollbackGuardRootKey,
) -> Result<BackupHeader, StorageError> {
    if &read_exact_hashed::<21, _>(input, hasher)? != BACKUP_MAGIC {
        return Err(StorageError::InvalidEncoding);
    }
    let header_length = u32::from_be_bytes(read_exact_hashed::<4, _>(input, hasher)?);
    if usize::try_from(header_length).map_err(|_| StorageError::Overflow)? != BACKUP_HEADER_BYTES {
        return Err(StorageError::InvalidEncoding);
    }
    BackupHeader::decode(
        &read_vector_hashed(input, hasher, BACKUP_HEADER_BYTES)?,
        source_guard_root,
    )
}

fn trusted_backup_key(
    header: &BackupHeader,
    trusted_keys: &[BackupTrustKey],
) -> Result<Ed25519PublicKey, StorageError> {
    let mut trusted_public_key = None;
    for entry in trusted_keys {
        if entry.key_id == header.signing_key_id()
            && entry.accepts_creation_time(header.created_at())
            && trusted_public_key.replace(entry.public_key).is_some()
        {
            return Err(StorageError::AuthenticationFailed);
        }
    }
    let trusted_public_key = trusted_public_key.ok_or(StorageError::AuthenticationFailed)?;
    if backup_signing_key_id(trusted_public_key.as_bytes())? != header.signing_key_id() {
        return Err(StorageError::AuthenticationFailed);
    }
    Ok(trusted_public_key)
}

struct BackupRecordVerification<'a> {
    header: &'a BackupHeader,
    source_master_key: &'a StorageMasterKey,
    binding: DatabaseBinding,
    integrity_keys: StorageIntegrityKeys,
    record_count: u64,
    logical_database_bytes: u64,
    previous: Option<(TableId, Vec<u8>)>,
    state_meta: Option<StateMeta>,
    key_check_seen: bool,
    reconstruction: BackupReconstruction,
}

impl<'a> BackupRecordVerification<'a> {
    fn new(
        header: &'a BackupHeader,
        source_master_key: &'a StorageMasterKey,
        source_guard_root: &RollbackGuardRootKey,
    ) -> Result<Self, StorageError> {
        let source_header = header.source_header();
        let integrity_keys = derive_storage_integrity_keys(
            source_guard_root,
            StorageIntegrityContext::new(
                source_header.tbs().network_id,
                source_header.tbs().server_id,
                source_header.tbs().database_instance_id,
            ),
        )?;
        Ok(Self {
            header,
            source_master_key,
            binding: database_binding(source_header),
            integrity_keys,
            record_count: 0,
            logical_database_bytes: meta_logical_bytes()?,
            previous: None,
            state_meta: None,
            key_check_seen: false,
            reconstruction: BackupReconstruction::new(),
        })
    }

    fn observe(&mut self, record: &BackupRecord) -> Result<(), StorageError> {
        let identity = (record.table(), record.stored_key().as_bytes());
        if self
            .previous
            .as_ref()
            .is_some_and(|(table, key)| (*table, key.as_slice()) >= identity)
        {
            return Err(StorageError::InvalidEncoding);
        }
        let sealed = SealedRecord::decode(record.sealed_record())?;
        let source_generation = self.header.source_header().tbs().storage_key_generation;
        if sealed.key_generation() != source_generation {
            return Err(StorageError::AuthenticationFailed);
        }
        let plaintext = sealed.open(
            self.source_master_key,
            self.binding,
            record.table(),
            record.record_schema(),
            source_generation,
            record.stored_key(),
        )?;
        let plaintext = plaintext.expose_for_storage_codec();
        validate_record_plaintext(
            record.table(),
            record.stored_key(),
            record.record_schema(),
            plaintext,
        )?;
        self.reconstruction.observe(
            record,
            plaintext,
            self.header.source_header().tbs().database_instance_id,
        )?;
        self.observe_key_check(record, &sealed, plaintext)?;
        self.observe_state_meta(record, &sealed, plaintext)?;
        self.logical_database_bytes = self
            .logical_database_bytes
            .checked_add(logical_record_charge(
                record.stored_key().as_bytes().len(),
                record.sealed_record().len(),
            )?)
            .ok_or(StorageError::Overflow)?;
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        self.previous = Some((record.table(), record.stored_key().as_bytes().to_vec()));
        Ok(())
    }

    fn observe_key_check(
        &mut self,
        record: &BackupRecord,
        sealed: &SealedRecord,
        plaintext: &[u8],
    ) -> Result<(), StorageError> {
        if record.table() != TableId::KeyCheck || record.stored_key().as_bytes() != KEY_CHECK_KEY {
            return Ok(());
        }
        if self.key_check_seen
            || sealed.record_id()? != self.header.source_header().key_check_object_id()
            || plaintext
                != self
                    .header
                    .source_header()
                    .tbs()
                    .key_check_plaintext()?
                    .as_bytes()
        {
            return Err(StorageError::AuthenticationFailed);
        }
        self.key_check_seen = true;
        Ok(())
    }

    fn observe_state_meta(
        &mut self,
        record: &BackupRecord,
        sealed: &SealedRecord,
        plaintext: &[u8],
    ) -> Result<(), StorageError> {
        if record.table() != TableId::StateMeta || record.stored_key().as_bytes() != STATE_META_KEY
        {
            return Ok(());
        }
        if self.state_meta.is_some()
            || sealed.record_id()?
                != self
                    .header
                    .source_nonce_reservation()
                    .tbs()
                    .state_meta_record_id
        {
            return Err(StorageError::StaleState);
        }
        self.state_meta = Some(StateMeta::decode_and_verify(
            plaintext,
            self.header.source_header().complete_hash()?,
            &self.integrity_keys,
        )?);
        Ok(())
    }

    fn finish(self, stream_bytes: u64) -> Result<(u64, StateMeta), StorageError> {
        let state_meta = self.state_meta.ok_or(StorageError::InvalidEncoding)?;
        let reservation = self.header.source_nonce_reservation().tbs();
        if !self.key_check_seen
            || state_meta.tbs().logical_database_bytes != self.logical_database_bytes
            || state_meta.tbs().backup_stream_bytes != stream_bytes
            || state_meta.tbs().storage_commit_sequence != reservation.storage_commit_sequence
            || state_meta.tbs().manifest_sequence != reservation.manifest_sequence
            || state_meta.tbs().state_generation != reservation.state_generation
        {
            return Err(StorageError::StaleState);
        }
        self.reconstruction.finish(&state_meta)?;
        Ok((self.logical_database_bytes, state_meta))
    }
}

fn read_backup_records<R: std::io::BufRead>(
    input: &mut R,
    hasher: &mut BackupStreamHasher,
    verification: &mut BackupRecordVerification<'_>,
) -> Result<Vec<u8>, StorageError> {
    loop {
        let mut length_bytes = [0_u8; 4];
        input.read_exact(&mut length_bytes).map_err(io_rejected)?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| StorageError::Overflow)?;
        if length == 0 || length > MAX_BACKUP_RECORD_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(length)
            .map_err(|_| StorageError::AllocationFailed)?;
        encoded.resize(length, 0);
        input.read_exact(&mut encoded).map_err(io_rejected)?;
        if length == BACKUP_TRAILER_BYTES && input.fill_buf().map_err(io_rejected)?.is_empty() {
            return Ok(encoded);
        }
        hasher.update(&length_bytes)?;
        hasher.update(&encoded)?;
        verification.observe(&BackupRecord::decode(&encoded)?)?;
    }
}

/// Computes the exact complete stream length from canonical numbered rows.
pub fn backup_stream_bytes<'a>(
    records: impl IntoIterator<Item = (&'a StoredKey, usize)>,
) -> Result<u64, StorageError> {
    let mut bytes = BACKUP_FIXED_STREAM_BYTES;
    for (key, sealed_bytes) in records {
        bytes = bytes
            .checked_add(backup_record_charge(key.as_bytes().len(), sealed_bytes)?)
            .ok_or(StorageError::Overflow)?;
    }
    Ok(bytes)
}

fn backup_record_charge(key_bytes: usize, sealed_bytes: usize) -> Result<u64, StorageError> {
    let logical = logical_record_charge(key_bytes, sealed_bytes)?;
    logical.checked_add(8).ok_or(StorageError::Overflow)
}

fn meta_logical_bytes() -> Result<u64, StorageError> {
    crate::logical_meta_charge(b"header/v1".len(), DATABASE_HEADER_BYTES)?
        .checked_add(crate::logical_meta_charge(
            b"nonce-reservation/v1".len(),
            NONCE_RESERVATION_BYTES,
        )?)
        .ok_or(StorageError::Overflow)
}

fn write_hashed<W: Write>(
    output: &mut W,
    hasher: &mut BackupStreamHasher,
    bytes: &[u8],
) -> Result<(), StorageError> {
    hasher.update(bytes)?;
    output.write_all(bytes).map_err(io_rejected)
}

fn read_exact_hashed<const N: usize, R: Read>(
    input: &mut R,
    hasher: &mut BackupStreamHasher,
) -> Result<[u8; N], StorageError> {
    let mut bytes = [0_u8; N];
    input.read_exact(&mut bytes).map_err(io_rejected)?;
    hasher.update(&bytes)?;
    Ok(bytes)
}

fn read_vector_hashed<R: Read>(
    input: &mut R,
    hasher: &mut BackupStreamHasher,
    length: usize,
) -> Result<Vec<u8>, StorageError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| StorageError::AllocationFailed)?;
    bytes.resize(length, 0);
    input.read_exact(&mut bytes).map_err(io_rejected)?;
    hasher.update(&bytes)?;
    Ok(bytes)
}

fn io_rejected(_error: std::io::Error) -> StorageError {
    StorageError::FilesystemRejected
}

fn database_binding(header: &DatabaseHeader) -> DatabaseBinding {
    DatabaseBinding::new(
        header.tbs().network_id,
        header.tbs().server_id,
        header.tbs().server_incarnation,
        header.tbs().database_instance_id,
    )
}
