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
    verify_guard_pair,
};

const BACKUP_MAGIC: &[u8; 21] = b"AGENC-IRCD-BACKUP-V1\0";
const BACKUP_FORMAT: u16 = 1;
const BACKUP_HEADER_BYTES: usize = 736;
const BACKUP_TRAILER_BYTES: usize = 104;
pub(crate) const BACKUP_RECORDS_OFFSET: u64 = 21 + 4 + BACKUP_HEADER_BYTES as u64;
pub(crate) const BACKUP_TRAILER_FRAME_BYTES: u64 = 4 + BACKUP_TRAILER_BYTES as u64;
/// Exact version-one stream bytes excluding numbered records.
pub const BACKUP_FIXED_STREAM_BYTES: u64 = 869;
/// Largest encoded record body: table, key length, key, schema, sealed length,
/// and the sealed bytes, matching `BackupRecord::encode` field for field.
pub(crate) const MAX_BACKUP_RECORD_BYTES: usize =
    2 + 4 + crate::MAX_STORED_KEY_BYTES + 4 + 4 + crate::MAX_SEALED_RECORD_BYTES;
/// Greatest number of offline-authorized backup signing keys one verification accepts.
pub const MAX_BACKUP_TRUST_KEYS: usize = 1_024;
/// Bytes a stream adds over the logical record charge: the 4-byte frame length prefix
/// and the 4-byte record-schema field.
pub(crate) const BACKUP_RECORD_OVERHEAD_BYTES: u64 = 8;
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

    /// Returns the authenticated random identity used in the published name.
    #[must_use]
    pub const fn backup_id(&self) -> [u8; 16] {
        self.backup_id
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
            TableId::Account
            | TableId::OpaqueRecord
            | TableId::AuthTransaction
            | TableId::NicknameReservation
            | TableId::RegistrationInvite
            | TableId::Session
            | TableId::Channel
            | TableId::ChannelName
            | TableId::Sanction
            | TableId::FederationPeer
            | TableId::FederationOrigin
            | TableId::RequestResult
            | TableId::EdgeOutbox
            | TableId::EdgeProjection
            | TableId::History
            | TableId::Audit
            | TableId::AuditCheckpoint
            | TableId::E2eeObject
            | TableId::E2eeState => {}
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
        if (
            self.key_check_count,
            self.state_meta_count,
            self.construction_count,
        ) != (1, 1, 0)
        {
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
        let expected_previous_count = login_state.previous().map_or(0, |(_, count)| count);
        if previous_count != expected_previous_count {
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
        } else if (
            self.first_manifest_sequence,
            self.last_manifest_sequence,
            self.last_manifest_hash,
            self.last_manifest_state_generation,
            self.last_manifest_response_count,
        ) != (
            Some(
                state
                    .checkpoint_manifest_sequence
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?,
            ),
            Some(state.manifest_sequence),
            Some(state.latest_manifest_hash),
            Some(state.state_generation),
            Some(state.account_service_response_count),
        ) {
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
            if (self.checkpoints.len(), active.previous_checkpoint_hash) != (1, zero) {
                return Err(StorageError::StaleState);
            }
        } else if (
            self.checkpoints.len(),
            self.checkpoints
                .iter()
                .any(|checkpoint| checkpoint.checkpoint_hash == active.previous_checkpoint_hash),
        ) != (2, true)
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
    if trusted_keys.is_empty() || trusted_keys.len() > MAX_BACKUP_TRUST_KEYS {
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
    history_inventory: crate::history_records::HistoryInventory,
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
            history_inventory: crate::history_records::HistoryInventory::new(1_073_741_824),
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
        crate::migration::validate_source_record(
            self.header.source_header().tbs().schema_generation,
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
        self.history_inventory.observe(
            record.table(),
            record.stored_key(),
            record.sealed_record().len(),
            plaintext,
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
        if (self.key_check_seen, sealed.record_id()?, plaintext)
            != (
                false,
                self.header.source_header().key_check_object_id(),
                self.header
                    .source_header()
                    .tbs()
                    .key_check_plaintext()?
                    .as_bytes(),
            )
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
        if (self.state_meta.is_some(), sealed.record_id()?)
            != (
                false,
                self.header
                    .source_nonce_reservation()
                    .tbs()
                    .state_meta_record_id,
            )
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
        self.history_inventory.finish()?;
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
    logical
        .checked_add(BACKUP_RECORD_OVERHEAD_BYTES)
        .ok_or(StorageError::Overflow)
}

fn meta_logical_bytes() -> Result<u64, StorageError> {
    crate::logical_meta_charge(
        crate::redb_store::HEADER_META_KEY.len(),
        DATABASE_HEADER_BYTES,
    )?
    .checked_add(crate::logical_meta_charge(
        crate::redb_store::RESERVATION_META_KEY.len(),
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

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::{
        LoginIndexKey, RollbackGuardRootKey, StorageIntegrityContext, derive_storage_integrity_keys,
    };
    use agenc_ircd_types::{DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

    use super::*;
    use crate::{
        DatabaseHeaderTbs, IntegrityCheckpointTbs, IntegrityManifestTbs, IntegrityRecordMutation,
        IntegrityRecordVersion, NonceReservationTbs, RollbackGuardPhase, RollbackGuardTbs,
        StateMetaTbs, StorageSealContext,
    };

    const ZERO: StorageDigest = StorageDigest::from_bytes([0; 32]);

    fn state_meta(
        manifest_sequence: u64,
        checkpoint_manifest_sequence: u64,
        latest_manifest_hash: StorageDigest,
        checkpoint_hash: StorageDigest,
    ) -> Result<StateMeta, StorageError> {
        let network = NetworkId::from_bytes([1; 32]);
        let server = ServerId::from_bytes([2; 16]);
        let database = DatabaseId::from_bytes([3; 16]);
        let keys = derive_storage_integrity_keys(
            &RollbackGuardRootKey::from_bytes([4; 32]),
            StorageIntegrityContext::new(network, server, database),
        )?;
        StateMeta::authenticate(
            StateMetaTbs {
                storage_commit_sequence: manifest_sequence,
                manifest_sequence,
                state_generation: manifest_sequence,
                account_service_response_count: manifest_sequence,
                nonce_draw_high_water: manifest_sequence,
                logical_database_bytes: 1,
                backup_stream_bytes: 1,
                checkpoint_manifest_sequence,
                latest_manifest_hash,
                checkpoint_hash,
                previous_rollback_guard_hash: ZERO,
            },
            StorageDigest::from_bytes([5; 32]),
            &keys,
        )
    }

    fn baseline_reconstruction(
        checkpoint_hash: StorageDigest,
    ) -> Result<BackupReconstruction, StorageError> {
        let network = NetworkId::from_bytes([1; 32]);
        let login_key = LoginIndexKey::from_bytes([6; 32]);
        Ok(BackupReconstruction {
            key_check_count: 1,
            state_meta_count: 1,
            login_key_state: Some(LoginIndexKeyState::stable(1, login_key.key_id(network))?),
            login_generations: [None, None],
            construction_count: 0,
            manifest_count: 0,
            first_manifest_sequence: None,
            first_manifest_previous_hash: None,
            last_manifest_sequence: None,
            last_manifest_hash: None,
            last_manifest_state_generation: None,
            last_manifest_response_count: None,
            checkpoints: vec![CheckpointFacts {
                cut_manifest_sequence: 0,
                checkpoint_hash,
                previous_checkpoint_hash: ZERO,
                cut_manifest_hash: ZERO,
            }],
        })
    }

    fn reconstruction_record(table: TableId, key: Vec<u8>) -> Result<BackupRecord, StorageError> {
        Ok(BackupRecord {
            table,
            stored_key: StoredKey::new(key)?,
            record_schema: 1,
            sealed_record: Vec::new(),
        })
    }

    fn manifest(
        database: DatabaseId,
        sequence: u64,
        previous_hash: StorageDigest,
    ) -> Result<IntegrityManifest, StorageError> {
        let mutation = IntegrityRecordMutation::new(
            TableId::Account,
            StoredKey::new(vec![u8::try_from(sequence).unwrap_or(0)])?,
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Present {
                record_schema: 1,
                sealed_record_id: StorageDigest::from_bytes([31; 32]),
            },
        )?;
        IntegrityManifest::new(IntegrityManifestTbs::new(
            database,
            sequence,
            sequence,
            sequence.saturating_sub(1),
            sequence,
            sequence.saturating_sub(1),
            sequence,
            0,
            0,
            3,
            3,
            previous_hash,
            vec![mutation],
        )?)
    }

    fn checkpoint(
        database: DatabaseId,
        cut_sequence: u64,
        previous_hash: StorageDigest,
    ) -> Result<IntegrityCheckpoint, StorageError> {
        IntegrityCheckpoint::new(IntegrityCheckpointTbs {
            database_instance_id: database,
            cut_storage_commit_sequence: cut_sequence,
            cut_manifest_sequence: cut_sequence,
            cut_state_generation: cut_sequence,
            cut_account_service_response_count: cut_sequence,
            cut_nonce_draw_high_water: 0,
            cut_manifest_hash: ZERO,
            tracked_record_count: 0,
            tracked_state_digest: ZERO,
            previous_checkpoint_hash: previous_hash,
            installation_storage_commit_sequence: cut_sequence.saturating_add(1),
            installation_manifest_sequence: cut_sequence,
            installation_nonce_reservation_start: 0,
            installation_nonce_draw_high_water: 2,
        })
    }

    fn backup_boundary() -> Result<
        (
            BackupHeader,
            StorageMasterKey,
            RollbackGuardRootKey,
            Ed25519SecretKey,
        ),
        StorageError,
    > {
        let network = NetworkId::from_bytes([61; 32]);
        let server = ServerId::from_bytes([62; 16]);
        let incarnation = ServerIncarnation::from_bytes([63; 16]);
        let database = DatabaseId::from_bytes([64; 16]);
        let header = DatabaseHeader::new(
            DatabaseHeaderTbs::new(
                network,
                server,
                incarnation,
                database,
                1,
                crate::SCHEMA_GENERATION,
                RecoveryEpoch::from_bytes([65; 16]),
            )?,
            StorageDigest::from_bytes([66; 32]),
        );
        let guard_root = RollbackGuardRootKey::from_bytes([67; 32]);
        let integrity_keys = derive_storage_integrity_keys(
            &guard_root,
            StorageIntegrityContext::new(network, server, database),
        )?;
        let state_meta_record_id = StorageDigest::from_bytes([68; 32]);
        let reservation = NonceReservationState::authenticate(
            NonceReservationTbs {
                database_instance_id: database,
                reservation_sequence: 0,
                phase: RollbackGuardPhase::Committed,
                nonce_reservation_start: 0,
                nonce_draw_high_water: 0,
                storage_commit_sequence: 0,
                manifest_sequence: 0,
                state_generation: 0,
                database_header_hash: header.complete_hash()?,
                state_meta_record_id,
                previous_guard_hash: ZERO,
            },
            &integrity_keys,
        )?;
        let guard = RollbackGuard::authenticate(
            RollbackGuardTbs {
                network_id: network,
                server_id: server,
                database_instance_id: database,
                storage_key_generation: 1,
                schema_generation: crate::SCHEMA_GENERATION,
                recovery_epoch: header.tbs().recovery_epoch,
                storage_commit_sequence: 0,
                manifest_sequence: 0,
                state_generation: 0,
                phase: RollbackGuardPhase::Committed,
                reservation_sequence: 0,
                nonce_reservation_start: 0,
                nonce_draw_high_water: 0,
                database_header_hash: header.complete_hash()?,
                state_meta_record_id,
                nonce_reservation_state_hash: reservation.complete_hash()?,
                previous_guard_hash: ZERO,
            },
            &integrity_keys,
        )?;
        let signing_key = Ed25519SecretKey::from_bytes([69; 32]);
        let backup_header = BackupHeader::new(
            header,
            reservation,
            guard,
            123,
            [70; 16],
            signing_key.public_key(),
        )?;
        Ok((
            backup_header,
            StorageMasterKey::from_bytes([71; 32]),
            guard_root,
            signing_key,
        ))
    }

    fn complete_verification<'a>(
        header: &'a BackupHeader,
        master_key: &'a StorageMasterKey,
        guard_root: &RollbackGuardRootKey,
        stream_bytes: u64,
    ) -> Result<BackupRecordVerification<'a>, StorageError> {
        let mut verification = BackupRecordVerification::new(header, master_key, guard_root)?;
        let source = header.source_header();
        let keys = derive_storage_integrity_keys(
            guard_root,
            StorageIntegrityContext::new(
                source.tbs().network_id,
                source.tbs().server_id,
                source.tbs().database_instance_id,
            ),
        )?;
        verification.key_check_seen = true;
        verification.state_meta = Some(StateMeta::authenticate(
            StateMetaTbs {
                storage_commit_sequence: 0,
                manifest_sequence: 0,
                state_generation: 0,
                account_service_response_count: 0,
                nonce_draw_high_water: 0,
                logical_database_bytes: verification.logical_database_bytes,
                backup_stream_bytes: stream_bytes,
                checkpoint_manifest_sequence: 0,
                latest_manifest_hash: ZERO,
                checkpoint_hash: ZERO,
                previous_rollback_guard_hash: ZERO,
            },
            source.complete_hash()?,
            &keys,
        )?);
        Ok(verification)
    }

    #[test]
    fn reconstruction_rejects_each_singleton_login_and_genesis_mismatch() -> Result<(), StorageError>
    {
        let checkpoint_hash = StorageDigest::from_bytes([7; 32]);
        let state = state_meta(0, 0, ZERO, checkpoint_hash)?;
        baseline_reconstruction(checkpoint_hash)?.finish(&state)?;

        let mut missing_key_check = baseline_reconstruction(checkpoint_hash)?;
        missing_key_check.key_check_count = 0;
        assert_eq!(
            missing_key_check.finish(&state),
            Err(StorageError::StaleState)
        );

        let mut missing_state = baseline_reconstruction(checkpoint_hash)?;
        missing_state.state_meta_count = 0;
        assert_eq!(missing_state.finish(&state), Err(StorageError::StaleState));

        let mut construction = baseline_reconstruction(checkpoint_hash)?;
        construction.construction_count = 1;
        assert_eq!(construction.finish(&state), Err(StorageError::StaleState));

        let mut missing_login_state = baseline_reconstruction(checkpoint_hash)?;
        missing_login_state.login_key_state = None;
        assert_eq!(
            missing_login_state.finish(&state),
            Err(StorageError::StaleState)
        );

        let mut unknown_login_generation = baseline_reconstruction(checkpoint_hash)?;
        unknown_login_generation.login_generations[0] = Some((2, 1));
        assert_eq!(
            unknown_login_generation.finish(&state),
            Err(StorageError::StaleState)
        );

        let mut unexpected_checkpoint = baseline_reconstruction(checkpoint_hash)?;
        unexpected_checkpoint.checkpoints.push(CheckpointFacts {
            cut_manifest_sequence: 1,
            checkpoint_hash: StorageDigest::from_bytes([8; 32]),
            previous_checkpoint_hash: checkpoint_hash,
            cut_manifest_hash: ZERO,
        });
        assert_eq!(
            unexpected_checkpoint.finish(&state),
            Err(StorageError::StaleState)
        );

        let mut wrong_genesis_predecessor = baseline_reconstruction(checkpoint_hash)?;
        wrong_genesis_predecessor
            .checkpoints
            .first_mut()
            .ok_or(StorageError::StaleState)?
            .previous_checkpoint_hash = StorageDigest::from_bytes([9; 32]);
        assert_eq!(
            wrong_genesis_predecessor.finish(&state),
            Err(StorageError::StaleState)
        );

        let mut wrong_cut_hash = baseline_reconstruction(checkpoint_hash)?;
        wrong_cut_hash
            .checkpoints
            .first_mut()
            .ok_or(StorageError::StaleState)?
            .cut_manifest_hash = StorageDigest::from_bytes([10; 32]);
        assert_eq!(wrong_cut_hash.finish(&state), Err(StorageError::StaleState));
        Ok(())
    }

    #[test]
    fn reconstruction_rejects_each_manifest_and_checkpoint_chain_mismatch()
    -> Result<(), StorageError> {
        let checkpoint_hash = StorageDigest::from_bytes([11; 32]);
        let manifest_hash = StorageDigest::from_bytes([12; 32]);
        let state = state_meta(1, 0, manifest_hash, checkpoint_hash)?;

        let wrong_count = baseline_reconstruction(checkpoint_hash)?;
        assert_eq!(wrong_count.finish(&state), Err(StorageError::StaleState));

        let complete = || -> Result<BackupReconstruction, StorageError> {
            let mut reconstruction = baseline_reconstruction(checkpoint_hash)?;
            reconstruction.manifest_count = 1;
            reconstruction.first_manifest_sequence = Some(1);
            reconstruction.first_manifest_previous_hash = Some(ZERO);
            reconstruction.last_manifest_sequence = Some(1);
            reconstruction.last_manifest_hash = Some(manifest_hash);
            reconstruction.last_manifest_state_generation = Some(1);
            reconstruction.last_manifest_response_count = Some(1);
            Ok(reconstruction)
        };
        complete()?.finish(&state)?;

        for changed in 0..5 {
            let mut reconstruction = complete()?;
            match changed {
                0 => reconstruction.first_manifest_sequence = Some(2),
                1 => reconstruction.last_manifest_sequence = Some(2),
                2 => reconstruction.last_manifest_hash = Some(ZERO),
                3 => reconstruction.last_manifest_state_generation = Some(2),
                _ => reconstruction.last_manifest_response_count = Some(2),
            }
            assert_eq!(reconstruction.finish(&state), Err(StorageError::StaleState));
        }

        let cut_hash = StorageDigest::from_bytes([13; 32]);
        let active_hash = StorageDigest::from_bytes([14; 32]);
        let predecessor_hash = StorageDigest::from_bytes([15; 32]);
        let checkpoint_state = state_meta(1, 1, cut_hash, active_hash)?;
        let mut checkpointed = baseline_reconstruction(active_hash)?;
        checkpointed.checkpoints = vec![
            CheckpointFacts {
                cut_manifest_sequence: 0,
                checkpoint_hash: predecessor_hash,
                previous_checkpoint_hash: ZERO,
                cut_manifest_hash: ZERO,
            },
            CheckpointFacts {
                cut_manifest_sequence: 1,
                checkpoint_hash: active_hash,
                previous_checkpoint_hash: predecessor_hash,
                cut_manifest_hash: cut_hash,
            },
        ];
        let mut unknown_active = baseline_reconstruction(active_hash)?;
        unknown_active.checkpoints = checkpointed.checkpoints.clone();
        unknown_active
            .checkpoints
            .get_mut(1)
            .ok_or(StorageError::StaleState)?
            .checkpoint_hash = ZERO;
        checkpointed.finish(&checkpoint_state)?;

        let mut missing_predecessor = baseline_reconstruction(active_hash)?;
        missing_predecessor.checkpoints = vec![CheckpointFacts {
            cut_manifest_sequence: 1,
            checkpoint_hash: active_hash,
            previous_checkpoint_hash: predecessor_hash,
            cut_manifest_hash: cut_hash,
        }];
        assert_eq!(
            missing_predecessor.finish(&checkpoint_state),
            Err(StorageError::StaleState)
        );

        assert_eq!(
            unknown_active.finish(&checkpoint_state),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn login_generation_accumulator_accepts_two_generations_only() {
        let mut reconstruction = BackupReconstruction::new();
        assert_eq!(reconstruction.observe_login_generation(1), Ok(()));
        assert_eq!(reconstruction.observe_login_generation(1), Ok(()));
        assert_eq!(reconstruction.observe_login_generation(2), Ok(()));
        assert_eq!(
            reconstruction.observe_login_generation(3),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            reconstruction.login_generations,
            [Some((1, 2)), Some((2, 1))]
        );
    }

    #[test]
    fn reconstruction_observe_authenticates_singletons_manifests_and_checkpoints()
    -> Result<(), StorageError> {
        let database = DatabaseId::from_bytes([41; 16]);
        let other_database = DatabaseId::from_bytes([42; 16]);

        let mut reconstruction = BackupReconstruction::new();
        reconstruction.observe(
            &reconstruction_record(TableId::KeyCheck, KEY_CHECK_KEY.to_vec())?,
            &[],
            database,
        )?;
        reconstruction.observe(
            &reconstruction_record(TableId::StateMeta, STATE_META_KEY.to_vec())?,
            &[],
            database,
        )?;
        assert_eq!(
            (
                reconstruction.key_check_count,
                reconstruction.state_meta_count
            ),
            (1, 1)
        );
        reconstruction.key_check_count = u8::MAX;
        assert_eq!(
            reconstruction.observe(
                &reconstruction_record(TableId::KeyCheck, KEY_CHECK_KEY.to_vec())?,
                &[],
                database,
            ),
            Err(StorageError::Overflow)
        );
        reconstruction.state_meta_count = u8::MAX;
        assert_eq!(
            reconstruction.observe(
                &reconstruction_record(TableId::StateMeta, STATE_META_KEY.to_vec())?,
                &[],
                database,
            ),
            Err(StorageError::Overflow)
        );

        let login_key = LoginIndexKey::from_bytes([43; 32]);
        let key_state =
            LoginIndexKeyState::stable(1, login_key.key_id(NetworkId::from_bytes([44; 32])))?
                .encode()?;
        let key_state_record = reconstruction_record(
            TableId::LoginIndexKeyState,
            crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec(),
        )?;
        let mut reconstruction = BackupReconstruction::new();
        reconstruction.observe(&key_state_record, &key_state, database)?;
        assert_eq!(
            reconstruction.observe(&key_state_record, &key_state, database),
            Err(StorageError::StaleState)
        );

        let first = manifest(database, 1, ZERO)?;
        let second = manifest(database, 2, first.manifest_hash())?;
        let first_record =
            reconstruction_record(TableId::IntegrityManifest, 1_u64.to_be_bytes().to_vec())?;
        let second_record =
            reconstruction_record(TableId::IntegrityManifest, 2_u64.to_be_bytes().to_vec())?;
        let mut reconstruction = BackupReconstruction::new();
        reconstruction.observe(&first_record, &first.encode()?, database)?;
        reconstruction.observe(&second_record, &second.encode()?, database)?;
        assert_eq!(reconstruction.manifest_count, 2);

        let wrong_database = manifest(other_database, 1, ZERO)?;
        assert_eq!(
            BackupReconstruction::new()
                .observe(&first_record, &wrong_database.encode()?, database,),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            BackupReconstruction::new().observe(&second_record, &first.encode()?, database,),
            Err(StorageError::StaleState)
        );

        let mut gap = BackupReconstruction::new();
        gap.observe(&first_record, &first.encode()?, database)?;
        let third = manifest(database, 3, first.manifest_hash())?;
        let third_record =
            reconstruction_record(TableId::IntegrityManifest, 3_u64.to_be_bytes().to_vec())?;
        assert_eq!(
            gap.observe(&third_record, &third.encode()?, database),
            Err(StorageError::StaleState)
        );
        let mut wrong_hash = BackupReconstruction::new();
        wrong_hash.observe(&first_record, &first.encode()?, database)?;
        let second_wrong_hash = manifest(database, 2, ZERO)?;
        assert_eq!(
            wrong_hash.observe(&second_record, &second_wrong_hash.encode()?, database),
            Err(StorageError::StaleState)
        );
        let mut sequence_overflow = BackupReconstruction::new();
        sequence_overflow.last_manifest_sequence = Some(u64::MAX);
        assert_eq!(
            sequence_overflow.observe(&first_record, &first.encode()?, database),
            Err(StorageError::Overflow)
        );
        let mut count_overflow = BackupReconstruction::new();
        count_overflow.manifest_count = u64::MAX;
        assert_eq!(
            count_overflow.observe(&first_record, &first.encode()?, database),
            Err(StorageError::Overflow)
        );

        let first_checkpoint = checkpoint(database, 0, ZERO)?;
        let checkpoint_record =
            reconstruction_record(TableId::IntegrityCheckpoint, 0_u64.to_be_bytes().to_vec())?;
        let mut reconstruction = BackupReconstruction::new();
        reconstruction.observe(&checkpoint_record, &first_checkpoint.encode()?, database)?;
        reconstruction.observe(
            &reconstruction_record(TableId::IntegrityCheckpoint, 1_u64.to_be_bytes().to_vec())?,
            &checkpoint(database, 1, first_checkpoint.checkpoint_hash())?.encode()?,
            database,
        )?;
        assert_eq!(
            reconstruction.observe(
                &reconstruction_record(
                    TableId::IntegrityCheckpoint,
                    2_u64.to_be_bytes().to_vec(),
                )?,
                &checkpoint(database, 2, first_checkpoint.checkpoint_hash())?.encode()?,
                database,
            ),
            Err(StorageError::LimitExceeded)
        );
        assert_eq!(
            BackupReconstruction::new().observe(
                &checkpoint_record,
                &checkpoint(other_database, 0, ZERO)?.encode()?,
                database,
            ),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            BackupReconstruction::new().observe(
                &reconstruction_record(
                    TableId::IntegrityCheckpoint,
                    1_u64.to_be_bytes().to_vec(),
                )?,
                &first_checkpoint.encode()?,
                database,
            ),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn fixed_backup_codecs_and_trust_validity_reject_each_boundary() -> Result<(), StorageError> {
        let guard_root = RollbackGuardRootKey::from_bytes([51; 32]);
        assert_eq!(
            BackupHeader::decode(&[], &guard_root).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        let mut wrong_version = vec![0; BACKUP_HEADER_BYTES];
        wrong_version
            .get_mut(..2)
            .ok_or(StorageError::InvalidEncoding)?
            .copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            BackupHeader::decode(&wrong_version, &guard_root).map(|_| ()),
            Err(StorageError::UnsupportedVersion)
        );
        assert_eq!(
            BackupTrailer::decode(&[]),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            BackupRecord::decode(&vec![0; MAX_BACKUP_RECORD_BYTES + 1]).map(|_| ()),
            Err(StorageError::LimitExceeded)
        );

        let signing_key = Ed25519SecretKey::from_bytes([52; 32]);
        let key_id = backup_signing_key_id(signing_key.public_key().as_bytes())?;
        let trust = BackupTrustKey::with_validity(key_id, signing_key.public_key(), 10, 20)?;
        assert!(!trust.accepts_creation_time(9));
        assert!(trust.accepts_creation_time(10));
        assert!(trust.accepts_creation_time(19));
        assert!(!trust.accepts_creation_time(20));
        assert_eq!(
            BackupTrustKey::with_validity(key_id, signing_key.public_key(), 20, 20),
            Err(StorageError::AuthenticationFailed)
        );
        assert_eq!(
            BackupTrustKey::with_validity(
                StorageDigest::from_bytes([53; 32]),
                signing_key.public_key(),
                10,
                20,
            ),
            Err(StorageError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn streaming_and_verification_limits_reject_each_late_boundary() -> Result<(), StorageError> {
        let (header, master_key, guard_root, signing_key) = backup_boundary()?;
        let trust = BackupTrustKey::new(signing_key.public_key())?;
        assert_eq!(
            trusted_backup_key(&header, &[]),
            Err(StorageError::AuthenticationFailed)
        );
        assert_eq!(
            trusted_backup_key(
                &header,
                &[
                    BackupTrustKey::new(signing_key.public_key())?,
                    BackupTrustKey::new(signing_key.public_key())?,
                ],
            ),
            Err(StorageError::AuthenticationFailed)
        );
        let wrong_key = Ed25519SecretKey::from_bytes([72; 32]);
        assert_eq!(
            trusted_backup_key(&header, &[BackupTrustKey::new(wrong_key.public_key())?]),
            Err(StorageError::AuthenticationFailed)
        );

        let oversized_trust = (0..1_025)
            .map(|_| BackupTrustKey::new(signing_key.public_key()))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            verify_backup(
                std::io::Cursor::new(Vec::<u8>::new()),
                &master_key,
                &guard_root,
                &oversized_trust,
                BACKUP_FIXED_STREAM_BYTES,
            )
            .map(|_| ()),
            Err(StorageError::LimitExceeded)
        );

        let mut writer = BackupStreamWriter::start(Vec::new(), &header, BACKUP_FIXED_STREAM_BYTES)?;
        writer.write_record(&BackupRecord {
            table: TableId::KeyCheck,
            stored_key: StoredKey::new(KEY_CHECK_KEY.to_vec())?,
            record_schema: 1,
            sealed_record: Vec::new(),
        })?;
        assert_eq!(
            writer.finish(&signing_key).map(|_| ()),
            Err(StorageError::LimitExceeded)
        );

        let (bytes, _) = BackupStreamWriter::start(Vec::new(), &header, BACKUP_FIXED_STREAM_BYTES)?
            .finish(&signing_key)?;
        assert_eq!(
            verify_backup(
                std::io::Cursor::new(bytes),
                &master_key,
                &guard_root,
                &[trust],
                BACKUP_FIXED_STREAM_BYTES - 1,
            )
            .map(|_| ()),
            Err(StorageError::LimitExceeded)
        );

        let mut verification = BackupRecordVerification::new(&header, &master_key, &guard_root)?;
        let mut hasher = BackupStreamHasher::new(BACKUP_FIXED_STREAM_BYTES)?;
        assert_eq!(
            read_backup_records(
                &mut std::io::Cursor::new(0_u32.to_be_bytes()),
                &mut hasher,
                &mut verification,
            ),
            Err(StorageError::LimitExceeded)
        );
        let too_large = u32::try_from(MAX_BACKUP_RECORD_BYTES)
            .map_err(|_| StorageError::Overflow)?
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        assert_eq!(
            read_backup_records(
                &mut std::io::Cursor::new(too_large.to_be_bytes()),
                &mut hasher,
                &mut verification,
            ),
            Err(StorageError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn largest_record_body_encodes_exactly_at_the_record_ceiling() -> Result<(), StorageError> {
        let record = BackupRecord {
            table: TableId::E2eeObject,
            stored_key: StoredKey::new(vec![1; crate::MAX_STORED_KEY_BYTES])?,
            record_schema: 1,
            sealed_record: vec![2; crate::MAX_SEALED_RECORD_BYTES],
        };
        let encoded = record.encode()?;
        assert_eq!(encoded.len(), MAX_BACKUP_RECORD_BYTES);
        Ok(())
    }

    #[test]
    fn record_verification_finish_binds_each_state_and_reservation_counter()
    -> Result<(), StorageError> {
        let (header, master_key, guard_root, _) = backup_boundary()?;
        let stream_bytes = BACKUP_FIXED_STREAM_BYTES;
        for changed in 0..6 {
            let mut verification =
                complete_verification(&header, &master_key, &guard_root, stream_bytes)?;
            match changed {
                0 => verification.key_check_seen = false,
                1 => verification.logical_database_bytes += 1,
                2 => {}
                3 => {
                    let mut state = *verification
                        .state_meta
                        .as_ref()
                        .ok_or(StorageError::StaleState)?
                        .tbs();
                    state.storage_commit_sequence += 1;
                    verification.state_meta = Some(StateMeta::authenticate(
                        state,
                        header.source_header().complete_hash()?,
                        &verification.integrity_keys,
                    )?);
                }
                4 => {
                    let mut state = *verification
                        .state_meta
                        .as_ref()
                        .ok_or(StorageError::StaleState)?
                        .tbs();
                    state.manifest_sequence += 1;
                    verification.state_meta = Some(StateMeta::authenticate(
                        state,
                        header.source_header().complete_hash()?,
                        &verification.integrity_keys,
                    )?);
                }
                _ => {
                    let mut state = *verification
                        .state_meta
                        .as_ref()
                        .ok_or(StorageError::StaleState)?
                        .tbs();
                    state.state_generation += 1;
                    verification.state_meta = Some(StateMeta::authenticate(
                        state,
                        header.source_header().complete_hash()?,
                        &verification.integrity_keys,
                    )?);
                }
            }
            let supplied_stream_bytes = if changed == 2 {
                stream_bytes + 1
            } else {
                stream_bytes
            };
            assert_eq!(
                verification.finish(supplied_stream_bytes).map(|_| ()),
                Err(StorageError::StaleState)
            );
        }
        Ok(())
    }

    #[test]
    fn reconstruction_accepts_an_exact_previous_generation_and_rejects_empty_head_metadata()
    -> Result<(), StorageError> {
        let checkpoint_hash = StorageDigest::from_bytes([73; 32]);
        let state = state_meta(0, 0, ZERO, checkpoint_hash)?;
        let network = NetworkId::from_bytes([1; 32]);
        let previous = LoginIndexKey::from_bytes([74; 32]);
        let current = LoginIndexKey::from_bytes([75; 32]);
        let mut transition = baseline_reconstruction(checkpoint_hash)?;
        transition.login_key_state = Some(LoginIndexKeyState::transition(
            1,
            previous.key_id(network),
            current.key_id(network),
            1,
        )?);
        transition.login_generations = [Some((2, 1)), Some((1, 1))];
        transition.finish(&state)?;

        let mut unexpected_head = baseline_reconstruction(checkpoint_hash)?;
        unexpected_head.last_manifest_sequence = Some(0);
        assert_eq!(
            unexpected_head.finish(&state),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn trust_and_singleton_observers_reject_internally_inconsistent_rows()
    -> Result<(), StorageError> {
        let (header, master_key, guard_root, signing_key) = backup_boundary()?;
        let mut inconsistent_trust =
            BackupTrustKey::new(Ed25519SecretKey::from_bytes([73; 32]).public_key())?;
        inconsistent_trust.key_id = header.signing_key_id();
        assert_eq!(
            trusted_backup_key(&header, &[inconsistent_trust]),
            Err(StorageError::AuthenticationFailed),
        );

        let key = StoredKey::new(
            agenc_ircd_types::AccountRandomId::from_bytes([74; 16])
                .to_text()
                .into_bytes(),
        )?;
        let plaintext = crate::PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            1,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?
        .encode()?;
        let sealed = StorageSealContext::new(
            &master_key,
            database_binding(header.source_header()),
            header.source_header().tbs().storage_key_generation,
        )?
        .seal(TableId::Account, 1, [75; 24], &key, &plaintext)?;
        let wrong_key_check = BackupRecord {
            table: TableId::KeyCheck,
            stored_key: StoredKey::new(b"wrong-key-check".to_vec())?,
            record_schema: 1,
            sealed_record: Vec::new(),
        };
        let mut verification = BackupRecordVerification::new(&header, &master_key, &guard_root)?;
        verification.observe_key_check(&wrong_key_check, &sealed, &plaintext)?;
        verification.key_check_seen = true;
        let key_check = BackupRecord {
            table: TableId::KeyCheck,
            stored_key: StoredKey::new(KEY_CHECK_KEY.to_vec())?,
            record_schema: 1,
            sealed_record: Vec::new(),
        };
        assert_eq!(
            verification.observe_key_check(&key_check, &sealed, &plaintext),
            Err(StorageError::AuthenticationFailed),
        );

        let wrong_state_meta = BackupRecord {
            table: TableId::StateMeta,
            stored_key: StoredKey::new(b"wrong-state-meta".to_vec())?,
            record_schema: 1,
            sealed_record: Vec::new(),
        };
        verification.observe_state_meta(&wrong_state_meta, &sealed, &plaintext)?;
        verification.state_meta = Some(state_meta(0, 0, ZERO, ZERO)?);
        let state_meta_record = BackupRecord {
            table: TableId::StateMeta,
            stored_key: StoredKey::new(STATE_META_KEY.to_vec())?,
            record_schema: 1,
            sealed_record: Vec::new(),
        };
        assert_eq!(
            verification.observe_state_meta(&state_meta_record, &sealed, &plaintext),
            Err(StorageError::StaleState),
        );

        let network = header.source_header().tbs().network_id;
        let current = LoginIndexKey::from_bytes([76; 32]);
        let previous = LoginIndexKey::from_bytes([77; 32]);
        let mut reconstruction = baseline_reconstruction(ZERO)?;
        reconstruction.login_key_state = Some(LoginIndexKeyState::transition(
            1,
            previous.key_id(network),
            current.key_id(network),
            1,
        )?);
        assert_eq!(
            reconstruction.finish(&state_meta(0, 0, ZERO, ZERO)?),
            Err(StorageError::StaleState),
        );
        assert_ne!(signing_key.public_key(), inconsistent_trust.public_key);
        Ok(())
    }
}
