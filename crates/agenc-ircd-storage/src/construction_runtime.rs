//! Bounded, resumable execution of authenticated construction plans.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use agenc_ircd_crypto::{
    ConstructionPlanHasher, DatabaseBinding, LoginIndexKey, LoginIndexKeyId, OsEntropy,
    RollbackGuardRootKey, StorageDigest, StorageMasterKey, StorageTable, TrackedStateHasher,
    derive_storage_index, tracked_record_commitment,
};
use agenc_ircd_types::{ChannelName, Generation, Nickname, RecoveryEpoch, Revision, TransactionId};
use redb::{
    Database, Durability, ReadableDatabase as _, ReadableTable as _, ReadableTableMetadata as _,
    TableDefinition,
};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::engine::{StorageEngine, StorageOpenConfig};
use crate::{
    AccountRecordBody, BACKUP_FIXED_STREAM_BYTES, BackupRecord, BackupTrustKey, ChannelRecordBody,
    DatabaseHeader, ExistingRecord, INTEGRITY_CHECKPOINT_BYTES, IntegrityCheckpoint,
    IntegrityManifest, IntegrityRecordVersion, MAX_CONSTRUCTION_PLAN_BYTES,
    MIN_SEALED_RECORD_BYTES, PersistentRecordValue, ReadPlan, RecordMutation, RecordReference,
    STATE_META_BYTES, SealedRecord, StateMetaTbs, StorageAccountingLimits, StorageConstruction,
    StorageConstructionAction, StorageConstructionCursor, StorageConstructionKind,
    StorageConstructionPlanEntry, StorageConstructionSource, StorageConstructionSourceKind,
    StorageError, StorageFaultBoundary, StorageFaultSite, StorageMutationBatch,
    StorageMutationHead, StorageOperationCompletion, StorageOperationIdentity, StoragePort,
    StoredKey, TableId, VerifiedBackup, construction_plan_hash, logical_meta_charge,
    logical_record_charge, validate_record_plaintext, verify_backup,
};

/// Fixed version-one source logical/backup ceiling.
pub const MAX_CONSTRUCTION_SOURCE_BYTES: u64 = 1_099_511_627_776;
/// Fixed version-one target logical/backup ceiling.
pub const MAX_CONSTRUCTION_TARGET_BYTES: u64 = 1_099_511_627_776;
/// Greatest entries committed by one construction service batch.
pub const MAX_CONSTRUCTION_BATCH_RECORDS: usize = 1_000;
/// Greatest transformed plaintext bytes committed by one construction batch.
pub const MAX_CONSTRUCTION_BATCH_BYTES: usize = 16_777_216;

/// redb page cache used by the scratch plan database.
const CONSTRUCTION_PLAN_CACHE_BYTES: usize = 8 * 1_024 * 1_024;
/// Sequence-zero initialization seals the key check, construction marker, genesis
/// checkpoint, and StateMeta, so a fresh target starts at this nonce high-water mark.
/// Mirrors `initialize_storage`.
const INITIALIZED_NONCE_DRAW_HIGH_WATER: u64 = 4;
/// The dedicated finalization transaction seals the completion record, its manifest,
/// and StateMeta. The simulated finalization batch must reproduce this count.
const FINALIZATION_NONCE_DRAWS: u64 = 3;
/// Checkpoint installation seals the checkpoint record and StateMeta; mirrors the
/// two-draw reservation validated by `IntegrityCheckpointTbs`.
const CHECKPOINT_INSTALLATION_NONCE_DRAWS: u64 = 2;
/// Manifest and checkpoint rows are keyed by one big-endian `u64` sequence.
const SEQUENCE_STORED_KEY_BYTES: usize = 8;
/// The key-check row stores one 32-byte `StorageDigest` plaintext.
const KEY_CHECK_PLAINTEXT_BYTES: usize = 32;

const CONSTRUCTION_PLAN_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("construction_plan");
const CONSTRUCTION_PLAN_UNSORTED_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("construction_plan_unsorted");
const RESTORE_CHANNEL_SOURCE_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("restore_channel_sources");
const RESTORE_CURRENT_RECORD_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("restore_current_records");
const RESTORE_REFERENCE_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("restore_references");
const RESTORE_MANIFEST_TABLE: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("restore_manifests");

/// Validated source, target, plan, and batch ceilings for one command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstructionLimits {
    /// Greatest accepted source logical charge.
    pub source_database_bytes: u64,
    /// Greatest accepted source backup-stream charge.
    pub source_backup_bytes: u64,
    /// Greatest accepted target logical charge.
    pub target_database_bytes: u64,
    /// Greatest accepted target backup-stream charge.
    pub target_backup_bytes: u64,
    /// Greatest canonical plan bytes, at most 2 TiB.
    pub plan_bytes: u64,
    /// Entries admitted in one commit.
    pub batch_records: usize,
    /// Transformed plaintext bytes admitted in one commit.
    pub batch_bytes: usize,
}

impl ConstructionLimits {
    /// Validates every inclusive version-one bound.
    pub fn validate(self) -> Result<Self, StorageError> {
        self.validate_source_limits()?;
        self.validate_target_limits()?;
        self.validate_work_limits()?;
        Ok(self)
    }

    fn validate_source_limits(self) -> Result<(), StorageError> {
        validate_nonzero_limit(self.source_database_bytes, MAX_CONSTRUCTION_SOURCE_BYTES)?;
        validate_nonzero_limit(self.source_backup_bytes, MAX_CONSTRUCTION_SOURCE_BYTES)
    }

    fn validate_target_limits(self) -> Result<(), StorageError> {
        validate_nonzero_limit(self.target_database_bytes, MAX_CONSTRUCTION_TARGET_BYTES)?;
        validate_nonzero_limit(self.target_backup_bytes, MAX_CONSTRUCTION_TARGET_BYTES)?;
        if self.target_database_bytes > self.target_backup_bytes {
            return Err(StorageError::LimitExceeded);
        }
        Ok(())
    }

    fn validate_work_limits(self) -> Result<(), StorageError> {
        validate_nonzero_limit(self.plan_bytes, MAX_CONSTRUCTION_PLAN_BYTES)?;
        validate_nonzero_usize_limit(self.batch_records, MAX_CONSTRUCTION_BATCH_RECORDS)?;
        validate_nonzero_usize_limit(self.batch_bytes, MAX_CONSTRUCTION_BATCH_BYTES)
    }
}

fn validate_nonzero_limit(value: u64, maximum: u64) -> Result<(), StorageError> {
    if value == 0 || value > maximum {
        return Err(StorageError::LimitExceeded);
    }
    Ok(())
}

fn validate_nonzero_usize_limit(value: usize, maximum: usize) -> Result<(), StorageError> {
    if value == 0 || value > maximum {
        return Err(StorageError::LimitExceeded);
    }
    Ok(())
}

/// Rebuilt, hash-verified construction plan in target order.
pub struct ConstructionPlan {
    kind: StorageConstructionKind,
    storage: ConstructionPlanStorage,
    entry_count: u64,
    encoded_bytes: u64,
    hash: StorageDigest,
}

enum ConstructionPlanStorage {
    Memory(Vec<StorageConstructionPlanEntry>),
    Disk(Database),
}

/// Incremental secret-free writer for one scratch construction plan.
pub struct ConstructionPlanBuilder {
    kind: StorageConstructionKind,
    database: Database,
    transaction: redb::WriteTransaction,
    expected_entries: Option<u64>,
    entry_count: u64,
    encoded_bytes: u64,
    maximum_bytes: u64,
}

impl ConstructionPlanBuilder {
    /// Creates or replaces one scratch redb plan table.
    pub fn start(
        kind: StorageConstructionKind,
        expected_entries: u64,
        file: File,
        limits: ConstructionLimits,
    ) -> Result<Self, StorageError> {
        Self::start_inner(kind, Some(expected_entries), file, limits)
    }

    /// Creates a plan whose exact entry count is established by one streamed preflight.
    pub fn start_streaming(
        kind: StorageConstructionKind,
        file: File,
        limits: ConstructionLimits,
    ) -> Result<Self, StorageError> {
        Self::start_inner(kind, None, file, limits)
    }

    fn start_inner(
        kind: StorageConstructionKind,
        expected_entries: Option<u64>,
        file: File,
        limits: ConstructionLimits,
    ) -> Result<Self, StorageError> {
        let limits = limits.validate()?;
        let maximum_bytes = limits.plan_bytes.min(MAX_CONSTRUCTION_PLAN_BYTES);
        let mut builder = redb::Builder::new();
        builder.set_cache_size(CONSTRUCTION_PLAN_CACHE_BYTES);
        let database = builder
            .create_file(file)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let mut transaction = database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| StorageError::DatabaseRejected)?;
        transaction.set_two_phase_commit(true);
        {
            let mut ordered = transaction
                .open_table(CONSTRUCTION_PLAN_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            ordered
                .retain(|_, _| false)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let mut unsorted = transaction
                .open_table(CONSTRUCTION_PLAN_UNSORTED_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            unsorted
                .retain(|_, _| false)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let mut channels = transaction
                .open_table(RESTORE_CHANNEL_SOURCE_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            channels
                .retain(|_, _| false)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let mut current = transaction
                .open_table(RESTORE_CURRENT_RECORD_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            current
                .retain(|_, _| false)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let mut references = transaction
                .open_table(RESTORE_REFERENCE_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            references
                .retain(|_, _| false)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let mut manifests = transaction
                .open_table(RESTORE_MANIFEST_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            manifests
                .retain(|_, _| false)
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        Ok(Self {
            kind,
            database,
            transaction,
            expected_entries,
            entry_count: 0,
            encoded_bytes: 0,
            maximum_bytes,
        })
    }

    /// Indexes one unique target entry while retaining no prior entry body.
    pub fn push(&mut self, entry: StorageConstructionPlanEntry) -> Result<(), StorageError> {
        if self
            .expected_entries
            .is_some_and(|expected| self.entry_count == expected)
        {
            return Err(StorageError::LimitExceeded);
        }
        let encoded = entry.encode()?;
        StorageConstructionPlanEntry::decode(self.kind, &encoded)?;
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(u64::try_from(encoded.len()).map_err(|_| StorageError::Overflow)?)
            .ok_or(StorageError::Overflow)?;
        if self.encoded_bytes > self.maximum_bytes {
            return Err(StorageError::LimitExceeded);
        }
        let target = construction_plan_target_key(&entry)?;
        {
            let mut table = self
                .transaction
                .open_table(CONSTRUCTION_PLAN_UNSORTED_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            if table
                .insert(target.as_slice(), encoded.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?
                .is_some()
            {
                return Err(StorageError::InvalidEncoding);
            }
        }
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        Ok(())
    }

    fn index_restore_channel_source(
        &mut self,
        source: &StorageConstructionSource,
    ) -> Result<(), StorageError> {
        if self.kind != StorageConstructionKind::Restore
            || source.kind() != StorageConstructionSourceKind::BackupRecord
            || source.table() != TableId::Channel
        {
            return Err(StorageError::InvalidEncoding);
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(44)
            .map_err(|_| StorageError::AllocationFailed)?;
        encoded.extend_from_slice(&source.record_schema().to_be_bytes());
        encoded.extend_from_slice(source.sealed_record_id().as_bytes());
        encoded.extend_from_slice(&source.backup_byte_offset().to_be_bytes());
        let mut table = self
            .transaction
            .open_table(RESTORE_CHANNEL_SOURCE_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        if table
            .insert(source.key().as_bytes(), encoded.as_slice())
            .map_err(|_| StorageError::DatabaseRejected)?
            .is_some()
        {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    fn restore_channel_source(
        &self,
        key: &StoredKey,
    ) -> Result<StorageConstructionSource, StorageError> {
        let table = self
            .transaction
            .open_table(RESTORE_CHANNEL_SOURCE_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let encoded = table
            .get(key.as_bytes())
            .map_err(|_| StorageError::DatabaseRejected)?
            .ok_or(StorageError::StaleState)?;
        let encoded = encoded.value();
        let (schema, remaining) = encoded
            .split_first_chunk::<4>()
            .ok_or(StorageError::InvalidEncoding)?;
        let (record_id, offset) = remaining
            .split_first_chunk::<32>()
            .ok_or(StorageError::InvalidEncoding)?;
        let offset: [u8; 8] = offset
            .try_into()
            .map_err(|_| StorageError::InvalidEncoding)?;
        StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            TableId::Channel,
            StoredKey::new(key.as_bytes().to_vec())?,
            u32::from_be_bytes(*schema),
            StorageDigest::from_bytes(*record_id),
            u64::from_be_bytes(offset),
        )
    }

    fn observe_restore_source_record(
        &mut self,
        source: &StorageConstructionSource,
        record: &ConstructionSourceRecord,
    ) -> Result<(), StorageError> {
        if self.kind != StorageConstructionKind::Restore {
            return Err(StorageError::InvalidEncoding);
        }
        if source.table().is_integrity_tracked() {
            let identity = restore_scratch_key(source.table(), source.key())?;
            let mut version = Vec::new();
            version
                .try_reserve_exact(36)
                .map_err(|_| StorageError::AllocationFailed)?;
            version.extend_from_slice(&source.record_schema().to_be_bytes());
            version.extend_from_slice(source.sealed_record_id().as_bytes());
            {
                let mut current = self
                    .transaction
                    .open_table(RESTORE_CURRENT_RECORD_TABLE)
                    .map_err(|_| StorageError::DatabaseRejected)?;
                if current
                    .insert(identity.as_slice(), version.as_slice())
                    .map_err(|_| StorageError::DatabaseRejected)?
                    .is_some()
                {
                    return Err(StorageError::StaleState);
                }
            }
            let references =
                construction_record_references(source.table(), source.key(), record.plaintext())?;
            let mut table = self
                .transaction
                .open_table(RESTORE_REFERENCE_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            for (index, reference) in references.iter().enumerate() {
                let mut reference_key = identity.clone();
                reference_key.extend_from_slice(
                    &u32::try_from(index)
                        .map_err(|_| StorageError::Overflow)?
                        .to_be_bytes(),
                );
                let target = restore_scratch_key(reference.table(), reference.key())?;
                table
                    .insert(reference_key.as_slice(), target.as_slice())
                    .map_err(|_| StorageError::DatabaseRejected)?;
            }
        }
        if source.table() == TableId::IntegrityManifest {
            let manifest = IntegrityManifest::decode(record.plaintext())?;
            let mut manifests = self
                .transaction
                .open_table(RESTORE_MANIFEST_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            if manifests
                .insert(manifest.tbs().manifest_sequence, record.plaintext())
                .map_err(|_| StorageError::DatabaseRejected)?
                .is_some()
            {
                return Err(StorageError::StaleState);
            }
        }
        Ok(())
    }

    fn verify_restore_source(
        &self,
        state: StateMetaTbs,
        checkpoint: &IntegrityCheckpoint,
    ) -> Result<(), StorageError> {
        if (
            checkpoint.tbs().cut_manifest_sequence,
            checkpoint.checkpoint_hash(),
        ) != (state.checkpoint_manifest_sequence, state.checkpoint_hash)
        {
            return Err(StorageError::StaleState);
        }
        self.verify_restore_references()?;
        self.reverse_restore_manifests(state)?;
        self.verify_restore_checkpoint(checkpoint)
    }

    fn verify_restore_references(&self) -> Result<(), StorageError> {
        let current = self
            .transaction
            .open_table(RESTORE_CURRENT_RECORD_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let references = self
            .transaction
            .open_table(RESTORE_REFERENCE_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        for row in references
            .iter()
            .map_err(|_| StorageError::DatabaseRejected)?
        {
            let (_, target) = row.map_err(|_| StorageError::DatabaseRejected)?;
            if current
                .get(target.value())
                .map_err(|_| StorageError::DatabaseRejected)?
                .is_none()
            {
                return Err(StorageError::StaleState);
            }
        }
        Ok(())
    }

    fn reverse_restore_manifests(&self, state: StateMetaTbs) -> Result<(), StorageError> {
        if state.manifest_sequence > state.checkpoint_manifest_sequence {
            for sequence in (state.checkpoint_manifest_sequence + 1..=state.manifest_sequence).rev()
            {
                self.reverse_restore_manifest(sequence)?;
            }
        }
        Ok(())
    }

    fn reverse_restore_manifest(&self, sequence: u64) -> Result<(), StorageError> {
        let encoded = {
            let manifests = self
                .transaction
                .open_table(RESTORE_MANIFEST_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            manifests
                .get(sequence)
                .map_err(|_| StorageError::DatabaseRejected)?
                .ok_or(StorageError::StaleState)?
                .value()
                .to_vec()
        };
        let manifest = IntegrityManifest::decode(&encoded)?;
        let mut current = self
            .transaction
            .open_table(RESTORE_CURRENT_RECORD_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        for mutation in manifest.tbs().mutations().iter().rev() {
            let key = restore_scratch_key(mutation.table(), mutation.stored_key())?;
            let actual = current
                .get(key.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?
                .map(|value| decode_restore_version(value.value()))
                .transpose()?
                .unwrap_or(IntegrityRecordVersion::Absent);
            if actual != mutation.after() {
                return Err(StorageError::StaleState);
            }
            match encode_restore_version(mutation.before())? {
                Some(value) => current
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(|_| StorageError::DatabaseRejected)?,
                None => current
                    .remove(key.as_slice())
                    .map_err(|_| StorageError::DatabaseRejected)?,
            };
        }
        Ok(())
    }

    fn verify_restore_checkpoint(
        &self,
        checkpoint: &IntegrityCheckpoint,
    ) -> Result<(), StorageError> {
        let current = self
            .transaction
            .open_table(RESTORE_CURRENT_RECORD_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let count = current.len().map_err(|_| StorageError::DatabaseRejected)?;
        let mut hasher = TrackedStateHasher::new(count);
        for row in current.iter().map_err(|_| StorageError::DatabaseRejected)? {
            let (identity, encoded) = row.map_err(|_| StorageError::DatabaseRejected)?;
            let (table, key) = decode_restore_scratch_key(identity.value())?;
            let (record_schema, sealed_record_id) = decode_restore_present(encoded.value())?;
            let tuple = tracked_commitment_tuple(table, &key, record_schema, sealed_record_id)?;
            hasher.update(tracked_record_commitment(&tuple)?)?;
        }
        if (count, hasher.finalize()?)
            != (
                checkpoint.tbs().tracked_record_count,
                checkpoint.tbs().tracked_state_digest,
            )
        {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    /// Durably commits and independently re-reads the complete scratch plan.
    pub fn finish(self) -> Result<ConstructionPlan, StorageError> {
        if self
            .expected_entries
            .is_some_and(|expected| self.entry_count != expected)
        {
            return Err(StorageError::StaleState);
        }
        let mut hasher = ConstructionPlanHasher::new(self.entry_count, self.maximum_bytes)?;
        let mut key_state_records = 0_u8;
        let mut previous_target: Option<(TableId, Vec<u8>)> = None;
        {
            let unsorted = self
                .transaction
                .open_table(CONSTRUCTION_PLAN_UNSORTED_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let mut ordered = self
                .transaction
                .open_table(CONSTRUCTION_PLAN_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            for (index, row) in unsorted
                .iter()
                .map_err(|_| StorageError::DatabaseRejected)?
                .enumerate()
            {
                let (_, encoded) = row.map_err(|_| StorageError::DatabaseRejected)?;
                let entry = StorageConstructionPlanEntry::decode(self.kind, encoded.value())?;
                let target = (entry.target_table(), entry.target_key().as_bytes().to_vec());
                if previous_target.as_ref().is_some_and(|previous| {
                    (previous.0, previous.1.as_slice()) >= (target.0, target.1.as_slice())
                }) {
                    return Err(StorageError::InvalidEncoding);
                }
                if entry.target_table() == TableId::LoginIndexKeyState {
                    key_state_records = key_state_records
                        .checked_add(1)
                        .ok_or(StorageError::Overflow)?;
                }
                hasher.update_entry(encoded.value())?;
                ordered
                    .insert(
                        u64::try_from(index)
                            .map_err(|_| StorageError::Overflow)?
                            .to_be_bytes()
                            .as_slice(),
                        encoded.value(),
                    )
                    .map_err(|_| StorageError::DatabaseRejected)?;
                previous_target = Some(target);
            }
        }
        if key_state_records != 1 {
            return Err(StorageError::StaleState);
        }
        let hash = hasher.finalize()?;
        self.transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let plan = ConstructionPlan {
            kind: self.kind,
            storage: ConstructionPlanStorage::Disk(self.database),
            entry_count: self.entry_count,
            encoded_bytes: self.encoded_bytes,
            hash,
        };
        plan.reverify_disk()?;
        Ok(plan)
    }
}

fn construction_plan_target_key(
    entry: &StorageConstructionPlanEntry,
) -> Result<Vec<u8>, StorageError> {
    let mut key = Vec::new();
    key.try_reserve_exact(
        2_usize
            .checked_add(entry.target_key().as_bytes().len())
            .ok_or(StorageError::Overflow)?,
    )
    .map_err(|_| StorageError::AllocationFailed)?;
    key.extend_from_slice(&entry.target_table().as_u16().to_be_bytes());
    key.extend_from_slice(entry.target_key().as_bytes());
    Ok(key)
}

fn restore_scratch_key(table: TableId, key: &StoredKey) -> Result<Vec<u8>, StorageError> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(
            2_usize
                .checked_add(key.as_bytes().len())
                .ok_or(StorageError::Overflow)?,
        )
        .map_err(|_| StorageError::AllocationFailed)?;
    encoded.extend_from_slice(&table.as_u16().to_be_bytes());
    encoded.extend_from_slice(key.as_bytes());
    Ok(encoded)
}

fn decode_restore_scratch_key(encoded: &[u8]) -> Result<(TableId, StoredKey), StorageError> {
    let (table, key) = encoded
        .split_first_chunk::<2>()
        .ok_or(StorageError::InvalidEncoding)?;
    let table = TableId::from_u16(u16::from_be_bytes(*table))?;
    if !table.is_integrity_tracked() {
        return Err(StorageError::InvalidEncoding);
    }
    Ok((table, StoredKey::new(key.to_vec())?))
}

fn encode_restore_version(
    version: IntegrityRecordVersion,
) -> Result<Option<[u8; 36]>, StorageError> {
    let IntegrityRecordVersion::Present {
        record_schema,
        sealed_record_id,
    } = version
    else {
        return Ok(None);
    };
    if record_schema == 0 {
        return Err(StorageError::InvalidEncoding);
    }
    let mut encoded = [0_u8; 36];
    encoded[..4].copy_from_slice(&record_schema.to_be_bytes());
    encoded[4..].copy_from_slice(sealed_record_id.as_bytes());
    Ok(Some(encoded))
}

fn decode_restore_version(encoded: &[u8]) -> Result<IntegrityRecordVersion, StorageError> {
    let (record_schema, sealed_record_id) = decode_restore_present(encoded)?;
    Ok(IntegrityRecordVersion::Present {
        record_schema,
        sealed_record_id,
    })
}

fn decode_restore_present(encoded: &[u8]) -> Result<(u32, StorageDigest), StorageError> {
    let (schema, record_id) = encoded
        .split_first_chunk::<4>()
        .ok_or(StorageError::InvalidEncoding)?;
    let record_id: [u8; 32] = record_id
        .try_into()
        .map_err(|_| StorageError::InvalidEncoding)?;
    let record_schema = u32::from_be_bytes(*schema);
    if record_schema == 0 {
        return Err(StorageError::InvalidEncoding);
    }
    Ok((record_schema, StorageDigest::from_bytes(record_id)))
}

fn tracked_commitment_tuple(
    table: TableId,
    stored_key: &StoredKey,
    record_schema: u32,
    sealed_record_id: StorageDigest,
) -> Result<Vec<u8>, StorageError> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(
            42_usize
                .checked_add(stored_key.as_bytes().len())
                .ok_or(StorageError::Overflow)?,
        )
        .map_err(|_| StorageError::AllocationFailed)?;
    encoded.extend_from_slice(&table.as_u16().to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(stored_key.as_bytes().len())
            .map_err(|_| StorageError::Overflow)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(stored_key.as_bytes());
    encoded.extend_from_slice(&record_schema.to_be_bytes());
    encoded.extend_from_slice(sealed_record_id.as_bytes());
    Ok(encoded)
}

fn construction_record_references(
    table: TableId,
    stored_key: &StoredKey,
    plaintext: &[u8],
) -> Result<Vec<RecordReference>, StorageError> {
    if table == TableId::LoginIndex {
        let login_key = crate::LoginIndexStoredKey::decode(stored_key.as_bytes())?;
        let value = crate::LoginIndexValue::decode(plaintext, &login_key)?;
        return match value.kind() {
            crate::LoginIndexValueKind::Live { account_id, .. } => Ok(vec![
                RecordReference::new(
                    TableId::Account,
                    StoredKey::new(account_id.to_text().as_bytes().to_vec())?,
                )?,
                RecordReference::new(
                    TableId::OpaqueRecord,
                    StoredKey::new(account_id.to_text().as_bytes().to_vec())?,
                )?,
            ]),
            crate::LoginIndexValueKind::CreationReservation { transaction_id, .. } => {
                Ok(vec![RecordReference::new(
                    TableId::AuthTransaction,
                    StoredKey::new(transaction_id.as_bytes().to_vec())?,
                )?])
            }
            crate::LoginIndexValueKind::DeletionTombstone {
                deleted_account_id, ..
            } => Ok(vec![RecordReference::new(
                TableId::Account,
                StoredKey::new(deleted_account_id.to_text().as_bytes().to_vec())?,
            )?]),
        };
    }
    if crate::table_schema(table).codec() == crate::RecordCodecKind::Domain {
        return Ok(PersistentRecordValue::decode(table, plaintext)?
            .references()
            .to_vec());
    }
    Ok(Vec::new())
}

impl ConstructionPlan {
    /// Validates target order, byte ceiling, required key state, count, and identity hash.
    pub fn new(
        identity: &StorageOperationIdentity,
        entries: Vec<StorageConstructionPlanEntry>,
        limits: ConstructionLimits,
    ) -> Result<Self, StorageError> {
        let limits = limits.validate()?;
        identity.validate()?;
        let count = u64::try_from(entries.len()).map_err(|_| StorageError::Overflow)?;
        if count != identity.planned_entry_count {
            return Err(StorageError::ResumeMismatch);
        }
        let mut encoded_bytes = 0_u64;
        let mut key_state_records = 0_u8;
        for entry in &entries {
            encoded_bytes = encoded_bytes
                .checked_add(
                    u64::try_from(entry.encode()?.len()).map_err(|_| StorageError::Overflow)?,
                )
                .ok_or(StorageError::Overflow)?;
            if encoded_bytes > limits.plan_bytes {
                return Err(StorageError::LimitExceeded);
            }
            if entry.target_table() == TableId::LoginIndexKeyState {
                key_state_records = key_state_records
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?;
            }
        }
        if key_state_records != 1 {
            return Err(StorageError::StaleState);
        }
        let hash = construction_plan_hash(identity.kind, &entries, limits.plan_bytes)?;
        if hash != identity.construction_plan_hash {
            return Err(StorageError::ResumeMismatch);
        }
        Ok(Self {
            kind: identity.kind,
            storage: ConstructionPlanStorage::Memory(entries),
            entry_count: count,
            encoded_bytes,
            hash,
        })
    }

    /// Rebuilds a secret-free scratch redb plan from one streamed preflight.
    pub fn rebuild_disk<I>(
        identity: &StorageOperationIdentity,
        file: File,
        entries: I,
        limits: ConstructionLimits,
    ) -> Result<Self, StorageError>
    where
        I: IntoIterator<Item = Result<StorageConstructionPlanEntry, StorageError>>,
    {
        identity.validate()?;
        let mut builder = ConstructionPlanBuilder::start(
            identity.kind,
            identity.planned_entry_count,
            file,
            limits,
        )?;
        for entry in entries {
            builder.push(entry?)?;
        }
        let plan = builder.finish()?;
        plan.validate_identity(identity)?;
        Ok(plan)
    }

    /// Returns the operation kind bound by the plan.
    #[must_use]
    pub const fn kind(&self) -> StorageConstructionKind {
        self.kind
    }

    /// Returns the exact number of canonical entries.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Returns the exact canonical entry-byte total.
    #[must_use]
    pub const fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }

    /// Returns the recomputed complete plan hash.
    #[must_use]
    pub const fn hash(&self) -> StorageDigest {
        self.hash
    }

    /// Binds a rebuilt scratch plan to one authenticated construction identity.
    pub fn validate_identity(
        &self,
        identity: &StorageOperationIdentity,
    ) -> Result<(), StorageError> {
        identity.validate()?;
        if identity.kind != self.kind
            || identity.planned_entry_count != self.entry_count
            || identity.construction_plan_hash != self.hash
        {
            return Err(StorageError::ResumeMismatch);
        }
        Ok(())
    }

    fn entry(&self, index: u64) -> Result<Option<StorageConstructionPlanEntry>, StorageError> {
        if index >= self.entry_count {
            return Ok(None);
        }
        match &self.storage {
            ConstructionPlanStorage::Memory(entries) => {
                let index = usize::try_from(index).map_err(|_| StorageError::Overflow)?;
                entries
                    .get(index)
                    .map(|entry| StorageConstructionPlanEntry::decode(self.kind, &entry.encode()?))
                    .transpose()
            }
            ConstructionPlanStorage::Disk(database) => {
                let transaction = database
                    .begin_read()
                    .map_err(|_| StorageError::DatabaseRejected)?;
                let table = transaction
                    .open_table(CONSTRUCTION_PLAN_TABLE)
                    .map_err(|_| StorageError::DatabaseRejected)?;
                let encoded = table
                    .get(index.to_be_bytes().as_slice())
                    .map_err(|_| StorageError::DatabaseRejected)?
                    .ok_or(StorageError::StaleState)?;
                StorageConstructionPlanEntry::decode(self.kind, encoded.value()).map(Some)
            }
        }
    }

    fn reverify_disk(&self) -> Result<(), StorageError> {
        let ConstructionPlanStorage::Disk(database) = &self.storage else {
            return Ok(());
        };
        let transaction = database
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let table = transaction
            .open_table(CONSTRUCTION_PLAN_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let mut hasher =
            ConstructionPlanHasher::new(self.entry_count, MAX_CONSTRUCTION_PLAN_BYTES)?;
        let mut count = 0_u64;
        let mut bytes = 0_u64;
        let mut previous_target: Option<(TableId, Vec<u8>)> = None;
        for row in table.iter().map_err(|_| StorageError::DatabaseRejected)? {
            let (key, encoded) = row.map_err(|_| StorageError::DatabaseRejected)?;
            if key.value() != count.to_be_bytes().as_slice() {
                return Err(StorageError::StaleState);
            }
            let entry = StorageConstructionPlanEntry::decode(self.kind, encoded.value())?;
            let target = (entry.target_table(), entry.target_key().as_bytes().to_vec());
            if previous_target.as_ref().is_some_and(|previous| {
                (previous.0, previous.1.as_slice()) >= (target.0, target.1.as_slice())
            }) {
                return Err(StorageError::InvalidEncoding);
            }
            let canonical = entry.encode()?;
            bytes = bytes
                .checked_add(u64::try_from(canonical.len()).map_err(|_| StorageError::Overflow)?)
                .ok_or(StorageError::Overflow)?;
            hasher.update_entry(&canonical)?;
            count = count.checked_add(1).ok_or(StorageError::Overflow)?;
            previous_target = Some(target);
        }
        if count != self.entry_count
            || bytes != self.encoded_bytes
            || hasher.finalize()? != self.hash
        {
            return Err(StorageError::ResumeMismatch);
        }
        Ok(())
    }

    /// Executes every transform without creating the target and predicts its exact final charges.
    pub fn preflight<R, T>(
        &self,
        marker: &StorageConstruction,
        target_state_generation: u64,
        target_account_service_response_count: u64,
        source: &mut R,
        transformer: &mut T,
        limits: ConstructionLimits,
    ) -> Result<ConstructionPreflight, StorageError>
    where
        R: ConstructionSourceReader,
        T: ConstructionTransformer,
    {
        self.preflight_with(
            marker,
            target_state_generation,
            target_account_service_response_count,
            source,
            transformer,
            limits,
        )
    }

    fn preflight_with(
        &self,
        marker: &StorageConstruction,
        target_state_generation: u64,
        target_account_service_response_count: u64,
        source: &mut dyn ConstructionSourceReader,
        transformer: &mut dyn ConstructionTransformer,
        limits: ConstructionLimits,
    ) -> Result<ConstructionPreflight, StorageError> {
        let limits = limits.validate()?;
        self.validate_initial_marker(marker)?;
        let initial = initial_construction_accounting(marker, limits)?;
        let mut simulation = ConstructionPreflightSimulation::new(
            marker,
            initial,
            target_state_generation,
            target_account_service_response_count,
            limits,
        );
        while simulation.marker.target_records_committed < self.entry_count {
            simulation.service_batch(self, source, transformer)?;
        }
        simulation.finalize()
    }

    fn validate_initial_marker(&self, marker: &StorageConstruction) -> Result<(), StorageError> {
        marker.validate()?;
        self.validate_identity(&marker.identity)?;
        if marker.next_target != StorageConstructionCursor::BeforeFirst {
            return Err(StorageError::ResumeMismatch);
        }
        Ok(())
    }
}

/// Exact target accounting and counters produced by a clean construction execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstructionPreflight {
    /// Logical database charge after final checkpoint installation.
    pub final_logical_database_bytes: u64,
    /// Signed-backup stream size after final checkpoint installation.
    pub final_backup_stream_bytes: u64,
    /// Greatest logical database charge before manifest pruning.
    pub peak_logical_database_bytes: u64,
    /// Greatest backup-stream size before manifest pruning.
    pub peak_backup_stream_bytes: u64,
    /// Number of bounded target batches.
    pub target_batch_count: u64,
    /// Completion transaction's storage commit sequence.
    pub finalization_storage_commit_sequence: u64,
    /// Completion transaction's manifest sequence.
    pub finalization_manifest_sequence: u64,
    /// Checkpoint installation storage commit sequence.
    pub checkpoint_storage_commit_sequence: u64,
    /// Checkpoint installation nonce high-water mark.
    pub checkpoint_nonce_draw_high_water: u64,
}

struct ConstructionPreflightSimulation {
    marker: StorageConstruction,
    accounting: StorageAccountingLimits,
    state_generation: u64,
    response_count: u64,
    storage_commit_sequence: u64,
    manifest_sequence: u64,
    nonce_high_water: u64,
    target_batch_count: u64,
    manifest_sealed_bytes: Vec<usize>,
    peak_logical_database_bytes: u64,
    peak_backup_stream_bytes: u64,
    limits: ConstructionLimits,
}

type PreparedConstructionEntry = (StorageConstructionPlanEntry, Zeroizing<Vec<u8>>);

impl ConstructionPreflightSimulation {
    fn new(
        marker: &StorageConstruction,
        accounting: StorageAccountingLimits,
        state_generation: u64,
        response_count: u64,
        limits: ConstructionLimits,
    ) -> Self {
        Self {
            marker: StorageConstruction {
                identity: marker.identity,
                output_path_hash: marker.output_path_hash,
                next_target: StorageConstructionCursor::BeforeFirst,
                target_records_committed: 0,
            },
            accounting,
            state_generation,
            response_count,
            storage_commit_sequence: 0,
            manifest_sequence: 0,
            nonce_high_water: INITIALIZED_NONCE_DRAW_HIGH_WATER,
            target_batch_count: 0,
            manifest_sealed_bytes: Vec::new(),
            peak_logical_database_bytes: accounting.current_logical_database_bytes,
            peak_backup_stream_bytes: accounting.current_backup_stream_bytes,
            limits,
        }
    }

    fn service_batch(
        &mut self,
        plan: &ConstructionPlan,
        source: &mut dyn ConstructionSourceReader,
        transformer: &mut dyn ConstructionTransformer,
    ) -> Result<(), StorageError> {
        let prepared = self.prepare_batch(plan, source, transformer)?;
        let records = prepared
            .iter()
            .map(|(entry, plaintext)| ConstructionTargetRecord {
                entry,
                plaintext: plaintext.as_slice(),
            })
            .collect::<Vec<_>>();
        let successor = successor_marker(&self.marker, plan, records.len())?;
        let mut mutations = prepared
            .iter()
            .map(|(entry, plaintext)| {
                RecordMutation::put(
                    entry.target_table(),
                    StoredKey::new(entry.target_key().as_bytes().to_vec())?,
                    entry.target_record_schema(),
                    None,
                    plaintext.to_vec(),
                )
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        mutations.push(marker_replacement(&self.marker, &successor)?);
        self.apply_manifested_batch(mutations)?;
        self.marker = successor;
        self.target_batch_count = self
            .target_batch_count
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        Ok(())
    }

    fn prepare_batch(
        &self,
        plan: &ConstructionPlan,
        source: &mut dyn ConstructionSourceReader,
        transformer: &mut dyn ConstructionTransformer,
    ) -> Result<Vec<PreparedConstructionEntry>, StorageError> {
        let prepared = prepare_construction_batch(
            plan,
            self.marker.target_records_committed,
            self.limits,
            source,
            transformer,
        )?;
        if prepared.is_empty() {
            return Err(StorageError::StaleState);
        }
        Ok(prepared)
    }

    fn apply_manifested_batch(
        &mut self,
        mutations: Vec<RecordMutation>,
    ) -> Result<(), StorageError> {
        let manifest_bytes = crate::mutation::manifest_sealed_record_bytes(&mutations)?;
        let head = StorageMutationHead {
            transaction_id: TransactionId::from_bytes([0; 16]),
            expected_storage_commit_sequence: self.storage_commit_sequence,
            expected_state_generation: self.state_generation,
            resulting_state_generation: self.state_generation,
            state_advancing_plan_count: 0,
            expected_account_service_response_count: self.response_count,
            resulting_account_service_response_count: self.response_count,
        };
        let batch = StorageMutationBatch::new_construction(head, self.accounting, mutations)?;
        self.accounting.current_logical_database_bytes = batch.resulting_logical_database_bytes();
        self.accounting.current_backup_stream_bytes = batch.resulting_backup_stream_bytes();
        self.peak_logical_database_bytes = self
            .peak_logical_database_bytes
            .max(self.accounting.current_logical_database_bytes);
        self.peak_backup_stream_bytes = self
            .peak_backup_stream_bytes
            .max(self.accounting.current_backup_stream_bytes);
        self.storage_commit_sequence = self
            .storage_commit_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        self.manifest_sequence = self
            .manifest_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        self.nonce_high_water = self
            .nonce_high_water
            .checked_add(u64::from(batch.seal_count()))
            .ok_or(StorageError::Overflow)?;
        self.manifest_sealed_bytes.push(manifest_bytes);
        Ok(())
    }

    fn finalize(mut self) -> Result<ConstructionPreflight, StorageError> {
        let completion = self.predicted_completion()?;
        self.apply_completion(&completion)?;
        self.prune_manifests()?;
        self.add_final_checkpoint()?;
        self.finished_preflight(&completion)
    }

    fn predicted_completion(&self) -> Result<StorageOperationCompletion, StorageError> {
        let finalization_storage_commit_sequence = self
            .storage_commit_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let finalization_manifest_sequence = self
            .manifest_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let finalization_nonce_draw_high_water = self
            .nonce_high_water
            .checked_add(FINALIZATION_NONCE_DRAWS)
            .ok_or(StorageError::Overflow)?;
        let operation_id = self.marker.identity.operation_id()?;
        Ok(StorageOperationCompletion {
            identity: self.marker.identity,
            storage_operation_id: operation_id,
            target_records_committed: self.marker.target_records_committed,
            finalization_storage_commit_sequence,
            finalization_manifest_sequence,
            finalization_state_generation: self.state_generation,
            finalization_account_service_response_count: self.response_count,
            finalization_nonce_draw_high_water,
        })
    }

    fn apply_completion(
        &mut self,
        completion: &StorageOperationCompletion,
    ) -> Result<(), StorageError> {
        let marker_key = StoredKey::new(crate::STORAGE_CONSTRUCTION_KEY.to_vec())?;
        let operation_key = StoredKey::new(completion.storage_operation_id.as_bytes().to_vec())?;
        let mutations = vec![
            RecordMutation::delete(
                TableId::StorageConstruction,
                marker_key,
                encoded_existing(&self.marker.encode()?)?,
            ),
            RecordMutation::put(
                TableId::StorageOperation,
                operation_key,
                1,
                None,
                completion.encode()?,
            )?,
        ];
        self.apply_manifested_batch(mutations)?;
        if self.storage_commit_sequence != completion.finalization_storage_commit_sequence
            || self.manifest_sequence != completion.finalization_manifest_sequence
            || self.nonce_high_water != completion.finalization_nonce_draw_high_water
        {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    fn finished_preflight(
        self,
        completion: &StorageOperationCompletion,
    ) -> Result<ConstructionPreflight, StorageError> {
        let checkpoint_storage_commit_sequence = self
            .storage_commit_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let checkpoint_nonce_draw_high_water = self
            .nonce_high_water
            .checked_add(CHECKPOINT_INSTALLATION_NONCE_DRAWS)
            .ok_or(StorageError::Overflow)?;
        Ok(ConstructionPreflight {
            final_logical_database_bytes: self.accounting.current_logical_database_bytes,
            final_backup_stream_bytes: self.accounting.current_backup_stream_bytes,
            peak_logical_database_bytes: self.peak_logical_database_bytes,
            peak_backup_stream_bytes: self.peak_backup_stream_bytes,
            target_batch_count: self.target_batch_count,
            finalization_storage_commit_sequence: completion.finalization_storage_commit_sequence,
            finalization_manifest_sequence: completion.finalization_manifest_sequence,
            checkpoint_storage_commit_sequence,
            checkpoint_nonce_draw_high_water,
        })
    }

    fn prune_manifests(&mut self) -> Result<(), StorageError> {
        for sealed_bytes in &self.manifest_sealed_bytes {
            let logical = logical_record_charge(SEQUENCE_STORED_KEY_BYTES, *sealed_bytes)?;
            self.accounting.current_logical_database_bytes = self
                .accounting
                .current_logical_database_bytes
                .checked_sub(logical)
                .ok_or(StorageError::StaleState)?;
            self.accounting.current_backup_stream_bytes = self
                .accounting
                .current_backup_stream_bytes
                .checked_sub(
                    logical
                        .checked_add(crate::backup::BACKUP_RECORD_OVERHEAD_BYTES)
                        .ok_or(StorageError::Overflow)?,
                )
                .ok_or(StorageError::StaleState)?;
        }
        Ok(())
    }

    fn add_final_checkpoint(&mut self) -> Result<(), StorageError> {
        add_preflight_record_charge(
            &mut self.accounting.current_logical_database_bytes,
            &mut self.accounting.current_backup_stream_bytes,
            SEQUENCE_STORED_KEY_BYTES,
            INTEGRITY_CHECKPOINT_BYTES,
        )?;
        if self.accounting.current_logical_database_bytes > self.accounting.database_max_bytes
            || self.accounting.current_backup_stream_bytes > self.accounting.backup_max_bytes
        {
            return Err(StorageError::LimitExceeded);
        }
        self.peak_logical_database_bytes = self
            .peak_logical_database_bytes
            .max(self.accounting.current_logical_database_bytes);
        self.peak_backup_stream_bytes = self
            .peak_backup_stream_bytes
            .max(self.accounting.current_backup_stream_bytes);
        Ok(())
    }
}

fn read_construction_sources(
    source: &mut dyn ConstructionSourceReader,
    entry: &StorageConstructionPlanEntry,
) -> Result<Vec<ConstructionSourceRecord>, StorageError> {
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(entry.sources().len())
        .map_err(|_| StorageError::AllocationFailed)?;
    for reference in entry.sources() {
        sources.push(source.read_source(reference)?);
    }
    Ok(sources)
}

/// Transforms consecutive plan entries from `committed` until the batch record or byte
/// ceiling is reached. The result is empty only when no entry remains; the preflight
/// simulation and the executor apply their own policy to that case.
fn prepare_construction_batch(
    plan: &ConstructionPlan,
    committed: u64,
    limits: ConstructionLimits,
    source: &mut dyn ConstructionSourceReader,
    transformer: &mut dyn ConstructionTransformer,
) -> Result<Vec<PreparedConstructionEntry>, StorageError> {
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(limits.batch_records)
        .map_err(|_| StorageError::AllocationFailed)?;
    let mut transformed_bytes = 0_usize;
    while prepared.len() < limits.batch_records {
        let index = committed
            .checked_add(u64::try_from(prepared.len()).map_err(|_| StorageError::Overflow)?)
            .ok_or(StorageError::Overflow)?;
        let Some(entry) = plan.entry(index)? else {
            break;
        };
        let sources = read_construction_sources(source, &entry)?;
        let plaintext = transformer.transform(plan.kind(), &entry, &sources)?;
        validate_record_plaintext(
            entry.target_table(),
            entry.target_key(),
            entry.target_record_schema(),
            &plaintext,
        )?;
        let next_bytes = transformed_bytes
            .checked_add(plaintext.len())
            .ok_or(StorageError::Overflow)?;
        if next_bytes > limits.batch_bytes {
            if prepared.is_empty() {
                return Err(StorageError::LimitExceeded);
            }
            break;
        }
        prepared.push((entry, plaintext));
        transformed_bytes = next_bytes;
    }
    Ok(prepared)
}

fn marker_replacement(
    marker: &StorageConstruction,
    successor: &StorageConstruction,
) -> Result<RecordMutation, StorageError> {
    RecordMutation::put(
        TableId::StorageConstruction,
        StoredKey::new(crate::STORAGE_CONSTRUCTION_KEY.to_vec())?,
        1,
        Some(encoded_existing(&marker.encode()?)?),
        successor.encode()?,
    )
}

fn encoded_existing(plaintext: &[u8]) -> Result<ExistingRecord, StorageError> {
    ExistingRecord::new(
        1,
        StorageDigest::from_bytes([0; 32]),
        plaintext
            .len()
            .checked_add(MIN_SEALED_RECORD_BYTES)
            .ok_or(StorageError::Overflow)?,
    )
}

fn initial_construction_accounting(
    marker: &StorageConstruction,
    limits: ConstructionLimits,
) -> Result<StorageAccountingLimits, StorageError> {
    let mut logical = logical_meta_charge(
        crate::redb_store::HEADER_META_KEY.len(),
        crate::DATABASE_HEADER_BYTES,
    )?
    .checked_add(logical_meta_charge(
        crate::redb_store::RESERVATION_META_KEY.len(),
        crate::NONCE_RESERVATION_BYTES,
    )?)
    .ok_or(StorageError::Overflow)?;
    let mut backup = BACKUP_FIXED_STREAM_BYTES;
    add_preflight_record_charge(
        &mut logical,
        &mut backup,
        crate::KEY_CHECK_STORED_KEY.len(),
        KEY_CHECK_PLAINTEXT_BYTES,
    )?;
    add_preflight_record_charge(
        &mut logical,
        &mut backup,
        crate::STORAGE_CONSTRUCTION_KEY.len(),
        marker.encode()?.len(),
    )?;
    add_preflight_record_charge(
        &mut logical,
        &mut backup,
        SEQUENCE_STORED_KEY_BYTES,
        INTEGRITY_CHECKPOINT_BYTES,
    )?;
    add_preflight_record_charge(
        &mut logical,
        &mut backup,
        crate::STATE_META_STORED_KEY.len(),
        STATE_META_BYTES,
    )?;
    if logical > limits.target_database_bytes || backup > limits.target_backup_bytes {
        return Err(StorageError::LimitExceeded);
    }
    Ok(StorageAccountingLimits {
        current_logical_database_bytes: logical,
        current_backup_stream_bytes: backup,
        database_max_bytes: limits.target_database_bytes,
        backup_max_bytes: limits.target_backup_bytes,
    })
}

fn add_preflight_record_charge(
    logical: &mut u64,
    backup: &mut u64,
    key_bytes: usize,
    plaintext_bytes: usize,
) -> Result<(), StorageError> {
    let sealed_bytes = plaintext_bytes
        .checked_add(MIN_SEALED_RECORD_BYTES)
        .ok_or(StorageError::Overflow)?;
    let charge = logical_record_charge(key_bytes, sealed_bytes)?;
    *logical = logical.checked_add(charge).ok_or(StorageError::Overflow)?;
    *backup = backup
        .checked_add(
            charge
                .checked_add(crate::backup::BACKUP_RECORD_OVERHEAD_BYTES)
                .ok_or(StorageError::Overflow)?,
        )
        .ok_or(StorageError::Overflow)?;
    Ok(())
}

/// One source record reopened and authenticated immediately before transform.
pub struct ConstructionSourceRecord {
    table: TableId,
    key: StoredKey,
    record_schema: u32,
    plaintext: Zeroizing<Vec<u8>>,
}

impl ConstructionSourceRecord {
    /// Opens a database or backup source under its exact signed plan reference.
    pub fn open(
        reference: &StorageConstructionSource,
        encoded_sealed_record: &[u8],
        master_key: &StorageMasterKey,
        binding: DatabaseBinding,
        storage_key_generation: u32,
    ) -> Result<Self, StorageError> {
        let sealed = SealedRecord::decode(encoded_sealed_record)?;
        if sealed.record_id()? != reference.sealed_record_id() {
            return Err(StorageError::AuthenticationFailed);
        }
        let plaintext = sealed.open(
            master_key,
            binding,
            reference.table(),
            reference.record_schema(),
            storage_key_generation,
            reference.key(),
        )?;
        validate_record_plaintext(
            reference.table(),
            reference.key(),
            reference.record_schema(),
            plaintext.expose_for_storage_codec(),
        )?;
        Ok(Self {
            table: reference.table(),
            key: StoredKey::new(reference.key().as_bytes().to_vec())?,
            record_schema: reference.record_schema(),
            plaintext: Zeroizing::new(plaintext.expose_for_storage_codec().to_vec()),
        })
    }

    /// Returns the authenticated source table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Borrows the authenticated source key.
    #[must_use]
    pub const fn key(&self) -> &StoredKey {
        &self.key
    }

    /// Returns the authenticated source record schema.
    #[must_use]
    pub const fn record_schema(&self) -> u32 {
        self.record_schema
    }

    /// Borrows plaintext only at the fixed transform boundary.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

/// Source adapter that reopens exact references on every attempt.
pub trait ConstructionSourceReader {
    /// Reopens and authenticates one source reference.
    fn read_source(
        &mut self,
        reference: &StorageConstructionSource,
    ) -> Result<ConstructionSourceRecord, StorageError>;
}

/// Authenticated control facts retained from a fully reconstructed source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstructionSourceFacts {
    /// Complete source database header.
    pub header: DatabaseHeader,
    /// Authenticated source StateMeta counters and integrity anchors.
    pub state: StateMetaTbs,
    /// Complete verified source rollback-guard hash.
    pub rollback_guard_hash: StorageDigest,
}

/// Continuously locked source database used by offline construction commands.
pub struct ConstructionSourceDatabase {
    engine: StorageEngine,
}

impl ConstructionSourceDatabase {
    /// Opens, reconstructs, and cross-validates the complete source database.
    pub fn open(config: StorageOpenConfig) -> Result<Self, StorageError> {
        let engine = StorageEngine::open(config)?;
        let _capacity = engine.startup_scan()?;
        Ok(Self { engine })
    }

    /// Returns authenticated facts needed to bind the construction identity.
    pub fn facts(&self) -> Result<ConstructionSourceFacts, StorageError> {
        Ok(ConstructionSourceFacts {
            header: self.engine.construction_source_header(),
            state: self.engine.construction_source_state(),
            rollback_guard_hash: self.engine.construction_source_guard_hash()?,
        })
    }

    /// Counts all target records after revalidating every source plaintext.
    pub fn rekey_entry_count(&self) -> Result<u64, StorageError> {
        let mut count = 0_u64;
        self.engine.visit_construction_source_records(|_, _| {
            count = count.checked_add(1).ok_or(StorageError::Overflow)?;
            Ok(())
        })?;
        Ok(count)
    }

    /// Scans every login-index row before an offline two-generation key transition.
    pub fn login_index_transition_preflight(
        &self,
        new_key_id: LoginIndexKeyId,
    ) -> Result<crate::LoginIndexKeyState, StorageError> {
        self.engine.login_index_transition_preflight(new_key_id)
    }

    /// Rebuilds a canonical rekey plan while retaining only one plaintext record.
    pub fn rebuild_rekey_plan(
        &self,
        file: File,
        target_master_key: &StorageMasterKey,
        target_binding: DatabaseBinding,
        target_storage_key_generation: u32,
        limits: ConstructionLimits,
    ) -> Result<ConstructionPlan, StorageError> {
        let limits = limits.validate()?;
        let facts = self.facts()?;
        validate_source_charges(facts.state, limits)?;
        validate_rekey_generation(
            self.engine.construction_source_master_key(),
            facts.header.tbs().storage_key_generation,
            target_master_key,
            target_storage_key_generation,
        )?;

        let entry_count = self.rekey_entry_count()?;
        let mut builder = ConstructionPlanBuilder::start(
            StorageConstructionKind::Rekey,
            entry_count,
            file,
            limits,
        )?;
        self.engine
            .visit_construction_source_records(|source, record| {
                let target_key = rekey_target_stored_key(
                    &source,
                    &record,
                    self.engine.construction_source_master_key(),
                    self.engine.construction_source_binding(),
                    facts.header.tbs().storage_key_generation,
                    target_master_key,
                    target_binding,
                    target_storage_key_generation,
                )?;
                builder.push(StorageConstructionPlanEntry::new(
                    StorageConstructionKind::Rekey,
                    vec![source],
                    record.table(),
                    target_key,
                    record.record_schema(),
                    StorageConstructionAction::RekeyCopy,
                    0,
                )?)
            })?;
        builder.finish()
    }
}

impl ConstructionSourceReader for ConstructionSourceDatabase {
    fn read_source(
        &mut self,
        reference: &StorageConstructionSource,
    ) -> Result<ConstructionSourceRecord, StorageError> {
        self.engine.open_construction_source_record(reference)
    }
}

fn validate_source_charges(
    state: StateMetaTbs,
    limits: ConstructionLimits,
) -> Result<(), StorageError> {
    if state.logical_database_bytes > limits.source_database_bytes
        || state.backup_stream_bytes > limits.source_backup_bytes
    {
        return Err(StorageError::LimitExceeded);
    }
    Ok(())
}

fn validate_rekey_generation(
    source_master_key: &StorageMasterKey,
    source_generation: u32,
    target_master_key: &StorageMasterKey,
    target_generation: u32,
) -> Result<(), StorageError> {
    let expected = if source_master_key.matches(target_master_key) {
        source_generation
            .checked_add(1)
            .ok_or(StorageError::LimitExceeded)?
    } else {
        1
    };
    if target_generation != expected {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the key transform binds both complete source and target encryption contexts"
)]
fn rekey_target_stored_key(
    source: &StorageConstructionSource,
    record: &ConstructionSourceRecord,
    source_master_key: &StorageMasterKey,
    source_binding: DatabaseBinding,
    source_generation: u32,
    target_master_key: &StorageMasterKey,
    target_binding: DatabaseBinding,
    target_generation: u32,
) -> Result<StoredKey, StorageError> {
    let semantic_key = match source.table() {
        TableId::NicknameReservation => {
            let value = PersistentRecordValue::decode(source.table(), record.plaintext())?;
            let spelling =
                std::str::from_utf8(value.body()).map_err(|_| StorageError::InvalidEncoding)?;
            Nickname::parse(spelling)
                .map_err(|_| StorageError::InvalidEncoding)?
                .canonical()
                .as_bytes()
                .to_vec()
        }
        TableId::ChannelName => {
            let value = PersistentRecordValue::decode(source.table(), record.plaintext())?;
            let spelling =
                std::str::from_utf8(value.body()).map_err(|_| StorageError::InvalidEncoding)?;
            ChannelName::parse(spelling)
                .map_err(|_| StorageError::InvalidEncoding)?
                .canonical()
                .as_bytes()
                .to_vec()
        }
        _ => return StoredKey::new(source.key().as_bytes().to_vec()),
    };
    let table = StorageTable::new(source.table().as_u16())?;
    let expected_source = derive_storage_index(
        source_master_key,
        source_binding,
        table,
        source_generation,
        &semantic_key,
    )?;
    if !bool::from(
        expected_source
            .expose_for_storage_key()
            .ct_eq(source.key().as_bytes()),
    ) {
        return Err(StorageError::AuthenticationFailed);
    }
    let target = derive_storage_index(
        target_master_key,
        target_binding,
        table,
        target_generation,
        &semantic_key,
    )?;
    StoredKey::new(target.expose_for_storage_key().to_vec())
}

/// Locked live-database source that reopens every planned row through `StoragePort`.
pub struct DatabaseConstructionSourceReader {
    port: StoragePort,
    master_key: StorageMasterKey,
    binding: DatabaseBinding,
    storage_key_generation: u32,
}

impl DatabaseConstructionSourceReader {
    /// Binds one continuously locked and already reconstructed source database.
    pub fn new(
        port: StoragePort,
        master_key: StorageMasterKey,
        binding: DatabaseBinding,
        storage_key_generation: u32,
    ) -> Result<Self, StorageError> {
        if storage_key_generation == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            port,
            master_key,
            binding,
            storage_key_generation,
        })
    }
}

impl ConstructionSourceReader for DatabaseConstructionSourceReader {
    fn read_source(
        &mut self,
        reference: &StorageConstructionSource,
    ) -> Result<ConstructionSourceRecord, StorageError> {
        if reference.kind() != StorageConstructionSourceKind::DatabaseRecord {
            return Err(StorageError::InvalidEncoding);
        }
        let result = self
            .port
            .try_read(ReadPlan::exact(
                reference.table(),
                StoredKey::new(reference.key().as_bytes().to_vec())?,
            ))?
            .wait()?;
        let [record] = result.records.as_slice() else {
            return Err(StorageError::StaleState);
        };
        if record.table != reference.table() || record.key.as_bytes() != reference.key().as_bytes()
        {
            return Err(StorageError::StaleState);
        }
        ConstructionSourceRecord::open(
            reference,
            &record.sealed_record,
            &self.master_key,
            self.binding,
            self.storage_key_generation,
        )
    }
}

/// Seekable, already-verified backup source that reopens one signed record offset at a time.
pub struct BackupConstructionSourceReader<R: Read + Seek> {
    input: R,
    source_master_key: StorageMasterKey,
    binding: DatabaseBinding,
    storage_key_generation: u32,
    stream_bytes: u64,
}

impl<R: Read + Seek> BackupConstructionSourceReader<R> {
    /// Binds one fully verified signed stream and its authenticated source header.
    pub fn new(
        input: R,
        source_master_key: StorageMasterKey,
        binding: DatabaseBinding,
        storage_key_generation: u32,
        stream_bytes: u64,
    ) -> Result<Self, StorageError> {
        if storage_key_generation == 0 || stream_bytes < crate::BACKUP_FIXED_STREAM_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            input,
            source_master_key,
            binding,
            storage_key_generation,
            stream_bytes,
        })
    }
}

impl<R: Read + Seek> ConstructionSourceReader for BackupConstructionSourceReader<R> {
    fn read_source(
        &mut self,
        reference: &StorageConstructionSource,
    ) -> Result<ConstructionSourceRecord, StorageError> {
        if reference.kind() != StorageConstructionSourceKind::BackupRecord {
            return Err(StorageError::InvalidEncoding);
        }
        // This reader validates a frame against the whole stream length it was given;
        // `RestoreBackupSource` narrows the window to the numbered-record region.
        let record = read_backup_frame(
            &mut self.input,
            reference.backup_byte_offset(),
            0,
            self.stream_bytes,
        )?;
        if record.table() != reference.table()
            || record.stored_key().as_bytes() != reference.key().as_bytes()
            || record.record_schema() != reference.record_schema()
        {
            return Err(StorageError::StaleState);
        }
        ConstructionSourceRecord::open(
            reference,
            record.sealed_record(),
            &self.source_master_key,
            self.binding,
            self.storage_key_generation,
        )
    }
}

/// Fully verified signed-backup source for deterministic restore preflight and execution.
pub struct RestoreBackupSource<R: Read + Seek> {
    input: R,
    source_master_key: StorageMasterKey,
    login_index_key: LoginIndexKey,
    previous_login_index_key: Option<LoginIndexKey>,
    binding: DatabaseBinding,
    verified: VerifiedBackup,
}

struct RekeyContext<'a> {
    source_master_key: &'a StorageMasterKey,
    source_binding: DatabaseBinding,
    source_generation: u32,
    target_master_key: &'a StorageMasterKey,
    target_binding: DatabaseBinding,
    target_generation: u32,
}

#[derive(Clone, Copy)]
struct RestoreLoginGeneration {
    generation: u32,
    entry_count: u64,
    creation_reservations: u64,
}

struct RestoreLoginScan {
    key_state: Option<crate::LoginIndexKeyState>,
    generations: [Option<RestoreLoginGeneration>; 2],
}

impl RestoreLoginScan {
    const fn new() -> Self {
        Self {
            key_state: None,
            generations: [None, None],
        }
    }

    fn observe(
        &mut self,
        source: &StorageConstructionSource,
        record: &ConstructionSourceRecord,
    ) -> Result<(), StorageError> {
        if source.table() == TableId::LoginIndexKeyState {
            if self.key_state.is_some() {
                return Err(StorageError::StaleState);
            }
            self.key_state = Some(crate::LoginIndexKeyState::decode(record.plaintext())?);
            return Ok(());
        }
        if source.table() != TableId::LoginIndex {
            return Ok(());
        }
        let stored_key = crate::LoginIndexStoredKey::decode(source.key().as_bytes())?;
        let value = crate::LoginIndexValue::decode(record.plaintext(), &stored_key)?;
        let creation = matches!(
            value.kind(),
            crate::LoginIndexValueKind::CreationReservation { .. }
        );
        self.observe_generation(stored_key.generation(), creation)
    }

    fn observe_generation(&mut self, generation: u32, creation: bool) -> Result<(), StorageError> {
        let entry = self
            .generations
            .iter_mut()
            .find(|entry| {
                entry.is_none() || entry.is_some_and(|known| known.generation == generation)
            })
            .ok_or(StorageError::StaleState)?;
        let mut facts = entry.unwrap_or(RestoreLoginGeneration {
            generation,
            entry_count: 0,
            creation_reservations: 0,
        });
        facts.entry_count = facts
            .entry_count
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        if creation {
            facts.creation_reservations = facts
                .creation_reservations
                .checked_add(1)
                .ok_or(StorageError::Overflow)?;
        }
        *entry = Some(facts);
        Ok(())
    }

    fn finish(
        self,
        network_id: agenc_ircd_types::NetworkId,
        current_key: &LoginIndexKey,
        previous_key: Option<&LoginIndexKey>,
    ) -> Result<(), StorageError> {
        let key_state = self.key_state.ok_or(StorageError::StaleState)?;
        key_state.validate_configured_keys(network_id, current_key, previous_key)?;
        let previous = key_state.previous();
        let mut previous_count = 0_u64;
        for facts in self.generations.into_iter().flatten() {
            if facts.generation == key_state.current_generation() {
                continue;
            }
            if previous.is_some_and(|(generation, _)| generation == facts.generation)
                && facts.creation_reservations == 0
            {
                previous_count = facts.entry_count;
                continue;
            }
            return Err(StorageError::StaleState);
        }
        if previous.map_or(previous_count != 0, |(_, expected)| {
            previous_count != expected
        }) {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }
}

impl<R: Read + Seek> RestoreBackupSource<R> {
    /// Verifies the complete signed stream before admitting it as restore authority.
    pub fn open(
        mut input: R,
        source_master_key: StorageMasterKey,
        source_guard_root: RollbackGuardRootKey,
        login_index_key: LoginIndexKey,
        previous_login_index_key: Option<LoginIndexKey>,
        trusted_keys: &[BackupTrustKey],
        maximum_bytes: u64,
    ) -> Result<Self, StorageError> {
        input
            .seek(SeekFrom::Start(0))
            .map_err(|_| StorageError::FilesystemRejected)?;
        let verified = verify_backup(
            &mut input,
            &source_master_key,
            &source_guard_root,
            trusted_keys,
            maximum_bytes,
        )?;
        let source = verified.header.source_header();
        let binding = DatabaseBinding::new(
            source.tbs().network_id,
            source.tbs().server_id,
            source.tbs().server_incarnation,
            source.tbs().database_instance_id,
        );
        Ok(Self {
            input,
            source_master_key,
            login_index_key,
            previous_login_index_key,
            binding,
            verified,
        })
    }

    /// Returns the verified signed boundary retained for restore identity construction.
    #[must_use]
    pub const fn verified(&self) -> &VerifiedBackup {
        &self.verified
    }

    /// Returns authenticated source facts needed by the restore construction marker.
    pub fn facts(&self) -> Result<ConstructionSourceFacts, StorageError> {
        Ok(ConstructionSourceFacts {
            header: *self.verified.header.source_header(),
            state: *self.verified.state_meta.tbs(),
            rollback_guard_hash: self
                .verified
                .header
                .source_rollback_guard()
                .complete_hash()?,
        })
    }

    /// Streams the fixed recovery transform into one target-sorted disk plan.
    pub fn rebuild_restore_plan(
        &mut self,
        file: File,
        target_master_key: &StorageMasterKey,
        target_binding: DatabaseBinding,
        target_storage_key_generation: u32,
        limits: ConstructionLimits,
    ) -> Result<ConstructionPlan, StorageError> {
        let limits = limits.validate()?;
        let facts = self.facts()?;
        validate_source_charges(facts.state, limits)?;
        if (
            self.verified.logical_database_bytes > limits.source_database_bytes,
            self.verified.stream_bytes > limits.source_backup_bytes,
        ) != (false, false)
        {
            return Err(StorageError::LimitExceeded);
        }
        validate_rekey_generation(
            &self.source_master_key,
            facts.header.tbs().storage_key_generation,
            target_master_key,
            target_storage_key_generation,
        )?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            limits,
        )?;
        let context = RekeyContext {
            source_master_key: &self.source_master_key,
            source_binding: self.binding,
            source_generation: facts.header.tbs().storage_key_generation,
            target_master_key,
            target_binding,
            target_generation: target_storage_key_generation,
        };
        let active_checkpoint = Self::scan_restore_records(
            &mut self.input,
            self.verified.stream_bytes,
            &mut builder,
            facts,
            &context,
            &self.login_index_key,
            self.previous_login_index_key.as_ref(),
        )?;
        builder.verify_restore_source(facts.state, &active_checkpoint)?;
        builder.finish()
    }

    fn scan_restore_records(
        input: &mut R,
        stream_bytes: u64,
        builder: &mut ConstructionPlanBuilder,
        facts: ConstructionSourceFacts,
        context: &RekeyContext<'_>,
        login_index_key: &LoginIndexKey,
        previous_login_index_key: Option<&LoginIndexKey>,
    ) -> Result<IntegrityCheckpoint, StorageError> {
        let trailer_start = stream_bytes
            .checked_sub(crate::backup::BACKUP_TRAILER_FRAME_BYTES)
            .ok_or(StorageError::InvalidEncoding)?;
        input
            .seek(SeekFrom::Start(crate::backup::BACKUP_RECORDS_OFFSET))
            .map_err(|_| StorageError::FilesystemRejected)?;
        let mut active_checkpoint = None;
        let mut login_scan = RestoreLoginScan::new();
        while input
            .stream_position()
            .map_err(|_| StorageError::FilesystemRejected)?
            < trailer_start
        {
            let offset = input
                .stream_position()
                .map_err(|_| StorageError::FilesystemRejected)?;
            let record = read_backup_record(input, offset, trailer_start)?;
            let sealed = SealedRecord::decode(record.sealed_record())?;
            let source = StorageConstructionSource::new(
                StorageConstructionSourceKind::BackupRecord,
                record.table(),
                StoredKey::new(record.stored_key().as_bytes().to_vec())?,
                record.record_schema(),
                sealed.record_id()?,
                offset,
            )?;
            let opened = ConstructionSourceRecord::open(
                &source,
                record.sealed_record(),
                context.source_master_key,
                context.source_binding,
                context.source_generation,
            )?;
            builder.observe_restore_source_record(&source, &opened)?;
            login_scan.observe(&source, &opened)?;
            observe_active_checkpoint(
                &source,
                &opened,
                facts.state.checkpoint_manifest_sequence,
                &mut active_checkpoint,
            )?;
            push_restore_record(builder, source, &opened, context)?;
        }
        if input
            .stream_position()
            .map_err(|_| StorageError::FilesystemRejected)?
            != trailer_start
        {
            return Err(StorageError::InvalidEncoding);
        }
        login_scan.finish(
            facts.header.tbs().network_id,
            login_index_key,
            previous_login_index_key,
        )?;
        active_checkpoint.ok_or(StorageError::StaleState)
    }
}

fn observe_active_checkpoint(
    source: &StorageConstructionSource,
    record: &ConstructionSourceRecord,
    active_sequence: u64,
    active: &mut Option<IntegrityCheckpoint>,
) -> Result<(), StorageError> {
    let is_active = source.table() == TableId::IntegrityCheckpoint
        && source.key().as_bytes() == active_sequence.to_be_bytes();
    if !is_active {
        return Ok(());
    }
    if active.is_some() {
        return Err(StorageError::StaleState);
    }
    *active = Some(IntegrityCheckpoint::decode(record.plaintext())?);
    Ok(())
}

impl<R: Read + Seek> ConstructionSourceReader for RestoreBackupSource<R> {
    fn read_source(
        &mut self,
        reference: &StorageConstructionSource,
    ) -> Result<ConstructionSourceRecord, StorageError> {
        if reference.kind() != StorageConstructionSourceKind::BackupRecord {
            return Err(StorageError::InvalidEncoding);
        }
        let trailer_start = self
            .verified
            .stream_bytes
            .checked_sub(crate::backup::BACKUP_TRAILER_FRAME_BYTES)
            .ok_or(StorageError::InvalidEncoding)?;
        let record = read_backup_record(
            &mut self.input,
            reference.backup_byte_offset(),
            trailer_start,
        )?;
        if (
            record.table(),
            record.stored_key().as_bytes(),
            record.record_schema(),
        ) != (
            reference.table(),
            reference.key().as_bytes(),
            reference.record_schema(),
        ) {
            return Err(StorageError::StaleState);
        }
        ConstructionSourceRecord::open(
            reference,
            record.sealed_record(),
            &self.source_master_key,
            self.binding,
            self.verified
                .header
                .source_header()
                .tbs()
                .storage_key_generation,
        )
    }
}

/// Reads one numbered record whose frame lies inside the verified record region.
fn read_backup_record<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    trailer_start: u64,
) -> Result<BackupRecord, StorageError> {
    read_backup_frame(
        input,
        offset,
        crate::backup::BACKUP_RECORDS_OFFSET,
        trailer_start,
    )
}

/// Reads one length-prefixed frame that starts and ends inside `[start, end)`.
fn read_backup_frame<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    start: u64,
    end: u64,
) -> Result<BackupRecord, StorageError> {
    if offset < start || offset >= end {
        return Err(StorageError::InvalidEncoding);
    }
    input
        .seek(SeekFrom::Start(offset))
        .map_err(|_| StorageError::FilesystemRejected)?;
    let mut length_bytes = [0_u8; 4];
    input
        .read_exact(&mut length_bytes)
        .map_err(|_| StorageError::FilesystemRejected)?;
    let length =
        usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| StorageError::Overflow)?;
    let frame_end = offset
        .checked_add(4)
        .and_then(|value| value.checked_add(u64::try_from(length).ok()?))
        .ok_or(StorageError::Overflow)?;
    if length == 0 || length > crate::backup::MAX_BACKUP_RECORD_BYTES || frame_end > end {
        return Err(StorageError::LimitExceeded);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| StorageError::AllocationFailed)?;
    encoded.resize(length, 0);
    input
        .read_exact(&mut encoded)
        .map_err(|_| StorageError::FilesystemRejected)?;
    BackupRecord::decode(&encoded)
}

fn push_restore_record(
    builder: &mut ConstructionPlanBuilder,
    source: StorageConstructionSource,
    record: &ConstructionSourceRecord,
    context: &RekeyContext<'_>,
) -> Result<(), StorageError> {
    let selection = select_restore_record(builder, &source, record)?;
    let RestoreSelection::Direct(action) = selection else {
        return match selection {
            RestoreSelection::ChannelName => {
                push_restore_channel_name(builder, source, record, context)
            }
            RestoreSelection::Omit => Ok(()),
            RestoreSelection::Direct(_) => Err(StorageError::InvalidEncoding),
        };
    };
    let target_key = rekey_target_stored_key(
        &source,
        record,
        context.source_master_key,
        context.source_binding,
        context.source_generation,
        context.target_master_key,
        context.target_binding,
        context.target_generation,
    )?;
    let target_table = source.table();
    builder.push(StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![source],
        target_table,
        target_key,
        record.record_schema(),
        action,
        0,
    )?)
}

#[derive(Clone, Copy)]
enum RestoreSelection {
    Omit,
    Direct(StorageConstructionAction),
    ChannelName,
}

// agenc-review: focus owner=storage reviewed=2026-08-28 reason=closed restore table matrix mirrors every normative preserve transform and omission arm
fn select_restore_record(
    builder: &mut ConstructionPlanBuilder,
    source: &StorageConstructionSource,
    record: &ConstructionSourceRecord,
) -> Result<RestoreSelection, StorageError> {
    let table = source.table();
    let action = match table {
        TableId::Account => Some(StorageConstructionAction::RestoreAccount),
        TableId::LoginIndex => {
            let key = crate::LoginIndexStoredKey::decode(source.key().as_bytes())?;
            let value = crate::LoginIndexValue::decode(record.plaintext(), &key)?;
            match value.kind() {
                crate::LoginIndexValueKind::Live { .. }
                | crate::LoginIndexValueKind::DeletionTombstone { .. } => {
                    Some(StorageConstructionAction::RestoreCopy)
                }
                crate::LoginIndexValueKind::CreationReservation { .. } => None,
            }
        }
        TableId::OpaqueRecord
        | TableId::NicknameReservation
        | TableId::Sanction
        | TableId::History
        | TableId::Audit
        | TableId::AuditCheckpoint
        | TableId::E2eeObject
        | TableId::LoginIndexKeyState
        | TableId::StorageOperation => Some(StorageConstructionAction::RestoreCopy),
        TableId::RegistrationInvite => {
            let value = PersistentRecordValue::decode(table, record.plaintext())?;
            (value.record_kind() == 2).then_some(StorageConstructionAction::RestoreCopy)
        }
        TableId::Channel => {
            let value = PersistentRecordValue::decode(table, record.plaintext())?;
            if value.record_kind() == 1 {
                // Backup streams are written in strictly increasing (table, key) order by
                // `BackupStreamWriter::write_record`, and Channel (8) precedes ChannelName
                // (9), so every channel is indexed here before `push_restore_channel_name`
                // looks it up.
                builder.index_restore_channel_source(source)?;
                Some(StorageConstructionAction::RestoreChannel)
            } else {
                None
            }
        }
        TableId::ChannelName => {
            let value = PersistentRecordValue::decode(table, record.plaintext())?;
            if value.record_kind() != 1 {
                return Ok(RestoreSelection::Omit);
            }
            return Ok(RestoreSelection::ChannelName);
        }
        TableId::FederationPeer => {
            let value = PersistentRecordValue::decode(table, record.plaintext())?;
            (value.record_kind() == 2).then_some(StorageConstructionAction::RestorePeerTombstones)
        }
        TableId::E2eeState => Some(StorageConstructionAction::RestoreE2eeState),
        TableId::KeyCheck
        | TableId::AuthTransaction
        | TableId::Session
        | TableId::FederationOrigin
        | TableId::RequestResult
        | TableId::StateMeta
        | TableId::IntegrityManifest
        | TableId::IntegrityCheckpoint
        | TableId::EdgeOutbox
        | TableId::EdgeProjection
        | TableId::StorageConstruction => None,
    };
    Ok(action.map_or(RestoreSelection::Omit, RestoreSelection::Direct))
}

fn push_restore_channel_name(
    builder: &mut ConstructionPlanBuilder,
    source: StorageConstructionSource,
    record: &ConstructionSourceRecord,
    context: &RekeyContext<'_>,
) -> Result<(), StorageError> {
    let value = PersistentRecordValue::decode(source.table(), record.plaintext())?;
    let mut channels = value
        .references()
        .iter()
        .filter(|reference| reference.table() == TableId::Channel);
    let channel = channels.next().ok_or(StorageError::StaleState)?;
    if channels.next().is_some() {
        return Err(StorageError::StaleState);
    }
    let channel_source = builder.restore_channel_source(channel.key())?;
    let target_key = rekey_target_stored_key(
        &source,
        record,
        context.source_master_key,
        context.source_binding,
        context.source_generation,
        context.target_master_key,
        context.target_binding,
        context.target_generation,
    )?;
    builder.push(StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![source, channel_source],
        TableId::ChannelName,
        target_key,
        record.record_schema(),
        StorageConstructionAction::RestoreChannelName,
        0,
    )?)
}

/// Closed transform implementation selected by a reviewed command profile.
pub trait ConstructionTransformer {
    /// Produces exactly one target plaintext for one canonical plan entry.
    fn transform(
        &mut self,
        kind: StorageConstructionKind,
        entry: &StorageConstructionPlanEntry,
        sources: &[ConstructionSourceRecord],
    ) -> Result<Zeroizing<Vec<u8>>, StorageError>;
}

/// One freshly transformed target value in a construction transaction.
pub struct ConstructionTargetRecord<'a> {
    /// Exact canonical plan entry.
    pub entry: &'a StorageConstructionPlanEntry,
    /// Fresh target plaintext to seal once.
    pub plaintext: &'a [u8],
}

/// Bounded target values and their successor marker that must commit atomically.
pub struct ConstructionTargetBatch<'a> {
    /// Canonically ordered target values committed by this transaction.
    pub records: &'a [ConstructionTargetRecord<'a>],
    /// Authenticated marker successor committed in the same transaction.
    pub successor: &'a StorageConstruction,
}

/// Authenticated counters returned by one committed construction transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstructionCommitReceipt {
    /// Number of plan targets now durably committed.
    pub target_records_committed: u64,
    /// Resulting storage commit sequence.
    pub storage_commit_sequence: u64,
    /// Resulting manifest sequence.
    pub manifest_sequence: u64,
    /// Resulting logical state generation.
    pub state_generation: u64,
    /// Preserved or reset account-service response count.
    pub account_service_response_count: u64,
    /// Resulting committed nonce high-water mark.
    pub nonce_draw_high_water: u64,
}

/// Exact counters predicted for the marker-replacement transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstructionFinalizationCounters {
    /// Final storage commit sequence.
    pub storage_commit_sequence: u64,
    /// Final manifest sequence.
    pub manifest_sequence: u64,
    /// Final state generation.
    pub state_generation: u64,
    /// Final account-service response count.
    pub account_service_response_count: u64,
    /// Final nonce high-water mark.
    pub nonce_draw_high_water: u64,
}

/// Target adapter that owns sealing, nonce reservation, and immediate commit.
pub trait ConstructionTargetWriter {
    /// Commits one target batch and the exact cursor successor atomically.
    ///
    /// Callers guarantee that `batch.records` are the consecutive plan entries starting at
    /// the marker cursor; the writer verifies the marker chain, not plan membership.
    fn commit_batch(
        &mut self,
        batch: ConstructionTargetBatch<'_>,
    ) -> Result<ConstructionCommitReceipt, StorageError>;

    /// Predicts the counters of the dedicated three-seal finalization transaction.
    fn finalization_counters(
        &mut self,
        marker: &StorageConstruction,
    ) -> Result<ConstructionFinalizationCounters, StorageError>;

    /// Atomically deletes the marker and inserts the exact completion record.
    fn finalize(
        &mut self,
        marker: &StorageConstruction,
        completion: &StorageOperationCompletion,
    ) -> Result<(), StorageError>;
}

/// Authenticated staging-database adapter used by restore, rekey, and migration commands.
pub struct ConstructionTarget {
    engine: StorageEngine,
}

/// Proof that a completed construction passed a clean second open and full startup scan.
pub struct VerifiedConstructionOutput {
    completion: StorageOperationCompletion,
    output_path_hash: StorageDigest,
    logical_database_bytes: u64,
    backup_stream_bytes: u64,
}

impl VerifiedConstructionOutput {
    /// Borrows the exact permanent completion record found during read-back.
    #[must_use]
    pub const fn completion(&self) -> &StorageOperationCompletion {
        &self.completion
    }

    /// Returns the reconstructed final logical database charge.
    #[must_use]
    pub const fn logical_database_bytes(&self) -> u64 {
        self.logical_database_bytes
    }

    /// Returns the reconstructed final signed-backup stream size.
    #[must_use]
    pub const fn backup_stream_bytes(&self) -> u64 {
        self.backup_stream_bytes
    }

    pub(crate) const fn output_path_hash(&self) -> StorageDigest {
        self.output_path_hash
    }
}

impl ConstructionTarget {
    /// Reconstructs a completed output and returns its authenticated header.
    pub fn completed_header(config: StorageOpenConfig) -> Result<DatabaseHeader, StorageError> {
        let engine = StorageEngine::open(config)?;
        let _capacity = engine.startup_scan()?;
        Ok(engine.construction_source_header())
    }

    /// Opens and completely verifies one resumable staging database.
    pub fn open(config: StorageOpenConfig) -> Result<Self, StorageError> {
        let engine = StorageEngine::open(config)?;
        let _marker = engine.construction_scan()?;
        Ok(Self { engine })
    }

    /// Reads the sole authenticated construction marker.
    pub fn marker(&self) -> Result<StorageConstruction, StorageError> {
        self.engine.construction_marker()
    }

    /// Returns the staging database header bound by the authenticated marker.
    #[must_use]
    pub const fn header(&self) -> DatabaseHeader {
        self.engine.construction_source_header()
    }

    /// Reopens a completed output and binds its exact completion to the requested path.
    pub fn verify_completed(
        config: StorageOpenConfig,
        expected_identity: StorageOperationIdentity,
        output_path_hash: StorageDigest,
    ) -> Result<VerifiedConstructionOutput, StorageError> {
        let mut engine = StorageEngine::open(config)?;
        let _capacity = engine.startup_scan()?;
        let completion = engine.resume_completed_construction(expected_identity)?;
        let state = engine.construction_source_state();
        Ok(VerifiedConstructionOutput {
            completion,
            output_path_hash,
            logical_database_bytes: state.logical_database_bytes,
            backup_stream_bytes: state.backup_stream_bytes,
        })
    }

    fn prepare_batch_mutations(
        &self,
        batch: &ConstructionTargetBatch<'_>,
    ) -> Result<StorageMutationBatch, StorageError> {
        let current = self.engine.construction_marker()?;
        validate_marker_successor(&current, batch.records, batch.successor)?;
        let capacity = batch
            .records
            .len()
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let mut mutations = Vec::new();
        mutations
            .try_reserve_exact(capacity)
            .map_err(|_| StorageError::AllocationFailed)?;
        for record in batch.records {
            if self
                .engine
                .construction_existing(record.entry.target_table(), record.entry.target_key())?
                .is_some()
            {
                return Err(StorageError::StaleState);
            }
            mutations.push(RecordMutation::put(
                record.entry.target_table(),
                StoredKey::new(record.entry.target_key().as_bytes().to_vec())?,
                record.entry.target_record_schema(),
                None,
                record.plaintext.to_vec(),
            )?);
        }
        let marker_key = StoredKey::new(crate::STORAGE_CONSTRUCTION_KEY.to_vec())?;
        let marker_before = self
            .engine
            .construction_existing(TableId::StorageConstruction, &marker_key)?
            .ok_or(StorageError::StaleState)?;
        mutations.push(RecordMutation::put(
            TableId::StorageConstruction,
            marker_key,
            1,
            Some(marker_before),
            batch.successor.encode()?,
        )?);
        StorageMutationBatch::new_construction(
            self.engine.construction_head(fresh_transaction_id()?),
            self.engine.construction_accounting(),
            mutations,
        )
    }

    fn commit_prepared_batch(
        &mut self,
        storage_batch: StorageMutationBatch,
        successor: &StorageConstruction,
    ) -> Result<ConstructionCommitReceipt, StorageError> {
        self.engine.check_construction_fault(
            StorageFaultSite::ConstructionCursor,
            StorageFaultBoundary::Before,
        )?;
        let receipt = self.engine.construction_commit(storage_batch)?;
        self.engine.check_construction_fault(
            StorageFaultSite::ConstructionCursor,
            StorageFaultBoundary::After,
        )?;
        let state = self.engine.construction_committed_counters();
        Ok(ConstructionCommitReceipt {
            target_records_committed: successor.target_records_committed,
            storage_commit_sequence: receipt.storage_commit_sequence,
            manifest_sequence: state.manifest_sequence,
            state_generation: receipt.state_generation,
            account_service_response_count: state.account_service_response_count,
            nonce_draw_high_water: state.nonce_draw_high_water,
        })
    }
}

impl ConstructionTargetWriter for ConstructionTarget {
    fn commit_batch(
        &mut self,
        batch: ConstructionTargetBatch<'_>,
    ) -> Result<ConstructionCommitReceipt, StorageError> {
        self.engine.check_construction_fault(
            StorageFaultSite::ConstructionBatch,
            StorageFaultBoundary::Before,
        )?;
        let storage_batch = self.prepare_batch_mutations(&batch)?;
        let receipt = self.commit_prepared_batch(storage_batch, batch.successor)?;
        self.engine.check_construction_fault(
            StorageFaultSite::ConstructionBatch,
            StorageFaultBoundary::After,
        )?;
        Ok(receipt)
    }

    fn finalization_counters(
        &mut self,
        marker: &StorageConstruction,
    ) -> Result<ConstructionFinalizationCounters, StorageError> {
        require_current_marker(&self.engine, marker)?;
        self.engine.construction_counters()
    }

    fn finalize(
        &mut self,
        marker: &StorageConstruction,
        completion: &StorageOperationCompletion,
    ) -> Result<(), StorageError> {
        self.engine.check_construction_fault(
            StorageFaultSite::ConstructionCompletion,
            StorageFaultBoundary::Before,
        )?;
        require_current_marker(&self.engine, marker)?;
        completion.validate()?;
        if (completion.identity, completion.target_records_committed)
            != (marker.identity, marker.target_records_committed)
        {
            return Err(StorageError::ResumeMismatch);
        }
        let marker_key = StoredKey::new(crate::STORAGE_CONSTRUCTION_KEY.to_vec())?;
        let marker_before = self
            .engine
            .construction_existing(TableId::StorageConstruction, &marker_key)?
            .ok_or(StorageError::StaleState)?;
        let operation_key = StoredKey::new(completion.storage_operation_id.as_bytes().to_vec())?;
        if self
            .engine
            .construction_existing(TableId::StorageOperation, &operation_key)?
            .is_some()
        {
            return Err(StorageError::StaleState);
        }
        let mutations = vec![
            RecordMutation::delete(TableId::StorageConstruction, marker_key, marker_before),
            RecordMutation::put(
                TableId::StorageOperation,
                operation_key,
                1,
                None,
                completion.encode()?,
            )?,
        ];
        let transaction_id = fresh_transaction_id()?;
        let storage_batch = StorageMutationBatch::new_construction(
            self.engine.construction_head(transaction_id),
            self.engine.construction_accounting(),
            mutations,
        )?;
        let receipt = self.engine.construction_commit(storage_batch)?;
        self.engine.check_construction_fault(
            StorageFaultSite::ConstructionCompletion,
            StorageFaultBoundary::After,
        )?;
        let actual = self.engine.construction_committed_counters();
        let expected = ConstructionFinalizationCounters {
            storage_commit_sequence: completion.finalization_storage_commit_sequence,
            manifest_sequence: completion.finalization_manifest_sequence,
            state_generation: completion.finalization_state_generation,
            account_service_response_count: completion.finalization_account_service_response_count,
            nonce_draw_high_water: completion.finalization_nonce_draw_high_water,
        };
        if (receipt.storage_commit_sequence, actual) != (expected.storage_commit_sequence, expected)
        {
            return Err(StorageError::StaleState);
        }
        self.engine.finish_construction()
    }
}

fn validate_marker_successor(
    current: &StorageConstruction,
    records: &[ConstructionTargetRecord<'_>],
    successor: &StorageConstruction,
) -> Result<(), StorageError> {
    current.validate()?;
    successor.validate()?;
    let Some(first) = records.first() else {
        return Err(StorageError::InvalidEncoding);
    };
    let current_targets_entry = match &current.next_target {
        StorageConstructionCursor::BeforeFirst => current.target_records_committed == 0,
        StorageConstructionCursor::AtTarget { table, key } => {
            *table == first.entry.target_table()
                && key.as_bytes() == first.entry.target_key().as_bytes()
        }
        StorageConstructionCursor::Complete => false,
    };
    let added = u64::try_from(records.len()).map_err(|_| StorageError::Overflow)?;
    if !current_targets_entry
        || records
            .iter()
            .zip(records.iter().skip(1))
            .any(|(left, right)| {
                (
                    left.entry.target_table(),
                    left.entry.target_key().as_bytes(),
                ) >= (
                    right.entry.target_table(),
                    right.entry.target_key().as_bytes(),
                )
            })
        || current.identity != successor.identity
        || current.output_path_hash != successor.output_path_hash
        || successor.target_records_committed
            != current
                .target_records_committed
                .checked_add(added)
                .ok_or(StorageError::Overflow)?
    {
        return Err(StorageError::ResumeMismatch);
    }
    Ok(())
}

fn require_current_marker(
    engine: &StorageEngine,
    expected: &StorageConstruction,
) -> Result<(), StorageError> {
    let current = engine.construction_marker()?;
    if current.encode()? != expected.encode()? {
        return Err(StorageError::ResumeMismatch);
    }
    Ok(())
}

fn fresh_transaction_id() -> Result<TransactionId, StorageError> {
    let mut bytes = [0_u8; 16];
    OsEntropy::fill(&mut bytes)?;
    Ok(TransactionId::from_bytes(bytes))
}

/// Resumable executor that buffers at most `limits.batch_records` transformed entries
/// and `limits.batch_bytes` of plaintext per batch, then commits them in one target
/// transaction.
pub struct ConstructionExecutor {
    marker: StorageConstruction,
    plan: ConstructionPlan,
    limits: ConstructionLimits,
    last_receipt: Option<ConstructionCommitReceipt>,
}

impl ConstructionExecutor {
    /// Rebuilds authority from the authenticated marker and canonical plan.
    pub fn resume(
        marker: StorageConstruction,
        plan: ConstructionPlan,
        limits: ConstructionLimits,
    ) -> Result<Self, StorageError> {
        let limits = limits.validate()?;
        marker.validate()?;
        if marker.identity.kind != plan.kind()
            || marker.identity.construction_plan_hash != plan.hash()
            || marker.identity.planned_entry_count != plan.entry_count()
        {
            return Err(StorageError::ResumeMismatch);
        }
        validate_cursor(&marker, &plan)?;
        Ok(Self {
            marker,
            plan,
            limits,
            last_receipt: None,
        })
    }

    /// Borrows the current authenticated construction marker.
    #[must_use]
    pub const fn marker(&self) -> &StorageConstruction {
        &self.marker
    }

    /// Returns the last authenticated batch receipt, if this executor committed one.
    #[must_use]
    pub const fn last_receipt(&self) -> Option<ConstructionCommitReceipt> {
        self.last_receipt
    }

    /// Processes one bounded group in one target transaction.
    pub fn service_batch<R, T, W>(
        &mut self,
        source: &mut R,
        transformer: &mut T,
        target: &mut W,
    ) -> Result<usize, StorageError>
    where
        R: ConstructionSourceReader,
        T: ConstructionTransformer,
        W: ConstructionTargetWriter,
    {
        self.service_batch_with(source, transformer, target)
    }

    fn service_batch_with(
        &mut self,
        source: &mut dyn ConstructionSourceReader,
        transformer: &mut dyn ConstructionTransformer,
        target: &mut dyn ConstructionTargetWriter,
    ) -> Result<usize, StorageError> {
        let prepared = prepare_construction_batch(
            &self.plan,
            self.marker.target_records_committed,
            self.limits,
            source,
            transformer,
        )?;
        if prepared.is_empty() {
            return Ok(0);
        }
        let records = prepared
            .iter()
            .map(|(entry, plaintext)| ConstructionTargetRecord {
                entry,
                plaintext: plaintext.as_slice(),
            })
            .collect::<Vec<_>>();
        let successor = successor_marker(&self.marker, &self.plan, records.len())?;
        let receipt = target.commit_batch(ConstructionTargetBatch {
            records: &records,
            successor: &successor,
        })?;
        if receipt.target_records_committed != successor.target_records_committed {
            return Err(StorageError::StaleState);
        }
        self.marker = successor;
        self.last_receipt = Some(receipt);
        Ok(records.len())
    }

    /// Replaces a complete marker with its permanent operation record.
    pub fn finalize<W: ConstructionTargetWriter>(
        &mut self,
        target: &mut W,
    ) -> Result<StorageDigest, StorageError> {
        self.finalize_with(target)
    }

    fn finalize_with(
        &mut self,
        target: &mut dyn ConstructionTargetWriter,
    ) -> Result<StorageDigest, StorageError> {
        if self.marker.next_target != StorageConstructionCursor::Complete
            || self.marker.target_records_committed != self.marker.identity.planned_entry_count
        {
            return Err(StorageError::StaleState);
        }
        let counters = target.finalization_counters(&self.marker)?;
        let operation_id = self.marker.identity.operation_id()?;
        let completion = StorageOperationCompletion {
            identity: self.marker.identity,
            storage_operation_id: operation_id,
            target_records_committed: self.marker.target_records_committed,
            finalization_storage_commit_sequence: counters.storage_commit_sequence,
            finalization_manifest_sequence: counters.manifest_sequence,
            finalization_state_generation: counters.state_generation,
            finalization_account_service_response_count: counters.account_service_response_count,
            finalization_nonce_draw_high_water: counters.nonce_draw_high_water,
        };
        completion.validate()?;
        target.finalize(&self.marker, &completion)?;
        Ok(operation_id)
    }
}

/// Reuses exact logical plaintext for same-table rekey and admitted restore-copy entries.
pub struct ExactCopyTransformer;

impl ConstructionTransformer for ExactCopyTransformer {
    fn transform(
        &mut self,
        kind: StorageConstructionKind,
        entry: &StorageConstructionPlanEntry,
        sources: &[ConstructionSourceRecord],
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let copy = matches!(
            (kind, entry.action()),
            (
                StorageConstructionKind::Rekey,
                StorageConstructionAction::RekeyCopy
            ) | (
                StorageConstructionKind::Restore,
                StorageConstructionAction::RestoreCopy
            )
        );
        let Some(source) = sources.first() else {
            return Err(StorageError::StaleState);
        };
        if !copy
            || sources.len() != 1
            || source.table() != entry.target_table()
            || source.record_schema() != entry.target_record_schema()
        {
            return Err(StorageError::InvalidEncoding);
        }
        if kind == StorageConstructionKind::Restore {
            validate_restore_copy_source(source)?;
        }
        Ok(Zeroizing::new(source.plaintext().to_vec()))
    }
}

fn validate_restore_copy_source(source: &ConstructionSourceRecord) -> Result<(), StorageError> {
    match source.table() {
        TableId::LoginIndex => {
            let key = crate::LoginIndexStoredKey::decode(source.key().as_bytes())?;
            let value = crate::LoginIndexValue::decode(source.plaintext(), &key)?;
            if matches!(
                value.kind(),
                crate::LoginIndexValueKind::Live { .. }
                    | crate::LoginIndexValueKind::DeletionTombstone { .. }
            ) {
                Ok(())
            } else {
                Err(StorageError::StaleState)
            }
        }
        TableId::RegistrationInvite => {
            let value = PersistentRecordValue::decode(source.table(), source.plaintext())?;
            if value.record_kind() == 2 {
                Ok(())
            } else {
                Err(StorageError::StaleState)
            }
        }
        TableId::OpaqueRecord
        | TableId::NicknameReservation
        | TableId::Sanction
        | TableId::History
        | TableId::Audit
        | TableId::AuditCheckpoint
        | TableId::E2eeObject
        | TableId::LoginIndexKeyState
        | TableId::StorageOperation => Ok(()),
        _ => Err(StorageError::InvalidEncoding),
    }
}

/// Deterministic schema-one restore transform selected by restore identities.
pub struct RecoveryTransformV1 {
    target_recovery_epoch: RecoveryEpoch,
    source_rollback_guard_hash: StorageDigest,
}

impl RecoveryTransformV1 {
    /// Binds every recovered live E2EE route to the fresh target lineage and source guard.
    #[must_use]
    pub const fn new(
        target_recovery_epoch: RecoveryEpoch,
        source_rollback_guard_hash: StorageDigest,
    ) -> Self {
        Self {
            target_recovery_epoch,
            source_rollback_guard_hash,
        }
    }
}

impl ConstructionTransformer for RecoveryTransformV1 {
    fn transform(
        &mut self,
        kind: StorageConstructionKind,
        entry: &StorageConstructionPlanEntry,
        sources: &[ConstructionSourceRecord],
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        if kind != StorageConstructionKind::Restore {
            return Err(StorageError::InvalidEncoding);
        }
        let encoded = match entry.action() {
            StorageConstructionAction::RestoreCopy => {
                let [source] = sources else {
                    return Err(StorageError::StaleState);
                };
                validate_restore_copy_source(source)?;
                exact_source(entry, sources)?.to_vec()
            }
            StorageConstructionAction::RestoreAccount => {
                let source = exact_source(entry, sources)?;
                recovery_transform_prefix(TableId::Account, source)?
            }
            StorageConstructionAction::RestoreChannel => {
                let source = exact_source(entry, sources)?;
                recovery_transform_prefix(TableId::Channel, source)?
            }
            StorageConstructionAction::RestoreChannelName => {
                transform_channel_name(entry, sources)?
            }
            StorageConstructionAction::RestorePeerTombstones => {
                transform_peer_tombstones(entry, sources)?
            }
            StorageConstructionAction::RestoreE2eeState => transform_e2ee_recovery_pending(
                entry,
                sources,
                self.target_recovery_epoch,
                self.source_rollback_guard_hash,
            )?,
            _ => return Err(StorageError::InvalidEncoding),
        };
        validate_record_plaintext(
            entry.target_table(),
            entry.target_key(),
            entry.target_record_schema(),
            &encoded,
        )?;
        Ok(Zeroizing::new(encoded))
    }
}

fn validate_cursor(
    marker: &StorageConstruction,
    plan: &ConstructionPlan,
) -> Result<(), StorageError> {
    let committed = marker.target_records_committed;
    let entry = plan.entry(committed)?;
    match (&marker.next_target, entry.as_ref()) {
        (StorageConstructionCursor::BeforeFirst, Some(_)) => Ok(()),
        (StorageConstructionCursor::AtTarget { table, key }, Some(entry))
            if *table == entry.target_table()
                && key.as_bytes() == entry.target_key().as_bytes() =>
        {
            Ok(())
        }
        (StorageConstructionCursor::Complete, None) => Ok(()),
        _ => Err(StorageError::ResumeMismatch),
    }
}

fn successor_marker(
    marker: &StorageConstruction,
    plan: &ConstructionPlan,
    added_records: usize,
) -> Result<StorageConstruction, StorageError> {
    if added_records == 0 {
        return Err(StorageError::InvalidEncoding);
    }
    let committed = marker
        .target_records_committed
        .checked_add(u64::try_from(added_records).map_err(|_| StorageError::Overflow)?)
        .ok_or(StorageError::Overflow)?;
    let next_target = match plan.entry(committed)? {
        Some(entry) => StorageConstructionCursor::AtTarget {
            table: entry.target_table(),
            key: StoredKey::new(entry.target_key().as_bytes().to_vec())?,
        },
        None if committed == plan.entry_count() => StorageConstructionCursor::Complete,
        None => return Err(StorageError::StaleState),
    };
    let successor = StorageConstruction {
        identity: marker.identity,
        output_path_hash: marker.output_path_hash,
        next_target,
        target_records_committed: committed,
    };
    successor.validate()?;
    Ok(successor)
}

fn exact_source<'a>(
    entry: &StorageConstructionPlanEntry,
    sources: &'a [ConstructionSourceRecord],
) -> Result<&'a [u8], StorageError> {
    let [source] = sources else {
        return Err(StorageError::StaleState);
    };
    if source.table() != entry.target_table()
        || source.record_schema() != entry.target_record_schema()
    {
        return Err(StorageError::StaleState);
    }
    Ok(source.plaintext())
}

fn transform_channel_name(
    entry: &StorageConstructionPlanEntry,
    sources: &[ConstructionSourceRecord],
) -> Result<Vec<u8>, StorageError> {
    if entry.target_table() != TableId::ChannelName || sources.len() != 2 {
        return Err(StorageError::StaleState);
    }
    let channel_source = sources
        .iter()
        .find(|source| source.table() == TableId::Channel)
        .ok_or(StorageError::StaleState)?;
    let name_source = sources
        .iter()
        .find(|source| source.table() == TableId::ChannelName)
        .ok_or(StorageError::StaleState)?;
    let channel = PersistentRecordValue::decode(TableId::Channel, channel_source.plaintext())?;
    let name = PersistentRecordValue::decode(TableId::ChannelName, name_source.plaintext())?;
    if channel.record_kind() != 1
        || name.record_kind() != 1
        || !name.references().iter().any(|reference| {
            reference.table() == TableId::Channel
                && reference.key().as_bytes() == channel_source.key().as_bytes()
        })
    {
        return Err(StorageError::StaleState);
    }
    let revision = channel
        .revision()
        .checked_add(1)
        .ok_or(StorageError::Overflow)?;
    rebuild_persistent(
        &name,
        TableId::ChannelName,
        name.record_kind(),
        revision,
        name.generation(),
    )
}

fn transform_peer_tombstones(
    entry: &StorageConstructionPlanEntry,
    sources: &[ConstructionSourceRecord],
) -> Result<Vec<u8>, StorageError> {
    let source = exact_source(entry, sources)?;
    let peer = PersistentRecordValue::decode(TableId::FederationPeer, source)?;
    if peer.record_kind() != 2 {
        return Err(StorageError::StaleState);
    }
    rebuild_persistent(
        &peer,
        TableId::FederationPeer,
        peer.record_kind(),
        peer.revision(),
        peer.generation(),
    )
}

fn transform_e2ee_recovery_pending(
    entry: &StorageConstructionPlanEntry,
    sources: &[ConstructionSourceRecord],
    target_recovery_epoch: RecoveryEpoch,
    source_rollback_guard_hash: StorageDigest,
) -> Result<Vec<u8>, StorageError> {
    let source = exact_source(entry, sources)?;
    let state = PersistentRecordValue::decode(TableId::E2eeState, source)?;
    if state.record_kind() != 1 {
        return rebuild_persistent(
            &state,
            TableId::E2eeState,
            state.record_kind(),
            state.revision(),
            state.generation(),
        );
    }
    let body = crate::E2eeRecoveryGate::decode(state.body())?
        .recover(target_recovery_epoch, source_rollback_guard_hash)
        .encode()?;
    PersistentRecordValue::new(
        TableId::E2eeState,
        state.record_kind(),
        state.revision(),
        state.generation(),
        state.expires_at(),
        state.references().to_vec(),
        body,
    )?
    .encode()
}

fn rebuild_persistent(
    value: &PersistentRecordValue,
    table: TableId,
    record_kind: u16,
    revision: u64,
    generation: u64,
) -> Result<Vec<u8>, StorageError> {
    PersistentRecordValue::new(
        table,
        record_kind,
        revision,
        generation,
        value.expires_at(),
        value.references().to_vec(),
        value.body().to_vec(),
    )?
    .encode()
}

/// Applies the fixed prefix changes common to restore account/channel records.
pub fn recovery_transform_prefix(table: TableId, encoded: &[u8]) -> Result<Vec<u8>, StorageError> {
    let value = PersistentRecordValue::decode(table, encoded)?;
    let (revision, generation) = match (table, value.record_kind()) {
        (TableId::Account, 1) => (
            value
                .revision()
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
            value
                .generation()
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
        ),
        (TableId::Channel, 1) => (
            value
                .revision()
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
            value.generation(),
        ),
        (TableId::Account, 2) => (value.revision(), value.generation()),
        _ => return Err(StorageError::InvalidEncoding),
    };
    let references = if table == TableId::Channel {
        value
            .references()
            .iter()
            .filter(|reference| {
                !matches!(
                    reference.table(),
                    TableId::Session | TableId::RegistrationInvite
                )
            })
            .cloned()
            .collect()
    } else {
        value.references().to_vec()
    };
    let body = recovery_domain_body(&value, table, revision, generation)?;
    PersistentRecordValue::new(
        table,
        value.record_kind(),
        revision,
        generation,
        value.expires_at(),
        references,
        body,
    )?
    .encode()
}

fn recovery_domain_body(
    value: &PersistentRecordValue,
    table: TableId,
    revision: u64,
    generation: u64,
) -> Result<Vec<u8>, StorageError> {
    match (table, value.record_kind()) {
        (TableId::Account, 1) => {
            let mut account = AccountRecordBody::decode(value.body())?;
            account.revision = Revision::new(revision).map_err(|_| StorageError::Overflow)?;
            account.session_generation =
                Generation::new(generation).map_err(|_| StorageError::Overflow)?;
            AccountRecordBody::encode(&account)
        }
        (TableId::Channel, 1) => {
            let mut channel = ChannelRecordBody::decode(value.body())?;
            channel.revision = Revision::new(revision).map_err(|_| StorageError::Overflow)?;
            ChannelRecordBody::encode(&channel)
        }
        (TableId::Account, 2) => Ok(value.body().to_vec()),
        _ => Err(StorageError::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use agenc_ircd_crypto::{LoginIndexKey, derive_login_index};
    use agenc_ircd_types::{
        AccountRandomId, DatabaseId, NetworkId, NormalizedLogin, OpaqueCredentialId, ServerId,
        ServerIncarnation, TransactionId,
    };

    use super::*;
    use crate::{IntegrityCheckpointTbs, IntegrityManifestTbs, IntegrityRecordMutation};

    const ZERO: StorageDigest = StorageDigest::from_bytes([0; 32]);
    static SCRATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn scratch_file(label: &str) -> Result<(File, PathBuf), StorageError> {
        let sequence = SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::current_dir()
            .map_err(|_| StorageError::FilesystemRejected)?
            .join("target");
        std::fs::create_dir_all(&directory).map_err(|_| StorageError::FilesystemRejected)?;
        let path = directory.join(format!(
            "construction-{label}-{}-{sequence}.redb",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| StorageError::FilesystemRejected)?;
        Ok((file, path))
    }

    fn state(logical: u64, backup: u64) -> StateMetaTbs {
        StateMetaTbs {
            storage_commit_sequence: 0,
            manifest_sequence: 0,
            state_generation: 0,
            account_service_response_count: 0,
            nonce_draw_high_water: 0,
            logical_database_bytes: logical,
            backup_stream_bytes: backup,
            checkpoint_manifest_sequence: 0,
            latest_manifest_hash: ZERO,
            checkpoint_hash: ZERO,
            previous_rollback_guard_hash: ZERO,
        }
    }

    fn test_limits() -> ConstructionLimits {
        ConstructionLimits {
            source_database_bytes: 100,
            source_backup_bytes: 200,
            target_database_bytes: 300,
            target_backup_bytes: 400,
            plan_bytes: 1_024,
            batch_records: 2,
            batch_bytes: 1_024,
        }
    }

    fn maximum_limits() -> ConstructionLimits {
        ConstructionLimits {
            source_database_bytes: MAX_CONSTRUCTION_SOURCE_BYTES,
            source_backup_bytes: MAX_CONSTRUCTION_SOURCE_BYTES,
            target_database_bytes: MAX_CONSTRUCTION_TARGET_BYTES,
            target_backup_bytes: MAX_CONSTRUCTION_TARGET_BYTES,
            plan_bytes: MAX_CONSTRUCTION_PLAN_BYTES,
            batch_records: MAX_CONSTRUCTION_BATCH_RECORDS,
            batch_bytes: MAX_CONSTRUCTION_BATCH_BYTES,
        }
    }

    fn account_key(byte: u8) -> Result<StoredKey, StorageError> {
        StoredKey::new(
            AccountRandomId::from_bytes([byte; 16])
                .to_text()
                .into_bytes(),
        )
    }

    fn source(table: TableId, key: &StoredKey) -> Result<StorageConstructionSource, StorageError> {
        StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            table,
            StoredKey::new(key.as_bytes().to_vec())?,
            1,
            ZERO,
            0,
        )
    }

    fn rekey_entry(
        table: TableId,
        key: StoredKey,
    ) -> Result<StorageConstructionPlanEntry, StorageError> {
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Rekey,
            vec![source(table, &key)?],
            table,
            key,
            1,
            StorageConstructionAction::RekeyCopy,
            0,
        )
    }

    fn rekey_entries() -> Result<Vec<StorageConstructionPlanEntry>, StorageError> {
        Ok(vec![
            rekey_entry(TableId::Account, account_key(1)?)?,
            rekey_entry(
                TableId::LoginIndexKeyState,
                StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            )?,
        ])
    }

    fn rekey_identity(
        entries: &[StorageConstructionPlanEntry],
    ) -> Result<StorageOperationIdentity, StorageError> {
        Ok(StorageOperationIdentity {
            kind: StorageConstructionKind::Rekey,
            command_version: 1,
            source_database_header_hash: ZERO,
            target_database_header_hash: ZERO,
            source_rollback_guard_hash: ZERO,
            source_stream_digest: None,
            source_schema_generation: 1,
            target_schema_generation: 1,
            transform_profile_hash: agenc_ircd_crypto::rekey_transform_profile_hash()?,
            target_database_instance_id: DatabaseId::from_bytes([1; 16]),
            source_master_key_id: ZERO,
            source_guard_root_key_id: ZERO,
            target_master_key_id: ZERO,
            target_guard_root_key_id: ZERO,
            planned_entry_count: u64::try_from(entries.len())
                .map_err(|_| StorageError::Overflow)?,
            construction_plan_hash: construction_plan_hash(
                StorageConstructionKind::Rekey,
                entries,
                MAX_CONSTRUCTION_PLAN_BYTES,
            )?,
        })
    }

    fn rekey_plan() -> Result<(StorageOperationIdentity, ConstructionPlan), StorageError> {
        let entries = rekey_entries()?;
        let identity = rekey_identity(&entries)?;
        let plan = ConstructionPlan::new(&identity, entries, maximum_limits())?;
        Ok((identity, plan))
    }

    fn marker(
        identity: StorageOperationIdentity,
        next_target: StorageConstructionCursor,
        committed: u64,
    ) -> StorageConstruction {
        StorageConstruction {
            identity,
            output_path_hash: StorageDigest::from_bytes([2; 32]),
            next_target,
            target_records_committed: committed,
        }
    }

    fn record(table: TableId, key: StoredKey, plaintext: Vec<u8>) -> ConstructionSourceRecord {
        ConstructionSourceRecord {
            table,
            key,
            record_schema: 1,
            plaintext: Zeroizing::new(plaintext),
        }
    }

    fn backup_source(
        table: TableId,
        key: &StoredKey,
        offset: u64,
    ) -> Result<StorageConstructionSource, StorageError> {
        StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            table,
            StoredKey::new(key.as_bytes().to_vec())?,
            1,
            StorageDigest::from_bytes([71; 32]),
            offset,
        )
    }

    fn domain_plaintext(table: TableId, kind: u16) -> Result<Vec<u8>, StorageError> {
        let body = if matches!(
            table,
            TableId::FederationPeer
                | TableId::FederationOrigin
                | TableId::RequestResult
                | TableId::EdgeOutbox
                | TableId::EdgeProjection
                | TableId::E2eeObject
        ) || (table == TableId::E2eeState && kind != 1)
        {
            crate::ProtocolRecordBody::new(table, kind, 1, vec![1])?.encode()?
        } else if kind == 1 {
            crate::domain_records::fixtures::live_body(table, 1)?
        } else {
            Vec::new()
        };
        let generation = if matches!(
            table,
            TableId::Account | TableId::Session | TableId::EdgeProjection
        ) && kind == 1
        {
            1
        } else {
            0
        };
        PersistentRecordValue::new(table, kind, 1, generation, None, Vec::new(), body)?.encode()
    }

    #[test]
    fn source_charges_and_rekey_generation_cover_each_independent_boundary() {
        let limits = test_limits();
        assert_eq!(validate_source_charges(state(100, 200), limits), Ok(()));
        assert_eq!(
            validate_source_charges(state(101, 200), limits),
            Err(StorageError::LimitExceeded)
        );
        assert_eq!(
            validate_source_charges(state(100, 201), limits),
            Err(StorageError::LimitExceeded)
        );

        let source = StorageMasterKey::from_bytes([1; 32]);
        let same = StorageMasterKey::from_bytes([1; 32]);
        let different = StorageMasterKey::from_bytes([2; 32]);
        assert_eq!(validate_rekey_generation(&source, 1, &same, 2), Ok(()));
        assert_eq!(
            validate_rekey_generation(&source, 1, &same, 1),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            validate_rekey_generation(&source, u32::MAX, &same, 1),
            Err(StorageError::LimitExceeded)
        );
        assert_eq!(validate_rekey_generation(&source, 1, &different, 1), Ok(()));
        assert_eq!(
            validate_rekey_generation(&source, 1, &different, 2),
            Err(StorageError::InvalidEncoding)
        );
    }

    #[test]
    fn restore_login_scan_rejects_missing_unknown_and_creation_generations()
    -> Result<(), StorageError> {
        let network = NetworkId::from_bytes([3; 32]);
        let previous_key = LoginIndexKey::from_bytes([4; 32]);
        let current_key = LoginIndexKey::from_bytes([5; 32]);
        let stable = crate::LoginIndexKeyState::stable(1, current_key.key_id(network))?;
        let transition = crate::LoginIndexKeyState::transition(
            1,
            previous_key.key_id(network),
            current_key.key_id(network),
            2,
        )?;

        assert_eq!(
            RestoreLoginScan::new().finish(network, &current_key, None),
            Err(StorageError::StaleState)
        );

        let mut stable_scan = RestoreLoginScan::new();
        stable_scan.key_state = Some(stable);
        stable_scan.observe_generation(1, false)?;
        stable_scan.finish(network, &current_key, None)?;

        let mut transition_scan = RestoreLoginScan::new();
        transition_scan.key_state = Some(transition);
        transition_scan.observe_generation(1, false)?;
        transition_scan.observe_generation(1, false)?;
        transition_scan.observe_generation(2, false)?;
        transition_scan.finish(network, &current_key, Some(&previous_key))?;

        let mut creation_scan = RestoreLoginScan::new();
        creation_scan.key_state = Some(transition);
        creation_scan.observe_generation(1, true)?;
        creation_scan.observe_generation(2, false)?;
        assert_eq!(
            creation_scan.finish(network, &current_key, Some(&previous_key)),
            Err(StorageError::StaleState)
        );

        let mut unknown_scan = RestoreLoginScan::new();
        unknown_scan.key_state = Some(transition);
        unknown_scan.observe_generation(3, false)?;
        assert_eq!(
            unknown_scan.finish(network, &current_key, Some(&previous_key)),
            Err(StorageError::StaleState)
        );

        let mut count_scan = RestoreLoginScan::new();
        count_scan.key_state = Some(transition);
        count_scan.observe_generation(1, false)?;
        count_scan.observe_generation(2, false)?;
        assert_eq!(
            count_scan.finish(network, &current_key, Some(&previous_key)),
            Err(StorageError::StaleState)
        );

        let mut full_scan = RestoreLoginScan::new();
        full_scan.observe_generation(1, false)?;
        full_scan.observe_generation(2, false)?;
        assert_eq!(
            full_scan.observe_generation(3, false),
            Err(StorageError::StaleState)
        );
        full_scan.generations[0] = Some(RestoreLoginGeneration {
            generation: 1,
            entry_count: u64::MAX,
            creation_reservations: 0,
        });
        assert_eq!(
            full_scan.observe_generation(1, false),
            Err(StorageError::Overflow)
        );
        full_scan.generations[0] = Some(RestoreLoginGeneration {
            generation: 1,
            entry_count: 0,
            creation_reservations: u64::MAX,
        });
        assert_eq!(
            full_scan.observe_generation(1, true),
            Err(StorageError::Overflow)
        );
        Ok(())
    }

    #[test]
    fn rekey_private_index_transform_authenticates_source_and_target_keys()
    -> Result<(), StorageError> {
        let network = NetworkId::from_bytes([6; 32]);
        let server = ServerId::from_bytes([7; 16]);
        let source_binding = DatabaseBinding::new(
            network,
            server,
            ServerIncarnation::from_bytes([8; 16]),
            DatabaseId::from_bytes([9; 16]),
        );
        let target_binding = DatabaseBinding::new(
            network,
            server,
            ServerIncarnation::from_bytes([10; 16]),
            DatabaseId::from_bytes([11; 16]),
        );
        let source_master = StorageMasterKey::from_bytes([12; 32]);
        let target_master = StorageMasterKey::from_bytes([13; 32]);
        let table = StorageTable::new(TableId::NicknameReservation.as_u16())?;
        let source_index =
            derive_storage_index(&source_master, source_binding, table, 1, b"nickname")?;
        let source_key = StoredKey::new(source_index.expose_for_storage_key().to_vec())?;
        let plaintext = PersistentRecordValue::new(
            TableId::NicknameReservation,
            1,
            1,
            0,
            None,
            Vec::new(),
            b"Nickname".to_vec(),
        )?
        .encode()?;
        let source = StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::NicknameReservation,
            StoredKey::new(source_key.as_bytes().to_vec())?,
            1,
            ZERO,
            0,
        )?;
        let record = ConstructionSourceRecord {
            table: TableId::NicknameReservation,
            key: StoredKey::new(source_key.as_bytes().to_vec())?,
            record_schema: 1,
            plaintext: Zeroizing::new(plaintext),
        };
        let target_key = rekey_target_stored_key(
            &source,
            &record,
            &source_master,
            source_binding,
            1,
            &target_master,
            target_binding,
            1,
        )?;
        assert_ne!(target_key.as_bytes(), source.key().as_bytes());

        let wrong_source = StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::NicknameReservation,
            StoredKey::new(vec![0; 32])?,
            1,
            ZERO,
            0,
        )?;
        assert_eq!(
            rekey_target_stored_key(
                &wrong_source,
                &record,
                &source_master,
                source_binding,
                1,
                &target_master,
                target_binding,
                1,
            )
            .map(|_| ()),
            Err(StorageError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn construction_limits_reject_each_zero_excess_and_cross_limit() {
        assert!(maximum_limits().validate().is_ok());

        let mut cases = Vec::new();
        for value in [0, MAX_CONSTRUCTION_SOURCE_BYTES + 1] {
            cases.push(ConstructionLimits {
                source_database_bytes: value,
                ..maximum_limits()
            });
            cases.push(ConstructionLimits {
                source_backup_bytes: value,
                ..maximum_limits()
            });
        }
        for value in [0, MAX_CONSTRUCTION_TARGET_BYTES + 1] {
            cases.push(ConstructionLimits {
                target_database_bytes: value,
                ..maximum_limits()
            });
            cases.push(ConstructionLimits {
                target_backup_bytes: value,
                ..maximum_limits()
            });
        }
        cases.extend([
            ConstructionLimits {
                target_database_bytes: 2,
                target_backup_bytes: 1,
                ..maximum_limits()
            },
            ConstructionLimits {
                plan_bytes: 0,
                ..maximum_limits()
            },
            ConstructionLimits {
                plan_bytes: MAX_CONSTRUCTION_PLAN_BYTES + 1,
                ..maximum_limits()
            },
            ConstructionLimits {
                batch_records: 0,
                ..maximum_limits()
            },
            ConstructionLimits {
                batch_records: MAX_CONSTRUCTION_BATCH_RECORDS + 1,
                ..maximum_limits()
            },
            ConstructionLimits {
                batch_bytes: 0,
                ..maximum_limits()
            },
            ConstructionLimits {
                batch_bytes: MAX_CONSTRUCTION_BATCH_BYTES + 1,
                ..maximum_limits()
            },
        ]);
        for limits in cases {
            assert_eq!(limits.validate(), Err(StorageError::LimitExceeded));
        }
    }

    #[test]
    fn in_memory_plan_rejects_count_key_state_size_and_hash_mismatches() -> Result<(), StorageError>
    {
        let entries = rekey_entries()?;
        let mut wrong_count = rekey_identity(&entries)?;
        wrong_count.planned_entry_count += 1;
        assert!(matches!(
            ConstructionPlan::new(&wrong_count, rekey_entries()?, maximum_limits()),
            Err(StorageError::ResumeMismatch)
        ));

        let account_only = vec![rekey_entry(TableId::Account, account_key(2)?)?];
        let account_identity = rekey_identity(&account_only)?;
        assert!(matches!(
            ConstructionPlan::new(&account_identity, account_only, maximum_limits()),
            Err(StorageError::StaleState)
        ));

        let key = StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
        let duplicate_key_states = vec![
            rekey_entry(
                TableId::LoginIndexKeyState,
                StoredKey::new(key.as_bytes().to_vec())?,
            )?,
            rekey_entry(TableId::LoginIndexKeyState, key)?,
        ];
        let mut duplicate_identity = rekey_identity(&entries)?;
        duplicate_identity.planned_entry_count = 2;
        assert!(matches!(
            ConstructionPlan::new(&duplicate_identity, duplicate_key_states, maximum_limits()),
            Err(StorageError::StaleState)
        ));

        let mut bad_hash = rekey_identity(&entries)?;
        bad_hash.construction_plan_hash = StorageDigest::from_bytes([9; 32]);
        assert!(matches!(
            ConstructionPlan::new(&bad_hash, rekey_entries()?, maximum_limits()),
            Err(StorageError::ResumeMismatch)
        ));

        let identity = rekey_identity(&entries)?;
        assert!(matches!(
            ConstructionPlan::new(
                &identity,
                entries,
                ConstructionLimits {
                    plan_bytes: 1,
                    ..maximum_limits()
                }
            ),
            Err(StorageError::LimitExceeded)
        ));
        Ok(())
    }

    #[test]
    fn plan_identity_cursor_and_successor_bind_every_resume_field() -> Result<(), StorageError> {
        let (identity, plan) = rekey_plan()?;
        assert!(plan.validate_identity(&identity).is_ok());

        let mut wrong_count = identity;
        wrong_count.planned_entry_count += 1;
        assert_eq!(
            plan.validate_identity(&wrong_count),
            Err(StorageError::ResumeMismatch)
        );
        let mut wrong_hash = identity;
        wrong_hash.construction_plan_hash = StorageDigest::from_bytes([8; 32]);
        assert_eq!(
            plan.validate_identity(&wrong_hash),
            Err(StorageError::ResumeMismatch)
        );
        let mut restore = identity;
        restore.kind = StorageConstructionKind::Restore;
        restore.source_stream_digest = Some(StorageDigest::from_bytes([7; 32]));
        restore.transform_profile_hash = agenc_ircd_crypto::restore_transform_profile_hash()?;
        assert_eq!(
            plan.validate_identity(&restore),
            Err(StorageError::ResumeMismatch)
        );

        let before = marker(identity, StorageConstructionCursor::BeforeFirst, 0);
        assert!(validate_cursor(&before, &plan).is_ok());
        assert_eq!(
            successor_marker(&before, &plan, 0).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        let second = successor_marker(&before, &plan, 1)?;
        assert!(matches!(
            second.next_target,
            StorageConstructionCursor::AtTarget { .. }
        ));
        assert!(validate_cursor(&second, &plan).is_ok());
        let complete = successor_marker(&before, &plan, 2)?;
        assert!(matches!(
            complete.next_target,
            StorageConstructionCursor::Complete
        ));
        assert!(validate_cursor(&complete, &plan).is_ok());
        assert_eq!(
            successor_marker(&before, &plan, 3).map(|_| ()),
            Err(StorageError::StaleState)
        );

        let wrong_complete = marker(identity, StorageConstructionCursor::Complete, 1);
        assert_eq!(
            validate_cursor(&wrong_complete, &plan),
            Err(StorageError::ResumeMismatch)
        );
        let overflow = marker(identity, StorageConstructionCursor::Complete, u64::MAX);
        assert_eq!(
            successor_marker(&overflow, &plan, 1).map(|_| ()),
            Err(StorageError::Overflow)
        );
        Ok(())
    }

    #[test]
    fn restore_scratch_codecs_reject_noncanonical_keys_and_versions() -> Result<(), StorageError> {
        assert_eq!(
            decode_restore_scratch_key(&[0]).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        let mut untracked = TableId::KeyCheck.as_u16().to_be_bytes().to_vec();
        untracked.push(1);
        assert_eq!(
            decode_restore_scratch_key(&untracked).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );

        assert_eq!(
            encode_restore_version(IntegrityRecordVersion::Absent)?,
            None
        );
        assert_eq!(
            encode_restore_version(IntegrityRecordVersion::Present {
                record_schema: 0,
                sealed_record_id: ZERO,
            }),
            Err(StorageError::InvalidEncoding)
        );
        let present = encode_restore_version(IntegrityRecordVersion::Present {
            record_schema: 1,
            sealed_record_id: ZERO,
        })?
        .ok_or(StorageError::InvalidEncoding)?;
        assert!(matches!(
            decode_restore_version(&present),
            Ok(IntegrityRecordVersion::Present {
                record_schema: 1,
                ..
            })
        ));
        assert_eq!(
            decode_restore_version(&present[..35]),
            Err(StorageError::InvalidEncoding)
        );
        let mut zero_schema = present;
        zero_schema[..4].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            decode_restore_version(&zero_schema),
            Err(StorageError::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn source_readers_reject_invalid_generation_offsets_and_frame_lengths()
    -> Result<(), StorageError> {
        let binding = DatabaseBinding::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([2; 16]),
            ServerIncarnation::from_bytes([3; 16]),
            DatabaseId::from_bytes([4; 16]),
        );
        let master = StorageMasterKey::from_bytes([5; 32]);
        assert!(matches!(
            BackupConstructionSourceReader::new(
                Cursor::new(Vec::new()),
                StorageMasterKey::from_bytes([5; 32]),
                binding,
                0,
                BACKUP_FIXED_STREAM_BYTES,
            ),
            Err(StorageError::InvalidEncoding)
        ));
        assert!(matches!(
            BackupConstructionSourceReader::new(
                Cursor::new(Vec::new()),
                StorageMasterKey::from_bytes([5; 32]),
                binding,
                1,
                BACKUP_FIXED_STREAM_BYTES - 1,
            ),
            Err(StorageError::InvalidEncoding)
        ));
        let mut reader = BackupConstructionSourceReader::new(
            Cursor::new(Vec::new()),
            master,
            binding,
            1,
            BACKUP_FIXED_STREAM_BYTES,
        )?;
        let key = account_key(1)?;
        let database_reference = source(TableId::Account, &key)?;
        assert_eq!(
            reader.read_source(&database_reference).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        let past_end = StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            TableId::Account,
            key,
            1,
            ZERO,
            BACKUP_FIXED_STREAM_BYTES,
        )?;
        assert_eq!(
            reader.read_source(&past_end).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );

        let offset = crate::backup::BACKUP_RECORDS_OFFSET;
        let trailer = offset + 8;
        let trailer_length = usize::try_from(trailer).map_err(|_| StorageError::Overflow)?;
        let mut bytes = vec![0; trailer_length];
        assert_eq!(
            read_backup_record(&mut Cursor::new(bytes.clone()), offset - 1, trailer).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            read_backup_record(&mut Cursor::new(bytes.clone()), trailer, trailer).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            read_backup_record(&mut Cursor::new(bytes.clone()), offset, trailer).map(|_| ()),
            Err(StorageError::LimitExceeded)
        );
        let offset_index = usize::try_from(offset).map_err(|_| StorageError::Overflow)?;
        let length_end = offset_index.checked_add(4).ok_or(StorageError::Overflow)?;
        bytes
            .get_mut(offset_index..length_end)
            .ok_or(StorageError::InvalidEncoding)?
            .copy_from_slice(&(crate::backup::MAX_BACKUP_RECORD_BYTES as u32 + 1).to_be_bytes());
        assert_eq!(
            read_backup_record(&mut Cursor::new(bytes), offset, trailer).map(|_| ()),
            Err(StorageError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn exact_copy_and_recovery_prefix_enforce_table_schema_and_counter_rules()
    -> Result<(), StorageError> {
        let stored_account_key = account_key(1)?;
        let account_plaintext = PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            1,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?
        .encode()?;
        let entry = rekey_entry(
            TableId::Account,
            StoredKey::new(stored_account_key.as_bytes().to_vec())?,
        )?;
        let account = record(
            TableId::Account,
            stored_account_key,
            account_plaintext.clone(),
        );
        assert_eq!(exact_source(&entry, &[]), Err(StorageError::StaleState));
        assert_eq!(
            exact_source(
                &entry,
                &[
                    account,
                    record(TableId::Account, account_key(2)?, Vec::new())
                ]
            ),
            Err(StorageError::StaleState)
        );
        let wrong_table = record(TableId::Channel, account_key(3)?, account_plaintext.clone());
        assert_eq!(
            exact_source(&entry, &[wrong_table]),
            Err(StorageError::StaleState)
        );
        let account = record(TableId::Account, account_key(1)?, account_plaintext.clone());
        assert_eq!(exact_source(&entry, &[account])?, account_plaintext);

        let transformed = recovery_transform_prefix(TableId::Account, &account_plaintext)?;
        let transformed = PersistentRecordValue::decode(TableId::Account, &transformed)?;
        assert_eq!(transformed.revision(), 2);
        assert_eq!(transformed.generation(), 2);

        let tombstone =
            PersistentRecordValue::new(TableId::Account, 2, 0, 0, None, Vec::new(), Vec::new())?
                .encode()?;
        let unchanged = recovery_transform_prefix(TableId::Account, &tombstone)?;
        let unchanged = PersistentRecordValue::decode(TableId::Account, &unchanged)?;
        assert_eq!((unchanged.revision(), unchanged.generation()), (0, 0));

        let channel = PersistentRecordValue::new(
            TableId::Channel,
            1,
            1,
            0,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Channel, 2)?,
        )?
        .encode()?;
        let channel = recovery_transform_prefix(TableId::Channel, &channel)?;
        assert_eq!(
            PersistentRecordValue::decode(TableId::Channel, &channel)?.revision(),
            2
        );

        let overflow_revision = PersistentRecordValue::new(
            TableId::Account,
            1,
            u64::MAX,
            1,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?
        .encode()?;
        assert_eq!(
            recovery_transform_prefix(TableId::Account, &overflow_revision),
            Err(StorageError::Overflow)
        );
        let overflow_generation = PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            u64::MAX,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?
        .encode()?;
        assert_eq!(
            recovery_transform_prefix(TableId::Account, &overflow_generation),
            Err(StorageError::Overflow)
        );
        assert_eq!(
            recovery_transform_prefix(TableId::Session, &account_plaintext),
            Err(StorageError::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn disk_plan_builder_enforces_count_uniqueness_order_and_byte_limits()
    -> Result<(), StorageError> {
        let entries = rekey_entries()?;
        let identity = rekey_identity(&entries)?;
        let (file, path) = scratch_file("complete")?;
        let plan = ConstructionPlan::rebuild_disk(
            &identity,
            file,
            rekey_entries()?.into_iter().rev().map(Ok),
            maximum_limits(),
        )?;
        assert_eq!(plan.entry_count(), 2);
        assert!(plan.encoded_bytes() > 0);
        assert_eq!(plan.hash(), identity.construction_plan_hash);
        assert!(plan.entry(0)?.is_some());
        assert!(plan.entry(1)?.is_some());
        assert!(plan.entry(2)?.is_none());
        plan.reverify_disk()?;
        drop(plan);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;

        let (file, path) = scratch_file("streaming")?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Rekey,
            file,
            maximum_limits(),
        )?;
        for entry in rekey_entries()?.into_iter().rev() {
            builder.push(entry)?;
        }
        let plan = builder.finish()?;
        assert_eq!(plan.entry_count(), 2);
        drop(plan);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;

        let (file, path) = scratch_file("duplicate")?;
        let mut builder = ConstructionPlanBuilder::start(
            StorageConstructionKind::Rekey,
            2,
            file,
            maximum_limits(),
        )?;
        builder.push(rekey_entry(TableId::Account, account_key(1)?)?)?;
        assert_eq!(
            builder.push(rekey_entry(TableId::Account, account_key(1)?)?),
            Err(StorageError::InvalidEncoding)
        );
        drop(builder);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;

        let (file, path) = scratch_file("count")?;
        let mut builder = ConstructionPlanBuilder::start(
            StorageConstructionKind::Rekey,
            1,
            file,
            maximum_limits(),
        )?;
        builder.push(rekey_entry(TableId::Account, account_key(1)?)?)?;
        assert_eq!(
            builder.push(rekey_entry(
                TableId::LoginIndexKeyState,
                StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            )?),
            Err(StorageError::LimitExceeded)
        );
        drop(builder);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;

        let (file, path) = scratch_file("bytes")?;
        let mut builder = ConstructionPlanBuilder::start(
            StorageConstructionKind::Rekey,
            2,
            file,
            ConstructionLimits {
                plan_bytes: 1,
                ..maximum_limits()
            },
        )?;
        assert_eq!(
            builder.push(rekey_entry(TableId::Account, account_key(1)?)?),
            Err(StorageError::LimitExceeded)
        );
        drop(builder);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
        Ok(())
    }

    #[test]
    fn restore_scratch_indexes_channels_references_and_current_versions() -> Result<(), StorageError>
    {
        let channel_key = StoredKey::new([7; 16].to_vec())?;
        let backup_channel = StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            TableId::Channel,
            StoredKey::new(channel_key.as_bytes().to_vec())?,
            1,
            StorageDigest::from_bytes([8; 32]),
            91,
        )?;
        let (file, path) = scratch_file("wrong-kind")?;
        let mut rekey = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Rekey,
            file,
            maximum_limits(),
        )?;
        assert_eq!(
            rekey.index_restore_channel_source(&backup_channel),
            Err(StorageError::InvalidEncoding)
        );
        drop(rekey);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
        let (file, path) = scratch_file("restore-index")?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            maximum_limits(),
        )?;
        assert_eq!(
            builder.index_restore_channel_source(&source(TableId::Channel, &channel_key)?),
            Err(StorageError::InvalidEncoding)
        );
        let backup_account = StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            TableId::Account,
            account_key(9)?,
            1,
            ZERO,
            92,
        )?;
        assert_eq!(
            builder.index_restore_channel_source(&backup_account),
            Err(StorageError::InvalidEncoding)
        );
        builder.index_restore_channel_source(&backup_channel)?;
        assert_eq!(
            builder.index_restore_channel_source(&backup_channel),
            Err(StorageError::StaleState)
        );
        let restored_channel = builder.restore_channel_source(&channel_key)?;
        assert_eq!(restored_channel.kind(), backup_channel.kind());
        assert_eq!(restored_channel.table(), backup_channel.table());
        assert_eq!(
            restored_channel.key().as_bytes(),
            backup_channel.key().as_bytes()
        );
        assert_eq!(
            restored_channel.backup_byte_offset(),
            backup_channel.backup_byte_offset()
        );
        assert!(matches!(
            builder.restore_channel_source(&account_key(10)?),
            Err(StorageError::StaleState)
        ));
        let stored_account_key = account_key(11)?;
        let opaque_key = account_key(12)?;
        let account_reference = RecordReference::new(
            TableId::OpaqueRecord,
            StoredKey::new(opaque_key.as_bytes().to_vec())?,
        )?;
        let account_plaintext = PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            1,
            None,
            vec![account_reference],
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?
        .encode()?;
        let account_source = StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            TableId::Account,
            StoredKey::new(stored_account_key.as_bytes().to_vec())?,
            1,
            StorageDigest::from_bytes([13; 32]),
            93,
        )?;
        let account_record = record(
            TableId::Account,
            StoredKey::new(stored_account_key.as_bytes().to_vec())?,
            account_plaintext,
        );
        builder.observe_restore_source_record(&account_source, &account_record)?;
        assert_eq!(
            builder.observe_restore_source_record(&account_source, &account_record),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            builder.verify_restore_references(),
            Err(StorageError::StaleState)
        );
        let opaque_source = StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            TableId::OpaqueRecord,
            StoredKey::new(opaque_key.as_bytes().to_vec())?,
            1,
            StorageDigest::from_bytes([14; 32]),
            94,
        )?;
        let opaque_plaintext = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            1,
            1,
            0,
            None,
            Vec::new(),
            Vec::new(),
        )?
        .encode()?;
        builder.observe_restore_source_record(
            &opaque_source,
            &record(TableId::OpaqueRecord, opaque_key, opaque_plaintext),
        )?;
        assert_eq!(builder.verify_restore_references(), Ok(()));

        let mut state = state(1, 1);
        state.checkpoint_hash = StorageDigest::from_bytes([15; 32]);
        let checkpoint = IntegrityCheckpoint::new(IntegrityCheckpointTbs {
            database_instance_id: DatabaseId::from_bytes([16; 16]),
            cut_storage_commit_sequence: 0,
            cut_manifest_sequence: 0,
            cut_state_generation: 0,
            cut_account_service_response_count: 0,
            cut_nonce_draw_high_water: 0,
            cut_manifest_hash: ZERO,
            tracked_record_count: 0,
            tracked_state_digest: ZERO,
            previous_checkpoint_hash: ZERO,
            installation_storage_commit_sequence: 0,
            installation_manifest_sequence: 0,
            installation_nonce_reservation_start: 0,
            installation_nonce_draw_high_water: 2,
        })?;
        assert_eq!(
            builder.verify_restore_source(state, &checkpoint),
            Err(StorageError::StaleState)
        );
        drop(builder);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
        Ok(())
    }

    #[test]
    fn restore_selection_covers_every_preserve_transform_and_omission_arm()
    -> Result<(), StorageError> {
        let (file, path) = scratch_file("selection")?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            maximum_limits(),
        )?;

        for table in [
            TableId::Account,
            TableId::OpaqueRecord,
            TableId::NicknameReservation,
            TableId::Sanction,
            TableId::History,
            TableId::Audit,
            TableId::AuditCheckpoint,
            TableId::E2eeObject,
            TableId::LoginIndexKeyState,
            TableId::StorageOperation,
            TableId::E2eeState,
        ] {
            let key = if table == TableId::LoginIndexKeyState {
                StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?
            } else {
                account_key(table.as_u16() as u8 + 80)?
            };
            let source = backup_source(table, &key, u64::from(table.as_u16()) + 1)?;
            let record = record(table, StoredKey::new(key.as_bytes().to_vec())?, Vec::new());
            assert!(matches!(
                select_restore_record(&mut builder, &source, &record)?,
                RestoreSelection::Direct(_)
            ));
        }

        for table in [
            TableId::KeyCheck,
            TableId::AuthTransaction,
            TableId::Session,
            TableId::FederationOrigin,
            TableId::RequestResult,
            TableId::StateMeta,
            TableId::IntegrityManifest,
            TableId::IntegrityCheckpoint,
            TableId::EdgeOutbox,
            TableId::EdgeProjection,
            TableId::StorageConstruction,
        ] {
            let key = account_key(table.as_u16() as u8 + 110)?;
            let source = backup_source(table, &key, u64::from(table.as_u16()) + 40)?;
            let record = record(table, key, Vec::new());
            assert!(matches!(
                select_restore_record(&mut builder, &source, &record)?,
                RestoreSelection::Omit
            ));
        }

        for (kind, expected_direct) in [(1_u16, false), (2, true)] {
            let key = account_key(140 + kind as u8)?;
            let source = backup_source(TableId::RegistrationInvite, &key, 70 + u64::from(kind))?;
            let record = record(
                TableId::RegistrationInvite,
                key,
                domain_plaintext(TableId::RegistrationInvite, kind)?,
            );
            assert_eq!(
                matches!(
                    select_restore_record(&mut builder, &source, &record)?,
                    RestoreSelection::Direct(_)
                ),
                expected_direct
            );
        }

        for (kind, expected_direct) in [(1_u16, true), (2, false)] {
            let key = StoredKey::new(vec![150 + kind as u8; 16])?;
            let source = backup_source(TableId::Channel, &key, 80 + u64::from(kind))?;
            let record = record(
                TableId::Channel,
                key,
                domain_plaintext(TableId::Channel, kind)?,
            );
            assert_eq!(
                matches!(
                    select_restore_record(&mut builder, &source, &record)?,
                    RestoreSelection::Direct(StorageConstructionAction::RestoreChannel)
                ),
                expected_direct
            );
        }

        for kind in [1_u16, 2] {
            let key = StoredKey::new(vec![160 + kind as u8; 16])?;
            let source = backup_source(TableId::ChannelName, &key, 90 + u64::from(kind))?;
            let body = if kind == 1 {
                b"#channel".to_vec()
            } else {
                Vec::new()
            };
            let plaintext = PersistentRecordValue::new(
                TableId::ChannelName,
                kind,
                1,
                0,
                None,
                Vec::new(),
                body,
            )?
            .encode()?;
            let selection = select_restore_record(
                &mut builder,
                &source,
                &record(TableId::ChannelName, key, plaintext),
            )?;
            assert_eq!(
                matches!(selection, RestoreSelection::ChannelName),
                kind == 1
            );
        }

        for (kind, expected_direct) in [(1_u16, false), (2, true)] {
            let key = account_key(170 + kind as u8)?;
            let source = backup_source(TableId::FederationPeer, &key, 100 + u64::from(kind))?;
            let plaintext = domain_plaintext(TableId::FederationPeer, kind)?;
            assert_eq!(
                matches!(
                    select_restore_record(
                        &mut builder,
                        &source,
                        &record(TableId::FederationPeer, key, plaintext),
                    )?,
                    RestoreSelection::Direct(StorageConstructionAction::RestorePeerTombstones)
                ),
                expected_direct
            );
        }

        let network = NetworkId::from_bytes([181; 32]);
        let login_secret = LoginIndexKey::from_bytes([182; 32]);
        let login = NormalizedLogin::prepare("restore-selection")
            .map_err(|_| StorageError::InvalidEncoding)?;
        let login_key = crate::LoginIndexStoredKey::new(
            1,
            derive_login_index(&login_secret, network, &login)?,
        )?;
        let stored_login_key = login_key.encode()?;
        let account = AccountRandomId::from_bytes([183; 16]).to_account_id();
        let login_values = [
            crate::LoginIndexValue::new(
                &login_key,
                crate::LoginIndexValueKind::Live {
                    account_id: account,
                    opaque_credential_id: OpaqueCredentialId::from_bytes([184; 32]),
                },
            )?,
            crate::LoginIndexValue::new(
                &login_key,
                crate::LoginIndexValueKind::CreationReservation {
                    transaction_id: TransactionId::from_bytes([185; 16]),
                    expires_at: 1,
                },
            )?,
            crate::LoginIndexValue::new(
                &login_key,
                crate::LoginIndexValueKind::DeletionTombstone {
                    deleted_account_id: account,
                    expires_at: 2,
                },
            )?,
        ];
        for (index, value) in login_values.into_iter().enumerate() {
            let source = backup_source(TableId::LoginIndex, &stored_login_key, 120 + index as u64)?;
            let record = record(
                TableId::LoginIndex,
                StoredKey::new(stored_login_key.as_bytes().to_vec())?,
                value.encode()?,
            );
            assert_eq!(
                matches!(
                    select_restore_record(&mut builder, &source, &record)?,
                    RestoreSelection::Direct(StorageConstructionAction::RestoreCopy)
                ),
                index != 1
            );
        }

        drop(builder);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
        Ok(())
    }

    #[test]
    fn restore_copy_validation_covers_every_admitted_and_rejected_table() -> Result<(), StorageError>
    {
        for table in [
            TableId::OpaqueRecord,
            TableId::NicknameReservation,
            TableId::Sanction,
            TableId::History,
            TableId::Audit,
            TableId::AuditCheckpoint,
            TableId::E2eeObject,
            TableId::LoginIndexKeyState,
            TableId::StorageOperation,
        ] {
            assert_eq!(
                validate_restore_copy_source(&record(table, account_key(200)?, Vec::new())),
                Ok(())
            );
        }
        assert_eq!(
            validate_restore_copy_source(&record(
                TableId::RegistrationInvite,
                account_key(201)?,
                domain_plaintext(TableId::RegistrationInvite, 2)?,
            )),
            Ok(())
        );
        assert_eq!(
            validate_restore_copy_source(&record(
                TableId::RegistrationInvite,
                account_key(202)?,
                domain_plaintext(TableId::RegistrationInvite, 1)?,
            )),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            validate_restore_copy_source(&record(TableId::Account, account_key(203)?, Vec::new(),)),
            Err(StorageError::InvalidEncoding)
        );
        Ok(())
    }

    fn restore_entry(
        table: TableId,
        key: StoredKey,
        action: StorageConstructionAction,
    ) -> Result<StorageConstructionPlanEntry, StorageError> {
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![backup_source(table, &key, 1)?],
            table,
            key,
            1,
            action,
            0,
        )
    }

    #[test]
    fn exact_copy_transformer_rejects_mismatched_inputs_and_admits_both_copy_profiles()
    -> Result<(), StorageError> {
        let key = account_key(210)?;
        let entry = rekey_entry(TableId::Account, StoredKey::new(key.as_bytes().to_vec())?)?;
        let source_record = record(TableId::Account, key, vec![1, 2, 3]);
        let mut transformer = ExactCopyTransformer;
        assert_eq!(
            transformer
                .transform(StorageConstructionKind::Rekey, &entry, &[source_record])?
                .as_slice(),
            [1, 2, 3]
        );
        assert_eq!(
            transformer.transform(StorageConstructionKind::Rekey, &entry, &[]),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            transformer.transform(
                StorageConstructionKind::Restore,
                &entry,
                &[record(TableId::Account, account_key(210)?, Vec::new())]
            ),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            transformer.transform(
                StorageConstructionKind::Rekey,
                &entry,
                &[
                    record(TableId::Account, account_key(210)?, Vec::new()),
                    record(TableId::Account, account_key(211)?, Vec::new()),
                ]
            ),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            transformer.transform(
                StorageConstructionKind::Rekey,
                &entry,
                &[record(
                    TableId::Channel,
                    StoredKey::new(vec![1; 16])?,
                    Vec::new()
                )]
            ),
            Err(StorageError::InvalidEncoding)
        );
        let mismatched_schema = ConstructionSourceRecord {
            table: TableId::Account,
            key: account_key(210)?,
            record_schema: 2,
            plaintext: Zeroizing::new(Vec::new()),
        };
        assert_eq!(
            transformer.transform(StorageConstructionKind::Rekey, &entry, &[mismatched_schema]),
            Err(StorageError::InvalidEncoding)
        );

        let invite_key = StoredKey::new(vec![212; 16])?;
        let invite_entry = restore_entry(
            TableId::RegistrationInvite,
            StoredKey::new(invite_key.as_bytes().to_vec())?,
            StorageConstructionAction::RestoreCopy,
        )?;
        let tombstone = domain_plaintext(TableId::RegistrationInvite, 2)?;
        assert_eq!(
            transformer
                .transform(
                    StorageConstructionKind::Restore,
                    &invite_entry,
                    &[record(
                        TableId::RegistrationInvite,
                        invite_key,
                        tombstone.clone()
                    )]
                )?
                .as_slice(),
            tombstone
        );
        Ok(())
    }

    #[test]
    fn recovery_transformer_applies_account_channel_and_peer_profiles() -> Result<(), StorageError>
    {
        let epoch = RecoveryEpoch::from_bytes([213; 16]);
        let source_guard = StorageDigest::from_bytes([214; 32]);
        let mut transformer = RecoveryTransformV1::new(epoch, source_guard);

        let account_key = account_key(215)?;
        let account_entry = restore_entry(
            TableId::Account,
            StoredKey::new(account_key.as_bytes().to_vec())?,
            StorageConstructionAction::RestoreAccount,
        )?;
        let account_plaintext = domain_plaintext(TableId::Account, 1)?;
        let transformed = transformer.transform(
            StorageConstructionKind::Restore,
            &account_entry,
            &[record(TableId::Account, account_key, account_plaintext)],
        )?;
        let account = PersistentRecordValue::decode(TableId::Account, &transformed)?;
        assert_eq!((account.revision(), account.generation()), (2, 2));

        let channel_key = StoredKey::new(vec![216; 16])?;
        let channel_entry = restore_entry(
            TableId::Channel,
            StoredKey::new(channel_key.as_bytes().to_vec())?,
            StorageConstructionAction::RestoreChannel,
        )?;
        let channel_plaintext = domain_plaintext(TableId::Channel, 1)?;
        let transformed = transformer.transform(
            StorageConstructionKind::Restore,
            &channel_entry,
            &[record(TableId::Channel, channel_key, channel_plaintext)],
        )?;
        let channel = PersistentRecordValue::decode(TableId::Channel, &transformed)?;
        assert_eq!((channel.revision(), channel.generation()), (2, 0));

        let peer_key = StoredKey::new(vec![217; 16])?;
        let peer_entry = restore_entry(
            TableId::FederationPeer,
            StoredKey::new(peer_key.as_bytes().to_vec())?,
            StorageConstructionAction::RestorePeerTombstones,
        )?;
        let peer_plaintext = domain_plaintext(TableId::FederationPeer, 2)?;
        let transformed = transformer.transform(
            StorageConstructionKind::Restore,
            &peer_entry,
            &[record(TableId::FederationPeer, peer_key, peer_plaintext)],
        )?;
        let peer = PersistentRecordValue::decode(TableId::FederationPeer, &transformed)?;
        assert_eq!(peer.record_kind(), 2);
        Ok(())
    }

    #[test]
    fn recovery_transformer_rebuilds_channel_name_from_both_sources() -> Result<(), StorageError> {
        let channel_key = StoredKey::new(vec![218; 16])?;
        let name_key = StoredKey::new(vec![219; 32])?;
        let channel_source = backup_source(TableId::Channel, &channel_key, 1)?;
        let name_source = backup_source(TableId::ChannelName, &name_key, 2)?;
        let entry = StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![name_source, channel_source],
            TableId::ChannelName,
            StoredKey::new(name_key.as_bytes().to_vec())?,
            1,
            StorageConstructionAction::RestoreChannelName,
            0,
        )?;
        let channel_plaintext = PersistentRecordValue::new(
            TableId::Channel,
            1,
            7,
            0,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Channel, 1)?,
        )?
        .encode()?;
        let reference = RecordReference::new(
            TableId::Channel,
            StoredKey::new(channel_key.as_bytes().to_vec())?,
        )?;
        let name_plaintext = PersistentRecordValue::new(
            TableId::ChannelName,
            1,
            1,
            0,
            None,
            vec![reference],
            b"#restored".to_vec(),
        )?
        .encode()?;
        let sources = [
            record(TableId::ChannelName, name_key, name_plaintext),
            record(TableId::Channel, channel_key, channel_plaintext),
        ];
        let mut transformer = RecoveryTransformV1::new(
            RecoveryEpoch::from_bytes([220; 16]),
            StorageDigest::from_bytes([221; 32]),
        );
        let transformed =
            transformer.transform(StorageConstructionKind::Restore, &entry, &sources)?;
        let name = PersistentRecordValue::decode(TableId::ChannelName, &transformed)?;
        assert_eq!(name.revision(), 8);
        assert_eq!(name.body(), b"#restored");
        Ok(())
    }

    #[test]
    fn recovery_transformer_rebinds_only_live_e2ee_routes() -> Result<(), StorageError> {
        let target_epoch = RecoveryEpoch::from_bytes([222; 16]);
        let source_guard = StorageDigest::from_bytes([223; 32]);
        let mut transformer = RecoveryTransformV1::new(target_epoch, source_guard);
        for (index, state) in [
            crate::E2eeRecoveryKind::Normal,
            crate::E2eeRecoveryKind::Pending,
            crate::E2eeRecoveryKind::Conflict,
            crate::E2eeRecoveryKind::Closed,
        ]
        .into_iter()
        .enumerate()
        {
            let key = StoredKey::new(vec![224, index as u8, 1])?;
            let entry = restore_entry(
                TableId::E2eeState,
                StoredKey::new(key.as_bytes().to_vec())?,
                StorageConstructionAction::RestoreE2eeState,
            )?;
            let original_epoch = RecoveryEpoch::from_bytes([225; 16]);
            let original_guard = StorageDigest::from_bytes([226; 32]);
            let gate = crate::E2eeRecoveryGate::new(
                StorageDigest::from_bytes([227; 32]),
                state,
                original_epoch,
                StorageDigest::from_bytes([228; 32]),
                StorageDigest::from_bytes([229; 32]),
                StorageDigest::from_bytes([230; 32]),
                original_guard,
            );
            let plaintext = PersistentRecordValue::new(
                TableId::E2eeState,
                1,
                1,
                0,
                None,
                Vec::new(),
                gate.encode()?,
            )?
            .encode()?;
            let transformed = transformer.transform(
                StorageConstructionKind::Restore,
                &entry,
                &[record(TableId::E2eeState, key, plaintext)],
            )?;
            let value = PersistentRecordValue::decode(TableId::E2eeState, &transformed)?;
            let recovered = crate::E2eeRecoveryGate::decode(value.body())?;
            if matches!(
                state,
                crate::E2eeRecoveryKind::Normal | crate::E2eeRecoveryKind::Pending
            ) {
                assert_eq!(recovered.state(), crate::E2eeRecoveryKind::Pending);
                assert_eq!(recovered.recovery_epoch(), target_epoch);
                assert_eq!(recovered.source_rollback_guard_hash(), source_guard);
            } else {
                assert_eq!(recovered.state(), state);
                assert_eq!(recovered.recovery_epoch(), original_epoch);
                assert_eq!(recovered.source_rollback_guard_hash(), original_guard);
            }
        }
        Ok(())
    }

    #[test]
    fn recovery_transformer_rejects_wrong_kind_action_source_and_target_key()
    -> Result<(), StorageError> {
        let mut transformer = RecoveryTransformV1::new(
            RecoveryEpoch::from_bytes([231; 16]),
            StorageDigest::from_bytes([232; 32]),
        );
        let key = account_key(233)?;
        let entry = restore_entry(
            TableId::Account,
            StoredKey::new(key.as_bytes().to_vec())?,
            StorageConstructionAction::RestoreAccount,
        )?;
        let plaintext = domain_plaintext(TableId::Account, 1)?;
        assert_eq!(
            transformer.transform(
                StorageConstructionKind::Rekey,
                &entry,
                &[record(TableId::Account, key, plaintext.clone())]
            ),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            transformer.transform(StorageConstructionKind::Restore, &entry, &[]),
            Err(StorageError::StaleState)
        );

        let rekey = rekey_entry(TableId::Account, account_key(234)?)?;
        assert_eq!(
            transformer.transform(
                StorageConstructionKind::Restore,
                &rekey,
                &[record(
                    TableId::Account,
                    account_key(234)?,
                    plaintext.clone()
                )]
            ),
            Err(StorageError::InvalidEncoding)
        );

        let invalid_target = restore_entry(
            TableId::E2eeState,
            StoredKey::new(vec![1])?,
            StorageConstructionAction::RestoreE2eeState,
        )?;
        let opaque = domain_plaintext(TableId::E2eeState, 2)?;
        assert_eq!(
            transformer.transform(
                StorageConstructionKind::Restore,
                &invalid_target,
                &[record(TableId::E2eeState, StoredKey::new(vec![1])?, opaque)]
            ),
            Err(StorageError::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn construction_source_open_binds_each_authenticated_envelope_field() -> Result<(), StorageError>
    {
        let master_key = StorageMasterKey::from_bytes([235; 32]);
        let binding = DatabaseBinding::new(
            NetworkId::from_bytes([236; 32]),
            ServerId::from_bytes([237; 16]),
            ServerIncarnation::from_bytes([238; 16]),
            DatabaseId::from_bytes([239; 16]),
        );
        let key = account_key(240)?;
        let plaintext = domain_plaintext(TableId::Account, 1)?;
        let encoded = crate::StorageSealContext::new(&master_key, binding, 1)?
            .seal(TableId::Account, 1, [241; 24], &key, &plaintext)?
            .encode()?;
        let record_id = SealedRecord::decode(&encoded)?.record_id()?;
        let reference = StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::Account,
            StoredKey::new(key.as_bytes().to_vec())?,
            1,
            record_id,
            0,
        )?;
        assert!(
            ConstructionSourceRecord::open(&reference, &encoded, &master_key, binding, 1).is_ok()
        );

        let wrong_table = StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::OpaqueRecord,
            StoredKey::new(key.as_bytes().to_vec())?,
            1,
            record_id,
            0,
        )?;
        assert!(matches!(
            ConstructionSourceRecord::open(&wrong_table, &encoded, &master_key, binding, 1),
            Err(StorageError::AuthenticationFailed)
        ));
        let wrong_schema = StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::Account,
            StoredKey::new(key.as_bytes().to_vec())?,
            2,
            record_id,
            0,
        )?;
        assert!(matches!(
            ConstructionSourceRecord::open(&wrong_schema, &encoded, &master_key, binding, 1),
            Err(StorageError::AuthenticationFailed)
        ));
        let wrong_identifier = StorageConstructionSource::new(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::Account,
            StoredKey::new(key.as_bytes().to_vec())?,
            1,
            StorageDigest::from_bytes([242; 32]),
            0,
        )?;
        assert!(matches!(
            ConstructionSourceRecord::open(&wrong_identifier, &encoded, &master_key, binding, 1),
            Err(StorageError::AuthenticationFailed)
        ));
        assert!(matches!(
            ConstructionSourceRecord::open(&reference, &encoded, &master_key, binding, 2),
            Err(StorageError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn executor_resume_and_batch_successor_reject_each_independent_binding()
    -> Result<(), StorageError> {
        let (identity, mut wrong_kind_plan) = rekey_plan()?;
        wrong_kind_plan.kind = StorageConstructionKind::Restore;
        let before = marker(identity, StorageConstructionCursor::BeforeFirst, 0);
        assert!(matches!(
            ConstructionExecutor::resume(before, wrong_kind_plan, maximum_limits()),
            Err(StorageError::ResumeMismatch)
        ));

        let (identity, mut wrong_hash_plan) = rekey_plan()?;
        wrong_hash_plan.hash = StorageDigest::from_bytes([243; 32]);
        let before = marker(identity, StorageConstructionCursor::BeforeFirst, 0);
        assert!(matches!(
            ConstructionExecutor::resume(before, wrong_hash_plan, maximum_limits()),
            Err(StorageError::ResumeMismatch)
        ));

        let (identity, mut wrong_count_plan) = rekey_plan()?;
        wrong_count_plan.entry_count = 1;
        let before = marker(identity, StorageConstructionCursor::BeforeFirst, 0);
        assert!(matches!(
            ConstructionExecutor::resume(before, wrong_count_plan, maximum_limits()),
            Err(StorageError::ResumeMismatch)
        ));

        let (identity, plan) = rekey_plan()?;
        let first_entry = plan.entry(0)?.ok_or(StorageError::StaleState)?;
        let second_entry = plan.entry(1)?.ok_or(StorageError::StaleState)?;
        let first = || ConstructionTargetRecord {
            entry: &first_entry,
            plaintext: &[],
        };
        let second = || ConstructionTargetRecord {
            entry: &second_entry,
            plaintext: &[],
        };
        let current = marker(identity, StorageConstructionCursor::BeforeFirst, 0);
        let successor = successor_marker(&current, &plan, 1)?;

        let wrong_cursor = marker(
            identity,
            StorageConstructionCursor::AtTarget {
                table: TableId::Account,
                key: account_key(244)?,
            },
            0,
        );
        assert_eq!(
            validate_marker_successor(&wrong_cursor, &[first()], &successor),
            Err(StorageError::ResumeMismatch)
        );
        assert_eq!(
            validate_marker_successor(&current, &[second(), first()], &successor),
            Err(StorageError::ResumeMismatch)
        );

        let mut identity_successor = successor_marker(&current, &plan, 1)?;
        identity_successor.identity.source_master_key_id = StorageDigest::from_bytes([245; 32]);
        assert_eq!(
            validate_marker_successor(&current, &[first()], &identity_successor),
            Err(StorageError::ResumeMismatch)
        );
        let mut path_successor = successor_marker(&current, &plan, 1)?;
        path_successor.output_path_hash = StorageDigest::from_bytes([246; 32]);
        assert_eq!(
            validate_marker_successor(&current, &[first()], &path_successor),
            Err(StorageError::ResumeMismatch)
        );
        let count_successor = marker(identity, StorageConstructionCursor::Complete, 2);
        assert_eq!(
            validate_marker_successor(&current, &[first()], &count_successor),
            Err(StorageError::ResumeMismatch)
        );
        Ok(())
    }

    #[test]
    fn disk_plan_and_preflight_accounting_reject_each_independent_internal_mismatch()
    -> Result<(), StorageError> {
        for changed in 0..3 {
            let entries = rekey_entries()?;
            let identity = rekey_identity(&entries)?;
            let (file, path) = scratch_file("reverify-fields")?;
            let mut plan = ConstructionPlan::rebuild_disk(
                &identity,
                file,
                entries.into_iter().map(Ok),
                maximum_limits(),
            )?;
            match changed {
                0 => plan.entry_count += 1,
                1 => plan.encoded_bytes += 1,
                _ => plan.hash = StorageDigest::from_bytes([251; 32]),
            }
            assert_eq!(plan.reverify_disk(), Err(StorageError::ResumeMismatch));
            drop(plan);
            std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
        }

        let (identity, plan) = rekey_plan()?;
        let marker = marker(identity, StorageConstructionCursor::BeforeFirst, 0);
        assert_eq!(
            initial_construction_accounting(
                &marker,
                ConstructionLimits {
                    target_database_bytes: 1,
                    ..maximum_limits()
                },
            )
            .map(|_| ()),
            Err(StorageError::LimitExceeded)
        );
        assert_eq!(
            initial_construction_accounting(
                &marker,
                ConstructionLimits {
                    target_backup_bytes: 1,
                    ..maximum_limits()
                },
            )
            .map(|_| ()),
            Err(StorageError::LimitExceeded)
        );
        let initial = initial_construction_accounting(&marker, maximum_limits())?;

        for changed in 0..3 {
            let mut simulation =
                ConstructionPreflightSimulation::new(&marker, initial, 0, 0, maximum_limits());
            let mut completion = simulation.predicted_completion()?;
            match changed {
                0 => completion.finalization_storage_commit_sequence += 1,
                1 => completion.finalization_manifest_sequence += 1,
                _ => completion.finalization_nonce_draw_high_water += 1,
            }
            assert_eq!(
                simulation.apply_completion(&completion),
                Err(StorageError::StaleState)
            );
        }

        let mut storage_overflow =
            ConstructionPreflightSimulation::new(&marker, initial, 0, 0, maximum_limits());
        storage_overflow.storage_commit_sequence = u64::MAX;
        assert_eq!(
            storage_overflow.predicted_completion().map(|_| ()),
            Err(StorageError::Overflow)
        );
        let mut manifest_overflow =
            ConstructionPreflightSimulation::new(&marker, initial, 0, 0, maximum_limits());
        manifest_overflow.manifest_sequence = u64::MAX;
        assert_eq!(
            manifest_overflow.predicted_completion().map(|_| ()),
            Err(StorageError::Overflow)
        );
        let mut nonce_overflow =
            ConstructionPreflightSimulation::new(&marker, initial, 0, 0, maximum_limits());
        nonce_overflow.nonce_high_water = u64::MAX;
        assert_eq!(
            nonce_overflow.predicted_completion().map(|_| ()),
            Err(StorageError::Overflow)
        );

        let completion =
            ConstructionPreflightSimulation::new(&marker, initial, 0, 0, maximum_limits())
                .predicted_completion()?;
        let mut checkpoint_storage_overflow =
            ConstructionPreflightSimulation::new(&marker, initial, 0, 0, maximum_limits());
        checkpoint_storage_overflow.storage_commit_sequence = u64::MAX;
        assert_eq!(
            checkpoint_storage_overflow
                .finished_preflight(&completion)
                .map(|_| ()),
            Err(StorageError::Overflow)
        );
        let mut checkpoint_nonce_overflow =
            ConstructionPreflightSimulation::new(&marker, initial, 0, 0, maximum_limits());
        checkpoint_nonce_overflow.nonce_high_water = u64::MAX;
        assert_eq!(
            checkpoint_nonce_overflow
                .finished_preflight(&completion)
                .map(|_| ()),
            Err(StorageError::Overflow)
        );

        let mut logical_limit = ConstructionPreflightSimulation::new(
            &marker,
            StorageAccountingLimits {
                current_logical_database_bytes: 0,
                current_backup_stream_bytes: 0,
                database_max_bytes: 0,
                backup_max_bytes: u64::MAX,
            },
            0,
            0,
            maximum_limits(),
        );
        assert_eq!(
            logical_limit.add_final_checkpoint(),
            Err(StorageError::LimitExceeded)
        );
        let mut backup_limit = ConstructionPreflightSimulation::new(
            &marker,
            StorageAccountingLimits {
                current_logical_database_bytes: 0,
                current_backup_stream_bytes: 0,
                database_max_bytes: u64::MAX,
                backup_max_bytes: 0,
            },
            0,
            0,
            maximum_limits(),
        );
        assert_eq!(
            backup_limit.add_final_checkpoint(),
            Err(StorageError::LimitExceeded)
        );

        let sealed_bytes = MIN_SEALED_RECORD_BYTES;
        let logical_charge = logical_record_charge(8, sealed_bytes)?;
        let mut logical_underflow =
            ConstructionPreflightSimulation::new(&marker, initial, 0, 0, maximum_limits());
        logical_underflow.accounting.current_logical_database_bytes = 0;
        logical_underflow.manifest_sealed_bytes = vec![sealed_bytes];
        assert_eq!(
            logical_underflow.prune_manifests(),
            Err(StorageError::StaleState)
        );
        let mut backup_underflow =
            ConstructionPreflightSimulation::new(&marker, initial, 0, 0, maximum_limits());
        backup_underflow.accounting.current_logical_database_bytes = logical_charge;
        backup_underflow.accounting.current_backup_stream_bytes = 0;
        backup_underflow.manifest_sealed_bytes = vec![sealed_bytes];
        assert_eq!(
            backup_underflow.prune_manifests(),
            Err(StorageError::StaleState)
        );

        assert_eq!(plan.validate_initial_marker(&marker), Ok(()));
        let non_initial = successor_marker(&marker, &plan, 1)?;
        assert_eq!(
            plan.validate_initial_marker(&non_initial),
            Err(StorageError::ResumeMismatch)
        );
        Ok(())
    }

    struct UnusedConstructionTarget;

    impl ConstructionTargetWriter for UnusedConstructionTarget {
        fn commit_batch(
            &mut self,
            _batch: ConstructionTargetBatch<'_>,
        ) -> Result<ConstructionCommitReceipt, StorageError> {
            Err(StorageError::Unavailable)
        }

        fn finalization_counters(
            &mut self,
            _marker: &StorageConstruction,
        ) -> Result<ConstructionFinalizationCounters, StorageError> {
            Err(StorageError::Unavailable)
        }

        fn finalize(
            &mut self,
            _marker: &StorageConstruction,
            _completion: &StorageOperationCompletion,
        ) -> Result<(), StorageError> {
            Err(StorageError::Unavailable)
        }
    }

    #[test]
    fn cursor_successor_and_completion_guards_reject_reachable_internal_mismatches()
    -> Result<(), StorageError> {
        let (identity, plan) = rekey_plan()?;
        let first_entry = plan.entry(0)?.ok_or(StorageError::StaleState)?;
        let second_entry = plan.entry(1)?.ok_or(StorageError::StaleState)?;
        let first_record = ConstructionTargetRecord {
            entry: &first_entry,
            plaintext: &[],
        };
        let second_record = ConstructionTargetRecord {
            entry: &second_entry,
            plaintext: &[],
        };
        let before = marker(identity, StorageConstructionCursor::BeforeFirst, 0);
        assert_eq!(
            validate_marker_successor(&before, &[], &before),
            Err(StorageError::InvalidEncoding)
        );

        let complete = successor_marker(&before, &plan, 2)?;
        let at_second = marker(
            identity,
            StorageConstructionCursor::AtTarget {
                table: second_entry.target_table(),
                key: StoredKey::new(second_entry.target_key().as_bytes().to_vec())?,
            },
            1,
        );
        assert_eq!(
            validate_marker_successor(&at_second, &[second_record], &complete),
            Ok(())
        );
        let wrong_table = marker(
            identity,
            StorageConstructionCursor::AtTarget {
                table: TableId::Account,
                key: StoredKey::new(second_entry.target_key().as_bytes().to_vec())?,
            },
            1,
        );
        assert_eq!(
            validate_marker_successor(
                &wrong_table,
                &[ConstructionTargetRecord {
                    entry: &second_entry,
                    plaintext: &[],
                }],
                &complete
            ),
            Err(StorageError::ResumeMismatch)
        );
        let wrong_key = marker(
            identity,
            StorageConstructionCursor::AtTarget {
                table: second_entry.target_table(),
                key: account_key(252)?,
            },
            1,
        );
        assert_eq!(
            validate_marker_successor(
                &wrong_key,
                &[ConstructionTargetRecord {
                    entry: &second_entry,
                    plaintext: &[],
                }],
                &complete
            ),
            Err(StorageError::ResumeMismatch)
        );
        let larger_identity = StorageOperationIdentity {
            planned_entry_count: 3,
            ..identity
        };
        let larger_successor = marker(larger_identity, StorageConstructionCursor::Complete, 3);
        assert_eq!(
            validate_marker_successor(&complete, &[first_record], &larger_successor),
            Err(StorageError::ResumeMismatch)
        );

        assert_eq!(validate_cursor(&before, &plan), Ok(()));
        assert_eq!(validate_cursor(&at_second, &plan), Ok(()));
        assert_eq!(
            validate_cursor(&wrong_table, &plan),
            Err(StorageError::ResumeMismatch)
        );
        assert_eq!(
            validate_cursor(&wrong_key, &plan),
            Err(StorageError::ResumeMismatch)
        );
        assert_eq!(validate_cursor(&complete, &plan), Ok(()));
        assert_eq!(
            successor_marker(&before, &plan, 0).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            successor_marker(&before, &plan, 3).map(|_| ()),
            Err(StorageError::StaleState)
        );

        let initial = initial_construction_accounting(&before, maximum_limits())?;
        let mut prediction =
            ConstructionPreflightSimulation::new(&complete, initial, 0, 0, maximum_limits());
        prediction.marker = marker(identity, StorageConstructionCursor::Complete, 2);
        let completion = prediction.predicted_completion()?;
        assert_eq!(completion.identity.validate(), Ok(()));
        assert_eq!(
            completion.storage_operation_id,
            completion.identity.operation_id()?
        );
        assert_eq!(
            completion.target_records_committed,
            completion.identity.planned_entry_count
        );
        assert_ne!(completion.finalization_storage_commit_sequence, 0);
        completion.validate()?;
        let mut valid_completion =
            ConstructionPreflightSimulation::new(&complete, initial, 0, 0, maximum_limits());
        valid_completion.marker = marker(identity, StorageConstructionCursor::Complete, 2);
        assert_eq!(valid_completion.apply_completion(&completion), Ok(()));
        let mut storage_mismatch =
            ConstructionPreflightSimulation::new(&complete, initial, 0, 0, maximum_limits());
        storage_mismatch.marker = marker(identity, StorageConstructionCursor::Complete, 2);
        storage_mismatch.storage_commit_sequence = 1;
        assert_eq!(
            storage_mismatch.apply_completion(&completion),
            Err(StorageError::StaleState)
        );
        let mut manifest_mismatch =
            ConstructionPreflightSimulation::new(&complete, initial, 0, 0, maximum_limits());
        manifest_mismatch.marker = marker(identity, StorageConstructionCursor::Complete, 2);
        manifest_mismatch.manifest_sequence = 1;
        assert_eq!(
            manifest_mismatch.apply_completion(&completion),
            Err(StorageError::StaleState)
        );
        let mut nonce_mismatch =
            ConstructionPreflightSimulation::new(&complete, initial, 0, 0, maximum_limits());
        nonce_mismatch.marker = marker(identity, StorageConstructionCursor::Complete, 2);
        nonce_mismatch.nonce_high_water = 1;
        assert_eq!(
            nonce_mismatch.apply_completion(&completion),
            Err(StorageError::StaleState)
        );

        let mut incomplete = ConstructionExecutor {
            marker: StorageConstruction {
                next_target: StorageConstructionCursor::Complete,
                target_records_committed: 1,
                ..before
            },
            plan,
            limits: maximum_limits(),
            last_receipt: None,
        };
        assert_eq!(
            incomplete.finalize(&mut UnusedConstructionTarget),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn recovery_transforms_reject_each_semantic_source_mismatch() -> Result<(), StorageError> {
        let channel_key = StoredKey::new(vec![253; 16])?;
        let name_key = StoredKey::new(vec![254; 32])?;
        let entry = StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            vec![
                backup_source(TableId::ChannelName, &name_key, 1)?,
                backup_source(TableId::Channel, &channel_key, 2)?,
            ],
            TableId::ChannelName,
            StoredKey::new(name_key.as_bytes().to_vec())?,
            1,
            StorageConstructionAction::RestoreChannelName,
            0,
        )?;
        let channel_reference = RecordReference::new(
            TableId::Channel,
            StoredKey::new(channel_key.as_bytes().to_vec())?,
        )?;
        let valid_channel = PersistentRecordValue::new(
            TableId::Channel,
            1,
            1,
            0,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Channel, 1)?,
        )?
        .encode()?;
        let valid_name = PersistentRecordValue::new(
            TableId::ChannelName,
            1,
            1,
            0,
            None,
            vec![channel_reference],
            b"#name".to_vec(),
        )?
        .encode()?;
        let channel_tombstone = domain_plaintext(TableId::Channel, 2)?;
        assert_eq!(
            transform_channel_name(
                &entry,
                &[
                    record(
                        TableId::ChannelName,
                        StoredKey::new(name_key.as_bytes().to_vec())?,
                        valid_name.clone()
                    ),
                    record(
                        TableId::Channel,
                        StoredKey::new(channel_key.as_bytes().to_vec())?,
                        channel_tombstone
                    ),
                ],
            ),
            Err(StorageError::StaleState)
        );
        let name_tombstone = domain_plaintext(TableId::ChannelName, 2)?;
        assert_eq!(
            transform_channel_name(
                &entry,
                &[
                    record(
                        TableId::ChannelName,
                        StoredKey::new(name_key.as_bytes().to_vec())?,
                        name_tombstone
                    ),
                    record(
                        TableId::Channel,
                        StoredKey::new(channel_key.as_bytes().to_vec())?,
                        valid_channel.clone()
                    ),
                ],
            ),
            Err(StorageError::StaleState)
        );
        let missing_reference = PersistentRecordValue::new(
            TableId::ChannelName,
            1,
            1,
            0,
            None,
            Vec::new(),
            b"#name".to_vec(),
        )?
        .encode()?;
        assert_eq!(
            transform_channel_name(
                &entry,
                &[
                    record(
                        TableId::ChannelName,
                        StoredKey::new(name_key.as_bytes().to_vec())?,
                        missing_reference
                    ),
                    record(
                        TableId::Channel,
                        StoredKey::new(channel_key.as_bytes().to_vec())?,
                        valid_channel.clone()
                    ),
                ],
            ),
            Err(StorageError::StaleState)
        );
        let wrong_reference = RecordReference::new(TableId::Account, account_key(1)?)?;
        let wrong_reference_name = PersistentRecordValue::new(
            TableId::ChannelName,
            1,
            1,
            0,
            None,
            vec![wrong_reference],
            b"#name".to_vec(),
        )?
        .encode()?;
        assert_eq!(
            transform_channel_name(
                &entry,
                &[
                    record(
                        TableId::ChannelName,
                        StoredKey::new(name_key.as_bytes().to_vec())?,
                        wrong_reference_name
                    ),
                    record(
                        TableId::Channel,
                        StoredKey::new(channel_key.as_bytes().to_vec())?,
                        valid_channel.clone()
                    ),
                ],
            ),
            Err(StorageError::StaleState)
        );

        let peer_key = StoredKey::new(vec![2; 16])?;
        let peer_entry = restore_entry(
            TableId::FederationPeer,
            StoredKey::new(peer_key.as_bytes().to_vec())?,
            StorageConstructionAction::RestorePeerTombstones,
        )?;
        assert_eq!(
            transform_peer_tombstones(
                &peer_entry,
                &[record(
                    TableId::FederationPeer,
                    peer_key,
                    domain_plaintext(TableId::FederationPeer, 1)?,
                )],
            ),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            recovery_transform_prefix(TableId::Channel, &domain_plaintext(TableId::Channel, 2)?,),
            Err(StorageError::InvalidEncoding)
        );
        let _account_tombstone = domain_plaintext(TableId::Account, 2)?;

        let account = account_key(3)?;
        let account_entry = restore_entry(
            TableId::Account,
            StoredKey::new(account.as_bytes().to_vec())?,
            StorageConstructionAction::RestoreAccount,
        )?;
        let wrong_schema = ConstructionSourceRecord {
            table: TableId::Account,
            key: StoredKey::new(account.as_bytes().to_vec())?,
            record_schema: 2,
            plaintext: Zeroizing::new(domain_plaintext(TableId::Account, 1)?),
        };
        assert_eq!(
            exact_source(&account_entry, &[wrong_schema]),
            Err(StorageError::StaleState)
        );
        assert!(
            construction_record_references(
                TableId::Account,
                &account,
                &domain_plaintext(TableId::Account, 1)?,
            )?
            .is_empty()
        );

        let copy_key = StoredKey::new(vec![6; 16])?;
        let copy_entry = restore_entry(
            TableId::OpaqueRecord,
            StoredKey::new(copy_key.as_bytes().to_vec())?,
            StorageConstructionAction::RestoreCopy,
        )?;
        let mut transformer = RecoveryTransformV1::new(
            RecoveryEpoch::from_bytes([4; 16]),
            StorageDigest::from_bytes([5; 32]),
        );
        assert_eq!(
            transformer.transform(StorageConstructionKind::Restore, &copy_entry, &[]),
            Err(StorageError::StaleState)
        );
        let copy_plaintext = domain_plaintext(TableId::OpaqueRecord, 2)?;
        assert_eq!(
            transformer.transform(
                StorageConstructionKind::Restore,
                &copy_entry,
                &[
                    record(
                        TableId::OpaqueRecord,
                        StoredKey::new(copy_key.as_bytes().to_vec())?,
                        copy_plaintext.clone()
                    ),
                    record(TableId::OpaqueRecord, copy_key, copy_plaintext),
                ],
            ),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn internal_restore_scans_reject_duplicate_and_cross_kind_inputs() -> Result<(), StorageError> {
        let stored_account_key = account_key(104)?;
        let account_source = backup_source(TableId::Account, &stored_account_key, 1)?;
        let account_record = record(
            TableId::Account,
            StoredKey::new(stored_account_key.as_bytes().to_vec())?,
            domain_plaintext(TableId::Account, 1)?,
        );
        let (file, path) = scratch_file("rekey-restore-source")?;
        let mut rekey_builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Rekey,
            file,
            maximum_limits(),
        )?;
        assert_eq!(
            rekey_builder.observe_restore_source_record(&account_source, &account_record),
            Err(StorageError::InvalidEncoding),
        );
        drop(rekey_builder);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;

        let mutation = IntegrityRecordMutation::new(
            TableId::Account,
            StoredKey::new(stored_account_key.as_bytes().to_vec())?,
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Present {
                record_schema: 1,
                sealed_record_id: StorageDigest::from_bytes([105; 32]),
            },
        )?;
        let manifest = IntegrityManifest::new(IntegrityManifestTbs::new(
            DatabaseId::from_bytes([106; 16]),
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            3,
            3,
            ZERO,
            vec![mutation],
        )?)?
        .encode()?;
        let (file, path) = scratch_file("duplicate-restore-manifest")?;
        let mut restore_builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            maximum_limits(),
        )?;
        for (key_sequence, offset) in [(1_u64, 2_u64), (2, 3)] {
            let key = StoredKey::new(key_sequence.to_be_bytes().to_vec())?;
            let source = backup_source(TableId::IntegrityManifest, &key, offset)?;
            let manifest_record = record(
                TableId::IntegrityManifest,
                StoredKey::new(key.as_bytes().to_vec())?,
                manifest.clone(),
            );
            let result = restore_builder.observe_restore_source_record(&source, &manifest_record);
            if key_sequence == 1 {
                result?;
            } else {
                assert_eq!(result, Err(StorageError::StaleState));
            }
        }
        drop(restore_builder);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;

        let (_, memory_plan) = rekey_plan()?;
        memory_plan.reverify_disk()?;

        let login_key = LoginIndexKey::from_bytes([107; 32]);
        let login_state = crate::LoginIndexKeyState::stable(
            1,
            login_key.key_id(NetworkId::from_bytes([108; 32])),
        )?;
        let login_state_key = StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
        let login_state_source = backup_source(TableId::LoginIndexKeyState, &login_state_key, 4)?;
        let login_state_record = record(
            TableId::LoginIndexKeyState,
            login_state_key,
            login_state.encode()?,
        );
        let mut login_scan = RestoreLoginScan::new();
        login_scan.observe(&login_state_source, &login_state_record)?;
        assert_eq!(
            login_scan.observe(&login_state_source, &login_state_record),
            Err(StorageError::StaleState),
        );

        let active_sequence = 9_u64;
        let checkpoint_key = StoredKey::new(active_sequence.to_be_bytes().to_vec())?;
        let checkpoint_source = backup_source(TableId::IntegrityCheckpoint, &checkpoint_key, 5)?;
        let checkpoint_record = record(TableId::IntegrityCheckpoint, checkpoint_key, Vec::new());
        let mut active = Some(IntegrityCheckpoint::new(IntegrityCheckpointTbs {
            database_instance_id: DatabaseId::from_bytes([109; 16]),
            cut_storage_commit_sequence: 0,
            cut_manifest_sequence: 0,
            cut_state_generation: 0,
            cut_account_service_response_count: 0,
            cut_nonce_draw_high_water: 0,
            cut_manifest_hash: ZERO,
            tracked_record_count: 0,
            tracked_state_digest: ZERO,
            previous_checkpoint_hash: ZERO,
            installation_storage_commit_sequence: 0,
            installation_manifest_sequence: 0,
            installation_nonce_reservation_start: 0,
            installation_nonce_draw_high_water: 2,
        })?);
        assert_eq!(
            observe_active_checkpoint(
                &checkpoint_source,
                &checkpoint_record,
                active_sequence,
                &mut active,
            ),
            Err(StorageError::StaleState),
        );

        let offset = crate::backup::BACKUP_RECORDS_OFFSET;
        let trailer_start = offset.checked_add(8).ok_or(StorageError::Overflow)?;
        let mut bytes =
            vec![0_u8; usize::try_from(trailer_start).map_err(|_| StorageError::Overflow)?];
        let length_end = usize::try_from(offset.checked_add(4).ok_or(StorageError::Overflow)?)
            .map_err(|_| StorageError::Overflow)?;
        bytes
            .get_mut(usize::try_from(offset).map_err(|_| StorageError::Overflow)?..length_end)
            .ok_or(StorageError::InvalidEncoding)?
            .copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            read_backup_record(&mut Cursor::new(bytes), offset, trailer_start).map(|_| ()),
            Err(StorageError::InvalidEncoding),
        );

        let wrong_entry = rekey_entry(TableId::Account, account_key(110)?)?;
        assert_eq!(
            transform_channel_name(&wrong_entry, &[]),
            Err(StorageError::StaleState),
        );
        Ok(())
    }

    #[test]
    fn restore_scratch_and_disk_plan_rereads_reject_corruption() -> Result<(), StorageError> {
        let stored_account_key = account_key(111)?;
        let mutation = IntegrityRecordMutation::new(
            TableId::Account,
            StoredKey::new(stored_account_key.as_bytes().to_vec())?,
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Present {
                record_schema: 1,
                sealed_record_id: StorageDigest::from_bytes([112; 32]),
            },
        )?;
        let manifest = IntegrityManifest::new(IntegrityManifestTbs::new(
            DatabaseId::from_bytes([113; 16]),
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            3,
            3,
            ZERO,
            vec![mutation],
        )?)?;
        let manifest_key = StoredKey::new(1_u64.to_be_bytes().to_vec())?;
        let manifest_source = backup_source(TableId::IntegrityManifest, &manifest_key, 1)?;
        let manifest_record = record(
            TableId::IntegrityManifest,
            StoredKey::new(manifest_key.as_bytes().to_vec())?,
            manifest.encode()?,
        );
        let (file, path) = scratch_file("restore-corruption")?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            maximum_limits(),
        )?;
        builder.observe_restore_source_record(&manifest_source, &manifest_record)?;
        let checkpoint = IntegrityCheckpoint::new(IntegrityCheckpointTbs {
            database_instance_id: DatabaseId::from_bytes([113; 16]),
            cut_storage_commit_sequence: 0,
            cut_manifest_sequence: 0,
            cut_state_generation: 0,
            cut_account_service_response_count: 0,
            cut_nonce_draw_high_water: 0,
            cut_manifest_hash: ZERO,
            tracked_record_count: 0,
            tracked_state_digest: ZERO,
            previous_checkpoint_hash: ZERO,
            installation_storage_commit_sequence: 0,
            installation_manifest_sequence: 0,
            installation_nonce_reservation_start: 0,
            installation_nonce_draw_high_water: 2,
        })?;
        assert_eq!(
            builder.verify_restore_checkpoint(&checkpoint),
            Err(StorageError::StaleState),
        );
        assert_eq!(
            builder.reverse_restore_manifest(1),
            Err(StorageError::StaleState),
        );
        drop(builder);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;

        let entries = rekey_entries()?;
        let identity = rekey_identity(&entries)?;
        let (file, path) = scratch_file("disk-sequence-corruption")?;
        let plan = ConstructionPlan::rebuild_disk(
            &identity,
            file,
            entries.into_iter().map(Ok),
            maximum_limits(),
        )?;
        let ConstructionPlanStorage::Disk(database) = &plan.storage else {
            return Err(StorageError::StaleState);
        };
        let transaction = database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let mut table = transaction
                .open_table(CONSTRUCTION_PLAN_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let value = table
                .remove(0_u64.to_be_bytes().as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?
                .ok_or(StorageError::StaleState)?
                .value()
                .to_vec();
            table
                .insert(2_u64.to_be_bytes().as_slice(), value.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;
        assert_eq!(plan.reverify_disk(), Err(StorageError::StaleState));
        drop(plan);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;

        let entries = rekey_entries()?;
        let identity = rekey_identity(&entries)?;
        let (file, path) = scratch_file("disk-order-corruption")?;
        let plan = ConstructionPlan::rebuild_disk(
            &identity,
            file,
            entries.into_iter().map(Ok),
            maximum_limits(),
        )?;
        let ConstructionPlanStorage::Disk(database) = &plan.storage else {
            return Err(StorageError::StaleState);
        };
        let transaction = database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let mut table = transaction
                .open_table(CONSTRUCTION_PLAN_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let first = table
                .get(0_u64.to_be_bytes().as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?
                .ok_or(StorageError::StaleState)?
                .value()
                .to_vec();
            let second = table
                .get(1_u64.to_be_bytes().as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?
                .ok_or(StorageError::StaleState)?
                .value()
                .to_vec();
            table
                .insert(0_u64.to_be_bytes().as_slice(), second.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
            table
                .insert(1_u64.to_be_bytes().as_slice(), first.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;
        assert_eq!(plan.reverify_disk(), Err(StorageError::InvalidEncoding));
        drop(plan);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;

        let (file, path) = scratch_file("builder-order-corruption")?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Rekey,
            file,
            maximum_limits(),
        )?;
        let key_state = rekey_entry(
            TableId::LoginIndexKeyState,
            StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        )?
        .encode()?;
        let account = rekey_entry(TableId::Account, account_key(114)?)?.encode()?;
        {
            let mut table = builder
                .transaction
                .open_table(CONSTRUCTION_PLAN_UNSORTED_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            table
                .insert(&[0_u8][..], key_state.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
            table
                .insert(&[1_u8][..], account.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        builder.entry_count = 2;
        builder.encoded_bytes = u64::try_from(
            key_state
                .len()
                .checked_add(account.len())
                .ok_or(StorageError::Overflow)?,
        )
        .map_err(|_| StorageError::Overflow)?;
        assert!(matches!(
            builder.finish(),
            Err(StorageError::InvalidEncoding)
        ));
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
        Ok(())
    }

    #[test]
    fn login_references_and_restore_boundaries_cover_each_exact_arm() -> Result<(), StorageError> {
        let network = NetworkId::from_bytes([115; 32]);
        let login_secret = LoginIndexKey::from_bytes([116; 32]);
        let login = NormalizedLogin::prepare("reference-arms")
            .map_err(|_| StorageError::InvalidEncoding)?;
        let login_key = crate::LoginIndexStoredKey::new(
            1,
            derive_login_index(&login_secret, network, &login)?,
        )?;
        let stored_login_key = login_key.encode()?;
        let account = AccountRandomId::from_bytes([117; 16]).to_account_id();
        let values = [
            crate::LoginIndexValue::new(
                &login_key,
                crate::LoginIndexValueKind::Live {
                    account_id: account,
                    opaque_credential_id: OpaqueCredentialId::from_bytes([118; 32]),
                },
            )?,
            crate::LoginIndexValue::new(
                &login_key,
                crate::LoginIndexValueKind::CreationReservation {
                    transaction_id: TransactionId::from_bytes([119; 16]),
                    expires_at: 1,
                },
            )?,
            crate::LoginIndexValue::new(
                &login_key,
                crate::LoginIndexValueKind::DeletionTombstone {
                    deleted_account_id: account,
                    expires_at: 2,
                },
            )?,
        ];
        let expected_counts = [2_usize, 1, 1];
        for (value, expected_count) in values.into_iter().zip(expected_counts) {
            assert_eq!(
                construction_record_references(
                    TableId::LoginIndex,
                    &stored_login_key,
                    &value.encode()?,
                )?
                .len(),
                expected_count,
            );
        }

        let account_key = account_key(120)?;
        let account_source = backup_source(TableId::Account, &account_key, 1)?;
        let account_record = record(
            TableId::Account,
            StoredKey::new(account_key.as_bytes().to_vec())?,
            domain_plaintext(TableId::Account, 1)?,
        );
        let mut login_scan = RestoreLoginScan::new();
        login_scan.observe(&account_source, &account_record)?;
        let live_login = crate::LoginIndexValue::new(
            &login_key,
            crate::LoginIndexValueKind::Live {
                account_id: account,
                opaque_credential_id: OpaqueCredentialId::from_bytes([129; 32]),
            },
        )?;
        let login_source = backup_source(TableId::LoginIndex, &stored_login_key, 2)?;
        let login_record = record(
            TableId::LoginIndex,
            StoredKey::new(stored_login_key.as_bytes().to_vec())?,
            live_login.encode()?,
        );
        login_scan.observe(&login_source, &login_record)?;

        let offset = crate::backup::BACKUP_RECORDS_OFFSET;
        let trailer_start = offset.checked_add(8).ok_or(StorageError::Overflow)?;
        let mut bytes =
            vec![0_u8; usize::try_from(trailer_start).map_err(|_| StorageError::Overflow)?];
        let length_end = usize::try_from(offset.checked_add(4).ok_or(StorageError::Overflow)?)
            .map_err(|_| StorageError::Overflow)?;
        bytes
            .get_mut(usize::try_from(offset).map_err(|_| StorageError::Overflow)?..length_end)
            .ok_or(StorageError::InvalidEncoding)?
            .copy_from_slice(&5_u32.to_be_bytes());
        assert_eq!(
            read_backup_record(&mut Cursor::new(bytes), offset, trailer_start,).map(|_| ()),
            Err(StorageError::LimitExceeded),
        );

        let first_channel = StoredKey::new(vec![121; 16])?;
        let second_channel = StoredKey::new(vec![122; 16])?;
        let channel_name_key = StoredKey::new(vec![123; 32])?;
        let channel_name_source = backup_source(TableId::ChannelName, &channel_name_key, 2)?;
        let channel_name_plaintext = PersistentRecordValue::new(
            TableId::ChannelName,
            1,
            1,
            0,
            None,
            vec![
                RecordReference::new(TableId::Channel, first_channel.clone())?,
                RecordReference::new(TableId::Channel, second_channel)?,
            ],
            b"#duplicate-channels".to_vec(),
        )?
        .encode()?;
        let channel_name_record = record(
            TableId::ChannelName,
            StoredKey::new(channel_name_key.as_bytes().to_vec())?,
            channel_name_plaintext,
        );
        let (file, path) = scratch_file("duplicate-channel-references")?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            maximum_limits(),
        )?;
        let source_master = StorageMasterKey::from_bytes([124; 32]);
        let target_master = StorageMasterKey::from_bytes([125; 32]);
        let binding = DatabaseBinding::new(
            network,
            ServerId::from_bytes([126; 16]),
            ServerIncarnation::from_bytes([127; 16]),
            DatabaseId::from_bytes([128; 16]),
        );
        let context = RekeyContext {
            source_master_key: &source_master,
            source_binding: binding,
            source_generation: 1,
            target_master_key: &target_master,
            target_binding: binding,
            target_generation: 1,
        };
        assert_eq!(
            push_restore_channel_name(
                &mut builder,
                channel_name_source,
                &channel_name_record,
                &context,
            ),
            Err(StorageError::StaleState),
        );
        let single_channel_plaintext = PersistentRecordValue::new(
            TableId::ChannelName,
            1,
            1,
            0,
            None,
            vec![RecordReference::new(TableId::Channel, first_channel)?],
            b"#single-channel".to_vec(),
        )?
        .encode()?;
        let single_channel_source = backup_source(TableId::ChannelName, &channel_name_key, 3)?;
        let single_channel_record = record(
            TableId::ChannelName,
            channel_name_key,
            single_channel_plaintext,
        );
        assert_eq!(
            push_restore_channel_name(
                &mut builder,
                single_channel_source,
                &single_channel_record,
                &context,
            ),
            Err(StorageError::StaleState),
        );
        drop(builder);
        std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
        Ok(())
    }
}
