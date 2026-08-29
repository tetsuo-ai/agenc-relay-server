//! Bounded, resumable execution of authenticated construction plans.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use agenc_ircd_crypto::{
    ConstructionPlanHasher, DatabaseBinding, LoginIndexKey, LoginIndexKeyId, OsEntropy,
    RollbackGuardRootKey, StorageDigest, StorageMasterKey, StorageTable, TrackedStateHasher,
    derive_storage_index, tracked_record_commitment,
};
use agenc_ircd_types::{ChannelName, Nickname, RecoveryEpoch, TransactionId};
use redb::{
    Database, Durability, ReadableDatabase as _, ReadableTable as _, ReadableTableMetadata as _,
    TableDefinition,
};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::engine::{StorageEngine, StorageOpenConfig};
use crate::{
    BACKUP_FIXED_STREAM_BYTES, BackupRecord, BackupTrustKey, DatabaseHeader, ExistingRecord,
    INTEGRITY_CHECKPOINT_BYTES, IntegrityCheckpoint, IntegrityManifest, IntegrityRecordVersion,
    MAX_CONSTRUCTION_PLAN_BYTES, MIN_SEALED_RECORD_BYTES, PersistentRecordValue, ReadPlan,
    RecordMutation, RecordReference, STATE_META_BYTES, SealedRecord, StateMetaTbs,
    StorageAccountingLimits, StorageConstruction, StorageConstructionAction,
    StorageConstructionCursor, StorageConstructionKind, StorageConstructionPlanEntry,
    StorageConstructionSource, StorageConstructionSourceKind, StorageError, StorageFaultBoundary,
    StorageFaultSite, StorageMutationBatch, StorageMutationHead, StorageOperationCompletion,
    StorageOperationIdentity, StoragePort, StoredKey, TableId, VerifiedBackup,
    construction_plan_hash, logical_meta_charge, logical_record_charge, validate_record_plaintext,
    verify_backup,
};

/// Fixed version-one construction-plan ceiling.
pub const MAX_CONSTRUCTION_SOURCE_BYTES: u64 = 1_099_511_627_776;
/// Fixed version-one target logical/backup ceiling.
pub const MAX_CONSTRUCTION_TARGET_BYTES: u64 = 1_099_511_627_776;
/// Greatest entries committed by one construction service batch.
pub const MAX_CONSTRUCTION_BATCH_RECORDS: usize = 1_000;
/// Greatest transformed plaintext bytes committed by one construction batch.
pub const MAX_CONSTRUCTION_BATCH_BYTES: usize = 16_777_216;

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
        builder.set_cache_size(8 * 1_024 * 1_024);
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
        if checkpoint.tbs().cut_manifest_sequence != state.checkpoint_manifest_sequence
            || checkpoint.checkpoint_hash() != state.checkpoint_hash
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
            let IntegrityRecordVersion::Present {
                record_schema,
                sealed_record_id,
            } = decode_restore_version(encoded.value())?
            else {
                return Err(StorageError::InvalidEncoding);
            };
            let tuple = tracked_commitment_tuple(table, &key, record_schema, sealed_record_id)?;
            hasher.update(tracked_record_commitment(&tuple)?)?;
        }
        if count != checkpoint.tbs().tracked_record_count
            || hasher.finalize()? != checkpoint.tbs().tracked_state_digest
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
    Ok(IntegrityRecordVersion::Present {
        record_schema,
        sealed_record_id: StorageDigest::from_bytes(record_id),
    })
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
            if encoded_bytes > limits.plan_bytes || encoded_bytes > MAX_CONSTRUCTION_PLAN_BYTES {
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
            if canonical != encoded.value() {
                return Err(StorageError::InvalidEncoding);
            }
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
        if marker.next_target != StorageConstructionCursor::BeforeFirst
            || marker.target_records_committed != 0
        {
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
            nonce_high_water: 4,
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
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(self.limits.batch_records)
            .map_err(|_| StorageError::AllocationFailed)?;
        let mut transformed_bytes = 0_usize;
        while prepared.len() < self.limits.batch_records {
            let index = self
                .marker
                .target_records_committed
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
            if next_bytes > self.limits.batch_bytes {
                if prepared.is_empty() {
                    return Err(StorageError::LimitExceeded);
                }
                break;
            }
            prepared.push((entry, plaintext));
            transformed_bytes = next_bytes;
        }
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
            .checked_add(3)
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
            .checked_add(2)
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
            let logical = logical_record_charge(8, *sealed_bytes)?;
            self.accounting.current_logical_database_bytes = self
                .accounting
                .current_logical_database_bytes
                .checked_sub(logical)
                .ok_or(StorageError::StaleState)?;
            self.accounting.current_backup_stream_bytes = self
                .accounting
                .current_backup_stream_bytes
                .checked_sub(logical.checked_add(8).ok_or(StorageError::Overflow)?)
                .ok_or(StorageError::StaleState)?;
        }
        Ok(())
    }

    fn add_final_checkpoint(&mut self) -> Result<(), StorageError> {
        add_preflight_record_charge(
            &mut self.accounting.current_logical_database_bytes,
            &mut self.accounting.current_backup_stream_bytes,
            8,
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
    let mut logical = logical_meta_charge(b"header/v1".len(), crate::DATABASE_HEADER_BYTES)?
        .checked_add(logical_meta_charge(
            b"nonce-reservation/v1".len(),
            crate::NONCE_RESERVATION_BYTES,
        )?)
        .ok_or(StorageError::Overflow)?;
    let mut backup = BACKUP_FIXED_STREAM_BYTES;
    add_preflight_record_charge(
        &mut logical,
        &mut backup,
        crate::KEY_CHECK_STORED_KEY.len(),
        32,
    )?;
    add_preflight_record_charge(
        &mut logical,
        &mut backup,
        crate::STORAGE_CONSTRUCTION_KEY.len(),
        marker.encode()?.len(),
    )?;
    add_preflight_record_charge(&mut logical, &mut backup, 8, INTEGRITY_CHECKPOINT_BYTES)?;
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
        .checked_add(charge.checked_add(8).ok_or(StorageError::Overflow)?)
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
        if sealed.table() != reference.table()
            || sealed.record_schema() != reference.record_schema()
            || sealed.record_id()? != reference.sealed_record_id()
            || sealed.key_generation() != storage_key_generation
        {
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
        || state.logical_database_bytes > MAX_CONSTRUCTION_SOURCE_BYTES
        || state.backup_stream_bytes > limits.source_backup_bytes
        || state.backup_stream_bytes > MAX_CONSTRUCTION_SOURCE_BYTES
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
        if reference.kind() != StorageConstructionSourceKind::BackupRecord
            || reference.backup_byte_offset() >= self.stream_bytes
        {
            return Err(StorageError::InvalidEncoding);
        }
        self.input
            .seek(SeekFrom::Start(reference.backup_byte_offset()))
            .map_err(|_| StorageError::FilesystemRejected)?;
        let mut length_bytes = [0_u8; 4];
        self.input
            .read_exact(&mut length_bytes)
            .map_err(|_| StorageError::FilesystemRejected)?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| StorageError::Overflow)?;
        let end = reference
            .backup_byte_offset()
            .checked_add(4)
            .and_then(|value| value.checked_add(u64::try_from(length).ok()?))
            .ok_or(StorageError::Overflow)?;
        if length == 0 || length > 16_781_364 || end > self.stream_bytes {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(length)
            .map_err(|_| StorageError::AllocationFailed)?;
        encoded.resize(length, 0);
        self.input
            .read_exact(&mut encoded)
            .map_err(|_| StorageError::FilesystemRejected)?;
        let record = BackupRecord::decode(&encoded)?;
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
        if self.verified.logical_database_bytes > limits.source_database_bytes
            || self.verified.stream_bytes > limits.source_backup_bytes
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
            let record = read_backup_record(input, offset, trailer_start, stream_bytes)?;
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
            self.verified.stream_bytes,
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
            self.verified
                .header
                .source_header()
                .tbs()
                .storage_key_generation,
        )
    }
}

fn read_backup_record<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    trailer_start: u64,
    stream_bytes: u64,
) -> Result<BackupRecord, StorageError> {
    if offset < crate::backup::BACKUP_RECORDS_OFFSET || offset >= trailer_start {
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
    let end = offset
        .checked_add(4)
        .and_then(|value| value.checked_add(u64::try_from(length).ok()?))
        .ok_or(StorageError::Overflow)?;
    if length == 0 || length > crate::backup::MAX_BACKUP_RECORD_BYTES || end > trailer_start {
        return Err(StorageError::LimitExceeded);
    }
    if end > stream_bytes {
        return Err(StorageError::InvalidEncoding);
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
    /// Commits one target record and the exact cursor successor atomically.
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
        if completion.identity != marker.identity
            || completion.target_records_committed != marker.target_records_committed
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
        if receipt.storage_commit_sequence != completion.finalization_storage_commit_sequence
            || actual.storage_commit_sequence != completion.finalization_storage_commit_sequence
            || actual.manifest_sequence != completion.finalization_manifest_sequence
            || actual.state_generation != completion.finalization_state_generation
            || actual.account_service_response_count
                != completion.finalization_account_service_response_count
            || actual.nonce_draw_high_water != completion.finalization_nonce_draw_high_water
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
        || records.windows(2).any(|pair| {
            let [left, right] = pair else {
                return false;
            };
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

/// Resumable executor that retains only one entry, two sources, and one target.
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
        let mut prepared: Vec<(StorageConstructionPlanEntry, Zeroizing<Vec<u8>>)> = Vec::new();
        prepared
            .try_reserve_exact(self.limits.batch_records)
            .map_err(|_| StorageError::AllocationFailed)?;
        let mut transformed_bytes = 0_usize;
        while prepared.len() < self.limits.batch_records {
            let index = self
                .marker
                .target_records_committed
                .checked_add(u64::try_from(prepared.len()).map_err(|_| StorageError::Overflow)?)
                .ok_or(StorageError::Overflow)?;
            let Some(entry) = self.plan.entry(index)? else {
                break;
            };
            let mut sources = Vec::new();
            sources
                .try_reserve_exact(entry.sources().len())
                .map_err(|_| StorageError::AllocationFailed)?;
            for reference in entry.sources() {
                sources.push(source.read_source(reference)?);
            }
            let plaintext = transformer.transform(self.plan.kind(), &entry, &sources)?;
            validate_record_plaintext(
                entry.target_table(),
                entry.target_key(),
                entry.target_record_schema(),
                &plaintext,
            )?;
            let next_bytes = transformed_bytes
                .checked_add(plaintext.len())
                .ok_or(StorageError::Overflow)?;
            if next_bytes > self.limits.batch_bytes || next_bytes > MAX_CONSTRUCTION_BATCH_BYTES {
                if prepared.is_empty() {
                    return Err(StorageError::LimitExceeded);
                }
                break;
            }
            prepared.push((entry, plaintext));
            transformed_bytes = next_bytes;
        }
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
        (StorageConstructionCursor::BeforeFirst, Some(_)) if committed == 0 => Ok(()),
        (StorageConstructionCursor::AtTarget { table, key }, Some(entry))
            if *table == entry.target_table()
                && key.as_bytes() == entry.target_key().as_bytes() =>
        {
            Ok(())
        }
        (StorageConstructionCursor::Complete, None) if committed == plan.entry_count() => Ok(()),
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
    let channel = sources
        .iter()
        .find(|source| source.table() == TableId::Channel)
        .ok_or(StorageError::StaleState)?;
    let name = sources
        .iter()
        .find(|source| source.table() == TableId::ChannelName)
        .ok_or(StorageError::StaleState)?;
    let channel = PersistentRecordValue::decode(TableId::Channel, channel.plaintext())?;
    let name = PersistentRecordValue::decode(TableId::ChannelName, name.plaintext())?;
    let source_channel = sources
        .iter()
        .find(|source| source.table() == TableId::Channel)
        .ok_or(StorageError::StaleState)?;
    if channel.record_kind() != 1
        || name.record_kind() != 1
        || !name.references().iter().any(|reference| {
            reference.table() == TableId::Channel
                && reference.key().as_bytes() == source_channel.key().as_bytes()
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
    let (revision, generation) = match table {
        TableId::Account if value.record_kind() == 1 => (
            value
                .revision()
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
            value
                .generation()
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
        ),
        TableId::Channel if value.record_kind() == 1 => (
            value
                .revision()
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
            value.generation(),
        ),
        TableId::Account if value.record_kind() == 2 => (value.revision(), value.generation()),
        _ => return Err(StorageError::InvalidEncoding),
    };
    let references = if table == TableId::Channel && value.record_kind() == 1 {
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
    PersistentRecordValue::new(
        table,
        value.record_kind(),
        revision,
        generation,
        value.expires_at(),
        references,
        value.body().to_vec(),
    )?
    .encode()
}
