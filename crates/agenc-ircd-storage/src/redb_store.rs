//! Narrow redb adapter with fixed tables and mandatory durable commit settings.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Error as IoError;
use std::ops::Bound::{Excluded, Unbounded};
use std::os::unix::fs::FileExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use agenc_ircd_crypto::{StorageDigest, TrackedStateHasher, tracked_record_commitment};
use redb::{
    CommitError, Database, Durability, ReadTransaction, ReadableDatabase as _, ReadableTable as _,
    ReadableTableMetadata as _, StorageBackend, TableDefinition, TableHandle as _,
    WriteTransaction,
};
use rustix::fs::{AtFlags, unlinkat};

use crate::{
    IntegrityRecordMutation, IntegrityRecordVersion, MAX_SEALED_RECORD_BYTES, MAX_STORED_KEY_BYTES,
    RecordReference, StorageError, StorageFaultBoundary, StorageFaultInjector, StorageFaultSite,
    StoredKey, TableId,
};

const META_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("meta");
const RECOVERY_SCRATCH_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("recovery_versions");
const REFERENCE_RECORDS_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("reference_records");
const REFERENCES_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("record_references");
pub(crate) const HEADER_META_KEY: &[u8] = b"header/v1";
pub(crate) const RESERVATION_META_KEY: &[u8] = b"nonce-reservation/v1";
const STATE_META_RECORD_KEY: &[u8] = b"agenc-chat/state-meta/v1";

pub(crate) struct RedbStore {
    database: Database,
    faults: StorageFaultInjector,
    commit_flushes: Arc<CommitFlushCounter>,
}

/// Labels the durable flushes redb issues inside one two-phase transaction.
///
/// redb also syncs the file outside transactions: twice on creation, once when the first
/// writable transaction after open marks the header, after a repair, and at shutdown. Those
/// flushes are reported only as [`StorageFaultSite::DatabaseSync`]. The first and second flush
/// issued between [`Self::begin`] and [`Self::end`] are the two transaction phases.
#[derive(Debug, Default)]
struct CommitFlushCounter {
    in_transaction: AtomicBool,
    flushes: AtomicU8,
}

impl CommitFlushCounter {
    fn begin(&self) {
        self.flushes.store(0, Ordering::Release);
        self.in_transaction.store(true, Ordering::Release);
    }

    fn end(&self) {
        self.in_transaction.store(false, Ordering::Release);
    }

    fn next_phase_site(&self) -> Option<StorageFaultSite> {
        if !self.in_transaction.load(Ordering::Acquire) {
            return None;
        }
        let counted = self
            .flushes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |seen| {
                Some(seen.saturating_add(1))
            });
        match counted {
            Ok(0) => Some(StorageFaultSite::TransactionPhaseOne),
            Ok(1) => Some(StorageFaultSite::TransactionPhaseTwo),
            Ok(_) | Err(_) => None,
        }
    }
}

#[derive(Debug)]
struct FaultingFileBackend {
    file: File,
    faults: StorageFaultInjector,
    commit_flushes: Arc<CommitFlushCounter>,
}

impl FaultingFileBackend {
    fn new(
        file: File,
        faults: StorageFaultInjector,
        commit_flushes: Arc<CommitFlushCounter>,
    ) -> Self {
        Self {
            file,
            faults,
            commit_flushes,
        }
    }

    fn inject(
        &self,
        site: StorageFaultSite,
        boundary: StorageFaultBoundary,
    ) -> Result<(), IoError> {
        self.faults
            .check(site, boundary)
            .map_err(|_| IoError::other("injected storage qualification fault"))
    }
}

impl StorageBackend for FaultingFileBackend {
    fn len(&self) -> Result<u64, IoError> {
        self.file.metadata().map(|metadata| metadata.len())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), IoError> {
        self.inject(StorageFaultSite::RecordRead, StorageFaultBoundary::Before)?;
        self.file.read_exact_at(out, offset)?;
        self.inject(StorageFaultSite::RecordRead, StorageFaultBoundary::After)
    }

    fn set_len(&self, len: u64) -> Result<(), IoError> {
        self.inject(StorageFaultSite::Allocation, StorageFaultBoundary::Before)?;
        self.file.set_len(len)?;
        self.inject(StorageFaultSite::Allocation, StorageFaultBoundary::After)
    }

    fn sync_data(&self) -> Result<(), IoError> {
        let phase_site = self.commit_flushes.next_phase_site();
        if let Some(site) = phase_site {
            self.inject(site, StorageFaultBoundary::Before)?;
        }
        self.inject(StorageFaultSite::DatabaseSync, StorageFaultBoundary::Before)?;
        self.file.sync_data()?;
        self.inject(StorageFaultSite::DatabaseSync, StorageFaultBoundary::After)?;
        if let Some(site) = phase_site {
            self.inject(site, StorageFaultBoundary::After)?;
        }
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), IoError> {
        self.inject(StorageFaultSite::RecordWrite, StorageFaultBoundary::Before)?;
        self.file.write_all_at(data, offset)?;
        self.inject(StorageFaultSite::RecordWrite, StorageFaultBoundary::After)
    }
}

pub(crate) enum RedbCommitFailure {
    Rejected(StorageError),
    Indeterminate,
}

pub(crate) struct RedbWrite<'a> {
    pub(crate) table: TableId,
    pub(crate) key: &'a [u8],
    pub(crate) value: Option<&'a [u8]>,
}

type OwnedRow = (Vec<u8>, Vec<u8>);

pub(crate) struct SnapshotScan {
    transaction: ReadTransaction,
    next_table: u16,
    previous_key: Option<Vec<u8>>,
    complete: bool,
}

pub(crate) struct StorageSnapshot {
    transaction: ReadTransaction,
}

pub(crate) struct SnapshotSlice {
    pub(crate) rows: Vec<(TableId, Vec<u8>, Vec<u8>)>,
    pub(crate) complete: bool,
}

impl SnapshotScan {
    pub(crate) fn reset(&mut self) {
        self.next_table = 0;
        self.previous_key = None;
        self.complete = false;
    }

    pub(crate) fn next_tracked_slice(
        &mut self,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<SnapshotSlice, StorageError> {
        self.next_slice(maximum_records, maximum_bytes, true)
    }

    pub(crate) fn next_all_slice(
        &mut self,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<SnapshotSlice, StorageError> {
        self.next_slice(maximum_records, maximum_bytes, false)
    }

    // agenc-review: focus owner=storage reviewed=2026-08-28 reason=bounded canonical cursor state machine keeps table advancement and row budgets co-located
    fn next_slice(
        &mut self,
        maximum_records: usize,
        maximum_bytes: usize,
        tracked_only: bool,
    ) -> Result<SnapshotSlice, StorageError> {
        if maximum_records == 0 || maximum_bytes == 0 {
            return Err(StorageError::LimitExceeded);
        }
        if self.complete {
            return Ok(SnapshotSlice {
                rows: Vec::new(),
                complete: true,
            });
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(maximum_records)
            .map_err(|_| StorageError::AllocationFailed)?;
        let mut bytes = 0_usize;
        while self.next_table <= 26 {
            let table_id = TableId::from_u16(self.next_table)?;
            if tracked_only && !table_id.is_integrity_tracked() {
                self.advance_table()?;
                continue;
            }
            let table = self
                .transaction
                .open_table(table_definition(table_id))
                .map_err(|_| StorageError::DatabaseRejected)?;
            let mut exhausted = true;
            let range = match self.previous_key.as_deref() {
                Some(previous) => table.range::<&[u8]>((Excluded(previous), Unbounded)),
                None => {
                    let bounds: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>) =
                        (Unbounded, Unbounded);
                    table.range::<&[u8]>(bounds)
                }
            }
            .map_err(|_| StorageError::DatabaseRejected)?;
            for entry in range {
                let (key, value) = entry.map_err(|_| StorageError::DatabaseRejected)?;
                let row_bytes = key
                    .value()
                    .len()
                    .checked_add(value.value().len())
                    .ok_or(StorageError::Overflow)?;
                let next_bytes = bytes.checked_add(row_bytes).ok_or(StorageError::Overflow)?;
                if !rows.is_empty() && next_bytes > maximum_bytes {
                    exhausted = false;
                    break;
                }
                validate_row_shape(key.value(), value.value())?;
                let key = key.value().to_vec();
                let value = value.value().to_vec();
                bytes = next_bytes;
                self.previous_key = Some(key.clone());
                rows.push((table_id, key, value));
                if rows.len() == maximum_records || bytes >= maximum_bytes {
                    exhausted = false;
                    break;
                }
            }
            if !exhausted {
                return Ok(SnapshotSlice {
                    rows,
                    complete: false,
                });
            }
            self.advance_table()?;
            if !rows.is_empty() {
                return Ok(SnapshotSlice {
                    rows,
                    complete: false,
                });
            }
        }
        self.complete = true;
        Ok(SnapshotSlice {
            rows,
            complete: true,
        })
    }

    fn advance_table(&mut self) -> Result<(), StorageError> {
        self.next_table = self
            .next_table
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        self.previous_key = None;
        Ok(())
    }
}

impl StorageSnapshot {
    pub(crate) fn visit_table<F>(
        &self,
        table: TableId,
        maximum_bytes: u64,
        mut visitor: F,
    ) -> Result<u64, StorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
    {
        let table = self
            .transaction
            .open_table(table_definition(table))
            .map_err(|_| StorageError::DatabaseRejected)?;
        let iterator = table.iter().map_err(|_| StorageError::DatabaseRejected)?;
        let mut bytes_seen = 0_u64;
        for entry in iterator {
            let (key, value) = entry.map_err(|_| StorageError::DatabaseRejected)?;
            let row_bytes = key
                .value()
                .len()
                .checked_add(value.value().len())
                .ok_or(StorageError::Overflow)?;
            bytes_seen = bytes_seen
                .checked_add(u64::try_from(row_bytes).map_err(|_| StorageError::Overflow)?)
                .ok_or(StorageError::Overflow)?;
            if bytes_seen > maximum_bytes {
                return Err(StorageError::LimitExceeded);
            }
            visitor(key.value(), value.value())?;
        }
        Ok(bytes_seen)
    }
}

pub(crate) struct RecoveryScratch {
    database: Database,
    directory: File,
    temporary_name: String,
}

pub(crate) struct RecoveryScratchWriter {
    transaction: WriteTransaction,
}

pub(crate) struct ReferenceScratch {
    database: Database,
    directory: File,
    temporary_name: String,
}

pub(crate) struct ReferenceScratchWriter {
    transaction: WriteTransaction,
}

impl ReferenceScratch {
    pub(crate) fn create(
        file: File,
        directory: File,
        temporary_name: String,
    ) -> Result<Self, StorageError> {
        let mut builder = redb::Builder::new();
        builder.set_cache_size(8 * 1_024 * 1_024);
        let database = builder
            .create_file(file)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let transaction = database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let _records = transaction
                .open_table(REFERENCE_RECORDS_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            let _references = transaction
                .open_table(REFERENCES_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;
        Ok(Self {
            database,
            directory,
            temporary_name,
        })
    }

    pub(crate) fn begin(&self) -> Result<ReferenceScratchWriter, StorageError> {
        Ok(ReferenceScratchWriter {
            transaction: self
                .database
                .begin_write()
                .map_err(|_| StorageError::DatabaseRejected)?,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), StorageError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let records = transaction
            .open_table(REFERENCE_RECORDS_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let references = transaction
            .open_table(REFERENCES_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        for entry in references
            .iter()
            .map_err(|_| StorageError::DatabaseRejected)?
        {
            let (_, target) = entry.map_err(|_| StorageError::DatabaseRejected)?;
            if records
                .get(target.value())
                .map_err(|_| StorageError::DatabaseRejected)?
                .is_none()
            {
                return Err(StorageError::StaleState);
            }
        }
        Ok(())
    }
}

impl Drop for ReferenceScratch {
    fn drop(&mut self) {
        let _ = unlinkat(
            &self.directory,
            self.temporary_name.as_str(),
            AtFlags::empty(),
        );
    }
}

impl ReferenceScratchWriter {
    pub(crate) fn insert(
        &mut self,
        table: TableId,
        stored_key: &StoredKey,
        references: &[RecordReference],
    ) -> Result<(), StorageError> {
        let identity = scratch_key(table, stored_key)?;
        {
            let empty: &[u8] = &[];
            let mut records = self
                .transaction
                .open_table(REFERENCE_RECORDS_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            if records
                .insert(identity.as_slice(), empty)
                .map_err(|_| StorageError::DatabaseRejected)?
                .is_some()
            {
                return Err(StorageError::StaleState);
            }
        }
        let mut table = self
            .transaction
            .open_table(REFERENCES_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        for (index, reference) in references.iter().enumerate() {
            let mut reference_key = identity.clone();
            reference_key.extend_from_slice(
                &u32::try_from(index)
                    .map_err(|_| StorageError::Overflow)?
                    .to_be_bytes(),
            );
            let target = scratch_key(reference.table(), reference.key())?;
            table
                .insert(reference_key.as_slice(), target.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        Ok(())
    }

    pub(crate) fn commit(self) -> Result<(), StorageError> {
        self.transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)
    }
}

impl RecoveryScratch {
    pub(crate) fn create(
        file: File,
        directory: File,
        temporary_name: String,
    ) -> Result<Self, StorageError> {
        let mut builder = redb::Builder::new();
        builder.set_cache_size(8 * 1_024 * 1_024);
        let database = builder
            .create_file(file)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let transaction = database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let _table = transaction
                .open_table(RECOVERY_SCRATCH_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;
        Ok(Self {
            database,
            directory,
            temporary_name,
        })
    }

    pub(crate) fn begin_current(&self) -> Result<RecoveryScratchWriter, StorageError> {
        Ok(RecoveryScratchWriter {
            transaction: self
                .database
                .begin_write()
                .map_err(|_| StorageError::DatabaseRejected)?,
        })
    }

    // agenc-review: focus owner=storage reviewed=2026-08-27 reason=reverse manifest application keeps exact after-before scratch transitions in one transaction
    pub(crate) fn apply_reverse(
        &self,
        mutations: &[IntegrityRecordMutation],
    ) -> Result<(), StorageError> {
        let transaction = self
            .database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let mut table = transaction
                .open_table(RECOVERY_SCRATCH_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            for mutation in mutations.iter().rev() {
                let key = scratch_key(mutation.table(), mutation.stored_key())?;
                let current = table
                    .get(key.as_slice())
                    .map_err(|_| StorageError::DatabaseRejected)?
                    .map(|value| decode_present_version(value.value()))
                    .transpose()?;
                let current = current.unwrap_or(IntegrityRecordVersion::Absent);
                if current != mutation.after() {
                    return Err(StorageError::StaleState);
                }
                match encode_present_version(mutation.before())? {
                    Some(value) => {
                        table
                            .insert(key.as_slice(), value.as_slice())
                            .map_err(|_| StorageError::DatabaseRejected)?;
                    }
                    None => {
                        table
                            .remove(key.as_slice())
                            .map_err(|_| StorageError::DatabaseRejected)?;
                    }
                }
            }
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)
    }

    pub(crate) fn digest(&self) -> Result<(u64, StorageDigest), StorageError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let table = transaction
            .open_table(RECOVERY_SCRATCH_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let record_count = table.len().map_err(|_| StorageError::DatabaseRejected)?;
        let mut hasher = TrackedStateHasher::new(record_count);
        for entry in table.iter().map_err(|_| StorageError::DatabaseRejected)? {
            let (key, value) = entry.map_err(|_| StorageError::DatabaseRejected)?;
            let (table_id, stored_key) = decode_scratch_key(key.value())?;
            let version = decode_present_version(value.value())?;
            let IntegrityRecordVersion::Present {
                record_schema,
                sealed_record_id,
            } = version
            else {
                return Err(StorageError::InvalidEncoding);
            };
            let tuple = commitment_tuple(table_id, &stored_key, record_schema, sealed_record_id)?;
            hasher.update(tracked_record_commitment(&tuple)?)?;
        }
        Ok((record_count, hasher.finalize()?))
    }
}

impl Drop for RecoveryScratch {
    fn drop(&mut self) {
        let _ = unlinkat(
            &self.directory,
            self.temporary_name.as_str(),
            AtFlags::empty(),
        );
    }
}

impl RecoveryScratchWriter {
    pub(crate) fn insert_current(
        &mut self,
        table_id: TableId,
        stored_key: &StoredKey,
        record_schema: u32,
        sealed_record_id: StorageDigest,
    ) -> Result<(), StorageError> {
        let key = scratch_key(table_id, stored_key)?;
        let value = encode_present_version(IntegrityRecordVersion::Present {
            record_schema,
            sealed_record_id,
        })?
        .ok_or(StorageError::InvalidEncoding)?;
        let mut table = self
            .transaction
            .open_table(RECOVERY_SCRATCH_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        if table
            .insert(key.as_slice(), value.as_slice())
            .map_err(|_| StorageError::DatabaseRejected)?
            .is_some()
        {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    pub(crate) fn commit(self) -> Result<(), StorageError> {
        self.transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)
    }
}

fn scratch_key(table: TableId, stored_key: &StoredKey) -> Result<Vec<u8>, StorageError> {
    let capacity = 2_usize
        .checked_add(stored_key.as_bytes().len())
        .ok_or(StorageError::Overflow)?;
    let mut key = Vec::new();
    key.try_reserve_exact(capacity)
        .map_err(|_| StorageError::AllocationFailed)?;
    key.extend_from_slice(&table.as_u16().to_be_bytes());
    key.extend_from_slice(stored_key.as_bytes());
    Ok(key)
}

fn decode_scratch_key(encoded: &[u8]) -> Result<(TableId, StoredKey), StorageError> {
    let table_bytes: [u8; 2] = encoded
        .get(..2)
        .ok_or(StorageError::InvalidEncoding)?
        .try_into()
        .map_err(|_| StorageError::InvalidEncoding)?;
    let table = TableId::from_u16(u16::from_be_bytes(table_bytes))?;
    let key = StoredKey::new(
        encoded
            .get(2..)
            .ok_or(StorageError::InvalidEncoding)?
            .to_vec(),
    )?;
    if !table.is_integrity_tracked() {
        return Err(StorageError::InvalidEncoding);
    }
    Ok((table, key))
}

fn encode_present_version(
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
    encoded
        .get_mut(..4)
        .ok_or(StorageError::InvalidEncoding)?
        .copy_from_slice(&record_schema.to_be_bytes());
    encoded
        .get_mut(4..)
        .ok_or(StorageError::InvalidEncoding)?
        .copy_from_slice(sealed_record_id.as_bytes());
    Ok(Some(encoded))
}

fn decode_present_version(encoded: &[u8]) -> Result<IntegrityRecordVersion, StorageError> {
    if encoded.len() != 36 {
        return Err(StorageError::InvalidEncoding);
    }
    let schema = u32::from_be_bytes(
        encoded
            .get(..4)
            .ok_or(StorageError::InvalidEncoding)?
            .try_into()
            .map_err(|_| StorageError::InvalidEncoding)?,
    );
    let identifier = StorageDigest::from_bytes(
        encoded
            .get(4..)
            .ok_or(StorageError::InvalidEncoding)?
            .try_into()
            .map_err(|_| StorageError::InvalidEncoding)?,
    );
    if schema == 0 {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(IntegrityRecordVersion::Present {
        record_schema: schema,
        sealed_record_id: identifier,
    })
}

fn commitment_tuple(
    table: TableId,
    stored_key: &StoredKey,
    record_schema: u32,
    sealed_record_id: StorageDigest,
) -> Result<Vec<u8>, StorageError> {
    let capacity = 42_usize
        .checked_add(stored_key.as_bytes().len())
        .ok_or(StorageError::Overflow)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(capacity)
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

impl RedbStore {
    pub(crate) fn open_with_faults(
        file: File,
        cache_bytes: usize,
        faults: StorageFaultInjector,
    ) -> Result<Self, StorageError> {
        if cache_bytes == 0 {
            return Err(StorageError::LimitExceeded);
        }
        let mut builder = redb::Builder::new();
        builder.set_cache_size(cache_bytes);
        let commit_flushes = Arc::new(CommitFlushCounter::default());
        let database = if faults.is_enabled() {
            builder
                .create_with_backend(FaultingFileBackend::new(
                    file,
                    faults.clone(),
                    Arc::clone(&commit_flushes),
                ))
                .map_err(|_| StorageError::DatabaseRejected)?
        } else {
            builder
                .create_file(file)
                .map_err(|_| StorageError::DatabaseRejected)?
        };
        Ok(Self {
            database,
            faults,
            commit_flushes,
        })
    }

    pub(crate) fn snapshot_scan(&self) -> Result<SnapshotScan, StorageError> {
        Ok(SnapshotScan {
            transaction: self
                .database
                .begin_read()
                .map_err(|_| StorageError::DatabaseRejected)?,
            next_table: 0,
            previous_key: None,
            complete: false,
        })
    }

    pub(crate) fn snapshot(&self) -> Result<StorageSnapshot, StorageError> {
        Ok(StorageSnapshot {
            transaction: self
                .database
                .begin_read()
                .map_err(|_| StorageError::DatabaseRejected)?,
        })
    }

    pub(crate) fn read_meta(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let table = transaction
            .open_table(META_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let value = table.get(key).map_err(|_| StorageError::DatabaseRejected)?;
        Ok(value.map(|guard| guard.value().to_vec()))
    }

    pub(crate) fn validate_meta_membership(&self) -> Result<(), StorageError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let table = transaction
            .open_table(META_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let mut header_seen = false;
        let mut reservation_seen = false;
        let mut count = 0_u8;
        for entry in table.iter().map_err(|_| StorageError::DatabaseRejected)? {
            let (key, _) = entry.map_err(|_| StorageError::DatabaseRejected)?;
            count = count.checked_add(1).ok_or(StorageError::Overflow)?;
            match key.value() {
                HEADER_META_KEY if !header_seen => header_seen = true,
                RESERVATION_META_KEY if !reservation_seen => reservation_seen = true,
                _ => return Err(StorageError::InvalidEncoding),
            }
        }
        if count != 2 || !header_seen || !reservation_seen {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    pub(crate) fn read_record(
        &self,
        table: TableId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let table = transaction
            .open_table(table_definition(table))
            .map_err(|_| StorageError::DatabaseRejected)?;
        let value = table.get(key).map_err(|_| StorageError::DatabaseRejected)?;
        value
            .map(|guard| {
                validate_row_shape(key, guard.value())?;
                Ok(guard.value().to_vec())
            })
            .transpose()
    }

    pub(crate) fn read_range(
        &self,
        table: TableId,
        start: &[u8],
        end: &[u8],
        limit: usize,
    ) -> Result<Vec<OwnedRow>, StorageError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let table = transaction
            .open_table(table_definition(table))
            .map_err(|_| StorageError::DatabaseRejected)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(limit)
            .map_err(|_| StorageError::AllocationFailed)?;
        let range = table
            .range(start..end)
            .map_err(|_| StorageError::DatabaseRejected)?;
        for entry in range.take(limit) {
            let (key, value) = entry.map_err(|_| StorageError::DatabaseRejected)?;
            validate_row_shape(key.value(), value.value())?;
            rows.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(rows)
    }

    pub(crate) fn visit_table<F>(
        &self,
        table: TableId,
        maximum_bytes: u64,
        visitor: F,
    ) -> Result<u64, StorageError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
    {
        self.snapshot()?.visit_table(table, maximum_bytes, visitor)
    }

    pub(crate) fn table_usage(
        &self,
        table: TableId,
        maximum_bytes: u64,
    ) -> Result<(u64, u64), StorageError> {
        let mut records = 0_u64;
        let bytes = self.visit_table(table, maximum_bytes, |_key, _value| {
            records = records.checked_add(1).ok_or(StorageError::Overflow)?;
            Ok(())
        })?;
        Ok((records, bytes))
    }

    pub(crate) fn validate_inventory(&self) -> Result<(), StorageError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let actual = transaction
            .list_tables()
            .map_err(|_| StorageError::DatabaseRejected)?
            .map(|table| table.name().to_owned())
            .collect::<BTreeSet<_>>();
        let mut expected = BTreeSet::new();
        expected.insert("meta".to_owned());
        for number in 0_u16..=26 {
            expected.insert(TableId::from_u16(number)?.name().to_owned());
        }
        if actual != expected {
            return Err(StorageError::InvalidEncoding);
        }
        let multimaps = transaction
            .list_multimap_tables()
            .map_err(|_| StorageError::DatabaseRejected)?
            .count();
        if multimaps != 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    pub(crate) fn write_meta(&self, key: &[u8], value: &[u8]) -> Result<(), RedbCommitFailure> {
        let transaction = self.begin_durable_write()?;
        {
            let mut table = transaction.open_table(META_TABLE).map_err(rejected_table)?;
            table.insert(key, value).map_err(rejected_storage)?;
        }
        self.finish_transaction(transaction)
    }

    pub(crate) fn initialize_database(
        &self,
        header: &[u8],
        reservation: &[u8],
        writes: &[RedbWrite<'_>],
    ) -> Result<(), RedbCommitFailure> {
        let transaction = self.begin_durable_write()?;
        {
            let mut meta = transaction.open_table(META_TABLE).map_err(rejected_table)?;
            meta.insert(HEADER_META_KEY, header)
                .map_err(rejected_storage)?;
            meta.insert(RESERVATION_META_KEY, reservation)
                .map_err(rejected_storage)?;
        }
        for number in 0_u16..=26 {
            let table = TableId::from_u16(number).map_err(RedbCommitFailure::Rejected)?;
            {
                let _created = transaction
                    .open_table(table_definition(table))
                    .map_err(rejected_table)?;
            }
        }
        for write in writes {
            let Some(value) = write.value else {
                return Err(RedbCommitFailure::Rejected(StorageError::InvalidEncoding));
            };
            let mut table = transaction
                .open_table(table_definition(write.table))
                .map_err(rejected_table)?;
            table.insert(write.key, value).map_err(rejected_storage)?;
        }
        self.finish_transaction(transaction)
    }

    pub(crate) fn commit_records(
        &self,
        writes: &[RedbWrite<'_>],
        reservation: &[u8],
    ) -> Result<(), RedbCommitFailure> {
        let transaction = self.begin_durable_write()?;
        for write in writes {
            let mut table = transaction
                .open_table(table_definition(write.table))
                .map_err(rejected_table)?;
            if let Some(value) = write.value {
                table.insert(write.key, value).map_err(rejected_storage)?;
            } else {
                table.remove(write.key).map_err(rejected_storage)?;
            }
        }
        {
            let mut meta = transaction.open_table(META_TABLE).map_err(rejected_table)?;
            meta.insert(RESERVATION_META_KEY, reservation)
                .map_err(rejected_storage)?;
        }
        self.finish_transaction(transaction)
    }

    pub(crate) fn commit_checkpoint(
        &self,
        checkpoint_key: &[u8; 8],
        checkpoint_record: &[u8],
        previous_checkpoint_key: &[u8; 8],
        state_meta_record: &[u8],
        reservation: &[u8],
    ) -> Result<(), RedbCommitFailure> {
        let transaction = self.begin_durable_write()?;
        {
            let mut checkpoints = transaction
                .open_table(table_definition(TableId::IntegrityCheckpoint))
                .map_err(rejected_table)?;
            checkpoints
                .insert(checkpoint_key.as_slice(), checkpoint_record)
                .map_err(rejected_storage)?;
            checkpoints
                .retain(|key, _| {
                    key == checkpoint_key.as_slice() || key == previous_checkpoint_key.as_slice()
                })
                .map_err(rejected_storage)?;
        }
        {
            let mut manifests = transaction
                .open_table(table_definition(TableId::IntegrityManifest))
                .map_err(rejected_table)?;
            manifests
                .retain(|key, _| key > checkpoint_key.as_slice())
                .map_err(rejected_storage)?;
        }
        {
            let mut state_meta = transaction
                .open_table(table_definition(TableId::StateMeta))
                .map_err(rejected_table)?;
            state_meta
                .insert(STATE_META_RECORD_KEY, state_meta_record)
                .map_err(rejected_storage)?;
        }
        {
            let mut meta = transaction.open_table(META_TABLE).map_err(rejected_table)?;
            meta.insert(RESERVATION_META_KEY, reservation)
                .map_err(rejected_storage)?;
        }
        self.finish_transaction(transaction)
    }

    fn begin_durable_write(&self) -> Result<WriteTransaction, RedbCommitFailure> {
        self.faults
            .check(
                StorageFaultSite::TransactionBegin,
                StorageFaultBoundary::Before,
            )
            .map_err(RedbCommitFailure::Rejected)?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| RedbCommitFailure::Rejected(StorageError::DatabaseRejected))?;
        self.faults
            .check(
                StorageFaultSite::TransactionBegin,
                StorageFaultBoundary::After,
            )
            .map_err(RedbCommitFailure::Rejected)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| RedbCommitFailure::Rejected(StorageError::DatabaseRejected))?;
        transaction.set_two_phase_commit(true);
        Ok(transaction)
    }
}

fn table_definition(table: TableId) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
    TableDefinition::new(table.name())
}

fn rejected_table(_error: redb::TableError) -> RedbCommitFailure {
    RedbCommitFailure::Rejected(StorageError::DatabaseRejected)
}

fn rejected_storage(_error: redb::StorageError) -> RedbCommitFailure {
    RedbCommitFailure::Rejected(StorageError::DatabaseRejected)
}

impl RedbStore {
    /// Runs the durable two-phase completion with its flushes labeled as transaction phases.
    fn finish_transaction(&self, transaction: WriteTransaction) -> Result<(), RedbCommitFailure> {
        self.commit_flushes.begin();
        let result = transaction.commit();
        self.commit_flushes.end();
        match result {
            Ok(()) => Ok(()),
            Err(CommitError::TransactionPoisoned) => {
                Err(RedbCommitFailure::Rejected(StorageError::DatabaseRejected))
            }
            Err(CommitError::Storage(_)) => Err(RedbCommitFailure::Indeterminate),
            Err(_) => Err(RedbCommitFailure::Indeterminate),
        }
    }
}

/// Rejects a stored row whose key or value exceeds the schema ceilings before it is copied.
///
/// Every legitimate row was bounded when it was written, so an oversized row can only come from
/// a tampered file; copying it first would let that file drive the allocation.
fn validate_row_shape(key: &[u8], value: &[u8]) -> Result<(), StorageError> {
    if (
        key.len() > MAX_STORED_KEY_BYTES,
        value.len() > MAX_SEALED_RECORD_BYTES,
    ) != (false, false)
    {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use redb::MultimapTableDefinition;

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create(label: &str) -> Result<Self, StorageError> {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agenc-redb-store-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).map_err(|_| StorageError::DatabaseRejected)?;
            Ok(Self { path })
        }

        fn create_file(&self, name: &str) -> Result<File, StorageError> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(self.path.join(name))
                .map_err(|_| StorageError::DatabaseRejected)
        }

        fn open_directory(&self) -> Result<File, StorageError> {
            File::open(&self.path).map_err(|_| StorageError::DatabaseRejected)
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn open_store(label: &str) -> Result<(TestDirectory, RedbStore), StorageError> {
        let directory = TestDirectory::create(label)?;
        let file = directory.create_file("state.redb")?;
        let store = RedbStore::open_with_faults(file, 1_048_576, StorageFaultInjector::disabled())?;
        Ok((directory, store))
    }

    fn initialize(store: &RedbStore, writes: &[RedbWrite<'_>]) -> Result<(), StorageError> {
        store
            .initialize_database(b"header", b"reservation", writes)
            .map_err(|failure| match failure {
                RedbCommitFailure::Rejected(error) => error,
                RedbCommitFailure::Indeterminate => StorageError::DatabaseRejected,
            })
    }

    fn scratch(
        directory: &TestDirectory,
        name: &str,
    ) -> Result<(File, File, String), StorageError> {
        Ok((
            directory.create_file(name)?,
            directory.open_directory()?,
            name.to_owned(),
        ))
    }

    #[test]
    fn version_and_scratch_key_codecs_reject_invalid_forms() -> Result<(), StorageError> {
        let digest = StorageDigest::from_bytes([7_u8; 32]);
        let present = IntegrityRecordVersion::Present {
            record_schema: 3,
            sealed_record_id: digest,
        };
        let encoded = encode_present_version(present)?.ok_or(StorageError::InvalidEncoding)?;
        assert_eq!(decode_present_version(&encoded)?, present);
        assert_eq!(
            encode_present_version(IntegrityRecordVersion::Absent)?,
            None
        );
        assert_eq!(
            encode_present_version(IntegrityRecordVersion::Present {
                record_schema: 0,
                sealed_record_id: digest,
            }),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            decode_present_version(&encoded[..35]),
            Err(StorageError::InvalidEncoding)
        );
        let mut zero_schema = encoded;
        zero_schema[..4].fill(0);
        assert_eq!(
            decode_present_version(&zero_schema),
            Err(StorageError::InvalidEncoding)
        );

        let stored_key = StoredKey::new(vec![9_u8; 32])?;
        let key = scratch_key(TableId::E2eeObject, &stored_key)?;
        let (decoded_table, decoded_key) = decode_scratch_key(&key)?;
        assert_eq!(decoded_table, TableId::E2eeObject);
        assert!(decoded_key == stored_key);
        assert!(matches!(
            decode_scratch_key(&[0]),
            Err(StorageError::InvalidEncoding)
        ));
        let untracked = scratch_key(TableId::KeyCheck, &StoredKey::new(vec![1])?)?;
        assert!(matches!(
            decode_scratch_key(&untracked),
            Err(StorageError::InvalidEncoding)
        ));
        Ok(())
    }

    #[test]
    fn reference_scratch_detects_duplicates_and_missing_targets() -> Result<(), StorageError> {
        let directory = TestDirectory::create("references")?;
        let (file, parent, name) = scratch(&directory, "references.redb")?;
        let scratch = ReferenceScratch::create(file, parent, name)?;
        let source_key = StoredKey::new(vec![1_u8; 32])?;
        let target_key = StoredKey::new(vec![2_u8; 32])?;
        let target = RecordReference::new(TableId::E2eeObject, target_key.clone())?;

        let mut writer = scratch.begin()?;
        writer.insert(
            TableId::E2eeObject,
            &source_key,
            std::slice::from_ref(&target),
        )?;
        assert_eq!(
            writer.insert(TableId::E2eeObject, &source_key, &[]),
            Err(StorageError::StaleState)
        );
        writer.commit()?;
        assert_eq!(scratch.validate(), Err(StorageError::StaleState));

        let mut writer = scratch.begin()?;
        writer.insert(TableId::E2eeObject, &target_key, &[])?;
        writer.commit()?;
        scratch.validate()?;
        drop(scratch);
        assert!(!directory.path().join("references.redb").exists());
        Ok(())
    }

    #[test]
    fn recovery_scratch_validates_versions_and_reverse_transitions() -> Result<(), StorageError> {
        let directory = TestDirectory::create("recovery")?;
        let (file, parent, name) = scratch(&directory, "recovery.redb")?;
        let scratch = RecoveryScratch::create(file, parent, name)?;
        let stored_key = StoredKey::new(vec![3_u8; 32])?;
        let digest = StorageDigest::from_bytes([4_u8; 32]);
        let present = IntegrityRecordVersion::Present {
            record_schema: 1,
            sealed_record_id: digest,
        };

        let mut writer = scratch.begin_current()?;
        writer.insert_current(TableId::E2eeObject, &stored_key, 1, digest)?;
        assert_eq!(
            writer.insert_current(TableId::E2eeObject, &stored_key, 1, digest),
            Err(StorageError::StaleState)
        );
        writer.commit()?;
        assert_eq!(scratch.digest()?.0, 1);

        let mismatch = IntegrityRecordMutation::new(
            TableId::E2eeObject,
            stored_key.clone(),
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Present {
                record_schema: 2,
                sealed_record_id: digest,
            },
        )?;
        assert_eq!(
            scratch.apply_reverse(&[mismatch]),
            Err(StorageError::StaleState)
        );

        let mutation = IntegrityRecordMutation::new(
            TableId::E2eeObject,
            stored_key,
            IntegrityRecordVersion::Absent,
            present,
        )?;
        scratch.apply_reverse(&[mutation])?;
        assert_eq!(scratch.digest()?.0, 0);
        Ok(())
    }

    #[test]
    fn recovery_digest_rejects_malformed_scratch_rows() -> Result<(), StorageError> {
        let directory = TestDirectory::create("malformed-recovery")?;
        let (file, parent, name) = scratch(&directory, "recovery.redb")?;
        let scratch = RecoveryScratch::create(file, parent, name)?;
        let transaction = scratch
            .database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let mut table = transaction
                .open_table(RECOVERY_SCRATCH_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            table
                .insert(&[0_u8, 0, 1][..], &[0_u8; 36][..])
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;
        assert_eq!(scratch.digest(), Err(StorageError::InvalidEncoding));
        Ok(())
    }

    #[test]
    fn snapshot_scans_are_bounded_resettable_and_table_aware() -> Result<(), StorageError> {
        let (_directory, store) = open_store("snapshot")?;
        let first_key = [1_u8; 32];
        let second_key = [2_u8; 32];
        let writes = [
            RedbWrite {
                table: TableId::KeyCheck,
                key: b"control",
                value: Some(b"value"),
            },
            RedbWrite {
                table: TableId::E2eeObject,
                key: &first_key,
                value: Some(b"a"),
            },
            RedbWrite {
                table: TableId::E2eeObject,
                key: &second_key,
                value: Some(b"b"),
            },
        ];
        initialize(&store, &writes)?;

        let mut scan = store.snapshot_scan()?;
        assert!(matches!(
            scan.next_all_slice(0, 1),
            Err(StorageError::LimitExceeded)
        ));
        assert!(matches!(
            scan.next_all_slice(1, 0),
            Err(StorageError::LimitExceeded)
        ));
        let first = scan.next_tracked_slice(10, 40)?;
        assert_eq!(first.rows.len(), 1);
        assert!(!first.complete);
        let second = scan.next_tracked_slice(10, 40)?;
        assert_eq!(second.rows.len(), 1);
        while !scan.next_tracked_slice(10, 40)?.complete {}
        assert!(scan.next_tracked_slice(10, 40)?.complete);

        scan.reset();
        let control = scan.next_all_slice(1, usize::MAX)?;
        assert_eq!(
            control.rows.first().map(|row| row.0),
            Some(TableId::KeyCheck)
        );
        Ok(())
    }

    #[test]
    fn snapshot_scans_stop_at_exact_byte_and_next_row_boundaries() -> Result<(), StorageError> {
        let (_directory, store) = open_store("snapshot-byte-boundaries")?;
        let first_key = [1_u8; 32];
        let second_key = [2_u8; 32];
        initialize(
            &store,
            &[
                RedbWrite {
                    table: TableId::E2eeObject,
                    key: &first_key,
                    value: Some(b"a"),
                },
                RedbWrite {
                    table: TableId::E2eeObject,
                    key: &second_key,
                    value: Some(b"b"),
                },
            ],
        )?;

        let mut exact = store.snapshot_scan()?;
        let exact_slice = exact.next_tracked_slice(10, 33)?;
        assert_eq!(exact_slice.rows.len(), 1);
        assert!(!exact_slice.complete);

        let mut next_row = store.snapshot_scan()?;
        let next_row_slice = next_row.next_tracked_slice(10, 34)?;
        assert_eq!(next_row_slice.rows.len(), 1);
        assert!(!next_row_slice.complete);
        Ok(())
    }

    #[test]
    fn snapshots_and_store_visitors_enforce_byte_limits_and_errors() -> Result<(), StorageError> {
        let (_directory, store) = open_store("visitors")?;
        let key = [5_u8; 32];
        initialize(
            &store,
            &[RedbWrite {
                table: TableId::E2eeObject,
                key: &key,
                value: Some(b"payload"),
            }],
        )?;

        let snapshot = store.snapshot()?;
        assert_eq!(
            snapshot.visit_table(TableId::E2eeObject, 1, |_key, _value| Ok(())),
            Err(StorageError::LimitExceeded)
        );
        assert_eq!(
            store.visit_table(TableId::E2eeObject, u64::MAX, |_key, _value| {
                Err(StorageError::StaleState)
            }),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            store.visit_table(TableId::E2eeObject, 1, |_key, _value| Ok(())),
            Err(StorageError::LimitExceeded)
        );
        assert_eq!(store.table_usage(TableId::E2eeObject, u64::MAX)?, (1, 39));
        Ok(())
    }

    #[test]
    fn initialization_and_inventory_reject_invalid_database_shapes() -> Result<(), StorageError> {
        let (_directory, store) = open_store("inventory-extra-table")?;
        let rejected = store.initialize_database(
            b"header",
            b"reservation",
            &[RedbWrite {
                table: TableId::E2eeObject,
                key: b"key",
                value: None,
            }],
        );
        assert!(matches!(
            rejected,
            Err(RedbCommitFailure::Rejected(StorageError::InvalidEncoding))
        ));
        initialize(&store, &[])?;
        store.validate_inventory()?;
        store.validate_meta_membership()?;
        store
            .write_meta(b"unexpected", b"value")
            .map_err(|failure| match failure {
                RedbCommitFailure::Rejected(error) => error,
                RedbCommitFailure::Indeterminate => StorageError::DatabaseRejected,
            })?;
        assert_eq!(
            store.validate_meta_membership(),
            Err(StorageError::InvalidEncoding)
        );

        let transaction = store
            .database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let extra: TableDefinition<'static, &'static [u8], &'static [u8]> =
                TableDefinition::new("unexpected");
            let _table = transaction
                .open_table(extra)
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;
        assert_eq!(
            store.validate_inventory(),
            Err(StorageError::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn inventory_rejects_multimap_tables() -> Result<(), StorageError> {
        let (_directory, store) = open_store("inventory-multimap")?;
        initialize(&store, &[])?;
        let transaction = store
            .database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let definition: MultimapTableDefinition<'static, &'static [u8], &'static [u8]> =
                MultimapTableDefinition::new("unexpected-multimap");
            let _table = transaction
                .open_multimap_table(definition)
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;
        assert_eq!(
            store.validate_inventory(),
            Err(StorageError::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn record_commits_cover_insert_replace_and_delete() -> Result<(), StorageError> {
        let (_directory, store) = open_store("record-commits")?;
        initialize(&store, &[])?;
        let key = [8_u8; 32];
        store
            .commit_records(
                &[RedbWrite {
                    table: TableId::E2eeObject,
                    key: &key,
                    value: Some(b"first"),
                }],
                b"reservation-2",
            )
            .map_err(|failure| match failure {
                RedbCommitFailure::Rejected(error) => error,
                RedbCommitFailure::Indeterminate => StorageError::DatabaseRejected,
            })?;
        assert_eq!(
            store.read_record(TableId::E2eeObject, &key)?,
            Some(b"first".to_vec())
        );
        store
            .commit_records(
                &[RedbWrite {
                    table: TableId::E2eeObject,
                    key: &key,
                    value: None,
                }],
                b"reservation-3",
            )
            .map_err(|failure| match failure {
                RedbCommitFailure::Rejected(error) => error,
                RedbCommitFailure::Indeterminate => StorageError::DatabaseRejected,
            })?;
        assert_eq!(store.read_record(TableId::E2eeObject, &key)?, None);
        assert_eq!(
            store.read_meta(RESERVATION_META_KEY)?,
            Some(b"reservation-3".to_vec())
        );
        Ok(())
    }

    #[test]
    fn oversized_rows_are_rejected_before_any_read_path_copies_them() -> Result<(), StorageError> {
        let (_directory, store) = open_store("oversized-rows")?;
        initialize(&store, &[])?;
        let key = [9_u8; 32];
        let oversized = vec![0_u8; MAX_SEALED_RECORD_BYTES + 1];
        let transaction = store
            .database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let mut table = transaction
                .open_table(table_definition(TableId::E2eeObject))
                .map_err(|_| StorageError::DatabaseRejected)?;
            table
                .insert(key.as_slice(), oversized.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;

        assert_eq!(
            store.read_record(TableId::E2eeObject, &key),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            store
                .read_range(TableId::E2eeObject, &[0; 32], &[255; 32], 4)
                .map(|rows| rows.len()),
            Err(StorageError::InvalidEncoding)
        );
        let mut scan = store.snapshot_scan()?;
        assert_eq!(
            scan.next_all_slice(4, MAX_SEALED_RECORD_BYTES * 2)
                .map(|slice| slice.rows.len()),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            validate_row_shape(&[0; MAX_STORED_KEY_BYTES + 1], &[]),
            Err(StorageError::InvalidEncoding)
        );
        validate_row_shape(&[0; MAX_STORED_KEY_BYTES], &[0; MAX_SEALED_RECORD_BYTES])
    }

    #[test]
    fn open_and_transaction_fault_paths_fail_closed() -> Result<(), StorageError> {
        let directory = TestDirectory::create("faults")?;
        let empty = directory.create_file("empty.redb")?;
        assert!(matches!(
            RedbStore::open_with_faults(empty, 0, StorageFaultInjector::disabled()),
            Err(StorageError::LimitExceeded)
        ));

        let file = directory.create_file("faulted.redb")?;
        let injector = StorageFaultInjector::new(
            crate::StorageFaultCase {
                site: StorageFaultSite::TransactionBegin,
                boundary: StorageFaultBoundary::Before,
            },
            1,
        )?;
        let store = RedbStore::open_with_faults(file, 1_048_576, injector)?;
        assert!(matches!(
            store.write_meta(b"key", b"value"),
            Err(RedbCommitFailure::Rejected(StorageError::DatabaseRejected))
        ));
        Ok(())
    }
}
