//! Narrow redb adapter with fixed tables and mandatory durable commit settings.
//!
//! Every durable write of the live database is one bounded, immediate, two-phase transaction
//! charged to the allowance its caller derived from Section 19.3's `G`; the adapter reports the
//! bytes each transaction charged so the caller can debit one ledger across the operation. The
//! scratch databases keep redb's ordinary transactions until their own allowances arrive.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Error as IoError;
use std::ops::Bound::{Excluded, Unbounded};
use std::os::unix::fs::FileExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use agenc_relay_crypto::{StorageDigest, TrackedStateHasher, tracked_record_commitment};
use redb::{
    AllocationAllowance, BoundedWriteTransaction, Database, ReadOnlyDatabase, ReadTransaction,
    ReadableDatabase as _, ReadableTable as _, ReadableTableMetadata as _, ReclaimProgress,
    StorageBackend, TableDefinition, TableHandle as _, WriteTransaction,
};

use crate::bounded::{
    LIVE_DATABASE_REGION_BYTES, MAX_DEFERRED_RECLAIM_RECORDS, MaintenanceOutcome,
    live_database_builder, map_maintenance, map_preparation_error, map_publication_error,
    map_table_error, map_write_error,
};
use crate::scratch::{
    SCRATCH_SLICE_BYTES, SCRATCH_SLICE_ROWS, SCRATCH_TRANSACTION_ALLOWANCE, ScratchAdmission,
    ScratchDatabase, ScratchLocation, ScratchUsage,
};
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
    database: RedbDatabase,
    faults: StorageFaultInjector,
    commit_flushes: Arc<CommitFlushCounter>,
    repaired: Arc<AtomicBool>,
}

enum RedbDatabase {
    Writable(Database),
    ReadOnly(ReadOnlyDatabase),
}

impl RedbDatabase {
    fn begin_read(&self) -> Result<ReadTransaction, StorageError> {
        match self {
            Self::Writable(database) => database.begin_read(),
            Self::ReadOnly(database) => database.begin_read(),
        }
        .map_err(|_| StorageError::DatabaseRejected)
    }

    fn writable(&self) -> Result<&Database, StorageError> {
        match self {
            Self::Writable(database) => Ok(database),
            Self::ReadOnly(_) => Err(StorageError::DatabaseRejected),
        }
    }

    /// An unbounded transaction, kept for the tests that shape a database the adapter refuses.
    #[cfg(test)]
    fn begin_write(&self) -> Result<WriteTransaction, StorageError> {
        self.writable()?
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)
    }
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

/// The tracked-record index one verification rebuilds from the current records and reverses
/// through the manifests since the checkpoint cut, in admitted, bounded slices.
pub(crate) struct RecoveryScratch<'a> {
    inner: ScratchDatabase<'a>,
}

/// Buffers current tracked rows and publishes them one bounded slice at a time.
pub(crate) struct RecoveryScratchWriter<'s, 'a> {
    scratch: &'s mut RecoveryScratch<'a>,
    pending: Vec<OwnedRow>,
    pending_bytes: usize,
}

/// The record-and-reference index startup validates every cross-reference against, in
/// admitted, bounded slices.
pub(crate) struct ReferenceScratch<'a> {
    inner: ScratchDatabase<'a>,
}

/// Buffers records and their references and publishes them one bounded slice at a time. A
/// record's references may span slices: validation reads the complete published index, so no
/// slice boundary changes what it proves.
pub(crate) struct ReferenceScratchWriter<'s, 'a> {
    scratch: &'s mut ReferenceScratch<'a>,
    records: Vec<Vec<u8>>,
    references: Vec<OwnedRow>,
    pending_bytes: usize,
}

/// Whether a buffered slice has reached its row or byte budget.
fn slice_is_full(rows: usize, bytes: usize) -> bool {
    rows >= SCRATCH_SLICE_ROWS || bytes >= SCRATCH_SLICE_BYTES
}

impl<'a> ReferenceScratch<'a> {
    pub(crate) fn create(
        location: ScratchLocation,
        admission: &'a dyn ScratchAdmission,
    ) -> Result<Self, StorageError> {
        Ok(Self {
            inner: ScratchDatabase::create(
                location,
                admission,
                &[REFERENCE_RECORDS_TABLE, REFERENCES_TABLE],
            )?,
        })
    }

    pub(crate) fn begin(&mut self) -> ReferenceScratchWriter<'_, 'a> {
        ReferenceScratchWriter {
            scratch: self,
            records: Vec::new(),
            references: Vec::new(),
            pending_bytes: 0,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), StorageError> {
        let transaction = self.inner.read()?;
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

    /// Closes the scratch, removes its entry, and reports its complete metered usage.
    pub(crate) fn close(self) -> ScratchUsage {
        self.inner.close()
    }
}

impl ReferenceScratchWriter<'_, '_> {
    pub(crate) fn insert(
        &mut self,
        table: TableId,
        stored_key: &StoredKey,
        references: &[RecordReference],
    ) -> Result<(), StorageError> {
        let identity = scratch_key(table, stored_key)?;
        self.records
            .try_reserve(1)
            .map_err(|_| StorageError::AllocationFailed)?;
        self.pending_bytes = self
            .pending_bytes
            .checked_add(identity.len())
            .ok_or(StorageError::Overflow)?;
        self.records.push(identity.clone());
        self.flush_if_full()?;
        for (index, reference) in references.iter().enumerate() {
            let mut reference_key = identity.clone();
            reference_key.extend_from_slice(
                &u32::try_from(index)
                    .map_err(|_| StorageError::Overflow)?
                    .to_be_bytes(),
            );
            let target = scratch_key(reference.table(), reference.key())?;
            self.references
                .try_reserve(1)
                .map_err(|_| StorageError::AllocationFailed)?;
            self.pending_bytes = self
                .pending_bytes
                .checked_add(reference_key.len())
                .and_then(|bytes| bytes.checked_add(target.len()))
                .ok_or(StorageError::Overflow)?;
            self.references.push((reference_key, target));
            self.flush_if_full()?;
        }
        Ok(())
    }

    fn flush_if_full(&mut self) -> Result<(), StorageError> {
        let rows = self
            .records
            .len()
            .checked_add(self.references.len())
            .ok_or(StorageError::Overflow)?;
        if slice_is_full(rows, self.pending_bytes) {
            self.flush()?;
        }
        Ok(())
    }

    /// Publishes the buffered slice: one bounded transaction, each table opened once.
    fn flush(&mut self) -> Result<(), StorageError> {
        if self.records.is_empty() && self.references.is_empty() {
            return Ok(());
        }
        self.scratch
            .inner
            .observe_buffer(u64::try_from(self.pending_bytes).map_err(|_| StorageError::Overflow)?);
        let transaction = self.scratch.inner.begin()?;
        {
            let empty: &[u8] = &[];
            let mut records = transaction
                .open_table(REFERENCE_RECORDS_TABLE)
                .map_err(map_table_error)?;
            for identity in self.records.drain(..) {
                if records
                    .insert(identity.as_slice(), empty)
                    .map_err(map_write_error)?
                    .is_some()
                {
                    return Err(StorageError::StaleState);
                }
            }
            let mut table = transaction
                .open_table(REFERENCES_TABLE)
                .map_err(map_table_error)?;
            for (reference_key, target) in self.references.drain(..) {
                table
                    .insert(reference_key.as_slice(), target.as_slice())
                    .map_err(map_write_error)?;
            }
        }
        self.pending_bytes = 0;
        self.scratch.inner.publish(transaction)
    }

    /// Publishes whatever remains buffered.
    pub(crate) fn finish(mut self) -> Result<(), StorageError> {
        self.flush()
    }
}

impl<'a> RecoveryScratch<'a> {
    pub(crate) fn create(
        location: ScratchLocation,
        admission: &'a dyn ScratchAdmission,
    ) -> Result<Self, StorageError> {
        Self::create_with_allowance(location, admission, SCRATCH_TRANSACTION_ALLOWANCE)
    }

    /// Creates the index bounding every transaction by `allowance` instead of the fixed one.
    pub(crate) fn create_with_allowance(
        location: ScratchLocation,
        admission: &'a dyn ScratchAdmission,
        allowance: AllocationAllowance,
    ) -> Result<Self, StorageError> {
        Ok(Self {
            inner: ScratchDatabase::create_with_allowance(
                location,
                admission,
                &[RECOVERY_SCRATCH_TABLE],
                allowance,
            )?,
        })
    }

    pub(crate) fn begin_current(&mut self) -> RecoveryScratchWriter<'_, 'a> {
        RecoveryScratchWriter {
            scratch: self,
            pending: Vec::new(),
            pending_bytes: 0,
        }
    }

    /// Reverses one manifest: every mutation's `after` must be the scratch's current version,
    /// which then becomes its `before`. Mutations are applied in exact reverse manifest order,
    /// at most [`SCRATCH_SLICE_ROWS`] or [`SCRATCH_SLICE_BYTES`] of keys per admitted, bounded
    /// transaction.
    pub(crate) fn apply_reverse(
        &mut self,
        mutations: &[IntegrityRecordMutation],
    ) -> Result<(), StorageError> {
        let mut chunk: Vec<&IntegrityRecordMutation> = Vec::new();
        let mut chunk_bytes = 0_usize;
        for mutation in mutations.iter().rev() {
            chunk
                .try_reserve(1)
                .map_err(|_| StorageError::AllocationFailed)?;
            chunk.push(mutation);
            chunk_bytes = chunk_bytes
                .checked_add(mutation.stored_key().as_bytes().len())
                .and_then(|bytes| bytes.checked_add(38))
                .ok_or(StorageError::Overflow)?;
            if slice_is_full(chunk.len(), chunk_bytes) {
                self.reverse_chunk(&chunk)?;
                chunk.clear();
                chunk_bytes = 0;
            }
        }
        if chunk.is_empty() {
            return Ok(());
        }
        self.reverse_chunk(&chunk)
    }

    fn reverse_chunk(&mut self, chunk: &[&IntegrityRecordMutation]) -> Result<(), StorageError> {
        let transaction = self.inner.begin()?;
        {
            let mut table = transaction
                .open_table(RECOVERY_SCRATCH_TABLE)
                .map_err(map_table_error)?;
            for mutation in chunk {
                reverse_mutation(&mut table, mutation)?;
            }
        }
        self.inner.publish(transaction)
    }

    pub(crate) fn digest(&self) -> Result<(u64, StorageDigest), StorageError> {
        let transaction = self.inner.read()?;
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

    /// Closes the scratch, removes its entry, and reports its complete metered usage.
    pub(crate) fn close(self) -> ScratchUsage {
        self.inner.close()
    }
}

fn reverse_mutation(
    table: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    mutation: &IntegrityRecordMutation,
) -> Result<(), StorageError> {
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
                .map_err(map_write_error)?;
        }
        None => {
            table.remove(key.as_slice()).map_err(map_write_error)?;
        }
    }
    Ok(())
}

impl RecoveryScratchWriter<'_, '_> {
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
        self.pending_bytes = self
            .pending_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(StorageError::Overflow)?;
        self.pending
            .try_reserve(1)
            .map_err(|_| StorageError::AllocationFailed)?;
        self.pending.push((key, value.to_vec()));
        if slice_is_full(self.pending.len(), self.pending_bytes) {
            self.flush()?;
        }
        Ok(())
    }

    /// Publishes the buffered slice: one bounded transaction, the table opened once.
    fn flush(&mut self) -> Result<(), StorageError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.scratch
            .inner
            .observe_buffer(u64::try_from(self.pending_bytes).map_err(|_| StorageError::Overflow)?);
        let transaction = self.scratch.inner.begin()?;
        {
            let mut table = transaction
                .open_table(RECOVERY_SCRATCH_TABLE)
                .map_err(map_table_error)?;
            for (key, value) in self.pending.drain(..) {
                if table
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(map_write_error)?
                    .is_some()
                {
                    return Err(StorageError::StaleState);
                }
            }
        }
        self.pending_bytes = 0;
        self.scratch.inner.publish(transaction)
    }

    /// Publishes whatever remains buffered.
    pub(crate) fn finish(mut self) -> Result<(), StorageError> {
        self.flush()
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
        require_bounded_region(&file)?;
        let mut builder = live_database_builder(cache_bytes);
        let repaired = Arc::new(AtomicBool::new(false));
        let observed_repair = Arc::clone(&repaired);
        builder.set_repair_callback(move |_session| observed_repair.store(true, Ordering::Release));
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
            database: RedbDatabase::Writable(database),
            faults,
            commit_flushes,
            repaired,
        })
    }

    /// Reports whether this open had to repair the database, which a close that persisted
    /// its allocator state within its allowance makes unnecessary.
    pub(crate) fn opened_after_repair(&self) -> bool {
        self.repaired.load(Ordering::Acquire)
    }

    pub(crate) fn open_read_only(
        descriptor_path: &std::path::Path,
        cache_bytes: usize,
    ) -> Result<Self, StorageError> {
        if cache_bytes == 0 {
            return Err(StorageError::LimitExceeded);
        }
        let mut builder = redb::Builder::new();
        builder.set_cache_size(cache_bytes);
        let database = builder
            .open_read_only(descriptor_path)
            .map_err(|_| StorageError::DatabaseRejected)?;
        Ok(Self {
            database: RedbDatabase::ReadOnly(database),
            faults: StorageFaultInjector::disabled(),
            commit_flushes: Arc::new(CommitFlushCounter::default()),
            repaired: Arc::new(AtomicBool::new(false)),
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

    /// Copies only named rows from one consistent transaction, without scanning gaps.
    pub(crate) fn read_exact_keys(
        &self,
        table: TableId,
        keys: &[StoredKey],
    ) -> Result<Vec<OwnedRow>, StorageError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)?;
        let table = transaction
            .open_table(table_definition(table))
            .map_err(|_| StorageError::DatabaseRejected)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(keys.len())
            .map_err(|_| StorageError::AllocationFailed)?;
        let mut copied = 0_usize;
        for key in keys {
            let Some(value) = table
                .get(key.as_bytes())
                .map_err(|_| StorageError::DatabaseRejected)?
            else {
                continue;
            };
            validate_row_shape(key.as_bytes(), value.value())?;
            copied = copied
                .checked_add(key.as_bytes().len())
                .and_then(|total| total.checked_add(value.value().len()))
                .ok_or(StorageError::Overflow)?;
            if copied > crate::mutation::MAX_RANGE_READ_BYTES {
                return Err(StorageError::LimitExceeded);
            }
            rows.push((key.as_bytes().to_vec(), value.value().to_vec()));
        }
        Ok(rows)
    }

    /// Reads up to `limit` rows in `start..end` within the byte budget and
    /// reports whether any row remains in the range after the last one copied.
    pub(crate) fn read_range(
        &self,
        table: TableId,
        start: &[u8],
        end: &[u8],
        limit: usize,
    ) -> Result<(Vec<OwnedRow>, bool), StorageError> {
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
        let mut copied = 0_usize;
        let mut truncated = false;
        for entry in range {
            let (key, value) = entry.map_err(|_| StorageError::DatabaseRejected)?;
            validate_row_shape(key.value(), value.value())?;
            let row_bytes = key
                .value()
                .len()
                .checked_add(value.value().len())
                .ok_or(StorageError::Overflow)?;
            let next = copied
                .checked_add(row_bytes)
                .ok_or(StorageError::Overflow)?;
            // The first row always fits so a page never stalls; a later row that
            // would exceed the row limit or the byte budget ends the page and
            // proves that more rows remain.
            if rows.len() >= limit
                || (!rows.is_empty() && next > crate::mutation::MAX_RANGE_READ_BYTES)
            {
                truncated = true;
                break;
            }
            copied = next;
            rows.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok((rows, truncated))
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

    /// Writes one control record within `allowance` and returns the bytes charged.
    pub(crate) fn write_meta(
        &self,
        key: &[u8],
        value: &[u8],
        allowance: AllocationAllowance,
    ) -> Result<u64, RedbCommitFailure> {
        let transaction = self.begin_bounded_write(allowance)?;
        {
            let mut table = transaction.open_table(META_TABLE).map_err(rejected_table)?;
            table.insert(key, value).map_err(rejected_storage)?;
        }
        self.finish_transaction(transaction)
    }

    /// Creates every table and the first control records within `allowance` and returns the
    /// bytes charged.
    pub(crate) fn initialize_database(
        &self,
        header: &[u8],
        reservation: &[u8],
        writes: &[RedbWrite<'_>],
        allowance: AllocationAllowance,
    ) -> Result<u64, RedbCommitFailure> {
        let transaction = self.begin_bounded_write(allowance)?;
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
        if writes.iter().any(|write| write.value.is_none()) {
            return Err(RedbCommitFailure::Rejected(StorageError::InvalidEncoding));
        }
        apply_writes(&transaction, writes)?;
        self.finish_transaction(transaction)
    }

    /// Commits application rows and the committed reservation record within `allowance` and
    /// returns the bytes charged.
    pub(crate) fn commit_records(
        &self,
        writes: &[RedbWrite<'_>],
        reservation: &[u8],
        allowance: AllocationAllowance,
    ) -> Result<u64, RedbCommitFailure> {
        let transaction = self.begin_bounded_write(allowance)?;
        apply_writes(&transaction, writes)?;
        {
            let mut meta = transaction.open_table(META_TABLE).map_err(rejected_table)?;
            meta.insert(RESERVATION_META_KEY, reservation)
                .map_err(rejected_storage)?;
        }
        self.finish_transaction(transaction)
    }

    /// Installs one checkpoint, prunes its ancestors and writes the committed reservation
    /// record within `allowance`, and returns the bytes charged.
    pub(crate) fn commit_checkpoint(
        &self,
        checkpoint_key: &[u8; 8],
        checkpoint_record: &[u8],
        previous_checkpoint_key: &[u8; 8],
        state_meta_record: &[u8],
        reservation: &[u8],
        allowance: AllocationAllowance,
    ) -> Result<u64, RedbCommitFailure> {
        let transaction = self.begin_bounded_write(allowance)?;
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

    /// Begins one bounded write transaction charged to `allowance`.
    ///
    /// A bounded transaction is always immediately durable; two-phase commit is enabled
    /// explicitly so its publication flushes the secondary header slot before the primary slot
    /// swap, the two flushes the `TransactionPhaseOne` and `TransactionPhaseTwo` fault sites
    /// label.
    fn begin_bounded_write(
        &self,
        allowance: AllocationAllowance,
    ) -> Result<BoundedWriteTransaction, RedbCommitFailure> {
        self.faults
            .check(
                StorageFaultSite::TransactionBegin,
                StorageFaultBoundary::Before,
            )
            .map_err(RedbCommitFailure::Rejected)?;
        let mut transaction = self
            .database
            .writable()
            .map_err(RedbCommitFailure::Rejected)?
            .begin_write_bounded(allowance)
            .map_err(|_| RedbCommitFailure::Rejected(StorageError::DatabaseRejected))?;
        self.faults
            .check(
                StorageFaultSite::TransactionBegin,
                StorageFaultBoundary::After,
            )
            .map_err(RedbCommitFailure::Rejected)?;
        transaction.set_two_phase_commit(true);
        Ok(transaction)
    }

    /// Reclaims freed-page records of earlier transactions in one bounded publication of at
    /// most [`MAX_DEFERRED_RECLAIM_RECORDS`] records.
    ///
    /// Bounded transactions never reclaim in their own commit, so this is the deferred cleanup
    /// of the operation that owns `allowance`. Progress is durable and monotonic: a refusal
    /// reclaims nothing and leaves the database usable, and a later call resumes where the
    /// last publication stopped, including after a restart.
    pub(crate) fn reclaim_deferred(
        &self,
        allowance: AllocationAllowance,
    ) -> Result<MaintenanceOutcome<ReclaimProgress>, RedbCommitFailure> {
        let database = self
            .database
            .writable()
            .map_err(RedbCommitFailure::Rejected)?;
        map_maintenance(database.reclaim_bounded(allowance, MAX_DEFERRED_RECLAIM_RECORDS))
    }

    /// Persists the allocator state within `allowance` so that the next open needs no repair,
    /// and takes that duty from the close path whatever the outcome: after a refusal the drop
    /// only flushes and closes the file, and the next open repairs it exactly as after a crash.
    pub(crate) fn persist_for_close(
        &self,
        allowance: AllocationAllowance,
    ) -> Result<MaintenanceOutcome<()>, RedbCommitFailure> {
        let database = self
            .database
            .writable()
            .map_err(RedbCommitFailure::Rejected)?;
        map_maintenance(database.persist_allocator_state_bounded(allowance))
    }
}

fn table_definition(table: TableId) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
    TableDefinition::new(table.name())
}

/// The redb 4.2.0 file header fields that fix a database's region layout: the magic number,
/// then at fixed little-endian offsets the page size and the data pages per region.
const REDB_MAGIC: [u8; 9] = [b'r', b'e', b'd', b'b', 0x1A, 0x0A, 0xA9, 0x0D, 0x0A];
const REDB_PAGE_SIZE_OFFSET: u64 = 12;
const REDB_REGION_MAX_DATA_PAGES_OFFSET: u64 = 20;

/// Refuses an existing database whose header lays it out with regions larger than
/// [`LIVE_DATABASE_REGION_BYTES`], which the bounded allowance could never extend.
///
/// An empty file is a creation, which the builder lays out bounded; a file too short or
/// without the magic number is left for redb to reject. The region size is read exactly as
/// the vendored header parser reads it, so the check cannot disagree with the open.
fn require_bounded_region(file: &File) -> Result<(), StorageError> {
    let length = file.metadata().map_err(crate::filesystem_rejected)?.len();
    if length < REDB_REGION_MAX_DATA_PAGES_OFFSET + 4 {
        return Ok(());
    }
    let mut magic = [0_u8; 9];
    file.read_exact_at(&mut magic, 0)
        .map_err(crate::filesystem_rejected)?;
    if magic != REDB_MAGIC {
        return Ok(());
    }
    let mut field = [0_u8; 4];
    file.read_exact_at(&mut field, REDB_PAGE_SIZE_OFFSET)
        .map_err(crate::filesystem_rejected)?;
    let page_size = u64::from(u32::from_le_bytes(field));
    file.read_exact_at(&mut field, REDB_REGION_MAX_DATA_PAGES_OFFSET)
        .map_err(crate::filesystem_rejected)?;
    let region_bytes = u64::from(u32::from_le_bytes(field))
        .checked_mul(page_size)
        .ok_or(StorageError::Overflow)?;
    if region_bytes > LIVE_DATABASE_REGION_BYTES {
        return Err(StorageError::UnboundedRegion(region_bytes));
    }
    Ok(())
}

/// Applies writes with one open table handle per run of same-table writes, each run in
/// descending key order.
///
/// Reopening a redb table for every row copies the table tree and the row's leaf path again on
/// each open, which multiplied the physical growth of a maximum-count transaction by more than
/// ten times the row bytes. Batches arrive sorted by table and key, so one handle covers a whole
/// table.
///
/// The order inside a run is load-bearing. redb 4.2.0 never rebuilds a leaf that holds a single
/// value of at least one page: an insert that lands in such a leaf becomes a new sibling leaf
/// holding that one row. With ascending keys the sibling's separator is the key just inserted, so
/// the next greater key is routed to the large leaf again, and every row of the run receives a
/// page of its own and a rewritten branch. Measured through the production workload, 65,535
/// rows of 134 bytes inserted below one 8 MiB row charged 825,901,056 bytes and grew the file by
/// 257,761,280, which no allowance of `G` can admit. With descending keys the first sibling's
/// separator bounds every later key of the run, the rows share ordinary leaves, and the same
/// transaction charges 71,286,784 bytes and grows the file by 16,625,664. Keys are distinct
/// within one batch, so the order inside the transaction changes nothing a reader can observe.
fn apply_writes(
    transaction: &WriteTransaction,
    writes: &[RedbWrite<'_>],
) -> Result<(), RedbCommitFailure> {
    for run in writes.chunk_by(|left, right| left.table == right.table) {
        let Some(first) = run.first() else {
            continue;
        };
        let mut table = transaction
            .open_table(table_definition(first.table))
            .map_err(rejected_table)?;
        for write in run.iter().rev() {
            if let Some(value) = write.value {
                table.insert(write.key, value).map_err(rejected_storage)?;
            } else {
                table.remove(write.key).map_err(rejected_storage)?;
            }
        }
    }
    Ok(())
}

/// A table could not be opened for writing; an allowance refusal keeps its own determinate
/// outcome and everything else is the determinate rejection before commit.
fn rejected_table(error: redb::TableError) -> RedbCommitFailure {
    RedbCommitFailure::Rejected(map_table_error(error))
}

/// A row could not be written; an allowance refusal keeps its own determinate outcome and
/// everything else is the determinate rejection before commit.
fn rejected_storage(error: redb::StorageError) -> RedbCommitFailure {
    RedbCommitFailure::Rejected(map_write_error(error))
}

impl RedbStore {
    /// Prepares and publishes one bounded transaction, with the two durable flushes of its
    /// publication labeled as the transaction phases, and returns the bytes it charged.
    ///
    /// A refusal during preparation aborted the transaction cleanly: no root changed, every page
    /// it freed is allocated again, and the next writer is unaffected. Any other preparation or
    /// publication failure is uncertain and keeps Section 21.5's indeterminate outcome.
    fn finish_transaction(
        &self,
        transaction: BoundedWriteTransaction,
    ) -> Result<u64, RedbCommitFailure> {
        self.commit_flushes.begin();
        let result = prepare_and_publish(transaction);
        self.commit_flushes.end();
        result
    }
}

fn prepare_and_publish(transaction: BoundedWriteTransaction) -> Result<u64, RedbCommitFailure> {
    let prepared = transaction.prepare().map_err(map_preparation_error)?;
    let charged = prepared
        .allowance_charged()
        .map_err(|_| RedbCommitFailure::Rejected(StorageError::DatabaseRejected))?;
    prepared.publish().map_err(map_publication_error)?;
    Ok(charged)
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
    use crate::AllowancePhase;

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

    /// The whole Section 19.3 allowance, which every ordinary test transaction fits.
    fn full_allowance() -> AllocationAllowance {
        AllocationAllowance::new(crate::MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
    }

    fn certain(failure: RedbCommitFailure) -> StorageError {
        match failure {
            RedbCommitFailure::Rejected(error) => error,
            RedbCommitFailure::Indeterminate => StorageError::DatabaseRejected,
        }
    }

    fn initialize(store: &RedbStore, writes: &[RedbWrite<'_>]) -> Result<(), StorageError> {
        store
            .initialize_database(b"header", b"reservation", writes, full_allowance())
            .map(|_| ())
            .map_err(certain)
    }

    /// Admits every scratch transaction: these tests exercise the scratch itself, not the gate.
    struct AlwaysAdmit;

    impl ScratchAdmission for AlwaysAdmit {
        fn admit_scratch(&self, _allowance: AllocationAllowance) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn scratch(directory: &TestDirectory, name: &str) -> Result<ScratchLocation, StorageError> {
        Ok(ScratchLocation::Exclusive {
            file: directory.create_file(name)?,
            directory: directory.open_directory()?,
            name: name.to_owned(),
        })
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
        let mut scratch =
            ReferenceScratch::create(scratch(&directory, "references.redb")?, &AlwaysAdmit)?;
        let source_key = StoredKey::new(vec![1_u8; 32])?;
        let target_key = StoredKey::new(vec![2_u8; 32])?;
        let target = RecordReference::new(TableId::E2eeObject, target_key.clone())?;

        let mut writer = scratch.begin();
        writer.insert(
            TableId::E2eeObject,
            &source_key,
            std::slice::from_ref(&target),
        )?;
        writer.finish()?;
        assert_eq!(scratch.validate(), Err(StorageError::StaleState));

        // A duplicate record is refused when its slice is published, whether the first copy
        // is in an earlier slice or in the same buffer.
        let mut writer = scratch.begin();
        writer.insert(TableId::E2eeObject, &source_key, &[])?;
        assert_eq!(writer.finish(), Err(StorageError::StaleState));
        let mut writer = scratch.begin();
        writer.insert(TableId::E2eeObject, &target_key, &[])?;
        writer.insert(TableId::E2eeObject, &target_key, &[])?;
        assert_eq!(writer.finish(), Err(StorageError::StaleState));

        let mut writer = scratch.begin();
        writer.insert(TableId::E2eeObject, &target_key, &[])?;
        writer.finish()?;
        scratch.validate()?;
        let usage = scratch.close();
        assert_eq!(usage.transactions, 3);
        assert!(usage.charged_bytes > 0);
        assert!(usage.peak_file_bytes >= usage.creation_bytes);
        assert!(!directory.path().join("references.redb").exists());
        Ok(())
    }

    #[test]
    fn recovery_scratch_validates_versions_and_reverse_transitions() -> Result<(), StorageError> {
        let directory = TestDirectory::create("recovery")?;
        let mut scratch =
            RecoveryScratch::create(scratch(&directory, "recovery.redb")?, &AlwaysAdmit)?;
        let stored_key = StoredKey::new(vec![3_u8; 32])?;
        let digest = StorageDigest::from_bytes([4_u8; 32]);
        let present = IntegrityRecordVersion::Present {
            record_schema: 1,
            sealed_record_id: digest,
        };

        let mut writer = scratch.begin_current();
        writer.insert_current(TableId::E2eeObject, &stored_key, 1, digest)?;
        writer.finish()?;
        let mut writer = scratch.begin_current();
        writer.insert_current(TableId::E2eeObject, &stored_key, 1, digest)?;
        assert_eq!(writer.finish(), Err(StorageError::StaleState));
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
        let usage = scratch.close();
        assert_eq!(usage.transactions, 3);
        assert!(!directory.path().join("recovery.redb").exists());
        Ok(())
    }

    #[test]
    fn recovery_digest_rejects_malformed_scratch_rows() -> Result<(), StorageError> {
        let directory = TestDirectory::create("malformed-recovery")?;
        let mut scratch =
            RecoveryScratch::create(scratch(&directory, "recovery.redb")?, &AlwaysAdmit)?;
        let transaction = scratch.inner.begin()?;
        {
            let mut table = transaction
                .open_table(RECOVERY_SCRATCH_TABLE)
                .map_err(|_| StorageError::DatabaseRejected)?;
            table
                .insert(&[0_u8, 0, 1][..], &[0_u8; 36][..])
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
        scratch.inner.publish(transaction)?;
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
            full_allowance(),
        );
        assert!(matches!(
            rejected,
            Err(RedbCommitFailure::Rejected(StorageError::InvalidEncoding))
        ));
        initialize(&store, &[])?;
        store.validate_inventory()?;
        store.validate_meta_membership()?;
        store
            .write_meta(b"unexpected", b"value", full_allowance())
            .map_err(certain)?;
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
                full_allowance(),
            )
            .map_err(certain)?;
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
                full_allowance(),
            )
            .map_err(certain)?;
        assert_eq!(store.read_record(TableId::E2eeObject, &key)?, None);
        assert_eq!(
            store.read_meta(RESERVATION_META_KEY)?,
            Some(b"reservation-3".to_vec())
        );
        Ok(())
    }

    #[test]
    fn range_reads_stop_at_the_byte_budget_but_always_return_one_row() -> Result<(), StorageError> {
        let (_directory, store) = open_store("range-byte-budget")?;
        initialize(&store, &[])?;
        // Three rows of six MiB: two fit the sixteen MiB budget, the third does not.
        let row = vec![0_u8; 6 * 1_048_576];
        let transaction = store
            .database
            .begin_write()
            .map_err(|_| StorageError::DatabaseRejected)?;
        {
            let mut table = transaction
                .open_table(table_definition(TableId::E2eeObject))
                .map_err(|_| StorageError::DatabaseRejected)?;
            for index in 1_u8..=3 {
                table
                    .insert([index; 32].as_slice(), row.as_slice())
                    .map_err(|_| StorageError::DatabaseRejected)?;
            }
        }
        transaction
            .commit()
            .map_err(|_| StorageError::DatabaseRejected)?;

        let (first, first_truncated) =
            store.read_range(TableId::E2eeObject, &[0; 32], &[255; 32], 4)?;
        assert!(first_truncated);
        assert_eq!(first.len(), 2);
        assert_eq!(
            first.last().map(|(key, _)| key.as_slice()),
            Some([2; 32].as_slice())
        );
        let (rest, rest_truncated) =
            store.read_range(TableId::E2eeObject, &[2, 255], &[255; 32], 4)?;
        assert!(!rest_truncated);
        assert_eq!(rest.len(), 1);
        let (limited, limit_truncated) =
            store.read_range(TableId::E2eeObject, &[0; 32], &[255; 32], 1)?;
        assert!(limit_truncated);
        assert_eq!(limited.len(), 1);
        assert_eq!(
            rest.first().map(|(key, _)| key.as_slice()),
            Some([3; 32].as_slice())
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
                .map(|(rows, _)| rows.len()),
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
            store.write_meta(b"key", b"value", full_allowance()),
            Err(RedbCommitFailure::Rejected(StorageError::DatabaseRejected))
        ));
        Ok(())
    }

    fn reopen_store(directory: &TestDirectory, name: &str) -> Result<RedbStore, StorageError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join(name))
            .map_err(|_| StorageError::DatabaseRejected)?;
        RedbStore::open_with_faults(file, 1_048_576, StorageFaultInjector::disabled())
    }

    const CHARGED_KEY: [u8; 32] = [8_u8; 32];

    fn charged_write() -> RedbWrite<'static> {
        RedbWrite {
            table: TableId::E2eeObject,
            key: &CHARGED_KEY,
            value: Some(b"first"),
        }
    }

    /// Initializes a fresh store and commits one fixed row under `allowance`, so that the same
    /// deterministic transaction can be replayed against different allowances.
    fn first_commit(
        label: &str,
        allowance: AllocationAllowance,
    ) -> Result<(TestDirectory, RedbStore, Result<u64, RedbCommitFailure>), StorageError> {
        let (directory, store) = open_store(label)?;
        initialize(&store, &[])?;
        let outcome = store.commit_records(&[charged_write()], b"reservation-2", allowance);
        Ok((directory, store, outcome))
    }

    #[test]
    fn bounded_commits_are_charged_exactly_and_refused_without_side_effects()
    -> Result<(), StorageError> {
        let (_reference_directory, _reference, measured) =
            first_commit("charge-reference", full_allowance())?;
        let charged = measured.map_err(certain)?;
        assert!(charged > 0);
        assert!(charged <= crate::MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH);

        // Exactly the measured charge fits, to the byte.
        let (_exact_directory, exact, outcome) =
            first_commit("charge-exact", AllocationAllowance::new(charged))?;
        assert_eq!(outcome.map_err(certain)?, charged);
        assert_eq!(
            exact.read_record(TableId::E2eeObject, &CHARGED_KEY)?,
            Some(b"first".to_vec())
        );

        // One byte less refuses during preparation: nothing is written, the reservation record
        // is untouched, and the next writer on the same store is usable.
        let (_short_directory, short, outcome) =
            first_commit("charge-short", AllocationAllowance::new(charged - 1))?;
        assert!(matches!(
            outcome,
            Err(RedbCommitFailure::Rejected(StorageError::AllowanceRefused(
                AllowancePhase::Preparation
            )))
        ));
        assert_eq!(short.read_record(TableId::E2eeObject, &CHARGED_KEY)?, None);
        assert_eq!(
            short.read_meta(RESERVATION_META_KEY)?,
            Some(b"reservation".to_vec())
        );
        short
            .commit_records(&[charged_write()], b"reservation-2", full_allowance())
            .map_err(certain)?;
        assert_eq!(
            short.read_record(TableId::E2eeObject, &CHARGED_KEY)?,
            Some(b"first".to_vec())
        );
        assert_eq!(
            short.read_meta(RESERVATION_META_KEY)?,
            Some(b"reservation-2".to_vec())
        );

        // No allowance at all refuses the first mutation, before anything is prepared.
        let (_none_directory, none, outcome) =
            first_commit("charge-none", AllocationAllowance::new(0))?;
        assert!(matches!(
            outcome,
            Err(RedbCommitFailure::Rejected(StorageError::AllowanceRefused(
                AllowancePhase::Mutation
            )))
        ));
        assert_eq!(
            none.read_meta(RESERVATION_META_KEY)?,
            Some(b"reservation".to_vec())
        );
        Ok(())
    }

    #[test]
    fn deferred_cleanup_and_close_stay_inside_their_allowances() -> Result<(), StorageError> {
        let directory = TestDirectory::create("cleanup")?;
        let store = RedbStore::open_with_faults(
            directory.create_file("state.redb")?,
            1_048_576,
            StorageFaultInjector::disabled(),
        )?;
        initialize(&store, &[])?;
        store
            .commit_records(&[charged_write()], b"reservation-2", full_allowance())
            .map_err(certain)?;

        // A reclamation without allowance reclaims nothing and leaves the database usable; a
        // reclamation with allowance returns the pages the commit freed, then finds nothing.
        assert!(matches!(
            store.reclaim_deferred(AllocationAllowance::new(0)),
            Ok(MaintenanceOutcome::Refused(AllowancePhase::Cleanup))
        ));
        let progress = store
            .reclaim_deferred(full_allowance())
            .ok()
            .and_then(MaintenanceOutcome::completed)
            .ok_or(StorageError::StaleState)?;
        assert!(progress.records >= 1);
        assert!(progress.pages >= 1);
        assert!(!progress.remaining);
        let drained = store
            .reclaim_deferred(full_allowance())
            .ok()
            .and_then(MaintenanceOutcome::completed)
            .ok_or(StorageError::StaleState)?;
        assert_eq!((drained.records, drained.remaining), (0, false));

        // A refused close persists nothing, so the next open repairs exactly as after a crash;
        // a close within its allowance leaves the next open clean.
        assert!(matches!(
            store.persist_for_close(AllocationAllowance::new(0)),
            Ok(MaintenanceOutcome::Refused(AllowancePhase::Close))
        ));
        drop(store);
        let repaired = reopen_store(&directory, "state.redb")?;
        assert!(repaired.opened_after_repair());
        assert_eq!(
            repaired.read_record(TableId::E2eeObject, &CHARGED_KEY)?,
            Some(b"first".to_vec())
        );
        assert!(matches!(
            repaired.persist_for_close(full_allowance()),
            Ok(MaintenanceOutcome::Completed(()))
        ));
        drop(repaired);
        let clean = reopen_store(&directory, "state.redb")?;
        assert!(!clean.opened_after_repair());
        Ok(())
    }

    #[test]
    fn a_database_laid_out_with_unbounded_regions_is_refused_at_open() -> Result<(), StorageError> {
        let directory = TestDirectory::create("regions")?;
        let file = directory.create_file("unbounded.redb")?;
        // The upstream default region, which the bounded allowance could never extend.
        let mut builder = redb::Builder::new();
        builder.set_cache_size(1_048_576);
        let database = builder
            .create_file(file)
            .map_err(|_| StorageError::DatabaseRejected)?;
        drop(database);
        assert_eq!(
            reopen_store(&directory, "unbounded.redb").err(),
            Some(StorageError::UnboundedRegion(4_294_967_296))
        );

        // A database the adapter created opens again, and an empty file is a creation.
        let (bounded_directory, bounded) = open_store("regions-bounded")?;
        initialize(&bounded, &[])?;
        drop(bounded);
        let reopened = reopen_store(&bounded_directory, "state.redb")?;
        reopened.validate_inventory()?;
        Ok(())
    }

    #[test]
    fn ascending_rows_below_a_large_value_share_leaves_instead_of_taking_a_page_each()
    -> Result<(), StorageError> {
        let (_directory, store) = open_store("large-neighbor")?;
        initialize(&store, &[])?;
        // One value of many pages whose key sorts directly above the rows that follow.
        let large_key = [0x13_u8; 18];
        let large = vec![1_u8; 8 * 1_048_576];
        store
            .commit_records(
                &[RedbWrite {
                    table: TableId::Sanction,
                    key: &large_key,
                    value: Some(&large),
                }],
                b"reservation-2",
                full_allowance(),
            )
            .map_err(certain)?;

        const ROWS: u64 = 8_192;
        let value = [7_u8; 134];
        let keys = (0..ROWS)
            .map(|index| {
                let mut key = [0x12_u8; 18];
                for (slot, byte) in key.iter_mut().skip(10).zip(index.to_be_bytes()) {
                    *slot = byte;
                }
                key
            })
            .collect::<Vec<_>>();
        let writes = keys
            .iter()
            .map(|key| RedbWrite {
                table: TableId::Sanction,
                key,
                value: Some(&value),
            })
            .collect::<Vec<_>>();
        let charged = store
            .commit_records(&writes, b"reservation-3", full_allowance())
            .map_err(certain)?;
        // A page and a rewritten branch for every row would charge more than 6 KiB a row; rows
        // that share leaves charge well under one page a row.
        assert!(
            charged < ROWS * 2_048,
            "{ROWS} rows below a large value charged {charged} bytes"
        );
        assert_eq!(store.table_usage(TableId::Sanction, u64::MAX)?.0, ROWS + 1);
        Ok(())
    }
}
