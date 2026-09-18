//! Bounded, incremental online backup over one authenticated snapshot cut.
//!
//! `BACKUP CREATE` runs as a phase machine on the storage owner thread. Each
//! service call performs at most one bounded slice of one phase and yields,
//! so commits and reads are served between slices, and every phase is
//! admitted against its own allowance before it does any work:
//!
//! 1. Capture (`start_backup`): the single snapshot slot is taken, the table
//!    inventory and meta membership are checked, the reservation and guard
//!    are re-authenticated and bound to the header, the pair must classify
//!    as an exact committed or reserved boundary, and one redb read
//!    transaction is opened. That transaction is the cut: accounting and the
//!    copy both read it and nothing else, so a writer that advances after
//!    capture never changes what is backed up.
//! 2. Accounting: every row of the cut is decrypted and checked exactly as
//!    the post-write pass will check it, the logical and exact stream
//!    counters are recomputed, and every reference is recorded in a scratch
//!    whose every transaction is charged to the fork's allowance before it
//!    allocates. At the end the recomputed counters must equal the
//!    authenticated StateMeta of the cut, which the engine also holds in
//!    memory. The exact final length `O` is known here, before any output
//!    exists.
//! 3. Resolution: every recorded reference resolves to a recorded row.
//! 4. Admission: the temporary is created and admitted at `R(F) + O`.
//! 5. Copy: the cut is streamed through the same read transaction.
//! 6. Seal: the trailer is written and the temporary's length must be `O`.
//! 7. Verification: the temporary is re-read, decrypted and authenticated
//!    frame by frame; the verified facts must equal the captured cut.
//! 8. Publication: the verified inode is renamed in place.
//!
//! A failure in any phase drops the job: the temporary and the scratch are
//! removed and nothing is published. Nothing here writes the main database,
//! so no backup outcome is ever a claim about durable state; the Section
//! 21.5 indeterminate path belongs to the write path alone.

use std::fs::File;
use std::io::{Seek as _, SeekFrom};
use std::ops::Bound::{self, Excluded, Unbounded};

use agenc_ircd_crypto::Ed25519SecretKey;
use redb::{AllocationAllowance, TableDefinition};

use super::{StorageEngine, record_references, validate_recovered_domain_record};
use crate::backup::{
    BACKUP_FIXED_STREAM_BYTES, BackupRecordVerification, BackupStreamVerifier, backup_record_charge,
};
use crate::bounded::{map_table_error, map_write_error};
use crate::redb_store::SnapshotScan;
use crate::scratch::{ScratchAdmission, ScratchDatabase};
use crate::{
    BackupDestination, BackupHeader, BackupOutput, BackupReceipt, BackupRecord, BackupStreamWriter,
    BackupTrailer, BackupTrustKey, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, NonceReservationState,
    RecordReference, RecoveryDisposition, RollbackGuard, StateMetaTbs, StorageError,
    StorageFaultBoundary, StorageFaultSite, StoredKey, TableId, classify_recovery_state,
};

/// Records one accounting, resolution, copy or verification slice may cover:
/// the Section 23.5.2 service slice the checkpoint scan uses.
pub(crate) const BACKUP_SLICE_RECORDS: usize = 4_096;
/// Bytes one accounting, resolution, copy or verification slice may cover.
pub(crate) const BACKUP_SLICE_BYTES: usize = 16_777_216;
/// Allowance charged to every bounded scratch transaction: the Section 19.3
/// per-transaction physical growth ceiling `G`. One slice records at most
/// the identities and references of `BACKUP_SLICE_BYTES` of sealed rows,
/// which stays far inside `G`; a transaction that would exceed it refuses
/// before allocating.
pub(crate) const SCRATCH_TRANSACTION_ALLOWANCE: u64 = MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH;

const SCRATCH_RECORDS_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("backup_reference_records");
const SCRATCH_REFERENCES_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("backup_record_references");

/// One online backup in progress: the captured cut, the boundary facts every
/// phase binds itself to, and the current phase.
pub(crate) struct BackupJob {
    destination: Option<BackupDestination>,
    signing_key: Ed25519SecretKey,
    header: BackupHeader,
    expected_state_meta: StateMetaTbs,
    maximum_bytes: u64,
    database_max_bytes: u64,
    expected_stream_bytes: Option<u64>,
    scan: SnapshotScan,
    slice_records: usize,
    slice_bytes: usize,
    scratch_allowance: u64,
    phase: BackupPhase,
}

enum BackupPhase {
    Accounting(Box<Accounting>),
    Resolving(Resolving),
    Admitting,
    Copying(Copying),
    Sealing(Copying),
    Verifying(Box<Verifying>),
    Publishing(Publishing),
    Finished,
}

#[cfg(test)]
impl BackupPhase {
    const fn name(&self) -> &'static str {
        match self {
            Self::Accounting(_) => "accounting",
            Self::Resolving(_) => "resolving",
            Self::Admitting => "admitting",
            Self::Copying(_) => "copying",
            Self::Sealing(_) => "sealing",
            Self::Verifying(_) => "verifying",
            Self::Publishing(_) => "publishing",
            Self::Finished => "finished",
        }
    }
}

struct Accounting {
    scratch: Option<ReferenceScratch>,
    verification: BackupRecordVerification,
    stream_bytes: u64,
}

struct Resolving {
    scratch: ReferenceScratch,
    cursor: Option<Vec<u8>>,
}

struct Copying {
    writer: BackupStreamWriter<File>,
    output: BackupOutput,
}

struct Verifying {
    output: BackupOutput,
    trailer: BackupTrailer,
    verifier: BackupStreamVerifier<File>,
    actual_bytes: u64,
}

struct Publishing {
    output: BackupOutput,
    trailer: BackupTrailer,
    stream_bytes: u64,
}

impl StorageEngine {
    /// Captures one authenticated cut and takes the single snapshot slot.
    ///
    /// Nothing here is proportional to the database: the inventory and meta
    /// membership checks, the re-authentication of the reservation and guard,
    /// the boundary classification and one read transaction. No file is
    /// created.
    pub(crate) fn start_backup(
        &mut self,
        destination: BackupDestination,
        signing_key: Ed25519SecretKey,
        created_at: u64,
        backup_id: [u8; 16],
    ) -> Result<(), StorageError> {
        if (self.backup_job.is_some(), self.checkpoint_job.is_some()) != (false, false) {
            return Err(StorageError::QueueFull);
        }
        // A backup writes nothing to this database and is admitted at `R(F) + O` on its own
        // filesystem, far below the scratch gate, so it is not held behind an owed scratch
        // verification: capture never runs the startup verification, its own reference scratch
        // is bounded but not reserve-admitted, the debt stays recorded for the next durable
        // write, and a restore reconstructs and verifies the whole ledger again.
        self.store.validate_inventory()?;
        self.store.validate_meta_membership()?;
        let reservation = NonceReservationState::decode_and_verify(
            &self.reservation.encode()?,
            &self.integrity_keys,
        )?;
        let guard = RollbackGuard::decode_and_verify(&self.guard.encode()?, &self.integrity_keys)?;
        if !matches!(
            classify_recovery_state(
                &self.header,
                &self.state_meta,
                self.state_meta_record_id,
                &reservation,
                &guard,
            )?,
            RecoveryDisposition::ExactCommitted | RecoveryDisposition::ExactReserved
        ) {
            return Err(StorageError::StaleState);
        }
        let header = BackupHeader::new(
            self.header,
            reservation,
            guard,
            created_at,
            backup_id,
            signing_key.public_key(),
        )?;
        let verification = BackupRecordVerification::new(&header, &self.guard_root_key)?;
        let scan = self.store.snapshot_scan()?;
        self.backup_job = Some(BackupJob {
            destination: Some(destination),
            signing_key,
            header,
            expected_state_meta: *self.state_meta.tbs(),
            maximum_bytes: self.limits.backup_max_bytes,
            database_max_bytes: self.limits.database_max_bytes,
            expected_stream_bytes: None,
            scan,
            slice_records: BACKUP_SLICE_RECORDS,
            slice_bytes: BACKUP_SLICE_BYTES,
            scratch_allowance: SCRATCH_TRANSACTION_ALLOWANCE,
            phase: BackupPhase::Accounting(Box::new(Accounting {
                scratch: None,
                verification,
                stream_bytes: BACKUP_FIXED_STREAM_BYTES,
            })),
        });
        Ok(())
    }

    pub(crate) fn backup_is_active(&self) -> bool {
        self.backup_job.is_some()
    }

    /// Runs one bounded slice of the active backup. A receipt means the
    /// artifact is published; an error means the job is gone, its temporary
    /// and scratch removed, and nothing was published.
    pub(crate) fn service_backup(&mut self) -> Result<Option<BackupReceipt>, StorageError> {
        let mut job = self.backup_job.take().ok_or(StorageError::StaleState)?;
        let receipt = job.service(self)?;
        if receipt.is_none() {
            self.backup_job = Some(job);
        }
        Ok(receipt)
    }

    /// Drops the active backup before it publishes: the temporary and the
    /// scratch are removed with it.
    pub(crate) fn abandon_backup(&mut self) {
        self.backup_job = None;
    }
}

#[cfg(test)]
impl StorageEngine {
    /// Names the active backup's phase.
    pub(crate) fn backup_phase(&self) -> Option<&'static str> {
        self.backup_job.as_ref().map(|job| job.phase.name())
    }

    /// Shrinks the active backup's slice budget so a small corpus takes
    /// several slices per phase.
    pub(crate) fn set_backup_slice_budget(
        &mut self,
        records: usize,
        bytes: usize,
    ) -> Result<(), StorageError> {
        let job = self.backup_job.as_mut().ok_or(StorageError::StaleState)?;
        job.slice_records = records;
        job.slice_bytes = bytes;
        Ok(())
    }

    /// Replaces the allowance charged to every scratch transaction of the
    /// active backup.
    pub(crate) fn set_backup_scratch_allowance(&mut self, bytes: u64) -> Result<(), StorageError> {
        let job = self.backup_job.as_mut().ok_or(StorageError::StaleState)?;
        job.scratch_allowance = bytes;
        Ok(())
    }

    /// Lowers the stream and logical ceilings the active backup is admitted
    /// under, so a small corpus can exhaust them.
    pub(crate) fn set_backup_maximum_bytes(&mut self, bytes: u64) -> Result<(), StorageError> {
        let job = self.backup_job.as_mut().ok_or(StorageError::StaleState)?;
        job.maximum_bytes = bytes;
        job.database_max_bytes = bytes;
        Ok(())
    }
}

impl BackupJob {
    /// The stream ceiling this job was admitted under; a later limit change
    /// does not move it.
    #[cfg(test)]
    pub(super) const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    fn service(&mut self, engine: &StorageEngine) -> Result<Option<BackupReceipt>, StorageError> {
        let phase = std::mem::replace(&mut self.phase, BackupPhase::Finished);
        let (next, receipt) = match phase {
            BackupPhase::Accounting(state) => (self.account(engine, state)?, None),
            BackupPhase::Resolving(state) => (self.resolve(state)?, None),
            BackupPhase::Admitting => (self.admit(engine)?, None),
            BackupPhase::Copying(state) => (self.copy(engine, state)?, None),
            BackupPhase::Sealing(state) => (self.seal(engine, state)?, None),
            BackupPhase::Verifying(state) => (self.verify(engine, state)?, None),
            BackupPhase::Publishing(state) => (BackupPhase::Finished, Some(publish(state)?)),
            BackupPhase::Finished => return Err(StorageError::StaleState),
        };
        self.phase = next;
        Ok(receipt)
    }

    /// Decrypts, checks, counts and records the references of one slice of
    /// the cut. The last slice binds the recomputed counters to the
    /// authenticated StateMeta and fixes the exact stream length.
    // agenc-review: focus owner=storage reviewed=2026-09-18 reason=one slice loop keeps the per-record grammar the running counters and the bounded scratch publication in one auditable order
    fn account(
        &mut self,
        engine: &StorageEngine,
        mut state: Box<Accounting>,
    ) -> Result<BackupPhase, StorageError> {
        let slice = self
            .scan
            .next_all_slice(self.slice_records, self.slice_bytes)?;
        let faults = engine.state_directory.faults();
        let mut rows = Vec::new();
        rows.try_reserve_exact(slice.rows.len())
            .map_err(|_| StorageError::AllocationFailed)?;
        for (table, key, sealed_record) in slice.rows {
            faults.check(StorageFaultSite::BackupRecord, StorageFaultBoundary::Before)?;
            let record = source_record(table, key, sealed_record)?;
            let plaintext = state.verification.observe(&engine.master_key, &record)?;
            validate_domain_row(engine, &record, plaintext.expose_for_storage_codec())?;
            if table.is_integrity_tracked() {
                rows.push((
                    scratch_identity(table, record.stored_key())?,
                    record_references(
                        table,
                        record.stored_key(),
                        plaintext.expose_for_storage_codec(),
                    )?,
                ));
            }
            state.stream_bytes = state
                .stream_bytes
                .checked_add(backup_record_charge(
                    record.stored_key().as_bytes().len(),
                    record.sealed_record().len(),
                )?)
                .ok_or(StorageError::Overflow)?;
            if state.stream_bytes > self.maximum_bytes
                || state.verification.logical_database_bytes() > self.database_max_bytes
            {
                return Err(StorageError::LimitExceeded);
            }
            faults.check(StorageFaultSite::BackupRecord, StorageFaultBoundary::After)?;
        }
        let mut scratch = match state.scratch.take() {
            Some(scratch) => scratch,
            None => ReferenceScratch::create(engine, self.scratch_allowance)?,
        };
        scratch.record(engine, &rows)?;
        if !slice.complete {
            state.scratch = Some(scratch);
            return Ok(BackupPhase::Accounting(state));
        }
        let (_logical_database_bytes, state_meta) =
            state.verification.finish(state.stream_bytes)?;
        if state_meta.tbs() != &self.expected_state_meta {
            return Err(StorageError::StaleState);
        }
        self.expected_stream_bytes = Some(state.stream_bytes);
        self.scan.reset();
        Ok(BackupPhase::Resolving(Resolving {
            scratch,
            cursor: None,
        }))
    }

    fn resolve(&self, mut state: Resolving) -> Result<BackupPhase, StorageError> {
        let complete =
            state
                .scratch
                .resolve_slice(&mut state.cursor, self.slice_records, self.slice_bytes)?;
        if complete {
            Ok(BackupPhase::Admitting)
        } else {
            Ok(BackupPhase::Resolving(state))
        }
    }

    /// Creates the temporary and admits it at `R(F) + O` on the backup
    /// filesystem, then writes the fixed prefix.
    fn admit(&mut self, engine: &StorageEngine) -> Result<BackupPhase, StorageError> {
        let expected = self.expected_stream_bytes.ok_or(StorageError::StaleState)?;
        let destination = self.destination.take().ok_or(StorageError::StaleState)?;
        let output = destination.create_output(engine.state_directory.faults())?;
        crate::platform::admit_backup_output(
            output.file(),
            expected,
            engine.limits.fixed_reserve_bytes,
            engine.limits.reserve_percent,
            &engine.state_directory.faults(),
        )?;
        let writer_file = output
            .file()
            .try_clone()
            .map_err(crate::filesystem_rejected)?;
        let writer = BackupStreamWriter::start(writer_file, &self.header, expected)?;
        Ok(BackupPhase::Copying(Copying { writer, output }))
    }

    fn copy(
        &mut self,
        engine: &StorageEngine,
        mut state: Copying,
    ) -> Result<BackupPhase, StorageError> {
        let slice = self
            .scan
            .next_all_slice(self.slice_records, self.slice_bytes)?;
        let faults = engine.state_directory.faults();
        for (table, key, sealed_record) in slice.rows {
            faults.check(StorageFaultSite::BackupRecord, StorageFaultBoundary::Before)?;
            state
                .writer
                .write_record(&source_record(table, key, sealed_record)?)?;
            faults.check(StorageFaultSite::BackupRecord, StorageFaultBoundary::After)?;
        }
        if slice.complete {
            Ok(BackupPhase::Sealing(state))
        } else {
            Ok(BackupPhase::Copying(state))
        }
    }

    /// Writes the trailer, requires the temporary to be exactly `O` bytes
    /// long, and opens the post-write pass on the same inode.
    fn seal(
        &mut self,
        engine: &StorageEngine,
        state: Copying,
    ) -> Result<BackupPhase, StorageError> {
        let expected = self.expected_stream_bytes.ok_or(StorageError::StaleState)?;
        let (writer_file, trailer) = state.writer.finish(&self.signing_key)?;
        drop(writer_file);
        let output = state.output;
        let actual_bytes = output
            .file()
            .metadata()
            .map_err(crate::filesystem_rejected)?
            .len();
        if actual_bytes != expected {
            return Err(StorageError::StaleState);
        }
        let mut reader = output
            .file()
            .try_clone()
            .map_err(crate::filesystem_rejected)?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(crate::filesystem_rejected)?;
        let trusted = BackupTrustKey::new(self.signing_key.public_key())?;
        let verifier = BackupStreamVerifier::start(
            reader,
            &engine.guard_root_key,
            &[trusted],
            self.maximum_bytes,
        )?;
        Ok(BackupPhase::Verifying(Box::new(Verifying {
            output,
            trailer,
            verifier,
            actual_bytes,
        })))
    }

    /// Verifies one slice of the temporary; the last slice binds the verified
    /// facts to the captured cut.
    fn verify(
        &mut self,
        engine: &StorageEngine,
        mut state: Box<Verifying>,
    ) -> Result<BackupPhase, StorageError> {
        let complete = state.verifier.step(
            &engine.master_key,
            &engine.state_directory.faults(),
            self.slice_records,
            self.slice_bytes,
        )?;
        if !complete {
            return Ok(BackupPhase::Verifying(state));
        }
        let verified = state.verifier.finish()?;
        if (
            verified.stream_bytes,
            verified.trailer,
            verified.state_meta.tbs(),
            verified.header.encode()?,
        ) != (
            state.actual_bytes,
            state.trailer,
            &self.expected_state_meta,
            self.header.encode()?,
        ) {
            return Err(StorageError::AuthenticationFailed);
        }
        Ok(BackupPhase::Publishing(Publishing {
            output: state.output,
            trailer: state.trailer,
            stream_bytes: state.actual_bytes,
        }))
    }
}

/// Renames the verified inode in place and reports the receipt.
///
/// The one full verification ran on the descriptor that the rename carries
/// under the final name; publication proves by inode identity that the final
/// name refers to that verified file, so no failure after the rename leaves
/// the final name occupied.
fn publish(state: Publishing) -> Result<BackupReceipt, StorageError> {
    let mut published = state.output.publish()?;
    let published_bytes = published
        .file_mut()
        .metadata()
        .map_err(crate::filesystem_rejected)?
        .len();
    if published_bytes != state.stream_bytes {
        return Err(StorageError::AuthenticationFailed);
    }
    Ok(BackupReceipt {
        stream_bytes: state.stream_bytes,
        record_count: state.trailer.record_count,
        stream_digest: state.trailer.stream_digest,
    })
}

/// Shapes one row of the cut into the record the stream carries.
fn source_record(
    table: TableId,
    key: Vec<u8>,
    sealed_record: Vec<u8>,
) -> Result<BackupRecord, StorageError> {
    let stored_key = StoredKey::new(key)?;
    let record_schema =
        crate::validate_sealed_record(table, &stored_key, &sealed_record)?.record_schema();
    BackupRecord::new(table, stored_key, record_schema, sealed_record)
}

/// The startup scan's per-row domain checks: reference legality, required
/// references and the private index binding.
fn validate_domain_row(
    engine: &StorageEngine,
    record: &BackupRecord,
    plaintext: &[u8],
) -> Result<(), StorageError> {
    if crate::table_schema(record.table()).codec() != crate::RecordCodecKind::Domain {
        return Ok(());
    }
    let value = crate::PersistentRecordValue::decode(record.table(), plaintext)?;
    validate_recovered_domain_record(record.table(), &value)?;
    engine.validate_recovered_index_binding(record.table(), record.stored_key(), &value)
}

fn scratch_identity(table: TableId, stored_key: &StoredKey) -> Result<Vec<u8>, StorageError> {
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

/// References are keyed by the record's ordinal in cut order and the
/// reference's index, so a record's identity is stored once however many
/// references it carries.
fn reference_key(ordinal: u64, index: usize) -> Result<[u8; 12], StorageError> {
    let index = u32::try_from(index).map_err(|_| StorageError::Overflow)?;
    let mut key = [0_u8; 12];
    key.get_mut(..8)
        .ok_or(StorageError::Overflow)?
        .copy_from_slice(&ordinal.to_be_bytes());
    key.get_mut(8..)
        .ok_or(StorageError::Overflow)?
        .copy_from_slice(&index.to_be_bytes());
    Ok(key)
}

/// The backup scratch is deliberately not admitted against the filesystem
/// reserve: it lives only for the phases that build and read it and is
/// unlinked before the output is admitted at `R(F) + O`, so the Section 28.7
/// backup boundaries hold whether or not the state and backup directories
/// share a filesystem. Every transaction is still bounded by the allowance.
struct UnreservedScratch;

impl ScratchAdmission for UnreservedScratch {
    fn admit_scratch(&self, _allowance: AllocationAllowance) -> Result<(), StorageError> {
        Ok(())
    }
}

static UNRESERVED_SCRATCH: UnreservedScratch = UnreservedScratch;

/// Reference scratch over the shared [`ScratchDatabase`]: every transaction
/// is a bounded, two-phase publication under one allowance, created with
/// regions a quarter of it. A refusal is the determinate `AllowanceRefused`
/// with its phase and leaves the scratch exactly as it was; a real I/O
/// failure discards the scratch with the job.
struct ReferenceScratch {
    database: ScratchDatabase<'static>,
    ordinal: u64,
}

impl ReferenceScratch {
    fn create(engine: &StorageEngine, allowance: u64) -> Result<Self, StorageError> {
        let database = ScratchDatabase::create_with_allowance(
            engine.state_directory.scratch_location()?,
            &UNRESERVED_SCRATCH,
            &[SCRATCH_RECORDS_TABLE, SCRATCH_REFERENCES_TABLE],
            AllocationAllowance::new(allowance),
        )?;
        Ok(Self {
            database,
            ordinal: 0,
        })
    }

    /// Records one slice's identities and references in one bounded
    /// publication; an empty slice publishes nothing.
    fn record(
        &mut self,
        engine: &StorageEngine,
        rows: &[(Vec<u8>, Vec<RecordReference>)],
    ) -> Result<(), StorageError> {
        if rows.is_empty() {
            return Ok(());
        }
        let first_ordinal = self.ordinal;
        let next_ordinal = self.publish_bounded(engine, |transaction| {
            let mut records = transaction
                .open_table(SCRATCH_RECORDS_TABLE)
                .map_err(map_table_error)?;
            let mut references = transaction
                .open_table(SCRATCH_REFERENCES_TABLE)
                .map_err(map_table_error)?;
            let mut ordinal = first_ordinal;
            for (identity, targets) in rows {
                let empty: &[u8] = &[];
                if records
                    .insert(identity.as_slice(), empty)
                    .map_err(map_write_error)?
                    .is_some()
                {
                    return Err(StorageError::StaleState);
                }
                for (index, target) in targets.iter().enumerate() {
                    let key = reference_key(ordinal, index)?;
                    let target = scratch_identity(target.table(), target.key())?;
                    references
                        .insert(key.as_slice(), target.as_slice())
                        .map_err(map_write_error)?;
                }
                ordinal = ordinal.checked_add(1).ok_or(StorageError::Overflow)?;
            }
            Ok(ordinal)
        })?;
        self.ordinal = next_ordinal;
        Ok(())
    }

    /// One bounded transaction through the shared scratch: charged to the
    /// allowance before it allocates, prepared into new pages, and published
    /// two-phase.
    fn publish_bounded<T>(
        &mut self,
        engine: &StorageEngine,
        fill: impl FnOnce(&redb::BoundedWriteTransaction) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let faults = engine.state_directory.faults();
        faults.check(StorageFaultSite::Allocation, StorageFaultBoundary::Before)?;
        let mut transaction = self.database.begin()?;
        transaction.set_two_phase_commit(true);
        let value = fill(&transaction)?;
        self.database.publish(transaction)?;
        faults.check(StorageFaultSite::Allocation, StorageFaultBoundary::After)?;
        Ok(value)
    }

    /// Resolves at most `maximum_records` references or `maximum_bytes` of
    /// scratch rows from the cursor and reports whether every reference has
    /// been resolved.
    fn resolve_slice(
        &self,
        cursor: &mut Option<Vec<u8>>,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<bool, StorageError> {
        if maximum_records == 0 || maximum_bytes == 0 {
            return Err(StorageError::LimitExceeded);
        }
        let read = self.database.read()?;
        let records = read
            .open_table(SCRATCH_RECORDS_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let references = read
            .open_table(SCRATCH_REFERENCES_TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let range = match cursor.as_deref() {
            Some(previous) => references.range::<&[u8]>((Excluded(previous), Unbounded)),
            None => {
                let bounds: (Bound<&[u8]>, Bound<&[u8]>) = (Unbounded, Unbounded);
                references.range::<&[u8]>(bounds)
            }
        }
        .map_err(|_| StorageError::DatabaseRejected)?;
        let mut checked = 0_usize;
        let mut bytes = 0_usize;
        for entry in range {
            let (key, target) = entry.map_err(|_| StorageError::DatabaseRejected)?;
            if records
                .get(target.value())
                .map_err(|_| StorageError::DatabaseRejected)?
                .is_none()
            {
                return Err(StorageError::StaleState);
            }
            bytes = bytes
                .checked_add(key.value().len())
                .and_then(|bytes| bytes.checked_add(target.value().len()))
                .ok_or(StorageError::Overflow)?;
            checked = checked.checked_add(1).ok_or(StorageError::Overflow)?;
            *cursor = Some(key.value().to_vec());
            if checked >= maximum_records || bytes >= maximum_bytes {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
#[path = "backup_job/tests/phases.rs"]
mod phase_tests;
