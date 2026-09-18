//! Bounded verification scratch: one descriptor-bound location, fresh exact-filesystem
//! admission before every transaction, and a typed allowance on each of them.
//!
//! Startup integrity reconstruction, reference validation, stopped-daemon inspection, checkpoint
//! readback and construction verification all rebuild a tracked-record index in a private redb
//! scratch file. Each of them used to hold one unbounded write transaction over the whole current
//! record set, and the checkpoint ran it after publication, so a large database could turn a
//! consistent checkpoint into an uncertain one by running out of disk inside its own verifier.
//! Here every scratch transaction is admitted against the Section 19.3 `R(F) + G` gate
//! immediately before it begins, runs under an [`AllocationAllowance`] of `G`, and covers at most
//! [`SCRATCH_SLICE_ROWS`] rows. An allowance refusal is [`StorageError::AllowanceRefused`], an
//! admission refusal is [`StorageError::FilesystemRejected`], both are determinate, and neither is
//! ever reported as stale state or as an uncertain commit.
//!
//! The scratch lives in the daemon's private mode-0700 state directory, on the qualified
//! filesystem the reserve is measured on, so its bytes count against the same reserve
//! (Section 23.5.3) and it is removed through the retained directory descriptor; inspection uses
//! an anonymous inode on the same filesystem. Nothing in a scratch is trusted across a restart,
//! and its close persists nothing: the allocator state is offered a zero allowance on purpose, so
//! redb's drop cannot run its unmetered close transaction and the file is unlinked as it stands.

use std::fs::File;

use redb::{
    AllocationAllowance, BoundedWriteTransaction, CommitError, Database, Error as RedbError,
    ReadTransaction, ReadableDatabase as _, TableDefinition, TransactionError,
};
use rustix::fs::{AtFlags, unlinkat};

use crate::bounded::{map_table_error, map_write_error, refusal_phase};
use crate::{MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, StorageError};

/// Allowance of one scratch transaction: the fixed Section 19.3 growth ceiling `G`, the same
/// quantity the exact-filesystem gate requires above the reserve before the transaction begins.
pub(crate) const SCRATCH_TRANSACTION_ALLOWANCE: AllocationAllowance =
    AllocationAllowance::new(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH);
/// Rows one scratch transaction covers before it is published and the next one is admitted.
///
/// A full current-record set is never one transaction: it is at most this many rows, or
/// [`SCRATCH_SLICE_BYTES`] of them, at a time, the same row count the checkpoint scan uses.
pub const SCRATCH_SLICE_ROWS: usize = 4_096;
/// Logical key and value bytes one scratch transaction covers before it is published.
///
/// The allowance account charges every copy-on-write rewrite of a leaf without refund, so a
/// transaction's charge grows with its rows times the leaf size its rows produce, not with its
/// row bytes: a slice of maximum stored keys charges about fourteen times its logical bytes.
/// Bounding the logical bytes keeps the charge of any slice, whatever its key shape, far inside
/// the allowance; it also bounds the resident row buffer a slice holds.
pub const SCRATCH_SLICE_BYTES: usize = 1_048_576;
/// Resident redb cache of one scratch database.
pub(crate) const SCRATCH_CACHE_BYTES: usize = 8 * 1_048_576;
/// Region size every scratch database is created with: a quarter of the allowance.
///
/// A bounded transaction charges every file extension at its full length before it happens,
/// and redb grows a full file by up to two regions at once, so a bounded database must be
/// created with regions of at most half its allowance or no transaction could ever extend it
/// past its first region. A quarter leaves the slice's own pages room beside the extension.
const SCRATCH_REGION_BYTES: u64 = 64 * 1_048_576;
/// Freed-page records one bounded reclamation publication removes.
const SCRATCH_RECLAIM_RECORDS: usize = 64;
/// Reclamation publications one slice may need before the pages it freed are back in the
/// allocator; each publication makes monotonic progress, so the loop always stops.
const SCRATCH_RECLAIM_ROUNDS: usize = 4;

/// A scratch table: raw keys and values, exactly as the store's own tables.
pub(crate) type ScratchTable = TableDefinition<'static, &'static [u8], &'static [u8]>;

/// Fresh exact-filesystem admission of one bounded scratch transaction.
pub(crate) trait ScratchAdmission {
    /// Admits a transaction that may grow the scratch filesystem by at most `allowance`, sampled
    /// immediately before the transaction begins.
    fn admit_scratch(&self, allowance: AllocationAllowance) -> Result<(), StorageError>;
}

/// Where a scratch database lives and how it is removed.
pub(crate) enum ScratchLocation {
    /// A create-exclusive mode-0600 entry of the private state directory, unlinked by name
    /// through the retained directory descriptor.
    Exclusive {
        /// The freshly created, empty scratch file.
        file: File,
        /// The directory descriptor the entry is unlinked through.
        directory: File,
        /// The random entry name.
        name: String,
    },
    /// An anonymous `O_TMPFILE` inode on the same filesystem, gone with its last descriptor.
    Anonymous {
        /// The freshly created, empty, unnamed scratch file.
        file: File,
    },
}

/// Metered disk and memory ownership of one scratch database.
///
/// Every field is an observation of the real scratch, not of its logical row bytes: the charges
/// come from the allowance account that debits every page extent and file extension before it
/// happens, and the file lengths from the scratch descriptor itself.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScratchUsage {
    /// Bounded transactions published, including the one that created the tables.
    pub transactions: u64,
    /// Bounded reclamation publications that returned freed pages to the scratch allocator.
    pub reclamations: u64,
    /// Bytes every published transaction charged to its allowance, summed: an upper bound of
    /// the physical growth all of them together could have caused.
    pub charged_bytes: u64,
    /// Greatest charge of one transaction: the peak one allowance had to cover.
    pub peak_transaction_bytes: u64,
    /// Greatest resident row buffer one slice held before its transaction began.
    pub peak_buffer_bytes: u64,
    /// Scratch file length right after redb created it, before any table existed.
    pub creation_bytes: u64,
    /// Greatest scratch file length observed: the peak disk the scratch occupied.
    pub peak_file_bytes: u64,
    /// Pages the bounded reclamations returned to the scratch allocator.
    pub reclaimed_pages: u64,
    /// Resident redb cache the scratch database was configured with.
    pub cache_bytes: u64,
    /// Allowance each transaction was bounded by.
    pub allowance_bytes: u64,
}

/// One private redb scratch database whose every transaction is admitted and bounded.
pub(crate) struct ScratchDatabase<'a> {
    database: Option<Database>,
    file: File,
    cleanup: Option<(File, String)>,
    admission: &'a dyn ScratchAdmission,
    allowance: AllocationAllowance,
    usage: ScratchUsage,
}

impl<'a> ScratchDatabase<'a> {
    /// Creates the scratch file and its tables under the fixed allowance.
    pub(crate) fn create(
        location: ScratchLocation,
        admission: &'a dyn ScratchAdmission,
        tables: &[ScratchTable],
    ) -> Result<Self, StorageError> {
        Self::create_with_allowance(location, admission, tables, SCRATCH_TRANSACTION_ALLOWANCE)
    }

    /// Creates the scratch file and its tables, bounding every transaction by `allowance`.
    ///
    /// Creation itself is admitted like a transaction, because redb writes the file header and
    /// first region before any transaction exists; the transaction that opens the tables is then
    /// admitted and bounded like every later one.
    pub(crate) fn create_with_allowance(
        location: ScratchLocation,
        admission: &'a dyn ScratchAdmission,
        tables: &[ScratchTable],
        allowance: AllocationAllowance,
    ) -> Result<Self, StorageError> {
        Self::create_opened(location, admission, tables, allowance, |builder, file| {
            builder.create_file(file)
        })
    }

    /// Creates the scratch through `open`, which receives the configured builder and the
    /// scratch descriptor; production opens the file itself, tests may wrap it in a backend
    /// that fails on demand.
    fn create_opened(
        location: ScratchLocation,
        admission: &'a dyn ScratchAdmission,
        tables: &[ScratchTable],
        allowance: AllocationAllowance,
        open: impl FnOnce(&redb::Builder, File) -> Result<Database, redb::DatabaseError>,
    ) -> Result<Self, StorageError> {
        let (file, cleanup) = match location {
            ScratchLocation::Exclusive {
                file,
                directory,
                name,
            } => (file, Some((directory, name))),
            ScratchLocation::Anonymous { file } => (file, None),
        };
        let mut scratch = Self {
            database: None,
            file,
            cleanup,
            admission,
            allowance,
            usage: ScratchUsage {
                cache_bytes: u64::try_from(SCRATCH_CACHE_BYTES)
                    .map_err(|_| StorageError::Overflow)?,
                allowance_bytes: allowance.bytes(),
                ..ScratchUsage::default()
            },
        };
        // From here on a refusal or failure drops `scratch`, which removes the entry.
        admission.admit_scratch(allowance)?;
        let redb_file = scratch
            .file
            .try_clone()
            .map_err(crate::filesystem_rejected)?;
        let mut builder = redb::Builder::new();
        builder.set_cache_size(SCRATCH_CACHE_BYTES);
        builder.set_region_size(SCRATCH_REGION_BYTES);
        scratch.database =
            Some(open(&builder, redb_file).map_err(|_| StorageError::DatabaseRejected)?);
        scratch.usage.creation_bytes = scratch.file_length()?;
        scratch.usage.peak_file_bytes = scratch.usage.creation_bytes;
        let transaction = scratch.begin()?;
        for table in tables {
            let _created = transaction.open_table(*table).map_err(map_table_error)?;
        }
        scratch.publish(transaction)?;
        Ok(scratch)
    }

    fn database(&self) -> Result<&Database, StorageError> {
        self.database.as_ref().ok_or(StorageError::Unavailable)
    }

    fn file_length(&self) -> Result<u64, StorageError> {
        self.file
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(crate::filesystem_rejected)
    }

    fn observe_file_length(&mut self) -> Result<(), StorageError> {
        let length = self.file_length()?;
        self.usage.peak_file_bytes = self.usage.peak_file_bytes.max(length);
        Ok(())
    }

    /// Records the resident row buffer one slice held before its transaction began.
    pub(crate) fn observe_buffer(&mut self, bytes: u64) {
        self.usage.peak_buffer_bytes = self.usage.peak_buffer_bytes.max(bytes);
    }

    /// Admits and begins one bounded write transaction.
    ///
    /// The transaction is single-phase: nothing in a scratch survives a restart, so it needs no
    /// second header flush.
    pub(crate) fn begin(&self) -> Result<BoundedWriteTransaction, StorageError> {
        self.admission.admit_scratch(self.allowance)?;
        self.database()?
            .begin_write_bounded(self.allowance)
            .map_err(|error: TransactionError| match error {
                TransactionError::Storage(error) => map_write_error(error),
                _ => StorageError::DatabaseRejected,
            })
    }

    /// Prepares and publishes one bounded transaction, records its charge, and reclaims the
    /// pages it freed in bounded publications of their own.
    pub(crate) fn publish(
        &mut self,
        transaction: BoundedWriteTransaction,
    ) -> Result<(), StorageError> {
        let prepared = transaction.prepare().map_err(commit_failure)?;
        let charged = prepared
            .allowance_charged()
            .map_err(|_| StorageError::DatabaseRejected)?;
        prepared.publish().map_err(commit_failure)?;
        self.usage.transactions = self
            .usage
            .transactions
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        self.usage.charged_bytes = self
            .usage
            .charged_bytes
            .checked_add(charged)
            .ok_or(StorageError::Overflow)?;
        self.usage.peak_transaction_bytes = self.usage.peak_transaction_bytes.max(charged);
        self.observe_file_length()?;
        self.reclaim()
    }

    /// Returns freed pages to the scratch allocator so the file does not grow by every page a
    /// slice rewrote; each publication is admitted and bounded like a slice.
    fn reclaim(&mut self) -> Result<(), StorageError> {
        for _round in 0..SCRATCH_RECLAIM_ROUNDS {
            self.admission.admit_scratch(self.allowance)?;
            let progress = self
                .database()?
                .reclaim_bounded(self.allowance, SCRATCH_RECLAIM_RECORDS)
                .map_err(|error: RedbError| match error {
                    RedbError::Allowance(refusal) => {
                        StorageError::AllowanceRefused(refusal_phase(refusal))
                    }
                    _ => StorageError::DatabaseRejected,
                })?;
            self.usage.reclamations = self
                .usage
                .reclamations
                .checked_add(1)
                .ok_or(StorageError::Overflow)?;
            self.usage.reclaimed_pages = self
                .usage
                .reclaimed_pages
                .checked_add(u64::try_from(progress.pages).map_err(|_| StorageError::Overflow)?)
                .ok_or(StorageError::Overflow)?;
            self.observe_file_length()?;
            if !progress.remaining || progress.records == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Opens one read transaction over the published scratch state.
    pub(crate) fn read(&self) -> Result<ReadTransaction, StorageError> {
        self.database()?
            .begin_read()
            .map_err(|_| StorageError::DatabaseRejected)
    }

    /// Closes the scratch without persisting anything, removes its entry, and reports the
    /// complete metered usage.
    pub(crate) fn close(mut self) -> ScratchUsage {
        self.release();
        self.usage
    }

    fn release(&mut self) {
        if let Some(database) = self.database.take() {
            // Nothing in the scratch survives, so its allocator state is never written: the zero
            // allowance refuses the close transaction before it allocates, and after that redb's
            // drop only flushes and closes the descriptor instead of running its unmetered close.
            let _ = database.persist_allocator_state_bounded(AllocationAllowance::new(0));
            let _ = self.observe_file_length();
            drop(database);
        }
        if let Some((directory, name)) = self.cleanup.take() {
            let _ = unlinkat(&directory, name.as_str(), AtFlags::empty());
        }
    }
}

impl Drop for ScratchDatabase<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Maps the failure of a scratch preparation or publication. A refusal is the shared determinate
/// allowance refusal with its phase; anything else is the scratch database itself, which is a
/// determinate rejection here because nothing in a scratch is ever trusted, where the live
/// database's `map_preparation_error` must keep the same failure indeterminate.
fn commit_failure(error: CommitError) -> StorageError {
    match error {
        CommitError::Allowance(refusal) => StorageError::AllowanceRefused(refusal_phase(refusal)),
        CommitError::Storage(error) => map_write_error(error),
        _ => StorageError::DatabaseRejected,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::io::Error as IoError;
    use std::os::unix::fs::FileExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use redb::{ReadableTableMetadata as _, StorageBackend};
    use rustix::fs::{CWD, Mode, OFlags, openat};

    use super::*;
    use crate::FilesystemCause;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const TABLE: ScratchTable = TableDefinition::new("scratch_rows");
    const ROW_VALUE: [u8; 36] = [7_u8; 36];

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create(label: &str) -> Result<Self, StorageError> {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agenc-scratch-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).map_err(crate::filesystem_rejected)?;
            Ok(Self { path })
        }

        fn exclusive(&self, name: &str) -> Result<ScratchLocation, StorageError> {
            Ok(ScratchLocation::Exclusive {
                file: OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(self.path.join(name))
                    .map_err(crate::filesystem_rejected)?,
                directory: File::open(&self.path).map_err(crate::filesystem_rejected)?,
                name: name.to_owned(),
            })
        }

        fn anonymous(&self) -> Result<ScratchLocation, StorageError> {
            let file = openat(
                CWD,
                &self.path,
                OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(crate::filesystem_rejected)?;
            Ok(ScratchLocation::Anonymous {
                file: File::from(file),
            })
        }

        fn entries(&self) -> Result<Vec<String>, StorageError> {
            let mut names = fs::read_dir(&self.path)
                .map_err(crate::filesystem_rejected)?
                .map(|entry| {
                    entry
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .map_err(crate::filesystem_rejected)
                })
                .collect::<Result<Vec<_>, _>>()?;
            names.sort();
            Ok(names)
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

    /// Admits every call until the configured one, which refuses like a filesystem that an
    /// external writer filled between two slices; records what every call asked for.
    struct CountingAdmission {
        calls: AtomicU64,
        refuse_from: Option<u64>,
        unexpected_allowance: AtomicU64,
        expected: AllocationAllowance,
    }

    impl CountingAdmission {
        fn new(refuse_from: Option<u64>, expected: AllocationAllowance) -> Self {
            Self {
                calls: AtomicU64::new(0),
                refuse_from,
                unexpected_allowance: AtomicU64::new(0),
                expected,
            }
        }

        fn calls(&self) -> u64 {
            self.calls.load(Ordering::Acquire)
        }
    }

    impl ScratchAdmission for CountingAdmission {
        fn admit_scratch(&self, allowance: AllocationAllowance) -> Result<(), StorageError> {
            let call = self
                .calls
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |calls| {
                    calls.checked_add(1)
                })
                .map_err(|_| StorageError::Overflow)?
                .checked_add(1)
                .ok_or(StorageError::Overflow)?;
            if allowance != self.expected {
                self.unexpected_allowance.store(call, Ordering::Release);
            }
            if self.refuse_from.is_some_and(|from| call >= from) {
                return Err(StorageError::FilesystemRejected(
                    FilesystemCause::InsufficientCapacity,
                ));
            }
            Ok(())
        }
    }

    /// A real file whose writes start failing after a configured count: a genuine I/O
    /// failure, which is never an allowance refusal.
    #[derive(Debug)]
    struct FailingBackend {
        file: File,
        writes_left: AtomicU64,
    }

    impl FailingBackend {
        fn new(file: File, writes_left: u64) -> Self {
            Self {
                file,
                writes_left: AtomicU64::new(writes_left),
            }
        }
    }

    impl StorageBackend for FailingBackend {
        fn len(&self) -> Result<u64, IoError> {
            self.file.metadata().map(|metadata| metadata.len())
        }

        fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), IoError> {
            self.file.read_exact_at(out, offset)
        }

        fn set_len(&self, len: u64) -> Result<(), IoError> {
            self.file.set_len(len)
        }

        fn sync_data(&self) -> Result<(), IoError> {
            self.file.sync_data()
        }

        fn write(&self, offset: u64, data: &[u8]) -> Result<(), IoError> {
            let admitted = self
                .writes_left
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                    left.checked_sub(1)
                })
                .is_ok();
            if !admitted {
                return Err(IoError::other("injected scratch write failure"));
            }
            self.file.write_all_at(data, offset)
        }
    }

    fn row_key(index: u32, key_bytes: usize) -> Vec<u8> {
        let mut key = vec![0_u8; key_bytes];
        for (slot, byte) in key.iter_mut().zip(index.to_be_bytes()) {
            *slot = byte;
        }
        key
    }

    /// Publishes one slice of `rows` fixed-shape rows and returns its charge.
    fn publish_rows(
        scratch: &mut ScratchDatabase<'_>,
        first: u32,
        rows: u32,
        key_bytes: usize,
    ) -> Result<u64, StorageError> {
        let before = scratch.usage.charged_bytes;
        let transaction = scratch.begin()?;
        {
            let mut table = transaction.open_table(TABLE).map_err(map_table_error)?;
            for index in first..first.checked_add(rows).ok_or(StorageError::Overflow)? {
                table
                    .insert(row_key(index, key_bytes).as_slice(), ROW_VALUE.as_slice())
                    .map_err(map_write_error)?;
            }
        }
        scratch.publish(transaction)?;
        scratch
            .usage
            .charged_bytes
            .checked_sub(before)
            .ok_or(StorageError::Overflow)
    }

    fn row_count(scratch: &ScratchDatabase<'_>) -> Result<u64, StorageError> {
        scratch
            .read()?
            .open_table(TABLE)
            .map_err(|_| StorageError::DatabaseRejected)?
            .len()
            .map_err(|_| StorageError::DatabaseRejected)
    }

    /// Runs the fixed workload (creation, then two 64-row slices) under `allowance`.
    fn fixed_workload(
        directory: &TestDirectory,
        name: &str,
        allowance: AllocationAllowance,
    ) -> Result<ScratchUsage, StorageError> {
        let admission = CountingAdmission::new(None, allowance);
        let mut scratch = ScratchDatabase::create_with_allowance(
            directory.exclusive(name)?,
            &admission,
            &[TABLE],
            allowance,
        )?;
        publish_rows(&mut scratch, 0, 64, 32)?;
        publish_rows(&mut scratch, 64, 64, 32)?;
        Ok(scratch.close())
    }

    #[test]
    fn zero_exact_one_less_and_one_more_allowances_bound_a_fixed_workload()
    -> Result<(), StorageError> {
        let directory = TestDirectory::create("allowance-boundary")?;
        let measured = fixed_workload(&directory, "measure.redb", SCRATCH_TRANSACTION_ALLOWANCE)?;
        assert!(measured.peak_transaction_bytes > 0);
        assert!(measured.charged_bytes >= measured.peak_transaction_bytes);
        assert_eq!(measured.transactions, 3);
        assert_eq!(
            measured.allowance_bytes,
            MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH
        );
        let peak = measured.peak_transaction_bytes;

        // The charge of a fixed workload on a fresh scratch is deterministic, so the same
        // workload fits exactly at its peak, refuses one byte below it and fits one byte above.
        let exact = fixed_workload(&directory, "exact.redb", AllocationAllowance::new(peak))?;
        assert_eq!(exact.peak_transaction_bytes, peak);
        assert!(matches!(
            fixed_workload(
                &directory,
                "one-less.redb",
                AllocationAllowance::new(peak.checked_sub(1).ok_or(StorageError::Overflow)?),
            ),
            Err(StorageError::AllowanceRefused(_))
        ));
        let one_more = fixed_workload(
            &directory,
            "one-more.redb",
            AllocationAllowance::new(peak.checked_add(1).ok_or(StorageError::Overflow)?),
        )?;
        assert_eq!(one_more.peak_transaction_bytes, peak);
        assert!(matches!(
            fixed_workload(&directory, "zero.redb", AllocationAllowance::new(0)),
            Err(StorageError::AllowanceRefused(_))
        ));
        // Every refused or finished scratch removed its own entry.
        assert_eq!(directory.entries()?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn a_refused_slice_publishes_nothing_and_leaves_the_next_writer_usable()
    -> Result<(), StorageError> {
        let directory = TestDirectory::create("refused-slice")?;
        let measured = fixed_workload(&directory, "measure.redb", SCRATCH_TRANSACTION_ALLOWANCE)?;
        let allowance = AllocationAllowance::new(measured.peak_transaction_bytes);
        let admission = CountingAdmission::new(None, allowance);
        let mut scratch = ScratchDatabase::create_with_allowance(
            directory.exclusive("scratch.redb")?,
            &admission,
            &[TABLE],
            allowance,
        )?;
        publish_rows(&mut scratch, 0, 64, 32)?;
        let published = scratch.usage.transactions;

        // A slice sixty-four times larger than the allowance was measured for is refused, in
        // the mutation phase or in preparation, and nothing of it is visible afterwards.
        assert!(matches!(
            publish_rows(&mut scratch, 1_000, 4_096, 32),
            Err(StorageError::AllowanceRefused(_))
        ));
        assert_eq!(scratch.usage.transactions, published);
        assert_eq!(row_count(&scratch)?, 64);

        // The next writer of the same scratch is unaffected by the refusal: the second slice
        // of the measured workload still fits the measured peak.
        publish_rows(&mut scratch, 64, 64, 32)?;
        assert_eq!(row_count(&scratch)?, 128);
        let usage = scratch.close();
        assert_eq!(
            usage.transactions,
            published.checked_add(1).ok_or(StorageError::Overflow)?
        );
        assert!(usage.peak_transaction_bytes <= measured.peak_transaction_bytes);
        assert_eq!(directory.entries()?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn every_transaction_is_admitted_afresh_with_the_fixed_allowance_and_a_refusal_is_determinate()
    -> Result<(), StorageError> {
        let directory = TestDirectory::create("admission")?;
        let admission = CountingAdmission::new(None, SCRATCH_TRANSACTION_ALLOWANCE);
        let mut scratch =
            ScratchDatabase::create(directory.exclusive("scratch.redb")?, &admission, &[TABLE])?;
        let after_creation = admission.calls();
        // Creation, the table transaction and its reclamation are each admitted.
        assert!(after_creation >= 3);
        publish_rows(&mut scratch, 0, 8, 32)?;
        assert!(admission.calls() > after_creation);
        assert_eq!(admission.unexpected_allowance.load(Ordering::Acquire), 0);
        let usage = scratch.close();
        assert_eq!(usage.transactions, 2);

        // External consumption between two slices: the second slice's own admission refuses,
        // with the filesystem's classified cause, before the slice begins.
        let refusing = CountingAdmission::new(
            Some(
                after_creation
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?,
            ),
            SCRATCH_TRANSACTION_ALLOWANCE,
        );
        let mut scratch =
            ScratchDatabase::create(directory.exclusive("refused.redb")?, &refusing, &[TABLE])?;
        assert_eq!(
            publish_rows(&mut scratch, 0, 8, 32),
            Err(StorageError::FilesystemRejected(
                FilesystemCause::InsufficientCapacity
            ))
        );
        assert_eq!(scratch.usage.transactions, 1);
        drop(scratch);
        // A refusal on creation itself never creates the database.
        let refusing_creation = CountingAdmission::new(Some(1), SCRATCH_TRANSACTION_ALLOWANCE);
        assert!(matches!(
            ScratchDatabase::create(
                directory.exclusive("never.redb")?,
                &refusing_creation,
                &[TABLE]
            )
            .map(|scratch| scratch.usage.transactions),
            Err(StorageError::FilesystemRejected(
                FilesystemCause::InsufficientCapacity
            ))
        ));
        assert_eq!(directory.entries()?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn a_genuine_write_failure_is_the_database_speaking_not_the_allowance()
    -> Result<(), StorageError> {
        let directory = TestDirectory::create("io-failure")?;
        let admission = CountingAdmission::new(None, SCRATCH_TRANSACTION_ALLOWANCE);
        // Enough writes for creation and the table transaction, not for the first slice.
        let mut scratch = ScratchDatabase::create_opened(
            directory.exclusive("failing.redb")?,
            &admission,
            &[TABLE],
            SCRATCH_TRANSACTION_ALLOWANCE,
            |builder, file| builder.create_with_backend(FailingBackend::new(file, 64)),
        )?;
        let mut outcome = Ok(0);
        for slice in 0..8_u32 {
            outcome = publish_rows(&mut scratch, slice.saturating_mul(1_024), 1_024, 32);
            if outcome.is_err() {
                break;
            }
        }
        assert_eq!(outcome, Err(StorageError::DatabaseRejected));
        assert!(scratch.usage.peak_file_bytes >= scratch.usage.creation_bytes);
        drop(scratch);
        assert_eq!(directory.entries()?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn close_persists_nothing_and_meters_creation_peak_cache_and_reclamation()
    -> Result<(), StorageError> {
        let directory = TestDirectory::create("close")?;
        let admission = CountingAdmission::new(None, SCRATCH_TRANSACTION_ALLOWANCE);
        let mut scratch =
            ScratchDatabase::create(directory.exclusive("scratch.redb")?, &admission, &[TABLE])?;
        let creation = scratch.usage.creation_bytes;
        assert!(creation > 0);
        for slice in 0..4_u32 {
            publish_rows(&mut scratch, slice.saturating_mul(512), 512, 64)?;
        }
        // Rewriting the same rows frees the pages they occupied; the bounded reclamations
        // return them, so the file does not grow by every rewritten page.
        let grown = scratch.usage.peak_file_bytes;
        for _rewrite in 0..8 {
            publish_rows(&mut scratch, 0, 512, 64)?;
        }
        scratch.observe_buffer(4_096);
        let usage = scratch.close();
        assert_eq!(usage.transactions, 13);
        assert!(usage.reclamations >= usage.transactions);
        assert!(usage.reclaimed_pages > 0);
        assert!(usage.peak_file_bytes >= grown);
        assert!(usage.peak_file_bytes < grown.saturating_mul(4));
        assert_eq!(usage.peak_buffer_bytes, 4_096);
        assert_eq!(usage.cache_bytes, 8 * 1_048_576);
        assert_eq!(
            usage.allowance_bytes,
            MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH
        );
        assert!(usage.charged_bytes >= usage.peak_transaction_bytes);
        assert_eq!(directory.entries()?, Vec::<String>::new());

        // An anonymous scratch has no entry to remove and meters the same way.
        let mut anonymous = ScratchDatabase::create(directory.anonymous()?, &admission, &[TABLE])?;
        publish_rows(&mut anonymous, 0, 8, 32)?;
        assert_eq!(directory.entries()?, Vec::<String>::new());
        let usage = anonymous.close();
        assert_eq!(usage.transactions, 2);
        assert!(usage.creation_bytes > 0);
        assert!(directory.path().is_dir());
        Ok(())
    }

    #[test]
    fn a_byte_budget_of_maximum_keys_charges_far_less_than_the_allowance()
    -> Result<(), StorageError> {
        let directory = TestDirectory::create("maximum-keys")?;
        let admission = CountingAdmission::new(None, SCRATCH_TRANSACTION_ALLOWANCE);
        let mut scratch =
            ScratchDatabase::create(directory.exclusive("scratch.redb")?, &admission, &[TABLE])?;
        let rows = u32::try_from(
            SCRATCH_SLICE_BYTES
                / crate::MAX_STORED_KEY_BYTES
                    .checked_add(ROW_VALUE.len())
                    .ok_or(StorageError::Overflow)?,
        )
        .map_err(|_| StorageError::Overflow)?;
        let charged = publish_rows(&mut scratch, 0, rows, crate::MAX_STORED_KEY_BYTES)?;
        // One byte budget of maximum stored keys charges less than an eighth of the allowance:
        // the copy-on-write rewrites are charged, so the charge is many times the row bytes,
        // and the byte budget is what keeps it bounded whatever the key shape.
        assert!(charged > u64::try_from(SCRATCH_SLICE_BYTES).map_err(|_| StorageError::Overflow)?);
        assert!(
            charged <= MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH / 8,
            "a maximum-key byte budget charged {charged} bytes"
        );
        let usage = scratch.close();
        assert!(
            usage.peak_file_bytes
                > u64::try_from(SCRATCH_SLICE_BYTES).map_err(|_| StorageError::Overflow)?
        );
        assert!(usage.peak_file_bytes <= charged);
        Ok(())
    }
}
