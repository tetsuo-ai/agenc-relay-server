//! Safe Linux filesystem adapter for locks, space admission, and atomic guards.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::path::{Component, Path, PathBuf};

use agenc_ircd_crypto::OsEntropy;
use rustix::fs::{
    AtFlags, CWD, Dir, FileType, Mode, OFlags, RenameFlags, StatVfs, fstat, fstatfs, fstatvfs,
    fsync, openat, renameat, renameat_with, unlinkat,
};

use crate::{
    MAX_QUALIFIED_OBSERVED_GROWTH, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, StorageError,
    StorageFaultBoundary, StorageFaultInjector, StorageFaultSite,
};

const DATABASE_FILE: &str = "database.redb";
const GUARD_FILE: &str = "rollback.guard";
const WRITER_LOCK_FILE: &str = "writer.lock";
/// Prefix of the random create-exclusive file a backup is written to before its rename.
const BACKUP_TEMPORARY_PREFIX: &str = ".agenc-backup-tmp-v1-";
/// Prefix of the random scratch database used while startup replays manifests.
const RECOVERY_SCRATCH_PREFIX: &str = ".agenc-recovery-scratch-v1-";
/// Prefix of the random file a rollback guard is written to before its rename.
const GUARD_TEMPORARY_PREFIX: &str = ".rollback.guard.agenc-tmp-v1-";

#[cfg(target_arch = "x86_64")]
const TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";
#[cfg(target_arch = "aarch64")]
const TARGET_TRIPLE: &str = "aarch64-unknown-linux-gnu";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Stage 05 storage qualification supports only x86_64 and aarch64 Linux");

fn io_rejected(_error: std::io::Error) -> StorageError {
    StorageError::FilesystemRejected
}

fn rustix_rejected(_error: rustix::io::Errno) -> StorageError {
    StorageError::FilesystemRejected
}

/// Exact host tuple that must have passing characterization evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemTuple {
    /// Rust target triple compiled into the artifact.
    pub target: &'static str,
    /// Linux filesystem magic returned by `fstatfs`.
    pub filesystem_type: u64,
    /// Fundamental allocation block size.
    pub block_size: u64,
    /// Relevant `statvfs` mount flags.
    pub mount_flags: u64,
}

/// One passing, signed-off characterization accepted by startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageQualification {
    tuple: FilesystemTuple,
    maximum_observed_growth: u64,
}

impl StorageQualification {
    pub(crate) const fn from_verified_report(
        tuple: FilesystemTuple,
        maximum_observed_growth: u64,
    ) -> Self {
        Self {
            tuple,
            maximum_observed_growth,
        }
    }

    /// Validates the mandatory twofold margin inside the live reserve.
    pub const fn validate(self) -> Result<Self, StorageError> {
        if self.maximum_observed_growth > MAX_QUALIFIED_OBSERVED_GROWTH {
            return Err(StorageError::FilesystemRejected);
        }
        Ok(self)
    }

    /// Returns the exact characterized filesystem tuple.
    #[must_use]
    pub const fn tuple(self) -> FilesystemTuple {
        self.tuple
    }

    /// Returns the greatest observed positive physical growth.
    #[must_use]
    pub const fn maximum_observed_growth(self) -> u64 {
        self.maximum_observed_growth
    }
}

/// Effective free-space and reserve sample taken from one open filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemCapacity {
    /// Bytes available to the daemon UID.
    pub available_bytes: u64,
    /// Greater of the fixed and percentage reserve.
    pub reserve_bytes: u64,
}

/// Open, no-follow state-directory authority and lifetime writer lock.
pub struct StateDirectory {
    directory: File,
    writer_lock: File,
    construction_sibling: PathBuf,
    tuple: FilesystemTuple,
    faults: StorageFaultInjector,
}

/// Read-only state-directory authority used by stopped-daemon inspection.
///
/// Opening this authority never creates the writer lock, removes temporary
/// files, repairs the database, or replaces the rollback guard.
pub struct InspectionStateDirectory {
    directory: File,
    database: File,
    construction_sibling: PathBuf,
    tuple: FilesystemTuple,
}

/// Atomically moves one initialized path into place without replacing an
/// entry created after preflight validation.
pub fn rename_path_no_replace(source: &Path, target: &Path) -> Result<(), StorageError> {
    renameat_with(CWD, source, CWD, target, RenameFlags::NOREPLACE).map_err(rustix_rejected)
}

/// Validated backup location that creates no file until source verification completes.
pub struct BackupDestination {
    directory_path: PathBuf,
    final_name: String,
}

/// Bounded, descriptor-relative reader for an existing backup directory.
///
/// Enumeration and file opens use the same validated directory authority.
/// Candidate files are accepted only when they are regular mode-0600 files
/// on that directory's filesystem.
pub struct BackupDirectoryReader {
    entries: Dir,
    examined: usize,
    maximum_entries: usize,
}

impl BackupDirectoryReader {
    /// Opens one mode-0700 backup directory without following a symlink.
    pub fn open(directory_path: &Path, maximum_entries: usize) -> Result<Self, StorageError> {
        if maximum_entries == 0 {
            return Err(StorageError::LimitExceeded);
        }
        let directory = openat(
            CWD,
            directory_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&directory, FileType::Directory, Mode::RWXU)?;
        Ok(Self {
            entries: Dir::new(directory).map_err(rustix_rejected)?,
            examined: 0,
            maximum_entries,
        })
    }

    /// Returns the next UTF-8 directory entry after accounting for every
    /// entry the kernel supplied. Dot entries and non-UTF-8 names are skipped.
    pub fn next_name(&mut self) -> Result<Option<String>, StorageError> {
        loop {
            let Some(entry) = self.entries.next() else {
                return Ok(None);
            };
            let entry = entry.map_err(rustix_rejected)?;
            self.examined = self.examined.checked_add(1).ok_or(StorageError::Overflow)?;
            if self.examined > self.maximum_entries {
                return Err(StorageError::LimitExceeded);
            }
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            let Ok(name) = std::str::from_utf8(bytes) else {
                continue;
            };
            return Ok(Some(name.to_owned()));
        }
    }

    /// Opens one named candidate relative to the validated directory.
    pub fn open_candidate(&self, name: &str) -> Result<File, StorageError> {
        validate_single_component(name)?;
        let directory = self.entries.fd().map_err(rustix_rejected)?;
        let candidate = openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&candidate, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(directory, &candidate)?;
        Ok(File::from(candidate))
    }
}

impl BackupDestination {
    /// Retains a directory and one safe final component without touching the filesystem.
    pub fn new(directory_path: &Path, final_name: &str) -> Result<Self, StorageError> {
        validate_single_component(final_name)?;
        Ok(Self {
            directory_path: directory_path.to_path_buf(),
            final_name: final_name.to_owned(),
        })
    }

    pub(crate) fn create_output(
        self,
        faults: StorageFaultInjector,
    ) -> Result<BackupOutput, StorageError> {
        BackupOutput::create(&self.directory_path, &self.final_name, faults)
    }
}

/// Create-exclusive backup output published by no-replace rename and directory sync.
pub struct BackupOutput {
    directory: File,
    file: File,
    temporary_name: String,
    final_name: String,
    published: bool,
    faults: StorageFaultInjector,
}

pub(crate) struct PublishedBackup {
    file: File,
}

impl PublishedBackup {
    pub(crate) const fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl BackupOutput {
    /// Creates a random mode-0600 temporary file in a validated mode-0700 backup directory.
    fn create(
        directory_path: &Path,
        final_name: &str,
        faults: StorageFaultInjector,
    ) -> Result<Self, StorageError> {
        validate_single_component(final_name)?;
        let directory_fd = openat(
            CWD,
            directory_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&directory_fd, FileType::Directory, Mode::RWXU)?;
        let directory = File::from(directory_fd);
        // One producer per backup directory. The directory descriptor itself carries the lock,
        // so no extra file appears in the directory, a crashed producer releases it, and the
        // sweep below can never remove another live producer's temporary.
        directory
            .try_lock()
            .map_err(|_| StorageError::WriterLocked)?;
        cleanup_random_temporaries(&directory, directory_path, BACKUP_TEMPORARY_PREFIX)?;
        let temporary_name = random_temporary_name(BACKUP_TEMPORARY_PREFIX)?;
        let file_fd = openat(
            &directory,
            temporary_name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(rustix_rejected)?;
        validate_file(&file_fd, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(&directory, &file_fd)?;
        Ok(Self {
            directory,
            file: File::from(file_fd),
            temporary_name,
            final_name: final_name.to_owned(),
            published: false,
            faults,
        })
    }

    pub(crate) const fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(crate) fn publish(mut self) -> Result<PublishedBackup, StorageError> {
        self.faults.check(
            StorageFaultSite::BackupFileSync,
            StorageFaultBoundary::Before,
        )?;
        self.file.sync_all().map_err(io_rejected)?;
        self.faults.check(
            StorageFaultSite::BackupFileSync,
            StorageFaultBoundary::After,
        )?;
        self.faults
            .check(StorageFaultSite::BackupRename, StorageFaultBoundary::Before)?;
        renameat_with(
            &self.directory,
            self.temporary_name.as_str(),
            &self.directory,
            self.final_name.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(rustix_rejected)?;
        self.faults
            .check(StorageFaultSite::BackupRename, StorageFaultBoundary::After)?;
        self.faults.check(
            StorageFaultSite::BackupDirectorySync,
            StorageFaultBoundary::Before,
        )?;
        fsync(&self.directory).map_err(rustix_rejected)?;
        self.faults.check(
            StorageFaultSite::BackupDirectorySync,
            StorageFaultBoundary::After,
        )?;
        self.published = true;
        let published = openat(
            &self.directory,
            self.final_name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&published, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(&self.directory, &published)?;
        Ok(PublishedBackup {
            file: File::from(published),
        })
    }
}

impl Drop for BackupOutput {
    fn drop(&mut self) {
        if !self.published {
            let _ = unlinkat(
                &self.directory,
                self.temporary_name.as_str(),
                AtFlags::empty(),
            );
        }
    }
}

impl StateDirectory {
    /// Probes the exact filesystem tuple before selecting signed qualification evidence.
    pub fn probe(path: &Path) -> Result<FilesystemTuple, StorageError> {
        let directory_fd = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&directory_fd, FileType::Directory, Mode::RWXU)?;
        filesystem_tuple(&directory_fd)
    }

    /// Opens a mode-0700 directory, locks its fixed writer file, and validates qualification.
    pub fn open(
        path: &Path,
        qualifications: &[StorageQualification],
    ) -> Result<Self, StorageError> {
        Self::open_with_faults(path, qualifications, StorageFaultInjector::disabled())
    }

    /// Opens the state directory with one deterministic qualification fault schedule.
    pub fn open_with_faults(
        path: &Path,
        qualifications: &[StorageQualification],
        faults: StorageFaultInjector,
    ) -> Result<Self, StorageError> {
        let construction_sibling = construction_sibling(path)?;
        let directory_fd = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&directory_fd, FileType::Directory, Mode::RWXU)?;
        let tuple = filesystem_tuple(&directory_fd)?;
        if !qualifications
            .iter()
            .any(|entry| entry.validate().is_ok() && entry.tuple == tuple)
        {
            return Err(StorageError::FilesystemRejected);
        }
        let writer_fd = openat(
            &directory_fd,
            WRITER_LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(rustix_rejected)?;
        validate_file(&writer_fd, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        let writer_lock = File::from(writer_fd);
        faults.check(StorageFaultSite::WriterLock, StorageFaultBoundary::Before)?;
        writer_lock
            .try_lock()
            .map_err(|_| StorageError::WriterLocked)?;
        faults.check(StorageFaultSite::WriterLock, StorageFaultBoundary::After)?;
        cleanup_random_temporaries(&directory_fd, path, RECOVERY_SCRATCH_PREFIX)?;
        cleanup_random_temporaries(&directory_fd, path, GUARD_TEMPORARY_PREFIX)?;
        Ok(Self {
            directory: File::from(directory_fd),
            writer_lock,
            construction_sibling,
            tuple,
            faults,
        })
    }

    /// Returns the exact recognized host tuple.
    #[must_use]
    pub const fn tuple(&self) -> FilesystemTuple {
        self.tuple
    }

    pub(crate) fn faults(&self) -> StorageFaultInjector {
        self.faults.clone()
    }

    /// Samples UID-available bytes and computes the checked effective reserve.
    pub fn capacity(
        &self,
        fixed_reserve_bytes: u64,
        reserve_percent: u8,
    ) -> Result<FilesystemCapacity, StorageError> {
        self.faults.run(StorageFaultSite::CapacityAdmission, || {
            self.capacity_inner(fixed_reserve_bytes, reserve_percent)
        })
    }

    /// Reports the one fixed sibling used by an interrupted offline
    /// construction without scanning arbitrary directory entries.
    pub(crate) fn pending_construction(&self) -> Result<u64, StorageError> {
        match openat(
            CWD,
            &self.construction_sibling,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(directory) => {
                validate_file(&directory, FileType::Directory, Mode::RWXU)?;
                Ok(1)
            }
            Err(rustix::io::Errno::NOENT) => Ok(0),
            Err(error) => Err(rustix_rejected(error)),
        }
    }

    fn capacity_inner(
        &self,
        fixed_reserve_bytes: u64,
        reserve_percent: u8,
    ) -> Result<FilesystemCapacity, StorageError> {
        if reserve_percent > 100 {
            return Err(StorageError::LimitExceeded);
        }
        let statistics = fstatvfs(&self.directory).map_err(rustix_rejected)?;
        capacity_from_statistics(&statistics, fixed_reserve_bytes, reserve_percent)
    }

    /// Enforces `R(F) + G` immediately before a durable transaction.
    pub fn admit_transaction(
        &self,
        fixed_reserve_bytes: u64,
        reserve_percent: u8,
    ) -> Result<FilesystemCapacity, StorageError> {
        let capacity = self.capacity(fixed_reserve_bytes, reserve_percent)?;
        let required = capacity
            .reserve_bytes
            .checked_add(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
            .ok_or(StorageError::Overflow)?;
        if capacity.available_bytes < required {
            return Err(StorageError::FilesystemRejected);
        }
        Ok(capacity)
    }

    /// Opens the fixed database path without following a final symlink.
    pub fn open_database_file(&self) -> Result<File, StorageError> {
        let fd = openat(
            &self.directory,
            DATABASE_FILE,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(rustix_rejected)?;
        validate_file(&fd, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(&self.directory, &fd)?;
        Ok(File::from(fd))
    }

    /// Creates the fixed database path exclusively inside a fresh staging directory.
    pub fn create_database_file(&self) -> Result<File, StorageError> {
        let fd = openat(
            &self.directory,
            DATABASE_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(rustix_rejected)?;
        validate_file(&fd, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(&self.directory, &fd)?;
        Ok(File::from(fd))
    }

    /// Reads and validates the exact fixed rollback guard.
    pub fn read_guard(&self, expected_bytes: usize) -> Result<Vec<u8>, StorageError> {
        let fd = openat(
            &self.directory,
            GUARD_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&fd, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(&self.directory, &fd)?;
        let file = File::from(fd);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected_bytes)
            .map_err(|_| StorageError::AllocationFailed)?;
        self.faults
            .check(StorageFaultSite::RecordRead, StorageFaultBoundary::Before)?;
        file.take(
            u64::try_from(
                expected_bytes
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?,
            )
            .map_err(|_| StorageError::Overflow)?,
        )
        .read_to_end(&mut bytes)
        .map_err(io_rejected)?;
        self.faults
            .check(StorageFaultSite::RecordRead, StorageFaultBoundary::After)?;
        if bytes.len() != expected_bytes {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(bytes)
    }

    /// Replaces the guard with create-exclusive temporary, file sync, rename, and directory sync.
    pub fn replace_guard(&self, bytes: &[u8]) -> Result<(), StorageError> {
        let temporary_name = random_guard_temporary_name()?;
        self.faults.check(
            StorageFaultSite::GuardTemporaryCreate,
            StorageFaultBoundary::Before,
        )?;
        let temporary = openat(
            &self.directory,
            temporary_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(rustix_rejected)?;
        validate_file(&temporary, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(&self.directory, &temporary)?;
        self.faults.check(
            StorageFaultSite::GuardTemporaryCreate,
            StorageFaultBoundary::After,
        )?;
        let mut file = File::from(temporary);
        self.faults
            .check(StorageFaultSite::GuardWrite, StorageFaultBoundary::Before)?;
        file.write_all(bytes).map_err(io_rejected)?;
        self.faults
            .check(StorageFaultSite::GuardWrite, StorageFaultBoundary::After)?;
        self.faults.check(
            StorageFaultSite::GuardFileSync,
            StorageFaultBoundary::Before,
        )?;
        file.sync_all().map_err(io_rejected)?;
        self.faults
            .check(StorageFaultSite::GuardFileSync, StorageFaultBoundary::After)?;
        self.faults
            .check(StorageFaultSite::GuardRename, StorageFaultBoundary::Before)?;
        renameat(
            &self.directory,
            temporary_name.as_str(),
            &self.directory,
            GUARD_FILE,
        )
        .map_err(rustix_rejected)?;
        self.faults
            .check(StorageFaultSite::GuardRename, StorageFaultBoundary::After)?;
        self.faults.check(
            StorageFaultSite::GuardDirectorySync,
            StorageFaultBoundary::Before,
        )?;
        fsync(&self.directory).map_err(rustix_rejected)?;
        self.faults.check(
            StorageFaultSite::GuardDirectorySync,
            StorageFaultBoundary::After,
        )?;
        let reopened = self.read_guard(bytes.len())?;
        if reopened != bytes {
            return Err(StorageError::AuthenticationFailed);
        }
        Ok(())
    }

    pub(crate) fn create_recovery_scratch(&self) -> Result<(File, File, String), StorageError> {
        let temporary_name = random_temporary_name(RECOVERY_SCRATCH_PREFIX)?;
        let scratch = openat(
            &self.directory,
            temporary_name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(rustix_rejected)?;
        validate_file(&scratch, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(&self.directory, &scratch)?;
        Ok((
            File::from(scratch),
            self.directory.try_clone().map_err(io_rejected)?,
            temporary_name,
        ))
    }
}

impl InspectionStateDirectory {
    /// Opens an existing mode-0700 state directory without taking write
    /// authority over any entry.
    pub fn open(
        path: &Path,
        qualifications: &[StorageQualification],
    ) -> Result<Self, StorageError> {
        let construction_sibling = construction_sibling(path)?;
        let directory_fd = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&directory_fd, FileType::Directory, Mode::RWXU)?;
        let tuple = filesystem_tuple(&directory_fd)?;
        if !qualifications
            .iter()
            .any(|entry| entry.validate().is_ok() && entry.tuple == tuple)
        {
            return Err(StorageError::FilesystemRejected);
        }
        let database_fd = openat(
            &directory_fd,
            DATABASE_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&database_fd, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(&directory_fd, &database_fd)?;
        Ok(Self {
            directory: File::from(directory_fd),
            database: File::from(database_fd),
            construction_sibling,
            tuple,
        })
    }

    /// Returns the exact recognized host tuple.
    #[must_use]
    pub const fn tuple(&self) -> FilesystemTuple {
        self.tuple
    }

    /// Returns a process-local path to the already validated database
    /// descriptor. redb opens this path read-only and therefore cannot race a
    /// replacement of the state-directory entry.
    pub(crate) fn database_descriptor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.database.as_raw_fd()))
    }

    pub(crate) fn open_database_file(&self) -> Result<File, StorageError> {
        self.database.try_clone().map_err(io_rejected)
    }

    /// Reads and validates the fixed rollback guard without write authority.
    pub(crate) fn read_guard(&self, expected_bytes: usize) -> Result<Vec<u8>, StorageError> {
        let fd = openat(
            &self.directory,
            GUARD_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        validate_file(&fd, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        require_same_filesystem(&self.directory, &fd)?;
        let file = File::from(fd);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected_bytes)
            .map_err(|_| StorageError::AllocationFailed)?;
        file.take(
            u64::try_from(
                expected_bytes
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?,
            )
            .map_err(|_| StorageError::Overflow)?,
        )
        .read_to_end(&mut bytes)
        .map_err(io_rejected)?;
        if bytes.len() != expected_bytes {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(bytes)
    }

    /// Samples UID-available bytes and computes the checked effective reserve.
    pub(crate) fn capacity(
        &self,
        fixed_reserve_bytes: u64,
        reserve_percent: u8,
    ) -> Result<FilesystemCapacity, StorageError> {
        if reserve_percent > 100 {
            return Err(StorageError::LimitExceeded);
        }
        let statistics = fstatvfs(&self.directory).map_err(rustix_rejected)?;
        capacity_from_statistics(&statistics, fixed_reserve_bytes, reserve_percent)
    }

    /// Reports only the one fixed offline-construction sibling.
    pub(crate) fn pending_construction(&self) -> Result<u64, StorageError> {
        match openat(
            CWD,
            &self.construction_sibling,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(directory) => {
                validate_file(&directory, FileType::Directory, Mode::RWXU)?;
                Ok(1)
            }
            Err(rustix::io::Errno::NOENT) => Ok(0),
            Err(error) => Err(rustix_rejected(error)),
        }
    }

    /// Creates an anonymous mode-0600 scratch inode on the qualified state
    /// filesystem. Unsupported `O_TMPFILE` is a closed inspection failure.
    pub(crate) fn create_anonymous_scratch(&self) -> Result<File, StorageError> {
        let scratch = openat(
            &self.directory,
            ".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(rustix_rejected)?;
        validate_file(&scratch, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        let metadata = fstat(&scratch).map_err(rustix_rejected)?;
        if metadata.st_nlink != 0 {
            return Err(StorageError::FilesystemRejected);
        }
        require_same_filesystem(&self.directory, &scratch)?;
        Ok(File::from(scratch))
    }
}

fn random_guard_temporary_name() -> Result<String, StorageError> {
    random_temporary_name(GUARD_TEMPORARY_PREFIX)
}

fn construction_sibling(path: &Path) -> Result<PathBuf, StorageError> {
    let output_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(StorageError::FilesystemRejected)?;
    validate_single_component(output_name)?;
    let parent = path.parent().ok_or(StorageError::FilesystemRejected)?;
    let sibling = format!(
        ".{output_name}{}",
        crate::construction_directory::STAGING_SUFFIX
    );
    validate_single_component(&sibling)?;
    Ok(parent.join(sibling))
}

/// Computes UID-available bytes and the effective reserve `max(fixed, ceil(total * percent / 100))`.
fn capacity_from_statistics(
    statistics: &StatVfs,
    fixed_reserve_bytes: u64,
    reserve_percent: u8,
) -> Result<FilesystemCapacity, StorageError> {
    let block_size = statistics.f_frsize;
    let available_bytes = statistics
        .f_bavail
        .checked_mul(block_size)
        .ok_or(StorageError::Overflow)?;
    let total_bytes = statistics
        .f_blocks
        .checked_mul(block_size)
        .ok_or(StorageError::Overflow)?;
    let percentage_reserve = total_bytes
        .checked_mul(u64::from(reserve_percent))
        .and_then(|bytes| bytes.checked_add(99))
        .ok_or(StorageError::Overflow)?
        / 100;
    Ok(FilesystemCapacity {
        available_bytes,
        reserve_bytes: fixed_reserve_bytes.max(percentage_reserve),
    })
}

fn random_temporary_name(prefix: &str) -> Result<String, StorageError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0_u8; 16];
    OsEntropy::fill(&mut random)?;
    let capacity = prefix.len().checked_add(32).ok_or(StorageError::Overflow)?;
    let mut name = String::with_capacity(capacity);
    name.push_str(prefix);
    for byte in random {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        name.push(char::from(
            *HEX.get(high).ok_or(StorageError::InvalidEncoding)?,
        ));
        name.push(char::from(
            *HEX.get(low).ok_or(StorageError::InvalidEncoding)?,
        ));
    }
    Ok(name)
}

fn validate_single_component(name: &str) -> Result<(), StorageError> {
    let mut components = Path::new(name).components();
    if name.is_empty()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(StorageError::FilesystemRejected);
    }
    Ok(())
}

fn cleanup_random_temporaries(
    directory: &impl AsFd,
    directory_path: &Path,
    prefix: &str,
) -> Result<(), StorageError> {
    for entry in std::fs::read_dir(directory_path).map_err(io_rejected)? {
        let entry = entry.map_err(io_rejected)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(suffix) = name.strip_prefix(prefix) else {
            continue;
        };
        if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StorageError::FilesystemRejected);
        }
        unlinkat(directory, name.as_str(), AtFlags::empty()).map_err(rustix_rejected)?;
    }
    Ok(())
}

impl Drop for StateDirectory {
    fn drop(&mut self) {
        let _ = self.writer_lock.unlock();
    }
}

fn validate_file(
    fd: &impl AsFd,
    expected_type: FileType,
    expected_mode: Mode,
) -> Result<(), StorageError> {
    let metadata = fstat(fd).map_err(rustix_rejected)?;
    if FileType::from_raw_mode(metadata.st_mode) != expected_type
        || Mode::from_raw_mode(metadata.st_mode) != expected_mode
    {
        return Err(StorageError::FilesystemRejected);
    }
    Ok(())
}

pub(crate) fn admit_backup_output(
    file: &File,
    required_stream_bytes: u64,
    fixed_reserve_bytes: u64,
    reserve_percent: u8,
) -> Result<(), StorageError> {
    if reserve_percent > 100 || file.metadata().map_err(io_rejected)?.len() != 0 {
        return Err(StorageError::FilesystemRejected);
    }
    validate_file(file, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
    let statistics = fstatvfs(file).map_err(rustix_rejected)?;
    let capacity = capacity_from_statistics(&statistics, fixed_reserve_bytes, reserve_percent)?;
    let required = capacity
        .reserve_bytes
        .checked_add(required_stream_bytes)
        .ok_or(StorageError::Overflow)?;
    if capacity.available_bytes < required {
        return Err(StorageError::FilesystemRejected);
    }
    Ok(())
}

fn require_same_filesystem<Left: std::os::fd::AsFd, Right: std::os::fd::AsFd>(
    left: Left,
    right: Right,
) -> Result<(), StorageError> {
    let left_stat = fstat(left).map_err(rustix_rejected)?;
    let right_stat = fstat(right).map_err(rustix_rejected)?;
    if left_stat.st_dev != right_stat.st_dev {
        return Err(StorageError::FilesystemRejected);
    }
    Ok(())
}

fn filesystem_tuple(fd: &OwnedFd) -> Result<FilesystemTuple, StorageError> {
    let fs = fstatfs(fd).map_err(rustix_rejected)?;
    let vfs = fstatvfs(fd).map_err(rustix_rejected)?;
    Ok(FilesystemTuple {
        target: TARGET_TRIPLE,
        filesystem_type: u64::try_from(fs.f_type).map_err(|_| StorageError::FilesystemRejected)?,
        block_size: vfs.f_frsize,
        mount_flags: vfs.f_flag.bits(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create(label: &str) -> Result<Self, StorageError> {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agenc-platform-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).map_err(io_rejected)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(io_rejected)?;
            Ok(Self(path))
        }

        fn create_file(&self, name: &str, mode: u32) -> Result<File, StorageError> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(self.0.join(name))
                .map_err(io_rejected)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn qualification_and_component_validation_cover_both_outcomes() {
        let tuple = FilesystemTuple {
            target: TARGET_TRIPLE,
            filesystem_type: 1,
            block_size: 4_096,
            mount_flags: 0,
        };
        let valid =
            StorageQualification::from_verified_report(tuple, MAX_QUALIFIED_OBSERVED_GROWTH);
        assert_eq!(valid.validate(), Ok(valid));
        assert_eq!(valid.tuple(), tuple);
        assert_eq!(valid.maximum_observed_growth(), 134_217_728);
        assert_eq!(
            StorageQualification::from_verified_report(tuple, MAX_QUALIFIED_OBSERVED_GROWTH + 1)
                .validate(),
            Err(StorageError::FilesystemRejected)
        );

        assert!(BackupDestination::new(Path::new("/tmp"), "backup.bin").is_ok());
        for name in ["", ".", "..", "nested/backup", "/absolute"] {
            assert!(matches!(
                BackupDestination::new(Path::new("/tmp"), name),
                Err(StorageError::FilesystemRejected)
            ));
        }
    }

    #[test]
    fn backup_directory_reader_is_bounded_and_opens_only_safe_candidates()
    -> Result<(), StorageError> {
        use std::io::{Read as _, Write as _};
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::create("backup-reader")?;
        let mut file = directory.create_file("candidate.agenc-backup", 0o600)?;
        file.write_all(b"verified-input").map_err(io_rejected)?;
        drop(file);
        symlink(
            directory.path().join("candidate.agenc-backup"),
            directory.path().join("linked.agenc-backup"),
        )
        .map_err(io_rejected)?;

        let mut reader = BackupDirectoryReader::open(directory.path(), 4)?;
        let mut names = Vec::new();
        while let Some(name) = reader.next_name()? {
            names.push(name);
        }
        names.sort();
        assert_eq!(
            names,
            vec![
                "candidate.agenc-backup".to_owned(),
                "linked.agenc-backup".to_owned()
            ]
        );
        let mut candidate = reader.open_candidate("candidate.agenc-backup")?;
        let mut bytes = Vec::new();
        candidate.read_to_end(&mut bytes).map_err(io_rejected)?;
        assert_eq!(bytes, b"verified-input");
        assert_eq!(
            reader.open_candidate("linked.agenc-backup").err(),
            Some(StorageError::FilesystemRejected)
        );

        let mut bounded = BackupDirectoryReader::open(directory.path(), 3)?;
        assert!(bounded.next_name()?.is_some());
        assert_eq!(bounded.next_name(), Err(StorageError::LimitExceeded));
        Ok(())
    }

    #[test]
    fn temporary_cleanup_removes_only_well_formed_owned_files() -> Result<(), StorageError> {
        let directory = TestDirectory::create("cleanup")?;
        let directory_fd = openat(
            CWD,
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_rejected)?;
        let prefix = ".agenc-test-";
        let valid_name = format!("{prefix}{}", "a".repeat(32));
        directory.create_file(&valid_name, 0o600)?;
        directory.create_file("unrelated", 0o600)?;
        cleanup_random_temporaries(&directory_fd, directory.path(), prefix)?;
        assert!(!directory.path().join(valid_name).exists());
        assert!(directory.path().join("unrelated").exists());

        directory.create_file(&format!("{prefix}short"), 0o600)?;
        assert_eq!(
            cleanup_random_temporaries(&directory_fd, directory.path(), prefix),
            Err(StorageError::FilesystemRejected)
        );
        Ok(())
    }

    #[test]
    fn inspection_keeps_directory_entries_and_uses_anonymous_scratch() -> Result<(), StorageError> {
        let directory = TestDirectory::create("inspection")?;
        directory.create_file(DATABASE_FILE, 0o600)?;
        directory.create_file(GUARD_FILE, 0o600)?;
        let recovery_temporary = format!("{RECOVERY_SCRATCH_PREFIX}{}", "a".repeat(32));
        let guard_temporary = format!("{GUARD_TEMPORARY_PREFIX}{}", "b".repeat(32));
        directory.create_file(&recovery_temporary, 0o600)?;
        directory.create_file(&guard_temporary, 0o600)?;
        let entries = || -> Result<Vec<String>, StorageError> {
            let mut names = fs::read_dir(directory.path())
                .map_err(io_rejected)?
                .map(|entry| {
                    entry
                        .map_err(io_rejected)?
                        .file_name()
                        .into_string()
                        .map_err(|_| StorageError::FilesystemRejected)
                })
                .collect::<Result<Vec<_>, _>>()?;
            names.sort();
            Ok(names)
        };
        let before = entries()?;
        let tuple = StateDirectory::probe(directory.path())?;
        let qualification = StorageQualification::from_verified_report(tuple, 1).validate()?;

        let inspection = InspectionStateDirectory::open(directory.path(), &[qualification])?;
        assert_eq!(inspection.tuple(), tuple);
        assert!(!directory.path().join(WRITER_LOCK_FILE).exists());
        let scratch = inspection.create_anonymous_scratch()?;
        let metadata = fstat(&scratch).map_err(rustix_rejected)?;
        assert_eq!(metadata.st_nlink, 0);
        assert_eq!(
            Mode::from_raw_mode(metadata.st_mode),
            Mode::RUSR | Mode::WUSR
        );
        assert_eq!(entries()?, before);
        drop(scratch);
        drop(inspection);
        assert_eq!(entries()?, before);
        assert!(directory.path().join(recovery_temporary).exists());
        assert!(directory.path().join(guard_temporary).exists());
        Ok(())
    }

    #[test]
    fn backup_outputs_hold_the_directory_lock_and_sweep_only_stale_temporaries()
    -> Result<(), StorageError> {
        let directory = TestDirectory::create("backup-lock")?;
        let faults = StorageFaultInjector::disabled();
        let first = BackupOutput::create(directory.path(), "first.backup", faults.clone())?;
        assert_eq!(
            BackupOutput::create(directory.path(), "second.backup", faults.clone()).err(),
            Some(StorageError::WriterLocked)
        );
        drop(first);

        let stale = format!("{BACKUP_TEMPORARY_PREFIX}{}", "b".repeat(32));
        directory.create_file(&stale, 0o600)?;
        let second = BackupOutput::create(directory.path(), "second.backup", faults)?;
        assert!(!directory.path().join(stale).exists());
        drop(second);
        assert_eq!(
            fs::read_dir(directory.path()).map_err(io_rejected)?.count(),
            0
        );
        Ok(())
    }

    #[test]
    fn file_validation_and_backup_admission_fail_closed() -> Result<(), StorageError> {
        let directory = TestDirectory::create("admission")?;
        let file = directory.create_file("empty", 0o600)?;
        validate_file(&file, FileType::RegularFile, Mode::RUSR | Mode::WUSR)?;
        assert_eq!(
            validate_file(&file, FileType::Directory, Mode::RUSR | Mode::WUSR),
            Err(StorageError::FilesystemRejected)
        );
        assert_eq!(
            validate_file(&file, FileType::RegularFile, Mode::RUSR),
            Err(StorageError::FilesystemRejected)
        );
        assert_eq!(
            admit_backup_output(&file, 0, 0, 101),
            Err(StorageError::FilesystemRejected)
        );
        admit_backup_output(&file, 0, 0, 0)?;
        assert_eq!(
            admit_backup_output(&file, u64::MAX, u64::MAX, 0),
            Err(StorageError::Overflow)
        );

        file.set_len(1).map_err(io_rejected)?;
        assert_eq!(
            admit_backup_output(&file, 0, 0, 0),
            Err(StorageError::FilesystemRejected)
        );
        require_same_filesystem(directory.create_file("second", 0o600)?, file)?;
        Ok(())
    }

    #[test]
    fn state_directory_exercises_capacity_guard_and_exclusive_database_paths()
    -> Result<(), StorageError> {
        let directory = TestDirectory::create("state")?;
        let tuple = StateDirectory::probe(directory.path())?;
        let qualification = StorageQualification::from_verified_report(tuple, 1).validate()?;
        let stale_guard = format!("{GUARD_TEMPORARY_PREFIX}{}", "c".repeat(32));
        directory.create_file(&stale_guard, 0o600)?;
        let state = StateDirectory::open(directory.path(), &[qualification])?;
        assert!(!directory.path().join(stale_guard).exists());
        assert_eq!(state.tuple(), tuple);
        assert_eq!(state.capacity(0, 101), Err(StorageError::LimitExceeded));
        let capacity = state.capacity(0, 0)?;
        assert!(capacity.available_bytes > 0);

        assert_eq!(state.read_guard(1), Err(StorageError::FilesystemRejected));
        state.replace_guard(b"guard")?;
        assert_eq!(state.read_guard(5)?, b"guard");
        assert_eq!(state.read_guard(4), Err(StorageError::InvalidEncoding));

        let database = state.create_database_file()?;
        assert_eq!(database.metadata().map_err(io_rejected)?.len(), 0);
        assert!(matches!(
            state.create_database_file(),
            Err(StorageError::FilesystemRejected)
        ));
        assert_eq!(
            state
                .open_database_file()?
                .metadata()
                .map_err(io_rejected)?
                .len(),
            0
        );
        let (scratch, _parent, name) = state.create_recovery_scratch()?;
        assert_eq!(scratch.metadata().map_err(io_rejected)?.len(), 0);
        assert!(directory.path().join(name).exists());
        Ok(())
    }
}
