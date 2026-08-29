//! Safe, resumable staging-directory lifecycle for offline storage construction.

use std::fs::{File, read_dir, symlink_metadata};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

use agenc_ircd_crypto::{StorageDigest, storage_output_path_hash};
use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, RenameFlags, fstat, fsync, mkdirat, openat,
    renameat_with, unlinkat,
};
use rustix::io::Errno;

use crate::{
    StorageError, StorageFaultBoundary, StorageFaultInjector, StorageFaultSite,
    VerifiedConstructionOutput,
};

const STAGING_SUFFIX: &str = ".agenc-construction-v1";
const DATABASE_FILE: &str = "database.redb";
const GUARD_FILE: &str = "rollback.guard";
const WRITER_LOCK_FILE: &str = "writer.lock";
const CONSTRUCTION_PLAN_FILE: &str = "construction-plan.redb";

/// Authenticated phase selected by the exact new/resume path rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstructionDirectoryPhase {
    /// A private sibling staging directory is ready for construction.
    Staging,
    /// The final output already exists and may only be reverified.
    Installed,
}

/// Canonical output and fixed sibling staging authority for one offline command.
pub struct ConstructionDirectory {
    parent: File,
    parent_path: PathBuf,
    output_name: String,
    staging_name: String,
    phase: ConstructionDirectoryPhase,
    output_path_hash: StorageDigest,
    faults: StorageFaultInjector,
}

impl ConstructionDirectory {
    /// Creates a fresh staging directory or selects exactly one resumable phase.
    pub fn open(output_path: &Path, resume: bool) -> Result<Self, StorageError> {
        Self::open_with_faults(output_path, resume, StorageFaultInjector::disabled())
    }

    /// Opens a construction directory with one deterministic qualification schedule.
    pub fn open_with_faults(
        output_path: &Path,
        resume: bool,
        faults: StorageFaultInjector,
    ) -> Result<Self, StorageError> {
        validate_lexical_absolute_path(output_path)?;
        let output_name = output_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(StorageError::InvalidEncoding)?
            .to_owned();
        if output_name.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        let parent_input = output_path.parent().ok_or(StorageError::InvalidEncoding)?;
        let parent_path = parent_input
            .canonicalize()
            .map_err(|_| StorageError::FilesystemRejected)?;
        let canonical_output = parent_path.join(&output_name);
        let canonical_text = canonical_output
            .to_str()
            .ok_or(StorageError::InvalidEncoding)?;
        let output_path_hash = storage_output_path_hash(canonical_text)?;
        let staging_name = format!(".{output_name}{STAGING_SUFFIX}");
        let parent_fd = openat(
            CWD,
            &parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageError::FilesystemRejected)?;
        require_kind_and_mode(&parent_fd, FileType::Directory, None)?;
        let output_exists = directory_exists(&parent_path.join(&output_name))?;
        let staging_exists = directory_exists(&parent_path.join(&staging_name))?;
        let phase = match (resume, staging_exists, output_exists) {
            (false, false, false) => {
                mkdirat(&parent_fd, staging_name.as_str(), Mode::RWXU)
                    .map_err(|_| StorageError::FilesystemRejected)?;
                fsync(&parent_fd).map_err(|_| StorageError::FilesystemRejected)?;
                ConstructionDirectoryPhase::Staging
            }
            (true, true, false) => ConstructionDirectoryPhase::Staging,
            (true, false, true) => ConstructionDirectoryPhase::Installed,
            _ => return Err(StorageError::StaleState),
        };
        let selected_name = match phase {
            ConstructionDirectoryPhase::Staging => staging_name.as_str(),
            ConstructionDirectoryPhase::Installed => output_name.as_str(),
        };
        let selected = openat(
            &parent_fd,
            selected_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageError::FilesystemRejected)?;
        require_kind_and_mode(&selected, FileType::Directory, Some(Mode::RWXU))?;
        Ok(Self {
            parent: File::from(parent_fd),
            parent_path,
            output_name,
            staging_name,
            phase,
            output_path_hash,
            faults,
        })
    }

    /// Returns the selected staging or already-installed path.
    #[must_use]
    pub fn selected_path(&self) -> PathBuf {
        self.parent_path.join(match self.phase {
            ConstructionDirectoryPhase::Staging => &self.staging_name,
            ConstructionDirectoryPhase::Installed => &self.output_name,
        })
    }

    /// Returns the canonical requested final output path.
    #[must_use]
    pub fn output_path(&self) -> PathBuf {
        self.parent_path.join(&self.output_name)
    }

    /// Returns the exact path hash bound by the construction marker.
    #[must_use]
    pub const fn output_path_hash(&self) -> StorageDigest {
        self.output_path_hash
    }

    /// Returns whether construction or read-only installed verification is required.
    #[must_use]
    pub const fn phase(&self) -> ConstructionDirectoryPhase {
        self.phase
    }

    /// Replaces the non-authoritative scratch plan with a fresh mode-0600 file.
    pub fn rebuild_plan_file(&self) -> Result<File, StorageError> {
        self.faults.check(
            StorageFaultSite::ConstructionPlanRebuild,
            StorageFaultBoundary::Before,
        )?;
        if self.phase != ConstructionDirectoryPhase::Staging {
            return Err(StorageError::StaleState);
        }
        let staging = openat(
            &self.parent,
            self.staging_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageError::FilesystemRejected)?;
        match unlinkat(&staging, CONSTRUCTION_PLAN_FILE, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(_) => return Err(StorageError::FilesystemRejected),
        }
        let plan = openat(
            &staging,
            CONSTRUCTION_PLAN_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| StorageError::FilesystemRejected)?;
        require_kind_and_mode(&plan, FileType::RegularFile, Some(Mode::RUSR | Mode::WUSR))?;
        fsync(&staging).map_err(|_| StorageError::FilesystemRejected)?;
        self.faults.check(
            StorageFaultSite::ConstructionPlanRebuild,
            StorageFaultBoundary::After,
        )?;
        Ok(File::from(plan))
    }

    /// Removes the rebuilt scratch plan before a completed directory is installed.
    pub fn remove_plan_file(&self) -> Result<(), StorageError> {
        if self.phase != ConstructionDirectoryPhase::Staging {
            return Err(StorageError::StaleState);
        }
        let staging = openat(
            &self.parent,
            self.staging_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageError::FilesystemRejected)?;
        unlinkat(&staging, CONSTRUCTION_PLAN_FILE, AtFlags::empty())
            .map_err(|_| StorageError::FilesystemRejected)?;
        fsync(&staging).map_err(|_| StorageError::FilesystemRejected)
    }

    /// Syncs and atomically installs a completed database/guard pair without replacement.
    pub fn install(
        self,
        verification: VerifiedConstructionOutput,
    ) -> Result<PathBuf, StorageError> {
        if self.phase != ConstructionDirectoryPhase::Staging {
            return Err(StorageError::StaleState);
        }
        if verification.output_path_hash() != self.output_path_hash {
            return Err(StorageError::ResumeMismatch);
        }
        let staging = openat(
            &self.parent,
            self.staging_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageError::FilesystemRejected)?;
        require_kind_and_mode(&staging, FileType::Directory, Some(Mode::RWXU))?;
        validate_completed_membership(&self.selected_path())?;
        let database = open_regular(&staging, DATABASE_FILE)?;
        let guard = open_regular(&staging, GUARD_FILE)?;
        let writer_lock = open_regular(&staging, WRITER_LOCK_FILE)?;
        let writer_lock = File::from(writer_lock);
        writer_lock
            .try_lock()
            .map_err(|_| StorageError::WriterLocked)?;
        fsync(&database).map_err(|_| StorageError::FilesystemRejected)?;
        fsync(&guard).map_err(|_| StorageError::FilesystemRejected)?;
        fsync(&writer_lock).map_err(|_| StorageError::FilesystemRejected)?;
        fsync(&staging).map_err(|_| StorageError::FilesystemRejected)?;
        self.faults.check(
            StorageFaultSite::ConstructionDirectoryRename,
            StorageFaultBoundary::Before,
        )?;
        renameat_with(
            &self.parent,
            self.staging_name.as_str(),
            &self.parent,
            self.output_name.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| StorageError::FilesystemRejected)?;
        self.faults.check(
            StorageFaultSite::ConstructionDirectoryRename,
            StorageFaultBoundary::After,
        )?;
        fsync(&self.parent).map_err(|_| StorageError::FilesystemRejected)?;
        let output = self.output_path();
        if !directory_exists(&output)? {
            return Err(StorageError::FilesystemRejected);
        }
        Ok(output)
    }
}

fn validate_lexical_absolute_path(path: &Path) -> Result<(), StorageError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(StorageError::InvalidEncoding);
    }
    Ok(())
}

fn directory_exists(path: &Path) -> Result<bool, StorageError> {
    match symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(true)
        }
        Ok(_) => Err(StorageError::FilesystemRejected),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(StorageError::FilesystemRejected),
    }
}

fn open_regular(directory: &OwnedFd, name: &str) -> Result<OwnedFd, StorageError> {
    let file = openat(
        directory,
        name,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StorageError::FilesystemRejected)?;
    require_kind_and_mode(&file, FileType::RegularFile, Some(Mode::RUSR | Mode::WUSR))?;
    Ok(file)
}

fn require_kind_and_mode(
    file: &OwnedFd,
    expected_kind: FileType,
    expected_mode: Option<Mode>,
) -> Result<(), StorageError> {
    let status = fstat(file).map_err(|_| StorageError::FilesystemRejected)?;
    let actual_mode = Mode::from_raw_mode(status.st_mode);
    if (
        FileType::from_raw_mode(status.st_mode),
        expected_mode.is_none_or(|mode| actual_mode & Mode::RWXU == mode),
        actual_mode.intersects(Mode::RWXG | Mode::RWXO),
    ) != (expected_kind, true, false)
    {
        return Err(StorageError::FilesystemRejected);
    }
    Ok(())
}

fn validate_completed_membership(path: &Path) -> Result<(), StorageError> {
    let mut names = Vec::with_capacity(3);
    for entry in read_dir(path).map_err(|_| StorageError::FilesystemRejected)? {
        let entry = entry.map_err(|_| StorageError::FilesystemRejected)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| StorageError::InvalidEncoding)?;
        names.push(name);
        if names.len() > 3 {
            return Err(StorageError::StaleState);
        }
    }
    names.sort_unstable();
    if names != [DATABASE_FILE, GUARD_FILE, WRITER_LOCK_FILE] {
        return Err(StorageError::StaleState);
    }
    Ok(())
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
                "agenc-construction-directory-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).map_err(|_| StorageError::FilesystemRejected)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|_| StorageError::FilesystemRejected)?;
            Ok(Self(path))
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

    fn private_file(path: &Path) -> Result<(), StorageError> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| StorageError::FilesystemRejected)?;
        Ok(())
    }

    #[test]
    fn lexical_paths_and_directory_queries_reject_ambiguous_objects() -> Result<(), StorageError> {
        assert_eq!(
            validate_lexical_absolute_path(Path::new("relative")),
            Err(StorageError::InvalidEncoding)
        );
        assert_eq!(
            validate_lexical_absolute_path(Path::new("/tmp/../ambiguous")),
            Err(StorageError::InvalidEncoding)
        );
        validate_lexical_absolute_path(Path::new("/tmp/unambiguous"))?;

        let directory = TestDirectory::create("queries")?;
        assert!(!directory_exists(&directory.path().join("missing"))?);
        let file = directory.path().join("file");
        private_file(&file)?;
        assert_eq!(
            directory_exists(&file),
            Err(StorageError::FilesystemRejected)
        );
        assert!(directory_exists(directory.path())?);
        Ok(())
    }

    #[test]
    fn completed_membership_requires_exact_fixed_files() -> Result<(), StorageError> {
        let directory = TestDirectory::create("membership")?;
        assert_eq!(
            validate_completed_membership(directory.path()),
            Err(StorageError::StaleState)
        );
        for name in [DATABASE_FILE, GUARD_FILE, WRITER_LOCK_FILE] {
            private_file(&directory.path().join(name))?;
        }
        validate_completed_membership(directory.path())?;
        private_file(&directory.path().join("unexpected"))?;
        assert_eq!(
            validate_completed_membership(directory.path()),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn directory_phases_reject_conflicts_and_installed_plan_mutation() -> Result<(), StorageError> {
        let parent = TestDirectory::create("phases")?;
        let output = parent.path().join("output");
        let staging = ConstructionDirectory::open(&output, false)?;
        assert_eq!(staging.phase(), ConstructionDirectoryPhase::Staging);
        assert_eq!(staging.output_path(), output);
        assert!(staging.selected_path().is_dir());
        drop(staging);

        assert!(matches!(
            ConstructionDirectory::open(&output, false),
            Err(StorageError::StaleState)
        ));
        let resumed = ConstructionDirectory::open(&output, true)?;
        let plan = resumed.rebuild_plan_file()?;
        drop(plan);
        resumed.remove_plan_file()?;
        drop(resumed);

        let staging_name = ".output.agenc-construction-v1";
        fs::rename(parent.path().join(staging_name), &output)
            .map_err(|_| StorageError::FilesystemRejected)?;
        let installed = ConstructionDirectory::open(&output, true)?;
        assert_eq!(installed.phase(), ConstructionDirectoryPhase::Installed);
        assert!(matches!(
            installed.rebuild_plan_file(),
            Err(StorageError::StaleState)
        ));
        assert_eq!(installed.remove_plan_file(), Err(StorageError::StaleState));
        assert!(matches!(
            ConstructionDirectory::open(&output, false),
            Err(StorageError::StaleState)
        ));
        Ok(())
    }

    #[test]
    fn directory_mode_validation_rejects_public_permissions() -> Result<(), StorageError> {
        let directory = TestDirectory::create("mode")?;
        let fd = openat(
            CWD,
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageError::FilesystemRejected)?;
        require_kind_and_mode(&fd, FileType::Directory, Some(Mode::RWXU))?;
        assert_eq!(
            require_kind_and_mode(&fd, FileType::RegularFile, Some(Mode::RWXU)),
            Err(StorageError::FilesystemRejected)
        );
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
            .map_err(|_| StorageError::FilesystemRejected)?;
        assert_eq!(
            require_kind_and_mode(&fd, FileType::Directory, Some(Mode::RWXU)),
            Err(StorageError::FilesystemRejected)
        );
        Ok(())
    }
}
