//! Path resolution against the configuration file and host-depth path checks.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};

use crate::bounds::{MAX_PUBLIC_TEXT_BYTES, MAX_PUBLIC_TEXT_LINES};
use crate::config::Config;
use crate::error::{ConfigError, IssueSink, SchemaKey, ValidationStage};
use crate::listeners::ListenerBind;

const MAX_TLS_MATERIAL_BYTES: u64 = 65_536;

/// Resolves relative configuration paths against the configuration file's
/// canonical parent directory (spec 4277-4279).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathResolver {
    base: Option<PathBuf>,
}

impl PathResolver {
    /// A resolver with no base: relative paths are rejected.
    #[must_use]
    pub const fn none() -> Self {
        Self { base: None }
    }

    /// A resolver rooted at the canonical parent of the configuration file.
    pub fn for_config_file(path: &Path) -> Result<Self, ConfigError> {
        let parent = path.parent().ok_or(ConfigError::FileRejected)?;
        let base = fs::canonicalize(parent).map_err(|_| ConfigError::FileRejected)?;
        Self::with_base(base)
    }

    /// A resolver rooted at an explicit absolute directory.
    pub fn with_base(base: PathBuf) -> Result<Self, ConfigError> {
        if !base.is_absolute() || base.components().any(is_unsafe_component) {
            return Err(ConfigError::FileRejected);
        }
        Ok(Self { base: Some(base) })
    }

    /// Resolves one configured path to an absolute, dot-free path.
    pub fn resolve(&self, text: &str) -> Result<PathBuf, ConfigError> {
        let path = Path::new(text);
        if path.is_absolute() {
            return absolute_path(text);
        }
        let base = self.base.as_ref().ok_or(ConfigError::InvalidValue)?;
        let joined = base.join(path);
        if joined.components().any(is_unsafe_component) {
            return Err(ConfigError::InvalidValue);
        }
        Ok(joined)
    }
}

/// Validates an absolute path with no `.` or `..` components.
pub(crate) fn absolute_path(text: &str) -> Result<PathBuf, ConfigError> {
    let path = PathBuf::from(text);
    if !path.is_absolute() || path.components().any(is_unsafe_component) {
        return Err(ConfigError::InvalidValue);
    }
    Ok(path)
}

pub(crate) fn is_unsafe_component(component: Component<'_>) -> bool {
    matches!(component, Component::CurDir | Component::ParentDir)
}

/// Reads one protected regular file from a single no-follow descriptor, bounded
/// by `maximum` bytes. Group- or world-writable files and files whose identity,
/// size, mode, or modification metadata changes during the read are rejected.
///
/// # Errors
///
/// Returns a closed configuration error when the path, descriptor metadata,
/// allocation, read, or stability check fails.
pub fn read_protected_bytes(path: &Path, maximum: u64) -> Result<Vec<u8>, ConfigError> {
    if !path.is_absolute() || path.components().any(is_unsafe_component) {
        return Err(ConfigError::FileRejected);
    }

    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ConfigError::FileRejected)?;
    read_opened_protected_bytes(fs::File::from(fd), maximum, || {})
}

/// Reads one protected regular UTF-8 text file bounded by `maximum` bytes.
pub(crate) fn read_protected_text(path: &Path, maximum: u64) -> Result<String, ConfigError> {
    let bytes = read_protected_bytes(path, maximum)?;
    String::from_utf8(bytes).map_err(|_| ConfigError::FileRejected)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtectedFileStatus {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

fn protected_file_status(
    file: &fs::File,
    maximum: u64,
) -> Result<ProtectedFileStatus, ConfigError> {
    let status = fstat(file).map_err(|_| ConfigError::FileRejected)?;
    let size = u64::try_from(status.st_size).map_err(|_| ConfigError::FileRejected)?;
    let mode = status.st_mode & 0o7777;
    let modified_seconds = status.st_mtime;
    let modified_nanoseconds = status.st_mtime_nsec;
    let changed_seconds = status.st_ctime;
    let changed_nanoseconds = status.st_ctime_nsec;
    if FileType::from_raw_mode(status.st_mode) != FileType::RegularFile
        || size > maximum
        || mode & 0o022 != 0
        || modified_nanoseconds >= 1_000_000_000
        || changed_nanoseconds >= 1_000_000_000
    {
        return Err(ConfigError::FileRejected);
    }
    Ok(ProtectedFileStatus {
        device: status.st_dev,
        inode: status.st_ino,
        size,
        mode,
        modified_seconds,
        modified_nanoseconds,
        changed_seconds,
        changed_nanoseconds,
    })
}

fn read_opened_protected_bytes(
    mut file: fs::File,
    maximum: u64,
    after_initial_status: impl FnOnce(),
) -> Result<Vec<u8>, ConfigError> {
    let before = protected_file_status(&file, maximum)?;
    after_initial_status();

    let read_limit = maximum.checked_add(1).ok_or(ConfigError::Overflow)?;
    let capacity = usize::try_from(read_limit).map_err(|_| ConfigError::Overflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| ConfigError::FileRejected)?;
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::FileRejected)?;

    let after = protected_file_status(&file, maximum)?;
    let bytes_read = u64::try_from(bytes.len()).map_err(|_| ConfigError::Overflow)?;
    if before != after || bytes_read != after.size {
        return Err(ConfigError::FileRejected);
    }
    Ok(bytes)
}

/// Returns whether `candidate` is `root` or lies strictly below it.
pub(crate) fn is_within(candidate: &Path, root: &Path) -> bool {
    candidate.starts_with(root)
}

/// Runs the stage-3 host checks: directory existence and types, state and
/// secret directory permissions, and public text file limits (spec 4329-4334,
/// 9040-9050, 9185-9186).
pub(crate) fn verify_host_paths(config: &Config, sink: &mut IssueSink) {
    let stage = ValidationStage::PathsAndFileTypes;
    check_directory(
        &config.server.data_dir,
        SchemaKey::new("server", "data_dir"),
        None,
        sink,
    );
    check_directory(
        &config.server.runtime_dir,
        SchemaKey::new("server", "runtime_dir"),
        None,
        sink,
    );
    check_directory(
        &config.storage.backup_dir,
        SchemaKey::new("storage", "backup_dir"),
        None,
        sink,
    );
    check_directory(
        &config.storage.state_dir,
        SchemaKey::new("storage", "state_dir"),
        Some(0o700),
        sink,
    );
    for (key, path) in config.secret_paths() {
        if let Err(error) = protected_ancestors(&path) {
            sink.push(stage, key, error);
        }
    }
    for (key, path) in config.public_text_paths() {
        if let Err(error) = public_text(&path) {
            sink.push(stage, key, error);
        }
    }
    for (key, path) in config.trust_manifest_paths() {
        if let Err(error) = read_protected_text(&path, crate::bounds::MAX_CONFIG_BYTES) {
            sink.push(stage, key, error);
        }
    }
    check_listener_material_paths(config, sink);
    for (index, listener) in config.listeners.iter().enumerate() {
        if let ListenerBind::Unix(path) = &listener.bind {
            let key = SchemaKey::indexed("listeners.endpoint", index_u16(index), "bind");
            if let Err(error) = socket_parent(path) {
                sink.push(stage, key, error);
            }
        }
    }
}

fn check_listener_material_paths(config: &Config, sink: &mut IssueSink) {
    for (key, path) in config.listener_material_paths() {
        let result = protected_ancestors(&path)
            .and_then(|()| read_protected_bytes(&path, MAX_TLS_MATERIAL_BYTES).map(|_| ()));
        if let Err(error) = result {
            sink.push(ValidationStage::PathsAndFileTypes, key, error);
        }
    }
}

pub(crate) fn index_u16(index: usize) -> u16 {
    u16::try_from(index).unwrap_or(u16::MAX)
}

fn check_directory(path: &Path, key: SchemaKey, exact_mode: Option<u32>, sink: &mut IssueSink) {
    if let Err(error) = directory_metadata(path, exact_mode) {
        sink.push(ValidationStage::PathsAndFileTypes, key, error);
    }
}

fn directory_metadata(path: &Path, exact_mode: Option<u32>) -> Result<(), ConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ConfigError::FileRejected)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ConfigError::FileRejected);
    }
    let mode = metadata.permissions().mode() & 0o777;
    if exact_mode.is_some_and(|expected| mode != expected) {
        return Err(ConfigError::FileRejected);
    }
    if exact_mode.is_some() && !owned_by_daemon_or_root(metadata.uid()) {
        return Err(ConfigError::FileRejected);
    }
    Ok(())
}

/// Returns whether a file owner is the daemon's effective UID or root (spec 4329).
pub(crate) fn owned_by_daemon_or_root(uid: u32) -> bool {
    uid == 0 || uid == rustix::process::geteuid().as_raw()
}

/// Rejects any group- or world-writable directory on the path to a secret (spec 4331).
pub(crate) fn protected_ancestors(path: &Path) -> Result<(), ConfigError> {
    let parent = path.parent().ok_or(ConfigError::FileRejected)?;
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        cursor.push(component);
        let metadata = fs::symlink_metadata(&cursor).map_err(|_| ConfigError::FileRejected)?;
        if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o022 != 0 {
            return Err(ConfigError::FileRejected);
        }
    }
    Ok(())
}

/// Requires the parent of a Unix socket path to be an existing directory.
fn socket_parent(path: &Path) -> Result<(), ConfigError> {
    let parent = path.parent().ok_or(ConfigError::FileRejected)?;
    protected_ancestors(path)?;
    directory_metadata(parent, Some(0o750))
}

/// Validates a MOTD or public-info file: UTF-8, at most 64 KiB and 256 lines.
pub(crate) fn public_text(path: &Path) -> Result<String, ConfigError> {
    let text = read_protected_text(path, MAX_PUBLIC_TEXT_BYTES)?;
    if text.lines().count() > MAX_PUBLIC_TEXT_LINES {
        return Err(ConfigError::InvalidValue);
    }
    Ok(text)
}

/// Loads one host-validated MOTD or public-info file.
pub fn load_public_text(path: &Path) -> Result<String, ConfigError> {
    public_text(path)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime};

    use super::{read_opened_protected_bytes, read_protected_bytes, read_protected_text};
    use crate::error::ConfigError;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn create() -> io::Result<Self> {
            for _ in 0..32 {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir().join(format!(
                    "agenc-protected-text-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                        return Ok(Self { root });
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a protected-text test directory",
            ))
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }

        fn file(&self, name: &str, contents: &[u8], mode: u32) -> io::Result<PathBuf> {
            let path = self.path(name);
            fs::write(&path, contents)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            Ok(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn set_modified(path: &Path, seconds: u64) -> io::Result<()> {
        let file = fs::OpenOptions::new().write(true).open(path)?;
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
        file.set_times(fs::FileTimes::new().set_modified(modified))
    }

    #[test]
    fn opened_descriptor_never_reads_a_path_replacement() -> TestResult {
        let directory = TestDirectory::create()?;
        let path = directory.file("public.txt", b"original", 0o600)?;
        let displaced = directory.path("displaced.txt");
        let file = fs::File::open(&path)?;

        let result = read_opened_protected_bytes(file, 64, || {
            assert!(fs::rename(&path, &displaced).is_ok());
            assert!(fs::write(&path, b"replacement").is_ok());
            assert!(fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).is_ok());
        });

        match result {
            Ok(bytes) => assert_eq!(bytes, b"original"),
            Err(error) => assert_eq!(error, ConfigError::FileRejected),
        }
        Ok(())
    }

    #[test]
    fn protected_bytes_reject_a_final_symlink() -> TestResult {
        let directory = TestDirectory::create()?;
        let target = directory.file("target.txt", b"target", 0o600)?;
        let link = directory.path("link.txt");
        symlink(target, &link)?;

        assert_eq!(
            read_protected_bytes(&link, 64),
            Err(ConfigError::FileRejected)
        );
        Ok(())
    }

    #[test]
    fn protected_bytes_reject_growth_after_initial_status() -> TestResult {
        let directory = TestDirectory::create()?;
        let path = directory.file("growing.txt", b"1234", 0o600)?;
        let file = fs::File::open(&path)?;

        let result = read_opened_protected_bytes(file, 4, || {
            assert!(fs::write(&path, b"12345").is_ok());
        });

        assert_eq!(result, Err(ConfigError::FileRejected));
        Ok(())
    }

    #[test]
    fn protected_bytes_reject_mode_change_after_initial_status() -> TestResult {
        let directory = TestDirectory::create()?;
        let path = directory.file("mode.txt", b"protected", 0o600)?;
        let file = fs::File::open(&path)?;

        let result = read_opened_protected_bytes(file, 64, || {
            assert!(fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).is_ok());
        });

        assert_eq!(result, Err(ConfigError::FileRejected));
        Ok(())
    }

    #[test]
    fn protected_bytes_reject_same_size_content_mutation() -> TestResult {
        let directory = TestDirectory::create()?;
        let path = directory.file("mutable.txt", b"1234", 0o600)?;
        set_modified(&path, 1_000_000)?;
        let file = fs::File::open(&path)?;

        let result = read_opened_protected_bytes(file, 4, || {
            assert!(fs::write(&path, b"5678").is_ok());
            assert!(set_modified(&path, 2_000_000).is_ok());
        });

        assert_eq!(result, Err(ConfigError::FileRejected));
        Ok(())
    }

    #[test]
    fn protected_bytes_reject_maximum_plus_one_bytes() -> TestResult {
        let directory = TestDirectory::create()?;
        let path = directory.file("large.txt", b"12345", 0o600)?;

        assert_eq!(
            read_protected_bytes(&path, 4),
            Err(ConfigError::FileRejected)
        );
        Ok(())
    }

    #[test]
    fn protected_bytes_preserve_non_utf8_while_text_rejects_it() -> TestResult {
        let directory = TestDirectory::create()?;
        let path = directory.file("binary.data", &[0xff, 0x00], 0o600)?;

        assert_eq!(read_protected_bytes(&path, 2)?, [0xff, 0x00]);
        assert_eq!(
            read_protected_text(&path, 2),
            Err(ConfigError::FileRejected)
        );
        Ok(())
    }
}
