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
    protected_ancestors(path)?;

    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
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
    links: u64,
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
        || status.st_nlink != 1
        || size > maximum
        || mode & 0o022 != 0
        || !owned_by_daemon_or_root(status.st_uid)
        || modified_nanoseconds >= 1_000_000_000
        || changed_nanoseconds >= 1_000_000_000
    {
        return Err(ConfigError::FileRejected);
    }
    // `nlink_t` is `u64` on x86_64 Linux and `u32` on AArch64 Linux.
    // agenc-review: allow owner=config reviewed=2026-09-01 reason=nlink_t is u64 on x86_64 Linux and u32 on AArch64 Linux so the widening conversion is required on one supported target and a no-op on the other
    #[allow(clippy::useless_conversion)]
    let links = u64::from(status.st_nlink);
    Ok(ProtectedFileStatus {
        device: status.st_dev,
        inode: status.st_ino,
        links,
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
    verify_physical_directory_layout(config, sink);
    verify_protected_material_locations(config, sink);
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
    if !path.is_absolute() || path.components().any(is_unsafe_component) {
        return Err(ConfigError::FileRejected);
    }
    protected_ancestors(&path.join("agenc-host-path-check"))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ConfigError::FileRejected)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ConfigError::FileRejected);
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 || exact_mode.is_some_and(|expected| mode != expected) {
        return Err(ConfigError::FileRejected);
    }
    if !owned_by_daemon_or_root(metadata.uid()) {
        return Err(ConfigError::FileRejected);
    }
    Ok(())
}

#[derive(Debug)]
struct PhysicalDirectory {
    canonical: PathBuf,
    device: u64,
    inode: u64,
}

impl PhysicalDirectory {
    fn open(path: &Path) -> Result<Self, ConfigError> {
        let canonical = fs::canonicalize(path).map_err(|_| ConfigError::FileRejected)?;
        let metadata = fs::metadata(&canonical).map_err(|_| ConfigError::FileRejected)?;
        if !metadata.is_dir() {
            return Err(ConfigError::FileRejected);
        }
        Ok(Self {
            canonical,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn same_as(&self, other: &Self) -> bool {
        self.canonical == other.canonical
            || (self.device == other.device && self.inode == other.inode)
    }

    fn within(&self, other: &Self) -> Result<bool, ConfigError> {
        if self.same_as(other) {
            return Ok(true);
        }
        other.contains_path(&self.canonical)
    }

    fn overlaps(&self, other: &Self) -> Result<bool, ConfigError> {
        if self.within(other)? {
            return Ok(true);
        }
        other.within(self)
    }

    fn contains_path(&self, path: &Path) -> Result<bool, ConfigError> {
        if path.starts_with(&self.canonical) {
            return Ok(true);
        }
        let Some(parent) = path.parent() else {
            return Ok(false);
        };
        for ancestor in parent.ancestors() {
            let metadata = fs::metadata(ancestor).map_err(|_| ConfigError::FileRejected)?;
            if metadata.dev() == self.device && metadata.ino() == self.inode {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn state_directory_layout_is_valid(
    state: &PhysicalDirectory,
    data: &PhysicalDirectory,
    runtime: &PhysicalDirectory,
    backup: &PhysicalDirectory,
) -> Result<bool, ConfigError> {
    Ok(state.within(data)?
        && !state.same_as(data)
        && !state.overlaps(runtime)?
        && !state.overlaps(backup)?)
}

fn backup_directory_layout_is_valid(
    backup: &PhysicalDirectory,
    data: &PhysicalDirectory,
    runtime: &PhysicalDirectory,
) -> Result<bool, ConfigError> {
    Ok(!backup.overlaps(runtime)? && !backup.same_as(data))
}

fn contained_by_any(path: &Path, roots: &[&PhysicalDirectory]) -> Result<bool, ConfigError> {
    for root in roots {
        if root.contains_path(path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_physical_directory_layout(config: &Config, sink: &mut IssueSink) {
    let directories = (
        PhysicalDirectory::open(&config.server.data_dir),
        PhysicalDirectory::open(&config.server.runtime_dir),
        PhysicalDirectory::open(&config.storage.state_dir),
        PhysicalDirectory::open(&config.storage.backup_dir),
    );
    let (Ok(data), Ok(runtime), Ok(state), Ok(backup)) = directories else {
        return;
    };
    let stage = ValidationStage::PathsAndFileTypes;
    match state_directory_layout_is_valid(&state, &data, &runtime, &backup) {
        Ok(true) => {}
        Ok(false) => sink.push(
            stage,
            SchemaKey::new("storage", "state_dir"),
            ConfigError::Topology,
        ),
        Err(error) => sink.push(stage, SchemaKey::new("storage", "state_dir"), error),
    }
    match backup_directory_layout_is_valid(&backup, &data, &runtime) {
        Ok(true) => {}
        Ok(false) => sink.push(
            stage,
            SchemaKey::new("storage", "backup_dir"),
            ConfigError::Topology,
        ),
        Err(error) => sink.push(stage, SchemaKey::new("storage", "backup_dir"), error),
    }
    if runtime.same_as(&data) {
        sink.push(
            stage,
            SchemaKey::new("server", "runtime_dir"),
            ConfigError::Topology,
        );
    }
}

fn verify_protected_material_locations(config: &Config, sink: &mut IssueSink) {
    let roots = (
        PhysicalDirectory::open(&config.server.runtime_dir),
        PhysicalDirectory::open(&config.storage.state_dir),
        PhysicalDirectory::open(&config.storage.backup_dir),
    );
    let (Ok(runtime), Ok(state), Ok(backup)) = roots else {
        return;
    };
    let roots = [&runtime, &state, &backup];
    for (key, path) in config
        .secret_paths()
        .into_iter()
        .chain(config.trust_manifest_paths())
        .chain(config.listener_material_paths())
        .chain(config.public_text_paths())
    {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.nlink() != 1 {
            sink.push(
                ValidationStage::PathsAndFileTypes,
                key,
                ConfigError::FileRejected,
            );
            continue;
        }
        let Ok(canonical) = fs::canonicalize(&path) else {
            continue;
        };
        match contained_by_any(&canonical, &roots) {
            Ok(true) => sink.push(
                ValidationStage::PathsAndFileTypes,
                key,
                ConfigError::Topology,
            ),
            Ok(false) => {}
            Err(error) => sink.push(ValidationStage::PathsAndFileTypes, key, error),
        }
    }
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
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime};

    use super::{
        PhysicalDirectory, protected_ancestors, read_opened_protected_bytes, read_protected_bytes,
        read_protected_text,
    };
    use crate::error::ConfigError;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn create() -> io::Result<Self> {
            let base = protected_test_base()?;
            for _ in 0..32 {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = base.join(format!(
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

    fn protected_test_base() -> io::Result<PathBuf> {
        let candidates = [
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            std::env::var_os("CARGO_TARGET_TMPDIR").map(PathBuf::from),
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")),
        ];
        for base in candidates.into_iter().flatten() {
            if fs::create_dir_all(&base).is_ok()
                && protected_ancestors(&base.join("agenc-test-entry")).is_ok()
            {
                return Ok(base);
            }
        }
        Err(io::Error::other(
            "no protected base is available for path tests",
        ))
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
    fn protected_bytes_reject_an_unprotected_ancestor() -> TestResult {
        let directory = TestDirectory::create()?;
        let loose = directory.path("loose");
        fs::create_dir(&loose)?;
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o770))?;
        let path = loose.join("public.txt");
        fs::write(&path, b"public")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        assert_eq!(
            read_protected_bytes(&path, 64),
            Err(ConfigError::FileRejected)
        );
        Ok(())
    }

    #[test]
    fn protected_bytes_reject_a_hard_link() -> TestResult {
        let directory = TestDirectory::create()?;
        let path = directory.file("public.txt", b"public", 0o600)?;
        let alias = directory.path("public-alias.txt");
        fs::hard_link(&path, &alias)?;

        assert_eq!(
            read_protected_bytes(&path, 64),
            Err(ConfigError::FileRejected)
        );
        assert_eq!(
            read_protected_bytes(&alias, 64),
            Err(ConfigError::FileRejected)
        );
        Ok(())
    }

    #[test]
    fn physical_directories_recognize_a_canonical_alias() -> TestResult {
        let directory = TestDirectory::create()?;
        let physical = directory.path("physical");
        fs::create_dir(&physical)?;
        fs::set_permissions(&physical, fs::Permissions::from_mode(0o700))?;
        let material = physical.join("material");
        fs::write(&material, b"material")?;
        fs::set_permissions(&material, fs::Permissions::from_mode(0o600))?;
        let alias = directory.path("alias");
        symlink(&physical, &alias)?;

        let physical = PhysicalDirectory::open(&physical)?;
        let alias = PhysicalDirectory::open(&alias)?;
        assert!(physical.same_as(&alias));
        assert!(physical.overlaps(&alias)?);
        assert!(physical.contains_path(&fs::canonicalize(&material)?)?);
        let root_metadata = fs::metadata(&directory.root)?;
        let simulated_bind_alias = PhysicalDirectory {
            canonical: directory.path("simulated-bind-alias"),
            device: root_metadata.dev(),
            inode: root_metadata.ino(),
        };
        assert!(physical.within(&simulated_bind_alias)?);
        Ok(())
    }

    #[test]
    fn physical_directory_rejects_unreadable_or_changed_ancestry() -> TestResult {
        let directory = TestDirectory::create()?;
        let physical = directory.path("physical");
        fs::create_dir(&physical)?;
        fs::set_permissions(&physical, fs::Permissions::from_mode(0o700))?;
        let physical = PhysicalDirectory::open(&physical)?;
        let missing_path = directory.path("removed-ancestor/material");

        assert_eq!(
            physical.contains_path(&missing_path),
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
