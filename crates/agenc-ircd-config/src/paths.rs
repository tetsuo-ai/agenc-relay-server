//! Path resolution against the configuration file and host-depth path checks.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use crate::bounds::{MAX_PUBLIC_TEXT_BYTES, MAX_PUBLIC_TEXT_LINES};
use crate::config::Config;
use crate::error::{ConfigError, IssueSink, SchemaKey, ValidationStage};
use crate::listeners::ListenerBind;

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

/// Reads one protected regular text file bounded by `maximum` bytes.
pub(crate) fn read_protected_text(path: &Path, maximum: u64) -> Result<String, ConfigError> {
    if !path.is_absolute() || path.components().any(is_unsafe_component) {
        return Err(ConfigError::FileRejected);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ConfigError::FileRejected)?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum
        || mode & 0o022 != 0
    {
        return Err(ConfigError::FileRejected);
    }
    fs::read_to_string(path).map_err(|_| ConfigError::FileRejected)
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
    for (index, listener) in config.listeners.iter().enumerate() {
        if let ListenerBind::Unix(path) = &listener.bind {
            let key = SchemaKey::indexed("listeners.endpoint", index_u16(index), "bind");
            if let Err(error) = socket_parent(path) {
                sink.push(stage, key, error);
            }
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
    directory_metadata(parent, None)
}

/// Validates a MOTD or public-info file: UTF-8, at most 64 KiB and 256 lines.
pub(crate) fn public_text(path: &Path) -> Result<String, ConfigError> {
    let text = read_protected_text(path, MAX_PUBLIC_TEXT_BYTES)?;
    if text.lines().count() > MAX_PUBLIC_TEXT_LINES {
        return Err(ConfigError::InvalidValue);
    }
    Ok(text)
}
