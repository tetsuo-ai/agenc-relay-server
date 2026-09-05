//! Secret file rules and the loaded secret set (spec 22.2 4307-4334).

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::error::{ConfigError, ConfigReport, IssueSink, SchemaKey, ValidationStage};
use crate::listeners::ListenerName;
use crate::paths::{is_unsafe_component, owned_by_daemon_or_root, protected_ancestors};

/// Exact secret file mode (spec 4330).
pub const SECRET_FILE_MODE: u32 = 0o600;
/// Largest PEM private key, OPAQUE setup, or sequencer key file accepted.
pub const MAX_SECRET_BLOB_BYTES: usize = 16_384;

/// A required secret file length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretLength {
    /// Exactly this many bytes.
    Exact(usize),
    /// At least one and at most this many bytes.
    AtMost(usize),
}

impl SecretLength {
    const fn maximum(self) -> usize {
        match self {
            Self::Exact(bytes) | Self::AtMost(bytes) => bytes,
        }
    }

    fn accepts(self, actual: usize) -> bool {
        match self {
            Self::Exact(bytes) => actual == bytes,
            Self::AtMost(bytes) => actual >= 1 && actual <= bytes,
        }
    }
}

/// The device and inode identity of an opened secret file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct FileIdentity {
    /// Device number.
    pub device: u64,
    /// Inode number.
    pub inode: u64,
}

/// Exactly 32 secret bytes that zeroize on drop.
pub struct SecretBytes32(Zeroizing<[u8; 32]>);

impl SecretBytes32 {
    /// Borrows the bytes at the crypto adapter boundary.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A bounded secret byte string that zeroizes on drop.
pub struct SecretBlob(Zeroizing<Vec<u8>>);

impl SecretBlob {
    /// Borrows the bytes at the crypto adapter boundary.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Opens one secret file under the Section 22.2 rules and reads it exactly once.
pub fn open_secret_file(
    path: &Path,
    length: SecretLength,
) -> Result<(Zeroizing<Vec<u8>>, FileIdentity), ConfigError> {
    open_secret_file_with_hook(path, length, || {})
}

/// The same as [`open_secret_file`] with a hook between the metadata check and the
/// open, so tests can prove a swapped file is rejected.
pub fn open_secret_file_with_hook(
    path: &Path,
    length: SecretLength,
    between_stat_and_open: impl FnOnce(),
) -> Result<(Zeroizing<Vec<u8>>, FileIdentity), ConfigError> {
    if !path.is_absolute() || path.components().any(is_unsafe_component) {
        return Err(ConfigError::FileRejected);
    }
    protected_ancestors(path)?;
    let before = fs::symlink_metadata(path).map_err(|_| ConfigError::FileRejected)?;
    check_metadata(&before, length)?;
    between_stat_and_open();
    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ConfigError::FileRejected)?;
    let after = fstat(&fd).map_err(|_| ConfigError::FileRejected)?;
    let same = FileType::from_raw_mode(after.st_mode) == FileType::RegularFile
        && Mode::from_raw_mode(after.st_mode) == Mode::from_raw_mode(SECRET_FILE_MODE)
        && after.st_nlink == 1
        && after.st_dev == before.dev()
        && after.st_ino == before.ino()
        && after.st_uid == before.uid()
        && u64::try_from(after.st_size).is_ok_and(|size| size == before.len());
    if !same {
        return Err(ConfigError::FileRejected);
    }
    let bytes = read_once(fs::File::from(fd), length)?;
    Ok((
        bytes,
        FileIdentity {
            device: before.dev(),
            inode: before.ino(),
        },
    ))
}

fn check_metadata(metadata: &fs::Metadata, length: SecretLength) -> Result<(), ConfigError> {
    let regular = metadata.file_type().is_file() && !metadata.file_type().is_symlink();
    let mode = metadata.permissions().mode() & 0o7777;
    let size_ok = usize::try_from(metadata.len()).is_ok_and(|size| length.accepts(size));
    if !regular
        || metadata.nlink() != 1
        || mode != SECRET_FILE_MODE
        || !owned_by_daemon_or_root(metadata.uid())
        || !size_ok
    {
        return Err(ConfigError::FileRejected);
    }
    Ok(())
}

fn read_once(mut file: fs::File, length: SecretLength) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    let maximum = length.maximum();
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(maximum.saturating_add(1))
        .map_err(|_| ConfigError::FileRejected)?;
    let limit = u64::try_from(maximum.saturating_add(1)).map_err(|_| ConfigError::Overflow)?;
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::FileRejected)?;
    if !length.accepts(bytes.len()) {
        return Err(ConfigError::FileRejected);
    }
    Ok(bytes)
}

fn secret_32(path: &Path) -> Result<(SecretBytes32, FileIdentity), ConfigError> {
    let (bytes, identity) = open_secret_file(path, SecretLength::Exact(32))?;
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&bytes);
    Ok((SecretBytes32(key), identity))
}

fn trusted_32(path: &Path) -> Result<(SecretBytes32, FileIdentity), ConfigError> {
    let (before, before_mode) = trusted_metadata(path)?;
    let (file, identity) = open_same_trusted_file(path, &before, before_mode)?;
    let bytes = read_once(file, SecretLength::Exact(32))?;
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&bytes);
    Ok((SecretBytes32(key), identity))
}

fn trusted_metadata(path: &Path) -> Result<(fs::Metadata, u32), ConfigError> {
    if !path.is_absolute() || path.components().any(is_unsafe_component) {
        return Err(ConfigError::FileRejected);
    }
    protected_ancestors(path)?;
    let before = fs::symlink_metadata(path).map_err(|_| ConfigError::FileRejected)?;
    let before_mode = before.permissions().mode() & 0o7777;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.nlink() != 1
        || before.len() != 32
        || before_mode & 0o022 != 0
        || !owned_by_daemon_or_root(before.uid())
    {
        return Err(ConfigError::FileRejected);
    }
    Ok((before, before_mode))
}

fn open_same_trusted_file(
    path: &Path,
    before: &fs::Metadata,
    before_mode: u32,
) -> Result<(fs::File, FileIdentity), ConfigError> {
    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ConfigError::FileRejected)?;
    let after = fstat(&fd).map_err(|_| ConfigError::FileRejected)?;
    let same = FileType::from_raw_mode(after.st_mode) == FileType::RegularFile
        && after.st_dev == before.dev()
        && after.st_ino == before.ino()
        && after.st_uid == before.uid()
        && after.st_size == 32
        && after.st_mode & 0o7777 == before_mode;
    if !same {
        return Err(ConfigError::FileRejected);
    }
    Ok((
        fs::File::from(fd),
        FileIdentity {
            device: before.dev(),
            inode: before.ino(),
        },
    ))
}

fn secret_blob(path: &Path) -> Result<(SecretBlob, FileIdentity), ConfigError> {
    let (bytes, identity) = open_secret_file(path, SecretLength::AtMost(MAX_SECRET_BLOB_BYTES))?;
    Ok((SecretBlob(bytes), identity))
}

/// Every secret the daemon holds after stage 4, keyed by purpose.
pub struct SecretSet {
    storage_master: SecretBytes32,
    rollback_guard_root: SecretBytes32,
    login_index: SecretBytes32,
    login_index_previous: Option<SecretBytes32>,
    backup_signing: SecretBytes32,
    audit_signing: SecretBytes32,
    federation_signing: Option<SecretBytes32>,
    access_token: Option<SecretBytes32>,
    invitation_verification: Option<SecretBytes32>,
    account_service_hpke_private: Option<SecretBytes32>,
    opaque_fake_credential: Option<SecretBytes32>,
    opaque_server_setup: Option<SecretBlob>,
    sequencer_private: Option<SecretBytes32>,
    tls_private_keys: Vec<(ListenerName, SecretBlob)>,
}

impl SecretSet {
    /// Opens every configured secret (stage 4), reporting each failure by key and
    /// rejecting any two secrets that share a file identity or byte value
    /// (spec 4303-4306).
    pub fn load(config: &Config) -> Result<Self, ConfigReport> {
        let mut sink = IssueSink::default();
        let mut loader = Loader::default();
        let required = loader.required_keys(&mut sink, config);
        let optional = loader.optional_keys(&mut sink, config);
        let tls_private_keys = loader.tls_keys(&mut sink, config);
        match Self::assemble(required, optional, tls_private_keys) {
            Some(set) if sink.is_empty() => Ok(set),
            _ => Err(sink.into_report()),
        }
    }

    fn assemble(
        required: RequiredKeys,
        optional: OptionalKeys,
        tls_private_keys: Option<Vec<(ListenerName, SecretBlob)>>,
    ) -> Option<Self> {
        Some(Self {
            storage_master: required.storage_master?,
            rollback_guard_root: required.rollback_guard_root?,
            login_index: required.login_index?,
            login_index_previous: required.login_index_previous?,
            backup_signing: required.backup_signing?,
            audit_signing: required.audit_signing?,
            federation_signing: optional.federation_signing?,
            access_token: optional.access_token?,
            invitation_verification: optional.invitation_verification?,
            account_service_hpke_private: optional.account_service_hpke_private?,
            opaque_fake_credential: optional.opaque_fake_credential?,
            opaque_server_setup: optional.opaque_server_setup?,
            sequencer_private: optional.sequencer_private?,
            tls_private_keys: tls_private_keys?,
        })
    }

    /// Storage master key bytes.
    #[must_use]
    pub fn storage_master(&self) -> &SecretBytes32 {
        &self.storage_master
    }

    /// Rollback-guard root key bytes.
    #[must_use]
    pub fn rollback_guard_root(&self) -> &SecretBytes32 {
        &self.rollback_guard_root
    }

    /// Current login-index key bytes.
    #[must_use]
    pub fn login_index(&self) -> &SecretBytes32 {
        &self.login_index
    }

    /// Previous login-index key bytes during a transition.
    #[must_use]
    pub fn login_index_previous(&self) -> Option<&SecretBytes32> {
        self.login_index_previous.as_ref()
    }

    /// Backup signing key bytes.
    #[must_use]
    pub fn backup_signing(&self) -> &SecretBytes32 {
        &self.backup_signing
    }

    /// Audit signing key bytes.
    #[must_use]
    pub fn audit_signing(&self) -> &SecretBytes32 {
        &self.audit_signing
    }

    /// Federation signing key bytes when federation is enabled.
    #[must_use]
    pub fn federation_signing(&self) -> Option<&SecretBytes32> {
        self.federation_signing.as_ref()
    }

    /// PASS admission token key bytes when configured.
    #[must_use]
    pub fn access_token(&self) -> Option<&SecretBytes32> {
        self.access_token.as_ref()
    }

    /// Account-creation invitation verification key bytes when configured.
    #[must_use]
    pub fn invitation_verification(&self) -> Option<&SecretBytes32> {
        self.invitation_verification.as_ref()
    }

    /// Coordinator account-service HPKE private key bytes.
    #[must_use]
    pub fn account_service_hpke_private(&self) -> Option<&SecretBytes32> {
        self.account_service_hpke_private.as_ref()
    }

    /// Coordinator fake-credential key bytes.
    #[must_use]
    pub fn opaque_fake_credential(&self) -> Option<&SecretBytes32> {
        self.opaque_fake_credential.as_ref()
    }

    /// Coordinator OPAQUE server setup bytes.
    #[must_use]
    pub fn opaque_server_setup(&self) -> Option<&SecretBlob> {
        self.opaque_server_setup.as_ref()
    }

    /// E2EE sequencer private key bytes.
    #[must_use]
    pub fn sequencer_private(&self) -> Option<&SecretBytes32> {
        self.sequencer_private.as_ref()
    }

    /// TLS private key file bytes by listener name.
    #[must_use]
    pub fn tls_private_key(&self, listener: &ListenerName) -> Option<&SecretBlob> {
        self.tls_private_keys
            .iter()
            .find(|(name, _)| name == listener)
            .map(|(_, blob)| blob)
    }
}

struct RequiredKeys {
    storage_master: Option<SecretBytes32>,
    rollback_guard_root: Option<SecretBytes32>,
    login_index: Option<SecretBytes32>,
    login_index_previous: Option<Option<SecretBytes32>>,
    backup_signing: Option<SecretBytes32>,
    audit_signing: Option<SecretBytes32>,
}

struct OptionalKeys {
    federation_signing: Option<Option<SecretBytes32>>,
    access_token: Option<Option<SecretBytes32>>,
    invitation_verification: Option<Option<SecretBytes32>>,
    account_service_hpke_private: Option<Option<SecretBytes32>>,
    opaque_fake_credential: Option<Option<SecretBytes32>>,
    opaque_server_setup: Option<Option<SecretBlob>>,
    sequencer_private: Option<Option<SecretBytes32>>,
}

/// Tracks identities and byte values so no two secrets coincide.
#[derive(Default)]
struct Loader {
    identities: Vec<FileIdentity>,
    values: Vec<Zeroizing<Vec<u8>>>,
}

impl Loader {
    fn register(&mut self, identity: FileIdentity, bytes: &[u8]) -> Result<(), ConfigError> {
        if self.identities.contains(&identity)
            || self.values.iter().any(|value| value.as_slice() == bytes)
        {
            return Err(ConfigError::InvalidValue);
        }
        self.identities.push(identity);
        self.values.push(Zeroizing::new(bytes.to_vec()));
        Ok(())
    }

    fn key32(
        &mut self,
        sink: &mut IssueSink,
        table: &'static str,
        field: &'static str,
        path: &Path,
    ) -> Option<SecretBytes32> {
        let result = secret_32(path).and_then(|(key, identity)| {
            self.register(identity, key.expose())?;
            Ok(key)
        });
        stage4(sink, SchemaKey::new(table, field), result)
    }

    fn optional32(
        &mut self,
        sink: &mut IssueSink,
        table: &'static str,
        field: &'static str,
        path: Option<&Path>,
    ) -> Option<Option<SecretBytes32>> {
        match path {
            None => Some(None),
            Some(path) => self.key32(sink, table, field, path).map(Some),
        }
    }

    fn optional_blob(
        &mut self,
        sink: &mut IssueSink,
        key: SchemaKey,
        path: Option<&Path>,
    ) -> Option<Option<SecretBlob>> {
        let Some(path) = path else {
            return Some(None);
        };
        let result = secret_blob(path).and_then(|(blob, identity)| {
            self.register(identity, blob.expose())?;
            Ok(blob)
        });
        stage4(sink, key, result).map(Some)
    }

    fn optional_trusted32(
        &mut self,
        sink: &mut IssueSink,
        table: &'static str,
        field: &'static str,
        path: Option<&Path>,
    ) -> Option<Option<SecretBytes32>> {
        let Some(path) = path else {
            return Some(None);
        };
        let result = trusted_32(path).and_then(|(key, identity)| {
            self.register(identity, key.expose())?;
            Ok(key)
        });
        stage4(sink, SchemaKey::new(table, field), result).map(Some)
    }

    fn required_keys(&mut self, sink: &mut IssueSink, config: &Config) -> RequiredKeys {
        let storage = &config.storage;
        RequiredKeys {
            storage_master: self.key32(
                sink,
                "storage",
                "master_key_file",
                &storage.master_key_file,
            ),
            rollback_guard_root: self.key32(
                sink,
                "storage",
                "rollback_guard_key_file",
                &storage.rollback_guard_key_file,
            ),
            login_index: self.key32(
                sink,
                "storage",
                "login_index_key_file",
                &storage.login_index_key_file,
            ),
            login_index_previous: self.optional32(
                sink,
                "storage",
                "login_index_previous_key_file",
                storage.login_index_previous_key_file.as_deref(),
            ),
            backup_signing: self.key32(
                sink,
                "storage",
                "backup_signing_private_key_file",
                &storage.backup_signing_private_key_file,
            ),
            audit_signing: self.key32(
                sink,
                "moderation",
                "audit_signing_private_key_file",
                &config.moderation.audit_signing_private_key_file,
            ),
        }
    }

    fn optional_keys(&mut self, sink: &mut IssueSink, config: &Config) -> OptionalKeys {
        let accounts = &config.accounts;
        OptionalKeys {
            federation_signing: self.optional32(
                sink,
                "federation",
                "signing_private_key_file",
                config.federation.signing_private_key_file.as_deref(),
            ),
            access_token: self.optional32(
                sink,
                "accounts",
                "access_token_key_file",
                accounts.access_token_key_file.as_deref(),
            ),
            invitation_verification: self.optional_trusted32(
                sink,
                "accounts",
                "invite_verification_key_file",
                accounts.invite_verification_key_file.as_deref(),
            ),
            account_service_hpke_private: self.optional32(
                sink,
                "accounts",
                "account_service_hpke_private_key_file",
                accounts.account_service_hpke_private_key_file.as_deref(),
            ),
            opaque_fake_credential: self.optional32(
                sink,
                "accounts",
                "opaque_fake_credential_key_file",
                accounts.opaque_fake_credential_key_file.as_deref(),
            ),
            opaque_server_setup: self.optional_blob(
                sink,
                SchemaKey::new("accounts", "opaque_server_setup_file"),
                accounts.opaque_server_setup_file.as_deref(),
            ),
            sequencer_private: self.optional32(
                sink,
                "e2ee",
                "sequencer_private_key_file",
                config.e2ee.sequencer_private_key_file.as_deref(),
            ),
        }
    }

    fn tls_keys(
        &mut self,
        sink: &mut IssueSink,
        config: &Config,
    ) -> Option<Vec<(ListenerName, SecretBlob)>> {
        let mut keys = Vec::new();
        let mut complete = true;
        for (index, listener) in config.listeners.iter().enumerate() {
            let Some(tls) = &listener.tls else {
                continue;
            };
            let key = SchemaKey::indexed(
                "listeners.endpoint",
                crate::paths::index_u16(index),
                "tls_private_key_file",
            );
            match self.optional_blob(sink, key, Some(tls.private_key_file.as_path())) {
                Some(Some(blob)) => keys.push((listener.name.clone(), blob)),
                _ => complete = false,
            }
        }
        complete.then_some(keys)
    }
}

fn stage4<T>(sink: &mut IssueSink, key: SchemaKey, result: Result<T, ConfigError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            sink.push(ValidationStage::KeyParsing, key, error);
            None
        }
    }
}

/// Returns the configured secret path list for callers that report by key.
#[must_use]
pub fn secret_paths(config: &Config) -> Vec<(SchemaKey, PathBuf)> {
    config.secret_paths()
}
