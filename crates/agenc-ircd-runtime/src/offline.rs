//! Stopped-daemon initialization and inspection commands (spec 22.2-22.3
//! and Appendix C.8).
//!
//! These entry points do not start Tokio, bind a socket, contact a network,
//! or make generated listeners active. Secret bytes move from operating-system
//! entropy into mode-0600 files and crypto adapters only.

use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, chown};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use agenc_ircd_admin::encode_base64url;
use agenc_ircd_auth::{AccountCreationInvite, OpaqueProfile};
use agenc_ircd_config::{
    Config, ConfigError, ConfigReport, DEFAULT_REDB_CACHE_BYTES, DisplayLabel, DnsName,
    InitProfile, InitValues, MAX_ONBOARDING_DESCRIPTOR_BYTES, NodeRole, OnboardingDescriptor,
    OnboardingFacts, OperatorTemplate, SecretLength, SecretSet, ValidationDepth,
    encode_base64url_32, load_config, open_secret_file, parse_onboarding_descriptor,
    render_onboarding as render_config_onboarding, render_template,
};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, AccountHpkePublicKey, Ed25519SecretKey, LoginIndexKey, OsEntropy,
    RollbackGuardRootKey, SemanticHashDomain, StorageDigest, StorageMasterKey,
    audit_signing_key_id, backup_signing_key_id, semantic_digest,
};
use agenc_ircd_storage::{
    DatabaseHeaderTbs, InitialStorageRecord, InspectionStateDirectory, LIVE_RECORD_KIND,
    LOGIN_INDEX_KEY_STATE_KEY, LoginIndexKeyState, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue,
    SCHEMA_GENERATION, StateDirectory, StorageEngineLimits, StorageError,
    StorageInitializationConfig, StorageInitializationMode, StorageInitializationOutcome,
    StorageInspectionConfig, StoredKey, TableId, embedded_storage_qualifications,
    initialize_storage, inspect_storage, rename_path_no_replace,
};
use agenc_ircd_types::{
    DatabaseId, InviteId, NetworkId, OperatorId, RecoveryEpoch, ServerId, ServerIncarnation,
    UtcSecond,
};
use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, fsync, openat};
use rustix::process::geteuid;
use zeroize::Zeroizing;

#[cfg(test)]
use agenc_ircd_storage::{StorageOpenConfig, StorageOwner};

const DIRECTORY_MODE: u32 = 0o700;
const SECRET_MODE: u32 = 0o600;
const CONFIG_MODE: u32 = 0o640;
const MAX_STAGED_PATHS: usize = 256;
const INSTALL_DIRECTORY_NAMES: [&str; 4] = ["keys", "trust", "state", "backups"];
const MAX_INVITE_LIFETIME_SECONDS: u64 = 2_592_000;
const DEFAULT_DATABASE_BYTES: u64 = 85_899_345_920;
const DEFAULT_BACKUP_BYTES: u64 = 107_374_182_400;
const DEFAULT_RESERVE_BYTES: u64 = 1_073_741_824;
const DEFAULT_RESERVE_PERCENT: u8 = 5;
const DEFAULT_CHECKPOINT_MANIFESTS: u64 = 100_000;

/// Network authority selected for one stopped-daemon initialization.
pub enum InitMode {
    /// Create a coordinator, generating a Network ID unless one is supplied by
    /// an embedding or deterministic test.
    Coordinator {
        /// Optional preselected Network ID.
        network_id: Option<NetworkId>,
    },
    /// Create an edge from one trusted coordinator descriptor.
    Edge {
        /// Trusted canonical onboarding descriptor.
        coordinator_descriptor: PathBuf,
        /// Coordinator identity confirmed out of band with the descriptor.
        coordinator_server_id: ServerId,
    },
}

/// Inputs for one stopped-daemon first-run initialization.
pub struct InitRequest {
    /// Configuration file installed last.
    pub config_path: PathBuf,
    /// Convenience listener profile.
    pub profile: InitProfile,
    /// Coordinator creation or trusted edge import.
    pub mode: InitMode,
    /// Dedicated persistent directory.
    pub data_dir: PathBuf,
    /// Dedicated runtime directory.
    pub runtime_dir: PathBuf,
    /// Offline operator signing authority, outside daemon-readable roots.
    pub operator_signing_key_file: PathBuf,
    /// Local DNS-style server name.
    pub server_name: DnsName,
    /// Public network display label.
    pub display_name: DisplayLabel,
    /// Public DNS endpoint for public and dual profiles.
    pub dns_name: Option<DnsName>,
}

/// Public, non-secret output from successful initialization.
pub struct InitReceipt {
    /// Fresh network identity.
    pub network_id: NetworkId,
    /// Fresh local server identity.
    pub server_id: ServerId,
    /// Fresh local operator identity.
    pub operator_id: OperatorId,
    /// Offline operator signing-key path.
    pub operator_signing_key_file: PathBuf,
    /// Tor configuration to review and install separately.
    pub tor_snippet: String,
    /// Service-manager configuration to review separately.
    pub systemd_snippet: String,
    /// Certificate enrollment steps.
    pub certificate_instructions: String,
}

/// Authenticated stopped-database facts used by `check-config` and onboarding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderFacts {
    /// Continuous recovery lineage.
    pub recovery_epoch: RecoveryEpoch,
    /// Durable logical state generation.
    pub state_generation: u64,
    /// Account-service response counter.
    pub account_service_response_count: u64,
}

/// Closed, secret-free failures for offline operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineError {
    /// A command argument or descriptor was invalid.
    InvalidRequest,
    /// An initialization target already existed.
    ExistingTarget,
    /// Protected filesystem work failed.
    Filesystem,
    /// Configuration parsing or validation failed.
    Configuration,
    /// Key construction or operating-system entropy failed.
    Cryptography,
    /// Account invitation or OPAQUE construction failed.
    Authentication,
    /// Authenticated storage refused the operation.
    Storage,
    /// Initialization crossed an unknowable durable boundary.
    Indeterminate,
    /// At least one final initialization artifact was already installed.
    PartialInitialization,
}

impl OfflineError {
    /// Returns whether `init` must use its partial-installation exit status.
    #[must_use]
    pub const fn is_partial_initialization(self) -> bool {
        matches!(self, Self::PartialInitialization | Self::Indeterminate)
    }
}

impl fmt::Display for OfflineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidRequest => "offline request rejected",
            Self::ExistingTarget => "initialization target already exists",
            Self::Filesystem => "protected filesystem operation failed",
            Self::Configuration => "configuration validation failed",
            Self::Cryptography => "cryptographic setup failed",
            Self::Authentication => "account setup failed",
            Self::Storage => "authenticated storage operation failed",
            Self::Indeterminate => "storage initialization outcome is indeterminate",
            Self::PartialInitialization => "initialization is partially installed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OfflineError {}

impl From<ConfigError> for OfflineError {
    fn from(_: ConfigError) -> Self {
        Self::Configuration
    }
}

impl From<ConfigReport> for OfflineError {
    fn from(_: ConfigReport) -> Self {
        Self::Configuration
    }
}

impl From<StorageError> for OfflineError {
    fn from(_: StorageError) -> Self {
        Self::Storage
    }
}

struct GeneratedSecrets {
    storage_master: Zeroizing<[u8; 32]>,
    rollback_guard: Zeroizing<[u8; 32]>,
    login_index: Zeroizing<[u8; 32]>,
    federation_signing: Zeroizing<[u8; 32]>,
    backup_signing: Zeroizing<[u8; 32]>,
    audit_signing: Zeroizing<[u8; 32]>,
    operator_signing: Zeroizing<[u8; 32]>,
    coordinator: Option<CoordinatorSecrets>,
}

struct CoordinatorSecrets {
    account_hpke: Zeroizing<[u8; 32]>,
    opaque_fake_credential: Zeroizing<[u8; 32]>,
    sequencer: Zeroizing<[u8; 32]>,
    opaque: OpaqueProfile,
}

impl GeneratedSecrets {
    fn generate(network_id: NetworkId, role: NodeRole) -> Result<Self, OfflineError> {
        Ok(Self {
            storage_master: random_32()?,
            rollback_guard: random_32()?,
            login_index: random_32()?,
            federation_signing: random_32()?,
            backup_signing: random_32()?,
            audit_signing: random_32()?,
            operator_signing: random_32()?,
            coordinator: match role {
                NodeRole::Coordinator => Some(CoordinatorSecrets {
                    account_hpke: random_32()?,
                    opaque_fake_credential: random_32()?,
                    sequencer: random_32()?,
                    opaque: OpaqueProfile::generate(network_id)
                        .map_err(|_| OfflineError::Authentication)?,
                }),
                NodeRole::Edge => None,
            },
        })
    }
}

enum PreparedInitMode {
    Coordinator {
        network_id: Option<NetworkId>,
    },
    Edge {
        network_id: NetworkId,
        account_service_hpke_public_key: [u8; 32],
        coordinator_server_id: ServerId,
    },
}

impl PreparedInitMode {
    const fn role(&self) -> NodeRole {
        match self {
            Self::Coordinator { .. } => NodeRole::Coordinator,
            Self::Edge { .. } => NodeRole::Edge,
        }
    }

    const fn imported_network_id(&self) -> Option<NetworkId> {
        match self {
            Self::Coordinator { network_id } => *network_id,
            Self::Edge { network_id, .. } => Some(*network_id),
        }
    }

    const fn coordinator_server_id(&self, local_server_id: ServerId) -> ServerId {
        match self {
            Self::Coordinator { .. } => local_server_id,
            Self::Edge {
                coordinator_server_id,
                ..
            } => *coordinator_server_id,
        }
    }

    const fn imported_hpke_public_key(&self) -> Option<[u8; 32]> {
        match self {
            Self::Coordinator { .. } => None,
            Self::Edge {
                account_service_hpke_public_key,
                ..
            } => Some(*account_service_hpke_public_key),
        }
    }
}

#[derive(Clone, Copy)]
struct InitIdentity {
    network_id: NetworkId,
    server_id: ServerId,
    server_incarnation: ServerIncarnation,
    database_id: DatabaseId,
    recovery_epoch: RecoveryEpoch,
    operator_id: OperatorId,
}

impl InitIdentity {
    fn generate(mode: &PreparedInitMode) -> Result<Self, OfflineError> {
        let mut entropy = OsEntropy;
        let identity = Self {
            network_id: mode
                .imported_network_id()
                .map_or_else(|| NetworkId::generate(&mut entropy), Ok)
                .map_err(|_| OfflineError::Cryptography)?,
            server_id: ServerId::generate(&mut entropy).map_err(|_| OfflineError::Cryptography)?,
            server_incarnation: ServerIncarnation::generate(&mut entropy)
                .map_err(|_| OfflineError::Cryptography)?,
            database_id: DatabaseId::generate(&mut entropy)
                .map_err(|_| OfflineError::Cryptography)?,
            recovery_epoch: RecoveryEpoch::generate(&mut entropy)
                .map_err(|_| OfflineError::Cryptography)?,
            operator_id: OperatorId::generate(&mut entropy)
                .map_err(|_| OfflineError::Cryptography)?,
        };
        if mode.role() == NodeRole::Edge
            && mode.coordinator_server_id(identity.server_id) == identity.server_id
        {
            return Err(OfflineError::InvalidRequest);
        }
        Ok(identity)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ownership {
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: Ownership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryTarget {
    name: &'static str,
    precreated: Option<DirectoryIdentity>,
}

struct Staging {
    data_root: PathBuf,
    config_file: PathBuf,
    operator_signing_key_file: PathBuf,
    directory_targets: Vec<DirectoryTarget>,
    data_owner: Ownership,
    config_owner: Ownership,
    operator_owner: Ownership,
    installed: bool,
}

impl Staging {
    fn create(request: &InitRequest) -> Result<Self, OfflineError> {
        ensure_data_directory(&request.data_dir)?;
        validate_physical_root_separation(request)?;
        let data_identity = private_directory_identity(&request.data_dir, DIRECTORY_MODE)?;
        let directory_targets = prepare_directory_targets(request, data_identity.owner)?;
        let data_root = request.data_dir.join(staging_name()?);
        let config_parent = request
            .config_path
            .parent()
            .ok_or(OfflineError::InvalidRequest)?;
        let config_owner = directory_identity(config_parent)?.owner;
        let config_file = config_parent.join(format!("{}-config.toml", staging_name()?));
        let operator_parent = request
            .operator_signing_key_file
            .parent()
            .ok_or(OfflineError::InvalidRequest)?;
        let operator_owner = private_directory_identity(operator_parent, DIRECTORY_MODE)?.owner;
        let operator_signing_key_file =
            operator_parent.join(format!("{}-operator-signing.key", staging_name()?));
        create_staging_directory(&data_root)?;
        let staging = Self {
            data_root,
            config_file,
            operator_signing_key_file,
            directory_targets,
            data_owner: data_identity.owner,
            config_owner,
            operator_owner,
            installed: false,
        };
        for name in INSTALL_DIRECTORY_NAMES {
            create_staging_directory(&staging.data_root.join(name))?;
        }
        Ok(staging)
    }

    fn data_root(&self) -> &Path {
        &self.data_root
    }

    fn config_file(&self) -> &Path {
        &self.config_file
    }

    fn operator_signing_key_file(&self) -> &Path {
        &self.operator_signing_key_file
    }

    fn install(&mut self, request: &InitRequest) -> Result<(), OfflineError> {
        self.verify_publish_targets(request)?;
        self.prepare_ownership()?;
        for target in self.directory_targets.clone() {
            self.install_directory_target(request, target)?;
        }
        self.rename(
            self.operator_signing_key_file.clone(),
            request.operator_signing_key_file.clone(),
        )?;
        self.rename(self.config_file.clone(), request.config_path.clone())?;
        fs::remove_dir(&self.data_root).map_err(|_| OfflineError::PartialInitialization)?;
        sync_directory(&request.data_dir).map_err(|_| OfflineError::PartialInitialization)
    }

    fn install_directory_target(
        &mut self,
        request: &InitRequest,
        target: DirectoryTarget,
    ) -> Result<(), OfflineError> {
        let final_path = request.data_dir.join(target.name);
        self.remove_precreated_target(&final_path, target.precreated)?;
        let source = self.data_root.join(target.name);
        match self.rename(source, final_path.clone()) {
            Ok(()) => Ok(()),
            Err(error) => restore_target_after_failure(&final_path, target.precreated, error),
        }
    }

    fn remove_precreated_target(
        &self,
        path: &Path,
        expected: Option<DirectoryIdentity>,
    ) -> Result<(), OfflineError> {
        let Some(expected) = expected else {
            return Ok(());
        };
        verify_precreated_directory(path, expected).map_err(|error| self.install_error(error))?;
        fs::remove_dir(path).map_err(|_| self.install_error(OfflineError::Filesystem))
    }

    fn rename(&mut self, source: PathBuf, target: PathBuf) -> Result<(), OfflineError> {
        match rename_path_no_replace(&source, &target) {
            Ok(()) => {
                self.installed = true;
                sync_parent(&target).map_err(|_| OfflineError::PartialInitialization)
            }
            Err(_) if self.installed => Err(OfflineError::PartialInitialization),
            Err(_) => Err(OfflineError::Filesystem),
        }
    }

    fn verify_publish_targets(&self, request: &InitRequest) -> Result<(), OfflineError> {
        require_absent(&request.config_path)
            .map_err(|_| self.install_error(OfflineError::Filesystem))?;
        require_absent(&request.operator_signing_key_file)
            .map_err(|_| self.install_error(OfflineError::Filesystem))?;
        for target in &self.directory_targets {
            let path = request.data_dir.join(target.name);
            match target.precreated {
                Some(expected) => verify_precreated_directory(&path, expected),
                None => require_absent(&path),
            }
            .map_err(|_| self.install_error(OfflineError::Filesystem))?;
        }
        Ok(())
    }

    fn prepare_ownership(&self) -> Result<(), OfflineError> {
        for target in &self.directory_targets {
            let owner = target
                .precreated
                .map_or(self.data_owner, |identity| identity.owner);
            let path = self.data_root.join(target.name);
            set_tree_ownership(&path, owner)?;
            sync_directory(&path)?;
        }
        set_path_ownership(&self.operator_signing_key_file, self.operator_owner)?;
        fs::set_permissions(
            &self.operator_signing_key_file,
            fs::Permissions::from_mode(SECRET_MODE),
        )
        .map_err(|_| OfflineError::Filesystem)?;
        sync_regular_file(&self.operator_signing_key_file)?;
        set_path_ownership(&self.config_file, self.config_owner)?;
        fs::set_permissions(&self.config_file, fs::Permissions::from_mode(CONFIG_MODE))
            .map_err(|_| OfflineError::Filesystem)?;
        sync_regular_file(&self.config_file)
    }

    const fn install_error(&self, error: OfflineError) -> OfflineError {
        if self.installed {
            OfflineError::PartialInitialization
        } else {
            error
        }
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _config_cleanup = fs::remove_file(&self.config_file);
        let _operator_cleanup = fs::remove_file(&self.operator_signing_key_file);
        if !self.installed {
            let _cleanup = fs::remove_dir_all(&self.data_root);
        }
    }
}

/// Creates a new stopped node and installs the configuration last.
pub fn initialize_node(request: InitRequest) -> Result<InitReceipt, OfflineError> {
    validate_init_request(&request)?;
    refuse_existing_targets(&request)?;
    let mode = prepare_init_mode(&request.mode)?;
    let identity = InitIdentity::generate(&mode)?;
    let secrets = GeneratedSecrets::generate(identity.network_id, mode.role())?;
    let mut staging = Staging::create(&request)?;
    write_generated_secrets(&staging.data_root().join("keys"), &secrets)?;
    write_secret(
        staging.operator_signing_key_file(),
        secrets.operator_signing.as_slice(),
    )?;
    write_trust_manifests(&staging.data_root().join("trust"), &secrets)?;
    if let Err(error) = initialize_database(&staging.data_root().join("state"), identity, &secrets)
    {
        // An indeterminate storage outcome leaves the staged tree in place so
        // the operator can inspect it; nothing was published.
        if error == OfflineError::Indeterminate {
            staging.installed = true;
        }
        return Err(error);
    }
    write_configuration(staging.config_file(), &request, &mode, identity, &secrets)?;
    staging.install(&request)?;
    Ok(init_receipt(&request, identity))
}

fn prepare_init_mode(mode: &InitMode) -> Result<PreparedInitMode, OfflineError> {
    match mode {
        InitMode::Coordinator { network_id } => Ok(PreparedInitMode::Coordinator {
            network_id: *network_id,
        }),
        InitMode::Edge {
            coordinator_descriptor,
            coordinator_server_id,
        } => {
            let descriptor = read_descriptor(coordinator_descriptor)?.descriptor;
            Ok(PreparedInitMode::Edge {
                network_id: descriptor.network_id,
                account_service_hpke_public_key: descriptor.account_service_hpke_public_key,
                coordinator_server_id: *coordinator_server_id,
            })
        }
    }
}

/// Parses a command-line network identity without making the binary depend on
/// the foundational types crate directly.
pub fn parse_network_id(text: &str) -> Result<NetworkId, OfflineError> {
    NetworkId::parse(text).map_err(|_| OfflineError::InvalidRequest)
}

/// Parses a command-line server identity without making the binary depend on
/// the foundational types crate directly.
pub fn parse_server_id(text: &str) -> Result<ServerId, OfflineError> {
    ServerId::parse(text).map_err(|_| OfflineError::InvalidRequest)
}

fn validate_init_request(request: &InitRequest) -> Result<(), OfflineError> {
    validate_init_paths(request)?;
    if matches!(request.profile, InitProfile::Public | InitProfile::Dual)
        && request.dns_name.is_none()
    {
        return Err(OfflineError::InvalidRequest);
    }
    if matches!(
        &request.mode,
        InitMode::Edge {
            coordinator_descriptor,
            ..
        } if !safe_absolute_path(coordinator_descriptor)
    ) {
        return Err(OfflineError::InvalidRequest);
    }
    Ok(())
}

fn validate_init_paths(request: &InitRequest) -> Result<(), OfflineError> {
    if !valid_init_path_shapes(request) {
        return Err(OfflineError::InvalidRequest);
    }
    validate_lexical_root_separation(request)?;
    validate_init_path_controls(request)?;
    validate_physical_root_separation(request)?;
    validate_edge_descriptor_path(request)
}

fn valid_init_path_shapes(request: &InitRequest) -> bool {
    valid_output_path(&request.config_path)
        && safe_absolute_path(&request.data_dir)
        && safe_absolute_path(&request.runtime_dir)
        && valid_output_path(&request.operator_signing_key_file)
}

fn valid_output_path(path: &Path) -> bool {
    safe_absolute_path(path) && path.file_name().is_some()
}

fn validate_lexical_root_separation(request: &InitRequest) -> Result<(), OfflineError> {
    let config_root = request
        .config_path
        .parent()
        .ok_or(OfflineError::InvalidRequest)?;
    let operator_root = request
        .operator_signing_key_file
        .parent()
        .ok_or(OfflineError::InvalidRequest)?;
    let root_overlap = paths_overlap(config_root, &request.data_dir)
        || paths_overlap(config_root, &request.runtime_dir)
        || paths_overlap(config_root, operator_root)
        || paths_overlap(operator_root, &request.data_dir)
        || paths_overlap(operator_root, &request.runtime_dir)
        || paths_overlap(&request.data_dir, &request.runtime_dir);
    if root_overlap {
        return Err(OfflineError::InvalidRequest);
    }
    Ok(())
}

fn validate_init_path_controls(request: &InitRequest) -> Result<(), OfflineError> {
    validate_creation_parent(&request.config_path, None)?;
    validate_data_path(&request.data_dir)?;
    private_directory_identity(&request.runtime_dir, 0o750)?;
    validate_creation_parent(&request.operator_signing_key_file, Some(DIRECTORY_MODE))?;
    Ok(())
}

fn validate_edge_descriptor_path(request: &InitRequest) -> Result<(), OfflineError> {
    if let InitMode::Edge {
        coordinator_descriptor,
        ..
    } = &request.mode
    {
        validate_existing_file_path(coordinator_descriptor)?;
    }
    Ok(())
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.to_str().is_some()
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn validate_physical_root_separation(request: &InitRequest) -> Result<(), OfflineError> {
    let config_root = request
        .config_path
        .parent()
        .ok_or(OfflineError::InvalidRequest)?;
    let operator_root = request
        .operator_signing_key_file
        .parent()
        .ok_or(OfflineError::InvalidRequest)?;
    let mut roots = vec![config_root, request.runtime_dir.as_path(), operator_root];
    if fs::symlink_metadata(&request.data_dir).is_ok() {
        roots.push(&request.data_dir);
    }
    for (index, left) in roots.iter().enumerate() {
        for right in roots.iter().skip(index + 1) {
            if physical_directories_overlap(left, right)? {
                return Err(OfflineError::InvalidRequest);
            }
        }
    }
    Ok(())
}

fn physical_directories_overlap(left: &Path, right: &Path) -> Result<bool, OfflineError> {
    let left_identity = directory_identity(left)?;
    let right_identity = directory_identity(right)?;
    if same_directory(left_identity, right_identity) {
        return Ok(true);
    }
    Ok(physical_directory_contains(left_identity, right)?
        || physical_directory_contains(right_identity, left)?)
}

fn physical_directory_contains(
    ancestor: DirectoryIdentity,
    descendant: &Path,
) -> Result<bool, OfflineError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open_physical_directory(descendant)?;
    for _ in 0..MAX_STAGED_PATHS {
        let current = opened_directory_identity(&directory)?;
        if same_directory(ancestor, current) {
            return Ok(true);
        }
        let parent = openat(&directory, Path::new(".."), flags, Mode::empty())
            .map_err(|_| OfflineError::Filesystem)?;
        let parent_file = fs::File::from(parent);
        let parent_identity = opened_directory_identity(&parent_file)?;
        if same_directory(current, parent_identity) {
            return Ok(false);
        }
        directory = parent_file;
    }
    Err(OfflineError::Filesystem)
}

const fn same_directory(left: DirectoryIdentity, right: DirectoryIdentity) -> bool {
    left.device == right.device && left.inode == right.inode
}

fn open_physical_directory(path: &Path) -> Result<fs::File, OfflineError> {
    if !safe_absolute_path(path) {
        return Err(OfflineError::InvalidRequest);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        openat(CWD, Path::new("/"), flags, Mode::empty()).map_err(|_| OfflineError::Filesystem)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, Path::new(name), flags, Mode::empty())
                    .map_err(|_| OfflineError::Filesystem)?;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(OfflineError::InvalidRequest);
            }
        }
    }
    Ok(fs::File::from(directory))
}

fn directory_identity(path: &Path) -> Result<DirectoryIdentity, OfflineError> {
    let directory = open_physical_directory(path)?;
    opened_directory_identity(&directory)
}

fn opened_directory_identity(directory: &fs::File) -> Result<DirectoryIdentity, OfflineError> {
    let status = fstat(directory).map_err(|_| OfflineError::Filesystem)?;
    if FileType::from_raw_mode(status.st_mode) != FileType::Directory {
        return Err(OfflineError::Filesystem);
    }
    Ok(DirectoryIdentity {
        device: status.st_dev,
        inode: status.st_ino,
        mode: status.st_mode & 0o777,
        owner: Ownership {
            uid: status.st_uid,
            gid: status.st_gid,
        },
    })
}

fn private_directory_identity(
    path: &Path,
    expected_mode: u32,
) -> Result<DirectoryIdentity, OfflineError> {
    let identity = directory_identity(path)?;
    if identity.mode != expected_mode {
        return Err(OfflineError::Filesystem);
    }
    Ok(identity)
}

fn validate_creation_parent(path: &Path, exact_mode: Option<u32>) -> Result<(), OfflineError> {
    let parent = path.parent().ok_or(OfflineError::InvalidRequest)?;
    let identity = directory_identity(parent)?;
    if exact_mode.is_some_and(|mode| identity.mode != mode)
        || exact_mode.is_none() && identity.mode & 0o022 != 0
    {
        return Err(OfflineError::Filesystem);
    }
    Ok(())
}

fn validate_data_path(path: &Path) -> Result<(), OfflineError> {
    validate_data_path_for_privilege(path, geteuid().is_root())
}

fn validate_data_path_for_privilege(path: &Path, is_root: bool) -> Result<(), OfflineError> {
    match fs::symlink_metadata(path) {
        Ok(_) => private_directory_identity(path, DIRECTORY_MODE).map(|_| ()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !is_root => {
            validate_creation_parent(path, None)
        }
        Err(_) => Err(OfflineError::Filesystem),
    }
}

fn validate_existing_file_path(path: &Path) -> Result<(), OfflineError> {
    if !safe_absolute_path(path) || path.file_name().is_none() {
        return Err(OfflineError::InvalidRequest);
    }
    validate_creation_parent(path, None)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| OfflineError::Filesystem)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(OfflineError::Filesystem);
    }
    Ok(())
}

fn require_absent(path: &Path) -> Result<(), OfflineError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(OfflineError::ExistingTarget),
        Err(_) => Err(OfflineError::Filesystem),
    }
}

fn inspect_precreated_directory(
    path: &Path,
    required_owner: Ownership,
) -> Result<Option<DirectoryIdentity>, OfflineError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(OfflineError::Filesystem),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(OfflineError::ExistingTarget);
    }
    let identity = private_directory_identity(path, DIRECTORY_MODE)?;
    if identity.owner != required_owner {
        return Err(OfflineError::Filesystem);
    }
    if directory_has_entry(path)? {
        return Err(OfflineError::ExistingTarget);
    }
    if directory_identity(path)? != identity {
        return Err(OfflineError::Filesystem);
    }
    Ok(Some(identity))
}

fn directory_has_entry(path: &Path) -> Result<bool, OfflineError> {
    fs::read_dir(path)
        .map_err(|_| OfflineError::Filesystem)?
        .next()
        .transpose()
        .map(|entry| entry.is_some())
        .map_err(|_| OfflineError::Filesystem)
}

fn verify_precreated_directory(
    path: &Path,
    expected: DirectoryIdentity,
) -> Result<(), OfflineError> {
    if private_directory_identity(path, DIRECTORY_MODE)? != expected || directory_has_entry(path)? {
        return Err(OfflineError::Filesystem);
    }
    Ok(())
}

fn prepare_directory_targets(
    request: &InitRequest,
    data_owner: Ownership,
) -> Result<Vec<DirectoryTarget>, OfflineError> {
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(INSTALL_DIRECTORY_NAMES.len())
        .map_err(|_| OfflineError::Filesystem)?;
    for name in INSTALL_DIRECTORY_NAMES {
        targets.push(DirectoryTarget {
            name,
            precreated: inspect_precreated_directory(&request.data_dir.join(name), data_owner)?,
        });
    }
    Ok(targets)
}

fn restore_precreated_directory(
    path: &Path,
    identity: DirectoryIdentity,
) -> Result<(), OfflineError> {
    create_private_directory(path)?;
    set_path_ownership(path, identity.owner)?;
    fs::set_permissions(path, fs::Permissions::from_mode(identity.mode))
        .map_err(|_| OfflineError::Filesystem)?;
    sync_directory(path)?;
    sync_parent(path)
}

fn restore_target_after_failure(
    path: &Path,
    expected: Option<DirectoryIdentity>,
    error: OfflineError,
) -> Result<(), OfflineError> {
    let Some(expected) = expected else {
        return Err(error);
    };
    restore_precreated_directory(path, expected)
        .map_err(|_| OfflineError::PartialInitialization)?;
    Err(error)
}

fn set_tree_ownership(root: &Path, owner: Ownership) -> Result<(), OfflineError> {
    let paths = collect_staged_tree_paths(root)?;
    for path in paths.iter().rev() {
        set_path_ownership(path, owner)?;
    }
    Ok(())
}

fn collect_staged_tree_paths(root: &Path) -> Result<Vec<PathBuf>, OfflineError> {
    let mut pending = Vec::new();
    let mut paths = Vec::new();
    pending
        .try_reserve_exact(MAX_STAGED_PATHS)
        .map_err(|_| OfflineError::Filesystem)?;
    paths
        .try_reserve_exact(MAX_STAGED_PATHS)
        .map_err(|_| OfflineError::Filesystem)?;
    pending.push(root.to_path_buf());
    while let Some(path) = pending.pop() {
        if paths.len() == MAX_STAGED_PATHS {
            return Err(OfflineError::Filesystem);
        }
        collect_staged_path(&path, &mut pending, paths.len())?;
        paths.push(path);
    }
    Ok(paths)
}

fn collect_staged_path(
    path: &Path,
    pending: &mut Vec<PathBuf>,
    observed: usize,
) -> Result<(), OfflineError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| OfflineError::Filesystem)?;
    if metadata.file_type().is_symlink()
        || !(metadata.file_type().is_dir() || metadata.file_type().is_file())
    {
        return Err(OfflineError::Filesystem);
    }
    if metadata.file_type().is_dir() {
        collect_directory_entries(path, pending, observed)?;
    }
    Ok(())
}

fn collect_directory_entries(
    path: &Path,
    pending: &mut Vec<PathBuf>,
    observed: usize,
) -> Result<(), OfflineError> {
    let remaining = MAX_STAGED_PATHS.saturating_sub(observed + pending.len());
    let entries = fs::read_dir(path).map_err(|_| OfflineError::Filesystem)?;
    for entry in entries.take(remaining.saturating_add(1)) {
        if pending.len() + observed == MAX_STAGED_PATHS {
            return Err(OfflineError::Filesystem);
        }
        pending.push(entry.map_err(|_| OfflineError::Filesystem)?.path());
    }
    Ok(())
}

fn set_path_ownership(path: &Path, owner: Ownership) -> Result<(), OfflineError> {
    let before = fs::symlink_metadata(path).map_err(|_| OfflineError::Filesystem)?;
    if before.file_type().is_symlink() {
        return Err(OfflineError::Filesystem);
    }
    if before.uid() != owner.uid || before.gid() != owner.gid {
        chown(path, Some(owner.uid), Some(owner.gid)).map_err(|_| OfflineError::Filesystem)?;
    }
    let after = fs::symlink_metadata(path).map_err(|_| OfflineError::Filesystem)?;
    if after.file_type().is_symlink() || after.uid() != owner.uid || after.gid() != owner.gid {
        return Err(OfflineError::Filesystem);
    }
    if after.file_type().is_dir() {
        sync_directory(path)
    } else if after.file_type().is_file() {
        sync_regular_file(path)
    } else {
        Err(OfflineError::Filesystem)
    }
}

fn sync_parent(path: &Path) -> Result<(), OfflineError> {
    let parent = path.parent().ok_or(OfflineError::InvalidRequest)?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<(), OfflineError> {
    let directory = open_physical_directory(path)?;
    fsync(&directory).map_err(|_| OfflineError::Filesystem)
}

fn sync_regular_file(path: &Path) -> Result<(), OfflineError> {
    let file = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| OfflineError::Filesystem)?;
    let status = fstat(&file).map_err(|_| OfflineError::Filesystem)?;
    if FileType::from_raw_mode(status.st_mode) != FileType::RegularFile {
        return Err(OfflineError::Filesystem);
    }
    fsync(&file).map_err(|_| OfflineError::Filesystem)
}

fn refuse_existing_targets(request: &InitRequest) -> Result<(), OfflineError> {
    require_absent(&request.config_path)?;
    require_absent(&request.operator_signing_key_file)?;
    let data_owner = match fs::symlink_metadata(&request.data_dir) {
        Ok(_) => private_directory_identity(&request.data_dir, DIRECTORY_MODE)?.owner,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(OfflineError::Filesystem),
    };
    for name in INSTALL_DIRECTORY_NAMES {
        inspect_precreated_directory(&request.data_dir.join(name), data_owner)?;
    }
    Ok(())
}

fn ensure_data_directory(path: &Path) -> Result<(), OfflineError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0 => Ok(()),
        Ok(_) => Err(OfflineError::Filesystem),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path)
        }
        Err(_) => Err(OfflineError::Filesystem),
    }
}

fn create_private_directory(path: &Path) -> Result<(), OfflineError> {
    fs::create_dir(path).map_err(|_| OfflineError::Filesystem)?;
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|_| OfflineError::Filesystem)
}

fn create_staging_directory(path: &Path) -> Result<(), OfflineError> {
    if let Err(error) = create_private_directory(path) {
        let _cleanup = fs::remove_dir(path);
        return Err(error);
    }
    Ok(())
}

fn staging_name() -> Result<String, OfflineError> {
    let mut random = [0_u8; 8];
    OsEntropy::fill(&mut random).map_err(|_| OfflineError::Cryptography)?;
    let mut name = String::from(".init-staging-");
    for byte in random {
        write!(name, "{byte:02x}").map_err(|_| OfflineError::Filesystem)?;
    }
    Ok(name)
}

fn random_32() -> Result<Zeroizing<[u8; 32]>, OfflineError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    OsEntropy::fill(bytes.as_mut()).map_err(|_| OfflineError::Cryptography)?;
    Ok(bytes)
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), OfflineError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(SECRET_MODE);
    let mut file = options.open(path).map_err(|_| OfflineError::Filesystem)?;
    file.write_all(bytes)
        .map_err(|_| OfflineError::Filesystem)?;
    file.sync_all().map_err(|_| OfflineError::Filesystem)
}

// agenc-review: focus owner=runtime reviewed=2026-08-29 reason=closed purpose-to-file list keeps every generated secret distinct and auditable
fn write_generated_secrets(root: &Path, keys: &GeneratedSecrets) -> Result<(), OfflineError> {
    for (name, bytes) in [
        ("storage-master.key", keys.storage_master.as_slice()),
        ("rollback-guard.key", keys.rollback_guard.as_slice()),
        ("login-index-g1.key", keys.login_index.as_slice()),
        ("federation-signing.key", keys.federation_signing.as_slice()),
        ("backup-signing.key", keys.backup_signing.as_slice()),
        ("audit-signing.key", keys.audit_signing.as_slice()),
    ] {
        write_secret(&root.join(name), bytes)?;
    }
    let Some(coordinator) = &keys.coordinator else {
        return Ok(());
    };
    for (name, bytes) in [
        (
            "account-service-hpke.key",
            coordinator.account_hpke.as_slice(),
        ),
        (
            "opaque-fake-credential.key",
            coordinator.opaque_fake_credential.as_slice(),
        ),
        ("sequencer.key", coordinator.sequencer.as_slice()),
    ] {
        write_secret(&root.join(name), bytes)?;
    }
    write_secret(
        &root.join("opaque-server-setup.key"),
        coordinator.opaque.expose_setup_for_persistence(),
    )
}

fn signing_public(secret: &[u8; 32]) -> [u8; 32] {
    *Ed25519SecretKey::from_bytes(*secret)
        .public_key()
        .as_bytes()
}

fn write_trust_manifests(root: &Path, keys: &GeneratedSecrets) -> Result<(), OfflineError> {
    let backup_public = signing_public(&keys.backup_signing);
    let backup_id =
        backup_signing_key_id(&backup_public).map_err(|_| OfflineError::Cryptography)?;
    let audit_public = signing_public(&keys.audit_signing);
    let audit_id = audit_signing_key_id(&audit_public).map_err(|_| OfflineError::Cryptography)?;
    let backup = trust_manifest("backup", backup_id, backup_public);
    let audit = trust_manifest("audit", audit_id, audit_public);
    write_secret(&root.join("backup-trust.toml"), backup.as_bytes())?;
    write_secret(&root.join("audit-trust.toml"), audit.as_bytes())
}

fn trust_manifest(kind: &str, id: StorageDigest, public_key: [u8; 32]) -> String {
    format!(
        "{kind}_trust_version = 1\n\n[[key]]\nkey_id = \"{}\"\ned25519_public_key = \"{}\"\nnot_before = 0\nnot_after = {}\n",
        encode_base64url_32(id.as_bytes()),
        encode_base64url_32(&public_key),
        i64::MAX,
    )
}

fn storage_limits() -> StorageEngineLimits {
    StorageEngineLimits {
        redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
        fixed_reserve_bytes: DEFAULT_RESERVE_BYTES,
        reserve_percent: DEFAULT_RESERVE_PERCENT,
        database_max_bytes: DEFAULT_DATABASE_BYTES,
        backup_max_bytes: DEFAULT_BACKUP_BYTES,
        integrity_checkpoint_manifests: DEFAULT_CHECKPOINT_MANIFESTS,
    }
}

fn initialize_database(
    state: &Path,
    identity: InitIdentity,
    keys: &GeneratedSecrets,
) -> Result<(), OfflineError> {
    let login = LoginIndexKey::from_bytes(*keys.login_index);
    let key_state = LoginIndexKeyState::stable(1, login.key_id(identity.network_id))?;
    let key_state_record = InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let mut initial_records = vec![key_state_record];
    if let Some(coordinator) = &keys.coordinator {
        let fake_record = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            LIVE_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            coordinator
                .opaque
                .expose_fake_record_for_persistence()
                .to_vec(),
        )?;
        initial_records.push(InitialStorageRecord::new(
            TableId::OpaqueRecord,
            StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
            1,
            fake_record.encode()?,
        )?);
    }
    let qualifications = embedded_storage_qualifications()?;
    let directory = StateDirectory::open(state, &qualifications)?;
    let outcome = initialize_storage(StorageInitializationConfig {
        state_directory: directory,
        header_tbs: DatabaseHeaderTbs::new(
            identity.network_id,
            identity.server_id,
            identity.server_incarnation,
            identity.database_id,
            1,
            SCHEMA_GENERATION,
            identity.recovery_epoch,
        )?,
        storage_master_key: StorageMasterKey::from_bytes(*keys.storage_master),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(*keys.rollback_guard),
        mode: StorageInitializationMode::Live,
        initial_records,
        account_service_response_count: 0,
        state_generation: 1,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: storage_limits(),
    })?;
    match outcome {
        StorageInitializationOutcome::Complete { .. } => Ok(()),
        StorageInitializationOutcome::Indeterminate => Err(OfflineError::Indeterminate),
    }
}

fn write_configuration(
    staging_file: &Path,
    request: &InitRequest,
    mode: &PreparedInitMode,
    identity: InitIdentity,
    secrets: &GeneratedSecrets,
) -> Result<(), OfflineError> {
    let account_service_hpke_public_key = match (
        mode.imported_hpke_public_key(),
        secrets.coordinator.as_ref(),
    ) {
        (Some(public), None) => public,
        (None, Some(coordinator)) => *AccountHpkePrivateKey::from_bytes(*coordinator.account_hpke)
            .map_err(|_| OfflineError::Cryptography)?
            .public_key()
            .map_err(|_| OfflineError::Cryptography)?
            .as_bytes(),
        _ => return Err(OfflineError::InvalidRequest),
    };
    let tls_dir = request
        .config_path
        .parent()
        .ok_or(OfflineError::InvalidRequest)?
        .join("tls");
    let values = InitValues {
        profile: request.profile,
        network_id: identity.network_id,
        server_id: identity.server_id,
        role: mode.role(),
        coordinator_server_id: mode.coordinator_server_id(identity.server_id),
        server_name: request.server_name.clone(),
        display_name: request.display_name.clone(),
        data_dir: request.data_dir.clone(),
        runtime_dir: request.runtime_dir.clone(),
        tls_dir,
        dns_name: request.dns_name.clone(),
        account_service_hpke_public_key,
        operator: OperatorTemplate {
            operator_id: identity.operator_id,
            signing_public_key: signing_public(&secrets.operator_signing),
        },
    };
    let document = render_template(&values)?;
    write_secret(staging_file, document.as_bytes())
}

fn init_receipt(request: &InitRequest, identity: InitIdentity) -> InitReceipt {
    let onion_socket = request.runtime_dir.join("onion.sock");
    InitReceipt {
        network_id: identity.network_id,
        server_id: identity.server_id,
        operator_id: identity.operator_id,
        operator_signing_key_file: request.operator_signing_key_file.clone(),
        tor_snippet: format!(
            "HiddenServiceDir /var/lib/tor/agenc-ircd\nHiddenServiceVersion 3\nHiddenServicePort 6697 unix:{}\n",
            onion_socket.display(),
        ),
        systemd_snippet: "Use the packaged agenc-ircd.service and one reviewed address-family profile; socket activation is not supported.\n".to_owned(),
        certificate_instructions: "Enroll TLS certificates for every configured public or onion listener, place them under the configured tls directory, then enable the reviewed listeners.\n".to_owned(),
    }
}

/// Inspects the configured database without taking writer authority and
/// returns only authenticated facts.
pub fn verify_database_header(
    config: &Config,
    secrets: &SecretSet,
) -> Result<HeaderFacts, OfflineError> {
    validate_account_hpke_pin(config, secrets)?;
    let qualifications = embedded_storage_qualifications()?;
    let state_directory =
        InspectionStateDirectory::open(&config.storage.state_dir, &qualifications)?;
    let recovered = inspect_storage(StorageInspectionConfig {
        expected_network_id: config.network.network_id,
        expected_server_id: config.server.server_id,
        state_directory,
        storage_master_key: StorageMasterKey::from_bytes(*secrets.storage_master().expose()),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(
            *secrets.rollback_guard_root().expose(),
        ),
        login_index_key: LoginIndexKey::from_bytes(*secrets.login_index().expose()),
        previous_login_index_key: secrets
            .login_index_previous()
            .map(|key| LoginIndexKey::from_bytes(*key.expose())),
        limits: limits_from_config(config),
    })?;
    Ok(HeaderFacts {
        recovery_epoch: recovered.recovery_epoch(),
        state_generation: recovered.state_generation(),
        account_service_response_count: recovered.account_service_response_count(),
    })
}

fn limits_from_config(config: &Config) -> StorageEngineLimits {
    StorageEngineLimits {
        redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
        fixed_reserve_bytes: config.storage.disk_reserve_bytes,
        reserve_percent: config.storage.disk_reserve_percent,
        database_max_bytes: config.storage.database_max_bytes,
        backup_max_bytes: config.storage.backup_max_bytes,
        integrity_checkpoint_manifests: config.storage.integrity_checkpoint_manifests,
    }
}

fn validate_account_hpke_pin(config: &Config, secrets: &SecretSet) -> Result<(), OfflineError> {
    let configured_public =
        AccountHpkePublicKey::from_bytes(config.accounts.account_service_hpke_public_key)
            .map_err(|_| OfflineError::Cryptography)?;
    let Some(private) = secrets.account_service_hpke_private() else {
        return Ok(());
    };
    let private = AccountHpkePrivateKey::from_bytes(*private.expose())
        .map_err(|_| OfflineError::Cryptography)?;
    let public = private
        .public_key()
        .map_err(|_| OfflineError::Cryptography)?;
    if public.as_bytes() != configured_public.as_bytes() {
        return Err(OfflineError::Configuration);
    }
    Ok(())
}

/// Renders the canonical stopped-node onboarding descriptor.
pub fn render_onboarding(config_path: &Path) -> Result<String, OfflineError> {
    let config = load_config(config_path, ValidationDepth::Document)?;
    let secrets = SecretSet::load(&config)?;
    let header = verify_database_header(&config, &secrets)?;
    let hpke = AccountHpkePublicKey::from_bytes(config.accounts.account_service_hpke_public_key)
        .map_err(|_| OfflineError::Cryptography)?;
    let empty_key_set = semantic_digest(SemanticHashDomain::SequencerKeySet, &[])
        .map_err(|_| OfflineError::Cryptography)?;
    let facts = OnboardingFacts {
        recovery_epoch: header.recovery_epoch,
        account_service_hpke_key_id: *hpke.key_id().as_bytes(),
        sequencer_key_set_generation: 0,
        sequencer_key_set_hash: *empty_key_set.as_bytes(),
    };
    Ok(render_config_onboarding(&config, &facts)?)
}

/// Issues one canonical three-line account-creation invitation envelope.
pub fn create_account_invite(
    descriptor_path: &Path,
    signing_key_file: &Path,
    expires_in_seconds: u64,
) -> Result<String, OfflineError> {
    if !(1..=MAX_INVITE_LIFETIME_SECONDS).contains(&expires_in_seconds) {
        return Err(OfflineError::InvalidRequest);
    }
    let descriptor = read_descriptor(descriptor_path)?;
    let network_id = descriptor.descriptor.network_id;
    let (secret, _) = open_secret_file(signing_key_file, SecretLength::Exact(32))?;
    let key_bytes: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| OfflineError::Configuration)?;
    let now = current_utc_second()?;
    let expires = now
        .get()
        .checked_add(expires_in_seconds)
        .map(UtcSecond::from_unix_seconds)
        .ok_or(OfflineError::InvalidRequest)?;
    let mut entropy = OsEntropy;
    let invite_id = InviteId::generate(&mut entropy).map_err(|_| OfflineError::Cryptography)?;
    let invite = AccountCreationInvite::issue(
        network_id,
        invite_id,
        now,
        expires,
        &Ed25519SecretKey::from_bytes(key_bytes),
    )
    .map_err(|_| OfflineError::Authentication)?;
    Ok(format!(
        "AGENC-CHAT-ACCOUNT-INVITE/1\nconnect-descriptor={}\naccount-invite={}\n",
        encode_base64url(descriptor.text.as_bytes()),
        encode_base64url(invite.expose_for_account_request()),
    ))
}

struct LoadedDescriptor {
    text: String,
    descriptor: OnboardingDescriptor,
}

fn read_descriptor(path: &Path) -> Result<LoadedDescriptor, OfflineError> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| OfflineError::Filesystem)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(MAX_ONBOARDING_DESCRIPTOR_BYTES + 1)
        .map_err(|_| OfflineError::Filesystem)?;
    file.take((MAX_ONBOARDING_DESCRIPTOR_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| OfflineError::Filesystem)?;
    if bytes.is_empty() || bytes.len() > MAX_ONBOARDING_DESCRIPTOR_BYTES {
        return Err(OfflineError::InvalidRequest);
    }
    let text = String::from_utf8(bytes).map_err(|_| OfflineError::InvalidRequest)?;
    let descriptor =
        parse_onboarding_descriptor(&text).map_err(|_| OfflineError::InvalidRequest)?;
    validate_descriptor_hpke_pin(&descriptor)?;
    Ok(LoadedDescriptor { text, descriptor })
}

fn validate_descriptor_hpke_pin(descriptor: &OnboardingDescriptor) -> Result<(), OfflineError> {
    let public = AccountHpkePublicKey::from_bytes(descriptor.account_service_hpke_public_key)
        .map_err(|_| OfflineError::InvalidRequest)?;
    if public.key_id().as_bytes() != &descriptor.account_service_hpke_key_id {
        return Err(OfflineError::InvalidRequest);
    }
    Ok(())
}

fn current_utc_second() -> Result<UtcSecond, OfflineError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OfflineError::InvalidRequest)?
        .as_secs();
    Ok(UtcSecond::from_unix_seconds(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_ircd_storage::ReadPlan;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Result<Self, OfflineError> {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(
                "offline-runtime-test-{}-{sequence}-{}",
                std::process::id(),
                unique_suffix()?
            );
            // A candidate base can pass every ancestor and storage check and
            // still refuse the mkdir, for example a root-owned `~/.cache` on a
            // hosted runner, so the first base that accepts the directory wins.
            for base in protected_test_bases() {
                if qualified_test_base(&base).is_err() {
                    continue;
                }
                let root = base.join(&name);
                if fs::create_dir(&root).is_ok() {
                    return Self::finish(root);
                }
            }
            Err(OfflineError::Filesystem)
        }

        fn finish(root: PathBuf) -> Result<Self, OfflineError> {
            fs::set_permissions(&root, fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|_| OfflineError::Filesystem)?;
            let directory = Self(root);
            create_private_directory(&directory.0.join("etc"))?;
            create_private_directory(&directory.0.join("run"))?;
            Ok(directory)
        }
    }

    /// Candidate scratch bases in preference order; the home directory itself
    /// is the last resort because the daemon integration fixture already
    /// qualifies it on every supported host.
    fn protected_test_bases() -> Vec<PathBuf> {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        [
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            std::env::var_os("CARGO_TARGET_TMPDIR").map(PathBuf::from),
            home.as_ref().map(|home| home.join(".cache")),
            home,
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    fn qualified_test_base(base: &Path) -> Result<(), OfflineError> {
        fs::create_dir_all(base).map_err(|_| OfflineError::Filesystem)?;
        test_ancestors_are_protected(base)?;
        test_base_is_storage_qualified(base)
    }

    fn unique_suffix() -> Result<String, OfflineError> {
        let bytes = random_32()?;
        let mut suffix = String::new();
        for byte in bytes.iter().take(8) {
            write!(suffix, "{byte:02x}").map_err(|_| OfflineError::Filesystem)?;
        }
        Ok(suffix)
    }

    fn test_base_is_storage_qualified(path: &Path) -> Result<(), OfflineError> {
        let observed = StateDirectory::probe(path)?;
        let accepted = embedded_storage_qualifications()?
            .into_iter()
            .any(|qualification| {
                qualification
                    .validate()
                    .is_ok_and(|_| qualification.tuple() == observed)
            });
        if accepted {
            Ok(())
        } else {
            Err(OfflineError::Storage)
        }
    }

    fn test_ancestors_are_protected(path: &Path) -> Result<(), OfflineError> {
        let effective_uid = geteuid().as_raw();
        for ancestor in path.ancestors() {
            let identity = directory_identity(ancestor)?;
            if identity.mode & 0o022 != 0
                || !(identity.owner.uid == 0 || identity.owner.uid == effective_uid)
            {
                return Err(OfflineError::Filesystem);
            }
        }
        Ok(())
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    fn test_request(root: &Path) -> Result<InitRequest, OfflineError> {
        let operator_dir = root.join("operator");
        ensure_data_directory(&operator_dir)?;
        fs::set_permissions(root.join("run"), fs::Permissions::from_mode(0o750))
            .map_err(|_| OfflineError::Filesystem)?;
        Ok(InitRequest {
            config_path: root.join("etc/config.toml"),
            profile: InitProfile::Public,
            mode: InitMode::Coordinator {
                network_id: Some(NetworkId::from_bytes([1; 32])),
            },
            data_dir: root.join("data"),
            runtime_dir: root.join("run"),
            operator_signing_key_file: operator_dir.join("operator-signing.key"),
            server_name: DnsName::parse("chat.example")?,
            display_name: DisplayLabel::parse("Example")?,
            dns_name: Some(DnsName::parse("chat.example")?),
        })
    }

    fn precreate_data_layout(request: &InitRequest) -> Result<(), OfflineError> {
        ensure_data_directory(&request.data_dir)?;
        for name in INSTALL_DIRECTORY_NAMES {
            create_private_directory(&request.data_dir.join(name))?;
        }
        Ok(())
    }

    fn valid_descriptor() -> Result<String, OfflineError> {
        let private =
            AccountHpkePrivateKey::from_bytes([12; 32]).map_err(|_| OfflineError::Cryptography)?;
        let public = private
            .public_key()
            .map_err(|_| OfflineError::Cryptography)?;
        Ok(format!(
            "AGENC-CHAT-CONNECT/1\nnetwork-id={}\nserver-name=chat.example\ndns-endpoint=chat.example:6697\nrecovery-epoch={}\nbase-profile-sha256={}\naccount-service-hpke-key-id={}\naccount-service-hpke-public-key={}\ne2ee-profile={}\ne2ee-profile-sha256={}\nsequencer-key-set-generation=0\nsequencer-key-set-hash={}\n",
            NetworkId::from_bytes([1; 32]).to_base64url(),
            RecoveryEpoch::from_bytes([2; 16]).to_base64url(),
            agenc_ircd_config::BASE_PROFILE_SHA256_TOKEN,
            encode_base64url_32(public.key_id().as_bytes()),
            encode_base64url_32(public.as_bytes()),
            agenc_ircd_config::E2EE_PROFILE_TOKEN,
            agenc_ircd_config::E2EE_PROFILE_SHA256_TOKEN,
            encode_base64url_32(&[3; 32]),
        ))
    }

    fn enable_test_listener(root: &Path) -> Result<(), OfflineError> {
        let config_path = root.join("etc/config.toml");
        let text = fs::read_to_string(&config_path).map_err(|_| OfflineError::Filesystem)?;
        let enabled = text.replacen(
            "enabled = false\npurpose = \"client_tls\"",
            "enabled = true\npurpose = \"client_tls\"",
            1,
        );
        fs::write(&config_path, enabled).map_err(|_| OfflineError::Filesystem)?;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(SECRET_MODE))
            .map_err(|_| OfflineError::Filesystem)?;
        let tls = root.join("etc/tls");
        create_private_directory(&tls)?;
        write_secret(&tls.join("server.key"), &[42; 64])
    }

    #[test]
    fn descriptor_shape_and_invite_lifetime_bounds_are_closed() -> Result<(), OfflineError> {
        let descriptor = valid_descriptor()?;
        let parsed = parse_onboarding_descriptor(&descriptor)?;
        assert_eq!(parsed.network_id, NetworkId::from_bytes([1; 32]));
        assert_eq!(
            create_account_invite(Path::new("/missing"), Path::new("/missing"), 0),
            Err(OfflineError::InvalidRequest)
        );
        assert_eq!(
            create_account_invite(
                Path::new("/missing"),
                Path::new("/missing"),
                MAX_INVITE_LIFETIME_SECONDS + 1,
            ),
            Err(OfflineError::InvalidRequest)
        );
        assert_eq!(
            parse_onboarding_descriptor(descriptor.trim_end()),
            Err(ConfigError::InvalidDocument)
        );
        Ok(())
    }

    #[test]
    fn init_request_and_private_directory_validation_reject_every_path_class()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;

        let mut request = test_request(&root.0)?;
        request.config_path = PathBuf::from("config.toml");
        assert_eq!(
            validate_init_request(&request),
            Err(OfflineError::InvalidRequest)
        );
        let mut request = test_request(&root.0)?;
        request.data_dir = PathBuf::from("data");
        assert_eq!(
            validate_init_request(&request),
            Err(OfflineError::InvalidRequest)
        );
        let mut request = test_request(&root.0)?;
        request.runtime_dir = PathBuf::from("run");
        assert_eq!(
            validate_init_request(&request),
            Err(OfflineError::InvalidRequest)
        );
        let mut request = test_request(&root.0)?;
        request.config_path = request.data_dir.clone();
        assert_eq!(
            validate_init_request(&request),
            Err(OfflineError::InvalidRequest)
        );
        for profile in [InitProfile::Public, InitProfile::Dual] {
            let mut request = test_request(&root.0)?;
            request.profile = profile;
            request.dns_name = None;
            assert_eq!(
                validate_init_request(&request),
                Err(OfflineError::InvalidRequest)
            );
        }
        let mut onion = test_request(&root.0)?;
        onion.profile = InitProfile::Onion;
        onion.dns_name = None;
        assert_eq!(validate_init_request(&onion), Ok(()));

        let fresh = root.0.join("fresh-private");
        ensure_data_directory(&fresh)?;
        assert_eq!(ensure_data_directory(&fresh), Ok(()));
        let broad = root.0.join("broad");
        create_private_directory(&broad)?;
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o755))
            .map_err(|_| OfflineError::Filesystem)?;
        assert_eq!(ensure_data_directory(&broad), Err(OfflineError::Filesystem));
        let file = root.0.join("not-a-directory");
        write_secret(&file, b"file")?;
        assert_eq!(ensure_data_directory(&file), Err(OfflineError::Filesystem));
        assert_eq!(
            ensure_data_directory(&file.join("child")),
            Err(OfflineError::Filesystem)
        );
        Ok(())
    }

    #[test]
    fn root_init_requires_precreated_data_while_non_root_may_create_private_data()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let data_dir = root.0.join("missing-data");

        assert_eq!(
            validate_data_path_for_privilege(&data_dir, true),
            Err(OfflineError::Filesystem)
        );
        assert!(!data_dir.exists());
        assert_eq!(validate_data_path_for_privilege(&data_dir, false), Ok(()));
        assert!(!data_dir.exists());
        Ok(())
    }

    #[test]
    fn descriptor_reader_rejects_size_encoding_shape_and_duplicate_fields()
    -> Result<(), OfflineError> {
        let valid = valid_descriptor()?;
        assert!(parse_onboarding_descriptor(&valid).is_ok());
        for invalid in [
            valid.replace('\n', "\r\n"),
            valid.replacen("AGENC-CHAT-CONNECT/1", "WRONG/1", 1),
            "AGENC-CHAT-CONNECT/1\nnetwork-id=x\n".to_owned(),
            format!("{valid}extra-1=x\nextra-2=x\nextra-3=x\nextra-4=x\n"),
            valid.replacen("server-name=chat.example\n", "optional=x\n", 1),
            format!("{valid}network-id=duplicate\n"),
        ] {
            assert!(parse_onboarding_descriptor(&invalid).is_err());
        }

        let root = TestDirectory::create()?;
        assert!(matches!(
            read_descriptor(&root.0.join("missing")),
            Err(OfflineError::Filesystem)
        ));
        for (name, bytes, expected) in [
            ("empty", Vec::new(), OfflineError::InvalidRequest),
            (
                "oversized",
                vec![b'x'; MAX_ONBOARDING_DESCRIPTOR_BYTES + 1],
                OfflineError::InvalidRequest,
            ),
            (
                "invalid-utf8",
                vec![0xff, 0xfe, 0xfd],
                OfflineError::InvalidRequest,
            ),
            (
                "invalid-shape",
                b"AGENC-CHAT-CONNECT/1".to_vec(),
                OfflineError::InvalidRequest,
            ),
        ] {
            let path = root.0.join(name);
            write_secret(&path, &bytes)?;
            assert_eq!(read_descriptor(&path).err(), Some(expected), "{name}");
        }
        let valid_path = root.0.join("valid");
        write_secret(&valid_path, valid.as_bytes())?;
        assert_eq!(read_descriptor(&valid_path)?.text, valid);
        let declared_key_id = valid
            .lines()
            .find(|line| line.starts_with("account-service-hpke-key-id="))
            .ok_or(OfflineError::InvalidRequest)?;
        let forged = valid.replacen(
            declared_key_id,
            &format!(
                "account-service-hpke-key-id={}",
                encode_base64url_32(&[0; 32])
            ),
            1,
        );
        let forged_path = root.0.join("forged");
        write_secret(&forged_path, forged.as_bytes())?;
        assert!(matches!(
            read_descriptor(&forged_path),
            Err(OfflineError::InvalidRequest)
        ));
        assert_eq!(
            create_account_invite(&forged_path, Path::new("/missing"), 60),
            Err(OfflineError::InvalidRequest)
        );
        assert_eq!(
            parse_network_id("invalid"),
            Err(OfflineError::InvalidRequest)
        );
        assert_eq!(
            parse_network_id("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
            Ok(NetworkId::from_bytes([1; 32]))
        );
        assert_eq!(
            parse_server_id("invalid"),
            Err(OfflineError::InvalidRequest)
        );
        Ok(())
    }

    #[test]
    fn staging_rename_distinguishes_preinstall_and_partial_failures() -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let staging_root = root.0.join("rename-staging");
        create_private_directory(&staging_root)?;
        let mut staging = Staging {
            data_root: staging_root,
            config_file: root.0.join("config-staging"),
            operator_signing_key_file: root.0.join("operator-staging"),
            directory_targets: Vec::new(),
            data_owner: directory_identity(&root.0)?.owner,
            config_owner: directory_identity(&root.0)?.owner,
            operator_owner: directory_identity(&root.0)?.owner,
            installed: false,
        };
        assert_eq!(
            staging.rename(root.0.join("missing"), root.0.join("target")),
            Err(OfflineError::Filesystem)
        );
        staging.installed = true;
        assert_eq!(
            staging.rename(root.0.join("missing"), root.0.join("target")),
            Err(OfflineError::PartialInitialization)
        );
        Ok(())
    }

    #[test]
    fn staging_install_never_replaces_a_target_created_after_preflight() -> Result<(), OfflineError>
    {
        let root = TestDirectory::create()?;
        let request = test_request(&root.0)?;
        validate_init_request(&request)?;
        refuse_existing_targets(&request)?;
        let mut staging = Staging::create(&request)?;
        let late_target = request.data_dir.join("keys");
        create_private_directory(&late_target)?;
        write_secret(&late_target.join("sentinel"), b"preserve")?;

        assert_eq!(staging.install(&request), Err(OfflineError::Filesystem));
        assert_eq!(
            fs::read(late_target.join("sentinel")).map_err(|_| OfflineError::Filesystem)?,
            b"preserve"
        );
        assert!(!request.data_dir.join("trust").exists());
        assert!(!request.config_path.exists());
        Ok(())
    }

    #[test]
    fn init_rejects_overlapping_and_noncanonical_target_paths() -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;

        let mut runtime_is_data = test_request(&root.0)?;
        runtime_is_data.runtime_dir = runtime_is_data.data_dir.clone();
        assert_eq!(
            validate_init_request(&runtime_is_data),
            Err(OfflineError::InvalidRequest)
        );

        let mut runtime_is_state = test_request(&root.0)?;
        runtime_is_state.runtime_dir = runtime_is_state.data_dir.join("state");
        assert_eq!(
            validate_init_request(&runtime_is_state),
            Err(OfflineError::InvalidRequest)
        );

        let mut config_is_keys = test_request(&root.0)?;
        config_is_keys.config_path = config_is_keys.data_dir.join("keys");
        assert_eq!(
            validate_init_request(&config_is_keys),
            Err(OfflineError::InvalidRequest)
        );

        let mut config_is_runtime = test_request(&root.0)?;
        config_is_runtime.config_path = config_is_runtime.runtime_dir.join("config.toml");
        assert_eq!(
            validate_init_request(&config_is_runtime),
            Err(OfflineError::InvalidRequest)
        );

        let mut parent_component = test_request(&root.0)?;
        parent_component.config_path = root.0.join("etc/../config.toml");
        assert_eq!(
            validate_init_request(&parent_component),
            Err(OfflineError::InvalidRequest)
        );
        Ok(())
    }

    #[test]
    fn every_error_has_a_fixed_secret_free_message() {
        for (error, message) in [
            (OfflineError::InvalidRequest, "offline request rejected"),
            (
                OfflineError::ExistingTarget,
                "initialization target already exists",
            ),
            (
                OfflineError::Filesystem,
                "protected filesystem operation failed",
            ),
            (
                OfflineError::Configuration,
                "configuration validation failed",
            ),
            (OfflineError::Cryptography, "cryptographic setup failed"),
            (OfflineError::Authentication, "account setup failed"),
            (
                OfflineError::Storage,
                "authenticated storage operation failed",
            ),
            (
                OfflineError::Indeterminate,
                "storage initialization outcome is indeterminate",
            ),
            (
                OfflineError::PartialInitialization,
                "initialization is partially installed",
            ),
        ] {
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn clean_init_reopens_for_onboarding_and_repeated_init_is_refused() -> Result<(), OfflineError>
    {
        let root = TestDirectory::create()?;
        let request = test_request(&root.0)?;
        let config_path = request.config_path.clone();
        let data_dir = request.data_dir.clone();
        let receipt = initialize_node(request)?;
        assert_eq!(receipt.network_id, NetworkId::from_bytes([1; 32]));
        assert_eq!(
            fs::symlink_metadata(&config_path)
                .map_err(|_| OfflineError::Filesystem)?
                .permissions()
                .mode()
                & 0o777,
            CONFIG_MODE
        );
        for name in ["keys", "trust", "state", "backups"] {
            assert_eq!(
                fs::symlink_metadata(data_dir.join(name))
                    .map_err(|_| OfflineError::Filesystem)?
                    .permissions()
                    .mode()
                    & 0o777,
                DIRECTORY_MODE
            );
        }
        enable_test_listener(&root.0)?;
        let config = load_config(&config_path, ValidationDepth::Document)?;
        assert_eq!(
            agenc_ircd_config::load_backup_trust_manifest(
                &config.storage.backup_trust_manifest_file,
            )?
            .len(),
            1,
        );
        assert_eq!(
            agenc_ircd_config::load_audit_trust_manifest(
                &config.moderation.audit_trust_manifest_file,
            )?
            .len(),
            1,
        );
        let secrets = SecretSet::load(&config)?;
        let qualifications = embedded_storage_qualifications()?;
        let state_directory = StateDirectory::open(&config.storage.state_dir, &qualifications)?;
        let owner = StorageOwner::start(StorageOpenConfig {
            expected_network_id: config.network.network_id,
            expected_server_id: config.server.server_id,
            state_directory,
            storage_master_key: StorageMasterKey::from_bytes(*secrets.storage_master().expose()),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(
                *secrets.rollback_guard_root().expose(),
            ),
            login_index_key: LoginIndexKey::from_bytes(*secrets.login_index().expose()),
            previous_login_index_key: None,
            limits: limits_from_config(&config),
        })?;
        assert_eq!(
            owner
                .recovered_state()
                .table_record_count(TableId::OpaqueRecord),
            1
        );
        let fake_key = StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?;
        let fake_rows = owner
            .port()
            .try_read(ReadPlan::exact(TableId::OpaqueRecord, fake_key.clone()))?
            .wait()?;
        let fake_row_keys: Vec<(TableId, StoredKey)> = fake_rows
            .records
            .iter()
            .map(|record| (record.table, record.key.clone()))
            .collect();
        assert!(fake_row_keys == vec![(TableId::OpaqueRecord, fake_key)]);
        owner.shutdown()?;
        let descriptor = render_onboarding(&config_path)?;
        assert!(descriptor.starts_with("AGENC-CHAT-CONNECT/1\n"));
        assert!(descriptor.contains("recovery-epoch="));
        assert!(descriptor.ends_with('\n'));
        let descriptor_path = root.0.join("connect.txt");
        write_secret(&descriptor_path, descriptor.as_bytes())?;
        let invite =
            create_account_invite(&descriptor_path, &receipt.operator_signing_key_file, 3_600)?;
        let invite_lines: Vec<&str> = invite.lines().collect();
        assert_eq!(invite_lines.len(), 3);
        assert_eq!(
            invite_lines.first().copied(),
            Some("AGENC-CHAT-ACCOUNT-INVITE/1")
        );
        assert!(
            invite_lines
                .get(1)
                .is_some_and(|line| line.starts_with("connect-descriptor="))
        );
        assert!(
            invite_lines
                .get(2)
                .is_some_and(|line| line.starts_with("account-invite="))
        );
        assert!(matches!(
            initialize_node(test_request(&root.0)?),
            Err(OfflineError::ExistingTarget)
        ));
        Ok(())
    }

    #[test]
    fn init_adopts_only_the_empty_precreated_layout_and_separates_operator_authority()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let request = test_request(&root.0)?;
        precreate_data_layout(&request)?;
        let operator_key = request.operator_signing_key_file.clone();
        let data_dir = request.data_dir.clone();

        let receipt = initialize_node(request)?;

        assert_eq!(receipt.operator_signing_key_file, operator_key);
        assert!(operator_key.is_file());
        assert!(!data_dir.join("keys/operator-signing.key").exists());
        assert_eq!(
            fs::symlink_metadata(&operator_key)
                .map_err(|_| OfflineError::Filesystem)?
                .permissions()
                .mode()
                & 0o777,
            SECRET_MODE
        );
        for name in INSTALL_DIRECTORY_NAMES {
            assert!(data_dir.join(name).is_dir());
        }
        assert!(!directory_has_entry(&data_dir.join("backups"))?);
        Ok(())
    }

    #[test]
    fn init_rejects_nonempty_and_symlinked_precreated_targets_without_output()
    -> Result<(), OfflineError> {
        let nonempty_root = TestDirectory::create()?;
        let nonempty = test_request(&nonempty_root.0)?;
        ensure_data_directory(&nonempty.data_dir)?;
        create_private_directory(&nonempty.data_dir.join("keys"))?;
        write_secret(&nonempty.data_dir.join("keys/sentinel"), b"existing")?;
        let config_path = nonempty.config_path.clone();
        let operator_key = nonempty.operator_signing_key_file.clone();
        assert!(matches!(
            initialize_node(nonempty),
            Err(OfflineError::ExistingTarget)
        ));
        assert!(!config_path.exists());
        assert!(!operator_key.exists());

        let symlink_root = TestDirectory::create()?;
        let symlinked = test_request(&symlink_root.0)?;
        ensure_data_directory(&symlinked.data_dir)?;
        let displaced = symlink_root.0.join("displaced-keys");
        create_private_directory(&displaced)?;
        std::os::unix::fs::symlink(&displaced, symlinked.data_dir.join("keys"))
            .map_err(|_| OfflineError::Filesystem)?;
        let config_path = symlinked.config_path.clone();
        let operator_key = symlinked.operator_signing_key_file.clone();
        assert!(matches!(
            initialize_node(symlinked),
            Err(OfflineError::ExistingTarget)
        ));
        assert!(!config_path.exists());
        assert!(!operator_key.exists());
        Ok(())
    }

    #[test]
    fn init_rejects_symlinked_ancestors_and_operator_paths_inside_daemon_roots()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let physical = root.0.join("physical");
        create_private_directory(&physical)?;
        let alias = root.0.join("alias");
        std::os::unix::fs::symlink(&physical, &alias).map_err(|_| OfflineError::Filesystem)?;
        let mut symlinked = test_request(&root.0)?;
        symlinked.data_dir = alias.join("data");
        assert_eq!(
            validate_init_request(&symlinked),
            Err(OfflineError::Filesystem)
        );

        let mut exposed = test_request(&root.0)?;
        exposed.operator_signing_key_file = exposed.data_dir.join("operator-signing.key");
        assert_eq!(
            validate_init_request(&exposed),
            Err(OfflineError::InvalidRequest)
        );
        Ok(())
    }

    #[test]
    fn init_receipt_uses_the_configured_runtime_socket() -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let request = test_request(&root.0)?;
        let receipt = init_receipt(
            &request,
            InitIdentity {
                network_id: NetworkId::from_bytes([1; 32]),
                server_id: ServerId::from_bytes([2; 16]),
                server_incarnation: ServerIncarnation::from_bytes([3; 16]),
                database_id: DatabaseId::from_bytes([4; 16]),
                recovery_epoch: RecoveryEpoch::from_bytes([5; 16]),
                operator_id: OperatorId::from_bytes([6; 16]),
            },
        );
        assert!(receipt.tor_snippet.contains(&format!(
            "HiddenServicePort 6697 unix:{}\n",
            request.runtime_dir.join("onion.sock").display(),
        )));
        assert!(!receipt.tor_snippet.contains("/run/agenc-ircd/onion.sock"));
        Ok(())
    }

    #[test]
    fn edge_init_imports_public_pins_without_creating_coordinator_secrets()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let descriptor = valid_descriptor()?;
        let parsed = parse_onboarding_descriptor(&descriptor)?;
        let descriptor_path = root.0.join("trusted-connect.txt");
        write_secret(&descriptor_path, descriptor.as_bytes())?;
        let coordinator_server_id = ServerId::from_bytes([8; 16]);
        let mut request = test_request(&root.0)?;
        request.mode = InitMode::Edge {
            coordinator_descriptor: descriptor_path,
            coordinator_server_id,
        };
        let config_path = request.config_path.clone();
        let data_dir = request.data_dir.clone();
        let receipt = initialize_node(request)?;
        assert_eq!(receipt.network_id, parsed.network_id);
        assert_ne!(receipt.server_id, coordinator_server_id);

        enable_test_listener(&root.0)?;
        let config = load_config(&config_path, ValidationDepth::Document)?;
        assert_eq!(config.network.role, NodeRole::Edge);
        assert_eq!(config.network.coordinator_server_id, coordinator_server_id);
        assert_eq!(
            config.accounts.account_service_hpke_public_key,
            parsed.account_service_hpke_public_key
        );
        let secrets = SecretSet::load(&config)?;
        assert!(secrets.account_service_hpke_private().is_none());
        assert!(secrets.opaque_server_setup().is_none());
        assert!(secrets.opaque_fake_credential().is_none());
        assert!(secrets.sequencer_private().is_none());
        for absent in [
            "account-service-hpke.key",
            "opaque-server-setup.key",
            "opaque-fake-credential.key",
            "sequencer.key",
        ] {
            assert_eq!(
                fs::symlink_metadata(data_dir.join("keys").join(absent))
                    .err()
                    .map(|error| error.kind()),
                Some(std::io::ErrorKind::NotFound),
                "{absent}"
            );
        }

        let qualifications = embedded_storage_qualifications()?;
        let state_directory = StateDirectory::open(&config.storage.state_dir, &qualifications)?;
        let owner = StorageOwner::start(StorageOpenConfig {
            expected_network_id: config.network.network_id,
            expected_server_id: config.server.server_id,
            state_directory,
            storage_master_key: StorageMasterKey::from_bytes(*secrets.storage_master().expose()),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(
                *secrets.rollback_guard_root().expose(),
            ),
            login_index_key: LoginIndexKey::from_bytes(*secrets.login_index().expose()),
            previous_login_index_key: None,
            limits: limits_from_config(&config),
        })?;
        assert_eq!(
            owner
                .recovered_state()
                .table_record_count(TableId::OpaqueRecord),
            0
        );
        assert_eq!(owner.recovered_state().account_service_response_count(), 0);
        assert_ne!(
            owner.recovered_state().recovery_epoch(),
            parsed.recovery_epoch
        );
        owner.shutdown()?;
        Ok(())
    }

    #[test]
    fn edge_onboarding_uses_read_only_reconstruction_without_fake_opaque_state()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let trusted = valid_descriptor()?;
        let parsed = parse_onboarding_descriptor(&trusted)?;
        let descriptor_path = root.0.join("trusted-edge-connect.txt");
        write_secret(&descriptor_path, trusted.as_bytes())?;
        let mut request = test_request(&root.0)?;
        request.mode = InitMode::Edge {
            coordinator_descriptor: descriptor_path,
            coordinator_server_id: ServerId::from_bytes([8; 16]),
        };
        let config_path = request.config_path.clone();
        initialize_node(request)?;
        enable_test_listener(&root.0)?;

        let rendered = render_onboarding(&config_path)?;
        let rendered = parse_onboarding_descriptor(&rendered)?;
        assert_eq!(rendered.network_id, parsed.network_id);
        assert_eq!(
            rendered.account_service_hpke_public_key,
            parsed.account_service_hpke_public_key
        );
        assert_ne!(rendered.recovery_epoch, parsed.recovery_epoch);
        Ok(())
    }

    #[test]
    fn edge_init_rejects_a_forged_hpke_id_before_creating_targets() -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let descriptor = valid_descriptor()?;
        let declared_key_id = descriptor
            .lines()
            .find(|line| line.starts_with("account-service-hpke-key-id="))
            .ok_or(OfflineError::InvalidRequest)?;
        let forged = descriptor.replacen(
            declared_key_id,
            &format!(
                "account-service-hpke-key-id={}",
                encode_base64url_32(&[0; 32])
            ),
            1,
        );
        let descriptor_path = root.0.join("forged-connect.txt");
        write_secret(&descriptor_path, forged.as_bytes())?;
        let mut request = test_request(&root.0)?;
        let config_path = request.config_path.clone();
        let data_dir = request.data_dir.clone();
        request.mode = InitMode::Edge {
            coordinator_descriptor: descriptor_path,
            coordinator_server_id: ServerId::from_bytes([8; 16]),
        };
        assert!(matches!(
            initialize_node(request),
            Err(OfflineError::InvalidRequest)
        ));
        assert!(fs::symlink_metadata(config_path).is_err());
        assert!(fs::symlink_metadata(data_dir).is_err());
        Ok(())
    }

    /// Owner and group identifiers no unprivileged process can grant.
    const UNGRANTABLE_ID: u32 = u32::MAX - 2;

    fn set_mode(path: &Path, mode: u32) -> Result<(), OfflineError> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| OfflineError::Filesystem)
    }

    fn owner_of(path: &Path) -> Result<Ownership, OfflineError> {
        Ok(directory_identity(path)?.owner)
    }

    fn file_owner(path: &Path) -> Result<Ownership, OfflineError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| OfflineError::Filesystem)?;
        Ok(Ownership {
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }

    fn create_fifo(path: &Path) -> Result<(), OfflineError> {
        rustix::fs::mkfifoat(CWD, path, Mode::RUSR | Mode::WUSR)
            .map_err(|_| OfflineError::Filesystem)
    }

    fn fill_directory(path: &Path, count: usize) -> Result<(), OfflineError> {
        create_private_directory(path)?;
        for index in 0..count {
            fs::write(path.join(format!("entry-{index}")), b"")
                .map_err(|_| OfflineError::Filesystem)?;
        }
        Ok(())
    }

    fn write_staged_files(staging: &Staging) -> Result<(), OfflineError> {
        write_secret(staging.operator_signing_key_file(), &[9; 32])?;
        write_secret(staging.config_file(), b"staged config")
    }

    #[test]
    fn init_rejects_operator_authority_beside_config_or_inside_runtime() -> Result<(), OfflineError>
    {
        let root = TestDirectory::create()?;
        let mut beside_config = test_request(&root.0)?;
        beside_config.operator_signing_key_file = root.0.join("etc/operator-signing.key");
        assert_eq!(
            validate_init_request(&beside_config),
            Err(OfflineError::InvalidRequest)
        );
        let mut inside_runtime = test_request(&root.0)?;
        inside_runtime.operator_signing_key_file = root.0.join("run/operator-signing.key");
        assert_eq!(
            validate_init_request(&inside_runtime),
            Err(OfflineError::InvalidRequest)
        );
        Ok(())
    }

    #[test]
    fn init_rejects_parent_directories_with_the_wrong_mode() -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let request = test_request(&root.0)?;
        assert_eq!(validate_init_request(&request), Ok(()));

        let etc = root.0.join("etc");
        set_mode(&etc, 0o775)?;
        assert_eq!(
            validate_init_request(&request),
            Err(OfflineError::Filesystem)
        );
        set_mode(&etc, DIRECTORY_MODE)?;

        let run = root.0.join("run");
        set_mode(&run, DIRECTORY_MODE)?;
        assert_eq!(
            validate_init_request(&request),
            Err(OfflineError::Filesystem)
        );
        set_mode(&run, 0o750)?;

        let operator = root.0.join("operator");
        set_mode(&operator, 0o750)?;
        assert_eq!(
            validate_init_request(&request),
            Err(OfflineError::Filesystem)
        );
        set_mode(&operator, DIRECTORY_MODE)?;
        assert_eq!(validate_init_request(&request), Ok(()));
        Ok(())
    }

    #[test]
    fn physical_root_separation_rejects_shared_and_nested_roots() -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let separated = test_request(&root.0)?;
        assert_eq!(validate_physical_root_separation(&separated), Ok(()));

        let mut shared = test_request(&root.0)?;
        shared.config_path = shared.runtime_dir.join("config.toml");
        assert_eq!(
            validate_physical_root_separation(&shared),
            Err(OfflineError::InvalidRequest)
        );

        let mut config_above_runtime = test_request(&root.0)?;
        config_above_runtime.config_path = root.0.join("config.toml");
        assert_eq!(
            validate_physical_root_separation(&config_above_runtime),
            Err(OfflineError::InvalidRequest)
        );

        let mut config_below_runtime = test_request(&root.0)?;
        let nested = root.0.join("run/nested");
        create_private_directory(&nested)?;
        config_below_runtime.config_path = nested.join("config.toml");
        assert_eq!(
            validate_physical_root_separation(&config_below_runtime),
            Err(OfflineError::InvalidRequest)
        );

        let identity = DirectoryIdentity {
            device: 1,
            inode: 2,
            mode: DIRECTORY_MODE,
            owner: Ownership { uid: 0, gid: 0 },
        };
        assert!(same_directory(identity, identity));
        assert!(!same_directory(
            identity,
            DirectoryIdentity {
                device: 3,
                ..identity
            }
        ));
        assert!(!same_directory(
            identity,
            DirectoryIdentity {
                inode: 3,
                ..identity
            }
        ));
        Ok(())
    }

    #[test]
    fn physical_directory_helpers_reject_relative_paths_and_non_directories()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        assert_eq!(
            open_physical_directory(Path::new("relative/path")).err(),
            Some(OfflineError::InvalidRequest)
        );
        assert_eq!(
            directory_identity(Path::new("../parent")),
            Err(OfflineError::InvalidRequest)
        );
        let file = root.0.join("regular");
        write_secret(&file, b"regular")?;
        let handle = fs::File::open(&file).map_err(|_| OfflineError::Filesystem)?;
        assert_eq!(
            opened_directory_identity(&handle),
            Err(OfflineError::Filesystem)
        );
        assert_eq!(sync_regular_file(&root.0), Err(OfflineError::Filesystem));
        assert_eq!(sync_regular_file(&file), Ok(()));
        assert_eq!(
            private_directory_identity(&root.0, 0o750),
            Err(OfflineError::Filesystem)
        );
        Ok(())
    }

    #[test]
    fn path_probes_report_unreadable_paths_as_filesystem_failures() -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let file = root.0.join("not-a-directory");
        write_secret(&file, b"file")?;
        let below_file = file.join("child");
        let owner = owner_of(&root.0)?;
        assert_eq!(require_absent(&below_file), Err(OfflineError::Filesystem));
        assert_eq!(
            validate_data_path_for_privilege(&below_file, false),
            Err(OfflineError::Filesystem)
        );
        assert_eq!(
            inspect_precreated_directory(&below_file, owner),
            Err(OfflineError::Filesystem)
        );
        let mut request = test_request(&root.0)?;
        request.data_dir = below_file;
        assert_eq!(
            refuse_existing_targets(&request),
            Err(OfflineError::Filesystem)
        );
        let missing_parent = root.0.join("missing");
        assert_eq!(
            create_staging_directory(&missing_parent.join("staging")),
            Err(OfflineError::Filesystem)
        );
        assert!(!missing_parent.exists());
        Ok(())
    }

    #[test]
    fn precreated_target_checks_reject_foreign_owner_replacement_and_entries()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let target = root.0.join("precreated");
        create_private_directory(&target)?;
        let owner = owner_of(&root.0)?;
        let foreign = Ownership {
            uid: UNGRANTABLE_ID,
            gid: owner.gid,
        };
        assert_eq!(
            inspect_precreated_directory(&target, foreign),
            Err(OfflineError::Filesystem)
        );
        let identity =
            inspect_precreated_directory(&target, owner)?.ok_or(OfflineError::Filesystem)?;
        assert_eq!(verify_precreated_directory(&target, identity), Ok(()));
        let replaced = DirectoryIdentity {
            inode: identity.inode.wrapping_add(1),
            ..identity
        };
        assert_eq!(
            verify_precreated_directory(&target, replaced),
            Err(OfflineError::Filesystem)
        );
        write_secret(&target.join("entry"), b"entry")?;
        assert_eq!(
            verify_precreated_directory(&target, identity),
            Err(OfflineError::Filesystem)
        );
        assert_eq!(
            inspect_precreated_directory(&target, owner),
            Err(OfflineError::ExistingTarget)
        );
        Ok(())
    }

    #[test]
    fn failed_target_rename_restores_only_precreated_directories() -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let fresh = root.0.join("fresh-target");
        assert_eq!(
            restore_target_after_failure(&fresh, None, OfflineError::Filesystem),
            Err(OfflineError::Filesystem)
        );
        assert!(!fresh.exists());

        let precreated = root.0.join("precreated-target");
        create_private_directory(&precreated)?;
        let identity = directory_identity(&precreated)?;
        fs::remove_dir(&precreated).map_err(|_| OfflineError::Filesystem)?;
        assert_eq!(
            restore_target_after_failure(&precreated, Some(identity), OfflineError::Filesystem),
            Err(OfflineError::Filesystem)
        );
        let restored = private_directory_identity(&precreated, DIRECTORY_MODE)?;
        assert_eq!(restored.owner, identity.owner);
        assert!(!directory_has_entry(&precreated)?);

        let unrestorable = root.0.join("missing/precreated-target");
        assert_eq!(
            restore_target_after_failure(&unrestorable, Some(identity), OfflineError::Filesystem),
            Err(OfflineError::PartialInitialization)
        );
        Ok(())
    }

    #[test]
    fn staged_tree_walk_rejects_symlinks_special_files_and_oversized_trees()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let owner = owner_of(&root.0)?;

        let linked = root.0.join("linked");
        create_private_directory(&linked)?;
        let target = root.0.join("link-target");
        write_secret(&target, b"target")?;
        std::os::unix::fs::symlink(&target, linked.join("link"))
            .map_err(|_| OfflineError::Filesystem)?;
        assert_eq!(
            collect_staged_tree_paths(&linked),
            Err(OfflineError::Filesystem)
        );
        assert_eq!(
            set_path_ownership(&linked.join("link"), owner),
            Err(OfflineError::Filesystem)
        );

        let special = root.0.join("special");
        create_private_directory(&special)?;
        create_fifo(&special.join("fifo"))?;
        assert_eq!(
            collect_staged_tree_paths(&special),
            Err(OfflineError::Filesystem)
        );
        assert_eq!(
            set_path_ownership(&special.join("fifo"), owner),
            Err(OfflineError::Filesystem)
        );

        let bounded = root.0.join("bounded");
        fill_directory(&bounded, MAX_STAGED_PATHS - 1)?;
        assert_eq!(collect_staged_tree_paths(&bounded)?.len(), MAX_STAGED_PATHS);
        let full = root.0.join("full");
        fill_directory(&full, MAX_STAGED_PATHS)?;
        assert_eq!(
            collect_staged_tree_paths(&full),
            Err(OfflineError::Filesystem)
        );
        let overflowing = root.0.join("overflowing");
        fill_directory(&overflowing, MAX_STAGED_PATHS + 1)?;
        assert_eq!(
            collect_staged_tree_paths(&overflowing),
            Err(OfflineError::Filesystem)
        );
        Ok(())
    }

    #[test]
    fn ownership_repair_refuses_identities_the_process_cannot_grant() -> Result<(), OfflineError> {
        if geteuid().is_root() {
            return Ok(());
        }
        let root = TestDirectory::create()?;
        let file = root.0.join("owned");
        write_secret(&file, b"owned")?;
        let owner = owner_of(&root.0)?;
        assert_eq!(set_path_ownership(&file, owner), Ok(()));
        let foreign_user = Ownership {
            uid: UNGRANTABLE_ID,
            gid: owner.gid,
        };
        assert_eq!(
            set_path_ownership(&file, foreign_user),
            Err(OfflineError::Filesystem)
        );
        let foreign_group = Ownership {
            uid: owner.uid,
            gid: UNGRANTABLE_ID,
        };
        assert_eq!(
            set_path_ownership(&file, foreign_group),
            Err(OfflineError::Filesystem)
        );
        assert_eq!(file_owner(&file)?, owner);
        Ok(())
    }

    #[test]
    fn descriptor_path_validation_rejects_relative_bare_directory_symlink_and_shared_files()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        assert_eq!(
            validate_existing_file_path(Path::new("relative/connect.txt")),
            Err(OfflineError::InvalidRequest)
        );
        assert_eq!(
            validate_existing_file_path(Path::new("/")),
            Err(OfflineError::InvalidRequest)
        );
        let directory = root.0.join("descriptor-directory");
        create_private_directory(&directory)?;
        assert_eq!(
            validate_existing_file_path(&directory),
            Err(OfflineError::Filesystem)
        );
        let descriptor = root.0.join("connect.txt");
        write_secret(&descriptor, b"descriptor")?;
        assert_eq!(validate_existing_file_path(&descriptor), Ok(()));
        let link = root.0.join("connect-link.txt");
        std::os::unix::fs::symlink(&descriptor, &link).map_err(|_| OfflineError::Filesystem)?;
        assert_eq!(
            validate_existing_file_path(&link),
            Err(OfflineError::Filesystem)
        );
        set_mode(&descriptor, 0o660)?;
        assert_eq!(
            validate_existing_file_path(&descriptor),
            Err(OfflineError::Filesystem)
        );

        let mut relative_edge = test_request(&root.0)?;
        relative_edge.mode = InitMode::Edge {
            coordinator_descriptor: PathBuf::from("relative/connect.txt"),
            coordinator_server_id: ServerId::from_bytes([8; 16]),
        };
        assert_eq!(
            validate_init_request(&relative_edge),
            Err(OfflineError::InvalidRequest)
        );
        Ok(())
    }

    #[test]
    fn config_install_failure_after_data_install_is_partial_and_inspectable()
    -> Result<(), OfflineError> {
        if geteuid().is_root() {
            return Ok(());
        }
        let root = TestDirectory::create()?;
        let request = test_request(&root.0)?;
        validate_init_request(&request)?;
        refuse_existing_targets(&request)?;
        let mut staging = Staging::create(&request)?;
        write_staged_files(&staging)?;
        let staging_root = staging.data_root().to_path_buf();
        let etc = root.0.join("etc");
        set_mode(&etc, 0o500)?;
        let outcome = staging.install(&request);
        drop(staging);
        set_mode(&etc, DIRECTORY_MODE)?;

        assert_eq!(outcome, Err(OfflineError::PartialInitialization));
        for name in INSTALL_DIRECTORY_NAMES {
            assert!(request.data_dir.join(name).is_dir(), "{name}");
        }
        assert!(request.operator_signing_key_file.is_file());
        assert!(!request.config_path.exists());
        assert!(staging_root.is_dir());
        assert!(!directory_has_entry(&staging_root)?);
        Ok(())
    }

    #[test]
    fn failed_first_target_rename_restores_the_precreated_layout_without_output()
    -> Result<(), OfflineError> {
        if geteuid().is_root() {
            return Ok(());
        }
        let root = TestDirectory::create()?;
        let request = test_request(&root.0)?;
        precreate_data_layout(&request)?;
        validate_init_request(&request)?;
        refuse_existing_targets(&request)?;
        let mut staging = Staging::create(&request)?;
        write_staged_files(&staging)?;
        let staging_root = staging.data_root().to_path_buf();
        set_mode(&staging_root, 0o500)?;
        let outcome = staging.install(&request);
        set_mode(&staging_root, DIRECTORY_MODE)?;
        drop(staging);

        assert_eq!(outcome, Err(OfflineError::Filesystem));
        let data_owner = owner_of(&request.data_dir)?;
        for name in INSTALL_DIRECTORY_NAMES {
            let target = request.data_dir.join(name);
            assert_eq!(
                private_directory_identity(&target, DIRECTORY_MODE)?.owner,
                data_owner,
                "{name}"
            );
            assert!(!directory_has_entry(&target)?, "{name}");
        }
        assert!(!request.operator_signing_key_file.exists());
        assert!(!request.config_path.exists());
        assert!(!staging_root.exists());
        Ok(())
    }

    #[test]
    fn onboarding_rejects_an_hpke_pin_that_does_not_match_the_private_key()
    -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let request = test_request(&root.0)?;
        let config_path = request.config_path.clone();
        initialize_node(request)?;
        enable_test_listener(&root.0)?;
        assert!(render_onboarding(&config_path).is_ok());

        let text = fs::read_to_string(&config_path).map_err(|_| OfflineError::Filesystem)?;
        let pinned = text
            .lines()
            .find(|line| line.starts_with("account_service_hpke_public_key = "))
            .ok_or(OfflineError::Configuration)?;
        let other = AccountHpkePrivateKey::from_bytes([12; 32])
            .map_err(|_| OfflineError::Cryptography)?
            .public_key()
            .map_err(|_| OfflineError::Cryptography)?;
        let repinned = text.replacen(
            pinned,
            &format!(
                "account_service_hpke_public_key = \"{}\"",
                encode_base64url_32(other.as_bytes())
            ),
            1,
        );
        fs::write(&config_path, repinned).map_err(|_| OfflineError::Filesystem)?;
        assert_eq!(
            render_onboarding(&config_path).err(),
            Some(OfflineError::Configuration)
        );
        Ok(())
    }
}
