//! Stopped-daemon initialization and inspection commands (spec 22.2-22.3
//! and Appendix C.8).
//!
//! These entry points do not start Tokio, bind a socket, contact a network,
//! or make generated listeners active. Secret bytes move from operating-system
//! entropy into mode-0600 files and crypto adapters only.

use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use agenc_ircd_admin::encode_base64url;
use agenc_ircd_auth::{AccountCreationInvite, OpaqueProfile};
use agenc_ircd_config::{
    Config, ConfigError, ConfigReport, DEFAULT_REDB_CACHE_BYTES, DisplayLabel, DnsName,
    InitProfile, InitValues, NodeRole, OnboardingFacts, OperatorTemplate, SecretLength, SecretSet,
    ValidationDepth, encode_base64url_32, load_config, open_secret_file,
    render_onboarding as render_config_onboarding, render_template,
};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, AccountHpkePublicKey, Ed25519SecretKey, LoginIndexKey, OsEntropy,
    RollbackGuardRootKey, SemanticHashDomain, StorageDigest, StorageMasterKey,
    audit_signing_key_id, backup_signing_key_id, semantic_digest,
};
use agenc_ircd_storage::{
    DatabaseHeaderTbs, InitialStorageRecord, LIVE_RECORD_KIND, LOGIN_INDEX_KEY_STATE_KEY,
    LoginIndexKeyState, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue, SCHEMA_GENERATION,
    StateDirectory, StorageEngineLimits, StorageError, StorageInitializationConfig,
    StorageInitializationMode, StorageInitializationOutcome, StorageOpenConfig, StorageOwner,
    StoredKey, TableId, embedded_storage_qualifications, initialize_storage,
};
use agenc_ircd_types::{
    DatabaseId, InviteId, NetworkId, OperatorId, RecoveryEpoch, ServerId, ServerIncarnation,
    UtcSecond,
};
use zeroize::Zeroizing;

use crate::StateCoreSeed;

const DIRECTORY_MODE: u32 = 0o700;
const SECRET_MODE: u32 = 0o600;
const MAX_DESCRIPTOR_BYTES: usize = 4_096;
const MAX_INVITE_LIFETIME_SECONDS: u64 = 2_592_000;
const DEFAULT_DATABASE_BYTES: u64 = 85_899_345_920;
const DEFAULT_BACKUP_BYTES: u64 = 107_374_182_400;
const DEFAULT_RESERVE_BYTES: u64 = 1_073_741_824;
const DEFAULT_RESERVE_PERCENT: u8 = 5;
const DEFAULT_CHECKPOINT_MANIFESTS: u64 = 100_000;

/// Inputs for one stopped-daemon first-run initialization.
pub struct InitRequest {
    /// Configuration file installed last.
    pub config_path: PathBuf,
    /// Convenience listener profile.
    pub profile: InitProfile,
    /// Imported network identity. Reserved for edge enrollment in Stage 07.
    pub network_id: Option<NetworkId>,
    /// Coordinator descriptor. Edge enrollment is not active before Stage 07.
    pub coordinator_descriptor: Option<PathBuf>,
    /// Dedicated persistent directory.
    pub data_dir: PathBuf,
    /// Dedicated runtime directory.
    pub runtime_dir: PathBuf,
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
    account_hpke: Zeroizing<[u8; 32]>,
    opaque_fake_credential: Zeroizing<[u8; 32]>,
    sequencer: Zeroizing<[u8; 32]>,
    opaque: OpaqueProfile,
}

impl GeneratedSecrets {
    fn generate(network_id: NetworkId) -> Result<Self, OfflineError> {
        Ok(Self {
            storage_master: random_32()?,
            rollback_guard: random_32()?,
            login_index: random_32()?,
            federation_signing: random_32()?,
            backup_signing: random_32()?,
            audit_signing: random_32()?,
            operator_signing: random_32()?,
            account_hpke: random_32()?,
            opaque_fake_credential: random_32()?,
            sequencer: random_32()?,
            opaque: OpaqueProfile::generate(network_id)
                .map_err(|_| OfflineError::Authentication)?,
        })
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
    fn generate(request: &InitRequest) -> Result<Self, OfflineError> {
        if request.coordinator_descriptor.is_some() {
            return Err(OfflineError::InvalidRequest);
        }
        let mut entropy = OsEntropy;
        Ok(Self {
            network_id: request
                .network_id
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
        })
    }
}

struct Staging {
    root: PathBuf,
    installed: bool,
}

impl Staging {
    fn create(data_dir: &Path) -> Result<Self, OfflineError> {
        ensure_data_directory(data_dir)?;
        let root = data_dir.join(staging_name()?);
        create_private_directory(&root)?;
        for name in ["keys", "trust", "state", "backups"] {
            create_private_directory(&root.join(name))?;
        }
        Ok(Self {
            root,
            installed: false,
        })
    }

    fn install(&mut self, request: &InitRequest) -> Result<(), OfflineError> {
        for name in ["keys", "trust", "state", "backups"] {
            self.rename(self.root.join(name), request.data_dir.join(name))?;
        }
        self.rename(self.root.join("config.toml"), request.config_path.clone())?;
        fs::remove_dir(&self.root).map_err(|_| OfflineError::PartialInitialization)
    }

    fn rename(&mut self, source: PathBuf, target: PathBuf) -> Result<(), OfflineError> {
        match fs::rename(source, target) {
            Ok(()) => {
                self.installed = true;
                Ok(())
            }
            Err(_) if self.installed => Err(OfflineError::PartialInitialization),
            Err(_) => Err(OfflineError::Filesystem),
        }
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.installed {
            let _cleanup = fs::remove_dir_all(&self.root);
        }
    }
}

/// Creates a new stopped node and installs the configuration last.
pub fn initialize_node(request: InitRequest) -> Result<InitReceipt, OfflineError> {
    validate_init_request(&request)?;
    refuse_existing_targets(&request)?;
    let identity = InitIdentity::generate(&request)?;
    let secrets = GeneratedSecrets::generate(identity.network_id)?;
    let mut staging = Staging::create(&request.data_dir)?;
    write_generated_secrets(&staging.root.join("keys"), &secrets)?;
    write_trust_manifests(&staging.root.join("trust"), &secrets)?;
    initialize_database(&staging.root.join("state"), identity, &secrets)?;
    write_configuration(&staging.root, &request, identity, &secrets)?;
    staging.install(&request)?;
    Ok(init_receipt(&request, identity))
}

/// Parses a command-line network identity without making the binary depend on
/// the foundational types crate directly.
pub fn parse_network_id(text: &str) -> Result<NetworkId, OfflineError> {
    NetworkId::parse(text).map_err(|_| OfflineError::InvalidRequest)
}

fn validate_init_request(request: &InitRequest) -> Result<(), OfflineError> {
    if !request.config_path.is_absolute()
        || !request.data_dir.is_absolute()
        || !request.runtime_dir.is_absolute()
        || request.config_path == request.data_dir
    {
        return Err(OfflineError::InvalidRequest);
    }
    if matches!(request.profile, InitProfile::Public | InitProfile::Dual)
        && request.dns_name.is_none()
    {
        return Err(OfflineError::InvalidRequest);
    }
    Ok(())
}

fn refuse_existing_targets(request: &InitRequest) -> Result<(), OfflineError> {
    let targets = [
        request.config_path.clone(),
        request.data_dir.join("keys"),
        request.data_dir.join("trust"),
        request.data_dir.join("state"),
        request.data_dir.join("backups"),
    ];
    if targets
        .iter()
        .any(|path| fs::symlink_metadata(path).is_ok())
    {
        return Err(OfflineError::ExistingTarget);
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
        ("operator-signing.key", keys.operator_signing.as_slice()),
        ("account-service-hpke.key", keys.account_hpke.as_slice()),
        (
            "opaque-fake-credential.key",
            keys.opaque_fake_credential.as_slice(),
        ),
        ("sequencer.key", keys.sequencer.as_slice()),
    ] {
        write_secret(&root.join(name), bytes)?;
    }
    write_secret(
        &root.join("opaque-server-setup.key"),
        keys.opaque.expose_setup_for_persistence(),
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
    let fake_record = PersistentRecordValue::new(
        TableId::OpaqueRecord,
        LIVE_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        keys.opaque.expose_fake_record_for_persistence().to_vec(),
    )?;
    let fake_record = InitialStorageRecord::new(
        TableId::OpaqueRecord,
        StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
        1,
        fake_record.encode()?,
    )?;
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
        initial_records: vec![key_state_record, fake_record],
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
    staging: &Path,
    request: &InitRequest,
    identity: InitIdentity,
    secrets: &GeneratedSecrets,
) -> Result<(), OfflineError> {
    let hpke = AccountHpkePrivateKey::from_bytes(*secrets.account_hpke)
        .map_err(|_| OfflineError::Cryptography)?;
    let tls_dir = request
        .config_path
        .parent()
        .ok_or(OfflineError::InvalidRequest)?
        .join("tls");
    let values = InitValues {
        profile: request.profile,
        network_id: identity.network_id,
        server_id: identity.server_id,
        role: NodeRole::Coordinator,
        coordinator_server_id: identity.server_id,
        server_name: request.server_name.clone(),
        display_name: request.display_name.clone(),
        data_dir: request.data_dir.clone(),
        runtime_dir: request.runtime_dir.clone(),
        tls_dir,
        dns_name: request.dns_name.clone(),
        account_service_hpke_public_key: *hpke
            .public_key()
            .map_err(|_| OfflineError::Cryptography)?
            .as_bytes(),
        operator: OperatorTemplate {
            operator_id: identity.operator_id,
            signing_public_key: signing_public(&secrets.operator_signing),
        },
    };
    let document = render_template(&values)?;
    write_secret(&staging.join("config.toml"), document.as_bytes())
}

fn init_receipt(request: &InitRequest, identity: InitIdentity) -> InitReceipt {
    InitReceipt {
        network_id: identity.network_id,
        server_id: identity.server_id,
        operator_id: identity.operator_id,
        operator_signing_key_file: request.data_dir.join("keys/operator-signing.key"),
        tor_snippet: "HiddenServiceDir /var/lib/tor/agenc-ircd\nHiddenServiceVersion 3\nHiddenServicePort 6697 unix:/run/agenc-ircd/onion.sock\n".to_owned(),
        systemd_snippet: "Use the packaged agenc-ircd.service and one reviewed address-family profile; socket activation is not supported.\n".to_owned(),
        certificate_instructions: "Enroll TLS certificates for every configured public or onion listener, place them under the configured tls directory, then enable the reviewed listeners.\n".to_owned(),
    }
}

/// Opens the configured database through the exclusive storage owner and
/// returns only authenticated header facts.
pub fn verify_database_header(
    config: &Config,
    secrets: &SecretSet,
) -> Result<HeaderFacts, OfflineError> {
    validate_account_hpke_pin(config, secrets)?;
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
        previous_login_index_key: secrets
            .login_index_previous()
            .map(|key| LoginIndexKey::from_bytes(*key.expose())),
        limits: limits_from_config(config),
    })?;
    let _seed = StateCoreSeed::from_storage(&owner)?;
    let recovered = *owner.recovered_state();
    owner.shutdown()?;
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
    let Some(private) = secrets.account_service_hpke_private() else {
        return Ok(());
    };
    let private = AccountHpkePrivateKey::from_bytes(*private.expose())
        .map_err(|_| OfflineError::Cryptography)?;
    let public = private
        .public_key()
        .map_err(|_| OfflineError::Cryptography)?;
    if public.as_bytes() != &config.accounts.account_service_hpke_public_key {
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
    let network_id = descriptor_network_id(&descriptor)?;
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
        encode_base64url(descriptor.as_bytes()),
        encode_base64url(invite.expose_for_account_request()),
    ))
}

fn read_descriptor(path: &Path) -> Result<String, OfflineError> {
    let bytes = fs::read(path).map_err(|_| OfflineError::Filesystem)?;
    if bytes.is_empty() || bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err(OfflineError::InvalidRequest);
    }
    let text = String::from_utf8(bytes).map_err(|_| OfflineError::InvalidRequest)?;
    validate_descriptor_shape(&text)?;
    Ok(text)
}

fn validate_descriptor_shape(text: &str) -> Result<(), OfflineError> {
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(OfflineError::InvalidRequest);
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.first().copied() != Some("AGENC-CHAT-CONNECT/1") || !(10..=14).contains(&lines.len()) {
        return Err(OfflineError::InvalidRequest);
    }
    let required = [
        "network-id=",
        "server-name=",
        "recovery-epoch=",
        "base-profile-sha256=",
        "account-service-hpke-key-id=",
        "account-service-hpke-public-key=",
        "e2ee-profile=",
        "e2ee-profile-sha256=",
        "sequencer-key-set-generation=",
        "sequencer-key-set-hash=",
    ];
    if required
        .iter()
        .any(|prefix| lines.iter().filter(|line| line.starts_with(prefix)).count() != 1)
    {
        return Err(OfflineError::InvalidRequest);
    }
    Ok(())
}

fn descriptor_network_id(descriptor: &str) -> Result<NetworkId, OfflineError> {
    let value = descriptor
        .lines()
        .find_map(|line| line.strip_prefix("network-id="))
        .ok_or(OfflineError::InvalidRequest)?;
    NetworkId::parse(value).map_err(|_| OfflineError::InvalidRequest)
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
            let target =
                fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"))
                    .map_err(|_| OfflineError::Filesystem)?;
            let root = target.join(format!(
                "offline-runtime-test-{}-{sequence}",
                std::process::id()
            ));
            create_private_directory(&root)?;
            create_private_directory(&root.join("etc"))?;
            create_private_directory(&root.join("run"))?;
            Ok(Self(root))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    fn test_request(root: &Path) -> Result<InitRequest, OfflineError> {
        Ok(InitRequest {
            config_path: root.join("etc/config.toml"),
            profile: InitProfile::Public,
            network_id: Some(NetworkId::from_bytes([1; 32])),
            coordinator_descriptor: None,
            data_dir: root.join("data"),
            runtime_dir: root.join("run"),
            server_name: DnsName::parse("chat.example")?,
            display_name: DisplayLabel::parse("Example")?,
            dns_name: Some(DnsName::parse("chat.example")?),
        })
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
    fn descriptor_shape_and_invite_lifetime_bounds_are_closed() {
        let descriptor = "AGENC-CHAT-CONNECT/1\nnetwork-id=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\nserver-name=chat.example\nrecovery-epoch=AQEBAQEBAQEBAQEBAQEBAQ\nbase-profile-sha256=x\naccount-service-hpke-key-id=x\naccount-service-hpke-public-key=x\ne2ee-profile=IRC-MLS/1\ne2ee-profile-sha256=x\nsequencer-key-set-generation=0\nsequencer-key-set-hash=x\n";
        assert!(validate_descriptor_shape(descriptor).is_ok());
        assert_eq!(
            descriptor_network_id(descriptor),
            Ok(NetworkId::from_bytes([1; 32]))
        );
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
            validate_descriptor_shape(descriptor.trim_end()),
            Err(OfflineError::InvalidRequest)
        );
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
    fn descriptor_reader_rejects_size_encoding_shape_and_duplicate_fields()
    -> Result<(), OfflineError> {
        let valid = "AGENC-CHAT-CONNECT/1\nnetwork-id=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\nserver-name=chat.example\nrecovery-epoch=AQEBAQEBAQEBAQEBAQEBAQ\nbase-profile-sha256=x\naccount-service-hpke-key-id=x\naccount-service-hpke-public-key=x\ne2ee-profile=IRC-MLS/1\ne2ee-profile-sha256=x\nsequencer-key-set-generation=0\nsequencer-key-set-hash=x\n";
        assert_eq!(validate_descriptor_shape(valid), Ok(()));
        for invalid in [
            valid.replace('\n', "\r\n"),
            valid.replacen("AGENC-CHAT-CONNECT/1", "WRONG/1", 1),
            "AGENC-CHAT-CONNECT/1\nnetwork-id=x\n".to_owned(),
            format!("{valid}extra-1=x\nextra-2=x\nextra-3=x\nextra-4=x\n"),
            valid.replacen("server-name=chat.example\n", "optional=x\n", 1),
            format!("{valid}network-id=duplicate\n"),
        ] {
            assert_eq!(
                validate_descriptor_shape(&invalid),
                Err(OfflineError::InvalidRequest)
            );
        }

        let root = TestDirectory::create()?;
        assert_eq!(
            read_descriptor(&root.0.join("missing")),
            Err(OfflineError::Filesystem)
        );
        for (name, bytes, expected) in [
            ("empty", Vec::new(), OfflineError::InvalidRequest),
            (
                "oversized",
                vec![b'x'; MAX_DESCRIPTOR_BYTES + 1],
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
            assert_eq!(read_descriptor(&path), Err(expected));
        }
        let valid_path = root.0.join("valid");
        write_secret(&valid_path, valid.as_bytes())?;
        assert_eq!(read_descriptor(&valid_path)?, valid);
        assert_eq!(
            parse_network_id("invalid"),
            Err(OfflineError::InvalidRequest)
        );
        assert_eq!(
            parse_network_id("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
            Ok(NetworkId::from_bytes([1; 32]))
        );
        Ok(())
    }

    #[test]
    fn staging_rename_distinguishes_preinstall_and_partial_failures() -> Result<(), OfflineError> {
        let root = TestDirectory::create()?;
        let staging_root = root.0.join("rename-staging");
        create_private_directory(&staging_root)?;
        let mut staging = Staging {
            root: staging_root,
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
            SECRET_MODE
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
        assert!(matches!(fake_rows.records.as_slice(), [record]
                if record.table == TableId::OpaqueRecord && record.key == fake_key));
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
}
