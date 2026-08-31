//! Live Stage 06 daemon composition for a standalone coordinator.

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agenc_ircd_admin::{AdminSessionBinding, OperatorRecord, OperatorRegistry};
use agenc_ircd_auth::{
    AuthError, CHANNEL_KEY_HASH_BYTES as AUTH_CHANNEL_HASH_BYTES,
    CHANNEL_KEY_ITERATIONS as AUTH_CHANNEL_ITERATIONS, CHANNEL_KEY_LANES as AUTH_CHANNEL_LANES,
    CHANNEL_KEY_MEMORY_KIB as AUTH_CHANNEL_MEMORY_KIB,
    CHANNEL_KEY_SALT_BYTES as AUTH_CHANNEL_SALT_BYTES, OpaqueProfile, derive_channel_key_verifier,
};
use agenc_ircd_config::{
    Config, ConfigError, ConfigReport, DEFAULT_REDB_CACHE_BYTES, DirectMessageDefault, LimitKey,
    ListenerBind as ConfigListenerBind, ListenerPurpose as ConfigListenerPurpose, NodeRole,
    RATE_ROWS, RegistrationPolicy, SecretSet, ValidationDepth, apply_process_hardening,
    load_audit_trust_manifest, load_config,
};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, CryptoError, CryptoWorkerConfig, Ed25519PublicKey, Ed25519SecretKey,
    LoginIndexKey, OpaqueFakeCredentialKey, OsEntropy, RollbackGuardRootKey, StorageMasterKey,
};
use agenc_ircd_domain::{
    DirectMessagePolicy, GuestDirectMessagePolicy, OperationalLimitValues, OperationalLimits,
    PresencePolicy,
};
use agenc_ircd_storage::{
    StateDirectory, StorageEngineLimits, StorageError, StorageOpenConfig, StorageOwner,
    embedded_storage_qualifications,
};
use agenc_ircd_types::{EntropySource as _, Generation, OriginId, WallClock as _};
use tokio::runtime::Builder;
use tokio::sync::{Semaphore, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::RuntimeError;
use crate::StateCoreSeed;
use crate::account_service::AccountCreationPolicy;
use crate::admin::{
    AdminAdmissionSnapshot, AdminOwner, AdminOwnerClocks, AdminOwnerInbox, AdminTransportPort,
    AuditAuthority, admin_transport_channel,
};
use crate::admission::{BucketKind, BucketRate, RateLimits, TransportAdmission};
use crate::bridge::crypto::{
    CHANNEL_KEY_ARGON2_ITERATIONS, CHANNEL_KEY_ARGON2_MEMORY_KIB, CHANNEL_KEY_ARGON2_PARALLELISM,
    CHANNEL_KEY_HASH_BYTES, CHANNEL_KEY_SALT_BYTES, ChannelKeyVerifier, ChannelKeyVerifierRecord,
    CryptoBridge,
};
use crate::bridge::storage::StorageBridge;
use crate::budget::{MemoryBudget, startup_arithmetic};
use crate::channels::RegisteredCommandExecutor;
use crate::clock::{SystemMonotonicClock, SystemWallClock};
use crate::connection::{
    CONTROL_ITEM_SLOTS, ConnectionLimits, MAX_DEMAND_FRAMES, QueueLimits, ReaderLimits,
};
use crate::listener::{
    ListenerContext, ListenerControl, ListenerError, ListenerSet, ListenerSource, ListenerSpec,
    LocalAdminAdmission, NoObserver, spki_sha256,
};
use crate::purpose::ListenerPurpose;
use crate::registration::{AccountServiceConfig, RegistrationRouter, RegistrationRouterConfig};
use crate::state_core::durable::{AccountingCeilings, KeyDeriver};
use crate::state_core::inbox::{
    LifecycleControl, LifecycleFailure, LifecyclePhase, MaintenanceEvent, SIGNAL_EVENT_CAPACITY,
    SignalEvent, StateCoreMessage, lifecycle_channel,
};
use crate::state_core::reconstruct::{Reconstruction, reconstruct};
use crate::state_core::{
    StateCore, StateCoreClocks, StateCoreConfig, StateCoreExit, StateCoreInputs, admin_core_channel,
};
use crate::supervisor::{
    ChildFailure, ChildKind, ChildName, JoinReport, ShutdownFailure, ShutdownHooks, ShutdownPhase,
    ShutdownPlan, ShutdownProblemKind, ShutdownReport, Supervisor, run_shutdown, run_signal_task,
};
use crate::sync::Arc;
use crate::tls::{
    ClientAuth, HandshakeLimiter, PrivateKey, TlsConfigError, TlsEndpointProfile,
    build_server_config, load_certificate_chain, load_trust_store,
};

const RUNTIME_THREAD_NAME: &str = "agenc-ircd-tokio";
const MAINTENANCE_MINUTE: Duration = Duration::from_secs(60);
const PREFIX_ERASURE_INTERVAL: Duration = Duration::from_secs(600);
const RETENTION_INTERVAL: Duration = Duration::from_secs(3_600);
/// Fixed process status used only for a committed service-manager restart.
pub const RESTART_EXIT_CODE: u8 = 75;

/// A completed daemon run classified for the service manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonExit {
    /// Graceful DIE, process signal, or ordinary service stop.
    Stopped,
    /// A committed administrative RESTART requested service-manager restart.
    RestartRequested,
}

/// A public-safe live-daemon startup or ownership failure.
pub enum DaemonError {
    /// Strict configuration or secret loading failed.
    Configuration(ConfigReport),
    /// A required host control could not be installed.
    HostControl(ConfigError),
    /// The selected topology is not implemented by this core-only runtime.
    UnsupportedProfile,
    /// Authentication material was invalid.
    Authentication(AuthError),
    /// Cryptographic material was invalid.
    Cryptography(CryptoError),
    /// TLS material or policy was invalid.
    Tls(TlsConfigError),
    /// Storage startup or shutdown failed.
    Storage(StorageError),
    /// A bounded runtime invariant failed.
    Runtime(RuntimeError),
    /// Tokio could not start the configured worker set.
    RuntimeStart,
    /// A supervised owner ended unexpectedly.
    TaskFailed,
    /// One or more owners did not join within the configured shutdown budget.
    ShutdownTimeout,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(report) => fmt::Display::fmt(report, formatter),
            Self::HostControl(error) => write!(formatter, "process hardening failed: {error}"),
            Self::UnsupportedProfile => {
                formatter.write_str("enabled listener or node profile is not available in core-v1")
            }
            Self::Authentication(error) => {
                write!(formatter, "authentication startup failed: {error}")
            }
            Self::Cryptography(error) => write!(formatter, "cryptographic startup failed: {error}"),
            Self::Tls(error) => write!(formatter, "TLS startup failed: {error}"),
            Self::Storage(error) => write!(formatter, "storage owner failed: {error}"),
            Self::Runtime(error) => write!(formatter, "runtime startup failed: {error}"),
            Self::RuntimeStart => formatter.write_str("Tokio runtime startup failed"),
            Self::TaskFailed => formatter.write_str("a supervised daemon owner failed"),
            Self::ShutdownTimeout => formatter.write_str("daemon shutdown exceeded its deadline"),
        }
    }
}

impl fmt::Debug for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for DaemonError {}

impl From<ConfigReport> for DaemonError {
    fn from(report: ConfigReport) -> Self {
        Self::Configuration(report)
    }
}

impl From<ConfigError> for DaemonError {
    fn from(error: ConfigError) -> Self {
        Self::HostControl(error)
    }
}

impl From<AuthError> for DaemonError {
    fn from(error: AuthError) -> Self {
        Self::Authentication(error)
    }
}

impl From<CryptoError> for DaemonError {
    fn from(error: CryptoError) -> Self {
        Self::Cryptography(error)
    }
}

impl From<TlsConfigError> for DaemonError {
    fn from(error: TlsConfigError) -> Self {
        Self::Tls(error)
    }
}

impl From<StorageError> for DaemonError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<RuntimeError> for DaemonError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<ListenerError> for DaemonError {
    fn from(_error: ListenerError) -> Self {
        Self::Runtime(RuntimeError::InvalidValue)
    }
}

/// Loads, reconstructs, serves, and joins one standalone coordinator.
pub fn serve(config_path: &Path) -> Result<DaemonExit, DaemonError> {
    let config = load_config(config_path, ValidationDepth::Host)?;
    validate_profile(&config)?;
    harden_process(&config)?;
    let secrets = SecretSet::load(&config)?;
    let operators = operator_registry(&config)?;
    let storage = LiveStorage::open(&config, &secrets, &operators)?;
    let workers = usize_value(config.server.tokio_worker_threads)?;
    let runtime = Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name(RUNTIME_THREAD_NAME)
        .enable_all()
        .build()
        .map_err(|_| DaemonError::RuntimeStart)?;
    runtime.block_on(run(
        config_path.to_path_buf(),
        config,
        secrets,
        operators,
        storage,
    ))
}

fn validate_profile(config: &Config) -> Result<(), DaemonError> {
    if config.network.role != NodeRole::Coordinator
        || config.federation.enabled
        || config.e2ee.enabled
        || !config.accounts.accept_clients
    {
        return Err(DaemonError::UnsupportedProfile);
    }
    for listener in config.listeners.iter().filter(|listener| listener.enabled) {
        if !matches!(
            listener.purpose,
            ConfigListenerPurpose::ClientTls
                | ConfigListenerPurpose::ClientOnion
                | ConfigListenerPurpose::AdminLocal
                | ConfigListenerPurpose::AdminTls
        ) {
            return Err(DaemonError::UnsupportedProfile);
        }
    }
    Ok(())
}

fn harden_process(config: &Config) -> Result<(), DaemonError> {
    let outcome = apply_process_hardening(config.server.require_locked_secrets)?;
    if !outcome.dumpable_disabled || !outcome.core_limit_zero {
        return Err(DaemonError::HostControl(ConfigError::HostControl));
    }
    Ok(())
}

struct LiveStorage {
    owner: StorageOwner,
    seed: StateCoreSeed,
    keys: KeyDeriver,
    reconstruction: Reconstruction,
    audit: AuditAuthority,
}

impl LiveStorage {
    fn open(
        config: &Config,
        secrets: &SecretSet,
        operators: &OperatorRegistry,
    ) -> Result<Self, DaemonError> {
        let qualifications = embedded_storage_qualifications()?;
        let state_directory = StateDirectory::open(&config.storage.state_dir, &qualifications)?;
        let owner = StorageOwner::start(storage_open_config(config, secrets, state_directory))?;
        let seed = StateCoreSeed::from_storage(&owner)?;
        let storage = seed.storage();
        let keys = KeyDeriver::new(
            StorageMasterKey::from_bytes(*secrets.storage_master().expose()),
            storage.database_binding(),
            storage.storage_key_generation(),
        )?;
        let reconstruction = reconstruct(&seed, &owner.port(), &keys)?;
        let trust = load_audit_trust_manifest(&config.moderation.audit_trust_manifest_file)?;
        let now = SystemWallClock
            .utc_now()
            .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))?
            .get();
        let audit = AuditAuthority::reconstruct(
            AdminSessionBinding {
                network_id: config.network.network_id,
                server_id: config.server.server_id,
            },
            Ed25519SecretKey::from_bytes(*secrets.audit_signing().expose()),
            &trust,
            &owner.port(),
            &keys,
            operators,
            now,
        )?;
        Ok(Self {
            owner,
            seed,
            keys,
            reconstruction,
            audit,
        })
    }
}

fn storage_open_config(
    config: &Config,
    secrets: &SecretSet,
    state_directory: StateDirectory,
) -> StorageOpenConfig {
    StorageOpenConfig {
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
        limits: StorageEngineLimits {
            redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
            fixed_reserve_bytes: config.storage.disk_reserve_bytes,
            reserve_percent: config.storage.disk_reserve_percent,
            database_max_bytes: config.storage.database_max_bytes,
            backup_max_bytes: config.storage.backup_max_bytes,
            integrity_checkpoint_manifests: config.storage.integrity_checkpoint_manifests,
        },
    }
}

struct LiveState {
    owner: StorageOwner,
    state: StateCore,
    storage: mpsc::Receiver<crate::bridge::StorageCompletionMessage>,
    storage_reads: mpsc::Receiver<crate::bridge::StorageReadCompletionMessage>,
    crypto: mpsc::Receiver<
        crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
    >,
    audit: Option<AuditAuthority>,
}

fn build_live_state(
    config: &Config,
    secrets: &SecretSet,
    storage: LiveStorage,
    budget: Arc<MemoryBudget>,
    rates: RateLimits,
) -> Result<LiveState, DaemonError> {
    let LiveStorage {
        owner,
        seed,
        keys,
        mut reconstruction,
        audit,
    } = storage;
    let (bridge, storage, storage_reads) = StorageBridge::start(owner.port())?;
    let crypto_config = CryptoWorkerConfig::new(
        limit_usize(config, LimitKey::ChannelKeyJobs)?,
        limit_usize(config, LimitKey::OpaqueJobs)?,
        usize_value(config.server.crypto_worker_threads)?,
    )
    .map_err(|_| RuntimeError::InvalidValue)?;
    let (crypto_bridge, crypto) = CryptoBridge::start(crypto_config)?;
    let commands = registered_commands()?;
    let router = RegistrationRouter::new(
        registration_config(config, secrets, &seed, &reconstruction)?,
        commands,
    )?;
    reconstruction
        .domain
        .set_operational_limits(operational_limits(config)?);
    let state = StateCore::new(StateCoreInputs {
        config: StateCoreConfig {
            server_prefix: config.server.name.as_str().to_owned(),
            rate_limits: rates,
            ceilings: AccountingCeilings {
                database_max_bytes: config.storage.database_max_bytes,
                backup_max_bytes: config.storage.backup_max_bytes,
            },
        },
        reconstruction,
        keys,
        bridge,
        crypto: crypto_bridge,
        budget,
        clocks: StateCoreClocks {
            monotonic: Box::new(SystemMonotonicClock::start()),
            wall: Box::new(SystemWallClock),
        },
        entropy: Box::new(OsEntropy),
        router: Box::new(router),
    });
    Ok(LiveState {
        owner,
        state,
        storage,
        storage_reads,
        crypto,
        audit: Some(audit),
    })
}

fn registration_config(
    config: &Config,
    secrets: &SecretSet,
    seed: &StateCoreSeed,
    reconstruction: &Reconstruction,
) -> Result<RegistrationRouterConfig, DaemonError> {
    let account_service = account_service_config(config, secrets, seed, reconstruction)?;
    let access_token = secrets
        .access_token()
        .map(|secret| Zeroizing::new(*secret.expose()));
    Ok(RegistrationRouterConfig {
        network_id: config.network.network_id,
        server_id: config.server.server_id,
        server_prefix: config.server.name.as_str().to_owned(),
        display_name: config.network.display_name.as_str().to_owned(),
        access_token,
        account_service,
    })
}

fn account_service_config(
    config: &Config,
    secrets: &SecretSet,
    seed: &StateCoreSeed,
    reconstruction: &Reconstruction,
) -> Result<AccountServiceConfig, DaemonError> {
    let private_bytes = secrets
        .account_service_hpke_private()
        .ok_or(DaemonError::UnsupportedProfile)?;
    let hpke_private_key = AccountHpkePrivateKey::from_bytes(*private_bytes.expose())?;
    if hpke_private_key.public_key()?.as_bytes() != &config.accounts.account_service_hpke_public_key
    {
        return Err(DaemonError::Cryptography(CryptoError::AuthenticationFailed));
    }
    let setup = secrets
        .opaque_server_setup()
        .ok_or(DaemonError::UnsupportedProfile)?
        .expose()
        .try_into()
        .map_err(|_| DaemonError::Authentication(AuthError::InvalidEncoding))?;
    let fake_record = *reconstruction.account_service.fake_opaque_record();
    let opaque_profile =
        OpaqueProfile::from_serialized(config.network.network_id, setup, fake_record)?;
    let fake_key = secrets
        .opaque_fake_credential()
        .ok_or(DaemonError::UnsupportedProfile)?;
    let mut entropy = OsEntropy;
    let origin_id = OriginId::generate(&mut entropy)
        .map_err(|_| DaemonError::Cryptography(CryptoError::EntropyUnavailable))?;
    let storage = seed.storage();
    let creation_policy = creation_policy(config, secrets)?;
    let (default_presence, default_guest_direct_messages, default_direct_messages) =
        account_defaults(config);
    Ok(AccountServiceConfig {
        network_id: config.network.network_id,
        server_id: config.server.server_id,
        server_incarnation: storage.database_binding().server_incarnation(),
        origin_id,
        origin_generation: Generation::new(1).map_err(|_| RuntimeError::InvalidValue)?,
        recovery_epoch: storage.recovery_epoch(),
        hpke_private_key: Arc::new(hpke_private_key),
        opaque_profile: Arc::new(opaque_profile),
        current_login_index_key: Arc::new(LoginIndexKey::from_bytes(
            *secrets.login_index().expose(),
        )),
        previous_login_index_key: secrets
            .login_index_previous()
            .map(|key| Arc::new(LoginIndexKey::from_bytes(*key.expose()))),
        fake_credential_key: Arc::new(OpaqueFakeCredentialKey::from_bytes(*fake_key.expose())),
        login_index_key_state: reconstruction.account_service.login_index_key_state(),
        live_login_keys: reconstruction.account_service.live_login_keys().clone(),
        login_deletion_tombstones: reconstruction
            .account_service
            .login_deletion_tombstones()
            .clone(),
        startup_transaction_cleanups: reconstruction
            .account_service
            .startup_transaction_cleanups()
            .to_vec(),
        creation_policy,
        default_presence,
        default_guest_direct_messages,
        default_direct_messages,
    })
}

fn creation_policy(
    config: &Config,
    secrets: &SecretSet,
) -> Result<AccountCreationPolicy, DaemonError> {
    match config.accounts.registration {
        RegistrationPolicy::Open => Ok(AccountCreationPolicy::Open),
        RegistrationPolicy::Invite => {
            let key = secrets
                .invitation_verification()
                .ok_or(DaemonError::UnsupportedProfile)?;
            Ok(AccountCreationPolicy::Invite(Ed25519PublicKey::from_bytes(
                *key.expose(),
            )?))
        }
        RegistrationPolicy::Closed => Ok(AccountCreationPolicy::Closed),
    }
}

const fn account_defaults(
    config: &Config,
) -> (
    PresencePolicy,
    GuestDirectMessagePolicy,
    DirectMessagePolicy,
) {
    let presence = if config.accounts.default_public_presence {
        PresencePolicy::Public
    } else {
        PresencePolicy::Private
    };
    let guest_direct_messages = if config.accounts.default_allow_guest_dm {
        GuestDirectMessagePolicy::Allow
    } else {
        GuestDirectMessagePolicy::Deny
    };
    let direct_messages = match config.accounts.default_direct_messages {
        DirectMessageDefault::Allow => DirectMessagePolicy::Allow,
        DirectMessageDefault::Contacts => DirectMessagePolicy::Contacts,
        DirectMessageDefault::Deny => DirectMessagePolicy::Deny,
    };
    (presence, guest_direct_messages, direct_messages)
}

struct ReviewedChannelKeyVerifier;

impl ChannelKeyVerifier for ReviewedChannelKeyVerifier {
    fn derive(
        &self,
        secret: &[u8],
        salt: &[u8; CHANNEL_KEY_SALT_BYTES],
    ) -> Result<[u8; CHANNEL_KEY_HASH_BYTES], CryptoError> {
        if CHANNEL_KEY_ARGON2_MEMORY_KIB != AUTH_CHANNEL_MEMORY_KIB
            || CHANNEL_KEY_ARGON2_ITERATIONS != AUTH_CHANNEL_ITERATIONS
            || CHANNEL_KEY_ARGON2_PARALLELISM != AUTH_CHANNEL_LANES
            || CHANNEL_KEY_SALT_BYTES != AUTH_CHANNEL_SALT_BYTES
            || CHANNEL_KEY_HASH_BYTES != AUTH_CHANNEL_HASH_BYTES
        {
            return Err(CryptoError::InvalidEncoding);
        }
        derive_channel_key_verifier(secret, salt).map_err(|_| CryptoError::AuthenticationFailed)
    }
}

fn registered_commands() -> Result<RegisteredCommandExecutor, DaemonError> {
    let verifier: Arc<dyn ChannelKeyVerifier> = Arc::new(ReviewedChannelKeyVerifier);
    let mut entropy = OsEntropy;
    let mut salt = [0_u8; CHANNEL_KEY_SALT_BYTES];
    let mut secret = Zeroizing::new([0_u8; 32]);
    entropy
        .fill_exact(&mut salt)
        .map_err(|_| CryptoError::EntropyUnavailable)?;
    entropy
        .fill_exact(secret.as_mut())
        .map_err(|_| CryptoError::EntropyUnavailable)?;
    let hash = verifier.derive(secret.as_ref(), &salt)?;
    let dummy = ChannelKeyVerifierRecord::new(salt, hash);
    Ok(RegisteredCommandExecutor::new(verifier, dummy))
}

fn memory_budget(config: &Config) -> Result<Arc<MemoryBudget>, DaemonError> {
    let purposes = enabled_runtime_purposes(config)?;
    let parsed_arena = config.limits.values.get(LimitKey::ParsedArenaBytes);
    let pool = startup_arithmetic(
        config.server.memory_budget_bytes,
        config.server.crypto_worker_threads,
        &purposes,
        parsed_arena,
    )?;
    Ok(Arc::new(MemoryBudget::new(pool.protocol_pool_bytes())))
}

fn enabled_runtime_purposes(config: &Config) -> Result<Vec<ListenerPurpose>, DaemonError> {
    config
        .listeners
        .iter()
        .filter(|listener| listener.enabled)
        .map(|listener| runtime_purpose(listener.purpose))
        .collect()
}

fn runtime_purpose(purpose: ConfigListenerPurpose) -> Result<ListenerPurpose, DaemonError> {
    match purpose {
        ConfigListenerPurpose::ClientTls => Ok(ListenerPurpose::ClientTls),
        ConfigListenerPurpose::ClientOnion => Ok(ListenerPurpose::ClientOnion),
        ConfigListenerPurpose::AdminLocal => Ok(ListenerPurpose::AdminLocal),
        ConfigListenerPurpose::AdminTls => Ok(ListenerPurpose::AdminTls),
        ConfigListenerPurpose::ClientWss | ConfigListenerPurpose::Federation => {
            Err(DaemonError::UnsupportedProfile)
        }
    }
}

fn configured_rates(config: &Config) -> Result<RateLimits, DaemonError> {
    let mut limits = RateLimits::defaults();
    for kind in BucketKind::ALL {
        let Some(name) = kind.config_name() else {
            continue;
        };
        let row = RATE_ROWS
            .iter()
            .find(|row| row.name == name)
            .ok_or(RuntimeError::InvalidValue)?;
        let spec = config.limits.rates.get(row.key);
        limits.set(
            kind,
            BucketRate::new(spec.refill_tokens, spec.refill_seconds, spec.burst)?,
        )?;
    }
    Ok(limits)
}

fn connection_limits(config: &Config) -> Result<ConnectionLimits, DaemonError> {
    let batches = limit_usize(config, LimitKey::ResponseBatchesPerConnection)?;
    let items = batches
        .checked_mul(MAX_DEMAND_FRAMES)
        .and_then(|items| items.checked_add(CONTROL_ITEM_SLOTS))
        .ok_or(RuntimeError::Overflow)?;
    Ok(ConnectionLimits {
        reader: ReaderLimits::new(
            limit_usize(config, LimitKey::RequestsPerConnection)?,
            limit_usize(config, LimitKey::ParsedArenaBytes)?,
        )?,
        queue: QueueLimits::new(
            limit_usize(config, LimitKey::ClientOutputBytes)?,
            limit_usize(config, LimitKey::ClientControlOutputBytes)?,
            items,
        )?,
    })
}

fn operational_limits(config: &Config) -> Result<OperationalLimits, DaemonError> {
    OperationalLimits::new(OperationalLimitValues {
        sessions_per_account: limit_usize(config, LimitKey::SessionsPerAccount)?,
        channels_per_session: limit_usize(config, LimitKey::ChannelsPerSession)?,
        members_per_channel: limit_usize(config, LimitKey::MembersPerChannel)?,
        global_channels: limit_usize(config, LimitKey::GlobalChannels)?,
        local_channels: limit_usize(config, LimitKey::LocalChannels)?,
        invites_per_channel: limit_usize(config, LimitKey::InvitesPerChannel)?,
        invites_per_principal: limit_usize(config, LimitKey::InvitesPerPrincipal)?,
        invites_global: limit_usize(config, LimitKey::InvitesGlobal)?,
        contacts_per_account: usize_value(config.accounts.max_contacts)?,
    })
    .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))
}

fn limit_usize(config: &Config, key: LimitKey) -> Result<usize, DaemonError> {
    usize_value(config.limits.values.get(key))
}

fn usize_value(value: u64) -> Result<usize, DaemonError> {
    usize::try_from(value).map_err(|_| DaemonError::Runtime(RuntimeError::Overflow))
}

async fn build_listener_specs(
    config: &Config,
    secrets: &SecretSet,
) -> Result<Vec<ListenerSpec>, DaemonError> {
    let mut specs = Vec::new();
    for listener in config.listeners.iter().filter(|listener| listener.enabled) {
        let purpose = runtime_purpose(listener.purpose)?;
        let tls = if purpose == ListenerPurpose::AdminLocal {
            None
        } else {
            let files = listener
                .tls
                .as_ref()
                .ok_or(DaemonError::Tls(TlsConfigError::ClientAuthMismatch))?;
            let chain = load_certificate_chain(files.certificate_file.clone()).await?;
            validate_onion_pin(config, purpose, &chain)?;
            let private = secrets
                .tls_private_key(&listener.name)
                .ok_or(DaemonError::Tls(TlsConfigError::InvalidPrivateKey))?;
            let key = PrivateKey::parse(private.expose())?;
            let profile =
                TlsEndpointProfile::for_purpose(purpose).ok_or(DaemonError::UnsupportedProfile)?;
            let client_auth = if purpose == ListenerPurpose::AdminTls {
                let ca = listener
                    .client_ca_file
                    .clone()
                    .ok_or(DaemonError::Tls(TlsConfigError::ClientAuthMismatch))?;
                ClientAuth::MutualTls(load_trust_store(ca).await?)
            } else {
                ClientAuth::None
            };
            Some(build_server_config(profile, chain, key, client_auth).await?)
        };
        let local_admin = listener
            .local_admin
            .as_ref()
            .map(|policy| {
                LocalAdminAdmission::new(policy.allowed_uids.clone(), policy.allowed_gids.clone())
            })
            .transpose()?;
        let source = match &listener.bind {
            ConfigListenerBind::Socket(address) => ListenerSource::Tcp(*address),
            ConfigListenerBind::Unix(path) => ListenerSource::Unix(path.clone()),
        };
        specs.push(ListenerSpec {
            purpose,
            source,
            max_connections: usize_value(listener.max_connections)?,
            tls,
            local_admin,
        });
    }
    Ok(specs)
}

fn validate_onion_pin(
    config: &Config,
    purpose: ListenerPurpose,
    chain: &crate::tls::CertChain,
) -> Result<(), DaemonError> {
    if purpose != ListenerPurpose::ClientOnion {
        return Ok(());
    }
    let expected = config
        .network
        .onion
        .as_ref()
        .ok_or(DaemonError::UnsupportedProfile)?
        .tls_spki_sha256;
    let leaf = chain
        .leaf()
        .ok_or(DaemonError::Tls(TlsConfigError::InvalidCertificate))?;
    if spki_sha256(leaf.as_ref()) != Some(expected) {
        return Err(DaemonError::Tls(TlsConfigError::InvalidCertificate));
    }
    Ok(())
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=top-level composition installs bounded owners before accepting and routes every exit through the phased shutdown budget
async fn run(
    config_path: PathBuf,
    config: Config,
    secrets: SecretSet,
    operators: OperatorRegistry,
    storage: LiveStorage,
) -> Result<DaemonExit, DaemonError> {
    let shutdown = shutdown_plan(&config)?;
    let specs = build_listener_specs(&config, &secrets).await?;
    let budget = memory_budget(&config)?;
    let rates = configured_rates(&config)?;
    let admission = Arc::new(TransportAdmission::new(
        rates,
        config
            .limits
            .values
            .get(LimitKey::DirectConnectionsPerAddress),
        Arc::clone(&budget),
        Box::new(SystemMonotonicClock::start()),
    )?);
    let mut live = build_live_state(&config, &secrets, storage, Arc::clone(&budget), rates)?;
    let (inbox, inbox_receiver) = mpsc::channel(SIGNAL_EVENT_CAPACITY);
    let admin_binding = AdminSessionBinding {
        network_id: config.network.network_id,
        server_id: config.server.server_id,
    };
    let (admin_port, admin_inbox) = admin_transport_channel(admin_binding);
    let (admin_core, admin_core_inbox) = admin_core_channel();
    live.state.install_admin_inbox(admin_core_inbox)?;
    let audit = live
        .audit
        .take()
        .ok_or(DaemonError::Runtime(RuntimeError::InvalidValue))?;
    let admin_owner = AdminOwner::new(
        admin_binding,
        operators,
        operator_admission(&config),
        audit,
        admin_core,
        AdminOwnerClocks {
            monotonic: Box::new(SystemMonotonicClock::start()),
            wall: Box::new(SystemWallClock),
        },
    );
    let context = listener_context(&config, &inbox, admin_port, budget, Arc::clone(&admission))?;
    let RunningOwners {
        owner,
        mut supervisor,
        control,
        lifecycle,
        mut signals,
        mut state_exited,
        mut listener_exited,
    } = start_owners(
        specs,
        context,
        live,
        inbox_receiver,
        &inbox,
        admission,
        AdminOwnerStart {
            owner: admin_owner,
            inbox: admin_inbox,
        },
    )?;
    let trigger = wait_for_shutdown(
        &config_path,
        &config,
        &mut signals,
        &mut state_exited,
        &mut listener_exited,
    )
    .await;
    let mut hooks = RuntimeShutdownHooks {
        owner: Some(owner),
        supervisor: &mut supervisor,
        listeners: &control,
        lifecycle: &lifecycle,
        listener_exited: &mut listener_exited,
        listener_joined: false,
        stopped: false,
    };
    let report = run_shutdown(shutdown, &mut hooks, &mut signals).await;
    let shutdown_result = validate_shutdown_report(report);
    trigger.and(shutdown_result)?;
    Ok(DaemonExit::Stopped)
}

struct RunningOwners {
    owner: StorageOwner,
    supervisor: Supervisor,
    control: ListenerControl,
    lifecycle: LifecycleControl,
    signals: mpsc::Receiver<SignalEvent>,
    state_exited: oneshot::Receiver<StateCoreExit>,
    listener_exited: oneshot::Receiver<()>,
}

struct AdminOwnerStart {
    owner: AdminOwner,
    inbox: AdminOwnerInbox,
}

fn start_owners(
    specs: Vec<ListenerSpec>,
    context: ListenerContext,
    live: LiveState,
    inbox_receiver: mpsc::Receiver<StateCoreMessage>,
    inbox: &mpsc::Sender<StateCoreMessage>,
    admission: Arc<TransportAdmission>,
    admin: AdminOwnerStart,
) -> Result<RunningOwners, DaemonError> {
    let mut supervisor = Supervisor::new();
    spawn_admin_owner(&mut supervisor, admin.owner, admin.inbox)?;
    let listeners = ListenerSet::start(specs, context, &supervisor.root_token())?;
    let control = listeners.control();
    let listener_exited = spawn_listener_owner(&mut supervisor, listeners)?;
    let LiveState {
        owner,
        state,
        storage,
        storage_reads,
        crypto,
        audit: _,
    } = live;
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let state_exited = spawn_state_owner(
        &mut supervisor,
        state,
        inbox_receiver,
        lifecycle_receiver,
        storage,
        storage_reads,
        crypto,
    )?;
    let signals = spawn_background_owners(&mut supervisor, inbox, admission)?;
    Ok(RunningOwners {
        owner,
        supervisor,
        control,
        lifecycle,
        signals,
        state_exited,
        listener_exited,
    })
}

fn spawn_admin_owner(
    supervisor: &mut Supervisor,
    owner: AdminOwner,
    inbox: AdminOwnerInbox,
) -> Result<(), DaemonError> {
    supervisor.spawn(
        ChildName::AdminOwner,
        ChildKind::Critical,
        |token| async move {
            owner.run(inbox, token).await;
            Ok(())
        },
    )?;
    Ok(())
}

fn spawn_listener_owner(
    supervisor: &mut Supervisor,
    listeners: ListenerSet,
) -> Result<oneshot::Receiver<()>, DaemonError> {
    let (listener_exit, listener_exited) = oneshot::channel();
    supervisor.spawn(
        ChildName::ListenerSet,
        ChildKind::Critical,
        |_token| async move {
            let _exits = listeners.join().await;
            let _sent = listener_exit.send(());
            Ok(())
        },
    )?;
    Ok(listener_exited)
}

fn spawn_state_owner(
    supervisor: &mut Supervisor,
    state: StateCore,
    inbox_receiver: mpsc::Receiver<StateCoreMessage>,
    lifecycle: mpsc::Receiver<crate::state_core::inbox::LifecycleRequest>,
    storage: mpsc::Receiver<crate::bridge::StorageCompletionMessage>,
    storage_reads: mpsc::Receiver<crate::bridge::StorageReadCompletionMessage>,
    crypto: mpsc::Receiver<
        crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
    >,
) -> Result<oneshot::Receiver<StateCoreExit>, DaemonError> {
    let (state_exit, state_exited) = oneshot::channel();
    let receivers = StateOwnerReceivers {
        inbox: inbox_receiver,
        lifecycle,
        storage,
        storage_reads,
        crypto,
    };
    supervisor.spawn(ChildName::StateCoreTask, ChildKind::Critical, |token| {
        run_state_owner(state, receivers, token, state_exit)
    })?;
    Ok(state_exited)
}

fn spawn_background_owners(
    supervisor: &mut Supervisor,
    inbox: &mpsc::Sender<StateCoreMessage>,
    admission: Arc<TransportAdmission>,
) -> Result<mpsc::Receiver<SignalEvent>, DaemonError> {
    let (signals, signal_receiver) = mpsc::channel(SIGNAL_EVENT_CAPACITY);
    supervisor.spawn(ChildName::SignalTask, ChildKind::Critical, |token| {
        run_signal_task(token, signals)
    })?;
    let maintenance_inbox = inbox.clone();
    supervisor.spawn(ChildName::MaintenanceTask, ChildKind::Critical, |token| {
        run_maintenance(token, maintenance_inbox, admission)
    })?;
    Ok(signal_receiver)
}

fn listener_context(
    config: &Config,
    inbox: &mpsc::Sender<StateCoreMessage>,
    admin: AdminTransportPort,
    budget: Arc<MemoryBudget>,
    admission: Arc<TransportAdmission>,
) -> Result<ListenerContext, DaemonError> {
    let clients = limit_usize(config, LimitKey::ClientConnections)?;
    let handshakes = limit_usize(config, LimitKey::TlsHandshakes)?;
    Ok(ListenerContext {
        budget,
        handshakes: HandshakeLimiter::new(handshakes)?,
        client_slots: Arc::new(Semaphore::new(clients)),
        admission,
        observer: Arc::new(NoObserver),
        inbox: inbox.clone(),
        admin: Some(admin),
        limits: connection_limits(config)?,
    })
}

fn operator_registry(config: &Config) -> Result<OperatorRegistry, DaemonError> {
    let mut records = Vec::with_capacity(config.moderation.operators.len());
    for operator in &config.moderation.operators {
        records.push(
            OperatorRecord::new(
                operator.operator_id,
                Ed25519PublicKey::from_bytes(operator.signing_public_key)?,
                operator.certificate_spki_sha256,
                operator.local_uids.clone(),
                operator.local_gids.clone(),
                operator.permissions,
                operator.enabled,
            )
            .map_err(|_| RuntimeError::InvalidValue)?,
        );
    }
    OperatorRegistry::from_records(records)
        .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))
}

fn operator_admission(config: &Config) -> AdminAdmissionSnapshot {
    let enabled = config
        .moderation
        .operators
        .iter()
        .filter(|operator| operator.enabled);
    let mut uids = Vec::new();
    let mut gids = Vec::new();
    let mut pins = Vec::new();
    for operator in enabled {
        uids.extend_from_slice(&operator.local_uids);
        gids.extend_from_slice(&operator.local_gids);
        if let Some(pin) = operator.certificate_spki_sha256 {
            pins.push(pin);
        }
    }
    AdminAdmissionSnapshot::new(uids, gids, pins)
}

struct StateOwnerReceivers {
    inbox: mpsc::Receiver<StateCoreMessage>,
    lifecycle: mpsc::Receiver<crate::state_core::inbox::LifecycleRequest>,
    storage: mpsc::Receiver<crate::bridge::StorageCompletionMessage>,
    storage_reads: mpsc::Receiver<crate::bridge::StorageReadCompletionMessage>,
    crypto: mpsc::Receiver<
        crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
    >,
}

async fn run_state_owner(
    mut state: StateCore,
    receivers: StateOwnerReceivers,
    token: crate::cancel::CancellationToken,
    exited: oneshot::Sender<StateCoreExit>,
) -> Result<(), RuntimeError> {
    let StateOwnerReceivers {
        inbox,
        lifecycle,
        storage,
        storage_reads,
        crypto,
    } = receivers;
    let exit = state
        .run(inbox, lifecycle, storage, storage_reads, crypto, token)
        .await;
    let (storage_bridge, crypto_bridge) = state.into_bridges();
    crypto_bridge.shutdown().await?;
    tokio::task::spawn_blocking(move || storage_bridge.shutdown())
        .await
        .map_err(|_| RuntimeError::Cancelled)??;
    let healthy = matches!(
        exit,
        StateCoreExit::Cancelled
            | StateCoreExit::Quiesced
            | StateCoreExit::Interrupted
            | StateCoreExit::Stopped
    );
    let _sent = exited.send(exit);
    if healthy {
        Ok(())
    } else {
        Err(RuntimeError::InvalidValue)
    }
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=closed owner loop admits reload or one shutdown trigger and treats premature owner exit as fatal
async fn wait_for_shutdown(
    config_path: &Path,
    active: &Config,
    signals: &mut mpsc::Receiver<SignalEvent>,
    state_exited: &mut oneshot::Receiver<StateCoreExit>,
    listener_exited: &mut oneshot::Receiver<()>,
) -> Result<(), DaemonError> {
    loop {
        let event = tokio::select! {
            biased;
            signal = signals.recv() => SupervisorEvent::Signal(signal),
            _exit = &mut *state_exited => SupervisorEvent::State,
            _listener = &mut *listener_exited => SupervisorEvent::Listener,
        };
        match event {
            SupervisorEvent::Signal(Some(SignalEvent::Reload)) => {
                let _result = validate_reload(config_path, active).await;
            }
            SupervisorEvent::Signal(Some(SignalEvent::Terminate | SignalEvent::Interrupt)) => {
                return Ok(());
            }
            SupervisorEvent::Signal(None) | SupervisorEvent::State | SupervisorEvent::Listener => {
                return Err(DaemonError::TaskFailed);
            }
        }
    }
}

enum SupervisorEvent {
    Signal(Option<SignalEvent>),
    State,
    Listener,
}

struct RuntimeShutdownHooks<'a> {
    owner: Option<StorageOwner>,
    supervisor: &'a mut Supervisor,
    listeners: &'a ListenerControl,
    lifecycle: &'a LifecycleControl,
    listener_exited: &'a mut oneshot::Receiver<()>,
    listener_joined: bool,
    stopped: bool,
}

impl ShutdownHooks for RuntimeShutdownHooks<'_> {
    async fn run(&mut self, phase: ShutdownPhase) -> Result<(), ShutdownFailure> {
        match phase {
            ShutdownPhase::Quiesce => {
                self.listeners.stop_accepting();
                self.listeners.wait_accept_stopped().await;
                request_lifecycle(self.lifecycle, LifecyclePhase::Quiesce).await
            }
            ShutdownPhase::Drain => request_lifecycle(self.lifecycle, LifecyclePhase::Drain).await,
            ShutdownPhase::Flush => {
                if !self.listener_joined {
                    (&mut *self.listener_exited)
                        .await
                        .map_err(|_| ShutdownFailure::Writer)?;
                    self.listener_joined = true;
                }
                request_lifecycle(self.lifecycle, LifecyclePhase::Flush).await
            }
            ShutdownPhase::Stop => self.stop().await,
        }
    }
}

impl RuntimeShutdownHooks<'_> {
    async fn stop(&mut self) -> Result<(), ShutdownFailure> {
        if self.stopped {
            return Ok(());
        }
        self.stopped = true;
        self.listeners.stop_accepting();
        let mut first_failure = request_lifecycle(self.lifecycle, LifecyclePhase::Stop)
            .await
            .err();
        self.listeners.cancel_connections();
        self.supervisor.cancel();
        let report = self.supervisor.join_all(crate::supervisor::MAX_TOTAL).await;
        if validate_join_report(&report).is_err() && first_failure.is_none() {
            first_failure = Some(ShutdownFailure::Join);
        }
        if let Some(owner) = self.owner.take()
            && shutdown_storage(owner).await.is_err()
            && first_failure.is_none()
        {
            first_failure = Some(ShutdownFailure::Storage);
        }
        first_failure.map_or(Ok(()), Err)
    }
}

async fn request_lifecycle(
    control: &LifecycleControl,
    phase: LifecyclePhase,
) -> Result<(), ShutdownFailure> {
    control
        .request(phase)
        .await
        .map_err(|_failure: LifecycleFailure| ShutdownFailure::StateCore)
}

fn validate_shutdown_report(report: ShutdownReport) -> Result<(), DaemonError> {
    match report.first_problem().map(|problem| problem.kind) {
        None => Ok(()),
        Some(ShutdownProblemKind::TimedOut) => Err(DaemonError::ShutdownTimeout),
        Some(ShutdownProblemKind::Failed(_)) => Err(DaemonError::TaskFailed),
    }
}

async fn validate_reload(config_path: &Path, active: &Config) -> Result<(), DaemonError> {
    let path = config_path.to_path_buf();
    let active = active.clone();
    tokio::task::spawn_blocking(move || {
        let candidate = load_config(&path, ValidationDepth::Host)?;
        validate_profile(&candidate)?;
        let _secrets = SecretSet::load(&candidate)?;
        let diff = agenc_ircd_config::ConfigDiff::compute(&active, &candidate);
        if diff.is_empty() {
            Ok(())
        } else {
            Err(DaemonError::UnsupportedProfile)
        }
    })
    .await
    .map_err(|_| DaemonError::TaskFailed)?
}

async fn run_maintenance(
    token: crate::cancel::CancellationToken,
    inbox: mpsc::Sender<StateCoreMessage>,
    admission: Arc<TransportAdmission>,
) -> Result<(), RuntimeError> {
    let mut minute = tokio::time::interval(MAINTENANCE_MINUTE);
    let mut prefixes = tokio::time::interval(PREFIX_ERASURE_INTERVAL);
    let mut retention = tokio::time::interval(RETENTION_INTERVAL);
    minute.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    prefixes.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    retention.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    minute.tick().await;
    prefixes.tick().await;
    retention.tick().await;
    loop {
        let event = tokio::select! {
            () = token.cancelled() => return Ok(()),
            _ = minute.tick() => MaintenanceEvent::ClockDriftCheck,
            _ = prefixes.tick() => {
                admission.erase_idle();
                MaintenanceEvent::PrefixErasure
            },
            _ = retention.tick() => MaintenanceEvent::RetentionSweep,
        };
        match inbox.try_send(StateCoreMessage::Maintenance(event)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
        }
    }
}

fn shutdown_plan(config: &Config) -> Result<ShutdownPlan, DaemonError> {
    let phases = config.server.shutdown;
    Ok(ShutdownPlan::new(
        Duration::from_secs(phases.quiesce_seconds),
        Duration::from_secs(phases.drain_seconds),
        Duration::from_secs(phases.flush_seconds),
        Duration::from_secs(phases.stop_seconds),
    )?)
}

fn validate_join_report(report: &JoinReport) -> Result<(), DaemonError> {
    if report.unfinished != 0 {
        return Err(DaemonError::ShutdownTimeout);
    }
    for exit in &report.exits {
        if matches!(
            exit.outcome,
            Err(ChildFailure::Failed(_) | ChildFailure::Panicked | ChildFailure::Cancelled)
        ) {
            return Err(DaemonError::TaskFailed);
        }
    }
    Ok(())
}

async fn shutdown_storage(owner: StorageOwner) -> Result<(), DaemonError> {
    tokio::task::spawn_blocking(move || owner.shutdown())
        .await
        .map_err(|_| DaemonError::TaskFailed)??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use agenc_ircd_config::RateTable;

    use super::*;

    #[test]
    fn runtime_purposes_enable_admin_but_keep_deferred_transports_closed() {
        assert_eq!(
            runtime_purpose(ConfigListenerPurpose::ClientTls).ok(),
            Some(ListenerPurpose::ClientTls)
        );
        assert_eq!(
            runtime_purpose(ConfigListenerPurpose::ClientOnion).ok(),
            Some(ListenerPurpose::ClientOnion)
        );
        assert_eq!(
            runtime_purpose(ConfigListenerPurpose::AdminLocal).ok(),
            Some(ListenerPurpose::AdminLocal)
        );
        assert_eq!(
            runtime_purpose(ConfigListenerPurpose::AdminTls).ok(),
            Some(ListenerPurpose::AdminTls)
        );
        for purpose in [
            ConfigListenerPurpose::ClientWss,
            ConfigListenerPurpose::Federation,
        ] {
            assert!(runtime_purpose(purpose).is_err());
        }
    }

    #[test]
    fn config_and_runtime_rate_defaults_match() -> Result<(), DaemonError> {
        let config_rates = RateTable::defaults();
        let mut runtime_rates = RateLimits::defaults();
        for kind in BucketKind::ALL {
            let Some(name) = kind.config_name() else {
                continue;
            };
            let row = RATE_ROWS
                .iter()
                .find(|row| row.name == name)
                .ok_or(RuntimeError::InvalidValue)?;
            let configured = config_rates.get(row.key);
            let expected = runtime_rates.rate(kind);
            assert_eq!(configured.refill_tokens, expected.refill_tokens());
            assert_eq!(configured.refill_seconds, expected.refill_seconds());
            assert_eq!(configured.burst, expected.burst());
            runtime_rates.set(kind, expected)?;
        }
        Ok(())
    }
}
