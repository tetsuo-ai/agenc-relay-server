//! Live Stage 06 daemon composition for a standalone coordinator.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use agenc_ircd_admin::{AdminSessionBinding, OperatorRecord, OperatorRegistry};
use agenc_ircd_auth::{
    AuthError, CHANNEL_KEY_HASH_BYTES as AUTH_CHANNEL_HASH_BYTES,
    CHANNEL_KEY_ITERATIONS as AUTH_CHANNEL_ITERATIONS, CHANNEL_KEY_LANES as AUTH_CHANNEL_LANES,
    CHANNEL_KEY_MEMORY_KIB as AUTH_CHANNEL_MEMORY_KIB,
    CHANNEL_KEY_SALT_BYTES as AUTH_CHANNEL_SALT_BYTES, OpaqueProfile, derive_channel_key_verifier,
};
use agenc_ircd_config::{
    Config, ConfigError, ConfigReport, DEFAULT_REDB_CACHE_BYTES, DirectMessageDefault,
    HardeningOutcome, LimitKey, ListenerBind as ConfigListenerBind,
    ListenerPurpose as ConfigListenerPurpose, NodeRole, RATE_ROWS, RegistrationPolicy, SecretSet,
    ValidationDepth, apply_process_hardening, load_audit_trust_manifest,
    load_backup_trust_manifest, load_config, load_public_text,
};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, CryptoError, CryptoWorkerConfig, Ed25519PublicKey, Ed25519SecretKey,
    LoginIndexKey, OpaqueFakeCredentialKey, OsEntropy, RollbackGuardRootKey, SemanticHashDomain,
    StorageDigest, StorageMasterKey, semantic_digest,
};
use agenc_ircd_domain::{
    DirectMessagePolicy, GuestDirectMessagePolicy, OperationalLimitValues, OperationalLimits,
    PresencePolicy,
};
use agenc_ircd_storage::{
    BackupTrustKey, CommitOutcome, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, ReadPlan,
    StateDirectory, StorageEngineLimits, StorageError, StorageLimitWriter, StorageOpenConfig,
    StorageOwner, StoragePort, StorageRuntimeLimits, StorageShutdown, StorageStatistics, TableId,
    embedded_storage_qualifications,
};
use agenc_ircd_types::{
    AccountId, ChannelInstanceId, EntropySource as _, Generation, MonotonicClock as _, OriginId,
    TransactionId, WallClock as _,
};
use tokio::runtime::Builder;
use tokio::sync::{Semaphore, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::RuntimeError;
use crate::StateCoreSeed;
use crate::account_service::AccountCreationPolicy;
use crate::admin::{
    AdminAdmissionSnapshot, AdminBackupRuntime, AdminLifecycleControl, AdminLifecycleFailure,
    AdminLifecycleInbox, AdminOwner, AdminOwnerClocks, AdminOwnerHealth, AdminOwnerInbox,
    AdminOwnerRuntime, AdminProcessAction, AdminProcessInbox, AdminTransportPort, AuditAuthority,
    admin_lifecycle_channel, admin_process_channel, admin_transport_channel,
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
    CONTROL_ITEM_SLOTS, ConnectionLimits, FlushAcknowledgement, MAX_DEMAND_FRAMES, QueueLimits,
    ReaderLimits,
};
use crate::listener::{
    ListenerContext, ListenerControl, ListenerError, ListenerSet, ListenerSource, ListenerSpec,
    LocalAdminAdmission, MAX_CLIENT_CONNECTIONS, spki_sha256,
};
use crate::observe::adapter::RuntimeObserver;
use crate::observe::events::{CorrelationSource, Severity};
use crate::observe::health::{Liveness, ReadinessGate, ReadinessStage};
use crate::observe::log::{FileLogControl, FileLogOwner, FileLogShutdown, LogFilter, LogRetention};
use crate::observe::metrics::MetricsRegistry;
use crate::purpose::ListenerPurpose;
use crate::registration::{AccountServiceConfig, RegistrationRouter, RegistrationRouterConfig};
use crate::runtime_config::{
    AccountRuntimePolicy, ConfigRevision, PreparedReload, ReloadOutcome, ReloadPort,
    ReloadPreparationInbox, ReloadPreparationReply, ReloadPrepareFailure, RestartMaterial,
    RestartMaterialKey, RuntimeConfigHandle, RuntimeConfigParts, RuntimeConfigSnapshot,
    reload_channel, reload_preparation_channel,
};
use crate::state_core::durable::{
    AccountingCeilings, AdminMutationAfterImage, KeyDeriver, project_admin_policy_backfill,
    read_back_record,
};
use crate::state_core::inbox::{
    ConnectionCloseInbox, ConnectionClosePort, LifecycleControl, LifecycleFailure, LifecyclePhase,
    MaintenanceEvent, SIGNAL_EVENT_CAPACITY, SignalEvent, StateCoreMessage,
    connection_close_channel, lifecycle_channel,
};
use crate::state_core::reconstruct::{Reconstruction, reconstruct};
use crate::state_core::{
    StateCore, StateCoreClocks, StateCoreConfig, StateCoreExit, StateCoreInputs, admin_core_channel,
};
use crate::supervisor::{
    CRASH_EXIT_CODE, ChildFailure, ChildKind, ChildName, CrashReporter, JoinReport,
    ShutdownFailure, ShutdownHooks, ShutdownPhase, ShutdownPlan, ShutdownProblemKind,
    ShutdownReport, Supervisor, exit_process, run_shutdown, run_signal_task,
};
use crate::sync::Arc;
use crate::tls::{
    ClientAuth, HandshakeLimiter, MAX_HANDSHAKES_IN_PROGRESS, PrivateKey, TlsConfigError,
    TlsEndpointProfile, TlsServerPolicy, build_server_config_with_policy,
    load_certificate_chain_material, load_trust_store_material,
};

const RUNTIME_THREAD_NAME: &str = "agenc-ircd-tokio";
const MAINTENANCE_MINUTE: Duration = Duration::from_secs(60);
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
    let hardening = harden_process(&config)?;
    let secrets = SecretSet::load(&config)?;
    let operators = operator_registry(&config)?;
    let workers = usize_value(config.server.tokio_worker_threads)?;
    let runtime = Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name(RUNTIME_THREAD_NAME)
        .enable_all()
        .build()
        .map_err(|_| DaemonError::RuntimeStart)?;
    let process_clock = SystemMonotonicClock::start();
    let correlation = Arc::new(CorrelationSource::from_os_entropy()?);
    CrashReporter::new(
        config.server.server_id,
        Arc::clone(&correlation),
        Arc::new(SystemWallClock),
        |code| exit_process(code),
    )
    .ok_or(DaemonError::Runtime(RuntimeError::InvalidValue))?
    .install();
    let retention = LogRetention::hours(config.privacy.log_retention_hours)?;
    let (log_owner, log) = FileLogOwner::start(
        &config.server.data_dir,
        retention,
        LogFilter::new(Severity::Info),
        config.server.server_id,
        Arc::clone(&correlation),
    )
    .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))?;
    let observer = Arc::new(RuntimeObserver::new(
        config.server.server_id,
        process_clock,
        correlation,
        log,
        Arc::new(MetricsRegistry::new()),
    ));
    observer.process_started();
    if !hardening.secrets_locked {
        observer.hardening_warning();
    }
    let storage = LiveStorage::open(&config, &secrets, &operators)?;
    observer.storage_recovered();
    let result = runtime.block_on(run(DaemonRunInputs {
        config_path: config_path.to_path_buf(),
        config,
        secrets,
        operators,
        storage,
        process_clock,
        observer,
        log_owner,
    }));
    runtime.shutdown_timeout(Duration::ZERO);
    result
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

fn harden_process(config: &Config) -> Result<HardeningOutcome, DaemonError> {
    let outcome = apply_process_hardening(config.server.require_locked_secrets)?;
    if !outcome.dumpable_disabled || !outcome.core_limit_zero {
        return Err(DaemonError::HostControl(ConfigError::HostControl));
    }
    Ok(outcome)
}

struct LiveStorage {
    owner: StorageOwner,
    limit_writer: StorageLimitWriter,
    seed: StateCoreSeed,
    keys: KeyDeriver,
    reconstruction: Reconstruction,
    audit: AuditAuthority,
    backup_trust: Vec<BackupTrustKey>,
}

impl LiveStorage {
    fn open(
        config: &Config,
        secrets: &SecretSet,
        operators: &OperatorRegistry,
    ) -> Result<Self, DaemonError> {
        let qualifications = embedded_storage_qualifications()?;
        let state_directory = StateDirectory::open(&config.storage.state_dir, &qualifications)?;
        let mut owner = StorageOwner::start(storage_open_config(config, secrets, state_directory))?;
        let limit_writer = owner.take_limit_writer()?;
        let seed = StateCoreSeed::from_storage(&owner)?;
        let storage = seed.storage();
        let keys = KeyDeriver::new(
            StorageMasterKey::from_bytes(*secrets.storage_master().expose()),
            storage.database_binding(),
            storage.storage_key_generation(),
        )?;
        let reconstruction = reconstruct(&seed, &owner.port(), &keys)?;
        let trust = load_audit_trust_manifest(&config.moderation.audit_trust_manifest_file)?;
        let audit_keys = KeyDeriver::new(
            StorageMasterKey::from_bytes(*secrets.storage_master().expose()),
            storage.database_binding(),
            storage.storage_key_generation(),
        )?;
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
            owner.port(),
            audit_keys,
            operators,
            now,
        )?;
        let backup_trust = backup_trust_keys(load_backup_trust_manifest(
            &config.storage.backup_trust_manifest_file,
        )?)?;
        Ok(Self {
            owner,
            limit_writer,
            seed,
            keys,
            reconstruction,
            audit,
            backup_trust,
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
    checkpoints: mpsc::Receiver<crate::bridge::StorageCheckpointCompletionMessage>,
    crypto: mpsc::Receiver<
        crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
    >,
    audit: Option<AuditAuthority>,
    backup: Option<AdminBackupRuntime>,
}

struct BuildLiveStateInputs<'a> {
    config: &'a Config,
    secrets: &'a SecretSet,
    runtime_config: &'a RuntimeConfigSnapshot,
    storage: LiveStorage,
    budget: Arc<MemoryBudget>,
    rates: RateLimits,
    monotonic: SystemMonotonicClock,
    liveness: Arc<Liveness>,
}

struct BuildLiveStateFailure {
    error: DaemonError,
    storage: LiveStorage,
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=single startup composition consumes one validated input bundle and constructs the exact storage crypto router and StateCore ownership graph
fn build_live_state(
    inputs: BuildLiveStateInputs<'_>,
) -> Result<LiveState, Box<BuildLiveStateFailure>> {
    let BuildLiveStateInputs {
        config,
        secrets,
        runtime_config,
        mut storage,
        budget,
        rates,
        monotonic,
        liveness,
    } = inputs;
    let prepared = (|| -> Result<_, DaemonError> {
        let (suspensions, quarantined_channels) = storage.audit.policy_seed().into_parts();
        let backfills = missing_admin_policy_backfills(
            &storage.reconstruction.domain,
            &suspensions,
            &quarantined_channels,
        )?;
        storage
            .reconstruction
            .domain
            .install_admin_policy(suspensions, quarantined_channels)
            .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))?;
        persist_admin_policy_backfills(
            &storage.owner.port(),
            &mut storage.reconstruction,
            &storage.keys,
            AccountingCeilings {
                database_max_bytes: config.storage.database_max_bytes,
                backup_max_bytes: config.storage.backup_max_bytes,
            },
            backfills,
        )?;
        let crypto_config = CryptoWorkerConfig::new(
            limit_usize(config, LimitKey::ChannelKeyJobs)?,
            limit_usize(config, LimitKey::OpaqueJobs)?,
            usize_value(config.server.crypto_worker_threads)?,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let commands = registered_commands()?;
        let router = RegistrationRouter::new(
            registration_config(
                config,
                secrets,
                runtime_config,
                &storage.seed,
                &storage.reconstruction,
            )?,
            commands,
        )?;
        let limits = operational_limits(config)?;
        Ok((crypto_config, router, limits))
    })();
    let (crypto_config, router, limits) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return Err(Box::new(BuildLiveStateFailure { error, storage })),
    };
    storage.reconstruction.domain.set_operational_limits(limits);
    let (bridge, completions, storage_reads, checkpoints) =
        match StorageBridge::start(storage.owner.port()) {
            Ok(bridge) => bridge,
            Err(error) => {
                return Err(Box::new(BuildLiveStateFailure {
                    error: error.into(),
                    storage,
                }));
            }
        };
    let (crypto_bridge, crypto) = match CryptoBridge::start(crypto_config) {
        Ok(bridge) => bridge,
        Err(error) => {
            let _closed = bridge.shutdown();
            return Err(Box::new(BuildLiveStateFailure {
                error: error.into(),
                storage,
            }));
        }
    };
    let LiveStorage {
        owner,
        limit_writer,
        seed: _,
        keys,
        reconstruction,
        audit,
        backup_trust,
    } = storage;
    let backup = AdminBackupRuntime::new(
        owner.port(),
        config.storage.backup_dir.clone(),
        *secrets.backup_signing().expose(),
        *secrets.storage_master().expose(),
        *secrets.rollback_guard_root().expose(),
        backup_trust,
        config.storage.backup_max_bytes,
    );
    let state = StateCore::new(StateCoreInputs {
        config: StateCoreConfig {
            server_prefix: config.server.name.as_str().to_owned(),
            rate_limits: rates,
            ceilings: AccountingCeilings {
                database_max_bytes: config.storage.database_max_bytes,
                backup_max_bytes: config.storage.backup_max_bytes,
            },
            motd: runtime_config.motd_arc(),
            public_info: runtime_config.public_info_arc(),
        },
        reconstruction,
        keys,
        bridge,
        crypto: crypto_bridge,
        budget,
        liveness,
        clocks: StateCoreClocks {
            monotonic: Box::new(monotonic),
            wall: Box::new(SystemWallClock),
        },
        entropy: Box::new(OsEntropy),
        router: Box::new(router),
        storage_limit_writer: limit_writer,
    });
    Ok(LiveState {
        owner,
        state,
        storage: completions,
        storage_reads,
        checkpoints,
        crypto,
        audit: Some(audit),
        backup: Some(backup),
    })
}

enum AdminPolicyBackfill {
    Account(AccountId),
    Channel(ChannelInstanceId),
}

fn missing_admin_policy_backfills(
    domain: &agenc_ircd_domain::DomainState,
    suspensions: &[(AccountId, agenc_ircd_types::UtcSecond)],
    quarantined_channels: &[ChannelInstanceId],
) -> Result<Vec<AdminPolicyBackfill>, DaemonError> {
    let capacity = suspensions
        .len()
        .checked_add(quarantined_channels.len())
        .ok_or(RuntimeError::Overflow)?;
    let mut backfills = Vec::new();
    backfills
        .try_reserve_exact(capacity)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for (account_id, expires_at) in suspensions {
        if domain
            .durable_account(*account_id)
            .is_some_and(|account| account.admin_suspension_expires_at != Some(*expires_at))
        {
            backfills.push(AdminPolicyBackfill::Account(*account_id));
        }
    }
    for channel_id in quarantined_channels {
        if domain
            .durable_channel(*channel_id)
            .is_some_and(|channel| !channel.admin_quarantined)
        {
            backfills.push(AdminPolicyBackfill::Channel(*channel_id));
        }
    }
    Ok(backfills)
}

fn persist_admin_policy_backfills(
    storage: &StoragePort,
    reconstruction: &mut Reconstruction,
    keys: &KeyDeriver,
    ceilings: AccountingCeilings,
    backfills: Vec<AdminPolicyBackfill>,
) -> Result<(), DaemonError> {
    for backfill in backfills {
        let after_image = match backfill {
            AdminPolicyBackfill::Account(account_id) => AdminMutationAfterImage::Account(
                reconstruction
                    .domain
                    .durable_account(account_id)
                    .ok_or(RuntimeError::InvalidValue)?,
            ),
            AdminPolicyBackfill::Channel(channel_id) => AdminMutationAfterImage::Channel(
                reconstruction
                    .domain
                    .durable_channel(channel_id)
                    .ok_or(RuntimeError::InvalidValue)?,
            ),
        };
        commit_admin_policy_backfill(storage, reconstruction, keys, ceilings, &after_image)?;
    }
    Ok(())
}

fn commit_admin_policy_backfill(
    storage: &StoragePort,
    reconstruction: &mut Reconstruction,
    keys: &KeyDeriver,
    ceilings: AccountingCeilings,
    after_image: &AdminMutationAfterImage,
) -> Result<(), DaemonError> {
    let (table, key) = match after_image {
        AdminMutationAfterImage::Account(account) => (
            TableId::Account,
            KeyDeriver::account_key(account.account_id)?,
        ),
        AdminMutationAfterImage::Channel(channel) => (
            TableId::Channel,
            KeyDeriver::channel_key(channel.channel_id)?,
        ),
    };
    let transaction_id = startup_transaction_id()?;
    let projected = project_admin_policy_backfill(
        transaction_id,
        after_image,
        &reconstruction.index,
        keys,
        reconstruction.head,
        ceilings,
    )?;
    let (batch, retained) = projected.into_parts();
    let receipt = match storage.try_commit(batch)?.wait()? {
        CommitOutcome::Committed(receipt) if receipt.transaction_id == transaction_id => receipt,
        CommitOutcome::Committed(_) | CommitOutcome::Indeterminate => {
            return Err(DaemonError::Runtime(RuntimeError::Storage(
                StorageError::Unavailable,
            )));
        }
        CommitOutcome::Rejected(error) => return Err(DaemonError::Storage(error)),
    };
    reconstruction.head = retained.advance(&receipt);
    reconstruction.index.apply(retained.updates());
    let result = storage
        .try_read(ReadPlan::exact(table, key.clone()))?
        .wait()?;
    if result.storage_commit_sequence != receipt.storage_commit_sequence {
        return Err(DaemonError::Runtime(RuntimeError::Storage(
            StorageError::StaleState,
        )));
    }
    reconstruction
        .index
        .refresh(vec![read_back_record(table, key, result)?])?;
    Ok(())
}

fn startup_transaction_id() -> Result<TransactionId, DaemonError> {
    let mut bytes = [0_u8; 16];
    OsEntropy
        .fill_exact(&mut bytes)
        .map_err(|_| RuntimeError::Storage(StorageError::Unavailable))?;
    Ok(TransactionId::from_bytes(bytes))
}

fn registration_config(
    config: &Config,
    secrets: &SecretSet,
    runtime_config: &RuntimeConfigSnapshot,
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
        display_name: runtime_config.display_name().to_string(),
        allow_guests: runtime_config.account_policy().allow_guests,
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

struct PreparedListenerSpecs {
    specs: Vec<ListenerSpec>,
    tls_endpoints: BTreeMap<agenc_ircd_config::ListenerName, Arc<rustls::ServerConfig>>,
    certificate_fingerprints: BTreeMap<agenc_ircd_config::ListenerName, [u8; 32]>,
    client_ca_fingerprints: BTreeMap<agenc_ircd_config::ListenerName, [u8; 32]>,
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=one closed listener preparation pass validates every enabled and disabled TLS identity CA and admission profile before activation
async fn build_listener_specs(
    config: &Config,
    secrets: &SecretSet,
) -> Result<PreparedListenerSpecs, DaemonError> {
    let mut specs = Vec::new();
    let mut tls_endpoints = BTreeMap::new();
    let mut certificate_fingerprints = BTreeMap::new();
    let mut client_ca_fingerprints = BTreeMap::new();
    for listener in config.listeners.iter().filter(|listener| listener.enabled) {
        let purpose = runtime_purpose(listener.purpose)?;
        let tls = if purpose == ListenerPurpose::AdminLocal {
            None
        } else {
            let files = listener
                .tls
                .as_ref()
                .ok_or(DaemonError::Tls(TlsConfigError::ClientAuthMismatch))?;
            let (chain, certificate_fingerprint) =
                load_certificate_chain_material(files.certificate_file.clone()).await?;
            validate_onion_pin(config, purpose, &chain)?;
            let private = secrets
                .tls_private_key(&listener.name)
                .ok_or(DaemonError::Tls(TlsConfigError::InvalidPrivateKey))?;
            let key = PrivateKey::parse(private.expose())?;
            let profile =
                TlsEndpointProfile::for_purpose(purpose).ok_or(DaemonError::UnsupportedProfile)?;
            let client_auth = if matches!(
                purpose,
                ListenerPurpose::AdminTls | ListenerPurpose::Federation
            ) {
                let ca = listener
                    .client_ca_file
                    .clone()
                    .ok_or(DaemonError::Tls(TlsConfigError::ClientAuthMismatch))?;
                let (store, fingerprint) = load_trust_store_material(ca).await?;
                if client_ca_fingerprints
                    .insert(listener.name.clone(), fingerprint)
                    .is_some()
                {
                    return Err(DaemonError::Runtime(RuntimeError::InvalidValue));
                }
                ClientAuth::MutualTls(store)
            } else {
                ClientAuth::None
            };
            let policy = TlsServerPolicy::new(
                config.tls.group_policy,
                config.tls.session_tickets,
                config.tls.require_ocsp_staple && purpose == ListenerPurpose::ClientTls,
            );
            let endpoint =
                build_server_config_with_policy(profile, chain, key, client_auth, policy, None)
                    .await?;
            if tls_endpoints
                .insert(listener.name.clone(), Arc::clone(&endpoint))
                .is_some()
                || certificate_fingerprints
                    .insert(listener.name.clone(), certificate_fingerprint)
                    .is_some()
            {
                return Err(DaemonError::Runtime(RuntimeError::InvalidValue));
            }
            Some(endpoint)
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
            name: listener.name.clone(),
            purpose,
            source,
            max_connections: usize_value(listener.max_connections)?,
            tls,
            local_admin,
        });
    }
    for listener in config.listeners.iter().filter(|listener| !listener.enabled) {
        if let Some(tls) = &listener.tls {
            let (chain, fingerprint) =
                load_certificate_chain_material(tls.certificate_file.clone()).await?;
            let private = secrets
                .tls_private_key(&listener.name)
                .ok_or(DaemonError::Tls(TlsConfigError::InvalidPrivateKey))?;
            let key = PrivateKey::parse(private.expose())?;
            let validation_policy = TlsServerPolicy::new(config.tls.group_policy, false, false);
            let _validated_identity = build_server_config_with_policy(
                TlsEndpointProfile::Client,
                chain,
                key,
                ClientAuth::None,
                validation_policy,
                None,
            )
            .await?;
            if certificate_fingerprints
                .insert(listener.name.clone(), fingerprint)
                .is_some()
            {
                return Err(DaemonError::Runtime(RuntimeError::InvalidValue));
            }
        }
    }
    for listener in &config.listeners {
        if let Some(path) = listener.client_ca_file.clone()
            && !client_ca_fingerprints.contains_key(&listener.name)
        {
            let (_store, fingerprint) = load_trust_store_material(path).await?;
            if client_ca_fingerprints
                .insert(listener.name.clone(), fingerprint)
                .is_some()
            {
                return Err(DaemonError::Runtime(RuntimeError::InvalidValue));
            }
        }
    }
    Ok(PreparedListenerSpecs {
        specs,
        tls_endpoints,
        certificate_fingerprints,
        client_ca_fingerprints,
    })
}

struct PreparedRuntimeFiles {
    motd: Option<Arc<str>>,
    public_info: Option<Arc<str>>,
    backup_trust: [u8; 32],
    audit_trust: [u8; 32],
}

async fn prepare_runtime_parts(
    config: &Config,
    secrets: &SecretSet,
    operators: OperatorRegistry,
) -> Result<(RuntimeConfigParts, Vec<ListenerSpec>), DaemonError> {
    let operator_admission = operator_admission(config);
    let (default_presence, default_guest_direct_messages, default_direct_messages) =
        account_defaults(config);
    let prepared = build_listener_specs(config, secrets).await?;
    let files = load_runtime_files(config).await?;
    let federation_ca = match config.federation.private_ca_file.clone() {
        Some(path) => Some(load_trust_store_material(path).await?.1),
        None => None,
    };
    let restart_material = restart_material(
        config,
        secrets,
        files.backup_trust,
        files.audit_trust,
        federation_ca,
        &prepared.client_ca_fingerprints,
    )?;
    let parts = RuntimeConfigParts {
        tls_endpoints: prepared.tls_endpoints,
        certificate_fingerprints: prepared.certificate_fingerprints,
        restart_material,
        motd: files.motd,
        public_info: files.public_info,
        display_name: Arc::from(config.network.display_name.as_str()),
        operators,
        operator_admission,
        account_policy: AccountRuntimePolicy {
            allow_guests: config.accounts.allow_guests,
            creation: creation_policy(config, secrets)?,
            default_presence,
            default_guest_direct_messages,
            default_direct_messages,
        },
        rates: configured_rates(config)?,
        operational_limits: operational_limits(config)?,
        connection_limits: connection_limits(config)?,
        storage_limits: StorageRuntimeLimits::new(
            config.storage.database_max_bytes,
            config.storage.backup_max_bytes,
            config.storage.integrity_checkpoint_manifests,
        )?,
        shutdown: shutdown_plan(config)?,
    };
    Ok((parts, prepared.specs))
}

async fn load_runtime_files(config: &Config) -> Result<PreparedRuntimeFiles, DaemonError> {
    let motd_path = config.privacy.motd_file.clone();
    let public_info_path = config.privacy.public_info_file.clone();
    let backup_path = config.storage.backup_trust_manifest_file.clone();
    let audit_path = config.moderation.audit_trust_manifest_file.clone();
    tokio::task::spawn_blocking(move || {
        let motd = motd_path
            .as_deref()
            .map(load_public_text)
            .transpose()?
            .map(Arc::<str>::from);
        let public_info = public_info_path
            .as_deref()
            .map(load_public_text)
            .transpose()?
            .map(Arc::<str>::from);
        let backup = load_backup_trust_manifest(&backup_path)?;
        let audit = load_audit_trust_manifest(&audit_path)?;
        Ok::<_, DaemonError>(PreparedRuntimeFiles {
            motd,
            public_info,
            backup_trust: backup_trust_fingerprint(&backup)?,
            audit_trust: audit_trust_fingerprint(&audit)?,
        })
    })
    .await
    .map_err(|_| DaemonError::TaskFailed)?
}

fn backup_trust_fingerprint(
    entries: &[agenc_ircd_config::BackupTrustManifestEntry],
) -> Result<[u8; 32], DaemonError> {
    trust_fingerprint(entries.iter().map(|entry| {
        (
            entry.key_id,
            entry.ed25519_public_key,
            entry.not_before,
            entry.not_after,
        )
    }))
}

fn audit_trust_fingerprint(
    entries: &[agenc_ircd_config::AuditTrustManifestEntry],
) -> Result<[u8; 32], DaemonError> {
    trust_fingerprint(entries.iter().map(|entry| {
        (
            entry.key_id,
            entry.ed25519_public_key,
            entry.not_before,
            entry.not_after,
        )
    }))
}

fn backup_trust_keys(
    entries: Vec<agenc_ircd_config::BackupTrustManifestEntry>,
) -> Result<Vec<BackupTrustKey>, DaemonError> {
    let mut trusted = Vec::new();
    trusted
        .try_reserve_exact(entries.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for entry in entries {
        trusted.push(BackupTrustKey::with_validity(
            StorageDigest::from_bytes(entry.key_id),
            Ed25519PublicKey::from_bytes(entry.ed25519_public_key)?,
            entry.not_before,
            entry.not_after,
        )?);
    }
    Ok(trusted)
}

fn trust_fingerprint(
    entries: impl ExactSizeIterator<Item = ([u8; 32], [u8; 32], u64, u64)>,
) -> Result<[u8; 32], DaemonError> {
    const ROW_BYTES: usize = 80;
    let capacity = entries
        .len()
        .checked_mul(ROW_BYTES)
        .ok_or(RuntimeError::Overflow)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for (key_id, public_key, not_before, not_after) in entries {
        encoded.extend_from_slice(&key_id);
        encoded.extend_from_slice(&public_key);
        encoded.extend_from_slice(&not_before.to_be_bytes());
        encoded.extend_from_slice(&not_after.to_be_bytes());
    }
    material_fingerprint(&encoded)
}

fn material_fingerprint(bytes: &[u8]) -> Result<[u8; 32], DaemonError> {
    Ok(*semantic_digest(SemanticHashDomain::PolicyId, bytes)?.as_bytes())
}

fn insert_material(
    material: &mut RestartMaterial,
    key: RestartMaterialKey,
    bytes: &[u8],
) -> Result<(), DaemonError> {
    material
        .insert(key, material_fingerprint(bytes)?)
        .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))
}

fn insert_optional_material(
    material: &mut RestartMaterial,
    key: RestartMaterialKey,
    bytes: Option<&[u8]>,
) -> Result<(), DaemonError> {
    if let Some(bytes) = bytes {
        insert_material(material, key, bytes)?;
    }
    Ok(())
}

fn restart_material(
    config: &Config,
    secrets: &SecretSet,
    backup_trust: [u8; 32],
    audit_trust: [u8; 32],
    federation_ca: Option<[u8; 32]>,
    client_ca: &BTreeMap<agenc_ircd_config::ListenerName, [u8; 32]>,
) -> Result<RestartMaterial, DaemonError> {
    let mut material = RestartMaterial::default();
    insert_material(
        &mut material,
        RestartMaterialKey::StorageMaster,
        secrets.storage_master().expose(),
    )?;
    insert_material(
        &mut material,
        RestartMaterialKey::RollbackGuard,
        secrets.rollback_guard_root().expose(),
    )?;
    insert_material(
        &mut material,
        RestartMaterialKey::LoginIndex,
        secrets.login_index().expose(),
    )?;
    if let Some(secret) = secrets.login_index_previous() {
        insert_material(
            &mut material,
            RestartMaterialKey::LoginIndexPrevious,
            secret.expose(),
        )?;
    }
    insert_material(
        &mut material,
        RestartMaterialKey::BackupSigning,
        secrets.backup_signing().expose(),
    )?;
    material
        .insert(RestartMaterialKey::BackupTrust, backup_trust)
        .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))?;
    insert_material(
        &mut material,
        RestartMaterialKey::AuditSigning,
        secrets.audit_signing().expose(),
    )?;
    material
        .insert(RestartMaterialKey::AuditTrust, audit_trust)
        .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))?;
    if let Some(secret) = secrets.federation_signing() {
        insert_material(
            &mut material,
            RestartMaterialKey::FederationSigning,
            secret.expose(),
        )?;
    }
    if let Some(fingerprint) = federation_ca {
        material
            .insert(RestartMaterialKey::FederationCa, fingerprint)
            .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))?;
    }
    if let Some(secret) = secrets.access_token() {
        insert_material(
            &mut material,
            RestartMaterialKey::AccessToken,
            secret.expose(),
        )?;
    }
    if let Some(secret) = secrets.invitation_verification() {
        insert_material(
            &mut material,
            RestartMaterialKey::InvitationVerification,
            secret.expose(),
        )?;
    }
    if let Some(secret) = secrets.account_service_hpke_private() {
        insert_material(
            &mut material,
            RestartMaterialKey::AccountHpkePrivate,
            secret.expose(),
        )?;
    }
    insert_optional_material(
        &mut material,
        RestartMaterialKey::OpaqueServerSetup,
        secrets
            .opaque_server_setup()
            .map(agenc_ircd_config::SecretBlob::expose),
    )?;
    if let Some(secret) = secrets.opaque_fake_credential() {
        insert_material(
            &mut material,
            RestartMaterialKey::OpaqueFakeCredential,
            secret.expose(),
        )?;
    }
    if let Some(secret) = secrets.sequencer_private() {
        insert_material(
            &mut material,
            RestartMaterialKey::SequencerPrivate,
            secret.expose(),
        )?;
    }
    for listener in &config.listeners {
        if listener.tls.is_some() {
            let private = secrets
                .tls_private_key(&listener.name)
                .ok_or(DaemonError::Tls(TlsConfigError::InvalidPrivateKey))?;
            insert_material(
                &mut material,
                RestartMaterialKey::TlsPrivate(listener.name.clone()),
                private.expose(),
            )?;
        }
    }
    for (listener, fingerprint) in client_ca {
        material
            .insert(RestartMaterialKey::ClientCa(listener.clone()), *fingerprint)
            .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))?;
    }
    Ok(material)
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

struct DaemonRunInputs {
    config_path: PathBuf,
    config: Config,
    secrets: SecretSet,
    operators: OperatorRegistry,
    storage: LiveStorage,
    process_clock: SystemMonotonicClock,
    observer: Arc<RuntimeObserver>,
    log_owner: FileLogOwner,
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=top-level composition installs bounded owners before accepting and routes every exit through the phased shutdown budget
async fn run(inputs: DaemonRunInputs) -> Result<DaemonExit, DaemonError> {
    let DaemonRunInputs {
        config_path,
        config,
        secrets,
        operators,
        storage,
        process_clock,
        observer,
        log_owner,
    } = inputs;
    let startup_deadline = tokio::time::Instant::now() + crate::supervisor::MAX_TOTAL;
    let readiness = Arc::new(ReadinessGate::new());
    readiness.mark(ReadinessStage::Configuration);
    readiness.mark(ReadinessStage::Keys);
    readiness.mark(ReadinessStage::StorageRecovered);
    let liveness = Arc::new(Liveness::new());
    let (parts, specs) = match prepare_runtime_parts(&config, &secrets, operators.clone()).await {
        Ok(prepared) => prepared,
        Err(error) => {
            return Err(
                unwind_live_storage_and_log(storage, log_owner, startup_deadline, error).await,
            );
        }
    };
    let snapshot = Arc::new(RuntimeConfigSnapshot::from_parts(
        ConfigRevision::INITIAL,
        config.clone(),
        parts,
    ));
    let runtime_config = RuntimeConfigHandle::new(Arc::clone(&snapshot));
    let budget = match memory_budget(&config) {
        Ok(budget) => budget,
        Err(error) => {
            return Err(
                unwind_live_storage_and_log(storage, log_owner, startup_deadline, error).await,
            );
        }
    };
    let rates = snapshot.rates();
    let admission = match TransportAdmission::new(
        rates,
        config
            .limits
            .values
            .get(LimitKey::DirectConnectionsPerAddress),
        Arc::clone(&budget),
        Box::new(process_clock),
    ) {
        Ok(admission) => Arc::new(admission),
        Err(error) => {
            return Err(unwind_live_storage_and_log(
                storage,
                log_owner,
                startup_deadline,
                error.into(),
            )
            .await);
        }
    };
    admission.install_observer(Arc::clone(&observer));
    let mut live = match build_live_state(BuildLiveStateInputs {
        config: &config,
        secrets: &secrets,
        runtime_config: snapshot.as_ref(),
        storage,
        budget: Arc::clone(&budget),
        rates,
        monotonic: process_clock,
        liveness: Arc::clone(&liveness),
    }) {
        Ok(live) => live,
        Err(failure) => {
            return Err(unwind_live_storage_and_log(
                failure.storage,
                log_owner,
                startup_deadline,
                failure.error,
            )
            .await);
        }
    };
    let (inbox, inbox_receiver) = mpsc::channel(SIGNAL_EVENT_CAPACITY);
    let (connection_closes, connection_close_inbox) = connection_close_channel();
    let admin_binding = AdminSessionBinding {
        network_id: config.network.network_id,
        server_id: config.server.server_id,
    };
    let (admin_port, admin_inbox) = admin_transport_channel(admin_binding);
    let (admin_core, admin_core_inbox) = admin_core_channel();
    if let Err(error) = live.state.install_admin_inbox(admin_core_inbox) {
        return Err(
            unwind_live_state_and_log(live, log_owner, startup_deadline, error.into()).await,
        );
    }
    live.state.install_observer(Arc::clone(&observer));
    let (reload, reload_inbox) = reload_channel(runtime_config.clone(), Arc::clone(&admission));
    if let Err(error) = live.state.install_reload_inbox(reload_inbox) {
        return Err(
            unwind_live_state_and_log(live, log_owner, startup_deadline, error.into()).await,
        );
    }
    let (admin_reload, mut reload_preparation) = reload_preparation_channel(reload.clone());
    let (admin_fatal, mut admin_failed) = mpsc::channel(1);
    let (admin_process, mut admin_process_inbox) = admin_process_channel();
    let reload_storage = live.owner.port();
    let context = match listener_context(
        &config,
        runtime_config.clone(),
        &inbox,
        connection_closes,
        admin_port,
        Arc::clone(&budget),
        Arc::clone(&admission),
        Arc::clone(&observer),
    ) {
        Ok(context) => context,
        Err(error) => {
            return Err(unwind_live_state_and_log(live, log_owner, startup_deadline, error).await);
        }
    };
    let Some(audit) = live.audit.take() else {
        return Err(unwind_live_state_and_log(
            live,
            log_owner,
            startup_deadline,
            DaemonError::Runtime(RuntimeError::InvalidValue),
        )
        .await);
    };
    let Some(backup) = live.backup.take() else {
        drop(audit);
        return Err(unwind_live_state_and_log(
            live,
            log_owner,
            startup_deadline,
            DaemonError::Runtime(RuntimeError::InvalidValue),
        )
        .await);
    };
    let mut admin_owner = AdminOwner::new(
        admin_binding,
        operators,
        operator_admission(&config),
        audit,
        admin_core,
        AdminOwnerRuntime {
            health: AdminOwnerHealth {
                readiness: Arc::clone(&readiness),
                liveness: Arc::clone(&liveness),
            },
            config: Some(runtime_config.clone()),
            reload: Some(admin_reload),
            backup: Some(backup),
            process: Some(admin_process),
            fatal: Some(admin_fatal),
            observer: Some(Arc::clone(&observer)),
            budget: Arc::clone(&budget),
            entropy: Box::new(OsEntropy),
            clocks: AdminOwnerClocks {
                monotonic: Box::new(process_clock),
                wall: Box::new(SystemWallClock),
            },
        },
    );
    if let Err(error) = admin_owner.install_statistics_storage(live.owner.port()) {
        drop(admin_owner);
        return Err(
            unwind_live_state_and_log(live, log_owner, startup_deadline, error.into()).await,
        );
    }
    let RunningOwners {
        owner,
        log_owner,
        mut supervisor,
        control,
        lifecycle,
        admin_lifecycle,
        mut signals,
        mut state_exited,
        mut listener_exited,
    } = Box::pin(start_owners(StartOwnersInputs {
        specs,
        context,
        live,
        log_owner,
        startup_deadline,
        inbox_receiver,
        connection_close_inbox,
        inbox: inbox.clone(),
        admission,
        admin: AdminOwnerStart {
            owner: admin_owner,
            inbox: admin_inbox,
        },
        readiness: Arc::clone(&readiness),
        liveness: Arc::clone(&liveness),
    }))
    .await?;
    observer.state_core_ready();
    let trigger = wait_for_shutdown(ShutdownWaitInputs {
        config_path: &config_path,
        runtime_config: &runtime_config,
        reload: &reload,
        reload_preparation: &mut reload_preparation,
        admin_failed: &mut admin_failed,
        admin_process: &mut admin_process_inbox,
        budget: Arc::clone(&budget),
        storage: &reload_storage,
        signals: &mut signals,
        state_exited: &mut state_exited,
        listener_exited: &mut listener_exited,
        liveness: Arc::clone(&liveness),
        monotonic: process_clock,
        observer: Arc::clone(&observer),
    })
    .await;
    let shutdown = runtime_config.load().shutdown_plan();
    let log_control = log_owner.control();
    let log_shutdown = log_owner.into_shutdown();
    let mut hooks = RuntimeShutdownHooks {
        storage_shutdown: owner.into_shutdown(),
        supervisor: &mut supervisor,
        listeners: &control,
        lifecycle: &lifecycle,
        admin: &admin_lifecycle,
        admin_acknowledgements: Vec::new(),
        listener_exited: &mut listener_exited,
        listener_joined: false,
        readiness,
        observer,
        log_control,
        log_shutdown,
        stop_failure: None,
    };
    let report = run_shutdown(shutdown, &mut hooks, &mut signals).await;
    let shutdown_result = validate_shutdown_report(report);
    finish_daemon_run(trigger, shutdown_result)
}

fn finish_daemon_run(
    trigger: Result<ShutdownTrigger, DaemonError>,
    shutdown: Result<(), DaemonError>,
) -> Result<DaemonExit, DaemonError> {
    match trigger {
        Ok(ShutdownTrigger::CommittedDie) => Ok(DaemonExit::Stopped),
        Ok(ShutdownTrigger::CommittedRestart) => Ok(DaemonExit::RestartRequested),
        Ok(ShutdownTrigger::Signal) => shutdown.map(|()| DaemonExit::Stopped),
        Err(error) => Err(error),
    }
}

struct RunningOwners {
    owner: StorageOwner,
    log_owner: FileLogOwner,
    supervisor: Supervisor,
    control: ListenerControl,
    lifecycle: LifecycleControl,
    admin_lifecycle: AdminLifecycleControl,
    signals: mpsc::Receiver<SignalEvent>,
    state_exited: oneshot::Receiver<StateCoreExit>,
    listener_exited: oneshot::Receiver<()>,
}

struct AdminOwnerStart {
    owner: AdminOwner,
    inbox: AdminOwnerInbox,
}

struct StartOwnersInputs {
    specs: Vec<ListenerSpec>,
    context: ListenerContext,
    live: LiveState,
    log_owner: FileLogOwner,
    startup_deadline: tokio::time::Instant,
    inbox_receiver: mpsc::Receiver<StateCoreMessage>,
    connection_close_inbox: ConnectionCloseInbox,
    inbox: mpsc::Sender<StateCoreMessage>,
    admission: Arc<TransportAdmission>,
    admin: AdminOwnerStart,
    readiness: Arc<ReadinessGate>,
    liveness: Arc<Liveness>,
}

// agenc-review: focus owner=runtime reviewed=2026-08-31 reason=single startup barrier constructs every bounded owner before listener admission and unwinds storage on acknowledgement failure
async fn start_owners(inputs: StartOwnersInputs) -> Result<RunningOwners, DaemonError> {
    let StartOwnersInputs {
        specs,
        context,
        live,
        log_owner,
        startup_deadline,
        inbox_receiver,
        connection_close_inbox,
        inbox,
        admission,
        admin,
        readiness,
        liveness,
    } = inputs;
    let mut supervisor = Supervisor::new();
    let (admin_lifecycle, admin_lifecycle_inbox) = admin_lifecycle_channel();
    if let Err(error) = spawn_admin_owner(
        &mut supervisor,
        admin.owner,
        admin.inbox,
        admin_lifecycle_inbox,
    ) {
        return Err(unwind_live_state_and_log(live, log_owner, startup_deadline, error).await);
    }
    let LiveState {
        owner,
        state,
        storage,
        storage_reads,
        checkpoints,
        crypto,
        audit: _,
        backup: _,
    } = live;
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let receivers = StateOwnerReceivers {
        inbox: inbox_receiver,
        connection_closes: connection_close_inbox,
        lifecycle: lifecycle_receiver,
        storage,
        storage_reads,
        checkpoints,
        crypto,
    };
    let state_owner = spawn_state_owner(
        &mut supervisor,
        StateOwnerStart {
            state,
            receivers,
            readiness: Arc::clone(&readiness),
            liveness,
        },
    );
    let (state_exited, state_started) = match state_owner {
        Ok(started) => started,
        Err(error) => {
            return Err(unwind_started_owners(
                &mut supervisor,
                owner,
                log_owner,
                startup_deadline,
                error,
            )
            .await);
        }
    };
    if state_started.await.is_err() {
        return Err(unwind_started_owners(
            &mut supervisor,
            owner,
            log_owner,
            startup_deadline,
            DaemonError::TaskFailed,
        )
        .await);
    }
    let listeners = match ListenerSet::start(specs, context, &supervisor.root_token()) {
        Ok(listeners) => listeners,
        Err(error) => {
            return Err(unwind_started_owners(
                &mut supervisor,
                owner,
                log_owner,
                startup_deadline,
                error.into(),
            )
            .await);
        }
    };
    let control = listeners.control();
    let listener_exited = match spawn_listener_owner(&mut supervisor, listeners) {
        Ok(exited) => exited,
        Err(error) => {
            return Err(unwind_started_owners(
                &mut supervisor,
                owner,
                log_owner,
                startup_deadline,
                error,
            )
            .await);
        }
    };
    let signals = match spawn_background_owners(&mut supervisor, &inbox, admission) {
        Ok(signals) => signals,
        Err(error) => {
            return Err(unwind_started_owners(
                &mut supervisor,
                owner,
                log_owner,
                startup_deadline,
                error,
            )
            .await);
        }
    };
    Ok(RunningOwners {
        owner,
        log_owner,
        supervisor,
        control,
        lifecycle,
        admin_lifecycle,
        signals,
        state_exited,
        listener_exited,
    })
}

async fn unwind_started_owners(
    supervisor: &mut Supervisor,
    owner: StorageOwner,
    log_owner: FileLogOwner,
    deadline: tokio::time::Instant,
    first_failure: DaemonError,
) -> DaemonError {
    supervisor.cancel();
    let report = supervisor
        .join_all(deadline.saturating_duration_since(tokio::time::Instant::now()))
        .await;
    if report.unfinished != 0 {
        fail_stop_shutdown();
    }
    let _closed = shutdown_blocking_owners(owner, log_owner, deadline).await;
    first_failure
}

fn spawn_admin_owner(
    supervisor: &mut Supervisor,
    owner: AdminOwner,
    inbox: AdminOwnerInbox,
    lifecycle: AdminLifecycleInbox,
) -> Result<(), DaemonError> {
    supervisor.spawn(
        ChildName::AdminOwner,
        ChildKind::Critical,
        |token| async move {
            owner.run(inbox, lifecycle, token).await;
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
            let exits = listeners.join().await;
            let _sent = listener_exit.send(());
            let exits = exits?;
            if exits.iter().any(|exit| exit.task_failed) {
                Err(RuntimeError::InvalidValue)
            } else {
                Ok(())
            }
        },
    )?;
    Ok(listener_exited)
}

struct StateOwnerStart {
    state: StateCore,
    receivers: StateOwnerReceivers,
    readiness: Arc<ReadinessGate>,
    liveness: Arc<Liveness>,
}

fn spawn_state_owner(
    supervisor: &mut Supervisor,
    start: StateOwnerStart,
) -> Result<(oneshot::Receiver<StateCoreExit>, oneshot::Receiver<()>), DaemonError> {
    let (state_exit, state_exited) = oneshot::channel();
    let (state_started, state_ready) = oneshot::channel();
    let StateOwnerStart {
        state,
        receivers,
        readiness,
        liveness,
    } = start;
    supervisor.spawn(ChildName::StateCoreTask, ChildKind::Critical, |token| {
        run_state_owner(
            state,
            receivers,
            token,
            state_exit,
            state_started,
            readiness,
            liveness,
        )
    })?;
    Ok((state_exited, state_ready))
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

// agenc-review: allow owner=runtime reviewed=2026-08-31 reason=listener composition keeps each independently owned bounded port and policy authority visible at the root wiring boundary
#[allow(clippy::too_many_arguments)]
fn listener_context(
    config: &Config,
    runtime_config: RuntimeConfigHandle,
    inbox: &mpsc::Sender<StateCoreMessage>,
    connection_closes: ConnectionClosePort,
    admin: AdminTransportPort,
    budget: Arc<MemoryBudget>,
    admission: Arc<TransportAdmission>,
    observer: Arc<RuntimeObserver>,
) -> Result<ListenerContext, DaemonError> {
    let _clients = limit_usize(config, LimitKey::ClientConnections)?;
    let _handshakes = limit_usize(config, LimitKey::TlsHandshakes)?;
    Ok(ListenerContext {
        budget,
        handshakes: HandshakeLimiter::new(MAX_HANDSHAKES_IN_PROGRESS)?,
        client_slots: Arc::new(Semaphore::new(MAX_CLIENT_CONNECTIONS)),
        admission,
        observer,
        inbox: inbox.clone(),
        connection_closes,
        admin: Some(admin),
        limits: connection_limits(config)?,
        runtime_config: Some(runtime_config),
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
    connection_closes: ConnectionCloseInbox,
    lifecycle: mpsc::Receiver<crate::state_core::inbox::LifecycleRequest>,
    storage: mpsc::Receiver<crate::bridge::StorageCompletionMessage>,
    storage_reads: mpsc::Receiver<crate::bridge::StorageReadCompletionMessage>,
    checkpoints: mpsc::Receiver<crate::bridge::StorageCheckpointCompletionMessage>,
    crypto: mpsc::Receiver<
        crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
    >,
}

async fn run_state_owner(
    mut state: StateCore,
    receivers: StateOwnerReceivers,
    token: crate::cancel::CancellationToken,
    exited: oneshot::Sender<StateCoreExit>,
    started: oneshot::Sender<()>,
    readiness: Arc<ReadinessGate>,
    liveness: Arc<Liveness>,
) -> Result<(), RuntimeError> {
    let StateOwnerReceivers {
        inbox,
        connection_closes,
        lifecycle,
        storage,
        storage_reads,
        checkpoints,
        crypto,
    } = receivers;
    readiness.mark(ReadinessStage::StateCore);
    liveness.record_state_core(state.context().now());
    let _sent = started.send(());
    let exit = state
        .run(
            inbox,
            connection_closes,
            lifecycle,
            storage,
            storage_reads,
            checkpoints,
            crypto,
            token,
        )
        .await;
    readiness.clear(ReadinessStage::StateCore);
    let (storage_bridge, crypto_bridge) = state.into_bridges();
    let mut storage_shutdown = storage_bridge.into_shutdown();
    let storage_wait = async {
        loop {
            if let Some(result) = storage_shutdown.try_complete() {
                return result;
            }
            tokio::time::sleep(OWNER_SHUTDOWN_POLL_INTERVAL).await;
        }
    };
    let (storage_result, crypto_result) = tokio::join!(storage_wait, crypto_bridge.shutdown());
    storage_result?;
    crypto_result?;
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

struct ShutdownWaitInputs<'a> {
    config_path: &'a Path,
    runtime_config: &'a RuntimeConfigHandle,
    reload: &'a ReloadPort,
    reload_preparation: &'a mut ReloadPreparationInbox,
    admin_failed: &'a mut mpsc::Receiver<()>,
    admin_process: &'a mut AdminProcessInbox,
    budget: Arc<MemoryBudget>,
    storage: &'a StoragePort,
    signals: &'a mut mpsc::Receiver<SignalEvent>,
    state_exited: &'a mut oneshot::Receiver<StateCoreExit>,
    listener_exited: &'a mut oneshot::Receiver<()>,
    liveness: Arc<Liveness>,
    monotonic: SystemMonotonicClock,
    observer: Arc<RuntimeObserver>,
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=closed owner loop keeps termination selectable while serializing admin preparation signal coalescing activation progress and critical owner exits
async fn wait_for_shutdown(inputs: ShutdownWaitInputs<'_>) -> Result<ShutdownTrigger, DaemonError> {
    let ShutdownWaitInputs {
        config_path,
        runtime_config,
        reload,
        reload_preparation,
        admin_failed,
        admin_process,
        budget,
        storage,
        signals,
        state_exited,
        listener_exited,
        liveness,
        monotonic,
        observer,
    } = inputs;
    type PreparationFuture<'a> =
        Pin<Box<dyn Future<Output = Result<PreparedReload, ReloadPrepareFailure>> + Send + 'a>>;
    type ActivationFuture<'a> = Pin<Box<dyn Future<Output = ReloadOutcome> + Send + 'a>>;

    let mut progress = tokio::time::interval(Duration::from_secs(5));
    progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    progress.tick().await;
    liveness.record_supervisor(monotonic.now());
    let mut preparation: Option<PreparationFuture<'_>> = None;
    let mut preparation_origin = None;
    let mut activation: Option<ActivationFuture<'_>> = None;
    let mut pending_sighup = false;
    loop {
        let event = tokio::select! {
            biased;
            signal = signals.recv() => Some(SupervisorEvent::Signal(signal)),
            request = reload_preparation.recv() => {
                Some(SupervisorEvent::ReloadPreparation(request))
            },
            result = async {
                match preparation.as_mut() {
                    Some(future) => future.await,
                    None => std::future::pending().await,
                }
            }, if preparation.is_some() => Some(SupervisorEvent::Prepared(result)),
            outcome = async {
                match activation.as_mut() {
                    Some(future) => future.await,
                    None => std::future::pending().await,
                }
            }, if activation.is_some() => Some(SupervisorEvent::Activated(outcome)),
            () = runtime_config.wait_for_reload_idle(),
                if pending_sighup && preparation.is_none() && activation.is_none() => {
                    Some(SupervisorEvent::ReloadIdle)
                },
            _failure = admin_failed.recv() => Some(SupervisorEvent::AdminFailure),
            process = admin_process.recv() => Some(SupervisorEvent::AdminProcess(process)),
            exit = &mut *state_exited => Some(SupervisorEvent::State(exit)),
            _listener = &mut *listener_exited => Some(SupervisorEvent::Listener),
            _ = progress.tick() => None,
        };
        let Some(event) = event else {
            liveness.record_supervisor(monotonic.now());
            continue;
        };
        match event {
            SupervisorEvent::Signal(Some(SignalEvent::Reload)) => {
                if preparation.is_some() || activation.is_some() || pending_sighup {
                    pending_sighup = true;
                } else {
                    preparation = Some(Box::pin(prepare_reload(
                        config_path,
                        runtime_config,
                        &budget,
                        storage,
                    )));
                    preparation_origin = Some(ReloadPreparationOrigin::Signal);
                }
            }
            SupervisorEvent::ReloadPreparation(Some(reply)) => {
                if preparation.is_some() || activation.is_some() || pending_sighup {
                    reply.send(Err(ReloadPrepareFailure::Busy));
                } else {
                    preparation = Some(Box::pin(prepare_reload(
                        config_path,
                        runtime_config,
                        &budget,
                        storage,
                    )));
                    preparation_origin = Some(ReloadPreparationOrigin::Admin(reply));
                }
            }
            SupervisorEvent::Prepared(result) => {
                preparation = None;
                match preparation_origin.take() {
                    Some(ReloadPreparationOrigin::Signal) => match result {
                        Ok(prepared) => {
                            activation = Some(Box::pin(reload.activate_signal(prepared)));
                        }
                        Err(ReloadPrepareFailure::Busy) => pending_sighup = true,
                        Err(_) => observer.reload(false),
                    },
                    Some(ReloadPreparationOrigin::Admin(reply)) => reply.send(result),
                    None => return Err(DaemonError::TaskFailed),
                }
            }
            SupervisorEvent::Activated(outcome) => {
                observer.reload(matches!(
                    outcome,
                    ReloadOutcome::Applied(_) | ReloadOutcome::NoChange(_)
                ));
                activation = None;
            }
            SupervisorEvent::ReloadIdle => {
                pending_sighup = false;
                preparation = Some(Box::pin(prepare_reload(
                    config_path,
                    runtime_config,
                    &budget,
                    storage,
                )));
                preparation_origin = Some(ReloadPreparationOrigin::Signal);
            }
            SupervisorEvent::Signal(Some(SignalEvent::Terminate | SignalEvent::Interrupt)) => {
                return Ok(ShutdownTrigger::Signal);
            }
            SupervisorEvent::AdminProcess(Some(AdminProcessAction::Die)) => {
                return Ok(ShutdownTrigger::CommittedDie);
            }
            SupervisorEvent::AdminProcess(Some(AdminProcessAction::Restart)) => {
                return Ok(ShutdownTrigger::CommittedRestart);
            }
            SupervisorEvent::State(Ok(StateCoreExit::Indeterminate(_))) => {
                observer.storage_indeterminate();
                return Err(DaemonError::TaskFailed);
            }
            SupervisorEvent::Signal(None)
            | SupervisorEvent::ReloadPreparation(None)
            | SupervisorEvent::AdminProcess(None)
            | SupervisorEvent::AdminFailure
            | SupervisorEvent::State(_)
            | SupervisorEvent::Listener => {
                return Err(DaemonError::TaskFailed);
            }
        }
    }
}

enum ShutdownTrigger {
    Signal,
    CommittedDie,
    CommittedRestart,
}

enum SupervisorEvent {
    Signal(Option<SignalEvent>),
    ReloadPreparation(Option<ReloadPreparationReply>),
    Prepared(Result<PreparedReload, ReloadPrepareFailure>),
    Activated(ReloadOutcome),
    ReloadIdle,
    AdminProcess(Option<AdminProcessAction>),
    AdminFailure,
    State(Result<StateCoreExit, oneshot::error::RecvError>),
    Listener,
}

enum ReloadPreparationOrigin {
    Signal,
    Admin(ReloadPreparationReply),
}

const OWNER_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(1);

struct RuntimeShutdownHooks<'a> {
    storage_shutdown: StorageShutdown,
    supervisor: &'a mut Supervisor,
    listeners: &'a ListenerControl,
    lifecycle: &'a LifecycleControl,
    admin: &'a AdminLifecycleControl,
    admin_acknowledgements: Vec<FlushAcknowledgement>,
    listener_exited: &'a mut oneshot::Receiver<()>,
    listener_joined: bool,
    readiness: Arc<ReadinessGate>,
    observer: Arc<RuntimeObserver>,
    log_control: FileLogControl,
    log_shutdown: FileLogShutdown,
    stop_failure: Option<ShutdownFailure>,
}

impl ShutdownHooks for RuntimeShutdownHooks<'_> {
    async fn run(&mut self, phase: ShutdownPhase, budget: Duration) -> Result<(), ShutdownFailure> {
        self.observer.shutdown_phase(phase);
        match phase {
            ShutdownPhase::Quiesce => {
                self.readiness.clear(ReadinessStage::StateCore);
                self.listeners.stop_accepting();
                self.listeners.wait_accept_stopped().await;
                self.admin.quiesce().await.map_err(map_admin_lifecycle)?;
                request_lifecycle(self.lifecycle, LifecyclePhase::Quiesce).await
            }
            ShutdownPhase::Drain => {
                self.admin_acknowledgements =
                    self.admin.drain().await.map_err(map_admin_lifecycle)?;
                request_lifecycle(self.lifecycle, LifecyclePhase::Drain).await
            }
            ShutdownPhase::Flush => {
                self.admin.flush().await.map_err(map_admin_lifecycle)?;
                request_lifecycle(self.lifecycle, LifecyclePhase::Flush).await?;
                for acknowledgement in &self.admin_acknowledgements {
                    acknowledgement.wait().await;
                }
                if !self.listener_joined {
                    (&mut *self.listener_exited)
                        .await
                        .map_err(|_| ShutdownFailure::Writer)?;
                    self.listener_joined = true;
                }
                self.log_control
                    .flush()
                    .await
                    .map_err(|_| ShutdownFailure::Writer)
            }
            ShutdownPhase::Stop => self.stop(budget).await,
        }
    }

    fn retained_failure(&self, phase: ShutdownPhase) -> Option<ShutdownFailure> {
        if phase == ShutdownPhase::Stop {
            self.stop_failure
        } else {
            None
        }
    }

    fn stop_deadline_expired(&mut self) {
        fail_stop_shutdown();
    }
}

impl RuntimeShutdownHooks<'_> {
    // agenc-review: focus owner=runtime reviewed=2026-08-31 reason=one stop budget retains first failure while ordering control cancellation forced join storage and log closure
    async fn stop(&mut self, budget: Duration) -> Result<(), ShutdownFailure> {
        if budget.is_zero() {
            fail_stop_shutdown();
        }
        let deadline = tokio::time::Instant::now() + budget;
        self.listeners.stop_accepting();
        let control_budget =
            (budget / 5).min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        let controls = tokio::time::timeout(control_budget, async {
            tokio::join!(
                self.admin.stop(),
                request_lifecycle(self.lifecycle, LifecyclePhase::Stop)
            )
        })
        .await;
        match controls {
            Ok((admin, state)) => {
                if let Err(failure) = admin.map_err(map_admin_lifecycle) {
                    self.retain_stop_failure(failure);
                }
                if let Err(failure) = state {
                    self.retain_stop_failure(failure);
                }
            }
            Err(_) => self.retain_stop_failure(ShutdownFailure::StateCore),
        }
        self.listeners.cancel_connections();
        self.supervisor.cancel();
        let cooperative_budget =
            (budget / 3).min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        let report = self.supervisor.join_all(cooperative_budget).await;
        if validate_join_report(&report).is_err() {
            self.retain_stop_failure(ShutdownFailure::Join);
        }
        if report.unfinished != 0 {
            let final_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            let forced = self.supervisor.join_all(final_budget).await;
            if validate_join_report(&forced).is_err() {
                self.retain_stop_failure(ShutdownFailure::Join);
            }
            if forced.unfinished != 0 {
                fail_stop_shutdown();
            }
        }
        if self.storage_shutdown.start().is_err() {
            self.retain_stop_failure(ShutdownFailure::Storage);
            fail_stop_shutdown();
        }
        if self.log_shutdown.start().is_err() {
            self.retain_stop_failure(ShutdownFailure::Writer);
            fail_stop_shutdown();
        }
        self.wait_for_blocking_owners(deadline).await;
        self.stop_failure.map_or(Ok(()), Err)
    }

    async fn wait_for_blocking_owners(&mut self, deadline: tokio::time::Instant) {
        loop {
            let storage = self.storage_shutdown.try_complete();
            if matches!(storage, Some(Err(_))) {
                self.retain_stop_failure(ShutdownFailure::Storage);
            }
            let logs = self.log_shutdown.try_complete();
            if !matches!(logs, None | Some(Ok(0))) {
                self.retain_stop_failure(ShutdownFailure::Writer);
            }
            if storage.is_some() && logs.is_some() {
                return;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                fail_stop_shutdown();
            }
            tokio::time::sleep_until(deadline.min(now + OWNER_SHUTDOWN_POLL_INTERVAL)).await;
        }
    }

    fn retain_stop_failure(&mut self, failure: ShutdownFailure) {
        if self.stop_failure.is_none() {
            self.stop_failure = Some(failure);
        }
    }
}

fn fail_stop_shutdown() -> ! {
    exit_process(CRASH_EXIT_CODE)
}

fn map_admin_lifecycle(failure: AdminLifecycleFailure) -> ShutdownFailure {
    match failure {
        AdminLifecycleFailure::Writer => ShutdownFailure::Writer,
        AdminLifecycleFailure::Audit => ShutdownFailure::Audit,
        AdminLifecycleFailure::Unavailable | AdminLifecycleFailure::Busy => {
            ShutdownFailure::StateCore
        }
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

async fn prepare_reload(
    config_path: &Path,
    runtime_config: &RuntimeConfigHandle,
    budget: &MemoryBudget,
    storage: &StoragePort,
) -> Result<PreparedReload, ReloadPrepareFailure> {
    let lease = runtime_config.begin_reload()?;
    let path = config_path.to_path_buf();
    let active = runtime_config.load();
    let (candidate, secrets, operators) = tokio::task::spawn_blocking(move || {
        let candidate = load_config(&path, ValidationDepth::Host)?;
        validate_profile(&candidate)?;
        let secrets = SecretSet::load(&candidate)?;
        let operators = operator_registry(&candidate)?;
        Ok::<_, DaemonError>((candidate, secrets, operators))
    })
    .await
    .map_err(|_| ReloadPrepareFailure::InvalidConfig)?
    .map_err(reload_prepare_failure)?;
    let purposes = enabled_runtime_purposes(&candidate).map_err(reload_prepare_failure)?;
    let pool = startup_arithmetic(
        candidate.server.memory_budget_bytes,
        candidate.server.crypto_worker_threads,
        &purposes,
        candidate.limits.values.get(LimitKey::ParsedArenaBytes),
    )
    .map_err(|_| ReloadPrepareFailure::ResourceFloor)?;
    if pool.protocol_pool_bytes() != budget.capacity()
        || pool.working_set_floor_bytes() > budget.capacity()
    {
        return Err(ReloadPrepareFailure::ResourceFloor);
    }
    let statistics = reload_storage_statistics(storage).await?;
    validate_reload_storage(&candidate, statistics)?;
    let (parts, _unused_specs) = prepare_runtime_parts(&candidate, &secrets, operators)
        .await
        .map_err(reload_prepare_failure)?;
    let mut prepared = PreparedReload::new(&active, candidate, parts)?;
    prepared.attach_lease(lease);
    Ok(prepared)
}

async fn reload_storage_statistics(
    storage: &StoragePort,
) -> Result<StorageStatistics, ReloadPrepareFailure> {
    let completion = storage.try_statistics().map_err(map_reload_storage_error)?;
    tokio::task::spawn_blocking(move || completion.wait())
        .await
        .map_err(|_| ReloadPrepareFailure::Unavailable)?
        .map_err(map_reload_storage_error)
}

fn validate_reload_storage(
    candidate: &Config,
    statistics: StorageStatistics,
) -> Result<(), ReloadPrepareFailure> {
    if statistics.logical_database_bytes() > candidate.storage.database_max_bytes
        || statistics.backup_stream_bytes() > candidate.storage.backup_max_bytes
    {
        return Err(ReloadPrepareFailure::StorageFloor);
    }
    let required_available = statistics
        .filesystem_reserve_bytes()
        .checked_add(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
        .ok_or(ReloadPrepareFailure::StorageFloor)?;
    if statistics.filesystem_available_bytes() < required_available {
        return Err(ReloadPrepareFailure::StorageFloor);
    }
    Ok(())
}

const fn map_reload_storage_error(error: StorageError) -> ReloadPrepareFailure {
    match error {
        StorageError::QueueFull => ReloadPrepareFailure::Busy,
        StorageError::LimitExceeded => ReloadPrepareFailure::StorageFloor,
        _ => ReloadPrepareFailure::Unavailable,
    }
}

fn reload_prepare_failure(error: DaemonError) -> ReloadPrepareFailure {
    match error {
        DaemonError::Runtime(
            RuntimeError::BudgetArithmetic
            | RuntimeError::BudgetBelowWorkingSet
            | RuntimeError::MemoryExhausted,
        ) => ReloadPrepareFailure::ResourceFloor,
        _ => ReloadPrepareFailure::InvalidConfig,
    }
}

async fn run_maintenance(
    token: crate::cancel::CancellationToken,
    inbox: mpsc::Sender<StateCoreMessage>,
    admission: Arc<TransportAdmission>,
) -> Result<(), RuntimeError> {
    let mut minute = tokio::time::interval(MAINTENANCE_MINUTE);
    let mut retention = tokio::time::interval(RETENTION_INTERVAL);
    let mut pending = PendingMaintenance::default();
    minute.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    retention.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    minute.tick().await;
    retention.tick().await;
    while maintenance_iteration(
        &token,
        &inbox,
        admission.as_ref(),
        &mut minute,
        &mut retention,
        &mut pending,
    )
    .await?
    {}
    Ok(())
}

async fn maintenance_iteration(
    token: &crate::cancel::CancellationToken,
    inbox: &mpsc::Sender<StateCoreMessage>,
    admission: &TransportAdmission,
    minute: &mut tokio::time::Interval,
    retention: &mut tokio::time::Interval,
    pending: &mut PendingMaintenance,
) -> Result<bool, RuntimeError> {
    tokio::select! {
        biased;
        () = token.cancelled() => Ok(false),
        () = inbox.closed() => Ok(false),
        _ = minute.tick() => {
            pending.record_clock_drift_check();
            Ok(true)
        },
        () = wait_for_prefix_erasure(admission) => {
            admission.erase_idle();
            Ok(true)
        },
        _ = retention.tick() => {
            pending.record_retention_sweep();
            Ok(true)
        },
        permit = inbox.reserve(), if !pending.is_empty() => {
            let Ok(permit) = permit else {
                return Ok(false);
            };
            let event = pending.take().ok_or(RuntimeError::InvalidValue)?;
            permit.send(StateCoreMessage::Maintenance(event));
            Ok(true)
        },
    }
}

#[derive(Default)]
struct PendingMaintenance {
    clock_drift_check: bool,
    retention_sweep: bool,
}

impl PendingMaintenance {
    const fn record_clock_drift_check(&mut self) {
        self.clock_drift_check = true;
    }

    const fn record_retention_sweep(&mut self) {
        self.retention_sweep = true;
    }

    const fn is_empty(&self) -> bool {
        !self.clock_drift_check && !self.retention_sweep
    }

    fn take(&mut self) -> Option<MaintenanceEvent> {
        if self.clock_drift_check {
            self.clock_drift_check = false;
            return Some(MaintenanceEvent::ClockDriftCheck);
        }
        if self.retention_sweep {
            self.retention_sweep = false;
            return Some(MaintenanceEvent::RetentionSweep);
        }
        None
    }
}

async fn wait_for_prefix_erasure(admission: &TransportAdmission) {
    loop {
        let changed = admission.prefix_expiry_changed();
        tokio::pin!(changed);
        let Some(delay) = admission.prefix_erasure_delay() else {
            changed.as_mut().await;
            continue;
        };
        tokio::select! {
            () = tokio::time::sleep(delay) => return,
            () = changed.as_mut() => {}
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

async fn unwind_live_storage_and_log(
    storage: LiveStorage,
    log_owner: FileLogOwner,
    deadline: tokio::time::Instant,
    first_failure: DaemonError,
) -> DaemonError {
    let LiveStorage { owner, .. } = storage;
    let _closed = shutdown_blocking_owners(owner, log_owner, deadline).await;
    first_failure
}

async fn unwind_live_state_and_log(
    live: LiveState,
    log_owner: FileLogOwner,
    deadline: tokio::time::Instant,
    first_failure: DaemonError,
) -> DaemonError {
    let LiveState {
        owner,
        state,
        storage,
        storage_reads,
        checkpoints,
        crypto,
        audit,
        backup,
    } = live;
    drop((storage, storage_reads, checkpoints, crypto, audit, backup));
    let (storage_bridge, crypto_bridge) = state.into_bridges();
    let _bridges = shutdown_startup_bridges(storage_bridge, crypto_bridge, deadline).await;
    let _closed = shutdown_blocking_owners(owner, log_owner, deadline).await;
    first_failure
}

async fn shutdown_startup_bridges(
    storage_bridge: StorageBridge,
    crypto_bridge: CryptoBridge,
    deadline: tokio::time::Instant,
) -> (Result<(), RuntimeError>, Result<(), RuntimeError>) {
    let mut storage_shutdown = storage_bridge.into_shutdown();
    let storage = async {
        loop {
            if let Some(result) = storage_shutdown.try_complete() {
                return result;
            }
            tokio::time::sleep(OWNER_SHUTDOWN_POLL_INTERVAL).await;
        }
    };
    let cleanup = async { tokio::join!(storage, crypto_bridge.shutdown()) };
    tokio::pin!(cleanup);
    tokio::select! {
        result = &mut cleanup => result,
        () = tokio::time::sleep_until(deadline) => fail_stop_shutdown(),
    }
}

async fn shutdown_blocking_owners(
    owner: StorageOwner,
    log_owner: FileLogOwner,
    deadline: tokio::time::Instant,
) -> (Result<(), StorageError>, Result<u64, RuntimeError>) {
    let mut storage = owner.into_shutdown();
    let mut logs = log_owner.into_shutdown();
    if storage.start().is_err() || logs.start().is_err() {
        fail_stop_shutdown();
    }
    let mut storage_result = None;
    let mut log_result = None;
    loop {
        if storage_result.is_none() {
            storage_result = storage.try_complete();
        }
        if log_result.is_none() {
            log_result = logs.try_complete();
        }
        if let (Some(storage_result), Some(log_result)) = (storage_result, log_result) {
            return (storage_result, log_result);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            fail_stop_shutdown();
        }
        tokio::time::sleep_until(deadline.min(now + OWNER_SHUTDOWN_POLL_INTERVAL)).await;
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_config::{PathResolver, RateTable};
    use agenc_ircd_domain::DurableAccount;
    use agenc_ircd_storage::AccountRecordBody;
    use agenc_ircd_testkit::{DeterministicMonotonicClock, account_id};
    use agenc_ircd_types::{Revision, UtcSecond};

    use super::*;

    const PUBLIC_CONFIG: &str = include_str!("../../agenc-ircd-config/tests/golden/public.toml");

    fn public_config() -> Result<Config, DaemonError> {
        Config::parse_text(
            PUBLIC_CONFIG,
            &PathResolver::none(),
            ValidationDepth::Document,
        )
        .map_err(DaemonError::Configuration)
    }

    #[test]
    fn legacy_admin_policy_backfill_survives_retention_and_restart() -> Result<(), DaemonError> {
        let account_id = account_id(91);
        let revision = Revision::new(1).map_err(|_| RuntimeError::InvalidValue)?;
        let legacy = DurableAccount {
            account_id,
            label: None,
            presence: PresencePolicy::Private,
            guest_direct_messages: GuestDirectMessagePolicy::Deny,
            direct_messages: DirectMessagePolicy::Deny,
            contacts: Vec::new(),
            reserved_nicknames: Vec::new(),
            session_generation: Generation::new(1).map_err(|_| RuntimeError::InvalidValue)?,
            revision,
            admin_suspension_expires_at: None,
        };
        let mut domain = agenc_ircd_domain::DomainState::restore(
            revision,
            vec![AccountRecordBody::decode(&AccountRecordBody::encode(
                &legacy,
            )?)?],
            Vec::new(),
            Vec::new(),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let expires_at = UtcSecond::from_unix_seconds(10_000);
        let suspensions = vec![(account_id, expires_at)];
        let backfills = missing_admin_policy_backfills(&domain, &suspensions, &[])?;
        assert!(matches!(
            backfills.as_slice(),
            [AdminPolicyBackfill::Account(found)] if *found == account_id
        ));
        domain
            .install_admin_policy(suspensions, Vec::new())
            .map_err(|_| RuntimeError::InvalidValue)?;

        let persisted = AccountRecordBody::encode(
            &domain
                .durable_account(account_id)
                .ok_or(RuntimeError::InvalidValue)?,
        )?;
        let restarted = agenc_ircd_domain::DomainState::restore(
            revision,
            vec![AccountRecordBody::decode(&persisted)?],
            Vec::new(),
            Vec::new(),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(
            restarted
                .durable_account(account_id)
                .and_then(|account| account.admin_suspension_expires_at),
            Some(expires_at)
        );
        assert!(missing_admin_policy_backfills(&restarted, &[], &[])?.is_empty());
        Ok(())
    }

    #[test]
    fn pending_maintenance_coalesces_without_dropping_distinct_work() {
        let mut pending = PendingMaintenance::default();
        pending.record_retention_sweep();
        pending.record_clock_drift_check();
        pending.record_retention_sweep();
        pending.record_clock_drift_check();

        assert_eq!(pending.take(), Some(MaintenanceEvent::ClockDriftCheck));
        assert_eq!(pending.take(), Some(MaintenanceEvent::RetentionSweep));
        assert_eq!(pending.take(), None);
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn pending_maintenance_survives_full_inbox_and_stops_on_close() -> Result<(), RuntimeError>
    {
        let admission = TransportAdmission::new(
            RateLimits::defaults(),
            1,
            Arc::new(MemoryBudget::new(1_024 * 1_024)),
            Box::new(DeterministicMonotonicClock::at(0)),
        )?;
        let token = crate::cancel::CancellationToken::root();
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .send(StateCoreMessage::Maintenance(
                MaintenanceEvent::CheckpointDue,
            ))
            .await
            .map_err(|_| RuntimeError::Cancelled)?;
        let mut minute = tokio::time::interval(Duration::from_secs(3_600));
        let mut retention = tokio::time::interval(Duration::from_secs(3_600));
        minute.tick().await;
        retention.tick().await;
        let mut pending = PendingMaintenance::default();
        pending.record_clock_drift_check();
        pending.record_retention_sweep();

        assert!(
            tokio::time::timeout(
                Duration::from_millis(5),
                maintenance_iteration(
                    &token,
                    &sender,
                    &admission,
                    &mut minute,
                    &mut retention,
                    &mut pending,
                ),
            )
            .await
            .is_err()
        );
        assert!(receiver.recv().await.is_some());
        assert!(
            maintenance_iteration(
                &token,
                &sender,
                &admission,
                &mut minute,
                &mut retention,
                &mut pending,
            )
            .await?
        );
        assert!(matches!(
            receiver.recv().await,
            Some(StateCoreMessage::Maintenance(
                MaintenanceEvent::ClockDriftCheck
            ))
        ));
        drop(receiver);
        assert!(
            !maintenance_iteration(
                &token,
                &sender,
                &admission,
                &mut minute,
                &mut retention,
                &mut pending,
            )
            .await?
        );
        Ok(())
    }

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

    #[test]
    fn core_v1_profile_rejects_each_deferred_role_feature_and_listener() -> Result<(), DaemonError>
    {
        let baseline = public_config()?;
        assert!(validate_profile(&baseline).is_ok());

        let mut edge = baseline.clone();
        edge.network.role = NodeRole::Edge;
        assert!(matches!(
            validate_profile(&edge),
            Err(DaemonError::UnsupportedProfile)
        ));

        let mut federation = baseline.clone();
        federation.federation.enabled = true;
        assert!(matches!(
            validate_profile(&federation),
            Err(DaemonError::UnsupportedProfile)
        ));

        let mut e2ee = baseline.clone();
        e2ee.e2ee.enabled = true;
        assert!(matches!(
            validate_profile(&e2ee),
            Err(DaemonError::UnsupportedProfile)
        ));

        let mut no_clients = baseline.clone();
        no_clients.accounts.accept_clients = false;
        assert!(matches!(
            validate_profile(&no_clients),
            Err(DaemonError::UnsupportedProfile)
        ));

        for purpose in [
            ConfigListenerPurpose::ClientWss,
            ConfigListenerPurpose::Federation,
        ] {
            let mut enabled = baseline.clone();
            enabled
                .listeners
                .first_mut()
                .ok_or(RuntimeError::InvalidValue)?
                .purpose = purpose;
            assert!(matches!(
                validate_profile(&enabled),
                Err(DaemonError::UnsupportedProfile)
            ));

            enabled
                .listeners
                .first_mut()
                .ok_or(RuntimeError::InvalidValue)?
                .enabled = false;
            assert!(validate_profile(&enabled).is_ok());
        }
        Ok(())
    }

    #[test]
    fn committed_process_actions_preserve_their_exit_status_after_cleanup_failure()
    -> Result<(), DaemonError> {
        assert_eq!(
            finish_daemon_run(
                Ok(ShutdownTrigger::CommittedDie),
                Err(DaemonError::ShutdownTimeout),
            )?,
            DaemonExit::Stopped
        );
        assert_eq!(
            finish_daemon_run(
                Ok(ShutdownTrigger::CommittedRestart),
                Err(DaemonError::TaskFailed),
            )?,
            DaemonExit::RestartRequested
        );
        assert!(matches!(
            finish_daemon_run(
                Ok(ShutdownTrigger::Signal),
                Err(DaemonError::ShutdownTimeout),
            ),
            Err(DaemonError::ShutdownTimeout)
        ));
        Ok(())
    }

    #[test]
    fn account_defaults_cover_every_policy_combination() -> Result<(), DaemonError> {
        let baseline = public_config()?;
        for (public_presence, expected_presence) in [
            (false, PresencePolicy::Private),
            (true, PresencePolicy::Public),
        ] {
            for (allow_guest_dm, expected_guest_dm) in [
                (false, GuestDirectMessagePolicy::Deny),
                (true, GuestDirectMessagePolicy::Allow),
            ] {
                for (configured_dm, expected_dm) in [
                    (DirectMessageDefault::Allow, DirectMessagePolicy::Allow),
                    (
                        DirectMessageDefault::Contacts,
                        DirectMessagePolicy::Contacts,
                    ),
                    (DirectMessageDefault::Deny, DirectMessagePolicy::Deny),
                ] {
                    let mut config = baseline.clone();
                    config.accounts.default_public_presence = public_presence;
                    config.accounts.default_allow_guest_dm = allow_guest_dm;
                    config.accounts.default_direct_messages = configured_dm;
                    assert_eq!(
                        account_defaults(&config),
                        (expected_presence, expected_guest_dm, expected_dm)
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn validated_config_builds_exact_runtime_rates_limits_and_budget() -> Result<(), DaemonError> {
        let config = public_config()?;

        let purposes = enabled_runtime_purposes(&config)?;
        assert_eq!(
            purposes,
            vec![ListenerPurpose::ClientTls, ListenerPurpose::AdminLocal]
        );

        let rates = configured_rates(&config)?;
        for kind in BucketKind::ALL {
            let Some(name) = kind.config_name() else {
                assert_eq!(rates.rate(kind), RateLimits::defaults().rate(kind));
                continue;
            };
            let row = RATE_ROWS
                .iter()
                .find(|row| row.name == name)
                .ok_or(RuntimeError::InvalidValue)?;
            let expected = config.limits.rates.get(row.key);
            let actual = rates.rate(kind);
            assert_eq!(actual.refill_tokens(), expected.refill_tokens);
            assert_eq!(actual.refill_seconds(), expected.refill_seconds);
            assert_eq!(actual.burst(), expected.burst);
        }

        let connections = connection_limits(&config)?;
        assert_eq!(connections.reader.requests(), 32);
        assert_eq!(connections.reader.arena_bytes(), 32_768);
        assert_eq!(connections.queue.total_bytes(), 1_048_576);
        assert_eq!(connections.queue.control_bytes(), 65_536);
        assert_eq!(connections.queue.items(), 4_104);

        assert_eq!(
            operational_limits(&config)?.values(),
            OperationalLimitValues {
                sessions_per_account: 8,
                channels_per_session: 64,
                members_per_channel: 4_096,
                global_channels: 100_000,
                local_channels: 10_000,
                invites_per_channel: 256,
                invites_per_principal: 32,
                invites_global: 100_000,
                contacts_per_account: 1_000,
            }
        );

        let budget = memory_budget(&config)?;
        assert!(budget.capacity() > 0);
        assert_eq!(budget.available(), budget.capacity());
        Ok(())
    }
}
