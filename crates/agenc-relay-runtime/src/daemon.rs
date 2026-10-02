//! Live Stage 06 daemon composition for a standalone coordinator.

pub(crate) mod login_index;

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use agenc_relay_admin::{
    AdminSessionBinding, MaintenanceAuditScope, OperatorRecord, OperatorRegistry,
};
use agenc_relay_auth::{
    AuthError, CHANNEL_KEY_HASH_BYTES as AUTH_CHANNEL_HASH_BYTES,
    CHANNEL_KEY_ITERATIONS as AUTH_CHANNEL_ITERATIONS, CHANNEL_KEY_LANES as AUTH_CHANNEL_LANES,
    CHANNEL_KEY_MEMORY_KIB as AUTH_CHANNEL_MEMORY_KIB,
    CHANNEL_KEY_SALT_BYTES as AUTH_CHANNEL_SALT_BYTES, OPAQUE_REGISTRATION_RECORD_BYTES,
    OpaqueProfile, derive_channel_key_verifier, opaque_server_public_key,
};
use agenc_relay_config::{
    Config, ConfigError, ConfigReport, DEFAULT_REDB_CACHE_BYTES, DirectMessageDefault,
    HardeningOutcome, LimitKey, ListenerBind as ConfigListenerBind,
    ListenerPurpose as ConfigListenerPurpose, NodeRole, RATE_ROWS, RegistrationPolicy,
    SecretBytes32, SecretSet, ValidationDepth, apply_process_hardening, load_audit_trust_manifest,
    load_backup_trust_manifest, load_config, load_public_text,
};
use agenc_relay_crypto::{
    AccountHpkePrivateKey, AccountHpkePublicKey, CryptoError, CryptoWorkerConfig, Ed25519PublicKey,
    Ed25519SecretKey, LoginIndexKey, OpaqueFakeCredentialKey, OsEntropy, RollbackGuardRootKey,
    SemanticHashDomain, StorageDigest, StorageMasterKey, semantic_digest,
};
use agenc_relay_domain::{
    DirectMessagePolicy, GuestDirectMessagePolicy, OperationalLimitValues, OperationalLimits,
    PresencePolicy,
};
use agenc_relay_storage::{
    BackupTrustKey, CommitOutcome, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, ReadPlan,
    StateDirectory, StorageEngineLimits, StorageError, StorageLimitWriter, StorageOpenConfig,
    StorageOwner, StoragePort, StorageRuntimeLimits, StorageShutdown, StorageStatistics, TableId,
    embedded_storage_qualifications,
};
use agenc_relay_types::{
    EntropySource as _, FederationRole, Generation, MonotonicClock as _, OriginId, ServerId,
    TransactionId, UserId, WallClock as _,
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
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::e2ee::edge::{E2eeEdge, E2eeEdgeConfig};
use crate::e2ee::link::CompanionProfile;
use crate::federation::coordinator::{CoordinatorConfig, FederationCoordinator};
use crate::federation::edge::{EdgeConfig, EdgeFederation};
use crate::federation::link::INBOUND_QUEUE_ITEMS;
use crate::federation::owner::{
    DialOwnerPlan, FederationControl, LinkOwnerShared, run_accept_owner, run_dial_owner,
};
use crate::federation::{
    AcceptedFederationSocket, LocalIdentity, MAX_FEDERATION_PEERS, PeerIdentity,
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
use crate::registration::{
    AccountServiceConfig, AccountServiceRole, RegistrationRouter, RegistrationRouterConfig,
};
use crate::runtime_config::{
    AccountRuntimePolicy, ConfigRevision, PreparedReload, ReloadOutcome, ReloadPort,
    ReloadPreparationInbox, ReloadPreparationReply, ReloadPrepareFailure, RestartMaterial,
    RestartMaterialKey, RuntimeConfigHandle, RuntimeConfigParts, RuntimeConfigSnapshot,
    reload_channel, reload_preparation_channel,
};
use crate::state_core::durable::{
    AccountingCeilings, KeyDeriver, PlanProjection, project_batch, read_back_record,
};
use crate::state_core::inbox::{
    CLIENT_EVENT_CAPACITY, ConnectionCloseInbox, ConnectionClosePort, LifecycleControl,
    LifecycleFailure, LifecyclePhase, MAINTENANCE_EVENT_CAPACITY, MaintenanceEvent,
    SIGNAL_EVENT_CAPACITY, SignalEvent, StateCoreMessage, connection_close_channel,
    lifecycle_channel,
};
use crate::state_core::projector::FederationProjector;
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
    TlsEndpointProfile, TlsServerPolicy, build_federation_client_config_with_group_policy,
    build_server_config_with_policy, load_certificate_chain_material, load_ocsp_staple_material,
    load_trust_store_material,
};

const RUNTIME_THREAD_NAME: &str = "arcd-tokio";
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
    /// A configured listener could not be opened. The error names the
    /// address and the operating-system refusal, which a generic runtime
    /// invariant failure would hide from the operator.
    Listener(ListenerError),
    /// Tokio could not start the configured worker set.
    RuntimeStart,
    /// A supervised owner ended unexpectedly.
    TaskFailed,
    /// The state owner stopped on its own; the exit names why.
    StateCore(StateCoreExit),
    /// One or more owners did not join within the configured shutdown budget.
    ShutdownTimeout,
    /// One shutdown phase outlived its configured budget. The phase is kept
    /// because `quiesce`, `drain`, `flush` and `stop` wait on different
    /// owners, and the bare deadline message could not say which one an
    /// operator has to look at (QA-04, issue #175).
    ShutdownPhaseTimeout(ShutdownPhase),
    /// A shutdown phase returned a closed owner failure.
    ShutdownFailed(ShutdownPhase, ShutdownFailure),
    /// The sequencer credentials file did not parse, did not verify for
    /// this network, or names no key the coordinator holds.
    E2eeCredentials,
    /// One named startup reconstruction refused the recovered state. The
    /// error keeps the meaning it had; the surface is the identification the
    /// daemon adds so an operator knows which owner refused and on what.
    Reconstruction(ReconstructionSurface, RuntimeError),
}

/// Names the startup reconstruction that refused a recovered state.
///
/// `storage state is stale or inconsistent` names neither the surface nor the
/// record, so a refusal reported without this identification cannot be
/// attributed to an owner from the daemon's stderr line alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconstructionSurface {
    /// The durable account, channel, session and account-service scan.
    DurableState,
    /// The startup reconciliation of every session recovered from storage.
    RecoveredSessions,
    /// The authenticated edge federation restore, naming the step it reached
    /// and the cause that step classified.
    EdgeFederation(
        crate::federation::edge::EdgeRestoreStep,
        crate::federation::edge::EdgeRestoreCause,
    ),
    /// The optional durable history index load.
    History,
}

impl fmt::Display for ReconstructionSurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DurableState => formatter.write_str("durable state reconstruction"),
            Self::RecoveredSessions => formatter.write_str("recovered session reconciliation"),
            Self::EdgeFederation(step, cause) => match cause {
                crate::federation::edge::EdgeRestoreCause::Unclassified => {
                    write!(formatter, "edge federation restore at {}", step.label())
                }
                cause => write!(
                    formatter,
                    "edge federation restore at {} ({cause})",
                    step.label()
                ),
            },
            Self::History => formatter.write_str("history reconstruction"),
        }
    }
}

impl From<crate::federation::edge::EdgeRestoreRefusal> for DaemonError {
    fn from(refusal: crate::federation::edge::EdgeRestoreRefusal) -> Self {
        Self::Reconstruction(
            ReconstructionSurface::EdgeFederation(refusal.step, refusal.cause),
            refusal.error,
        )
    }
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
            Self::Listener(error) => write!(formatter, "listener startup failed: {error}"),
            Self::RuntimeStart => formatter.write_str("Tokio runtime startup failed"),
            Self::TaskFailed => formatter.write_str("a supervised daemon owner failed"),
            Self::StateCore(exit) => write!(formatter, "the state owner stopped: {exit}"),
            Self::ShutdownTimeout => formatter.write_str("daemon shutdown exceeded its deadline"),
            Self::ShutdownPhaseTimeout(phase) => write!(
                formatter,
                "daemon shutdown exceeded its deadline: phase={}",
                phase.label(),
            ),
            Self::ShutdownFailed(phase, failure) => write!(
                formatter,
                "daemon shutdown failed: phase={} owner={}",
                phase.label(),
                shutdown_failure_label(*failure),
            ),
            Self::E2eeCredentials => formatter.write_str(
                "E2EE sequencer credentials file is invalid or does not match the sequencer key",
            ),
            Self::Reconstruction(surface, error) => write!(
                formatter,
                "runtime startup failed: {surface} refused the recovered state: {error}",
            ),
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
    fn from(error: ListenerError) -> Self {
        Self::Listener(error)
    }
}

/// Performs the complete read-only runtime preparation used by `serve`.
///
/// This validates the core-v1 profile, memory and crypto-worker arithmetic,
/// operator authority, listener/TLS identities, trust inputs, public text,
/// and every ready-to-use runtime policy without binding a listener or
/// starting a storage or crypto owner.
pub fn check_configuration(config: &Config, secrets: &SecretSet) -> Result<(), DaemonError> {
    validate_profile(config)?;
    let operators = operator_registry(config)?;
    let _budget = memory_budget(config)?;
    let _crypto = CryptoWorkerConfig::new(
        limit_usize(config, LimitKey::ChannelKeyJobs)?,
        limit_usize(config, LimitKey::OpaqueJobs)?,
        usize_value(config.server.crypto_worker_threads)?,
    )
    .map_err(|_| RuntimeError::InvalidValue)?;
    std::thread::scope(|scope| {
        let task = std::thread::Builder::new()
            .name("arcd-config-check".to_owned())
            .spawn_scoped(scope, move || {
                let runtime = Builder::new_current_thread()
                    .thread_name(RUNTIME_THREAD_NAME)
                    .enable_all()
                    .build()
                    .map_err(|_| DaemonError::RuntimeStart)?;
                let prepared = runtime.block_on(prepare_runtime_parts(config, secrets, operators));
                runtime.shutdown_timeout(Duration::ZERO);
                let _prepared = prepared?;
                Ok(())
            })
            .map_err(|_| DaemonError::RuntimeStart)?;
        task.join().map_err(|_| DaemonError::TaskFailed)?
    })
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
    let storage = LiveStorage::open(&config, &secrets, &operators, process_clock)?;
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

/// The profiles this build serves: a core-only coordinator, a federated
/// coordinator, and a federated edge. E2EE and worker-only nodes remain
/// deferred. Listener topology rules stay with configuration validation.
fn validate_profile(config: &Config) -> Result<(), DaemonError> {
    if !config.accounts.accept_clients {
        return Err(DaemonError::UnsupportedProfile);
    }
    if config.network.role == NodeRole::Edge && !config.federation.enabled {
        return Err(DaemonError::UnsupportedProfile);
    }
    validate_e2ee_profile(config)?;
    let federated_coordinator =
        config.federation.enabled && config.network.role == NodeRole::Coordinator;
    for listener in config.listeners.iter().filter(|listener| listener.enabled) {
        let supported = match listener.purpose {
            ConfigListenerPurpose::ClientTls
            | ConfigListenerPurpose::ClientOnion
            | ConfigListenerPurpose::AdminLocal
            | ConfigListenerPurpose::AdminTls => true,
            ConfigListenerPurpose::Federation => federated_coordinator,
            ConfigListenerPurpose::ClientWss => cfg!(feature = "wss"),
        };
        if !supported {
            return Err(DaemonError::UnsupportedProfile);
        }
    }
    Ok(())
}

/// The encrypted profile rides on the federation link (companion 12.5):
/// both roles need federation, the coordinator named by `[e2ee]` is the
/// network coordinator, and only that coordinator holds the sequencer key
/// (the configuration cross-check pins the key file to that role).
fn validate_e2ee_profile(config: &Config) -> Result<(), DaemonError> {
    if !config.e2ee.enabled {
        return Ok(());
    }
    let coordinator = Some(config.network.coordinator_server_id);
    if !config.federation.enabled || config.e2ee.coordinator_server_id != coordinator {
        return Err(DaemonError::UnsupportedProfile);
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
    // agenc-review: focus owner=runtime reviewed=2026-09-01 reason=single startup storage boundary opens reconstructs reconciles stale sessions and loads audit authority before listener admission
    fn open(
        config: &Config,
        secrets: &SecretSet,
        operators: &OperatorRegistry,
        process_clock: SystemMonotonicClock,
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
        let reconstruction_utc = SystemWallClock
            .utc_now()
            .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))?;
        let mut reconstruction = reconstruct(
            &seed,
            &owner.port(),
            &keys,
            config.network.role,
            process_clock.now(),
            reconstruction_utc,
        )
        .map_err(|error| DaemonError::Reconstruction(ReconstructionSurface::DurableState, error))?;
        reconcile_recovered_sessions(
            &owner.port(),
            &mut reconstruction,
            &keys,
            AccountingCeilings {
                database_max_bytes: config.storage.database_max_bytes,
                backup_max_bytes: config.storage.backup_max_bytes,
            },
            RecoveredSessionScope {
                local_server_id: config.server.server_id,
                keep_remote: config.federation.enabled
                    && config.network.role == NodeRole::Coordinator,
            },
        )?;
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
            MaintenanceAuditScope::new(
                config.network.network_id,
                config.server.server_id,
                storage.database_binding().database_instance_id(),
                storage.database_binding().server_incarnation(),
                storage.recovery_epoch(),
            ),
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
    federation: Option<&'a FederationSetup>,
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
        federation,
        mut storage,
        budget,
        rates,
        monotonic,
        liveness,
    } = inputs;
    let prepared = (|| -> Result<_, DaemonError> {
        let (suspensions, quarantined_channels) = storage.audit.policy_seed().into_parts();
        storage
            .reconstruction
            .domain
            .validate_retained_admin_policy(&suspensions, &quarantined_channels)
            .map_err(|_| DaemonError::Runtime(RuntimeError::InvalidValue))?;
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
        #[cfg(feature = "history")]
        let router = if config.privacy.history_enabled {
            router.with_history()?
        } else {
            router
        };
        let e2ee = e2ee_setup(
            config,
            SequencerSecrets {
                active: secrets.sequencer_private().map(SecretBytes32::expose),
                successor: secrets
                    .sequencer_successor_private()
                    .map(SecretBytes32::expose),
                retired: secrets
                    .sequencer_retired_private()
                    .map(SecretBytes32::expose),
            },
        )?;
        let mut router = attach_federation_role(config, federation, e2ee, router)?;
        router.restore_edge(
            &storage.owner.port(),
            &storage.keys,
            storage.reconstruction.head,
            crate::budget::BackingReservationPort::new(Arc::clone(&budget)),
        )?;
        let limits = operational_limits(config)?;
        let history = crate::state_core::history::HistoryState::load(
            config,
            &storage.owner.port(),
            &storage.keys,
            &storage.reconstruction.domain,
            &mut storage.reconstruction.index,
            Arc::clone(&budget),
        )
        .map_err(|error| DaemonError::Reconstruction(ReconstructionSurface::History, error))?;
        Ok((crypto_config, router, limits, history))
    })();
    let (crypto_config, router, limits, history) = match prepared {
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
            secret_lookup_floor_millis: config.privacy.secret_lookup_floor_milliseconds,
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
    let mut state = state;
    state.install_history(history);
    if federation.is_some() && config.network.role == NodeRole::Coordinator {
        // The coordinator derives edge projections from every committed
        // plan; without the projector no FEVENT would ever be produced.
        state
            .context_mut()
            .install_federation_projector(FederationProjector::new(
                config.network.network_id,
                config.server.server_id,
            ));
    }
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

fn startup_transaction_id() -> Result<TransactionId, DaemonError> {
    Ok(startup_transaction_id_value()?)
}

/// The same fresh transaction identifier as the runtime refusal an entropy
/// failure raises, for the startup paths that label their own refusals.
fn startup_transaction_id_value() -> Result<TransactionId, RuntimeError> {
    let mut bytes = [0_u8; 16];
    OsEntropy
        .fill_exact(&mut bytes)
        .map_err(|_| RuntimeError::Storage(StorageError::Unavailable))?;
    Ok(TransactionId::from_bytes(bytes))
}

/// Which recovered sessions startup closes: every local session lost its
/// connection with the process, while a federated coordinator keeps the
/// sessions its edges host so their origins can resume (spec 20.5).
#[derive(Clone, Copy)]
struct RecoveredSessionScope {
    local_server_id: ServerId,
    keep_remote: bool,
}

/// Reconciles the recovered sessions and labels **every** refusal it raises
/// with the surface that raised it.
///
/// This is the only conversion from the reconciliation's `RuntimeError` to a
/// `DaemonError`, which is what makes the label total: an inner refusal
/// cannot escape unlabelled because the inner function has no way to build a
/// `DaemonError` at all. Before this, the loop's own commit path converted
/// through `?`, so an allocation, ceiling or projection refusal printed
/// `runtime startup failed: storage owner failed: storage state is stale or
/// inconsistent` naming no surface — the exact line that sent issue #124 to
/// the storage layer — and a refused commit or read printed `storage owner
/// failed: ...` alone, which is the storage open's own line.
fn reconcile_recovered_sessions(
    storage: &StoragePort,
    reconstruction: &mut Reconstruction,
    keys: &KeyDeriver,
    ceilings: AccountingCeilings,
    scope: RecoveredSessionScope,
) -> Result<(), DaemonError> {
    reconcile_recovered_session_scope(storage, reconstruction, keys, ceilings, scope).map_err(
        |error| DaemonError::Reconstruction(ReconstructionSurface::RecoveredSessions, error),
    )
}

/// Closes every recovered session the scope owns, one committed plan at a
/// time. It returns `RuntimeError` so that no refusal it raises can reach the
/// operator without the surface its caller adds.
fn reconcile_recovered_session_scope(
    storage: &StoragePort,
    reconstruction: &mut Reconstruction,
    keys: &KeyDeriver,
    ceilings: AccountingCeilings,
    scope: RecoveredSessionScope,
) -> Result<(), RuntimeError> {
    let recovered: Vec<UserId> = reconstruction.domain.session_user_ids().collect();
    for user_id in recovered {
        let remote = reconstruction
            .domain
            .session(user_id)
            .is_some_and(|session| session.home_server_id() != scope.local_server_id);
        if scope.keep_remote && remote {
            continue;
        }
        let plan = reconstruction
            .domain
            .plan_session_disconnected(user_id)
            .map_err(|_| startup_stale_state())?;
        commit_startup_plan(storage, reconstruction, keys, ceilings, plan)?;
    }
    Ok(())
}

fn commit_startup_plan(
    storage: &StoragePort,
    reconstruction: &mut Reconstruction,
    keys: &KeyDeriver,
    ceilings: AccountingCeilings,
    plan: agenc_relay_domain::MutationPlan,
) -> Result<(), RuntimeError> {
    let transaction_id = startup_transaction_id_value()?;
    let expected_revision = plan.resulting_revision();
    let projections = [PlanProjection {
        plan: &plan,
        response_count_increment: 0,
        account_service_writes: &[],
    }];
    let mut entropy = OsEntropy;
    let projected = project_batch(
        transaction_id,
        &projections,
        &reconstruction.index,
        keys,
        reconstruction.head,
        ceilings,
        &mut entropy,
    )?
    .ok_or_else(startup_stale_state)?;
    let (batch, retained) = projected.into_parts();
    let receipt = match storage.try_commit(batch)?.wait()? {
        CommitOutcome::Committed(receipt)
            if receipt.transaction_id == transaction_id
                && receipt.state_generation == expected_revision.get() =>
        {
            receipt
        }
        CommitOutcome::Committed(_) | CommitOutcome::Indeterminate => {
            return Err(RuntimeError::Storage(StorageError::Unavailable));
        }
        CommitOutcome::Rejected(error) => return Err(RuntimeError::Storage(error)),
    };
    reconstruction.head = retained.advance(&receipt);
    reconstruction.index.apply(retained.updates());
    refresh_startup_rows(storage, reconstruction, receipt.storage_commit_sequence)?;
    let prepared = reconstruction
        .domain
        .prepare_mutation(plan)
        .map_err(|_| startup_stale_state())?;
    let applied = reconstruction
        .domain
        .apply_prepared(prepared)
        .map_err(|_| startup_stale_state())?;
    if applied.revision() != expected_revision {
        return Err(startup_stale_state());
    }
    Ok(())
}

fn refresh_startup_rows(
    storage: &StoragePort,
    reconstruction: &mut Reconstruction,
    storage_commit_sequence: u64,
) -> Result<(), RuntimeError> {
    let pending = reconstruction.index.pending_rows();
    let mut rows = Vec::new();
    rows.try_reserve_exact(pending.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for (table, key) in pending {
        let result = storage
            .try_read(ReadPlan::exact(table, key.clone()))?
            .wait()?;
        if result.storage_commit_sequence != storage_commit_sequence {
            return Err(startup_stale_state());
        }
        rows.push(read_back_record(table, key, result)?);
    }
    reconstruction.index.refresh(rows)?;
    Ok(())
}

/// The recovered-session reconciliation could not prove the state it read.
/// The surface is added once, where the reconciliation converts to a
/// `DaemonError`.
fn startup_stale_state() -> RuntimeError {
    RuntimeError::Storage(StorageError::StaleState)
}

fn registration_config(
    config: &Config,
    secrets: &SecretSet,
    runtime_config: &RuntimeConfigSnapshot,
    seed: &StateCoreSeed,
    reconstruction: &Reconstruction,
) -> Result<RegistrationRouterConfig, DaemonError> {
    let account_service = match config.network.role {
        NodeRole::Coordinator => AccountServiceRole::Hosted(Box::new(account_service_config(
            config,
            secrets,
            seed,
            reconstruction,
        )?)),
        // An edge advertises the coordinator's recovery epoch: the sealed
        // account envelopes its clients build bind to the account service
        // that opens them (spec 22.2).
        NodeRole::Edge => AccountServiceRole::Advertised {
            creation_policy: creation_policy(config, secrets)?,
            recovery_epoch: config
                .federation
                .peers
                .iter()
                .find(|peer| peer.enabled && peer.role == NodeRole::Coordinator)
                .map_or_else(
                    || seed.storage().recovery_epoch(),
                    |peer| peer.recovery_epoch,
                ),
        },
    };
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
    let fake_record = hosted_fake_opaque_record(reconstruction)?;
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

/// The fake OPAQUE record the hosted account service answers an unknown
/// login with. Reconstruction refuses a coordinator database without it, so
/// its absence here is that same durable-state refusal.
fn hosted_fake_opaque_record(
    reconstruction: &Reconstruction,
) -> Result<[u8; OPAQUE_REGISTRATION_RECORD_BYTES], DaemonError> {
    reconstruction
        .account_service
        .fake_opaque_record()
        .copied()
        .ok_or_else(|| {
            DaemonError::Reconstruction(ReconstructionSurface::DurableState, startup_stale_state())
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
    let (verifier, dummy) = channel_key_verifier()?;
    Ok(RegisteredCommandExecutor::new(verifier, dummy))
}

/// The production channel-key verifier with a fresh dummy record for
/// constant-shape verification of unknown channels.
fn channel_key_verifier()
-> Result<(Arc<dyn ChannelKeyVerifier>, ChannelKeyVerifierRecord), DaemonError> {
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
    Ok((verifier, ChannelKeyVerifierRecord::new(salt, hash)))
}

/// The federation role composed before the state owner starts: the local
/// identity, the static peer table, the operator control surface, and on an
/// edge the dial plan for its coordinator.
struct FederationSetup {
    local: LocalIdentity,
    peers: Vec<PeerIdentity>,
    control: FederationControl,
    readiness: Arc<ReadinessGate>,
    dial: Option<DialOwnerPlan>,
}

async fn federation_setup(
    config: &Config,
    secrets: &SecretSet,
    seed: &StateCoreSeed,
    readiness: Arc<ReadinessGate>,
) -> Result<Option<FederationSetup>, DaemonError> {
    if !config.federation.enabled {
        return Ok(None);
    }
    let signing = secrets
        .federation_signing()
        .ok_or(DaemonError::UnsupportedProfile)?;
    let role = match config.network.role {
        NodeRole::Coordinator => FederationRole::Coordinator,
        NodeRole::Edge => FederationRole::Edge,
    };
    let storage = seed.storage();
    let local = LocalIdentity::new(
        config.network.network_id,
        config.server.server_id,
        config.server.name.as_str(),
        storage.database_binding().server_incarnation(),
        storage.recovery_epoch(),
        role,
        Arc::new(Ed25519SecretKey::from_bytes(*signing.expose())),
    )?;
    let peers = config
        .federation
        .peers
        .iter()
        .filter(|peer| peer.enabled)
        .map(PeerIdentity::from_config)
        .collect::<Result<Vec<_>, _>>()?;
    let control = FederationControl::new(role, peers.iter().map(PeerIdentity::server_id));
    let dial = if role == FederationRole::Edge {
        Some(edge_dial_plan(config, secrets, &peers).await?)
    } else {
        None
    };
    Ok(Some(FederationSetup {
        local,
        peers,
        control,
        readiness,
        dial,
    }))
}

/// Builds the edge's dial plan. The edge presents the certificate of its
/// `federation` listener entry, which stays disabled because an edge never
/// accepts (spec C.3); the private CA bundle anchors the coordinator chain.
async fn edge_dial_plan(
    config: &Config,
    secrets: &SecretSet,
    peers: &[PeerIdentity],
) -> Result<DialOwnerPlan, DaemonError> {
    let peer_config = config
        .federation
        .peers
        .iter()
        .find(|peer| peer.enabled && peer.role == NodeRole::Coordinator)
        .ok_or(DaemonError::UnsupportedProfile)?;
    let peer = peers
        .iter()
        .find(|peer| peer.server_id() == peer_config.server_id)
        .cloned()
        .ok_or(DaemonError::UnsupportedProfile)?;
    let listener = config
        .listeners
        .iter()
        .find(|listener| listener.purpose == ConfigListenerPurpose::Federation)
        .ok_or(DaemonError::UnsupportedProfile)?;
    let files = listener
        .tls
        .as_ref()
        .ok_or(DaemonError::Tls(TlsConfigError::ClientAuthMismatch))?;
    let (chain, _fingerprint) =
        load_certificate_chain_material(files.certificate_file.clone()).await?;
    let private = secrets
        .tls_private_key(&listener.name)
        .ok_or(DaemonError::Tls(TlsConfigError::InvalidPrivateKey))?;
    let key = PrivateKey::parse(private.expose())?;
    let ca = config
        .federation
        .private_ca_file
        .clone()
        .ok_or(DaemonError::UnsupportedProfile)?;
    let (roots, _fingerprint) = load_trust_store_material(ca).await?;
    let tls = build_federation_client_config_with_group_policy(
        roots,
        (chain, key),
        *peer.certificate_spki_sha256(),
        peer.server_id(),
        config.tls.group_policy,
    )?;
    Ok(DialOwnerPlan {
        peer,
        endpoints: peer_config.endpoints.clone(),
        tls,
        connect_timeout: Duration::from_secs(config.federation.connect_timeout_seconds),
        reconnect_max: Duration::from_secs(config.federation.reconnect_max_seconds),
        tor_proxy: config.federation.tor_socks_endpoint.clone(),
    })
}

/// The companion profile of an encrypted node and, on the coordinator, the
/// executor with its sequencer installed.
struct E2eeSetup {
    profile: CompanionProfile,
    executor: Option<CompanionCoordinator>,
    /// The verified key set the ECAP tuple advertises: an edge authenticates
    /// every witness-resolution record under it (companion 12.5.1).
    key_set: agenc_relay_e2ee::sequencer::SequencerKeySet,
}

/// Reads the sequencer credentials file through one bounded, protected
/// descriptor read and verifies it as this network's key set (spec 4331,
/// 9364; companion 9.2). The declared maximum is enforced on the opened
/// descriptor's status before any allocation, so an oversized or sparse
/// file is refused before its content is read; the bytes parsed are exactly
/// the bytes that single descriptor returned, so a file that grows or is
/// replaced after inspection is refused; and every failure maps to the
/// closed `E2eeCredentials` error, which carries neither the path nor any
/// document byte. Offline `print-onboarding` reuses this reader.
pub(crate) fn load_sequencer_credentials(
    path: &Path,
    network: &[u8; 32],
    after_initial_status: impl FnOnce(),
) -> Result<
    (
        agenc_relay_e2ee::sequencer::SequencerCredentialsFile,
        agenc_relay_e2ee::sequencer::SequencerKeySet,
    ),
    DaemonError,
> {
    use agenc_relay_e2ee::sequencer::{
        MAX_SEQUENCER_CREDENTIALS_FILE_BYTES, SequencerCredentialsFile,
    };
    let maximum = u64::try_from(MAX_SEQUENCER_CREDENTIALS_FILE_BYTES)
        .map_err(|_| DaemonError::E2eeCredentials)?;
    let bytes =
        agenc_relay_config::read_protected_bytes_with_hook(path, maximum, after_initial_status)
            .map_err(|_| DaemonError::E2eeCredentials)?;
    let document =
        SequencerCredentialsFile::parse(&bytes).map_err(|_| DaemonError::E2eeCredentials)?;
    let key_set = document
        .key_set(network)
        .map_err(|_| DaemonError::E2eeCredentials)?;
    Ok((document, key_set))
}

/// Reads and verifies the sequencer credentials file when `[e2ee]` is
/// enabled: the key set must verify for this network, and the coordinator's
/// sequencer key must be one of the credentials (spec 9200, 9201).
/// The configured sequencer private key seeds by companion 9.2.1 role.
#[derive(Clone, Copy, Default)]
struct SequencerSecrets<'a> {
    active: Option<&'a [u8; 32]>,
    successor: Option<&'a [u8; 32]>,
    retired: Option<&'a [u8; 32]>,
}

fn e2ee_setup(
    config: &Config,
    sequencer: SequencerSecrets<'_>,
) -> Result<Option<E2eeSetup>, DaemonError> {
    e2ee_setup_with_hook(config, sequencer, || {})
}

/// [`e2ee_setup`] with the credentials read's post-inspection hook exposed,
/// so tests can race the real composition path.
fn e2ee_setup_with_hook(
    config: &Config,
    sequencer: SequencerSecrets<'_>,
    after_initial_status: impl FnOnce(),
) -> Result<Option<E2eeSetup>, DaemonError> {
    use agenc_relay_e2ee::profile::EcapTuple;
    use agenc_relay_e2ee::wire::tokens::base64url_encode;
    if !config.e2ee.enabled {
        return Ok(None);
    }
    let path = config
        .e2ee
        .sequencer_credentials_file
        .as_ref()
        .ok_or(DaemonError::UnsupportedProfile)?;
    let network = *config.network.network_id.as_bytes();
    let (document, key_set) = load_sequencer_credentials(path, &network, after_initial_status)?;
    let coordinator = config
        .e2ee
        .coordinator_server_id
        .ok_or(DaemonError::UnsupportedProfile)?;
    let tuple = EcapTuple::local(
        &base64url_encode(&network),
        &base64url_encode(coordinator.as_bytes()),
        key_set.set_generation,
        &base64url_encode(&key_set.digest),
    )
    .map_err(|_| DaemonError::E2eeCredentials)?;
    let profile = CompanionProfile { local: tuple };
    let negotiated = key_set.clone();
    let executor = match config.network.role {
        NodeRole::Coordinator => {
            let seed = sequencer.active.ok_or(DaemonError::UnsupportedProfile)?;
            let key = Ed25519SecretKey::from_bytes(*seed);
            let public = *key.public_key().as_bytes();
            // The active key serves the credential the file lists first; the
            // successor key is required exactly when the file holds a
            // successor (spec 9457).
            let current = document
                .credentials
                .as_slice()
                .first()
                .filter(|credential| credential.tbs.sequencer_public_key == public)
                .cloned()
                .ok_or(DaemonError::E2eeCredentials)?;
            let successor = match (sequencer.successor, document.credentials.as_slice().len()) {
                (Some(seed), 2) => Some(Ed25519SecretKey::from_bytes(*seed)),
                (None, 1) => None,
                _ => return Err(DaemonError::E2eeCredentials),
            };
            let mut executor = CompanionCoordinator::new(
                network,
                config.server.server_id,
                config.server.name.as_str().to_owned(),
            );
            executor
                .install_signers(key, key_set, current, successor, None)
                .map_err(|_| DaemonError::E2eeCredentials)?;
            if let Some(seed) = sequencer.retired {
                executor.configure_retired_key(Ed25519SecretKey::from_bytes(*seed));
            }
            executor.set_global_disk_bytes(config.e2ee.global_disk_bytes);
            Some(executor)
        }
        NodeRole::Edge => None,
    };
    Ok(Some(E2eeSetup {
        profile,
        executor,
        key_set: negotiated,
    }))
}

/// Attaches the coordinator or edge role to the registration router, with
/// the companion profile and the E2EE router or executor when `[e2ee]` is
/// enabled.
fn attach_federation_role(
    config: &Config,
    setup: Option<&FederationSetup>,
    e2ee: Option<E2eeSetup>,
    router: RegistrationRouter,
) -> Result<RegistrationRouter, DaemonError> {
    let Some(setup) = setup else {
        return Ok(router);
    };
    match config.network.role {
        NodeRole::Coordinator => attach_coordinator_role(config, setup, e2ee, router),
        NodeRole::Edge => attach_edge_role(config, setup, e2ee, router),
    }
}

fn attach_coordinator_role(
    config: &Config,
    setup: &FederationSetup,
    e2ee: Option<E2eeSetup>,
    router: RegistrationRouter,
) -> Result<RegistrationRouter, DaemonError> {
    let mut entropy = OsEntropy;
    let mut query_cursor_key = [0_u8; 32];
    let mut process_nonce = [0_u8; 16];
    entropy
        .fill_exact(&mut query_cursor_key)
        .map_err(|_| CryptoError::EntropyUnavailable)?;
    entropy
        .fill_exact(&mut process_nonce)
        .map_err(|_| CryptoError::EntropyUnavailable)?;
    let (verifier, dummy) = channel_key_verifier()?;
    let mut coordinator = FederationCoordinator::new(
        CoordinatorConfig {
            network_id: config.network.network_id,
            server_id: config.server.server_id,
            server_name: config.server.name.as_str().to_owned(),
            recovery_epoch: setup.local.recovery_epoch(),
            query_cursor_key,
            process_nonce,
            outbox_bytes_per_edge: config.limits.values.get(LimitKey::BaseOutboxBytesPerEdge),
            outbox_objects_per_edge: config.limits.values.get(LimitKey::BaseOutboxObjectsPerEdge),
        },
        setup.peers.clone(),
        verifier,
        dummy,
    );
    if let Some(e2ee) = e2ee {
        coordinator.set_companion_profile(Some(e2ee.profile));
        if let Some(executor) = e2ee.executor {
            coordinator
                .install_companion_executor(executor, setup.local.incarnation())
                .map_err(|_| DaemonError::E2eeCredentials)?;
        }
    }
    Ok(router.with_federation(coordinator))
}

fn attach_edge_role(
    config: &Config,
    setup: &FederationSetup,
    e2ee: Option<E2eeSetup>,
    router: RegistrationRouter,
) -> Result<RegistrationRouter, DaemonError> {
    let server_name = config.server.name.as_str().to_owned();
    let coordinator = setup
        .peers
        .first()
        .cloned()
        .ok_or(DaemonError::UnsupportedProfile)?;
    let coordinator_server_id = coordinator.server_id();
    let mut edge = EdgeFederation::new(EdgeConfig {
        network_id: config.network.network_id,
        server_id: config.server.server_id,
        server_name: server_name.clone(),
        incarnation: setup.local.incarnation(),
        coordinator,
    })
    .with_readiness(Arc::clone(&setup.readiness));
    let Some(e2ee) = e2ee else {
        return Ok(router.with_edge(edge));
    };
    edge.set_companion_profile(Some(e2ee.profile));
    let e2ee_edge = E2eeEdge::new(E2eeEdgeConfig {
        network_id: *config.network.network_id.as_bytes(),
        server_id: config.server.server_id,
        server_name,
        coordinator_server_id,
        sequencer_key_set: Some(e2ee.key_set),
        incarnation: *setup.local.incarnation().as_bytes(),
        global_disk_bytes: config.e2ee.global_disk_bytes,
    });
    Ok(router.with_edge(edge).with_e2ee_edge(e2ee_edge)?)
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
        ConfigListenerPurpose::Federation => Ok(ListenerPurpose::Federation),
        ConfigListenerPurpose::ClientWss if cfg!(feature = "wss") => Ok(ListenerPurpose::ClientWss),
        ConfigListenerPurpose::ClientWss => Err(DaemonError::UnsupportedProfile),
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
    tls_endpoints: BTreeMap<agenc_relay_config::ListenerName, Arc<rustls::ServerConfig>>,
    certificate_fingerprints: BTreeMap<agenc_relay_config::ListenerName, [u8; 32]>,
    ocsp_fingerprints: BTreeMap<agenc_relay_config::ListenerName, [u8; 32]>,
    client_ca_fingerprints: BTreeMap<agenc_relay_config::ListenerName, [u8; 32]>,
    public_identities: PublicIdentitySet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicIdentityPurpose {
    AccountHpke,
    AdminCa,
    AdminListenerTls,
    AdminOperator,
    AdminOperatorCertificate,
    AuditSigning,
    BackupSigning,
    ClientListenerTls,
    FederationCa,
    FederationListenerTls,
    FederationPeer,
    FederationPeerCertificate,
    FederationSigning,
    InvitationSigning,
    OpaqueServer,
    SequencerSigning,
}

#[derive(Default)]
struct PublicIdentitySet {
    purposes: BTreeMap<[u8; 32], PublicIdentityPurpose>,
}

impl PublicIdentitySet {
    fn insert(
        &mut self,
        identity: [u8; 32],
        purpose: PublicIdentityPurpose,
    ) -> Result<(), DaemonError> {
        if self.purposes.insert(identity, purpose).is_some() {
            return Err(DaemonError::Runtime(RuntimeError::InvalidValue));
        }
        Ok(())
    }

    fn insert_alias(
        &mut self,
        identity: [u8; 32],
        purpose: PublicIdentityPurpose,
    ) -> Result<(), DaemonError> {
        match self.purposes.get(&identity) {
            Some(existing) if *existing == purpose => Ok(()),
            Some(_) => Err(DaemonError::Runtime(RuntimeError::InvalidValue)),
            None => {
                self.purposes.insert(identity, purpose);
                Ok(())
            }
        }
    }
}

fn prepared_public_identities(
    config: &Config,
    secrets: &SecretSet,
) -> Result<PublicIdentitySet, DaemonError> {
    let mut identities = PublicIdentitySet::default();
    insert_signing_identity(
        &mut identities,
        secrets.backup_signing().expose(),
        PublicIdentityPurpose::BackupSigning,
    )?;
    insert_signing_identity(
        &mut identities,
        secrets.audit_signing().expose(),
        PublicIdentityPurpose::AuditSigning,
    )?;
    if let Some(secret) = secrets.federation_signing() {
        insert_signing_identity(
            &mut identities,
            secret.expose(),
            PublicIdentityPurpose::FederationSigning,
        )?;
    }
    if let Some(secret) = secrets.sequencer_private() {
        insert_signing_identity(
            &mut identities,
            secret.expose(),
            PublicIdentityPurpose::SequencerSigning,
        )?;
    }
    if let Some(authority) = secrets.invitation_verification() {
        let public = Ed25519PublicKey::from_bytes(*authority.expose())?;
        identities.insert(*public.as_bytes(), PublicIdentityPurpose::InvitationSigning)?;
    }

    let configured_hpke =
        AccountHpkePublicKey::from_bytes(config.accounts.account_service_hpke_public_key)?;
    if let Some(private) = secrets.account_service_hpke_private() {
        let public = AccountHpkePrivateKey::from_bytes(*private.expose())?.public_key()?;
        if public != configured_hpke {
            return Err(DaemonError::Cryptography(CryptoError::AuthenticationFailed));
        }
    }
    identities.insert(
        *configured_hpke.as_bytes(),
        PublicIdentityPurpose::AccountHpke,
    )?;

    if let Some(setup) = secrets.opaque_server_setup() {
        let setup = setup
            .expose()
            .try_into()
            .map_err(|_| DaemonError::Authentication(AuthError::InvalidEncoding))?;
        identities.insert(
            opaque_server_public_key(setup)?,
            PublicIdentityPurpose::OpaqueServer,
        )?;
    }

    for peer in &config.federation.peers {
        let public = Ed25519PublicKey::from_bytes(peer.signing_public_key)?;
        identities.insert(*public.as_bytes(), PublicIdentityPurpose::FederationPeer)?;
        identities.insert(
            peer.certificate_spki_sha256,
            PublicIdentityPurpose::FederationPeerCertificate,
        )?;
    }
    for operator in &config.moderation.operators {
        let public = Ed25519PublicKey::from_bytes(operator.signing_public_key)?;
        identities.insert(*public.as_bytes(), PublicIdentityPurpose::AdminOperator)?;
        if let Some(pin) = operator.certificate_spki_sha256 {
            identities.insert(pin, PublicIdentityPurpose::AdminOperatorCertificate)?;
        }
    }
    Ok(identities)
}

fn insert_signing_identity(
    identities: &mut PublicIdentitySet,
    secret: &[u8; 32],
    purpose: PublicIdentityPurpose,
) -> Result<(), DaemonError> {
    let public = Ed25519SecretKey::from_bytes(*secret).public_key();
    identities.insert(*public.as_bytes(), purpose)
}

fn insert_listener_identity(
    identities: &mut PublicIdentitySet,
    purpose: ConfigListenerPurpose,
    chain: &crate::tls::CertChain,
) -> Result<(), DaemonError> {
    let identity_purpose = match purpose.key_class() {
        0 => PublicIdentityPurpose::ClientListenerTls,
        1 => PublicIdentityPurpose::FederationListenerTls,
        2 => PublicIdentityPurpose::AdminListenerTls,
        _ => return Err(DaemonError::Runtime(RuntimeError::InvalidValue)),
    };
    let leaf = chain
        .leaf()
        .ok_or(DaemonError::Tls(TlsConfigError::InvalidCertificate))?;
    let identity =
        spki_sha256(leaf.as_ref()).ok_or(DaemonError::Tls(TlsConfigError::InvalidCertificate))?;
    identities.insert_alias(identity, identity_purpose)
}

fn insert_ca_identities(
    identities: &mut PublicIdentitySet,
    store: &crate::tls::TrustStore,
    purpose: PublicIdentityPurpose,
) -> Result<(), DaemonError> {
    for identity in store.spki_identities() {
        identities.insert_alias(*identity, purpose)?;
    }
    Ok(())
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=one closed listener preparation pass validates active listener and outbound TLS identities CA and admission profiles before activation
async fn build_listener_specs(
    config: &Config,
    secrets: &SecretSet,
) -> Result<PreparedListenerSpecs, DaemonError> {
    let mut specs = Vec::new();
    let mut tls_endpoints = BTreeMap::new();
    let mut certificate_fingerprints = BTreeMap::new();
    let mut ocsp_fingerprints = BTreeMap::new();
    let mut client_ca_fingerprints = BTreeMap::new();
    let mut public_identities = prepared_public_identities(config, secrets)?;
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
            insert_listener_identity(&mut public_identities, listener.purpose, &chain)?;
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
                let ca_purpose = match purpose {
                    ListenerPurpose::AdminTls => PublicIdentityPurpose::AdminCa,
                    ListenerPurpose::Federation => PublicIdentityPurpose::FederationCa,
                    _ => return Err(DaemonError::Runtime(RuntimeError::InvalidValue)),
                };
                insert_ca_identities(&mut public_identities, &store, ca_purpose)?;
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
                config.tls.require_ocsp_staple
                    && matches!(
                        purpose,
                        ListenerPurpose::ClientTls | ListenerPurpose::ClientWss
                    ),
            );
            let ocsp_staple = match files.ocsp_staple_file.clone() {
                Some(path) => {
                    let (staple, fingerprint) = load_ocsp_staple_material(path).await?;
                    if ocsp_fingerprints
                        .insert(listener.name.clone(), fingerprint)
                        .is_some()
                    {
                        return Err(DaemonError::Runtime(RuntimeError::InvalidValue));
                    }
                    Some(staple)
                }
                None => None,
            };
            let endpoint = build_server_config_with_policy(
                profile,
                chain,
                key,
                client_auth,
                policy,
                ocsp_staple,
            )
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
    for listener in config
        .listeners
        .iter()
        .filter(|listener| !listener.enabled && config.listener_material_required(listener))
    {
        if let Some(tls) = &listener.tls {
            let (chain, fingerprint) =
                load_certificate_chain_material(tls.certificate_file.clone()).await?;
            insert_listener_identity(&mut public_identities, listener.purpose, &chain)?;
            let private = secrets
                .tls_private_key(&listener.name)
                .ok_or(DaemonError::Tls(TlsConfigError::InvalidPrivateKey))?;
            let key = PrivateKey::parse(private.expose())?;
            let validation_policy = TlsServerPolicy::new(config.tls.group_policy, false, false);
            let ocsp_staple = match tls.ocsp_staple_file.clone() {
                Some(path) => {
                    let (staple, fingerprint) = load_ocsp_staple_material(path).await?;
                    if ocsp_fingerprints
                        .insert(listener.name.clone(), fingerprint)
                        .is_some()
                    {
                        return Err(DaemonError::Runtime(RuntimeError::InvalidValue));
                    }
                    Some(staple)
                }
                None => None,
            };
            let _validated_identity = build_server_config_with_policy(
                TlsEndpointProfile::Client,
                chain,
                key,
                ClientAuth::None,
                validation_policy,
                ocsp_staple,
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
    for listener in config
        .listeners
        .iter()
        .filter(|listener| config.listener_material_required(listener))
    {
        if let Some(path) = listener.client_ca_file.clone()
            && !client_ca_fingerprints.contains_key(&listener.name)
        {
            let (store, fingerprint) = load_trust_store_material(path).await?;
            let ca_purpose = match listener.purpose {
                ConfigListenerPurpose::AdminTls => PublicIdentityPurpose::AdminCa,
                ConfigListenerPurpose::Federation => PublicIdentityPurpose::FederationCa,
                _ => return Err(DaemonError::Runtime(RuntimeError::InvalidValue)),
            };
            insert_ca_identities(&mut public_identities, &store, ca_purpose)?;
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
        ocsp_fingerprints,
        client_ca_fingerprints,
        public_identities,
    })
}

struct PreparedRuntimeFiles {
    motd: Option<Arc<str>>,
    public_info: Option<Arc<str>>,
    backup_trust: [u8; 32],
    audit_trust: [u8; 32],
    backup_trust_identities: Vec<[u8; 32]>,
    audit_trust_identities: Vec<[u8; 32]>,
}

async fn prepare_runtime_parts(
    config: &Config,
    secrets: &SecretSet,
    operators: OperatorRegistry,
) -> Result<(RuntimeConfigParts, Vec<ListenerSpec>), DaemonError> {
    let operator_admission = operator_admission(config);
    let (default_presence, default_guest_direct_messages, default_direct_messages) =
        account_defaults(config);
    let mut prepared = build_listener_specs(config, secrets).await?;
    let files = load_runtime_files(config).await?;
    let restart_material = prepare_restart_material(config, secrets, &mut prepared, &files).await?;
    let parts = RuntimeConfigParts {
        tls_endpoints: prepared.tls_endpoints,
        certificate_fingerprints: prepared.certificate_fingerprints,
        ocsp_fingerprints: prepared.ocsp_fingerprints,
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

async fn prepare_restart_material(
    config: &Config,
    secrets: &SecretSet,
    prepared: &mut PreparedListenerSpecs,
    files: &PreparedRuntimeFiles,
) -> Result<RestartMaterial, DaemonError> {
    let federation_ca = match config.federation.private_ca_file.clone() {
        Some(path) => {
            let (store, fingerprint) = load_trust_store_material(path).await?;
            insert_ca_identities(
                &mut prepared.public_identities,
                &store,
                PublicIdentityPurpose::FederationCa,
            )?;
            Some(fingerprint)
        }
        None => None,
    };
    for identity in &files.backup_trust_identities {
        prepared
            .public_identities
            .insert_alias(*identity, PublicIdentityPurpose::BackupSigning)?;
    }
    for identity in &files.audit_trust_identities {
        prepared
            .public_identities
            .insert_alias(*identity, PublicIdentityPurpose::AuditSigning)?;
    }
    restart_material(
        config,
        secrets,
        files.backup_trust,
        files.audit_trust,
        federation_ca,
        &prepared.client_ca_fingerprints,
    )
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
            backup_trust_identities: collect_public_identities(
                backup.iter().map(|entry| entry.ed25519_public_key),
            )?,
            audit_trust_identities: collect_public_identities(
                audit.iter().map(|entry| entry.ed25519_public_key),
            )?,
        })
    })
    .await
    .map_err(|_| DaemonError::TaskFailed)?
}

fn collect_public_identities(
    identities: impl ExactSizeIterator<Item = [u8; 32]>,
) -> Result<Vec<[u8; 32]>, DaemonError> {
    let mut collected = Vec::new();
    collected
        .try_reserve_exact(identities.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    collected.extend(identities);
    Ok(collected)
}

fn backup_trust_fingerprint(
    entries: &[agenc_relay_config::BackupTrustManifestEntry],
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
    entries: &[agenc_relay_config::AuditTrustManifestEntry],
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
    entries: Vec<agenc_relay_config::BackupTrustManifestEntry>,
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
    client_ca: &BTreeMap<agenc_relay_config::ListenerName, [u8; 32]>,
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
            .map(agenc_relay_config::SecretBlob::expose),
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
    for listener in config
        .listeners
        .iter()
        .filter(|listener| config.listener_material_required(listener))
    {
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
    let federation =
        match federation_setup(&config, &secrets, &storage.seed, Arc::clone(&readiness)).await {
            Ok(federation) => federation,
            Err(error) => {
                return Err(unwind_live_storage_and_log(
                    storage,
                    log_owner,
                    startup_deadline,
                    error,
                )
                .await);
            }
        };
    // An edge becomes ready only once its coordinator link is ACTIVE; every
    // other profile has no synchronization to wait for.
    if !(config.network.role == NodeRole::Edge && federation.is_some()) {
        readiness.mark(ReadinessStage::Federation);
    }
    let mut live = match build_live_state(BuildLiveStateInputs {
        config: &config,
        secrets: &secrets,
        runtime_config: snapshot.as_ref(),
        federation: federation.as_ref(),
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
    let (inbox, inbox_receiver) = mpsc::channel(CLIENT_EVENT_CAPACITY);
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
    let (federation_inbound, federation_receiver) = mpsc::channel(INBOUND_QUEUE_ITEMS);
    if federation.is_some()
        && let Err(error) = live.state.install_federation_inbox(federation_receiver)
    {
        return Err(
            unwind_live_state_and_log(live, log_owner, startup_deadline, error.into()).await,
        );
    }
    let (federation_accepts, federation_sockets) = mpsc::channel(MAX_FEDERATION_PEERS);
    let accepts_federation = federation.is_some() && config.network.role == NodeRole::Coordinator;
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
        accepts_federation.then_some(federation_accepts),
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
    if let Some(setup) = &federation
        && let Err(error) = admin_owner.install_federation_control(setup.control.clone())
    {
        drop(admin_owner);
        return Err(
            unwind_live_state_and_log(live, log_owner, startup_deadline, error.into()).await,
        );
    }
    let federation_owner = federation.map(|setup| {
        let outbound_bytes = config.limits.values.get(LimitKey::FederationOutputBytes);
        let shared = Arc::new(LinkOwnerShared::new(
            setup.local,
            setup.peers,
            federation_inbound,
            Some(Arc::clone(&observer)),
            outbound_bytes,
        ));
        let kind = match setup.dial {
            Some(plan) => FederationOwnerKind::Dial(Box::new(plan)),
            None => FederationOwnerKind::Accept(federation_sockets),
        };
        FederationOwnerStart {
            shared,
            control: setup.control,
            kind,
        }
    });
    let RunningOwners {
        owner,
        log_owner,
        mut supervisor,
        control,
        lifecycle,
        admin_lifecycle,
        mut signals,
        mut maintenance_exited,
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
        federation: federation_owner,
        readiness: Arc::clone(&readiness),
        liveness: Arc::clone(&liveness),
    }))
    .await?;
    observer.state_core_ready();
    let shutdown_wait = wait_for_shutdown(ShutdownWaitInputs {
        config_path: &config_path,
        runtime_config: &runtime_config,
        reload: &reload,
        reload_preparation: &mut reload_preparation,
        admin_failed: &mut admin_failed,
        admin_process: &mut admin_process_inbox,
        budget: Arc::clone(&budget),
        storage: &reload_storage,
        signals: &mut signals,
        maintenance_exited: &mut maintenance_exited,
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
        pending_reload: shutdown_wait.pending_reload,
        log_flush: TrackedLogFlush::default(),
        stop_failure: None,
    };
    let report = run_shutdown(shutdown, &mut hooks, &mut signals).await;
    let shutdown_result = validate_shutdown_report(report);
    finish_daemon_run(shutdown_wait.trigger, shutdown_result)
}

fn finish_daemon_run(
    trigger: Result<ShutdownTrigger, DaemonError>,
    shutdown: Result<(), DaemonError>,
) -> Result<DaemonExit, DaemonError> {
    let trigger = trigger?;
    shutdown?;
    Ok(match trigger {
        ShutdownTrigger::Signal | ShutdownTrigger::CommittedDie => DaemonExit::Stopped,
        ShutdownTrigger::CommittedRestart => DaemonExit::RestartRequested,
    })
}

struct RunningOwners {
    owner: StorageOwner,
    log_owner: FileLogOwner,
    supervisor: Supervisor,
    control: ListenerControl,
    lifecycle: LifecycleControl,
    admin_lifecycle: AdminLifecycleControl,
    signals: mpsc::Receiver<SignalEvent>,
    maintenance_exited: oneshot::Receiver<Result<(), RuntimeError>>,
    state_exited: oneshot::Receiver<StateCoreExit>,
    listener_exited: oneshot::Receiver<()>,
}

struct BackgroundOwners {
    signals: mpsc::Receiver<SignalEvent>,
    maintenance_exited: oneshot::Receiver<Result<(), RuntimeError>>,
}

struct AdminOwnerStart {
    owner: AdminOwner,
    inbox: AdminOwnerInbox,
}

/// Which link owner the federation role runs.
enum FederationOwnerKind {
    /// The coordinator's accept owner over the federation listener's sockets.
    Accept(mpsc::Receiver<AcceptedFederationSocket>),
    /// The edge's dial owner for its coordinator.
    Dial(Box<DialOwnerPlan>),
}

struct FederationOwnerStart {
    shared: Arc<LinkOwnerShared>,
    control: FederationControl,
    kind: FederationOwnerKind,
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
    federation: Option<FederationOwnerStart>,
    readiness: Arc<ReadinessGate>,
    liveness: Arc<Liveness>,
}

// agenc-review: focus owner=runtime reviewed=2026-08-31 reason=single startup barrier constructs every bounded owner before listener admission and unwinds storage on acknowledgement failure
async fn start_owners(inputs: StartOwnersInputs) -> Result<RunningOwners, DaemonError> {
    let StartOwnersInputs {
        specs,
        context,
        mut live,
        log_owner,
        startup_deadline,
        inbox_receiver,
        connection_close_inbox,
        inbox: _inbox,
        admission,
        admin,
        federation,
        readiness,
        liveness,
    } = inputs;
    let (maintenance, maintenance_receiver) = mpsc::channel(MAINTENANCE_EVENT_CAPACITY);
    if let Err(error) = live.state.install_maintenance_inbox(maintenance_receiver) {
        return Err(
            unwind_live_state_and_log(live, log_owner, startup_deadline, error.into()).await,
        );
    }
    if let Err(error) = live.state.install_client_inputs() {
        return Err(
            unwind_live_state_and_log(live, log_owner, startup_deadline, error.into()).await,
        );
    }
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
    // The link owners start after the state owner so every `Established`
    // reaches a running federation inbox, and before any listener accepts.
    if let Some(start) = federation
        && let Err(error) = spawn_federation_owner(&mut supervisor, start)
    {
        return Err(unwind_started_owners(
            &mut supervisor,
            owner,
            log_owner,
            startup_deadline,
            error,
        )
        .await);
    }
    // Signal handlers are installed before any listener accepts, so a stop
    // request during startup always reaches the phased shutdown.
    let background = match spawn_background_owners(&mut supervisor, &maintenance, admission) {
        Ok(background) => background,
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
    Ok(RunningOwners {
        owner,
        log_owner,
        supervisor,
        control,
        lifecycle,
        admin_lifecycle,
        signals: background.signals,
        maintenance_exited: background.maintenance_exited,
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
            let _diagnostics = exits?;
            Ok(())
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

fn spawn_federation_owner(
    supervisor: &mut Supervisor,
    start: FederationOwnerStart,
) -> Result<(), DaemonError> {
    let FederationOwnerStart {
        shared,
        control,
        kind,
    } = start;
    supervisor.spawn(
        ChildName::FederationLinks,
        ChildKind::Critical,
        |token| async move {
            match kind {
                FederationOwnerKind::Accept(sockets) => {
                    run_accept_owner(sockets, shared, control, token).await
                }
                FederationOwnerKind::Dial(plan) => {
                    run_dial_owner(*plan, shared, control, token).await
                }
            }
        },
    )?;
    Ok(())
}

fn spawn_background_owners(
    supervisor: &mut Supervisor,
    inbox: &mpsc::Sender<MaintenanceEvent>,
    admission: Arc<TransportAdmission>,
) -> Result<BackgroundOwners, DaemonError> {
    let (signals, signal_receiver) = mpsc::channel(SIGNAL_EVENT_CAPACITY);
    supervisor.spawn(ChildName::SignalTask, ChildKind::Critical, |token| {
        run_signal_task(token, signals)
    })?;
    let maintenance_inbox = inbox.clone();
    let (maintenance_exit, maintenance_exited) = oneshot::channel();
    supervisor.spawn(ChildName::MaintenanceTask, ChildKind::Critical, |token| {
        report_maintenance_completion(
            run_maintenance(token, maintenance_inbox, admission),
            maintenance_exit,
        )
    })?;
    Ok(BackgroundOwners {
        signals: signal_receiver,
        maintenance_exited,
    })
}

async fn report_maintenance_completion<F>(
    task: F,
    completion: oneshot::Sender<Result<(), RuntimeError>>,
) -> Result<(), RuntimeError>
where
    F: Future<Output = Result<(), RuntimeError>>,
{
    let result = task.await;
    let _sent = completion.send(result);
    result
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
    federation_accepts: Option<mpsc::Sender<AcceptedFederationSocket>>,
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
        federation_accepts,
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
    maintenance_exited: &'a mut oneshot::Receiver<Result<(), RuntimeError>>,
    state_exited: &'a mut oneshot::Receiver<StateCoreExit>,
    listener_exited: &'a mut oneshot::Receiver<()>,
    liveness: Arc<Liveness>,
    monotonic: SystemMonotonicClock,
    observer: Arc<RuntimeObserver>,
}

type ReloadPreparationFuture =
    Pin<Box<dyn Future<Output = Result<PreparedReload, ReloadPrepareFailure>> + Send + 'static>>;
type ReloadActivationFuture = Pin<Box<dyn Future<Output = ReloadOutcome> + Send + 'static>>;

struct PendingReloadWork {
    preparation: Option<ReloadPreparationFuture>,
    observe_discarded_signal_preparation: bool,
    activation: Option<ReloadActivationFuture>,
}

impl PendingReloadWork {
    async fn finish(&mut self) -> Option<bool> {
        let mut observation = None;
        if let Some(preparation) = self.preparation.as_mut() {
            let _discarded = preparation.as_mut().await;
            self.preparation = None;
            if self.observe_discarded_signal_preparation {
                observation = Some(false);
            }
            self.observe_discarded_signal_preparation = false;
        }
        if let Some(activation) = self.activation.as_mut() {
            let outcome = activation.as_mut().await;
            self.activation = None;
            observation = Some(matches!(
                outcome,
                ReloadOutcome::Applied(_) | ReloadOutcome::NoChange(_)
            ));
        }
        observation
    }
}

struct ShutdownWaitResult {
    trigger: Result<ShutdownTrigger, DaemonError>,
    pending_reload: PendingReloadWork,
}

fn reload_preparation_future(
    config_path: &Path,
    runtime_config: &RuntimeConfigHandle,
    budget: &Arc<MemoryBudget>,
    storage: &StoragePort,
) -> ReloadPreparationFuture {
    Box::pin(prepare_reload(
        config_path.to_path_buf(),
        runtime_config.clone(),
        Arc::clone(budget),
        storage.clone(),
    ))
}

fn reload_activation_future(
    reload: &ReloadPort,
    prepared: PreparedReload,
) -> ReloadActivationFuture {
    let reload = reload.clone();
    Box::pin(async move { reload.activate_signal(prepared).await })
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=closed owner loop keeps termination selectable while serializing admin preparation signal coalescing activation progress and critical owner exits
async fn wait_for_shutdown(inputs: ShutdownWaitInputs<'_>) -> ShutdownWaitResult {
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
        maintenance_exited,
        state_exited,
        listener_exited,
        liveness,
        monotonic,
        observer,
    } = inputs;
    let mut progress = tokio::time::interval(Duration::from_secs(5));
    progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    progress.tick().await;
    liveness.record_supervisor(monotonic.now());
    let mut preparation: Option<ReloadPreparationFuture> = None;
    let mut preparation_origin = None;
    let mut activation: Option<ReloadActivationFuture> = None;
    let mut pending_sighup = false;
    let mut maintenance_running = true;
    let trigger = loop {
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
            maintenance = &mut *maintenance_exited, if maintenance_running => {
                Some(SupervisorEvent::Maintenance(maintenance))
            },
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
                    preparation = Some(reload_preparation_future(
                        config_path,
                        runtime_config,
                        &budget,
                        storage,
                    ));
                    preparation_origin = Some(ReloadPreparationOrigin::Signal);
                }
            }
            SupervisorEvent::ReloadPreparation(Some(reply)) => {
                if preparation.is_some() || activation.is_some() || pending_sighup {
                    reply.send(Err(ReloadPrepareFailure::Busy));
                } else {
                    preparation = Some(reload_preparation_future(
                        config_path,
                        runtime_config,
                        &budget,
                        storage,
                    ));
                    preparation_origin = Some(ReloadPreparationOrigin::Admin(reply));
                }
            }
            SupervisorEvent::Prepared(result) => {
                preparation = None;
                match preparation_origin.take() {
                    Some(ReloadPreparationOrigin::Signal) => match result {
                        Ok(prepared) if prepared.permits_signal_activation() => {
                            activation = Some(reload_activation_future(reload, prepared));
                        }
                        Ok(_raised_candidate) => observer.reload(false),
                        Err(ReloadPrepareFailure::Busy) => pending_sighup = true,
                        Err(_) => observer.reload(false),
                    },
                    Some(ReloadPreparationOrigin::Admin(reply)) => reply.send(result),
                    None => break Err(DaemonError::TaskFailed),
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
                preparation = Some(reload_preparation_future(
                    config_path,
                    runtime_config,
                    &budget,
                    storage,
                ));
                preparation_origin = Some(ReloadPreparationOrigin::Signal);
            }
            SupervisorEvent::Signal(Some(SignalEvent::Terminate | SignalEvent::Interrupt)) => {
                break Ok(ShutdownTrigger::Signal);
            }
            SupervisorEvent::AdminProcess(Some(AdminProcessAction::Die)) => {
                break Ok(ShutdownTrigger::CommittedDie);
            }
            SupervisorEvent::AdminProcess(Some(AdminProcessAction::Restart)) => {
                break Ok(ShutdownTrigger::CommittedRestart);
            }
            SupervisorEvent::State(completion) => {
                break Err(state_completion_failure(completion, observer.as_ref()));
            }
            SupervisorEvent::Maintenance(completion) => {
                if let Some(error) = maintenance_completion_failure(completion) {
                    break Err(error);
                }
                maintenance_running = false;
            }
            SupervisorEvent::Signal(None)
            | SupervisorEvent::ReloadPreparation(None)
            | SupervisorEvent::AdminProcess(None)
            | SupervisorEvent::AdminFailure
            | SupervisorEvent::Listener => {
                break Err(DaemonError::TaskFailed);
            }
        }
    };
    let observe_discarded_signal_preparation =
        matches!(preparation_origin, Some(ReloadPreparationOrigin::Signal));
    if let Some(ReloadPreparationOrigin::Admin(reply)) = preparation_origin {
        reply.send(Err(ReloadPrepareFailure::Unavailable));
    }
    ShutdownWaitResult {
        trigger,
        pending_reload: PendingReloadWork {
            preparation,
            observe_discarded_signal_preparation,
            activation,
        },
    }
}

fn maintenance_completion_failure(
    completion: Result<Result<(), RuntimeError>, oneshot::error::RecvError>,
) -> Option<DaemonError> {
    match completion {
        Ok(Ok(())) => None,
        Ok(Err(_)) | Err(_) => Some(DaemonError::TaskFailed),
    }
}

fn state_completion_failure(
    completion: Result<StateCoreExit, oneshot::error::RecvError>,
    observer: &RuntimeObserver,
) -> DaemonError {
    if matches!(completion, Ok(StateCoreExit::Indeterminate(_))) {
        observer.storage_indeterminate();
    }
    match completion {
        Ok(exit) => DaemonError::StateCore(exit),
        Err(_) => DaemonError::TaskFailed,
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
    Maintenance(Result<Result<(), RuntimeError>, oneshot::error::RecvError>),
    State(Result<StateCoreExit, oneshot::error::RecvError>),
    Listener,
}

enum ReloadPreparationOrigin {
    Signal,
    Admin(ReloadPreparationReply),
}

const OWNER_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(1);

type LogFlushFuture = Pin<Box<dyn Future<Output = Result<(), ShutdownFailure>> + Send + 'static>>;

/// Runs the flush phase's administrative and state halves.
///
/// Crate-visible so the RUN-12 regression drives the same function the
/// daemon's flush hook does.
pub(crate) async fn flush_admin_and_state<D, A, S>(
    acknowledgements: &mut Vec<FlushAcknowledgement>,
    drain: D,
    admin_flush: A,
    state_flush: S,
) -> Result<(), ShutdownFailure>
where
    D: Future<Output = Result<Vec<FlushAcknowledgement>, AdminLifecycleFailure>>,
    A: Future<Output = Result<(), AdminLifecycleFailure>>,
    S: Future<Output = Result<(), ShutdownFailure>>,
{
    *acknowledgements = drain.await.map_err(map_admin_lifecycle)?;
    // The state owner's flush is the durable one, so it never queues behind
    // the administrative flush: both run together and both must succeed.
    let (state, admin) = tokio::join!(state_flush, admin_flush);
    state?;
    admin.map_err(map_admin_lifecycle)?;
    for acknowledgement in acknowledgements {
        acknowledgement.wait().await;
    }
    Ok(())
}

#[derive(Default)]
struct TrackedLogFlush {
    future: Option<LogFlushFuture>,
    result: Option<Result<(), ShutdownFailure>>,
}

impl TrackedLogFlush {
    fn start(&mut self, control: &FileLogControl) {
        if self.future.is_none() && self.result.is_none() {
            let control = control.clone();
            self.future = Some(Box::pin(async move {
                control.flush().await.map_err(|_| ShutdownFailure::Writer)
            }));
        }
    }

    async fn finish(&mut self) -> Result<(), ShutdownFailure> {
        if let Some(future) = self.future.as_mut() {
            let result = future.as_mut().await;
            self.future = None;
            self.result = Some(result);
        }
        self.result.unwrap_or(Ok(()))
    }
}

#[derive(Default)]
struct NestedOwnerJoins {
    admin: bool,
    state_core: bool,
    listeners: bool,
}

impl NestedOwnerJoins {
    fn observe(&mut self, name: ChildName) {
        match name {
            ChildName::AdminOwner => self.admin = true,
            ChildName::StateCoreTask => self.state_core = true,
            ChildName::ListenerSet => self.listeners = true,
            ChildName::SignalTask
            | ChildName::StorageBridge
            | ChildName::CryptoBridge
            | ChildName::MaintenanceTask
            | ChildName::FederationLinks
            | ChildName::Connection => {}
        }
    }

    fn observe_report(&mut self, report: &JoinReport) {
        for exit in &report.exits {
            self.observe(exit.name);
        }
    }

    const fn all_joined(&self) -> bool {
        self.admin && self.state_core && self.listeners
    }
}

async fn join_or_abort_supervised_remainder(
    supervisor: &mut Supervisor,
    deadline: tokio::time::Instant,
    mut nested_owners: NestedOwnerJoins,
) -> JoinReport {
    let mut report = JoinReport::default();
    loop {
        if supervisor.live_children() == 0 {
            return report;
        }
        if nested_owners.all_joined() {
            supervisor.abort_all();
            let forced = supervisor
                .join_all(deadline.saturating_duration_since(tokio::time::Instant::now()))
                .await;
            report.exits.extend(forced.exits);
            report.unfinished = forced.unfinished;
            return report;
        }
        match tokio::time::timeout_at(deadline, supervisor.next_exit()).await {
            Ok(Some(exit)) => {
                nested_owners.observe(exit.name);
                report.exits.push(exit);
            }
            Ok(None) | Err(_) => {
                report.unfinished = supervisor.live_children();
                return report;
            }
        }
    }
}

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
    pending_reload: PendingReloadWork,
    log_flush: TrackedLogFlush,
    stop_failure: Option<ShutdownFailure>,
}

impl ShutdownHooks for RuntimeShutdownHooks<'_> {
    async fn run(&mut self, phase: ShutdownPhase, budget: Duration) -> Result<(), ShutdownFailure> {
        self.observer.shutdown_phase(phase);
        match phase {
            ShutdownPhase::Quiesce => {
                self.readiness.clear(ReadinessStage::StateCore);
                self.listeners.stop_accepting();
                self.finish_pending_reload().await;
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
                flush_admin_and_state(
                    &mut self.admin_acknowledgements,
                    self.admin.drain(),
                    self.admin.flush(),
                    request_lifecycle(self.lifecycle, LifecyclePhase::Flush),
                )
                .await?;
                if !self.listener_joined {
                    (&mut *self.listener_exited)
                        .await
                        .map_err(|_| ShutdownFailure::Writer)?;
                    self.listener_joined = true;
                }
                self.log_flush.start(&self.log_control);
                self.log_flush.finish().await
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
        self.finish_pending_reload().await;
        if let Err(failure) = self.log_flush.finish().await {
            self.retain_stop_failure(failure);
        }
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
            let mut nested_owners = NestedOwnerJoins::default();
            nested_owners.observe_report(&report);
            let forced =
                join_or_abort_supervised_remainder(self.supervisor, deadline, nested_owners).await;
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

    async fn finish_pending_reload(&mut self) {
        if let Some(succeeded) = self.pending_reload.finish().await {
            self.observer.reload(succeeded);
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
    match report.first_problem() {
        None => Ok(()),
        Some(problem) => match problem.kind {
            ShutdownProblemKind::TimedOut => Err(DaemonError::ShutdownPhaseTimeout(problem.phase)),
            ShutdownProblemKind::Failed(failure) => {
                Err(DaemonError::ShutdownFailed(problem.phase, failure))
            }
        },
    }
}

fn shutdown_failure_label(failure: ShutdownFailure) -> &'static str {
    match failure {
        ShutdownFailure::Listener => "listener",
        ShutdownFailure::StateCore => "state_core",
        ShutdownFailure::Writer => "writer",
        ShutdownFailure::Audit => "audit",
        ShutdownFailure::Storage => "storage",
        ShutdownFailure::Join => "join",
    }
}

async fn prepare_reload(
    config_path: PathBuf,
    runtime_config: RuntimeConfigHandle,
    budget: Arc<MemoryBudget>,
    storage: StoragePort,
) -> Result<PreparedReload, ReloadPrepareFailure> {
    let lease = runtime_config.begin_reload()?;
    let active = runtime_config.load();
    let (candidate, secrets, operators) = tokio::task::spawn_blocking(move || {
        let candidate = load_config(&config_path, ValidationDepth::Host)?;
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
    let statistics = reload_storage_statistics(&storage).await?;
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
    inbox: mpsc::Sender<MaintenanceEvent>,
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
    inbox: &mpsc::Sender<MaintenanceEvent>,
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
            permit.send(event);
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
#[path = "daemon/tests/classification.rs"]
mod classification_tests;

#[cfg(test)]
mod tests {
    use super::{DaemonError, ReconstructionSurface};
    use crate::RuntimeError;
    use crate::federation::edge::{EdgeRestoreCause, EdgeRestoreStep};
    use agenc_relay_storage::StorageError;

    /// A storage-open refusal, an unlabelled runtime refusal and each labelled
    /// reconstruction refusal print lines an operator can tell apart. The bare
    /// two-prefix line names neither a surface nor a record, which is why the
    /// first report of this failure was filed against the wrong component.
    #[test]
    fn every_startup_refusal_prints_the_reconstruction_that_refused() {
        let stale = StorageError::StaleState;
        assert_eq!(
            DaemonError::Storage(stale).to_string(),
            "storage owner failed: storage state is stale or inconsistent",
        );
        assert_eq!(
            DaemonError::Runtime(RuntimeError::Storage(stale)).to_string(),
            "runtime startup failed: storage owner failed: storage state is stale or inconsistent",
        );
        assert_eq!(
            DaemonError::Reconstruction(
                ReconstructionSurface::DurableState,
                RuntimeError::Storage(stale),
            )
            .to_string(),
            "runtime startup failed: durable state reconstruction refused the recovered state: \
             storage owner failed: storage state is stale or inconsistent",
        );
        assert_eq!(
            DaemonError::Reconstruction(
                ReconstructionSurface::RecoveredSessions,
                RuntimeError::Storage(stale),
            )
            .to_string(),
            "runtime startup failed: recovered session reconciliation refused the recovered \
             state: storage owner failed: storage state is stale or inconsistent",
        );
        assert_eq!(
            DaemonError::Reconstruction(
                ReconstructionSurface::EdgeFederation(
                    EdgeRestoreStep::BarrierInstall,
                    EdgeRestoreCause::Unclassified,
                ),
                RuntimeError::Storage(stale),
            )
            .to_string(),
            "runtime startup failed: edge federation restore at barrier-install refused the \
             recovered state: storage owner failed: storage state is stale or inconsistent",
        );
        assert_eq!(
            DaemonError::Reconstruction(
                ReconstructionSurface::EdgeFederation(
                    EdgeRestoreStep::ProjectionEntries,
                    EdgeRestoreCause::ActiveProjectionCeiling,
                ),
                RuntimeError::LimitExceeded,
            )
            .to_string(),
            "runtime startup failed: edge federation restore at edge-projection-rows (active \
             projection over the standing-projection ceiling) refused the recovered state: \
             runtime ceiling exceeded",
        );
    }

    /// Every edge restore step prints a distinct, fixed lowercase label.
    #[test]
    fn every_edge_restore_step_names_a_distinct_record_family() {
        let steps = [
            EdgeRestoreStep::WitnessBacking,
            EdgeRestoreStep::PeerRecord,
            EdgeRestoreStep::ProjectionEntries,
            EdgeRestoreStep::ProjectionInstall,
            EdgeRestoreStep::OriginJournal,
            EdgeRestoreStep::RequestJournal,
            EdgeRestoreStep::CompanionState,
            EdgeRestoreStep::CompanionSnapshot,
            EdgeRestoreStep::BarrierInstall,
        ];
        let mut labels: Vec<&str> = steps.iter().map(|step| step.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), steps.len());
        assert!(
            labels
                .iter()
                .all(|label| !label.is_empty() && *label == label.to_lowercase())
        );
    }

    /// The active sequencer seed alone.
    fn active(seed: &[u8; 32]) -> super::SequencerSecrets<'_> {
        super::SequencerSecrets {
            active: Some(seed),
            successor: None,
            retired: None,
        }
    }

    /// The active and successor seeds of the overlap document.
    fn overlap_secrets() -> super::SequencerSecrets<'static> {
        super::SequencerSecrets {
            active: Some(&[90; 32]),
            successor: Some(&[91; 32]),
            retired: None,
        }
    }

    use agenc_relay_config::{PathResolver, RateTable};
    use agenc_relay_testkit::DeterministicMonotonicClock;
    use agenc_relay_types::ServerId;

    use crate::observe::log::{LogTarget, LogWriter};
    use crate::observe::metrics::{MetricLabel, MetricName, MetricsView, QueueName};
    use crate::state_core::IndeterminateCause;

    use super::*;

    struct FailingShutdown {
        phase: ShutdownPhase,
        failure: ShutdownFailure,
    }

    impl ShutdownHooks for FailingShutdown {
        async fn run(
            &mut self,
            phase: ShutdownPhase,
            _budget: Duration,
        ) -> Result<(), ShutdownFailure> {
            if phase == self.phase {
                Err(self.failure)
            } else {
                Ok(())
            }
        }

        fn stop_deadline_expired(&mut self) {}
    }

    #[tokio::test]
    async fn shutdown_errors_retain_the_first_phase_and_closed_owner_label() {
        for (failure, label) in [
            (ShutdownFailure::Listener, "listener"),
            (ShutdownFailure::StateCore, "state_core"),
            (ShutdownFailure::Writer, "writer"),
            (ShutdownFailure::Audit, "audit"),
            (ShutdownFailure::Storage, "storage"),
            (ShutdownFailure::Join, "join"),
        ] {
            let (_signals, mut inbox) = tokio::sync::mpsc::channel(1);
            let mut hooks = FailingShutdown {
                phase: ShutdownPhase::Flush,
                failure,
            };
            let report = run_shutdown(ShutdownPlan::DEFAULT, &mut hooks, &mut inbox).await;
            let result = validate_shutdown_report(report);
            assert!(
                matches!(result, Err(DaemonError::ShutdownFailed(ShutdownPhase::Flush, actual)) if actual == failure)
            );
            if let Err(error) = result {
                assert_eq!(
                    error.to_string(),
                    format!("daemon shutdown failed: phase=flush owner={label}")
                );
            }
        }
    }

    /// A hook whose one chosen phase never finishes.
    struct StalledShutdown(ShutdownPhase);

    impl ShutdownHooks for StalledShutdown {
        async fn run(
            &mut self,
            phase: ShutdownPhase,
            _budget: Duration,
        ) -> Result<(), ShutdownFailure> {
            if phase == self.0 {
                std::future::pending::<()>().await;
            }
            Ok(())
        }

        fn stop_deadline_expired(&mut self) {}
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_shutdown_names_the_first_phase_that_outlived_its_budget() {
        for (phase, label) in [
            (ShutdownPhase::Quiesce, "quiesce"),
            (ShutdownPhase::Drain, "drain"),
            (ShutdownPhase::Flush, "flush"),
        ] {
            let (_signals, mut inbox) = tokio::sync::mpsc::channel(1);
            let mut hooks = StalledShutdown(phase);
            let report = run_shutdown(ShutdownPlan::DEFAULT, &mut hooks, &mut inbox).await;
            let result = validate_shutdown_report(report);
            assert!(
                matches!(result, Err(DaemonError::ShutdownPhaseTimeout(actual)) if actual == phase)
            );
            if let Err(error) = result {
                assert_eq!(
                    error.to_string(),
                    format!("daemon shutdown exceeded its deadline: phase={label}")
                );
            }
        }
    }

    struct MemoryLogTarget(Vec<String>);

    impl LogTarget for MemoryLogTarget {
        fn open_segment(&mut self, _hour: u64) -> std::io::Result<()> {
            Ok(())
        }

        fn write_line(&mut self, line: &str) -> std::io::Result<()> {
            self.0.push(line.to_owned());
            Ok(())
        }

        fn retire_before(&mut self, _hour: u64, _limit: usize) -> std::io::Result<bool> {
            Ok(true)
        }
    }

    fn test_observer() -> (Arc<RuntimeObserver>, LogWriter<MemoryLogTarget>) {
        let server_id = ServerId::from_bytes([3; 16]);
        let correlation = Arc::new(CorrelationSource::new(10));
        let (writer, log) = LogWriter::start(
            MemoryLogTarget(Vec::new()),
            LogRetention::DEFAULT,
            LogFilter::new(Severity::Debug),
            server_id,
            Arc::clone(&correlation),
        );
        let observer = Arc::new(RuntimeObserver::new(
            server_id,
            SystemMonotonicClock::start(),
            correlation,
            log,
            Arc::new(MetricsRegistry::new()),
        ));
        (observer, writer)
    }

    const PUBLIC_CONFIG: &str = include_str!("../../agenc-relay-config/tests/golden/public.toml");

    fn public_config() -> Result<Config, DaemonError> {
        Config::parse_text(
            PUBLIC_CONFIG,
            &PathResolver::none(),
            ValidationDepth::Document,
        )
        .map_err(DaemonError::Configuration)
    }

    /// A refusal from the storage open and a refusal raised after it are the same
    /// `StorageError` but two different daemon failures, and the single operator line each one
    /// prints is what tells them apart: only the second carries the runtime-startup prefix,
    /// because only `DaemonError::Runtime` adds one. Stage 10's CAP-01 record read a
    /// two-prefix line as a rollback-guard refusal from `verify_guard_pair`, which cannot
    /// produce one; this keeps that distinction checkable against the real strings.
    #[test]
    fn a_storage_open_refusal_and_a_later_startup_refusal_print_different_lines() {
        let opening = DaemonError::Storage(StorageError::StaleState);
        let after_open = DaemonError::Runtime(RuntimeError::Storage(StorageError::StaleState));
        assert_eq!(
            opening.to_string(),
            "storage owner failed: storage state is stale or inconsistent",
        );
        assert_eq!(
            after_open.to_string(),
            "runtime startup failed: storage owner failed: storage state is stale or inconsistent",
        );
        assert!(!opening.to_string().starts_with("runtime startup failed: "));
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
    async fn a_state_owner_exit_names_its_cause_in_the_daemon_failure() {
        use crate::state_core::{CorruptionCause, IndeterminateCause};
        let (observer, _log) = test_observer();
        let corrupt = state_completion_failure(
            Ok(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed)),
            &observer,
        );
        assert_eq!(
            corrupt.to_string(),
            "the state owner stopped: state core committed state unusable: a plan projection failed"
        );
        let indeterminate = state_completion_failure(
            Ok(StateCoreExit::Indeterminate(
                IndeterminateCause::StorageIndeterminate,
            )),
            &observer,
        );
        assert_eq!(
            indeterminate.to_string(),
            "the state owner stopped: state core durable outcome indeterminate: storage reported an indeterminate commit"
        );
        let (sender, receiver) = oneshot::channel::<StateCoreExit>();
        drop(sender);
        let lost = receiver.await;
        assert!(matches!(
            state_completion_failure(lost, &observer),
            DaemonError::TaskFailed
        ));
    }

    #[tokio::test]
    async fn maintenance_completion_triggers_shutdown_without_consuming_the_join_record()
    -> Result<(), RuntimeError> {
        let mut supervisor = Supervisor::new();
        let (completion, completed) = oneshot::channel();
        supervisor.spawn(ChildName::MaintenanceTask, ChildKind::Critical, |_| {
            report_maintenance_completion(async { Err(RuntimeError::InvalidValue) }, completion)
        })?;

        assert!(matches!(
            maintenance_completion_failure(completed.await),
            Some(DaemonError::TaskFailed)
        ));
        assert_eq!(supervisor.live_children(), 1);
        let exit = supervisor
            .next_exit()
            .await
            .ok_or(RuntimeError::Cancelled)?;
        assert_eq!(exit.name, ChildName::MaintenanceTask);
        assert!(matches!(
            exit.outcome,
            Err(ChildFailure::Failed(RuntimeError::InvalidValue))
        ));

        let (panicked, panic_observed) = oneshot::channel();
        drop(panicked);
        assert!(matches!(
            maintenance_completion_failure(panic_observed.await),
            Some(DaemonError::TaskFailed)
        ));
        assert!(maintenance_completion_failure(Ok(Ok(()))).is_none());
        Ok(())
    }

    #[test]
    fn clean_maintenance_completion_preserves_indeterminate_state_observation() {
        let (observer, _writer) = test_observer();
        assert!(maintenance_completion_failure(Ok(Ok(()))).is_none());
        assert!(matches!(
            state_completion_failure(
                Ok(StateCoreExit::Indeterminate(
                    IndeterminateCause::StorageIndeterminate
                )),
                observer.as_ref(),
            ),
            DaemonError::StateCore(StateCoreExit::Indeterminate(
                IndeterminateCause::StorageIndeterminate
            ))
        ));
        let snapshot = observer.metrics().snapshot(MetricsView::Operator);
        assert!(snapshot.counts.iter().any(|(key, histogram)| {
            key.name == MetricName::QueueDepth
                && key
                    .labels
                    .iter()
                    .any(|label| label == MetricLabel::QueueName(QueueName::Log))
                && histogram.counts()[0] == 1
        }));
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
            .send(MaintenanceEvent::CheckpointDue)
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
            Some(MaintenanceEvent::ClockDriftCheck)
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
        assert_eq!(
            runtime_purpose(ConfigListenerPurpose::Federation).ok(),
            Some(ListenerPurpose::Federation)
        );
        assert_eq!(
            runtime_purpose(ConfigListenerPurpose::ClientWss).is_ok(),
            cfg!(feature = "wss")
        );
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

        // An edge without federation has no coordinator and is refused; a
        // federated edge and a federated coordinator are both served.
        let mut edge = baseline.clone();
        edge.network.role = NodeRole::Edge;
        assert!(matches!(
            validate_profile(&edge),
            Err(DaemonError::UnsupportedProfile)
        ));
        edge.federation.enabled = true;
        assert!(validate_profile(&edge).is_ok());

        let mut federation = baseline.clone();
        federation.federation.enabled = true;
        assert!(validate_profile(&federation).is_ok());

        // The encrypted profile needs federation and the network coordinator
        // named in `[e2ee]`; both federated roles then serve it.
        let mut e2ee = baseline.clone();
        e2ee.e2ee.enabled = true;
        assert!(matches!(
            validate_profile(&e2ee),
            Err(DaemonError::UnsupportedProfile)
        ));
        e2ee.federation.enabled = true;
        assert!(validate_profile(&e2ee).is_ok());
        e2ee.network.role = NodeRole::Edge;
        assert!(validate_profile(&e2ee).is_ok());
        e2ee.e2ee.coordinator_server_id = Some(ServerId::from_bytes([200; 16]));
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
            assert_eq!(
                validate_profile(&enabled).is_ok(),
                purpose == ConfigListenerPurpose::ClientWss && cfg!(feature = "wss")
            );

            enabled
                .listeners
                .first_mut()
                .ok_or(RuntimeError::InvalidValue)?
                .enabled = false;
            assert!(validate_profile(&enabled).is_ok());
        }
        Ok(())
    }

    /// Writes or replaces one mode-0600 credentials file, as an operator would.
    fn write_credentials(path: &Path, bytes: &[u8]) -> Result<(), DaemonError> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let _removed = std::fs::remove_file(path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| RuntimeError::InvalidValue)?;
        file.write_all(bytes)
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(())
    }

    /// One two-credential (current plus overlap successor) document for the
    /// public configuration's network.
    fn sequencer_overlap_document() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use crate::e2ee::coordinator::tests::support::{key, sequencer_credential_in};
        use agenc_relay_e2ee::sequencer::SequencerCredentialsFile;
        use agenc_relay_e2ee::tls::{TlsEncode, TlsVec};
        let network = *public_config()?.network.network_id.as_bytes();
        let old = sequencer_credential_in(network, &key(90), 0, (0, 1_000), None)?;
        let next =
            sequencer_credential_in(network, &key(91), 1, (100, 2_000), Some((&key(90), &old)))?;
        Ok(SequencerCredentialsFile {
            set_generation: 1,
            credentials: TlsVec::new(vec![old, next])?,
        }
        .encode()?)
    }

    /// An enabled coordinator configuration whose credentials file is `path`.
    fn e2ee_coordinator_config(path: &Path) -> Result<Config, DaemonError> {
        let mut config = public_config()?;
        config.federation.enabled = true;
        config.e2ee.enabled = true;
        config.e2ee.sequencer_credentials_file = Some(path.to_path_buf());
        Ok(config)
    }

    /// ENC-13 (#39): the declared maximum applies on the descriptor before
    /// any allocation or parsing, at both supported document sizes.
    #[test]
    fn credentials_read_admits_supported_sizes_and_refuses_oversize_before_allocation()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::e2ee::coordinator::tests::support::key;
        use agenc_relay_e2ee::sequencer::MAX_SEQUENCER_CREDENTIALS_FILE_BYTES;
        let directory = crate::test_support::TestDirectory::create_protected()?;
        let path = directory.0.join("sequencer-credentials.bin");
        let config = e2ee_coordinator_config(&path)?;
        let mut edge = config.clone();
        edge.network.role = NodeRole::Edge;

        write_credentials(&path, &sequencer_credentials_document(&key(90))?)?;
        assert!(e2ee_setup(&config, active(&[90; 32]))?.is_some());
        assert!(e2ee_setup(&edge, SequencerSecrets::default())?.is_some());
        write_credentials(&path, &sequencer_overlap_document()?)?;
        assert!(e2ee_setup(&config, overlap_secrets())?.is_some());
        assert!(e2ee_setup(&edge, SequencerSecrets::default())?.is_some());

        // Limit plus one, written and sparse: refused before the hook that
        // precedes the read ever runs, so nothing is allocated or parsed.
        let oversize = MAX_SEQUENCER_CREDENTIALS_FILE_BYTES + 1;
        write_credentials(&path, &vec![0x5a; oversize])?;
        let mut hook_fired = false;
        assert!(matches!(
            e2ee_setup_with_hook(&edge, SequencerSecrets::default(), || hook_fired = true),
            Err(DaemonError::E2eeCredentials)
        ));
        write_credentials(&path, b"")?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(u64::try_from(oversize)?)?;
        assert!(matches!(
            e2ee_setup_with_hook(&config, active(&[90; 32]), || hook_fired = true),
            Err(DaemonError::E2eeCredentials)
        ));
        assert!(
            !hook_fired,
            "an oversize document is refused before the read"
        );
        Ok(())
    }

    /// ENC-13 (#39): the bytes parsed are exactly the bytes the single
    /// descriptor returned; growth or replacement after inspection is refused.
    #[test]
    fn credentials_read_refuses_growth_and_replacement_after_inspection()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::e2ee::coordinator::tests::support::key;
        use std::io::Write as _;
        let directory = crate::test_support::TestDirectory::create_protected()?;
        let path = directory.0.join("sequencer-credentials.bin");
        let config = e2ee_coordinator_config(&path)?;
        let document = sequencer_credentials_document(&key(90))?;

        write_credentials(&path, &document)?;
        assert!(matches!(
            e2ee_setup_with_hook(&config, active(&[90; 32]), || {
                let mut file = std::fs::OpenOptions::new().append(true).open(&path).ok();
                assert!(
                    file.as_mut()
                        .is_some_and(|file| file.write_all(&[0]).is_ok())
                );
            }),
            Err(DaemonError::E2eeCredentials)
        ));

        // A valid document for key 91 renamed over the inspected key-90
        // document never becomes the parsed bytes: the coordinator secret
        // 91 cannot compose from a descriptor that inspected key 90.
        write_credentials(&path, &document)?;
        let replacement = directory.0.join("replacement.bin");
        write_credentials(&replacement, &sequencer_overlap_document()?)?;
        assert!(matches!(
            e2ee_setup_with_hook(&config, overlap_secrets(), || {
                assert!(std::fs::rename(&replacement, &path).is_ok());
            }),
            Err(DaemonError::E2eeCredentials)
        ));
        // Without the race the replacement document admits both keys normally.
        assert!(e2ee_setup(&config, overlap_secrets())?.is_some());
        Ok(())
    }

    /// ENC-13 (#39): the protected-file policy applies to the credentials
    /// path exactly as to every other secret path, with a positive control.
    #[test]
    fn credentials_read_applies_the_protected_file_policy() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::e2ee::coordinator::tests::support::key;
        use rustix::fs::{CWD, Mode, mkfifoat};
        use std::os::unix::fs::PermissionsExt as _;
        let directory = crate::test_support::TestDirectory::create_protected()?;
        let document = sequencer_credentials_document(&key(90))?;
        let real = directory.0.join("real.bin");
        write_credentials(&real, &document)?;
        let refused = |path: &Path| -> Result<bool, DaemonError> {
            let config = e2ee_coordinator_config(path)?;
            Ok(matches!(
                e2ee_setup(&config, active(&[90; 32])),
                Err(DaemonError::E2eeCredentials)
            ))
        };

        let link = directory.0.join("link.bin");
        std::os::unix::fs::symlink(&real, &link)?;
        assert!(refused(&link)?, "a symlink is refused");

        let alias = directory.0.join("alias.bin");
        std::fs::hard_link(&real, &alias)?;
        assert!(refused(&alias)?, "a hard-linked document is refused");
        assert!(refused(&real)?, "the linked original is refused too");
        std::fs::remove_file(&alias)?;

        let fifo = directory.0.join("fifo.bin");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR)?;
        assert!(refused(&fifo)?, "a FIFO is refused");

        let loose = directory.0.join("loose.bin");
        write_credentials(&loose, &document)?;
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o666))?;
        assert!(
            refused(&loose)?,
            "a group- or world-writable document is refused"
        );

        let shared = directory.0.join("shared");
        std::fs::create_dir(&shared)?;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o770))?;
        let under_shared = shared.join("credentials.bin");
        write_credentials(&under_shared, &document)?;
        assert!(
            refused(&under_shared)?,
            "a group-writable ancestor is refused"
        );

        // Positive control: the same document at mode 0600 under the
        // mode-0700 root is admitted.
        assert!(e2ee_setup(&e2ee_coordinator_config(&real)?, active(&[90; 32]))?.is_some());
        Ok(())
    }

    /// ENC-13 (#39): a disabled profile never touches the credentials path,
    /// and the refusal carries neither the path nor any document byte.
    #[test]
    fn credentials_refusal_is_inert_when_disabled_and_leaks_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        use agenc_relay_e2ee::sequencer::MAX_SEQUENCER_CREDENTIALS_FILE_BYTES;
        let directory = crate::test_support::TestDirectory::create_protected()?;
        let missing = directory.0.join("missing-credentials.bin");
        let oversize = directory.0.join("oversize-credentials.bin");
        write_credentials(
            &oversize,
            &vec![0x5a; MAX_SEQUENCER_CREDENTIALS_FILE_BYTES + 1],
        )?;
        for path in [&missing, &oversize] {
            let mut disabled = e2ee_coordinator_config(path)?;
            disabled.e2ee.enabled = false;
            assert!(e2ee_setup(&disabled, active(&[90; 32]))?.is_none());
        }
        let error = e2ee_setup(&e2ee_coordinator_config(&oversize)?, active(&[90; 32]))
            .err()
            .ok_or("an oversize document must be refused")?;
        assert!(matches!(error, DaemonError::E2eeCredentials));
        let path_text = oversize.to_string_lossy();
        for rendered in [format!("{error}"), format!("{error:?}")] {
            assert!(!rendered.contains(path_text.as_ref()));
            assert!(!rendered.contains("ZZZZ"));
            assert!(!rendered.contains(directory.0.to_string_lossy().as_ref()));
        }
        Ok(())
    }

    fn sequencer_credentials_document(
        secret: &agenc_relay_crypto::Ed25519SecretKey,
    ) -> Result<Vec<u8>, DaemonError> {
        use crate::e2ee::coordinator::tests::support::sequencer_credential_in;
        use agenc_relay_e2ee::sequencer::SequencerCredentialsFile;
        use agenc_relay_e2ee::tls::{TlsEncode, TlsVec};
        let network = *public_config()?.network.network_id.as_bytes();
        let credential = sequencer_credential_in(network, secret, 0, (0, 4_000_000_000), None)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let document = SequencerCredentialsFile {
            set_generation: 0,
            credentials: TlsVec::new(vec![credential]).map_err(|_| RuntimeError::InvalidValue)?,
        };
        document
            .encode()
            .map_err(|_| RuntimeError::InvalidValue.into())
    }

    #[test]
    fn e2ee_setup_verifies_the_credentials_file_for_both_roles() -> Result<(), DaemonError> {
        use crate::e2ee::coordinator::tests::support::key;
        let directory = crate::test_support::TestDirectory::create_protected()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let path = directory.0.join("sequencer-credentials.bin");
        let sequencer = key(90);
        write_credentials(&path, &sequencer_credentials_document(&sequencer)?)?;
        let seed = [90_u8; 32];

        let mut disabled = public_config()?;
        disabled.federation.enabled = true;
        assert!(e2ee_setup(&disabled, active(&seed))?.is_none());

        let mut coordinator = disabled.clone();
        coordinator.e2ee.enabled = true;
        coordinator.e2ee.sequencer_credentials_file = Some(path.clone());
        let setup = e2ee_setup(&coordinator, active(&seed))?.ok_or(RuntimeError::InvalidValue)?;
        assert!(setup.executor.is_some());
        assert_eq!(setup.profile.local.key_set_generation, 0);
        // The sequencer key must be one of the credentials.
        assert!(matches!(
            e2ee_setup(&coordinator, active(&[91; 32])),
            Err(DaemonError::E2eeCredentials)
        ));
        assert!(matches!(
            e2ee_setup(&coordinator, SequencerSecrets::default()),
            Err(DaemonError::UnsupportedProfile)
        ));

        let mut edge = coordinator.clone();
        edge.network.role = NodeRole::Edge;
        let setup =
            e2ee_setup(&edge, SequencerSecrets::default())?.ok_or(RuntimeError::InvalidValue)?;
        assert!(setup.executor.is_none());

        // A document that does not parse, or one for another network, is
        // refused before any role composes.
        write_credentials(&path, b"not a credentials document")?;
        assert!(matches!(
            e2ee_setup(&edge, SequencerSecrets::default()),
            Err(DaemonError::E2eeCredentials)
        ));
        let mut other = edge.clone();
        other.network.network_id = agenc_relay_types::NetworkId::from_bytes([77; 32]);
        write_credentials(&path, &sequencer_credentials_document(&sequencer)?)?;
        assert!(matches!(
            e2ee_setup(&other, SequencerSecrets::default()),
            Err(DaemonError::E2eeCredentials)
        ));
        Ok(())
    }

    #[test]
    fn sequencer_eligibility_setup_preserves_selected_credential_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::e2ee::coordinator::tests::support::{key, sequencer_credential_in};
        use agenc_relay_crypto::{SemanticHashDomain, SignatureDomain};
        use agenc_relay_e2ee::ids::semantic_id_of;
        use agenc_relay_e2ee::sequencer::SequencerCredentialsFile;
        use agenc_relay_e2ee::tls::{TlsEncode, TlsVec};
        let directory = crate::test_support::TestDirectory::create_protected()?;
        let path = directory.0.join("sequencer-overlap.bin");
        let mut config = public_config()?;
        config.federation.enabled = true;
        config.e2ee.enabled = true;
        config.e2ee.sequencer_credentials_file = Some(path.clone());
        let network = *config.network.network_id.as_bytes();
        let old = sequencer_credential_in(network, &key(90), 0, (0, 1_000), None)?;
        let next =
            sequencer_credential_in(network, &key(91), 1, (100, 2_000), Some((&key(90), &old)))?;
        let document = SequencerCredentialsFile {
            set_generation: 1,
            credentials: TlsVec::new(vec![old.clone(), next.clone()])?,
        };
        write_credentials(&path, &document.encode()?)?;
        // The active key serves the first credential and the successor key
        // the second; either key alone cannot install a two-credential set.
        let setup = e2ee_setup(&config, overlap_secrets())?.ok_or("setup")?;
        assert_eq!(setup.profile.local.key_set_generation, 1);
        let executor = setup.executor.ok_or("executor")?;
        let signers = executor.signers().ok_or("signers")?;
        assert_eq!(
            signers.active.credential_id,
            semantic_id_of(SemanticHashDomain::SequencerKey, &old.tbs)?
        );
        assert_eq!(
            signers
                .successor
                .as_ref()
                .map(|signer| signer.credential_id),
            Some(semantic_id_of(SemanticHashDomain::SequencerKey, &next.tbs)?)
        );
        let tbs = [7_u8; 8];
        for (signer, credential) in [
            (&signers.active, &old),
            (signers.successor.as_ref().ok_or("successor")?, &next),
        ] {
            let signature = signer.sign(SignatureDomain::CandidateReceipt, &tbs)?;
            let public = agenc_relay_crypto::Ed25519PublicKey::from_bytes(
                credential.tbs.sequencer_public_key,
            )?;
            assert!(
                agenc_relay_crypto::verify_canonical(
                    public,
                    SignatureDomain::CandidateReceipt,
                    &tbs.encode()?,
                    agenc_relay_crypto::Ed25519Signature::from_bytes(signature),
                )
                .is_ok()
            );
        }
        for seed in [90_u8, 91] {
            assert!(matches!(
                e2ee_setup(&config, active(&[seed; 32])),
                Err(DaemonError::E2eeCredentials)
            ));
        }
        Ok(())
    }

    #[test]
    fn sequencer_setup_loads_a_retired_set_with_the_configured_retired_key()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::e2ee::coordinator::tests::support::{key, sequencer_credential_in};
        use agenc_relay_crypto::SemanticHashDomain;
        use agenc_relay_e2ee::ids::semantic_id_of;
        use agenc_relay_e2ee::sequencer::{SequencerCredentialsFile, SequencerKeySet};
        use agenc_relay_e2ee::tls::{TlsEncode, TlsVec};
        let directory = crate::test_support::TestDirectory::create_protected()?;
        let path = directory.0.join("sequencer-retired.bin");
        let mut config = public_config()?;
        config.federation.enabled = true;
        config.e2ee.enabled = true;
        config.e2ee.sequencer_credentials_file = Some(path.clone());
        let network = *config.network.network_id.as_bytes();
        let old = sequencer_credential_in(network, &key(90), 0, (0, 1_000), None)?;
        let next =
            sequencer_credential_in(network, &key(91), 1, (100, 2_000), Some((&key(90), &old)))?;
        // After the old credential retired the file opens at generation 1
        // with the successor alone, which every role verifies structurally
        // and advertises with the digest of that one credential.
        let document = SequencerCredentialsFile {
            set_generation: 2,
            credentials: TlsVec::new(vec![next.clone()])?,
        };
        write_credentials(&path, &document.encode()?)?;
        let expected = SequencerKeySet::verify_opened(&network, std::slice::from_ref(&next), 2)?;
        let secrets = super::SequencerSecrets {
            active: Some(&[91; 32]),
            successor: None,
            retired: Some(&[90; 32]),
        };
        let setup = e2ee_setup(&config, secrets)?.ok_or("setup")?;
        assert_eq!(setup.profile.local.key_set_generation, 2);
        let executor = setup.executor.ok_or("executor")?;
        assert_eq!(executor.key_set(), Some(&expected));
        let signers = executor.signers().ok_or("signers")?;
        assert_eq!(
            signers.active.credential_id,
            semantic_id_of(SemanticHashDomain::SequencerKey, &next.tbs)?
        );
        assert!(signers.successor.is_none());
        // The retired key waits for the durable reload to decide whether
        // any route or receipt still requires it.
        assert!(signers.retired.is_none());
        let mut edge = config.clone();
        edge.network.role = NodeRole::Edge;
        let edge_setup = e2ee_setup(&edge, super::SequencerSecrets::default())?.ok_or("edge")?;
        assert_eq!(edge_setup.profile.local, setup.profile.local);
        // The old key is not the key of the file's first credential, and a
        // successor key is refused when the file names no successor.
        assert!(matches!(
            e2ee_setup(&config, active(&[90; 32])),
            Err(DaemonError::E2eeCredentials)
        ));
        assert!(matches!(
            e2ee_setup(&config, overlap_secrets()),
            Err(DaemonError::E2eeCredentials)
        ));
        Ok(())
    }

    #[test]
    fn committed_process_actions_require_successful_cleanup() -> Result<(), DaemonError> {
        assert_eq!(
            finish_daemon_run(Ok(ShutdownTrigger::CommittedDie), Ok(()))?,
            DaemonExit::Stopped
        );
        assert_eq!(
            finish_daemon_run(Ok(ShutdownTrigger::CommittedRestart), Ok(()))?,
            DaemonExit::RestartRequested
        );
        assert!(matches!(
            finish_daemon_run(
                Ok(ShutdownTrigger::CommittedDie),
                Err(DaemonError::ShutdownTimeout),
            ),
            Err(DaemonError::ShutdownTimeout)
        ));
        assert!(matches!(
            finish_daemon_run(
                Ok(ShutdownTrigger::CommittedRestart),
                Err(DaemonError::TaskFailed),
            ),
            Err(DaemonError::TaskFailed)
        ));
        assert!(matches!(
            finish_daemon_run(
                Ok(ShutdownTrigger::Signal),
                Err(DaemonError::ShutdownTimeout),
            ),
            Err(DaemonError::ShutdownTimeout)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn flush_reacquires_admin_acknowledgements_after_a_dropped_drain()
    -> Result<(), RuntimeError> {
        let acknowledgement = FlushAcknowledgement::pending();
        let retained = acknowledgement.clone();
        let (_release, wait) = oneshot::channel::<()>();
        let first_drain = async move {
            let _released = wait.await;
            Ok::<_, AdminLifecycleFailure>(vec![retained])
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(5), first_drain)
                .await
                .is_err()
        );

        let retention_runs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_runs = std::sync::Arc::clone(&retention_runs);
        let repeated = acknowledgement.clone();
        let mut acknowledgements = Vec::new();
        {
            let flush = flush_admin_and_state(
                &mut acknowledgements,
                async move { Ok(vec![repeated]) },
                async move {
                    observed_runs.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    Ok(())
                },
                async { Ok(()) },
            );
            tokio::pin!(flush);
            assert!(
                tokio::time::timeout(Duration::from_millis(5), &mut flush)
                    .await
                    .is_err(),
                "flush must retain the reacquired writer acknowledgement"
            );
            assert_eq!(retention_runs.load(std::sync::atomic::Ordering::Acquire), 1);
            acknowledgement.acknowledge();
            flush.await.map_err(|_| RuntimeError::Cancelled)?;
        }
        assert_eq!(acknowledgements.len(), 1);
        assert_eq!(retention_runs.load(std::sync::atomic::Ordering::Acquire), 1);
        Ok(())
    }

    #[tokio::test]
    async fn tracked_shutdown_work_survives_a_dropped_phase_future() -> Result<(), RuntimeError> {
        let (reload_release, reload_wait) = oneshot::channel();
        let reload_finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished = std::sync::Arc::clone(&reload_finished);
        let mut pending_reload = PendingReloadWork {
            preparation: Some(Box::pin(async move {
                let _released = reload_wait.await;
                finished.store(true, std::sync::atomic::Ordering::Release);
                Err(ReloadPrepareFailure::Unavailable)
            })),
            observe_discarded_signal_preparation: true,
            activation: None,
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(5), pending_reload.finish())
                .await
                .is_err()
        );
        assert!(!reload_finished.load(std::sync::atomic::Ordering::Acquire));
        reload_release
            .send(())
            .map_err(|()| RuntimeError::Cancelled)?;
        assert_eq!(pending_reload.finish().await, Some(false));
        assert!(reload_finished.load(std::sync::atomic::Ordering::Acquire));

        let (flush_release, flush_wait) = oneshot::channel();
        let flush_finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished = std::sync::Arc::clone(&flush_finished);
        let mut log_flush = TrackedLogFlush {
            future: Some(Box::pin(async move {
                let _released = flush_wait.await;
                finished.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            })),
            result: None,
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(5), log_flush.finish())
                .await
                .is_err()
        );
        assert!(!flush_finished.load(std::sync::atomic::Ordering::Acquire));
        flush_release
            .send(())
            .map_err(|()| RuntimeError::Cancelled)?;
        assert_eq!(log_flush.finish().await, Ok(()));
        assert!(flush_finished.load(std::sync::atomic::Ordering::Acquire));
        Ok(())
    }

    #[tokio::test]
    async fn forced_abort_waits_until_nested_owners_have_joined() -> Result<(), RuntimeError> {
        let mut supervisor = Supervisor::new();
        supervisor.spawn(ChildName::AdminOwner, ChildKind::Critical, |_| async {
            Ok(())
        })?;
        supervisor.spawn(ChildName::ListenerSet, ChildKind::Critical, |_| async {
            Ok(())
        })?;
        let (state_release, state_wait) = oneshot::channel();
        supervisor.spawn(
            ChildName::StateCoreTask,
            ChildKind::Critical,
            |_| async move {
                let _released = state_wait.await;
                Ok(())
            },
        )?;
        supervisor.spawn(ChildName::MaintenanceTask, ChildKind::Critical, |_| async {
            std::future::pending::<()>().await;
            Ok(())
        })?;

        let first = join_or_abort_supervised_remainder(
            &mut supervisor,
            tokio::time::Instant::now() + Duration::from_millis(10),
            NestedOwnerJoins::default(),
        )
        .await;
        assert!(first.unfinished >= 2);
        assert!(
            first
                .exits
                .iter()
                .all(|exit| !matches!(exit.outcome, Err(ChildFailure::Cancelled)))
        );

        let mut joined = NestedOwnerJoins::default();
        joined.observe_report(&first);
        state_release
            .send(())
            .map_err(|()| RuntimeError::Cancelled)?;
        let forced = join_or_abort_supervised_remainder(
            &mut supervisor,
            tokio::time::Instant::now() + Duration::from_secs(1),
            joined,
        )
        .await;
        assert_eq!(forced.unfinished, 0);
        assert!(
            forced
                .exits
                .iter()
                .any(|exit| matches!(exit.outcome, Err(ChildFailure::Cancelled)))
        );
        assert_eq!(supervisor.live_children(), 0);
        Ok(())
    }

    #[test]
    fn trigger_failure_remains_primary_when_cleanup_also_fails() {
        assert!(matches!(
            finish_daemon_run(
                Err(DaemonError::TaskFailed),
                Err(DaemonError::ShutdownTimeout),
            ),
            Err(DaemonError::TaskFailed)
        ));
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

    /// The recovered session reconciliation converts to a `DaemonError` in
    /// exactly one place, where it names its surface.
    ///
    /// The loop closes one recovered session per committed plan, so its work
    /// is proportional to the live client sessions a kill leaves behind, and
    /// its commit path used to convert through `?`: a projection refusal
    /// printed `runtime startup failed: storage owner failed: storage state
    /// is stale or inconsistent` naming no surface, which is exactly the line
    /// issue #124 was filed against the storage layer on, and a refused
    /// commit or read printed the storage open's own single-prefix line.
    /// Binding the four signatures here fails to compile if any inner step
    /// regains the ability to build a `DaemonError` of its own.
    #[test]
    fn the_recovered_session_reconciliation_labels_at_its_only_conversion() {
        let _scope: fn(
            &agenc_relay_storage::StoragePort,
            &mut crate::state_core::reconstruct::Reconstruction,
            &crate::state_core::durable::KeyDeriver,
            crate::state_core::durable::AccountingCeilings,
            super::RecoveredSessionScope,
        ) -> Result<(), RuntimeError> = super::reconcile_recovered_session_scope;
        let _commit: fn(
            &agenc_relay_storage::StoragePort,
            &mut crate::state_core::reconstruct::Reconstruction,
            &crate::state_core::durable::KeyDeriver,
            crate::state_core::durable::AccountingCeilings,
            agenc_relay_domain::MutationPlan,
        ) -> Result<(), RuntimeError> = super::commit_startup_plan;
        let _refresh: fn(
            &agenc_relay_storage::StoragePort,
            &mut crate::state_core::reconstruct::Reconstruction,
            u64,
        ) -> Result<(), RuntimeError> = super::refresh_startup_rows;
        let _labelled: fn(
            &agenc_relay_storage::StoragePort,
            &mut crate::state_core::reconstruct::Reconstruction,
            &crate::state_core::durable::KeyDeriver,
            crate::state_core::durable::AccountingCeilings,
            super::RecoveredSessionScope,
        ) -> Result<(), DaemonError> = super::reconcile_recovered_sessions;
        assert_eq!(
            super::startup_stale_state(),
            RuntimeError::Storage(StorageError::StaleState),
        );
    }

    /// Every kind the recovered session reconciliation can raise prints with
    /// its surface named, and none of them prints either line that a reader
    /// has already mistaken for the storage open.
    #[test]
    fn no_recovered_session_refusal_prints_either_unlabelled_line() {
        let two_prefix = "runtime startup failed: storage owner failed: storage state is stale                           or inconsistent";
        let one_prefix = "storage owner failed: storage state is stale or inconsistent";
        for error in [
            RuntimeError::Storage(StorageError::StaleState),
            RuntimeError::Storage(StorageError::Unavailable),
            RuntimeError::MemoryExhausted,
            RuntimeError::LimitExceeded,
            RuntimeError::Overflow,
            RuntimeError::InvalidValue,
        ] {
            let printed =
                DaemonError::Reconstruction(ReconstructionSurface::RecoveredSessions, error)
                    .to_string();
            assert!(
                printed.starts_with(
                    "runtime startup failed: recovered session reconciliation refused the \
                     recovered state: "
                ),
                "{printed} does not name the surface that refused",
            );
            assert_ne!(printed, two_prefix);
            assert_ne!(printed, one_prefix);
        }
    }
}
