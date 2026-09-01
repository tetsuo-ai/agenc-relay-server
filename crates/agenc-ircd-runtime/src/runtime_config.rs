//! Prepared runtime configuration and the bounded activation boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use agenc_ircd_admin::AdminAuditEvent;
use agenc_ircd_admin::OperatorRegistry;
use agenc_ircd_config::{
    Config, ConfigDiff, HistoryDefault, LimitKey, ListenerName, ReloadPlan, ReloadRejected,
    RestartOnlyField,
};
use agenc_ircd_domain::{
    DirectMessagePolicy, GuestDirectMessagePolicy, OperationalLimits, PresencePolicy,
};
use agenc_ircd_storage::StorageRuntimeLimits;
use agenc_ircd_types::TransactionId;
use rustls::ServerConfig;
use tokio::sync::{Notify, mpsc, oneshot, watch};

use crate::RuntimeError;
use crate::account_service::AccountCreationPolicy;
use crate::admin::AdminAdmissionSnapshot;
use crate::admission::{RateLimits, TransportAdmission};
use crate::connection::{ClientQueueSnapshot, ConnectionLimits};
use crate::state_core::durable::AccountingCeilings;
use crate::supervisor::ShutdownPlan;
use crate::sync::{Arc, Mutex, lock};

/// Requests waiting at the StateCore reload boundary.
const RELOAD_REQUEST_CAPACITY: usize = 4;
/// At most one preparation waits behind the active reload.
const RELOAD_PREPARATION_CAPACITY: usize = 1;
/// Conservative payload chunk that fits below the public and admin command
/// ceilings even with the longest validated server name and nickname.
const PUBLIC_TEXT_CHUNK_BYTES: usize = 8_192;

/// Allocation-free UTF-8 chunks used to render bounded public text files.
pub(crate) struct PublicTextChunks<'a> {
    lines: std::str::Lines<'a>,
    remainder: Option<&'a str>,
}

impl<'a> Iterator for PublicTextChunks<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(remainder) = self.remainder {
                if remainder.len() <= PUBLIC_TEXT_CHUNK_BYTES {
                    self.remainder = None;
                    return Some(remainder);
                }
                let mut end = PUBLIC_TEXT_CHUNK_BYTES;
                while !remainder.is_char_boundary(end) {
                    end = end.saturating_sub(1);
                }
                let (chunk, rest) = remainder.split_at(end);
                self.remainder = Some(rest);
                return Some(chunk);
            }
            self.remainder = Some(self.lines.next()?);
        }
    }
}

pub(crate) fn public_text_chunks(text: &str) -> PublicTextChunks<'_> {
    PublicTextChunks {
        lines: text.lines(),
        remainder: None,
    }
}

/// A configuration revision independent of the protocol-state revision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConfigRevision(u64);

impl ConfigRevision {
    /// The revision installed at process startup.
    pub const INITIAL: Self = Self(1);

    /// Constructs a revision restored by a test or embedding boundary.
    pub const fn new(value: u64) -> Result<Self, RuntimeError> {
        if value == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self(value))
    }

    /// Returns the integer revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, ReloadPrepareFailure> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ReloadPrepareFailure::RevisionExhausted)
    }
}

/// A restart-only material slot compared by a one-way content fingerprint.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum RestartMaterialKey {
    StorageMaster,
    RollbackGuard,
    LoginIndex,
    LoginIndexPrevious,
    BackupSigning,
    BackupTrust,
    AuditSigning,
    AuditTrust,
    FederationSigning,
    FederationCa,
    AccessToken,
    InvitationVerification,
    AccountHpkePrivate,
    OpaqueServerSetup,
    OpaqueFakeCredential,
    SequencerPrivate,
    TlsPrivate(ListenerName),
    ClientCa(ListenerName),
}

/// Content fingerprints for every restart-only secret and trust input.
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct RestartMaterial {
    values: BTreeMap<RestartMaterialKey, [u8; 32]>,
}

impl RestartMaterial {
    pub(crate) fn insert(
        &mut self,
        key: RestartMaterialKey,
        fingerprint: [u8; 32],
    ) -> Result<(), ReloadPrepareFailure> {
        if self.values.insert(key, fingerprint).is_some() {
            return Err(ReloadPrepareFailure::InvalidMaterial);
        }
        Ok(())
    }
}

/// Values fully prepared before StateCore reaches an activation safe point.
pub(crate) struct RuntimeConfigParts {
    pub(crate) tls_endpoints: BTreeMap<ListenerName, Arc<ServerConfig>>,
    pub(crate) certificate_fingerprints: BTreeMap<ListenerName, [u8; 32]>,
    pub(crate) ocsp_fingerprints: BTreeMap<ListenerName, [u8; 32]>,
    pub(crate) restart_material: RestartMaterial,
    pub(crate) motd: Option<Arc<str>>,
    pub(crate) public_info: Option<Arc<str>>,
    pub(crate) display_name: Arc<str>,
    pub(crate) operators: OperatorRegistry,
    pub(crate) operator_admission: AdminAdmissionSnapshot,
    pub(crate) account_policy: AccountRuntimePolicy,
    pub(crate) history_default: HistoryDefault,
    pub(crate) sanction_windows: SanctionWindows,
    pub(crate) rates: RateLimits,
    pub(crate) operational_limits: OperationalLimits,
    pub(crate) connection_limits: ConnectionLimits,
    pub(crate) storage_limits: StorageRuntimeLimits,
    pub(crate) shutdown: ShutdownPlan,
}

/// Copy-only default sanction durations installed with one runtime snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SanctionWindows {
    pub(crate) session_hours: u64,
    pub(crate) account_days: u64,
}

impl SanctionWindows {
    /// Returns the default duration for a session-only sanction.
    #[must_use]
    pub const fn session_hours(self) -> u64 {
        self.session_hours
    }

    /// Returns the default duration for an account sanction.
    #[must_use]
    pub const fn account_days(self) -> u64 {
        self.account_days
    }
}

/// Copy-only account policy installed at a StateCore reload safe point.
#[derive(Clone, Copy)]
pub(crate) struct AccountRuntimePolicy {
    pub(crate) allow_guests: bool,
    pub(crate) creation: AccountCreationPolicy,
    pub(crate) default_presence: PresencePolicy,
    pub(crate) default_guest_direct_messages: GuestDirectMessagePolicy,
    pub(crate) default_direct_messages: DirectMessagePolicy,
}

/// Copy-only resource ceilings enforced at StateCore operation boundaries.
///
/// Configuration validation establishes the cross-field relationships. This
/// second checked view keeps architecture-sized integers out of allocation and
/// queue APIs and gives StateCore one atomic value to replace during reload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeResourceLimits {
    response_batch_bytes: usize,
    query_snapshot_rows: u64,
    query_snapshots_per_session: u64,
    query_snapshot_rows_global: u64,
    query_snapshot_bytes_global: u64,
}

impl RuntimeResourceLimits {
    pub(crate) const HARD_MAX: Self = Self {
        response_batch_bytes: 262_144,
        query_snapshot_rows: 100_000,
        query_snapshots_per_session: 16,
        query_snapshot_rows_global: 1_000_000,
        query_snapshot_bytes_global: 536_870_912,
    };

    fn from_config(config: &Config) -> Option<Self> {
        let response_batch_bytes =
            usize::try_from(config.limits.values.get(LimitKey::ResponseBatchBytes)).ok()?;
        let limits = Self {
            response_batch_bytes,
            query_snapshot_rows: config.limits.values.get(LimitKey::QuerySnapshotRows),
            query_snapshots_per_session: config
                .limits
                .values
                .get(LimitKey::QuerySnapshotsPerSession),
            query_snapshot_rows_global: config.limits.values.get(LimitKey::QuerySnapshotRowsGlobal),
            query_snapshot_bytes_global: config
                .limits
                .values
                .get(LimitKey::QuerySnapshotBytesGlobal),
        };
        (limits.response_batch_bytes != 0
            && limits.response_batch_bytes <= Self::HARD_MAX.response_batch_bytes
            && limits.query_snapshot_rows != 0
            && limits.query_snapshot_rows <= Self::HARD_MAX.query_snapshot_rows
            && limits.query_snapshots_per_session != 0
            && limits.query_snapshots_per_session <= Self::HARD_MAX.query_snapshots_per_session
            && limits.query_snapshot_rows <= limits.query_snapshot_rows_global
            && limits.query_snapshot_rows_global <= Self::HARD_MAX.query_snapshot_rows_global
            && limits.query_snapshot_bytes_global != 0
            && limits.query_snapshot_bytes_global <= Self::HARD_MAX.query_snapshot_bytes_global)
            .then_some(limits)
    }

    pub(crate) const fn response_batch_bytes(self) -> usize {
        self.response_batch_bytes
    }

    pub(crate) fn admits_query(
        self,
        session: ClientQueueSnapshot,
        global: ClientQueueSnapshot,
        rows: u64,
        bytes: u64,
    ) -> bool {
        rows <= self.query_snapshot_rows
            && session
                .query_snapshots()
                .checked_add(1)
                .is_some_and(|count| count <= self.query_snapshots_per_session)
            && global
                .query_rows()
                .checked_add(rows)
                .is_some_and(|total| total <= self.query_snapshot_rows_global)
            && global
                .query_bytes()
                .checked_add(bytes)
                .is_some_and(|total| total <= self.query_snapshot_bytes_global)
    }

    pub(crate) const fn accepts_query_usage(self, usage: ClientQueueSnapshot) -> bool {
        usage.largest_query_rows() <= self.query_snapshot_rows
            && usage.max_query_snapshots_per_session() <= self.query_snapshots_per_session
            && usage.query_rows() <= self.query_snapshot_rows_global
            && usage.query_bytes() <= self.query_snapshot_bytes_global
    }
}

/// One immutable, ready-to-use runtime policy view.
///
/// The fields remain private so consumers cannot assemble a partially
/// validated view. StateCore publishes one complete `Arc` at a time.
pub struct RuntimeConfigSnapshot {
    revision: ConfigRevision,
    config: Config,
    tls_endpoints: BTreeMap<ListenerName, Arc<ServerConfig>>,
    certificate_fingerprints: BTreeMap<ListenerName, [u8; 32]>,
    ocsp_fingerprints: BTreeMap<ListenerName, [u8; 32]>,
    restart_material: RestartMaterial,
    motd: Option<Arc<str>>,
    public_info: Option<Arc<str>>,
    display_name: Arc<str>,
    operators: OperatorRegistry,
    operator_admission: AdminAdmissionSnapshot,
    account_policy: AccountRuntimePolicy,
    history_default: HistoryDefault,
    sanction_windows: SanctionWindows,
    rates: RateLimits,
    operational_limits: OperationalLimits,
    connection_limits: ConnectionLimits,
    storage_limits: StorageRuntimeLimits,
    shutdown: ShutdownPlan,
}

impl RuntimeConfigSnapshot {
    pub(crate) fn from_parts(
        revision: ConfigRevision,
        config: Config,
        parts: RuntimeConfigParts,
    ) -> Self {
        Self {
            revision,
            config,
            tls_endpoints: parts.tls_endpoints,
            certificate_fingerprints: parts.certificate_fingerprints,
            ocsp_fingerprints: parts.ocsp_fingerprints,
            restart_material: parts.restart_material,
            motd: parts.motd,
            public_info: parts.public_info,
            display_name: parts.display_name,
            operators: parts.operators,
            operator_admission: parts.operator_admission,
            account_policy: parts.account_policy,
            history_default: parts.history_default,
            sanction_windows: parts.sanction_windows,
            rates: parts.rates,
            operational_limits: parts.operational_limits,
            connection_limits: parts.connection_limits,
            storage_limits: parts.storage_limits,
            shutdown: parts.shutdown,
        }
    }

    /// Returns this independently versioned configuration view.
    #[must_use]
    pub const fn revision(&self) -> ConfigRevision {
        self.revision
    }

    /// Borrows the completely validated source document.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Returns a prepared TLS endpoint for a new handshake.
    #[must_use]
    pub fn tls_endpoint(&self, listener: &ListenerName) -> Option<Arc<ServerConfig>> {
        self.tls_endpoints.get(listener).cloned()
    }

    /// Borrows content-loaded MOTD text.
    #[must_use]
    pub fn motd(&self) -> Option<&str> {
        self.motd.as_deref()
    }

    pub(crate) fn motd_arc(&self) -> Option<Arc<str>> {
        self.motd.clone()
    }

    /// Borrows content-loaded public ADMIN/INFO text.
    #[must_use]
    pub fn public_info(&self) -> Option<&str> {
        self.public_info.as_deref()
    }

    pub(crate) fn public_info_arc(&self) -> Option<Arc<str>> {
        self.public_info.clone()
    }

    pub(crate) fn display_name(&self) -> Arc<str> {
        Arc::clone(&self.display_name)
    }

    /// Borrows the exact enabled and disabled operator registry.
    #[must_use]
    pub const fn operators(&self) -> &OperatorRegistry {
        &self.operators
    }

    pub(crate) const fn operator_admission(&self) -> &AdminAdmissionSnapshot {
        &self.operator_admission
    }

    pub(crate) const fn account_policy(&self) -> AccountRuntimePolicy {
        self.account_policy
    }

    /// Returns the retention copied when an owner explicitly enables history.
    #[must_use]
    pub const fn history_default(&self) -> HistoryDefault {
        self.history_default
    }

    /// Returns the live default sanction durations.
    #[must_use]
    pub const fn sanction_windows(&self) -> SanctionWindows {
        self.sanction_windows
    }

    /// Returns the connection limits used for each new reader and queue
    /// admission. Existing reservations keep their prior admission.
    #[must_use]
    pub const fn connection_limits(&self) -> ConnectionLimits {
        self.connection_limits
    }

    pub(crate) fn listener_ceiling(&self, name: &ListenerName) -> Option<usize> {
        self.config
            .listeners
            .iter()
            .find(|listener| &listener.name == name && listener.enabled)
            .and_then(|listener| usize::try_from(listener.max_connections).ok())
    }

    pub(crate) fn client_connection_ceiling(&self) -> Option<usize> {
        usize::try_from(self.config.limits.values.get(LimitKey::ClientConnections)).ok()
    }

    pub(crate) fn tls_handshake_ceiling(&self) -> Option<usize> {
        usize::try_from(self.config.limits.values.get(LimitKey::TlsHandshakes)).ok()
    }

    pub(crate) fn direct_connections_per_address(&self) -> u64 {
        self.config
            .limits
            .values
            .get(LimitKey::DirectConnectionsPerAddress)
    }

    pub(crate) fn crypto_job_ceilings(&self) -> Option<(usize, usize)> {
        let channel =
            usize::try_from(self.config.limits.values.get(LimitKey::ChannelKeyJobs)).ok()?;
        let opaque = usize::try_from(self.config.limits.values.get(LimitKey::OpaqueJobs)).ok()?;
        Some((channel, opaque))
    }

    pub(crate) fn runtime_resource_limits(&self) -> Option<RuntimeResourceLimits> {
        RuntimeResourceLimits::from_config(&self.config)
    }

    /// Returns the currently configured four-phase shutdown budget.
    #[must_use]
    pub const fn shutdown_plan(&self) -> ShutdownPlan {
        self.shutdown
    }

    pub(crate) const fn rates(&self) -> RateLimits {
        self.rates
    }

    pub(crate) const fn operational_limits(&self) -> OperationalLimits {
        self.operational_limits
    }

    pub(crate) const fn storage_ceilings(&self) -> AccountingCeilings {
        AccountingCeilings {
            database_max_bytes: self.storage_limits.database_max_bytes(),
            backup_max_bytes: self.storage_limits.backup_max_bytes(),
        }
    }

    pub(crate) const fn storage_limits(&self) -> StorageRuntimeLimits {
        self.storage_limits
    }

    fn effective_content_matches(&self, other: &Self) -> bool {
        self.certificate_fingerprints == other.certificate_fingerprints
            && self.ocsp_fingerprints == other.ocsp_fingerprints
            && self.motd == other.motd
            && self.public_info == other.public_info
    }
}

/// A short-held handle from which runtime consumers clone one immutable view.
#[derive(Clone)]
pub struct RuntimeConfigHandle {
    current: Arc<Mutex<Arc<RuntimeConfigSnapshot>>>,
    revision: watch::Sender<ConfigRevision>,
    single_flight: Arc<AtomicBool>,
    reload_idle: Arc<Notify>,
}

impl RuntimeConfigHandle {
    /// Installs the startup snapshot.
    #[must_use]
    pub fn new(initial: Arc<RuntimeConfigSnapshot>) -> Self {
        let (revision, _initial_receiver) = watch::channel(initial.revision());
        Self {
            current: Arc::new(Mutex::new(initial)),
            revision,
            single_flight: Arc::new(AtomicBool::new(false)),
            reload_idle: Arc::new(Notify::new()),
        }
    }

    /// Clones the current immutable snapshot under a short-held lock.
    #[must_use]
    pub fn load(&self) -> Arc<RuntimeConfigSnapshot> {
        Arc::clone(&lock(&self.current))
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<ConfigRevision> {
        self.revision.subscribe()
    }

    pub(crate) fn begin_reload(&self) -> Result<ReloadLease, ReloadPrepareFailure> {
        self.single_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ReloadPrepareFailure::Busy)?;
        Ok(ReloadLease {
            gate: Arc::clone(&self.single_flight),
            idle: Arc::clone(&self.reload_idle),
        })
    }

    pub(crate) async fn wait_for_reload_idle(&self) {
        loop {
            let notified = self.reload_idle.notified();
            if !self.single_flight.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn publish_after<F>(
        &self,
        expected: ConfigRevision,
        candidate: Arc<RuntimeConfigSnapshot>,
        activate: F,
    ) -> Result<Arc<RuntimeConfigSnapshot>, ReloadRejection>
    where
        F: FnOnce() -> Result<(), ReloadRejection>,
    {
        let mut current = lock(&self.current);
        if current.revision != expected {
            return Err(ReloadRejection::StaleRevision);
        }
        activate()?;
        let revision = candidate.revision();
        let previous = std::mem::replace(&mut *current, candidate);
        drop(current);
        self.revision.send_replace(revision);
        Ok(previous)
    }

    pub(crate) fn activate_after<F>(
        &self,
        expected: ConfigRevision,
        activate: F,
    ) -> Result<(), ReloadRejection>
    where
        F: FnOnce() -> Result<(), ReloadRejection>,
    {
        let current = lock(&self.current);
        if current.revision != expected {
            return Err(ReloadRejection::StaleRevision);
        }
        activate()
    }
}

pub(crate) struct ReloadLease {
    gate: Arc<AtomicBool>,
    idle: Arc<Notify>,
}

impl Drop for ReloadLease {
    fn drop(&mut self) {
        self.gate.store(false, Ordering::Release);
        self.idle.notify_waiters();
    }
}

/// A fully prepared candidate held without changing live state.
pub struct PreparedReload {
    expected: ConfigRevision,
    candidate: Arc<RuntimeConfigSnapshot>,
    plan: ReloadPlan,
    changes_live_state: bool,
    lease: Option<ReloadLease>,
}

impl PreparedReload {
    pub(crate) fn new(
        active: &Arc<RuntimeConfigSnapshot>,
        candidate_config: Config,
        candidate_parts: RuntimeConfigParts,
    ) -> Result<Self, ReloadPrepareFailure> {
        let diff = ConfigDiff::compute(&active.config, &candidate_config);
        let plan = ReloadPlan::try_from(diff).map_err(ReloadPrepareFailure::from)?;
        let candidate = Arc::new(RuntimeConfigSnapshot::from_parts(
            active.revision.next()?,
            candidate_config,
            candidate_parts,
        ));
        if active.restart_material != candidate.restart_material {
            return Err(ReloadPrepareFailure::RestartMaterialChanged);
        }
        let changes_live_state =
            !plan.changes().is_empty() || !active.effective_content_matches(candidate.as_ref());
        Ok(Self {
            expected: active.revision,
            candidate,
            plan,
            changes_live_state,
            lease: None,
        })
    }

    /// Returns the typed document changes that passed restart-only checks.
    #[must_use]
    pub fn plan(&self) -> &ReloadPlan {
        &self.plan
    }

    pub(crate) fn is_noop(&self) -> bool {
        !self.changes_live_state
    }

    pub(crate) fn permits_signal_activation(&self) -> bool {
        !self.plan.requires_budget_check()
    }

    pub(crate) const fn expected_revision(&self) -> ConfigRevision {
        self.expected
    }

    pub(crate) fn candidate(&self) -> Arc<RuntimeConfigSnapshot> {
        Arc::clone(&self.candidate)
    }

    pub(crate) fn attach_lease(&mut self, lease: ReloadLease) {
        self.lease = Some(lease);
    }

    pub(crate) fn take_lease(&mut self) -> Option<ReloadLease> {
        self.lease.take()
    }
}

/// A preparation failure before any live state changed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReloadPrepareFailure {
    /// The candidate document, host state, or loaded content was invalid.
    InvalidConfig,
    /// One or more typed fields require a process restart.
    RestartRequired(Vec<RestartOnlyField>),
    /// A same-path restart-only secret or trust input changed bytes.
    RestartMaterialChanged,
    /// A material set was incomplete or contained duplicate purpose keys.
    InvalidMaterial,
    /// The configuration revision cannot be incremented.
    RevisionExhausted,
    /// The candidate could not fit the process memory working set.
    ResourceFloor,
    /// The candidate storage ceiling is already below committed use.
    StorageFloor,
    /// Another reload already occupies the single-flight preparation slot.
    Busy,
    /// The preparation owner is no longer available.
    Unavailable,
}

impl From<ReloadRejected> for ReloadPrepareFailure {
    fn from(rejected: ReloadRejected) -> Self {
        match rejected {
            ReloadRejected::RestartOnly(fields) => Self::RestartRequired(fields),
        }
    }
}

impl fmt::Display for ReloadPrepareFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "reload candidate is invalid",
            Self::RestartRequired(_) => "reload candidate requires restart",
            Self::RestartMaterialChanged => "reload changed restart-only material",
            Self::InvalidMaterial => "reload material is invalid",
            Self::RevisionExhausted => "configuration revision exhausted",
            Self::ResourceFloor => "reload violates a resource floor",
            Self::StorageFloor => "reload violates a storage floor",
            Self::Busy => "reload preparation is busy",
            Self::Unavailable => "reload preparation is unavailable",
        })
    }
}

impl std::error::Error for ReloadPrepareFailure {}

/// Why StateCore rejected a prepared candidate without changing live state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReloadRejection {
    Busy,
    Quiescing,
    StaleRevision,
    CurrentUse,
    StorageUnavailable,
}

impl fmt::Display for ReloadRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "reload is busy",
            Self::Quiescing => "runtime is quiescing",
            Self::StaleRevision => "configuration revision is stale",
            Self::CurrentUse => "reload is below current use",
            Self::StorageUnavailable => "reload owner is unavailable",
        })
    }
}

impl std::error::Error for ReloadRejection {}

/// A provisional activation held behind the administrative audit barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReloadActivation {
    pub(crate) revision: ConfigRevision,
    pub(crate) transaction_id: TransactionId,
    pub(crate) changes_live_state: bool,
}

/// Typed activation outcomes returned by StateCore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReloadOutcome {
    NoChange(ConfigRevision),
    Applied(ConfigRevision),
    Rejected(ReloadRejection),
}

/// Result of installing the global barrier for an audited reload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditedReloadStart {
    Provisional(ReloadActivation),
    Indeterminate,
}

/// Which exact, signed outcome became durable behind the reload barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditedReloadResult {
    Success,
    Failure(ReloadRejection),
}

/// Result of committing the exact audit outcome held by a provisional reload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReloadAuditCommitOutcome {
    Committed(AuditedReloadResult),
    NotCommitted(ReloadRejection),
    Indeterminate,
}

pub(crate) enum ReloadCoreRequest {
    ActivateSignal {
        prepared: Box<PreparedReload>,
        reply: oneshot::Sender<ReloadOutcome>,
    },
    ActivateAudited {
        prepared: Box<PreparedReload>,
        success_event: Box<AdminAuditEvent>,
        failure_event: Box<AdminAuditEvent>,
        reply: oneshot::Sender<AuditedReloadStart>,
    },
    CommitOutcome {
        activation: ReloadActivation,
        reply: oneshot::Sender<Result<AuditedReloadResult, ReloadRejection>>,
    },
    Finalize {
        activation: ReloadActivation,
        reply: oneshot::Sender<Result<ConfigRevision, ReloadRejection>>,
    },
}

/// Cloneable sending half held by signal and administrative reload owners.
#[derive(Clone)]
pub(crate) struct ReloadPort {
    sender: mpsc::Sender<ReloadCoreRequest>,
}

impl ReloadPort {
    pub(crate) async fn activate_signal(&self, prepared: PreparedReload) -> ReloadOutcome {
        let (reply, response) = oneshot::channel();
        self.send_activation(
            ReloadCoreRequest::ActivateSignal {
                prepared: Box::new(prepared),
                reply,
            },
            response,
        )
        .await
    }

    async fn activate_audited(
        &self,
        prepared: PreparedReload,
        success_event: AdminAuditEvent,
        failure_event: AdminAuditEvent,
    ) -> AuditedReloadStart {
        let (reply, response) = oneshot::channel();
        let request = ReloadCoreRequest::ActivateAudited {
            prepared: Box::new(prepared),
            success_event: Box::new(success_event),
            failure_event: Box::new(failure_event),
            reply,
        };
        if self.sender.try_send(request).is_err() {
            return AuditedReloadStart::Indeterminate;
        }
        response.await.unwrap_or(AuditedReloadStart::Indeterminate)
    }

    async fn send_activation(
        &self,
        request: ReloadCoreRequest,
        response: oneshot::Receiver<ReloadOutcome>,
    ) -> ReloadOutcome {
        if let Err(error) = self.sender.try_send(request) {
            return match error {
                mpsc::error::TrySendError::Full(_) => {
                    ReloadOutcome::Rejected(ReloadRejection::Busy)
                }
                mpsc::error::TrySendError::Closed(_) => {
                    ReloadOutcome::Rejected(ReloadRejection::StorageUnavailable)
                }
            };
        }
        response
            .await
            .unwrap_or(ReloadOutcome::Rejected(ReloadRejection::StorageUnavailable))
    }

    pub(crate) async fn commit_outcome(
        &self,
        activation: ReloadActivation,
        token: &crate::cancel::CancellationToken,
    ) -> ReloadAuditCommitOutcome {
        let (reply, response) = oneshot::channel();
        let request = ReloadCoreRequest::CommitOutcome { activation, reply };
        match self.sender.try_send(request) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return ReloadAuditCommitOutcome::Indeterminate;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return ReloadAuditCommitOutcome::Indeterminate;
            }
        }
        tokio::select! {
            () = token.cancelled() => ReloadAuditCommitOutcome::Indeterminate,
            result = response => match result {
                Ok(Ok(outcome)) => ReloadAuditCommitOutcome::Committed(outcome),
                Ok(Err(rejection)) => ReloadAuditCommitOutcome::NotCommitted(rejection),
                Err(_) => ReloadAuditCommitOutcome::Indeterminate,
            }
        }
    }

    pub(crate) async fn finalize(
        &self,
        activation: ReloadActivation,
    ) -> Result<ConfigRevision, ReloadRejection> {
        self.finish(activation).await
    }

    async fn finish(
        &self,
        activation: ReloadActivation,
    ) -> Result<ConfigRevision, ReloadRejection> {
        let (reply, response) = oneshot::channel();
        let request = ReloadCoreRequest::Finalize { activation, reply };
        self.sender.try_send(request).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => ReloadRejection::Busy,
            mpsc::error::TrySendError::Closed(_) => ReloadRejection::StorageUnavailable,
        })?;
        response
            .await
            .unwrap_or(Err(ReloadRejection::StorageUnavailable))
    }
}

/// Receiving half installed exactly once into StateCore.
pub(crate) struct ReloadCoreInbox {
    receiver: mpsc::Receiver<ReloadCoreRequest>,
    handle: RuntimeConfigHandle,
    admission: Arc<TransportAdmission>,
}

impl ReloadCoreInbox {
    pub(super) fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<ReloadCoreRequest>,
        RuntimeConfigHandle,
        Arc<TransportAdmission>,
    ) {
        (self.receiver, self.handle, self.admission)
    }
}

/// Creates the one bounded reload channel and binds it to one snapshot handle.
pub(crate) fn reload_channel(
    handle: RuntimeConfigHandle,
    admission: Arc<TransportAdmission>,
) -> (ReloadPort, ReloadCoreInbox) {
    let (sender, receiver) = mpsc::channel(RELOAD_REQUEST_CAPACITY);
    (
        ReloadPort { sender },
        ReloadCoreInbox {
            receiver,
            handle,
            admission,
        },
    )
}

struct ReloadPreparationRequest {
    reply: oneshot::Sender<Result<PreparedReload, ReloadPrepareFailure>>,
}

/// Cloneable single-flight preparation and audited-activation handle.
#[derive(Clone)]
pub(crate) struct ReloadPreparationPort {
    sender: mpsc::Sender<ReloadPreparationRequest>,
    activation: ReloadPort,
}

impl ReloadPreparationPort {
    pub(crate) async fn prepare(
        &self,
        token: &crate::cancel::CancellationToken,
    ) -> Result<PreparedReload, ReloadPrepareFailure> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(ReloadPreparationRequest { reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ReloadPrepareFailure::Busy,
                mpsc::error::TrySendError::Closed(_) => ReloadPrepareFailure::Unavailable,
            })?;
        tokio::select! {
            () = token.cancelled() => Err(ReloadPrepareFailure::Unavailable),
            result = response => result.unwrap_or(Err(ReloadPrepareFailure::Unavailable)),
        }
    }

    pub(crate) async fn activate(
        &self,
        prepared: PreparedReload,
        success_event: AdminAuditEvent,
        failure_event: AdminAuditEvent,
    ) -> AuditedReloadStart {
        self.activation
            .activate_audited(prepared, success_event, failure_event)
            .await
    }

    pub(crate) async fn commit_outcome(
        &self,
        activation: ReloadActivation,
        token: &crate::cancel::CancellationToken,
    ) -> ReloadAuditCommitOutcome {
        self.activation.commit_outcome(activation, token).await
    }

    pub(crate) async fn finalize(
        &self,
        activation: ReloadActivation,
    ) -> Result<ConfigRevision, ReloadRejection> {
        self.activation.finalize(activation).await
    }
}

/// Single receiving half selected by the daemon control owner.
pub(crate) struct ReloadPreparationInbox {
    receiver: mpsc::Receiver<ReloadPreparationRequest>,
}

impl ReloadPreparationInbox {
    pub(crate) async fn recv(&mut self) -> Option<ReloadPreparationReply> {
        self.receiver
            .recv()
            .await
            .map(|request| ReloadPreparationReply {
                reply: request.reply,
            })
    }
}

pub(crate) struct ReloadPreparationReply {
    reply: oneshot::Sender<Result<PreparedReload, ReloadPrepareFailure>>,
}

impl ReloadPreparationReply {
    pub(crate) fn send(self, result: Result<PreparedReload, ReloadPrepareFailure>) {
        let _sent = self.reply.send(result);
    }
}

/// Binds administrative preparation to the same StateCore activation port
/// used by SIGHUP.
pub(crate) fn reload_preparation_channel(
    activation: ReloadPort,
) -> (ReloadPreparationPort, ReloadPreparationInbox) {
    let (sender, receiver) = mpsc::channel(RELOAD_PREPARATION_CAPACITY);
    (
        ReloadPreparationPort { sender, activation },
        ReloadPreparationInbox { receiver },
    )
}

#[cfg(test)]
mod tests {
    use agenc_ircd_admin::{OperatorRecord, OperatorRegistry};
    use agenc_ircd_config::{Config, LimitKey, PathResolver, ValidationDepth};
    use agenc_ircd_crypto::Ed25519SecretKey;
    use agenc_ircd_domain::{OperationalLimitValues, OperationalLimits};
    use agenc_ircd_types::{AdminPermission, AdminPermissionSet, OperatorId};

    use super::*;
    use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort};
    use crate::connection::{
        CONTROL_ITEM_SLOTS, ClientQueueDemand, ClientSink, ConnectionGeneration, ConnectionLimits,
        MAX_DEMAND_FRAMES, QueueLimits, SinkReserveError, WriterQueue,
    };

    const PUBLIC: &str = include_str!("../../agenc-ircd-config/tests/golden/public.toml");

    fn config() -> Result<Config, Box<dyn std::error::Error>> {
        Ok(Config::parse_text(
            PUBLIC,
            &PathResolver::none(),
            ValidationDepth::Document,
        )?)
    }

    fn operators() -> Result<OperatorRegistry, Box<dyn std::error::Error>> {
        let mut permissions = AdminPermissionSet::EMPTY;
        permissions.insert(AdminPermission::Observe);
        Ok(OperatorRegistry::from_records(vec![OperatorRecord::new(
            OperatorId::from_bytes([4; 16]),
            Ed25519SecretKey::from_bytes([5; 32]).public_key(),
            None,
            vec![1_000],
            Vec::new(),
            permissions,
            true,
        )?])?)
    }

    fn parts() -> Result<RuntimeConfigParts, Box<dyn std::error::Error>> {
        Ok(RuntimeConfigParts {
            tls_endpoints: BTreeMap::new(),
            certificate_fingerprints: BTreeMap::new(),
            ocsp_fingerprints: BTreeMap::new(),
            restart_material: RestartMaterial::default(),
            motd: None,
            public_info: None,
            display_name: Arc::from("AgenC"),
            operators: operators()?,
            operator_admission: AdminAdmissionSnapshot::new(vec![1_000], Vec::new(), Vec::new()),
            account_policy: AccountRuntimePolicy {
                allow_guests: true,
                creation: AccountCreationPolicy::Open,
                default_presence: PresencePolicy::Private,
                default_guest_direct_messages: GuestDirectMessagePolicy::Deny,
                default_direct_messages: DirectMessagePolicy::Contacts,
            },
            history_default: HistoryDefault::OneDay,
            sanction_windows: SanctionWindows {
                session_hours: 24,
                account_days: 30,
            },
            rates: RateLimits::defaults(),
            operational_limits: OperationalLimits::new(OperationalLimitValues {
                sessions_per_account: 8,
                channels_per_session: 64,
                members_per_channel: 4_096,
                global_channels: 100_000,
                local_channels: 10_000,
                invites_per_channel: 256,
                invites_per_principal: 32,
                invites_global: 100_000,
                contacts_per_account: 1_000,
            })?,
            connection_limits: ConnectionLimits::DEFAULT,
            storage_limits: StorageRuntimeLimits::new(1 << 30, 1 << 31, 10_000)?,
            shutdown: ShutdownPlan::DEFAULT,
        })
    }

    fn snapshot() -> Result<Arc<RuntimeConfigSnapshot>, Box<dyn std::error::Error>> {
        Ok(Arc::new(RuntimeConfigSnapshot::from_parts(
            ConfigRevision::INITIAL,
            config()?,
            parts()?,
        )))
    }

    #[test]
    fn handle_publishes_only_from_the_expected_revision() -> Result<(), Box<dyn std::error::Error>>
    {
        let initial = snapshot()?;
        let handle = RuntimeConfigHandle::new(Arc::clone(&initial));
        let candidate = Arc::new(RuntimeConfigSnapshot::from_parts(
            ConfigRevision::new(2)?,
            config()?,
            parts()?,
        ));
        let replaced =
            handle.publish_after(ConfigRevision::INITIAL, Arc::clone(&candidate), || Ok(()))?;
        assert!(Arc::ptr_eq(&replaced, &initial));
        assert!(Arc::ptr_eq(&handle.load(), &candidate));
        assert!(matches!(
            handle.publish_after(ConfigRevision::INITIAL, initial, || Ok(())),
            Err(ReloadRejection::StaleRevision)
        ));
        Ok(())
    }

    #[test]
    fn no_op_candidate_keeps_the_revision_stable() -> Result<(), Box<dyn std::error::Error>> {
        let active = snapshot()?;
        let prepared = PreparedReload::new(&active, config()?, parts()?)?;
        assert!(prepared.is_noop());
        assert!(prepared.plan().changes().is_empty());
        assert_eq!(active.revision().get(), 1);
        assert_eq!(prepared.candidate.revision().get(), 2);
        Ok(())
    }

    #[test]
    fn signal_activation_accepts_lowered_limits_but_requires_rehash_for_raises()
    -> Result<(), Box<dyn std::error::Error>> {
        let active = snapshot()?;
        let mut lowered = config()?;
        lowered.limits.values = lowered
            .limits
            .values
            .with(LimitKey::ClientConnections, 40_000);
        let lowered = PreparedReload::new(&active, lowered, parts()?)?;
        assert!(lowered.permits_signal_activation());

        let mut raised = config()?;
        raised.limits.values = raised
            .limits
            .values
            .with(LimitKey::ClientConnections, 60_000);
        let raised = PreparedReload::new(&active, raised, parts()?)?;
        assert!(!raised.permits_signal_activation());
        Ok(())
    }

    #[test]
    fn live_queue_limits_gate_new_work_while_old_reservations_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let initial = snapshot()?;
        let handle = RuntimeConfigHandle::new(initial);
        let initial_limits = ConnectionLimits::DEFAULT.queue;
        let budget = MemoryBudget::new(64 * 1_048_576);
        let charge = initial_limits.backing_charge()?;
        let mut batch = budget.try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?;
        let backing = batch
            .split_exact(charge.bytes())
            .ok_or(RuntimeError::InvalidValue)?;
        let queue = WriterQueue::new_live(
            ConnectionGeneration::new(1),
            initial_limits,
            backing,
            handle.clone(),
        )?;
        let first = queue
            .try_reserve(ClientQueueDemand::new(vec![1])?)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        let second = queue
            .try_reserve(ClientQueueDemand::new(vec![1])?)
            .map_err(|_| RuntimeError::LimitExceeded)?;

        let mut candidate_config = config()?;
        candidate_config.limits.values = candidate_config
            .limits
            .values
            .with(LimitKey::ResponseBatchesPerConnection, 1)
            .with(LimitKey::ClientOutputBytes, 262_144);
        let mut candidate_parts = parts()?;
        candidate_parts.connection_limits.queue =
            QueueLimits::new(262_144, 65_536, MAX_DEMAND_FRAMES + CONTROL_ITEM_SLOTS)?;
        let candidate = Arc::new(RuntimeConfigSnapshot::from_parts(
            ConfigRevision::new(2)?,
            candidate_config,
            candidate_parts,
        ));
        let _previous = handle.publish_after(ConfigRevision::INITIAL, candidate, || Ok(()))?;

        assert_eq!(queue.limits().response_batches(), 1);
        assert_eq!(queue.queue_snapshot().capacity_bytes(), 262_144);
        assert_eq!(
            queue.try_reserve(ClientQueueDemand::new(vec![1])?).err(),
            Some(SinkReserveError::Full)
        );
        drop(first);
        assert_eq!(
            queue.try_reserve(ClientQueueDemand::new(vec![1])?).err(),
            Some(SinkReserveError::Full),
            "the second old reservation remains valid and occupies the lowered ceiling"
        );
        drop(second);
        assert_eq!(
            queue
                .try_reserve(ClientQueueDemand::new(vec![4_096; 49])?)
                .err(),
            Some(SinkReserveError::Full),
            "new work observes the lowered byte ceiling"
        );
        let newly_admitted = queue
            .try_reserve(ClientQueueDemand::new(vec![1])?)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        drop(newly_admitted);
        Ok(())
    }

    #[test]
    fn snapshot_carries_ready_history_and_sanction_defaults()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = snapshot()?;
        assert_eq!(snapshot.history_default(), HistoryDefault::OneDay);
        assert_eq!(snapshot.sanction_windows().session_hours(), 24);
        assert_eq!(snapshot.sanction_windows().account_days(), 30);
        Ok(())
    }

    #[test]
    fn snapshot_carries_the_validated_direct_connection_ceiling()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = snapshot()?;
        assert_eq!(snapshot.direct_connections_per_address(), 16);
        Ok(())
    }

    #[test]
    fn snapshot_carries_the_validated_crypto_job_ceilings() -> Result<(), Box<dyn std::error::Error>>
    {
        let snapshot = snapshot()?;
        assert_eq!(snapshot.crypto_job_ceilings(), Some((4, 8)));
        Ok(())
    }

    #[test]
    fn snapshot_carries_the_validated_query_and_response_ceilings()
    -> Result<(), Box<dyn std::error::Error>> {
        let limits = snapshot()?
            .runtime_resource_limits()
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(limits.response_batch_bytes(), 65_536);
        assert_eq!(limits.query_snapshot_rows, 10_000);
        assert_eq!(limits.query_snapshots_per_session, 4);
        assert_eq!(limits.query_snapshot_rows_global, 100_000);
        assert_eq!(limits.query_snapshot_bytes_global, 67_108_864);
        Ok(())
    }

    #[test]
    fn query_ceilings_gate_new_work_and_reload_at_exact_current_use()
    -> Result<(), Box<dyn std::error::Error>> {
        let limits = snapshot()?
            .runtime_resource_limits()
            .ok_or(RuntimeError::InvalidValue)?;
        let session = ClientQueueSnapshot::with_query_usage(0, 0, 3, 0, 0, 0, 3);
        let global = ClientQueueSnapshot::with_query_usage(0, 0, 3, 90_000, 67_104_768, 9_000, 3);
        assert!(limits.admits_query(session, global, 10_000, 4_096));
        assert!(!limits.admits_query(session, global, 10_001, 4_096));
        assert!(!limits.admits_query(
            ClientQueueSnapshot::with_query_usage(0, 0, 4, 0, 0, 0, 4),
            global,
            1,
            4_096,
        ));
        assert!(!limits.admits_query(
            session,
            ClientQueueSnapshot::with_query_usage(0, 0, 3, 90_001, 0, 9_000, 3),
            10_000,
            4_096,
        ));
        assert!(!limits.admits_query(session, global, 10_000, 4_097));

        let exact_use =
            ClientQueueSnapshot::with_query_usage(0, 0, 4, 100_000, 67_108_864, 10_000, 4);
        assert!(limits.accepts_query_usage(exact_use));
        for over in [
            ClientQueueSnapshot::with_query_usage(0, 0, 4, 100_000, 67_108_864, 10_001, 4),
            ClientQueueSnapshot::with_query_usage(0, 0, 5, 100_000, 67_108_864, 10_000, 5),
            ClientQueueSnapshot::with_query_usage(0, 0, 4, 100_001, 67_108_864, 10_000, 4),
            ClientQueueSnapshot::with_query_usage(0, 0, 4, 100_000, 67_108_865, 10_000, 4),
        ] {
            assert!(!limits.accepts_query_usage(over));
        }
        Ok(())
    }

    #[test]
    fn same_path_content_and_restart_material_are_distinguished()
    -> Result<(), Box<dyn std::error::Error>> {
        let active = snapshot()?;
        let mut content_parts = parts()?;
        content_parts.motd = Some(Arc::from("new text"));
        let content = PreparedReload::new(&active, config()?, content_parts)?;
        assert!(!content.is_noop());

        let mut ocsp_parts = parts()?;
        ocsp_parts
            .ocsp_fingerprints
            .insert(ListenerName::parse("public")?, [8; 32]);
        let ocsp = PreparedReload::new(&active, config()?, ocsp_parts)?;
        assert!(!ocsp.is_noop());

        let mut material_parts = parts()?;
        material_parts
            .restart_material
            .insert(RestartMaterialKey::StorageMaster, [9; 32])?;
        assert!(matches!(
            PreparedReload::new(&active, config()?, material_parts),
            Err(ReloadPrepareFailure::RestartMaterialChanged)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn bounded_channel_reports_busy_without_waiting() -> Result<(), Box<dyn std::error::Error>>
    {
        let handle = RuntimeConfigHandle::new(snapshot()?);
        let admission = Arc::new(TransportAdmission::new(
            RateLimits::defaults(),
            16,
            Arc::new(crate::budget::MemoryBudget::new(1 << 20)),
            Box::new(crate::clock::SystemMonotonicClock::start()),
        )?);
        let (port, _inbox) = reload_channel(handle, admission);
        for _ in 0..RELOAD_REQUEST_CAPACITY {
            let active = snapshot()?;
            let prepared = PreparedReload::new(&active, config()?, parts()?)?;
            let (reply, _response) = oneshot::channel();
            port.sender.try_send(ReloadCoreRequest::ActivateSignal {
                prepared: Box::new(prepared),
                reply,
            })?;
        }
        let prepared = PreparedReload::new(&snapshot()?, config()?, parts()?)?;
        assert_eq!(
            port.activate_signal(prepared).await,
            ReloadOutcome::Rejected(ReloadRejection::Busy)
        );
        Ok(())
    }

    #[test]
    fn public_text_chunks_preserve_utf8_with_a_bounded_line_size() {
        let text = format!("short\n{}\nlast", "é".repeat(32_768));
        let chunks: Vec<&str> = public_text_chunks(&text).collect();
        assert_eq!(chunks.first(), Some(&"short"));
        assert_eq!(chunks.last(), Some(&"last"));
        assert!(chunks.iter().all(|chunk| chunk.len() <= 8_192));
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.is_char_boundary(chunk.len()))
        );
        let reconstructed = chunks
            .iter()
            .skip(1)
            .take(chunks.len().saturating_sub(2))
            .copied()
            .collect::<String>();
        assert_eq!(reconstructed, "é".repeat(32_768));
    }

    #[test]
    fn reload_lease_serializes_preparation_until_the_candidate_is_consumed()
    -> Result<(), Box<dyn std::error::Error>> {
        let handle = RuntimeConfigHandle::new(snapshot()?);
        let lease = handle.begin_reload()?;
        assert!(matches!(
            handle.begin_reload(),
            Err(ReloadPrepareFailure::Busy)
        ));
        drop(lease);
        assert!(handle.begin_reload().is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn coalesced_reload_waiter_resumes_only_after_the_lease_drops()
    -> Result<(), Box<dyn std::error::Error>> {
        let handle = RuntimeConfigHandle::new(snapshot()?);
        let lease = handle.begin_reload()?;
        let waiter_handle = handle.clone();
        let waiter = tokio::spawn(async move {
            waiter_handle.wait_for_reload_idle().await;
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(lease);
        waiter.await?;
        Ok(())
    }
}
