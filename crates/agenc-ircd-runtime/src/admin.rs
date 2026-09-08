//! Isolated administrative transport ownership (spec 22.4 and 22.5).
//!
//! This module is the only runtime boundary that accepts administrative
//! plaintext. Listener tasks hand complete bounded CRLF records to the
//! private admin-owner channel; neither credentials nor lines are converted
//! into public client messages or sent to `StateCore`'s client inbox.

mod audit;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use agenc_ircd_admin::{
    AdminAuditEvent, AdminAuditPhase, AdminChallenge, AdminCommand, AdminCommandEvent,
    AdminSession, AdminSessionBinding, ConfirmationState, ConfirmationToken, MAX_ADMIN_LINE_BYTES,
    MAX_ADMIN_OUTPUT_LINE_BYTES, MAX_AUDIT_EXPORT_BYTES, MAX_AUDIT_EXPORT_RECORDS,
    OperatorRegistry, PeerIdentity, StatsSelector, StatsValues, TransportKind, encode_base64url,
    render_stats_batch, render_stats_storage_unavailable, render_stats_unavailable,
};
use agenc_ircd_crypto::{Ed25519SecretKey, RollbackGuardRootKey, StorageMasterKey};
use agenc_ircd_storage::{
    BackupDestination, BackupDirectoryReader, BackupReceipt, BackupTrustKey, StorageCompletion,
    StorageError, StoragePort, verify_backup,
};
use agenc_ircd_types::{EntropySource, MonotonicClock, ServerId, WallClock};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot, watch};
use zeroize::Zeroizing;

use crate::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort as _, MemoryCharge, MemoryPermitBatch,
};
use crate::cancel::CancellationToken;
use crate::connection::{
    ConnectionExit, ConnectionGeneration, ConnectionResources, FlushAcknowledgement,
};
use crate::federation::owner::FederationControl;
use crate::observe::adapter::RuntimeObserver;
use crate::observe::health::{HealthSnapshot, Liveness, ReadinessGate};
use crate::observe::metrics::ResultClass;
use crate::purpose::ListenerPurpose;
use crate::runtime_config::{
    AuditedReloadResult, AuditedReloadStart, ReloadAuditCommitOutcome, ReloadPreparationPort,
    ReloadPrepareFailure, ReloadRejection, RuntimeConfigHandle,
};
use crate::state_core::inbox::CloseReason;
use crate::state_core::{
    AdminCoreFailure, AdminCorePort, AdminCoreResult, AdminMutation, AdminTarget,
};
use crate::sync::Arc;
use crate::tls::{CLOSE_NOTIFY_GRACE, WRITE_STALL_BUDGET};

pub(crate) use audit::{AuditAuthority, PreparedMaintenanceAudit};
use audit::{AuditExportFailure, PendingStartupActionKind};
pub use audit::{LegacyAuditSourceValidator, SchemaThreeAuditSourceValidator};

/// RFC 9846 exporter label for the remote administrative session binding.
pub(crate) const ADMIN_EXPORTER_LABEL: &[u8] = b"EXPORTER-agenc-chat-admin-v1";
/// Admin messages waiting for the single owner.
const ADMIN_OWNER_CAPACITY: usize = 64;
/// Lifecycle requests waiting for the administrative owner.
const ADMIN_LIFECYCLE_CAPACITY: usize = 4;
/// One selected lifecycle request plus every request that can already be
/// queued behind it.
const ADMIN_LIFECYCLE_BATCH_CAPACITY: usize = ADMIN_LIFECYCLE_CAPACITY + 1;
/// Complete ordered response batches waiting for one writer.
const ADMIN_OUTPUT_CAPACITY: usize = 4;
/// Owner notification stall budget, matching the public connection boundary.
const ADMIN_NOTICE_BUDGET: Duration = Duration::from_secs(30);
/// Largest ordinary response batch. Audit export has a separately charged
/// path and will raise this through a typed constructor in its composition
/// slice.
const MAX_ORDINARY_BATCH_LINES: usize = 266;
/// Process actions waiting for the root shutdown driver.
const ADMIN_PROCESS_CAPACITY: usize = 1;
/// Periodic opportunity to replace one expired audit prefix.
const AUDIT_RETENTION_SWEEP: Duration = Duration::from_secs(60 * 60);
/// Cooperative cadence for polling an admitted storage-owner completion.
const ADMIN_STORAGE_COMPLETION_POLL: Duration = Duration::from_millis(1);
/// Checked conversion unit for configured retention days.
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
/// Maximum directory entries examined while reconciling one interrupted
/// administrative backup action.
const MAX_ADMIN_BACKUP_DIRECTORY_ENTRIES: usize = 4_096;
/// One input-free final frame queued for each administrative connection.
const ADMIN_SHUTDOWN_LINE: &str = "ERROR :Server shutting down";

fn acquire_audit_export_memory(
    budget: &MemoryBudget,
) -> Result<MemoryPermitBatch, crate::RuntimeError> {
    let frozen = MemoryCharge::allocation(MAX_AUDIT_EXPORT_BYTES)?;
    let rendered = MemoryCharge::allocation(MAX_AUDIT_EXPORT_BYTES)?;
    let charges = BoundedMemoryCharges::new(&[frozen, rendered])?;
    budget.try_acquire_batch(charges).map_err(Into::into)
}

// agenc-review: focus owner=runtime reviewed=2026-09-01 reason=cooperative polling leaves admitted storage work owned by the joined storage thread without spawning a detachable blocking waiter
async fn wait_storage_completion<T>(completion: StorageCompletion<T>) -> Result<T, StorageError> {
    loop {
        match completion.try_take()? {
            Some(result) => return result,
            None => tokio::time::sleep(ADMIN_STORAGE_COMPLETION_POLL).await,
        }
    }
}

/// A committed administrative process request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminProcessAction {
    Die,
    Restart,
}

#[derive(Clone)]
pub(crate) struct AdminProcessPort {
    sender: mpsc::Sender<AdminProcessAction>,
}

impl AdminProcessPort {
    fn request(&self, action: AdminProcessAction) -> Result<(), AdminCoreFailure> {
        self.sender.try_send(action).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => AdminCoreFailure::Busy,
            mpsc::error::TrySendError::Closed(_) => AdminCoreFailure::StorageUnavailable,
        })
    }
}

pub(crate) struct AdminProcessInbox {
    receiver: mpsc::Receiver<AdminProcessAction>,
}

impl AdminProcessInbox {
    pub(crate) async fn recv(&mut self) -> Option<AdminProcessAction> {
        self.receiver.recv().await
    }
}

pub(crate) fn admin_process_channel() -> (AdminProcessPort, AdminProcessInbox) {
    let (sender, receiver) = mpsc::channel(ADMIN_PROCESS_CAPACITY);
    (AdminProcessPort { sender }, AdminProcessInbox { receiver })
}

/// Private capability for one signed backup action. The owner retains only
/// the configured directory, a bounded storage port, and zeroized key bytes.
pub(crate) struct AdminBackupRuntime {
    storage: StoragePort,
    directory: PathBuf,
    signing_key: Zeroizing<[u8; 32]>,
    source_master_key: Zeroizing<[u8; 32]>,
    source_guard_root_key: Zeroizing<[u8; 32]>,
    trusted_keys: Vec<BackupTrustKey>,
    maximum_bytes: u64,
}

impl AdminBackupRuntime {
    pub(crate) fn new(
        storage: StoragePort,
        directory: PathBuf,
        signing_key: [u8; 32],
        source_master_key: [u8; 32],
        source_guard_root_key: [u8; 32],
        trusted_keys: Vec<BackupTrustKey>,
        maximum_bytes: u64,
    ) -> Self {
        Self {
            storage,
            directory,
            signing_key: Zeroizing::new(signing_key),
            source_master_key: Zeroizing::new(source_master_key),
            source_guard_root_key: Zeroizing::new(source_guard_root_key),
            trusted_keys,
            maximum_bytes,
        }
    }

    fn start(
        &self,
        audit_sequence: u64,
        created_at: u64,
        backup_id: [u8; 16],
    ) -> Result<StorageCompletion<BackupReceipt>, agenc_ircd_storage::StorageError> {
        let name = format!(
            "admin-{audit_sequence:020}-{}.agenc-backup",
            encode_base64url(&backup_id)
        );
        let destination = BackupDestination::new(&self.directory, &name)?;
        self.storage.try_backup(
            destination,
            Ed25519SecretKey::from_bytes(*self.signing_key),
            created_at,
            backup_id,
        )
    }

    fn reconciliation_job(&self, audit_sequence: u64, created_at: u64) -> BackupReconciliationJob {
        BackupReconciliationJob {
            directory: self.directory.clone(),
            source_master_key: self.source_master_key.clone(),
            source_guard_root_key: self.source_guard_root_key.clone(),
            trusted_keys: self.trusted_keys.clone(),
            maximum_bytes: self.maximum_bytes,
            audit_sequence,
            created_at,
        }
    }
}

struct BackupReconciliationJob {
    directory: PathBuf,
    source_master_key: Zeroizing<[u8; 32]>,
    source_guard_root_key: Zeroizing<[u8; 32]>,
    trusted_keys: Vec<BackupTrustKey>,
    maximum_bytes: u64,
    audit_sequence: u64,
    created_at: u64,
}

impl BackupReconciliationJob {
    fn run(self) -> Result<bool, StorageError> {
        let prefix = format!("admin-{:020}-", self.audit_sequence);
        let suffix = ".agenc-backup";
        let mut directory =
            BackupDirectoryReader::open(&self.directory, MAX_ADMIN_BACKUP_DIRECTORY_ENTRIES)?;
        let mut completed = false;
        while let Some(name) = directory.next_name()? {
            let Some(encoded_id) = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix(suffix))
            else {
                continue;
            };
            if encoded_id.len() != 22 || completed {
                return Err(StorageError::AuthenticationFailed);
            }
            let candidate = directory.open_candidate(&name)?;
            let verified = verify_backup(
                candidate,
                &StorageMasterKey::from_bytes(*self.source_master_key),
                &RollbackGuardRootKey::from_bytes(*self.source_guard_root_key),
                &self.trusted_keys,
                self.maximum_bytes,
            )?;
            if verified.header.created_at() != self.created_at
                || encode_base64url(&verified.header.backup_id()) != encoded_id
            {
                return Err(StorageError::AuthenticationFailed);
            }
            completed = true;
        }
        Ok(completed)
    }
}

/// Opaque listener-side handle for the private admin-owner inbox.
///
/// The fields and construction path stay crate-private. Embedders can place
/// `None` in [`crate::listener::ListenerContext`] when no admin endpoint is
/// present, but cannot inject administrative events.
#[derive(Clone)]
pub struct AdminTransportPort {
    binding: AdminSessionBinding,
    sender: mpsc::Sender<AdminOwnerMessage>,
}

impl AdminTransportPort {
    pub(crate) const fn binding(&self) -> AdminSessionBinding {
        self.binding
    }

    async fn opened(
        &self,
        generation: ConnectionGeneration,
        challenge: AdminChallenge,
        peer: PeerIdentity,
        output: AdminOutput,
        token: &CancellationToken,
    ) -> Result<(), CloseReason> {
        self.send(
            AdminOwnerMessage::Opened {
                generation,
                challenge,
                peer,
                output,
            },
            token,
        )
        .await
    }

    async fn line(
        &self,
        generation: ConnectionGeneration,
        line: Vec<u8>,
        token: &CancellationToken,
    ) -> Result<(), CloseReason> {
        self.send(AdminOwnerMessage::Line { generation, line }, token)
            .await
    }

    async fn closed(&self, generation: ConnectionGeneration, reason: CloseReason) {
        let message = AdminOwnerMessage::Closed { generation, reason };
        let _ = tokio::time::timeout(ADMIN_NOTICE_BUDGET, self.sender.send(message)).await;
    }

    async fn send(
        &self,
        message: AdminOwnerMessage,
        token: &CancellationToken,
    ) -> Result<(), CloseReason> {
        tokio::select! {
            () = token.cancelled() => Err(CloseReason::Shutdown),
            sent = tokio::time::timeout(ADMIN_NOTICE_BUDGET, self.sender.send(message)) => {
                match sent {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(CloseReason::Shutdown),
                    Err(_) => Err(CloseReason::ReadStall),
                }
            }
        }
    }
}

/// Cloneable shutdown authority for the isolated administrative owner.
#[derive(Clone)]
pub(crate) struct AdminLifecycleControl {
    sender: mpsc::Sender<AdminLifecycleRequest>,
}

impl AdminLifecycleControl {
    pub(crate) async fn quiesce(&self) -> Result<(), AdminLifecycleFailure> {
        match self.request(AdminLifecyclePhase::Quiesce).await? {
            AdminLifecycleOutcome::Complete => Ok(()),
            AdminLifecycleOutcome::Draining(_) => Err(AdminLifecycleFailure::Unavailable),
        }
    }

    pub(crate) async fn drain(&self) -> Result<Vec<FlushAcknowledgement>, AdminLifecycleFailure> {
        match self.request(AdminLifecyclePhase::Drain).await? {
            AdminLifecycleOutcome::Draining(acknowledgements) => Ok(acknowledgements),
            AdminLifecycleOutcome::Complete => Err(AdminLifecycleFailure::Unavailable),
        }
    }

    pub(crate) async fn flush(&self) -> Result<(), AdminLifecycleFailure> {
        match self.request(AdminLifecyclePhase::Flush).await? {
            AdminLifecycleOutcome::Complete => Ok(()),
            AdminLifecycleOutcome::Draining(_) => Err(AdminLifecycleFailure::Unavailable),
        }
    }

    pub(crate) async fn stop(&self) -> Result<(), AdminLifecycleFailure> {
        match self.request(AdminLifecyclePhase::Stop).await? {
            AdminLifecycleOutcome::Complete => Ok(()),
            AdminLifecycleOutcome::Draining(_) => Err(AdminLifecycleFailure::Unavailable),
        }
    }

    async fn request(
        &self,
        phase: AdminLifecyclePhase,
    ) -> Result<AdminLifecycleOutcome, AdminLifecycleFailure> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(AdminLifecycleRequest { phase, reply })
            .await
            .map_err(|_| AdminLifecycleFailure::Unavailable)?;
        response
            .await
            .unwrap_or(Err(AdminLifecycleFailure::Unavailable))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminLifecycleFailure {
    Unavailable,
    Writer,
    Audit,
    Busy,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum AdminLifecyclePhase {
    Quiesce,
    Drain,
    Flush,
    Stop,
}

enum AdminLifecycleOutcome {
    Complete,
    Draining(Vec<FlushAcknowledgement>),
}

type AdminLifecycleResult = Result<AdminLifecycleOutcome, AdminLifecycleFailure>;

struct AdminLifecycleRequest {
    phase: AdminLifecyclePhase,
    reply: oneshot::Sender<AdminLifecycleResult>,
}

struct AdminLifecycleBatch {
    requests: [Option<AdminLifecycleRequest>; ADMIN_LIFECYCLE_BATCH_CAPACITY],
    len: usize,
}

impl AdminLifecycleBatch {
    fn new(first: AdminLifecycleRequest) -> Self {
        let mut requests = std::array::from_fn(|_| None);
        requests[0] = Some(first);
        Self { requests, len: 1 }
    }

    fn collect_queued(&mut self, receiver: &mut mpsc::Receiver<AdminLifecycleRequest>) {
        while self.len < self.requests.len() {
            let Ok(request) = receiver.try_recv() else {
                break;
            };
            let Some(slot) = self.requests.get_mut(self.len) else {
                break;
            };
            *slot = Some(request);
            self.len += 1;
        }
    }

    fn contains_stop(&self) -> bool {
        let Some(requests) = self.requests.get(..self.len) else {
            return false;
        };
        requests.iter().any(|request| {
            request
                .as_ref()
                .is_some_and(|request| request.phase == AdminLifecyclePhase::Stop)
        })
    }

    fn into_requests(self) -> impl Iterator<Item = AdminLifecycleRequest> {
        self.requests.into_iter().take(self.len).flatten()
    }
}

pub(crate) struct AdminLifecycleInbox {
    receiver: mpsc::Receiver<AdminLifecycleRequest>,
}

#[must_use]
pub(crate) fn admin_lifecycle_channel() -> (AdminLifecycleControl, AdminLifecycleInbox) {
    let (sender, receiver) = mpsc::channel(ADMIN_LIFECYCLE_CAPACITY);
    (
        AdminLifecycleControl { sender },
        AdminLifecycleInbox { receiver },
    )
}

enum AdminOwnerMessage {
    Opened {
        generation: ConnectionGeneration,
        challenge: AdminChallenge,
        peer: PeerIdentity,
        output: AdminOutput,
    },
    Line {
        generation: ConnectionGeneration,
        line: Vec<u8>,
    },
    Closed {
        generation: ConnectionGeneration,
        reason: CloseReason,
    },
}

enum AdminOwnerEvent {
    Lifecycle(AdminLifecycleRequest),
    Transport(AdminOwnerMessage),
}

struct AdminOutput {
    sender: mpsc::Sender<AdminWrite>,
    flush_acknowledgement: FlushAcknowledgement,
}

impl AdminOutput {
    fn new(sender: mpsc::Sender<AdminWrite>) -> Self {
        Self {
            sender,
            flush_acknowledgement: FlushAcknowledgement::pending(),
        }
    }

    fn try_line(&self, line: String) -> Result<(), CloseReason> {
        self.try_batch(vec![line], None)
    }

    fn try_close(&self, reason: CloseReason) -> Result<(), CloseReason> {
        self.try_batch(Vec::new(), Some(reason))
    }

    fn try_shutdown(&self) -> Result<FlushAcknowledgement, CloseReason> {
        self.try_batch(
            vec![ADMIN_SHUTDOWN_LINE.to_owned()],
            Some(CloseReason::Shutdown),
        )?;
        Ok(self.flush_acknowledgement.clone())
    }

    fn try_batch(&self, lines: Vec<String>, close: Option<CloseReason>) -> Result<(), CloseReason> {
        let batch = AdminWrite::ordinary(lines, close)?;
        self.sender.try_send(batch).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => CloseReason::SlowConsumer,
            mpsc::error::TrySendError::Closed(_) => CloseReason::TransportLoss,
        })
    }

    fn try_export(&self, batch: AdminWrite) -> Result<(), CloseReason> {
        self.sender.try_send(batch).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => CloseReason::SlowConsumer,
            mpsc::error::TrySendError::Closed(_) => CloseReason::TransportLoss,
        })
    }
}

struct AdminWrite {
    lines: Vec<Vec<u8>>,
    close: Option<CloseReason>,
    _memory: Option<MemoryPermitBatch>,
}

impl AdminWrite {
    fn ordinary(lines: Vec<String>, close: Option<CloseReason>) -> Result<Self, CloseReason> {
        if lines.len() > MAX_ORDINARY_BATCH_LINES {
            return Err(CloseReason::Overload);
        }
        let mut encoded = Vec::with_capacity(lines.len());
        for line in lines {
            let bytes = line.into_bytes();
            if bytes.is_empty()
                || bytes.len() > MAX_ADMIN_OUTPUT_LINE_BYTES
                || bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
            {
                return Err(CloseReason::ProtocolError);
            }
            encoded.push(bytes);
        }
        Ok(Self {
            lines: encoded,
            close,
            _memory: None,
        })
    }

    fn export(lines: Vec<String>, memory: MemoryPermitBatch) -> Result<Self, CloseReason> {
        Self::export_bounded(
            lines,
            memory,
            MAX_AUDIT_EXPORT_RECORDS,
            MAX_AUDIT_EXPORT_BYTES,
        )
    }

    fn export_bounded(
        lines: Vec<String>,
        memory: MemoryPermitBatch,
        max_records: usize,
        max_wire_bytes: u64,
    ) -> Result<Self, CloseReason> {
        let max_lines = max_records.checked_add(2).ok_or(CloseReason::Overload)?;
        if lines.len() > max_lines {
            return Err(CloseReason::Overload);
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(lines.len())
            .map_err(|_| CloseReason::Overload)?;
        let mut wire_bytes = 0_u64;
        for line in lines {
            let bytes = line.into_bytes();
            if bytes.is_empty()
                || bytes.len() > MAX_ADMIN_OUTPUT_LINE_BYTES
                || bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
            {
                return Err(CloseReason::ProtocolError);
            }
            let line_wire_bytes = u64::try_from(bytes.len())
                .ok()
                .and_then(|length| length.checked_add(2))
                .ok_or(CloseReason::Overload)?;
            wire_bytes = wire_bytes
                .checked_add(line_wire_bytes)
                .ok_or(CloseReason::Overload)?;
            if wire_bytes > max_wire_bytes {
                return Err(CloseReason::Overload);
            }
            encoded.push(bytes);
        }
        Ok(Self {
            lines: encoded,
            close: None,
            _memory: Some(memory),
        })
    }
}

/// Creates the one private transport port and receiver owned by
/// `AdminOwner`.
pub(crate) fn admin_transport_channel(
    binding: AdminSessionBinding,
) -> (AdminTransportPort, AdminOwnerInbox) {
    let (sender, receiver) = mpsc::channel(ADMIN_OWNER_CAPACITY);
    (
        AdminTransportPort { binding, sender },
        AdminOwnerInbox { receiver },
    )
}

pub(crate) struct AdminOwnerInbox {
    receiver: mpsc::Receiver<AdminOwnerMessage>,
}

/// Private owner of every live administrative session and its response order.
///
/// Command execution and durable audit composition are added on top of this
/// owner boundary; until then, authenticated commands fail closed instead of
/// crossing into the public protocol owner.
pub(crate) struct AdminOwner {
    binding: AdminSessionBinding,
    registry: OperatorRegistry,
    admission: AdminAdmissionSnapshot,
    audit: AuditAuthority,
    core: AdminCorePort,
    statistics_storage: Option<StoragePort>,
    federation: Option<FederationControl>,
    health: AdminOwnerHealth,
    config: Option<RuntimeConfigHandle>,
    config_changes: Option<watch::Receiver<crate::runtime_config::ConfigRevision>>,
    reload: Option<ReloadPreparationPort>,
    backup: Option<AdminBackupRuntime>,
    process: Option<AdminProcessPort>,
    fatal: Option<mpsc::Sender<()>>,
    observer: Option<Arc<RuntimeObserver>>,
    budget: Arc<MemoryBudget>,
    entropy: Box<dyn EntropySource + Send>,
    monotonic: Box<dyn MonotonicClock + Send>,
    wall: Box<dyn WallClock + Send>,
    sessions: BTreeMap<ConnectionGeneration, OwnedAdminSession>,
    shutdown_acknowledgements: BTreeMap<ConnectionGeneration, FlushAcknowledgement>,
    command_observation: Cell<AdminCommandObservation>,
    quiescing: bool,
    lifecycle_completed: Option<AdminLifecyclePhase>,
    flush_outcome: Option<Result<(), AdminLifecycleFailure>>,
}

#[derive(Clone, Copy)]
enum AdminCommandObservation {
    Inactive,
    Pending,
    Complete(ResultClass),
}

pub(crate) struct AdminOwnerClocks {
    pub(crate) monotonic: Box<dyn MonotonicClock + Send>,
    pub(crate) wall: Box<dyn WallClock + Send>,
}

pub(crate) struct AdminOwnerRuntime {
    pub(crate) health: AdminOwnerHealth,
    pub(crate) config: Option<RuntimeConfigHandle>,
    pub(crate) reload: Option<ReloadPreparationPort>,
    pub(crate) backup: Option<AdminBackupRuntime>,
    pub(crate) process: Option<AdminProcessPort>,
    pub(crate) fatal: Option<mpsc::Sender<()>>,
    pub(crate) observer: Option<Arc<RuntimeObserver>>,
    pub(crate) budget: Arc<MemoryBudget>,
    pub(crate) entropy: Box<dyn EntropySource + Send>,
    pub(crate) clocks: AdminOwnerClocks,
}

#[derive(Clone)]
pub(crate) struct AdminOwnerHealth {
    pub(crate) readiness: Arc<ReadinessGate>,
    pub(crate) liveness: Arc<Liveness>,
}

impl AdminOwnerHealth {
    fn capture(&self, now: agenc_ircd_types::MonotonicTick) -> HealthSnapshot {
        HealthSnapshot::capture(&self.readiness, &self.liveness, now)
    }
}

/// Exact enabled-operator transport identities accepted before a challenge.
#[derive(Clone)]
pub(crate) struct AdminAdmissionSnapshot {
    uids: Vec<u32>,
    gids: Vec<u32>,
    pins: Vec<[u8; 32]>,
}

impl AdminAdmissionSnapshot {
    pub(crate) fn new(mut uids: Vec<u32>, mut gids: Vec<u32>, mut pins: Vec<[u8; 32]>) -> Self {
        uids.sort_unstable();
        uids.dedup();
        gids.sort_unstable();
        gids.dedup();
        pins.sort_unstable();
        pins.dedup();
        Self { uids, gids, pins }
    }

    fn admits(&self, peer: PeerIdentity) -> bool {
        match peer {
            PeerIdentity::Local { uid, gid } => {
                self.uids.binary_search(&uid).is_ok() || self.gids.binary_search(&gid).is_ok()
            }
            PeerIdentity::Pin(pin) => self.pins.binary_search(&pin).is_ok(),
        }
    }
}

struct OwnedAdminSession {
    session: AdminSession,
    output: AdminOutput,
    purpose: ListenerPurpose,
}

impl AdminOwner {
    pub(crate) fn new(
        binding: AdminSessionBinding,
        registry: OperatorRegistry,
        admission: AdminAdmissionSnapshot,
        audit: AuditAuthority,
        core: AdminCorePort,
        runtime: AdminOwnerRuntime,
    ) -> Self {
        let config_changes = runtime.config.as_ref().map(RuntimeConfigHandle::subscribe);
        Self {
            binding,
            registry,
            admission,
            audit,
            core,
            statistics_storage: None,
            federation: None,
            health: runtime.health,
            config: runtime.config,
            config_changes,
            reload: runtime.reload,
            backup: runtime.backup,
            process: runtime.process,
            fatal: runtime.fatal,
            observer: runtime.observer,
            budget: runtime.budget,
            entropy: runtime.entropy,
            monotonic: runtime.clocks.monotonic,
            wall: runtime.clocks.wall,
            sessions: BTreeMap::new(),
            shutdown_acknowledgements: BTreeMap::new(),
            command_observation: Cell::new(AdminCommandObservation::Inactive),
            quiescing: false,
            lifecycle_completed: None,
            flush_outcome: None,
        }
    }

    /// Installs the link control surface behind `CONNECT` and `SQUIT`.
    pub(crate) fn install_federation_control(
        &mut self,
        control: FederationControl,
    ) -> Result<(), crate::RuntimeError> {
        if self.federation.is_some() {
            return Err(crate::RuntimeError::InvalidValue);
        }
        self.federation = Some(control);
        Ok(())
    }

    pub(crate) fn install_statistics_storage(
        &mut self,
        storage: StoragePort,
    ) -> Result<(), crate::RuntimeError> {
        if self.statistics_storage.is_some() {
            return Err(crate::RuntimeError::InvalidValue);
        }
        self.statistics_storage = Some(storage);
        Ok(())
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=single bounded admin select owns session authority reload notifications transport input and cancellation ordering
    pub(crate) async fn run(
        mut self,
        mut inbox: AdminOwnerInbox,
        mut lifecycle: AdminLifecycleInbox,
        token: CancellationToken,
    ) {
        if self.reconcile_pending_startup_action(&token).await.is_err() {
            self.signal_fatal();
            return;
        }
        let first_retention = tokio::time::Instant::now() + AUDIT_RETENTION_SWEEP;
        let mut retention = tokio::time::interval_at(first_retention, AUDIT_RETENTION_SWEEP);
        retention.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut transport_open = true;
        loop {
            let event = tokio::select! {
                biased;
                () = token.cancelled() => break,
                request = lifecycle.receiver.recv() => match request {
                    Some(request) => AdminOwnerEvent::Lifecycle(request),
                    None => {
                        self.signal_fatal();
                        break;
                    }
                },
                _ = retention.tick(), if !self.quiescing => {
                    if self.retention_sweep(&token).await == Err(AdminLifecycleFailure::Audit) {
                        self.signal_fatal();
                    }
                    continue;
                }
                changed = wait_for_config_change(&mut self.config_changes) => {
                    if changed {
                        self.reconcile_authority();
                        continue;
                    }
                    break;
                }
                message = inbox.receiver.recv(), if transport_open => match message {
                    Some(message) => AdminOwnerEvent::Transport(message),
                    None => {
                        transport_open = false;
                        continue;
                    }
                },
            };
            match event {
                AdminOwnerEvent::Lifecycle(request) => {
                    if self
                        .handle_lifecycle_batch(request, &mut lifecycle.receiver, &token)
                        .await
                    {
                        break;
                    }
                }
                AdminOwnerEvent::Transport(message) => self.handle(message, &token).await,
            }
        }
        for (_, owned) in self.sessions {
            let _ = owned.output.try_close(CloseReason::Shutdown);
        }
    }

    async fn reconcile_pending_startup_action(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(), AdminLifecycleFailure> {
        let Some(action) = self.audit.take_pending_startup_action() else {
            return self
                .audit
                .is_reconciled()
                .then_some(())
                .ok_or(AdminLifecycleFailure::Audit);
        };
        let phase = match action.kind() {
            PendingStartupActionKind::Kill(user) => match self.core.kill(user, token).await {
                Ok(()) | Err(AdminCoreFailure::InvalidTarget) => AdminAuditPhase::OutcomeSuccess,
                Err(
                    AdminCoreFailure::Busy
                    | AdminCoreFailure::Quiescing
                    | AdminCoreFailure::StaleRevision
                    | AdminCoreFailure::StorageUnavailable,
                ) => AdminAuditPhase::OutcomeFailure,
            },
            PendingStartupActionKind::Rehash => AdminAuditPhase::OutcomeFailure,
            PendingStartupActionKind::BackupCreate => {
                let backup = self.backup.as_ref().ok_or(AdminLifecycleFailure::Audit)?;
                let job = backup.reconciliation_job(action.audit_sequence(), action.created_at());
                match tokio::task::spawn_blocking(move || job.run())
                    .await
                    .map_err(|_| AdminLifecycleFailure::Audit)?
                    .map_err(|_| AdminLifecycleFailure::Audit)?
                {
                    true => AdminAuditPhase::OutcomeSuccess,
                    false => AdminAuditPhase::OutcomeFailure,
                }
            }
        };
        let created_at = self
            .wall
            .utc_now()
            .map_err(|_| AdminLifecycleFailure::Audit)?
            .get();
        let outcome = self
            .audit
            .prepare_startup_outcome(&action, phase, created_at)
            .map_err(|_| AdminLifecycleFailure::Audit)?;
        self.core
            .commit_audit(outcome.clone(), token)
            .await
            .map_err(|_| AdminLifecycleFailure::Audit)?;
        self.audit
            .resolve_committed_startup_action(action, &outcome)
            .map_err(|_| AdminLifecycleFailure::Audit)
    }

    async fn retention_sweep(
        &mut self,
        token: &CancellationToken,
    ) -> Result<(), AdminLifecycleFailure> {
        let Some(snapshot) = self.config.as_ref().map(RuntimeConfigHandle::load) else {
            return Ok(());
        };
        let Some(retention_seconds) = snapshot
            .config()
            .moderation
            .audit_retention_days
            .checked_mul(SECONDS_PER_DAY)
        else {
            return Err(AdminLifecycleFailure::Audit);
        };
        let Ok(now) = self.wall.utc_now() else {
            return Err(AdminLifecycleFailure::Audit);
        };
        let Ok(job) = self.audit.prepare_retention(now.get(), retention_seconds) else {
            return Err(AdminLifecycleFailure::Audit);
        };
        let scan = tokio::task::spawn_blocking(move || job.run()).await;
        if token.is_cancelled() {
            return Err(AdminLifecycleFailure::Unavailable);
        }
        let tbs = match scan {
            Ok(Ok(Some(tbs))) => tbs,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(_)) | Err(_) => return Err(AdminLifecycleFailure::Audit),
        };
        let checkpoint = self
            .audit
            .sign_retention(tbs)
            .map_err(|_| AdminLifecycleFailure::Audit)?;
        match self.core.commit_retention(checkpoint, token).await {
            Ok(()) => self
                .audit
                .commit_retention(&checkpoint)
                .map_err(|_| AdminLifecycleFailure::Audit),
            Err(AdminCoreFailure::Busy | AdminCoreFailure::Quiescing) => {
                Err(AdminLifecycleFailure::Busy)
            }
            Err(
                AdminCoreFailure::InvalidTarget
                | AdminCoreFailure::StaleRevision
                | AdminCoreFailure::StorageUnavailable,
            ) => Err(AdminLifecycleFailure::Audit),
        }
    }

    async fn handle_lifecycle(
        &mut self,
        request: AdminLifecycleRequest,
        token: &CancellationToken,
    ) -> bool {
        let stop = request.phase == AdminLifecyclePhase::Stop;
        let outcome = self.lifecycle_outcome(request.phase, token).await;
        let _sent = request.reply.send(outcome);
        stop
    }

    async fn handle_lifecycle_batch(
        &mut self,
        first: AdminLifecycleRequest,
        receiver: &mut mpsc::Receiver<AdminLifecycleRequest>,
        token: &CancellationToken,
    ) -> bool {
        let mut batch = AdminLifecycleBatch::new(first);
        batch.collect_queued(receiver);
        if batch.contains_stop() {
            self.quiescing = true;
            self.lifecycle_completed = Some(AdminLifecyclePhase::Stop);
            for request in batch.into_requests() {
                let outcome = if request.phase == AdminLifecyclePhase::Stop {
                    Ok(AdminLifecycleOutcome::Complete)
                } else {
                    Err(AdminLifecycleFailure::Unavailable)
                };
                let _sent = request.reply.send(outcome);
            }
            return true;
        }

        for request in batch.into_requests() {
            if self.handle_lifecycle(request, token).await {
                return true;
            }
        }
        false
    }

    async fn lifecycle_outcome(
        &mut self,
        phase: AdminLifecyclePhase,
        token: &CancellationToken,
    ) -> AdminLifecycleResult {
        self.quiescing = true;
        if phase == AdminLifecyclePhase::Stop {
            self.lifecycle_completed = Some(AdminLifecyclePhase::Stop);
            return Ok(AdminLifecycleOutcome::Complete);
        }
        if self
            .lifecycle_completed
            .is_some_and(|completed| completed >= phase)
        {
            return match phase {
                AdminLifecyclePhase::Drain => {
                    self.begin_shutdown().map(AdminLifecycleOutcome::Draining)
                }
                AdminLifecyclePhase::Quiesce | AdminLifecyclePhase::Flush => {
                    Ok(AdminLifecycleOutcome::Complete)
                }
                AdminLifecyclePhase::Stop => Ok(AdminLifecycleOutcome::Complete),
            };
        }

        if !self
            .lifecycle_completed
            .is_some_and(|completed| completed >= AdminLifecyclePhase::Quiesce)
        {
            self.lifecycle_completed = Some(AdminLifecyclePhase::Quiesce);
        }
        if phase == AdminLifecyclePhase::Quiesce {
            return Ok(AdminLifecycleOutcome::Complete);
        }

        if !self
            .lifecycle_completed
            .is_some_and(|completed| completed >= AdminLifecyclePhase::Drain)
        {
            let acknowledgements = self.begin_shutdown()?;
            self.lifecycle_completed = Some(AdminLifecyclePhase::Drain);
            if phase == AdminLifecyclePhase::Drain {
                return Ok(AdminLifecycleOutcome::Draining(acknowledgements));
            }
        } else if phase == AdminLifecyclePhase::Drain {
            return self.begin_shutdown().map(AdminLifecycleOutcome::Draining);
        }

        let flush = match self.flush_outcome {
            Some(outcome) => outcome,
            None => {
                let outcome = self.retention_sweep(token).await;
                self.flush_outcome = Some(outcome);
                outcome
            }
        };
        flush?;
        self.lifecycle_completed = Some(AdminLifecyclePhase::Flush);
        Ok(AdminLifecycleOutcome::Complete)
    }

    fn begin_shutdown(&mut self) -> Result<Vec<FlushAcknowledgement>, AdminLifecycleFailure> {
        let mut failed = false;
        for (generation, owned) in &self.sessions {
            if self.shutdown_acknowledgements.contains_key(generation) {
                continue;
            }
            match owned.output.try_shutdown() {
                Ok(acknowledgement) => {
                    self.shutdown_acknowledgements
                        .insert(*generation, acknowledgement);
                }
                Err(_) => failed = true,
            }
        }
        if failed {
            return Err(AdminLifecycleFailure::Writer);
        }
        let mut acknowledgements = Vec::new();
        acknowledgements
            .try_reserve_exact(self.shutdown_acknowledgements.len())
            .map_err(|_| AdminLifecycleFailure::Writer)?;
        acknowledgements.extend(self.shutdown_acknowledgements.values().cloned());
        Ok(acknowledgements)
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-31 reason=bounded quiescing dispatch keeps each transport message closed before ordinary authority handling
    async fn handle(&mut self, message: AdminOwnerMessage, token: &CancellationToken) {
        if self.quiescing {
            match message {
                AdminOwnerMessage::Opened { output, .. } => {
                    let _ = output.try_close(CloseReason::Shutdown);
                }
                AdminOwnerMessage::Line { generation, .. } => {
                    if !self.shutdown_acknowledgements.contains_key(&generation) {
                        self.close(generation, CloseReason::Shutdown);
                    }
                }
                AdminOwnerMessage::Closed { generation, .. } => {
                    self.sessions.remove(&generation);
                }
            }
            return;
        }
        match message {
            AdminOwnerMessage::Opened {
                generation,
                challenge,
                peer,
                output,
            } => self.open(generation, challenge, peer, output),
            AdminOwnerMessage::Line { generation, line } => {
                self.line(generation, &line, token).await;
            }
            AdminOwnerMessage::Closed { generation, reason } => {
                let _ = reason;
                self.sessions.remove(&generation);
            }
        }
    }

    fn open(
        &mut self,
        generation: ConnectionGeneration,
        challenge: AdminChallenge,
        peer: PeerIdentity,
        output: AdminOutput,
    ) {
        if self.sessions.contains_key(&generation)
            || !self.admission.admits(peer)
            || !self.audit.is_reconciled()
        {
            let _ = output.try_close(CloseReason::ProtocolError);
            return;
        }
        let note = challenge.render_note();
        let purpose = match challenge.kind() {
            TransportKind::Local => ListenerPurpose::AdminLocal,
            TransportKind::Tls => ListenerPurpose::AdminTls,
        };
        let session = AdminSession::new(self.binding, challenge, peer);
        if output.try_line(note).is_err() {
            let _ = output.try_close(CloseReason::SlowConsumer);
            return;
        }
        self.sessions.insert(
            generation,
            OwnedAdminSession {
                session,
                output,
                purpose,
            },
        );
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-31 reason=closed admin line dispatch records only transport and result classes while preserving proof command and close ordering
    async fn line(
        &mut self,
        generation: ConnectionGeneration,
        line: &[u8],
        token: &CancellationToken,
    ) {
        let now = self.monotonic.now();
        let (outcome, purpose, was_authenticated) = {
            let Some(owned) = self.sessions.get_mut(&generation) else {
                return;
            };
            let was_authenticated = owned.session.operator().is_some();
            (
                owned.session.accept_line(line, now, &self.registry),
                owned.purpose,
                was_authenticated,
            )
        };
        match outcome {
            Ok(agenc_ircd_admin::AdminEvent::PreAuthPing(ping)) => {
                self.output_line(generation, format!("PONG :{}", ping.as_str()));
            }
            Ok(agenc_ircd_admin::AdminEvent::PreAuthPong(_)) => {}
            Ok(agenc_ircd_admin::AdminEvent::Quit) => {
                self.close(generation, CloseReason::ClientQuit);
            }
            Ok(agenc_ircd_admin::AdminEvent::Authenticated { .. }) => {
                if let Some(observer) = &self.observer {
                    observer.admin_authentication(purpose, true);
                }
            }
            Ok(agenc_ircd_admin::AdminEvent::Command(event)) => {
                self.command_observation
                    .set(AdminCommandObservation::Pending);
                let observer = self.observer.as_ref().map(Arc::clone);
                self.command(generation, *event, token).await;
                let result = match self
                    .command_observation
                    .replace(AdminCommandObservation::Inactive)
                {
                    AdminCommandObservation::Complete(result) => result,
                    AdminCommandObservation::Pending if token.is_cancelled() => ResultClass::Closed,
                    AdminCommandObservation::Pending | AdminCommandObservation::Inactive => {
                        ResultClass::Error
                    }
                };
                if let Some(observer) = observer {
                    observer.admin_action(result);
                }
            }
            Ok(agenc_ircd_admin::AdminEvent::PermissionDenied { verb, .. }) => {
                if let Some(observer) = &self.observer {
                    observer.admin_action(ResultClass::Rejected);
                }
                self.output_line(
                    generation,
                    format!("FAIL {verb} PRIVILEGES :Insufficient privileges"),
                );
            }
            Err(_reason) => {
                if let Some(observer) = &self.observer {
                    if was_authenticated {
                        observer.admin_action(ResultClass::Rejected);
                    } else {
                        observer.admin_authentication(purpose, false);
                    }
                }
                self.close(generation, CloseReason::ProtocolError);
            }
        }
    }

    fn complete_immediate_command(
        &mut self,
        generation: ConnectionGeneration,
        command: &AdminCommand,
    ) -> bool {
        match command {
            AdminCommand::Ping(ping) => {
                self.output_line(generation, format!("PONG :{}", ping.as_str()));
            }
            AdminCommand::Pong(_) => {
                self.record_command_result(ResultClass::Ok);
            }
            AdminCommand::Connect { .. }
            | AdminCommand::Squit { .. }
            | AdminCommand::PeerQuarantine { .. }
                if self.federation.is_none() =>
            {
                self.output_line(
                    generation,
                    format!("FAIL {} UNAVAILABLE :Command unavailable", command.verb()),
                );
            }
            _ => return false,
        }
        true
    }

    async fn command(
        &mut self,
        generation: ConnectionGeneration,
        event: AdminCommandEvent,
        token: &CancellationToken,
    ) {
        if self.complete_immediate_command(generation, &event.command) {
            return;
        }
        if event.confirmation == ConfirmationState::Required {
            self.issue_confirmation(generation, &event, token).await;
            return;
        }
        match &event.command {
            AdminCommand::Rehash(_) => self.rehash(generation, &event, token).await,
            AdminCommand::Kill { user, .. } => {
                self.kill(generation, &event, *user, token).await;
            }
            AdminCommand::Connect { .. }
            | AdminCommand::Squit { .. }
            | AdminCommand::PeerQuarantine { .. } => {
                self.federation_action(generation, &event, token).await;
            }
            AdminCommand::AccountSuspend { account, .. }
            | AdminCommand::AccountRestore { account, .. } => {
                self.mutate_account(generation, &event, *account, token)
                    .await;
            }
            AdminCommand::ChannelQuarantine { channel, .. }
            | AdminCommand::ChannelHistoryPurge { channel, .. } => {
                self.mutate_channel(generation, &event, *channel, token)
                    .await;
            }
            AdminCommand::Restart(_) => {
                self.process_action(generation, &event, AdminProcessAction::Restart, token)
                    .await;
            }
            AdminCommand::Die(_) => {
                self.process_action(generation, &event, AdminProcessAction::Die, token)
                    .await;
            }
            AdminCommand::AuditExport(range) | AdminCommand::AuditExportMaintenance(range) => {
                self.audit_export(generation, &event, *range, token).await;
            }
            AdminCommand::BackupCreate(_) => {
                self.backup(generation, &event, token).await;
            }
            _ => {
                let Some(lines) = self
                    .prepare_command_lines(generation, &event.command, token)
                    .await
                else {
                    return;
                };
                let Some(audit) = self.prepare_observed_event(generation, &event) else {
                    return;
                };
                self.commit_observed(generation, &event.command, lines, audit, token)
                    .await;
            }
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=external backup action keeps intent action outcome and indeterminate branches in one auditable sequence
    async fn backup(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        token: &CancellationToken,
    ) {
        if self.backup.is_none() {
            self.output_line(
                generation,
                "FAIL BACKUP UNAVAILABLE :Command unavailable".to_owned(),
            );
            return;
        }
        let Some(intent) = self.prepare_action_event(generation, event, AdminAuditPhase::Intent)
        else {
            return;
        };
        if let Err(failure) = self
            .commit_action_audit(generation, intent.clone(), token)
            .await
        {
            self.output_audit_failure(generation, "BACKUP", failure);
            return;
        }

        let mut backup_id = [0_u8; 16];
        let completion = self
            .entropy
            .fill_exact(&mut backup_id)
            .map_err(|_| AdminCoreFailure::StorageUnavailable)
            .and_then(|()| {
                self.backup
                    .as_ref()
                    .ok_or(AdminCoreFailure::StorageUnavailable)?
                    .start(
                        intent.tbs().audit_sequence,
                        intent.tbs().created_at,
                        backup_id,
                    )
                    .map_err(map_backup_failure)
            });
        let result = match completion {
            Ok(completion) => {
                let completed = wait_storage_completion(completion).await;
                if token.is_cancelled() {
                    return;
                }
                completed.map(|_receipt| ()).map_err(map_backup_failure)
            }
            Err(failure) => Err(failure),
        };
        let phase = if result.is_ok() {
            AdminAuditPhase::OutcomeSuccess
        } else {
            AdminAuditPhase::OutcomeFailure
        };
        if !self
            .commit_rehash_outcome(generation, event, phase, token)
            .await
        {
            self.fail_closed(generation);
            return;
        }
        match result {
            Ok(()) => self.output_line(generation, "NOTE BACKUP OK :Backup created".to_owned()),
            Err(failure) => self.output_admin_failure(generation, "BACKUP", failure),
        }
    }

    fn prepare_audit_export_job(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        range: agenc_ircd_admin::AuditRange,
    ) -> Option<audit::AuditExportJob> {
        let mut batch_id = [0_u8; 16];
        if self.entropy.fill_exact(&mut batch_id).is_err() {
            self.output_storage_unavailable(generation, "AUDIT");
            return None;
        }
        let profile = if matches!(event.command, AdminCommand::AuditExportMaintenance(_)) {
            agenc_ircd_admin::AuditExportProfile::MaintenanceV1
        } else {
            agenc_ircd_admin::AuditExportProfile::Legacy
        };
        match self.audit.prepare_export(range, batch_id) {
            Ok(job) => Some(job.with_profile(profile)),
            Err(error) => {
                self.output_export_failure(generation, error);
                None
            }
        }
    }

    async fn audit_export(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        range: agenc_ircd_admin::AuditRange,
        token: &CancellationToken,
    ) {
        let Ok(memory) = acquire_audit_export_memory(&self.budget) else {
            self.output_line(
                generation,
                "FAIL AUDIT BUSY :Administrative action busy".to_owned(),
            );
            return;
        };
        let Some(export) = self.prepare_audit_export_job(generation, event, range) else {
            return;
        };
        let frozen = match tokio::task::spawn_blocking(move || export.run()).await {
            Ok(Ok(frozen)) => frozen,
            Ok(Err(error)) => {
                self.output_export_job_failure(generation, error);
                return;
            }
            Err(_) => {
                self.fail_closed(generation);
                return;
            }
        };
        let Some(observed) = self.prepare_observed_event(generation, event) else {
            return;
        };
        let rendered_observed = observed.clone();
        let rendered =
            tokio::task::spawn_blocking(move || frozen.finish_with_observed(&rendered_observed))
                .await;
        let lines = match rendered {
            Ok(Ok(lines)) => lines,
            Ok(Err(error)) => {
                self.output_export_failure(generation, error);
                return;
            }
            Err(_) => {
                self.fail_closed(generation);
                return;
            }
        };
        let prepared = match AdminWrite::export(lines, memory) {
            Ok(prepared) => prepared,
            Err(CloseReason::Overload) => {
                self.output_line(
                    generation,
                    "FAIL AUDIT UNAVAILABLE :Audit export unavailable".to_owned(),
                );
                return;
            }
            Err(_) => {
                self.fail_closed(generation);
                return;
            }
        };
        if let Err(failure) = self.commit_action_audit(generation, observed, token).await {
            self.output_audit_failure(generation, "AUDIT", failure);
            return;
        }
        self.output_export(generation, prepared);
    }

    async fn issue_confirmation(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        token: &CancellationToken,
    ) {
        let Some(target) = confirmation_target(&event.command) else {
            self.close(generation, CloseReason::ProtocolError);
            return;
        };
        let revision = match self.core.target_revision(target, token).await {
            Ok(revision) => revision,
            Err(failure) => {
                self.output_admin_failure(generation, event.command.verb(), failure);
                return;
            }
        };
        let mut bytes = [0_u8; 16];
        if self.entropy.fill_exact(&mut bytes).is_err() {
            self.output_storage_unavailable(generation, event.command.verb());
            return;
        }
        let token_text = {
            let Some(owned) = self.sessions.get_mut(&generation) else {
                return;
            };
            match owned.session.issue_confirmation(
                ConfirmationToken::from_bytes(bytes),
                self.monotonic.now(),
                event.tbs.canonical_command(),
                revision,
            ) {
                Ok(token) => token.to_base64url(),
                Err(_) => return,
            }
        };
        self.output_line(
            generation,
            format!(
                "NOTE {} CONFIRM {token_text} :Repeat this exact command to confirm",
                event.command.verb()
            ),
        );
    }

    async fn kill(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        user_id: agenc_ircd_types::UserId,
        token: &CancellationToken,
    ) {
        let Some(intent) = self.prepare_action_event(generation, event, AdminAuditPhase::Intent)
        else {
            return;
        };
        if let Err(failure) = self.commit_action_audit(generation, intent, token).await {
            self.output_audit_failure(generation, "KILL", failure);
            return;
        }
        let result = self.core.kill(user_id, token).await;
        let phase = if result.is_ok() {
            AdminAuditPhase::OutcomeSuccess
        } else {
            AdminAuditPhase::OutcomeFailure
        };
        if !self
            .commit_rehash_outcome(generation, event, phase, token)
            .await
        {
            self.fail_closed(generation);
            return;
        }
        match result {
            Ok(()) => self.output_line(generation, "NOTE KILL OK :Session terminated".to_owned()),
            Err(failure) => self.output_admin_failure(generation, "KILL", failure),
        }
    }

    /// `CONNECT`, `SQUIT`, and `PEER QUARANTINE` (spec 22.3): an intent
    /// record, the link or durable action, then the outcome record.
    async fn federation_action(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        token: &CancellationToken,
    ) {
        let verb = event.command.verb();
        let Some(intent) = self.prepare_action_event(generation, event, AdminAuditPhase::Intent)
        else {
            return;
        };
        if let Err(failure) = self.commit_action_audit(generation, intent, token).await {
            self.output_audit_failure(generation, verb, failure);
            return;
        }
        let result = match &event.command {
            AdminCommand::Connect { server, .. } => {
                self.link_control(*server, true).map(|()| "Link requested")
            }
            AdminCommand::Squit { server, .. } => {
                self.link_control(*server, false).map(|()| "Link closed")
            }
            AdminCommand::PeerQuarantine { server, .. } => self
                .core
                .peer_quarantine(*server, token)
                .await
                .map(|()| "Peer quarantined"),
            _ => return,
        };
        let phase = if result.is_ok() {
            AdminAuditPhase::OutcomeSuccess
        } else {
            AdminAuditPhase::OutcomeFailure
        };
        if !self
            .commit_rehash_outcome(generation, event, phase, token)
            .await
        {
            self.fail_closed(generation);
            return;
        }
        match result {
            Ok(text) => self.output_line(generation, format!("NOTE {verb} OK :{text}")),
            Err(failure) => self.output_admin_failure(generation, verb, failure),
        }
    }

    /// Applies one link command through the installed control surface.
    fn link_control(&self, server: ServerId, connect: bool) -> AdminCoreResult {
        let control = self
            .federation
            .as_ref()
            .ok_or(AdminCoreFailure::StorageUnavailable)?;
        let outcome = if connect {
            control.connect(server)
        } else {
            control.squit(server)
        };
        outcome.map_err(|_| AdminCoreFailure::InvalidTarget)
    }

    async fn mutate_account(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        account_id: agenc_ircd_types::AccountId,
        token: &CancellationToken,
    ) {
        let Some(revision) = self
            .mutation_revision(generation, event, AdminTarget::Account(account_id), token)
            .await
        else {
            return;
        };
        let Some(audit) =
            self.prepare_action_event(generation, event, AdminAuditPhase::CommittedMutation)
        else {
            return;
        };
        let mutation = match &event.command {
            AdminCommand::AccountSuspend { seconds, .. } => {
                let Some(expires_at) = audit.tbs().created_at.checked_add(seconds.get()) else {
                    self.output_storage_unavailable(generation, "ACCOUNT");
                    return;
                };
                AdminMutation::SuspendAccount {
                    account_id,
                    expires_at: agenc_ircd_types::UtcSecond::from_unix_seconds(expires_at),
                }
            }
            AdminCommand::AccountRestore { .. } => AdminMutation::RestoreAccount(account_id),
            _ => return,
        };
        match self
            .commit_mutation_with_stale_retry(
                event,
                &audit,
                mutation,
                AdminTarget::Account(account_id),
                revision,
                token,
            )
            .await
        {
            Ok(()) => {
                if self.audit.commit_event(&audit).is_err() {
                    self.fail_closed(generation);
                    return;
                }
                let text = if matches!(event.command, AdminCommand::AccountSuspend { .. }) {
                    "NOTE ACCOUNT OK :Account suspended"
                } else {
                    "NOTE ACCOUNT OK :Account restored"
                };
                self.output_line(generation, text.to_owned());
            }
            Err(failure) => self.output_admin_failure(generation, "ACCOUNT", failure),
        }
    }

    async fn mutate_channel(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        channel_id: agenc_ircd_types::ChannelInstanceId,
        token: &CancellationToken,
    ) {
        let (mutation, success) = match event.command {
            AdminCommand::ChannelQuarantine { .. } => (
                AdminMutation::QuarantineChannel(channel_id),
                "Channel quarantined",
            ),
            AdminCommand::ChannelHistoryPurge { .. } => (
                AdminMutation::PurgeChannelHistory(channel_id),
                "Channel history purged",
            ),
            _ => {
                self.fail_closed(generation);
                return;
            }
        };
        let Some(revision) = self
            .mutation_revision(generation, event, AdminTarget::Channel(channel_id), token)
            .await
        else {
            return;
        };
        let Some(audit) =
            self.prepare_action_event(generation, event, AdminAuditPhase::CommittedMutation)
        else {
            return;
        };
        match self
            .commit_mutation_with_stale_retry(
                event,
                &audit,
                mutation,
                AdminTarget::Channel(channel_id),
                revision,
                token,
            )
            .await
        {
            Ok(()) => {
                if self.audit.commit_event(&audit).is_err() {
                    self.fail_closed(generation);
                    return;
                }
                self.output_line(generation, format!("NOTE CHANNEL OK :{success}"));
            }
            Err(failure) => self.output_admin_failure(generation, "CHANNEL", failure),
        }
    }

    async fn commit_mutation_with_stale_retry(
        &mut self,
        event: &AdminCommandEvent,
        audit: &AdminAuditEvent,
        mutation: AdminMutation,
        target: AdminTarget,
        revision: agenc_ircd_types::Revision,
        token: &CancellationToken,
    ) -> Result<(), AdminCoreFailure> {
        let outcome = self
            .core
            .commit_mutation(audit.clone(), mutation, revision, token)
            .await;
        if !matches!(outcome, Err(AdminCoreFailure::StaleRevision))
            || event.confirmation != ConfirmationState::NotRequired
        {
            return outcome;
        }
        let revision = self.core.target_revision(target, token).await?;
        self.core
            .commit_mutation(audit.clone(), mutation, revision, token)
            .await
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=confirmation and fresh target revision branches remain adjacent to their closed reply mapping
    async fn mutation_revision(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        target: AdminTarget,
        token: &CancellationToken,
    ) -> Option<agenc_ircd_types::Revision> {
        match event.confirmation {
            ConfirmationState::Satisfied { target_revision } => Some(target_revision),
            ConfirmationState::NotRequired => {
                match self.core.target_revision(target, token).await {
                    Ok(revision) => Some(revision),
                    Err(failure) => {
                        self.output_admin_failure(generation, event.command.verb(), failure);
                        None
                    }
                }
            }
            ConfirmationState::Required => None,
        }
    }

    async fn process_action(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        action: AdminProcessAction,
        token: &CancellationToken,
    ) {
        let Some(process) = self.process.clone() else {
            self.output_line(
                generation,
                format!(
                    "FAIL {} UNAVAILABLE :Command unavailable",
                    event.command.verb()
                ),
            );
            return;
        };
        let ConfirmationState::Satisfied { target_revision } = event.confirmation else {
            self.close(generation, CloseReason::ProtocolError);
            return;
        };
        match self.core.target_revision(AdminTarget::Process, token).await {
            Ok(current) if current == target_revision => {}
            Ok(_) => {
                self.output_admin_failure(
                    generation,
                    event.command.verb(),
                    AdminCoreFailure::StaleRevision,
                );
                return;
            }
            Err(failure) => {
                self.output_admin_failure(generation, event.command.verb(), failure);
                return;
            }
        }
        let Some(intent) = self.prepare_action_event(generation, event, AdminAuditPhase::Intent)
        else {
            return;
        };
        if let Err(failure) = self.commit_action_audit(generation, intent, token).await {
            self.output_audit_failure(generation, event.command.verb(), failure);
            return;
        }
        // Process intents are terminal audit records. A failed handoff is
        // indeterminate and must stop the daemon without inventing an outcome.
        self.quiescing = true;
        if process.request(action).is_err() {
            self.fail_closed(generation);
        } else {
            self.record_command_result(ResultClass::Ok);
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=audited reload keeps intent provisional activation outcome and rollback in one explicit fail-closed barrier
    async fn rehash(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        token: &CancellationToken,
    ) {
        let Some(reload) = self.reload.clone() else {
            self.output_storage_unavailable(generation, "REHASH");
            return;
        };
        let prepared = match reload.prepare(token).await {
            Ok(prepared) => prepared,
            Err(failure) => {
                if let Some(observer) = &self.observer {
                    observer.reload(false);
                }
                self.output_reload_prepare_failure(generation, failure);
                return;
            }
        };
        let Some(intent) = self.prepare_action_event(generation, event, AdminAuditPhase::Intent)
        else {
            return;
        };
        if let Err(failure) = self.commit_action_audit(generation, intent, token).await {
            self.output_audit_failure(generation, "REHASH", failure);
            return;
        }
        let Some((success, failure)) = self.prepare_rehash_outcomes(generation, event) else {
            self.fail_closed(generation);
            return;
        };

        match reload
            .activate(prepared, success.clone(), failure.clone())
            .await
        {
            AuditedReloadStart::Provisional(activation) => {
                match reload.commit_outcome(activation, token).await {
                    ReloadAuditCommitOutcome::Committed(result) => {
                        let committed = match result {
                            AuditedReloadResult::Success => &success,
                            AuditedReloadResult::Failure(_) => &failure,
                        };
                        if self.audit.commit_event(committed).is_err() {
                            self.fail_closed(generation);
                            return;
                        }
                        if reload.finalize(activation).await.is_err() {
                            self.fail_closed(generation);
                            return;
                        }
                        match result {
                            AuditedReloadResult::Success => {
                                if let Some(observer) = &self.observer {
                                    observer.reload(true);
                                }
                                if activation.changes_live_state {
                                    self.reconcile_authority();
                                    self.output_line(
                                        generation,
                                        "NOTE REHASH OK :Configuration reloaded".to_owned(),
                                    );
                                } else {
                                    self.output_line(
                                        generation,
                                        "NOTE REHASH OK :Configuration unchanged".to_owned(),
                                    );
                                }
                            }
                            AuditedReloadResult::Failure(rejection) => {
                                if let Some(observer) = &self.observer {
                                    observer.reload(false);
                                }
                                self.output_reload_rejection(generation, rejection);
                            }
                        }
                    }
                    ReloadAuditCommitOutcome::NotCommitted(_)
                    | ReloadAuditCommitOutcome::Indeterminate => self.fail_closed(generation),
                }
            }
            AuditedReloadStart::Refused(rejection) => {
                if self.audit.commit_event(&failure).is_err() {
                    self.fail_closed(generation);
                    return;
                }
                if let Some(observer) = &self.observer {
                    observer.reload(false);
                }
                self.output_reload_rejection(generation, rejection);
            }
            AuditedReloadStart::Indeterminate => self.fail_closed(generation),
        }
    }

    fn prepare_rehash_outcomes(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
    ) -> Option<(AdminAuditEvent, AdminAuditEvent)> {
        if !audit_phase_is_valid(&event.command, AdminAuditPhase::OutcomeSuccess)
            || !audit_phase_is_valid(&event.command, AdminAuditPhase::OutcomeFailure)
        {
            self.fail_closed(generation);
            return None;
        }
        let Some((operator_id, _permissions)) = self
            .sessions
            .get(&generation)
            .and_then(|owned| owned.session.operator())
        else {
            self.close(generation, CloseReason::ProtocolError);
            return None;
        };
        let created_at = match self.wall.utc_now() {
            Ok(now) => now.get(),
            Err(_) => {
                self.output_storage_unavailable(generation, event.command.verb());
                return None;
            }
        };
        let success = self.audit.prepare_event(
            self.binding,
            operator_id,
            event,
            AdminAuditPhase::OutcomeSuccess,
            created_at,
        );
        let failure = self.audit.prepare_event(
            self.binding,
            operator_id,
            event,
            AdminAuditPhase::OutcomeFailure,
            created_at,
        );
        match (success, failure) {
            (Ok(success), Ok(failure)) => Some((success, failure)),
            _ => {
                self.output_storage_unavailable(generation, event.command.verb());
                None
            }
        }
    }

    fn prepare_action_event(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        phase: AdminAuditPhase,
    ) -> Option<AdminAuditEvent> {
        if !audit_phase_is_valid(&event.command, phase) {
            self.fail_closed(generation);
            return None;
        }
        let Some((operator_id, _permissions)) = self
            .sessions
            .get(&generation)
            .and_then(|owned| owned.session.operator())
        else {
            self.close(generation, CloseReason::ProtocolError);
            return None;
        };
        let created_at = match self.wall.utc_now() {
            Ok(now) => now.get(),
            Err(_) => {
                self.output_storage_unavailable(generation, event.command.verb());
                return None;
            }
        };
        match self
            .audit
            .prepare_event(self.binding, operator_id, event, phase, created_at)
        {
            Ok(audit) => Some(audit),
            Err(_) => {
                self.output_storage_unavailable(generation, event.command.verb());
                None
            }
        }
    }

    async fn commit_action_audit(
        &mut self,
        generation: ConnectionGeneration,
        audit: AdminAuditEvent,
        token: &CancellationToken,
    ) -> Result<(), AdminCoreFailure> {
        self.core.commit_audit(audit.clone(), token).await?;
        if self.audit.commit_event(&audit).is_err() {
            self.fail_closed(generation);
            return Err(AdminCoreFailure::StorageUnavailable);
        }
        Ok(())
    }

    async fn commit_rehash_outcome(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
        phase: AdminAuditPhase,
        token: &CancellationToken,
    ) -> bool {
        let Some(audit) = self.prepare_action_event(generation, event, phase) else {
            self.fail_closed(generation);
            return false;
        };
        if self
            .commit_action_audit(generation, audit, token)
            .await
            .is_err()
        {
            self.fail_closed(generation);
            return false;
        }
        true
    }

    fn output_reload_prepare_failure(
        &self,
        generation: ConnectionGeneration,
        failure: ReloadPrepareFailure,
    ) {
        let line = match failure {
            ReloadPrepareFailure::RestartRequired(_)
            | ReloadPrepareFailure::RestartMaterialChanged => {
                "FAIL REHASH RESTART_REQUIRED :Configuration requires restart"
            }
            ReloadPrepareFailure::Busy => "FAIL REHASH BUSY :Administrative action busy",
            ReloadPrepareFailure::Unavailable => {
                "FAIL REHASH STORAGE_UNAVAILABLE :Administrative reload unavailable"
            }
            ReloadPrepareFailure::InvalidConfig
            | ReloadPrepareFailure::InvalidMaterial
            | ReloadPrepareFailure::RevisionExhausted
            | ReloadPrepareFailure::ResourceFloor
            | ReloadPrepareFailure::StorageFloor => {
                "FAIL REHASH INVALID_CONFIG :Configuration rejected"
            }
        };
        self.output_line(generation, line.to_owned());
    }

    fn output_reload_rejection(
        &self,
        generation: ConnectionGeneration,
        rejection: ReloadRejection,
    ) {
        let line = match rejection {
            ReloadRejection::Busy | ReloadRejection::Quiescing | ReloadRejection::StaleRevision => {
                "FAIL REHASH BUSY :Administrative action busy"
            }
            ReloadRejection::CurrentUse => "FAIL REHASH INVALID_CONFIG :Configuration rejected",
            ReloadRejection::StorageUnavailable => {
                "FAIL REHASH STORAGE_UNAVAILABLE :Administrative reload unavailable"
            }
        };
        self.output_line(generation, line.to_owned());
    }

    fn output_audit_failure(
        &self,
        generation: ConnectionGeneration,
        verb: &str,
        failure: AdminCoreFailure,
    ) {
        self.output_admin_failure(generation, verb, failure);
    }

    fn output_admin_failure(
        &self,
        generation: ConnectionGeneration,
        verb: &str,
        failure: AdminCoreFailure,
    ) {
        match failure {
            AdminCoreFailure::Busy | AdminCoreFailure::Quiescing => self.output_line(
                generation,
                format!("FAIL {verb} BUSY :Administrative action busy"),
            ),
            AdminCoreFailure::InvalidTarget | AdminCoreFailure::StaleRevision => self.output_line(
                generation,
                format!("FAIL {verb} INVALID_TARGET :Administrative target unavailable"),
            ),
            AdminCoreFailure::StorageUnavailable => {
                self.output_storage_unavailable(generation, verb);
            }
        }
    }

    fn fail_closed(&self, generation: ConnectionGeneration) {
        self.record_command_result(ResultClass::Error);
        self.close(generation, CloseReason::ProtocolError);
        self.signal_fatal();
    }

    fn signal_fatal(&self) {
        if let Some(fatal) = &self.fatal {
            let _sent = fatal.try_send(());
        }
    }

    fn reconcile_authority(&mut self) {
        let Some(snapshot) = self.config.as_ref().map(RuntimeConfigHandle::load) else {
            return;
        };
        let changed = self.registry != *snapshot.operators();
        self.admission = snapshot.operator_admission().clone();
        if !changed {
            return;
        }
        self.registry = snapshot.operators().clone();
        self.sessions.retain(|_, owned| {
            let retained = owned.session.reconcile_authority(&self.registry);
            if !retained {
                let _closed = owned.output.try_close(CloseReason::ProtocolError);
            }
            retained
        });
    }

    async fn prepare_command_lines(
        &mut self,
        generation: ConnectionGeneration,
        command: &AdminCommand,
        token: &CancellationToken,
    ) -> Option<Vec<String>> {
        if let AdminCommand::Stats(selector) = command {
            return match self.prepare_stats(*selector, token).await {
                Ok(lines) => Some(lines),
                Err(failure) => {
                    self.output_stats_failure(generation, *selector, failure);
                    None
                }
            };
        }
        let lines = self.prepare_read_only(command);
        if lines.is_none() {
            self.output_line(
                generation,
                format!("FAIL {} UNAVAILABLE :Command unavailable", command.verb()),
            );
        }
        lines
    }

    fn prepare_observed_event(
        &mut self,
        generation: ConnectionGeneration,
        event: &AdminCommandEvent,
    ) -> Option<AdminAuditEvent> {
        let verb = event.command.verb();
        if !audit_phase_is_valid(&event.command, AdminAuditPhase::Observed) {
            self.fail_closed(generation);
            return None;
        }
        let Some((operator_id, _permissions)) = self
            .sessions
            .get(&generation)
            .and_then(|owned| owned.session.operator())
        else {
            self.close(generation, CloseReason::ProtocolError);
            return None;
        };
        let created_at = match self.wall.utc_now() {
            Ok(now) => now.get(),
            Err(_) => {
                self.output_storage_unavailable(generation, verb);
                return None;
            }
        };
        match self.audit.prepare_event(
            self.binding,
            operator_id,
            event,
            AdminAuditPhase::Observed,
            created_at,
        ) {
            Ok(audit) => Some(audit),
            Err(_) => {
                self.output_storage_unavailable(generation, verb);
                None
            }
        }
    }

    async fn commit_observed(
        &mut self,
        generation: ConnectionGeneration,
        command: &AdminCommand,
        lines: Vec<String>,
        audit: AdminAuditEvent,
        token: &CancellationToken,
    ) {
        let verb = command.verb();
        match self.core.commit_audit(audit.clone(), token).await {
            Ok(()) => {
                if self.audit.commit_event(&audit).is_err() {
                    self.close(generation, CloseReason::ProtocolError);
                    return;
                }
                self.output_batch(generation, lines);
            }
            Err(
                failure @ (AdminCoreFailure::Busy
                | AdminCoreFailure::InvalidTarget
                | AdminCoreFailure::Quiescing
                | AdminCoreFailure::StaleRevision),
            ) => self.output_admin_failure(generation, verb, failure),
            Err(AdminCoreFailure::StorageUnavailable) => {
                if let AdminCommand::Stats(selector) = command {
                    self.output_line(generation, render_stats_storage_unavailable(*selector));
                } else {
                    self.output_storage_unavailable(generation, verb);
                }
            }
        }
    }

    async fn prepare_stats(
        &mut self,
        selector: StatsSelector,
        token: &CancellationToken,
    ) -> Result<Vec<String>, AdminCoreFailure> {
        let mut storage_completion = if selector == StatsSelector::Storage {
            self.statistics_storage
                .as_ref()
                .map(StoragePort::try_statistics)
                .transpose()
                .map_err(|_| AdminCoreFailure::StorageUnavailable)?
        } else {
            None
        };
        let (mut snapshot, storage) = tokio::time::timeout(Duration::from_secs(1), async {
            let snapshot = self.core.snapshot(token).await?;
            let storage = if let Some(completion) = storage_completion.take() {
                Some(
                    wait_storage_completion(completion)
                        .await
                        .map_err(|_| AdminCoreFailure::StorageUnavailable)?,
                )
            } else {
                None
            };
            Ok::<_, AdminCoreFailure>((snapshot, storage))
        })
        .await
        .map_err(|_| AdminCoreFailure::StorageUnavailable)??;
        if let Some(storage) = storage {
            snapshot = snapshot.with_storage(storage.values());
        }
        if let Some(observer) = &self.observer {
            let observed = observer
                .stats_values()
                .map_err(|_| AdminCoreFailure::StorageUnavailable)?;
            snapshot = snapshot.with_observed_runtime(observed.runtime(), observed.rates());
        }
        let values = StatsValues::new(selector, snapshot.values(selector))
            .map_err(|_| AdminCoreFailure::StorageUnavailable)?;
        let sampled_at = self
            .wall
            .utc_now()
            .map_err(|_| AdminCoreFailure::StorageUnavailable)?;
        let mut batch_id = [0_u8; 16];
        self.entropy
            .fill_exact(&mut batch_id)
            .map_err(|_| AdminCoreFailure::StorageUnavailable)?;
        Ok(render_stats_batch(&batch_id, sampled_at.get(), &values))
    }

    fn prepare_read_only(&self, command: &AdminCommand) -> Option<Vec<String>> {
        match command {
            AdminCommand::Motd => Some(self.admin_motd()),
            AdminCommand::Version => Some(vec![
                format!(
                    ":agenc-ircd 371 * :agenc-ircd-{}",
                    env!("CARGO_PKG_VERSION")
                ),
                ":agenc-ircd 374 * :End of INFO".to_owned(),
            ]),
            AdminCommand::Time => self
                .wall
                .utc_now()
                .ok()
                .map(|now| vec![format!(":agenc-ircd 391 * agenc-ircd :{}", now.get())]),
            AdminCommand::Links => Some(vec![
                ":agenc-ircd 371 * :Server topology is not exposed".to_owned(),
                ":agenc-ircd 374 * :End of INFO".to_owned(),
            ]),
            AdminCommand::Info => {
                let snapshot = self.health.capture(self.monotonic.now());
                Some(vec![
                    format!(
                        ":agenc-ircd 371 * :health readiness={} liveness={}",
                        u8::from(snapshot.readiness.ready()),
                        u8::from(snapshot.liveness.live())
                    ),
                    ":agenc-ircd 374 * :End of INFO".to_owned(),
                ])
            }
            AdminCommand::Stats(_)
            | AdminCommand::AuditExport(_)
            | AdminCommand::AuditExportMaintenance(_)
            | AdminCommand::Ping(_)
            | AdminCommand::Pong(_)
            | AdminCommand::Quit
            | AdminCommand::Rehash(_)
            | AdminCommand::Kill { .. }
            | AdminCommand::AccountSuspend { .. }
            | AdminCommand::AccountRestore { .. }
            | AdminCommand::ChannelQuarantine { .. }
            | AdminCommand::ChannelHistoryPurge { .. }
            | AdminCommand::Connect { .. }
            | AdminCommand::Squit { .. }
            | AdminCommand::PeerQuarantine { .. }
            | AdminCommand::BackupCreate(_)
            | AdminCommand::Restart(_)
            | AdminCommand::Die(_) => None,
        }
    }

    fn admin_motd(&self) -> Vec<String> {
        let Some(motd) = self
            .config
            .as_ref()
            .map(RuntimeConfigHandle::load)
            .and_then(|snapshot| snapshot.motd_arc())
        else {
            return vec!["422 * :MOTD File is missing".to_owned()];
        };
        let chunks = crate::runtime_config::public_text_chunks(&motd);
        let mut lines = Vec::with_capacity(chunks.count().saturating_add(2));
        lines.push(":agenc-ircd 375 * :- agenc-ircd Message of the day -".to_owned());
        lines.extend(
            crate::runtime_config::public_text_chunks(&motd)
                .map(|line| format!(":agenc-ircd 372 * :- {line}")),
        );
        lines.push(":agenc-ircd 376 * :End of MOTD".to_owned());
        lines
    }

    fn output_storage_unavailable(&self, generation: ConnectionGeneration, verb: &str) {
        self.output_line(
            generation,
            format!("FAIL {verb} STORAGE_UNAVAILABLE :Administrative audit unavailable"),
        );
    }

    fn output_stats_failure(
        &self,
        generation: ConnectionGeneration,
        selector: StatsSelector,
        failure: AdminCoreFailure,
    ) {
        let line = match failure {
            AdminCoreFailure::Busy | AdminCoreFailure::Quiescing => {
                format!(
                    "FAIL STATS BUSY {} :Administrative action busy",
                    selector.as_str()
                )
            }
            AdminCoreFailure::InvalidTarget
            | AdminCoreFailure::StaleRevision
            | AdminCoreFailure::StorageUnavailable => render_stats_unavailable(selector),
        };
        self.output_line(generation, line);
    }

    fn output_export_job_failure(
        &self,
        generation: ConnectionGeneration,
        error: AuditExportFailure,
    ) {
        match error {
            AuditExportFailure::UnsupportedProfile => self.output_line(
                generation,
                "FAIL AUDIT UNAVAILABLE :Audit export unavailable".to_owned(),
            ),
            AuditExportFailure::Source(error) => self.output_export_failure(generation, error),
        }
    }

    fn output_export_failure(&self, generation: ConnectionGeneration, error: crate::RuntimeError) {
        self.record_command_result(ResultClass::Error);
        match error {
            crate::RuntimeError::Storage(_) => self.output_storage_unavailable(generation, "AUDIT"),
            crate::RuntimeError::LimitExceeded | crate::RuntimeError::MemoryExhausted => self
                .output_line(
                    generation,
                    "FAIL AUDIT UNAVAILABLE :Audit export unavailable".to_owned(),
                ),
            _ => self.fail_closed(generation),
        }
    }

    fn output_export(&self, generation: ConnectionGeneration, prepared: AdminWrite) {
        if let Some(owned) = self.sessions.get(&generation) {
            match owned.output.try_export(prepared) {
                Ok(()) => self.record_command_result(ResultClass::Ok),
                Err(_) => {
                    self.record_command_result(ResultClass::Closed);
                    let _ = owned.output.try_close(CloseReason::SlowConsumer);
                }
            }
        } else {
            self.record_command_result(ResultClass::Closed);
        }
    }

    fn output_line(&self, generation: ConnectionGeneration, line: String) {
        self.output_batch(generation, vec![line]);
    }

    fn output_batch(&self, generation: ConnectionGeneration, lines: Vec<String>) {
        self.record_command_result(classify_admin_output(&lines));
        if let Some(owned) = self.sessions.get(&generation) {
            if owned.output.try_batch(lines, None).is_err() {
                self.record_command_result(ResultClass::Closed);
                let _ = owned.output.try_close(CloseReason::SlowConsumer);
            }
        } else {
            self.record_command_result(ResultClass::Closed);
        }
    }

    fn close(&self, generation: ConnectionGeneration, reason: CloseReason) {
        self.record_command_result(ResultClass::Closed);
        if let Some(owned) = self.sessions.get(&generation) {
            let _ = owned.output.try_close(reason);
        }
    }

    fn record_command_result(&self, result: ResultClass) {
        let next = match self.command_observation.get() {
            AdminCommandObservation::Inactive => return,
            AdminCommandObservation::Pending => result,
            AdminCommandObservation::Complete(current) => merge_result_class(current, result),
        };
        self.command_observation
            .set(AdminCommandObservation::Complete(next));
    }
}

fn classify_admin_output(lines: &[String]) -> ResultClass {
    lines
        .iter()
        .filter_map(|line| {
            let mut words = line.split_ascii_whitespace();
            if words.next() != Some("FAIL") {
                return None;
            }
            let _verb = words.next();
            match words.next() {
                Some("BUSY") => Some(ResultClass::Busy),
                Some("STORAGE_UNAVAILABLE") => Some(ResultClass::Error),
                Some(_) | None => Some(ResultClass::Rejected),
            }
        })
        .fold(ResultClass::Ok, merge_result_class)
}

const fn merge_result_class(left: ResultClass, right: ResultClass) -> ResultClass {
    if result_class_rank(left) >= result_class_rank(right) {
        left
    } else {
        right
    }
}

const fn result_class_rank(result: ResultClass) -> u8 {
    match result {
        ResultClass::Ok => 0,
        ResultClass::Rejected => 1,
        ResultClass::Busy => 2,
        ResultClass::Closed => 3,
        ResultClass::Error => 4,
    }
}

const fn audit_phase_is_valid(command: &AdminCommand, phase: AdminAuditPhase) -> bool {
    match command {
        AdminCommand::Motd
        | AdminCommand::Version
        | AdminCommand::Time
        | AdminCommand::Info
        | AdminCommand::Links
        | AdminCommand::Stats(_)
        | AdminCommand::AuditExport(_)
        | AdminCommand::AuditExportMaintenance(_) => matches!(phase, AdminAuditPhase::Observed),
        AdminCommand::Rehash(_)
        | AdminCommand::Kill { .. }
        | AdminCommand::BackupCreate(_)
        | AdminCommand::Connect { .. }
        | AdminCommand::Squit { .. }
        | AdminCommand::PeerQuarantine { .. } => {
            matches!(
                phase,
                AdminAuditPhase::Intent
                    | AdminAuditPhase::OutcomeSuccess
                    | AdminAuditPhase::OutcomeFailure
            )
        }
        AdminCommand::AccountSuspend { .. }
        | AdminCommand::AccountRestore { .. }
        | AdminCommand::ChannelQuarantine { .. }
        | AdminCommand::ChannelHistoryPurge { .. } => {
            matches!(phase, AdminAuditPhase::CommittedMutation)
        }
        AdminCommand::Restart(_) | AdminCommand::Die(_) => {
            matches!(phase, AdminAuditPhase::Intent)
        }
        AdminCommand::Ping(_) | AdminCommand::Pong(_) | AdminCommand::Quit => false,
    }
}

fn confirmation_target(command: &AdminCommand) -> Option<AdminTarget> {
    match command {
        AdminCommand::AccountSuspend { account, .. } => Some(AdminTarget::Account(*account)),
        AdminCommand::ChannelHistoryPurge { channel, .. } => Some(AdminTarget::Channel(*channel)),
        // A peer has no domain revision; the durable deny confirms against
        // the live process target, within the bound admin session authority.
        AdminCommand::Restart(_) | AdminCommand::Die(_) | AdminCommand::PeerQuarantine { .. } => {
            Some(AdminTarget::Process)
        }
        _ => None,
    }
}

fn map_backup_failure(error: StorageError) -> AdminCoreFailure {
    match error {
        StorageError::QueueFull | StorageError::AllocationFailed => AdminCoreFailure::Busy,
        StorageError::InvalidEncoding
        | StorageError::UnsupportedVersion
        | StorageError::LimitExceeded
        | StorageError::Overflow
        | StorageError::AuthenticationFailed
        | StorageError::StaleState
        | StorageError::Unavailable
        | StorageError::FilesystemRejected
        | StorageError::WriterLocked
        | StorageError::DatabaseRejected
        | StorageError::UnsupportedMigration
        | StorageError::ResumeMismatch => AdminCoreFailure::StorageUnavailable,
    }
}

async fn wait_for_config_change(
    receiver: &mut Option<watch::Receiver<crate::runtime_config::ConfigRevision>>,
) -> bool {
    match receiver {
        Some(receiver) => receiver.changed().await.is_ok(),
        None => std::future::pending().await,
    }
}

/// Inputs transferred into one administrative connection owner.
pub(crate) struct AdminConnectionStart {
    pub(crate) generation: ConnectionGeneration,
    pub(crate) purpose: ListenerPurpose,
    pub(crate) resources: ConnectionResources,
    pub(crate) challenge: AdminChallenge,
    pub(crate) peer: PeerIdentity,
    pub(crate) port: AdminTransportPort,
    pub(crate) token: CancellationToken,
}

/// Runs one bounded administrative reader/writer pair to completion.
// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=one connection scope owns paired bounded reader writer cancellation and all resource permits
pub(crate) async fn run_admin_connection<T>(
    transport: T,
    start: AdminConnectionStart,
) -> ConnectionExit
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let AdminConnectionStart {
        generation,
        purpose,
        resources,
        challenge,
        peer,
        port,
        token,
    } = start;
    let ConnectionResources {
        permits,
        global_slot,
        listener_slot,
        queue_backing,
    } = resources;
    let (output_sender, output_receiver) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
    let output = AdminOutput::new(output_sender);
    let flush_acknowledgement = output.flush_acknowledgement.clone();
    if let Err(reason) = port
        .opened(generation, challenge, peer, output, &token)
        .await
    {
        drop((permits, global_slot, listener_slot, queue_backing));
        return ConnectionExit {
            generation,
            purpose,
            reason,
        };
    }

    let (read_half, write_half) = tokio::io::split(transport);
    let reader_token = token.child();
    let writer_token = token.child();
    let reason = match (reader_token, writer_token) {
        (Ok(reader_token), Ok(writer_token)) => {
            let mut reader = tokio::spawn(run_admin_reader(
                read_half,
                generation,
                port.clone(),
                reader_token.clone(),
            ));
            let mut writer = tokio::spawn(run_admin_writer(
                write_half,
                output_receiver,
                writer_token.clone(),
                flush_acknowledgement,
            ));
            tokio::select! {
                read = &mut reader => {
                    let reason = read.unwrap_or(CloseReason::TransportLoss);
                    writer_token.cancel();
                    let _ = writer.await;
                    reason
                }
                written = &mut writer => {
                    let reason = written.unwrap_or(CloseReason::TransportLoss);
                    reader_token.cancel();
                    let _ = reader.await;
                    reason
                }
            }
        }
        _ => CloseReason::Overload,
    };
    port.closed(generation, reason).await;
    drop((permits, global_slot, listener_slot, queue_backing));
    ConnectionExit {
        generation,
        purpose,
        reason,
    }
}

async fn run_admin_reader<R>(
    mut reader: R,
    generation: ConnectionGeneration,
    port: AdminTransportPort,
    token: CancellationToken,
) -> CloseReason
where
    R: AsyncRead + Unpin,
{
    let mut frame = [0_u8; MAX_ADMIN_LINE_BYTES];
    let mut used = 0_usize;
    loop {
        if used == frame.len() {
            return CloseReason::ProtocolError;
        }
        let Some(remaining) = frame.get_mut(used..) else {
            return CloseReason::ProtocolError;
        };
        let read = tokio::select! {
            () = token.cancelled() => return CloseReason::Shutdown,
            read = reader.read(remaining) => match read {
                Ok(read) => read,
                Err(_) => return CloseReason::TransportLoss,
            },
        };
        if read == 0 {
            return if used == 0 {
                CloseReason::TransportLoss
            } else {
                CloseReason::ProtocolError
            };
        }
        used = used.saturating_add(read);
        while let Some(end) = frame
            .get(..used)
            .and_then(|buffered| buffered.iter().position(|byte| *byte == b'\n'))
        {
            let line_len = end.saturating_add(1);
            if line_len < 2 || frame.get(line_len - 2) != Some(&b'\r') {
                return CloseReason::ProtocolError;
            }
            let Some(line) = frame.get(..line_len).map(<[u8]>::to_vec) else {
                return CloseReason::ProtocolError;
            };
            frame.copy_within(line_len..used, 0);
            used -= line_len;
            if let Err(reason) = port.line(generation, line, &token).await {
                return reason;
            }
        }
    }
}

async fn run_admin_writer<W>(
    mut writer: W,
    mut output: mpsc::Receiver<AdminWrite>,
    token: CancellationToken,
    flush_acknowledgement: FlushAcknowledgement,
) -> CloseReason
where
    W: AsyncWrite + Unpin,
{
    let reason = 'writer: loop {
        let batch = tokio::select! {
            () = token.cancelled() => break 'writer CloseReason::Shutdown,
            batch = output.recv() => match batch {
                Some(batch) => batch,
                None => break 'writer CloseReason::TransportLoss,
            },
        };
        if let Err(reason) = write_admin_batch(&mut writer, &batch).await {
            break reason;
        }
        if let Some(reason) = batch.close {
            break reason;
        }
    };
    finish_admin_writer(&mut writer).await;
    flush_acknowledgement.acknowledge();
    reason
}

async fn write_admin_batch<W: AsyncWrite + Unpin>(
    writer: &mut W,
    batch: &AdminWrite,
) -> Result<(), CloseReason> {
    let write = async {
        for line in &batch.lines {
            writer.write_all(line).await?;
            writer.write_all(b"\r\n").await?;
        }
        writer.flush().await
    };
    match tokio::time::timeout(WRITE_STALL_BUDGET, write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(CloseReason::TransportLoss),
        Err(_) => Err(CloseReason::WriteStall),
    }
}

async fn finish_admin_writer<W: AsyncWrite + Unpin>(writer: &mut W) {
    let finish = async {
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
    };
    let _ = tokio::time::timeout(CLOSE_NOTIFY_GRACE, finish).await;
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    use agenc_ircd_admin::{
        AdminChallenge, AdminCommandTbs, AdminSessionBinding, AdminSessionId, Challenge,
        OperatorRecord, OperatorRegistry, PeerIdentity, TransportBinding, TransportKind,
        encode_base64url, render_admin_tag,
    };
    use agenc_ircd_crypto::Ed25519SecretKey;
    use agenc_ircd_testkit::ScriptedEntropy;
    use agenc_ircd_types::{
        AdminPermission, AdminPermissionSet, MonotonicTick, NetworkId, OperatorId, ServerId,
    };

    use super::*;
    use crate::RuntimeError;
    use crate::clock::{SystemMonotonicClock, SystemWallClock};
    use crate::connection::AdmittedConnection;
    use crate::listener::{ConnectionObserver as _, RefusalReason};
    use crate::observe::events::{CorrelationSource, Severity};
    use crate::observe::health::ReadinessStage;
    use crate::observe::log::{LogFilter, LogRetention, LogTarget, LogWriter};
    use crate::observe::metrics::{CommandClass, MetricsRegistry};
    use crate::state_core::{AdminCoreSnapshot, admin_core_channel};

    static NEXT_BACKUP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct DiscardLog;

    impl LogTarget for DiscardLog {
        fn open_segment(&mut self, _hour: u64) -> io::Result<()> {
            Ok(())
        }

        fn write_line(&mut self, _line: &str) -> io::Result<()> {
            Ok(())
        }

        fn retire_before(&mut self, _hour: u64, _limit: usize) -> io::Result<bool> {
            Ok(true)
        }
    }

    struct BackupTestDirectory(PathBuf);

    impl BackupTestDirectory {
        fn create() -> Result<Self, RuntimeError> {
            let sequence = NEXT_BACKUP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agenc-admin-backup-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .map_err(|_| RuntimeError::Storage(StorageError::FilesystemRejected))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|_| RuntimeError::Storage(StorageError::FilesystemRejected))?;
            Ok(Self(path))
        }
    }

    impl Drop for BackupTestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn backup_reconciliation_job(
        directory: &BackupTestDirectory,
        audit_sequence: u64,
        created_at: u64,
    ) -> Result<BackupReconciliationJob, RuntimeError> {
        Ok(BackupReconciliationJob {
            directory: directory.0.clone(),
            source_master_key: Zeroizing::new([31; 32]),
            source_guard_root_key: Zeroizing::new([32; 32]),
            trusted_keys: vec![BackupTrustKey::new(
                Ed25519SecretKey::from_bytes([33; 32]).public_key(),
            )?],
            maximum_bytes: 1_048_576,
            audit_sequence,
            created_at,
        })
    }

    fn registry() -> Result<OperatorRegistry, RuntimeError> {
        let mut permissions = AdminPermissionSet::EMPTY;
        permissions.insert(AdminPermission::Observe);
        let record = OperatorRecord::new(
            OperatorId::from_bytes([7; 16]),
            Ed25519SecretKey::from_bytes([8; 32]).public_key(),
            None,
            vec![1000],
            Vec::new(),
            permissions,
            true,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        OperatorRegistry::from_records(vec![record]).map_err(|_| RuntimeError::InvalidValue)
    }

    fn all_permissions_registry() -> Result<OperatorRegistry, RuntimeError> {
        let mut permissions = AdminPermissionSet::EMPTY;
        for permission in AdminPermission::ALL {
            permissions.insert(permission);
        }
        let record = OperatorRecord::new(
            OperatorId::from_bytes([7; 16]),
            Ed25519SecretKey::from_bytes([8; 32]).public_key(),
            None,
            vec![1000],
            Vec::new(),
            permissions,
            true,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        OperatorRegistry::from_records(vec![record]).map_err(|_| RuntimeError::InvalidValue)
    }

    fn binding() -> AdminSessionBinding {
        AdminSessionBinding {
            network_id: NetworkId::from_bytes([1; 32]),
            server_id: ServerId::from_bytes([2; 16]),
        }
    }

    #[test]
    fn backup_startup_reconciliation_never_invents_completion() -> Result<(), RuntimeError> {
        use std::io::Write as _;

        let directory = BackupTestDirectory::create()?;
        assert_eq!(
            backup_reconciliation_job(&directory, 7, 50)?.run(),
            Ok(false)
        );

        let name = format!(
            "admin-{:020}-{}.agenc-backup",
            7,
            encode_base64url(&[41; 16])
        );
        let mut candidate = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.0.join(name))
            .map_err(|_| RuntimeError::Storage(StorageError::FilesystemRejected))?;
        candidate
            .write_all(b"not a signed backup")
            .map_err(|_| RuntimeError::Storage(StorageError::FilesystemRejected))?;
        drop(candidate);

        assert!(backup_reconciliation_job(&directory, 7, 50)?.run().is_err());
        Ok(())
    }

    fn challenge() -> AdminChallenge {
        AdminChallenge::new(
            AdminSessionId::from_bytes([3; 16]),
            Challenge::from_bytes([4; 32]),
            TransportKind::Local,
            TransportBinding::from_bytes([5; 32]),
        )
    }

    fn live_health() -> AdminOwnerHealth {
        let readiness = Arc::new(ReadinessGate::new());
        for stage in [
            ReadinessStage::Configuration,
            ReadinessStage::Keys,
            ReadinessStage::StorageRecovered,
            ReadinessStage::StateCore,
            ReadinessStage::Federation,
        ] {
            readiness.mark(stage);
        }
        let liveness = Arc::new(Liveness::new());
        let now = MonotonicTick::from_ticks(0);
        liveness.record_supervisor(now);
        liveness.record_state_core(now);
        AdminOwnerHealth {
            readiness,
            liveness,
        }
    }

    fn lifecycle_owner() -> Result<AdminOwner, RuntimeError> {
        let (core, _core_inbox) = admin_core_channel();
        Ok(AdminOwner::new(
            binding(),
            registry()?,
            AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new()),
            AuditAuthority::empty_for_test()?,
            core,
            AdminOwnerRuntime {
                health: live_health(),
                config: None,
                reload: None,
                backup: None,
                process: None,
                fatal: None,
                observer: None,
                budget: Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 2)),
                entropy: Box::new(
                    ScriptedEntropy::new(vec![0; 64]).map_err(|_| RuntimeError::InvalidValue)?,
                ),
                clocks: AdminOwnerClocks {
                    monotonic: Box::new(SystemMonotonicClock::start()),
                    wall: Box::new(SystemWallClock),
                },
            },
        ))
    }

    fn oper_line() -> Result<Vec<u8>, RuntimeError> {
        let operator = OperatorId::from_bytes([7; 16]);
        let signature = challenge()
            .sign_oper(
                binding().network_id,
                binding().server_id,
                &Ed25519SecretKey::from_bytes([8; 32]),
            )
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(format!(
            "OPER {} {}\r\n",
            operator.to_base64url(),
            encode_base64url(signature.as_bytes())
        )
        .into_bytes())
    }

    fn signed_line(counter: u64, command: &str) -> Result<Vec<u8>, RuntimeError> {
        let tbs = AdminCommandTbs::new(
            binding().network_id,
            binding().server_id,
            challenge().session_id(),
            counter,
            None,
            command.as_bytes(),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let signature = tbs
            .sign(&Ed25519SecretKey::from_bytes([8; 32]))
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(format!(
            "{} {command}\r\n",
            render_admin_tag(counter, &signature, None)
        )
        .into_bytes())
    }

    fn confirmed_line(
        counter: u64,
        command: &str,
        token: &ConfirmationToken,
    ) -> Result<Vec<u8>, RuntimeError> {
        let tbs = AdminCommandTbs::new(
            binding().network_id,
            binding().server_id,
            challenge().session_id(),
            counter,
            Some(token.hash().map_err(|_| RuntimeError::InvalidValue)?),
            command.as_bytes(),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let signature = tbs
            .sign(&Ed25519SecretKey::from_bytes([8; 32]))
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(format!(
            "{} {command}\r\n",
            render_admin_tag(counter, &signature, Some(token))
        )
        .into_bytes())
    }

    #[tokio::test]
    async fn command_rejection_keeps_its_authenticated_observation_category()
    -> Result<(), RuntimeError> {
        use crate::observe::log::FileLogOwner;
        use crate::observe::metrics::{LabelSet, MetricKey, MetricLabel, MetricName, MetricsView};

        let directory = BackupTestDirectory::create()?;
        let correlation = Arc::new(CorrelationSource::new(10));
        let metrics = Arc::new(MetricsRegistry::new());
        let (log_owner, log) = FileLogOwner::start(
            &directory.0,
            LogRetention::DEFAULT,
            LogFilter::new(Severity::Debug),
            binding().server_id,
            Arc::clone(&correlation),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let observer = Arc::new(RuntimeObserver::new(
            binding().server_id,
            SystemMonotonicClock::start(),
            correlation,
            log,
            Arc::clone(&metrics),
        ));
        let mut owner = lifecycle_owner()?;
        owner.registry = all_permissions_registry()?;
        owner.observer = Some(observer);
        let root = CancellationToken::root();
        let token = ConfirmationToken::from_bytes([42; 16]);
        let cases = [
            (false, b"OPER invalid proof\r\n".to_vec()),
            (true, signed_line(0, "DIE :resync")?),
            (true, signed_line(1, "VERSION")?),
            (true, confirmed_line(0, "DIE resync", &token)?),
        ];
        for (index, (authenticated, line)) in cases.into_iter().enumerate() {
            let generation = ConnectionGeneration::new(
                u64::try_from(index).map_err(|_| RuntimeError::InvalidValue)? + 1,
            );
            let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
            owner.open(
                generation,
                challenge(),
                PeerIdentity::Local {
                    uid: 1000,
                    gid: 1000,
                },
                AdminOutput::new(sender),
            );
            let challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
            assert_eq!(challenge.close, None);
            if authenticated {
                owner.line(generation, &oper_line()?, &root).await;
            }
            owner.line(generation, &line, &root).await;
            let rejection = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
            assert_eq!(rejection.close, Some(CloseReason::ProtocolError));
        }
        let key = MetricKey {
            name: MetricName::CommandsHandled,
            labels: LabelSet::new(&[
                MetricLabel::CommandClass(CommandClass::Administration),
                MetricLabel::ResultClass(ResultClass::Rejected),
            ])?,
        };
        assert_eq!(
            metrics.snapshot(MetricsView::Operator).counters,
            vec![(key, 3)]
        );
        drop(owner);
        assert_eq!(log_owner.shutdown().await?, 0);
        let logs = admin_observation_logs(&directory)?;
        assert_eq!(logs.matches("admin_rejected").count(), 1);
        assert_eq!(logs.matches("authentication_failed").count(), 1);
        assert_eq!(logs.matches("admin_authenticated").count(), 3);
        assert_eq!(logs.matches("admin_action").count(), 3);
        Ok(())
    }

    fn admin_observation_logs(directory: &BackupTestDirectory) -> Result<String, RuntimeError> {
        let entries =
            fs::read_dir(directory.0.join("logs")).map_err(|_| RuntimeError::InvalidValue)?;
        let mut logs = String::new();
        for entry in entries.take(4) {
            let path = entry.map_err(|_| RuntimeError::InvalidValue)?.path();
            if path.extension().is_some_and(|extension| extension == "log") {
                logs.push_str(&fs::read_to_string(path).map_err(|_| RuntimeError::InvalidValue)?);
            }
        }
        Ok(logs)
    }

    #[tokio::test]
    async fn owner_answers_only_bounded_pre_auth_liveness() -> Result<(), RuntimeError> {
        let (port, inbox) = admin_transport_channel(binding());
        let (_lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
        let root = CancellationToken::root();
        let admission = AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new());
        let (core, _core_inbox) = admin_core_channel();
        let owner = tokio::spawn(
            AdminOwner::new(
                binding(),
                registry()?,
                admission,
                AuditAuthority::empty_for_test()?,
                core,
                AdminOwnerRuntime {
                    health: live_health(),
                    config: None,
                    reload: None,
                    backup: None,
                    process: None,
                    fatal: None,
                    observer: None,
                    budget: Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 2)),
                    entropy: Box::new(
                        ScriptedEntropy::new(vec![0; 64])
                            .map_err(|_| RuntimeError::InvalidValue)?,
                    ),
                    clocks: AdminOwnerClocks {
                        monotonic: Box::new(SystemMonotonicClock::start()),
                        wall: Box::new(SystemWallClock),
                    },
                },
            )
            .run(inbox, lifecycle_inbox, root.clone()),
        );
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        port.opened(
            ConnectionGeneration::new(1),
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput::new(sender),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(challenge.lines.len(), 1);
        assert!(
            challenge
                .lines
                .first()
                .is_some_and(|line| line.starts_with(b"NOTE OPER CHALLENGE "))
        );
        port.line(
            ConnectionGeneration::new(1),
            b"PING token\r\n".to_vec(),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let pong = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(pong.lines, vec![b"PONG :token".to_vec()]);
        root.cancel();
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[tokio::test]
    async fn lifecycle_queues_one_shutdown_frame_and_reuses_its_acknowledgement()
    -> Result<(), RuntimeError> {
        let (port, inbox) = admin_transport_channel(binding());
        let (lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
        let root = CancellationToken::root();
        let (core, _core_inbox) = admin_core_channel();
        let owner = tokio::spawn(
            AdminOwner::new(
                binding(),
                registry()?,
                AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new()),
                AuditAuthority::empty_for_test()?,
                core,
                AdminOwnerRuntime {
                    health: live_health(),
                    config: None,
                    reload: None,
                    backup: None,
                    process: None,
                    fatal: None,
                    observer: None,
                    budget: Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 2)),
                    entropy: Box::new(
                        ScriptedEntropy::new(vec![0; 64])
                            .map_err(|_| RuntimeError::InvalidValue)?,
                    ),
                    clocks: AdminOwnerClocks {
                        monotonic: Box::new(SystemMonotonicClock::start()),
                        wall: Box::new(SystemWallClock),
                    },
                },
            )
            .run(inbox, lifecycle_inbox, root.clone()),
        );
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        port.opened(
            ConnectionGeneration::new(2),
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput::new(sender),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;

        lifecycle
            .quiesce()
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        drop(port);
        let acknowledgements = lifecycle
            .drain()
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(acknowledgements.len(), 1);
        let acknowledgement = acknowledgements.first().ok_or(RuntimeError::InvalidValue)?;
        assert!(!acknowledgement.is_acknowledged());
        let shutdown = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            shutdown.lines,
            vec![ADMIN_SHUTDOWN_LINE.as_bytes().to_vec()]
        );
        assert_eq!(shutdown.close, Some(CloseReason::Shutdown));

        let repeated = lifecycle
            .drain()
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(repeated.len(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), output.recv())
                .await
                .is_err()
        );
        let repeated_acknowledgement = repeated.first().ok_or(RuntimeError::InvalidValue)?;
        acknowledgement.acknowledge();
        repeated_acknowledgement.wait().await;
        lifecycle
            .flush()
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        lifecycle
            .stop()
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[tokio::test]
    async fn lifecycle_progress_is_monotonic_and_reuses_the_flush_result()
    -> Result<(), RuntimeError> {
        let root = CancellationToken::root();
        let mut owner = lifecycle_owner()?;

        assert!(matches!(
            owner
                .lifecycle_outcome(AdminLifecyclePhase::Drain, &root)
                .await,
            Ok(AdminLifecycleOutcome::Draining(acknowledgements))
                if acknowledgements.is_empty()
        ));
        assert_eq!(owner.lifecycle_completed, Some(AdminLifecyclePhase::Drain));
        assert!(matches!(
            owner
                .lifecycle_outcome(AdminLifecyclePhase::Quiesce, &root)
                .await,
            Ok(AdminLifecycleOutcome::Complete)
        ));
        assert_eq!(owner.lifecycle_completed, Some(AdminLifecyclePhase::Drain));
        assert!(matches!(
            owner
                .lifecycle_outcome(AdminLifecyclePhase::Flush, &root)
                .await,
            Ok(AdminLifecycleOutcome::Complete)
        ));
        assert_eq!(owner.lifecycle_completed, Some(AdminLifecyclePhase::Flush));
        assert_eq!(owner.flush_outcome, Some(Ok(())));
        assert!(matches!(
            owner
                .lifecycle_outcome(AdminLifecyclePhase::Flush, &root)
                .await,
            Ok(AdminLifecycleOutcome::Complete)
        ));

        let mut failed = lifecycle_owner()?;
        failed.quiescing = true;
        failed.lifecycle_completed = Some(AdminLifecyclePhase::Drain);
        failed.flush_outcome = Some(Err(AdminLifecycleFailure::Audit));
        assert!(matches!(
            failed
                .lifecycle_outcome(AdminLifecyclePhase::Flush, &root)
                .await,
            Err(AdminLifecycleFailure::Audit)
        ));
        assert_eq!(
            failed.flush_outcome,
            Some(Err(AdminLifecycleFailure::Audit))
        );
        Ok(())
    }

    #[tokio::test]
    async fn queued_stop_supersedes_every_other_bounded_lifecycle_reply() -> Result<(), RuntimeError>
    {
        let (_transport, inbox) = admin_transport_channel(binding());
        let (lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
        let root = CancellationToken::root();

        let (quiesce_reply, quiesce_response) = oneshot::channel();
        lifecycle
            .sender
            .try_send(AdminLifecycleRequest {
                phase: AdminLifecyclePhase::Quiesce,
                reply: quiesce_reply,
            })
            .map_err(|_| RuntimeError::InvalidValue)?;
        let (stop_reply, stop_response) = oneshot::channel();
        lifecycle
            .sender
            .try_send(AdminLifecycleRequest {
                phase: AdminLifecyclePhase::Stop,
                reply: stop_reply,
            })
            .map_err(|_| RuntimeError::InvalidValue)?;
        let (drain_reply, drain_response) = oneshot::channel();
        lifecycle
            .sender
            .try_send(AdminLifecycleRequest {
                phase: AdminLifecyclePhase::Drain,
                reply: drain_reply,
            })
            .map_err(|_| RuntimeError::InvalidValue)?;

        let owner = tokio::spawn(lifecycle_owner()?.run(inbox, lifecycle_inbox, root));
        assert!(matches!(
            quiesce_response.await,
            Ok(Err(AdminLifecycleFailure::Unavailable))
        ));
        assert!(matches!(
            stop_response.await,
            Ok(Ok(AdminLifecycleOutcome::Complete))
        ));
        assert!(matches!(
            drain_response.await,
            Ok(Err(AdminLifecycleFailure::Unavailable))
        ));
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[tokio::test]
    async fn writer_acknowledges_after_the_final_admin_frame_and_transport_close()
    -> Result<(), RuntimeError> {
        let (transport, mut peer) = tokio::io::duplex(1_024);
        let (sender, receiver) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        let acknowledgement = FlushAcknowledgement::pending();
        let root = CancellationToken::root();
        let writer_acknowledgement = acknowledgement.clone();
        let writer = tokio::spawn(run_admin_writer(
            transport,
            receiver,
            root,
            writer_acknowledgement,
        ));
        let batch = AdminWrite::ordinary(
            vec![ADMIN_SHUTDOWN_LINE.to_owned()],
            Some(CloseReason::Shutdown),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        sender
            .send(batch)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(bytes, b"ERROR :Server shutting down\r\n");
        assert_eq!(
            writer.await.map_err(|_| RuntimeError::Cancelled)?,
            CloseReason::Shutdown
        );
        acknowledgement.wait().await;
        assert!(acknowledgement.is_acknowledged());
        Ok(())
    }

    #[tokio::test]
    async fn reader_rejects_lf_only_and_overlong_frames() {
        let (port, _inbox) = admin_transport_channel(binding());
        let root = CancellationToken::root();
        let reason = run_admin_reader(
            &b"PING x\n"[..],
            ConnectionGeneration::new(1),
            port.clone(),
            root.clone(),
        )
        .await;
        assert_eq!(reason, CloseReason::ProtocolError);
        let oversized = vec![b'a'; MAX_ADMIN_LINE_BYTES];
        let reason = run_admin_reader(
            oversized.as_slice(),
            ConnectionGeneration::new(2),
            port,
            root,
        )
        .await;
        assert_eq!(reason, CloseReason::ProtocolError);
    }

    /// One authenticated owner with the edge control surface installed.
    async fn federation_owner_session(
        control: FederationControl,
    ) -> Result<FederationOwnerSession, RuntimeError> {
        let (port, inbox) = admin_transport_channel(binding());
        let (lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
        let (core, core_inbox) = admin_core_channel();
        let root = CancellationToken::root();
        let mut owner = AdminOwner::new(
            binding(),
            all_permissions_registry()?,
            AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new()),
            AuditAuthority::empty_for_test()?,
            core,
            AdminOwnerRuntime {
                health: live_health(),
                config: None,
                reload: None,
                backup: None,
                process: None,
                fatal: None,
                observer: None,
                budget: Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 2)),
                entropy: Box::new(
                    ScriptedEntropy::new(vec![0; 64]).map_err(|_| RuntimeError::InvalidValue)?,
                ),
                clocks: AdminOwnerClocks {
                    monotonic: Box::new(SystemMonotonicClock::start()),
                    wall: Box::new(SystemWallClock),
                },
            },
        );
        owner.install_federation_control(control)?;
        let task = tokio::spawn(owner.run(inbox, lifecycle_inbox, root.clone()));
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        port.opened(
            ConnectionGeneration::new(9),
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput::new(sender),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        port.line(ConnectionGeneration::new(9), oper_line()?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(FederationOwnerSession {
            port,
            core_inbox,
            output,
            root,
            task,
            _lifecycle: lifecycle,
        })
    }

    /// The live pieces of one federation admin session; the lifecycle
    /// control must outlive the owner or it stops.
    struct FederationOwnerSession {
        port: AdminTransportPort,
        core_inbox: crate::state_core::AdminCoreInbox,
        output: mpsc::Receiver<AdminWrite>,
        root: CancellationToken,
        task: tokio::task::JoinHandle<()>,
        _lifecycle: AdminLifecycleControl,
    }

    #[tokio::test]
    async fn federation_commands_record_intent_and_outcome() -> Result<(), RuntimeError> {
        const PEER: &str = "AAAAAAAAAAAAAAAAAAAAAA";
        let peer =
            agenc_ircd_types::ServerId::parse(PEER).map_err(|_| RuntimeError::InvalidValue)?;
        let control = FederationControl::new(agenc_ircd_types::FederationRole::Edge, [peer]);
        let FederationOwnerSession {
            port,
            mut core_inbox,
            mut output,
            root,
            task: owner,
            _lifecycle,
        } = federation_owner_session(control.clone()).await?;
        let generation = ConnectionGeneration::new(9);

        // CONNECT on an edge succeeds through the control surface alone.
        port.line(
            generation,
            signed_line(0, &format!("CONNECT {PEER} :bring up"))?,
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let intent = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(intent.tbs().phase, AdminAuditPhase::Intent);
        let outcome = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(outcome.tbs().phase, AdminAuditPhase::OutcomeSuccess);
        let reply = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            reply.lines,
            vec![b"NOTE CONNECT OK :Link requested".to_vec()]
        );

        // SQUIT on an unknown peer fails after its intent record.
        port.line(
            generation,
            signed_line(1, "SQUIT AAAAAAAAAAAAAAAAAAAAAQ :take down")?,
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _intent = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        let outcome = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(outcome.tbs().phase, AdminAuditPhase::OutcomeFailure);
        let reply = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert!(
            reply
                .lines
                .iter()
                .any(|line| line.starts_with(b"FAIL SQUIT "))
        );

        // PEER QUARANTINE is a confirmed action: the first submission binds a
        // token to the process target, the repeat runs it, and the durable
        // deny goes to the state core between its two records.
        let quarantine = format!("PEER QUARANTINE {PEER} :deny now");
        port.line(generation, signed_line(2, &quarantine)?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        let revision =
            agenc_ircd_types::Revision::new(9).map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(
            core_inbox.complete_target_revision_for_test(revision).await,
            Some(AdminTarget::Process)
        );
        let confirmation = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert!(
            confirmation
                .lines
                .iter()
                .any(|line| line.starts_with(b"NOTE PEER CONFIRM "))
        );
        port.line(
            generation,
            confirmed_line(3, &quarantine, &ConfirmationToken::from_bytes([0; 16]))?,
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _intent = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert!(
            core_inbox
                .complete_next_for_test(Err(AdminCoreFailure::InvalidTarget))
                .await
                .is_none()
        );
        let outcome = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(outcome.tbs().phase, AdminAuditPhase::OutcomeFailure);
        let reply = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert!(
            reply
                .lines
                .iter()
                .any(|line| line.starts_with(b"FAIL PEER "))
        );

        root.cancel();
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[tokio::test]
    async fn observed_output_waits_for_the_durable_audit_reply() -> Result<(), RuntimeError> {
        let (port, inbox) = admin_transport_channel(binding());
        let (_lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
        let (core, mut core_inbox) = admin_core_channel();
        let root = CancellationToken::root();
        let owner = tokio::spawn(
            AdminOwner::new(
                binding(),
                registry()?,
                AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new()),
                AuditAuthority::empty_for_test()?,
                core,
                AdminOwnerRuntime {
                    health: live_health(),
                    config: None,
                    reload: None,
                    backup: None,
                    process: None,
                    fatal: None,
                    observer: None,
                    budget: Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 2)),
                    entropy: Box::new(
                        ScriptedEntropy::new(vec![0; 64])
                            .map_err(|_| RuntimeError::InvalidValue)?,
                    ),
                    clocks: AdminOwnerClocks {
                        monotonic: Box::new(SystemMonotonicClock::start()),
                        wall: Box::new(SystemWallClock),
                    },
                },
            )
            .run(inbox, lifecycle_inbox, root.clone()),
        );
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        port.opened(
            ConnectionGeneration::new(9),
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput::new(sender),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        port.line(ConnectionGeneration::new(9), oper_line()?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        port.line(ConnectionGeneration::new(9), signed_line(0, "MOTD")?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        tokio::task::yield_now().await;
        assert!(output.try_recv().is_err());

        let event = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(event.tbs().phase, AdminAuditPhase::Observed);
        assert_eq!(event.tbs().command_tbs.canonical_command(), b"MOTD");
        let reply = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(reply.lines, vec![b"422 * :MOTD File is missing".to_vec()]);

        port.line(ConnectionGeneration::new(9), signed_line(1, "INFO")?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        tokio::task::yield_now().await;
        assert!(output.try_recv().is_err());
        let event = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(event.tbs().command_tbs.canonical_command(), b"INFO");
        let reply = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            reply.lines,
            vec![
                b":agenc-ircd 371 * :health readiness=1 liveness=1".to_vec(),
                b":agenc-ircd 374 * :End of INFO".to_vec(),
            ]
        );

        port.line(
            ConnectionGeneration::new(9),
            signed_line(2, "STATS E2EE")?,
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        tokio::task::yield_now().await;
        assert!(output.try_recv().is_err());
        let snapshot = AdminCoreSnapshot::new([0; 9], [0; 14], [0; 10], [0; 8]);
        assert!(core_inbox.complete_snapshot_for_test(snapshot).await);
        tokio::task::yield_now().await;
        assert!(output.try_recv().is_err());
        let event = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(event.tbs().command_tbs.canonical_command(), b"STATS E2EE");
        let reply = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(reply.lines.len(), 11);
        assert!(reply.lines.first().is_some_and(|line| {
            line.starts_with(b"BATCH +AAAAAAAAAAAAAAAAAAAAAA agenc.ag/stats E2EE 9 ")
        }));
        assert!(
            reply
                .lines
                .iter()
                .skip(1)
                .take(9)
                .all(|line| { line.ends_with(b" 0 :Statistic value") })
        );
        assert_eq!(
            reply.lines.last(),
            Some(&b"BATCH -AAAAAAAAAAAAAAAAAAAAAA".to_vec())
        );
        root.cancel();
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[tokio::test]
    async fn authenticated_stats_read_the_process_metrics_registry() -> Result<(), RuntimeError> {
        let correlation = Arc::new(CorrelationSource::new(10));
        let metrics = Arc::new(MetricsRegistry::new());
        let (log_writer, log) = LogWriter::start(
            DiscardLog,
            LogRetention::DEFAULT,
            LogFilter::new(Severity::Debug),
            ServerId::from_bytes([2; 16]),
            Arc::clone(&correlation),
        );
        let observer = Arc::new(RuntimeObserver::new(
            ServerId::from_bytes([2; 16]),
            SystemMonotonicClock::start(),
            correlation,
            log,
            Arc::clone(&metrics),
        ));
        observer.command_classified(CommandClass::Message, ResultClass::Ok);
        observer.command_classified(CommandClass::Message, ResultClass::Busy);
        observer.authentication(false);
        observer.authentication(true);
        observer.federation_ingress(4, false);
        observer.federation_ingress(5, true);
        observer.tls_started();
        observer.admitted(&AdmittedConnection {
            generation: ConnectionGeneration::new(1),
            purpose: ListenerPurpose::ClientTls,
            source: crate::state_core::inbox::SourceAddressKey::ipv4([127, 0, 0, 1]),
            peer: crate::connection::PeerIdentity::Anonymous,
        });
        observer.refused(ListenerPurpose::ClientTls, RefusalReason::Admission);
        assert!(
            !metrics
                .snapshot(crate::observe::metrics::MetricsView::Operator)
                .counters
                .is_empty()
        );

        let (port, inbox) = admin_transport_channel(binding());
        let (_lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
        let (core, mut core_inbox) = admin_core_channel();
        let root = CancellationToken::root();
        let owner_observer = Arc::clone(&observer);
        let owner = tokio::spawn(
            AdminOwner::new(
                binding(),
                registry()?,
                AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new()),
                AuditAuthority::empty_for_test()?,
                core,
                AdminOwnerRuntime {
                    health: live_health(),
                    config: None,
                    reload: None,
                    backup: None,
                    process: None,
                    fatal: None,
                    observer: Some(owner_observer),
                    budget: Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 2)),
                    entropy: Box::new(
                        ScriptedEntropy::new(vec![0; 128])
                            .map_err(|_| RuntimeError::InvalidValue)?,
                    ),
                    clocks: AdminOwnerClocks {
                        monotonic: Box::new(SystemMonotonicClock::start()),
                        wall: Box::new(SystemWallClock),
                    },
                },
            )
            .run(inbox, lifecycle_inbox, root.clone()),
        );
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        let generation = ConnectionGeneration::new(9);
        port.opened(
            generation,
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput::new(sender),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        port.line(generation, oper_line()?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;

        port.line(generation, signed_line(0, "STATS RATES")?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(
            core_inbox
                .complete_snapshot_for_test(AdminCoreSnapshot::new(
                    [0; 9], [0; 14], [0; 10], [0; 8],
                ))
                .await
        );
        let _audit = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        let rates = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        for (field, value) in [
            ("client_commands_accepted_60s", 1),
            ("client_commands_rate_limited_60s", 1),
            ("connections_admitted_60s", 1),
            ("connections_rejected_60s", 1),
            ("authentication_started_60s", 1),
            ("authentication_rejected_60s", 1),
            ("federation_ingress_bytes_60s", 4),
            ("federation_rejected_bytes_60s", 5),
        ] {
            let expected = format!(" {field} {value} :Statistic value").into_bytes();
            assert!(rates.lines.iter().any(|line| line.ends_with(&expected)));
        }

        port.line(generation, signed_line(1, "STATS RUNTIME")?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(
            core_inbox
                .complete_snapshot_for_test(AdminCoreSnapshot::new(
                    [0; 9], [0; 14], [0; 10], [0; 8],
                ))
                .await
        );
        let _audit = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        let runtime = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        for expected in [
            b" live_client_connections 1 :Statistic value".as_slice(),
            b" tls_handshakes_in_progress 1 :Statistic value".as_slice(),
        ] {
            assert!(runtime.lines.iter().any(|line| line.ends_with(expected)));
        }

        root.cancel();
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        drop(observer);
        drop(log_writer);
        Ok(())
    }

    #[tokio::test]
    async fn account_mutation_waits_for_one_atomic_state_core_commit() -> Result<(), RuntimeError> {
        let (port, inbox) = admin_transport_channel(binding());
        let (_lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
        let (core, mut core_inbox) = admin_core_channel();
        let root = CancellationToken::root();
        let owner = tokio::spawn(
            AdminOwner::new(
                binding(),
                all_permissions_registry()?,
                AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new()),
                AuditAuthority::empty_for_test()?,
                core,
                AdminOwnerRuntime {
                    health: live_health(),
                    config: None,
                    reload: None,
                    backup: None,
                    process: None,
                    fatal: None,
                    observer: None,
                    budget: Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 2)),
                    entropy: Box::new(
                        ScriptedEntropy::new(vec![0; 64])
                            .map_err(|_| RuntimeError::InvalidValue)?,
                    ),
                    clocks: AdminOwnerClocks {
                        monotonic: Box::new(SystemMonotonicClock::start()),
                        wall: Box::new(SystemWallClock),
                    },
                },
            )
            .run(inbox, lifecycle_inbox, root.clone()),
        );
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        port.opened(
            ConnectionGeneration::new(12),
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput::new(sender),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        port.line(ConnectionGeneration::new(12), oper_line()?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;

        let account = agenc_ircd_types::AccountId::from_random(
            agenc_ircd_types::AccountRandomId::from_bytes([9; 16]),
        );
        let command = format!("ACCOUNT SUSPEND {} 60 :policy action", account.to_text());
        let canonical = agenc_ircd_admin::CanonicalCommand::check(command.as_bytes())
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(matches!(
            AdminCommand::parse(canonical),
            Ok(AdminCommand::AccountSuspend { account: parsed, .. }) if parsed == account
        ));
        port.line(
            ConnectionGeneration::new(12),
            signed_line(0, &command)?,
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let revision =
            agenc_ircd_types::Revision::new(7).map_err(|_| RuntimeError::InvalidValue)?;
        let target = tokio::time::timeout(
            Duration::from_secs(1),
            core_inbox.complete_target_revision_for_test(revision),
        )
        .await
        .map_err(|_| RuntimeError::Cancelled)?;
        assert_eq!(target, Some(AdminTarget::Account(account)));
        let first_mutation = tokio::time::timeout(
            Duration::from_secs(1),
            core_inbox.complete_mutation_for_test(Err(AdminCoreFailure::StaleRevision)),
        )
        .await
        .map_err(|_| RuntimeError::Cancelled)?;
        let (event, mutation, expected_revision) =
            first_mutation.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(event.tbs().phase, AdminAuditPhase::CommittedMutation);
        assert_eq!(
            event.tbs().command_tbs.canonical_command(),
            command.as_bytes()
        );
        assert_eq!(expected_revision, revision);
        assert!(matches!(
            mutation,
            AdminMutation::SuspendAccount {
                account_id,
                expires_at,
            } if account_id == account
                && expires_at.get() == event.tbs().created_at.saturating_add(60)
        ));
        let retry_revision =
            agenc_ircd_types::Revision::new(8).map_err(|_| RuntimeError::InvalidValue)?;
        let target = tokio::time::timeout(
            Duration::from_secs(1),
            core_inbox.complete_target_revision_for_test(retry_revision),
        )
        .await
        .map_err(|_| RuntimeError::Cancelled)?;
        assert_eq!(target, Some(AdminTarget::Account(account)));
        let retried_mutation = tokio::time::timeout(
            Duration::from_secs(1),
            core_inbox.complete_mutation_for_test(Ok(())),
        )
        .await
        .map_err(|_| RuntimeError::Cancelled)?;
        let (retried_event, retried_mutation, expected_revision) =
            retried_mutation.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(retried_event, event);
        assert_eq!(retried_mutation, mutation);
        assert_eq!(expected_revision, retry_revision);
        let reply = tokio::time::timeout(Duration::from_secs(1), output.recv())
            .await
            .map_err(|_| RuntimeError::Cancelled)?
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            reply.lines,
            vec![b"NOTE ACCOUNT OK :Account suspended".to_vec()]
        );

        root.cancel();
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[tokio::test]
    async fn confirmed_die_commits_intent_before_requesting_stop() -> Result<(), RuntimeError> {
        let (port, inbox) = admin_transport_channel(binding());
        let (_lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
        let (core, mut core_inbox) = admin_core_channel();
        let (process, mut process_inbox) = admin_process_channel();
        let root = CancellationToken::root();
        let owner = tokio::spawn(
            AdminOwner::new(
                binding(),
                all_permissions_registry()?,
                AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new()),
                AuditAuthority::empty_for_test()?,
                core,
                AdminOwnerRuntime {
                    health: live_health(),
                    config: None,
                    reload: None,
                    backup: None,
                    process: Some(process),
                    fatal: None,
                    observer: None,
                    budget: Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 2)),
                    entropy: Box::new(
                        ScriptedEntropy::new(vec![0; 64])
                            .map_err(|_| RuntimeError::InvalidValue)?,
                    ),
                    clocks: AdminOwnerClocks {
                        monotonic: Box::new(SystemMonotonicClock::start()),
                        wall: Box::new(SystemWallClock),
                    },
                },
            )
            .run(inbox, lifecycle_inbox, root.clone()),
        );
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        port.opened(
            ConnectionGeneration::new(13),
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput::new(sender),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        port.line(ConnectionGeneration::new(13), oper_line()?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;

        let command = "DIE :planned maintenance";
        port.line(
            ConnectionGeneration::new(13),
            signed_line(0, command)?,
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let revision =
            agenc_ircd_types::Revision::new(9).map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(
            core_inbox.complete_target_revision_for_test(revision).await,
            Some(AdminTarget::Process)
        );
        let confirmation = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            confirmation.lines,
            vec![
                b"NOTE DIE CONFIRM AAAAAAAAAAAAAAAAAAAAAA :Repeat this exact command to confirm"
                    .to_vec()
            ]
        );

        let confirmation_token = ConfirmationToken::from_bytes([0; 16]);
        port.line(
            ConnectionGeneration::new(13),
            confirmed_line(1, command, &confirmation_token)?,
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(
            core_inbox.complete_target_revision_for_test(revision).await,
            Some(AdminTarget::Process)
        );
        let event = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(event.tbs().phase, AdminAuditPhase::Intent);
        assert_eq!(
            event.tbs().command_tbs.canonical_command(),
            command.as_bytes()
        );
        let action = tokio::time::timeout(Duration::from_secs(1), process_inbox.recv())
            .await
            .map_err(|_| RuntimeError::Cancelled)?;
        assert_eq!(action, Some(AdminProcessAction::Die));
        port.line(
            ConnectionGeneration::new(13),
            signed_line(2, "MOTD")?,
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                core_inbox.complete_next_for_test(Ok(())),
            )
            .await
            .is_err(),
            "terminal intent admitted a later audit event"
        );
        let close = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        assert!(close.lines.is_empty());
        assert_eq!(close.close, Some(CloseReason::Shutdown));

        root.cancel();
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[tokio::test]
    async fn terminal_delivery_failure_keeps_the_committed_intent_terminal()
    -> Result<(), RuntimeError> {
        let (port, inbox) = admin_transport_channel(binding());
        let (_lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
        let (core, mut core_inbox) = admin_core_channel();
        let (process, process_inbox) = admin_process_channel();
        drop(process_inbox);
        let root = CancellationToken::root();
        let owner = tokio::spawn(
            AdminOwner::new(
                binding(),
                all_permissions_registry()?,
                AdminAdmissionSnapshot::new(vec![1000], Vec::new(), Vec::new()),
                AuditAuthority::empty_for_test()?,
                core,
                AdminOwnerRuntime {
                    health: live_health(),
                    config: None,
                    reload: None,
                    backup: None,
                    process: Some(process),
                    fatal: None,
                    observer: None,
                    budget: Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 2)),
                    entropy: Box::new(
                        ScriptedEntropy::new(vec![0; 64])
                            .map_err(|_| RuntimeError::InvalidValue)?,
                    ),
                    clocks: AdminOwnerClocks {
                        monotonic: Box::new(SystemMonotonicClock::start()),
                        wall: Box::new(SystemWallClock),
                    },
                },
            )
            .run(inbox, lifecycle_inbox, root.clone()),
        );
        let (sender, mut output) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
        let generation = ConnectionGeneration::new(14);
        port.opened(
            generation,
            challenge(),
            PeerIdentity::Local {
                uid: 1000,
                gid: 1000,
            },
            AdminOutput::new(sender),
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        let _challenge = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        port.line(generation, oper_line()?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;

        let command = "DIE :terminal intent";
        port.line(generation, signed_line(0, command)?, &root)
            .await
            .map_err(|_| RuntimeError::InvalidValue)?;
        let revision =
            agenc_ircd_types::Revision::new(10).map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(
            core_inbox.complete_target_revision_for_test(revision).await,
            Some(AdminTarget::Process)
        );
        let _confirmation = output.recv().await.ok_or(RuntimeError::InvalidValue)?;
        let confirmation_token = ConfirmationToken::from_bytes([0; 16]);
        port.line(
            generation,
            confirmed_line(1, command, &confirmation_token)?,
            &root,
        )
        .await
        .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(
            core_inbox.complete_target_revision_for_test(revision).await,
            Some(AdminTarget::Process)
        );
        let intent = core_inbox
            .complete_next_for_test(Ok(()))
            .await
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(intent.tbs().phase, AdminAuditPhase::Intent);

        let second_audit = tokio::time::timeout(
            Duration::from_millis(100),
            core_inbox.complete_next_for_test(Ok(())),
        )
        .await;
        assert!(
            second_audit.is_err(),
            "terminal intent gained an outcome event"
        );
        let close = tokio::time::timeout(Duration::from_secs(1), output.recv())
            .await
            .map_err(|_| RuntimeError::Cancelled)?
            .ok_or(RuntimeError::InvalidValue)?;
        assert!(close.lines.is_empty());
        assert_eq!(close.close, Some(CloseReason::ProtocolError));

        root.cancel();
        owner.await.map_err(|_| RuntimeError::Cancelled)?;
        Ok(())
    }

    #[test]
    fn audit_phase_contract_is_exhaustive_for_every_command_variant() -> Result<(), RuntimeError> {
        const USER: &str = "AAAAAAAAAAAAAAAAAAAAAA";
        const ACCOUNT: &str = "a_AAAAAAAAAAAAAAAAAAAAAA";
        let observed = vec![AdminAuditPhase::Observed];
        let external = vec![
            AdminAuditPhase::Intent,
            AdminAuditPhase::OutcomeSuccess,
            AdminAuditPhase::OutcomeFailure,
        ];
        let mutation = vec![AdminAuditPhase::CommittedMutation];
        let terminal = vec![AdminAuditPhase::Intent];
        let cases = [
            ("PING token".to_owned(), Vec::new()),
            ("PONG token".to_owned(), Vec::new()),
            ("QUIT".to_owned(), Vec::new()),
            ("MOTD".to_owned(), observed.clone()),
            ("VERSION".to_owned(), observed.clone()),
            ("TIME".to_owned(), observed.clone()),
            ("INFO".to_owned(), observed.clone()),
            ("LINKS".to_owned(), observed.clone()),
            ("STATS RUNTIME".to_owned(), observed.clone()),
            ("REHASH :reload now".to_owned(), external.clone()),
            (format!("KILL {USER} :policy action"), external.clone()),
            (
                format!("ACCOUNT SUSPEND {ACCOUNT} 60 :policy action"),
                mutation.clone(),
            ),
            (
                format!("ACCOUNT RESTORE {ACCOUNT} :policy action"),
                mutation.clone(),
            ),
            (
                format!("CHANNEL QUARANTINE {USER} :policy action"),
                mutation,
            ),
            (format!("CONNECT {USER} :policy action"), external.clone()),
            (format!("SQUIT {USER} :policy action"), external.clone()),
            (
                format!("PEER QUARANTINE {USER} :policy action"),
                external.clone(),
            ),
            ("BACKUP CREATE :policy action".to_owned(), external),
            ("AUDIT EXPORT 0 10".to_owned(), observed.clone()),
            ("AUDIT EXPORT 0 10 maintenance-v1".to_owned(), observed),
            ("RESTART :policy action".to_owned(), terminal.clone()),
            ("DIE :policy action".to_owned(), terminal),
        ];
        let phases = [
            AdminAuditPhase::CommittedMutation,
            AdminAuditPhase::Intent,
            AdminAuditPhase::OutcomeSuccess,
            AdminAuditPhase::OutcomeFailure,
            AdminAuditPhase::Observed,
        ];

        for (line, allowed) in cases {
            let canonical = agenc_ircd_admin::CanonicalCommand::check(line.as_bytes())
                .map_err(|_| RuntimeError::InvalidValue)?;
            let command = AdminCommand::parse(canonical).map_err(|_| RuntimeError::InvalidValue)?;
            for phase in phases {
                assert_eq!(
                    audit_phase_is_valid(&command, phase),
                    allowed.contains(&phase),
                    "{line} accepted the wrong audit phase {phase:?}"
                );
            }
        }
        Ok(())
    }

    fn export_memory() -> Result<MemoryPermitBatch, RuntimeError> {
        let budget = MemoryBudget::new(4_096);
        budget
            .try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(1)])?)
            .map_err(Into::into)
    }

    #[test]
    fn audit_export_memory_holds_frozen_and_rendered_peaks() -> Result<(), RuntimeError> {
        let one_peak = MemoryCharge::allocation(MAX_AUDIT_EXPORT_BYTES)?.bytes();
        let two_peaks = one_peak.checked_mul(2).ok_or(RuntimeError::Overflow)?;
        let budget = MemoryBudget::new(two_peaks);
        let permit = acquire_audit_export_memory(&budget)?;
        assert_eq!(budget.charged(), two_peaks);
        drop(permit);
        assert_eq!(budget.charged(), 0);

        let undersized = MemoryBudget::new(two_peaks.saturating_sub(1));
        assert!(acquire_audit_export_memory(&undersized).is_err());
        Ok(())
    }

    #[test]
    fn bounded_admin_outputs_reject_every_invalid_line_and_queue_state() -> Result<(), RuntimeError>
    {
        assert!(matches!(
            AdminWrite::ordinary(vec!["x".to_owned(); MAX_ORDINARY_BATCH_LINES + 1], None),
            Err(CloseReason::Overload)
        ));
        for invalid in [
            String::new(),
            "x".repeat(MAX_ADMIN_OUTPUT_LINE_BYTES + 1),
            "embedded\rreturn".to_owned(),
            "embedded\nline".to_owned(),
        ] {
            assert!(matches!(
                AdminWrite::ordinary(vec![invalid.clone()], None),
                Err(CloseReason::ProtocolError)
            ));
            assert!(matches!(
                AdminWrite::export(vec![invalid], export_memory()?),
                Err(CloseReason::ProtocolError)
            ));
        }
        assert!(AdminWrite::ordinary(Vec::new(), None).is_ok());
        assert!(AdminWrite::export(vec!["bounded".to_owned()], export_memory()?).is_ok());
        assert!(matches!(
            AdminWrite::export_bounded(vec!["record".to_owned(); 4], export_memory()?, 1, u64::MAX,),
            Err(CloseReason::Overload)
        ));
        assert!(matches!(
            AdminWrite::export_bounded(vec!["four".to_owned()], export_memory()?, 1, 5),
            Err(CloseReason::Overload)
        ));
        assert!(
            AdminWrite::export_bounded(vec!["four".to_owned()], export_memory()?, 1, 6).is_ok()
        );

        let (sender, mut receiver) = mpsc::channel(1);
        let output = AdminOutput::new(sender);
        output
            .try_line("first".to_owned())
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(
            output.try_line("second".to_owned()),
            Err(CloseReason::SlowConsumer)
        );
        let _first = receiver
            .try_recv()
            .map_err(|_| RuntimeError::InvalidValue)?;
        drop(receiver);
        assert_eq!(
            output.try_line("closed".to_owned()),
            Err(CloseReason::TransportLoss)
        );
        assert_eq!(
            output.try_export(
                AdminWrite::export(vec!["closed".to_owned()], export_memory()?)
                    .map_err(|_| RuntimeError::InvalidValue)?,
            ),
            Err(CloseReason::TransportLoss)
        );
        Ok(())
    }

    #[test]
    fn admission_and_process_ports_cover_uid_gid_pin_full_and_closed() -> Result<(), RuntimeError> {
        let pin = [3; 32];
        let admission =
            AdminAdmissionSnapshot::new(vec![20, 10, 20], vec![40, 30, 40], vec![pin, pin]);
        assert!(admission.admits(PeerIdentity::Local { uid: 10, gid: 0 }));
        assert!(admission.admits(PeerIdentity::Local { uid: 0, gid: 30 }));
        assert!(!admission.admits(PeerIdentity::Local { uid: 1, gid: 2 }));
        assert!(admission.admits(PeerIdentity::Pin(pin)));
        assert!(!admission.admits(PeerIdentity::Pin([4; 32])));

        let (process, mut inbox) = admin_process_channel();
        assert!(process.request(AdminProcessAction::Die).is_ok());
        assert_eq!(
            process.request(AdminProcessAction::Restart),
            Err(AdminCoreFailure::Busy)
        );
        assert_eq!(inbox.receiver.try_recv(), Ok(AdminProcessAction::Die));
        drop(inbox);
        assert_eq!(
            process.request(AdminProcessAction::Restart),
            Err(AdminCoreFailure::StorageUnavailable)
        );

        let (transport, _inbox) = admin_transport_channel(binding());
        assert_eq!(transport.binding(), binding());
        Ok(())
    }

    #[tokio::test]
    async fn lifecycle_control_rejects_wrong_outcomes_and_lost_replies() {
        let (sender, mut receiver) = mpsc::channel(ADMIN_LIFECYCLE_CAPACITY);
        let control = AdminLifecycleControl { sender };
        let responder = tokio::spawn(async move {
            let outcomes = [
                AdminLifecycleOutcome::Draining(Vec::new()),
                AdminLifecycleOutcome::Complete,
                AdminLifecycleOutcome::Draining(Vec::new()),
                AdminLifecycleOutcome::Draining(Vec::new()),
            ];
            for outcome in outcomes {
                if let Some(request) = receiver.recv().await {
                    let _sent = request.reply.send(Ok(outcome));
                }
            }
        });
        assert_eq!(
            control.quiesce().await,
            Err(AdminLifecycleFailure::Unavailable)
        );
        assert!(matches!(
            control.drain().await,
            Err(AdminLifecycleFailure::Unavailable)
        ));
        assert_eq!(
            control.flush().await,
            Err(AdminLifecycleFailure::Unavailable)
        );
        assert_eq!(
            control.stop().await,
            Err(AdminLifecycleFailure::Unavailable)
        );
        let _joined = responder.await;

        let (sender, mut receiver) = mpsc::channel(1);
        let control = AdminLifecycleControl { sender };
        let responder = tokio::spawn(async move {
            if let Some(request) = receiver.recv().await {
                drop(request.reply);
            }
        });
        assert_eq!(
            control.quiesce().await,
            Err(AdminLifecycleFailure::Unavailable)
        );
        let _joined = responder.await;

        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let control = AdminLifecycleControl { sender };
        assert_eq!(
            control.stop().await,
            Err(AdminLifecycleFailure::Unavailable)
        );
    }

    #[tokio::test]
    async fn admin_transport_and_io_cover_shutdown_eof_and_partial_frames()
    -> Result<(), RuntimeError> {
        let root = CancellationToken::root();
        let (port, inbox) = admin_transport_channel(binding());
        drop(inbox);
        assert_eq!(
            port.opened(
                ConnectionGeneration::new(30),
                challenge(),
                PeerIdentity::Local { uid: 1, gid: 1 },
                AdminOutput::new(mpsc::channel(1).0),
                &root,
            )
            .await,
            Err(CloseReason::Shutdown)
        );

        let cancelled = CancellationToken::root();
        cancelled.cancel();
        let (port, _inbox) = admin_transport_channel(binding());
        for generation in 0..ADMIN_OWNER_CAPACITY {
            port.sender
                .try_send(AdminOwnerMessage::Closed {
                    generation: ConnectionGeneration::new(generation as u64),
                    reason: CloseReason::TransportLoss,
                })
                .map_err(|_| RuntimeError::InvalidValue)?;
        }
        assert_eq!(
            port.line(
                ConnectionGeneration::new(31),
                b"PING x\r\n".to_vec(),
                &cancelled,
            )
            .await,
            Err(CloseReason::Shutdown)
        );

        let (port, mut inbox) = admin_transport_channel(binding());
        assert_eq!(
            run_admin_reader(
                &b"PING x\r\n"[..],
                ConnectionGeneration::new(32),
                port,
                CancellationToken::root(),
            )
            .await,
            CloseReason::TransportLoss
        );
        assert!(matches!(
            inbox.receiver.try_recv(),
            Ok(AdminOwnerMessage::Line { generation, line })
                if generation == ConnectionGeneration::new(32) && line == b"PING x\r\n"
        ));

        let (port, _inbox) = admin_transport_channel(binding());
        assert_eq!(
            run_admin_reader(
                &b"PING partial"[..],
                ConnectionGeneration::new(33),
                port,
                CancellationToken::root(),
            )
            .await,
            CloseReason::ProtocolError
        );

        let (transport, _peer) = tokio::io::duplex(64);
        let (sender, receiver) = mpsc::channel(1);
        drop(sender);
        assert_eq!(
            run_admin_writer(
                transport,
                receiver,
                CancellationToken::root(),
                FlushAcknowledgement::pending(),
            )
            .await,
            CloseReason::TransportLoss
        );

        let (transport, _peer) = tokio::io::duplex(64);
        let (_sender, receiver) = mpsc::channel(1);
        let token = CancellationToken::root();
        token.cancel();
        assert_eq!(
            run_admin_writer(transport, receiver, token, FlushAcknowledgement::pending(),).await,
            CloseReason::Shutdown
        );
        Ok(())
    }

    #[test]
    fn backup_failure_mapping_is_closed_over_every_storage_error() {
        for error in [StorageError::QueueFull, StorageError::AllocationFailed] {
            assert_eq!(map_backup_failure(error), AdminCoreFailure::Busy);
        }
        for error in [
            StorageError::InvalidEncoding,
            StorageError::UnsupportedVersion,
            StorageError::LimitExceeded,
            StorageError::Overflow,
            StorageError::AuthenticationFailed,
            StorageError::StaleState,
            StorageError::Unavailable,
            StorageError::FilesystemRejected,
            StorageError::WriterLocked,
            StorageError::DatabaseRejected,
            StorageError::UnsupportedMigration,
            StorageError::ResumeMismatch,
        ] {
            assert_eq!(
                map_backup_failure(error),
                AdminCoreFailure::StorageUnavailable
            );
        }
    }

    #[test]
    fn admin_output_classification_uses_only_closed_final_result_codes() {
        assert_eq!(
            classify_admin_output(&["NOTE REHASH OK :Configuration reloaded".to_owned()]),
            ResultClass::Ok
        );
        assert_eq!(
            classify_admin_output(&["FAIL REHASH BUSY :Administrative action busy".to_owned()]),
            ResultClass::Busy
        );
        assert_eq!(
            classify_admin_output(&[
                "FAIL REHASH STORAGE_UNAVAILABLE :Administrative reload unavailable".to_owned(),
            ]),
            ResultClass::Error
        );
        assert_eq!(
            classify_admin_output(&[
                "FAIL REHASH INVALID_CONFIG :Configuration rejected".to_owned(),
            ]),
            ResultClass::Rejected
        );
    }
}
