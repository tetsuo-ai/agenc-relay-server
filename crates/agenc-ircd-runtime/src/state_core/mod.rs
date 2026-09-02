//! The single state owner and its inbound message contract (spec 21.1,
//! lines 3970-4002; spec 21.4-21.5, lines 4119-4215).
//!
//! `StateCore` is one actor that owns every mutable protocol datum: the
//! domain state, the session table, the rate buckets, the timer heap, the
//! durable before-image index, and the one pending mutation batch. It
//! consumes the bounded inbox, the sole storage completion receiver, the
//! crypto completion receiver, and its own timers. Command handling is
//! delegated to a [`CommandRouter`] so registration, channel, and admin
//! composition plug in without touching the loop or the durable path.

mod admin;
pub mod durable;
pub mod fanout;
pub mod inbox;
mod pending;
pub mod reconstruct;
pub mod session;
pub mod timers;

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use agenc_ircd_client_wire::{ParsedMessage, WireMessage, numeric_reply};
use agenc_ircd_crypto::OpenedStoragePlaintext;
use agenc_ircd_domain::{
    ApplyReceipt, DomainError, DomainState, MutationPlan, OperationalLimits, OperationalUsage,
};
use agenc_ircd_storage::{
    CheckpointOutcome, CheckpointReceipt, CommitOutcome, ExistingRecord, ReadPlan, SealedRecord,
    StorageError, StorageLimitWriter, StorageMutationBatch, StoredKey, TableId,
};
use agenc_ircd_types::{
    ClockError, EntropySource, MonotonicClock, MonotonicTick, Revision, TransactionId, UserId,
    UtcSecond, WallClock,
};
use tokio::sync::mpsc;
use tokio::time::Instant;

pub(crate) use admin::{
    AdminCoreFailure, AdminCoreInbox, AdminCorePort, AdminCoreSnapshot, AdminMutation, AdminTarget,
    admin_core_channel,
};
pub use pending::{GATHER_WINDOW_MILLIS, MAX_BATCH_PLANS, StagedOrigin};

use crate::RuntimeError;
use crate::admission::{
    BucketKey, BucketTable, OverloadClass, OverloadState, PrefixRegistry, RateLimits,
};
use crate::bridge::crypto::{CryptoBridge, CryptoJobOutput};
use crate::bridge::storage::{BridgeFailure, STORAGE_HANDOFF_CAPACITY, StorageBridge, SubmitError};
use crate::bridge::{
    CryptoCompletionMessage, StorageCheckpointCompletionMessage, StorageCheckpointId,
    StorageCompletionMessage, StorageReadCompletionMessage, StorageReadId,
};
use crate::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge, MemoryPermitBatch,
};
use crate::cancel::CancellationToken;
use crate::connection::sink::QuerySnapshotPermit;
use crate::connection::{ConnectionGeneration, FlushAcknowledgement};
use crate::observe::adapter::RuntimeObserver;
use crate::observe::health::Liveness;
use crate::observe::metrics::{CommandClass, QueueName, ResultClass};
use crate::runtime_config::{
    AuditedReloadResult, AuditedReloadStart, PreparedReload, ReloadActivation, ReloadCoreInbox,
    ReloadCoreRequest, ReloadOutcome, ReloadRejection, RuntimeConfigHandle, RuntimeConfigSnapshot,
    RuntimeResourceLimits,
};
use crate::state_core::admin::{AdminCoreRequest, AdminCoreResult};
use crate::state_core::durable::{
    AccountServiceDurableWrite, AccountingCeilings, AdminMutationAfterImage, DurableIndex,
    HeadCounters, KeyDeriver, PlanProjection, RetainedProjection, project_admin_audit_event,
    project_admin_audit_retention, project_admin_mutation_event, project_batch, read_back_record,
};
use crate::state_core::fanout::{
    FanoutCommitReport, FanoutFrame, FanoutRefused, FanoutRequest, FanoutReservation, FanoutTarget,
    reserve_bounded, reserve_query,
};
use crate::state_core::inbox::{
    CloseReason, ConnectionCloseInbox, ConnectionOpenOutcome, LifecycleFailure, LifecyclePhase,
    LifecycleRequest, LifecycleResult, MaintenanceEvent, PhysicalCloseNotice, SignalEvent,
    SourceAddressKey, StateCoreMessage,
};
use crate::state_core::pending::{PendingMutationBatch, StagedPlan};
use crate::state_core::reconstruct::Reconstruction;
use crate::state_core::session::SessionTable;
use crate::state_core::timers::{DriftMonitor, DriftTransition, TimerEntry, TimerHeap};
use crate::sync::Arc;

/// The numeric a registered session receives for an unknown command.
const ERR_UNKNOWNCOMMAND: u16 = 421;
/// The numeric an unregistered connection receives for a post-registration
/// command.
const ERR_NOTREGISTERED: u16 = 451;
/// Owner progress cadence used by authenticated liveness.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);
/// Retry cadence after a bounded storage queue temporarily refuses index
/// readback without producing a StateCore completion wake.
const INDEX_REFRESH_RETRY_INTERVAL: Duration = Duration::from_millis(10);
/// Bounded cadence used only while orderly connection flushes are pending.
const SHUTDOWN_FLUSH_POLL: Duration = Duration::from_millis(10);

/// Fixed configuration the state owner runs with.
pub struct StateCoreConfig {
    /// The server prefix used on every rendered frame.
    pub server_prefix: String,
    /// The configured rate rows (spec 19.1).
    pub rate_limits: RateLimits,
    /// The configured storage ceilings.
    pub ceilings: AccountingCeilings,
    /// Content-loaded public message of the day.
    pub motd: Option<Arc<str>>,
    /// Content-loaded public ADMIN/INFO text.
    pub public_info: Option<Arc<str>>,
}

/// The explicit clocks StateCore consults (spec 24.2, line 6549).
pub struct StateCoreClocks {
    /// Monotonic ticks for every duration and deadline.
    pub monotonic: Box<dyn MonotonicClock + Send>,
    /// Wall time only for displayed and durable timestamps.
    pub wall: Box<dyn WallClock + Send>,
}

/// Everything a state owner is built from.
pub struct StateCoreInputs {
    /// Fixed configuration.
    pub config: StateCoreConfig,
    /// The reconstructed domain state, index, and head counters.
    pub reconstruction: Reconstruction,
    /// The key deriver bound to the open database.
    pub keys: KeyDeriver,
    /// The storage bridge; its completion receiver is passed to `run`.
    pub bridge: StorageBridge,
    /// The crypto bridge; its completion receiver is passed to `run`.
    pub crypto: CryptoBridge,
    /// The process-wide memory budget.
    pub budget: Arc<MemoryBudget>,
    /// Process-wide progress counters shared with authenticated health.
    pub liveness: Arc<Liveness>,
    /// The explicit clocks.
    pub clocks: StateCoreClocks,
    /// The entropy source for identities and keys.
    pub entropy: Box<dyn EntropySource + Send>,
    /// The command router.
    pub router: Box<dyn CommandRouter>,
    /// The sole writer for storage ceilings applied at reload safe points.
    pub storage_limit_writer: StorageLimitWriter,
}

/// What a router asks the loop to do after handling one line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteOutcome {
    /// Keep serving the connection.
    Continue,
    /// Close the connection for the given reason.
    Close(CloseReason),
}

/// Input-free observation ownership for exactly one client command.
#[must_use = "a command observation must be completed or transferred to pending work"]
pub struct CommandObservation {
    class: CommandClass,
}

impl CommandObservation {
    const fn new(class: CommandClass) -> Self {
        Self { class }
    }
}

/// The command boundary composition stages plug into.
///
/// Every method receives the state owner's context; the loop itself never
/// interprets a command. Default hooks do nothing so a router only
/// implements what it owns.
pub trait CommandRouter: Send {
    /// Starts fail-closed work reconstructed before the live loop accepts
    /// command authority.
    fn startup(&mut self, _context: &mut StateCoreContext) {}

    /// Handles one parsed line from an admitted connection.
    fn route(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: ParsedMessage,
        observation: CommandObservation,
    ) -> RouteOutcome;

    /// A connection was admitted and recorded.
    fn connection_opened(
        &mut self,
        _context: &mut StateCoreContext,
        _generation: ConnectionGeneration,
    ) {
    }

    /// A connection left and was removed.
    fn connection_closed(
        &mut self,
        _context: &mut StateCoreContext,
        _generation: ConnectionGeneration,
        _reason: CloseReason,
    ) {
    }

    /// A crypto job completed.
    fn crypto_completed(
        &mut self,
        _context: &mut StateCoreContext,
        _message: CryptoCompletionMessage<CryptoJobOutput>,
    ) {
    }

    /// A bounded storage read completed.
    fn storage_read_completed(
        &mut self,
        _context: &mut StateCoreContext,
        _message: StorageReadCompletionMessage,
    ) {
    }

    /// A timer became due.
    fn timer_fired(&mut self, _context: &mut StateCoreContext, _entry: TimerEntry) {}

    /// A staged plan's batch was rejected before anything irreversible began.
    fn batch_rejected(
        &mut self,
        _context: &mut StateCoreContext,
        _origin: Option<StagedOrigin>,
        _error: StorageError,
    ) {
    }

    /// One or more staged plans became visible after their complete durable
    /// barrier. Routers use this only to retry work that was deferred behind
    /// the single in-flight batch.
    fn batch_applied(&mut self, _context: &mut StateCoreContext, _plan_count: usize) {}

    /// A reload signal arrived.
    fn reload_requested(&mut self, _context: &mut StateCoreContext) {}

    /// Applies already prepared router policy at the same safe point as the
    /// StateCore-owned ceilings. Implementations must not allocate or await.
    fn config_reloaded(
        &mut self,
        _context: &mut StateCoreContext,
        _snapshot: &RuntimeConfigSnapshot,
    ) {
    }

    /// Whether no router-owned asynchronous operation straddles a reload.
    fn reload_ready(&self) -> bool {
        true
    }

    /// A maintenance tick the loop does not consume itself.
    fn maintenance(&mut self, _context: &mut StateCoreContext, _event: MaintenanceEvent) {}
}

/// The router installed before composition: every line is unknown.
pub struct DefaultRouter;

impl CommandRouter for DefaultRouter {
    fn route(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: ParsedMessage,
        observation: CommandObservation,
    ) -> RouteOutcome {
        let registered = context
            .sessions()
            .connection(generation)
            .is_some_and(|entry| entry.session().is_some());
        let reply = if registered {
            numeric_reply(
                context.server_prefix(),
                ERR_UNKNOWNCOMMAND,
                "*",
                &[message.command()],
                Some("Unknown command"),
            )
        } else {
            numeric_reply(
                context.server_prefix(),
                ERR_NOTREGISTERED,
                "*",
                &[],
                Some("You have not registered"),
            )
        };
        let result = match reply {
            Ok(frame) => {
                if context.send_to(generation, vec![frame]).is_ok() {
                    ResultClass::Rejected
                } else {
                    ResultClass::Busy
                }
            }
            Err(_) => ResultClass::Error,
        };
        context.complete_command_observation(observation, result);
        RouteOutcome::Continue
    }
}

/// Why the state owner stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateCoreExit {
    /// The owning token was cancelled.
    Cancelled,
    /// Every inbox sender was dropped.
    InboxClosed,
    /// A termination signal arrived and no batch was in flight.
    Quiesced,
    /// A second termination signal skipped to the stop phase.
    Interrupted,
    /// The lifecycle driver completed the ordered stop request.
    Stopped,
    /// Durable state may or may not have changed; the supervisor restarts
    /// into offline recovery (spec lines 4188-4194 and 4207-4210).
    Indeterminate(IndeterminateCause),
    /// Applying an already committed plan failed; the process terminates
    /// and startup reconstructs authoritative state (spec lines 4138-4140).
    Corrupt(CorruptionCause),
}

/// The exact reason a durable outcome is unknowable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndeterminateCause {
    /// The storage owner reported `Indeterminate`.
    StorageIndeterminate,
    /// The receipt named a different transaction than the one in flight.
    TransactionMismatch,
    /// A receipt arrived while nothing was in flight.
    UnexpectedCompletion,
    /// The completion channel closed while a batch was pending.
    CompletionChannelClosed,
    /// The bridge refused or failed.
    Bridge(BridgeFailure),
}

/// The exact reason committed state could not be applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorruptionCause {
    /// `apply_prepared` failed after the storage owner committed.
    ApplyFailed,
    /// The committed rows could not be read back into the index.
    IndexRefreshFailed,
    /// A plan projection failed for a reason other than a storage ceiling.
    ProjectionFailed,
    /// A physical close named a generation StateCore had not admitted.
    ConnectionStateFailed,
}

impl fmt::Display for StateCoreExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("state core cancelled"),
            Self::InboxClosed => formatter.write_str("state core inbox closed"),
            Self::Quiesced => formatter.write_str("state core quiesced"),
            Self::Interrupted => formatter.write_str("state core interrupted"),
            Self::Stopped => formatter.write_str("state core stopped"),
            Self::Indeterminate(_) => {
                formatter.write_str("state core durable outcome indeterminate")
            }
            Self::Corrupt(_) => formatter.write_str("state core committed state unusable"),
        }
    }
}

/// Bounded counters the admin owner reads.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StateCoreCounters {
    /// Lines handed to the router.
    pub lines_routed: u64,
    /// Lines dropped because their connection was unknown.
    pub lines_dropped: u64,
    /// Connections recorded.
    pub connections_opened: u64,
    /// Connections removed.
    pub connections_closed: u64,
    /// Batches the storage owner committed.
    pub batches_committed: u64,
    /// Batches rejected before anything irreversible began.
    pub batches_rejected: u64,
    /// Plans applied to the domain state.
    pub plans_applied: u64,
    /// Fanouts refused before any state changed.
    pub fanout_refusals: u64,
    /// Timers handed to the router.
    pub timers_fired: u64,
    /// Maintenance events consumed.
    pub maintenance_events: u64,
}

/// Why a durable plan could not be staged; nothing changed.
#[derive(Debug)]
pub enum StageRefused {
    /// The fanout could not be represented.
    Fanout(FanoutRefused),
    /// A batch is already in flight or gathering; re-plan after it resolves.
    Busy,
    /// The owner is quiescing and accepts no new mutation (spec line 4258).
    Quiescing,
    /// An empty-projection plan failed to prepare or apply.
    Domain(DomainError),
}

/// How a staged plan was accepted.
pub enum StageAccepted {
    /// The plan waits on the storage receipt.
    Staged {
        /// Plans now in the pending batch.
        plans_in_batch: usize,
    },
    /// The plan produced no persisted delta and was applied in this step.
    AppliedInStep(Box<ApplyReceipt>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DurableAdmission {
    Ordinary,
    ShutdownSessionClose,
}

/// Why an ephemeral plan could not be applied; nothing changed.
#[derive(Debug)]
pub enum EphemeralRefused {
    /// The fanout could not be represented.
    Fanout(FanoutRefused),
    /// The plan failed to prepare or apply.
    Domain(DomainError),
}

/// One rejected staged plan, reported to the router.
pub struct Rejection {
    origin: Option<StagedOrigin>,
    error: StorageError,
}

/// The result of driving one pending batch forward.
pub enum BatchStep {
    /// Nothing was due.
    Idle,
    /// The batch was handed to storage.
    Submitted,
    /// No plan projected a persisted delta; all were applied in step.
    AppliedInStep(usize),
    /// The batch was rejected; the router renders the bounded failures.
    Rejected(Vec<Rejection>),
}

/// Everything the loop and the router share.
pub struct StateCoreContext {
    domain: DomainState,
    sessions: SessionTable,
    buckets: BucketTable,
    prefixes: PrefixRegistry,
    timers: TimerHeap,
    drift: DriftMonitor,
    pending: Option<PendingMutationBatch>,
    index: DurableIndex,
    keys: KeyDeriver,
    head: HeadCounters,
    ceilings: AccountingCeilings,
    overload: OverloadState,
    budget: Arc<MemoryBudget>,
    runtime_resource_limits: RuntimeResourceLimits,
    bridge: StorageBridge,
    crypto: CryptoBridge,
    entropy: Box<dyn EntropySource + Send>,
    monotonic: Box<dyn MonotonicClock + Send>,
    wall: Box<dyn WallClock + Send>,
    server_prefix: String,
    motd: Option<Arc<str>>,
    public_info: Option<Arc<str>>,
    counters: StateCoreCounters,
    quiescing: bool,
    observer: Option<Arc<RuntimeObserver>>,
}

/// A side-effect-free query allocation reservation sealed only after the
/// immutable projection reports its exact row count and requested backing.
pub(crate) struct PreparedQuerySnapshot {
    max_rows: u64,
    max_backing_capacity: u64,
    permits: MemoryPermitBatch,
}

impl PreparedQuerySnapshot {
    pub(crate) fn finish(
        mut self,
        rows: usize,
        backing_capacity: usize,
    ) -> Result<QuerySnapshotPermit, RuntimeError> {
        let rows = u64::try_from(rows).map_err(|_| RuntimeError::Overflow)?;
        let backing_capacity =
            u64::try_from(backing_capacity).map_err(|_| RuntimeError::Overflow)?;
        if rows > self.max_rows || backing_capacity > self.max_backing_capacity {
            return Err(RuntimeError::LimitExceeded);
        }
        let charge = MemoryCharge::allocation(backing_capacity)?;
        let permit = self
            .permits
            .split_exact(charge.bytes())
            .ok_or(RuntimeError::InvalidValue)?;
        Ok(QuerySnapshotPermit::new(rows, permit))
    }
}

impl StateCoreContext {
    fn begin_command_observation(&self, command: &str) -> CommandObservation {
        let class = RuntimeObserver::classify_command(command);
        if class == CommandClass::Authentication
            && let Some(observer) = &self.observer
        {
            observer.authentication(false);
        }
        CommandObservation::new(class)
    }

    pub(crate) fn complete_command_observation(
        &self,
        observation: CommandObservation,
        result: ResultClass,
    ) {
        let Some(observer) = &self.observer else {
            return;
        };
        observer.command_classified(observation.class, result);
        if observation.class == CommandClass::Authentication && result != ResultClass::Ok {
            observer.authentication(true);
        }
    }

    /// Borrows the committed domain state.
    #[must_use]
    pub const fn domain(&self) -> &DomainState {
        &self.domain
    }

    /// Borrows the session table.
    #[must_use]
    pub const fn sessions(&self) -> &SessionTable {
        &self.sessions
    }

    /// Mutably borrows the session table for registration composition.
    pub const fn sessions_mut(&mut self) -> &mut SessionTable {
        &mut self.sessions
    }

    /// Mutably borrows the rate buckets.
    pub const fn buckets_mut(&mut self) -> &mut BucketTable {
        &mut self.buckets
    }

    /// Mutably borrows the timer heap.
    pub const fn timers_mut(&mut self) -> &mut TimerHeap {
        &mut self.timers
    }

    /// Mutably borrows the bounded crypto submission bridge.
    pub const fn crypto_mut(&mut self) -> &mut CryptoBridge {
        &mut self.crypto
    }

    /// Submits one bounded live read through the storage owner without
    /// blocking the state actor.
    pub fn submit_storage_read(&mut self, plan: ReadPlan) -> Result<StorageReadId, StorageError> {
        self.bridge.submit_read(plan)
    }

    /// Authenticates one asynchronously read row under the active database
    /// binding before an owning record codec sees its plaintext.
    pub(crate) fn open_storage_plaintext(
        &self,
        table: TableId,
        key: &StoredKey,
        sealed_record: &[u8],
    ) -> Result<OpenedStoragePlaintext, RuntimeError> {
        let sealed = SealedRecord::decode(sealed_record)?;
        self.keys.open(table, key, &sealed)
    }

    /// Borrows the drift monitor.
    #[must_use]
    pub const fn drift(&self) -> &DriftMonitor {
        &self.drift
    }

    /// Mutably borrows the entropy source.
    pub fn entropy_mut(&mut self) -> &mut dyn EntropySource {
        self.entropy.as_mut()
    }

    /// Returns the current monotonic tick.
    #[must_use]
    pub fn now(&self) -> MonotonicTick {
        self.monotonic.now()
    }

    /// Reads the wall clock.
    pub fn utc_now(&self) -> Result<UtcSecond, ClockError> {
        self.wall.utc_now()
    }

    /// Returns the server prefix for rendering.
    #[must_use]
    pub fn server_prefix(&self) -> &str {
        &self.server_prefix
    }

    /// Borrows the published public MOTD content.
    #[must_use]
    pub fn motd(&self) -> Option<&str> {
        self.motd.as_deref()
    }

    /// Borrows the published public ADMIN/INFO content.
    #[must_use]
    pub fn public_info(&self) -> Option<&str> {
        self.public_info.as_deref()
    }

    /// Returns the head counters the next batch is fenced against.
    #[must_use]
    pub const fn head(&self) -> HeadCounters {
        self.head
    }

    /// Returns the counters.
    #[must_use]
    pub const fn counters(&self) -> StateCoreCounters {
        self.counters
    }

    /// Returns the current overload class.
    #[must_use]
    pub const fn overload_class(&self) -> OverloadClass {
        self.overload.class()
    }

    /// Returns whether a batch is with storage.
    #[must_use]
    pub fn in_flight(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(PendingMutationBatch::in_flight)
    }

    /// Returns the number of plans in the pending batch.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.as_ref().map_or(0, PendingMutationBatch::len)
    }

    /// Returns whether a termination signal was received.
    #[must_use]
    pub const fn is_quiescing(&self) -> bool {
        self.quiescing
    }

    /// Borrows the durable index.
    #[must_use]
    pub const fn index(&self) -> &DurableIndex {
        &self.index
    }

    /// Resolves registered users to their live sinks; users whose transport
    /// is gone are skipped.
    #[must_use]
    pub fn targets_for(&self, users: impl IntoIterator<Item = UserId>) -> Vec<FanoutTarget> {
        users
            .into_iter()
            .filter_map(|user| self.sessions.sink_for_user(user))
            .map(|(generation, sink)| FanoutTarget { generation, sink })
            .collect()
    }

    /// Delivers frames to one connection immediately (replies, notices).
    pub fn send_to(
        &mut self,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
    ) -> Result<FanoutCommitReport, FanoutRefused> {
        let request = self.fanout_request_to(generation, frames)?;
        self.fanout_now(request)
    }

    /// Reserves all live query ceilings and the maximum backing charge before
    /// the caller allocates its immutable projection.
    pub(crate) fn prepare_query_snapshot(
        &self,
        generation: ConnectionGeneration,
        max_rows: usize,
        max_backing_capacity: usize,
    ) -> Result<PreparedQuerySnapshot, RuntimeError> {
        let max_rows = u64::try_from(max_rows).map_err(|_| RuntimeError::Overflow)?;
        let max_backing_capacity =
            u64::try_from(max_backing_capacity).map_err(|_| RuntimeError::Overflow)?;
        let limits = self.runtime_resource_limits;
        let session = self
            .sessions
            .sink_for_generation(generation)
            .ok_or(RuntimeError::InvalidValue)?
            .queue_snapshot();
        let global = self.sessions.queue_snapshot();
        let charge = MemoryCharge::allocation(max_backing_capacity)?;
        if !limits.admits_query(session, global, max_rows, charge.bytes()) {
            return Err(RuntimeError::LimitExceeded);
        }
        let permits = self
            .budget
            .try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?;
        Ok(PreparedQuerySnapshot {
            max_rows,
            max_backing_capacity,
            permits,
        })
    }

    /// Sends a query response through the existing fanout path while moving
    /// its snapshot lease into the final queued frame.
    pub(crate) fn send_query_to(
        &mut self,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
        snapshot: QuerySnapshotPermit,
    ) -> Result<FanoutCommitReport, FanoutRefused> {
        let request = self.fanout_request_to(generation, frames)?;
        let reservation = self.reserve_query_fanout(&request, snapshot)?;
        Ok(self.commit_fanout(reservation))
    }

    /// Builds one generation-fenced fanout without making its frames visible.
    pub(crate) fn fanout_request_to(
        &self,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
    ) -> Result<FanoutRequest, FanoutRefused> {
        let sink = self
            .sessions
            .sink_for_generation(generation)
            .ok_or(FanoutRefused::Invalid(RuntimeError::InvalidValue))?;
        let mut fanout_frames = Vec::new();
        fanout_frames
            .try_reserve_exact(frames.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for frame in frames {
            fanout_frames.push(FanoutFrame::new(frame, vec![0])?);
        }
        Ok(FanoutRequest::new(
            vec![FanoutTarget { generation, sink }],
            fanout_frames,
        )?)
    }

    /// Reserves and commits a fanout with no plan behind it.
    pub fn fanout_now(
        &mut self,
        request: FanoutRequest,
    ) -> Result<FanoutCommitReport, FanoutRefused> {
        let reservation = self.reserve_fanout(&request)?;
        Ok(self.commit_fanout(reservation))
    }

    /// Applies an ephemeral plan after reserving its complete fanout.
    pub fn apply_ephemeral(
        &mut self,
        plan: MutationPlan,
        request: FanoutRequest,
    ) -> Result<ApplyReceipt, EphemeralRefused> {
        let reservation = self
            .reserve_fanout(&request)
            .map_err(EphemeralRefused::Fanout)?;
        let receipt = self.apply_plan(plan).map_err(EphemeralRefused::Domain)?;
        self.commit_fanout(reservation);
        Ok(receipt)
    }

    /// Stages a durable plan behind its complete fanout reservation.
    ///
    /// `response_count_increment` is the number of account-service response
    /// permits the plan consumes (spec lines 4026-4030).
    pub fn stage_durable(
        &mut self,
        plan: MutationPlan,
        request: FanoutRequest,
        origin: Option<StagedOrigin>,
        response_count_increment: u64,
    ) -> Result<StageAccepted, StageRefused> {
        self.stage_durable_with_account_service(
            plan,
            request,
            origin,
            response_count_increment,
            Vec::new(),
        )
    }

    /// Stages one account-service record set behind the same durable barrier
    /// as its domain transition and sealed response count.
    pub(crate) fn stage_durable_with_account_service(
        &mut self,
        plan: MutationPlan,
        request: FanoutRequest,
        origin: Option<StagedOrigin>,
        response_count_increment: u64,
        account_service_writes: Vec<AccountServiceDurableWrite>,
    ) -> Result<StageAccepted, StageRefused> {
        self.stage_durable_inner(
            plan,
            request,
            origin,
            response_count_increment,
            account_service_writes,
            DurableAdmission::Ordinary,
        )
    }

    /// Stages the one internal session-close transition emitted after an
    /// admitted transport ends during shutdown. Client and admin mutations
    /// continue to use the ordinary quiescence gate.
    pub(crate) fn stage_shutdown_session_close(
        &mut self,
        plan: MutationPlan,
        request: FanoutRequest,
    ) -> Result<StageAccepted, StageRefused> {
        let hidden_sessions = plan
            .events()
            .iter()
            .filter(|event| matches!(event, agenc_ircd_domain::DomainEvent::SessionHidden(_)))
            .count();
        if hidden_sessions != 1 {
            return Err(StageRefused::Domain(DomainError::InvariantViolation));
        }
        self.stage_durable_inner(
            plan,
            request,
            None,
            0,
            Vec::new(),
            DurableAdmission::ShutdownSessionClose,
        )
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-01 reason=one safe-point admission transaction owns validation fanout reservation batch joining and final command-observation transfer
    fn stage_durable_inner(
        &mut self,
        plan: MutationPlan,
        request: FanoutRequest,
        mut origin: Option<StagedOrigin>,
        response_count_increment: u64,
        account_service_writes: Vec<AccountServiceDurableWrite>,
        admission: DurableAdmission,
    ) -> Result<StageAccepted, StageRefused> {
        let Ok(account_service_writes) = account_service_writes
            .into_iter()
            .map(AccountServiceDurableWrite::revalidate)
            .collect::<Result<Vec<_>, _>>()
        else {
            self.complete_staged_origin(&mut origin, ResultClass::Error);
            return Err(StageRefused::Domain(DomainError::InvariantViolation));
        };
        if self.quiescing && admission == DurableAdmission::Ordinary {
            self.complete_staged_origin(&mut origin, ResultClass::Busy);
            return Err(StageRefused::Quiescing);
        }
        if self.in_flight() || self.conflicts(&plan) {
            self.complete_staged_origin(&mut origin, ResultClass::Busy);
            return Err(StageRefused::Busy);
        }
        let reservation = match self.reserve_fanout(&request) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.complete_staged_origin(&mut origin, ResultClass::Busy);
                return Err(StageRefused::Fanout(error));
            }
        };
        if plan.durable_writes().is_empty()
            && account_service_writes.is_empty()
            && self.pending.is_none()
        {
            let receipt = match self.apply_plan(plan) {
                Ok(receipt) => receipt,
                Err(error) => {
                    self.complete_staged_origin(
                        &mut origin,
                        if error == DomainError::ServerBusy {
                            ResultClass::Busy
                        } else {
                            ResultClass::Rejected
                        },
                    );
                    return Err(StageRefused::Domain(error));
                }
            };
            self.commit_fanout(reservation);
            self.complete_staged_origin(&mut origin, ResultClass::Ok);
            return Ok(StageAccepted::AppliedInStep(Box::new(receipt)));
        }
        let staged = StagedPlan::with_account_service_writes(
            plan,
            reservation,
            origin,
            response_count_increment,
            account_service_writes,
        );
        let now = self.now();
        match self.pending.take() {
            None => {
                self.pending = match PendingMutationBatch::start(staged, now) {
                    Ok(batch) => Some(batch),
                    Err((error, staged)) => {
                        let mut staged = *staged;
                        if let Some(observation) = staged.take_observation() {
                            self.complete_command_observation(observation, ResultClass::Error);
                        }
                        return Err(StageRefused::Fanout(FanoutRefused::Invalid(error)));
                    }
                };
            }
            Some(mut batch) => {
                let joined = match batch.try_stage(staged) {
                    Ok(()) => true,
                    Err((_refusal, staged)) => {
                        let mut staged = *staged;
                        if let Some(observation) = staged.take_observation() {
                            self.complete_command_observation(observation, ResultClass::Busy);
                        }
                        false
                    }
                };
                self.pending = Some(batch);
                if !joined {
                    return Err(StageRefused::Busy);
                }
            }
        }
        Ok(StageAccepted::Staged {
            plans_in_batch: self.pending_len(),
        })
    }

    fn complete_staged_origin(&self, origin: &mut Option<StagedOrigin>, result: ResultClass) {
        if let Some(observation) = origin.as_mut().and_then(StagedOrigin::take_observation) {
            self.complete_command_observation(observation, result);
        }
    }

    fn conflicts(&self, plan: &MutationPlan) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|batch| batch.conflicts_with(plan))
    }

    fn reserve_fanout(
        &mut self,
        request: &FanoutRequest,
    ) -> Result<FanoutReservation, FanoutRefused> {
        match reserve_bounded(
            request,
            self.budget.as_ref(),
            self.runtime_resource_limits.response_batch_bytes(),
        ) {
            Ok(reservation) => Ok(reservation),
            Err(refused) => {
                self.counters.fanout_refusals = self.counters.fanout_refusals.saturating_add(1);
                Err(refused)
            }
        }
    }

    fn reserve_query_fanout(
        &mut self,
        request: &FanoutRequest,
        snapshot: QuerySnapshotPermit,
    ) -> Result<FanoutReservation, FanoutRefused> {
        match reserve_query(
            request,
            self.budget.as_ref(),
            self.runtime_resource_limits.response_batch_bytes(),
            snapshot,
        ) {
            Ok(reservation) => Ok(reservation),
            Err(refused) => {
                self.counters.fanout_refusals = self.counters.fanout_refusals.saturating_add(1);
                Err(refused)
            }
        }
    }

    fn commit_fanout(&mut self, reservation: FanoutReservation) -> FanoutCommitReport {
        let report = reservation.commit();
        for generation in report.slow_consumer_generations() {
            self.sessions.mark_sink_gone(generation);
        }
        report
    }

    fn apply_plan(&mut self, plan: MutationPlan) -> Result<ApplyReceipt, DomainError> {
        let prepared = self.domain.prepare_mutation(plan)?;
        let receipt = self.domain.apply_prepared(prepared)?;
        self.counters.plans_applied = self.counters.plans_applied.saturating_add(1);
        Ok(receipt)
    }

    /// The next monotonic tick the loop must wake at.
    #[must_use]
    pub fn next_wake(&mut self) -> Option<MonotonicTick> {
        let timer = self.timers.next_deadline();
        let gather = self
            .pending
            .as_ref()
            .and_then(PendingMutationBatch::gather_deadline);
        let prefix = self.prefixes.next_erasure_deadline();
        [timer, gather, prefix].into_iter().flatten().min()
    }

    /// Submits the pending batch when its gather window closed.
    pub fn drive_batch(&mut self) -> Result<BatchStep, StateCoreExit> {
        let now = self.now();
        let due = self
            .pending
            .as_ref()
            .is_some_and(|batch| batch.gather_due(now));
        if !due {
            return Ok(BatchStep::Idle);
        }
        self.submit_batch()
    }

    /// Projects the gathering batch and hands it to storage.
    fn submit_batch(&mut self) -> Result<BatchStep, StateCoreExit> {
        let Some(batch) = self.pending.take() else {
            return Ok(BatchStep::Idle);
        };
        let Ok(transaction_id) = next_transaction_id(self.entropy.as_mut()) else {
            self.complete_batch_observations(batch, ResultClass::Error);
            return Err(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed));
        };
        let projections: Vec<PlanProjection<'_>> = batch
            .plans()
            .iter()
            .map(|staged| PlanProjection {
                plan: staged.plan(),
                response_count_increment: staged.response_count_increment(),
                account_service_writes: staged.account_service_writes(),
            })
            .collect();
        let projected = project_batch(
            transaction_id,
            &projections,
            &self.index,
            &self.keys,
            self.head,
            self.ceilings,
            self.entropy.as_mut(),
        );
        match projected {
            Ok(Some(projected)) => self.submit_projected(batch, projected),
            Ok(None) => self.apply_batch_in_step(batch),
            Err(RuntimeError::Storage(error @ StorageError::LimitExceeded)) => {
                Ok(BatchStep::Rejected(self.reject_batch(batch, error)))
            }
            Err(_) => {
                self.complete_batch_observations(batch, ResultClass::Error);
                Err(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed))
            }
        }
    }

    fn submit_projected(
        &mut self,
        mut batch: PendingMutationBatch,
        projected: durable::ProjectedBatch,
    ) -> Result<BatchStep, StateCoreExit> {
        let (storage_batch, retained) = projected.into_parts();
        let batch_bytes = storage_batch
            .resulting_logical_database_bytes()
            .saturating_sub(storage_batch.expected_logical_database_bytes());
        match self.bridge.submit(storage_batch) {
            Ok(transaction_id) => {
                if let Some(observer) = &self.observer {
                    observer.storage_batch(batch_bytes);
                }
                batch.mark_in_flight(transaction_id, retained);
                self.pending = Some(batch);
                Ok(BatchStep::Submitted)
            }
            Err(SubmitError::Storage(error)) => {
                Ok(BatchStep::Rejected(self.reject_batch(batch, error)))
            }
            Err(SubmitError::Bridge(failure)) => {
                self.complete_batch_observations(batch, ResultClass::Error);
                Err(StateCoreExit::Indeterminate(IndeterminateCause::Bridge(
                    failure,
                )))
            }
        }
    }

    fn apply_batch_in_step(
        &mut self,
        batch: PendingMutationBatch,
    ) -> Result<BatchStep, StateCoreExit> {
        let (plans, _retained) = batch.finish();
        let count = plans.len();
        let mut plans = plans.into_iter();
        while let Some(mut staged) = plans.next() {
            let observation = staged.take_observation();
            let (plan, fanout, _origin) = staged.into_parts();
            if self.apply_plan(plan).is_err() {
                if let Some(observation) = observation {
                    self.complete_command_observation(observation, ResultClass::Error);
                }
                self.complete_plan_observations(plans, ResultClass::Error);
                return Err(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed));
            }
            self.commit_fanout(fanout);
            if let Some(observation) = observation {
                self.complete_command_observation(observation, ResultClass::Ok);
            }
        }
        Ok(BatchStep::AppliedInStep(count))
    }

    fn reject_batch(&mut self, batch: PendingMutationBatch, error: StorageError) -> Vec<Rejection> {
        self.counters.batches_rejected = self.counters.batches_rejected.saturating_add(1);
        let (plans, _retained) = batch.finish();
        plans
            .into_iter()
            .map(|staged| {
                let (_plan, _fanout, origin) = staged.into_parts();
                Rejection { origin, error }
            })
            .collect()
    }

    /// Consumes one storage receipt for the in-flight batch.
    fn consume_completion(
        &mut self,
        message: StorageCompletionMessage,
    ) -> Result<BatchStep, StateCoreExit> {
        let Some(batch) = self.pending.take() else {
            return Err(StateCoreExit::Indeterminate(
                IndeterminateCause::UnexpectedCompletion,
            ));
        };
        if batch.transaction_id() != Some(message.transaction_id) {
            self.complete_batch_observations(batch, ResultClass::Error);
            return Err(StateCoreExit::Indeterminate(
                IndeterminateCause::TransactionMismatch,
            ));
        }
        match message.outcome {
            CommitOutcome::Committed(receipt) => {
                self.apply_committed(batch, message.transaction_id, receipt)
            }
            CommitOutcome::Rejected(error) => {
                Ok(BatchStep::Rejected(self.reject_batch(batch, error)))
            }
            CommitOutcome::Indeterminate => {
                self.complete_batch_observations(batch, ResultClass::Error);
                Err(StateCoreExit::Indeterminate(
                    IndeterminateCause::StorageIndeterminate,
                ))
            }
        }
    }

    fn apply_committed(
        &mut self,
        batch: PendingMutationBatch,
        transaction_id: TransactionId,
        receipt: agenc_ircd_storage::CommitReceipt,
    ) -> Result<BatchStep, StateCoreExit> {
        if receipt.transaction_id != transaction_id {
            self.complete_batch_observations(batch, ResultClass::Error);
            return Err(StateCoreExit::Indeterminate(
                IndeterminateCause::TransactionMismatch,
            ));
        }
        let (plans, retained) = batch.finish();
        let Some(retained) = retained else {
            self.complete_plan_observations(plans.into_iter(), ResultClass::Error);
            return Err(StateCoreExit::Indeterminate(
                IndeterminateCause::UnexpectedCompletion,
            ));
        };
        let count = plans.len();
        self.apply_staged_plans(plans)?;
        self.head = retained.advance(&receipt);
        self.index.apply(retained.updates());
        self.counters.batches_committed = self.counters.batches_committed.saturating_add(1);
        Ok(BatchStep::AppliedInStep(count))
    }

    fn apply_staged_plans(&mut self, plans: Vec<StagedPlan>) -> Result<(), StateCoreExit> {
        let mut plans = plans.into_iter();
        while let Some(mut staged) = plans.next() {
            let observation = staged.take_observation();
            let (plan, fanout, _origin) = staged.into_parts();
            if self.apply_plan(plan).is_err() {
                if let Some(observation) = observation {
                    self.complete_command_observation(observation, ResultClass::Error);
                }
                self.complete_plan_observations(plans, ResultClass::Error);
                return Err(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed));
            }
            self.commit_fanout(fanout);
            if let Some(observation) = observation {
                self.complete_command_observation(observation, ResultClass::Ok);
            }
        }
        Ok(())
    }

    fn complete_batch_observations(&self, batch: PendingMutationBatch, result: ResultClass) {
        let (plans, _retained) = batch.finish();
        self.complete_plan_observations(plans.into_iter(), result);
    }

    fn complete_plan_observations(
        &self,
        plans: impl Iterator<Item = StagedPlan>,
        result: ResultClass,
    ) {
        for mut staged in plans {
            if let Some(observation) = staged.take_observation() {
                self.complete_command_observation(observation, result);
            }
        }
    }

    /// The rows whose sealed identity must be read back after a commit.
    #[must_use]
    pub fn pending_index_rows(&self) -> Vec<(TableId, StoredKey)> {
        self.index.pending_rows()
    }

    /// Records one admitted connection.
    fn admit_connection(
        &mut self,
        generation: ConnectionGeneration,
        purpose: crate::purpose::ListenerPurpose,
        source_prefix: SourceAddressKey,
        sink: Arc<dyn crate::connection::sink::ClientSink>,
    ) -> Result<(), RuntimeError> {
        let now = self.now();
        self.sessions
            .open(generation, purpose, source_prefix, sink, now)?;
        let evicted = match self.prefixes.connection_opened(source_prefix, now) {
            Ok(evicted) => evicted,
            Err(error) => {
                let _closed = self.sessions.close(generation);
                return Err(error);
            }
        };
        if let Some(prefix) = evicted {
            self.erase_prefix_buckets(prefix);
        }
        self.counters.connections_opened = self.counters.connections_opened.saturating_add(1);
        let previous = self.overload.class();
        let current = self
            .overload
            .classify(self.budget.charged(), self.budget.capacity());
        if current != previous
            && let Some(observer) = &self.observer
        {
            observer.overload_transition(current);
        }
        Ok(())
    }

    /// Removes one connection and every bucket keyed by it.
    fn release_connection(
        &mut self,
        generation: ConnectionGeneration,
        closed_at: Option<MonotonicTick>,
        prefix_recorded: bool,
    ) -> bool {
        let observed_now = self.now();
        let closed_at = closed_at.map_or(observed_now, |tick| tick.min(observed_now));
        let Some(entry) = self.sessions.close(generation) else {
            return false;
        };
        self.counters.connections_closed = self.counters.connections_closed.saturating_add(1);
        if !prefix_recorded {
            let _prefix_result = self
                .prefixes
                .connection_closed(entry.source_prefix(), closed_at);
        }
        self.buckets.erase_key(BucketKey::Connection(generation));
        if let Some(session) = entry.session() {
            self.buckets.erase_key(BucketKey::Session(session.user_id));
        }
        true
    }

    fn record_physical_close(
        &mut self,
        generation: ConnectionGeneration,
        closed_at: Option<MonotonicTick>,
    ) -> bool {
        let Some(source_prefix) = self
            .sessions
            .connection(generation)
            .map(|entry| entry.source_prefix())
        else {
            return false;
        };
        let observed_now = self.now();
        let closed_at = closed_at.map_or(observed_now, |tick| tick.min(observed_now));
        self.prefixes
            .connection_closed(source_prefix, closed_at)
            .is_ok()
    }

    fn erase_idle_prefixes(&mut self) {
        let now = self.now();
        self.erase_idle_prefixes_at(now);
    }

    fn erase_idle_prefixes_at(&mut self, now: MonotonicTick) {
        if !self
            .prefixes
            .next_erasure_deadline()
            .is_some_and(|deadline| deadline <= now)
        {
            return;
        }
        for prefix in self.prefixes.erase_idle(now) {
            self.erase_prefix_buckets(prefix);
        }
    }

    fn erase_prefix_buckets(&mut self, prefix: SourceAddressKey) {
        self.buckets.erase_key(BucketKey::Prefix(prefix));
        if prefix == SourceAddressKey::onion_listener() {
            self.buckets.erase_key(BucketKey::OnionListener);
        }
    }

    fn check_drift(&mut self) {
        let now = self.now();
        let wall = self.wall.utc_now().ok();
        let transition = self.drift.observe(now, wall);
        if let Some(observer) = &self.observer {
            match transition {
                DriftTransition::Distrusted => observer.clock_trust_changed(false),
                DriftTransition::Trusted => observer.clock_trust_changed(true),
                DriftTransition::Unchanged => {}
            }
        }
    }
}

fn next_transaction_id(entropy: &mut dyn EntropySource) -> Result<TransactionId, RuntimeError> {
    let mut bytes = [0_u8; 16];
    entropy
        .fill_exact(&mut bytes)
        .map_err(|_| RuntimeError::Storage(StorageError::Unavailable))?;
    Ok(TransactionId::from_bytes(bytes))
}

const fn storage_rejection_result(error: StorageError) -> ResultClass {
    match error {
        StorageError::LimitExceeded | StorageError::StaleState => ResultClass::Rejected,
        StorageError::AllocationFailed | StorageError::QueueFull => ResultClass::Busy,
        StorageError::InvalidEncoding
        | StorageError::UnsupportedVersion
        | StorageError::Overflow
        | StorageError::AuthenticationFailed
        | StorageError::Unavailable
        | StorageError::FilesystemRejected
        | StorageError::WriterLocked
        | StorageError::DatabaseRejected
        | StorageError::UnsupportedMigration
        | StorageError::ResumeMismatch => ResultClass::Error,
    }
}

fn valid_rehash_outcome_pair(
    success: &agenc_ircd_admin::AdminAuditEvent,
    failure: &agenc_ircd_admin::AdminAuditEvent,
) -> bool {
    if success.tbs().phase != agenc_ircd_admin::AdminAuditPhase::OutcomeSuccess
        || failure.tbs().phase != agenc_ircd_admin::AdminAuditPhase::OutcomeFailure
    {
        return false;
    }
    let Ok(canonical) =
        agenc_ircd_admin::CanonicalCommand::check(success.tbs().command_tbs.canonical_command())
    else {
        return false;
    };
    if !matches!(
        agenc_ircd_admin::AdminCommand::parse(canonical),
        Ok(agenc_ircd_admin::AdminCommand::Rehash(_))
    ) {
        return false;
    }
    let mut normalized_failure = failure.tbs().clone();
    normalized_failure.phase = agenc_ircd_admin::AdminAuditPhase::OutcomeSuccess;
    success.tbs() == &normalized_failure
}

const fn map_storage_reload_rejection(error: StorageError) -> ReloadRejection {
    match error {
        StorageError::LimitExceeded => ReloadRejection::CurrentUse,
        StorageError::QueueFull => ReloadRejection::Busy,
        _ => ReloadRejection::StorageUnavailable,
    }
}

/// The actor: the context plus the router that interprets commands.
pub struct StateCore {
    context: StateCoreContext,
    router: Box<dyn CommandRouter>,
    admin_receiver: mpsc::Receiver<AdminCoreRequest>,
    admin_open: bool,
    admin_pending: Option<PendingAdminCommit>,
    reload_receiver: mpsc::Receiver<ReloadCoreRequest>,
    reload_open: bool,
    reload_handle: Option<RuntimeConfigHandle>,
    reload_admission: Option<Arc<crate::admission::TransportAdmission>>,
    reload_pending: Option<PendingReload>,
    reload_provisional: Option<ProvisionalReload>,
    checkpoint_pending: Option<PendingIntegrityCheckpoint>,
    checkpoint_retry_suppressed: bool,
    storage_limit_writer: StorageLimitWriter,
    liveness: Arc<Liveness>,
}

struct PendingIntegrityCheckpoint {
    checkpoint_id: StorageCheckpointId,
    shutdown: bool,
}

struct PendingAdminCommit {
    transaction_id: TransactionId,
    retained: RetainedProjection,
    mutation: Option<AdminMutation>,
    reload_activation: Option<ReloadActivation>,
    reply: PendingAdminReply,
}

enum PendingAdminReply {
    Admin(tokio::sync::oneshot::Sender<AdminCoreResult>),
    Reload {
        activation: ReloadActivation,
        result: AuditedReloadResult,
        reply: tokio::sync::oneshot::Sender<Result<AuditedReloadResult, ReloadRejection>>,
    },
}

impl PendingAdminReply {
    fn complete(self) {
        match self {
            Self::Admin(reply) => {
                let _sent = reply.send(Ok(()));
            }
            Self::Reload { result, reply, .. } => {
                let _sent = reply.send(Ok(result));
            }
        }
    }

    const fn reload_activation(&self) -> Option<ReloadActivation> {
        match self {
            Self::Admin(_) => None,
            Self::Reload { activation, .. } => Some(*activation),
        }
    }

    const fn reload_result(&self) -> Option<AuditedReloadResult> {
        match self {
            Self::Admin(_) => None,
            Self::Reload { result, .. } => Some(*result),
        }
    }
}

struct PendingReload {
    prepared: PreparedReload,
    kind: PendingReloadKind,
}

enum PendingReloadKind {
    Signal(tokio::sync::oneshot::Sender<ReloadOutcome>),
    Audited {
        success: Box<agenc_ircd_admin::AdminAuditEvent>,
        failure: Box<agenc_ircd_admin::AdminAuditEvent>,
        reply: tokio::sync::oneshot::Sender<AuditedReloadStart>,
    },
}

struct ReservedReloadOutcome {
    transaction_id: TransactionId,
    batch: StorageMutationBatch,
    retained: RetainedProjection,
    resulting_logical_database_bytes: u64,
    resulting_backup_stream_bytes: u64,
}

struct ProvisionalReload {
    activation: ReloadActivation,
    previous: Arc<RuntimeConfigSnapshot>,
    candidate: Arc<RuntimeConfigSnapshot>,
    changes_live_state: bool,
    reservation_transaction_id: TransactionId,
    state: AuditedReloadState,
    _lease: Option<crate::runtime_config::ReloadLease>,
}

enum AuditedReloadState {
    ReadySuccess {
        success: Box<ReservedReloadOutcome>,
        failure: Box<ReservedReloadOutcome>,
    },
    CommittingSuccess {
        failure: Box<ReservedReloadOutcome>,
    },
    DurableSuccess,
    ReadyFailure {
        failure: Box<ReservedReloadOutcome>,
        rejection: ReloadRejection,
    },
    CommittingFailure {
        rejection: ReloadRejection,
    },
    DurableFailure,
}

enum IndexRefreshContinuation {
    Batch,
    Admin(PendingAdminReply),
}

impl IndexRefreshContinuation {
    fn reload_activation(&self) -> Option<ReloadActivation> {
        match self {
            Self::Batch => None,
            Self::Admin(reply) => reply.reload_activation(),
        }
    }

    fn complete(self) {
        if let Self::Admin(reply) = self {
            reply.complete();
        }
    }
}

struct PendingIndexRefresh {
    expected_commit_sequence: u64,
    remaining: VecDeque<(TableId, StoredKey)>,
    waiting: Option<(StorageReadId, TableId, StoredKey)>,
    refreshed: Vec<(TableId, StoredKey, Option<ExistingRecord>)>,
    continuation: IndexRefreshContinuation,
}

enum IndexReadSubmission {
    Complete,
    Submitted,
    Blocked,
}

impl PendingIndexRefresh {
    fn new(
        rows: Vec<(TableId, StoredKey)>,
        expected_commit_sequence: u64,
        continuation: IndexRefreshContinuation,
    ) -> Result<Self, RuntimeError> {
        let mut refreshed = Vec::new();
        refreshed
            .try_reserve_exact(rows.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(Self {
            expected_commit_sequence,
            remaining: VecDeque::from(rows),
            waiting: None,
            refreshed,
            continuation,
        })
    }

    fn submit_next(
        &mut self,
        bridge: &mut StorageBridge,
    ) -> Result<IndexReadSubmission, RuntimeError> {
        if self.waiting.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        let Some((table, key)) = self.remaining.front().cloned() else {
            return Ok(IndexReadSubmission::Complete);
        };
        match bridge.submit_read(ReadPlan::exact(table, key.clone())) {
            Ok(read_id) => {
                let _submitted = self.remaining.pop_front();
                self.waiting = Some((read_id, table, key));
                Ok(IndexReadSubmission::Submitted)
            }
            Err(StorageError::QueueFull) => Ok(IndexReadSubmission::Blocked),
            Err(error) => Err(RuntimeError::Storage(error)),
        }
    }

    fn owns(&self, read_id: StorageReadId) -> bool {
        self.waiting
            .as_ref()
            .is_some_and(|(expected, _, _)| *expected == read_id)
    }

    fn complete_read(&mut self, message: StorageReadCompletionMessage) -> Result<(), RuntimeError> {
        let Some((read_id, table, key)) = self.waiting.take() else {
            return Err(RuntimeError::InvalidValue);
        };
        if read_id != message.read_id {
            return Err(RuntimeError::InvalidValue);
        }
        let result = message.result?;
        if result.storage_commit_sequence != self.expected_commit_sequence {
            return Err(RuntimeError::Storage(StorageError::StaleState));
        }
        self.refreshed.push(read_back_record(table, key, result)?);
        Ok(())
    }

    fn finish(self, index: &mut DurableIndex) -> Result<IndexRefreshContinuation, RuntimeError> {
        if self.waiting.is_some() || !self.remaining.is_empty() {
            return Err(RuntimeError::InvalidValue);
        }
        index.refresh(self.refreshed)?;
        Ok(self.continuation)
    }
}

enum CompletionStep {
    Ready(Option<StateCoreExit>),
    Refresh(IndexRefreshContinuation),
}

enum CheckpointCompletionStep {
    Normal,
    ShutdownComplete,
    ShutdownRejected,
    Exit(StateCoreExit),
}

#[derive(Default)]
struct PendingLifecycleReplies {
    drain: Option<tokio::sync::oneshot::Sender<LifecycleResult>>,
    flush: Option<tokio::sync::oneshot::Sender<LifecycleResult>>,
}

impl PendingLifecycleReplies {
    fn install(
        &mut self,
        phase: LifecyclePhase,
        reply: tokio::sync::oneshot::Sender<LifecycleResult>,
    ) {
        let slot = match phase {
            LifecyclePhase::Drain => &mut self.drain,
            LifecyclePhase::Flush => &mut self.flush,
            LifecyclePhase::Quiesce | LifecyclePhase::Stop => {
                let _sent = reply.send(Ok(()));
                return;
            }
        };
        if slot.is_some() {
            let _sent = reply.send(Err(LifecycleFailure::Busy));
        } else {
            *slot = Some(reply);
        }
    }

    fn acknowledge(&mut self, phase: LifecyclePhase) {
        let reply = match phase {
            LifecyclePhase::Drain => self.drain.take(),
            LifecyclePhase::Flush => self.flush.take(),
            LifecyclePhase::Quiesce | LifecyclePhase::Stop => None,
        };
        if let Some(reply) = reply {
            let _sent = reply.send(Ok(()));
        }
    }

    fn fail(&mut self, phase: LifecyclePhase, failure: LifecycleFailure) {
        let reply = match phase {
            LifecyclePhase::Drain => self.drain.take(),
            LifecyclePhase::Flush => self.flush.take(),
            LifecyclePhase::Quiesce | LifecyclePhase::Stop => None,
        };
        if let Some(reply) = reply {
            let _sent = reply.send(Err(failure));
        }
    }

    fn supersede(&mut self) {
        for reply in [self.drain.take(), self.flush.take()].into_iter().flatten() {
            let _sent = reply.send(Err(LifecycleFailure::Superseded));
        }
    }
}

impl StateCore {
    /// Builds the state owner from reconstructed state.
    #[must_use]
    pub fn new(inputs: StateCoreInputs) -> Self {
        let now = inputs.clocks.monotonic.now();
        let wall = inputs
            .clocks
            .wall
            .utc_now()
            .unwrap_or(UtcSecond::from_unix_seconds(0));
        let (unused_admin, admin_receiver) = mpsc::channel(1);
        drop(unused_admin);
        let (unused_reload, reload_receiver) = mpsc::channel(1);
        drop(unused_reload);
        let bucket_budget = Arc::clone(&inputs.budget);
        let prefix_budget = Arc::clone(&inputs.budget);
        let mut state = Self {
            context: StateCoreContext {
                domain: inputs.reconstruction.domain,
                sessions: SessionTable::new(),
                buckets: BucketTable::new(inputs.config.rate_limits, bucket_budget),
                prefixes: PrefixRegistry::new(prefix_budget),
                timers: TimerHeap::new(),
                drift: DriftMonitor::new(now, wall),
                pending: None,
                index: inputs.reconstruction.index,
                keys: inputs.keys,
                head: inputs.reconstruction.head,
                ceilings: inputs.config.ceilings,
                overload: OverloadState::new(),
                budget: inputs.budget,
                runtime_resource_limits: RuntimeResourceLimits::HARD_MAX,
                bridge: inputs.bridge,
                crypto: inputs.crypto,
                entropy: inputs.entropy,
                monotonic: inputs.clocks.monotonic,
                wall: inputs.clocks.wall,
                server_prefix: inputs.config.server_prefix,
                motd: inputs.config.motd,
                public_info: inputs.config.public_info,
                counters: StateCoreCounters::default(),
                quiescing: false,
                observer: None,
            },
            router: inputs.router,
            admin_receiver,
            admin_open: false,
            admin_pending: None,
            reload_receiver,
            reload_open: false,
            reload_handle: None,
            reload_admission: None,
            reload_pending: None,
            reload_provisional: None,
            checkpoint_pending: None,
            checkpoint_retry_suppressed: false,
            storage_limit_writer: inputs.storage_limit_writer,
            liveness: inputs.liveness,
        };
        state.router.startup(&mut state.context);
        state
    }

    /// Installs the process observer before the actor starts.
    pub(crate) fn install_observer(&mut self, observer: Arc<RuntimeObserver>) {
        self.context.observer = Some(observer);
    }

    /// Installs the sole private administrative receiver before the actor
    /// starts. A second installation is rejected.
    pub(crate) fn install_admin_inbox(
        &mut self,
        inbox: AdminCoreInbox,
    ) -> Result<(), RuntimeError> {
        if self.admin_open || self.admin_pending.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        self.admin_receiver = inbox.into_receiver();
        self.admin_open = true;
        Ok(())
    }

    /// Installs the sole private reload receiver before the actor starts.
    pub(crate) fn install_reload_inbox(
        &mut self,
        inbox: ReloadCoreInbox,
    ) -> Result<(), RuntimeError> {
        if self.reload_open
            || self.reload_pending.is_some()
            || self.reload_provisional.is_some()
            || self.reload_handle.is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        let (receiver, handle, admission) = inbox.into_parts();
        let limits = handle
            .load()
            .runtime_resource_limits()
            .ok_or(RuntimeError::InvalidValue)?;
        self.context.runtime_resource_limits = limits;
        self.reload_receiver = receiver;
        self.reload_handle = Some(handle);
        self.reload_admission = Some(admission);
        self.reload_open = true;
        Ok(())
    }

    /// Borrows the context.
    #[must_use]
    pub const fn context(&self) -> &StateCoreContext {
        &self.context
    }

    /// Mutably borrows the context.
    pub const fn context_mut(&mut self) -> &mut StateCoreContext {
        &mut self.context
    }

    /// Returns both blocking bridges for the supervisor to join.
    #[must_use]
    pub fn into_bridges(self) -> (StorageBridge, CryptoBridge) {
        (self.context.bridge, self.context.crypto)
    }

    fn begin_connection_shutdown(&mut self) -> Vec<FlushAcknowledgement> {
        let sinks = self.context.sessions.live_sinks();
        let mut acknowledgements = Vec::with_capacity(sinks.len());
        for sink in sinks {
            let generation = sink.generation();
            let frame = WireMessage::new(
                self.context.server_prefix(),
                "ERROR",
                &[],
                Some("Server shutting down"),
            );
            if frame
                .ok()
                .and_then(|frame| self.context.send_to(generation, vec![frame]).ok())
                .is_none()
            {
                sink.begin_slow_consumer_close();
            }
            acknowledgements.push(sink.shutdown_after_flush());
        }
        acknowledgements
    }

    fn storage_in_flight(&self) -> bool {
        self.context.in_flight()
            || self.admin_pending.is_some()
            || self.checkpoint_pending.is_some()
    }

    fn start_integrity_checkpoint(&mut self, shutdown: bool) -> Result<bool, StateCoreExit> {
        if self.checkpoint_pending.is_some() || (!shutdown && self.checkpoint_retry_suppressed) {
            return Ok(false);
        }
        if !shutdown {
            match self.storage_limit_writer.checkpoint_due() {
                Ok(true) => {}
                Ok(false) => return Ok(false),
                Err(_) => {
                    return Err(StateCoreExit::Indeterminate(
                        IndeterminateCause::StorageIndeterminate,
                    ));
                }
            }
        }
        match self.context.bridge.submit_checkpoint() {
            Ok(checkpoint_id) => {
                self.checkpoint_pending = Some(PendingIntegrityCheckpoint {
                    checkpoint_id,
                    shutdown,
                });
                if let Some(observer) = &self.context.observer {
                    observer.storage_batch(0);
                }
                Ok(true)
            }
            Err(StorageError::QueueFull) => Ok(false),
            Err(_) => Err(StateCoreExit::Indeterminate(
                IndeterminateCause::StorageIndeterminate,
            )),
        }
    }

    fn step_checkpoint_completion(
        &mut self,
        message: StorageCheckpointCompletionMessage,
    ) -> CheckpointCompletionStep {
        let Some(pending) = self.checkpoint_pending.take() else {
            return CheckpointCompletionStep::Exit(StateCoreExit::Indeterminate(
                IndeterminateCause::UnexpectedCompletion,
            ));
        };
        if pending.checkpoint_id != message.checkpoint_id {
            return CheckpointCompletionStep::Exit(StateCoreExit::Indeterminate(
                IndeterminateCause::TransactionMismatch,
            ));
        }
        match message.outcome {
            CheckpointOutcome::NotNeeded => {
                self.checkpoint_retry_suppressed = false;
                if pending.shutdown {
                    CheckpointCompletionStep::ShutdownComplete
                } else {
                    CheckpointCompletionStep::Normal
                }
            }
            CheckpointOutcome::Installed(receipt) => {
                if !self.apply_checkpoint_receipt(receipt) {
                    return CheckpointCompletionStep::Exit(StateCoreExit::Indeterminate(
                        IndeterminateCause::TransactionMismatch,
                    ));
                }
                self.checkpoint_retry_suppressed = false;
                if pending.shutdown {
                    CheckpointCompletionStep::ShutdownComplete
                } else {
                    CheckpointCompletionStep::Normal
                }
            }
            CheckpointOutcome::Rejected(_error) => {
                self.context.counters.batches_rejected =
                    self.context.counters.batches_rejected.saturating_add(1);
                self.checkpoint_retry_suppressed = true;
                if pending.shutdown {
                    CheckpointCompletionStep::ShutdownRejected
                } else {
                    CheckpointCompletionStep::Normal
                }
            }
            CheckpointOutcome::Indeterminate => CheckpointCompletionStep::Exit(
                StateCoreExit::Indeterminate(IndeterminateCause::StorageIndeterminate),
            ),
        }
    }

    fn apply_checkpoint_receipt(&mut self, receipt: CheckpointReceipt) -> bool {
        let head = self.context.head;
        let Some(expected_commit) = head.storage_commit_sequence.checked_add(1) else {
            return false;
        };
        if receipt.storage_commit_sequence != expected_commit
            || receipt.state_generation != head.state_generation
            || receipt.account_service_response_count != head.account_service_response_count
            || receipt.cut_manifest_sequence > receipt.installation_manifest_sequence
            || receipt.logical_database_bytes > self.context.ceilings.database_max_bytes
            || receipt.backup_stream_bytes > self.context.ceilings.backup_max_bytes
        {
            return false;
        }
        self.context.head = HeadCounters {
            state_generation: receipt.state_generation,
            storage_commit_sequence: receipt.storage_commit_sequence,
            account_service_response_count: receipt.account_service_response_count,
            logical_database_bytes: receipt.logical_database_bytes,
            backup_stream_bytes: receipt.backup_stream_bytes,
        };
        self.context.counters.batches_committed =
            self.context.counters.batches_committed.saturating_add(1);
        true
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=closed reload request union preserves quiescence single-flight activation finalize and rollback ordering
    fn step_reload_request(&mut self, request: ReloadCoreRequest) -> Option<StateCoreExit> {
        match request {
            ReloadCoreRequest::ActivateSignal { prepared, reply } => {
                if self.context.quiescing {
                    let _sent = reply.send(ReloadOutcome::Rejected(ReloadRejection::Quiescing));
                } else if self.reload_pending.is_some() || self.reload_provisional.is_some() {
                    let _sent = reply.send(ReloadOutcome::Rejected(ReloadRejection::Busy));
                } else {
                    self.reload_pending = Some(PendingReload {
                        prepared: *prepared,
                        kind: PendingReloadKind::Signal(reply),
                    });
                }
                None
            }
            ReloadCoreRequest::ActivateAudited {
                prepared,
                success_event,
                failure_event,
                reply,
            } => {
                if self.context.quiescing
                    || self.reload_pending.is_some()
                    || self.reload_provisional.is_some()
                {
                    let _sent = reply.send(AuditedReloadStart::Indeterminate);
                } else {
                    self.reload_pending = Some(PendingReload {
                        prepared: *prepared,
                        kind: PendingReloadKind::Audited {
                            success: success_event,
                            failure: failure_event,
                            reply,
                        },
                    });
                }
                None
            }
            ReloadCoreRequest::CommitOutcome { activation, reply } => {
                self.commit_reserved_reload_outcome(activation, reply)
            }
            ReloadCoreRequest::Finalize { activation, reply } => {
                let result = self.finalize_reload(activation);
                let _sent = reply.send(result);
                None
            }
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=one safe-point transition validates revision current-use floors applies prepared cells and publishes or retains an audited rollback barrier
    fn activate_pending_reload(&mut self) -> Option<StateCoreExit> {
        let mut pending = self.reload_pending.take()?;
        let Some(handle) = self.reload_handle.clone() else {
            match pending.kind {
                PendingReloadKind::Signal(reply) => {
                    let _sent =
                        reply.send(ReloadOutcome::Rejected(ReloadRejection::StorageUnavailable));
                }
                PendingReloadKind::Audited { reply, .. } => {
                    let _sent = reply.send(AuditedReloadStart::Indeterminate);
                }
            }
            return Some(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed));
        };
        let current = handle.load();
        let candidate = pending.prepared.candidate();
        let changes_live_state = !pending.prepared.is_noop();
        match pending.kind {
            PendingReloadKind::Signal(reply) => {
                if current.revision() != pending.prepared.expected_revision() {
                    let _sent = reply.send(ReloadOutcome::Rejected(ReloadRejection::StaleRevision));
                    return None;
                }
                if !changes_live_state {
                    let _sent = reply.send(ReloadOutcome::NoChange(current.revision()));
                    return None;
                }
                if !self.reload_floors_accept(&candidate) {
                    let _sent = reply.send(ReloadOutcome::Rejected(ReloadRejection::CurrentUse));
                    return None;
                }
                let publication = Arc::clone(&candidate);
                let published = handle.publish_after(current.revision(), publication, || {
                    self.storage_limit_writer
                        .activate(candidate.storage_limits())
                        .map_err(map_storage_reload_rejection)?;
                    self.apply_runtime_snapshot(&candidate);
                    Ok(())
                });
                let outcome = match published {
                    Ok(_) => {
                        self.checkpoint_retry_suppressed = false;
                        ReloadOutcome::Applied(candidate.revision())
                    }
                    Err(rejection) => ReloadOutcome::Rejected(rejection),
                };
                let _sent = reply.send(outcome);
                None
            }
            PendingReloadKind::Audited {
                success,
                failure,
                reply,
            } => {
                if !valid_rehash_outcome_pair(&success, &failure) {
                    let _sent = reply.send(AuditedReloadStart::Indeterminate);
                    return Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed));
                }
                let Ok(failure) = self.project_reload_audit(&failure, &current) else {
                    let _sent = reply.send(AuditedReloadStart::Indeterminate);
                    return Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed));
                };
                let rejection = if current.revision() != pending.prepared.expected_revision() {
                    Some(ReloadRejection::StaleRevision)
                } else if changes_live_state && !self.reload_floors_accept(&candidate) {
                    Some(ReloadRejection::CurrentUse)
                } else {
                    None
                };
                if let Some(rejection) = rejection {
                    return self.install_failed_reload(
                        pending.prepared.take_lease(),
                        current,
                        failure,
                        rejection,
                        reply,
                    );
                }
                let success = match self.project_reload_audit(&success, &candidate) {
                    Ok(projected) => projected,
                    Err(RuntimeError::Storage(StorageError::LimitExceeded)) => {
                        return self.install_failed_reload(
                            pending.prepared.take_lease(),
                            current,
                            failure,
                            ReloadRejection::CurrentUse,
                            reply,
                        );
                    }
                    Err(_) => {
                        return self.install_failed_reload(
                            pending.prepared.take_lease(),
                            current,
                            failure,
                            ReloadRejection::StorageUnavailable,
                            reply,
                        );
                    }
                };
                if let Err(error) = self.storage_limit_writer.reserve(
                    success.transaction_id,
                    candidate.storage_limits(),
                    success.resulting_logical_database_bytes,
                    success.resulting_backup_stream_bytes,
                ) {
                    return self.install_failed_reload(
                        pending.prepared.take_lease(),
                        current,
                        failure,
                        map_storage_reload_rejection(error),
                        reply,
                    );
                }
                let activation = ReloadActivation {
                    revision: candidate.revision(),
                    transaction_id: success.transaction_id,
                    changes_live_state,
                };
                self.reload_provisional = Some(ProvisionalReload {
                    activation,
                    previous: current,
                    candidate,
                    changes_live_state,
                    reservation_transaction_id: success.transaction_id,
                    state: AuditedReloadState::ReadySuccess {
                        success: Box::new(success),
                        failure: Box::new(failure),
                    },
                    _lease: pending.prepared.take_lease(),
                });
                let _sent = reply.send(AuditedReloadStart::Provisional(activation));
                None
            }
        }
    }

    fn project_reload_audit(
        &mut self,
        event: &agenc_ircd_admin::AdminAuditEvent,
        snapshot: &RuntimeConfigSnapshot,
    ) -> Result<ReservedReloadOutcome, RuntimeError> {
        let transaction_id = next_transaction_id(self.context.entropy.as_mut())?;
        let projected = project_admin_audit_event(
            transaction_id,
            event,
            &self.context.index,
            &self.context.keys,
            self.context.head,
            snapshot.storage_ceilings(),
        )?;
        let resulting_logical_database_bytes = projected.resulting_logical_database_bytes();
        let resulting_backup_stream_bytes = projected.resulting_backup_stream_bytes();
        let (batch, retained) = projected.into_parts();
        Ok(ReservedReloadOutcome {
            transaction_id,
            batch,
            retained,
            resulting_logical_database_bytes,
            resulting_backup_stream_bytes,
        })
    }

    fn install_failed_reload(
        &mut self,
        lease: Option<crate::runtime_config::ReloadLease>,
        current: Arc<RuntimeConfigSnapshot>,
        failure: ReservedReloadOutcome,
        rejection: ReloadRejection,
        reply: tokio::sync::oneshot::Sender<AuditedReloadStart>,
    ) -> Option<StateCoreExit> {
        if self
            .storage_limit_writer
            .reserve(
                failure.transaction_id,
                current.storage_limits(),
                failure.resulting_logical_database_bytes,
                failure.resulting_backup_stream_bytes,
            )
            .is_err()
        {
            let _sent = reply.send(AuditedReloadStart::Indeterminate);
            return Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed));
        }
        let activation = ReloadActivation {
            revision: current.revision(),
            transaction_id: failure.transaction_id,
            changes_live_state: false,
        };
        self.reload_provisional = Some(ProvisionalReload {
            activation,
            previous: Arc::clone(&current),
            candidate: current,
            changes_live_state: false,
            reservation_transaction_id: failure.transaction_id,
            state: AuditedReloadState::ReadyFailure {
                failure: Box::new(failure),
                rejection,
            },
            _lease: lease,
        });
        let _sent = reply.send(AuditedReloadStart::Provisional(activation));
        None
    }

    fn reload_floors_accept(&self, candidate: &RuntimeConfigSnapshot) -> bool {
        let Some(resource_limits) = candidate.runtime_resource_limits() else {
            return false;
        };
        if candidate.crypto_job_ceilings().is_none() {
            return false;
        }
        let query = self.context.sessions.queue_snapshot();
        if !resource_limits.accepts_query_usage(query) {
            return false;
        }
        let Ok(usage) = self.context.domain.operational_usage() else {
            return false;
        };
        if !invite_reload_floor_accepts(candidate.operational_limits(), usage) {
            return false;
        }
        let ceilings = candidate.storage_ceilings();
        self.context.head.logical_database_bytes <= ceilings.database_max_bytes
            && self.context.head.backup_stream_bytes <= ceilings.backup_max_bytes
    }

    fn apply_runtime_snapshot(&mut self, snapshot: &RuntimeConfigSnapshot) {
        if let Some(limits) = snapshot.runtime_resource_limits() {
            self.context.runtime_resource_limits = limits;
        }
        self.context
            .domain
            .set_operational_limits(snapshot.operational_limits());
        self.context.buckets.reload(snapshot.rates());
        self.context.ceilings = snapshot.storage_ceilings();
        self.context.motd = snapshot.motd_arc();
        self.context.public_info = snapshot.public_info_arc();
        if let Some((channel_job_limit, opaque_job_limit)) = snapshot.crypto_job_ceilings() {
            self.context
                .crypto
                .reload_job_limits(channel_job_limit, opaque_job_limit);
        }
        if let Some(admission) = &self.reload_admission {
            admission.reload(snapshot.rates(), snapshot.direct_connections_per_address());
        }
        self.router.config_reloaded(&mut self.context, snapshot);
        if let Some(observer) = &self.context.observer {
            let _updated =
                observer.set_log_retention(snapshot.config().privacy.log_retention_hours);
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-01 reason=closed submit result keeps exact reserved outcome and determinate rollback distinct from indeterminate closure
    fn commit_reserved_reload_outcome(
        &mut self,
        activation: ReloadActivation,
        reply: tokio::sync::oneshot::Sender<Result<AuditedReloadResult, ReloadRejection>>,
    ) -> Option<StateCoreExit> {
        let (outcome, result) = match self.begin_reserved_reload_outcome(activation) {
            Ok(outcome) => outcome,
            Err(rejection) => {
                let _sent = reply.send(Err(rejection));
                return None;
            }
        };
        self.submit_reload_outcome(activation, outcome, result, reply)
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-01 reason=closed bridge outcomes either retain the exact barrier-bound result transition to the prebuilt failure batch or terminate indeterminate
    fn submit_reload_outcome(
        &mut self,
        activation: ReloadActivation,
        outcome: ReservedReloadOutcome,
        result: AuditedReloadResult,
        reply: tokio::sync::oneshot::Sender<Result<AuditedReloadResult, ReloadRejection>>,
    ) -> Option<StateCoreExit> {
        let transaction_id = outcome.transaction_id;
        let retained = outcome.retained;
        match self.context.bridge.submit(outcome.batch) {
            Ok(submitted) if submitted == transaction_id => {
                self.admin_pending = Some(PendingAdminCommit {
                    transaction_id,
                    retained,
                    mutation: None,
                    reload_activation: Some(activation),
                    reply: PendingAdminReply::Reload {
                        activation,
                        result,
                        reply,
                    },
                });
                None
            }
            Ok(_) => Some(StateCoreExit::Indeterminate(
                IndeterminateCause::TransactionMismatch,
            )),
            Err(SubmitError::Storage(_)) if result == AuditedReloadResult::Success => self
                .submit_reload_failure_after_rejection(
                    activation,
                    ReloadRejection::StorageUnavailable,
                    reply,
                ),
            Err(SubmitError::Storage(_)) => Some(StateCoreExit::Indeterminate(
                IndeterminateCause::StorageIndeterminate,
            )),
            Err(SubmitError::Bridge(failure)) => Some(StateCoreExit::Indeterminate(
                IndeterminateCause::Bridge(failure),
            )),
        }
    }

    fn begin_reserved_reload_outcome(
        &mut self,
        activation: ReloadActivation,
    ) -> Result<(ReservedReloadOutcome, AuditedReloadResult), ReloadRejection> {
        if self.storage_in_flight() || self.context.pending_len() != 0 {
            return Err(ReloadRejection::Busy);
        }
        let Some(mut provisional) = self.reload_provisional.take() else {
            return Err(ReloadRejection::StaleRevision);
        };
        if provisional.activation != activation {
            self.reload_provisional = Some(provisional);
            return Err(ReloadRejection::StaleRevision);
        }
        let (outcome, result, next_state) = match provisional.state {
            AuditedReloadState::ReadySuccess { success, failure } => (
                *success,
                AuditedReloadResult::Success,
                AuditedReloadState::CommittingSuccess { failure },
            ),
            AuditedReloadState::ReadyFailure { failure, rejection } => (
                *failure,
                AuditedReloadResult::Failure(rejection),
                AuditedReloadState::CommittingFailure { rejection },
            ),
            state => {
                provisional.state = state;
                self.reload_provisional = Some(provisional);
                return Err(ReloadRejection::Busy);
            }
        };
        provisional.state = next_state;
        self.reload_provisional = Some(provisional);
        Ok((outcome, result))
    }

    fn submit_reload_failure_after_rejection(
        &mut self,
        activation: ReloadActivation,
        rejection: ReloadRejection,
        reply: tokio::sync::oneshot::Sender<Result<AuditedReloadResult, ReloadRejection>>,
    ) -> Option<StateCoreExit> {
        let Some(mut provisional) = self.reload_provisional.take() else {
            return Some(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed));
        };
        if provisional.activation != activation {
            self.reload_provisional = Some(provisional);
            return Some(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed));
        }
        let failure = match provisional.state {
            AuditedReloadState::CommittingSuccess { failure } => *failure,
            state => {
                provisional.state = state;
                self.reload_provisional = Some(provisional);
                return Some(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed));
            }
        };
        if self
            .storage_limit_writer
            .rollback(provisional.reservation_transaction_id)
            .is_err()
            || self
                .storage_limit_writer
                .reserve(
                    failure.transaction_id,
                    provisional.previous.storage_limits(),
                    failure.resulting_logical_database_bytes,
                    failure.resulting_backup_stream_bytes,
                )
                .is_err()
        {
            provisional.state = AuditedReloadState::CommittingFailure { rejection };
            self.reload_provisional = Some(provisional);
            return Some(StateCoreExit::Indeterminate(
                IndeterminateCause::StorageIndeterminate,
            ));
        }
        provisional.reservation_transaction_id = failure.transaction_id;
        provisional.state = AuditedReloadState::CommittingFailure { rejection };
        self.reload_provisional = Some(provisional);
        self.submit_reload_outcome(
            activation,
            failure,
            AuditedReloadResult::Failure(rejection),
            reply,
        )
    }

    fn finalize_reload(
        &mut self,
        activation: ReloadActivation,
    ) -> Result<crate::runtime_config::ConfigRevision, ReloadRejection> {
        let provisional = self
            .reload_provisional
            .take()
            .ok_or(ReloadRejection::StaleRevision)?;
        if provisional.activation != activation {
            self.reload_provisional = Some(provisional);
            return Err(ReloadRejection::StaleRevision);
        }
        if !matches!(
            provisional.state,
            AuditedReloadState::DurableSuccess | AuditedReloadState::DurableFailure
        ) {
            self.reload_provisional = Some(provisional);
            return Err(ReloadRejection::Busy);
        }
        let Some(handle) = self.reload_handle.clone() else {
            self.reload_provisional = Some(provisional);
            return Err(ReloadRejection::StorageUnavailable);
        };
        let durable_success = matches!(provisional.state, AuditedReloadState::DurableSuccess);
        if !durable_success || !provisional.changes_live_state {
            let result = handle.activate_after(provisional.previous.revision(), || {
                self.storage_limit_writer
                    .finalize(provisional.reservation_transaction_id)
                    .map_err(map_storage_reload_rejection)
            });
            return match result {
                Ok(()) => {
                    self.checkpoint_retry_suppressed = false;
                    Ok(provisional.previous.revision())
                }
                Err(rejection) => {
                    self.reload_provisional = Some(provisional);
                    Err(rejection)
                }
            };
        }
        let publication = Arc::clone(&provisional.candidate);
        let result = handle.publish_after(provisional.previous.revision(), publication, || {
            self.storage_limit_writer
                .finalize(provisional.reservation_transaction_id)
                .map_err(map_storage_reload_rejection)?;
            self.apply_runtime_snapshot(&provisional.candidate);
            Ok(())
        });
        match result {
            Ok(_) => {
                self.checkpoint_retry_suppressed = false;
                Ok(provisional.candidate.revision())
            }
            Err(rejection) => {
                self.reload_provisional = Some(provisional);
                Err(rejection)
            }
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=single admin safe-point dispatch owns validation projection submission and closed failure routing
    fn step_admin_request(&mut self, request: AdminCoreRequest) -> Option<StateCoreExit> {
        let (event, mutation, after_image, reply) = match request {
            AdminCoreRequest::CommitAudit { event, reply } => (event, None, None, reply),
            AdminCoreRequest::CommitMutation {
                event,
                mutation,
                expected_revision,
                reply,
            } => {
                if !mutation.matches_event(&event) {
                    return Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed));
                }
                match self.validate_admin_mutation(mutation, expected_revision) {
                    Ok(()) => match self.prepare_admin_after_image(mutation) {
                        Ok(after_image) => (event, Some(mutation), Some(after_image), reply),
                        Err(failure) => {
                            let _sent = reply.send(Err(failure));
                            return None;
                        }
                    },
                    Err(failure) => {
                        let _sent = reply.send(Err(failure));
                        return None;
                    }
                }
            }
            AdminCoreRequest::Snapshot { reply } => {
                let _sent = reply.send(Ok(self.admin_snapshot()));
                return None;
            }
            AdminCoreRequest::TargetRevision { target, reply } => {
                let _sent = reply.send(self.admin_target_revision(target));
                return None;
            }
            AdminCoreRequest::Kill { user_id, reply } => {
                let _sent = reply.send(self.admin_kill(user_id));
                return None;
            }
            AdminCoreRequest::CommitRetention { checkpoint, reply } => {
                return self.step_admin_retention(*checkpoint, reply);
            }
        };
        if self.context.quiescing {
            let _sent = reply.send(Err(AdminCoreFailure::Quiescing));
            return None;
        }
        if self.storage_in_flight() || self.context.pending_len() != 0 {
            let _sent = reply.send(Err(AdminCoreFailure::Busy));
            return None;
        }
        let Ok(transaction_id) = next_transaction_id(self.context.entropy.as_mut()) else {
            return Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed));
        };
        let projected = match &after_image {
            Some(after_image) => project_admin_mutation_event(
                transaction_id,
                &event,
                after_image,
                &self.context.index,
                &self.context.keys,
                self.context.head,
                self.context.ceilings,
            ),
            None => project_admin_audit_event(
                transaction_id,
                &event,
                &self.context.index,
                &self.context.keys,
                self.context.head,
                self.context.ceilings,
            ),
        };
        let projected = match projected {
            Ok(projected) => projected,
            Err(RuntimeError::Storage(StorageError::LimitExceeded)) => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                return None;
            }
            Err(_) => return Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed)),
        };
        let (batch, retained) = projected.into_parts();
        match self.context.bridge.submit(batch) {
            Ok(submitted) if submitted == transaction_id => {
                self.admin_pending = Some(PendingAdminCommit {
                    transaction_id,
                    retained,
                    mutation,
                    reload_activation: None,
                    reply: PendingAdminReply::Admin(reply),
                });
                None
            }
            Ok(_) => Some(StateCoreExit::Indeterminate(
                IndeterminateCause::TransactionMismatch,
            )),
            Err(SubmitError::Storage(_)) => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                None
            }
            Err(SubmitError::Bridge(failure)) => Some(StateCoreExit::Indeterminate(
                IndeterminateCause::Bridge(failure),
            )),
        }
    }

    fn step_admin_retention(
        &mut self,
        checkpoint: agenc_ircd_admin::AdminAuditCheckpoint,
        reply: tokio::sync::oneshot::Sender<AdminCoreResult>,
    ) -> Option<StateCoreExit> {
        if self.storage_in_flight() || self.context.pending_len() != 0 {
            let _sent = reply.send(Err(AdminCoreFailure::Busy));
            return None;
        }
        let Ok(transaction_id) = next_transaction_id(self.context.entropy.as_mut()) else {
            return Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed));
        };
        let projected = project_admin_audit_retention(
            transaction_id,
            &checkpoint,
            &self.context.index,
            &self.context.keys,
            self.context.head,
            self.context.ceilings,
        );
        let projected = match projected {
            Ok(projected) => projected,
            Err(
                RuntimeError::Storage(StorageError::LimitExceeded) | RuntimeError::LimitExceeded,
            ) => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                return None;
            }
            Err(_) => return Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed)),
        };
        let (batch, retained) = projected.into_parts();
        match self.context.bridge.submit(batch) {
            Ok(submitted) if submitted == transaction_id => {
                self.admin_pending = Some(PendingAdminCommit {
                    transaction_id,
                    retained,
                    mutation: None,
                    reload_activation: None,
                    reply: PendingAdminReply::Admin(reply),
                });
                None
            }
            Ok(_) => Some(StateCoreExit::Indeterminate(
                IndeterminateCause::TransactionMismatch,
            )),
            Err(SubmitError::Storage(_)) => {
                let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                None
            }
            Err(SubmitError::Bridge(failure)) => Some(StateCoreExit::Indeterminate(
                IndeterminateCause::Bridge(failure),
            )),
        }
    }

    fn admin_target_revision(&self, target: AdminTarget) -> Result<Revision, AdminCoreFailure> {
        if self.context.quiescing {
            return Err(AdminCoreFailure::Quiescing);
        }
        let exists = match target {
            AdminTarget::Account(account_id) => self.context.domain.account(account_id).is_some(),
            AdminTarget::Channel(channel_id) => self.context.domain.channel(channel_id).is_some(),
            AdminTarget::Process => true,
        };
        if !exists {
            return Err(AdminCoreFailure::InvalidTarget);
        }
        Revision::new(self.context.head.storage_commit_sequence)
            .map_err(|_| AdminCoreFailure::StorageUnavailable)
    }

    fn validate_admin_mutation(
        &self,
        mutation: AdminMutation,
        expected_revision: Revision,
    ) -> AdminCoreResult {
        let target = match mutation {
            AdminMutation::SuspendAccount { account_id, .. }
            | AdminMutation::RestoreAccount(account_id) => AdminTarget::Account(account_id),
            AdminMutation::QuarantineChannel(channel_id) => AdminTarget::Channel(channel_id),
        };
        if self.admin_target_revision(target)? != expected_revision {
            return Err(AdminCoreFailure::StaleRevision);
        }
        match mutation {
            AdminMutation::SuspendAccount { expires_at, .. } => {
                let now = self
                    .context
                    .utc_now()
                    .map_err(|_| AdminCoreFailure::StorageUnavailable)?;
                if expires_at <= now {
                    return Err(AdminCoreFailure::InvalidTarget);
                }
            }
            AdminMutation::RestoreAccount(account_id) => {
                if !self.context.domain.account_has_admin_suspension(account_id) {
                    return Err(AdminCoreFailure::InvalidTarget);
                }
            }
            AdminMutation::QuarantineChannel(channel_id) => {
                if self.context.domain.channel_is_quarantined(channel_id) {
                    return Err(AdminCoreFailure::InvalidTarget);
                }
            }
        }
        Ok(())
    }

    fn prepare_admin_after_image(
        &self,
        mutation: AdminMutation,
    ) -> Result<AdminMutationAfterImage, AdminCoreFailure> {
        let revision = self
            .context
            .domain
            .revision()
            .checked_add(1)
            .map_err(|_| AdminCoreFailure::StorageUnavailable)?;
        match mutation {
            AdminMutation::SuspendAccount {
                account_id,
                expires_at,
            } => {
                let mut account = self
                    .context
                    .domain
                    .durable_account(account_id)
                    .ok_or(AdminCoreFailure::InvalidTarget)?;
                account.admin_suspension_expires_at = Some(expires_at);
                Ok(AdminMutationAfterImage::Account(account))
            }
            AdminMutation::RestoreAccount(account_id) => {
                let mut account = self
                    .context
                    .domain
                    .durable_account(account_id)
                    .ok_or(AdminCoreFailure::InvalidTarget)?;
                account.admin_suspension_expires_at = None;
                Ok(AdminMutationAfterImage::Account(account))
            }
            AdminMutation::QuarantineChannel(channel_id) => {
                let mut channel = self
                    .context
                    .domain
                    .durable_channel(channel_id)
                    .ok_or(AdminCoreFailure::InvalidTarget)?;
                channel.admin_quarantined = true;
                channel.revision = revision;
                Ok(AdminMutationAfterImage::Channel(channel))
            }
        }
    }

    fn admin_kill(&mut self, user_id: UserId) -> AdminCoreResult {
        if self.context.quiescing {
            return Err(AdminCoreFailure::Quiescing);
        }
        if self.context.domain.session(user_id).is_none() {
            return Err(AdminCoreFailure::InvalidTarget);
        }
        let Some(generation) = self.context.sessions.generation_for_user(user_id) else {
            return Err(AdminCoreFailure::InvalidTarget);
        };
        let Some(sink) = self.context.sessions.sink_for_generation(generation) else {
            return Err(AdminCoreFailure::InvalidTarget);
        };
        sink.begin_slow_consumer_close();
        self.context.sessions.mark_sink_gone(generation);
        Ok(())
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=post-commit policy application keeps account disconnect and channel quarantine effects adjacent
    fn apply_admin_mutation(&mut self, mutation: AdminMutation) -> Result<(), DomainError> {
        match mutation {
            AdminMutation::SuspendAccount {
                account_id,
                expires_at,
            } => {
                let users = self.context.domain.users_for_account(account_id);
                self.context
                    .domain
                    .admin_suspend_account(account_id, expires_at)?;
                for user_id in users {
                    if let Some(generation) = self.context.sessions.generation_for_user(user_id) {
                        if let Some(sink) = self.context.sessions.sink_for_generation(generation) {
                            sink.begin_slow_consumer_close();
                        }
                        self.context.sessions.mark_sink_gone(generation);
                    }
                }
            }
            AdminMutation::RestoreAccount(account_id) => {
                self.context.domain.admin_restore_account(account_id)?;
            }
            AdminMutation::QuarantineChannel(channel_id) => {
                self.context.domain.admin_quarantine_channel(channel_id)?;
            }
        }
        Ok(())
    }

    fn admin_snapshot(&self) -> AdminCoreSnapshot {
        let (local_channels, global_channels) = self.context.domain.channel_scope_counts();
        let counters = self.context.counters;
        let head = self.context.head;
        let storage_in_flight = u64::from(self.context.in_flight());
        let client_queues = self.context.sessions.queue_snapshot();
        AdminCoreSnapshot::new(
            [
                self.context.now().get() / 1_000,
                usize_u64(self.context.sessions.len()),
                0,
                usize_u64(self.context.sessions.registered_len()),
                usize_u64(self.context.domain.authenticated_session_count()),
                usize_u64(local_channels),
                usize_u64(global_channels),
                self.context.budget.charged(),
                self.context.budget.capacity(),
            ],
            [
                head.logical_database_bytes,
                0,
                self.context.ceilings.database_max_bytes,
                head.backup_stream_bytes,
                self.context.ceilings.backup_max_bytes,
                head.state_generation,
                0,
                head.storage_commit_sequence,
                head.account_service_response_count,
                0,
                0,
                0,
                0,
                0,
            ],
            [
                client_queues.queued_bytes(),
                client_queues.capacity_bytes(),
                0,
                0,
                usize_u64(self.context.crypto.snapshot_in_flight()),
                usize_u64(self.context.crypto.capacity()),
                storage_in_flight,
                usize_u64(STORAGE_HANDOFF_CAPACITY),
                client_queues.query_snapshots(),
                client_queues.query_rows(),
            ],
            [
                counters.lines_routed,
                counters.batches_rejected,
                counters.connections_opened,
                counters.connections_closed,
                0,
                0,
                0,
                0,
            ],
        )
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-01 reason=the sole admin receipt router preserves the reload barrier across success rejection and treats failure rejection as indeterminate
    fn step_admin_completion(&mut self, message: StorageCompletionMessage) -> CompletionStep {
        let Some(pending) = self.admin_pending.take() else {
            return CompletionStep::Ready(Some(StateCoreExit::Indeterminate(
                IndeterminateCause::UnexpectedCompletion,
            )));
        };
        if pending.transaction_id != message.transaction_id {
            return CompletionStep::Ready(Some(StateCoreExit::Indeterminate(
                IndeterminateCause::TransactionMismatch,
            )));
        }
        match message.outcome {
            CommitOutcome::Committed(receipt) => match self.apply_committed_admin(pending, receipt)
            {
                Ok(reply) => CompletionStep::Refresh(IndexRefreshContinuation::Admin(reply)),
                Err(exit) => CompletionStep::Ready(Some(exit)),
            },
            CommitOutcome::Rejected(_error) => {
                self.context.counters.batches_rejected =
                    self.context.counters.batches_rejected.saturating_add(1);
                match pending.reply {
                    PendingAdminReply::Admin(reply) => {
                        let _sent = reply.send(Err(AdminCoreFailure::StorageUnavailable));
                        CompletionStep::Ready(self.step_batch())
                    }
                    PendingAdminReply::Reload {
                        activation,
                        result: AuditedReloadResult::Success,
                        reply,
                    } if pending.reload_activation == Some(activation) => {
                        CompletionStep::Ready(self.submit_reload_failure_after_rejection(
                            activation,
                            ReloadRejection::StorageUnavailable,
                            reply,
                        ))
                    }
                    PendingAdminReply::Reload { .. } => CompletionStep::Ready(Some(
                        StateCoreExit::Indeterminate(IndeterminateCause::StorageIndeterminate),
                    )),
                }
            }
            CommitOutcome::Indeterminate => CompletionStep::Ready(Some(
                StateCoreExit::Indeterminate(IndeterminateCause::StorageIndeterminate),
            )),
        }
    }

    fn apply_committed_admin(
        &mut self,
        pending: PendingAdminCommit,
        receipt: agenc_ircd_storage::CommitReceipt,
    ) -> Result<PendingAdminReply, StateCoreExit> {
        if receipt.transaction_id != pending.transaction_id {
            return Err(StateCoreExit::Indeterminate(
                IndeterminateCause::TransactionMismatch,
            ));
        }
        self.context.head = pending.retained.advance(&receipt);
        self.checkpoint_retry_suppressed = false;
        self.context.index.apply(pending.retained.updates());
        self.context.counters.batches_committed =
            self.context.counters.batches_committed.saturating_add(1);
        if let Some(mutation) = pending.mutation {
            self.apply_admin_mutation(mutation)
                .map_err(|_| StateCoreExit::Corrupt(CorruptionCause::ApplyFailed))?;
        }
        if let Some(activation) = pending.reload_activation {
            let result = pending
                .reply
                .reload_result()
                .ok_or(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed))?;
            self.mark_reload_outcome_committed(activation, result)?;
        }
        Ok(pending.reply)
    }

    fn mark_reload_outcome_committed(
        &mut self,
        activation: ReloadActivation,
        result: AuditedReloadResult,
    ) -> Result<(), StateCoreExit> {
        let provisional = self
            .reload_provisional
            .as_mut()
            .ok_or(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed))?;
        let state_matches = match (&provisional.state, result) {
            (AuditedReloadState::CommittingSuccess { .. }, AuditedReloadResult::Success) => true,
            (
                AuditedReloadState::CommittingFailure {
                    rejection: expected,
                },
                AuditedReloadResult::Failure(actual),
            ) => *expected == actual,
            _ => false,
        };
        if provisional.activation != activation || !state_matches {
            return Err(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed));
        }
        Ok(())
    }

    fn step_physical_close(&mut self, notice: PhysicalCloseNotice) -> Option<StateCoreExit> {
        if !self
            .context
            .record_physical_close(notice.generation, notice.closed_at)
        {
            drop(notice.state_permit);
            return Some(StateCoreExit::Corrupt(
                CorruptionCause::ConnectionStateFailed,
            ));
        }
        match self.context.sessions.begin_physical_close(notice) {
            Ok(Some(ready)) => self.finish_physical_close(ready),
            Ok(None) => None,
            Err(rejected) => {
                drop(rejected.state_permit);
                Some(StateCoreExit::Corrupt(
                    CorruptionCause::ConnectionStateFailed,
                ))
            }
        }
    }

    fn finish_physical_close(&mut self, notice: PhysicalCloseNotice) -> Option<StateCoreExit> {
        if !self
            .context
            .release_connection(notice.generation, notice.closed_at, true)
        {
            drop(notice.state_permit);
            return Some(StateCoreExit::Corrupt(
                CorruptionCause::ConnectionStateFailed,
            ));
        }
        self.router
            .connection_closed(&mut self.context, notice.generation, notice.reason);
        drop(notice.state_permit);
        None
    }

    /// Handles one inbox message; `Some` ends the loop.
    pub fn step_message(&mut self, message: StateCoreMessage) -> Option<StateCoreExit> {
        let exit = match message {
            StateCoreMessage::Opened {
                generation,
                purpose,
                source,
                sink,
                acknowledgement,
            } => {
                let outcome = if self
                    .context
                    .admit_connection(generation, purpose, source, sink)
                    .is_ok()
                {
                    self.router.connection_opened(&mut self.context, generation);
                    ConnectionOpenOutcome::Accepted
                } else {
                    ConnectionOpenOutcome::Refused
                };
                let _sent = acknowledgement.send(outcome);
                None
            }
            StateCoreMessage::Line {
                generation,
                sequence,
                message,
            } => self.route_line(generation, sequence, *message),
            StateCoreMessage::Signal(signal) => self.step_signal(signal),
            StateCoreMessage::Maintenance(event) => {
                self.step_maintenance(event);
                None
            }
        };
        exit.or_else(|| self.step_batch())
    }

    fn route_line(
        &mut self,
        generation: ConnectionGeneration,
        sequence: u64,
        message: ParsedMessage,
    ) -> Option<StateCoreExit> {
        let acceptance = match self.context.sessions.accept_line(generation, sequence) {
            Ok(Some(acceptance)) => acceptance,
            Ok(None) => {
                self.context.counters.lines_dropped =
                    self.context.counters.lines_dropped.saturating_add(1);
                return None;
            }
            Err(_) => {
                return Some(StateCoreExit::Corrupt(
                    CorruptionCause::ConnectionStateFailed,
                ));
            }
        };
        if !acceptance.route || self.context.quiescing {
            self.context.counters.lines_dropped =
                self.context.counters.lines_dropped.saturating_add(1);
            return acceptance
                .completed_close
                .and_then(|notice| self.finish_physical_close(notice));
        }
        self.context.counters.lines_routed = self.context.counters.lines_routed.saturating_add(1);
        let observation = self.context.begin_command_observation(message.command());
        let outcome = self
            .router
            .route(&mut self.context, generation, message, observation);
        if let RouteOutcome::Close(_reason) = outcome {
            // The sink contract exposes one close path; the transport owner
            // ends the connection and reports it on the reserved close lane.
            if let Some(sink) = self.context.sessions.sink_for_generation(generation) {
                sink.begin_slow_consumer_close();
            }
            self.context.sessions.mark_sink_gone(generation);
        }
        acceptance
            .completed_close
            .and_then(|notice| self.finish_physical_close(notice))
    }

    fn step_signal(&mut self, signal: SignalEvent) -> Option<StateCoreExit> {
        match signal {
            SignalEvent::Terminate => {
                self.context.quiescing = true;
                (!self.context.in_flight()).then_some(StateCoreExit::Quiesced)
            }
            SignalEvent::Interrupt => Some(StateCoreExit::Interrupted),
            SignalEvent::Reload => {
                self.router.reload_requested(&mut self.context);
                None
            }
        }
    }

    fn step_maintenance(&mut self, event: MaintenanceEvent) {
        self.context.counters.maintenance_events =
            self.context.counters.maintenance_events.saturating_add(1);
        match event {
            MaintenanceEvent::PrefixErasure => self.context.erase_idle_prefixes(),
            MaintenanceEvent::ClockDriftCheck => self.context.check_drift(),
            MaintenanceEvent::RetentionSweep | MaintenanceEvent::CheckpointDue => {
                self.router.maintenance(&mut self.context, event);
            }
        }
    }

    /// Drives the pending batch and routes any rejections.
    fn step_batch(&mut self) -> Option<StateCoreExit> {
        if self.admin_pending.is_some()
            || self.reload_provisional.is_some()
            || self.checkpoint_pending.is_some()
        {
            return None;
        }
        match self.context.drive_batch() {
            Ok(BatchStep::Rejected(rejections)) => {
                self.report_rejections(rejections);
                None
            }
            Ok(BatchStep::AppliedInStep(count)) => {
                self.router.batch_applied(&mut self.context, count);
                None
            }
            Ok(_) => None,
            Err(exit) => Some(exit),
        }
    }

    fn report_rejections(&mut self, rejections: Vec<Rejection>) {
        for mut rejection in rejections {
            if let Some(observation) = rejection
                .origin
                .as_mut()
                .and_then(StagedOrigin::take_observation)
            {
                self.context.complete_command_observation(
                    observation,
                    storage_rejection_result(rejection.error),
                );
            }
            self.router
                .batch_rejected(&mut self.context, rejection.origin, rejection.error);
        }
    }

    /// Fires every due timer; `Some` ends the loop.
    pub fn step_wake(&mut self) -> Option<StateCoreExit> {
        let now = self.context.now();
        self.context.erase_idle_prefixes_at(now);
        while let Some(entry) = self.context.timers.pop_due(now) {
            self.context.counters.timers_fired =
                self.context.counters.timers_fired.saturating_add(1);
            self.router.timer_fired(&mut self.context, entry);
        }
        self.step_batch()
    }

    /// Consumes one storage receipt and starts bounded index readback.
    fn step_completion(&mut self, message: StorageCompletionMessage) -> CompletionStep {
        if self.admin_pending.is_some() {
            return self.step_admin_completion(message);
        }
        match self.context.consume_completion(message) {
            Ok(BatchStep::Rejected(rejections)) => self.report_rejections(rejections),
            Ok(BatchStep::AppliedInStep(count)) => {
                self.checkpoint_retry_suppressed = false;
                self.router.batch_applied(&mut self.context, count);
            }
            Ok(_) => {}
            Err(exit) => return CompletionStep::Ready(Some(exit)),
        }
        CompletionStep::Refresh(IndexRefreshContinuation::Batch)
    }

    fn start_index_refresh(
        &mut self,
        continuation: IndexRefreshContinuation,
    ) -> Result<Option<PendingIndexRefresh>, StateCoreExit> {
        let rows = self.context.pending_index_rows();
        if rows.is_empty() {
            self.complete_index_refresh(continuation)?;
            return Ok(None);
        }
        let pending = PendingIndexRefresh::new(
            rows,
            self.context.head.storage_commit_sequence,
            continuation,
        )
        .map_err(|_| StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed))?;
        self.continue_index_refresh(pending)
    }

    fn advance_index_refresh(
        &mut self,
        mut pending: PendingIndexRefresh,
        message: StorageReadCompletionMessage,
    ) -> Result<Option<PendingIndexRefresh>, StateCoreExit> {
        pending
            .complete_read(message)
            .map_err(|_| StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed))?;
        self.continue_index_refresh(pending)
    }

    fn continue_index_refresh(
        &mut self,
        mut pending: PendingIndexRefresh,
    ) -> Result<Option<PendingIndexRefresh>, StateCoreExit> {
        match pending
            .submit_next(&mut self.context.bridge)
            .map_err(|_| StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed))?
        {
            IndexReadSubmission::Submitted | IndexReadSubmission::Blocked => Ok(Some(pending)),
            IndexReadSubmission::Complete => {
                let continuation = pending
                    .finish(&mut self.context.index)
                    .map_err(|_| StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed))?;
                self.complete_index_refresh(continuation)?;
                Ok(None)
            }
        }
    }

    fn complete_index_refresh(
        &mut self,
        continuation: IndexRefreshContinuation,
    ) -> Result<(), StateCoreExit> {
        if let Some(activation) = continuation.reload_activation() {
            let result = match &continuation {
                IndexRefreshContinuation::Admin(reply) => reply
                    .reload_result()
                    .ok_or(StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed))?,
                IndexRefreshContinuation::Batch => {
                    return Err(StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed));
                }
            };
            let provisional = self
                .reload_provisional
                .as_mut()
                .ok_or(StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed))?;
            if provisional.activation != activation {
                return Err(StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed));
            }
            provisional.state = match (&provisional.state, result) {
                (AuditedReloadState::CommittingSuccess { .. }, AuditedReloadResult::Success) => {
                    AuditedReloadState::DurableSuccess
                }
                (
                    AuditedReloadState::CommittingFailure {
                        rejection: expected,
                    },
                    AuditedReloadResult::Failure(actual),
                ) if *expected == actual => AuditedReloadState::DurableFailure,
                _ => {
                    return Err(StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed));
                }
            };
        }
        continuation.complete();
        Ok(())
    }

    /// Runs the actor until it exits (spec 21.3 channel table, lines
    /// 4077-4090).
    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=single bounded select owns actor cancellation completion inbox crypto and timer ordering
    // agenc-review: allow owner=runtime reviewed=2026-08-31 reason=the sole actor select names every independently bounded completion and control receiver at its ownership boundary
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &mut self,
        mut inbox: mpsc::Receiver<StateCoreMessage>,
        mut physical_closes: ConnectionCloseInbox,
        mut lifecycle: mpsc::Receiver<LifecycleRequest>,
        mut storage: mpsc::Receiver<StorageCompletionMessage>,
        mut storage_reads: mpsc::Receiver<StorageReadCompletionMessage>,
        mut checkpoints: mpsc::Receiver<StorageCheckpointCompletionMessage>,
        mut crypto: mpsc::Receiver<CryptoCompletionMessage<CryptoJobOutput>>,
        token: CancellationToken,
    ) -> StateCoreExit {
        let mut storage_reads_open = true;
        let mut crypto_open = true;
        let mut cancellation_open = true;
        let mut lifecycle_open = true;
        let mut physical_closes_open = true;
        let mut cancellation_pending = false;
        let mut lifecycle_target = None;
        let mut lifecycle_completed = None;
        let mut lifecycle_replies = PendingLifecycleReplies::default();
        let mut shutdown_connections_started = false;
        let mut shutdown_acknowledgements = Vec::new();
        let mut shutdown_checkpoint_attempted = false;
        let mut shutdown_checkpoint_complete = false;
        let mut shutdown_checkpoint_failed = false;
        let mut index_refresh = None;
        let mut index_refresh_retry = tokio::time::interval(INDEX_REFRESH_RETRY_INTERVAL);
        index_refresh_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        index_refresh_retry.tick().await;
        let mut flush_poll = tokio::time::interval(SHUTDOWN_FLUSH_POLL);
        flush_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        flush_poll.tick().await;
        let mut progress = tokio::time::interval(PROGRESS_INTERVAL);
        progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        progress.tick().await;
        loop {
            let refresh_in_flight = index_refresh.is_some();
            let refresh_blocked = index_refresh
                .as_ref()
                .is_some_and(|pending: &PendingIndexRefresh| pending.waiting.is_none());
            let in_flight = self.storage_in_flight() || refresh_in_flight;
            let safe_point =
                !in_flight && self.context.pending_len() == 0 && self.router.reload_ready();
            if safe_point {
                if self.reload_pending.is_some()
                    && let Some(exit) = self.activate_pending_reload()
                {
                    return exit;
                }
                let activation_barrier =
                    self.reload_pending.is_some() || self.reload_provisional.is_some();
                if !activation_barrier
                    && lifecycle_target.is_some_and(|phase| phase >= LifecyclePhase::Drain)
                    && !lifecycle_completed.is_some_and(|phase| phase >= LifecyclePhase::Drain)
                {
                    if !shutdown_connections_started {
                        shutdown_acknowledgements = self.begin_connection_shutdown();
                        shutdown_connections_started = true;
                    }
                    lifecycle_replies.acknowledge(LifecyclePhase::Drain);
                    lifecycle_completed = Some(LifecyclePhase::Drain);
                }
                if !activation_barrier
                    && lifecycle_target.is_some_and(|phase| phase >= LifecyclePhase::Flush)
                    && !lifecycle_completed.is_some_and(|phase| phase >= LifecyclePhase::Flush)
                    && shutdown_acknowledgements
                        .iter()
                        .all(FlushAcknowledgement::is_acknowledged)
                    && !shutdown_checkpoint_attempted
                    && !shutdown_checkpoint_failed
                {
                    match self.start_integrity_checkpoint(true) {
                        Ok(started) => shutdown_checkpoint_attempted = started,
                        Err(exit) => return exit,
                    }
                }
                if !activation_barrier
                    && lifecycle_target.is_some_and(|phase| phase >= LifecyclePhase::Flush)
                    && !lifecycle_completed.is_some_and(|phase| phase >= LifecyclePhase::Flush)
                    && shutdown_checkpoint_complete
                    && shutdown_acknowledgements
                        .iter()
                        .all(FlushAcknowledgement::is_acknowledged)
                {
                    lifecycle_replies.acknowledge(LifecyclePhase::Flush);
                    lifecycle_completed = Some(LifecyclePhase::Flush);
                }
                if !activation_barrier && lifecycle_target.is_none() {
                    match self.start_integrity_checkpoint(false) {
                        Ok(_started) => {}
                        Err(exit) => return exit,
                    }
                }
                if cancellation_pending && !activation_barrier && self.checkpoint_pending.is_none()
                {
                    return StateCoreExit::Cancelled;
                }
            }
            let activation_barrier =
                self.reload_pending.is_some() || self.reload_provisional.is_some();
            let provisional_barrier = self.reload_provisional.is_some();
            let waiting_for_shutdown_flush = safe_point
                && lifecycle_target.is_some_and(|phase| phase >= LifecyclePhase::Flush)
                && !lifecycle_completed.is_some_and(|phase| phase >= LifecyclePhase::Flush)
                && !shutdown_checkpoint_failed
                && (shutdown_acknowledgements
                    .iter()
                    .any(|acknowledgement| !acknowledgement.is_acknowledged())
                    || !shutdown_checkpoint_attempted);
            let wake = self.wake_instant();
            let prefix_wake = self.prefix_wake_instant();
            let exit = tokio::select! {
                biased;
                () = token.cancelled(), if cancellation_open => {
                    cancellation_open = false;
                    cancellation_pending = true;
                    self.context.quiescing = true;
                    (safe_point
                        && !activation_barrier
                        && self.checkpoint_pending.is_none())
                    .then_some(StateCoreExit::Cancelled)
                },
                request = lifecycle.recv(), if lifecycle_open => match request {
                    Some(request) => {
                        let (requested, reply) = request.into_parts();
                        self.context.quiescing = true;
                        if requested == LifecyclePhase::Stop {
                            lifecycle_replies.supersede();
                            let _sent = reply.send(Ok(()));
                            Some(StateCoreExit::Stopped)
                        } else if lifecycle_completed.is_some_and(|current| current >= requested) {
                            let _sent = reply.send(Ok(()));
                            None
                        } else if lifecycle_target.is_some_and(|current| current >= requested) {
                            let _sent = reply.send(Err(LifecycleFailure::Busy));
                            None
                        } else {
                            lifecycle_target = Some(requested);
                            if requested == LifecyclePhase::Quiesce {
                                let _sent = reply.send(Ok(()));
                                lifecycle_completed = Some(LifecyclePhase::Quiesce);
                            } else {
                                lifecycle_replies.install(requested, reply);
                            }
                            None
                        }
                    }
                    None => {
                        lifecycle_open = false;
                        None
                    }
                },
                _ = progress.tick() => {
                    self.liveness.record_state_core(self.context.now());
                    if let Some(observer) = &self.context.observer {
                        let client_queues = self.context.sessions.queue_snapshot();
                        observer.queue_depth(
                            QueueName::ClientWriter,
                            client_queues.queued_bytes(),
                        );
                        observer.queue_depth(
                            QueueName::StateCoreInbox,
                            usize_u64(inbox.len().saturating_add(physical_closes.len())),
                        );
                        observer.queue_depth(
                            QueueName::StorageBatches,
                            usize_u64(self.context.bridge.in_flight()),
                        );
                        observer.queue_depth(
                            QueueName::StorageCompletions,
                            usize_u64(storage.len()),
                        );
                        observer.queue_depth(QueueName::CryptoJobs, usize_u64(crypto.len()));
                        observer.queue_depth(
                            QueueName::SignalMaintenance,
                            usize_u64(lifecycle.len()),
                        );
                    }
                    None
                },
                notice = physical_closes.recv(), if physical_closes_open && !provisional_barrier => {
                    match notice {
                        Some(notice) => self.step_physical_close(notice),
                        None => {
                            physical_closes_open = false;
                            None
                        }
                    }
                },
                () = tokio::time::sleep_until(prefix_wake.unwrap_or_else(Instant::now)), if prefix_wake.is_some() && !provisional_barrier => {
                    self.context.erase_idle_prefixes();
                    None
                },
                request = self.admin_receiver.recv(), if self.admin_open && !in_flight && self.context.pending_len() == 0 && !activation_barrier => match request {
                    Some(request) => self.step_admin_request(request),
                    None => {
                        self.admin_open = false;
                        None
                    }
                },
                request = self.reload_receiver.recv(), if self.reload_open => match request {
                    Some(request) => self.step_reload_request(request),
                    None => {
                        self.reload_open = false;
                        None
                    }
                },
                completion = checkpoints.recv() => match completion {
                    Some(message) => match self.step_checkpoint_completion(message) {
                        CheckpointCompletionStep::Normal => None,
                        CheckpointCompletionStep::ShutdownComplete => {
                            shutdown_checkpoint_complete = true;
                            None
                        }
                        CheckpointCompletionStep::ShutdownRejected => {
                            shutdown_checkpoint_failed = true;
                            lifecycle_replies.fail(
                                LifecyclePhase::Flush,
                                LifecycleFailure::Unavailable,
                            );
                            None
                        }
                        CheckpointCompletionStep::Exit(exit) => Some(exit),
                    },
                    None => Some(StateCoreExit::Indeterminate(
                        IndeterminateCause::CompletionChannelClosed,
                    )),
                },
                completion = storage.recv() => match completion {
                    Some(message) => match self.step_completion(message) {
                        CompletionStep::Ready(exit) => exit,
                        CompletionStep::Refresh(continuation) => {
                            match self.start_index_refresh(continuation) {
                                Ok(pending) => {
                                    let complete = pending.is_none();
                                    index_refresh = pending;
                                    if complete {
                                        self.step_batch()
                                    } else {
                                        None
                                    }
                                }
                                Err(exit) => Some(exit),
                            }
                        }
                    },
                    None => Some(StateCoreExit::Indeterminate(
                        IndeterminateCause::CompletionChannelClosed,
                    )),
                },
                completion = storage_reads.recv(), if storage_reads_open && (!provisional_barrier || refresh_in_flight) => {
                    match completion {
                        Some(message) => {
                            if index_refresh
                                .as_ref()
                                .is_some_and(|pending| pending.owns(message.read_id))
                            {
                                match index_refresh.take() {
                                    Some(pending) => {
                                        match self.advance_index_refresh(pending, message) {
                                            Ok(next) => {
                                                let complete = next.is_none();
                                                index_refresh = next;
                                                if complete {
                                                    self.step_batch()
                                                } else {
                                                    None
                                                }
                                            }
                                            Err(exit) => Some(exit),
                                        }
                                    }
                                    None => Some(StateCoreExit::Corrupt(
                                        CorruptionCause::IndexRefreshFailed,
                                    )),
                                }
                            } else {
                                let refresh_step = if index_refresh
                                    .as_ref()
                                    .is_some_and(|pending| pending.waiting.is_none())
                                {
                                    match index_refresh.take() {
                                        Some(pending) => {
                                            match self.continue_index_refresh(pending) {
                                                Ok(next) => {
                                                    let complete = next.is_none();
                                                    index_refresh = next;
                                                    Ok(complete)
                                                }
                                                Err(exit) => Err(exit),
                                            }
                                        }
                                        None => Err(StateCoreExit::Corrupt(
                                            CorruptionCause::IndexRefreshFailed,
                                        )),
                                    }
                                } else {
                                    Ok(false)
                                };
                                match refresh_step {
                                    Ok(complete) => {
                                        self.router.storage_read_completed(
                                            &mut self.context,
                                            message,
                                        );
                                        if complete {
                                            self.step_batch()
                                        } else {
                                            None
                                        }
                                    }
                                    Err(exit) => Some(exit),
                                }
                            }
                        }
                        None => {
                            storage_reads_open = false;
                            index_refresh.is_some().then_some(StateCoreExit::Corrupt(
                                CorruptionCause::IndexRefreshFailed,
                            ))
                        }
                    }
                },
                _ = index_refresh_retry.tick(), if refresh_blocked => {
                    match index_refresh.take() {
                        Some(pending) => match self.continue_index_refresh(pending) {
                            Ok(next) => {
                                let complete = next.is_none();
                                index_refresh = next;
                                if complete {
                                    self.step_batch()
                                } else {
                                    None
                                }
                            }
                            Err(exit) => Some(exit),
                        },
                        None => Some(StateCoreExit::Corrupt(
                            CorruptionCause::IndexRefreshFailed,
                        )),
                    }
                },
                completion = crypto.recv(), if crypto_open && !provisional_barrier => {
                    match completion {
                        Some(message) => self.router.crypto_completed(&mut self.context, message),
                        None => crypto_open = false,
                    }
                    None
                },
                message = inbox.recv(), if !in_flight && !activation_barrier => match message {
                    Some(StateCoreMessage::Opened { .. }) if self.context.quiescing => None,
                    Some(message) => self.step_message(message),
                    None => Some(StateCoreExit::InboxClosed),
                },
                _ = flush_poll.tick(), if waiting_for_shutdown_flush => None,
                () = tokio::time::sleep_until(wake.unwrap_or_else(Instant::now)), if wake.is_some() && !refresh_in_flight && !provisional_barrier => {
                    self.step_wake()
                },
            };
            if let Some(exit) = exit {
                return exit;
            }
        }
    }

    fn wake_instant(&mut self) -> Option<Instant> {
        let deadline = self.context.next_wake()?;
        let now = self.context.now();
        let delay = deadline.get().saturating_sub(now.get());
        Some(Instant::now() + Duration::from_millis(delay))
    }

    fn prefix_wake_instant(&self) -> Option<Instant> {
        let deadline = self.context.prefixes.next_erasure_deadline()?;
        let now = self.context.now();
        let delay = deadline.get().saturating_sub(now.get());
        Some(Instant::now() + Duration::from_millis(delay))
    }
}

fn invite_reload_floor_accepts(limits: OperationalLimits, usage: OperationalUsage) -> bool {
    let limits = limits.values();
    usage.invites_per_channel <= limits.invites_per_channel
        && usage.invites_per_principal <= limits.invites_per_principal
        && usage.invites_global <= limits.invites_global
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn invite_limits() -> Result<OperationalLimits, DomainError> {
        OperationalLimits::new(agenc_ircd_domain::OperationalLimitValues {
            sessions_per_account: 8,
            channels_per_session: 64,
            members_per_channel: 4_096,
            global_channels: 100_000,
            local_channels: 10_000,
            invites_per_channel: 3,
            invites_per_principal: 2,
            invites_global: 4,
            contacts_per_account: 1_000,
        })
    }

    #[test]
    fn invite_reload_floor_checks_each_live_counter() -> Result<(), DomainError> {
        let limits = invite_limits()?;
        let exact = OperationalUsage {
            invites_per_channel: 3,
            invites_per_principal: 2,
            invites_global: 4,
            ..OperationalUsage::default()
        };
        assert!(invite_reload_floor_accepts(limits, exact));
        for over in [
            OperationalUsage {
                invites_per_channel: 4,
                ..exact
            },
            OperationalUsage {
                invites_per_principal: 3,
                ..exact
            },
            OperationalUsage {
                invites_global: 5,
                ..exact
            },
        ] {
            assert!(!invite_reload_floor_accepts(limits, over));
        }
        Ok(())
    }

    #[tokio::test]
    async fn lifecycle_replies_are_bounded_idempotent_and_stop_supersedes_waiters() {
        let mut pending = PendingLifecycleReplies::default();
        let (drain_reply, drain) = tokio::sync::oneshot::channel();
        pending.install(LifecyclePhase::Drain, drain_reply);
        let (duplicate_reply, duplicate) = tokio::sync::oneshot::channel();
        pending.install(LifecyclePhase::Drain, duplicate_reply);
        assert_eq!(duplicate.await, Ok(Err(LifecycleFailure::Busy)));
        pending.acknowledge(LifecyclePhase::Drain);
        assert_eq!(drain.await, Ok(Ok(())));

        let (flush_reply, flush) = tokio::sync::oneshot::channel();
        pending.install(LifecyclePhase::Flush, flush_reply);
        pending.supersede();
        assert_eq!(flush.await, Ok(Err(LifecycleFailure::Superseded)));
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::{StateCoreExit, StateCoreMessage};
    use crate::cancel::CancellationToken;
    use crate::state_core::inbox::{
        LifecycleControl, LifecyclePhase, MaintenanceEvent, SignalEvent, connection_close_channel,
        lifecycle_channel,
    };
    use crate::test_support::{StateCoreFixture, TestResult};

    /// Runs the actor with fresh control channels and returns its exit
    /// together with whatever the driver produced. The driver must keep the
    /// inbox sender alive until the actor exits, otherwise the closed inbox
    /// ends the run first.
    async fn run_core<Driver, Output>(
        registration: bool,
        driver: impl FnOnce(
            mpsc::Sender<StateCoreMessage>,
            LifecycleControl,
            CancellationToken,
        ) -> Driver,
    ) -> TestResult<(StateCoreExit, Output)>
    where
        Driver: Future<Output = TestResult<Output>>,
    {
        let mut fixture = if registration {
            StateCoreFixture::with_registration_router(vec![5; 4_096])?
        } else {
            StateCoreFixture::new(Vec::new())?
        };
        let mut parts = fixture.take_run_parts()?;
        let (inbox, inbox_receiver) = mpsc::channel(8);
        let (_close_port, close_inbox) = connection_close_channel();
        let (lifecycle, lifecycle_receiver) = lifecycle_channel();
        let token = CancellationToken::root();
        let driven = driver(inbox, lifecycle, token.child()?);
        let run = parts.state.run(
            inbox_receiver,
            close_inbox,
            lifecycle_receiver,
            parts.storage,
            parts.storage_reads,
            parts.checkpoints,
            parts.crypto,
            token,
        );
        let (exit, output) = tokio::join!(run, driven);
        Ok((exit, output?))
    }

    async fn send(inbox: &mpsc::Sender<StateCoreMessage>, message: StateCoreMessage) -> TestResult {
        inbox
            .send(message)
            .await
            .map_err(|_| "the core closed its inbox")?;
        Ok(())
    }

    #[tokio::test]
    async fn ordered_lifecycle_requests_stop_an_idle_core() -> TestResult {
        let (exit, (_open, replies)) = run_core(false, |inbox, lifecycle, _token| async move {
            let mut replies = Vec::new();
            for phase in [
                LifecyclePhase::Quiesce,
                LifecyclePhase::Quiesce,
                LifecyclePhase::Drain,
                LifecyclePhase::Flush,
                LifecyclePhase::Stop,
            ] {
                replies.push(lifecycle.request(phase).await);
            }
            Ok((inbox, replies))
        })
        .await?;
        assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
        assert!(replies.iter().all(Result::is_ok), "{replies:?}");
        Ok(())
    }

    #[tokio::test]
    async fn stop_may_skip_straight_past_earlier_phases() -> TestResult {
        let (exit, (_open, reply)) = run_core(false, |inbox, lifecycle, _token| async move {
            Ok((inbox, lifecycle.request(LifecyclePhase::Stop).await))
        })
        .await?;
        assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
        assert!(reply.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn termination_signals_quiesce_or_interrupt_an_idle_core() -> TestResult {
        let (exit, (_open, _lifecycle)) = run_core(false, |inbox, lifecycle, _token| async move {
            for event in [
                MaintenanceEvent::RetentionSweep,
                MaintenanceEvent::ClockDriftCheck,
                MaintenanceEvent::PrefixErasure,
                MaintenanceEvent::CheckpointDue,
                MaintenanceEvent::CheckpointDue,
            ] {
                send(&inbox, StateCoreMessage::Maintenance(event)).await?;
            }
            send(&inbox, StateCoreMessage::Signal(SignalEvent::Reload)).await?;
            send(&inbox, StateCoreMessage::Signal(SignalEvent::Terminate)).await?;
            Ok((inbox, lifecycle))
        })
        .await?;
        assert!(matches!(exit, StateCoreExit::Quiesced), "{exit:?}");

        let (exit, (_open, _lifecycle)) = run_core(false, |inbox, lifecycle, _token| async move {
            send(&inbox, StateCoreMessage::Signal(SignalEvent::Interrupt)).await?;
            Ok((inbox, lifecycle))
        })
        .await?;
        assert!(matches!(exit, StateCoreExit::Interrupted), "{exit:?}");
        Ok(())
    }

    #[tokio::test]
    async fn a_guest_session_registers_and_commands_flow_through_the_router() -> TestResult {
        use agenc_ircd_client_wire::{FramedLine, parse_message};
        use tokio::sync::oneshot;

        use crate::connection::{ClientSink, ConnectionGeneration};
        use crate::purpose::ListenerPurpose;
        use crate::state_core::inbox::{ConnectionOpenOutcome, SourceAddressKey};
        use crate::sync::Arc;
        use crate::test_support::FrameSink;

        const LINES: &[&str] = &[
            "CAP LS 302",
            "NICK alice",
            "USER alice 0 * :Alice",
            "CAP REQ :multi-prefix userhost-in-names",
            "CAP END",
            "PING :probe",
            "JOIN #room",
            "TOPIC #room :welcome",
            "NAMES #room",
            "WHO #room",
            "MODE #room +m",
            "PRIVMSG #room :hello",
            "AWAY :busy",
            "AWAY",
            "LIST",
            "MOTD",
            "PART #room :bye",
            "JOIN #room",
            "QUIT :done",
        ];
        let generation = ConnectionGeneration::new(1);
        let sink = FrameSink::new(generation, true);
        let core_sink = Arc::clone(&sink) as Arc<dyn ClientSink>;
        let (exit, (_open, outcome, stopped)) =
            run_core(true, |inbox, lifecycle, _token| async move {
                let (acknowledgement, accepted) = oneshot::channel();
                send(
                    &inbox,
                    StateCoreMessage::Opened {
                        generation,
                        purpose: ListenerPurpose::ClientOnion,
                        source: SourceAddressKey::onion_listener(),
                        sink: core_sink,
                        acknowledgement,
                    },
                )
                .await?;
                let outcome = accepted.await?;
                for (index, line) in LINES.iter().enumerate() {
                    let message = parse_message(FramedLine::new(line)?)?.ok_or("empty line")?;
                    send(
                        &inbox,
                        StateCoreMessage::Line {
                            generation,
                            sequence: u64::try_from(index)? + 1,
                            message: Box::new(message),
                        },
                    )
                    .await?;
                }
                let stopped = lifecycle.request(LifecyclePhase::Stop).await;
                Ok((inbox, outcome, stopped))
            })
            .await?;
        assert!(matches!(outcome, ConnectionOpenOutcome::Accepted));
        assert!(stopped.is_ok());
        assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
        assert!(sink.commits() > 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_closed_inbox_exits_the_core() -> TestResult {
        let (exit, ()) = run_core(false, |inbox, _lifecycle, _token| async move {
            drop(inbox);
            Ok(())
        })
        .await?;
        assert!(matches!(exit, StateCoreExit::InboxClosed));
        Ok(())
    }
}
