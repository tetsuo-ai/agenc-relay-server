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

pub mod durable;
pub mod fanout;
pub mod inbox;
mod pending;
pub mod reconstruct;
pub mod session;
pub mod timers;

use std::fmt;
use std::time::Duration;

use agenc_ircd_client_wire::{ParsedMessage, WireMessage, numeric_reply};
use agenc_ircd_crypto::OpenedStoragePlaintext;
use agenc_ircd_domain::{ApplyReceipt, DomainError, DomainState, MutationPlan};
use agenc_ircd_storage::{CommitOutcome, ReadPlan, SealedRecord, StorageError, StoredKey, TableId};
use agenc_ircd_types::{
    ClockError, EntropySource, MonotonicClock, MonotonicTick, TransactionId, UserId, UtcSecond,
    WallClock,
};
use tokio::sync::mpsc;
use tokio::time::Instant;

pub use pending::{GATHER_WINDOW_MILLIS, MAX_BATCH_PLANS, StagedOrigin};

use crate::RuntimeError;
use crate::admission::{
    BucketKey, BucketTable, OverloadClass, OverloadState, PrefixRegistry, RateLimits,
};
use crate::bridge::crypto::{CryptoBridge, CryptoJobOutput};
use crate::bridge::storage::{BridgeFailure, StorageBridge, SubmitError};
use crate::bridge::{
    CryptoCompletionMessage, StorageCompletionMessage, StorageReadCompletionMessage, StorageReadId,
};
use crate::budget::MemoryBudget;
use crate::cancel::CancellationToken;
use crate::connection::sink::ConnectionGeneration;
use crate::state_core::durable::{
    AccountServiceDurableWrite, AccountingCeilings, DurableIndex, HeadCounters, KeyDeriver,
    PlanProjection, project_batch, read_back,
};
use crate::state_core::fanout::{
    FanoutCommitReport, FanoutFrame, FanoutRefused, FanoutRequest, FanoutReservation, FanoutTarget,
    reserve,
};
use crate::state_core::inbox::{
    CloseReason, MaintenanceEvent, SignalEvent, SourceAddressKey, StateCoreMessage,
};
use crate::state_core::pending::{PendingMutationBatch, StagedPlan};
use crate::state_core::reconstruct::Reconstruction;
use crate::state_core::session::SessionTable;
use crate::state_core::timers::{DriftMonitor, TimerEntry, TimerHeap};
use crate::sync::Arc;

/// The numeric a registered session receives for an unknown command.
const ERR_UNKNOWNCOMMAND: u16 = 421;
/// The numeric an unregistered connection receives for a post-registration
/// command.
const ERR_NOTREGISTERED: u16 = 451;

/// Fixed configuration the state owner runs with.
pub struct StateCoreConfig {
    /// The server prefix used on every rendered frame.
    pub server_prefix: String,
    /// The configured rate rows (spec 19.1).
    pub rate_limits: RateLimits,
    /// The configured storage ceilings.
    pub ceilings: AccountingCeilings,
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
    /// The explicit clocks.
    pub clocks: StateCoreClocks,
    /// The entropy source for identities and keys.
    pub entropy: Box<dyn EntropySource + Send>,
    /// The command router.
    pub router: Box<dyn CommandRouter>,
}

/// What a router asks the loop to do after handling one line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteOutcome {
    /// Keep serving the connection.
    Continue,
    /// Close the connection for the given reason.
    Close(CloseReason),
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
        if let Ok(frame) = reply {
            let _refused = context.send_to(generation, vec![frame]);
        }
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
}

impl fmt::Display for StateCoreExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("state core cancelled"),
            Self::InboxClosed => formatter.write_str("state core inbox closed"),
            Self::Quiesced => formatter.write_str("state core quiesced"),
            Self::Interrupted => formatter.write_str("state core interrupted"),
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
    bridge: StorageBridge,
    crypto: CryptoBridge,
    entropy: Box<dyn EntropySource + Send>,
    monotonic: Box<dyn MonotonicClock + Send>,
    wall: Box<dyn WallClock + Send>,
    server_prefix: String,
    counters: StateCoreCounters,
    quiescing: bool,
}

impl StateCoreContext {
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
        Ok(reservation.commit())
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
        reservation.commit();
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
        let account_service_writes = account_service_writes
            .into_iter()
            .map(AccountServiceDurableWrite::revalidate)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StageRefused::Domain(DomainError::InvariantViolation))?;
        if self.quiescing {
            return Err(StageRefused::Quiescing);
        }
        if self.in_flight() || self.conflicts(&plan) {
            return Err(StageRefused::Busy);
        }
        let reservation = self
            .reserve_fanout(&request)
            .map_err(StageRefused::Fanout)?;
        if plan.durable_writes().is_empty()
            && account_service_writes.is_empty()
            && self.pending.is_none()
        {
            let receipt = self.apply_plan(plan).map_err(StageRefused::Domain)?;
            reservation.commit();
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
                self.pending = Some(
                    PendingMutationBatch::start(staged, now)
                        .map_err(|error| StageRefused::Fanout(FanoutRefused::Invalid(error)))?,
                );
            }
            Some(mut batch) => {
                let joined = batch.try_stage(staged).is_ok();
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

    fn conflicts(&self, plan: &MutationPlan) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|batch| batch.conflicts_with(plan))
    }

    fn reserve_fanout(
        &mut self,
        request: &FanoutRequest,
    ) -> Result<FanoutReservation, FanoutRefused> {
        match reserve(request, self.budget.as_ref()) {
            Ok(reservation) => Ok(reservation),
            Err(refused) => {
                self.counters.fanout_refusals = self.counters.fanout_refusals.saturating_add(1);
                Err(refused)
            }
        }
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
        match (timer, gather) {
            (Some(timer), Some(gather)) => Some(timer.min(gather)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
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
            Err(_) => Err(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed)),
        }
    }

    fn submit_projected(
        &mut self,
        mut batch: PendingMutationBatch,
        projected: durable::ProjectedBatch,
    ) -> Result<BatchStep, StateCoreExit> {
        let (storage_batch, retained) = projected.into_parts();
        match self.bridge.submit(storage_batch) {
            Ok(transaction_id) => {
                batch.mark_in_flight(transaction_id, retained);
                self.pending = Some(batch);
                Ok(BatchStep::Submitted)
            }
            Err(SubmitError::Storage(error)) => {
                Ok(BatchStep::Rejected(self.reject_batch(batch, error)))
            }
            Err(SubmitError::Bridge(failure)) => Err(StateCoreExit::Indeterminate(
                IndeterminateCause::Bridge(failure),
            )),
        }
    }

    fn apply_batch_in_step(
        &mut self,
        batch: PendingMutationBatch,
    ) -> Result<BatchStep, StateCoreExit> {
        let (plans, _retained) = batch.finish();
        let count = plans.len();
        for staged in plans {
            let (plan, fanout, _origin) = staged.into_parts();
            if self.apply_plan(plan).is_err() {
                return Err(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed));
            }
            fanout.commit();
        }
        Ok(BatchStep::AppliedInStep(count))
    }

    fn reject_batch(&mut self, batch: PendingMutationBatch, error: StorageError) -> Vec<Rejection> {
        self.counters.batches_rejected = self.counters.batches_rejected.saturating_add(1);
        let (plans, _retained) = batch.finish();
        plans
            .into_iter()
            .map(|staged| Rejection {
                origin: staged.origin(),
                error,
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
            CommitOutcome::Indeterminate => Err(StateCoreExit::Indeterminate(
                IndeterminateCause::StorageIndeterminate,
            )),
        }
    }

    fn apply_committed(
        &mut self,
        batch: PendingMutationBatch,
        transaction_id: TransactionId,
        receipt: agenc_ircd_storage::CommitReceipt,
    ) -> Result<BatchStep, StateCoreExit> {
        if receipt.transaction_id != transaction_id {
            return Err(StateCoreExit::Indeterminate(
                IndeterminateCause::TransactionMismatch,
            ));
        }
        let (plans, retained) = batch.finish();
        let Some(retained) = retained else {
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
        for staged in plans {
            let (plan, fanout, _origin) = staged.into_parts();
            if self.apply_plan(plan).is_err() {
                return Err(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed));
            }
            fanout.commit();
        }
        Ok(())
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
        source: SourceAddressKey,
        sink: Arc<dyn crate::connection::sink::ClientSink>,
    ) -> Result<(), RuntimeError> {
        let now = self.now();
        self.sessions.open(generation, purpose, source, sink, now)?;
        self.counters.connections_opened = self.counters.connections_opened.saturating_add(1);
        let _prefix_result = self.prefixes.connection_opened(source.prefix_key(), now);
        self.overload
            .classify(self.budget.charged(), self.budget.capacity());
        Ok(())
    }

    /// Removes one connection and every bucket keyed by it.
    fn release_connection(&mut self, generation: ConnectionGeneration) -> bool {
        let now = self.now();
        let Some(entry) = self.sessions.close(generation) else {
            return false;
        };
        self.counters.connections_closed = self.counters.connections_closed.saturating_add(1);
        let _prefix_result = self
            .prefixes
            .connection_closed(entry.source().prefix_key(), now);
        self.buckets.erase_key(BucketKey::Connection(generation));
        if let Some(session) = entry.session() {
            self.buckets.erase_key(BucketKey::Session(session.user_id));
        }
        true
    }

    fn erase_idle_prefixes(&mut self) {
        let now = self.now();
        for prefix in self.prefixes.erase_idle(now) {
            self.buckets.erase_key(BucketKey::Prefix(prefix));
        }
    }

    fn check_drift(&mut self) {
        let now = self.now();
        let wall = self.wall.utc_now().ok();
        let _transition = self.drift.observe(now, wall);
    }
}

fn next_transaction_id(entropy: &mut dyn EntropySource) -> Result<TransactionId, RuntimeError> {
    let mut bytes = [0_u8; 16];
    entropy
        .fill_exact(&mut bytes)
        .map_err(|_| RuntimeError::Storage(StorageError::Unavailable))?;
    Ok(TransactionId::from_bytes(bytes))
}

/// The actor: the context plus the router that interprets commands.
pub struct StateCore {
    context: StateCoreContext,
    router: Box<dyn CommandRouter>,
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
        let mut state = Self {
            context: StateCoreContext {
                domain: inputs.reconstruction.domain,
                sessions: SessionTable::new(),
                buckets: BucketTable::new(inputs.config.rate_limits),
                prefixes: PrefixRegistry::new(),
                timers: TimerHeap::new(),
                drift: DriftMonitor::new(now, wall),
                pending: None,
                index: inputs.reconstruction.index,
                keys: inputs.keys,
                head: inputs.reconstruction.head,
                ceilings: inputs.config.ceilings,
                overload: OverloadState::new(),
                budget: inputs.budget,
                bridge: inputs.bridge,
                crypto: inputs.crypto,
                entropy: inputs.entropy,
                monotonic: inputs.clocks.monotonic,
                wall: inputs.clocks.wall,
                server_prefix: inputs.config.server_prefix,
                counters: StateCoreCounters::default(),
                quiescing: false,
            },
            router: inputs.router,
        };
        state.router.startup(&mut state.context);
        state
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

    /// Handles one inbox message; `Some` ends the loop.
    pub fn step_message(&mut self, message: StateCoreMessage) -> Option<StateCoreExit> {
        let exit = match message {
            StateCoreMessage::Opened {
                generation,
                purpose,
                source,
                sink,
            } => {
                if self
                    .context
                    .admit_connection(generation, purpose, source, sink)
                    .is_ok()
                {
                    self.router.connection_opened(&mut self.context, generation);
                }
                None
            }
            StateCoreMessage::Line {
                generation,
                message,
            } => {
                self.route_line(generation, *message);
                None
            }
            StateCoreMessage::Closed { generation, reason } => {
                if self.context.release_connection(generation) {
                    self.router
                        .connection_closed(&mut self.context, generation, reason);
                }
                None
            }
            StateCoreMessage::Signal(signal) => self.step_signal(signal),
            StateCoreMessage::Maintenance(event) => {
                self.step_maintenance(event);
                None
            }
        };
        exit.or_else(|| self.step_batch())
    }

    fn route_line(&mut self, generation: ConnectionGeneration, message: ParsedMessage) {
        if self.context.sessions.connection(generation).is_none() {
            self.context.counters.lines_dropped =
                self.context.counters.lines_dropped.saturating_add(1);
            return;
        }
        self.context.counters.lines_routed = self.context.counters.lines_routed.saturating_add(1);
        if let RouteOutcome::Close(_reason) =
            self.router.route(&mut self.context, generation, message)
        {
            // The sink contract exposes one close path; the transport owner
            // ends the connection and reports it back through `Closed`.
            if let Some(sink) = self.context.sessions.sink_for_generation(generation) {
                sink.begin_slow_consumer_close();
            }
            self.context.sessions.mark_sink_gone(generation);
        }
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
        for rejection in rejections {
            self.router
                .batch_rejected(&mut self.context, rejection.origin, rejection.error);
        }
    }

    /// Fires every due timer; `Some` ends the loop.
    pub fn step_wake(&mut self) -> Option<StateCoreExit> {
        let now = self.context.now();
        while let Some(entry) = self.context.timers.pop_due(now) {
            self.context.counters.timers_fired =
                self.context.counters.timers_fired.saturating_add(1);
            self.router.timer_fired(&mut self.context, entry);
        }
        self.step_batch()
    }

    /// Consumes one storage receipt, applies committed plans, and reads the
    /// written rows back into the index; `Some` ends the loop.
    pub async fn step_completion(
        &mut self,
        message: StorageCompletionMessage,
    ) -> Option<StateCoreExit> {
        match self.context.consume_completion(message) {
            Ok(BatchStep::Rejected(rejections)) => self.report_rejections(rejections),
            Ok(BatchStep::AppliedInStep(count)) => {
                self.router.batch_applied(&mut self.context, count);
            }
            Ok(_) => {}
            Err(exit) => return Some(exit),
        }
        if let Some(exit) = self.refresh_index().await {
            return Some(exit);
        }
        if self.context.quiescing {
            return Some(StateCoreExit::Quiesced);
        }
        self.step_batch()
    }

    async fn refresh_index(&mut self) -> Option<StateCoreExit> {
        let rows = self.context.pending_index_rows();
        if rows.is_empty() {
            return None;
        }
        let port = self.context.bridge.port().clone();
        let joined = tokio::task::spawn_blocking(move || read_back(&port, rows)).await;
        let Ok(Ok(refreshed)) = joined else {
            return Some(StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed));
        };
        if self.context.index.refresh(refreshed).is_err() {
            return Some(StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed));
        }
        None
    }

    /// Runs the actor until it exits (spec 21.3 channel table, lines
    /// 4077-4090).
    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=single bounded select owns actor cancellation completion inbox crypto and timer ordering
    pub async fn run(
        &mut self,
        mut inbox: mpsc::Receiver<StateCoreMessage>,
        mut storage: mpsc::Receiver<StorageCompletionMessage>,
        mut storage_reads: mpsc::Receiver<StorageReadCompletionMessage>,
        mut crypto: mpsc::Receiver<CryptoCompletionMessage<CryptoJobOutput>>,
        token: CancellationToken,
    ) -> StateCoreExit {
        let mut storage_reads_open = true;
        let mut crypto_open = true;
        let mut cancellation_open = true;
        loop {
            let in_flight = self.context.in_flight();
            let wake = self.wake_instant();
            let exit = tokio::select! {
                biased;
                () = token.cancelled(), if cancellation_open => {
                    cancellation_open = false;
                    self.context.quiescing = true;
                    (!in_flight).then_some(StateCoreExit::Cancelled)
                },
                completion = storage.recv() => match completion {
                    Some(message) => self.step_completion(message).await,
                    None => Some(StateCoreExit::Indeterminate(
                        IndeterminateCause::CompletionChannelClosed,
                    )),
                },
                completion = storage_reads.recv(), if storage_reads_open => {
                    match completion {
                        Some(message) => {
                            self.router.storage_read_completed(&mut self.context, message);
                        }
                        None => storage_reads_open = false,
                    }
                    None
                },
                completion = crypto.recv(), if crypto_open => {
                    match completion {
                        Some(message) => self.router.crypto_completed(&mut self.context, message),
                        None => crypto_open = false,
                    }
                    None
                },
                message = inbox.recv(), if !in_flight => match message {
                    Some(message) => self.step_message(message),
                    None => Some(StateCoreExit::InboxClosed),
                },
                () = tokio::time::sleep_until(wake.unwrap_or_else(Instant::now)), if wake.is_some() => {
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
}
