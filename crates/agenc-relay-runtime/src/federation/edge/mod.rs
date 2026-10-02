//! The edge role of the base federation profile (spec 20).
//!
//! An edge owns client connections and a read-only replica of the
//! coordinator's projection for this server. Every global mutation or query
//! becomes a durable `FederationRequest`; the coordinator's events drive the
//! replica and the client-visible lines. The registration router hosts one
//! instance and forwards the seams that differ from a coordinator: session
//! open and close, registered commands, and connection origins.

mod barrier;
mod directory;
mod events;
mod fence;
mod history;
mod join_echo;
mod journal;
mod journal_retry;
mod ordinary_batch;
pub(crate) use render::prefix as source_prefix;
mod render;
mod request;
mod retention;
mod revocations;
mod startup;
mod sync;
#[cfg(test)]
#[path = "tests/harness.rs"]
mod tests;

#[cfg(test)]
pub(crate) use sync::pending_generation::{host_channels, host_nothing};
#[cfg(test)]
pub(crate) use tests::committed_ordinary_acknowledgements;

use std::collections::{BTreeMap, VecDeque};

use agenc_relay_domain::NicknameValue;
use agenc_relay_domain::federation::EdgeReplica;
use agenc_relay_federation_wire::{
    EventHeader, FederationFrame, FederationLineText, federation_object_id, split_fragments,
};
use agenc_relay_types::{
    AccountId, ConnectionId, EventId, NetworkId, OriginId, RecoveryEpoch, RequestId, ServerId,
    ServerIncarnation, SessionId, UserId,
};

use crate::RuntimeError;
use crate::connection::ConnectionGeneration;
use crate::e2ee::link::{
    CompanionAction, CompanionLinks, CompanionProfile, CompanionViolation, tick_millis,
};
use crate::federation::link::{LinkHandle, SendRefusal};
use crate::federation::{
    FederationInbound, IngressCharge, LinkEvent, LinkId, LinkSession, ObjectCarrier, PeerIdentity,
};
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use agenc_relay_client_wire::RegisteredCommandKind;
use agenc_relay_e2ee::federation::frames::CompanionFrame;
use agenc_relay_types::MonotonicTick;

use crate::observe::health::{ReadinessGate, ReadinessStage};
use crate::state_core::StateCoreContext;
use crate::sync::Arc;

pub(crate) use request::is_local_user_mode_query;
pub use request::{EdgeCompletion, RemoteCarrierOutcome};
pub use startup::{EdgeRestoreCause, EdgeRestoreRefusal, EdgeRestoreStep};

/// Events held while one durable batch is in flight.
const MAX_QUEUED_EVENTS: usize = 256;

/// The fixed edge identity and its coordinator.
pub struct EdgeConfig {
    /// The permanent network identity.
    pub network_id: NetworkId,
    /// This edge's Server ID.
    pub server_id: ServerId,
    /// The local server name used as the prefix of rendered lines.
    pub server_name: String,
    /// This process's incarnation, fresh per process start.
    pub incarnation: ServerIncarnation,
    /// The configured coordinator.
    pub coordinator: PeerIdentity,
}

/// The base origin facts a companion declaration mirrors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseOriginFacts {
    /// The origin identity.
    pub origin_id: [u8; 16],
    /// The current base generation.
    pub generation: u64,
    /// The generation the coordinator acknowledged.
    pub acked_generation: Option<u64>,
    /// The connection identity.
    pub connection_id: [u8; 16],
    /// The connection nonce.
    pub connection_nonce: [u8; 32],
    /// The session and user, when registered.
    pub session: Option<([u8; 16], [u8; 16])>,
    /// The account and its session generation, when authenticated.
    pub account: Option<([u8; 24], u64)>,
}

/// One authenticated live link to the coordinator.
struct LiveLink {
    link: LinkId,
    handle: LinkHandle,
    coordinator_epoch: RecoveryEpoch,
    coordinator_incarnation: ServerIncarnation,
}

/// Where the link is in the synchronization protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// No authenticated link.
    Down,
    /// Origins are being replayed; coordinator READY and exact ACKs gate admission.
    Origins,
    /// FRESUME sent, answer pending.
    Resuming,
    /// A snapshot is being received or installed.
    Snapshot,
    /// Events flow and requests are accepted.
    Active,
}

/// The origin one client connection declares (spec 20.5).
struct ConnectionOrigin {
    pending_updates: VecDeque<agenc_relay_federation_wire::OriginRecord>,
    origin_id: OriginId,
    connection_id: ConnectionId,
    connection_nonce: [u8; 32],
    generation: u64,
    sequence: u64,
    object_id: [u8; 32],
    previous_object_id: [u8; 32],
    session: Option<(SessionId, UserId)>,
    /// The account and its session generation the coordinator registered.
    account: Option<(AccountId, u64)>,
    acked_generation: Option<u64>,
    /// Whether an exact declaration acknowledgement has been received.
    ever_acked: bool,
    /// A committed JOIN still owns its topic and NAMES response.
    join_names_pending: bool,
    /// A committed session removal requires closure after any final receipt.
    revoked: bool,
    deleted: bool,
    del_acked: bool,
}

impl ConnectionOrigin {
    /// Whether a deletion acknowledgement names this closed origin: at the
    /// generation the edge holds, or at the generation of the update still
    /// in flight, which precedes the DEL on the link.
    fn deletion_acknowledged_at(&self, generation: u64) -> bool {
        let declared = self
            .pending_updates
            .front()
            .map_or(self.generation, |update| update.generation);
        self.deleted && (self.generation == generation || declared == generation)
    }
}

/// The durable batch the edge is waiting on.
enum PendingCommit {
    Journal {
        staged_after: u64,
        versions: Vec<journal::Version>,
    },
    History(Box<history::Prepared>),
    HistoryCleanup(crate::federation::history_retention::Cleanup),
    /// One cross-profile part was staged.
    BarrierPart(Box<barrier::OpenBarrier>),
    /// The authenticated replacement coordinator durably fenced the old stage.
    BarrierFence,
    /// A bounded expired barrier cleanup batch.
    BarrierCleanup {
        mutation_id: [u8; 16],
        finished: bool,
    },
    /// The complete barrier applied.
    BarrierApplied {
        receipt: Box<agenc_relay_storage::e2ee_records::barrier::BarrierReceipt>,
        base_last: (u64, EventId),
        companion_last: (u64, u64, [u8; 16]),
        coverage: Vec<journal::Version>,
        join_echoes: Vec<join_echo::JoinEcho>,
        revoked: Vec<ConnectionGeneration>,
    },
    /// An event was applied; ACK follows the commit.
    Event {
        header: Box<EventHeader>,
        completion: Option<RequestId>,
        coverage: Option<journal::Version>,
        join_echo: Option<Box<join_echo::JoinEcho>>,
        revoked: Option<ConnectionGeneration>,
    },
    /// A complete ordinary prefix shares one exclusive storage receipt.
    OrdinaryBatch(Box<ordinary_batch::Pending>),
    /// The pending snapshot generation is durable; READY follows.
    SnapshotInstalled,
    /// Matching ACTIVE is authorized only after the durable generation swap.
    SnapshotActivated {
        coverage: Vec<journal::Version>,
    },
}

/// Counters exposed through STATS FEDERATION on an edge.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EdgeCounters {
    /// Requests sent to the coordinator.
    pub requests_sent: u64,
    /// Results applied.
    pub results_applied: u64,
    /// Events applied to the replica.
    pub events_applied: u64,
    /// Snapshots installed.
    pub snapshots_installed: u64,
    /// Protocol violations that closed the link.
    pub violations: u64,
    /// Cross-profile barriers applied.
    pub barriers_applied: u64,
}

/// The edge's federation state machine.
pub struct EdgeFederation {
    journal: journal::Journal,
    config: EdgeConfig,
    live: Option<LiveLink>,
    phase: Phase,
    origin_ready: bool,
    replica: EdgeReplica,
    cursor: Option<(u64, EventId)>,
    installed_epoch: Option<RecoveryEpoch>,
    installed_incarnation: Option<ServerIncarnation>,
    accepted_epoch: Option<RecoveryEpoch>,
    origins: BTreeMap<ConnectionGeneration, ConnectionOrigin>,
    pending: BTreeMap<RequestId, request::PendingRequest>,
    history: history::HistoryRequests,
    by_completion: BTreeMap<EventId, RequestId>,
    applied_completions: std::collections::BTreeSet<EventId>,
    nicknames: BTreeMap<UserId, NicknameValue>,
    event_before: Option<events::ProjectionBefore>,
    commit: Option<PendingCommit>,
    queued_events: VecDeque<events::QueuedEvent>,
    snapshot: Option<sync::SnapshotInstall>,
    snapshot_cut: Option<(u64, u64)>,
    /// Shutdown has begun: a snapshot install no longer holds the drain
    /// safe point unless one of its own commits is in flight (RUN-11).
    stopping: bool,
    next_origin: u64,
    client_resync_epoch: u64,
    counters: EdgeCounters,
    readiness: Option<Arc<ReadinessGate>>,
    /// Commands waiting for the connection's earlier request to complete,
    /// so the revisions they carry are read from a replica that already
    /// reflects that request (spec 20.5 ordering per origin).
    deferred: BTreeMap<ConnectionGeneration, crate::budget::RetainedQueue<DeferredCommand>>,
    /// The account carrier a connection sent while its origin update awaited the
    /// coordinator's acknowledgement; a carrier is one exchange at a time, so one per
    /// connection.
    deferred_carriers: BTreeMap<ConnectionGeneration, DeferredCarrier>,
    companion: CompanionLinks,
    barrier: barrier::BarrierState,
}

/// One account carrier envelope held back behind the connection's origin update.
pub(super) struct DeferredCarrier {
    pub(super) opcode: agenc_relay_types::FederationOpcode,
    pub(super) envelope: Vec<u8>,
    pub(super) finish: bool,
    pub(super) carrier_generation: u64,
    /// Returned only after the retained envelope has been dropped.
    pub(super) _permit: crate::budget::MemoryPermit,
}

/// One client command held back behind an in-flight request.
pub(super) struct DeferredCommand {
    pub(super) kind: RegisteredCommandKind,
    pub(super) message: Box<agenc_relay_client_wire::ParsedMessage>,
    /// Returned only after the retained parsed command has been dropped.
    pub(super) _permit: crate::budget::MemoryPermit,
}

/// The most commands one connection may queue behind its in-flight
/// request before further commands answer `SERVER_BUSY`.
pub(super) const MAX_DEFERRED_COMMANDS: usize = 32;

/// Why an outbound write did not reach the link task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendFailure {
    /// The frame or the queue violated a bound.
    Violation(Violation),
    /// The link task already ended; its `Closed` event follows.
    Closed,
}

impl From<SendRefusal> for SendFailure {
    fn from(refusal: SendRefusal) -> Self {
        match refusal {
            SendRefusal::QueueFull => Self::Violation(Violation::SlowConsumer),
            SendRefusal::Closed => Self::Closed,
        }
    }
}

impl EdgeFederation {
    /// Creates an edge with no link and an empty replica at the first
    /// projection generation, matching a coordinator that never snapshotted.
    #[must_use]
    pub fn new(config: EdgeConfig) -> Self {
        let mut replica = EdgeReplica::new(config.server_id);
        let _installed = replica.install(1, Vec::new());
        let companion = CompanionLinks::new(None, config.server_name.clone());
        Self {
            journal: journal::Journal::default(),
            companion,
            config,
            live: None,
            phase: Phase::Down,
            origin_ready: false,
            replica,
            cursor: None,
            installed_epoch: None,
            installed_incarnation: None,
            accepted_epoch: None,
            origins: BTreeMap::new(),
            pending: BTreeMap::new(),
            history: history::HistoryRequests::default(),
            by_completion: BTreeMap::new(),
            applied_completions: std::collections::BTreeSet::new(),
            nicknames: BTreeMap::new(),
            event_before: None,
            commit: None,
            queued_events: VecDeque::new(),
            snapshot: None,
            snapshot_cut: None,
            stopping: false,
            next_origin: 1,
            client_resync_epoch: 0,
            counters: EdgeCounters::default(),
            readiness: None,
            deferred: BTreeMap::new(),
            deferred_carriers: BTreeMap::new(),
            barrier: barrier::BarrierState::default(),
        }
    }

    /// Installs the companion profile before any link exists; `None`
    /// refuses every companion frame.
    pub fn set_companion_profile(&mut self, profile: Option<CompanionProfile>) {
        self.companion = CompanionLinks::new(profile, self.config.server_name.clone());
    }

    /// Whether a companion profile is installed on this edge.
    #[must_use]
    pub fn has_companion_profile(&self) -> bool {
        self.companion.has_profile()
    }

    /// Whether the companion profile is active on the live link.
    #[must_use]
    pub fn companion_active(&self) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| self.companion.profile_active(live.link))
    }

    /// Drains the admitted companion frames of the live link.
    pub fn drain_companion(&mut self) -> Vec<CompanionFrame> {
        match self.live.as_ref() {
            Some(live) => self.companion.drain(live.link),
            None => Vec::new(),
        }
    }

    fn handle_companion(
        &mut self,
        frame: CompanionFrame,
    ) -> Result<Vec<EdgeCompletion>, Violation> {
        let Some(live) = self.live.as_ref() else {
            return Ok(Vec::new());
        };
        match self.companion.on_frame(live.link, frame) {
            Ok(CompanionAction::Quiet) => Ok(Vec::new()),
            Ok(CompanionAction::Send(line)) => match live.handle.try_send(line) {
                Ok(()) | Err(SendRefusal::Closed) => Ok(Vec::new()),
                Err(SendRefusal::QueueFull) => Err(Violation::SlowConsumer),
            },
            Err(violation) => {
                if let Ok(line) = self.companion.violation_line() {
                    let _ = live.handle.try_send(line);
                }
                Err(Violation::Companion(violation))
            }
        }
    }

    fn start_companion(&mut self, context: &mut StateCoreContext) {
        let Some(live) = self.live.as_ref() else {
            return;
        };
        let now = context.now();
        let link = live.link;
        match self.companion.link_established(link, tick_millis(now)) {
            Ok(Some(offer)) => {
                let _ = live.handle.try_send(offer);
                let deadline = self
                    .companion
                    .deadline(link)
                    .map_or(now, MonotonicTick::from_ticks);
                let _ = context.timers_mut().schedule(
                    deadline,
                    TimerKind::CompanionProfileDeadline,
                    TimedId::Peer(self.config.coordinator.server_id()),
                );
            }
            Ok(None) => {}
            Err(violation) => self.fail_link(context, Violation::Companion(violation)),
        }
    }

    /// Handles a due timer; returns `false` when it was not the edge's.
    pub fn timer_fired(&mut self, context: &mut StateCoreContext, entry: TimerEntry) -> bool {
        if journal_retry::timer_fired(self, context, entry) {
            return true;
        }
        let (TimerKind::CompanionProfileDeadline, TimedId::Peer(peer)) = (entry.kind, entry.id)
        else {
            return false;
        };
        if peer != self.config.coordinator.server_id() {
            return false;
        }
        let Some(link) = self.live.as_ref().map(|live| live.link) else {
            return true;
        };
        if let Err(violation) = self
            .companion
            .deadline_fired(link, tick_millis(entry.deadline))
        {
            self.fail_link(context, Violation::Companion(violation));
        }
        true
    }

    /// The base origin facts of one connection the companion origin mirrors.
    #[must_use]
    pub fn origin_facts(&self, generation: ConnectionGeneration) -> Option<BaseOriginFacts> {
        let origin = self.origins.get(&generation)?;
        Some(BaseOriginFacts {
            origin_id: *origin.origin_id.as_bytes(),
            generation: origin.generation,
            acked_generation: origin.acked_generation,
            connection_id: *origin.connection_id.as_bytes(),
            connection_nonce: origin.connection_nonce,
            session: origin
                .session
                .map(|(session, user)| (*session.as_bytes(), *user.as_bytes())),
            account: origin.account.and_then(|(account, generation)| {
                let text: [u8; 24] = account.to_text().as_bytes().try_into().ok()?;
                Some((text, generation))
            }),
        })
    }

    /// Every open connection with a base origin; an origin retained only
    /// until its deletion is acknowledged has no connection behind it.
    #[must_use]
    pub fn connection_generations(&self) -> Vec<ConnectionGeneration> {
        self.origins
            .iter()
            .filter(|(_, origin)| !origin.deleted)
            .map(|(generation, _)| *generation)
            .collect()
    }

    /// Advances the connection's shared origin generation after a device
    /// attachment and declares the update (E2EE 12.5).
    pub fn advance_origin(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        self.session_bound(context, generation);
    }

    /// Whether this edge holds the base channel-detail entitlement of
    /// `channel`: in the active projection, or in a snapshot generation
    /// still being installed, whose cut pairs with a companion ESTATE
    /// transfer in flight (companion 12.5).
    #[must_use]
    pub fn holds_channel(&self, channel: agenc_relay_types::ChannelInstanceId) -> bool {
        use agenc_relay_domain::federation::ProjectionKey;
        self.replica.channel(channel).is_some()
            || self
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.holds(&ProjectionKey::channel_detail(channel)))
    }

    /// Whether this edge hosts `account`: its account projection stands in
    /// the active or the installing generation, or a base origin this edge
    /// declared, live or awaiting its deletion, is authenticated as it.
    #[must_use]
    pub fn hosts_account(&self, account: agenc_relay_types::AccountId) -> bool {
        use agenc_relay_domain::federation::ProjectionKey;
        self.replica.account(account).is_some()
            || self
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.holds(&ProjectionKey::account(account)))
            || self
                .origins
                .values()
                .any(|origin| origin.account.is_some_and(|(held, _)| held == account))
    }

    /// Every account [`Self::hosts_account`] answers for now, unordered and
    /// with repeats: the accounts of the active and installing sessions and
    /// of every declared origin.
    pub fn hosted_accounts(&self) -> impl Iterator<Item = agenc_relay_types::AccountId> + '_ {
        self.replica
            .sessions()
            .filter_map(|session| session.account.map(|(account, _)| account))
            .chain(
                self.snapshot
                    .iter()
                    .flat_map(sync::SnapshotInstall::session_accounts),
            )
            .chain(
                self.origins
                    .values()
                    .filter_map(|origin| origin.account.map(|(account, _)| account)),
            )
    }

    /// Exact transport identity for companion receipt publication ownership.
    pub(crate) fn current_companion_link_id(&self) -> Option<LinkId> {
        self.live.as_ref().map(|live| live.link)
    }

    /// The coordinator's recovery epoch and incarnation on the live link.
    #[must_use]
    pub fn coordinator_link_identity(&self) -> Option<([u8; 16], [u8; 16])> {
        self.live.as_ref().map(|live| {
            (
                *live.coordinator_epoch.as_bytes(),
                *live.coordinator_incarnation.as_bytes(),
            )
        })
    }

    /// Sends companion lines over the live link; returns whether every line
    /// was queued.
    pub fn send_companion_lines(
        &mut self,
        context: &mut StateCoreContext,
        lines: Vec<agenc_relay_federation_wire::FederationLineText>,
    ) -> bool {
        for line in lines {
            let Some(live) = self.live.as_ref() else {
                return false;
            };
            if let Err(refusal) = live.handle.try_send(line) {
                self.send_failed(context, SendFailure::from(refusal));
                return false;
            }
        }
        true
    }

    /// Closes the link after a companion violation.
    pub fn fail_companion_link(&mut self, context: &mut StateCoreContext) {
        self.fail_link(context, Violation::Companion(CompanionViolation::Request));
    }

    /// Closes the link after the E2EE edge witnessed a sequencer record
    /// chain that did not extend (companion 12.5).
    pub fn fail_companion_witness(&mut self, context: &mut StateCoreContext) {
        self.fail_link(context, Violation::Companion(CompanionViolation::Witness));
    }

    /// Stages one companion part of a cross-profile barrier handed over by
    /// the E2EE router; a violation closes the link and returns `false`.
    pub fn companion_barrier_part(
        &mut self,
        context: &mut StateCoreContext,
        part: agenc_relay_storage::e2ee_records::barrier::BarrierPart,
        payload: Option<Vec<u8>>,
    ) -> bool {
        match barrier::companion_part(self, context, part, payload) {
            Ok(()) => true,
            Err(violation) => {
                self.fail_link(context, violation);
                false
            }
        }
    }

    /// The complete barrier awaiting its apply transaction, when the batch
    /// slot can take it; the E2EE router answers with its companion writes.
    #[must_use]
    pub fn barrier_ready(&self) -> Option<[u8; 16]> {
        barrier::ready_mutation(self)
    }

    /// Applies the complete barrier with the E2EE router's rows in the same
    /// transaction; a violation closes the link and returns `false`.
    pub(crate) fn apply_barrier(
        &mut self,
        context: &mut StateCoreContext,
        companion_writes: Vec<crate::state_core::durable::AccountServiceDurableWrite>,
        companion_outputs: Vec<crate::e2ee::edge::ClientOutput>,
    ) -> bool {
        match barrier::apply(self, context, companion_writes, companion_outputs) {
            Ok(()) => true,
            Err(violation) => {
                self.fail_link(context, violation);
                false
            }
        }
    }

    /// Whether the barrier of `mutation_id` applied and its receipt stands.
    #[must_use]
    pub fn barrier_applied(&self, mutation_id: &[u8; 16]) -> bool {
        self.barrier.applied.contains_key(mutation_id)
    }

    /// Records the companion delivery position the E2EE router has applied
    /// and acknowledged, so a barrier's companion parts verify against the
    /// live stream rather than a cursor of their own.
    pub fn note_companion_delivery(&mut self, generation: u64, cursor: Option<(u64, [u8; 16])>) {
        self.barrier.companion_generation = generation;
        self.barrier.companion_cursor = cursor;
    }

    /// The companion delivery generation and last acknowledged position the
    /// barrier owner tracks.
    #[must_use]
    pub fn companion_cursor(&self) -> (u64, Option<(u64, [u8; 16])>) {
        (
            self.barrier.companion_generation,
            self.barrier.companion_cursor,
        )
    }

    /// Returns the STATS counters.
    #[must_use]
    pub const fn counters(&self) -> EdgeCounters {
        self.counters
    }

    /// Reports the coordinator link state through the process readiness
    /// gate: an edge is ready only while its link is ACTIVE (spec 21.5).
    #[must_use]
    pub fn with_readiness(mut self, readiness: Arc<ReadinessGate>) -> Self {
        self.readiness = Some(readiness);
        self
    }

    /// The seven `STATS FEDERATION` values from the edge's view: its one
    /// coordinator, whether the link is ACTIVE, no quarantines, the pending
    /// request count, no outbox bytes, results applied, and no barriers.
    #[must_use]
    pub fn federation_stats(&self) -> [u64; 7] {
        [
            1,
            u64::from(self.network_available()),
            0,
            u64::try_from(self.pending.len()).unwrap_or(u64::MAX),
            0,
            self.counters.results_applied,
            self.counters.barriers_applied,
        ]
    }

    /// Mirrors the phase into the readiness gate after every transition.
    pub(super) fn note_phase(&self) {
        let Some(readiness) = &self.readiness else {
            return;
        };
        // An encrypted node is ready only once the companion profile is
        // active on the same link (companion 12.5).
        let companion_ready = !self.companion.has_profile() || self.companion_active();
        if self.network_available() && companion_ready {
            readiness.mark(ReadinessStage::Federation);
        } else {
            readiness.clear(ReadinessStage::Federation);
        }
    }

    /// Reports whether the coordinator link accepts global work.
    #[must_use]
    pub fn network_available(&self) -> bool {
        self.phase == Phase::Active && self.live.is_some()
    }

    /// Reports whether no federated operation straddles a reload.
    ///
    /// Once shutdown has begun, a snapshot install holds this only while one
    /// of its own commits is in flight. Every other install stage waits on a
    /// frame that only the coordinator can send, and drain must never wait
    /// on a remote peer (RUN-11, issue #178).
    #[must_use]
    pub fn reload_ready(&self) -> bool {
        self.commit.is_none() && !sync::holds_safe_point(self)
    }

    /// Borrows the replica.
    #[must_use]
    pub const fn replica(&self) -> &EdgeReplica {
        &self.replica
    }

    /// What a `900` names for one authenticated session this edge homes,
    /// read from the session projection its coordinator installed. A session
    /// the replica does not hold, or one without an account, has no
    /// logged-in state.
    pub(crate) fn logged_in(
        &self,
        user_id: UserId,
    ) -> Result<crate::client_render::LoggedIn, RuntimeError> {
        let record = self
            .replica
            .session(user_id)
            .ok_or(RuntimeError::InvalidValue)?;
        if record.account.is_none() {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(crate::client_render::LoggedIn {
            mask: render::prefix(&record.source_view())?,
            label: record
                .account_label
                .as_ref()
                .map_or("*", agenc_relay_domain::AccountLabelValue::as_str)
                .to_owned(),
        })
    }

    /// The account the session projection of one session this edge homes
    /// names, if any.
    pub(crate) fn home_session_account(&self, user_id: UserId) -> Option<AccountId> {
        self.replica
            .session(user_id)?
            .account
            .map(|(account_id, _)| account_id)
    }

    /// Lets a router test install the projections a coordinator would send.
    #[cfg(test)]
    pub(crate) fn replica_mut(&mut self) -> &mut EdgeReplica {
        &mut self.replica
    }

    /// Dispatches one link message; completions are returned to the router.
    pub fn inbound(
        &mut self,
        context: &mut StateCoreContext,
        message: FederationInbound,
    ) -> Vec<EdgeCompletion> {
        let FederationInbound {
            link,
            peer,
            event,
            charge,
        } = message;
        if peer != self.config.coordinator.server_id() {
            return Vec::new();
        }
        match event {
            LinkEvent::Established { session, handle } => {
                self.link_established(context, session, handle);
                Vec::new()
            }
            LinkEvent::Closed(_) => {
                self.link_closed(context, link);
                Vec::new()
            }
            LinkEvent::Frame(frame) if self.link_is(link) => {
                let outcome = self.handle_frame(context, frame);
                self.settle(context, link, outcome)
            }
            LinkEvent::Object { carrier, object } if self.link_is(link) => {
                let outcome = self.handle_object(context, carrier, object, charge);
                self.settle(context, link, outcome)
            }
            LinkEvent::Companion(frame) if self.link_is(link) => {
                let outcome = self.handle_companion(frame);
                self.note_phase();
                self.settle(context, link, outcome)
            }
            LinkEvent::Frame(_) | LinkEvent::Object { .. } | LinkEvent::Companion(_) => Vec::new(),
        }
    }

    /// Turns a handler outcome into completions, failing the link on a
    /// violation.
    /// Applies a handler's outcome. A handler may retire the link itself
    /// when a write finds the link task gone; a failure after that is moot.
    fn settle(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        outcome: Result<Vec<EdgeCompletion>, Violation>,
    ) -> Vec<EdgeCompletion> {
        match outcome {
            Ok(completions) => completions,
            Err(violation) => {
                if self.link_is(link) {
                    self.fail_link(context, violation);
                }
                Vec::new()
            }
        }
    }

    fn link_is(&self, link: LinkId) -> bool {
        self.live.as_ref().is_some_and(|live| live.link == link)
    }

    fn link_established(
        &mut self,
        context: &mut StateCoreContext,
        session: LinkSession,
        handle: LinkHandle,
    ) {
        if !journal_retry::observe_link(self, session.link) {
            return;
        }
        ordinary_batch::release_acknowledgements(self);
        self.live = Some(LiveLink {
            link: session.link,
            handle,
            coordinator_epoch: session.peer_recovery_epoch,
            coordinator_incarnation: session.peer_incarnation,
        });
        self.phase = Phase::Origins;
        self.note_phase();
        if !journal_retry::link_reestablished(self, context) {
            return;
        }
        self.begin_link_sync(context);
    }

    // A replacement transport must not negotiate either profile against the
    // tentative projection or start another checkpoint ahead of its receipt.
    fn begin_link_sync(&mut self, context: &mut StateCoreContext) {
        if matches!(self.commit, Some(PendingCommit::OrdinaryBatch(_))) {
            return;
        }
        if fence::needed(self) {
            if let Err(violation) = fence::stage(self, context) {
                self.fail_link(context, violation);
            }
            return;
        }
        self.start_companion(context);
        sync::begin(self, context);
    }

    fn link_closed(&mut self, context: &mut StateCoreContext, link: LinkId) {
        if !self.link_is(link) {
            return;
        }
        ordinary_batch::release_acknowledgements(self);
        self.companion.link_closed(link);
        let _cancelled = context.timers_mut().cancel(
            TimerKind::CompanionProfileDeadline,
            TimedId::Peer(self.config.coordinator.server_id()),
        );
        self.live = None;
        self.phase = Phase::Down;
        self.origin_ready = false;
        self.note_phase();
        if sync::pending_generation(self).is_none() {
            self.snapshot = None;
        }
        self.queued_events.clear();
        self.abort_interrupted_joins(context);
        for pending in self.pending.values_mut() {
            pending.sent = false;
        }
    }

    fn abort_interrupted_joins(&self, context: &mut StateCoreContext) {
        let active = self
            .origins
            .iter()
            .filter(|(_, origin)| origin.join_names_pending)
            .map(|(generation, _)| *generation);
        let waiting = self
            .pending
            .values()
            .filter(|pending| !pending.sink_gone)
            .filter(|pending| {
                matches!(&pending.kind, request::PendingKind::Command { message }
                    if message.command() == "JOIN")
            })
            .map(|pending| pending.generation);
        for generation in active.chain(waiting) {
            if let Some(sink) = context.sessions().sink_for_generation(generation) {
                let _closed =
                    sink.close_after_flush(crate::state_core::inbox::CloseReason::ProtocolError);
            }
            context.sessions_mut().mark_sink_gone(generation);
        }
    }

    /// Closes the link after a violation; the supervisor reconnects.
    fn fail_link(&mut self, context: &mut StateCoreContext, _violation: Violation) {
        ordinary_batch::release_acknowledgements(self);
        self.counters.violations = self.counters.violations.saturating_add(1);
        if let Some(live) = self.live.as_ref() {
            live.handle.close();
            let link = live.link;
            self.link_closed(context, link);
        }
    }

    fn handle_frame(
        &mut self,
        context: &mut StateCoreContext,
        frame: FederationFrame,
    ) -> Result<Vec<EdgeCompletion>, Violation> {
        match frame {
            FederationFrame::OriginReady {
                edge_server_id,
                server_incarnation,
            } => {
                self.require_self(edge_server_id)?;
                sync::origin_ready(self, context, server_incarnation)?;
                Ok(Vec::new())
            }
            FederationFrame::OriginAck {
                edge_server_id,
                server_incarnation,
                origin_id,
                generation,
                object_id,
            } => {
                self.require_self(edge_server_id)?;
                self.origin_acked(
                    context,
                    server_incarnation,
                    origin_id,
                    generation,
                    object_id,
                )
            }
            FederationFrame::ResumeOk {
                edge_server_id,
                projection_generation,
                next_delivery_sequence,
            } => {
                self.require_self(edge_server_id)?;
                sync::resume_ok(self, context, projection_generation, next_delivery_sequence)?;
                Ok(Vec::new())
            }
            FederationFrame::ResumeSnapshot { edge_server_id } => {
                self.require_self(edge_server_id)?;
                sync::resume_snapshot(self)?;
                Ok(Vec::new())
            }
            FederationFrame::SnapshotBegin {
                edge_server_id,
                identity,
                entry_count,
            } => {
                self.require_self(edge_server_id)?;
                sync::snapshot_begin(self, identity, entry_count)?;
                Ok(Vec::new())
            }
            FederationFrame::SnapshotEnd {
                edge_server_id,
                snapshot_token,
                cursor,
            } => {
                self.require_self(edge_server_id)?;
                sync::snapshot_end(self, context, snapshot_token, cursor)
            }
            FederationFrame::SnapshotActive {
                edge_server_id,
                identity,
            } => {
                self.require_self(edge_server_id)?;
                sync::snapshot_active(self, context, identity)?;
                Ok(Vec::new())
            }
            _ => Err(Violation::Phase),
        }
    }

    fn handle_object(
        &mut self,
        context: &mut StateCoreContext,
        carrier: ObjectCarrier,
        object: agenc_relay_federation_wire::AssembledObject,
        charge: Option<IngressCharge>,
    ) -> Result<Vec<EdgeCompletion>, Violation> {
        drop(charge);
        match carrier {
            ObjectCarrier::Result(descriptor) => {
                request::receive_result(self, context, descriptor, &object)
            }
            ObjectCarrier::Event(descriptor) => events::receive(self, context, descriptor, &object),
            ObjectCarrier::SnapshotEntry {
                edge_server_id,
                snapshot_token,
                entry_index,
                object_id,
            } => {
                self.require_self(edge_server_id)?;
                sync::snapshot_entry(self, snapshot_token, entry_index, object_id, &object)?;
                Ok(Vec::new())
            }
            ObjectCarrier::Request(_)
            | ObjectCarrier::OriginAdd(_)
            | ObjectCarrier::OriginUpdate(_) => Err(Violation::Phase),
        }
    }

    fn require_self(&self, server_id: ServerId) -> Result<(), Violation> {
        if server_id == self.config.server_id {
            Ok(())
        } else {
            Err(Violation::Misaddressed)
        }
    }

    /// Records the coordinator's acknowledgement of one origin declaration,
    /// or drops the retained origin once its deletion is acknowledged.
    fn origin_acked(
        &mut self,
        context: &mut StateCoreContext,
        incarnation: ServerIncarnation,
        origin_id: OriginId,
        generation: u64,
        object_id: Option<agenc_relay_federation_wire::FederationHash32>,
    ) -> Result<Vec<EdgeCompletion>, Violation> {
        if incarnation != self.config.incarnation {
            return Err(Violation::Consistency);
        }
        let Some(connection) = self
            .origins
            .iter()
            .find(|(_, origin)| origin.origin_id == origin_id)
            .map(|(connection, _)| *connection)
        else {
            return Ok(Vec::new());
        };
        let origin = self.origins.get_mut(&connection).ok_or(Violation::Phase)?;
        let Some(object_id) = object_id else {
            if !origin.deletion_acknowledged_at(generation) {
                return Err(Violation::Consistency);
            }
            origin.del_acked = true;
            journal::retain(self, context, journal::Identity::Origin(connection));
            return Ok(Vec::new());
        };
        if let Some(update) = origin.pending_updates.front().copied()
            && update.generation == generation
        {
            let encoded = agenc_relay_federation_wire::CanonicalEncode::encode_canonical(
                &update.to_object().map_err(|_| Violation::Codec)?,
            )
            .map_err(|_| Violation::Codec)?;
            if federation_object_id(encoded.as_slice()) != object_id {
                return Err(Violation::Consistency);
            }
            origin.pending_updates.pop_front();
            origin.generation = generation;
            origin.sequence = 0;
            origin.previous_object_id = update.previous_origin_object_id;
            origin.object_id = *object_id.as_bytes();
        } else if origin.generation != generation || origin.object_id != *object_id.as_bytes() {
            return Err(Violation::Consistency);
        }
        origin.ever_acked = true;
        if !origin.pending_updates.is_empty() {
            request::declare_origin(self, context, connection, true);
            return Ok(Vec::new());
        }
        origin.acked_generation = Some(generation);
        sync::activate_origins(self, context);
        request::resend_pending(self, context);
        Ok(request::dispatch_deferred(self, context, connection))
    }

    /// Sends one rendered control frame over the live link.
    /// Queues one frame for the link; returns whether the link is still
    /// live afterwards, so a caller can stop a sequence the write ended.
    fn send_frame(&mut self, context: &mut StateCoreContext, frame: &FederationFrame) -> bool {
        let Some(live) = self.live.as_ref() else {
            return false;
        };
        let sent = frame
            .render(&self.config.server_name)
            .map_err(|_| SendFailure::Violation(Violation::Codec))
            .and_then(|line| live.handle.try_send(line).map_err(SendFailure::from));
        if let Err(failure) = sent {
            self.send_failed(context, failure);
        }
        self.live.is_some()
    }

    /// Handles a refused outbound write: a violation fails the link, while a
    /// queue whose task already ended retires the link without a violation.
    fn send_failed(&mut self, context: &mut StateCoreContext, failure: SendFailure) {
        match failure {
            SendFailure::Violation(violation) => self.fail_link(context, violation),
            SendFailure::Closed => {
                if let Some(link) = self.live.as_ref().map(|live| live.link) {
                    self.link_closed(context, link);
                }
            }
        }
    }

    /// Sends one object as fragments over the live link.
    fn send_object(
        &mut self,
        context: &mut StateCoreContext,
        encoded: &[u8],
        frame: impl Fn(agenc_relay_federation_wire::FederationFragment) -> FederationFrame,
    ) -> bool {
        let Some(live) = self.live.as_ref() else {
            return false;
        };
        let object_id = federation_object_id(encoded);
        let sent = split_fragments(object_id, encoded)
            .map_err(|_| SendFailure::Violation(Violation::Codec))
            .and_then(|fragments| {
                let mut lines: Vec<FederationLineText> = Vec::new();
                lines
                    .try_reserve_exact(fragments.len())
                    .map_err(|_| SendFailure::Violation(Violation::Ceiling))?;
                for fragment in fragments {
                    lines.push(
                        frame(fragment)
                            .render(&self.config.server_name)
                            .map_err(|_| SendFailure::Violation(Violation::Codec))?,
                    );
                }
                for line in lines {
                    live.handle.try_send(line)?;
                }
                Ok(())
            });
        match sent {
            Ok(()) => true,
            Err(failure) => {
                self.send_failed(context, failure);
                false
            }
        }
    }

    /// A client connection was admitted: its origin exists from now on and
    /// is declared as soon as the link is synchronizing or active.
    pub fn connection_opened(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        let mut random = [0_u8; 64];
        if context.entropy_mut().fill_exact(&mut random).is_err() {
            return;
        }
        let (origin, rest) = random.split_at(16);
        let (connection, nonce) = rest.split_at(16);
        let (Ok(origin_id), Ok(connection_id), Ok(nonce)) = (
            <[u8; 16]>::try_from(origin),
            <[u8; 16]>::try_from(connection),
            <[u8; 32]>::try_from(nonce),
        ) else {
            return;
        };
        self.origins.insert(
            generation,
            ConnectionOrigin {
                pending_updates: VecDeque::new(),
                origin_id: OriginId::from_bytes(origin_id),
                connection_id: ConnectionId::from_bytes(connection_id),
                connection_nonce: nonce,
                generation: 0,
                sequence: 0,
                object_id: [0; 32],
                previous_object_id: [0; 32],
                session: None,
                account: None,
                acked_generation: None,
                ever_acked: false,
                revoked: false,
                join_names_pending: false,
                del_acked: false,
                deleted: false,
            },
        );
        self.next_origin = self.next_origin.saturating_add(1);
        if matches!(
            self.phase,
            Phase::Origins | Phase::Resuming | Phase::Snapshot | Phase::Active
        ) {
            request::declare_origin(self, context, generation, false);
        }
    }

    /// A client connection ended: its session closes through the coordinator
    /// and its origin is deleted.
    pub fn connection_closed(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        reason: &str,
    ) {
        history::connection_closed(self, generation);
        let session = self
            .origins
            .get(&generation)
            .and_then(|origin| origin.session);
        if let Some((session_id, _)) = session {
            request::send_session_close(self, context, generation, session_id, reason);
        }
        request::delete_origin(self, context, generation);
        self.deferred.remove(&generation);
        self.deferred_carriers.remove(&generation);
        let changed: Vec<_> = self
            .pending
            .iter_mut()
            .filter(|(_, pending)| pending.generation == generation)
            .map(|(id, pending)| {
                pending.sink_gone = true;
                *id
            })
            .collect();
        // Snapshot coverage compares the current request with its durable
        // body, including this sink flag. Persist every changed request.
        for id in changed {
            journal::mark_dirty(self, journal::Identity::Request(id));
        }
        journal::continue_write(self, context);
    }

    /// Requests a session for a connection that completed local
    /// registration; returns whether the request was accepted for sending.
    // agenc-review: allow owner=runtime reviewed=2026-09-03 reason=a session open carries the connection its registration facts capability hash and optional grant in the exact field order of the operation
    #[allow(clippy::too_many_arguments)]
    pub fn open_session(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        event_generation: u64,
        nickname: &str,
        realname: &str,
        capability_hash: [u8; 32],
        auth_grant_id: Option<[u8; 32]>,
    ) -> bool {
        self.network_available()
            && request::send_session_open(
                self,
                context,
                generation,
                event_generation,
                nickname,
                realname,
                capability_hash,
                auth_grant_id,
            )
            .is_ok()
    }

    /// Forwards one sealed account carrier envelope of a pre-registration
    /// client to the coordinator (spec 22.2); `false` when the link is not
    /// active or the envelope does not decode.
    pub fn send_account_carrier(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        opcode: agenc_relay_types::FederationOpcode,
        envelope: &[u8],
        finish: bool,
        carrier_generation: u64,
    ) -> bool {
        self.network_available()
            && request::send_account_carrier(
                self,
                context,
                generation,
                opcode,
                envelope,
                finish,
                carrier_generation,
            )
            .is_ok()
    }

    /// Sends one registered command; on failure the line comes back with
    /// the error the router renders.
    pub fn send_command(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        kind: RegisteredCommandKind,
        message: agenc_relay_client_wire::ParsedMessage,
    ) -> Result<
        (),
        (
            Box<agenc_relay_client_wire::ParsedMessage>,
            agenc_relay_domain::DomainError,
        ),
    > {
        request::send_command(self, context, generation, kind, Box::new(message))
    }

    /// The router bound the coordinator-assigned session: the origin moves
    /// to its next generation carrying the session binding.
    pub fn session_bound(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        if let Err(violation) = journal::queue_update(self, generation) {
            self.fail_link(context, violation);
            return;
        }
        request::declare_origin(self, context, generation, true);
    }

    /// Requests the NAMES page of one channel after its JOIN completed.
    pub fn request_names(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        channel: &str,
    ) {
        request::send_names(self, context, generation, channel, None);
    }

    /// Continues a paged query with the cursor the coordinator issued.
    pub fn continue_query(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: Box<agenc_relay_client_wire::ParsedMessage>,
        cursor: [u8; 32],
    ) -> bool {
        request::continue_query(self, context, generation, message, cursor)
    }

    /// Requests the next NAMES page while its JOIN holds origin admission.
    pub(crate) fn continue_join_names(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        channels: &[agenc_relay_domain::ChannelNameValue],
        message: Box<agenc_relay_client_wire::ParsedMessage>,
        cursor: Option<[u8; 32]>,
    ) -> bool {
        request::continue_join_names(self, context, generation, channels, message, cursor)
    }

    /// Releases the completed JOIN burst and admits deferred commands in order.
    pub(crate) fn finish_join_names(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Vec<EdgeCompletion> {
        if let Some(origin) = self.origins.get_mut(&generation) {
            origin.join_names_pending = false;
        }
        request::dispatch_deferred(self, context, generation)
    }

    /// Drains queued events only after complete authenticated index readback.
    pub(crate) fn index_refreshed(
        &mut self,
        context: &mut StateCoreContext,
    ) -> Vec<EdgeCompletion> {
        events::drain_queued(self, context)
    }

    /// Finishes the batch that just committed.
    pub fn batch_applied(&mut self, context: &mut StateCoreContext) -> Vec<EdgeCompletion> {
        if self.receipt_pending(context) {
            return Vec::new();
        }
        let mut completions = Vec::new();
        match self.commit.take() {
            Some(PendingCommit::Journal { versions, .. }) => {
                completions.extend(journal::committed(self, context, versions))
            }
            Some(PendingCommit::History(prepared)) => {
                completions.extend(history::committed(self, context, *prepared))
            }
            Some(PendingCommit::HistoryCleanup(cleanup)) => {
                history::cleanup_committed(self, cleanup)
            }
            Some(PendingCommit::OrdinaryBatch(pending)) => {
                completions.extend(ordinary_batch::committed(self, context, *pending));
            }
            Some(PendingCommit::Event {
                header,
                completion,
                coverage,
                join_echo,
                revoked,
            }) => {
                if let Some(echo) = join_echo
                    && let Err(violation) = join_echo::committed(self, *echo)
                {
                    self.fail_link(context, violation);
                    return Vec::new();
                }
                completions.extend(self.settle_event(context, *header, completion, coverage));
                completions.extend(revocations::committed(self, revoked));
            }
            Some(PendingCommit::SnapshotInstalled) => {
                completions.extend(sync::installed(self, context));
            }
            Some(PendingCommit::SnapshotActivated { coverage }) => {
                completions.extend(sync::activated(self, context, coverage));
            }
            Some(PendingCommit::BarrierPart(open)) => barrier::part_committed(self, *open),
            Some(PendingCommit::BarrierFence) => fence::committed(self, context),
            Some(PendingCommit::BarrierCleanup {
                mutation_id,
                finished,
            }) => {
                retention::committed(self, mutation_id, finished);
            }
            Some(PendingCommit::BarrierApplied {
                receipt,
                base_last,
                companion_last,
                coverage,
                join_echoes,
                revoked,
            }) => {
                if !self.commit_coverage(context, coverage) {
                    return Vec::new();
                }
                if !self.commit_join_echoes(context, join_echoes) {
                    return Vec::new();
                }
                completions.extend(barrier::applied(
                    self,
                    context,
                    *receipt,
                    base_last,
                    companion_last,
                ));
                completions.extend(revocations::committed(self, revoked));
            }
            None => {}
        }
        completions.extend(events::drain_queued(self, context));
        journal::continue_write(self, context);
        completions
    }

    fn receipt_pending(&self, context: &StateCoreContext) -> bool {
        let staged_after = match self.commit.as_ref() {
            Some(PendingCommit::Journal { staged_after, .. }) => Some(*staged_after),
            Some(PendingCommit::OrdinaryBatch(pending)) => Some(pending.staged_after),
            _ => None,
        };
        staged_after.is_some_and(|sequence| context.head().storage_commit_sequence <= sequence)
    }

    fn commit_join_echoes(
        &mut self,
        context: &mut StateCoreContext,
        echoes: Vec<join_echo::JoinEcho>,
    ) -> bool {
        for echo in echoes {
            if let Err(violation) = join_echo::committed(self, echo) {
                self.fail_link(context, violation);
                return false;
            }
        }
        true
    }

    fn commit_coverage(
        &mut self,
        context: &mut StateCoreContext,
        coverage: Vec<journal::Version>,
    ) -> bool {
        for version in coverage {
            if let Err(violation) = journal::completion_committed(self, version) {
                self.fail_link(context, violation);
                return false;
            }
        }
        true
    }

    fn settle_event(
        &mut self,
        context: &mut StateCoreContext,
        header: EventHeader,
        completion: Option<agenc_relay_types::RequestId>,
        coverage: Option<journal::Version>,
    ) -> Vec<EdgeCompletion> {
        if let Some(coverage) = coverage
            && let Err(violation) = journal::completion_committed(self, coverage)
        {
            self.fail_link(context, violation);
            return Vec::new();
        }
        self.event_before = None;
        self.counters.events_applied = self.counters.events_applied.saturating_add(1);
        self.cursor = Some((header.delivery_sequence, header.event_id));
        self.send_frame(
            context,
            &FederationFrame::Ack {
                coordinator_server_id: self.config.coordinator.server_id(),
                delivery_sequence: header.delivery_sequence,
                event_id: header.event_id,
            },
        );
        if let Some(request_id) = completion {
            return events::committed_completion(
                self,
                context,
                header.event_id,
                request_id,
                header.coordinator_state_generation,
            );
        }
        Vec::new()
    }

    /// Drops the work behind a rejected batch; the coordinator re-delivers.
    pub fn batch_rejected(&mut self, context: &mut StateCoreContext) {
        self.batch_rejected_with_error(context, agenc_relay_storage::StorageError::Unavailable);
    }

    /// Retains journal ownership only after a determinate storage refusal.
    pub fn batch_rejected_with_error(
        &mut self,
        context: &mut StateCoreContext,
        error: agenc_relay_storage::StorageError,
    ) {
        if matches!(self.commit, Some(PendingCommit::OrdinaryBatch(_))) {
            // Rejection callbacks drain after the old StateCore batch was
            // removed. A live exclusive batch belongs to a newer receipt.
            if context.pending_len() != 0 {
                return;
            }
            let pending = self.commit.take();
            events::restore_projection(self);
            drop(pending);
            self.fail_link(context, Violation::Ceiling);
            return;
        }
        if matches!(self.commit, Some(PendingCommit::Journal { .. })) {
            self.commit = None;
            journal_retry::rejected(self, context, error);
            return;
        }
        if matches!(
            self.commit,
            Some(PendingCommit::SnapshotInstalled | PendingCommit::SnapshotActivated { .. })
        ) {
            self.commit = None;
            sync::rejected_install(self);
            // No failed install may resume from its in-memory cut. A new
            // authenticated link must negotiate another verified snapshot.
            self.installed_epoch = None;
            self.fail_link(context, Violation::Ceiling);
            return;
        }
        if matches!(self.commit, Some(PendingCommit::History(_))) {
            if let Some(PendingCommit::History(prepared)) = self.commit.take() {
                history::rejected(self, context, *prepared);
            }
            return;
        }
        if let Some(
            PendingCommit::Event { .. }
            | PendingCommit::OrdinaryBatch(_)
            | PendingCommit::BarrierPart(_)
            | PendingCommit::BarrierFence
            | PendingCommit::BarrierApplied { .. },
        ) = self.commit.take()
        {
            events::restore_projection(self);
            barrier::rejected(self);
            // Resume starts at the previous committed projection and cursor.
            self.fail_link(context, Violation::Ceiling);
        }
    }

    /// Cancels ordinary retry work when StateCore starts shutdown.
    pub(crate) fn cancel_journal_retry(&mut self, context: &mut StateCoreContext) {
        journal_retry::cancel(self, context);
    }

    /// Marks the edge as stopping and abandons the snapshot install stages
    /// that wait on the coordinator. StateCore calls this only with no
    /// storage work in flight, so nothing staged is cut short.
    pub(crate) fn begin_shutdown(&mut self) {
        self.stopping = true;
        sync::abandon_for_shutdown(self);
    }
}

/// Why the edge refused a frame or object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Violation {
    /// The frame was addressed to another server.
    Misaddressed,
    /// The frame arrived in a phase that does not permit it.
    Phase,
    /// The object could not be decoded under its schema.
    Codec,
    /// An event or result broke a B.7 consistency rule.
    Consistency,
    /// The link's outbound queue is full.
    SlowConsumer,
    /// A bounded ceiling was crossed.
    Ceiling,
    /// A companion frame or its negotiation violated the ARC-MLS profile.
    Companion(CompanionViolation),
}

impl From<RuntimeError> for Violation {
    fn from(_: RuntimeError) -> Self {
        Self::Ceiling
    }
}
