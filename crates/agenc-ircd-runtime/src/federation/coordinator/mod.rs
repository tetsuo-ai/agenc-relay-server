//! The coordinator role of the base federation profile (spec 20).
//!
//! One instance lives inside the coordinator's command router. It owns the
//! authenticated edge links, the origin table, the retained request index,
//! and the per-edge outbox position. Every durable effect it produces rides
//! a StateCore batch: the request result, origin, outbox, projection, and
//! peer rows commit with the domain mutation that caused them, and the
//! coordinator only renders FRESULT and FEVENT lines after that commit.

mod accounts;
mod authority;
mod barriers;
mod companion;
mod convert;
mod grace;
mod history;
mod origin;
mod query;
mod request;
mod resume_reconciliation;
mod snapshot;
mod startup;
#[cfg(test)]
#[path = "tests/harness.rs"]
mod tests;

use std::collections::{BTreeMap, VecDeque};

use agenc_ircd_domain::federation::{OperationKey, OriginKey, OriginTable, RetainedRequest};
use agenc_ircd_federation_wire::{
    CanonicalEncode, EventDescriptor, FederationFrame, FederationHash32, FederationLineText,
    OperationDescriptor, RequestHeader, SchemaObject, federation_object_id, split_fragments,
};
use agenc_ircd_storage::federation_records::{
    DeliveryCursorRecord, FederationPeerRecord, PEER_RECORD_KIND, PeerPhase, peer_key,
};
use agenc_ircd_storage::{PersistentRecordValue, TableId};
use agenc_ircd_types::{
    EventId, MonotonicTick, NetworkId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation,
};

use crate::RuntimeError;
use crate::bridge::StorageReadId;
use crate::bridge::crypto::{ChannelKeyVerifier, ChannelKeyVerifierRecord};
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::e2ee::link::{
    CompanionAction, CompanionLinks, CompanionProfile, CompanionViolation, tick_millis,
};
use crate::federation::link::{LinkHandle, SendRefusal};
use crate::federation::{
    FederationInbound, IngressCharge, LinkCloseReason, LinkEvent, LinkId, LinkSession,
    ObjectCarrier, PeerIdentity,
};
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::projector::{EdgeDelivery, OutboundEvent};
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use crate::state_core::{PeerQuarantineRefusal, StateCoreContext};
use crate::sync::Arc;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;

pub(crate) use accounts::{
    InFlightCarrier, RemoteAccountWork, RemoteSessionGrant, challenge_object,
};
pub(crate) use request::{FreshRequest, PendingCrypto};

/// Requests queued behind one link's in-flight crypto continuation; the
/// fragment assembler already bounds a link to this many objects.
const MAX_QUEUED_REQUESTS: usize = 32;

/// The fixed coordinator identity and per-edge outbox ceilings.
pub struct CoordinatorConfig {
    /// The permanent network identity.
    pub network_id: NetworkId,
    /// This coordinator's Server ID.
    pub server_id: ServerId,
    /// The local server name used as the prefix of every rendered line.
    pub server_name: String,
    /// The recovery epoch advertised in this coordinator's FHELLO.
    pub recovery_epoch: RecoveryEpoch,
    /// The per-process query cursor key drawn from the CSPRNG at startup.
    pub query_cursor_key: [u8; 32],
    /// The per-process nonce bound into every query cursor.
    pub process_nonce: [u8; 16],
    /// Unacknowledged outbox bytes per edge before a snapshot is required.
    pub outbox_bytes_per_edge: u64,
    /// Unacknowledged outbox objects per edge before a snapshot is required.
    pub outbox_objects_per_edge: u64,
}

/// One authenticated live link.
struct LiveLink {
    link: LinkId,
    handle: LinkHandle,
    incarnation: ServerIncarnation,
}

/// The per-edge outbox position and unacknowledged window.
#[derive(Default)]
struct OutboxState {
    unacked: VecDeque<(u64, EventId, u64)>,
    unacked_bytes: u64,
    cursor: Option<(u64, EventId)>,
    snapshot_required: bool,
    dirty: bool,
    reserved_next: u64,
}

/// Everything the coordinator knows about one configured edge.
struct PeerState {
    identity: PeerIdentity,
    live: Option<LiveLink>,
    incarnation: Option<ServerIncarnation>,
    recovery_epoch: Option<RecoveryEpoch>,
    accepted_epochs: Vec<RecoveryEpoch>,
    phase: PeerPhase,
    projection_generation: u64,
    outbox: OutboxState,
    grace_deadline: Option<MonotonicTick>,
    cleanup: VecDeque<agenc_ircd_types::UserId>,
    cleanup_cursor: Option<[u8; 16]>,
    fence_pending: bool,
    quarantined: bool,
    client_resync_epoch: u64,
    queued: VecDeque<QueuedRequest>,
    /// Whether the link finished FRESUME or ACTIVE and receives live events.
    active: bool,
    snapshot: Option<snapshot::Snapshot>,
    resend: Option<snapshot::Resend>,
    reconciliation: Option<resume_reconciliation::Reconciliation>,
    ready_identity: Option<agenc_ircd_federation_wire::SnapshotIdentity>,
}

/// One request held while the same link waits on crypto.
struct QueuedRequest {
    link: LinkId,
    descriptor: OperationDescriptor,
    object: agenc_ircd_federation_wire::AssembledObject,
    charge: Option<IngressCharge>,
}

/// Why the coordinator refused a frame or object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Violation {
    /// The frame was addressed to another server or carried another network.
    Misaddressed,
    /// The frame arrived in a phase that does not permit it.
    Phase,
    /// The origin declaration or replay key conflicts with durable state.
    Origin,
    /// The object could not be decoded under its schema.
    Codec,
    /// The acknowledgement did not name the oldest unacknowledged event.
    Acknowledgement,
    /// The link's outbound queue is full; the peer is a slow consumer.
    SlowConsumer,
    /// A per-link ceiling was crossed.
    Ceiling,
    /// A companion frame or its negotiation violated the IRC-MLS profile.
    Companion(CompanionViolation),
}

/// What one staged batch must finish once it commits.
enum PendingCommit {
    History(Box<history::Prepared>),
    HistoryCleanup(crate::federation::history_retention::Cleanup),
    Request {
        /// A result staged after this durable head requires a later receipt.
        staged_after: u64,
        peer: ServerId,
        link: LinkId,
        key: OperationKey,
        request_id: RequestId,
        request_object_id: FederationHash32,
        result: Vec<u8>,
        descriptor: OperationDescriptor,
        /// The request header, kept so a refused batch can still answer.
        header: RequestHeader,
        _charge: Option<IngressCharge>,
        query: Option<query::QueryReceipt>,
    },
    OriginReady {
        peer: ServerId,
        link: LinkId,
    },
    OriginAck {
        peer: ServerId,
        link: LinkId,
        frame: FederationFrame,
        closed_carrier: Option<crate::connection::ConnectionGeneration>,
        _charge: Option<IngressCharge>,
    },
    OriginExpired {
        peer: ServerId,
        link: LinkId,
        descriptor: OperationDescriptor,
        result: Vec<u8>,
        _charge: Option<IngressCharge>,
    },
    Cleanup {
        peer: ServerId,
    },
    AuthorityFence {
        peer: ServerId,
        generation: u64,
        cursor: Option<[u8; 16]>,
    },
    CleanupFinished {
        peer: ServerId,
    },
    /// Startup retirement cannot publish to any live link.
    CompanionRestore(Box<startup::retirement::Receipt>),
    /// A companion request batch; the executor holds its result.
    Companion {
        peer: ServerId,
        link: LinkId,
        resume: bool,
        barrier: Option<Box<barriers::Prepared>>,
    },
    SnapshotRows {
        peer: ServerId,
    },
    SnapshotReady {
        peer: ServerId,
    },
    DeliveryAcknowledged {
        resume: Option<LinkId>,
        peer: ServerId,
        delivery_sequence: u64,
        event_id: EventId,
        barrier: Option<Box<barriers::Prepared>>,
    },
    ResumeAcknowledged(resume_reconciliation::ChunkReceipt),
    OutboxRequired {
        peer: ServerId,
    },
    Acknowledged,
}

/// The most backlogged link items held across one in-flight batch.
const MAX_BACKLOG: usize = 1_024;

/// Counters exposed through STATS FEDERATION.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoordinatorCounters {
    /// Fresh requests committed.
    pub requests_committed: u64,
    /// Exact duplicates answered from the durable result.
    pub requests_replayed: u64,
    /// Requests refused before a plan was staged.
    pub requests_failed: u64,
    /// Events delivered over live links.
    pub events_sent: u64,
    /// Protocol violations that closed a link.
    pub violations: u64,
    /// Sessions hidden by origin expiry cleanup.
    pub sessions_expired: u64,
    /// Live query cursors.
    pub live_cursors: u64,
}

/// The coordinator's federation state machine.
pub struct FederationCoordinator {
    config: CoordinatorConfig,
    verifier: Arc<dyn ChannelKeyVerifier>,
    dummy: ChannelKeyVerifierRecord,
    origins: OriginTable,
    origin_objects: BTreeMap<OriginKey, Vec<u8>>,
    /// Registration ownership before the edge acknowledges its principal UPDATE.
    registered_sessions: BTreeMap<OriginKey, std::collections::BTreeSet<agenc_ircd_types::UserId>>,
    retained: BTreeMap<OperationKey, RetainedRequest>,
    peers: BTreeMap<ServerId, PeerState>,
    links: BTreeMap<LinkId, ServerId>,
    pending: Option<PendingCommit>,
    crypto: Option<PendingCrypto>,
    replays: BTreeMap<StorageReadId, (LinkId, ServerId, OperationDescriptor)>,
    loader: startup::Loader,
    /// Frames and objects that arrived while a federation batch was in
    /// flight; they replay in order once the batch commits. Peers pipeline
    /// their synchronization frames, so refusing them would close every
    /// reconnecting link.
    backlog: VecDeque<FederationInbound>,
    /// The peer whose queue drained last; the next drain starts after it.
    drain_cursor: Option<ServerId>,
    queries: query::Queries,
    history: history::HistoryQueries,
    counters: CoordinatorCounters,
    companion: CompanionLinks,
    /// The E2EE executor; `None` on a node without a sequencer.
    companion_exec: Option<CompanionCoordinator>,
    companion_page_read: Option<companion::page_read::Pending>,
    companion_ack_read: Option<Box<companion::ack_read::Pending>>,
    /// Open cross-profile barriers by target (spec 20.8): later events on
    /// either stream wait until both final acknowledgements arrive.
    barriers: BTreeMap<ServerId, OpenBarrier>,
    remote_accounts: accounts::RemoteAccounts,
}

/// One cross-profile barrier awaiting both cumulative acknowledgements.
pub(super) type OpenBarrier = agenc_ircd_storage::e2ee_records::delivery_recovery::DeliveryBarrier;

impl FederationCoordinator {
    /// Creates a coordinator that knows the configured edges and holds no
    /// live link.
    #[must_use]
    pub fn new(
        config: CoordinatorConfig,
        peers: Vec<PeerIdentity>,
        verifier: Arc<dyn ChannelKeyVerifier>,
        dummy: ChannelKeyVerifierRecord,
    ) -> Self {
        let peers = peers
            .into_iter()
            .map(|identity| {
                (
                    identity.server_id(),
                    PeerState {
                        identity,
                        live: None,
                        incarnation: None,
                        recovery_epoch: None,
                        accepted_epochs: Vec::new(),
                        phase: PeerPhase::Clean,
                        projection_generation: 1,
                        outbox: OutboxState::default(),
                        grace_deadline: None,
                        cleanup: VecDeque::new(),
                        cleanup_cursor: None,
                        fence_pending: false,
                        quarantined: false,
                        client_resync_epoch: 0,
                        queued: VecDeque::new(),
                        active: false,
                        snapshot: None,
                        resend: None,
                        reconciliation: None,
                        ready_identity: None,
                    },
                )
            })
            .collect();
        let queries = query::Queries::new(config.query_cursor_key, config.process_nonce);
        let history = history::HistoryQueries::new(config.query_cursor_key, config.process_nonce);
        let companion = CompanionLinks::new(None, config.server_name.clone());
        Self {
            companion,
            config,
            verifier,
            dummy,
            origins: OriginTable::new(),
            origin_objects: BTreeMap::new(),
            registered_sessions: BTreeMap::new(),
            retained: BTreeMap::new(),
            peers,
            links: BTreeMap::new(),
            pending: None,
            crypto: None,
            replays: BTreeMap::new(),
            history,
            loader: startup::Loader::default(),
            backlog: VecDeque::new(),
            drain_cursor: None,
            queries,
            counters: CoordinatorCounters::default(),
            companion_exec: None,
            companion_page_read: None,
            companion_ack_read: None,
            barriers: BTreeMap::new(),
            remote_accounts: accounts::RemoteAccounts::default(),
        }
    }

    /// Installs the companion executor before any link exists.
    pub fn install_companion_executor(
        &mut self,
        mut executor: CompanionCoordinator,
        incarnation: ServerIncarnation,
    ) -> Result<(), crate::e2ee::coordinator::CompanionFault> {
        if executor.network_id != *self.config.network_id.as_bytes()
            || executor.server_id != self.config.server_id
        {
            return Err(crate::e2ee::coordinator::CompanionFault::Protocol);
        }
        executor.configure_delivery_identity(incarnation, self.config.recovery_epoch)?;
        self.companion_exec = Some(executor);
        Ok(())
    }

    /// The companion executor, if one is installed.
    #[must_use]
    pub fn companion_executor(&self) -> Option<&CompanionCoordinator> {
        self.companion_exec.as_ref()
    }

    /// Returns the STATS counters.
    #[must_use]
    pub fn counters(&self) -> CoordinatorCounters {
        CoordinatorCounters {
            live_cursors: u64::try_from(self.queries.live_cursors()).unwrap_or(u64::MAX),
            ..self.counters
        }
    }

    /// Returns the configured Server ID.
    #[must_use]
    pub const fn server_id(&self) -> ServerId {
        self.config.server_id
    }

    /// The seven `STATS FEDERATION` values: configured, active, and
    /// quarantined peers, unacknowledged outbox objects and bytes, replayed
    /// requests, and the cross-profile barrier count (zero before Stage 08).
    #[must_use]
    pub fn federation_stats(&self) -> [u64; 7] {
        let count = |predicate: fn(&PeerState) -> bool| {
            u64::try_from(self.peers.values().filter(|state| predicate(state)).count())
                .unwrap_or(u64::MAX)
        };
        let outbox_objects = self
            .peers
            .values()
            .map(|state| u64::try_from(state.outbox.unacked.len()).unwrap_or(u64::MAX))
            .fold(0_u64, u64::saturating_add);
        let outbox_bytes = self
            .peers
            .values()
            .map(|state| state.outbox.unacked_bytes)
            .fold(0_u64, u64::saturating_add);
        [
            count(|_| true),
            count(|state| state.active),
            count(|state| state.quarantined),
            outbox_objects,
            outbox_bytes,
            self.counters.requests_replayed,
            0,
        ]
    }

    /// `PEER QUARANTINE`: marks the peer denied in memory, closes its live
    /// link, and stages the durable peer row so the fence survives restart.
    pub fn admin_quarantine_peer(
        &mut self,
        context: &mut StateCoreContext,
        peer: ServerId,
    ) -> Result<(), PeerQuarantineRefusal> {
        let Some(state) = self.peers.get_mut(&peer) else {
            return Err(PeerQuarantineRefusal::UnknownPeer);
        };
        if state.quarantined {
            return Err(PeerQuarantineRefusal::AlreadyQuarantined);
        }
        if self.pending.is_some() {
            return Err(PeerQuarantineRefusal::Busy);
        }
        state.quarantined = true;
        let live = state.live.as_ref().map(|live| live.link);
        if let Some(link) = live {
            self.fail_link(context, link, peer, Violation::Phase);
        }
        self.stage_rows(context, Vec::new(), PendingCommit::Acknowledged, Some(peer))
            .map_err(|_| PeerQuarantineRefusal::Busy)
    }

    /// Returns the configured identity of one edge.
    #[must_use]
    pub fn peer_identity(&self, peer: ServerId) -> Option<&PeerIdentity> {
        self.peers.get(&peer).map(|state| &state.identity)
    }

    /// Reports whether a crypto job belongs to a federated request.
    #[must_use]
    pub fn owns_crypto_job(&self, job_id: crate::bridge::CryptoJobId) -> bool {
        self.crypto
            .as_ref()
            .is_some_and(|pending| pending.job_id == job_id)
    }

    /// Reports whether no federated operation straddles a reload.
    #[must_use]
    pub fn reload_ready(&self) -> bool {
        self.pending.is_none()
            && self.companion_ack_read.is_none()
            && self.crypto.is_none()
            && self.replays.is_empty()
            && !self.history.busy()
            && self
                .peers
                .values()
                .all(|state| state.reconciliation.is_none())
    }

    /// Dispatches one link message at a safe point.
    pub fn inbound(&mut self, context: &mut StateCoreContext, message: FederationInbound) {
        if self.loader.blocks_admission() {
            startup::hold_before_loaded(self, message);
            return;
        }
        let FederationInbound {
            link,
            peer,
            event,
            charge,
        } = message;
        if !self.peers.contains_key(&peer) {
            return;
        }
        if (self.pending.is_some() || self.companion_ack_read.is_some())
            && matches!(
                event,
                LinkEvent::Frame(_) | LinkEvent::Object { .. } | LinkEvent::Companion(_)
            )
        {
            if self.backlog.len() >= MAX_BACKLOG {
                self.fail_link(context, link, peer, Violation::SlowConsumer);
                return;
            }
            self.backlog.push_back(FederationInbound {
                link,
                peer,
                event,
                charge,
            });
            return;
        }
        match event {
            LinkEvent::Established { session, handle } => {
                self.link_established(context, session, handle);
            }
            LinkEvent::Closed(reason) => {
                self.backlog.retain(|message| message.link != link);
                self.link_closed(context, link, peer, reason);
            }
            LinkEvent::Frame(_) | LinkEvent::Object { .. } | LinkEvent::Companion(_) => {
                self.handle_traffic(context, link, peer, event, charge);
            }
        }
    }

    /// Installs the companion profile before any link exists; `None`
    /// refuses every companion frame.
    pub fn set_companion_profile(&mut self, profile: Option<CompanionProfile>) {
        self.companion = CompanionLinks::new(profile, self.config.server_name.clone());
    }

    /// Whether the companion profile is active on the live link of `peer`.
    #[must_use]
    pub fn companion_active(&self, peer: ServerId) -> bool {
        self.peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .is_some_and(|live| self.companion.profile_active(live.link))
    }

    /// Drains the admitted companion frames of `peer`'s live link.
    pub fn drain_companion(&mut self, peer: ServerId) -> Vec<CompanionFrame> {
        match self.peers.get(&peer).and_then(|state| state.live.as_ref()) {
            Some(live) => self.companion.drain(live.link),
            None => Vec::new(),
        }
    }

    fn handle_companion(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        frame: CompanionFrame,
    ) -> Result<(), Violation> {
        let Some(live) = self
            .peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .filter(|live| live.link == link)
        else {
            return Ok(());
        };
        match self.companion.on_frame(link, frame) {
            Ok(CompanionAction::Quiet) => {}
            Ok(CompanionAction::Send(line)) => match live.handle.try_send(line) {
                Ok(()) | Err(SendRefusal::Closed) => {}
                Err(SendRefusal::QueueFull) => return Err(Violation::SlowConsumer),
            },
            Err(violation) => {
                if let Ok(line) = self.companion.violation_line() {
                    let _ = live.handle.try_send(line);
                }
                return Err(Violation::Companion(violation));
            }
        }
        for admitted in self.companion.drain(link) {
            companion::admitted(self, context, link, peer, admitted)?;
        }
        Ok(())
    }

    fn start_companion(&mut self, context: &mut StateCoreContext, link: LinkId, peer: ServerId) {
        let now = context.now();
        let outcome = self.companion.link_established(link, tick_millis(now));
        let Some(live) = self
            .peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .filter(|live| live.link == link)
        else {
            return;
        };
        match outcome {
            Ok(Some(offer)) => {
                let _ = live.handle.try_send(offer);
                let deadline = self
                    .companion
                    .deadline(link)
                    .map_or(now, MonotonicTick::from_ticks);
                let _ = context.timers_mut().schedule(
                    deadline,
                    TimerKind::CompanionProfileDeadline,
                    TimedId::Peer(peer),
                );
            }
            Ok(None) => {}
            Err(violation) => self.fail_link(context, link, peer, Violation::Companion(violation)),
        }
    }

    fn companion_timer_fired(&mut self, context: &mut StateCoreContext, entry: TimerEntry) -> bool {
        let (TimerKind::CompanionProfileDeadline, TimedId::Peer(peer)) = (entry.kind, entry.id)
        else {
            return false;
        };
        let Some(link) = self
            .peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .map(|live| live.link)
        else {
            return true;
        };
        if let Err(violation) = self
            .companion
            .deadline_fired(link, tick_millis(entry.deadline))
        {
            self.fail_link(context, link, peer, Violation::Companion(violation));
        }
        true
    }

    /// Runs one frame or object handler on a live link. A handler may
    /// retire the link itself when a write finds the link task gone; a
    /// failure after that is moot.
    fn handle_traffic(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        event: LinkEvent,
        charge: Option<IngressCharge>,
    ) {
        if !self.link_is_live(link, peer) {
            return;
        }
        let outcome = match event {
            LinkEvent::Frame(frame) => self.handle_frame(context, link, peer, frame),
            LinkEvent::Object { carrier, object } => {
                self.handle_object(context, link, peer, carrier, object, charge)
            }
            LinkEvent::Companion(frame) => self.handle_companion(context, link, peer, frame),
            LinkEvent::Established { .. } | LinkEvent::Closed(_) => return,
        };
        if let Err(violation) = outcome
            && self.link_is_live(link, peer)
        {
            self.fail_link(context, link, peer, violation);
        }
    }

    fn link_is_live(&self, link: LinkId, peer: ServerId) -> bool {
        self.peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .is_some_and(|live| live.link == link)
    }

    fn link_established(
        &mut self,
        context: &mut StateCoreContext,
        session: LinkSession,
        handle: LinkHandle,
    ) {
        let Some(state) = self.peers.get_mut(&session.peer) else {
            return;
        };
        if state.quarantined
            || state.fence_pending
            || state.phase == PeerPhase::Expired
            || self
                .origins
                .fenced_incarnations_of(session.peer)
                .any(|incarnation| incarnation == session.peer_incarnation)
        {
            // A quarantined peer never regains a link until an operator
            // re-enables it through configuration and a restart.
            handle.close();
            return;
        }
        if let Some(previous) = state.live.take() {
            self.links.remove(&previous.link);
        }
        state.reconciliation = None;
        let _cancelled = context.timers_mut().cancel(
            TimerKind::FederationResumeRetry,
            TimedId::Peer(session.peer),
        );
        state.live = Some(LiveLink {
            link: session.link,
            handle,
            incarnation: session.peer_incarnation,
        });
        state.recovery_epoch = Some(session.peer_recovery_epoch);
        if !state.accepted_epochs.contains(&session.peer_recovery_epoch) {
            state.accepted_epochs.push(session.peer_recovery_epoch);
        }
        if self
            .origins
            .link_reestablished(session.peer, session.peer_incarnation)
        {
            // The edge is back before its grace passed, so its disconnect grace
            // is cancelled: a link that reconnects but resyncs slowly must not
            // be fenced as if it were gone. A later loss starts a fresh grace.
            state.grace_deadline = None;
            grace::cancel_grace(context, session.peer);
        }
        self.links.insert(session.link, session.peer);
        if context
            .federation()
            .and_then(|projector| projector.edge(session.peer))
            .is_none()
        {
            let generation = state.projection_generation;
            if let Some(projector) = context.federation_mut() {
                projector.set_edge(
                    session.peer,
                    EdgeDelivery {
                        projection_generation: generation,
                        next_delivery_sequence: 0,
                    },
                );
            }
        }
        self.sync_outbox_budget(context, session.peer);
        self.start_companion(context, session.link, session.peer);
    }

    fn link_closed(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        _reason: LinkCloseReason,
    ) {
        if !self.link_is_live(link, peer) {
            return;
        }
        resume_reconciliation::cancel(self, context, peer);
        self.links.remove(&link);
        self.remote_carriers_link_closed(peer);
        self.companion.link_closed(link);
        if let Some(executor) = self.companion_exec.as_mut() {
            executor.link_closed(peer);
        }
        let _cancelled = context
            .timers_mut()
            .cancel(TimerKind::CompanionProfileDeadline, TimedId::Peer(peer));
        let _cancelled = context
            .timers_mut()
            .cancel(TimerKind::CompanionSnapshotExpiry, TimedId::Peer(peer));
        if let Some(state) = self.peers.get_mut(&peer) {
            state.live = None;
            state.queued.clear();
            state.active = false;
            state.resend = None;
            if state
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| !snapshot.ready)
            {
                state.snapshot = None;
            }
        }
        if self
            .crypto
            .as_ref()
            .is_some_and(|pending| pending.link == link)
        {
            request::abandon_crypto(self, context);
        }
        grace::link_lost(self, context, peer);
    }

    /// Closes a link after a protocol violation and treats it as lost.
    fn fail_link(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        _violation: Violation,
    ) {
        self.counters.violations = self.counters.violations.saturating_add(1);
        if let Some(live) = self
            .peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .filter(|live| live.link == link)
        {
            live.handle.close();
        }
        self.link_closed(context, link, peer, LinkCloseReason::Framing);
    }

    fn handle_frame(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        frame: FederationFrame,
    ) -> Result<(), Violation> {
        match frame {
            FederationFrame::Ack {
                coordinator_server_id,
                delivery_sequence,
                event_id,
            } => {
                self.require_self(coordinator_server_id)?;
                self.acknowledge(context, peer, delivery_sequence, event_id)
            }
            FederationFrame::OriginReset {
                coordinator_server_id,
                server_incarnation,
            } => {
                self.require_self(coordinator_server_id)?;
                origin::reset(self, context, peer, server_incarnation)
            }
            FederationFrame::OriginDel {
                coordinator_server_id,
                server_incarnation,
                origin_id,
                generation,
                next_operation_sequence,
            } => {
                self.require_self(coordinator_server_id)?;
                origin::delete(
                    self,
                    context,
                    link,
                    peer,
                    OriginKey {
                        home_server_id: peer,
                        server_incarnation,
                        origin_id,
                    },
                    generation,
                    next_operation_sequence,
                )
            }
            FederationFrame::Resume {
                coordinator_server_id,
                projection_generation,
                cursor,
            } => {
                self.require_self(coordinator_server_id)?;
                snapshot::resume(self, context, link, peer, projection_generation, cursor)
            }
            FederationFrame::SnapshotReady {
                coordinator_server_id,
                identity,
            } => {
                self.require_self(coordinator_server_id)?;
                snapshot::ready(self, context, link, peer, identity)
            }
            _ => Err(Violation::Phase),
        }
    }

    fn handle_object(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        carrier: ObjectCarrier,
        object: agenc_ircd_federation_wire::AssembledObject,
        charge: Option<IngressCharge>,
    ) -> Result<(), Violation> {
        match carrier {
            ObjectCarrier::Request(descriptor) => {
                request::receive(self, context, link, peer, descriptor, object, charge)
            }
            ObjectCarrier::OriginAdd(descriptor) => origin::declare(
                self, context, link, peer, descriptor, &object, charge, false,
            ),
            ObjectCarrier::OriginUpdate(descriptor) => {
                origin::declare(self, context, link, peer, descriptor, &object, charge, true)
            }
            ObjectCarrier::Result(_)
            | ObjectCarrier::Event(_)
            | ObjectCarrier::SnapshotEntry { .. } => Err(Violation::Phase),
        }
    }

    fn require_self(&self, server_id: ServerId) -> Result<(), Violation> {
        if server_id == self.config.server_id {
            Ok(())
        } else {
            Err(Violation::Misaddressed)
        }
    }

    /// Records one cumulative acknowledgement of exactly the oldest event.
    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one acknowledgement walks the unacknowledged window once under both the exact-next and the barrier-cumulative rules
    fn acknowledge(
        &mut self,
        context: &mut StateCoreContext,
        peer: ServerId,
        delivery_sequence: u64,
        event_id: EventId,
    ) -> Result<(), Violation> {
        let barrier = barriers::prepare(
            self,
            peer,
            barriers::Side::Base,
            delivery_sequence,
            *event_id.as_bytes(),
        )?;
        // Inside an open barrier the edge acknowledges the last base part
        // cumulatively; elsewhere the ACK advances by exactly one.
        let barrier_last = self
            .barriers
            .get(&peer)
            .filter(|barrier| !barrier.base_acked())
            .map(|barrier| barrier.base().last());
        let state = self.peers.get(&peer).ok_or(Violation::Misaddressed)?;
        if state.reconciliation.is_some() {
            return Err(Violation::Phase);
        }
        let Some((front, expected, _)) = state.outbox.unacked.front().copied() else {
            return Err(Violation::Acknowledgement);
        };
        let cumulative = barrier_last == Some(delivery_sequence) && delivery_sequence >= front;
        if !cumulative && (front != delivery_sequence || expected != event_id) {
            return Err(Violation::Acknowledgement);
        }
        let generation = state.projection_generation;
        let mut writes = Vec::new();
        let mut matched = false;
        for (sequence, id, _) in state.outbox.unacked.iter().copied() {
            if sequence > delivery_sequence {
                break;
            }
            matched |= sequence == delivery_sequence && id == event_id;
            let key =
                agenc_ircd_storage::federation_records::outbox_key(peer, generation, sequence)
                    .map_err(|_| Violation::Ceiling)?;
            writes.push(
                AccountServiceDurableWrite::delete(TableId::EdgeOutbox, key)
                    .map_err(|_| Violation::Ceiling)?,
            );
        }
        if !matched {
            return Err(Violation::Acknowledgement);
        }
        let plan = context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| Violation::Ceiling)?;
        writes.push(
            self.peer_row_at(
                peer,
                plan.resulting_revision().get(),
                Some((delivery_sequence, event_id)),
            )
            .map_err(|_| Violation::Ceiling)?,
        );
        if let Some(update) = &barrier {
            writes.push(update.write(plan.resulting_revision().get())?);
        }
        let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
            .map_err(|_| Violation::Ceiling)?;
        context
            .stage_durable_with_account_service(plan, fanout, None, 0, writes)
            .map_err(|_| Violation::Ceiling)?;
        self.pending = Some(PendingCommit::DeliveryAcknowledged {
            resume: None,
            peer,
            delivery_sequence,
            event_id,
            barrier,
        });
        Ok(())
    }

    /// Publishes ACK coverage only after its deletion and peer row commit.
    fn acknowledgement_committed(
        &mut self,
        context: &mut StateCoreContext,
        peer: ServerId,
        delivery_sequence: u64,
        event_id: EventId,
        barrier: Option<Box<barriers::Prepared>>,
    ) {
        if barrier.is_some_and(|update| update.apply(self).is_err()) {
            startup::fail_restore(self);
            return;
        }
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        while let Some((sequence, _, bytes)) = state.outbox.unacked.front().copied() {
            if sequence > delivery_sequence {
                break;
            }
            state.outbox.unacked.pop_front();
            state.outbox.unacked_bytes = state.outbox.unacked_bytes.saturating_sub(bytes);
        }
        state.outbox.cursor = Some((delivery_sequence, event_id));
        companion::try_close_barrier(self, context, peer);
    }

    /// Stages rows that carry no domain mutation behind a checkpoint plan,
    /// adding the current peer row of `peer_row` when requested.
    fn stage_rows(
        &mut self,
        context: &mut StateCoreContext,
        mut writes: Vec<AccountServiceDurableWrite>,
        pending: PendingCommit,
        peer_row: Option<ServerId>,
    ) -> Result<(), RuntimeError> {
        if self.pending.is_some() {
            return Err(RuntimeError::LimitExceeded);
        }
        let plan = context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| RuntimeError::InvalidValue)?;
        if let Some(peer) = peer_row {
            writes.push(self.peer_row(peer, plan.resulting_revision().get())?);
        }
        let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?;
        context
            .stage_durable_with_account_service(plan, fanout, None, 0, writes)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        self.pending = Some(pending);
        Ok(())
    }

    /// Encodes the durable peer row reflecting the current in-memory state.
    fn peer_row(
        &self,
        peer: ServerId,
        revision: u64,
    ) -> Result<AccountServiceDurableWrite, RuntimeError> {
        let cursor = self
            .peers
            .get(&peer)
            .ok_or(RuntimeError::InvalidValue)?
            .outbox
            .cursor;
        self.peer_row_at(peer, revision, cursor)
    }

    fn peer_record_at(
        &self,
        peer: ServerId,
        cursor: Option<(u64, EventId)>,
    ) -> Result<FederationPeerRecord, RuntimeError> {
        let state = self.peers.get(&peer).ok_or(RuntimeError::InvalidValue)?;
        let next_delivery_sequence = state.outbox.reserved_next.max(
            state.outbox.unacked.back().map_or(
                state
                    .outbox
                    .cursor
                    .map_or(0, |(sequence, _)| sequence.saturating_add(1)),
                |(sequence, _, _)| sequence.saturating_add(1),
            ),
        );
        Ok(FederationPeerRecord {
            fenced_incarnations: self
                .origins
                .fenced_incarnations_of(peer)
                .map(|incarnation| *incarnation.as_bytes())
                .collect(),
            server_incarnation: state
                .incarnation
                .map_or([0; 16], |incarnation| *incarnation.as_bytes()),
            recovery_epoch: state
                .recovery_epoch
                .map_or([0; 16], |epoch| *epoch.as_bytes()),
            accepted_epochs: state
                .accepted_epochs
                .iter()
                .map(|epoch| *epoch.as_bytes())
                .collect(),
            phase: state.phase,
            projection_generation: state.projection_generation,
            next_delivery_sequence,
            cursor: cursor.map(|(delivery_sequence, event_id)| DeliveryCursorRecord {
                delivery_sequence,
                event_id: *event_id.as_bytes(),
            }),
            active_entry_count: context_entry_count(state),
            active_entry_bytes: 0,
            pending_generation: None,
            snapshot_required: state.outbox.snapshot_required,
            cleanup_cursor: state.cleanup_cursor,
            quarantined: state.quarantined,
            client_resync_epoch: state.client_resync_epoch,
        })
    }

    fn peer_row_at(
        &self,
        peer: ServerId,
        revision: u64,
        cursor: Option<(u64, EventId)>,
    ) -> Result<AccountServiceDurableWrite, RuntimeError> {
        let record = self.peer_record_at(peer, cursor)?.encode()?;
        let plaintext = PersistentRecordValue::new(
            TableId::FederationPeer,
            PEER_RECORD_KIND,
            revision,
            0,
            None,
            Vec::new(),
            record,
        )?
        .encode()?;
        AccountServiceDurableWrite::put(TableId::FederationPeer, peer_key(peer)?, plaintext)
    }

    fn sync_outbox_budget(&self, context: &mut StateCoreContext, peer: ServerId) {
        let Some(state) = self.peers.get(&peer) else {
            return;
        };
        let Ok(record) = self.peer_record_at(peer, state.outbox.cursor) else {
            return;
        };
        if let Some(projector) = context.federation_mut() {
            projector.set_outbox_budget(
                peer,
                crate::state_core::projector::OutboxBudget {
                    peer: record,
                    objects: u64::try_from(state.outbox.unacked.len()).unwrap_or(u64::MAX),
                    bytes: state.outbox.unacked_bytes,
                    max_objects: self.config.outbox_objects_per_edge,
                    max_bytes: self.config.outbox_bytes_per_edge,
                    barrier_open: self.barriers.contains_key(&peer),
                },
            );
        }
    }

    fn apply_outbox_fences(&mut self, context: &mut StateCoreContext) {
        let fences = context
            .federation_mut()
            .map_or_else(Vec::new, |projector| projector.take_outbox_fences());
        for peer in fences {
            let Some(state) = self.peers.get_mut(&peer) else {
                continue;
            };
            state.outbox.snapshot_required = true;
            state.outbox.dirty = false;
            if let Some(link) = state.live.as_ref().map(|live| live.link) {
                self.fail_link(context, link, peer, Violation::Ceiling);
            }
        }
    }

    /// Starts the durable reload before the first link is accepted.
    pub fn startup(&mut self, context: &mut StateCoreContext) {
        startup::begin(self, context);
    }

    /// Reports whether the durable reload finished.
    #[must_use]
    pub fn loaded(&self) -> bool {
        self.loader.is_complete()
    }

    /// Reports whether a storage read belongs to the coordinator.
    #[must_use]
    pub fn owns_storage_read(&self, read_id: StorageReadId) -> bool {
        self.loader.owns(read_id)
            || companion::ack_read::owns(self, read_id)
            || companion::page_read::owns(self, read_id)
            || self.replays.contains_key(&read_id)
            || snapshot::owns_read(self, read_id)
            || resume_reconciliation::owns_read(self, read_id)
            || self.history.owns(read_id)
    }

    /// Consumes a completed storage read that belongs to the coordinator.
    pub fn storage_read_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: crate::bridge::StorageReadCompletionMessage,
    ) {
        if companion::ack_read::owns(self, message.read_id) {
            companion::ack_read::completed(self, context, message);
            return;
        }
        if companion::page_read::owns(self, message.read_id) {
            companion::page_read::completed(self, context, message);
            return;
        }
        if self.loader.owns(message.read_id) {
            startup::read_completed(self, context, message);
            return;
        }
        if resume_reconciliation::owns_read(self, message.read_id) {
            resume_reconciliation::read_completed(self, context, message);
            return;
        }
        if snapshot::owns_read(self, message.read_id) {
            snapshot::resend_completed(self, context, message);
            return;
        }
        if self.history.owns(message.read_id) {
            history::read_completed(self, context, message);
            request::drain_queued(self, context);
            return;
        }
        request::replay_completed(self, context, message);
        request::drain_queued(self, context);
    }

    /// Resumes the federated request whose crypto job completed.
    pub fn crypto_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
    ) {
        request::crypto_completed(self, context, message);
    }

    /// Handles a due timer; returns `false` when it was not federation's.
    pub fn timer_fired(
        &mut self,
        context: &mut StateCoreContext,
        entry: crate::state_core::timers::TimerEntry,
    ) -> bool {
        grace::timer_fired(self, context, entry)
            || resume_reconciliation::timer_fired(self, context, entry)
            || snapshot::timer_fired(self, context, entry)
            || self.companion_timer_fired(context, entry)
            || companion::snapshot_timer_fired(self, context, entry)
            || companion::mailbox_timer_fired(self, context, entry)
            || self.queries.timer_fired(context, entry)
    }

    fn settle_request(&mut self, context: &mut StateCoreContext, pending: PendingCommit) -> bool {
        let PendingCommit::Request {
            peer,
            link,
            key,
            request_id,
            request_object_id,
            result,
            descriptor,
            query,
            ..
        } = pending
        else {
            return false;
        };
        // Tuple fields drop in order on every return: destroy encoded result
        // backing before returning its final-page reservation.
        let publication = (result, query);
        if self.origins.commit_request(key, request_id).is_err() {
            self.fail_link(context, link, peer, Violation::Origin);
            return false;
        }
        self.retained.insert(
            key,
            RetainedRequest {
                request_id,
                request_object_id: *request_object_id.as_bytes(),
            },
        );
        self.counters.requests_committed = self.counters.requests_committed.saturating_add(1);
        if request::remember_registration(self, context, key.origin, &publication.0).is_err() {
            self.fail_link(context, link, peer, Violation::Codec);
            return false;
        }
        self.send_result(context, link, peer, descriptor, &publication.0);
        self.remote_grant_committed();
        true
    }

    fn publish_origin_ack(
        &mut self,
        context: &mut StateCoreContext,
        peer: ServerId,
        link: LinkId,
        frame: FederationFrame,
        closed_carrier: Option<crate::connection::ConnectionGeneration>,
    ) {
        if let Some(generation) = closed_carrier {
            self.retire_remote_carrier(generation);
        }
        let _live = self.send_frame(context, link, peer, &frame);
        origin::continue_ready(self, context, peer);
    }

    fn publish_origin_ready(
        &mut self,
        context: &mut StateCoreContext,
        peer: ServerId,
        link: LinkId,
    ) {
        context.resume_federation_peer(peer);
        if let Some(incarnation) = self.peers.get(&peer).and_then(|state| state.incarnation) {
            self.send_frame(
                context,
                link,
                peer,
                &FederationFrame::OriginReady {
                    edge_server_id: peer,
                    server_incarnation: incarnation,
                },
            );
            companion::base_ready(self, context, peer, incarnation);
        }
    }

    fn settle_remote_results(&mut self, context: &mut StateCoreContext) {
        for result in context.take_committed_remote_results() {
            let peer = result.header.replay_key.home_server_id;
            if self.record_remote_result(result).is_err()
                && let Some(link) = self
                    .peers
                    .get(&peer)
                    .and_then(|state| state.live.as_ref())
                    .map(|live| live.link)
            {
                self.fail_link(context, link, peer, Violation::Origin);
            }
        }
    }

    fn take_pending_for_receipt(&mut self, context: &StateCoreContext) -> Option<PendingCommit> {
        // Account completion runs earlier in the router's callback and can
        // stage a new outer result. That result does not belong to this receipt.
        if matches!(self.pending.as_ref(), Some(PendingCommit::Request { staged_after, .. })
            if context.head().storage_commit_sequence <= *staged_after)
            || matches!(self.pending.as_ref(), Some(PendingCommit::ResumeAcknowledged(receipt))
                if context.head().storage_commit_sequence <= receipt.staged_after)
            || matches!(self.pending.as_ref(), Some(PendingCommit::CompanionRestore(receipt))
                if context.head().storage_commit_sequence <= receipt.staged_after)
        {
            None
        } else {
            self.pending.take()
        }
    }

    /// Finishes the batch that just committed and delivers its events.
    pub fn batch_applied(&mut self, context: &mut StateCoreContext) {
        let events = context.take_outbound_events();
        self.settle_remote_results(context);
        let pending = self.take_pending_for_receipt(context);
        match pending {
            Some(PendingCommit::History(prepared)) => history::committed(self, context, *prepared),
            Some(PendingCommit::HistoryCleanup(cleanup)) => {
                history::cleanup_committed(self, context, cleanup)
            }
            Some(pending @ PendingCommit::Request { .. }) => {
                if !self.settle_request(context, pending) {
                    return;
                }
            }
            Some(PendingCommit::OriginAck {
                peer,
                link,
                frame,
                closed_carrier,
                ..
            }) => self.publish_origin_ack(context, peer, link, frame, closed_carrier),
            Some(PendingCommit::OriginReady { peer, link }) => {
                self.publish_origin_ready(context, peer, link)
            }
            Some(PendingCommit::OriginExpired {
                peer,
                link,
                descriptor,
                result,
                ..
            }) => {
                self.send_result(context, link, peer, descriptor, &result);
            }
            Some(PendingCommit::AuthorityFence {
                peer,
                generation,
                cursor,
            }) => {
                authority::committed(self, context, peer, generation, cursor);
            }
            Some(PendingCommit::CleanupFinished { peer }) => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.phase = PeerPhase::Clean;
                    state.cleanup_cursor = None;
                }
            }
            Some(PendingCommit::Cleanup { peer }) => {
                authority::cleanup_committed(self, context, peer);
            }
            Some(
                pending @ (PendingCommit::CompanionRestore(_) | PendingCommit::Companion { .. }),
            ) => {
                self.companion_receipt(context, pending, &events);
            }
            Some(PendingCommit::SnapshotRows { peer }) => {
                snapshot::continue_write(self, context, peer)
            }
            Some(PendingCommit::SnapshotReady { peer }) => {
                snapshot::ready_committed(self, context, peer)
            }
            Some(pending @ PendingCommit::DeliveryAcknowledged { .. }) => {
                self.delivery_ack_receipt(context, pending)
            }
            Some(PendingCommit::ResumeAcknowledged(receipt)) => {
                resume_reconciliation::committed(self, context, receipt);
            }
            Some(PendingCommit::OutboxRequired { peer }) => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.outbox.dirty = false;
                }
            }
            Some(PendingCommit::Acknowledged) | None => {}
        }
        self.deliver_committed_then_continue(context, events);
    }

    fn delivery_ack_receipt(&mut self, context: &mut StateCoreContext, pending: PendingCommit) {
        let PendingCommit::DeliveryAcknowledged {
            resume,
            peer,
            delivery_sequence,
            event_id,
            barrier,
        } = pending
        else {
            return;
        };
        self.acknowledgement_committed(context, peer, delivery_sequence, event_id, barrier);
        if let Some(link) = resume {
            snapshot::barrier_resume_committed(self, context, peer, link);
        }
    }

    fn deliver_committed_then_continue(
        &mut self,
        context: &mut StateCoreContext,
        events: Vec<crate::state_core::projector::OutboundEvent>,
    ) {
        self.deliver(context, events);
        self.continue_after_commit(context);
    }

    fn companion_receipt(
        &mut self,
        context: &mut StateCoreContext,
        pending: PendingCommit,
        events: &[crate::state_core::projector::OutboundEvent],
    ) {
        match pending {
            PendingCommit::CompanionRestore(receipt) => {
                startup::retirement::committed(self, context, *receipt)
            }
            PendingCommit::Companion {
                peer,
                link,
                barrier,
                resume,
            } => companion::committed(self, context, link, peer, events, barrier, resume),
            _ => {}
        }
    }

    fn continue_after_commit(&mut self, context: &mut StateCoreContext) {
        self.continue_background(context);
        request::drain_queued(self, context);
        companion::drain_queued(self, context);
        self.drain_backlog(context);
    }

    /// Resumes bounded background work that waits for a free batch slot:
    /// pending snapshot rows and expiry cleanup.
    fn continue_background(&mut self, context: &mut StateCoreContext) {
        if context.in_flight()
            || context.pending_len() != 0
            || self.loader.blocks_admission()
            || self.companion_ack_read.is_some()
        {
            return;
        }
        let peers: Vec<ServerId> = self.peers.keys().copied().collect();
        for peer in peers {
            if self.pending.is_some() {
                return;
            }
            authority::continue_fence(self, context, peer);
            if self.pending.is_some() {
                return;
            }
            authority::continue_clean(self, context, peer);
            if self.pending.is_some() {
                return;
            }
            if self
                .peers
                .get(&peer)
                .is_some_and(|state| state.outbox.dirty)
            {
                let _staged = self.stage_rows(
                    context,
                    Vec::new(),
                    PendingCommit::OutboxRequired { peer },
                    Some(peer),
                );
                return;
            }
            self.continue_delivery_work(context, peer);
        }
    }

    fn continue_delivery_work(&mut self, context: &mut StateCoreContext, peer: ServerId) {
        origin::continue_ready(self, context, peer);
        if self.pending.is_some() {
            return;
        }
        snapshot::continue_write(self, context, peer);
        if self.pending.is_some() {
            return;
        }
        grace::continue_cleanup(self, context, peer);
    }

    /// Drops the work behind a rejected batch. A request answers busy without
    /// a durable row, so its client retries and the origin sequence stays
    /// where the edge left it. An origin acknowledgement that did not
    /// persist and a snapshot whose marker row did not persist lose their
    /// link, so the edge declares or resumes again from its committed state
    /// instead of waiting for an answer the coordinator will never send.
    pub fn batch_rejected(&mut self, context: &mut StateCoreContext) {
        self.batch_rejected_with_error(context, agenc_ircd_storage::StorageError::Unavailable);
    }

    /// Settles the exact storage refusal without advancing durable coverage.
    pub fn batch_rejected_with_error(
        &mut self,
        context: &mut StateCoreContext,
        error: agenc_ircd_storage::StorageError,
    ) {
        context.reject_remote_account_results();
        self.remote_grant_rejected();
        match self.pending.take() {
            Some(PendingCommit::ResumeAcknowledged(receipt)) => {
                resume_reconciliation::rejected(self, context, receipt, error);
            }
            Some(PendingCommit::History(prepared)) => history::rejected(self, *prepared),
            Some(PendingCommit::Cleanup { peer }) => grace::continue_cleanup(self, context, peer),
            Some(PendingCommit::Request {
                peer,
                link,
                key,
                request_object_id,
                descriptor,
                header,
                result,
                query,
                ..
            }) => {
                // The serialized page must die before its last query permit.
                drop(result);
                if let Some(receipt) = query {
                    self.queries.reject_page(receipt, context.now());
                }
                request::rejected(
                    self,
                    context,
                    link,
                    peer,
                    FreshRequest {
                        key,
                        header,
                        descriptor,
                        request_object_id,
                        bound: None,
                        command: None,
                        mutation: agenc_ircd_domain::federation::MutationContext::default(),
                        charge: None,
                    },
                );
            }
            Some(PendingCommit::OriginAck { peer, link, .. })
            | Some(PendingCommit::OriginReady { peer, link })
            | Some(PendingCommit::OriginExpired { peer, link, .. }) => {
                if self.link_is_live(link, peer) {
                    self.fail_link(context, link, peer, Violation::Ceiling);
                }
            }
            Some(PendingCommit::CompanionRestore(receipt)) => {
                startup::retirement::rejected(self, context, *receipt, error);
            }
            Some(PendingCommit::Companion { .. }) => {
                if let Some(executor) = self.companion_exec.as_mut() {
                    executor.batch_rejected();
                }
            }
            Some(PendingCommit::SnapshotRows { peer } | PendingCommit::SnapshotReady { peer }) => {
                snapshot::rejected(self, context, peer);
            }
            Some(PendingCommit::DeliveryAcknowledged { peer, .. }) => {
                let link = self
                    .peers
                    .get(&peer)
                    .and_then(|state| state.live.as_ref())
                    .map(|live| live.link);
                if let Some(link) = link {
                    self.fail_link(context, link, peer, Violation::Ceiling);
                }
            }
            _ => {}
        }
        request::drain_queued(self, context);
        self.drain_backlog(context);
    }

    /// Replays backlogged link traffic in arrival order until a replayed
    /// item stages the next batch.
    fn drain_backlog(&mut self, context: &mut StateCoreContext) {
        while self.pending.is_none()
            && self.companion_ack_read.is_none()
            && !self.loader.blocks_admission()
        {
            let Some(message) = self.backlog.pop_front() else {
                break;
            };
            self.inbound(context, message);
        }
    }

    /// Sends committed events to their live links and tracks the
    /// unacknowledged window.
    fn deliver(&mut self, context: &mut StateCoreContext, events: Vec<OutboundEvent>) {
        self.apply_outbox_fences(context);
        for event in events {
            if !self.retain_outbound(context, &event) {
                continue;
            }
            let Some(state) = self.peers.get(&event.target) else {
                continue;
            };
            // Inactive links and events behind a barrier remain in the
            // durable outbox, but still count against the retention budget.
            if !state.active
                || self
                    .barriers
                    .get(&event.target)
                    .is_some_and(|barrier| event.delivery_sequence > barrier.base().last())
            {
                continue;
            }
            let Some(live) = state.live.as_ref() else {
                continue;
            };
            let frame = |fragment| FederationFrame::Event {
                descriptor: EventDescriptor {
                    target_server_id: event.target,
                    delivery_sequence: event.delivery_sequence,
                    event_id: event.event_id,
                    object_id: event.object_id,
                },
                fragment,
            };
            let (link, sent) = (
                live.link,
                send_object(
                    &live.handle,
                    &self.config.server_name,
                    &event.encoded,
                    frame,
                ),
            );
            match sent {
                Ok(()) => self.counters.events_sent = self.counters.events_sent.saturating_add(1),
                Err(failure) => self.send_failed(context, link, event.target, failure),
            }
        }
        for peer in self.peers.keys().copied() {
            self.sync_outbox_budget(context, peer);
        }
    }

    fn retain_outbound(&mut self, context: &mut StateCoreContext, event: &OutboundEvent) -> bool {
        let Some(state) = self.peers.get_mut(&event.target) else {
            return false;
        };
        if event.projection_generation != state.projection_generation {
            return false;
        }
        state.outbox.reserved_next = state
            .outbox
            .reserved_next
            .max(event.delivery_sequence.saturating_add(1));
        let bytes = u64::try_from(event.encoded.len()).unwrap_or(u64::MAX);
        if !state.outbox.snapshot_required {
            state
                .outbox
                .unacked
                .push_back((event.delivery_sequence, event.event_id, bytes));
            state.outbox.unacked_bytes = state.outbox.unacked_bytes.saturating_add(bytes);
        }
        let over_ceiling = u64::try_from(state.outbox.unacked.len()).unwrap_or(u64::MAX)
            > self.config.outbox_objects_per_edge
            || state.outbox.unacked_bytes > self.config.outbox_bytes_per_edge;
        if over_ceiling && !state.outbox.snapshot_required {
            state.outbox.snapshot_required = true;
            state.outbox.dirty = true;
        }
        if state.outbox.snapshot_required {
            if let Some(projector) = context.federation_mut() {
                projector.require_snapshot(event.target);
            }
            if let Some(link) = state.live.as_ref().map(|live| live.link) {
                self.fail_link(context, link, event.target, Violation::Ceiling);
            }
            return false;
        }
        true
    }

    fn send_result(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        descriptor: OperationDescriptor,
        encoded: &[u8],
    ) {
        let Some(live) = self.peers.get(&peer).and_then(|state| state.live.as_ref()) else {
            return;
        };
        if live.link != link {
            return;
        }
        let descriptor = OperationDescriptor {
            object_id: federation_object_id(encoded),
            ..descriptor
        };
        let frame = |fragment| FederationFrame::Result {
            descriptor,
            fragment,
        };
        if let Err(failure) = send_object(&live.handle, &self.config.server_name, encoded, frame) {
            self.send_failed(context, link, peer, failure);
        }
    }

    /// Queues one frame for the link; returns whether the link is still
    /// live afterwards, so a caller can stop a sequence the write ended.
    fn send_frame(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        frame: &FederationFrame,
    ) -> bool {
        let Some(live) = self.peers.get(&peer).and_then(|state| state.live.as_ref()) else {
            return false;
        };
        if live.link != link {
            return false;
        }
        let sent = frame
            .render(&self.config.server_name)
            .map_err(|_| SendFailure::Violation(Violation::Codec))
            .and_then(|line| live.handle.try_send(line).map_err(SendFailure::from));
        if let Err(failure) = sent {
            self.send_failed(context, link, peer, failure);
        }
        self.link_is_live(link, peer)
    }

    /// Handles a refused outbound write: a violation fails the link, while a
    /// queue whose task already ended retires the link without a violation.
    fn send_failed(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        failure: SendFailure,
    ) {
        match failure {
            SendFailure::Violation(violation) => self.fail_link(context, link, peer, violation),
            SendFailure::Closed => {
                self.link_closed(context, link, peer, LinkCloseReason::PeerClosed)
            }
        }
    }
}

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

/// Standing entry counts are accounted per edge by the projector; the peer
/// row records the last known count for STATS and the snapshot ceiling.
fn context_entry_count(state: &PeerState) -> u64 {
    let _ = state;
    0
}

/// Splits one encoded object into fragments and queues every rendered line.
fn send_object(
    handle: &LinkHandle,
    server_name: &str,
    encoded: &[u8],
    frame: impl Fn(agenc_ircd_federation_wire::FederationFragment) -> FederationFrame,
) -> Result<(), SendFailure> {
    let object_id = federation_object_id(encoded);
    let fragments = split_fragments(object_id, encoded)
        .map_err(|_| SendFailure::Violation(Violation::Codec))?;
    let mut lines: Vec<FederationLineText> = Vec::new();
    lines
        .try_reserve_exact(fragments.len())
        .map_err(|_| SendFailure::Violation(Violation::Ceiling))?;
    for fragment in fragments {
        lines.push(
            frame(fragment)
                .render(server_name)
                .map_err(|_| SendFailure::Violation(Violation::Codec))?,
        );
    }
    for line in lines {
        handle.try_send(line)?;
    }
    Ok(())
}

/// Encodes one schema object to its canonical bytes.
fn encode_object(object: &SchemaObject) -> Result<Vec<u8>, RuntimeError> {
    object
        .encode_canonical()
        .map(|bytes| bytes.as_slice().to_vec())
        .map_err(|_| RuntimeError::InvalidValue)
}
