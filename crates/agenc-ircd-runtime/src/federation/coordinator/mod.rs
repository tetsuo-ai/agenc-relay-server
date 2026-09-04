//! The coordinator role of the base federation profile (spec 20).
//!
//! One instance lives inside the coordinator's command router. It owns the
//! authenticated edge links, the origin table, the retained request index,
//! and the per-edge outbox position. Every durable effect it produces rides
//! a StateCore batch: the request result, origin, outbox, projection, and
//! peer rows commit with the domain mutation that caused them, and the
//! coordinator only renders FRESULT and FEVENT lines after that commit.

mod accounts;
mod companion;
mod convert;
mod grace;
mod origin;
mod query;
mod request;
mod snapshot;
mod startup;
#[cfg(test)]
#[path = "tests/harness.rs"]
mod tests;

use std::collections::{BTreeMap, VecDeque};

use agenc_ircd_domain::federation::{OperationKey, OriginKey, OriginTable, RetainedRequest};
use agenc_ircd_federation_wire::{
    CanonicalEncode, EventDescriptor, FederationFrame, FederationHash32, FederationLineText,
    OperationDescriptor, SchemaObject, federation_object_id, split_fragments,
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

pub(crate) use accounts::{InFlightCarrier, RemoteAccountWork, challenge_object};
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
    quarantined: bool,
    client_resync_epoch: u64,
    queued: VecDeque<QueuedRequest>,
    /// Whether the link finished FRESUME or ACTIVE and receives live events.
    active: bool,
    snapshot: Option<snapshot::Snapshot>,
    resend: Option<snapshot::Resend>,
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
    Request {
        peer: ServerId,
        link: LinkId,
        key: OperationKey,
        request_id: RequestId,
        request_object_id: FederationHash32,
        result: Vec<u8>,
        descriptor: OperationDescriptor,
        _charge: Option<IngressCharge>,
    },
    OriginAck {
        peer: ServerId,
        link: LinkId,
        frame: FederationFrame,
        _charge: Option<IngressCharge>,
    },
    Cleanup {
        peer: ServerId,
    },
    /// A companion request batch; the executor holds its result.
    Companion {
        peer: ServerId,
        link: LinkId,
    },
    SnapshotRows {
        peer: ServerId,
    },
    SnapshotReady {
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
    queries: query::Queries,
    counters: CoordinatorCounters,
    companion: CompanionLinks,
    /// The E2EE executor; `None` on a node without a sequencer.
    companion_exec: Option<CompanionCoordinator>,
    /// Open cross-profile barriers by target (spec 20.8): later events on
    /// either stream wait until both final acknowledgements arrive.
    barriers: BTreeMap<ServerId, OpenBarrier>,
    remote_accounts: accounts::RemoteAccounts,
}

/// One cross-profile barrier awaiting both cumulative acknowledgements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OpenBarrier {
    /// The per-target mutation identity.
    pub(super) mutation_id: [u8; 16],
    /// The last base delivery sequence of the barrier.
    pub(super) base_last: u64,
    /// Whether the base stream acknowledged through `base_last`.
    pub(super) base_acked: bool,
    /// The last companion delivery sequence of the barrier.
    pub(super) companion_last: u64,
    /// Whether the companion stream acknowledged through `companion_last`.
    pub(super) companion_acked: bool,
}

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
                        quarantined: false,
                        client_resync_epoch: 0,
                        queued: VecDeque::new(),
                        active: false,
                        snapshot: None,
                        resend: None,
                        ready_identity: None,
                    },
                )
            })
            .collect();
        let queries = query::Queries::new(config.query_cursor_key, config.process_nonce);
        let companion = CompanionLinks::new(None, config.server_name.clone());
        Self {
            companion,
            config,
            verifier,
            dummy,
            origins: OriginTable::new(),
            origin_objects: BTreeMap::new(),
            retained: BTreeMap::new(),
            peers,
            links: BTreeMap::new(),
            pending: None,
            crypto: None,
            replays: BTreeMap::new(),
            loader: startup::Loader::default(),
            backlog: VecDeque::new(),
            queries,
            counters: CoordinatorCounters::default(),
            companion_exec: None,
            barriers: BTreeMap::new(),
            remote_accounts: accounts::RemoteAccounts::default(),
        }
    }

    /// Installs the companion executor before any link exists.
    pub fn install_companion_executor(&mut self, executor: CompanionCoordinator) {
        self.companion_exec = Some(executor);
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
        self.pending.is_none() && self.crypto.is_none() && self.replays.is_empty()
    }

    /// Dispatches one link message at a safe point.
    pub fn inbound(&mut self, context: &mut StateCoreContext, message: FederationInbound) {
        let FederationInbound {
            link,
            peer,
            event,
            charge,
        } = message;
        if !self.peers.contains_key(&peer) {
            return;
        }
        if self.pending.is_some()
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
        if state.quarantined {
            // A quarantined peer never regains a link until an operator
            // re-enables it through configuration and a restart.
            handle.close();
            return;
        }
        if let Some(previous) = state.live.take() {
            self.links.remove(&previous.link);
        }
        state.live = Some(LiveLink {
            link: session.link,
            handle,
            incarnation: session.peer_incarnation,
        });
        state.recovery_epoch = Some(session.peer_recovery_epoch);
        if !state.accepted_epochs.contains(&session.peer_recovery_epoch) {
            state.accepted_epochs.push(session.peer_recovery_epoch);
        }
        state.grace_deadline = None;
        self.links.insert(session.link, session.peer);
        grace::cancel_grace(context, session.peer);
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
            FederationFrame::OriginReady {
                edge_server_id,
                server_incarnation,
            } => {
                if edge_server_id != peer {
                    return Err(Violation::Misaddressed);
                }
                origin::ready(self, context, peer, server_incarnation)?;
                companion::base_ready(self, context, peer, server_incarnation);
                Ok(())
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
        // Inside an open barrier the edge acknowledges the last base part
        // cumulatively; elsewhere the ACK advances by exactly one.
        let barrier_last = self
            .barriers
            .get(&peer)
            .filter(|barrier| !barrier.base_acked)
            .map(|barrier| barrier.base_last);
        let state = self.peers.get_mut(&peer).ok_or(Violation::Misaddressed)?;
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
        while let Some((sequence, id, bytes)) = state.outbox.unacked.front().copied() {
            if sequence > delivery_sequence {
                break;
            }
            state.outbox.unacked.pop_front();
            state.outbox.unacked_bytes = state.outbox.unacked_bytes.saturating_sub(bytes);
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
        state.outbox.cursor = Some((delivery_sequence, event_id));
        self.stage_rows(context, writes, PendingCommit::Acknowledged, Some(peer))
            .map_err(|_| Violation::Ceiling)?;
        if barrier_last == Some(delivery_sequence) {
            if let Some(barrier) = self.barriers.get_mut(&peer) {
                barrier.base_acked = true;
            }
            companion::try_close_barrier(self, context, peer);
        }
        Ok(())
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
        let state = self.peers.get(&peer).ok_or(RuntimeError::InvalidValue)?;
        let next_delivery_sequence = state.outbox.unacked.back().map_or(
            state
                .outbox
                .cursor
                .map_or(0, |(sequence, _)| sequence.saturating_add(1)),
            |(sequence, _, _)| sequence.saturating_add(1),
        );
        let record = FederationPeerRecord {
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
            cursor: state
                .outbox
                .cursor
                .map(|(delivery_sequence, event_id)| DeliveryCursorRecord {
                    delivery_sequence,
                    event_id: *event_id.as_bytes(),
                }),
            active_entry_count: context_entry_count(state),
            active_entry_bytes: 0,
            pending_generation: None,
            snapshot_required: state.outbox.snapshot_required,
            cleanup_cursor: state.cleanup.front().map(|user| *user.as_bytes()),
            quarantined: state.quarantined,
            client_resync_epoch: state.client_resync_epoch,
        }
        .encode()?;
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
            || self.replays.contains_key(&read_id)
            || snapshot::owns_read(self, read_id)
    }

    /// Consumes a completed storage read that belongs to the coordinator.
    pub fn storage_read_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: crate::bridge::StorageReadCompletionMessage,
    ) {
        if startup::read_completed(self, context, &message) {
            return;
        }
        if snapshot::owns_read(self, message.read_id) {
            snapshot::resend_completed(self, context, message);
            return;
        }
        request::replay_completed(self, context, message);
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
            || snapshot::timer_fired(self, context, entry)
            || self.companion_timer_fired(context, entry)
            || companion::snapshot_timer_fired(self, context, entry)
    }

    /// Finishes the batch that just committed and delivers its events.
    pub fn batch_applied(&mut self, context: &mut StateCoreContext) {
        let events = context.take_outbound_events();
        match self.pending.take() {
            Some(PendingCommit::Request {
                peer,
                link,
                key,
                request_id,
                request_object_id,
                result,
                descriptor,
                ..
            }) => {
                let _ = self.origins.commit_request(key, request_id);
                self.retained.insert(
                    key,
                    RetainedRequest {
                        request_id,
                        request_object_id: *request_object_id.as_bytes(),
                    },
                );
                self.counters.requests_committed =
                    self.counters.requests_committed.saturating_add(1);
                self.send_result(context, link, peer, descriptor, &result);
                self.remote_grant_committed();
            }
            Some(PendingCommit::OriginAck {
                peer, link, frame, ..
            }) => {
                let _live = self.send_frame(context, link, peer, &frame);
            }
            Some(PendingCommit::Cleanup { peer }) => grace::continue_cleanup(self, context, peer),
            Some(PendingCommit::Companion { peer, link }) => {
                companion::committed(self, context, link, peer, &events);
            }
            Some(PendingCommit::SnapshotRows { peer }) => {
                snapshot::continue_write(self, context, peer)
            }
            Some(PendingCommit::SnapshotReady { peer }) => {
                snapshot::ready_committed(self, context, peer)
            }
            Some(PendingCommit::Acknowledged) | None => {}
        }
        self.deliver(context, events);
        self.continue_background(context);
        request::drain_queued(self, context);
        companion::drain_queued(self, context);
        self.drain_backlog(context);
    }

    /// Resumes bounded background work that waits for a free batch slot:
    /// pending snapshot rows and expiry cleanup.
    fn continue_background(&mut self, context: &mut StateCoreContext) {
        let peers: Vec<ServerId> = self.peers.keys().copied().collect();
        for peer in peers {
            if self.pending.is_some() {
                return;
            }
            snapshot::continue_write(self, context, peer);
            if self.pending.is_some() {
                return;
            }
            grace::continue_cleanup(self, context, peer);
        }
    }

    /// Drops the work behind a rejected batch; the edge retries it.
    pub fn batch_rejected(&mut self, context: &mut StateCoreContext) {
        self.remote_grant_rejected();
        match self.pending.take() {
            Some(PendingCommit::Cleanup { peer }) => grace::continue_cleanup(self, context, peer),
            Some(PendingCommit::Companion { .. }) => {
                if let Some(executor) = self.companion_exec.as_mut() {
                    executor.batch_rejected();
                }
            }
            _ => {}
        }
        self.drain_backlog(context);
    }

    /// Replays backlogged link traffic in arrival order until a replayed
    /// item stages the next batch.
    fn drain_backlog(&mut self, context: &mut StateCoreContext) {
        while self.pending.is_none() {
            let Some(message) = self.backlog.pop_front() else {
                break;
            };
            self.inbound(context, message);
        }
    }

    /// Sends committed events to their live links and tracks the
    /// unacknowledged window.
    fn deliver(&mut self, context: &mut StateCoreContext, events: Vec<OutboundEvent>) {
        for event in events {
            let Some(state) = self.peers.get_mut(&event.target) else {
                continue;
            };
            // A link that is not active yet replays the durable outbox when
            // it resumes; only live delivery tracks the window here.
            if !state.active || event.projection_generation != state.projection_generation {
                continue;
            }
            // Later events wait behind an open barrier; the durable outbox
            // replays them once both streams acknowledged (spec 20.8).
            if self
                .barriers
                .get(&event.target)
                .is_some_and(|barrier| event.delivery_sequence > barrier.base_last)
            {
                continue;
            }
            let bytes = u64::try_from(event.encoded.len()).unwrap_or(u64::MAX);
            state
                .outbox
                .unacked
                .push_back((event.delivery_sequence, event.event_id, bytes));
            state.outbox.unacked_bytes = state.outbox.unacked_bytes.saturating_add(bytes);
            let over_ceiling = u64::try_from(state.outbox.unacked.len()).unwrap_or(u64::MAX)
                > self.config.outbox_objects_per_edge
                || state.outbox.unacked_bytes > self.config.outbox_bytes_per_edge;
            if over_ceiling {
                state.outbox.snapshot_required = true;
            }
            if state.outbox.snapshot_required {
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
