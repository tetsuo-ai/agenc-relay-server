//! The edge role of the base federation profile (spec 20).
//!
//! An edge owns client connections and a read-only replica of the
//! coordinator's projection for this server. Every global mutation or query
//! becomes a durable `FederationRequest`; the coordinator's events drive the
//! replica and the client-visible lines. The registration router hosts one
//! instance and forwards the seams that differ from a coordinator: session
//! open and close, registered commands, and connection origins.

mod events;
mod render;
mod request;
mod sync;
#[cfg(test)]
#[path = "tests/harness.rs"]
mod tests;

use std::collections::{BTreeMap, VecDeque};

use agenc_ircd_domain::NicknameValue;
use agenc_ircd_domain::federation::{EdgeReplica, ProjectedEvent};
use agenc_ircd_federation_wire::{
    EventHeader, FederationFrame, FederationLineText, OriginDescriptor, federation_object_id,
    split_fragments,
};
use agenc_ircd_types::{
    ConnectionId, EventId, NetworkId, OriginId, RecoveryEpoch, RequestId, ServerId,
    ServerIncarnation, SessionId, UserId,
};

use crate::RuntimeError;
use crate::connection::ConnectionGeneration;
use crate::federation::link::LinkHandle;
use crate::federation::{
    FederationInbound, IngressCharge, LinkEvent, LinkId, LinkSession, ObjectCarrier, PeerIdentity,
};
use crate::state_core::StateCoreContext;

pub use request::EdgeCompletion;

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

/// One authenticated live link to the coordinator.
struct LiveLink {
    link: LinkId,
    handle: LinkHandle,
    coordinator_epoch: RecoveryEpoch,
}

/// Where the link is in the synchronization protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// No authenticated link.
    Down,
    /// Origins are being replayed; READY not yet sent.
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
    origin_id: OriginId,
    connection_id: ConnectionId,
    connection_nonce: [u8; 32],
    generation: u64,
    sequence: u64,
    object_id: [u8; 32],
    previous_object_id: [u8; 32],
    session: Option<(SessionId, UserId)>,
    acked_generation: Option<u64>,
    deleted: bool,
}

/// The durable batch the edge is waiting on.
enum PendingCommit {
    /// An event was applied; ACK follows the commit.
    Event {
        header: Box<EventHeader>,
        completion: Option<RequestId>,
    },
    /// The pending snapshot generation is durable; READY follows.
    SnapshotInstalled,
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
}

/// The edge's federation state machine.
pub struct EdgeFederation {
    config: EdgeConfig,
    live: Option<LiveLink>,
    phase: Phase,
    replica: EdgeReplica,
    cursor: Option<(u64, EventId)>,
    installed_epoch: Option<RecoveryEpoch>,
    origins: BTreeMap<ConnectionGeneration, ConnectionOrigin>,
    pending: BTreeMap<RequestId, request::PendingRequest>,
    by_completion: BTreeMap<EventId, RequestId>,
    applied_completions: std::collections::BTreeSet<EventId>,
    nicknames: BTreeMap<UserId, NicknameValue>,
    commit: Option<PendingCommit>,
    queued_events: VecDeque<(EventHeader, ProjectedEvent)>,
    snapshot: Option<sync::SnapshotInstall>,
    next_origin: u64,
    client_resync_epoch: u64,
    counters: EdgeCounters,
}

impl EdgeFederation {
    /// Creates an edge with no link and an empty replica at the first
    /// projection generation, matching a coordinator that never snapshotted.
    #[must_use]
    pub fn new(config: EdgeConfig) -> Self {
        let mut replica = EdgeReplica::new(config.server_id);
        let _installed = replica.install(1, Vec::new());
        Self {
            config,
            live: None,
            phase: Phase::Down,
            replica,
            cursor: None,
            installed_epoch: None,
            origins: BTreeMap::new(),
            pending: BTreeMap::new(),
            by_completion: BTreeMap::new(),
            applied_completions: std::collections::BTreeSet::new(),
            nicknames: BTreeMap::new(),
            commit: None,
            queued_events: VecDeque::new(),
            snapshot: None,
            next_origin: 1,
            client_resync_epoch: 0,
            counters: EdgeCounters::default(),
        }
    }

    /// Returns the STATS counters.
    #[must_use]
    pub const fn counters(&self) -> EdgeCounters {
        self.counters
    }

    /// Reports whether the coordinator link accepts global work.
    #[must_use]
    pub fn network_available(&self) -> bool {
        self.phase == Phase::Active && self.live.is_some()
    }

    /// Reports whether no federated operation straddles a reload.
    #[must_use]
    pub fn reload_ready(&self) -> bool {
        self.commit.is_none() && self.snapshot.is_none()
    }

    /// Borrows the replica.
    #[must_use]
    pub const fn replica(&self) -> &EdgeReplica {
        &self.replica
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
                self.settle(context, outcome)
            }
            LinkEvent::Object { carrier, object } if self.link_is(link) => {
                let outcome = self.handle_object(context, carrier, object, charge);
                self.settle(context, outcome)
            }
            LinkEvent::Frame(_) | LinkEvent::Object { .. } => Vec::new(),
        }
    }

    /// Turns a handler outcome into completions, failing the link on a
    /// violation.
    fn settle(
        &mut self,
        context: &mut StateCoreContext,
        outcome: Result<Vec<EdgeCompletion>, Violation>,
    ) -> Vec<EdgeCompletion> {
        match outcome {
            Ok(completions) => completions,
            Err(violation) => {
                self.fail_link(context, violation);
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
        self.live = Some(LiveLink {
            link: session.link,
            handle,
            coordinator_epoch: session.peer_recovery_epoch,
        });
        self.phase = Phase::Origins;
        sync::begin(self, context);
    }

    fn link_closed(&mut self, _context: &mut StateCoreContext, link: LinkId) {
        if !self.link_is(link) {
            return;
        }
        self.live = None;
        self.phase = Phase::Down;
        self.snapshot = None;
        self.queued_events.clear();
        for pending in self.pending.values_mut() {
            pending.sent = false;
        }
    }

    /// Closes the link after a violation; the supervisor reconnects.
    fn fail_link(&mut self, context: &mut StateCoreContext, _violation: Violation) {
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
            FederationFrame::OriginAck {
                edge_server_id,
                origin_id,
                generation,
                ..
            } => {
                self.require_self(edge_server_id)?;
                self.origin_acked(origin_id, generation);
                Ok(Vec::new())
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
        object: agenc_ircd_federation_wire::AssembledObject,
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

    fn origin_acked(&mut self, origin_id: OriginId, generation: u64) {
        for origin in self.origins.values_mut() {
            if origin.origin_id == origin_id && origin.generation == generation {
                origin.acked_generation = Some(generation);
            }
        }
    }

    /// Sends one rendered control frame over the live link.
    fn send_frame(&mut self, context: &mut StateCoreContext, frame: &FederationFrame) {
        let Some(live) = self.live.as_ref() else {
            return;
        };
        let sent = frame
            .render(&self.config.server_name)
            .map_err(|_| Violation::Codec)
            .and_then(|line| {
                live.handle
                    .try_send(line)
                    .map_err(|_| Violation::SlowConsumer)
            });
        if let Err(violation) = sent {
            self.fail_link(context, violation);
        }
    }

    /// Sends one object as fragments over the live link.
    fn send_object(
        &mut self,
        context: &mut StateCoreContext,
        encoded: &[u8],
        frame: impl Fn(agenc_ircd_federation_wire::FederationFragment) -> FederationFrame,
    ) -> bool {
        let Some(live) = self.live.as_ref() else {
            return false;
        };
        let object_id = federation_object_id(encoded);
        let sent = split_fragments(object_id, encoded)
            .map_err(|_| Violation::Codec)
            .and_then(|fragments| {
                let mut lines: Vec<FederationLineText> = Vec::new();
                lines
                    .try_reserve_exact(fragments.len())
                    .map_err(|_| Violation::Ceiling)?;
                for fragment in fragments {
                    lines.push(
                        frame(fragment)
                            .render(&self.config.server_name)
                            .map_err(|_| Violation::Codec)?,
                    );
                }
                for line in lines {
                    live.handle
                        .try_send(line)
                        .map_err(|_| Violation::SlowConsumer)?;
                }
                Ok(())
            });
        match sent {
            Ok(()) => true,
            Err(violation) => {
                self.fail_link(context, violation);
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
                origin_id: OriginId::from_bytes(origin_id),
                connection_id: ConnectionId::from_bytes(connection_id),
                connection_nonce: nonce,
                generation: 0,
                sequence: 0,
                object_id: [0; 32],
                previous_object_id: [0; 32],
                session: None,
                acked_generation: None,
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
        let session = self
            .origins
            .get(&generation)
            .and_then(|origin| origin.session);
        if let Some((session_id, _)) = session {
            request::send_session_close(self, context, generation, session_id, reason);
        }
        request::delete_origin(self, context, generation);
        let stale: Vec<RequestId> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.generation == generation)
            .map(|(request_id, _)| *request_id)
            .collect();
        for request_id in stale {
            if let Some(pending) = self.pending.remove(&request_id) {
                pending.sink_gone(self);
            }
        }
    }

    /// Requests a session for a connection that completed local
    /// registration; returns whether the request was accepted for sending.
    pub fn open_session(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        event_generation: u64,
        nickname: &str,
        realname: &str,
        capability_hash: [u8; 32],
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
            )
            .is_ok()
    }

    /// Sends one registered command; on failure the line comes back with
    /// the error the router renders.
    pub fn send_command(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: agenc_ircd_client_wire::ParsedMessage,
        command: &agenc_ircd_domain::CanonicalCommand,
    ) -> Result<
        (),
        (
            Box<agenc_ircd_client_wire::ParsedMessage>,
            agenc_ircd_domain::DomainError,
        ),
    > {
        request::send_command(self, context, generation, message, command)
    }

    /// The router bound the coordinator-assigned session: the origin moves
    /// to its next generation carrying the session binding.
    pub fn session_bound(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        let Some(origin) = self.origins.get_mut(&generation) else {
            return;
        };
        origin.previous_object_id = origin.object_id;
        origin.generation = origin.generation.saturating_add(1);
        origin.sequence = 0;
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
        message: &agenc_ircd_client_wire::ParsedMessage,
        cursor: [u8; 32],
    ) {
        request::continue_query(self, context, generation, message, cursor);
    }

    /// Finishes the batch that just committed.
    pub fn batch_applied(&mut self, context: &mut StateCoreContext) -> Vec<EdgeCompletion> {
        let mut completions = Vec::new();
        match self.commit.take() {
            Some(PendingCommit::Event { header, completion }) => {
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
                    completions.extend(request::completed(self, context, request_id));
                }
            }
            Some(PendingCommit::SnapshotInstalled) => sync::installed(self, context),
            None => {}
        }
        completions.extend(events::drain_queued(self, context));
        completions
    }

    /// Drops the work behind a rejected batch; the coordinator re-delivers.
    pub fn batch_rejected(&mut self, context: &mut StateCoreContext) {
        if let Some(PendingCommit::Event { .. }) = self.commit.take() {
            // The replica already applied the event; without the durable
            // row the only safe course is a fresh synchronization.
            self.fail_link(context, Violation::Ceiling);
        }
    }

    fn origin_descriptor(
        &self,
        generation: ConnectionGeneration,
    ) -> Option<(OriginDescriptor, &ConnectionOrigin)> {
        let origin = self.origins.get(&generation)?;
        Some((
            OriginDescriptor {
                coordinator_server_id: self.config.coordinator.server_id(),
                server_incarnation: self.config.incarnation,
                origin_id: origin.origin_id,
                generation: origin.generation,
                object_id: agenc_ircd_federation_wire::FederationHash32::from_bytes(
                    origin.object_id,
                ),
            },
            origin,
        ))
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
}

impl From<RuntimeError> for Violation {
    fn from(_: RuntimeError) -> Self {
        Self::Ceiling
    }
}
