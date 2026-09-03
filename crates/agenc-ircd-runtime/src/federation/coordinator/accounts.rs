//! Remote account carriers: an edge forwards the sealed account-service
//! envelopes of its pre-registration clients (spec 22.2), and the
//! coordinator serves each remote client through one virtual connection of
//! its own account service. The virtual connection speaks the exact carrier
//! grammar the client spoke on the edge, its frames land in a capturing sink
//! instead of a socket, and the request ends as the `auth_challenge`,
//! `authenticated`, or `account_created` result the profile permits, with
//! the sealed finish completion in the reply block.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use agenc_ircd_client_wire::WireMessage;
use agenc_ircd_domain::SessionSeed;
use agenc_ircd_federation_wire::SchemaObject;
use agenc_ircd_types::FederationOpcode;
use agenc_ircd_types::{ServerId, UserId};

use super::request::FreshRequest;
use super::{FederationCoordinator, Violation};
use crate::connection::{
    BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, ClientQueueSnapshot,
    ClientSink, ConnectionGeneration, FlushAcknowledgement, QueueAllocationError,
    QueueReservationLedger, SinkReserveError, TentativeClientQueueReservation,
};
use crate::federation::LinkId;
use crate::federation::codec::results::ResultArm;
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::inbox::CloseReason;

/// The first virtual connection generation; real generations count up from
/// one, so the top quarter of the space never collides with a socket.
const VIRTUAL_BASE: u64 = 1 << 62;

/// Remote carriers a coordinator serves at once.
const MAX_REMOTE_CARRIERS: usize = 4_096;

struct NoopLedger;

impl QueueReservationLedger for NoopLedger {
    fn rollback(&self, _frames: usize, _bytes: usize) {}
}

/// The sink of one virtual connection: it keeps every delivered line so the
/// carrier's sealed response and completion can be relayed as replies.
pub(crate) struct CaptureSink {
    generation: ConnectionGeneration,
    lines: Mutex<Vec<String>>,
}

impl CaptureSink {
    fn new(generation: ConnectionGeneration) -> Arc<Self> {
        Arc::new(Self {
            generation,
            lines: Mutex::new(Vec::new()),
        })
    }

    /// Takes every line delivered so far, in order, without the CRLF.
    pub(crate) fn take_lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|mut lines| std::mem::take(&mut *lines))
            .unwrap_or_default()
    }
}

impl ClientSink for CaptureSink {
    fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    fn try_reserve(
        &self,
        demand: ClientQueueDemand,
    ) -> Result<TentativeClientQueueReservation, SinkReserveError> {
        Ok(TentativeClientQueueReservation::new(
            self.generation,
            demand,
            0,
            Arc::new(NoopLedger) as Arc<dyn QueueReservationLedger>,
        ))
    }

    fn prepare(
        &self,
        tentative: TentativeClientQueueReservation,
        backing: Option<crate::budget::MemoryPermit>,
    ) -> Result<ClientQueueReservation, QueueAllocationError> {
        ClientQueueReservation::prepare(tentative, backing)
    }

    fn commit(&self, reservation: ClientQueueReservation, frames: BoundedSharedClientFrames) {
        if let Ok(mut lines) = self.lines.lock() {
            for frame in frames.into_frames() {
                let text = String::from_utf8_lossy(frame.as_bytes());
                lines.push(text.trim_end_matches("\r\n").to_owned());
            }
        }
        reservation.into_transfer().discard();
    }

    fn begin_slow_consumer_close(&self) {}

    fn close_after_flush(&self, _reason: CloseReason) -> FlushAcknowledgement {
        FlushAcknowledgement::complete()
    }

    fn queue_snapshot(&self) -> ClientQueueSnapshot {
        ClientQueueSnapshot::default()
    }
}

/// One remote client connection served through a virtual connection.
pub(crate) struct RemoteCarrier {
    /// The edge that hosts the client.
    pub peer: ServerId,
    /// The frames the account service delivered to the virtual connection.
    pub sink: Arc<CaptureSink>,
    /// Whether the virtual SASL transport already selected its mechanism.
    pub sasl_started: bool,
    /// The request in flight on this carrier, if any.
    pub in_flight: Option<InFlightCarrier>,
}

/// The federated request a virtual connection is answering.
pub(crate) struct InFlightCarrier {
    pub(super) link: LinkId,
    pub(super) fresh: FreshRequest,
    /// The request opcode, which fixes the permitted result kind.
    pub opcode: FederationOpcode,
    /// The carrier generation the account service reports back.
    pub carrier_generation: u64,
}

/// Work the router performs with the account service on the coordinator's
/// behalf after an inbound frame.
pub(crate) enum RemoteAccountWork {
    /// Feed one sealed envelope to the virtual connection of `origin`.
    Carrier {
        /// The virtual connection the router opens on first use.
        generation: ConnectionGeneration,
        /// The request opcode.
        opcode: FederationOpcode,
        /// The exact envelope bytes.
        envelope: Vec<u8>,
        /// The federated request; handed back when the carrier finishes.
        in_flight: Box<InFlightCarrier>,
    },
    /// Open a session whose account a pre-registration grant proves.
    SessionOpen {
        /// The edge that opens the session.
        peer: ServerId,
        /// The link the request arrived on.
        link: LinkId,
        /// The request.
        fresh: Box<FreshRequest>,
        /// The seed without its account.
        seed: Box<SessionSeed>,
        /// The grant the edge presented.
        grant_id: [u8; 32],
    },
}

/// The coordinator's remote-carrier bookkeeping.
#[derive(Default)]
pub(crate) struct RemoteAccounts {
    carriers: BTreeMap<ConnectionGeneration, RemoteCarrier>,
    by_origin: BTreeMap<(ServerId, [u8; 16]), ConnectionGeneration>,
    next_virtual: u64,
    queued: VecDeque<RemoteAccountWork>,
    pending_grant: Option<(ConnectionGeneration, UserId)>,
    committed_grant: Option<(ConnectionGeneration, UserId)>,
    rejected_grant: Option<ConnectionGeneration>,
    closed: Vec<ConnectionGeneration>,
}

impl RemoteAccounts {
    /// The virtual connection of one edge client, allocated on first use.
    fn carrier_for(
        &mut self,
        peer: ServerId,
        origin_id: [u8; 16],
    ) -> Result<(ConnectionGeneration, bool), Violation> {
        if let Some(generation) = self.by_origin.get(&(peer, origin_id)) {
            return Ok((*generation, false));
        }
        if self.carriers.len() >= MAX_REMOTE_CARRIERS {
            return Err(Violation::Ceiling);
        }
        let number = VIRTUAL_BASE
            .checked_add(self.next_virtual)
            .ok_or(Violation::Ceiling)?;
        self.next_virtual = self.next_virtual.saturating_add(1);
        let generation = ConnectionGeneration::new(number);
        self.carriers.insert(
            generation,
            RemoteCarrier {
                peer,
                sink: CaptureSink::new(generation),
                sasl_started: false,
                in_flight: None,
            },
        );
        self.by_origin.insert((peer, origin_id), generation);
        Ok((generation, true))
    }

    fn remove(&mut self, generation: ConnectionGeneration) -> Option<RemoteCarrier> {
        let carrier = self.carriers.remove(&generation)?;
        self.by_origin
            .retain(|_, candidate| *candidate != generation);
        Some(carrier)
    }
}

impl FederationCoordinator {
    /// Queues one remote carrier request for the router.
    pub(super) fn queue_remote_carrier(
        &mut self,
        link: LinkId,
        peer: ServerId,
        fresh: FreshRequest,
        opcode: FederationOpcode,
        envelope: Vec<u8>,
    ) -> Result<(), Violation> {
        let origin_id = *fresh.header.replay_key.origin_id.as_bytes();
        let (generation, _fresh) = self.remote_accounts.carrier_for(peer, origin_id)?;
        let busy = self
            .remote_accounts
            .carriers
            .get(&generation)
            .is_some_and(|carrier| carrier.in_flight.is_some());
        if busy {
            return Err(Violation::Ceiling);
        }
        let carrier_generation = fresh.header.replay_key.operation_sequence.saturating_add(1);
        self.remote_accounts
            .queued
            .push_back(RemoteAccountWork::Carrier {
                generation,
                opcode,
                envelope,
                in_flight: Box::new(InFlightCarrier {
                    link,
                    fresh,
                    opcode,
                    carrier_generation,
                }),
            });
        Ok(())
    }

    /// Queues one grant-backed session open for the router.
    pub(super) fn queue_remote_session_open(
        &mut self,
        link: LinkId,
        peer: ServerId,
        fresh: FreshRequest,
        seed: SessionSeed,
        grant_id: [u8; 32],
    ) {
        self.remote_accounts
            .queued
            .push_back(RemoteAccountWork::SessionOpen {
                peer,
                link,
                fresh: Box::new(fresh),
                seed: Box::new(seed),
                grant_id,
            });
    }

    /// Takes the queued remote account work.
    pub(crate) fn take_remote_account_work(&mut self) -> Vec<RemoteAccountWork> {
        self.remote_accounts.queued.drain(..).collect()
    }

    /// The capturing sink of one virtual connection, when it is one.
    #[must_use]
    pub(crate) fn remote_carrier_sink(
        &self,
        generation: ConnectionGeneration,
    ) -> Option<Arc<CaptureSink>> {
        self.remote_accounts
            .carriers
            .get(&generation)
            .map(|carrier| Arc::clone(&carrier.sink))
    }

    /// The edge behind one virtual connection.
    #[must_use]
    pub(crate) fn remote_carrier_peer(&self, generation: ConnectionGeneration) -> Option<ServerId> {
        self.remote_accounts
            .carriers
            .get(&generation)
            .map(|carrier| carrier.peer)
    }

    /// Whether the virtual SASL transport already selected its mechanism;
    /// the first call records that it now has.
    pub(crate) fn remote_sasl_started(&mut self, generation: ConnectionGeneration) -> bool {
        let Some(carrier) = self.remote_accounts.carriers.get_mut(&generation) else {
            return false;
        };
        std::mem::replace(&mut carrier.sasl_started, true)
    }

    /// Records the request a virtual connection is now answering.
    pub(crate) fn remote_carrier_started(
        &mut self,
        generation: ConnectionGeneration,
        in_flight: Box<InFlightCarrier>,
    ) {
        if let Some(carrier) = self.remote_accounts.carriers.get_mut(&generation) {
            carrier.in_flight = Some(*in_flight);
        }
    }

    /// Finishes the request a virtual connection was answering with the
    /// result the router built from the captured frames; returns the
    /// opcode and carrier generation it answered.
    pub(crate) fn finish_remote_carrier(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        arm: ResultArm,
        replies: Vec<WireMessage>,
    ) -> Option<(FederationOpcode, u64)> {
        let carrier = self.remote_accounts.carriers.get_mut(&generation)?;
        let peer = carrier.peer;
        let in_flight = carrier.in_flight.take()?;
        let link = in_flight.link;
        let answered = (in_flight.opcode, in_flight.carrier_generation);
        let mut objects = Vec::new();
        for reply in &replies {
            match crate::federation::codec::results::reply_object(reply) {
                Ok(object) => objects.push(object),
                Err(_) => {
                    self.fail_link(context, link, peer, Violation::Codec);
                    return None;
                }
            }
        }
        if !self.link_is_live(link, peer) {
            return None;
        }
        if let Err(violation) = super::request::finish_without_plan(
            self,
            context,
            link,
            peer,
            in_flight.fresh,
            arm,
            objects,
        ) {
            self.fail_link(context, link, peer, violation);
            return None;
        }
        super::request::drain_queued(self, context);
        Some(answered)
    }

    /// Fails the link of one virtual connection after a router-side
    /// violation.
    pub(crate) fn remote_carrier_violation(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
    ) {
        self.fail_link(context, link, peer, Violation::Ceiling);
    }

    /// The in-flight opcode of one virtual connection.
    #[must_use]
    pub(crate) fn remote_carrier_opcode(
        &self,
        generation: ConnectionGeneration,
    ) -> Option<FederationOpcode> {
        self.remote_accounts
            .carriers
            .get(&generation)
            .and_then(|carrier| carrier.in_flight.as_ref())
            .map(|in_flight| in_flight.opcode)
    }

    /// Stages a session whose account a remote grant proved; the grant row
    /// deletion joins the session transaction and the grant's consumption
    /// completes or rolls back with the batch.
    // agenc-review: allow owner=runtime reviewed=2026-09-03 reason=the remote session open carries its link peer request seed grant rows and virtual connection to one staging boundary
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_remote_session(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        fresh: Box<FreshRequest>,
        seed: SessionSeed,
        grant_writes: Vec<AccountServiceDurableWrite>,
        virtual_connection: ConnectionGeneration,
    ) -> Result<(), Violation> {
        if !self.link_is_live(link, peer) {
            return Err(Violation::Phase);
        }
        let user_id = seed.user_id;
        super::request::open_session_with_writes(
            self,
            context,
            link,
            peer,
            *fresh,
            seed,
            grant_writes,
        )?;
        self.remote_accounts.pending_grant = Some((virtual_connection, user_id));
        Ok(())
    }

    /// Fails a queued session open without staging anything.
    pub(crate) fn refuse_remote_session(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        fresh: Box<FreshRequest>,
    ) {
        if !self.link_is_live(link, peer) {
            return;
        }
        if let Err(violation) = super::request::finish_failed(
            self,
            context,
            link,
            peer,
            *fresh,
            agenc_ircd_domain::DomainError::BadState,
        ) {
            self.fail_link(context, link, peer, violation);
        }
    }

    /// The grant whose session open the last batch committed.
    pub(crate) fn take_committed_grant(&mut self) -> Option<(ConnectionGeneration, UserId)> {
        self.remote_accounts.committed_grant.take()
    }

    /// The grant whose session open the last batch rejected.
    pub(crate) fn take_rejected_grant(&mut self) -> Option<ConnectionGeneration> {
        self.remote_accounts.rejected_grant.take()
    }

    /// Virtual connections whose edge link ended or whose session opened.
    pub(crate) fn take_closed_remote_carriers(&mut self) -> Vec<ConnectionGeneration> {
        std::mem::take(&mut self.remote_accounts.closed)
    }

    /// Forgets one virtual connection after the router closed it.
    pub(crate) fn remote_carrier_closed(&mut self, generation: ConnectionGeneration) {
        let _removed = self.remote_accounts.remove(generation);
    }

    pub(super) fn remote_grant_committed(&mut self) {
        if let Some((generation, user_id)) = self.remote_accounts.pending_grant.take() {
            self.remote_accounts.committed_grant = Some((generation, user_id));
            self.remote_accounts.closed.push(generation);
        }
    }

    pub(super) fn remote_grant_rejected(&mut self) {
        if let Some((generation, _)) = self.remote_accounts.pending_grant.take() {
            self.remote_accounts.rejected_grant = Some(generation);
        }
    }

    /// Releases every virtual connection of a peer whose link ended.
    pub(super) fn remote_carriers_link_closed(&mut self, peer: ServerId) {
        let generations: Vec<ConnectionGeneration> = self
            .remote_accounts
            .carriers
            .iter()
            .filter(|(_, carrier)| carrier.peer == peer)
            .map(|(generation, _)| *generation)
            .collect();
        for generation in generations {
            self.remote_accounts.closed.push(generation);
        }
    }
}

/// Encodes a captured `AccountServiceResponse` for the `auth_challenge`
/// result: the concatenated chunk text decodes to the exact sealed bytes.
pub(crate) fn challenge_object(bytes: &[u8]) -> Option<SchemaObject> {
    let mut budget = agenc_ircd_federation_wire::DecodeBudget::new(8_192, 64);
    SchemaObject::decode_exact("AccountServiceResponse", bytes, &mut budget).ok()
}
