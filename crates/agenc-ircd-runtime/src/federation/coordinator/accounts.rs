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

#[cfg(test)]
#[path = "tests/carrier_budget.rs"]
mod budget_tests;

/// The first virtual connection generation; real generations count up from
/// one, so the top quarter of the space never collides with a socket.
const VIRTUAL_BASE: u64 = 1 << 62;

/// Remote carriers share the tracked-connection ceiling and memory admission.
const MAX_REMOTE_CARRIERS: usize = crate::state_core::session::MAX_TRACKED_CONNECTIONS;

/// A live grant consumed atomically with its remote session insertion.
pub(crate) struct RemoteSessionGrant {
    /// The exact durable grant-row deletion.
    pub writes: Vec<AccountServiceDurableWrite>,
    /// The same connection's original OPAQUE authentication instant.
    pub authenticated_at: agenc_ircd_types::MonotonicTick,
    /// The virtual connection whose grant barrier settles with the batch.
    pub owner: ConnectionGeneration,
}

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
    /// Covers the virtual connection, fixed carrier buffers and origin maps
    /// through registration until origin deletion, link closure or shutdown.
    _backing: crate::budget::MemoryPermit,
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

impl InFlightCarrier {
    pub(crate) fn registered_session(&self) -> Option<crate::state_core::session::BoundSession> {
        self.fresh.bound
    }
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
    /// Apply account settings with any account-service deletion barrier.
    AccountMutation {
        peer: ServerId,
        link: LinkId,
        fresh: Box<FreshRequest>,
        plan: Box<agenc_ircd_domain::MutationPlan>,
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
    pending_deletion: Option<ConnectionGeneration>,
    rejected_deletion: Option<ConnectionGeneration>,
    closed: Vec<ConnectionGeneration>,
}

impl RemoteAccounts {
    /// The virtual connection of one edge client, allocated on first use.
    fn carrier_for(
        &mut self,
        context: &StateCoreContext,
        peer: ServerId,
        origin_id: [u8; 16],
    ) -> Result<(ConnectionGeneration, bool), Violation> {
        if let Some(generation) = self.by_origin.get(&(peer, origin_id)) {
            return Ok((*generation, false));
        }
        if self.carriers.len() >= MAX_REMOTE_CARRIERS {
            return Err(Violation::Ceiling);
        }
        let capacity = usize::try_from(crate::budget::CLIENT_CONNECTION_BASE_BYTES)
            .map_err(|_| Violation::Ceiling)?;
        let backing = context
            .reserve_output_backing(capacity)
            .map_err(|_| Violation::Ceiling)?;
        let number = VIRTUAL_BASE
            .checked_add(self.next_virtual)
            .ok_or(Violation::Ceiling)?;
        self.next_virtual = self.next_virtual.saturating_add(1);
        let generation = ConnectionGeneration::new(number);
        self.carriers.insert(
            generation,
            RemoteCarrier {
                _backing: backing,
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

fn validate_remote_principal(
    context: &StateCoreContext,
    peer: ServerId,
    bound: crate::state_core::session::BoundSession,
    principal: agenc_ircd_domain::federation::OriginPrincipal,
    authentication: bool,
) -> Result<(), Violation> {
    let session = context
        .domain()
        .session(bound.user_id)
        .ok_or(Violation::Origin)?;
    let account = session
        .account_id()
        .map(|id| (id, session.account_session_generation()));
    if principal.session != Some((bound.session_id, bound.user_id))
        || session.session_id() != bound.session_id
        || session.negotiated_capability_hash() != &bound.capability_hash
        || session.home_server_id() != peer
        || principal.account != account
        || (!authentication && account.is_none())
    {
        return Err(Violation::Origin);
    }
    if let Some((id, generation)) = account
        && !context
            .domain()
            .account(id)
            .is_some_and(|account| account.session_generation() == generation)
    {
        return Err(Violation::Origin);
    }
    Ok(())
}

impl FederationCoordinator {
    /// Rechecks the declared principal against the live session before a
    /// sealed carrier can use its registered account authority.
    pub(super) fn bind_remote_account_request(
        &self,
        context: &StateCoreContext,
        peer: ServerId,
        fresh: &mut FreshRequest,
        opcode: FederationOpcode,
        bound: Option<crate::state_core::session::BoundSession>,
    ) -> Result<(), Violation> {
        let principal = self
            .origins
            .origin(&fresh.key.origin)
            .ok_or(Violation::Origin)?
            .principal;
        let authentication = matches!(
            opcode,
            FederationOpcode::OpaqueAuthStart | FederationOpcode::OpaqueAuthFinish
        );
        let bound = bound.or_else(|| {
            let (session_id, user_id) = authentication.then_some(principal.session).flatten()?;
            let session = context.domain().session(user_id)?;
            Some(crate::state_core::session::BoundSession {
                session_id,
                user_id,
                capability_hash: *session.negotiated_capability_hash(),
            })
        });
        let Some(bound) = bound else {
            if principal.session.is_some() || principal.account.is_some() {
                return Err(Violation::Origin);
            }
            return Ok(());
        };
        validate_remote_principal(context, peer, bound, principal, authentication)?;
        fresh.bound = Some(bound);
        Ok(())
    }

    /// Queues one remote carrier request for the router.
    pub(super) fn queue_remote_carrier(
        &mut self,
        context: &mut StateCoreContext,
        link: LinkId,
        peer: ServerId,
        fresh: FreshRequest,
        envelope: Vec<u8>,
    ) -> Result<(), Violation> {
        if let Some(bound) = fresh.bound {
            let principal = self
                .origins
                .origin(&fresh.key.origin)
                .ok_or(Violation::Origin)?
                .principal;
            if principal.session != Some((bound.session_id, bound.user_id)) {
                return Err(Violation::Origin);
            }
        }
        let opcode = fresh.header.opcode;
        let origin_id = *fresh.header.replay_key.origin_id.as_bytes();
        let (generation, _fresh) = match self.remote_accounts.carrier_for(context, peer, origin_id)
        {
            Ok(carrier) => carrier,
            Err(Violation::Ceiling) => {
                return super::request::finish_failed(
                    self,
                    context,
                    link,
                    peer,
                    fresh,
                    agenc_ircd_domain::DomainError::ServerBusy,
                );
            }
            Err(error) => return Err(error),
        };
        let busy = self
            .remote_accounts
            .carriers
            .get(&generation)
            .is_some_and(|carrier| carrier.in_flight.is_some());
        if busy {
            context
                .account_request_refused(crate::observe::events::AccountRefusalReason::CarrierBusy);
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

    /// Queues account mutations for the router that owns account authority.
    pub(super) fn queue_remote_account_mutation(
        &mut self,
        link: LinkId,
        peer: ServerId,
        fresh: FreshRequest,
        plan: agenc_ircd_domain::MutationPlan,
    ) {
        self.remote_accounts
            .queued
            .push_back(RemoteAccountWork::AccountMutation {
                peer,
                link,
                fresh: Box::new(fresh),
                plan: Box::new(plan),
            });
    }

    /// Joins credential removal and authority invalidation to account deletion.
    // agenc-review: allow owner=runtime reviewed=2026-09-07 reason=one remote account operation retains its link peer request domain plan and account-service owner through the atomic staging boundary
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_remote_account(
        &mut self,
        context: &mut StateCoreContext,
        accounts: &mut crate::account_service::AccountServiceCoordinator,
        link: LinkId,
        peer: ServerId,
        fresh: Box<FreshRequest>,
        plan: Box<agenc_ircd_domain::MutationPlan>,
    ) -> Result<(), Violation> {
        if !self.link_is_live(link, peer) {
            return Err(Violation::Phase);
        }
        let result = account_result(context, &fresh, &plan)?;
        let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
            .map_err(|_| Violation::Ceiling)?;
        let Ok(deletion) = self.begin_remote_deletion(context, accounts, peer, &fresh, &plan)
        else {
            return super::request::finish_failed(
                self,
                context,
                link,
                peer,
                *fresh,
                agenc_ircd_domain::DomainError::ServerBusy,
            );
        };
        let (owner, writes) = deletion.map_or_else(
            || (None, Vec::new()),
            |(owner, writes)| (Some(owner), writes),
        );
        let staged = super::request::stage_with_plan_and_writes(
            self, context, link, peer, *fresh, result, *plan, fanout, writes,
        );
        if let Some(owner) = owner {
            if matches!(staged, Ok(true)) {
                self.remote_accounts.pending_deletion = Some(owner);
            } else {
                let cancelled = accounts.cancel_account_deletion(context, owner);
                self.remote_accounts.closed.push(owner);
                cancelled.map_err(|_| Violation::Ceiling)?;
            }
        }
        staged.map(|_| ())
    }

    fn begin_remote_deletion(
        &mut self,
        context: &mut StateCoreContext,
        accounts: &mut crate::account_service::AccountServiceCoordinator,
        peer: ServerId,
        fresh: &FreshRequest,
        plan: &agenc_ircd_domain::MutationPlan,
    ) -> Result<Option<(ConnectionGeneration, Vec<AccountServiceDurableWrite>)>, Violation> {
        let account = plan.events().iter().find_map(|event| match event {
            agenc_ircd_domain::DomainEvent::AccountDeleted(account) => Some(*account),
            _ => None,
        });
        let Some(account) = account else {
            return Ok(None);
        };
        let (owner, _) = self.remote_accounts.carrier_for(
            context,
            peer,
            *fresh.header.replay_key.origin_id.as_bytes(),
        )?;
        match accounts.begin_account_deletion(context, owner, account) {
            Ok(writes) => Ok(Some((owner, writes))),
            Err(_) => {
                self.remote_accounts.closed.push(owner);
                Err(Violation::Ceiling)
            }
        }
    }

    /// The account deletion whose durable batch was rejected.
    pub(crate) fn take_rejected_deletion(&mut self) -> Option<ConnectionGeneration> {
        self.remote_accounts.rejected_deletion.take()
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
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        in_flight: Box<InFlightCarrier>,
    ) -> Result<(), Violation> {
        let fresh = &in_flight.fresh;
        let next = fresh
            .key
            .sequence
            .checked_add(1)
            .ok_or(Violation::Ceiling)?;
        let origin = super::origin::origin_row(
            self,
            fresh.key.origin,
            next,
            context.domain().revision().get(),
        )?;
        context.bind_remote_account_result(
            generation,
            fresh.header,
            fresh.request_object_id,
            origin,
        );
        if let Some(carrier) = self.remote_accounts.carriers.get_mut(&generation) {
            carrier.in_flight = Some(*in_flight);
        }
        Ok(())
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
        if in_flight.opcode == FederationOpcode::OpaqueAuthFinish {
            carrier.sasl_started = false;
        }
        let link = in_flight.link;
        let answered = (in_flight.opcode, in_flight.carrier_generation);
        if let Some(committed) = context.take_remote_account_result(generation) {
            let bytes = committed.bytes.clone();
            if self.record_remote_result(committed).is_err() {
                self.fail_link(context, link, peer, Violation::Origin);
                return None;
            }
            self.send_result(context, link, peer, in_flight.fresh.descriptor, &bytes);
            return Some(answered);
        }
        context.forget_remote_account_result(generation);
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
        grant: RemoteSessionGrant,
    ) -> Result<bool, Violation> {
        if !self.link_is_live(link, peer) {
            return Err(Violation::Phase);
        }
        let user_id = seed.user_id;
        let virtual_connection = grant.owner;
        let staged = super::request::open_session_with_writes(
            self,
            context,
            link,
            peer,
            *fresh,
            seed,
            Some(grant),
        )?;
        if staged {
            self.remote_accounts.pending_grant = Some((virtual_connection, user_id));
        }
        Ok(staged)
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

    /// Virtual connections whose authority ended through origin or link closure.
    pub(crate) fn take_closed_remote_carriers(&mut self) -> Vec<ConnectionGeneration> {
        std::mem::take(&mut self.remote_accounts.closed)
    }

    /// The existing virtual carrier behind a validated origin declaration.
    pub(super) fn remote_carrier_for_origin(
        &self,
        peer: ServerId,
        origin_id: [u8; 16],
    ) -> Option<ConnectionGeneration> {
        self.remote_accounts
            .by_origin
            .get(&(peer, origin_id))
            .copied()
    }

    /// Closes the exact carrier captured by a committed origin deletion.
    pub(super) fn retire_remote_carrier(&mut self, generation: ConnectionGeneration) {
        if self.remote_accounts.carriers.contains_key(&generation) {
            self.remote_accounts.closed.push(generation);
        }
    }

    /// Cancels internal carriers after the last admitted batch settles.
    pub(crate) fn shutdown_remote_carriers(&mut self) {
        self.remote_accounts
            .closed
            .extend(self.remote_accounts.carriers.keys().copied());
    }

    /// Forgets one virtual connection after the router closed it.
    pub(crate) fn remote_carrier_closed(&mut self, generation: ConnectionGeneration) {
        let _removed = self.remote_accounts.remove(generation);
    }

    pub(super) fn remote_grant_committed(&mut self) {
        if let Some(generation) = self.remote_accounts.pending_deletion.take() {
            self.remote_accounts.closed.push(generation);
        }
        if let Some((generation, user_id)) = self.remote_accounts.pending_grant.take() {
            self.remote_accounts.committed_grant = Some((generation, user_id));
        }
    }

    pub(super) fn remote_grant_rejected(&mut self) {
        if let Some(generation) = self.remote_accounts.pending_deletion.take() {
            self.remote_accounts.rejected_deletion = Some(generation);
            self.remote_accounts.closed.push(generation);
        }
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

/// Builds private account replies; the edge applies the client's capabilities.
fn account_result(
    context: &StateCoreContext,
    fresh: &FreshRequest,
    plan: &agenc_ircd_domain::MutationPlan,
) -> Result<(ResultArm, Vec<SchemaObject>), Violation> {
    let Some(agenc_ircd_domain::CanonicalCommandView::Account(command)) = fresh
        .command
        .as_ref()
        .map(agenc_ircd_domain::CanonicalCommand::view)
    else {
        return Err(Violation::Codec);
    };
    let frame = account_reply(context.server_prefix(), command, plan)?;
    let arm = if matches!(command, agenc_ircd_domain::AccountCommand::DeleteStart) {
        ResultArm::NoContent
    } else {
        ResultArm::Committed {
            resulting_state_generation: plan.resulting_revision().get(),
        }
    };
    let reply =
        crate::federation::codec::results::reply_object(&frame).map_err(|_| Violation::Codec)?;
    Ok((arm, vec![reply]))
}

fn account_reply(
    prefix: &str,
    command: &agenc_ircd_domain::AccountCommand,
    plan: &agenc_ircd_domain::MutationPlan,
) -> Result<WireMessage, Violation> {
    if plan.events().iter().any(|event| {
        matches!(
            event,
            agenc_ircd_domain::DomainEvent::AccountDeletionConfirmationRejected(_)
        )
    }) {
        return WireMessage::new(
            prefix,
            "FAIL",
            &["ACCT", "BAD_STATE"],
            Some("Command is not valid in this state"),
        )
        .map_err(|_| Violation::Codec);
    }
    if matches!(command, agenc_ircd_domain::AccountCommand::DeleteStart) {
        let token = plan.account_deletion_token().ok_or(Violation::Codec)?;
        let token = agenc_ircd_admin::encode_base64url(token);
        return WireMessage::new(
            prefix,
            "NOTE",
            &["ACCT", "DELETE_CHALLENGE", &token],
            Some("Confirm account deletion"),
        )
        .map_err(|_| Violation::Codec);
    }
    WireMessage::new(
        prefix,
        "NOTE",
        &["ACCT", "UPDATED"],
        Some("Account setting updated"),
    )
    .map_err(|_| Violation::Codec)
}

/// Encodes a captured `AccountServiceResponse` for the `auth_challenge`
/// result: the concatenated chunk text decodes to the exact sealed bytes.
pub(crate) fn challenge_object(bytes: &[u8]) -> Option<SchemaObject> {
    let mut budget = agenc_ircd_federation_wire::DecodeBudget::new(8_192, 64);
    SchemaObject::decode_exact("AccountServiceResponse", bytes, &mut budget).ok()
}

impl FederationCoordinator {
    pub(super) fn record_remote_result(
        &mut self,
        result: crate::state_core::remote_result::CommittedRemoteResult,
    ) -> Result<(), Violation> {
        let replay = result.header.replay_key;
        let key = agenc_ircd_domain::federation::OperationKey {
            origin: agenc_ircd_domain::federation::OriginKey {
                home_server_id: replay.home_server_id,
                server_incarnation: replay.server_incarnation,
                origin_id: replay.origin_id,
            },
            generation: replay.origin_generation,
            sequence: replay.operation_sequence,
        };
        self.origins
            .commit_request(key, result.header.request_id)
            .map_err(|_| Violation::Origin)?;
        self.retained.insert(
            key,
            super::RetainedRequest {
                request_id: result.header.request_id,
                request_object_id: *result.request_object_id.as_bytes(),
            },
        );
        self.counters.requests_committed = self.counters.requests_committed.saturating_add(1);
        Ok(())
    }
}
