//! Live client registration and the connection-to-domain session handoff.
//!
//! The wire crate owns the pure registration state machine. This module owns
//! only its external effects: temporary nickname leases, constant-time PASS
//! checks, fresh session identities, the ephemeral domain insertion, and
//! bounded rendering into the connection sink.

use std::collections::{BTreeMap, VecDeque};

use agenc_ircd_client_wire::{
    AccessTokenPolicy, AccountCarrierKind, CapRequestReply, CapabilityProfile, CapabilitySpec,
    CapabilityState, KEEPALIVE_IDLE_MILLIS, KEEPALIVE_PONG_MILLIS, PostRegistrationCommandKind,
    REGISTRATION_TIMEOUT_MILLIS, RegisteredCommandHandoff, RegisteredCommandKind,
    RegistrationAction, RegistrationAuthCarrier, RegistrationCommand, RegistrationError,
    RegistrationEvent, RegistrationPhase, RegistrationState, WelcomeStep, WireMessage,
    isupport_messages, numeric_reply, parse_registration_command, split_capability_lines,
};
use agenc_ircd_crypto::{SemanticHashDomain, semantic_digest};
use agenc_ircd_domain::{DisplayNameValue, DomainError, NicknameValue, SessionSeed};
use agenc_ircd_types::{
    Generation, NetworkId, PublicCloak, RecoveryEpoch, Revision, ServerId, SessionId, UserId,
};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::RuntimeError;
pub use crate::account_service::AccountServiceConfig;
use crate::account_service::{
    AccountCreationPolicy, AccountServiceCoordinator, CarrierCompletion, CarrierRoute,
};
use crate::admission::{BucketDemand, BucketKey, BucketKind};
use crate::connection::sink::ConnectionGeneration;
use crate::federation::coordinator::FederationCoordinator;
use crate::federation::edge::EdgeFederation;
use crate::observe::metrics::ResultClass;
use crate::purpose::ListenerPurpose;
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::inbox::CloseReason;
use crate::state_core::session::BoundSession;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use crate::state_core::{
    CommandObservation, CommandRouter, PeerQuarantineRefusal, RouteOutcome, StageAccepted,
    StagedOrigin, StateCoreContext,
};
use crate::sync::Arc;

const MAX_PENDING_ACTIONS: usize = 64;
const CAPABILITY_LINE_BYTES: usize = 512;
const CAPABILITY_FIXED_MARGIN: usize = 320;
const STS_CAPABILITY_VALUE: &str = "duration=31536000";

/// Fixed public and secret inputs for client registration.
pub struct RegistrationRouterConfig {
    /// Permanent network identity used by ISUPPORT and capability hashing.
    pub network_id: NetworkId,
    /// Local server identity installed in new domain sessions.
    pub server_id: ServerId,
    /// Public server prefix used on every frame.
    pub server_prefix: String,
    /// Public network label.
    pub display_name: String,
    /// Whether newly admitted unauthenticated registrations may complete.
    pub allow_guests: bool,
    /// Optional configured connection PASS token.
    pub access_token: Option<Zeroizing<[u8; 32]>>,
    /// The account service this node hosts or merely advertises.
    pub account_service: AccountServiceRole,
}

/// Whether this node hosts the account service (spec 22.2 keeps its keys on
/// the coordinator) or only advertises the network policy, as an edge does.
pub enum AccountServiceRole {
    /// The coordinator's account-service keys and route identity.
    Hosted(Box<AccountServiceConfig>),
    /// An edge: the policy to advertise; every carrier answers unavailable.
    Advertised {
        /// The account creation policy to advertise.
        creation_policy: AccountCreationPolicy,
        /// The recovery epoch to advertise.
        recovery_epoch: RecoveryEpoch,
    },
}

struct RegistrationRuntimeConfig {
    network_id: NetworkId,
    server_id: ServerId,
    server_prefix: String,
    display_name: Arc<str>,
    allow_guests: bool,
    access_token: Option<Zeroizing<[u8; 32]>>,
}

struct NicknameLease {
    generation: u64,
    nickname: NicknameValue,
}

struct RegistrationCommit<'a> {
    event_generation: u64,
    nickname: &'a str,
    realname: &'a str,
}

struct CarrierObservation<'a> {
    token: &'a mut Option<CommandObservation>,
    result: &'a mut ResultClass,
}

struct ConnectionState {
    registration: RegistrationState,
    advertised: Arc<CapabilityProfile>,
    lease: Option<NicknameLease>,
    bound: Option<BoundSession>,
    nickname: Option<String>,
    departure_reason: Option<String>,
    deadline: DeadlineState,
    allow_guests: bool,
    deferred_observations: VecDeque<CommandObservation>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DeadlineState {
    Registration,
    Idle,
    Pong,
    None,
}

struct PendingClosure {
    bound: BoundSession,
    reason: String,
}

struct PendingRegistration {
    event_generation: u64,
    bound: BoundSession,
    nickname: String,
    authenticated: bool,
}

/// Registration router for every public client connection.
pub struct RegistrationRouter {
    config: RegistrationRuntimeConfig,
    advertised: ClientCapabilityProfiles,
    accounts: Option<AccountServiceCoordinator>,
    commands: crate::channels::RegisteredCommandExecutor,
    connections: BTreeMap<ConnectionGeneration, ConnectionState>,
    leases: BTreeMap<NicknameValue, ConnectionGeneration>,
    pending_registrations: BTreeMap<ConnectionGeneration, PendingRegistration>,
    pending_closures: Vec<PendingClosure>,
    pending_observations: BTreeMap<(ConnectionGeneration, u64), CommandObservation>,
    federation: Option<FederationCoordinator>,
    edge: Option<EdgeFederation>,
    e2ee: Option<crate::e2ee::edge::E2eeEdge>,
    edge_carriers: BTreeMap<ConnectionGeneration, EdgeCarrier>,
}

/// The carrier transports of one pre-registration client on an edge; the
/// sealed envelopes they assemble cross the federation and the answers
/// come back through them (spec 22.2).
struct EdgeCarrier {
    sasl: agenc_ircd_client_wire::SaslTransport,
    creation: agenc_ircd_client_wire::AccountTransfer,
    grant: Option<(agenc_ircd_types::AccountId, u64, [u8; 32])>,
}

impl EdgeCarrier {
    fn new() -> Result<Self, RuntimeError> {
        Ok(Self {
            sasl: agenc_ircd_client_wire::SaslTransport::new()
                .map_err(|_| RuntimeError::MemoryExhausted)?,
            creation: agenc_ircd_client_wire::AccountTransfer::new(AccountCarrierKind::Create)
                .map_err(|_| RuntimeError::MemoryExhausted)?,
            grant: None,
        })
    }
}

struct ClientCapabilityProfiles {
    dns_tls: Arc<CapabilityProfile>,
    onion: Arc<CapabilityProfile>,
}

impl ClientCapabilityProfiles {
    fn new(
        creation_policy: AccountCreationPolicy,
        recovery_epoch: RecoveryEpoch,
    ) -> Result<Self, RuntimeError> {
        Ok(Self {
            dns_tls: Arc::new(core_capabilities(
                creation_policy,
                recovery_epoch,
                ListenerPurpose::ClientTls,
            )?),
            onion: Arc::new(core_capabilities(
                creation_policy,
                recovery_epoch,
                ListenerPurpose::ClientOnion,
            )?),
        })
    }

    /// The same profiles with the E2EE capability and its fixed value added
    /// (companion 11.1).
    fn with_e2ee(&self) -> Result<Self, RuntimeError> {
        let extend = |profile: &CapabilityProfile| -> Result<Arc<CapabilityProfile>, RuntimeError> {
            let mut capabilities = profile.capabilities().to_vec();
            capabilities.push(
                CapabilitySpec::new(
                    crate::e2ee::edge::E2EE_CAPABILITY,
                    Some(agenc_ircd_e2ee::limits::CAPABILITY_VALUE),
                )
                .map_err(|_| RuntimeError::InvalidValue)?,
            );
            CapabilityProfile::new(capabilities)
                .map(Arc::new)
                .map_err(|_| RuntimeError::InvalidValue)
        };
        Ok(Self {
            dns_tls: extend(&self.dns_tls)?,
            onion: extend(&self.onion)?,
        })
    }

    fn for_purpose(&self, purpose: ListenerPurpose) -> Option<Arc<CapabilityProfile>> {
        match purpose {
            ListenerPurpose::ClientTls => Some(Arc::clone(&self.dns_tls)),
            #[cfg(feature = "wss")]
            ListenerPurpose::ClientWss => Some(Arc::clone(&self.dns_tls)),
            ListenerPurpose::ClientOnion => Some(Arc::clone(&self.onion)),
            #[cfg(not(feature = "wss"))]
            ListenerPurpose::ClientWss => None,
            ListenerPurpose::Federation
            | ListenerPurpose::AdminLocal
            | ListenerPurpose::AdminTls => None,
        }
    }
}

impl RegistrationRouter {
    /// Builds the closed core-v1 capability advertisement.
    pub fn new(
        config: RegistrationRouterConfig,
        commands: crate::channels::RegisteredCommandExecutor,
    ) -> Result<Self, RuntimeError> {
        let RegistrationRouterConfig {
            network_id,
            server_id,
            server_prefix,
            display_name,
            allow_guests,
            access_token,
            account_service,
        } = config;
        let (creation_policy, recovery_epoch, hosted) = match account_service {
            AccountServiceRole::Hosted(config) => {
                if config.network_id != network_id || config.server_id != server_id {
                    return Err(RuntimeError::InvalidValue);
                }
                (config.creation_policy, config.recovery_epoch, Some(*config))
            }
            AccountServiceRole::Advertised {
                creation_policy,
                recovery_epoch,
            } => (creation_policy, recovery_epoch, None),
        };
        let advertised = ClientCapabilityProfiles::new(creation_policy, recovery_epoch)?;
        Ok(Self {
            config: RegistrationRuntimeConfig {
                network_id,
                server_id,
                server_prefix,
                display_name: Arc::from(display_name),
                allow_guests,
                access_token,
            },
            advertised,
            accounts: hosted.map(AccountServiceCoordinator::new).transpose()?,
            commands,
            connections: BTreeMap::new(),
            leases: BTreeMap::new(),
            pending_registrations: BTreeMap::new(),
            pending_closures: Vec::new(),
            pending_observations: BTreeMap::new(),
            federation: None,
            edge: None,
            e2ee: None,
            edge_carriers: BTreeMap::new(),
        })
    }

    /// Advertises the configured history profile; service admission remains
    /// owned by StateCore and the coordinator.
    #[cfg(feature = "history")]
    pub fn with_history(mut self) -> Result<Self, RuntimeError> {
        let extend = |profile: &CapabilityProfile| -> Result<Arc<CapabilityProfile>, RuntimeError> {
            let mut capabilities = profile.capabilities().to_vec();
            capabilities.push(
                CapabilitySpec::new("draft/chathistory", None)
                    .map_err(|_| RuntimeError::InvalidValue)?,
            );
            CapabilityProfile::new(capabilities)
                .map(Arc::new)
                .map_err(|_| RuntimeError::InvalidValue)
        };
        self.advertised = ClientCapabilityProfiles {
            dns_tls: extend(&self.advertised.dns_tls)?,
            onion: extend(&self.advertised.onion)?,
        };
        Ok(self)
    }

    /// Restores the edge before a link or client can consume projection authority.
    pub(crate) fn restore_edge(
        &mut self,
        port: &agenc_ircd_storage::StoragePort,
        keys: &crate::state_core::durable::KeyDeriver,
        head: crate::state_core::durable::HeadCounters,
    ) -> Result<(), crate::RuntimeError> {
        if let Some(edge) = self.edge.as_mut() {
            edge.restore(port, keys, self.e2ee.as_mut(), head)?;
        }
        Ok(())
    }

    /// Attaches the edge role: sessions, global commands, and queries go
    /// through the coordinator and this router renders the projection.
    #[must_use]
    pub fn with_edge(mut self, edge: EdgeFederation) -> Self {
        self.edge = Some(edge);
        self
    }

    /// Borrows the edge role when attached.
    #[must_use]
    pub fn edge(&self) -> Option<&EdgeFederation> {
        self.edge.as_ref()
    }

    /// Attaches the edge E2EE router beside the edge role and advertises the
    /// E2EE capability with its fixed value.
    pub fn with_e2ee_edge(
        mut self,
        e2ee: crate::e2ee::edge::E2eeEdge,
    ) -> Result<Self, RuntimeError> {
        self.advertised = self.advertised.with_e2ee()?;
        self.e2ee = Some(e2ee);
        Ok(self)
    }

    /// Borrows the edge E2EE router when attached.
    #[must_use]
    pub fn e2ee(&self) -> Option<&crate::e2ee::edge::E2eeEdge> {
        self.e2ee.as_ref()
    }

    /// Routes one E2EE client line through the edge E2EE router.
    fn route_e2ee_line(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &ConnectionState,
        message: &agenc_ircd_client_wire::ParsedMessage,
    ) -> ResultClass {
        let (Some(e2ee), Some(edge), Some(bound)) =
            (self.e2ee.as_mut(), self.edge.as_mut(), state.bound)
        else {
            return ResultClass::Rejected;
        };
        let account_id = edge
            .replica()
            .session(bound.user_id)
            .and_then(|record| record.account)
            .map(|(account, _)| account);
        let account = account_id.and_then(|account| account.to_text().as_bytes().try_into().ok());
        // Admission runs before parsing, crypto, and storage (companion
        // 16): one E2EE command per session, and one signature-verification
        // charge per account when the line carries object bytes.
        let mut demands = Vec::new();
        demands.push(BucketDemand::new(
            BucketKind::E2eeCommand,
            BucketKey::Session(bound.user_id),
            1,
        ));
        let carries_object = message
            .tags()
            .iter()
            .any(|tag| tag.key() == "+agenc.ag/e2ee");
        if let (true, Some(account_id)) = (carries_object, account_id) {
            demands.push(BucketDemand::new(
                BucketKind::E2eeSignature,
                BucketKey::Account(account_id),
                1,
            ));
        }
        let demands: Result<Vec<BucketDemand>, _> = demands.into_iter().collect();
        let now = context.now();
        let admitted = demands.is_ok_and(|demands| {
            context
                .buckets_mut()
                .charge_all_or_nothing(now, &demands)
                .is_ok()
        });
        if !admitted {
            for output in e2ee.rate_limited(generation, message) {
                let _sent = context.send_to(output.generation, output.frames);
            }
            return ResultClass::Rejected;
        }
        let nickname = state.nickname.as_deref().unwrap_or("*").to_owned();
        let facts = crate::e2ee::edge::SessionFacts {
            user_id: bound.user_id,
            account,
            capabilities: state.registration.capability_state(),
            nickname: &nickname,
        };
        let outputs = e2ee.client_line(context, edge, generation, message, &facts);
        let refused = !outputs.is_empty();
        for output in outputs {
            let _sent = context.send_to(output.generation, output.frames);
        }
        if refused {
            ResultClass::Rejected
        } else {
            ResultClass::Ok
        }
    }

    /// The `E2EE_REQUIRED` refusal for a plaintext line aimed at a bound
    /// target, when the edge E2EE router is attached.
    fn e2ee_downgrade_refusal(
        &self,
        state: &ConnectionState,
        message: &agenc_ircd_client_wire::ParsedMessage,
    ) -> Option<WireMessage> {
        let (Some(e2ee), Some(edge), Some(bound)) =
            (self.e2ee.as_ref(), self.edge.as_ref(), state.bound)
        else {
            return None;
        };
        let account = edge
            .replica()
            .session(bound.user_id)
            .and_then(|record| record.account)
            .and_then(|(account, _)| account.to_text().as_bytes().try_into().ok());
        e2ee.plaintext_refusal(edge, message, account)
    }

    /// Drains the companion frames the edge admitted and applies what the
    /// E2EE router produced.
    fn drive_e2ee(&mut self, context: &mut StateCoreContext) {
        let (Some(e2ee), Some(edge)) = (self.e2ee.as_mut(), self.edge.as_mut()) else {
            return;
        };
        if edge.companion_active() {
            e2ee.link_active(context, edge);
        } else if e2ee.phase() != crate::e2ee::edge::Phase::Down {
            e2ee.link_down();
        }
        let frames = edge.drain_companion();
        let mut outputs = e2ee.handle_frames(context, edge, frames);
        e2ee.apply_attachments(context, edge);
        e2ee.declare_origins(context, edge);
        apply_ready_barrier(context, e2ee, edge);
        outputs.extend(e2ee.barrier_outputs(context, edge));
        outputs.extend(e2ee.batch_applied_outputs());
        for output in outputs {
            let _sent = context.send_to(output.generation, output.frames);
        }
    }

    /// Attaches the coordinator role so federated edges are served through
    /// this router's safe points.
    #[must_use]
    pub fn with_federation(mut self, coordinator: FederationCoordinator) -> Self {
        self.federation = Some(coordinator);
        self
    }

    /// Borrows the coordinator role when attached.
    #[must_use]
    pub fn federation(&self) -> Option<&FederationCoordinator> {
        self.federation.as_ref()
    }

    fn access_policy(&self) -> AccessTokenPolicy {
        if self.config.access_token.is_some() {
            AccessTokenPolicy::RequireConfiguredToken
        } else {
            AccessTokenPolicy::IgnoreCompatibilityPass
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-01 reason=registration routing keeps parsing admission state-machine effects and final observation ownership in one ordered command boundary
    fn route_message(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: agenc_ircd_client_wire::ParsedMessage,
        observation: CommandObservation,
    ) -> RouteOutcome {
        let mut observation = Some(observation);
        let command = message.command().to_owned();
        let Some(mut state) = self.connections.remove(&generation) else {
            complete_observation(context, &mut observation, ResultClass::Error);
            return RouteOutcome::Close(CloseReason::ProtocolError);
        };
        let authority_fenced = state.bound.is_some()
            && !authority_fence_exempt(&message)
            && self
                .accounts
                .as_mut()
                .is_some_and(|accounts| accounts.registered_authority_fenced(context, generation));
        let admission = if state.bound.is_none() {
            charge_preauth(context, generation)
        } else if authority_fenced
            || should_charge_registered_control(&message, self.access_policy())
        {
            state
                .bound
                .ok_or(RuntimeError::InvalidValue)
                .and_then(|bound| charge_registered_control(context, bound.user_id))
        } else {
            Ok(())
        };
        if admission.is_err() || authority_fenced {
            let outcome = if command == "NOTICE"
                || self
                    .send_numeric(
                        context,
                        generation,
                        &state,
                        263,
                        &[&command],
                        "Please wait a while and try again.",
                    )
                    .is_ok()
            {
                RouteOutcome::Continue
            } else {
                RouteOutcome::Close(CloseReason::ProtocolError)
            };
            complete_observation(
                context,
                &mut observation,
                if matches!(outcome, RouteOutcome::Continue) {
                    ResultClass::Busy
                } else {
                    ResultClass::Error
                },
            );
            self.refresh_deadline(context, generation, &mut state, outcome);
            self.connections.insert(generation, state);
            return outcome;
        }
        if state.bound.is_some() && self.e2ee.is_some() && crate::e2ee::edge::is_e2ee_line(&message)
        {
            let class = self.route_e2ee_line(context, generation, &state, &message);
            complete_observation(context, &mut observation, class);
            let outcome = RouteOutcome::Continue;
            self.refresh_deadline(context, generation, &mut state, outcome);
            self.connections.insert(generation, state);
            return outcome;
        }
        let actions =
            state
                .registration
                .message(message, context.now().get(), state.advertised.as_ref());
        let outcome = match actions {
            Ok(actions) => {
                self.drive_actions(context, generation, &mut state, actions, &mut observation)
            }
            Err(error) => {
                let outcome =
                    self.render_registration_error(context, generation, &state, &command, error);
                complete_observation(
                    context,
                    &mut observation,
                    if matches!(outcome, RouteOutcome::Continue) {
                        ResultClass::Rejected
                    } else {
                        ResultClass::Error
                    },
                );
                outcome
            }
        };
        if matches!(outcome, RouteOutcome::Close(_)) {
            self.release_lease(generation, &mut state);
        }
        self.refresh_deadline(context, generation, &mut state, outcome);
        // StateCore keeps the connection entry until the transport reports
        // `Closed`. Keep the matching protocol state for that same event so
        // a registered session can be removed through the durable domain
        // path exactly once.
        self.connections.insert(generation, state);
        outcome
    }

    fn refresh_deadline(
        &self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        outcome: RouteOutcome,
    ) {
        if matches!(outcome, RouteOutcome::Close(_)) {
            cancel_connection_timers(context, generation);
            state.deadline = DeadlineState::None;
            return;
        }
        if state.registration.phase() != RegistrationPhase::Registered {
            return;
        }
        if state.registration.has_outstanding_ping() {
            if state.deadline != DeadlineState::Pong {
                schedule_connection_timer(
                    context,
                    generation,
                    TimerKind::Pong,
                    KEEPALIVE_PONG_MILLIS,
                );
                state.deadline = DeadlineState::Pong;
            }
            return;
        }
        if state.deadline == DeadlineState::Registration {
            context.timers_mut().cancel(
                TimerKind::RegistrationDeadline,
                TimedId::Connection(generation),
            );
        } else if state.deadline == DeadlineState::Pong {
            context
                .timers_mut()
                .cancel(TimerKind::Pong, TimedId::Connection(generation));
        }
        schedule_connection_timer(context, generation, TimerKind::Ping, KEEPALIVE_IDLE_MILLIS);
        state.deadline = DeadlineState::Idle;
    }

    fn timer_actions(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        entry: TimerEntry,
    ) {
        let Some(mut state) = self.connections.remove(&generation) else {
            return;
        };
        if !deadline_matches(state.deadline, entry.kind) {
            self.connections.insert(generation, state);
            return;
        }
        let ping = if entry.kind == TimerKind::Ping {
            self.ping_token(context).ok()
        } else {
            None
        };
        let actions = state
            .registration
            .tick(context.now().get(), ping.as_deref());
        let mut observation = None;
        let outcome = match actions {
            Ok(actions) => {
                self.drive_actions(context, generation, &mut state, actions, &mut observation)
            }
            Err(_) => RouteOutcome::Close(CloseReason::ProtocolError),
        };
        self.refresh_deadline(context, generation, &mut state, outcome);
        if matches!(outcome, RouteOutcome::Close(_)) {
            self.release_lease(generation, &mut state);
            close_transport(context, generation);
        }
        self.connections.insert(generation, state);
    }

    fn ping_token(&self, context: &mut StateCoreContext) -> Result<String, RuntimeError> {
        let mut random = [0_u8; 16];
        context
            .entropy_mut()
            .fill_exact(&mut random)
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(SessionId::from_bytes(random).to_base64url())
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=bounded action queue preserves external-result ordering and closes on any recursive expansion overflow
    fn drive_actions(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        actions: Vec<RegistrationAction>,
        observation: &mut Option<CommandObservation>,
    ) -> RouteOutcome {
        let mut result = ResultClass::Ok;
        let mut pending: VecDeque<RegistrationAction> = actions.into();
        while let Some(action) = pending.pop_front() {
            if pending.len() >= MAX_PENDING_ACTIONS {
                complete_observation(context, observation, ResultClass::Error);
                return RouteOutcome::Close(CloseReason::ProtocolError);
            }
            match self.apply_action(context, generation, state, action, observation, &mut result) {
                Ok(ActionStep::Continue) => {}
                Ok(ActionStep::FollowUp(actions)) => {
                    if pending.len().saturating_add(actions.len()) > MAX_PENDING_ACTIONS {
                        complete_observation(context, observation, ResultClass::Error);
                        return RouteOutcome::Close(CloseReason::ProtocolError);
                    }
                    pending.extend(actions);
                }
                Ok(ActionStep::Resume(messages)) => {
                    for message in messages {
                        let Some(deferred) = state.deferred_observations.pop_front() else {
                            complete_observation(context, observation, ResultClass::Error);
                            return RouteOutcome::Close(CloseReason::ProtocolError);
                        };
                        let mut deferred = Some(deferred);
                        let command = message.command().to_owned();
                        match state.registration.message(
                            message,
                            context.now().get(),
                            state.advertised.as_ref(),
                        ) {
                            Ok(actions) => {
                                let outcome = self.drive_actions(
                                    context,
                                    generation,
                                    state,
                                    actions,
                                    &mut deferred,
                                );
                                if matches!(outcome, RouteOutcome::Close(_)) {
                                    complete_observation(context, observation, ResultClass::Closed);
                                    return outcome;
                                }
                            }
                            Err(error) => {
                                let outcome = self.render_registration_error(
                                    context, generation, state, &command, error,
                                );
                                complete_observation(
                                    context,
                                    &mut deferred,
                                    if matches!(outcome, RouteOutcome::Continue) {
                                        ResultClass::Rejected
                                    } else {
                                        ResultClass::Error
                                    },
                                );
                                if matches!(outcome, RouteOutcome::Close(_)) {
                                    complete_observation(context, observation, ResultClass::Closed);
                                    return outcome;
                                }
                            }
                        }
                    }
                }
                Ok(ActionStep::Close(reason)) => {
                    complete_observation(context, observation, result);
                    return RouteOutcome::Close(reason);
                }
                Err(_) => {
                    complete_observation(context, observation, ResultClass::Error);
                    return RouteOutcome::Close(CloseReason::ProtocolError);
                }
            }
        }
        complete_observation(context, observation, result);
        RouteOutcome::Continue
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=closed registration action dispatcher mirrors the wire state machine
    fn apply_action(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        action: RegistrationAction,
        observation: &mut Option<CommandObservation>,
        result: &mut ResultClass,
    ) -> Result<ActionStep, RuntimeError> {
        match action {
            RegistrationAction::CapabilityLs(tokens) => {
                self.send_capabilities(context, generation, state, "LS", true, &tokens)?;
            }
            RegistrationAction::CapabilityRequest(reply) => match reply {
                CapRequestReply::Ack(tokens) => {
                    self.send_capabilities(context, generation, state, "ACK", false, &tokens)?;
                }
                CapRequestReply::Nak(tokens) => {
                    record_result(result, ResultClass::Rejected);
                    self.send_capabilities(context, generation, state, "NAK", false, &tokens)?;
                }
            },
            RegistrationAction::CapabilityList { tokens, multiline } => {
                self.send_capabilities(context, generation, state, "LIST", multiline, &tokens)?;
            }
            RegistrationAction::CapabilityNew(token) => {
                self.send_capabilities(context, generation, state, "NEW", false, &[token])?;
            }
            RegistrationAction::CapabilityDel(name) => {
                self.send_capabilities(context, generation, state, "DEL", false, &[name])?;
            }
            RegistrationAction::CapabilityReconnectRequired(_) => {
                record_result(result, ResultClass::Error);
                return Ok(ActionStep::Close(CloseReason::ProtocolError));
            }
            RegistrationAction::ReserveNickname {
                generation: lease_generation,
                nickname,
            } => {
                return self.reserve_nickname(
                    context,
                    generation,
                    state,
                    lease_generation,
                    &nickname,
                    result,
                );
            }
            RegistrationAction::CancelNicknameReservation {
                generation: lease_generation,
            }
            | RegistrationAction::ReleaseNickname {
                generation: lease_generation,
            } => {
                self.release_matching_lease(generation, state, lease_generation);
            }
            RegistrationAction::ReplaceNickname {
                generation: lease_generation,
                previous_generation,
                nickname,
            } => {
                self.release_matching_lease(generation, state, previous_generation);
                return self.reserve_nickname(
                    context,
                    generation,
                    state,
                    lease_generation,
                    &nickname,
                    result,
                );
            }
            RegistrationAction::CheckAccessToken {
                generation: token_generation,
                token,
            } => {
                let accepted =
                    self.config.access_token.as_ref().is_some_and(|configured| {
                        configured.as_slice().ct_eq(token.expose()).into()
                    });
                if !accepted {
                    record_result(result, ResultClass::Rejected);
                }
                return self.registration_event(
                    context,
                    generation,
                    state,
                    RegistrationEvent::AccessTokenChecked {
                        generation: token_generation,
                        accepted,
                    },
                );
            }
            RegistrationAction::CommitRegistration {
                generation: commit_generation,
                nickname,
                realname,
                ..
            } => {
                return self.commit_registration(
                    context,
                    generation,
                    state,
                    RegistrationCommit {
                        event_generation: commit_generation,
                        nickname: &nickname,
                        realname: &realname,
                    },
                    observation,
                    result,
                );
            }
            RegistrationAction::WelcomeBurst(steps) => {
                let frames = self.welcome_frames(context, state, &steps)?;
                context
                    .send_to(generation, frames)
                    .map_err(|_| RuntimeError::MemoryExhausted)?;
            }
            RegistrationAction::ForwardAuthCarrier {
                generation: carrier_generation,
                carrier,
                message,
            } => {
                if self.edge.is_some() && carrier != RegistrationAuthCarrier::AccountCredentials {
                    return self.route_edge_carrier(
                        context,
                        generation,
                        state,
                        carrier_generation,
                        carrier,
                        message,
                        CarrierObservation {
                            token: observation,
                            result,
                        },
                    );
                }
                if self.edge.is_some() || self.accounts.is_none() {
                    // Credential changes need the registered session's
                    // account authority, which stays with the coordinator; an
                    // edge answers them unavailable.
                    record_result(result, ResultClass::Rejected);
                    let command = message.command().to_owned();
                    self.send_one(
                        context,
                        generation,
                        WireMessage::new(
                            &self.config.server_prefix,
                            "FAIL",
                            &[&command, "UNAVAILABLE"],
                            Some("Account service is not available on this server"),
                        )
                        .map_err(|_| RuntimeError::InvalidValue)?,
                    )?;
                    let _ = carrier;
                    return self.registration_event(
                        context,
                        generation,
                        state,
                        RegistrationEvent::AuthCarrierFinished {
                            generation: carrier_generation,
                        },
                    );
                }
                let target = self.target(state).to_owned();
                let Some(accounts) = self.accounts.as_mut() else {
                    return Err(RuntimeError::InvalidValue);
                };
                let route = match carrier {
                    RegistrationAuthCarrier::Sasl => accounts.route_sasl(
                        context,
                        generation,
                        carrier_generation,
                        &target,
                        message,
                    ),
                    RegistrationAuthCarrier::AccountCreate => accounts.route_account(
                        context,
                        generation,
                        carrier_generation,
                        &target,
                        AccountCarrierKind::Create,
                        message,
                    ),
                    RegistrationAuthCarrier::AccountCredentials => accounts.route_account(
                        context,
                        generation,
                        carrier_generation,
                        &target,
                        AccountCarrierKind::Credentials,
                        message,
                    ),
                };
                return self.complete_carrier_route(
                    context,
                    generation,
                    state,
                    carrier_generation,
                    route,
                    CarrierObservation {
                        token: observation,
                        result,
                    },
                );
            }
            RegistrationAction::ForwardRegisteredCommand(handoff) => {
                let observation = observation.take().ok_or(RuntimeError::InvalidValue)?;
                if self.edge.is_some() {
                    return self.route_edge_command(
                        context,
                        generation,
                        state,
                        handoff,
                        observation,
                    );
                }
                let capabilities = state.registration.capability_state();
                return self
                    .commands
                    .route_registered(
                        context,
                        self.accounts.as_mut(),
                        generation,
                        state.bound,
                        capabilities,
                        &mut state.nickname,
                        handoff,
                        observation,
                    )
                    .map(ActionStep::from);
            }
            RegistrationAction::ResumeDeferredInput(queue) => {
                return Ok(ActionStep::Resume(queue.into_messages()));
            }
            RegistrationAction::InputDeferred => {
                state
                    .deferred_observations
                    .try_reserve(1)
                    .map_err(|_| RuntimeError::MemoryExhausted)?;
                let observation = observation.take().ok_or(RuntimeError::InvalidValue)?;
                state.deferred_observations.push_back(observation);
            }
            RegistrationAction::NotRegistered => {
                record_result(result, ResultClass::Rejected);
                self.send_numeric(
                    context,
                    generation,
                    state,
                    451,
                    &[],
                    "You have not registered",
                )?;
            }
            RegistrationAction::AlreadyRegistered => {
                record_result(result, ResultClass::Rejected);
                self.send_numeric(
                    context,
                    generation,
                    state,
                    462,
                    &[],
                    "You may not reregister",
                )?;
            }
            RegistrationAction::Pong(token) => {
                self.send_one(
                    context,
                    generation,
                    WireMessage::new(&self.config.server_prefix, "PONG", &[], Some(&token))
                        .map_err(|_| RuntimeError::InvalidValue)?,
                )?;
            }
            RegistrationAction::Ping(token) => {
                self.send_one(
                    context,
                    generation,
                    WireMessage::new(&self.config.server_prefix, "PING", &[], Some(&token))
                        .map_err(|_| RuntimeError::InvalidValue)?,
                )?;
            }
            RegistrationAction::Close(reason) => {
                state.departure_reason = Some(reason.clone());
                self.send_one(
                    context,
                    generation,
                    WireMessage::new(&self.config.server_prefix, "ERROR", &[], Some(&reason))
                        .map_err(|_| RuntimeError::InvalidValue)?,
                )?;
                return Ok(ActionStep::Close(CloseReason::ClientQuit));
            }
        }
        Ok(ActionStep::Continue)
    }

    /// Edge mode: the coordinator assigns the session; the registration
    /// completes when its result and completion event arrive.
    fn commit_edge_registration(
        &mut self,
        context: &mut StateCoreContext,
        connection: ConnectionGeneration,
        state: &mut ConnectionState,
        commit: RegistrationCommit<'_>,
        result: &mut ResultClass,
    ) -> Result<ActionStep, RuntimeError> {
        let RegistrationCommit {
            event_generation,
            nickname,
            realname,
        } = commit;
        let capability_hash = capability_hash(state.registration.enabled_capabilities())?;
        let auth_grant_id = self
            .edge_carriers
            .get(&connection)
            .and_then(|carrier| carrier.grant)
            .map(|(_, _, grant_id)| grant_id);
        let sent = self.edge.as_mut().is_some_and(|edge| {
            edge.open_session(
                context,
                connection,
                event_generation,
                nickname,
                realname,
                capability_hash,
                auth_grant_id,
            )
        });
        if sent {
            return Ok(ActionStep::Continue);
        }
        record_result(result, ResultClass::Busy);
        self.send_one(
            context,
            connection,
            WireMessage::new(
                &self.config.server_prefix,
                "FAIL",
                &["USER", "NETWORK_UNAVAILABLE"],
                Some("The network is unavailable"),
            )
            .map_err(|_| RuntimeError::InvalidValue)?,
        )?;
        self.registration_event(
            context,
            connection,
            state,
            RegistrationEvent::RegistrationCommitted {
                generation: event_generation,
                accepted: false,
                authenticated: false,
            },
        )
    }

    /// Edge mode: local information queries stay local; everything else is
    /// a federation request or fails closed while the link is unavailable.
    fn route_edge_command(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        handoff: RegisteredCommandHandoff,
        observation: CommandObservation,
    ) -> Result<ActionStep, RuntimeError> {
        if matches!(
            handoff.kind(),
            RegisteredCommandKind::Public(PostRegistrationCommandKind::LocalInformation(_))
        ) {
            let capabilities = state.registration.capability_state();
            return self
                .commands
                .route_registered(
                    context,
                    self.accounts.as_mut(),
                    generation,
                    state.bound,
                    capabilities,
                    &mut state.nickname,
                    handoff,
                    observation,
                )
                .map(ActionStep::from);
        }
        let (kind, message) = handoff.into_parts();
        if state.bound.is_none() {
            context.complete_command_observation(observation, ResultClass::Rejected);
            return Ok(ActionStep::Close(CloseReason::ProtocolError));
        }
        let command_name = message.command().to_owned();
        if let Some(frame) = self.e2ee_downgrade_refusal(state, &message) {
            context.complete_command_observation(observation, ResultClass::Rejected);
            self.send_one(context, generation, frame)?;
            return Ok(ActionStep::Continue);
        }
        let Some(edge) = self.edge.as_mut() else {
            return Err(RuntimeError::InvalidValue);
        };
        if !edge.network_available() {
            context.complete_command_observation(observation, ResultClass::Busy);
            self.send_one(
                context,
                generation,
                WireMessage::new(
                    &self.config.server_prefix,
                    "FAIL",
                    &[&command_name, "NETWORK_UNAVAILABLE"],
                    Some("The network is unavailable"),
                )
                .map_err(|_| RuntimeError::InvalidValue)?,
            )?;
            return Ok(ActionStep::Continue);
        }
        match edge.send_command(context, generation, kind, message) {
            Ok(()) => {
                context.complete_command_observation(observation, ResultClass::Ok);
            }
            Err((message, error)) => {
                context.complete_command_observation(observation, ResultClass::Rejected);
                self.render_edge_failure(context, generation, state, &message, error)?;
            }
        }
        Ok(ActionStep::Continue)
    }

    fn render_edge_failure(
        &self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &ConnectionState,
        message: &agenc_ircd_client_wire::ParsedMessage,
        error: DomainError,
    ) -> Result<(), RuntimeError> {
        let nickname = self.target(state).to_owned();
        let frame = crate::client_render::failure_frame(
            state.registration.capability_state(),
            &self.config.server_prefix,
            &nickname,
            message,
            error,
            None,
        )?;
        self.send_one(context, generation, frame)
    }

    /// Applies what the edge finished: registrations, failures, completions,
    /// query pages, and forced resynchronization.
    fn apply_edge_completions(
        &mut self,
        context: &mut StateCoreContext,
        completions: Vec<crate::federation::edge::EdgeCompletion>,
    ) {
        for completion in completions {
            self.apply_edge_completion(context, completion);
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match dispatches every edge completion kind to its handler with the exact fields the result carried
    fn apply_edge_completion(
        &mut self,
        context: &mut StateCoreContext,
        completion: crate::federation::edge::EdgeCompletion,
    ) {
        use crate::federation::edge::EdgeCompletion;
        match completion {
            EdgeCompletion::SessionRegistered {
                generation,
                session_id,
                user_id,
                event_generation,
                nickname,
            } => {
                let bound = BoundSession {
                    session_id,
                    user_id,
                    capability_hash: [0; 32],
                };
                self.finish_edge_registration(
                    context,
                    generation,
                    bound,
                    nickname,
                    event_generation,
                    true,
                );
            }
            EdgeCompletion::RegistrationRefused {
                generation,
                event_generation,
            } => {
                let bound = BoundSession {
                    session_id: SessionId::from_bytes([0; 16]),
                    user_id: UserId::from_bytes([0; 16]),
                    capability_hash: [0; 32],
                };
                self.finish_edge_registration(
                    context,
                    generation,
                    bound,
                    String::new(),
                    event_generation,
                    false,
                );
            }
            EdgeCompletion::CommandFailed {
                generation,
                message,
                error,
            } => {
                if let Some(state) = self.connections.get(&generation) {
                    let _rendered =
                        self.render_edge_failure(context, generation, state, &message, error);
                }
            }
            EdgeCompletion::CommandCompleted {
                generation,
                message,
            } => self.after_edge_completion(context, generation, &message),
            EdgeCompletion::Replies {
                generation,
                frames,
                next_cursor,
                message,
            } => self.deliver_edge_replies(context, generation, frames, next_cursor, &message),
            EdgeCompletion::Resync { generation } => self.resync_edge_client(context, generation),
            EdgeCompletion::AccountCarrier {
                generation,
                carrier_generation,
                sasl,
                finish,
                outcome,
            } => self.edge_carrier_answered(
                context,
                generation,
                carrier_generation,
                (sasl, finish),
                outcome,
            ),
        }
    }

    /// Drives one carrier line of a pre-registration client on an edge:
    /// the transport assembles the sealed envelope, which crosses the
    /// federation; every other action renders locally.
    // agenc-review: allow owner=runtime reviewed=2026-09-03 reason=the carrier route keeps the connection state transfer generation carrier class message and observation of one client line together
    #[allow(clippy::too_many_arguments)]
    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=each carrier class takes its parameters from the line in its own grammar before the shared completion path
    fn route_edge_carrier(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        carrier_generation: u64,
        carrier: RegistrationAuthCarrier,
        mut message: agenc_ircd_client_wire::ParsedMessage,
        observation: CarrierObservation<'_>,
    ) -> Result<ActionStep, RuntimeError> {
        let now = context.now().get();
        let target = self.target(state).to_owned();
        let prefix = self.config.server_prefix.clone();
        if let std::collections::btree_map::Entry::Vacant(slot) =
            self.edge_carriers.entry(generation)
        {
            slot.insert(EdgeCarrier::new()?);
        }
        let route = match carrier {
            RegistrationAuthCarrier::Sasl => {
                let parameter = (message.parameter_count() == 1)
                    .then(|| message.take_parameter(0))
                    .flatten();
                match parameter {
                    Some(parameter) => self.edge_sasl_line(
                        context,
                        generation,
                        carrier_generation,
                        (&prefix, &target),
                        &parameter,
                        now,
                    ),
                    None => CarrierRoute::Close,
                }
            }
            RegistrationAuthCarrier::AccountCreate => {
                let has_tags = !message.tags().is_empty();
                match message.take_parameter(0) {
                    Some(subcommand) => {
                        let parameter = message.take_parameter(1);
                        self.edge_account_line(
                            context,
                            generation,
                            carrier_generation,
                            &prefix,
                            (&subcommand, parameter.as_deref(), has_tags),
                            now,
                        )
                    }
                    None => CarrierRoute::Close,
                }
            }
            RegistrationAuthCarrier::AccountCredentials => CarrierRoute::Close,
        };
        self.complete_carrier_route(
            context,
            generation,
            state,
            carrier_generation,
            route,
            observation,
        )
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=the SASL line loop forwards the assembled envelope and renders every other transport action in the order the transport produced them
    fn edge_sasl_line(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        names: (&str, &str),
        parameter: &str,
        now: u64,
    ) -> CarrierRoute {
        use agenc_ircd_client_wire::SaslAction;
        let (prefix, target) = names;
        let Some(carrier) = self.edge_carriers.get_mut(&generation) else {
            return CarrierRoute::Close;
        };
        let Ok(actions) = carrier.sasl.client(parameter, now) else {
            return CarrierRoute::Close;
        };
        let mut rendered = Vec::new();
        let mut result = ResultClass::Ok;
        for action in actions {
            match action {
                SaslAction::RequestEnvelope { finish, bytes } => {
                    let opcode = if finish {
                        agenc_ircd_types::FederationOpcode::OpaqueAuthFinish
                    } else {
                        agenc_ircd_types::FederationOpcode::OpaqueAuthStart
                    };
                    let sent = self.edge.as_mut().is_some_and(|edge| {
                        edge.send_account_carrier(
                            context,
                            generation,
                            opcode,
                            bytes.expose(),
                            finish,
                            carrier_generation,
                        )
                    });
                    if sent {
                        return CarrierRoute::Pending;
                    }
                    let Ok(actions) = carrier.sasl.unavailable(now) else {
                        return CarrierRoute::Close;
                    };
                    return match crate::account_service::render_sasl_actions(
                        prefix, target, actions,
                    ) {
                        Ok(frames) => CarrierRoute::Finished {
                            frames,
                            result: ResultClass::Rejected,
                        },
                        Err(_) => CarrierRoute::Close,
                    };
                }
                SaslAction::Logout => {
                    let Ok(actions) = carrier.sasl.reject_logout() else {
                        return CarrierRoute::Close;
                    };
                    rendered.extend(actions);
                    result = ResultClass::Rejected;
                }
                action => {
                    if crate::account_service::sasl_action_result(&action) == ResultClass::Rejected
                    {
                        result = ResultClass::Rejected;
                    }
                    rendered.push(action);
                }
            }
        }
        match crate::account_service::render_sasl_actions(prefix, target, rendered) {
            Ok(frames) => CarrierRoute::Finished { frames, result },
            Err(_) => CarrierRoute::Close,
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=the account carrier loop forwards the assembled envelope and renders every other transport action in the order the transport produced them
    fn edge_account_line(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        prefix: &str,
        line: (&str, Option<&str>, bool),
        now: u64,
    ) -> CarrierRoute {
        use agenc_ircd_client_wire::{AccountCarrierAction, AccountCarrierPhase};
        let (subcommand, parameter, has_tags) = line;
        let Some(carrier) = self.edge_carriers.get_mut(&generation) else {
            return CarrierRoute::Close;
        };
        let Ok(actions) = carrier
            .creation
            .client(subcommand, parameter, has_tags, now)
        else {
            return account_unavailable(prefix);
        };
        let mut rendered = Vec::new();
        for action in actions {
            match action {
                AccountCarrierAction::RequestEnvelope { phase, bytes } => {
                    let finish = phase == AccountCarrierPhase::Finish;
                    let opcode = if finish {
                        agenc_ircd_types::FederationOpcode::AccountCreateFinish
                    } else {
                        agenc_ircd_types::FederationOpcode::AccountCreateStart
                    };
                    let sent = self.edge.as_mut().is_some_and(|edge| {
                        edge.send_account_carrier(
                            context,
                            generation,
                            opcode,
                            bytes.expose(),
                            finish,
                            carrier_generation,
                        )
                    });
                    if sent {
                        return CarrierRoute::Pending;
                    }
                    carrier.creation.reject();
                    return account_unavailable(prefix);
                }
                action => rendered.push(action),
            }
        }
        match crate::account_service::render_account_actions(
            prefix,
            AccountCarrierKind::Create,
            rendered,
        ) {
            Ok(frames) => CarrierRoute::Finished {
                frames,
                result: ResultClass::Ok,
            },
            Err(_) => CarrierRoute::Close,
        }
    }

    /// The coordinator answered one forwarded carrier envelope: the edge
    /// transport renders the sealed response and outcome for the client,
    /// and a successful SASL finish keeps its grant for session open.
    fn edge_carrier_answered(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        phase: (bool, bool),
        outcome: crate::federation::edge::RemoteCarrierOutcome,
    ) {
        let (sasl, finish) = phase;
        let now = context.now().get();
        let prefix = self.config.server_prefix.clone();
        let target = self
            .connections
            .get(&generation)
            .map_or_else(|| "*".to_owned(), |state| self.target(state).to_owned());
        let Some(carrier) = self.edge_carriers.get_mut(&generation) else {
            return;
        };
        let answered = if sasl {
            edge_sasl_answer(carrier, (&prefix, &target), finish, outcome, now)
        } else {
            edge_account_answer(carrier, &prefix, finish, outcome, now)
        };
        let completion = match answered {
            Some((frames, result)) => {
                let _sent = context.send_to(generation, frames);
                CarrierCompletion {
                    generation,
                    carrier_generation,
                    close: false,
                    result,
                }
            }
            None => CarrierCompletion {
                generation,
                carrier_generation,
                close: true,
                result: ResultClass::Error,
            },
        };
        self.apply_account_completions(context, vec![completion]);
    }

    fn deliver_edge_replies(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
        next_cursor: Option<[u8; 32]>,
        message: &agenc_ircd_client_wire::ParsedMessage,
    ) {
        let _sent = context.send_to(generation, frames);
        if let (Some(cursor), Some(edge)) = (next_cursor, self.edge.as_mut()) {
            edge.continue_query(context, generation, message, cursor);
        }
    }

    fn resync_edge_client(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        if let Ok(frame) = WireMessage::new(
            &self.config.server_prefix,
            "ERROR",
            &[],
            Some("Network state resynchronization required; reconnect"),
        ) {
            let _sent = self.send_one(context, generation, frame);
        }
        close_transport(context, generation);
    }

    /// Binds a coordinator-assigned session and runs the welcome burst, or
    /// reports the refusal through the registration state machine.
    fn finish_edge_registration(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        mut bound: BoundSession,
        nickname: String,
        event_generation: u64,
        accepted: bool,
    ) {
        let Some(mut state) = self.connections.remove(&generation) else {
            return;
        };
        if accepted {
            let capabilities = state.registration.capability_state().try_clone().ok();
            bound.capability_hash =
                capability_hash(state.registration.enabled_capabilities()).unwrap_or([0; 32]);
            let bound_ok = capabilities.is_some_and(|capabilities| {
                context
                    .sessions_mut()
                    .bind_session(generation, bound, capabilities)
                    .is_ok()
            });
            if !bound_ok {
                close_transport(context, generation);
                self.connections.insert(generation, state);
                return;
            }
            state.bound = Some(bound);
            state.nickname = Some(nickname);
            self.release_lease(generation, &mut state);
            if let Some(edge) = self.edge.as_mut() {
                edge.session_bound(context, generation);
            }
        }
        let outcome = match state.registration.event(
            RegistrationEvent::RegistrationCommitted {
                generation: event_generation,
                accepted,
                authenticated: accepted
                    && self
                        .edge_carriers
                        .get(&generation)
                        .is_some_and(|carrier| carrier.grant.is_some()),
            },
            context.now().get(),
        ) {
            Ok(actions) => {
                let mut observation = None;
                self.drive_actions(context, generation, &mut state, actions, &mut observation)
            }
            Err(_) => RouteOutcome::Close(CloseReason::ProtocolError),
        };
        self.refresh_deadline(context, generation, &mut state, outcome);
        if matches!(outcome, RouteOutcome::Close(_)) {
            close_transport(context, generation);
        }
        self.connections.insert(generation, state);
    }

    /// After a committed request: a JOIN gets its NAMES pages and topic.
    fn after_edge_completion(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: &agenc_ircd_client_wire::ParsedMessage,
    ) {
        match message.command() {
            "JOIN" => {
                let Some(edge) = self.edge.as_mut() else {
                    return;
                };
                let Some(channels) = message.middle().first() else {
                    return;
                };
                for name in channels.split(',') {
                    edge.request_names(context, generation, name);
                }
            }
            "CHANCTL" => self.note_channel_setting_updated(context, generation, message),
            _ => {}
        }
    }

    /// The `NOTE CHANCTL UPDATED` a committed channel setting earns on its
    /// requesting connection; the coordinator renders it only for local
    /// origins.
    fn note_channel_setting_updated(
        &self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: &agenc_ircd_client_wire::ParsedMessage,
    ) {
        let Some(state) = self.connections.get(&generation) else {
            return;
        };
        let capabilities = state.registration.capability_state();
        if !capabilities.enabled("standard-replies") {
            return;
        }
        let Some(name) = message
            .middle()
            .get(1)
            .and_then(|channel| agenc_ircd_types::ChannelName::parse(channel).ok())
        else {
            return;
        };
        let Ok(description) =
            agenc_ircd_client_wire::SafeReplyDescription::new("Channel setting updated")
        else {
            return;
        };
        let Ok(frame) = agenc_ircd_client_wire::standard_reply(
            capabilities,
            &self.config.server_prefix,
            agenc_ircd_client_wire::ReplyKind::Note,
            "CHANCTL",
            agenc_ircd_types::PublicErrorCode::UPDATED,
            &[agenc_ircd_client_wire::SafeReplyContext::Channel(&name)],
            description,
        ) else {
            return;
        };
        let _sent = self.send_one(context, generation, frame);
    }

    fn reserve_nickname(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        lease_generation: u64,
        nickname: &str,
        result: &mut ResultClass,
    ) -> Result<ActionStep, RuntimeError> {
        let nickname = NicknameValue::parse(nickname).map_err(|_| RuntimeError::InvalidValue)?;
        let domain_taken = context.domain().resolve_nickname(&nickname).is_some()
            || context.domain().nickname_reserved_by(&nickname).is_some();
        let lease_taken = self
            .leases
            .get(&nickname)
            .is_some_and(|owner| *owner != generation);
        let accepted = !domain_taken && !lease_taken;
        if !accepted {
            record_result(result, ResultClass::Rejected);
        }
        if accepted {
            self.release_lease(generation, state);
            self.leases.insert(nickname.clone(), generation);
            state.lease = Some(NicknameLease {
                generation: lease_generation,
                nickname,
            });
        }
        self.registration_event(
            context,
            generation,
            state,
            RegistrationEvent::NicknameReserved {
                generation: lease_generation,
                accepted,
            },
        )
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=registration commit binds one captured guest policy session seed capability set and welcome handoff at the existing atomic boundary
    fn commit_registration(
        &mut self,
        context: &mut StateCoreContext,
        connection: ConnectionGeneration,
        state: &mut ConnectionState,
        commit: RegistrationCommit<'_>,
        observation: &mut Option<CommandObservation>,
        result: &mut ResultClass,
    ) -> Result<ActionStep, RuntimeError> {
        let RegistrationCommit {
            event_generation,
            nickname,
            realname,
        } = commit;
        if self.edge.is_some() {
            return self.commit_edge_registration(
                context,
                connection,
                state,
                RegistrationCommit {
                    event_generation,
                    nickname,
                    realname,
                },
                result,
            );
        }
        let authenticated_account = match self.accounts.as_mut() {
            Some(accounts) => accounts.authenticated_binding(connection, context.now())?,
            None => None,
        };
        if authenticated_account.is_none() && !state.allow_guests {
            record_result(result, ResultClass::Rejected);
            return self.registration_event(
                context,
                connection,
                state,
                RegistrationEvent::RegistrationCommitted {
                    generation: event_generation,
                    accepted: false,
                    authenticated: false,
                },
            );
        }
        let seed = self.session_seed(context, state, nickname, realname, authenticated_account)?;
        let bound = BoundSession {
            session_id: seed.session_id,
            user_id: seed.user_id,
            capability_hash: seed.negotiated_capability_hash,
        };
        let capabilities = state
            .registration
            .capability_state()
            .try_clone()
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        if authenticated_account.is_some() {
            if self.stage_authenticated_session(
                context,
                connection,
                event_generation,
                bound,
                capabilities,
                seed,
                nickname,
                observation,
            )? {
                return Ok(ActionStep::Continue);
            }
            record_result(result, ResultClass::Rejected);
            return self.registration_event(
                context,
                connection,
                state,
                RegistrationEvent::RegistrationCommitted {
                    generation: event_generation,
                    accepted: false,
                    authenticated: true,
                },
            );
        }
        if self.commit_session(
            context,
            connection,
            event_generation,
            bound,
            capabilities,
            seed,
            nickname,
            observation,
        )? {
            return Ok(ActionStep::Continue);
        }
        record_result(result, ResultClass::Rejected);
        self.registration_event(
            context,
            connection,
            state,
            RegistrationEvent::RegistrationCommitted {
                generation: event_generation,
                accepted: false,
                authenticated: false,
            },
        )
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-30 reason=authenticated registration requires the complete session seed capability binding and durable grant handoff at one atomic staging boundary
    #[allow(clippy::too_many_arguments)]
    fn stage_authenticated_session(
        &mut self,
        context: &mut StateCoreContext,
        connection: ConnectionGeneration,
        event_generation: u64,
        bound: BoundSession,
        capabilities: CapabilityState,
        seed: SessionSeed,
        nickname: &str,
        observation: &mut Option<CommandObservation>,
    ) -> Result<bool, RuntimeError> {
        if self.pending_registrations.contains_key(&connection) {
            return Err(RuntimeError::InvalidValue);
        }
        let Ok(plan) = context.domain().plan_session_opened(seed) else {
            return Ok(false);
        };
        let grant_writes = match self.accounts.as_mut() {
            Some(accounts) => vec![accounts.registration_grant_write(connection, context.now())?],
            None => Vec::new(),
        };
        let mut owned_nickname = String::new();
        owned_nickname
            .try_reserve_exact(nickname.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        owned_nickname.push_str(nickname);
        let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
        context
            .sessions_mut()
            .bind_session(connection, bound, capabilities)?;
        self.pending_registrations.insert(
            connection,
            PendingRegistration {
                event_generation,
                bound,
                nickname: owned_nickname,
                authenticated: true,
            },
        );
        if self.accounts.as_mut().is_some_and(|accounts| {
            accounts
                .begin_registration_grant_consumption(context, connection)
                .is_err()
        }) {
            self.pending_registrations.remove(&connection);
            context.sessions_mut().unbind_session(connection, bound)?;
            return Err(RuntimeError::InvalidValue);
        }
        let staged = context.stage_durable_with_account_service(
            plan,
            fanout,
            Some(StagedOrigin::silent(connection).with_observation(observation.take())),
            0,
            grant_writes,
        );
        if matches!(staged, Ok(StageAccepted::Staged { .. })) {
            return Ok(true);
        }
        let cancelled = self.accounts.as_mut().map_or(Ok(()), |accounts| {
            accounts.cancel_registration_grant_consumption(context, connection)
        });
        self.pending_registrations.remove(&connection);
        context.sessions_mut().unbind_session(connection, bound)?;
        cancelled?;
        Ok(false)
    }

    // agenc-review: allow owner=runtime reviewed=2026-09-01 reason=guest registration binds its complete session projection and command observation to one durable staging boundary
    #[allow(clippy::too_many_arguments)]
    fn commit_session(
        &mut self,
        context: &mut StateCoreContext,
        connection: ConnectionGeneration,
        event_generation: u64,
        bound: BoundSession,
        capabilities: CapabilityState,
        seed: SessionSeed,
        nickname: &str,
        observation: &mut Option<CommandObservation>,
    ) -> Result<bool, RuntimeError> {
        if self.pending_registrations.contains_key(&connection) {
            return Err(RuntimeError::InvalidValue);
        }
        let Ok(plan) = context.domain().plan_session_opened(seed) else {
            return Ok(false);
        };
        let mut owned_nickname = String::new();
        owned_nickname
            .try_reserve_exact(nickname.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        owned_nickname.push_str(nickname);
        let request = FanoutRequest::new(Vec::new(), Vec::new())?;
        context
            .sessions_mut()
            .bind_session(connection, bound, capabilities)?;
        self.pending_registrations.insert(
            connection,
            PendingRegistration {
                event_generation,
                bound,
                nickname: owned_nickname,
                authenticated: false,
            },
        );
        let staged = context.stage_durable(
            plan,
            request,
            Some(StagedOrigin::silent(connection).with_observation(observation.take())),
            0,
        );
        if matches!(staged, Ok(StageAccepted::Staged { .. })) {
            return Ok(true);
        }
        self.pending_registrations.remove(&connection);
        context.sessions_mut().unbind_session(connection, bound)?;
        Ok(false)
    }

    fn session_seed(
        &self,
        context: &mut StateCoreContext,
        state: &ConnectionState,
        nickname: &str,
        realname: &str,
        authenticated_account: Option<(agenc_ircd_types::AccountId, Generation)>,
    ) -> Result<SessionSeed, RuntimeError> {
        let mut random = [0_u8; 90];
        context
            .entropy_mut()
            .fill_exact(&mut random)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let session_id = SessionId::from_bytes(array_16(&random, 0)?);
        let user_id = UserId::from_bytes(array_16(&random, 16)?);
        let connection_nonce = array_32(&random, 32)?;
        let public_cloak =
            cloak_from_random(random.get(64..90).ok_or(RuntimeError::InvalidValue)?)?;
        Ok(SessionSeed {
            session_id,
            user_id,
            home_server_id: self.config.server_id,
            account_id: authenticated_account.map(|(account_id, _)| account_id),
            account_session_generation: authenticated_account
                .map_or_else(|| Generation::new(0), |(_, generation)| Ok(generation))
                .map_err(|_| RuntimeError::InvalidValue)?,
            generation: Generation::new(1).map_err(|_| RuntimeError::InvalidValue)?,
            nickname: NicknameValue::parse(nickname).map_err(|_| RuntimeError::InvalidValue)?,
            display_name: DisplayNameValue::prepare(realname)
                .map_err(|_| RuntimeError::InvalidValue)?,
            public_cloak,
            connection_nonce,
            negotiated_capability_hash: capability_hash(state.registration.enabled_capabilities())?,
            created_at_utc: context.utc_now().map_err(|_| RuntimeError::InvalidValue)?,
            revision: Revision::new(context.domain().revision().get())
                .map_err(|_| RuntimeError::InvalidValue)?,
        })
    }

    fn registration_event(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        event: RegistrationEvent,
    ) -> Result<ActionStep, RuntimeError> {
        let actions = state
            .registration
            .event(event, context.now().get())
            .map_err(|_| RuntimeError::InvalidValue)?;
        let _ = generation;
        Ok(ActionStep::FollowUp(actions))
    }

    fn send_capabilities(
        &self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &ConnectionState,
        subcommand: &str,
        multiline: bool,
        tokens: &[String],
    ) -> Result<(), RuntimeError> {
        let target = self.target(state);
        let lines = if multiline {
            split_capability_lines(tokens, CAPABILITY_LINE_BYTES - CAPABILITY_FIXED_MARGIN)
                .map_err(|_| RuntimeError::InvalidValue)?
        } else {
            vec![agenc_ircd_client_wire::CapLine {
                continuation: false,
                capabilities: join_tokens(tokens)?,
            }]
        };
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(lines.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for line in lines {
            let middle: Vec<&str> = if line.continuation {
                vec![target, subcommand, "*"]
            } else {
                vec![target, subcommand]
            };
            frames.push(
                WireMessage::new(
                    &self.config.server_prefix,
                    "CAP",
                    &middle,
                    Some(&line.capabilities),
                )
                .map_err(|_| RuntimeError::InvalidValue)?,
            );
        }
        context
            .send_to(generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(())
    }

    fn welcome_frames(
        &self,
        context: &StateCoreContext,
        state: &ConnectionState,
        steps: &[WelcomeStep],
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        let target = self.target(state);
        let mut frames = Vec::new();
        for step in steps {
            match step {
                WelcomeStep::WelcomeThroughMyInfo => frames.extend(self.welcome_numerics(target)?),
                WelcomeStep::Isupport => {
                    frames.extend(
                        isupport_messages(
                            &self.config.server_prefix,
                            target,
                            &self.config.display_name,
                            &self.config.network_id,
                        )
                        .map_err(|_| RuntimeError::InvalidValue)?,
                    );
                    #[cfg(feature = "history")]
                    self.history_isupport(target, &mut frames)?;
                }
                WelcomeStep::LuserCounters => frames.push(
                    numeric_reply(
                        &self.config.server_prefix,
                        251,
                        target,
                        &[],
                        Some(&format!(
                            "There are {} users and 0 services on 1 servers",
                            context.sessions().registered_len()
                        )),
                    )
                    .map_err(|_| RuntimeError::InvalidValue)?,
                ),
                WelcomeStep::Motd => self.append_motd(context, target, &mut frames)?,
                WelcomeStep::RecoveryEpoch
                | WelcomeStep::AccountState
                | WelcomeStep::RegistrationBatches => {}
            }
        }
        Ok(frames)
    }

    #[cfg(feature = "history")]
    fn history_isupport(
        &self,
        target: &str,
        frames: &mut Vec<WireMessage>,
    ) -> Result<(), RuntimeError> {
        if self
            .advertised
            .dns_tls
            .capabilities()
            .iter()
            .any(|capability| capability.name() == "draft/chathistory")
        {
            frames.push(
                numeric_reply(
                    &self.config.server_prefix,
                    5,
                    target,
                    &["CHATHISTORY=100", "MSGREFTYPES=msgid,timestamp"],
                    Some("are supported by this server"),
                )
                .map_err(|_| RuntimeError::InvalidValue)?,
            );
        }
        Ok(())
    }

    fn append_motd(
        &self,
        context: &StateCoreContext,
        target: &str,
        frames: &mut Vec<WireMessage>,
    ) -> Result<(), RuntimeError> {
        let Some(motd) = context.motd() else {
            frames.push(
                numeric_reply(
                    &self.config.server_prefix,
                    422,
                    target,
                    &[],
                    Some("MOTD File is missing"),
                )
                .map_err(|_| RuntimeError::InvalidValue)?,
            );
            return Ok(());
        };
        frames.push(
            numeric_reply(
                &self.config.server_prefix,
                375,
                target,
                &[],
                Some("Message of the day"),
            )
            .map_err(|_| RuntimeError::InvalidValue)?,
        );
        for line in motd.lines() {
            frames.push(
                numeric_reply(&self.config.server_prefix, 372, target, &[], Some(line))
                    .map_err(|_| RuntimeError::InvalidValue)?,
            );
        }
        frames.push(
            numeric_reply(
                &self.config.server_prefix,
                376,
                target,
                &[],
                Some("End of MOTD"),
            )
            .map_err(|_| RuntimeError::InvalidValue)?,
        );
        Ok(())
    }

    fn welcome_numerics(&self, target: &str) -> Result<[WireMessage; 4], RuntimeError> {
        Ok([
            numeric_reply(
                &self.config.server_prefix,
                1,
                target,
                &[],
                Some("Welcome to AgenC"),
            )
            .map_err(|_| RuntimeError::InvalidValue)?,
            numeric_reply(
                &self.config.server_prefix,
                2,
                target,
                &[],
                Some(&format!("Your host is {}", self.config.server_prefix)),
            )
            .map_err(|_| RuntimeError::InvalidValue)?,
            numeric_reply(
                &self.config.server_prefix,
                3,
                target,
                &[],
                Some("This server was created at build time"),
            )
            .map_err(|_| RuntimeError::InvalidValue)?,
            numeric_reply(
                &self.config.server_prefix,
                4,
                target,
                &[&self.config.server_prefix, "agenc-ircd", "io", "io"],
                None,
            )
            .map_err(|_| RuntimeError::InvalidValue)?,
        ])
    }

    fn complete_carrier_route(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        carrier_generation: u64,
        route: CarrierRoute,
        observation: CarrierObservation<'_>,
    ) -> Result<ActionStep, RuntimeError> {
        match route {
            CarrierRoute::Finished {
                frames,
                result: carrier_result,
            } => {
                if !frames.is_empty() {
                    context
                        .send_to(generation, frames)
                        .map_err(|_| RuntimeError::MemoryExhausted)?;
                }
                record_result(observation.result, carrier_result);
                self.registration_event(
                    context,
                    generation,
                    state,
                    RegistrationEvent::AuthCarrierFinished {
                        generation: carrier_generation,
                    },
                )
            }
            CarrierRoute::Pending => {
                if self
                    .pending_observations
                    .contains_key(&(generation, carrier_generation))
                {
                    complete_observation(context, observation.token, ResultClass::Error);
                    return Err(RuntimeError::InvalidValue);
                }
                let observation = observation.token.take().ok_or(RuntimeError::InvalidValue)?;
                self.pending_observations
                    .insert((generation, carrier_generation), observation);
                Ok(ActionStep::Continue)
            }
            CarrierRoute::Close => {
                record_result(observation.result, ResultClass::Error);
                Ok(ActionStep::Close(CloseReason::ProtocolError))
            }
        }
    }

    fn send_numeric(
        &self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &ConnectionState,
        code: u16,
        middle: &[&str],
        description: &str,
    ) -> Result<(), RuntimeError> {
        let frame = numeric_reply(
            &self.config.server_prefix,
            code,
            self.target(state),
            middle,
            Some(description),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        self.send_one(context, generation, frame)
    }

    fn send_one(
        &self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        frame: WireMessage,
    ) -> Result<(), RuntimeError> {
        context
            .send_to(generation, vec![frame])
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(())
    }

    fn render_registration_error(
        &self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &ConnectionState,
        command: &str,
        error: RegistrationError,
    ) -> RouteOutcome {
        let result = match error {
            RegistrationError::InvalidNickname => self.send_numeric(
                context,
                generation,
                state,
                432,
                &["*"],
                "Erroneous nickname",
            ),
            RegistrationError::InvalidAccessToken => {
                self.send_numeric(context, generation, state, 464, &[], "Password incorrect")
            }
            RegistrationError::Grammar(
                agenc_ircd_client_wire::RegistrationGrammarError::NeedMoreParameters,
            ) => self.send_numeric(
                context,
                generation,
                state,
                461,
                &[command],
                "Not enough parameters",
            ),
            RegistrationError::Grammar(
                agenc_ircd_client_wire::RegistrationGrammarError::NoPrivileges,
            ) => self.send_numeric(context, generation, state, 481, &[], "Permission denied"),
            RegistrationError::Grammar(_) | RegistrationError::InvalidCommand => self.send_numeric(
                context,
                generation,
                state,
                421,
                &[command],
                "Unknown command",
            ),
            _ => Err(RuntimeError::InvalidValue),
        };
        if result.is_ok() {
            RouteOutcome::Continue
        } else {
            RouteOutcome::Close(CloseReason::ProtocolError)
        }
    }

    fn target<'a>(&self, state: &'a ConnectionState) -> &'a str {
        state
            .nickname
            .as_deref()
            .or_else(|| {
                state
                    .lease
                    .as_ref()
                    .map(|lease| lease.nickname.presentation())
            })
            .unwrap_or("*")
    }

    fn release_matching_lease(
        &mut self,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        lease_generation: u64,
    ) {
        if state
            .lease
            .as_ref()
            .is_some_and(|lease| lease.generation == lease_generation)
        {
            self.release_lease(generation, state);
        }
    }

    fn release_lease(&mut self, generation: ConnectionGeneration, state: &mut ConnectionState) {
        if let Some(lease) = state.lease.take()
            && self.leases.get(&lease.nickname) == Some(&generation)
        {
            self.leases.remove(&lease.nickname);
        }
    }

    fn queue_session_close(
        &mut self,
        context: &mut StateCoreContext,
        bound: BoundSession,
        reason: &str,
    ) {
        if self
            .pending_closures
            .iter()
            .any(|pending| pending.bound.user_id == bound.user_id)
        {
            return;
        }
        if self.pending_closures.try_reserve_exact(1).is_err() {
            return;
        }
        let mut owned_reason = String::new();
        if owned_reason.try_reserve_exact(reason.len()).is_err() {
            return;
        }
        owned_reason.push_str(reason);
        self.pending_closures.push(PendingClosure {
            bound,
            reason: owned_reason,
        });
        self.retry_session_closes(context);
    }

    fn retry_session_closes(&mut self, context: &mut StateCoreContext) {
        self.pending_closures.retain(|pending| {
            let user_id = pending.bound.user_id;
            if context.domain().session(user_id).is_none() {
                return false;
            }
            if context.pending_len() == 0 {
                crate::channels::close_registered(context, pending.bound, &pending.reason);
            }
            context.domain().session(user_id).is_some()
        });
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-01 reason=durable registration completion atomically installs each retained session or closes it and resolves its one command observation
    fn finalize_pending_registrations(&mut self, context: &mut StateCoreContext) {
        for (generation, pending) in std::mem::take(&mut self.pending_registrations) {
            let PendingRegistration {
                event_generation,
                bound,
                nickname,
                authenticated,
            } = pending;
            let account_committed = !authenticated
                || self.accounts.as_mut().is_some_and(|accounts| {
                    accounts
                        .registration_committed(
                            context,
                            generation,
                            bound.user_id,
                            crate::account_service::SessionHome::Local,
                        )
                        .is_ok()
                });
            let Some(mut state) = self.connections.remove(&generation) else {
                self.queue_session_close(context, bound, "connection closed");
                continue;
            };
            state.bound = Some(bound);
            state.nickname = Some(nickname);
            self.release_lease(generation, &mut state);
            let outcome = if account_committed {
                match state.registration.event(
                    RegistrationEvent::RegistrationCommitted {
                        generation: event_generation,
                        accepted: true,
                        authenticated,
                    },
                    context.now().get(),
                ) {
                    Ok(actions) => {
                        let mut observation = None;
                        self.drive_actions(
                            context,
                            generation,
                            &mut state,
                            actions,
                            &mut observation,
                        )
                    }
                    Err(_) => RouteOutcome::Close(CloseReason::ProtocolError),
                }
            } else {
                RouteOutcome::Close(CloseReason::ProtocolError)
            };
            self.refresh_deadline(context, generation, &mut state, outcome);
            if matches!(outcome, RouteOutcome::Close(_)) {
                close_transport(context, generation);
            }
            self.connections.insert(generation, state);
        }
    }

    fn reject_pending_registration(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> bool {
        let Some(pending) = self.pending_registrations.remove(&generation) else {
            return false;
        };
        if context
            .sessions()
            .connection(generation)
            .is_some_and(|entry| entry.session() == Some(pending.bound))
        {
            let _unbound = context
                .sessions_mut()
                .unbind_session(generation, pending.bound);
        }
        if pending.authenticated
            && let Some(accounts) = self.accounts.as_mut()
        {
            let _rejected = accounts.registration_rejected(context, generation);
        }
        close_transport(context, generation);
        true
    }

    /// Runs the remote account carriers the coordinator queued.
    fn drive_remote_accounts(&mut self, context: &mut StateCoreContext) {
        if let (Some(accounts), Some(federation)) =
            (self.accounts.as_mut(), self.federation.as_mut())
        {
            crate::remote_accounts::drive(context, accounts, federation);
        }
    }

    fn apply_account_completions(
        &mut self,
        context: &mut StateCoreContext,
        completions: Vec<CarrierCompletion>,
    ) {
        for completion in completions {
            if let (Some(accounts), Some(federation)) =
                (self.accounts.as_mut(), self.federation.as_mut())
                && crate::remote_accounts::completion(context, accounts, federation, &completion)
            {
                continue;
            }
            if completion.carrier_generation != 0
                && let Some(observation) = self
                    .pending_observations
                    .remove(&(completion.generation, completion.carrier_generation))
            {
                context.complete_command_observation(observation, completion.result);
            }
            if completion.close {
                close_transport(context, completion.generation);
                continue;
            }
            let Some(mut state) = self.connections.remove(&completion.generation) else {
                continue;
            };
            let actions = state.registration.event(
                RegistrationEvent::AuthCarrierFinished {
                    generation: completion.carrier_generation,
                },
                context.now().get(),
            );
            let mut observation = None;
            let outcome = match actions {
                Ok(actions) => self.drive_actions(
                    context,
                    completion.generation,
                    &mut state,
                    actions,
                    &mut observation,
                ),
                Err(_) => RouteOutcome::Close(CloseReason::ProtocolError),
            };
            if matches!(outcome, RouteOutcome::Close(_)) {
                self.release_lease(completion.generation, &mut state);
                close_transport(context, completion.generation);
            } else {
                self.connections.insert(completion.generation, state);
            }
        }
    }
}

fn charge_preauth(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
) -> Result<(), RuntimeError> {
    let demand = preauth_demand(generation)?;
    let now = context.now();
    context
        .buckets_mut()
        .charge_all_or_nothing(now, &[demand])
        .map_err(|_| RuntimeError::LimitExceeded)
}

fn preauth_demand(generation: ConnectionGeneration) -> Result<BucketDemand, RuntimeError> {
    BucketDemand::new(
        BucketKind::PreAuthCommand,
        BucketKey::Connection(generation),
        1,
    )
}

fn should_charge_registered_control(
    message: &agenc_ircd_client_wire::ParsedMessage,
    access_policy: AccessTokenPolicy,
) -> bool {
    !matches!(
        parse_registration_command(message, access_policy),
        Ok(RegistrationCommand::Nick
            | RegistrationCommand::PostRegistration(_)
            | RegistrationCommand::Quit)
    )
}

fn authority_fence_exempt(message: &agenc_ircd_client_wire::ParsedMessage) -> bool {
    matches!(message.command(), "PING" | "PONG" | "QUIT")
}

fn charge_registered_control(
    context: &mut StateCoreContext,
    user_id: UserId,
) -> Result<(), RuntimeError> {
    let demand = registered_command_demand(user_id)?;
    let now = context.now();
    context
        .buckets_mut()
        .charge_all_or_nothing(now, &[demand])
        .map_err(|_| RuntimeError::LimitExceeded)
}

fn registered_command_demand(user_id: UserId) -> Result<BucketDemand, RuntimeError> {
    BucketDemand::new(
        BucketKind::RegisteredCommand,
        BucketKey::Session(user_id),
        1,
    )
}

impl CommandRouter for RegistrationRouter {
    fn maintenance(
        &mut self,
        context: &mut StateCoreContext,
        event: crate::state_core::inbox::MaintenanceEvent,
    ) {
        if event == crate::state_core::inbox::MaintenanceEvent::RetentionSweep {
            let pending = self
                .e2ee
                .as_ref()
                .is_some_and(|edge| edge.retention_blocked());
            if let Some(edge) = self.edge.as_mut() {
                edge.retain_barriers(context, pending);
                edge.retain_history(context);
            }
            if let Some(federation) = self.federation.as_mut() {
                federation.retain_history(context);
            }
        }
    }

    fn startup(&mut self, context: &mut StateCoreContext) {
        if let Some(accounts) = self.accounts.as_mut() {
            accounts.startup(context);
        }
        if let Some(federation) = self.federation.as_mut() {
            federation.startup(context);
        }
    }

    fn e2ee_stats(&self) -> Option<[u64; 9]> {
        if let Some(e2ee) = self.e2ee.as_ref() {
            return Some(e2ee.stats());
        }
        self.federation
            .as_ref()
            .and_then(|federation| federation.companion_executor())
            .map(crate::e2ee::coordinator::CompanionCoordinator::stats)
    }

    fn federation_inbound(
        &mut self,
        context: &mut StateCoreContext,
        message: crate::federation::FederationInbound,
    ) {
        if let Some(edge) = self.edge.as_mut() {
            let completions = edge.inbound(context, message);
            self.apply_edge_completions(context, completions);
            self.drive_e2ee(context);
            return;
        }
        if let Some(federation) = self.federation.as_mut() {
            federation.inbound(context, message);
            self.drive_remote_accounts(context);
        }
    }

    fn federation_stats(&self) -> Option<[u64; 7]> {
        if let Some(edge) = &self.edge {
            return Some(edge.federation_stats());
        }
        self.federation
            .as_ref()
            .map(FederationCoordinator::federation_stats)
    }

    fn admin_peer_quarantine(
        &mut self,
        context: &mut StateCoreContext,
        server: ServerId,
    ) -> Result<(), PeerQuarantineRefusal> {
        match self.federation.as_mut() {
            Some(federation) => federation.admin_quarantine_peer(context, server),
            None => Err(PeerQuarantineRefusal::UnknownPeer),
        }
    }

    fn route(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: agenc_ircd_client_wire::ParsedMessage,
        observation: CommandObservation,
    ) -> RouteOutcome {
        self.route_message(context, generation, message, observation)
    }

    fn connection_opened(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        let Some(advertised) = context
            .sessions()
            .connection(generation)
            .and_then(|entry| self.advertised.for_purpose(entry.purpose()))
        else {
            close_transport(context, generation);
            return;
        };
        let now = context.now();
        let elapsed = context
            .sessions()
            .connection(generation)
            .map_or(0, |entry| entry.sink().registration_elapsed_millis());
        let Some((started, deadline)) = registration_window(now, elapsed) else {
            close_transport(context, generation);
            return;
        };
        if let Ok(registration) = RegistrationState::new(started, self.access_policy()) {
            let scheduled = context.timers_mut().schedule(
                deadline,
                TimerKind::RegistrationDeadline,
                TimedId::Connection(generation),
            );
            if scheduled.is_err() {
                close_transport(context, generation);
                return;
            }
            if self
                .accounts
                .as_mut()
                .is_some_and(|accounts| accounts.connection_opened(context, generation).is_err())
            {
                cancel_connection_timers(context, generation);
                close_transport(context, generation);
                return;
            }
            self.connections.insert(
                generation,
                ConnectionState {
                    registration,
                    advertised,
                    lease: None,
                    bound: None,
                    nickname: None,
                    departure_reason: None,
                    deadline: DeadlineState::Registration,
                    allow_guests: self.config.allow_guests,
                    deferred_observations: VecDeque::new(),
                },
            );
            if let Some(edge) = self.edge.as_mut() {
                edge.connection_opened(context, generation);
            }
        } else {
            close_transport(context, generation);
        }
    }

    fn connection_closed(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        _reason: CloseReason,
    ) {
        if let Some(accounts) = self.accounts.as_mut() {
            accounts.connection_closed(context, generation);
        }
        self.commands.connection_closed(context, generation);
        while let Some(key) = self
            .pending_observations
            .keys()
            .find(|(pending_generation, _)| *pending_generation == generation)
            .copied()
        {
            if let Some(observation) = self.pending_observations.remove(&key) {
                context.complete_command_observation(observation, ResultClass::Closed);
            }
        }
        let Some(mut state) = self.connections.remove(&generation) else {
            return;
        };
        for observation in state.deferred_observations.drain(..) {
            context.complete_command_observation(observation, ResultClass::Closed);
        }
        cancel_connection_timers(context, generation);
        let _event = state
            .registration
            .event(RegistrationEvent::TransportClosed, context.now().get());
        self.release_lease(generation, &mut state);
        let reason = state
            .departure_reason
            .as_deref()
            .unwrap_or("connection closed")
            .to_owned();
        self.edge_carriers.remove(&generation);
        if let Some(edge) = self.edge.as_mut() {
            if let Some(e2ee) = self.e2ee.as_mut() {
                e2ee.delete_origin(context, edge, generation);
            }
            edge.connection_closed(context, generation, &reason);
            return;
        }
        if let Some(bound) = state.bound {
            self.queue_session_close(context, bound, &reason);
        }
    }

    fn config_reloaded(
        &mut self,
        _context: &mut StateCoreContext,
        snapshot: &crate::runtime_config::RuntimeConfigSnapshot,
    ) {
        self.config.display_name = snapshot.display_name();
        self.config.allow_guests = snapshot.account_policy().allow_guests;
        if let Some(accounts) = self.accounts.as_mut() {
            accounts.reload_policy(snapshot.account_policy());
        }
    }

    fn reload_ready(&self) -> bool {
        self.federation
            .as_ref()
            .is_none_or(FederationCoordinator::reload_ready)
            && self.edge.as_ref().is_none_or(EdgeFederation::reload_ready)
            && self.pending_registrations.is_empty()
            && self.pending_closures.is_empty()
            && self.pending_observations.is_empty()
            && self
                .connections
                .values()
                .all(|state| state.deferred_observations.is_empty())
            && self
                .accounts
                .as_ref()
                .is_none_or(AccountServiceCoordinator::reload_ready)
            && self.commands.reload_ready()
    }

    fn batch_applied(&mut self, context: &mut StateCoreContext, _plan_count: usize) {
        self.finalize_pending_registrations(context);
        if let Some(accounts) = self.accounts.as_mut() {
            let completions = accounts.batch_applied(context);
            self.apply_account_completions(context, completions);
        }
        self.retry_session_closes(context);
        if let Some(federation) = self.federation.as_mut() {
            federation.batch_applied(context);
        }
        if let (Some(accounts), Some(federation)) =
            (self.accounts.as_mut(), self.federation.as_mut())
        {
            crate::remote_accounts::batch_settled(context, accounts, federation);
        }
        self.drive_remote_accounts(context);
        if let Some(edge) = self.edge.as_mut() {
            let completions = edge.batch_applied(context);
            self.apply_edge_completions(context, completions);
        }
        if let (Some(e2ee), Some(edge)) = (self.e2ee.as_mut(), self.edge.as_mut()) {
            let outputs = e2ee.batch_applied(context, edge);
            for output in outputs {
                let _sent = context.send_to(output.generation, output.frames);
            }
        }
        // A committed barrier part may have completed the set.
        self.drive_e2ee(context);
    }

    fn crypto_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
    ) {
        if let Some(accounts) = self
            .accounts
            .as_mut()
            .filter(|accounts| accounts.owns_crypto_job(message.job_id))
        {
            let completions = accounts.crypto_completed(context, message);
            self.apply_account_completions(context, completions);
            return;
        }
        if let Some(federation) = self
            .federation
            .as_mut()
            .filter(|federation| federation.owns_crypto_job(message.job_id))
        {
            federation.crypto_completed(context, message);
            self.drive_remote_accounts(context);
            return;
        }
        if let Err((generation, _error)) = self.commands.crypto_completed(context, message) {
            close_transport(context, generation);
        }
    }

    fn storage_read_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: crate::bridge::StorageReadCompletionMessage,
    ) {
        if let Some(edge) = self
            .edge
            .as_mut()
            .filter(|edge| edge.owns_history_read(message.read_id))
        {
            edge.history_read_completed(context, message);
            return;
        }
        if let Some(federation) = self
            .federation
            .as_mut()
            .filter(|federation| federation.owns_storage_read(message.read_id))
        {
            federation.storage_read_completed(context, message);
            self.drive_remote_accounts(context);
            return;
        }
        if self.commands.owns_history_read(message.read_id) {
            if let Err((generation, _)) = self.commands.history_read_completed(context, message) {
                close_transport(context, generation);
            }
            return;
        }
        if let Some(accounts) = self.accounts.as_mut() {
            let completions = accounts.storage_read_completed(context, message);
            self.apply_account_completions(context, completions);
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=a rejected batch notifies every attached role in a fixed order so no role observes the others' rollback out of sequence
    fn batch_rejected(
        &mut self,
        context: &mut StateCoreContext,
        origin: Option<crate::state_core::StagedOrigin>,
        _error: agenc_ircd_storage::StorageError,
    ) {
        if let Some(federation) = self.federation.as_mut() {
            federation.batch_rejected(context);
        }
        if let (Some(accounts), Some(federation)) =
            (self.accounts.as_mut(), self.federation.as_mut())
        {
            crate::remote_accounts::batch_settled(context, accounts, federation);
        }
        if let Some(edge) = self.edge.as_mut() {
            edge.batch_rejected(context);
        }
        if let Some(e2ee) = self.e2ee.as_mut() {
            e2ee.batch_rejected();
        }
        let generation = origin.as_ref().map(StagedOrigin::generation);
        if generation
            .is_some_and(|generation| self.reject_pending_registration(context, generation))
        {
            self.retry_session_closes(context);
            return;
        }
        if let Some((generation, accounts)) = generation.zip(self.accounts.as_mut())
            && accounts.account_deletion_rejected(context, generation)
        {
            if let Some(origin) = origin {
                reject_staged_origin(context, origin);
            }
            self.retry_session_closes(context);
            return;
        }
        let completions = self
            .accounts
            .as_mut()
            .map(|accounts| accounts.batch_rejected(context, generation));
        if let Some(origin) = origin {
            reject_staged_origin(context, origin);
        }
        if let Some(completions) = completions {
            self.apply_account_completions(context, completions);
        }
        self.retry_session_closes(context);
    }

    fn timer_fired(&mut self, context: &mut StateCoreContext, entry: TimerEntry) {
        if let Some(federation) = self.federation.as_mut()
            && federation.timer_fired(context, entry)
        {
            return;
        }
        if let Some(edge) = self.edge.as_mut()
            && edge.timer_fired(context, entry)
        {
            return;
        }
        let Some(accounts) = self.accounts.as_mut() else {
            return;
        };
        let (handled, completions) = accounts.timer_fired(context, entry);
        self.apply_account_completions(context, completions);
        if handled {
            return;
        }
        match self.commands.timer_fired(context, entry) {
            Ok(true) => return,
            Err((generation, _error)) => {
                close_transport(context, generation);
                return;
            }
            Ok(false) => {}
        }
        let TimedId::Connection(generation) = entry.id else {
            return;
        };
        if matches!(
            entry.kind,
            TimerKind::RegistrationDeadline | TimerKind::Ping | TimerKind::Pong
        ) {
            self.timer_actions(context, generation, entry);
        }
    }
}

enum ActionStep {
    Continue,
    FollowUp(Vec<RegistrationAction>),
    Resume(std::vec::IntoIter<agenc_ircd_client_wire::ParsedMessage>),
    Close(CloseReason),
}

impl From<RouteOutcome> for ActionStep {
    fn from(outcome: RouteOutcome) -> Self {
        match outcome {
            RouteOutcome::Continue => Self::Continue,
            RouteOutcome::Close(reason) => Self::Close(reason),
        }
    }
}

fn registration_window(
    now: agenc_ircd_types::MonotonicTick,
    elapsed: u64,
) -> Option<(u64, agenc_ircd_types::MonotonicTick)> {
    let remaining = REGISTRATION_TIMEOUT_MILLIS.checked_sub(elapsed)?;
    if remaining == 0 {
        return None;
    }
    Some((
        now.get().checked_sub(elapsed)?,
        now.checked_add(remaining).ok()?,
    ))
}

pub(crate) fn core_capabilities(
    creation_policy: AccountCreationPolicy,
    recovery_epoch: RecoveryEpoch,
    purpose: ListenerPurpose,
) -> Result<CapabilityProfile, RuntimeError> {
    let advertise_sts = match purpose {
        ListenerPurpose::ClientTls => true,
        #[cfg(feature = "wss")]
        ListenerPurpose::ClientWss => true,
        ListenerPurpose::ClientOnion => false,
        #[cfg(not(feature = "wss"))]
        ListenerPurpose::ClientWss => return Err(RuntimeError::InvalidValue),
        ListenerPurpose::Federation | ListenerPurpose::AdminLocal | ListenerPurpose::AdminTls => {
            return Err(RuntimeError::InvalidValue);
        }
    };
    let recovery_value = format!("v1.{}", recovery_epoch.to_base64url());
    let mut capabilities = Vec::new();
    for (name, value) in [
        ("account-notify", None),
        ("account-tag", None),
        ("away-notify", None),
        ("batch", None),
        ("cap-notify", None),
        ("echo-message", None),
        ("extended-join", None),
        ("invite-notify", None),
        ("labeled-response", None),
        ("message-ids", None),
        ("message-tags", None),
        ("monitor", None),
        ("multi-prefix", None),
        ("sasl", Some("AGENC-OPAQUE")),
        ("server-time", None),
        ("setname", None),
        ("standard-replies", None),
        ("userhost-in-names", None),
        ("utf8only", None),
        ("agenc.ag/privacy", Some("v1")),
        ("agenc.ag/account-controls", Some("v1")),
        ("agenc.ag/account-credentials", Some("v1")),
        ("agenc.ag/channel-controls", Some("v1")),
        ("agenc.ag/recovery", Some(recovery_value.as_str())),
    ] {
        capabilities
            .push(CapabilitySpec::new(name, value).map_err(|_| RuntimeError::InvalidValue)?);
    }
    if advertise_sts {
        capabilities.push(
            CapabilitySpec::new("sts", Some(STS_CAPABILITY_VALUE))
                .map_err(|_| RuntimeError::InvalidValue)?,
        );
    }
    if !matches!(creation_policy, AccountCreationPolicy::Closed) {
        capabilities.push(
            CapabilitySpec::new("agenc.ag/account-create", Some("v1"))
                .map_err(|_| RuntimeError::InvalidValue)?,
        );
    }
    CapabilityProfile::new(capabilities).map_err(|_| RuntimeError::InvalidValue)
}

fn join_tokens(tokens: &[String]) -> Result<String, RuntimeError> {
    let separators = tokens.len().saturating_sub(1);
    let length = tokens.iter().try_fold(separators, |length, token| {
        length
            .checked_add(token.len())
            .ok_or(RuntimeError::Overflow)
    })?;
    let mut joined = String::new();
    joined
        .try_reserve_exact(length)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for (index, token) in tokens.iter().enumerate() {
        if index != 0 {
            joined.push(' ');
        }
        joined.push_str(token);
    }
    Ok(joined)
}

fn capability_hash(names: &[String]) -> Result<[u8; 32], RuntimeError> {
    let mut names = names.to_vec();
    names.sort_unstable();
    let bytes = names.join("\0");
    semantic_digest(SemanticHashDomain::CapabilityId, bytes.as_bytes())
        .map(|digest| *digest.as_bytes())
        .map_err(|_| RuntimeError::InvalidValue)
}

pub(crate) fn cloak_from_random(random: &[u8]) -> Result<PublicCloak, RuntimeError> {
    if random.len() != 26 {
        return Err(RuntimeError::InvalidValue);
    }
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut text = [0_u8; 26];
    for (target, source) in text.iter_mut().zip(random) {
        *target = *ALPHABET
            .get(usize::from(*source & 31))
            .ok_or(RuntimeError::InvalidValue)?;
    }
    let user = std::str::from_utf8(text.get(..10).ok_or(RuntimeError::InvalidValue)?)
        .map_err(|_| RuntimeError::InvalidValue)?;
    let host = std::str::from_utf8(text.get(10..).ok_or(RuntimeError::InvalidValue)?)
        .map_err(|_| RuntimeError::InvalidValue)?;
    PublicCloak::parse(user, host).map_err(|_| RuntimeError::InvalidValue)
}

fn array_16(bytes: &[u8], start: usize) -> Result<[u8; 16], RuntimeError> {
    bytes
        .get(start..start.saturating_add(16))
        .ok_or(RuntimeError::InvalidValue)?
        .try_into()
        .map_err(|_| RuntimeError::InvalidValue)
}

fn array_32(bytes: &[u8], start: usize) -> Result<[u8; 32], RuntimeError> {
    bytes
        .get(start..start.saturating_add(32))
        .ok_or(RuntimeError::InvalidValue)?
        .try_into()
        .map_err(|_| RuntimeError::InvalidValue)
}

fn deadline_matches(deadline: DeadlineState, kind: TimerKind) -> bool {
    matches!(
        (deadline, kind),
        (DeadlineState::Registration, TimerKind::RegistrationDeadline)
            | (DeadlineState::Idle, TimerKind::Ping)
            | (DeadlineState::Pong, TimerKind::Pong)
    )
}

fn schedule_connection_timer(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    kind: TimerKind,
    delay: u64,
) {
    let Ok(deadline) = context.now().checked_add(delay) else {
        close_transport(context, generation);
        return;
    };
    if context
        .timers_mut()
        .schedule(deadline, kind, TimedId::Connection(generation))
        .is_err()
    {
        close_transport(context, generation);
    }
}

fn cancel_connection_timers(context: &mut StateCoreContext, generation: ConnectionGeneration) {
    let id = TimedId::Connection(generation);
    for kind in [
        TimerKind::RegistrationDeadline,
        TimerKind::Ping,
        TimerKind::Pong,
    ] {
        context.timers_mut().cancel(kind, id);
    }
}

fn close_transport(context: &mut StateCoreContext, generation: ConnectionGeneration) {
    if let Some(sink) = context.sessions().sink_for_generation(generation) {
        sink.begin_slow_consumer_close();
    }
    context.sessions_mut().mark_sink_gone(generation);
}

fn complete_observation(
    context: &StateCoreContext,
    observation: &mut Option<CommandObservation>,
    result: ResultClass,
) {
    if let Some(observation) = observation.take() {
        context.complete_command_observation(observation, result);
    }
}

fn record_result(current: &mut ResultClass, candidate: ResultClass) {
    if result_class_rank(candidate) > result_class_rank(*current) {
        *current = candidate;
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

fn reject_staged_origin(context: &mut StateCoreContext, origin: StagedOrigin) {
    let (generation, frames) = origin.into_rejection();
    if !frames.is_empty() && context.send_to(generation, frames).is_err() {
        close_transport(context, generation);
    }
}

/// The `FAIL ACCTCREATE UNAVAILABLE` route of an edge carrier.
fn account_unavailable(prefix: &str) -> CarrierRoute {
    match crate::account_service::account_failure(prefix, AccountCarrierKind::Create) {
        Ok(frame) => CarrierRoute::Finished {
            frames: vec![frame],
            result: ResultClass::Rejected,
        },
        Err(_) => CarrierRoute::Close,
    }
}

/// Renders the coordinator's answer to a forwarded SASL envelope through
/// the edge transport; `None` closes the transport.
fn edge_sasl_answer(
    carrier: &mut EdgeCarrier,
    names: (&str, &str),
    finish: bool,
    outcome: crate::federation::edge::RemoteCarrierOutcome,
    now: u64,
) -> Option<(Vec<WireMessage>, ResultClass)> {
    use crate::federation::edge::RemoteCarrierOutcome;
    let (prefix, target) = names;
    let (mut actions, accepted) = match outcome {
        RemoteCarrierOutcome::Challenge(bytes) if !finish => {
            (carrier.sasl.server_response(&bytes, now).ok()?, None)
        }
        RemoteCarrierOutcome::Authenticated {
            account_id,
            account_session_generation,
            auth_grant_id,
            chunks,
        } if finish => {
            let bytes = agenc_ircd_client_wire::decode_sasl_payload(&chunks.concat())?;
            let actions = carrier.sasl.server_response(&bytes, now).ok()?;
            carrier.grant = Some((account_id, account_session_generation, auth_grant_id));
            (actions, Some(true))
        }
        RemoteCarrierOutcome::Failed { chunks } if finish && !chunks.is_empty() => {
            let bytes = agenc_ircd_client_wire::decode_sasl_payload(&chunks.concat())?;
            (carrier.sasl.server_response(&bytes, now).ok()?, Some(false))
        }
        _ => (carrier.sasl.unavailable(now).ok()?, None),
    };
    let result = match accepted {
        Some(accepted) => {
            actions.extend(carrier.sasl.complete(accepted, now).ok()?);
            if accepted {
                ResultClass::Ok
            } else {
                ResultClass::Rejected
            }
        }
        None if actions.is_empty() => ResultClass::Rejected,
        None => ResultClass::Ok,
    };
    let frames = crate::account_service::render_sasl_actions(prefix, target, actions).ok()?;
    Some((frames, result))
}

/// Renders the coordinator's answer to a forwarded account-creation
/// envelope through the edge transport; `None` closes the transport.
fn edge_account_answer(
    carrier: &mut EdgeCarrier,
    prefix: &str,
    finish: bool,
    outcome: crate::federation::edge::RemoteCarrierOutcome,
    now: u64,
) -> Option<(Vec<WireMessage>, ResultClass)> {
    use crate::federation::edge::RemoteCarrierOutcome;
    use agenc_ircd_client_wire::AccountCarrierPhase;
    let (actions, created) = match outcome {
        RemoteCarrierOutcome::Challenge(bytes) if !finish => (
            carrier
                .creation
                .server_response(AccountCarrierPhase::Start, &bytes, now)
                .ok()?,
            None,
        ),
        RemoteCarrierOutcome::Created { account_id, chunks } if finish => {
            let bytes = agenc_ircd_client_wire::decode_account_payload(&chunks.concat())?;
            (
                carrier
                    .creation
                    .server_response(AccountCarrierPhase::Finish, &bytes, now)
                    .ok()?,
                Some(account_id),
            )
        }
        _ => {
            carrier.creation.reject();
            let frame =
                crate::account_service::account_failure(prefix, AccountCarrierKind::Create).ok()?;
            return Some((vec![frame], ResultClass::Rejected));
        }
    };
    let mut frames =
        crate::account_service::render_account_actions(prefix, AccountCarrierKind::Create, actions)
            .ok()?;
    if let Some(account_id) = created {
        frames.push(crate::account_service::account_created_note(prefix, account_id).ok()?);
    }
    Some((frames, ResultClass::Ok))
}

/// Applies a complete cross-profile barrier: both halves commit in one
/// transaction, the router's companion rows joining the base apply.
pub(crate) fn apply_ready_barrier(
    context: &mut StateCoreContext,
    e2ee: &mut crate::e2ee::edge::E2eeEdge,
    edge: &mut crate::federation::edge::EdgeFederation,
) {
    if !e2ee.is_active() {
        return;
    }
    let Some(mutation_id) = edge.barrier_ready() else {
        return;
    };
    match e2ee.prepare_barrier(context, edge, mutation_id) {
        Ok((writes, rendered)) => {
            if edge.apply_barrier(context, writes, rendered) {
                e2ee.barrier_staged(mutation_id, Vec::new());
            } else {
                e2ee.rollback_projection();
            }
        }
        Err(_) => e2ee.fail_frame(context, edge),
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_client_wire::{FramedLine, parse_message};
    use agenc_ircd_types::MonotonicTick;

    use super::*;
    use crate::admission::{BucketTable, RateLimits};

    #[test]
    fn registration_budget_includes_upgrade_and_admission_delay() -> Result<(), RuntimeError> {
        let now = MonotonicTick::from_ticks(50_000);
        assert_eq!(
            registration_window(now, 0),
            Some((50_000, MonotonicTick::from_ticks(80_000)))
        );
        assert_eq!(
            registration_window(now, 4_999),
            Some((45_001, MonotonicTick::from_ticks(75_001)))
        );
        assert_eq!(
            registration_window(now, 29_999),
            Some((20_001, MonotonicTick::from_ticks(50_001)))
        );
        assert!(registration_window(now, 30_000).is_none());
        assert!(registration_window(now, u64::MAX).is_none());
        assert!(registration_window(MonotonicTick::from_ticks(1), 2).is_none());
        assert!(registration_window(MonotonicTick::from_ticks(u64::MAX), 0).is_none());
        Ok(())
    }

    #[test]
    fn core_capabilities_and_cloaks_are_closed() -> Result<(), RuntimeError> {
        let recovery_epoch = RecoveryEpoch::from_bytes([0; 16]);
        let profile = core_capabilities(
            AccountCreationPolicy::Closed,
            recovery_epoch,
            ListenerPurpose::ClientOnion,
        )?;
        let names = profile
            .capabilities()
            .iter()
            .map(CapabilitySpec::name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "account-notify",
                "account-tag",
                "away-notify",
                "batch",
                "cap-notify",
                "echo-message",
                "extended-join",
                "invite-notify",
                "labeled-response",
                "message-ids",
                "message-tags",
                "monitor",
                "multi-prefix",
                "sasl",
                "server-time",
                "setname",
                "standard-replies",
                "userhost-in-names",
                "utf8only",
                "agenc.ag/privacy",
                "agenc.ag/account-controls",
                "agenc.ag/account-credentials",
                "agenc.ag/channel-controls",
                "agenc.ag/recovery",
            ]
        );
        assert_eq!(
            profile
                .capabilities()
                .iter()
                .find(|capability| capability.name() == "agenc.ag/recovery")
                .and_then(CapabilitySpec::value),
            Some("v1.AAAAAAAAAAAAAAAAAAAAAA")
        );
        let open = core_capabilities(
            AccountCreationPolicy::Open,
            recovery_epoch,
            ListenerPurpose::ClientOnion,
        )?;
        assert_eq!(
            open.capabilities().last().map(CapabilitySpec::name),
            Some("agenc.ag/account-create")
        );
        let cloak = cloak_from_random(&[0; 26])?;
        assert_eq!(cloak.user_component(), b"aaaaaaaaaa");
        assert_eq!(cloak.host_component(), b"aaaaaaaaaaaaaaaa");
        assert_eq!(
            cloak_from_random(&[0; 25]).err(),
            Some(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn transport_capabilities_advertise_sts_only_on_dns_tls() -> Result<(), RuntimeError> {
        let profiles = ClientCapabilityProfiles::new(
            AccountCreationPolicy::Closed,
            RecoveryEpoch::from_bytes([0; 16]),
        )?;
        let direct = profiles
            .for_purpose(ListenerPurpose::ClientTls)
            .ok_or(RuntimeError::InvalidValue)?;
        let onion = profiles
            .for_purpose(ListenerPurpose::ClientOnion)
            .ok_or(RuntimeError::InvalidValue)?;

        assert_eq!(
            direct
                .capabilities()
                .iter()
                .find(|capability| capability.name() == "sts")
                .and_then(CapabilitySpec::value),
            Some(STS_CAPABILITY_VALUE)
        );
        assert!(
            onion
                .capabilities()
                .iter()
                .all(|capability| capability.name() != "sts")
        );
        Ok(())
    }

    #[test]
    fn capability_hash_is_order_independent() -> Result<(), RuntimeError> {
        assert_eq!(
            capability_hash(&["batch".to_owned(), "message-tags".to_owned()])?,
            capability_hash(&["message-tags".to_owned(), "batch".to_owned()])?
        );
        Ok(())
    }

    #[test]
    fn preauth_lines_stop_at_the_exact_connection_burst() -> Result<(), RuntimeError> {
        let generation = ConnectionGeneration::new(7);
        let mut buckets = BucketTable::new(
            RateLimits::defaults(),
            crate::sync::Arc::new(crate::budget::MemoryBudget::new(1 << 20)),
        );
        let demand = preauth_demand(generation)?;
        let now = MonotonicTick::from_ticks(0);
        for _ in 0..10 {
            assert!(buckets.charge_all_or_nothing(now, &[demand]).is_ok());
        }
        assert!(buckets.charge_all_or_nothing(now, &[demand]).is_err());
        Ok(())
    }

    #[test]
    fn registered_control_lines_stop_at_the_exact_session_burst() -> Result<(), RuntimeError> {
        let user_id = UserId::from_bytes([7; 16]);
        let mut buckets = BucketTable::new(
            RateLimits::defaults(),
            crate::sync::Arc::new(crate::budget::MemoryBudget::new(1 << 20)),
        );
        let demand = registered_command_demand(user_id)?;
        let now = MonotonicTick::from_ticks(0);
        for _ in 0..20 {
            assert!(buckets.charge_all_or_nothing(now, &[demand]).is_ok());
        }
        assert!(buckets.charge_all_or_nothing(now, &[demand]).is_err());
        Ok(())
    }

    fn parsed(
        line: &str,
    ) -> Result<agenc_ircd_client_wire::ParsedMessage, Box<dyn core::error::Error>> {
        parse_message(FramedLine::new(line)?)?.ok_or_else(|| "empty test message".into())
    }

    #[test]
    fn token_join_array_and_hash_helpers_cover_empty_exact_and_short_inputs()
    -> Result<(), RuntimeError> {
        assert_eq!(join_tokens(&[])?, "");
        assert_eq!(join_tokens(&["one".to_owned()])?, "one");
        assert_eq!(
            join_tokens(&["one".to_owned(), "two".to_owned(), "three".to_owned()])?,
            "one two three"
        );
        assert_eq!(capability_hash(&[])?, capability_hash(&[])?);
        assert_ne!(
            capability_hash(&[])?,
            capability_hash(&["batch".to_owned()])?
        );

        let bytes = (0_u8..64).collect::<Vec<_>>();
        assert_eq!(
            array_16(&bytes, 0)?.as_slice(),
            bytes.get(..16).ok_or(RuntimeError::InvalidValue)?
        );
        assert_eq!(
            array_16(&bytes, 48)?.as_slice(),
            bytes.get(48..64).ok_or(RuntimeError::InvalidValue)?
        );
        assert_eq!(array_16(&bytes, 49), Err(RuntimeError::InvalidValue));
        assert_eq!(
            array_16(&bytes, usize::MAX),
            Err(RuntimeError::InvalidValue)
        );
        assert_eq!(
            array_32(&bytes, 0)?.as_slice(),
            bytes.get(..32).ok_or(RuntimeError::InvalidValue)?
        );
        assert_eq!(
            array_32(&bytes, 32)?.as_slice(),
            bytes.get(32..64).ok_or(RuntimeError::InvalidValue)?
        );
        assert_eq!(array_32(&bytes, 33), Err(RuntimeError::InvalidValue));
        assert_eq!(
            array_32(&bytes, usize::MAX),
            Err(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn registration_deadline_matching_is_exact_for_every_state_and_timer_kind() {
        let exact = [
            (DeadlineState::Registration, TimerKind::RegistrationDeadline),
            (DeadlineState::Idle, TimerKind::Ping),
            (DeadlineState::Pong, TimerKind::Pong),
        ];
        for (deadline, kind) in exact {
            assert!(deadline_matches(deadline, kind));
        }
        for deadline in [
            DeadlineState::None,
            DeadlineState::Registration,
            DeadlineState::Idle,
            DeadlineState::Pong,
        ] {
            for kind in [
                TimerKind::RegistrationDeadline,
                TimerKind::Ping,
                TimerKind::Pong,
                TimerKind::Reservation,
            ] {
                let expected = exact.contains(&(deadline, kind));
                assert_eq!(deadline_matches(deadline, kind), expected);
            }
        }
    }

    #[test]
    fn registered_control_charging_exempts_only_closed_command_classes()
    -> Result<(), Box<dyn core::error::Error>> {
        let ignored = AccessTokenPolicy::IgnoreCompatibilityPass;
        let required = AccessTokenPolicy::RequireConfiguredToken;
        for line in ["NICK tester", "QUIT :bye", "PRIVMSG target :body"] {
            assert!(!should_charge_registered_control(&parsed(line)?, ignored));
        }
        for line in ["CAP LS 302", "AUTHENTICATE AGENC-OPAQUE", "UNKNOWN"] {
            assert!(should_charge_registered_control(&parsed(line)?, ignored));
        }
        assert!(should_charge_registered_control(
            &parsed("PASS compatibility")?,
            required,
        ));
        Ok(())
    }

    #[test]
    fn pending_authority_fence_exempts_only_ping_pong_and_quit()
    -> Result<(), Box<dyn core::error::Error>> {
        for line in ["PING token", "PONG token", "QUIT :bye"] {
            assert!(authority_fence_exempt(&parsed(line)?));
        }
        for line in [
            "CAP LIST",
            "AUTHENTICATE *",
            "ACCTCRED START",
            "NICK tester",
            "PRIVMSG target :body",
            "NOTICE target :body",
        ] {
            assert!(!authority_fence_exempt(&parsed(line)?));
        }
        Ok(())
    }

    #[test]
    fn action_step_conversion_and_cloak_alphabet_cover_closed_variants() -> Result<(), RuntimeError>
    {
        assert!(matches!(
            ActionStep::from(RouteOutcome::Continue),
            ActionStep::Continue
        ));
        assert!(matches!(
            ActionStep::from(RouteOutcome::Close(CloseReason::Shutdown)),
            ActionStep::Close(CloseReason::Shutdown)
        ));
        let random = (0_u8..26).map(|value| value * 7).collect::<Vec<_>>();
        let cloak = cloak_from_random(&random)?;
        assert_eq!(cloak.user_component().len(), 10);
        assert_eq!(cloak.host_component().len(), 16);
        assert_eq!(
            cloak_from_random(&[]).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            cloak_from_random(&[0; 27]).err(),
            Some(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn command_result_accumulates_the_strongest_final_outcome() {
        let mut result = ResultClass::Ok;
        record_result(&mut result, ResultClass::Rejected);
        record_result(&mut result, ResultClass::Ok);
        assert_eq!(result, ResultClass::Rejected);

        record_result(&mut result, ResultClass::Busy);
        record_result(&mut result, ResultClass::Closed);
        record_result(&mut result, ResultClass::Error);
        record_result(&mut result, ResultClass::Rejected);
        assert_eq!(result, ResultClass::Error);
    }
}
