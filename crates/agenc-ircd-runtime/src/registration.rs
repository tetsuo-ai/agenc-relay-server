//! Live client registration and the connection-to-domain session handoff.
//!
//! The wire crate owns the pure registration state machine. This module owns
//! only its external effects: temporary nickname leases, constant-time PASS
//! checks, fresh session identities, the ephemeral domain insertion, and
//! bounded rendering into the connection sink.

use std::collections::{BTreeMap, VecDeque};

use agenc_ircd_client_wire::{
    AccessTokenPolicy, AccountCarrierKind, CapRequestReply, CapabilityProfile, CapabilitySpec,
    CapabilityState, KEEPALIVE_IDLE_MILLIS, KEEPALIVE_PONG_MILLIS, REGISTRATION_TIMEOUT_MILLIS,
    RegistrationAction, RegistrationAuthCarrier, RegistrationCommand, RegistrationError,
    RegistrationEvent, RegistrationPhase, RegistrationState, WelcomeStep, WireMessage,
    isupport_messages, numeric_reply, parse_registration_command, split_capability_lines,
};
use agenc_ircd_crypto::{SemanticHashDomain, semantic_digest};
use agenc_ircd_domain::{DisplayNameValue, NicknameValue, SessionSeed};
use agenc_ircd_types::{Generation, NetworkId, PublicCloak, Revision, ServerId, SessionId, UserId};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::RuntimeError;
pub use crate::account_service::AccountServiceConfig;
use crate::account_service::{AccountServiceCoordinator, CarrierCompletion, CarrierRoute};
use crate::admission::{BucketDemand, BucketKey, BucketKind};
use crate::connection::sink::ConnectionGeneration;
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::inbox::CloseReason;
use crate::state_core::session::BoundSession;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use crate::state_core::{CommandRouter, RouteOutcome, StateCoreContext};

const MAX_PENDING_ACTIONS: usize = 64;
const CAPABILITY_LINE_BYTES: usize = 512;
const CAPABILITY_FIXED_MARGIN: usize = 320;

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
    /// Optional configured connection PASS token.
    pub access_token: Option<Zeroizing<[u8; 32]>>,
    /// Coordinator-only account-service keys and route identity.
    pub account_service: AccountServiceConfig,
}

struct RegistrationRuntimeConfig {
    network_id: NetworkId,
    server_id: ServerId,
    server_prefix: String,
    display_name: String,
    access_token: Option<Zeroizing<[u8; 32]>>,
}

struct NicknameLease {
    generation: u64,
    nickname: NicknameValue,
}

struct ConnectionState {
    registration: RegistrationState,
    lease: Option<NicknameLease>,
    bound: Option<BoundSession>,
    nickname: Option<String>,
    departure_reason: Option<String>,
    deadline: DeadlineState,
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

/// Registration router for every public client connection.
pub struct RegistrationRouter {
    config: RegistrationRuntimeConfig,
    advertised: CapabilityProfile,
    accounts: AccountServiceCoordinator,
    commands: crate::channels::RegisteredCommandExecutor,
    connections: BTreeMap<ConnectionGeneration, ConnectionState>,
    leases: BTreeMap<NicknameValue, ConnectionGeneration>,
    pending_closures: Vec<PendingClosure>,
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
            access_token,
            account_service,
        } = config;
        if account_service.network_id != network_id || account_service.server_id != server_id {
            return Err(RuntimeError::InvalidValue);
        }
        let advertised = core_capabilities()?;
        Ok(Self {
            config: RegistrationRuntimeConfig {
                network_id,
                server_id,
                server_prefix,
                display_name,
                access_token,
            },
            advertised,
            accounts: AccountServiceCoordinator::new(account_service)?,
            commands,
            connections: BTreeMap::new(),
            leases: BTreeMap::new(),
            pending_closures: Vec::new(),
        })
    }

    fn access_policy(&self) -> AccessTokenPolicy {
        if self.config.access_token.is_some() {
            AccessTokenPolicy::RequireConfiguredToken
        } else {
            AccessTokenPolicy::IgnoreCompatibilityPass
        }
    }

    fn route_message(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: agenc_ircd_client_wire::ParsedMessage,
    ) -> RouteOutcome {
        let command = message.command().to_owned();
        let Some(mut state) = self.connections.remove(&generation) else {
            return RouteOutcome::Close(CloseReason::ProtocolError);
        };
        let admission = if state.bound.is_none() {
            charge_preauth(context, generation)
        } else if should_charge_registered_control(&message, self.access_policy()) {
            state
                .bound
                .ok_or(RuntimeError::InvalidValue)
                .and_then(|bound| charge_registered_control(context, bound.user_id))
        } else {
            Ok(())
        };
        if admission.is_err() {
            let outcome = if self
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
            self.refresh_deadline(context, generation, &mut state, outcome);
            self.connections.insert(generation, state);
            return outcome;
        }
        let actions = state
            .registration
            .message(message, context.now().get(), &self.advertised);
        let outcome = match actions {
            Ok(actions) => self.drive_actions(context, generation, &mut state, actions),
            Err(error) => {
                self.render_registration_error(context, generation, &state, &command, error)
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
        let outcome = match actions {
            Ok(actions) => self.drive_actions(context, generation, &mut state, actions),
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
    ) -> RouteOutcome {
        let mut pending: VecDeque<RegistrationAction> = actions.into();
        while let Some(action) = pending.pop_front() {
            if pending.len() >= MAX_PENDING_ACTIONS {
                return RouteOutcome::Close(CloseReason::ProtocolError);
            }
            match self.apply_action(context, generation, state, action) {
                Ok(ActionStep::Continue) => {}
                Ok(ActionStep::FollowUp(actions)) => {
                    if pending.len().saturating_add(actions.len()) > MAX_PENDING_ACTIONS {
                        return RouteOutcome::Close(CloseReason::ProtocolError);
                    }
                    pending.extend(actions);
                }
                Ok(ActionStep::Close(reason)) => return RouteOutcome::Close(reason),
                Err(_) => return RouteOutcome::Close(CloseReason::ProtocolError),
            }
        }
        RouteOutcome::Continue
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=closed registration action dispatcher mirrors the wire state machine
    fn apply_action(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        action: RegistrationAction,
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
                    commit_generation,
                    &nickname,
                    &realname,
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
                let target = self.target(state).to_owned();
                let route = match carrier {
                    RegistrationAuthCarrier::Sasl => self.accounts.route_sasl(
                        context,
                        generation,
                        carrier_generation,
                        &target,
                        message,
                    ),
                    RegistrationAuthCarrier::AccountCreate => self.accounts.route_account(
                        context,
                        generation,
                        carrier_generation,
                        &target,
                        AccountCarrierKind::Create,
                        message,
                    ),
                    RegistrationAuthCarrier::AccountCredentials => self.accounts.route_account(
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
                );
            }
            RegistrationAction::ForwardRegisteredCommand(handoff) => {
                let capabilities = state.registration.capability_state();
                return self
                    .commands
                    .route_registered(
                        context,
                        generation,
                        state.bound,
                        capabilities,
                        &mut state.nickname,
                        handoff,
                    )
                    .map(ActionStep::from);
            }
            RegistrationAction::ResumeDeferredInput(queue) => {
                let mut follow_up = Vec::new();
                for message in queue.into_messages() {
                    follow_up.extend(
                        state
                            .registration
                            .message(message, context.now().get(), &self.advertised)
                            .map_err(|_| RuntimeError::InvalidValue)?,
                    );
                }
                return Ok(ActionStep::FollowUp(follow_up));
            }
            RegistrationAction::InputDeferred => {}
            RegistrationAction::NotRegistered => {
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

    fn reserve_nickname(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
        lease_generation: u64,
        nickname: &str,
    ) -> Result<ActionStep, RuntimeError> {
        let nickname = NicknameValue::parse(nickname).map_err(|_| RuntimeError::InvalidValue)?;
        let domain_taken = context.domain().resolve_nickname(&nickname).is_some()
            || context.domain().nickname_reserved_by(&nickname).is_some();
        let lease_taken = self
            .leases
            .get(&nickname)
            .is_some_and(|owner| *owner != generation);
        let accepted = !domain_taken && !lease_taken;
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

    fn commit_registration(
        &mut self,
        context: &mut StateCoreContext,
        connection: ConnectionGeneration,
        state: &mut ConnectionState,
        event_generation: u64,
        nickname: &str,
        realname: &str,
    ) -> Result<ActionStep, RuntimeError> {
        let authenticated_account = self.accounts.authenticated_binding(connection);
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
        let accepted = self.commit_session(context, connection, bound, capabilities, seed)?;
        if accepted {
            state.bound = Some(bound);
            state.nickname = Some(nickname.to_owned());
            self.release_lease(connection, state);
            self.accounts
                .registration_committed(context, connection, bound.user_id)?;
        }
        self.registration_event(
            context,
            connection,
            state,
            RegistrationEvent::RegistrationCommitted {
                generation: event_generation,
                accepted,
                authenticated: authenticated_account.is_some(),
            },
        )
    }

    fn commit_session(
        &self,
        context: &mut StateCoreContext,
        connection: ConnectionGeneration,
        bound: BoundSession,
        capabilities: CapabilityState,
        seed: SessionSeed,
    ) -> Result<bool, RuntimeError> {
        let Ok(plan) = context.domain().plan_session_opened(seed) else {
            return Ok(false);
        };
        context
            .sessions_mut()
            .bind_session(connection, bound, capabilities)?;
        let request = FanoutRequest::new(Vec::new(), Vec::new())?;
        if context.apply_ephemeral(plan, request).is_err() {
            context.sessions_mut().unbind_session(connection, bound)?;
            return Err(RuntimeError::InvalidValue);
        }
        Ok(true)
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
            generation: Generation::new(0).map_err(|_| RuntimeError::InvalidValue)?,
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
                WelcomeStep::Isupport => frames.extend(
                    isupport_messages(
                        &self.config.server_prefix,
                        target,
                        &self.config.display_name,
                        &self.config.network_id,
                    )
                    .map_err(|_| RuntimeError::InvalidValue)?,
                ),
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
                WelcomeStep::Motd => frames.push(
                    numeric_reply(
                        &self.config.server_prefix,
                        422,
                        target,
                        &[],
                        Some("MOTD File is missing"),
                    )
                    .map_err(|_| RuntimeError::InvalidValue)?,
                ),
                WelcomeStep::RecoveryEpoch
                | WelcomeStep::AccountState
                | WelcomeStep::RegistrationBatches => {}
            }
        }
        Ok(frames)
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
    ) -> Result<ActionStep, RuntimeError> {
        match route {
            CarrierRoute::Finished(frames) => {
                if !frames.is_empty() {
                    context
                        .send_to(generation, frames)
                        .map_err(|_| RuntimeError::MemoryExhausted)?;
                }
                self.registration_event(
                    context,
                    generation,
                    state,
                    RegistrationEvent::AuthCarrierFinished {
                        generation: carrier_generation,
                    },
                )
            }
            CarrierRoute::Pending => Ok(ActionStep::Continue),
            CarrierRoute::Close => Ok(ActionStep::Close(CloseReason::ProtocolError)),
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

    fn apply_account_completions(
        &mut self,
        context: &mut StateCoreContext,
        completions: Vec<CarrierCompletion>,
    ) {
        for completion in completions {
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
            let outcome = match actions {
                Ok(actions) => {
                    self.drive_actions(context, completion.generation, &mut state, actions)
                }
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
    fn route(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        message: agenc_ircd_client_wire::ParsedMessage,
    ) -> RouteOutcome {
        self.route_message(context, generation, message)
    }

    fn connection_opened(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        let now = context.now();
        let deadline = now.checked_add(REGISTRATION_TIMEOUT_MILLIS);
        if let (Ok(registration), Ok(deadline)) = (
            RegistrationState::new(now.get(), self.access_policy()),
            deadline,
        ) {
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
                .connection_opened(context, generation)
                .is_err()
            {
                cancel_connection_timers(context, generation);
                close_transport(context, generation);
                return;
            }
            self.connections.insert(
                generation,
                ConnectionState {
                    registration,
                    lease: None,
                    bound: None,
                    nickname: None,
                    departure_reason: None,
                    deadline: DeadlineState::Registration,
                },
            );
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
        self.accounts.connection_closed(context, generation);
        self.commands.connection_closed(context, generation);
        let Some(mut state) = self.connections.remove(&generation) else {
            return;
        };
        cancel_connection_timers(context, generation);
        let _event = state
            .registration
            .event(RegistrationEvent::TransportClosed, context.now().get());
        self.release_lease(generation, &mut state);
        if let Some(bound) = state.bound {
            let reason = state
                .departure_reason
                .as_deref()
                .unwrap_or("connection closed");
            self.queue_session_close(context, bound, reason);
        }
    }

    fn batch_applied(&mut self, context: &mut StateCoreContext, _plan_count: usize) {
        let completions = self.accounts.batch_applied(context);
        self.apply_account_completions(context, completions);
        self.retry_session_closes(context);
    }

    fn crypto_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
    ) {
        if self.accounts.owns_crypto_job(message.job_id) {
            let completions = self.accounts.crypto_completed(context, message);
            self.apply_account_completions(context, completions);
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
        let completions = self.accounts.storage_read_completed(context, message);
        self.apply_account_completions(context, completions);
    }

    fn batch_rejected(
        &mut self,
        context: &mut StateCoreContext,
        origin: Option<crate::state_core::StagedOrigin>,
        _error: agenc_ircd_storage::StorageError,
    ) {
        let completions = self.accounts.batch_rejected(context, origin);
        self.apply_account_completions(context, completions);
        self.retry_session_closes(context);
    }

    fn timer_fired(&mut self, context: &mut StateCoreContext, entry: TimerEntry) {
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

fn core_capabilities() -> Result<CapabilityProfile, RuntimeError> {
    let mut capabilities = Vec::new();
    for name in [
        "account-notify",
        "account-tag",
        "away-notify",
        "batch",
        "cap-notify",
        "echo-message",
        "labeled-response",
        "message-ids",
        "message-tags",
        "sasl",
        "server-time",
        "setname",
        "standard-replies",
        "utf8only",
    ] {
        let value = (name == "sasl").then_some("AGENC-OPAQUE");
        capabilities
            .push(CapabilitySpec::new(name, value).map_err(|_| RuntimeError::InvalidValue)?);
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

fn cloak_from_random(random: &[u8]) -> Result<PublicCloak, RuntimeError> {
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

#[cfg(test)]
mod tests {
    use agenc_ircd_types::MonotonicTick;

    use super::*;
    use crate::admission::{BucketTable, RateLimits};

    #[test]
    fn core_capabilities_and_cloaks_are_closed() -> Result<(), RuntimeError> {
        let profile = core_capabilities()?;
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
                "labeled-response",
                "message-ids",
                "message-tags",
                "sasl",
                "server-time",
                "setname",
                "standard-replies",
                "utf8only",
            ]
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
        let mut buckets = BucketTable::new(RateLimits::defaults());
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
        let mut buckets = BucketTable::new(RateLimits::defaults());
        let demand = registered_command_demand(user_id)?;
        let now = MonotonicTick::from_ticks(0);
        for _ in 0..20 {
            assert!(buckets.charge_all_or_nothing(now, &[demand]).is_ok());
        }
        assert!(buckets.charge_all_or_nothing(now, &[demand]).is_err());
        Ok(())
    }
}
