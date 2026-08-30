//! Coordinator-owned OPAQUE account-service execution for live SASL clients.
//!
//! The client-wire state machine owns only bounded IRC framing. This module
//! owns the private HPKE/Opaque workflow, the fixed storage lookup schedule,
//! exact request replay, and the durable barrier that makes a response visible
//! only with its transaction/result/session effects.

use std::collections::{BTreeMap, VecDeque};

use agenc_ircd_auth::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES, AccountAuthenticationState,
    AccountCredentialRecord, AccountOperationContext, AccountRouteBinding, AccountServiceEnvelope,
    AccountStartOutcome, AccountTransaction, AuthenticatedAccountRequest, AuthenticationGrant,
    AuthenticationLookup, AuthenticationStart, AuthenticationStartParameters, OpaqueProfile,
    OpaqueRegistrationRecord, OpenedAccountServiceRequest, SealedAccountFinishOutcome,
    SealedAccountStart,
};
use agenc_ircd_client_wire::{
    ParsedMessage, SaslAction, SaslNumeric, SaslTransport, SecretBytes, WireMessage, numeric_reply,
};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, LoginIndexKey, OpaqueFakeCredentialKey, derive_login_index,
};
use agenc_ircd_storage::{
    LIVE_RECORD_KIND, LOGIN_INDEX_KEY_STATE_KEY, LoginIndexKeyState, LoginIndexLazyMigration,
    LoginIndexLookupSchedule, LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind,
    OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue, ProtocolRecordBody, ReadPlan, ReadResult,
    StoredKey, TableId,
};
use agenc_ircd_types::{
    AccountId, AccountServiceMessageKind, ConnectionId, Generation, MonotonicTick, NetworkId,
    NormalizedLogin, OriginId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation,
    TransactionId,
};

use crate::RuntimeError;
use crate::admission::{BucketDemand, BucketKey, BucketKind, LoginHashKey};
use crate::bridge::crypto::{
    AccountOpenJob, CryptoJobOutput, OpaqueFinishJob, OpaqueFinishSealJob, OpaqueStartJob,
    OpaqueStartSealJob, RuntimeCryptoJob,
};
use crate::bridge::{
    CryptoCompletionMessage, CryptoJobId, StorageReadCompletionMessage, StorageReadId,
};
use crate::connection::sink::ConnectionGeneration;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::{StageAccepted, StagedOrigin, StateCoreContext};
use crate::sync::Arc;

const AUTHENTICATION_TRANSACTION_KIND: u16 = 2;
const REQUEST_RESULT_KIND: u16 = 1;
const REQUEST_RESULT_VERSION: u16 = 1;
const REQUEST_RESULT_ROUTE_BYTES: usize = 16 + 8 + 16 + 32;
const REQUEST_RESULT_BYTES: usize = 2
    + REQUEST_RESULT_ROUTE_BYTES
    + 1
    + ACCOUNT_SERVICE_ENVELOPE_BYTES
    + ACCOUNT_SERVICE_RESPONSE_BYTES;
const TERMINAL_START: u8 = 1;
const TERMINAL_ACCEPTED: u8 = 2;
const TERMINAL_REJECTED: u8 = 3;
const MAX_READY_SEALS: usize = 128;

/// Coordinator-only keys and immutable route identity for live account work.
pub struct AccountServiceConfig {
    /// Permanent network identity.
    pub network_id: NetworkId,
    /// Local server authority.
    pub server_id: ServerId,
    /// Current local server incarnation.
    pub server_incarnation: ServerIncarnation,
    /// Federation origin represented by this single-node coordinator.
    pub origin_id: OriginId,
    /// Nonzero origin generation.
    pub origin_generation: Generation,
    /// Current recovery lineage used by HPKE request and response contexts.
    pub recovery_epoch: RecoveryEpoch,
    /// Coordinator-only HPKE recipient private key.
    pub hpke_private_key: Arc<AccountHpkePrivateKey>,
    /// Coordinator-only OPAQUE server setup and stable fake record.
    pub opaque_profile: Arc<OpaqueProfile>,
    /// Current login-index key.
    pub current_login_index_key: Arc<LoginIndexKey>,
    /// Optional previous login-index key during one bounded transition.
    pub previous_login_index_key: Option<Arc<LoginIndexKey>>,
    /// Coordinator-only fake credential-ID key.
    pub fake_credential_key: Arc<OpaqueFakeCredentialKey>,
    /// Authenticated startup key-generation state.
    pub login_index_key_state: LoginIndexKeyState,
}

/// One carrier line either finished synchronously or remains owned by an
/// asynchronous account-service continuation.
pub(crate) enum CarrierRoute {
    Finished(Vec<WireMessage>),
    Pending,
    Close,
}

/// A delayed carrier line whose frames are now visible or whose failure is
/// terminal for the transport.
#[derive(Clone, Copy)]
pub(crate) struct CarrierCompletion {
    pub(crate) generation: ConnectionGeneration,
    pub(crate) carrier_generation: u64,
    pub(crate) close: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RequestTerminal {
    Start,
    Accepted,
    Rejected,
}

impl RequestTerminal {
    const fn tag(self) -> u8 {
        match self {
            Self::Start => TERMINAL_START,
            Self::Accepted => TERMINAL_ACCEPTED,
            Self::Rejected => TERMINAL_REJECTED,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, RuntimeError> {
        match tag {
            TERMINAL_START => Ok(Self::Start),
            TERMINAL_ACCEPTED => Ok(Self::Accepted),
            TERMINAL_REJECTED => Ok(Self::Rejected),
            _ => Err(RuntimeError::InvalidValue),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ConnectionRoute {
    origin_id: OriginId,
    origin_generation: Generation,
    connection_id: ConnectionId,
    connection_nonce: [u8; 32],
}

impl ConnectionRoute {
    fn binding(&self, config: &AccountServiceConfig) -> AccountRouteBinding {
        AccountRouteBinding::new(
            config.server_id,
            config.server_incarnation,
            self.origin_id,
            self.origin_generation,
            self.connection_id,
            self.connection_nonce,
        )
    }
}

struct RequestResultRecord {
    route: ConnectionRoute,
    terminal: RequestTerminal,
    request: [u8; ACCOUNT_SERVICE_ENVELOPE_BYTES],
    response: [u8; ACCOUNT_SERVICE_RESPONSE_BYTES],
}

impl RequestResultRecord {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(REQUEST_RESULT_BYTES);
        encoded.extend_from_slice(&REQUEST_RESULT_VERSION.to_be_bytes());
        encoded.extend_from_slice(self.route.origin_id.as_bytes());
        encoded.extend_from_slice(&self.route.origin_generation.get().to_be_bytes());
        encoded.extend_from_slice(self.route.connection_id.as_bytes());
        encoded.extend_from_slice(&self.route.connection_nonce);
        encoded.push(self.terminal.tag());
        encoded.extend_from_slice(&self.request);
        encoded.extend_from_slice(&self.response);
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, RuntimeError> {
        if encoded.len() != REQUEST_RESULT_BYTES {
            return Err(RuntimeError::InvalidValue);
        }
        let mut cursor = RequestResultCursor::new(encoded);
        if cursor.read_u16()? != REQUEST_RESULT_VERSION {
            return Err(RuntimeError::InvalidValue);
        }
        let origin_id = OriginId::from_bytes(cursor.read_array()?);
        let origin_generation =
            Generation::new(cursor.read_u64()?).map_err(|_| RuntimeError::InvalidValue)?;
        if origin_generation.get() == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        let connection_id = ConnectionId::from_bytes(cursor.read_array()?);
        let connection_nonce = cursor.read_array()?;
        let terminal = RequestTerminal::from_tag(cursor.read_array::<1>()?[0])?;
        let request = cursor.read_array()?;
        let response = cursor.read_array()?;
        cursor.finish()?;
        Ok(Self {
            route: ConnectionRoute {
                origin_id,
                origin_generation,
                connection_id,
                connection_nonce,
            },
            terminal,
            request,
            response,
        })
    }
}

struct RequestResultCursor<'a> {
    encoded: &'a [u8],
    position: usize,
}

impl<'a> RequestResultCursor<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self {
            encoded,
            position: 0,
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], RuntimeError> {
        let end = self.position.checked_add(N).ok_or(RuntimeError::Overflow)?;
        let value = self
            .encoded
            .get(self.position..end)
            .ok_or(RuntimeError::InvalidValue)?
            .try_into()
            .map_err(|_| RuntimeError::InvalidValue)?;
        self.position = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, RuntimeError> {
        self.read_array().map(u16::from_be_bytes)
    }

    fn read_u64(&mut self) -> Result<u64, RuntimeError> {
        self.read_array().map(u64::from_be_bytes)
    }

    fn finish(self) -> Result<(), RuntimeError> {
        if self.position == self.encoded.len() {
            Ok(())
        } else {
            Err(RuntimeError::InvalidValue)
        }
    }
}

struct AuthenticatedBinding {
    account_id: AccountId,
    account_session_generation: Generation,
    authenticated_at: MonotonicTick,
}

struct LiveAuthentication {
    transaction: AccountTransaction<AccountAuthenticationState>,
    login: NormalizedLogin,
    previous_value: Option<LoginIndexValue>,
}

struct AccountConnection {
    sasl: SaslTransport,
    route: ConnectionRoute,
    transaction: Option<LiveAuthentication>,
    authenticated: Option<AuthenticatedBinding>,
}

struct RequestContext {
    generation: ConnectionGeneration,
    carrier_generation: u64,
    target: String,
    route: ConnectionRoute,
    envelope: AccountServiceEnvelope,
    finish: bool,
}

enum PendingRead {
    Replay(RequestContext),
    CurrentIndex {
        request: RequestContext,
        opened: AuthenticatedAccountRequest<AuthenticationStart>,
        login: NormalizedLogin,
        schedule: LoginIndexLookupSchedule,
    },
    PreviousIndex {
        request: RequestContext,
        opened: AuthenticatedAccountRequest<AuthenticationStart>,
        login: NormalizedLogin,
        schedule: LoginIndexLookupSchedule,
        current: Option<LoginIndexValue>,
    },
    OpaqueRecord {
        request: RequestContext,
        opened: AuthenticatedAccountRequest<AuthenticationStart>,
        login: NormalizedLogin,
        current: Option<LoginIndexValue>,
        previous: Option<LoginIndexValue>,
        selected: Option<(AccountId, agenc_ircd_types::OpaqueCredentialId)>,
        record_key: StoredKey,
    },
}

struct OpaqueRecordContinuation {
    request: RequestContext,
    opened: AuthenticatedAccountRequest<AuthenticationStart>,
    login: NormalizedLogin,
    current: Option<LoginIndexValue>,
    previous: Option<LoginIndexValue>,
    selected: Option<(AccountId, agenc_ircd_types::OpaqueCredentialId)>,
    record_key: StoredKey,
}

enum PendingCrypto {
    Open(RequestContext),
    Start {
        request: RequestContext,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    StartSeal {
        request: RequestContext,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    Finish {
        request: RequestContext,
        transaction_id: TransactionId,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
        authenticated_at: MonotonicTick,
    },
    FinishSeal {
        request: RequestContext,
        transaction_id: TransactionId,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
        authenticated_at: MonotonicTick,
    },
}

enum ReadySeal {
    Start {
        request: RequestContext,
        outcome: AccountStartOutcome<AccountAuthenticationState>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    Finish {
        request: RequestContext,
        transaction_id: TransactionId,
        outcome: agenc_ircd_auth::AccountFinishOutcome<AuthenticationGrant>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
        authenticated_at: MonotonicTick,
    },
}

enum ReadyStage {
    Start {
        request: RequestContext,
        sealed: SealedAccountStart<AccountAuthenticationState>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    Finish {
        request: RequestContext,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<AuthenticationGrant>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
        authenticated_at: MonotonicTick,
    },
}

enum PendingAuthority {
    Logout {
        generation: ConnectionGeneration,
        carrier_generation: u64,
    },
    Start {
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountStart<AccountAuthenticationState>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    Finish {
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountFinishOutcome<AuthenticationGrant>,
        authenticated_at: MonotonicTick,
        sasl_accepted: bool,
        fresh_auth_session: Option<(agenc_ircd_types::UserId, Generation, AccountId)>,
        resulting_key_state: Option<LoginIndexKeyState>,
    },
}

/// Live coordinator-side account-service owner.
pub(crate) struct AccountServiceCoordinator {
    config: AccountServiceConfig,
    connections: BTreeMap<ConnectionGeneration, AccountConnection>,
    reads: BTreeMap<StorageReadId, PendingRead>,
    crypto: BTreeMap<CryptoJobId, PendingCrypto>,
    ready_seals: VecDeque<ReadySeal>,
    ready_stage: Option<ReadyStage>,
    pending_authority: Option<PendingAuthority>,
}

impl AccountServiceCoordinator {
    /// Validates immutable configuration and creates an empty live owner.
    pub(crate) fn new(config: AccountServiceConfig) -> Result<Self, RuntimeError> {
        if config.origin_generation.get() == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        if config
            .opaque_profile
            .expose_fake_record_for_persistence()
            .len()
            != agenc_ircd_auth::OPAQUE_REGISTRATION_RECORD_BYTES
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self {
            config,
            connections: BTreeMap::new(),
            reads: BTreeMap::new(),
            crypto: BTreeMap::new(),
            ready_seals: VecDeque::new(),
            ready_stage: None,
            pending_authority: None,
        })
    }

    /// Creates fresh connection and nonce bindings for one admitted transport.
    pub(crate) fn connection_opened(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Result<(), RuntimeError> {
        let mut connection_id_bytes = [0_u8; 16];
        context
            .entropy_mut()
            .fill_exact(&mut connection_id_bytes)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let connection_id = ConnectionId::from_bytes(connection_id_bytes);
        let mut connection_nonce = [0_u8; 32];
        context
            .entropy_mut()
            .fill_exact(&mut connection_nonce)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let state = AccountConnection {
            sasl: SaslTransport::new().map_err(|_| RuntimeError::MemoryExhausted)?,
            route: ConnectionRoute {
                origin_id: self.config.origin_id,
                origin_generation: self.config.origin_generation,
                connection_id,
                connection_nonce,
            },
            transaction: None,
            authenticated: None,
        };
        if self.connections.insert(generation, state).is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }

    /// Erases and cancels every continuation owned by a closed transport.
    pub(crate) fn connection_closed(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        self.connections.remove(&generation);
        let jobs = self
            .crypto
            .iter()
            .filter_map(|(job_id, pending)| (pending.generation() == generation).then_some(*job_id))
            .collect::<Vec<_>>();
        for job_id in jobs {
            self.crypto.remove(&job_id);
            let _cancelled = context.crypto_mut().cancel(job_id);
        }
        self.reads
            .retain(|_, pending| pending.generation() != generation);
        self.ready_seals
            .retain(|pending| pending.generation() != generation);
        if self
            .ready_stage
            .as_ref()
            .is_some_and(|pending| pending.generation() == generation)
        {
            self.ready_stage = None;
        }
        if self
            .pending_authority
            .as_ref()
            .is_some_and(|pending| pending.generation() == generation)
        {
            self.pending_authority = None;
        }
    }

    /// Returns a committed pre-registration account binding without exposing
    /// any request or credential material.
    pub(crate) fn authenticated_binding(
        &self,
        generation: ConnectionGeneration,
    ) -> Option<(AccountId, Generation)> {
        self.connections.get(&generation).and_then(|connection| {
            connection
                .authenticated
                .as_ref()
                .map(|binding| (binding.account_id, binding.account_session_generation))
        })
    }

    /// Applies a fresh-auth proof after registration has inserted a session
    /// that was already authenticated during CAP negotiation.
    pub(crate) fn registration_committed(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        user_id: agenc_ircd_types::UserId,
    ) -> Result<(), RuntimeError> {
        let Some(binding) = self
            .connections
            .get_mut(&generation)
            .and_then(|connection| connection.authenticated.take())
        else {
            return Ok(());
        };
        let session = context
            .domain()
            .session(user_id)
            .ok_or(RuntimeError::InvalidValue)?;
        let plan = context
            .domain()
            .plan_session_fresh_authentication(
                user_id,
                binding.account_id,
                session.generation(),
                binding.authenticated_at,
            )
            .map_err(|_| RuntimeError::InvalidValue)?;
        let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
        context
            .apply_ephemeral(plan, fanout)
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(())
    }

    /// Routes one grammar-validated AUTHENTICATE command.
    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=closed SASL action dispatcher keeps one carrier generation and returns immediately for every authority-moving action
    pub(crate) fn route_sasl(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        target: &str,
        mut message: ParsedMessage,
    ) -> CarrierRoute {
        if message.parameter_count() != 1 {
            return CarrierRoute::Close;
        }
        let Some(parameter) = message.take_parameter(0) else {
            return CarrierRoute::Close;
        };
        let now = context.now().get();
        let Some(connection) = self.connections.get_mut(&generation) else {
            return CarrierRoute::Close;
        };
        let Ok(actions) = connection.sasl.client(&parameter, now) else {
            return CarrierRoute::Close;
        };
        let route = connection.route;
        let mut frames = Vec::new();
        for action in actions {
            match action {
                SaslAction::RequestEnvelope { finish, bytes } => {
                    return self.route_envelope(
                        context,
                        generation,
                        carrier_generation,
                        target,
                        route,
                        finish,
                        bytes,
                    );
                }
                SaslAction::Logout => {
                    return self.route_logout(context, generation, carrier_generation, target);
                }
                action => match render_sasl_action(context.server_prefix(), target, action) {
                    Ok(Some(frame)) => frames.push(frame),
                    Ok(None) => {}
                    Err(_) => return CarrierRoute::Close,
                },
            }
        }
        CarrierRoute::Finished(frames)
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-29 reason=the fixed carrier route tuple is clearer than an intermediate request builder with the same fields
    #[allow(clippy::too_many_arguments)]
    fn route_envelope(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        target: &str,
        route: ConnectionRoute,
        finish: bool,
        bytes: SecretBytes,
    ) -> CarrierRoute {
        let Ok(encoded) = bytes.expose().try_into() else {
            return CarrierRoute::Close;
        };
        let Ok(envelope) = AccountServiceEnvelope::parse(encoded) else {
            return self.fail_route(context, generation, target);
        };
        let expected = if finish {
            AccountServiceMessageKind::OpaqueAuthFinish
        } else {
            AccountServiceMessageKind::OpaqueAuthStart
        };
        if envelope.message_kind() != expected {
            return self.fail_route(context, generation, target);
        }
        let request = RequestContext {
            generation,
            carrier_generation,
            target: target.to_owned(),
            route,
            envelope,
            finish,
        };
        if self.submit_replay_read(context, request).is_err() {
            return CarrierRoute::Close;
        }
        CarrierRoute::Pending
    }

    fn route_logout(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        target: &str,
    ) -> CarrierRoute {
        let bound = context
            .sessions()
            .connection(generation)
            .and_then(|entry| entry.session());
        let Some(bound) = bound else {
            let Some(connection) = self.connections.get_mut(&generation) else {
                return CarrierRoute::Close;
            };
            if connection.authenticated.take().is_none()
                || connection.sasl.complete_logout().is_err()
            {
                return CarrierRoute::Close;
            }
            return CarrierRoute::Finished(Vec::new());
        };
        if self.pending_authority.is_some() {
            return self.reject_logout(context, generation, target);
        }
        let Some(session) = context.domain().session(bound.user_id) else {
            return CarrierRoute::Close;
        };
        if session.account_id().is_none() {
            return CarrierRoute::Close;
        }
        let Ok(plan) =
            context
                .domain()
                .plan_session_account_switch(bound.user_id, session.generation(), None)
        else {
            return self.reject_logout(context, generation, target);
        };
        let Ok(fanout) = crate::mutation_render::render_account_logout(context, bound, &plan)
        else {
            return CarrierRoute::Close;
        };
        match context.stage_durable(plan, fanout, Some(StagedOrigin { generation }), 0) {
            Ok(StageAccepted::Staged { .. }) => {
                self.pending_authority = Some(PendingAuthority::Logout {
                    generation,
                    carrier_generation,
                });
                CarrierRoute::Pending
            }
            Ok(StageAccepted::AppliedInStep(_)) => {
                let Some(connection) = self.connections.get_mut(&generation) else {
                    return CarrierRoute::Close;
                };
                if connection.sasl.complete_logout().is_err() {
                    return CarrierRoute::Close;
                }
                CarrierRoute::Finished(Vec::new())
            }
            Err(_) => self.reject_logout(context, generation, target),
        }
    }

    fn reject_logout(
        &mut self,
        context: &StateCoreContext,
        generation: ConnectionGeneration,
        target: &str,
    ) -> CarrierRoute {
        let Some(connection) = self.connections.get_mut(&generation) else {
            return CarrierRoute::Close;
        };
        let Ok(actions) = connection.sasl.reject_logout() else {
            return CarrierRoute::Close;
        };
        match render_sasl_actions(context.server_prefix(), target, actions) {
            Ok(frames) => CarrierRoute::Finished(frames),
            Err(_) => CarrierRoute::Close,
        }
    }

    fn fail_route(
        &mut self,
        context: &StateCoreContext,
        generation: ConnectionGeneration,
        target: &str,
    ) -> CarrierRoute {
        let Some(connection) = self.connections.get_mut(&generation) else {
            return CarrierRoute::Close;
        };
        let Ok(actions) = connection.sasl.unavailable(context.now().get()) else {
            return CarrierRoute::Close;
        };
        match render_sasl_actions(context.server_prefix(), target, actions) {
            Ok(frames) => CarrierRoute::Finished(frames),
            Err(_) => CarrierRoute::Close,
        }
    }

    fn submit_replay_read(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
    ) -> Result<(), RuntimeError> {
        let key = request_result_key(request.envelope.client_request_id())?;
        let read_id = context.submit_storage_read(ReadPlan::exact(TableId::RequestResult, key))?;
        if self
            .reads
            .insert(read_id, PendingRead::Replay(request))
            .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }

    /// Returns whether one crypto completion belongs to this coordinator.
    #[must_use]
    pub(crate) fn owns_crypto_job(&self, job_id: CryptoJobId) -> bool {
        self.crypto.contains_key(&job_id)
    }

    /// Resumes one account-service crypto job.
    pub(crate) fn crypto_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: CryptoCompletionMessage<CryptoJobOutput>,
    ) -> Vec<CarrierCompletion> {
        let Some(pending) = self.crypto.remove(&message.job_id) else {
            return Vec::new();
        };
        let generation = pending.generation();
        let Ok(output) = message.output else {
            return vec![self.close_completion(&pending)];
        };
        let result = self.apply_crypto_output(context, pending, output);
        match result {
            Ok(mut completions) => {
                completions.extend(self.progress(context));
                completions
            }
            Err(_) => vec![CarrierCompletion {
                generation,
                carrier_generation: 0,
                close: true,
            }],
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=closed pending-job/output pairing rejects every cross-kind completion before authority moves
    fn apply_crypto_output(
        &mut self,
        context: &mut StateCoreContext,
        pending: PendingCrypto,
        output: CryptoJobOutput,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        match (pending, output) {
            (PendingCrypto::Open(request), CryptoJobOutput::AccountOpen(output)) => {
                self.open_completed(context, request, *output)
            }
            (
                PendingCrypto::Start {
                    request,
                    login,
                    previous_value,
                },
                CryptoJobOutput::OpaqueStart(output),
            ) => {
                let outcome = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                self.push_ready_seal(ReadySeal::Start {
                    request,
                    outcome,
                    login,
                    previous_value,
                })?;
                Ok(Vec::new())
            }
            (
                PendingCrypto::StartSeal {
                    request,
                    login,
                    previous_value,
                },
                CryptoJobOutput::OpaqueStartSealed(output),
            ) => {
                let sealed = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                if self.ready_stage.is_some() {
                    return Err(RuntimeError::InvalidValue);
                }
                self.ready_stage = Some(ReadyStage::Start {
                    request,
                    sealed,
                    login,
                    previous_value,
                });
                Ok(Vec::new())
            }
            (
                PendingCrypto::Finish {
                    request,
                    transaction_id,
                    login,
                    previous_value,
                    authenticated_at,
                },
                CryptoJobOutput::OpaqueFinish(output),
            ) => {
                let outcome = output.outcome.map_err(|_| RuntimeError::InvalidValue)?;
                self.push_ready_seal(ReadySeal::Finish {
                    request,
                    transaction_id,
                    outcome,
                    login,
                    previous_value,
                    authenticated_at,
                })?;
                Ok(Vec::new())
            }
            (
                PendingCrypto::FinishSeal {
                    request,
                    transaction_id,
                    login,
                    previous_value,
                    authenticated_at,
                },
                CryptoJobOutput::OpaqueFinishSealed(output),
            ) => {
                let sealed = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                if self.ready_stage.is_some() {
                    return Err(RuntimeError::InvalidValue);
                }
                self.ready_stage = Some(ReadyStage::Finish {
                    request,
                    transaction_id,
                    sealed,
                    login,
                    previous_value,
                    authenticated_at,
                });
                Ok(Vec::new())
            }
            _ => Err(RuntimeError::InvalidValue),
        }
    }

    fn open_completed(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: Result<OpenedAccountServiceRequest, agenc_ircd_auth::AuthError>,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let Ok(opened) = opened else {
            return self.fail_pending(context, request);
        };
        match opened {
            OpenedAccountServiceRequest::AuthenticationStart(opened) if !request.finish => {
                let login = NormalizedLogin::prepare(opened.payload().login.as_str())
                    .map_err(|_| RuntimeError::InvalidValue)?;
                if self.charge_opaque_attempt(context, &login).is_err() {
                    return self.fail_pending(context, request);
                }
                let schedule = LoginIndexLookupSchedule::new(
                    self.config.network_id,
                    &login,
                    self.config.login_index_key_state,
                    &self.config.current_login_index_key,
                    self.config.previous_login_index_key.as_deref(),
                )?;
                let key = schedule.current().encode()?;
                let read_id =
                    context.submit_storage_read(ReadPlan::exact(TableId::LoginIndex, key))?;
                if self
                    .reads
                    .insert(
                        read_id,
                        PendingRead::CurrentIndex {
                            request,
                            opened,
                            login,
                            schedule,
                        },
                    )
                    .is_some()
                {
                    return Err(RuntimeError::InvalidValue);
                }
                Ok(Vec::new())
            }
            OpenedAccountServiceRequest::AuthenticationFinish(opened) if request.finish => {
                let transaction_id = opened.payload().transaction_id;
                let Some(live) = self
                    .connections
                    .get_mut(&request.generation)
                    .and_then(|connection| connection.transaction.take())
                else {
                    return self.fail_pending(context, request);
                };
                let operation = self.operation_context(context, request.route)?;
                let job = RuntimeCryptoJob::OpaqueFinish(Box::new(OpaqueFinishJob::new(
                    live.transaction,
                    operation,
                    opened,
                )));
                let pending = PendingCrypto::Finish {
                    request,
                    transaction_id,
                    login: live.login,
                    previous_value: live.previous_value,
                    authenticated_at: context.now(),
                };
                self.submit_crypto(context, pending, job)?;
                Ok(Vec::new())
            }
            _ => self.fail_pending(context, request),
        }
    }

    fn charge_opaque_attempt(
        &self,
        context: &mut StateCoreContext,
        login: &NormalizedLogin,
    ) -> Result<(), RuntimeError> {
        let demand = opaque_attempt_demand(
            &self.config.current_login_index_key,
            self.config.network_id,
            login,
        )?;
        let now = context.now();
        context
            .buckets_mut()
            .charge_all_or_nothing(now, &[demand])
            .map_err(|_| RuntimeError::LimitExceeded)
    }

    fn operation_context(
        &self,
        context: &StateCoreContext,
        route: ConnectionRoute,
    ) -> Result<AccountOperationContext, RuntimeError> {
        let now_utc = context.utc_now().map_err(|_| RuntimeError::InvalidValue)?;
        Ok(AccountOperationContext::new(
            self.config.network_id,
            route.binding(&self.config),
            context.now(),
            now_utc,
        ))
    }

    fn submit_crypto(
        &mut self,
        context: &mut StateCoreContext,
        pending: PendingCrypto,
        job: RuntimeCryptoJob,
    ) -> Result<(), RuntimeError> {
        let job_id = context
            .crypto_mut()
            .try_submit(job)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        if self.crypto.insert(job_id, pending).is_some() {
            let _cancelled = context.crypto_mut().cancel(job_id);
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }

    fn push_ready_seal(&mut self, ready: ReadySeal) -> Result<(), RuntimeError> {
        if self.ready_seals.len() >= MAX_READY_SEALS {
            return Err(RuntimeError::LimitExceeded);
        }
        self.ready_seals.push_back(ready);
        Ok(())
    }

    /// Resumes one exact storage lookup.
    pub(crate) fn storage_read_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: StorageReadCompletionMessage,
    ) -> Vec<CarrierCompletion> {
        let Some(pending) = self.reads.remove(&message.read_id) else {
            return Vec::new();
        };
        let close = CarrierCompletion {
            generation: pending.generation(),
            carrier_generation: pending.carrier_generation(),
            close: true,
        };
        let result = match message.result {
            Ok(result) => self.apply_read_result(context, pending, result),
            Err(_) => Err(RuntimeError::InvalidValue),
        };
        match result {
            Ok(mut completions) => {
                completions.extend(self.progress(context));
                completions
            }
            Err(_) => vec![close],
        }
    }

    fn apply_read_result(
        &mut self,
        context: &mut StateCoreContext,
        pending: PendingRead,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        match pending {
            PendingRead::Replay(request) => self.replay_read(context, request, result),
            PendingRead::CurrentIndex {
                request,
                opened,
                login,
                schedule,
            } => self.current_index_read(context, request, opened, login, schedule, result),
            PendingRead::PreviousIndex {
                request,
                opened,
                login,
                schedule,
                current,
            } => {
                self.previous_index_read(context, request, opened, login, schedule, current, result)
            }
            PendingRead::OpaqueRecord {
                request,
                opened,
                login,
                current,
                previous,
                selected,
                record_key,
            } => self.opaque_record_read(
                context,
                OpaqueRecordContinuation {
                    request,
                    opened,
                    login,
                    current,
                    previous,
                    selected,
                    record_key,
                },
                result,
            ),
        }
    }

    fn current_index_read(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<AuthenticationStart>,
        login: NormalizedLogin,
        schedule: LoginIndexLookupSchedule,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let current = read_login_index(context, result, schedule.current())?;
        let key = schedule.previous_or_dummy().encode()?;
        let read_id = context.submit_storage_read(ReadPlan::exact(TableId::LoginIndex, key))?;
        if self
            .reads
            .insert(
                read_id,
                PendingRead::PreviousIndex {
                    request,
                    opened,
                    login,
                    schedule,
                    current,
                },
            )
            .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Vec::new())
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-29 reason=the fixed lookup continuation carries the complete current and previous schedule state explicitly
    #[allow(clippy::too_many_arguments)]
    fn previous_index_read(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<AuthenticationStart>,
        login: NormalizedLogin,
        schedule: LoginIndexLookupSchedule,
        current: Option<LoginIndexValue>,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let previous_lookup = read_login_index(context, result, schedule.previous_or_dummy())?;
        let previous = schedule
            .is_transition()
            .then_some(previous_lookup)
            .flatten();
        let selected = select_live_login(&current, &previous)?;
        let record_key = match selected {
            Some((account_id, _)) => StoredKey::new(account_id.to_text().into_bytes())?,
            None => StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
        };
        let read_id = context
            .submit_storage_read(ReadPlan::exact(TableId::OpaqueRecord, record_key.clone()))?;
        if self
            .reads
            .insert(
                read_id,
                PendingRead::OpaqueRecord {
                    request,
                    opened,
                    login,
                    current,
                    previous,
                    selected,
                    record_key,
                },
            )
            .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Vec::new())
    }

    fn opaque_record_read(
        &mut self,
        context: &mut StateCoreContext,
        continuation: OpaqueRecordContinuation,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let OpaqueRecordContinuation {
            request,
            opened,
            login,
            current,
            previous,
            selected,
            record_key,
        } = continuation;
        let value = read_required_persistent(context, result, TableId::OpaqueRecord, &record_key)?;
        let (lookup, previous_value) =
            self.authentication_lookup(context, &login, current, previous, selected, &value)?;
        let parameters = AuthenticationStartParameters {
            context: self.operation_context(context, request.route)?,
            request: opened,
            lookup,
        };
        let job = RuntimeCryptoJob::OpaqueStart(Box::new(OpaqueStartJob::new(
            Arc::clone(&self.config.opaque_profile),
            Arc::clone(&self.config.current_login_index_key),
            Arc::clone(&self.config.fake_credential_key),
            parameters,
        )));
        let pending = PendingCrypto::Start {
            request,
            login,
            previous_value,
        };
        self.submit_crypto(context, pending, job)?;
        Ok(Vec::new())
    }

    fn authentication_lookup(
        &self,
        context: &StateCoreContext,
        login: &NormalizedLogin,
        current: Option<LoginIndexValue>,
        previous: Option<LoginIndexValue>,
        selected: Option<(AccountId, agenc_ircd_types::OpaqueCredentialId)>,
        value: &PersistentRecordValue,
    ) -> Result<(AuthenticationLookup, Option<LoginIndexValue>), RuntimeError> {
        let record_bytes: [u8; agenc_ircd_auth::OPAQUE_REGISTRATION_RECORD_BYTES] = value
            .body()
            .try_into()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let Some((account_id, credential_id)) = selected else {
            if value.record_kind() != LIVE_RECORD_KIND
                || value.body()
                    != self
                        .config
                        .opaque_profile
                        .expose_fake_record_for_persistence()
            {
                return Err(RuntimeError::InvalidValue);
            }
            let _validated = OpaqueRegistrationRecord::from_bytes(record_bytes)
                .map_err(|_| RuntimeError::InvalidValue)?;
            return Ok((AuthenticationLookup::Unknown, None));
        };
        let account = context
            .domain()
            .account(account_id)
            .ok_or(RuntimeError::InvalidValue)?;
        if value.record_kind() != LIVE_RECORD_KIND
            || value.revision() != account.revision().get()
            || value.generation() != account.session_generation().get()
        {
            return Err(RuntimeError::InvalidValue);
        }
        let digest = derive_login_index(
            &self.config.current_login_index_key,
            self.config.network_id,
            login,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let record = OpaqueRegistrationRecord::from_bytes(record_bytes)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let credential = AccountCredentialRecord::new(
            account_id,
            account.revision(),
            account.session_generation(),
            digest,
            credential_id,
            record,
        );
        let previous_value = if current
            .as_ref()
            .is_some_and(|value| matches!(value.kind(), LoginIndexValueKind::Live { .. }))
        {
            None
        } else {
            previous
        };
        Ok((
            AuthenticationLookup::Known(Box::new(credential)),
            previous_value,
        ))
    }

    fn replay_read(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let key = request_result_key(request.envelope.client_request_id())?;
        let Some(value) = read_optional_persistent(context, result, TableId::RequestResult, &key)?
        else {
            let job_envelope = AccountServiceEnvelope::parse(*request.envelope.as_bytes())
                .map_err(|_| RuntimeError::InvalidValue)?;
            let job = RuntimeCryptoJob::AccountOpen(Box::new(AccountOpenJob::new(
                Arc::clone(&self.config.hpke_private_key),
                self.config.recovery_epoch,
                self.config.network_id,
                request.envelope.message_kind(),
                job_envelope,
            )));
            self.submit_crypto(context, PendingCrypto::Open(request), job)?;
            return Ok(Vec::new());
        };
        if value.record_kind() != REQUEST_RESULT_KIND {
            return Err(RuntimeError::InvalidValue);
        }
        let protocol =
            ProtocolRecordBody::decode(TableId::RequestResult, REQUEST_RESULT_KIND, value.body())?;
        let stored = RequestResultRecord::decode(protocol.canonical_object())?;
        if stored.route != request.route || stored.request != *request.envelope.as_bytes() {
            return Err(RuntimeError::InvalidValue);
        }
        let expected_terminal = if request.finish {
            matches!(
                stored.terminal,
                RequestTerminal::Accepted | RequestTerminal::Rejected
            )
        } else {
            stored.terminal == RequestTerminal::Start
        };
        if !expected_terminal {
            return Err(RuntimeError::InvalidValue);
        }
        let response = agenc_ircd_auth::AccountServiceResponse::parse(stored.response)
            .map_err(|_| RuntimeError::InvalidValue)?;
        if response.client_request_id() != request.envelope.client_request_id() {
            return Err(RuntimeError::InvalidValue);
        }
        let frames = self.response_frames(
            context,
            request.generation,
            &request.target,
            response.as_bytes(),
            request.finish,
            stored.terminal == RequestTerminal::Accepted,
        )?;
        context
            .send_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(vec![CarrierCompletion {
            generation: request.generation,
            carrier_generation: request.carrier_generation,
            close: false,
        }])
    }

    fn progress(&mut self, context: &mut StateCoreContext) -> Vec<CarrierCompletion> {
        let mut completions = Vec::new();
        if self.pending_authority.is_none()
            && self.ready_stage.is_some()
            && context.pending_len() == 0
            && let Err(completion) = self.stage_ready(context)
        {
            completions.push(completion);
        }
        if self.pending_authority.is_none()
            && self.ready_stage.is_none()
            && !self.has_seal_job()
            && let Some(ready) = self.ready_seals.pop_front()
            && let Err(completion) = self.begin_seal(context, ready)
        {
            completions.push(completion);
        }
        completions
    }

    fn has_seal_job(&self) -> bool {
        self.crypto.values().any(|pending| {
            matches!(
                pending,
                PendingCrypto::StartSeal { .. } | PendingCrypto::FinishSeal { .. }
            )
        })
    }

    fn begin_seal(
        &mut self,
        context: &mut StateCoreContext,
        ready: ReadySeal,
    ) -> Result<(), CarrierCompletion> {
        let response_count = context.head().account_service_response_count;
        let (pending, job) = match ready {
            ReadySeal::Start {
                request,
                outcome,
                login,
                previous_value,
            } => (
                PendingCrypto::StartSeal {
                    request,
                    login,
                    previous_value,
                },
                RuntimeCryptoJob::OpaqueStartSeal(Box::new(OpaqueStartSealJob::new(
                    outcome,
                    response_count,
                ))),
            ),
            ReadySeal::Finish {
                request,
                transaction_id,
                outcome,
                login,
                previous_value,
                authenticated_at,
            } => (
                PendingCrypto::FinishSeal {
                    request,
                    transaction_id,
                    login,
                    previous_value,
                    authenticated_at,
                },
                RuntimeCryptoJob::OpaqueFinishSeal(Box::new(OpaqueFinishSealJob::new(
                    outcome,
                    response_count,
                ))),
            ),
        };
        let completion = CarrierCompletion {
            generation: pending.generation(),
            carrier_generation: pending.carrier_generation(),
            close: true,
        };
        self.submit_crypto(context, pending, job)
            .map_err(|_| completion)
    }

    fn stage_ready(&mut self, context: &mut StateCoreContext) -> Result<(), CarrierCompletion> {
        let ready = self.ready_stage.take().ok_or(CarrierCompletion {
            generation: ConnectionGeneration::new(0),
            carrier_generation: 0,
            close: true,
        })?;
        let completion = CarrierCompletion {
            generation: ready.generation(),
            carrier_generation: ready.carrier_generation(),
            close: true,
        };
        let staged = match ready {
            ReadyStage::Start {
                request,
                sealed,
                login,
                previous_value,
            } => self.stage_start(context, request, sealed, login, previous_value),
            ReadyStage::Finish {
                request,
                transaction_id,
                sealed,
                login,
                previous_value,
                authenticated_at,
            } => self.stage_finish(
                context,
                request,
                transaction_id,
                sealed,
                login,
                previous_value,
                authenticated_at,
            ),
        };
        staged.map_err(|_| completion)
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=one authentication-start atomic set constructs transaction result fanout and response-count authority before staging once
    fn stage_start(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        sealed: SealedAccountStart<AccountAuthenticationState>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    ) -> Result<(), RuntimeError> {
        let now = context.now();
        let now_utc = context.utc_now().map_err(|_| RuntimeError::InvalidValue)?;
        let transaction_record = sealed
            .authentication_transaction_record(now, now_utc)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let plan = context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let revision = plan.resulting_revision().get();
        let response = sealed.response_intent().response().as_bytes();
        let result_write =
            request_result_write(revision, &request, RequestTerminal::Start, response)?;
        let transaction_value = PersistentRecordValue::new(
            TableId::AuthTransaction,
            AUTHENTICATION_TRANSACTION_KIND,
            revision,
            0,
            Some(
                transaction_record
                    .durable_expires_at_utc()
                    .map_err(|_| RuntimeError::InvalidValue)?
                    .get(),
            ),
            Vec::new(),
            transaction_record.expose_for_persistence().to_vec(),
        )?;
        let transaction_write = AccountServiceDurableWrite::put(
            TableId::AuthTransaction,
            StoredKey::new(sealed.transaction_id().as_bytes().to_vec())?,
            transaction_value.encode()?,
        )?;
        let frames = self.response_frames(
            context,
            request.generation,
            &request.target,
            response,
            false,
            false,
        )?;
        let fanout = context
            .fanout_request_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let next = sealed.response_intent().next_response_count();
        let accepted = context.stage_durable_with_account_service(
            plan,
            fanout,
            Some(StagedOrigin {
                generation: request.generation,
            }),
            1,
            vec![transaction_write, result_write],
        );
        if !matches!(accepted, Ok(StageAccepted::Staged { .. }))
            || next
                != context
                    .head()
                    .account_service_response_count
                    .saturating_add(1)
        {
            return Err(RuntimeError::InvalidValue);
        }
        self.pending_authority = Some(PendingAuthority::Start {
            generation: request.generation,
            carrier_generation: request.carrier_generation,
            sealed,
            login,
            previous_value,
        });
        Ok(())
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-29 reason=the finish continuation keeps every consumed authority and migration input explicit at the durable barrier
    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=one authentication-finish atomic set binds the domain plan transaction deletion replay result optional migration response and postcommit authority
    #[allow(clippy::too_many_arguments)]
    fn stage_finish(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<AuthenticationGrant>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
        authenticated_at: MonotonicTick,
    ) -> Result<(), RuntimeError> {
        let semantic_grant = sealed.result().ok();
        let bound = context
            .sessions()
            .connection(request.generation)
            .and_then(|entry| entry.session());
        let mut fresh_auth_session = None;
        let mut sasl_accepted = semantic_grant.is_some();
        let plan = match (semantic_grant, bound) {
            (Some(grant), Some(bound)) => {
                let session = context
                    .domain()
                    .session(bound.user_id)
                    .ok_or(RuntimeError::InvalidValue)?;
                match session.account_id() {
                    None => {
                        let resulting_generation = session
                            .generation()
                            .checked_add(1)
                            .map_err(|_| RuntimeError::Overflow)?;
                        fresh_auth_session =
                            Some((bound.user_id, resulting_generation, grant.account_id()));
                        context
                            .domain()
                            .plan_session_account_switch(
                                bound.user_id,
                                session.generation(),
                                Some((grant.account_id(), grant.account_session_generation())),
                            )
                            .map_err(|_| RuntimeError::InvalidValue)?
                    }
                    Some(account_id) if account_id == grant.account_id() => {
                        fresh_auth_session =
                            Some((bound.user_id, session.generation(), account_id));
                        context
                            .domain()
                            .plan_account_service_checkpoint()
                            .map_err(|_| RuntimeError::InvalidValue)?
                    }
                    Some(_) => {
                        sasl_accepted = false;
                        context
                            .domain()
                            .plan_account_service_checkpoint()
                            .map_err(|_| RuntimeError::InvalidValue)?
                    }
                }
            }
            _ => context
                .domain()
                .plan_account_service_checkpoint()
                .map_err(|_| RuntimeError::InvalidValue)?,
        };
        let revision = plan.resulting_revision().get();
        let terminal = if sasl_accepted {
            RequestTerminal::Accepted
        } else {
            RequestTerminal::Rejected
        };
        let response = sealed.response_intent().response().as_bytes();
        let mut writes = vec![
            AccountServiceDurableWrite::delete(
                TableId::AuthTransaction,
                StoredKey::new(transaction_id.as_bytes().to_vec())?,
            )?,
            request_result_write(revision, &request, terminal, response)?,
        ];
        let resulting_key_state = if let (Some(grant), Some(previous_value)) =
            (semantic_grant, previous_value.as_ref())
        {
            let previous_key = self
                .config
                .previous_login_index_key
                .as_deref()
                .ok_or(RuntimeError::InvalidValue)?;
            let migration = LoginIndexLazyMigration::new(
                self.config.network_id,
                &login,
                self.config.login_index_key_state,
                &self.config.current_login_index_key,
                previous_key,
                grant.account_id(),
                credential_id(previous_value)?,
                previous_value,
            )?;
            writes.push(AccountServiceDurableWrite::delete(
                TableId::LoginIndex,
                migration.previous_key().clone(),
            )?);
            writes.push(AccountServiceDurableWrite::put(
                TableId::LoginIndex,
                migration.current_key().clone(),
                migration.current_value().encode()?,
            )?);
            writes.push(AccountServiceDurableWrite::put(
                TableId::LoginIndexKeyState,
                StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
                migration.resulting_key_state().encode()?,
            )?);
            Some(migration.resulting_key_state())
        } else {
            None
        };
        let frames = self.response_frames(
            context,
            request.generation,
            &request.target,
            response,
            true,
            sasl_accepted,
        )?;
        let fanout = context
            .fanout_request_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let next = sealed.response_intent().next_response_count();
        let accepted = context.stage_durable_with_account_service(
            plan,
            fanout,
            Some(StagedOrigin {
                generation: request.generation,
            }),
            1,
            writes,
        );
        if !matches!(accepted, Ok(StageAccepted::Staged { .. }))
            || next
                != context
                    .head()
                    .account_service_response_count
                    .saturating_add(1)
        {
            return Err(RuntimeError::InvalidValue);
        }
        self.pending_authority = Some(PendingAuthority::Finish {
            generation: request.generation,
            carrier_generation: request.carrier_generation,
            sealed,
            authenticated_at,
            sasl_accepted,
            fresh_auth_session,
            resulting_key_state,
        });
        Ok(())
    }

    fn response_frames(
        &mut self,
        context: &StateCoreContext,
        generation: ConnectionGeneration,
        target: &str,
        response: &[u8],
        finish: bool,
        accepted: bool,
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        let connection = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        let mut actions = connection
            .sasl
            .server_response(response, context.now().get())
            .map_err(|_| RuntimeError::InvalidValue)?;
        if finish {
            actions.extend(
                connection
                    .sasl
                    .complete(accepted, context.now().get())
                    .map_err(|_| RuntimeError::InvalidValue)?,
            );
        }
        render_sasl_actions(context.server_prefix(), target, actions)
    }

    fn fail_pending(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let route = self.fail_route(context, request.generation, &request.target);
        let CarrierRoute::Finished(frames) = route else {
            return Err(RuntimeError::InvalidValue);
        };
        context
            .send_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(vec![CarrierCompletion {
            generation: request.generation,
            carrier_generation: request.carrier_generation,
            close: false,
        }])
    }

    fn close_completion(&self, pending: &PendingCrypto) -> CarrierCompletion {
        CarrierCompletion {
            generation: pending.generation(),
            carrier_generation: pending.carrier_generation(),
            close: true,
        }
    }

    fn commit_logout(
        &mut self,
        generation: ConnectionGeneration,
        carrier_generation: u64,
    ) -> CarrierCompletion {
        let close = self
            .connections
            .get_mut(&generation)
            .is_none_or(|connection| connection.sasl.complete_logout().is_err());
        CarrierCompletion {
            generation,
            carrier_generation,
            close,
        }
    }

    fn commit_start(
        &mut self,
        committed_count: u64,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountStart<AccountAuthenticationState>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    ) -> Option<CarrierCompletion> {
        let Ok(transaction) = sealed.into_transaction_after_commit(committed_count) else {
            return Some(CarrierCompletion {
                generation,
                carrier_generation,
                close: true,
            });
        };
        let connection = self.connections.get_mut(&generation)?;
        connection.transaction = Some(LiveAuthentication {
            transaction,
            login,
            previous_value,
        });
        Some(CarrierCompletion {
            generation,
            carrier_generation,
            close: false,
        })
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-29 reason=the postcommit finish authority carries every independently fenced session and key-transition result explicitly
    #[allow(clippy::too_many_arguments)]
    fn commit_finish(
        &mut self,
        context: &mut StateCoreContext,
        committed_count: u64,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountFinishOutcome<AuthenticationGrant>,
        authenticated_at: MonotonicTick,
        sasl_accepted: bool,
        fresh_auth_session: Option<(agenc_ircd_types::UserId, Generation, AccountId)>,
        resulting_key_state: Option<LoginIndexKeyState>,
    ) -> CarrierCompletion {
        let Ok(result) = sealed.into_result_after_commit(committed_count) else {
            return CarrierCompletion {
                generation,
                carrier_generation,
                close: true,
            };
        };
        if let Some(key_state) = resulting_key_state {
            self.config.login_index_key_state = key_state;
        }
        let close = match result {
            Ok(grant) if sasl_accepted => self.install_committed_grant(
                context,
                generation,
                &grant,
                authenticated_at,
                fresh_auth_session,
            ),
            _ => false,
        };
        CarrierCompletion {
            generation,
            carrier_generation,
            close,
        }
    }

    fn install_committed_grant(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        grant: &AuthenticationGrant,
        authenticated_at: MonotonicTick,
        fresh_auth_session: Option<(agenc_ircd_types::UserId, Generation, AccountId)>,
    ) -> bool {
        if let Some((user_id, session_generation, account_id)) = fresh_auth_session {
            let applied = context
                .domain()
                .plan_session_fresh_authentication(
                    user_id,
                    account_id,
                    session_generation,
                    authenticated_at,
                )
                .ok()
                .and_then(|plan| {
                    FanoutRequest::new(Vec::new(), Vec::new())
                        .ok()
                        .and_then(|fanout| context.apply_ephemeral(plan, fanout).ok())
                });
            return applied.is_none();
        }
        let preregistered = context
            .sessions()
            .connection(generation)
            .is_some_and(|entry| entry.session().is_none());
        if preregistered && let Some(connection) = self.connections.get_mut(&generation) {
            connection.authenticated = Some(AuthenticatedBinding {
                account_id: grant.account_id(),
                account_session_generation: grant.account_session_generation(),
                authenticated_at,
            });
        }
        false
    }

    /// Releases sealed transaction/result authority only after the matching
    /// durable head became visible.
    pub(crate) fn batch_applied(
        &mut self,
        context: &mut StateCoreContext,
    ) -> Vec<CarrierCompletion> {
        let mut completions = Vec::new();
        let Some(authority) = self.pending_authority.take() else {
            return self.progress(context);
        };
        let committed_count = context.head().account_service_response_count;
        let completion = match authority {
            PendingAuthority::Logout {
                generation,
                carrier_generation,
            } => Some(self.commit_logout(generation, carrier_generation)),
            PendingAuthority::Start {
                generation,
                carrier_generation,
                sealed,
                login,
                previous_value,
            } => self.commit_start(
                committed_count,
                generation,
                carrier_generation,
                sealed,
                login,
                previous_value,
            ),
            PendingAuthority::Finish {
                generation,
                carrier_generation,
                sealed,
                authenticated_at,
                sasl_accepted,
                fresh_auth_session,
                resulting_key_state,
            } => Some(self.commit_finish(
                context,
                committed_count,
                generation,
                carrier_generation,
                sealed,
                authenticated_at,
                sasl_accepted,
                fresh_auth_session,
                resulting_key_state,
            )),
        };
        if let Some(completion) = completion {
            completions.push(completion);
        }
        completions.extend(self.progress(context));
        completions
    }

    /// Drops authority after a determinate batch rejection and closes its
    /// originating transport; a sealed response is never retried after its
    /// fanout reservation was discarded.
    pub(crate) fn batch_rejected(
        &mut self,
        context: &mut StateCoreContext,
        origin: Option<StagedOrigin>,
    ) -> Vec<CarrierCompletion> {
        let Some(authority) = self.pending_authority.take() else {
            return self.progress(context);
        };
        let generation = authority.generation();
        let carrier_generation = authority.carrier_generation();
        let mut completions = vec![CarrierCompletion {
            generation,
            carrier_generation,
            close: true,
        }];
        if origin.is_some_and(|origin| origin.generation != generation) {
            completions.push(CarrierCompletion {
                generation: origin.map_or(generation, |origin| origin.generation),
                carrier_generation: 0,
                close: true,
            });
        }
        completions.extend(self.progress(context));
        completions
    }
}

impl PendingRead {
    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::Replay(request)
            | Self::CurrentIndex { request, .. }
            | Self::PreviousIndex { request, .. }
            | Self::OpaqueRecord { request, .. } => request.generation,
        }
    }

    const fn carrier_generation(&self) -> u64 {
        match self {
            Self::Replay(request)
            | Self::CurrentIndex { request, .. }
            | Self::PreviousIndex { request, .. }
            | Self::OpaqueRecord { request, .. } => request.carrier_generation,
        }
    }
}

impl PendingCrypto {
    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::Open(request)
            | Self::Start { request, .. }
            | Self::StartSeal { request, .. }
            | Self::Finish { request, .. }
            | Self::FinishSeal { request, .. } => request.generation,
        }
    }

    const fn carrier_generation(&self) -> u64 {
        match self {
            Self::Open(request)
            | Self::Start { request, .. }
            | Self::StartSeal { request, .. }
            | Self::Finish { request, .. }
            | Self::FinishSeal { request, .. } => request.carrier_generation,
        }
    }
}

impl ReadySeal {
    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::Start { request, .. } | Self::Finish { request, .. } => request.generation,
        }
    }
}

impl ReadyStage {
    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::Start { request, .. } | Self::Finish { request, .. } => request.generation,
        }
    }

    const fn carrier_generation(&self) -> u64 {
        match self {
            Self::Start { request, .. } | Self::Finish { request, .. } => {
                request.carrier_generation
            }
        }
    }
}

impl PendingAuthority {
    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::Logout { generation, .. }
            | Self::Start { generation, .. }
            | Self::Finish { generation, .. } => *generation,
        }
    }

    const fn carrier_generation(&self) -> u64 {
        match self {
            Self::Logout {
                carrier_generation, ..
            }
            | Self::Start {
                carrier_generation, ..
            }
            | Self::Finish {
                carrier_generation, ..
            } => *carrier_generation,
        }
    }
}

fn opaque_attempt_demand(
    key: &LoginIndexKey,
    network_id: NetworkId,
    login: &NormalizedLogin,
) -> Result<BucketDemand, RuntimeError> {
    let digest =
        derive_login_index(key, network_id, login).map_err(|_| RuntimeError::InvalidValue)?;
    let key = LoginHashKey::from_digest_bytes(*digest.expose_for_storage_key());
    BucketDemand::new(BucketKind::OpaqueAttempt, BucketKey::LoginHash(key), 1)
}

fn request_result_key(request_id: RequestId) -> Result<StoredKey, RuntimeError> {
    Ok(StoredKey::new(request_id.as_bytes().to_vec())?)
}

fn request_result_write(
    revision: u64,
    request: &RequestContext,
    terminal: RequestTerminal,
    response: &[u8; ACCOUNT_SERVICE_RESPONSE_BYTES],
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    let record = RequestResultRecord {
        route: request.route,
        terminal,
        request: *request.envelope.as_bytes(),
        response: *response,
    };
    let body = ProtocolRecordBody::new(
        TableId::RequestResult,
        REQUEST_RESULT_KIND,
        1,
        record.encode(),
    )?;
    let value = PersistentRecordValue::new(
        TableId::RequestResult,
        REQUEST_RESULT_KIND,
        revision,
        0,
        None,
        Vec::new(),
        body.encode()?,
    )?;
    AccountServiceDurableWrite::put(
        TableId::RequestResult,
        request_result_key(request.envelope.client_request_id())?,
        value.encode()?,
    )
}

fn read_login_index(
    context: &StateCoreContext,
    result: ReadResult,
    key: &LoginIndexStoredKey,
) -> Result<Option<LoginIndexValue>, RuntimeError> {
    let stored_key = key.encode()?;
    let Some(opened) = open_optional(context, result, TableId::LoginIndex, &stored_key)? else {
        return Ok(None);
    };
    Ok(Some(LoginIndexValue::decode(
        opened.expose_for_storage_codec(),
        key,
    )?))
}

fn read_optional_persistent(
    context: &StateCoreContext,
    result: ReadResult,
    table: TableId,
    key: &StoredKey,
) -> Result<Option<PersistentRecordValue>, RuntimeError> {
    let Some(opened) = open_optional(context, result, table, key)? else {
        return Ok(None);
    };
    Ok(Some(PersistentRecordValue::decode(
        table,
        opened.expose_for_storage_codec(),
    )?))
}

fn read_required_persistent(
    context: &StateCoreContext,
    result: ReadResult,
    table: TableId,
    key: &StoredKey,
) -> Result<PersistentRecordValue, RuntimeError> {
    read_optional_persistent(context, result, table, key)?.ok_or(RuntimeError::InvalidValue)
}

fn open_optional(
    context: &StateCoreContext,
    result: ReadResult,
    table: TableId,
    key: &StoredKey,
) -> Result<Option<agenc_ircd_crypto::OpenedStoragePlaintext>, RuntimeError> {
    if result.records.len() > 1 {
        return Err(RuntimeError::InvalidValue);
    }
    let Some(record) = result.records.into_iter().next() else {
        return Ok(None);
    };
    if record.table != table || record.key != *key {
        return Err(RuntimeError::InvalidValue);
    }
    context
        .open_storage_plaintext(table, key, &record.sealed_record)
        .map(Some)
}

fn select_live_login(
    current: &Option<LoginIndexValue>,
    previous: &Option<LoginIndexValue>,
) -> Result<Option<(AccountId, agenc_ircd_types::OpaqueCredentialId)>, RuntimeError> {
    let current_live = current.as_ref().and_then(live_login);
    let previous_live = previous.as_ref().and_then(live_login);
    match (current_live, previous_live) {
        (Some(_), Some(_)) => Err(RuntimeError::InvalidValue),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn live_login(
    value: &LoginIndexValue,
) -> Option<(AccountId, agenc_ircd_types::OpaqueCredentialId)> {
    match value.kind() {
        LoginIndexValueKind::Live {
            account_id,
            opaque_credential_id,
        } => Some((
            *account_id,
            agenc_ircd_types::OpaqueCredentialId::from_bytes(
                *opaque_credential_id.expose_for_account_service(),
            ),
        )),
        LoginIndexValueKind::CreationReservation { .. }
        | LoginIndexValueKind::DeletionTombstone { .. } => None,
    }
}

fn credential_id(
    value: &LoginIndexValue,
) -> Result<agenc_ircd_types::OpaqueCredentialId, RuntimeError> {
    match value.kind() {
        LoginIndexValueKind::Live {
            opaque_credential_id,
            ..
        } => Ok(agenc_ircd_types::OpaqueCredentialId::from_bytes(
            *opaque_credential_id.expose_for_account_service(),
        )),
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn render_sasl_actions(
    prefix: &str,
    target: &str,
    actions: Vec<SaslAction>,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(actions.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for action in actions {
        if let Some(frame) = render_sasl_action(prefix, target, action)? {
            frames.push(frame);
        }
    }
    Ok(frames)
}

fn render_sasl_action(
    prefix: &str,
    target: &str,
    action: SaslAction,
) -> Result<Option<WireMessage>, RuntimeError> {
    let frame = match action {
        SaslAction::SendPlus => WireMessage::new(prefix, "AUTHENTICATE", &["+"], None),
        SaslAction::SendChunk(chunk) => {
            let text =
                std::str::from_utf8(chunk.expose()).map_err(|_| RuntimeError::InvalidValue)?;
            WireMessage::new(prefix, "AUTHENTICATE", &[text], None)
        }
        SaslAction::Numeric(numeric) => {
            let (middle, trailing): (&[&str], &str) = match numeric {
                SaslNumeric::Success => (&[], "SASL authentication successful"),
                SaslNumeric::Failed => (&[], "SASL authentication failed"),
                SaslNumeric::TooLong => (&[], "SASL message too long"),
                SaslNumeric::Aborted => (&[], "SASL authentication aborted"),
                SaslNumeric::AlreadyAuthenticated => (&[], "You have already authenticated"),
                SaslNumeric::Mechanisms => (&["AGENC-OPAQUE"], "Available SASL mechanisms"),
            };
            numeric_reply(prefix, numeric as u16, target, middle, Some(trailing))
        }
        SaslAction::RequestEnvelope { .. } | SaslAction::Logout => return Ok(None),
    }
    .map_err(|_| RuntimeError::InvalidValue)?;
    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::{LoginIndexKey, derive_login_index};
    use agenc_ircd_storage::{LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind};
    use agenc_ircd_types::{
        AccountId, AccountRandomId, ConnectionId, Generation, MonotonicTick, NetworkId,
        NormalizedLogin, OpaqueCredentialId, OriginId,
    };

    use crate::admission::{BucketTable, RateLimits};

    use super::{
        ConnectionRoute, REQUEST_RESULT_BYTES, RequestResultRecord, RequestTerminal, RuntimeError,
        opaque_attempt_demand, select_live_login,
    };

    fn account(byte: u8) -> AccountId {
        AccountId::from_random(AccountRandomId::from_bytes([byte; 16]))
    }

    fn live_value(
        network: NetworkId,
        generation: u32,
        login: &NormalizedLogin,
        byte: u8,
    ) -> Result<LoginIndexValue, Box<dyn core::error::Error>> {
        let key = LoginIndexKey::from_bytes([byte; 32]);
        let stored =
            LoginIndexStoredKey::new(generation, derive_login_index(&key, network, login)?)?;
        Ok(LoginIndexValue::new(
            &stored,
            LoginIndexValueKind::Live {
                account_id: account(byte),
                opaque_credential_id: OpaqueCredentialId::from_bytes([byte; 32]),
            },
        )?)
    }

    #[test]
    fn request_results_bind_route_terminal_and_exact_ciphertexts()
    -> Result<(), Box<dyn core::error::Error>> {
        let route = ConnectionRoute {
            origin_id: OriginId::from_bytes([1; 16]),
            origin_generation: Generation::new(2)?,
            connection_id: ConnectionId::from_bytes([3; 16]),
            connection_nonce: [4; 32],
        };
        for terminal in [
            RequestTerminal::Start,
            RequestTerminal::Accepted,
            RequestTerminal::Rejected,
        ] {
            let record = RequestResultRecord {
                route,
                terminal,
                request: [5; agenc_ircd_auth::ACCOUNT_SERVICE_ENVELOPE_BYTES],
                response: [6; agenc_ircd_auth::ACCOUNT_SERVICE_RESPONSE_BYTES],
            };
            let encoded = record.encode();
            assert_eq!(encoded.len(), REQUEST_RESULT_BYTES);
            let decoded = RequestResultRecord::decode(&encoded)?;
            assert!(decoded.route == route);
            assert!(decoded.terminal == terminal);
            assert_eq!(decoded.request, record.request);
            assert_eq!(decoded.response, record.response);
        }
        Ok(())
    }

    #[test]
    fn request_result_decoder_rejects_truncation_version_and_terminal_tag()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut encoded = vec![0_u8; REQUEST_RESULT_BYTES];
        encoded
            .get_mut(..2)
            .ok_or(RuntimeError::InvalidValue)?
            .copy_from_slice(&1_u16.to_be_bytes());
        encoded
            .get_mut(2 + 16..2 + 16 + 8)
            .ok_or(RuntimeError::InvalidValue)?
            .copy_from_slice(&1_u64.to_be_bytes());
        let terminal_offset = 2 + 16 + 8 + 16 + 32;
        *encoded
            .get_mut(terminal_offset)
            .ok_or(RuntimeError::InvalidValue)? = 1;

        let truncated = encoded
            .get(..encoded.len().saturating_sub(1))
            .ok_or(RuntimeError::InvalidValue)?;
        assert!(RequestResultRecord::decode(truncated).is_err());
        encoded
            .get_mut(..2)
            .ok_or(RuntimeError::InvalidValue)?
            .copy_from_slice(&2_u16.to_be_bytes());
        assert!(RequestResultRecord::decode(&encoded).is_err());
        encoded
            .get_mut(..2)
            .ok_or(RuntimeError::InvalidValue)?
            .copy_from_slice(&1_u16.to_be_bytes());
        *encoded
            .get_mut(terminal_offset)
            .ok_or(RuntimeError::InvalidValue)? = 0;
        assert!(RequestResultRecord::decode(&encoded).is_err());
        Ok(())
    }

    #[test]
    fn login_selection_rejects_two_live_generations() -> Result<(), Box<dyn core::error::Error>> {
        let network = NetworkId::from_bytes([7; 32]);
        let login = NormalizedLogin::prepare("bounded-user")?;
        let current = Some(live_value(network, 2, &login, 8)?);
        let previous = Some(live_value(network, 1, &login, 9)?);

        assert!(select_live_login(&current, &previous).is_err());
        let selected = select_live_login(&current, &None)?.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(selected.0, account(8));
        assert_eq!(selected.1.expose_for_account_service(), &[8; 32]);
        Ok(())
    }

    #[test]
    fn opaque_attempts_stop_at_the_keyed_login_burst_before_lookup()
    -> Result<(), Box<dyn core::error::Error>> {
        let key = LoginIndexKey::from_bytes([9; 32]);
        let network = NetworkId::from_bytes([7; 32]);
        let login = NormalizedLogin::prepare("bounded-user")?;
        let demand = opaque_attempt_demand(&key, network, &login)?;
        let mut buckets = BucketTable::new(RateLimits::defaults());
        let now = MonotonicTick::from_ticks(0);
        for _ in 0..5 {
            assert!(buckets.charge_all_or_nothing(now, &[demand]).is_ok());
        }
        assert!(buckets.charge_all_or_nothing(now, &[demand]).is_err());
        Ok(())
    }
}
