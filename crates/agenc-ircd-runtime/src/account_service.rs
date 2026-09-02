//! Coordinator-owned OPAQUE account-service execution for live SASL clients.
//!
//! The client-wire state machine owns only bounded IRC framing. This module
//! owns the private HPKE/Opaque workflow, the fixed storage lookup schedule,
//! exact request replay, and the durable barrier that makes a response visible
//! only with its transaction/result/session effects.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use agenc_ircd_auth::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES, AccountAuthenticationState,
    AccountCreationStartParameters, AccountCreationState, AccountCredentialRecord,
    AccountOperationContext, AccountRouteBinding, AccountServiceEnvelope, AccountStartOutcome,
    AccountTransaction, AuthenticatedAccountRequest, AuthenticationGrant,
    AuthenticationGrantRecord, AuthenticationLookup, AuthenticationStart,
    AuthenticationStartParameters, CreateAccountIntent, CreationAdmission, CreationFinish,
    CreationStart, CredentialChangeFinish, CredentialChangeStart, CredentialChangeStartParameters,
    CredentialChangeState, CredentialReplacementIntent, DestructiveAccountSnapshot,
    FreshAuthenticationProof, OpaqueProfile, OpaqueRegistrationRecord, OpenedAccountServiceRequest,
    SealedAccountFinishOutcome, SealedAccountStart,
};
use agenc_ircd_client_wire::{
    AccountCarrierAction, AccountCarrierKind, AccountCarrierPhase, AccountTransfer, ParsedMessage,
    SaslAction, SaslNumeric, SaslTransport, SecretBytes, WireMessage, numeric_reply,
};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, Ed25519PublicKey, LoginIndexKey, OpaqueFakeCredentialKey,
    derive_login_index,
};
use agenc_ircd_domain::{
    AccountState, DirectMessagePolicy, DomainEvent, GuestDirectMessagePolicy, PresencePolicy,
};
use agenc_ircd_storage::{
    LIVE_RECORD_KIND, LOGIN_INDEX_KEY_STATE_KEY, LoginIndexKeyState, LoginIndexLazyMigration,
    LoginIndexLookupSchedule, LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind,
    OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue, ProtocolRecordBody, ReadPlan, ReadResult,
    RecordReference, StoredKey, TableId,
};
use agenc_ircd_types::{
    AccountId, AccountServiceMessageKind, ConnectionId, Generation, MonotonicTick, NetworkId,
    NormalizedLogin, OriginId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation,
    TransactionId, UtcSecond,
};

use crate::RuntimeError;
use crate::admission::{BucketDemand, BucketKey, BucketKind, LoginHashKey};
use crate::bridge::crypto::{
    AccountOpenJob, CreationFinishJob, CreationFinishSealJob, CreationPreflightJob,
    CreationStartJob, CreationStartSealJob, CredentialFinishJob, CredentialFinishSealJob,
    CredentialStartJob, CredentialStartSealJob, CryptoJobOutput, OpaqueFinishJob,
    OpaqueFinishSealJob, OpaqueStartJob, OpaqueStartSealJob, RuntimeCryptoJob,
};
use crate::bridge::{
    CryptoCompletionMessage, CryptoJobId, StorageReadCompletionMessage, StorageReadId,
};
use crate::connection::sink::ConnectionGeneration;
use crate::mutation_render::render_account_credential_replacement;
use crate::observe::metrics::ResultClass;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::inbox::CloseReason;
use crate::state_core::reconstruct::RecoveredAccountTransactionCleanup;
use crate::state_core::session::{AdmissionClass, MAX_TRACKED_CONNECTIONS};
use crate::state_core::timers::{DRIFT_CHECK_INTERVAL_MILLIS, TimedId, TimerEntry, TimerKind};
use crate::state_core::{StageAccepted, StagedOrigin, StateCoreContext};
use crate::sync::Arc;

const AUTHENTICATION_TRANSACTION_KIND: u16 = 2;
const CREATION_TRANSACTION_KIND: u16 = 1;
const CREDENTIAL_CHANGE_TRANSACTION_KIND: u16 = 3;
const AUTHENTICATION_GRANT_KIND: u16 = 4;
const INVITATION_RESERVATION_KIND: u16 = 1;
const INVITATION_TOMBSTONE_KIND: u16 = 2;
const INVITATION_TOMBSTONE_SECONDS: u64 = 7 * 24 * 60 * 60;
const LOGIN_DELETION_TOMBSTONE_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_LOGIN_TOMBSTONE_EXPIRIES_PER_BATCH: usize = 256;
const REQUEST_RESULT_KIND: u16 = 1;
const REQUEST_RESULT_VERSION: u16 = 2;
const REQUEST_RESULT_ROUTE_BYTES: usize = 16 + 8 + 16 + 32;
const REQUEST_RESULT_BYTES: usize = 2
    + REQUEST_RESULT_ROUTE_BYTES
    + 1
    + 24
    + ACCOUNT_SERVICE_ENVELOPE_BYTES
    + ACCOUNT_SERVICE_RESPONSE_BYTES;
const TERMINAL_START: u8 = 1;
const TERMINAL_ACCEPTED: u8 = 2;
const TERMINAL_REJECTED: u8 = 3;
const MAX_READY_SEALS: usize = 128;
const MAX_OPAQUE_ATTEMPTS_PER_CONNECTION: u8 = 2;
const MAX_PENDING_TRANSACTION_CLEANUPS: usize = MAX_TRACKED_CONNECTIONS;
const MAX_TRANSACTION_CLEANUPS_PER_BATCH: usize = 256;

/// Deployment policy applied to authenticated account-creation requests.
#[derive(Clone, Copy)]
pub enum AccountCreationPolicy {
    /// Creation is open and an invitation is forbidden.
    Open,
    /// Creation requires one valid invitation under this offline authority.
    Invite(Ed25519PublicKey),
    /// Every creation request follows the latent-rejection path.
    Closed,
}

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
    /// One validated live private login-index key for each account.
    pub live_login_keys: BTreeMap<AccountId, StoredKey>,
    /// Validated deletion tombstones ordered by expiry and Account ID.
    pub login_deletion_tombstones: BTreeMap<(u64, AccountId), StoredKey>,
    /// Fully validated connection-bound rows left by the prior process.
    pub startup_transaction_cleanups: Vec<RecoveredAccountTransactionCleanup>,
    /// Deployment account-creation policy and optional invitation authority.
    pub creation_policy: AccountCreationPolicy,
    /// Initial public-presence policy copied into a committed account.
    pub default_presence: PresencePolicy,
    /// Initial guest direct-message policy copied into a committed account.
    pub default_guest_direct_messages: GuestDirectMessagePolicy,
    /// Initial authenticated direct-message policy copied into a committed account.
    pub default_direct_messages: DirectMessagePolicy,
}

/// One carrier line either finished synchronously or remains owned by an
/// asynchronous account-service continuation.
pub(crate) enum CarrierRoute {
    Finished {
        frames: Vec<WireMessage>,
        result: ResultClass,
    },
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
    pub(crate) result: ResultClass,
}

impl CarrierCompletion {
    const fn finished(
        generation: ConnectionGeneration,
        carrier_generation: u64,
        result: ResultClass,
    ) -> Self {
        Self {
            generation,
            carrier_generation,
            close: false,
            result,
        }
    }

    const fn closed(generation: ConnectionGeneration, carrier_generation: u64) -> Self {
        Self {
            generation,
            carrier_generation,
            close: true,
            result: ResultClass::Error,
        }
    }

    const fn with_close(
        generation: ConnectionGeneration,
        carrier_generation: u64,
        close: bool,
        result: ResultClass,
    ) -> Self {
        if close {
            Self::closed(generation, carrier_generation)
        } else {
            Self::finished(generation, carrier_generation, result)
        }
    }
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
    terminal_account: Option<AccountId>,
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
        match self.terminal_account {
            Some(account_id) => encoded.extend_from_slice(account_id.to_text().as_bytes()),
            None => encoded.extend_from_slice(&[0_u8; 24]),
        }
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
        let account_bytes = cursor.read_array::<24>()?;
        let terminal_account = if account_bytes == [0_u8; 24] {
            None
        } else {
            Some(
                AccountId::parse_wire_bytes(&account_bytes)
                    .map_err(|_| RuntimeError::InvalidValue)?,
            )
        };
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
            terminal_account,
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
    transaction_id: TransactionId,
    grant: AuthenticationGrant,
    authenticated_at: MonotonicTick,
}

impl AuthenticatedBinding {
    const fn account_id(&self) -> AccountId {
        self.grant.account_id()
    }

    const fn account_session_generation(&self) -> Generation {
        self.grant.account_session_generation()
    }

    const fn process_expires_at(&self) -> MonotonicTick {
        self.grant.process_expires_at()
    }
}

struct LiveAuthentication {
    transaction: AccountTransaction<AccountAuthenticationState>,
    account_id: Option<AccountId>,
    login: NormalizedLogin,
    previous_value: Option<LoginIndexValue>,
}

#[derive(Clone)]
struct CreationReservation {
    login_key: StoredKey,
    invitation_id: Option<agenc_ircd_types::InviteId>,
}

struct LiveCreation {
    transaction: AccountTransaction<AccountCreationState>,
    reservation: Option<CreationReservation>,
}

struct LiveCredentialChange {
    transaction: AccountTransaction<CredentialChangeState>,
    reservation: Option<AccountId>,
}

struct CommittedLoginIndexMigration {
    account_id: AccountId,
    previous_key: StoredKey,
    current_key: StoredKey,
}

struct AccountDeletionBarrier {
    account_id: AccountId,
    tombstone_id: (u64, AccountId),
    authentications: Vec<(ConnectionGeneration, TransactionId)>,
    grants: Vec<(ConnectionGeneration, TransactionId)>,
    completions: Vec<CarrierCompletion>,
}

struct PendingLoginTombstoneExpiry {
    tombstones: Vec<((u64, AccountId), StoredKey)>,
    resulting_key_state: Option<LoginIndexKeyState>,
}

struct LoginTombstoneExpiryBatch {
    pending: PendingLoginTombstoneExpiry,
    writes: Vec<AccountServiceDurableWrite>,
    successor: Option<(u64, AccountId)>,
}

type DeletionAuthorities = (
    Vec<(ConnectionGeneration, TransactionId)>,
    Vec<(ConnectionGeneration, TransactionId)>,
);

#[derive(Clone, Copy, Eq, PartialEq)]
enum LiveTransactionClass {
    Authentication,
    AuthenticationGrant,
    Creation,
    CredentialChange,
}

#[derive(Clone)]
enum TransactionCleanupReservation {
    None,
    Creation(CreationReservation),
    Credential {
        account_id: AccountId,
        owner: ConnectionGeneration,
    },
}

#[derive(Clone)]
struct TransactionCleanup {
    transaction_id: TransactionId,
    reservation: TransactionCleanupReservation,
    recovered: bool,
}

impl TransactionCleanup {
    const fn authentication(transaction_id: TransactionId) -> Self {
        Self {
            transaction_id,
            reservation: TransactionCleanupReservation::None,
            recovered: false,
        }
    }

    fn creation(transaction_id: TransactionId, reservation: Option<CreationReservation>) -> Self {
        Self {
            transaction_id,
            reservation: match reservation {
                Some(reservation) => TransactionCleanupReservation::Creation(reservation),
                None => TransactionCleanupReservation::None,
            },
            recovered: false,
        }
    }

    fn credential(
        transaction_id: TransactionId,
        reservation: Option<AccountId>,
        owner: ConnectionGeneration,
    ) -> Self {
        let reservation = reservation
            .map(|account_id| TransactionCleanupReservation::Credential { account_id, owner })
            .unwrap_or(TransactionCleanupReservation::None);
        Self {
            transaction_id,
            reservation,
            recovered: false,
        }
    }

    fn recovered(cleanup: RecoveredAccountTransactionCleanup) -> Result<Self, RuntimeError> {
        let (transaction_id, login_key, invitation_id) = cleanup.into_parts();
        let reservation = match (login_key, invitation_id) {
            (Some(login_key), invitation_id) => {
                TransactionCleanupReservation::Creation(CreationReservation {
                    login_key,
                    invitation_id,
                })
            }
            (None, None) => TransactionCleanupReservation::None,
            (None, Some(_)) => return Err(RuntimeError::InvalidValue),
        };
        Ok(Self {
            transaction_id,
            reservation,
            recovered: true,
        })
    }

    fn durable_writes(&self) -> Result<Vec<AccountServiceDurableWrite>, RuntimeError> {
        let mut writes = Vec::new();
        writes
            .try_reserve_exact(3)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        writes.push(AccountServiceDurableWrite::delete(
            TableId::AuthTransaction,
            StoredKey::new(self.transaction_id.as_bytes().to_vec())?,
        )?);
        if let TransactionCleanupReservation::Creation(reservation) = &self.reservation {
            writes.push(AccountServiceDurableWrite::delete(
                TableId::LoginIndex,
                reservation.login_key.clone(),
            )?);
            if let Some(invite_id) = reservation.invitation_id {
                writes.push(AccountServiceDurableWrite::delete(
                    TableId::RegistrationInvite,
                    StoredKey::new(invite_id.as_bytes().to_vec())?,
                )?);
            }
        }
        Ok(writes)
    }
}

struct AccountConnection {
    sasl: SaslTransport,
    creation: AccountTransfer,
    credentials: AccountTransfer,
    route: ConnectionRoute,
    opaque_attempts: u8,
    transaction: Option<LiveAuthentication>,
    creation_transaction: Option<LiveCreation>,
    credential_transaction: Option<LiveCredentialChange>,
    authenticated: Option<AuthenticatedBinding>,
    credential_id: Option<agenc_ircd_types::OpaqueCredentialId>,
    fresh_authentication: Option<FreshAuthenticationProof>,
}

struct RequestContext {
    generation: ConnectionGeneration,
    carrier_generation: u64,
    target: String,
    route: ConnectionRoute,
    envelope: AccountServiceEnvelope,
    carrier: RequestCarrier,
    phase: AccountCarrierPhase,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RequestCarrier {
    Sasl,
    Account(AccountCarrierKind),
}

impl RequestContext {
    fn is_finish(&self) -> bool {
        self.phase == AccountCarrierPhase::Finish
    }

    const fn expected_message_kind(&self) -> AccountServiceMessageKind {
        match (self.carrier, self.phase) {
            (RequestCarrier::Sasl, AccountCarrierPhase::Start) => {
                AccountServiceMessageKind::OpaqueAuthStart
            }
            (RequestCarrier::Sasl, AccountCarrierPhase::Finish) => {
                AccountServiceMessageKind::OpaqueAuthFinish
            }
            (RequestCarrier::Account(AccountCarrierKind::Create), AccountCarrierPhase::Start) => {
                AccountServiceMessageKind::AccountCreateStart
            }
            (RequestCarrier::Account(AccountCarrierKind::Create), AccountCarrierPhase::Finish) => {
                AccountServiceMessageKind::AccountCreateFinish
            }
            (
                RequestCarrier::Account(AccountCarrierKind::Credentials),
                AccountCarrierPhase::Start,
            ) => AccountServiceMessageKind::CredentialChangeStart,
            (
                RequestCarrier::Account(AccountCarrierKind::Credentials),
                AccountCarrierPhase::Finish,
            ) => AccountServiceMessageKind::CredentialChangeFinish,
        }
    }
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
    CreationCurrentIndex {
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationStart>,
        schedule: LoginIndexLookupSchedule,
        rate_available: bool,
    },
    CreationPreviousIndex {
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationStart>,
        schedule: LoginIndexLookupSchedule,
        current_available: bool,
        rate_available: bool,
    },
    CreationInvitation {
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationStart>,
        login_available: bool,
        rate_available: bool,
        invitation_key: StoredKey,
    },
    CredentialOpaque {
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CredentialChangeStart>,
        account: DestructiveAccountSnapshot,
        credential_id: agenc_ircd_types::OpaqueCredentialId,
        proof: Option<FreshAuthenticationProof>,
        reservation: Option<AccountId>,
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

struct CredentialOpaqueContinuation {
    request: RequestContext,
    opened: AuthenticatedAccountRequest<CredentialChangeStart>,
    account: DestructiveAccountSnapshot,
    credential_id: agenc_ircd_types::OpaqueCredentialId,
    proof: Option<FreshAuthenticationProof>,
    reservation: Option<AccountId>,
    record_key: StoredKey,
}

enum PendingCrypto {
    Open(RequestContext),
    CreationPreflight {
        request: RequestContext,
    },
    CreationStart {
        request: RequestContext,
    },
    CreationStartSeal {
        request: RequestContext,
    },
    CreationFinish {
        request: RequestContext,
        transaction_id: TransactionId,
        reservation: Option<CreationReservation>,
    },
    CreationFinishSeal {
        request: RequestContext,
        transaction_id: TransactionId,
        reservation: Option<CreationReservation>,
    },
    CredentialStart {
        request: RequestContext,
        reservation: Option<AccountId>,
    },
    CredentialStartSeal {
        request: RequestContext,
        reservation: Option<AccountId>,
    },
    CredentialFinish {
        request: RequestContext,
        transaction_id: TransactionId,
        reservation: Option<AccountId>,
    },
    CredentialFinishSeal {
        request: RequestContext,
        transaction_id: TransactionId,
        reservation: Option<AccountId>,
    },
    Start {
        request: RequestContext,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    StartSeal {
        request: RequestContext,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    Finish {
        request: RequestContext,
        transaction_id: TransactionId,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
        authenticated_at: MonotonicTick,
    },
    FinishSeal {
        request: RequestContext,
        transaction_id: TransactionId,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
        authenticated_at: MonotonicTick,
    },
}

enum ReadySeal {
    CreationStart {
        request: RequestContext,
        outcome: AccountStartOutcome<AccountCreationState>,
    },
    CreationFinish {
        request: RequestContext,
        transaction_id: TransactionId,
        outcome: agenc_ircd_auth::AccountFinishOutcome<CreateAccountIntent>,
        reservation: Option<CreationReservation>,
    },
    CredentialStart {
        request: RequestContext,
        outcome: AccountStartOutcome<CredentialChangeState>,
        reservation: Option<AccountId>,
    },
    CredentialFinish {
        request: RequestContext,
        transaction_id: TransactionId,
        outcome: agenc_ircd_auth::AccountFinishOutcome<CredentialReplacementIntent>,
        reservation: Option<AccountId>,
    },
    Start {
        request: RequestContext,
        outcome: AccountStartOutcome<AccountAuthenticationState>,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    Finish {
        request: RequestContext,
        transaction_id: TransactionId,
        outcome: agenc_ircd_auth::AccountFinishOutcome<AuthenticationGrant>,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
        authenticated_at: MonotonicTick,
    },
}

enum ReadyStage {
    CreationStart {
        request: RequestContext,
        sealed: SealedAccountStart<AccountCreationState>,
    },
    CreationFinish {
        request: RequestContext,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<CreateAccountIntent>,
        reservation: Option<CreationReservation>,
    },
    CredentialStart {
        request: RequestContext,
        sealed: SealedAccountStart<CredentialChangeState>,
        reservation: Option<AccountId>,
    },
    CredentialFinish {
        request: RequestContext,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<CredentialReplacementIntent>,
        reservation: Option<AccountId>,
    },
    Start {
        request: RequestContext,
        sealed: SealedAccountStart<AccountAuthenticationState>,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    Finish {
        request: RequestContext,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<AuthenticationGrant>,
        account_id: Option<AccountId>,
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
    CreationStart {
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountStart<AccountCreationState>,
        reservation: Option<CreationReservation>,
    },
    CreationFinish {
        generation: ConnectionGeneration,
        carrier_generation: u64,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<CreateAccountIntent>,
        reservation: Option<CreationReservation>,
    },
    CredentialStart {
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountStart<CredentialChangeState>,
        reservation: Option<AccountId>,
    },
    CredentialFinish {
        generation: ConnectionGeneration,
        carrier_generation: u64,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<CredentialReplacementIntent>,
        reservation: Option<AccountId>,
        fenced: Vec<ConnectionGeneration>,
        invalidated_authentications: Vec<ConnectionGeneration>,
        invalidated_grants: Vec<ConnectionGeneration>,
    },
    Start {
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountStart<AccountAuthenticationState>,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    },
    Finish {
        generation: ConnectionGeneration,
        carrier_generation: u64,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<AuthenticationGrant>,
        account_id: Option<AccountId>,
        authenticated_at: MonotonicTick,
        sasl_accepted: bool,
        fresh_auth_session: Option<(agenc_ircd_types::UserId, Generation, AccountId)>,
        resulting_key_state: Option<LoginIndexKeyState>,
        login_index_migration: Option<CommittedLoginIndexMigration>,
    },
}

/// Live coordinator-side account-service owner.
pub(crate) struct AccountServiceCoordinator {
    config: AccountServiceConfig,
    connections: BTreeMap<ConnectionGeneration, AccountConnection>,
    credential_reservations: BTreeMap<AccountId, ConnectionGeneration>,
    transaction_owners: BTreeMap<TransactionId, (ConnectionGeneration, LiveTransactionClass)>,
    grant_consumptions: BTreeMap<ConnectionGeneration, TransactionId>,
    pending_account_deletions: BTreeMap<ConnectionGeneration, AccountDeletionBarrier>,
    scheduled_login_tombstone: Option<(u64, AccountId)>,
    pending_login_tombstone_expiry: Option<PendingLoginTombstoneExpiry>,
    cleanup_queue: VecDeque<TransactionCleanup>,
    startup_cleanup_remaining: usize,
    credential_cleanup_owners: BTreeSet<ConnectionGeneration>,
    pending_cleanups: Vec<TransactionCleanup>,
    reads: BTreeMap<StorageReadId, PendingRead>,
    crypto: BTreeMap<CryptoJobId, PendingCrypto>,
    ready_seals: VecDeque<ReadySeal>,
    ready_stage: Option<ReadyStage>,
    pending_authority: Option<PendingAuthority>,
}

impl AccountServiceCoordinator {
    /// Validates immutable configuration and creates an empty live owner.
    pub(crate) fn new(mut config: AccountServiceConfig) -> Result<Self, RuntimeError> {
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
        if config.startup_transaction_cleanups.len() > MAX_PENDING_TRANSACTION_CLEANUPS {
            return Err(RuntimeError::LimitExceeded);
        }
        let startup_cleanup_remaining = config.startup_transaction_cleanups.len();
        let mut cleanup_queue = VecDeque::new();
        cleanup_queue
            .try_reserve_exact(startup_cleanup_remaining)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for cleanup in std::mem::take(&mut config.startup_transaction_cleanups) {
            cleanup_queue.push_back(TransactionCleanup::recovered(cleanup)?);
        }
        Ok(Self {
            config,
            connections: BTreeMap::new(),
            credential_reservations: BTreeMap::new(),
            transaction_owners: BTreeMap::new(),
            grant_consumptions: BTreeMap::new(),
            pending_account_deletions: BTreeMap::new(),
            scheduled_login_tombstone: None,
            pending_login_tombstone_expiry: None,
            cleanup_queue,
            startup_cleanup_remaining,
            credential_cleanup_owners: BTreeSet::new(),
            pending_cleanups: Vec::new(),
            reads: BTreeMap::new(),
            crypto: BTreeMap::new(),
            ready_seals: VecDeque::new(),
            ready_stage: None,
            pending_authority: None,
        })
    }

    /// Installs copy-only account defaults at a StateCore reload safe point.
    pub(crate) fn reload_policy(&mut self, policy: crate::runtime_config::AccountRuntimePolicy) {
        self.config.creation_policy = policy.creation;
        self.config.default_presence = policy.default_presence;
        self.config.default_guest_direct_messages = policy.default_guest_direct_messages;
        self.config.default_direct_messages = policy.default_direct_messages;
    }

    /// Returns whether no account-service continuation can observe both
    /// sides of a runtime policy activation.
    pub(crate) fn reload_ready(&self) -> bool {
        self.exclusive_account_service_transition_available()
            && self.connections.values().all(|connection| {
                connection.transaction.is_none()
                    && connection.creation_transaction.is_none()
                    && connection.credential_transaction.is_none()
            })
    }

    /// Returns whether one registered connection is behind a staged durable
    /// principal transition and therefore cannot admit later authority-bearing
    /// input until that batch commits or is rejected.
    pub(crate) fn registered_authority_fenced(
        &self,
        context: &StateCoreContext,
        generation: ConnectionGeneration,
    ) -> bool {
        let authority_fenced = match self.pending_authority.as_ref() {
            Some(PendingAuthority::Logout {
                generation: pending,
                ..
            }) => *pending == generation,
            Some(PendingAuthority::CredentialFinish { sealed, fenced, .. }) => {
                sealed.result().is_ok() && pending_credential_finish_fences(fenced, generation)
            }
            Some(PendingAuthority::Finish {
                generation: pending,
                fresh_auth_session: Some((user_id, resulting_session_generation, _account_id)),
                ..
            }) => context.domain().session(*user_id).is_some_and(|session| {
                pending_guest_account_switch_fences(
                    *pending,
                    generation,
                    session.account_id(),
                    session.generation(),
                    *resulting_session_generation,
                )
            }),
            Some(
                PendingAuthority::CreationStart { .. }
                | PendingAuthority::CreationFinish { .. }
                | PendingAuthority::CredentialStart { .. }
                | PendingAuthority::Start { .. }
                | PendingAuthority::Finish { .. },
            )
            | None => false,
        };
        authority_fenced
            || self
                .pending_account_deletions
                .values()
                .any(|pending| pending.fences_generation(generation))
    }

    /// Creates fresh connection and nonce bindings for one admitted transport.
    pub(crate) fn connection_opened(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Result<(), RuntimeError> {
        if self.startup_cleanup_remaining != 0 {
            self.try_stage_transaction_cleanup(context)?;
            return Err(RuntimeError::Storage(
                agenc_ircd_storage::StorageError::Unavailable,
            ));
        }
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
            creation: AccountTransfer::new(AccountCarrierKind::Create)
                .map_err(|_| RuntimeError::MemoryExhausted)?,
            credentials: AccountTransfer::new(AccountCarrierKind::Credentials)
                .map_err(|_| RuntimeError::MemoryExhausted)?,
            route: ConnectionRoute {
                origin_id: self.config.origin_id,
                origin_generation: self.config.origin_generation,
                connection_id,
                connection_nonce,
            },
            opaque_attempts: 0,
            transaction: None,
            creation_transaction: None,
            credential_transaction: None,
            authenticated: None,
            credential_id: None,
            fresh_authentication: None,
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
        let mut retained = self.queue_closed_live_transactions(context, generation);
        retained |= self.cancel_closed_crypto(context, generation);
        self.reads
            .retain(|_, pending| pending.generation() != generation);
        retained |= self.discard_closed_ready_seals(context, generation);
        retained |= self.discard_closed_ready_stage(context, generation);
        if !self.retains_credential_reservation(generation, retained) {
            self.credential_reservations
                .retain(|_, owner| *owner != generation);
        }
        let _cleanup = self.try_stage_transaction_cleanup(context);
    }

    fn queue_closed_live_transactions(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> bool {
        let Some(mut connection) = self.connections.remove(&generation) else {
            return false;
        };
        if let Some(live) = connection.transaction.take() {
            let transaction_id = live.transaction.binding().transaction_id();
            let cleanup = TransactionCleanup::authentication(transaction_id);
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::Authentication,
                cleanup,
            );
        }
        if let Some(live) = connection.creation_transaction.take() {
            let transaction_id = live.transaction.binding().transaction_id();
            let cleanup = TransactionCleanup::creation(transaction_id, live.reservation);
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::Creation,
                cleanup,
            );
        }
        if let Some(binding) = connection.authenticated.take() {
            let transaction_id = binding.transaction_id;
            if self.grant_consumptions.get(&generation) != Some(&transaction_id) {
                let cleanup = TransactionCleanup::authentication(transaction_id);
                let _queued = self.queue_transaction_cleanup(
                    context,
                    generation,
                    LiveTransactionClass::AuthenticationGrant,
                    cleanup,
                );
            }
        }
        let Some(live) = connection.credential_transaction.take() else {
            return false;
        };
        let transaction_id = live.transaction.binding().transaction_id();
        let retained = live.reservation.is_some();
        let cleanup = TransactionCleanup::credential(transaction_id, live.reservation, generation);
        let _queued = self.queue_transaction_cleanup(
            context,
            generation,
            LiveTransactionClass::CredentialChange,
            cleanup,
        );
        retained
    }

    fn cancel_closed_crypto(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> bool {
        let mut retained = false;
        let jobs = self
            .crypto
            .iter()
            .filter_map(|(job_id, pending)| (pending.generation() == generation).then_some(*job_id))
            .collect::<Vec<_>>();
        for job_id in jobs {
            if let Some(pending) = self.crypto.remove(&job_id)
                && let Some((class, cleanup)) = pending.into_transaction_cleanup()
            {
                retained |= matches!(
                    &cleanup.reservation,
                    TransactionCleanupReservation::Credential { .. }
                );
                let _queued = self.queue_transaction_cleanup(context, generation, class, cleanup);
            }
            let _cancelled = context.crypto_mut().cancel(job_id);
        }
        retained
    }

    fn discard_closed_ready_seals(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> bool {
        let mut retained = false;
        let mut retained_seals = VecDeque::new();
        while let Some(pending) = self.ready_seals.pop_front() {
            if pending.generation() != generation {
                retained_seals.push_back(pending);
            } else if let Some((class, cleanup)) = pending.into_transaction_cleanup() {
                retained |= matches!(
                    &cleanup.reservation,
                    TransactionCleanupReservation::Credential { .. }
                );
                let _queued = self.queue_transaction_cleanup(context, generation, class, cleanup);
            }
        }
        self.ready_seals = retained_seals;
        retained
    }

    fn discard_closed_ready_stage(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> bool {
        if self
            .ready_stage
            .as_ref()
            .is_some_and(|pending| pending.generation() == generation)
            && let Some(pending) = self.ready_stage.take()
            && let Some((class, cleanup)) = pending.into_transaction_cleanup()
        {
            let retained = matches!(
                &cleanup.reservation,
                TransactionCleanupReservation::Credential { .. }
            );
            let _queued = self.queue_transaction_cleanup(context, generation, class, cleanup);
            return retained;
        }
        false
    }

    fn retains_credential_reservation(
        &self,
        generation: ConnectionGeneration,
        queued_credential_cleanup: bool,
    ) -> bool {
        let retained_authority_reservation = self
            .pending_authority
            .as_ref()
            .filter(|pending| pending.generation() == generation)
            .and_then(PendingAuthority::credential_reservation)
            .is_some();
        let retained_transaction_reservation =
            self.transaction_owners.values().any(|(owner, class)| {
                *owner == generation && *class == LiveTransactionClass::CredentialChange
            });
        queued_credential_cleanup
            || self.credential_cleanup_owners.contains(&generation)
            || retained_authority_reservation
            || retained_transaction_reservation
    }

    /// Consumes one account-transaction expiry from the shared timer heap.
    pub(crate) fn timer_fired(
        &mut self,
        context: &mut StateCoreContext,
        entry: TimerEntry,
    ) -> (bool, Vec<CarrierCompletion>) {
        if entry.kind == TimerKind::Reservation
            && entry.id == TimedId::Global
            && self.scheduled_login_tombstone.take().is_some()
        {
            let _staged = self.try_stage_login_tombstone_expiry(context);
            return (true, self.progress(context));
        }
        let TimedId::Transaction(transaction_id) = entry.id else {
            return (false, Vec::new());
        };
        if entry.kind != TimerKind::Reservation {
            return (false, Vec::new());
        }
        let Some((generation, class)) = self.transaction_owners.get(&transaction_id).copied()
        else {
            return (true, Vec::new());
        };
        let expired_grant = class == LiveTransactionClass::AuthenticationGrant;
        let Some(cleanup) = self.take_live_transaction(generation, class, transaction_id) else {
            return (true, Vec::new());
        };
        let _queued = self.queue_transaction_cleanup(context, generation, class, cleanup);
        let mut completions = self.progress(context);
        if expired_grant {
            completions.push(CarrierCompletion::closed(generation, 0));
        }
        (true, completions)
    }

    fn take_live_transaction(
        &mut self,
        generation: ConnectionGeneration,
        class: LiveTransactionClass,
        transaction_id: TransactionId,
    ) -> Option<TransactionCleanup> {
        let connection = self.connections.get_mut(&generation)?;
        let matches_transaction = match class {
            LiveTransactionClass::Authentication => connection
                .transaction
                .as_ref()
                .is_some_and(|live| live.transaction.binding().transaction_id() == transaction_id),
            LiveTransactionClass::AuthenticationGrant => connection
                .authenticated
                .as_ref()
                .is_some_and(|binding| binding.transaction_id == transaction_id),
            LiveTransactionClass::Creation => connection
                .creation_transaction
                .as_ref()
                .is_some_and(|live| live.transaction.binding().transaction_id() == transaction_id),
            LiveTransactionClass::CredentialChange => connection
                .credential_transaction
                .as_ref()
                .is_some_and(|live| live.transaction.binding().transaction_id() == transaction_id),
        };
        if !matches_transaction {
            return None;
        }
        match class {
            LiveTransactionClass::Authentication => connection
                .transaction
                .take()
                .map(|_| TransactionCleanup::authentication(transaction_id)),
            LiveTransactionClass::AuthenticationGrant => connection
                .authenticated
                .take()
                .map(|_| TransactionCleanup::authentication(transaction_id)),
            LiveTransactionClass::Creation => connection
                .creation_transaction
                .take()
                .map(|live| TransactionCleanup::creation(transaction_id, live.reservation)),
            LiveTransactionClass::CredentialChange => {
                connection.credential_transaction.take().map(|live| {
                    TransactionCleanup::credential(transaction_id, live.reservation, generation)
                })
            }
        }
    }

    fn install_transaction_timer(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        class: LiveTransactionClass,
        transaction_id: TransactionId,
        deadline: MonotonicTick,
    ) -> Result<(), RuntimeError> {
        let retained = self
            .cleanup_queue
            .len()
            .saturating_add(self.pending_cleanups.len())
            .saturating_add(self.transaction_owners.len());
        if retained >= MAX_PENDING_TRANSACTION_CLEANUPS
            || self.transaction_owners.contains_key(&transaction_id)
        {
            return Err(RuntimeError::LimitExceeded);
        }
        self.transaction_owners
            .insert(transaction_id, (generation, class));
        if context
            .timers_mut()
            .schedule(
                deadline,
                TimerKind::Reservation,
                TimedId::Transaction(transaction_id),
            )
            .is_err()
        {
            return Err(RuntimeError::LimitExceeded);
        }
        Ok(())
    }

    fn transaction_capacity_available(&self) -> bool {
        self.cleanup_queue
            .len()
            .saturating_add(self.pending_cleanups.len())
            .saturating_add(self.transaction_owners.len())
            < MAX_PENDING_TRANSACTION_CLEANUPS
    }

    fn release_finished_transaction(
        &mut self,
        generation: ConnectionGeneration,
        class: LiveTransactionClass,
        transaction_id: TransactionId,
    ) -> Result<(), RuntimeError> {
        match self.transaction_owners.remove(&transaction_id) {
            Some((owner, stored_class)) if owner == generation && stored_class == class => Ok(()),
            Some(owner) => {
                self.transaction_owners.insert(transaction_id, owner);
                Err(RuntimeError::InvalidValue)
            }
            None => Err(RuntimeError::InvalidValue),
        }
    }

    fn queue_transaction_cleanup(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        class: LiveTransactionClass,
        cleanup: TransactionCleanup,
    ) -> Result<(), RuntimeError> {
        if self.cleanup_queue.len().saturating_add(1) > MAX_PENDING_TRANSACTION_CLEANUPS {
            return Err(RuntimeError::LimitExceeded);
        }
        self.cleanup_queue
            .try_reserve(1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        if self.transaction_owners.get(&cleanup.transaction_id) != Some(&(generation, class)) {
            return Err(RuntimeError::InvalidValue);
        }
        self.transaction_owners.remove(&cleanup.transaction_id);
        context.timers_mut().cancel(
            TimerKind::Reservation,
            TimedId::Transaction(cleanup.transaction_id),
        );
        if let TransactionCleanupReservation::Credential { owner, .. } = &cleanup.reservation {
            self.credential_cleanup_owners.insert(*owner);
        }
        self.cleanup_queue.push_back(cleanup);
        Ok(())
    }

    fn queue_unowned_transaction_cleanup(
        &mut self,
        cleanup: TransactionCleanup,
    ) -> Result<(), RuntimeError> {
        let retained = self
            .cleanup_queue
            .len()
            .saturating_add(self.pending_cleanups.len())
            .saturating_add(self.transaction_owners.len());
        if retained >= MAX_PENDING_TRANSACTION_CLEANUPS {
            return Err(RuntimeError::LimitExceeded);
        }
        self.cleanup_queue
            .try_reserve(1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        self.cleanup_queue.push_back(cleanup);
        Ok(())
    }

    fn try_stage_transaction_cleanup(
        &mut self,
        context: &mut StateCoreContext,
    ) -> Result<(), RuntimeError> {
        if self.pending_authority.is_some()
            || !self.pending_cleanups.is_empty()
            || context.pending_len() != 0
        {
            return Ok(());
        }
        if self.cleanup_queue.is_empty() {
            return Ok(());
        }
        let plan = context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let (cleanup_count, writes) = transaction_cleanup_batch(&self.cleanup_queue)?;
        self.pending_cleanups
            .try_reserve_exact(cleanup_count)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
        if !matches!(
            context.stage_durable_with_account_service(plan, fanout, None, 0, writes),
            Ok(StageAccepted::Staged { .. })
        ) {
            return Ok(());
        }
        for _ in 0..cleanup_count {
            let cleanup = self
                .cleanup_queue
                .pop_front()
                .ok_or(RuntimeError::InvalidValue)?;
            self.pending_cleanups.push(cleanup);
        }
        Ok(())
    }

    fn complete_transaction_cleanup(
        &mut self,
        cleanup: TransactionCleanup,
    ) -> Result<(), RuntimeError> {
        if cleanup.recovered {
            self.startup_cleanup_remaining = self
                .startup_cleanup_remaining
                .checked_sub(1)
                .ok_or(RuntimeError::InvalidValue)?;
        }
        if let TransactionCleanupReservation::Credential { account_id, owner } = cleanup.reservation
        {
            self.release_credential_reservation(account_id, owner)?;
            self.credential_cleanup_owners.remove(&owner);
        }
        Ok(())
    }

    fn schedule_login_tombstone(
        &mut self,
        context: &mut StateCoreContext,
        tombstone_id: (u64, AccountId),
    ) -> Result<(), RuntimeError> {
        if self.scheduled_login_tombstone == Some(tombstone_id) {
            return Ok(());
        }
        let deadline = login_tombstone_deadline(context, tombstone_id.0)?;
        context
            .timers_mut()
            .schedule(deadline, TimerKind::Reservation, TimedId::Global)?;
        self.scheduled_login_tombstone = Some(tombstone_id);
        Ok(())
    }

    fn schedule_login_tombstone_retry(
        &mut self,
        context: &mut StateCoreContext,
    ) -> Result<(), RuntimeError> {
        let Some(tombstone_id) = self
            .config
            .login_deletion_tombstones
            .first_key_value()
            .map(|(tombstone_id, _)| *tombstone_id)
        else {
            context
                .timers_mut()
                .cancel(TimerKind::Reservation, TimedId::Global);
            self.scheduled_login_tombstone = None;
            return Ok(());
        };
        let deadline = context
            .now()
            .checked_add(DRIFT_CHECK_INTERVAL_MILLIS)
            .map_err(|_| RuntimeError::Overflow)?;
        context
            .timers_mut()
            .schedule(deadline, TimerKind::Reservation, TimedId::Global)?;
        self.scheduled_login_tombstone = Some(tombstone_id);
        Ok(())
    }

    fn schedule_next_login_tombstone(
        &mut self,
        context: &mut StateCoreContext,
    ) -> Result<(), RuntimeError> {
        let Some(tombstone_id) = self
            .config
            .login_deletion_tombstones
            .first_key_value()
            .map(|(tombstone_id, _)| *tombstone_id)
        else {
            context
                .timers_mut()
                .cancel(TimerKind::Reservation, TimedId::Global);
            self.scheduled_login_tombstone = None;
            return Ok(());
        };
        self.schedule_login_tombstone(context, tombstone_id)
    }

    fn try_stage_login_tombstone_expiry(
        &mut self,
        context: &mut StateCoreContext,
    ) -> Result<(), RuntimeError> {
        if !self.exclusive_account_service_transition_available() || context.pending_len() != 0 {
            return self.schedule_login_tombstone_retry(context);
        }
        if !context.drift().wall_trusted() {
            return self.schedule_login_tombstone_retry(context);
        }
        let Ok(now_utc) = context.utc_now() else {
            return self.schedule_login_tombstone_retry(context);
        };
        let Some(batch) = login_tombstone_expiry_batch(
            &self.config.login_deletion_tombstones,
            self.config.login_index_key_state,
            now_utc,
        )?
        else {
            return self.schedule_next_login_tombstone(context);
        };
        let plan = context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
        if let Some(successor) = batch.successor {
            self.schedule_login_tombstone(context, successor)?;
        }
        if matches!(
            context.stage_durable_with_account_service(plan, fanout, None, 0, batch.writes),
            Ok(StageAccepted::Staged { .. })
        ) {
            self.pending_login_tombstone_expiry = Some(batch.pending);
            return Ok(());
        }
        self.schedule_next_login_tombstone(context)
    }

    /// Starts deleting fully validated connection-bound rows recovered from
    /// the prior process before any new account connection is accepted.
    pub(crate) fn startup(&mut self, context: &mut StateCoreContext) {
        let _scheduled = self.schedule_next_login_tombstone(context);
        let _staged = self.try_stage_transaction_cleanup(context);
    }

    /// Returns a committed pre-registration account binding without exposing
    /// any request or credential material.
    pub(crate) fn authenticated_binding(
        &self,
        generation: ConnectionGeneration,
        now: MonotonicTick,
    ) -> Result<Option<(AccountId, Generation)>, RuntimeError> {
        let binding = self
            .connections
            .get(&generation)
            .and_then(|connection| connection.authenticated.as_ref());
        match binding {
            Some(binding) if now < binding.process_expires_at() => Ok(Some((
                binding.account_id(),
                binding.account_session_generation(),
            ))),
            Some(_) => Err(RuntimeError::InvalidValue),
            None => Ok(None),
        }
    }

    /// Constructs the one durable delete that consumes a pre-registration
    /// grant with its matching session-open plan.
    pub(crate) fn registration_grant_write(
        &self,
        generation: ConnectionGeneration,
        now: MonotonicTick,
    ) -> Result<AccountServiceDurableWrite, RuntimeError> {
        let binding = self
            .connections
            .get(&generation)
            .and_then(|connection| connection.authenticated.as_ref())
            .ok_or(RuntimeError::InvalidValue)?;
        if now >= binding.process_expires_at()
            || self.transaction_owners.get(&binding.transaction_id)
                != Some(&(generation, LiveTransactionClass::AuthenticationGrant))
            || self.grant_consumptions.contains_key(&generation)
        {
            return Err(RuntimeError::InvalidValue);
        }
        AccountServiceDurableWrite::delete(
            TableId::AuthTransaction,
            StoredKey::new(binding.transaction_id.as_bytes().to_vec())?,
        )
    }

    /// Moves one live grant timer into an in-flight registration barrier.
    pub(crate) fn begin_registration_grant_consumption(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Result<(), RuntimeError> {
        if self.grant_consumptions.contains_key(&generation) {
            return Err(RuntimeError::InvalidValue);
        }
        let transaction_id = self
            .connections
            .get(&generation)
            .and_then(|connection| connection.authenticated.as_ref())
            .map(|binding| binding.transaction_id)
            .ok_or(RuntimeError::InvalidValue)?;
        self.release_finished_transaction(
            generation,
            LiveTransactionClass::AuthenticationGrant,
            transaction_id,
        )?;
        context
            .timers_mut()
            .cancel(TimerKind::Reservation, TimedId::Transaction(transaction_id));
        self.grant_consumptions.insert(generation, transaction_id);
        Ok(())
    }

    /// Restores a grant timer when session-open could not enter a durable
    /// batch and no grant row was consumed.
    pub(crate) fn cancel_registration_grant_consumption(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Result<(), RuntimeError> {
        let transaction_id = self
            .grant_consumptions
            .remove(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        let deadline = self
            .connections
            .get(&generation)
            .and_then(|connection| connection.authenticated.as_ref())
            .filter(|binding| binding.transaction_id == transaction_id)
            .map(AuthenticatedBinding::process_expires_at)
            .ok_or(RuntimeError::InvalidValue)?;
        self.install_transaction_timer(
            context,
            generation,
            LiveTransactionClass::AuthenticationGrant,
            transaction_id,
            deadline,
        )
    }

    /// Applies a fresh-auth proof after registration has inserted a session
    /// that was already authenticated during CAP negotiation.
    pub(crate) fn registration_committed(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        user_id: agenc_ircd_types::UserId,
    ) -> Result<(), RuntimeError> {
        let transaction_id = self
            .grant_consumptions
            .remove(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        let binding = self
            .connections
            .get_mut(&generation)
            .and_then(|connection| connection.authenticated.take());
        let Some(binding) = binding else {
            return Ok(());
        };
        if binding.transaction_id != transaction_id {
            return Err(RuntimeError::InvalidValue);
        }
        let session = context
            .domain()
            .session(user_id)
            .ok_or(RuntimeError::InvalidValue)?;
        if session.account_id() != Some(binding.account_id())
            || session.account_session_generation() != binding.account_session_generation()
        {
            return Err(RuntimeError::InvalidValue);
        }
        let plan = context
            .domain()
            .plan_session_fresh_authentication(
                user_id,
                binding.account_id(),
                session.generation(),
                binding.authenticated_at,
            )
            .map_err(|_| RuntimeError::InvalidValue)?;
        let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
        context
            .apply_ephemeral(plan, fanout)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let proof = binding.grant.into_fresh_authentication_after_commit();
        let credential_id = duplicate_credential_id(proof.credential_id_for_replacement());
        let connection = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        connection.credential_id = Some(credential_id);
        connection.fresh_authentication = Some(proof);
        Ok(())
    }

    /// Drops an uncommitted registration grant and schedules its durable row
    /// for deletion after a determinate batch rejection.
    pub(crate) fn registration_rejected(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Result<(), RuntimeError> {
        let transaction_id = *self
            .grant_consumptions
            .get(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        if self
            .connections
            .get(&generation)
            .and_then(|connection| connection.authenticated.as_ref())
            .is_some_and(|binding| binding.transaction_id != transaction_id)
        {
            return Err(RuntimeError::InvalidValue);
        }
        self.grant_consumptions.remove(&generation);
        if let Some(connection) = self.connections.get_mut(&generation) {
            connection.authenticated = None;
        }
        self.queue_unowned_transaction_cleanup(TransactionCleanup::authentication(transaction_id))?;
        let _staged = self.try_stage_transaction_cleanup(context);
        Ok(())
    }

    /// Retains one account-deletion invalidation set before its domain plan
    /// enters the same durable batch.
    pub(crate) fn begin_account_deletion(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        account_id: AccountId,
    ) -> Result<Vec<AccountServiceDurableWrite>, RuntimeError> {
        if !self.account_deletion_transition_available(account_id)
            || !self.pending_account_deletions.is_empty()
        {
            return Err(RuntimeError::LimitExceeded);
        }
        if !context.drift().wall_trusted() {
            return Err(RuntimeError::InvalidValue);
        }
        let now_utc = context.utc_now().map_err(|_| RuntimeError::InvalidValue)?;
        let expires_at = now_utc
            .checked_add(LOGIN_DELETION_TOMBSTONE_SECONDS)
            .map_err(|_| RuntimeError::Overflow)?;
        let login_key = self
            .config
            .live_login_keys
            .get(&account_id)
            .cloned()
            .ok_or(RuntimeError::InvalidValue)?;
        let (authentications, grants) = self.account_deletion_authorities(account_id)?;
        let writes = account_deletion_writes(
            account_id,
            expires_at,
            &login_key,
            &authentications,
            &grants,
        )?;
        let completions = account_deletion_completions(generation, &authentications, &grants)?;
        let tombstone_id = (expires_at.get(), account_id);
        if self
            .config
            .login_deletion_tombstones
            .contains_key(&tombstone_id)
        {
            return Err(RuntimeError::InvalidValue);
        }
        self.config
            .login_deletion_tombstones
            .insert(tombstone_id, login_key);
        if let Err(error) = self.schedule_next_login_tombstone(context) {
            self.config.login_deletion_tombstones.remove(&tombstone_id);
            return Err(error);
        }
        let pending = AccountDeletionBarrier {
            account_id,
            tombstone_id,
            authentications,
            grants,
            completions,
        };
        if self
            .pending_account_deletions
            .insert(generation, pending)
            .is_some()
        {
            self.config.login_deletion_tombstones.remove(&tombstone_id);
            self.scheduled_login_tombstone = None;
            let _rescheduled = self.schedule_next_login_tombstone(context);
            return Err(RuntimeError::InvalidValue);
        }
        Ok(writes)
    }

    fn account_deletion_authorities(
        &self,
        account_id: AccountId,
    ) -> Result<DeletionAuthorities, RuntimeError> {
        let mut authentications = Vec::new();
        let mut grants = Vec::new();
        authentications
            .try_reserve_exact(self.connections.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        grants
            .try_reserve_exact(self.connections.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for (connection_generation, connection) in &self.connections {
            if let Some(authentication) = connection
                .transaction
                .as_ref()
                .filter(|authentication| authentication.account_id == Some(account_id))
            {
                authentications.push((
                    *connection_generation,
                    authentication.transaction.binding().transaction_id(),
                ));
            }
            if let Some(binding) = connection
                .authenticated
                .as_ref()
                .filter(|binding| binding.account_id() == account_id)
            {
                grants.push((*connection_generation, binding.transaction_id));
            }
        }
        Ok((authentications, grants))
    }

    fn account_deletion_transition_available(&self, account_id: AccountId) -> bool {
        self.exclusive_account_service_transition_available()
            && !self.credential_reservations.contains_key(&account_id)
    }

    fn exclusive_account_service_transition_available(&self) -> bool {
        self.pending_authority.is_none()
            && self.pending_cleanups.is_empty()
            && self.cleanup_queue.is_empty()
            && self.reads.is_empty()
            && self.crypto.is_empty()
            && self.ready_seals.is_empty()
            && self.ready_stage.is_none()
            && self.grant_consumptions.is_empty()
            && self.pending_account_deletions.is_empty()
            && self.pending_login_tombstone_expiry.is_none()
    }

    /// Rolls back a deletion barrier that could not enter a durable batch.
    pub(crate) fn cancel_account_deletion(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Result<(), RuntimeError> {
        let pending = self
            .pending_account_deletions
            .remove(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        self.remove_uncommitted_account_tombstone(context, pending.tombstone_id)
    }

    /// Drops one determinate rejected deletion barrier.
    pub(crate) fn account_deletion_rejected(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> bool {
        let Some(pending) = self.pending_account_deletions.remove(&generation) else {
            return false;
        };
        let _removed = self.remove_uncommitted_account_tombstone(context, pending.tombstone_id);
        true
    }

    fn remove_uncommitted_account_tombstone(
        &mut self,
        context: &mut StateCoreContext,
        tombstone_id: (u64, AccountId),
    ) -> Result<(), RuntimeError> {
        self.config
            .login_deletion_tombstones
            .remove(&tombstone_id)
            .ok_or(RuntimeError::InvalidValue)?;
        self.schedule_next_login_tombstone(context)
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
        let mut result = ResultClass::Ok;
        for action in actions {
            if sasl_action_result(&action) == ResultClass::Rejected {
                result = ResultClass::Rejected;
            }
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
        CarrierRoute::Finished { frames, result }
    }

    /// Routes one grammar-validated account-creation or credential carrier line.
    pub(crate) fn route_account(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        target: &str,
        kind: AccountCarrierKind,
        mut message: ParsedMessage,
    ) -> CarrierRoute {
        let has_tags = !message.tags().is_empty();
        let Some(subcommand) = message.take_parameter(0) else {
            return CarrierRoute::Close;
        };
        let parameter = message.take_parameter(1);
        let now = context.now().get();
        let (route, result) = {
            let Some(connection) = self.connections.get_mut(&generation) else {
                return CarrierRoute::Close;
            };
            let transfer = match kind {
                AccountCarrierKind::Create => &mut connection.creation,
                AccountCarrierKind::Credentials => &mut connection.credentials,
            };
            (
                connection.route,
                transfer.client(&subcommand, parameter.as_deref(), has_tags, now),
            )
        };
        let Ok(actions) = result else {
            return self.fail_account_route(context, generation, kind);
        };
        let mut frames = Vec::new();
        for action in actions {
            match action {
                AccountCarrierAction::RequestEnvelope { phase, bytes } => {
                    return self.route_account_envelope(
                        context,
                        generation,
                        carrier_generation,
                        target,
                        route,
                        kind,
                        phase,
                        bytes,
                    );
                }
                action => match render_account_action(context.server_prefix(), kind, action) {
                    Ok(frame) => frames.push(frame),
                    Err(_) => return CarrierRoute::Close,
                },
            }
        }
        CarrierRoute::Finished {
            frames,
            result: ResultClass::Ok,
        }
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-29 reason=the fixed account carrier tuple preserves the exact connection route and transfer phase
    #[allow(clippy::too_many_arguments)]
    fn route_account_envelope(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        target: &str,
        route: ConnectionRoute,
        kind: AccountCarrierKind,
        phase: AccountCarrierPhase,
        bytes: SecretBytes,
    ) -> CarrierRoute {
        let Ok(encoded) = bytes.expose().try_into() else {
            return CarrierRoute::Close;
        };
        let Ok(envelope) = AccountServiceEnvelope::parse(encoded) else {
            return self.fail_account_route(context, generation, kind);
        };
        let request = RequestContext {
            generation,
            carrier_generation,
            target: target.to_owned(),
            route,
            envelope,
            carrier: RequestCarrier::Account(kind),
            phase,
        };
        if request.envelope.message_kind() != request.expected_message_kind() {
            return self.fail_account_route(context, generation, kind);
        }
        if self.submit_replay_read(context, request).is_err() {
            return CarrierRoute::Close;
        }
        CarrierRoute::Pending
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
        let phase = if finish {
            AccountCarrierPhase::Finish
        } else {
            AccountCarrierPhase::Start
        };
        let expected = match phase {
            AccountCarrierPhase::Start => AccountServiceMessageKind::OpaqueAuthStart,
            AccountCarrierPhase::Finish => AccountServiceMessageKind::OpaqueAuthFinish,
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
            carrier: RequestCarrier::Sasl,
            phase,
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
            return self.route_preregistered_logout(context, generation);
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
        match context.stage_durable(plan, fanout, Some(StagedOrigin::silent(generation)), 0) {
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
                CarrierRoute::Finished {
                    frames: Vec::new(),
                    result: ResultClass::Ok,
                }
            }
            Err(_) => self.reject_logout(context, generation, target),
        }
    }

    fn route_preregistered_logout(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> CarrierRoute {
        let Some((transaction_id, logout_completed)) = self
            .connections
            .get_mut(&generation)
            .and_then(|connection| {
                connection.authenticated.take().map(|binding| {
                    (
                        binding.transaction_id,
                        connection.sasl.complete_logout().is_ok(),
                    )
                })
            })
        else {
            return CarrierRoute::Close;
        };
        let queued = self
            .queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::AuthenticationGrant,
                TransactionCleanup::authentication(transaction_id),
            )
            .is_ok();
        if queued {
            let _staged = self.try_stage_transaction_cleanup(context);
        }
        if !logout_completed || !queued {
            return CarrierRoute::Close;
        }
        CarrierRoute::Finished {
            frames: Vec::new(),
            result: ResultClass::Ok,
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
            Ok(frames) => CarrierRoute::Finished {
                frames,
                result: ResultClass::Rejected,
            },
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
            Ok(frames) => CarrierRoute::Finished {
                frames,
                result: ResultClass::Rejected,
            },
            Err(_) => CarrierRoute::Close,
        }
    }

    fn fail_account_route(
        &mut self,
        context: &StateCoreContext,
        generation: ConnectionGeneration,
        kind: AccountCarrierKind,
    ) -> CarrierRoute {
        let Some(connection) = self.connections.get_mut(&generation) else {
            return CarrierRoute::Close;
        };
        match kind {
            AccountCarrierKind::Create => connection.creation.reject(),
            AccountCarrierKind::Credentials => connection.credentials.reject(),
        }
        match account_failure(context.server_prefix(), kind) {
            Ok(frame) => CarrierRoute::Finished {
                frames: vec![frame],
                result: ResultClass::Rejected,
            },
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
        let carrier_generation = pending.carrier_generation();
        let Ok(output) = message.output else {
            return vec![self.close_completion(&pending)];
        };
        let result = self.apply_crypto_output(context, pending, output);
        match result {
            Ok(mut completions) => {
                completions.extend(self.progress(context));
                completions
            }
            Err(_) => vec![CarrierCompletion::closed(generation, carrier_generation)],
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
                PendingCrypto::CreationPreflight { request },
                CryptoJobOutput::CreationPreflight(output),
            ) => {
                let rate_available = match output.verified_invite {
                    Some(invite_id) => {
                        self.charge_creation_key(context, BucketKey::Invite(invite_id))?
                    }
                    None => true,
                };
                self.begin_creation_reads(context, request, output.request, rate_available)?;
                Ok(Vec::new())
            }
            (PendingCrypto::CreationStart { request }, CryptoJobOutput::CreationStart(output)) => {
                let outcome = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                self.push_ready_seal(ReadySeal::CreationStart { request, outcome })?;
                Ok(Vec::new())
            }
            (
                PendingCrypto::CreationStartSeal { request },
                CryptoJobOutput::CreationStartSealed(output),
            ) => {
                let sealed = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                if self.ready_stage.is_some() {
                    return Err(RuntimeError::InvalidValue);
                }
                self.ready_stage = Some(ReadyStage::CreationStart { request, sealed });
                Ok(Vec::new())
            }
            (
                PendingCrypto::CreationFinish {
                    request,
                    transaction_id,
                    reservation,
                },
                CryptoJobOutput::CreationFinish(output),
            ) => {
                if output.transaction.binding().transaction_id() != transaction_id {
                    return Err(RuntimeError::InvalidValue);
                }
                let outcome = output.outcome.map_err(|_| RuntimeError::InvalidValue)?;
                self.push_ready_seal(ReadySeal::CreationFinish {
                    request,
                    transaction_id,
                    outcome,
                    reservation,
                })?;
                Ok(Vec::new())
            }
            (
                PendingCrypto::CreationFinishSeal {
                    request,
                    transaction_id,
                    reservation,
                },
                CryptoJobOutput::CreationFinishSealed(output),
            ) => {
                let sealed = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                if self.ready_stage.is_some() {
                    return Err(RuntimeError::InvalidValue);
                }
                self.ready_stage = Some(ReadyStage::CreationFinish {
                    request,
                    transaction_id,
                    sealed,
                    reservation,
                });
                Ok(Vec::new())
            }
            (
                PendingCrypto::CredentialStart {
                    request,
                    reservation,
                },
                CryptoJobOutput::CredentialStart(output),
            ) => {
                let outcome = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                self.push_ready_seal(ReadySeal::CredentialStart {
                    request,
                    outcome,
                    reservation,
                })?;
                Ok(Vec::new())
            }
            (
                PendingCrypto::CredentialStartSeal {
                    request,
                    reservation,
                },
                CryptoJobOutput::CredentialStartSealed(output),
            ) => {
                let sealed = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                if self.ready_stage.is_some() {
                    return Err(RuntimeError::InvalidValue);
                }
                self.ready_stage = Some(ReadyStage::CredentialStart {
                    request,
                    sealed,
                    reservation,
                });
                Ok(Vec::new())
            }
            (
                PendingCrypto::CredentialFinish {
                    request,
                    transaction_id,
                    reservation,
                },
                CryptoJobOutput::CredentialFinish(output),
            ) => {
                if output.transaction.binding().transaction_id() != transaction_id {
                    return Err(RuntimeError::InvalidValue);
                }
                let outcome = output.outcome.map_err(|_| RuntimeError::InvalidValue)?;
                self.push_ready_seal(ReadySeal::CredentialFinish {
                    request,
                    transaction_id,
                    outcome,
                    reservation,
                })?;
                Ok(Vec::new())
            }
            (
                PendingCrypto::CredentialFinishSeal {
                    request,
                    transaction_id,
                    reservation,
                },
                CryptoJobOutput::CredentialFinishSealed(output),
            ) => {
                let sealed = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                if self.ready_stage.is_some() {
                    return Err(RuntimeError::InvalidValue);
                }
                self.ready_stage = Some(ReadyStage::CredentialFinish {
                    request,
                    transaction_id,
                    sealed,
                    reservation,
                });
                Ok(Vec::new())
            }
            (
                PendingCrypto::Start {
                    request,
                    account_id,
                    login,
                    previous_value,
                },
                CryptoJobOutput::OpaqueStart(output),
            ) => {
                let outcome = (*output).map_err(|_| RuntimeError::InvalidValue)?;
                self.push_ready_seal(ReadySeal::Start {
                    request,
                    outcome,
                    account_id,
                    login,
                    previous_value,
                })?;
                Ok(Vec::new())
            }
            (
                PendingCrypto::StartSeal {
                    request,
                    account_id,
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
                    account_id,
                    login,
                    previous_value,
                });
                Ok(Vec::new())
            }
            (
                PendingCrypto::Finish {
                    request,
                    transaction_id,
                    account_id,
                    login,
                    previous_value,
                    authenticated_at,
                },
                CryptoJobOutput::OpaqueFinish(output),
            ) => {
                let outcome = output.outcome.map_err(|_| RuntimeError::InvalidValue)?;
                if let Ok(grant) = outcome.result()
                    && account_id != Some(grant.account_id())
                {
                    return Err(RuntimeError::InvalidValue);
                }
                let operation_is_available = match outcome.result() {
                    Ok(grant) => {
                        self.authentication_finish_available(context, request.generation, grant)
                    }
                    Err(_) => true,
                };
                let outcome = outcome
                    .reject_when_unavailable(operation_is_available)
                    .map_err(|_| RuntimeError::InvalidValue)?;
                self.push_ready_seal(ReadySeal::Finish {
                    request,
                    transaction_id,
                    outcome,
                    account_id,
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
                    account_id,
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
                    account_id,
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
            OpenedAccountServiceRequest::CreationStart(opened) if !request.is_finish() => {
                self.open_creation_start(context, request, opened)
            }
            OpenedAccountServiceRequest::CreationFinish(opened) if request.is_finish() => {
                self.open_creation_finish(context, request, opened)
            }
            OpenedAccountServiceRequest::CredentialChangeStart(opened) if !request.is_finish() => {
                self.open_credential_start(context, request, opened)
            }
            OpenedAccountServiceRequest::CredentialChangeFinish(opened) if request.is_finish() => {
                self.open_credential_finish(context, request, opened)
            }
            OpenedAccountServiceRequest::AuthenticationStart(opened) if !request.is_finish() => {
                self.open_authentication_start(context, request, opened)
            }
            OpenedAccountServiceRequest::AuthenticationFinish(opened) if request.is_finish() => {
                self.open_authentication_finish(context, request, opened)
            }
            _ => self.fail_pending(context, request),
        }
    }

    fn open_creation_start(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationStart>,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        if self
            .connections
            .get(&request.generation)
            .is_none_or(|connection| connection.creation_transaction.is_some())
        {
            return self.fail_pending(context, request);
        }
        match self.config.creation_policy {
            AccountCreationPolicy::Invite(authority) => {
                let now = context.utc_now().map_err(|_| RuntimeError::InvalidValue)?;
                let job = RuntimeCryptoJob::CreationPreflight(Box::new(CreationPreflightJob::new(
                    opened,
                    authority,
                    self.config.network_id,
                    now,
                )));
                self.submit_crypto(context, PendingCrypto::CreationPreflight { request }, job)?;
            }
            AccountCreationPolicy::Open | AccountCreationPolicy::Closed => {
                let rate_available =
                    self.charge_creation_connection(context, request.generation)?;
                self.begin_creation_reads(context, request, opened, rate_available)?;
            }
        }
        Ok(Vec::new())
    }

    fn open_creation_finish(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationFinish>,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let Some(live) = self
            .connections
            .get_mut(&request.generation)
            .and_then(|connection| connection.creation_transaction.take())
        else {
            return self.fail_pending(context, request);
        };
        let transaction_id = live.transaction.binding().transaction_id();
        context
            .timers_mut()
            .cancel(TimerKind::Reservation, TimedId::Transaction(transaction_id));
        let generation = request.generation;
        let cleanup = TransactionCleanup::creation(transaction_id, live.reservation.clone());
        let operation = match self.operation_context(context, request.route) {
            Ok(operation) => operation,
            Err(error) => {
                let _queued = self.queue_transaction_cleanup(
                    context,
                    generation,
                    LiveTransactionClass::Creation,
                    cleanup,
                );
                return Err(error);
            }
        };
        let job = RuntimeCryptoJob::CreationFinish(Box::new(CreationFinishJob::new(
            live.transaction,
            operation,
            opened,
        )));
        let submitted = self.submit_crypto(
            context,
            PendingCrypto::CreationFinish {
                request,
                transaction_id,
                reservation: live.reservation,
            },
            job,
        );
        if let Err(error) = submitted {
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::Creation,
                cleanup,
            );
            return Err(error);
        }
        Ok(Vec::new())
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=credential START gathers one registered snapshot consumes one proof reserves one account and submits one fixed consistency read without exposing private predicates
    fn open_credential_start(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CredentialChangeStart>,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let bound = context
            .sessions()
            .connection(request.generation)
            .and_then(|entry| entry.session())
            .ok_or(RuntimeError::InvalidValue)?;
        let session = context
            .domain()
            .session(bound.user_id)
            .ok_or(RuntimeError::InvalidValue)?;
        let account_id = session.account_id().ok_or(RuntimeError::InvalidValue)?;
        let fresh_auth_deadline = session.fresh_auth_deadline();
        let account = context
            .domain()
            .account(account_id)
            .ok_or(RuntimeError::InvalidValue)?;
        let snapshot = DestructiveAccountSnapshot::new(
            account_id,
            account.revision(),
            account.session_generation(),
        );
        let demand = BucketDemand::new(
            BucketKind::CredentialChange,
            BucketKey::Account(account_id),
            1,
        )?;
        let now = context.now();
        if context
            .buckets_mut()
            .charge_all_or_nothing(now, &[demand])
            .is_err()
        {
            return self.fail_pending(context, request);
        }
        let authentication_in_flight = self.account_authentication_in_flight(account_id);
        let connection = self
            .connections
            .get_mut(&request.generation)
            .ok_or(RuntimeError::InvalidValue)?;
        if connection.credential_transaction.is_some() {
            return self.fail_pending(context, request);
        }
        let proof = connection.fresh_authentication.take();
        let credential_id = connection
            .credential_id
            .as_ref()
            .map(duplicate_credential_id)
            .or_else(|| {
                proof
                    .as_ref()
                    .map(FreshAuthenticationProof::credential_id_for_replacement)
                    .map(duplicate_credential_id)
            })
            .unwrap_or_else(|| agenc_ircd_types::OpaqueCredentialId::from_bytes([0_u8; 32]));
        let fresh_deadline_valid = fresh_auth_deadline.is_some_and(|deadline| now <= deadline);
        let operation_available = opened.payload().account_id == account_id
            && proof.is_some()
            && connection.credential_id.is_some()
            && fresh_deadline_valid
            && !authentication_in_flight
            && !self.credential_reservations.contains_key(&account_id);
        let reservation = operation_available.then_some(account_id);
        if reservation.is_some()
            && self
                .credential_reservations
                .insert(account_id, request.generation)
                .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        let record_key = if connection.credential_id.is_some() {
            StoredKey::new(account_id.to_text().into_bytes())?
        } else {
            StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?
        };
        let read_id = context
            .submit_storage_read(ReadPlan::exact(TableId::OpaqueRecord, record_key.clone()))?;
        if self
            .reads
            .insert(
                read_id,
                PendingRead::CredentialOpaque {
                    request,
                    opened,
                    account: snapshot,
                    credential_id,
                    proof,
                    reservation,
                    record_key,
                },
            )
            .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Vec::new())
    }

    fn account_authentication_in_flight(&self, account_id: AccountId) -> bool {
        let live = self.connections.values().any(|connection| {
            connection
                .transaction
                .as_ref()
                .is_some_and(|transaction| transaction.account_id == Some(account_id))
        });
        let crypto = self.crypto.values().any(|pending| match pending {
            PendingCrypto::Start {
                account_id: candidate,
                ..
            }
            | PendingCrypto::StartSeal {
                account_id: candidate,
                ..
            }
            | PendingCrypto::Finish {
                account_id: candidate,
                ..
            }
            | PendingCrypto::FinishSeal {
                account_id: candidate,
                ..
            } => *candidate == Some(account_id),
            _ => false,
        });
        let ready_seal = self.ready_seals.iter().any(|ready| match ready {
            ReadySeal::Start {
                account_id: candidate,
                ..
            }
            | ReadySeal::Finish {
                account_id: candidate,
                ..
            } => *candidate == Some(account_id),
            _ => false,
        });
        let ready_stage = self.ready_stage.as_ref().is_some_and(|ready| match ready {
            ReadyStage::Start {
                account_id: candidate,
                ..
            }
            | ReadyStage::Finish {
                account_id: candidate,
                ..
            } => *candidate == Some(account_id),
            _ => false,
        });
        let authority = self
            .pending_authority
            .as_ref()
            .is_some_and(|authority| match authority {
                PendingAuthority::Start {
                    account_id: candidate,
                    ..
                }
                | PendingAuthority::Finish {
                    account_id: candidate,
                    ..
                } => *candidate == Some(account_id),
                _ => false,
            });
        live || crypto || ready_seal || ready_stage || authority
    }

    fn open_credential_finish(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CredentialChangeFinish>,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let Some(live) = self
            .connections
            .get_mut(&request.generation)
            .and_then(|connection| connection.credential_transaction.take())
        else {
            return self.fail_pending(context, request);
        };
        let transaction_id = live.transaction.binding().transaction_id();
        context
            .timers_mut()
            .cancel(TimerKind::Reservation, TimedId::Transaction(transaction_id));
        let generation = request.generation;
        let reservation = live.reservation;
        let cleanup = TransactionCleanup::credential(transaction_id, reservation, generation);
        let operation = match self.operation_context(context, request.route) {
            Ok(operation) => operation,
            Err(error) => {
                let _queued = self.queue_transaction_cleanup(
                    context,
                    generation,
                    LiveTransactionClass::CredentialChange,
                    cleanup,
                );
                return Err(error);
            }
        };
        let job = RuntimeCryptoJob::CredentialFinish(Box::new(CredentialFinishJob::new(
            live.transaction,
            operation,
            opened,
        )));
        let submitted = self.submit_crypto(
            context,
            PendingCrypto::CredentialFinish {
                request,
                transaction_id,
                reservation,
            },
            job,
        );
        if let Err(error) = submitted {
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::CredentialChange,
                cleanup,
            );
            return Err(error);
        }
        Ok(Vec::new())
    }

    fn begin_creation_reads(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationStart>,
        rate_available: bool,
    ) -> Result<(), RuntimeError> {
        let schedule = LoginIndexLookupSchedule::new(
            self.config.network_id,
            &opened.payload().login,
            self.config.login_index_key_state,
            &self.config.current_login_index_key,
            self.config.previous_login_index_key.as_deref(),
        )?;
        let key = schedule.current().encode()?;
        let read_id = context.submit_storage_read(ReadPlan::exact(TableId::LoginIndex, key))?;
        if self
            .reads
            .insert(
                read_id,
                PendingRead::CreationCurrentIndex {
                    request,
                    opened,
                    schedule,
                    rate_available,
                },
            )
            .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }

    fn charge_creation_connection(
        &self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Result<bool, RuntimeError> {
        let entry = context
            .sessions()
            .connection(generation)
            .ok_or(RuntimeError::InvalidValue)?;
        let key = match entry.admission() {
            AdmissionClass::Direct => BucketKey::Prefix(entry.source_prefix()),
            AdmissionClass::Onion => BucketKey::OnionListener,
            AdmissionClass::Admin => return Err(RuntimeError::InvalidValue),
        };
        self.charge_creation_key(context, key)
    }

    fn charge_creation_key(
        &self,
        context: &mut StateCoreContext,
        key: BucketKey,
    ) -> Result<bool, RuntimeError> {
        let demand = BucketDemand::new(BucketKind::AccountCreation, key, 1)?;
        let now = context.now();
        Ok(context
            .buckets_mut()
            .charge_all_or_nothing(now, &[demand])
            .is_ok())
    }

    fn open_authentication_start(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<AuthenticationStart>,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let attempt = self
            .connections
            .get_mut(&request.generation)
            .ok_or(RuntimeError::InvalidValue)
            .and_then(|connection| {
                consume_opaque_connection_attempt(&mut connection.opaque_attempts)
            });
        if attempt.is_err() {
            return self.fail_pending(context, request);
        }
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
        let read_id = context.submit_storage_read(ReadPlan::exact(TableId::LoginIndex, key))?;
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

    fn open_authentication_finish(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<agenc_ircd_auth::AuthenticationFinish>,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let Some(live) = self
            .connections
            .get_mut(&request.generation)
            .and_then(|connection| connection.transaction.take())
        else {
            return self.fail_pending(context, request);
        };
        let transaction_id = live.transaction.binding().transaction_id();
        context
            .timers_mut()
            .cancel(TimerKind::Reservation, TimedId::Transaction(transaction_id));
        let generation = request.generation;
        let cleanup = TransactionCleanup::authentication(transaction_id);
        let operation = match self.operation_context(context, request.route) {
            Ok(operation) => operation,
            Err(error) => {
                let _queued = self.queue_transaction_cleanup(
                    context,
                    generation,
                    LiveTransactionClass::Authentication,
                    cleanup,
                );
                return Err(error);
            }
        };
        let job = RuntimeCryptoJob::OpaqueFinish(Box::new(OpaqueFinishJob::new(
            live.transaction,
            operation,
            opened,
        )));
        let pending = PendingCrypto::Finish {
            request,
            transaction_id,
            account_id: live.account_id,
            login: live.login,
            previous_value: live.previous_value,
            authenticated_at: context.now(),
        };
        if let Err(error) = self.submit_crypto(context, pending, job) {
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::Authentication,
                cleanup,
            );
            return Err(error);
        }
        Ok(Vec::new())
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

    fn authentication_finish_available(
        &self,
        context: &StateCoreContext,
        generation: ConnectionGeneration,
        grant: &AuthenticationGrant,
    ) -> bool {
        let account_not_suspended = context.utc_now().is_ok_and(|now| {
            !context
                .domain()
                .account_is_suspended(grant.account_id(), now)
        });
        let account_is_current =
            context
                .domain()
                .account(grant.account_id())
                .is_some_and(|account| {
                    account.session_generation() == grant.account_session_generation()
                });
        if !account_is_current || !account_not_suspended {
            return false;
        }
        let Some(connection) = context.sessions().connection(generation) else {
            return false;
        };
        let Some(bound) = connection.session() else {
            return self
                .connections
                .get(&generation)
                .is_some_and(|connection| connection.authenticated.is_none());
        };
        context
            .domain()
            .session(bound.user_id)
            .is_some_and(|session| {
                session
                    .account_id()
                    .is_none_or(|account_id| account_id == grant.account_id())
            })
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
        let close = CarrierCompletion::closed(pending.generation(), pending.carrier_generation());
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

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=closed read-continuation dispatcher keeps every move-only opened request paired with its exact storage result
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
            PendingRead::CreationCurrentIndex {
                request,
                opened,
                schedule,
                rate_available,
            } => self.creation_current_index_read(
                context,
                request,
                opened,
                schedule,
                rate_available,
                result,
            ),
            PendingRead::CreationPreviousIndex {
                request,
                opened,
                schedule,
                current_available,
                rate_available,
            } => self.creation_previous_index_read(
                context,
                request,
                opened,
                schedule,
                current_available,
                rate_available,
                result,
            ),
            PendingRead::CreationInvitation {
                request,
                opened,
                login_available,
                rate_available,
                invitation_key,
            } => self.creation_invitation_read(
                context,
                request,
                opened,
                login_available,
                rate_available,
                invitation_key,
                result,
            ),
            PendingRead::CredentialOpaque {
                request,
                opened,
                account,
                credential_id,
                proof,
                reservation,
                record_key,
            } => self.credential_opaque_read(
                context,
                CredentialOpaqueContinuation {
                    request,
                    opened,
                    account,
                    credential_id,
                    proof,
                    reservation,
                    record_key,
                },
                result,
            ),
        }
    }

    fn creation_current_index_read(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationStart>,
        schedule: LoginIndexLookupSchedule,
        rate_available: bool,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let current_available = read_login_index(context, result, schedule.current())?.is_none();
        let key = schedule.previous_or_dummy().encode()?;
        let read_id = context.submit_storage_read(ReadPlan::exact(TableId::LoginIndex, key))?;
        if self
            .reads
            .insert(
                read_id,
                PendingRead::CreationPreviousIndex {
                    request,
                    opened,
                    schedule,
                    current_available,
                    rate_available,
                },
            )
            .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Vec::new())
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-30 reason=the fixed current-then-previous login lookup continuation keeps its request admission and availability state explicit
    #[allow(clippy::too_many_arguments)]
    fn creation_previous_index_read(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationStart>,
        schedule: LoginIndexLookupSchedule,
        current_available: bool,
        rate_available: bool,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let previous = read_login_index(context, result, schedule.previous_or_dummy())?;
        let previous_available = !schedule.is_transition() || previous.is_none();
        let login_available = current_available && previous_available;
        let invitation_id = opened
            .payload()
            .invitation
            .as_ref()
            .map(agenc_ircd_auth::AccountCreationInvite::invite_id);
        let Some(invitation_id) = invitation_id else {
            self.start_creation_crypto(
                context,
                request,
                opened,
                login_available,
                true,
                rate_available,
            )?;
            return Ok(Vec::new());
        };
        let invitation_key = StoredKey::new(invitation_id.as_bytes().to_vec())?;
        let read_id = context.submit_storage_read(ReadPlan::exact(
            TableId::RegistrationInvite,
            invitation_key.clone(),
        ))?;
        if self
            .reads
            .insert(
                read_id,
                PendingRead::CreationInvitation {
                    request,
                    opened,
                    login_available,
                    rate_available,
                    invitation_key,
                },
            )
            .is_some()
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Vec::new())
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-30 reason=fixed invitation-read continuation keeps request availability and exact key ownership explicit
    #[allow(clippy::too_many_arguments)]
    fn creation_invitation_read(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationStart>,
        login_available: bool,
        rate_available: bool,
        invitation_key: StoredKey,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let invitation_available = read_optional_persistent(
            context,
            result,
            TableId::RegistrationInvite,
            &invitation_key,
        )?
        .is_none();
        self.start_creation_crypto(
            context,
            request,
            opened,
            login_available,
            invitation_available,
            rate_available,
        )?;
        Ok(Vec::new())
    }

    fn start_creation_crypto(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        opened: AuthenticatedAccountRequest<CreationStart>,
        login_available: bool,
        invitation_available: bool,
        rate_available: bool,
    ) -> Result<(), RuntimeError> {
        let admission = match self.config.creation_policy {
            AccountCreationPolicy::Open => CreationAdmission::Open,
            AccountCreationPolicy::Invite(authority) => CreationAdmission::Invitation {
                authority,
                now: context.utc_now().map_err(|_| RuntimeError::InvalidValue)?,
            },
            AccountCreationPolicy::Closed => CreationAdmission::Closed,
        };
        let parameters = AccountCreationStartParameters {
            context: self.operation_context(context, request.route)?,
            request: opened,
            admission,
            login_is_available: login_available && rate_available,
            invitation_is_available: invitation_available,
        };
        let job = RuntimeCryptoJob::CreationStart(Box::new(CreationStartJob::new(
            Arc::clone(&self.config.opaque_profile),
            Arc::clone(&self.config.current_login_index_key),
            parameters,
        )));
        self.submit_crypto(context, PendingCrypto::CreationStart { request }, job)
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
        let mut account_id = selected.as_ref().map(|(account_id, _)| *account_id);
        let value = read_required_persistent(context, result, TableId::OpaqueRecord, &record_key)?;
        let (mut lookup, mut previous_value) =
            self.authentication_lookup(context, &login, current, previous, selected, &value)?;
        if account_id
            .is_some_and(|account_id| self.credential_reservations.contains_key(&account_id))
        {
            account_id = None;
            lookup = AuthenticationLookup::Unknown;
            previous_value = None;
        }
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
            account_id,
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

    fn credential_opaque_read(
        &mut self,
        context: &mut StateCoreContext,
        continuation: CredentialOpaqueContinuation,
        result: ReadResult,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let CredentialOpaqueContinuation {
            request,
            opened,
            account,
            credential_id,
            proof,
            mut reservation,
            record_key,
        } = continuation;
        let value = read_optional_persistent(context, result, TableId::OpaqueRecord, &record_key)?;
        let expected_key = StoredKey::new(account.account_id().to_text().into_bytes())?;
        let record_matches = record_key == expected_key
            && value.as_ref().is_some_and(|value| {
                value.record_kind() == LIVE_RECORD_KIND
                    && value.revision() == account.account_revision().get()
                    && value.generation() == account.account_session_generation().get()
                    && value
                        .body()
                        .try_into()
                        .ok()
                        .and_then(|bytes| OpaqueRegistrationRecord::from_bytes(bytes).ok())
                        .is_some()
            });
        if reservation.is_some() && !record_matches {
            self.release_credential_reservation(account.account_id(), request.generation)?;
            reservation = None;
        }
        let parameters = CredentialChangeStartParameters {
            context: self.operation_context(context, request.route)?,
            proof,
            account,
            credential_id,
            request: opened,
            operation_is_available: reservation.is_some(),
        };
        let job = RuntimeCryptoJob::CredentialStart(Box::new(CredentialStartJob::new(
            Arc::clone(&self.config.opaque_profile),
            parameters,
        )));
        self.submit_crypto(
            context,
            PendingCrypto::CredentialStart {
                request,
                reservation,
            },
            job,
        )?;
        Ok(Vec::new())
    }

    fn release_credential_reservation(
        &mut self,
        account_id: AccountId,
        generation: ConnectionGeneration,
    ) -> Result<(), RuntimeError> {
        match self.credential_reservations.remove(&account_id) {
            Some(owner) if owner == generation => Ok(()),
            _ => Err(RuntimeError::InvalidValue),
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=one replay path validates route request terminal receipt and terminal companion frames before exact delivery
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
        let expected_terminal = if request.is_finish() {
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
        let terminal_account = replay_terminal_account(
            request.expected_message_kind(),
            stored.terminal,
            stored.terminal_account,
        )?;
        let mut frames = self.response_frames(
            context,
            &request,
            response.as_bytes(),
            stored.terminal == RequestTerminal::Accepted,
        )?;
        if let Some(account_id) = terminal_account {
            frames.push(account_created_note(context.server_prefix(), account_id)?);
        }
        let credential_changed = request.expected_message_kind()
            == AccountServiceMessageKind::CredentialChangeFinish
            && stored.terminal == RequestTerminal::Accepted;
        if credential_changed {
            frames.push(account_credential_changed_note(context.server_prefix())?);
        }
        context
            .send_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        if credential_changed {
            close_account_authority_after_flush(context, request.generation);
        }
        let result = request_terminal_result(stored.terminal);
        Ok(vec![CarrierCompletion::finished(
            request.generation,
            request.carrier_generation,
            result,
        )])
    }

    fn progress(&mut self, context: &mut StateCoreContext) -> Vec<CarrierCompletion> {
        let mut completions = Vec::new();
        if let Some(completion) = self.progress_ready_stage(context) {
            completions.push(completion);
        }
        if self.pending_cleanups.is_empty()
            && self.pending_authority.is_none()
            && self.ready_stage.is_none()
        {
            let _cleanup = self.try_stage_transaction_cleanup(context);
        }
        if let Some(completion) = self.progress_ready_seal(context) {
            completions.push(completion);
        }
        completions
    }

    fn progress_ready_stage(
        &mut self,
        context: &mut StateCoreContext,
    ) -> Option<CarrierCompletion> {
        if !self.pending_cleanups.is_empty()
            || self.pending_authority.is_some()
            || self.ready_stage.is_none()
            || context.pending_len() != 0
        {
            return None;
        }
        self.stage_ready(context).err()
    }

    fn progress_ready_seal(&mut self, context: &mut StateCoreContext) -> Option<CarrierCompletion> {
        if !self.pending_cleanups.is_empty()
            || self.pending_authority.is_some()
            || self.ready_stage.is_some()
            || self.has_seal_job()
        {
            return None;
        }
        let ready = self.ready_seals.pop_front()?;
        self.begin_seal(context, ready).err()
    }

    fn has_seal_job(&self) -> bool {
        self.crypto.values().any(|pending| {
            matches!(
                pending,
                PendingCrypto::CreationStartSeal { .. }
                    | PendingCrypto::CreationFinishSeal { .. }
                    | PendingCrypto::CredentialStartSeal { .. }
                    | PendingCrypto::CredentialFinishSeal { .. }
                    | PendingCrypto::StartSeal { .. }
                    | PendingCrypto::FinishSeal { .. }
            )
        })
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=closed seal dispatcher preserves each semantic outcome and response-count authority in one exhaustive match
    fn begin_seal(
        &mut self,
        context: &mut StateCoreContext,
        ready: ReadySeal,
    ) -> Result<(), CarrierCompletion> {
        let cleanup = ready.transaction_cleanup();
        let response_count = context.head().account_service_response_count;
        let (pending, job) = match ready {
            ReadySeal::CreationStart { request, outcome } => (
                PendingCrypto::CreationStartSeal { request },
                RuntimeCryptoJob::CreationStartSeal(Box::new(CreationStartSealJob::new(
                    outcome,
                    response_count,
                ))),
            ),
            ReadySeal::CreationFinish {
                request,
                transaction_id,
                outcome,
                reservation,
            } => (
                PendingCrypto::CreationFinishSeal {
                    request,
                    transaction_id,
                    reservation,
                },
                RuntimeCryptoJob::CreationFinishSeal(Box::new(CreationFinishSealJob::new(
                    outcome,
                    response_count,
                ))),
            ),
            ReadySeal::CredentialStart {
                request,
                outcome,
                reservation,
            } => (
                PendingCrypto::CredentialStartSeal {
                    request,
                    reservation,
                },
                RuntimeCryptoJob::CredentialStartSeal(Box::new(CredentialStartSealJob::new(
                    outcome,
                    response_count,
                ))),
            ),
            ReadySeal::CredentialFinish {
                request,
                transaction_id,
                outcome,
                reservation,
            } => (
                PendingCrypto::CredentialFinishSeal {
                    request,
                    transaction_id,
                    reservation,
                },
                RuntimeCryptoJob::CredentialFinishSeal(Box::new(CredentialFinishSealJob::new(
                    outcome,
                    response_count,
                ))),
            ),
            ReadySeal::Start {
                request,
                outcome,
                account_id,
                login,
                previous_value,
            } => (
                PendingCrypto::StartSeal {
                    request,
                    account_id,
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
                account_id,
                login,
                previous_value,
                authenticated_at,
            } => (
                PendingCrypto::FinishSeal {
                    request,
                    transaction_id,
                    account_id,
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
        let completion =
            CarrierCompletion::closed(pending.generation(), pending.carrier_generation());
        if self.submit_crypto(context, pending, job).is_ok() {
            return Ok(());
        }
        if let Some((generation, class, cleanup)) = cleanup {
            let _queued = self.queue_transaction_cleanup(context, generation, class, cleanup);
        }
        Err(completion)
    }

    fn stage_ready(&mut self, context: &mut StateCoreContext) -> Result<(), CarrierCompletion> {
        let ready = self
            .ready_stage
            .take()
            .ok_or(CarrierCompletion::closed(ConnectionGeneration::new(0), 0))?;
        let completion = CarrierCompletion::closed(ready.generation(), ready.carrier_generation());
        let cleanup = ready.transaction_cleanup();
        if self.stage_ready_work(context, ready).is_ok() {
            return Ok(());
        }
        if let Some((generation, class, cleanup)) = cleanup {
            let _queued = self.queue_transaction_cleanup(context, generation, class, cleanup);
        }
        Err(completion)
    }

    fn stage_ready_work(
        &mut self,
        context: &mut StateCoreContext,
        ready: ReadyStage,
    ) -> Result<(), RuntimeError> {
        match ready {
            ReadyStage::CreationStart { request, sealed } => {
                self.stage_creation_start(context, request, sealed)
            }
            ReadyStage::CreationFinish {
                request,
                transaction_id,
                sealed,
                reservation,
            } => self.stage_creation_finish(context, request, transaction_id, sealed, reservation),
            ReadyStage::CredentialStart {
                request,
                sealed,
                reservation,
            } => self.stage_credential_start(context, request, sealed, reservation),
            ReadyStage::CredentialFinish {
                request,
                transaction_id,
                sealed,
                reservation,
            } => {
                self.stage_credential_finish(context, request, transaction_id, sealed, reservation)
            }
            ReadyStage::Start {
                request,
                sealed,
                account_id,
                login,
                previous_value,
            } => self.stage_start(context, request, sealed, account_id, login, previous_value),
            ReadyStage::Finish {
                request,
                transaction_id,
                sealed,
                account_id,
                login,
                previous_value,
                authenticated_at,
            } => self.stage_finish(
                context,
                request,
                transaction_id,
                sealed,
                account_id,
                login,
                previous_value,
                authenticated_at,
            ),
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=creation START commits the sealed challenge transaction replay row and only admissible identifier reservations as one set
    fn stage_creation_start(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        sealed: SealedAccountStart<AccountCreationState>,
    ) -> Result<(), RuntimeError> {
        if !self.transaction_capacity_available() {
            return Err(RuntimeError::LimitExceeded);
        }
        let now = context.now();
        let now_utc = context.utc_now().map_err(|_| RuntimeError::InvalidValue)?;
        let transaction_record = sealed
            .creation_transaction_record(now, now_utc)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let transaction_expiry = transaction_record
            .durable_expires_at_utc()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let reservation = self.creation_reservation(&sealed)?;
        let plan = context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let revision = plan.resulting_revision().get();
        let response = sealed.response_intent().response().as_bytes();
        let mut writes = Vec::new();
        writes
            .try_reserve_exact(5)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let mut transaction_references = Vec::new();
        if let Some(invite_id) = reservation
            .as_ref()
            .and_then(|reservation| reservation.invitation_id)
        {
            let invitation_key = StoredKey::new(invite_id.as_bytes().to_vec())?;
            transaction_references.push(RecordReference::new(
                TableId::RegistrationInvite,
                invitation_key.clone(),
            )?);
            let invitation = PersistentRecordValue::new(
                TableId::RegistrationInvite,
                INVITATION_RESERVATION_KIND,
                revision,
                0,
                Some(transaction_expiry.get()),
                vec![RecordReference::new(
                    TableId::AuthTransaction,
                    StoredKey::new(sealed.transaction_id().as_bytes().to_vec())?,
                )?],
                Vec::new(),
            )?;
            writes.push(AccountServiceDurableWrite::put(
                TableId::RegistrationInvite,
                invitation_key,
                invitation.encode()?,
            )?);
        }
        let transaction_value = PersistentRecordValue::new(
            TableId::AuthTransaction,
            CREATION_TRANSACTION_KIND,
            revision,
            0,
            Some(transaction_expiry.get()),
            transaction_references,
            transaction_record.expose_for_persistence().to_vec(),
        )?;
        writes.push(AccountServiceDurableWrite::put(
            TableId::AuthTransaction,
            StoredKey::new(sealed.transaction_id().as_bytes().to_vec())?,
            transaction_value.encode()?,
        )?);
        if let Some(reservation) = reservation.as_ref() {
            let login_key = LoginIndexStoredKey::decode(reservation.login_key.as_bytes())?;
            let login_value = LoginIndexValue::new(
                &login_key,
                LoginIndexValueKind::CreationReservation {
                    transaction_id: sealed.transaction_id(),
                    expires_at: transaction_expiry.get(),
                },
            )?;
            writes.push(AccountServiceDurableWrite::put(
                TableId::LoginIndex,
                reservation.login_key.clone(),
                login_value.encode()?,
            )?);
        }
        writes.push(request_result_write(
            revision,
            &request,
            RequestTerminal::Start,
            None,
            response,
        )?);
        let frames = self.response_frames(context, &request, response, false)?;
        let fanout = context
            .fanout_request_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let next = sealed.response_intent().next_response_count();
        let accepted = context.stage_durable_with_account_service(
            plan,
            fanout,
            Some(StagedOrigin::silent(request.generation)),
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
        self.pending_authority = Some(PendingAuthority::CreationStart {
            generation: request.generation,
            carrier_generation: request.carrier_generation,
            sealed,
            reservation,
        });
        Ok(())
    }

    fn creation_reservation(
        &self,
        sealed: &SealedAccountStart<AccountCreationState>,
    ) -> Result<Option<CreationReservation>, RuntimeError> {
        let Some(digest) = sealed.creation_reservation_login_digest() else {
            if sealed.creation_reservation_invitation().is_some() {
                return Err(RuntimeError::InvalidValue);
            }
            return Ok(None);
        };
        let key = LoginIndexStoredKey::new(
            self.config.login_index_key_state.current_generation(),
            agenc_ircd_crypto::LoginIndexDigest::from_storage_key(*digest.expose_for_storage_key()),
        )?
        .encode()?;
        Ok(Some(CreationReservation {
            login_key: key,
            invitation_id: sealed
                .creation_reservation_invitation()
                .map(|(invite_id, _)| invite_id),
        }))
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=creation FINISH consumes or releases every reservation with account index OPAQUE result and sealed completion in one durable set
    fn stage_creation_finish(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<CreateAccountIntent>,
        reservation: Option<CreationReservation>,
    ) -> Result<(), RuntimeError> {
        let plan = match sealed.result() {
            Ok(intent) => {
                let generation = Generation::new(1).map_err(|_| RuntimeError::InvalidValue)?;
                let account = AccountState::with_policies(
                    intent.account_id(),
                    generation,
                    context.domain().revision(),
                    self.config.default_presence,
                    self.config.default_guest_direct_messages,
                    self.config.default_direct_messages,
                );
                context
                    .domain()
                    .plan_account_created(account)
                    .map_err(|_| RuntimeError::InvalidValue)?
            }
            Err(_) => context
                .domain()
                .plan_account_service_checkpoint()
                .map_err(|_| RuntimeError::InvalidValue)?,
        };
        let revision = plan.resulting_revision().get();
        let response = sealed.response_intent().response().as_bytes();
        let mut writes = Vec::new();
        writes
            .try_reserve_exact(6)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        writes.push(AccountServiceDurableWrite::delete(
            TableId::AuthTransaction,
            StoredKey::new(transaction_id.as_bytes().to_vec())?,
        )?);
        let terminal = if sealed.result().is_ok() {
            RequestTerminal::Accepted
        } else {
            RequestTerminal::Rejected
        };
        let terminal_account = sealed.result().ok().map(CreateAccountIntent::account_id);
        writes.push(request_result_write(
            revision,
            &request,
            terminal,
            terminal_account,
            response,
        )?);
        match (sealed.result(), reservation.as_ref()) {
            (Ok(intent), Some(reservation)) => {
                self.push_creation_success_writes(revision, intent, reservation, &mut writes)?;
            }
            (Err(_), Some(reservation)) => {
                writes.push(AccountServiceDurableWrite::delete(
                    TableId::LoginIndex,
                    reservation.login_key.clone(),
                )?);
                if let Some(invite_id) = reservation.invitation_id {
                    writes.push(AccountServiceDurableWrite::delete(
                        TableId::RegistrationInvite,
                        StoredKey::new(invite_id.as_bytes().to_vec())?,
                    )?);
                }
            }
            (Err(_), None) => {}
            (Ok(_), None) => return Err(RuntimeError::InvalidValue),
        }
        let mut frames =
            self.response_frames(context, &request, response, sealed.result().is_ok())?;
        if let Ok(intent) = sealed.result() {
            frames.push(account_created_note(
                context.server_prefix(),
                intent.account_id(),
            )?);
        }
        let fanout = context
            .fanout_request_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let next = sealed.response_intent().next_response_count();
        let accepted = context.stage_durable_with_account_service(
            plan,
            fanout,
            Some(StagedOrigin::silent(request.generation)),
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
        self.pending_authority = Some(PendingAuthority::CreationFinish {
            generation: request.generation,
            carrier_generation: request.carrier_generation,
            transaction_id,
            sealed,
            reservation,
        });
        Ok(())
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=one creation-success atomic set checks reservation identity before emitting every account index credential and invite write
    fn push_creation_success_writes(
        &self,
        revision: u64,
        intent: &CreateAccountIntent,
        reservation: &CreationReservation,
        writes: &mut Vec<AccountServiceDurableWrite>,
    ) -> Result<(), RuntimeError> {
        let login_key = LoginIndexStoredKey::new(
            self.config.login_index_key_state.current_generation(),
            agenc_ircd_crypto::LoginIndexDigest::from_storage_key(
                *intent.login_digest().expose_for_storage_key(),
            ),
        )?;
        let stored_login_key = login_key.encode()?;
        if stored_login_key != reservation.login_key
            || intent.invitation_id() != reservation.invitation_id
        {
            return Err(RuntimeError::InvalidValue);
        }
        let login_value = LoginIndexValue::new(
            &login_key,
            LoginIndexValueKind::Live {
                account_id: intent.account_id(),
                opaque_credential_id: agenc_ircd_types::OpaqueCredentialId::from_bytes(
                    *intent.credential_id().expose_for_account_service(),
                ),
            },
        )?;
        writes.push(AccountServiceDurableWrite::put(
            TableId::LoginIndex,
            stored_login_key,
            login_value.encode()?,
        )?);
        let account_key = StoredKey::new(intent.account_id().to_text().into_bytes())?;
        let opaque = PersistentRecordValue::new(
            TableId::OpaqueRecord,
            LIVE_RECORD_KIND,
            revision,
            1,
            None,
            vec![RecordReference::new(TableId::Account, account_key.clone())?],
            intent.record().expose_for_persistence().to_vec(),
        )?;
        writes.push(AccountServiceDurableWrite::put(
            TableId::OpaqueRecord,
            account_key.clone(),
            opaque.encode()?,
        )?);
        if let Some(invite_id) = intent.invitation_id() {
            let expires_at = intent
                .invitation_expires_at()
                .ok_or(RuntimeError::InvalidValue)?
                .checked_add(INVITATION_TOMBSTONE_SECONDS)
                .map_err(|_| RuntimeError::Overflow)?;
            let tombstone = PersistentRecordValue::new(
                TableId::RegistrationInvite,
                INVITATION_TOMBSTONE_KIND,
                revision,
                0,
                Some(expires_at.get()),
                vec![RecordReference::new(TableId::Account, account_key)?],
                Vec::new(),
            )?;
            writes.push(AccountServiceDurableWrite::put(
                TableId::RegistrationInvite,
                StoredKey::new(invite_id.as_bytes().to_vec())?,
                tombstone.encode()?,
            )?);
        } else if intent.invitation_expires_at().is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=credential START consumes proof reservation transaction challenge replay and response authority in one durable set
    fn stage_credential_start(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        sealed: SealedAccountStart<CredentialChangeState>,
        mut reservation: Option<AccountId>,
    ) -> Result<(), RuntimeError> {
        if !self.transaction_capacity_available() {
            return Err(RuntimeError::LimitExceeded);
        }
        match (sealed.credential_reservation_account_id(), reservation) {
            (Some(admitted), Some(reserved)) if admitted == reserved => {}
            (None, Some(reserved)) => {
                self.release_credential_reservation(reserved, request.generation)?;
                reservation = None;
            }
            (None, None) => {}
            _ => return Err(RuntimeError::InvalidValue),
        }
        let now = context.now();
        let now_utc = context.utc_now().map_err(|_| RuntimeError::InvalidValue)?;
        let transaction_record = sealed
            .credential_change_transaction_record(now, now_utc)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let plan = context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let revision = plan.resulting_revision().get();
        let mut references = Vec::new();
        if let Some(account_id) = reservation {
            references.push(RecordReference::new(
                TableId::Account,
                StoredKey::new(account_id.to_text().into_bytes())?,
            )?);
        }
        let transaction_value = PersistentRecordValue::new(
            TableId::AuthTransaction,
            CREDENTIAL_CHANGE_TRANSACTION_KIND,
            revision,
            0,
            Some(
                transaction_record
                    .durable_expires_at_utc()
                    .map_err(|_| RuntimeError::InvalidValue)?
                    .get(),
            ),
            references,
            transaction_record.expose_for_persistence().to_vec(),
        )?;
        let response = sealed.response_intent().response().as_bytes();
        let writes = vec![
            AccountServiceDurableWrite::put(
                TableId::AuthTransaction,
                StoredKey::new(sealed.transaction_id().as_bytes().to_vec())?,
                transaction_value.encode()?,
            )?,
            request_result_write(revision, &request, RequestTerminal::Start, None, response)?,
        ];
        let frames = self.response_frames(context, &request, response, false)?;
        let fanout = context
            .fanout_request_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let next = sealed.response_intent().next_response_count();
        let accepted = context.stage_durable_with_account_service(
            plan,
            fanout,
            Some(StagedOrigin::silent(request.generation)),
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
        self.pending_authority = Some(PendingAuthority::CredentialStart {
            generation: request.generation,
            carrier_generation: request.carrier_generation,
            sealed,
            reservation,
        });
        Ok(())
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=credential FINISH replacement fencing encrypted receipt NOTE and close set share one durable and fanout barrier
    fn stage_credential_finish(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<CredentialReplacementIntent>,
        reservation: Option<AccountId>,
    ) -> Result<(), RuntimeError> {
        let bound = context
            .sessions()
            .connection(request.generation)
            .and_then(|entry| entry.session())
            .ok_or(RuntimeError::InvalidValue)?;
        let (plan, resulting_generation) = match (sealed.result(), reservation) {
            (Ok(intent), Some(reserved)) if intent.account_id() == reserved => {
                let (plan, generation) = context
                    .domain()
                    .plan_account_credential_replaced(
                        reserved,
                        intent.expected_account_session_generation(),
                        intent.expected_account_revision(),
                    )
                    .map_err(|_| RuntimeError::InvalidValue)?;
                if generation != intent.next_account_session_generation() {
                    return Err(RuntimeError::InvalidValue);
                }
                (plan, Some(generation))
            }
            (Err(_), _) => (
                context
                    .domain()
                    .plan_account_service_checkpoint()
                    .map_err(|_| RuntimeError::InvalidValue)?,
                None,
            ),
            _ => return Err(RuntimeError::InvalidValue),
        };
        let revision = plan.resulting_revision().get();
        let terminal = if sealed.result().is_ok() {
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
            request_result_write(revision, &request, terminal, None, response)?,
        ];
        let mut invalidated_authentications = Vec::new();
        let mut invalidated_grants = Vec::new();
        if let (Ok(intent), Some(generation)) = (sealed.result(), resulting_generation) {
            for (connection_generation, connection) in &self.connections {
                if let Some(authentication) = connection
                    .transaction
                    .as_ref()
                    .filter(|authentication| authentication.account_id == Some(intent.account_id()))
                {
                    invalidated_authentications.push(*connection_generation);
                    writes.push(AccountServiceDurableWrite::delete(
                        TableId::AuthTransaction,
                        StoredKey::new(
                            authentication
                                .transaction
                                .binding()
                                .transaction_id()
                                .as_bytes()
                                .to_vec(),
                        )?,
                    )?);
                }
                if let Some(binding) = connection
                    .authenticated
                    .as_ref()
                    .filter(|binding| binding.account_id() == intent.account_id())
                {
                    invalidated_grants.push(*connection_generation);
                    writes.push(AccountServiceDurableWrite::delete(
                        TableId::AuthTransaction,
                        StoredKey::new(binding.transaction_id.as_bytes().to_vec())?,
                    )?);
                }
            }
            let account_key = StoredKey::new(intent.account_id().to_text().into_bytes())?;
            let opaque = PersistentRecordValue::new(
                TableId::OpaqueRecord,
                LIVE_RECORD_KIND,
                revision,
                generation.get(),
                None,
                vec![RecordReference::new(TableId::Account, account_key.clone())?],
                intent.record().expose_for_persistence().to_vec(),
            )?;
            writes.push(AccountServiceDurableWrite::put(
                TableId::OpaqueRecord,
                account_key,
                opaque.encode()?,
            )?);
        }
        let mut frames =
            self.response_frames(context, &request, response, sealed.result().is_ok())?;
        if sealed.result().is_ok() {
            frames.push(account_credential_changed_note(context.server_prefix())?);
        }
        let mut fenced = Vec::new();
        let fanout = if let Ok(intent) = sealed.result() {
            for user_id in plan.events().iter().filter_map(|event| match event {
                DomainEvent::SessionHidden(user_id) => Some(*user_id),
                _ => None,
            }) {
                if let Some(generation) = context.sessions().generation_for_user(user_id) {
                    fenced.push(generation);
                }
            }
            render_account_credential_replacement(
                context,
                intent.account_id(),
                bound.user_id,
                frames,
                &plan,
            )?
        } else {
            context
                .fanout_request_to(request.generation, frames)
                .map_err(|_| RuntimeError::MemoryExhausted)?
        };
        let next = sealed.response_intent().next_response_count();
        let accepted = context.stage_durable_with_account_service(
            plan,
            fanout,
            Some(StagedOrigin::silent(request.generation)),
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
        self.pending_authority = Some(PendingAuthority::CredentialFinish {
            generation: request.generation,
            carrier_generation: request.carrier_generation,
            transaction_id,
            sealed,
            reservation,
            fenced,
            invalidated_authentications,
            invalidated_grants,
        });
        Ok(())
    }

    // agenc-review: focus owner=runtime reviewed=2026-08-29 reason=one authentication-start atomic set constructs transaction result fanout and response-count authority before staging once
    fn stage_start(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
        sealed: SealedAccountStart<AccountAuthenticationState>,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    ) -> Result<(), RuntimeError> {
        if !self.transaction_capacity_available() {
            return Err(RuntimeError::LimitExceeded);
        }
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
            request_result_write(revision, &request, RequestTerminal::Start, None, response)?;
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
        let frames = self.response_frames(context, &request, response, false)?;
        let fanout = context
            .fanout_request_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let next = sealed.response_intent().next_response_count();
        let accepted = context.stage_durable_with_account_service(
            plan,
            fanout,
            Some(StagedOrigin::silent(request.generation)),
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
            account_id,
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
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
        authenticated_at: MonotonicTick,
    ) -> Result<(), RuntimeError> {
        let semantic_grant = sealed.result().ok();
        if let Some(grant) = semantic_grant
            && (account_id != Some(grant.account_id())
                || !self.authentication_finish_available(context, request.generation, grant))
        {
            return Err(RuntimeError::InvalidValue);
        }
        let bound = context
            .sessions()
            .connection(request.generation)
            .ok_or(RuntimeError::InvalidValue)?
            .session();
        let mut fresh_auth_session = None;
        let sasl_accepted = semantic_grant.is_some();
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
                        return Err(RuntimeError::InvalidValue);
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
        let transaction_write = if let (Some(grant), None) = (semantic_grant, bound) {
            let record = AuthenticationGrantRecord::capture(transaction_id, grant)
                .map_err(|_| RuntimeError::InvalidValue)?;
            let account_key = StoredKey::new(grant.account_id().to_text().into_bytes())?;
            let value = PersistentRecordValue::new(
                TableId::AuthTransaction,
                AUTHENTICATION_GRANT_KIND,
                revision,
                0,
                Some(grant.durable_expires_at_utc().get()),
                vec![RecordReference::new(TableId::Account, account_key)?],
                record.expose_for_persistence().to_vec(),
            )?;
            AccountServiceDurableWrite::put(
                TableId::AuthTransaction,
                StoredKey::new(transaction_id.as_bytes().to_vec())?,
                value.encode()?,
            )?
        } else {
            AccountServiceDurableWrite::delete(
                TableId::AuthTransaction,
                StoredKey::new(transaction_id.as_bytes().to_vec())?,
            )?
        };
        let mut writes = vec![
            transaction_write,
            request_result_write(revision, &request, terminal, None, response)?,
        ];
        let mut login_index_migration = None;
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
            login_index_migration = Some(CommittedLoginIndexMigration {
                account_id: grant.account_id(),
                previous_key: migration.previous_key().clone(),
                current_key: migration.current_key().clone(),
            });
            Some(migration.resulting_key_state())
        } else {
            None
        };
        let frames = self.response_frames(context, &request, response, sasl_accepted)?;
        let fanout = context
            .fanout_request_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let next = sealed.response_intent().next_response_count();
        let accepted = context.stage_durable_with_account_service(
            plan,
            fanout,
            Some(StagedOrigin::silent(request.generation)),
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
            transaction_id,
            sealed,
            account_id,
            authenticated_at,
            sasl_accepted,
            fresh_auth_session,
            resulting_key_state,
            login_index_migration,
        });
        Ok(())
    }

    fn response_frames(
        &mut self,
        context: &StateCoreContext,
        request: &RequestContext,
        response: &[u8],
        accepted: bool,
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        match request.carrier {
            RequestCarrier::Sasl => self.sasl_response_frames(context, request, response, accepted),
            RequestCarrier::Account(kind) => {
                self.account_response_frames(context, request, kind, response, accepted)
            }
        }
    }

    fn sasl_response_frames(
        &mut self,
        context: &StateCoreContext,
        request: &RequestContext,
        response: &[u8],
        accepted: bool,
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        let connection = self
            .connections
            .get_mut(&request.generation)
            .ok_or(RuntimeError::InvalidValue)?;
        let mut actions = connection
            .sasl
            .server_response(response, context.now().get())
            .map_err(|_| RuntimeError::InvalidValue)?;
        if request.is_finish() {
            actions.extend(
                connection
                    .sasl
                    .complete(accepted, context.now().get())
                    .map_err(|_| RuntimeError::InvalidValue)?,
            );
        }
        render_sasl_actions(context.server_prefix(), &request.target, actions)
    }

    fn account_response_frames(
        &mut self,
        context: &StateCoreContext,
        request: &RequestContext,
        kind: AccountCarrierKind,
        response: &[u8],
        accepted: bool,
    ) -> Result<Vec<WireMessage>, RuntimeError> {
        let connection = self
            .connections
            .get_mut(&request.generation)
            .ok_or(RuntimeError::InvalidValue)?;
        let transfer = match kind {
            AccountCarrierKind::Create => &mut connection.creation,
            AccountCarrierKind::Credentials => &mut connection.credentials,
        };
        let actions = transfer
            .server_response(request.phase, response, context.now().get())
            .map_err(|_| RuntimeError::InvalidValue)?;
        let mut frames = render_account_actions(context.server_prefix(), kind, actions)?;
        if !request.is_finish() {
            return Ok(frames);
        }
        if accepted {
            return Ok(frames);
        }
        frames.push(account_failure(context.server_prefix(), kind)?);
        Ok(frames)
    }

    fn fail_pending(
        &mut self,
        context: &mut StateCoreContext,
        request: RequestContext,
    ) -> Result<Vec<CarrierCompletion>, RuntimeError> {
        let route = match request.carrier {
            RequestCarrier::Sasl => self.fail_route(context, request.generation, &request.target),
            RequestCarrier::Account(kind) => {
                self.fail_account_route(context, request.generation, kind)
            }
        };
        let CarrierRoute::Finished { frames, result } = route else {
            return Err(RuntimeError::InvalidValue);
        };
        context
            .send_to(request.generation, frames)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(vec![CarrierCompletion::finished(
            request.generation,
            request.carrier_generation,
            result,
        )])
    }

    fn close_completion(&self, pending: &PendingCrypto) -> CarrierCompletion {
        CarrierCompletion::closed(pending.generation(), pending.carrier_generation())
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
        CarrierCompletion::with_close(generation, carrier_generation, close, ResultClass::Ok)
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-30 reason=authentication postcommit retains its account candidate login migration and exact carrier ownership explicitly
    #[allow(clippy::too_many_arguments)]
    fn commit_start(
        &mut self,
        context: &mut StateCoreContext,
        committed_count: u64,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountStart<AccountAuthenticationState>,
        account_id: Option<AccountId>,
        login: NormalizedLogin,
        previous_value: Option<LoginIndexValue>,
    ) -> Option<CarrierCompletion> {
        let Ok(transaction) = sealed.into_transaction_after_commit(committed_count) else {
            return Some(CarrierCompletion::closed(generation, carrier_generation));
        };
        let transaction_id = transaction.binding().transaction_id();
        let deadline = transaction.binding().expires_at();
        if self
            .install_transaction_timer(
                context,
                generation,
                LiveTransactionClass::Authentication,
                transaction_id,
                deadline,
            )
            .is_err()
        {
            let cleanup = TransactionCleanup::authentication(transaction_id);
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::Authentication,
                cleanup,
            );
            return Some(CarrierCompletion::closed(generation, carrier_generation));
        }
        let Some(connection) = self.connections.get_mut(&generation) else {
            let cleanup = TransactionCleanup::authentication(transaction_id);
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::Authentication,
                cleanup,
            );
            return None;
        };
        connection.transaction = Some(LiveAuthentication {
            transaction,
            account_id,
            login,
            previous_value,
        });
        Some(CarrierCompletion::finished(
            generation,
            carrier_generation,
            ResultClass::Ok,
        ))
    }

    fn commit_creation_start(
        &mut self,
        context: &mut StateCoreContext,
        committed_count: u64,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountStart<AccountCreationState>,
        reservation: Option<CreationReservation>,
    ) -> Option<CarrierCompletion> {
        let Ok(transaction) = sealed.into_transaction_after_commit(committed_count) else {
            return Some(CarrierCompletion::closed(generation, carrier_generation));
        };
        let transaction_id = transaction.binding().transaction_id();
        let deadline = transaction.binding().expires_at();
        if self
            .install_transaction_timer(
                context,
                generation,
                LiveTransactionClass::Creation,
                transaction_id,
                deadline,
            )
            .is_err()
        {
            let cleanup = TransactionCleanup::creation(transaction_id, reservation);
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::Creation,
                cleanup,
            );
            return Some(CarrierCompletion::closed(generation, carrier_generation));
        }
        let Some(connection) = self.connections.get_mut(&generation) else {
            let cleanup = TransactionCleanup::creation(transaction_id, reservation);
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::Creation,
                cleanup,
            );
            return None;
        };
        connection.creation_transaction = Some(LiveCreation {
            transaction,
            reservation,
        });
        Some(CarrierCompletion::finished(
            generation,
            carrier_generation,
            ResultClass::Ok,
        ))
    }

    fn commit_creation_finish(
        &mut self,
        committed_count: u64,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<CreateAccountIntent>,
        reservation: Option<CreationReservation>,
    ) -> CarrierCompletion {
        let release_failed = self
            .release_finished_transaction(
                generation,
                LiveTransactionClass::Creation,
                transaction_id,
            )
            .is_err();
        let result = sealed.into_result_after_commit(committed_count);
        let result_class = match result.as_ref() {
            Ok(Ok(_)) => ResultClass::Ok,
            Ok(Err(_)) => ResultClass::Rejected,
            Err(_) => ResultClass::Error,
        };
        let install_failed = match (result.as_ref(), reservation) {
            (Ok(Ok(intent)), Some(reservation)) => {
                let account_id = intent.account_id();
                self.config.live_login_keys.contains_key(&account_id)
                    || self
                        .config
                        .live_login_keys
                        .insert(account_id, reservation.login_key)
                        .is_some()
            }
            (Ok(Err(_)), _) => false,
            _ => true,
        };
        CarrierCompletion::with_close(
            generation,
            carrier_generation,
            release_failed || install_failed,
            result_class,
        )
    }

    fn commit_credential_start(
        &mut self,
        context: &mut StateCoreContext,
        committed_count: u64,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        sealed: SealedAccountStart<CredentialChangeState>,
        reservation: Option<AccountId>,
    ) -> Option<CarrierCompletion> {
        let Ok(transaction) = sealed.into_transaction_after_commit(committed_count) else {
            return Some(CarrierCompletion::closed(generation, carrier_generation));
        };
        let transaction_id = transaction.binding().transaction_id();
        let deadline = transaction.binding().expires_at();
        if self
            .install_transaction_timer(
                context,
                generation,
                LiveTransactionClass::CredentialChange,
                transaction_id,
                deadline,
            )
            .is_err()
        {
            let cleanup = TransactionCleanup::credential(transaction_id, reservation, generation);
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::CredentialChange,
                cleanup,
            );
            return Some(CarrierCompletion::closed(generation, carrier_generation));
        }
        let Some(connection) = self.connections.get_mut(&generation) else {
            let cleanup = TransactionCleanup::credential(transaction_id, reservation, generation);
            let _queued = self.queue_transaction_cleanup(
                context,
                generation,
                LiveTransactionClass::CredentialChange,
                cleanup,
            );
            return None;
        };
        connection.credential_transaction = Some(LiveCredentialChange {
            transaction,
            reservation,
        });
        Some(CarrierCompletion::finished(
            generation,
            carrier_generation,
            ResultClass::Ok,
        ))
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-30 reason=credential postcommit keeps reservation sealed result and independently fenced authority sets explicit
    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=credential postcommit release invalidates account authorities clears reservations and returns the complete generation-fenced close set
    #[allow(clippy::too_many_arguments)]
    fn commit_credential_finish(
        &mut self,
        context: &mut StateCoreContext,
        committed_count: u64,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<CredentialReplacementIntent>,
        reservation: Option<AccountId>,
        fenced: Vec<ConnectionGeneration>,
        invalidated_authentications: Vec<ConnectionGeneration>,
        invalidated_grants: Vec<ConnectionGeneration>,
    ) -> Vec<CarrierCompletion> {
        if self
            .release_finished_transaction(
                generation,
                LiveTransactionClass::CredentialChange,
                transaction_id,
            )
            .is_err()
        {
            return vec![CarrierCompletion::closed(generation, carrier_generation)];
        }
        if let Some(account_id) = reservation
            && self
                .release_credential_reservation(account_id, generation)
                .is_err()
        {
            return vec![CarrierCompletion::closed(generation, carrier_generation)];
        }
        let Ok(result) = sealed.into_result_after_commit(committed_count) else {
            return vec![CarrierCompletion::closed(generation, carrier_generation)];
        };
        let Ok(_intent) = result else {
            return vec![CarrierCompletion::finished(
                generation,
                carrier_generation,
                ResultClass::Rejected,
            )];
        };
        for invalidated in invalidated_authentications {
            if let Some(connection) = self.connections.get_mut(&invalidated)
                && let Some(authentication) = connection.transaction.take()
            {
                let transaction_id = authentication.transaction.binding().transaction_id();
                context
                    .timers_mut()
                    .cancel(TimerKind::Reservation, TimedId::Transaction(transaction_id));
                let _released = self.release_finished_transaction(
                    invalidated,
                    LiveTransactionClass::Authentication,
                    transaction_id,
                );
            }
        }
        for invalidated in invalidated_grants {
            let Some(binding) = self
                .connections
                .get_mut(&invalidated)
                .and_then(|connection| connection.authenticated.take())
            else {
                continue;
            };
            context.timers_mut().cancel(
                TimerKind::Reservation,
                TimedId::Transaction(binding.transaction_id),
            );
            let _released = self.release_finished_transaction(
                invalidated,
                LiveTransactionClass::AuthenticationGrant,
                binding.transaction_id,
            );
            if let Some(connection) = self.connections.get_mut(&invalidated) {
                connection.credential_id = None;
                connection.fresh_authentication = None;
            }
            close_account_authority_after_flush(context, invalidated);
        }
        for fenced_generation in fenced {
            if let Some(connection) = self.connections.get_mut(&fenced_generation) {
                connection.authenticated = None;
                connection.credential_id = None;
                connection.fresh_authentication = None;
                connection.transaction = None;
                connection.credential_transaction = None;
            }
            close_account_authority_after_flush(context, fenced_generation);
        }
        close_account_authority_after_flush(context, generation);
        vec![CarrierCompletion::finished(
            generation,
            carrier_generation,
            ResultClass::Ok,
        )]
    }

    // agenc-review: allow owner=runtime reviewed=2026-08-29 reason=the postcommit finish authority carries every independently fenced session and key-transition result explicitly
    #[allow(clippy::too_many_arguments)]
    fn commit_finish(
        &mut self,
        context: &mut StateCoreContext,
        committed_count: u64,
        generation: ConnectionGeneration,
        carrier_generation: u64,
        transaction_id: TransactionId,
        sealed: SealedAccountFinishOutcome<AuthenticationGrant>,
        authenticated_at: MonotonicTick,
        sasl_accepted: bool,
        fresh_auth_session: Option<(agenc_ircd_types::UserId, Generation, AccountId)>,
        resulting_key_state: Option<LoginIndexKeyState>,
        login_index_migration: Option<CommittedLoginIndexMigration>,
    ) -> CarrierCompletion {
        if self
            .release_finished_transaction(
                generation,
                LiveTransactionClass::Authentication,
                transaction_id,
            )
            .is_err()
        {
            return CarrierCompletion::closed(generation, carrier_generation);
        }
        let Ok(result) = sealed.into_result_after_commit(committed_count) else {
            return CarrierCompletion::closed(generation, carrier_generation);
        };
        if let Some(key_state) = resulting_key_state {
            self.config.login_index_key_state = key_state;
        }
        if let Some(migration) = login_index_migration {
            let valid = result.as_ref().is_ok_and(|grant| {
                grant.account_id() == migration.account_id
                    && self.config.live_login_keys.get(&migration.account_id)
                        == Some(&migration.previous_key)
            });
            if !valid {
                return CarrierCompletion::closed(generation, carrier_generation);
            }
            self.config
                .live_login_keys
                .insert(migration.account_id, migration.current_key);
        }
        let accepted = result.is_ok() && sasl_accepted;
        let close = match result {
            Ok(grant) if sasl_accepted => self.install_committed_grant(
                context,
                generation,
                transaction_id,
                grant,
                authenticated_at,
                fresh_auth_session,
            ),
            _ => false,
        };
        CarrierCompletion::with_close(
            generation,
            carrier_generation,
            close,
            if accepted {
                ResultClass::Ok
            } else {
                ResultClass::Rejected
            },
        )
    }

    fn install_committed_grant(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        transaction_id: TransactionId,
        grant: AuthenticationGrant,
        authenticated_at: MonotonicTick,
        fresh_auth_session: Option<(agenc_ircd_types::UserId, Generation, AccountId)>,
    ) -> bool {
        match fresh_auth_session {
            Some(session) => self.install_registered_fresh_authentication(
                context,
                generation,
                grant,
                authenticated_at,
                session,
            ),
            None => self.install_preregistration_grant(
                context,
                generation,
                transaction_id,
                grant,
                authenticated_at,
            ),
        }
    }

    fn install_registered_fresh_authentication(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        grant: AuthenticationGrant,
        authenticated_at: MonotonicTick,
        session: (agenc_ircd_types::UserId, Generation, AccountId),
    ) -> bool {
        let (user_id, session_generation, account_id) = session;
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
        if applied.is_none() {
            return true;
        }
        let proof = grant.into_fresh_authentication_after_commit();
        let credential_id = duplicate_credential_id(proof.credential_id_for_replacement());
        let Some(connection) = self.connections.get_mut(&generation) else {
            return true;
        };
        connection.credential_id = Some(credential_id);
        connection.fresh_authentication = Some(proof);
        false
    }

    fn install_preregistration_grant(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        transaction_id: TransactionId,
        grant: AuthenticationGrant,
        authenticated_at: MonotonicTick,
    ) -> bool {
        let preregistered = context
            .sessions()
            .connection(generation)
            .is_some_and(|entry| entry.session().is_none());
        if !preregistered {
            return true;
        }
        let deadline = grant.process_expires_at();
        let Some(connection) = self.connections.get_mut(&generation) else {
            return true;
        };
        if connection.authenticated.is_some() {
            return true;
        }
        connection.authenticated = Some(AuthenticatedBinding {
            transaction_id,
            grant,
            authenticated_at,
        });
        if self
            .install_transaction_timer(
                context,
                generation,
                LiveTransactionClass::AuthenticationGrant,
                transaction_id,
                deadline,
            )
            .is_err()
        {
            if let Some(connection) = self.connections.get_mut(&generation) {
                connection.authenticated = None;
            }
            let cleanup = TransactionCleanup::authentication(transaction_id);
            if self.transaction_owners.get(&transaction_id)
                == Some(&(generation, LiveTransactionClass::AuthenticationGrant))
            {
                let _queued = self.queue_transaction_cleanup(
                    context,
                    generation,
                    LiveTransactionClass::AuthenticationGrant,
                    cleanup,
                );
            } else {
                let _queued = self.queue_unowned_transaction_cleanup(cleanup);
            }
            return true;
        }
        false
    }

    fn commit_login_tombstone_expiry(&mut self) {
        let Some(pending) = self.pending_login_tombstone_expiry.take() else {
            return;
        };
        let exact = pending.tombstones.iter().all(|(tombstone_id, key)| {
            self.config.login_deletion_tombstones.get(tombstone_id) == Some(key)
        });
        if !exact {
            return;
        }
        for (tombstone_id, _) in pending.tombstones {
            self.config.login_deletion_tombstones.remove(&tombstone_id);
        }
        if let Some(key_state) = pending.resulting_key_state {
            self.config.login_index_key_state = key_state;
        }
    }

    fn commit_account_deletions(
        &mut self,
        context: &mut StateCoreContext,
    ) -> Vec<CarrierCompletion> {
        let Some((_, pending)) = std::mem::take(&mut self.pending_account_deletions)
            .into_iter()
            .next()
        else {
            return Vec::new();
        };
        let _removed_login_key = self.config.live_login_keys.remove(&pending.account_id);
        for (generation, transaction_id) in pending.authentications {
            self.invalidate_deleted_authentication(context, generation, transaction_id);
        }
        for (generation, transaction_id) in pending.grants {
            self.invalidate_deleted_grant(context, generation, transaction_id);
        }
        pending.completions
    }

    fn invalidate_deleted_authentication(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        transaction_id: TransactionId,
    ) -> bool {
        let matches = self
            .connections
            .get(&generation)
            .and_then(|connection| connection.transaction.as_ref())
            .is_some_and(|authentication| {
                authentication.transaction.binding().transaction_id() == transaction_id
            });
        if !matches {
            return false;
        }
        if let Some(connection) = self.connections.get_mut(&generation) {
            connection.transaction = None;
            connection.credential_id = None;
            connection.fresh_authentication = None;
        }
        context
            .timers_mut()
            .cancel(TimerKind::Reservation, TimedId::Transaction(transaction_id));
        let _released = self.release_finished_transaction(
            generation,
            LiveTransactionClass::Authentication,
            transaction_id,
        );
        true
    }

    fn invalidate_deleted_grant(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        transaction_id: TransactionId,
    ) -> bool {
        let matches = self
            .connections
            .get(&generation)
            .and_then(|connection| connection.authenticated.as_ref())
            .is_some_and(|binding| binding.transaction_id == transaction_id);
        if !matches {
            return false;
        }
        if let Some(connection) = self.connections.get_mut(&generation) {
            connection.authenticated = None;
            connection.credential_id = None;
            connection.fresh_authentication = None;
        }
        context
            .timers_mut()
            .cancel(TimerKind::Reservation, TimedId::Transaction(transaction_id));
        if self.grant_consumptions.get(&generation) == Some(&transaction_id) {
            self.grant_consumptions.remove(&generation);
        } else {
            let _released = self.release_finished_transaction(
                generation,
                LiveTransactionClass::AuthenticationGrant,
                transaction_id,
            );
        }
        true
    }

    /// Releases sealed transaction/result authority only after the matching
    /// durable head became visible.
    // agenc-review: focus owner=runtime reviewed=2026-08-30 reason=closed postcommit dispatcher releases each sealed authority only against the matching visible response-count successor
    pub(crate) fn batch_applied(
        &mut self,
        context: &mut StateCoreContext,
    ) -> Vec<CarrierCompletion> {
        self.commit_login_tombstone_expiry();
        let mut completions = self.commit_account_deletions(context);
        for cleanup in std::mem::take(&mut self.pending_cleanups) {
            let _completed = self.complete_transaction_cleanup(cleanup);
        }
        let Some(authority) = self.pending_authority.take() else {
            completions.extend(self.progress(context));
            return completions;
        };
        let committed_count = context.head().account_service_response_count;
        let completion = match authority {
            PendingAuthority::Logout {
                generation,
                carrier_generation,
            } => Some(self.commit_logout(generation, carrier_generation)),
            PendingAuthority::CreationStart {
                generation,
                carrier_generation,
                sealed,
                reservation,
            } => self.commit_creation_start(
                context,
                committed_count,
                generation,
                carrier_generation,
                sealed,
                reservation,
            ),
            PendingAuthority::CreationFinish {
                generation,
                carrier_generation,
                transaction_id,
                sealed,
                reservation,
            } => Some(self.commit_creation_finish(
                committed_count,
                generation,
                carrier_generation,
                transaction_id,
                sealed,
                reservation,
            )),
            PendingAuthority::CredentialStart {
                generation,
                carrier_generation,
                sealed,
                reservation,
            } => self.commit_credential_start(
                context,
                committed_count,
                generation,
                carrier_generation,
                sealed,
                reservation,
            ),
            PendingAuthority::CredentialFinish {
                generation,
                carrier_generation,
                transaction_id,
                sealed,
                reservation,
                fenced,
                invalidated_authentications,
                invalidated_grants,
            } => {
                completions.extend(self.commit_credential_finish(
                    context,
                    committed_count,
                    generation,
                    carrier_generation,
                    transaction_id,
                    sealed,
                    reservation,
                    fenced,
                    invalidated_authentications,
                    invalidated_grants,
                ));
                None
            }
            PendingAuthority::Start {
                generation,
                carrier_generation,
                sealed,
                account_id,
                login,
                previous_value,
            } => self.commit_start(
                context,
                committed_count,
                generation,
                carrier_generation,
                sealed,
                account_id,
                login,
                previous_value,
            ),
            PendingAuthority::Finish {
                generation,
                carrier_generation,
                transaction_id,
                sealed,
                account_id: _,
                authenticated_at,
                sasl_accepted,
                fresh_auth_session,
                resulting_key_state,
                login_index_migration,
            } => Some(self.commit_finish(
                context,
                committed_count,
                generation,
                carrier_generation,
                transaction_id,
                sealed,
                authenticated_at,
                sasl_accepted,
                fresh_auth_session,
                resulting_key_state,
                login_index_migration,
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
        origin: Option<ConnectionGeneration>,
    ) -> Vec<CarrierCompletion> {
        if self.pending_login_tombstone_expiry.take().is_some() && origin.is_none() {
            let _scheduled = self.schedule_next_login_tombstone(context);
            return self.progress(context);
        }
        if !self.pending_cleanups.is_empty() && origin.is_none() {
            for cleanup in std::mem::take(&mut self.pending_cleanups).into_iter().rev() {
                self.cleanup_queue.push_front(cleanup);
            }
            return Vec::new();
        }
        let Some(authority) = self.pending_authority.take() else {
            return self.progress(context);
        };
        let generation = authority.generation();
        let carrier_generation = authority.carrier_generation();
        let credential_reservation = authority.credential_reservation();
        let cleanup = authority.into_transaction_cleanup();
        if let Some((class, cleanup)) = cleanup {
            let _queued = self.queue_transaction_cleanup(context, generation, class, cleanup);
        } else if let Some(account_id) = credential_reservation
            && self.credential_reservations.get(&account_id) == Some(&generation)
        {
            self.credential_reservations.remove(&account_id);
        }
        let mut completions = vec![CarrierCompletion::closed(generation, carrier_generation)];
        completions.extend(self.progress(context));
        completions
    }
}

impl AccountDeletionBarrier {
    fn fences_generation(&self, generation: ConnectionGeneration) -> bool {
        self.completions
            .iter()
            .any(|completion| completion.generation == generation)
            || self
                .authentications
                .iter()
                .any(|(pending, _)| *pending == generation)
            || self
                .grants
                .iter()
                .any(|(pending, _)| *pending == generation)
    }
}

fn pending_credential_finish_fences(
    fenced: &[ConnectionGeneration],
    generation: ConnectionGeneration,
) -> bool {
    fenced.contains(&generation)
}

fn pending_guest_account_switch_fences(
    pending_generation: ConnectionGeneration,
    generation: ConnectionGeneration,
    current_account_id: Option<AccountId>,
    current_session_generation: Generation,
    resulting_session_generation: Generation,
) -> bool {
    pending_generation == generation
        && current_account_id.is_none()
        && current_session_generation
            .checked_add(1)
            .is_ok_and(|successor| successor == resulting_session_generation)
}

fn login_tombstone_deadline(
    context: &StateCoreContext,
    expires_at: u64,
) -> Result<MonotonicTick, RuntimeError> {
    let delay_millis = if context.drift().wall_trusted() {
        match context.utc_now() {
            Ok(now_utc) => expires_at
                .saturating_sub(now_utc.get())
                .checked_mul(1_000)
                .ok_or(RuntimeError::Overflow)?,
            Err(_) => DRIFT_CHECK_INTERVAL_MILLIS,
        }
    } else {
        DRIFT_CHECK_INTERVAL_MILLIS
    };
    context
        .now()
        .checked_add(delay_millis)
        .map_err(|_| RuntimeError::Overflow)
}

fn login_tombstone_expiry_batch(
    tombstones: &BTreeMap<(u64, AccountId), StoredKey>,
    key_state: LoginIndexKeyState,
    now_utc: UtcSecond,
) -> Result<Option<LoginTombstoneExpiryBatch>, RuntimeError> {
    let mut expired = Vec::new();
    expired
        .try_reserve_exact(MAX_LOGIN_TOMBSTONE_EXPIRIES_PER_BATCH)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    let mut writes = Vec::new();
    writes
        .try_reserve_exact(MAX_LOGIN_TOMBSTONE_EXPIRIES_PER_BATCH.saturating_add(1))
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    let mut resulting_key_state = key_state;
    let mut key_state_changed = false;
    let mut successor = None;
    for (tombstone_id, key) in tombstones {
        if expired.len() == MAX_LOGIN_TOMBSTONE_EXPIRIES_PER_BATCH || tombstone_id.0 > now_utc.get()
        {
            successor = Some(*tombstone_id);
            break;
        }
        let stored_key = LoginIndexStoredKey::decode(key.as_bytes())?;
        if stored_key.generation() == key_state.current_generation() {
        } else if key_state
            .previous()
            .is_some_and(|(generation, _)| stored_key.generation() == generation)
        {
            resulting_key_state = resulting_key_state.decrement_previous()?;
            key_state_changed = true;
        } else {
            return Err(RuntimeError::Storage(
                agenc_ircd_storage::StorageError::StaleState,
            ));
        }
        writes.push(AccountServiceDurableWrite::delete(
            TableId::LoginIndex,
            key.clone(),
        )?);
        expired.push((*tombstone_id, key.clone()));
    }
    if expired.is_empty() {
        return Ok(None);
    }
    if key_state_changed {
        writes.push(AccountServiceDurableWrite::put(
            TableId::LoginIndexKeyState,
            StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            resulting_key_state.encode()?,
        )?);
    }
    Ok(Some(LoginTombstoneExpiryBatch {
        pending: PendingLoginTombstoneExpiry {
            tombstones: expired,
            resulting_key_state: key_state_changed.then_some(resulting_key_state),
        },
        writes,
        successor,
    }))
}

fn account_deletion_writes(
    account_id: AccountId,
    expires_at: UtcSecond,
    login_key: &StoredKey,
    authentications: &[(ConnectionGeneration, TransactionId)],
    grants: &[(ConnectionGeneration, TransactionId)],
) -> Result<Vec<AccountServiceDurableWrite>, RuntimeError> {
    let stored_login_key = LoginIndexStoredKey::decode(login_key.as_bytes())?;
    let tombstone = LoginIndexValue::new(
        &stored_login_key,
        LoginIndexValueKind::DeletionTombstone {
            deleted_account_id: account_id,
            expires_at: expires_at.get(),
        },
    )?;
    let write_count = 2_usize
        .checked_add(authentications.len())
        .and_then(|count| count.checked_add(grants.len()))
        .ok_or(RuntimeError::Overflow)?;
    let mut writes = Vec::new();
    writes
        .try_reserve_exact(write_count)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    writes.push(AccountServiceDurableWrite::put(
        TableId::LoginIndex,
        login_key.clone(),
        tombstone.encode()?,
    )?);
    writes.push(AccountServiceDurableWrite::delete(
        TableId::OpaqueRecord,
        StoredKey::new(account_id.to_text().into_bytes())?,
    )?);
    for (_, transaction_id) in authentications.iter().chain(grants) {
        writes.push(AccountServiceDurableWrite::delete(
            TableId::AuthTransaction,
            StoredKey::new(transaction_id.as_bytes().to_vec())?,
        )?);
    }
    Ok(writes)
}

fn close_account_authority_after_flush(
    context: &StateCoreContext,
    generation: ConnectionGeneration,
) {
    if let Some(sink) = context.sessions().sink_for_generation(generation) {
        let _acknowledgement = sink.close_after_flush(CloseReason::ClientQuit);
    }
}

fn account_deletion_completions(
    generation: ConnectionGeneration,
    authentications: &[(ConnectionGeneration, TransactionId)],
    grants: &[(ConnectionGeneration, TransactionId)],
) -> Result<Vec<CarrierCompletion>, RuntimeError> {
    // One deletion origin plus the two bounded progress continuations that
    // may fail immediately after the receipt becomes visible.
    let completion_capacity = 3_usize
        .checked_add(authentications.len())
        .and_then(|count| count.checked_add(grants.len()))
        .ok_or(RuntimeError::Overflow)?;
    let mut completions = Vec::new();
    completions
        .try_reserve_exact(completion_capacity)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    completions.push(CarrierCompletion::closed(generation, 0));
    for (closing_generation, _) in authentications.iter().chain(grants) {
        if !completions
            .iter()
            .any(|completion| completion.generation == *closing_generation)
        {
            completions.push(CarrierCompletion::closed(*closing_generation, 0));
        }
    }
    Ok(completions)
}

fn transaction_cleanup_batch(
    cleanup_queue: &VecDeque<TransactionCleanup>,
) -> Result<(usize, Vec<AccountServiceDurableWrite>), RuntimeError> {
    let cleanup_count = cleanup_queue.len().min(MAX_TRANSACTION_CLEANUPS_PER_BATCH);
    let mut writes = Vec::new();
    writes
        .try_reserve_exact(cleanup_count.saturating_mul(3))
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for cleanup in cleanup_queue.iter().take(cleanup_count) {
        writes.extend(cleanup.durable_writes()?);
    }
    Ok((cleanup_count, writes))
}

impl PendingRead {
    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::Replay(request)
            | Self::CurrentIndex { request, .. }
            | Self::PreviousIndex { request, .. }
            | Self::OpaqueRecord { request, .. }
            | Self::CreationCurrentIndex { request, .. }
            | Self::CreationPreviousIndex { request, .. }
            | Self::CreationInvitation { request, .. }
            | Self::CredentialOpaque { request, .. } => request.generation,
        }
    }

    const fn carrier_generation(&self) -> u64 {
        match self {
            Self::Replay(request)
            | Self::CurrentIndex { request, .. }
            | Self::PreviousIndex { request, .. }
            | Self::OpaqueRecord { request, .. }
            | Self::CreationCurrentIndex { request, .. }
            | Self::CreationPreviousIndex { request, .. }
            | Self::CreationInvitation { request, .. }
            | Self::CredentialOpaque { request, .. } => request.carrier_generation,
        }
    }
}

impl PendingCrypto {
    fn into_transaction_cleanup(self) -> Option<(LiveTransactionClass, TransactionCleanup)> {
        match self {
            Self::CreationFinish {
                transaction_id,
                reservation,
                ..
            }
            | Self::CreationFinishSeal {
                transaction_id,
                reservation,
                ..
            } => Some((
                LiveTransactionClass::Creation,
                TransactionCleanup::creation(transaction_id, reservation),
            )),
            Self::CredentialFinish {
                request,
                transaction_id,
                reservation,
            }
            | Self::CredentialFinishSeal {
                request,
                transaction_id,
                reservation,
            } => Some((
                LiveTransactionClass::CredentialChange,
                TransactionCleanup::credential(transaction_id, reservation, request.generation),
            )),
            Self::Finish { transaction_id, .. } | Self::FinishSeal { transaction_id, .. } => {
                Some((
                    LiveTransactionClass::Authentication,
                    TransactionCleanup::authentication(transaction_id),
                ))
            }
            _ => None,
        }
    }

    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::Open(request)
            | Self::CreationPreflight { request }
            | Self::CreationStart { request }
            | Self::CreationStartSeal { request }
            | Self::CreationFinish { request, .. }
            | Self::CreationFinishSeal { request, .. }
            | Self::CredentialStart { request, .. }
            | Self::CredentialStartSeal { request, .. }
            | Self::CredentialFinish { request, .. }
            | Self::CredentialFinishSeal { request, .. }
            | Self::Start { request, .. }
            | Self::StartSeal { request, .. }
            | Self::Finish { request, .. }
            | Self::FinishSeal { request, .. } => request.generation,
        }
    }

    const fn carrier_generation(&self) -> u64 {
        match self {
            Self::Open(request)
            | Self::CreationPreflight { request }
            | Self::CreationStart { request }
            | Self::CreationStartSeal { request }
            | Self::CreationFinish { request, .. }
            | Self::CreationFinishSeal { request, .. }
            | Self::CredentialStart { request, .. }
            | Self::CredentialStartSeal { request, .. }
            | Self::CredentialFinish { request, .. }
            | Self::CredentialFinishSeal { request, .. }
            | Self::Start { request, .. }
            | Self::StartSeal { request, .. }
            | Self::Finish { request, .. }
            | Self::FinishSeal { request, .. } => request.carrier_generation,
        }
    }
}

impl ReadySeal {
    fn transaction_cleanup(
        &self,
    ) -> Option<(
        ConnectionGeneration,
        LiveTransactionClass,
        TransactionCleanup,
    )> {
        match self {
            Self::CreationFinish {
                request,
                transaction_id,
                reservation,
                ..
            } => Some((
                request.generation,
                LiveTransactionClass::Creation,
                TransactionCleanup::creation(*transaction_id, reservation.clone()),
            )),
            Self::CredentialFinish {
                request,
                transaction_id,
                reservation,
                ..
            } => Some((
                request.generation,
                LiveTransactionClass::CredentialChange,
                TransactionCleanup::credential(*transaction_id, *reservation, request.generation),
            )),
            Self::Finish {
                request,
                transaction_id,
                ..
            } => Some((
                request.generation,
                LiveTransactionClass::Authentication,
                TransactionCleanup::authentication(*transaction_id),
            )),
            _ => None,
        }
    }

    fn into_transaction_cleanup(self) -> Option<(LiveTransactionClass, TransactionCleanup)> {
        match self {
            Self::CreationFinish {
                transaction_id,
                reservation,
                ..
            } => Some((
                LiveTransactionClass::Creation,
                TransactionCleanup::creation(transaction_id, reservation),
            )),
            Self::CredentialFinish {
                request,
                transaction_id,
                reservation,
                ..
            } => Some((
                LiveTransactionClass::CredentialChange,
                TransactionCleanup::credential(transaction_id, reservation, request.generation),
            )),
            Self::Finish { transaction_id, .. } => Some((
                LiveTransactionClass::Authentication,
                TransactionCleanup::authentication(transaction_id),
            )),
            _ => None,
        }
    }

    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::CreationStart { request, .. }
            | Self::CreationFinish { request, .. }
            | Self::CredentialStart { request, .. }
            | Self::CredentialFinish { request, .. }
            | Self::Start { request, .. }
            | Self::Finish { request, .. } => request.generation,
        }
    }
}

impl ReadyStage {
    fn transaction_cleanup(
        &self,
    ) -> Option<(
        ConnectionGeneration,
        LiveTransactionClass,
        TransactionCleanup,
    )> {
        match self {
            Self::CreationFinish {
                request,
                transaction_id,
                reservation,
                ..
            } => Some((
                request.generation,
                LiveTransactionClass::Creation,
                TransactionCleanup::creation(*transaction_id, reservation.clone()),
            )),
            Self::CredentialFinish {
                request,
                transaction_id,
                reservation,
                ..
            } => Some((
                request.generation,
                LiveTransactionClass::CredentialChange,
                TransactionCleanup::credential(*transaction_id, *reservation, request.generation),
            )),
            Self::Finish {
                request,
                transaction_id,
                ..
            } => Some((
                request.generation,
                LiveTransactionClass::Authentication,
                TransactionCleanup::authentication(*transaction_id),
            )),
            _ => None,
        }
    }

    fn into_transaction_cleanup(self) -> Option<(LiveTransactionClass, TransactionCleanup)> {
        match self {
            Self::CreationFinish {
                transaction_id,
                reservation,
                ..
            } => Some((
                LiveTransactionClass::Creation,
                TransactionCleanup::creation(transaction_id, reservation),
            )),
            Self::CredentialFinish {
                request,
                transaction_id,
                reservation,
                ..
            } => Some((
                LiveTransactionClass::CredentialChange,
                TransactionCleanup::credential(transaction_id, reservation, request.generation),
            )),
            Self::Finish { transaction_id, .. } => Some((
                LiveTransactionClass::Authentication,
                TransactionCleanup::authentication(transaction_id),
            )),
            _ => None,
        }
    }

    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::CreationStart { request, .. }
            | Self::CreationFinish { request, .. }
            | Self::CredentialStart { request, .. }
            | Self::CredentialFinish { request, .. }
            | Self::Start { request, .. }
            | Self::Finish { request, .. } => request.generation,
        }
    }

    const fn carrier_generation(&self) -> u64 {
        match self {
            Self::CreationStart { request, .. }
            | Self::CreationFinish { request, .. }
            | Self::CredentialStart { request, .. }
            | Self::CredentialFinish { request, .. }
            | Self::Start { request, .. }
            | Self::Finish { request, .. } => request.carrier_generation,
        }
    }
}

impl PendingAuthority {
    fn into_transaction_cleanup(self) -> Option<(LiveTransactionClass, TransactionCleanup)> {
        match self {
            Self::CreationFinish {
                transaction_id,
                reservation,
                ..
            } => Some((
                LiveTransactionClass::Creation,
                TransactionCleanup::creation(transaction_id, reservation),
            )),
            Self::CredentialFinish {
                generation,
                transaction_id,
                reservation,
                ..
            } => Some((
                LiveTransactionClass::CredentialChange,
                TransactionCleanup::credential(transaction_id, reservation, generation),
            )),
            Self::Finish { transaction_id, .. } => Some((
                LiveTransactionClass::Authentication,
                TransactionCleanup::authentication(transaction_id),
            )),
            _ => None,
        }
    }

    const fn credential_reservation(&self) -> Option<AccountId> {
        match self {
            Self::CredentialStart { reservation, .. }
            | Self::CredentialFinish { reservation, .. } => *reservation,
            _ => None,
        }
    }

    const fn generation(&self) -> ConnectionGeneration {
        match self {
            Self::Logout { generation, .. }
            | Self::CreationStart { generation, .. }
            | Self::CreationFinish { generation, .. }
            | Self::CredentialStart { generation, .. }
            | Self::CredentialFinish { generation, .. }
            | Self::Start { generation, .. }
            | Self::Finish { generation, .. } => *generation,
        }
    }

    const fn carrier_generation(&self) -> u64 {
        match self {
            Self::Logout {
                carrier_generation, ..
            }
            | Self::CreationStart {
                carrier_generation, ..
            }
            | Self::CreationFinish {
                carrier_generation, ..
            }
            | Self::CredentialStart {
                carrier_generation, ..
            }
            | Self::CredentialFinish {
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

fn consume_opaque_connection_attempt(attempts: &mut u8) -> Result<(), RuntimeError> {
    if *attempts >= MAX_OPAQUE_ATTEMPTS_PER_CONNECTION {
        return Err(RuntimeError::LimitExceeded);
    }
    *attempts = attempts.checked_add(1).ok_or(RuntimeError::Overflow)?;
    Ok(())
}

fn request_result_key(request_id: RequestId) -> Result<StoredKey, RuntimeError> {
    Ok(StoredKey::new(request_id.as_bytes().to_vec())?)
}

fn replay_terminal_account(
    message_kind: AccountServiceMessageKind,
    terminal: RequestTerminal,
    terminal_account: Option<AccountId>,
) -> Result<Option<AccountId>, RuntimeError> {
    match (message_kind, terminal, terminal_account) {
        (
            AccountServiceMessageKind::AccountCreateFinish,
            RequestTerminal::Accepted,
            Some(account_id),
        ) => Ok(Some(account_id)),
        (AccountServiceMessageKind::AccountCreateFinish, RequestTerminal::Rejected, None) => {
            Ok(None)
        }
        (AccountServiceMessageKind::AccountCreateFinish, _, _) => Err(RuntimeError::InvalidValue),
        (_, _, None) => Ok(None),
        (_, _, Some(_)) => Err(RuntimeError::InvalidValue),
    }
}

fn request_result_write(
    revision: u64,
    request: &RequestContext,
    terminal: RequestTerminal,
    terminal_account: Option<AccountId>,
    response: &[u8; ACCOUNT_SERVICE_RESPONSE_BYTES],
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    let record = RequestResultRecord {
        route: request.route,
        terminal,
        terminal_account,
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

fn account_created_note(prefix: &str, account_id: AccountId) -> Result<WireMessage, RuntimeError> {
    let account = account_id.to_text();
    WireMessage::new(
        prefix,
        "NOTE",
        &["ACCTCREATE", "CREATED", &account],
        Some("Account created"),
    )
    .map_err(|_| RuntimeError::InvalidValue)
}

fn account_credential_changed_note(prefix: &str) -> Result<WireMessage, RuntimeError> {
    WireMessage::new(
        prefix,
        "NOTE",
        &["ACCTCRED", "CHANGED"],
        Some("Account credential changed; reconnect required"),
    )
    .map_err(|_| RuntimeError::InvalidValue)
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

fn duplicate_credential_id(
    credential_id: &agenc_ircd_types::OpaqueCredentialId,
) -> agenc_ircd_types::OpaqueCredentialId {
    agenc_ircd_types::OpaqueCredentialId::from_bytes(*credential_id.expose_for_account_service())
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

fn render_account_actions(
    prefix: &str,
    kind: AccountCarrierKind,
    actions: Vec<AccountCarrierAction>,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(actions.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for action in actions {
        frames.push(render_account_action(prefix, kind, action)?);
    }
    Ok(frames)
}

fn render_account_action(
    prefix: &str,
    kind: AccountCarrierKind,
    action: AccountCarrierAction,
) -> Result<WireMessage, RuntimeError> {
    let frame = match action {
        AccountCarrierAction::Ready(phase) => WireMessage::new(
            prefix,
            kind.command(),
            &["READY", account_phase_name(phase), "4726"],
            None,
        ),
        AccountCarrierAction::ResponseStart(phase) => {
            let response = match phase {
                AccountCarrierPhase::Start => "CHALLENGE",
                AccountCarrierPhase::Finish => "COMPLETE",
            };
            WireMessage::new(prefix, kind.command(), &[response, "4342"], None)
        }
        AccountCarrierAction::Data(chunk) => {
            let text =
                std::str::from_utf8(chunk.expose()).map_err(|_| RuntimeError::InvalidValue)?;
            WireMessage::new(prefix, kind.command(), &["DATA", text], None)
        }
        AccountCarrierAction::End => WireMessage::new(prefix, kind.command(), &["END"], None),
        AccountCarrierAction::RequestEnvelope { .. } => return Err(RuntimeError::InvalidValue),
    }
    .map_err(|_| RuntimeError::InvalidValue)?;
    Ok(frame)
}

const fn account_phase_name(phase: AccountCarrierPhase) -> &'static str {
    match phase {
        AccountCarrierPhase::Start => "START",
        AccountCarrierPhase::Finish => "FINISH",
    }
}

fn account_failure(prefix: &str, kind: AccountCarrierKind) -> Result<WireMessage, RuntimeError> {
    let description = match kind {
        AccountCarrierKind::Create => "Account creation unavailable",
        AccountCarrierKind::Credentials => "Credential change unavailable",
    };
    WireMessage::new(
        prefix,
        "FAIL",
        &[kind.command(), "UNAVAILABLE"],
        Some(description),
    )
    .map_err(|_| RuntimeError::InvalidValue)
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

const fn sasl_action_result(action: &SaslAction) -> ResultClass {
    match action {
        SaslAction::Numeric(SaslNumeric::Success) => ResultClass::Ok,
        SaslAction::Numeric(
            SaslNumeric::Failed
            | SaslNumeric::TooLong
            | SaslNumeric::Aborted
            | SaslNumeric::AlreadyAuthenticated
            | SaslNumeric::Mechanisms,
        ) => ResultClass::Rejected,
        SaslAction::SendPlus
        | SaslAction::SendChunk(_)
        | SaslAction::RequestEnvelope { .. }
        | SaslAction::Logout => ResultClass::Ok,
    }
}

const fn request_terminal_result(terminal: RequestTerminal) -> ResultClass {
    match terminal {
        RequestTerminal::Start | RequestTerminal::Accepted => ResultClass::Ok,
        RequestTerminal::Rejected => ResultClass::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountCarrierAction, AccountCarrierKind, AccountCarrierPhase, AccountCreationPolicy,
        AccountDeletionBarrier, AccountServiceConfig, AccountServiceCoordinator, CarrierCompletion,
        CarrierRoute, ConnectionGeneration, ConnectionRoute, CreationReservation,
        LiveTransactionClass, MAX_OPAQUE_ATTEMPTS_PER_CONNECTION, MAX_PENDING_TRANSACTION_CLEANUPS,
        PendingAuthority, PendingCrypto, PendingLoginTombstoneExpiry, REQUEST_RESULT_BYTES,
        REQUEST_RESULT_VERSION, RequestCarrier, RequestContext, RequestResultCursor,
        RequestResultRecord, RequestTerminal, RuntimeError, TransactionCleanup,
        account_created_note, account_credential_changed_note, account_deletion_completions,
        account_deletion_writes, account_failure, account_phase_name,
        consume_opaque_connection_attempt, credential_id, live_login, login_tombstone_expiry_batch,
        opaque_attempt_demand, pending_credential_finish_fences,
        pending_guest_account_switch_fences, render_account_action, render_sasl_action,
        render_sasl_actions, replay_terminal_account, request_terminal_result, sasl_action_result,
        select_live_login, transaction_cleanup_batch,
    };
    use crate::admission::{BucketTable, RateLimits};
    use crate::bridge::crypto::{ChannelKeyVerdict, CryptoJobOutput};
    use crate::bridge::{CryptoCompletionMessage, CryptoJobId};
    use crate::budget::MemoryBudget;
    use crate::observe::metrics::ResultClass;
    use crate::runtime_config::AccountRuntimePolicy;
    use crate::state_core::StateCoreContext;
    use crate::state_core::durable::AccountServiceDurableWrite;
    use crate::sync::Arc;
    use crate::test_support::StateCoreFixture;
    use agenc_ircd_auth::AccountServiceEnvelope;
    use agenc_ircd_client_wire::{
        FramedLine, OutputBudget, RenderError, SASL_REQUEST_CHARACTERS, SaslAction, SaslNumeric,
        SecretBytes, parse_message,
    };
    use agenc_ircd_crypto::{
        ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES, AccountHpkePrivateKey, LoginIndexDigest,
        LoginIndexKey, OpaqueFakeCredentialKey, derive_login_index,
    };
    use agenc_ircd_domain::{DirectMessagePolicy, GuestDirectMessagePolicy, PresencePolicy};
    use agenc_ircd_storage::{
        LoginIndexKeyState, LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind, StoredKey,
        TableId,
    };
    use agenc_ircd_types::{
        AccountId, AccountRandomId, AccountServiceMessageKind, ConnectionId, Generation, InviteId,
        MonotonicTick, NetworkId, NormalizedLogin, OpaqueCredentialId, OriginId, TransactionId,
        UtcSecond,
    };
    use std::collections::{BTreeMap, VecDeque};

    struct CoordinatorFixture {
        coordinator: AccountServiceCoordinator,
        core: StateCoreFixture,
    }

    impl CoordinatorFixture {
        fn new(entropy: Vec<u8>) -> Result<Self, Box<dyn core::error::Error>> {
            let core = StateCoreFixture::new(entropy)?;
            let identity = &core.identity;
            let coordinator = AccountServiceCoordinator::new(AccountServiceConfig {
                network_id: identity.network_id,
                server_id: identity.server_id,
                server_incarnation: identity.server_incarnation,
                origin_id: OriginId::from_bytes([39; 16]),
                origin_generation: Generation::new(1)?,
                recovery_epoch: identity.recovery_epoch,
                hpke_private_key: Arc::new(AccountHpkePrivateKey::from_bytes([40; 32])?),
                opaque_profile: Arc::clone(&core.opaque),
                current_login_index_key: Arc::new(LoginIndexKey::from_bytes(identity.login_index)),
                previous_login_index_key: None,
                fake_credential_key: Arc::new(OpaqueFakeCredentialKey::from_bytes([41; 32])),
                login_index_key_state: core.key_state,
                live_login_keys: BTreeMap::new(),
                login_deletion_tombstones: BTreeMap::new(),
                startup_transaction_cleanups: Vec::new(),
                creation_policy: AccountCreationPolicy::Open,
                default_presence: PresencePolicy::Private,
                default_guest_direct_messages: GuestDirectMessagePolicy::Deny,
                default_direct_messages: DirectMessagePolicy::Allow,
            })?;
            Ok(Self { coordinator, core })
        }

        fn parts(
            &mut self,
        ) -> Result<(&mut AccountServiceCoordinator, &mut StateCoreContext), RuntimeError> {
            Ok((&mut self.coordinator, self.core.context_mut()?))
        }
    }

    struct ExactBudget(usize);

    impl OutputBudget for ExactBudget {
        type Permit = ();

        fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
            (bytes == self.0)
                .then_some(())
                .ok_or(RenderError::ReservationFailed)
        }
    }

    fn encoded(message: agenc_ircd_client_wire::WireMessage) -> Result<Vec<u8>, RenderError> {
        let measured = message.measure()?;
        let mut budget = ExactBudget(measured.bytes());
        Ok(measured.encode(&mut budget)?.as_bytes().to_vec())
    }

    fn account(byte: u8) -> AccountId {
        AccountId::from_random(AccountRandomId::from_bytes([byte; 16]))
    }

    fn parsed(
        line: &str,
    ) -> Result<agenc_ircd_client_wire::ParsedMessage, Box<dyn core::error::Error>> {
        parse_message(FramedLine::new(line)?)?.ok_or_else(|| "empty test message".into())
    }

    fn structural_envelope(
        kind: AccountServiceMessageKind,
    ) -> Result<AccountServiceEnvelope, Box<dyn core::error::Error>> {
        let mut encoded = [0_u8; agenc_ircd_auth::ACCOUNT_SERVICE_ENVELOPE_BYTES];
        encoded
            .get_mut(..2)
            .ok_or(RuntimeError::InvalidValue)?
            .copy_from_slice(&1_u16.to_be_bytes());
        let kind_offset = 2 + 32 + 32 + 16;
        encoded
            .get_mut(kind_offset..kind_offset + 2)
            .ok_or(RuntimeError::InvalidValue)?
            .copy_from_slice(&kind.wire_value().to_be_bytes());
        let ciphertext_length_offset = kind_offset + 2 + 32;
        let ciphertext_length = u16::try_from(ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES)?;
        encoded
            .get_mut(ciphertext_length_offset..ciphertext_length_offset + 2)
            .ok_or(RuntimeError::InvalidValue)?
            .copy_from_slice(&ciphertext_length.to_be_bytes());
        Ok(AccountServiceEnvelope::parse(encoded)?)
    }

    fn request_context(
        generation: u64,
        carrier_generation: u64,
        carrier: RequestCarrier,
        phase: AccountCarrierPhase,
    ) -> Result<RequestContext, Box<dyn core::error::Error>> {
        let kind = match (carrier, phase) {
            (RequestCarrier::Sasl, AccountCarrierPhase::Start) => {
                AccountServiceMessageKind::OpaqueAuthStart
            }
            (RequestCarrier::Sasl, AccountCarrierPhase::Finish) => {
                AccountServiceMessageKind::OpaqueAuthFinish
            }
            (RequestCarrier::Account(AccountCarrierKind::Create), AccountCarrierPhase::Start) => {
                AccountServiceMessageKind::AccountCreateStart
            }
            (RequestCarrier::Account(AccountCarrierKind::Create), AccountCarrierPhase::Finish) => {
                AccountServiceMessageKind::AccountCreateFinish
            }
            (
                RequestCarrier::Account(AccountCarrierKind::Credentials),
                AccountCarrierPhase::Start,
            ) => AccountServiceMessageKind::CredentialChangeStart,
            (
                RequestCarrier::Account(AccountCarrierKind::Credentials),
                AccountCarrierPhase::Finish,
            ) => AccountServiceMessageKind::CredentialChangeFinish,
        };
        Ok(RequestContext {
            generation: ConnectionGeneration::new(generation),
            carrier_generation,
            target: "tester".to_owned(),
            route: ConnectionRoute {
                origin_id: OriginId::from_bytes([1; 16]),
                origin_generation: Generation::new(1)?,
                connection_id: ConnectionId::from_bytes([2; 16]),
                connection_nonce: [3; 32],
            },
            envelope: structural_envelope(kind)?,
            carrier,
            phase,
        })
    }

    #[test]
    fn request_context_and_pending_crypto_cover_every_closed_variant()
    -> Result<(), Box<dyn core::error::Error>> {
        let cases = [
            (
                RequestCarrier::Sasl,
                AccountCarrierPhase::Start,
                AccountServiceMessageKind::OpaqueAuthStart,
            ),
            (
                RequestCarrier::Sasl,
                AccountCarrierPhase::Finish,
                AccountServiceMessageKind::OpaqueAuthFinish,
            ),
            (
                RequestCarrier::Account(AccountCarrierKind::Create),
                AccountCarrierPhase::Start,
                AccountServiceMessageKind::AccountCreateStart,
            ),
            (
                RequestCarrier::Account(AccountCarrierKind::Create),
                AccountCarrierPhase::Finish,
                AccountServiceMessageKind::AccountCreateFinish,
            ),
            (
                RequestCarrier::Account(AccountCarrierKind::Credentials),
                AccountCarrierPhase::Start,
                AccountServiceMessageKind::CredentialChangeStart,
            ),
            (
                RequestCarrier::Account(AccountCarrierKind::Credentials),
                AccountCarrierPhase::Finish,
                AccountServiceMessageKind::CredentialChangeFinish,
            ),
        ];
        for (carrier, phase, expected) in cases {
            let request = request_context(1, 7, carrier, phase)?;
            assert_eq!(request.is_finish(), phase == AccountCarrierPhase::Finish);
            assert_eq!(request.expected_message_kind(), expected);
        }

        let login = || NormalizedLogin::prepare("bounded-user");
        let pending = vec![
            PendingCrypto::Open(request_context(
                1,
                1,
                RequestCarrier::Sasl,
                AccountCarrierPhase::Start,
            )?),
            PendingCrypto::CreationPreflight {
                request: request_context(
                    2,
                    2,
                    RequestCarrier::Account(AccountCarrierKind::Create),
                    AccountCarrierPhase::Start,
                )?,
            },
            PendingCrypto::CreationStart {
                request: request_context(
                    3,
                    3,
                    RequestCarrier::Account(AccountCarrierKind::Create),
                    AccountCarrierPhase::Start,
                )?,
            },
            PendingCrypto::CreationStartSeal {
                request: request_context(
                    4,
                    4,
                    RequestCarrier::Account(AccountCarrierKind::Create),
                    AccountCarrierPhase::Start,
                )?,
            },
            PendingCrypto::CreationFinish {
                request: request_context(
                    5,
                    5,
                    RequestCarrier::Account(AccountCarrierKind::Create),
                    AccountCarrierPhase::Finish,
                )?,
                transaction_id: TransactionId::from_bytes([5; 16]),
                reservation: None,
            },
            PendingCrypto::CreationFinishSeal {
                request: request_context(
                    6,
                    6,
                    RequestCarrier::Account(AccountCarrierKind::Create),
                    AccountCarrierPhase::Finish,
                )?,
                transaction_id: TransactionId::from_bytes([6; 16]),
                reservation: Some(CreationReservation {
                    login_key: StoredKey::new(vec![6])?,
                    invitation_id: None,
                }),
            },
            PendingCrypto::CredentialStart {
                request: request_context(
                    7,
                    7,
                    RequestCarrier::Account(AccountCarrierKind::Credentials),
                    AccountCarrierPhase::Start,
                )?,
                reservation: None,
            },
            PendingCrypto::CredentialStartSeal {
                request: request_context(
                    8,
                    8,
                    RequestCarrier::Account(AccountCarrierKind::Credentials),
                    AccountCarrierPhase::Start,
                )?,
                reservation: Some(account(8)),
            },
            PendingCrypto::CredentialFinish {
                request: request_context(
                    9,
                    9,
                    RequestCarrier::Account(AccountCarrierKind::Credentials),
                    AccountCarrierPhase::Finish,
                )?,
                transaction_id: TransactionId::from_bytes([9; 16]),
                reservation: None,
            },
            PendingCrypto::CredentialFinishSeal {
                request: request_context(
                    10,
                    10,
                    RequestCarrier::Account(AccountCarrierKind::Credentials),
                    AccountCarrierPhase::Finish,
                )?,
                transaction_id: TransactionId::from_bytes([10; 16]),
                reservation: Some(account(10)),
            },
            PendingCrypto::Start {
                request: request_context(11, 11, RequestCarrier::Sasl, AccountCarrierPhase::Start)?,
                account_id: None,
                login: login()?,
                previous_value: None,
            },
            PendingCrypto::StartSeal {
                request: request_context(12, 12, RequestCarrier::Sasl, AccountCarrierPhase::Start)?,
                account_id: Some(account(12)),
                login: login()?,
                previous_value: None,
            },
            PendingCrypto::Finish {
                request: request_context(
                    13,
                    13,
                    RequestCarrier::Sasl,
                    AccountCarrierPhase::Finish,
                )?,
                transaction_id: TransactionId::from_bytes([13; 16]),
                account_id: None,
                login: login()?,
                previous_value: None,
                authenticated_at: MonotonicTick::from_ticks(1),
            },
            PendingCrypto::FinishSeal {
                request: request_context(
                    14,
                    14,
                    RequestCarrier::Sasl,
                    AccountCarrierPhase::Finish,
                )?,
                transaction_id: TransactionId::from_bytes([14; 16]),
                account_id: Some(account(14)),
                login: login()?,
                previous_value: None,
                authenticated_at: MonotonicTick::from_ticks(1),
            },
        ];
        let mut cleanup_count = 0;
        for (index, pending) in pending.into_iter().enumerate() {
            let generation = u64::try_from(index)?.saturating_add(1);
            assert_eq!(pending.generation(), ConnectionGeneration::new(generation));
            assert_eq!(pending.carrier_generation(), generation);
            if pending.into_transaction_cleanup().is_some() {
                cleanup_count += 1;
            }
        }
        assert_eq!(cleanup_count, 6);
        Ok(())
    }

    #[test]
    fn coordinator_internal_fences_cover_each_independent_busy_source()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut fixture = CoordinatorFixture::new(vec![1; 96])?;
        let coordinator = &mut fixture.coordinator;
        let generation = ConnectionGeneration::new(1);
        let transaction = TransactionId::from_bytes([1; 16]);
        assert!(coordinator.reload_ready());
        assert!(coordinator.exclusive_account_service_transition_available());

        coordinator.pending_authority = Some(PendingAuthority::Logout {
            generation,
            carrier_generation: 1,
        });
        assert!(!coordinator.exclusive_account_service_transition_available());
        coordinator.pending_authority = None;

        coordinator
            .pending_cleanups
            .push(TransactionCleanup::authentication(transaction));
        assert!(!coordinator.exclusive_account_service_transition_available());
        coordinator.pending_cleanups.clear();

        coordinator
            .cleanup_queue
            .push_back(TransactionCleanup::authentication(transaction));
        assert!(!coordinator.exclusive_account_service_transition_available());
        coordinator.cleanup_queue.clear();

        coordinator
            .grant_consumptions
            .insert(generation, transaction);
        assert!(!coordinator.exclusive_account_service_transition_available());
        coordinator.grant_consumptions.clear();

        coordinator.pending_account_deletions.insert(
            generation,
            AccountDeletionBarrier {
                account_id: account(1),
                tombstone_id: (100, account(1)),
                authentications: Vec::new(),
                grants: Vec::new(),
                completions: Vec::new(),
            },
        );
        assert!(!coordinator.exclusive_account_service_transition_available());
        coordinator.pending_account_deletions.clear();

        coordinator.pending_login_tombstone_expiry = Some(PendingLoginTombstoneExpiry {
            tombstones: Vec::new(),
            resulting_key_state: None,
        });
        assert!(!coordinator.exclusive_account_service_transition_available());
        coordinator.pending_login_tombstone_expiry = None;

        assert!(coordinator.account_deletion_transition_available(account(2)));
        coordinator
            .credential_reservations
            .insert(account(2), generation);
        assert!(!coordinator.account_deletion_transition_available(account(2)));
        assert!(coordinator.retains_credential_reservation(generation, true));
        assert!(!coordinator.retains_credential_reservation(ConnectionGeneration::new(2), false));
        coordinator.credential_reservations.clear();
        coordinator.credential_cleanup_owners.insert(generation);
        assert!(coordinator.retains_credential_reservation(generation, false));
        coordinator.credential_cleanup_owners.clear();
        coordinator.transaction_owners.insert(
            transaction,
            (generation, LiveTransactionClass::CredentialChange),
        );
        assert!(coordinator.retains_credential_reservation(generation, false));

        assert!(
            coordinator
                .release_finished_transaction(
                    generation,
                    LiveTransactionClass::CredentialChange,
                    transaction,
                )
                .is_ok()
        );
        assert!(
            coordinator
                .release_finished_transaction(
                    generation,
                    LiveTransactionClass::CredentialChange,
                    transaction,
                )
                .is_err()
        );
        coordinator.transaction_owners.insert(
            transaction,
            (generation, LiveTransactionClass::Authentication),
        );
        assert!(
            coordinator
                .release_finished_transaction(
                    generation,
                    LiveTransactionClass::CredentialChange,
                    transaction,
                )
                .is_err()
        );
        assert!(coordinator.transaction_owners.contains_key(&transaction));
        coordinator.transaction_owners.clear();

        coordinator.reload_policy(AccountRuntimePolicy {
            allow_guests: false,
            creation: AccountCreationPolicy::Closed,
            default_presence: PresencePolicy::Public,
            default_guest_direct_messages: GuestDirectMessagePolicy::Allow,
            default_direct_messages: DirectMessagePolicy::Contacts,
        });
        assert!(matches!(
            coordinator.config.creation_policy,
            AccountCreationPolicy::Closed
        ));
        assert_eq!(coordinator.config.default_presence, PresencePolicy::Public);
        assert_eq!(
            coordinator.config.default_guest_direct_messages,
            GuestDirectMessagePolicy::Allow
        );
        assert_eq!(
            coordinator.config.default_direct_messages,
            DirectMessagePolicy::Contacts
        );

        coordinator.cleanup_queue = (0..MAX_PENDING_TRANSACTION_CLEANUPS)
            .map(|_| TransactionCleanup::authentication(transaction))
            .collect();
        assert!(!coordinator.transaction_capacity_available());
        assert!(
            coordinator
                .queue_unowned_transaction_cleanup(TransactionCleanup::authentication(
                    TransactionId::from_bytes([2; 16]),
                ))
                .is_err()
        );
        coordinator.cleanup_queue.clear();
        assert!(coordinator.transaction_capacity_available());
        assert!(
            coordinator
                .queue_unowned_transaction_cleanup(TransactionCleanup::authentication(
                    TransactionId::from_bytes([2; 16]),
                ))
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn pending_session_authority_fences_only_exact_security_generations()
    -> Result<(), Box<dyn core::error::Error>> {
        let first = ConnectionGeneration::new(1);
        let second = ConnectionGeneration::new(2);
        assert!(pending_credential_finish_fences(&[first], first));
        assert!(!pending_credential_finish_fences(&[first], second));
        assert!(!pending_credential_finish_fences(&[], first));

        let current = Generation::new(4)?;
        let successor = current.checked_add(1)?;
        assert!(pending_guest_account_switch_fences(
            first, first, None, current, successor,
        ));
        assert!(!pending_guest_account_switch_fences(
            first, second, None, current, successor,
        ));
        assert!(!pending_guest_account_switch_fences(
            first,
            first,
            Some(account(1)),
            current,
            successor,
        ));
        assert!(!pending_guest_account_switch_fences(
            first, first, None, current, current,
        ));
        Ok(())
    }

    #[test]
    fn deletion_barrier_fences_origin_authentication_and_grant_generations() {
        let origin = ConnectionGeneration::new(1);
        let authentication = ConnectionGeneration::new(2);
        let grant = ConnectionGeneration::new(3);
        let barrier = AccountDeletionBarrier {
            account_id: account(1),
            tombstone_id: (100, account(1)),
            authentications: vec![(authentication, TransactionId::from_bytes([2; 16]))],
            grants: vec![(grant, TransactionId::from_bytes([3; 16]))],
            completions: vec![CarrierCompletion::closed(origin, 0)],
        };
        assert!(barrier.fences_generation(origin));
        assert!(barrier.fences_generation(authentication));
        assert!(barrier.fences_generation(grant));
        assert!(!barrier.fences_generation(ConnectionGeneration::new(4)));
    }

    #[test]
    fn pending_authority_fences_release_on_commit_and_rejection()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut fixture = CoordinatorFixture::new(vec![1; 96])?;
        let generation = ConnectionGeneration::new(1);
        {
            let (coordinator, context) = fixture.parts()?;
            coordinator.pending_authority = Some(PendingAuthority::Logout {
                generation,
                carrier_generation: 11,
            });
            assert!(coordinator.registered_authority_fenced(context, generation));
            let _completions = coordinator.batch_applied(context);
            assert!(!coordinator.registered_authority_fenced(context, generation));

            coordinator.pending_authority = Some(PendingAuthority::Logout {
                generation,
                carrier_generation: 12,
            });
            assert!(coordinator.registered_authority_fenced(context, generation));
            let _completions = coordinator.batch_rejected(context, Some(generation));
            assert!(!coordinator.registered_authority_fenced(context, generation));
        }
        Ok(())
    }

    #[test]
    fn deletion_fence_releases_on_commit_and_determinate_rejection()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut fixture = CoordinatorFixture::new(vec![1; 96])?;
        let generation = ConnectionGeneration::new(1);
        let account_id = account(1);
        let tombstone_id = (100, account_id);
        let pending = || AccountDeletionBarrier {
            account_id,
            tombstone_id,
            authentications: Vec::new(),
            grants: Vec::new(),
            completions: vec![CarrierCompletion::closed(generation, 0)],
        };
        {
            let (coordinator, context) = fixture.parts()?;
            coordinator
                .config
                .login_deletion_tombstones
                .insert(tombstone_id, StoredKey::new(vec![1])?);
            coordinator
                .pending_account_deletions
                .insert(generation, pending());
            assert!(coordinator.registered_authority_fenced(context, generation));
            assert!(coordinator.account_deletion_rejected(context, generation));
            assert!(!coordinator.registered_authority_fenced(context, generation));

            coordinator
                .pending_account_deletions
                .insert(generation, pending());
            assert!(coordinator.registered_authority_fenced(context, generation));
            let _completions = coordinator.batch_applied(context);
            assert!(!coordinator.registered_authority_fenced(context, generation));
        }
        Ok(())
    }

    #[test]
    fn carrier_rendering_covers_every_closed_control_and_numeric_arm()
    -> Result<(), Box<dyn core::error::Error>> {
        for kind in [AccountCarrierKind::Create, AccountCarrierKind::Credentials] {
            for phase in [AccountCarrierPhase::Start, AccountCarrierPhase::Finish] {
                assert!(
                    render_account_action(
                        "server.example",
                        kind,
                        AccountCarrierAction::Ready(phase)
                    )
                    .is_ok()
                );
                assert!(
                    render_account_action(
                        "server.example",
                        kind,
                        AccountCarrierAction::ResponseStart(phase),
                    )
                    .is_ok()
                );
                assert_eq!(
                    account_phase_name(phase),
                    if phase == AccountCarrierPhase::Start {
                        "START"
                    } else {
                        "FINISH"
                    }
                );
            }
            assert!(
                render_account_action("server.example", kind, AccountCarrierAction::End).is_ok()
            );
            assert!(account_failure("server.example", kind).is_ok());
            assert!(
                render_account_action(
                    "server.example",
                    kind,
                    AccountCarrierAction::RequestEnvelope {
                        phase: AccountCarrierPhase::Start,
                        bytes: SecretBytes::new(&[])?,
                    },
                )
                .is_err()
            );
        }

        assert!(render_sasl_action("server.example", "tester", SaslAction::SendPlus)?.is_some());
        for numeric in [
            SaslNumeric::Success,
            SaslNumeric::Failed,
            SaslNumeric::TooLong,
            SaslNumeric::Aborted,
            SaslNumeric::AlreadyAuthenticated,
            SaslNumeric::Mechanisms,
        ] {
            assert!(
                render_sasl_action("server.example", "tester", SaslAction::Numeric(numeric),)?
                    .is_some()
            );
        }
        assert!(render_sasl_action("server.example", "tester", SaslAction::Logout)?.is_none());
        assert!(
            render_sasl_action(
                "server.example",
                "tester",
                SaslAction::RequestEnvelope {
                    finish: false,
                    bytes: SecretBytes::new(&[])?,
                },
            )?
            .is_none()
        );
        assert!(
            render_sasl_actions("server.example", "tester", vec![SaslAction::Logout])?.is_empty()
        );
        Ok(())
    }

    #[test]
    fn carrier_completion_preserves_closed_final_result_classes() {
        assert_eq!(
            sasl_action_result(&SaslAction::Numeric(SaslNumeric::Success)),
            ResultClass::Ok
        );
        for numeric in [
            SaslNumeric::Failed,
            SaslNumeric::TooLong,
            SaslNumeric::Aborted,
            SaslNumeric::AlreadyAuthenticated,
            SaslNumeric::Mechanisms,
        ] {
            assert_eq!(
                sasl_action_result(&SaslAction::Numeric(numeric)),
                ResultClass::Rejected
            );
        }
        assert_eq!(
            request_terminal_result(RequestTerminal::Start),
            ResultClass::Ok
        );
        assert_eq!(
            request_terminal_result(RequestTerminal::Accepted),
            ResultClass::Ok
        );
        assert_eq!(
            request_terminal_result(RequestTerminal::Rejected),
            ResultClass::Rejected
        );

        let rejected =
            CarrierCompletion::finished(ConnectionGeneration::new(1), 7, ResultClass::Rejected);
        assert!(!rejected.close);
        assert_eq!(rejected.result, ResultClass::Rejected);
        let closed = CarrierCompletion::closed(ConnectionGeneration::new(1), 7);
        assert!(closed.close);
        assert_eq!(closed.result, ResultClass::Error);
    }

    #[test]
    fn crypto_apply_error_completes_the_exact_pending_carrier_as_error()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut fixture = CoordinatorFixture::new(vec![7; 48 * 16])?;
        let generation = ConnectionGeneration::new(11);
        let carrier_generation = 37;
        let job_id = CryptoJobId::new(23);
        let pending = PendingCrypto::Open(request_context(
            generation.get(),
            carrier_generation,
            RequestCarrier::Sasl,
            AccountCarrierPhase::Start,
        )?);
        assert!(fixture.coordinator.crypto.insert(job_id, pending).is_none());

        let completions = {
            let (coordinator, context) = fixture.parts()?;
            coordinator.crypto_completed(
                context,
                CryptoCompletionMessage {
                    job_id,
                    output: Ok(CryptoJobOutput::ChannelKey(ChannelKeyVerdict::for_test(
                        true,
                    ))),
                },
            )
        };
        let [completion] = completions.as_slice() else {
            return Err("crypto apply mismatch did not close exactly one carrier".into());
        };
        assert_eq!(completion.generation, generation);
        assert_eq!(completion.carrier_generation, carrier_generation);
        assert!(completion.close);
        assert_eq!(completion.result, ResultClass::Error);
        Ok(())
    }

    #[test]
    fn coordinator_connection_carriers_and_timer_boundaries_fail_closed()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut fixture = CoordinatorFixture::new(vec![7; 48 * 16])?;
        let unknown = ConnectionGeneration::new(99);
        {
            let (coordinator, context) = fixture.parts()?;
            assert!(matches!(
                coordinator.route_sasl(
                    context,
                    unknown,
                    1,
                    "tester",
                    parsed("AUTHENTICATE AGENC-OPAQUE")?
                ),
                CarrierRoute::Close
            ));
            assert!(matches!(
                coordinator.route_account(
                    context,
                    unknown,
                    1,
                    "tester",
                    AccountCarrierKind::Create,
                    parsed("ACCTCREATE START")?,
                ),
                CarrierRoute::Close
            ));
        }

        for generation in 1..=8 {
            let (coordinator, context) = fixture.parts()?;
            coordinator.connection_opened(context, ConnectionGeneration::new(generation))?;
        }
        {
            let (coordinator, context) = fixture.parts()?;
            assert!(
                coordinator
                    .connection_opened(context, ConnectionGeneration::new(1))
                    .is_err()
            );
            assert!(matches!(
                coordinator.route_sasl(
                    context,
                    ConnectionGeneration::new(1),
                    1,
                    "tester",
                    parsed("AUTHENTICATE one two")?,
                ),
                CarrierRoute::Close
            ));
            assert!(matches!(
                coordinator.route_sasl(
                    context,
                    ConnectionGeneration::new(2),
                    2,
                    "tester",
                    parsed("AUTHENTICATE SCRAM-SHA-256")?,
                ),
                CarrierRoute::Finished {
                    result: ResultClass::Rejected,
                    ..
                }
            ));
            assert!(matches!(
                coordinator.route_sasl(
                    context,
                    ConnectionGeneration::new(2),
                    2,
                    "tester",
                    parsed("AUTHENTICATE AGENC-OPAQUE")?,
                ),
                CarrierRoute::Finished {
                    result: ResultClass::Ok,
                    ..
                }
            ));
            assert!(matches!(
                coordinator.route_sasl(
                    context,
                    ConnectionGeneration::new(2),
                    2,
                    "tester",
                    parsed("AUTHENTICATE !")?,
                ),
                CarrierRoute::Close
            ));
            assert!(matches!(
                coordinator.route_account(
                    context,
                    ConnectionGeneration::new(3),
                    3,
                    "tester",
                    AccountCarrierKind::Create,
                    parsed("ACCTCREATE")?,
                ),
                CarrierRoute::Close
            ));
            assert!(matches!(
                coordinator.route_account(
                    context,
                    ConnectionGeneration::new(4),
                    4,
                    "tester",
                    AccountCarrierKind::Create,
                    parsed("ACCTCREATE START")?,
                ),
                CarrierRoute::Finished { .. }
            ));
            assert!(matches!(
                coordinator.route_account(
                    context,
                    ConnectionGeneration::new(5),
                    5,
                    "tester",
                    AccountCarrierKind::Create,
                    parsed("ACCTCREATE BOGUS")?,
                ),
                CarrierRoute::Finished {
                    result: ResultClass::Rejected,
                    ..
                }
            ));
            assert!(matches!(
                coordinator.route_account(
                    context,
                    ConnectionGeneration::new(6),
                    6,
                    "tester",
                    AccountCarrierKind::Credentials,
                    parsed("ACCTCRED START")?,
                ),
                CarrierRoute::Finished { .. }
            ));
            assert!(matches!(
                coordinator.route_account(
                    context,
                    ConnectionGeneration::new(7),
                    7,
                    "tester",
                    AccountCarrierKind::Create,
                    parsed("@label=x ACCTCREATE START")?,
                ),
                CarrierRoute::Finished { .. }
            ));
            assert!(matches!(
                coordinator.fail_route(context, unknown, "tester"),
                CarrierRoute::Close
            ));
            assert!(matches!(
                coordinator.route_sasl(
                    context,
                    ConnectionGeneration::new(8),
                    8,
                    "tester",
                    parsed("AUTHENTICATE AGENC-OPAQUE")?,
                ),
                CarrierRoute::Finished { .. }
            ));
            let mut request = "A".repeat(SASL_REQUEST_CHARACTERS - 2);
            request.push_str("==");
            let connection = coordinator
                .connections
                .get_mut(&ConnectionGeneration::new(8))
                .ok_or(RuntimeError::InvalidValue)?;
            for chunk in request.as_bytes().chunks(400) {
                let chunk = std::str::from_utf8(chunk)?;
                let _actions = connection.sasl.client(chunk, context.now().get())?;
            }
            assert!(matches!(
                coordinator.fail_route(context, ConnectionGeneration::new(8), "tester"),
                CarrierRoute::Finished { .. }
            ));
            assert!(matches!(
                coordinator.fail_account_route(context, unknown, AccountCarrierKind::Credentials,),
                CarrierRoute::Close
            ));
        }

        {
            let (coordinator, context) = fixture.parts()?;
            context.timers_mut().schedule(
                MonotonicTick::from_ticks(0),
                crate::state_core::timers::TimerKind::Ping,
                crate::state_core::timers::TimedId::Global,
            )?;
            let entry = context
                .timers_mut()
                .pop_due(MonotonicTick::from_ticks(0))
                .ok_or(RuntimeError::InvalidValue)?;
            assert!(!coordinator.timer_fired(context, entry).0);

            context.timers_mut().schedule(
                MonotonicTick::from_ticks(0),
                crate::state_core::timers::TimerKind::Reservation,
                crate::state_core::timers::TimedId::Transaction(TransactionId::from_bytes([9; 16])),
            )?;
            let entry = context
                .timers_mut()
                .pop_due(MonotonicTick::from_ticks(0))
                .ok_or(RuntimeError::InvalidValue)?;
            assert!(coordinator.timer_fired(context, entry).0);

            coordinator.scheduled_login_tombstone = Some((1, account(1)));
            context.timers_mut().schedule(
                MonotonicTick::from_ticks(0),
                crate::state_core::timers::TimerKind::Reservation,
                crate::state_core::timers::TimedId::Global,
            )?;
            let entry = context
                .timers_mut()
                .pop_due(MonotonicTick::from_ticks(0))
                .ok_or(RuntimeError::InvalidValue)?;
            assert!(coordinator.timer_fired(context, entry).0);

            coordinator.connection_closed(context, unknown);
            coordinator.connection_closed(context, ConnectionGeneration::new(1));
        }
        Ok(())
    }

    #[test]
    fn connection_open_refuses_partial_entropy_without_installing_state()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut fixture = CoordinatorFixture::new(vec![1; 16])?;
        let generation = ConnectionGeneration::new(1);
        let (coordinator, context) = fixture.parts()?;
        assert!(coordinator.connection_opened(context, generation).is_err());
        assert!(!coordinator.connections.contains_key(&generation));
        Ok(())
    }

    #[test]
    fn request_cursor_login_kinds_and_cleanup_reservations_cover_absent_paths()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut complete = RequestResultCursor::new(&[0, 1]);
        assert_eq!(complete.read_u16()?, 1);
        assert!(complete.finish().is_ok());
        let incomplete = RequestResultCursor::new(&[0, 1]);
        assert!(incomplete.finish().is_err());
        let mut short = RequestResultCursor::new(&[0]);
        assert!(short.read_u16().is_err());

        assert_eq!(
            replay_terminal_account(
                AccountServiceMessageKind::OpaqueAuthFinish,
                RequestTerminal::Rejected,
                None,
            )?,
            None
        );
        let network = NetworkId::from_bytes([7; 32]);
        let login = NormalizedLogin::prepare("bounded-user")?;
        let key = LoginIndexStoredKey::new(
            1,
            derive_login_index(&LoginIndexKey::from_bytes([8; 32]), network, &login)?,
        )?;
        let reservation = LoginIndexValue::new(
            &key,
            LoginIndexValueKind::CreationReservation {
                transaction_id: TransactionId::from_bytes([9; 16]),
                expires_at: 10,
            },
        )?;
        let tombstone = LoginIndexValue::new(
            &key,
            LoginIndexValueKind::DeletionTombstone {
                deleted_account_id: account(9),
                expires_at: 10,
            },
        )?;
        assert!(live_login(&reservation).is_none());
        assert!(live_login(&tombstone).is_none());
        assert!(credential_id(&reservation).is_err());
        assert!(credential_id(&live_value(network, 1, &login, 10)?).is_ok());
        assert!(select_live_login(&None, &None)?.is_none());
        assert!(select_live_login(&None, &Some(live_value(network, 1, &login, 11)?))?.is_some());

        let writes = TransactionCleanup::creation(
            TransactionId::from_bytes([12; 16]),
            Some(CreationReservation {
                login_key: key.encode()?,
                invitation_id: None,
            }),
        )
        .durable_writes()?;
        assert_eq!(writes.len(), 2);
        let credential = TransactionCleanup::credential(
            TransactionId::from_bytes([13; 16]),
            Some(account(13)),
            ConnectionGeneration::new(13),
        );
        assert_eq!(credential.durable_writes()?.len(), 1);
        Ok(())
    }

    #[test]
    fn account_carrier_control_frames_match_the_normative_text()
    -> Result<(), Box<dyn core::error::Error>> {
        let prefix = "server.example";
        let frames = [
            (
                render_account_action(
                    prefix,
                    AccountCarrierKind::Create,
                    AccountCarrierAction::Ready(AccountCarrierPhase::Start),
                )?,
                ":server.example ACCTCREATE READY START 4726\r\n",
            ),
            (
                render_account_action(
                    prefix,
                    AccountCarrierKind::Credentials,
                    AccountCarrierAction::ResponseStart(AccountCarrierPhase::Finish),
                )?,
                ":server.example ACCTCRED COMPLETE 4342\r\n",
            ),
            (
                render_account_action(
                    prefix,
                    AccountCarrierKind::Create,
                    AccountCarrierAction::End,
                )?,
                ":server.example ACCTCREATE END\r\n",
            ),
            (
                account_failure(prefix, AccountCarrierKind::Credentials)?,
                ":server.example FAIL ACCTCRED UNAVAILABLE :Credential change unavailable\r\n",
            ),
        ];
        for (frame, expected) in frames {
            assert_eq!(encoded(frame)?, expected.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn credential_change_terminal_note_matches_the_normative_text()
    -> Result<(), Box<dyn core::error::Error>> {
        assert_eq!(
            encoded(account_credential_changed_note("server.example")?)?,
            b":server.example NOTE ACCTCRED CHANGED :Account credential changed; reconnect required\r\n"
        );
        Ok(())
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
            let terminal_account = (terminal == RequestTerminal::Accepted).then(|| account(7));
            let record = RequestResultRecord {
                route,
                terminal,
                terminal_account,
                request: [5; agenc_ircd_auth::ACCOUNT_SERVICE_ENVELOPE_BYTES],
                response: [6; agenc_ircd_auth::ACCOUNT_SERVICE_RESPONSE_BYTES],
            };
            let encoded = record.encode();
            assert_eq!(encoded.len(), REQUEST_RESULT_BYTES);
            let decoded = RequestResultRecord::decode(&encoded)?;
            assert!(decoded.route == route);
            assert!(decoded.terminal == terminal);
            assert_eq!(decoded.terminal_account, terminal_account);
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
            .copy_from_slice(&REQUEST_RESULT_VERSION.to_be_bytes());
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
            .copy_from_slice(&REQUEST_RESULT_VERSION.saturating_add(1).to_be_bytes());
        assert!(RequestResultRecord::decode(&encoded).is_err());
        encoded
            .get_mut(..2)
            .ok_or(RuntimeError::InvalidValue)?
            .copy_from_slice(&REQUEST_RESULT_VERSION.to_be_bytes());
        *encoded
            .get_mut(terminal_offset)
            .ok_or(RuntimeError::InvalidValue)? = 0;
        assert!(RequestResultRecord::decode(&encoded).is_err());
        Ok(())
    }

    #[test]
    fn creation_replay_requires_and_renders_the_committed_account()
    -> Result<(), Box<dyn core::error::Error>> {
        let account_id = account(7);
        assert_eq!(
            replay_terminal_account(
                AccountServiceMessageKind::AccountCreateFinish,
                RequestTerminal::Accepted,
                Some(account_id),
            )?,
            Some(account_id)
        );
        assert_eq!(
            replay_terminal_account(
                AccountServiceMessageKind::AccountCreateFinish,
                RequestTerminal::Rejected,
                None,
            )?,
            None
        );
        assert!(
            replay_terminal_account(
                AccountServiceMessageKind::AccountCreateFinish,
                RequestTerminal::Accepted,
                None,
            )
            .is_err()
        );
        assert!(
            replay_terminal_account(
                AccountServiceMessageKind::OpaqueAuthFinish,
                RequestTerminal::Accepted,
                Some(account_id),
            )
            .is_err()
        );

        let expected = format!(
            ":server.example NOTE ACCTCREATE CREATED {} :Account created\r\n",
            account_id.to_text()
        );
        assert_eq!(
            encoded(account_created_note("server.example", account_id)?)?,
            expected.as_bytes()
        );
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
        let mut buckets =
            BucketTable::new(RateLimits::defaults(), Arc::new(MemoryBudget::new(1 << 20)));
        let now = MonotonicTick::from_ticks(0);
        for _ in 0..5 {
            assert!(buckets.charge_all_or_nothing(now, &[demand]).is_ok());
        }
        assert!(buckets.charge_all_or_nothing(now, &[demand]).is_err());
        Ok(())
    }

    #[test]
    fn opaque_attempts_stop_at_two_per_connection() -> Result<(), RuntimeError> {
        let mut attempts = 0;
        consume_opaque_connection_attempt(&mut attempts)?;
        consume_opaque_connection_attempt(&mut attempts)?;
        assert_eq!(attempts, MAX_OPAQUE_ATTEMPTS_PER_CONNECTION);
        assert_eq!(
            consume_opaque_connection_attempt(&mut attempts).err(),
            Some(RuntimeError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn creation_expiry_deletes_the_transaction_and_both_reservations() -> Result<(), RuntimeError> {
        let transaction_id = TransactionId::from_bytes([1; 16]);
        let login_key =
            LoginIndexStoredKey::new(1, LoginIndexDigest::from_storage_key([2; 32]))?.encode()?;
        let invite_id = InviteId::from_bytes([3; 16]);
        let cleanup = TransactionCleanup::creation(
            transaction_id,
            Some(CreationReservation {
                login_key: login_key.clone(),
                invitation_id: Some(invite_id),
            }),
        );

        let writes = cleanup.durable_writes()?;
        assert_eq!(writes.len(), 3);
        assert_delete(
            writes.first().ok_or(RuntimeError::InvalidValue)?,
            TableId::AuthTransaction,
            &StoredKey::new(transaction_id.as_bytes().to_vec())?,
        );
        assert_delete(
            writes.get(1).ok_or(RuntimeError::InvalidValue)?,
            TableId::LoginIndex,
            &login_key,
        );
        assert_delete(
            writes.get(2).ok_or(RuntimeError::InvalidValue)?,
            TableId::RegistrationInvite,
            &StoredKey::new(invite_id.as_bytes().to_vec())?,
        );
        Ok(())
    }

    #[test]
    fn authentication_expiry_deletes_only_its_server_owned_transaction() -> Result<(), RuntimeError>
    {
        let transaction_id = TransactionId::from_bytes([4; 16]);
        let writes = TransactionCleanup::authentication(transaction_id).durable_writes()?;
        assert_eq!(writes.len(), 1);
        assert_delete(
            writes.first().ok_or(RuntimeError::InvalidValue)?,
            TableId::AuthTransaction,
            &StoredKey::new(transaction_id.as_bytes().to_vec())?,
        );
        Ok(())
    }

    #[test]
    fn account_deletion_tombstones_login_and_deletes_private_authorities()
    -> Result<(), RuntimeError> {
        let account_id = account(9);
        let login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key([10; 32]))?.encode()?;
        let authentication = TransactionId::from_bytes([11; 16]);
        let grant = TransactionId::from_bytes([12; 16]);
        let authentications = [(ConnectionGeneration::new(7), authentication)];
        let grants = [(ConnectionGeneration::new(8), grant)];
        let writes = account_deletion_writes(
            account_id,
            UtcSecond::from_unix_seconds(2_592_100),
            &login_key,
            &authentications,
            &grants,
        )?;
        assert_eq!(writes.len(), 4);
        let AccountServiceDurableWrite::Put {
            table,
            key,
            plaintext,
        } = writes.first().ok_or(RuntimeError::InvalidValue)?
        else {
            return Err(RuntimeError::InvalidValue);
        };
        assert!(*table == TableId::LoginIndex && key == &login_key);
        let stored_key = LoginIndexStoredKey::decode(key.as_bytes())?;
        let tombstone = LoginIndexValue::decode(plaintext.as_slice(), &stored_key)?;
        assert!(matches!(
            tombstone.kind(),
            LoginIndexValueKind::DeletionTombstone {
                deleted_account_id,
                expires_at: 2_592_100,
            } if *deleted_account_id == account_id
        ));
        assert_delete(
            writes.get(1).ok_or(RuntimeError::InvalidValue)?,
            TableId::OpaqueRecord,
            &StoredKey::new(account_id.to_text().into_bytes())?,
        );
        assert_delete(
            writes.get(2).ok_or(RuntimeError::InvalidValue)?,
            TableId::AuthTransaction,
            &StoredKey::new(authentication.as_bytes().to_vec())?,
        );
        assert_delete(
            writes.get(3).ok_or(RuntimeError::InvalidValue)?,
            TableId::AuthTransaction,
            &StoredKey::new(grant.as_bytes().to_vec())?,
        );
        let completions =
            account_deletion_completions(ConnectionGeneration::new(6), &authentications, &grants)?;
        assert_eq!(completions.len(), 3);
        assert!(completions.iter().all(|completion| completion.close));
        assert!(
            completions
                .iter()
                .any(|completion| completion.generation == ConnectionGeneration::new(6))
        );
        assert!(completions.capacity().saturating_sub(completions.len()) >= 2);
        Ok(())
    }

    #[test]
    fn login_tombstone_expiry_decrements_previous_generation_exactly_once()
    -> Result<(), RuntimeError> {
        let network = NetworkId::from_bytes([13; 32]);
        let previous_key = LoginIndexKey::from_bytes([14; 32]);
        let current_key = LoginIndexKey::from_bytes([15; 32]);
        let key_state = LoginIndexKeyState::transition(
            2,
            previous_key.key_id(network),
            current_key.key_id(network),
            1,
        )?;
        let previous_login_key =
            LoginIndexStoredKey::new(2, LoginIndexDigest::from_storage_key([16; 32]))?.encode()?;
        let current_login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key([17; 32]))?.encode()?;
        let future_login_key =
            LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key([18; 32]))?.encode()?;
        let mut tombstones = BTreeMap::new();
        tombstones.insert((99, account(16)), previous_login_key.clone());
        tombstones.insert((100, account(17)), current_login_key.clone());
        tombstones.insert((101, account(18)), future_login_key);

        let Some(batch) = login_tombstone_expiry_batch(
            &tombstones,
            key_state,
            UtcSecond::from_unix_seconds(100),
        )?
        else {
            return Err(RuntimeError::InvalidValue);
        };
        assert_eq!(batch.pending.tombstones.len(), 2);
        assert_eq!(batch.successor, Some((101, account(18))));
        assert_eq!(batch.writes.len(), 3);
        assert_delete(
            batch.writes.first().ok_or(RuntimeError::InvalidValue)?,
            TableId::LoginIndex,
            &previous_login_key,
        );
        assert_delete(
            batch.writes.get(1).ok_or(RuntimeError::InvalidValue)?,
            TableId::LoginIndex,
            &current_login_key,
        );
        let AccountServiceDurableWrite::Put {
            table,
            key,
            plaintext,
        } = batch.writes.get(2).ok_or(RuntimeError::InvalidValue)?
        else {
            return Err(RuntimeError::InvalidValue);
        };
        assert_eq!(*table, TableId::LoginIndexKeyState);
        assert_eq!(
            key.as_bytes(),
            agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY
        );
        let resulting = LoginIndexKeyState::decode(plaintext.as_slice())?;
        assert_eq!(resulting.previous(), Some((2, 0)));
        assert_eq!(batch.pending.resulting_key_state, Some(resulting));
        Ok(())
    }

    #[test]
    fn login_tombstone_expiry_batch_stops_at_the_bounded_chunk() -> Result<(), RuntimeError> {
        let network = NetworkId::from_bytes([19; 32]);
        let current_key = LoginIndexKey::from_bytes([20; 32]);
        let key_state = LoginIndexKeyState::stable(3, current_key.key_id(network))?;
        let mut tombstones = BTreeMap::new();
        for index in 0..=super::MAX_LOGIN_TOMBSTONE_EXPIRIES_PER_BATCH {
            let suffix = u64::try_from(index).map_err(|_| RuntimeError::Overflow)?;
            let mut account_bytes = [0_u8; 16];
            account_bytes
                .get_mut(8..)
                .ok_or(RuntimeError::InvalidValue)?
                .copy_from_slice(&suffix.to_be_bytes());
            let mut digest = [0_u8; 32];
            digest
                .get_mut(24..)
                .ok_or(RuntimeError::InvalidValue)?
                .copy_from_slice(&suffix.to_be_bytes());
            tombstones.insert(
                (
                    100,
                    AccountId::from_random(AccountRandomId::from_bytes(account_bytes)),
                ),
                LoginIndexStoredKey::new(3, LoginIndexDigest::from_storage_key(digest))?
                    .encode()?,
            );
        }
        let Some(batch) = login_tombstone_expiry_batch(
            &tombstones,
            key_state,
            UtcSecond::from_unix_seconds(100),
        )?
        else {
            return Err(RuntimeError::InvalidValue);
        };
        assert_eq!(
            batch.pending.tombstones.len(),
            super::MAX_LOGIN_TOMBSTONE_EXPIRIES_PER_BATCH
        );
        assert_eq!(
            batch.writes.len(),
            super::MAX_LOGIN_TOMBSTONE_EXPIRIES_PER_BATCH
        );
        assert!(batch.successor.is_some());
        assert!(batch.pending.resulting_key_state.is_none());
        Ok(())
    }

    #[test]
    fn restart_cleanup_batches_stop_at_the_bounded_storage_chunk() -> Result<(), RuntimeError> {
        let mut cleanups = VecDeque::new();
        cleanups
            .try_reserve_exact(super::MAX_TRANSACTION_CLEANUPS_PER_BATCH + 1)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for byte in 0..=super::MAX_TRANSACTION_CLEANUPS_PER_BATCH {
            let suffix = u64::try_from(byte).map_err(|_| RuntimeError::Overflow)?;
            let mut identifier = [0_u8; 16];
            identifier
                .get_mut(8..)
                .ok_or(RuntimeError::InvalidValue)?
                .copy_from_slice(&suffix.to_be_bytes());
            cleanups.push_back(TransactionCleanup::authentication(
                TransactionId::from_bytes(identifier),
            ));
        }

        let (cleanup_count, writes) = transaction_cleanup_batch(&cleanups)?;
        assert_eq!(cleanup_count, super::MAX_TRANSACTION_CLEANUPS_PER_BATCH);
        assert_eq!(writes.len(), super::MAX_TRANSACTION_CLEANUPS_PER_BATCH);
        assert_eq!(
            cleanups.len(),
            super::MAX_TRANSACTION_CLEANUPS_PER_BATCH + 1
        );
        Ok(())
    }

    fn assert_delete(
        write: &AccountServiceDurableWrite,
        expected_table: TableId,
        expected_key: &StoredKey,
    ) {
        assert!(matches!(
            write,
            AccountServiceDurableWrite::Delete { table, key }
                if *table == expected_table && key == expected_key
        ));
    }

    #[test]
    fn batch_rejection_and_expiry_timers_release_authority_without_live_transactions()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut fixture = CoordinatorFixture::new(vec![3; 192])?;
        let (coordinator, context) = fixture.parts()?;
        let generation = ConnectionGeneration::new(1);
        let transaction = TransactionId::from_bytes([5; 16]);
        coordinator.connection_opened(context, generation)?;

        // A rejected tombstone batch reschedules the sweep and reports nothing.
        coordinator.pending_login_tombstone_expiry = Some(PendingLoginTombstoneExpiry {
            tombstones: Vec::new(),
            resulting_key_state: None,
        });
        assert!(coordinator.batch_rejected(context, None).is_empty());
        assert!(coordinator.pending_login_tombstone_expiry.is_none());

        // Rejected cleanups return to the front of the queue in their original order.
        coordinator
            .pending_cleanups
            .push(TransactionCleanup::authentication(transaction));
        coordinator
            .pending_cleanups
            .push(TransactionCleanup::authentication(
                TransactionId::from_bytes([6; 16]),
            ));
        assert!(coordinator.batch_rejected(context, None).is_empty());
        assert!(coordinator.pending_cleanups.is_empty());
        assert_eq!(coordinator.cleanup_queue.len(), 2);
        coordinator.cleanup_queue.clear();

        // Without pending authority a rejection only reports progress.
        assert!(
            coordinator
                .batch_rejected(context, Some(generation))
                .is_empty()
        );

        // A rejected logout closes exactly its originating carrier.
        coordinator.pending_authority = Some(PendingAuthority::Logout {
            generation,
            carrier_generation: 7,
        });
        let completions = coordinator.batch_rejected(context, Some(generation));
        assert!(coordinator.pending_authority.is_none());
        assert_eq!(completions.len(), 1);

        // A non-reservation timer for a transaction is not the coordinator's, and a
        // reservation timer for an owned transaction without live state is consumed.
        context.timers_mut().schedule(
            MonotonicTick::from_ticks(0),
            crate::state_core::timers::TimerKind::Ping,
            crate::state_core::timers::TimedId::Transaction(transaction),
        )?;
        let entry = context
            .timers_mut()
            .pop_due(MonotonicTick::from_ticks(0))
            .ok_or(RuntimeError::InvalidValue)?;
        let (consumed, completions) = coordinator.timer_fired(context, entry);
        assert!(!consumed && completions.is_empty());
        coordinator.transaction_owners.insert(
            transaction,
            (generation, LiveTransactionClass::Authentication),
        );
        context.timers_mut().schedule(
            MonotonicTick::from_ticks(0),
            crate::state_core::timers::TimerKind::Reservation,
            crate::state_core::timers::TimedId::Transaction(transaction),
        )?;
        let entry = context
            .timers_mut()
            .pop_due(MonotonicTick::from_ticks(0))
            .ok_or(RuntimeError::InvalidValue)?;
        let (consumed, completions) = coordinator.timer_fired(context, entry);
        assert!(consumed && completions.is_empty());
        coordinator.transaction_owners.clear();

        // A logout before registration without an authenticated binding closes the
        // carrier, and so does a logout from an unknown connection.
        assert!(matches!(
            coordinator.route_logout(context, generation, 1, "tester"),
            CarrierRoute::Close
        ));
        assert!(matches!(
            coordinator.route_logout(context, ConnectionGeneration::new(9), 1, "tester"),
            CarrierRoute::Close
        ));
        Ok(())
    }
}
