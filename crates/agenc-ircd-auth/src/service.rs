//! Complete coordinator-side account protocol state machines.

use agenc_ircd_crypto::{
    AccountHpkeKeyId, AccountRequestBinding, Ed25519PublicKey, LoginIndexDigest, LoginIndexKey,
    OpaqueFakeCredentialKey, OsEntropy, derive_fake_credential_id, derive_login_index,
};
use agenc_ircd_types::{
    AccountDeletionToken, AccountId, AccountRandomId, AccountServiceCompletionStatus,
    AccountServiceMessageKind, AuthGrantId, ConnectionId, EntropySource, Generation, InviteId,
    MonotonicTick, NetworkId, OpaqueCredentialId, OriginId, RecoveryEpoch, RequestId, Revision,
    ServerId, ServerIncarnation, TransactionId, UtcSecond,
};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::AuthError;
use crate::opaque::{
    OPAQUE_SERVER_LOGIN_STATE_BYTES, OpaqueAuthentication, OpaqueProfile, OpaqueRegistrationRecord,
    OpaqueServerLoginState, finish_authentication,
};
use crate::transaction::{
    AUTHENTICATION_GRANT_TIMEOUT_SECONDS, AUTHENTICATION_GRANT_TIMEOUT_TICKS, AccountRouteBinding,
    AccountTransaction, AccountTransactionBinding, FRESH_AUTH_TIMEOUT_TICKS, TransactionClass,
};
use crate::wire::{
    AccountRequestLineage, AccountServiceResponse, AccountServiceResponsePayload,
    AuthenticatedAccountRequest, AuthenticationFinish, AuthenticationStart, Completion,
    CreationFinish, CreationStart, CredentialChangeFinish, CredentialChangeStart,
    encode_response_plaintext,
};

/// Complete coordinator-validated route identity and clock readings for one
/// account operation.
#[derive(Clone, Copy)]
pub struct AccountOperationContext {
    network_id: NetworkId,
    route: AccountRouteBinding,
    now: MonotonicTick,
    now_utc: UtcSecond,
}

impl AccountOperationContext {
    /// Constructs the complete connection-bound coordinator context.
    #[must_use]
    pub const fn new(
        network_id: NetworkId,
        route: AccountRouteBinding,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Self {
        Self {
            network_id,
            route,
            now,
            now_utc,
        }
    }

    fn binding(
        self,
        transaction_id: TransactionId,
        class: TransactionClass,
    ) -> Result<AccountTransactionBinding, AuthError> {
        AccountTransactionBinding::new(transaction_id, class, self.network_id, self.route, self.now)
    }
}

/// One authenticated response payload inseparably bound to its request's
/// one-use HPKE exporter authority.
#[must_use = "an opened account request must retain or seal its response plan"]
pub struct AccountResponsePlan {
    lineage: AccountRequestLineage,
    transaction_id: TransactionId,
    payload: AccountServiceResponsePayload,
}

impl AccountResponsePlan {
    fn new(
        lineage: AccountRequestLineage,
        transaction_id: TransactionId,
        payload: AccountServiceResponsePayload,
    ) -> Result<Self, AuthError> {
        let binding = lineage.binding();
        if payload.transaction_id() != transaction_id
            || !payload.matches_request_kind(binding.message_kind())
        {
            return Err(AuthError::ContextMismatch);
        }
        Ok(Self {
            lineage,
            transaction_id,
            payload,
        })
    }

    /// Returns the authenticated request fields that this response must repeat.
    #[must_use]
    pub const fn request_binding(&self) -> AccountRequestBinding {
        self.lineage.binding()
    }

    /// Returns the transaction repeated inside the encrypted response payload.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Borrows the exact bound payload for protocol inspection before sealing.
    #[must_use]
    pub const fn payload(&self) -> &AccountServiceResponsePayload {
        &self.payload
    }
}

/// A terminal semantic FINISH outcome with the exact committed or rejected
/// response plan that must accompany it.
#[must_use = "a semantic finish outcome must be checked and sealed exactly once"]
pub struct AccountFinishOutcome<T> {
    result: Result<T, AuthError>,
    response: AccountResponsePlan,
}

impl<T> AccountFinishOutcome<T> {
    fn committed(value: T, response: AccountResponsePlan) -> Self {
        Self {
            result: Ok(value),
            response,
        }
    }

    fn rejected(reason: AuthError, response: AccountResponsePlan) -> Self {
        Self {
            result: Err(reason),
            response,
        }
    }

    /// Borrows the committed value or returns the internal rejection class.
    pub const fn result(&self) -> Result<&T, AuthError> {
        match &self.result {
            Ok(value) => Ok(value),
            Err(error) => Err(*error),
        }
    }

    /// Borrows the response that must be sealed and committed for this outcome.
    pub const fn response_plan(&self) -> &AccountResponsePlan {
        &self.response
    }

    fn seal_checked(
        self,
        current_response_count: u64,
        matches_committed: impl FnOnce(&T, Completion) -> bool,
        expected_payload: fn(&AccountServiceResponsePayload) -> Option<Completion>,
    ) -> Result<SealedAccountFinishOutcome<T>, AuthError> {
        let completion =
            expected_payload(self.response.payload()).ok_or(AuthError::ContextMismatch)?;
        let matches_result = match &self.result {
            Ok(value) => {
                completion.status() == AccountServiceCompletionStatus::Committed
                    && matches_committed(value, completion)
            }
            Err(_) => completion.status() == AccountServiceCompletionStatus::Rejected,
        };
        if !matches_result {
            return Err(AuthError::ContextMismatch);
        }
        let response = seal_account_response(self.response, current_response_count)?;
        Ok(SealedAccountFinishOutcome {
            result: self.result,
            response,
        })
    }
}

/// A finish result whose exact committed/rejected receipt has been checked
/// against the semantic result and sealed for one durable commit.
///
/// ```compile_fail
/// use agenc_ircd_auth::SealedAccountFinishOutcome;
/// fn separate<T>(outcome: SealedAccountFinishOutcome<T>) {
///     let _ = outcome.into_parts();
/// }
/// ```
#[must_use = "the sealed result and receipt must remain together for durable commit"]
pub struct SealedAccountFinishOutcome<T> {
    result: Result<T, AuthError>,
    response: AccountResponseIntent,
}

impl<T> SealedAccountFinishOutcome<T> {
    /// Borrows the committed value or returns the internal rejection class.
    pub const fn result(&self) -> Result<&T, AuthError> {
        match &self.result {
            Ok(value) => Ok(value),
            Err(error) => Err(*error),
        }
    }

    /// Borrows the checked encrypted response for the same terminal result.
    pub const fn response_intent(&self) -> &AccountResponseIntent {
        &self.response
    }

    /// Consumes the terminal result only after storage has committed the
    /// response-count successor reserved for this response.
    ///
    /// The outer result reports a mismatched durable head. The inner result
    /// is the authenticated operation's committed or rejected outcome.
    pub fn into_result_after_commit(
        self,
        committed_response_count: u64,
    ) -> Result<Result<T, AuthError>, AuthError> {
        if committed_response_count < self.response.next_response_count() {
            return Err(AuthError::ContextMismatch);
        }
        Ok(self.result)
    }
}

/// A parsed START transaction inseparably paired with its authenticated challenge.
#[must_use = "an opened start must seal its challenge before processing FINISH"]
pub struct AccountStartOutcome<S> {
    transaction: AccountTransaction<S>,
    response: AccountResponsePlan,
}

impl<S> AccountStartOutcome<S> {
    fn new(
        transaction: AccountTransaction<S>,
        response: AccountResponsePlan,
    ) -> Result<Self, AuthError> {
        if transaction.binding().transaction_id() != response.transaction_id() {
            return Err(AuthError::ContextMismatch);
        }
        Ok(Self {
            transaction,
            response,
        })
    }

    /// Returns the generated transaction identity repeated by the challenge.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction.binding().transaction_id()
    }

    /// Borrows the challenge before its one-use response authority is sealed.
    pub const fn response_plan(&self) -> &AccountResponsePlan {
        &self.response
    }

    /// Checks the transaction-to-challenge binding and consumes the one-use
    /// response authority, retaining the transaction beside the sealed bytes.
    pub fn seal(self, current_response_count: u64) -> Result<SealedAccountStart<S>, AuthError> {
        if self.transaction.binding().transaction_id() != self.response.transaction_id() {
            return Err(AuthError::ContextMismatch);
        }
        let response = seal_account_response(self.response, current_response_count)?;
        Ok(SealedAccountStart {
            transaction: self.transaction,
            response,
        })
    }
}

/// A START transaction retained with the exact encrypted challenge sent for it.
///
/// ```compile_fail
/// use agenc_ircd_auth::SealedAccountStart;
/// fn bypass_commit<S>(mut start: SealedAccountStart<S>) {
///     let _ = start.transaction_mut();
/// }
/// ```
#[must_use = "the transaction and encrypted challenge must remain in one lineage"]
pub struct SealedAccountStart<S> {
    transaction: AccountTransaction<S>,
    response: AccountResponseIntent,
}

impl<S> SealedAccountStart<S> {
    /// Returns the retained transaction identity used as its durable row key.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction.binding().transaction_id()
    }

    /// Borrows the encrypted START response retained for exact replay.
    pub const fn response_intent(&self) -> &AccountResponseIntent {
        &self.response
    }

    /// Consumes the retained START lineage only after storage has committed
    /// the response-count successor reserved for its challenge.
    pub fn into_transaction_after_commit(
        self,
        committed_response_count: u64,
    ) -> Result<AccountTransaction<S>, AuthError> {
        if committed_response_count < self.response.next_response_count() {
            return Err(AuthError::ContextMismatch);
        }
        Ok(self.transaction)
    }
}

impl SealedAccountStart<AccountAuthenticationState> {
    /// Captures the retained authentication transaction for encrypted durable
    /// storage without releasing its post-commit continuation authority.
    pub fn authentication_transaction_record(
        &self,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<AuthenticationTransactionRecord, AuthError> {
        AuthenticationTransactionRecord::capture(&self.transaction, now, now_utc)
    }
}

impl SealedAccountStart<AccountCreationState> {
    /// Captures one creation transaction for encrypted durable storage without
    /// releasing its post-commit continuation authority.
    pub fn creation_transaction_record(
        &self,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<CreationTransactionRecord, AuthError> {
        CreationTransactionRecord::capture(&self.transaction, now, now_utc)
    }

    /// Borrows the keyed login digest only when START admitted a reservation.
    #[must_use]
    pub fn creation_reservation_login_digest(&self) -> Option<&LoginIndexDigest> {
        self.transaction.state_ref().and_then(|state| {
            state
                .disposition
                .rejection()
                .is_none()
                .then_some(&state.login_digest)
        })
    }

    /// Returns verified invitation metadata only when START admitted its
    /// corresponding reservation.
    #[must_use]
    pub fn creation_reservation_invitation(&self) -> Option<(InviteId, UtcSecond)> {
        self.transaction.state_ref().and_then(|state| {
            state
                .disposition
                .rejection()
                .is_none()
                .then_some(state.invitation.as_ref())
                .flatten()
                .map(|invitation| (invitation.invite_id, invitation.expires_at))
        })
    }
}

impl SealedAccountStart<CredentialChangeState> {
    /// Captures one credential-change transaction for encrypted durable storage
    /// without releasing its post-commit continuation authority.
    pub fn credential_change_transaction_record(
        &self,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<CredentialChangeTransactionRecord, AuthError> {
        CredentialChangeTransactionRecord::capture(&self.transaction, now, now_utc)
    }
}

/// The invitation policy already selected for one account-creation request.
pub enum CreationAdmission {
    /// Deployment policy permits creation only when the request carries no invitation.
    Open,
    /// The invitation inside the authenticated request must verify under this authority.
    Invitation {
        /// Offline creation authority configured by the coordinator.
        authority: Ed25519PublicKey,
        /// Current UTC second used only for invitation validity.
        now: UtcSecond,
    },
    /// Deployment policy refuses every account-creation request.
    Closed,
}

#[derive(Clone, Copy)]
enum StartDisposition {
    SuccessCandidate,
    RejectAtFinish(AuthError),
}

impl StartDisposition {
    const fn reject(self, reason: AuthError) -> Self {
        match self {
            Self::SuccessCandidate => Self::RejectAtFinish(reason),
            Self::RejectAtFinish(_) => self,
        }
    }

    const fn rejection(self) -> Option<AuthError> {
        match self {
            Self::SuccessCandidate => None,
            Self::RejectAtFinish(reason) => Some(reason),
        }
    }
}

/// Inputs retained between an account-creation challenge and finish.
///
/// This state is not a storage reservation or account-creation authority.
pub struct AccountCreationState {
    start_request_binding: AccountRequestBinding,
    disposition: StartDisposition,
    login_digest: LoginIndexDigest,
    credential_id: OpaqueCredentialId,
    invitation: Option<ValidatedInvitation>,
}

struct ValidatedInvitation {
    invite_id: InviteId,
    expires_at: UtcSecond,
}

/// Complete coordinator inputs for one account-creation START.
pub struct AccountCreationStartParameters {
    /// Complete route identity and clock binding.
    pub context: AccountOperationContext,
    /// Fully opened creation request with its authenticated response authority.
    pub request: AuthenticatedAccountRequest<CreationStart>,
    /// Deployment invitation decision and proof.
    pub admission: CreationAdmission,
    /// Storage result proving no live, reserved, or tombstoned login conflict.
    pub login_is_available: bool,
    /// Storage result proving the supplied Invite ID was never reserved, redeemed,
    /// or tombstoned. Ignored when the request carries no invitation.
    pub invitation_is_available: bool,
}

/// Result of a successful account-creation finish, ready for one storage transaction.
pub struct CreateAccountIntent {
    account_id: AccountId,
    login_digest: LoginIndexDigest,
    credential_id: OpaqueCredentialId,
    record: OpaqueRegistrationRecord,
    invitation: Option<ValidatedInvitation>,
}

impl CreateAccountIntent {
    /// Returns the new immutable account authority.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Returns the keyed canonical-login index value.
    #[must_use]
    pub const fn login_digest(&self) -> &LoginIndexDigest {
        &self.login_digest
    }

    /// Borrows the private credential ID only for the atomic account record write.
    #[must_use]
    pub const fn credential_id(&self) -> &OpaqueCredentialId {
        &self.credential_id
    }

    /// Borrows the validated password file only for encrypted persistence.
    #[must_use]
    pub const fn record(&self) -> &OpaqueRegistrationRecord {
        &self.record
    }

    /// Returns the invitation reservation consumed by the same commit.
    #[must_use]
    pub const fn invitation_id(&self) -> Option<InviteId> {
        match self.invitation.as_ref() {
            Some(invitation) => Some(invitation.invite_id),
            None => None,
        }
    }

    /// Returns the exclusive invitation expiry used to retain its redemption tombstone.
    #[must_use]
    pub const fn invitation_expires_at(&self) -> Option<UtcSecond> {
        match self.invitation.as_ref() {
            Some(invitation) => Some(invitation.expires_at),
            None => None,
        }
    }
}

/// Starts a one-use account-creation registration transaction.
pub fn begin_account_creation(
    profile: &OpaqueProfile,
    login_index_key: &LoginIndexKey,
    parameters: AccountCreationStartParameters,
) -> Result<AccountStartOutcome<AccountCreationState>, AuthError> {
    let mut entropy = OsEntropy;
    begin_account_creation_with_entropy(profile, login_index_key, parameters, &mut entropy)
}

fn begin_account_creation_with_entropy(
    profile: &OpaqueProfile,
    login_index_key: &LoginIndexKey,
    parameters: AccountCreationStartParameters,
    entropy: &mut impl EntropySource,
) -> Result<AccountStartOutcome<AccountCreationState>, AuthError> {
    let AccountCreationStartParameters {
        context,
        request,
        admission,
        login_is_available,
        invitation_is_available,
    } = parameters;
    let (request, response_lineage) = request.into_parts();
    let start_request_binding = response_lineage.binding();
    if request.network_id != context.network_id {
        return Err(AuthError::ContextMismatch);
    }
    let (invitation, disposition) =
        evaluate_creation_admission(admission, request.invitation.as_ref(), context.network_id);
    let disposition = if request.invitation.is_some() && !invitation_is_available {
        disposition.reject(AuthError::InvitationRejected)
    } else {
        disposition
    };
    let disposition = if login_is_available {
        disposition
    } else {
        disposition.reject(AuthError::WrongState)
    };
    let login_digest = derive_login_index(login_index_key, context.network_id, &request.login)?;
    let transaction_id = fresh_transaction_id(entropy)?;
    let credential_id = fresh_opaque_credential_id(entropy)?;
    let response = profile.registration_start(&credential_id, &request.registration_request)?;
    let challenge_credential = duplicate_credential_id(&credential_id);
    let binding = context.binding(transaction_id, TransactionClass::AccountCreation)?;
    let state = AccountCreationState {
        start_request_binding,
        disposition,
        login_digest,
        credential_id,
        invitation,
    };
    let response = AccountResponsePlan::new(
        response_lineage,
        transaction_id,
        AccountServiceResponsePayload::CreationChallenge {
            transaction_id,
            credential_id: challenge_credential,
            response,
        },
    )?;
    AccountStartOutcome::new(AccountTransaction::new(binding, state), response)
}

fn evaluate_creation_admission(
    admission: CreationAdmission,
    invitation: Option<&crate::AccountCreationInvite>,
    network_id: NetworkId,
) -> (Option<ValidatedInvitation>, StartDisposition) {
    match (admission, invitation) {
        (CreationAdmission::Open, None) => (None, StartDisposition::SuccessCandidate),
        (CreationAdmission::Invitation { authority, now }, Some(invitation)) => {
            evaluate_creation_invitation(invitation, authority, network_id, now)
        }
        (CreationAdmission::Open, Some(_))
        | (CreationAdmission::Invitation { .. }, None)
        | (CreationAdmission::Closed, _) => (
            None,
            StartDisposition::RejectAtFinish(AuthError::InvitationRejected),
        ),
    }
}

fn evaluate_creation_invitation(
    invitation: &crate::AccountCreationInvite,
    authority: Ed25519PublicKey,
    network_id: NetworkId,
    now: UtcSecond,
) -> (Option<ValidatedInvitation>, StartDisposition) {
    if let Err(error) = invitation.verify(authority, network_id, now) {
        return (None, StartDisposition::RejectAtFinish(error));
    }
    (
        Some(ValidatedInvitation {
            invite_id: invitation.invite_id(),
            expires_at: invitation.expires_at(),
        }),
        StartDisposition::SuccessCandidate,
    )
}

/// Consumes account-creation state on every finish outcome.
pub fn finish_account_creation(
    transaction: &mut AccountTransaction<AccountCreationState>,
    context: AccountOperationContext,
    finish: AuthenticatedAccountRequest<CreationFinish>,
) -> Result<AccountFinishOutcome<CreateAccountIntent>, AuthError> {
    let mut entropy = OsEntropy;
    finish_account_creation_with_entropy(transaction, context, finish, &mut entropy)
}

fn finish_account_creation_with_entropy(
    transaction: &mut AccountTransaction<AccountCreationState>,
    context: AccountOperationContext,
    finish: AuthenticatedAccountRequest<CreationFinish>,
    entropy: &mut impl EntropySource,
) -> Result<AccountFinishOutcome<CreateAccountIntent>, AuthError> {
    let (finish, response_lineage) = finish.into_parts();
    let finish_request_binding = response_lineage.binding();
    let claimed_transaction = finish.transaction_id;
    let expected_transaction = transaction.binding().transaction_id();
    let state = match transaction.consume(
        TransactionClass::AccountCreation,
        context.network_id,
        context.route,
        context.now,
    ) {
        Ok(state) => state,
        Err(error) => {
            let response = rejected_creation_response(response_lineage, claimed_transaction)?;
            return Ok(AccountFinishOutcome::rejected(error, response));
        }
    };
    if finish.network_id != context.network_id
        || finish.transaction_id != expected_transaction
        || validate_finish_lineage(state.start_request_binding, finish_request_binding).is_err()
    {
        let response = rejected_creation_response(response_lineage, claimed_transaction)?;
        return Ok(AccountFinishOutcome::rejected(
            AuthError::ContextMismatch,
            response,
        ));
    }
    if let Some(error) = state.disposition.rejection() {
        let response = rejected_creation_response(response_lineage, expected_transaction)?;
        return Ok(AccountFinishOutcome::rejected(error, response));
    }
    let account_id = fresh_account_id(entropy)?;
    let intent = CreateAccountIntent {
        account_id,
        login_digest: state.login_digest,
        credential_id: state.credential_id,
        record: finish.registration_record,
        invitation: state.invitation,
    };
    let response = AccountResponsePlan::new(
        response_lineage,
        expected_transaction,
        AccountServiceResponsePayload::CreationCompletion(Completion::committed(
            expected_transaction,
            account_id,
            0,
        )),
    )?;
    Ok(AccountFinishOutcome::committed(intent, response))
}

/// Current account and credential state selected by the private login index.
pub struct AccountCredentialRecord {
    account_id: AccountId,
    account_revision: Revision,
    account_session_generation: Generation,
    login_digest: LoginIndexDigest,
    credential_id: OpaqueCredentialId,
    record: OpaqueRegistrationRecord,
}

impl AccountCredentialRecord {
    /// Takes ownership of one internally consistent storage lookup result.
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        account_revision: Revision,
        account_session_generation: Generation,
        login_digest: LoginIndexDigest,
        credential_id: OpaqueCredentialId,
        record: OpaqueRegistrationRecord,
    ) -> Self {
        Self {
            account_id,
            account_revision,
            account_session_generation,
            login_digest,
            credential_id,
            record,
        }
    }
}

/// Private login-index outcome; both arms perform the same OPAQUE start shape.
pub enum AuthenticationLookup {
    /// One exact live account record matched the keyed login index.
    Known(Box<AccountCredentialRecord>),
    /// No live record matched, so the fixed fake record must be used.
    Unknown,
}

#[derive(Clone, Copy)]
enum AuthenticationCandidate {
    Known(AccountSnapshot),
    RejectAtFinish,
}

/// Complete coordinator inputs for one OPAQUE authentication START.
pub struct AuthenticationStartParameters {
    /// Complete route identity and clock binding.
    pub context: AccountOperationContext,
    /// Fully opened OPAQUE start request with its authenticated response authority.
    pub request: AuthenticatedAccountRequest<AuthenticationStart>,
    /// Private login-index result selected after generation checks.
    pub lookup: AuthenticationLookup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AccountSnapshot {
    account_id: AccountId,
    account_revision: Revision,
    account_session_generation: Generation,
}

/// Encrypted OPAQUE server state retained for one authentication finish.
///
/// A rejected candidate retains only fake-path state and cannot authorize a grant.
pub struct AccountAuthenticationState {
    start_request_binding: AccountRequestBinding,
    candidate: AuthenticationCandidate,
    credential_id: OpaqueCredentialId,
    server_state: OpaqueServerLoginState,
}

/// Exact version-one bytes of one live OPAQUE authentication transaction.
pub const AUTHENTICATION_TRANSACTION_RECORD_BYTES: usize = 2
    + 2
    + 16
    + 32
    + (16 + 16 + 16 + 8 + 16 + 32)
    + 8
    + (32 + 16 + 32 + 16 + 2)
    + (1 + 24 + 8 + 8)
    + 32
    + OPAQUE_SERVER_LOGIN_STATE_BYTES;

const AUTHENTICATION_TRANSACTION_RECORD_VERSION: u16 = 1;
const AUTHENTICATION_TRANSACTION_CLASS: u16 = 2;
const AUTHENTICATION_CANDIDATE_KNOWN: u8 = 1;
const AUTHENTICATION_CANDIDATE_REJECT: u8 = 2;

/// Move-only encrypted-record plaintext for one live authentication attempt.
///
/// The fixed body contains no normalized login. It retains only keyed/private
/// identities, the exact route and request bindings, and the reviewed OPAQUE
/// server-state serialization required by a later FINISH.
pub struct AuthenticationTransactionRecord(
    Zeroizing<[u8; AUTHENTICATION_TRANSACTION_RECORD_BYTES]>,
);

impl AuthenticationTransactionRecord {
    /// Captures an unconsumed transaction with a conservative UTC deadline.
    ///
    /// Whole-second persistence rounds the remaining monotonic lifetime down,
    /// so restart can shorten an attempt but can never extend it.
    pub fn capture(
        transaction: &AccountTransaction<AccountAuthenticationState>,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<Self, AuthError> {
        let binding = transaction.binding();
        if binding.class() != TransactionClass::Authentication || now >= binding.expires_at() {
            return Err(AuthError::Expired);
        }
        let state = transaction.state_ref().ok_or(AuthError::Consumed)?;
        let remaining_millis = binding
            .expires_at()
            .get()
            .checked_sub(now.get())
            .ok_or(AuthError::Expired)?;
        let remaining_seconds = remaining_millis / 1_000;
        if remaining_seconds == 0 {
            return Err(AuthError::Expired);
        }
        let durable_expires_at = now_utc
            .checked_add(remaining_seconds)
            .map_err(|_| AuthError::Overflow)?;
        let mut encoded = Zeroizing::new([0_u8; AUTHENTICATION_TRANSACTION_RECORD_BYTES]);
        let mut writer = AuthenticationRecordWriter::new(encoded.as_mut());
        writer.put_u16(AUTHENTICATION_TRANSACTION_RECORD_VERSION)?;
        writer.put_u16(AUTHENTICATION_TRANSACTION_CLASS)?;
        writer.put(binding.transaction_id().as_bytes())?;
        writer.put(binding.network_id().as_bytes())?;
        put_route(&mut writer, binding.route())?;
        writer.put_u64(durable_expires_at.get())?;
        put_request_binding(&mut writer, state.start_request_binding)?;
        put_authentication_candidate(&mut writer, state.candidate)?;
        writer.put(state.credential_id.expose_for_account_service())?;
        writer.put(state.server_state.expose_for_persistence())?;
        writer.finish()?;
        Ok(Self(encoded))
    }

    /// Copies one opened storage body into a fixed zeroizing allocation.
    pub fn parse(encoded: &[u8]) -> Result<Self, AuthError> {
        let bytes: [u8; AUTHENTICATION_TRANSACTION_RECORD_BYTES] =
            encoded.try_into().map_err(|_| AuthError::InvalidEncoding)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Borrows the exact body only for encrypted persistence.
    #[must_use]
    pub fn expose_for_persistence(&self) -> &[u8; AUTHENTICATION_TRANSACTION_RECORD_BYTES] {
        &self.0
    }

    /// Returns the conservative exclusive UTC deadline encoded in this row.
    pub fn durable_expires_at_utc(&self) -> Result<UtcSecond, AuthError> {
        let mut reader = AuthenticationRecordReader::new(self.0.as_ref());
        if reader.read_u16()? != AUTHENTICATION_TRANSACTION_RECORD_VERSION
            || reader.read_u16()? != AUTHENTICATION_TRANSACTION_CLASS
        {
            return Err(AuthError::InvalidEncoding);
        }
        let _transaction_id = reader.read_array::<16>()?;
        let _network_id = reader.read_array::<32>()?;
        let _route = read_route(&mut reader)?;
        Ok(UtcSecond::from_unix_seconds(reader.read_u64()?))
    }

    /// Restores a still-live transaction under new process-local monotonic time.
    pub fn restore(
        self,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<AccountTransaction<AccountAuthenticationState>, AuthError> {
        let mut reader = AuthenticationRecordReader::new(self.0.as_ref());
        if reader.read_u16()? != AUTHENTICATION_TRANSACTION_RECORD_VERSION
            || reader.read_u16()? != AUTHENTICATION_TRANSACTION_CLASS
        {
            return Err(AuthError::InvalidEncoding);
        }
        let transaction_id = TransactionId::from_bytes(reader.read_array()?);
        let network_id = NetworkId::from_bytes(reader.read_array()?);
        let route = read_route(&mut reader)?;
        let durable_expires_at = UtcSecond::from_unix_seconds(reader.read_u64()?);
        if now_utc >= durable_expires_at {
            return Err(AuthError::Expired);
        }
        let start_request_binding = read_request_binding(&mut reader)?;
        if start_request_binding.network_id() != network_id
            || start_request_binding.message_kind() != AccountServiceMessageKind::OpaqueAuthStart
        {
            return Err(AuthError::ContextMismatch);
        }
        let candidate = read_authentication_candidate(&mut reader)?;
        let credential_id = OpaqueCredentialId::from_bytes(reader.read_array()?);
        let server_state = OpaqueServerLoginState::from_persisted_bytes(reader.read_array()?)?;
        reader.finish()?;
        let remaining_seconds = durable_expires_at
            .get()
            .checked_sub(now_utc.get())
            .ok_or(AuthError::Expired)?;
        let remaining_millis = remaining_seconds
            .checked_mul(1_000)
            .ok_or(AuthError::Overflow)?;
        let expires_at = now
            .checked_add(remaining_millis)
            .map_err(|_| AuthError::Overflow)?;
        let binding = AccountTransactionBinding::restore_authentication(
            transaction_id,
            network_id,
            route,
            expires_at,
        );
        Ok(AccountTransaction::new(
            binding,
            AccountAuthenticationState {
                start_request_binding,
                candidate,
                credential_id,
                server_state,
            },
        ))
    }
}

/// Exact version-one bytes of one live account-creation transaction.
pub const CREATION_TRANSACTION_RECORD_BYTES: usize = 2
    + 2
    + 16
    + 32
    + (16 + 16 + 16 + 8 + 16 + 32)
    + 8
    + (32 + 16 + 32 + 16 + 2)
    + 2
    + 32
    + 32
    + 1
    + 16
    + 8;

const CREATION_TRANSACTION_RECORD_VERSION: u16 = 1;
const CREATION_TRANSACTION_CLASS: u16 = 1;

/// Move-only encrypted-record plaintext for one live account-creation attempt.
///
/// The fixed body contains no normalized login or invitation bearer. It stores
/// only the keyed login digest and already-verified invitation metadata.
pub struct CreationTransactionRecord(Zeroizing<[u8; CREATION_TRANSACTION_RECORD_BYTES]>);

impl CreationTransactionRecord {
    fn capture(
        transaction: &AccountTransaction<AccountCreationState>,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<Self, AuthError> {
        let binding = transaction.binding();
        let durable_expires_at =
            durable_transaction_expiry(binding, TransactionClass::AccountCreation, now, now_utc)?;
        let state = transaction.state_ref().ok_or(AuthError::Consumed)?;
        let mut encoded = Zeroizing::new([0_u8; CREATION_TRANSACTION_RECORD_BYTES]);
        let mut writer = AuthenticationRecordWriter::new(encoded.as_mut());
        put_transaction_record_header(
            &mut writer,
            binding,
            CREATION_TRANSACTION_RECORD_VERSION,
            CREATION_TRANSACTION_CLASS,
            durable_expires_at,
        )?;
        put_request_binding(&mut writer, state.start_request_binding)?;
        put_start_disposition(&mut writer, state.disposition)?;
        writer.put(state.login_digest.expose_for_storage_key())?;
        writer.put(state.credential_id.expose_for_account_service())?;
        put_validated_invitation(&mut writer, state.invitation.as_ref())?;
        writer.finish()?;
        Ok(Self(encoded))
    }

    /// Copies one opened storage body into a fixed zeroizing allocation.
    pub fn parse(encoded: &[u8]) -> Result<Self, AuthError> {
        let bytes: [u8; CREATION_TRANSACTION_RECORD_BYTES] =
            encoded.try_into().map_err(|_| AuthError::InvalidEncoding)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Borrows the exact body only for encrypted persistence.
    #[must_use]
    pub fn expose_for_persistence(&self) -> &[u8; CREATION_TRANSACTION_RECORD_BYTES] {
        &self.0
    }

    /// Returns the conservative exclusive UTC deadline encoded in this row.
    pub fn durable_expires_at_utc(&self) -> Result<UtcSecond, AuthError> {
        let mut reader = AuthenticationRecordReader::new(self.0.as_ref());
        let (_, _, _, durable_expires_at) = read_transaction_record_header(
            &mut reader,
            CREATION_TRANSACTION_RECORD_VERSION,
            CREATION_TRANSACTION_CLASS,
        )?;
        Ok(durable_expires_at)
    }

    /// Restores a still-live transaction under new process-local monotonic time.
    pub fn restore(
        self,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<AccountTransaction<AccountCreationState>, AuthError> {
        let mut reader = AuthenticationRecordReader::new(self.0.as_ref());
        let (transaction_id, network_id, route, durable_expires_at) =
            read_transaction_record_header(
                &mut reader,
                CREATION_TRANSACTION_RECORD_VERSION,
                CREATION_TRANSACTION_CLASS,
            )?;
        let expires_at = restore_transaction_deadline(durable_expires_at, now, now_utc)?;
        let start_request_binding = read_request_binding(&mut reader)?;
        validate_start_request_binding(
            start_request_binding,
            network_id,
            AccountServiceMessageKind::AccountCreateStart,
        )?;
        let disposition = read_start_disposition(&mut reader)?;
        let login_digest = LoginIndexDigest::from_storage_key(reader.read_array()?);
        let credential_id = OpaqueCredentialId::from_bytes(reader.read_array()?);
        let invitation = read_validated_invitation(&mut reader)?;
        reader.finish()?;
        let binding = AccountTransactionBinding::restore(
            transaction_id,
            TransactionClass::AccountCreation,
            network_id,
            route,
            expires_at,
        );
        Ok(AccountTransaction::new(
            binding,
            AccountCreationState {
                start_request_binding,
                disposition,
                login_digest,
                credential_id,
                invitation,
            },
        ))
    }
}

/// Exact version-one bytes of one live credential-change transaction.
pub const CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES: usize = 2
    + 2
    + 16
    + 32
    + (16 + 16 + 16 + 8 + 16 + 32)
    + 8
    + (32 + 16 + 32 + 16 + 2)
    + 2
    + 24
    + 8
    + 8
    + 32;

const CREDENTIAL_CHANGE_TRANSACTION_RECORD_VERSION: u16 = 1;
const CREDENTIAL_CHANGE_TRANSACTION_CLASS: u16 = 3;

/// Move-only encrypted-record plaintext for one live credential-change attempt.
///
/// Process-local fresh-auth proof material is deliberately absent. Proof is
/// consumed before this state can be captured.
pub struct CredentialChangeTransactionRecord(
    Zeroizing<[u8; CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES]>,
);

impl CredentialChangeTransactionRecord {
    fn capture(
        transaction: &AccountTransaction<CredentialChangeState>,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<Self, AuthError> {
        let binding = transaction.binding();
        let durable_expires_at =
            durable_transaction_expiry(binding, TransactionClass::CredentialChange, now, now_utc)?;
        let state = transaction.state_ref().ok_or(AuthError::Consumed)?;
        let mut encoded = Zeroizing::new([0_u8; CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES]);
        let mut writer = AuthenticationRecordWriter::new(encoded.as_mut());
        put_transaction_record_header(
            &mut writer,
            binding,
            CREDENTIAL_CHANGE_TRANSACTION_RECORD_VERSION,
            CREDENTIAL_CHANGE_TRANSACTION_CLASS,
            durable_expires_at,
        )?;
        put_request_binding(&mut writer, state.start_request_binding)?;
        put_start_disposition(&mut writer, state.disposition)?;
        writer.put(state.account.account_id.to_text().as_bytes())?;
        writer.put_u64(state.account.account_revision.get())?;
        writer.put_u64(state.account.account_session_generation.get())?;
        writer.put(state.credential_id.expose_for_account_service())?;
        writer.finish()?;
        Ok(Self(encoded))
    }

    /// Copies one opened storage body into a fixed zeroizing allocation.
    pub fn parse(encoded: &[u8]) -> Result<Self, AuthError> {
        let bytes: [u8; CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES] =
            encoded.try_into().map_err(|_| AuthError::InvalidEncoding)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Borrows the exact body only for encrypted persistence.
    #[must_use]
    pub fn expose_for_persistence(&self) -> &[u8; CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES] {
        &self.0
    }

    /// Returns the conservative exclusive UTC deadline encoded in this row.
    pub fn durable_expires_at_utc(&self) -> Result<UtcSecond, AuthError> {
        let mut reader = AuthenticationRecordReader::new(self.0.as_ref());
        let (_, _, _, durable_expires_at) = read_transaction_record_header(
            &mut reader,
            CREDENTIAL_CHANGE_TRANSACTION_RECORD_VERSION,
            CREDENTIAL_CHANGE_TRANSACTION_CLASS,
        )?;
        Ok(durable_expires_at)
    }

    /// Restores a still-live transaction under new process-local monotonic time.
    pub fn restore(
        self,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<AccountTransaction<CredentialChangeState>, AuthError> {
        let mut reader = AuthenticationRecordReader::new(self.0.as_ref());
        let (transaction_id, network_id, route, durable_expires_at) =
            read_transaction_record_header(
                &mut reader,
                CREDENTIAL_CHANGE_TRANSACTION_RECORD_VERSION,
                CREDENTIAL_CHANGE_TRANSACTION_CLASS,
            )?;
        let expires_at = restore_transaction_deadline(durable_expires_at, now, now_utc)?;
        let start_request_binding = read_request_binding(&mut reader)?;
        validate_start_request_binding(
            start_request_binding,
            network_id,
            AccountServiceMessageKind::CredentialChangeStart,
        )?;
        let disposition = read_start_disposition(&mut reader)?;
        let account_id = AccountId::parse_wire_bytes(&reader.read_array::<24>()?)
            .map_err(|_| AuthError::InvalidEncoding)?;
        let account_revision =
            Revision::new(reader.read_u64()?).map_err(|_| AuthError::InvalidEncoding)?;
        let account_session_generation =
            Generation::new(reader.read_u64()?).map_err(|_| AuthError::InvalidEncoding)?;
        if account_session_generation.get() == 0 {
            return Err(AuthError::InvalidEncoding);
        }
        let credential_id = OpaqueCredentialId::from_bytes(reader.read_array()?);
        reader.finish()?;
        let binding = AccountTransactionBinding::restore(
            transaction_id,
            TransactionClass::CredentialChange,
            network_id,
            route,
            expires_at,
        );
        Ok(AccountTransaction::new(
            binding,
            CredentialChangeState {
                start_request_binding,
                disposition,
                account: AccountSnapshot {
                    account_id,
                    account_revision,
                    account_session_generation,
                },
                credential_id,
            },
        ))
    }
}

fn durable_transaction_expiry(
    binding: AccountTransactionBinding,
    expected_class: TransactionClass,
    now: MonotonicTick,
    now_utc: UtcSecond,
) -> Result<UtcSecond, AuthError> {
    if binding.class() != expected_class || now >= binding.expires_at() {
        return Err(AuthError::Expired);
    }
    let remaining_millis = binding
        .expires_at()
        .get()
        .checked_sub(now.get())
        .ok_or(AuthError::Expired)?;
    let remaining_seconds = remaining_millis / 1_000;
    if remaining_seconds == 0 {
        return Err(AuthError::Expired);
    }
    now_utc
        .checked_add(remaining_seconds)
        .map_err(|_| AuthError::Overflow)
}

fn restore_transaction_deadline(
    durable_expires_at: UtcSecond,
    now: MonotonicTick,
    now_utc: UtcSecond,
) -> Result<MonotonicTick, AuthError> {
    if now_utc >= durable_expires_at {
        return Err(AuthError::Expired);
    }
    let remaining_seconds = durable_expires_at
        .get()
        .checked_sub(now_utc.get())
        .ok_or(AuthError::Expired)?;
    let remaining_millis = remaining_seconds
        .checked_mul(1_000)
        .ok_or(AuthError::Overflow)?;
    now.checked_add(remaining_millis)
        .map_err(|_| AuthError::Overflow)
}

fn put_transaction_record_header(
    writer: &mut AuthenticationRecordWriter<'_>,
    binding: AccountTransactionBinding,
    version: u16,
    class: u16,
    durable_expires_at: UtcSecond,
) -> Result<(), AuthError> {
    writer.put_u16(version)?;
    writer.put_u16(class)?;
    writer.put(binding.transaction_id().as_bytes())?;
    writer.put(binding.network_id().as_bytes())?;
    put_route(writer, binding.route())?;
    writer.put_u64(durable_expires_at.get())
}

fn read_transaction_record_header(
    reader: &mut AuthenticationRecordReader<'_>,
    expected_version: u16,
    expected_class: u16,
) -> Result<(TransactionId, NetworkId, AccountRouteBinding, UtcSecond), AuthError> {
    if reader.read_u16()? != expected_version || reader.read_u16()? != expected_class {
        return Err(AuthError::InvalidEncoding);
    }
    let transaction_id = TransactionId::from_bytes(reader.read_array()?);
    let network_id = NetworkId::from_bytes(reader.read_array()?);
    let route = read_route(reader)?;
    let durable_expires_at = UtcSecond::from_unix_seconds(reader.read_u64()?);
    Ok((transaction_id, network_id, route, durable_expires_at))
}

fn validate_start_request_binding(
    binding: AccountRequestBinding,
    network_id: NetworkId,
    message_kind: AccountServiceMessageKind,
) -> Result<(), AuthError> {
    if binding.network_id() != network_id || binding.message_kind() != message_kind {
        return Err(AuthError::ContextMismatch);
    }
    Ok(())
}

fn put_start_disposition(
    writer: &mut AuthenticationRecordWriter<'_>,
    disposition: StartDisposition,
) -> Result<(), AuthError> {
    let code = match disposition {
        StartDisposition::SuccessCandidate => 0,
        StartDisposition::RejectAtFinish(error) => auth_error_record_code(error),
    };
    writer.put_u16(code)
}

fn read_start_disposition(
    reader: &mut AuthenticationRecordReader<'_>,
) -> Result<StartDisposition, AuthError> {
    let code = reader.read_u16()?;
    if code == 0 {
        return Ok(StartDisposition::SuccessCandidate);
    }
    Ok(StartDisposition::RejectAtFinish(
        auth_error_from_record_code(code)?,
    ))
}

const fn auth_error_record_code(error: AuthError) -> u16 {
    match error {
        AuthError::InvalidEncoding => 1,
        AuthError::ContextMismatch => 2,
        AuthError::Consumed => 3,
        AuthError::Expired => 4,
        AuthError::WrongConnection => 5,
        AuthError::WrongOrigin => 6,
        AuthError::AuthenticationFailed => 7,
        AuthError::InvitationRejected => 8,
        AuthError::EntropyUnavailable => 9,
        AuthError::AllocationFailed => 10,
        AuthError::Overflow => 11,
        AuthError::WorkerUnavailable => 12,
        AuthError::WrongState => 13,
    }
}

const fn auth_error_from_record_code(code: u16) -> Result<AuthError, AuthError> {
    match code {
        1 => Ok(AuthError::InvalidEncoding),
        2 => Ok(AuthError::ContextMismatch),
        3 => Ok(AuthError::Consumed),
        4 => Ok(AuthError::Expired),
        5 => Ok(AuthError::WrongConnection),
        6 => Ok(AuthError::WrongOrigin),
        7 => Ok(AuthError::AuthenticationFailed),
        8 => Ok(AuthError::InvitationRejected),
        9 => Ok(AuthError::EntropyUnavailable),
        10 => Ok(AuthError::AllocationFailed),
        11 => Ok(AuthError::Overflow),
        12 => Ok(AuthError::WorkerUnavailable),
        13 => Ok(AuthError::WrongState),
        _ => Err(AuthError::InvalidEncoding),
    }
}

fn put_validated_invitation(
    writer: &mut AuthenticationRecordWriter<'_>,
    invitation: Option<&ValidatedInvitation>,
) -> Result<(), AuthError> {
    match invitation {
        Some(invitation) => {
            writer.put(&[1])?;
            writer.put(invitation.invite_id.as_bytes())?;
            writer.put_u64(invitation.expires_at.get())
        }
        None => {
            writer.put(&[0])?;
            writer.put(&[0_u8; 16])?;
            writer.put_u64(0)
        }
    }
}

fn read_validated_invitation(
    reader: &mut AuthenticationRecordReader<'_>,
) -> Result<Option<ValidatedInvitation>, AuthError> {
    let tag = reader.read_array::<1>()?[0];
    let invite_id = reader.read_array::<16>()?;
    let expires_at = reader.read_u64()?;
    match tag {
        0 if invite_id == [0_u8; 16] && expires_at == 0 => Ok(None),
        1 if expires_at != 0 => Ok(Some(ValidatedInvitation {
            invite_id: InviteId::from_bytes(invite_id),
            expires_at: UtcSecond::from_unix_seconds(expires_at),
        })),
        _ => Err(AuthError::InvalidEncoding),
    }
}

fn put_route(
    writer: &mut AuthenticationRecordWriter<'_>,
    route: AccountRouteBinding,
) -> Result<(), AuthError> {
    writer.put(route.edge_server_id().as_bytes())?;
    writer.put(route.edge_incarnation().as_bytes())?;
    writer.put(route.origin_id().as_bytes())?;
    writer.put_u64(route.origin_generation().get())?;
    writer.put(route.connection_id().as_bytes())?;
    writer.put(route.connection_nonce())
}

fn read_route(
    reader: &mut AuthenticationRecordReader<'_>,
) -> Result<AccountRouteBinding, AuthError> {
    let edge_server_id = ServerId::from_bytes(reader.read_array()?);
    let edge_incarnation = ServerIncarnation::from_bytes(reader.read_array()?);
    let origin_id = OriginId::from_bytes(reader.read_array()?);
    let origin_generation =
        Generation::new(reader.read_u64()?).map_err(|_| AuthError::InvalidEncoding)?;
    if origin_generation.get() == 0 {
        return Err(AuthError::InvalidEncoding);
    }
    let connection_id = ConnectionId::from_bytes(reader.read_array()?);
    let connection_nonce = reader.read_array()?;
    Ok(AccountRouteBinding::new(
        edge_server_id,
        edge_incarnation,
        origin_id,
        origin_generation,
        connection_id,
        connection_nonce,
    ))
}

fn put_request_binding(
    writer: &mut AuthenticationRecordWriter<'_>,
    binding: AccountRequestBinding,
) -> Result<(), AuthError> {
    writer.put(binding.network_id().as_bytes())?;
    writer.put(binding.recovery_epoch().as_bytes())?;
    writer.put(binding.recipient_key_id().as_bytes())?;
    writer.put(binding.client_request_id().as_bytes())?;
    writer.put_u16(binding.message_kind().wire_value())
}

fn read_request_binding(
    reader: &mut AuthenticationRecordReader<'_>,
) -> Result<AccountRequestBinding, AuthError> {
    let network_id = NetworkId::from_bytes(reader.read_array()?);
    let recovery_epoch = RecoveryEpoch::from_bytes(reader.read_array()?);
    let recipient_key_id = AccountHpkeKeyId::from_bytes(reader.read_array()?);
    let client_request_id = RequestId::from_bytes(reader.read_array()?);
    let message_kind = AccountServiceMessageKind::from_wire(reader.read_u16()?)
        .map_err(|_| AuthError::InvalidEncoding)?;
    Ok(AccountRequestBinding::new(
        network_id,
        recovery_epoch,
        recipient_key_id,
        client_request_id,
        message_kind,
    ))
}

fn put_authentication_candidate(
    writer: &mut AuthenticationRecordWriter<'_>,
    candidate: AuthenticationCandidate,
) -> Result<(), AuthError> {
    match candidate {
        AuthenticationCandidate::Known(account) => {
            writer.put(&[AUTHENTICATION_CANDIDATE_KNOWN])?;
            writer.put(account.account_id.to_text().as_bytes())?;
            writer.put_u64(account.account_revision.get())?;
            writer.put_u64(account.account_session_generation.get())
        }
        AuthenticationCandidate::RejectAtFinish => {
            writer.put(&[AUTHENTICATION_CANDIDATE_REJECT])?;
            writer.put(&[0_u8; 24])?;
            writer.put_u64(0)?;
            writer.put_u64(0)
        }
    }
}

fn read_authentication_candidate(
    reader: &mut AuthenticationRecordReader<'_>,
) -> Result<AuthenticationCandidate, AuthError> {
    let tag = reader.read_array::<1>()?[0];
    let account_bytes = reader.read_array::<24>()?;
    let account_revision = reader.read_u64()?;
    let account_session_generation = reader.read_u64()?;
    match tag {
        AUTHENTICATION_CANDIDATE_KNOWN => {
            let account_id = AccountId::parse_wire_bytes(&account_bytes)
                .map_err(|_| AuthError::InvalidEncoding)?;
            let account_revision =
                Revision::new(account_revision).map_err(|_| AuthError::InvalidEncoding)?;
            let account_session_generation = Generation::new(account_session_generation)
                .map_err(|_| AuthError::InvalidEncoding)?;
            if account_session_generation.get() == 0 {
                return Err(AuthError::InvalidEncoding);
            }
            Ok(AuthenticationCandidate::Known(AccountSnapshot {
                account_id,
                account_revision,
                account_session_generation,
            }))
        }
        AUTHENTICATION_CANDIDATE_REJECT
            if account_bytes == [0_u8; 24]
                && account_revision == 0
                && account_session_generation == 0 =>
        {
            Ok(AuthenticationCandidate::RejectAtFinish)
        }
        _ => Err(AuthError::InvalidEncoding),
    }
}

struct AuthenticationRecordWriter<'a> {
    encoded: &'a mut [u8],
    position: usize,
}

impl<'a> AuthenticationRecordWriter<'a> {
    const fn new(encoded: &'a mut [u8]) -> Self {
        Self {
            encoded,
            position: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), AuthError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(AuthError::Overflow)?;
        let destination = self
            .encoded
            .get_mut(self.position..end)
            .ok_or(AuthError::InvalidEncoding)?;
        destination.copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn put_u16(&mut self, value: u16) -> Result<(), AuthError> {
        self.put(&value.to_be_bytes())
    }

    fn put_u64(&mut self, value: u64) -> Result<(), AuthError> {
        self.put(&value.to_be_bytes())
    }

    fn finish(self) -> Result<(), AuthError> {
        if self.position == self.encoded.len() {
            Ok(())
        } else {
            Err(AuthError::InvalidEncoding)
        }
    }
}

struct AuthenticationRecordReader<'a> {
    encoded: &'a [u8],
    position: usize,
}

impl<'a> AuthenticationRecordReader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self {
            encoded,
            position: 0,
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], AuthError> {
        let end = self.position.checked_add(N).ok_or(AuthError::Overflow)?;
        let value = self
            .encoded
            .get(self.position..end)
            .ok_or(AuthError::InvalidEncoding)?
            .try_into()
            .map_err(|_| AuthError::InvalidEncoding)?;
        self.position = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, AuthError> {
        self.read_array().map(u16::from_be_bytes)
    }

    fn read_u64(&mut self) -> Result<u64, AuthError> {
        self.read_array().map(u64::from_be_bytes)
    }

    fn finish(self) -> Result<(), AuthError> {
        if self.position == self.encoded.len() {
            Ok(())
        } else {
            Err(AuthError::InvalidEncoding)
        }
    }
}

/// One-use bearer grant and exact route binding to commit when OPAQUE
/// authentication succeeds.
///
/// This commit intent is neither proof of durability nor session-open
/// authority. Stage 5 must persist it with the sealed completion before Stage 6
/// may atomically consume the stored grant. The intent stays inseparable from
/// its process-local fresh-auth proof and has no formatting or cloning surface.
///
/// ```compile_fail
/// use agenc_ircd_auth::AuthenticationGrant;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AuthenticationGrant>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_auth::AuthenticationGrant;
/// fn separate(grant: AuthenticationGrant) {
///     let _ = grant.into_parts();
/// }
/// ```
///
/// ```compile_fail
/// use agenc_ircd_auth::AuthenticationGrant;
/// fn authorize_before_commit(grant: AuthenticationGrant) {
///     grant.consume_session_open();
/// }
/// ```
pub struct AuthenticationGrant {
    grant_id: AuthGrantId,
    network_id: NetworkId,
    route: AccountRouteBinding,
    account: AccountSnapshot,
    process_expires_at: MonotonicTick,
    durable_expires_at_utc: UtcSecond,
    fresh_authentication: FreshAuthenticationProof,
}

impl AuthenticationGrant {
    /// Returns the authenticated account.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account.account_id
    }

    /// Returns the generation that fences prior credentials and sessions.
    #[must_use]
    pub const fn account_session_generation(&self) -> Generation {
        self.account.account_session_generation
    }

    /// Returns the Network ID required by the matching session-open request.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Returns the home edge required by the matching session-open request.
    #[must_use]
    pub const fn edge_server_id(&self) -> ServerId {
        self.route.edge_server_id()
    }

    /// Returns the home-edge incarnation required by session open.
    #[must_use]
    pub const fn edge_incarnation(&self) -> ServerIncarnation {
        self.route.edge_incarnation()
    }

    /// Returns the federation origin required by session open.
    #[must_use]
    pub const fn origin_id(&self) -> OriginId {
        self.route.origin_id()
    }

    /// Returns the origin generation required by session open.
    #[must_use]
    pub const fn origin_generation(&self) -> Generation {
        self.route.origin_generation()
    }

    /// Returns the transport identity required by session open.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.route.connection_id()
    }

    /// Borrows the private nonce only for the future encrypted grant row or
    /// its one matching session-open comparison. Possessing this value does
    /// not authorize session open without the durable one-use row.
    #[must_use]
    pub const fn connection_nonce_for_persistence_or_session_open(&self) -> &[u8; 32] {
        self.route.connection_nonce()
    }

    /// Returns the current-process exclusive monotonic grant deadline.
    #[must_use]
    pub const fn process_expires_at(&self) -> MonotonicTick {
        self.process_expires_at
    }

    /// Returns the exclusive durable UTC deadline used to reject replay after
    /// restart.
    #[must_use]
    pub const fn durable_expires_at_utc(&self) -> UtcSecond {
        self.durable_expires_at_utc
    }

    /// Returns the separate process-local fresh-auth deadline retained inside
    /// this inseparable grant intent. Unlike the exclusive transaction
    /// deadlines, this instant is inclusive: the proof stays valid while
    /// `now <= expires_at`.
    #[must_use]
    pub const fn fresh_authentication_expires_at(&self) -> MonotonicTick {
        self.fresh_authentication.expires_at
    }

    /// Borrows the bearer only for encrypted persistence or the matching
    /// session-open request. Stage 4 does not treat this borrow as proof that
    /// the grant was committed.
    #[must_use]
    pub const fn grant_id_for_persistence_or_session_open(&self) -> &AuthGrantId {
        &self.grant_id
    }

    /// Consumes a durably released authentication grant and returns its
    /// process-local, one-use destructive-operation proof.
    ///
    /// External callers can obtain an owned grant only from
    /// [`SealedAccountFinishOutcome::into_result_after_commit`], so the proof
    /// cannot cross the durable completion barrier early.
    #[must_use]
    pub fn into_fresh_authentication_after_commit(self) -> FreshAuthenticationProof {
        self.fresh_authentication
    }
}

/// Starts a real-or-fake OPAQUE login without retaining the normalized login.
pub fn begin_authentication(
    profile: &OpaqueProfile,
    login_index_key: &LoginIndexKey,
    fake_credential_key: &OpaqueFakeCredentialKey,
    parameters: AuthenticationStartParameters,
) -> Result<AccountStartOutcome<AccountAuthenticationState>, AuthError> {
    let mut entropy = OsEntropy;
    begin_authentication_with_entropy(
        profile,
        login_index_key,
        fake_credential_key,
        parameters,
        &mut entropy,
    )
}

fn begin_authentication_with_entropy(
    profile: &OpaqueProfile,
    login_index_key: &LoginIndexKey,
    fake_credential_key: &OpaqueFakeCredentialKey,
    parameters: AuthenticationStartParameters,
    entropy: &mut impl EntropySource,
) -> Result<AccountStartOutcome<AccountAuthenticationState>, AuthError> {
    let AuthenticationStartParameters {
        context,
        request,
        lookup,
    } = parameters;
    let (request, response_lineage) = request.into_parts();
    let start_request_binding = response_lineage.binding();
    if request.network_id != context.network_id {
        return Err(AuthError::AuthenticationFailed);
    }
    let login_digest = derive_login_index(login_index_key, context.network_id, &request.login)?;
    let (candidate, credential_id, record) = select_authentication_candidate(
        fake_credential_key,
        context.network_id,
        &request.login,
        &login_digest,
        lookup,
    )?;
    let transaction_id = fresh_transaction_id(entropy)?;
    let (ke2, server_state) = profile.authentication_start(
        context.network_id,
        &credential_id,
        record.as_ref(),
        &request.ke1,
    )?;
    let challenge_credential = duplicate_credential_id(&credential_id);
    let binding = context.binding(transaction_id, TransactionClass::Authentication)?;
    let state = AccountAuthenticationState {
        start_request_binding,
        candidate,
        credential_id,
        server_state,
    };
    let response = AccountResponsePlan::new(
        response_lineage,
        transaction_id,
        AccountServiceResponsePayload::AuthenticationChallenge {
            transaction_id,
            credential_id: challenge_credential,
            ke2: Box::new(ke2),
        },
    )?;
    AccountStartOutcome::new(AccountTransaction::new(binding, state), response)
}

fn select_authentication_candidate(
    fake_credential_key: &OpaqueFakeCredentialKey,
    network_id: NetworkId,
    login: &agenc_ircd_types::NormalizedLogin,
    login_digest: &LoginIndexDigest,
    lookup: AuthenticationLookup,
) -> Result<AuthenticationSelection, AuthError> {
    // Keep the keyed lookup work independent of account existence. The real
    // arm discards this value after the same HMAC performed by the fake arm.
    let fake_credential_id = derive_fake_credential_id(fake_credential_key, network_id, login)?;
    match lookup {
        AuthenticationLookup::Known(known)
            if known.login_digest.matches(login_digest)
                && known.account_session_generation.get() != 0 =>
        {
            let candidate = AuthenticationCandidate::Known(AccountSnapshot {
                account_id: known.account_id,
                account_revision: known.account_revision,
                account_session_generation: known.account_session_generation,
            });
            Ok((candidate, known.credential_id, Some(known.record)))
        }
        AuthenticationLookup::Known(_) | AuthenticationLookup::Unknown => Ok((
            AuthenticationCandidate::RejectAtFinish,
            fake_credential_id,
            None,
        )),
    }
}

type AuthenticationSelection = (
    AuthenticationCandidate,
    OpaqueCredentialId,
    Option<OpaqueRegistrationRecord>,
);

/// Consumes an OPAQUE authentication transaction and creates a bound grant.
pub fn finish_account_authentication(
    transaction: &mut AccountTransaction<AccountAuthenticationState>,
    context: AccountOperationContext,
    finish: AuthenticatedAccountRequest<AuthenticationFinish>,
) -> Result<AccountFinishOutcome<AuthenticationGrant>, AuthError> {
    let mut entropy = OsEntropy;
    finish_account_authentication_with_entropy(transaction, context, finish, &mut entropy)
}

fn finish_account_authentication_with_entropy(
    transaction: &mut AccountTransaction<AccountAuthenticationState>,
    context: AccountOperationContext,
    finish: AuthenticatedAccountRequest<AuthenticationFinish>,
    entropy: &mut impl EntropySource,
) -> Result<AccountFinishOutcome<AuthenticationGrant>, AuthError> {
    let (finish, response_lineage) = finish.into_parts();
    let finish_request_binding = response_lineage.binding();
    let claimed_transaction = finish.transaction_id;
    let expected_transaction = transaction.binding().transaction_id();
    let state = match transaction.consume(
        TransactionClass::Authentication,
        context.network_id,
        context.route,
        context.now,
    ) {
        Ok(state) => state,
        Err(error) => {
            let response = rejected_authentication_response(response_lineage, claimed_transaction)?;
            return Ok(AccountFinishOutcome::rejected(error, response));
        }
    };
    let authentication = evaluate_authentication_finish(
        state,
        context.network_id,
        &finish,
        expected_transaction,
        finish_request_binding,
    );
    let (account, credential_id, authentication) = match authentication? {
        AuthenticationFinishEvaluation::Accepted(account, credential_id, authentication) => {
            (account, credential_id, authentication)
        }
        AuthenticationFinishEvaluation::Rejected => {
            let response = rejected_authentication_response(response_lineage, claimed_transaction)?;
            return Ok(AccountFinishOutcome::rejected(
                AuthError::AuthenticationFailed,
                response,
            ));
        }
    };
    authorize_opaque(authentication);
    let grant = create_authentication_grant(account, credential_id, context, entropy)?;
    let response = AccountResponsePlan::new(
        response_lineage,
        expected_transaction,
        authentication_completion(expected_transaction, &grant),
    )?;
    Ok(AccountFinishOutcome::committed(grant, response))
}

enum AuthenticationFinishEvaluation {
    Accepted(AccountSnapshot, OpaqueCredentialId, OpaqueAuthentication),
    Rejected,
}

fn evaluate_authentication_finish(
    state: AccountAuthenticationState,
    network_id: NetworkId,
    finish: &AuthenticationFinish,
    expected_transaction: TransactionId,
    finish_request_binding: AccountRequestBinding,
) -> Result<AuthenticationFinishEvaluation, AuthError> {
    let AccountAuthenticationState {
        start_request_binding,
        candidate,
        credential_id,
        server_state,
    } = state;
    let authentication =
        match finish_authentication(network_id, &credential_id, server_state, &finish.ke3) {
            Ok(authentication) => Some(authentication),
            Err(AuthError::AuthenticationFailed) => None,
            Err(error) => return Err(error),
        };
    let account = match candidate {
        AuthenticationCandidate::Known(account) => Some(account),
        AuthenticationCandidate::RejectAtFinish => None,
    };
    if finish.network_id != network_id
        || finish.transaction_id != expected_transaction
        || validate_finish_lineage(start_request_binding, finish_request_binding).is_err()
        || account.is_none()
        || authentication.is_none()
    {
        return Ok(AuthenticationFinishEvaluation::Rejected);
    }
    let (Some(account), Some(authentication)) = (account, authentication) else {
        return Ok(AuthenticationFinishEvaluation::Rejected);
    };
    Ok(AuthenticationFinishEvaluation::Accepted(
        account,
        credential_id,
        authentication,
    ))
}

fn create_authentication_grant(
    account: AccountSnapshot,
    credential_id: OpaqueCredentialId,
    context: AccountOperationContext,
    entropy: &mut impl EntropySource,
) -> Result<AuthenticationGrant, AuthError> {
    let process_expires_at = context
        .now
        .get()
        .checked_add(AUTHENTICATION_GRANT_TIMEOUT_TICKS)
        .ok_or(AuthError::Overflow)?;
    let durable_expires_at_utc = context
        .now_utc
        .checked_add(AUTHENTICATION_GRANT_TIMEOUT_SECONDS)
        .map_err(|_| AuthError::Overflow)?;
    let fresh_authentication_expires_at = context
        .now
        .get()
        .checked_add(FRESH_AUTH_TIMEOUT_TICKS)
        .ok_or(AuthError::Overflow)?;
    let grant_id = AuthGrantId::generate(entropy).map_err(|_| AuthError::EntropyUnavailable)?;
    let fresh_authentication = FreshAuthenticationProof {
        account,
        credential_id,
        network_id: context.network_id,
        route: context.route,
        expires_at: MonotonicTick::from_ticks(fresh_authentication_expires_at),
    };
    Ok(AuthenticationGrant {
        grant_id,
        network_id: context.network_id,
        route: context.route,
        account,
        process_expires_at: MonotonicTick::from_ticks(process_expires_at),
        durable_expires_at_utc,
        fresh_authentication,
    })
}

fn authorize_opaque(authentication: OpaqueAuthentication) {
    authentication.authorize_account_transition();
}

/// Process-local, one-use proof for one destructive same-account start.
pub struct FreshAuthenticationProof {
    account: AccountSnapshot,
    credential_id: OpaqueCredentialId,
    network_id: NetworkId,
    route: AccountRouteBinding,
    expires_at: MonotonicTick,
}

impl FreshAuthenticationProof {
    /// Borrows the authenticated private credential identity for the one
    /// consistency read that precedes credential replacement.
    #[must_use]
    pub const fn credential_id_for_replacement(&self) -> &OpaqueCredentialId {
        &self.credential_id
    }

    fn consume_for_credential_change(
        self,
        context: AccountOperationContext,
        account: AccountSnapshot,
        credential_id: &OpaqueCredentialId,
    ) -> Result<(), AuthError> {
        let credential_matches = self
            .credential_id
            .expose_for_account_service()
            .ct_eq(credential_id.expose_for_account_service());
        self.consume(context, account)?;
        if bool::from(credential_matches) {
            Ok(())
        } else {
            Err(AuthError::WrongState)
        }
    }

    fn consume(
        self,
        context: AccountOperationContext,
        account: AccountSnapshot,
    ) -> Result<(), AuthError> {
        if self.network_id != context.network_id || self.account.account_id != account.account_id {
            return Err(AuthError::ContextMismatch);
        }
        self.route.validate_match(context.route)?;
        if self.account.account_revision != account.account_revision
            || self.account.account_session_generation != account.account_session_generation
        {
            return Err(AuthError::WrongState);
        }
        if context.now > self.expires_at {
            return Err(AuthError::Expired);
        }
        Ok(())
    }
}

/// Current account values authenticated before a destructive operation starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DestructiveAccountSnapshot(AccountSnapshot);

impl DestructiveAccountSnapshot {
    /// Constructs a storage-validated account snapshot.
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        account_revision: Revision,
        account_session_generation: Generation,
    ) -> Self {
        Self(AccountSnapshot {
            account_id,
            account_revision,
            account_session_generation,
        })
    }
}

/// Credential-change challenge state bound to one account incarnation and credential ID.
///
/// This state is not permission to replace a credential record.
pub struct CredentialChangeState {
    start_request_binding: AccountRequestBinding,
    disposition: StartDisposition,
    account: AccountSnapshot,
    credential_id: OpaqueCredentialId,
}

/// Complete coordinator inputs for one credential-replacement START.
pub struct CredentialChangeStartParameters {
    /// Complete route identity and clock binding.
    pub context: AccountOperationContext,
    /// Consumed same-account OPAQUE proof, or absence for a latent rejection.
    pub proof: Option<FreshAuthenticationProof>,
    /// Current storage-validated account state.
    pub account: DestructiveAccountSnapshot,
    /// Existing private credential identity, which must not change.
    pub credential_id: OpaqueCredentialId,
    /// Fully opened registration request with its authenticated response authority.
    pub request: AuthenticatedAccountRequest<CredentialChangeStart>,
    /// Conflict and recovery-state precondition result.
    pub operation_is_available: bool,
}

/// Atomic replacement-record and session-fence intent for Stage 05 storage.
pub struct CredentialReplacementIntent {
    account: AccountSnapshot,
    next_account_session_generation: Generation,
    credential_id: OpaqueCredentialId,
    record: OpaqueRegistrationRecord,
}

impl CredentialReplacementIntent {
    /// Returns the account whose sole password file must be replaced.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account.account_id
    }

    /// Returns the exact account revision authenticated at START.
    #[must_use]
    pub const fn expected_account_revision(&self) -> Revision {
        self.account.account_revision
    }

    /// Returns the old generation authenticated at START.
    #[must_use]
    pub const fn expected_account_session_generation(&self) -> Generation {
        self.account.account_session_generation
    }

    /// Returns the checked successor that fences every old session.
    #[must_use]
    pub const fn next_account_session_generation(&self) -> Generation {
        self.next_account_session_generation
    }

    /// Borrows the unchanged private OPAQUE credential identity.
    #[must_use]
    pub const fn credential_id(&self) -> &OpaqueCredentialId {
        &self.credential_id
    }

    /// Borrows the validated replacement password file.
    #[must_use]
    pub const fn record(&self) -> &OpaqueRegistrationRecord {
        &self.record
    }
}

/// Starts credential replacement after consuming a fresh same-account proof.
///
/// Stage 06 reaches this entry point only after a sealed authentication grant
/// crosses its durable completion barrier. A grant reconstructed from storage
/// must never yield a proof; the client reauthenticates before a destructive
/// control.
pub fn begin_credential_change(
    profile: &OpaqueProfile,
    parameters: CredentialChangeStartParameters,
) -> Result<AccountStartOutcome<CredentialChangeState>, AuthError> {
    let mut entropy = OsEntropy;
    begin_credential_change_with_entropy(profile, parameters, &mut entropy)
}

fn begin_credential_change_with_entropy(
    profile: &OpaqueProfile,
    parameters: CredentialChangeStartParameters,
    entropy: &mut impl EntropySource,
) -> Result<AccountStartOutcome<CredentialChangeState>, AuthError> {
    let CredentialChangeStartParameters {
        context,
        proof,
        account,
        credential_id,
        request,
        operation_is_available,
    } = parameters;
    let (request, response_lineage) = request.into_parts();
    let start_request_binding = response_lineage.binding();
    if request.network_id != context.network_id {
        return Err(AuthError::ContextMismatch);
    }
    let proof_result = proof.map_or(Err(AuthError::WrongState), |proof| {
        proof.consume_for_credential_change(context, account.0, &credential_id)
    });
    let mut disposition = StartDisposition::SuccessCandidate;
    if request.account_id != account.0.account_id {
        disposition = disposition.reject(AuthError::ContextMismatch);
    }
    if !operation_is_available {
        disposition = disposition.reject(AuthError::WrongState);
    }
    if let Err(error) = proof_result {
        disposition = disposition.reject(error);
    }
    let transaction_id = fresh_transaction_id(entropy)?;
    let response = profile.registration_start(&credential_id, &request.registration_request)?;
    let challenge_credential = duplicate_credential_id(&credential_id);
    let binding = context.binding(transaction_id, TransactionClass::CredentialChange)?;
    let state = CredentialChangeState {
        start_request_binding,
        disposition,
        account: account.0,
        credential_id,
    };
    let response = AccountResponsePlan::new(
        response_lineage,
        transaction_id,
        AccountServiceResponsePayload::CredentialChangeChallenge {
            transaction_id,
            credential_id: challenge_credential,
            response,
        },
    )?;
    AccountStartOutcome::new(AccountTransaction::new(binding, state), response)
}

/// Consumes credential-change state and produces one atomic replacement intent.
pub fn finish_credential_change(
    transaction: &mut AccountTransaction<CredentialChangeState>,
    context: AccountOperationContext,
    finish: AuthenticatedAccountRequest<CredentialChangeFinish>,
) -> Result<AccountFinishOutcome<CredentialReplacementIntent>, AuthError> {
    let (finish, response_lineage) = finish.into_parts();
    let finish_request_binding = response_lineage.binding();
    let claimed_transaction = finish.transaction_id;
    let expected_transaction = transaction.binding().transaction_id();
    let state = match transaction.consume(
        TransactionClass::CredentialChange,
        context.network_id,
        context.route,
        context.now,
    ) {
        Ok(state) => state,
        Err(error) => {
            let response =
                rejected_credential_change_response(response_lineage, claimed_transaction)?;
            return Ok(AccountFinishOutcome::rejected(error, response));
        }
    };
    if finish.network_id != context.network_id
        || finish.transaction_id != expected_transaction
        || validate_finish_lineage(state.start_request_binding, finish_request_binding).is_err()
    {
        let response = rejected_credential_change_response(response_lineage, claimed_transaction)?;
        return Ok(AccountFinishOutcome::rejected(
            AuthError::ContextMismatch,
            response,
        ));
    }
    if let Some(error) = state.disposition.rejection() {
        let response = rejected_credential_change_response(response_lineage, expected_transaction)?;
        return Ok(AccountFinishOutcome::rejected(error, response));
    }
    let next_account_session_generation = state
        .account
        .account_session_generation
        .checked_add(1)
        .map_err(|_| AuthError::Overflow)?;
    let intent = CredentialReplacementIntent {
        account: state.account,
        next_account_session_generation,
        credential_id: state.credential_id,
        record: finish.registration_record,
    };
    let response = AccountResponsePlan::new(
        response_lineage,
        expected_transaction,
        AccountServiceResponsePayload::CredentialChangeCompletion(Completion::committed(
            expected_transaction,
            intent.account_id(),
            next_account_session_generation.get(),
        )),
    )?;
    Ok(AccountFinishOutcome::committed(intent, response))
}

impl AccountFinishOutcome<CreateAccountIntent> {
    /// Verifies the creation receipt against the exact new-account intent and
    /// seals both as one checked terminal outcome.
    pub fn seal(
        self,
        current_response_count: u64,
    ) -> Result<SealedAccountFinishOutcome<CreateAccountIntent>, AuthError> {
        self.seal_checked(
            current_response_count,
            |intent, completion| {
                completion.account_id() == Some(intent.account_id())
                    && completion.account_session_generation() == 0
            },
            creation_completion,
        )
    }
}

impl AccountFinishOutcome<AuthenticationGrant> {
    /// Verifies the authentication receipt against the exact grant and seals
    /// both as one checked terminal outcome.
    pub fn seal(
        self,
        current_response_count: u64,
    ) -> Result<SealedAccountFinishOutcome<AuthenticationGrant>, AuthError> {
        self.seal_checked(
            current_response_count,
            |grant, completion| {
                completion.account_id() == Some(grant.account_id())
                    && completion.account_session_generation()
                        == grant.account_session_generation().get()
            },
            authentication_completion_fields,
        )
    }
}

impl AccountFinishOutcome<CredentialReplacementIntent> {
    /// Verifies the replacement receipt against the exact credential intent
    /// and seals both as one checked terminal outcome.
    pub fn seal(
        self,
        current_response_count: u64,
    ) -> Result<SealedAccountFinishOutcome<CredentialReplacementIntent>, AuthError> {
        self.seal_checked(
            current_response_count,
            |intent, completion| {
                completion.account_id() == Some(intent.account_id())
                    && completion.account_session_generation()
                        == intent.next_account_session_generation().get()
            },
            credential_change_completion,
        )
    }
}

fn creation_completion(payload: &AccountServiceResponsePayload) -> Option<Completion> {
    match payload {
        AccountServiceResponsePayload::CreationCompletion(completion) => Some(*completion),
        _ => None,
    }
}

fn authentication_completion_fields(payload: &AccountServiceResponsePayload) -> Option<Completion> {
    match payload {
        AccountServiceResponsePayload::AuthenticationCompletion(completion) => Some(*completion),
        _ => None,
    }
}

fn credential_change_completion(payload: &AccountServiceResponsePayload) -> Option<Completion> {
    match payload {
        AccountServiceResponsePayload::CredentialChangeCompletion(completion) => Some(*completion),
        _ => None,
    }
}

struct AccountDeletionState {
    account: AccountSnapshot,
    token: AccountDeletionToken,
}

/// One revision-bound, connection-bound deletion challenge.
pub struct AccountDeletionChallenge {
    transaction: AccountTransaction<AccountDeletionState>,
}

impl AccountDeletionChallenge {
    /// Borrows the raw token only for the private deletion reply.
    pub fn token(&self) -> Result<&[u8; 16], AuthError> {
        self.transaction
            .state_ref()
            .map(|state| state.token.expose_for_deletion())
            .ok_or(AuthError::Consumed)
    }

    /// Returns the original exclusive deadline for exact idempotent replay.
    #[must_use]
    pub const fn expires_at(&self) -> MonotonicTick {
        self.transaction.binding().expires_at()
    }

    /// Consumes this challenge on success or every terminal rejection.
    pub fn confirm(
        &mut self,
        context: AccountOperationContext,
        candidate: &[u8; 16],
        current_account: DestructiveAccountSnapshot,
        deletion_preconditions_hold: bool,
    ) -> Result<AccountDeletionIntent, AuthError> {
        let state = self.transaction.consume(
            TransactionClass::AccountDeletion,
            context.network_id,
            context.route,
            context.now,
        )?;
        if !state.token.matches(candidate) {
            return Err(AuthError::AuthenticationFailed);
        }
        if state.account.account_id != current_account.0.account_id
            || state.account.account_revision != current_account.0.account_revision
            || state.account.account_session_generation
                != current_account.0.account_session_generation
            || !deletion_preconditions_hold
        {
            return Err(AuthError::WrongState);
        }
        Ok(AccountDeletionIntent {
            account: state.account,
        })
    }
}

/// Revision and generation preconditions for one atomic deletion tombstone commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountDeletionIntent {
    account: AccountSnapshot,
}

impl AccountDeletionIntent {
    /// Returns the account being permanently tombstoned.
    #[must_use]
    pub const fn account_id(self) -> AccountId {
        self.account.account_id
    }

    /// Returns the account revision bound into the confirmation challenge.
    #[must_use]
    pub const fn expected_account_revision(self) -> Revision {
        self.account.account_revision
    }

    /// Returns the credential generation bound into the challenge.
    #[must_use]
    pub const fn expected_account_session_generation(self) -> Generation {
        self.account.account_session_generation
    }
}

/// Starts one deletion confirmation after consuming a fresh same-account proof.
///
/// Stage 04 withholds the `FreshAuthenticationProof` accessor, so this entry
/// point becomes reachable only when Stage 06 consumes an authentication
/// grant through `session_open`. A grant reconstructed from storage must never
/// yield a proof; the client reauthenticates before a destructive control.
pub fn begin_account_deletion(
    context: AccountOperationContext,
    proof: FreshAuthenticationProof,
    account: DestructiveAccountSnapshot,
) -> Result<AccountDeletionChallenge, AuthError> {
    let mut entropy = OsEntropy;
    begin_account_deletion_with_entropy(context, proof, account, &mut entropy)
}

fn begin_account_deletion_with_entropy(
    context: AccountOperationContext,
    proof: FreshAuthenticationProof,
    account: DestructiveAccountSnapshot,
    entropy: &mut impl EntropySource,
) -> Result<AccountDeletionChallenge, AuthError> {
    proof.consume(context, account.0)?;
    let transaction_id = fresh_transaction_id(entropy)?;
    let token =
        AccountDeletionToken::generate(entropy).map_err(|_| AuthError::EntropyUnavailable)?;
    let binding = context.binding(transaction_id, TransactionClass::AccountDeletion)?;
    Ok(AccountDeletionChallenge {
        transaction: AccountTransaction::new(
            binding,
            AccountDeletionState {
                account: account.0,
                token,
            },
        ),
    })
}

/// Newly sealed response plus the response count that must commit with it.
#[must_use = "the encrypted response and next response count must commit together"]
pub struct AccountResponseIntent {
    response: AccountServiceResponse,
    next_response_count: u64,
}

impl AccountResponseIntent {
    /// Borrows the exact response that all idempotent retries must replay.
    #[must_use]
    pub const fn response(&self) -> &AccountServiceResponse {
        &self.response
    }

    /// Returns the checked epoch-scoped response count to commit atomically.
    #[must_use]
    pub const fn next_response_count(&self) -> u64 {
        self.next_response_count
    }
}

/// Seals one response exactly once; callers persist and replay the returned bytes.
fn seal_account_response(
    plan: AccountResponsePlan,
    current_response_count: u64,
) -> Result<AccountResponseIntent, AuthError> {
    let AccountResponsePlan {
        lineage,
        transaction_id,
        payload,
    } = plan;
    let request_kind = lineage.binding().message_kind();
    if payload.transaction_id() != transaction_id || !payload.matches_request_kind(request_kind) {
        return Err(AuthError::ContextMismatch);
    }
    let plaintext = encode_response_plaintext(&payload)?;
    let sealed = lineage.seal_response(
        current_response_count,
        payload.response_kind(),
        plaintext.expose_for_hpke(),
    )?;
    let next_response_count = sealed.next_response_count();
    let response = AccountServiceResponse::from_sealed(sealed)?;
    Ok(AccountResponseIntent {
        response,
        next_response_count,
    })
}

fn fresh_transaction_id(entropy: &mut impl EntropySource) -> Result<TransactionId, AuthError> {
    TransactionId::generate(entropy).map_err(|_| AuthError::EntropyUnavailable)
}

fn fresh_opaque_credential_id(
    entropy: &mut impl EntropySource,
) -> Result<OpaqueCredentialId, AuthError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    entropy
        .fill_exact(bytes.as_mut())
        .map_err(|_| AuthError::EntropyUnavailable)?;
    Ok(OpaqueCredentialId::from_bytes(*bytes))
}

fn fresh_account_id(entropy: &mut impl EntropySource) -> Result<AccountId, AuthError> {
    AccountRandomId::generate(entropy)
        .map(AccountRandomId::to_account_id)
        .map_err(|_| AuthError::EntropyUnavailable)
}

fn validate_finish_lineage(
    start: AccountRequestBinding,
    finish: AccountRequestBinding,
) -> Result<(), AuthError> {
    let operation_matches = matches!(
        (start.message_kind(), finish.message_kind()),
        (
            agenc_ircd_types::AccountServiceMessageKind::AccountCreateStart,
            agenc_ircd_types::AccountServiceMessageKind::AccountCreateFinish
        ) | (
            agenc_ircd_types::AccountServiceMessageKind::OpaqueAuthStart,
            agenc_ircd_types::AccountServiceMessageKind::OpaqueAuthFinish
        ) | (
            agenc_ircd_types::AccountServiceMessageKind::CredentialChangeStart,
            agenc_ircd_types::AccountServiceMessageKind::CredentialChangeFinish
        )
    );
    if !operation_matches
        || start.network_id() != finish.network_id()
        || start.recovery_epoch() != finish.recovery_epoch()
        || start.recipient_key_id() != finish.recipient_key_id()
        || start.client_request_id() == finish.client_request_id()
    {
        return Err(AuthError::ContextMismatch);
    }
    Ok(())
}

fn rejected_creation_response(
    lineage: AccountRequestLineage,
    transaction_id: TransactionId,
) -> Result<AccountResponsePlan, AuthError> {
    AccountResponsePlan::new(
        lineage,
        transaction_id,
        AccountServiceResponsePayload::CreationCompletion(Completion::rejected(transaction_id)),
    )
}

fn rejected_authentication_response(
    lineage: AccountRequestLineage,
    transaction_id: TransactionId,
) -> Result<AccountResponsePlan, AuthError> {
    AccountResponsePlan::new(
        lineage,
        transaction_id,
        AccountServiceResponsePayload::AuthenticationCompletion(Completion::rejected(
            transaction_id,
        )),
    )
}

fn rejected_credential_change_response(
    lineage: AccountRequestLineage,
    transaction_id: TransactionId,
) -> Result<AccountResponsePlan, AuthError> {
    AccountResponsePlan::new(
        lineage,
        transaction_id,
        AccountServiceResponsePayload::CredentialChangeCompletion(Completion::rejected(
            transaction_id,
        )),
    )
}

/// Builds the response payload for one successful OPAQUE login.
#[must_use]
pub fn authentication_completion(
    transaction_id: TransactionId,
    grant: &AuthenticationGrant,
) -> AccountServiceResponsePayload {
    AccountServiceResponsePayload::AuthenticationCompletion(Completion::committed(
        transaction_id,
        grant.account_id(),
        grant.account_session_generation().get(),
    ))
}

fn duplicate_credential_id(credential_id: &OpaqueCredentialId) -> OpaqueCredentialId {
    OpaqueCredentialId::from_bytes(*credential_id.expose_for_account_service())
}

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::{
        AccountHpkePrivateKey, AccountRequestBinding, AccountResponseOpenToken, LoginIndexDigest,
        LoginIndexKey, OpaqueFakeCredentialKey, seal_account_request,
    };
    use agenc_ircd_types::{
        AccountRandomId, AccountServiceCompletionStatus, AccountServiceMessageKind, ConnectionId,
        EntropyError, EntropySource, Generation, MonotonicTick, NetworkId, NormalizedLogin,
        OpaqueCredentialId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation, TransactionId,
        UtcSecond,
    };

    use super::{
        AUTHENTICATION_TRANSACTION_RECORD_BYTES, AccountAuthenticationState,
        AccountCreationStartParameters, AccountCreationState, AccountOperationContext,
        AccountSnapshot, AuthError, AuthenticationCandidate, AuthenticationLookup,
        AuthenticationStartParameters, AuthenticationTransactionRecord,
        CREATION_TRANSACTION_RECORD_BYTES, CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES,
        CreationAdmission, CreationTransactionRecord, CredentialChangeStartParameters,
        CredentialChangeState, CredentialChangeTransactionRecord, DestructiveAccountSnapshot,
        FreshAuthenticationProof, StartDisposition, ValidatedInvitation,
        begin_account_creation_with_entropy, begin_account_deletion,
        begin_account_deletion_with_entropy, begin_authentication_with_entropy,
        begin_credential_change_with_entropy, create_authentication_grant,
        finish_account_authentication_with_entropy, finish_credential_change, fresh_account_id,
        fresh_opaque_credential_id, fresh_transaction_id,
    };
    use crate::opaque::{
        OpaqueKe1, OpaqueKe3, OpaqueProfile, OpaqueRegistrationRecord, OpaqueRegistrationRequest,
        OpaqueServerLoginState,
    };
    use crate::transaction::{
        AccountRouteBinding, AccountTransaction, AccountTransactionBinding, TransactionClass,
    };
    use crate::wire::{
        ACCOUNT_SERVICE_RESPONSE_BYTES, AccountRequestPayload, AccountServiceEnvelope,
        AccountServiceResponsePayload, AuthenticatedAccountRequest, AuthenticationFinish,
        AuthenticationStart, CreationStart, CredentialChangeFinish, CredentialChangeStart,
        OpenedAccountServiceRequest, encode_request_plaintext, open_and_parse_request,
        open_and_parse_response,
    };
    use agenc_ircd_types::{OriginId, Revision};

    const TEST_RECOVERY_EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([5_u8; 16]);
    const OPAQUE_VECTOR: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-data/vectors/stage-four-opaque-v1.vectors"
    ));

    struct FilledEntropy(u8);

    impl EntropySource for FilledEntropy {
        fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill_exact(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::Unavailable)
        }
    }

    fn context(now: u64) -> Result<AccountOperationContext, agenc_ircd_types::ValidationError> {
        context_for_network(NetworkId::from_bytes([1_u8; 32]), now)
    }

    fn context_for_network(
        network_id: NetworkId,
        now: u64,
    ) -> Result<AccountOperationContext, agenc_ircd_types::ValidationError> {
        let route = AccountRouteBinding::new(
            ServerId::from_bytes([6_u8; 16]),
            ServerIncarnation::from_bytes([7_u8; 16]),
            OriginId::from_bytes([2_u8; 16]),
            Generation::new(4)?,
            ConnectionId::from_bytes([3_u8; 16]),
            [8_u8; 32],
        );
        Ok(AccountOperationContext::new(
            network_id,
            route,
            MonotonicTick::from_ticks(now),
            UtcSecond::from_unix_seconds(now),
        ))
    }

    fn account() -> Result<DestructiveAccountSnapshot, agenc_ircd_types::ValidationError> {
        Ok(DestructiveAccountSnapshot::new(
            AccountRandomId::from_bytes([4_u8; 16]).to_account_id(),
            Revision::new(7)?,
            Generation::new(9)?,
        ))
    }

    fn fresh_proof(
        expires_at: u64,
    ) -> Result<FreshAuthenticationProof, agenc_ircd_types::ValidationError> {
        Ok(FreshAuthenticationProof {
            account: account()?.0,
            credential_id: OpaqueCredentialId::from_bytes([9_u8; 32]),
            network_id: context(0)?.network_id,
            route: context(0)?.route,
            expires_at: MonotonicTick::from_ticks(expires_at),
        })
    }

    #[derive(Clone, Copy)]
    enum CredentialStartRejectionCase {
        RequestedAccount,
        OperationUnavailable,
        ProofNetwork,
        ProofAccount,
        ProofEdge,
        ProofIncarnation,
        ProofOrigin,
        ProofOriginGeneration,
        ProofConnection,
        ProofConnectionNonce,
        ProofRevision,
        ProofGeneration,
        ProofCredential,
        ProofExpired,
    }

    impl CredentialStartRejectionCase {
        const ALL: [Self; 14] = [
            Self::RequestedAccount,
            Self::OperationUnavailable,
            Self::ProofNetwork,
            Self::ProofAccount,
            Self::ProofEdge,
            Self::ProofIncarnation,
            Self::ProofOrigin,
            Self::ProofOriginGeneration,
            Self::ProofConnection,
            Self::ProofConnectionNonce,
            Self::ProofRevision,
            Self::ProofGeneration,
            Self::ProofCredential,
            Self::ProofExpired,
        ];

        fn inputs(
            self,
            snapshot: AccountSnapshot,
            operation: AccountOperationContext,
            other_account_id: agenc_ircd_types::AccountId,
        ) -> Result<CredentialRejectionInputs, agenc_ircd_types::ValidationError> {
            let mut proof = FreshAuthenticationProof {
                account: snapshot,
                credential_id: OpaqueCredentialId::from_bytes([40_u8; 32]),
                network_id: operation.network_id,
                route: operation.route,
                expires_at: MonotonicTick::from_ticks(20),
            };
            let mut requested_account = snapshot.account_id;
            let mut operation_is_available = true;
            let expected_error = match self {
                Self::RequestedAccount => {
                    requested_account = other_account_id;
                    AuthError::ContextMismatch
                }
                Self::OperationUnavailable => {
                    operation_is_available = false;
                    AuthError::WrongState
                }
                Self::ProofNetwork => {
                    proof.network_id = NetworkId::from_bytes([42_u8; 32]);
                    AuthError::ContextMismatch
                }
                Self::ProofAccount => {
                    proof.account.account_id = other_account_id;
                    AuthError::ContextMismatch
                }
                Self::ProofEdge => {
                    proof.route = AccountRouteBinding::new(
                        ServerId::from_bytes([43_u8; 16]),
                        proof.route.edge_incarnation(),
                        proof.route.origin_id(),
                        proof.route.origin_generation(),
                        proof.route.connection_id(),
                        *proof.route.connection_nonce(),
                    );
                    AuthError::ContextMismatch
                }
                Self::ProofIncarnation => {
                    proof.route = AccountRouteBinding::new(
                        proof.route.edge_server_id(),
                        ServerIncarnation::from_bytes([43_u8; 16]),
                        proof.route.origin_id(),
                        proof.route.origin_generation(),
                        proof.route.connection_id(),
                        *proof.route.connection_nonce(),
                    );
                    AuthError::ContextMismatch
                }
                Self::ProofOrigin => {
                    proof.route = AccountRouteBinding::new(
                        proof.route.edge_server_id(),
                        proof.route.edge_incarnation(),
                        OriginId::from_bytes([43_u8; 16]),
                        proof.route.origin_generation(),
                        proof.route.connection_id(),
                        *proof.route.connection_nonce(),
                    );
                    AuthError::WrongOrigin
                }
                Self::ProofOriginGeneration => {
                    proof.route = AccountRouteBinding::new(
                        proof.route.edge_server_id(),
                        proof.route.edge_incarnation(),
                        proof.route.origin_id(),
                        Generation::new(43)?,
                        proof.route.connection_id(),
                        *proof.route.connection_nonce(),
                    );
                    AuthError::WrongOrigin
                }
                Self::ProofConnection => {
                    proof.route = AccountRouteBinding::new(
                        proof.route.edge_server_id(),
                        proof.route.edge_incarnation(),
                        proof.route.origin_id(),
                        proof.route.origin_generation(),
                        ConnectionId::from_bytes([44_u8; 16]),
                        *proof.route.connection_nonce(),
                    );
                    AuthError::WrongConnection
                }
                Self::ProofConnectionNonce => {
                    proof.route = AccountRouteBinding::new(
                        proof.route.edge_server_id(),
                        proof.route.edge_incarnation(),
                        proof.route.origin_id(),
                        proof.route.origin_generation(),
                        proof.route.connection_id(),
                        [44_u8; 32],
                    );
                    AuthError::WrongConnection
                }
                Self::ProofRevision => {
                    proof.account.account_revision = Revision::new(8)?;
                    AuthError::WrongState
                }
                Self::ProofGeneration => {
                    proof.account.account_session_generation = Generation::new(10)?;
                    AuthError::WrongState
                }
                Self::ProofCredential => {
                    proof.credential_id = OpaqueCredentialId::from_bytes([41_u8; 32]);
                    AuthError::WrongState
                }
                Self::ProofExpired => {
                    proof.expires_at = MonotonicTick::from_ticks(9);
                    AuthError::Expired
                }
            };
            Ok((
                proof,
                requested_account,
                operation_is_available,
                expected_error,
            ))
        }
    }

    type CredentialRejectionInputs = (
        FreshAuthenticationProof,
        agenc_ircd_types::AccountId,
        bool,
        AuthError,
    );

    fn decode_nibble(byte: u8) -> Result<u8, AuthError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(AuthError::InvalidEncoding),
        }
    }

    fn vector_bytes<const N: usize>(name: &str) -> Result<[u8; N], AuthError> {
        let field = OPAQUE_VECTOR
            .trim()
            .split('|')
            .find_map(|field| {
                field
                    .strip_prefix(name)
                    .and_then(|value| value.strip_prefix('='))
            })
            .ok_or(AuthError::InvalidEncoding)?;
        if field.len() != N.checked_mul(2).ok_or(AuthError::Overflow)? {
            return Err(AuthError::InvalidEncoding);
        }
        let mut output = [0_u8; N];
        for (index, slot) in output.iter_mut().enumerate() {
            let offset = index.checked_mul(2).ok_or(AuthError::Overflow)?;
            let high = *field
                .as_bytes()
                .get(offset)
                .ok_or(AuthError::InvalidEncoding)?;
            let low = *field
                .as_bytes()
                .get(offset + 1)
                .ok_or(AuthError::InvalidEncoding)?;
            *slot = (decode_nibble(high)? << 4) | decode_nibble(low)?;
        }
        Ok(output)
    }

    fn open_request(
        request_id: u8,
        payload: AccountRequestPayload,
    ) -> Result<OpenedAccountServiceRequest, Box<dyn core::error::Error>> {
        open_request_for_network(context(0)?.network_id, request_id, payload)
    }

    fn open_request_for_network(
        network_id: NetworkId,
        request_id: u8,
        payload: AccountRequestPayload,
    ) -> Result<OpenedAccountServiceRequest, Box<dyn core::error::Error>> {
        let (request, _response_token) =
            open_request_for_network_with_token(network_id, request_id, payload)?;
        Ok(request)
    }

    fn open_request_with_token(
        request_id: u8,
        payload: AccountRequestPayload,
    ) -> Result<(OpenedAccountServiceRequest, AccountResponseOpenToken), Box<dyn core::error::Error>>
    {
        open_request_for_network_with_token(context(0)?.network_id, request_id, payload)
    }

    fn open_request_for_network_with_token(
        network_id: NetworkId,
        request_id: u8,
        payload: AccountRequestPayload,
    ) -> Result<(OpenedAccountServiceRequest, AccountResponseOpenToken), Box<dyn core::error::Error>>
    {
        let private_key = AccountHpkePrivateKey::from_bytes([6_u8; 32])?;
        let public_key = private_key.public_key()?;
        let message_kind = payload.message_kind();
        let binding = AccountRequestBinding::new(
            network_id,
            TEST_RECOVERY_EPOCH,
            public_key.key_id(),
            RequestId::from_bytes([request_id; 16]),
            message_kind,
        );
        let plaintext = encode_request_plaintext(&payload)?;
        let (sealed, response_token) =
            seal_account_request(public_key, binding, plaintext.expose_for_hpke())?;
        let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
        let request = open_and_parse_request(
            &private_key,
            TEST_RECOVERY_EPOCH,
            network_id,
            message_kind,
            &envelope,
        )?;
        Ok((request, response_token))
    }

    fn credential_start_request(
        request_id: u8,
        account_id: agenc_ircd_types::AccountId,
    ) -> Result<AuthenticatedAccountRequest<CredentialChangeStart>, Box<dyn core::error::Error>>
    {
        let payload = CredentialChangeStart {
            network_id: context(0)?.network_id,
            account_id,
            registration_request: OpaqueRegistrationRequest::from_bytes(vector_bytes(
                "registration_request",
            )?)?,
        };
        match open_request(
            request_id,
            AccountRequestPayload::CredentialChangeStart(payload),
        )? {
            OpenedAccountServiceRequest::CredentialChangeStart(request) => Ok(request),
            _ => Err("opened request kind changed".into()),
        }
    }

    fn creation_start_request(
        request_id: u8,
    ) -> Result<AuthenticatedAccountRequest<CreationStart>, Box<dyn core::error::Error>> {
        let payload = CreationStart {
            network_id: context(0)?.network_id,
            login: NormalizedLogin::prepare("entropy-user")?,
            registration_request: OpaqueRegistrationRequest::from_bytes(vector_bytes(
                "registration_request",
            )?)?,
            invitation: None,
        };
        match open_request(request_id, AccountRequestPayload::CreationStart(payload))? {
            OpenedAccountServiceRequest::CreationStart(request) => Ok(request),
            _ => Err("opened request kind changed".into()),
        }
    }

    fn authentication_start_request(
        request_id: u8,
    ) -> Result<AuthenticatedAccountRequest<AuthenticationStart>, Box<dyn core::error::Error>> {
        let payload = AuthenticationStart {
            network_id: context(0)?.network_id,
            login: NormalizedLogin::prepare("entropy-user")?,
            ke1: OpaqueKe1::from_bytes(vector_bytes("ke1")?)?,
        };
        match open_request(
            request_id,
            AccountRequestPayload::AuthenticationStart(payload),
        )? {
            OpenedAccountServiceRequest::AuthenticationStart(request) => Ok(request),
            _ => Err("opened request kind changed".into()),
        }
    }

    fn authentication_finish_request(
        network_id: NetworkId,
        request_id: u8,
        transaction_id: TransactionId,
    ) -> Result<AuthenticatedAccountRequest<AuthenticationFinish>, Box<dyn core::error::Error>>
    {
        let payload = AuthenticationFinish {
            network_id,
            transaction_id,
            ke3: OpaqueKe3::from_bytes(vector_bytes("ke3")?)?,
        };
        match open_request_for_network(
            network_id,
            request_id,
            AccountRequestPayload::AuthenticationFinish(payload),
        )? {
            OpenedAccountServiceRequest::AuthenticationFinish(request) => Ok(request),
            _ => Err("opened request kind changed".into()),
        }
    }

    fn credential_finish_request(
        request_id: u8,
        transaction_id: TransactionId,
    ) -> Result<AuthenticatedAccountRequest<CredentialChangeFinish>, Box<dyn core::error::Error>>
    {
        let payload = CredentialChangeFinish {
            network_id: context(0)?.network_id,
            transaction_id,
            registration_record: OpaqueRegistrationRecord::from_bytes(vector_bytes(
                "registration_record",
            )?)?,
        };
        match open_request(
            request_id,
            AccountRequestPayload::CredentialChangeFinish(payload),
        )? {
            OpenedAccountServiceRequest::CredentialChangeFinish(request) => Ok(request),
            _ => Err("opened request kind changed".into()),
        }
    }

    fn assert_rejected_credential_start(
        profile: &OpaqueProfile,
        request_id: u8,
        proof: Option<FreshAuthenticationProof>,
        account: DestructiveAccountSnapshot,
        requested_account: agenc_ircd_types::AccountId,
        operation_is_available: bool,
        expected_error: AuthError,
    ) -> Result<(), Box<dyn core::error::Error>> {
        let start_payload = CredentialChangeStart {
            network_id: context(0)?.network_id,
            account_id: requested_account,
            registration_request: OpaqueRegistrationRequest::from_bytes(vector_bytes(
                "registration_request",
            )?)?,
        };
        let (start_request, challenge_token) = open_request_with_token(
            request_id,
            AccountRequestPayload::CredentialChangeStart(start_payload),
        )?;
        let OpenedAccountServiceRequest::CredentialChangeStart(start_request) = start_request
        else {
            return Err("opened request kind changed".into());
        };
        let mut entropy = FilledEntropy(request_id);
        let start = begin_credential_change_with_entropy(
            profile,
            CredentialChangeStartParameters {
                context: context(10)?,
                proof,
                account,
                credential_id: OpaqueCredentialId::from_bytes([40_u8; 32]),
                request: start_request,
                operation_is_available,
            },
            &mut entropy,
        )?;
        let transaction_id = start.transaction_id();
        let start = start.seal(0)?;
        assert_eq!(
            start.response_intent().response().as_bytes().len(),
            ACCOUNT_SERVICE_RESPONSE_BYTES
        );
        assert!(matches!(
            open_and_parse_response(challenge_token, start.response_intent().response())?,
            AccountServiceResponsePayload::CredentialChangeChallenge {
                transaction_id: found,
                ..
            } if found == transaction_id
        ));

        let finish_payload = CredentialChangeFinish {
            network_id: context(0)?.network_id,
            transaction_id,
            registration_record: OpaqueRegistrationRecord::from_bytes(vector_bytes(
                "registration_record",
            )?)?,
        };
        let (finish_request, completion_token) = open_request_with_token(
            request_id.wrapping_add(1),
            AccountRequestPayload::CredentialChangeFinish(finish_payload),
        )?;
        let OpenedAccountServiceRequest::CredentialChangeFinish(finish_request) = finish_request
        else {
            return Err("opened request kind changed".into());
        };
        let mut transaction = start.into_transaction_after_commit(1)?;
        let outcome = finish_credential_change(&mut transaction, context(11)?, finish_request)?;
        assert_eq!(outcome.result().err(), Some(expected_error));
        let outcome = outcome.seal(1)?;
        assert_eq!(
            outcome.response_intent().response().as_bytes().len(),
            ACCOUNT_SERVICE_RESPONSE_BYTES
        );
        assert!(matches!(
            open_and_parse_response(completion_token, outcome.response_intent().response())?,
            AccountServiceResponsePayload::CredentialChangeCompletion(completion)
                if completion.status() == AccountServiceCompletionStatus::Rejected
                    && completion.transaction_id() == transaction_id
        ));
        Ok(())
    }

    #[test]
    fn fresh_identifiers_use_exact_injected_entropy_and_fail_closed() {
        let mut zero = FilledEntropy(0);
        assert_eq!(
            fresh_transaction_id(&mut zero).map(|identifier| *identifier.as_bytes()),
            Ok([0_u8; 16])
        );
        let mut zero = FilledEntropy(0);
        assert_eq!(
            fresh_opaque_credential_id(&mut zero)
                .map(|identifier| *identifier.expose_for_account_service()),
            Ok([0_u8; 32])
        );
        let mut zero = FilledEntropy(0);
        assert_eq!(
            fresh_account_id(&mut zero),
            Ok(AccountRandomId::from_bytes([0_u8; 16]).to_account_id())
        );

        assert_eq!(
            fresh_transaction_id(&mut FailingEntropy),
            Err(AuthError::EntropyUnavailable)
        );
        assert_eq!(
            fresh_opaque_credential_id(&mut FailingEntropy).err(),
            Some(AuthError::EntropyUnavailable)
        );
        assert_eq!(
            fresh_account_id(&mut FailingEntropy),
            Err(AuthError::EntropyUnavailable)
        );
    }

    #[test]
    fn every_start_path_propagates_entropy_failure_without_a_response()
    -> Result<(), Box<dyn core::error::Error>> {
        let profile = OpaqueProfile::generate(context(0)?.network_id)?;
        let login_key = LoginIndexKey::from_bytes([7_u8; 32]);
        let fake_key = OpaqueFakeCredentialKey::from_bytes([8_u8; 32]);
        let creation = AccountCreationStartParameters {
            context: context(10)?,
            request: creation_start_request(20)?,
            admission: CreationAdmission::Open,
            login_is_available: true,
            invitation_is_available: true,
        };
        assert_eq!(
            begin_account_creation_with_entropy(
                &profile,
                &login_key,
                creation,
                &mut FailingEntropy,
            )
            .err(),
            Some(AuthError::EntropyUnavailable)
        );

        let authentication = AuthenticationStartParameters {
            context: context(10)?,
            request: authentication_start_request(21)?,
            lookup: AuthenticationLookup::Unknown,
        };
        assert_eq!(
            begin_authentication_with_entropy(
                &profile,
                &login_key,
                &fake_key,
                authentication,
                &mut FailingEntropy,
            )
            .err(),
            Some(AuthError::EntropyUnavailable)
        );

        let destructive_account = account()?;
        let credential_change = CredentialChangeStartParameters {
            context: context(10)?,
            proof: Some(fresh_proof(20)?),
            account: destructive_account,
            credential_id: OpaqueCredentialId::from_bytes([9_u8; 32]),
            request: credential_start_request(22, destructive_account.0.account_id)?,
            operation_is_available: true,
        };
        assert_eq!(
            begin_credential_change_with_entropy(&profile, credential_change, &mut FailingEntropy,)
                .err(),
            Some(AuthError::EntropyUnavailable)
        );
        assert_eq!(
            begin_account_deletion_with_entropy(
                context(10)?,
                fresh_proof(20)?,
                destructive_account,
                &mut FailingEntropy,
            )
            .err(),
            Some(AuthError::EntropyUnavailable)
        );
        Ok(())
    }

    #[test]
    fn authentication_finish_entropy_failure_emits_no_completion()
    -> Result<(), Box<dyn core::error::Error>> {
        let network_id = NetworkId::from_bytes(vector_bytes("network")?);
        let context = context_for_network(network_id, 11)?;
        let transaction_id = TransactionId::from_bytes([25_u8; 16]);
        let private_key = AccountHpkePrivateKey::from_bytes([6_u8; 32])?;
        let start_request_binding = AccountRequestBinding::new(
            network_id,
            TEST_RECOVERY_EPOCH,
            private_key.public_key()?.key_id(),
            RequestId::from_bytes([25_u8; 16]),
            AccountServiceMessageKind::OpaqueAuthStart,
        );
        let transaction_binding = AccountTransactionBinding::new(
            transaction_id,
            TransactionClass::Authentication,
            network_id,
            context.route,
            MonotonicTick::from_ticks(10),
        )?;
        let state = AccountAuthenticationState {
            start_request_binding,
            candidate: AuthenticationCandidate::Known(account()?.0),
            credential_id: OpaqueCredentialId::from_bytes(vector_bytes("credential_id")?),
            server_state: OpaqueServerLoginState::from_persisted_bytes(vector_bytes(
                "server_login_state",
            )?)?,
        };
        let mut transaction = AccountTransaction::new(transaction_binding, state);
        let finish = authentication_finish_request(network_id, 26, transaction_id)?;
        assert_eq!(
            finish_account_authentication_with_entropy(
                &mut transaction,
                context,
                finish,
                &mut FailingEntropy,
            )
            .err(),
            Some(AuthError::EntropyUnavailable)
        );
        Ok(())
    }

    #[test]
    fn authentication_transaction_record_round_trips_without_login_plaintext()
    -> Result<(), Box<dyn core::error::Error>> {
        let network_id = NetworkId::from_bytes(vector_bytes("network")?);
        let operation = context_for_network(network_id, 100)?;
        let transaction_id = TransactionId::from_bytes([41_u8; 16]);
        let private_key = AccountHpkePrivateKey::from_bytes([6_u8; 32])?;
        let start_request_binding = AccountRequestBinding::new(
            network_id,
            TEST_RECOVERY_EPOCH,
            private_key.public_key()?.key_id(),
            RequestId::from_bytes([42_u8; 16]),
            AccountServiceMessageKind::OpaqueAuthStart,
        );
        let transaction_binding = AccountTransactionBinding::new(
            transaction_id,
            TransactionClass::Authentication,
            network_id,
            operation.route,
            operation.now,
        )?;
        let expected_account = account()?.0;
        let state = AccountAuthenticationState {
            start_request_binding,
            candidate: AuthenticationCandidate::Known(expected_account),
            credential_id: OpaqueCredentialId::from_bytes(vector_bytes("credential_id")?),
            server_state: OpaqueServerLoginState::from_persisted_bytes(vector_bytes(
                "server_login_state",
            )?)?,
        };
        let transaction = AccountTransaction::new(transaction_binding, state);
        let record = AuthenticationTransactionRecord::capture(
            &transaction,
            MonotonicTick::from_ticks(1_100),
            UtcSecond::from_unix_seconds(500),
        )?;
        assert_eq!(
            record.expose_for_persistence().len(),
            AUTHENTICATION_TRANSACTION_RECORD_BYTES
        );
        assert_eq!(
            record.durable_expires_at_utc()?,
            UtcSecond::from_unix_seconds(529)
        );
        assert!(
            !record
                .expose_for_persistence()
                .windows("entropy-user".len())
                .any(|window| window == b"entropy-user")
        );

        let restored = AuthenticationTransactionRecord::parse(record.expose_for_persistence())?
            .restore(
                MonotonicTick::from_ticks(2_000),
                UtcSecond::from_unix_seconds(501),
            )?;
        let restored_binding = restored.binding();
        assert_eq!(restored_binding.transaction_id(), transaction_id);
        assert_eq!(restored_binding.network_id(), network_id);
        assert_eq!(
            restored_binding.expires_at(),
            MonotonicTick::from_ticks(30_000)
        );
        restored_binding.route().validate_match(operation.route)?;
        let restored_state = restored.state_ref().ok_or(AuthError::Consumed)?;
        assert_eq!(restored_state.start_request_binding, start_request_binding);
        let AuthenticationCandidate::Known(restored_account) = restored_state.candidate else {
            return Err("restored known account became a rejection candidate".into());
        };
        assert_eq!(restored_account, expected_account);
        assert_eq!(
            restored_state.credential_id.expose_for_account_service(),
            vector_bytes::<32>("credential_id")?.as_slice()
        );
        assert_eq!(
            restored_state.server_state.expose_for_persistence(),
            vector_bytes::<128>("server_login_state")?.as_slice()
        );
        Ok(())
    }

    #[test]
    fn authentication_transaction_record_rejects_expiry_and_corruption()
    -> Result<(), Box<dyn core::error::Error>> {
        let network_id = NetworkId::from_bytes(vector_bytes("network")?);
        let operation = context_for_network(network_id, 100)?;
        let transaction_id = TransactionId::from_bytes([51_u8; 16]);
        let private_key = AccountHpkePrivateKey::from_bytes([6_u8; 32])?;
        let state = AccountAuthenticationState {
            start_request_binding: AccountRequestBinding::new(
                network_id,
                TEST_RECOVERY_EPOCH,
                private_key.public_key()?.key_id(),
                RequestId::from_bytes([52_u8; 16]),
                AccountServiceMessageKind::OpaqueAuthStart,
            ),
            candidate: AuthenticationCandidate::RejectAtFinish,
            credential_id: OpaqueCredentialId::from_bytes(vector_bytes("credential_id")?),
            server_state: OpaqueServerLoginState::from_persisted_bytes(vector_bytes(
                "fake_server_login_state",
            )?)?,
        };
        let binding = AccountTransactionBinding::new(
            transaction_id,
            TransactionClass::Authentication,
            network_id,
            operation.route,
            operation.now,
        )?;
        let transaction = AccountTransaction::new(binding, state);
        let record = AuthenticationTransactionRecord::capture(
            &transaction,
            MonotonicTick::from_ticks(1_100),
            UtcSecond::from_unix_seconds(700),
        )?;
        assert_eq!(
            AuthenticationTransactionRecord::parse(record.expose_for_persistence())?
                .restore(
                    MonotonicTick::from_ticks(0),
                    UtcSecond::from_unix_seconds(729),
                )
                .err(),
            Some(AuthError::Expired)
        );
        assert_eq!(
            AuthenticationTransactionRecord::parse(
                &record.expose_for_persistence()[..AUTHENTICATION_TRANSACTION_RECORD_BYTES - 1],
            )
            .err(),
            Some(AuthError::InvalidEncoding)
        );

        let mut corrupted = *record.expose_for_persistence();
        corrupted[0] ^= 1;
        assert_eq!(
            AuthenticationTransactionRecord::parse(&corrupted)?
                .restore(
                    MonotonicTick::from_ticks(0),
                    UtcSecond::from_unix_seconds(701),
                )
                .err(),
            Some(AuthError::InvalidEncoding)
        );
        let candidate_tag_offset = 262;
        let mut corrupted = *record.expose_for_persistence();
        *corrupted
            .get_mut(candidate_tag_offset)
            .ok_or("candidate-tag fixture offset is out of bounds")? = 9;
        assert_eq!(
            AuthenticationTransactionRecord::parse(&corrupted)?
                .restore(
                    MonotonicTick::from_ticks(0),
                    UtcSecond::from_unix_seconds(701),
                )
                .err(),
            Some(AuthError::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn creation_transaction_record_round_trips_private_reservations()
    -> Result<(), Box<dyn core::error::Error>> {
        let network_id = NetworkId::from_bytes(vector_bytes("network")?);
        let operation = context_for_network(network_id, 100)?;
        let transaction_id = TransactionId::from_bytes([61_u8; 16]);
        let private_key = AccountHpkePrivateKey::from_bytes([6_u8; 32])?;
        let start_request_binding = AccountRequestBinding::new(
            network_id,
            TEST_RECOVERY_EPOCH,
            private_key.public_key()?.key_id(),
            RequestId::from_bytes([62_u8; 16]),
            AccountServiceMessageKind::AccountCreateStart,
        );
        let login_digest = [63_u8; 32];
        let credential_id = [64_u8; 32];
        let invite_id = agenc_ircd_types::InviteId::from_bytes([65_u8; 16]);
        let binding = AccountTransactionBinding::new(
            transaction_id,
            TransactionClass::AccountCreation,
            network_id,
            operation.route,
            operation.now,
        )?;
        let transaction = AccountTransaction::new(
            binding,
            AccountCreationState {
                start_request_binding,
                disposition: StartDisposition::RejectAtFinish(AuthError::InvitationRejected),
                login_digest: LoginIndexDigest::from_storage_key(login_digest),
                credential_id: OpaqueCredentialId::from_bytes(credential_id),
                invitation: Some(ValidatedInvitation {
                    invite_id,
                    expires_at: UtcSecond::from_unix_seconds(900),
                }),
            },
        );
        let record = CreationTransactionRecord::capture(
            &transaction,
            MonotonicTick::from_ticks(1_100),
            UtcSecond::from_unix_seconds(500),
        )?;
        assert_eq!(
            record.expose_for_persistence().len(),
            CREATION_TRANSACTION_RECORD_BYTES
        );
        assert_eq!(
            record.durable_expires_at_utc()?,
            UtcSecond::from_unix_seconds(559)
        );
        assert!(
            !record
                .expose_for_persistence()
                .windows("entropy-user".len())
                .any(|window| window == b"entropy-user")
        );

        let restored = CreationTransactionRecord::parse(record.expose_for_persistence())?.restore(
            MonotonicTick::from_ticks(2_000),
            UtcSecond::from_unix_seconds(501),
        )?;
        assert_eq!(restored.binding().transaction_id(), transaction_id);
        assert_eq!(
            restored.binding().expires_at(),
            MonotonicTick::from_ticks(60_000)
        );
        let state = restored.state_ref().ok_or(AuthError::Consumed)?;
        assert_eq!(state.start_request_binding, start_request_binding);
        assert!(matches!(
            state.disposition,
            StartDisposition::RejectAtFinish(AuthError::InvitationRejected)
        ));
        assert_eq!(state.login_digest.expose_for_storage_key(), &login_digest);
        assert_eq!(
            state.credential_id.expose_for_account_service(),
            &credential_id
        );
        let invitation = state.invitation.as_ref().ok_or("invitation was lost")?;
        assert_eq!(invitation.invite_id, invite_id);
        assert_eq!(invitation.expires_at, UtcSecond::from_unix_seconds(900));
        Ok(())
    }

    #[test]
    fn credential_transaction_record_round_trips_consumed_proof_result()
    -> Result<(), Box<dyn core::error::Error>> {
        let network_id = NetworkId::from_bytes(vector_bytes("network")?);
        let operation = context_for_network(network_id, 100)?;
        let transaction_id = TransactionId::from_bytes([71_u8; 16]);
        let private_key = AccountHpkePrivateKey::from_bytes([6_u8; 32])?;
        let start_request_binding = AccountRequestBinding::new(
            network_id,
            TEST_RECOVERY_EPOCH,
            private_key.public_key()?.key_id(),
            RequestId::from_bytes([72_u8; 16]),
            AccountServiceMessageKind::CredentialChangeStart,
        );
        let account = account()?.0;
        let credential_id = [73_u8; 32];
        let binding = AccountTransactionBinding::new(
            transaction_id,
            TransactionClass::CredentialChange,
            network_id,
            operation.route,
            operation.now,
        )?;
        let transaction = AccountTransaction::new(
            binding,
            CredentialChangeState {
                start_request_binding,
                disposition: StartDisposition::RejectAtFinish(AuthError::WrongOrigin),
                account,
                credential_id: OpaqueCredentialId::from_bytes(credential_id),
            },
        );
        let record = CredentialChangeTransactionRecord::capture(
            &transaction,
            MonotonicTick::from_ticks(1_100),
            UtcSecond::from_unix_seconds(700),
        )?;
        assert_eq!(
            record.expose_for_persistence().len(),
            CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES
        );
        assert_eq!(
            record.durable_expires_at_utc()?,
            UtcSecond::from_unix_seconds(759)
        );

        let restored = CredentialChangeTransactionRecord::parse(record.expose_for_persistence())?
            .restore(
            MonotonicTick::from_ticks(3_000),
            UtcSecond::from_unix_seconds(702),
        )?;
        assert_eq!(restored.binding().transaction_id(), transaction_id);
        assert_eq!(
            restored.binding().expires_at(),
            MonotonicTick::from_ticks(60_000)
        );
        let state = restored.state_ref().ok_or(AuthError::Consumed)?;
        assert_eq!(state.start_request_binding, start_request_binding);
        assert!(matches!(
            state.disposition,
            StartDisposition::RejectAtFinish(AuthError::WrongOrigin)
        ));
        assert_eq!(state.account, account);
        assert_eq!(
            state.credential_id.expose_for_account_service(),
            &credential_id
        );
        Ok(())
    }

    #[test]
    fn durable_transaction_records_reject_expiry_truncation_and_bad_tags()
    -> Result<(), Box<dyn core::error::Error>> {
        let operation = context(100)?;
        let private_key = AccountHpkePrivateKey::from_bytes([6_u8; 32])?;
        let binding = AccountTransactionBinding::new(
            TransactionId::from_bytes([81_u8; 16]),
            TransactionClass::AccountCreation,
            operation.network_id,
            operation.route,
            operation.now,
        )?;
        let transaction = AccountTransaction::new(
            binding,
            AccountCreationState {
                start_request_binding: AccountRequestBinding::new(
                    operation.network_id,
                    TEST_RECOVERY_EPOCH,
                    private_key.public_key()?.key_id(),
                    RequestId::from_bytes([82_u8; 16]),
                    AccountServiceMessageKind::AccountCreateStart,
                ),
                disposition: StartDisposition::SuccessCandidate,
                login_digest: LoginIndexDigest::from_storage_key([83_u8; 32]),
                credential_id: OpaqueCredentialId::from_bytes([84_u8; 32]),
                invitation: None,
            },
        );
        let record = CreationTransactionRecord::capture(
            &transaction,
            MonotonicTick::from_ticks(1_100),
            UtcSecond::from_unix_seconds(800),
        )?;
        assert_eq!(
            CreationTransactionRecord::parse(record.expose_for_persistence())?
                .restore(
                    MonotonicTick::from_ticks(0),
                    UtcSecond::from_unix_seconds(859),
                )
                .err(),
            Some(AuthError::Expired)
        );
        assert_eq!(
            CreationTransactionRecord::parse(
                &record.expose_for_persistence()[..CREATION_TRANSACTION_RECORD_BYTES - 1]
            )
            .err(),
            Some(AuthError::InvalidEncoding)
        );

        let disposition_offset = 262;
        let mut corrupted = *record.expose_for_persistence();
        corrupted
            .get_mut(disposition_offset..disposition_offset + 2)
            .ok_or("disposition fixture offset is out of bounds")?
            .copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            CreationTransactionRecord::parse(&corrupted)?
                .restore(
                    MonotonicTick::from_ticks(0),
                    UtcSecond::from_unix_seconds(801),
                )
                .err(),
            Some(AuthError::InvalidEncoding)
        );

        let invitation_tag_offset = 328;
        let mut corrupted = *record.expose_for_persistence();
        *corrupted
            .get_mut(invitation_tag_offset)
            .ok_or("invitation fixture offset is out of bounds")? = 2;
        assert_eq!(
            CreationTransactionRecord::parse(&corrupted)?
                .restore(
                    MonotonicTick::from_ticks(0),
                    UtcSecond::from_unix_seconds(801),
                )
                .err(),
            Some(AuthError::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn authentication_grant_deadlines_fail_closed_on_overflow()
    -> Result<(), Box<dyn core::error::Error>> {
        let account = account()?.0;
        let base = context(0)?;
        let mut entropy = FilledEntropy(30);
        let monotonic_overflow = AccountOperationContext {
            now: MonotonicTick::from_ticks(u64::MAX),
            ..base
        };
        assert_eq!(
            create_authentication_grant(
                account,
                OpaqueCredentialId::from_bytes([9_u8; 32]),
                monotonic_overflow,
                &mut entropy,
            )
            .err(),
            Some(AuthError::Overflow)
        );
        let utc_overflow = AccountOperationContext {
            now_utc: UtcSecond::from_unix_seconds(u64::MAX),
            ..base
        };
        assert_eq!(
            create_authentication_grant(
                account,
                OpaqueCredentialId::from_bytes([9_u8; 32]),
                utc_overflow,
                &mut entropy,
            )
            .err(),
            Some(AuthError::Overflow)
        );
        let grant = create_authentication_grant(
            account,
            OpaqueCredentialId::from_bytes([9_u8; 32]),
            context(100)?,
            &mut entropy,
        )?;
        assert_eq!(grant.grant_id.expose_for_session_open(), &[30_u8; 32]);
        assert_eq!(grant.route.connection_nonce(), &[8_u8; 32]);
        Ok(())
    }

    #[test]
    fn credential_replacement_reuses_identity_and_fences_generation()
    -> Result<(), Box<dyn core::error::Error>> {
        let profile = OpaqueProfile::generate(context(0)?.network_id)?;
        let destructive_account = account()?;
        let credential_bytes = [10_u8; 32];
        let mut entropy = FilledEntropy(11);
        let start = begin_credential_change_with_entropy(
            &profile,
            CredentialChangeStartParameters {
                context: context(10)?,
                proof: Some(FreshAuthenticationProof {
                    account: destructive_account.0,
                    credential_id: OpaqueCredentialId::from_bytes(credential_bytes),
                    network_id: context(0)?.network_id,
                    route: context(0)?.route,
                    expires_at: MonotonicTick::from_ticks(20),
                }),
                account: destructive_account,
                credential_id: OpaqueCredentialId::from_bytes(credential_bytes),
                request: credential_start_request(23, destructive_account.0.account_id)?,
                operation_is_available: true,
            },
            &mut entropy,
        )?;
        assert_eq!(start.transaction_id().as_bytes(), &[11_u8; 16]);
        assert!(matches!(
            start.response_plan().payload(),
            AccountServiceResponsePayload::CredentialChangeChallenge { credential_id, .. }
                if credential_id.expose_for_account_service() == &credential_bytes
        ));
        let transaction_id = start.transaction_id();
        let mut transaction = start.seal(0)?.into_transaction_after_commit(1)?;
        let outcome = finish_credential_change(
            &mut transaction,
            context(11)?,
            credential_finish_request(24, transaction_id)?,
        )?;
        let intent = outcome.result()?;
        assert_eq!(intent.account_id(), destructive_account.0.account_id);
        assert_eq!(intent.expected_account_revision(), Revision::new(7)?);
        assert_eq!(
            intent.next_account_session_generation(),
            Generation::new(10)?
        );
        assert_eq!(
            intent.credential_id().expose_for_account_service(),
            &credential_bytes
        );
        let sealed = outcome.seal(1)?;
        assert!(sealed.result().is_ok());
        Ok(())
    }

    #[test]
    fn credential_generation_overflow_consumes_without_response_authority()
    -> Result<(), Box<dyn core::error::Error>> {
        let profile = OpaqueProfile::generate(context(0)?.network_id)?;
        let operation = context(10)?;
        let account = DestructiveAccountSnapshot::new(
            AccountRandomId::from_bytes([4_u8; 16]).to_account_id(),
            Revision::new(7)?,
            Generation::new(u64::MAX)?,
        );
        let proof = FreshAuthenticationProof {
            account: account.0,
            credential_id: OpaqueCredentialId::from_bytes([10_u8; 32]),
            network_id: operation.network_id,
            route: operation.route,
            expires_at: MonotonicTick::from_ticks(20),
        };
        let mut entropy = FilledEntropy(11);
        let start = begin_credential_change_with_entropy(
            &profile,
            CredentialChangeStartParameters {
                context: operation,
                proof: Some(proof),
                account,
                credential_id: OpaqueCredentialId::from_bytes([10_u8; 32]),
                request: credential_start_request(25, account.0.account_id)?,
                operation_is_available: true,
            },
            &mut entropy,
        )?;
        let transaction_id = start.transaction_id();
        let mut transaction = start.seal(0)?.into_transaction_after_commit(1)?;

        assert_eq!(
            finish_credential_change(
                &mut transaction,
                context(11)?,
                credential_finish_request(26, transaction_id)?,
            )
            .err(),
            Some(AuthError::Overflow)
        );
        assert!(transaction.state_ref().is_none());
        Ok(())
    }

    #[test]
    fn credential_start_rejections_keep_fixed_challenge_and_completion_lineage()
    -> Result<(), Box<dyn core::error::Error>> {
        let profile = OpaqueProfile::generate(context(0)?.network_id)?;
        let current = account()?;
        let snapshot = current.0;
        let other_account_id = AccountRandomId::from_bytes([41_u8; 16]).to_account_id();
        let operation = context(10)?;
        for (index, case) in CredentialStartRejectionCase::ALL.into_iter().enumerate() {
            let (proof, requested_account, available, expected) =
                case.inputs(snapshot, operation, other_account_id)?;
            let request_id = 90_u8
                .checked_add(
                    u8::try_from(index)?
                        .checked_mul(2)
                        .ok_or(AuthError::Overflow)?,
                )
                .ok_or(AuthError::Overflow)?;
            assert_rejected_credential_start(
                &profile,
                request_id,
                Some(proof),
                current,
                requested_account,
                available,
                expected,
            )?;
        }
        assert_rejected_credential_start(
            &profile,
            118,
            None,
            current,
            snapshot.account_id,
            true,
            AuthError::WrongState,
        )?;
        Ok(())
    }

    #[test]
    fn deletion_confirmation_is_revision_bound_and_consumed_on_failure()
    -> Result<(), Box<dyn core::error::Error>> {
        let mut challenge = begin_account_deletion(context(10)?, fresh_proof(20)?, account()?)?;
        let token = *challenge.token()?;
        let stale = DestructiveAccountSnapshot(AccountSnapshot {
            account_revision: Revision::new(8)?,
            ..account()?.0
        });
        assert!(
            challenge
                .confirm(context(11)?, &token, stale, true)
                .is_err()
        );
        assert!(
            challenge
                .confirm(context(11)?, &token, account()?, true)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn deletion_confirmation_accepts_the_unchanged_snapshot()
    -> Result<(), Box<dyn core::error::Error>> {
        let expected = account()?;
        let mut challenge = begin_account_deletion(context(10)?, fresh_proof(20)?, expected)?;
        let token = *challenge.token()?;
        let intent = challenge.confirm(context(11)?, &token, expected, true)?;
        assert_eq!(intent.account_id(), expected.0.account_id);
        Ok(())
    }

    #[test]
    fn fresh_authentication_has_an_inclusive_five_minute_boundary()
    -> Result<(), Box<dyn core::error::Error>> {
        let challenge =
            begin_account_deletion(context(300_000)?, fresh_proof(300_000)?, account()?)?;
        assert_eq!(challenge.token()?.len(), 16);
        assert!(
            begin_account_deletion(context(300_001)?, fresh_proof(300_000)?, account()?,).is_err()
        );
        Ok(())
    }

    #[test]
    fn destructive_proofs_and_deletion_confirmations_reject_every_substitution()
    -> Result<(), Box<dyn core::error::Error>> {
        let expected = account()?.0;
        let operation = context(10)?;
        let proof = |expires_at| FreshAuthenticationProof {
            account: expected,
            credential_id: OpaqueCredentialId::from_bytes([9_u8; 32]),
            network_id: operation.network_id,
            route: operation.route,
            expires_at: MonotonicTick::from_ticks(expires_at),
        };
        let other_account_id = AccountRandomId::from_bytes([8_u8; 16]).to_account_id();
        for case in [
            CredentialStartRejectionCase::ProofNetwork,
            CredentialStartRejectionCase::ProofAccount,
            CredentialStartRejectionCase::ProofEdge,
            CredentialStartRejectionCase::ProofIncarnation,
            CredentialStartRejectionCase::ProofOrigin,
            CredentialStartRejectionCase::ProofOriginGeneration,
            CredentialStartRejectionCase::ProofConnection,
            CredentialStartRejectionCase::ProofConnectionNonce,
            CredentialStartRejectionCase::ProofRevision,
            CredentialStartRejectionCase::ProofGeneration,
            CredentialStartRejectionCase::ProofExpired,
        ] {
            let (substituted, _, _, expected_error) =
                case.inputs(expected, operation, other_account_id)?;
            assert_eq!(
                substituted.consume(operation, expected),
                Err(expected_error)
            );
        }
        let deletion_account = account()?;
        let mut wrong_token = begin_account_deletion(operation, proof(20), deletion_account)?;
        assert_eq!(
            wrong_token
                .confirm(context(11)?, &[0_u8; 16], deletion_account, true)
                .err(),
            Some(super::AuthError::AuthenticationFailed)
        );
        assert_eq!(wrong_token.token().err(), Some(super::AuthError::Consumed));

        let deletion_account = account()?;
        let mut wrong_account = begin_account_deletion(operation, proof(20), deletion_account)?;
        let token = *wrong_account.token()?;
        let changed_account = DestructiveAccountSnapshot(AccountSnapshot {
            account_id: AccountRandomId::from_bytes([12_u8; 16]).to_account_id(),
            ..expected
        });
        assert_eq!(
            wrong_account
                .confirm(context(11)?, &token, changed_account, true)
                .err(),
            Some(super::AuthError::WrongState)
        );

        let deletion_account = account()?;
        let mut wrong_generation = begin_account_deletion(operation, proof(20), deletion_account)?;
        let token = *wrong_generation.token()?;
        let changed_generation = DestructiveAccountSnapshot(AccountSnapshot {
            account_session_generation: Generation::new(10)?,
            ..expected
        });
        assert_eq!(
            wrong_generation
                .confirm(context(11)?, &token, changed_generation, true)
                .err(),
            Some(super::AuthError::WrongState)
        );

        let deletion_account = account()?;
        let mut failed_precondition =
            begin_account_deletion(operation, proof(20), deletion_account)?;
        assert_eq!(
            failed_precondition.expires_at(),
            MonotonicTick::from_ticks(60_010)
        );
        let token = *failed_precondition.token()?;
        assert_eq!(
            failed_precondition
                .confirm(context(11)?, &token, deletion_account, false)
                .err(),
            Some(super::AuthError::WrongState)
        );
        Ok(())
    }
}
