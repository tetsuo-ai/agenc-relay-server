//! The crypto bridge: the closed runtime job set over the bounded crypto
//! pool and the bounded completion path back to StateCore (spec 21.3, line
//! 4085; 21.7, lines 4242-4250).
//!
//! Every job copies only bounded owned inputs, secret outputs are wrapped in
//! types without `Debug`, and a job that cannot be admitted returns its
//! input unchanged so StateCore renders `SERVER_BUSY` before anything was
//! enqueued. The bridge awaits each job handle in a supervised task set
//! whose size is bounded by the same two slots per worker as the pool's
//! physical queue, and forwards outcomes into a channel of that capacity.
//!
//! This module keeps its tests in `tests/bridge_crypto.rs` so the file can be
//! compiled unchanged for the schedule models.

use std::collections::BTreeMap;
use std::fmt;

use agenc_ircd_auth::{
    AccountAuthenticationState, AccountCreationStartParameters, AccountCreationState,
    AccountFinishOutcome, AccountOperationContext, AccountServiceEnvelope, AccountStartOutcome,
    AccountTransaction, AuthError, AuthenticatedAccountRequest, AuthenticationFinish,
    AuthenticationGrant, AuthenticationStartParameters, CreateAccountIntent, CreationFinish,
    CreationStart, CredentialChangeFinish, CredentialChangeStartParameters, CredentialChangeState,
    CredentialReplacementIntent, OpaqueProfile, OpenedAccountServiceRequest,
    SealedAccountFinishOutcome, SealedAccountStart, begin_account_creation, begin_authentication,
    begin_credential_change, finish_account_authentication, finish_account_creation,
    finish_credential_change, open_and_parse_request,
};
use agenc_ircd_crypto::{
    ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES, AccountHpkePrivateKey, AccountResponseSealToken,
    BoundedCryptoPool, CRYPTO_WORKER_RESERVED_BYTES, CryptoError, CryptoJob, CryptoPort,
    CryptoWorkerConfig, CryptoWorkerError, Ed25519PublicKey, JobCancellationToken, JobClass,
    LoginIndexKey, OpaqueFakeCredentialKey, SealedAccountResponse,
};
use agenc_ircd_types::{
    AccountServiceMessageKind, AccountServiceResponseKind, InviteId, NetworkId, RecoveryEpoch,
    UtcSecond,
};
use subtle::ConstantTimeEq as _;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use zeroize::Zeroizing;

use crate::RuntimeError;
use crate::bridge::{CryptoCompletionMessage, CryptoJobId};
use crate::state_core::inbox::CRYPTO_COMPLETION_SLOTS_PER_WORKER;
use crate::sync::Arc;

/// Argon2id memory cost for channel secrets, 64 MiB in KiB (spec line 1851).
pub const CHANNEL_KEY_ARGON2_MEMORY_KIB: u32 = 65_536;
/// Argon2id iteration count for channel secrets (spec line 1851).
pub const CHANNEL_KEY_ARGON2_ITERATIONS: u32 = 3;
/// Argon2id parallelism for channel secrets (spec line 1851).
pub const CHANNEL_KEY_ARGON2_PARALLELISM: u32 = 4;
/// Random salt bytes stored beside each channel-key hash (spec line 1852).
pub const CHANNEL_KEY_SALT_BYTES: usize = 16;
/// Derived hash bytes compared in constant time.
pub const CHANNEL_KEY_HASH_BYTES: usize = 32;
/// Shortest accepted channel secret (spec line 1849).
pub const MIN_CHANNEL_KEY_BYTES: usize = 8;
/// Longest accepted channel secret (spec line 1849).
pub const MAX_CHANNEL_KEY_BYTES: usize = 256;

/// The Argon2id derivation the runtime delegates to.
///
/// Implementations must use Argon2id version 0x13 with exactly
/// [`CHANNEL_KEY_ARGON2_MEMORY_KIB`], [`CHANNEL_KEY_ARGON2_ITERATIONS`], and
/// [`CHANNEL_KEY_ARGON2_PARALLELISM`], producing [`CHANNEL_KEY_HASH_BYTES`]
/// bytes. The runtime never implements the primitive itself (spec 24.1,
/// line 6459); the composition layer injects the reviewed implementation.
pub trait ChannelKeyVerifier: Send + Sync {
    /// Derives the verifier hash of `secret` under `salt`.
    fn derive(
        &self,
        secret: &[u8],
        salt: &[u8; CHANNEL_KEY_SALT_BYTES],
    ) -> Result<[u8; CHANNEL_KEY_HASH_BYTES], CryptoError>;
}

/// The domain-owned stored salt and hash of one channel secret.
pub use agenc_ircd_domain::ChannelKeyVerifier as ChannelKeyVerifierRecord;

/// What a channel-key job compares against.
///
/// Every syntactically valid nonempty JOIN key runs exactly one derivation
/// in the same work class whether or not the channel exists or has a key
/// (spec lines 1861-1865); the startup dummy record makes the absent case
/// indistinguishable by timing and never matches.
#[derive(Clone, Copy)]
pub enum ChannelKeyTarget {
    /// The channel's stored verifier.
    Stored(ChannelKeyVerifierRecord),
    /// The process-wide dummy verifier; the verdict is always `false`.
    Dummy(ChannelKeyVerifierRecord),
}

/// One channel-key verification.
pub struct ChannelKeyVerifyJob {
    verifier: Arc<dyn ChannelKeyVerifier>,
    target: ChannelKeyTarget,
    candidate: Zeroizing<Vec<u8>>,
}

impl ChannelKeyVerifyJob {
    /// Binds a candidate secret of 8..=256 bytes to its target.
    pub fn new(
        verifier: Arc<dyn ChannelKeyVerifier>,
        target: ChannelKeyTarget,
        candidate: Vec<u8>,
    ) -> Result<Self, RuntimeError> {
        let candidate = Zeroizing::new(candidate);
        if !(MIN_CHANNEL_KEY_BYTES..=MAX_CHANNEL_KEY_BYTES).contains(&candidate.len()) {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self {
            verifier,
            target,
            candidate,
        })
    }

    fn execute(self) -> ChannelKeyVerdict {
        let (record, real) = match self.target {
            ChannelKeyTarget::Stored(record) => (record, true),
            ChannelKeyTarget::Dummy(record) => (record, false),
        };
        let matches = match self.verifier.derive(&self.candidate, record.salt()) {
            Ok(derived) => bool::from(derived.ct_eq(record.hash())),
            Err(_) => false,
        };
        // A dummy target performs the full derivation but never matches; the
        // bitwise AND keeps the comparison result independent of the target.
        ChannelKeyVerdict {
            matches: matches & real,
        }
    }
}

/// One channel-key verifier construction.
pub struct ChannelKeyConstructJob {
    verifier: Arc<dyn ChannelKeyVerifier>,
    salt: [u8; CHANNEL_KEY_SALT_BYTES],
    candidate: Zeroizing<Vec<u8>>,
}

impl ChannelKeyConstructJob {
    /// Binds a candidate secret and fresh random salt to one derivation.
    pub fn new(
        verifier: Arc<dyn ChannelKeyVerifier>,
        salt: [u8; CHANNEL_KEY_SALT_BYTES],
        candidate: Vec<u8>,
    ) -> Result<Self, RuntimeError> {
        let candidate = Zeroizing::new(candidate);
        if !(MIN_CHANNEL_KEY_BYTES..=MAX_CHANNEL_KEY_BYTES).contains(&candidate.len()) {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self {
            verifier,
            salt,
            candidate,
        })
    }

    fn execute(self) -> Result<ChannelKeyVerifierRecord, CryptoError> {
        let hash = self.verifier.derive(&self.candidate, &self.salt)?;
        Ok(ChannelKeyVerifierRecord::new(self.salt, hash))
    }
}

/// The outcome of one channel-key verification.
#[derive(Clone, Copy)]
pub struct ChannelKeyVerdict {
    matches: bool,
}

impl ChannelKeyVerdict {
    #[cfg(test)]
    pub(crate) const fn for_test(matches: bool) -> Self {
        Self { matches }
    }

    /// Returns whether the candidate matched a stored verifier.
    #[must_use]
    pub const fn matches(self) -> bool {
        self.matches
    }
}

/// One account-service HPKE request opening.
pub struct AccountOpenJob {
    private_key: Arc<AccountHpkePrivateKey>,
    recovery_epoch: RecoveryEpoch,
    expected_network: NetworkId,
    expected_message_kind: AccountServiceMessageKind,
    envelope: AccountServiceEnvelope,
}

impl AccountOpenJob {
    /// Binds the exact request bytes to the recipient key.
    #[must_use]
    pub fn new(
        private_key: Arc<AccountHpkePrivateKey>,
        recovery_epoch: RecoveryEpoch,
        expected_network: NetworkId,
        expected_message_kind: AccountServiceMessageKind,
        envelope: AccountServiceEnvelope,
    ) -> Self {
        Self {
            private_key,
            recovery_epoch,
            expected_network,
            expected_message_kind,
            envelope,
        }
    }

    fn execute(self) -> Result<OpenedAccountServiceRequest, AuthError> {
        open_and_parse_request(
            &self.private_key,
            self.recovery_epoch,
            self.expected_network,
            self.expected_message_kind,
            &self.envelope,
        )
    }
}

/// One account-service response sealing; the token is consumed exactly
/// once (spec lines 4025-4030).
pub struct AccountSealJob {
    token: AccountResponseSealToken,
    current_response_count: u64,
    response_kind: AccountServiceResponseKind,
    plaintext: Box<Zeroizing<[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES]>>,
}

impl AccountSealJob {
    /// Moves the one-use token and the exact plaintext into the job.
    #[must_use]
    pub fn new(
        token: AccountResponseSealToken,
        current_response_count: u64,
        response_kind: AccountServiceResponseKind,
        plaintext: Box<Zeroizing<[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES]>>,
    ) -> Self {
        Self {
            token,
            current_response_count,
            response_kind,
            plaintext,
        }
    }

    fn execute(self) -> Result<SealedAccountResponse, CryptoError> {
        self.token.seal_response(
            self.current_response_count,
            self.response_kind,
            &self.plaintext,
        )
    }
}

/// One OPAQUE authentication start.
pub struct OpaqueStartJob {
    profile: Arc<OpaqueProfile>,
    login_index_key: Arc<LoginIndexKey>,
    fake_credential_key: Arc<OpaqueFakeCredentialKey>,
    parameters: AuthenticationStartParameters,
}

impl OpaqueStartJob {
    /// Binds the shared coordinator keys to one start request.
    #[must_use]
    pub fn new(
        profile: Arc<OpaqueProfile>,
        login_index_key: Arc<LoginIndexKey>,
        fake_credential_key: Arc<OpaqueFakeCredentialKey>,
        parameters: AuthenticationStartParameters,
    ) -> Self {
        Self {
            profile,
            login_index_key,
            fake_credential_key,
            parameters,
        }
    }

    fn execute(self) -> Result<AccountStartOutcome<AccountAuthenticationState>, AuthError> {
        begin_authentication(
            &self.profile,
            &self.login_index_key,
            &self.fake_credential_key,
            self.parameters,
        )
    }
}

/// One OPAQUE authentication START challenge seal after StateCore reserves
/// the exact response-count successor.
pub struct OpaqueStartSealJob {
    outcome: AccountStartOutcome<AccountAuthenticationState>,
    current_response_count: u64,
}

impl OpaqueStartSealJob {
    /// Moves the authenticated transaction lineage into its one-use seal job.
    #[must_use]
    pub fn new(
        outcome: AccountStartOutcome<AccountAuthenticationState>,
        current_response_count: u64,
    ) -> Self {
        Self {
            outcome,
            current_response_count,
        }
    }

    fn execute(self) -> Result<SealedAccountStart<AccountAuthenticationState>, AuthError> {
        self.outcome.seal(self.current_response_count)
    }
}

/// One OPAQUE authentication finish over a START lineage whose challenge is
/// already durably committed.
pub struct OpaqueFinishJob {
    transaction: AccountTransaction<AccountAuthenticationState>,
    context: AccountOperationContext,
    finish: AuthenticatedAccountRequest<AuthenticationFinish>,
}

impl OpaqueFinishJob {
    /// Moves the transaction and the finish request into the job.
    #[must_use]
    pub fn new(
        transaction: AccountTransaction<AccountAuthenticationState>,
        context: AccountOperationContext,
        finish: AuthenticatedAccountRequest<AuthenticationFinish>,
    ) -> Self {
        Self {
            transaction,
            context,
            finish,
        }
    }

    fn execute(mut self) -> OpaqueFinishOutput {
        let outcome =
            finish_account_authentication(&mut self.transaction, self.context, self.finish);
        OpaqueFinishOutput { outcome }
    }
}

/// The terminal outcome of one OPAQUE finish.
pub struct OpaqueFinishOutput {
    /// The finish outcome.
    pub outcome: Result<AccountFinishOutcome<AuthenticationGrant>, AuthError>,
}

/// One OPAQUE authentication FINISH completion seal after StateCore reserves
/// the exact response-count successor.
pub struct OpaqueFinishSealJob {
    outcome: AccountFinishOutcome<AuthenticationGrant>,
    current_response_count: u64,
}

impl OpaqueFinishSealJob {
    /// Moves the checked semantic result into its one-use completion seal.
    #[must_use]
    pub fn new(
        outcome: AccountFinishOutcome<AuthenticationGrant>,
        current_response_count: u64,
    ) -> Self {
        Self {
            outcome,
            current_response_count,
        }
    }

    fn execute(self) -> Result<SealedAccountFinishOutcome<AuthenticationGrant>, AuthError> {
        self.outcome.seal(self.current_response_count)
    }
}

/// One account-creation start.
pub struct CreationStartJob {
    profile: Arc<OpaqueProfile>,
    login_index_key: Arc<LoginIndexKey>,
    parameters: AccountCreationStartParameters,
}

/// One invitation verification preflight used only to derive the authenticated
/// account-creation rate key.
pub struct CreationPreflightJob {
    request: AuthenticatedAccountRequest<CreationStart>,
    authority: Ed25519PublicKey,
    network_id: NetworkId,
    now: UtcSecond,
}

impl CreationPreflightJob {
    /// Binds one opened request to the configured offline invitation authority.
    #[must_use]
    pub fn new(
        request: AuthenticatedAccountRequest<CreationStart>,
        authority: Ed25519PublicKey,
        network_id: NetworkId,
        now: UtcSecond,
    ) -> Self {
        Self {
            request,
            authority,
            network_id,
            now,
        }
    }

    fn execute(self) -> CreationPreflightOutput {
        let verified_invite = self
            .request
            .payload()
            .invitation
            .as_ref()
            .and_then(|invite| {
                invite
                    .verify(self.authority, self.network_id, self.now)
                    .is_ok()
                    .then_some(invite.invite_id())
            });
        CreationPreflightOutput {
            request: self.request,
            verified_invite,
        }
    }
}

/// The opened request and optional signature-verified invitation rate key.
pub struct CreationPreflightOutput {
    /// The request retaining its one-use response authority.
    pub request: AuthenticatedAccountRequest<CreationStart>,
    /// The verified invitation identity; invalid or absent invitations have no key.
    pub verified_invite: Option<InviteId>,
}

impl CreationStartJob {
    /// Binds the shared coordinator keys to one creation start.
    #[must_use]
    pub fn new(
        profile: Arc<OpaqueProfile>,
        login_index_key: Arc<LoginIndexKey>,
        parameters: AccountCreationStartParameters,
    ) -> Self {
        Self {
            profile,
            login_index_key,
            parameters,
        }
    }

    fn execute(self) -> Result<AccountStartOutcome<AccountCreationState>, AuthError> {
        begin_account_creation(&self.profile, &self.login_index_key, self.parameters)
    }
}

/// One account-creation START challenge seal after StateCore reserves the
/// exact response-count successor.
pub struct CreationStartSealJob {
    outcome: AccountStartOutcome<AccountCreationState>,
    current_response_count: u64,
}

impl CreationStartSealJob {
    /// Moves the creation transaction lineage into its one-use seal job.
    #[must_use]
    pub fn new(
        outcome: AccountStartOutcome<AccountCreationState>,
        current_response_count: u64,
    ) -> Self {
        Self {
            outcome,
            current_response_count,
        }
    }

    fn execute(self) -> Result<SealedAccountStart<AccountCreationState>, AuthError> {
        self.outcome.seal(self.current_response_count)
    }
}

/// One account-creation finish.
pub struct CreationFinishJob {
    transaction: AccountTransaction<AccountCreationState>,
    context: AccountOperationContext,
    finish: AuthenticatedAccountRequest<CreationFinish>,
}

impl CreationFinishJob {
    /// Moves the transaction and the finish request into the job.
    #[must_use]
    pub fn new(
        transaction: AccountTransaction<AccountCreationState>,
        context: AccountOperationContext,
        finish: AuthenticatedAccountRequest<CreationFinish>,
    ) -> Self {
        Self {
            transaction,
            context,
            finish,
        }
    }

    fn execute(mut self) -> CreationFinishOutput {
        let outcome = finish_account_creation(&mut self.transaction, self.context, self.finish);
        CreationFinishOutput {
            transaction: self.transaction,
            outcome,
        }
    }
}

/// The transaction and outcome of one creation finish.
pub struct CreationFinishOutput {
    /// The transaction, consumed or not, returned to its owner.
    pub transaction: AccountTransaction<AccountCreationState>,
    /// The finish outcome.
    pub outcome: Result<AccountFinishOutcome<CreateAccountIntent>, AuthError>,
}

/// One account-creation FINISH completion seal after StateCore reserves the
/// exact response-count successor.
pub struct CreationFinishSealJob {
    outcome: AccountFinishOutcome<CreateAccountIntent>,
    current_response_count: u64,
}

impl CreationFinishSealJob {
    /// Moves the checked creation result into its one-use completion seal.
    #[must_use]
    pub fn new(
        outcome: AccountFinishOutcome<CreateAccountIntent>,
        current_response_count: u64,
    ) -> Self {
        Self {
            outcome,
            current_response_count,
        }
    }

    fn execute(self) -> Result<SealedAccountFinishOutcome<CreateAccountIntent>, AuthError> {
        self.outcome.seal(self.current_response_count)
    }
}

/// One credential-change start.
pub struct CredentialStartJob {
    profile: Arc<OpaqueProfile>,
    parameters: CredentialChangeStartParameters,
}

impl CredentialStartJob {
    /// Binds the coordinator OPAQUE profile to one credential-change start.
    #[must_use]
    pub fn new(profile: Arc<OpaqueProfile>, parameters: CredentialChangeStartParameters) -> Self {
        Self {
            profile,
            parameters,
        }
    }

    fn execute(self) -> Result<AccountStartOutcome<CredentialChangeState>, AuthError> {
        begin_credential_change(&self.profile, self.parameters)
    }
}

/// One credential-change START challenge seal after StateCore reserves the
/// exact response-count successor.
pub struct CredentialStartSealJob {
    outcome: AccountStartOutcome<CredentialChangeState>,
    current_response_count: u64,
}

impl CredentialStartSealJob {
    /// Moves the replacement transaction lineage into its one-use seal job.
    #[must_use]
    pub fn new(
        outcome: AccountStartOutcome<CredentialChangeState>,
        current_response_count: u64,
    ) -> Self {
        Self {
            outcome,
            current_response_count,
        }
    }

    fn execute(self) -> Result<SealedAccountStart<CredentialChangeState>, AuthError> {
        self.outcome.seal(self.current_response_count)
    }
}

/// One credential-change finish.
pub struct CredentialFinishJob {
    transaction: AccountTransaction<CredentialChangeState>,
    context: AccountOperationContext,
    finish: AuthenticatedAccountRequest<CredentialChangeFinish>,
}

impl CredentialFinishJob {
    /// Moves the transaction and finish request into one blocking job.
    #[must_use]
    pub fn new(
        transaction: AccountTransaction<CredentialChangeState>,
        context: AccountOperationContext,
        finish: AuthenticatedAccountRequest<CredentialChangeFinish>,
    ) -> Self {
        Self {
            transaction,
            context,
            finish,
        }
    }

    fn execute(mut self) -> CredentialFinishOutput {
        let outcome = finish_credential_change(&mut self.transaction, self.context, self.finish);
        CredentialFinishOutput {
            transaction: self.transaction,
            outcome,
        }
    }
}

/// The transaction and outcome of one credential-change finish.
pub struct CredentialFinishOutput {
    /// The transaction, consumed or not, returned to its owner.
    pub transaction: AccountTransaction<CredentialChangeState>,
    /// The finish outcome.
    pub outcome: Result<AccountFinishOutcome<CredentialReplacementIntent>, AuthError>,
}

/// One credential-change FINISH completion seal after StateCore reserves the
/// exact response-count successor.
pub struct CredentialFinishSealJob {
    outcome: AccountFinishOutcome<CredentialReplacementIntent>,
    current_response_count: u64,
}

impl CredentialFinishSealJob {
    /// Moves the checked replacement result into its one-use completion seal.
    #[must_use]
    pub fn new(
        outcome: AccountFinishOutcome<CredentialReplacementIntent>,
        current_response_count: u64,
    ) -> Self {
        Self {
            outcome,
            current_response_count,
        }
    }

    fn execute(self) -> Result<SealedAccountFinishOutcome<CredentialReplacementIntent>, AuthError> {
        self.outcome.seal(self.current_response_count)
    }
}

/// The closed set of blocking crypto jobs the runtime submits.
pub enum RuntimeCryptoJob {
    /// One Argon2id channel-key verification.
    ChannelKeyVerify(ChannelKeyVerifyJob),
    /// One Argon2id channel-key verifier construction.
    ChannelKeyConstruct(ChannelKeyConstructJob),
    /// One account-service request opening.
    AccountOpen(Box<AccountOpenJob>),
    /// One account-service response sealing.
    AccountSeal(Box<AccountSealJob>),
    /// One OPAQUE authentication start.
    OpaqueStart(Box<OpaqueStartJob>),
    /// One OPAQUE authentication START response seal.
    OpaqueStartSeal(Box<OpaqueStartSealJob>),
    /// One OPAQUE authentication finish.
    OpaqueFinish(Box<OpaqueFinishJob>),
    /// One OPAQUE authentication FINISH response seal.
    OpaqueFinishSeal(Box<OpaqueFinishSealJob>),
    /// One account-creation start.
    CreationStart(Box<CreationStartJob>),
    /// One invitation verification preflight.
    CreationPreflight(Box<CreationPreflightJob>),
    /// One account-creation START response seal.
    CreationStartSeal(Box<CreationStartSealJob>),
    /// One account-creation finish.
    CreationFinish(Box<CreationFinishJob>),
    /// One account-creation FINISH response seal.
    CreationFinishSeal(Box<CreationFinishSealJob>),
    /// One credential-change start.
    CredentialStart(Box<CredentialStartJob>),
    /// One credential-change START response seal.
    CredentialStartSeal(Box<CredentialStartSealJob>),
    /// One credential-change finish.
    CredentialFinish(Box<CredentialFinishJob>),
    /// One credential-change FINISH response seal.
    CredentialFinishSeal(Box<CredentialFinishSealJob>),
}

/// The closed set of job outputs; secret-bearing payloads have no `Debug`.
pub enum CryptoJobOutput {
    /// A channel-key verdict.
    ChannelKey(ChannelKeyVerdict),
    /// A newly derived channel-key verifier, or the closed crypto failure.
    ChannelKeyConstruct(Result<ChannelKeyVerifierRecord, CryptoError>),
    /// A fully opened and parsed request retaining its one-use response authority.
    AccountOpen(Box<Result<OpenedAccountServiceRequest, AuthError>>),
    /// A sealed response, or the closed failure.
    AccountSeal(Box<Result<SealedAccountResponse, CryptoError>>),
    /// An authentication start outcome.
    OpaqueStart(Box<Result<AccountStartOutcome<AccountAuthenticationState>, AuthError>>),
    /// An authentication START with its one-use challenge sealed.
    OpaqueStartSealed(Box<Result<SealedAccountStart<AccountAuthenticationState>, AuthError>>),
    /// An authentication finish outcome.
    OpaqueFinish(Box<OpaqueFinishOutput>),
    /// An authentication FINISH with its checked completion sealed.
    OpaqueFinishSealed(Box<Result<SealedAccountFinishOutcome<AuthenticationGrant>, AuthError>>),
    /// A creation start outcome.
    CreationStart(Box<Result<AccountStartOutcome<AccountCreationState>, AuthError>>),
    /// An invitation verification preflight result.
    CreationPreflight(Box<CreationPreflightOutput>),
    /// A creation START with its one-use challenge sealed.
    CreationStartSealed(Box<Result<SealedAccountStart<AccountCreationState>, AuthError>>),
    /// A creation finish outcome with its transaction.
    CreationFinish(Box<CreationFinishOutput>),
    /// A creation FINISH with its checked completion sealed.
    CreationFinishSealed(Box<Result<SealedAccountFinishOutcome<CreateAccountIntent>, AuthError>>),
    /// A credential-change start outcome.
    CredentialStart(Box<Result<AccountStartOutcome<CredentialChangeState>, AuthError>>),
    /// A credential-change START with its one-use challenge sealed.
    CredentialStartSealed(Box<Result<SealedAccountStart<CredentialChangeState>, AuthError>>),
    /// A credential-change finish outcome with its transaction.
    CredentialFinish(Box<CredentialFinishOutput>),
    /// A credential-change FINISH with its checked completion sealed.
    CredentialFinishSealed(
        Box<Result<SealedAccountFinishOutcome<CredentialReplacementIntent>, AuthError>>,
    ),
}

impl CryptoJob for RuntimeCryptoJob {
    type Output = CryptoJobOutput;

    fn class(&self) -> JobClass {
        match self {
            Self::ChannelKeyVerify(_) | Self::ChannelKeyConstruct(_) => JobClass::Channel,
            Self::AccountOpen(_)
            | Self::AccountSeal(_)
            | Self::OpaqueStart(_)
            | Self::OpaqueStartSeal(_)
            | Self::OpaqueFinish(_)
            | Self::OpaqueFinishSeal(_)
            | Self::CreationStart(_)
            | Self::CreationPreflight(_)
            | Self::CreationStartSeal(_)
            | Self::CreationFinish(_)
            | Self::CreationFinishSeal(_)
            | Self::CredentialStart(_)
            | Self::CredentialStartSeal(_)
            | Self::CredentialFinish(_)
            | Self::CredentialFinishSeal(_) => JobClass::Opaque,
        }
    }

    fn execute(self) -> Self::Output {
        match self {
            Self::ChannelKeyVerify(job) => CryptoJobOutput::ChannelKey(job.execute()),
            Self::ChannelKeyConstruct(job) => CryptoJobOutput::ChannelKeyConstruct(job.execute()),
            Self::AccountOpen(job) => CryptoJobOutput::AccountOpen(Box::new(job.execute())),
            Self::AccountSeal(job) => CryptoJobOutput::AccountSeal(Box::new(job.execute())),
            Self::OpaqueStart(job) => CryptoJobOutput::OpaqueStart(Box::new(job.execute())),
            Self::OpaqueStartSeal(job) => {
                CryptoJobOutput::OpaqueStartSealed(Box::new(job.execute()))
            }
            Self::OpaqueFinish(job) => CryptoJobOutput::OpaqueFinish(Box::new(job.execute())),
            Self::OpaqueFinishSeal(job) => {
                CryptoJobOutput::OpaqueFinishSealed(Box::new(job.execute()))
            }
            Self::CreationStart(job) => CryptoJobOutput::CreationStart(Box::new(job.execute())),
            Self::CreationPreflight(job) => {
                CryptoJobOutput::CreationPreflight(Box::new(job.execute()))
            }
            Self::CreationStartSeal(job) => {
                CryptoJobOutput::CreationStartSealed(Box::new(job.execute()))
            }
            Self::CreationFinish(job) => CryptoJobOutput::CreationFinish(Box::new(job.execute())),
            Self::CreationFinishSeal(job) => {
                CryptoJobOutput::CreationFinishSealed(Box::new(job.execute()))
            }
            Self::CredentialStart(job) => CryptoJobOutput::CredentialStart(Box::new(job.execute())),
            Self::CredentialStartSeal(job) => {
                CryptoJobOutput::CredentialStartSealed(Box::new(job.execute()))
            }
            Self::CredentialFinish(job) => {
                CryptoJobOutput::CredentialFinish(Box::new(job.execute()))
            }
            Self::CredentialFinishSeal(job) => {
                CryptoJobOutput::CredentialFinishSealed(Box::new(job.execute()))
            }
        }
    }
}

/// A submission refused before enqueue; the job is returned unchanged.
pub struct CryptoSubmitRefused {
    reason: CryptoWorkerError,
    job: RuntimeCryptoJob,
}

impl CryptoSubmitRefused {
    /// Returns the closed refusal reason.
    #[must_use]
    pub const fn reason(&self) -> CryptoWorkerError {
        self.reason
    }

    /// Returns whether StateCore should answer `SERVER_BUSY` (spec line
    /// 4085).
    #[must_use]
    pub const fn is_server_busy(&self) -> bool {
        matches!(self.reason, CryptoWorkerError::QueueFull)
    }

    /// Recovers the exact job that was never admitted.
    #[must_use]
    pub fn into_job(self) -> RuntimeCryptoJob {
        self.job
    }
}

impl fmt::Display for CryptoSubmitRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, formatter)
    }
}

/// The bounded path from StateCore into the crypto pool and back.
pub struct CryptoBridge {
    pool: Option<BoundedCryptoPool<RuntimeCryptoJob>>,
    waiters: JoinSet<CryptoJobId>,
    active: BTreeMap<CryptoJobId, ActiveCryptoJob>,
    waiter_ceiling: usize,
    completions: mpsc::Sender<CryptoCompletionMessage<CryptoJobOutput>>,
    next_job: u64,
}

struct ActiveCryptoJob {
    abort: AbortHandle,
    cancellation: JobCancellationToken,
}

impl CryptoBridge {
    /// Starts the pool and returns the sole completion receiver.
    ///
    /// The completion channel and the waiter ceiling both hold two slots
    /// per worker (spec line 4085).
    pub fn start(
        config: CryptoWorkerConfig,
    ) -> Result<
        (
            Self,
            mpsc::Receiver<CryptoCompletionMessage<CryptoJobOutput>>,
        ),
        RuntimeError,
    > {
        let reserved = config
            .reserved_memory_bytes()
            .map_err(worker_error_to_runtime)?;
        let workers = usize::try_from(reserved / CRYPTO_WORKER_RESERVED_BYTES)
            .map_err(|_| RuntimeError::Overflow)?;
        let capacity = workers
            .checked_mul(CRYPTO_COMPLETION_SLOTS_PER_WORKER)
            .filter(|capacity| *capacity > 0)
            .ok_or(RuntimeError::InvalidValue)?;
        let pool = BoundedCryptoPool::start(config).map_err(worker_error_to_runtime)?;
        let (completions, receiver) = mpsc::channel(capacity);
        Ok((
            Self {
                pool: Some(pool),
                waiters: JoinSet::new(),
                active: BTreeMap::new(),
                waiter_ceiling: capacity,
                completions,
                next_job: 1,
            },
            receiver,
        ))
    }

    /// Admits one job immediately or returns it with the closed reason.
    ///
    /// Must be called on the Tokio runtime: the completion is awaited by a
    /// supervised task whose drop requests pre-start cancellation.
    pub fn try_submit(
        &mut self,
        job: RuntimeCryptoJob,
    ) -> Result<CryptoJobId, CryptoSubmitRefused> {
        self.reap_finished();
        if self.active.len() >= self.waiter_ceiling {
            return Err(CryptoSubmitRefused {
                reason: CryptoWorkerError::QueueFull,
                job,
            });
        }
        let Some(pool) = &self.pool else {
            return Err(CryptoSubmitRefused {
                reason: CryptoWorkerError::ShuttingDown,
                job,
            });
        };
        let Some(next) = self.next_job.checked_add(1) else {
            return Err(CryptoSubmitRefused {
                reason: CryptoWorkerError::ShuttingDown,
                job,
            });
        };
        let handle = pool.try_submit(job).map_err(|error| CryptoSubmitRefused {
            reason: error.reason(),
            job: error.into_job(),
        })?;
        let job_id = CryptoJobId::new(self.next_job);
        self.next_job = next;
        let cancellation = handle.cancellation_token();
        let completions = self.completions.clone();
        let abort = self.waiters.spawn(async move {
            let output = handle.completion().await;
            let _send_result = completions
                .send(CryptoCompletionMessage { job_id, output })
                .await;
            job_id
        });
        let _previous = self.active.insert(
            job_id,
            ActiveCryptoJob {
                abort,
                cancellation,
            },
        );
        Ok(job_id)
    }

    /// Cancels one matching waiter and requests pre-start worker cancellation.
    /// A job already executing remains side-effect-free and finishes without a
    /// completion routed back to StateCore.
    pub fn cancel(&mut self, job_id: CryptoJobId) -> bool {
        self.reap_finished();
        let Some(active) = self.active.remove(&job_id) else {
            return false;
        };
        active.cancellation.cancel_before_start();
        active.abort.abort();
        true
    }

    /// Returns the number of jobs whose completion is still awaited.
    pub fn in_flight(&mut self) -> usize {
        self.reap_finished();
        self.active.len()
    }

    /// Aborts every waiter (cancelling unstarted jobs) and joins the pool
    /// on the blocking thread pool.
    pub async fn shutdown(mut self) -> Result<(), RuntimeError> {
        self.cancel_all();
        self.waiters.shutdown().await;
        if let Some(pool) = self.pool.take() {
            tokio::task::spawn_blocking(move || pool.shutdown())
                .await
                .map_err(|_| RuntimeError::Cancelled)?;
        }
        Ok(())
    }

    fn reap_finished(&mut self) {
        while let Some(result) = self.waiters.try_join_next() {
            if let Ok(job_id) = result {
                self.active.remove(&job_id);
            }
        }
    }

    fn cancel_all(&mut self) {
        for active in self.active.values() {
            active.cancellation.cancel_before_start();
            active.abort.abort();
        }
        self.active.clear();
    }
}

/// Dropping aborts the waiters and joins the pool on the current thread;
/// use [`CryptoBridge::shutdown`] from async code.
impl Drop for CryptoBridge {
    fn drop(&mut self) {
        self.cancel_all();
        self.waiters.abort_all();
        if let Some(pool) = self.pool.take() {
            pool.shutdown();
        }
    }
}

const fn worker_error_to_runtime(error: CryptoWorkerError) -> RuntimeError {
    match error {
        CryptoWorkerError::InvalidConfiguration => RuntimeError::InvalidValue,
        CryptoWorkerError::WorkerSpawnFailed
        | CryptoWorkerError::QueueFull
        | CryptoWorkerError::CancelledBeforeStart
        | CryptoWorkerError::WorkerPanicked
        | CryptoWorkerError::ShuttingDown => RuntimeError::LimitExceeded,
    }
}
