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

use std::fmt;

use agenc_ircd_auth::{
    AccountAuthenticationState, AccountCreationStartParameters, AccountCreationState,
    AccountFinishOutcome, AccountOperationContext, AccountStartOutcome, AccountTransaction,
    AuthError, AuthenticatedAccountRequest, AuthenticationFinish, AuthenticationGrant,
    AuthenticationStartParameters, CreateAccountIntent, CreationFinish, OpaqueProfile,
    begin_account_creation, begin_authentication, finish_account_authentication,
    finish_account_creation,
};
use agenc_ircd_crypto::{
    ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES, ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES,
    ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES, AccountHpkePrivateKey, AccountRequestBinding,
    AccountResponseSealToken, BoundedCryptoPool, CRYPTO_WORKER_RESERVED_BYTES, CryptoError,
    CryptoJob, CryptoPort, CryptoWorkerConfig, CryptoWorkerError, JobClass, LoginIndexKey,
    OpaqueFakeCredentialKey, OpenedAccountRequest, SealedAccountResponse, open_account_request,
};
use agenc_ircd_types::AccountServiceResponseKind;
use subtle::ConstantTimeEq as _;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
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

/// The stored salt and hash of one channel secret.
#[derive(Clone, Copy)]
pub struct ChannelKeyVerifierRecord {
    salt: [u8; CHANNEL_KEY_SALT_BYTES],
    hash: [u8; CHANNEL_KEY_HASH_BYTES],
}

impl ChannelKeyVerifierRecord {
    /// Wraps a stored salt and hash.
    #[must_use]
    pub const fn new(
        salt: [u8; CHANNEL_KEY_SALT_BYTES],
        hash: [u8; CHANNEL_KEY_HASH_BYTES],
    ) -> Self {
        Self { salt, hash }
    }

    /// Returns the salt.
    #[must_use]
    pub const fn salt(&self) -> &[u8; CHANNEL_KEY_SALT_BYTES] {
        &self.salt
    }

    /// Returns the hash.
    #[must_use]
    pub const fn hash(&self) -> &[u8; CHANNEL_KEY_HASH_BYTES] {
        &self.hash
    }
}

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
        let matches = match self.verifier.derive(&self.candidate, &record.salt) {
            Ok(derived) => bool::from(derived.ct_eq(&record.hash)),
            Err(_) => false,
        };
        // A dummy target performs the full derivation but never matches; the
        // bitwise AND keeps the comparison result independent of the target.
        ChannelKeyVerdict {
            matches: matches & real,
        }
    }
}

/// The outcome of one channel-key verification.
#[derive(Clone, Copy)]
pub struct ChannelKeyVerdict {
    matches: bool,
}

impl ChannelKeyVerdict {
    /// Returns whether the candidate matched a stored verifier.
    #[must_use]
    pub const fn matches(self) -> bool {
        self.matches
    }
}

/// One account-service HPKE request opening.
pub struct AccountOpenJob {
    private_key: Arc<AccountHpkePrivateKey>,
    binding: AccountRequestBinding,
    encapsulated_key: Box<[u8; ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES]>,
    ciphertext: Box<[u8; ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES]>,
}

impl AccountOpenJob {
    /// Binds the exact request bytes to the recipient key.
    #[must_use]
    pub fn new(
        private_key: Arc<AccountHpkePrivateKey>,
        binding: AccountRequestBinding,
        encapsulated_key: Box<[u8; ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES]>,
        ciphertext: Box<[u8; ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES]>,
    ) -> Self {
        Self {
            private_key,
            binding,
            encapsulated_key,
            ciphertext,
        }
    }

    fn execute(self) -> Result<(OpenedAccountRequest, AccountResponseSealToken), CryptoError> {
        open_account_request(
            &self.private_key,
            self.binding,
            &self.encapsulated_key,
            &self.ciphertext,
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

/// One OPAQUE authentication finish; the transaction returns with the
/// outcome so StateCore keeps sole ownership of it.
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
        OpaqueFinishOutput {
            transaction: self.transaction,
            outcome,
        }
    }
}

/// The transaction and outcome of one OPAQUE finish.
pub struct OpaqueFinishOutput {
    /// The transaction, consumed or not, returned to its owner.
    pub transaction: AccountTransaction<AccountAuthenticationState>,
    /// The finish outcome.
    pub outcome: Result<AccountFinishOutcome<AuthenticationGrant>, AuthError>,
}

/// One account-creation start.
pub struct CreationStartJob {
    profile: Arc<OpaqueProfile>,
    login_index_key: Arc<LoginIndexKey>,
    parameters: AccountCreationStartParameters,
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

/// The closed set of blocking crypto jobs the runtime submits.
pub enum RuntimeCryptoJob {
    /// One Argon2id channel-key verification.
    ChannelKeyVerify(ChannelKeyVerifyJob),
    /// One account-service request opening.
    AccountOpen(Box<AccountOpenJob>),
    /// One account-service response sealing.
    AccountSeal(Box<AccountSealJob>),
    /// One OPAQUE authentication start.
    OpaqueStart(Box<OpaqueStartJob>),
    /// One OPAQUE authentication finish.
    OpaqueFinish(Box<OpaqueFinishJob>),
    /// One account-creation start.
    CreationStart(Box<CreationStartJob>),
    /// One account-creation finish.
    CreationFinish(Box<CreationFinishJob>),
}

/// The closed set of job outputs; secret-bearing payloads have no `Debug`.
pub enum CryptoJobOutput {
    /// A channel-key verdict.
    ChannelKey(ChannelKeyVerdict),
    /// An opened request with its one-use seal token, or the closed failure.
    AccountOpen(Box<Result<(OpenedAccountRequest, AccountResponseSealToken), CryptoError>>),
    /// A sealed response, or the closed failure.
    AccountSeal(Box<Result<SealedAccountResponse, CryptoError>>),
    /// An authentication start outcome.
    OpaqueStart(Box<Result<AccountStartOutcome<AccountAuthenticationState>, AuthError>>),
    /// An authentication finish outcome with its transaction.
    OpaqueFinish(Box<OpaqueFinishOutput>),
    /// A creation start outcome.
    CreationStart(Box<Result<AccountStartOutcome<AccountCreationState>, AuthError>>),
    /// A creation finish outcome with its transaction.
    CreationFinish(Box<CreationFinishOutput>),
}

impl CryptoJob for RuntimeCryptoJob {
    type Output = CryptoJobOutput;

    fn class(&self) -> JobClass {
        match self {
            Self::ChannelKeyVerify(_) => JobClass::Channel,
            Self::AccountOpen(_)
            | Self::AccountSeal(_)
            | Self::OpaqueStart(_)
            | Self::OpaqueFinish(_)
            | Self::CreationStart(_)
            | Self::CreationFinish(_) => JobClass::Opaque,
        }
    }

    fn execute(self) -> Self::Output {
        match self {
            Self::ChannelKeyVerify(job) => CryptoJobOutput::ChannelKey(job.execute()),
            Self::AccountOpen(job) => CryptoJobOutput::AccountOpen(Box::new(job.execute())),
            Self::AccountSeal(job) => CryptoJobOutput::AccountSeal(Box::new(job.execute())),
            Self::OpaqueStart(job) => CryptoJobOutput::OpaqueStart(Box::new(job.execute())),
            Self::OpaqueFinish(job) => CryptoJobOutput::OpaqueFinish(Box::new(job.execute())),
            Self::CreationStart(job) => CryptoJobOutput::CreationStart(Box::new(job.execute())),
            Self::CreationFinish(job) => CryptoJobOutput::CreationFinish(Box::new(job.execute())),
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
    waiters: JoinSet<()>,
    waiter_ceiling: usize,
    completions: mpsc::Sender<CryptoCompletionMessage<CryptoJobOutput>>,
    next_job: u64,
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
        if self.waiters.len() >= self.waiter_ceiling {
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
        let completions = self.completions.clone();
        self.waiters.spawn(async move {
            let output = handle.completion().await;
            let _send_result = completions
                .send(CryptoCompletionMessage { job_id, output })
                .await;
        });
        Ok(job_id)
    }

    /// Returns the number of jobs whose completion is still awaited.
    pub fn in_flight(&mut self) -> usize {
        self.reap_finished();
        self.waiters.len()
    }

    /// Aborts every waiter (cancelling unstarted jobs) and joins the pool
    /// on the blocking thread pool.
    pub async fn shutdown(mut self) -> Result<(), RuntimeError> {
        self.waiters.shutdown().await;
        if let Some(pool) = self.pool.take() {
            tokio::task::spawn_blocking(move || pool.shutdown())
                .await
                .map_err(|_| RuntimeError::Cancelled)?;
        }
        Ok(())
    }

    fn reap_finished(&mut self) {
        while self.waiters.try_join_next().is_some() {}
    }
}

/// Dropping aborts the waiters and joins the pool on the current thread;
/// use [`CryptoBridge::shutdown`] from async code.
impl Drop for CryptoBridge {
    fn drop(&mut self) {
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
