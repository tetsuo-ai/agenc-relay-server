//! Shared live `StateCore` fixture for unit tests inside the runtime crate.
//!
//! The fixture initializes a private storage directory, opens the storage
//! owner, reconstructs an empty durable index, and composes one `StateCore`
//! with deterministic clocks and scripted entropy. Tests reach the live
//! `StateCoreContext` through `context_mut`.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use std::collections::BTreeMap;

use agenc_ircd_auth::OpaqueProfile;
use agenc_ircd_client_wire::{CapRequestReply, CapabilityState};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, CryptoWorkerConfig, Ed25519SecretKey, LoginIndexKey,
    OpaqueFakeCredentialKey, RollbackGuardRootKey, StorageDigest, StorageMasterKey,
};
use agenc_ircd_domain::{DirectMessagePolicy, GuestDirectMessagePolicy, PresencePolicy};
use agenc_ircd_storage::{
    DatabaseHeaderTbs, InitialStorageRecord, LIVE_RECORD_KIND, LOGIN_INDEX_KEY_STATE_KEY,
    LoginIndexKeyState, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue, QualificationTarget,
    SCHEMA_GENERATION, StateDirectory, StorageEngineLimits, StorageGrowthCase,
    StorageInitializationConfig, StorageInitializationMode, StorageInitializationOutcome,
    StorageOpenConfig, StorageOwner, StorageQualification, StorageQualificationReport,
    StorageQualificationReportTbs, StoredKey, TableId, initialize_storage,
};
use agenc_ircd_testkit::{
    DeterministicMonotonicClock, DeterministicWallClock, DomainTestIdentity, ScriptedEntropy,
};
use agenc_ircd_types::{
    AccountId, DatabaseId, Generation, MonotonicTick, NetworkId, OriginId, RecoveryEpoch, ServerId,
    ServerIncarnation, SessionId, UserId, UtcSecond,
};

use crate::RuntimeError;
use crate::StateCoreSeed;
use crate::account_service::{AccountCreationPolicy, AccountServiceConfig};
use crate::admission::RateLimits;
use crate::bridge::crypto::{
    CHANNEL_KEY_HASH_BYTES, CHANNEL_KEY_SALT_BYTES, ChannelKeyVerifier, ChannelKeyVerifierRecord,
    CryptoBridge,
};
use crate::bridge::storage::StorageBridge;
use crate::budget::MemoryBudget;
use crate::channels::RegisteredCommandExecutor;
use crate::connection::{
    BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, ClientQueueSnapshot,
    ClientSink, ConnectionGeneration, FlushAcknowledgement, QueueAllocationError,
    QueueReservationLedger, SinkReserveError, TentativeClientQueueReservation,
};
use crate::observe::health::Liveness;
use crate::registration::{RegistrationRouter, RegistrationRouterConfig};
use crate::state_core::durable::{AccountingCeilings, KeyDeriver};
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::inbox::{CloseReason, SourceAddressKey};
use crate::state_core::reconstruct::reconstruct;
use crate::state_core::session::BoundSession;
use crate::state_core::{
    CommandRouter, DefaultRouter, StateCore, StateCoreClocks, StateCoreConfig, StateCoreContext,
    StateCoreInputs,
};
use crate::sync::Arc;

/// Boxed error alias for fixture construction and test bodies.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static NEXT_CHANNEL_SEED: AtomicU64 = AtomicU64::new(100);

/// Storage limits small enough for unit tests and large enough for every
/// mutation batch a test stages.
pub(crate) const TEST_STORAGE_LIMITS: StorageEngineLimits = StorageEngineLimits {
    redb_cache_bytes: 8 * 1_024 * 1_024,
    fixed_reserve_bytes: 64 * 1_024 * 1_024,
    reserve_percent: 1,
    database_max_bytes: 1_073_741_824,
    backup_max_bytes: 2_147_483_648,
    integrity_checkpoint_manifests: 100_000,
};

/// Signs a qualification report for the filesystem under the test directory.
pub(crate) fn signed_test_qualification(
    tuple: agenc_ircd_storage::FilesystemTuple,
) -> TestResult<StorageQualification> {
    let target = match tuple.target {
        "x86_64-unknown-linux-gnu" => QualificationTarget::X86_64UnknownLinuxGnu,
        "aarch64-unknown-linux-gnu" => QualificationTarget::Aarch64UnknownLinuxGnu,
        _ => return Err("unsupported test target".into()),
    };
    let mut cases = agenc_ircd_storage::REQUIRED_QUALIFICATION_CASES
        .iter()
        .map(|name| StorageGrowthCase::new((*name).to_owned(), 1_000, 1_001))
        .collect::<Result<Vec<_>, _>>()?;
    cases.sort_by(|left, right| left.name().cmp(right.name()));
    let key = Ed25519SecretKey::from_bytes([99; 32]);
    let report = StorageQualificationReport::sign(
        StorageQualificationReportTbs {
            target,
            filesystem_type: tuple.filesystem_type,
            block_size: tuple.block_size,
            mount_flags: tuple.mount_flags,
            kernel_release: "test-kernel".to_owned(),
            redb_features_hash: StorageDigest::from_bytes([1; 32]),
            release_profile_hash: StorageDigest::from_bytes([2; 32]),
            corpus_hash: StorageDigest::from_bytes([3; 32]),
            cases,
            maximum_observed_growth: 1,
            raw_log_hash: StorageDigest::from_bytes([4; 32]),
        },
        &key,
    )?;
    let verified =
        StorageQualificationReport::decode_and_verify(&report.encode()?, key.public_key())?;
    Ok(verified.qualification_for(tuple)?)
}

/// One private, mode 0700 directory removed when the fixture drops.
pub(crate) struct TestDirectory(pub(crate) PathBuf);

impl TestDirectory {
    pub(crate) fn create() -> TestResult<Self> {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agenc-ircd-runtime-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

/// Fixed identities shared by every fixture instance.
pub(crate) struct FixtureIdentity {
    pub(crate) network_id: NetworkId,
    pub(crate) server_id: ServerId,
    pub(crate) server_incarnation: ServerIncarnation,
    pub(crate) recovery_epoch: RecoveryEpoch,
    pub(crate) login_index: [u8; 32],
}

/// A live `StateCore` over freshly initialized storage.
pub(crate) struct StateCoreFixture {
    pub(crate) identity: FixtureIdentity,
    pub(crate) opaque: Arc<OpaqueProfile>,
    pub(crate) key_state: LoginIndexKeyState,
    state: Option<StateCore>,
    owner: Option<StorageOwner>,
    storage_receivers: Option<StorageReceivers>,
    crypto_completions: Option<CryptoReceiver>,
    _directory: TestDirectory,
}

/// The owned parts a test needs to drive `StateCore::run` to completion.
pub(crate) struct RunParts {
    pub(crate) state: StateCore,
    pub(crate) storage: tokio::sync::mpsc::Receiver<crate::bridge::StorageCompletionMessage>,
    pub(crate) storage_reads:
        tokio::sync::mpsc::Receiver<crate::bridge::StorageReadCompletionMessage>,
    pub(crate) checkpoints:
        tokio::sync::mpsc::Receiver<crate::bridge::StorageCheckpointCompletionMessage>,
    pub(crate) crypto: CryptoReceiver,
}

type StorageReceivers = (
    tokio::sync::mpsc::Receiver<crate::bridge::StorageCompletionMessage>,
    tokio::sync::mpsc::Receiver<crate::bridge::StorageReadCompletionMessage>,
    tokio::sync::mpsc::Receiver<crate::bridge::StorageCheckpointCompletionMessage>,
);

type CryptoReceiver = tokio::sync::mpsc::Receiver<
    crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
>;

const STORAGE_MASTER: [u8; 32] = [35; 32];
const ROLLBACK_GUARD: [u8; 32] = [36; 32];

/// Initializes live storage under `directory` with the login index key state
/// and the fake OPAQUE record every core needs, and returns the qualification
/// that reopens it.
fn initialize_test_storage(
    identity: &FixtureIdentity,
    directory: &TestDirectory,
    opaque: &OpaqueProfile,
    key_state: &LoginIndexKeyState,
) -> TestResult<StorageQualification> {
    let key_state_record = InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let fake_value = PersistentRecordValue::new(
        TableId::OpaqueRecord,
        LIVE_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        opaque.expose_fake_record_for_persistence().to_vec(),
    )?;
    let fake_record = InitialStorageRecord::new(
        TableId::OpaqueRecord,
        StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
        1,
        fake_value.encode()?,
    )?;
    let qualification = signed_test_qualification(StateDirectory::probe(&directory.0)?)?;
    let state_directory =
        StateDirectory::open(&directory.0, core::slice::from_ref(&qualification))?;
    let initialized = initialize_storage(StorageInitializationConfig {
        state_directory,
        header_tbs: DatabaseHeaderTbs::new(
            identity.network_id,
            identity.server_id,
            identity.server_incarnation,
            DatabaseId::from_bytes([38; 16]),
            1,
            SCHEMA_GENERATION,
            identity.recovery_epoch,
        )?,
        storage_master_key: StorageMasterKey::from_bytes(STORAGE_MASTER),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(ROLLBACK_GUARD),
        mode: StorageInitializationMode::Live,
        initial_records: vec![key_state_record, fake_record],
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: TEST_STORAGE_LIMITS,
    })?;
    if !matches!(initialized, StorageInitializationOutcome::Complete { .. }) {
        return Err("storage initialization was indeterminate".into());
    }
    Ok(qualification)
}

/// Opens the storage owner over initialized storage.
fn open_test_storage(
    identity: &FixtureIdentity,
    directory: &TestDirectory,
    qualification: &StorageQualification,
) -> TestResult<StorageOwner> {
    let state_directory = StateDirectory::open(&directory.0, core::slice::from_ref(qualification))?;
    Ok(StorageOwner::start(StorageOpenConfig {
        expected_network_id: identity.network_id,
        expected_server_id: identity.server_id,
        state_directory,
        storage_master_key: StorageMasterKey::from_bytes(STORAGE_MASTER),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(ROLLBACK_GUARD),
        login_index_key: LoginIndexKey::from_bytes(identity.login_index),
        previous_login_index_key: None,
        limits: TEST_STORAGE_LIMITS,
    })?)
}

/// Reconstructs the durable index and composes the core over the owner.
fn compose_test_state(
    owner: &mut StorageOwner,
    entropy: Vec<u8>,
    router: Box<dyn CommandRouter>,
) -> TestResult<(StateCore, StorageReceivers, CryptoReceiver)> {
    let seed = StateCoreSeed::from_storage(owner)?;
    let storage = seed.storage();
    let keys = KeyDeriver::new(
        StorageMasterKey::from_bytes(STORAGE_MASTER),
        storage.database_binding(),
        storage.storage_key_generation(),
    )?;
    let reconstruction = reconstruct(
        &seed,
        &owner.port(),
        &keys,
        MonotonicTick::from_ticks(10),
        UtcSecond::from_unix_seconds(1_000),
    )?;
    let (storage_bridge, storage_completions, storage_reads, storage_checkpoints) =
        StorageBridge::start(owner.port())?;
    let (crypto_bridge, crypto_completions) =
        CryptoBridge::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
    let storage_limit_writer = owner.take_limit_writer()?;
    let state = StateCore::new(StateCoreInputs {
        config: StateCoreConfig {
            server_prefix: "server.example".to_owned(),
            rate_limits: RateLimits::defaults(),
            ceilings: AccountingCeilings {
                database_max_bytes: TEST_STORAGE_LIMITS.database_max_bytes,
                backup_max_bytes: TEST_STORAGE_LIMITS.backup_max_bytes,
            },
            motd: None,
            public_info: None,
        },
        reconstruction,
        keys,
        bridge: storage_bridge,
        crypto: crypto_bridge,
        budget: Arc::new(MemoryBudget::new(512 * 1_024 * 1_024)),
        liveness: Arc::new(Liveness::new()),
        clocks: StateCoreClocks {
            monotonic: Box::new(DeterministicMonotonicClock::at(10)),
            wall: Box::new(DeterministicWallClock::at(1_000)),
        },
        entropy: Box::new(ScriptedEntropy::new(entropy)?),
        router,
        storage_limit_writer,
    });
    Ok((
        state,
        (storage_completions, storage_reads, storage_checkpoints),
        crypto_completions,
    ))
}

/// The coordinator-only account-service configuration of a fixture.
pub(crate) fn account_service_config(
    identity: &FixtureIdentity,
    opaque: &Arc<OpaqueProfile>,
    key_state: LoginIndexKeyState,
) -> TestResult<AccountServiceConfig> {
    Ok(AccountServiceConfig {
        network_id: identity.network_id,
        server_id: identity.server_id,
        server_incarnation: identity.server_incarnation,
        origin_id: OriginId::from_bytes([39; 16]),
        origin_generation: Generation::new(1)?,
        recovery_epoch: identity.recovery_epoch,
        hpke_private_key: Arc::new(AccountHpkePrivateKey::from_bytes([40; 32])?),
        opaque_profile: Arc::clone(opaque),
        current_login_index_key: Arc::new(LoginIndexKey::from_bytes(identity.login_index)),
        previous_login_index_key: None,
        fake_credential_key: Arc::new(OpaqueFakeCredentialKey::from_bytes([41; 32])),
        login_index_key_state: key_state,
        live_login_keys: BTreeMap::new(),
        login_deletion_tombstones: BTreeMap::new(),
        startup_transaction_cleanups: Vec::new(),
        creation_policy: AccountCreationPolicy::Open,
        default_presence: PresencePolicy::Private,
        default_guest_direct_messages: GuestDirectMessagePolicy::Deny,
        default_direct_messages: DirectMessagePolicy::Allow,
    })
}

/// A channel-key verifier whose hash is the first salt byte repeated.
struct TestChannelKeyVerifier;

impl ChannelKeyVerifier for TestChannelKeyVerifier {
    fn derive(
        &self,
        _secret: &[u8],
        salt: &[u8; CHANNEL_KEY_SALT_BYTES],
    ) -> Result<[u8; CHANNEL_KEY_HASH_BYTES], agenc_ircd_crypto::CryptoError> {
        Ok([salt[0]; CHANNEL_KEY_HASH_BYTES])
    }
}

/// The production registration router over the fixture identity with guests
/// allowed and no connection password.
fn registration_router(
    identity: &FixtureIdentity,
    opaque: &Arc<OpaqueProfile>,
    key_state: LoginIndexKeyState,
) -> TestResult<RegistrationRouter> {
    let verifier: Arc<dyn ChannelKeyVerifier> = Arc::new(TestChannelKeyVerifier);
    let salt = [7; CHANNEL_KEY_SALT_BYTES];
    let hash = verifier.derive(b"dummy", &salt)?;
    let commands =
        RegisteredCommandExecutor::new(verifier, ChannelKeyVerifierRecord::new(salt, hash));
    Ok(RegistrationRouter::new(
        RegistrationRouterConfig {
            network_id: identity.network_id,
            server_id: identity.server_id,
            server_prefix: "server.example".to_owned(),
            display_name: "Test Network".to_owned(),
            allow_guests: true,
            access_token: None,
            account_service: account_service_config(identity, opaque, key_state)?,
        },
        commands,
    )?)
}

impl StateCoreFixture {
    /// Builds the fixture with the pre-composition router that rejects every
    /// line; `entropy` scripts every entropy draw the test makes.
    pub(crate) fn new(entropy: Vec<u8>) -> TestResult<Self> {
        Self::build(entropy, false)
    }

    /// Builds the fixture with the production registration router so lines
    /// register sessions and reach the registered command executor.
    pub(crate) fn with_registration_router(entropy: Vec<u8>) -> TestResult<Self> {
        Self::build(entropy, true)
    }

    fn build(entropy: Vec<u8>, registration: bool) -> TestResult<Self> {
        let identity = FixtureIdentity {
            network_id: NetworkId::from_bytes([31; 32]),
            server_id: ServerId::from_bytes([32; 16]),
            server_incarnation: ServerIncarnation::from_bytes([33; 16]),
            recovery_epoch: RecoveryEpoch::from_bytes([34; 16]),
            login_index: [37; 32],
        };
        let directory = TestDirectory::create()?;
        let opaque = Arc::new(OpaqueProfile::generate(identity.network_id)?);
        let login_key = LoginIndexKey::from_bytes(identity.login_index);
        let key_state = LoginIndexKeyState::stable(1, login_key.key_id(identity.network_id))?;
        let qualification = initialize_test_storage(&identity, &directory, &opaque, &key_state)?;
        let mut owner = open_test_storage(&identity, &directory, &qualification)?;
        let router: Box<dyn CommandRouter> = if registration {
            Box::new(registration_router(&identity, &opaque, key_state)?)
        } else {
            Box::new(DefaultRouter)
        };
        let (state, storage_receivers, crypto_completions) =
            compose_test_state(&mut owner, entropy, router)?;
        Ok(Self {
            identity,
            opaque,
            key_state,
            state: Some(state),
            owner: Some(owner),
            storage_receivers: Some(storage_receivers),
            crypto_completions: Some(crypto_completions),
            _directory: directory,
        })
    }

    /// Moves the core and its completion receivers out so a test can run the
    /// actor loop; the storage owner stays with the fixture until drop.
    pub(crate) fn take_run_parts(&mut self) -> Result<RunParts, RuntimeError> {
        let state = self.state.take().ok_or(RuntimeError::InvalidValue)?;
        let (storage, storage_reads, checkpoints) = self
            .storage_receivers
            .take()
            .ok_or(RuntimeError::InvalidValue)?;
        let crypto = self
            .crypto_completions
            .take()
            .ok_or(RuntimeError::InvalidValue)?;
        Ok(RunParts {
            state,
            storage,
            storage_reads,
            checkpoints,
            crypto,
        })
    }

    /// The live core.
    pub(crate) fn state_mut(&mut self) -> Result<&mut StateCore, RuntimeError> {
        self.state.as_mut().ok_or(RuntimeError::InvalidValue)
    }

    /// The live context owned by the core.
    pub(crate) fn context_mut(&mut self) -> Result<&mut StateCoreContext, RuntimeError> {
        Ok(self.state_mut()?.context_mut())
    }
}

impl Drop for StateCoreFixture {
    fn drop(&mut self) {
        drop(self.state.take());
        if let Some(owner) = self.owner.take() {
            let _shutdown = owner.shutdown();
        }
    }
}

/// Applies one plan to the live domain behind an empty fanout.
pub(crate) fn apply_live_plan(
    context: &mut StateCoreContext,
    plan: agenc_ircd_domain::MutationPlan,
) -> TestResult {
    let request = FanoutRequest::new(Vec::new(), Vec::new())?;
    context
        .apply_ephemeral(plan, request)
        .map_err(|_| "ephemeral apply was refused")?;
    Ok(())
}

/// Creates one account in the live domain.
pub(crate) fn seed_account(
    context: &mut StateCoreContext,
    seed: u8,
    account_generation: u64,
) -> TestResult<(AccountId, Generation)> {
    let account = agenc_ircd_testkit::account_id(seed);
    let account_generation = agenc_ircd_testkit::generation(account_generation)?;
    let plan = context
        .domain()
        .plan_account_created(agenc_ircd_domain::AccountState::new(
            account,
            account_generation,
            context.domain().revision(),
        ))?;
    apply_live_plan(context, plan)?;
    Ok((account, account_generation))
}

/// Opens one session in the live domain the way the testkit does, without
/// binding it to a connection.
pub(crate) fn seed_session(
    context: &mut StateCoreContext,
    seed: u8,
    nickname: &str,
    account: Option<(AccountId, Generation)>,
) -> TestResult<DomainTestIdentity> {
    let session_generation = agenc_ircd_testkit::generation(1)?;
    let (account_id, account_session_generation) = match account {
        Some((account_id, account_generation)) => (Some(account_id), account_generation),
        None => (None, agenc_ircd_testkit::generation(0)?),
    };
    let identity = DomainTestIdentity {
        session_id: SessionId::from_bytes(agenc_ircd_testkit::bytes(seed)),
        user_id: UserId::from_bytes(agenc_ircd_testkit::bytes(seed.wrapping_add(64))),
        generation: session_generation,
        account_id,
    };
    let plan = context
        .domain()
        .plan_session_opened(agenc_ircd_domain::SessionSeed {
            session_id: identity.session_id,
            user_id: identity.user_id,
            home_server_id: ServerId::from_bytes(agenc_ircd_testkit::bytes(240)),
            account_id,
            account_session_generation,
            generation: session_generation,
            nickname: agenc_ircd_domain::NicknameValue::parse(nickname)?,
            display_name: agenc_ircd_domain::DisplayNameValue::prepare(nickname)?,
            public_cloak: agenc_ircd_testkit::deterministic_cloak(seed)?,
            connection_nonce: [seed; 32],
            negotiated_capability_hash: [seed.wrapping_add(1); 32],
            created_at_utc: UtcSecond::from_unix_seconds(1_700_000_000 + u64::from(seed)),
            revision: context.domain().revision(),
        })?;
    apply_live_plan(context, plan)?;
    Ok(identity)
}

/// The bound-session view of a seeded identity.
pub(crate) const fn bound(identity: DomainTestIdentity) -> BoundSession {
    BoundSession {
        session_id: identity.session_id,
        user_id: identity.user_id,
        capability_hash: [0; 32],
    }
}

/// Negotiates `names` from the real core-v1 capability profile of an onion
/// client listener with account creation open.
pub(crate) fn negotiated_capabilities(names: &[&str]) -> TestResult<CapabilityState> {
    let profile = crate::registration::core_capabilities(
        crate::account_service::AccountCreationPolicy::Open,
        RecoveryEpoch::from_bytes([0; 16]),
        crate::purpose::ListenerPurpose::ClientOnion,
    )?;
    let mut capabilities = CapabilityState::default();
    let _listed = capabilities.ls(Some("302"), &profile)?;
    if names.is_empty() {
        return Ok(capabilities);
    }
    if !matches!(
        capabilities.request(&names.join(" "), &profile)?,
        CapRequestReply::Ack(_)
    ) {
        return Err("capability request was refused".into());
    }
    Ok(capabilities)
}

/// Fills one purpose-bound entropy request and returns the next channel seed.
fn answer_entropy(
    purpose: &agenc_ircd_domain::EntropyPurpose,
    inputs: &mut agenc_ircd_domain::ExternalInputs,
    next_channel: u8,
) -> u8 {
    use agenc_ircd_domain::EntropyPurpose;
    use agenc_ircd_testkit::bytes;
    match purpose {
        EntropyPurpose::ChannelInstance(_) => {
            inputs
                .channel_ids
                .push(agenc_ircd_testkit::channel_id(next_channel));
            return next_channel.wrapping_add(1);
        }
        EntropyPurpose::Message(_) => inputs
            .message_ids
            .push(agenc_ircd_types::MessageId::from_bytes(bytes(2))),
        EntropyPurpose::Invite => inputs
            .invite_ids
            .push(agenc_ircd_types::InviteId::from_bytes(bytes(3))),
        EntropyPurpose::MaskEntry(_) => inputs
            .entry_ids
            .push(agenc_ircd_types::EntryId::from_bytes(bytes(4))),
        EntropyPurpose::AccountDeletionChallenge => inputs
            .deletion_tokens
            .push(agenc_ircd_types::AccountDeletionToken::from_bytes(bytes(5))),
    }
    next_channel
}

/// Answers one external request vector deterministically; every fresh channel
/// identity comes from a process-wide counter so repeated creations never
/// collide.
pub(crate) fn answer_external(
    requests: &[agenc_ircd_domain::ExternalInputRequest],
) -> agenc_ircd_domain::ExternalInputs {
    use agenc_ircd_domain::{ExternalInputRequest, ExternalInputs};
    let mut inputs = ExternalInputs::default();
    let mut next_channel =
        u8::try_from(NEXT_CHANNEL_SEED.fetch_add(8, Ordering::Relaxed) % 256).unwrap_or_default();
    for request in requests {
        match request {
            ExternalInputRequest::UtcNow { .. } => {
                inputs.utc_now = Some(UtcSecond::from_unix_seconds(1_720_000_100));
            }
            ExternalInputRequest::MonotonicNow { .. } => {
                inputs.monotonic_now = Some(MonotonicTick::from_ticks(11));
            }
            ExternalInputRequest::Entropy { purpose, .. } => {
                next_channel = answer_entropy(purpose, &mut inputs, next_channel);
            }
            ExternalInputRequest::ChannelKeyVerification { .. } => inputs.key_verdicts.push(true),
            // Key construction needs a crypto verifier; tests that set a key answer it themselves.
            ExternalInputRequest::ChannelKeyConstruction { .. } => {}
        }
    }
    inputs
}

/// Plans one registered command against the live domain, answering any
/// external request vector exactly once.
pub(crate) fn plan_live(
    context: &StateCoreContext,
    identity: DomainTestIdentity,
    command: &dyn Fn()
        -> Result<agenc_ircd_domain::CanonicalCommand, agenc_ircd_domain::DomainError>,
) -> TestResult<agenc_ircd_domain::PlanDecision> {
    use agenc_ircd_domain::PlanDecision;
    // A superset admission: registered-command credit plus message credit
    // for the caller and for every channel the counter could have created.
    let mut entries = vec![
        (
            agenc_ircd_domain::RateBucket::RegisteredCommand(identity.user_id),
            100,
        ),
        (
            agenc_ircd_domain::RateBucket::ExpensiveQuery(identity.user_id),
            100,
        ),
    ];
    entries.push(match identity.account_id {
        Some(account_id) => (
            agenc_ircd_domain::RateBucket::AccountMessage(account_id),
            100,
        ),
        None => (
            agenc_ircd_domain::RateBucket::GuestMessage(identity.user_id),
            100,
        ),
    });
    entries.extend((0..=u8::MAX).map(|seed| {
        (
            agenc_ircd_domain::RateBucket::ChannelMessage(agenc_ircd_testkit::channel_id(seed)),
            100,
        )
    }));
    let admission = agenc_ircd_domain::AdmissionSnapshot::new(entries)?;
    match agenc_ircd_testkit::plan(context.domain(), identity, command()?, &admission, None)? {
        PlanDecision::NeedsExternal(requests) => {
            let inputs = answer_external(&requests);
            Ok(agenc_ircd_testkit::plan(
                context.domain(),
                identity,
                command()?,
                &admission,
                Some(inputs),
            )?)
        }
        decision => Ok(decision),
    }
}

struct NoopLedger;

impl QueueReservationLedger for NoopLedger {
    fn rollback(&self, _frames: usize, _bytes: usize) {}
}

/// A client sink that counts commits and never blocks.
pub(crate) struct FrameSink {
    generation: ConnectionGeneration,
    admit: bool,
    commits: AtomicUsize,
}

impl FrameSink {
    pub(crate) fn new(generation: ConnectionGeneration, admit: bool) -> Arc<Self> {
        Arc::new(Self {
            generation,
            admit,
            commits: AtomicUsize::new(0),
        })
    }

    pub(crate) fn commits(&self) -> usize {
        self.commits.load(Ordering::SeqCst)
    }
}

impl ClientSink for FrameSink {
    fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    fn try_reserve(
        &self,
        demand: ClientQueueDemand,
    ) -> Result<TentativeClientQueueReservation, SinkReserveError> {
        if !self.admit {
            return Err(SinkReserveError::Closed);
        }
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

    fn commit(&self, reservation: ClientQueueReservation, _frames: BoundedSharedClientFrames) {
        self.commits.fetch_add(1, Ordering::SeqCst);
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

/// Opens one onion client connection whose sink admits or refuses every
/// reservation, and binds a seeded session to it.
pub(crate) fn bind_live_session(
    context: &mut StateCoreContext,
    generation: u64,
    identity: DomainTestIdentity,
    capabilities: CapabilityState,
    admit: bool,
) -> TestResult<Arc<FrameSink>> {
    let generation = ConnectionGeneration::new(generation);
    let sink = FrameSink::new(generation, admit);
    let now = context.now();
    context.sessions_mut().open(
        generation,
        crate::purpose::ListenerPurpose::ClientOnion,
        SourceAddressKey::onion_listener(),
        Arc::clone(&sink) as Arc<dyn ClientSink>,
        now,
    )?;
    context
        .sessions_mut()
        .bind_session(generation, bound(identity), capabilities)?;
    Ok(sink)
}
