//! Shared live `StateCore` fixture for unit tests inside the runtime crate.
//!
//! The fixture initializes a private storage directory, opens the storage
//! owner, reconstructs an empty durable index, and composes one `StateCore`
//! with deterministic clocks and scripted entropy. Tests reach the live
//! `StateCoreContext` through `context_mut`.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use agenc_ircd_auth::OpaqueProfile;
use agenc_ircd_crypto::{
    CryptoWorkerConfig, Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, StorageDigest,
    StorageMasterKey,
};
use agenc_ircd_storage::{
    DatabaseHeaderTbs, InitialStorageRecord, LIVE_RECORD_KIND, LOGIN_INDEX_KEY_STATE_KEY,
    LoginIndexKeyState, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue, QualificationTarget,
    SCHEMA_GENERATION, StateDirectory, StorageEngineLimits, StorageGrowthCase,
    StorageInitializationConfig, StorageInitializationMode, StorageInitializationOutcome,
    StorageOpenConfig, StorageOwner, StorageQualification, StorageQualificationReport,
    StorageQualificationReportTbs, StoredKey, TableId, initialize_storage,
};
use agenc_ircd_testkit::{DeterministicMonotonicClock, DeterministicWallClock, ScriptedEntropy};
use agenc_ircd_types::{
    DatabaseId, MonotonicTick, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation, UtcSecond,
};

use crate::RuntimeError;
use crate::StateCoreSeed;
use crate::admission::RateLimits;
use crate::bridge::crypto::CryptoBridge;
use crate::bridge::storage::StorageBridge;
use crate::budget::MemoryBudget;
use crate::observe::health::Liveness;
use crate::state_core::durable::{AccountingCeilings, KeyDeriver};
use crate::state_core::reconstruct::reconstruct;
use crate::state_core::{
    DefaultRouter, StateCore, StateCoreClocks, StateCoreConfig, StateCoreContext, StateCoreInputs,
};
use crate::sync::Arc;

/// Boxed error alias for fixture construction and test bodies.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    _storage_completions: tokio::sync::mpsc::Receiver<crate::bridge::StorageCompletionMessage>,
    _storage_reads: tokio::sync::mpsc::Receiver<crate::bridge::StorageReadCompletionMessage>,
    _storage_checkpoints:
        tokio::sync::mpsc::Receiver<crate::bridge::StorageCheckpointCompletionMessage>,
    _crypto_completions: tokio::sync::mpsc::Receiver<
        crate::bridge::CryptoCompletionMessage<crate::bridge::crypto::CryptoJobOutput>,
    >,
    _directory: TestDirectory,
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
        router: Box::new(DefaultRouter),
        storage_limit_writer,
    });
    Ok((
        state,
        (storage_completions, storage_reads, storage_checkpoints),
        crypto_completions,
    ))
}

impl StateCoreFixture {
    /// Builds the fixture; `entropy` scripts every entropy draw the test makes.
    pub(crate) fn new(entropy: Vec<u8>) -> TestResult<Self> {
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
        let (state, storage_receivers, crypto_completions) =
            compose_test_state(&mut owner, entropy)?;
        let (storage_completions, storage_reads, storage_checkpoints) = storage_receivers;
        Ok(Self {
            identity,
            opaque,
            key_state,
            state: Some(state),
            owner: Some(owner),
            _storage_completions: storage_completions,
            _storage_reads: storage_reads,
            _storage_checkpoints: storage_checkpoints,
            _crypto_completions: crypto_completions,
            _directory: directory,
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
