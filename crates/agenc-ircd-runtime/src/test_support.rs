//! Shared live `StateCore` fixture for unit tests inside the runtime crate.
//!
//! The fixture initializes a private storage directory, opens the storage
//! owner, reconstructs an empty durable index, and composes one `StateCore`
//! with deterministic clocks and scripted entropy. Tests reach the live
//! `StateCoreContext` through `context_mut`.

mod audit;

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
use crate::admission::{BucketKind, RateLimits};
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
use crate::registration::{AccountServiceRole, RegistrationRouter, RegistrationRouterConfig};
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
    records: Vec<InitialStorageRecord>,
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
        initial_records: [key_state_record, fake_record]
            .into_iter()
            .chain(records)
            .collect(),
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
    real_clocks: bool,
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
    // Scripted sessions send many commands within one second, so the actor
    // fixture lifts every bucket far above the production defaults.
    let mut rate_limits = RateLimits::defaults();
    if real_clocks {
        for kind in BucketKind::ALL {
            rate_limits.set(kind, kind.hard_rate())?;
        }
    }
    let state = StateCore::new(StateCoreInputs {
        config: StateCoreConfig {
            server_prefix: "server.example".to_owned(),
            rate_limits,
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
        // The actor loop gathers durable batches against monotonic time, so a
        // frozen clock would never submit them; the synchronous fixture keeps
        // deterministic clocks for exact timer and expiry assertions.
        clocks: if real_clocks {
            StateCoreClocks {
                monotonic: Box::new(crate::clock::SystemMonotonicClock::start()),
                wall: Box::new(crate::clock::SystemWallClock),
            }
        } else {
            StateCoreClocks {
                monotonic: Box::new(DeterministicMonotonicClock::at(10)),
                wall: Box::new(DeterministicWallClock::at(1_000)),
            }
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
pub(crate) struct TestChannelKeyVerifier;

impl ChannelKeyVerifier for TestChannelKeyVerifier {
    fn derive(
        &self,
        _secret: &[u8],
        salt: &[u8; CHANNEL_KEY_SALT_BYTES],
    ) -> Result<[u8; CHANNEL_KEY_HASH_BYTES], agenc_ircd_crypto::CryptoError> {
        Ok([salt[0]; CHANNEL_KEY_HASH_BYTES])
    }
}

/// Which federation role the fixture's router plays.
pub(crate) enum FederationRole {
    Coordinator(Vec<crate::federation::PeerIdentity>),
    Edge(crate::federation::PeerIdentity),
}

/// The companion profile and executor a coordinator fixture starts with.
pub(crate) struct CompanionSetup {
    /// The local ECAP tuple.
    pub(crate) profile: crate::e2ee::link::CompanionProfile,
    /// The executor with its sequencer installed.
    pub(crate) executor: crate::e2ee::coordinator::CompanionCoordinator,
}

/// The coordinator role over the fixture identity with generous outbox
/// ceilings so tests exercise ordering rather than backpressure.
fn federation_coordinator(
    identity: &FixtureIdentity,
    peers: Vec<crate::federation::PeerIdentity>,
) -> TestResult<crate::federation::coordinator::FederationCoordinator> {
    let verifier: Arc<dyn ChannelKeyVerifier> = Arc::new(TestChannelKeyVerifier);
    let salt = [7; CHANNEL_KEY_SALT_BYTES];
    let hash = verifier.derive(b"dummy", &salt)?;
    Ok(crate::federation::coordinator::FederationCoordinator::new(
        crate::federation::coordinator::CoordinatorConfig {
            network_id: identity.network_id,
            server_id: identity.server_id,
            server_name: "server.example".to_owned(),
            recovery_epoch: identity.recovery_epoch,
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        peers,
        verifier,
        ChannelKeyVerifierRecord::new(salt, hash),
    ))
}

/// The production registration router over the fixture identity with guests
/// allowed and no connection password.
fn registration_router(
    identity: &FixtureIdentity,
    opaque: &Arc<OpaqueProfile>,
    key_state: LoginIndexKeyState,
    prefix: &str,
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
            server_prefix: prefix.to_owned(),
            display_name: "TestNetwork".to_owned(),
            allow_guests: true,
            access_token: None,
            account_service: if prefix == "edge.example" {
                // An edge holds no account-service keys (spec 22.2).
                AccountServiceRole::Advertised {
                    creation_policy: AccountCreationPolicy::Open,
                    recovery_epoch: identity.recovery_epoch,
                }
            } else {
                AccountServiceRole::Hosted(Box::new(account_service_config(
                    identity, opaque, key_state,
                )?))
            },
        },
        commands,
    )?)
}

/// The edge role over `router`, with the companion profile and the edge
/// E2EE router attached when `edge_profile` is given.
fn edge_router(
    router: RegistrationRouter,
    identity: &FixtureIdentity,
    prefix: &str,
    coordinator: crate::federation::PeerIdentity,
    edge_profile: Option<crate::e2ee::link::CompanionProfile>,
) -> TestResult<RegistrationRouter> {
    let coordinator_server_id = coordinator.server_id();
    let mut edge =
        crate::federation::edge::EdgeFederation::new(crate::federation::edge::EdgeConfig {
            network_id: identity.network_id,
            server_id: identity.server_id,
            server_name: prefix.to_owned(),
            incarnation: identity.server_incarnation,
            coordinator,
        });
    let Some(profile) = edge_profile else {
        return Ok(router.with_edge(edge));
    };
    edge.set_companion_profile(Some(profile));
    let e2ee = crate::e2ee::edge::E2eeEdge::new(crate::e2ee::edge::E2eeEdgeConfig {
        network_id: *identity.network_id.as_bytes(),
        server_id: identity.server_id,
        server_name: prefix.to_owned(),
        coordinator_server_id,
        incarnation: *identity.server_incarnation.as_bytes(),
        global_disk_bytes: 1 << 30,
    });
    Ok(router.with_edge(edge).with_e2ee_edge(e2ee)?)
}

impl StateCoreFixture {
    /// Stops the storage owner and reconstructs a registration core from the same directory.
    pub(crate) fn restart_registration_storage(&mut self, entropy: Vec<u8>) -> TestResult {
        drop(self.state.take());
        drop(self.storage_receivers.take());
        drop(self.crypto_completions.take());
        let owner = self.owner.take().ok_or("storage owner")?;
        owner.shutdown()?;
        let qualification = signed_test_qualification(StateDirectory::probe(&self._directory.0)?)?;
        let mut owner = open_test_storage(&self.identity, &self._directory, &qualification)?;
        let router = registration_router(
            &self.identity,
            &self.opaque,
            self.key_state,
            "server.example",
        )?;
        let (state, storage_receivers, crypto_completions) =
            compose_test_state(&mut owner, entropy, Box::new(router), true)?;
        self.owner = Some(owner);
        self.state = Some(state);
        self.storage_receivers = Some(storage_receivers);
        self.crypto_completions = Some(crypto_completions);
        Ok(())
    }

    /// Exercises the daemon's authenticated edge reload against this fixture's storage.
    pub(crate) fn restore_edge_state(
        &self,
        edge: &mut crate::federation::edge::EdgeFederation,
        companion: Option<&mut crate::e2ee::edge::E2eeEdge>,
    ) -> TestResult {
        let owner = self.owner.as_ref().ok_or("storage owner")?;
        let recovered = owner.recovered_state();
        let keys = KeyDeriver::new(
            StorageMasterKey::from_bytes(STORAGE_MASTER),
            recovered.database_binding(),
            recovered.storage_key_generation(),
        )?;
        edge.restore(
            &owner.port(),
            &keys,
            companion,
            self.state.as_ref().map_or_else(
                || crate::state_core::durable::HeadCounters::from_recovered(recovered),
                |state| state.context().head(),
            ),
            self.state
                .as_ref()
                .map(|state| state.context().backing_reservations()),
        )?;
        Ok(())
    }

    /// Commits a crash image through real storage, then reloads a fresh edge owner.
    pub(crate) fn commit_and_restore_edge(
        &mut self,
        writes: Vec<crate::state_core::durable::AccountServiceDurableWrite>,
        edge: &mut crate::federation::edge::EdgeFederation,
        companion: Option<&mut crate::e2ee::edge::E2eeEdge>,
    ) -> TestResult {
        use crate::state_core::durable::{PlanProjection, project_batch};
        let owner = self.owner.as_ref().ok_or("storage owner")?;
        let recovered = owner.recovered_state();
        let keys = KeyDeriver::new(
            StorageMasterKey::from_bytes(STORAGE_MASTER),
            recovered.database_binding(),
            recovered.storage_key_generation(),
        )?;
        let context = self.state.as_mut().ok_or("state")?.context_mut();
        let plan = context.domain().plan_account_service_checkpoint()?;
        let plans = [PlanProjection {
            plan: &plan,
            response_count_increment: 0,
            account_service_writes: &writes,
        }];
        let mut entropy = ScriptedEntropy::new(vec![44; 4096])?;
        let projected = project_batch(
            agenc_ircd_types::TransactionId::from_bytes([54; 16]),
            &plans,
            context.index(),
            &keys,
            context.head(),
            AccountingCeilings {
                database_max_bytes: TEST_STORAGE_LIMITS.database_max_bytes,
                backup_max_bytes: TEST_STORAGE_LIMITS.backup_max_bytes,
            },
            &mut entropy,
        )?
        .ok_or("empty image")?;
        let (batch, retained) = projected.into_parts();
        let agenc_ircd_storage::CommitOutcome::Committed(receipt) =
            owner.port().try_commit(batch)?.wait()?
        else {
            return Err("image commit refused".into());
        };
        edge.restore(
            &owner.port(),
            &keys,
            companion,
            retained.advance(&receipt),
            Some(context.backing_reservations()),
        )?;
        Ok(())
    }

    pub(crate) fn stored_row_exists(&self, table: TableId, key: StoredKey) -> TestResult<bool> {
        let owner = self.owner.as_ref().ok_or("storage owner")?;
        let result = crate::bridge::storage::read_blocking(
            &owner.port(),
            agenc_ircd_storage::ReadPlan::exact(table, key),
        )?;
        Ok(!result.records.is_empty())
    }

    /// Reconstructs the durable account-service state from the live owner and
    /// counts the stale transaction cleanups a restart would schedule.
    pub(crate) fn recovered_startup_cleanup_count(&self) -> TestResult<usize> {
        let owner = self.owner.as_ref().ok_or("storage owner")?;
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
        Ok(reconstruction
            .account_service
            .startup_transaction_cleanups()
            .len())
    }

    /// Reads one plan through the fixture's live storage port.
    pub(crate) fn read_rows(
        &self,
        plan: agenc_ircd_storage::ReadPlan,
    ) -> TestResult<agenc_ircd_storage::ReadResult> {
        let owner = self.owner.as_ref().ok_or("storage owner")?;
        Ok(crate::bridge::storage::read_blocking(&owner.port(), plan)?)
    }

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

    /// Like `with_registration_router`, over storage that already holds
    /// `records`, as a restarted process finds them.
    pub(crate) fn with_registration_router_and_records(
        entropy: Vec<u8>,
        records: Vec<InitialStorageRecord>,
    ) -> TestResult<Self> {
        Self::build_with(entropy, true, None, records)
    }

    /// The next storage read completion, for a test that drives a router's
    /// reload by hand instead of running the actor loop.
    pub(crate) async fn next_storage_read(
        &mut self,
    ) -> TestResult<crate::bridge::StorageReadCompletionMessage> {
        let receivers = self
            .storage_receivers
            .as_mut()
            .ok_or("storage receivers were taken")?;
        receivers
            .1
            .recv()
            .await
            .ok_or_else(|| "storage read channel closed".into())
    }

    /// Builds the fixture with the registration router acting as the
    /// federation coordinator for `peers`, with the projector installed.
    pub(crate) fn with_federation_coordinator(
        entropy: Vec<u8>,
        peers: Vec<crate::federation::PeerIdentity>,
    ) -> TestResult<Self> {
        let mut fixture = Self::build_with(
            entropy,
            true,
            Some(FederationRole::Coordinator(peers)),
            Vec::new(),
        )?;
        let network_id = fixture.identity.network_id;
        let server_id = fixture.identity.server_id;
        fixture.context_mut()?.install_federation_projector(
            crate::state_core::projector::FederationProjector::new(network_id, server_id),
        );
        Ok(fixture)
    }

    fn build(entropy: Vec<u8>, registration: bool) -> TestResult<Self> {
        Self::build_with(entropy, registration, None, Vec::new())
    }

    /// Builds the fixture with the registration router acting as an edge of
    /// `coordinator`.
    pub(crate) fn with_edge(
        entropy: Vec<u8>,
        coordinator: crate::federation::PeerIdentity,
    ) -> TestResult<Self> {
        Self::build_with(
            entropy,
            true,
            Some(FederationRole::Edge(coordinator)),
            Vec::new(),
        )
    }

    fn build_with(
        entropy: Vec<u8>,
        registration: bool,
        role: Option<FederationRole>,
        records: Vec<InitialStorageRecord>,
    ) -> TestResult<Self> {
        Self::build_with_companion(entropy, registration, role, records, None, None)
    }

    /// Builds an edge fixture whose edge role negotiates the companion
    /// profile and routes E2EE client lines through the edge E2EE router.
    pub(crate) fn with_e2ee_edge(
        entropy: Vec<u8>,
        coordinator: crate::federation::PeerIdentity,
        profile: crate::e2ee::link::CompanionProfile,
    ) -> TestResult<Self> {
        Self::build_with_companion(
            entropy,
            true,
            Some(FederationRole::Edge(coordinator)),
            Vec::new(),
            None,
            Some(profile),
        )
    }

    /// Builds a coordinator fixture whose federation coordinator carries the
    /// companion profile and executor before any link exists.
    pub(crate) fn with_companion_coordinator(
        entropy: Vec<u8>,
        peers: Vec<crate::federation::PeerIdentity>,
        companion: CompanionSetup,
    ) -> TestResult<Self> {
        let mut fixture = Self::build_with_companion(
            entropy,
            true,
            Some(FederationRole::Coordinator(peers)),
            Vec::new(),
            Some(companion),
            None,
        )?;
        let network_id = fixture.identity.network_id;
        let server_id = fixture.identity.server_id;
        fixture.context_mut()?.install_federation_projector(
            crate::state_core::projector::FederationProjector::new(network_id, server_id),
        );
        Ok(fixture)
    }

    fn build_with_companion(
        entropy: Vec<u8>,
        registration: bool,
        role: Option<FederationRole>,
        records: Vec<InitialStorageRecord>,
        companion: Option<CompanionSetup>,
        edge_profile: Option<crate::e2ee::link::CompanionProfile>,
    ) -> TestResult<Self> {
        // An edge fixture carries its own server identity so it never shares
        // the coordinator fixture's Server ID inside one test.
        let edge_role = matches!(role, Some(FederationRole::Edge(_)));
        let identity = FixtureIdentity {
            network_id: NetworkId::from_bytes([31; 32]),
            server_id: ServerId::from_bytes(if edge_role { [36; 16] } else { [32; 16] }),
            server_incarnation: ServerIncarnation::from_bytes(if edge_role {
                [35; 16]
            } else {
                [33; 16]
            }),
            recovery_epoch: RecoveryEpoch::from_bytes([34; 16]),
            login_index: [37; 32],
        };
        let prefix = if edge_role {
            "edge.example"
        } else {
            "server.example"
        };
        let directory = TestDirectory::create()?;
        let opaque = Arc::new(OpaqueProfile::generate(identity.network_id)?);
        let login_key = LoginIndexKey::from_bytes(identity.login_index);
        let key_state = LoginIndexKeyState::stable(1, login_key.key_id(identity.network_id))?;
        let qualification =
            initialize_test_storage(&identity, &directory, &opaque, &key_state, records)?;
        let mut owner = open_test_storage(&identity, &directory, &qualification)?;
        let router: Box<dyn CommandRouter> = match (registration, role) {
            (true, Some(FederationRole::Coordinator(peers))) => {
                let mut coordinator = federation_coordinator(&identity, peers)?;
                if let Some(setup) = companion {
                    coordinator.set_companion_profile(Some(setup.profile));
                    coordinator
                        .install_companion_executor(setup.executor, identity.server_incarnation)?;
                }
                Box::new(
                    registration_router(&identity, &opaque, key_state, prefix)?
                        .with_federation(coordinator),
                )
            }
            (true, Some(FederationRole::Edge(coordinator))) => {
                let router = registration_router(&identity, &opaque, key_state, prefix)?;
                Box::new(edge_router(
                    router,
                    &identity,
                    prefix,
                    coordinator,
                    edge_profile,
                )?)
            }
            (true, None) => Box::new(registration_router(&identity, &opaque, key_state, prefix)?),
            (false, _) => Box::new(DefaultRouter),
        };
        let (state, storage_receivers, crypto_completions) =
            compose_test_state(&mut owner, entropy, router, registration)?;
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

impl StateCoreFixture {
    /// Settles one staged component batch through storage and authenticated readback.
    pub(crate) async fn commit_staged_batch(&mut self) -> TestResult {
        let state = self.state.as_mut().ok_or("state")?;
        let (storage, reads, _) = self.storage_receivers.as_mut().ok_or("storage receivers")?;
        state.commit_fixture_batch(storage, reads).await
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

/// A session seed homed on a remote edge, for coordinator tests.
pub(crate) fn remote_session_seed(
    context: &mut StateCoreContext,
    home: ServerId,
    nickname: &str,
) -> TestResult<agenc_ircd_domain::SessionSeed> {
    let seed = home.as_bytes()[0];
    Ok(agenc_ircd_domain::SessionSeed {
        session_id: SessionId::from_bytes(agenc_ircd_testkit::bytes(seed)),
        user_id: UserId::from_bytes(agenc_ircd_testkit::bytes(seed.wrapping_add(64))),
        home_server_id: home,
        account_id: None,
        account_session_generation: agenc_ircd_testkit::generation(0)?,
        generation: agenc_ircd_testkit::generation(1)?,
        nickname: agenc_ircd_domain::NicknameValue::parse(nickname)?,
        display_name: agenc_ircd_domain::DisplayNameValue::prepare(nickname)?,
        public_cloak: agenc_ircd_testkit::deterministic_cloak(seed)?,
        connection_nonce: [seed; 32],
        negotiated_capability_hash: [seed.wrapping_add(1); 32],
        created_at_utc: UtcSecond::from_unix_seconds(1_700_000_000 + u64::from(seed)),
        revision: context.domain().revision(),
    })
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

/// A client sink that records every delivered line and never blocks.
pub(crate) struct FrameSink {
    generation: ConnectionGeneration,
    admit: bool,
    commits: AtomicUsize,
    lines: std::sync::Mutex<Vec<String>>,
}

impl FrameSink {
    pub(crate) fn new(generation: ConnectionGeneration, admit: bool) -> Arc<Self> {
        Arc::new(Self {
            generation,
            admit,
            commits: AtomicUsize::new(0),
            lines: std::sync::Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn commits(&self) -> usize {
        self.commits.load(Ordering::SeqCst)
    }

    /// Every line delivered so far, in order, without the trailing CRLF.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|lines| lines.clone())
            .unwrap_or_default()
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

    fn commit(&self, reservation: ClientQueueReservation, frames: BoundedSharedClientFrames) {
        self.commits.fetch_add(1, Ordering::SeqCst);
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
        // Recorded frames have already drained from this nonblocking test sink.
        ClientQueueSnapshot::new(0, 1_048_576)
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

/// The golden public configuration parsed at document depth.
pub(crate) fn golden_config() -> TestResult<agenc_ircd_config::Config> {
    const PUBLIC: &str = include_str!("../../agenc-ircd-config/tests/golden/public.toml");
    Ok(agenc_ircd_config::Config::parse_text(
        PUBLIC,
        &agenc_ircd_config::PathResolver::none(),
        agenc_ircd_config::ValidationDepth::Document,
    )?)
}

/// One observe-only operator so the registry is non-empty.
fn golden_operators() -> TestResult<agenc_ircd_admin::OperatorRegistry> {
    use agenc_ircd_types::{AdminPermission, AdminPermissionSet, OperatorId};
    let mut permissions = AdminPermissionSet::EMPTY;
    permissions.insert(AdminPermission::Observe);
    Ok(agenc_ircd_admin::OperatorRegistry::from_records(vec![
        agenc_ircd_admin::OperatorRecord::new(
            OperatorId::from_bytes([4; 16]),
            Ed25519SecretKey::from_bytes([5; 32]).public_key(),
            None,
            vec![1_000],
            Vec::new(),
            permissions,
            true,
        )?,
    ])?)
}

/// Runtime parts for the golden configuration; `display_name` and `motd`
/// are the live values a reload test varies.
pub(crate) fn golden_parts(
    display_name: &str,
    motd: Option<&str>,
) -> TestResult<crate::runtime_config::RuntimeConfigParts> {
    use agenc_ircd_domain::{OperationalLimitValues, OperationalLimits};
    Ok(crate::runtime_config::RuntimeConfigParts {
        tls_endpoints: BTreeMap::new(),
        certificate_fingerprints: BTreeMap::new(),
        ocsp_fingerprints: BTreeMap::new(),
        restart_material: crate::runtime_config::RestartMaterial::default(),
        motd: motd.map(Arc::from),
        public_info: None,
        display_name: Arc::from(display_name),
        operators: golden_operators()?,
        operator_admission: crate::admin::AdminAdmissionSnapshot::new(
            vec![1_000],
            Vec::new(),
            Vec::new(),
        ),
        account_policy: crate::runtime_config::AccountRuntimePolicy {
            allow_guests: true,
            creation: AccountCreationPolicy::Open,
            default_presence: PresencePolicy::Private,
            default_guest_direct_messages: GuestDirectMessagePolicy::Deny,
            default_direct_messages: DirectMessagePolicy::Contacts,
        },
        rates: RateLimits::defaults(),
        operational_limits: OperationalLimits::new(OperationalLimitValues {
            sessions_per_account: 8,
            channels_per_session: 64,
            members_per_channel: 4_096,
            global_channels: 100_000,
            local_channels: 10_000,
            invites_per_channel: 256,
            invites_per_principal: 32,
            invites_global: 100_000,
            contacts_per_account: 1_000,
        })?,
        connection_limits: crate::connection::ConnectionLimits::DEFAULT,
        storage_limits: agenc_ircd_storage::StorageRuntimeLimits::new(1 << 30, 1 << 31, 10_000)?,
        shutdown: crate::supervisor::ShutdownPlan::DEFAULT,
    })
}

/// The initial runtime configuration snapshot over the golden configuration.
pub(crate) fn golden_snapshot(
    display_name: &str,
    motd: Option<&str>,
) -> TestResult<Arc<crate::runtime_config::RuntimeConfigSnapshot>> {
    Ok(Arc::new(
        crate::runtime_config::RuntimeConfigSnapshot::from_parts(
            crate::runtime_config::ConfigRevision::INITIAL,
            golden_config()?,
            golden_parts(display_name, motd)?,
        ),
    ))
}

impl StateCoreFixture {
    /// Installs the private admin channel and returns its port.
    pub(crate) fn install_admin_port(
        &mut self,
    ) -> TestResult<crate::state_core::admin::AdminCorePort> {
        let (port, inbox) = crate::state_core::admin::admin_core_channel();
        self.state_mut()?.install_admin_inbox(inbox)?;
        Ok(port)
    }

    /// Installs the private reload channel over `handle` and returns its port
    /// together with the transport admission the reload updates.
    pub(crate) fn install_reload_port(
        &mut self,
        handle: crate::runtime_config::RuntimeConfigHandle,
    ) -> TestResult<(
        crate::runtime_config::ReloadPort,
        Arc<crate::admission::TransportAdmission>,
    )> {
        let admission = Arc::new(crate::admission::TransportAdmission::new(
            handle.load().rates(),
            1,
            Arc::new(MemoryBudget::new(64 * 1_024 * 1_024)),
            Box::new(crate::clock::SystemMonotonicClock::start()),
        )?);
        let (port, inbox) = crate::runtime_config::reload_channel(handle, Arc::clone(&admission));
        self.state_mut()?.install_reload_inbox(inbox)?;
        Ok((port, admission))
    }
}

/// A sealed authentication-start envelope for the fixture's account service:
/// the OPAQUE KE1 carries valid group elements so the server round runs.
pub(crate) fn sealed_authentication_start(
    network_id: agenc_ircd_types::NetworkId,
    recovery_epoch: agenc_ircd_types::RecoveryEpoch,
    login: &str,
    request_seed: u8,
) -> TestResult<Vec<u8>> {
    use agenc_ircd_auth::{
        AccountRequestPayload, AccountServiceEnvelope, AuthenticationStart, OpaqueKe1,
        encode_request_plaintext,
    };
    use agenc_ircd_crypto::{AccountHpkePrivateKey, AccountRequestBinding, seal_account_request};
    const BASEPOINT: [u8; 32] = [
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51,
        0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d,
        0x2d, 0x76,
    ];
    let private_key = AccountHpkePrivateKey::from_bytes([40; 32])?;
    let public_key = private_key.public_key()?;
    let mut ke1 = [0_u8; 96];
    ke1[..32].copy_from_slice(&BASEPOINT);
    ke1[32..64].copy_from_slice(&[7; 32]);
    ke1[64..].copy_from_slice(&BASEPOINT);
    let payload = AccountRequestPayload::AuthenticationStart(AuthenticationStart {
        network_id,
        login: agenc_ircd_types::NormalizedLogin::prepare(login)?,
        ke1: OpaqueKe1::from_bytes(ke1)?,
    });
    let binding = AccountRequestBinding::new(
        network_id,
        recovery_epoch,
        public_key.key_id(),
        agenc_ircd_types::RequestId::from_bytes([request_seed; 16]),
        payload.message_kind(),
    );
    let plaintext = encode_request_plaintext(&payload)?;
    let (sealed, _token) = seal_account_request(public_key, binding, plaintext.expose_for_hpke())?;
    Ok(AccountServiceEnvelope::from_sealed(sealed)?
        .as_bytes()
        .to_vec())
}

/// A sealed authentication-finish envelope for the fixture's account
/// service; the edge relays it without opening it.
pub(crate) fn sealed_authentication_finish(
    network_id: agenc_ircd_types::NetworkId,
    recovery_epoch: agenc_ircd_types::RecoveryEpoch,
    request_seed: u8,
) -> TestResult<Vec<u8>> {
    use agenc_ircd_auth::{
        AccountRequestPayload, AccountServiceEnvelope, AuthenticationFinish, OpaqueKe3,
        encode_request_plaintext,
    };
    use agenc_ircd_crypto::{AccountHpkePrivateKey, AccountRequestBinding, seal_account_request};
    let private_key = AccountHpkePrivateKey::from_bytes([40; 32])?;
    let public_key = private_key.public_key()?;
    let payload = AccountRequestPayload::AuthenticationFinish(AuthenticationFinish {
        network_id,
        transaction_id: agenc_ircd_types::TransactionId::from_bytes([request_seed; 16]),
        ke3: OpaqueKe3::from_bytes([3; 64])?,
    });
    let binding = AccountRequestBinding::new(
        network_id,
        recovery_epoch,
        public_key.key_id(),
        agenc_ircd_types::RequestId::from_bytes([request_seed; 16]),
        payload.message_kind(),
    );
    let plaintext = encode_request_plaintext(&payload)?;
    let (sealed, _token) = seal_account_request(public_key, binding, plaintext.expose_for_hpke())?;
    Ok(AccountServiceEnvelope::from_sealed(sealed)?
        .as_bytes()
        .to_vec())
}
