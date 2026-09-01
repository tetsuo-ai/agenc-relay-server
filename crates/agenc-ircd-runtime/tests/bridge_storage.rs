//! Storage bridge behavior against a real storage owner (spec 21.5, lines
//! 4173-4210).
#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agenc_ircd_crypto::{
    Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, StorageDigest, StorageMasterKey,
};
use agenc_ircd_domain::{
    DirectMessagePolicy, DurableAccount, GuestDirectMessagePolicy, PresencePolicy,
};
use agenc_ircd_runtime::bridge::storage::{
    BridgeFailure, CompletionLedger, STORAGE_HANDOFF_CAPACITY, StorageBridge, SubmitError,
    classify_completion,
};
use agenc_ircd_storage::{
    AccountRecordBody, CheckpointOutcome, CommitOutcome, DatabaseHeaderTbs, InitialStorageRecord,
    LoginIndexKeyState, PersistentRecordValue, QualificationTarget, ReadPlan, RecordMutation,
    SCHEMA_GENERATION, StateDirectory, StorageAccountingLimits, StorageEngineLimits, StorageError,
    StorageFaultBoundary, StorageFaultCase, StorageFaultInjector, StorageFaultSite,
    StorageGrowthCase, StorageInitializationConfig, StorageInitializationMode,
    StorageInitializationOutcome, StorageMutationBatch, StorageMutationHead, StorageOpenConfig,
    StorageOwner, StorageQualification, StorageQualificationReport, StorageQualificationReportTbs,
    StoredKey, TableId, initialize_storage,
};
use agenc_ircd_types::{
    AccountRandomId, DatabaseId, Generation, NetworkId, RecoveryEpoch, Revision, ServerId,
    ServerIncarnation, TransactionId,
};

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agenc-ircd-bridge-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const LIMITS: StorageEngineLimits = StorageEngineLimits {
    redb_cache_bytes: 8 * 1_024 * 1_024,
    fixed_reserve_bytes: 64 * 1_024 * 1_024,
    reserve_percent: 1,
    database_max_bytes: 1_073_741_824,
    backup_max_bytes: 2_147_483_648,
    integrity_checkpoint_manifests: 100_000,
};

fn network() -> NetworkId {
    NetworkId::from_bytes([13; 32])
}

fn server() -> ServerId {
    ServerId::from_bytes([14; 16])
}

fn signed_test_qualification(
    tuple: agenc_ircd_storage::FilesystemTuple,
) -> Result<StorageQualification, Box<dyn Error>> {
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

/// An initialized directory plus the accounting the first batch must carry.
struct Initialized {
    directory: TestDirectory,
    qualification: StorageQualification,
    logical_database_bytes: u64,
    backup_stream_bytes: u64,
}

fn initialize() -> Result<Initialized, Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let tuple = StateDirectory::probe(directory.path())?;
    let qualification = signed_test_qualification(tuple)?;
    let login_key = LoginIndexKey::from_bytes([15; 32]);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(network()))?;
    let initial = InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let state_directory = StateDirectory::open(directory.path(), &[qualification])?;
    let outcome = initialize_storage(StorageInitializationConfig {
        state_directory,
        header_tbs: DatabaseHeaderTbs::new(
            network(),
            server(),
            ServerIncarnation::from_bytes([16; 16]),
            DatabaseId::from_bytes([17; 16]),
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([18; 16]),
        )?,
        storage_master_key: StorageMasterKey::from_bytes([19; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([20; 32]),
        mode: StorageInitializationMode::Live,
        initial_records: vec![initial],
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: LIMITS,
    })?;
    let (logical_database_bytes, backup_stream_bytes) = match outcome {
        StorageInitializationOutcome::Complete {
            logical_database_bytes,
            backup_stream_bytes,
            ..
        } => (logical_database_bytes, backup_stream_bytes),
        StorageInitializationOutcome::Indeterminate => {
            return Err("initialization was indeterminate".into());
        }
    };
    Ok(Initialized {
        directory,
        qualification,
        logical_database_bytes,
        backup_stream_bytes,
    })
}

fn open_owner(
    initialized: &Initialized,
    faults: StorageFaultInjector,
) -> Result<StorageOwner, Box<dyn Error>> {
    let state_directory = StateDirectory::open_with_faults(
        initialized.directory.path(),
        &[initialized.qualification],
        faults,
    )?;
    Ok(StorageOwner::start(StorageOpenConfig {
        expected_network_id: network(),
        expected_server_id: server(),
        state_directory,
        storage_master_key: StorageMasterKey::from_bytes([19; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([20; 32]),
        login_index_key: LoginIndexKey::from_bytes([15; 32]),
        previous_login_index_key: None,
        limits: LIMITS,
    })?)
}

fn account_key(seed: u8) -> Result<StoredKey, StorageError> {
    StoredKey::new(
        AccountRandomId::from_bytes([seed; 16])
            .to_text()
            .into_bytes(),
    )
}

fn batch(
    initialized: &Initialized,
    transaction: u8,
    expected_commit_sequence: u64,
    expected_generation: u64,
) -> Result<StorageMutationBatch, Box<dyn Error>> {
    // Live account rows carry a decodable body since the persistence boundary
    // landed; an opaque body is rejected at commit time.
    let account = DurableAccount {
        account_id: AccountRandomId::from_bytes([transaction; 16]).to_account_id(),
        label: None,
        presence: PresencePolicy::Private,
        guest_direct_messages: GuestDirectMessagePolicy::Allow,
        direct_messages: DirectMessagePolicy::Allow,
        contacts: Vec::new(),
        reserved_nicknames: Vec::new(),
        session_generation: Generation::new(1)?,
        revision: Revision::new(1)?,
        admin_suspension_expires_at: None,
    };
    let value = PersistentRecordValue::new(
        TableId::Account,
        1,
        1,
        1,
        None,
        Vec::new(),
        AccountRecordBody::encode(&account)?,
    )?
    .encode()?;
    let mutation =
        RecordMutation::put(TableId::Account, account_key(transaction)?, 1, None, value)?;
    Ok(StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([transaction; 16]),
            expected_storage_commit_sequence: expected_commit_sequence,
            expected_state_generation: expected_generation,
            resulting_state_generation: expected_generation + 1,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: initialized.logical_database_bytes,
            current_backup_stream_bytes: initialized.backup_stream_bytes,
            database_max_bytes: LIMITS.database_max_bytes,
            backup_max_bytes: LIMITS.backup_max_bytes,
        },
        vec![mutation],
    )?)
}

async fn next_outcome(
    receiver: &mut tokio::sync::mpsc::Receiver<
        agenc_ircd_runtime::bridge::StorageCompletionMessage,
    >,
) -> Result<agenc_ircd_runtime::bridge::StorageCompletionMessage, Box<dyn Error>> {
    Ok(
        tokio::time::timeout(Duration::from_secs(60), receiver.recv())
            .await?
            .ok_or("completion channel closed")?,
    )
}

async fn next_checkpoint_outcome(
    receiver: &mut tokio::sync::mpsc::Receiver<
        agenc_ircd_runtime::bridge::StorageCheckpointCompletionMessage,
    >,
) -> Result<agenc_ircd_runtime::bridge::StorageCheckpointCompletionMessage, Box<dyn Error>> {
    Ok(
        tokio::time::timeout(Duration::from_secs(60), receiver.recv())
            .await?
            .ok_or("checkpoint completion channel closed")?,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_and_rejected_outcomes_arrive_with_their_transaction_ids()
-> Result<(), Box<dyn Error>> {
    let initialized = initialize()?;
    let owner = open_owner(&initialized, StorageFaultInjector::disabled())?;
    let (mut bridge, mut receiver, mut read_receiver, mut checkpoint_receiver) =
        StorageBridge::start(owner.port())?;
    assert_eq!(bridge.in_flight(), 0);
    let first = batch(&initialized, 1, 0, 0)?;
    let first_id = first.transaction_id();
    let first_logical = first.resulting_logical_database_bytes();
    assert_eq!(bridge.submit(first)?, first_id);
    assert_eq!(bridge.in_flight(), 1);
    let message = next_outcome(&mut receiver).await?;
    assert_eq!(message.transaction_id, first_id);
    match message.outcome {
        CommitOutcome::Committed(receipt) => {
            assert_eq!(receipt.transaction_id, first_id);
            assert_eq!(receipt.storage_commit_sequence, 1);
            assert_eq!(receipt.state_generation, 1);
        }
        CommitOutcome::Rejected(error) => return Err(error.into()),
        CommitOutcome::Indeterminate => return Err("first commit was indeterminate".into()),
    }
    assert_eq!(bridge.in_flight(), 0);
    assert!(bridge.failure().is_none());

    // A stale head is rejected before anything irreversible begins.
    let stale = batch(&initialized, 2, 0, 0)?;
    let stale_id = bridge.submit(stale)?;
    let message = next_outcome(&mut receiver).await?;
    assert_eq!(message.transaction_id, stale_id);
    assert!(matches!(
        message.outcome,
        CommitOutcome::Rejected(StorageError::StaleState)
    ));

    // Live reads use their own bounded completion lane and retain their
    // process-local identity.
    let read_id = bridge.submit_read(ReadPlan::exact(TableId::Account, account_key(1)?))?;
    let read_message = tokio::time::timeout(Duration::from_secs(60), read_receiver.recv())
        .await?
        .ok_or("read completion channel closed")?;
    assert_eq!(read_message.read_id, read_id);
    let read = read_message.result?;
    assert_eq!(read.records.len(), 1);
    assert!(first_logical > initialized.logical_database_bytes);

    let checkpoint_id = bridge.submit_checkpoint()?;
    let checkpoint = next_checkpoint_outcome(&mut checkpoint_receiver).await?;
    assert_eq!(checkpoint.checkpoint_id, checkpoint_id);
    let CheckpointOutcome::Installed(receipt) = checkpoint.outcome else {
        return Err("checkpoint was not installed".into());
    };
    assert_eq!(receipt.cut_manifest_sequence, 1);
    assert_eq!(receipt.installation_manifest_sequence, 1);
    assert_eq!(receipt.storage_commit_sequence, 2);
    assert_eq!(receipt.state_generation, 1);
    assert_eq!(receipt.account_service_response_count, 0);
    assert!(receipt.logical_database_bytes > 0);
    assert!(receipt.backup_stream_bytes > receipt.logical_database_bytes);

    let no_change_id = bridge.submit_checkpoint()?;
    let no_change = next_checkpoint_outcome(&mut checkpoint_receiver).await?;
    assert_eq!(no_change.checkpoint_id, no_change_id);
    assert!(matches!(no_change.outcome, CheckpointOutcome::NotNeeded));
    bridge.shutdown()?;
    owner.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicate_transaction_identity_fails_the_bridge_closed() -> Result<(), Box<dyn Error>> {
    let initialized = initialize()?;
    let owner = open_owner(&initialized, StorageFaultInjector::disabled())?;
    let (bridge, mut receiver, _read_receiver, _checkpoint_receiver) =
        StorageBridge::start(owner.port())?;
    let first = batch(&initialized, 3, 0, 0)?;
    let duplicate = batch(&initialized, 3, 1, 1)?;
    let id = bridge.submit(first)?;
    let refused = bridge.submit(duplicate).err();
    assert!(matches!(
        refused,
        Some(SubmitError::Bridge(BridgeFailure::DuplicateTransaction))
    ));
    assert_eq!(bridge.failure(), Some(BridgeFailure::DuplicateTransaction));
    // The ledger failed before the first completion was routed, so the
    // bridge stops without forwarding it: the closed channel is the
    // indeterminate signal StateCore acts on (spec line 4209).
    let closed = tokio::time::timeout(Duration::from_secs(60), receiver.recv()).await?;
    assert!(
        closed.is_none(),
        "the bridge forwards nothing after failing"
    );
    assert!(id != TransactionId::from_bytes([0; 16]));
    let later = batch(&initialized, 4, 1, 1)?;
    let stopped = bridge.submit(later).err();
    assert!(matches!(
        stopped,
        Some(SubmitError::Bridge(BridgeFailure::DuplicateTransaction))
    ));
    assert!(
        SubmitError::Bridge(BridgeFailure::Stopped)
            .to_string()
            .is_ascii()
    );
    assert!(
        SubmitError::Storage(StorageError::QueueFull)
            .to_string()
            .is_ascii()
    );
    drop(bridge);
    owner.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_receiver_stops_the_bridge_and_later_submissions_report_stopped()
-> Result<(), Box<dyn Error>> {
    let initialized = initialize()?;
    let owner = open_owner(&initialized, StorageFaultInjector::disabled())?;
    let (bridge, receiver, _read_receiver, _checkpoint_receiver) =
        StorageBridge::start(owner.port())?;
    drop(receiver);
    let id = bridge.submit(batch(&initialized, 5, 0, 0)?)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while bridge.failure().is_none() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(bridge.failure(), Some(BridgeFailure::ReceiverLost));
    assert!(id != TransactionId::from_bytes([0; 16]));
    let stopped = bridge.submit(batch(&initialized, 6, 1, 1)?).err();
    assert!(matches!(
        stopped,
        Some(SubmitError::Bridge(BridgeFailure::ReceiverLost))
    ));
    bridge.shutdown()?;
    owner.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_storage_refusal_abandons_the_ledger_entry() -> Result<(), Box<dyn Error>> {
    let initialized = initialize()?;
    let owner = open_owner(&initialized, StorageFaultInjector::disabled())?;
    let (bridge, mut receiver, _read_receiver, _checkpoint_receiver) =
        StorageBridge::start(owner.port())?;
    owner.shutdown()?;
    let refused = bridge.submit(batch(&initialized, 7, 0, 0)?).err();
    assert!(matches!(
        refused,
        Some(SubmitError::Storage(StorageError::Unavailable))
    ));
    assert_eq!(
        bridge.in_flight(),
        0,
        "a refused batch leaves no ledger entry"
    );
    assert!(bridge.failure().is_none());
    assert!(
        tokio::time::timeout(Duration::from_millis(200), receiver.recv())
            .await
            .is_err()
    );
    bridge.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_injected_commit_fault_after_the_primary_swap_is_indeterminate()
-> Result<(), Box<dyn Error>> {
    let initialized = initialize()?;
    let case = StorageFaultCase {
        site: StorageFaultSite::GuardRename,
        boundary: StorageFaultBoundary::After,
    };
    let owner = open_owner(&initialized, StorageFaultInjector::new(case, 1)?)?;
    let (bridge, mut receiver, _read_receiver, _checkpoint_receiver) =
        StorageBridge::start(owner.port())?;
    let id = bridge.submit(batch(&initialized, 8, 0, 0)?)?;
    let message = next_outcome(&mut receiver).await?;
    assert_eq!(message.transaction_id, id);
    assert!(matches!(message.outcome, CommitOutcome::Indeterminate));
    bridge.shutdown()?;
    let _ = owner.shutdown();
    Ok(())
}

#[test]
fn the_ledger_and_classification_fail_closed_on_every_loss() -> Result<(), Box<dyn Error>> {
    let ledger = CompletionLedger::new();
    let id = TransactionId::from_bytes([1; 16]);
    let other = TransactionId::from_bytes([2; 16]);
    ledger.begin(id)?;
    assert_eq!(ledger.in_flight(), 1);
    assert_eq!(ledger.begin(id), Err(BridgeFailure::DuplicateTransaction));
    assert_eq!(ledger.failure(), Some(BridgeFailure::DuplicateTransaction));
    assert_eq!(
        ledger.begin(other),
        Err(BridgeFailure::DuplicateTransaction)
    );
    ledger.fail(BridgeFailure::ReceiverLost);
    assert_eq!(
        ledger.failure(),
        Some(BridgeFailure::DuplicateTransaction),
        "the first failure is retained"
    );

    let fresh = CompletionLedger::default();
    assert_eq!(
        fresh.finish(other),
        Err(BridgeFailure::DuplicateTransaction)
    );
    let healthy = CompletionLedger::new();
    healthy.begin(id)?;
    healthy.abandon(id);
    assert_eq!(healthy.in_flight(), 0);
    healthy.begin(id)?;
    healthy.finish(id)?;
    assert!(healthy.failure().is_none());

    let (outcome, failure) = classify_completion(Err(StorageError::Unavailable));
    assert!(matches!(outcome, CommitOutcome::Indeterminate));
    assert_eq!(failure, Some(BridgeFailure::SenderLost));
    let (outcome, failure) =
        classify_completion(Ok(CommitOutcome::Rejected(StorageError::QueueFull)));
    assert!(matches!(
        outcome,
        CommitOutcome::Rejected(StorageError::QueueFull)
    ));
    assert!(failure.is_none());
    for failure in [
        BridgeFailure::HandoffFull,
        BridgeFailure::DuplicateTransaction,
        BridgeFailure::SenderLost,
        BridgeFailure::ReceiverLost,
        BridgeFailure::Stopped,
    ] {
        assert!(failure.to_string().is_ascii());
    }
    assert_eq!(STORAGE_HANDOFF_CAPACITY, 2);
    Ok(())
}
