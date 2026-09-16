//! Stage 05 trust-boundary and end-to-end durable storage evidence.

#![forbid(unsafe_code)]

mod domain_records;
mod e2ee_records;
mod federation_records;
mod fuzz_seeds;
mod history_records;
mod initialization_guard;
mod qualification_workload;
mod recovery_matrix;
mod witness_cursor;

use std::error::Error;
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agenc_ircd_crypto::{
    DatabaseBinding, Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, StorageDigest,
    StorageMasterKey, restore_transform_profile_hash,
};
use agenc_ircd_storage::{
    BACKUP_FIXED_STREAM_BYTES, BackupDestination, BackupTrustKey, CommitOutcome,
    ConstructionDirectory, ConstructionExecutor, ConstructionLimits, ConstructionTarget,
    DatabaseHeaderTbs, ExistingRecord, InitialStorageRecord, LoginIndexKeyState,
    PersistentRecordValue, QualificationTarget, ReadPlan, RecordMutation, RecoveryTransformV1,
    RestoreBackupSource, SCHEMA_GENERATION, SealedRecord, StateDirectory, StorageAccountingLimits,
    StorageConstruction, StorageConstructionAction, StorageConstructionCursor,
    StorageConstructionKind, StorageConstructionPlanEntry, StorageConstructionSource,
    StorageConstructionSourceKind, StorageEngineLimits, StorageError, StorageGrowthCase,
    StorageInitializationConfig, StorageInitializationMode, StorageInitializationOutcome,
    StorageMutationBatch, StorageMutationHead, StorageOpenConfig, StorageOperationIdentity,
    StorageOwner, StorageQualificationReport, StorageQualificationReportTbs, StorageSealContext,
    StoredKey, TableId, construction_plan_hash, initialize_storage, verify_backup,
};
use agenc_ircd_types::{
    AccountRandomId, DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation,
    TransactionId,
};

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Backup stream layout in bytes: magic, header length, header, record frames, trailer frame.
const BACKUP_MAGIC_BYTES: usize = 21;
const BACKUP_HEADER_LENGTH_BYTES: usize = 4;
const BACKUP_FORMAT_BYTES: usize = 2;
const BACKUP_HEADER_BYTES: usize = 736;
const BACKUP_TRAILER_FRAME_BYTES: usize = 108;
/// The header ends with created_at (8), backup_id (16), and signing_key_id (32).
const BACKUP_HEADER_TAIL_BYTES: usize = 56;
const _: () = assert!(
    (BACKUP_MAGIC_BYTES
        + BACKUP_HEADER_LENGTH_BYTES
        + BACKUP_HEADER_BYTES
        + BACKUP_TRAILER_FRAME_BYTES) as u64
        == BACKUP_FIXED_STREAM_BYTES
);

/// Exact stream length and record count of the deterministic backup fixture in
/// `initialized_owner_commits_and_reads_one_manifested_mutation`. Fixed keys, a fixed
/// creation time, and a fixed backup id make the stream reproducible; a fixture or
/// framing change must update both values deliberately.
const EXPECTED_BACKUP_STREAM_BYTES: u64 = 2_773;
const EXPECTED_BACKUP_RECORD_COUNT: u64 = 7;

/// Rejections one flipped byte at `offset` of a verified backup may legitimately produce.
fn expected_backup_flip_rejections(offset: usize) -> &'static [StorageError] {
    let format_start = BACKUP_MAGIC_BYTES + BACKUP_HEADER_LENGTH_BYTES;
    let embedded_start = format_start + BACKUP_FORMAT_BYTES;
    let header_end = format_start + BACKUP_HEADER_BYTES;
    let tail_start = header_end - BACKUP_HEADER_TAIL_BYTES;
    if offset < format_start {
        // Magic and the fixed header length are compared exactly before any decoding.
        &[StorageError::InvalidEncoding]
    } else if offset < embedded_start {
        &[StorageError::UnsupportedVersion]
    } else if offset < tail_start {
        // The embedded database header, nonce reservation, and rollback guard validate
        // their own fields before their integrity MAC is checked.
        &[
            StorageError::UnsupportedVersion,
            StorageError::AuthenticationFailed,
            StorageError::StaleState,
            StorageError::LimitExceeded,
            StorageError::InvalidEncoding,
        ]
    } else if offset < header_end {
        // created_at, backup_id, and signing_key_id only feed the signed stream digest
        // and the trust-key match.
        &[StorageError::AuthenticationFailed]
    } else {
        // Record frames and the trailer: a flipped length prefix causes a short read,
        // envelopes validate their fields, and every other flip fails authentication or
        // the StateMeta cross-check.
        &[
            StorageError::FilesystemRejected(agenc_ircd_storage::FilesystemCause::IoFailure),
            StorageError::InvalidEncoding,
            StorageError::UnsupportedVersion,
            StorageError::LimitExceeded,
            StorageError::AuthenticationFailed,
            StorageError::StaleState,
        ]
    }
}

fn account_key_bytes(seed: u8) -> Vec<u8> {
    AccountRandomId::from_bytes([seed; 16])
        .to_text()
        .into_bytes()
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agenc-ircd-stage-five-{}-{sequence}",
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

fn signed_test_qualification(
    tuple: agenc_ircd_storage::FilesystemTuple,
) -> Result<agenc_ircd_storage::StorageQualification, Box<dyn Error>> {
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

#[test]
fn sealed_record_rejects_wrong_stored_key() -> Result<(), Box<dyn Error>> {
    let binding = DatabaseBinding::new(
        NetworkId::from_bytes([1; 32]),
        ServerId::from_bytes([2; 16]),
        ServerIncarnation::from_bytes([3; 16]),
        DatabaseId::from_bytes([4; 16]),
    );
    let master = StorageMasterKey::from_bytes([5; 32]);
    let context = StorageSealContext::new(&master, binding, 1)?;
    let key = StoredKey::new(b"account-key".to_vec())?;
    let sealed = context.seal(TableId::Account, 1, [6; 24], &key, b"record")?;
    let encoded = sealed.encode()?;
    let decoded = agenc_ircd_storage::SealedRecord::decode(&encoded)?;
    let wrong_key = StoredKey::new(b"other-key".to_vec())?;
    assert_eq!(
        decoded
            .open(&master, binding, TableId::Account, 1, 1, &wrong_key)
            .err(),
        Some(StorageError::AuthenticationFailed)
    );
    let opened = decoded.open(&master, binding, TableId::Account, 1, 1, &key)?;
    assert_eq!(opened.expose_for_storage_codec(), b"record");
    Ok(())
}

#[test]
fn login_index_transition_is_exactly_two_generations() -> Result<(), Box<dyn Error>> {
    let network = NetworkId::from_bytes([7; 32]);
    let previous = LoginIndexKey::from_bytes([8; 32]);
    let current = LoginIndexKey::from_bytes([9; 32]);
    let state =
        LoginIndexKeyState::transition(1, previous.key_id(network), current.key_id(network), 2)?;
    let decoded = LoginIndexKeyState::decode(&state.encode()?)?;
    decoded.validate_configured_keys(network, &current, Some(&previous))?;
    let decoded = decoded.decrement_previous()?.decrement_previous()?;
    assert!(decoded.finish().is_ok());
    assert!(
        LoginIndexKeyState::transition(
            u32::MAX,
            LoginIndexKey::from_bytes([10; 32]).key_id(network),
            LoginIndexKey::from_bytes([11; 32]).key_id(network),
            1,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn construction_plan_rejects_action_kind_confusion() -> Result<(), Box<dyn Error>> {
    let key = StoredKey::new(b"account".to_vec())?;
    let source = StorageConstructionSource::new(
        StorageConstructionSourceKind::DatabaseRecord,
        TableId::Account,
        StoredKey::new(key.as_bytes().to_vec())?,
        1,
        StorageDigest::from_bytes([12; 32]),
        0,
    )?;
    let entry = StorageConstructionPlanEntry::new(
        StorageConstructionKind::Rekey,
        vec![source],
        TableId::Account,
        key,
        1,
        StorageConstructionAction::RekeyCopy,
        0,
    )?;
    assert!(construction_plan_hash(StorageConstructionKind::Rekey, &[entry], 16_384).is_ok());
    assert!(
        StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            Vec::new(),
            TableId::Account,
            StoredKey::new(b"bad".to_vec())?,
            1,
            StorageConstructionAction::RekeyCopy,
            0,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn mutation_batch_rejects_control_rows_and_generation_mismatch() -> Result<(), Box<dyn Error>> {
    let accounting = StorageAccountingLimits {
        current_logical_database_bytes: 10_000,
        current_backup_stream_bytes: 20_000,
        database_max_bytes: 1_073_741_824,
        backup_max_bytes: 2_147_483_648,
    };
    let head = StorageMutationHead {
        transaction_id: TransactionId::from_bytes([31; 16]),
        expected_storage_commit_sequence: 7,
        expected_state_generation: 9,
        resulting_state_generation: 10,
        state_advancing_plan_count: 0,
        expected_account_service_response_count: 3,
        resulting_account_service_response_count: 3,
    };
    let application = RecordMutation::put(
        TableId::Account,
        StoredKey::new(b"account".to_vec())?,
        1,
        None,
        b"value".to_vec(),
    )?;
    assert_eq!(
        StorageMutationBatch::new(head, 1, accounting, vec![application]).err(),
        Some(StorageError::InvalidEncoding)
    );

    let control = RecordMutation::put(
        TableId::StateMeta,
        StoredKey::new(b"control".to_vec())?,
        1,
        None,
        b"value".to_vec(),
    )?;
    let control_head = StorageMutationHead {
        state_advancing_plan_count: 1,
        ..head
    };
    assert_eq!(
        StorageMutationBatch::new(control_head, 1, accounting, vec![control]).err(),
        Some(StorageError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn storage_engine_limits_enforce_the_appendix_c_profile() {
    let valid = StorageEngineLimits {
        redb_cache_bytes: 8 * 1_024 * 1_024,
        fixed_reserve_bytes: 64 * 1_024 * 1_024,
        reserve_percent: 1,
        database_max_bytes: 1_073_741_824,
        backup_max_bytes: 1_073_741_824,
        integrity_checkpoint_manifests: 10_000,
    };
    assert_eq!(valid.validate(), Ok(valid));
    assert_eq!(
        StorageEngineLimits {
            reserve_percent: 0,
            ..valid
        }
        .validate(),
        Err(StorageError::LimitExceeded)
    );
    assert_eq!(
        StorageEngineLimits {
            database_max_bytes: valid.backup_max_bytes + 1,
            ..valid
        }
        .validate(),
        Err(StorageError::LimitExceeded)
    );
    assert_eq!(
        StorageEngineLimits {
            integrity_checkpoint_manifests: 9_999,
            ..valid
        }
        .validate(),
        Err(StorageError::LimitExceeded)
    );
}

#[test]
fn backup_output_rejects_paths_and_cleans_unpublished_files() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    assert!(matches!(
        BackupDestination::new(directory.path(), "../escape").err(),
        Some(StorageError::FilesystemRejected(_))
    ));
    let destination = BackupDestination::new(directory.path(), "unused.backup")?;
    assert_eq!(fs::read_dir(directory.path())?.count(), 0);
    drop(destination);
    assert_eq!(fs::read_dir(directory.path())?.count(), 0);
    Ok(())
}

#[test]
fn initialized_owner_commits_and_reads_one_manifested_mutation() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let tuple = StateDirectory::probe(directory.path())?;
    let qualification = signed_test_qualification(tuple)?;
    let limits = StorageEngineLimits {
        redb_cache_bytes: 8 * 1_024 * 1_024,
        fixed_reserve_bytes: 64 * 1_024 * 1_024,
        reserve_percent: 1,
        database_max_bytes: 1_073_741_824,
        backup_max_bytes: 2_147_483_648,
        integrity_checkpoint_manifests: 100_000,
    };
    let network = NetworkId::from_bytes([13; 32]);
    let server = ServerId::from_bytes([14; 16]);
    let login_key = LoginIndexKey::from_bytes([15; 32]);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
    let initial = InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let state_directory = StateDirectory::open(directory.path(), &[qualification])?;
    let initialization = initialize_storage(StorageInitializationConfig {
        state_directory,
        header_tbs: DatabaseHeaderTbs::new(
            network,
            server,
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
        limits,
    })?;
    let (logical_database_bytes, backup_stream_bytes) = match initialization {
        StorageInitializationOutcome::Complete {
            logical_database_bytes,
            backup_stream_bytes,
            ..
        } => (logical_database_bytes, backup_stream_bytes),
        StorageInitializationOutcome::Indeterminate => {
            return Err(std::io::Error::other("initialization was indeterminate").into());
        }
    };
    let state_directory = StateDirectory::open(directory.path(), &[qualification])?;
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: network,
        expected_server_id: server,
        state_directory,
        storage_master_key: StorageMasterKey::from_bytes([19; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([20; 32]),
        login_index_key: LoginIndexKey::from_bytes([15; 32]),
        previous_login_index_key: None,
        limits,
    })?;
    let recovered = owner.recovered_state();
    assert_eq!(recovered.table_record_count(TableId::KeyCheck), 1);
    assert_eq!(recovered.table_record_count(TableId::StateMeta), 1);
    assert_eq!(recovered.state_generation(), 0);
    assert_eq!(recovered.account_service_response_count(), 0);
    assert_eq!(recovered.storage_commit_sequence(), 0);
    assert_eq!(recovered.manifest_sequence(), 0);
    assert_eq!(recovered.nonce_draw_high_water(), 4);
    assert_eq!(recovered.maximum_record_revision(), 0);
    assert!(recovered.capacity().available_bytes > 0);
    let port = owner.port();
    let account_key = StoredKey::new(account_key_bytes(1))?;
    let account_v1 = PersistentRecordValue::new(
        TableId::Account,
        1,
        1,
        1,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 1)?,
    )?
    .encode()?;
    let mutation = RecordMutation::put(
        TableId::Account,
        StoredKey::new(account_key.as_bytes().to_vec())?,
        1,
        None,
        account_v1,
    )?;
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([21; 16]),
            expected_storage_commit_sequence: 0,
            expected_state_generation: 0,
            resulting_state_generation: 1,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: logical_database_bytes,
            current_backup_stream_bytes: backup_stream_bytes,
            database_max_bytes: limits.database_max_bytes,
            backup_max_bytes: limits.backup_max_bytes,
        },
        vec![mutation],
    )?;
    let first_logical_bytes = batch.resulting_logical_database_bytes();
    let first_backup_bytes = batch.resulting_backup_stream_bytes();
    let outcome = port.try_commit(batch)?.wait()?;
    match outcome {
        CommitOutcome::Committed(receipt) => {
            assert_eq!(receipt.storage_commit_sequence, 1);
            assert_eq!(receipt.state_generation, 1);
        }
        CommitOutcome::Rejected(error) => return Err(error.into()),
        CommitOutcome::Indeterminate => {
            return Err(std::io::Error::other("commit was indeterminate").into());
        }
    }
    let read = port
        .try_read(ReadPlan::exact(TableId::Account, account_key.clone()))?
        .wait()?;
    assert_eq!(read.storage_commit_sequence, 1);
    assert_eq!(read.records.len(), 1);
    let read_record = read
        .records
        .first()
        .ok_or_else(|| std::io::Error::other("account record is missing"))?;
    let sealed = SealedRecord::decode(&read_record.sealed_record)?;
    let existing = ExistingRecord::new(
        sealed.record_schema(),
        sealed.record_id()?,
        read_record.sealed_record.len(),
    )?;
    let stale = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([25; 16]),
            expected_storage_commit_sequence: 0,
            expected_state_generation: 0,
            resulting_state_generation: 1,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: first_logical_bytes,
            current_backup_stream_bytes: first_backup_bytes,
            database_max_bytes: limits.database_max_bytes,
            backup_max_bytes: limits.backup_max_bytes,
        },
        vec![RecordMutation::put(
            TableId::Account,
            StoredKey::new(account_key_bytes(2))?,
            1,
            None,
            PersistentRecordValue::new(
                TableId::Account,
                1,
                1,
                1,
                None,
                Vec::new(),
                crate::domain_records::live_body(TableId::Account, 3)?,
            )?
            .encode()?,
        )?],
    )?;
    assert!(matches!(
        port.try_commit(stale)?.wait()?,
        CommitOutcome::Rejected(StorageError::StaleState)
    ));

    let replacement = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([26; 16]),
            expected_storage_commit_sequence: 1,
            expected_state_generation: 1,
            resulting_state_generation: 2,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: first_logical_bytes,
            current_backup_stream_bytes: first_backup_bytes,
            database_max_bytes: limits.database_max_bytes,
            backup_max_bytes: limits.backup_max_bytes,
        },
        vec![RecordMutation::put(
            TableId::Account,
            StoredKey::new(account_key.as_bytes().to_vec())?,
            1,
            Some(existing),
            PersistentRecordValue::new(
                TableId::Account,
                1,
                2,
                1,
                None,
                Vec::new(),
                crate::domain_records::live_body(TableId::Account, 2)?,
            )?
            .encode()?,
        )?],
    )?;
    let second_logical_bytes = replacement.resulting_logical_database_bytes();
    let second_backup_bytes = replacement.resulting_backup_stream_bytes();
    assert!(matches!(
        port.try_commit(replacement)?.wait()?,
        CommitOutcome::Committed(_)
    ));
    let range = port
        .try_read(ReadPlan::range(
            TableId::Account,
            StoredKey::new(b"a".to_vec())?,
            StoredKey::new(b"b".to_vec())?,
            10,
        )?)?
        .wait()?;
    assert_eq!(range.records.len(), 1);
    let replacement_record = range
        .records
        .first()
        .ok_or_else(|| std::io::Error::other("replacement record is missing"))?;
    let replacement_sealed = SealedRecord::decode(&replacement_record.sealed_record)?;
    let replacement_existing = ExistingRecord::new(
        replacement_sealed.record_schema(),
        replacement_sealed.record_id()?,
        replacement_record.sealed_record.len(),
    )?;
    let deletion = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([27; 16]),
            expected_storage_commit_sequence: 2,
            expected_state_generation: 2,
            resulting_state_generation: 3,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: second_logical_bytes,
            current_backup_stream_bytes: second_backup_bytes,
            database_max_bytes: limits.database_max_bytes,
            backup_max_bytes: limits.backup_max_bytes,
        },
        vec![RecordMutation::delete(
            TableId::Account,
            StoredKey::new(account_key.as_bytes().to_vec())?,
            replacement_existing,
        )],
    )?;
    assert!(matches!(
        port.try_commit(deletion)?.wait()?,
        CommitOutcome::Committed(_)
    ));
    assert!(
        port.try_read(ReadPlan::exact(
            TableId::Account,
            StoredKey::new(account_key.as_bytes().to_vec())?,
        ))?
        .wait()?
        .records
        .is_empty()
    );
    let backup_file = BackupDestination::new(directory.path(), "verified.backup")?;
    let backup = port
        .try_backup(
            backup_file,
            Ed25519SecretKey::from_bytes([22; 32]),
            1_800_000_000,
            [23; 16],
        )?
        .wait()?;
    assert_eq!(backup.stream_bytes, EXPECTED_BACKUP_STREAM_BYTES);
    assert_eq!(backup.record_count, EXPECTED_BACKUP_RECORD_COUNT);
    let backup_path = directory.path().join("verified.backup");
    assert!(backup_path.is_file());
    let backup_bytes = fs::read(&backup_path)?;
    let signing_key = Ed25519SecretKey::from_bytes([22; 32]);
    let trusted = BackupTrustKey::new(signing_key.public_key())?;
    let verified = verify_backup(
        backup_bytes.as_slice(),
        &StorageMasterKey::from_bytes([19; 32]),
        &RollbackGuardRootKey::from_bytes([20; 32]),
        &[trusted],
        limits.backup_max_bytes,
    )?;
    assert_eq!(verified.stream_bytes, backup.stream_bytes);
    let bounded_trust = BackupTrustKey::with_validity(
        trusted.key_id,
        signing_key.public_key(),
        1_800_000_000,
        1_800_000_001,
    )?;
    assert!(
        verify_backup(
            backup_bytes.as_slice(),
            &StorageMasterKey::from_bytes([19; 32]),
            &RollbackGuardRootKey::from_bytes([20; 32]),
            &[bounded_trust],
            limits.backup_max_bytes,
        )
        .is_ok()
    );
    for (not_before, not_after) in [
        (1_800_000_001, 1_800_000_002),
        (1_799_999_999, 1_800_000_000),
    ] {
        let outside = BackupTrustKey::with_validity(
            trusted.key_id,
            signing_key.public_key(),
            not_before,
            not_after,
        )?;
        assert_eq!(
            verify_backup(
                backup_bytes.as_slice(),
                &StorageMasterKey::from_bytes([19; 32]),
                &RollbackGuardRootKey::from_bytes([20; 32]),
                &[outside],
                limits.backup_max_bytes,
            )
            .err(),
            Some(StorageError::AuthenticationFailed)
        );
    }
    // Current-format policy, documented in the operator guide: the interval
    // constrains only the signed claim. A backup created now but claiming
    // Unix second 1_500_000_000 (2017) verifies under a key whose interval
    // ended in 2020, because the row is still retained and the claim lies
    // inside it; removing the row is what stops the key from vouching.
    let backdated_file = BackupDestination::new(directory.path(), "backdated.backup")?;
    let backdated = port
        .try_backup(
            backdated_file,
            Ed25519SecretKey::from_bytes([22; 32]),
            1_500_000_000,
            [24; 16],
        )?
        .wait()?;
    assert_eq!(backdated.stream_bytes, backup.stream_bytes);
    let backdated_bytes = fs::read(directory.path().join("backdated.backup"))?;
    let retired_interval = BackupTrustKey::with_validity(
        trusted.key_id,
        signing_key.public_key(),
        1_400_000_000,
        1_600_000_000,
    )?;
    let accepted = verify_backup(
        backdated_bytes.as_slice(),
        &StorageMasterKey::from_bytes([19; 32]),
        &RollbackGuardRootKey::from_bytes([20; 32]),
        &[retired_interval],
        limits.backup_max_bytes,
    )?;
    assert_eq!(accepted.header.created_at(), 1_500_000_000);
    // With that row gone (only an unrelated key retained), the same backup
    // verifies nothing.
    let unrelated = BackupTrustKey::new(Ed25519SecretKey::from_bytes([25; 32]).public_key())?;
    assert_eq!(
        verify_backup(
            backdated_bytes.as_slice(),
            &StorageMasterKey::from_bytes([19; 32]),
            &RollbackGuardRootKey::from_bytes([20; 32]),
            &[unrelated],
            limits.backup_max_bytes,
        )
        .err(),
        Some(StorageError::AuthenticationFailed)
    );
    let restore_directory = TestDirectory::create()?;
    let restore_output = restore_directory.path().join("restored-state");
    let construction_directory = ConstructionDirectory::open(&restore_output, false)?;
    let plan_file = construction_directory.rebuild_plan_file()?;
    let target_incarnation = ServerIncarnation::from_bytes([31; 16]);
    let target_database = DatabaseId::from_bytes([32; 16]);
    let target_binding = DatabaseBinding::new(network, server, target_incarnation, target_database);
    let target_recovery_epoch = RecoveryEpoch::from_bytes([33; 16]);
    let target_guard_root = [34; 32];
    let construction_limits = ConstructionLimits {
        source_database_bytes: 1_073_741_824,
        source_backup_bytes: 1_073_741_824,
        target_database_bytes: 1_073_741_824,
        target_backup_bytes: 1_073_741_824,
        plan_bytes: 1_073_741_824,
        batch_records: 1_000,
        batch_bytes: 16_777_216,
    };
    let mut restore_source = RestoreBackupSource::open(
        Cursor::new(backup_bytes.clone()),
        StorageMasterKey::from_bytes([19; 32]),
        RollbackGuardRootKey::from_bytes([20; 32]),
        LoginIndexKey::from_bytes([15; 32]),
        None,
        &[trusted],
        limits.backup_max_bytes,
    )?;
    let restore_plan = restore_source.rebuild_restore_plan(
        plan_file,
        &StorageMasterKey::from_bytes([19; 32]),
        target_binding,
        2,
        construction_limits,
    )?;
    assert_eq!(restore_plan.entry_count(), 1);
    let source_facts = restore_source.facts()?;
    let identity = StorageOperationIdentity {
        kind: StorageConstructionKind::Restore,
        command_version: 1,
        source_database_header_hash: source_facts.header.complete_hash()?,
        target_database_header_hash: StorageDigest::from_bytes([0; 32]),
        source_rollback_guard_hash: source_facts.rollback_guard_hash,
        source_stream_digest: Some(verified.trailer.stream_digest),
        source_schema_generation: source_facts.header.tbs().schema_generation,
        target_schema_generation: source_facts.header.tbs().schema_generation,
        transform_profile_hash: restore_transform_profile_hash()?,
        target_database_instance_id: target_database,
        source_master_key_id: StorageMasterKey::from_bytes([19; 32]).source_operation_key_id()?,
        source_guard_root_key_id: RollbackGuardRootKey::from_bytes([20; 32])
            .source_operation_key_id()?,
        target_master_key_id: StorageMasterKey::from_bytes([19; 32]).target_operation_key_id()?,
        target_guard_root_key_id: RollbackGuardRootKey::from_bytes(target_guard_root)
            .target_operation_key_id()?,
        planned_entry_count: restore_plan.entry_count(),
        construction_plan_hash: restore_plan.hash(),
    };
    let marker = StorageConstruction {
        identity,
        output_path_hash: construction_directory.output_path_hash(),
        next_target: StorageConstructionCursor::BeforeFirst,
        target_records_committed: 0,
    };
    let target_tuple = StateDirectory::probe(&construction_directory.selected_path())?;
    let target_qualification = signed_test_qualification(target_tuple)?;
    let target_initialization = initialize_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(
            &construction_directory.selected_path(),
            &[target_qualification],
        )?,
        header_tbs: DatabaseHeaderTbs::new(
            network,
            server,
            target_incarnation,
            target_database,
            2,
            SCHEMA_GENERATION,
            target_recovery_epoch,
        )?,
        storage_master_key: StorageMasterKey::from_bytes([19; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(target_guard_root),
        mode: StorageInitializationMode::Construction,
        initial_records: vec![InitialStorageRecord::new(
            TableId::StorageConstruction,
            StoredKey::new(agenc_ircd_storage::STORAGE_CONSTRUCTION_KEY.to_vec())?,
            1,
            marker.encode()?,
        )?],
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash: source_facts.rollback_guard_hash,
        limits,
    })?;
    assert!(matches!(
        target_initialization,
        StorageInitializationOutcome::Complete { .. }
    ));
    let target_config = || -> Result<StorageOpenConfig, StorageError> {
        Ok(StorageOpenConfig {
            expected_network_id: network,
            expected_server_id: server,
            state_directory: StateDirectory::open(
                &construction_directory.selected_path(),
                &[target_qualification],
            )?,
            storage_master_key: StorageMasterKey::from_bytes([19; 32]),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(target_guard_root),
            login_index_key: LoginIndexKey::from_bytes([15; 32]),
            previous_login_index_key: None,
            limits,
        })
    };
    let mut target = ConstructionTarget::open(target_config()?)?;
    let final_marker = target.marker()?;
    let expected_identity = final_marker.identity;
    let mut transformer =
        RecoveryTransformV1::new(target_recovery_epoch, source_facts.rollback_guard_hash);
    let preflight = restore_plan.preflight(
        &final_marker,
        0,
        0,
        &mut restore_source,
        &mut transformer,
        construction_limits,
    )?;
    let mut executor =
        ConstructionExecutor::resume(final_marker, restore_plan, construction_limits)?;
    assert_eq!(
        executor.service_batch(&mut restore_source, &mut transformer, &mut target)?,
        1
    );
    assert_eq!(
        executor.service_batch(&mut restore_source, &mut transformer, &mut target)?,
        0
    );
    let operation_id = executor.finalize(&mut target)?;
    drop(executor);
    drop(target);
    construction_directory.remove_plan_file()?;
    let verification = ConstructionTarget::verify_completed(
        target_config()?,
        expected_identity,
        construction_directory.output_path_hash(),
    )?;
    assert_eq!(verification.completion().storage_operation_id, operation_id);
    assert_eq!(
        verification.logical_database_bytes(),
        preflight.final_logical_database_bytes
    );
    assert_eq!(
        verification.backup_stream_bytes(),
        preflight.final_backup_stream_bytes
    );
    let installed = construction_directory.install(verification)?;
    assert_eq!(installed, restore_output);
    let restored = StorageOwner::start(StorageOpenConfig {
        expected_network_id: network,
        expected_server_id: server,
        state_directory: StateDirectory::open(&installed, &[target_qualification])?,
        storage_master_key: StorageMasterKey::from_bytes([19; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(target_guard_root),
        login_index_key: LoginIndexKey::from_bytes([15; 32]),
        previous_login_index_key: None,
        limits,
    })?;
    restored.shutdown()?;
    assert_eq!(
        verify_backup(
            backup_bytes.as_slice(),
            &StorageMasterKey::from_bytes([19; 32]),
            &RollbackGuardRootKey::from_bytes([20; 32]),
            &[],
            limits.backup_max_bytes,
        )
        .err(),
        Some(StorageError::LimitExceeded)
    );
    assert_eq!(
        verify_backup(
            backup_bytes.as_slice(),
            &StorageMasterKey::from_bytes([99; 32]),
            &RollbackGuardRootKey::from_bytes([20; 32]),
            &[trusted],
            limits.backup_max_bytes,
        )
        .err(),
        Some(StorageError::AuthenticationFailed)
    );
    assert_eq!(
        verify_backup(
            backup_bytes.as_slice(),
            &StorageMasterKey::from_bytes([19; 32]),
            &RollbackGuardRootKey::from_bytes([99; 32]),
            &[trusted],
            limits.backup_max_bytes,
        )
        .err(),
        Some(StorageError::AuthenticationFailed)
    );
    assert_eq!(
        verify_backup(
            backup_bytes.as_slice(),
            &StorageMasterKey::from_bytes([19; 32]),
            &RollbackGuardRootKey::from_bytes([20; 32]),
            &[trusted, trusted],
            limits.backup_max_bytes,
        )
        .err(),
        Some(StorageError::AuthenticationFailed)
    );
    let wrong_trust = BackupTrustKey::new(Ed25519SecretKey::from_bytes([98; 32]).public_key())?;
    assert_eq!(
        verify_backup(
            backup_bytes.as_slice(),
            &StorageMasterKey::from_bytes([19; 32]),
            &RollbackGuardRootKey::from_bytes([20; 32]),
            &[wrong_trust],
            limits.backup_max_bytes,
        )
        .err(),
        Some(StorageError::AuthenticationFailed)
    );
    for length in [0, 1, 20, 21, 100, backup_bytes.len() - 1] {
        let candidate = backup_bytes
            .get(..length)
            .ok_or_else(|| std::io::Error::other("backup truncation is out of range"))?;
        assert!(
            matches!(
                verify_backup(
                    candidate,
                    &StorageMasterKey::from_bytes([19; 32]),
                    &RollbackGuardRootKey::from_bytes([20; 32]),
                    &[trusted],
                    limits.backup_max_bytes,
                )
                .err(),
                Some(StorageError::FilesystemRejected(_))
            ),
            "truncation at {length}"
        );
    }
    for offset in 0..backup_bytes.len() {
        let mut corrupted = backup_bytes.clone();
        let byte = corrupted
            .get_mut(offset)
            .ok_or_else(|| std::io::Error::other("backup corruption is out of range"))?;
        *byte ^= 1;
        let rejection = verify_backup(
            corrupted.as_slice(),
            &StorageMasterKey::from_bytes([19; 32]),
            &RollbackGuardRootKey::from_bytes([20; 32]),
            &[trusted],
            limits.backup_max_bytes,
        )
        .err();
        let allowed = expected_backup_flip_rejections(offset);
        assert!(
            rejection.is_some_and(|error| allowed.contains(&error)),
            "flip at {offset} produced {rejection:?}, expected one of {allowed:?}"
        );
    }
    let replacement = BackupDestination::new(directory.path(), "verified.backup")?;
    assert!(matches!(
        port.try_backup(
            replacement,
            Ed25519SecretKey::from_bytes([22; 32]),
            1_800_000_001,
            [24; 16],
        )?
        .wait()
        .err(),
        Some(StorageError::FilesystemRejected(_))
    ));
    assert!(fs::read_dir(directory.path())?.all(|entry| {
        entry
            .ok()
            .and_then(|entry| entry.file_name().into_string().ok())
            .is_some_and(|name| !name.starts_with(".agenc-backup-tmp-v1-"))
    }));
    drop(port);
    owner.shutdown()?;
    let wrong_key_directory = StateDirectory::open(directory.path(), &[qualification])?;
    assert_eq!(
        StorageOwner::start(StorageOpenConfig {
            expected_network_id: network,
            expected_server_id: server,
            state_directory: wrong_key_directory,
            storage_master_key: StorageMasterKey::from_bytes([99; 32]),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes([20; 32]),
            login_index_key: LoginIndexKey::from_bytes([15; 32]),
            previous_login_index_key: None,
            limits,
        })
        .err(),
        Some(StorageError::AuthenticationFailed)
    );
    let state_directory = StateDirectory::open(directory.path(), &[qualification])?;
    let reopened = StorageOwner::start(StorageOpenConfig {
        expected_network_id: network,
        expected_server_id: server,
        state_directory,
        storage_master_key: StorageMasterKey::from_bytes([19; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([20; 32]),
        login_index_key: LoginIndexKey::from_bytes([15; 32]),
        previous_login_index_key: None,
        limits,
    })?;
    let reopened_port = reopened.port();
    let pruned_manifest = reopened_port
        .try_read(ReadPlan::exact(
            TableId::IntegrityManifest,
            StoredKey::new(1_u64.to_be_bytes().to_vec())?,
        ))?
        .wait()?;
    assert_eq!(pruned_manifest.storage_commit_sequence, 4);
    assert!(pruned_manifest.records.is_empty());
    let genesis_checkpoint = reopened_port
        .try_read(ReadPlan::exact(
            TableId::IntegrityCheckpoint,
            StoredKey::new(0_u64.to_be_bytes().to_vec())?,
        ))?
        .wait()?;
    let active_checkpoint = reopened_port
        .try_read(ReadPlan::exact(
            TableId::IntegrityCheckpoint,
            StoredKey::new(3_u64.to_be_bytes().to_vec())?,
        ))?
        .wait()?;
    assert_eq!(genesis_checkpoint.records.len(), 1);
    assert_eq!(active_checkpoint.records.len(), 1);
    drop(reopened_port);
    reopened.shutdown()?;
    Ok(())
}

#[path = "codec_matrix.rs"]
mod codec_matrix;

#[path = "stage_five_completion.rs"]
mod stage_five_completion;
