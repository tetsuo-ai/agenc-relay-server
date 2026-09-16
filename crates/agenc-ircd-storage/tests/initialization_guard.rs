//! Initialization must never replace a previous lineage's rollback anchor.

#![forbid(unsafe_code)]

use std::os::unix::fs::symlink;

use super::*;

fn initialize(directory: &TestDirectory) -> Result<StorageInitializationOutcome, Box<dyn Error>> {
    let network = NetworkId::from_bytes([13; 32]);
    let login_key = LoginIndexKey::from_bytes([15; 32]);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
    let qualification = signed_test_qualification(StateDirectory::probe(directory.path())?)?;
    Ok(initialize_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(directory.path(), &[qualification])?,
        header_tbs: DatabaseHeaderTbs::new(
            network,
            ServerId::from_bytes([14; 16]),
            ServerIncarnation::from_bytes([16; 16]),
            DatabaseId::from_bytes([17; 16]),
            1,
            SCHEMA_GENERATION,
            RecoveryEpoch::from_bytes([18; 16]),
        )?,
        storage_master_key: StorageMasterKey::from_bytes([19; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([20; 32]),
        mode: StorageInitializationMode::Live,
        initial_records: vec![InitialStorageRecord::new(
            TableId::LoginIndexKeyState,
            StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            key_state.encode()?,
        )?],
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: StorageEngineLimits {
            redb_cache_bytes: 8 * 1_024 * 1_024,
            fixed_reserve_bytes: 64 * 1_024 * 1_024,
            reserve_percent: 1,
            database_max_bytes: 1_073_741_824,
            backup_max_bytes: 2_147_483_648,
            integrity_checkpoint_manifests: 100_000,
        },
    })?)
}

fn require_refusal(directory: &TestDirectory) -> Result<(), Box<dyn Error>> {
    let outcome = initialize(directory);
    assert!(
        matches!(
            outcome
                .as_ref()
                .err()
                .and_then(|error| error.downcast_ref::<StorageError>()),
            Some(StorageError::FilesystemRejected(_))
        ),
        "unexpected initialization outcome: {outcome:?}"
    );
    assert!(!directory.path().join("database.redb").exists());
    Ok(())
}

#[test]
fn initialization_preserves_the_guard_when_the_database_was_removed() -> Result<(), Box<dyn Error>>
{
    let directory = TestDirectory::create()?;
    assert!(matches!(
        initialize(&directory)?,
        StorageInitializationOutcome::Complete { .. }
    ));
    let guard = fs::read(directory.path().join("rollback.guard"))?;
    fs::remove_file(directory.path().join("database.redb"))?;
    require_refusal(&directory)?;
    assert_eq!(fs::read(directory.path().join("rollback.guard"))?, guard);
    Ok(())
}

#[test]
fn initialization_preserves_malformed_and_empty_guards() -> Result<(), Box<dyn Error>> {
    for bytes in [b"old guard".as_slice(), b"".as_slice()] {
        let directory = TestDirectory::create()?;
        let guard = directory.path().join("rollback.guard");
        fs::write(&guard, bytes)?;
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o600))?;
        require_refusal(&directory)?;
        assert_eq!(fs::read(&guard)?, bytes);
    }
    Ok(())
}

#[test]
fn initialization_refuses_guard_symlinks_and_directories() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let guard = directory.path().join("rollback.guard");
    symlink("absent-guard-target", &guard)?;
    require_refusal(&directory)?;
    assert_eq!(fs::read_link(&guard)?, PathBuf::from("absent-guard-target"));
    fs::remove_file(&guard)?;
    fs::create_dir(&guard)?;
    require_refusal(&directory)?;
    assert!(guard.is_dir());
    Ok(())
}
