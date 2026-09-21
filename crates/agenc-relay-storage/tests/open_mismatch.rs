#![forbid(unsafe_code)]

//! An initialized database refuses to open under another network or server
//! identity, or under a ceiling already below its committed use.

use super::*;

#[test]
fn an_existing_database_refuses_another_identity_or_a_ceiling_below_its_use()
-> Result<(), Box<dyn Error>> {
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
        StoredKey::new(agenc_relay_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let state_directory =
        StateDirectory::open(directory.path(), std::slice::from_ref(&qualification))?;
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
    assert!(matches!(
        initialization,
        StorageInitializationOutcome::Complete { .. }
    ));
    let open = |network: NetworkId, server: ServerId, limits: StorageEngineLimits| {
        StateDirectory::open(directory.path(), std::slice::from_ref(&qualification)).and_then(
            |state_directory| {
                StorageOwner::start(StorageOpenConfig {
                    expected_network_id: network,
                    expected_server_id: server,
                    state_directory,
                    storage_master_key: StorageMasterKey::from_bytes([19; 32]),
                    rollback_guard_root_key: RollbackGuardRootKey::from_bytes([20; 32]),
                    login_index_key: LoginIndexKey::from_bytes([15; 32]),
                    previous_login_index_key: None,
                    limits,
                })
            },
        )
    };
    assert_eq!(
        open(NetworkId::from_bytes([99; 32]), server, limits)
            .err()
            .map(|error| error.to_string()),
        Some(StorageError::AuthenticationFailed.to_string()),
        "another network"
    );
    assert_eq!(
        open(network, ServerId::from_bytes([99; 16]), limits)
            .err()
            .map(|error| error.to_string()),
        Some(StorageError::AuthenticationFailed.to_string()),
        "another server"
    );
    let shrunk = StorageEngineLimits {
        database_max_bytes: 1,
        ..limits
    };
    assert_eq!(
        open(network, server, shrunk)
            .err()
            .map(|error| error.to_string()),
        Some(StorageError::LimitExceeded.to_string()),
        "a database ceiling below the committed bytes"
    );
    let owner = open(network, server, limits)?;
    assert_eq!(owner.recovered_state().state_generation(), 0);
    let _shutdown = owner.shutdown();
    Ok(())
}
