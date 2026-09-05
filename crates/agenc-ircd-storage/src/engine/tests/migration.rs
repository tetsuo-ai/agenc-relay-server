//! Real predecessor/target databases for the first offline schema migration.
#![forbid(unsafe_code)]

use std::os::unix::fs::PermissionsExt as _;

use agenc_ircd_crypto::{StorageTable, derive_storage_index};
use agenc_ircd_domain::HistoryPolicy;

use super::*;
use crate::history_records::{HistoryControlRecord, history_control_key};
use crate::{
    ChannelNameRecordBody, ChannelRecordBody, ConstructionSourceDatabase, DatabaseHeaderTbs,
    MigrationCommandRequest, execute_migration_command,
};

struct Fixture {
    path: PathBuf,
    qualifications: Vec<StorageQualification>,
}

impl Fixture {
    fn new() -> Result<Self, StorageError> {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::current_dir()
            .map_err(|_| StorageError::FilesystemRejected)?
            .join("target/migration-unit-tests")
            .join(format!("{}-{sequence}", std::process::id()));
        for child in ["", "source", "backups"] {
            let directory = path.join(child);
            std::fs::create_dir_all(&directory).map_err(|_| StorageError::FilesystemRejected)?;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| StorageError::FilesystemRejected)?;
        }
        for (name, byte) in [("master", 27), ("guard", 28), ("login", 23), ("sign", 30)] {
            let path = path.join(name);
            std::fs::write(&path, [byte; 32]).map_err(|_| StorageError::FilesystemRejected)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| StorageError::FilesystemRejected)?;
        }
        let qualifications = vec![test_qualification(&path)?];
        Ok(Self {
            path,
            qualifications,
        })
    }

    fn header(&self) -> DatabaseHeaderTbs {
        DatabaseHeaderTbs {
            network_id: NetworkId::from_bytes([21; 32]),
            server_id: ServerId::from_bytes([22; 16]),
            server_incarnation: ServerIncarnation::from_bytes([24; 16]),
            database_instance_id: DatabaseId::from_bytes([25; 16]),
            storage_key_generation: 1,
            schema_generation: 1,
            recovery_epoch: RecoveryEpoch::from_bytes([26; 16]),
        }
    }

    fn config(&self, child: &str) -> Result<StorageOpenConfig, StorageError> {
        Ok(StorageOpenConfig {
            expected_network_id: self.header().network_id,
            expected_server_id: self.header().server_id,
            state_directory: StateDirectory::open(&self.path.join(child), &self.qualifications)?,
            storage_master_key: StorageMasterKey::from_bytes([27; 32]),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes([28; 32]),
            login_index_key: LoginIndexKey::from_bytes([23; 32]),
            previous_login_index_key: None,
            limits: engine_limits(),
        })
    }

    fn initialize(&self, history: bool) -> Result<(), StorageError> {
        let mut records = vec![InitialStorageRecord::new(
            TableId::LoginIndexKeyState,
            StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            LoginIndexKeyState::stable(
                1,
                LoginIndexKey::from_bytes([23; 32]).key_id(self.header().network_id),
            )?
            .encode()?,
        )?];
        let account = crate::domain_records::fixtures::account(1)?;
        records.push(initial_value(
            TableId::Account,
            account.account_id.to_text().as_bytes().to_vec(),
            PersistentRecordValue::new(
                TableId::Account,
                1,
                1,
                1,
                None,
                Vec::new(),
                crate::AccountRecordBody::encode(&account)?,
            )?,
        )?);
        if history {
            self.add_channel(&mut records)?;
        }
        let result =
            crate::initialize::initialize_legacy_test_storage(StorageInitializationConfig {
                state_directory: StateDirectory::open(
                    &self.path.join("source"),
                    &self.qualifications,
                )?,
                header_tbs: self.header(),
                storage_master_key: StorageMasterKey::from_bytes([27; 32]),
                rollback_guard_root_key: RollbackGuardRootKey::from_bytes([28; 32]),
                mode: StorageInitializationMode::Live,
                initial_records: records,
                account_service_response_count: 11,
                state_generation: 7,
                predecessor_guard_hash: ZERO,
                limits: engine_limits(),
            })?;
        assert!(matches!(
            result,
            StorageInitializationOutcome::Complete { .. }
        ));
        Ok(())
    }

    fn add_channel(&self, records: &mut Vec<InitialStorageRecord>) -> Result<(), StorageError> {
        let mut channel = crate::domain_records::fixtures::channel(1)?;
        channel.history = HistoryPolicy::OneHour;
        records.push(initial_value(
            TableId::Channel,
            channel.channel_id.as_bytes().to_vec(),
            PersistentRecordValue::new(
                TableId::Channel,
                1,
                1,
                0,
                None,
                Vec::new(),
                ChannelRecordBody::encode(&channel)?,
            )?,
        )?);
        let h = self.header();
        let binding = DatabaseBinding::new(
            h.network_id,
            h.server_id,
            h.server_incarnation,
            h.database_instance_id,
        );
        let key = derive_storage_index(
            &StorageMasterKey::from_bytes([27; 32]),
            binding,
            StorageTable::new(TableId::ChannelName.as_u16())?,
            1,
            channel.name.canonical().as_bytes(),
        )?;
        records.push(initial_value(
            TableId::ChannelName,
            key.expose_for_storage_key().to_vec(),
            PersistentRecordValue::new(
                TableId::ChannelName,
                1,
                1,
                0,
                None,
                vec![crate::RecordReference::new(
                    TableId::Channel,
                    StoredKey::new(channel.channel_id.as_bytes().to_vec())?,
                )?],
                ChannelNameRecordBody::encode(channel.channel_id, &channel.name)?,
            )?,
        )?);
        Ok(())
    }

    fn request(&self, resume: bool) -> Result<MigrationCommandRequest, StorageError> {
        let trust = BackupTrustKey::new(Ed25519SecretKey::from_bytes([30; 32]).public_key())?;
        Ok(MigrationCommandRequest {
            network_id: self.header().network_id,
            server_id: self.header().server_id,
            source_state_directory: self.path.join("source"),
            master_key_file: self.path.join("master"),
            rollback_guard_key_file: self.path.join("guard"),
            login_index_key_file: self.path.join("login"),
            previous_login_index_key_file: None,
            backup_directory: self.path.join("backups"),
            backup_signing_key_file: self.path.join("sign"),
            trusted_backup_keys: vec![crate::RestoreTrustKey::new(
                *trust.key_id.as_bytes(),
                *trust.public_key.as_bytes(),
                0,
                u64::MAX,
            )],
            created_at: 100,
            target_schema_generation: 2,
            output_state_directory: self.path.join("target"),
            resume,
            limits: engine_limits(),
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn initial_value(
    table: TableId,
    key: Vec<u8>,
    value: PersistentRecordValue,
) -> Result<InitialStorageRecord, StorageError> {
    InitialStorageRecord::new(table, StoredKey::new(key)?, 1, value.encode()?)
}

#[test]
fn migration_preserves_continuity_and_initializes_enabled_legacy_history()
-> Result<(), StorageError> {
    let fixture = Fixture::new()?;
    fixture.initialize(true)?;
    let original = std::fs::read(fixture.path.join("source/database.redb"))
        .map_err(|_| StorageError::FilesystemRejected)?;
    assert!(matches!(
        StorageEngine::open(fixture.config("source")?),
        Err(StorageError::UnsupportedVersion)
    ));
    assert!(
        std::fs::read(fixture.path.join("source/database.redb"))
            .map_err(|_| StorageError::FilesystemRejected)?
            == original
    );
    let source = ConstructionSourceDatabase::open_migration(fixture.config("source")?)?;
    let before = source.facts()?;
    drop(source);
    let receipt = execute_migration_command(fixture.request(false)?, &fixture.qualifications)?;
    assert_eq!(receipt.state_generation, 7);
    assert!(receipt.source_backup.is_file());
    let target = StorageEngine::open(fixture.config("target")?)?;
    let _recovered = target.startup_scan()?;
    assert_eq!(target.header.tbs().schema_generation, 2);
    assert_eq!(target.header.tbs().storage_key_generation, 2);
    assert_ne!(
        target.header.tbs().database_instance_id,
        before.header.tbs().database_instance_id
    );
    assert_eq!(
        target.header.tbs().server_incarnation,
        before.header.tbs().server_incarnation
    );
    assert_eq!(
        target.header.tbs().recovery_epoch,
        before.header.tbs().recovery_epoch
    );
    assert_eq!(target.state_meta.tbs().state_generation, 7);
    assert_eq!(target.state_meta.tbs().account_service_response_count, 11);
    let channel = crate::domain_records::fixtures::channel(1)?;
    let key = history_control_key(channel.channel_id)?;
    let encoded = target
        .store
        .read_record(TableId::History, key.as_bytes())?
        .ok_or(StorageError::StaleState)?;
    let plaintext = SealedRecord::decode(&encoded)?.open(
        &target.master_key,
        target.binding,
        TableId::History,
        1,
        2,
        &key,
    )?;
    let value =
        PersistentRecordValue::decode(TableId::History, plaintext.expose_for_storage_codec())?;
    assert!(
        HistoryControlRecord::decode(value.body())?
            == HistoryControlRecord::empty(channel.channel_id, 7)?
    );
    drop(target);
    let resumed = execute_migration_command(fixture.request(true)?, &fixture.qualifications)?;
    assert_eq!(resumed.storage_operation_id, receipt.storage_operation_id);
    let unchanged = ConstructionSourceDatabase::open_migration(fixture.config("source")?)?;
    assert_eq!(unchanged.facts()?, before);
    Ok(())
}

#[test]
fn migration_rejects_wrong_keys_live_writers_and_uncompiled_successors() -> Result<(), StorageError>
{
    let fixture = Fixture::new()?;
    fixture.initialize(false)?;
    let source = ConstructionSourceDatabase::open_migration(fixture.config("source")?)?;
    assert!(execute_migration_command(fixture.request(false)?, &fixture.qualifications).is_err());
    drop(source);
    let mut request = fixture.request(false)?;
    request.target_schema_generation = 3;
    assert_eq!(
        execute_migration_command(request, &fixture.qualifications),
        Err(StorageError::UnsupportedMigration)
    );
    let mut request = fixture.request(false)?;
    request.master_key_file = fixture.path.join("guard");
    assert!(execute_migration_command(request, &fixture.qualifications).is_err());
    assert!(!fixture.path.join("target").exists());
    Ok(())
}

#[test]
fn migration_resumes_each_batch_cursor_completion_and_installation_boundary()
-> Result<(), StorageError> {
    for site in [
        StorageFaultSite::ConstructionBatch,
        StorageFaultSite::ConstructionCursor,
        StorageFaultSite::ConstructionCompletion,
        StorageFaultSite::ConstructionDirectoryRename,
    ] {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let fixture = Fixture::new()?;
            fixture.initialize(true)?;
            let faults = StorageFaultInjector::new(crate::StorageFaultCase { site, boundary }, 1)?;
            assert!(
                crate::migration_command::execute_migration_with_faults(
                    fixture.request(false)?,
                    &fixture.qualifications,
                    faults
                )
                .is_err()
            );
            let resumed =
                execute_migration_command(fixture.request(true)?, &fixture.qualifications)?;
            assert_eq!(resumed.state_generation, 7);
            let target = StorageEngine::open(fixture.config("target")?)?;
            let state = target.startup_scan()?;
            assert_eq!(state.state_generation(), 7);
            assert_eq!(target.state_meta.tbs().account_service_response_count, 11);
        }
    }
    Ok(())
}
