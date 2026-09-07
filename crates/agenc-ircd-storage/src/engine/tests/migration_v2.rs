//! Real schema-two sources require complete validation before a schema-three copy.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use super::*;
use crate::{AuthenticatedSourceRecord, ConstructionSourceFacts, SourceRecordValidator};

#[path = "migration_backup.rs"]
mod backup_admission;

#[derive(Default)]
struct SourceTranscript {
    begins: u64,
    finished: bool,
    reject_audit: bool,
    records: BTreeMap<(TableId, Vec<u8>), Vec<u8>>,
}

impl SourceRecordValidator for SourceTranscript {
    fn begin_source(&mut self, facts: &ConstructionSourceFacts) -> Result<(), StorageError> {
        assert_eq!(facts.header.tbs().schema_generation, 2);
        assert_eq!(facts.state.state_generation, 7);
        self.begins += 1;
        self.finished = false;
        self.records.clear();
        Ok(())
    }

    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        assert_eq!(record.source_schema_generation(), 2);
        self.records.insert(
            (record.table(), record.key().as_bytes().to_vec()),
            record.plaintext().to_vec(),
        );
        if self.reject_audit && record.table() == TableId::Audit {
            return Err(StorageError::UnsupportedVersion);
        }
        Ok(())
    }

    fn finish_source(&mut self) -> Result<(), StorageError> {
        assert!(
            self.records
                .keys()
                .any(|(table, _)| *table == TableId::History)
        );
        self.finished = true;
        Ok(())
    }
}

fn source_records(fixture: &Fixture) -> Result<Vec<InitialStorageRecord>, StorageError> {
    let mut records = vec![InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        LoginIndexKeyState::stable(
            1,
            LoginIndexKey::from_bytes([23; 32]).key_id(fixture.header().network_id),
        )?
        .encode()?,
    )?];
    fixture.add_channel(&mut records)?;
    let channel = crate::domain_records::fixtures::channel(1)?;
    let mut control = HistoryControlRecord::empty(channel.channel_id, 3)?;
    control.high_water_sequence = 5;
    control.purged_through = 5;
    records.push(initial_value(
        TableId::History,
        history_control_key(channel.channel_id)?.as_bytes().to_vec(),
        PersistentRecordValue::new(
            TableId::History,
            2,
            7,
            0,
            None,
            vec![crate::RecordReference::new(
                TableId::Channel,
                StoredKey::new(channel.channel_id.as_bytes().to_vec())?,
            )?],
            control.encode()?,
        )?,
    )?);
    Ok(records)
}

fn initialize_two(
    fixture: &Fixture,
    records: Vec<InitialStorageRecord>,
) -> Result<(), StorageError> {
    let header_tbs = DatabaseHeaderTbs {
        schema_generation: 2,
        ..fixture.header()
    };
    let result = crate::initialize::initialize_legacy_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(
            &fixture.path.join("source"),
            &fixture.qualifications,
        )?,
        header_tbs,
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

fn request_three(fixture: &Fixture, resume: bool) -> Result<MigrationCommandRequest, StorageError> {
    Ok(MigrationCommandRequest {
        target_schema_generation: 3,
        ..fixture.request(resume)?
    })
}

#[test]
fn legacy_mailbox_without_durable_sequence_evidence_cannot_install_schema_three()
-> Result<(), StorageError> {
    use crate::e2ee_records::{MAILBOX_ROW_KIND, MailboxKind, MailboxRow};

    let fixture = Fixture::new()?;
    let mut records = source_records(&fixture)?;
    let key = MailboxRow::item_key(&[23; 32], &[24; 16], MailboxKind::Binding, 17)?;
    let item = MailboxRow::Item {
        object_id: [25; 32],
        conversation_id: [0; 32],
        inserted_at: 10,
        expires_at: 100,
        grant: None,
    };
    records.push(initial_value(
        TableId::E2eeState,
        key.as_bytes().to_vec(),
        PersistentRecordValue::new(
            TableId::E2eeState,
            MAILBOX_ROW_KIND,
            7,
            0,
            None,
            Vec::new(),
            item.encode()?,
        )?,
    )?);
    initialize_two(&fixture, records)?;
    let mut validator = SourceTranscript::default();
    assert_eq!(
        crate::execute_validated_migration_command(
            request_three(&fixture, false)?,
            &fixture.qualifications,
            &mut validator,
        ),
        Err(StorageError::UnsupportedMigration),
        "the target cannot infer a missing historical mailbox counter",
    );
    assert_eq!(backup_count(&fixture)?, 0);
    assert!(!fixture.path.join("target").exists());
    Ok(())
}

fn backup_count(fixture: &Fixture) -> Result<usize, StorageError> {
    std::fs::read_dir(fixture.path.join("backups"))
        .map_err(|_| StorageError::FilesystemRejected)?
        .try_fold(0, |count, entry| {
            entry.map_err(|_| StorageError::FilesystemRejected)?;
            Ok(count + 1)
        })
}

fn target_plaintext(
    engine: &StorageEngine,
    table: TableId,
    key: &StoredKey,
) -> Result<Vec<u8>, StorageError> {
    let bytes = engine
        .store
        .read_record(table, key.as_bytes())?
        .ok_or(StorageError::StaleState)?;
    let opened = SealedRecord::decode(&bytes)?.open(
        &engine.master_key,
        engine.binding,
        table,
        1,
        engine.header.tbs().storage_key_generation,
        key,
    )?;
    Ok(opened.expose_for_storage_codec().to_vec())
}

#[test]
fn schema_three_migration_preserves_existing_history_and_revalidates_installed_resume()
-> Result<(), StorageError> {
    let fixture = Fixture::new()?;
    initialize_two(&fixture, source_records(&fixture)?)?;
    assert!(matches!(
        StorageEngine::open(fixture.config("source")?),
        Err(StorageError::UnsupportedVersion)
    ));
    let mut validator = SourceTranscript::default();
    let receipt = crate::execute_validated_migration_command(
        request_three(&fixture, false)?,
        &fixture.qualifications,
        &mut validator,
    )?;
    assert!(validator.finished);
    assert_eq!(validator.begins, 1);
    let target = StorageEngine::open(fixture.config("target")?)?;
    target.startup_scan()?;
    assert_eq!(target.header.tbs().schema_generation, 3);
    assert_eq!(target.header.tbs().storage_key_generation, 2);
    assert_eq!(target.state_meta.tbs().state_generation, 7);
    assert_eq!(target.state_meta.tbs().account_service_response_count, 11);
    let channel = crate::domain_records::fixtures::channel(1)?;
    let key = history_control_key(channel.channel_id)?;
    assert_eq!(
        Some(&target_plaintext(&target, TableId::History, &key)?),
        validator
            .records
            .get(&(TableId::History, key.as_bytes().to_vec())),
    );
    drop(target);
    let resumed = crate::execute_validated_migration_command(
        request_three(&fixture, true)?,
        &fixture.qualifications,
        &mut validator,
    )?;
    assert_eq!(resumed.storage_operation_id, receipt.storage_operation_id);
    assert!(validator.finished);
    assert_eq!(validator.begins, 2);
    Ok(())
}

#[test]
fn semantic_source_refusal_precedes_backup_and_target_creation() -> Result<(), StorageError> {
    let fixture = Fixture::new()?;
    let mut records = source_records(&fixture)?;
    records.push(initial_value(
        TableId::Audit,
        1_u64.to_be_bytes().to_vec(),
        PersistentRecordValue::new(TableId::Audit, 1, 7, 0, None, Vec::new(), vec![99])?,
    )?);
    initialize_two(&fixture, records)?;
    let mut validator = SourceTranscript {
        reject_audit: true,
        ..SourceTranscript::default()
    };
    let result = crate::execute_validated_migration_command(
        request_three(&fixture, false)?,
        &fixture.qualifications,
        &mut validator,
    );
    assert_eq!(result, Err(StorageError::UnsupportedVersion));
    assert_eq!(validator.begins, 1);
    assert!(!validator.finished);
    assert!(
        validator
            .records
            .keys()
            .any(|(table, _)| *table == TableId::History)
    );
    assert_eq!(backup_count(&fixture)?, 0);
    assert!(!fixture.path.join("target").exists());
    assert!(!fixture.path.join("target.staging").exists());
    Ok(())
}

#[test]
fn an_unvalidated_command_cannot_select_the_schema_three_profile() -> Result<(), StorageError> {
    let fixture = Fixture::new()?;
    initialize_two(&fixture, source_records(&fixture)?)?;
    assert_eq!(
        execute_migration_command(request_three(&fixture, false)?, &fixture.qualifications),
        Err(StorageError::UnsupportedMigration),
    );
    assert_eq!(backup_count(&fixture)?, 0);
    assert!(!fixture.path.join("target").exists());
    Ok(())
}
