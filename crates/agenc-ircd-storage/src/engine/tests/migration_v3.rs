//! Exact generation-three source admission and durable generation-four construction.
#![forbid(unsafe_code)]

use super::*;
use crate::construction_schema::ConstructionSchema;
use crate::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;
use crate::e2ee_records::delivery_recovery::DeliveryRecoveryRow;

#[derive(Default)]
struct ThreeTranscript {
    begins: u64,
    finished: bool,
    reject: bool,
    records: BTreeMap<(TableId, Vec<u8>), Vec<u8>>,
}

impl SourceRecordValidator for ThreeTranscript {
    fn begin_source(&mut self, facts: &ConstructionSourceFacts) -> Result<(), StorageError> {
        assert_eq!(facts.header.tbs().schema_generation, 3);
        self.begins += 1;
        self.finished = false;
        self.records.clear();
        Ok(())
    }

    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        assert_eq!(record.source_schema_generation(), 3);
        self.records.insert(
            (record.table(), record.key().as_bytes().to_vec()),
            record.plaintext().to_vec(),
        );
        if self.reject && record.table() == TableId::E2eeState {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    fn finish_source(&mut self) -> Result<(), StorageError> {
        self.finished = true;
        Ok(())
    }
}

fn initialize_three(fixture: &Fixture) -> Result<(), StorageError> {
    let mut records = source_records(fixture)?;
    let body = crate::e2ee_records::delivery_recovery::fixture_body(7)?;
    let row = DeliveryRecoveryRow::decode(&body)?;
    records.push(initial_value(
        TableId::E2eeState,
        row.key()?.as_bytes().to_vec(),
        PersistentRecordValue::new(
            TableId::E2eeState,
            DELIVERY_RECOVERY_ROW_KIND,
            7,
            0,
            None,
            Vec::new(),
            body,
        )?,
    )?);
    let outcome = crate::initialize::initialize_legacy_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(
            &fixture.path.join("source"),
            &fixture.qualifications,
        )?,
        header_tbs: DatabaseHeaderTbs {
            schema_generation: 3,
            ..fixture.header()
        },
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
        outcome,
        StorageInitializationOutcome::Complete { .. }
    ));
    Ok(())
}

fn request_four(fixture: &Fixture, resume: bool) -> Result<MigrationCommandRequest, StorageError> {
    Ok(MigrationCommandRequest {
        target_schema_generation: 4,
        ..fixture.request(resume)?
    })
}

#[test]
fn schema_four_preserves_original_delivery_bytes_and_revalidates_installed_resume()
-> Result<(), StorageError> {
    let fixture = Fixture::new()?;
    initialize_three(&fixture)?;
    let mut validator = ThreeTranscript::default();
    let receipt = crate::execute_validated_migration_command(
        request_four(&fixture, false)?,
        &fixture.qualifications,
        &mut validator,
    )?;
    assert!(validator.finished);
    let target = StorageEngine::open_construction_target(
        fixture.config("target")?,
        ConstructionSchema::Four,
    )?;
    target.startup_scan()?;
    assert_eq!(target.header.tbs().schema_generation, 4);
    assert_eq!(target.header.tbs().storage_key_generation, 2);
    assert_eq!(
        target.header.tbs().server_incarnation,
        fixture.header().server_incarnation
    );
    assert_eq!(
        target.header.tbs().recovery_epoch,
        fixture.header().recovery_epoch
    );
    assert_eq!(target.state_meta.tbs().state_generation, 7);
    assert_eq!(target.state_meta.tbs().account_service_response_count, 11);
    for ((table, key), bytes) in &validator.records {
        if matches!(table, TableId::ChannelName | TableId::NicknameReservation) {
            continue;
        }
        assert_eq!(
            target_plaintext(&target, *table, &StoredKey::new(key.clone())?)?,
            *bytes
        );
    }
    drop(target);
    let resumed = crate::execute_validated_migration_command(
        request_four(&fixture, true)?,
        &fixture.qualifications,
        &mut validator,
    )?;
    assert_eq!(resumed.storage_operation_id, receipt.storage_operation_id);
    assert_eq!(validator.begins, 2);
    assert!(validator.finished);
    let backups = backup_count(&fixture)?;
    validator.reject = true;
    assert_eq!(
        crate::execute_validated_migration_command(
            request_four(&fixture, true)?,
            &fixture.qualifications,
            &mut validator,
        ),
        Err(StorageError::InvalidEncoding)
    );
    assert!(!validator.finished);
    assert_eq!(backup_count(&fixture)?, backups);
    Ok(())
}

#[test]
fn schema_three_semantic_refusal_creates_neither_backup_nor_target() -> Result<(), StorageError> {
    let fixture = Fixture::new()?;
    initialize_three(&fixture)?;
    let mut validator = ThreeTranscript {
        reject: true,
        ..ThreeTranscript::default()
    };
    assert_eq!(
        crate::execute_validated_migration_command(
            request_four(&fixture, false)?,
            &fixture.qualifications,
            &mut validator,
        ),
        Err(StorageError::InvalidEncoding)
    );
    assert_eq!(validator.begins, 1);
    assert!(!validator.finished);
    assert_eq!(backup_count(&fixture)?, 0);
    assert!(!fixture.path.join("target").exists());
    assert!(!fixture.path.join("target.staging").exists());
    Ok(())
}

#[test]
fn successor_selection_cannot_skip_or_omit_semantic_admission() -> Result<(), StorageError> {
    let fixture = Fixture::new()?;
    initialize_two(&fixture, source_records(&fixture)?)?;
    let mut validator = ThreeTranscript::default();
    assert!(
        crate::execute_validated_migration_command(
            request_four(&fixture, false)?,
            &fixture.qualifications,
            &mut validator,
        )
        .is_err()
    );
    assert_eq!(validator.begins, 0);
    assert_eq!(
        execute_migration_command(request_four(&fixture, false)?, &fixture.qualifications),
        Err(StorageError::UnsupportedMigration)
    );
    assert_eq!(backup_count(&fixture)?, 0);
    assert!(!fixture.path.join("target").exists());
    Ok(())
}
