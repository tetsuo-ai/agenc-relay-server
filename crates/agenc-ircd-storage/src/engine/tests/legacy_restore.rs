//! Legacy restore keeps its source generation and requires semantic admission.
#![forbid(unsafe_code)]

use std::os::unix::fs::PermissionsExt as _;

use super::*;
use crate::{
    RestoreBackupSource, RestoreBackupSourceConfig, RestoreCommandRequest, RestoreTrustKey,
};

fn trust() -> Result<BackupTrustKey, StorageError> {
    BackupTrustKey::new(Ed25519SecretKey::from_bytes([30; 32]).public_key())
}

fn source_config(keys: &[BackupTrustKey]) -> RestoreBackupSourceConfig<'_> {
    RestoreBackupSourceConfig {
        source_master_key: StorageMasterKey::from_bytes([27; 32]),
        source_guard_root: RollbackGuardRootKey::from_bytes([28; 32]),
        login_index_key: LoginIndexKey::from_bytes([23; 32]),
        previous_login_index_key: None,
        trusted_keys: keys,
        maximum_bytes: engine_limits().backup_max_bytes,
    }
}

#[test]
fn a_legacy_backup_cannot_gain_a_usable_restore_handle_without_semantic_admission()
-> Result<(), StorageError> {
    let (_fixture, bytes) = signed_backup()?;
    assert!(matches!(
        RestoreBackupSource::open(
            Cursor::new(bytes.clone()),
            StorageMasterKey::from_bytes([27; 32]),
            RollbackGuardRootKey::from_bytes([28; 32]),
            LoginIndexKey::from_bytes([23; 32]),
            None,
            &[trust()?],
            engine_limits().backup_max_bytes,
        ),
        Err(StorageError::UnsupportedMigration)
    ));
    let mut validator = SourceTranscript::default();
    let source = RestoreBackupSource::open_with_legacy_validation(
        Cursor::new(bytes.clone()),
        source_config(&[trust()?]),
        &mut validator,
    )?;
    assert_eq!(source.facts()?.header.tbs().schema_generation, 2);
    assert!(validator.finished);
    let mut refusal = RefuseHistory(SourceTranscript::default());
    assert!(matches!(
        RestoreBackupSource::open_with_legacy_validation(
            Cursor::new(bytes),
            source_config(&[trust()?]),
            &mut refusal,
        ),
        Err(StorageError::UnsupportedVersion)
    ));
    assert!(!refusal.0.finished);
    Ok(())
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), StorageError> {
    std::fs::write(path, bytes).map_err(|_| StorageError::FilesystemRejected)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| StorageError::FilesystemRejected)
}

fn restore_request(
    fixture: &Fixture,
    bytes: &[u8],
    resume: bool,
) -> Result<RestoreCommandRequest, StorageError> {
    write_private(&fixture.path.join("restore.backup"), bytes)?;
    write_private(&fixture.path.join("restore-guard"), &[39; 32])?;
    let signing_key = Ed25519SecretKey::from_bytes([30; 32]).public_key();
    Ok(RestoreCommandRequest {
        network_id: fixture.header().network_id,
        server_id: fixture.header().server_id,
        current_state_directory: fixture.path.join("source"),
        current_master_key_file: fixture.path.join("master"),
        current_rollback_guard_key_file: fixture.path.join("guard"),
        backup_path: fixture.path.join("restore.backup"),
        source_master_key_file: fixture.path.join("master"),
        source_rollback_guard_key_file: fixture.path.join("guard"),
        login_index_key_file: fixture.path.join("login"),
        login_index_previous_key_file: None,
        output_state_directory: fixture.path.join("restored-two"),
        target_rollback_guard_key_file: fixture.path.join("restore-guard"),
        target_master_key_file: None,
        resume,
        declare_recovery_epoch: true,
        trusted_backup_keys: vec![RestoreTrustKey::new(
            *trust()?.key_id.as_bytes(),
            *signing_key.as_bytes(),
            0,
            u64::MAX,
        )],
        limits: engine_limits(),
    })
}

fn restored_config(fixture: &Fixture) -> Result<StorageOpenConfig, StorageError> {
    Ok(StorageOpenConfig {
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([39; 32]),
        ..fixture.config("restored-two")?
    })
}

#[test]
fn legacy_restore_installs_schema_two_and_revalidates_installed_resume() -> Result<(), StorageError>
{
    let (fixture, bytes) = signed_backup()?;
    let mut validator = SourceTranscript::default();
    let receipt = crate::execute_validated_restore_command(
        restore_request(&fixture, &bytes, false)?,
        &fixture.qualifications,
        &mut validator,
    )?;
    assert!(validator.finished);
    assert_eq!(validator.begins, 1);
    assert_eq!(receipt.schema_generation, 2);
    assert_eq!(receipt.source_state_generation, 7);
    assert_eq!(receipt.target_state_generation, 0);
    assert_ne!(
        receipt.source_server_incarnation,
        receipt.target_server_incarnation
    );
    assert_ne!(receipt.source_recovery_epoch, receipt.target_recovery_epoch);
    assert!(matches!(
        StorageEngine::open(restored_config(&fixture)?),
        Err(StorageError::UnsupportedVersion)
    ));
    let target = ConstructionSourceDatabase::open_restore_boundary(
        restored_config(&fixture)?,
        crate::construction_schema::ConstructionSchema::Two,
    )?;
    assert_eq!(target.facts()?.header.tbs().schema_generation, 2);
    assert_eq!(target.facts()?.state.state_generation, 0);
    drop(target);
    let resumed = crate::execute_validated_restore_command(
        restore_request(&fixture, &bytes, true)?,
        &fixture.qualifications,
        &mut validator,
    )?;
    assert_eq!(resumed, receipt);
    assert_eq!(validator.begins, 2);
    let mut refusal = RefuseHistory(SourceTranscript::default());
    assert_eq!(
        crate::execute_validated_restore_command(
            restore_request(&fixture, &bytes, true)?,
            &fixture.qualifications,
            &mut refusal,
        ),
        Err(StorageError::UnsupportedVersion)
    );
    assert!(!refusal.0.finished);
    Ok(())
}

#[test]
fn a_refused_legacy_restore_creates_neither_output_nor_staging() -> Result<(), StorageError> {
    let (fixture, bytes) = signed_backup()?;
    for resume in [false, true] {
        let mut refusal = RefuseHistory(SourceTranscript::default());
        assert_eq!(
            crate::execute_validated_restore_command(
                restore_request(&fixture, &bytes, resume)?,
                &fixture.qualifications,
                &mut refusal,
            ),
            Err(StorageError::UnsupportedVersion)
        );
        assert!(!refusal.0.finished);
        assert!(!fixture.path.join("restored-two").exists());
        assert!(
            !fixture
                .path
                .join(".restored-two.agenc-construction-v1")
                .exists()
        );
    }
    assert_eq!(
        crate::execute_restore_command(
            restore_request(&fixture, &bytes, false)?,
            &fixture.qualifications,
        ),
        Err(StorageError::UnsupportedMigration)
    );
    assert!(!fixture.path.join("restored-two").exists());
    Ok(())
}
