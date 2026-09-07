//! The actual stopped command validates original signed legacy audit bytes.
#![forbid(unsafe_code)]

use agenc_ircd_admin::{
    AdminAuditEvent, AdminAuditEventTbs, AdminAuditPhase, AdminCommandTbs, AdminSessionId,
};
use agenc_ircd_runtime::state_core::durable::KeyDeriver;
use agenc_ircd_storage::{ReadPlan, SealedRecord, StorageOpenConfig, StorageOwner};

use super::*;

#[derive(Clone, Copy, Debug)]
enum AuditCase {
    Legacy,
    NewCommand,
    NewEncoding,
    BadSignature,
}

fn audit_body(fixture: &NodeFixture, case: AuditCase) -> TestResult<Vec<u8>> {
    let audit_key = Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(11); 32]);
    let operator_key = Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(12); 32]);
    let command: &[u8] = if matches!(case, AuditCase::NewCommand) {
        b"AUDIT EXPORT 0 0 maintenance-v1"
    } else {
        b"MOTD"
    };
    let command_tbs = AdminCommandTbs::new(
        NETWORK_ID,
        fixture.server_id,
        AdminSessionId::from_bytes([3; 16]),
        0,
        None,
        command,
    )?;
    let operator_signature = command_tbs.sign(&operator_key)?;
    let mut bytes = AdminAuditEvent::sign(
        AdminAuditEventTbs {
            network_id: NETWORK_ID,
            server_id: fixture.server_id,
            audit_signing_key_id: *audit_signing_key_id(audit_key.public_key().as_bytes())?
                .as_bytes(),
            audit_sequence: 0,
            created_at: 50,
            operator_id: fixture.operator_id,
            command_tbs,
            operator_signature,
            phase: AdminAuditPhase::Observed,
            previous_event_hash: [0; 32],
        },
        &audit_key,
    )?
    .encode()?;
    match case {
        AuditCase::NewEncoding => {
            *bytes
                .get_mut(1)
                .ok_or_else(|| failure("audit encoding is short"))? = 2;
        }
        AuditCase::BadSignature => {
            *bytes
                .last_mut()
                .ok_or_else(|| failure("audit signature is absent"))? ^= 1;
        }
        AuditCase::Legacy | AuditCase::NewCommand => {}
    }
    Ok(bytes)
}

fn limits() -> StorageEngineLimits {
    StorageEngineLimits {
        redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
        fixed_reserve_bytes: DISK_RESERVE_BYTES,
        reserve_percent: 1,
        database_max_bytes: DATABASE_MAX_BYTES,
        backup_max_bytes: BACKUP_MAX_BYTES,
        integrity_checkpoint_manifests: 10_000,
    }
}

fn initial_records(fixture: &NodeFixture, audit: &[u8]) -> TestResult<Vec<InitialStorageRecord>> {
    let login = LoginIndexKey::from_bytes([fixture.seed.wrapping_add(9); 32]);
    let key_state = LoginIndexKeyState::stable(1, login.key_id(NETWORK_ID))?;
    let opaque = PersistentRecordValue::new(
        TableId::OpaqueRecord,
        LIVE_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        fixture.opaque_fake_record.clone(),
    )?;
    Ok(vec![
        InitialStorageRecord::new(
            TableId::LoginIndexKeyState,
            StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            key_state.encode()?,
        )?,
        InitialStorageRecord::new(
            TableId::OpaqueRecord,
            StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
            1,
            opaque.encode()?,
        )?,
        InitialStorageRecord::new(
            TableId::Audit,
            StoredKey::new(0_u64.to_be_bytes().to_vec())?,
            1,
            audit.to_vec(),
        )?,
    ])
}

fn legacy_source(fixture: &NodeFixture, case: AuditCase) -> TestResult<Vec<u8>> {
    let source = fixture.data_dir.join("legacy-source");
    create_directory(&source, 0o700)?;
    let audit = PersistentRecordValue::new(
        TableId::Audit,
        1,
        1,
        0,
        None,
        Vec::new(),
        audit_body(fixture, case)?,
    )?
    .encode()?;
    let result = agenc_ircd_storage::initialize_legacy_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(&source, &embedded_storage_qualifications()?)?,
        header_tbs: DatabaseHeaderTbs {
            network_id: NETWORK_ID,
            server_id: fixture.server_id,
            server_incarnation: ServerIncarnation::from_bytes([fixture.seed.wrapping_add(1); 16]),
            database_instance_id: DatabaseId::from_bytes([fixture.seed.wrapping_add(6); 16]),
            storage_key_generation: 1,
            schema_generation: 2,
            recovery_epoch: RecoveryEpoch::from_bytes([fixture.seed.wrapping_add(2); 16]),
        },
        storage_master_key: StorageMasterKey::from_bytes([fixture.seed.wrapping_add(7); 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(
            [fixture.seed.wrapping_add(8); 32],
        ),
        mode: StorageInitializationMode::Live,
        initial_records: initial_records(fixture, &audit)?,
        account_service_response_count: 0,
        state_generation: 1,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: limits(),
    })?;
    assert!(matches!(
        result,
        StorageInitializationOutcome::Complete { .. }
    ));
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        &format!(
            "state_dir = \"{}\"",
            protected_path_text(&fixture.data_dir.join("state"))?
        ),
        &format!("state_dir = \"{}\"", protected_path_text(&source)?),
    )?;
    fs::write(&fixture.config_path, config)?;
    Ok(audit)
}

fn migrate(fixture: &NodeFixture, target: &Path, resume: bool) -> TestResult<std::process::Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"));
    command
        .args(["storage", "migrate", "--config"])
        .arg(&fixture.config_path)
        .args([
            "--target-schema-generation",
            "3",
            "--output-state-directory",
        ])
        .arg(target)
        .stdin(Stdio::null());
    if resume {
        command.arg("--resume");
    }
    Ok(command.output()?)
}

fn target_audit(fixture: &NodeFixture, target: &Path) -> TestResult<Vec<u8>> {
    target_audit_with_guard(fixture, target, [fixture.seed.wrapping_add(8); 32])
}

fn target_audit_with_guard(
    fixture: &NodeFixture,
    target: &Path,
    guard: [u8; 32],
) -> TestResult<Vec<u8>> {
    let master = [fixture.seed.wrapping_add(7); 32];
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: NETWORK_ID,
        expected_server_id: fixture.server_id,
        state_directory: StateDirectory::open(target, &embedded_storage_qualifications()?)?,
        storage_master_key: StorageMasterKey::from_bytes(master),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(guard),
        login_index_key: LoginIndexKey::from_bytes([fixture.seed.wrapping_add(9); 32]),
        previous_login_index_key: None,
        limits: limits(),
    })?;
    let recovered = owner.recovered_state();
    let keys = KeyDeriver::new(
        StorageMasterKey::from_bytes(master),
        recovered.database_binding(),
        recovered.storage_key_generation(),
    )?;
    let result = (|| {
        let key = StoredKey::new(0_u64.to_be_bytes().to_vec())?;
        let mut result = owner
            .port()
            .try_read(ReadPlan::exact(TableId::Audit, key.clone()))?
            .wait()?;
        assert!(!result.truncated);
        assert_eq!(result.records.len(), 1);
        let row = result
            .records
            .pop()
            .ok_or_else(|| failure("target audit row is absent"))?;
        assert_eq!(row.table, TableId::Audit);
        assert!(row.key == key);
        let sealed = SealedRecord::decode(&row.sealed_record)?;
        Ok(keys
            .open(TableId::Audit, &key, &sealed)?
            .expose_for_storage_codec()
            .to_vec())
    })();
    owner.shutdown()?;
    result
}

#[test]
fn schema_three_cli_requires_signed_legacy_audit_admission_before_outputs() -> TestResult {
    for case in [
        AuditCase::Legacy,
        AuditCase::NewCommand,
        AuditCase::NewEncoding,
        AuditCase::BadSignature,
    ] {
        let network = build_network()?;
        let fixture = &network.coordinator;
        let original = legacy_source(fixture, case)?;
        let target = fixture.data_dir.join("migrated");
        let output = migrate(fixture, &target, false)?;
        if matches!(case, AuditCase::Legacy) {
            assert!(
                output.status.success(),
                "{case:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(target_audit(fixture, &target)?, original);
            let resumed = migrate(fixture, &target, true)?;
            assert!(
                resumed.status.success(),
                "{}",
                String::from_utf8_lossy(&resumed.stderr)
            );
        } else {
            assert!(
                !output.status.success(),
                "unsupported source was installed: {case:?}"
            );
            assert!(!target.exists());
            assert_eq!(fs::read_dir(fixture.data_dir.join("backups"))?.count(), 0);
        }
    }
    Ok(())
}

fn restore_legacy(
    fixture: &NodeFixture,
    backup: &Path,
    target: &Path,
    guard: &Path,
    resume: bool,
) -> TestResult<std::process::Output> {
    let config = agenc_ircd_config::load_maintenance_config(&fixture.config_path)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"));
    command
        .args(["storage", "restore", "--config"])
        .arg(&fixture.config_path)
        .arg("--backup")
        .arg(backup)
        .arg("--source-master-key-file")
        .arg(&config.storage_master_key_file)
        .arg("--source-rollback-guard-key-file")
        .arg(&config.rollback_guard_key_file)
        .arg("--output-state-directory")
        .arg(target)
        .arg("--target-rollback-guard-key-file")
        .arg(guard)
        .arg("--declare-recovery-epoch")
        .stdin(Stdio::null());
    if resume {
        command.arg("--resume");
    }
    Ok(command.output()?)
}

fn one_migration_backup(fixture: &NodeFixture) -> TestResult<PathBuf> {
    let mut files = fs::read_dir(fixture.data_dir.join("backups"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(files.len(), 1);
    files
        .pop()
        .ok_or_else(|| failure("migration source backup is absent"))
}

fn point_at_restored_source(fixture: &NodeFixture, target: &Path, guard: &Path) -> TestResult {
    let old = agenc_ircd_config::load_maintenance_config(&fixture.config_path)?;
    let mut text = fs::read_to_string(&fixture.config_path)?;
    for (key, before, after) in [
        ("state_dir", old.state_directory.as_path(), target),
        (
            "rollback_guard_key_file",
            old.rollback_guard_key_file.as_path(),
            guard,
        ),
    ] {
        replace_once(
            &mut text,
            &format!("{key} = \"{}\"", protected_path_text(before)?),
            &format!("{key} = \"{}\"", protected_path_text(after)?),
        )?;
    }
    fs::write(&fixture.config_path, text)?;
    Ok(())
}

fn require_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn refuse_corrupted_backup(fixture: &NodeFixture, backup: &Path, guard: &Path) -> TestResult {
    let mut bytes = fs::read(backup)?;
    *bytes
        .last_mut()
        .ok_or_else(|| failure("signed backup is empty"))? ^= 1;
    let corrupt = fixture.data_dir.join("corrupt-legacy.backup");
    write_private(&corrupt, &bytes)?;
    let target = fixture.data_dir.join("refused-legacy-restore");
    let output = restore_legacy(fixture, &corrupt, &target, guard, false)?;
    assert!(!output.status.success());
    assert!(!target.exists());
    assert!(
        !fixture
            .data_dir
            .join(".refused-legacy-restore.agenc-construction-v1")
            .exists()
    );
    Ok(())
}

#[test]
fn legacy_restore_roundtrip_preserves_original_signatures_through_explicit_migration() -> TestResult
{
    let network = build_network()?;
    let fixture = &network.coordinator;
    let original = legacy_source(fixture, AuditCase::Legacy)?;
    require_success(&migrate(
        fixture,
        &fixture.data_dir.join("first-migration"),
        false,
    )?);
    let backup = one_migration_backup(fixture)?;
    let guard = fixture.data_dir.join("keys/legacy-restore-guard.key");
    write_private(&guard, &[39; 32])?;
    refuse_corrupted_backup(fixture, &backup, &guard)?;
    let restored = fixture.data_dir.join("legacy-restored");
    let output = restore_legacy(fixture, &backup, &restored, &guard, false)?;
    require_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("restored schema generation 2"));
    require_success(&restore_legacy(fixture, &backup, &restored, &guard, true)?);
    point_at_restored_source(fixture, &restored, &guard)?;
    let target = fixture.data_dir.join("restored-and-migrated");
    require_success(&migrate(fixture, &target, false)?);
    assert_eq!(
        target_audit_with_guard(fixture, &target, [39; 32])?,
        original
    );
    require_success(&migrate(fixture, &target, true)?);
    Ok(())
}
