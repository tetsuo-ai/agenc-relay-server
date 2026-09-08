//! The real successor command admits an unchanged, fully signed mixed audit chain.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_admin::{
    AuditChainCursor, AuditEvent, MaintenanceAuditEvent, MaintenanceAuditEventTbs,
    MaintenanceAuditPosition, MaintenanceAuditScope, MaintenanceKeyState, MaintenanceOperation,
    MaintenanceTransition,
};

fn migrate(fixture: &NodeFixture, target: &Path, resume: bool) -> TestResult<std::process::Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"));
    command
        .args(["storage", "migrate", "--config"])
        .arg(&fixture.config_path)
        .args([
            "--target-schema-generation",
            "4",
            "--output-state-directory",
        ])
        .arg(target)
        .stdin(Stdio::null());
    if resume {
        command.arg("--resume");
    }
    Ok(command.output()?)
}

pub(super) fn extend_to_current(
    fixture: &NodeFixture,
    source: &Path,
    guard: &Path,
) -> TestResult<PathBuf> {
    point_at_restored_source(fixture, source, guard)?;
    let target = fixture.data_dir.join("schema-four");
    require_success(&migrate(fixture, &target, false)?);
    require_success(&migrate(fixture, &target, true)?);
    Ok(target)
}

fn admin(
    fixture: &NodeFixture,
    cursor: AuditChainCursor,
    command: &[u8],
) -> TestResult<AuditEvent> {
    let audit_key = Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(11); 32]);
    let operator_key = Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(12); 32]);
    let command_tbs = AdminCommandTbs::new(
        NETWORK_ID,
        fixture.server_id,
        AdminSessionId::from_bytes([3; 16]),
        cursor.next_sequence,
        None,
        command,
    )?;
    let signature = command_tbs.sign(&operator_key)?;
    Ok(AuditEvent::Admin(AdminAuditEvent::sign(
        AdminAuditEventTbs {
            network_id: NETWORK_ID,
            server_id: fixture.server_id,
            audit_signing_key_id: *audit_signing_key_id(audit_key.public_key().as_bytes())?
                .as_bytes(),
            audit_sequence: cursor.next_sequence,
            created_at: 50,
            operator_id: fixture.operator_id,
            command_tbs,
            operator_signature: signature,
            phase: AdminAuditPhase::Observed,
            previous_event_hash: cursor.previous_event_hash,
        },
        &audit_key,
    )?))
}

fn maintenance(fixture: &NodeFixture, cursor: AuditChainCursor) -> TestResult<AuditEvent> {
    let key = Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(11); 32]);
    let scope = MaintenanceAuditScope::new(
        NETWORK_ID,
        fixture.server_id,
        DatabaseId::from_bytes([81; 16]),
        ServerIncarnation::from_bytes([82; 16]),
        RecoveryEpoch::from_bytes([83; 16]),
    );
    let transition = MaintenanceTransition::new(
        MaintenanceOperation::LoginIndexRotateStart,
        MaintenanceKeyState::new(1, [11; 32], 0, [0; 32], 0)?,
        MaintenanceKeyState::new(2, [12; 32], 1, [11; 32], 7)?,
    )?;
    Ok(AuditEvent::Maintenance(MaintenanceAuditEvent::sign(
        MaintenanceAuditEventTbs::new(
            scope,
            *audit_signing_key_id(key.public_key().as_bytes())?.as_bytes(),
            MaintenanceAuditPosition::new(
                cursor.next_sequence,
                49,
                10,
                11,
                cursor.previous_event_hash,
            )?,
            transition,
        )?,
        &key,
    )?))
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Valid,
    FutureCommand,
    BadTailSignature,
    Gap,
}

fn source(fixture: &NodeFixture, case: Case) -> TestResult<Vec<Vec<u8>>> {
    let first = admin(fixture, AuditChainCursor::genesis(), b"MOTD")?;
    let mut cursor = AuditChainCursor::genesis().advance_event(&first)?;
    if matches!(case, Case::Gap) {
        cursor.next_sequence += 1;
    }
    let second = maintenance(fixture, cursor)?;
    let cursor = cursor.advance_event(&second)?;
    let command: &[u8] = if matches!(case, Case::FutureCommand) {
        b"AUDIT EXPORT 0 0 maintenance-v2"
    } else {
        b"AUDIT EXPORT 0 0 maintenance-v1"
    };
    let third = admin(fixture, cursor, command)?;
    let mut originals = Vec::new();
    let mut records = Vec::new();
    for event in [first, second, third] {
        let mut body = event.encode()?;
        if matches!(case, Case::BadTailSignature) && event.audit_sequence() == 2 {
            *body
                .last_mut()
                .ok_or_else(|| failure("event has no signature"))? ^= 1;
        }
        let plaintext = PersistentRecordValue::new(
            TableId::Audit,
            event.encoding(),
            event.audit_sequence() + 1,
            0,
            None,
            Vec::new(),
            body,
        )?
        .encode()?;
        if records.is_empty() {
            records = initial_records(fixture, &plaintext)?;
        } else {
            records.push(InitialStorageRecord::new(
                TableId::Audit,
                StoredKey::new(event.audit_sequence().to_be_bytes().to_vec())?,
                1,
                plaintext.clone(),
            )?);
        }
        originals.push(plaintext);
    }
    initialize_source(fixture, 3, records)?;
    Ok(originals)
}

fn read_all_audit(fixture: &NodeFixture, target: &Path) -> TestResult<Vec<Vec<u8>>> {
    let master = [fixture.seed.wrapping_add(7); 32];
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: NETWORK_ID,
        expected_server_id: fixture.server_id,
        state_directory: StateDirectory::open(target, &embedded_storage_qualifications()?)?,
        storage_master_key: StorageMasterKey::from_bytes(master),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(
            [fixture.seed.wrapping_add(8); 32],
        ),
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
        let keys_to_read = (0_u64..3)
            .map(|sequence| StoredKey::new(sequence.to_be_bytes().to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        let read = owner
            .port()
            .try_read(ReadPlan::exact_keys(TableId::Audit, keys_to_read)?)?
            .wait()?;
        assert!(!read.truncated);
        assert_eq!(read.records.len(), 3);
        read.records
            .into_iter()
            .map(|row| {
                let opened = keys.open(
                    TableId::Audit,
                    &row.key,
                    &SealedRecord::decode(&row.sealed_record)?,
                )?;
                Ok(opened.expose_for_storage_codec().to_vec())
            })
            .collect::<TestResult<Vec<_>>>()
    })();
    owner.shutdown()?;
    result
}

#[test]
fn schema_four_cli_preserves_mixed_signatures_and_refuses_invalid_complete_sources() -> TestResult {
    for case in [
        Case::Valid,
        Case::FutureCommand,
        Case::BadTailSignature,
        Case::Gap,
    ] {
        let network = build_network()?;
        let fixture = &network.coordinator;
        let originals = source(fixture, case)?;
        let target = fixture.data_dir.join("schema-four-direct");
        let output = migrate(fixture, &target, false)?;
        if matches!(case, Case::Valid) {
            require_success(&output);
            assert_eq!(read_all_audit(fixture, &target)?, originals);
            require_success(&migrate(fixture, &target, true)?);
            assert_eq!(read_all_audit(fixture, &target)?, originals);
        } else {
            assert!(
                !output.status.success(),
                "invalid source installed: {case:?}"
            );
            assert!(!target.exists());
            assert_eq!(fs::read_dir(fixture.data_dir.join("backups"))?.count(), 0);
        }
    }
    Ok(())
}
