//! Actual stopped commands must produce authenticated atomic maintenance history.
#![forbid(unsafe_code)]

#[path = "stage_ten_login_index/paging.rs"]
mod paging;

use super::*;
use agenc_ircd_admin::{AuditChainCursor, AuditEvent, MaintenanceAuditEvent, MaintenanceOperation};
use agenc_ircd_runtime::state_core::durable::KeyDeriver;
use agenc_ircd_storage::{ReadPlan, SealedRecord, StorageOpenConfig, StorageOwner};

const NEW_KEY: [u8; 32] = [219; 32];

pub(super) fn rotation(
    fixture: &NodeFixture,
    new_key: Option<&Path>,
) -> TestResult<std::process::Output> {
    let command_name = if new_key.is_some() {
        "login-index-rotate-start"
    } else {
        "login-index-rotate-finish"
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"));
    command
        .args(["storage", command_name, "--config"])
        .arg(&fixture.config_path);
    if let Some(path) = new_key {
        command.arg("--new-key-file").arg(path);
    }
    Ok(command.stdin(Stdio::null()).output()?)
}

pub(super) fn rotation_commit(output: &std::process::Output) -> TestResult<u64> {
    let text = std::str::from_utf8(&output.stdout)?;
    let values: Vec<_> = text
        .lines()
        .flat_map(|line| line.split("; "))
        .filter_map(|field| field.strip_prefix("storage commit sequence: "))
        .collect();
    assert_eq!(values.len(), 1);
    Ok(values
        .first()
        .ok_or_else(|| failure("missing rotation receipt"))?
        .parse()?)
}

pub(super) fn open_owner(
    fixture: &NodeFixture,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
) -> TestResult<StorageOwner> {
    Ok(StorageOwner::start(StorageOpenConfig {
        expected_network_id: NETWORK_ID,
        expected_server_id: fixture.server_id,
        state_directory: StateDirectory::open(
            &fixture.data_dir.join("state"),
            &embedded_storage_qualifications()?,
        )?,
        storage_master_key: StorageMasterKey::from_bytes([fixture.seed.wrapping_add(7); 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(
            [fixture.seed.wrapping_add(8); 32],
        ),
        login_index_key: LoginIndexKey::from_bytes(current),
        previous_login_index_key: previous.map(LoginIndexKey::from_bytes),
        limits: StorageEngineLimits {
            redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
            fixed_reserve_bytes: DISK_RESERVE_BYTES,
            reserve_percent: 1,
            database_max_bytes: DATABASE_MAX_BYTES,
            backup_max_bytes: BACKUP_MAX_BYTES,
            integrity_checkpoint_manifests: 10_000,
        },
    })?)
}

pub(super) fn read_plaintext(
    owner: &StorageOwner,
    keys: &KeyDeriver,
    table: TableId,
    key: StoredKey,
) -> TestResult<Vec<u8>> {
    let result = owner
        .port()
        .try_read(ReadPlan::exact(table, key.clone()))?
        .wait()?;
    assert_eq!(
        result.storage_commit_sequence,
        owner.recovered_state().storage_commit_sequence()
    );
    assert!(!result.truncated);
    assert_eq!(result.records.len(), 1);
    let record = result
        .records
        .first()
        .ok_or_else(|| failure("missing sealed row"))?;
    assert_eq!(record.table, table);
    assert_eq!(record.key.as_bytes(), key.as_bytes());
    let sealed = SealedRecord::decode(&record.sealed_record)?;
    Ok(keys
        .open(table, &key, &sealed)?
        .expose_for_storage_codec()
        .to_vec())
}

struct RotationState {
    state: LoginIndexKeyState,
    generation: u64,
    commit: u64,
    opaque: Vec<u8>,
    events: Vec<MaintenanceAuditEvent>,
}

fn inspect(
    fixture: &NodeFixture,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
    count: u64,
) -> TestResult<RotationState> {
    let owner = open_owner(fixture, current, previous)?;
    let recovered = owner.recovered_state();
    let keys = KeyDeriver::new(
        StorageMasterKey::from_bytes([fixture.seed.wrapping_add(7); 32]),
        recovered.database_binding(),
        recovered.storage_key_generation(),
    )?;
    let state = LoginIndexKeyState::decode(&read_plaintext(
        &owner,
        &keys,
        TableId::LoginIndexKeyState,
        StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
    )?)?;
    let opaque = read_plaintext(
        &owner,
        &keys,
        TableId::OpaqueRecord,
        StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
    )?;
    assert_eq!(recovered.table_record_count(TableId::Audit), count);
    let mut events = Vec::new();
    let mut cursor = AuditChainCursor {
        next_sequence: 0,
        previous_event_hash: [0; 32],
    };
    for sequence in 0..count {
        let bytes = read_plaintext(
            &owner,
            &keys,
            TableId::Audit,
            StoredKey::new(sequence.to_be_bytes().to_vec())?,
        )?;
        let value = PersistentRecordValue::decode(TableId::Audit, &bytes)?;
        assert_eq!(value.record_kind(), 2);
        assert_eq!(value.revision(), sequence + 1);
        assert_eq!(value.generation(), 0);
        assert!(value.references().is_empty());
        assert_eq!(value.expires_at(), None);
        let event = MaintenanceAuditEvent::decode_exact(value.body())?;
        event.verify(
            NETWORK_ID,
            fixture.server_id,
            Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(11); 32]).public_key(),
        )?;
        cursor = cursor.advance_event(&AuditEvent::Maintenance(event.clone()))?;
        events.push(event);
    }
    let result = RotationState {
        state,
        generation: recovered.state_generation(),
        commit: recovered.storage_commit_sequence(),
        opaque,
        events,
    };
    owner.shutdown()?;
    Ok(result)
}

pub(super) fn install_key_mapping(
    fixture: &NodeFixture,
    new_key: &Path,
    previous: bool,
) -> TestResult {
    let configured = agenc_ircd_config::load_maintenance_config(&fixture.config_path)?;
    let old_key = if previous {
        configured.login_index_key_file
    } else {
        configured
            .login_index_previous_key_file
            .ok_or_else(|| failure("previous login-index key is not configured"))?
    };
    let mut config = fs::read_to_string(&fixture.config_path)?;
    if previous {
        replace_once(
            &mut config,
            &format!("login_index_key_file = \"{}\"", old_key.display()),
            &format!(
                "login_index_key_file = \"{}\"\nlogin_index_previous_key_file = \"{}\"",
                new_key.display(),
                old_key.display()
            ),
        )?;
    } else {
        replace_once(
            &mut config,
            &format!(
                "login_index_previous_key_file = \"{}\"\n",
                old_key.display()
            ),
            "",
        )?;
    }
    fs::write(&fixture.config_path, config)?;
    Ok(())
}

#[test]
fn rotation_commands_commit_signed_empty_start_and_finish() -> TestResult {
    let network = build_network()?;
    let fixture = &network.coordinator;
    let old_key = [fixture.seed.wrapping_add(9); 32];
    let before = inspect(fixture, old_key, None, 0)?;
    let new_key = fixture.data_dir.join("keys/login-index-next.key");
    write_private(&new_key, &NEW_KEY)?;
    let original_config = fs::read(&fixture.config_path)?;
    let started = rotation(fixture, Some(&new_key))?;
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let start_commit = rotation_commit(&started)?;
    assert_eq!(start_commit, before.commit + 1);
    assert_eq!(fs::read(&fixture.config_path)?, original_config);
    let started = inspect(fixture, NEW_KEY, Some(old_key), 1)?;
    assert_eq!(started.generation, before.generation + 1);
    // Shutdown installs the integrity checkpoint after the rotation receipt.
    assert_eq!(started.commit, start_commit + 1);
    assert_eq!(started.opaque, before.opaque);
    assert_eq!(started.state.previous(), Some((1, 0)));
    assert_eq!(
        started
            .events
            .first()
            .ok_or_else(|| failure("start audit event missing"))?
            .tbs()
            .transition()
            .operation(),
        MaintenanceOperation::LoginIndexRotateStart
    );
    for (current, previous) in [
        (old_key, None),
        (NEW_KEY, None),
        (old_key, Some(NEW_KEY)),
        (NEW_KEY, Some([220; 32])),
    ] {
        assert!(open_owner(fixture, current, previous).is_err());
    }
    assert!(!rotation(fixture, Some(&new_key))?.status.success());
    install_key_mapping(fixture, &new_key, true)?;
    let finished = rotation(fixture, None)?;
    assert!(
        finished.status.success(),
        "{}",
        String::from_utf8_lossy(&finished.stderr)
    );
    let finish_commit = rotation_commit(&finished)?;
    assert_eq!(finish_commit, started.commit + 1);
    assert!(open_owner(fixture, NEW_KEY, Some(old_key)).is_err());
    install_key_mapping(fixture, &new_key, false)?;
    let finished = inspect(fixture, NEW_KEY, None, 2)?;
    assert_eq!(finished.generation, started.generation + 1);
    assert_eq!(finished.commit, finish_commit + 1);
    assert_eq!(finished.opaque, before.opaque);
    assert_eq!(finished.state.previous(), None);
    assert_eq!(finished.events.first(), started.events.first());
    assert_eq!(
        finished
            .events
            .get(1)
            .ok_or_else(|| failure("finish audit event missing"))?
            .tbs()
            .transition()
            .operation(),
        MaintenanceOperation::LoginIndexRotateFinish
    );
    assert!(!rotation(fixture, None)?.status.success());
    assert_eq!(inspect(fixture, NEW_KEY, None, 2)?.commit, finished.commit);
    Ok(())
}
