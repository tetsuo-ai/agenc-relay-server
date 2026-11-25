//! A real old writer must open the original format and refuse a copy bearing the irreversible fence.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_storage::e2ee_records::initial_root::{FORMAT_KEY, InitialRootRow, KIND};
use agenc_relay_storage::{
    CommitOutcome, RecordMutation, StorageAccountingLimits, StorageMutationBatch,
    StorageMutationHead,
};
use agenc_relay_types::TransactionId;

fn seed_format_fence(fixture: &NodeFixture) -> TestResult {
    let owner = super::stage_ten_login_index::open_owner(
        fixture,
        [fixture.seed.wrapping_add(9); 32],
        None,
    )?;
    let recovered = owner.recovered_state();
    let revision = recovered
        .state_generation()
        .checked_add(1)
        .ok_or_else(|| failure("fixture revision overflow"))?;
    let marker = PersistentRecordValue::new(
        TableId::E2eeState,
        KIND,
        revision,
        0,
        None,
        vec![],
        InitialRootRow::format()?,
    )?;
    let mut writes = vec![RecordMutation::put(
        TableId::E2eeState,
        StoredKey::new(FORMAT_KEY.to_vec())?,
        1,
        None,
        marker.encode()?,
    )?];
    if let Some(accounting) = recovered.companion_disk_accounting() {
        let projected = accounting
            .project(&writes)?
            .ok_or_else(|| failure("format marker has no disk charge"))?;
        writes.push(RecordMutation::put(
            TableId::E2eeState,
            agenc_relay_storage::CompanionDiskAccounting::key()?,
            1,
            None,
            projected.record(revision)?.encode()?,
        )?);
    }
    let transaction_id = TransactionId::from_bytes([0x4a; 16]);
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id,
            expected_storage_commit_sequence: recovered.storage_commit_sequence(),
            expected_state_generation: recovered.state_generation(),
            resulting_state_generation: revision,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: recovered.account_service_response_count(),
            resulting_account_service_response_count: recovered.account_service_response_count(),
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: recovered.logical_database_bytes(),
            current_backup_stream_bytes: recovered.backup_stream_bytes(),
            database_max_bytes: DATABASE_MAX_BYTES,
            backup_max_bytes: BACKUP_MAX_BYTES,
        },
        writes,
    )?;
    let committed = owner.port().try_commit(batch)?.wait()?;
    assert!(
        matches!(committed, CommitOutcome::Committed(receipt) if receipt.transaction_id == transaction_id)
    );
    owner.shutdown()?;
    Ok(())
}

/// Copy only fixture-owned regular files; do not traverse links or share mutable database inodes.
fn copy_storage(source: &Path, target: &Path) -> TestResult {
    create_directory(target, 0o700)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let into = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_storage(&entry.path(), &into)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), into)?;
        } else {
            return Err(failure("unexpected nonregular fixture storage entry"));
        }
    }
    Ok(())
}

fn snapshot_configuration(fixture: &NodeFixture, label: &str) -> TestResult<PathBuf> {
    let old = fixture.data_dir.join("state");
    let new = fixture.data_dir.join(label);
    copy_storage(&old, &new)?;
    let text = fs::read_to_string(&fixture.config_path)?;
    let old = format!("state_dir = \"{}\"", old.display());
    let replacement = format!("state_dir = \"{}\"", new.display());
    if text.matches(&old).count() != 1 {
        return Err(failure(
            "expected one disposable state path in this fixture",
        ));
    }
    let config = fixture.config_path.with_file_name(format!("{label}.toml"));
    // Remove only the new per-peer opt-in when opening a cross-version profile.
    // The older daemon must fail its storage recovery, not its configuration parser.
    let mut compatible = String::new();
    for line in text.replace(&old, &replacement).lines() {
        if !matches!(
            line.trim(),
            "initial_root_profile = true" | "initial_root_profile = false"
        ) {
            compatible.push_str(line);
            compatible.push('\n');
        }
    }
    write_private(&config, compatible.as_bytes())?;
    Ok(config)
}

fn serve_with_tls(binary: &Path, config: &Path, fixture: &NodeFixture) -> TestResult {
    let mut child = DaemonProcess::start_binary(binary, config, None, None)?;
    let mut client = ArcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    client.read_until(|s| s.contains(" CAP * LS ") && !s.contains(" CAP * LS * :"))?;
    drop(client);
    let exit = child.stop()?;
    assert!(
        exit.success(),
        "serving control did not exit cleanly: {exit}"
    );
    Ok(())
}

/// Both calls require an orderly stopped coordinator before cloning its active state.
pub(super) fn verify_guarded_snapshot(
    fixture: &NodeFixture,
    legacy: &Path,
    label: &str,
) -> TestResult {
    let path = snapshot_configuration(fixture, label)?;
    let stderr = fixture.log_dir.join(format!("{label}.stderr"));
    let mut old = DaemonProcess::start_binary(legacy, &path, None, Some(&stderr))?;
    let status = old.wait_within(START_TIMEOUT)?;
    assert!(
        !status.success(),
        "the predecessor opened an enhanced store"
    );
    let message = fs::read_to_string(stderr)?;
    assert!(
        message.contains("storage"),
        "predecessor did not identify storage recovery: {message}"
    );
    assert!(
        !message.contains("configuration"),
        "predecessor refused configuration: {message}"
    );
    assert!(TcpStream::connect(fixture.public_address).is_err());
    serve_with_tls(Path::new(env!("CARGO_BIN_EXE_arcd")), &path, fixture)?;
    Ok(())
}

#[test]
#[ignore = "requires an independently built immutable pre-extension arcd; run scripts/test-initial-root-downgrade.sh"]
fn previous_daemon_accepts_legacy_and_refuses_the_last_guarded_account_format_fence() -> TestResult
{
    let previous = std::env::var_os("ARC_INITIAL_ROOT_PREVIOUS_ARCD")
        .ok_or_else(|| failure("missing immutable predecessor arcd"))?;
    let legacy = PathBuf::from(previous);
    let network = build_network()?;
    let fixture = &network.coordinator;
    let baseline = snapshot_configuration(fixture, "legacy-baseline")?;
    serve_with_tls(&legacy, &baseline, fixture)?;
    seed_format_fence(fixture)?;
    verify_guarded_snapshot(fixture, &legacy, "fenced")?;
    Ok(())
}
