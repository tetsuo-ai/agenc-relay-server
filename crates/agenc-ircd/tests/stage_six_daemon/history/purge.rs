//! Signed purge confirmation, physical deletion, and restart behavior.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::{ReadPlan, StorageOpenConfig, StorageOwner};

fn retained(client: &mut IrcClient, phase: &str) -> TestResult<Vec<String>> {
    client.send("CHATHISTORY LATEST #history * 100")?;
    let lines = read_until(&mut client.reader, |line| {
        line.contains(" BATCH -") || line.contains("FAIL CHATHISTORY")
    })
    .map_err(|error| failure(format!("{phase}: {error}")))?;
    if lines.iter().any(|line| line.contains("FAIL CHATHISTORY")) {
        return Err(failure(format!("{phase}: {lines:?}")));
    }
    Ok(lines)
}

fn until(client: &mut IrcClient, command: &str, ending: &str) -> TestResult<Vec<String>> {
    client
        .send_until(command, ending)
        .map_err(|error| failure(format!("{command}: {error}")))
}

fn stored_history(fixture: &LiveFixture) -> TestResult<(ChannelInstanceId, usize)> {
    let config = load_config(&fixture.config_path, ValidationDepth::Host)?;
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: fixture.network_id,
        expected_server_id: fixture.server_id,
        state_directory: StateDirectory::open(
            &config.storage.state_dir,
            &embedded_storage_qualifications()?,
        )?,
        storage_master_key: StorageMasterKey::from_bytes([7; 32]),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes([8; 32]),
        login_index_key: LoginIndexKey::from_bytes([9; 32]),
        previous_login_index_key: None,
        limits: StorageEngineLimits {
            redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
            fixed_reserve_bytes: DISK_RESERVE_BYTES,
            reserve_percent: 1,
            database_max_bytes: DATABASE_MAX_BYTES,
            backup_max_bytes: BACKUP_MAX_BYTES,
            integrity_checkpoint_manifests: 10_000,
        },
    })?;
    let channel = owner
        .port()
        .try_read(ReadPlan::range(
            TableId::Channel,
            StoredKey::new(vec![0; 16])?,
            StoredKey::new(vec![255; 16])?,
            2,
        )?)?
        .wait()?;
    assert_eq!(channel.records.len(), 1);
    let id = ChannelInstanceId::from_bytes(
        channel
            .records
            .first()
            .ok_or_else(|| failure("channel missing"))?
            .key
            .as_bytes()
            .try_into()?,
    );
    let history = owner
        .port()
        .try_read(ReadPlan::range(
            TableId::History,
            StoredKey::new(vec![0; 24])?,
            StoredKey::new(vec![255; 24])?,
            100,
        )?)?
        .wait()?;
    let recovered = owner.recovered_state();
    let keys = agenc_ircd_runtime::state_core::durable::KeyDeriver::new(
        StorageMasterKey::from_bytes([7; 32]),
        recovered.database_binding(),
        recovered.storage_key_generation(),
    )?;
    for row in &history.records {
        if row.key.as_bytes().get(16..) == Some(&[0; 8]) {
            let sealed = agenc_ircd_storage::SealedRecord::decode(&row.sealed_record)?;
            let opened = keys.open(TableId::History, &row.key, &sealed)?;
            let value =
                PersistentRecordValue::decode(TableId::History, opened.expose_for_storage_codec())?;
            let control =
                agenc_ircd_storage::history_records::HistoryControlRecord::decode(value.body())?;
            assert!(
                control.history_authorization_generation <= recovered.state_generation(),
                "control authority {} exceeds state {}",
                control.history_authorization_generation,
                recovered.state_generation()
            );
            assert!(
                control.high_water_sequence <= recovered.state_generation(),
                "history sequence {} exceeds state {}",
                control.high_water_sequence,
                recovered.state_generation()
            );
        }
    }
    let messages = history
        .records
        .iter()
        .filter(|row| row.key.as_bytes().get(16..) != Some(&[0; 8]))
        .count();
    owner.shutdown()?;
    Ok((id, messages))
}

#[test]
fn confirmed_history_purge_deletes_rows_before_success_and_preserves_new_messages() -> TestResult {
    let fixture = LiveFixture::create()?;
    enable_history(&fixture)?;
    let mut first = DaemonProcess::start(&fixture.config_path)?;
    let (mut client, account) = exercise_account_client(&fixture)?;
    capabilities(&mut client)?;
    let _joined = until(&mut client, "JOIN #history", " 366 ")?;
    for command in ["CHANCTL REGISTER #history", "CHANCTL HISTORY #history ON"] {
        let setup = until(&mut client, command, "CHANCTL")?;
        assert_contains(&setup, "NOTE CHANCTL UPDATED")?;
    }
    let _captured = send_and_sync(&mut client, &["PRIVMSG #history :before-purge".into()])?;
    assert_eq!(
        message_rows(&retained(&mut client, "initial capture")?).len(),
        1
    );
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :identify history instance")?;
    assert!(first.wait()?.success());
    drop(admin);
    drop(client);
    let (channel, rows) = stored_history(&fixture)?;
    assert_eq!(rows, 1);

    let mut second = DaemonProcess::start(&fixture.config_path)?;
    let mut client = connect_registered_account(&fixture, "PurgeReader", 91, account)
        .map_err(|error| failure(format!("restart before purge: {error}")))?;
    capabilities(&mut client)?;
    let _joined = until(&mut client, "JOIN #history", " 366 ")?;
    let mut admin = AdminClient::connect(&fixture)?;
    let command = format!(
        "CHANNEL HISTORY PURGE {} :delete retained plaintext",
        channel.to_base64url()
    );
    let challenge = admin.command_line(&command)?;
    assert!(
        challenge.starts_with("NOTE CHANNEL CONFIRM "),
        "{challenge}"
    );
    // The unsigned confirmation stage cannot hide or delete retained messages.
    assert_eq!(
        message_rows(&retained(&mut client, "unconfirmed purge")?).len(),
        1
    );
    let token = ConfirmationToken::parse(
        challenge
            .split_ascii_whitespace()
            .nth(3)
            .ok_or_else(|| failure("confirmation token"))?
            .as_bytes(),
    )?;
    admin.send(&command, Some(&token))?;
    let result = read_line(&mut admin.reader)?;
    assert!(
        result.contains("NOTE CHANNEL OK :Channel history purged"),
        "{result}"
    );
    assert!(message_rows(&retained(&mut client, "completed purge")?).is_empty());
    admin.confirm_process("DIE :verify physical purge")?;
    assert!(second.wait()?.success(), "{}", fixture.log_excerpt());
    drop(admin);
    drop(client);
    assert_eq!(stored_history(&fixture)?.1, 0);

    let mut third = DaemonProcess::start(&fixture.config_path)?;
    let mut client = connect_registered_account(&fixture, "AfterPurge", 93, account)
        .map_err(|error| failure(format!("restart after purge: {error}")))?;
    capabilities(&mut client)?;
    let _joined = until(&mut client, "JOIN #history", " 366 ")?;
    let _captured = send_and_sync(&mut client, &["PRIVMSG #history :after-purge".into()])?;
    let current = retained(&mut client, "new message after restart")?;
    assert_eq!(message_rows(&current).len(), 1);
    assert_contains(&current, "after-purge")?;
    assert!(!current.iter().any(|line| line.contains("before-purge")));
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :purge test complete")?;
    assert!(third.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}
