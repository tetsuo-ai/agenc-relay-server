//! Retained rows remain readable after disabled service and compiled-off restarts.
#![forbid(unsafe_code)]

use super::*;

fn set_enabled(fixture: &LiveFixture, enabled: bool) -> TestResult {
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        &format!("history_enabled = {}", !enabled),
        &format!("history_enabled = {enabled}"),
    )?;
    fs::write(&fixture.config_path, config)?;
    Ok(())
}

fn start_binary(fixture: &LiveFixture, binary: &Path) -> TestResult<DaemonProcess> {
    let child = Command::new(binary)
        .args(["serve", "--config"])
        .arg(&fixture.config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(DaemonProcess { child: Some(child) })
}

fn stop(fixture: &LiveFixture, daemon: &mut DaemonProcess) -> TestResult {
    let mut admin = AdminClient::connect(fixture)?;
    admin.confirm_process("DIE :disabled history restart")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}

fn logical_rows(lines: &[String]) -> TestResult<Vec<String>> {
    message_rows(lines)
        .into_iter()
        .map(|line| {
            let (tags, message) = line
                .split_once(' ')
                .ok_or_else(|| failure("history row omitted tags"))?;
            let tags = tags
                .trim_start_matches('@')
                .split(';')
                .filter(|tag| !tag.starts_with("batch="))
                .collect::<Vec<_>>()
                .join(";");
            Ok(format!("@{tags} {message}"))
        })
        .collect()
}

fn seed_rows(fixture: &LiveFixture) -> TestResult<(AccountId, Vec<String>)> {
    enable_history(fixture)?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let (mut client, account) = exercise_account_client(fixture)?;
    capabilities(&mut client)?;
    let _setup = send_and_sync(
        &mut client,
        &[
            "JOIN #history".into(),
            "CHANCTL REGISTER #history".into(),
            "CHANCTL HISTORY #history ON".into(),
            "@+example/preserved=first PRIVMSG #history :retained-first".into(),
            "NOTICE #history :retained-second".into(),
        ],
    )?;
    let rows = logical_rows(&history(&mut client, "CHATHISTORY LATEST #history * 100")?)?;
    assert_eq!(rows.len(), 2);
    stop(fixture, &mut daemon)?;
    Ok((account, rows))
}

fn disabled_restart(
    fixture: &LiveFixture,
    binary: &Path,
    account: AccountId,
    seed: u8,
) -> TestResult {
    let mut daemon = start_binary(fixture, binary)?;
    let mut client = IrcClient::connect(fixture).map_err(|error| {
        failure(format!(
            "disabled startup using {}: {error}; {}",
            binary.display(),
            fixture.log_excerpt()
        ))
    })?;
    let offered = client.send_until("CAP LS 302", " CAP * LS :")?;
    assert!(
        !offered
            .iter()
            .any(|line| line.contains("draft/chathistory"))
    );
    drop(client);
    let mut client = connect_registered_account(fixture, "DisabledHistory", seed, account)?;
    let output = send_and_sync(
        &mut client,
        &[
            "JOIN #history".into(),
            "PRIVMSG #history :not-retained-while-disabled".into(),
            "CHATHISTORY LATEST #history * 100".into(),
        ],
    )?;
    assert!(message_rows(&output).is_empty(), "{output:?}");
    assert!(
        output.iter().any(|line| {
            line.contains("FAIL CHATHISTORY")
                || (line.contains(" 421 ") && line.contains("CHATHISTORY"))
                || line.contains(" 481 DisabledHistory :Command is unavailable")
        }),
        "{output:?}"
    );
    stop(fixture, &mut daemon)
}

#[test]
fn disabled_history_startup_preserves_original_rows() -> TestResult {
    let fixture = LiveFixture::create()?;
    let (account, original) = seed_rows(&fixture)?;
    set_enabled(&fixture, false)?;
    disabled_restart(
        &fixture,
        Path::new(env!("CARGO_BIN_EXE_agenc-ircd")),
        account,
        91,
    )?;
    if let Some(binaries) = std::env::var_os("AGENC_STAGE09_DISABLED_BINARIES") {
        let binaries: Vec<_> = std::env::split_paths(&binaries).collect();
        assert_eq!(
            binaries.len(),
            2,
            "matrix must supply default and WSS-only binaries"
        );
        for (seed, binary) in [95, 97].into_iter().zip(binaries) {
            disabled_restart(&fixture, &binary, account, seed)?;
        }
    }
    set_enabled(&fixture, true)?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut client =
        connect_registered_account(&fixture, "RestoredHistory", 93, account).map_err(|error| {
            failure(format!(
                "re-enabled startup: {error}; {}",
                fixture.log_excerpt()
            ))
        })?;
    capabilities(&mut client)?;
    let _joined = send_and_sync(&mut client, &["JOIN #history".into()])?;
    let restored = history(&mut client, "CHATHISTORY LATEST #history * 100")?;
    assert_eq!(logical_rows(&restored)?, original);
    stop(&fixture, &mut daemon)
}
