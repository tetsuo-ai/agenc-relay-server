//! History behavior through the production daemon and authenticated storage restart.
#![forbid(unsafe_code)]

use super::*;

#[path = "history/disabled.rs"]
mod disabled;

#[path = "history/purge.rs"]
mod purge;

pub(super) fn enable_history(fixture: &LiveFixture) -> TestResult {
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        "history_enabled = false",
        "history_enabled = true",
    )?;
    fs::write(&fixture.config_path, config.as_bytes())?;
    Ok(())
}

fn capabilities(client: &mut IrcClient) -> TestResult {
    let lines = client.send_until("CAP REQ :batch server-time message-tags message-ids draft/chathistory labeled-response account-tag standard-replies agenc.ag/account-controls agenc.ag/channel-controls", " ACK ")?;
    assert_contains(&lines, "draft/chathistory")
}

fn history(client: &mut IrcClient, command: &str) -> TestResult<Vec<String>> {
    client.send(command)?;
    read_until(&mut client.reader, |line| line.contains(" BATCH -"))
}

fn message_rows(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter(|line| line.contains(" PRIVMSG #history ") || line.contains(" NOTICE #history "))
        .map(String::as_str)
        .collect()
}

#[test]
fn plaintext_history_preserves_identity_pages_and_policy_across_restart() -> TestResult {
    let fixture = LiveFixture::create()?;
    enable_history(&fixture)?;
    let mut first = DaemonProcess::start(&fixture.config_path)?;
    let (mut client, account) = exercise_account_client(&fixture)?;
    capabilities(&mut client)?;
    let setup = send_and_sync(
        &mut client,
        &[
            "JOIN #history".to_owned(),
            "CHANCTL REGISTER #history".to_owned(),
            "CHANCTL HISTORY #history ON".to_owned(),
        ],
    )?;
    assert_contains(&setup, "NOTE CHANCTL UPDATED")?;
    let messages: Vec<_> = (0..10)
        .map(|number| format!("@+example/tag=value{number} PRIVMSG #history :message-{number:02}"))
        .collect();
    let _sent = send_and_sync(&mut client, &messages)?;
    let initial = history(
        &mut client,
        "@label=history-test CHATHISTORY LATEST #history * 100",
    )?;
    assert_eq!(message_rows(&initial).len(), 10, "{initial:?}");
    assert_eq!(
        initial
            .iter()
            .filter(|line| line.contains(" BATCH +"))
            .count(),
        1
    );
    assert_eq!(
        initial
            .iter()
            .filter(|line| line.contains(" BATCH -"))
            .count(),
        1
    );
    assert_contains(&initial, "label=history-test")?;
    assert_contains(&initial, "+example/tag=value0")?;
    assert_contains(&initial, "AccountLive!")?;
    let originals: Vec<_> = message_rows(&initial)
        .iter()
        .map(|line| {
            line.split_once(" PRIVMSG #history :")
                .map(|(_, body)| body.to_owned())
                .ok_or_else(|| failure("missing history body"))
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(originals.first().map(String::as_str), Some("message-00"));
    assert_eq!(originals.last().map(String::as_str), Some("message-09"));
    let _renamed = send_and_sync(&mut client, &["NICK Changed".to_owned()])?;
    let again = history(&mut client, "CHATHISTORY LATEST #history * 100")?;
    assert_contains(&again, "AccountLive!")?;
    assert!(!again.iter().any(|line| line.contains("Changed!")));
    let unknown = history(
        &mut client,
        "CHATHISTORY BEFORE #history msgid=AAAAAAAAAAAAAAAAAAAAAA 100",
    )?;
    assert!(message_rows(&unknown).is_empty());
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :history restart")?;
    assert!(first.wait()?.success(), "{}", fixture.log_excerpt());
    drop(client);
    drop(admin);
    let mut second = DaemonProcess::start(&fixture.config_path)?;
    let mut reader = connect_registered_account(&fixture, "AfterRestart", 89, account)?;
    capabilities(&mut reader)?;
    let _joined = send_and_sync(&mut reader, &["JOIN #history".to_owned()])?;
    let restored = history(&mut reader, "CHATHISTORY LATEST #history * 100")?;
    assert_eq!(message_rows(&restored).len(), 10, "{restored:?}");
    assert_contains(&restored, "AccountLive!")?;
    let off = send_and_sync(
        &mut reader,
        &[
            "CHANCTL HISTORY #history OFF".to_owned(),
            "CHATHISTORY LATEST #history * 100".to_owned(),
        ],
    )?;
    assert!(message_rows(&off).is_empty());
    assert_contains(&off, " 481 AfterRestart :Command is unavailable")?;
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :history complete")?;
    assert!(second.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}
