//! STA-10 and PRV-01: bounded replies and authorization through real TLS clients.
#![forbid(unsafe_code)]

use super::*;

fn assert_control_refused(lines: &[String]) -> TestResult {
    assert_contains(lines, " 481 ")
}

#[test]
fn missing_control_capabilities_refuse_before_mutation_and_survive_cap_removal() -> TestResult {
    let fixture = LiveFixture::create()?;
    #[cfg(feature = "history")]
    super::history::enable_history(&fixture)?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let (mut client, _) = exercise_account_client(&fixture)?;
    assert_contains(&client.send_until("JOIN #caps", " 366 ")?, " 366 ")?;
    for command in ["ACCT LABEL Refused", "CHANCTL REGISTER #caps"] {
        assert_control_refused(&send_and_sync(&mut client, &[command.to_owned()])?)?;
    }
    client.send_until("CAP REQ :standard-replies", " ACK ")?;
    assert_control_refused(&send_and_sync(
        &mut client,
        &["CHANCTL REGISTER #caps".to_owned()],
    )?)?;
    client.send_until(
        "CAP REQ :agenc.ag/account-controls agenc.ag/channel-controls",
        " ACK ",
    )?;
    // Success proves the refused REGISTER did not register the channel silently.
    assert_contains(
        &send_and_sync(&mut client, &["CHANCTL REGISTER #caps".to_owned()])?,
        "NOTE CHANCTL UPDATED",
    )?;
    assert_contains(
        &send_and_sync(&mut client, &["ACCT LABEL Accepted".to_owned()])?,
        "NOTE ACCT UPDATED",
    )?;
    #[cfg(feature = "history")]
    check_history_capability(&mut client)?;
    client.send_until("CAP REQ :-standard-replies", " ACK ")?;
    assert_control_refused(&send_and_sync(
        &mut client,
        &["ACCT LABEL RefusedAgain".to_owned()],
    )?)?;
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :capability regression complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}

#[cfg(feature = "history")]
fn check_history_capability(client: &mut IrcClient) -> TestResult {
    assert_contains(
        &send_and_sync(client, &["CHANCTL HISTORY #caps ON".to_owned()])?,
        "NOTE CHANCTL UPDATED",
    )?;
    let query = "CHATHISTORY LATEST #caps * 1".to_owned();
    assert_control_refused(&send_and_sync(client, std::slice::from_ref(&query))?)?;
    client.send_until(
        "CAP REQ :batch server-time message-tags message-ids draft/chathistory",
        " ACK ",
    )?;
    let history = send_and_sync(client, std::slice::from_ref(&query))?;
    assert_contains(&history, " BATCH +")?;
    assert_contains(&history, " BATCH -")?;
    client.send_until("CAP REQ :-draft/chathistory", " ACK ")?;
    assert_control_refused(&send_and_sync(client, &[query])?)
}

#[test]
fn secret_channel_mask_removal_and_controls_hide_channel_and_entry_existence() -> TestResult {
    let fixture = LiveFixture::create()?;
    #[cfg(feature = "history")]
    super::history::enable_history(&fixture)?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let (mut owner, account) = exercise_account_client(&fixture)?;
    owner.send_until("JOIN #secret", " 366 ")?;
    owner.send_until("MODE #secret +s", " MODE #secret ")?;
    owner.send_until("MODE #secret +b $n:blocked", " MODE #secret ")?;
    let (mut guest, _) = connect_registered_guest(&fixture)?;
    guest.send_until(
        "CAP REQ :standard-replies agenc.ag/channel-controls",
        " ACK ",
    )?;
    for channel in ["#secret", "#absent"] {
        assert_contains(
            &send_and_sync(&mut guest, &[format!("CHANCTL HISTORY {channel} ON")])?,
            " FAIL * REGISTRATION_REQUIRED :An account is required",
        )?;
    }
    let mut outsider = connect_registered_account(&fixture, "Outside", 91, account)?;
    outsider.send_until(
        "CAP REQ :standard-replies agenc.ag/channel-controls",
        " ACK ",
    )?;
    #[cfg(feature = "history")]
    outsider.send_until(
        "CAP REQ :batch server-time message-tags message-ids draft/chathistory",
        " ACK ",
    )?;
    let mut control_refusals = Vec::new();
    for channel in ["#secret", "#absent"] {
        for mask in ["$n:blocked", "$n:absent"] {
            let lines = send_and_sync(&mut outsider, &[format!("MODE {channel} -b {mask}")])?;
            assert_contains(
                &lines,
                &format!(" FAIL MODE SECRET_UNAVAILABLE {channel} :Channel is unavailable"),
            )?;
        }
        let lines = send_and_sync(&mut outsider, &[format!("CHANCTL HISTORY {channel} ON")])?;
        let refusal = lines
            .iter()
            .find(|line| line.contains(" 481 "))
            .ok_or_else(|| failure(format!("missing channel refusal: {lines:?}")))?;
        control_refusals.push(refusal.replace(channel, "#target"));
        #[cfg(feature = "history")]
        assert_contains(
            &send_and_sync(
                &mut outsider,
                &[format!("CHATHISTORY LATEST {channel} * 1")],
            )?,
            " 481 Outside :Command is unavailable",
        )?;
    }
    assert_eq!(control_refusals.first(), control_refusals.last());
    assert_contains(
        &owner.send_until("MODE #secret -b $n:blocked", " MODE #secret ")?,
        " MODE #secret -b $n:blocked",
    )?;
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :privacy regression complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}

#[test]
fn disabled_client_listener_needs_no_tls_files_but_enablement_requires_them() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut config = load_config(&fixture.config_path, ValidationDepth::Host)?;
    let mut dormant = config
        .listeners
        .iter()
        .find(|listener| listener.purpose == agenc_ircd_config::ListenerPurpose::ClientTls)
        .cloned()
        .ok_or("missing client listener")?;
    dormant.name = agenc_ircd_config::ListenerName::parse("dormant")?;
    dormant.enabled = false;
    let tls = dormant.tls.as_mut().ok_or("missing TLS config")?;
    tls.certificate_file = fixture._root.path().join("etc/tls/missing.crt");
    tls.private_key_file = fixture._root.path().join("etc/tls/missing.key");
    config.listeners.push(dormant);
    let secrets = SecretSet::load(&config)?;
    agenc_ircd_runtime::daemon::check_configuration(&config, &secrets)?;
    config
        .listeners
        .last_mut()
        .ok_or("missing dormant listener")?
        .enabled = true;
    assert!(SecretSet::load(&config).is_err());
    assert!(agenc_ircd_runtime::daemon::check_configuration(&config, &secrets).is_err());
    Ok(())
}
