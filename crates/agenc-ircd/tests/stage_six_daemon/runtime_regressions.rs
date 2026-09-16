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

/// RUN-01 (#44): on the real daemon, a hidden channel that is full at the
/// operational member ceiling is refused with the same unavailable failure
/// as any unauthorized hidden JOIN, an absent name is created, and a full
/// listed channel reports its capacity outcome instead.
#[test]
fn full_hidden_channel_join_is_unavailable_and_absent_name_is_created() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        "[limits]\n",
        "[limits]\nmembers_per_channel = 2\n",
    )?;
    fs::write(&fixture.config_path, config)?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let (mut owner, account) = exercise_account_client(&fixture)?;
    owner.send_until("JOIN #packed", " 366 ")?;
    owner.send_until("MODE #packed +s", " MODE #packed ")?;
    owner.send_until("JOIN #quiet", " 366 ")?;
    owner.send_until("MODE #quiet +p", " MODE #quiet ")?;
    owner.send_until("JOIN #open", " 366 ")?;
    let mut second = connect_registered_account(&fixture, "Second", 95, account)?;
    // An invitation admits the second member to each hidden channel, which
    // fills every channel to the two-member ceiling.
    owner.send_until("INVITE Second #packed", " 341 ")?;
    owner.send_until("INVITE Second #quiet", " 341 ")?;
    for channel in ["#packed", "#quiet", "#open"] {
        second.send_until(&format!("JOIN {channel}"), " 366 ")?;
    }
    let mut outsider = connect_registered_account(&fixture, "Outside", 91, account)?;
    outsider.send_until("CAP REQ :standard-replies", " ACK ")?;
    let (mut guest, _) = connect_registered_guest(&fixture)?;
    guest.send_until("CAP REQ :standard-replies", " ACK ")?;
    for (client, creates_absent) in [(&mut outsider, false), (&mut guest, true)] {
        for channel in ["#packed", "#quiet"] {
            let lines = send_and_sync(client, &[format!("JOIN {channel}")])?;
            assert_contains(
                &lines,
                &format!(" FAIL JOIN SECRET_UNAVAILABLE {channel} :Channel is unavailable"),
            )?;
        }
        if creates_absent {
            // A guest may create an absent name: the creation path is a
            // documented, distinguishable outcome, not an existence leak.
            let lines = send_and_sync(client, &["JOIN #absent".to_owned()])?;
            assert_contains(&lines, " 366 ")?;
        }
    }
    let open = send_and_sync(&mut outsider, &["JOIN #open".to_owned()])?;
    assert!(
        !open.iter().any(|line| line.contains("SECRET_UNAVAILABLE")),
        "a full listed channel must not read as hidden: {open:?}"
    );
    assert!(
        open.iter()
            .any(|line| line.contains("SERVER_BUSY") || line.contains(" 471 ")),
        "a full listed channel reports capacity: {open:?}"
    );
    outsider.send_until("JOIN #fresh", " 366 ")?;
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :join privacy regression complete")?;
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

/// Idle, healthy admission: every fresh TLS connection to an otherwise idle
/// daemon receives its registration burst on the first attempt. A silent
/// close after the handshake is a failure here, never a retry, and the
/// daemon's own log must not record a deadline or overload close for any
/// of these connections (the two listener paths that close a fresh
/// connection before its first reply).
#[test]
fn idle_healthy_admission_never_silently_closes_a_fresh_connection() -> TestResult {
    LiveFixture::create()?.run(|fixture| {
        let mut daemon = DaemonProcess::start_for(fixture)?;
        for attempt in 1..=8_u32 {
            fixture.phase(&format!("fresh connection {attempt}"));
            let mut client = IrcClient::connect(fixture)?;
            let registered = client.register().map_err(|error| {
                fixture.attempt(format!(
                    "fresh connection {attempt}/8: silent close or refusal before the first reply ({error})"
                ));
                failure(format!(
                    "fresh connection {attempt} of 8 did not register on its only attempt: {error}\n{}",
                    fixture.log_excerpt()
                ))
            })?;
            fixture.attempt(format!("fresh connection {attempt}/8: registered"));
            assert_contains(&registered, " 001 LiveUser ")?;
            client.send("QUIT :idle admission")?;
            let _closed = client.shutdown_lines()?;
        }
        fixture.phase("shutdown");
        let mut admin = AdminClient::connect(fixture)?;
        admin.confirm_process("DIE :idle admission complete")?;
        assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
        let log = fixture.log_excerpt();
        let closes = log
            .lines()
            .filter(|line| line.contains("event=connection_closed"))
            .collect::<Vec<_>>();
        assert!(
            closes.iter().all(|line| {
                !line.contains("error=deadline") && !line.contains("error=memory_exhausted")
            }),
            "a fresh connection was closed by the daemon before its first reply:\n{}",
            closes.join("\n")
        );
        assert!(
            log.lines().any(|line| line.contains("event=connection_admitted")),
            "the retained log records admissions:\n{log}"
        );
        Ok(())
    })
}

/// A fixture that failed keeps exactly its bounded daemon logs and one
/// diagnostics record under a private directory: phases, every attempt with
/// its reason, the daemon child's exit, and the first failure. Keys, the
/// database, and the configuration are never copied.
#[test]
fn a_failed_fixture_retains_only_bounded_logs_and_diagnostics() -> TestResult {
    let retain_root = TestRoot::create()?;
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start_for(&fixture)?;
    fixture.phase("registration");
    let (mut guest, _) = connect_registered_guest(&fixture)?;
    guest.send("QUIT :retention")?;
    let _closed = guest.shutdown_lines()?;
    fixture.phase("shutdown");
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :retention complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    fixture.record_failure(String::from("injected failure"));
    fixture.record_failure(String::from("a later failure never replaces the first"));
    fixture.preserve(retain_root.path())?;

    let mut retained = fs::read_dir(retain_root.path())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert_eq!(retained.len(), 1, "one directory per fixture: {retained:?}");
    let directory = retained
        .pop()
        .ok_or_else(|| failure("retained directory"))?;
    assert_eq!(fs::metadata(&directory)?.mode() & 0o777, 0o700);
    let mut files = fs::read_dir(&directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        files.len() >= 2,
        "diagnostics and at least one log: {files:?}"
    );
    let mut copied_bytes = 0_usize;
    for file in &files {
        let metadata = fs::metadata(file)?;
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600, "{file:?}");
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("retained file name"))?;
        assert!(
            name == "diagnostics.txt" || !name.contains("key") && !name.ends_with(".toml"),
            "only logs and the record are retained: {name}"
        );
        if name != "diagnostics.txt" {
            copied_bytes = copied_bytes.saturating_add(usize::try_from(metadata.len())?);
        }
    }
    assert!(copied_bytes <= RETAINED_LOG_BYTES);
    let record = fs::read_to_string(directory.join("diagnostics.txt"))?;
    assert!(
        record.contains("child_exit: joined: exit status: 0"),
        "{record}"
    );
    assert!(
        record.contains("first_failure: injected failure"),
        "{record}"
    );
    assert!(!record.contains("a later failure"), "{record}");
    assert!(record.contains("  registration\n  shutdown\n"), "{record}");
    assert!(record.contains("guest registration attempt 1/"), "{record}");
    assert!(record.contains(": registered"), "{record}");
    let logs = files
        .iter()
        .filter(|file| {
            file.file_name()
                .is_some_and(|name| name != "diagnostics.txt")
        })
        .map(fs::read_to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    assert!(logs.contains("event=connection_admitted"), "{logs}");
    assert!(logs.contains("event=connection_closed"), "{logs}");
    Ok(())
}

/// Registers one guest under `nickname` on a fresh connection.
fn guest_named(fixture: &LiveFixture, nickname: &str) -> TestResult<IrcClient> {
    let mut client = IrcClient::connect(fixture)?;
    let registered = client.complete_registration(nickname)?;
    assert_contains(&registered, &format!(" 001 {nickname} "))?;
    Ok(client)
}

/// LIST selection precedes the 200-row page and the scan is charged first
/// (spec 14.3, Appendix A.1): with more than 200 listed channels an explicit
/// name still returns its row wherever it sorts, the unselected page holds
/// exactly 200 rows for ten query tokens, the next unselected LIST is
/// refused before any scan while the bucket is empty, and a named LIST is
/// admitted again once the bucket refilled one token.
#[test]
fn list_selection_precedes_the_page_and_the_scan_is_charged_first() -> TestResult {
    let fixture = LiveFixture::create()?;
    // The shared fixture refills two query tokens a second, so under a loaded
    // gate the page's own scan can refill the burst it just spent. One token
    // per twenty seconds keeps the refusal independent of load.
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        "[limits.rate.expensive_query]\nrefill_tokens = 2\nrefill_seconds = 1\nburst = 10",
        "[limits.rate.expensive_query]\nrefill_tokens = 1\nrefill_seconds = 20\nburst = 10",
    )?;
    fs::write(&fixture.config_path, config)?;
    let fixture = &fixture;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut creators = Vec::new();
    let mut joined = Vec::new();
    for creator in 1..=4_u32 {
        let mut client = guest_named(fixture, &format!("Lister{creator}"))?;
        for index in 1..=51_u32 {
            let channel = format!("#late-{creator}-{index}");
            client.send_until(&format!("JOIN {channel}"), " 366 ")?;
            joined.push(channel);
        }
        creators.push(client);
    }
    assert_eq!(joined.len(), 204);
    let mut lister = guest_named(fixture, "Lister5")?;
    let page = lister.send_until("LIST", " 323 ")?;
    let rows = page.iter().filter(|line| line.contains(" 322 ")).count();
    assert_eq!(rows, 200, "the page holds exactly the ceiling: {rows} rows");
    let missing = joined
        .iter()
        .find(|channel| {
            !page
                .iter()
                .any(|line| line.contains(&format!(" {channel} ")))
        })
        .cloned()
        .ok_or_else(|| failure("every channel fit the page"))?;
    // The page cost the whole ten-token burst: another unselected LIST
    // is refused before scanning, with nothing listed.
    let refused = send_and_sync(&mut lister, &["LIST".to_owned()])?;
    assert!(
        refused
            .iter()
            .any(|line| line.contains(" 481 ") || line.contains("SERVER_BUSY")),
        "an empty bucket refuses the scan: {refused:?}"
    );
    assert!(!refused.iter().any(|line| line.contains(" 322 ")));
    // One token refills within the interval; a named LIST costs one and
    // returns the late channel the page could not hold.
    thread::sleep(Duration::from_millis(20_500));
    let named = lister.send_until(&format!("LIST {missing}"), " 323 ")?;
    assert_eq!(
        named.iter().filter(|line| line.contains(" 322 ")).count(),
        1,
        "{named:?}"
    );
    assert_contains(&named, &format!(" {missing} "))?;
    // Two names cost one token as well, and an absent name yields no row.
    thread::sleep(Duration::from_millis(20_500));
    let mixed = lister.send_until(&format!("LIST {missing},#late-absent"), " 323 ")?;
    assert_eq!(
        mixed.iter().filter(|line| line.contains(" 322 ")).count(),
        1
    );
    drop(creators);
    let mut admin = AdminClient::connect(fixture)?;
    admin.confirm_process("DIE :list selection complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}
