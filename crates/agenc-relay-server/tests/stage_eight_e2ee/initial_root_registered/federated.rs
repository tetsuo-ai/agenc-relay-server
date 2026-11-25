//! Ordinary registered creation and choice through a specifically negotiated remote edge.
#![forbid(unsafe_code)]

use super::*;

fn select_peer(host: &NodeFixture, peer: &NodeFixture) -> TestResult {
    let config = fs::read_to_string(&host.config_path)?;
    let selector = format!(
        "[[federation.peer]]\nserver_id = \"{}\"\n",
        peer.server_id.to_base64url()
    );
    if config.matches(&selector).count() != 1 {
        return Err(failure(
            "the fixture needs exactly one selected authenticated peer",
        ));
    }
    let selected = format!("{selector}initial_root_profile = true\n");
    fs::write(&host.config_path, config.replacen(&selector, &selected, 1))?;
    Ok(())
}

fn ordinary_edge(fixture: &NodeFixture) -> TestResult {
    let mut client = ArcClient::connect(fixture)?;
    client.negotiate_sasl()?;
    client.send("CAP REQ :agenc.ag/initial-root")?;
    let replies = client.read_until(|line| line.contains(" NAK ") || line.contains(" ACK "))?;
    if replies.iter().any(|line| line.contains(" NEW ")) {
        return Err(failure(
            "an unselected edge offered private account commands",
        ));
    }
    assert_contains(&replies, " NAK :agenc.ag/initial-root")
}

fn same_sealed_read_twice(
    client: &mut ArcClient,
    fixture: &NodeFixture,
    account: AccountId,
    start: RequestId,
    secret: &InitialRootSecret,
    expected: ClaimState,
) -> TestResult {
    let (request, opener) = sealed_claim(fixture, account, start, secret, ClaimAction::Read, 176)?;
    let first =
        client.account_carrier_bytes("ACCTROOT", "CLAIM", "COMPLETE", request.as_bytes())?;
    let second =
        client.account_carrier_bytes("ACCTROOT", "CLAIM", "COMPLETE", request.as_bytes())?;
    if first != second {
        return Err(failure(
            "a fresh federation sequence changed the original private response",
        ));
    }
    let response = InitialRootServiceResponse::parse(
        first
            .try_into()
            .map_err(|_| failure("private replay width"))?,
    )?;
    let opened = opener.open(&response)?;
    if opened.state() != Some(expected)
        || opened.account() != account
        || opened.creation_request() != start
    {
        return Err(failure(
            "private replay lost its account, original creation, or choice",
        ));
    }
    Ok(())
}

fn wait_for_public_account(client: &mut ArcClient, account: AccountId) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    for attempt in 0_u32.. {
        let label = format!("guardedpublisher{attempt}");
        client.send(&format!("@label={label} EKEY WHOAMI"))?;
        let reply = labeled_reply(client, &label)?;
        let words = result_words(completion_line(&reply)?)
            .ok_or_else(|| failure("missing scalar WHOAMI"))?;
        if matches!(words.as_slice(), [kind,verb,id,..] if kind == "EKEY" && verb == "ACCOUNT" && id == &account.to_text())
        {
            return Ok(());
        }
        if !matches!(words.as_slice(), [kind,command,code,..] if kind == "FAIL" && command == "EKEY" && matches!(code.as_str(), "E2EE_SYNCING" | "E2EE_ACCOUNT_REQUIRED"))
            || Instant::now() >= deadline
        {
            return Err(failure(
                "the ordinary edge did not resolve the signed-in publication account",
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(failure("WHOAMI label range exhausted"))
}

fn assert_withdrawn(owner: &mut ArcClient) -> TestResult {
    fn closed(e: &io::Error) -> bool {
        matches!(
            e.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionAborted
        )
    }
    let socket = owner.reader.get_mut();
    if let Err(error) = socket
        .write_all(b"CAP LIST\r\n")
        .and_then(|()| socket.flush())
    {
        return if closed(&error) {
            Ok(())
        } else {
            Err(error.into())
        };
    }
    // A read timeout, unrelated daemon line or a successful CAP reply does not prove withdrawal.
    for _ in 0..32 {
        let mut line = String::new();
        match owner.reader.read_line(&mut line) {
            Ok(0) => return Ok(()),
            Err(error) if closed(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(_) if line.contains(" DEL :agenc.ag/initial-root") => continue,
            Ok(_) if line.contains(" CAP ") => {
                return Err(failure(
                    "old client accepted a command after link replacement",
                ));
            }
            Ok(_) => {}
        }
    }
    Err(failure("old client never closed after link replacement"))
}

#[test]
fn negotiated_edge_transfers_preserve_guarded_choices_and_exact_replies_across_restart()
-> TestResult {
    let network = build_network()?;
    let fixture = &network.edge_a;
    select_peer(&network.coordinator, fixture)?;
    select_peer(fixture, &network.coordinator)?;
    let mut coord = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge = DaemonProcess::start(&fixture.config_path)?;
    let mut baseline = DaemonProcess::start(&network.edge_b.config_path)?;
    wait_for_link(fixture, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    ordinary_edge(&network.edge_b)?;
    let requests = account_requests(164)?;
    let [start, ..] = requests;
    let secret = InitialRootSecret::generate()?;
    let mut creator = ArcClient::connect(fixture)?;
    creator.negotiate_sasl()?;
    negotiate_root(&mut creator)?;
    let login = "federated-creator";
    let account =
        create_account_with_root_option(&mut creator, fixture, login, requests, Some(&secret))?;
    drop(creator);
    let mut owner = registered_owner(fixture, "EdgeOwner", login, 168, account)?;
    let mut selected = Principal::new(86, 87, account)?;
    let fingerprint = builders::root_fingerprint(&selected.keys.root)?;
    let wrong = InitialRootSecret::generate()?;
    assert!(
        claim(
            &mut owner,
            fixture,
            account,
            start,
            &wrong,
            ClaimAction::Read,
            174
        )?
        .is_none()
    );
    same_sealed_read_twice(
        &mut owner,
        fixture,
        account,
        start,
        &secret,
        ClaimState::Reserved,
    )?;
    assert!(
        claim(
            &mut owner,
            fixture,
            account,
            start,
            &secret,
            ClaimAction::Choose(fingerprint),
            177
        )? == Some(ClaimState::Chosen(fingerprint))
    );
    assert!(
        claim(
            &mut owner,
            fixture,
            account,
            start,
            &secret,
            ClaimAction::Choose([6; 32]),
            178
        )?
        .is_none()
    );
    let mut publisher = authenticated_session(&network.edge_b, "Publisher", login, 181, account)?;
    wait_for_public_account(&mut publisher, account)?;
    let object_id = publish(&mut publisher, &mut selected, true)?;
    drop(publisher);
    assert!(baseline.stop()?.success());
    assert!(coord.stop()?.success());
    // The registered client still has its old TCP stream. The replacement link cannot inherit consent.
    let before = links_established(fixture);
    let mut coord = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(fixture, before)?;
    assert_withdrawn(&mut owner)?;
    drop(owner);
    let mut reopened = registered_owner(fixture, "NewOwner", login, 188, account)?;
    assert!(
        claim(
            &mut reopened,
            fixture,
            account,
            start,
            &secret,
            ClaimAction::Read,
            192
        )? == Some(ClaimState::Published {
            fingerprint,
            object_id
        })
    );
    drop(reopened);
    assert!(edge.stop()?.success());
    assert!(coord.stop()?.success());
    Ok(())
}
