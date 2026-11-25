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
    eprintln!("federated account check: initial read on the registered origin");
    let first =
        client.account_carrier_bytes("ACCTROOT", "CLAIM", "COMPLETE", request.as_bytes())?;
    eprintln!("federated account check: identical private read on a new federation sequence");
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

fn unexpected_full_origin_reply(line: &str, peer: &str) -> Box<dyn std::error::Error> {
    let mut fields = line.split_ascii_whitespace();
    let first = fields.next().unwrap_or_default();
    let (source, command) = match first.strip_prefix(':') {
        Some(prefix) if prefix == peer => ("expected edge", fields.next().unwrap_or_default()),
        Some(_) => ("other prefix", fields.next().unwrap_or_default()),
        None => ("unprefixed", first),
    };
    let kind = match (command, fields.next(), fields.next()) {
        ("FAIL", Some("ACCTROOT"), Some("UNAVAILABLE")) => {
            "FAIL ACCTROOT UNAVAILABLE with different trailing text"
        }
        ("FAIL", _, _) => "other FAIL",
        ("ACCTROOT", Some("COMPLETE"), _) => "ACCTROOT COMPLETE",
        ("ACCTROOT", Some("DATA"), _) => "ACCTROOT DATA",
        ("PING", _, _) => "PING",
        ("CAP", _, _) => "CAP",
        (numeric, _, _) if numeric.len() == 3 && numeric.bytes().all(|b| b.is_ascii_digit()) => {
            numeric
        }
        _ => "other command",
    };
    failure(format!(
        "unexpected full-origin reply from {source} ({kind})"
    ))
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
    eprintln!("federated account check: a different private owner reads");
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
    eprintln!("federated account check: first valid choice");
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
    eprintln!("federated account check: competing choice");
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
    await_directory_account(&mut publisher, account)?;
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
    eprintln!("federated account check: published choice after coordinator restart");
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

#[test]
fn a_full_remote_origin_refuses_before_hpke_and_keeps_its_sibling_on_the_same_link() -> TestResult {
    let network = build_network()?;
    let edge = &network.edge_a;
    select_peer(&network.coordinator, edge)?;
    select_peer(edge, &network.coordinator)?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut serving = DaemonProcess::start(&edge.config_path)?;
    wait_for_link(edge, 0)?;
    let connections = links_established(edge);
    let requests = account_requests(72)?;
    let [start, ..] = requests;
    let secret = InitialRootSecret::generate()?;
    let login = "root-capacity";
    let mut creator = ArcClient::connect(edge)?;
    creator.negotiate_sasl()?;
    negotiate_root(&mut creator)?;
    let id = create_account_with_root_option(&mut creator, edge, login, requests, Some(&secret))?;
    drop(creator);
    let mut filling = registered_owner(edge, "Filling", login, 77, id)?;
    let mut sibling = registered_owner(edge, "Sibling", login, 87, id)?;
    let (frozen, opener) = sealed_claim(edge, id, start, &secret, ClaimAction::Read, 97)?;
    let first =
        filling.account_carrier_bytes("ACCTROOT", "CLAIM", "COMPLETE", frozen.as_bytes())?;
    let opened = InitialRootServiceResponse::parse(first.as_slice().try_into()?)?;
    assert!(opener.open(&opened)?.state() == Some(ClaimState::Reserved));
    for n in 1..128 {
        // Each exchange sends 18 IRC commands. Stage 08 admits 40 registered
        // commands per second. Leave both the configured rate and its burst intact.
        thread::sleep(Duration::from_millis(500));
        let again =
            filling.account_carrier_bytes("ACCTROOT", "CLAIM", "COMPLETE", frozen.as_bytes())?;
        if again != first {
            return Err(failure(
                "room for the same inner replay changed the committed response",
            ));
        }
        if n % 8 == 0 {
            sibling.send_until("PING :capacity-sibling", " PONG ")?;
        }
    }
    let mut root = Principal::new(91, 92, id)?;
    let fingerprint = builders::root_fingerprint(&root.keys.root)?;
    let (overflow, _unused) = sealed_claim(
        edge,
        id,
        start,
        &secret,
        ClaimAction::Choose(fingerprint),
        98,
    )?;
    let refusal = filling.account_carrier_header("ACCTROOT", "CLAIM", overflow.as_bytes())?;
    let expected = format!(
        ":{} FAIL ACCTROOT UNAVAILABLE :Account root claim unavailable",
        edge.dns_name
    );
    if refusal != expected {
        return Err(unexpected_full_origin_reply(&refusal, &edge.dns_name));
    }
    assert_withdrawn(&mut filling)?;
    assert!(
        claim(
            &mut sibling,
            edge,
            id,
            start,
            &secret,
            ClaimAction::Read,
            99
        )? == Some(ClaimState::Reserved)
    );
    assert!(
        claim(
            &mut sibling,
            edge,
            id,
            start,
            &secret,
            ClaimAction::Choose(fingerprint),
            100
        )? == Some(ClaimState::Chosen(fingerprint))
    );
    let mut ordinary = authenticated_session(edge, "Ordinary", login, 102, id)?;
    await_directory_account(&mut ordinary, id)?;
    publish(&mut ordinary, &mut root, true)?;
    assert_eq!(links_established(edge), connections);
    drop((ordinary, sibling));
    assert!(serving.stop()?.success());
    assert!(coordinator.stop()?.success());
    Ok(())
}
