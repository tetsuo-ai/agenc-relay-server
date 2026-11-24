//! SC-006. A registered device decrypts the exact real MLS object sent while its TLS
//! origin was offline, after the coordinator restarts and a fresh attachment fetches it.
#![forbid(unsafe_code)]
use super::recovery_submission::{attach_when_active, settle};
use super::recreated_routes::{Party, bind_direct};
use super::stage_ten_drills::wait_for_account_authority;
use super::*;

fn fetch(client: &mut ArcClient, owner: &mut Principal) -> TestResult<Vec<String>> {
    let label = owner.label();
    client.send(&format!("@label={label} EKEY FETCH MAILBOX APPLICATION *"))?;
    labeled_reply(client, &label)
}

fn empty(client: &mut ArcClient, owner: &mut Principal) -> TestResult {
    settle("a current empty device mailbox", || {
        assert_contains(&fetch(client, owner)?, " EKEY EMPTY APPLICATION")
    })
}

fn ack(
    client: &mut ArcClient,
    owner: &mut Principal,
    token: &[u8; 32],
    object: &[u8; 32],
) -> TestResult<Vec<String>> {
    settle("the device's ACK result", || {
        let label = owner.label();
        client.send(&format!(
            "@label={label} EKEY ACK MAILBOX {} {}",
            base64url_encode(token),
            base64url_encode(object)
        ))?;
        let reply = labeled_reply(client, &label)?;
        if reply.iter().any(|line| line.contains("E2EE_SYNCING")) {
            return Err(failure("E2EE_SYNCING"));
        }
        Ok(reply)
    })
}

fn item(page: &[String], bytes: &[u8]) -> TestResult<[u8; 32]> {
    let lines: Vec<_> = page
        .iter()
        .filter(|line| line.contains(" EKEY MAILBOX "))
        .collect();
    // This message is small enough for one mailbox object line.
    if lines.len() != 1 {
        let status = page
            .iter()
            .filter_map(|line| {
                let fields = words(line);
                fields
                    .iter()
                    .position(|w| w == "FAIL" || w == "EKEY" || w == "BATCH")
                    .map(|i| {
                        fields
                            .iter()
                            .skip(i)
                            .take(3)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
            })
            .collect::<Vec<_>>();
        return Err(failure(format!(
            "expected one mailbox item, received {status:?}"
        )));
    }
    assert_eq!(
        hash_at(page, "MAILBOX", 5)?,
        *e2ee::ObjectId::compute(bytes).as_bytes()
    );
    assert_eq!(fragments_object(page)?, bytes);
    hash_at(page, "MAILBOX", 3)
}

fn submit(sender: &mut Party, bound: &BoundConversation, object: &[u8]) -> TestResult {
    let label = sender.keys.label();
    send_object(
        &mut sender.client,
        &label,
        &bound.application_command(),
        object,
    )?;
    let echo = labeled_reply(&mut sender.client, &label)?;
    let completion = std::slice::from_ref(completion_line(&echo)?);
    assert_contains(completion, &bound.application_marker())?;
    assert!(fragments_object(completion)? == object);
    Ok(())
}

/// Only a definitive SYNCING refusal is retried, using a fresh MLS ciphertext each time.
fn send_when_ready(
    alice: &mut Party,
    bound: &BoundConversation,
    terminal: [u8; 32],
    sender: &real_clients::OpenMlsMember,
    group: &mut openmls::prelude::MlsGroup,
    sequence: u64,
    text: &str,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let aad = real_clients::application_aad(bound, terminal)?;
    let plaintext = real_clients::padded_content(bound, &alice.keys, sequence, terminal, text)?;
    let deadline = Instant::now() + NETWORK_WAIT;
    loop {
        group.set_aad(aad.clone());
        let message = group
            .create_message(&sender.provider, &sender.signer, &plaintext)?
            .to_bytes()?;
        let object = raw_object(ArcWireObjectKind::ApplicationMls, message)?;
        match submit(alice, bound, &object) {
            Ok(()) => return Ok((object, plaintext)),
            Err(error)
                if error.to_string().contains("E2EE_SYNCING") && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(200))
            }
            Err(error) => return Err(error),
        }
    }
}

fn enroll_secondary(bob: &mut Party, device: u8, now: u64) -> TestResult<Principal> {
    let facts = &bob.keys.keys;
    let initial = &facts.roster;
    let cert = builders::certificate(
        &facts.root_secret,
        &facts.root,
        &builders::DeviceSpec {
            target_roster_generation: 1,
            interval: (now - 3600, now + 86400),
            enrollment: (now - 10, now + 10),
            ..builders::DeviceSpec::new(device)
        },
    )?;
    let mut active: Vec<_> = initial
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .map(|active| active.certificate.clone())
        .collect();
    active.push(cert);
    active.sort_by_key(|c| c.tbs.device_id);
    let updated = builders::roster(
        &facts.root_secret,
        &facts.root,
        1,
        builders::roster_id(initial)?,
        (now, now + 86400),
        active,
        vec![],
    )?;
    let label = bob.keys.label();
    send_object(
        &mut bob.client,
        &label,
        "EKEY PUBLISH ROSTER",
        &wire_object(ArcWireObjectKind::DeviceRoster, &updated)?,
    )?;
    assert_contains(
        &labeled_reply(&mut bob.client, &label)?,
        " EKEY STORED ROSTER ",
    )?;
    let mut secondary = Principal::new_valid_at(BOB_ROOT, device, bob.account, now)?;
    secondary.keys.roster = updated;
    Ok(secondary)
}

fn party(
    fixture: &NodeFixture,
    nickname: &'static str,
    login: &'static str,
    seed: u8,
    identity: (u8, u8),
    now: u64,
) -> TestResult<Party> {
    let account = {
        let mut creation = ArcClient::connect(fixture)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, fixture, login, seed)?
    };
    let mut client = ArcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))?;
    client.send_until(&format!("CAP REQ :{E2EE_CAPS}"), " CAP * ACK ")?;
    client.complete_registration(nickname)?;
    let mut owner = Principal::new_valid_at(identity.0, identity.1, account, now)?;
    settle("the active companion origin before login", || {
        assert_contains(&fetch(&mut client, &mut owner)?, "E2EE_ACCOUNT_REQUIRED")
    })?;
    authenticate_live_account(
        &mut client,
        fixture,
        login,
        ACCOUNT_PASSWORD,
        seed + 2,
        account,
    )?;
    let mut party = Party {
        client,
        keys: owner,
        nickname,
        login,
        account,
        rejoin_seed: seed + 6,
    };
    settle("registered origin before publication", || {
        publish_and_attach(&mut party.client, &mut party.keys)
    })?;
    Ok(party)
}

fn restart_coordinator(network: &Network, coordinator: &mut DaemonProcess) -> TestResult {
    let (first, second) = (
        links_established(&network.edge_a),
        links_established(&network.edge_b),
    );
    assert!(coordinator.stop()?.success());
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(&network.edge_a, first)?;
    wait_for_link(&network.edge_b, second)?;
    Ok(())
}

#[test]
fn offline_direct_ciphertext_survives_restart_and_only_the_new_target_attachment_can_ack()
-> TestResult {
    encrypted_clients::run_network(|network, coordinator, _, _| {
        for edge in [&network.edge_a, &network.edge_b] {
            wait_for_link(edge, 0)?;
            wait_for_account_authority(edge)?;
        }
        let now = real_clients::wall_clock_seconds()?;
        let mut alice = party(
            &network.edge_a,
            "alice",
            "alice-account",
            41,
            (ALICE_ROOT, ALICE_DEVICE),
            now,
        )?;
        let mut bob = party(
            &network.edge_b,
            "bob",
            "bob-account",
            51,
            (BOB_ROOT, BOB_DEVICE),
            now,
        )?;
        let (creator, peer) = if alice.keys.account < bob.keys.account {
            (&mut alice, &mut bob)
        } else {
            (&mut bob, &mut alice)
        };
        let direct = bind_direct(creator, peer, (0, [0; 32]), None, DIRECT_GROUP)?;
        let terminal = activate_bootstrap_with(
            &mut creator.client,
            &mut creator.keys,
            &direct,
            &[&peer.keys],
        )?;

        let interval = (now - 60, now + 3600);
        let sender = real_clients::OpenMlsMember::new(&alice.keys, interval)?;
        let recipient = real_clients::OpenMlsMember::new(&bob.keys, interval)?;
        let mut group = sender.create_group(&direct.group_id)?;
        let key_package = sender.import_key_package(&recipient.key_package()?)?;
        let (_, welcome, _) =
            group.add_members(&sender.provider, &sender.signer, &[key_package])?;
        group.merge_pending_commit(&sender.provider)?;
        let mut receiving = recipient.join(&welcome.to_bytes()?)?;
        let aad = real_clients::application_aad(&direct, terminal)?;
        // The same registered account also has a second session on another edge
        // without this device's attachment. It cannot consume the device's mailbox.
        let mut mirror =
            authenticated_session(&network.edge_a, "bobmirror", bob.login, 57, bob.account)?;
        assert_contains(&fetch(&mut mirror, &mut bob.keys)?, "E2EE_DEVICE_REQUIRED")?;
        let mut second_bob = enroll_secondary(&mut bob, 99, now)?;
        attach_when_active(&mut mirror, &mut second_bob)?;
        empty(&mut mirror, &mut second_bob)?;
        empty(&mut bob.client, &mut bob.keys)?;
        let (live, _) = step(
            "live direct submission",
            send_when_ready(
                &mut alice,
                &direct,
                terminal,
                &sender,
                &mut group,
                0,
                "before disconnect",
            ),
        )?;
        assert!(receive_application(&mut bob.client, &direct)? == live);
        assert!(receive_application(&mut mirror, &direct)? == live);
        assert_contains(
            &fetch(&mut bob.client, &mut bob.keys)?,
            " EKEY EMPTY APPLICATION",
        )?;

        // Observe Bob's actual QUIT across the normal federation before the next EDIRECT.
        alice.client.send("JOIN #seen")?;
        alice
            .client
            .read_until(|l| l.contains(" 366 alice #seen "))?;
        bob.client.send("JOIN #seen")?;
        bob.client.read_until(|l| l.contains(" 366 bob #seen "))?;
        alice
            .client
            .read_until(|l| l.starts_with(":bob!") && l.contains(" JOIN #seen"))?;
        bob.client.send("QUIT :finish offline run")?;
        drop(bob.client);
        alice
            .client
            .read_until(|l| l.starts_with(":bob!") && l.contains(" QUIT "))?;
        // The coordinator and edges replay which ACKed origins are still live.
        restart_coordinator(network, coordinator)?;
        attach_when_active(&mut alice.client, &mut alice.keys)?;
        attach_when_active(&mut mirror, &mut second_bob)?;
        empty(&mut mirror, &mut second_bob)?;
        let (offline, plaintext) = step(
            "offline direct submission",
            send_when_ready(
                &mut alice,
                &direct,
                terminal,
                &sender,
                &mut group,
                1,
                "during disconnect",
            ),
        )?;
        assert!(receive_application(&mut mirror, &direct)? == offline); // Bob's other device is live.
        submit(&mut alice, &direct, &offline)?; // new label on a byte-identical retry
        assert_contains(
            &fetch(&mut alice.client, &mut alice.keys)?,
            " EKEY EMPTY APPLICATION",
        )?;
        assert_contains(
            &fetch(&mut mirror, &mut second_bob)?,
            " EKEY EMPTY APPLICATION",
        )?;

        restart_coordinator(network, coordinator)?;
        attach_when_active(&mut alice.client, &mut alice.keys)?;
        let mut returning =
            authenticated_session(&network.edge_b, "bobback", bob.login, 61, bob.account)?;
        attach_when_active(&mut returning, &mut bob.keys)?;
        let first = settle("first fetch after durable restart", || {
            item(&fetch(&mut returning, &mut bob.keys)?, &offline)
        })?;
        let id = *e2ee::ObjectId::compute(&offline).as_bytes();
        attach_when_active(&mut mirror, &mut second_bob)?;
        assert_contains(
            &ack(&mut mirror, &mut second_bob, &first, &id)?,
            "E2EE_OBJECT_NOT_FOUND",
        )?;
        assert_contains(
            &ack(&mut alice.client, &mut alice.keys, &first, &id)?,
            "E2EE_OBJECT_NOT_FOUND",
        )?;
        // A newer attachment on the other edge supersedes this origin and its grant.
        attach_when_active(&mut mirror, &mut bob.keys)?;
        assert_contains(
            &fetch(&mut returning, &mut bob.keys)?,
            "E2EE_DEVICE_REQUIRED",
        )?;
        let (again, fresh) = settle("fresh fetch at the other edge", || {
            let page = fetch(&mut mirror, &mut bob.keys)?;
            let token = item(&page, &offline)?;
            Ok((page, token))
        })?;
        assert_ne!(fresh, first);
        assert_contains(
            &ack(&mut mirror, &mut bob.keys, &first, &id)?,
            "E2EE_OBJECT_NOT_FOUND",
        )?;
        let received = real_clients::mls_body(
            &fragments_object(&again)?,
            ArcWireObjectKind::ApplicationMls,
        )?;
        assert_eq!(
            recipient.decrypt(&mut receiving, &received)?,
            (plaintext, aad.clone())
        );
        for _ in 0..2 {
            assert_contains(
                &ack(&mut mirror, &mut bob.keys, &fresh, &id)?,
                " EKEY ACKED ",
            )?;
        }
        assert_contains(
            &fetch(&mut mirror, &mut bob.keys)?,
            " EKEY EMPTY APPLICATION",
        )?;
        // Both edges retain a current eligible device. Only those current sessions get this copy.
        let mut second =
            authenticated_session(&network.edge_b, "bobother", bob.login, 72, bob.account)?;
        attach_when_active(&mut second, &mut second_bob)?;
        empty(&mut second, &mut second_bob)?;
        let (current, _) = send_when_ready(
            &mut alice,
            &direct,
            terminal,
            &sender,
            &mut group,
            2,
            "current devices on both edges",
        )?;
        assert_eq!(receive_application(&mut mirror, &direct)?, current);
        assert_eq!(receive_application(&mut second, &direct)?, current);
        returning.send("PING :old-device-copy")?;
        let quiet = returning
            .read_until(|line| line.contains(" PONG ") && line.contains("old-device-copy"))?;
        assert!(
            !quiet
                .iter()
                .any(|line| line.contains(&direct.application_marker())),
            "superseded attachment received a live direct application"
        );
        // This ordinary disconnect has no coordinator or edge restart between QUIT and submit.
        mirror.send("JOIN #seen")?;
        mirror.read_until(|l| l.contains(" 366 bobmirror #seen "))?;
        alice
            .client
            .read_until(|l| l.starts_with(":bobmirror!") && l.contains(" JOIN #seen"))?;
        mirror.send("QUIT :verify offline delivery without restart")?;
        drop(mirror);
        alice
            .client
            .read_until(|l| l.starts_with(":bobmirror!") && l.contains(" QUIT "))?;
        empty(&mut alice.client, &mut alice.keys)?;
        let (ordinary, content) = send_when_ready(
            &mut alice,
            &direct,
            terminal,
            &sender,
            &mut group,
            3,
            "offline without a restart",
        )?;
        attach_when_active(&mut returning, &mut bob.keys)?;
        let (exact, grant) = settle("ordinary reconnect fetch", || {
            let page = fetch(&mut returning, &mut bob.keys)?;
            let grant = item(&page, &ordinary)?;
            Ok((fragments_object(&page)?, grant))
        })?;
        let body = real_clients::mls_body(&exact, ArcWireObjectKind::ApplicationMls)?;
        assert_eq!(recipient.decrypt(&mut receiving, &body)?, (content, aad));
        let object = *e2ee::ObjectId::compute(&ordinary).as_bytes();
        assert_contains(
            &ack(&mut returning, &mut bob.keys, &grant, &object)?,
            " EKEY ACKED ",
        )?;
        empty(&mut returning, &mut bob.keys)?;
        Ok(())
    })
}
