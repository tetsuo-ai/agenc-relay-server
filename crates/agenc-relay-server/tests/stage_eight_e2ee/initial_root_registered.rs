//! Negotiated, registered prospective authority through a real coordinator and its persistent directory.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_auth::{
    InitialRootServiceResponse,
    initial_root::{ClaimAction, ClaimState, seal_claim},
};
use agenc_relay_crypto::{InitialRootExchange, InitialRootSecret};

fn negotiate_root(client: &mut ArcClient) -> TestResult {
    client.send("CAP LS 302")?;
    let offered = client.read_until(|line| line.contains(" LS ") && !line.contains(" LS * :"))?;
    if offered
        .iter()
        .any(|line| line.contains("agenc.ag/initial-root"))
    {
        return Err(failure(
            "a fresh legacy listing received an unsolicited optional capability",
        ));
    }
    client.send("CAP REQ :agenc.ag/initial-root")?;
    let expected = format!(
        " NEW :agenc.ag/initial-root=v1.{}",
        agenc_relay_types::INITIAL_ROOT_PROFILE_TOKEN
    );
    let discovered = client.read_until(|line| {
        line.contains(" NEW ") || line.contains(" ACK ") || line.contains(" NAK ")
    })?;
    assert_contains(&discovered, &expected)?;
    let ack = client.read_until(|line| line.contains(" ACK ") || line.contains(" NAK "))?;
    assert_contains(&ack, " ACK :agenc.ag/initial-root")
}

fn registered_owner(
    fixture: &NodeFixture,
    nick: &str,
    login: &str,
    seed: u8,
    account: AccountId,
) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(fixture)?;
    client.negotiate_sasl()?;
    negotiate_root(&mut client)?;
    authenticate_live_account(&mut client, fixture, login, ACCOUNT_PASSWORD, seed, account)?;
    client.complete_registration(nick)?;
    Ok(client)
}

fn sealed_claim(
    fixture: &NodeFixture,
    account: AccountId,
    start: RequestId,
    secret: &InitialRootSecret,
    action: ClaimAction,
    request_id: u8,
) -> TestResult<(
    agenc_relay_auth::InitialRootServiceEnvelope,
    agenc_relay_auth::initial_root::ClaimOpenToken,
)> {
    let public = AccountHpkePrivateKey::from_bytes(ACCOUNT_HPKE_PRIVATE)?.public_key()?;
    let binding = AccountRequestBinding::new(
        NETWORK_ID,
        account_recovery_epoch(fixture, NETWORK_ID)?,
        public.key_id(),
        RequestId::from_bytes([request_id; 16]),
        InitialRootExchange::Claim,
    );
    Ok(seal_claim(public, binding, account, start, secret, action)?)
}

fn claim(
    client: &mut ArcClient,
    fixture: &NodeFixture,
    account: AccountId,
    start: RequestId,
    secret: &InitialRootSecret,
    action: ClaimAction,
    request_id: u8,
) -> TestResult<Option<ClaimState>> {
    let (request, token) = sealed_claim(fixture, account, start, secret, action, request_id)?;
    let bytes =
        client.account_carrier_bytes("ACCTROOT", "CLAIM", "COMPLETE", request.as_bytes())?;
    let result = token.open(&InitialRootServiceResponse::parse(
        bytes
            .try_into()
            .map_err(|_| failure("private claim response width"))?,
    )?)?;
    if result.account() != account
        || result.creation_request() != start
        || result.action() != action
    {
        return Err(failure(
            "private claim did not belong to the original account operation",
        ));
    }
    Ok(result.state())
}

fn publish(
    client: &mut ArcClient,
    principal: &mut Principal,
    accepted: bool,
) -> TestResult<[u8; 32]> {
    let bytes = wire_object(ArcWireObjectKind::RootIdentity, &principal.keys.root)?;
    let label = principal.label();
    send_object(client, &label, "EKEY PUBLISH IDENTITY", &bytes)?;
    let lines = labeled_reply(client, &label)?;
    assert_contains(
        &lines,
        if accepted {
            " EKEY STORED IDENTITY "
        } else {
            " FAIL EKEY "
        },
    )?;
    Ok(*e2ee::ObjectId::compute(&bytes).as_bytes())
}

#[test]
fn registered_guarded_creation_choice_and_directory_survive_coordinator_restart() -> TestResult {
    let network = build_network()?;
    let fixture = &network.coordinator;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut edge = DaemonProcess::start(&network.edge_a.config_path)?;
    wait_for_link(&network.edge_a, 0)?;
    let keys = account_requests(31)?;
    let start = keys[0];
    let secret = InitialRootSecret::generate()?;
    let other_secret = InitialRootSecret::generate()?;
    let account = {
        let mut creator = ArcClient::connect(fixture)?;
        creator.negotiate_sasl()?;
        negotiate_root(&mut creator)?;
        create_account_with_root_option(
            &mut creator,
            fixture,
            "protected-creator",
            keys,
            Some(&secret),
        )?
    };
    let mut publisher = registered_owner(fixture, "Creator", "protected-creator", 39, account)?;
    let mut directory = authenticated_session(
        &network.edge_a,
        "Directory",
        "protected-creator",
        55,
        account,
    )?;
    let mut selected = Principal::new(72, 73, account)?;
    let mut other = Principal::new(74, 75, account)?;
    let fingerprint = builders::root_fingerprint(&selected.keys.root)?;
    let other_fp = builders::root_fingerprint(&other.keys.root)?;
    assert!(
        claim(
            &mut publisher,
            fixture,
            account,
            start,
            &other_secret,
            ClaimAction::Read,
            101
        )?
        .is_none()
    );
    assert!(
        claim(
            &mut publisher,
            fixture,
            account,
            start,
            &secret,
            ClaimAction::Read,
            102
        )? == Some(ClaimState::Reserved)
    );
    publish(&mut directory, &mut selected, false)?;
    assert!(
        claim(
            &mut publisher,
            fixture,
            account,
            start,
            &secret,
            ClaimAction::Choose(fingerprint),
            103
        )? == Some(ClaimState::Chosen(fingerprint))
    );
    assert!(
        claim(
            &mut publisher,
            fixture,
            account,
            start,
            &secret,
            ClaimAction::Choose(other_fp),
            104
        )?
        .is_none()
    );
    publish(&mut directory, &mut other, false)?;
    // The edge retains the original terminal response for this connection and identical object.
    publish(&mut directory, &mut selected, false)?;
    drop(directory);
    let mut directory = authenticated_session(
        &network.edge_a,
        "FreshDirectory",
        "protected-creator",
        63,
        account,
    )?;
    let object_id = publish(&mut directory, &mut selected, true)?;
    let published = ClaimState::Published {
        fingerprint,
        object_id,
    };
    assert!(
        claim(
            &mut publisher,
            fixture,
            account,
            start,
            &secret,
            ClaimAction::Read,
            105
        )? == Some(published)
    );
    drop(publisher);
    drop(directory);
    let _ = edge.stop()?;
    let _ = daemon.stop()?;
    if let Some(previous) = std::env::var_os("ARC_INITIAL_ROOT_PREVIOUS_ARCD") {
        super::initial_root_downgrade::verify_guarded_snapshot(
            fixture,
            Path::new(&previous),
            "registered-guarded-copy",
        )?;
    }

    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut restored = registered_owner(fixture, "Returned", "protected-creator", 47, account)?;
    assert!(
        claim(
            &mut restored,
            fixture,
            account,
            start,
            &secret,
            ClaimAction::Read,
            106
        )? == Some(published)
    );
    let _ = daemon.stop()?;
    Ok(())
}

#[test]
fn separate_registered_legacy_account_cannot_read_or_choose_the_creators_claim() -> TestResult {
    let network = build_network()?;
    let fixture = &network.coordinator;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut edge = DaemonProcess::start(&network.edge_a.config_path)?;
    wait_for_link(&network.edge_a, 0)?;

    // An unchanged client sees its closed base registry on either listener.
    // Even an explicit 302 probe on an ordinary federation route receives a NAK.
    let mut ordinary_edge = ArcClient::connect(&network.edge_a)?;
    ordinary_edge.negotiate_sasl()?;
    ordinary_edge.send("CAP REQ :agenc.ag/initial-root")?;
    let refusal = ordinary_edge.read_until(|line| {
        line.contains(" NAK ") || line.contains(" ACK ") || line.contains(" NEW ")
    })?;
    assert_contains(&refusal, " NAK :agenc.ag/initial-root")?;
    drop(ordinary_edge);

    let secret = InitialRootSecret::generate()?;
    let requests = account_requests(110)?;
    let mut creator = ArcClient::connect(fixture)?;
    creator.negotiate_sasl()?;
    negotiate_root(&mut creator)?;
    let owner = create_account_with_root_option(
        &mut creator,
        fixture,
        "reserved-owner",
        requests,
        Some(&secret),
    )?;
    drop(creator);
    let mut ordinary = ArcClient::connect(fixture)?;
    ordinary.negotiate_sasl()?;
    let other = create_live_account(&mut ordinary, fixture, "ordinary-stranger", 113)?;
    drop(ordinary);
    assert_ne!(owner, other);

    let mut stranger = registered_owner(fixture, "Stranger", "ordinary-stranger", 116, other)?;
    let mut request_id = 121;
    for target in [owner, other] {
        for action in [ClaimAction::Read, ClaimAction::Choose([9; 32])] {
            // Both the original START and the secret belong to the real guarded owner.
            assert!(
                claim(
                    &mut stranger,
                    fixture,
                    target,
                    requests[0],
                    &secret,
                    action,
                    request_id
                )?
                .is_none()
            );
            request_id += 1;
        }
    }
    drop(stranger);
    let mut returned = registered_owner(fixture, "Owner", "reserved-owner", 126, owner)?;
    assert!(
        claim(
            &mut returned,
            fixture,
            owner,
            requests[0],
            &secret,
            ClaimAction::Read,
            129
        )? == Some(ClaimState::Reserved)
    );
    let _ = edge.stop()?;
    let _ = daemon.stop()?;
    Ok(())
}

#[test]
fn lost_chosen_reply_is_recovered_privately_after_restore_while_older_reserved_is_fenced()
-> TestResult {
    use super::stage_ten_drills::{RestorePlan, restore_node, write_backup};
    let mut network = build_network()?;
    let fixture = &mut network.coordinator;
    let original_config = fs::read(&fixture.config_path)?;
    let original_epoch = fixture.provisioned_epoch.clone();
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let secret = InitialRootSecret::generate()?;
    let ids = account_requests(141)?;
    let mut creator = ArcClient::connect(fixture)?;
    creator.negotiate_sasl()?;
    negotiate_root(&mut creator)?;
    let account = create_account_with_root_option(
        &mut creator,
        fixture,
        "restored-creator",
        ids,
        Some(&secret),
    )?;
    drop(creator);
    assert!(daemon.stop()?.success());
    let (reserved, _, _) = write_backup(fixture, "private-before-choose.backup", 1)?;

    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut client = registered_owner(fixture, "Chooser", "restored-creator", 147, account)?;
    let identity = Principal::new(88, 89, account)?;
    let fingerprint = builders::root_fingerprint(&identity.keys.root)?;
    let (request, token) = sealed_claim(
        fixture,
        account,
        ids[0],
        &secret,
        ClaimAction::Choose(fingerprint),
        150,
    )?;
    // The production actor only admits this fixed outer header after its durable result.
    // Drop the connection and one-use opener without reading the sealed response or its choice.
    client.begin_account_carrier("ACCTROOT", "CLAIM", "COMPLETE", request.as_bytes())?;
    drop((client, token));
    assert!(daemon.stop()?.success());
    let (chosen, _, _) = write_backup(fixture, "private-after-choose.backup", 2)?;

    // Both snapshots are of the same original account, preimage, START and physical creation.
    for (backup, expected, generation) in [
        (&chosen, Some(ClaimState::Chosen(fingerprint)), 2),
        (&reserved, None, 3),
    ] {
        fs::write(&fixture.config_path, &original_config)?;
        let restored = restore_node(
            fixture,
            &RestorePlan {
                backup,
                new_master: false,
                // The first restore removes the original state directory for both cases.
                disaster: generation == 2,
                generation,
            },
        )
        .map_err(|error| {
            failure(format!(
                "signed backup recovery generation {generation}: {error}"
            ))
        })?;
        assert!(restored.incarnation_changed && restored.epoch != original_epoch);
        fixture.provisioned_epoch = restored.epoch;
        let mut daemon = DaemonProcess::start(&fixture.config_path)?;
        let mut owner = registered_owner(fixture, "Returned", "restored-creator", 155, account)?;
        assert!(
            claim(
                &mut owner,
                fixture,
                account,
                ids[0],
                &secret,
                ClaimAction::Read,
                161
            )? == expected
        );
        assert!(
            claim(
                &mut owner,
                fixture,
                account,
                ids[0],
                &secret,
                ClaimAction::Choose(fingerprint),
                162
            )?
            .is_none()
        );
        drop(owner);
        assert!(daemon.stop()?.success());
    }
    Ok(())
}

#[test]
fn enhanced_edge_retires_its_idle_opted_client_on_link_loss_and_requires_fresh_consent()
-> TestResult {
    let network = build_network()?;
    for node in [&network.coordinator, &network.edge_a] {
        let text = fs::read_to_string(&node.config_path)?;
        let section = "[[federation.peer]]\n";
        if !text.contains(section) {
            return Err(failure("fixture has no configured federation peer"));
        }
        fs::write(
            &node.config_path,
            text.replace(
                section,
                "[[federation.peer]]\ninitial_root_profile = true\n",
            ),
        )?;
    }
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge = DaemonProcess::start(&network.edge_a.config_path)?;
    wait_for_link(&network.edge_a, 0)?;
    drop(register_when_available(&network.edge_a, "FirstProbe")?);
    let mut opted = ArcClient::connect(&network.edge_a)?;
    negotiate_root(&mut opted)?;
    let seen = links_established(&network.edge_a);
    // No client input and no active transfer: the old receipt still belongs only to this link.
    assert!(coordinator.stop()?.success());
    let lost = opted.read_until(|line| line.contains(" DEL :agenc.ag/initial-root"))?;
    assert_contains(&lost, " DEL :agenc.ag/initial-root")?;
    if opted.read_until(|_| true).is_ok() {
        return Err(failure("withdrawn connection remained open"));
    }
    let mut ordinary = ArcClient::connect(&network.edge_a)?;
    ordinary.send("CAP LS 302")?;
    let listed = ordinary.read_until(|line| line.contains(" LS ") && !line.contains(" LS * :"))?;
    assert!(
        !listed
            .iter()
            .any(|line| line.contains("agenc.ag/initial-root"))
    );
    ordinary.send("CAP REQ :agenc.ag/initial-root")?;
    let unavailable = ordinary.read_until(|line| {
        line.contains(" NAK ") || line.contains(" ACK ") || line.contains(" NEW ")
    })?;
    assert_contains(&unavailable, " NAK :agenc.ag/initial-root")?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(&network.edge_a, seen)?;
    drop(register_when_available(&network.edge_a, "FreshProbe")?);
    // A surviving ordinary connection gets no unsolicited capability on link replacement.
    ordinary.send("PING :new-link")?;
    let ordinary_reply = ordinary.read_until(|line| line.contains("new-link"))?;
    assert!(
        !ordinary_reply
            .iter()
            .any(|line| line.contains("agenc.ag/initial-root"))
    );
    let mut fresh = ArcClient::connect(&network.edge_a)?;
    negotiate_root(&mut fresh)?;
    drop((fresh, ordinary, opted));
    assert!(edge.stop()?.success());
    assert!(coordinator.stop()?.success());
    Ok(())
}

#[test]
fn two_registered_choices_and_bare_publication_share_one_genesis() -> TestResult {
    let network = build_network()?;
    let fixture = &network.coordinator;
    let mut coordinator = DaemonProcess::start(&fixture.config_path)?;
    let mut edge = DaemonProcess::start(&network.edge_a.config_path)?;
    wait_for_link(&network.edge_a, 0)?;
    let secret = InitialRootSecret::generate()?;
    let ids = account_requests(21)?;
    let mut creator = ArcClient::connect(fixture)?;
    creator.negotiate_sasl()?;
    negotiate_root(&mut creator)?;
    let account = create_account_with_root_option(
        &mut creator,
        fixture,
        "racing-creator",
        ids,
        Some(&secret),
    )?;
    drop(creator);
    let mut choices = [
        registered_owner(fixture, "ChoiceOne", "racing-creator", 31, account)?,
        registered_owner(fixture, "ChoiceTwo", "racing-creator", 41, account)?,
    ];
    let mut directory =
        authenticated_session(&network.edge_a, "Directory", "racing-creator", 51, account)?;
    let first = Principal::new(61, 62, account)?;
    let second = Principal::new(63, 64, account)?;
    let mut competing = Principal::new(65, 66, account)?;
    let a = builders::root_fingerprint(&first.keys.root)?;
    let b = builders::root_fingerprint(&second.keys.root)?;
    let barrier = std::sync::Barrier::new(3);
    let request = |client: &mut ArcClient, fingerprint, id| {
        barrier.wait();
        claim(
            client,
            fixture,
            account,
            ids[0],
            &secret,
            ClaimAction::Choose(fingerprint),
            id,
        )
    };
    let attempts = thread::scope(|scope| -> TestResult<_> {
        let [one, two] = &mut choices;
        let one = scope.spawn(|| request(one, a, 71));
        let two = scope.spawn(|| request(two, b, 72));
        barrier.wait();
        publish(&mut directory, &mut competing, false)?;
        let one = one
            .join()
            .map_err(|_| failure("first competing client stopped"))?;
        let two = two
            .join()
            .map_err(|_| failure("second competing client stopped"))?;
        Ok([one, two])
    })?;
    let mut fresh = registered_owner(fixture, "Reconcile", "racing-creator", 75, account)?;
    let Some(ClaimState::Chosen(winner)) = claim(
        &mut fresh,
        fixture,
        account,
        ids[0],
        &secret,
        ClaimAction::Read,
        80,
    )?
    else {
        return Err(failure("neither racing request fixed a root"));
    };
    if winner != a && winner != b {
        return Err(failure("unexpected selected root"));
    }
    let mut confirmed = false;
    for (requested, observed) in [a, b].into_iter().zip(attempts) {
        match observed {
            Ok(Some(ClaimState::Chosen(root))) if root == requested && root == winner => {
                confirmed = true;
            }
            Ok(None) if requested != winner => {}
            // The coordinator may fence a stale prepared request by closing its transport.
            Err(error)
                if requested != winner
                    && error
                        .to_string()
                        .starts_with("transport closed before the expected reply") => {}
            Err(error) => return Err(error),
            _ => {
                return Err(failure(
                    "a racing session disagreed with the permanent choice",
                ));
            }
        }
    }
    if !confirmed {
        return Err(failure("winning client received no protected choice"));
    }
    let (mut selected, mut loser) = if winner == a {
        (first, second)
    } else {
        (second, first)
    };
    publish(&mut directory, &mut loser, false)?;
    let object_id = publish(&mut directory, &mut selected, true)?;
    assert!(
        claim(
            &mut fresh,
            fixture,
            account,
            ids[0],
            &secret,
            ClaimAction::Read,
            81
        )? == Some(ClaimState::Published {
            fingerprint: winner,
            object_id
        })
    );
    drop((choices, fresh, directory));
    assert!(edge.stop()?.success());
    assert!(coordinator.stop()?.success());
    Ok(())
}
