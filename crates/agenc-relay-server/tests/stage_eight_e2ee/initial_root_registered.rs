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
    assert_contains(
        &offered,
        &format!(
            "agenc.ag/initial-root=v1.{}",
            agenc_relay_types::INITIAL_ROOT_PROFILE_TOKEN
        ),
    )?;
    client.send("CAP REQ :agenc.ag/initial-root")?;
    let ack = client.read_until(|line| line.contains(" ACK ") || line.contains(" NAK "))?;
    assert_contains(&ack, " ACK :agenc.ag/initial-root")
}

fn registered_owner(
    fixture: &NodeFixture,
    nick: &str,
    seed: u8,
    account: AccountId,
) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(fixture)?;
    client.negotiate_sasl()?;
    negotiate_root(&mut client)?;
    authenticate_live_account(
        &mut client,
        fixture,
        "protected-creator",
        ACCOUNT_PASSWORD,
        seed,
        account,
    )?;
    client.complete_registration(nick)?;
    Ok(client)
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
    let public = AccountHpkePrivateKey::from_bytes(ACCOUNT_HPKE_PRIVATE)?.public_key()?;
    let binding = AccountRequestBinding::new(
        NETWORK_ID,
        account_recovery_epoch(fixture, NETWORK_ID)?,
        public.key_id(),
        RequestId::from_bytes([request_id; 16]),
        InitialRootExchange::Claim,
    );
    let (request, token) = seal_claim(public, binding, account, start, secret, action)?;
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
    let mut publisher = registered_owner(fixture, "Creator", 39, account)?;
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
    let mut restored = registered_owner(fixture, "Returned", 47, account)?;
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
