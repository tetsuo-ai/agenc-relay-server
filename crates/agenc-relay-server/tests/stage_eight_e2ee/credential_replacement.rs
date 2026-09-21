//! Credential replacement through a registered edge session and real OPAQUE.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_auth::{CredentialChangeFinish, CredentialChangeStart};

const REPLACEMENT: &[u8] = b"a different credential for the edge regression";

fn replace(client: &mut ArcClient, fixture: &NodeFixture, account_id: AccountId) -> TestResult {
    let mut rng = TestOpaqueRng::new();
    let registration = ClientRegistration::<TestOpaqueSuite>::start(&mut rng, REPLACEMENT)?;
    let registration_request = OpaqueRegistrationRequest::from_bytes(
        registration.message.serialize().as_slice().try_into()?,
    )?;
    let (start, token) = seal_account_payload(
        fixture,
        NETWORK_ID,
        RequestId::from_bytes([81; 16]),
        AccountRequestPayload::CredentialChangeStart(CredentialChangeStart {
            network_id: NETWORK_ID,
            account_id,
            registration_request,
        }),
    )?;
    let challenge = client.account_exchange(
        AccountCarrier::Credentials,
        AccountPhase::Start,
        &start,
        token,
    )?;
    let AccountServiceResponsePayload::CredentialChangeChallenge {
        transaction_id,
        credential_id,
        response,
    } = challenge
    else {
        return Err(failure("credential change returned the wrong challenge"));
    };
    let finish = registration.state.finish(
        &mut rng,
        REPLACEMENT,
        RegistrationResponse::<TestOpaqueSuite>::deserialize(
            response.expose_for_account_response(),
        )?,
        ClientRegistrationFinishParameters::new(
            opaque_identifiers(&NETWORK_ID, &credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let registration_record =
        finish_registration(finish.message.serialize().as_slice().try_into()?)?;
    rng.require_success()?;
    let (finish, token) = seal_account_payload(
        fixture,
        NETWORK_ID,
        RequestId::from_bytes([82; 16]),
        AccountRequestPayload::CredentialChangeFinish(CredentialChangeFinish {
            network_id: NETWORK_ID,
            transaction_id,
            registration_record,
        }),
    )?;
    let completion = client.account_exchange(
        AccountCarrier::Credentials,
        AccountPhase::Finish,
        &finish,
        token,
    )?;
    let AccountServiceResponsePayload::CredentialChangeCompletion(completion) = completion else {
        return Err(failure("credential change returned the wrong completion"));
    };
    committed_account(completion, Some(account_id))?;
    let note = read_line_for(&mut client.reader, "credential replacement receipt")?;
    assert!(
        note.contains(" NOTE ACCTCRED CHANGED :Account credential changed; reconnect required"),
        "{note}"
    );
    let mut tail = String::new();
    assert_eq!(
        client.reader.read_line(&mut tail)?,
        0,
        "credential replacement must close after its receipt: {tail}"
    );
    Ok(())
}

fn exercise(network: &Network, coordinator: &mut DaemonProcess) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    // Established transports still synchronize before account carriers are available.
    super::stage_ten_drills::wait_for_account_authority(&network.edge_a)?;
    super::stage_ten_drills::wait_for_account_authority(&network.edge_b)?;
    let account = {
        let mut client = ArcClient::connect(&network.edge_a)?;
        client.negotiate_sasl()?;
        step(
            "create account",
            create_live_account(&mut client, &network.edge_a, "edge-credential", 71),
        )?
    };
    let mut client = ArcClient::connect(&network.edge_a)?;
    client.negotiate_sasl()?;
    step(
        "authenticate existing credential",
        authenticate_live_account(
            &mut client,
            &network.edge_a,
            "edge-credential",
            ACCOUNT_PASSWORD,
            73,
            account,
        ),
    )?;
    client.complete_registration("CredentialOwner")?;
    step(
        "reauthenticate registered session",
        authenticate_live_account(
            &mut client,
            &network.edge_a,
            "edge-credential",
            ACCOUNT_PASSWORD,
            79,
            account,
        ),
    )?;
    let mut old_session = ArcClient::connect(&network.edge_b)?;
    old_session.negotiate_sasl()?;
    step(
        "authenticate second old session",
        authenticate_live_account(
            &mut old_session,
            &network.edge_b,
            "edge-credential",
            ACCOUNT_PASSWORD,
            77,
            account,
        ),
    )?;
    old_session.complete_registration("OldCredentialOwner")?;
    step(
        "replace credential",
        replace(&mut client, &network.edge_a, account),
    )?;
    let mut revoked = String::new();
    assert_eq!(
        old_session.reader.read_line(&mut revoked)?,
        0,
        "credential replacement must close other edge sessions: {revoked}"
    );
    drop(old_session);
    drop(client);
    let links_b = links_established(&network.edge_b);
    assert!(coordinator.stop()?.success());
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(&network.edge_b, links_b)?;
    super::stage_ten_drills::wait_for_account_authority(&network.edge_b)?;
    let mut replacement = ArcClient::connect(&network.edge_b)?;
    replacement.negotiate_sasl()?;
    step(
        "authenticate replacement after restart",
        authenticate_live_account(
            &mut replacement,
            &network.edge_b,
            "edge-credential",
            REPLACEMENT,
            75,
            account,
        ),
    )?;
    replacement.complete_registration("ReplacementOwner")?;
    Ok(())
}

#[test]
fn edge_credential_replacement_survives_coordinator_restart() -> TestResult {
    let network = build_network()?;
    // Initial and post-restart readiness checks use the edges' signed admin sockets.
    for fixture in [&network.edge_a, &network.edge_b] {
        let mut config = fs::read_to_string(&fixture.config_path)?;
        replace_once(
            &mut config,
            "enabled = false\npurpose = \"admin_local\"",
            "enabled = true\npurpose = \"admin_local\"",
        )?;
        fs::write(&fixture.config_path, config)?;
    }
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let result = exercise(&network, &mut coordinator);
    let stopped_a = edge_a.stop();
    let stopped_b = edge_b.stop();
    let stopped_coordinator = coordinator.stop();
    if let Err(error) = result {
        return Err(failure(format!(
            "{error}\nCoordinator: {}\nEdge A: {}\nEdge B: {}",
            network.coordinator.log_text(),
            network.edge_a.log_text(),
            network.edge_b.log_text()
        )));
    }
    for status in [stopped_a, stopped_b, stopped_coordinator] {
        assert!(status?.success());
    }
    Ok(())
}
