//! Carrier lines of a pre-registration client on an edge: the envelope either
//! crosses the federation or is refused locally, and the coordinator's answer
//! reaches the client through the edge transport.
#![forbid(unsafe_code)]

use agenc_relay_client_wire::{
    ACCOUNT_REQUEST_BYTES, ACCOUNT_RESPONSE_BYTES, AccountCarrierAction, SaslAction,
    encode_account_payload, encode_sasl_payload,
};

use super::edge_answer_tests::{
    account_waiting, sasl_waiting_finish, sasl_waiting_start, text_chunks,
};
use super::test_harness::{Harness, Role, TestResult, saw};
use super::*;
use crate::federation::edge::{EdgeCompletion, RemoteCarrierOutcome};

const PREFIX: &str = "server.example";

fn sasl_lines() -> TestResult<Vec<String>> {
    let mut lines = vec!["AUTHENTICATE AGENC-OPAQUE".to_owned()];
    for chunk in text_chunks(&encode_sasl_payload(&[0; ACCOUNT_REQUEST_BYTES]))? {
        lines.push(format!("AUTHENTICATE {chunk}"));
    }
    Ok(lines)
}

fn create_lines() -> TestResult<Vec<String>> {
    let mut lines = vec!["ACCTCREATE START 4726".to_owned()];
    for chunk in text_chunks(&encode_account_payload(&[0; ACCOUNT_REQUEST_BYTES]))? {
        lines.push(format!("ACCTCREATE DATA {chunk}"));
    }
    lines.push("ACCTCREATE END".to_owned());
    Ok(lines)
}

/// Feeds one forwarded carrier line to the transport the test holds and
/// reports whether the transport assembled the request envelope.
fn feed(
    carrier: &mut EdgeCarrier,
    message: &mut agenc_relay_client_wire::ParsedMessage,
    now: u64,
) -> TestResult<bool> {
    let first = message.take_parameter(0).ok_or("carrier parameter")?;
    if message.command() == "AUTHENTICATE" {
        let actions = carrier.sasl.client(&first, now)?;
        return Ok(actions
            .iter()
            .any(|action| matches!(action, SaslAction::RequestEnvelope { .. })));
    }
    let second = message.take_parameter(1);
    let actions = carrier
        .creation
        .client(&first, second.as_deref(), false, now)?;
    Ok(actions
        .iter()
        .any(|action| matches!(action, AccountCarrierAction::RequestEnvelope { .. })))
}

/// Brings one connection to the point where its envelope is with the
/// coordinator: the registration state machine awaits the carrier and the
/// edge transport awaits the answer. Nothing is sent to the client.
fn hold(harness: &mut Harness, number: u64, lines: &[String]) -> TestResult<u64> {
    let generation = ConnectionGeneration::new(number);
    let now = harness.fixture.context_mut()?.now().get();
    let mut carrier = EdgeCarrier::new()?;
    let mut held = None;
    for line in lines {
        let action = harness.actions(number, line)?.into_iter().next();
        let Some(RegistrationAction::ForwardAuthCarrier {
            generation: carrier_generation,
            mut message,
            ..
        }) = action
        else {
            return Err(format!("{line} was not forwarded as a carrier").into());
        };
        if feed(&mut carrier, &mut message, now)? {
            held = Some(carrier_generation);
            continue;
        }
        let state = harness
            .router
            .connections
            .get_mut(&generation)
            .ok_or("connection")?;
        state.registration.event(
            RegistrationEvent::AuthCarrierFinished {
                generation: carrier_generation,
            },
            now,
        )?;
    }
    harness.router.edge_carriers.insert(generation, carrier);
    held.ok_or_else(|| "the envelope was never assembled".into())
}

fn hold_sasl(harness: &mut Harness, number: u64) -> TestResult<u64> {
    harness.actions(number, "CAP REQ :sasl")?;
    hold(harness, number, &sasl_lines()?)
}

fn answer(
    harness: &mut Harness,
    number: u64,
    carrier_generation: u64,
    outcome: RemoteCarrierOutcome,
) -> TestResult {
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completion(
        context,
        EdgeCompletion::AccountCarrier {
            generation: ConnectionGeneration::new(number),
            carrier_generation,
            sasl: true,
            finish: false,
            outcome,
        },
    );
    Ok(())
}

#[tokio::test]
async fn sasl_envelope_is_refused_with_a_failure_while_the_link_is_down() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    harness.line(1, "CAP REQ :sasl")?;
    for line in sasl_lines()? {
        let outcome = harness.line(1, &line)?;
        assert!(matches!(outcome, RouteOutcome::Continue));
    }
    assert!(saw(&sink, "AUTHENTICATE +"), "lines: {:?}", sink.lines());
    assert!(saw(&sink, " 904 "), "lines: {:?}", sink.lines());
    assert!(harness.router.pending_observations.is_empty());
    Ok(())
}

#[tokio::test]
async fn account_envelope_fails_unavailable_while_the_link_is_down() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    harness.line(1, "CAP REQ :agenc.ag/account-create")?;
    for line in create_lines()? {
        let outcome = harness.line(1, &line)?;
        assert!(matches!(outcome, RouteOutcome::Continue));
    }
    assert!(saw(&sink, "ACCTCREATE READY"), "lines: {:?}", sink.lines());
    assert!(
        saw(&sink, "FAIL ACCTCREATE UNAVAILABLE"),
        "lines: {:?}",
        sink.lines()
    );
    Ok(())
}

#[tokio::test]
async fn account_line_outside_a_transfer_fails_unavailable() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    harness.line(1, "CAP REQ :agenc.ag/account-create")?;
    let outcome = harness.line(1, "ACCTCREATE END")?;
    assert!(matches!(outcome, RouteOutcome::Continue));
    assert!(
        saw(&sink, "FAIL ACCTCREATE UNAVAILABLE"),
        "lines: {:?}",
        sink.lines()
    );
    Ok(())
}

#[tokio::test]
async fn unknown_sasl_mechanism_is_rejected_locally() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    harness.line(1, "CAP REQ :sasl")?;
    let outcome = harness.line(1, "AUTHENTICATE PLAIN")?;
    assert!(matches!(outcome, RouteOutcome::Continue));
    assert!(saw(&sink, " 908 "), "lines: {:?}", sink.lines());
    assert!(!saw(&sink, "AUTHENTICATE +"), "lines: {:?}", sink.lines());
    Ok(())
}

#[tokio::test]
async fn answer_for_a_connection_without_a_carrier_is_ignored() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    answer(
        &mut harness,
        1,
        3,
        RemoteCarrierOutcome::Challenge(vec![0; ACCOUNT_RESPONSE_BYTES]),
    )?;
    assert!(sink.lines().is_empty());
    assert!(!harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn held_start_challenge_reaches_the_client_and_the_exchange_continues() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    let held = hold_sasl(&mut harness, 1)?;
    answer(
        &mut harness,
        1,
        held,
        RemoteCarrierOutcome::Challenge(vec![0; ACCOUNT_RESPONSE_BYTES]),
    )?;
    assert_eq!(sink.lines().len(), 15, "lines: {:?}", sink.lines());
    assert!(!harness.sink_gone(1)?);
    // The state machine accepted the carrier result: the next chunk is routed.
    let next = harness.actions(1, "AUTHENTICATE AAAA")?;
    assert!(matches!(
        next.first(),
        Some(RegistrationAction::ForwardAuthCarrier { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn answer_after_the_transport_is_gone_leaves_the_carrier_unfinished() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    let held = hold_sasl(&mut harness, 1)?;
    harness.drop_transport(1)?;
    answer(
        &mut harness,
        1,
        held,
        RemoteCarrierOutcome::Challenge(vec![0; ACCOUNT_RESPONSE_BYTES]),
    )?;
    assert!(sink.lines().is_empty());
    assert!(harness.sink_gone(1)?);
    assert!(
        harness.state(1).is_ok(),
        "the protocol state waits for the transport's close event"
    );
    Ok(())
}

#[tokio::test]
async fn answer_the_transport_cannot_render_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    let held = hold_sasl(&mut harness, 1)?;
    answer(
        &mut harness,
        1,
        held,
        RemoteCarrierOutcome::Challenge(vec![0; 3]),
    )?;
    assert!(sink.lines().is_empty());
    assert!(harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn bare_and_sealed_authority_refusals_both_end_the_attempt_with_a_failure() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let bare = harness.open(1, true)?;
    let held = hold_sasl(&mut harness, 1)?;
    answer(
        &mut harness,
        1,
        held,
        RemoteCarrierOutcome::Failed { chunks: Vec::new() },
    )?;
    assert!(saw(&bare, " 904 "), "lines: {:?}", bare.lines());
    let sealed = harness.open(2, true)?;
    let held = hold_sasl(&mut harness, 2)?;
    let chunks = text_chunks(&encode_sasl_payload(&[0; ACCOUNT_RESPONSE_BYTES]))?;
    answer(
        &mut harness,
        2,
        held,
        RemoteCarrierOutcome::Failed { chunks },
    )?;
    assert!(saw(&sealed, " 904 "), "lines: {:?}", sealed.lines());
    assert!(!harness.sink_gone(1)?);
    assert!(!harness.sink_gone(2)?);
    Ok(())
}

#[tokio::test]
async fn held_account_creation_challenge_reaches_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    harness.actions(1, "CAP REQ :agenc.ag/account-create")?;
    let held = hold(&mut harness, 1, &create_lines()?)?;
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completion(
        context,
        EdgeCompletion::AccountCarrier {
            generation: ConnectionGeneration::new(1),
            carrier_generation: held,
            sasl: false,
            finish: false,
            outcome: RemoteCarrierOutcome::Challenge(vec![0; ACCOUNT_RESPONSE_BYTES]),
        },
    );
    assert!(
        saw(&sink, "ACCTCREATE CHALLENGE"),
        "lines: {:?}",
        sink.lines()
    );
    assert!(saw(&sink, "ACCTCREATE END"), "lines: {:?}", sink.lines());
    assert!(!harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn committed_credential_change_is_announced_and_the_client_is_closed() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    harness.router.edge_carriers.insert(
        generation,
        account_waiting(AccountCarrierKind::Credentials, true)?,
    );
    let chunks = text_chunks(&encode_account_payload(&[0; ACCOUNT_RESPONSE_BYTES]))?;
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completion(
        context,
        EdgeCompletion::CredentialCarrier {
            generation,
            carrier_generation: 0,
            finish: true,
            outcome: RemoteCarrierOutcome::CredentialChanged { chunks },
        },
    );
    assert!(
        saw(&sink, "NOTE ACCTCRED CHANGED"),
        "lines: {:?}",
        sink.lines()
    );
    assert!(harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn carrier_lines_without_a_transport_close_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let _sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    let context = harness.fixture.context_mut()?;
    let sasl =
        harness
            .router
            .edge_sasl_line(context, generation, 1, (PREFIX, "*"), ("AAAA", true), 0);
    assert!(matches!(sasl, CarrierRoute::Close));
    let account = harness.router.edge_account_line(
        context,
        generation,
        1,
        (PREFIX, AccountCarrierKind::Create),
        ("START", Some("4726"), false),
        0,
    );
    assert!(matches!(account, CarrierRoute::Close));
    Ok(())
}

#[tokio::test]
async fn sasl_line_while_the_coordinator_is_answering_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let _sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    harness
        .router
        .edge_carriers
        .insert(generation, sasl_waiting_start()?);
    let context = harness.fixture.context_mut()?;
    let route =
        harness
            .router
            .edge_sasl_line(context, generation, 1, (PREFIX, "*"), ("AAAA", true), 0);
    assert!(matches!(route, CarrierRoute::Close));
    Ok(())
}

#[tokio::test]
async fn credential_transfer_lines_use_the_credential_transport() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let _sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    harness
        .router
        .edge_carriers
        .insert(generation, EdgeCarrier::new()?);
    let context = harness.fixture.context_mut()?;
    let route = harness.router.edge_account_line(
        context,
        generation,
        1,
        (PREFIX, AccountCarrierKind::Credentials),
        ("START", Some("4726"), false),
        0,
    );
    let CarrierRoute::Finished { frames, result } = route else {
        return Err("the credential start must be answered locally".into());
    };
    assert_eq!(result, ResultClass::Ok);
    assert_eq!(frames.first().map(WireMessage::command), Some("ACCTCRED"));
    Ok(())
}

#[tokio::test]
async fn logout_of_an_edge_authenticated_client_is_refused_and_keeps_the_grant() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let _sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    let mut carrier = sasl_waiting_finish()?;
    carrier
        .sasl
        .server_response(&[0; ACCOUNT_RESPONSE_BYTES], 0)?;
    carrier.sasl.complete(true, 0)?;
    carrier.grant = Some((
        agenc_relay_types::AccountId::parse("a_AAAAAAAAAAAAAAAAAAAAAA")?,
        1,
        [9; 32],
    ));
    harness.router.edge_carriers.insert(generation, carrier);
    let context = harness.fixture.context_mut()?;
    let route =
        harness
            .router
            .edge_sasl_line(context, generation, 1, (PREFIX, "*"), ("*", true), 0);
    let CarrierRoute::Finished { frames, result } = route else {
        return Err("the logout must be answered locally".into());
    };
    assert_eq!(result, ResultClass::Rejected);
    assert_eq!(frames.first().map(WireMessage::command), Some("904"));
    let kept = harness.router.edge_carriers.get(&generation);
    assert!(kept.is_some_and(|carrier| carrier.grant.is_some()));
    Ok(())
}
