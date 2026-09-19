//! The edge transports render what the coordinator answered to a forwarded
//! carrier envelope, or refuse an answer that does not fit the exchange.
#![forbid(unsafe_code)]

use agenc_ircd_client_wire::{
    ACCOUNT_REQUEST_BYTES, ACCOUNT_RESPONSE_BYTES, AUTH_CHUNK_CHARACTERS, AccountCarrierAction,
    SaslAction, encode_account_payload, encode_sasl_payload,
};

use super::test_harness::TestResult;
use super::*;
use crate::federation::edge::RemoteCarrierOutcome;

const PREFIX: &str = "edge.example";

pub(super) fn text_chunks(text: &str) -> TestResult<Vec<String>> {
    text.as_bytes()
        .chunks(AUTH_CHUNK_CHARACTERS)
        .map(|chunk| Ok(std::str::from_utf8(chunk)?.to_owned()))
        .collect()
}

/// Feeds one whole request envelope through the SASL transport.
fn sasl_request(carrier: &mut EdgeCarrier) -> TestResult<bool> {
    let mut finish = None;
    for chunk in text_chunks(&encode_sasl_payload(&[0; ACCOUNT_REQUEST_BYTES]))? {
        for action in carrier.sasl.client(&chunk, 0)? {
            if let SaslAction::RequestEnvelope { finish: phase, .. } = action {
                finish = Some(phase);
            }
        }
    }
    finish.ok_or_else(|| "the transport never assembled the envelope".into())
}

pub(super) fn sasl_waiting_start() -> TestResult<EdgeCarrier> {
    let mut carrier = EdgeCarrier::new()?;
    carrier.sasl.client("AGENC-OPAQUE", 0)?;
    assert!(!sasl_request(&mut carrier)?);
    Ok(carrier)
}

pub(super) fn sasl_waiting_finish() -> TestResult<EdgeCarrier> {
    let mut carrier = sasl_waiting_start()?;
    carrier
        .sasl
        .server_response(&[0; ACCOUNT_RESPONSE_BYTES], 0)?;
    assert!(sasl_request(&mut carrier)?);
    Ok(carrier)
}

fn sasl_chunks() -> TestResult<Vec<String>> {
    text_chunks(&encode_sasl_payload(&[0; ACCOUNT_RESPONSE_BYTES]))
}

fn account_id() -> TestResult<agenc_ircd_types::AccountId> {
    Ok(agenc_ircd_types::AccountId::parse(
        "a_AAAAAAAAAAAAAAAAAAAAAA",
    )?)
}

fn rendered(frames: &[WireMessage]) -> Vec<String> {
    frames
        .iter()
        .map(|frame| {
            let trailing = frame.trailing().unwrap_or("");
            format!(
                " {} {} :{trailing}",
                frame.command(),
                frame.middle().join(" ")
            )
        })
        .collect()
}

fn any_line(frames: &[WireMessage], needle: &str) -> bool {
    rendered(frames).iter().any(|line| line.contains(needle))
}

#[test]
fn sasl_start_challenge_is_relayed_as_chunks() -> TestResult {
    let mut carrier = sasl_waiting_start()?;
    let (frames, result) = edge_sasl_answer(
        &mut carrier,
        (PREFIX, "*"),
        (false, true),
        RemoteCarrierOutcome::Challenge(vec![0; ACCOUNT_RESPONSE_BYTES]),
        0,
    )
    .ok_or("a start challenge must render")?;
    assert_eq!(result, ResultClass::Ok);
    assert_eq!(frames.len(), 15);
    assert!(carrier.grant.is_none());
    Ok(())
}

#[test]
fn sasl_challenge_answering_a_finish_is_reported_as_unavailable() -> TestResult {
    let mut carrier = sasl_waiting_finish()?;
    let (frames, result) = edge_sasl_answer(
        &mut carrier,
        (PREFIX, "*"),
        (true, true),
        RemoteCarrierOutcome::Challenge(vec![0; ACCOUNT_RESPONSE_BYTES]),
        0,
    )
    .ok_or("an unfit answer still renders the refusal")?;
    assert_eq!(result, ResultClass::Ok);
    assert!(any_line(&frames, " 904 "), "{:?}", rendered(&frames));
    Ok(())
}

#[test]
fn sasl_authenticated_finish_keeps_the_grant_and_ends_with_success() -> TestResult {
    let mut carrier = sasl_waiting_finish()?;
    let (frames, result) = edge_sasl_answer(
        &mut carrier,
        (PREFIX, "nick"),
        (true, false),
        RemoteCarrierOutcome::Authenticated {
            account_id: account_id()?,
            account_session_generation: 4,
            auth_grant_id: [9; 32],
            chunks: sasl_chunks()?,
        },
        0,
    )
    .ok_or("an authenticated finish must render")?;
    assert_eq!(result, ResultClass::Ok);
    assert!(any_line(&frames, " 903 "), "{:?}", rendered(&frames));
    assert_eq!(carrier.grant, Some((account_id()?, 4, [9; 32])));
    Ok(())
}

#[test]
fn sasl_authenticated_answer_to_a_start_grants_nothing() -> TestResult {
    let mut carrier = sasl_waiting_start()?;
    let (frames, _) = edge_sasl_answer(
        &mut carrier,
        (PREFIX, "*"),
        (false, true),
        RemoteCarrierOutcome::Authenticated {
            account_id: account_id()?,
            account_session_generation: 4,
            auth_grant_id: [9; 32],
            chunks: sasl_chunks()?,
        },
        0,
    )
    .ok_or("an unfit answer still renders the refusal")?;
    assert!(any_line(&frames, " 904 "), "{:?}", rendered(&frames));
    assert!(carrier.grant.is_none());
    Ok(())
}

#[test]
fn sasl_sealed_rejection_is_relayed_and_ends_with_failure() -> TestResult {
    let mut carrier = sasl_waiting_finish()?;
    let (frames, result) = edge_sasl_answer(
        &mut carrier,
        (PREFIX, "*"),
        (true, true),
        RemoteCarrierOutcome::Failed {
            chunks: sasl_chunks()?,
        },
        0,
    )
    .ok_or("a sealed rejection must render")?;
    assert_eq!(result, ResultClass::Rejected);
    assert_eq!(frames.len(), 16);
    assert!(any_line(&frames, " 904 "), "{:?}", rendered(&frames));
    Ok(())
}

#[test]
fn sasl_bare_rejection_renders_only_the_refusal() -> TestResult {
    let mut carrier = sasl_waiting_finish()?;
    let (frames, result) = edge_sasl_answer(
        &mut carrier,
        (PREFIX, "*"),
        (true, true),
        RemoteCarrierOutcome::Failed { chunks: Vec::new() },
        0,
    )
    .ok_or("a bare rejection must render")?;
    assert_eq!(result, ResultClass::Ok);
    assert!(frames.len() < 15, "{:?}", rendered(&frames));
    assert!(any_line(&frames, " 904 "), "{:?}", rendered(&frames));
    Ok(())
}

#[test]
fn sasl_sealed_rejection_of_a_start_is_not_relayed() -> TestResult {
    let mut carrier = sasl_waiting_start()?;
    let (frames, _) = edge_sasl_answer(
        &mut carrier,
        (PREFIX, "*"),
        (false, true),
        RemoteCarrierOutcome::Failed {
            chunks: sasl_chunks()?,
        },
        0,
    )
    .ok_or("a refused start must render")?;
    assert!(frames.len() < 15, "{:?}", rendered(&frames));
    Ok(())
}

#[test]
fn sasl_undecodable_completion_closes_the_transport() -> TestResult {
    let mut carrier = sasl_waiting_finish()?;
    let answered = edge_sasl_answer(
        &mut carrier,
        (PREFIX, "*"),
        (true, true),
        RemoteCarrierOutcome::Authenticated {
            account_id: account_id()?,
            account_session_generation: 4,
            auth_grant_id: [9; 32],
            chunks: vec!["not base64!".to_owned()],
        },
        0,
    );
    assert!(answered.is_none());
    assert!(carrier.grant.is_none());
    let mut carrier = sasl_waiting_finish()?;
    let answered = edge_sasl_answer(
        &mut carrier,
        (PREFIX, "*"),
        (true, true),
        RemoteCarrierOutcome::Failed {
            chunks: vec!["not base64!".to_owned()],
        },
        0,
    );
    assert!(answered.is_none());
    Ok(())
}

#[test]
fn sasl_answers_of_the_wrong_length_or_without_an_exchange_close_the_transport() -> TestResult {
    let mut carrier = sasl_waiting_start()?;
    assert!(
        edge_sasl_answer(
            &mut carrier,
            (PREFIX, "*"),
            (false, true),
            RemoteCarrierOutcome::Challenge(vec![0; 7]),
            0,
        )
        .is_none()
    );
    let mut idle = EdgeCarrier::new()?;
    assert!(
        edge_sasl_answer(
            &mut idle,
            (PREFIX, "*"),
            (true, true),
            RemoteCarrierOutcome::Failed { chunks: Vec::new() },
            0,
        )
        .is_none()
    );
    Ok(())
}

/// Feeds one whole request envelope through an account transfer.
fn account_request(
    transfer: &mut agenc_ircd_client_wire::AccountTransfer,
    phase: &str,
) -> TestResult {
    transfer.client(phase, Some("4726"), false, 0)?;
    for chunk in text_chunks(&encode_account_payload(&[0; ACCOUNT_REQUEST_BYTES]))? {
        transfer.client("DATA", Some(&chunk), false, 0)?;
    }
    let actions = transfer.client("END", None, false, 0)?;
    assert!(matches!(
        actions.first(),
        Some(AccountCarrierAction::RequestEnvelope { .. })
    ));
    Ok(())
}

pub(super) fn account_waiting(kind: AccountCarrierKind, finish: bool) -> TestResult<EdgeCarrier> {
    let mut carrier = EdgeCarrier::new()?;
    let transfer = match kind {
        AccountCarrierKind::Create => &mut carrier.creation,
        AccountCarrierKind::Credentials => &mut carrier.credentials,
    };
    account_request(transfer, "START")?;
    if finish {
        transfer.server_response(
            agenc_ircd_client_wire::AccountCarrierPhase::Start,
            &[0; ACCOUNT_RESPONSE_BYTES],
            0,
        )?;
        account_request(transfer, "FINISH")?;
    }
    Ok(carrier)
}

fn account_chunks() -> TestResult<Vec<String>> {
    text_chunks(&encode_account_payload(&[0; ACCOUNT_RESPONSE_BYTES]))
}

#[test]
fn account_start_challenge_is_relayed_between_challenge_and_end() -> TestResult {
    let mut carrier = account_waiting(AccountCarrierKind::Create, false)?;
    let (frames, result) = edge_account_answer(
        &mut carrier,
        PREFIX,
        (AccountCarrierKind::Create, false),
        RemoteCarrierOutcome::Challenge(vec![0; ACCOUNT_RESPONSE_BYTES]),
        0,
    )
    .ok_or("a start challenge must render")?;
    assert_eq!(result, ResultClass::Ok);
    assert!(any_line(&frames, "CHALLENGE"), "{:?}", rendered(&frames));
    assert!(any_line(&frames, " END"), "{:?}", rendered(&frames));
    Ok(())
}

#[test]
fn account_created_finish_adds_the_created_note() -> TestResult {
    let mut carrier = account_waiting(AccountCarrierKind::Create, true)?;
    let (frames, result) = edge_account_answer(
        &mut carrier,
        PREFIX,
        (AccountCarrierKind::Create, true),
        RemoteCarrierOutcome::Created {
            account_id: account_id()?,
            chunks: account_chunks()?,
        },
        0,
    )
    .ok_or("a created account must render")?;
    assert_eq!(result, ResultClass::Ok);
    assert!(
        any_line(&frames, "NOTE ACCTCREATE CREATED a_AAAAAAAAAAAAAAAAAAAAAA"),
        "{:?}",
        rendered(&frames)
    );
    Ok(())
}

#[test]
fn credential_change_finish_adds_the_reconnect_note() -> TestResult {
    let mut carrier = account_waiting(AccountCarrierKind::Credentials, true)?;
    let (frames, result) = edge_account_answer(
        &mut carrier,
        PREFIX,
        (AccountCarrierKind::Credentials, true),
        RemoteCarrierOutcome::CredentialChanged {
            chunks: account_chunks()?,
        },
        0,
    )
    .ok_or("a credential change must render")?;
    assert_eq!(result, ResultClass::Ok);
    assert!(
        any_line(&frames, "NOTE ACCTCRED CHANGED"),
        "{:?}",
        rendered(&frames)
    );
    Ok(())
}

#[test]
fn account_sealed_rejection_is_relayed_before_the_failure() -> TestResult {
    let mut carrier = account_waiting(AccountCarrierKind::Create, true)?;
    let (frames, result) = edge_account_answer(
        &mut carrier,
        PREFIX,
        (AccountCarrierKind::Create, true),
        RemoteCarrierOutcome::Failed {
            chunks: account_chunks()?,
        },
        0,
    )
    .ok_or("a sealed rejection must render")?;
    assert_eq!(result, ResultClass::Rejected);
    assert!(any_line(&frames, "COMPLETE"), "{:?}", rendered(&frames));
    let last = rendered(&frames).pop().ok_or("no frames")?;
    assert!(last.contains("FAIL ACCTCREATE UNAVAILABLE"), "{last}");
    Ok(())
}

fn refused_without_relay(
    kind: AccountCarrierKind,
    finish: bool,
    outcome: RemoteCarrierOutcome,
) -> TestResult {
    let mut carrier = account_waiting(kind, finish)?;
    let (frames, result) = edge_account_answer(&mut carrier, PREFIX, (kind, finish), outcome, 0)
        .ok_or("a refusal must render")?;
    assert_eq!(result, ResultClass::Rejected);
    assert_eq!(frames.len(), 1, "{:?}", rendered(&frames));
    assert!(any_line(&frames, "UNAVAILABLE"), "{:?}", rendered(&frames));
    Ok(())
}

#[test]
fn account_answers_that_do_not_fit_the_phase_or_kind_fail_without_relay() -> TestResult {
    let create = AccountCarrierKind::Create;
    let credentials = AccountCarrierKind::Credentials;
    let challenge = || RemoteCarrierOutcome::Challenge(vec![0; ACCOUNT_RESPONSE_BYTES]);
    refused_without_relay(create, true, challenge())?;
    let created = RemoteCarrierOutcome::Created {
        account_id: account_id()?,
        chunks: account_chunks()?,
    };
    refused_without_relay(create, false, created)?;
    let created = RemoteCarrierOutcome::Created {
        account_id: account_id()?,
        chunks: account_chunks()?,
    };
    refused_without_relay(credentials, true, created)?;
    let changed = |chunks| RemoteCarrierOutcome::CredentialChanged { chunks };
    refused_without_relay(credentials, false, changed(account_chunks()?))?;
    refused_without_relay(create, true, changed(account_chunks()?))?;
    Ok(())
}

#[test]
fn account_rejections_without_a_sealed_body_or_before_finish_fail_without_relay() -> TestResult {
    let create = AccountCarrierKind::Create;
    let failed = |chunks| RemoteCarrierOutcome::Failed { chunks };
    refused_without_relay(create, true, failed(Vec::new()))?;
    refused_without_relay(create, false, failed(account_chunks()?))?;
    refused_without_relay(create, true, failed(vec!["not base64url!".to_owned()]))?;
    Ok(())
}

#[test]
fn account_answer_of_the_wrong_length_closes_the_transport() -> TestResult {
    let mut carrier = account_waiting(AccountCarrierKind::Create, false)?;
    let answered = edge_account_answer(
        &mut carrier,
        PREFIX,
        (AccountCarrierKind::Create, false),
        RemoteCarrierOutcome::Challenge(vec![0; 9]),
        0,
    );
    assert!(answered.is_none());
    Ok(())
}
