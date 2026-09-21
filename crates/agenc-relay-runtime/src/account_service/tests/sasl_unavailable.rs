//! RUN-09 (issue #152): an unavailable account authority is reported as its
//! own Section 9.5 failure line ahead of the numeric it shares with a refused
//! credential, and only to a client that negotiated `standard-replies`.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::TestResult;
use agenc_relay_client_wire::{ACCOUNT_RESPONSE_BYTES, AUTH_CHUNK_CHARACTERS, SaslTransport};

/// The canonical padded Base64 of one fixed-size request envelope. Its bytes
/// are not a parsable account-service envelope, so the coordinator refuses the
/// exchange from the same route an edge that cannot reach its account
/// authority refuses it.
fn request_text() -> String {
    let mut request = "A".repeat(SASL_REQUEST_CHARACTERS - 2);
    request.push_str("==");
    request
}

/// Feeds one complete request envelope through the pure carrier.
fn feed(sasl: &mut SaslTransport, now: u64) -> TestResult {
    let request = request_text();
    for chunk in request.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        let _actions = sasl.client(std::str::from_utf8(chunk)?, now)?;
    }
    Ok(())
}

/// A carrier whose finish envelope has been answered and whose outcome the
/// account service is about to decide.
fn awaiting_outcome() -> TestResult<SaslTransport> {
    let mut sasl = SaslTransport::new()?;
    let _selected = sasl.client("AGENC-OPAQUE", 0)?;
    feed(&mut sasl, 0)?;
    let _start = sasl.server_response(&[9_u8; ACCOUNT_RESPONSE_BYTES], 0)?;
    feed(&mut sasl, 0)?;
    let _finish = sasl.server_response(&[9_u8; ACCOUNT_RESPONSE_BYTES], 0)?;
    Ok(sasl)
}

fn lines(frames: Vec<agenc_relay_client_wire::WireMessage>) -> TestResult<Vec<String>> {
    let mut rendered = Vec::new();
    for frame in frames {
        rendered.push(String::from_utf8(encoded(frame)?)?);
    }
    Ok(rendered)
}

/// Drives one connection's SASL carrier to the refusal an unreachable account
/// authority produces and returns the exact lines that client reads.
fn unavailable_transcript(standard_replies: bool) -> TestResult<(Vec<String>, String)> {
    let mut fixture = CoordinatorFixture::new(vec![7; 48 * 16])?;
    let generation = ConnectionGeneration::new(1);
    let (coordinator, context) = fixture.parts()?;
    let prefix = context.server_prefix().to_owned();
    coordinator.connection_opened(context, generation)?;
    let selected = coordinator.route_sasl(
        context,
        generation,
        1,
        "tester",
        standard_replies,
        parsed("AUTHENTICATE AGENC-OPAQUE")?,
    );
    assert!(matches!(selected, CarrierRoute::Finished { .. }));

    let request = request_text();
    let mut refusal = None;
    for chunk in request.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        let line = format!("AUTHENTICATE {}", std::str::from_utf8(chunk)?);
        refusal = Some(coordinator.route_sasl(
            context,
            generation,
            1,
            "tester",
            standard_replies,
            parsed(&line)?,
        ));
    }
    let Some(CarrierRoute::Finished { frames, result }) = refusal else {
        return Err("the refused envelope did not finish the carrier".into());
    };
    assert_eq!(result, ResultClass::Rejected);
    Ok((lines(frames)?, prefix))
}

#[test]
fn an_unavailable_authority_names_itself_before_the_numeric() -> TestResult {
    let (transcript, prefix) = unavailable_transcript(true)?;
    assert_eq!(
        transcript,
        vec![
            format!(":{prefix} FAIL AUTHENTICATE UNAVAILABLE :Account authority unavailable\r\n"),
            format!(":{prefix} 904 tester :SASL authentication failed\r\n"),
        ]
    );
    Ok(())
}

#[test]
fn a_client_without_standard_replies_reads_exactly_the_numeric() -> TestResult {
    let (transcript, prefix) = unavailable_transcript(false)?;
    assert_eq!(
        transcript,
        vec![format!(
            ":{prefix} 904 tester :SASL authentication failed\r\n"
        )]
    );
    Ok(())
}

#[test]
fn a_refused_credential_never_names_the_authority() -> TestResult {
    let mut rejected = awaiting_outcome()?;
    let actions = rejected.complete(false, 0)?;
    assert_eq!(
        lines(render_sasl_actions("server.test", "tester", true, actions)?)?,
        vec![":server.test 904 tester :SASL authentication failed\r\n".to_owned()]
    );
    Ok(())
}

#[test]
fn an_accepted_authentication_never_names_the_authority() -> TestResult {
    let mut accepted = awaiting_outcome()?;
    let actions = accepted.complete(true, 0)?;
    assert_eq!(
        lines(render_sasl_actions("server.test", "tester", true, actions)?)?,
        vec![":server.test 903 tester :SASL authentication successful\r\n".to_owned()]
    );
    Ok(())
}

#[test]
fn the_failure_line_precedes_the_numeric_and_is_itself_a_refusal() -> TestResult {
    let mut unavailable = awaiting_outcome()?;
    let actions = unavailable.unavailable(0)?;
    assert!(matches!(
        actions.as_slice(),
        [
            SaslAction::AuthorityUnavailable,
            SaslAction::Numeric(SaslNumeric::Failed),
        ]
    ));
    assert_eq!(
        sasl_action_result(&SaslAction::AuthorityUnavailable),
        ResultClass::Rejected
    );
    Ok(())
}
