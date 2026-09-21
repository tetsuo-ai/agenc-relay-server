#![forbid(unsafe_code)]

//! Transcript grammar boundaries and deterministic harness outcomes.

use std::error::Error;

use agenc_relay_client_wire::{AccessTokenPolicy, CapabilityProfile};
use agenc_relay_testkit::{
    ClientTranscriptError, ClientTranscriptHarness, ClientTranscriptOperation,
    MAX_TRANSCRIPT_STEP_BYTES, TranscriptEncoding, parse_client_transcript,
};

#[test]
fn transcript_payloads_accept_exact_ascii_and_hex_limits() -> Result<(), Box<dyn Error>> {
    let ascii = "a".repeat(MAX_TRANSCRIPT_STEP_BYTES);
    let ascii_fixture = format!("EVID-S02-ASCII|server|ascii|{ascii}");
    let transcript = parse_client_transcript(&ascii_fixture)?;
    let [step] = transcript.steps() else {
        return Err(ClientTranscriptError::Shape.into());
    };
    assert_eq!(step.evidence_id(), "EVID-S02-ASCII");
    assert_eq!(step.operation(), ClientTranscriptOperation::ServerBytes);
    assert_eq!(step.encoding(), TranscriptEncoding::Ascii);
    assert_eq!(step.payload().len(), MAX_TRANSCRIPT_STEP_BYTES);

    let hex = "00".repeat(MAX_TRANSCRIPT_STEP_BYTES);
    let hex_fixture = format!("EVID-S02-HEX|client|hex|{hex}");
    let transcript = parse_client_transcript(&hex_fixture)?;
    let [step] = transcript.steps() else {
        return Err(ClientTranscriptError::Shape.into());
    };
    assert_eq!(step.payload().len(), MAX_TRANSCRIPT_STEP_BYTES);

    let oversized_hex = format!("EVID-S02-HEX|client|hex|{hex}00");
    assert_eq!(
        parse_client_transcript(&oversized_hex).err(),
        Some(ClientTranscriptError::Limit)
    );
    Ok(())
}

#[test]
fn transcript_rejects_extra_fields_and_noncanonical_identifiers_or_payloads() {
    let invalid = [
        "EVID-S02-X|client|ascii|value|extra",
        "EVID_S02_X|client|ascii|value",
        "EVID-S02-é|client|ascii|value",
        "EVID-S02-X|client|ascii|bad\u{7f}",
        "EVID-S02-X|client|hex|0g",
        "EVID-S02-X|client|hex|A0",
    ];
    for fixture in invalid {
        assert!(parse_client_transcript(fixture).is_err(), "{fixture:?}");
    }
}

#[test]
fn harness_accepts_exact_server_bytes_and_ignores_syntax_noops() -> Result<(), Box<dyn Error>> {
    let transcript = parse_client_transcript(
        "EVID-S02-NOOP|client|hex|2020200d0a\n\
         EVID-S02-PING|client|hex|50494e47203a780d0a\n\
         EVID-S02-PING|server|hex|3a7365727665722e6578616d706c6520504f4e47203a780d0a",
    )?;
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&transcript)?;
    harness.finish()?;

    let [message] = harness.messages() else {
        return Err(ClientTranscriptError::Parsing.into());
    };
    assert_eq!(message.command(), "PING");
    assert_eq!(message.parameter_count(), 1);
    assert!(message.trailing_present());
    assert_eq!(harness.pending_server_frame_count(), 0);
    assert_eq!(harness.pending_server_frame_bytes(0), None);
    Ok(())
}

#[test]
fn harness_clock_overflow_is_reported_without_wrapping_time() -> Result<(), Box<dyn Error>> {
    let maximum = parse_client_transcript(&format!("EVID-S02-TIME|advance|ascii|{}", u64::MAX))?;
    let one = parse_client_transcript("EVID-S02-TIME|advance|ascii|1")?;
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&maximum)?;
    assert_eq!(harness.now(), u64::MAX);
    assert_eq!(harness.drive(&one), Err(ClientTranscriptError::Overflow));
    assert_eq!(harness.now(), u64::MAX);
    Ok(())
}

#[test]
fn harness_configuration_rejects_policy_and_token_mismatches() -> Result<(), Box<dyn Error>> {
    let token = [0_u8; 32];
    assert!(matches!(
        ClientTranscriptHarness::with_registration_scenario(
            CapabilityProfile::new(Vec::new())?,
            AccessTokenPolicy::IgnoreCompatibilityPass,
            Some(&token),
            false,
        ),
        Err(ClientTranscriptError::Value)
    ));
    assert!(matches!(
        ClientTranscriptHarness::with_registration_scenario(
            CapabilityProfile::new(Vec::new())?,
            AccessTokenPolicy::RequireConfiguredToken,
            None,
            false,
        ),
        Err(ClientTranscriptError::Value)
    ));
    Ok(())
}
