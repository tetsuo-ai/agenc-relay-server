#![forbid(unsafe_code)]

//! Stage-02 deterministic client transcript fixture tests.

use std::error::Error;

use agenc_relay_client_wire::RegistrationPhase;
use agenc_relay_testkit::{ClientTranscriptHarness, parse_client_transcript};

const TRANSCRIPT: &str =
    include_str!("../../../test-data/transcripts/client-registration-v1.transcript");

#[test]
fn checked_in_client_transcript_frames_and_parses_byte_exactly() -> Result<(), Box<dyn Error>> {
    let transcript = parse_client_transcript(TRANSCRIPT)?;
    assert_eq!(transcript.steps().len(), 18);
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&transcript)?;
    harness.finish()?;
    let commands: Vec<&str> = harness
        .messages()
        .iter()
        .map(agenc_relay_testkit::ClientTranscriptMessage::command)
        .collect();
    assert_eq!(commands, ["CAP", "CAP", "NICK", "USER", "CAP"]);
    assert_eq!(harness.empty_lines(), 1);
    assert_eq!(harness.now(), 120_000);
    assert_eq!(harness.registration_phase(), RegistrationPhase::Registered);
    let user = harness
        .messages()
        .get(3)
        .ok_or("USER observation is missing")?;
    assert_eq!(user.parameter_count(), 4);
    assert!(user.trailing_present());
    Ok(())
}

#[test]
fn transcript_loader_rejects_unbound_ids_and_malformed_hex() {
    assert!(parse_client_transcript("OTHER|client|hex|0d0a").is_err());
    assert!(parse_client_transcript("EVID-S02-X|client|hex|ABC").is_err());
    assert!(parse_client_transcript("EVID-S02-X|advance|hex|1").is_err());
}
