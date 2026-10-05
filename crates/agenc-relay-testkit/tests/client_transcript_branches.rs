#![forbid(unsafe_code)]

//! Negative transcript grammar and harness coverage for the Stage-02 gate.

use std::error::Error;

use agenc_relay_client_wire::{
    AccessTokenPolicy, CapabilityProfile, CapabilitySpec, RegistrationAuthCarrier,
    RegistrationPhase, WelcomeStep,
};
use agenc_relay_testkit::{
    ClientTranscriptError, ClientTranscriptHandoff, ClientTranscriptHarness,
    MAX_TRANSCRIPT_STEP_BYTES, MAX_TRANSCRIPT_STEPS, decode_server_frame, parse_client_transcript,
};
use agenc_relay_types::CAPABILITIES;

const REGISTRATION_TRANSCRIPT: &str =
    include_str!("../../../test-data/transcripts/client-registration-v1.transcript");

#[test]
fn transcript_accepts_comments_empty_lines_and_non_client_steps() -> Result<(), Box<dyn Error>> {
    let transcript =
        parse_client_transcript("# fixture comment\n\nEVID-S02-TIME|advance|ascii|10")?;
    assert_eq!(transcript.steps().len(), 1);
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&transcript)?;
    harness.finish()?;
    assert!(harness.messages().is_empty());
    assert_eq!(harness.now(), 10);

    let unexpected = parse_client_transcript("EVID-S02-SERVER|server|ascii|NOTICE")?;
    let mut harness = ClientTranscriptHarness::new()?;
    assert_eq!(
        harness.drive(&unexpected),
        Err(ClientTranscriptError::UnexpectedServerBytes)
    );
    Ok(())
}

#[test]
fn transcript_rejects_shape_field_and_payload_limit_variants() {
    for input in [
        "EVID-S02-X|client|hex",
        "EVID-S02-X|unknown|ascii|value",
        "EVID-S02-X|client|unknown|value",
        "EVID-S02-X|advance|hex|1",
        "EVID-S02-X|advance|ascii|",
        "EVID-S02-X|advance|ascii|x",
        "EVID-S02-X|advance|ascii|18446744073709551616",
        "EVID-S02-X|client|ascii|bad\tvalue",
        "EVID-S02-X|client|hex|0",
        "EVID-S02-X|client|hex|AA",
        "evid-S02-X|client|ascii|value",
    ] {
        assert!(parse_client_transcript(input).is_err(), "{input:?}");
    }

    let long_id = format!("EVID-S02-{}|client|ascii|value", "A".repeat(65));
    assert_eq!(
        parse_client_transcript(&long_id).err(),
        Some(ClientTranscriptError::Value)
    );
    let long_payload = format!(
        "EVID-S02-X|client|ascii|{}",
        "x".repeat(MAX_TRANSCRIPT_STEP_BYTES + 1)
    );
    assert_eq!(
        parse_client_transcript(&long_payload).err(),
        Some(ClientTranscriptError::Limit)
    );
}

#[test]
fn transcript_rejects_more_than_the_checked_step_count() {
    let line = "EVID-S02-X|server|ascii|x\n";
    let input = line.repeat(MAX_TRANSCRIPT_STEPS + 1);
    assert_eq!(
        parse_client_transcript(&input).err(),
        Some(ClientTranscriptError::Limit)
    );
}

#[test]
fn harness_maps_framing_parsing_and_partial_eof_failures() -> Result<(), Box<dyn Error>> {
    for (fixture, expected) in [
        ("EVID-S02-X|client|hex|0a", ClientTranscriptError::Framing),
        (
            "EVID-S02-X|client|hex|3132330d0a",
            ClientTranscriptError::Parsing,
        ),
    ] {
        let transcript = parse_client_transcript(fixture)?;
        let mut harness = ClientTranscriptHarness::new()?;
        assert_eq!(harness.drive(&transcript), Err(expected));
    }

    let transcript = parse_client_transcript("EVID-S02-X|client|ascii|PING")?;
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&transcript)?;
    assert_eq!(harness.finish(), Err(ClientTranscriptError::Framing));
    Ok(())
}

#[test]
fn harness_rejects_mismatched_or_omitted_rendered_server_frames() -> Result<(), Box<dyn Error>> {
    let mismatched = parse_client_transcript(
        "EVID-S02-X|client|hex|50494e47203a780d0a\nEVID-S02-X|server|ascii|wrong",
    )?;
    let mut harness = ClientTranscriptHarness::new()?;
    assert_eq!(
        harness.drive(&mismatched),
        Err(ClientTranscriptError::ServerBytesMismatch)
    );

    let omitted = parse_client_transcript("EVID-S02-X|client|hex|50494e47203a780d0a")?;
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&omitted)?;
    assert_eq!(
        harness.finish(),
        Err(ClientTranscriptError::MissingServerBytes)
    );
    Ok(())
}

#[test]
fn harness_covers_not_registered_and_registration_timeout_precedence() -> Result<(), Box<dyn Error>>
{
    let transcript = parse_client_transcript(
        "EVID-S02-006-REGISTRATION|client|hex|4a4f494e0d0a\n\
         EVID-S02-006-REGISTRATION|server|hex|3a7365727665722e6578616d706c6520343531202a203a596f752068617665206e6f7420726567697374657265640d0a\n\
         EVID-S02-006-REGISTRATION|advance|ascii|30000\n\
         EVID-S02-006-REGISTRATION|server|hex|3a7365727665722e6578616d706c65204552524f52203a526567697374726174696f6e2074696d6564206f75740d0a",
    )?;
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&transcript)?;
    harness.finish()?;
    assert_eq!(harness.registration_phase(), RegistrationPhase::Closing);
    Ok(())
}

#[test]
fn harness_distinguishes_matching_and_wrong_keepalive_pongs() -> Result<(), Box<dyn Error>> {
    let base = parse_client_transcript(REGISTRATION_TRANSCRIPT)?;
    let matching = parse_client_transcript(
        "EVID-S02-006-REGISTRATION|client|hex|504f4e47203a414141414141414141414141414141414141414141410d0a\n\
         EVID-S02-006-REGISTRATION|advance|ascii|30000",
    )?;
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&base)?;
    harness.drive(&matching)?;
    harness.finish()?;
    assert_eq!(harness.registration_phase(), RegistrationPhase::Registered);

    let wrong = parse_client_transcript(
        "EVID-S02-006-REGISTRATION|client|hex|504f4e47203a77726f6e670d0a\n\
         EVID-S02-006-REGISTRATION|advance|ascii|30000\n\
         EVID-S02-006-REGISTRATION|server|hex|3a7365727665722e6578616d706c65204552524f52203a50696e672074696d656f75740d0a",
    )?;
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&base)?;
    harness.drive(&wrong)?;
    harness.finish()?;
    assert_eq!(harness.registration_phase(), RegistrationPhase::Closing);
    Ok(())
}

#[test]
fn harness_uses_explicit_policy_profile_and_handoff_observations() -> Result<(), Box<dyn Error>> {
    let profile = CapabilityProfile::new(vec![
        CapabilitySpec::new("cap-notify", None)?,
        CapabilitySpec::new("sasl", Some("AGENC-OPAQUE"))?,
    ])?;
    let transcript = parse_client_transcript(
        "EVID-S02-007-AUTH|client|hex|434150204c53203330320d0a\n\
         EVID-S02-007-AUTH|server|hex|3a7365727665722e6578616d706c6520434150202a204c53203a6361702d6e6f74696679207361736c3d4147454e432d4f50415155450d0a\n\
         EVID-S02-007-AUTH|client|hex|43415020524551203a7361736c0d0a\n\
         EVID-S02-007-AUTH|server|hex|3a7365727665722e6578616d706c6520434150202a2041434b203a7361736c0d0a\n\
         EVID-S02-007-AUTH|client|hex|41555448454e544943415445204147454e432d4f50415155450d0a",
    )?;
    let mut harness = ClientTranscriptHarness::with_profile_and_policy(
        profile,
        AccessTokenPolicy::IgnoreCompatibilityPass,
    )?;
    harness.drive(&transcript)?;
    harness.finish()?;
    assert_eq!(
        harness.handoffs(),
        [ClientTranscriptHandoff::Authentication(
            RegistrationAuthCarrier::Sasl
        )]
    );

    let token = parse_client_transcript(
        "EVID-S02-006-REGISTRATION|client|hex|5041535320414141414141414141414141414141414141414141414141414141414141414141414141414141414141410d0a",
    )?;
    let mut configured = ClientTranscriptHarness::with_profile_and_policy(
        CapabilityProfile::new(Vec::new())?,
        AccessTokenPolicy::RequireConfiguredToken,
    )?;
    assert_eq!(configured.drive(&token), Ok(()));
    configured.finish()?;
    assert_eq!(
        configured.registration_phase(),
        RegistrationPhase::Negotiating
    );

    let wrong_token = parse_client_transcript(
        "EVID-S02-006-REGISTRATION|client|hex|5041535320415145424151454241514542415145424151454241514542415145424151454241514542415145424151450d0a\n\
         EVID-S02-006-REGISTRATION|server|hex|3a7365727665722e6578616d706c65204552524f52203a41636365737320746f6b656e2072656a65637465640d0a",
    )?;
    let mut configured = ClientTranscriptHarness::with_profile_and_policy(
        CapabilityProfile::new(Vec::new())?,
        AccessTokenPolicy::RequireConfiguredToken,
    )?;
    assert_eq!(configured.drive(&wrong_token), Ok(()));
    configured.finish()?;
    assert_eq!(configured.registration_phase(), RegistrationPhase::Closing);
    Ok(())
}

#[test]
fn harness_observes_and_renders_the_complete_welcome_order() -> Result<(), Box<dyn Error>> {
    let profile = CapabilityProfile::new(vec![
        CapabilitySpec::new("cap-notify", None)?,
        CapabilitySpec::new("agenc.ag/recovery", Some("v1.AAAAAAAAAAAAAAAAAAAAAA"))?,
    ])?;
    let transcript = parse_client_transcript(
        "EVID-S02-010-TRANSCRIPT|client|hex|434150204c53203330320d0a\n\
         EVID-S02-010-TRANSCRIPT|client|hex|43415020524551203a6167656e632e61672f7265636f766572790d0a\n\
         EVID-S02-010-TRANSCRIPT|client|hex|4e49434b20416c6963650d0a\n\
         EVID-S02-010-TRANSCRIPT|client|hex|555345522069676e6f7265642030202a203a5265616c204e616d650d0a\n\
         EVID-S02-010-TRANSCRIPT|client|hex|43415020454e440d0a",
    )?;
    let mut harness = ClientTranscriptHarness::with_registration_scenario(
        profile,
        AccessTokenPolicy::IgnoreCompatibilityPass,
        None,
        true,
    )?;

    harness.drive(&transcript)?;

    assert_eq!(harness.registration_phase(), RegistrationPhase::Registered);
    assert_eq!(
        harness.welcome_steps(),
        [
            WelcomeStep::WelcomeThroughMyInfo,
            WelcomeStep::Isupport,
            WelcomeStep::LuserCounters,
            WelcomeStep::Motd,
            WelcomeStep::RecoveryEpoch,
            WelcomeStep::AccountState,
            WelcomeStep::RegistrationBatches,
        ]
    );
    let frames: Vec<&[u8]> = (0..harness.pending_server_frame_count())
        .filter_map(|index| harness.pending_server_frame_bytes(index))
        .collect();
    // The model spells its session's mask as the runtime spells every user
    // prefix (the runtime's account-state tests compare the two): `Alice`,
    // then a user field holding the fixture-zero cloak's user component and
    // a host field holding its host component.
    let mask = agenc_relay_testkit::transcript_mask("Alice")?;
    let (nickname, fields) = mask
        .split_once('!')
        .ok_or("the model's mask has no nickname")?;
    let (user, host) = fields
        .split_once('@')
        .ok_or("the model's mask has no host")?;
    assert_eq!(nickname, "Alice");
    assert!(user.contains("aaaaaaaaaa"), "user field {user}");
    assert!(host.contains("bbbbbbbbbbbbbbff"), "host field {host}");
    let logged_in = format!(":server.example 900 Alice {mask} * :You are now logged in\r\n");
    // Architecture 10.2: the recovery NOTE (step 5), then the authenticated
    // account state (step 6), which ends the burst.
    assert_eq!(
        frames.get(frames.len().saturating_sub(2)..),
        Some(
            &[
                &b":server.example NOTE * RECOVERY_EPOCH AAAAAAAAAAAAAAAAAAAAAA :Current server recovery identity\r\n"[..],
                logged_in.as_bytes(),
            ][..]
        )
    );
    Ok(())
}

#[test]
fn harness_renders_no_account_state_for_a_guest() -> Result<(), Box<dyn Error>> {
    let profile = CapabilityProfile::new(vec![CapabilitySpec::new(
        "agenc.ag/recovery",
        Some("v1.AAAAAAAAAAAAAAAAAAAAAA"),
    )?])?;
    let transcript = parse_client_transcript(
        "EVID-S02-010-TRANSCRIPT|client|hex|434150204c53203330320d0a\n\
         EVID-S02-010-TRANSCRIPT|client|hex|43415020524551203a6167656e632e61672f7265636f766572790d0a\n\
         EVID-S02-010-TRANSCRIPT|client|hex|4e49434b20416c6963650d0a\n\
         EVID-S02-010-TRANSCRIPT|client|hex|555345522069676e6f7265642030202a203a5265616c204e616d650d0a\n\
         EVID-S02-010-TRANSCRIPT|client|hex|43415020454e440d0a",
    )?;
    let mut harness = ClientTranscriptHarness::with_registration_scenario(
        profile,
        AccessTokenPolicy::IgnoreCompatibilityPass,
        None,
        false,
    )?;

    harness.drive(&transcript)?;

    assert!(!harness.welcome_steps().contains(&WelcomeStep::AccountState));
    let last = harness
        .pending_server_frame_count()
        .checked_sub(1)
        .and_then(|index| harness.pending_server_frame_bytes(index));
    assert_eq!(
        last,
        Some(&b":server.example NOTE * RECOVERY_EPOCH AAAAAAAAAAAAAAAAAAAAAA :Current server recovery identity\r\n"[..])
    );
    assert!(
        (0..harness.pending_server_frame_count())
            .filter_map(|index| harness.pending_server_frame_bytes(index))
            .all(|frame| !frame.windows(5).any(|window| window == b" 900 "))
    );
    Ok(())
}

#[test]
fn full_profile_cap_ls_is_split_before_rendering() -> Result<(), Box<dyn Error>> {
    let profile = complete_capability_profile()?;
    let transcript =
        parse_client_transcript("EVID-S02-005-CAP|client|hex|434150204c53203330320d0a")?;
    let mut harness = ClientTranscriptHarness::with_profile_and_policy(
        profile,
        AccessTokenPolicy::IgnoreCompatibilityPass,
    )?;
    harness.drive(&transcript)?;
    assert!(harness.pending_server_frame_count() > 1);
    Ok(())
}

fn complete_capability_profile() -> Result<CapabilityProfile, Box<dyn Error>> {
    let mut capabilities = Vec::new();
    capabilities.try_reserve_exact(CAPABILITIES.len())?;
    for name in CAPABILITIES {
        let value = match *name {
            "sasl" => Some("AGENC-OPAQUE"),
            "agenc.ag/privacy"
            | "agenc.ag/account-controls"
            | "agenc.ag/account-credentials"
            | "agenc.ag/channel-controls"
            | "agenc.ag/account-create" => Some("v1"),
            "agenc.ag/recovery" => Some("v1.AAAAAAAAAAAAAAAAAAAAAA"),
            "agenc.ag/e2ee-mls" => Some(
                "v1,profile=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,seg=2940,obj=262144,parts=90,welcome=4194304",
            ),
            "sts" => Some("duration=31536000"),
            _ => None,
        };
        capabilities.push(CapabilitySpec::new(name, value)?);
    }
    Ok(CapabilityProfile::new(capabilities)?)
}

/// X-05: every server frame a fixture asserts must also be one line the
/// client's server-to-client decoder accepts. The registration transcript's
/// frames all pass through this check when it is driven.
#[test]
fn every_asserted_server_frame_decodes_as_one_server_line() -> Result<(), Box<dyn Error>> {
    assert_eq!(decode_server_frame(b":server.example PING :x\r\n"), Ok(()));
    for frame in [
        &b":Server.Example PING :x\r\n"[..],
        &b":server.example PING :x\r\n:server.example PING :y\r\n"[..],
        &b":server.example PING :x"[..],
        &b"PING\n"[..],
        &b"\r\n"[..],
        &b""[..],
    ] {
        assert_eq!(
            decode_server_frame(frame),
            Err(ClientTranscriptError::ServerDecoding),
            "{frame:?}"
        );
    }
    assert_eq!(
        ClientTranscriptError::ServerDecoding.to_string(),
        "client transcript server bytes do not decode"
    );
    let transcript = parse_client_transcript(REGISTRATION_TRANSCRIPT)?;
    let mut harness = ClientTranscriptHarness::new()?;
    harness.drive(&transcript)?;
    harness.finish()?;
    Ok(())
}
