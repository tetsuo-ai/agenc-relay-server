#![forbid(unsafe_code)]

//! Public state-machine boundaries not exercised by the main Stage 02 vectors.

use std::error::Error;
use std::io;

use agenc_ircd_client_wire::{
    ACCOUNT_IDLE_TIMEOUT_MILLIS, ACCOUNT_REQUEST_BYTES, ACCOUNT_RESPONSE_BYTES,
    ACCOUNT_TOTAL_TIMEOUT_MILLIS, AUTH_CHUNK_CHARACTERS, AccessTokenPolicy, AccountCarrierAction,
    AccountCarrierKind, AccountCarrierPhase, AccountTransfer, AuthTransportError,
    CapabilityProfile, CapabilitySpec, FramedLine, KEEPALIVE_IDLE_MILLIS, KEEPALIVE_PONG_MILLIS,
    MAX_PENDING_MESSAGES, REGISTRATION_TIMEOUT_MILLIS, RegistrationAction, RegistrationAuthCarrier,
    RegistrationError, RegistrationEvent, RegistrationPhase, RegistrationState, SaslTransport,
    parse_message,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[test]
fn sasl_and_account_carriers_reject_overrun_and_wrong_state_boundaries()
-> Result<(), Box<dyn Error>> {
    let mut sasl = SaslTransport::new()?;
    sasl.client("AGENC-OPAQUE", 0)?;
    let full_chunk = "A".repeat(AUTH_CHUNK_CHARACTERS);
    for _ in 0..15 {
        assert!(sasl.client(&full_chunk, 1)?.is_empty());
    }
    assert_eq!(
        sasl.client(&full_chunk, 1).err(),
        Some(AuthTransportError::InvalidChunk)
    );

    let mut idle = AccountTransfer::new(AccountCarrierKind::Create)?;
    assert_eq!(
        idle.client("END", None, false, 0).err(),
        Some(AuthTransportError::BadState)
    );

    let request = vec![3_u8; ACCOUNT_REQUEST_BYTES];
    let mut waiting = AccountTransfer::new(AccountCarrierKind::Create)?;
    feed_account_request(&mut waiting, AccountCarrierPhase::Start, &request, 0)?;
    let short_response = vec![4_u8; ACCOUNT_RESPONSE_BYTES - 1];
    assert_eq!(
        waiting
            .server_response(AccountCarrierPhase::Start, &short_response, 2)
            .err(),
        Some(AuthTransportError::WrongLength)
    );
    Ok(())
}

#[test]
fn empty_sasl_chunks_and_early_account_end_fail_closed() -> Result<(), Box<dyn Error>> {
    let mut sasl = SaslTransport::new()?;
    sasl.client("AGENC-OPAQUE", 0)?;
    assert_eq!(
        sasl.client("", 1).err(),
        Some(AuthTransportError::WrongLength)
    );

    let mut account = AccountTransfer::new(AccountCarrierKind::Create)?;
    account.client("START", Some("4726"), false, 0)?;
    assert_eq!(
        account.client("END", None, false, 1).err(),
        Some(AuthTransportError::WrongLength)
    );
    Ok(())
}

#[test]
fn account_carrier_checked_deadlines_cover_total_data_and_end_boundaries()
-> Result<(), Box<dyn Error>> {
    let mut start_overflow = AccountTransfer::new(AccountCarrierKind::Create)?;
    assert_eq!(
        start_overflow
            .client(
                "START",
                Some("4726"),
                false,
                u64::MAX - ACCOUNT_IDLE_TIMEOUT_MILLIS,
            )
            .err(),
        Some(AuthTransportError::Overflow)
    );

    let near_limit_start = u64::MAX - ACCOUNT_TOTAL_TIMEOUT_MILLIS;
    let full_chunk = "A".repeat(AUTH_CHUNK_CHARACTERS);
    let mut data_overflow = AccountTransfer::new(AccountCarrierKind::Create)?;
    data_overflow.client("START", Some("4726"), false, near_limit_start)?;
    for now in [u64::MAX - 45_001, u64::MAX - 30_002, u64::MAX - 15_003] {
        data_overflow.client("DATA", Some(&full_chunk), false, now)?;
    }
    assert_eq!(
        data_overflow
            .client("DATA", Some(&full_chunk), false, u64::MAX - 4)
            .err(),
        Some(AuthTransportError::Overflow)
    );

    let request = URL_SAFE_NO_PAD.encode(vec![7_u8; ACCOUNT_REQUEST_BYTES]);
    let chunks = request.as_bytes().chunks(AUTH_CHUNK_CHARACTERS);
    let mut end_overflow = AccountTransfer::new(AccountCarrierKind::Create)?;
    end_overflow.client("START", Some("4726"), false, near_limit_start)?;
    for (index, chunk) in chunks.enumerate() {
        let now = match index {
            0..=3 => near_limit_start,
            4..=7 => u64::MAX - 45_001,
            8..=11 => u64::MAX - 30_002,
            _ => u64::MAX - 15_003,
        };
        end_overflow.client("DATA", Some(std::str::from_utf8(chunk)?), false, now)?;
    }
    assert_eq!(
        end_overflow.client("END", None, false, u64::MAX - 4).err(),
        Some(AuthTransportError::Overflow)
    );

    let mut total_timeout = AccountTransfer::new(AccountCarrierKind::Create)?;
    total_timeout.client("START", Some("4726"), false, 0)?;
    for now in [0, 14_999, 29_998, 44_997, 59_996] {
        total_timeout.client("DATA", Some(&full_chunk), false, now)?;
    }
    assert_eq!(
        total_timeout.tick(ACCOUNT_TOTAL_TIMEOUT_MILLIS).err(),
        Some(AuthTransportError::TimedOut)
    );
    Ok(())
}

#[test]
fn registration_deadlines_and_transport_close_precede_new_input() -> Result<(), Box<dyn Error>> {
    let profile = registration_capabilities()?;

    let mut closed = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    closed.event(RegistrationEvent::TransportClosed, 0)?;
    assert_eq!(closed.phase(), RegistrationPhase::Closed);
    assert!(
        closed
            .message(parsed("PING token")?, 1, &profile)?
            .is_empty()
    );

    let mut registration_timeout =
        RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    assert!(matches!(
        registration_timeout
            .message(parsed("PING token")?, REGISTRATION_TIMEOUT_MILLIS, &profile)?
            .as_slice(),
        [RegistrationAction::Close(_)]
    ));

    let mut ping_timeout = complete_registration(&profile, None)?;
    let ping_at = 5 + KEEPALIVE_IDLE_MILLIS;
    ping_timeout.tick(ping_at, Some("ABCDEFGHIJKLMNOPQRSTUV"))?;
    assert!(matches!(
        ping_timeout
            .message(
                parsed("PING late")?,
                ping_at + KEEPALIVE_PONG_MILLIS,
                &profile,
            )?
            .as_slice(),
        [RegistrationAction::Close(_)]
    ));

    let mut invalid_token = complete_registration(&profile, None)?;
    assert_eq!(
        invalid_token
            .tick(5 + KEEPALIVE_IDLE_MILLIS, Some("ABCDEFGHIJKLMNOPQRSTU!"))
            .err(),
        Some(RegistrationError::InvalidRegistrationField)
    );
    invalid_token.tick(5 + KEEPALIVE_IDLE_MILLIS, Some("ABCDEFGHIJKLMNOPQRSTUV"))?;
    assert!(
        invalid_token
            .event(
                RegistrationEvent::TransportClosed,
                5 + KEEPALIVE_IDLE_MILLIS
            )?
            .is_empty()
    );
    assert_eq!(invalid_token.phase(), RegistrationPhase::Closed);
    Ok(())
}

#[test]
fn commit_backpressure_closes_after_the_exact_message_limit() -> Result<(), Box<dyn Error>> {
    let profile = registration_capabilities()?;
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let reservation =
        reservation_generation(&state.message(parsed("NICK Alice")?, 1, &profile)?)?;
    state.message(parsed("USER user 0 * :Real Name")?, 2, &profile)?;
    assert!(matches!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: reservation,
                    accepted: true,
                },
                2,
            )?
            .as_slice(),
        [RegistrationAction::CommitRegistration { .. }]
    ));

    for now in 3..3 + MAX_PENDING_MESSAGES as u64 {
        assert!(matches!(
            state
                .message(parsed("PING queued")?, now, &profile)?
                .as_slice(),
            [RegistrationAction::InputDeferred]
        ));
    }
    let actions = state.message(
        parsed("PING overflow")?,
        3 + MAX_PENDING_MESSAGES as u64,
        &profile,
    )?;
    assert!(matches!(
        actions.as_slice(),
        [
            RegistrationAction::ReleaseNickname { generation },
            RegistrationAction::Close(_),
        ] if *generation == reservation
    ));
    assert_eq!(state.phase(), RegistrationPhase::Closing);
    Ok(())
}

#[test]
fn authentication_capability_and_single_carrier_guards_are_enforced() -> Result<(), Box<dyn Error>>
{
    let profile = registration_capabilities()?;

    let mut unavailable = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    assert_eq!(
        unavailable
            .message(parsed("AUTHENTICATE AGENC-OPAQUE")?, 1, &profile)
            .err(),
        Some(RegistrationError::AuthenticationUnavailable)
    );

    let mut active = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    active.message(parsed("CAP LS 302")?, 1, &profile)?;
    active.message(
        parsed("CAP REQ :sasl agenc.ag/account-create")?,
        2,
        &profile,
    )?;
    let first = active.message(parsed("AUTHENTICATE AGENC-OPAQUE")?, 3, &profile)?;
    let generation = auth_generation(&first, RegistrationAuthCarrier::Sasl)?;
    let repeated = active.message(parsed("AUTHENTICATE +")?, 4, &profile)?;
    assert_eq!(
        auth_generation(&repeated, RegistrationAuthCarrier::Sasl)?,
        generation
    );
    assert_eq!(
        active.message(parsed("CAP REQ :-sasl")?, 5, &profile).err(),
        Some(RegistrationError::AuthenticationInProgress)
    );
    assert_eq!(
        active
            .message(parsed("ACCTCREATE START 4726")?, 6, &profile)
            .err(),
        Some(RegistrationError::AuthenticationInProgress)
    );
    assert!(
        active
            .event(
                RegistrationEvent::AuthCarrierFinished {
                    generation: generation + 1,
                },
                6,
            )?
            .is_empty()
    );

    let mut ended = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    ended.message(parsed("CAP LS 302")?, 1, &profile)?;
    ended.message(parsed("CAP REQ :sasl")?, 2, &profile)?;
    ended.message(parsed("CAP END")?, 3, &profile)?;
    assert_eq!(
        ended
            .message(parsed("AUTHENTICATE AGENC-OPAQUE")?, 4, &profile)
            .err(),
        Some(RegistrationError::AuthenticationUnavailable)
    );
    Ok(())
}

#[test]
fn registered_auth_and_nickname_results_are_generation_and_phase_bound()
-> Result<(), Box<dyn Error>> {
    let profile = registration_capabilities()?;
    let mut state = complete_registration(&profile, Some("agenc.ag/account-credentials"))?;
    let actions = state.message(parsed("ACCTCRED START 4726")?, 6, &profile)?;
    let generation = auth_generation(&actions, RegistrationAuthCarrier::AccountCredentials)?;
    assert!(
        state
            .event(
                RegistrationEvent::AuthCarrierFinished {
                    generation: generation + 1,
                },
                6,
            )?
            .is_empty()
    );
    assert!(
        state
            .event(RegistrationEvent::AuthCarrierFinished { generation }, 6,)?
            .is_empty()
    );
    assert!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: 999,
                    accepted: true,
                },
                6,
            )?
            .is_empty()
    );

    let mut held = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let reservation = reservation_generation(&held.message(parsed("NICK Held")?, 1, &profile)?)?;
    held.event(
        RegistrationEvent::NicknameReserved {
            generation: reservation,
            accepted: true,
        },
        1,
    )?;
    assert!(
        held.event(
            RegistrationEvent::NicknameReserved {
                generation: reservation,
                accepted: true,
            },
            1,
        )?
        .is_empty()
    );
    assert!(
        held.event(
            RegistrationEvent::NicknameReserved {
                generation: reservation + 1,
                accepted: false,
            },
            1,
        )?
        .is_empty()
    );
    Ok(())
}

#[test]
fn account_carrier_rejects_noncanonical_trailing_bits() -> Result<(), Box<dyn Error>> {
    let mut encoded = URL_SAFE_NO_PAD.encode(vec![0_u8; ACCOUNT_REQUEST_BYTES]);
    let Some(last) = encoded.pop() else {
        return Err(io::Error::other("missing encoded request").into());
    };
    if last != 'A' {
        return Err(io::Error::other("unexpected canonical request suffix").into());
    }
    encoded.push('B');

    let mut transfer = AccountTransfer::new(AccountCarrierKind::Create)?;
    transfer.client("START", Some("4726"), false, 0)?;
    for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        transfer.client("DATA", Some(std::str::from_utf8(chunk)?), false, 1)?;
    }
    assert_eq!(
        transfer.client("END", None, false, 1).err(),
        Some(AuthTransportError::InvalidChunk)
    );
    Ok(())
}

#[test]
fn active_auth_blocks_registration_until_its_generation_finishes() -> Result<(), Box<dyn Error>> {
    let profile = registration_capabilities()?;
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    state.message(parsed("CAP LS 302")?, 1, &profile)?;
    state.message(parsed("CAP REQ :sasl")?, 2, &profile)?;
    let auth = state.message(parsed("AUTHENTICATE AGENC-OPAQUE")?, 3, &profile)?;
    let auth_generation = auth_generation(&auth, RegistrationAuthCarrier::Sasl)?;
    let nickname = reservation_generation(&state.message(parsed("NICK Alice")?, 4, &profile)?)?;
    state.message(parsed("USER user 0 * :Real Name")?, 5, &profile)?;
    assert!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: nickname,
                    accepted: true,
                },
                5,
            )?
            .is_empty()
    );
    assert!(
        state
            .event(
                RegistrationEvent::AuthCarrierFinished {
                    generation: auth_generation,
                },
                6,
            )?
            .is_empty()
    );
    assert!(matches!(
        state.message(parsed("CAP END")?, 7, &profile)?.as_slice(),
        [RegistrationAction::CommitRegistration { .. }]
    ));
    Ok(())
}

fn feed_account_request(
    transfer: &mut AccountTransfer,
    phase: AccountCarrierPhase,
    request: &[u8],
    now: u64,
) -> Result<(), Box<dyn Error>> {
    let subcommand = match phase {
        AccountCarrierPhase::Start => "START",
        AccountCarrierPhase::Finish => "FINISH",
    };
    transfer.client(subcommand, Some("4726"), false, now)?;
    let encoded = URL_SAFE_NO_PAD.encode(request);
    for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        transfer.client("DATA", Some(std::str::from_utf8(chunk)?), false, now + 1)?;
    }
    assert!(matches!(
        transfer.client("END", None, false, now + 1)?.as_slice(),
        [AccountCarrierAction::RequestEnvelope { phase: actual, .. }] if *actual == phase
    ));
    Ok(())
}

fn complete_registration(
    profile: &CapabilityProfile,
    enabled: Option<&str>,
) -> Result<RegistrationState, Box<dyn Error>> {
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    state.message(parsed("CAP LS 302")?, 1, profile)?;
    if let Some(enabled) = enabled {
        state.message(parsed(&format!("CAP REQ :{enabled}"))?, 2, profile)?;
    }
    let reservation = reservation_generation(&state.message(parsed("NICK Alice")?, 3, profile)?)?;
    state.message(parsed("USER user 0 * :Real Name")?, 4, profile)?;
    assert!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: reservation,
                    accepted: true,
                },
                4,
            )?
            .is_empty()
    );
    let commit = commit_generation(&state.message(parsed("CAP END")?, 5, profile)?)?;
    state.event(
        RegistrationEvent::RegistrationCommitted {
            generation: commit,
            accepted: true,
            authenticated: false,
        },
        5,
    )?;
    assert_eq!(state.phase(), RegistrationPhase::Registered);
    Ok(state)
}

fn registration_capabilities() -> Result<CapabilityProfile, Box<dyn Error>> {
    Ok(CapabilityProfile::new(vec![
        CapabilitySpec::new("cap-notify", None)?,
        CapabilitySpec::new("message-tags", None)?,
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("sasl", Some("AGENC-OPAQUE"))?,
        CapabilitySpec::new("agenc.ag/account-create", Some("v1"))?,
        CapabilitySpec::new("agenc.ag/account-credentials", Some("v1"))?,
    ])?)
}

fn parsed(line: &str) -> Result<agenc_ircd_client_wire::ParsedMessage, Box<dyn Error>> {
    parse_message(FramedLine::new(line)?)?
        .ok_or_else(|| io::Error::other("missing parsed message").into())
}

fn reservation_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(generation) = actions.iter().find_map(|action| match action {
        RegistrationAction::ReserveNickname { generation, .. }
        | RegistrationAction::ReplaceNickname { generation, .. } => Some(*generation),
        _ => None,
    }) else {
        return Err(io::Error::other("missing nickname reservation"));
    };
    Ok(generation)
}

fn commit_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(RegistrationAction::CommitRegistration { generation, .. }) = actions.first() else {
        return Err(io::Error::other("missing registration commit"));
    };
    Ok(*generation)
}

fn auth_generation(
    actions: &[RegistrationAction],
    expected: RegistrationAuthCarrier,
) -> Result<u64, io::Error> {
    let Some(RegistrationAction::ForwardAuthCarrier {
        generation,
        carrier,
        ..
    }) = actions.first()
    else {
        return Err(io::Error::other("missing authentication handoff"));
    };
    if *carrier != expected {
        return Err(io::Error::other("unexpected authentication carrier"));
    }
    Ok(*generation)
}
