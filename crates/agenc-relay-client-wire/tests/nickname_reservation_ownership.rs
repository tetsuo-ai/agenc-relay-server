#![forbid(unsafe_code)]

//! Generation-bound nickname reservation ownership regressions.

use std::error::Error;
use std::io;

use agenc_relay_client_wire::{
    AccessTokenPolicy, CapabilityProfile, FramedLine, REGISTRATION_TIMEOUT_MILLIS,
    RegistrationAction, RegistrationEvent, RegistrationPhase, RegistrationState, parse_message,
};

#[test]
fn new_nick_cancels_pending_before_replacing_and_releases_stale_acceptance()
-> Result<(), Box<dyn Error>> {
    let profile = empty_profile()?;
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;

    let first = requested_generation(&state.message(parsed("NICK First")?, 1, &profile)?)?;
    let second_actions = state.message(parsed("NICK Second")?, 2, &profile)?;
    let [
        RegistrationAction::CancelNicknameReservation {
            generation: cancelled,
        },
        RegistrationAction::ReserveNickname {
            generation: second,
            nickname,
        },
    ] = second_actions.as_slice()
    else {
        return Err(test_error().into());
    };
    assert_eq!(*cancelled, first);
    assert_eq!(nickname, "Second");

    assert!(matches!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: first,
                    accepted: true,
                },
                2,
            )?
            .as_slice(),
        [RegistrationAction::ReleaseNickname { generation }] if *generation == first
    ));
    assert!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: *second,
                    accepted: true,
                },
                2,
            )?
            .is_empty()
    );

    let third_actions = state.message(parsed("NICK Third")?, 3, &profile)?;
    let [
        RegistrationAction::ReplaceNickname {
            generation: third,
            previous_generation,
            nickname,
        },
    ] = third_actions.as_slice()
    else {
        return Err(test_error().into());
    };
    assert_eq!(*previous_generation, *second);
    assert_eq!(nickname, "Third");

    let fourth_actions = state.message(parsed("NICK Fourth")?, 4, &profile)?;
    let [
        RegistrationAction::CancelNicknameReservation {
            generation: cancelled,
        },
        RegistrationAction::ReplaceNickname {
            generation: fourth,
            previous_generation,
            nickname,
        },
    ] = fourth_actions.as_slice()
    else {
        return Err(test_error().into());
    };
    assert_eq!(*cancelled, *third);
    assert_eq!(*previous_generation, *second);
    assert_eq!(nickname, "Fourth");
    assert!(matches!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: *third,
                    accepted: true,
                },
                4,
            )?
            .as_slice(),
        [RegistrationAction::ReleaseNickname { generation }] if *generation == *third
    ));
    assert!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: *fourth,
                    accepted: true,
                },
                4,
            )?
            .is_empty()
    );
    Ok(())
}

#[test]
fn replacement_result_selects_the_exact_lease_transferred_by_commit() -> Result<(), Box<dyn Error>>
{
    let profile = empty_profile()?;

    let mut rejected = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let held = hold_nickname(&mut rejected, "Held", 1, &profile)?;
    let replacement =
        requested_generation(&rejected.message(parsed("NICK Rejected")?, 2, &profile)?)?;
    assert!(
        rejected
            .message(parsed("USER user 0 * :Real Name")?, 3, &profile)?
            .is_empty()
    );
    let commit = rejected.event(
        RegistrationEvent::NicknameReserved {
            generation: replacement,
            accepted: false,
        },
        3,
    )?;
    let commit_generation = assert_commit_lease(&commit, held, "Held")?;
    rejected.event(
        RegistrationEvent::RegistrationCommitted {
            generation: commit_generation,
            accepted: true,
            authenticated: false,
        },
        3,
    )?;

    let mut accepted = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let held = hold_nickname(&mut accepted, "Held", 1, &profile)?;
    let replacement_actions = accepted.message(parsed("NICK Accepted")?, 2, &profile)?;
    let replacement = requested_generation(&replacement_actions)?;
    assert!(matches!(
        replacement_actions.as_slice(),
        [RegistrationAction::ReplaceNickname {
            previous_generation,
            ..
        }] if *previous_generation == held
    ));
    assert!(
        accepted
            .message(parsed("USER user 0 * :Real Name")?, 3, &profile)?
            .is_empty()
    );
    let commit = accepted.event(
        RegistrationEvent::NicknameReserved {
            generation: replacement,
            accepted: true,
        },
        3,
    )?;
    let commit_generation = assert_commit_lease(&commit, replacement, "Accepted")?;
    accepted.event(
        RegistrationEvent::RegistrationCommitted {
            generation: commit_generation,
            accepted: true,
            authenticated: false,
        },
        3,
    )?;
    Ok(())
}

#[test]
fn latest_nickname_blocks_pass_user_cap_and_token_completion_callers() -> Result<(), Box<dyn Error>>
{
    let profile = empty_profile()?;

    let mut pass = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    hold_nickname(&mut pass, "Held", 1, &profile)?;
    let replacement = requested_generation(&pass.message(parsed("NICK Latest")?, 2, &profile)?)?;
    assert!(pass.message(parsed("PASS token")?, 3, &profile)?.is_empty());
    assert!(
        pass.message(parsed("USER user 0 * :Real Name")?, 4, &profile)?
            .is_empty()
    );
    let commit = pass.event(
        RegistrationEvent::NicknameReserved {
            generation: replacement,
            accepted: true,
        },
        4,
    )?;
    assert_commit_lease(&commit, replacement, "Latest")?;

    let mut cap = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    cap.message(parsed("CAP LS 302")?, 1, &profile)?;
    hold_nickname(&mut cap, "Held", 2, &profile)?;
    cap.message(parsed("USER user 0 * :Real Name")?, 3, &profile)?;
    let replacement = requested_generation(&cap.message(parsed("NICK Latest")?, 4, &profile)?)?;
    assert!(cap.message(parsed("CAP END")?, 5, &profile)?.is_empty());
    let commit = cap.event(
        RegistrationEvent::NicknameReserved {
            generation: replacement,
            accepted: true,
        },
        5,
    )?;
    assert_commit_lease(&commit, replacement, "Latest")?;

    let mut token = RegistrationState::new(0, AccessTokenPolicy::RequireConfiguredToken)?;
    let token_actions = token.message(
        parsed("PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?,
        1,
        &profile,
    )?;
    let token_generation = checked_token_generation(&token_actions)?;
    hold_nickname(&mut token, "Held", 2, &profile)?;
    token.message(parsed("USER user 0 * :Real Name")?, 3, &profile)?;
    let replacement = requested_generation(&token.message(parsed("NICK Latest")?, 4, &profile)?)?;
    assert!(
        token
            .event(
                RegistrationEvent::AccessTokenChecked {
                    generation: token_generation,
                    accepted: true,
                },
                4,
            )?
            .is_empty()
    );
    let commit = token.event(
        RegistrationEvent::NicknameReserved {
            generation: replacement,
            accepted: true,
        },
        4,
    )?;
    assert_commit_lease(&commit, replacement, "Latest")?;
    Ok(())
}

#[test]
fn every_close_entry_cleans_nickname_ownership_once_before_close() -> Result<(), Box<dyn Error>> {
    let profile = empty_profile()?;

    let (mut message_state, held, pending) = state_with_held_and_pending(&profile)?;
    let actions = message_state.message(parsed("QUIT :done")?, 3, &profile)?;
    assert_cleanup_then_close(&actions, pending, held)?;
    assert!(
        message_state
            .message(parsed("QUIT :again")?, 4, &profile)?
            .is_empty()
    );
    assert!(
        message_state
            .tick(REGISTRATION_TIMEOUT_MILLIS, None)?
            .is_empty()
    );
    assert!(
        message_state
            .event(RegistrationEvent::TransportClosed, 4)?
            .is_empty()
    );
    assert_eq!(message_state.phase(), RegistrationPhase::Closed);

    let (mut tick_state, held, pending) = state_with_held_and_pending(&profile)?;
    let actions = tick_state.tick(REGISTRATION_TIMEOUT_MILLIS, None)?;
    assert_cleanup_then_close(&actions, pending, held)?;
    assert!(
        tick_state
            .tick(REGISTRATION_TIMEOUT_MILLIS + 1, None)?
            .is_empty()
    );

    let mut event_state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let held = requested_generation(&event_state.message(parsed("NICK Held")?, 1, &profile)?)?;
    event_state.message(parsed("USER user 0 * :Real Name")?, 2, &profile)?;
    let commit = event_state.event(
        RegistrationEvent::NicknameReserved {
            generation: held,
            accepted: true,
        },
        2,
    )?;
    let commit_generation = assert_commit_lease(&commit, held, "Held")?;
    let actions = event_state.event(
        RegistrationEvent::RegistrationCommitted {
            generation: commit_generation,
            accepted: false,
            authenticated: false,
        },
        2,
    )?;
    assert!(matches!(
        actions.as_slice(),
        [
            RegistrationAction::ReleaseNickname { generation },
            RegistrationAction::Close(_),
        ] if *generation == held
    ));
    assert!(
        event_state
            .event(
                RegistrationEvent::RegistrationCommitted {
                    generation: commit_generation,
                    accepted: false,
                    authenticated: false,
                },
                2,
            )?
            .is_empty()
    );
    Ok(())
}

#[test]
fn transport_close_and_deadline_stale_result_cleanup_are_generation_bound()
-> Result<(), Box<dyn Error>> {
    let profile = empty_profile()?;
    let (mut transport, held, pending) = state_with_held_and_pending(&profile)?;
    let actions = transport.event(RegistrationEvent::TransportClosed, 3)?;
    assert_cleanup_without_close(&actions, pending, held)?;
    assert_eq!(transport.phase(), RegistrationPhase::Closed);
    assert!(
        transport
            .event(RegistrationEvent::TransportClosed, 4)?
            .is_empty()
    );

    let mut deadline = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let stale = requested_generation(&deadline.message(parsed("NICK Stale")?, 1, &profile)?)?;
    let current = requested_generation(&deadline.message(parsed("NICK Current")?, 2, &profile)?)?;
    let actions = deadline.event(
        RegistrationEvent::NicknameReserved {
            generation: stale,
            accepted: true,
        },
        REGISTRATION_TIMEOUT_MILLIS,
    )?;
    assert!(matches!(
        actions.as_slice(),
        [
            RegistrationAction::CancelNicknameReservation { generation: cancelled },
            RegistrationAction::ReleaseNickname { generation: released },
            RegistrationAction::Close(_),
        ] if *cancelled == current && *released == stale
    ));
    Ok(())
}

fn empty_profile() -> Result<CapabilityProfile, Box<dyn Error>> {
    Ok(CapabilityProfile::new(Vec::new())?)
}

fn parsed(line: &str) -> Result<agenc_relay_client_wire::ParsedMessage, Box<dyn Error>> {
    parse_message(FramedLine::new(line)?)?
        .ok_or_else(|| io::Error::other("missing parsed message").into())
}

fn hold_nickname(
    state: &mut RegistrationState,
    nickname: &str,
    now: u64,
    profile: &CapabilityProfile,
) -> Result<u64, Box<dyn Error>> {
    let generation = requested_generation(&state.message(
        parsed(&format!("NICK {nickname}"))?,
        now,
        profile,
    )?)?;
    assert!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation,
                    accepted: true,
                },
                now,
            )?
            .is_empty()
    );
    Ok(generation)
}

fn state_with_held_and_pending(
    profile: &CapabilityProfile,
) -> Result<(RegistrationState, u64, u64), Box<dyn Error>> {
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let held = hold_nickname(&mut state, "Held", 1, profile)?;
    let pending = requested_generation(&state.message(parsed("NICK Pending")?, 2, profile)?)?;
    Ok((state, held, pending))
}

fn requested_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    actions
        .iter()
        .find_map(|action| match action {
            RegistrationAction::ReserveNickname { generation, .. }
            | RegistrationAction::ReplaceNickname { generation, .. } => Some(*generation),
            _ => None,
        })
        .ok_or_else(test_error)
}

fn checked_token_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(RegistrationAction::CheckAccessToken { generation, .. }) = actions.first() else {
        return Err(test_error());
    };
    Ok(*generation)
}

fn assert_commit_lease(
    actions: &[RegistrationAction],
    expected_reservation: u64,
    expected_nickname: &str,
) -> Result<u64, io::Error> {
    // A refused replacement answers 433 first; the commit that follows keeps the held lease.
    let Some(RegistrationAction::CommitRegistration {
        generation,
        nickname_reservation_generation,
        nickname,
        ..
    }) = actions
        .iter()
        .find(|action| !matches!(action, RegistrationAction::NicknameInUse(_)))
    else {
        return Err(test_error());
    };
    assert_eq!(*nickname_reservation_generation, expected_reservation);
    assert_eq!(nickname, expected_nickname);
    Ok(*generation)
}

fn assert_cleanup_then_close(
    actions: &[RegistrationAction],
    pending: u64,
    held: u64,
) -> Result<(), io::Error> {
    assert_cleanup_without_close(actions.get(..2).ok_or_else(test_error)?, pending, held)?;
    if !matches!(actions.get(2), Some(RegistrationAction::Close(_))) {
        return Err(test_error());
    }
    Ok(())
}

fn assert_cleanup_without_close(
    actions: &[RegistrationAction],
    pending: u64,
    held: u64,
) -> Result<(), io::Error> {
    assert!(matches!(
        actions,
        [
            RegistrationAction::CancelNicknameReservation { generation: cancelled },
            RegistrationAction::ReleaseNickname { generation: released },
        ] if *cancelled == pending && *released == held
    ));
    Ok(())
}

fn test_error() -> io::Error {
    io::Error::other("nickname reservation fixture mismatch")
}
