#![forbid(unsafe_code)]

//! Registered-session command ownership handoff regressions.

use std::error::Error;
use std::io;

use agenc_relay_client_wire::{
    AccessTokenPolicy, CapabilityProfile, FramedLine, PostRegistrationCommandKind,
    RegisteredCommandKind, RegistrationAction, RegistrationEvent, RegistrationState, parse_message,
};

#[test]
fn registered_public_commands_retain_their_validated_owned_handoff() -> Result<(), Box<dyn Error>> {
    let advertised = CapabilityProfile::new(Vec::new())?;
    let mut state = complete_registration(&advertised)?;

    let actions = state.message(parsed("NOTICE Target :hello")?, 4, &advertised)?;
    let [RegistrationAction::ForwardRegisteredCommand(command)] = actions.as_slice() else {
        return Err(test_error("missing public-command handoff").into());
    };
    assert_eq!(
        command.kind(),
        RegisteredCommandKind::Public(PostRegistrationCommandKind::Notice)
    );
    assert_eq!(command.message().command(), "NOTICE");
    assert_eq!(command.message().trailing(), Some("hello"));

    let actions = state.message(parsed("NICK Next")?, 5, &advertised)?;
    let [RegistrationAction::ForwardRegisteredCommand(command)] = actions.as_slice() else {
        return Err(test_error("missing nickname-command handoff").into());
    };
    assert_eq!(command.kind(), RegisteredCommandKind::Nickname);
    assert_eq!(command.message().middle(), ["Next"]);
    Ok(())
}

#[test]
fn negotiating_public_commands_remain_wire_rejections() -> Result<(), Box<dyn Error>> {
    let advertised = CapabilityProfile::new(Vec::new())?;
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;

    assert!(matches!(
        state
            .message(parsed("NOTICE Target :hello")?, 1, &advertised)?
            .as_slice(),
        [RegistrationAction::NotRegistered]
    ));
    for malformed in ["JOIN", "NOTICE", "ACCTCRED"] {
        assert!(matches!(
            state
                .message(parsed(malformed)?, 2, &advertised)?
                .as_slice(),
            [RegistrationAction::NotRegistered]
        ));
    }
    Ok(())
}

fn complete_registration(
    advertised: &CapabilityProfile,
) -> Result<RegistrationState, Box<dyn Error>> {
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let reserve = state.message(parsed("NICK Initial")?, 1, advertised)?;
    let Some(RegistrationAction::ReserveNickname { generation, .. }) = reserve.first() else {
        return Err(test_error("missing nickname reservation").into());
    };
    state.event(
        RegistrationEvent::NicknameReserved {
            generation: *generation,
            accepted: true,
        },
        1,
    )?;
    let commit = state.message(parsed("USER ignored 0 * :Name")?, 2, advertised)?;
    let Some(RegistrationAction::CommitRegistration { generation, .. }) = commit.first() else {
        return Err(test_error("missing registration commit").into());
    };
    state.event(
        RegistrationEvent::RegistrationCommitted {
            generation: *generation,
            accepted: true,
            authenticated: false,
        },
        3,
    )?;
    Ok(state)
}

fn parsed(line: &str) -> Result<agenc_relay_client_wire::ParsedMessage, Box<dyn Error>> {
    let framed = FramedLine::new(line)?;
    parse_message(framed)?.ok_or_else(|| test_error("empty parsed message").into())
}

fn test_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}
