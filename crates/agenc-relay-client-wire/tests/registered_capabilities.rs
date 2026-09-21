//! S06-009: commands must negotiate a usable response before reaching state owners.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_relay_client_wire::{
    AccessTokenPolicy, CapabilityProfile, CapabilitySpec, FramedLine, ParsedMessage,
    RegistrationAction, RegistrationError, RegistrationEvent, RegistrationGrammarError,
    RegistrationState, parse_message,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn parsed(line: &str) -> TestResult<ParsedMessage> {
    parse_message(FramedLine::new(line)?)?.ok_or_else(|| "empty test command".into())
}

fn profile() -> TestResult<CapabilityProfile> {
    Ok(CapabilityProfile::new(vec![
        CapabilitySpec::new("standard-replies", None)?,
        CapabilitySpec::new("agenc.ag/account-controls", Some("v1"))?,
        CapabilitySpec::new("agenc.ag/channel-controls", Some("v1"))?,
        CapabilitySpec::new("draft/chathistory", None)?,
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("server-time", None)?,
        CapabilitySpec::new("message-ids", None)?,
    ])?)
}

fn registered(profile: &CapabilityProfile) -> TestResult<RegistrationState> {
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let actions = state.message(parsed("NICK Alice")?, 1, profile)?;
    let Some(RegistrationAction::ReserveNickname { generation, .. }) = actions.first() else {
        return Err("nickname reservation missing".into());
    };
    state.event(
        RegistrationEvent::NicknameReserved {
            generation: *generation,
            accepted: true,
        },
        2,
    )?;
    let actions = state.message(parsed("USER alice 0 * :Alice")?, 3, profile)?;
    let Some(RegistrationAction::CommitRegistration { generation, .. }) = actions.first() else {
        return Err("registration commit missing".into());
    };
    state.event(
        RegistrationEvent::RegistrationCommitted {
            generation: *generation,
            accepted: true,
            authenticated: true,
        },
        4,
    )?;
    Ok(state)
}

#[test]
fn controls_require_both_the_vendor_capability_and_standard_replies() -> TestResult {
    let profile = profile()?;
    for (command, capability) in [
        ("ACCT LABEL example", "agenc.ag/account-controls"),
        ("ACCT DELETE START", "agenc.ag/account-controls"),
        ("CHANCTL REGISTER #room", "agenc.ag/channel-controls"),
        ("CHANCTL HISTORY #room OFF", "agenc.ag/channel-controls"),
    ] {
        for enabled in [
            String::new(),
            capability.to_owned(),
            "standard-replies".to_owned(),
        ] {
            let mut state = registered(&profile)?;
            if !enabled.is_empty() {
                state.message(parsed(&format!("CAP REQ :{enabled}"))?, 5, &profile)?;
            }
            assert_eq!(
                state.message(parsed(command)?, 6, &profile).err(),
                Some(RegistrationError::Grammar(
                    RegistrationGrammarError::NoPrivileges
                )),
                "{command} with {enabled} must not reach a state owner"
            );
        }
        let mut state = registered(&profile)?;
        state.message(
            parsed(&format!("CAP REQ :standard-replies {capability}"))?,
            5,
            &profile,
        )?;
        assert!(matches!(
            state.message(parsed(command)?, 6, &profile)?.as_slice(),
            [RegistrationAction::ForwardRegisteredCommand(_)]
        ));
        state.message(parsed("CAP REQ :-standard-replies")?, 7, &profile)?;
        assert!(state.message(parsed(command)?, 8, &profile).is_err());
    }
    Ok(())
}

#[test]
fn history_requires_its_negotiated_batch_profile_and_rechecks_capability_removal() -> TestResult {
    let profile = profile()?;
    let mut state = registered(&profile)?;
    let command = "CHATHISTORY LATEST #room * 1";
    assert_eq!(
        state.message(parsed(command)?, 5, &profile).err(),
        Some(RegistrationError::Grammar(
            RegistrationGrammarError::NoPrivileges
        ))
    );
    state.message(
        parsed("CAP REQ :batch server-time message-ids draft/chathistory")?,
        6,
        &profile,
    )?;
    assert!(matches!(
        state.message(parsed(command)?, 7, &profile)?.as_slice(),
        [RegistrationAction::ForwardRegisteredCommand(_)]
    ));
    state.message(parsed("CAP REQ :-draft/chathistory")?, 8, &profile)?;
    assert!(state.message(parsed(command)?, 9, &profile).is_err());
    assert!(matches!(
        state
            .message(parsed("JOIN #room")?, 10, &profile)?
            .as_slice(),
        [RegistrationAction::ForwardRegisteredCommand(_)]
    ));
    Ok(())
}
