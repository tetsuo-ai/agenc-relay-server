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

#[test]
fn only_an_explicit_current_root_profile_can_forward_its_transfer() -> TestResult {
    use agenc_relay_client_wire::{
        InitialRootCarrier as Family, RegistrationAuthCarrier as Carrier,
    };
    use agenc_relay_types::{INITIAL_ROOT_CAPABILITY, INITIAL_ROOT_PROFILE_TOKEN};

    let value = format!("v1.{INITIAL_ROOT_PROFILE_TOKEN}");
    for unsupported in [None, Some("v1"), Some("v1.other")] {
        assert!(CapabilitySpec::new(INITIAL_ROOT_CAPABILITY, unsupported).is_err());
    }
    let baseline = CapabilityProfile::new(vec![CapabilitySpec::new(
        "agenc.ag/account-create",
        Some("v1"),
    )?])?;
    let offered = CapabilityProfile::new(vec![
        CapabilitySpec::new("agenc.ag/account-create", Some("v1"))?,
        CapabilitySpec::new(INITIAL_ROOT_CAPABILITY, Some(&value))?,
    ])?;
    let claim_only = CapabilityProfile::new(vec![CapabilitySpec::new(
        INITIAL_ROOT_CAPABILITY,
        Some(&value),
    )?])?;
    let begin = "ACCTCREATE CLAIMSTART 4726";
    let mut create = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    create.message(parsed("CAP LS 302")?, 1, &offered)?;
    assert!(create.message(parsed(begin)?, 2, &offered).is_err());
    create.message(parsed("CAP REQ :agenc.ag/initial-root")?, 3, &offered)?;
    assert!(create.message(parsed(begin)?, 4, &offered).is_err());
    create.message(parsed("CAP REQ :agenc.ag/account-create")?, 5, &offered)?;
    for withdrawn in [&baseline, &claim_only] {
        assert!(create.message(parsed(begin)?, 6, withdrawn).is_err());
    }
    let transfer = create.message(parsed(begin)?, 6, &offered)?;
    let [
        RegistrationAction::ForwardAuthCarrier {
            generation,
            carrier: Carrier::InitialRoot(Family::GuardedCreation),
            ..
        },
    ] = transfer.as_slice()
    else {
        return Err("missing guarded START".into());
    };
    create.event(
        RegistrationEvent::AuthCarrierFinished {
            generation: *generation,
        },
        7,
    )?;
    // Leaving the initial transfer does not turn a pending guarded FINISH into a plain creation.
    assert!(
        create
            .message(parsed("ACCTCREATE START 4726")?, 8, &offered)
            .is_err()
    );
    assert!(
        create
            .message(parsed("CAP REQ :-agenc.ag/initial-root")?, 9, &offered)
            .is_err()
    );
    for withdrawn in [&baseline, &claim_only] {
        assert!(
            create
                .message(parsed("ACCTCREATE FINISH 4726")?, 10, withdrawn)
                .is_err()
        );
    }
    assert!(
        create
            .apply_capability_profile(&baseline)?
            .iter()
            .any(|a| matches!(a, RegistrationAction::CapabilityReconnectRequired(_)))
    );
    assert!(
        create
            .message(parsed("ACCTCREATE FINISH 4726")?, 10, &baseline)
            .is_err()
    );

    let claim = "ACCTROOT CLAIM 4726";
    let mut account = registered(&offered)?;
    assert!(account.message(parsed(claim)?, 5, &offered).is_err());
    account.message(parsed("CAP LS 302")?, 6, &offered)?;
    account.message(parsed("CAP REQ :agenc.ag/initial-root")?, 7, &offered)?;
    assert!(account.message(parsed(claim)?, 8, &baseline).is_err());
    assert!(matches!(
        account.message(parsed(claim)?, 8, &offered)?.as_slice(),
        [RegistrationAction::ForwardAuthCarrier {
            carrier: Carrier::InitialRoot(Family::Claim),
            ..
        }]
    ));
    assert!(
        account
            .message(parsed("ACCTROOT DATA AQ")?, 9, &baseline)
            .is_err()
    );
    assert!(
        account
            .apply_capability_profile(&baseline)?
            .iter()
            .any(|a| matches!(a, RegistrationAction::CapabilityReconnectRequired(_)))
    );
    assert!(
        account
            .message(parsed("ACCTROOT DATA AQ")?, 9, &baseline)
            .is_err()
    );
    Ok(())
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
