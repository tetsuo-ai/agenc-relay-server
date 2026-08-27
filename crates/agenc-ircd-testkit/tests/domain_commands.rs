#![forbid(unsafe_code)]

//! Stage-03 command registry, canonicalization, charging, and external-input tests.

use std::error::Error;

use agenc_ircd_client_wire::{FramedLine, POST_REGISTRATION_COMMANDS, parse_message};
use agenc_ircd_domain::{
    AccountCommand, AdmissionSnapshot, CanonicalCommand, ChannelNameValue, ChannelTarget,
    CommandEnvelope, DirectMessagePolicy, DomainCommandKind, DomainError, ExternalInputRequest,
    ExternalInputs, GuestDirectMessagePolicy, MessageCommand, MessageKind, MessageTarget,
    MessageText, PlanDecision, RateBucket,
};
use agenc_ircd_testkit::{
    ALL_REFERENCE_COMMAND_KINDS, ReferenceCommandKind, apply_command, bytes, create_account,
    message_admission, open_session, plan, registered_admission,
};
use agenc_ircd_types::{MessageId, UtcSecond};

fn message_body(text: &str) -> Result<MessageText, Box<dyn Error>> {
    Ok(MessageText::parse(text)?)
}

#[test]
fn client_wire_and_domain_agree_on_ctcp_message_semantics() -> Result<(), Box<dyn Error>> {
    let target = MessageTarget::User(agenc_ircd_domain::NicknameValue::parse("recipient")?);
    let action = parse_message(FramedLine::new(
        "PRIVMSG recipient :\u{1}ACTION waves\u{1}",
    )?)?
    .ok_or("ACTION message was ignored")?;
    let action_body = action.trailing().ok_or("ACTION body is missing")?;
    let accepted = MessageCommand::new(
        MessageKind::Privmsg,
        vec![target.clone()],
        Some(MessageText::parse(action_body)?),
    )?;
    assert_eq!(accepted.body(), Some("\u{1}ACTION waves\u{1}"));

    let dcc = parse_message(FramedLine::new(
        "PRIVMSG recipient :\u{1}DCC SEND secret 127.0.0.1 1\u{1}",
    )?)?
    .ok_or("DCC message was ignored")?;
    let dcc_body = dcc.trailing().ok_or("DCC body is missing")?;
    assert_eq!(
        MessageCommand::new(
            MessageKind::Privmsg,
            vec![target],
            Some(MessageText::parse(dcc_body)?),
        )
        .err(),
        Some(DomainError::UnsafeCtcp)
    );
    Ok(())
}

#[test]
fn domain_and_reference_models_cover_every_post_registration_registry_arm()
-> Result<(), Box<dyn Error>> {
    let names: Vec<&str> = ["NICK", "QUIT"]
        .into_iter()
        .chain(POST_REGISTRATION_COMMANDS.iter().copied())
        .collect();
    assert_eq!(names.len(), ALL_REFERENCE_COMMAND_KINDS.len());
    for name in names {
        let domain = DomainCommandKind::from_registered_name(name)?;
        let reference = ReferenceCommandKind::from_registered_name(name)?;
        assert_eq!(format!("{domain:?}"), format!("{reference:?}"));
    }
    assert_eq!(
        DomainCommandKind::from_registered_name("OPER").err(),
        Some(DomainError::InvalidArgument)
    );
    assert!(ReferenceCommandKind::from_registered_name("OPER").is_err());
    Ok(())
}

#[test]
fn canonical_multi_target_validation_is_atomic_and_scope_bound() -> Result<(), Box<dyn Error>> {
    let duplicate_join = CanonicalCommand::join(vec![
        ChannelTarget::new(ChannelNameValue::parse("#Same")?, false),
        ChannelTarget::new(ChannelNameValue::parse("#same")?, true),
    ]);
    assert_eq!(duplicate_join.err(), Some(DomainError::DuplicateTarget));

    let mixed_join = CanonicalCommand::join(vec![
        ChannelTarget::new(ChannelNameValue::parse("#global")?, false),
        ChannelTarget::new(ChannelNameValue::parse("&local")?, false),
    ]);
    assert_eq!(mixed_join.err(), Some(DomainError::MixedAuthority));

    let too_many: Vec<ChannelTarget> = (0..21)
        .map(|index| {
            ChannelNameValue::parse(&format!("#bounded-{index}"))
                .map(|name| ChannelTarget::new(name, false))
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(
        CanonicalCommand::join(too_many).err(),
        Some(DomainError::LimitExceeded)
    );

    let duplicate_message = MessageCommand::new(
        MessageKind::Privmsg,
        vec![
            MessageTarget::User(agenc_ircd_domain::NicknameValue::parse("Target")?),
            MessageTarget::User(agenc_ircd_domain::NicknameValue::parse("target")?),
        ],
        Some(message_body("hello")?),
    );
    assert_eq!(duplicate_message.err(), Some(DomainError::DuplicateTarget));
    assert_eq!(
        MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::User(
                agenc_ircd_domain::NicknameValue::parse("Target")?
            )],
            None,
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );
    assert_eq!(
        MessageCommand::new(
            MessageKind::Tagmsg,
            vec![MessageTarget::User(
                agenc_ircd_domain::NicknameValue::parse("Target")?
            )],
            Some(message_body("not tag-only")?),
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );
    Ok(())
}

#[test]
fn charging_precedes_policy_and_notice_failures_remain_silent() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (recipient_account, recipient_generation) = create_account(&mut state, 50, 1)?;
    let recipient = open_session(
        &mut state,
        50,
        "Recipient",
        Some((recipient_account, recipient_generation)),
    )?;
    let guest = open_session(&mut state, 51, "GuestSender", None)?;
    let recipient_admission = registered_admission(recipient.user_id)?;
    apply_command(
        &mut state,
        recipient,
        CanonicalCommand::account(AccountCommand::GuestDirectMessages(
            GuestDirectMessagePolicy::Deny,
        )),
        &recipient_admission,
        None,
    )?;
    apply_command(
        &mut state,
        recipient,
        CanonicalCommand::account(AccountCommand::DirectMessages(
            DirectMessagePolicy::Contacts,
        )),
        &recipient_admission,
        None,
    )?;

    let make_notice = || {
        Ok::<_, DomainError>(CanonicalCommand::message(MessageCommand::new(
            MessageKind::Notice,
            vec![MessageTarget::User(
                agenc_ircd_domain::NicknameValue::parse("Recipient")?,
            )],
            None,
        )?))
    };
    let no_message_credit =
        AdmissionSnapshot::new(vec![(RateBucket::RegisteredCommand(guest.user_id), 100)])?;
    let failure = state
        .authorize(
            CommandEnvelope::new(
                guest.session_id,
                guest.user_id,
                guest.generation,
                state.revision(),
                make_notice()?,
            ),
            &no_message_credit,
        )
        .err()
        .ok_or("message without hierarchical credit was accepted")?;
    assert_eq!(failure.error(), DomainError::ServerBusy);
    assert_eq!(failure.charges().len(), 2);
    assert!(failure.is_silent());

    let full_credit = message_admission(guest, &[])?;
    let authorized = state
        .authorize(
            CommandEnvelope::new(
                guest.session_id,
                guest.user_id,
                guest.generation,
                state.revision(),
                make_notice()?,
            ),
            &full_credit,
        )
        .map_err(|failure| failure.error())?;
    let PlanDecision::Rejected(failure) = state.plan_authorized(authorized, None)? else {
        return Err("denied guest message produced a non-rejection plan".into());
    };
    assert_eq!(failure.failures().len(), 1);
    assert_eq!(
        failure
            .failures()
            .first()
            .ok_or("missing direct-message rejection")?
            .error(),
        DomainError::Forbidden
    );
    assert_eq!(failure.charges().len(), 2);
    assert!(failure.is_silent());
    state.validate()?;
    Ok(())
}

#[test]
fn external_requests_are_stable_failure_aware_and_bound_before_ids() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let sender = open_session(&mut state, 60, "ExternalSender", None)?;
    open_session(&mut state, 61, "ExternalOne", None)?;
    open_session(&mut state, 62, "ExternalTwo", None)?;
    let admission = message_admission(sender, &[])?;
    let make_message = || {
        Ok::<_, DomainError>(CanonicalCommand::message(MessageCommand::new(
            MessageKind::Privmsg,
            vec![
                MessageTarget::User(agenc_ircd_domain::NicknameValue::parse("ExternalOne")?),
                MessageTarget::User(agenc_ircd_domain::NicknameValue::parse("ExternalTwo")?),
            ],
            Some(MessageText::parse("two targets")?),
        )?))
    };

    let first = plan(&state, sender, make_message()?, &admission, None)?;
    let PlanDecision::NeedsExternal(first_requests) = first else {
        return Err("message did not request explicit inputs".into());
    };
    let second = plan(&state, sender, make_message()?, &admission, None)?;
    let PlanDecision::NeedsExternal(second_requests) = second else {
        return Err("second message did not request explicit inputs".into());
    };
    assert_eq!(first_requests, second_requests);
    assert_eq!(first_requests.len(), 3);
    assert_eq!(
        first_requests.first(),
        Some(&ExternalInputRequest::UtcNow {
            request_sequence: 0
        })
    );
    assert_eq!(
        first_requests
            .get(1)
            .map(|request| request.request_sequence()),
        Some(1)
    );
    assert_eq!(
        first_requests
            .get(2)
            .map(|request| request.request_sequence()),
        Some(2)
    );

    let before = state.revision();
    let wall_failure = plan(
        &state,
        sender,
        make_message()?,
        &admission,
        Some(ExternalInputs {
            wall_clock_unavailable: true,
            message_ids: vec![
                MessageId::from_bytes(bytes(70)),
                MessageId::from_bytes(bytes(71)),
            ],
            ..ExternalInputs::default()
        }),
    );
    assert_eq!(wall_failure.err(), Some(DomainError::WallClockUnavailable));
    assert_eq!(state.revision(), before);

    let mismatch = plan(
        &state,
        sender,
        make_message()?,
        &admission,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_700_300_000)),
            message_ids: vec![MessageId::from_bytes(bytes(70))],
            ..ExternalInputs::default()
        }),
    );
    assert_eq!(mismatch.err(), Some(DomainError::ExternalInputMismatch));
    assert_eq!(state.revision(), before);

    let receipt = apply_command(
        &mut state,
        sender,
        make_message()?,
        &admission,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_700_300_000)),
            message_ids: vec![
                MessageId::from_bytes(bytes(70)),
                MessageId::from_bytes(bytes(71)),
            ],
            ..ExternalInputs::default()
        }),
    )?;
    assert_eq!(receipt.events().len(), 2);
    assert_eq!(receipt.recipients().len(), 3);
    state.validate()?;
    Ok(())
}
