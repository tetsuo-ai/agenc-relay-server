#![forbid(unsafe_code)]

//! Broad Stage-03 behavior matrices for every public domain transition family.

use std::error::Error;

use agenc_ircd_domain::{
    AccountCommand, AccountLabelValue, AdmissionSnapshot, CanonicalCommand, CanonicalCommandView,
    ChannelCommand, ChannelNameValue, ChannelTarget, DirectMessagePolicy, DisplayNameValue,
    DomainCommandKind, DomainError, ExternalInputRequest, ExternalInputs, GuestDirectMessagePolicy,
    HistoryPolicy, InformationQuery, MaskList, MessageCommand, MessageKind, MessageTarget,
    MessageText, ModeChange, ModeOperation, ModerationAction, ModerationReason,
    ModerationReasonCode, NicknameValue, PlanDecision, PresenceCommand, PresencePolicy,
    PresenceProjection, Principal, ProjectionDecision, RateBucket, ResolvedMessageTarget, Role,
    SanctionRequest, TopicProjection, TopicText, UserQuery, Visibility,
};
use agenc_ircd_testkit::{
    DomainTestIdentity, account_id, apply_command, apply_plan, bytes, channel_id, create_account,
    generation, message_admission, open_session, plan, registered_admission,
};
use agenc_ircd_types::{
    BoundedUtf8, ControlPolicy, EntryId, InviteId, MessageId, MonotonicTick, TypedMask, UserId,
    UtcSecond,
};

fn text(value: &str) -> Result<MessageText, DomainError> {
    BoundedUtf8::try_from_str(value, ControlPolicy::RejectAll).map_err(Into::into)
}

fn join_new(
    state: &mut agenc_ircd_domain::DomainState,
    identity: DomainTestIdentity,
    name: &str,
    seed: u8,
) -> Result<(), DomainError> {
    let admission = registered_admission(identity.user_id)?;
    apply_command(
        state,
        identity,
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse(name)?,
            false,
        )])?,
        &admission,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_710_000_000)),
            channel_ids: vec![channel_id(seed)],
            ..ExternalInputs::default()
        }),
    )?;
    Ok(())
}

fn join_existing(
    state: &mut agenc_ircd_domain::DomainState,
    identity: DomainTestIdentity,
    name: &str,
    now: Option<u64>,
) -> Result<(), DomainError> {
    let admission = registered_admission(identity.user_id)?;
    let external = now.map(|ticks| ExternalInputs {
        monotonic_now: Some(MonotonicTick::from_ticks(ticks)),
        ..ExternalInputs::default()
    });
    apply_command(
        state,
        identity,
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse(name)?,
            false,
        )])?,
        &admission,
        external,
    )?;
    Ok(())
}

fn apply_modes(
    state: &mut agenc_ircd_domain::DomainState,
    actor: DomainTestIdentity,
    name: &str,
    changes: Vec<ModeChange>,
    entry_ids: Vec<EntryId>,
) -> Result<(), DomainError> {
    let has_entries = !entry_ids.is_empty();
    let admission = registered_admission(actor.user_id)?;
    let external = has_entries.then_some(ExternalInputs {
        utc_now: Some(UtcSecond::from_unix_seconds(1_710_000_010)),
        entry_ids,
        ..ExternalInputs::default()
    });
    apply_command(
        state,
        actor,
        CanonicalCommand::mode(ChannelNameValue::parse(name)?, changes)?,
        &admission,
        external,
    )?;
    Ok(())
}

fn message(
    kind: MessageKind,
    targets: Vec<MessageTarget>,
    body: Option<&str>,
) -> Result<CanonicalCommand, DomainError> {
    let body = body.map(text).transpose()?;
    Ok(CanonicalCommand::message(MessageCommand::new(
        kind, targets, body,
    )?))
}

fn message_policy_error(
    state: &agenc_ircd_domain::DomainState,
    identity: DomainTestIdentity,
    command: CanonicalCommand,
    admission: &AdmissionSnapshot,
) -> Result<Option<DomainError>, DomainError> {
    match plan(state, identity, command, admission, None)? {
        PlanDecision::NeedsExternal(_) => Ok(None),
        PlanDecision::Rejected(rejected) => rejected
            .failures()
            .first()
            .map(|failure| Some(failure.error()))
            .ok_or(DomainError::InvariantViolation),
        PlanDecision::Mutation(_) | PlanDecision::Query(_) => Err(DomainError::InvariantViolation),
    }
}

#[test]
fn canonical_command_matrix_covers_bounds_scopes_and_kinds() -> Result<(), Box<dyn Error>> {
    let global = ChannelNameValue::parse("#global")?;
    let local = ChannelNameValue::parse("&local")?;
    let nick = NicknameValue::parse("Target")?;

    assert_eq!(
        CanonicalCommand::join(Vec::new()).err(),
        Some(DomainError::LimitExceeded)
    );
    assert_eq!(
        CanonicalCommand::part(Vec::new(), None).err(),
        Some(DomainError::LimitExceeded)
    );
    assert_eq!(
        CanonicalCommand::part(vec![global.clone(), global.clone()], None).err(),
        Some(DomainError::DuplicateTarget)
    );
    assert_eq!(
        CanonicalCommand::part(vec![global.clone(), local.clone()], None).err(),
        Some(DomainError::MixedAuthority)
    );
    assert_eq!(
        CanonicalCommand::mode(global.clone(), Vec::new()).err(),
        Some(DomainError::LimitExceeded)
    );
    assert_eq!(
        CanonicalCommand::kick(global.clone(), Vec::new(), None).err(),
        Some(DomainError::LimitExceeded)
    );
    assert_eq!(
        CanonicalCommand::kick(global.clone(), vec![nick.clone(), nick.clone()], None).err(),
        Some(DomainError::DuplicateTarget)
    );

    let mixed_message = MessageCommand::new(
        MessageKind::Notice,
        vec![
            MessageTarget::Channel(local),
            MessageTarget::User(nick.clone()),
        ],
        None,
    );
    assert_eq!(mixed_message.err(), Some(DomainError::MixedAuthority));
    assert_eq!(
        MessageCommand::new(MessageKind::Notice, Vec::new(), None).err(),
        Some(DomainError::LimitExceeded)
    );
    assert_eq!(
        MessageCommand::new(
            MessageKind::Tagmsg,
            vec![
                MessageTarget::User(nick.clone()),
                MessageTarget::User(NicknameValue::parse("Other")?),
            ],
            None,
        )
        .err(),
        Some(DomainError::LimitExceeded)
    );

    let duplicate_mask = TypedMask::parse("$n:target")?;
    let duplicate_mask_again = TypedMask::parse("$n:target")?;
    assert_eq!(
        CanonicalCommand::mode(
            global.clone(),
            vec![
                ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: duplicate_mask,
                },
                ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: duplicate_mask_again,
                },
            ],
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );
    assert_eq!(
        CanonicalCommand::mode(
            global.clone(),
            vec![ModeChange::Moderated(true), ModeChange::Moderated(false),],
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );

    let commands = vec![
        (
            CanonicalCommand::nick(nick.clone()),
            DomainCommandKind::Nick,
        ),
        (CanonicalCommand::quit(None), DomainCommandKind::Quit),
        (CanonicalCommand::part_all(), DomainCommandKind::Join),
        (
            CanonicalCommand::topic_query(global.clone()),
            DomainCommandKind::Topic,
        ),
        (
            CanonicalCommand::names(vec![global.clone()])?,
            DomainCommandKind::Names,
        ),
        (CanonicalCommand::list(Vec::new())?, DomainCommandKind::List),
        (
            CanonicalCommand::invite(nick.clone(), global.clone()),
            DomainCommandKind::Invite,
        ),
        (
            message(
                MessageKind::Privmsg,
                vec![MessageTarget::User(nick.clone())],
                Some("x"),
            )?,
            DomainCommandKind::Privmsg,
        ),
        (
            message(
                MessageKind::Notice,
                vec![MessageTarget::User(nick.clone())],
                None,
            )?,
            DomainCommandKind::Notice,
        ),
        (
            message(
                MessageKind::Tagmsg,
                vec![MessageTarget::User(nick.clone())],
                None,
            )?,
            DomainCommandKind::Tagmsg,
        ),
        (
            CanonicalCommand::information(InformationQuery::Motd),
            DomainCommandKind::Motd,
        ),
        (
            CanonicalCommand::information(InformationQuery::Lusers),
            DomainCommandKind::Lusers,
        ),
        (
            CanonicalCommand::information(InformationQuery::Version),
            DomainCommandKind::Version,
        ),
        (
            CanonicalCommand::information(InformationQuery::Time),
            DomainCommandKind::Time,
        ),
        (
            CanonicalCommand::information(InformationQuery::Admin),
            DomainCommandKind::Admin,
        ),
        (
            CanonicalCommand::information(InformationQuery::Info),
            DomainCommandKind::Info,
        ),
        (
            CanonicalCommand::information(InformationQuery::Links),
            DomainCommandKind::Links,
        ),
        (
            CanonicalCommand::user_query(UserQuery::Who(None))?,
            DomainCommandKind::Who,
        ),
        (
            CanonicalCommand::user_query(UserQuery::Whois(nick.clone()))?,
            DomainCommandKind::Whois,
        ),
        (
            CanonicalCommand::user_query(UserQuery::Whowas(nick.clone(), 1))?,
            DomainCommandKind::Whowas,
        ),
        (
            CanonicalCommand::user_query(UserQuery::Ison(vec![nick.clone()]))?,
            DomainCommandKind::Ison,
        ),
        (
            CanonicalCommand::user_query(UserQuery::Userhost(vec![nick.clone()]))?,
            DomainCommandKind::Userhost,
        ),
        (
            CanonicalCommand::presence(PresenceCommand::Away(None))?,
            DomainCommandKind::Away,
        ),
        (
            CanonicalCommand::presence(PresenceCommand::MonitorClear)?,
            DomainCommandKind::Monitor,
        ),
        (
            CanonicalCommand::setname(DisplayNameValue::prepare("Shown")?),
            DomainCommandKind::Setname,
        ),
        (
            CanonicalCommand::account(AccountCommand::Presence(PresencePolicy::Private)),
            DomainCommandKind::Acct,
        ),
        (
            CanonicalCommand::channel(ChannelCommand::History(channel_id(1), HistoryPolicy::Off)),
            DomainCommandKind::Chanctl,
        ),
        (
            CanonicalCommand::chathistory(channel_id(1), 1)?,
            DomainCommandKind::Chathistory,
        ),
    ];
    for (command, expected) in commands {
        assert_eq!(command.kind(), expected);
    }
    Ok(())
}

#[test]
fn account_direct_message_and_projection_matrix_is_recipient_scoped() -> Result<(), Box<dyn Error>>
{
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (alice_account, alice_generation) = create_account(&mut state, 1, 7)?;
    let (bob_account, bob_generation) = create_account(&mut state, 2, 8)?;
    let alice = open_session(
        &mut state,
        1,
        "MatrixAlice",
        Some((alice_account, alice_generation)),
    )?;
    let alice_phone = open_session(
        &mut state,
        5,
        "AlicePhone",
        Some((alice_account, alice_generation)),
    )?;
    let bob = open_session(
        &mut state,
        2,
        "MatrixBob",
        Some((bob_account, bob_generation)),
    )?;
    let guest = open_session(&mut state, 3, "MatrixGuest", None)?;
    let alice_admission = registered_admission(alice.user_id)?;
    let bob_admission = registered_admission(bob.user_id)?;

    for command in [
        AccountCommand::Label(Some(AccountLabelValue::parse("alice-public")?)),
        AccountCommand::Presence(PresencePolicy::Public),
        AccountCommand::GuestDirectMessages(GuestDirectMessagePolicy::Deny),
        AccountCommand::DirectMessages(DirectMessagePolicy::Contacts),
        AccountCommand::ContactAdd(bob_account),
        AccountCommand::NickReserve(NicknameValue::parse("ReservedAlice")?),
    ] {
        apply_command(
            &mut state,
            alice,
            CanonicalCommand::account(command),
            &alice_admission,
            None,
        )?;
    }
    apply_command(
        &mut state,
        bob,
        CanonicalCommand::account(AccountCommand::ContactAdd(alice_account)),
        &bob_admission,
        None,
    )?;

    let ProjectionDecision::Visible(account) = state.project_account(alice.user_id, alice_account)
    else {
        return Err("own account projection was hidden".into());
    };
    assert_eq!(account.account_id(), alice_account);
    assert_eq!(
        account.label().map(AccountLabelValue::as_str),
        Some("alice-public")
    );
    assert_eq!(account.presence(), PresencePolicy::Public);
    assert_eq!(
        account.guest_direct_messages(),
        GuestDirectMessagePolicy::Deny
    );
    assert_eq!(account.direct_messages(), DirectMessagePolicy::Contacts);
    assert!(matches!(
        state.project_account(guest.user_id, alice_account),
        ProjectionDecision::Hidden
    ));
    assert!(matches!(
        state.project_account(UserId::from_bytes([250; 16]), alice_account),
        ProjectionDecision::Hidden
    ));

    assert_eq!(
        state.project_presence(bob.user_id, alice.user_id),
        PresenceProjection::Present
    );
    let ProjectionDecision::Visible(projected) = state.project_session(bob.user_id, alice.user_id)
    else {
        return Err("mutual contact was hidden".into());
    };
    assert_eq!(projected.user_id(), alice.user_id);
    assert_eq!(projected.nickname().canonical(), "matrixalice");
    assert_eq!(projected.display_name().as_str(), "MatrixAlice");
    assert_eq!(
        projected.account_label().map(AccountLabelValue::as_str),
        Some("alice-public")
    );
    assert!(projected.away_text().is_none());
    assert!(
        projected.public_cloak()
            == state
                .session(alice.user_id)
                .ok_or("missing")?
                .public_cloak()
    );

    apply_command(
        &mut state,
        alice,
        CanonicalCommand::presence(PresenceCommand::Away(Some(BoundedUtf8::try_from_str(
            "away",
            ControlPolicy::RejectAll,
        )?)))?,
        &alice_admission,
        None,
    )?;
    apply_command(
        &mut state,
        alice,
        CanonicalCommand::setname(DisplayNameValue::prepare("Alice Display")?),
        &alice_admission,
        None,
    )?;
    let ProjectionDecision::Visible(projected) =
        state.project_session(alice_phone.user_id, alice.user_id)
    else {
        return Err("same-account contact was hidden".into());
    };
    assert_eq!(projected.away_text(), Some("away"));
    assert_eq!(projected.display_name().as_str(), "Alice Display");

    let bob_credit = message_admission(bob, &[])?;
    let direct_to_alice = || {
        message(
            MessageKind::Privmsg,
            vec![MessageTarget::User(NicknameValue::parse("MatrixAlice")?)],
            Some("hello"),
        )
    };
    assert_eq!(
        message_policy_error(&state, bob, direct_to_alice()?, &bob_credit)?,
        None
    );
    let guest_credit = message_admission(guest, &[])?;
    assert_eq!(
        message_policy_error(&state, guest, direct_to_alice()?, &guest_credit)?,
        Some(DomainError::Forbidden)
    );

    apply_command(
        &mut state,
        alice,
        CanonicalCommand::account(AccountCommand::ContactRemove(bob_account)),
        &alice_admission,
        None,
    )?;
    assert_eq!(
        message_policy_error(&state, bob, direct_to_alice()?, &bob_credit)?,
        Some(DomainError::Forbidden)
    );
    apply_command(
        &mut state,
        alice,
        CanonicalCommand::account(AccountCommand::DirectMessages(DirectMessagePolicy::Allow)),
        &alice_admission,
        None,
    )?;
    assert_eq!(
        message_policy_error(&state, bob, direct_to_alice()?, &bob_credit)?,
        None
    );
    apply_command(
        &mut state,
        alice,
        CanonicalCommand::account(AccountCommand::DirectMessages(DirectMessagePolicy::Deny)),
        &alice_admission,
        None,
    )?;
    assert_eq!(
        message_policy_error(
            &state,
            alice_phone,
            direct_to_alice()?,
            &message_admission(alice_phone, &[])?
        )?,
        None
    );

    apply_command(
        &mut state,
        alice,
        CanonicalCommand::account(AccountCommand::NickRelease(NicknameValue::parse(
            "ReservedAlice",
        )?)),
        &alice_admission,
        None,
    )?;
    apply_command(
        &mut state,
        alice,
        CanonicalCommand::account(AccountCommand::Label(None)),
        &alice_admission,
        None,
    )?;
    assert_eq!(
        state
            .account(alice_account)
            .ok_or("missing account")?
            .revision(),
        state.revision()
    );
    assert!(
        state
            .session(alice.user_id)
            .ok_or("missing session")?
            .revision()
            < state.revision()
    );
    state.validate()?;
    Ok(())
}

#[test]
fn invites_bans_exceptions_quiets_and_mode_roles_are_enforced() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 10, 3)?;
    let (operator_account, operator_generation) = create_account(&mut state, 11, 4)?;
    let owner = open_session(
        &mut state,
        10,
        "MatrixOwner",
        Some((owner_account, owner_generation)),
    )?;
    let operator = open_session(
        &mut state,
        11,
        "MatrixOperator",
        Some((operator_account, operator_generation)),
    )?;
    let operator_phone = open_session(
        &mut state,
        15,
        "OperatorPhone",
        Some((operator_account, operator_generation)),
    )?;
    let guest = open_session(&mut state, 12, "MatrixJoiner", None)?;
    let _outsider = open_session(&mut state, 13, "MatrixOutsider", None)?;
    let name = "#mode-matrix";
    let channel = channel_id(30);
    join_new(&mut state, owner, name, 30)?;
    join_existing(&mut state, operator, name, None)?;
    join_existing(&mut state, operator_phone, name, None)?;

    apply_modes(
        &mut state,
        owner,
        name,
        vec![ModeChange::Role {
            operation: ModeOperation::Add,
            target: NicknameValue::parse("MatrixOperator")?,
            role: Role::Operator,
        }],
        Vec::new(),
    )?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Register(channel)),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    assert_eq!(
        state
            .channel(channel)
            .ok_or("channel")?
            .role_of(operator_phone.user_id),
        Some(Role::Operator)
    );

    apply_modes(
        &mut state,
        operator,
        name,
        vec![
            ModeChange::InviteOnly(true),
            ModeChange::Moderated(true),
            ModeChange::MemberLimit(Some(10)),
        ],
        Vec::new(),
    )?;
    let denied_join = plan(
        &state,
        guest,
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse(name)?,
            false,
        )])?,
        &registered_admission(guest.user_id)?,
        Some(ExternalInputs {
            monotonic_now: Some(MonotonicTick::from_ticks(100)),
            ..ExternalInputs::default()
        }),
    );
    let PlanDecision::Rejected(denied_join) = denied_join? else {
        return Err("invite-only JOIN did not produce a target rejection".into());
    };
    assert_eq!(denied_join.failures().len(), 1);
    assert_eq!(
        denied_join
            .failures()
            .first()
            .ok_or("missing invite-only rejection")?
            .error(),
        DomainError::Forbidden
    );

    apply_command(
        &mut state,
        operator,
        CanonicalCommand::invite(
            NicknameValue::parse("MatrixJoiner")?,
            ChannelNameValue::parse(name)?,
        ),
        &registered_admission(operator.user_id)?,
        Some(ExternalInputs {
            monotonic_now: Some(MonotonicTick::from_ticks(200)),
            invite_ids: vec![InviteId::from_bytes(bytes(31))],
            ..ExternalInputs::default()
        }),
    )?;
    assert_eq!(
        state
            .channel(channel)
            .ok_or("channel")?
            .pending_invites()
            .count(),
        1
    );
    join_existing(&mut state, guest, name, Some(300))?;
    assert_eq!(
        state
            .channel(channel)
            .ok_or("channel")?
            .pending_invites()
            .count(),
        0
    );

    apply_command(
        &mut state,
        guest,
        CanonicalCommand::part(vec![ChannelNameValue::parse(name)?], None)?,
        &registered_admission(guest.user_id)?,
        None,
    )?;
    let user_mask = TypedMask::parse(&format!("$u:{}", guest.user_id.to_base64url()))?;
    apply_modes(
        &mut state,
        operator,
        name,
        vec![ModeChange::AddMask {
            list: MaskList::Ban,
            mask: user_mask,
        }],
        vec![EntryId::from_bytes(bytes(32))],
    )?;
    let banned = plan(
        &state,
        guest,
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse(name)?,
            false,
        )])?,
        &registered_admission(guest.user_id)?,
        Some(ExternalInputs {
            monotonic_now: Some(MonotonicTick::from_ticks(400)),
            ..ExternalInputs::default()
        }),
    );
    let PlanDecision::Rejected(banned) = banned? else {
        return Err("banned JOIN did not produce a target rejection".into());
    };
    assert_eq!(banned.failures().len(), 1);
    assert_eq!(
        banned
            .failures()
            .first()
            .ok_or("missing banned JOIN rejection")?
            .error(),
        DomainError::Forbidden
    );

    apply_modes(
        &mut state,
        operator,
        name,
        vec![ModeChange::AddMask {
            list: MaskList::Exception,
            mask: TypedMask::parse(&format!("$u:{}", guest.user_id.to_base64url()))?,
        }],
        vec![EntryId::from_bytes(bytes(33))],
    )?;
    apply_modes(
        &mut state,
        operator,
        name,
        vec![ModeChange::AddMask {
            list: MaskList::InviteException,
            mask: TypedMask::parse("$n:matrixjoiner")?,
        }],
        vec![EntryId::from_bytes(bytes(34))],
    )?;
    join_existing(&mut state, guest, name, Some(500))?;

    let quiet_id = EntryId::from_bytes(bytes(35));
    apply_modes(
        &mut state,
        owner,
        name,
        vec![ModeChange::AddMask {
            list: MaskList::Ban,
            mask: TypedMask::parse(&format!("$q:$a:{}", operator_account.to_text()))?,
        }],
        vec![quiet_id],
    )?;
    let channel_message = message(
        MessageKind::Privmsg,
        vec![MessageTarget::Channel(ChannelNameValue::parse(name)?)],
        Some("blocked"),
    )?;
    assert_eq!(
        message_policy_error(
            &state,
            operator,
            channel_message,
            &message_admission(operator, &[channel])?,
        )?,
        Some(DomainError::Forbidden)
    );
    assert_eq!(
        plan(
            &state,
            operator,
            CanonicalCommand::topic_set(
                ChannelNameValue::parse(name)?,
                TopicText::try_from_str("blocked topic", ControlPolicy::RejectAll)?,
            ),
            &registered_admission(operator.user_id)?,
            None,
        )
        .err(),
        Some(DomainError::Forbidden)
    );
    assert_eq!(
        plan(
            &state,
            operator,
            CanonicalCommand::invite(
                NicknameValue::parse("MatrixOutsider")?,
                ChannelNameValue::parse(name)?,
            ),
            &registered_admission(operator.user_id)?,
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(600)),
                invite_ids: vec![InviteId::from_bytes(bytes(36))],
                ..ExternalInputs::default()
            }),
        )
        .err(),
        Some(DomainError::Forbidden)
    );
    apply_modes(
        &mut state,
        owner,
        name,
        vec![ModeChange::RemoveMask {
            list: MaskList::Ban,
            entry_id: quiet_id,
        }],
        Vec::new(),
    )?;

    apply_modes(
        &mut state,
        operator,
        name,
        vec![ModeChange::Role {
            operation: ModeOperation::Remove,
            target: NicknameValue::parse("MatrixOperator")?,
            role: Role::Operator,
        }],
        Vec::new(),
    )?;
    assert_eq!(
        state
            .channel(channel)
            .ok_or("channel")?
            .role_of(operator_phone.user_id),
        Some(Role::HalfOperator)
    );
    assert_eq!(
        state.channel(channel).ok_or("channel")?.revision(),
        state.revision()
    );
    assert!(state.session(guest.user_id).ok_or("guest")?.revision() <= state.revision());
    state.validate()?;
    Ok(())
}

#[test]
fn topic_history_queries_sanctions_and_part_all_cover_closed_policies() -> Result<(), Box<dyn Error>>
{
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 40, 9)?;
    let owner = open_session(
        &mut state,
        40,
        "PolicyMatrix",
        Some((owner_account, owner_generation)),
    )?;
    let member = open_session(&mut state, 41, "PolicyMemberTwo", None)?;
    let outsider = open_session(&mut state, 42, "PolicyOutside", None)?;
    let name = ChannelNameValue::parse("#policy-matrix")?;
    let channel = channel_id(50);
    join_new(&mut state, owner, name.presentation(), 50)?;
    join_existing(&mut state, member, name.presentation(), None)?;

    assert_eq!(
        message_policy_error(
            &state,
            member,
            message(
                MessageKind::Privmsg,
                vec![MessageTarget::Channel(name.clone())],
                Some("allowed"),
            )?,
            &message_admission(member, &[channel])?,
        )?,
        None
    );
    assert_eq!(
        message_policy_error(
            &state,
            outsider,
            message(
                MessageKind::Privmsg,
                vec![MessageTarget::Channel(name.clone())],
                Some("outside"),
            )?,
            &message_admission(outsider, &[channel])?,
        )?,
        Some(DomainError::Forbidden)
    );
    assert_eq!(
        message_policy_error(
            &state,
            member,
            message(
                MessageKind::Tagmsg,
                vec![MessageTarget::Channel(name.clone())],
                None
            )?,
            &message_admission(member, &[channel])?,
        )?,
        Some(DomainError::PlaintextRoute)
    );

    apply_modes(
        &mut state,
        owner,
        name.presentation(),
        vec![ModeChange::TopicProtected(false)],
        Vec::new(),
    )?;
    apply_command(
        &mut state,
        member,
        CanonicalCommand::topic_set(
            name.clone(),
            TopicText::try_from_str("Visible topic", ControlPolicy::RejectAll)?,
        ),
        &registered_admission(member.user_id)?,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_710_000_100)),
            message_ids: vec![MessageId::from_bytes(bytes(51))],
            ..ExternalInputs::default()
        }),
    )?;
    let ProjectionDecision::Visible(view) = state.project_channel(outsider.user_id, channel)?
    else {
        return Err("listed channel hidden".into());
    };
    assert_eq!(view.channel_id(), channel);
    assert_eq!(view.name().canonical(), "#policy-matrix");
    assert_eq!(view.visibility(), Visibility::Listed);
    assert!(matches!(
        view.topic(),
        TopicProjection::Plaintext("Visible topic")
    ));
    assert_eq!(view.members().len(), 2);
    let first_member = view.members().first().ok_or("missing projected member")?;
    assert_eq!(first_member.role(), Role::Owner);
    assert!(!first_member.nickname().canonical().is_empty());
    assert!(!first_member.display_name().as_str().is_empty());
    assert_ne!(first_member.user_id(), outsider.user_id);

    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Register(channel)),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::History(
            channel,
            HistoryPolicy::TwentyFourHours,
        )),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    let query_credit = AdmissionSnapshot::new(vec![
        (RateBucket::RegisteredCommand(member.user_id), 20),
        (RateBucket::ExpensiveQuery(member.user_id), 20),
    ])?;
    let decision = plan(
        &state,
        member,
        CanonicalCommand::chathistory(channel, 100)?,
        &query_credit,
        None,
    )?;
    let PlanDecision::Query(query) = decision else {
        return Err("history was not a query".into());
    };
    assert_eq!(query.kind(), DomainCommandKind::Chathistory);
    assert_eq!(query.requester(), member.user_id);
    assert_eq!(query.expected_revision(), state.revision());
    assert_eq!(query.charges().len(), 2);
    assert!(matches!(
        query.command().view(),
        CanonicalCommandView::Chathistory(current, 100) if current == channel
    ));
    assert_eq!(
        plan(
            &state,
            outsider,
            CanonicalCommand::chathistory(channel, 1)?,
            &AdmissionSnapshot::new(vec![
                (RateBucket::RegisteredCommand(outsider.user_id), 20),
                (RateBucket::ExpensiveQuery(outsider.user_id), 20),
            ])?,
            None,
        )
        .err(),
        Some(DomainError::Forbidden)
    );

    let created = UtcSecond::from_unix_seconds(1_710_000_200);
    assert_eq!(
        state
            .plan_sanction(SanctionRequest {
                actor_user_id: member.user_id,
                target: Principal::Guest(outsider.user_id),
                channel_id: Some(channel),
                action: ModerationAction::Ban,
                reason_code: ModerationReasonCode::Spam,
                reason: None,
                created_at: created,
                expires_at: None,
            })
            .err(),
        Some(DomainError::Forbidden)
    );
    assert_eq!(
        state
            .plan_sanction(SanctionRequest {
                actor_user_id: owner.user_id,
                target: Principal::Guest(outsider.user_id),
                channel_id: None,
                action: ModerationAction::Suspend,
                reason_code: ModerationReasonCode::Security,
                reason: None,
                created_at: created,
                expires_at: None,
            })
            .err(),
        Some(DomainError::Forbidden)
    );
    assert_eq!(
        state
            .plan_sanction(SanctionRequest {
                actor_user_id: owner.user_id,
                target: Principal::Guest(outsider.user_id),
                channel_id: Some(channel),
                action: ModerationAction::Mute,
                reason_code: ModerationReasonCode::Harassment,
                reason: None,
                created_at: created,
                expires_at: Some(created),
            })
            .err(),
        Some(DomainError::InvalidArgument)
    );
    let sanction = state.plan_sanction(SanctionRequest {
        actor_user_id: owner.user_id,
        target: Principal::Guest(outsider.user_id),
        channel_id: Some(channel),
        action: ModerationAction::Mute,
        reason_code: ModerationReasonCode::Harassment,
        reason: Some(ModerationReason::try_from_str(
            "bounded reason",
            ControlPolicy::RejectAll,
        )?),
        created_at: created,
        expires_at: Some(UtcSecond::from_unix_seconds(created.get() + 60)),
    })?;
    apply_plan(&mut state, sanction)?;
    let stored = state.sanctions().next().ok_or("sanction")?;
    assert_eq!(stored.actor(), Principal::Account(owner_account));
    assert_eq!(stored.target(), Principal::Guest(outsider.user_id));
    assert_eq!(stored.channel_id(), Some(channel));
    assert_eq!(stored.action(), ModerationAction::Mute);
    assert_eq!(stored.reason_code(), ModerationReasonCode::Harassment);
    assert_eq!(
        stored.reason().map(BoundedUtf8::as_str),
        Some("bounded reason")
    );
    assert_eq!(stored.created_at(), created);
    assert!(stored.expires_at().is_some());
    assert_eq!(stored.revision(), state.revision());

    apply_command(
        &mut state,
        member,
        CanonicalCommand::part_all(),
        &registered_admission(member.user_id)?,
        None,
    )?;
    assert!(
        !state
            .session(member.user_id)
            .ok_or("member")?
            .is_joined(channel)
    );
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::History(channel, HistoryPolicy::Off)),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Unregister(channel)),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    state.validate()?;
    Ok(())
}

#[test]
fn lifecycle_rejections_preserve_state_and_checked_fences() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let missing_account = account_id(90);
    let bad_seed = agenc_ircd_domain::SessionSeed {
        session_id: agenc_ircd_types::SessionId::from_bytes(bytes(90)),
        user_id: UserId::from_bytes(bytes(91)),
        home_server_id: agenc_ircd_types::ServerId::from_bytes(bytes(92)),
        account_id: Some(missing_account),
        account_session_generation: generation(1)?,
        generation: generation(1)?,
        nickname: NicknameValue::parse("MissingAccount")?,
        display_name: DisplayNameValue::prepare("Missing Account")?,
        public_cloak: agenc_ircd_types::PublicCloak::parse("aaaaaaaaaa", "bbbbbbbbbbbbbbbb")?,
        connection_nonce: [1; 32],
        negotiated_capability_hash: [2; 32],
        created_at_utc: UtcSecond::from_unix_seconds(1),
        revision: state.revision(),
    };
    assert_eq!(
        state.plan_session_opened(bad_seed).err(),
        Some(DomainError::NotFound)
    );

    let (account, account_generation) = create_account(&mut state, 91, 2)?;
    let session = open_session(
        &mut state,
        91,
        "FenceMatrix",
        Some((account, account_generation)),
    )?;
    assert_eq!(
        state
            .plan_account_created(agenc_ircd_domain::AccountState::new(
                account,
                account_generation,
                state.revision(),
            ))
            .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        state
            .plan_session_account_switch(
                session.user_id,
                session.generation,
                Some((account, generation(99)?))
            )
            .err(),
        Some(DomainError::StaleGeneration)
    );
    let switched = state.plan_session_account_switch(session.user_id, session.generation, None)?;
    apply_plan(&mut state, switched)?;
    assert_eq!(
        state
            .session(session.user_id)
            .ok_or("session")?
            .account_id(),
        None
    );
    assert_eq!(
        state
            .session(session.user_id)
            .ok_or("session")?
            .account_session_generation(),
        generation(0)?
    );
    assert_eq!(state.account_count(), 1);
    assert_eq!(state.session_count(), 1);
    assert_eq!(state.channel_count(), 0);
    assert_eq!(state.sanction_count(), 0);
    assert_eq!(
        state.resolve_channel(&ChannelNameValue::parse("#absent")?),
        None
    );
    assert_eq!(
        state.resolve_nickname(&NicknameValue::parse("FenceMatrix")?),
        Some(session.user_id)
    );
    assert!(state.channel(channel_id(99)).is_none());
    assert!(state.account(missing_account).is_none());
    state.validate()?;
    Ok(())
}

#[test]
fn successful_target_subsets_commit_with_complete_canonical_failures() -> Result<(), Box<dyn Error>>
{
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 100, 1)?;
    let owner = open_session(
        &mut state,
        100,
        "SubsetOwner",
        Some((owner_account, owner_generation)),
    )?;
    let sender = open_session(&mut state, 101, "SubsetSender", None)?;
    let joiner = open_session(&mut state, 102, "SubsetJoiner", None)?;
    join_new(&mut state, owner, "#subset-one", 100)?;
    join_new(&mut state, owner, "#subset-two", 101)?;
    join_new(&mut state, owner, "#subset-secret", 102)?;
    join_existing(&mut state, sender, "#subset-one", None)?;
    apply_modes(
        &mut state,
        owner,
        "#subset-secret",
        vec![ModeChange::Visibility(Visibility::Secret)],
        Vec::new(),
    )?;

    let one = ChannelNameValue::parse("#subset-one")?;
    let two = ChannelNameValue::parse("#subset-two")?;
    let message_plan = plan(
        &state,
        sender,
        message(
            MessageKind::Privmsg,
            vec![
                MessageTarget::Channel(one.clone()),
                MessageTarget::Channel(two),
            ],
            Some("accepted subset"),
        )?,
        &message_admission(sender, &[channel_id(100), channel_id(101)])?,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_710_000_100)),
            message_ids: vec![MessageId::from_bytes(bytes(103))],
            ..ExternalInputs::default()
        }),
    )?;
    let PlanDecision::Mutation(message_plan) = message_plan else {
        return Err("message subset did not produce a mutation".into());
    };
    assert_eq!(message_plan.events().len(), 1);
    assert_eq!(message_plan.failures().len(), 1);
    let batch = message_plan
        .message_batch()
        .ok_or("message plan lost its delivery batch")?;
    assert_eq!(batch.kind(), MessageKind::Privmsg);
    assert_eq!(batch.sender(), sender.user_id);
    assert_eq!(batch.body(), Some("accepted subset"));
    assert_eq!(
        batch.accepted_at(),
        UtcSecond::from_unix_seconds(1_710_000_100)
    );
    assert_eq!(batch.routes().len(), 1);
    let route = batch.routes().first().ok_or("missing accepted route")?;
    assert_eq!(route.message_id(), MessageId::from_bytes(bytes(103)));
    assert_eq!(route.recipients().len(), 2);
    let message_failure = message_plan
        .failures()
        .first()
        .ok_or("missing message target failure")?;
    assert_eq!(message_failure.target_index(), 1);
    assert_eq!(message_failure.error(), DomainError::Forbidden);
    assert_eq!(
        message_failure
            .target()
            .channel()
            .ok_or("missing channel failure")?
            .canonical(),
        "#subset-two"
    );
    let message_receipt = apply_plan(&mut state, message_plan)?;
    assert_eq!(message_receipt.failures().len(), 1);

    let part_plan = plan(
        &state,
        sender,
        CanonicalCommand::part(vec![one, ChannelNameValue::parse("#subset-absent")?], None)?,
        &registered_admission(sender.user_id)?,
        None,
    )?;
    let PlanDecision::Mutation(part_plan) = part_plan else {
        return Err("PART subset did not produce a mutation".into());
    };
    assert_eq!(part_plan.failures().len(), 1);
    let part_failure = part_plan
        .failures()
        .first()
        .ok_or("missing PART target failure")?;
    assert_eq!(part_failure.target_index(), 0);
    assert_eq!(part_failure.error(), DomainError::NotFound);
    apply_plan(&mut state, part_plan)?;
    assert!(
        !state
            .session(sender.user_id)
            .ok_or("sender disappeared")?
            .is_joined(channel_id(100))
    );

    let join_plan = plan(
        &state,
        joiner,
        CanonicalCommand::join(vec![
            ChannelTarget::new(ChannelNameValue::parse("#subset-new")?, false),
            ChannelTarget::new(ChannelNameValue::parse("#subset-secret")?, false),
        ])?,
        &registered_admission(joiner.user_id)?,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_710_000_101)),
            channel_ids: vec![channel_id(104)],
            ..ExternalInputs::default()
        }),
    )?;
    let PlanDecision::Mutation(join_plan) = join_plan else {
        return Err("JOIN subset did not produce a mutation".into());
    };
    assert_eq!(join_plan.failures().len(), 1);
    let join_failure = join_plan
        .failures()
        .first()
        .ok_or("missing JOIN target failure")?;
    assert_eq!(join_failure.target_index(), 1);
    assert_eq!(join_failure.error(), DomainError::SecretUnavailable);
    apply_plan(&mut state, join_plan)?;
    assert!(
        state
            .session(joiner.user_id)
            .ok_or("joiner disappeared")?
            .is_joined(channel_id(104))
    );
    state.validate()?;
    Ok(())
}

#[test]
fn channel_key_mode_distinguishes_real_and_dummy_verification_without_raw_secrets()
-> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 110, 1)?;
    let owner = open_session(
        &mut state,
        110,
        "KeyOwner",
        Some((owner_account, owner_generation)),
    )?;
    let keyed_joiner = open_session(&mut state, 111, "KeyJoiner", None)?;
    let dummy_joiner = open_session(&mut state, 112, "DummyJoiner", None)?;
    join_new(&mut state, owner, "#keyed", 110)?;
    join_new(&mut state, owner, "#unkeyed", 111)?;
    apply_modes(
        &mut state,
        owner,
        "#keyed",
        vec![ModeChange::JoinKey(true)],
        Vec::new(),
    )?;
    assert!(
        state
            .channel(channel_id(110))
            .ok_or("keyed channel missing")?
            .modes()
            .join_key
    );

    let no_key = plan(
        &state,
        keyed_joiner,
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse("#keyed")?,
            false,
        )])?,
        &registered_admission(keyed_joiner.user_id)?,
        None,
    )?;
    let PlanDecision::Rejected(no_key) = no_key else {
        return Err("missing channel key was not rejected".into());
    };
    assert_eq!(
        no_key
            .failures()
            .first()
            .ok_or("missing no-key rejection")?
            .error(),
        DomainError::SecretUnavailable
    );

    let keyed_command = || {
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse("#keyed")?,
            true,
        )])
    };
    let needs_verification = plan(
        &state,
        keyed_joiner,
        keyed_command()?,
        &AdmissionSnapshot::new(vec![
            (RateBucket::RegisteredCommand(keyed_joiner.user_id), 10),
            (
                RateBucket::ChannelKeyAttempt(Principal::Guest(keyed_joiner.user_id)),
                10,
            ),
        ])?,
        None,
    )?;
    let PlanDecision::NeedsExternal(requests) = needs_verification else {
        return Err("supplied key did not request external verification".into());
    };
    assert_eq!(requests.len(), 1);
    let request = requests.first().ok_or("missing key verification request")?;
    assert!(matches!(
        request,
        ExternalInputRequest::ChannelKeyVerification {
            target_index: 0,
            ..
        }
    ));

    let key_admission = AdmissionSnapshot::new(vec![
        (RateBucket::RegisteredCommand(keyed_joiner.user_id), 10),
        (
            RateBucket::ChannelKeyAttempt(Principal::Guest(keyed_joiner.user_id)),
            10,
        ),
    ])?;
    let wrong_key = plan(
        &state,
        keyed_joiner,
        keyed_command()?,
        &key_admission,
        Some(ExternalInputs {
            key_verdicts: vec![false],
            ..ExternalInputs::default()
        }),
    )?;
    let PlanDecision::Rejected(wrong_key) = wrong_key else {
        return Err("wrong real key did not produce a target rejection".into());
    };
    assert_eq!(
        wrong_key
            .failures()
            .first()
            .ok_or("missing wrong-key rejection")?
            .error(),
        DomainError::SecretUnavailable
    );
    apply_command(
        &mut state,
        keyed_joiner,
        keyed_command()?,
        &key_admission,
        Some(ExternalInputs {
            key_verdicts: vec![true],
            ..ExternalInputs::default()
        }),
    )?;

    let dummy_admission = AdmissionSnapshot::new(vec![
        (RateBucket::RegisteredCommand(dummy_joiner.user_id), 10),
        (
            RateBucket::ChannelKeyAttempt(Principal::Guest(dummy_joiner.user_id)),
            10,
        ),
    ])?;
    apply_command(
        &mut state,
        dummy_joiner,
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse("#unkeyed")?,
            true,
        )])?,
        &dummy_admission,
        Some(ExternalInputs {
            key_verdicts: vec![false],
            ..ExternalInputs::default()
        }),
    )?;
    assert!(
        state
            .session(dummy_joiner.user_id)
            .ok_or("dummy joiner disappeared")?
            .is_joined(channel_id(111))
    );
    state.validate()?;
    Ok(())
}

#[test]
fn user_notice_and_monitor_mutations_enforce_the_total_limit() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let user = open_session(&mut state, 120, "MonitorOwner", None)?;
    let admission = registered_admission(user.user_id)?;
    let nickname = NicknameValue::parse("MonitorOwner")?;

    apply_command(
        &mut state,
        user,
        CanonicalCommand::user_operator_notices(nickname.clone(), true),
        &admission,
        None,
    )?;
    assert!(
        state
            .session(user.user_id)
            .ok_or("monitor session is missing")?
            .operator_notices()
    );
    assert_eq!(
        plan(
            &state,
            user,
            CanonicalCommand::user_operator_notices(NicknameValue::parse("SomeoneElse")?, true),
            &admission,
            None,
        )
        .err(),
        Some(DomainError::Forbidden)
    );

    for batch in 0..5 {
        let targets = (0..20)
            .map(|offset| NicknameValue::parse(&format!("watch{}", batch * 20 + offset)))
            .collect::<Result<Vec<_>, _>>()?;
        apply_command(
            &mut state,
            user,
            CanonicalCommand::presence(PresenceCommand::MonitorAdd(targets))?,
            &admission,
            None,
        )?;
    }
    assert_eq!(
        state
            .session(user.user_id)
            .ok_or("monitor session is missing")?
            .monitored_nicknames()
            .count(),
        100
    );
    assert_eq!(
        apply_command(
            &mut state,
            user,
            CanonicalCommand::presence(PresenceCommand::MonitorAdd(vec![NicknameValue::parse(
                "watch100"
            )?,]))?,
            &admission,
            None,
        )
        .err(),
        Some(DomainError::LimitExceeded)
    );
    apply_command(
        &mut state,
        user,
        CanonicalCommand::presence(PresenceCommand::MonitorRemove(vec![
            NicknameValue::parse("watch0")?,
            NicknameValue::parse("watch1")?,
        ]))?,
        &admission,
        None,
    )?;
    assert_eq!(
        state
            .session(user.user_id)
            .ok_or("monitor session is missing")?
            .monitored_nicknames()
            .count(),
        98
    );
    apply_command(
        &mut state,
        user,
        CanonicalCommand::presence(PresenceCommand::MonitorClear)?,
        &admission,
        None,
    )?;
    apply_command(
        &mut state,
        user,
        CanonicalCommand::user_operator_notices(nickname, false),
        &admission,
        None,
    )?;
    let session = state
        .session(user.user_id)
        .ok_or("monitor session is missing")?;
    assert_eq!(session.monitored_nicknames().count(), 0);
    assert!(!session.operator_notices());
    state.validate()?;
    Ok(())
}

#[test]
fn authority_changes_remove_only_invites_for_the_stale_principal() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 121, 1)?;
    let owner = open_session(
        &mut state,
        121,
        "InviteOwner",
        Some((owner_account, owner_generation)),
    )?;
    let (target_account, target_generation) = create_account(&mut state, 122, 1)?;
    let target = open_session(
        &mut state,
        122,
        "AccountInvitee",
        Some((target_account, target_generation)),
    )?;
    let guest = open_session(&mut state, 123, "GuestInvitee", None)?;
    let (switch_account, switch_generation) = create_account(&mut state, 124, 1)?;
    join_new(&mut state, owner, "#invite-cleanup", 121)?;
    let channel = channel_id(121);
    let channel_name = ChannelNameValue::parse("#invite-cleanup")?;
    let admission = registered_admission(owner.user_id)?;

    for (nickname, seed) in [("AccountInvitee", 122), ("GuestInvitee", 123)] {
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::invite(NicknameValue::parse(nickname)?, channel_name.clone()),
            &admission,
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(1_000)),
                invite_ids: vec![InviteId::from_bytes(bytes(seed))],
                ..ExternalInputs::default()
            }),
        )?;
    }
    assert_eq!(
        state
            .channel(channel)
            .ok_or("invite channel is missing")?
            .pending_invites()
            .count(),
        2
    );

    let switch = state.plan_session_account_switch(
        guest.user_id,
        guest.generation,
        Some((switch_account, switch_generation)),
    )?;
    apply_plan(&mut state, switch)?;
    assert_eq!(
        state
            .channel(channel)
            .ok_or("invite channel is missing")?
            .pending_invites()
            .count(),
        1
    );

    let deletion = state.plan_account_deleted(target_account, target_generation)?;
    apply_plan(&mut state, deletion)?;
    assert!(state.session(target.user_id).is_none());
    assert_eq!(
        state
            .channel(channel)
            .ok_or("invite channel is missing")?
            .pending_invites()
            .count(),
        0
    );
    state.validate()?;
    Ok(())
}

#[test]
fn kick_subsets_and_message_routes_use_immutable_identity_order() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 125, 1)?;
    let owner = open_session(
        &mut state,
        125,
        "KickOwner",
        Some((owner_account, owner_generation)),
    )?;
    let zulu = open_session(&mut state, 126, "ZuluTarget", None)?;
    let alpha = open_session(&mut state, 127, "AlphaTarget", None)?;
    join_new(&mut state, owner, "#kick-order", 125)?;
    join_existing(&mut state, zulu, "#kick-order", None)?;
    join_existing(&mut state, alpha, "#kick-order", None)?;
    let kick_channel = channel_id(125);

    let kick = plan(
        &state,
        owner,
        CanonicalCommand::kick(
            ChannelNameValue::parse("#kick-order")?,
            vec![
                NicknameValue::parse("ZuluTarget")?,
                NicknameValue::parse("MissingTarget")?,
                NicknameValue::parse("AlphaTarget")?,
                NicknameValue::parse("KickOwner")?,
            ],
            None,
        )?,
        &registered_admission(owner.user_id)?,
        None,
    )?;
    let PlanDecision::Mutation(kick) = kick else {
        return Err("KICK subset did not produce a mutation".into());
    };
    assert_eq!(
        kick.events(),
        &[
            agenc_ircd_domain::DomainEvent::Parted(kick_channel, zulu.user_id),
            agenc_ircd_domain::DomainEvent::Parted(kick_channel, alpha.user_id),
        ]
    );
    assert_eq!(kick.failures().len(), 2);
    let first_failure = kick
        .failures()
        .first()
        .ok_or("first KICK failure is missing")?;
    let second_failure = kick
        .failures()
        .get(1)
        .ok_or("second KICK failure is missing")?;
    assert_eq!(first_failure.target_index(), 1);
    assert_eq!(first_failure.error(), DomainError::Forbidden);
    assert_eq!(second_failure.target_index(), 2);
    assert_eq!(second_failure.error(), DomainError::NotFound);
    apply_plan(&mut state, kick)?;

    join_new(&mut state, owner, "#alpha-route", 210)?;
    join_new(&mut state, owner, "#zulu-route", 200)?;
    let message = plan(
        &state,
        owner,
        message(
            MessageKind::Privmsg,
            vec![
                MessageTarget::Channel(ChannelNameValue::parse("#alpha-route")?),
                MessageTarget::Channel(ChannelNameValue::parse("#zulu-route")?),
            ],
            Some("immutable order"),
        )?,
        &message_admission(owner, &[channel_id(210), channel_id(200)])?,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_710_000_200)),
            message_ids: vec![
                MessageId::from_bytes(bytes(201)),
                MessageId::from_bytes(bytes(202)),
            ],
            ..ExternalInputs::default()
        }),
    )?;
    let PlanDecision::Mutation(message) = message else {
        return Err("message ordering did not produce a mutation".into());
    };
    let routes = message
        .message_batch()
        .ok_or("message batch is missing")?
        .routes();
    assert_eq!(routes.len(), 2);
    let first_route = routes.first().ok_or("first message route is missing")?;
    let second_route = routes.get(1).ok_or("second message route is missing")?;
    assert_eq!(
        first_route.target(),
        ResolvedMessageTarget::Channel(channel_id(200))
    );
    assert_eq!(first_route.message_id(), MessageId::from_bytes(bytes(201)));
    assert_eq!(
        second_route.target(),
        ResolvedMessageTarget::Channel(channel_id(210))
    );
    assert_eq!(second_route.message_id(), MessageId::from_bytes(bytes(202)));
    apply_plan(&mut state, message)?;
    state.validate()?;
    Ok(())
}

#[test]
fn secret_channel_lookups_match_missing_channel_errors() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 128, 1)?;
    let owner = open_session(
        &mut state,
        128,
        "SecretOwner",
        Some((owner_account, owner_generation)),
    )?;
    let outsider = open_session(&mut state, 129, "SecretOutsider", None)?;
    join_new(&mut state, owner, "#hidden-parity", 128)?;
    apply_modes(
        &mut state,
        owner,
        "#hidden-parity",
        vec![ModeChange::Visibility(Visibility::Secret)],
        Vec::new(),
    )?;
    let admission = AdmissionSnapshot::new(vec![
        (RateBucket::RegisteredCommand(outsider.user_id), 10),
        (RateBucket::ExpensiveQuery(outsider.user_id), 10),
    ])?;

    for channel in ["#hidden-parity", "#missing-parity"] {
        let channel = ChannelNameValue::parse(channel)?;
        for command in [
            CanonicalCommand::channel_mode_query(channel.clone()),
            CanonicalCommand::topic_query(channel.clone()),
            CanonicalCommand::names(vec![channel.clone()])?,
            CanonicalCommand::invite(NicknameValue::parse("SecretOwner")?, channel.clone()),
            CanonicalCommand::kick(
                channel.clone(),
                vec![NicknameValue::parse("SecretOwner")?],
                None,
            )?,
        ] {
            assert_eq!(
                plan(&state, outsider, command, &admission, None).err(),
                Some(DomainError::SecretUnavailable)
            );
        }
        assert_eq!(
            message_policy_error(
                &state,
                outsider,
                message(
                    MessageKind::Privmsg,
                    vec![MessageTarget::Channel(channel)],
                    Some("hidden"),
                )?,
                &message_admission(outsider, &[channel_id(128)])?,
            )?,
            Some(DomainError::SecretUnavailable)
        );
    }
    state.validate()?;
    Ok(())
}
