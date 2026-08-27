#![forbid(unsafe_code)]

//! Stage-03 channel, projection, history, E2EE-boundary, and moderation tests.

use std::error::Error;

use agenc_ircd_domain::{
    CanonicalCommand, ChannelCommand, ChannelNameValue, ChannelTarget, ContentPolicy, DomainError,
    ExternalInputRequest, ExternalInputs, HistoryPolicy, MaskList, MessageCommand, MessageKind,
    MessageTarget, MessageText, ModeChange, ModeOperation, ModerationAction, ModerationReasonCode,
    PlanDecision, PresenceProjection, ProjectionDecision, Role, SanctionRequest, StorageClass,
    TopicProjection, Visibility,
};
use agenc_ircd_testkit::{
    DomainTestIdentity, apply_command, apply_plan, channel_id, create_account, message_admission,
    open_session, plan, registered_admission,
};
use agenc_ircd_types::{ControlPolicy, MessageId, UserId, UtcSecond};

fn join_new(
    state: &mut agenc_ircd_domain::DomainState,
    identity: DomainTestIdentity,
    name: &str,
    id_seed: u8,
) -> Result<(), DomainError> {
    let admission = registered_admission(identity.user_id)?;
    let make_command = || {
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse(name)?,
            false,
        )])
    };
    let decision = plan(state, identity, make_command()?, &admission, None)?;
    let PlanDecision::NeedsExternal(requests) = decision else {
        return Err(DomainError::BadState);
    };
    if requests.len() != 2
        || requests.first()
            != Some(&ExternalInputRequest::UtcNow {
                request_sequence: 0,
            })
        || requests.get(1).map(|request| request.request_sequence()) != Some(1)
    {
        return Err(DomainError::ExternalInputMismatch);
    }
    apply_command(
        state,
        identity,
        make_command()?,
        &admission,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_700_100_000)),
            channel_ids: vec![channel_id(id_seed)],
            ..ExternalInputs::default()
        }),
    )?;
    Ok(())
}

fn join_existing(
    state: &mut agenc_ircd_domain::DomainState,
    identity: DomainTestIdentity,
    name: &str,
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
        None,
    )?;
    Ok(())
}

#[test]
fn channel_recreation_roles_and_secret_projection_obey_current_instance()
-> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_account_generation) = create_account(&mut state, 10, 3)?;
    let owner = open_session(
        &mut state,
        10,
        "ChannelOwner",
        Some((owner_account, owner_account_generation)),
    )?;
    let member = open_session(&mut state, 11, "ChannelMember", None)?;
    let outsider = open_session(&mut state, 12, "ChannelOutsider", None)?;
    let name = ChannelNameValue::parse("#stage-three")?;
    let first_id = channel_id(20);

    join_new(&mut state, owner, name.presentation(), 20)?;
    join_existing(&mut state, member, name.presentation())?;
    assert_eq!(
        state
            .channel(first_id)
            .ok_or("channel is missing")?
            .role_of(owner.user_id),
        Some(Role::Owner)
    );

    let owner_admission = registered_admission(owner.user_id)?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::mode(
            name.clone(),
            vec![ModeChange::Role {
                operation: ModeOperation::Add,
                target: agenc_ircd_domain::NicknameValue::parse("ChannelMember")?,
                role: Role::HalfOperator,
            }],
        )?,
        &owner_admission,
        None,
    )?;
    let member_admission = registered_admission(member.user_id)?;
    apply_command(
        &mut state,
        member,
        CanonicalCommand::mode(name.clone(), vec![ModeChange::TopicProtected(false)])?,
        &member_admission,
        None,
    )?;
    assert!(
        !state
            .channel(first_id)
            .ok_or("channel is missing")?
            .modes()
            .topic_protected
    );

    apply_command(
        &mut state,
        owner,
        CanonicalCommand::mode(
            name.clone(),
            vec![ModeChange::Visibility(Visibility::Secret)],
        )?,
        &owner_admission,
        None,
    )?;
    assert!(matches!(
        state.project_channel(outsider.user_id, first_id)?,
        ProjectionDecision::Hidden
    ));
    assert!(matches!(
        state.project_channel(outsider.user_id, channel_id(99))?,
        ProjectionDecision::Hidden
    ));
    assert!(state.project_channel_list()?.is_empty());
    assert!(matches!(
        state.project_session(outsider.user_id, owner.user_id),
        ProjectionDecision::Hidden
    ));
    assert_eq!(
        state.project_presence(outsider.user_id, owner.user_id),
        PresenceProjection::Absent
    );
    assert_eq!(
        state.project_presence(outsider.user_id, UserId::from_bytes([255; 16])),
        PresenceProjection::Absent
    );
    let ProjectionDecision::Visible(channel) = state.project_channel(member.user_id, first_id)?
    else {
        return Err("member could not project the secret channel".into());
    };
    assert_eq!(channel.members().len(), 2);

    apply_command(
        &mut state,
        member,
        CanonicalCommand::part(vec![name.clone()], None)?,
        &member_admission,
        None,
    )?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::part(vec![name.clone()], None)?,
        &owner_admission,
        None,
    )?;
    assert!(state.channel(first_id).is_none());
    assert!(state.resolve_channel(&name).is_none());

    join_new(&mut state, owner, name.presentation(), 21)?;
    assert_eq!(state.resolve_channel(&name), Some(channel_id(21)));
    assert!(state.channel(first_id).is_none());
    state.validate()?;
    Ok(())
}

#[test]
fn registered_history_and_e2ee_policy_are_mutually_constrained() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_account_generation) = create_account(&mut state, 30, 4)?;
    let owner = open_session(
        &mut state,
        30,
        "PolicyOwner",
        Some((owner_account, owner_account_generation)),
    )?;
    let member = open_session(&mut state, 31, "PolicyMember", None)?;
    let name = ChannelNameValue::parse("#policy")?;
    let instance = channel_id(40);
    join_new(&mut state, owner, name.presentation(), 40)?;
    join_existing(&mut state, member, name.presentation())?;
    let owner_admission = registered_admission(owner.user_id)?;

    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Register(instance)),
        &owner_admission,
        None,
    )?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::History(instance, HistoryPolicy::OneHour)),
        &owner_admission,
        None,
    )?;
    let channel = state
        .channel(instance)
        .ok_or("registered channel is missing")?;
    assert_eq!(channel.history_policy(), HistoryPolicy::OneHour);
    assert_eq!(
        channel.persistence_policy(),
        agenc_ircd_domain::PersistencePolicy::Registered
    );

    let rejected = plan(
        &state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Content(instance, ContentPolicy::E2eeBound)),
        &owner_admission,
        None,
    );
    assert_eq!(rejected.err(), Some(DomainError::BadState));

    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::History(instance, HistoryPolicy::Off)),
        &owner_admission,
        None,
    )?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Content(instance, ContentPolicy::E2eeBound)),
        &owner_admission,
        None,
    )?;
    let channel = state.channel(instance).ok_or("E2EE channel is missing")?;
    assert_eq!(channel.content_policy(), ContentPolicy::E2eeBound);
    assert!(matches!(
        state.project_channel_list()?.first().map(|row| row.topic()),
        Some(TopicProjection::EncryptedPlaceholder)
    ));

    let body = MessageText::try_from_str("opaque route refusal", ControlPolicy::RejectAll)?;
    let message_admission = message_admission(owner, &[instance])?;
    let rejected = plan(
        &state,
        owner,
        CanonicalCommand::message(MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::Channel(name.clone())],
            Some(body),
        )?),
        &message_admission,
        None,
    )?;
    let PlanDecision::Rejected(rejected) = rejected else {
        return Err("plaintext on an E2EE route did not produce a target rejection".into());
    };
    assert_eq!(rejected.failures().len(), 1);
    assert_eq!(
        rejected
            .failures()
            .first()
            .ok_or("missing E2EE rejection")?
            .error(),
        DomainError::EncryptedRoute
    );

    apply_command(
        &mut state,
        owner,
        CanonicalCommand::message(MessageCommand::new(
            MessageKind::Tagmsg,
            vec![MessageTarget::Channel(name.clone())],
            None,
        )?),
        &message_admission,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_700_200_000)),
            message_ids: vec![MessageId::from_bytes([41; 16])],
            ..ExternalInputs::default()
        }),
    )?;

    apply_command(
        &mut state,
        owner,
        CanonicalCommand::kick(
            name,
            vec![agenc_ircd_domain::NicknameValue::parse("PolicyMember")?],
            None,
        )?,
        &owner_admission,
        None,
    )?;
    assert!(
        state
            .channel(instance)
            .ok_or("E2EE channel is missing")?
            .e2ee_removal_is_pending(member.user_id)
    );

    let sanction = state.plan_sanction(SanctionRequest {
        actor_user_id: owner.user_id,
        target: agenc_ircd_domain::Principal::Guest(member.user_id),
        channel_id: Some(instance),
        action: ModerationAction::Ban,
        reason_code: ModerationReasonCode::ChannelPolicy,
        reason: None,
        created_at: UtcSecond::from_unix_seconds(1_700_200_001),
        expires_at: None,
    })?;
    assert_eq!(sanction.storage_class(), StorageClass::Durable);
    apply_plan(&mut state, sanction)?;
    assert_eq!(state.sanction_count(), 1);
    assert_eq!(
        state
            .sanctions()
            .next()
            .ok_or("sanction is missing")?
            .reason_code(),
        ModerationReasonCode::ChannelPolicy
    );
    state.validate()?;
    Ok(())
}

#[test]
fn mode_vectors_reject_duplicate_singletons_and_quiet_lists_are_typed() -> Result<(), Box<dyn Error>>
{
    let duplicate = CanonicalCommand::mode(
        ChannelNameValue::parse("#duplicate")?,
        vec![
            ModeChange::Visibility(Visibility::Listed),
            ModeChange::Visibility(Visibility::Secret),
        ],
    );
    assert_eq!(duplicate.err(), Some(DomainError::InvalidArgument));

    let quiet = agenc_ircd_types::TypedMask::parse("$q:$n:*spam*")?;
    assert!(matches!(
        ModeChange::AddMask {
            list: MaskList::Ban,
            mask: quiet,
        },
        ModeChange::AddMask {
            list: MaskList::Ban,
            ..
        }
    ));
    Ok(())
}
