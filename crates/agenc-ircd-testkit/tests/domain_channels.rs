#![forbid(unsafe_code)]

//! Stage-03 channel, projection, history, E2EE-boundary, and moderation tests.

use std::error::Error;

use agenc_ircd_domain::{
    CanonicalCommand, ChannelCommand, ChannelNameValue, ChannelTarget, ContentPolicy, DomainError,
    E2eeApplicationProof, E2eeBindingProof, E2eeRemovalFinality, ExternalInputRequest,
    ExternalInputs, HistoryPolicy, MAX_CHANNELS_PER_SESSION, MAX_MEMBERS_PER_CHANNEL, MaskList,
    MessageCommand, MessageKind, MessageTarget, MessageText, ModeChange, ModeOperation,
    ModerationAction, ModerationReasonCode, NicknameValue, PlanDecision, PresenceProjection,
    ProjectionDecision, Role, SanctionRequest, StorageClass, TopicProjection, TopicText,
    VisibilityMode,
};
use agenc_ircd_testkit::{
    DomainTestIdentity, account_id, apply_command, apply_plan, bytes, channel_id, create_account,
    message_admission, open_session, plan, registered_admission, revision,
};
use agenc_ircd_types::{ControlPolicy, EntryId, MessageId, TypedMask, UserId, UtcSecond};

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
            vec![ModeChange::Visibility {
                operation: ModeOperation::Add,
                mode: VisibilityMode::Secret,
            }],
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
    let (member_account, member_account_generation) = create_account(&mut state, 31, 5)?;
    let member = open_session(
        &mut state,
        31,
        "PolicyMember",
        Some((member_account, member_account_generation)),
    )?;
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

    let rejected = state.plan_e2ee_binding(
        owner.user_id,
        E2eeBindingProof::new(
            instance,
            channel.revision(),
            vec![
                (owner.user_id, owner_account),
                (member.user_id, member_account),
            ],
        )?,
    );
    assert_eq!(rejected.err(), Some(DomainError::BadState));

    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::History(instance, HistoryPolicy::Off)),
        &owner_admission,
        None,
    )?;
    let channel_revision = state
        .channel(instance)
        .ok_or("registered channel is missing")?
        .revision();
    let binding = state.plan_e2ee_binding(
        owner.user_id,
        E2eeBindingProof::new(
            instance,
            channel_revision,
            vec![
                (owner.user_id, owner_account),
                (member.user_id, member_account),
            ],
        )?,
    )?;
    apply_plan(&mut state, binding)?;
    let channel = state.channel(instance).ok_or("E2EE channel is missing")?;
    assert_eq!(channel.content_policy(), ContentPolicy::E2eeBound);
    assert_eq!(
        plan(
            &state,
            owner,
            CanonicalCommand::channel(ChannelCommand::Unregister(instance)),
            &owner_admission,
            None,
        )
        .err(),
        Some(DomainError::BadState)
    );
    assert!(matches!(
        state.project_channel_list()?.first().map(|row| row.topic()),
        Some(TopicProjection::EncryptedPlaceholder)
    ));

    let body = MessageText::parse("opaque route refusal")?;
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

    let rejected = plan(
        &state,
        owner,
        CanonicalCommand::message(MessageCommand::new(
            MessageKind::Tagmsg,
            vec![MessageTarget::Channel(name.clone())],
            None,
        )?),
        &message_admission,
        None,
    )?;
    let PlanDecision::Rejected(rejected) = rejected else {
        return Err("ordinary TAGMSG entered an E2EE application route".into());
    };
    assert_eq!(
        rejected
            .failures()
            .first()
            .ok_or("missing ordinary TAGMSG rejection")?
            .error(),
        DomainError::EncryptedRoute
    );

    let e2ee_revision = state
        .channel(instance)
        .ok_or("E2EE channel is missing")?
        .revision();
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::message(MessageCommand::e2ee_tagmsg(
            MessageTarget::Channel(name.clone()),
            E2eeApplicationProof::new(instance, owner.user_id, e2ee_revision),
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
            name.clone(),
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

    let pending_revision = state
        .channel(instance)
        .ok_or("E2EE channel is missing")?
        .revision();
    let blocked = plan(
        &state,
        owner,
        CanonicalCommand::message(MessageCommand::e2ee_tagmsg(
            MessageTarget::Channel(name.clone()),
            E2eeApplicationProof::new(instance, owner.user_id, pending_revision),
        )?),
        &message_admission,
        None,
    )?;
    let PlanDecision::Rejected(blocked) = blocked else {
        return Err("E2EE send was accepted while removal was pending".into());
    };
    assert_eq!(
        blocked
            .failures()
            .first()
            .ok_or("missing pending-removal rejection")?
            .error(),
        DomainError::BadState
    );

    let sanction = state.plan_sanction(SanctionRequest {
        actor_user_id: owner.user_id,
        target: agenc_ircd_domain::Principal::Account(member_account),
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
    let finality = state.plan_e2ee_removal_finalized(E2eeRemovalFinality::new(
        instance,
        member.user_id,
        pending_revision,
    ))?;
    apply_plan(&mut state, finality)?;
    assert!(
        !state
            .channel(instance)
            .ok_or("E2EE channel is missing")?
            .e2ee_removal_is_pending(member.user_id)
    );
    state.validate()?;
    Ok(())
}

#[test]
fn account_identity_replacement_is_rejected_while_occupying_an_e2ee_channel()
-> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 32, 6)?;
    let owner = open_session(
        &mut state,
        32,
        "BoundAccountOwner",
        Some((owner_account, owner_generation)),
    )?;
    let (replacement_account, replacement_generation) = create_account(&mut state, 33, 7)?;
    let channel_name = "#bound-account-switch";
    let channel = channel_id(42);

    join_new(&mut state, owner, channel_name, 42)?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Register(channel)),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    let channel_revision = state
        .channel(channel)
        .ok_or("registered channel is missing")?
        .revision();
    let binding = state.plan_e2ee_binding(
        owner.user_id,
        E2eeBindingProof::new(
            channel,
            channel_revision,
            vec![(owner.user_id, owner_account)],
        )?,
    )?;
    apply_plan(&mut state, binding)?;

    let state_revision = state.revision();
    let session_generation = state
        .session(owner.user_id)
        .ok_or("owner session is missing")?
        .generation();
    assert_eq!(
        state
            .plan_session_account_switch(owner.user_id, session_generation, None)
            .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        state
            .plan_session_account_switch(
                owner.user_id,
                session_generation,
                Some((replacement_account, replacement_generation)),
            )
            .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(state.revision(), state_revision);
    let unchanged = state
        .session(owner.user_id)
        .ok_or("owner session is missing after rejected account switches")?;
    assert_eq!(unchanged.account_id(), Some(owner_account));
    assert_eq!(unchanged.generation(), session_generation);
    assert_eq!(
        state
            .plan_session_account_switch(
                owner.user_id,
                session_generation,
                Some((owner_account, owner_generation)),
            )
            .err(),
        Some(DomainError::BadState)
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
            ModeChange::Visibility {
                operation: ModeOperation::Add,
                mode: VisibilityMode::Secret,
            },
            ModeChange::Visibility {
                operation: ModeOperation::Add,
                mode: VisibilityMode::Secret,
            },
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

fn apply_modes(
    state: &mut agenc_ircd_domain::DomainState,
    identity: DomainTestIdentity,
    name: &str,
    changes: Vec<ModeChange>,
) -> Result<(), DomainError> {
    apply_command(
        state,
        identity,
        CanonicalCommand::mode(ChannelNameValue::parse(name)?, changes)?,
        &registered_admission(identity.user_id)?,
        None,
    )?;
    Ok(())
}

fn apply_mask_modes(
    state: &mut agenc_ircd_domain::DomainState,
    identity: DomainTestIdentity,
    name: &str,
    changes: Vec<ModeChange>,
    entry_ids: Vec<EntryId>,
) -> Result<(), DomainError> {
    apply_command(
        state,
        identity,
        CanonicalCommand::mode(ChannelNameValue::parse(name)?, changes)?,
        &registered_admission(identity.user_id)?,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_010)),
            entry_ids,
            ..ExternalInputs::default()
        }),
    )?;
    Ok(())
}

#[test]
fn e2ee_proofs_reject_empty_oversized_and_duplicate_rosters() -> Result<(), Box<dyn Error>> {
    let channel = channel_id(200);
    let current_revision = revision(1)?;
    let user = UserId::from_bytes(bytes(201));
    let account = account_id(202);

    assert_eq!(
        E2eeBindingProof::new(channel, current_revision, Vec::new()).err(),
        Some(DomainError::LimitExceeded)
    );
    assert_eq!(
        E2eeBindingProof::new(
            channel,
            current_revision,
            vec![(user, account); MAX_MEMBERS_PER_CHANNEL + 1],
        )
        .err(),
        Some(DomainError::LimitExceeded)
    );
    assert_eq!(
        E2eeBindingProof::new(
            channel,
            current_revision,
            vec![(user, account), (user, account_id(203))],
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );
    Ok(())
}

#[test]
fn session_channel_limit_rejects_the_next_public_join() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (account, account_generation) = create_account(&mut state, 40, 1)?;
    let identity = open_session(
        &mut state,
        40,
        "ChannelLimitOwner",
        Some((account, account_generation)),
    )?;

    for index in 0..MAX_CHANNELS_PER_SESSION {
        join_new(
            &mut state,
            identity,
            &format!("#channel-limit-{index}"),
            u8::try_from(index)?,
        )?;
    }
    assert_eq!(state.channel_count(), MAX_CHANNELS_PER_SESSION);
    assert_eq!(
        apply_command(
            &mut state,
            identity,
            CanonicalCommand::join(vec![ChannelTarget::new(
                ChannelNameValue::parse("#channel-limit-overflow")?,
                false,
            )])?,
            &registered_admission(identity.user_id)?,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_001)),
                channel_ids: vec![channel_id(0)],
                ..ExternalInputs::default()
            }),
        )
        .err(),
        Some(DomainError::BadState)
    );
    state.validate()?;
    Ok(())
}

#[test]
fn e2ee_binding_join_and_finality_guards_are_publicly_observable() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 20, 1)?;
    let owner = open_session(
        &mut state,
        20,
        "E2eeGuardOwner",
        Some((owner_account, owner_generation)),
    )?;
    let (member_account, member_generation) = create_account(&mut state, 21, 2)?;
    let member = open_session(
        &mut state,
        21,
        "E2eeGuardMember",
        Some((member_account, member_generation)),
    )?;
    let guest = open_session(&mut state, 22, "E2eeGuardGuest", None)?;
    let main_name = "#e2ee-guards";
    let main_id = channel_id(20);
    join_new(&mut state, owner, main_name, 20)?;
    join_existing(&mut state, member, main_name)?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Register(main_id)),
        &registered_admission(owner.user_id)?,
        None,
    )?;

    let main_revision = state
        .channel(main_id)
        .ok_or("registered E2EE candidate is missing")?
        .revision();
    let roster = vec![
        (owner.user_id, owner_account),
        (member.user_id, member_account),
    ];
    assert_eq!(
        state
            .plan_e2ee_binding(
                owner.user_id,
                E2eeBindingProof::new(main_id, main_revision.checked_add(1)?, roster.clone())?,
            )
            .err(),
        Some(DomainError::StaleRevision)
    );
    assert_eq!(
        state
            .plan_e2ee_binding(
                owner.user_id,
                E2eeBindingProof::new(
                    main_id,
                    main_revision,
                    vec![(owner.user_id, owner_account)],
                )?,
            )
            .err(),
        Some(DomainError::StaleRevision)
    );
    assert_eq!(
        state
            .plan_e2ee_binding(
                guest.user_id,
                E2eeBindingProof::new(main_id, main_revision, roster.clone())?,
            )
            .err(),
        Some(DomainError::Forbidden)
    );
    assert_eq!(
        state
            .plan_e2ee_binding(
                member.user_id,
                E2eeBindingProof::new(main_id, main_revision, roster.clone())?,
            )
            .err(),
        Some(DomainError::Forbidden)
    );

    let binding = state.plan_e2ee_binding(
        owner.user_id,
        E2eeBindingProof::new(main_id, main_revision, roster.clone())?,
    )?;
    apply_plan(&mut state, binding)?;
    let bound_revision = state
        .channel(main_id)
        .ok_or("bound E2EE channel is missing")?
        .revision();
    assert_eq!(
        state
            .plan_e2ee_binding(
                owner.user_id,
                E2eeBindingProof::new(main_id, bound_revision, roster)?,
            )
            .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        apply_command(
            &mut state,
            guest,
            CanonicalCommand::join(vec![ChannelTarget::new(
                ChannelNameValue::parse(main_name)?,
                false,
            )])?,
            &registered_admission(guest.user_id)?,
            None,
        )
        .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        state
            .plan_e2ee_removal_finalized(E2eeRemovalFinality::new(
                main_id,
                member.user_id,
                bound_revision.checked_add(1)?,
            ))
            .err(),
        Some(DomainError::StaleRevision)
    );
    assert_eq!(
        state
            .plan_e2ee_removal_finalized(E2eeRemovalFinality::new(
                main_id,
                member.user_id,
                bound_revision,
            ))
            .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        plan(
            &state,
            owner,
            CanonicalCommand::channel(ChannelCommand::History(main_id, HistoryPolicy::OneHour,)),
            &registered_admission(owner.user_id)?,
            None,
        )
        .err(),
        Some(DomainError::BadState)
    );

    apply_command(
        &mut state,
        member,
        CanonicalCommand::part(vec![ChannelNameValue::parse(main_name)?], None)?,
        &registered_admission(member.user_id)?,
        None,
    )?;
    assert_eq!(
        plan(
            &state,
            member,
            CanonicalCommand::part(vec![ChannelNameValue::parse(main_name)?], None)?,
            &registered_admission(member.user_id)?,
            None,
        )
        .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::kick(
                ChannelNameValue::parse(main_name)?,
                vec![NicknameValue::parse("E2eeGuardMember")?],
                None,
            )?,
            &registered_admission(owner.user_id)?,
            None,
        )
        .err(),
        Some(DomainError::BadState)
    );
    let pending_revision = state
        .channel(main_id)
        .ok_or("pending E2EE channel is missing")?
        .revision();
    let finalized = state.plan_e2ee_removal_finalized(E2eeRemovalFinality::new(
        main_id,
        member.user_id,
        pending_revision,
    ))?;
    apply_plan(&mut state, finalized)?;

    let ephemeral_name = "#e2ee-ephemeral";
    let ephemeral_id = channel_id(23);
    join_new(&mut state, owner, ephemeral_name, 23)?;
    let ephemeral_revision = state
        .channel(ephemeral_id)
        .ok_or("ephemeral E2EE candidate is missing")?
        .revision();
    assert_eq!(
        state
            .plan_e2ee_binding(
                owner.user_id,
                E2eeBindingProof::new(
                    ephemeral_id,
                    ephemeral_revision,
                    vec![(owner.user_id, owner_account)],
                )?,
            )
            .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        plan(
            &state,
            owner,
            CanonicalCommand::channel(ChannelCommand::History(
                ephemeral_id,
                HistoryPolicy::OneHour,
            )),
            &registered_admission(owner.user_id)?,
            None,
        )
        .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        state
            .plan_e2ee_removal_finalized(E2eeRemovalFinality::new(
                ephemeral_id,
                owner.user_id,
                ephemeral_revision,
            ))
            .err(),
        Some(DomainError::BadState)
    );

    let local_name = "&e2ee-local";
    let local_id = channel_id(24);
    join_new(&mut state, owner, local_name, 24)?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Register(local_id)),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    let local_revision = state
        .channel(local_id)
        .ok_or("local E2EE candidate is missing")?
        .revision();
    assert_eq!(
        state
            .plan_e2ee_binding(
                owner.user_id,
                E2eeBindingProof::new(
                    local_id,
                    local_revision,
                    vec![(owner.user_id, owner_account)],
                )?,
            )
            .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        plan(
            &state,
            owner,
            CanonicalCommand::channel(ChannelCommand::History(local_id, HistoryPolicy::OneHour,)),
            &registered_admission(owner.user_id)?,
            None,
        )
        .err(),
        Some(DomainError::BadState)
    );

    let topic_name = "#e2ee-topic";
    let topic_id = channel_id(25);
    join_new(&mut state, owner, topic_name, 25)?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::channel(ChannelCommand::Register(topic_id)),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::topic_set(
            ChannelNameValue::parse(topic_name)?,
            TopicText::try_from_str("binding blocker", ControlPolicy::RejectAll)?,
        ),
        &registered_admission(owner.user_id)?,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_020)),
            message_ids: vec![MessageId::from_bytes(bytes(25))],
            ..ExternalInputs::default()
        }),
    )?;
    let topic_revision = state
        .channel(topic_id)
        .ok_or("topical E2EE candidate is missing")?
        .revision();
    assert_eq!(
        state
            .plan_e2ee_binding(
                owner.user_id,
                E2eeBindingProof::new(
                    topic_id,
                    topic_revision,
                    vec![(owner.user_id, owner_account)],
                )?,
            )
            .err(),
        Some(DomainError::BadState)
    );
    state.validate()?;
    Ok(())
}

#[test]
fn ordered_mode_vectors_cover_visibility_and_mask_delta_outcomes() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        CanonicalCommand::mode(
            ChannelNameValue::parse("#invalid-zero-limit")?,
            vec![ModeChange::MemberLimit(Some(0))],
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 30, 1)?;
    let owner = open_session(
        &mut state,
        30,
        "ModeGuardOwner",
        Some((owner_account, owner_generation)),
    )?;
    let name = "#mode-guard-coverage";
    let channel = channel_id(30);
    join_new(&mut state, owner, name, 30)?;

    apply_modes(
        &mut state,
        owner,
        name,
        vec![ModeChange::Visibility {
            operation: ModeOperation::Remove,
            mode: VisibilityMode::Secret,
        }],
    )?;
    apply_modes(
        &mut state,
        owner,
        name,
        vec![
            ModeChange::Visibility {
                operation: ModeOperation::Add,
                mode: VisibilityMode::Unlisted,
            },
            ModeChange::Visibility {
                operation: ModeOperation::Remove,
                mode: VisibilityMode::Unlisted,
            },
        ],
    )?;

    let ban_a = TypedMask::parse("$n:mask-a")?;
    let ban_b = TypedMask::parse("$n:mask-b")?;
    let exception = TypedMask::parse("$n:mask-c")?;
    let first = EntryId::from_bytes(bytes(31));
    let second = EntryId::from_bytes(bytes(32));
    let third = EntryId::from_bytes(bytes(33));
    apply_mask_modes(
        &mut state,
        owner,
        name,
        vec![
            ModeChange::AddMask {
                list: MaskList::Ban,
                mask: ban_a,
            },
            ModeChange::AddMask {
                list: MaskList::Ban,
                mask: ban_b,
            },
            ModeChange::AddMask {
                list: MaskList::Exception,
                mask: exception,
            },
        ],
        vec![first, second, third],
    )?;
    assert_eq!(
        plan(
            &state,
            owner,
            CanonicalCommand::mode(
                ChannelNameValue::parse(name)?,
                vec![
                    ModeChange::AddMask {
                        list: MaskList::Ban,
                        mask: TypedMask::parse("$n:wrong-list")?,
                    },
                    ModeChange::RemoveMask {
                        list: MaskList::Exception,
                        entry_id: EntryId::from_bytes(bytes(34)),
                    },
                ],
            )?,
            &registered_admission(owner.user_id)?,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_011)),
                entry_ids: vec![EntryId::from_bytes(bytes(34))],
                ..ExternalInputs::default()
            }),
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );
    assert_eq!(
        plan(
            &state,
            owner,
            CanonicalCommand::mode(
                ChannelNameValue::parse(name)?,
                vec![ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: TypedMask::parse("$n:mask-a")?,
                }],
            )?,
            &registered_admission(owner.user_id)?,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_011)),
                entry_ids: vec![EntryId::from_bytes(bytes(34))],
                ..ExternalInputs::default()
            }),
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );

    let replacement = EntryId::from_bytes(bytes(35));
    apply_mask_modes(
        &mut state,
        owner,
        name,
        vec![
            ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: first,
            },
            ModeChange::RemoveMask {
                list: MaskList::Exception,
                entry_id: third,
            },
            ModeChange::AddMask {
                list: MaskList::Ban,
                mask: TypedMask::parse("$n:mask-a")?,
            },
        ],
        vec![replacement],
    )?;
    let transient = EntryId::from_bytes(bytes(36));
    apply_mask_modes(
        &mut state,
        owner,
        name,
        vec![
            ModeChange::AddMask {
                list: MaskList::Exception,
                mask: TypedMask::parse("$n:mask-d")?,
            },
            ModeChange::RemoveMask {
                list: MaskList::Exception,
                entry_id: transient,
            },
        ],
        vec![transient],
    )?;
    apply_modes(
        &mut state,
        owner,
        name,
        vec![
            ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: second,
            },
            ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: replacement,
            },
        ],
    )?;

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
        CanonicalCommand::channel(ChannelCommand::History(channel, HistoryPolicy::OneHour)),
        &registered_admission(owner.user_id)?,
        None,
    )?;
    apply_modes(&mut state, owner, name, vec![ModeChange::Moderated(true)])?;
    assert_eq!(
        plan(
            &state,
            owner,
            CanonicalCommand::channel(ChannelCommand::Register(channel)),
            &registered_admission(owner.user_id)?,
            None,
        )
        .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        plan(
            &state,
            owner,
            CanonicalCommand::mode(
                ChannelNameValue::parse(name)?,
                vec![ModeChange::Visibility {
                    operation: ModeOperation::Add,
                    mode: VisibilityMode::Unlisted,
                }],
            )?,
            &registered_admission(owner.user_id)?,
            None,
        )
        .err(),
        Some(DomainError::BadState)
    );
    assert_eq!(
        state
            .channel(channel)
            .ok_or("mode coverage channel is missing")?
            .role_of(owner.user_id),
        Some(Role::Owner)
    );
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::part(vec![ChannelNameValue::parse(name)?], None)?,
        &registered_admission(owner.user_id)?,
        None,
    )?;
    assert!(state.channel(channel).is_some());
    state.validate()?;
    Ok(())
}
