#![forbid(unsafe_code)]

//! Stage-03 independent model and generated state-machine comparisons.

use std::collections::BTreeSet;
use std::error::Error;

use agenc_ircd_domain::{
    CanonicalCommand, ChannelCommand, ChannelNameValue, ChannelTarget, DomainError, ExternalInputs,
    ModeChange, ModeOperation, NicknameValue, Role, Visibility,
};
use agenc_ircd_testkit::{
    ALL_REFERENCE_COMMAND_KINDS, ReferenceCommand, ReferenceCommandKind, ReferenceDomainError,
    ReferenceDomainModel, ReferenceDomainStep, ReferenceMessageTarget, ReferenceRole,
    ReferenceVisibility, apply_command, apply_plan, channel_id, create_account, open_session,
    registered_admission,
};
use agenc_ircd_types::{InviteId, MonotonicTick, UtcSecond};

const GENERATED_STEPS: &str =
    include_str!("../../../test-data/property/domain-stage-three-v1.steps");

#[test]
fn reference_model_executes_every_command_with_real_behavior() -> Result<(), Box<dyn Error>> {
    let mut observed = BTreeSet::new();
    for command in ALL_REFERENCE_COMMAND_KINDS {
        let (mut model, operation, mutating) = reference_command_fixture(*command)?;
        let revision = model.snapshot().revision;
        model.apply(ReferenceDomainStep::ExecuteCommand {
            user: 2,
            command: operation,
        })?;
        let snapshot = model.snapshot();
        assert_eq!(snapshot.revision, revision + u64::from(mutating));
        assert!(snapshot.observed_commands.contains(command));
        observed.insert(*command);
    }
    assert_eq!(
        observed.into_iter().collect::<Vec<_>>(),
        ALL_REFERENCE_COMMAND_KINDS
    );
    Ok(())
}

fn reference_command_fixture(
    kind: ReferenceCommandKind,
) -> Result<(ReferenceDomainModel, ReferenceCommand, bool), ReferenceDomainError> {
    let mut model = ReferenceDomainModel::new();
    model.apply(ReferenceDomainStep::CreateAccount {
        account: 1,
        generation: 7,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 1,
        user: 2,
        account: Some(1),
        account_generation: 7,
        session_generation: 1,
        nickname: "registry-owner".to_owned(),
        cloak: 3,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 4,
        user: 5,
        account: None,
        account_generation: 0,
        session_generation: 1,
        nickname: "registry-member".to_owned(),
        cloak: 6,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 2,
        channel: "#registry".to_owned(),
        instance: 8,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 5,
        channel: "#registry".to_owned(),
        instance: 8,
    })?;
    let mutating = !matches!(
        kind,
        ReferenceCommandKind::Privmsg
            | ReferenceCommandKind::Notice
            | ReferenceCommandKind::Tagmsg
            | ReferenceCommandKind::Names
            | ReferenceCommandKind::List
            | ReferenceCommandKind::Motd
            | ReferenceCommandKind::Lusers
            | ReferenceCommandKind::Version
            | ReferenceCommandKind::Time
            | ReferenceCommandKind::Admin
            | ReferenceCommandKind::Info
            | ReferenceCommandKind::Links
            | ReferenceCommandKind::Who
            | ReferenceCommandKind::Whois
            | ReferenceCommandKind::Whowas
            | ReferenceCommandKind::Ison
            | ReferenceCommandKind::Userhost
            | ReferenceCommandKind::Chathistory
    );
    let command = match kind {
        ReferenceCommandKind::Nick => ReferenceCommand::Nick {
            nickname: "registry-renamed".to_owned(),
        },
        ReferenceCommandKind::Quit => ReferenceCommand::Quit,
        ReferenceCommandKind::Join => ReferenceCommand::Join {
            channel: "#registry-two".to_owned(),
            instance: 9,
        },
        ReferenceCommandKind::Part => ReferenceCommand::Part { instance: 8 },
        ReferenceCommandKind::Mode => ReferenceCommand::ModeVisibility {
            instance: 8,
            visibility: ReferenceVisibility::Secret,
        },
        ReferenceCommandKind::Topic => ReferenceCommand::TopicSet { instance: 8 },
        ReferenceCommandKind::Invite => ReferenceCommand::Invite {
            target: 5,
            instance: 8,
            invite: 10,
            expires_at: 100,
        },
        ReferenceCommandKind::Kick => ReferenceCommand::Kick {
            target: 5,
            instance: 8,
        },
        ReferenceCommandKind::Privmsg
        | ReferenceCommandKind::Notice
        | ReferenceCommandKind::Tagmsg => ReferenceCommand::Message {
            kind,
            target: ReferenceMessageTarget::Channel(8),
        },
        ReferenceCommandKind::Away => ReferenceCommand::Away { enabled: true },
        ReferenceCommandKind::Monitor => ReferenceCommand::MonitorAdd {
            nickname: "registry-member".to_owned(),
        },
        ReferenceCommandKind::Setname => ReferenceCommand::Setname {
            display_name: "Registry Owner".to_owned(),
        },
        ReferenceCommandKind::Acct => ReferenceCommand::AccountUpdate,
        ReferenceCommandKind::Chanctl => ReferenceCommand::ChannelRegistration {
            instance: 8,
            registered: true,
        },
        ReferenceCommandKind::Chathistory => {
            model.apply(ReferenceDomainStep::ExecuteCommand {
                user: 2,
                command: ReferenceCommand::ChannelRegistration {
                    instance: 8,
                    registered: true,
                },
            })?;
            ReferenceCommand::Chathistory { instance: 8 }
        }
        ReferenceCommandKind::Names
        | ReferenceCommandKind::List
        | ReferenceCommandKind::Motd
        | ReferenceCommandKind::Lusers
        | ReferenceCommandKind::Version
        | ReferenceCommandKind::Time
        | ReferenceCommandKind::Admin
        | ReferenceCommandKind::Info
        | ReferenceCommandKind::Links
        | ReferenceCommandKind::Who
        | ReferenceCommandKind::Whois
        | ReferenceCommandKind::Whowas
        | ReferenceCommandKind::Ison
        | ReferenceCommandKind::Userhost => ReferenceCommand::Query(kind),
    };
    Ok((model, command, mutating))
}

#[test]
fn rejected_reference_steps_leave_every_snapshot_field_unchanged() -> Result<(), Box<dyn Error>> {
    let mut model = ReferenceDomainModel::new();
    model.apply(ReferenceDomainStep::CreateAccount {
        account: 1,
        generation: 7,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 10,
        user: 20,
        account: Some(1),
        account_generation: 7,
        session_generation: 1,
        nickname: "owner".to_owned(),
        cloak: 30,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 11,
        user: 21,
        account: None,
        account_generation: 0,
        session_generation: 1,
        nickname: "member".to_owned(),
        cloak: 31,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 20,
        channel: "#reference".to_owned(),
        instance: 40,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 21,
        channel: "#reference".to_owned(),
        instance: 40,
    })?;

    let baseline = model.snapshot();
    assert_eq!(
        model.apply(ReferenceDomainStep::OpenSession {
            session: 12,
            user: 22,
            account: None,
            account_generation: 0,
            session_generation: 1,
            nickname: "member".to_owned(),
            cloak: 32,
        }),
        Err(ReferenceDomainError::Duplicate)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::Join {
            user: 21,
            channel: "#reference".to_owned(),
            instance: 41,
        }),
        Err(ReferenceDomainError::Stale)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::DeleteAccount {
            account: 1,
            expected_generation: 6,
        }),
        Err(ReferenceDomainError::Stale)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::SetRole {
            actor: 21,
            target: 20,
            instance: 40,
            role: ReferenceRole::Owner,
        }),
        Err(ReferenceDomainError::Forbidden)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::SwitchAccount {
            user: 20,
            account: None,
            expected_session_generation: 0,
            account_generation: 0,
        }),
        Err(ReferenceDomainError::Stale)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::FederationApply {
            origin: 5,
            sequence: 2,
        }),
        Err(ReferenceDomainError::Gap)
    );
    assert_eq!(model.snapshot(), baseline);

    model.apply(ReferenceDomainStep::FederationApply {
        origin: 5,
        sequence: 1,
    })?;
    let after_sequence = model.snapshot();
    assert_eq!(
        model.apply(ReferenceDomainStep::FederationApply {
            origin: 5,
            sequence: 1,
        }),
        Err(ReferenceDomainError::Stale)
    );
    assert_eq!(model.snapshot(), after_sequence);
    Ok(())
}

#[test]
fn generated_membership_role_mode_and_recreation_sequences_match_production()
-> Result<(), Box<dyn Error>> {
    let (cases, rejections) = generated_fixture()?;
    assert_eq!(cases.len(), 12);
    assert_eq!(rejections.len(), 7);
    for (case, visibility, scenario) in cases {
        compare_generated_case(case, visibility, scenario)?;
    }
    for (name, error) in rejections {
        execute_generated_rejection(name, error)?;
    }
    Ok(())
}

fn compare_generated_case(
    case: u8,
    reference_visibility: ReferenceVisibility,
    scenario: &str,
) -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 79, 1)?;
    let owner = open_session(
        &mut state,
        80,
        "modelowner",
        Some((owner_account, owner_generation)),
    )?;
    let member = open_session(&mut state, 81, "modelmember", None)?;
    let owner_admission = registered_admission(owner.user_id)?;
    let member_admission = registered_admission(member.user_id)?;
    let name_text = format!("#generated-{case}");
    let name = ChannelNameValue::parse(&name_text)?;
    let instance = channel_id(100 + case);

    let mut reference = ReferenceDomainModel::new();
    reference.apply(ReferenceDomainStep::CreateAccount {
        account: 79,
        generation: 1,
    })?;
    reference.apply(ReferenceDomainStep::OpenSession {
        session: 80,
        user: 144,
        account: Some(79),
        account_generation: 1,
        session_generation: 1,
        nickname: "modelowner".to_owned(),
        cloak: 80,
    })?;
    reference.apply(ReferenceDomainStep::OpenSession {
        session: 81,
        user: 145,
        account: None,
        account_generation: 0,
        session_generation: 1,
        nickname: "modelmember".to_owned(),
        cloak: 81,
    })?;

    apply_join_new(&mut state, owner, &name, instance)?;
    reference.apply(ReferenceDomainStep::Join {
        user: 144,
        channel: name_text.clone(),
        instance: u16::from(100 + case),
    })?;
    apply_command(
        &mut state,
        member,
        CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])?,
        &member_admission,
        None,
    )?;
    reference.apply(ReferenceDomainStep::Join {
        user: 145,
        channel: name_text.clone(),
        instance: u16::from(100 + case),
    })?;

    apply_command(
        &mut state,
        owner,
        CanonicalCommand::mode(
            name.clone(),
            vec![ModeChange::Role {
                operation: ModeOperation::Add,
                target: NicknameValue::parse("modelmember")?,
                role: Role::HalfOperator,
            }],
        )?,
        &owner_admission,
        None,
    )?;
    reference.apply(ReferenceDomainStep::SetRole {
        actor: 144,
        target: 145,
        instance: u16::from(100 + case),
        role: ReferenceRole::HalfOperator,
    })?;

    let production_visibility = match reference_visibility {
        ReferenceVisibility::Listed => Visibility::Listed,
        ReferenceVisibility::Unlisted => Visibility::Unlisted,
        ReferenceVisibility::Secret => Visibility::Secret,
    };
    apply_command(
        &mut state,
        owner,
        CanonicalCommand::mode(
            name.clone(),
            vec![ModeChange::Visibility(production_visibility)],
        )?,
        &owner_admission,
        None,
    )?;
    reference.apply(ReferenceDomainStep::SetVisibility {
        actor: 144,
        instance: u16::from(100 + case),
        visibility: reference_visibility,
    })?;

    let new_nickname = format!("renamed{case}");
    apply_command(
        &mut state,
        member,
        CanonicalCommand::nick(NicknameValue::parse(&new_nickname)?),
        &member_admission,
        None,
    )?;
    reference.apply(ReferenceDomainStep::Rename {
        user: 145,
        nickname: new_nickname.clone(),
    })?;
    compare_live_snapshots(&state, &reference, instance, 145, &new_nickname)?;

    let family = scenario
        .split_once('-')
        .map(|(_, family)| family)
        .ok_or("generated scenario is missing its family")?;
    match family {
        "membership-role-mode" => {
            leave_generated_channel(
                &mut state,
                &mut reference,
                owner,
                member,
                &name,
                u16::from(100 + case),
            )?;
        }
        "nickname-reuse-recreation" => {
            leave_generated_channel(
                &mut state,
                &mut reference,
                owner,
                member,
                &name,
                u16::from(100 + case),
            )?;
            apply_command(
                &mut state,
                member,
                CanonicalCommand::quit(None),
                &member_admission,
                None,
            )?;
            reference.apply(ReferenceDomainStep::CloseSession { user: 145 })?;

            let replacement = open_session(&mut state, 180 + case, &new_nickname, None)?;
            let replacement_user = u16::from(200 + case);
            reference.apply(ReferenceDomainStep::OpenSession {
                session: u16::from(180 + case),
                user: replacement_user,
                account: None,
                account_generation: 0,
                session_generation: 1,
                nickname: new_nickname,
                cloak: u32::from(180 + case),
            })?;
            let replacement_instance = channel_id(120 + case);
            apply_join_new(&mut state, replacement, &name, replacement_instance)?;
            reference.apply(ReferenceDomainStep::Join {
                user: replacement_user,
                channel: name_text,
                instance: u16::from(120 + case),
            })?;
            apply_command(
                &mut state,
                replacement,
                CanonicalCommand::part(vec![name.clone()], None)?,
                &registered_admission(replacement.user_id)?,
                None,
            )?;
            reference.apply(ReferenceDomainStep::Part {
                user: replacement_user,
                instance: u16::from(120 + case),
            })?;
        }
        "invite-account-switch" => {
            apply_command(
                &mut state,
                member,
                CanonicalCommand::part(vec![name.clone()], None)?,
                &member_admission,
                None,
            )?;
            reference.apply(ReferenceDomainStep::Part {
                user: 145,
                instance: u16::from(100 + case),
            })?;

            let (account, account_generation) = create_account(&mut state, 150 + case, 1)?;
            reference.apply(ReferenceDomainStep::CreateAccount {
                account: u16::from(150 + case),
                generation: 1,
            })?;
            apply_command(
                &mut state,
                owner,
                CanonicalCommand::invite(NicknameValue::parse(&new_nickname)?, name.clone()),
                &owner_admission,
                Some(ExternalInputs {
                    monotonic_now: Some(MonotonicTick::from_ticks(900 + u64::from(case))),
                    invite_ids: vec![InviteId::from_bytes([case; 16])],
                    ..ExternalInputs::default()
                }),
            )?;
            reference.apply(ReferenceDomainStep::Invite {
                actor: 144,
                target: 145,
                instance: u16::from(100 + case),
                invite: u16::from(220 + case),
                expires_at: 1_000,
            })?;
            assert_eq!(
                state
                    .channel(instance)
                    .ok_or("production channel is missing")?
                    .pending_invites()
                    .count(),
                1
            );
            assert_eq!(
                reference
                    .snapshot()
                    .channels
                    .first()
                    .ok_or("reference channel is missing")?
                    .invites
                    .len(),
                1
            );

            let switch = state.plan_session_account_switch(
                member.user_id,
                member.generation,
                Some((account, account_generation)),
            )?;
            apply_plan(&mut state, switch)?;
            reference.apply(ReferenceDomainStep::SwitchAccount {
                user: 145,
                account: Some(u16::from(150 + case)),
                expected_session_generation: 1,
                account_generation: 1,
            })?;
            assert_eq!(
                state
                    .channel(instance)
                    .ok_or("production channel is missing")?
                    .pending_invites()
                    .count(),
                0
            );
            assert!(
                reference
                    .snapshot()
                    .channels
                    .first()
                    .ok_or("reference channel is missing")?
                    .invites
                    .is_empty()
            );

            apply_command(
                &mut state,
                owner,
                CanonicalCommand::part(vec![name.clone()], None)?,
                &owner_admission,
                None,
            )?;
            reference.apply(ReferenceDomainStep::Part {
                user: 144,
                instance: u16::from(100 + case),
            })?;
        }
        "account-deletion-federation" => {
            apply_command(
                &mut state,
                owner,
                CanonicalCommand::channel(ChannelCommand::Register(instance)),
                &owner_admission,
                None,
            )?;
            reference.apply(ReferenceDomainStep::ExecuteCommand {
                user: 144,
                command: ReferenceCommand::ChannelRegistration {
                    instance: u16::from(100 + case),
                    registered: true,
                },
            })?;
            assert_eq!(
                reference.snapshot().registered_channels,
                vec![u16::from(100 + case)]
            );
            apply_command(
                &mut state,
                owner,
                CanonicalCommand::channel(ChannelCommand::Unregister(instance)),
                &owner_admission,
                None,
            )?;
            reference.apply(ReferenceDomainStep::ExecuteCommand {
                user: 144,
                command: ReferenceCommand::ChannelRegistration {
                    instance: u16::from(100 + case),
                    registered: false,
                },
            })?;
            leave_generated_channel(
                &mut state,
                &mut reference,
                owner,
                member,
                &name,
                u16::from(100 + case),
            )?;
            let account_seed = 160 + case;
            let (account, account_generation) = create_account(&mut state, account_seed, 1)?;
            let account_user = open_session(
                &mut state,
                190 + case,
                &format!("deletion{case}"),
                Some((account, account_generation)),
            )?;
            reference.apply(ReferenceDomainStep::CreateAccount {
                account: u16::from(account_seed),
                generation: 1,
            })?;
            reference.apply(ReferenceDomainStep::OpenSession {
                session: u16::from(190 + case),
                user: u16::from(220 + case),
                account: Some(u16::from(account_seed)),
                account_generation: 1,
                session_generation: 1,
                nickname: format!("deletion{case}"),
                cloak: u32::from(190 + case),
            })?;
            let deletion = state.plan_account_deleted(account, account_generation)?;
            apply_plan(&mut state, deletion)?;
            reference.apply(ReferenceDomainStep::DeleteAccount {
                account: u16::from(account_seed),
                expected_generation: 1,
            })?;
            assert!(state.session(account_user.user_id).is_none());
            assert!(
                reference
                    .snapshot()
                    .sessions
                    .iter()
                    .all(|session| session.user != u16::from(220 + case))
            );
        }
        _ => return Err("generated scenario family is unknown".into()),
    }

    assert_eq!(state.revision().get(), reference.snapshot().revision);
    assert_eq!(state.channel_count(), 0);
    assert!(reference.snapshot().channels.is_empty());
    if family == "account-deletion-federation" {
        reference.apply(ReferenceDomainStep::FederationApply {
            origin: u16::from(case),
            sequence: 1,
        })?;
        reference.apply(ReferenceDomainStep::FederationApply {
            origin: u16::from(case),
            sequence: 2,
        })?;
        assert_eq!(
            reference.snapshot().federation_sequences,
            vec![(u16::from(case), 2)]
        );
    }
    state.validate()?;
    Ok(())
}

fn leave_generated_channel(
    state: &mut agenc_ircd_domain::DomainState,
    reference: &mut ReferenceDomainModel,
    owner: agenc_ircd_testkit::DomainTestIdentity,
    member: agenc_ircd_testkit::DomainTestIdentity,
    name: &ChannelNameValue,
    reference_instance: u16,
) -> Result<(), Box<dyn Error>> {
    apply_command(
        state,
        member,
        CanonicalCommand::part(vec![name.clone()], None)?,
        &registered_admission(member.user_id)?,
        None,
    )?;
    reference.apply(ReferenceDomainStep::Part {
        user: 145,
        instance: reference_instance,
    })?;
    apply_command(
        state,
        owner,
        CanonicalCommand::part(vec![name.clone()], None)?,
        &registered_admission(owner.user_id)?,
        None,
    )?;
    reference.apply(ReferenceDomainStep::Part {
        user: 144,
        instance: reference_instance,
    })?;
    Ok(())
}

type GeneratedFixture<'a> = (
    Vec<(u8, ReferenceVisibility, &'a str)>,
    Vec<(&'a str, &'a str)>,
);

fn generated_fixture() -> Result<GeneratedFixture<'static>, Box<dyn Error>> {
    let mut cases = Vec::new();
    let mut rejections = Vec::new();
    for line in GENERATED_STEPS.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        match fields.as_slice() {
            ["CASE", case, visibility, scenario] => {
                let visibility = match *visibility {
                    "listed" => ReferenceVisibility::Listed,
                    "unlisted" => ReferenceVisibility::Unlisted,
                    "secret" => ReferenceVisibility::Secret,
                    _ => return Err("generated visibility is invalid".into()),
                };
                let expected_prefix = match visibility {
                    ReferenceVisibility::Listed => "listed-",
                    ReferenceVisibility::Unlisted => "unlisted-",
                    ReferenceVisibility::Secret => "secret-",
                };
                if !scenario.starts_with(expected_prefix) {
                    return Err("generated scenario visibility is inconsistent".into());
                }
                cases.push((case.parse()?, visibility, *scenario));
            }
            ["REJECT", name, error, "state-unchanged"] => {
                rejections.push((*name, *error));
            }
            _ => return Err("generated Stage-03 record is malformed".into()),
        }
    }
    Ok((cases, rejections))
}

fn execute_generated_rejection(name: &str, error: &str) -> Result<(), Box<dyn Error>> {
    let mut model = ReferenceDomainModel::new();
    model.apply(ReferenceDomainStep::CreateAccount {
        account: 1,
        generation: 7,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 10,
        user: 20,
        account: Some(1),
        account_generation: 7,
        session_generation: 1,
        nickname: "owner".to_owned(),
        cloak: 30,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 11,
        user: 21,
        account: None,
        account_generation: 0,
        session_generation: 1,
        nickname: "member".to_owned(),
        cloak: 31,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 20,
        channel: "#reference".to_owned(),
        instance: 40,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 21,
        channel: "#reference".to_owned(),
        instance: 40,
    })?;
    if name == "federation-duplicate" {
        model.apply(ReferenceDomainStep::FederationApply {
            origin: 5,
            sequence: 1,
        })?;
    }
    let baseline = model.snapshot();
    let result = match name {
        "duplicate-nickname" => model.apply(ReferenceDomainStep::OpenSession {
            session: 12,
            user: 22,
            account: None,
            account_generation: 0,
            session_generation: 1,
            nickname: "member".to_owned(),
            cloak: 32,
        }),
        "stale-channel-instance" => model.apply(ReferenceDomainStep::Join {
            user: 21,
            channel: "#reference".to_owned(),
            instance: 41,
        }),
        "role-escalation" => model.apply(ReferenceDomainStep::SetRole {
            actor: 21,
            target: 20,
            instance: 40,
            role: ReferenceRole::Owner,
        }),
        "stale-session-generation" => model.apply(ReferenceDomainStep::SwitchAccount {
            user: 20,
            account: None,
            expected_session_generation: 0,
            account_generation: 0,
        }),
        "federation-duplicate" => model.apply(ReferenceDomainStep::FederationApply {
            origin: 5,
            sequence: 1,
        }),
        "federation-gap" => model.apply(ReferenceDomainStep::FederationApply {
            origin: 5,
            sequence: 2,
        }),
        "stale-account-deletion" => model.apply(ReferenceDomainStep::DeleteAccount {
            account: 1,
            expected_generation: 6,
        }),
        _ => return Err("generated rejection name is unknown".into()),
    };
    let expected = match error {
        "Duplicate" => ReferenceDomainError::Duplicate,
        "Stale" => ReferenceDomainError::Stale,
        "Gap" => ReferenceDomainError::Gap,
        "Forbidden" => ReferenceDomainError::Forbidden,
        _ => return Err("generated rejection error is unknown".into()),
    };
    assert_eq!(result, Err(expected));
    assert_eq!(model.snapshot(), baseline);
    Ok(())
}

fn apply_join_new(
    state: &mut agenc_ircd_domain::DomainState,
    owner: agenc_ircd_testkit::DomainTestIdentity,
    name: &ChannelNameValue,
    instance: agenc_ircd_types::ChannelInstanceId,
) -> Result<(), DomainError> {
    let admission = registered_admission(owner.user_id)?;
    apply_command(
        state,
        owner,
        CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])?,
        &admission,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_700_400_000)),
            channel_ids: vec![instance],
            ..ExternalInputs::default()
        }),
    )?;
    Ok(())
}

fn compare_live_snapshots(
    state: &agenc_ircd_domain::DomainState,
    reference: &ReferenceDomainModel,
    instance: agenc_ircd_types::ChannelInstanceId,
    reference_member: u16,
    nickname: &str,
) -> Result<(), Box<dyn Error>> {
    let snapshot = reference.snapshot();
    assert_eq!(state.revision().get(), snapshot.revision);
    let channel = state
        .channel(instance)
        .ok_or("production channel is missing")?;
    let reference_channel = snapshot
        .channels
        .first()
        .ok_or("reference channel is missing")?;
    assert_eq!(channel.member_count(), reference_channel.members.len());
    assert_eq!(
        channel.visibility() == Visibility::Secret,
        reference_channel.visibility == ReferenceVisibility::Secret
    );
    let reference_session = snapshot
        .sessions
        .iter()
        .find(|session| session.user == reference_member)
        .ok_or("reference member is missing")?;
    assert_eq!(reference_session.nickname, nickname);
    assert!(
        state
            .resolve_nickname(&NicknameValue::parse(nickname)?)
            .is_some()
    );
    Ok(())
}
