#![forbid(unsafe_code)]

//! Stage 06 persistence boundary: every plan's durable writes equal the change in
//! the durable projection, and the projection restores to itself.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use agenc_relay_domain::{
    AccountCommand, AccountLabelValue, AccountState, AdmissionSnapshot, CanonicalCommand,
    ChannelCommand, ChannelKeyVerifier, ChannelNameValue, ChannelTarget, DomainState,
    DurableAccount, DurableChannel, DurableSanction, DurableSession, DurableWrite,
    E2eeBindingProof, EntropyPurpose, ExternalInputRequest, ExternalInputs, HistoryPolicy,
    InformationQuery, MaskList, MessageCommand, MessageKind, MessageTarget, MessageText,
    ModeChange, ModeOperation, ModerationAction, ModerationReason, ModerationReasonCode,
    MutationPlan, NicknameValue, PlanDecision, PresenceCommand, PresencePolicy, Principal,
    RateBucket, Role, SanctionRequest, TopicText,
};
use agenc_relay_testkit::{
    DomainTestIdentity, account_id, apply_plan, bytes, channel_id, generation, message_admission,
    open_session, plan, registered_admission,
};
use agenc_relay_types::{
    AccountDeletionToken, AccountId, ChannelInstanceId, ControlPolicy, EntryId, InviteId,
    MessageId, MonotonicTick, Revision, TypedMask, UserId, UtcSecond,
};

#[derive(Clone, Eq, PartialEq)]
struct Snapshot {
    accounts: BTreeMap<AccountId, DurableAccount>,
    sessions: BTreeMap<UserId, DurableSession>,
    channels: BTreeMap<ChannelInstanceId, DurableChannel>,
    sanctions: Vec<DurableSanction>,
}

fn snapshot(state: &DomainState) -> Snapshot {
    Snapshot {
        accounts: state
            .durable_accounts()
            .map(|account| (account.account_id, account))
            .collect(),
        sessions: state
            .session_user_ids()
            .filter_map(|user_id| {
                state
                    .durable_session(user_id)
                    .map(|session| (user_id, session))
            })
            .collect(),
        channels: state
            .durable_channels()
            .map(|channel| (channel.channel_id, channel))
            .collect(),
        sanctions: state.durable_sanctions().collect(),
    }
}

/// The canonical write set implied by two projections: accounts, sessions, channels,
/// then appended sanctions. Revision-only changes are not writes.
fn projection_diff(before: &Snapshot, after: &Snapshot) -> Vec<DurableWrite> {
    let mut writes = Vec::new();
    for account_id in before.accounts.keys().chain(after.accounts.keys()) {
        if writes.iter().any(|write| {
            matches!(write, DurableWrite::PutAccount(a) if a.account_id == *account_id)
                || matches!(write, DurableWrite::TombstoneAccount(id) if id == account_id)
        }) {
            continue;
        }
        match (
            before.accounts.get(account_id),
            after.accounts.get(account_id),
        ) {
            (Some(_), None) => writes.push(DurableWrite::TombstoneAccount(*account_id)),
            (previous, Some(next))
                if previous.is_none_or(|previous| !previous.same_content(next)) =>
            {
                writes.push(DurableWrite::PutAccount(next.clone()));
            }
            _ => {}
        }
    }
    let session_user_ids = before
        .sessions
        .keys()
        .chain(after.sessions.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    for user_id in session_user_ids {
        match (before.sessions.get(&user_id), after.sessions.get(&user_id)) {
            (Some(previous), None) => {
                writes.push(DurableWrite::TombstoneSession(previous.session_id));
            }
            (previous, Some(next))
                if previous.is_none_or(|previous| !previous.same_content(next)) =>
            {
                writes.push(DurableWrite::PutSession(next.clone()));
            }
            _ => {}
        }
    }
    for channel_id in before.channels.keys().chain(after.channels.keys()) {
        if writes.iter().any(|write| matches!(write, DurableWrite::PutChannel(c) if c.channel_id == *channel_id)
            || matches!(write, DurableWrite::TombstoneChannel { channel_id: id, .. } if id == channel_id))
        {
            continue;
        }
        match (
            before.channels.get(channel_id),
            after.channels.get(channel_id),
        ) {
            (Some(previous), None) => writes.push(DurableWrite::TombstoneChannel {
                channel_id: *channel_id,
                name: previous.name.clone(),
            }),
            (previous, Some(next))
                if previous.is_none_or(|previous| !previous.same_content(next)) =>
            {
                writes.push(DurableWrite::PutChannel(next.clone()));
            }
            _ => {}
        }
    }
    for sanction in after.sanctions.iter().skip(before.sanctions.len()) {
        writes.push(DurableWrite::AppendSanction(sanction.clone()));
    }
    writes
}

fn restore_projection(
    revision: Revision,
    snapshot: &Snapshot,
) -> Result<DomainState, Box<dyn Error>> {
    Ok(DomainState::restore_authoritative(
        revision,
        snapshot.accounts.values().cloned().collect(),
        snapshot.sessions.values().cloned().collect(),
        snapshot.channels.values().cloned().collect(),
        snapshot.sanctions.clone(),
        MonotonicTick::from_ticks(50),
        UtcSecond::from_unix_seconds(1_710_000_000),
    )?)
}

/// Applies one plan and proves its declared writes are exactly the projection change,
/// then proves the projection restores to an equal projection.
fn check_plan(state: &mut DomainState, plan: MutationPlan) -> Result<(), Box<dyn Error>> {
    let declared = plan.durable_writes().to_vec();
    let before = snapshot(state);
    apply_plan(state, plan)?;
    let after = snapshot(state);
    let expected = projection_diff(&before, &after);
    assert!(
        declared == expected,
        "declared writes {declared:?} differ from projection diff {expected:?}"
    );
    let restored = restore_projection(state.revision(), &after)?;
    assert!(snapshot(&restored) == after, "restored projection differs");
    assert_eq!(restored.revision(), state.revision());
    Ok(())
}

/// Plans a command, supplying exactly the external inputs it requests from a
/// deterministic fixture, then checks the resulting mutation or query.
fn check_command(
    state: &mut DomainState,
    identity: DomainTestIdentity,
    build: impl Fn() -> Result<CanonicalCommand, Box<dyn Error>>,
    admission: &AdmissionSnapshot,
    seed: &mut u8,
) -> Result<(), Box<dyn Error>> {
    let mut decision = plan(state, identity, build()?, admission, None)?;
    if let PlanDecision::NeedsExternal(requests) = &decision {
        let inputs = fulfil(requests, seed);
        decision = plan(state, identity, build()?, admission, Some(inputs))?;
    }
    match decision {
        PlanDecision::Mutation(plan) => check_plan(state, plan),
        PlanDecision::Query(_) => Ok(()),
        PlanDecision::NeedsExternal(_) | PlanDecision::Rejected(_) => {
            Err("command did not produce a mutation or query".into())
        }
    }
}

fn fulfil(requests: &[ExternalInputRequest], seed: &mut u8) -> ExternalInputs {
    let mut inputs = ExternalInputs::default();
    for request in requests {
        *seed = seed.wrapping_add(1);
        match request {
            ExternalInputRequest::UtcNow { .. } => {
                inputs.utc_now = Some(UtcSecond::from_unix_seconds(1_710_000_000));
            }
            ExternalInputRequest::MonotonicNow { .. } => {
                inputs.monotonic_now = Some(MonotonicTick::from_ticks(50));
            }
            ExternalInputRequest::Entropy { purpose, .. } => match purpose {
                EntropyPurpose::ChannelInstance(_) => inputs.channel_ids.push(channel_id(*seed)),
                EntropyPurpose::Message(_) => {
                    inputs.message_ids.push(MessageId::from_bytes(bytes(*seed)));
                }
                EntropyPurpose::Invite => {
                    inputs.invite_ids.push(InviteId::from_bytes(bytes(*seed)))
                }
                EntropyPurpose::MaskEntry(_) => {
                    inputs.entry_ids.push(EntryId::from_bytes(bytes(*seed)));
                }
                EntropyPurpose::AccountDeletionChallenge => inputs
                    .deletion_tokens
                    .push(AccountDeletionToken::from_bytes(bytes(*seed))),
            },
            ExternalInputRequest::ChannelKeyVerification { .. } => inputs.key_verdicts.push(true),
            ExternalInputRequest::ChannelKeyConstruction { .. } => inputs
                .key_verifiers
                .push(ChannelKeyVerifier::new(bytes(*seed), [*seed; 32])),
        }
    }
    inputs
}

fn text(value: &str) -> Result<TopicText, Box<dyn Error>> {
    Ok(TopicText::try_from_str(value, ControlPolicy::RejectAll)?)
}

fn join(
    state: &mut DomainState,
    identity: DomainTestIdentity,
    name: &str,
    seed: &mut u8,
) -> Result<(), Box<dyn Error>> {
    check_command(
        state,
        identity,
        || {
            Ok(CanonicalCommand::join(vec![ChannelTarget::new(
                ChannelNameValue::parse(name)?,
                false,
            )])?)
        },
        &registered_admission(identity.user_id)?,
        seed,
    )
}

fn mode(
    state: &mut DomainState,
    identity: DomainTestIdentity,
    name: &str,
    changes: impl Fn() -> Result<Vec<ModeChange>, Box<dyn Error>>,
    seed: &mut u8,
) -> Result<(), Box<dyn Error>> {
    check_command(
        state,
        identity,
        || {
            Ok(CanonicalCommand::mode(
                ChannelNameValue::parse(name)?,
                changes()?,
            )?)
        },
        &registered_admission(identity.user_id)?,
        seed,
    )
}

fn create_checked_account(
    state: &mut DomainState,
    seed: u8,
) -> Result<(AccountId, agenc_relay_types::Generation), Box<dyn Error>> {
    let account = account_id(seed);
    let account_generation = generation(1)?;
    let plan = state.plan_account_created(AccountState::new(
        account,
        account_generation,
        state.revision(),
    ))?;
    check_plan(state, plan)?;
    Ok((account, account_generation))
}

#[test]
fn every_mutation_family_declares_exactly_its_projection_change() -> Result<(), Box<dyn Error>> {
    let mut state = DomainState::new()?;
    let seed = &mut 100_u8;
    let (alice_account, alice_generation) = create_checked_account(&mut state, 1)?;
    let (bob_account, bob_generation) = create_checked_account(&mut state, 2)?;
    assert_eq!(snapshot(&state).accounts.len(), 2);

    // Logical sessions survive coordinator restart.
    let alice = open_session(
        &mut state,
        10,
        "Alice",
        Some((alice_account, alice_generation)),
    )?;
    let bob = open_session(&mut state, 11, "Bob", Some((bob_account, bob_generation)))?;
    let carol = open_session(&mut state, 12, "Carol", None)?;
    assert_eq!(snapshot(&state).sessions.len(), 3);
    assert!(snapshot(&state).channels.is_empty());
    assert!(snapshot(&state).sanctions.is_empty());

    // Global channel authority and memberships are durable from the first JOIN.
    join(&mut state, alice, "#room", seed)?;
    join(&mut state, bob, "#room", seed)?;
    let room = state
        .resolve_channel(&ChannelNameValue::parse("#room")?)
        .ok_or("room")?;
    assert!(snapshot(&state).channels.contains_key(&room));
    assert_eq!(
        snapshot(&state)
            .sessions
            .get(&alice.user_id)
            .map(|session| session.joined_channels.as_slice()),
        Some([room].as_slice())
    );

    // Registration adds durable account ownership; later policy changes rewrite it.
    check_command(
        &mut state,
        alice,
        || Ok(CanonicalCommand::channel(ChannelCommand::Register(room))),
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    assert!(snapshot(&state).channels.contains_key(&room));
    check_command(
        &mut state,
        alice,
        || {
            Ok(CanonicalCommand::topic_set(
                ChannelNameValue::parse("#room")?,
                text("hello")?,
            ))
        },
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    mode(
        &mut state,
        alice,
        "#room",
        || Ok(vec![ModeChange::InviteOnly(true)]),
        seed,
    )?;
    mode(
        &mut state,
        alice,
        "#room",
        || {
            Ok(vec![
                ModeChange::MemberLimit(Some(10)),
                ModeChange::Moderated(true),
            ])
        },
        seed,
    )?;
    mode(
        &mut state,
        alice,
        "#room",
        || {
            Ok(vec![ModeChange::AddMask {
                list: MaskList::Ban,
                mask: TypedMask::parse("$n:spam*")?,
            }])
        },
        seed,
    )?;
    let ban_entry = snapshot(&state)
        .channels
        .get(&room)
        .and_then(|channel| channel.bans.first().map(|entry| entry.entry_id))
        .ok_or("ban entry")?;
    mode(
        &mut state,
        alice,
        "#room",
        || {
            Ok(vec![ModeChange::Role {
                operation: ModeOperation::Add,
                target: NicknameValue::parse("Bob")?,
                role: Role::Operator,
            }])
        },
        seed,
    )?;
    assert_eq!(
        snapshot(&state)
            .channels
            .get(&room)
            .map(|channel| channel.role_grants.clone()),
        Some(vec![
            (alice_account, Role::Owner),
            (bob_account, Role::Operator)
        ])
    );
    mode(
        &mut state,
        alice,
        "#room",
        || {
            Ok(vec![ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: ban_entry,
            }])
        },
        seed,
    )?;
    check_command(
        &mut state,
        alice,
        || {
            Ok(CanonicalCommand::channel(ChannelCommand::History(
                room,
                HistoryPolicy::OneHour,
            )))
        },
        &registered_admission(alice.user_id)?,
        seed,
    )?;

    // Invites, memberships, and presence update durable authority; messages do not.
    mode(
        &mut state,
        alice,
        "#room",
        || Ok(vec![ModeChange::InviteOnly(false)]),
        seed,
    )?;
    check_command(
        &mut state,
        alice,
        || {
            Ok(CanonicalCommand::invite(
                NicknameValue::parse("Carol")?,
                ChannelNameValue::parse("#room")?,
            ))
        },
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    join(&mut state, carol, "#room", seed)?;
    check_command(
        &mut state,
        alice,
        || {
            Ok(CanonicalCommand::message(MessageCommand::new(
                MessageKind::Privmsg,
                vec![MessageTarget::Channel(ChannelNameValue::parse("#room")?)],
                Some(MessageText::parse("hello room")?),
            )?))
        },
        &message_admission(alice, &[room])?,
        seed,
    )?;
    check_command(
        &mut state,
        alice,
        || {
            Ok(CanonicalCommand::kick(
                ChannelNameValue::parse("#room")?,
                vec![NicknameValue::parse("Carol")?],
                None,
            )?)
        },
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    check_command(
        &mut state,
        carol,
        || Ok(CanonicalCommand::nick(NicknameValue::parse("Carol2")?)),
        &registered_admission(carol.user_id)?,
        seed,
    )?;
    check_command(
        &mut state,
        carol,
        || Ok(CanonicalCommand::presence(PresenceCommand::Away(None))?),
        &registered_admission(carol.user_id)?,
        seed,
    )?;
    check_command(
        &mut state,
        carol,
        || {
            Ok(CanonicalCommand::user_operator_notices(
                NicknameValue::parse("Carol2")?,
                true,
            ))
        },
        &registered_admission(carol.user_id)?,
        seed,
    )?;
    let durable_after_session_changes = snapshot(&state);

    // Account settings persist; the reservation is visible through the index.
    check_command(
        &mut state,
        alice,
        || {
            Ok(CanonicalCommand::account(AccountCommand::Label(Some(
                AccountLabelValue::parse("Alice.label")?,
            ))))
        },
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    check_command(
        &mut state,
        alice,
        || {
            Ok(CanonicalCommand::account(AccountCommand::Presence(
                PresencePolicy::Public,
            )))
        },
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    check_command(
        &mut state,
        alice,
        || {
            Ok(CanonicalCommand::account(AccountCommand::ContactAdd(
                bob_account,
            )))
        },
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    check_command(
        &mut state,
        alice,
        || {
            Ok(CanonicalCommand::account(AccountCommand::NickReserve(
                NicknameValue::parse("Alice")?,
            )))
        },
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    assert_eq!(
        state.nickname_reserved_by(&NicknameValue::parse("alice")?),
        Some(alice_account)
    );
    assert_eq!(
        state.nickname_reserved_by(&NicknameValue::parse("nobody")?),
        None
    );
    assert_ne!(
        snapshot(&state).accounts,
        durable_after_session_changes.accounts
    );

    // Queries never plan a mutation.
    for query in [
        CanonicalCommand::names(vec![ChannelNameValue::parse("#room")?])?,
        CanonicalCommand::list(Vec::new())?,
        CanonicalCommand::topic_query(ChannelNameValue::parse("#room")?),
        CanonicalCommand::channel_mode_query(ChannelNameValue::parse("#room")?),
        CanonicalCommand::information(InformationQuery::Motd),
    ] {
        let admission = AdmissionSnapshot::new(vec![
            (RateBucket::RegisteredCommand(alice.user_id), 100),
            (RateBucket::ExpensiveQuery(alice.user_id), 100),
        ])?;
        let decision = plan(&state, alice, query, &admission, None)?;
        assert!(matches!(decision, PlanDecision::Query(_)));
    }

    // Sanctions append.
    let sanction = state.plan_sanction(SanctionRequest {
        actor_user_id: alice.user_id,
        target: Principal::Guest(carol.user_id),
        channel_id: Some(room),
        action: ModerationAction::Mute,
        reason_code: ModerationReasonCode::Harassment,
        reason: Some(ModerationReason::try_from_str(
            "bounded reason",
            ControlPolicy::RejectAll,
        )?),
        created_at: UtcSecond::from_unix_seconds(1_710_000_100),
        expires_at: Some(UtcSecond::from_unix_seconds(1_710_000_160)),
    })?;
    check_plan(&mut state, sanction)?;
    assert_eq!(snapshot(&state).sanctions.len(), 1);

    // A credential replacement rewrites the account fence and closes its sessions.
    let bob_revision = state.account(bob_account).ok_or("bob")?.revision();
    let (replacement, replaced_generation) =
        state.plan_account_credential_replaced(bob_account, bob_generation, bob_revision)?;
    check_plan(&mut state, replacement)?;
    assert_eq!(
        snapshot(&state)
            .accounts
            .get(&bob_account)
            .map(|account| account.session_generation),
        Some(replaced_generation)
    );

    // Part and quit are session state.
    check_command(
        &mut state,
        alice,
        || Ok(CanonicalCommand::part_all()),
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    check_command(
        &mut state,
        carol,
        || Ok(CanonicalCommand::quit(None)),
        &registered_admission(carol.user_id)?,
        seed,
    )?;

    // Deleting an account tombstones it and rewrites every channel that granted it.
    // Deletion needs exactly one live, channel-free session on the replaced fence.
    let bob_again = open_session(
        &mut state,
        13,
        "BobAgain",
        Some((bob_account, replaced_generation)),
    )?;
    let deletion = state.plan_account_deleted(bob_account, replaced_generation)?;
    let bob_writes = deletion.durable_writes().to_vec();
    assert!(matches!(
        bob_writes.first(),
        Some(DurableWrite::TombstoneAccount(id)) if *id == bob_account
    ));
    assert!(bob_writes.iter().any(
        |write| matches!(write, DurableWrite::TombstoneSession(id) if *id == bob_again.session_id)
    ));
    assert!(bob_writes.iter().any(|write| {
        matches!(write, DurableWrite::PutChannel(channel) if channel.channel_id == room
            && !channel.role_grants.iter().any(|(id, _)| *id == bob_account))
    }));
    check_plan(&mut state, deletion)?;

    // Unregistering drops account ownership while the global row remains durable.
    join(&mut state, alice, "#room", seed)?;
    check_command(
        &mut state,
        alice,
        || Ok(CanonicalCommand::channel(ChannelCommand::Unregister(room))),
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    assert!(snapshot(&state).channels.contains_key(&room));
    assert!(state.channel(room).is_some());

    // The E2EE binding is a persisted policy change on a registered channel.
    join(&mut state, alice, "#secure", seed)?;
    let secure = state
        .resolve_channel(&ChannelNameValue::parse("#secure")?)
        .ok_or("secure")?;
    check_command(
        &mut state,
        alice,
        || Ok(CanonicalCommand::channel(ChannelCommand::Register(secure))),
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    let channel_revision = state.channel(secure).ok_or("secure")?.revision();
    let binding = state.plan_e2ee_binding(
        alice.user_id,
        E2eeBindingProof::new(
            secure,
            channel_revision,
            vec![(alice.user_id, alice_account)],
        )?,
    )?;
    check_plan(&mut state, binding)?;
    state.validate()?;
    Ok(())
}

#[test]
fn restore_rejects_duplicates_unregistered_channels_and_invalid_projections()
-> Result<(), Box<dyn Error>> {
    let mut state = DomainState::new()?;
    let (alice_account, alice_generation) = create_checked_account(&mut state, 1)?;
    let alice = open_session(
        &mut state,
        10,
        "Alice",
        Some((alice_account, alice_generation)),
    )?;
    let seed = &mut 100_u8;
    join(&mut state, alice, "#room", seed)?;
    let room = state
        .resolve_channel(&ChannelNameValue::parse("#room")?)
        .ok_or("room")?;
    check_command(
        &mut state,
        alice,
        || Ok(CanonicalCommand::channel(ChannelCommand::Register(room))),
        &registered_admission(alice.user_id)?,
        seed,
    )?;
    let projection = snapshot(&state);
    let account = projection.accounts.get(&alice_account).ok_or("account")?;
    let session = projection.sessions.get(&alice.user_id).ok_or("session")?;
    let channel = projection.channels.get(&room).ok_or("channel")?;
    let accounts = || projection.accounts.values().cloned().collect::<Vec<_>>();
    let sessions = || projection.sessions.values().cloned().collect::<Vec<_>>();
    let channels = || projection.channels.values().cloned().collect::<Vec<_>>();
    let restore = |accounts, sessions, channels| {
        DomainState::restore_authoritative(
            state.revision(),
            accounts,
            sessions,
            channels,
            projection.sanctions.clone(),
            MonotonicTick::from_ticks(50),
            UtcSecond::from_unix_seconds(1_710_000_000),
        )
    };

    assert!(
        restore(
            vec![account.clone(), account.clone()],
            sessions(),
            channels()
        )
        .is_err()
    );
    assert!(
        restore(
            accounts(),
            vec![session.clone(), session.clone()],
            channels()
        )
        .is_err()
    );
    assert!(
        restore(
            accounts(),
            sessions(),
            vec![channel.clone(), channel.clone()]
        )
        .is_err()
    );
    let mut ephemeral = channel.clone();
    ephemeral.name = ChannelNameValue::parse("&room")?;
    ephemeral.scope = agenc_relay_domain::ChannelScope::Local;
    ephemeral.persistence = agenc_relay_domain::PersistencePolicy::Ephemeral;
    assert!(restore(accounts(), sessions(), vec![ephemeral]).is_err());
    let mut unsorted = account.clone();
    unsorted.contacts = vec![account_id(3), account_id(2)];
    assert!(restore(vec![unsorted], sessions(), channels()).is_err());
    let mut ownerless = channel.clone();
    ownerless.role_grants.clear();
    assert!(restore(accounts(), sessions(), vec![ownerless]).is_err());
    let mut unknown_grant = channel.clone();
    unknown_grant.role_grants = vec![(account_id(9), Role::Owner)];
    assert!(restore(accounts(), sessions(), vec![unknown_grant]).is_err());
    let mut bad_mask = channel.clone();
    bad_mask.bans.push(agenc_relay_domain::DurableListEntry {
        entry_id: EntryId::from_bytes(bytes(1)),
        mask: "not a mask".to_owned(),
        setter: Principal::Account(alice_account),
        created_at: UtcSecond::from_unix_seconds(1),
    });
    assert!(restore(accounts(), sessions(), vec![bad_mask]).is_err());

    let restored = restore(accounts(), sessions(), channels())?;
    assert!(snapshot(&restored) == projection);
    assert_eq!(restored.session_count(), 1);
    assert_eq!(
        restored.channel(room).map(|channel| channel.member_count()),
        Some(1)
    );
    assert_eq!(
        restored.resolve_channel(&ChannelNameValue::parse("#ROOM")?),
        Some(room)
    );
    Ok(())
}
