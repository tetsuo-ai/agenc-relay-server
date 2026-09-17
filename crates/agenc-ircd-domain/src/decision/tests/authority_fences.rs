#![forbid(unsafe_code)]

//! COV-01: the base domain authorization decisions the Stage 10 branch report
//! recorded as never taken.
//!
//! Each case drives a real planning boundary — `authorize`, `plan_session_opened`,
//! `plan_sanction` or the authorize/plan/prepare/apply mode path — so a refusal
//! is observed as the caller sees it and the refused state is re-read afterwards.

use agenc_ircd_types::{ServerId, UtcSecond};

use super::*;

/// Plans one message through the real authorize/plan boundary and reports the
/// first target failure, or `None` when the target was accepted.
///
/// A refused target resolves no route, so the planner asks for no external
/// input at all; an accepted target asks for a UTC second and one message
/// identifier, which the retry supplies exactly.
fn message_outcome(
    state: &DomainState,
    sender: &SessionState,
    command: &dyn Fn() -> Result<CanonicalCommand, DomainError>,
    credit: &AdmissionSnapshot,
) -> Result<Option<DomainError>, DomainError> {
    let plan = |inputs: Option<ExternalInputs>| -> Result<PlanDecision, DomainError> {
        let authorized = state
            .authorize(envelope(sender, state.revision, command()?), credit)
            .map_err(|failure| failure.error())?;
        state.plan_authorized(authorized, inputs)
    };
    match plan(None)? {
        PlanDecision::Rejected(rejected) => rejected
            .failures()
            .first()
            .map(TargetFailure::error)
            .map(Some)
            .ok_or(DomainError::InvariantViolation),
        PlanDecision::NeedsExternal(_) => {
            let inputs = ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(30)),
                message_ids: vec![MessageId::from_bytes(bytes(92))],
                ..ExternalInputs::default()
            };
            match plan(Some(inputs))? {
                PlanDecision::Mutation(_) => Ok(None),
                PlanDecision::NeedsExternal(_)
                | PlanDecision::Query(_)
                | PlanDecision::Rejected(_) => Err(DomainError::InvariantViolation),
            }
        }
        PlanDecision::Mutation(_) | PlanDecision::Query(_) => Err(DomainError::InvariantViolation),
    }
}

/// The federation-peer fence refuses execution for a session whose home peer is
/// suspended, refuses that session as a new direct-message target for anyone
/// else, changes no state while it refuses, and lifts completely on resume.
#[test]
fn a_suspended_home_peer_refuses_execution_and_direct_targeting() -> Result<(), DomainError> {
    let mut fixture = fixture()?;
    let remote_home = ServerId::from_bytes(bytes(200));
    let mut seed = session_seed(40, None, 0)?;
    seed.home_server_id = remote_home;
    let remote = SessionState::from_seed(seed);
    let remote_user = remote.user_id;
    let remote_nickname = remote.nickname.clone();
    let state = &mut fixture.state;
    state.apply_session(remote, Revision::new(1)?);
    let local_home = ServerId::from_bytes(bytes(240));
    let direct = |nickname: &NicknameValue| -> Result<CanonicalCommand, DomainError> {
        Ok(CanonicalCommand::message(MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::User(nickname.clone())],
            Some(MessageText::parse("x")?),
        )?))
    };
    let direct_credit = AdmissionSnapshot::new(vec![
        (RateBucket::RegisteredCommand(fixture.owner.user_id), 10),
        (RateBucket::AccountMessage(fixture.owner_account), 10),
    ])?;

    // The target is reachable before its home peer is suspended.
    assert_eq!(
        message_outcome(
            state,
            &fixture.owner,
            &|| direct(&remote_nickname),
            &direct_credit,
        )?,
        None
    );

    let before = state.revision;
    state.suspend_federation_peer(remote_home);
    // The suspended session is refused as a direct-message target, and the
    // refusal is the same "no such nickname" answer an absent target receives.
    assert_eq!(
        message_outcome(
            state,
            &fixture.owner,
            &|| direct(&remote_nickname),
            &direct_credit,
        )?,
        Some(DomainError::NotFound)
    );
    // Refusing changed nothing: the revision, the session and its nickname
    // index all stand, so the fence never deletes the grace-visible session.
    assert_eq!(state.revision, before);
    assert!(state.session(remote_user).is_some());
    assert!(!state.session_authority_available(remote_user));
    assert!(state.session_authority_available(fixture.owner.user_id));

    // Suspending the local home refuses the owner's own execution instead,
    // and does so before the session fence reports a stale generation.
    state.suspend_federation_peer(local_home);
    assert_eq!(
        state
            .authorize(
                envelope(&fixture.owner, state.revision, direct(&remote_nickname)?),
                &direct_credit,
            )
            .err()
            .map(|failure| failure.error()),
        Some(DomainError::ServerBusy)
    );
    assert!(!state.session_authority_available(fixture.owner.user_id));
    assert_eq!(state.revision, before);

    // Resuming both peers restores execution and direct targeting exactly.
    state.resume_federation_peer(local_home);
    state.resume_federation_peer(remote_home);
    assert!(state.session_authority_available(fixture.owner.user_id));
    assert!(state.session_authority_available(remote_user));
    assert_eq!(
        message_outcome(
            state,
            &fixture.owner,
            &|| direct(&remote_nickname),
            &direct_credit,
        )?,
        None
    );
    Ok(())
}

/// A session seed whose public cloak already belongs to a live session is
/// refused even though its session ID, user ID and nickname are all fresh.
#[test]
fn a_repeated_public_cloak_refuses_a_fresh_session_seed() -> Result<(), DomainError> {
    let fixture = fixture()?;
    let state = &fixture.state;
    let mut seed = session_seed(41, None, 0)?;
    // Every other index key is fresh; only the cloak repeats.
    assert!(state.session(seed.user_id).is_none());
    seed.public_cloak = fixture.owner.public_cloak;
    assert_eq!(
        state.plan_session_opened(seed).err(),
        Some(DomainError::BadState)
    );
    // The same seed with its own cloak is admitted, so the refusal above
    // rests on the cloak alone.
    let mut fresh = session_seed(41, None, 0)?;
    fresh.public_cloak = crate::model::test_public_cloak(41)?;
    state.plan_session_opened(fresh)?;
    Ok(())
}

/// A `Deny` direct-message policy refuses every other account, including one
/// that the recipient's contact set would admit under the `Contacts` policy.
#[test]
fn a_deny_direct_message_policy_refuses_a_contact_of_the_recipient() -> Result<(), DomainError> {
    let mut fixture = fixture()?;
    let owner_account = fixture.owner_account;
    let member_nickname = fixture.member.nickname.clone();
    let state = &mut fixture.state;
    let target = state
        .accounts
        .get_mut(&fixture.member_account)
        .ok_or(DomainError::NotFound)?;
    target.direct_messages = DirectMessagePolicy::Contacts;
    target.contacts.insert(owner_account);
    let command = || -> Result<CanonicalCommand, DomainError> {
        Ok(CanonicalCommand::message(MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::User(member_nickname.clone())],
            Some(MessageText::parse("x")?),
        )?))
    };
    let credit = AdmissionSnapshot::new(vec![
        (RateBucket::RegisteredCommand(fixture.owner.user_id), 10),
        (RateBucket::AccountMessage(owner_account), 10),
    ])?;
    // A recorded contact passes under `Contacts`.
    assert_eq!(
        message_outcome(state, &fixture.owner, &command, &credit)?,
        None
    );

    let before = state.revision;
    state
        .accounts
        .get_mut(&fixture.member_account)
        .ok_or(DomainError::NotFound)?
        .direct_messages = DirectMessagePolicy::Deny;
    // `Deny` outranks the contact set: the same sender is now forbidden.
    assert_eq!(
        message_outcome(state, &fixture.owner, &command, &credit)?,
        Some(DomainError::Forbidden)
    );
    assert_eq!(state.revision, before);
    assert!(
        state
            .accounts
            .get(&fixture.member_account)
            .is_some_and(|account| account.contacts.contains(&owner_account))
    );
    Ok(())
}

/// A permanent channel ban is admitted for an owner and refused for an
/// operator, and a permanent ban never applies the kick-only role comparison.
#[test]
fn a_permanent_ban_requires_owner_authority_and_skips_the_kick_rule() -> Result<(), DomainError> {
    let mut fixture = fixture()?;
    let channel_id = fixture.channel_id;
    let member_account = fixture.member_account;
    let state = &mut fixture.state;
    let request = |actor: UserId, expires_at: Option<UtcSecond>| SanctionRequest {
        actor_user_id: actor,
        target: Principal::Account(member_account),
        channel_id: Some(channel_id),
        action: ModerationAction::Ban,
        reason_code: ModerationReasonCode::Harassment,
        reason: None,
        created_at: UtcSecond::from_unix_seconds(20),
        expires_at,
    };
    // The channel owner may record a permanent ban.
    let plan = state.plan_sanction(request(fixture.owner.user_id, None))?;
    assert_eq!(plan.resulting_revision(), next_revision(state.revision)?);

    // An operator may record the same ban only with an expiry.
    let membership = state
        .channels
        .get_mut(&channel_id)
        .ok_or(DomainError::NotFound)?
        .memberships
        .get_mut(&fixture.outsider.user_id);
    assert!(membership.is_none());
    let operator = state
        .channels
        .get_mut(&channel_id)
        .ok_or(DomainError::NotFound)?
        .memberships
        .get_mut(&fixture.member.user_id)
        .ok_or(DomainError::NotFound)?;
    operator.session_role = Role::Operator;
    operator.effective_role = Role::Operator;
    let before = state.revision;
    assert_eq!(
        state
            .plan_sanction(request(fixture.member.user_id, None))
            .err(),
        Some(DomainError::Forbidden)
    );
    state.plan_sanction(request(
        fixture.member.user_id,
        Some(UtcSecond::from_unix_seconds(40)),
    ))?;
    // Planning a refusal never advanced the authoritative revision.
    assert_eq!(state.revision, before);
    Ok(())
}

/// Removing a mask by value inside one mode vector searches the additions the
/// same vector has already staged: a matching addition resolves, an addition on
/// another list or with another value does not, and neither leaves the channel
/// changed when the removal is refused.
#[test]
fn a_mask_removal_by_value_resolves_only_its_own_staged_addition() -> Result<(), DomainError> {
    let mut fixture = fixture()?;
    let channel_id = fixture.channel_id;
    let name = fixture.name.clone();
    let state = &mut fixture.state;
    let banned = || TypedMask::parse("$n:staged*");
    let other = || TypedMask::parse("$n:other*");
    let entry_id = EntryId::from_bytes(bytes(91));
    let plan_mode =
        |state: &DomainState, changes: Vec<ModeChange>| -> Result<PlanDecision, DomainError> {
            let authorized = state
                .authorize(
                    envelope(
                        &fixture.owner,
                        state.revision,
                        CanonicalCommand::mode(name.clone(), changes)?,
                    ),
                    &admission(fixture.owner.user_id)?,
                )
                .map_err(|failure| failure.error())?;
            state.plan_authorized(
                authorized,
                Some(ExternalInputs {
                    utc_now: Some(UtcSecond::from_unix_seconds(20)),
                    entry_ids: vec![entry_id],
                    ..ExternalInputs::default()
                }),
            )
        };

    // An addition on another list is not a candidate for this list's removal.
    assert_eq!(
        plan_mode(
            state,
            vec![
                ModeChange::AddMask {
                    list: MaskList::Exception,
                    mask: banned()?,
                },
                ModeChange::RemoveMaskValue {
                    list: MaskList::Ban,
                    mask: banned()?,
                },
            ],
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );
    // An addition of another value on the same list is not a candidate either.
    assert_eq!(
        plan_mode(
            state,
            vec![
                ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: other()?,
                },
                ModeChange::RemoveMaskValue {
                    list: MaskList::Ban,
                    mask: banned()?,
                },
            ],
        )
        .err(),
        Some(DomainError::InvalidArgument)
    );
    assert!(
        state
            .channel(channel_id)
            .is_some_and(|channel| channel.mask_list(MaskList::Ban).is_empty())
    );

    // The matching staged addition resolves, and the applied vector leaves the
    // ban list empty because the addition and its removal cancel exactly.
    let before = state.revision;
    let PlanDecision::Mutation(plan) = plan_mode(
        state,
        vec![
            ModeChange::AddMask {
                list: MaskList::Ban,
                mask: banned()?,
            },
            ModeChange::RemoveMaskValue {
                list: MaskList::Ban,
                mask: banned()?,
            },
        ],
    )?
    else {
        return Err(DomainError::InvariantViolation);
    };
    let prepared = state.prepare_mutation(plan)?;
    state.apply_prepared(prepared)?;
    assert_eq!(state.revision, next_revision(before)?);
    assert!(
        state
            .channel(channel_id)
            .is_some_and(|channel| channel.mask_list(MaskList::Ban).is_empty())
    );
    Ok(())
}
