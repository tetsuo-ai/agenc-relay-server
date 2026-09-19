//! Planner outcomes reached only by suspended peers, channel ceilings, mixed
//! join scopes, deletion-challenge binding mismatches, encrypted channels,
//! duplicate mask adds, corrupted role state and direct helper calls.
#![forbid(unsafe_code)]

use super::*;
use crate::model::{
    MAX_CHANNELS_PER_SESSION, MAX_GLOBAL_CHANNELS, MAX_INVITES_NETWORK_WIDE, MAX_LOCAL_CHANNELS,
    MAX_MEMBERS_PER_CHANNEL, MAX_SESSIONS_PER_ACCOUNT, OperationalLimitValues,
};
use crate::{ChannelTarget, MaskList, ModeChange, OperationalLimits, PlanDecision};
use agenc_ircd_types::TypedMask;

fn plan_for(
    state: &DomainState,
    actor: &SessionState,
    command: CanonicalCommand,
    inputs: Option<ExternalInputs>,
) -> Result<PlanDecision, DomainError> {
    let authorized = state
        .authorize(
            envelope(actor, state.revision, command),
            &admission(actor.user_id)?,
        )
        .map_err(|failure| failure.error())?;
    state.plan_authorized(authorized, inputs)
}

fn describe(outcome: Result<PlanDecision, DomainError>) -> String {
    match outcome {
        Ok(PlanDecision::Mutation(_)) => "mutation".to_owned(),
        Ok(PlanDecision::NeedsExternal(requests)) => format!("external:{}", requests.len()),
        Ok(PlanDecision::Query(_)) => "query".to_owned(),
        Ok(PlanDecision::Rejected(rejected)) => {
            format!(
                "rejected:{:?}",
                rejected
                    .failures
                    .iter()
                    .map(TargetFailure::error)
                    .collect::<Vec<_>>()
            )
        }
        Err(error) => format!("err:{error:?}"),
    }
}

fn join_inputs(seeds: &[u8]) -> ExternalInputs {
    ExternalInputs {
        utc_now: Some(UtcSecond::from_unix_seconds(20)),
        channel_ids: seeds
            .iter()
            .map(|seed| ChannelInstanceId::from_bytes(bytes(*seed)))
            .collect(),
        ..ExternalInputs::default()
    }
}

#[test]
fn a_session_behind_a_suspended_peer_cannot_plan() -> Result<(), DomainError> {
    let mut fixture = fixture()?;
    fixture
        .state
        .fence_federation_peer(ServerId::from_bytes(bytes(240)));
    let join = CanonicalCommand::join(vec![ChannelTarget::new(
        ChannelNameValue::parse("#elsewhere")?,
        false,
    )])?;
    assert_eq!(
        plan_for(&fixture.state, &fixture.outsider, join, None).err(),
        Some(DomainError::ServerBusy)
    );
    Ok(())
}

#[test]
fn a_join_creating_a_channel_beyond_the_global_ceiling_is_refused() -> Result<(), DomainError> {
    let mut fixture = fixture()?;
    fixture
        .state
        .set_operational_limits(OperationalLimits::new(OperationalLimitValues {
            sessions_per_account: MAX_SESSIONS_PER_ACCOUNT,
            channels_per_session: MAX_CHANNELS_PER_SESSION,
            members_per_channel: MAX_MEMBERS_PER_CHANNEL,
            global_channels: 1,
            local_channels: MAX_LOCAL_CHANNELS,
            invites_per_channel: crate::model::MAX_INVITES_PER_CHANNEL,
            invites_per_principal: crate::model::MAX_INVITES_PER_PRINCIPAL,
            invites_global: MAX_INVITES_NETWORK_WIDE,
            contacts_per_account: crate::model::MAX_CONTACTS_PER_ACCOUNT,
        })?);
    let join = CanonicalCommand::join(vec![ChannelTarget::new(
        ChannelNameValue::parse("#second")?,
        false,
    )])?;
    assert_eq!(
        describe(plan_for(
            &fixture.state,
            &fixture.outsider,
            join,
            Some(join_inputs(&[31]))
        )),
        "rejected:[LimitExceeded]"
    );
    let _ = MAX_GLOBAL_CHANNELS;
    Ok(())
}

/// Starts a deletion challenge for the private session and returns the state
/// holding it, the live session and the token the client must confirm.
fn challenged() -> Result<(DomainState, SessionState, AccountId), DomainError> {
    let (mut state, user_id, account_id) = private_auth_session()?;
    assert!(state.session(user_id).is_some());
    let live = SessionState::from_seed(session_seed(230, Some(account_id), 1)?);
    let start = mutation_of(account_command_plan(
        &state,
        &live,
        AccountCommand::DeleteStart,
        Some(ExternalInputs {
            monotonic_now: Some(MonotonicTick::from_ticks(101)),
            deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(231))],
            ..ExternalInputs::default()
        }),
    )?)?;
    let prepared = state.prepare_mutation(start)?;
    state.apply_prepared(prepared)?;
    Ok((state, live, account_id))
}

fn confirm(state: &DomainState, live: &SessionState) -> Result<MutationPlan, DomainError> {
    mutation_of(account_command_plan(
        state,
        live,
        AccountCommand::DeleteConfirm(AccountDeletionToken::from_bytes(bytes(231))),
        Some(ExternalInputs {
            monotonic_now: Some(MonotonicTick::from_ticks(102)),
            ..ExternalInputs::default()
        }),
    )?)
}

#[test]
fn a_deletion_challenge_bound_to_other_state_is_rejected_on_confirmation() -> Result<(), DomainError>
{
    type Corrupt =
        fn(&mut crate::model::AccountDeletionChallengeState, agenc_ircd_types::Generation);
    let other = agenc_ircd_types::Generation::new(7)?;
    let corruptions: [Corrupt; 5] = [
        |challenge, _| challenge.account_id = account_id(99),
        |challenge, other| challenge.account_session_generation = other,
        |challenge, _| challenge.session_id = SessionId::from_bytes(bytes(99)),
        |challenge, _| challenge.user_id = UserId::from_bytes(bytes(99)),
        |challenge, other| challenge.session_generation = other,
    ];
    for corrupt in corruptions {
        let (mut state, live, _account_id) = challenged()?;
        for challenge in state.account_deletion_challenges.values_mut() {
            corrupt(challenge, other);
        }
        let rejected = confirm(&state, &live)?;
        assert_eq!(
            rejected.events(),
            &[DomainEvent::AccountDeletionConfirmationRejected(
                live.user_id
            )]
        );
    }
    let (state, live, account_id) = challenged()?;
    let accepted = confirm(&state, &live)?;
    assert_eq!(
        accepted.events(),
        &[DomainEvent::AccountDeleted(account_id)]
    );
    Ok(())
}

#[test]
fn an_encrypted_channel_admits_no_guest() -> Result<(), DomainError> {
    let mut fixture = fixture()?;
    let ceiling = fixture.state.operational_limits().members_per_channel();
    let channel = fixture
        .state
        .channels
        .get_mut(&fixture.channel_id)
        .ok_or(DomainError::NotFound)?;
    channel.content_policy = ContentPolicy::E2eeBound;
    assert_eq!(
        validate_join_admission(channel, &fixture.outsider, None, false, false, ceiling).err(),
        Some(DomainError::RegistrationRequired)
    );
    assert_eq!(
        validate_join_admission(channel, &fixture.member, None, false, false, ceiling).err(),
        None
    );
    Ok(())
}

#[test]
fn adding_the_same_mask_twice_in_one_vector_is_refused() -> Result<(), DomainError> {
    let fixture = fixture()?;
    let channel = fixture
        .state
        .channels
        .get(&fixture.channel_id)
        .ok_or(DomainError::NotFound)?;
    let changes = vec![
        ModeChange::AddMask {
            list: MaskList::Ban,
            mask: TypedMask::parse("$n:troll")?,
        },
        ModeChange::AddMask {
            list: MaskList::Ban,
            mask: TypedMask::parse("$n:troll")?,
        },
    ];
    let entry_ids = [
        EntryId::from_bytes(bytes(90)),
        EntryId::from_bytes(bytes(91)),
    ];
    assert_eq!(
        validate_mode_vector(
            &fixture.state,
            channel,
            fixture.owner.user_id,
            &changes,
            &entry_ids
        )
        .err()
        .map(|error| format!("{error:?}")),
        Some("InvalidArgument".to_owned())
    );
    Ok(())
}

#[test]
fn a_membership_disagreeing_with_its_session_is_an_invariant_violation() -> Result<(), DomainError>
{
    let mut fixture = fixture()?;
    let nickname = fixture.member.nickname().clone();
    let channel = fixture
        .state
        .channels
        .get_mut(&fixture.channel_id)
        .ok_or(DomainError::NotFound)?;
    let membership = channel
        .memberships
        .get_mut(&fixture.member.user_id)
        .ok_or(DomainError::NotFound)?;
    membership.account_id = Some(account_id(77));
    let channel = fixture
        .state
        .channels
        .get(&fixture.channel_id)
        .ok_or(DomainError::NotFound)?;
    assert_eq!(
        resolve_mode_role_subject(&fixture.state, channel, &nickname).err(),
        Some(DomainError::InvariantViolation)
    );
    Ok(())
}

#[test]
fn a_registered_member_with_a_session_role_or_ungranted_role_is_an_invariant_violation()
-> Result<(), DomainError> {
    for (session_role, effective_role) in
        [(Role::Operator, Role::Member), (Role::Member, Role::Voice)]
    {
        let mut fixture = fixture()?;
        let nickname = fixture.member.nickname().clone();
        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::NotFound)?;
        register_channel_roles(channel);
        let membership = channel
            .memberships
            .get_mut(&fixture.member.user_id)
            .ok_or(DomainError::NotFound)?;
        membership.session_role = session_role;
        membership.effective_role = effective_role;
        let channel = fixture
            .state
            .channels
            .get(&fixture.channel_id)
            .ok_or(DomainError::NotFound)?;
        assert_eq!(
            resolve_mode_role_subject(&fixture.state, channel, &nickname).err(),
            Some(DomainError::InvariantViolation)
        );
    }
    Ok(())
}

#[test]
fn removal_finality_for_a_pending_user_who_is_not_a_member_is_bad_state() -> Result<(), DomainError>
{
    let mut fixture = fixture()?;
    let channel = fixture
        .state
        .channels
        .get_mut(&fixture.channel_id)
        .ok_or(DomainError::NotFound)?;
    channel.content_policy = ContentPolicy::E2eeBound;
    channel
        .e2ee_removal_pending
        .insert(fixture.outsider.user_id);
    let revision = channel.revision;
    let finality = E2eeRemovalFinality::new(fixture.channel_id, fixture.outsider.user_id, revision);
    assert_eq!(
        fixture.state.plan_e2ee_removal_finalized(finality).err(),
        Some(DomainError::BadState)
    );
    Ok(())
}

#[test]
fn join_requests_without_targets_request_nothing() -> Result<(), DomainError> {
    let fixture = fixture()?;
    let mut requests = Vec::new();
    fixture.state.join_requests(&[], &mut requests)?;
    assert!(requests.is_empty());
    Ok(())
}

#[test]
fn an_ephemeral_plan_that_would_write_is_an_invariant_violation() -> Result<(), DomainError> {
    let fixture = fixture()?;
    let mutations = vec![Mutation::Part {
        channel_id: fixture.channel_id,
        user_id: fixture.member.user_id,
    }];
    let revision = next_revision(fixture.state.revision)?;
    assert_eq!(
        fixture
            .state
            .durable_writes_for(&mutations, revision, StorageClass::Ephemeral)
            .err(),
        Some(DomainError::InvariantViolation)
    );
    Ok(())
}
