#![forbid(unsafe_code)]

//! Non-member admission to unlisted and secret channels, and channel-mode
//! authority for lower roles, driven through the public plan and apply surface.

use std::error::Error;

use agenc_ircd_domain::{
    AdmissionSnapshot, CanonicalCommand, ChannelKeyVerifier, ChannelNameValue, ChannelTarget,
    DomainError, DomainState, EntropyPurpose, ExternalInputRequest, ExternalInputs, MaskList,
    ModeChange, ModeOperation, NicknameValue, PlanDecision, Principal, RateBucket, Role,
    Visibility, VisibilityMode,
};
use agenc_ircd_testkit::{
    DomainTestIdentity, apply_plan, bytes, channel_id, create_account, open_session, plan,
};
use agenc_ircd_types::{
    AccountDeletionToken, EntryId, InviteId, MessageId, MonotonicTick, TypedMask, UtcSecond,
};

/// Builds one command; the builder runs again after external inputs are answered.
type Build<'a> = &'a dyn Fn() -> Result<CanonicalCommand, DomainError>;

/// Deterministic answers for the external-input requests of one command.
#[derive(Clone, Copy)]
struct Answers {
    /// Seed for the instance identity of a channel created by this command.
    channel_seed: u8,
    /// Verdict returned for every channel-key verification request.
    key_verdict: bool,
}

/// Answers for commands that create no channel and verify no key.
const PLAIN: Answers = Answers {
    channel_seed: 0,
    key_verdict: true,
};

/// Answers for a JOIN that creates the channel with the given instance seed.
const fn creating(channel_seed: u8) -> Answers {
    Answers {
        channel_seed,
        key_verdict: true,
    }
}

/// Answers for a keyed JOIN whose supplied key does not match.
const WRONG_KEY: Answers = Answers {
    channel_seed: 0,
    key_verdict: false,
};

/// Admission credit for one registered command plus one channel-key attempt.
fn admission(identity: DomainTestIdentity) -> Result<AdmissionSnapshot, DomainError> {
    let principal = identity
        .account_id
        .map_or(Principal::Guest(identity.user_id), Principal::Account);
    AdmissionSnapshot::new(vec![
        (RateBucket::RegisteredCommand(identity.user_id), 100),
        (RateBucket::ChannelKeyAttempt(principal), 100),
    ])
}

fn exact_inputs(requests: &[ExternalInputRequest], answers: Answers) -> ExternalInputs {
    let mut inputs = ExternalInputs::default();
    for request in requests {
        match request {
            ExternalInputRequest::UtcNow { .. } => {
                inputs.utc_now = Some(UtcSecond::from_unix_seconds(1_720_000_100));
            }
            ExternalInputRequest::MonotonicNow { .. } => {
                inputs.monotonic_now = Some(MonotonicTick::from_ticks(1));
            }
            ExternalInputRequest::Entropy { purpose, .. } => match purpose {
                EntropyPurpose::ChannelInstance(_) => {
                    inputs.channel_ids.push(channel_id(answers.channel_seed));
                }
                EntropyPurpose::Message(_) => {
                    inputs.message_ids.push(MessageId::from_bytes(bytes(2)));
                }
                EntropyPurpose::Invite => inputs.invite_ids.push(InviteId::from_bytes(bytes(3))),
                EntropyPurpose::MaskEntry(_) => {
                    inputs.entry_ids.push(EntryId::from_bytes(bytes(4)));
                }
                EntropyPurpose::AccountDeletionChallenge => inputs
                    .deletion_tokens
                    .push(AccountDeletionToken::from_bytes(bytes(5))),
            },
            ExternalInputRequest::ChannelKeyVerification { .. } => {
                inputs.key_verdicts.push(answers.key_verdict);
            }
            ExternalInputRequest::ChannelKeyConstruction { .. } => {
                inputs
                    .key_verifiers
                    .push(ChannelKeyVerifier::new(bytes(6), [7; 32]));
            }
        }
    }
    inputs
}

/// Plans one command, answering any external-input request vector once.
fn plan_auto(
    state: &DomainState,
    identity: DomainTestIdentity,
    answers: Answers,
    build: Build<'_>,
) -> Result<PlanDecision, DomainError> {
    let admission = admission(identity)?;
    match plan(state, identity, build()?, &admission, None)? {
        PlanDecision::NeedsExternal(requests) => plan(
            state,
            identity,
            build()?,
            &admission,
            Some(exact_inputs(&requests, answers)),
        ),
        decision => Ok(decision),
    }
}

/// Plans and applies one command that must produce a mutation.
fn apply_auto(
    state: &mut DomainState,
    identity: DomainTestIdentity,
    answers: Answers,
    build: Build<'_>,
) -> Result<(), Box<dyn Error>> {
    match plan_auto(state, identity, answers, build)? {
        PlanDecision::Mutation(mutation) => {
            apply_plan(state, mutation)?;
            Ok(())
        }
        PlanDecision::Rejected(rejected) => {
            let errors: Vec<DomainError> = rejected
                .failures()
                .iter()
                .map(|failure| failure.error())
                .collect();
            Err(format!("command was rejected: {errors:?}").into())
        }
        PlanDecision::NeedsExternal(_) | PlanDecision::Query(_) => {
            Err("command did not produce a mutation".into())
        }
    }
}

/// Checks that a plan was rejected with exactly one target failure carrying `expected`.
fn expect_rejected(decision: PlanDecision, expected: DomainError) -> Result<(), Box<dyn Error>> {
    let PlanDecision::Rejected(rejected) = decision else {
        return Err("expected a rejected plan".into());
    };
    let errors: Vec<DomainError> = rejected
        .failures()
        .iter()
        .map(|failure| failure.error())
        .collect();
    if errors != [expected] {
        return Err(format!("expected {expected:?}, got {errors:?}").into());
    }
    Ok(())
}

fn join(name: &ChannelNameValue, key: bool) -> impl Fn() -> Result<CanonicalCommand, DomainError> {
    let name = name.clone();
    move || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), key)])
}

fn member_role(
    state: &DomainState,
    name: &ChannelNameValue,
    user: DomainTestIdentity,
) -> Option<Role> {
    state
        .resolve_channel(name)
        .and_then(|id| state.channel(id))
        .and_then(|channel| channel.role_of(user.user_id))
}

fn member_count(state: &DomainState, name: &ChannelNameValue) -> Option<usize> {
    state
        .resolve_channel(name)
        .and_then(|id| state.channel(id))
        .map(agenc_ircd_domain::ChannelState::member_count)
}

/// One channel owner and one authenticated account that is a member of nothing.
fn owner_and_visitor()
-> Result<(DomainState, DomainTestIdentity, DomainTestIdentity), Box<dyn Error>> {
    let mut state = DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 1, 1)?;
    let owner = open_session(
        &mut state,
        1,
        "owner",
        Some((owner_account, owner_generation)),
    )?;
    let (visitor_account, visitor_generation) = create_account(&mut state, 2, 1)?;
    let visitor = open_session(
        &mut state,
        2,
        "visitor",
        Some((visitor_account, visitor_generation)),
    )?;
    Ok((state, owner, visitor))
}

/// Creates a channel as `owner` and switches it to the given discovery mode.
fn create_hidden_channel(
    state: &mut DomainState,
    owner: DomainTestIdentity,
    name: &str,
    channel_seed: u8,
    mode: VisibilityMode,
) -> Result<ChannelNameValue, Box<dyn Error>> {
    let name = ChannelNameValue::parse(name)?;
    apply_auto(state, owner, creating(channel_seed), &join(&name, false))?;
    apply_auto(state, owner, PLAIN, &|| {
        CanonicalCommand::mode(
            name.clone(),
            vec![ModeChange::Visibility {
                operation: ModeOperation::Add,
                mode,
            }],
        )
    })?;
    Ok(name)
}

#[test]
fn authenticated_non_member_join_of_hidden_channel_is_unavailable() -> Result<(), Box<dyn Error>> {
    let (mut state, owner, visitor) = owner_and_visitor()?;
    let secret = create_hidden_channel(&mut state, owner, "#secret", 10, VisibilityMode::Secret)?;
    let unlisted =
        create_hidden_channel(&mut state, owner, "#unlisted", 11, VisibilityMode::Unlisted)?;
    let secret_id = state
        .resolve_channel(&secret)
        .ok_or("secret channel missing")?;
    assert_eq!(
        state.channel(secret_id).map(|channel| channel.visibility()),
        Some(Visibility::Secret)
    );
    let guest = open_session(&mut state, 3, "guest", None)?;

    for name in [&secret, &unlisted] {
        expect_rejected(
            plan_auto(&state, guest, PLAIN, &join(name, false))?,
            DomainError::SecretUnavailable,
        )?;
        expect_rejected(
            plan_auto(&state, visitor, PLAIN, &join(name, false))?,
            DomainError::SecretUnavailable,
        )?;
        assert_eq!(member_count(&state, name), Some(1));
        assert_eq!(member_role(&state, name, visitor), None);
    }

    apply_auto(&mut state, owner, PLAIN, &|| {
        Ok(CanonicalCommand::invite(
            NicknameValue::parse("visitor")?,
            secret.clone(),
        ))
    })?;
    apply_auto(&mut state, visitor, PLAIN, &join(&secret, false))?;
    assert_eq!(member_role(&state, &secret, visitor), Some(Role::Member));
    assert_eq!(member_count(&state, &secret), Some(2));

    apply_auto(&mut state, owner, PLAIN, &|| {
        CanonicalCommand::mode(
            unlisted.clone(),
            vec![ModeChange::AddMask {
                list: MaskList::InviteException,
                mask: TypedMask::parse("$n:visitor")?,
            }],
        )
    })?;
    apply_auto(&mut state, visitor, PLAIN, &join(&unlisted, false))?;
    assert_eq!(member_role(&state, &unlisted, visitor), Some(Role::Member));
    assert_eq!(member_count(&state, &unlisted), Some(2));
    state.validate()?;
    Ok(())
}

#[test]
fn hidden_channel_join_admits_only_the_verified_channel_key() -> Result<(), Box<dyn Error>> {
    let (mut state, owner, visitor) = owner_and_visitor()?;
    let vault = create_hidden_channel(&mut state, owner, "#vault", 12, VisibilityMode::Secret)?;

    expect_rejected(
        plan_auto(&state, visitor, PLAIN, &join(&vault, true))?,
        DomainError::SecretUnavailable,
    )?;

    apply_auto(&mut state, owner, PLAIN, &|| {
        CanonicalCommand::mode(vault.clone(), vec![ModeChange::JoinKey(true)])
    })?;
    expect_rejected(
        plan_auto(&state, visitor, PLAIN, &join(&vault, false))?,
        DomainError::SecretUnavailable,
    )?;
    expect_rejected(
        plan_auto(&state, visitor, WRONG_KEY, &join(&vault, true))?,
        DomainError::SecretUnavailable,
    )?;
    assert_eq!(member_role(&state, &vault, visitor), None);

    apply_auto(&mut state, visitor, PLAIN, &join(&vault, true))?;
    assert_eq!(member_role(&state, &vault, visitor), Some(Role::Member));
    assert_eq!(member_count(&state, &vault), Some(2));
    state.validate()?;
    Ok(())
}
