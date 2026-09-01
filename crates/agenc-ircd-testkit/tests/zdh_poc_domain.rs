//! zeroday-hunter PoC battery: domain authorization findings (campaign ircd-2026-09-01).
//!
//! ZDH-C1: authenticated non-member JOIN of a Secret/Unlisted channel succeeds
//!         (missing visibility admission gate) — spec 13.5 violation.
//! ZDH-C2: HalfOperator can set the member limit (+l), an Operator-only mode per
//!         spec 13.2, enabling founder lockout of a registered channel.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_domain::{
    CanonicalCommand, ChannelTarget, DomainError, EntropyPurpose, ExternalInputRequest,
    ExternalInputs, ModeChange, ModeOperation, PlanDecision,
};
use agenc_ircd_testkit::{
    apply_plan, bytes, channel_id, create_account, open_session, plan, registered_admission,
};
use agenc_ircd_types::{MonotonicTick, UtcSecond};

/// Plans a command, answering any external-input request deterministically.
/// The command builder may run twice when external inputs are requested.
fn plan_auto(
    state: &agenc_ircd_domain::DomainState,
    identity: agenc_ircd_testkit::DomainTestIdentity,
    build: &dyn Fn() -> Result<CanonicalCommand, DomainError>,
) -> Result<PlanDecision, Box<dyn Error>> {
    let admission = registered_admission(identity.user_id)?;
    let first = build().map_err(Box::<dyn Error>::from)?;
    match plan(state, identity, first, &admission, None)? {
        PlanDecision::NeedsExternal(requests) => {
            let inputs = exact_inputs(&requests)?;
            let second = build().map_err(Box::<dyn Error>::from)?;
            Ok(plan(state, identity, second, &admission, Some(inputs))?)
        }
        decision => Ok(decision),
    }
}

fn exact_inputs(requests: &[ExternalInputRequest]) -> Result<ExternalInputs, Box<dyn Error>> {
    let mut inputs = ExternalInputs::default();
    let mut channel_seed = 9_u8;
    for request in requests {
        match request {
            ExternalInputRequest::UtcNow { .. } => {
                inputs.utc_now = Some(UtcSecond::from_unix_seconds(1_700_000_100));
            }
            ExternalInputRequest::MonotonicNow { .. } => {
                inputs.monotonic_now = Some(MonotonicTick::from_ticks(1));
            }
            ExternalInputRequest::Entropy { purpose, .. } => match purpose {
                EntropyPurpose::ChannelInstance(_) => {
                    channel_seed = channel_seed.wrapping_add(1);
                    inputs.channel_ids.push(channel_id(channel_seed));
                }
                EntropyPurpose::Message(_) => inputs
                    .message_ids
                    .push(agenc_ircd_types::MessageId::from_bytes(bytes(2))),
                EntropyPurpose::Invite => inputs
                    .invite_ids
                    .push(agenc_ircd_types::InviteId::from_bytes(bytes(3))),
                EntropyPurpose::MaskEntry(_) => inputs
                    .entry_ids
                    .push(agenc_ircd_types::EntryId::from_bytes(bytes(4))),
                EntropyPurpose::AccountDeletionChallenge => inputs
                    .deletion_tokens
                    .push(agenc_ircd_types::AccountDeletionToken::from_bytes(bytes(5))),
            },
            ExternalInputRequest::ChannelKeyVerification { .. } => {
                inputs.key_verdicts.push(true);
            }
        }
    }
    Ok(inputs)
}

/// Authorizes, plans (auto-external), applies, and validates one command.
fn apply_auto(
    state: &mut agenc_ircd_domain::DomainState,
    identity: agenc_ircd_testkit::DomainTestIdentity,
    label: &str,
    build: &dyn Fn() -> Result<CanonicalCommand, DomainError>,
) -> Result<(), Box<dyn Error>> {
    match plan_auto(state, identity, build).map_err(|e| format!("{label}: {e:?}"))? {
        PlanDecision::Mutation(plan) => {
            apply_plan(state, plan)?;
            Ok(())
        }
        _ => Err("expected mutation".into()),
    }
}

#[test]
fn zdh_c1_authenticated_non_member_joins_secret_channel() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 1, 1)?;
    let owner = open_session(
        &mut state,
        1,
        "owner",
        Some((owner_account, owner_generation)),
    )?;

    // Owner creates #hidden (default visibility) then marks it Secret (+s).
    let hidden = agenc_ircd_domain::ChannelNameValue::parse("#hidden")?;
    apply_auto(&mut state, owner, "owner-join-hidden", &|| {
        CanonicalCommand::join(vec![ChannelTarget::new(hidden.clone(), false)])
    })?;
    apply_auto(&mut state, owner, "owner-mode-secret", &|| {
        CanonicalCommand::mode(
            hidden.clone(),
            vec![ModeChange::Visibility {
                operation: ModeOperation::Add,
                mode: agenc_ircd_domain::VisibilityMode::Secret,
            }],
        )
    })?;
    let hidden_id = state.resolve_channel(&hidden).ok_or("channel missing")?;
    assert_eq!(
        state.channel(hidden_id).map(|c| c.visibility()),
        Some(agenc_ircd_domain::Visibility::Secret)
    );

    // Negative control: a GUEST is refused with SecretUnavailable.
    let guest = open_session(&mut state, 3, "guest", None)?;
    match plan_auto(&state, guest, &|| {
        CanonicalCommand::join(vec![ChannelTarget::new(hidden.clone(), false)])
    })? {
        PlanDecision::Rejected(rejected) => assert_eq!(
            rejected.failures().first().map(|f| f.error()),
            Some(DomainError::SecretUnavailable)
        ),
        _ => return Err("guest control: expected rejection".into()),
    }

    // VULN DEMO: an authenticated non-member (any registered account) JOINs the
    // Secret channel and becomes a member. Spec 13.5 requires the same
    // SecretUnavailable refusal that guests get.
    let (eve_account, eve_generation) = create_account(&mut state, 2, 1)?;
    let eve = open_session(&mut state, 2, "eve", Some((eve_account, eve_generation)))?;
    apply_auto(&mut state, eve, "eve-join-hidden", &|| {
        CanonicalCommand::join(vec![ChannelTarget::new(hidden.clone(), false)])
    })?;
    assert_eq!(
        state
            .channel(hidden_id)
            .and_then(|c| c.role_of(eve.user_id)),
        Some(agenc_ircd_domain::Role::Member),
        "ZDH-C1: eve must not be a member of the Secret channel"
    );
    assert_eq!(state.channel(hidden_id).map(|c| c.member_count()), Some(2));
    Ok(())
}

#[test]
fn zdh_c2_halfop_member_limit_locks_out_founder() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (owner_account, owner_generation) = create_account(&mut state, 1, 1)?;
    let owner = open_session(
        &mut state,
        1,
        "owner",
        Some((owner_account, owner_generation)),
    )?;
    let (eve_account, eve_generation) = create_account(&mut state, 2, 1)?;
    let eve = open_session(&mut state, 2, "eve", Some((eve_account, eve_generation)))?;

    let lock = agenc_ircd_domain::ChannelNameValue::parse("#lock")?;
    apply_auto(&mut state, owner, "owner-join", &|| {
        CanonicalCommand::join(vec![ChannelTarget::new(lock.clone(), false)])
    })?;
    apply_auto(&mut state, eve, "eve-join", &|| {
        CanonicalCommand::join(vec![ChannelTarget::new(lock.clone(), false)])
    })?;

    // Negative control: plain Member cannot set +l (authorization itself
    // refuses, which may surface as Err or as a rejected plan).
    match plan_auto(&state, eve, &|| {
        CanonicalCommand::mode(lock.clone(), vec![ModeChange::MemberLimit(Some(1))])
    }) {
        Err(error) => assert!(
            error.to_string().contains("Forbidden") || format!("{error:?}").contains("Forbidden"),
            "member control: expected Forbidden, got {error:?}"
        ),
        Ok(PlanDecision::Rejected(rejected)) => assert_eq!(
            rejected.failures().first().map(|f| f.error()),
            Some(DomainError::Forbidden)
        ),
        Ok(_) => return Err("member control: expected Forbidden".into()),
    }

    // Owner grants HalfOperator, then parts; eve is the only member left.
    apply_auto(&mut state, owner, "grant-halfop", &|| {
        CanonicalCommand::mode(
            lock.clone(),
            vec![ModeChange::Role {
                operation: ModeOperation::Add,
                target: agenc_ircd_domain::NicknameValue::parse("eve")?,
                role: agenc_ircd_domain::Role::HalfOperator,
            }],
        )
    })?;
    apply_auto(&mut state, owner, "owner-part", &|| {
        CanonicalCommand::part(vec![lock.clone()], None)
    })?;

    // VULN DEMO: HalfOperator sets +l 1 (Operator-only per spec 13.2). The
    // mutation applies without error; the installed limit is proven below by
    // the founder's rejected rejoin.
    apply_auto(&mut state, eve, "eve-set-limit", &|| {
        CanonicalCommand::mode(lock.clone(), vec![ModeChange::MemberLimit(Some(1))])
    })?;

    // Founder (still the channel Owner by grant) cannot rejoin: locked out.
    match plan_auto(&state, owner, &|| {
        CanonicalCommand::join(vec![ChannelTarget::new(lock.clone(), false)])
    })? {
        PlanDecision::Rejected(rejected) => assert_eq!(
            rejected.failures().first().map(|f| f.error()),
            Some(DomainError::LimitExceeded)
        ),
        _ => return Err("ZDH-C2: founder rejoin should fail".into()),
    }
    Ok(())
}
