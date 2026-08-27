#![forbid(unsafe_code)]

//! Stage-04 account-authentication intents applied through the public domain boundary.

use std::error::Error;

use agenc_ircd_domain::{
    CanonicalCommand, ChannelNameValue, ChannelTarget, DomainError, DomainEvent, DomainState,
    ExternalInputRequest, ExternalInputs, MAX_SESSIONS_PER_ACCOUNT, PlanDecision, StorageClass,
};
use agenc_ircd_testkit::{
    apply_command, apply_plan, channel_id, create_account, generation, open_session, plan,
    registered_admission, revision,
};
use agenc_ircd_types::{AccountRandomId, MonotonicTick, UtcSecond};

fn join_new_channel(
    state: &mut DomainState,
    identity: agenc_ircd_testkit::DomainTestIdentity,
) -> Result<(), DomainError> {
    let admission = registered_admission(identity.user_id)?;
    let command = || {
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse("#deletion-fence")?,
            false,
        )])
    };
    let PlanDecision::NeedsExternal(requests) =
        plan(state, identity, command()?, &admission, None)?
    else {
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
        command()?,
        &admission,
        Some(ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1_700_200_000)),
            channel_ids: vec![channel_id(158)],
            ..ExternalInputs::default()
        }),
    )?;
    Ok(())
}

#[test]
fn credential_replacement_rejects_every_stale_or_incomplete_snapshot() -> Result<(), Box<dyn Error>>
{
    let mut empty = DomainState::new()?;
    let (empty_account, empty_generation) = create_account(&mut empty, 150, 4)?;
    let empty_revision = empty
        .account(empty_account)
        .ok_or("new account is absent")?
        .revision();
    assert_eq!(
        empty
            .plan_account_credential_replaced(empty_account, empty_generation, empty_revision,)
            .err(),
        Some(DomainError::BadState)
    );

    let mut state = DomainState::new()?;
    let (account_id, account_generation) = create_account(&mut state, 151, 7)?;
    let account_revision = state
        .account(account_id)
        .ok_or("credential account is absent")?
        .revision();
    let first = open_session(
        &mut state,
        152,
        "CredentialFirst",
        Some((account_id, account_generation)),
    )?;
    let second = open_session(
        &mut state,
        153,
        "CredentialSecond",
        Some((account_id, account_generation)),
    )?;

    assert_eq!(
        state
            .plan_account_credential_replaced(
                account_id,
                generation(account_generation.get() - 1)?,
                account_revision,
            )
            .err(),
        Some(DomainError::StaleGeneration)
    );
    assert_eq!(
        state
            .plan_account_credential_replaced(
                account_id,
                account_generation,
                revision(account_revision.get() - 1)?,
            )
            .err(),
        Some(DomainError::StaleRevision)
    );
    assert_eq!(
        state
            .plan_account_credential_replaced(
                AccountRandomId::from_bytes([154_u8; 16]).to_account_id(),
                account_generation,
                account_revision,
            )
            .err(),
        Some(DomainError::NotFound)
    );

    let (plan, next_generation) =
        state.plan_account_credential_replaced(account_id, account_generation, account_revision)?;
    assert_eq!(next_generation.get(), account_generation.get() + 1);
    assert_eq!(plan.storage_class(), StorageClass::Durable);
    assert_eq!(
        plan.events(),
        [
            DomainEvent::AccountCredentialReplaced(account_id),
            DomainEvent::SessionHidden(first.user_id),
            DomainEvent::SessionHidden(second.user_id),
        ]
    );
    apply_plan(&mut state, plan)?;
    assert!(state.session(first.user_id).is_none());
    assert!(state.session(second.user_id).is_none());
    assert_eq!(
        state
            .account(account_id)
            .ok_or("credential account disappeared")?
            .session_generation(),
        next_generation
    );
    Ok(())
}

#[test]
fn deletion_confirmation_rechecks_account_revision_at_the_public_boundary()
-> Result<(), Box<dyn Error>> {
    let mut state = DomainState::new()?;
    let (account_id, account_generation) = create_account(&mut state, 155, 9)?;
    let account_revision = state
        .account(account_id)
        .ok_or("deletion account is absent")?
        .revision();
    let session = open_session(
        &mut state,
        156,
        "DeletionOwner",
        Some((account_id, account_generation)),
    )?;

    assert_eq!(
        state
            .plan_account_deleted_at_revision(
                AccountRandomId::from_bytes([157_u8; 16]).to_account_id(),
                account_generation,
                account_revision,
            )
            .err(),
        Some(DomainError::NotFound)
    );
    assert_eq!(
        state
            .plan_account_deleted_at_revision(
                account_id,
                account_generation,
                revision(account_revision.get() - 1)?,
            )
            .err(),
        Some(DomainError::StaleRevision)
    );
    assert_eq!(
        state
            .plan_account_deleted_at_revision(
                account_id,
                generation(account_generation.get() - 1)?,
                account_revision,
            )
            .err(),
        Some(DomainError::StaleGeneration)
    );

    let plan =
        state.plan_account_deleted_at_revision(account_id, account_generation, account_revision)?;
    assert_eq!(plan.events(), [DomainEvent::AccountDeleted(account_id)]);
    apply_plan(&mut state, plan)?;
    assert!(state.account(account_id).is_none());
    assert!(state.session(session.user_id).is_none());
    Ok(())
}

#[test]
fn deletion_requires_one_channel_free_confirming_session() -> Result<(), Box<dyn Error>> {
    let mut state = DomainState::new()?;
    let (account_id, account_generation) = create_account(&mut state, 158, 3)?;
    let account_revision = state
        .account(account_id)
        .ok_or("deletion precondition account is absent")?
        .revision();
    assert_eq!(
        state
            .plan_account_deleted_at_revision(account_id, account_generation, account_revision,)
            .err(),
        Some(DomainError::BadState)
    );

    let owner = open_session(
        &mut state,
        158,
        "DeletionChannelOwner",
        Some((account_id, account_generation)),
    )?;
    join_new_channel(&mut state, owner)?;
    assert_eq!(
        state
            .plan_account_deleted_at_revision(account_id, account_generation, account_revision,)
            .err(),
        Some(DomainError::BadState)
    );
    Ok(())
}

#[test]
fn account_switch_refuses_the_next_session_after_the_exact_account_limit()
-> Result<(), Box<dyn Error>> {
    let mut state = DomainState::new()?;
    let (account_id, account_generation) = create_account(&mut state, 159, 5)?;
    for index in 0..MAX_SESSIONS_PER_ACCOUNT {
        let seed = u8::try_from(160 + index)?;
        open_session(
            &mut state,
            seed,
            &format!("BoundedSession{index}"),
            Some((account_id, account_generation)),
        )?;
    }
    let guest = open_session(&mut state, 200, "OverflowGuest", None)?;
    assert_eq!(
        state
            .plan_session_account_switch(
                guest.user_id,
                guest.generation,
                Some((account_id, account_generation)),
            )
            .err(),
        Some(DomainError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn account_switch_checks_both_generation_fences_and_allows_current_authority()
-> Result<(), Box<dyn Error>> {
    let mut state = DomainState::new()?;
    let (account_id, account_generation) = create_account(&mut state, 201, 6)?;
    let session = open_session(
        &mut state,
        202,
        "SwitchFenceOwner",
        Some((account_id, account_generation)),
    )?;

    assert_eq!(
        state
            .plan_session_account_switch(
                session.user_id,
                generation(session.generation.get() - 1)?,
                Some((account_id, account_generation)),
            )
            .err(),
        Some(DomainError::StaleGeneration)
    );
    assert_eq!(
        state
            .plan_session_account_switch(
                session.user_id,
                session.generation,
                Some((account_id, generation(account_generation.get() - 1)?)),
            )
            .err(),
        Some(DomainError::StaleGeneration)
    );

    assert_eq!(
        state
            .plan_session_account_switch(
                session.user_id,
                session.generation,
                Some((account_id, account_generation)),
            )
            .err(),
        Some(DomainError::BadState)
    );
    let fresh = state.plan_session_fresh_authentication(
        session.user_id,
        account_id,
        session.generation,
        MonotonicTick::from_ticks(100),
    )?;
    assert!(fresh.events().is_empty());
    apply_plan(&mut state, fresh)?;
    let reauthenticated = state
        .session(session.user_id)
        .ok_or("reauthenticated session is missing")?;
    assert_eq!(reauthenticated.generation(), session.generation);
    assert_eq!(
        reauthenticated.fresh_auth_deadline(),
        Some(MonotonicTick::from_ticks(300_100))
    );

    let guest = state.plan_session_account_switch(session.user_id, session.generation, None)?;
    assert_eq!(
        guest.events(),
        [DomainEvent::SessionAuthorityChanged(session.user_id)]
    );
    Ok(())
}

#[test]
fn command_application_refuses_an_unresolved_external_input_request() -> Result<(), Box<dyn Error>>
{
    let mut state = DomainState::new()?;
    let guest = open_session(&mut state, 203, "UnresolvedJoin", None)?;
    let admission = registered_admission(guest.user_id)?;
    let command = CanonicalCommand::join(vec![ChannelTarget::new(
        ChannelNameValue::parse("#needs-channel-id")?,
        false,
    )])?;
    assert_eq!(
        apply_command(&mut state, guest, command, &admission, None).err(),
        Some(DomainError::BadState)
    );
    Ok(())
}
