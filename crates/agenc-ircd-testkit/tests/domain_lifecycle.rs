#![forbid(unsafe_code)]

//! Stage-03 identity, fencing, lifecycle, and apply-once tests.

use std::error::Error;

use agenc_ircd_domain::{
    CanonicalCommand, CommandEnvelope, DomainError, NicknameValue, PlanDecision, PresenceCommand,
};

use agenc_ircd_testkit::{
    apply_command, authorize, create_account, generation, open_session, plan, registered_admission,
    revision,
};

#[test]
fn identities_stay_separate_and_nicknames_are_reusable_after_quit() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (account_id, account_generation) = create_account(&mut state, 1, 7)?;
    let alice = open_session(
        &mut state,
        1,
        "Alice",
        Some((account_id, account_generation)),
    )?;
    let laptop = open_session(
        &mut state,
        2,
        "AliceLaptop",
        Some((account_id, account_generation)),
    )?;

    assert_ne!(alice.session_id, laptop.session_id);
    assert_ne!(alice.user_id, laptop.user_id);
    assert_eq!(state.account_count(), 1);
    assert_eq!(state.session_count(), 2);
    let alice_state = state.session(alice.user_id).ok_or("Alice is missing")?;
    let laptop_state = state.session(laptop.user_id).ok_or("laptop is missing")?;
    assert_eq!(alice_state.account_id(), laptop_state.account_id());
    assert_ne!(
        alice_state.public_cloak().host_component(),
        laptop_state.public_cloak().host_component()
    );
    assert_ne!(
        alice_state.connection_nonce(),
        laptop_state.connection_nonce()
    );

    let admission = registered_admission(alice.user_id)?;
    apply_command(
        &mut state,
        alice,
        CanonicalCommand::nick(NicknameValue::parse("AliceNew")?),
        &admission,
        None,
    )?;
    assert_eq!(
        state
            .session(alice.user_id)
            .ok_or("renamed session is missing")?
            .nickname()
            .canonical(),
        "alicenew"
    );
    assert_eq!(
        state.resolve_nickname(&NicknameValue::parse("Alice")?),
        None
    );

    let laptop_admission = registered_admission(laptop.user_id)?;
    apply_command(
        &mut state,
        laptop,
        CanonicalCommand::quit(None),
        &laptop_admission,
        None,
    )?;
    let replacement = open_session(&mut state, 3, "AliceLaptop", None)?;
    assert_ne!(replacement.user_id, laptop.user_id);
    assert_eq!(
        state.resolve_nickname(&NicknameValue::parse("AliceLaptop")?),
        Some(replacement.user_id)
    );
    state.validate()?;
    Ok(())
}

#[test]
fn stale_generation_revision_and_prepared_plans_are_rejected() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let alice = open_session(&mut state, 4, "FenceAlice", None)?;
    let admission = registered_admission(alice.user_id)?;

    let stale_generation = CommandEnvelope::new(
        alice.session_id,
        alice.user_id,
        generation(0)?,
        state.revision(),
        CanonicalCommand::nick(NicknameValue::parse("NeverApplied")?),
    );
    let failure = state
        .authorize(stale_generation, &admission)
        .err()
        .ok_or("stale generation was accepted")?;
    assert_eq!(failure.error(), DomainError::StaleGeneration);
    assert!(!failure.charges().is_empty());

    let stale_revision = CommandEnvelope::new(
        alice.session_id,
        alice.user_id,
        alice.generation,
        revision(0)?,
        CanonicalCommand::nick(NicknameValue::parse("StillNotApplied")?),
    );
    let failure = state
        .authorize(stale_revision, &admission)
        .err()
        .ok_or("stale revision was accepted")?;
    assert_eq!(failure.error(), DomainError::StaleRevision);

    let decision = plan(
        &state,
        alice,
        CanonicalCommand::presence(PresenceCommand::Away(None))?,
        &admission,
        None,
    )?;
    let PlanDecision::Mutation(stale_plan) = decision else {
        return Err("away did not produce a mutation".into());
    };
    let stale_prepared = state.prepare_mutation(stale_plan)?;

    apply_command(
        &mut state,
        alice,
        CanonicalCommand::nick(NicknameValue::parse("RevisionWinner")?),
        &admission,
        None,
    )?;
    assert_eq!(
        state.apply_prepared(stale_prepared).err(),
        Some(DomainError::StaleRevision)
    );
    assert_eq!(
        state
            .session(alice.user_id)
            .ok_or("Alice is missing")?
            .nickname()
            .canonical(),
        "revisionwinner"
    );

    let admitted = authorize(
        &state,
        alice,
        CanonicalCommand::presence(PresenceCommand::Away(None))?,
        &admission,
    )?;
    assert_eq!(admitted.user_id(), alice.user_id);
    state.validate()?;
    Ok(())
}

#[test]
fn account_switch_and_deletion_are_generation_fenced_pure_plans() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_ircd_domain::DomainState::new()?;
    let (first_account, first_generation) = create_account(&mut state, 6, 11)?;
    let (second_account, second_generation) = create_account(&mut state, 7, 12)?;
    let session = open_session(
        &mut state,
        6,
        "SwitchingUser",
        Some((first_account, first_generation)),
    )?;

    assert_eq!(
        state
            .plan_session_account_switch(
                session.user_id,
                generation(0)?,
                Some((second_account, second_generation)),
            )
            .err(),
        Some(DomainError::StaleGeneration)
    );
    let switch = state.plan_session_account_switch(
        session.user_id,
        session.generation,
        Some((second_account, second_generation)),
    )?;
    support_apply_plan(&mut state, switch)?;
    let switched = state
        .session(session.user_id)
        .ok_or("switched session is missing")?;
    assert_eq!(switched.account_id(), Some(second_account));
    assert_eq!(switched.generation().get(), 2);

    assert_eq!(
        state
            .plan_account_deleted(second_account, generation(0)?)
            .err(),
        Some(DomainError::StaleGeneration)
    );
    let deletion = state.plan_account_deleted(second_account, second_generation)?;
    support_apply_plan(&mut state, deletion)?;
    assert!(state.account(second_account).is_none());
    assert!(state.session(session.user_id).is_none());
    assert!(state.account(first_account).is_some());
    state.validate()?;
    Ok(())
}

fn support_apply_plan(
    state: &mut agenc_ircd_domain::DomainState,
    plan: agenc_ircd_domain::MutationPlan,
) -> Result<(), DomainError> {
    agenc_ircd_testkit::apply_plan(state, plan)?;
    Ok(())
}
