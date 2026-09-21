#![forbid(unsafe_code)]

//! Stage-03 identity, fencing, lifecycle, and apply-once tests.

use std::error::Error;

use agenc_relay_domain::{
    AccountCommand, CanonicalCommand, CommandEnvelope, DisplayNameValue, DomainError,
    ExternalInputs, NicknameValue, PlanDecision, PresenceCommand, SessionSeed,
};

use agenc_relay_testkit::{
    apply_command, apply_plan, authorize, bytes, create_account, generation, open_session, plan,
    registered_admission, revision,
};
use agenc_relay_types::{
    AccountDeletionToken, MonotonicTick, Revision, ServerId, SessionId, UserId, UtcSecond,
};

#[test]
fn identities_stay_separate_and_nicknames_are_reusable_after_quit() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_relay_domain::DomainState::new()?;
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
    let mut state = agenc_relay_domain::DomainState::new()?;
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
    let mut state = agenc_relay_domain::DomainState::new()?;
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
    assert_eq!(
        state
            .plan_session_account_switch(
                session.user_id,
                session.generation,
                Some((second_account, second_generation)),
            )
            .err(),
        Some(DomainError::BadState)
    );
    let logout = state.plan_session_account_switch(session.user_id, session.generation, None)?;
    support_apply_plan(&mut state, logout)?;
    let guest_generation = state
        .session(session.user_id)
        .ok_or("logged-out session is missing")?
        .generation();
    let switch = state.plan_session_account_switch(
        session.user_id,
        guest_generation,
        Some((second_account, second_generation)),
    )?;
    support_apply_plan(&mut state, switch)?;
    let switched = state
        .session(session.user_id)
        .ok_or("switched session is missing")?;
    assert_eq!(switched.account_id(), Some(second_account));
    assert_eq!(switched.generation().get(), 3);

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

#[test]
fn session_open_rejects_a_live_public_cloak_collision_without_state_change()
-> Result<(), Box<dyn Error>> {
    let mut state = agenc_relay_domain::DomainState::new()?;
    let first = open_session(&mut state, 17, "FirstCloakOwner", None)?;
    let public_cloak = state
        .session(first.user_id)
        .ok_or("first session is missing")?
        .public_cloak();
    let before_revision = state.revision();
    let before_sessions = state.session_count();
    let colliding_nickname = NicknameValue::parse("CollidingCloak")?;

    let result = state.plan_session_opened(SessionSeed {
        session_id: SessionId::from_bytes(bytes(18)),
        user_id: UserId::from_bytes(bytes(82)),
        home_server_id: ServerId::from_bytes(bytes(240)),
        account_id: None,
        account_session_generation: generation(0)?,
        generation: generation(1)?,
        nickname: colliding_nickname.clone(),
        display_name: DisplayNameValue::prepare("Colliding Cloak")?,
        public_cloak,
        connection_nonce: [18; 32],
        negotiated_capability_hash: [19; 32],
        created_at_utc: UtcSecond::from_unix_seconds(1_700_000_018),
        revision: Revision::new(before_revision.get())?,
    });

    assert_eq!(result.err(), Some(DomainError::BadState));
    assert_eq!(state.revision(), before_revision);
    assert_eq!(state.session_count(), before_sessions);
    assert_eq!(state.resolve_nickname(&colliding_nickname), None);
    state.validate()?;
    Ok(())
}

#[test]
fn a_public_cloak_can_be_reused_only_after_its_live_session_closes() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_relay_domain::DomainState::new()?;
    let first = open_session(&mut state, 19, "ClosingCloakOwner", None)?;
    let public_cloak = state
        .session(first.user_id)
        .ok_or("first session is missing")?
        .public_cloak();

    apply_command(
        &mut state,
        first,
        CanonicalCommand::quit(None),
        &registered_admission(first.user_id)?,
        None,
    )?;
    assert!(state.session(first.user_id).is_none());

    let replacement_user = UserId::from_bytes(bytes(84));
    let plan = state.plan_session_opened(SessionSeed {
        session_id: SessionId::from_bytes(bytes(20)),
        user_id: replacement_user,
        home_server_id: ServerId::from_bytes(bytes(240)),
        account_id: None,
        account_session_generation: generation(0)?,
        generation: generation(1)?,
        nickname: NicknameValue::parse("ReplacementCloakOwner")?,
        display_name: DisplayNameValue::prepare("Replacement Cloak Owner")?,
        public_cloak,
        connection_nonce: [20; 32],
        negotiated_capability_hash: [21; 32],
        created_at_utc: UtcSecond::from_unix_seconds(1_700_000_020),
        revision: state.revision(),
    })?;
    support_apply_plan(&mut state, plan)?;

    assert!(
        state
            .session(replacement_user)
            .ok_or("replacement session is missing")?
            .public_cloak()
            == public_cloak
    );
    state.validate()?;
    Ok(())
}

fn support_apply_plan(
    state: &mut agenc_relay_domain::DomainState,
    plan: agenc_relay_domain::MutationPlan,
) -> Result<(), DomainError> {
    agenc_relay_testkit::apply_plan(state, plan)?;
    Ok(())
}

#[test]
fn fresh_auth_and_deletion_start_reject_each_public_fence() -> Result<(), Box<dyn Error>> {
    let mut state = agenc_relay_domain::DomainState::new()?;
    let (account, account_generation) = create_account(&mut state, 10, 4)?;
    let (other_account, _) = create_account(&mut state, 11, 9)?;
    let identity = open_session(
        &mut state,
        10,
        "FreshAuthGuard",
        Some((account, account_generation)),
    )?;

    assert_eq!(
        state
            .plan_session_fresh_authentication(
                identity.user_id,
                other_account,
                identity.generation,
                MonotonicTick::from_ticks(100),
            )
            .err(),
        Some(DomainError::Forbidden)
    );
    assert_eq!(
        state
            .plan_session_fresh_authentication(
                identity.user_id,
                account,
                generation(99)?,
                MonotonicTick::from_ticks(100),
            )
            .err(),
        Some(DomainError::StaleGeneration)
    );

    let delete = CanonicalCommand::account(AccountCommand::DeleteStart);
    let delete_inputs = ExternalInputs {
        monotonic_now: Some(MonotonicTick::from_ticks(100)),
        deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(12))],
        ..ExternalInputs::default()
    };
    assert_eq!(
        plan(
            &state,
            identity,
            delete,
            &registered_admission(identity.user_id)?,
            Some(delete_inputs),
        )
        .err(),
        Some(DomainError::BadState)
    );

    let fresh = state.plan_session_fresh_authentication(
        identity.user_id,
        account,
        identity.generation,
        MonotonicTick::from_ticks(200),
    )?;
    apply_plan(&mut state, fresh)?;
    assert_eq!(
        plan(
            &state,
            identity,
            CanonicalCommand::account(AccountCommand::DeleteStart),
            &registered_admission(identity.user_id)?,
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(300_201)),
                deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(13))],
                ..ExternalInputs::default()
            }),
        )
        .err(),
        Some(DomainError::BadState)
    );
    state.validate()?;
    Ok(())
}
