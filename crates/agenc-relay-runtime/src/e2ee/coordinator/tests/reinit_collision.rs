//! ReInit cannot replace the authority of an already bound normal route.

#![forbid(unsafe_code)]

use super::*;
use agenc_relay_e2ee::objects::reinit::{
    ArcReInitAck, ArcReInitActivationCoreTbs, ArcReInitActivationRequest, ArcReInitAttempt,
};

#[test]
fn partial_retained_successor_state_cannot_be_reused() -> TestResult {
    for representation in 0..3 {
        let mut fixture = Harness::new()?;
        let old = fixture.bind_channel()?;
        let target = other_binding(&fixture)?.conversation;
        fixture.finalize_reinit_to(old, OTHER_GROUP)?;
        let attempt = successor_attempt(&fixture, old, target)?;
        let bytes = wire(ArcWireObjectKind::ReinitAttempt, &attempt)?;
        let normal = ok(evaluate_request(
            &mut fixture,
            Op::SubmitReinitAttempt,
            &old,
            Some(&bytes),
        )?)?;
        assert!(matches!(normal.result, ResultBody::ReinitStaged(..)));
        let state = &mut fixture.coordinator.state;
        match representation {
            0 => {
                state
                    .conversations
                    .insert(target, ConversationState::default());
            }
            1 => {
                state
                    .logs
                    .insert(target, SequencerLog::genesis(target, [1; 32]));
            }
            _ => {
                state.lifecycles.insert(target, Lifecycle::successor());
            }
        }
        let before = retained_state(&fixture)?;
        assert_route_refused(evaluate_request(
            &mut fixture,
            Op::SubmitReinitAttempt,
            &old,
            Some(&bytes),
        )?)?;
        assert_eq!(retained_state(&fixture)?, before);
    }
    Ok(())
}

/// The attempt for the successor on `#other`'s group that the finalized
/// ReInit Commit of `old` authorized.
fn successor_attempt(
    fixture: &Harness,
    old: [u8; 32],
    target: [u8; 32],
) -> TestResult<ArcReInitAttempt> {
    let state = *fixture
        .coordinator
        .state
        .logs
        .get(&old)
        .ok_or("old log")?
        .accepted_state_id();
    let (attempt, _) = super::super::super::reinit::attempt(fixture, old, state, 0)?;
    assert_eq!(attempt.tbs.new_conversation_id, target);
    Ok(attempt)
}

fn successor_activation(
    fixture: &Harness,
    old: [u8; 32],
    attempt: ArcReInitAttempt,
) -> TestResult<Vec<u8>> {
    let receipt = super::super::super::reinit::staged_receipt(fixture, old)?;
    let state = receipt.tbs.old_reinit_state_id;
    let id = receipt.tbs.reinit_attempt_id;
    let (mut ack, _) = super::super::super::reinit::ack(old, state, id)?;
    ack.tbs.new_conversation_id = attempt.tbs.new_conversation_id;
    let ack = super::super::super::reinit::signed_reinit_ack(
        ack,
        crate::e2ee::coordinator::tests::LEAF_SEED,
    )?;
    let core = activation_core(&attempt, &ack, id)?;
    let terminal_id = semantic_id_of(SemanticHashDomain::ReinitActivationId, &core)?;
    let vote = reinit_vote(
        fixture,
        DEVICE,
        &receipt,
        state,
        id,
        Terminal::finalize(terminal_id),
    )?;
    wire(
        ArcWireObjectKind::ReinitActivationRequest,
        &ArcReInitActivationRequest {
            core,
            receipt,
            attempt,
            acknowledgements: TlsVec::new(vec![ack])?,
            votes: TlsVec::new(vec![vote])?,
        },
    )
}

fn activation_core(
    attempt: &ArcReInitAttempt,
    ack: &ArcReInitAck,
    id: [u8; 32],
) -> TestResult<ArcReInitActivationCoreTbs> {
    Ok(ArcReInitActivationCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: attempt.tbs.old_conversation_id,
        new_conversation_id: attempt.tbs.new_conversation_id,
        old_reinit_state_id: attempt.tbs.old_reinit_state_id,
        attempt_sequence: attempt.tbs.attempt_sequence,
        reinit_attempt_id: id,
        new_group_info_digest: attempt.tbs.new_group_info_digest,
        new_group_context_digest: attempt.tbs.new_group_context_digest,
        new_ratchet_tree_digest: attempt.tbs.new_ratchet_tree_digest,
        new_exporter_authenticator: attempt.tbs.new_exporter_authenticator,
        acknowledgement_set_digest: agenc_relay_e2ee::ids::proof_set_digest(
            SemanticHashDomain::ReinitAcknowledgementSet,
            std::slice::from_ref(&ack.tbs),
        )?,
    })
}

#[test]
fn an_attempt_cannot_target_an_existing_normal_conversation() -> TestResult {
    let mut fixture = Harness::new()?;
    let old = fixture.bind_channel()?;
    let target = other_binding(&fixture)?.conversation;
    fixture.finalize_reinit_to(old, OTHER_GROUP)?;
    let attempt = successor_attempt(&fixture, old, target)?;
    let bytes = wire(ArcWireObjectKind::ReinitAttempt, &attempt)?;
    let positive = ok(evaluate_request(
        &mut fixture,
        Op::SubmitReinitAttempt,
        &old,
        Some(&bytes),
    )?)?;
    assert!(matches!(positive.result, ResultBody::ReinitStaged(..)));
    let other = bind_other(&mut fixture)?;
    assert_eq!(other.conversation, target);
    assert_normal_route(&fixture, old)?;
    assert_normal_route(&fixture, target)?;
    let before = retained_state(&fixture)?;
    assert_route_refused(evaluate_request(
        &mut fixture,
        Op::SubmitReinitAttempt,
        &old,
        Some(&bytes),
    )?)?;
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

#[test]
fn activation_cannot_overwrite_an_existing_normal_conversation() -> TestResult {
    let mut fixture = Harness::new()?;
    let old = fixture.bind_channel()?;
    let target = other_binding(&fixture)?.conversation;
    fixture.finalize_reinit_to(old, OTHER_GROUP)?;
    let attempt = successor_attempt(&fixture, old, target)?;
    let bytes = wire(ArcWireObjectKind::ReinitAttempt, &attempt)?;
    ok(fixture.run(Op::SubmitReinitAttempt, &old, Some(&bytes))?)?;
    let activation = successor_activation(&fixture, old, attempt)?;
    let positive = ok(evaluate_request(
        &mut fixture,
        Op::SubmitReinitActivate,
        &old,
        Some(&activation),
    )?)?;
    assert!(matches!(positive.result, ResultBody::ReinitActivated(..)));
    let other = bind_other(&mut fixture)?;
    assert_eq!(other.conversation, target);
    assert_normal_route(&fixture, old)?;
    assert_normal_route(&fixture, target)?;
    let before = retained_state(&fixture)?;
    let prior_head = *fixture
        .coordinator
        .state
        .logs
        .get(&target)
        .ok_or("target log")?
        .accepted_state_id();
    let outcome = evaluate_request(
        &mut fixture,
        Op::SubmitReinitActivate,
        &old,
        Some(&activation),
    )?;
    if let Ok(outcome) = outcome {
        for effect in outcome.effects {
            effect(&mut fixture.coordinator.state);
        }
        assert_eq!(
            fixture
                .coordinator
                .state
                .logs
                .get(&target)
                .ok_or("target log")?
                .accepted_state_id(),
            &prior_head,
            "activation replaced the existing successor head"
        );
        return Err("occupied successor produced a fresh activation".into());
    }
    assert_route_refused(outcome)?;
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

fn assert_normal_route(fixture: &Harness, conversation: [u8; 32]) -> TestResult {
    assert_eq!(
        fixture
            .coordinator
            .state
            .routes
            .route(&ConversationId(conversation))
            .ok_or("bound route")?
            .recovery,
        RecoveryState::Normal
    );
    assert_eq!(
        fixture
            .coordinator
            .state
            .lifecycles
            .get(&conversation)
            .ok_or("bound lifecycle")?
            .gate(),
        RecoveryGate::Normal
    );
    assert!(
        fixture
            .coordinator
            .state
            .conversations
            .contains_key(&conversation)
    );
    assert!(fixture.coordinator.state.logs.contains_key(&conversation));
    Ok(())
}
