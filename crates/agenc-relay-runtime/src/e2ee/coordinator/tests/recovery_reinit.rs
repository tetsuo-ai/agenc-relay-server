//! A normal predecessor cannot replace a successor's recovery state.

#![forbid(unsafe_code)]

use agenc_relay_e2ee::objects::reinit::{ArcReInitActivationCoreTbs, ArcReInitActivationRequest};

use super::*;

const SUCCESSOR: [u8; 32] = [77; 32];

fn attempt_fixture() -> TestResult<(Harness, [u8; 32], Vec<u8>)> {
    let mut fixture = Harness::new()?;
    let conversation = fixture.bind_channel()?;
    let old_state = *fixture
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let (_, bytes) = super::super::reinit::attempt(&fixture, conversation, old_state, 0)?;
    Ok((fixture, conversation, bytes))
}

fn activation_fixture() -> TestResult<(Harness, [u8; 32], Vec<u8>)> {
    let (mut fixture, conversation, bytes) = attempt_fixture()?;
    ok(fixture.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = super::super::reinit::staged_receipt(&fixture, conversation)?;
    let old_state = receipt.tbs.old_reinit_state_id;
    let attempt_id = receipt.tbs.reinit_attempt_id;
    let (ack, _) = super::super::reinit::ack(conversation, old_state, attempt_id)?;
    let core = ArcReInitActivationCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: conversation,
        new_conversation_id: SUCCESSOR,
        old_reinit_state_id: old_state,
        attempt_sequence: 0,
        reinit_attempt_id: attempt_id,
        new_group_info_digest: [7; 32],
        new_group_context_digest: [8; 32],
        new_ratchet_tree_digest: [9; 32],
        new_exporter_authenticator: [10; 32],
        acknowledgement_set_digest: agenc_relay_e2ee::ids::proof_set_digest(
            SemanticHashDomain::ReinitAcknowledgementSet,
            std::slice::from_ref(&ack.tbs),
        )?,
    };
    let terminal_id = semantic_id_of(SemanticHashDomain::ReinitActivationId, &core)?;
    let vote = reinit_vote(
        &fixture,
        DEVICE,
        &receipt,
        old_state,
        attempt_id,
        Terminal::finalize(terminal_id),
    )?;
    let (attempt, _) = super::super::reinit::attempt(&fixture, conversation, old_state, 0)?;
    let request = ArcReInitActivationRequest {
        core,
        receipt,
        attempt,
        acknowledgements: TlsVec::new(vec![ack])?,
        votes: TlsVec::new(vec![vote])?,
    };
    Ok((
        fixture,
        conversation,
        wire(ArcWireObjectKind::ReinitActivationRequest, &request)?,
    ))
}

fn assert_successor_refusal(
    mut fixture: Harness,
    conversation: [u8; 32],
    opcode: Op,
    bytes: &[u8],
) -> TestResult {
    let normal = ok(evaluate_request(
        &mut fixture,
        opcode,
        &conversation,
        Some(bytes),
    )?)?;
    assert!(matches!(
        (opcode, &normal.result),
        (Op::SubmitReinitAttempt, ResultBody::ReinitStaged(..))
            | (Op::SubmitReinitActivate, ResultBody::ReinitActivated(..))
    ));
    assert!(!normal.writes.is_empty());
    assert!(!normal.effects.is_empty());
    for gate in [
        RecoveryGate::Pending,
        RecoveryGate::Conflict,
        RecoveryGate::Closed,
    ] {
        fixture
            .coordinator
            .state
            .lifecycles
            .insert(SUCCESSOR, Lifecycle::restore(gate, false, false));
        let before = retained_state(&fixture)?;
        assert_route_refused(evaluate_request(
            &mut fixture,
            opcode,
            &conversation,
            Some(bytes),
        )?)?;
        assert_eq!(retained_state(&fixture)?, before);
    }
    fixture.coordinator.signer = None;
    assert_route_refused(evaluate_request(
        &mut fixture,
        opcode,
        &conversation,
        Some(bytes),
    )?)?;
    Ok(())
}

#[test]
fn a_normal_predecessor_cannot_stage_an_attempt_for_a_pending_successor() -> TestResult {
    let (fixture, conversation, bytes) = attempt_fixture()?;
    assert_successor_refusal(fixture, conversation, Op::SubmitReinitAttempt, &bytes)
}

#[test]
fn a_normal_predecessor_cannot_activate_over_a_pending_successor() -> TestResult {
    let (fixture, conversation, bytes) = activation_fixture()?;
    assert_successor_refusal(fixture, conversation, Op::SubmitReinitActivate, &bytes)
}
