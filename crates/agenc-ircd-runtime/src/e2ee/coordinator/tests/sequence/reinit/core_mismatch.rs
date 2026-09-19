//! A ReInit attempt must name its own conversation, network and slot, and
//! an abort core must repeat the receipt it names before its votes count.

#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::tests::sequence::submit_candidate;

type CoreEdit = fn(&mut IrcReInitAbortCoreTbs);
type ActivationEdit = fn(&mut IrcReInitActivationCoreTbs);

fn staged() -> TestResult<(Harness, [u8; 32], [u8; 32])> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let old_state = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    Ok((harness, conversation, old_state))
}

#[test]
fn an_attempt_naming_another_conversation_or_network_is_refused() -> TestResult {
    let (mut harness, conversation, old_state) = staged()?;
    let (attempt, _) = attempt(&harness, conversation, old_state, 0)?;
    let mut other_conversation = attempt.clone();
    other_conversation.tbs.old_conversation_id = [1; 32];
    let mut other_network = attempt.clone();
    other_network.tbs.network_id = [2; 32];
    for substituted in [other_conversation, other_network] {
        let bytes = wire(IrcWireObjectKind::ReinitAttempt, &substituted)?;
        assert_eq!(
            code(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?),
            Some(E2eeReplyCode::RouteInvalid)
        );
    }
    assert!(!matches!(
        harness
            .coordinator
            .state
            .logs
            .get(&conversation)
            .ok_or("log")?
            .phase(),
        Phase::Reinit { .. }
    ));
    Ok(())
}

#[test]
fn an_attempt_for_the_wrong_slot_is_stale() -> TestResult {
    let (mut harness, conversation, old_state) = staged()?;
    let (_, later) = attempt(&harness, conversation, old_state, 1)?;
    assert_eq!(
        code(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&later))?),
        Some(E2eeReplyCode::EpochStale)
    );
    let (_, first) = attempt(&harness, conversation, old_state, 0)?;
    assert!(matches!(
        ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&first))?)?.result,
        ResultBody::ReinitStaged(..)
    ));
    Ok(())
}

#[test]
fn an_abort_core_must_repeat_the_receipt_and_the_conversation() -> TestResult {
    let (mut harness, conversation, old_state) = staged()?;
    let (attempt, bytes) = attempt(&harness, conversation, old_state, 0)?;
    ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = staged_receipt(&harness, conversation)?;
    let request = IrcReInitAbortRequest {
        core: IrcReInitAbortCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: conversation,
            old_reinit_state_id: old_state,
            attempt_sequence: 0,
            slot_predecessor_record_id: receipt.tbs.predecessor_record_id,
            reinit_attempt_id: receipt.tbs.reinit_attempt_id,
            reason_code: 1,
            evidence_digest: [0; 32],
        },
        receipt,
        attempt,
        votes: TlsVec::new(Vec::new())?,
    };
    let edits: [(CoreEdit, E2eeReplyCode); 5] = [
        (
            |core| core.profile_version = 2,
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            |core| core.network_id = [2; 32],
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            |core| core.attempt_sequence = 1,
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            |core| core.slot_predecessor_record_id = [0; 32],
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            |core| core.old_conversation_id = [1; 32],
            E2eeReplyCode::RouteInvalid,
        ),
    ];
    for (edit, expected) in edits {
        let mut substituted = request.clone();
        edit(&mut substituted.core);
        let bytes = wire(IrcWireObjectKind::ReinitAbortRequest, &substituted)?;
        assert_eq!(
            code(harness.run(Op::SubmitReinitAbort, &conversation, Some(&bytes))?),
            Some(expected)
        );
    }
    let valid = wire(IrcWireObjectKind::ReinitAbortRequest, &request)?;
    assert!(matches!(
        ok(harness.run(Op::SubmitReinitAbort, &conversation, Some(&valid))?)?.result,
        ResultBody::Pending(..)
    ));
    Ok(())
}

#[test]
fn an_activation_core_must_repeat_the_attempt_its_result_and_its_acknowledgements() -> TestResult {
    let (mut harness, conversation, old_state) = staged()?;
    let (attempt, bytes) = attempt(&harness, conversation, old_state, 0)?;
    ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = staged_receipt(&harness, conversation)?;
    let attempt_id = receipt.tbs.reinit_attempt_id;
    let (ack, _) = ack(conversation, old_state, attempt_id)?;
    let ack = signed_reinit_ack(ack, crate::e2ee::coordinator::tests::LEAF_SEED)?;
    let core = IrcReInitActivationCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: conversation,
        new_conversation_id: NEW_CONVERSATION,
        old_reinit_state_id: old_state,
        attempt_sequence: 0,
        reinit_attempt_id: attempt_id,
        new_group_info_digest: [7; 32],
        new_group_context_digest: [8; 32],
        new_ratchet_tree_digest: [9; 32],
        new_exporter_authenticator: [10; 32],
        acknowledgement_set_digest: agenc_ircd_e2ee::ids::proof_set_digest(
            SemanticHashDomain::ReinitAcknowledgementSet,
            std::slice::from_ref(&ack.tbs),
        )?,
    };
    let request = |core: IrcReInitActivationCoreTbs| -> TestResult<Vec<u8>> {
        let terminal = Terminal::finalize(semantic_id_of(
            SemanticHashDomain::ReinitActivationId,
            &core,
        )?);
        let vote = reinit_vote(&harness, DEVICE, &receipt, old_state, attempt_id, terminal)?;
        wire(
            IrcWireObjectKind::ReinitActivationRequest,
            &IrcReInitActivationRequest {
                core,
                receipt: receipt.clone(),
                attempt: attempt.clone(),
                acknowledgements: TlsVec::new(vec![ack.clone()])?,
                votes: TlsVec::new(vec![vote])?,
            },
        )
    };
    let edits: [ActivationEdit; 5] = [
        |core| core.profile_version = 2,
        |core| core.new_conversation_id = [78; 32],
        |core| core.new_group_info_digest = [0; 32],
        |core| core.reinit_attempt_id = [0; 32],
        |core| core.acknowledgement_set_digest = [0; 32],
    ];
    let requests: Vec<Vec<u8>> = edits
        .iter()
        .map(|edit| {
            let mut substituted = core.clone();
            edit(&mut substituted);
            request(substituted)
        })
        .collect::<TestResult<_>>()?;
    let valid = request(core)?;
    for substituted in requests {
        assert_eq!(
            code(harness.run(Op::SubmitReinitActivate, &conversation, Some(&substituted))?),
            Some(E2eeReplyCode::BindingAuthInvalid)
        );
    }
    assert!(matches!(
        harness
            .coordinator
            .state
            .logs
            .get(&conversation)
            .ok_or("log")?
            .phase(),
        Phase::Reinit { .. }
    ));
    ok(harness.run(Op::SubmitReinitActivate, &conversation, Some(&valid))?)?;
    Ok(())
}

#[test]
fn an_acknowledgement_naming_another_conversation_or_network_is_refused() -> TestResult {
    let (mut harness, conversation, _) = staged()?;
    // A commit ACK for the open candidate that names another conversation.
    let (_, commit_id, candidate_id) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let elsewhere = super::super::ack([9; 32], 0, candidate_id, commit_id)?;
    assert_eq!(
        code(harness.run(Op::SubmitCommitAck, &conversation, Some(&elsewhere))?),
        Some(E2eeReplyCode::EpochStale)
    );
    let (mut other, conversation, old_state) = staged()?;
    let (_, bytes) = attempt(&other, conversation, old_state, 0)?;
    ok(other.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    let receipt = staged_receipt(&other, conversation)?;
    let (ack, _) = ack(conversation, old_state, receipt.tbs.reinit_attempt_id)?;
    let mut other_conversation = ack.clone();
    other_conversation.tbs.old_conversation_id = [1; 32];
    let mut other_network = ack;
    other_network.tbs.network_id = [2; 32];
    for substituted in [other_conversation, other_network] {
        let signed = signed_reinit_ack(substituted, crate::e2ee::coordinator::tests::LEAF_SEED)?;
        let bytes = wire(IrcWireObjectKind::ReinitAck, &signed)?;
        assert_eq!(
            code(other.run(Op::SubmitReinitAck, &conversation, Some(&bytes))?),
            Some(E2eeReplyCode::RouteInvalid)
        );
    }
    Ok(())
}

#[test]
fn a_policy_submission_refuses_a_wrapper_of_another_kind() -> TestResult {
    let (mut harness, conversation, _) = staged()?;
    let binding = harness.binding_bytes()?;
    assert_eq!(
        code(harness.run(Op::SubmitPolicy, &conversation, Some(&binding))?),
        Some(E2eeReplyCode::InvalidFragment)
    );
    Ok(())
}
