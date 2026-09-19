//! A ReInit attempt must name its own conversation, network and slot, and
//! an abort core must repeat the receipt it names before its votes count.

#![forbid(unsafe_code)]

use super::*;

type CoreEdit = fn(&mut IrcReInitAbortCoreTbs);

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
