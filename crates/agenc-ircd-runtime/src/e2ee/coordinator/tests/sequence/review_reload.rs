//! Review regressions (ENC-11): facts a reloaded coordinator derives from
//! retained objects must equal the facts the live coordinator admitted.

#![forbid(unsafe_code)]

use super::recovery_pending::close_authorization::{finalization_bytes, open_finalization};
use super::*;
use crate::e2ee::coordinator::tests::support::{MembershipSpec, membership_proof};

/// A `removed` leaf-membership proof must name a finalization the
/// conversation retains (companion 13.7.3). A pending, uncertified
/// finalization request is not one: the live coordinator refuses the
/// proof, and a reload must keep refusing it.
#[test]
fn a_reload_does_not_promote_a_pending_finalization_to_a_retained_one() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let opened = open_finalization(&mut harness, conversation, 0)?;
    // Two council devices with fault bound zero need both votes; one vote
    // retains the request as pending without certifying anything.
    let (one_vote, pending_id) = finalization_bytes(&harness, &opened, None, &[DEVICE])?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&one_vote))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Finalization, _)
    ));
    let removed = {
        let mut spec = MembershipSpec::continuing(
            &harness.principal,
            conversation,
            DEVICE,
            super::super::LEAF_SEED,
            1,
        );
        spec.removed = Some(pending_id);
        wire(
            IrcWireObjectKind::LeafMembershipProof,
            &membership_proof(&spec)?,
        )?
    };
    assert_eq!(
        code(harness.run(Op::SubmitMembership, &conversation, Some(&removed))?),
        Some(E2eeReplyCode::BindingAuthInvalid),
    );
    let mut reloaded = harness.reloaded()?;
    assert_eq!(
        code(reloaded.run(Op::SubmitMembership, &conversation, Some(&removed))?),
        Some(E2eeReplyCode::BindingAuthInvalid),
        "a reload turned a pending finalization request into a retained finalization",
    );
    Ok(())
}

/// A reloaded coordinator rebuilds each counted vote from its durable row
/// (companion 12.4). A bootstrap activation also counts the resulting
/// council's votes (companion 9.5), and those must survive a reload too.
#[test]
fn a_reload_keeps_the_resulting_council_votes_of_a_pending_bootstrap_activation() -> TestResult {
    let councils = || {
        Harness::with_councils(
            &[DEVICE, SECOND_DEVICE],
            &[DEVICE],
            &[DEVICE, SECOND_DEVICE],
        )
    };
    // Control: without a reload the resulting council's vote is kept and
    // the old council's vote then completes both quorums.
    let mut live = councils()?;
    let conversation = live.bind_channel()?;
    let opened = open_finalization(&mut live, conversation, 0)?;
    let (resulting_only, terminal) = finalization_bytes(&live, &opened, None, &[SECOND_DEVICE])?;
    let outcome = ok(live.run(Op::SubmitFinalization, &conversation, Some(&resulting_only))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Finalization, _)
    ));
    let (old_only, _) = finalization_bytes(&live, &opened, None, &[DEVICE])?;
    let outcome = ok(live.run(Op::SubmitFinalization, &conversation, Some(&old_only))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal));

    // The same two requests with a reload between them.
    let mut harness = councils()?;
    let conversation = harness.bind_channel()?;
    let opened = open_finalization(&mut harness, conversation, 0)?;
    let (resulting_only, terminal) = finalization_bytes(&harness, &opened, None, &[SECOND_DEVICE])?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&resulting_only))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Finalization, _)
    ));
    let mut reloaded = harness.reloaded()?;
    let (old_only, _) = finalization_bytes(&reloaded, &opened, None, &[DEVICE])?;
    let outcome = ok(reloaded.run(Op::SubmitFinalization, &conversation, Some(&old_only))?)?;
    assert!(
        matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal),
        "the reload lost the resulting council's counted vote: {:?}",
        outcome.result,
    );
    Ok(())
}

/// A terminal request below quorum is retained (companion 12.4), and every
/// retained proof byte counts against `MAX_STORED_BYTES_PER_CONVERSATION`
/// (companion 15 and 16). A request that adds no counted vote must still be
/// charged to its conversation, or any attached device can retain an
/// unbounded number of them against the global ceilings alone.
#[test]
fn a_pending_terminal_request_without_a_counted_vote_is_charged_to_its_conversation() -> TestResult
{
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let (receipt, _, candidate_id) = submit_candidate(&mut harness, conversation, 0, 10)?;
    let charged_before = harness
        .coordinator
        .state
        .owners
        .conversation_bytes(&conversation);
    let resident_before = harness.coordinator.state.object_bytes;
    let mut retained = Vec::new();
    for tag in 1..=3_u8 {
        // Distinct evidence digests make distinct abort identifiers; no vote
        // is attached, so nothing is counted and no vote row is written.
        let request = wire(
            IrcWireObjectKind::AbortRequest,
            &IrcAbortRequest {
                core: IrcAbortCoreTbs {
                    profile_version: 1,
                    network_id: NETWORK,
                    conversation_id: conversation,
                    prior_state_id: receipt.tbs.prior_state_id,
                    candidate_id,
                    prior_epoch: 0,
                    reason: IrcCommitAbortReason::SenderWithdrawn,
                    evidence_digest: [tag; 32],
                },
                receipt: receipt.clone(),
                votes: TlsVec::new(Vec::new())?,
            },
        )?;
        let outcome = ok(harness.run(Op::SubmitAbort, &conversation, Some(&request))?)?;
        assert!(matches!(
            outcome.result,
            ResultBody::Pending(_, PendingKind::Abort, _)
        ));
        retained.push((object_id(&request), request.len()));
    }
    let state = &harness.coordinator.state;
    let total: usize = retained.iter().map(|(_, size)| size).sum();
    // Every request is a retained, resident object of the global set ...
    assert!(
        retained
            .iter()
            .all(|(id, _)| state.objects.contains_key(id))
    );
    assert_eq!(state.object_bytes, resident_before + total);
    // ... so its bytes belong to the conversation that caused them.
    assert_eq!(
        state.owners.conversation_bytes(&conversation),
        charged_before + u64::try_from(total)?,
        "retained pending terminal requests are charged to no conversation",
    );
    Ok(())
}
