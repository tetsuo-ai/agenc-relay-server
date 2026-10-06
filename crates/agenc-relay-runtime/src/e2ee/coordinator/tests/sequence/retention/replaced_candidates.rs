//! A restart restores a route's validation-time floor from the Commits
//! its candidate slot rows name (companion 12.2, 15 and 16): a later
//! candidate of the same epoch replaces an aborted one in that epoch's slot,
//! the only durable row that names a candidate's Commit, so the replaced
//! Commit is ordinary material object expiry may collect, and the restart
//! does not need it. A Commit a slot still names is retained, and its
//! absence is a storage fault that refuses startup.

#![forbid(unsafe_code)]

use super::*;

/// Aborts the open candidate `receipt` of `conversation` with the attached
/// device's vote.
fn abort_candidate(
    harness: &mut Harness,
    conversation: [u8; 32],
    receipt: &ArcCandidateReceipt,
    candidate_id: [u8; 32],
) -> TestResult {
    let core = ArcAbortCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_state_id: receipt.tbs.prior_state_id,
        candidate_id,
        prior_epoch: receipt.tbs.prior_epoch,
        reason: ArcCommitAbortReason::SenderWithdrawn,
        evidence_digest: [0; 32],
    };
    let abort_id = semantic_id_of(SemanticHashDomain::AbortId, &core)?;
    let request = wire(
        ArcWireObjectKind::AbortRequest,
        &ArcAbortRequest {
            core,
            receipt: receipt.clone(),
            votes: TlsVec::new(vec![vote(
                harness,
                DEVICE,
                receipt,
                candidate_id,
                Terminal::abort(abort_id, 1)?,
            )?])?,
        },
    )?;
    let outcome = ok(harness.run(Op::SubmitAbort, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::Aborted(..)));
    Ok(())
}

#[test]
fn a_route_restarts_after_the_commit_of_a_replaced_candidate_expires() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    // A candidate is aborted, and a later candidate of the same epoch takes
    // its slot, the only durable row that named its Commit.
    let (receipt, replaced, candidate_id) = submit_candidate(&mut harness, conversation, 0, 10)?;
    abort_candidate(&mut harness, conversation, &receipt, candidate_id)?;
    let (_, current, _) = submit_candidate(&mut harness, conversation, 0, 11)?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(collected.contains(&replaced));
    assert!(!collected.contains(&current));
    let restarted = harness.reloaded()?;
    let state = restarted
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the restored conversation")?;
    // The validation-time floor is the one the slot's own Commit carries.
    assert_eq!(state.last_validation_time, 11);
    let log = restarted
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("the restored log")?;
    assert_eq!(
        log.candidate().map(|slot| slot.commit_object_id),
        Some(current)
    );
    Ok(())
}

#[test]
fn a_restart_still_refuses_a_route_whose_named_commit_is_missing() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (_, current, _) = submit_candidate(&mut harness, conversation, 0, 10)?;
    // The slot still names this Commit, so its loss is a storage fault.
    let key = agenc_relay_storage::e2ee_records::object_key(&current)?;
    harness.writes.retain(|write| {
        !matches!(write, Write::Put { table: TableId::E2eeObject, key: stored, .. } if *stored == key)
    });
    assert!(harness.reloaded().is_err());
    Ok(())
}
