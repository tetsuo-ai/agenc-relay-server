//! Restart preserves Commit validation-time ordering across terminal outcomes.

#![forbid(unsafe_code)]

use super::*;

#[test]
fn reload_refuses_a_route_whose_candidate_commit_is_missing() -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (_, commit_id, _) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let missing_key = agenc_relay_storage::e2ee_records::object_key(&commit_id)?;
    harness.writes.retain(|write| {
        !matches!(write, Write::Put { table: agenc_relay_storage::TableId::E2eeObject, key, .. } if *key == missing_key)
    });
    // A declared live gate cannot outlive a route that failed reconstruction.
    assert!(harness.reloaded().is_err());
    Ok(())
}

#[test]
fn reload_preserves_validation_time_of_an_open_candidate() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    submit_candidate(&mut harness, conversation, 0, 20)?;
    let mut reloaded = harness.reloaded()?;
    let stale = commit_bytes(&reloaded, conversation, 0, 19)?;
    assert_eq!(
        code(reloaded.run(Op::SubmitCandidate, &conversation, Some(&stale))?),
        Some(E2eeReplyCode::EpochStale),
    );
    let equal = commit_bytes(&reloaded, conversation, 0, 20)?;
    assert_eq!(
        code(reloaded.run(Op::SubmitCandidate, &conversation, Some(&equal))?),
        Some(E2eeReplyCode::CandidateActive),
    );
    Ok(())
}

#[test]
fn reload_preserves_validation_time_after_an_aborted_candidate() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, _, candidate_id) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let core = ArcAbortCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_state_id: receipt.tbs.prior_state_id,
        candidate_id,
        prior_epoch: 0,
        reason: ArcCommitAbortReason::SenderWithdrawn,
        evidence_digest: [0; 32],
    };
    let abort_id = semantic_id_of(SemanticHashDomain::AbortId, &core)?;
    let request = ArcAbortRequest {
        core,
        receipt: receipt.clone(),
        votes: TlsVec::new(vec![vote(
            &harness,
            DEVICE,
            &receipt,
            candidate_id,
            Terminal::abort(abort_id, 1)?,
        )?])?,
    };
    let abort = wire(ArcWireObjectKind::AbortRequest, &request)?;
    ok(harness.run(Op::SubmitAbort, &conversation, Some(&abort))?)?;
    assert_reloaded_validation_floor(harness, conversation, 0)
}

#[test]
fn reload_preserves_validation_time_after_a_finalized_candidate() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_id, candidate_id) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let ack = acknowledge(&mut harness, conversation, candidate_id, commit_id)?;
    let request = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_id,
        candidate_id,
        &ack,
        &[DEVICE],
    )?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    assert_reloaded_validation_floor(harness, conversation, 1)
}

fn assert_reloaded_validation_floor(
    harness: Harness,
    conversation: [u8; 32],
    epoch: u64,
) -> TestResult {
    let mut reloaded = harness.reloaded()?;
    let stale = commit_bytes(&reloaded, conversation, epoch, 19)?;
    assert_eq!(
        code(reloaded.run(Op::SubmitCandidate, &conversation, Some(&stale))?),
        Some(E2eeReplyCode::EpochStale),
    );
    let equal = commit_bytes(&reloaded, conversation, epoch, 20)?;
    assert_eq!(
        ok(reloaded.run(Op::SubmitCandidate, &conversation, Some(&equal))?)?.result,
        ResultBody::AcceptedEvent,
    );
    Ok(())
}

#[test]
fn reload_refuses_retained_records_stored_under_each_others_positions() -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_id, candidate_id) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let ack = acknowledge(&mut harness, conversation, candidate_id, commit_id)?;
    let request = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_id,
        candidate_id,
        &ack,
        &[DEVICE],
    )?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    let first = agenc_relay_storage::e2ee_records::SequencerRow::record_key(&conversation, 0)?;
    let second = agenc_relay_storage::e2ee_records::SequencerRow::record_key(&conversation, 1)?;
    let body_of = |wanted: &agenc_relay_storage::StoredKey| {
        harness.writes.iter().rev().find_map(|write| match write {
            Write::Put {
                table: agenc_relay_storage::TableId::E2eeState,
                key,
                plaintext,
            } if key == wanted => Some(plaintext.clone()),
            _ => None,
        })
    };
    let first_body = body_of(&first).ok_or("candidate record row")?;
    let second_body = body_of(&second).ok_or("finalization record row")?;
    for write in &mut harness.writes {
        if let Write::Put {
            table: agenc_relay_storage::TableId::E2eeState,
            key,
            plaintext,
        } = write
        {
            if *key == first {
                *plaintext = second_body.clone();
            } else if *key == second {
                *plaintext = first_body.clone();
            }
        }
    }
    assert!(harness.reloaded().is_err());
    Ok(())
}
