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
            ArcWireObjectKind::LeafMembershipProof,
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
    assert_eq!(reloaded.coordinator.unreplayed_votes(), 0);
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
            ArcWireObjectKind::AbortRequest,
            &ArcAbortRequest {
                core: ArcAbortCoreTbs {
                    profile_version: 1,
                    network_id: NETWORK,
                    conversation_id: conversation,
                    prior_state_id: receipt.tbs.prior_state_id,
                    candidate_id,
                    prior_epoch: 0,
                    reason: ArcCommitAbortReason::SenderWithdrawn,
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

/// The reload restores exactly the certified terminals the live coordinator
/// recorded: the abort and the finalization, each with its retained request.
#[test]
fn a_reload_restores_every_certified_terminal_proof() -> TestResult {
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
    let abort = wire(
        ArcWireObjectKind::AbortRequest,
        &ArcAbortRequest {
            core,
            receipt: receipt.clone(),
            votes: TlsVec::new(vec![vote(
                &harness,
                DEVICE,
                &receipt,
                candidate_id,
                Terminal::abort(abort_id, 1)?,
            )?])?,
        },
    )?;
    ok(harness.run(Op::SubmitAbort, &conversation, Some(&abort))?)?;
    let (receipt, commit_id, candidate_id) = submit_candidate(&mut harness, conversation, 0, 21)?;
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
    let proofs = |harness: &Harness| {
        harness
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .map(|state| state.proofs.clone())
    };
    let live = proofs(&harness).ok_or("the conversation")?;
    assert_eq!(live.len(), 2);
    assert!(live.contains_key(&abort_id));
    assert_eq!(proofs(&harness.reloaded()?), Some(live));
    Ok(())
}

/// A durable vote row that cannot be counted again is reported, never
/// dropped in silence (companion 12.4).
#[test]
fn a_reload_reports_a_vote_row_it_cannot_count_again() -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let opened = open_finalization(&mut harness, conversation, 0)?;
    let (one_vote, _) = finalization_bytes(&harness, &opened, None, &[DEVICE])?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&one_vote))?)?;
    // The retained request the vote row names is lost.
    let lost = agenc_relay_storage::e2ee_records::object_key(&object_id(&one_vote))?;
    harness.writes.retain(|write| {
        !matches!(write, Write::Put { table: agenc_relay_storage::TableId::E2eeObject, key, .. } if *key == lost)
    });
    assert_eq!(harness.reloaded()?.coordinator.unreplayed_votes(), 1);
    Ok(())
}

/// A below-quorum abort request of `candidate_id` without any vote, made
/// distinct by `tag`.
fn voteless_abort(
    conversation: [u8; 32],
    receipt: &ArcCandidateReceipt,
    candidate_id: [u8; 32],
    tag: u8,
) -> TestResult<Vec<u8>> {
    wire(
        ArcWireObjectKind::AbortRequest,
        &ArcAbortRequest {
            core: ArcAbortCoreTbs {
                profile_version: 1,
                network_id: NETWORK,
                conversation_id: conversation,
                prior_state_id: receipt.tbs.prior_state_id,
                candidate_id,
                prior_epoch: 0,
                reason: ArcCommitAbortReason::SenderWithdrawn,
                evidence_digest: [tag; 32],
            },
            receipt: receipt.clone(),
            votes: TlsVec::new(Vec::new())?,
        },
    )
}

/// A request that would push its conversation past
/// `MAX_STORED_BYTES_PER_CONVERSATION` is refused with `E2EE_RATE_LIMITED`
/// and leaves no object, row, or charge behind.
#[test]
fn a_pending_terminal_request_over_the_conversation_quota_is_refused_whole() -> TestResult {
    use crate::e2ee::coordinator::owners::Account;
    use agenc_relay_e2ee::limits::MAX_STORED_BYTES_PER_CONVERSATION;
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let (receipt, _, candidate_id) = submit_candidate(&mut harness, conversation, 0, 10)?;
    let request = voteless_abort(conversation, &receipt, candidate_id, 1)?;
    let charged = harness
        .coordinator
        .state
        .owners
        .conversation_bytes(&conversation);
    // Fill the conversation to one byte short of room for the request.
    let filler = MAX_STORED_BYTES_PER_CONVERSATION - charged - u64::try_from(request.len())? + 1;
    harness.coordinator.state.owners.install(
        [200; 32],
        Account {
            kind: 1,
            size: filler,
            retention: agenc_relay_storage::e2ee_records::RetentionClass::Ordinary,
            accepted_at: super::super::NOW,
            reconstructed: false,
            retired_at: None,
            owners: std::iter::once((b"filler".to_vec(), Some(conversation))).collect(),
        },
    );
    let rows = harness.writes.len();
    assert_eq!(
        code(harness.run(Op::SubmitAbort, &conversation, Some(&request))?),
        Some(E2eeReplyCode::RateLimited),
    );
    let state = &harness.coordinator.state;
    assert!(!state.objects.contains_key(&object_id(&request)));
    assert!(state.owners.account(&object_id(&request)).is_none());
    assert_eq!(harness.writes.len(), rows);
    assert!(
        state
            .conversations
            .get(&conversation)
            .is_some_and(|state| state.pending_requests.is_empty())
    );
    Ok(())
}

/// Once the slot reaches its terminal the retained-request row retires, and
/// a request no vote row names is collected at the ordinary retention
/// boundary and not a second before (ENC-09).
#[test]
fn an_unowned_pending_request_ages_out_through_the_expiry_collector() -> TestResult {
    use agenc_relay_e2ee::limits::SEQUENCER_RECORD_RETENTION_SECONDS;
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let (receipt, _, candidate_id) = submit_candidate(&mut harness, conversation, 0, 10)?;
    let voteless = voteless_abort(conversation, &receipt, candidate_id, 1)?;
    ok(harness.run(Op::SubmitAbort, &conversation, Some(&voteless))?)?;
    let id = object_id(&voteless);
    let owned = |harness: &Harness| {
        harness
            .coordinator
            .state
            .owners
            .account(&id)
            .map(|account| (account.owners.len(), account.retired_at))
    };
    assert_eq!(owned(&harness), Some((1, None)));
    // Both council devices certify another abort of the same candidate.
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
    let mut votes = [DEVICE, SECOND_DEVICE]
        .iter()
        .map(|device| {
            vote(
                &harness,
                *device,
                &receipt,
                candidate_id,
                Terminal::abort(abort_id, 1)?,
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
    let certified = wire(
        ArcWireObjectKind::AbortRequest,
        &ArcAbortRequest {
            core,
            receipt: receipt.clone(),
            votes: TlsVec::new(votes)?,
        },
    )?;
    let outcome = ok(harness.run(Op::SubmitAbort, &conversation, Some(&certified))?)?;
    assert!(matches!(outcome.result, ResultBody::Aborted(..)));
    let retired = super::super::NOW;
    assert_eq!(owned(&harness), Some((0, Some(retired))));
    let due = retired + SEQUENCER_RECORD_RETENTION_SECONDS;
    for (now, present) in [(due - 1, true), (due, false)] {
        for _ in 0..8 {
            super::object_expiry::sweep(&mut harness.coordinator, now)?;
        }
        assert_eq!(
            harness.coordinator.state.objects.contains_key(&id),
            present,
            "at {now}"
        );
    }
    Ok(())
}
