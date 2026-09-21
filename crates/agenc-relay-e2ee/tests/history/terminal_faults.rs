#![forbid(unsafe_code)]

//! An abort certificate must name the open candidate exactly, and a
//! finalization proof must carry the current policy and the authorization
//! it was built under.

use super::*;
use agenc_relay_e2ee::objects::sequencing::ArcCandidateReceipt;

fn open_candidate() -> Result<(Genesis, HistoricalChain, Log, Candidate), E2eeError> {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let (record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &record)?;
    Ok((genesis, chain, log, candidate))
}

type ReceiptEdit = fn(&mut ArcCandidateReceipt);

#[test]
fn an_abort_that_does_not_name_the_open_candidate_is_refused() -> TestResult {
    let (genesis, chain, log, candidate) = open_candidate()?;
    let council = operational_council(&genesis);
    let head = *chain.head();
    let receipt_edits: [(&str, ReceiptEdit); 5] = [
        ("route sequence", |receipt| receipt.tbs.route_sequence += 1),
        ("candidate sequence", |receipt| {
            receipt.tbs.candidate_sequence += 1
        }),
        ("predecessor", |receipt| {
            receipt.tbs.predecessor_record_id = [8; 32]
        }),
        ("commit object", |receipt| {
            receipt.tbs.commit_object_id = [9; 32]
        }),
        ("sequenced at", |receipt| receipt.tbs.sequenced_at += 1),
    ];
    for (name, edit) in receipt_edits {
        let mut named = candidate.clone();
        edit(&mut named.receipt);
        let mut fork = log.clone_for_fork();
        let abort = fork.abort(&named, ArcCommitAbortReason::StagingTimeout, &council)?;
        let mut probe = chain.clone();
        assert!(adopt(&mut probe, &abort).is_err(), "{name}");
        assert_eq!(*probe.head(), head, "{name}");
        assert!(probe.candidate().is_some(), "{name}");
    }
    // The abort's own core may not disagree with the chain position either.
    let mut other_epoch = log.clone_for_fork();
    other_epoch.epoch += 1;
    let abort = other_epoch.abort(&candidate, ArcCommitAbortReason::StagingTimeout, &council)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &abort).is_err(), "prior epoch");
    let mut other_state = log.clone_for_fork();
    other_state.accepted_state_id = [7; 32];
    let abort = other_state.abort(&candidate, ArcCommitAbortReason::StagingTimeout, &council)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &abort).is_err(), "prior state");
    let mut unknown = log.clone_for_fork();
    let (_, stranger) = unknown.candidate([3; 32])?;
    let abort =
        log.clone_for_fork()
            .abort(&stranger, ArcCommitAbortReason::StagingTimeout, &council)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &abort).is_err(), "another candidate");
    assert_eq!(*probe.head(), head);
    Ok(())
}

#[test]
fn a_finalization_must_carry_the_current_policy_and_its_own_authorization() -> TestResult {
    let (genesis, chain, log, candidate) = open_candidate()?;
    let council = operational_council(&genesis);
    let head = *chain.head();
    let policy_id = log.policy_id;

    // The proof's authorization names another old policy.
    let mut tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
        policy_id,
        [0; 32],
    );
    tbs.old_policy_id = [1; 32];
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log.clone_for_fork().finalization(request, id, policy_id)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &record).is_err(), "authorization policy");
    assert_eq!(*probe.head(), head);

    // The proof's core names another old policy.
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
        policy_id,
        [0; 32],
    );
    let mut other_policy = log.clone_for_fork();
    other_policy.policy_id = [1; 32];
    let (request, id) =
        other_policy.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = other_policy.finalization(request, id, policy_id)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &record).is_err(), "core policy");
    assert_eq!(*probe.head(), head);

    // The core disagrees with the authorization it embeds.
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
        policy_id,
        [0; 32],
    );
    let (mut request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    request.proof.core.commit_authorization_id = [7; 32];
    let record = log.clone_for_fork().finalization(request, id, policy_id)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &record).is_err(), "authorization id");
    assert_eq!(*probe.head(), head);

    // The honest finalization still advances.
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
        policy_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log.clone_for_fork().finalization(request, id, policy_id)?;
    let mut probe = chain.clone();
    assert!(matches!(
        adopt(&mut probe, &record)?,
        ChainStep::Finalized { .. }
    ));
    Ok(())
}
