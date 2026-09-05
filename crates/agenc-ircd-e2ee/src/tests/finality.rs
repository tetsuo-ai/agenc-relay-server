#![forbid(unsafe_code)]

//! Disposition votes, sign-once slots, and quorum accounting.

use std::error::Error;

use super::*;
use crate::policy::verify_policy;
use crate::test_support::*;

type TestResult = Result<(), Box<dyn Error>>;

const CONVERSATION: [u8; 32] = [20; 32];

fn slot() -> VoteSlot {
    VoteSlot {
        network_id: NETWORK,
        conversation_id: CONVERSATION,
        prior_epoch: 0,
        prior_state_id: [50; 32],
        candidate_sequence: 0,
        predecessor_record_id: [50; 32],
    }
}

#[test]
fn terminals_and_vote_tbs_are_reconstructed_exactly() -> TestResult {
    let finalize = Terminal::finalize([58; 32]);
    assert_eq!(finalize.disposition, IrcDisposition::Finalize);
    assert_eq!(finalize.reason_code, 0);
    assert_eq!(Terminal::abort([64; 32], 0), Err(E2eeError::InvalidValue));
    let abort = Terminal::abort([64; 32], 5)?;
    let tbs = vote_tbs(&slot(), [52; 32], abort);
    assert_eq!(tbs.disposition, IrcDisposition::Abort);
    assert_eq!(tbs.terminal_id, [64; 32]);
    assert_eq!(tbs.reason_code, 5);
    assert_eq!(tbs.slot_predecessor_record_id, [50; 32]);
    assert_eq!(tbs.candidate_id, [52; 32]);
    Ok(())
}

#[test]
fn a_ledger_counts_distinct_council_votes_and_signs_once() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7, 8])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = principal_rosters(&principals)?;
    let policy = verify_policy(
        &NETWORK,
        &CONVERSATION,
        &policy(&PolicySpec::moderated(&principals, CONVERSATION))?,
        &rosters,
        None,
    )?;
    assert_eq!(policy.quorum, 2);
    let finalize = Terminal::finalize([58; 32]);
    let abort = Terminal::abort([64; 32], 1)?;
    let finalize_tbs = vote_tbs(&slot(), [52; 32], finalize);
    let abort_tbs = vote_tbs(&slot(), [52; 32], abort);
    let mut ledger = QuorumLedger::new();
    let first = principals.first().ok_or("principal")?;
    let second = principals.get(1).ok_or("principal")?;
    ledger.record(
        &policy,
        &rosters,
        &finalize_tbs,
        &finality_vote(first, 7, &finalize_tbs)?,
    )?;
    assert_eq!(ledger.count(&finalize), 1);
    assert!(!ledger.quorum_reached(&policy, &finalize));
    // The same vote again is idempotent; a different terminal is a violation.
    ledger.record(
        &policy,
        &rosters,
        &finalize_tbs,
        &finality_vote(first, 7, &finalize_tbs)?,
    )?;
    assert_eq!(ledger.count(&finalize), 1);
    assert_eq!(
        ledger.record(
            &policy,
            &rosters,
            &abort_tbs,
            &finality_vote(first, 7, &abort_tbs)?
        ),
        Err(E2eeError::InvalidValue)
    );
    ledger.record(
        &policy,
        &rosters,
        &finalize_tbs,
        &finality_vote(second, 9, &finalize_tbs)?,
    )?;
    assert!(ledger.quorum_reached(&policy, &finalize));
    assert_eq!(ledger.votes().count(), 2);
    // Non-council, wrong certificate, and forged signature.
    let outsider = principal(42, &[b'c'; 24], &[11])?;
    assert_eq!(
        ledger.record(
            &policy,
            &rosters,
            &finalize_tbs,
            &finality_vote(&outsider, 11, &finalize_tbs)?
        ),
        Err(E2eeError::InvalidValue)
    );
    let mut wrong_certificate = finality_vote(first, 8, &finalize_tbs)?;
    wrong_certificate.signer_device_certificate_id = [1; 32];
    assert_eq!(
        ledger.record(&policy, &rosters, &finalize_tbs, &wrong_certificate),
        Err(E2eeError::InvalidValue)
    );
    let mut forged = finality_vote(first, 8, &finalize_tbs)?;
    forged.device_signature = [0; 64];
    assert_eq!(
        ledger.record(&policy, &rosters, &finalize_tbs, &forged),
        Err(E2eeError::SignatureInvalid)
    );
    // A vector must be canonical; every entry is verified.
    let mut fresh = QuorumLedger::new();
    let votes = vec![
        finality_vote(second, 9, &abort_tbs)?,
        finality_vote(first, 7, &abort_tbs)?,
    ];
    let mut sorted = votes.clone();
    sorted.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
    if sorted == votes {
        assert!(record_vote_vector(&mut fresh, &policy, &rosters, &abort_tbs, &votes).is_ok());
    } else {
        assert_eq!(
            record_vote_vector(&mut fresh, &policy, &rosters, &abort_tbs, &votes),
            Err(E2eeError::NonCanonical)
        );
        record_vote_vector(&mut fresh, &policy, &rosters, &abort_tbs, &sorted)?;
    }
    assert!(fresh.quorum_reached(&policy, &abort));
    Ok(())
}

#[test]
fn accumulated_signatures_form_a_verifiable_quorum_for_only_their_terminal() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7, 8])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = principal_rosters(&principals)?;
    let policy = verify_policy(
        &NETWORK,
        &CONVERSATION,
        &policy(&PolicySpec::moderated(&principals, CONVERSATION))?,
        &rosters,
        None,
    )?;
    let first = principals.first().ok_or("principal")?;
    let second = principals.get(1).ok_or("principal")?;
    let finalize = Terminal::finalize([58; 32]);
    let abort = Terminal::abort([64; 32], 1)?;
    let finalize_tbs = vote_tbs(&slot(), [52; 32], finalize);
    let abort_tbs = vote_tbs(&slot(), [52; 32], abort);
    let mut ledger = QuorumLedger::new();
    ledger.record(
        &policy,
        &rosters,
        &finalize_tbs,
        &finality_vote(second, 9, &finalize_tbs)?,
    )?;
    ledger.record(
        &policy,
        &rosters,
        &abort_tbs,
        &finality_vote(first, 8, &abort_tbs)?,
    )?;
    ledger.record(
        &policy,
        &rosters,
        &finalize_tbs,
        &finality_vote(first, 7, &finalize_tbs)?,
    )?;
    let certificate_votes = ledger.signed_votes(&finalize);
    assert_eq!(certificate_votes.len(), 2);
    assert_eq!(ledger.signed_votes(&abort).len(), 1);
    let mut endpoint = QuorumLedger::new();
    record_vote_vector(
        &mut endpoint,
        &policy,
        &rosters,
        &finalize_tbs,
        &certificate_votes,
    )?;
    assert!(endpoint.quorum_reached(&policy, &finalize));
    assert_eq!(endpoint.count(&abort), 0);
    Ok(())
}
