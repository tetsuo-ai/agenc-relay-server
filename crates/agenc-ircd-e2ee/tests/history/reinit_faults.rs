#![forbid(unsafe_code)]

//! A ReInit attempt must take the exact next slot of the reinit state and name a real
//! successor; an activation or abort must name the attempt that is open, and an abort needs
//! the council's quorum.

use super::*;
use agenc_ircd_e2ee::objects::reinit::{
    IrcReInitAbortCoreTbs, IrcReInitAttempt, IrcReInitAttemptReceipt,
};

const TARGET: [u8; 32] = [72; 32];

/// The pending chain with attempt zero open, and the receipt and attempt that opened it.
type OpenAttempt = (
    Genesis,
    HistoricalChain,
    Log,
    [u8; 32],
    IrcReInitAttemptReceipt,
    IrcReInitAttempt,
);

/// One edit of an abort core.
type CoreEdit = (&'static str, fn(&mut IrcReInitAbortCoreTbs));

/// An activated chain moved into its ReInit lifecycle, with the reinit state id.
fn reinit_pending() -> Result<(Genesis, HistoricalChain, Log, [u8; 32]), E2eeError> {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::REINIT,
        log.policy_id,
        TARGET,
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    adopt(&mut chain, &record)?;
    Ok((genesis, chain, log, record.id))
}

fn attempt_refused(chain: &HistoricalChain, attempt_bytes: &[u8], record: &Built) -> bool {
    let mut probe = chain.clone();
    let refused = probe
        .advance(
            &record.bytes,
            &RecordReferences {
                attempt_object: Some(attempt_bytes),
                ..RecordReferences::default()
            },
            &mut budget(),
        )
        .is_err();
    refused && probe.head() == chain.head()
}

#[test]
fn an_attempt_must_take_the_next_slot_and_name_a_real_successor() -> TestResult {
    let (genesis, chain, log, old_reinit_state_id) = reinit_pending()?;
    let council = operational_council(&genesis);
    let (bytes, record, _, _) = log
        .clone_for_fork()
        .reinit_attempt([9; 32], 0, TARGET, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "another reinit state"
    );
    let (bytes, record, _, _) =
        log.clone_for_fork()
            .reinit_attempt(old_reinit_state_id, 1, TARGET, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "a skipped attempt sequence"
    );
    let mut other_predecessor = log.clone_for_fork();
    other_predecessor.head = [9; 32];
    let (bytes, record, _, _) =
        other_predecessor.reinit_attempt(old_reinit_state_id, 0, TARGET, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "the first attempt must follow the reinit state itself"
    );
    let mut same_conversation = log.clone_for_fork();
    same_conversation.new_conversation = log.conversation;
    let (bytes, record, _, _) =
        same_conversation.reinit_attempt(old_reinit_state_id, 0, TARGET, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "the successor cannot be the old conversation"
    );
    let mut log = log;
    let mut chain = chain;
    let (bytes, record, _, _) = log.reinit_attempt(old_reinit_state_id, 0, TARGET, &council)?;
    chain.advance(
        &record.bytes,
        &RecordReferences {
            attempt_object: Some(&bytes),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    let (bytes, record, _, _) =
        log.clone_for_fork()
            .reinit_attempt(old_reinit_state_id, 1, TARGET, &council)?;
    assert!(
        attempt_refused(&chain, &bytes, &record),
        "no second attempt while one is open"
    );
    Ok(())
}

fn open_attempt() -> Result<OpenAttempt, E2eeError> {
    let (genesis, mut chain, mut log, old_reinit_state_id) = reinit_pending()?;
    let council = operational_council(&genesis);
    let (bytes, record, receipt, attempt) =
        log.reinit_attempt(old_reinit_state_id, 0, TARGET, &council)?;
    chain.advance(
        &record.bytes,
        &RecordReferences {
            attempt_object: Some(&bytes),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    Ok((genesis, chain, log, old_reinit_state_id, receipt, attempt))
}

#[test]
fn an_activation_for_an_attempt_that_is_not_open_is_refused() -> TestResult {
    let (genesis, chain, log, old_reinit_state_id, _, _) = open_attempt()?;
    let council = operational_council(&genesis);
    let mut fork = log.clone_for_fork();
    let (_, _, other_receipt, other_attempt) =
        fork.reinit_attempt(old_reinit_state_id, 1, TARGET, &council)?;
    let activation =
        log.clone_for_fork()
            .reinit_activation(&other_receipt, &other_attempt, &council)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &activation).is_err());
    assert!(!probe.is_terminal());
    Ok(())
}

#[test]
fn an_abort_core_must_name_the_open_attempt_and_reach_the_quorum() -> TestResult {
    let (genesis, chain, log, _, receipt, attempt) = open_attempt()?;
    let council = operational_council(&genesis);
    let edits: [CoreEdit; 5] = [
        ("old conversation", |core| {
            core.old_conversation_id = [9; 32]
        }),
        ("reinit state", |core| core.old_reinit_state_id = [9; 32]),
        ("attempt sequence", |core| core.attempt_sequence = 1),
        ("slot predecessor", |core| {
            core.slot_predecessor_record_id = [9; 32]
        }),
        ("attempt id", |core| core.reinit_attempt_id = [9; 32]),
    ];
    for (name, edit) in edits {
        let abort = log
            .clone_for_fork()
            .reinit_abort_with(&receipt, &attempt, 5, &council, edit)?;
        let mut probe = chain.clone();
        assert!(adopt(&mut probe, &abort).is_err(), "{name}");
        assert_eq!(probe.head(), chain.head(), "{name}");
    }
    let alone = Council {
        genesis: &genesis,
        approvers: vec![(0, 7)],
        voters: vec![(0, 7)],
    };
    let abort = log
        .clone_for_fork()
        .reinit_abort(&receipt, &attempt, 5, &alone)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &abort).is_err(), "one vote is no quorum");
    let abort = log
        .clone_for_fork()
        .reinit_abort(&receipt, &attempt, 5, &council)?;
    let mut probe = chain.clone();
    assert!(matches!(
        adopt(&mut probe, &abort)?,
        ChainStep::ReinitAborted { .. }
    ));
    Ok(())
}
