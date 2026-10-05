#![forbid(unsafe_code)]

//! The sequencer log state machine.

use super::*;

const CONVERSATION: Id = [1; 32];
const GENESIS: Id = [2; 32];
/// The finalization of the ReInit Commit of [`reinit_log`].
const REINIT: Id = [20; 32];

fn candidate(log: &mut SequencerLog, id: u8) -> Result<CandidatePosition, LogError> {
    let position = log.candidate_position(log.accepted_epoch())?;
    log.record_candidate([id; 32], [id + 100; 32], position)?;
    Ok(position)
}

/// A log whose ReInit Commit, candidate 10 of epoch zero, finalized as
/// [`REINIT`] at route sequence one.
fn reinit_log() -> Result<SequencerLog, LogError> {
    let mut log = SequencerLog::genesis(CONVERSATION, GENESIS);
    candidate(&mut log, 10)?;
    log.finalize_reinit(&[10; 32], REINIT, 1)?;
    Ok(log)
}

#[test]
fn candidates_finalize_and_abort_with_exact_positions() -> Result<(), LogError> {
    let mut log = SequencerLog::genesis(CONVERSATION, GENESIS);
    assert_eq!(log.conversation_id(), &CONVERSATION);
    assert_eq!(log.head().sequence, 0);
    assert!(!log.head().recorded);
    assert!(log.accepts_application());
    let first = candidate(&mut log, 10)?;
    assert_eq!(
        first,
        CandidatePosition {
            route_sequence: 0,
            prior_epoch: 0,
            prior_state_id: GENESIS,
            candidate_sequence: 0,
            predecessor_record_id: GENESIS,
        }
    );
    assert_eq!(log.head().record_id, [10; 32]);
    assert_eq!(log.candidate_position(0), Err(LogError::CandidateActive));
    assert_eq!(
        log.terminal_position(&[11; 32]),
        Err(LogError::NoSuchCandidate)
    );
    assert_eq!(
        log.terminal_position(&[10; 32])?,
        TerminalPosition {
            route_sequence: 1,
            predecessor_record_id: [10; 32],
        }
    );
    assert!(!log.proof_snapshot_allowed(&[10; 32]));
    assert_eq!(
        log.finalize(&[10; 32], [20; 32], 2),
        Err(LogError::EpochStale)
    );
    let position = log.finalize(&[10; 32], [20; 32], 1)?;
    assert_eq!(position.route_sequence, 1);
    assert_eq!(log.accepted_state_id(), &[20; 32]);
    assert_eq!(log.accepted_epoch(), 1);
    assert!(log.proof_snapshot_allowed(&[20; 32]));
    assert_eq!(log.candidate_position(0), Err(LogError::EpochStale));
    let second = candidate(&mut log, 11)?;
    assert_eq!(second.route_sequence, 2);
    assert_eq!(second.candidate_sequence, 0);
    assert_eq!(second.prior_state_id, [20; 32]);
    assert_eq!(second.predecessor_record_id, [20; 32]);
    let aborted = log.abort(&[11; 32], [21; 32])?;
    assert_eq!(aborted.route_sequence, 3);
    assert_eq!(aborted.predecessor_record_id, [11; 32]);
    assert_eq!(
        log.accepted_state_id(),
        &[20; 32],
        "an abort keeps the state"
    );
    let third = candidate(&mut log, 12)?;
    assert_eq!(third.route_sequence, 4);
    assert_eq!(third.candidate_sequence, 1);
    assert_eq!(third.predecessor_record_id, [21; 32]);
    assert_eq!(third.prior_state_id, [20; 32]);
    assert_eq!(log.check_incoming_position(5, &[12; 32]), Ok(()));
    assert_eq!(
        log.check_incoming_position(6, &[12; 32]),
        Err(LogError::EpochStale)
    );
    assert_eq!(
        log.check_incoming_position(5, &[11; 32]),
        Err(LogError::EpochStale)
    );
    Ok(())
}

#[test]
fn an_epoch_permits_a_bounded_number_of_attempts() -> Result<(), LogError> {
    let mut log = SequencerLog::genesis(CONVERSATION, GENESIS);
    for attempt in 0..8_u8 {
        candidate(&mut log, 30 + attempt)?;
        log.abort(&[30 + attempt; 32], [60 + attempt; 32])?;
    }
    assert_eq!(log.candidate_position(0), Err(LogError::AttemptsExhausted));
    let mut fresh = SequencerLog::genesis(CONVERSATION, GENESIS);
    let wrong = CandidatePosition {
        route_sequence: 1,
        ..fresh.candidate_position(0)?
    };
    assert_eq!(
        fresh.record_candidate([1; 32], [2; 32], wrong),
        Err(LogError::EpochStale)
    );
    Ok(())
}

#[test]
fn reinit_attempts_activate_or_abort_and_migrate_the_log() -> Result<(), LogError> {
    let mut log = SequencerLog::genesis(CONVERSATION, GENESIS);
    assert_eq!(log.attempt_position(), Err(LogError::NotReinit));
    // Without an active candidate there is nothing to finalize into the
    // phase, and a refused finalization changes nothing.
    assert_eq!(
        log.finalize_reinit(&[10; 32], [20; 32], 1),
        Err(LogError::NoSuchCandidate)
    );
    candidate(&mut log, 10)?;
    let before = log.clone();
    assert_eq!(
        log.finalize_reinit(&[11; 32], [20; 32], 1),
        Err(LogError::NoSuchCandidate)
    );
    assert_eq!(
        log.finalize_reinit(&[10; 32], [20; 32], 2),
        Err(LogError::EpochStale)
    );
    assert_eq!(log, before);
    // The ReInit finalization closes the old group in the same step.
    let finalized = log.finalize_reinit(&[10; 32], [20; 32], 1)?;
    assert_eq!(finalized.route_sequence, 1);
    assert_eq!(finalized.predecessor_record_id, [10; 32]);
    assert_eq!(
        log.phase(),
        Phase::Reinit {
            old_reinit_state_id: [20; 32],
        }
    );
    assert_eq!(log.accepted_state_id(), &[20; 32]);
    assert_eq!(log.accepted_epoch(), 1);
    assert!(!log.accepts_application());
    assert_eq!(log.candidate_position(1), Err(LogError::Closed));
    assert_eq!(log.close([90; 32]), Err(LogError::Closed));
    assert_eq!(
        log.finalize_reinit(&[10; 32], [21; 32], 2),
        Err(LogError::Closed)
    );
    let slot = log.attempt_position()?;
    assert_eq!(slot.route_sequence, 2);
    assert_eq!(slot.attempt_sequence, 0);
    assert_eq!(slot.predecessor_record_id, [20; 32]);
    let recorded = log.record_attempt([40; 32])?;
    assert_eq!(recorded.attempt_id, [40; 32]);
    assert_eq!(log.attempt_position(), Err(LogError::CandidateActive));
    assert_eq!(
        log.attempt_terminal_position(&[41; 32]),
        Err(LogError::NoSuchCandidate)
    );
    let aborted = log.abort_attempt(&[40; 32], [50; 32])?;
    assert_eq!(aborted.route_sequence, 3);
    assert_eq!(aborted.predecessor_record_id, [40; 32]);
    let next = log.attempt_position()?;
    assert_eq!(next.attempt_sequence, 1);
    assert_eq!(next.predecessor_record_id, [50; 32]);
    assert_eq!(next.route_sequence, 4);
    log.record_attempt([41; 32])?;
    let activated = log.activate(&[41; 32], [60; 32], [70; 32])?;
    assert_eq!(activated.route_sequence, 5);
    assert_eq!(
        log.phase(),
        Phase::Migrated {
            activation_id: [60; 32],
            new_conversation_id: [70; 32],
        }
    );
    assert_eq!(log.reinit_attempt(), None);
    let successor = SequencerLog::from_activation([70; 32], [60; 32]);
    assert_eq!(successor.accepted_epoch(), 1);
    assert_eq!(successor.accepted_state_id(), &[60; 32]);
    assert_eq!(successor.candidate_position(1)?.route_sequence, 0);
    Ok(())
}

#[test]
fn close_is_the_last_record_and_restore_reproduces_the_head() -> Result<(), LogError> {
    let mut log = SequencerLog::genesis(CONVERSATION, GENESIS);
    candidate(&mut log, 10)?;
    assert_eq!(log.close([90; 32]), Err(LogError::Closed));
    log.finalize(&[10; 32], [20; 32], 1)?;
    let closed = log.close([90; 32])?;
    assert_eq!(closed.route_sequence, 2);
    assert_eq!(closed.predecessor_record_id, [20; 32]);
    assert_eq!(log.phase(), Phase::Closed { close_id: [90; 32] });
    assert!(!log.accepts_application());
    assert_eq!(log.candidate_position(1), Err(LogError::Closed));
    assert_eq!(log.close([91; 32]), Err(LogError::Closed));
    let restored = SequencerLog::restore(
        CONVERSATION,
        log.head(),
        *log.accepted_state_id(),
        log.accepted_epoch(),
        log.phase(),
    );
    assert_eq!(restored.head(), log.head());
    assert_eq!(restored.phase(), log.phase());
    assert_eq!(restored.candidate(), None);
    assert!(!LogError::Overflow.to_string().is_empty());
    Ok(())
}

#[test]
fn reinit_restore_preserves_active_and_exhausted_attempt_slots() -> Result<(), LogError> {
    let mut original = reinit_log()?;
    let slot = original.record_attempt([40; 32])?;
    let mut restored =
        SequencerLog::restore(CONVERSATION, original.head(), REINIT, 1, original.phase());
    restored.restore_reinit(Some(slot), 0)?;
    assert_eq!(restored, original);
    restored.abort_attempt(&slot.attempt_id, [11; 32])?;
    let mut after_abort =
        SequencerLog::restore(CONVERSATION, restored.head(), REINIT, 1, restored.phase());
    after_abort.restore_reinit(None, 1)?;
    assert_eq!(after_abort, restored);
    assert_eq!(
        after_abort.attempt_position()?.predecessor_record_id,
        [11; 32]
    );
    after_abort.restore_reinit(None, MAX_CANDIDATE_ATTEMPTS_PER_EPOCH)?;
    assert_eq!(
        after_abort.attempt_position(),
        Err(LogError::AttemptsExhausted)
    );
    let before = after_abort.clone();
    assert_eq!(
        after_abort.restore_reinit(None, MAX_CANDIDATE_ATTEMPTS_PER_EPOCH + 1),
        Err(LogError::AttemptsExhausted)
    );
    assert_eq!(after_abort, before);
    Ok(())
}

#[test]
fn reinit_restore_rejects_a_slot_that_does_not_match_its_head() -> Result<(), LogError> {
    let mut open = SequencerLog::genesis(CONVERSATION, GENESIS);
    assert_eq!(open.restore_reinit(None, 0), Err(LogError::NotReinit));
    let mut original = reinit_log()?;
    let slot = original.record_attempt([40; 32])?;
    let mut restored =
        SequencerLog::restore(CONVERSATION, original.head(), REINIT, 1, original.phase());
    let before = restored.clone();
    for invalid in [
        AttemptSlot {
            attempt_id: [11; 32],
            ..slot
        },
        AttemptSlot {
            route_sequence: 1,
            ..slot
        },
        AttemptSlot {
            attempt_sequence: 1,
            ..slot
        },
    ] {
        assert_eq!(
            restored.restore_reinit(Some(invalid), 0),
            Err(LogError::EpochStale)
        );
        assert_eq!(restored, before);
    }
    Ok(())
}

#[test]
fn reinit_entry_and_restore_refuse_repeats_stale_states_unrecorded_heads_and_exhaustion()
-> Result<(), LogError> {
    let mut log = reinit_log()?;
    assert_eq!(
        log.finalize_reinit(&[10; 32], REINIT, 1),
        Err(LogError::Closed)
    );
    let slot = log.record_attempt([40; 32])?;
    // The durable accepted state must be the state the phase names.
    let mut stale = SequencerLog::restore(CONVERSATION, log.head(), [9; 32], 1, log.phase());
    assert_eq!(stale.restore_reinit(None, 0), Err(LogError::EpochStale));
    // A slot needs a recorded head.
    let unrecorded = Head {
        recorded: false,
        ..log.head()
    };
    let mut pending = SequencerLog::restore(CONVERSATION, unrecorded, REINIT, 1, log.phase());
    assert_eq!(
        pending.restore_reinit(Some(slot), 0),
        Err(LogError::EpochStale)
    );
    // A slot at the attempt ceiling is already exhausted.
    let mut exhausted = SequencerLog::restore(CONVERSATION, log.head(), REINIT, 1, log.phase());
    let last = AttemptSlot {
        attempt_sequence: MAX_CANDIDATE_ATTEMPTS_PER_EPOCH,
        ..slot
    };
    assert_eq!(
        exhausted.restore_reinit(Some(last), MAX_CANDIDATE_ATTEMPTS_PER_EPOCH),
        Err(LogError::AttemptsExhausted)
    );
    Ok(())
}
