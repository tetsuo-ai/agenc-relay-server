//! An integrity-checkpoint receipt advances the head only when it proves the
//! exact successor of the committed head.
#![forbid(unsafe_code)]

use agenc_relay_crypto::StorageDigest;
use agenc_relay_storage::{CheckpointOutcome, CheckpointReceipt, StorageError};

use super::*;
use crate::bridge::{StorageCheckpointCompletionMessage, StorageCheckpointId};
use crate::state_core::{
    CheckpointCompletionStep, IndeterminateCause, PendingIntegrityCheckpoint, StateCore,
};

const CHECKPOINT: StorageCheckpointId = StorageCheckpointId::new(77);

fn pend(state: &mut StateCore, shutdown: bool) {
    state.checkpoint_pending = Some(PendingIntegrityCheckpoint {
        checkpoint_id: CHECKPOINT,
        shutdown,
    });
}

fn complete(state: &mut StateCore, outcome: CheckpointOutcome) -> CheckpointCompletionStep {
    state.step_checkpoint_completion(StorageCheckpointCompletionMessage {
        checkpoint_id: CHECKPOINT,
        outcome,
    })
}

/// The receipt storage would issue for the very next checkpoint of `state`.
fn successor_receipt(state: &StateCore) -> TestResult<CheckpointReceipt> {
    let head = state.context.head;
    Ok(CheckpointReceipt {
        cut_manifest_sequence: 3,
        installation_manifest_sequence: 4,
        storage_commit_sequence: head
            .storage_commit_sequence
            .checked_add(1)
            .ok_or("commit sequence")?,
        state_generation: head.state_generation,
        account_service_response_count: head.account_service_response_count,
        logical_database_bytes: head.logical_database_bytes,
        backup_stream_bytes: head.backup_stream_bytes,
        rollback_guard_hash: StorageDigest::from_bytes([5; 32]),
        readback_scratch: Default::default(),
    })
}

fn is_mismatch(step: &CheckpointCompletionStep) -> bool {
    matches!(
        step,
        CheckpointCompletionStep::Exit(StateCoreExit::Indeterminate(
            IndeterminateCause::TransactionMismatch
        ))
    )
}

#[test]
fn a_checkpoint_receipt_nobody_waits_for_is_indeterminate() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let step = complete(state, CheckpointOutcome::NotNeeded);
    assert!(matches!(
        step,
        CheckpointCompletionStep::Exit(StateCoreExit::Indeterminate(
            IndeterminateCause::UnexpectedCompletion
        ))
    ));
    Ok(())
}

#[test]
fn a_checkpoint_receipt_for_another_request_is_a_transaction_mismatch() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    pend(state, false);
    let step = state.step_checkpoint_completion(StorageCheckpointCompletionMessage {
        checkpoint_id: StorageCheckpointId::new(78),
        outcome: CheckpointOutcome::NotNeeded,
    });
    assert!(is_mismatch(&step));
    Ok(())
}

#[test]
fn an_unneeded_periodic_checkpoint_completes_normally_and_a_shutdown_one_completes_shutdown()
-> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    state.checkpoint_retry_suppressed = true;
    pend(state, false);
    assert!(matches!(
        complete(state, CheckpointOutcome::NotNeeded),
        CheckpointCompletionStep::Normal
    ));
    assert!(!state.checkpoint_retry_suppressed);
    pend(state, true);
    assert!(matches!(
        complete(state, CheckpointOutcome::NotNeeded),
        CheckpointCompletionStep::ShutdownComplete
    ));
    assert!(state.checkpoint_pending.is_none());
    Ok(())
}

#[test]
fn an_installed_successor_receipt_advances_the_head_and_counts_one_commit() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let mut receipt = successor_receipt(state)?;
    receipt.logical_database_bytes += 1;
    receipt.backup_stream_bytes += 2;
    let committed = state.context.counters.batches_committed;
    pend(state, false);
    assert!(matches!(
        complete(state, CheckpointOutcome::Installed(receipt)),
        CheckpointCompletionStep::Normal
    ));
    let head = state.context.head;
    assert_eq!(
        head.storage_commit_sequence,
        receipt.storage_commit_sequence
    );
    assert_eq!(head.logical_database_bytes, receipt.logical_database_bytes);
    assert_eq!(head.backup_stream_bytes, receipt.backup_stream_bytes);
    assert_eq!(state.context.counters.batches_committed, committed + 1);

    let next = successor_receipt(state)?;
    pend(state, true);
    assert!(matches!(
        complete(state, CheckpointOutcome::Installed(next)),
        CheckpointCompletionStep::ShutdownComplete
    ));
    Ok(())
}

fn forged_receipts(state: &StateCore) -> TestResult<Vec<(&'static str, CheckpointReceipt)>> {
    let good = successor_receipt(state)?;
    let ceilings = state.context.ceilings;
    Ok(vec![
        (
            "commit sequence",
            CheckpointReceipt {
                storage_commit_sequence: good.storage_commit_sequence + 1,
                ..good
            },
        ),
        (
            "state generation",
            CheckpointReceipt {
                state_generation: good.state_generation + 1,
                ..good
            },
        ),
        (
            "response count",
            CheckpointReceipt {
                account_service_response_count: good.account_service_response_count + 1,
                ..good
            },
        ),
        (
            "cut after installation",
            CheckpointReceipt {
                cut_manifest_sequence: good.installation_manifest_sequence + 1,
                ..good
            },
        ),
        (
            "database ceiling",
            CheckpointReceipt {
                logical_database_bytes: ceilings.database_max_bytes + 1,
                ..good
            },
        ),
        (
            "backup ceiling",
            CheckpointReceipt {
                backup_stream_bytes: ceilings.backup_max_bytes + 1,
                ..good
            },
        ),
    ])
}

#[test]
fn a_receipt_that_is_not_the_exact_successor_never_moves_the_head() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let head = state.context.head;
    for (field, receipt) in forged_receipts(state)? {
        pend(state, false);
        let step = complete(state, CheckpointOutcome::Installed(receipt));
        assert!(is_mismatch(&step), "{field}");
        assert_eq!(state.context.head, head, "{field}");
    }
    Ok(())
}

#[test]
fn a_commit_sequence_at_its_ceiling_cannot_accept_any_checkpoint_receipt() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let receipt = successor_receipt(state)?;
    state.context.head.storage_commit_sequence = u64::MAX;
    pend(state, false);
    assert!(is_mismatch(&complete(
        state,
        CheckpointOutcome::Installed(receipt)
    )));
    assert_eq!(state.context.head.storage_commit_sequence, u64::MAX);
    Ok(())
}

#[test]
fn a_rejected_checkpoint_suppresses_periodic_retries_but_not_the_shutdown_one() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    let rejected = state.context.counters.batches_rejected;
    pend(state, false);
    assert!(matches!(
        complete(
            state,
            CheckpointOutcome::Rejected(StorageError::LimitExceeded)
        ),
        CheckpointCompletionStep::Normal
    ));
    assert_eq!(state.context.counters.batches_rejected, rejected + 1);
    assert!(state.checkpoint_retry_suppressed);
    assert!(matches!(state.start_integrity_checkpoint(false), Ok(false)));
    assert!(state.checkpoint_pending.is_none());

    assert!(matches!(state.start_integrity_checkpoint(true), Ok(true)));
    assert!(
        state
            .checkpoint_pending
            .as_ref()
            .is_some_and(|pending| pending.shutdown)
    );
    assert!(matches!(state.start_integrity_checkpoint(true), Ok(false)));
    Ok(())
}

#[test]
fn a_rejected_shutdown_checkpoint_is_reported_and_an_indeterminate_one_ends_the_core() -> TestResult
{
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    pend(state, true);
    assert!(matches!(
        complete(state, CheckpointOutcome::Rejected(StorageError::QueueFull)),
        CheckpointCompletionStep::ShutdownRejected
    ));
    pend(state, true);
    assert!(matches!(
        complete(state, CheckpointOutcome::Indeterminate),
        CheckpointCompletionStep::Exit(StateCoreExit::Indeterminate(
            IndeterminateCause::StorageIndeterminate
        ))
    ));
    Ok(())
}
