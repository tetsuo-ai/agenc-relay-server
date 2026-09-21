//! A storage receipt that does not answer the one transaction in flight ends
//! the core instead of being applied.
#![forbid(unsafe_code)]

use agenc_relay_admin::AdminAuditPhase;
use agenc_relay_crypto::StorageDigest;
use agenc_relay_storage::{CommitOutcome, CommitReceipt, StorageError};
use agenc_relay_types::TransactionId;

use super::support::{account_plan, audit_event, empty_fanout, observe};
use super::*;
use crate::bridge::StorageCompletionMessage;
use crate::observe::metrics::{CommandClass, ResultClass};
use crate::state_core::admin::{AdminCoreFailure, AdminCoreRequest, AdminCoreResult};
use crate::state_core::{
    BatchStep, CommandObservation, CompletionStep, IndeterminateCause, StagedOrigin, StateCore,
};

const FOREIGN: TransactionId = TransactionId::from_bytes([0xEE; 16]);

fn receipt(transaction_id: TransactionId) -> CommitReceipt {
    CommitReceipt {
        transaction_id,
        storage_commit_sequence: 2,
        state_generation: 1,
        rollback_guard_hash: StorageDigest::from_bytes([6; 32]),
    }
}

fn exit_cause(step: CompletionStep) -> Option<IndeterminateCause> {
    match step {
        CompletionStep::Ready(Some(StateCoreExit::Indeterminate(cause))) => Some(cause),
        _ => None,
    }
}

/// Stages one observed account creation and hands it to storage.
fn submit_observed_batch(state: &mut StateCore) -> TestResult<TransactionId> {
    let plan = account_plan(&state.context, 7)?;
    let origin = StagedOrigin::silent(ConnectionGeneration::new(1))
        .with_observation(Some(CommandObservation::new(CommandClass::Session)));
    state
        .context
        .stage_durable(plan, empty_fanout()?, Some(origin), 0)
        .map_err(|refused| format!("{refused:?}"))?;
    if !matches!(state.context.submit_batch(), Ok(BatchStep::Submitted)) {
        return Err("batch was not submitted".into());
    }
    Ok(state
        .context
        .pending
        .as_ref()
        .and_then(|batch| batch.transaction_id())
        .ok_or("no transaction in flight")?)
}

#[test]
fn a_commit_receipt_with_nothing_in_flight_is_an_unexpected_completion() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(vec![7; 4096])?;
    let state = fixture.state_mut()?;
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id: FOREIGN,
        outcome: CommitOutcome::Committed(receipt(FOREIGN)),
    });
    assert!(matches!(
        exit_cause(step),
        Some(IndeterminateCause::UnexpectedCompletion)
    ));
    Ok(())
}

#[test]
fn a_receipt_for_a_foreign_transaction_is_a_mismatch_observed_as_an_error() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(vec![7; 4096])?;
    let observed = observe(fixture.state_mut()?);
    let state = fixture.state_mut()?;
    let _submitted = submit_observed_batch(state)?;
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id: FOREIGN,
        outcome: CommitOutcome::Committed(receipt(FOREIGN)),
    });
    assert!(matches!(
        exit_cause(step),
        Some(IndeterminateCause::TransactionMismatch)
    ));
    assert_eq!(state.context.domain().revision().get(), 0);
    assert_eq!(
        observed.commands(CommandClass::Session, ResultClass::Error)?,
        1
    );
    Ok(())
}

#[test]
fn a_committed_receipt_naming_another_transaction_is_never_applied() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(vec![7; 4096])?;
    let observed = observe(fixture.state_mut()?);
    let state = fixture.state_mut()?;
    let transaction_id = submit_observed_batch(state)?;
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id,
        outcome: CommitOutcome::Committed(receipt(FOREIGN)),
    });
    assert!(matches!(
        exit_cause(step),
        Some(IndeterminateCause::TransactionMismatch)
    ));
    assert_eq!(state.context.counters.batches_committed, 0);
    assert_eq!(
        observed.commands(CommandClass::Session, ResultClass::Error)?,
        1
    );
    Ok(())
}

#[test]
fn an_indeterminate_commit_ends_the_core_and_observes_the_command_as_an_error() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(vec![7; 4096])?;
    let observed = observe(fixture.state_mut()?);
    let state = fixture.state_mut()?;
    let transaction_id = submit_observed_batch(state)?;
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id,
        outcome: CommitOutcome::Indeterminate,
    });
    assert!(matches!(
        exit_cause(step),
        Some(IndeterminateCause::StorageIndeterminate)
    ));
    assert_eq!(
        observed.commands(CommandClass::Session, ResultClass::Error)?,
        1
    );
    Ok(())
}

#[test]
fn a_rejected_batch_observes_its_command_by_the_storage_error_class() -> TestResult {
    for (error, result) in [
        (StorageError::QueueFull, ResultClass::Busy),
        (StorageError::LimitExceeded, ResultClass::Rejected),
        (StorageError::Unavailable, ResultClass::Error),
    ] {
        let mut fixture = StateCoreFixture::with_registration_router(vec![7; 4096])?;
        let observed = observe(fixture.state_mut()?);
        let state = fixture.state_mut()?;
        let transaction_id = submit_observed_batch(state)?;
        let step = state.step_completion(StorageCompletionMessage {
            transaction_id,
            outcome: CommitOutcome::Rejected(error),
        });
        assert!(matches!(step, CompletionStep::Refresh(_)), "{error:?}");
        assert_eq!(state.context.counters.batches_rejected, 1, "{error:?}");
        assert_eq!(state.context.pending_len(), 0, "{error:?}");
        assert_eq!(state.context.domain().revision().get(), 0, "{error:?}");
        assert_eq!(observed.commands(CommandClass::Session, result)?, 1);
    }
    Ok(())
}

/// Submits one audit-only administrative commit and returns its reply.
fn submit_audit(
    state: &mut StateCore,
) -> TestResult<(TransactionId, oneshot::Receiver<AdminCoreResult>)> {
    let (reply, response) = oneshot::channel();
    let exit = state.step_admin_request(AdminCoreRequest::CommitAudit {
        event: Box::new(audit_event(AdminAuditPhase::Observed, b"MOTD")?),
        reply,
    });
    if exit.is_some() {
        return Err(format!("audit commit ended the core: {exit:?}").into());
    }
    let pending = state.admin_pending.as_ref().ok_or("no admin commit")?;
    Ok((pending.transaction_id, response))
}

#[test]
fn an_admin_receipt_nobody_waits_for_is_an_unexpected_completion() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let step = state.step_admin_completion(StorageCompletionMessage {
        transaction_id: FOREIGN,
        outcome: CommitOutcome::Indeterminate,
    });
    assert!(matches!(
        exit_cause(step),
        Some(IndeterminateCause::UnexpectedCompletion)
    ));
    Ok(())
}

#[test]
fn an_admin_receipt_for_a_foreign_transaction_is_a_mismatch() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let (_transaction_id, mut response) = submit_audit(state)?;
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id: FOREIGN,
        outcome: CommitOutcome::Committed(receipt(FOREIGN)),
    });
    assert!(matches!(
        exit_cause(step),
        Some(IndeterminateCause::TransactionMismatch)
    ));
    assert!(
        response.try_recv().is_err(),
        "the operator is never told it committed"
    );
    Ok(())
}

#[test]
fn an_admin_commit_receipt_naming_another_transaction_is_never_applied() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let head = state.context.head;
    let (transaction_id, _response) = submit_audit(state)?;
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id,
        outcome: CommitOutcome::Committed(receipt(FOREIGN)),
    });
    assert!(matches!(
        exit_cause(step),
        Some(IndeterminateCause::TransactionMismatch)
    ));
    assert_eq!(state.context.head, head);
    Ok(())
}

#[test]
fn a_rejected_admin_commit_tells_the_operator_storage_is_unavailable() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let (transaction_id, mut response) = submit_audit(state)?;
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id,
        outcome: CommitOutcome::Rejected(StorageError::LimitExceeded),
    });
    assert!(matches!(step, CompletionStep::Ready(None)));
    assert_eq!(
        response.try_recv()?,
        Err(AdminCoreFailure::StorageUnavailable)
    );
    assert_eq!(state.context.counters.batches_rejected, 1);
    assert!(state.admin_pending.is_none());
    Ok(())
}

#[test]
fn an_indeterminate_admin_commit_ends_the_core() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let (transaction_id, _response) = submit_audit(state)?;
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id,
        outcome: CommitOutcome::Indeterminate,
    });
    assert!(matches!(
        exit_cause(step),
        Some(IndeterminateCause::StorageIndeterminate)
    ));
    Ok(())
}
