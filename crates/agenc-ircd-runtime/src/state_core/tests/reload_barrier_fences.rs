//! The audited reload barrier and the index read-back accept only the exact
//! activation, state and receipt they reserved.
#![forbid(unsafe_code)]

use agenc_ircd_admin::AdminAuditPhase::{OutcomeFailure, OutcomeSuccess};
use agenc_ircd_storage::{CommitOutcome, ReadResult, StorageError, StoredKey, TableId};
use agenc_ircd_types::TransactionId;

use super::support::audit_event;
use super::*;
use crate::bridge::{StorageCompletionMessage, StorageReadCompletionMessage, StorageReadId};
use crate::runtime_config::{
    AuditedReloadResult, AuditedReloadStart, ConfigRevision, PreparedReload, ReloadActivation,
    ReloadCoreRequest, ReloadRejection, RuntimeConfigHandle,
};
use crate::state_core::{
    CompletionStep, CorruptionCause, IndeterminateCause, IndexRefreshContinuation,
    PendingAdminReply, PendingIndexRefresh, PendingLifecycleReplies, StateCore,
};
use crate::test_support::{golden_config, golden_parts, golden_snapshot};

const REHASH: &[u8] = b"REHASH :reload now";
const FOREIGN: ReloadActivation = ReloadActivation {
    revision: ConfigRevision::INITIAL,
    transaction_id: TransactionId::from_bytes([0xEE; 16]),
    changes_live_state: true,
};

/// A fixture holding one provisional audited reload of the message of the day.
fn provisional() -> TestResult<(StateCoreFixture, ReloadActivation)> {
    // Distinct bytes per draw, so the two reserved outcomes differ in identity.
    let entropy = (0_u32..4_096)
        .map(|index| u8::try_from((index * 7 + 3) % 256).unwrap_or_default())
        .collect();
    let mut fixture = StateCoreFixture::new(entropy)?;
    let handle = RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?);
    let _port = fixture.install_reload_port(handle.clone())?;
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some("Audited"))?,
    )?;
    let state = fixture.state_mut()?;
    let (reply, mut response) = oneshot::channel();
    let _exit = state.step_reload_request(ReloadCoreRequest::ActivateAudited {
        prepared: Box::new(prepared),
        success_event: Box::new(audit_event(OutcomeSuccess, REHASH)?),
        failure_event: Box::new(audit_event(OutcomeFailure, REHASH)?),
        reply,
    });
    if state.activate_pending_reload().is_some() {
        return Err("the audited reload ended the core".into());
    }
    let AuditedReloadStart::Provisional(activation) = response.try_recv()? else {
        return Err("the audited reload was not provisional".into());
    };
    Ok((fixture, activation))
}

fn reload_continuation(
    activation: ReloadActivation,
    result: AuditedReloadResult,
) -> IndexRefreshContinuation {
    let (reply, _response) = oneshot::channel();
    IndexRefreshContinuation::Admin(PendingAdminReply::Reload {
        activation,
        result,
        reply,
    })
}

fn is_refresh_failure(result: Result<(), StateCoreExit>) -> bool {
    matches!(
        result,
        Err(StateCoreExit::Corrupt(CorruptionCause::IndexRefreshFailed))
    )
}

fn commit(state: &mut StateCore, activation: ReloadActivation) -> Option<StateCoreExit> {
    let (reply, _response) = oneshot::channel();
    state.step_reload_request(ReloadCoreRequest::CommitOutcome { activation, reply })
}

#[test]
fn a_reload_read_back_without_its_provisional_barrier_is_corrupt() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let continuation = reload_continuation(FOREIGN, AuditedReloadResult::Success);
    assert!(is_refresh_failure(
        state.complete_index_refresh(continuation)
    ));
    Ok(())
}

#[test]
fn a_reload_read_back_for_another_activation_or_state_is_corrupt() -> TestResult {
    let (mut fixture, activation) = provisional()?;
    let state = fixture.state_mut()?;
    let foreign = reload_continuation(FOREIGN, AuditedReloadResult::Success);
    assert!(is_refresh_failure(state.complete_index_refresh(foreign)));
    let premature = reload_continuation(activation, AuditedReloadResult::Success);
    assert!(
        is_refresh_failure(state.complete_index_refresh(premature)),
        "the outcome was never submitted"
    );
    assert!(commit(state, activation).is_none());
    let wrong_result = reload_continuation(
        activation,
        AuditedReloadResult::Failure(ReloadRejection::Busy),
    );
    assert!(is_refresh_failure(
        state.complete_index_refresh(wrong_result)
    ));
    Ok(())
}

#[test]
fn a_committed_reload_outcome_must_match_the_barrier_it_was_reserved_under() -> TestResult {
    let (mut fixture, activation) = provisional()?;
    let state = fixture.state_mut()?;
    let is_apply_failure = |result: Result<(), StateCoreExit>| {
        matches!(
            result,
            Err(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed))
        )
    };
    assert!(
        is_apply_failure(
            state.mark_reload_outcome_committed(activation, AuditedReloadResult::Success)
        ),
        "the outcome was never submitted"
    );
    assert!(commit(state, activation).is_none());
    assert!(is_apply_failure(state.mark_reload_outcome_committed(
        FOREIGN,
        AuditedReloadResult::Success
    )));
    assert!(is_apply_failure(state.mark_reload_outcome_committed(
        activation,
        AuditedReloadResult::Failure(ReloadRejection::Busy)
    )));
    assert!(
        state
            .mark_reload_outcome_committed(activation, AuditedReloadResult::Success)
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn a_rejected_success_outcome_falls_back_to_the_reserved_failure_outcome() -> TestResult {
    let (mut fixture, activation) = provisional()?;
    let mut parts = fixture.take_run_parts()?;
    let state = &mut parts.state;
    assert!(commit(state, activation).is_none());
    // Storage settles the success outcome; the core is told it was rejected.
    let settled = parts.storage.recv().await.ok_or("storage closed")?;
    assert_eq!(settled.transaction_id, activation.transaction_id);
    let step = state.step_completion(StorageCompletionMessage {
        transaction_id: activation.transaction_id,
        outcome: CommitOutcome::Rejected(StorageError::LimitExceeded),
    });
    assert!(matches!(step, CompletionStep::Ready(None)));
    let fallback = state
        .admin_pending
        .as_ref()
        .map(|pending| pending.transaction_id)
        .ok_or("the failure outcome was not submitted")?;
    assert_ne!(fallback, activation.transaction_id);
    assert_eq!(state.context.counters.batches_rejected, 1);

    let step = state.step_completion(StorageCompletionMessage {
        transaction_id: fallback,
        outcome: CommitOutcome::Rejected(StorageError::LimitExceeded),
    });
    assert!(
        matches!(
            step,
            CompletionStep::Ready(Some(StateCoreExit::Indeterminate(
                IndeterminateCause::StorageIndeterminate
            )))
        ),
        "a failure outcome that cannot be recorded is never reported as settled"
    );
    Ok(())
}

fn refresh_of_one_row() -> TestResult<PendingIndexRefresh> {
    let row = (TableId::OpaqueRecord, StoredKey::new(vec![1, 2, 3])?);
    Ok(PendingIndexRefresh::new(
        vec![row],
        4,
        IndexRefreshContinuation::Batch,
    )?)
}

fn read(read_id: u64, result: Result<ReadResult, StorageError>) -> StorageReadCompletionMessage {
    StorageReadCompletionMessage {
        read_id: StorageReadId::new(read_id),
        result,
    }
}

fn waiting_refresh() -> TestResult<PendingIndexRefresh> {
    let mut pending = refresh_of_one_row()?;
    let (table, key) = pending.remaining.pop_front().ok_or("row")?;
    pending.waiting = Some((StorageReadId::new(7), table, key));
    Ok(pending)
}

#[test]
fn an_index_read_back_accepts_only_the_read_it_waits_for() -> TestResult {
    let mut idle = refresh_of_one_row()?;
    assert!(!idle.owns(StorageReadId::new(7)));
    assert!(
        idle.complete_read(read(7, Err(StorageError::Unavailable)))
            .is_err()
    );

    let mut pending = waiting_refresh()?;
    assert!(pending.owns(StorageReadId::new(7)));
    assert!(!pending.owns(StorageReadId::new(8)));
    assert!(
        pending
            .complete_read(read(8, Err(StorageError::Unavailable)))
            .is_err()
    );
    Ok(())
}

#[test]
fn an_index_read_back_refuses_a_failed_or_stale_read() -> TestResult {
    let mut failed = waiting_refresh()?;
    assert!(matches!(
        failed.complete_read(read(7, Err(StorageError::Unavailable))),
        Err(crate::RuntimeError::Storage(StorageError::Unavailable))
    ));
    let mut stale = waiting_refresh()?;
    let older = ReadResult {
        storage_commit_sequence: 3,
        records: Vec::new(),
        truncated: false,
    };
    assert!(matches!(
        stale.complete_read(read(7, Ok(older))),
        Err(crate::RuntimeError::Storage(StorageError::StaleState))
    ));
    Ok(())
}

#[test]
fn an_index_read_back_cannot_finish_or_resubmit_with_rows_outstanding() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let state = fixture.state_mut()?;
    assert!(
        refresh_of_one_row()?
            .finish(&mut state.context.index)
            .is_err()
    );
    assert!(waiting_refresh()?.finish(&mut state.context.index).is_err());
    let mut waiting = waiting_refresh()?;
    assert!(waiting.submit_next(&mut state.context.bridge).is_err());
    Ok(())
}

#[tokio::test]
async fn a_lifecycle_failure_reaches_only_the_waiter_of_its_phase() -> TestResult {
    use crate::state_core::inbox::LifecycleFailure;
    let mut pending = PendingLifecycleReplies::default();
    pending.fail(LifecyclePhase::Flush, LifecycleFailure::Unavailable);
    pending.acknowledge(LifecyclePhase::Drain);
    pending.fail(LifecyclePhase::Stop, LifecycleFailure::Unavailable);

    let (drain_reply, mut drain) = oneshot::channel();
    pending.install(LifecyclePhase::Drain, drain_reply);
    let (flush_reply, flush) = oneshot::channel();
    pending.install(LifecyclePhase::Flush, flush_reply);
    pending.fail(LifecyclePhase::Flush, LifecycleFailure::Unavailable);
    assert_eq!(flush.await?, Err(LifecycleFailure::Unavailable));
    assert!(drain.try_recv().is_err(), "the drain waiter still waits");
    pending.fail(LifecyclePhase::Drain, LifecycleFailure::Busy);
    assert_eq!(drain.await?, Err(LifecycleFailure::Busy));

    let (stop_reply, stop) = oneshot::channel();
    pending.install(LifecyclePhase::Stop, stop_reply);
    assert_eq!(stop.await?, Ok(()));
    Ok(())
}
