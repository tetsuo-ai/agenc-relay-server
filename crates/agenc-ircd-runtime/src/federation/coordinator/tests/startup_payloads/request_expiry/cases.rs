//! Completed request cleanup respects exact ownership, retention, and receipt boundaries.
#![forbid(unsafe_code)]
use super::*;
use crate::state_core::timers::TimerHeap;
use agenc_ircd_storage::e2ee_records::{REPLAY_ROW_KIND, ReplayRow};

#[tokio::test]
async fn rejection_keeps_the_replay_and_result_until_an_idle_retry_commits() -> TestResult {
    let mut f = Fixture::new(true).await?;
    let budget = f.core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    f.idle()?;
    assert!(budget.charged() > baseline);
    f.core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_ircd_storage::StorageError::QueueFull)?;
    f.coordinator.batch_rejected(f.core.context_mut()?);
    assert!(f.coordinator.pending.is_none());
    assert_eq!(budget.charged(), baseline);
    assert!(f.executor()?.state.replays.contains_key(&f.key));
    assert!(
        f.stored(TableId::E2eeState, ReplayRow::key(&f.key)?)
            .await?
            .is_some()
    );
    f.retry()?;
    f.commit().await?;
    assert!(f.executor()?.state.replays.is_empty());
    assert!(f.executor()?.state.results.is_empty());
    assert!(budget.charged() < baseline);
    Ok(())
}

#[tokio::test]
async fn lost_publication_after_a_full_page_recovers_two_remaining_results_and_the_final_floor()
-> TestResult {
    let mut f = Fixture::many(130, true).await?;
    assert_eq!(f.executor()?.state.replays.len(), 130);
    f.idle()?;
    f.core.commit_staged_batch().await?;
    assert_eq!(f.executor()?.state.results.len(), 130);
    f.restart().await?;
    assert_eq!(f.executor()?.state.replays.len(), 2);
    assert_eq!(f.executor()?.state.results.len(), 2);
    assert_eq!(f.executor()?.state.objects.len(), 2);
    assert!(
        f.stored(
            TableId::E2eeState,
            ReplayRow::key(&ReplayKey {
                operation_sequence: 127,
                ..f.key
            })?
        )
        .await?
        .is_none()
    );
    assert!(
        f.stored(
            TableId::E2eeState,
            ReplayRow::key(&ReplayKey {
                operation_sequence: 128,
                ..f.key
            })?
        )
        .await?
        .is_some()
    );
    f.idle()?;
    f.commit().await?;
    f.restart().await?;
    assert!(f.executor()?.state.replays.is_empty());
    assert!(f.executor()?.state.results.is_empty());
    assert!(f.executor()?.state.objects.is_empty());
    let floor = f
        .stored(TableId::E2eeState, f.floor_key()?)
        .await?
        .ok_or("floor")?;
    assert_eq!(OriginSequenceRow::decode(floor.body())?.next_sequence, 130);
    Ok(())
}

#[tokio::test]
async fn a_security_retention_deadline_is_not_shortened_to_the_ordinary_window() -> TestResult {
    let mut f = Fixture::new(true).await?;
    let mut row = f
        .executor()?
        .state
        .replays
        .get(&f.key)
        .ok_or("row")?
        .clone();
    row.security_mutation = true;
    row.retain_until = 1000 + agenc_ircd_domain::e2ee::limits::WELCOME_RETENTION_SECONDS;
    let write = request::state_row(
        TableId::E2eeState,
        REPLAY_ROW_KIND,
        ReplayRow::key(&f.key)?,
        row.encode()?,
    )
    .map_err(|e| format!("row: {e:?}"))?;
    helpers::commit(&mut f.core, vec![write]).await?;
    f.restart().await?;
    f.idle()?;
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.executor()?.state.replays.len(), 1);
    f.core.context_mut()?.set_wall_for_test(row.retain_until);
    f.restart().await?;
    f.idle()?;
    f.commit().await?;
    assert!(f.executor()?.state.replays.is_empty());
    Ok(())
}

#[tokio::test]
async fn unfinished_unknown_deadline_or_missing_sequence_ownership_keeps_the_result() -> TestResult
{
    for fault in 0..4 {
        let mut f = Fixture::new(true).await?;
        let origin_key = f.origin_key();
        let executor = f.coordinator.companion_exec.as_mut().ok_or("executor")?;
        match fault {
            0 => {
                executor
                    .state
                    .replays
                    .get_mut(&f.key)
                    .ok_or("row")?
                    .result_object_id = None
            }
            1 => {
                executor
                    .state
                    .replays
                    .get_mut(&f.key)
                    .ok_or("row")?
                    .retain_until = 0
            }
            2 => {
                executor.state.origin_sequences.remove(&origin_key);
            }
            3 => {
                executor
                    .state
                    .origin_sequences
                    .get_mut(&origin_key)
                    .ok_or("owner")?
                    .next_sequence = 0
            }
            _ => return Err("fault".into()),
        }
        f.idle()?;
        assert!(f.coordinator.pending.is_none());
        assert_eq!(f.executor()?.state.replays.len(), 1);
        assert_eq!(f.executor()?.state.results.len(), 1);
        assert!(f.executor()?.state.objects.contains_key(&f.result_id));
    }
    Ok(())
}

#[tokio::test]
async fn changed_result_or_origin_floor_cannot_publish_a_committed_page() -> TestResult {
    for fault in 0..4 {
        let mut f = Fixture::new(true).await?;
        f.idle()?;
        let origin_key = f.origin_key();
        let executor = f.coordinator.companion_exec.as_mut().ok_or("executor")?;
        match fault {
            0 => {
                executor
                    .state
                    .origin_sequences
                    .get_mut(&origin_key)
                    .ok_or("owner")?
                    .next_sequence = 2
            }
            1 => {
                executor
                    .state
                    .replays
                    .get_mut(&f.key)
                    .ok_or("row")?
                    .retain_until += 1
            }
            2 => executor
                .state
                .results
                .get_mut(&f.request_object_id)
                .ok_or("result")?
                .result
                .push(0),
            3 => executor
                .state
                .results
                .get_mut(&f.request_object_id)
                .ok_or("result")?
                .responses
                .push([1; 32]),
            _ => return Err("fault".into()),
        }
        f.core.commit_staged_batch().await?;
        f.coordinator.batch_applied(f.core.context_mut()?);
        assert!(!f.coordinator.loaded());
        assert_eq!(f.coordinator.counters().violations, 1);
        assert_eq!(f.executor()?.state.replays.len(), 1);
        f.restart().await?;
        assert!(f.executor()?.state.replays.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn metadata_identity_and_size_refusals_cannot_stage_deletion() -> TestResult {
    for fault in 0..3 {
        let mut f = Fixture::new(true).await?;
        let executor = f.coordinator.companion_exec.as_mut().ok_or("executor")?;
        match fault {
            0 => {
                executor
                    .state
                    .replays
                    .get_mut(&f.key)
                    .ok_or("row")?
                    .request_id = [1; 16]
            }
            1 => executor
                .state
                .results
                .get_mut(&f.request_object_id)
                .ok_or("result")?
                .result
                .resize(8193, 0),
            2 => executor
                .state
                .replays
                .get_mut(&f.key)
                .ok_or("row")?
                .response_object_ids
                .resize(33, [1; 32]),
            _ => return Err("fault".into()),
        }
        f.idle()?;
        assert!(f.coordinator.pending.is_none());
        assert_eq!(f.executor()?.state.replays.len(), 1);
        assert_eq!(f.coordinator.counters().violations, 1);
    }
    Ok(())
}

#[tokio::test]
async fn unknown_clock_quiescing_or_memory_refusal_keeps_replay_ownership() -> TestResult {
    for fault in 0..5 {
        let mut f = Fixture::new(true).await?;
        let budget = f.core.context_mut()?.backing_budget_for_test();
        let held = match fault {
            0 => {
                f.core.context_mut()?.set_untrusted_wall_for_test(None);
                None
            }
            1 => {
                f.core
                    .context_mut()?
                    .set_untrusted_wall_for_test(Some(87398));
                None
            }
            2 => {
                f.core.context_mut()?.quiesce_for_test();
                None
            }
            3 | 4 => {
                let headroom = if fault == 3 { 8192 } else { 350_000 };
                Some(
                    f.core
                        .context_mut()?
                        .reserve_output_backing(usize::try_from(budget.available())? - headroom)?,
                )
            }
            _ => return Err("fault".into()),
        };
        let charge = budget.charged();
        f.idle()?;
        assert!(f.coordinator.pending.is_none());
        assert_eq!(f.executor()?.state.replays.len(), 1);
        assert_eq!(budget.charged(), charge);
        if fault >= 3 {
            drop(held);
            f.retry()?;
            f.commit().await?;
            assert!(f.executor()?.state.replays.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn timer_exhaustion_uses_the_existing_idle_sweep() -> TestResult {
    let mut f = Fixture::new(true).await?;
    *f.core.context_mut()?.timers_mut() = TimerHeap::with_ceiling(0);
    f.coordinator.continue_restore(f.core.context_mut()?);
    f.commit().await?;
    assert!(f.executor()?.state.replays.is_empty());
    Ok(())
}
