//! Timers, refusal, and cancellation preserve the durable retention boundary.
#![forbid(unsafe_code)]

use super::*;
use crate::state_core::timers::TimerKind;

mod cleanup;
mod faults;

async fn expired(close_gate: bool, known_ack_time: bool) -> TestResult<Fixture> {
    let mut fixture = Box::pin(Fixture::new()).await?;
    fixture.core.context_mut()?.set_wall_for_test(100);
    if !known_ack_time {
        fixture
            .core
            .context_mut()?
            .set_untrusted_wall_for_test(None);
    }
    fixture.stage_companion_ack()?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    if close_gate {
        fixture.stage_base_ack()?;
        fixture.core.commit_staged_batch().await?;
        fixture
            .coordinator
            .batch_applied(fixture.core.context_mut()?);
    }
    fixture.core.context_mut()?.set_wall_for_test(86_500);
    fixture.restart().await?;
    Ok(fixture)
}

fn stream(fixture: &Fixture) -> TestResult<&DeliveryStream> {
    Ok(fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?)
}

fn wake(fixture: &mut Fixture) -> TestResult {
    let context = fixture.core.context_mut()?;
    let now = context.now();
    for _ in 0..32 {
        let entry = context
            .timers_mut()
            .pop_due(now)
            .ok_or("maintenance timer was not armed")?;
        if entry.kind == TimerKind::CompanionReplayMaintenance {
            assert!(fixture.coordinator.timer_fired(context, entry));
            return Ok(());
        }
    }
    Err("maintenance timer was not found within the fixture's bounded timer set".into())
}

async fn reads(fixture: &mut Fixture) -> TestResult<usize> {
    let mut count = 0;
    while fixture.coordinator.replay_maintenance.busy() {
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.core.next_storage_read(),
        )
        .await??;
        assert!(fixture.coordinator.owns_storage_read(message.read_id));
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
        count += 1;
        assert!(count <= 8);
    }
    Ok(count)
}

#[tokio::test]
async fn startup_timer_expires_offline_history_and_a_crash_before_publication_recovers_the_floor()
-> TestResult {
    let mut fixture = Box::pin(expired(true, true)).await?;
    let before = stream(&fixture)?.acked;
    wake(&mut fixture)?;
    assert!(!fixture.coordinator.reload_ready());
    assert_eq!(reads(&mut fixture).await?, 3);
    assert!(fixture.coordinator.pending.is_some());
    assert_eq!(stream(&fixture)?.rows.len(), 2);
    fixture.core.commit_staged_batch().await?;
    assert_eq!(stream(&fixture)?.rows.len(), 2);
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    assert!(stream(&fixture)?.rows.is_empty());
    assert_eq!(stream(&fixture)?.acked, before);
    Ok(())
}

#[tokio::test]
async fn rejected_expiry_retains_history_and_its_timer_retries_without_an_ack() -> TestResult {
    let mut fixture = Box::pin(expired(true, true)).await?;
    let before = stream(&fixture)?.acked;
    wake(&mut fixture)?;
    reads(&mut fixture).await?;
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    fixture
        .coordinator
        .batch_rejected(fixture.core.context_mut()?);
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(stream(&fixture)?.rows.len(), 2);
    assert_eq!(stream(&fixture)?.acked, before);
    let now = fixture.core.context_mut()?.now().get();
    fixture
        .core
        .context_mut()?
        .set_monotonic_for_test(now.checked_add(1_000).ok_or("tick")?);
    wake(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 3);
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert!(stream(&fixture)?.rows.is_empty());
    assert_eq!(stream(&fixture)?.acked, before);
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    assert!(stream(&fixture)?.rows.is_empty());
    Ok(())
}

#[tokio::test]
async fn wrong_completion_cannot_release_a_read_and_a_changed_owner_cannot_publish() -> TestResult {
    let mut fixture = Box::pin(expired(true, true)).await?;
    wake(&mut fixture)?;
    let message = fixture.core.next_storage_read().await?;
    let id = message.read_id;
    fixture
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("executor")?
        .state
        .streams
        .get_mut(&PEER)
        .ok_or("stream")?
        .generation = 1;
    assert!(fixture.coordinator.owns_storage_read(id));
    fixture.coordinator.storage_read_completed(
        fixture.core.context_mut()?,
        crate::bridge::StorageReadCompletionMessage {
            read_id: StorageReadId::new(id.get().checked_add(1).ok_or("read ID")?),
            result: Err(agenc_relay_storage::StorageError::Unavailable),
        },
    );
    assert!(fixture.coordinator.owns_storage_read(id));
    assert!(!fixture.coordinator.reload_ready());
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(!fixture.coordinator.replay_maintenance.busy());
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    assert_eq!(stream(&fixture)?.rows.len(), 2);
    assert_eq!(stream(&fixture)?.generation, 0);
    Ok(())
}

#[tokio::test]
async fn unrelated_commit_between_expiry_pages_retries_without_quarantining_the_peer() -> TestResult
{
    let mut fixture = Box::pin(expired(true, true)).await?;
    wake(&mut fixture)?;
    let message = fixture.core.next_storage_read().await?;
    let write =
        CompanionCoordinator::object_write(&stream(&fixture)?.rows.front().ok_or("row")?.event)
            .map_err(|e| format!("object: {e:?}"))?;
    Box::pin(fixture.commit(vec![write])).await?;
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert_eq!(reads(&mut fixture).await?, 1);
    assert!(fixture.coordinator.pending.is_none());
    assert!(fixture.coordinator.loaded());
    assert!(
        !fixture
            .coordinator
            .peers
            .get(&PEER)
            .ok_or("peer")?
            .quarantined
    );
    assert_eq!(stream(&fixture)?.rows.len(), 2);
    let now = fixture.core.context_mut()?.now().get();
    fixture
        .core
        .context_mut()?
        .set_monotonic_for_test(now.checked_add(1_000).ok_or("tick")?);
    wake(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 3);
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert!(stream(&fixture)?.rows.is_empty());
    Ok(())
}

#[tokio::test]
async fn unknown_or_regressed_clock_before_or_during_a_read_preserves_history() -> TestResult {
    for during_read in [false, true] {
        for wall in [None, Some(99)] {
            let mut fixture = Box::pin(expired(true, true)).await?;
            if during_read {
                wake(&mut fixture)?;
            }
            fixture
                .core
                .context_mut()?
                .set_untrusted_wall_for_test(wall);
            if during_read {
                assert_eq!(reads(&mut fixture).await?, 1);
            } else {
                wake(&mut fixture)?;
            }
            assert!(!fixture.coordinator.replay_maintenance.busy());
            assert!(fixture.coordinator.pending.is_none());
            assert_eq!(stream(&fixture)?.rows.len(), 2);
            assert!(fixture.coordinator.loaded());
            fixture.restart().await?;
            assert!(fixture.coordinator.loaded());
            assert_eq!(stream(&fixture)?.rows.len(), 2);
        }
    }
    Ok(())
}

#[tokio::test]
async fn open_barrier_or_unknown_original_ack_time_prevents_idle_age_expiry() -> TestResult {
    for (close_gate, known_ack_time) in [(false, true), (true, false)] {
        let mut fixture = Box::pin(expired(close_gate, known_ack_time)).await?;
        wake(&mut fixture)?;
        assert!(!fixture.coordinator.replay_maintenance.busy());
        assert!(fixture.coordinator.pending.is_none());
        assert_eq!(stream(&fixture)?.rows.len(), 2);
        assert!(stream(&fixture)?.rows.iter().all(|row| row.acked()));
        assert_eq!(fixture.stored_gate().await?.is_none(), close_gate);
        fixture.restart().await?;
        assert!(fixture.coordinator.loaded());
        assert_eq!(stream(&fixture)?.rows.len(), 2);
    }
    Ok(())
}
