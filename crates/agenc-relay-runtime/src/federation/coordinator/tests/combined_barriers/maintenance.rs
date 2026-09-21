//! Replay expiry must progress while the peer is offline and sends no further ACK.
#![forbid(unsafe_code)]

use super::*;

mod cases;

#[tokio::test]
async fn offline_replay_expires_from_a_timer_without_a_new_acknowledgement() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    fixture.core.context_mut()?.set_wall_for_test(100);
    fixture.stage_base_ack()?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    fixture.stage_companion_ack()?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert!(fixture.stored_gate().await?.is_none());
    fixture.core.context_mut()?.set_wall_for_test(86_500);
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    assert!(
        fixture
            .coordinator
            .peers
            .get(&PEER)
            .ok_or("peer")?
            .live
            .is_none()
    );
    let before = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?
        .acked;
    fixture
        .coordinator
        .continue_restore(fixture.core.context_mut()?);
    let first = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        fixture.core.next_storage_read(),
    )
    .await
    .map_err(|_| "idle expiry did not submit a bounded storage read")??;
    assert!(fixture.coordinator.owns_storage_read(first.read_id));
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, first);
    for _ in 0..8 {
        if fixture.coordinator.pending.is_some() {
            break;
        }
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.core.next_storage_read(),
        )
        .await??;
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
    }
    assert!(fixture.coordinator.pending.is_some());
    assert_eq!(
        fixture
            .coordinator
            .companion_exec
            .as_ref()
            .ok_or("executor")?
            .state
            .streams
            .get(&PEER)
            .ok_or("stream")?
            .rows
            .len(),
        2
    );
    fixture.core.commit_staged_batch().await?;
    assert_eq!(
        fixture
            .coordinator
            .companion_exec
            .as_ref()
            .ok_or("executor")?
            .state
            .streams
            .get(&PEER)
            .ok_or("stream")?
            .rows
            .len(),
        2
    );
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    assert_eq!(stream.acked, before);
    assert!(stream.rows.is_empty());
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    assert_eq!(stream.acked, before);
    assert!(stream.rows.is_empty());
    Ok(())
}

#[tokio::test]
async fn replay_maintenance_answers_only_its_own_global_timer() -> TestResult {
    use crate::federation::coordinator::replay_maintenance;
    use crate::state_core::timers::{TimedId, TimerKind};
    let mut fixture = Box::pin(Fixture::new()).await?;
    let context = fixture.core.context_mut()?;
    let deadline = context.now();
    // The coordinator's own maintenance timer may already be due on a slow
    // host; only the timers this test schedules are popped below.
    while context.timers_mut().pop_due(deadline).is_some() {}
    context
        .timers_mut()
        .schedule(deadline, TimerKind::Batch, TimedId::Global)?;
    let other_kind = context
        .timers_mut()
        .pop_due(deadline)
        .ok_or("the batch timer")?;
    assert!(!replay_maintenance::timer_fired(
        &mut fixture.coordinator,
        context,
        other_kind
    ));
    context.timers_mut().schedule(
        deadline,
        TimerKind::CompanionReplayMaintenance,
        TimedId::Peer(PEER),
    )?;
    let other_id = context
        .timers_mut()
        .pop_due(deadline)
        .ok_or("the peer timer")?;
    assert!(!replay_maintenance::timer_fired(
        &mut fixture.coordinator,
        context,
        other_id
    ));
    Ok(())
}

#[tokio::test]
async fn replay_maintenance_waits_behind_a_staged_batch() -> TestResult {
    use crate::federation::coordinator::replay_maintenance;
    use crate::state_core::timers::{TimedId, TimerKind};
    let mut fixture = Box::pin(Fixture::new()).await?;
    fixture.core.context_mut()?.set_wall_for_test(100);
    fixture.stage_base_ack()?;
    let context = fixture.core.context_mut()?;
    assert!(fixture.coordinator.pending.is_some());
    let now = context.now().get();
    replay_maintenance::advance(&mut fixture.coordinator, context);
    let horizon = agenc_relay_types::MonotonicTick::from_ticks(now.saturating_add(1_000_000_000));
    let mut retry = None;
    while let Some(entry) = context.timers_mut().pop_due(horizon) {
        if entry.kind == TimerKind::CompanionReplayMaintenance && entry.id == TimedId::Global {
            retry = Some(entry);
            break;
        }
    }
    let timer = retry.ok_or("the retry timer")?;
    assert!(
        timer.deadline.get() > now,
        "a retry is scheduled behind the batch"
    );
    assert!(replay_maintenance::timer_fired(
        &mut fixture.coordinator,
        context,
        timer
    ));
    Ok(())
}
