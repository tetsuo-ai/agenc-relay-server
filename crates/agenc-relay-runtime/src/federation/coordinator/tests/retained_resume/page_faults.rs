#![forbid(unsafe_code)]

//! A validation page that is not exactly the retained prefix never advances coverage.

use super::*;
use crate::bridge::StorageReadCompletionMessage;

type Fault = fn(&mut StorageReadCompletionMessage) -> TestResult;

fn page(
    message: &mut StorageReadCompletionMessage,
) -> TestResult<&mut agenc_relay_storage::ReadResult> {
    message
        .result
        .as_mut()
        .map_err(|error| format!("validation read: {error:?}").into())
}

fn fatal_faults() -> [Fault; 4] {
    [
        |message| {
            page(message)?.records.clear();
            Ok(())
        },
        |message| {
            page(message)?.records.remove(0);
            Ok(())
        },
        |message| {
            let first = page(message)?.records.first_mut().ok_or("first row")?;
            first.table = TableId::FederationPeer;
            Ok(())
        },
        |message| {
            message.result = Err(agenc_relay_storage::StorageError::StaleState);
            Ok(())
        },
    ]
}

#[tokio::test]
async fn a_faulty_validation_page_retires_the_link_and_keeps_every_retained_row() -> TestResult {
    for fault in fatal_faults() {
        let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
        let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
        let mut completion = fixture.next_storage_read().await?;
        fault(&mut completion)?;
        coordinator.storage_read_completed(fixture.context_mut()?, completion);
        let state = coordinator.peers.get(&PEER).ok_or("peer")?;
        assert!(state.live.is_none());
        assert!(state.reconciliation.is_none());
        assert_eq!(handle.queued_bytes(), 0);
        assert_eq!(fixture.context_mut()?.pending_len(), 0);
        assert_unreconciled(&mut fixture, &coordinator)?;
    }
    Ok(())
}

#[tokio::test]
async fn a_resource_refused_validation_page_waits_for_its_retry_timer() -> TestResult {
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    use crate::state_core::timers::{TimedId, TimerKind};
    let (handle, mut queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    let mut completion = fixture.next_storage_read().await?;
    completion.result = Err(agenc_relay_storage::StorageError::QueueFull);
    coordinator.storage_read_completed(fixture.context_mut()?, completion);
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert!(state.live.is_some());
    assert!(state.reconciliation.is_some());
    assert_eq!(handle.queued_bytes(), 0);
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert_unreconciled(&mut fixture, &coordinator)?;
    let deadline = fixture.context_mut()?.now().checked_add(1_000)?;
    let timer = fixture
        .context_mut()?
        .timers_mut()
        .pop_due(deadline)
        .ok_or("resume retry timer")?;
    assert_eq!(
        (timer.kind, timer.id),
        (TimerKind::FederationResumeRetry, TimedId::Peer(PEER))
    );
    assert!(coordinator.timer_fired(fixture.context_mut()?, timer));
    validate_retained_prefix(&mut fixture, &mut coordinator).await?;
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert!(matches!(
        next_base_frame(&mut queue).await?,
        FederationFrame::ResumeOk {
            next_delivery_sequence: 2,
            ..
        }
    ));
    Ok(())
}
