//! Failed or cancelled reads retain exact ownership and never publish a partial answer.
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn malformed_raw_completions_fail_before_any_response_is_queued() -> TestResult {
    for fault in 0..6 {
        let mut fixture = Box::pin(Fixture::new(None)).await?;
        fixture.submit()?;
        let mut message = fixture.next_read().await?;
        let result = message
            .result
            .as_mut()
            .map_err(|e| format!("read: {e:?}"))?;
        match fault {
            0 => result.truncated = true,
            1 => result.records.clear(),
            2 => {
                result.storage_commit_sequence = result
                    .storage_commit_sequence
                    .checked_add(1)
                    .ok_or("commit")?
            }
            3 => result.records.first_mut().ok_or("row")?.table = TableId::E2eeState,
            4 => {
                result.records.first_mut().ok_or("row")?.key =
                    agenc_relay_storage::e2ee_records::object_key(&[99; 32])?
            }
            5 => {
                *result
                    .records
                    .first_mut()
                    .ok_or("row")?
                    .sealed_record
                    .last_mut()
                    .ok_or("sealed bytes")? ^= 1
            }
            _ => return Err("fault".into()),
        }
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
        assert!(fixture.coordinator.companion_response_read.is_none());
        assert_eq!(fixture.coordinator.counters.violations, 1);
        assert_eq!(fixture.coordinator.counters.requests_replayed, 0);
        assert_eq!(fixture.handle.queued_bytes(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn changed_metadata_or_base_epoch_cancels_private_response_bodies() -> TestResult {
    for change in 0..4 {
        let mut fixture = Box::pin(Fixture::new(None)).await?;
        fixture.submit()?;
        let message = fixture.next_read().await?;
        match change {
            0 => {
                fixture
                    .coordinator
                    .peers
                    .get_mut(&PEER)
                    .ok_or("peer")?
                    .client_resync_epoch += 1
            }
            1 => {
                fixture
                    .coordinator
                    .companion_exec
                    .as_mut()
                    .ok_or("executor")?
                    .state
                    .replays
                    .get_mut(&fixture.key)
                    .ok_or("row")?
                    .retain_until += 1
            }
            2 => fixture
                .coordinator
                .companion_exec
                .as_mut()
                .ok_or("executor")?
                .state
                .results
                .get_mut(&fixture.decoded.request_object_id)
                .ok_or("result")?
                .responses
                .reverse(),
            _ => {
                fixture
                    .coordinator
                    .peers
                    .get_mut(&PEER)
                    .ok_or("peer")?
                    .phase = PeerPhase::Suspended;
                companion::admitted(
                    &mut fixture.coordinator,
                    fixture.core.context_mut()?,
                    LinkId::new(1),
                    PEER,
                    CompanionFrame::OriginReset {
                        coordinator_server_id: *COORDINATOR.as_bytes(),
                        server_incarnation: *INCARNATION.as_bytes(),
                    },
                )
                .map_err(|e| format!("origin reset: {e:?}"))?;
            }
        }
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
        assert!(fixture.coordinator.companion_response_read.is_none());
        assert_eq!(fixture.coordinator.counters.violations, 1);
        assert_eq!(fixture.handle.queued_bytes(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn queued_complete_requests_wait_for_the_current_read_then_start_their_own_reads()
-> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    fixture.submit()?;
    queue_complete(&mut fixture)?;
    for page in 1..=6 {
        assert!(!fixture.coordinator.reload_ready());
        assert_eq!(fixture.handle.queued_bytes(), 0);
        let message = fixture.next_read().await?;
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
        if page % 3 == 0 {
            fixture.expect_complete_output().await?;
        }
    }
    assert_eq!(fixture.coordinator.counters.requests_replayed, 2);
    assert_eq!(fixture.coordinator.counters.violations, 0);
    assert!(fixture.coordinator.reload_ready());
    Ok(())
}

fn queue_complete(fixture: &mut Fixture) -> TestResult {
    let request = &fixture.decoded.request;
    let complete = crate::e2ee::coordinator::CompleteRequest {
        correlation: Correlation {
            peer_server_id: *PEER.as_bytes(),
            server_incarnation: request.server_incarnation,
            origin_id: request.origin_id,
            origin_generation: request.origin_generation,
            operation_sequence: request.operation_sequence,
            request_id: request.request_id,
        },
        request: fixture.request_bytes.clone(),
        payload: None,
    };
    companion::apply(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        LinkId::new(1),
        PEER,
        crate::e2ee::coordinator::sync::Action::Execute(complete),
    )
    .map_err(|e| format!("queue: {e:?}"))?;
    Ok(())
}

#[tokio::test]
async fn quiescing_keeps_read_ownership_until_completion_and_does_not_run_queued_work() -> TestResult
{
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let budget = fixture.core.context_mut()?.backing_budget_for_test();
    let before = budget.charged();
    fixture.submit()?;
    queue_complete(&mut fixture)?;
    let message = fixture.next_read().await?;
    let charged = budget.charged();
    assert!(charged > before + u64::try_from(agenc_relay_storage::MAX_SEALED_RECORD_BYTES)?);
    fixture.core.context_mut()?.quiesce_for_test();
    assert_eq!(budget.charged(), charged);
    assert!(fixture.coordinator.owns_storage_read(message.read_id));
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(fixture.coordinator.companion_response_read.is_none());
    assert_eq!(fixture.coordinator.counters.violations, 0);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert!(budget.charged() < charged);
    assert_eq!(fixture.coordinator.counters.requests_replayed, 0);
    Ok(())
}

#[tokio::test]
async fn budget_refusal_before_submission_releases_all_private_reservations() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let budget = fixture.core.context_mut()?.backing_budget_for_test();
    let held = fixture
        .core
        .context_mut()?
        .reserve_output_backing(480 * 1024 * 1024)?;
    let before = budget.charged();
    assert!(fixture.submit().is_err());
    assert!(fixture.coordinator.companion_response_read.is_none());
    assert_eq!(budget.charged(), before);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            fixture.core.next_storage_read()
        )
        .await
        .is_err()
    );
    drop(held);
    assert!(fixture.executor()?.state.replays.contains_key(&fixture.key));
    Ok(())
}

#[tokio::test]
async fn a_stalled_writer_keeps_the_complete_response_backing_until_queue_drop() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let budget = fixture.core.context_mut()?.backing_budget_for_test();
    let before = budget.charged();
    fixture.submit()?;
    fixture.finish_reads().await?;
    assert!(fixture.handle.queued_bytes() > 0);
    assert!(budget.charged() > before);
    drop(fixture.queue);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert_eq!(budget.charged(), before);
    Ok(())
}

#[tokio::test]
async fn wrong_read_id_and_replacement_link_cannot_publish_or_fail_the_new_link() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    fixture.submit()?;
    let message = fixture.next_read().await?;
    let id = message.read_id;
    fixture.coordinator.storage_read_completed(
        fixture.core.context_mut()?,
        StorageReadCompletionMessage {
            read_id: StorageReadId::new(id.get().checked_add(1).ok_or("read ID")?),
            result: Err(agenc_relay_storage::StorageError::Unavailable),
        },
    );
    assert!(fixture.coordinator.owns_storage_read(id));
    assert!(!fixture.coordinator.reload_ready());
    let (replacement, _queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(2),
        handle: replacement.clone(),
        incarnation: INCARNATION,
    });
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(fixture.coordinator.reload_ready());
    assert!(fixture.coordinator.link_is_live(LinkId::new(2), PEER));
    assert_eq!(fixture.coordinator.counters.violations, 0);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert_eq!(replacement.queued_bytes(), 0);
    Ok(())
}

#[tokio::test]
async fn unrelated_storage_commit_between_response_pages_refuses_the_entire_reply() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    fixture.submit()?;
    let message = fixture.next_read().await?;
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    let message = fixture.next_read().await?;
    let write = CompanionCoordinator::object_write(fixture.responses.first().ok_or("response")?)
        .map_err(|e| format!("write: {e:?}"))?;
    fixture::commit(&mut fixture.core, vec![write]).await?;
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(fixture.coordinator.companion_response_read.is_none());
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert_eq!(fixture.coordinator.counters.requests_replayed, 0);
    assert_eq!(fixture.coordinator.counters.violations, 1);
    assert!(fixture.executor()?.state.replays.contains_key(&fixture.key));
    Ok(())
}
