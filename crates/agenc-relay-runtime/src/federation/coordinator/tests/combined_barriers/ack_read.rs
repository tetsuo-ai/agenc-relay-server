//! Live ACK expiry scans preserve the open barrier and publish only after a receipt.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::sync::Action;
use agenc_relay_e2ee::federation::frames::DeliveryPosition;

fn position(fixture: &Fixture, sequence: u64) -> TestResult<DeliveryPosition> {
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    let row = stream
        .rows
        .iter()
        .find(|row| row.sequence == sequence)
        .ok_or("row")?;
    Ok(DeliveryPosition {
        server_id: *COORDINATOR.as_bytes(),
        delivery_generation: stream.generation,
        delivery_sequence: sequence,
        event_id: row.event_id,
    })
}

fn ack(fixture: &mut Fixture, sequence: u64, now: u64) -> TestResult {
    let position = position(fixture, sequence)?;
    let actions = events::on_ack(
        fixture
            .coordinator
            .companion_exec
            .as_mut()
            .ok_or("executor")?,
        LinkId::new(1),
        PEER,
        position,
        Some(now),
    )?;
    assert!(matches!(actions.first(), Some(Action::ReadAcknowledgement(_))) == (sequence == 3));
    for action in actions {
        companion::apply(
            &mut fixture.coordinator,
            fixture.core.context_mut()?,
            LinkId::new(1),
            PEER,
            action,
        )
        .map_err(|e| format!("apply ACK: {e:?}"))?;
    }
    Ok(())
}

async fn pending() -> TestResult<(Fixture, crate::federation::link::LinkQueue)> {
    let mut fixture = Box::pin(Fixture::seed(true)).await?;
    let (handle, queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        incarnation: INCARNATION,
    });
    companion::admitted(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        LinkId::new(1),
        PEER,
        CompanionFrame::Resume {
            coordinator_server_id: *COORDINATOR.as_bytes(),
            server_incarnation: *INCARNATION.as_bytes(),
            delivery_generation: 0,
            last: None,
        },
    )
    .map_err(|e| format!("resume: {e:?}"))?;
    for sequence in 0..2 {
        ack(&mut fixture, sequence, 100)?;
        fixture.core.commit_staged_batch().await?;
        fixture
            .coordinator
            .batch_applied(fixture.core.context_mut()?);
    }
    // Evict one acknowledged body from the cache; the sealed row and complete inventory remain.
    let stream = fixture
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("executor")?
        .state
        .streams
        .get_mut(&PEER)
        .ok_or("stream")?;
    assert_eq!(stream.rows.pop_front().ok_or("old head")?.sequence, 0);
    ack(&mut fixture, 3, 86_500)?;
    assert!(fixture.coordinator.companion_ack_read.is_some());
    assert!(!fixture.coordinator.reload_ready());
    assert!(fixture.coordinator.pending.is_none());
    Ok((fixture, queue))
}

async fn finish_reads(fixture: &mut Fixture) -> TestResult<usize> {
    let mut count = 0;
    while fixture.coordinator.companion_ack_read.is_some() {
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.core.next_storage_read(),
        )
        .await??;
        assert!(fixture.coordinator.owns_storage_read(message.read_id));
        let result = message
            .result
            .as_ref()
            .map_err(|e| format!("read: {e:?}"))?;
        assert!(
            result
                .records
                .iter()
                .all(|row| row.table == TableId::E2eeState)
        );
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
        count += 1;
        assert!(count <= 8);
    }
    Ok(count)
}

#[tokio::test]
async fn cold_ack_prefix_commits_expiry_with_the_barrier_and_recovers_it() -> TestResult {
    let (mut fixture, _queue) = Box::pin(pending()).await?;
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
    // Traffic remains queued without spinning the backlog drain while a prefix read is active.
    fixture.coordinator.inbound(
        fixture.core.context_mut()?,
        FederationInbound {
            link: LinkId::new(1),
            peer: PEER,
            event: LinkEvent::Frame(FederationFrame::Ack {
                coordinator_server_id: COORDINATOR,
                delivery_sequence: fixture.gate.base().last(),
                event_id: agenc_relay_types::EventId::from_bytes(
                    fixture.gate.base().final_event_id(),
                ),
            }),
            charge: None,
        },
    );
    assert_eq!(fixture.coordinator.backlog.len(), 1);
    fixture
        .coordinator
        .drain_backlog(fixture.core.context_mut()?);
    assert_eq!(fixture.coordinator.backlog.len(), 1);
    assert_eq!(finish_reads(&mut fixture).await?, 3);
    assert!(fixture.coordinator.pending.is_some());
    assert!(!fixture.coordinator.reload_ready());
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
            .acked,
        before
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
            .acked,
        before
    );
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert!(fixture.coordinator.backlog.is_empty());
    assert_eq!(fixture.coordinator.counters.violations, 0);
    assert!(
        fixture
            .stored_gate()
            .await?
            .ok_or("gate")?
            .companion_acked()
    );
    assert!(
        fixture.coordinator.pending.is_some(),
        "the queued base ACK owns the next batch"
    );
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert!(fixture.stored_gate().await?.is_none());
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
    assert_eq!(stream.rows.len(), 2);
    assert_eq!(stream.rows.front().ok_or("first")?.sequence, 2);
    assert_eq!(
        stream.acked,
        Some((3, fixture.gate.companion().final_event_id()))
    );
    assert!(stream.rows.iter().all(|row| row.acked()));
    Ok(())
}

#[tokio::test]
async fn cancelled_ack_read_keeps_ownership_and_never_fails_the_replacement_link() -> TestResult {
    let (mut fixture, _queue) = Box::pin(pending()).await?;
    let message = fixture.core.next_storage_read().await?;
    let id = message.read_id;
    fixture.coordinator.inbound(
        fixture.core.context_mut()?,
        FederationInbound {
            link: LinkId::new(1),
            peer: PEER,
            event: LinkEvent::Closed(LinkCloseReason::PeerClosed),
            charge: None,
        },
    );
    assert!(fixture.coordinator.owns_storage_read(id));
    assert!(!fixture.coordinator.reload_ready());
    let (handle, _replacement_queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(2),
        handle,
        incarnation: INCARNATION,
    });
    fixture.coordinator.storage_read_completed(
        fixture.core.context_mut()?,
        crate::bridge::StorageReadCompletionMessage {
            read_id: StorageReadId::new(id.get().checked_add(1).ok_or("read ID")?),
            result: Err(agenc_relay_storage::StorageError::Unavailable),
        },
    );
    assert!(fixture.coordinator.owns_storage_read(id));
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(!fixture.coordinator.owns_storage_read(id));
    assert!(fixture.coordinator.link_is_live(LinkId::new(2), PEER));
    assert_eq!(fixture.coordinator.counters.violations, 0);
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert!(
        !fixture
            .stored_gate()
            .await?
            .ok_or("gate")?
            .companion_acked()
    );
    Ok(())
}

#[tokio::test]
async fn refused_cold_ack_transaction_leaves_expired_rows_and_cursor_recoverable() -> TestResult {
    let (mut fixture, _queue) = Box::pin(pending()).await?;
    finish_reads(&mut fixture).await?;
    assert!(fixture.coordinator.pending.is_some());
    // Reject the batch before submission; neither journal nor barrier coverage can publish.
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    fixture
        .coordinator
        .batch_rejected(fixture.core.context_mut()?);
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
    assert_eq!(stream.rows.len(), 4);
    assert_eq!(stream.rows.front().ok_or("first")?.sequence, 0);
    assert_eq!(stream.acked.map(|(sequence, _)| sequence), Some(1));
    assert_eq!(stream.rows.iter().filter(|row| !row.acked()).count(), 2);
    assert!(
        !fixture
            .stored_gate()
            .await?
            .ok_or("gate")?
            .companion_acked()
    );
    Ok(())
}

#[tokio::test]
async fn an_unrelated_commit_between_ack_pages_refuses_mixed_inventory_without_advancing_coverage()
-> TestResult {
    let (mut fixture, _queue) = Box::pin(pending()).await?;
    let first = fixture.core.next_storage_read().await?;
    let pinned = first
        .result
        .as_ref()
        .map_err(|e| format!("first read: {e:?}"))?
        .storage_commit_sequence;
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    let existing = &stream.rows.back().ok_or("existing event")?.event;
    let unchanged_body =
        CompanionCoordinator::object_write(existing).map_err(|e| format!("object: {e:?}"))?;
    Box::pin(fixture.commit(vec![unchanged_body])).await?;
    assert!(fixture.core.context_mut()?.head().storage_commit_sequence > pinned);
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, first);
    assert!(fixture.coordinator.companion_ack_read.is_some());
    assert_eq!(finish_reads(&mut fixture).await?, 1);
    assert_eq!(fixture.coordinator.counters.violations, 1);
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
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
    assert_eq!(stream.rows.len(), 4);
    assert_eq!(stream.acked.map(|(sequence, _)| sequence), Some(1));
    assert_eq!(stream.rows.iter().filter(|row| !row.acked()).count(), 2);
    Ok(())
}

#[tokio::test]
async fn a_replay_cutoff_inside_an_open_barrier_refuses_before_installing_a_stream() -> TestResult {
    use agenc_relay_storage::e2ee_records::delivery_recovery::outbox::replay::{
        ReplayLedgerRow, ReplayOwner, ReplayOwnerFields,
    };
    let mut fixture = Box::pin(Fixture::new()).await?;
    fixture.stage_companion_ack()?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    let endpoint = fixture.gate.companion();
    let replay = ReplayLedgerRow::Owner(ReplayOwner::new(ReplayOwnerFields {
        scope: *fixture.gate.scope(),
        generation: endpoint.generation(),
        through: endpoint.last(),
        event_id: endpoint.final_event_id(),
        first_retained: endpoint.last().checked_add(1).ok_or("floor")?,
        retained_rows: 0,
        retained_bytes: 0,
        trusted_unix_seconds: None,
    })?);
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        agenc_relay_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND,
        1,
        0,
        None,
        Vec::new(),
        replay.encode()?,
    )?;
    Box::pin(fixture.commit(vec![AccountServiceDurableWrite::put(
        TableId::E2eeState,
        replay.key()?,
        value.encode()?,
    )?]))
    .await?;
    fixture.restart().await?;
    assert!(!fixture.coordinator.loaded());
    assert!(
        fixture
            .coordinator
            .peers
            .get(&PEER)
            .ok_or("peer")?
            .quarantined
    );
    assert!(
        fixture
            .coordinator
            .companion_exec
            .as_ref()
            .ok_or("executor")?
            .state
            .streams
            .is_empty(),
        "a replay cutoff cannot install a stream whose open barrier proof was discarded"
    );
    Ok(())
}

/// Every stream fact the request captured is re-checked when its page lands.
#[tokio::test]
async fn an_ack_read_whose_stream_or_link_drifted_fails_its_link_without_staging() -> TestResult {
    for variant in 0..7 {
        let (mut fixture, _queue) = Box::pin(pending()).await?;
        let message = fixture.core.next_storage_read().await?;
        {
            let executor = fixture
                .coordinator
                .companion_exec
                .as_mut()
                .ok_or("executor")?;
            let stream = executor.state.streams.get_mut(&PEER).ok_or("stream")?;
            match variant {
                0 => stream.owner = None,
                1 => stream.next_sequence = stream.next_sequence.saturating_add(1),
                2 => stream.replay = None,
                3 => stream.barrier = Some((0, 0)),
                4 => stream.hold_after = Some(0),
                _ => {
                    let sync = executor.peers.get_mut(&PEER).ok_or("peer sync")?;
                    if variant == 5 {
                        sync.link = Some(LinkId::new(9));
                    } else {
                        sync.active = !sync.active;
                    }
                }
            }
        }
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
        assert!(
            fixture.coordinator.companion_ack_read.is_none(),
            "variant {variant}"
        );
        assert!(
            !fixture.coordinator.link_is_live(LinkId::new(1), PEER),
            "variant {variant}"
        );
        assert!(fixture.coordinator.pending.is_none(), "variant {variant}");
        assert_eq!(
            fixture.core.context_mut()?.pending_len(),
            0,
            "variant {variant}"
        );
    }
    Ok(())
}

/// A staged batch of the coordinator's own holds the completion back.
#[tokio::test]
async fn an_ack_read_completing_behind_a_staged_batch_fails_its_link() -> TestResult {
    let (mut fixture, _queue) = Box::pin(pending()).await?;
    let message = fixture.core.next_storage_read().await?;
    fixture.coordinator.pending = Some(PendingCommit::Cleanup { peer: PEER });
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(fixture.coordinator.companion_ack_read.is_none());
    assert!(!fixture.coordinator.link_is_live(LinkId::new(1), PEER));
    fixture.coordinator.pending = None;
    Ok(())
}

#[tokio::test]
async fn a_queued_base_request_waits_for_a_companion_read_in_flight() -> TestResult {
    let (mut fixture, _queue) = Box::pin(pending()).await?;
    let (inbox, _receiver) = tokio::sync::mpsc::channel(1);
    let mut edge = super::super::Edge::new(inbox, 50);
    let origin = super::super::Origin::new(70);
    super::super::enqueue(
        &mut fixture.coordinator,
        &mut edge,
        &origin,
        LinkId::new(1),
        71,
    )?;
    // The read's completion must find no batch of this coordinator open, so
    // the queued request runs only after it.
    request::drain_queued(&mut fixture.coordinator, fixture.core.context_mut()?);
    assert!(fixture.coordinator.companion_ack_read.is_some());
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(
        fixture
            .coordinator
            .peers
            .get(&PEER)
            .ok_or("peer")?
            .queued
            .len(),
        1
    );
    assert_eq!(finish_reads(&mut fixture).await?, 3);
    assert!(
        fixture.coordinator.pending.is_some(),
        "the read staged its acknowledgement"
    );
    assert_eq!(fixture.coordinator.counters.violations, 0);
    Ok(())
}
