#![forbid(unsafe_code)]

//! Exact retained cursors reconcile durable coverage before replay.

use super::*;
use agenc_ircd_federation_wire::DeliveryCursor;
use agenc_ircd_storage::federation_records::{OUTBOX_EVENT_KIND, OutboxEventRecord, outbox_key};
use agenc_ircd_types::EventId;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);
const FIRST: EventId = EventId::from_bytes([61; 16]);
const SECOND: EventId = EventId::from_bytes([62; 16]);
const SUCCESSOR: EventId = EventId::from_bytes([63; 16]);

fn retained_event(sequence: u64, event_id: EventId) -> TestResult<InitialStorageRecord> {
    let event = ProjectedEvent::NetworkNotice {
        code: "REPLAY".to_owned(),
        text: "committed while disconnected".to_owned(),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: PEER,
        projection_generation: 0,
        coordinator_state_generation: 1,
        delivery_sequence: sequence,
        event_id,
        event_kind: event.kind(),
        correlation: None,
        cross_profile: None,
    };
    let arm = crate::federation::codec::events::event_arm_object(&event)
        .map_err(|error| format!("{error:?}"))?;
    let bytes = header.build(&arm)?.encode_canonical()?.as_slice().to_vec();
    let body = OutboxEventRecord {
        event_id: *event_id.as_bytes(),
        event_object_id: *federation_object_id(&bytes).as_bytes(),
        event_object: bytes,
        coordinator_state_generation: 1,
        acknowledged: false,
        completion_replay_key: None,
    }
    .encode()?;
    let value = PersistentRecordValue::new(
        TableId::EdgeOutbox,
        OUTBOX_EVENT_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?
    .encode()?;
    Ok(InitialStorageRecord::new(
        TableId::EdgeOutbox,
        outbox_key(PEER, 0, sequence)?,
        1,
        value,
    )?)
}

async fn retained_window_fixture(
    records: Vec<InitialStorageRecord>,
) -> TestResult<(StateCoreFixture, FederationCoordinator)> {
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    fixture.context_mut()?.install_federation_projector(
        crate::state_core::projector::FederationProjector::new(NETWORK, COORDINATOR),
    );
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.config.outbox_objects_per_edge = 512;
    coordinator.startup(fixture.context_mut()?);
    for _ in 0..64 {
        if coordinator.loaded() {
            break;
        }
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.next_storage_read(),
        )
        .await??;
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    assert!(coordinator.loaded());
    Ok((fixture, coordinator))
}

async fn rejected_ack_fixture() -> TestResult<(StateCoreFixture, FederationCoordinator)> {
    let records = vec![
        restored_peer_record(PEER, INCARNATION, PeerPhase::Ready)?,
        retained_event(0, FIRST)?,
        retained_event(1, SECOND)?,
        retained_event(2, SUCCESSOR)?,
    ];
    let (mut fixture, mut coordinator) = retained_window_fixture(records).await?;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(
        fixture.context_mut()?,
        established(1, PEER, INCARNATION, handle),
    );
    coordinator
        .acknowledge(fixture.context_mut()?, PEER, 0, FIRST)
        .map_err(|error| format!("initial ACK: {error:?}"))?;
    assert_unreconciled(&mut fixture, &coordinator)?;
    let head = fixture.context_mut()?.head().storage_commit_sequence;
    fixture
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_ircd_storage::StorageError::QueueFull)?;
    coordinator.batch_rejected(fixture.context_mut()?);
    assert_eq!(fixture.context_mut()?.head().storage_commit_sequence, head);
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert_unreconciled(&mut fixture, &coordinator)?;
    assert!(coordinator.peers.get(&PEER).ok_or("peer")?.live.is_none());
    Ok((fixture, coordinator))
}

fn assert_unreconciled(
    fixture: &mut StateCoreFixture,
    coordinator: &FederationCoordinator,
) -> TestResult {
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert_eq!(state.outbox.cursor, None);
    assert_eq!(state.outbox.unacked.len(), 3);
    for sequence in 0..3 {
        assert!(fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, sequence)?)?);
    }
    Ok(())
}

fn reconnect_with_cursor(
    fixture: &mut StateCoreFixture,
    coordinator: &mut FederationCoordinator,
    sequence: u64,
    event_id: EventId,
) -> TestResult<(LinkHandle, LinkQueue)> {
    let (handle, queue) = link_queue(1 << 20);
    coordinator.inbound(
        fixture.context_mut()?,
        established(2, PEER, INCARNATION, handle.clone()),
    );
    assert_eq!(
        handle.queued_bytes(),
        0,
        "the base-only fixture starts silent"
    );
    coordinator.inbound(
        fixture.context_mut()?,
        FederationInbound {
            link: LinkId::new(2),
            peer: PEER,
            event: LinkEvent::Frame(FederationFrame::Resume {
                coordinator_server_id: COORDINATOR,
                projection_generation: 0,
                cursor: DeliveryCursor::At {
                    delivery_sequence: sequence,
                    event_id,
                },
            }),
            charge: None,
        },
    );
    Ok((handle, queue))
}

async fn next_base_frame(queue: &mut LinkQueue) -> TestResult<FederationFrame> {
    let line = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv())
        .await?
        .ok_or("link closed before its response")?;
    parse_frame(line.as_str().trim_end_matches("\r\n"), COORDINATOR_NAME)
        .map_err(|error| format!("base frame: {error:?}").into())
}

async fn validate_retained_prefix(
    fixture: &mut StateCoreFixture,
    coordinator: &mut FederationCoordinator,
) -> TestResult {
    for _ in 0..64 {
        if fixture.context_mut()?.pending_len() != 0 {
            return Ok(());
        }
        let completion = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.next_storage_read(),
        )
        .await??;
        coordinator.storage_read_completed(fixture.context_mut()?, completion);
    }
    Err("retained prefix did not reach a bounded commit".into())
}

async fn assert_retained_resume(sequence: u64, event_id: EventId) -> TestResult {
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    let (handle, mut queue) =
        reconnect_with_cursor(&mut fixture, &mut coordinator, sequence, event_id)?;
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert_eq!(
        state.projection_generation, 0,
        "retained cursor requires no new generation"
    );
    assert!(
        state.snapshot.is_none(),
        "an exact retained event must avoid full snapshot"
    );
    assert!(!state.active && state.resend.is_none());
    assert_eq!(
        handle.queued_bytes(),
        0,
        "no ResumeOk before durable reconciliation"
    );
    validate_retained_prefix(&mut fixture, &mut coordinator).await?;
    assert_eq!(fixture.context_mut()?.pending_len(), 1);
    assert_unreconciled(&mut fixture, &coordinator)?;
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    let reply = next_base_frame(&mut queue).await?;
    assert!(matches!(reply, FederationFrame::ResumeOk {
        edge_server_id: PEER,
        projection_generation: 0,
        next_delivery_sequence,
    } if next_delivery_sequence == sequence + 1));
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert_eq!(state.outbox.cursor, Some((sequence, event_id)));
    assert!(!state.active, "replay must complete before live delivery");
    assert!(state.snapshot.is_none());
    for covered in 0..=sequence {
        assert!(!fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, covered)?)?);
    }
    assert!(fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, sequence + 1)?)?);
    let completion = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.next_storage_read(),
    )
    .await??;
    assert!(snapshot::owns_read(&coordinator, completion.read_id));
    coordinator.storage_read_completed(fixture.context_mut()?, completion);
    let next = next_base_frame(&mut queue).await?;
    let expected_id = if sequence == 0 { SECOND } else { SUCCESSOR };
    assert!(matches!(next, FederationFrame::Event { descriptor, .. }
        if descriptor.target_server_id == PEER
            && descriptor.delivery_sequence == sequence + 1
            && descriptor.event_id == expected_id));
    Ok(())
}

#[tokio::test]
async fn a_retained_cursor_reconciles_rejected_ack_before_resume() -> TestResult {
    Box::pin(assert_retained_resume(0, FIRST)).await
}

#[tokio::test]
async fn a_retained_newer_cursor_covers_the_contiguous_unacked_prefix() -> TestResult {
    Box::pin(assert_retained_resume(1, SECOND)).await
}

#[tokio::test]
async fn a_refused_resume_reconciliation_keeps_its_cursor_and_rows() -> TestResult {
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    assert!(
        coordinator
            .peers
            .get(&PEER)
            .ok_or("peer")?
            .snapshot
            .is_none()
    );
    assert_eq!(handle.queued_bytes(), 0);
    validate_retained_prefix(&mut fixture, &mut coordinator).await?;
    assert_eq!(fixture.context_mut()?.pending_len(), 1);
    fixture
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_ircd_storage::StorageError::QueueFull)?;
    coordinator.batch_rejected(fixture.context_mut()?);
    assert_unreconciled(&mut fixture, &coordinator)?;
    assert_eq!(
        handle.queued_bytes(),
        0,
        "refusal must never publish ResumeOk"
    );
    Ok(())
}

#[tokio::test]
async fn a_second_resume_cannot_replace_validation_ownership() -> TestResult {
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    let completion = fixture.next_storage_read().await?;
    let read_id = completion.read_id;
    assert!(coordinator.owns_storage_read(read_id));
    let result = snapshot::resume(
        &mut coordinator,
        fixture.context_mut()?,
        LinkId::new(2),
        PEER,
        0,
        DeliveryCursor::At {
            delivery_sequence: 0,
            event_id: FIRST,
        },
    );
    assert_eq!(result, Err(Violation::Phase));
    assert!(coordinator.owns_storage_read(read_id));
    coordinator.storage_read_completed(fixture.context_mut()?, completion);
    assert_eq!(handle.queued_bytes(), 0);
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert_eq!(
        coordinator.peers.get(&PEER).ok_or("peer")?.outbox.cursor,
        Some((1, SECOND))
    );
    Ok(())
}

#[tokio::test]
async fn an_intermediate_retained_event_id_must_match_its_sealed_row() -> TestResult {
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .outbox
        .unacked
        .get_mut(0)
        .ok_or("first retained row")?
        .1 = EventId::from_bytes([99; 16]);
    let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    let completion = fixture.next_storage_read().await?;
    coordinator.storage_read_completed(fixture.context_mut()?, completion);
    assert!(coordinator.peers.get(&PEER).ok_or("peer")?.live.is_none());
    assert_eq!(handle.queued_bytes(), 0);
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert_unreconciled(&mut fixture, &coordinator)?;
    Ok(())
}

#[tokio::test]
async fn a_replacement_link_never_receives_the_old_resume_receipt() -> TestResult {
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    let (old, _old_queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    validate_retained_prefix(&mut fixture, &mut coordinator).await?;
    let (replacement, _new_queue) = link_queue(1 << 20);
    coordinator.inbound(
        fixture.context_mut()?,
        established(3, PEER, INCARNATION, replacement.clone()),
    );
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert_eq!(old.queued_bytes(), 0);
    assert_eq!(replacement.queued_bytes(), 0);
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert_eq!(
        state.live.as_ref().ok_or("replacement link")?.link,
        LinkId::new(3)
    );
    assert_eq!(state.outbox.cursor, Some((1, SECOND)));
    assert!(state.resend.is_none() && state.reconciliation.is_none());
    Ok(())
}

#[tokio::test]
async fn a_resource_refused_resume_retries_only_after_its_timer() -> TestResult {
    use crate::state_core::timers::{TimedId, TimerKind};
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    let (handle, mut queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    validate_retained_prefix(&mut fixture, &mut coordinator).await?;
    fixture
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_ircd_storage::StorageError::QueueFull)?;
    coordinator.batch_rejected_with_error(
        fixture.context_mut()?,
        agenc_ircd_storage::StorageError::QueueFull,
    );
    coordinator.batch_rejected_with_error(
        fixture.context_mut()?,
        agenc_ircd_storage::StorageError::QueueFull,
    );
    assert_unreconciled(&mut fixture, &coordinator)?;
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert_eq!(handle.queued_bytes(), 0);
    assert!(coordinator.peers.get(&PEER).ok_or("peer")?.live.is_some());
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
    assert_eq!(fixture.context_mut()?.pending_len(), 1);
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

fn window_event_id(sequence: u64) -> TestResult<EventId> {
    let mut bytes = [91; 16];
    bytes
        .get_mut(8..)
        .ok_or("event ID suffix")?
        .copy_from_slice(&sequence.to_be_bytes());
    Ok(EventId::from_bytes(bytes))
}

async fn fire_resume_timer(
    fixture: &mut StateCoreFixture,
    coordinator: &mut FederationCoordinator,
) -> TestResult {
    let deadline = fixture.context_mut()?.now().checked_add(20)?;
    let timer = fixture
        .context_mut()?
        .timers_mut()
        .pop_due(deadline)
        .ok_or("next chunk timer")?;
    assert_eq!(
        timer.kind,
        crate::state_core::timers::TimerKind::FederationResumeRetry
    );
    assert!(coordinator.timer_fired(fixture.context_mut()?, timer));
    Ok(())
}

#[tokio::test]
async fn a_suspended_peer_reconciles_more_than_one_bounded_chunk() -> TestResult {
    let mut records = vec![restored_peer_record(
        PEER,
        INCARNATION,
        PeerPhase::Suspended,
    )?];
    for sequence in 0..260 {
        records.push(retained_event(sequence, window_event_id(sequence)?)?);
    }
    let (mut fixture, mut coordinator) = retained_window_fixture(records).await?;
    let (handle, mut queue) =
        reconnect_with_cursor(&mut fixture, &mut coordinator, 258, window_event_id(258)?)?;
    validate_retained_prefix(&mut fixture, &mut coordinator).await?;
    assert_eq!(handle.queued_bytes(), 0);
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert_eq!(
        coordinator.peers.get(&PEER).ok_or("peer")?.outbox.cursor,
        Some((255, window_event_id(255)?))
    );
    assert_eq!(
        handle.queued_bytes(),
        0,
        "intermediate receipt cannot resume"
    );
    assert!(!fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, 255)?)?);
    assert!(fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, 256)?)?);
    fire_resume_timer(&mut fixture, &mut coordinator).await?;
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert!(matches!(
        next_base_frame(&mut queue).await?,
        FederationFrame::ResumeOk {
            projection_generation: 0,
            next_delivery_sequence: 259,
            ..
        }
    ));
    assert_eq!(
        coordinator.peers.get(&PEER).ok_or("peer")?.outbox.cursor,
        Some((258, window_event_id(258)?))
    );
    assert!(!fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, 258)?)?);
    assert!(fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, 259)?)?);
    Ok(())
}

#[tokio::test]
async fn committed_resume_coverage_survives_coordinator_reload() -> TestResult {
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    let (_handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    validate_retained_prefix(&mut fixture, &mut coordinator).await?;
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    // The old owner has already submitted its first replay read. Consume that
    // receipt before replacing it, so it cannot be confused with loader work.
    let _old_read = fixture.next_storage_read().await?;
    let mut restored = standalone_coordinator(PEER);
    restored.startup(fixture.context_mut()?);
    for _ in 0..64 {
        if restored.loaded() {
            break;
        }
        let completion = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.next_storage_read(),
        )
        .await??;
        restored.storage_read_completed(fixture.context_mut()?, completion);
    }
    assert!(restored.loaded());
    let state = restored.peers.get(&PEER).ok_or("restored peer")?;
    assert_eq!(state.projection_generation, 0);
    assert_eq!(state.outbox.cursor, Some((1, SECOND)));
    assert_eq!(
        state
            .outbox
            .unacked
            .front()
            .map(|(sequence, id, _)| (*sequence, *id)),
        Some((2, SUCCESSOR))
    );
    assert_eq!(state.outbox.unacked.len(), 1);
    Ok(())
}

#[tokio::test]
async fn quiescing_during_retained_validation_releases_the_read_owner() -> TestResult {
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    let completion = fixture.next_storage_read().await?;
    let read_id = completion.read_id;
    fixture
        .state_mut()?
        .step_message(crate::state_core::inbox::StateCoreMessage::Signal(
            crate::state_core::inbox::SignalEvent::Terminate,
        ));
    assert!(fixture.context_mut()?.is_quiescing());
    coordinator.storage_read_completed(fixture.context_mut()?, completion);
    assert!(!coordinator.owns_storage_read(read_id));
    assert!(coordinator.reload_ready());
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert_eq!(handle.queued_bytes(), 0);
    assert_unreconciled(&mut fixture, &coordinator)?;
    Ok(())
}

fn retained_barrier_completion() -> TestResult<InitialStorageRecord> {
    let event = ProjectedEvent::RequestCompleted {
        resulting_state_generation: 1,
    };
    let correlation = agenc_ircd_federation_wire::RequestCorrelation {
        replay_key: ReplayKey {
            home_server_id: PEER,
            server_incarnation: INCARNATION,
            origin_id: OriginId::from_bytes([70; 16]),
            origin_generation: 1,
            operation_sequence: 0,
        },
        request_id: RequestId::from_bytes([71; 16]),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: PEER,
        projection_generation: 0,
        coordinator_state_generation: 1,
        delivery_sequence: 0,
        event_id: FIRST,
        event_kind: event.kind(),
        correlation: Some(correlation),
        cross_profile: Some(agenc_ircd_federation_wire::CrossProfilePart {
            mutation_id: [72; 16],
            part_index: 0,
            part_count: 2,
        }),
    };
    let arm =
        crate::federation::codec::events::event_arm_object(&event).map_err(|e| format!("{e:?}"))?;
    let bytes = header.build(&arm)?.encode_canonical()?.as_slice().to_vec();
    let body = OutboxEventRecord {
        event_id: *FIRST.as_bytes(),
        event_object_id: *federation_object_id(&bytes).as_bytes(),
        event_object: bytes,
        coordinator_state_generation: 1,
        acknowledged: false,
        completion_replay_key: Some(correlation.replay_key.to_bytes()),
    }
    .encode()?;
    let value = PersistentRecordValue::new(
        TableId::EdgeOutbox,
        OUTBOX_EVENT_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?
    .encode()?;
    Ok(InitialStorageRecord::new(
        TableId::EdgeOutbox,
        outbox_key(PEER, 0, 0)?,
        1,
        value,
    )?)
}

#[tokio::test]
async fn an_ordinary_resume_never_consumes_an_unrestored_barrier_prefix() -> TestResult {
    let records = vec![
        restored_peer_record(PEER, INCARNATION, PeerPhase::Suspended)?,
        retained_barrier_completion()?,
        retained_event(1, SECOND)?,
        retained_event(2, SUCCESSOR)?,
    ];
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    let head = fixture.context_mut()?.head().storage_commit_sequence;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.startup(fixture.context_mut()?);
    for _ in 0..16 {
        if coordinator.peers.get(&PEER).ok_or("peer")?.quarantined {
            break;
        }
        let completion = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.next_storage_read(),
        )
        .await??;
        coordinator.storage_read_completed(fixture.context_mut()?, completion);
    }
    assert!(!coordinator.loaded());
    assert!(coordinator.peers.get(&PEER).ok_or("peer")?.quarantined);
    assert!(
        coordinator.barriers.is_empty(),
        "the immutable row is the exclusion boundary"
    );
    let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    assert!(coordinator.peers.get(&PEER).ok_or("peer")?.live.is_none());
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert_eq!(handle.queued_bytes(), 0);
    assert_eq!(
        coordinator.peers.get(&PEER).ok_or("peer")?.outbox.cursor,
        None
    );
    assert_eq!(fixture.context_mut()?.head().storage_commit_sequence, head);
    for sequence in 0..3 {
        assert!(fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, sequence)?)?);
    }
    Ok(())
}

#[tokio::test]
async fn timer_exhaustion_closes_resume_without_advancing_coverage() -> TestResult {
    use crate::state_core::timers::{TimedId, TimerHeap, TimerKind};
    let (mut fixture, mut coordinator) = rejected_ack_fixture().await?;
    let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    validate_retained_prefix(&mut fixture, &mut coordinator).await?;
    let deadline = fixture.context_mut()?.now().checked_add(1_000)?;
    *fixture.context_mut()?.timers_mut() = TimerHeap::with_ceiling(1);
    fixture.context_mut()?.timers_mut().schedule(
        deadline,
        TimerKind::Batch,
        TimedId::Sequence(99),
    )?;
    fixture
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_ircd_storage::StorageError::QueueFull)?;
    coordinator.batch_rejected_with_error(
        fixture.context_mut()?,
        agenc_ircd_storage::StorageError::QueueFull,
    );
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert!(state.live.is_none() && state.reconciliation.is_none());
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert_eq!(fixture.context_mut()?.timers_mut().live_len(), 1);
    assert_eq!(handle.queued_bytes(), 0);
    assert_unreconciled(&mut fixture, &coordinator)?;
    Ok(())
}

async fn reload_partial_resume_owner(
    fixture: &mut StateCoreFixture,
) -> TestResult<FederationCoordinator> {
    let mut restored = standalone_coordinator(PEER);
    restored.config.outbox_objects_per_edge = 512;
    restored.startup(fixture.context_mut()?);
    for _ in 0..64 {
        if restored.loaded() {
            return Ok(restored);
        }
        let completion = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.next_storage_read(),
        )
        .await??;
        restored.storage_read_completed(fixture.context_mut()?, completion);
    }
    Err("partial prefix reload did not finish".into())
}

#[tokio::test]
async fn a_partial_resume_commit_reloads_and_finishes_its_remaining_prefix() -> TestResult {
    let mut records = vec![restored_peer_record(
        PEER,
        INCARNATION,
        PeerPhase::Suspended,
    )?];
    for sequence in 0..260 {
        records.push(retained_event(sequence, window_event_id(sequence)?)?);
    }
    let (mut fixture, mut coordinator) = retained_window_fixture(records).await?;
    let (old, _old_queue) =
        reconnect_with_cursor(&mut fixture, &mut coordinator, 258, window_event_id(258)?)?;
    validate_retained_prefix(&mut fixture, &mut coordinator).await?;
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert_eq!(old.queued_bytes(), 0);
    assert_eq!(
        coordinator.peers.get(&PEER).ok_or("peer")?.outbox.cursor,
        Some((255, window_event_id(255)?))
    );
    drop(coordinator);
    *fixture.context_mut()?.timers_mut() = crate::state_core::timers::TimerHeap::new();
    let mut restored = reload_partial_resume_owner(&mut fixture).await?;
    let state = restored.peers.get(&PEER).ok_or("restored peer")?;
    assert_eq!(state.outbox.cursor, Some((255, window_event_id(255)?)));
    assert_eq!(state.outbox.unacked.len(), 4);
    let (handle, mut queue) =
        reconnect_with_cursor(&mut fixture, &mut restored, 258, window_event_id(258)?)?;
    validate_retained_prefix(&mut fixture, &mut restored).await?;
    assert_eq!(handle.queued_bytes(), 0);
    fixture.commit_staged_batch().await?;
    restored.batch_applied(fixture.context_mut()?);
    assert!(matches!(
        next_base_frame(&mut queue).await?,
        FederationFrame::ResumeOk {
            projection_generation: 0,
            next_delivery_sequence: 259,
            ..
        }
    ));
    assert!(!fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, 258)?)?);
    assert!(fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, 259)?)?);
    Ok(())
}

#[path = "retained_resume/page_faults.rs"]
mod page_faults;
#[path = "retained_resume/row_faults.rs"]
mod row_faults;
