#![forbid(unsafe_code)]

//! The unacknowledged window: what it retains, what it refuses, and what it fences.

use agenc_relay_storage::e2ee_records::delivery_recovery::{
    BarrierEndpoint, DeliveryBarrier, DeliveryBarrierFields, DeliveryScope, DeliveryScopeFields,
};
use agenc_relay_storage::federation_records::{OUTBOX_EVENT_KIND, OutboxEventRecord, outbox_key};
use agenc_relay_types::EventId;

use super::*;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const STRANGER: ServerId = ServerId::from_bytes([99; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

fn event_id(sequence: u64) -> EventId {
    let seed = u8::try_from(sequence).unwrap_or(u8::MAX);
    EventId::from_bytes([seed.saturating_add(61); 16])
}

fn outbound(target: ServerId, generation: u64, sequence: u64) -> OutboundEvent {
    OutboundEvent {
        target,
        projection_generation: generation,
        delivery_sequence: sequence,
        event_id: event_id(sequence),
        object_id: FederationHash32::from_bytes([62; 32]),
        encoded: vec![1; 128],
        combined_barrier: None,
    }
}

fn ack(sequence: u64, event_id: EventId) -> FederationInbound {
    FederationInbound {
        link: LinkId::new(1),
        peer: PEER,
        event: LinkEvent::Frame(FederationFrame::Ack {
            coordinator_server_id: COORDINATOR,
            delivery_sequence: sequence,
            event_id,
        }),
        charge: None,
    }
}

/// Storage that already holds the outbox rows of sequences `0..count`.
fn stored_window(count: u64) -> TestResult<StateCoreFixture> {
    let mut records = Vec::new();
    for sequence in 0..count {
        let body = OutboxEventRecord {
            event_id: *event_id(sequence).as_bytes(),
            event_object_id: [62; 32],
            event_object: vec![1; 128],
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
        records.push(InitialStorageRecord::new(
            TableId::EdgeOutbox,
            outbox_key(PEER, 1, sequence)?,
            1,
            value,
        )?);
    }
    StateCoreFixture::with_registration_router_and_records(entropy_script(), records)
}

fn state(coordinator: &FederationCoordinator) -> TestResult<&PeerState> {
    Ok(coordinator.peers.get(&PEER).ok_or("peer")?)
}

fn state_mut(coordinator: &mut FederationCoordinator) -> TestResult<&mut PeerState> {
    Ok(coordinator.peers.get_mut(&PEER).ok_or("peer")?)
}

/// An active link whose window holds sequences `0..count`.
fn active_window(
    context: &mut StateCoreContext,
    count: u64,
) -> TestResult<(FederationCoordinator, crate::federation::link::LinkQueue)> {
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    state_mut(&mut coordinator)?.active = true;
    let events = (0..count)
        .map(|sequence| outbound(PEER, 1, sequence))
        .collect();
    coordinator.deliver(context, events);
    Ok((coordinator, queue))
}

fn barrier_over(first: u64, last: u64, final_event: EventId) -> TestResult<DeliveryBarrier> {
    let scope = DeliveryScope::new(DeliveryScopeFields {
        network_id: *NETWORK.as_bytes(),
        coordinator_server_id: *COORDINATOR.as_bytes(),
        coordinator_incarnation: [33; 16],
        coordinator_recovery_epoch: [34; 16],
        target_server_id: *PEER.as_bytes(),
        target_incarnation: *INCARNATION.as_bytes(),
        covered_base_client_resync_epoch: 0,
    })?;
    let parts = last
        .checked_sub(first)
        .and_then(|span| span.checked_add(2))
        .ok_or("barrier span")?;
    Ok(DeliveryBarrier::new(DeliveryBarrierFields {
        scope,
        mutation_id: [63; 16],
        state_generation: 1,
        part_count: u16::try_from(parts)?,
        base: BarrierEndpoint::new(1, first, last, *final_event.as_bytes())?,
        companion: BarrierEndpoint::new(1, 0, 0, [64; 16])?,
        base_acked: false,
        companion_acked: false,
    })?)
}

#[tokio::test]
async fn an_acknowledgement_of_an_empty_window_closes_the_link() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = active_window(context, 0)?;
    coordinator.inbound(context, ack(0, event_id(0)));
    assert_eq!(coordinator.counters().violations, 1);
    assert!(state(&coordinator)?.live.is_none());
    assert!(coordinator.pending.is_none());
    assert_eq!(context.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn an_acknowledgement_must_name_the_oldest_event_exactly() -> TestResult {
    for (sequence, id) in [(0, event_id(9)), (1, event_id(1)), (2, event_id(2))] {
        let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
        let context = fixture.context_mut()?;
        let (mut coordinator, _queue) = active_window(context, 2)?;
        coordinator.inbound(context, ack(sequence, id));
        assert_eq!(coordinator.counters().violations, 1);
        let state = state(&coordinator)?;
        assert!(state.live.is_none());
        assert_eq!(state.outbox.unacked.len(), 2, "the window is untouched");
        assert_eq!(state.outbox.cursor, None);
        assert!(coordinator.pending.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn an_exact_acknowledgement_retires_only_the_oldest_event_after_commit() -> TestResult {
    let mut fixture = stored_window(2)?;
    let (mut coordinator, _queue) = active_window(fixture.context_mut()?, 2)?;
    coordinator.inbound(fixture.context_mut()?, ack(0, event_id(0)));
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::DeliveryAcknowledged {
            delivery_sequence: 0,
            barrier: None,
            resume: None,
            ..
        })
    ));
    assert_eq!(state(&coordinator)?.outbox.unacked.len(), 2);
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    let state = state(&coordinator)?;
    assert_eq!(state.outbox.cursor, Some((0, event_id(0))));
    assert_eq!(
        state.outbox.unacked.front().copied(),
        Some((1, event_id(1), 128))
    );
    assert_eq!(state.outbox.unacked_bytes, 128);
    assert_eq!(coordinator.federation_stats(), [1, 1, 0, 1, 128, 0, 0]);
    Ok(())
}

#[tokio::test]
async fn a_barrier_acknowledgement_whose_final_event_is_not_in_the_window_is_refused() -> TestResult
{
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = active_window(context, 2)?;
    // The gate names a final event the window never delivered at that sequence.
    coordinator
        .barriers
        .insert(PEER, barrier_over(0, 1, event_id(9))?);
    coordinator.inbound(context, ack(1, event_id(9)));
    assert_eq!(coordinator.counters().violations, 1);
    assert!(state(&coordinator)?.live.is_none());
    assert!(coordinator.pending.is_none());
    assert!(
        coordinator
            .barriers
            .get(&PEER)
            .is_some_and(|gate| !gate.base_acked())
    );
    Ok(())
}

#[tokio::test]
async fn an_acknowledgement_inside_a_barrier_that_is_not_its_final_part_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = active_window(context, 2)?;
    coordinator
        .barriers
        .insert(PEER, barrier_over(0, 1, event_id(1))?);
    coordinator.inbound(context, ack(0, event_id(0)));
    assert_eq!(coordinator.counters().violations, 1);
    assert!(state(&coordinator)?.live.is_none());
    assert!(coordinator.pending.is_none());
    Ok(())
}

#[tokio::test]
async fn a_barrier_acknowledgement_covers_every_base_part_at_once() -> TestResult {
    let mut fixture = stored_window(3)?;
    let (mut coordinator, _queue) = active_window(fixture.context_mut()?, 3)?;
    coordinator
        .barriers
        .insert(PEER, barrier_over(0, 1, event_id(1))?);
    coordinator.inbound(fixture.context_mut()?, ack(1, event_id(1)));
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::DeliveryAcknowledged {
            delivery_sequence: 1,
            barrier: Some(_),
            ..
        })
    ));
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    let state = state(&coordinator)?;
    assert_eq!(state.outbox.cursor, Some((1, event_id(1))));
    assert_eq!(state.outbox.unacked.len(), 1);
    assert!(
        coordinator
            .barriers
            .get(&PEER)
            .is_some_and(|gate| gate.base_acked() && !gate.companion_acked())
    );
    Ok(())
}

#[tokio::test]
async fn a_barrier_that_changed_under_its_acknowledgement_fails_the_restore() -> TestResult {
    let mut fixture = stored_window(2)?;
    let (mut coordinator, _queue) = active_window(fixture.context_mut()?, 2)?;
    coordinator
        .barriers
        .insert(PEER, barrier_over(0, 1, event_id(1))?);
    coordinator.inbound(fixture.context_mut()?, ack(1, event_id(1)));
    fixture.commit_staged_batch().await?;
    coordinator.barriers.remove(&PEER);
    coordinator.batch_applied(fixture.context_mut()?);
    assert!(coordinator.loader.blocks_admission());
    assert!(state(&coordinator)?.quarantined);
    assert!(state(&coordinator)?.live.is_none());
    assert_eq!(coordinator.counters().violations, 1);
    assert_eq!(
        state(&coordinator)?.outbox.cursor,
        None,
        "coverage is never published over a gate that moved"
    );
    assert_eq!(state(&coordinator)?.outbox.unacked.len(), 2);
    Ok(())
}

#[tokio::test]
async fn an_event_past_an_open_barrier_is_retained_but_not_sent() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = active_window(context, 0)?;
    let observer = state(&coordinator)?
        .live
        .as_ref()
        .map(|live| live.handle.clone())
        .ok_or("live")?;
    coordinator
        .barriers
        .insert(PEER, barrier_over(0, 0, event_id(0))?);
    coordinator.deliver(context, vec![outbound(PEER, 1, 0)]);
    let sent = observer.queued_bytes();
    assert!(sent > 0, "the barrier's own part is delivered");
    coordinator.deliver(context, vec![outbound(PEER, 1, 1)]);
    assert_eq!(observer.queued_bytes(), sent);
    assert_eq!(coordinator.counters().events_sent, 1);
    assert_eq!(state(&coordinator)?.outbox.unacked.len(), 2);
    Ok(())
}

#[tokio::test]
async fn events_for_an_unknown_target_or_a_stale_generation_are_dropped() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = active_window(context, 0)?;
    coordinator.deliver(
        context,
        vec![outbound(STRANGER, 1, 0), outbound(PEER, 2, 0)],
    );
    let state = state(&coordinator)?;
    assert!(state.outbox.unacked.is_empty());
    assert_eq!(state.outbox.reserved_next, 0);
    assert_eq!(coordinator.counters().events_sent, 0);
    assert!(state.live.is_some());
    Ok(())
}

#[tokio::test]
async fn an_active_peer_without_a_link_retains_its_events() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    state_mut(&mut coordinator)?.active = true;
    coordinator.deliver(context, vec![outbound(PEER, 1, 0)]);
    let state = state(&coordinator)?;
    assert_eq!(state.outbox.unacked.len(), 1);
    assert_eq!(state.outbox.reserved_next, 1);
    assert_eq!(coordinator.counters().events_sent, 0);
    Ok(())
}

#[tokio::test]
async fn an_overflowing_window_without_a_link_still_requires_a_snapshot() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.config.outbox_bytes_per_edge = 127;
    coordinator.deliver(context, vec![outbound(PEER, 1, 0)]);
    let state = state(&coordinator)?;
    assert!(state.outbox.snapshot_required);
    assert!(state.outbox.dirty);
    assert_eq!(coordinator.counters().violations, 0);
    Ok(())
}

#[tokio::test]
async fn a_fenced_window_stops_growing_and_marks_itself_dirty_once() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.config.outbox_objects_per_edge = 0;
    coordinator.deliver(context, vec![outbound(PEER, 1, 0)]);
    state_mut(&mut coordinator)?.outbox.dirty = false;
    coordinator.deliver(context, vec![outbound(PEER, 1, 1)]);
    let state = state(&coordinator)?;
    assert_eq!(
        state.outbox.unacked.len(),
        1,
        "a fenced window adds nothing"
    );
    assert_eq!(state.outbox.unacked_bytes, 128);
    assert_eq!(state.outbox.reserved_next, 2);
    assert!(!state.outbox.dirty, "the fence is recorded once");
    Ok(())
}

#[tokio::test]
async fn the_snapshot_requirement_is_recorded_durably_before_it_is_clean() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.config.outbox_objects_per_edge = 0;
    coordinator.deliver(fixture.context_mut()?, vec![outbound(PEER, 1, 0)]);
    coordinator.continue_background(fixture.context_mut()?);
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::OutboxRequired { peer: PEER })
    ));
    assert!(state(&coordinator)?.outbox.dirty);
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert!(coordinator.pending.is_none());
    assert!(!state(&coordinator)?.outbox.dirty);
    assert!(fixture.stored_row_exists(TableId::FederationPeer, peer_key(PEER)?)?);
    coordinator.continue_background(fixture.context_mut()?);
    assert!(
        coordinator.pending.is_none(),
        "a clean fence stages nothing"
    );
    Ok(())
}

#[tokio::test]
async fn background_work_waits_for_an_open_batch_and_for_the_reload() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    state_mut(&mut coordinator)?.outbox.dirty = true;
    coordinator
        .stage_rows(context, Vec::new(), PendingCommit::Acknowledged, Some(PEER))
        .map_err(|error| format!("stage: {error:?}"))?;
    coordinator.pending = None;
    coordinator.continue_background(context);
    assert!(coordinator.pending.is_none(), "another plan is still open");
    assert_eq!(context.pending_len(), 1);

    let mut reloading = standalone_coordinator(PEER);
    state_mut(&mut reloading)?.outbox.dirty = true;
    let mut second = StateCoreFixture::with_registration_router(entropy_script())?;
    reloading.startup(second.context_mut()?);
    assert!(!reloading.loaded());
    reloading.continue_background(second.context_mut()?);
    assert!(
        reloading.pending.is_none(),
        "the reload owns the batch slot"
    );
    Ok(())
}

#[tokio::test]
async fn staging_rows_over_an_open_federation_batch_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.pending = Some(PendingCommit::Acknowledged);
    let refused = coordinator.stage_rows(
        context,
        Vec::new(),
        PendingCommit::OutboxRequired { peer: PEER },
        Some(PEER),
    );
    assert!(matches!(refused, Err(RuntimeError::LimitExceeded)));
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::Acknowledged)
    ));
    assert_eq!(context.pending_len(), 0);
    let unknown = coordinator.peer_row(STRANGER, 1);
    assert!(matches!(unknown, Err(RuntimeError::InvalidValue)));
    Ok(())
}
