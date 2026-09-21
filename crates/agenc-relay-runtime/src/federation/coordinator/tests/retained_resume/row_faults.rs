#![forbid(unsafe_code)]

//! A retained row that belongs to another network, or a retained window with a gap, never
//! reconciles a resume cursor and never advances coverage.

use super::*;

/// One retained ordinary event whose header names `network`.
fn retained_event_on(
    sequence: u64,
    event_id: EventId,
    network: NetworkId,
) -> TestResult<InitialStorageRecord> {
    let event = ProjectedEvent::NetworkNotice {
        code: "REPLAY".to_owned(),
        text: "committed while disconnected".to_owned(),
    };
    let header = EventHeader {
        network_id: network,
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

fn assert_retired(
    fixture: &mut StateCoreFixture,
    coordinator: &FederationCoordinator,
) -> TestResult {
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert!(state.live.is_none());
    assert!(state.reconciliation.is_none());
    assert_eq!(state.outbox.cursor, None);
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    for sequence in state
        .outbox
        .unacked
        .iter()
        .map(|(sequence, _, _)| *sequence)
    {
        assert!(fixture.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 0, sequence)?)?);
    }
    Ok(())
}

#[tokio::test]
async fn a_retained_row_addressed_to_another_network_retires_the_link() -> TestResult {
    let records = vec![
        restored_peer_record(PEER, INCARNATION, PeerPhase::Ready)?,
        retained_event(0, FIRST)?,
        retained_event_on(1, SECOND, NetworkId::from_bytes([99; 32]))?,
        retained_event(2, SUCCESSOR)?,
    ];
    let (mut fixture, mut coordinator) = retained_window_fixture(records).await?;
    let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 1, SECOND)?;
    assert!(
        coordinator
            .peers
            .get(&PEER)
            .ok_or("peer")?
            .reconciliation
            .is_some()
    );
    let completion = fixture.next_storage_read().await?;
    coordinator.storage_read_completed(fixture.context_mut()?, completion);
    assert_eq!(handle.queued_bytes(), 0);
    assert_retired(&mut fixture, &coordinator)
}

#[tokio::test]
async fn a_retained_window_with_a_gap_refuses_the_cursor_before_any_read() -> TestResult {
    let records = vec![
        restored_peer_record(PEER, INCARNATION, PeerPhase::Ready)?,
        retained_event(0, FIRST)?,
        retained_event(2, SECOND)?,
        retained_event(3, SUCCESSOR)?,
    ];
    let (mut fixture, mut coordinator) = retained_window_fixture(records).await?;
    let (handle, _queue) = reconnect_with_cursor(&mut fixture, &mut coordinator, 2, SECOND)?;
    assert_eq!(handle.queued_bytes(), 0);
    assert_retired(&mut fixture, &coordinator)?;
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            fixture.next_storage_read()
        )
        .await
        .is_err(),
        "no validation read was submitted"
    );
    Ok(())
}
