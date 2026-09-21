#![forbid(unsafe_code)]

//! Origin deletion may commit before the old completion finishes replaying.

use super::*;
use agenc_relay_domain::federation::ProjectionRecord;

fn deliver(
    edge: &mut EdgeFederation,
    fixture: &mut StateCoreFixture,
    sequence: u64,
    correlation: Option<RequestCorrelation>,
) -> TestResult {
    let event = if correlation.is_some() {
        ProjectedEvent::RequestCompleted {
            resulting_state_generation: 10,
        }
    } else {
        ProjectedEvent::NetworkNotice {
            code: "TEST".to_owned(),
            text: "ordered replay".to_owned(),
        }
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: 10,
        delivery_sequence: sequence,
        event_id: EventId::from_bytes([u8::try_from(sequence)? + 60; 16]),
        event_kind: event.kind(),
        correlation,
        cross_profile: None,
    };
    let bytes = header
        .build(&event_arm_object(&event)?)?
        .encode_canonical()?;
    let descriptor = agenc_relay_federation_wire::EventDescriptor {
        target_server_id: EDGE,
        delivery_sequence: sequence,
        event_id: header.event_id,
        object_id: federation_object_id(bytes.as_slice()),
    };
    let object = resync_assembled(bytes.as_slice(), |fragment| FederationFrame::Event {
        descriptor,
        fragment,
    })?;
    let result = events::receive(edge, fixture.context_mut()?, descriptor, &object);
    assert!(
        result.is_ok_and(|outputs| outputs.is_empty()),
        "ordered completion replay was rejected after durable origin retirement"
    );
    Ok(())
}

async fn retired_origin() -> TestResult<(StateCoreFixture, EdgeFederation, RequestCorrelation)> {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut edge, _queue) = active_edge(fixture.context_mut()?)?;
    edge.replica.install(1, Vec::<ProjectionRecord>::new())?;
    edge.accepted_epoch = Some(COORDINATOR_EPOCH);
    edge.installed_epoch = Some(COORDINATOR_EPOCH);
    edge.installed_incarnation = Some(HUB_INCARNATION);
    let request_id = start_request(&mut edge, fixture.context_mut()?)?;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let pending = edge.pending.get(&request_id).ok_or("pending request")?;
    let correlation = RequestCorrelation {
        replay_key: pending.header.replay_key,
        request_id,
    };
    let connection = pending.generation;
    edge.connection_closed(fixture.context_mut()?, connection, "client left");
    commit_edge_batches(&mut edge, &mut fixture).await?;
    edge.origin_acked(
        fixture.context_mut()?,
        EDGE_INCARNATION,
        correlation.replay_key.origin_id,
        correlation.replay_key.origin_generation,
        None,
    )
    .map_err(|error| format!("deletion ACK: {error:?}"))?;
    assert!(edge.pending.contains_key(&request_id));
    commit_edge_batches(&mut edge, &mut fixture).await?;
    assert!(!edge.pending.contains_key(&request_id));
    assert!(!edge.origins.contains_key(&connection));
    let mut restarted = resync_edge();
    fixture.restore_edge_state(&mut restarted, None)?;
    assert!(restarted.pending.is_empty());
    assert!(restarted.origins.is_empty());
    Ok((fixture, edge, correlation))
}

async fn replay(coalesce: bool) -> TestResult {
    let (mut fixture, mut edge, correlation) = retired_origin().await?;
    let mut queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Origins;
    deliver(&mut edge, &mut fixture, 0, None)?;
    if !coalesce {
        commit_edge_batches(&mut edge, &mut fixture).await?;
        assert!(queue.recv().await.is_some());
    }
    deliver(&mut edge, &mut fixture, 1, Some(correlation))?;
    if coalesce {
        deliver(&mut edge, &mut fixture, 2, None)?;
        fixture.commit_staged_batch().await?;
        assert!(edge.batch_applied(fixture.context_mut()?).is_empty());
        assert!(matches!(edge.commit, Some(PendingCommit::OrdinaryBatch(_))));
        assert!(queue.recv().await.is_some());
    }
    assert_eq!(edge.cursor.map(|cursor| cursor.0), Some(0));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv())
            .await
            .is_err(),
        "completion ACK escaped before storage"
    );
    assert!(
        commit_edge_batches(&mut edge, &mut fixture)
            .await?
            .is_empty()
    );
    let expected = if coalesce { 2 } else { 1 };
    assert_eq!(edge.cursor.map(|cursor| cursor.0), Some(expected));
    assert!(queue.recv().await.is_some());
    assert!(edge.pending.is_empty());
    assert!(edge.applied_completions.is_empty());
    assert!(edge.by_completion.is_empty());
    let mut restarted = resync_edge();
    fixture.restore_edge_state(&mut restarted, None)?;
    assert_eq!(restarted.cursor, edge.cursor);
    assert!(restarted.pending.is_empty());
    sync::origin_ready(&mut edge, fixture.context_mut()?, EDGE_INCARNATION)
        .map_err(|error| format!("READY: {error:?}"))?;
    assert_eq!(edge.phase, Phase::Active);
    Ok(())
}

#[tokio::test]
async fn a_retired_origin_completion_replays_after_durable_deletion() -> TestResult {
    replay(false).await
}

#[tokio::test]
async fn a_retired_origin_completion_replays_in_an_ordinary_batch() -> TestResult {
    replay(true).await
}
