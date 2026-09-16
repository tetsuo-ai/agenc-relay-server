#![forbid(unsafe_code)]

//! A never-transmitted origin still owns its pending storage records.

use super::*;

#[tokio::test]
async fn reconnect_retains_a_closed_origin_while_its_first_write_is_pending() -> TestResult {
    settle_closed_origin(false).await
}

#[tokio::test]
async fn reconnect_retains_a_closed_origin_after_its_first_write_is_refused() -> TestResult {
    settle_closed_origin(true).await
}

async fn settle_closed_origin(refuse: bool) -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    *fixture.context_mut()?.timers_mut() = TimerHeap::new();
    let mut edge = resync_edge();
    let mut queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Active;
    let connection = ConnectionGeneration::new(1);
    edge.connection_opened(fixture.context_mut()?, connection);
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!(origin.object_id, [0; 32]);
    let origin_id = origin.origin_id;
    assert_eq!(fixture.context_mut()?.pending_len(), 1);
    if refuse {
        reject_request(
            &mut edge,
            &mut fixture,
            StorageError::FilesystemRejected(agenc_ircd_storage::FilesystemCause::IoFailure),
        )?;
    }
    edge.connection_closed(fixture.context_mut()?, connection, "client left");
    edge.phase = Phase::Origins;
    request::replay_origin(&mut edge, fixture.context_mut()?, connection);
    assert!(
        edge.origins.contains_key(&connection),
        "reconnect discarded an origin with unsettled journal ownership"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv())
            .await
            .is_err(),
        "DEL escaped before its tombstone committed"
    );
    if refuse {
        let entry = retry_entry(fixture.context_mut()?)?;
        edge.timer_fired(fixture.context_mut()?, entry);
    }
    commit_edge_batches(&mut edge, &mut fixture).await?;
    assert_eq!(edge.phase, Phase::Origins);
    assert!(journal::is_durable(
        &edge,
        journal::Identity::Origin(connection)
    ));
    let mut restarted = resync_edge();
    fixture.restore_edge_state(&mut restarted, None)?;
    assert!(
        restarted
            .origins
            .values()
            .any(|origin| { origin.origin_id == origin_id && origin.deleted && !origin.del_acked })
    );
    let line = tokio::time::timeout(std::time::Duration::from_secs(2), queue.recv())
        .await?
        .ok_or("closed link")?;
    assert!(matches!(
        parse_frame(line.as_str().trim_end_matches("\r\n"), EDGE_NAME)
            .map_err(|error| format!("frame: {error:?}"))?,
        FederationFrame::OriginDel { origin_id: actual, generation: 0, next_operation_sequence: 0, .. }
            if actual == origin_id
    ));
    edge.origin_acked(fixture.context_mut()?, EDGE_INCARNATION, origin_id, 0, None)
        .map_err(|error| format!("deletion ACK: {error:?}"))?;
    assert!(
        edge.origins.contains_key(&connection),
        "ACK retired before storage"
    );
    commit_edge_batches(&mut edge, &mut fixture).await?;
    assert!(!edge.origins.contains_key(&connection));
    let mut retired_restart = resync_edge();
    fixture.restore_edge_state(&mut retired_restart, None)?;
    assert!(retired_restart.origins.is_empty());
    assert!(!edge.journal.retry.recovering);
    sync::origin_ready(&mut edge, fixture.context_mut()?, EDGE_INCARNATION)
        .map_err(|error| format!("origin ready: {error:?}"))?;
    assert_eq!(edge.phase, Phase::Active);

    // A fresh origin must still commit and transmit after the old owner retires.
    edge.connection_opened(fixture.context_mut()?, ConnectionGeneration::new(2));
    commit_edge_batches(&mut edge, &mut fixture).await?;
    assert_eq!(edge.phase, Phase::Active);
    assert!(journal::is_durable(
        &edge,
        journal::Identity::Origin(ConnectionGeneration::new(2))
    ));
    Ok(())
}
