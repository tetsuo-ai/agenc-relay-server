//! The real request checkpoint owns query backing until its exact receipt.

#![forbid(unsafe_code)]

use super::*;

fn staged_query() -> TestResult<(StateCoreFixture, FederationCoordinator, OperationKey)> {
    let (mut fixture, identity, plan) = query::names_query_fixture()?;
    let mut coordinator = standalone_coordinator(ServerId::from_bytes([50; 16]));
    let context = fixture.context_mut()?;
    let (mut fresh, edge) = remote_account_staging_request(&mut coordinator, context)?;
    fresh.header.opcode = agenc_relay_types::FederationOpcode::DirectoryQuery;
    fresh.command = None;
    let key = fresh.key;
    let scope = query::CursorScope {
        coordinator: COORDINATOR,
        network_id: NETWORK,
    };
    let page = coordinator
        .queries
        .first_page(context, &scope, &identity, &plan)?;
    request::answer_page(
        &mut coordinator,
        context,
        edge.link,
        edge.server_id,
        fresh,
        Ok(page),
    )
    .map_err(|error| format!("query checkpoint: {error:?}"))?;
    assert_eq!(context.pending_len(), 1);
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::Request { query: Some(_), .. })
    ));
    assert_eq!(context.sessions().queue_snapshot().query_snapshots(), 1);
    assert_eq!(coordinator.queries.live_cursors(), 1);
    // A callback for an earlier head must not consume this page or reservation.
    coordinator.batch_applied(context);
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::Request { query: Some(_), .. })
    ));
    assert_eq!(context.sessions().queue_snapshot().query_snapshots(), 1);
    Ok((fixture, coordinator, key))
}

#[test]
fn a_rejected_directory_checkpoint_releases_its_inaccessible_cursor_and_page() -> TestResult {
    let (mut fixture, mut coordinator, key) = staged_query()?;
    let error = agenc_relay_storage::StorageError::QueueFull;
    fixture
        .state_mut()?
        .reject_fixture_batch_before_submission(error)?;
    let context = fixture.context_mut()?;
    coordinator.batch_rejected_with_error(context, error);
    assert_eq!(context.pending_len(), 0);
    assert!(coordinator.pending.is_none());
    assert_eq!(coordinator.queries.live_cursors(), 0);
    let usage = context.sessions().queue_snapshot();
    assert_eq!(
        (
            usage.query_snapshots(),
            usage.query_rows(),
            usage.query_bytes()
        ),
        (0, 0, 0)
    );
    assert_eq!(
        coordinator
            .origins
            .origin(&key.origin)
            .ok_or("origin")?
            .next_sequence,
        0
    );
    assert!(!coordinator.retained.contains_key(&key));
    Ok(())
}

#[tokio::test]
async fn a_committed_directory_checkpoint_releases_its_page_and_keeps_its_cursor() -> TestResult {
    let (mut fixture, mut coordinator, key) = staged_query()?;
    fixture.commit_staged_batch().await?;
    let context = fixture.context_mut()?;
    coordinator.batch_applied(context);
    assert!(coordinator.pending.is_none());
    assert_eq!(coordinator.queries.live_cursors(), 1);
    assert_eq!(context.sessions().queue_snapshot().query_snapshots(), 1);
    assert_eq!(
        coordinator
            .origins
            .origin(&key.origin)
            .ok_or("origin")?
            .next_sequence,
        1
    );
    assert!(coordinator.retained.contains_key(&key));
    let replay = ReplayKey {
        home_server_id: key.origin.home_server_id,
        server_incarnation: key.origin.server_incarnation,
        origin_id: key.origin.origin_id,
        origin_generation: key.generation,
        operation_sequence: key.sequence,
    };
    let result_key =
        agenc_relay_storage::federation_records::request_result_key(replay.to_bytes())?;
    assert!(context.index().holds(TableId::RequestResult, &result_key));
    drop(coordinator);
    assert_eq!(context.sessions().queue_snapshot().query_snapshots(), 0);
    Ok(())
}
