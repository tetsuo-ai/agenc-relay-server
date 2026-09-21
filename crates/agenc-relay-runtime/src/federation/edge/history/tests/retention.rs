//! Edge history receipts retire only once no request or live origin can still claim them.
#![forbid(unsafe_code)]

use super::lifecycle::{Parts, begun, successor_header};
use super::refusals::apply;
use super::*;

const GENERATION: ConnectionGeneration = ConnectionGeneration::new(1);

/// A committed receipt whose query then failed, leaving only the durable row behind.
async fn finished_query() -> TestResult<(Parts, agenc_relay_storage::StoredKey)> {
    let ((mut fixture, mut edge, sink, page), _) = begun()?;
    apply(&mut fixture, &mut edge).await?;
    let id = *edge.pending.keys().next().ok_or("registered request")?;
    let record = edge.history.records.get(&id).ok_or("record")?;
    let key =
        agenc_relay_storage::federation_records::request_result_key(record.request.replay_key)?;
    let header = successor_header(&edge, id)?;
    let arm = ResultArm::Failed {
        code: "SERVER_BUSY".into(),
        context: String::new(),
    };
    receive(
        &mut edge,
        fixture.context_mut()?,
        header,
        FederationHash32::from_bytes([14; 32]),
        arm,
    )
    .map_err(|error| format!("receive: {error:?}"))?;
    assert!(edge.pending.is_empty());
    assert!(edge.history.batches.is_empty());
    assert!(fixture.stored_row_exists(TableId::RequestResult, key.clone())?);
    Ok(((fixture, edge, sink, page), key))
}

/// Runs one retention scan and reports whether it staged a cleanup batch.
async fn scan(fixture: &mut StateCoreFixture, edge: &mut EdgeFederation) -> TestResult<bool> {
    edge.retain_history(fixture.context_mut()?);
    let message = fixture.next_storage_read().await?;
    let read = message.read_id;
    assert!(edge.owns_history_read(read));
    edge.history_read_completed(fixture.context_mut()?, message);
    assert!(!edge.owns_history_read(read));
    Ok(matches!(
        edge.commit,
        Some(PendingCommit::HistoryCleanup(_))
    ))
}

#[tokio::test]
async fn a_receipt_of_a_live_origin_is_never_retired() -> TestResult {
    let ((mut fixture, mut edge, _, _), key) = finished_query().await?;
    assert!(!scan(&mut fixture, &mut edge).await?);
    assert!(edge.commit.is_none());
    fixture.context_mut()?.set_wall_for_test(1_000 + 2 * 86_400);
    assert!(!scan(&mut fixture, &mut edge).await?);
    assert!(fixture.stored_row_exists(TableId::RequestResult, key)?);
    Ok(())
}

#[tokio::test]
async fn a_deleted_origins_receipt_is_dated_then_removed_a_day_later() -> TestResult {
    let ((mut fixture, mut edge, _, _), key) = finished_query().await?;
    edge.origins.get_mut(&GENERATION).ok_or("origin")?.deleted = true;
    assert!(scan(&mut fixture, &mut edge).await?);
    apply(&mut fixture, &mut edge).await?;
    assert!(edge.commit.is_none());
    assert!(fixture.stored_row_exists(TableId::RequestResult, key.clone())?);
    assert!(!scan(&mut fixture, &mut edge).await?);
    assert!(fixture.stored_row_exists(TableId::RequestResult, key.clone())?);
    fixture.context_mut()?.set_wall_for_test(1_000 + 86_400 + 1);
    assert!(scan(&mut fixture, &mut edge).await?);
    apply(&mut fixture, &mut edge).await?;
    assert!(!fixture.stored_row_exists(TableId::RequestResult, key)?);
    Ok(())
}

#[tokio::test]
async fn a_scan_that_completes_behind_another_batch_stages_nothing() -> TestResult {
    let ((mut fixture, mut edge, _, _), key) = finished_query().await?;
    edge.origins.get_mut(&GENERATION).ok_or("origin")?.deleted = true;
    edge.commit = Some(PendingCommit::BarrierFence);
    edge.retain_history(fixture.context_mut()?);
    edge.commit = None;
    edge.retain_history(fixture.context_mut()?);
    let message = fixture.next_storage_read().await?;
    edge.commit = Some(PendingCommit::BarrierFence);
    edge.history_read_completed(fixture.context_mut()?, message);
    assert!(matches!(edge.commit, Some(PendingCommit::BarrierFence)));
    assert_eq!(fixture.context_mut()?.pending_len(), 0);
    assert!(fixture.stored_row_exists(TableId::RequestResult, key)?);
    Ok(())
}
