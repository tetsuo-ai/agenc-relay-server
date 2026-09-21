#![forbid(unsafe_code)]

//! Incoming events wait for every other storage owner, including gathering batches.

use super::*;
use crate::state_core::fanout::FanoutRequest;

async fn wait_for_other_checkpoint(exclusive: bool) -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    let initial_head = fixture.head()?;
    let context = fixture.core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let write = fixture
        .edge
        .peer_row(None, revision)
        .map_err(|error| format!("peer: {error:?}"))?;
    let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
    if exclusive {
        context
            .stage_edge_checkpoint(revision, fanout, vec![write])
            .map_err(|_| "other exclusive checkpoint refused")?;
    } else {
        context
            .stage_durable_with_account_service(plan, fanout, None, 0, vec![write])
            .map_err(|error| format!("other checkpoint: {error:?}"))?;
    }
    assert_eq!(context.pending_len(), 1);
    assert!(!context.in_flight());
    assert!(!context.edge_checkpoint_ready());
    assert!(fixture.edge.commit.is_none());
    fixture.receive(0)?;
    assert!(fixture.edge.commit.is_none());
    assert_eq!(fixture.edge.queued_events.len(), 1);
    assert!(fixture.edge.cursor.is_none());
    assert_outputs(&fixture.sink, 0);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_eq!(fixture.head()?, initial_head + 1);
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::Event { .. })
    ));
    assert!(fixture.edge.queued_events.is_empty());
    assert!(fixture.edge.cursor.is_none());
    assert_outputs(&fixture.sink, 0);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_eq!(fixture.head()?, initial_head + 2);
    assert_eq!(fixture.edge.cursor.map(|cursor| cursor.0), Some(0));
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert_outputs(&fixture.sink, 1);
    assert_eq!(fixture.edge.phase, Phase::Active);
    Ok(())
}

#[tokio::test]
async fn an_incoming_event_waits_for_another_gathering_checkpoint() -> TestResult {
    wait_for_other_checkpoint(false).await
}

#[tokio::test]
async fn an_incoming_event_waits_for_another_exclusive_checkpoint() -> TestResult {
    wait_for_other_checkpoint(true).await
}
