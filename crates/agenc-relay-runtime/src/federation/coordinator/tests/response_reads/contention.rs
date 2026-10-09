//! A commit landing while a stored reply is read never fails the link: no
//! other router writes companion rows, the completion waits while a batch
//! is open, and a batch of the coordinator's own has the reply read again.
#![forbid(unsafe_code)]

use super::*;
use crate::state_core::durable::AccountServiceDurableWrite;

/// A row another router could write: the edge's federation peer row.
fn other_row(fixture: &mut Fixture) -> TestResult<AccountServiceDurableWrite> {
    let revision = fixture
        .core
        .context_mut()?
        .domain()
        .plan_account_service_checkpoint()?
        .resulting_revision()
        .get();
    Ok(fixture.coordinator.peer_row_at(PEER, revision, None)?)
}

/// Reads the first of the three bodies, leaving the second one's
/// completion in hand.
async fn first_body(fixture: &mut Fixture) -> TestResult<StorageReadCompletionMessage> {
    fixture.submit()?;
    let message = fixture.next_read().await?;
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(fixture.coordinator.companion_response_read.is_some());
    fixture.next_read().await
}

async fn replied(fixture: &mut Fixture) -> TestResult {
    assert!(fixture.coordinator.companion_response_read.is_none());
    fixture.expect_complete_output().await?;
    assert_eq!(fixture.coordinator.counters.requests_replayed, 1);
    assert!(fixture.coordinator.link_is_live(LinkId::new(1), PEER));
    assert_eq!(fixture.coordinator.counters.violations, 0);
    Ok(())
}

/// A commit another router makes between two bodies leaves the read
/// current: the whole reply goes out.
#[tokio::test]
async fn a_commit_of_another_router_between_response_bodies_keeps_the_reply() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let second = first_body(&mut fixture).await?;
    let write = other_row(&mut fixture)?;
    fixture::commit(&mut fixture.core, vec![write]).await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, second);
    assert_eq!(fixture.finish_reads().await?, 1, "the last body");
    replied(&mut fixture).await
}

/// A batch of the coordinator's own that commits between two bodies may
/// have changed them: the completion waits for it, and its receipt reads
/// the reply again from its first body.
#[tokio::test]
async fn an_own_commit_between_response_bodies_reads_the_reply_again() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let second = first_body(&mut fixture).await?;
    let context = fixture.core.context_mut()?;
    fixture
        .coordinator
        .stage_rows(
            context,
            Vec::new(),
            PendingCommit::OutboxRequired { peer: PEER },
            Some(PEER),
        )
        .map_err(|error| format!("own batch: {error:?}"))?;
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, second);
    assert!(
        fixture.coordinator.parked_read.is_some(),
        "the completion waits"
    );
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert_eq!(fixture.coordinator.counters.violations, 0);
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert!(fixture.coordinator.parked_read.is_none());
    assert_eq!(fixture.finish_reads().await?, 3, "every body again");
    replied(&mut fixture).await
}
