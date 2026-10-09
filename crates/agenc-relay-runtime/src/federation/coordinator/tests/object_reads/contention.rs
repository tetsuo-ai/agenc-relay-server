//! A commit landing during a fresh object read never fails the link: no
//! other router writes companion rows, the completion waits while a batch
//! is open, and a batch of the coordinator's own runs the request again.
#![forbid(unsafe_code)]
use super::*;
use crate::state_core::durable::AccountServiceDurableWrite;

/// A row another router could write: the edge's federation peer row.
fn other_row(f: &mut Fixture) -> TestResult<AccountServiceDurableWrite> {
    let revision = f
        .core
        .context_mut()?
        .domain()
        .plan_account_service_checkpoint()?
        .resulting_revision()
        .get();
    Ok(f.coordinator.peer_row_at(PEER, revision, None)?)
}

/// Stages a batch another router could stage; the coordinator's own slot
/// stays free.
fn open_other_batch(f: &mut Fixture) -> TestResult {
    let write = other_row(f)?;
    let context = f.core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    context
        .stage_durable_with_account_service(
            plan,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            vec![write],
        )
        .map_err(|error| format!("other batch: {error:?}"))?;
    assert!(f.coordinator.pending.is_none());
    Ok(())
}

/// Commits the open batch and runs the coordinator's receipt.
async fn settle(f: &mut Fixture) -> TestResult {
    f.core.commit_staged_batch().await?;
    f.coordinator.batch_applied(f.core.context_mut()?);
    Ok(())
}

/// Commits the request's batch and checks its answer, one operation
/// sequence on, with the link up.
async fn answered(f: &mut Fixture, sequence: u64) -> TestResult {
    assert!(
        f.coordinator.pending.is_some(),
        "the request staged its batch"
    );
    f.commit_pending().await?;
    assert_eq!(f.next_sequence()?, sequence + 1);
    assert_eq!(f.output().await?, vec![f.bytes.clone()]);
    assert!(f.coordinator.link_is_live(LinkId::new(1), PEER));
    assert_eq!(f.coordinator.counters.violations, 0);
    Ok(())
}

/// A commit another router makes during the read leaves it current: the
/// request runs with the object it read, without a second read.
#[tokio::test]
async fn a_commit_of_another_router_during_an_object_read_leaves_it_current() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let sequence = f.next_sequence()?;
    f.submit()?;
    let message = f.next_read().await?;
    let read_at = message
        .result
        .as_ref()
        .map_err(|e| format!("read: {e:?}"))?
        .storage_commit_sequence;
    let write = other_row(&mut f)?;
    fixture::commit(&mut f.core, vec![write]).await?;
    f.coordinator.batch_applied(f.core.context_mut()?);
    assert!(f.core.context_mut()?.head().storage_commit_sequence > read_at);
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, message);
    assert!(f.coordinator.companion_object_read.is_none());
    answered(&mut f, sequence).await
}

/// A completion that finds another router's batch open waits for it; that
/// batch's receipt runs the request with the object it read.
#[tokio::test]
async fn an_object_read_completing_while_another_router_has_a_batch_open_waits_for_it() -> TestResult
{
    let mut f = Box::pin(Fixture::new(true)).await?;
    let sequence = f.next_sequence()?;
    f.submit()?;
    let message = f.next_read().await?;
    open_other_batch(&mut f)?;
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, message);
    assert!(f.coordinator.parked_read.is_some(), "the completion waits");
    assert!(f.coordinator.companion_object_read.is_some());
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.handle.queued_bytes(), 0);
    assert_eq!(f.coordinator.counters.violations, 0);
    settle(&mut f).await?;
    assert!(f.coordinator.parked_read.is_none());
    assert!(f.coordinator.companion_object_read.is_none());
    answered(&mut f, sequence).await
}

/// A batch of the coordinator's own that commits during the read may have
/// changed the object it read: the completion waits for that batch, and
/// its receipt runs the request again, which reads the object again.
#[tokio::test]
async fn an_own_commit_during_an_object_read_runs_its_request_again() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let sequence = f.next_sequence()?;
    f.submit()?;
    let first = f.next_read().await?;
    let context = f.core.context_mut()?;
    f.coordinator
        .stage_rows(
            context,
            Vec::new(),
            PendingCommit::OutboxRequired { peer: PEER },
            Some(PEER),
        )
        .map_err(|error| format!("own batch: {error:?}"))?;
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, first);
    assert!(f.coordinator.parked_read.is_some(), "the completion waits");
    assert_eq!(f.coordinator.counters.violations, 0);
    settle(&mut f).await?;
    assert!(f.coordinator.parked_read.is_none());
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.next_sequence()?, sequence);
    f.resolve().await?;
    answered(&mut f, sequence).await
}

/// A refused batch of the coordinator's own changed nothing: the waiting
/// completion runs the request with the object it read.
#[tokio::test]
async fn an_object_read_behind_a_refused_batch_of_its_own_keeps_its_object() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let sequence = f.next_sequence()?;
    f.submit()?;
    let first = f.next_read().await?;
    let context = f.core.context_mut()?;
    f.coordinator
        .stage_rows(
            context,
            Vec::new(),
            PendingCommit::OutboxRequired { peer: PEER },
            Some(PEER),
        )
        .map_err(|error| format!("own batch: {error:?}"))?;
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, first);
    assert!(f.coordinator.parked_read.is_some(), "the completion waits");
    f.core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    f.coordinator.batch_rejected(f.core.context_mut()?);
    assert!(f.coordinator.parked_read.is_none());
    assert!(f.coordinator.companion_object_read.is_none());
    answered(&mut f, sequence).await
}

/// A completion that arrives while the coordinator quiesces is settled at
/// once, even while another router's batch is open: nothing waits, and the
/// read's reservation is released.
#[tokio::test]
async fn a_completion_while_quiescing_settles_at_once_behind_another_batch() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let budget = f.core.context_mut()?.backing_budget_for_test();
    f.submit()?;
    let message = f.next_read().await?;
    open_other_batch(&mut f)?;
    f.core.context_mut()?.quiesce_for_test();
    let charged = budget.charged();
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, message);
    assert!(f.coordinator.parked_read.is_none(), "nothing waits");
    assert!(
        budget.charged() < charged,
        "the read's reservation is released"
    );
    assert!(f.coordinator.companion_object_read.is_none());
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.handle.queued_bytes(), 0);
    assert_eq!(f.coordinator.counters.violations, 0);
    Ok(())
}
