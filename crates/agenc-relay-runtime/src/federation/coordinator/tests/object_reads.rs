//! An evicted object is read once, reauthorized, and published only after its receipt.
#![forbid(unsafe_code)]
mod failures;
mod fixture;
mod resident;
mod validation;
use super::*;
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::e2ee::coordinator::{CompanionCoordinator, CompleteRequest};
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::federation::frames::Correlation;
use fixture::Fixture;
const PEER: ServerId = ServerId::from_bytes([2; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([4; 16]);
const COORDINATOR: ServerId = ServerId::from_bytes([3; 16]);
const COORDINATOR_NAME: &str = "coordinator.example";

#[tokio::test]
async fn cold_fetch_stages_once_then_replays_the_same_body_without_caching_it() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let sequence = f.next_sequence()?;
    let head = f.core.context_mut()?.head().storage_commit_sequence;
    f.submit()?;
    assert!(!f.coordinator.reload_ready());
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.next_sequence()?, sequence);
    assert_eq!(f.handle.queued_bytes(), 0);
    f.resolve().await?;
    assert!(f.coordinator.pending.is_some());
    assert_eq!(f.next_sequence()?, sequence);
    assert_eq!(f.handle.queued_bytes(), 0);
    f.commit_pending().await?;
    assert_eq!(f.next_sequence()?, sequence + 1);
    assert_eq!(
        f.core.context_mut()?.head().storage_commit_sequence,
        head + 1
    );
    assert_eq!(f.output().await?, vec![f.bytes.clone()]);
    assert!(!f.executor()?.state.objects.contains_key(&f.object_id));
    f.submit()?;
    assert!(f.coordinator.companion_response_read.is_some());
    let message = f.next_read().await?;
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, message);
    assert_eq!(f.output().await?, vec![f.bytes.clone()]);
    assert_eq!(
        f.core.context_mut()?.head().storage_commit_sequence,
        head + 1
    );
    Ok(())
}

#[tokio::test]
async fn confirmed_absence_commits_an_empty_reply_without_a_second_read() -> TestResult {
    let mut f = Box::pin(Fixture::new(false)).await?;
    f.submit()?;
    f.resolve().await?;
    assert!(f.coordinator.pending.is_some());
    f.commit_pending().await?;
    assert!(f.output().await?.is_empty());
    assert!(f.coordinator.reload_ready());
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            f.core.next_storage_read()
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn changed_attachment_is_checked_again_after_the_read() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    f.submit()?;
    f.executor_mut()?
        .state
        .origins
        .values_mut()
        .next()
        .ok_or("origin")?
        .device = None;
    f.resolve().await?;
    f.commit_pending().await?;
    assert!(f.output().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn pending_recovery_hides_the_loaded_commit_before_staging() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    f.submit()?;
    let conversation = agenc_relay_domain::e2ee::ConversationId(f.conversation);
    let mut route = *f
        .executor()?
        .state
        .routes
        .route(&conversation)
        .ok_or("route")?;
    route.recovery = agenc_relay_domain::e2ee::RecoveryState::Pending;
    f.executor_mut()?.state.routes.restore_entry(route);
    f.resolve().await?;
    f.commit_pending().await?;
    assert!(f.output().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn failed_storage_cannot_commit_an_empty_result() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let sequence = f.next_sequence()?;
    f.submit()?;
    let mut message = f.next_read().await?;
    message.result = Err(agenc_relay_storage::StorageError::Unavailable);
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, message);
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.handle.queued_bytes(), 0);
    assert_eq!(f.next_sequence()?, sequence);
    assert_eq!(f.coordinator.counters.violations, 1);
    Ok(())
}

#[tokio::test]
async fn wrong_completion_id_keeps_ownership_until_the_real_completion() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    f.submit()?;
    let message = f.next_read().await?;
    let id = message.read_id;
    f.coordinator.storage_read_completed(
        f.core.context_mut()?,
        StorageReadCompletionMessage {
            read_id: StorageReadId::new(id.get() + 1),
            result: Err(agenc_relay_storage::StorageError::Unavailable),
        },
    );
    assert!(f.coordinator.owns_storage_read(id));
    assert!(f.coordinator.pending.is_none());
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, message);
    f.commit_pending().await?;
    assert_eq!(f.output().await?, vec![f.bytes.clone()]);
    Ok(())
}
