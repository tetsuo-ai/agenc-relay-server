//! Wrong, stale and indeterminate boundaries fail the reload closed.
#![forbid(unsafe_code)]

use super::*;

/// The durable rows one restored startup write would stage.
fn writes(
    candidate: &RestoredWrite,
) -> TestResult<Vec<crate::state_core::durable::AccountServiceDurableWrite>> {
    candidate
        .writes()
        .map_err(|fault| format!("candidate writes: {fault:?}").into())
}

/// The batch actually reached the log while the owner was told it did not.
/// Returning the candidate there would stage the same row twice, so the
/// receipt is refused although the refusal itself is retryable.
#[tokio::test]
async fn a_receipt_taken_at_a_moved_durable_head_fails_closed_even_when_retryable() -> TestResult {
    let mut staged = Staged::open().await?;
    staged.core.commit_staged_batch().await?;
    let moved = staged.core.context_mut()?.head().storage_commit_sequence;
    assert_eq!(moved, staged.head.checked_add(1).ok_or("head")?);
    let context = staged.core.context_mut()?;
    staged
        .coordinator
        .batch_rejected_with_error(context, StorageError::QueueFull);
    assert!(staged.coordinator.pending.is_none());
    assert!(staged.coordinator.loader.failed);
    assert!(!staged.coordinator.loaded());
    assert_eq!(staged.coordinator.counters().violations, 1);
    assert!(staged.coordinator.loader.retirement.candidate.is_none());
    assert_eq!(staged.coordinator.loader.retirement.retry_at, 0);
    assert_eq!(
        staged.core.context_mut()?.head().storage_commit_sequence,
        moved
    );
    Ok(())
}

/// The pinned commit is the revision every startup pass must observe. A
/// receipt that no longer matches it is refused before the candidate returns.
#[tokio::test]
async fn a_receipt_whose_pinned_revision_moved_fails_closed_even_when_retryable() -> TestResult {
    let mut staged = Staged::open().await?;
    staged.coordinator.loader.pinned_commit = Some(staged.head.checked_add(1).ok_or("pin")?);
    staged.refuse(StorageError::QueueFull)?;
    staged.assert_failed_closed()?;
    assert!(staged.coordinator.loader.retirement.candidate.is_none());
    assert_eq!(staged.coordinator.loader.retirement.retry_at, 0);
    Ok(())
}

/// A stale receipt arriving while the loader already holds a candidate must
/// not replace it: the held candidate is the one the next pass will stage.
#[tokio::test]
async fn a_loader_already_holding_a_candidate_refuses_a_second_receipt() -> TestResult {
    let mut staged = Staged::open().await?;
    // The receipt's own candidate carries durable rows, which is why the
    // reload staged it instead of applying it at once; this one carries none,
    // so the two are told apart by what they would write.
    let held: Box<Reconciliation> = Box::default();
    assert!(writes(&RestoredWrite::Signers(held.clone()))?.is_empty());
    staged.coordinator.loader.retirement.candidate = Some(RestoredWrite::Signers(held));
    staged.refuse(StorageError::QueueFull)?;
    staged.assert_failed_closed()?;
    let kept = staged
        .coordinator
        .loader
        .retirement
        .candidate
        .as_ref()
        .ok_or("the candidate the loader already held")?;
    assert!(
        writes(kept)?.is_empty(),
        "the refusal replaced the candidate the loader already held"
    );
    assert_eq!(staged.coordinator.loader.retirement.retry_at, 0);
    Ok(())
}

/// Without an executor the candidate cannot be confirmed against live state,
/// so its disposition is indeterminate and the reload fails closed.
#[tokio::test]
async fn an_executor_that_cannot_confirm_the_candidate_fails_closed() -> TestResult {
    let mut staged = Staged::open().await?;
    let executor = staged.coordinator.companion_exec.take();
    assert!(executor.is_some());
    staged.refuse(StorageError::QueueFull)?;
    staged.assert_failed_closed()?;
    assert!(staged.coordinator.loader.retirement.candidate.is_none());
    assert_eq!(staged.coordinator.loader.retirement.retry_at, 0);
    Ok(())
}

/// A refusal outside the retryable set is determinate or indeterminate, never
/// paced: the reload fails closed and the candidate is not returned.
#[tokio::test]
async fn an_unretryable_storage_refusal_fails_the_reload_closed() -> TestResult {
    for error in [
        StorageError::Unavailable,
        StorageError::AuthenticationFailed,
        StorageError::StaleState,
    ] {
        let mut staged = Staged::open().await?;
        staged.refuse(error)?;
        staged.assert_failed_closed()?;
        assert!(
            staged.coordinator.loader.retirement.candidate.is_none(),
            "{error:?} returned a candidate the owner may not restage"
        );
        assert_eq!(staged.coordinator.loader.retirement.retry_at, 0);
    }
    Ok(())
}
