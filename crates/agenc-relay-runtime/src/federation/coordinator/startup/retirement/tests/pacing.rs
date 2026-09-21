//! One fixed retry paces a determinate retryable refusal, and a retry that
//! cannot be scheduled fails closed rather than running unpaced.
#![forbid(unsafe_code)]

use super::*;

/// The candidate returns to the loader, exactly one fixed interval is
/// reserved, nothing is staged before it elapses, and the same write is
/// staged again once it has.
#[tokio::test]
async fn a_retryable_refusal_returns_the_candidate_and_paces_one_fixed_retry() -> TestResult {
    let mut staged = Staged::open().await?;
    let now = staged.now()?;
    staged.refuse(StorageError::QueueFull)?;
    assert!(!staged.coordinator.loader.failed);
    assert!(!staged.coordinator.loaded());
    assert_eq!(staged.coordinator.counters().violations, 0);
    assert!(staged.coordinator.loader.retirement.candidate.is_some());
    assert_eq!(
        staged.coordinator.loader.retirement.retry_at,
        now.checked_add(RETRY_MILLIS).ok_or("retry deadline")?
    );
    assert_eq!(
        staged.core.context_mut()?.head().storage_commit_sequence,
        staged.head
    );
    let context = staged.core.context_mut()?;
    assert!(!advance(&mut staged.coordinator, context));
    assert!(
        staged.coordinator.pending.is_none(),
        "the paced interval had not elapsed and the write was staged anyway"
    );
    assert!(staged.coordinator.loader.retirement.candidate.is_some());
    let deadline = staged.coordinator.loader.retirement.retry_at;
    staged.core.context_mut()?.set_monotonic_for_test(deadline);
    let context = staged.core.context_mut()?;
    assert!(!advance(&mut staged.coordinator, context));
    assert!(matches!(
        staged.coordinator.pending,
        Some(PendingCommit::CompanionRestore(_))
    ));
    assert!(staged.coordinator.loader.retirement.candidate.is_none());
    assert!(!staged.coordinator.loader.failed);
    Ok(())
}

/// The retryable set is exactly the six bounded refusals; every other
/// storage outcome, including each filesystem cause, is determinate.
#[test]
fn exactly_the_six_bounded_storage_refusals_are_retryable() -> TestResult {
    let paced = [
        StorageError::AllocationFailed,
        StorageError::QueueFull,
        StorageError::LimitExceeded,
        StorageError::DatabaseRejected,
        StorageError::AllowanceRefused(agenc_relay_storage::AllowancePhase::Preparation),
    ];
    let refused = [
        StorageError::InvalidEncoding,
        StorageError::UnsupportedVersion,
        StorageError::Overflow,
        StorageError::AuthenticationFailed,
        StorageError::StaleState,
        StorageError::Unavailable,
        StorageError::WriterLocked,
        StorageError::ResumeMismatch,
        StorageError::UnboundedRegion(4_294_967_296),
    ];
    for error in paced {
        assert!(retryable(error), "{error:?} must be paced");
    }
    for error in refused {
        assert!(!retryable(error), "{error:?} must fail the reload closed");
    }
    for cause in agenc_relay_storage::FilesystemCause::ALL {
        assert!(
            retryable(StorageError::FilesystemRejected(cause)),
            "{cause:?} must be paced"
        );
    }
    Ok(())
}

/// A monotonic reading within one retry interval of the ceiling cannot carry
/// a paced deadline. The owner refuses rather than retrying without pacing.
#[tokio::test]
async fn a_paced_retry_that_cannot_be_scheduled_fails_closed() -> TestResult {
    let mut staged = Staged::open().await?;
    staged.core.context_mut()?.set_monotonic_for_test(u64::MAX);
    staged.refuse(StorageError::QueueFull)?;
    staged.assert_failed_closed()?;
    assert_eq!(
        staged.coordinator.loader.retirement.retry_at, 0,
        "an unschedulable retry reserved an interval anyway"
    );
    assert!(
        staged.coordinator.loader.retirement.candidate.is_some(),
        "the returned candidate was dropped instead of being held"
    );
    Ok(())
}
