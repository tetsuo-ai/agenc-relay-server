//! A real read, staged write, and receipt transfer the resident result separately from output.
#![forbid(unsafe_code)]
use super::*;

#[tokio::test]
async fn a_result_is_private_until_its_receipt_and_keeps_exact_resident_backing() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let budget = f.core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    let request = *ObjectId::compute(&f.complete.request).as_bytes();
    let before = f.executor()?.state.objects.len();
    f.submit()?;
    f.resolve().await?;
    assert!(f.coordinator.pending.is_some());
    assert!(!f.executor()?.state.results.contains_key(&request));
    assert_eq!(f.executor()?.state.objects.len(), before);
    assert!(budget.charged() > baseline);
    f.commit_pending().await?;
    let state = &f.executor()?.state;
    let result = &state
        .results
        .get(&request)
        .ok_or("committed result")?
        .result;
    let id = ObjectId::compute(result);
    let retained = state
        .object_memory
        .get(id.as_bytes())
        .ok_or("resident permit")?
        .bytes();
    assert_eq!(state.objects.get(id.as_bytes()), Some(result));
    assert_eq!(state.objects.len(), before + 1);
    assert!(!state.objects.contains_key(&f.object_id));
    assert_eq!(f.output().await?, vec![f.bytes.clone()]);
    assert_eq!(budget.charged(), baseline + retained);
    drop(f.coordinator);
    assert_eq!(budget.charged(), baseline);
    Ok(())
}

#[tokio::test]
async fn a_full_resident_counter_refuses_before_any_storage_submission() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let budget = f.core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    let sequence = f.next_sequence()?;
    let commit = f.core.context_mut()?.head().storage_commit_sequence;
    // Exercise the live adapter's limit result with a modeled full counter.
    // This fixture does not contain 256 MiB of resident objects.
    f.executor_mut()?.state.object_bytes = crate::e2ee::coordinator::MAX_RETAINED_OBJECT_BYTES;
    f.submit()?;
    f.resolve().await?;
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.next_sequence()?, sequence);
    assert_eq!(f.core.context_mut()?.head().storage_commit_sequence, commit);
    assert_eq!(f.handle.queued_bytes(), 0);
    assert_eq!(f.coordinator.counters.violations, 1);
    assert_eq!(budget.charged(), baseline);
    assert!(
        !f.executor()?
            .state
            .results
            .contains_key(ObjectId::compute(&f.complete.request).as_bytes())
    );
    Ok(())
}
