//! Allocation ownership tests; these arbitrary bytes are not protocol validation fixtures.
#![forbid(unsafe_code)]
use super::*;
use crate::budget::MemoryBudget;
use std::sync::Arc;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn prepared_result_keeps_its_vectors_and_permit_until_commit_or_drop() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(16_384));
    let backing = BackingReservationPort::new(budget.clone());
    let body = vec![42; MAX_RESULT_BYTES];
    let responses = [[7; 32]; MAX_RESPONSES];
    let mut store = Store::default();
    for commit in [false, true] {
        let prepared = Prepared::capture(&body, responses.into_iter(), &backing)?;
        assert_eq!(budget.charged(), 16_384);
        assert!(store.is_empty());
        if commit {
            prepared.apply(&mut store, [1; 32]);
            let value = store.get(&[1; 32]).ok_or("result")?;
            assert_eq!(value.result, body);
            assert_eq!(value.responses, responses);
            assert_eq!(budget.charged(), 16_384);
            store.remove(&[1; 32]);
        } else {
            drop(prepared);
        }
        assert_eq!(budget.charged(), 0);
    }
    Ok(())
}

#[test]
fn replacement_requires_overlap_backing_and_releases_the_previous_owner() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(16_384));
    let backing = BackingReservationPort::new(budget.clone());
    let mut store = Store::default();
    Prepared::capture(&[1, 2], std::iter::empty(), &backing)?.apply(&mut store, [1; 32]);
    assert_eq!(budget.charged(), 8192);
    let held = backing.reserve(1)?;
    assert!(Prepared::capture(&[3, 4], std::iter::empty(), &backing).is_err());
    assert_eq!(store.get(&[1; 32]).ok_or("old")?.result, [1, 2]);
    drop(held);
    let replacement = Prepared::capture(&[3, 4], std::iter::empty(), &backing)?;
    assert_eq!(budget.charged(), 16_384);
    replacement.apply(&mut store, [1; 32]);
    assert_eq!(budget.charged(), 8192);
    assert_eq!(store.get(&[1; 32]).ok_or("replacement")?.result, [3, 4]);
    drop(store);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn oversized_result_or_descriptor_count_is_refused_before_allocation() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(1 << 20));
    let backing = BackingReservationPort::new(budget.clone());
    assert!(
        Prepared::capture(&vec![1; MAX_RESULT_BYTES + 1], std::iter::empty(), &backing).is_err()
    );
    assert!(Prepared::capture(&[1], [[1; 32]; MAX_RESPONSES + 1].into_iter(), &backing).is_err());
    assert_eq!(budget.charged(), 0);
    Ok(())
}
