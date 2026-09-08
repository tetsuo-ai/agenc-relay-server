//! A delivery copy cannot outlive the reservation for its shared allocation.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::{MemoryBudget, MemoryCharge};
use crate::test_support::TestResult;

#[test]
fn clones_keep_the_same_allocation_charged_until_the_last_copy_is_dropped() -> TestResult {
    let charge = MemoryCharge::allocation(u64::try_from(allocation_capacity(1024)?)?)?;
    let budget = Arc::new(MemoryBudget::new(charge.bytes()));
    let backing = BackingReservationPort::new(Arc::clone(&budget));
    let first = SharedBytes::copy_from(&[31; 1024], &backing)?;
    let second = first.clone();
    assert!(std::ptr::eq(first.as_ptr(), second.as_ptr()));
    assert_eq!(budget.available(), 0);
    drop(first);
    assert_eq!(budget.available(), 0);
    assert_eq!(second.first(), Some(&31));
    drop(second);
    assert_eq!(budget.available(), charge.bytes());
    Ok(())
}

#[test]
fn insufficient_global_backing_refuses_a_new_body_and_returns_the_reservation() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(1024));
    let backing = BackingReservationPort::new(Arc::clone(&budget));
    assert!(SharedBytes::copy_from(&[21; 1024], &backing).is_err());
    assert!(SharedBytes::from_owned(vec![21; 1024], &backing).is_err());
    assert_eq!(budget.available(), 1024);
    Ok(())
}
