//! Failed preparation leaves the source stream and its existing body leases intact.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::{MemoryBudget, MemoryCharge};
use crate::test_support::TestResult;
use std::sync::Arc;

#[test]
fn a_prepared_stream_owns_a_separate_row_buffer_and_shares_only_its_bodies() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(1_048_576));
    let backing = BackingReservationPort::new(Arc::clone(&budget));
    let mut source = DeliveryStream::with_row_capacity(1, &backing)?;
    source.rows.push_back(StreamRow {
        sequence: 0,
        event_id: [0; 16],
        event: super::super::SharedBytes::copy_from(&[4; 1024], &backing)?,
        payload: None,
        acknowledgement:
            agenc_relay_storage::e2ee_records::delivery_recovery::Acknowledgement::Unacknowledged,
    });
    let available = budget.available();
    let prepared = source.try_clone(2, &backing)?;
    let expected =
        MemoryCharge::allocation(u64::try_from(3 * std::mem::size_of::<StreamRow>())?)?.bytes();
    assert_eq!(available - budget.available(), expected);
    assert!(std::ptr::eq(
        source.rows.front().ok_or("source")?.event.as_ptr(),
        prepared.rows.front().ok_or("prepared")?.event.as_ptr()
    ));
    assert!(!std::ptr::eq(
        source.rows.front().ok_or("source")?,
        prepared.rows.front().ok_or("prepared")?
    ));
    drop(prepared);
    assert_eq!(budget.available(), available);
    drop(source);
    assert_eq!(budget.available(), 1_048_576);
    Ok(())
}

#[test]
fn metadata_budget_refusal_does_not_publish_a_partially_copied_stream() -> TestResult {
    let charge =
        MemoryCharge::allocation(u64::try_from(std::mem::size_of::<StreamRow>())?)?.bytes();
    let budget = Arc::new(MemoryBudget::new(charge));
    let backing = BackingReservationPort::new(Arc::clone(&budget));
    let source = DeliveryStream::with_row_capacity(1, &backing)?;
    assert!(source.try_clone(1, &backing).is_err());
    assert!(source.rows.is_empty());
    assert_eq!(budget.available(), 0);
    drop(source);
    assert_eq!(budget.available(), charge);
    Ok(())
}
