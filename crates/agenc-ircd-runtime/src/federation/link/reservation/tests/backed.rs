//! Shared page backing follows every accepted frame and is refunded on refusal.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::test_support::TestResult;

const BUDGET: u64 = 1 << 20;

fn line() -> TestResult<FederationLineText> {
    Ok(FederationLineText::from_rendered(
        ":edge FPONG :page\r\n".to_owned(),
    )?)
}

fn backing(budget: &Arc<MemoryBudget>) -> TestResult<Arc<MemoryPermit>> {
    Ok(Arc::new(
        BackingReservationPort::new(Arc::clone(budget)).reserve(262_144)?,
    ))
}

#[test]
fn shared_page_backing_survives_partial_byte_refusal_until_accepted_frames_drop() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(BUDGET));
    let bytes = u64::try_from(line()?.len())?;
    let (handle, queue) = super::super::link_queue(bytes);
    let permit = backing(&budget)?;
    let charged = budget.charged();
    handle.try_send_backed(line()?, Arc::clone(&permit))?;
    assert_eq!(
        handle.try_send_backed(line()?, Arc::clone(&permit)),
        Err(SendRefusal::QueueFull)
    );
    drop(permit);
    assert_eq!(handle.queued_bytes(), bytes);
    assert_eq!(budget.charged(), charged);
    drop(queue);
    assert_eq!(handle.queued_bytes(), 0);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn shared_page_backing_survives_item_refusal_and_refunds_on_queue_drop() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(BUDGET));
    let (handle, queue) = super::super::link_queue(BUDGET);
    let permit = backing(&budget)?;
    let charged = budget.charged();
    for _ in 0..super::super::OUTBOUND_QUEUE_ITEMS {
        handle.try_send_backed(line()?, Arc::clone(&permit))?;
    }
    assert_eq!(
        handle.try_send_backed(line()?, Arc::clone(&permit)),
        Err(SendRefusal::QueueFull)
    );
    let expected =
        u64::try_from(line()?.len())? * u64::try_from(super::super::OUTBOUND_QUEUE_ITEMS)?;
    assert_eq!(handle.queued_bytes(), expected);
    drop(permit);
    assert_eq!(budget.charged(), charged);
    drop(queue);
    assert_eq!(handle.queued_bytes(), 0);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn closed_or_too_small_page_queues_release_their_only_output_owner() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(BUDGET));
    let (handle, queue) = super::super::link_queue(BUDGET);
    drop(queue);
    assert_eq!(
        handle.try_send_backed(line()?, backing(&budget)?),
        Err(SendRefusal::Closed)
    );
    assert_eq!(handle.queued_bytes(), 0);
    assert_eq!(budget.charged(), 0);
    let (handle, _queue) = super::super::link_queue(1);
    assert_eq!(
        handle.try_send_backed(line()?, backing(&budget)?),
        Err(SendRefusal::QueueFull)
    );
    assert_eq!(handle.queued_bytes(), 0);
    assert_eq!(budget.charged(), 0);
    Ok(())
}
