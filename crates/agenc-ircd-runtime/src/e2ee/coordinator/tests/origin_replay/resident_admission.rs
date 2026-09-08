//! Assembly must reserve resident result bytes before accepting a durable batch.
#![forbid(unsafe_code)]
use super::*;

#[test]
fn resident_result_admission_refuses_an_exhausted_process_budget() -> TestResult {
    let mut coordinator = coordinator();
    declare(&mut coordinator, 0)?;
    let decoded = decoded(0, 0)?;
    let budget = std::sync::Arc::new(crate::budget::MemoryBudget::new(0));
    let result = assemble(
        &coordinator,
        HOME,
        ServerId::from_bytes(HOME),
        &decoded,
        Outcome::scalar(request::ResultBody::Empty(EmptyKind::Identity)),
        1,
        500,
        None,
        BarrierInputs {
            backing: crate::budget::BackingReservationPort::new(budget),
            base_counts: None,
            base_capacity: &|_, _, _| true,
            entropy: &mut Entropy,
        },
    );
    assert!(
        matches!(result, Err(E2eeReplyCode::RateLimited)),
        "assembly accepted resident result bytes with no process memory available"
    );
    assert!(coordinator.state.results.is_empty());
    assert!(coordinator.state.replays.is_empty());
    Ok(())
}
