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

#[test]
fn result_assembly_releases_abandoned_copies_and_retains_committed_copies() -> TestResult {
    let mut coordinator = coordinator();
    declare(&mut coordinator, 0)?;
    let decoded = decoded(0, 0)?;
    let budget = std::sync::Arc::new(crate::budget::MemoryBudget::new(1 << 20));
    for commit in [false, true] {
        let mut outcome = assemble(
            &coordinator,
            HOME,
            ServerId::from_bytes(HOME),
            &decoded,
            Outcome::scalar(request::ResultBody::Empty(EmptyKind::Identity)),
            1,
            500,
            None,
            BarrierInputs {
                backing: crate::budget::BackingReservationPort::new(budget.clone()),
                base_counts: None,
                base_capacity: &|_, _, _| true,
                entropy: &mut Entropy,
            },
        )
        .map_err(|e| format!("assembly: {e:?}"))?;
        assert!(coordinator.state.results.is_empty());
        assert!(budget.charged() > 0);
        if commit {
            for effect in outcome.effects.drain(..) {
                effect(&mut coordinator.state);
            }
        }
        drop(outcome);
        if commit {
            let object_charge: u64 = coordinator
                .state
                .object_memory
                .values()
                .map(|p| p.bytes())
                .sum();
            let value = coordinator
                .state
                .results
                .get(&decoded.request_object_id)
                .ok_or("result")?;
            assert!(budget.charged() >= object_charge + u64::try_from(value.result.capacity())?);
        } else {
            assert_eq!(budget.charged(), 0);
        }
    }
    drop(coordinator);
    assert_eq!(budget.charged(), 0);
    Ok(())
}
