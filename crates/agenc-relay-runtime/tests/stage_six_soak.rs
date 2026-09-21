#![forbid(unsafe_code)]

//! Deterministic bounded churn used by the Stage 06 CI gate. The seven-day
//! production soak remains assigned to S10-007.

use std::error::Error;
use std::time::Duration;

use agenc_relay_runtime::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort as _, MemoryCharge,
};
use agenc_relay_runtime::cancel::CancellationToken;
use agenc_relay_runtime::supervisor::{ChildKind, ChildName, Supervisor};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

const CHURN_ROUNDS: usize = 10_000;
const SUPERVISOR_BATCHES: usize = 100;
const CHILDREN_PER_BATCH: usize = 100;

#[test]
fn cancellation_and_memory_ownership_survive_deterministic_churn() -> TestResult {
    let root = CancellationToken::root();
    let budget = MemoryBudget::new(64 * 1024 * 1024);
    let charge = MemoryCharge::allocation(8_703)?;
    for _ in 0..CHURN_ROUNDS {
        let child = root.child()?;
        let permit = budget.try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?;
        assert_eq!(permit.total(), charge.bytes());
        drop(permit);
        drop(child);
    }
    assert_eq!(root.live_children(), 0);
    assert_eq!(budget.available(), budget.capacity());
    Ok(())
}

#[tokio::test]
async fn supervised_connection_batches_join_without_live_owners() -> TestResult {
    let mut joined = 0;
    for _ in 0..SUPERVISOR_BATCHES {
        let mut supervisor = Supervisor::new();
        for _ in 0..CHILDREN_PER_BATCH {
            supervisor.spawn(ChildName::Connection, ChildKind::Connection, |_| async {
                Ok(())
            })?;
        }
        let report = supervisor.join_all(Duration::from_secs(2)).await;
        assert_eq!(report.unfinished, 0);
        assert_eq!(report.exits.len(), CHILDREN_PER_BATCH);
        assert_eq!(supervisor.live_children(), 0);
        joined += report.exits.len();
    }
    assert_eq!(joined, CHURN_ROUNDS);
    Ok(())
}
