//! Persistent result copies need their own charge beyond retained object bodies.
#![forbid(unsafe_code)]
use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use agenc_ircd_storage::e2ee_records::ReplayRow;
use std::sync::Arc;

async fn restored(
    fixture: &mut Fixture,
    backing: BackingReservationPort,
) -> TestResult<CompanionCoordinator> {
    let mut fresh = CompanionCoordinator::new(
        *fixture.core.identity.network_id.as_bytes(),
        fixture.core.identity.server_id,
        "server.example".into(),
    );
    fresh.configure_delivery_identity(
        fixture.core.identity.server_incarnation,
        fixture.core.identity.recovery_epoch,
    )?;
    let source = fixture.executor()?;
    let keys = source
        .state
        .replays
        .keys()
        .map(ReplayRow::key)
        .collect::<Result<Vec<_>, _>>()?;
    let objects = source
        .state
        .objects
        .keys()
        .map(agenc_ircd_storage::e2ee_records::object_key)
        .collect::<Result<Vec<_>, _>>()?;
    for key in keys.into_iter().chain([fixture.floor_key()?]) {
        let value = fixture
            .stored(TableId::E2eeState, key.clone())
            .await?
            .ok_or("metadata")?;
        fresh.admit_restored_with_backing(TableId::E2eeState, &key, &value, &backing);
    }
    fresh.select_restored_objects(backing.clone())?;
    for key in objects {
        let value = fixture
            .stored(TableId::E2eeObject, key.clone())
            .await?
            .ok_or("object")?;
        fresh.admit_restored_with_backing(TableId::E2eeObject, &key, &value, &backing);
    }
    fresh.finish_restore_with_backing(backing)?;
    Ok(fresh)
}

#[tokio::test]
async fn sealed_replay_results_reserve_their_second_persistent_body_copy() -> TestResult {
    let mut fixture = Box::pin(Fixture::many(3, true)).await?;
    let budget = Arc::new(MemoryBudget::new(16 * 1024 * 1024));
    let fresh = restored(&mut fixture, BackingReservationPort::new(budget.clone())).await?;
    assert_eq!(fresh.state.results.len(), 3);
    let object_charge: u64 = fresh
        .state
        .object_memory
        .values()
        .map(|permit| permit.bytes())
        .sum();
    let result_bytes: usize = fresh
        .state
        .results
        .values()
        .map(|result| result.result.capacity() + result.responses.capacity() * 32)
        .sum();
    assert!(result_bytes > 0);
    assert!(
        budget.charged() >= object_charge + u64::try_from(result_bytes)?,
        "persistent result copies have no separate charge: charged={}, object_charge={object_charge}, result_bytes={result_bytes}",
        budget.charged()
    );
    drop(fresh);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[tokio::test]
async fn result_rebuild_refusal_releases_partial_results_and_object_backing() -> TestResult {
    let mut fixture = Box::pin(Fixture::many(3, true)).await?;
    // Three object permits plus temporary selection fit; three persistent
    // result copies also need backing after selection releases its temporary map.
    let budget = Arc::new(MemoryBudget::new(24_576));
    let result = restored(&mut fixture, BackingReservationPort::new(budget.clone())).await;
    let error = result
        .err()
        .ok_or("uncharged results bypassed the memory ceiling")?;
    assert!(matches!(
        error.downcast_ref::<crate::e2ee::coordinator::CompanionFault>(),
        Some(crate::e2ee::coordinator::CompanionFault::Ceiling)
    ));
    assert_eq!(budget.charged(), 0);
    Ok(())
}
