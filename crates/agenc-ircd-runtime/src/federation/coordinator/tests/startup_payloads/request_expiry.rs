//! Completed request retention has a durable origin floor independent of its result.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::request::{self, Outcome, ResultBody};
use crate::e2ee::coordinator::{CompanionOriginKey, CompleteRequest};
use agenc_ircd_domain::e2ee::projection::EmptyKind;
use agenc_ircd_e2ee::federation::frames::Correlation;
use agenc_ircd_e2ee::objects::federation::{IrcFederationOpcode, IrcFederationRequest};
use agenc_ircd_e2ee::tls::Opaque;
use agenc_ircd_storage::e2ee_records::ReplayKey;
use agenc_ircd_storage::e2ee_records::origin::OriginSequenceRow;

mod cases;
mod fixture;
mod result_memory;
use fixture::Fixture;

#[tokio::test]
async fn idle_maintenance_retires_an_expired_request_result_but_keeps_its_origin_floor()
-> TestResult {
    let mut f = Fixture::new(true).await?;
    let executor = f.coordinator.companion_executor().ok_or("executor")?;
    assert!(executor.state.replays.contains_key(&f.key));
    assert!(executor.state.results.contains_key(&f.request_object_id));
    assert!(executor.state.objects.contains_key(&f.result_id));
    f.idle()?;
    assert!(
        f.coordinator.pending.is_some(),
        "idle maintenance retained an expired request result and its replay row"
    );
    let budget = f.core.context_mut()?.backing_budget_for_test();
    let staged_charge = budget.charged();
    f.coordinator.batch_applied(f.core.context_mut()?);
    assert!(f.coordinator.pending.is_some());
    f.core.commit_staged_batch().await?;
    assert!(f.executor()?.state.replays.contains_key(&f.key));
    assert!(
        f.executor()?
            .state
            .results
            .contains_key(&f.request_object_id)
    );
    f.coordinator.batch_applied(f.core.context_mut()?);
    assert!(f.coordinator.loaded());
    assert!(!f.executor()?.state.replays.contains_key(&f.key));
    assert!(
        !f.executor()?
            .state
            .results
            .contains_key(&f.request_object_id)
    );
    assert!(!f.executor()?.state.objects.contains_key(&f.result_id));
    assert!(budget.charged() < staged_charge);
    assert!(
        f.stored(
            TableId::E2eeState,
            agenc_ircd_storage::e2ee_records::ReplayRow::key(&f.key)?
        )
        .await?
        .is_none()
    );
    let floor = f
        .stored(TableId::E2eeState, f.floor_key()?)
        .await?
        .ok_or("floor")?;
    assert_eq!(OriginSequenceRow::decode(floor.body())?.next_sequence, 1);
    let body = f
        .stored(
            TableId::E2eeObject,
            agenc_ircd_storage::StoredKey::new(f.result_id.to_vec())?,
        )
        .await?
        .ok_or("retained body")?;
    let bytes = agenc_ircd_storage::e2ee_records::ObjectRow::decode(body.body())?.bytes;
    assert_eq!(ObjectId::compute(&bytes).as_bytes(), &f.result_id);
    f.restart().await?;
    assert!(f.executor()?.state.replays.is_empty());
    assert!(f.executor()?.state.results.is_empty());
    assert!(!f.executor()?.state.objects.contains_key(&f.result_id));
    Ok(())
}

#[tokio::test]
async fn startup_does_not_warm_a_result_without_a_retained_replay_owner() -> TestResult {
    let f = Fixture::new(false).await?;
    let executor = f.coordinator.companion_executor().ok_or("executor")?;
    assert!(executor.state.replays.is_empty());
    assert!(executor.state.results.is_empty());
    assert!(
        !executor.state.objects.contains_key(&f.result_id),
        "startup warmed an orphaned request result after its replay owner was retired"
    );
    Ok(())
}
