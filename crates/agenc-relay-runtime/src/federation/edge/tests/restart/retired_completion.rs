#![forbid(unsafe_code)]

//! A retained barrier does not recreate an absent request's completion owner.

use super::*;

#[tokio::test]
async fn a_barrier_completion_without_a_request_waits_for_the_joint_receipt() -> TestResult {
    let (header, _) = request_fixture()?;
    let mut fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        completion_rows(&header)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    let mut queue = resync_snapshot_link(&mut base);
    base.phase = Phase::Origins;
    assert!(base.pending.is_empty());
    let (writes, outputs) = companion
        .prepare_barrier(fixture.context_mut()?, &base, MUTATION)
        .map_err(|error| error.to_string())?;
    assert!(outputs.is_empty());
    assert!(base.apply_barrier(fixture.context_mut()?, writes, outputs));
    assert!(
        matches!(base.commit, Some(PendingCommit::BarrierApplied { .. })),
        "the barrier rejected a completion whose request was already retired"
    );
    assert!(base.cursor.is_none());
    assert!(!base.barrier_applied(&MUTATION));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv())
            .await
            .is_err(),
        "joint ACK escaped before storage"
    );
    assert!(
        commit_edge_batches(&mut base, &mut fixture)
            .await?
            .is_empty()
    );
    assert!(base.barrier_applied(&MUTATION));
    assert_eq!(base.cursor.map(|cursor| cursor.0), Some(0));
    assert!(base.pending.is_empty());
    assert!(base.applied_completions.is_empty());
    assert!(base.by_completion.is_empty());
    let (mut reloaded, mut reloaded_companion) = edges();
    fixture.restore_edge_state(&mut reloaded, Some(&mut reloaded_companion))?;
    assert!(reloaded.barrier_applied(&MUTATION));
    assert_eq!(reloaded.cursor, base.cursor);
    assert!(reloaded.pending.is_empty());
    Ok(())
}
