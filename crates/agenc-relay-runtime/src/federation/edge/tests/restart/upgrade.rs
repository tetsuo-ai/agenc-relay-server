#![forbid(unsafe_code)]

//! A missing edge checkpoint cannot authorize resume or barrier reconstruction.

use super::*;

fn rows_without_delivery_checkpoint(collecting: bool) -> TestResult<Vec<InitialStorageRecord>> {
    let mut rows = crash_rows(usize::from(collecting), false)?;
    if !collecting {
        rows.truncate(2);
    }
    rows.remove(1);
    Ok(rows)
}

#[tokio::test]
async fn missing_checkpoint_requires_base_and_companion_snapshots() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        rows_without_delivery_checkpoint(false)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    assert!(companion.needs_witness_snapshot());
    assert_eq!(base.installed_epoch, None);
    assert_eq!(base.companion_cursor(), (0, None));
    Ok(())
}

#[tokio::test]
async fn missing_checkpoint_refuses_barrier_recovery_without_deleting_records() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        rows_without_delivery_checkpoint(true)?,
    )?;
    let (mut base, mut companion) = edges();
    assert!(
        fixture
            .restore_edge_state(&mut base, Some(&mut companion))
            .is_err()
    );
    assert!(fixture.stored_row_exists(TableId::E2eeState, identity(2).head_key()?)?);
    assert!(fixture.stored_row_exists(TableId::E2eeState, identity(2).part_key(0)?)?);
    Ok(())
}
