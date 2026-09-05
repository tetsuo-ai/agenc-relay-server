#![forbid(unsafe_code)]

//! Legacy delivery cursors cannot stand in for a durable chain witness.

use super::*;

fn legacy_rows(collecting: bool) -> TestResult<Vec<InitialStorageRecord>> {
    let mut rows = crash_rows(usize::from(collecting), false)?;
    if !collecting {
        rows.truncate(2);
    }
    let cursor = DeliveryRow::Cursor {
        generation: 1,
        next_sequence: 7,
        acked_sequence: 6,
        acked_event_id: [75; 16],
        barrier_open: collecting,
    };
    *rows.get_mut(1).ok_or("cursor row")? = record(
        TableId::E2eeState,
        DELIVERY_ROW_KIND,
        DeliveryRow::cursor_key(COORDINATOR.as_bytes())?,
        cursor.encode()?,
    )?;
    Ok(rows)
}

#[tokio::test]
async fn a_legacy_cursor_requires_fresh_base_and_companion_snapshots() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        legacy_rows(false)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    assert!(companion.needs_witness_snapshot());
    assert_eq!(base.installed_epoch, None);
    // Retain the sealed position for receipt checks, never as resume authority.
    assert_eq!(base.companion_cursor(), (1, Some((6, [75; 16]))));
    Ok(())
}

#[tokio::test]
async fn a_legacy_collecting_barrier_requires_stopped_recovery_without_deleting_its_head()
-> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        legacy_rows(true)?,
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
