//! Post-receipt clock and allocation failures retain the exact committed cut.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_storage::e2ee_records::delivery_recovery::{DeliveryOwner, RetirementReason};

async fn committed_unpublished_owner() -> TestResult<(
    RestartFixture,
    Box<crate::e2ee::coordinator::sync::SnapshotPublication>,
    DeliveryOwner,
)> {
    let mut fixture = unstarted().await?;
    let actions = initial_frame(&mut fixture)?;
    let actions = fixture.commit_cut_stage(actions).await?;
    let DeliveryRecoveryRow::Owner(expected) = row_in(&actions)? else {
        return Err("exact Owner after immutable page receipt".into());
    };
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("Owner stage".into());
    };
    fixture.coordinator.set_pending(work);
    fixture.commit(writes).await?;
    let Some(Committed::Snapshot(publication)) = fixture.coordinator.batch_applied(Some(0))? else {
        return Err("matching Owner receipt".into());
    };
    Ok((fixture, publication, expected))
}

fn retained(fixture: &RestartFixture, expected: &DeliveryOwner) -> TestResult {
    assert_eq!(
        fixture
            .coordinator
            .state
            .streams
            .get(&home())
            .and_then(|stream| stream.owner.as_ref()),
        Some(expected)
    );
    let snapshot = fixture
        .coordinator
        .peer_sync(home())
        .and_then(|sync| sync.snapshot.as_ref())
        .ok_or("committed Pending cut must remain retained")?;
    assert_eq!(snapshot.cut.token, expected.cut().token());
    assert_eq!(snapshot.scope, *expected.scope());
    assert_eq!(snapshot.capture.page_count(), 1);
    assert_eq!(snapshot.capture.cursor(0), None);
    assert_eq!(snapshot.pages_sent, 1);
    assert!(!fixture.coordinator.delivering(home()));
    Ok(())
}

#[tokio::test]
async fn clock_loss_after_owner_receipt_retains_pending_cut_without_begin() -> TestResult {
    let (mut fixture, publication, expected) = committed_unpublished_owner().await?;
    fixture.host.clock = Err(RetirementReason::ClockScopeLost);
    let actions = fixture.coordinator.continue_snapshot_publication(
        *publication,
        NOW_MILLIS,
        &fixture.host,
    )?;
    assert!(actions.is_empty());
    retained(&fixture, &expected)?;
    assert_eq!(
        fixture
            .coordinator
            .peer_sync(home())
            .and_then(|sync| sync.snapshot.as_ref())
            .and_then(|snapshot| snapshot.retirement),
        Some(RetirementReason::ClockScopeLost)
    );
    Ok(())
}

#[tokio::test]
async fn output_allocation_refusal_after_owner_receipt_keeps_the_exact_pending_cut() -> TestResult {
    let (mut fixture, publication, expected) = committed_unpublished_owner().await?;
    fixture.host.backing = crate::budget::BackingReservationPort::new(crate::sync::Arc::new(
        crate::budget::MemoryBudget::new(0),
    ));
    assert!(matches!(
        fixture
            .coordinator
            .continue_snapshot_publication(*publication, NOW_MILLIS, &fixture.host),
        Err(CompanionFault::Ceiling)
    ));
    retained(&fixture, &expected)?;
    assert_eq!(
        fixture
            .coordinator
            .peer_sync(home())
            .and_then(|sync| sync.snapshot.as_ref())
            .and_then(|snapshot| snapshot.retirement),
        None
    );
    Ok(())
}
