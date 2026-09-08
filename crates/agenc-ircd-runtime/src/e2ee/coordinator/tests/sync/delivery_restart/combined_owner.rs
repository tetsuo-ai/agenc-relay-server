//! Companion reconstruction retains an unfinished gate for base-stream validation.
#![forbid(unsafe_code)]

use super::*;
use acknowledged_barriers::{acknowledge_copy, append_barrier};
use agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    BarrierEndpoint, DeliveryBarrier, DeliveryBarrierFields, DeliveryRecoveryRow,
};

async fn reconstruct(base_acked: bool, companion_acked: bool) -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    acknowledge_copy(&mut fixture, 0).await?;
    acknowledge_copy(&mut fixture, 1).await?;
    append_barrier(&mut fixture).await?;
    if companion_acked {
        acknowledge_copy(&mut fixture, 1).await?;
    }
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("companion stream")?;
    let owner = stream.owner.as_ref().ok_or("delivery owner")?;
    let first = fixture.copies.first().ok_or("first companion part")?;
    let last = fixture.copies.last().ok_or("last companion part")?;
    let barrier = DeliveryBarrier::new(DeliveryBarrierFields {
        scope: *owner.scope(),
        mutation_id: [91; 16],
        state_generation: 42,
        part_count: 3,
        base: BarrierEndpoint::new(7, 20, 20, [93; 16])?,
        companion: BarrierEndpoint::new(
            stream.generation,
            first.row.sequence,
            last.row.sequence,
            last.row.event_id,
        )?,
        base_acked,
        companion_acked,
    })?;
    barrier.validate_for(owner, 7)?;
    let row = DeliveryRecoveryRow::Barrier(barrier);
    let key = row.key()?;
    let body = row.encode()?;
    assert_eq!(DeliveryRecoveryRow::decode_at(&key, &body)?, row);
    // Both committed endpoints release their gate. The other three cases
    // retain it for the outer coordinator's independent base-cursor checks.
    if !(base_acked && companion_acked) {
        let value = PersistentRecordValue::new(
            TableId::E2eeState,
            DELIVERY_RECOVERY_ROW_KIND,
            1,
            0,
            None,
            Vec::new(),
            body,
        )?;
        fixture
            .commit(vec![AccountServiceDurableWrite::put(
                TableId::E2eeState,
                key,
                value.encode()?,
            )?])
            .await?;
    }
    let expected_rows = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("stream")?
        .rows
        .clone();
    fixture.restart().await?;
    let restored = &fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("stream")?;
    assert_eq!(restored.rows, expected_rows);
    assert_eq!(restored.barrier, (!companion_acked).then_some((2, 3)));
    assert!(!fixture.coordinator.delivering(home()));
    Ok(())
}

#[tokio::test]
async fn a_gate_with_neither_acknowledgement_restores_the_companion_window() -> TestResult {
    Box::pin(reconstruct(false, false)).await
}

#[tokio::test]
async fn a_gate_with_only_base_acknowledgement_restores_the_companion_window() -> TestResult {
    Box::pin(reconstruct(true, false)).await
}

#[tokio::test]
async fn a_gate_with_only_companion_acknowledgement_preserves_its_replay_rows() -> TestResult {
    Box::pin(reconstruct(false, true)).await
}

#[tokio::test]
async fn both_acknowledgements_leave_no_gate_to_reconstruct() -> TestResult {
    Box::pin(reconstruct(true, true)).await
}
