//! Complete retained inventory and an incomplete cache have different admission rules.
#![forbid(unsafe_code)]

mod events;

use super::*;
use crate::test_support::TestResult;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::{
    ReplayOwner, ReplayOwnerFields,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    BarrierEndpoint, CutPhase, DeliveryBarrierFields, DeliveryCursor, DeliveryOwner,
    DeliveryRecoveryRow, LastAcknowledged, fixture_body,
};

fn inventory(first: u64, generation: u64) -> TestResult<(DeliveryStream, DeliveryBarrier)> {
    let DeliveryRecoveryRow::Owner(template) = DeliveryRecoveryRow::decode(&fixture_body(7)?)?
    else {
        return Err("owner".into());
    };
    let last = LastAcknowledged::At {
        sequence: 1,
        event_id: [8; 16],
    };
    let owner = DeliveryOwner::new(
        *template.scope(),
        DeliveryCursor::new(0, 2, last)?,
        *template.cut(),
        CutPhase::Ready,
    )?;
    let gate = DeliveryBarrier::new(DeliveryBarrierFields {
        scope: *owner.scope(),
        mutation_id: [9; 16],
        state_generation: 1,
        part_count: 3,
        base: BarrierEndpoint::new(0, 0, 0, [7; 16])?,
        companion: BarrierEndpoint::new(0, 0, 1, [8; 16])?,
        base_acked: false,
        companion_acked: true,
    })?;
    let replay = ReplayOwner::new(ReplayOwnerFields {
        scope: *owner.scope(),
        generation,

        through: 1,
        event_id: [8; 16],
        first_retained: first,
        retained_rows: 2 - first,
        retained_bytes: 2 - first,
        trusted_unix_seconds: None,
    })?;
    let stream = DeliveryStream {
        owner: Some(owner),
        next_sequence: 2,
        acked: Some((1, [8; 16])),
        replay: Some(super::super::replay::State {
            owner: replay,
            head: None,
        }),
        ..DeliveryStream::default()
    };
    Ok((stream, gate))
}

#[test]
fn an_acknowledged_gate_uses_the_complete_inventory_when_its_bodies_are_cold() -> TestResult {
    let (mut stream, gate) = inventory(0, 0)?;
    assert!(stream.rows.is_empty());
    validate_complete(&stream, &gate)?;
    stream.replay = None;
    assert!(validate_complete(&stream, &gate).is_err());
    Ok(())
}

#[test]
fn a_gate_cannot_use_a_different_generation_or_a_floor_inside_its_parts() -> TestResult {
    for (first, generation) in [(1, 0), (0, 1)] {
        let (stream, gate) = inventory(first, generation)?;
        assert!(validate_complete(&stream, &gate).is_err());
    }
    Ok(())
}

#[test]
fn an_unacknowledged_gate_still_requires_every_resident_part() -> TestResult {
    let (mut stream, acknowledged) = inventory(0, 0)?;
    stream.acked = None;
    let gate = DeliveryBarrier::new(DeliveryBarrierFields {
        scope: *acknowledged.scope(),
        mutation_id: acknowledged.mutation_id(),
        state_generation: acknowledged.state_generation(),
        part_count: acknowledged.part_count(),
        base: *acknowledged.base(),
        companion: *acknowledged.companion(),
        base_acked: false,
        companion_acked: false,
    })?;
    assert!(validate_complete(&stream, &gate).is_err());
    Ok(())
}

#[path = "fences.rs"]
mod fences;
