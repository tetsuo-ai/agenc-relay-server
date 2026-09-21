#![forbid(unsafe_code)]

//! A stored barrier part must agree with the event it carries and with this edge's identity.

use super::*;
use crate::federation::edge::startup::EdgeRestoreStep;

type PartEdit = fn(&mut BarrierPart);
type ConfigEdit = fn(&mut EdgeFederation);

/// The crash image of one collected base part, with that part edited after the head sealed it.
fn rows_with(edit: PartEdit) -> TestResult<Vec<InitialStorageRecord>> {
    let mut rows = crash_rows(1, false)?;
    let (parts, _) = parts()?;
    let mut part = parts.into_iter().next().ok_or("base part")?;
    let key = part.identity.part_key(part.part_index)?;
    edit(&mut part);
    // `crash_rows(1, _)` writes the peer, the cursor, this part, then the head.
    let tampered = record(TableId::E2eeState, BARRIER_ROW_KIND, key, part.encode()?)?;
    *rows.get_mut(2).ok_or("part row")? = tampered;
    Ok(rows)
}

fn refused_step(
    rows: Vec<InitialStorageRecord>,
    config: ConfigEdit,
) -> TestResult<Option<EdgeRestoreStep>> {
    let fixture = StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    let (mut base, mut companion) = edges();
    config(&mut base);
    let refusal = fixture.restore_edge_refusal(&mut base, Some(&mut companion))?;
    assert_eq!(base.barrier.open.is_none(), refusal.is_err());
    assert!(!base.barrier.ready);
    Ok(refusal.err().map(|refusal| refusal.step))
}

#[tokio::test]
async fn a_part_that_disagrees_with_its_event_refuses_the_barrier_install() -> TestResult {
    let edits: [PartEdit; 5] = [
        |part| part.delivery_generation = 2,
        |part| part.delivery_sequence = 5,
        |part| part.event_id = [1; 16],
        |part| part.event_object_id = [1; 32],
        |part| part.identity.coordinator_state_generation = 11,
    ];
    for edit in edits {
        let step = refused_step(rows_with(edit)?, |_| {})?;
        assert_eq!(step, Some(EdgeRestoreStep::BarrierInstall));
    }
    assert_eq!(refused_step(rows_with(|_| {})?, |_| {})?, None);
    Ok(())
}

#[tokio::test]
async fn a_barrier_head_addressed_to_another_edge_refuses_the_reload() -> TestResult {
    let configs: [ConfigEdit; 2] = [
        |edge| edge.config.network_id = NetworkId::from_bytes([99; 32]),
        |edge| edge.config.server_id = ServerId::from_bytes([99; 16]),
    ];
    for config in configs {
        let step = refused_step(crash_rows(1, false)?, config)?;
        assert!(step.is_some());
    }
    Ok(())
}
