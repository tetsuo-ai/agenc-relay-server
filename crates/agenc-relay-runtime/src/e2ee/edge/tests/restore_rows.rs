#![forbid(unsafe_code)]

//! Restored companion rows are admitted only when they agree with themselves and with this
//! edge: a witnessed cursor whose ACK and next sequence match, a route row that names the
//! state it carries, a barrier part whose event names the part, and one marker per coordinator.

use super::*;
use agenc_relay_storage::e2ee_records::barrier::{
    BarrierIdentity, BarrierPart, CrossProfileStream,
};
use agenc_relay_storage::e2ee_records::{
    ROUTE_ROW_KIND, RouteRow, SnapshotMarkerRow, SnapshotPhase,
};

/// One edit of a checkpointed route row.
type RouteEdit = (&'static str, fn(&mut RouteRow));

/// One edit of a barrier part.
type PartEdit = (&'static str, fn(&mut BarrierPart));

fn cursor(next: u64, acked: u64, acked_event_id: [u8; 16]) -> DeliveryRow {
    DeliveryRow::WitnessedCursor {
        generation: 2,
        next_sequence: next,
        acked_sequence: acked,
        acked_event_id,
        barrier_open: false,
    }
}

#[test]
fn a_witnessed_cursor_must_agree_with_its_acknowledgement() -> TestResult {
    let mut fresh = edge();
    fresh.restore_delivery(&cursor(0, 0, [0; 16]))?;
    assert_eq!(fresh.resume_delivery().cursor, None);
    for (name, row) in [
        ("acked sequence before any delivery", cursor(0, 3, [0; 16])),
        ("acked event before any delivery", cursor(0, 0, [1; 16])),
        ("next sequence not one past the ack", cursor(8, 5, [11; 16])),
    ] {
        let mut fresh = edge();
        assert!(fresh.restore_delivery(&row).is_err(), "{name}");
        assert!(fresh.needs_witness_snapshot(), "{name}");
    }
    Ok(())
}

fn checkpointed_route() -> TestResult<(agenc_relay_storage::StoredKey, RouteRow)> {
    let mut original = edge();
    install_route(&mut original)?;
    let mut writes = Vec::new();
    original
        .checkpoint_witnesses([CONVERSATION], &mut writes)
        .map_err(|e| e.code.to_string())?;
    let AccountServiceDurableWrite::Put { key, plaintext, .. } =
        writes.pop().ok_or("route checkpoint")?
    else {
        return Err("route checkpoint write".into());
    };
    let value = PersistentRecordValue::decode(TableId::E2eeState, &plaintext)?;
    assert_eq!(value.record_kind(), ROUTE_ROW_KIND);
    Ok((key, RouteRow::decode(value.body())?))
}

#[test]
fn a_route_row_must_name_the_state_it_carries() -> TestResult {
    let (key, row) = checkpointed_route()?;
    edge().restore_route(&key, &row)?;
    let other_key = RouteRow::key(&[77; 32])?;
    assert!(edge().restore_route(&other_key, &row).is_err(), "key");
    let edits: [RouteEdit; 3] = [
        ("binding", |row| row.binding_id = [77; 32]),
        ("lock", |row| row.lock_id = [77; 32]),
        ("accepted state", |row| row.accepted_state_id = [77; 32]),
    ];
    for (name, edit) in edits {
        let mut edited = row.clone();
        edit(&mut edited);
        assert!(edge().restore_route(&key, &edited).is_err(), "{name}");
    }
    Ok(())
}

fn identity() -> BarrierIdentity {
    BarrierIdentity {
        network_id: [1; 32],
        coordinator_server_id: [3; 16],
        coordinator_server_incarnation: [4; 16],
        coordinator_recovery_epoch: [5; 16],
        target_server_id: [2; 16],
        target_server_incarnation: [4; 16],
        mutation_id: MUTATION,
        coordinator_state_generation: 5,
        part_count: 2,
    }
}

/// A companion part whose event is the one `part` renders, with its payload named.
fn companion_part(event: &ArcFederationEvent, payload: &[u8]) -> TestResult<BarrierPart> {
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationEvent, event.encode()?)?.encode()?;
    Ok(BarrierPart {
        identity: identity(),
        stream: CrossProfileStream::Companion,
        part_index: event.cross_profile_part_index,
        delivery_generation: event.delivery_generation,
        delivery_sequence: event.delivery_sequence,
        event_id: event.event_id,
        event_object_id: *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes(),
        encoded_event_object: bytes,
        payload_object_id: Some(*agenc_relay_e2ee::ObjectId::compute(payload).as_bytes()),
        payload_object_bytes: u32::try_from(payload.len())?,
    })
}

fn payload_bytes() -> Vec<u8> {
    vec![61; 48]
}

fn named_event() -> TestResult<ArcFederationEvent> {
    let mut event = part(ArcFederationEventKind::ClosedEvent, 5)?.event;
    event.payload_object_id = Opaque::new(
        agenc_relay_e2ee::ObjectId::compute(&payload_bytes())
            .as_bytes()
            .to_vec(),
    )?;
    Ok(event)
}

#[test]
fn a_barrier_part_whose_event_names_it_is_restored() -> TestResult {
    let event = named_event()?;
    let part = companion_part(&event, &payload_bytes())?;
    let mut fresh = edge();
    fresh.restore_part(&part, Some(payload_bytes()))?;
    assert_eq!(
        fresh.barrier_parts.get(&MUTATION).map(|parts| parts.len()),
        Some(1)
    );
    Ok(())
}

#[test]
fn a_barrier_part_that_disagrees_with_its_event_is_refused() -> TestResult {
    let event = named_event()?;
    let honest = companion_part(&event, &payload_bytes())?;
    let mut other_network = event.clone();
    other_network.network_id = [9; 32];
    let mut other_target = event.clone();
    other_target.target_server_id = [9; 16];
    let mut other_count = event.clone();
    other_count.cross_profile_part_count = 3;
    let mut unnamed = event.clone();
    unnamed.payload_object_id = Opaque::new(Vec::new())?;
    let mut cases: Vec<(&str, BarrierPart, Option<Vec<u8>>)> = vec![
        ("base stream", honest.clone(), Some(payload_bytes())),
        (
            "event network",
            companion_part(&other_network, &payload_bytes())?,
            Some(payload_bytes()),
        ),
        (
            "event target",
            companion_part(&other_target, &payload_bytes())?,
            Some(payload_bytes()),
        ),
        (
            "part count",
            companion_part(&other_count, &payload_bytes())?,
            Some(payload_bytes()),
        ),
        (
            "unnamed payload",
            companion_part(&unnamed, &payload_bytes())?,
            Some(payload_bytes()),
        ),
        ("payload bytes", honest.clone(), Some(vec![62; 48])),
        ("missing payload", honest.clone(), None),
    ];
    if let Some((_, part, _)) = cases.first_mut() {
        part.stream = CrossProfileStream::Base;
    }
    let edits: [PartEdit; 7] = [
        ("delivery generation", |part| part.delivery_generation += 1),
        ("delivery sequence", |part| part.delivery_sequence += 1),
        ("event id", |part| part.event_id = [9; 16]),
        ("event object id", |part| part.event_object_id = [9; 32]),
        ("state generation", |part| {
            part.identity.coordinator_state_generation += 1
        }),
        ("mutation", |part| part.identity.mutation_id = [9; 16]),
        ("part index", |part| part.part_index += 1),
    ];
    for (name, edit) in edits {
        let mut edited = honest.clone();
        edit(&mut edited);
        cases.push((name, edited, Some(payload_bytes())));
    }
    for (name, part, payload) in cases {
        let mut fresh = edge();
        assert!(fresh.restore_part(&part, payload).is_err(), "{name}");
        assert!(fresh.barrier_parts.is_empty(), "{name}");
    }
    Ok(())
}

fn marker() -> SnapshotMarkerRow {
    SnapshotMarkerRow {
        token: [1; 32],
        state_generation: 3,
        delivery_generation: 2,
        total_entries: 4,
        digest: [2; 32],
        staged_entries: 4,
        staged_bytes: 64,
        phase: SnapshotPhase::Ready,
        opened_at: 10,
        switched_through: None,
    }
}

#[test]
fn one_snapshot_marker_restores_only_under_this_coordinator() -> TestResult {
    let mut fresh = edge();
    let foreign = SnapshotMarkerRow::key(&[9; 16])?;
    assert!(fresh.restore_snapshot_marker(&foreign, &marker()).is_err());
    assert!(fresh.snapshot.is_none());
    let key = SnapshotMarkerRow::key(&[3; 16])?;
    fresh.restore_snapshot_marker(&key, &marker())?;
    assert!(fresh.snapshot.is_some());
    assert!(
        fresh.restore_snapshot_marker(&key, &marker()).is_err(),
        "a second marker for the same coordinator is refused"
    );
    Ok(())
}
