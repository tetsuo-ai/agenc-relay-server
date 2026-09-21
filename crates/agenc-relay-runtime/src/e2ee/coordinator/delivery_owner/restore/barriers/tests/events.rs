//! Restored rows are checked field by field before the stream trusts them.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use agenc_relay_e2ee::objects::federation::{ArcFederationEvent, ArcFederationEventKind};
use agenc_relay_e2ee::tls::Opaque;
use agenc_relay_storage::e2ee_records::delivery_recovery::DeliveryOwner;

use super::*;
use crate::e2ee::coordinator::delivery_owner::restore as restore_module;
use crate::e2ee::coordinator::events::{SharedBytes, StreamRow};

fn backing() -> crate::budget::BackingReservationPort {
    crate::budget::BackingReservationPort::new(Arc::new(crate::budget::MemoryBudget::new(1 << 20)))
}

fn event_for(owner: &DeliveryOwner, sequence: u64) -> TestResult<ArcFederationEvent> {
    Ok(ArcFederationEvent {
        profile_version: 1,
        network_id: owner.scope().network_id(),
        target_server_id: owner.scope().target_server_id(),
        delivery_generation: owner.cursor().generation(),
        coordinator_state_generation: owner.cut().state_generation(),
        delivery_sequence: sequence,
        event_id: [5; 16],
        event_kind: ArcFederationEventKind::ChannelApplication,
        cross_profile_mutation_id: Opaque::new(Vec::new())?,
        cross_profile_part_index: 0,
        cross_profile_part_count: 0,
        conversation_id: Opaque::new([9; 32].to_vec())?,
        route_sequence: 0,
        origin_id: Opaque::new(Vec::new())?,
        origin_generation: 0,
        source_view: Opaque::new(Vec::new())?,
        request_home_server_id: Opaque::new(Vec::new())?,
        request_server_incarnation: Opaque::new(Vec::new())?,
        request_origin_id: Opaque::new(Vec::new())?,
        request_origin_generation: 0,
        request_operation_sequence: 0,
        request_id: Opaque::new(Vec::new())?,
        payload_object_id: Opaque::new(Vec::new())?,
        encoded_event_result: Opaque::new(Vec::new())?,
    })
}

#[test]
fn cross_profile_tuples_need_a_consistent_index_and_count() -> TestResult {
    let (stream, _) = inventory(0, 0)?;
    let owner = stream.owner.clone().ok_or("owner")?;
    let mut lone_index = event_for(&owner, 2)?;
    lone_index.cross_profile_part_index = 1;
    assert!(restore_module::cross_profile(&lone_index).is_err());
    let mut lone_count = event_for(&owner, 2)?;
    lone_count.cross_profile_part_count = 2;
    assert!(restore_module::cross_profile(&lone_count).is_err());
    for (index, count) in [(0, 1), (0, 3_000), (2, 2)] {
        let mut part = event_for(&owner, 2)?;
        part.cross_profile_mutation_id = Opaque::new([9; 16].to_vec())?;
        part.cross_profile_part_index = index;
        part.cross_profile_part_count = count;
        assert!(
            restore_module::cross_profile(&part).is_err(),
            "index {index} of {count}"
        );
    }
    let mut part = event_for(&owner, 2)?;
    part.cross_profile_mutation_id = Opaque::new([9; 16].to_vec())?;
    part.cross_profile_part_index = 1;
    part.cross_profile_part_count = 3;
    assert!(restore_module::cross_profile(&part)?.is_some());
    Ok(())
}

#[test]
fn restored_event_headers_are_checked_field_by_field() -> TestResult {
    let (stream, _) = inventory(0, 0)?;
    let owner = stream.owner.clone().ok_or("owner")?;
    let good = event_for(&owner, 2)?;
    restore_module::validate_event(&owner, 2, [5; 16], &good)?;
    type Edit = fn(&mut ArcFederationEvent);
    let edits: [Edit; 6] = [
        |event| event.profile_version = 2,
        |event| event.network_id = [0xEE; 32],
        |event| event.target_server_id = [0xEE; 16],
        |event| event.delivery_generation = 9,
        |event| event.delivery_sequence = 3,
        |event| event.event_id = [6; 16],
    ];
    for (index, edit) in edits.into_iter().enumerate() {
        let mut event = event_for(&owner, 2)?;
        edit(&mut event);
        assert!(
            restore_module::validate_event(&owner, 2, [5; 16], &event).is_err(),
            "edit {index}"
        );
    }
    let mut stale = event_for(&owner, 2)?;
    stale.coordinator_state_generation = owner.cut().state_generation().saturating_sub(1);
    assert_eq!(
        restore_module::validate_event(&owner, 2, [5; 16], &stale).is_err(),
        owner.cut().state_generation() > 0
    );
    Ok(())
}

#[test]
fn restored_payloads_bind_their_object_identity_and_length() -> TestResult {
    let (stream, _) = inventory(0, 0)?;
    let owner = stream.owner.clone().ok_or("owner")?;
    let port = backing();
    let bytes = vec![1_u8, 2, 3];
    let id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    let mut objects = BTreeMap::new();
    objects.insert(id, bytes.clone());
    let none = event_for(&owner, 2)?;
    assert!(restore_module::payload(&objects, None, 0, &none, &port)?.is_none());
    assert!(restore_module::payload(&objects, None, 3, &none, &port).is_err());
    assert!(restore_module::payload(&objects, Some(id), 3, &none, &port).is_err());
    let mut carrying = event_for(&owner, 2)?;
    carrying.payload_object_id = Opaque::new(id.to_vec())?;
    assert!(restore_module::payload(&objects, Some(id), 2, &carrying, &port).is_err());
    let mut forged = BTreeMap::new();
    forged.insert(id, vec![9_u8, 9, 9]);
    assert!(restore_module::payload(&forged, Some(id), 3, &carrying, &port).is_err());
    assert!(restore_module::payload(&objects, Some(id), 3, &carrying, &port)?.is_some());
    Ok(())
}

#[test]
fn a_restored_stream_must_be_contiguous_from_its_acknowledgement() -> TestResult {
    let (stream, _) = inventory(0, 0)?;
    restore_module::validate_complete(&stream)?;
    let (mut advanced, _) = inventory(0, 0)?;
    advanced.next_sequence = 3;
    assert!(restore_module::validate_complete(&advanced).is_err());
    let (mut gapped, _) = inventory(0, 0)?;
    let port = backing();
    gapped.rows.push_back(StreamRow {
        sequence: 5,
        event_id: [5; 16],
        event: SharedBytes::copy_from(&[1, 2, 3], &port)?,
        payload: None,
        acknowledgement: agenc_relay_storage::e2ee_records::delivery_recovery::outbox::Acknowledgement::Unacknowledged,
    });
    assert!(restore_module::validate_complete(&gapped).is_err());
    Ok(())
}
