#![forbid(unsafe_code)]

//! An assembled event must agree with the position it was delivered at, and a
//! payload fragment must follow the exact event that named it.

use agenc_relay_e2ee::federation::frames::DeliveryPosition;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{ArcFederationEvent, ArcFederationEventKind};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};

use super::projection::base_edge;
use super::*;
use crate::test_support::StateCoreFixture;

const POSITION: DeliveryPosition = DeliveryPosition {
    server_id: [2; 16],
    delivery_generation: 2,
    delivery_sequence: 7,
    event_id: [11; 16],
};

/// An ordinary (non cross-profile) notice at `POSITION`.
fn notice(payload: Option<[u8; 32]>) -> TestResult<ArcFederationEvent> {
    Ok(ArcFederationEvent {
        profile_version: 1,
        network_id: [1; 32],
        target_server_id: [2; 16],
        delivery_generation: POSITION.delivery_generation,
        coordinator_state_generation: 5,
        delivery_sequence: POSITION.delivery_sequence,
        event_id: POSITION.event_id,
        event_kind: ArcFederationEventKind::RequestCompleted,
        cross_profile_mutation_id: Opaque::new(Vec::new())?,
        cross_profile_part_index: 0,
        cross_profile_part_count: 0,
        conversation_id: Opaque::new(Vec::new())?,
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
        payload_object_id: Opaque::new(payload.map(|id| id.to_vec()).unwrap_or_default())?,
        encoded_event_result: Opaque::new(Vec::new())?,
    })
}

/// Delivers `bytes` as one object at `POSITION` and reports whether the
/// completing fragment was refused.
fn deliver(
    edge: &mut E2eeEdge,
    fixture: &mut StateCoreFixture,
    bytes: &[u8],
    data: bool,
) -> TestResult<bool> {
    let object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
    let mut refused = false;
    for fragment in agenc_relay_e2ee::wire::fragment::fragment_object(bytes)? {
        refused |= edge
            .on_event_frame(
                fixture.context_mut()?,
                &mut base_edge(),
                POSITION,
                object_id,
                fragment,
                data,
            )
            .is_err();
    }
    Ok(refused)
}

fn event_bytes(event: &ArcFederationEvent) -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(ArcWireObjectKind::FederationEvent, event.encode()?)?.encode()?)
}

type EventEdit = fn(&mut ArcFederationEvent);

#[test]
fn an_event_whose_header_disagrees_with_its_position_is_an_invalid_fragment() -> TestResult {
    let edits: [(&str, EventEdit); 5] = [
        ("network", |event| event.network_id = [9; 32]),
        ("target", |event| event.target_server_id = [9; 16]),
        ("generation", |event| event.delivery_generation += 1),
        ("sequence", |event| event.delivery_sequence += 1),
        ("event id", |event| event.event_id = [9; 16]),
    ];
    for (name, edit) in edits {
        let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
        let mut edge = edge();
        let mut event = notice(None)?;
        edit(&mut event);
        let bytes = event_bytes(&event)?;
        assert!(deliver(&mut edge, &mut fixture, &bytes, false)?, "{name}");
        assert!(edge.events_in.is_empty(), "{name}");
    }
    Ok(())
}

#[test]
fn a_payload_must_follow_the_exact_event_that_named_it() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    let payload = ArcWireObject::new(ArcWireObjectKind::ApplicationMls, vec![12; 32])?.encode()?;
    // A payload for an event nobody opened.
    assert!(deliver(&mut edge, &mut fixture, &payload, true)?);
    // An event that names another payload keeps waiting; the wrong payload is refused.
    let event = notice(Some([99; 32]))?;
    let bytes = event_bytes(&event)?;
    assert!(!deliver(&mut edge, &mut fixture, &bytes, false)?);
    assert!(edge.events_in.contains_key(&POSITION.event_id));
    let other = ArcWireObject::new(ArcWireObjectKind::ApplicationMls, vec![13; 32])?.encode()?;
    assert!(deliver(&mut edge, &mut fixture, &other, true)?);
    assert!(
        !edge.events_in.contains_key(&POSITION.event_id),
        "the mismatched payload consumes the open event"
    );
    Ok(())
}

#[test]
fn an_event_assembles_whatever_the_client_cache_holds() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    super::fill_client_cache(&mut edge)?;
    // A delivery is keyed by its position and holds no recent-object slot.
    let event = notice(Some([99; 32]))?;
    let bytes = event_bytes(&event)?;
    assert!(!deliver(&mut edge, &mut fixture, &bytes, false)?);
    assert!(edge.events_in.contains_key(&POSITION.event_id));
    Ok(())
}

#[test]
fn a_lost_link_releases_the_coordinators_partial_objects() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    let payload =
        ArcWireObject::new(ArcWireObjectKind::ApplicationMls, vec![12; 8_000])?.encode()?;
    let payload_id = *agenc_relay_e2ee::ObjectId::compute(&payload).as_bytes();
    let event = event_bytes(&notice(Some(payload_id))?)?;
    assert!(!deliver(&mut edge, &mut fixture, &event, false)?);
    let fragments = agenc_relay_e2ee::wire::fragment::fragment_object(&payload)?;
    let first = fragments.first().ok_or("fragment")?.clone();
    edge.on_event_frame(
        fixture.context_mut()?,
        &mut base_edge(),
        POSITION,
        payload_id,
        first,
        true,
    )
    .map_err(|refusal| refusal.code.to_string())?;
    assert_eq!(edge.assembler.open_count(), 1);
    edge.link_down();
    assert_eq!(
        edge.assembler.open_count(),
        0,
        "the partial payload is released"
    );
    // Well past the idle deadline, the next link carries the event and its
    // payload again from their first fragments.
    fixture.context_mut()?.set_monotonic_for_test(120_000);
    assert!(!deliver(&mut edge, &mut fixture, &event, false)?);
    for fragment in fragments.into_iter().take(2) {
        edge.on_event_frame(
            fixture.context_mut()?,
            &mut base_edge(),
            POSITION,
            payload_id,
            fragment,
            true,
        )
        .map_err(|refusal| refusal.code.to_string())?;
    }
    assert_eq!(edge.assembler.open_count(), 1, "the payload assembles anew");
    Ok(())
}
