#![forbid(unsafe_code)]

//! Cross-profile barrier tests on the coordinator: companion copies of a
//! barrier target carry the tuple after the base parts, the stream holds a
//! barrier window, and the window admits the cumulative acknowledgement.

use std::collections::BTreeMap;

use agenc_relay_domain::e2ee::projection::{EventKind, EventPlan, PlannedEvent};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::ArcFederationEvent;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_types::ServerId;

use super::super::events::{
    BarrierAssignment, DeliveryStream, EventContent, StreamRow, sequence_copies,
};
use super::super::{CompanionFault, StoredResult};
use super::{Counter, HOME, Harness, TestResult};

fn planned(
    target: ServerId,
    kind: EventKind,
    conversation: Option<[u8; 32]>,
    payload: &[u8],
) -> PlannedEvent {
    PlannedEvent {
        kind,
        conversation_id: conversation,
        target,
        payload_object_id: kind
            .has_payload()
            .then(|| *agenc_relay_e2ee::ObjectId::compute(payload).as_bytes()),
        completion: kind == EventKind::RequestCompleted,
        route_sequence: 0,
        bytes: 1_024,
    }
}

fn content(planned: PlannedEvent, payload: &[u8]) -> EventContent {
    let payload = planned.kind.has_payload().then(|| payload.to_vec());
    EventContent {
        planned,
        origin: None,
        source_view: Vec::new(),
        correlation: None,
        encoded_result: Vec::new(),
        payload,
    }
}

fn decode_event(row: &StreamRow) -> TestResult<ArcFederationEvent> {
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let object = ArcWireObject::decode_kind(
        &row.event,
        Some(ArcWireObjectKind::FederationEvent),
        &mut budget,
    )?;
    Ok(ArcFederationEvent::decode_exact(
        object.body(),
        &mut budget,
    )?)
}

#[test]
fn companion_copies_of_a_barrier_target_carry_the_tuple_after_the_base_parts() -> TestResult {
    let mut harness = Harness::new()?;
    let home = ServerId::from_bytes(HOME);
    let other = ServerId::from_bytes([12; 16]);
    let conversation = [5; 32];
    let payload = super::sync::snapshot_route(super::NETWORK, conversation, 7)?;
    agenc_relay_storage::e2ee_records::ObjectRow::new(payload.clone())?;
    let events = vec![
        planned(
            home,
            EventKind::RouteStateChanged,
            Some(conversation),
            &payload,
        ),
        planned(
            other,
            EventKind::RouteStateChanged,
            Some(conversation),
            &payload,
        ),
        planned(home, EventKind::RequestCompleted, None, &payload),
    ];
    let plan = EventPlan::order(events.clone())?;
    let contents: Vec<EventContent> = plan
        .events()
        .iter()
        .cloned()
        .map(|planned| content(planned, &payload))
        .collect();
    let mut barriers = BTreeMap::new();
    barriers.insert(
        home,
        BarrierAssignment {
            mutation_id: [9; 16],
            base_parts: 2,
            part_count: 4,
        },
    );
    let mut entropy = Counter(0);
    assert!(matches!(
        sequence_copies(
            &harness.coordinator,
            &plan,
            &contents,
            7,
            &mut entropy,
            &barriers,
            &harness.backing,
        ),
        Err(agenc_relay_e2ee::wire::reply::E2eeReplyCode::Syncing)
    ));
    super::sync::initial_ready_peer(&mut harness.coordinator, home)?;
    super::sync::initial_ready_peer(&mut harness.coordinator, other)?;
    let sequenced = sequence_copies(
        &harness.coordinator,
        &plan,
        &contents,
        7,
        &mut entropy,
        &barriers,
        &harness.backing,
    )
    .map_err(|code| format!("{code:?}"))?;
    let home_copies: Vec<_> = sequenced
        .copies
        .iter()
        .filter(|copy| copy.target == home)
        .collect();
    assert_eq!(home_copies.len(), 2);
    for (index, copy) in home_copies.iter().enumerate() {
        let event = decode_event(&copy.row)?;
        assert_eq!(event.cross_profile_mutation_id.as_slice(), &[9; 16]);
        assert_eq!(usize::from(event.cross_profile_part_index), 2 + index);
        assert_eq!(event.cross_profile_part_count, 4);
        assert_eq!(event.delivery_sequence, u64::try_from(index)?);
    }
    let other_copy = sequenced
        .copies
        .iter()
        .find(|copy| copy.target == other)
        .ok_or("the other target's copy")?;
    let event = decode_event(&other_copy.row)?;
    assert!(event.cross_profile_mutation_id.as_slice().is_empty());
    assert_eq!(event.cross_profile_part_count, 0);
    assert_eq!(sequenced.barrier_last.get(&home), Some(&1));
    let (_, stream) = sequenced
        .streams
        .iter()
        .find(|(target, _)| *target == home)
        .ok_or("the home stream")?;
    assert_eq!(stream.barrier, Some((0, 1)));
    // Every barrier target must receive at least one companion copy.
    let mut absent = BTreeMap::new();
    absent.insert(
        ServerId::from_bytes([99; 16]),
        BarrierAssignment {
            mutation_id: [1; 16],
            base_parts: 1,
            part_count: 2,
        },
    );
    assert!(
        sequence_copies(
            &harness.coordinator,
            &plan,
            &contents,
            7,
            &mut entropy,
            &absent,
            &harness.backing,
        )
        .is_err()
    );
    // An index at or past the count is refused.
    let mut short = BTreeMap::new();
    short.insert(
        home,
        BarrierAssignment {
            mutation_id: [9; 16],
            base_parts: 2,
            part_count: 3,
        },
    );
    assert!(
        sequence_copies(
            &harness.coordinator,
            &plan,
            &contents,
            7,
            &mut entropy,
            &short,
            &harness.backing,
        )
        .is_err()
    );
    Ok(())
}

fn row(sequence: u64) -> TestResult<StreamRow> {
    Ok(StreamRow {
        sequence,
        event_id: [u8::try_from(sequence).unwrap_or(0) + 1; 16],
        event: super::super::events::SharedBytes::for_fixture(vec![1; 8])?,
        payload: None,
        acknowledgement:
            agenc_relay_storage::e2ee_records::delivery_recovery::Acknowledgement::Unacknowledged,
    })
}

#[test]
fn the_barrier_window_admits_one_cumulative_acknowledgement() -> TestResult {
    let acknowledgement = agenc_relay_storage::e2ee_records::delivery_recovery::Acknowledgement::AcknowledgedTimeUnknown;
    let mut stream = DeliveryStream::default();
    for sequence in 0..4 {
        stream.rows.push_back(row(sequence)?);
    }
    stream.next_sequence = 4;
    stream.barrier = Some((1, 2));
    // Outside the window the ACK advances by exactly one.
    assert_eq!(
        stream.acknowledge(1, [2; 16], acknowledgement),
        Err(CompanionFault::Protocol)
    );
    stream.acknowledge(0, [1; 16], acknowledgement)?;
    // Inside the window only the last part may be acknowledged, and the
    // acknowledgement is cumulative.
    assert_eq!(
        stream.acknowledge(3, [4; 16], acknowledgement),
        Err(CompanionFault::Protocol)
    );
    stream.acknowledge(2, [3; 16], acknowledgement)?;
    assert_eq!(stream.acked, Some((2, [3; 16])));
    assert!(stream.barrier.is_none());
    assert_eq!(stream.unacked_rows().len(), 1);
    // A wrong event identity at the last part is refused.
    stream.barrier = Some((3, 3));
    assert_eq!(
        stream.acknowledge(3, [9; 16], acknowledgement),
        Err(CompanionFault::Protocol)
    );
    stream.acknowledge(3, [4; 16], acknowledgement)?;
    assert!(stream.unacked_rows().is_empty());
    let _ = StoredResult {
        result: Vec::new(),
        responses: Vec::new(),
    };
    Ok(())
}
