//! A reloaded outbox event beside a restored delivery barrier must either sit outside the
//! barrier's base window as an ordinary or already-covered event, or be the exact part the
//! barrier names at that sequence.
#![forbid(unsafe_code)]

use agenc_ircd_domain::federation::ProjectedEvent;
use agenc_ircd_federation_wire::{CanonicalEncode, CrossProfilePart, EventHeader};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    BarrierEndpoint, DeliveryBarrier, DeliveryBarrierFields, DeliveryScope, DeliveryScopeFields,
};
use agenc_ircd_types::{EventId, NetworkId, ServerId};

use super::Violation;
use super::barriers::validate_event;
use crate::test_support::TestResult;

const NETWORK: NetworkId = NetworkId::from_bytes([31; 32]);
const COORDINATOR: ServerId = ServerId::from_bytes([32; 16]);
const PEER: ServerId = ServerId::from_bytes([50; 16]);
const MUTATION: [u8; 16] = [63; 16];
const FINAL: EventId = EventId::from_bytes([65; 16]);
const FIRST: u64 = 3;
const LAST: u64 = 5;

/// A restored gate over base sequences 3..=5 whose base is not yet acknowledged.
fn restored_gate(base_acked: bool) -> TestResult<DeliveryBarrier> {
    let scope = DeliveryScope::new(DeliveryScopeFields {
        network_id: *NETWORK.as_bytes(),
        coordinator_server_id: *COORDINATOR.as_bytes(),
        coordinator_incarnation: [33; 16],
        coordinator_recovery_epoch: [34; 16],
        target_server_id: *PEER.as_bytes(),
        target_incarnation: [51; 16],
        covered_base_client_resync_epoch: 0,
    })?;
    Ok(DeliveryBarrier::new(DeliveryBarrierFields {
        scope,
        mutation_id: MUTATION,
        state_generation: 7,
        part_count: 4,
        base: BarrierEndpoint::new(1, FIRST, LAST, *FINAL.as_bytes())?,
        companion: BarrierEndpoint::new(1, 0, 0, [64; 16])?,
        base_acked,
        companion_acked: false,
    })?)
}

fn header(sequence: u64, part: Option<CrossProfilePart>) -> EventHeader {
    EventHeader {
        network_id: NETWORK,
        target_server_id: PEER,
        projection_generation: 1,
        coordinator_state_generation: 7,
        delivery_sequence: sequence,
        event_id: if sequence == LAST {
            FINAL
        } else {
            EventId::from_bytes([u8::try_from(sequence).unwrap_or(0); 16])
        },
        event_kind: ProjectedEvent::NetworkNotice {
            code: "REPLAY".to_owned(),
            text: "replayed".to_owned(),
        }
        .kind(),
        correlation: None,
        cross_profile: part,
    }
}

fn part_at(sequence: u64) -> CrossProfilePart {
    CrossProfilePart {
        mutation_id: MUTATION,
        part_index: u16::try_from(sequence.saturating_sub(FIRST)).unwrap_or(u16::MAX),
        part_count: 4,
    }
}

fn encoded(header: &EventHeader) -> TestResult<Vec<u8>> {
    let event = ProjectedEvent::NetworkNotice {
        code: "REPLAY".to_owned(),
        text: "replayed".to_owned(),
    };
    let arm = crate::federation::codec::events::event_arm_object(&event)
        .map_err(|error| format!("{error:?}"))?;
    Ok(header.build(&arm)?.encode_canonical()?.as_slice().to_vec())
}

#[test]
fn an_event_beside_a_gate_must_be_addressed_like_the_gate() -> TestResult {
    let gate = restored_gate(false)?;
    let mut other_network = header(1, None);
    other_network.network_id = NetworkId::from_bytes([9; 32]);
    let mut other_target = header(1, None);
    other_target.target_server_id = ServerId::from_bytes([9; 16]);
    let mut other_generation = header(1, None);
    other_generation.projection_generation = 2;
    for (name, header) in [
        ("network", other_network),
        ("target", other_target),
        ("projection generation", other_generation),
    ] {
        assert_eq!(
            validate_event(&gate, &encoded(&header)?, false),
            Err(Violation::Codec),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn outside_the_base_window_only_ordinary_or_covered_foreign_parts_pass() -> TestResult {
    let gate = restored_gate(false)?;
    assert_eq!(
        validate_event(&gate, &encoded(&header(1, None))?, false),
        Ok(())
    );
    let foreign = CrossProfilePart {
        mutation_id: [9; 16],
        part_index: 0,
        part_count: 2,
    };
    assert_eq!(
        validate_event(&gate, &encoded(&header(1, Some(foreign)))?, true),
        Ok(()),
        "a covered part of another mutation is history"
    );
    assert_eq!(
        validate_event(&gate, &encoded(&header(1, Some(foreign)))?, false),
        Err(Violation::Codec),
        "an uncovered barrier part outside the window is not this gate's"
    );
    assert_eq!(
        validate_event(&gate, &encoded(&header(9, Some(part_at(9))))?, true),
        Err(Violation::Codec),
        "a covered part of this mutation past the window is a fork"
    );
    Ok(())
}

#[test]
fn inside_the_base_window_every_part_field_must_match_the_gate() -> TestResult {
    let gate = restored_gate(false)?;
    for sequence in FIRST..=LAST {
        assert_eq!(
            validate_event(
                &gate,
                &encoded(&header(sequence, Some(part_at(sequence))))?,
                false
            ),
            Ok(()),
            "honest part {sequence}"
        );
    }
    assert_eq!(
        validate_event(&gate, &encoded(&header(FIRST, None))?, false),
        Err(Violation::Codec),
        "an ordinary event cannot sit inside the window"
    );
    let mut other_mutation = part_at(FIRST);
    other_mutation.mutation_id = [9; 16];
    let mut other_count = part_at(FIRST);
    other_count.part_count = 3;
    let mut other_index = part_at(FIRST);
    other_index.part_index = 1;
    for (name, part) in [
        ("mutation", other_mutation),
        ("part count", other_count),
        ("part index", other_index),
    ] {
        assert_eq!(
            validate_event(&gate, &encoded(&header(FIRST, Some(part)))?, false),
            Err(Violation::Codec),
            "{name}"
        );
    }
    let mut other_state = header(FIRST, Some(part_at(FIRST)));
    other_state.coordinator_state_generation = 8;
    assert_eq!(
        validate_event(&gate, &encoded(&other_state)?, false),
        Err(Violation::Codec),
        "state generation"
    );
    assert_eq!(
        validate_event(&gate, &encoded(&header(FIRST, Some(part_at(FIRST))))?, true),
        Err(Violation::Codec),
        "a covered part beside an unacknowledged base"
    );
    let mut other_final = header(LAST, Some(part_at(LAST)));
    other_final.event_id = EventId::from_bytes([9; 16]);
    assert_eq!(
        validate_event(&gate, &encoded(&other_final)?, false),
        Err(Violation::Codec),
        "the last part must carry the final event id"
    );
    let acked = restored_gate(true)?;
    assert_eq!(
        validate_event(&acked, &encoded(&header(LAST, Some(part_at(LAST))))?, true),
        Ok(()),
        "a covered part beside an acknowledged base"
    );
    Ok(())
}
