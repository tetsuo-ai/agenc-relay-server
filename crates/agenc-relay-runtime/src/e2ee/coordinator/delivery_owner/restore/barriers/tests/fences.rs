//! A durable gate admits exactly one part per sequence, exactly one owner per
//! peer, and exactly the contiguous rows its companion endpoint names.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use agenc_relay_e2ee::objects::federation::{ArcFederationEvent, ArcFederationEventKind};
use agenc_relay_e2ee::tls::Opaque;
use agenc_relay_storage::e2ee_records::delivery_recovery::RetirementReason;
use agenc_relay_storage::e2ee_records::delivery_recovery::outbox::Acknowledgement;
use agenc_relay_types::ServerId;

use super::*;
use crate::e2ee::coordinator::events::{SharedBytes, StreamRow};

const MUTATION: [u8; 16] = [9; 16];
const PEER: ServerId = ServerId::from_bytes([3; 16]);

/// One single-field edit to a gated part, with the foreign mutation it may use.
type Edit = fn(&mut ArcFederationEvent, &Opaque<0, 16>);

/// The open companion gate of `inventory`: base part zero, companion parts
/// one and two of three, state generation one, not yet acknowledged.
fn open_gate() -> TestResult<DeliveryBarrier> {
    let (_, acknowledged) = inventory(0, 0)?;
    Ok(DeliveryBarrier::new(DeliveryBarrierFields {
        scope: *acknowledged.scope(),
        mutation_id: MUTATION,
        state_generation: 1,
        part_count: 3,
        base: BarrierEndpoint::new(0, 0, 0, [7; 16])?,
        companion: BarrierEndpoint::new(0, 0, 1, [8; 16])?,
        base_acked: false,
        companion_acked: false,
    })?)
}

/// One companion part of the open gate: delivery sequence zero is part index
/// one, because the single base part occupies index zero.
fn part(sequence: u64) -> TestResult<ArcFederationEvent> {
    Ok(ArcFederationEvent {
        profile_version: 1,
        network_id: [1; 32],
        target_server_id: *PEER.as_bytes(),
        delivery_generation: 0,
        coordinator_state_generation: 1,
        delivery_sequence: sequence,
        event_id: if sequence == 1 { [8; 16] } else { [5; 16] },
        event_kind: ArcFederationEventKind::ChannelApplication,
        cross_profile_mutation_id: Opaque::new(MUTATION.to_vec())?,
        cross_profile_part_index: u16::try_from(sequence.saturating_add(1))?,
        cross_profile_part_count: 3,
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
fn every_gated_field_of_one_part_is_checked_on_its_own() -> TestResult {
    let gate = open_gate()?;
    validate_event(Some(&gate), &part(0)?, false)?;
    validate_event(Some(&gate), &part(1)?, false)?;

    let edits: [(&str, Edit); 5] = [
        ("another delivery generation", |event, _| {
            event.delivery_generation = 1;
        }),
        ("another coordinator state generation", |event, _| {
            event.coordinator_state_generation = 2;
        }),
        ("another mutation", |event, other| {
            event.cross_profile_mutation_id = other.clone();
        }),
        ("another part index", |event, _| {
            event.cross_profile_part_index = 2;
        }),
        ("another part count", |event, _| {
            event.cross_profile_part_count = 2;
        }),
    ];
    let other_mutation: Opaque<0, 16> = Opaque::new([4; 16].to_vec())?;
    for (label, edit) in edits {
        let mut event = part(0)?;
        edit(&mut event, &other_mutation);
        assert!(
            matches!(
                validate_event(Some(&gate), &event, false),
                Err(CompanionFault::Storage)
            ),
            "{label} was admitted"
        );
    }
    // The acknowledgement state of the row must equal the gate's own.
    assert!(matches!(
        validate_event(Some(&gate), &part(0)?, true),
        Err(CompanionFault::Storage)
    ));
    // The last gated sequence additionally pins its event identity.
    let mut renamed = part(1)?;
    renamed.event_id = [6; 16];
    assert!(matches!(
        validate_event(Some(&gate), &renamed, false),
        Err(CompanionFault::Storage)
    ));
    Ok(())
}

#[test]
fn an_ungated_sequence_is_admitted_only_outside_the_gate_s_own_mutation() -> TestResult {
    let gate = open_gate()?;
    // A part of another mutation beyond the gated range is already
    // acknowledged and passes; the same part unacknowledged does not.
    let mut foreign = part(5)?;
    foreign.cross_profile_mutation_id = Opaque::new([4; 16].to_vec())?;
    foreign.cross_profile_part_index = 0;
    assert!(foreign.cross_profile_part_index < foreign.cross_profile_part_count);
    validate_event(Some(&gate), &foreign, true)?;
    assert!(matches!(
        validate_event(Some(&gate), &foreign, false),
        Err(CompanionFault::Storage)
    ));
    // The gate's own mutation beyond its range is refused even acknowledged.
    let mut outside = part(5)?;
    outside.cross_profile_part_index = 1;
    assert!(matches!(
        validate_event(Some(&gate), &outside, true),
        Err(CompanionFault::Storage)
    ));
    // A plain event carries no part at all and passes in either position.
    let mut plain = part(5)?;
    plain.cross_profile_mutation_id = Opaque::new(Vec::new())?;
    plain.cross_profile_part_index = 0;
    plain.cross_profile_part_count = 0;
    validate_event(Some(&gate), &plain, false)?;
    // Inside the gated range a plain event is a hole in the barrier.
    let mut hole = plain.clone();
    hole.delivery_sequence = 0;
    assert!(matches!(
        validate_event(Some(&gate), &hole, false),
        Err(CompanionFault::Storage)
    ));
    // A malformed part tuple is refused before any gate is consulted.
    let mut malformed = part(0)?;
    malformed.cross_profile_part_count = 1;
    assert!(matches!(
        validate_event(None, &malformed, true),
        Err(CompanionFault::Storage)
    ));
    Ok(())
}

fn row(sequence: u64) -> TestResult<StreamRow> {
    Ok(StreamRow {
        sequence,
        event_id: [8; 16],
        event: SharedBytes::for_fixture(vec![1, 2, 3])?,
        payload: None,
        acknowledgement: Acknowledgement::Unacknowledged,
    })
}

#[test]
fn an_open_gate_needs_its_rows_contiguous_from_the_first_sequence() -> TestResult {
    let (mut stream, _) = inventory(0, 0)?;
    let gate = open_gate()?;
    stream.acked = None;
    stream.replay = None;
    stream.rows.push_back(row(0)?);
    stream.rows.push_back(row(1)?);
    validate_complete(&stream, &gate)?;

    // The same two rows with the first one missing leave a hole the gate
    // refuses, and the stream is unchanged by the refusal.
    let mut gapped = DeliveryStream {
        owner: stream.owner.clone(),
        next_sequence: stream.next_sequence,
        ..DeliveryStream::default()
    };
    gapped.rows.push_back(row(1)?);
    assert!(matches!(
        validate_complete(&gapped, &gate),
        Err(CompanionFault::Storage)
    ));
    assert_eq!(gapped.rows.len(), 1);
    assert_eq!(stream.rows.len(), 2, "the refusal changed no retained row");
    Ok(())
}

#[test]
fn every_gate_needs_a_ready_owner_that_still_owes_one_profile() -> TestResult {
    // The owner's committed cursor already covers the companion endpoint, so
    // the gate that matches it is the acknowledged one; its base profile is
    // still open, which is what makes it installable.
    let (stream, gate) = inventory(0, 0)?;
    let owner = stream.owner.clone().ok_or("owner")?;
    let mut gates = BTreeMap::new();
    gates.insert(PEER, gate.clone());
    let mut owners = BTreeMap::new();
    owners.insert(PEER, owner.clone());
    validate_owners(&gates, &owners)?;

    // A gate whose peer holds no owner at all.
    assert!(matches!(
        validate_owners(&gates, &BTreeMap::new()),
        Err(CompanionFault::Storage)
    ));

    // A gate both of whose profiles are already acknowledged is closed and
    // must not be reinstalled.
    let mut closed = BTreeMap::new();
    closed.insert(
        PEER,
        DeliveryBarrier::new(DeliveryBarrierFields {
            scope: *gate.scope(),
            mutation_id: gate.mutation_id(),
            state_generation: gate.state_generation(),
            part_count: gate.part_count(),
            base: *gate.base(),
            companion: *gate.companion(),
            base_acked: true,
            companion_acked: true,
        })?,
    );
    assert!(matches!(
        validate_owners(&closed, &owners),
        Err(CompanionFault::Storage)
    ));

    // An owner that has not reached READY cannot carry a gate.
    let pending = DeliveryOwner::new(
        *owner.scope(),
        *owner.cursor(),
        *owner.cut(),
        CutPhase::Retired(RetirementReason::DeadlineReached),
    )?;
    let mut retired = BTreeMap::new();
    retired.insert(PEER, pending);
    assert!(matches!(
        validate_owners(&gates, &retired),
        Err(CompanionFault::Storage)
    ));
    assert!(gate.companion_acked() && !gate.base_acked());
    Ok(())
}

#[test]
fn installing_a_gate_needs_its_peer_stream_complete_first() -> TestResult {
    let (template, _) = inventory(0, 0)?;
    let gate = open_gate()?;
    let mut gates = BTreeMap::new();
    gates.insert(PEER, gate.clone());

    // A gate whose peer has no stream at all.
    let mut absent: BTreeMap<ServerId, DeliveryStream> = BTreeMap::new();
    assert!(matches!(
        install(&mut absent, &gates),
        Err(CompanionFault::Storage)
    ));
    assert!(absent.is_empty(), "the refusal installed nothing");

    // A stream that holds only the second gated row.
    let mut partial: BTreeMap<ServerId, DeliveryStream> = BTreeMap::new();
    let mut gapped = DeliveryStream {
        owner: template.owner.clone(),
        next_sequence: 2,
        ..DeliveryStream::default()
    };
    gapped.rows.push_back(row(1)?);
    partial.insert(PEER, gapped);
    assert!(matches!(
        install(&mut partial, &gates),
        Err(CompanionFault::Storage)
    ));
    assert_eq!(
        partial.get(&PEER).and_then(|stream| stream.barrier),
        None,
        "the refusal opened no barrier"
    );

    // The complete stream installs the hold and the open barrier.
    let mut streams: BTreeMap<ServerId, DeliveryStream> = BTreeMap::new();
    let mut complete = DeliveryStream {
        owner: template.owner.clone(),
        next_sequence: 2,
        ..DeliveryStream::default()
    };
    complete.rows.push_back(row(0)?);
    complete.rows.push_back(row(1)?);
    streams.insert(PEER, complete);
    install(&mut streams, &gates)?;
    let installed = streams.get(&PEER).ok_or("stream")?;
    assert_eq!(installed.barrier, Some((0, 1)));
    assert_eq!(installed.hold_after, Some(1));
    Ok(())
}
