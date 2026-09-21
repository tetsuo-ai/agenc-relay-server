#![forbid(unsafe_code)]

//! Response retention is bounded and reconciles either federation delivery order.

use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::federation::frames::{CompanionFrame, Correlation};
use agenc_relay_e2ee::limits::{
    MAX_BATCH_DECODED_BYTES, MAX_BATCH_OBJECTS, WIRE_OBJECT_ENVELOPE_BYTES,
};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{
    ArcFederationResponseDescriptor, ArcFederationResult, ArcFederationResultKind,
};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode, TlsVec};
use agenc_relay_e2ee::wire::command::EkeyCommand;
use agenc_relay_e2ee::wire::fragment::fragment_object;
use agenc_relay_types::{FederationRole, NetworkId, RecoveryEpoch, ServerIncarnation};

use super::super::{ClientOutput, Phase};
use super::*;
use crate::federation::PeerIdentity;
use crate::federation::edge::{EdgeConfig, EdgeFederation};
use crate::test_support::StateCoreFixture;

const REQUEST: [u8; 16] = [5; 16];

fn waiting() -> E2eeEdge {
    let mut edge = edge();
    let mut request = pending(1, 0, false);
    request.label = Some("fetch".to_owned());
    request.command = Resolved::Command(ClientCommand::Ekey(EkeyCommand::FetchRootChain {
        account: [b'a'; 24],
        first_generation: 0,
        cursor: None,
    }));
    edge.pending.insert(REQUEST, request);
    edge
}

fn object(kind: ArcWireObjectKind, total: usize, seed: u8) -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(
        kind,
        vec![
            seed;
            total
                .checked_sub(WIRE_OBJECT_ENVELOPE_BYTES)
                .ok_or("object size")?
        ],
    )?
    .encode()?)
}

fn descriptor(index: u16, bytes: &[u8]) -> TestResult<ArcFederationResponseDescriptor> {
    Ok(ArcFederationResponseDescriptor {
        response_index: index,
        wire_kind: ArcWireObject::peek(bytes)?.0,
        object_id: *ObjectId::compute(bytes).as_bytes(),
        total_size: u32::try_from(bytes.len())?,
        delivery_token: Opaque::new(Vec::new())?,
        target_device_id: Opaque::new(Vec::new())?,
    })
}

fn result(
    descriptors: Vec<ArcFederationResponseDescriptor>,
    state_generation: u64,
) -> TestResult<Vec<u8>> {
    let result = ArcFederationResult {
        profile_version: 1,
        network_id: [1; 32],
        home_server_id: [2; 16],
        server_incarnation: [4; 16],
        origin_id: [8; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: REQUEST,
        request_object_id: [7; 32],
        coordinator_state_generation: state_generation,
        completion_event_id: Opaque::new(Vec::new())?,
        result_kind: ArcFederationResultKind::ObjectPage,
        encoded_result: Opaque::new(Vec::new())?,
        snapshot_token: Opaque::new(vec![9; 32])?,
        next_cursor: Opaque::new(Vec::new())?,
        responses: TlsVec::new(descriptors)?,
    };
    Ok(ArcWireObject::new(ArcWireObjectKind::FederationResult, result.encode()?)?.encode()?)
}

fn frames(index: Option<u16>, bytes: &[u8]) -> TestResult<Vec<CompanionFrame>> {
    let correlation = Correlation {
        peer_server_id: [2; 16],
        server_incarnation: [4; 16],
        origin_id: [8; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: REQUEST,
    };
    let object_id = *ObjectId::compute(bytes).as_bytes();
    Ok(fragment_object(bytes)?
        .into_iter()
        .map(|fragment| match index {
            Some(response_index) => CompanionFrame::Response {
                correlation,
                response_index,
                object_id,
                fragment,
            },
            None => CompanionFrame::Result {
                correlation,
                object_id,
                fragment,
            },
        })
        .collect())
}

fn receive(
    edge: &mut E2eeEdge,
    fixture: &mut StateCoreFixture,
    index: Option<u16>,
    bytes: &[u8],
) -> TestResult<Vec<ClientOutput>> {
    let mut outputs = Vec::new();
    for frame in frames(index, bytes)? {
        outputs.extend(
            edge.on_result_frame(fixture.context_mut()?, frame)
                .map_err(|error| error.code.to_string())?,
        );
    }
    Ok(outputs)
}

#[test]
fn response_objects_reconcile_before_or_after_the_result() -> TestResult {
    let first = object(ArcWireObjectKind::RootIdentity, 30, 1)?;
    let second = object(ArcWireObjectKind::RootIdentity, 30, 2)?;
    let result = result(vec![descriptor(0, &first)?, descriptor(1, &second)?], 1)?;
    for result_first in [false, true] {
        let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
        let mut edge = waiting();
        if result_first {
            assert!(receive(&mut edge, &mut fixture, None, &result)?.is_empty());
        }
        assert!(receive(&mut edge, &mut fixture, Some(1), &second)?.is_empty());
        let ready = receive(&mut edge, &mut fixture, Some(0), &first)?;
        let outputs = if result_first {
            ready
        } else {
            assert!(ready.is_empty());
            receive(&mut edge, &mut fixture, None, &result)?
        };
        assert_eq!(outputs.len(), 1);
        assert!(!edge.pending.contains_key(&REQUEST));
    }
    Ok(())
}

#[test]
fn responses_before_results_cannot_exceed_the_count_or_byte_ceiling() -> TestResult {
    let small = object(ArcWireObjectKind::RootIdentity, 30, 1)?;
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = waiting();
    for index in 0..MAX_BATCH_OBJECTS {
        receive(&mut edge, &mut fixture, Some(u16::try_from(index)?), &small)?;
    }
    assert!(receive(&mut edge, &mut fixture, Some(32), &small).is_err());
    assert!(receive(&mut edge, &mut fixture, Some(u16::MAX), &small).is_err());
    assert_eq!(
        edge.pending.get(&REQUEST).ok_or("pending")?.responses.len(),
        MAX_BATCH_OBJECTS
    );

    let mut edge = waiting();
    let large = object(ArcWireObjectKind::WelcomeMls, MAX_BATCH_DECODED_BYTES, 1)?;
    receive(&mut edge, &mut fixture, Some(0), &large)?;
    receive(&mut edge, &mut fixture, Some(0), &large)?;
    assert!(receive(&mut edge, &mut fixture, Some(1), &small).is_err());
    assert_eq!(
        edge.pending.get(&REQUEST).ok_or("pending")?.responses.len(),
        1
    );
    Ok(())
}

#[test]
fn conflicting_responses_and_result_envelopes_leave_previous_values_intact() -> TestResult {
    let bytes = object(ArcWireObjectKind::RootIdentity, 30, 1)?;
    let different = object(ArcWireObjectKind::RootIdentity, 30, 2)?;
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = waiting();
    receive(&mut edge, &mut fixture, Some(0), &bytes)?;
    assert!(receive(&mut edge, &mut fixture, Some(0), &different).is_err());
    assert_eq!(
        edge.pending
            .get(&REQUEST)
            .ok_or("pending")?
            .responses
            .get(&0),
        Some(&bytes)
    );

    let mut edge = waiting();
    let original = result(vec![descriptor(0, &bytes)?], 1)?;
    receive(&mut edge, &mut fixture, None, &original)?;
    receive(&mut edge, &mut fixture, None, &original)?;
    let changed_envelope = result(vec![descriptor(0, &bytes)?], 2)?;
    assert!(receive(&mut edge, &mut fixture, None, &changed_envelope).is_err());
    assert_eq!(
        edge.pending
            .get(&REQUEST)
            .ok_or("pending")?
            .result_object_id,
        Some(*ObjectId::compute(&original).as_bytes())
    );
    Ok(())
}

#[test]
fn descriptors_reject_gaps_duplicates_oversized_pages_and_unmatched_responses() -> TestResult {
    let bytes = object(ArcWireObjectKind::RootIdentity, 30, 1)?;
    let valid = descriptor(0, &bytes)?;
    let mut oversize = valid.clone();
    oversize.wire_kind = ArcWireObjectKind::WelcomeMls;
    oversize.total_size = 3 * 1024 * 1024;
    let mut second = oversize.clone();
    second.response_index = 1;
    let too_many = (0..=MAX_BATCH_OBJECTS)
        .map(|index| {
            let mut descriptor = valid.clone();
            descriptor.response_index = u16::try_from(index).map_err(|_| "index")?;
            Ok(descriptor)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let invalid = [
        vec![descriptor(1, &bytes)?],
        vec![valid.clone(), valid.clone()],
        vec![oversize, second],
        too_many,
    ];
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    for descriptors in invalid {
        let mut edge = waiting();
        assert!(receive(&mut edge, &mut fixture, None, &result(descriptors, 1)?).is_err());
        assert!(
            edge.pending
                .get(&REQUEST)
                .ok_or("pending")?
                .result
                .is_none()
        );
    }
    let mut edge = waiting();
    receive(&mut edge, &mut fixture, Some(1), &bytes)?;
    assert!(receive(&mut edge, &mut fixture, None, &result(vec![valid], 1)?).is_err());
    assert!(
        edge.pending
            .get(&REQUEST)
            .ok_or("pending")?
            .result
            .is_none()
    );
    Ok(())
}

#[test]
fn descriptors_bind_response_kind_length_and_content_in_both_orders() -> TestResult {
    let bytes = object(ArcWireObjectKind::RootIdentity, 30, 1)?;
    let valid = descriptor(0, &bytes)?;
    let mut wrong_kind = valid.clone();
    wrong_kind.wire_kind = ArcWireObjectKind::DeviceRoster;
    let mut wrong_size = valid.clone();
    wrong_size.total_size += 1;
    let mut wrong_hash = valid;
    wrong_hash.object_id = [99; 32];
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    for descriptor in [wrong_kind, wrong_size, wrong_hash] {
        for result_first in [false, true] {
            let mut edge = waiting();
            let result = result(vec![descriptor.clone()], 1)?;
            if result_first {
                receive(&mut edge, &mut fixture, None, &result)?;
                assert!(receive(&mut edge, &mut fixture, Some(0), &bytes).is_err());
                assert!(
                    edge.pending
                        .get(&REQUEST)
                        .ok_or("pending")?
                        .responses
                        .is_empty()
                );
            } else {
                receive(&mut edge, &mut fixture, Some(0), &bytes)?;
                assert!(receive(&mut edge, &mut fixture, None, &result).is_err());
                assert!(
                    edge.pending
                        .get(&REQUEST)
                        .ok_or("pending")?
                        .result
                        .is_none()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn a_response_bound_violation_closes_the_companion_link() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = waiting();
    edge.phase = Phase::Active;
    let mut base = EdgeFederation::new(EdgeConfig {
        network_id: NetworkId::from_bytes([1; 32]),
        server_id: ServerId::from_bytes([2; 16]),
        server_name: "edge.example".to_owned(),
        incarnation: ServerIncarnation::from_bytes([4; 16]),
        coordinator: PeerIdentity::new(
            ServerId::from_bytes([3; 16]),
            "coordinator.example",
            FederationRole::Coordinator,
            RecoveryEpoch::from_bytes([5; 16]),
            agenc_relay_crypto::Ed25519SecretKey::from_bytes([6; 32]).public_key(),
            [7; 32],
        ),
    });
    let bytes = object(ArcWireObjectKind::RootIdentity, 30, 1)?;
    let outputs = edge.handle_frames(fixture.context_mut()?, &mut base, frames(Some(32), &bytes)?);
    assert!(outputs.is_empty());
    assert_eq!(edge.phase, Phase::Down);
    assert_eq!(edge.counters.violations, 1);
    assert!(
        edge.pending
            .get(&REQUEST)
            .ok_or("pending")?
            .responses
            .is_empty()
    );
    Ok(())
}

#[test]
fn a_result_for_an_unknown_request_is_dropped_and_one_for_another_object_is_refused() -> TestResult
{
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = waiting();
    let result = result(Vec::new(), 1)?;
    let object_id = *ObjectId::compute(&result).as_bytes();
    let stray = Correlation {
        peer_server_id: [2; 16],
        server_incarnation: [4; 16],
        origin_id: [8; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: [6; 16],
    };
    for fragment in fragment_object(&result)? {
        let outputs = edge
            .on_result_frame(
                fixture.context_mut()?,
                CompanionFrame::Result {
                    correlation: stray,
                    object_id,
                    fragment,
                },
            )
            .map_err(|error| error.code.to_string())?;
        assert!(outputs.is_empty(), "a stray result answers nothing");
    }
    assert!(edge.pending.contains_key(&REQUEST));
    // The result names a request object this request did not send.
    let foreign = ArcFederationResult {
        profile_version: 1,
        network_id: [1; 32],
        home_server_id: [2; 16],
        server_incarnation: [4; 16],
        origin_id: [8; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: REQUEST,
        request_object_id: [8; 32],
        coordinator_state_generation: 1,
        completion_event_id: Opaque::new(Vec::new())?,
        result_kind: ArcFederationResultKind::ObjectPage,
        encoded_result: Opaque::new(Vec::new())?,
        snapshot_token: Opaque::new(vec![9; 32])?,
        next_cursor: Opaque::new(Vec::new())?,
        responses: TlsVec::new(Vec::new())?,
    };
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationResult, foreign.encode()?)?.encode()?;
    let mut refused = false;
    for frame in frames(None, &bytes)? {
        if edge.on_result_frame(fixture.context_mut()?, frame).is_err() {
            refused = true;
        }
    }
    assert!(refused, "a result for another request object is refused");
    Ok(())
}
