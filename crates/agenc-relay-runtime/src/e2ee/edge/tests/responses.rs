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
    let mailbox = descriptors
        .iter()
        .any(|d| !d.delivery_token.as_slice().is_empty());
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
        result_kind: if mailbox {
            ArcFederationResultKind::MailboxPage
        } else {
            ArcFederationResultKind::ObjectPage
        },
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

/// A physically small attached client queue can carry a legal mailbox
/// response larger than a thousand IRC frames without widening its limits.
#[tokio::test]
async fn a_large_mailbox_reply_reaches_the_attached_client_in_order() -> TestResult {
    use crate::connection::{ClientSink, QueueLimits, WriterQueue};
    use crate::state_core::inbox::{CloseReason, SourceAddressKey};
    use agenc_relay_client_wire::WireMessage;
    use agenc_relay_e2ee::limits::MAX_FRAGMENT_RAW;
    use agenc_relay_e2ee::wire::command::MailboxKind;
    use agenc_relay_e2ee::wire::fragment::{FragmentTag, SERVER_FRAGMENT_TAG};
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt as _, BufReader};

    let mut fixture = StateCoreFixture::new(vec![0; 4096])?;
    let mut edge = waiting();
    let pending = edge
        .pending
        .get_mut(&REQUEST)
        .ok_or("missing mailbox origin")?;
    pending.command = Resolved::Command(ClientCommand::Ekey(EkeyCommand::FetchMailbox {
        kind: MailboxKind::Welcome,
        cursor: None,
    }));
    let generation = pending.generation;
    let queue = WriterQueue::new(generation, QueueLimits::DEFAULT)?;
    let context = fixture.context_mut()?;
    let now = context.now();
    context.sessions_mut().open(
        generation,
        crate::purpose::ListenerPurpose::ClientTls,
        SourceAddressKey::onion_listener(),
        Arc::clone(&queue) as Arc<dyn ClientSink>,
        now,
    )?;
    let notice = |text| WireMessage::new("edge.example", "NOTICE", &["nick"], Some(text));
    context.set_monotonic_for_test(100);
    context.begin_secret_floor(generation);
    assert!(
        context
            .hold_secret_floor(generation, vec![notice("before")?])
            .is_ok()
    );
    let bytes = object(ArcWireObjectKind::WelcomeMls, 3 * 1024 * 1024 + 17, 19)?;
    let object_id = ObjectId::compute(&bytes);
    let mut described = descriptor(0, &bytes)?;
    described.delivery_token = Opaque::new(vec![5; 32])?;
    described.target_device_id = Opaque::new(vec![4; 16])?;
    let result = result(vec![described], 1)?;
    assert!(receive(&mut edge, &mut fixture, None, &result)?.is_empty());
    let outputs = receive(&mut edge, &mut fixture, Some(0), &bytes)?;
    assert_eq!(outputs.len(), 1);
    let context = fixture.context_mut()?;
    for output in outputs {
        context.send_companion_output(output);
    }
    context.send_to(generation, vec![notice("after")?])?;
    assert_eq!(queue.queue_snapshot().queued_bytes(), 0);
    context.set_monotonic_for_test(200);
    assert!(context.release_secret_floor(generation));
    let occupied = queue.queue_snapshot().queued_bytes();
    assert!(
        occupied < 8704 && occupied > 2940,
        "one physical window: {occupied}"
    );
    queue.close(
        CloseReason::Shutdown,
        crate::connection::ClosePolicy::AfterFlush,
    );
    let (left, right) = tokio::io::duplex(4096);
    let writer = crate::connection::run_writer(
        left,
        Arc::clone(&queue),
        crate::cancel::CancellationToken::root(),
    );
    let read = async {
        let mut reader = BufReader::new(right);
        let mut line = String::new();
        let mut fragments = 0;
        let mut stage = 0;
        while reader.read_line(&mut line).await? != 0 {
            assert!(line.ends_with("\r\n") && line.len() <= 8703);
            if line.contains(" EOBJECT ") {
                assert_eq!(stage, 3);
                let tag = line
                    .split(' ')
                    .next()
                    .and_then(|tags| {
                        tags.split(';').find_map(|tag| {
                            tag.strip_prefix(SERVER_FRAGMENT_TAG)?.strip_prefix('=')
                        })
                    })
                    .ok_or("missing eobject tag")?;
                let fragment = FragmentTag::parse(tag)?;
                assert_eq!(fragment.object_id, object_id);
                assert_eq!(fragment.part as usize, fragments);
                let start = fragments * MAX_FRAGMENT_RAW;
                let end = (start + MAX_FRAGMENT_RAW).min(bytes.len());
                assert_eq!(Some(fragment.segment.as_slice()), bytes.get(start..end));
                fragments += 1;
            } else {
                match stage {
                    0 => assert!(line.contains(" NOTICE nick :before")),
                    1 => assert!(line.starts_with("@label=fetch ") && line.contains(" BATCH +")),
                    2 => assert!(line.contains(" MAILBOX ")),
                    3 => {
                        assert!(line.contains(" BATCH -"));
                        assert_eq!(fragments, bytes.len().div_ceil(MAX_FRAGMENT_RAW));
                    }
                    4 => assert!(line.contains(" NOTICE nick :after")),
                    _ => return Err("unexpected client line".into()),
                }
                stage += 1;
            }
            line.clear();
        }
        assert_eq!(stage, 5);
        assert!(fragments > 1024);
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (reason, read) = tokio::time::timeout(std::time::Duration::from_secs(25), async {
        tokio::join!(writer, read)
    })
    .await?;
    assert_eq!(reason, CloseReason::Shutdown);
    read?;
    assert_eq!(queue.queue_snapshot().queued_bytes(), 0);
    Ok(())
}
