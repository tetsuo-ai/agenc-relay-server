#![forbid(unsafe_code)]

//! Base results and completion events meet only after durable application.

use agenc_ircd_federation_wire::ReplayKey;
use agenc_ircd_types::{FederationOpcode, OriginId, RequestId};

use super::*;

const REQUEST: RequestId = RequestId::from_bytes([41; 16]);
const EVENT: EventId = EventId::from_bytes([42; 16]);

fn pending_edge() -> TestResult<EdgeFederation> {
    let mut edge = edge_with_projection()?;
    let header = RequestHeader {
        network_id: NETWORK,
        replay_key: ReplayKey {
            home_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id: OriginId::from_bytes([40; 16]),
            origin_generation: 0,
            operation_sequence: 0,
        },
        request_id: REQUEST,
        opcode: FederationOpcode::from_wire(1)?,
    };
    edge.pending.insert(
        REQUEST,
        request::PendingRequest {
            generation: ConnectionGeneration::new(1),
            kind: request::PendingKind::Command {
                message: Box::new(parse_message(FramedLine::new("NICK after")?)?.ok_or("message")?),
            },
            header,
            bytes: vec![1, 2, 3],
            sent: true,
            result: None,
            replies: Vec::new(),
            completion: None,
            completion_generation: None,
        },
    );
    Ok(edge)
}

fn assembled(
    bytes: &[u8],
    frame: impl Fn(agenc_ircd_federation_wire::FederationFragment) -> FederationFrame,
) -> TestResult<AssembledObject> {
    let mut assembler = FragmentAssembler::new();
    for fragment in split_fragments(federation_object_id(bytes), bytes)? {
        let frame = frame(fragment);
        let (_, key) = carrier_of(&frame).map_err(|error| error.to_string())?;
        if let AssemblyProgress::Complete(object) =
            assembler.admit(key, frame.fragment().ok_or("fragment")?, 0)?
        {
            return Ok(object);
        }
    }
    Err("object did not assemble".into())
}

fn completion_object(
    edge: &EdgeFederation,
) -> TestResult<(agenc_ircd_federation_wire::EventDescriptor, AssembledObject)> {
    completion_object_at(edge, 10, 10)
}

fn completion_object_at(
    edge: &EdgeFederation,
    header_generation: u64,
    arm_generation: u64,
) -> TestResult<(agenc_ircd_federation_wire::EventDescriptor, AssembledObject)> {
    let pending = edge.pending.get(&REQUEST).ok_or("pending")?;
    let event = ProjectedEvent::RequestCompleted {
        resulting_state_generation: arm_generation,
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: header_generation,
        delivery_sequence: 0,
        event_id: EVENT,
        event_kind: event.kind(),
        correlation: Some(RequestCorrelation {
            replay_key: pending.header.replay_key,
            request_id: REQUEST,
        }),
        cross_profile: None,
    };
    let arm = event_arm_object(&event).map_err(|error| format!("{error:?}"))?;
    let bytes = header.build(&arm)?.encode_canonical()?;
    let descriptor = agenc_ircd_federation_wire::EventDescriptor {
        target_server_id: EDGE,
        delivery_sequence: 0,
        event_id: EVENT,
        object_id: federation_object_id(bytes.as_slice()),
    };
    let object = assembled(bytes.as_slice(), |fragment| FederationFrame::Event {
        descriptor,
        fragment,
    })?;
    Ok((descriptor, object))
}

fn deliver_result(
    edge: &mut EdgeFederation,
    fixture: &mut StateCoreFixture,
) -> TestResult<Vec<EdgeCompletion>> {
    deliver_result_arm(
        edge,
        fixture,
        ResultArm::Committed {
            resulting_state_generation: 10,
        },
        Some(EVENT),
    )
}

fn deliver_result_arm(
    edge: &mut EdgeFederation,
    fixture: &mut StateCoreFixture,
    arm: ResultArm,
    completion_event_id: Option<EventId>,
) -> TestResult<Vec<EdgeCompletion>> {
    let (descriptor, object) = result_object(edge, arm, completion_event_id)?;
    request::receive_result(edge, fixture.context_mut()?, descriptor, &object)
        .map_err(|error| format!("{error:?}").into())
}

fn result_object(
    edge: &EdgeFederation,
    arm: ResultArm,
    completion_event_id: Option<EventId>,
) -> TestResult<(OperationDescriptor, AssembledObject)> {
    let pending = edge.pending.get(&REQUEST).ok_or("pending")?;
    let canonical_completion = if matches!(
        arm,
        ResultArm::Committed { .. } | ResultArm::SessionRegistered(_)
    ) {
        completion_event_id.or(Some(EVENT))
    } else {
        None
    };
    let header = ResultHeader {
        network_id: NETWORK,
        replay_key: pending.header.replay_key,
        request_id: REQUEST,
        request_object_id: federation_object_id(&pending.bytes),
        completion_event_id: canonical_completion,
        result_kind: arm.kind(),
    };
    let encoded = header
        .build(
            &arm.to_object().map_err(|error| format!("{error:?}"))?,
            Vec::new(),
        )?
        .encode_canonical()?;
    let mut bytes = encoded.as_slice().to_vec();
    if canonical_completion != completion_event_id {
        // The constructor rejects forbidden result shapes. Mutate only the
        // length-prefixed completion field to exercise the receive decoder.
        const COMPLETION_OFFSET: usize = 2 + 32 + 3 * 16 + 2 * 8 + 16 + 32;
        let old_length = usize::from(*bytes.get(COMPLETION_OFFSET).ok_or("completion length")?);
        let replacement: Vec<u8> = match completion_event_id {
            Some(event) => core::iter::once(16)
                .chain(event.as_bytes().iter().copied())
                .collect(),
            None => vec![0],
        };
        bytes.splice(
            COMPLETION_OFFSET..COMPLETION_OFFSET + 1 + old_length,
            replacement,
        );
    }
    let descriptor = OperationDescriptor {
        addressed_server_id: EDGE,
        server_incarnation: EDGE_INCARNATION,
        origin_id: header.replay_key.origin_id,
        origin_generation: 0,
        operation_sequence: 0,
        request_id: REQUEST,
        object_id: federation_object_id(&bytes),
    };
    let object = assembled(&bytes, |fragment| FederationFrame::Result {
        descriptor,
        fragment,
    })?;
    Ok((descriptor, object))
}

#[tokio::test]
async fn completion_results_before_during_and_after_storage_wait_for_commit() -> TestResult {
    for order in 0..3 {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = pending_edge()?;
        let (descriptor, object) = completion_object(&edge)?;
        if order == 0 {
            assert!(deliver_result(&mut edge, &mut fixture)?.is_empty());
        }
        assert!(
            events::receive(&mut edge, fixture.context_mut()?, descriptor, &object)
                .is_ok_and(|outputs| outputs.is_empty())
        );
        assert!(
            edge.applied_completions.is_empty(),
            "completion escaped before storage"
        );
        if order == 1 {
            assert!(deliver_result(&mut edge, &mut fixture)?.is_empty());
        }
        assert!(edge.pending.contains_key(&REQUEST));
        let outputs = edge.batch_applied(fixture.context_mut()?);
        if order == 2 {
            assert!(outputs.is_empty());
            assert!(edge.applied_completions.contains(&EVENT));
            assert_eq!(deliver_result(&mut edge, &mut fixture)?.len(), 1);
        } else {
            assert_eq!(outputs.len(), 1);
        }
        assert!(!edge.pending.contains_key(&REQUEST));
        assert!(edge.by_completion.is_empty());
        assert!(edge.applied_completions.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn refused_completion_storage_cannot_release_a_later_result() -> TestResult {
    for refused_admission in [true, false] {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = pending_edge()?;
        let (descriptor, object) = completion_object(&edge)?;
        if refused_admission {
            fixture
                .state_mut()?
                .step_message(StateCoreMessage::Signal(SignalEvent::Terminate));
        }
        let result = events::receive(&mut edge, fixture.context_mut()?, descriptor, &object);
        assert_eq!(result.is_err(), refused_admission);
        assert!(
            edge.applied_completions.is_empty(),
            "refused work retained a completion marker"
        );
        assert!(deliver_result(&mut edge, &mut fixture)?.is_empty());
        assert!(edge.pending.contains_key(&REQUEST));
        drop(fixture);
        let mut recovered = StateCoreFixture::new(entropy_script())?;
        if !refused_admission {
            edge.batch_rejected(recovered.context_mut()?);
        }
        assert_eq!(edge.cursor, None);
        assert!(events::receive(&mut edge, recovered.context_mut()?, descriptor, &object).is_ok());
        assert_eq!(edge.batch_applied(recovered.context_mut()?).len(), 1);
        assert!(!edge.pending.contains_key(&REQUEST));
    }
    Ok(())
}

#[tokio::test]
async fn completion_markers_live_only_as_long_as_their_pending_request() -> TestResult {
    for leave_before_commit in [true, false] {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = pending_edge()?;
        let (descriptor, object) = completion_object(&edge)?;
        assert!(events::receive(&mut edge, fixture.context_mut()?, descriptor, &object).is_ok());
        if leave_before_commit {
            edge.pending
                .remove(&REQUEST)
                .ok_or("pending")?
                .sink_gone(&mut edge);
        }
        assert!(edge.batch_applied(fixture.context_mut()?).is_empty());
        if !leave_before_commit {
            assert!(edge.applied_completions.contains(&EVENT));
            edge.pending
                .remove(&REQUEST)
                .ok_or("pending")?
                .sink_gone(&mut edge);
        }
        assert!(edge.pending.is_empty());
        assert!(edge.applied_completions.is_empty());
        assert!(edge.by_completion.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn nonterminal_results_cannot_consume_a_durable_completion() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = pending_edge()?;
    let (descriptor, object) = completion_object(&edge)?;
    assert!(events::receive(&mut edge, fixture.context_mut()?, descriptor, &object).is_ok());
    assert!(edge.batch_applied(fixture.context_mut()?).is_empty());
    let error = deliver_result_arm(
        &mut edge,
        &mut fixture,
        ResultArm::Failed {
            code: "UNAVAILABLE".to_owned(),
            context: String::new(),
        },
        Some(EVENT),
    )
    .err()
    .ok_or("nonterminal result consumed the committed marker")?;
    assert_eq!(error.to_string(), "Codec");
    assert!(
        edge.pending
            .get(&REQUEST)
            .is_some_and(|pending| pending.result.is_none())
    );
    assert!(edge.applied_completions.contains(&EVENT));
    assert_eq!(deliver_result(&mut edge, &mut fixture)?.len(), 1);
    assert!(edge.applied_completions.is_empty());
    Ok(())
}

#[tokio::test]
async fn terminal_results_without_completions_do_not_mutate_pending_state() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = pending_edge()?;
    let error = deliver_result_arm(
        &mut edge,
        &mut fixture,
        ResultArm::Committed {
            resulting_state_generation: 10,
        },
        None,
    )
    .err()
    .ok_or("terminal result omitted its completion")?;
    assert_eq!(error.to_string(), "Codec");
    assert!(
        edge.pending
            .get(&REQUEST)
            .is_some_and(|pending| pending.result.is_none())
    );
    assert!(edge.by_completion.is_empty());
    assert!(edge.applied_completions.is_empty());
    Ok(())
}

#[tokio::test]
async fn completion_generations_must_match_in_every_result_arrival_order() -> TestResult {
    for order in 0..3 {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = pending_edge()?;
        let (descriptor, object) = completion_object(&edge)?;
        if order == 0 {
            assert!(
                deliver_result_arm(
                    &mut edge,
                    &mut fixture,
                    ResultArm::Committed {
                        resulting_state_generation: 11
                    },
                    Some(EVENT)
                )?
                .is_empty()
            );
            assert!(matches!(
                events::receive(&mut edge, fixture.context_mut()?, descriptor, &object),
                Err(Violation::Consistency)
            ));
            assert!(edge.commit.is_none());
            assert_eq!(edge.cursor, None);
        } else {
            assert!(
                events::receive(&mut edge, fixture.context_mut()?, descriptor, &object).is_ok()
            );
            if order == 2 {
                assert!(edge.batch_applied(fixture.context_mut()?).is_empty());
            }
            let error = deliver_result_arm(
                &mut edge,
                &mut fixture,
                ResultArm::Committed {
                    resulting_state_generation: 11,
                },
                Some(EVENT),
            )
            .err()
            .ok_or("mismatched result generation accepted")?;
            assert_eq!(error.to_string(), "Consistency");
            assert!(
                edge.pending
                    .get(&REQUEST)
                    .is_some_and(|pending| pending.result.is_none())
            );
            let outputs = deliver_result(&mut edge, &mut fixture)?;
            if order == 1 {
                assert!(outputs.is_empty());
                assert_eq!(edge.batch_applied(fixture.context_mut()?).len(), 1);
            } else {
                assert_eq!(outputs.len(), 1);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn completion_header_and_arm_generations_must_agree_before_staging() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = pending_edge()?;
    let (descriptor, object) = completion_object_at(&edge, 10, 11)?;
    assert!(matches!(
        events::receive(&mut edge, fixture.context_mut()?, descriptor, &object),
        Err(Violation::Consistency)
    ));
    assert!(edge.commit.is_none());
    assert!(edge.event_before.is_none());
    assert_eq!(edge.cursor, None);
    assert!(edge.pending.contains_key(&REQUEST));
    Ok(())
}

#[tokio::test]
async fn completion_correlation_must_match_the_retained_request_replay_key() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = pending_edge()?;
    let mut other_request = pending_edge()?;
    other_request
        .pending
        .get_mut(&REQUEST)
        .ok_or("pending")?
        .header
        .replay_key
        .operation_sequence = 1;
    let (descriptor, object) = completion_object(&other_request)?;
    assert!(matches!(
        events::receive(&mut edge, fixture.context_mut()?, descriptor, &object),
        Err(Violation::Consistency)
    ));
    assert!(edge.pending.contains_key(&REQUEST));
    assert!(edge.commit.is_none());
    assert!(edge.applied_completions.is_empty());
    Ok(())
}

#[tokio::test]
async fn result_replay_and_object_ids_must_match_the_retained_request() -> TestResult {
    for changed_object in [false, true] {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = pending_edge()?;
        let mut other_request = pending_edge()?;
        let pending = other_request.pending.get_mut(&REQUEST).ok_or("pending")?;
        if changed_object {
            pending.bytes.push(4);
        } else {
            pending.header.replay_key.operation_sequence = 1;
        }
        let (descriptor, object) = result_object(
            &other_request,
            ResultArm::Committed {
                resulting_state_generation: 10,
            },
            Some(EVENT),
        )?;
        assert!(matches!(
            request::receive_result(&mut edge, fixture.context_mut()?, descriptor, &object),
            Err(Violation::Consistency)
        ));
        assert!(
            edge.pending
                .get(&REQUEST)
                .is_some_and(|pending| pending.result.is_none())
        );
        assert!(edge.by_completion.is_empty());
        assert!(edge.applied_completions.is_empty());
    }
    Ok(())
}
