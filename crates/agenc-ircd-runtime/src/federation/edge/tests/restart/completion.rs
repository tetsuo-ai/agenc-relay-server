#![forbid(unsafe_code)]

//! A result received first waits for the joint barrier's durable completion.

use super::*;
use crate::federation::edge::request::{PendingKind, PendingRequest};
use agenc_ircd_federation_wire::ReplayKey;
use agenc_ircd_types::{OriginId, RequestId};

fn request_fixture() -> TestResult<(RequestHeader, Vec<u8>)> {
    let operation = FederatedOperation::Part {
        session_id: SessionId::from_bytes([21; 16]),
        expected_session_revision: 1,
        all_channels: false,
        channels: vec![ChannelInstanceId::from_bytes([22; 16])],
        reason: "leave encrypted channel".to_owned(),
    };
    let header = RequestHeader {
        network_id: NETWORK,
        replay_key: ReplayKey {
            home_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id: OriginId::from_bytes([23; 16]),
            origin_generation: 1,
            operation_sequence: 0,
        },
        request_id: RequestId::from_bytes([24; 16]),
        opcode: operation.opcode(),
    };
    let bytes = header
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    Ok((header, bytes))
}

fn completion_rows(request: &RequestHeader) -> TestResult<Vec<InitialStorageRecord>> {
    let (mut parts, payload) = parts()?;
    let part = parts.first_mut().ok_or("base part")?;
    let event = ProjectedEvent::RequestCompleted {
        resulting_state_generation: 10,
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: 10,
        delivery_sequence: 0,
        event_id: EventId::from_bytes(part.event_id),
        event_kind: event.kind(),
        correlation: Some(RequestCorrelation {
            replay_key: request.replay_key,
            request_id: request.request_id,
        }),
        cross_profile: Some(agenc_ircd_federation_wire::CrossProfilePart {
            mutation_id: MUTATION,
            part_index: 0,
            part_count: 2,
        }),
    };
    let bytes = header
        .build(&event_arm_object(&event).map_err(|e| format!("{e:?}"))?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    part.event_object_id = *federation_object_id(&bytes).as_bytes();
    part.encoded_event_object = bytes;
    let mut rows = crash_rows(0, false)?;
    rows.truncate(2); // Preserve the committed peer and witnessed cursor.
    let mut assembly = BarrierAssembly::open(identity(2))?;
    for part in parts {
        rows.push(record(
            TableId::E2eeState,
            BARRIER_ROW_KIND,
            part.identity.part_key(part.part_index)?,
            part.encode()?,
        )?);
        assembly.stage(part)?;
    }
    rows.push(record(
        TableId::E2eeState,
        BARRIER_ROW_KIND,
        identity(2).head_key()?,
        BarrierHead::Stage(assembly.head().clone()).encode()?,
    )?);
    let payload = ObjectRow::new(payload)?;
    rows.push(record(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        payload.key()?,
        payload.encode()?,
    )?);
    Ok(rows)
}

fn result_object(
    header: &RequestHeader,
    request: &[u8],
) -> TestResult<(OperationDescriptor, AssembledObject)> {
    let arm = ResultArm::Committed {
        resulting_state_generation: 10,
    };
    let result = ResultHeader {
        network_id: NETWORK,
        replay_key: header.replay_key,
        request_id: header.request_id,
        request_object_id: federation_object_id(request),
        completion_event_id: Some(EventId::from_bytes([78; 16])),
        result_kind: arm.kind(),
    };
    let bytes = result
        .build(&arm.to_object()?, Vec::new())?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    let descriptor = OperationDescriptor {
        addressed_server_id: COORDINATOR,
        server_incarnation: header.replay_key.server_incarnation,
        origin_id: header.replay_key.origin_id,
        origin_generation: header.replay_key.origin_generation,
        operation_sequence: header.replay_key.operation_sequence,
        request_id: header.request_id,
        object_id: federation_object_id(&bytes),
    };
    let mut assembler = FragmentAssembler::new();
    for fragment in split_fragments(descriptor.object_id, &bytes)? {
        let frame = FederationFrame::Result {
            descriptor,
            fragment,
        };
        let (_, key) = carrier_of(&frame).map_err(|e| e.to_string())?;
        if let AssemblyProgress::Complete(object) =
            assembler.admit(key, frame.fragment().ok_or("fragment")?, 0)?
        {
            return Ok((descriptor, object));
        }
    }
    Err("incomplete result".into())
}

fn install_request(base: &mut EdgeFederation, header: RequestHeader, bytes: Vec<u8>) -> TestResult {
    let message = parse_message(FramedLine::new("PART #encrypted")?)?.ok_or("command")?;
    base.pending.insert(
        header.request_id,
        PendingRequest {
            generation: ConnectionGeneration::new(1),
            kind: PendingKind::Command {
                message: Box::new(message),
            },
            header,
            bytes,
            sent: true,
            result: None,
            replies: Vec::new(),
            completion: None,
            completion_generation: None,
        },
    );
    Ok(())
}

#[tokio::test]
async fn a_result_first_barrier_retires_its_request_only_after_the_durable_receipt() -> TestResult {
    let (header, request_bytes) = request_fixture()?;
    let mut fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        completion_rows(&header)?,
    )?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    base.phase = Phase::Active;
    install_request(&mut base, header, request_bytes.clone())?;
    let (descriptor, result) = result_object(&header, &request_bytes)?;
    assert!(
        request::receive_result(&mut base, fixture.context_mut()?, descriptor, &result)
            .is_ok_and(|outputs| outputs.is_empty())
    );
    assert!(base.pending.contains_key(&header.request_id));
    let (writes, outputs) = companion
        .prepare_barrier(fixture.context_mut()?, &base, MUTATION)
        .map_err(|e| e.to_string())?;
    assert!(outputs.is_empty());
    assert!(base.apply_barrier(fixture.context_mut()?, writes, outputs));
    assert!(base.pending.contains_key(&header.request_id));
    assert!(!base.barrier_applied(&MUTATION));
    assert!(
        !base
            .applied_completions
            .contains(&EventId::from_bytes([78; 16]))
    );
    let writes = fixture.context_mut()?.staged_rows_for_test()?;
    let (mut reloaded, mut reloaded_companion) = edges();
    fixture.commit_and_restore_edge(writes, &mut reloaded, Some(&mut reloaded_companion))?;
    assert!(reloaded.barrier_applied(&MUTATION));
    let outputs = base.batch_applied(fixture.context_mut()?);
    assert_eq!(outputs.len(), 1);
    assert!(
        matches!(outputs.first(), Some(EdgeCompletion::CommandCompleted { generation, message })
        if *generation == ConnectionGeneration::new(1) && message.command() == "PART")
    );
    assert!(!base.pending.contains_key(&header.request_id));
    assert!(
        !base
            .by_completion
            .contains_key(&EventId::from_bytes([78; 16]))
    );
    assert!(base.batch_applied(fixture.context_mut()?).is_empty());
    Ok(())
}
