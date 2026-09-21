#![forbid(unsafe_code)]

//! A deletion closes only after its exact result is durably covered.

use super::*;

fn deletion_request() -> TestResult<(RequestHeader, Vec<u8>)> {
    let (mut header, _) = request_fixture()?;
    let operation = FederatedOperation::AccountSettings {
        session_id: SessionId::from_bytes([21; 16]),
        expected_account_revision: 1,
        setting_kind: 12,
        value: vec![28; 16],
    };
    header.opcode = operation.opcode();
    let bytes = header
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    Ok((header, bytes))
}

fn final_reply(accepted: bool) -> TestResult<WireMessage> {
    Ok(if accepted {
        WireMessage::new(
            EDGE_NAME,
            "NOTE",
            &["ACCT", "UPDATED"],
            Some("Account setting updated"),
        )?
    } else {
        WireMessage::new(
            EDGE_NAME,
            "FAIL",
            &["ACCT", "BAD_STATE"],
            Some("Command is not valid in this state"),
        )?
    })
}

async fn prepared_deletion(
    barrier: bool,
    accepted: bool,
) -> TestResult<(StateCoreFixture, EdgeFederation, E2eeEdge, RequestHeader)> {
    let (header, bytes) = deletion_request()?;
    let mut rows = completion_rows(&header)?;
    if !barrier {
        let origin = rows.pop().ok_or("origin row")?;
        rows.truncate(2);
        rows.push(origin);
    }
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    base.phase = Phase::Active;
    install_request(&mut base, header, bytes.clone())?;
    let token = agenc_relay_admin::encode_base64url(&[28; 16]);
    let message = parse_message(FramedLine::new(&format!("ACCT DELETE CONFIRM {token}"))?)?
        .ok_or("deletion command")?;
    base.pending
        .get_mut(&header.request_id)
        .ok_or("pending request")?
        .kind = PendingKind::Command {
        message: Box::new(message),
    };
    let (descriptor, result) = result_object(&header, &bytes, vec![final_reply(accepted)?])?;
    assert!(
        request::receive_result(&mut base, fixture.context_mut()?, descriptor, &result)
            .is_ok_and(|outputs| outputs.is_empty())
    );
    assert!(
        commit_edge_batches(&mut base, &mut fixture)
            .await?
            .is_empty()
    );
    assert!(base.pending.contains_key(&header.request_id));
    Ok((fixture, base, companion, header))
}

fn ordinary_completion(
    base: &mut EdgeFederation,
    fixture: &mut StateCoreFixture,
    request: RequestHeader,
) -> TestResult {
    let event = ProjectedEvent::RequestCompleted {
        resulting_state_generation: 10,
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: 10,
        delivery_sequence: 0,
        event_id: EventId::from_bytes([78; 16]),
        event_kind: event.kind(),
        correlation: Some(RequestCorrelation {
            replay_key: request.replay_key,
            request_id: request.request_id,
        }),
        cross_profile: None,
    };
    let bytes = header
        .build(&event_arm_object(&event).map_err(|e| format!("{e:?}"))?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    let descriptor = agenc_relay_federation_wire::EventDescriptor {
        target_server_id: EDGE,
        delivery_sequence: 0,
        event_id: header.event_id,
        object_id: federation_object_id(&bytes),
    };
    let object = resync_assembled(&bytes, |fragment| FederationFrame::Event {
        descriptor,
        fragment,
    })?;
    assert!(
        events::receive(base, fixture.context_mut()?, descriptor, &object)
            .is_ok_and(|outputs| outputs.is_empty())
    );
    Ok(())
}

fn assert_deleted(outputs: Vec<EdgeCompletion>) -> TestResult {
    let [
        EdgeCompletion::AccountDeleted {
            generation,
            frames,
            message,
        },
    ] = outputs.as_slice()
    else {
        return Err("covered deletion did not close its requester".into());
    };
    assert_eq!(*generation, ConnectionGeneration::new(1));
    assert_eq!(frames, &[final_reply(true)?]);
    assert_eq!(message.command(), "ACCT");
    Ok(())
}

#[tokio::test]
async fn ordinary_deletion_closes_only_after_its_completion_commits() -> TestResult {
    let (mut fixture, mut base, _companion, header) = prepared_deletion(false, true).await?;
    ordinary_completion(&mut base, &mut fixture, header)?;
    assert!(base.pending.contains_key(&header.request_id));
    assert_deleted(commit_edge_batches(&mut base, &mut fixture).await?)?;
    assert!(!base.pending.contains_key(&header.request_id));
    assert!(base.batch_applied(fixture.context_mut()?).is_empty());
    Ok(())
}

#[tokio::test]
async fn barrier_deletion_closes_only_after_its_joint_receipt_commits() -> TestResult {
    let (mut fixture, mut base, mut companion, header) = prepared_deletion(true, true).await?;
    let (writes, outputs) = companion
        .prepare_barrier(fixture.context_mut()?, &base, MUTATION)
        .map_err(|e| e.to_string())?;
    assert!(outputs.is_empty());
    assert!(base.apply_barrier(fixture.context_mut()?, writes, outputs));
    assert!(base.pending.contains_key(&header.request_id));
    assert!(!base.barrier_applied(&MUTATION));
    assert_deleted(commit_edge_batches(&mut base, &mut fixture).await?)?;
    assert!(base.barrier_applied(&MUTATION));
    assert!(!base.pending.contains_key(&header.request_id));
    assert!(base.batch_applied(fixture.context_mut()?).is_empty());
    Ok(())
}

#[tokio::test]
async fn rejected_deletion_confirmation_keeps_its_client_open() -> TestResult {
    let (mut fixture, mut base, _companion, header) = prepared_deletion(false, false).await?;
    ordinary_completion(&mut base, &mut fixture, header)?;
    let outputs = commit_edge_batches(&mut base, &mut fixture).await?;
    assert!(
        matches!(outputs.as_slice(), [EdgeCompletion::Replies { frames, .. }]
        if frames == &[final_reply(false)?])
    );
    Ok(())
}
