//! Opaque credential responses wait for durable ordered completion coverage.
#![forbid(unsafe_code)]

use super::*;

fn credential_request() -> TestResult<(RequestHeader, Vec<u8>)> {
    let (mut header, _) = request_fixture()?;
    // The edge treats this sealed envelope as opaque. This test exercises
    // forwarding and receipt ownership, not account-service decryption.
    let private = agenc_relay_crypto::AccountHpkePrivateKey::from_bytes([40; 32])?;
    let public = private.public_key()?;
    let binding = agenc_relay_crypto::AccountRequestBinding::new(
        NETWORK,
        COORDINATOR_EPOCH,
        public.key_id(),
        header.request_id,
        agenc_relay_types::AccountServiceMessageKind::CredentialChangeFinish,
    );
    let (sealed, _) = agenc_relay_crypto::seal_account_request(
        public,
        binding,
        &[0; agenc_relay_crypto::ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES],
    )?;
    let envelope = agenc_relay_auth::AccountServiceEnvelope::from_sealed(sealed)?;
    let mut budget = DecodeBudget::new(8192, 64);
    let operation = FederatedOperation::AccountService {
        opcode: agenc_relay_types::FederationOpcode::CredentialChangeFinish,
        session_id: Some(SessionId::from_bytes([21; 16])),
        envelope: SchemaObject::decode_exact(
            "AccountServiceEnvelope",
            envelope.as_bytes(),
            &mut budget,
        )?,
    };
    header.opcode = operation.opcode();
    let bytes = header
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    Ok((header, bytes))
}

async fn prepared(
    barrier: bool,
) -> TestResult<(StateCoreFixture, EdgeFederation, E2eeEdge, RequestHeader)> {
    let (header, bytes) = credential_request()?;
    let mut rows = completion_rows(&header)?;
    if !barrier {
        let origin = rows.pop().ok_or("origin")?;
        rows.truncate(2);
        rows.push(origin);
    }
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    let (mut base, mut companion) = edges();
    fixture.restore_edge_state(&mut base, Some(&mut companion))?;
    base.phase = Phase::Active;
    install_request(&mut base, header, bytes.clone())?;
    base.pending
        .get_mut(&header.request_id)
        .ok_or("pending")?
        .kind = PendingKind::AccountCarrier {
        sasl: false,
        finish: true,
        carrier_generation: 7,
    };
    let reply = WireMessage::new(EDGE_NAME, "ACCTCRED", &["DATA", "AA"], None)?;
    let (descriptor, result) = result_object(&header, &bytes, vec![reply])?;
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

fn complete(
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

fn assert_changed(outputs: Vec<EdgeCompletion>) -> TestResult {
    let [
        EdgeCompletion::CredentialCarrier {
            generation,
            carrier_generation,
            finish,
            outcome: RemoteCarrierOutcome::CredentialChanged { chunks },
        },
    ] = outputs.as_slice()
    else {
        return Err("covered credential result must finish exactly one transfer".into());
    };
    assert_eq!(*generation, ConnectionGeneration::new(1));
    assert_eq!(*carrier_generation, 7);
    assert!(*finish);
    assert_eq!(chunks, &["AA"]);
    Ok(())
}

#[tokio::test]
async fn credential_result_waits_for_ordinary_completion_receipt() -> TestResult {
    let (mut fixture, mut base, _companion, header) = prepared(false).await?;
    complete(&mut base, &mut fixture, header)?;
    assert!(base.pending.contains_key(&header.request_id));
    assert_changed(commit_edge_batches(&mut base, &mut fixture).await?)?;
    assert!(!base.pending.contains_key(&header.request_id));
    assert!(base.batch_applied(fixture.context_mut()?).is_empty());
    Ok(())
}

#[tokio::test]
async fn credential_result_waits_for_joint_barrier_receipt() -> TestResult {
    let (mut fixture, mut base, mut companion, header) = prepared(true).await?;
    let (writes, outputs) = companion
        .prepare_barrier(fixture.context_mut()?, &base, MUTATION)
        .map_err(|e| e.to_string())?;
    assert!(outputs.is_empty());
    assert!(base.apply_barrier(fixture.context_mut()?, writes, outputs));
    assert!(base.pending.contains_key(&header.request_id));
    assert_changed(commit_edge_batches(&mut base, &mut fixture).await?)?;
    assert!(!base.pending.contains_key(&header.request_id));
    assert!(base.barrier_applied(&MUTATION));
    Ok(())
}
