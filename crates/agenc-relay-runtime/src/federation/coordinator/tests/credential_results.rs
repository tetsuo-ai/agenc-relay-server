//! Credential commits bind their exact response to the same durable completion.
#![forbid(unsafe_code)]

use super::*;
use crate::connection::ConnectionGeneration;
use crate::state_core::projector::{EdgeDelivery, FederationProjector};
use agenc_relay_storage::federation_records::{CoordinatorResultRecord, request_result_key};

const OWNER: ConnectionGeneration = ConnectionGeneration::new(1 << 62);

#[tokio::test]
async fn replayed_credential_success_commits_a_correlated_completion() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let peer = ServerId::from_bytes([50; 16]);
    let mut coordinator = standalone_coordinator(peer);
    let context = fixture.context_mut()?;
    let (mut fresh, _edge) = remote_account_staging_request(&mut coordinator, context)?;
    fresh.header.opcode = agenc_relay_types::FederationOpcode::CredentialChangeFinish;
    let request = fresh.header;
    let mut projector = FederationProjector::new(NETWORK, COORDINATOR);
    projector.set_edge(
        peer,
        EdgeDelivery {
            projection_generation: 1,
            next_delivery_sequence: 0,
        },
    );
    context.install_federation_projector(projector);
    let old_revision = context.domain().revision().get();
    super::super::request::finish_without_plan(
        &mut coordinator,
        context,
        LinkId::new(50),
        peer,
        fresh,
        ResultArm::Committed {
            resulting_state_generation: old_revision,
        },
        Vec::new(),
    )
    .map_err(|error| format!("replay checkpoint: {error:?}"))?;
    assert_eq!(context.pending_len(), 1);
    assert!(context.take_outbound_events().is_empty());
    fixture.commit_staged_batch().await?;
    let events = fixture.context_mut()?.take_outbound_events();
    let [event] = events.as_slice() else {
        return Err("replayed success must publish one correlated completion".into());
    };
    let record = read_result(&mut fixture, request).await?;
    let mut budget = DecodeBudget::new(1 << 20, 4096);
    let object =
        SchemaObject::decode_exact("FederationResult", &record.result_object, &mut budget)?;
    let header = ResultHeader::from_object(&object)?;
    assert_eq!(header.completion_event_id, Some(event.event_id));
    assert_eq!(record.completion_event_id, Some(*event.event_id.as_bytes()));
    let arm = decode_result_arm(&object, &mut budget)?;
    let ResultArm::Committed {
        resulting_state_generation,
    } = ResultArm::from_object(header.result_kind, &arm)?
    else {
        return Err("replayed credential success changed result kind".into());
    };
    assert!(resulting_state_generation > old_revision);
    assert_eq!(
        resulting_state_generation,
        record.resulting_state_generation
    );
    let object = SchemaObject::decode_exact("FederationEvent", &event.encoded, &mut budget)?;
    let event_header = EventHeader::from_object(&object)?;
    assert_eq!(
        event_header.coordinator_state_generation,
        resulting_state_generation
    );
    assert_eq!(
        event_header.correlation.ok_or("correlation")?.request_id,
        request.request_id
    );
    Ok(())
}

#[tokio::test]
async fn authentication_after_session_revocation_refuses_only_the_request() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let peer = ServerId::from_bytes([50; 16]);
    let mut coordinator = standalone_coordinator(peer);
    let context = fixture.context_mut()?;
    let (mut fresh, mut edge) = remote_account_staging_request(&mut coordinator, context)?;
    // An accepted registered origin can outlive its session until its home
    // edge applies SessionHidden. Represent that interval with no live session.
    let previous = coordinator
        .origins
        .origin(&fresh.key.origin)
        .ok_or("origin")?;
    let bytes = coordinator
        .origin_objects
        .get(&fresh.key.origin)
        .ok_or("origin bytes")?;
    let mut budget = DecodeBudget::new(8192, 64);
    let mut record = OriginRecord::from_object(&SchemaObject::decode_exact(
        "FederationOrigin",
        bytes,
        &mut budget,
    )?)?;
    record.generation = 1;
    record.previous_origin_object_id = previous.object_id;
    record.session = Some(OriginSession {
        session_id: SessionId::from_bytes([83; 16]),
        user_id: UserId::from_bytes([84; 16]),
    });
    let bytes = record.to_object()?.encode_canonical()?.as_slice().to_vec();
    coordinator
        .origins
        .update(agenc_relay_domain::federation::OriginDeclaration {
            origin: fresh.key.origin,
            generation: 1,
            previous_object_id: previous.object_id,
            binding: previous.binding,
            principal: agenc_relay_domain::federation::OriginPrincipal {
                session: Some((
                    SessionId::from_bytes([83; 16]),
                    UserId::from_bytes([84; 16]),
                )),
                account: None,
            },
            object_id: *federation_object_id(&bytes).as_bytes(),
        })?;
    coordinator.origin_objects.insert(fresh.key.origin, bytes);
    fresh.header.opcode = agenc_relay_types::FederationOpcode::OpaqueAuthStart;
    fresh.header.replay_key.origin_generation = 1;
    let request = fresh.header;
    let envelope = crate::test_support::sealed_authentication_start(
        NETWORK,
        RecoveryEpoch::from_bytes([34; 16]),
        "revoked-account",
        73,
    )?;
    let operation = FederatedOperation::AccountService {
        opcode: fresh.header.opcode,
        session_id: None,
        envelope: SchemaObject::decode_exact("AccountServiceEnvelope", &envelope, &mut budget)?,
    };
    let bytes = request
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    let descriptor = OperationDescriptor {
        origin_generation: 1,
        object_id: federation_object_id(&bytes),
        ..fresh.descriptor
    };
    let (carrier, object) = edge.assemble(&bytes, |fragment| FederationFrame::Request {
        descriptor,
        fragment,
    })?;
    assert!(coordinator.link_is_live(edge.link, peer));
    coordinator.inbound(
        context,
        FederationInbound {
            link: edge.link,
            peer,
            event: LinkEvent::Object { carrier, object },
            charge: None,
        },
    );
    assert!(
        coordinator.link_is_live(edge.link, peer),
        "revocation is a request refusal, not a link violation"
    );
    assert!(coordinator.take_remote_account_work().is_empty());
    assert_eq!(context.pending_len(), 1, "refusal must be durable");
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert!(coordinator.link_is_live(edge.link, peer));
    let record = read_result(&mut fixture, request).await?;
    let object =
        SchemaObject::decode_exact("FederationResult", &record.result_object, &mut budget)?;
    let header = ResultHeader::from_object(&object)?;
    let arm = decode_result_arm(&object, &mut budget)?;
    assert!(
        matches!(ResultArm::from_object(header.result_kind, &arm)?, ResultArm::Failed { code, .. } if code == "NOT_ALLOWED")
    );
    Ok(())
}

fn prepare(fixture: &mut StateCoreFixture) -> TestResult<(RequestHeader, u64)> {
    let peer = ServerId::from_bytes([50; 16]);
    let mut coordinator = standalone_coordinator(peer);
    let context = fixture.context_mut()?;
    let (mut fresh, _) = remote_account_staging_request(&mut coordinator, context)?;
    fresh.header.opcode = agenc_relay_types::FederationOpcode::CredentialChangeFinish;
    let mut projector = FederationProjector::new(NETWORK, COORDINATOR);
    projector.set_edge(
        peer,
        EdgeDelivery {
            projection_generation: 1,
            next_delivery_sequence: 0,
        },
    );
    context.install_federation_projector(projector);
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let origin = super::super::origin::origin_row(&coordinator, fresh.key.origin, 1, revision)
        .map_err(|error| format!("origin: {error:?}"))?;
    context.bind_remote_account_result(OWNER, fresh.header, fresh.request_object_id, origin);
    let writes = context.remote_account_result_writes(
        OWNER,
        revision,
        &ResultArm::Committed {
            resulting_state_generation: revision,
        },
        Vec::new(),
    )?;
    assert_eq!(writes.len(), 2);
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|error| format!("stage: {error:?}"))?;
    assert!(context.take_remote_account_result(OWNER).is_none());
    assert!(context.take_outbound_events().is_empty());
    Ok((fresh.header, revision))
}

async fn read_result(
    fixture: &mut StateCoreFixture,
    header: RequestHeader,
) -> TestResult<CoordinatorResultRecord> {
    let key = request_result_key(header.replay_key.to_bytes())?;
    let read = fixture
        .context_mut()?
        .submit_storage_read(agenc_relay_storage::ReadPlan::exact(
            TableId::RequestResult,
            key.clone(),
        ))?;
    let message = fixture.next_storage_read().await?;
    assert_eq!(message.read_id, read);
    let result = message.result?;
    let row = result.records.first().ok_or("missing replay row")?;
    let opened = fixture.context_mut()?.open_storage_plaintext(
        TableId::RequestResult,
        &key,
        &row.sealed_record,
    )?;
    let value =
        PersistentRecordValue::decode(TableId::RequestResult, opened.expose_for_storage_codec())?;
    Ok(CoordinatorResultRecord::decode(value.body())?)
}

#[tokio::test]
async fn credential_result_and_correlated_completion_share_one_receipt() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let (request, revision) = prepare(&mut fixture)?;
    fixture.commit_staged_batch().await?;
    let context = fixture.context_mut()?;
    let result = context
        .take_remote_account_result(OWNER)
        .ok_or("committed response")?;
    let events = context.take_outbound_events();
    let [event] = events.as_slice() else {
        return Err("one completion required".into());
    };
    let mut budget = DecodeBudget::new(1 << 20, 4096);
    let object = SchemaObject::decode_exact("FederationEvent", &event.encoded, &mut budget)?;
    let event_header = EventHeader::from_object(&object)?;
    let correlation = event_header.correlation.ok_or("completion correlation")?;
    assert_eq!(correlation.replay_key, request.replay_key);
    assert_eq!(correlation.request_id, request.request_id);
    assert_eq!(event_header.coordinator_state_generation, revision);
    assert_eq!(
        event_header.event_kind,
        agenc_relay_types::FederationEventKind::RequestCompleted
    );
    let record = read_result(&mut fixture, request).await?;
    assert_eq!(record.completion_event_id, Some(*event.event_id.as_bytes()));
    assert_eq!(record.result_object, result.bytes);
    let object =
        SchemaObject::decode_exact("FederationResult", &record.result_object, &mut budget)?;
    let header = ResultHeader::from_object(&object)?;
    assert_eq!(header.completion_event_id, Some(event.event_id));
    assert_eq!(header.request_id, request.request_id);
    assert_eq!(record.resulting_state_generation, revision);
    Ok(())
}
