//! Credential commits bind their exact response to the same durable completion.
#![forbid(unsafe_code)]

use super::*;
use crate::connection::ConnectionGeneration;
use crate::state_core::projector::{EdgeDelivery, FederationProjector};
use agenc_ircd_storage::federation_records::{CoordinatorResultRecord, request_result_key};

const OWNER: ConnectionGeneration = ConnectionGeneration::new(1 << 62);

fn prepare(fixture: &mut StateCoreFixture) -> TestResult<(RequestHeader, u64)> {
    let peer = ServerId::from_bytes([50; 16]);
    let mut coordinator = standalone_coordinator(peer);
    let context = fixture.context_mut()?;
    let (mut fresh, _) = remote_account_staging_request(&mut coordinator, context)?;
    fresh.header.opcode = agenc_ircd_types::FederationOpcode::CredentialChangeFinish;
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
        .submit_storage_read(agenc_ircd_storage::ReadPlan::exact(
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
        agenc_ircd_types::FederationEventKind::RequestCompleted
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
