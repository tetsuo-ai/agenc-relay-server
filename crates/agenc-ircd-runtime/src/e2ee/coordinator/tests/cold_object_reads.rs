//! An authorized fetch must distinguish an evicted body from a confirmed absent object.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::test_support::StateCoreFixture;
use agenc_ircd_storage::e2ee_records::ObjectRow;

#[tokio::test]
async fn an_authorized_fetch_finds_a_retained_commit_after_memory_eviction() -> TestResult {
    let (mut fixture, conversation, _) = finalization_fixture()?;
    let object_id = fixture
        .coordinator
        .state
        .logs
        .get(&conversation)
        .and_then(|log| log.candidate())
        .ok_or("candidate")?
        .commit_object_id;
    let bytes = fixture
        .coordinator
        .state
        .objects
        .get(&object_id)
        .ok_or("Commit body")?
        .clone();
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&object_id);
    let hot = ok(evaluate_request(
        &mut fixture,
        Op::FetchObject,
        &parameters,
        None,
    )?)?;
    assert_eq!(
        hot.responses.first().map(|response| &response.bytes),
        Some(&bytes)
    );
    let mut storage = StateCoreFixture::new(vec![44; 65_536])?;
    let records = persist_and_read_back(&mut storage, &bytes).await?;
    assert_eq!(
        fixture.coordinator.state.objects.remove(&object_id),
        Some(bytes.clone())
    );
    fixture.coordinator.state.object_bytes = fixture
        .coordinator
        .state
        .object_bytes
        .checked_sub(bytes.len())
        .ok_or("resident byte accounting")?;
    use crate::e2ee::coordinator::object_read::{Resolved, Source};
    let complete = fixture.request(Op::FetchObject, &parameters, None)?;
    let ops::Prepared::Read(request) = evaluate_lookup(&fixture, &complete, Source::Unread)? else {
        return Err("an uncached object must suspend for storage".into());
    };
    let resolved = Resolved::admit(request, records, &fixture.backing)
        .map_err(|e| format!("resolve: {e:?}"))?;
    let cold = ok(evaluate_lookup(&fixture, &complete, Source::Resolved(&resolved))?.complete())?;
    assert_eq!(
        cold.responses.first().map(|response| &response.bytes),
        Some(&bytes),
        "a retained sealed Commit was treated as an absent object after memory eviction"
    );
    Ok(())
}

async fn persist_and_read_back(
    storage: &mut StateCoreFixture,
    bytes: &[u8],
) -> TestResult<Vec<(agenc_ircd_storage::StoredKey, PersistentRecordValue)>> {
    let context = storage.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let write = CompanionCoordinator::object_write(bytes)
        .map_err(|e| format!("object write: {e:?}"))?
        .at_revision(plan.resulting_revision().get())?;
    context
        .stage_durable_with_account_service(
            plan,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            vec![write],
        )
        .map_err(|e| format!("stage Commit: {e:?}"))?;
    storage.commit_staged_batch().await?;
    let key = agenc_ircd_storage::e2ee_records::object_key(&object_id(bytes))?;
    let _raw = storage
        .context_mut()?
        .reserve_output_backing(agenc_ircd_storage::MAX_SEALED_RECORD_BYTES + 8192)?;
    let _decode = storage
        .context_mut()?
        .reserve_output_backing(3 * agenc_ircd_storage::MAX_SEALED_RECORD_BYTES + 8192)?;
    let id = storage
        .context_mut()?
        .submit_storage_read(agenc_ircd_storage::ReadPlan::exact(
            TableId::E2eeObject,
            key.clone(),
        ))?;
    let message = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        storage.next_storage_read(),
    )
    .await??;
    assert_eq!(message.read_id, id);
    let result = message.result?;
    assert!(!result.truncated);
    assert_eq!(result.records.len(), 1);
    let record = result.records.first().ok_or("sealed record")?;
    assert_eq!(record.key.as_bytes(), key.as_bytes());
    let plain = storage.context_mut()?.open_storage_plaintext(
        record.table,
        &record.key,
        &record.sealed_record,
    )?;
    let value = PersistentRecordValue::decode(record.table, plain.expose_for_storage_codec())?;
    assert_eq!(ObjectRow::decode(value.body())?.bytes, bytes);
    Ok(vec![(key, value)])
}

fn evaluate_lookup(
    harness: &Harness,
    complete: &crate::e2ee::coordinator::CompleteRequest,
    source: crate::e2ee::coordinator::object_read::Source<'_>,
) -> TestResult<ops::Prepared> {
    let decoded =
        request::decode(&harness.coordinator, complete).map_err(|e| format!("decode: {e:?}"))?;
    let origin = harness
        .coordinator
        .state
        .origins
        .values()
        .next()
        .ok_or("origin")?;
    let home = ServerId::from_bytes(origin.home_server_id);
    let mut entropy = crate::e2ee::coordinator::tests::Counter(99);
    let mut exec = Exec {
        object_source: source,
        queries: None,
        backing: harness.backing.clone(),
        monotonic_millis: harness.monotonic_millis,
        coordinator: &harness.coordinator,
        home,
        origin,
        decoded: &decoded,
        now: NOW,
        entropy: &mut entropy,
        peers: &[],
        holds_channel: &|_, _| false,
        hosting: &|_| Vec::new(),
        attached_edges: &|_| Vec::new(),
        channel_member: &|_| false,
        plan_binding: &|_, _| Ok(None),
        state_generation: 7,
        source_view: Vec::new(),
    };
    ops::execute(&mut exec).map_err(|e| format!("lookup: {:?}", e.code).into())
}
