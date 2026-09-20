//! Exact replay of a committed request result: only the same route, the same
//! ciphertext and the matching carrier phase read the stored response again,
//! and a storage answer that is not exactly the requested row is refused.
#![forbid(unsafe_code)]

use super::harness::{
    Live, arm_sasl, authentication_start, sealed_unknown_authentication,
    unsealed_unknown_authentication,
};
use super::*;
use crate::account_service::{request_result_key, request_result_write};
use crate::state_core::StageAccepted;
use crate::state_core::fanout::FanoutRequest;
use crate::test_support::TestResult;
use agenc_ircd_storage::{ReadPlan, ReadRecord, ReadResult};

/// Commits one authentication START and returns the envelope it answered.
async fn committed_start(live: &mut Live) -> TestResult<AccountServiceEnvelope> {
    let (sealed, envelope) = sealed_unknown_authentication(live, 1, "replayer")?;
    arm_sasl(&mut live.fixture, live.generation, false)?;
    let request = live.sasl(AccountCarrierPhase::Start, clone_envelope(&envelope)?);
    let login = NormalizedLogin::prepare("replayer")?;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.stage_start(context, request, sealed, None, login, None)?;
    live.fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = live.fixture.parts()?;
    assert_eq!(coordinator.batch_applied(context).len(), 1);
    Ok(envelope)
}

fn clone_envelope(envelope: &AccountServiceEnvelope) -> TestResult<AccountServiceEnvelope> {
    Ok(AccountServiceEnvelope::parse(*envelope.as_bytes())?)
}

fn stored_result(live: &Live, envelope: &AccountServiceEnvelope) -> TestResult<ReadResult> {
    let key = request_result_key(envelope.client_request_id())?;
    let result = live
        .fixture
        .core
        .read_rows(ReadPlan::exact(TableId::RequestResult, key))?;
    assert_eq!(result.records.len(), 1);
    Ok(result)
}

fn replay(
    live: &mut Live,
    request: RequestContext,
    result: ReadResult,
) -> Result<Vec<CarrierCompletion>, RuntimeError> {
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.replay_read(context, request, result)
}

/// The client aborts its finish and retries the identical START.
fn retry_start(live: &mut Live) -> TestResult {
    let connection = live
        .fixture
        .coordinator
        .connections
        .get_mut(&live.generation)
        .ok_or("connection")?;
    let _aborted = connection.sasl.client("*", 0)?;
    arm_sasl(&mut live.fixture, live.generation, false)
}

#[tokio::test]
async fn a_retried_start_reads_its_committed_response_without_new_work() -> TestResult {
    let mut live = Live::open()?;
    let envelope = committed_start(&mut live).await?;
    let result = stored_result(&live, &envelope)?;
    retry_start(&mut live)?;
    let sent_before = live.sink.lines().len();
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let completions = replay(&mut live, request, result)?;
    assert!(matches!(
        completions.as_slice(),
        [completion] if !completion.close && completion.result == ResultClass::Ok
    ));
    assert!(live.sink.lines().len() > sent_before);
    assert!(live.fixture.coordinator.crypto.is_empty());
    assert_eq!(live.fixture.core.context_mut()?.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_replay_from_another_connection_route_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let envelope = committed_start(&mut live).await?;
    let result = stored_result(&live, &envelope)?;
    let mut request = live.sasl(AccountCarrierPhase::Start, envelope);
    request.route.connection_nonce = [0xab; 32];
    let refused = replay(&mut live, request, result);
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[tokio::test]
async fn a_reused_request_id_with_different_ciphertext_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let envelope = committed_start(&mut live).await?;
    let result = stored_result(&live, &envelope)?;
    let (_, resealed) = authentication_start(&live.fixture.core.identity, 1, "replayer")?;
    assert!(resealed.client_request_id() == envelope.client_request_id());
    assert!(resealed.as_bytes() != envelope.as_bytes());
    let request = live.sasl(AccountCarrierPhase::Start, resealed);
    let refused = replay(&mut live, request, result);
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[tokio::test]
async fn a_finish_phase_replay_of_a_start_result_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let envelope = committed_start(&mut live).await?;
    let result = stored_result(&live, &envelope)?;
    let request = live.sasl(AccountCarrierPhase::Finish, envelope);
    let refused = replay(&mut live, request, result);
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    assert!(live.fixture.coordinator.crypto.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_stored_response_that_answers_another_request_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let (_, envelope) = authentication_start(&live.fixture.core.identity, 1, "replayer")?;
    let (other, _) = unsealed_unknown_authentication(&mut live, 2, "replayer")?;
    let other = other.seal(live.response_count()?)?;
    let response = other.response_intent().response().as_bytes();
    let request = live.sasl(AccountCarrierPhase::Start, clone_envelope(&envelope)?);
    let context = live.fixture.core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let write = request_result_write(revision, &request, RequestTerminal::Start, None, response)?;
    let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
    let staged = context.stage_durable_with_account_service(plan, fanout, None, 0, vec![write]);
    assert!(matches!(staged, Ok(StageAccepted::Staged { .. })));
    live.fixture.core.commit_staged_batch().await?;
    let result = stored_result(&live, &envelope)?;
    let refused = replay(&mut live, request, result);
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[tokio::test]
async fn a_read_answer_with_more_than_the_one_requested_row_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let envelope = committed_start(&mut live).await?;
    let mut result = stored_result(&live, &envelope)?;
    let copy = result.records.first().map(|record| ReadRecord {
        table: record.table,
        key: record.key.clone(),
        sealed_record: record.sealed_record.clone(),
    });
    result.records.extend(copy);
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let refused = replay(&mut live, request, result);
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[tokio::test]
async fn a_read_answer_from_another_table_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let envelope = committed_start(&mut live).await?;
    let mut result = stored_result(&live, &envelope)?;
    for record in &mut result.records {
        record.table = TableId::AuthTransaction;
    }
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let refused = replay(&mut live, request, result);
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[tokio::test]
async fn a_read_answer_under_another_key_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let envelope = committed_start(&mut live).await?;
    let mut result = stored_result(&live, &envelope)?;
    for record in &mut result.records {
        record.key = StoredKey::new(vec![0x5a; 16])?;
    }
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let refused = replay(&mut live, request, result);
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[test]
fn an_unknown_login_is_answered_only_from_the_profiles_own_fake_record() -> TestResult {
    let mut live = Live::open()?;
    let login = NormalizedLogin::prepare("nobody")?;
    let mut body = live
        .fixture
        .core
        .opaque
        .expose_fake_record_for_persistence()
        .to_vec();
    if let Some(byte) = body.first_mut() {
        *byte ^= 1;
    }
    let forged = agenc_ircd_storage::PersistentRecordValue::new(
        TableId::OpaqueRecord,
        agenc_ircd_storage::LIVE_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?;
    let (coordinator, context) = live.fixture.parts()?;
    let lookup = coordinator.authentication_lookup(context, &login, None, None, None, &forged);
    assert_eq!(lookup.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[tokio::test]
async fn a_storage_failure_during_replay_lookup_closes_the_waiting_carrier() -> TestResult {
    let mut live = Live::open()?;
    let (_, envelope) = authentication_start(&live.fixture.core.identity, 1, "replayer")?;
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.submit_replay_read(context, request)?;
    let read_id = *coordinator.reads.keys().next().ok_or("pending read")?;
    let failed = crate::bridge::StorageReadCompletionMessage {
        read_id,
        result: Err(agenc_ircd_storage::StorageError::Unavailable),
    };
    let completions = coordinator.storage_read_completed(context, failed);
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.generation == generation
    ));
    assert!(coordinator.reads.is_empty());
    Ok(())
}

#[test]
fn a_request_result_with_a_zero_origin_generation_does_not_decode() -> TestResult {
    let route = ConnectionRoute {
        origin_id: OriginId::from_bytes([1; 16]),
        origin_generation: Generation::new(2)?,
        connection_id: ConnectionId::from_bytes([3; 16]),
        connection_nonce: [4; 32],
    };
    let record = RequestResultRecord {
        route,
        terminal: RequestTerminal::Start,
        terminal_account: None,
        request: [5; agenc_ircd_auth::ACCOUNT_SERVICE_ENVELOPE_BYTES],
        response: [6; agenc_ircd_auth::ACCOUNT_SERVICE_RESPONSE_BYTES],
    };
    let mut encoded = record.encode();
    assert!(RequestResultRecord::decode(&encoded).is_ok());
    encoded
        .get_mut(2 + 16..2 + 16 + 8)
        .ok_or("generation field")?
        .copy_from_slice(&0_u64.to_be_bytes());
    assert_eq!(
        RequestResultRecord::decode(&encoded).err(),
        Some(RuntimeError::InvalidValue)
    );
    Ok(())
}

#[tokio::test]
async fn a_stored_row_of_another_record_kind_is_refused_on_replay() -> TestResult {
    let mut live = Live::open()?;
    let (_, envelope) = authentication_start(&live.fixture.core.identity, 1, "replayer")?;
    let (other, _) = unsealed_unknown_authentication(&mut live, 1, "replayer")?;
    let other = other.seal(live.response_count()?)?;
    let response = other.response_intent().response().as_bytes();
    let request = live.sasl(AccountCarrierPhase::Start, clone_envelope(&envelope)?);
    let record = RequestResultRecord {
        route: request.route,
        terminal: RequestTerminal::Start,
        terminal_account: None,
        request: *request.envelope.as_bytes(),
        response: *response,
    };
    let context = live.fixture.core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let other_kind = 2;
    let body = agenc_ircd_storage::ProtocolRecordBody::new(
        TableId::RequestResult,
        other_kind,
        1,
        record.encode(),
    )?;
    let value = agenc_ircd_storage::PersistentRecordValue::new(
        TableId::RequestResult,
        other_kind,
        revision,
        0,
        None,
        Vec::new(),
        body.encode()?,
    )?;
    let write = crate::state_core::durable::AccountServiceDurableWrite::put(
        TableId::RequestResult,
        request_result_key(envelope.client_request_id())?,
        value.encode()?,
    )?;
    let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
    let staged = context.stage_durable_with_account_service(plan, fanout, None, 0, vec![write]);
    assert!(matches!(staged, Ok(StageAccepted::Staged { .. })));
    live.fixture.core.commit_staged_batch().await?;
    let result = stored_result(&live, &envelope)?;
    let refused = replay(&mut live, request, result);
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}

#[test]
fn an_unknown_login_fake_record_under_another_record_kind_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let login = NormalizedLogin::prepare("nobody")?;
    let body = live
        .fixture
        .core
        .opaque
        .expose_fake_record_for_persistence()
        .to_vec();
    let forged = agenc_ircd_storage::PersistentRecordValue::new(
        TableId::OpaqueRecord,
        agenc_ircd_storage::LIVE_RECORD_KIND + 1,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?;
    let (coordinator, context) = live.fixture.parts()?;
    let lookup = coordinator.authentication_lookup(context, &login, None, None, None, &forged);
    assert_eq!(lookup.err(), Some(RuntimeError::InvalidValue));
    Ok(())
}
