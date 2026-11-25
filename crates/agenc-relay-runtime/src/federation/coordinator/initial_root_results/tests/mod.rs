//! Real redb, authenticated sealed response, exact disk reread and two independent retention floors.
#![forbid(unsafe_code)]

use super::*;
use crate::federation::codec::results::ResultArm;
use crate::federation::history_retention::Retention;
use crate::state_core::{durable::AccountServiceDurableWrite, fanout::FanoutRequest};
use crate::test_support::{StateCoreFixture, TestResult};
use agenc_relay_auth::initial_root::{ClaimAction, open_claim, seal_claim};
use agenc_relay_crypto::{
    AccountHpkePrivateKey, AccountRequestBinding, InitialRootExchange, InitialRootSecret,
};
use agenc_relay_federation_wire::{
    FederationProfile, InitialRootOperation, InitialRootResult, OperationDescriptor, ReplayKey,
    ResultHeader, federation_object_id,
};
use agenc_relay_storage::federation_records::{COORDINATOR_RESULT_KIND, CoordinatorResultRecord};
use agenc_relay_storage::{PersistentRecordValue, ReadPlan, StoredKey, TableId};
use agenc_relay_types::{
    AccountRandomId, FederationResultKind, OriginId, RequestId, ServerId, ServerIncarnation,
};

const START: u64 = 1_000_000;
const DAY: u64 = 86_400;

struct Case {
    descriptor: OperationDescriptor,
    outer: Vec<u8>,
    record: CoordinatorResultRecord,
    key: StoredKey,
    raw: Key,
    peer: ServerId,
}
fn decision(fixture: &StateCoreFixture) -> TestResult<Case> {
    let private = AccountHpkePrivateKey::generate()?;
    let public = private.public_key()?;
    let network = fixture.identity.network_id;
    let epoch = fixture.identity.recovery_epoch;
    let secret = InitialRootSecret::generate()?;
    let id = RequestId::from_bytes([31; 16]);
    let account = AccountRandomId::from_bytes([11; 16]).to_account_id();
    let (request, _opener) = seal_claim(
        public,
        AccountRequestBinding::new(
            network,
            epoch,
            public.key_id(),
            id,
            InitialRootExchange::Claim,
        ),
        account,
        RequestId::from_bytes([12; 16]),
        &secret,
        ClaimAction::Read,
    )?;
    // A real protected denial has exactly the same result shape and retention as a positive decision.
    let sealed = open_claim(&private, network, epoch, &request)?.prepare(Some(account), None, 0)?;
    let peer = ServerId::from_bytes([16; 16]);
    let replay = ReplayKey {
        home_server_id: peer,
        server_incarnation: ServerIncarnation::from_bytes([17; 16]),
        origin_id: OriginId::from_bytes([18; 16]),
        origin_generation: 1,
        operation_sequence: 4,
    };
    let request_object_id =
        federation_object_id(b"deterministic federation retention fixture request");
    let header = ResultHeader {
        network_id: network,
        replay_key: replay,
        request_id: id,
        request_object_id,
        completion_event_id: None,
        result_kind: FederationResultKind::AuthChallenge,
    };
    let outer = InitialRootResult::encode_sealed(
        FederationProfile::InitialRoot,
        &header,
        InitialRootOperation::Claim,
        sealed.bytes_for_commit(),
    )?;
    let descriptor = OperationDescriptor {
        addressed_server_id: fixture.identity.server_id,
        server_incarnation: replay.server_incarnation,
        origin_id: replay.origin_id,
        origin_generation: 1,
        operation_sequence: 4,
        request_id: id,
        object_id: request_object_id,
    };
    let raw = replay.to_bytes();
    let key = StoredKey::new(raw.to_vec())?;
    let record = CoordinatorResultRecord {
        request_id: *id.as_bytes(),
        request_object_id: *request_object_id.as_bytes(),
        result_object_id: *federation_object_id(&outer).as_bytes(),
        result_object: outer.clone(),
        completion_event_id: None,
        resulting_state_generation: 1,
    };
    Ok(Case {
        descriptor,
        outer,
        record,
        key,
        raw,
        peer,
    })
}
fn stage(fixture: &mut StateCoreFixture, writes: Vec<AccountServiceDurableWrite>) -> TestResult {
    let context = fixture.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(vec![], vec![])?,
            None,
            0,
            writes,
        )
        .map_err(|_| "could not stage the bounded federation rows")?;
    Ok(())
}
fn cleanup(
    fixture: &mut StateCoreFixture,
    case: &Case,
    closed: bool,
) -> TestResult<Vec<AccountServiceDurableWrite>> {
    let page = fixture.read_rows(ReadPlan::exact(TableId::RequestResult, case.key.clone()))?;
    let context = fixture.context_mut()?;
    let revision = context
        .domain()
        .plan_account_service_checkpoint()?
        .resulting_revision()
        .get();
    Ok(Retention::default()
        .prepare(
            context,
            &page,
            revision,
            agenc_relay_storage::history_records::HISTORY_COORDINATOR_RESULT_KIND,
            |key| *key == case.raw && closed,
        )?
        .writes)
}
fn read(case: &Case, fixture: &mut StateCoreFixture) -> TestResult<Vec<u8>> {
    let network = fixture.identity.network_id;
    Ok(authorized_output(
        fixture.context_mut()?,
        network,
        case.peer,
        &case.descriptor,
        &case.outer,
    )
    .map_err(|err| format!("federation replay {err:?}"))?
    .into_owned())
}

async fn through_both_floors(closed_at: u64, deadline: u64) -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![48; 32_768])?;
    let case = decision(&fixture)?;
    let revision = fixture
        .context_mut()?
        .domain()
        .plan_account_service_checkpoint()?
        .resulting_revision()
        .get();
    let value = PersistentRecordValue::new(
        TableId::RequestResult,
        COORDINATOR_RESULT_KIND,
        revision,
        0,
        Some(START + WEEK),
        vec![],
        case.record.encode()?,
    )?;
    assert!(
        crate::state_core::durable::federated_claims::read(&StoredKey::new(vec![40; 64])?, &value)
            .is_err()
    );
    // A request arrived at START. The decision has to survive an additional 400 s until staging.
    fixture
        .context_mut()?
        .set_untrusted_wall_for_test(Some(START + 400));
    assert!(
        stage(
            &mut fixture,
            vec![AccountServiceDurableWrite::put(
                TableId::RequestResult,
                case.key.clone(),
                value.encode()?
            )?]
        )
        .is_err()
    );
    fixture.context_mut()?.set_wall_for_test(START + 400);
    stage(
        &mut fixture,
        vec![AccountServiceDurableWrite::put(
            TableId::RequestResult,
            case.key.clone(),
            value.encode()?,
        )?],
    )?;
    assert!(
        !fixture
            .context_mut()?
            .index()
            .holds_federated_claim(&case.raw, &case.outer)
    );
    fixture.commit_staged_batch().await?;
    fixture.restart_registration_storage(vec![49; 32_768])?;
    let context = fixture.context_mut()?;
    let pending = context
        .index()
        .federated_claim(&case.raw)
        .ok_or("original committed result")?;
    assert_eq!(pending.deadline, START + 400 + WEEK);
    assert!(!pending.observed);
    // The first independent disk observation is another 500 s later.
    context.set_wall_for_test(START + 900);
    assert!(
        context
            .index()
            .holds_federated_claim(&case.raw, &case.outer)
    );
    assert!(
        !context
            .index()
            .holds_federated_claim(&case.raw, b"unrelated later result")
    );
    let first_observation = cleanup(&mut fixture, &case, false)?;
    assert_eq!(first_observation.len(), 1);
    stage(&mut fixture, first_observation)?;
    fixture.commit_staged_batch().await?;
    fixture.restart_registration_storage(vec![52; 32_768])?;
    let observed = fixture
        .context_mut()?
        .index()
        .federated_claim(&case.raw)
        .ok_or("live observed result")?;
    assert_eq!(observed.deadline, START + 900 + WEEK);
    assert!(observed.observed && !observed.closing);
    fixture.context_mut()?.set_wall_for_test(closed_at);
    assert!(cleanup(&mut fixture, &case, false)?.is_empty());
    assert!(read(&case, &mut fixture)? == case.outer);
    let writes = cleanup(&mut fixture, &case, true)?;
    assert_eq!(writes.len(), 1);
    stage(&mut fixture, writes)?;
    assert!(
        !fixture
            .context_mut()?
            .index()
            .federated_claim(&case.raw)
            .ok_or("original owner")?
            .closing
    );
    fixture.commit_staged_batch().await?;
    fixture.restart_registration_storage(vec![50; 32_768])?;
    let context = fixture.context_mut()?;
    let mapping = context
        .index()
        .federated_claim(&case.raw)
        .ok_or("closed origin owner")?;
    assert!(mapping.closing);
    assert_eq!(mapping.deadline, deadline);
    context.set_untrusted_wall_for_test(Some(deadline + DAY));
    assert!(read(&case, &mut fixture).is_err());
    assert!(cleanup(&mut fixture, &case, true).is_err());
    fixture.context_mut()?.set_wall_for_test(deadline - 1);
    assert!(cleanup(&mut fixture, &case, true)?.is_empty());
    assert!(
        stage(
            &mut fixture,
            vec![AccountServiceDurableWrite::delete(
                TableId::RequestResult,
                case.key.clone()
            )?]
        )
        .is_err()
    );
    assert!(fixture.stored_row_exists(TableId::RequestResult, case.key.clone())?);
    assert!(read(&case, &mut fixture)? == case.outer);
    fixture.context_mut()?.set_wall_for_test(deadline);
    let expired = read(&case, &mut fixture)?;
    let result = crate::federation::codec::initial_root::ResultObject::read(
        FederationProfile::InitialRoot,
        Some(InitialRootOperation::Claim),
        &expired,
        &mut agenc_relay_federation_wire::DecodeBudget::new(1 << 20, 4096),
    )?;
    assert!(matches!(result.arm,ResultArm::Failed{code,..} if code=="ORIGIN_EXPIRED"));
    let removes = cleanup(&mut fixture, &case, true)?;
    assert_eq!(removes.len(), 1);
    stage(&mut fixture, removes)?;
    assert!(
        fixture
            .context_mut()?
            .index()
            .holds_federated_claim(&case.raw, &case.outer)
    );
    fixture.commit_staged_batch().await?;
    assert!(!fixture.stored_row_exists(TableId::RequestResult, case.key.clone())?);
    fixture.restart_registration_storage(vec![51; 32_768])?;
    fixture.context_mut()?.set_wall_for_test(deadline + 1);
    assert!(
        fixture
            .context_mut()?
            .index()
            .federated_claim(&case.raw)
            .is_none()
    );
    assert!(read(&case, &mut fixture).is_err());
    Ok(())
}

#[tokio::test]
async fn exact_remote_results_survive_reopen_until_both_origin_and_security_floors() -> TestResult {
    through_both_floors(START + DAY, START + 900 + WEEK).await?;
    through_both_floors(START + WEEK + DAY, START + WEEK + 2 * DAY).await
}
