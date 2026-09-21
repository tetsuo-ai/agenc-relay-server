//! A crypto bridge that refuses the next job: a FINISH that already consumed
//! its live transaction queues that transaction's cleanup, and a ready seal
//! that cannot start closes exactly its own carrier.
#![forbid(unsafe_code)]

use super::harness::{
    Live, WALL, authentication_finish, commit_authentication_start, commit_credential_start,
    creation_finish, credential_finish, rejected_authentication_finish, saturate_crypto,
    unsealed_unknown_authentication,
};
use super::invitation_window::commit_start;
use super::*;
use crate::account_service::ReadySeal;
use crate::test_support::TestResult;
use agenc_relay_auth::OpenedAccountServiceRequest;

fn assert_queued(live: &Live, transaction_id: TransactionId) {
    let coordinator = &live.fixture.coordinator;
    assert!(coordinator.crypto.is_empty());
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    let queued = coordinator
        .cleanup_queue
        .iter()
        .chain(&coordinator.pending_cleanups)
        .any(|cleanup| cleanup.transaction_id == transaction_id);
    assert!(queued);
}

#[tokio::test]
async fn a_refused_authentication_finish_job_queues_the_consumed_transaction() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "finisher").await?;
    let (opened, envelope) = authentication_finish(&live.fixture.core.identity, 2, transaction_id)?;
    let request = live.sasl(AccountCarrierPhase::Finish, envelope);
    saturate_crypto(&mut live)?;
    let (coordinator, context) = live.fixture.parts()?;
    let opened = OpenedAccountServiceRequest::AuthenticationFinish(opened);
    let refused = coordinator.open_completed(context, request, Ok(opened));
    assert_eq!(refused.err(), Some(RuntimeError::LimitExceeded));
    assert_queued(&live, transaction_id);
    Ok(())
}

#[tokio::test]
async fn a_refused_creation_finish_job_queues_the_transaction_and_reservation() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_start(
        &mut live.fixture,
        live.generation,
        live.route,
        1,
        "creator",
        None,
        WALL,
    )
    .await?;
    let (opened, envelope) = creation_finish(&live.fixture.core.identity, 2, transaction_id)?;
    let request = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Finish,
        envelope,
    );
    saturate_crypto(&mut live)?;
    let (coordinator, context) = live.fixture.parts()?;
    let opened = OpenedAccountServiceRequest::CreationFinish(opened);
    let refused = coordinator.open_completed(context, request, Ok(opened));
    assert_eq!(refused.err(), Some(RuntimeError::LimitExceeded));
    assert_queued(&live, transaction_id);
    Ok(())
}

#[tokio::test]
async fn a_refused_credential_finish_job_queues_the_consumed_transaction() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let transaction_id = commit_credential_start(&mut live, 1, account_id).await?;
    let (opened, envelope) = credential_finish(&live.fixture.core.identity, 2, transaction_id)?;
    let request = live.account(
        AccountCarrierKind::Credentials,
        AccountCarrierPhase::Finish,
        envelope,
    );
    saturate_crypto(&mut live)?;
    let (coordinator, context) = live.fixture.parts()?;
    let opened = OpenedAccountServiceRequest::CredentialChangeFinish(opened);
    let refused = coordinator.open_completed(context, request, Ok(opened));
    assert_eq!(refused.err(), Some(RuntimeError::LimitExceeded));
    assert_queued(&live, transaction_id);
    Ok(())
}

#[tokio::test]
async fn a_ready_finish_seal_the_bridge_refuses_closes_and_queues_its_transaction() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "sealer").await?;
    let (outcome, envelope) = rejected_authentication_finish(&mut live, 2, transaction_id)?;
    let ready = ReadySeal::Finish {
        request: live.sasl(AccountCarrierPhase::Finish, envelope),
        transaction_id,
        outcome,
        account_id: None,
        login: NormalizedLogin::prepare("sealer")?,
        previous_value: None,
        authenticated_at: MonotonicTick::from_ticks(0),
    };
    live.fixture.coordinator.ready_seals.push_back(ready);
    saturate_crypto(&mut live)?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let completions = coordinator.progress(context);
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.generation == generation
    ));
    assert_queued(&live, transaction_id);
    Ok(())
}

#[tokio::test]
async fn a_ready_start_seal_the_bridge_refuses_closes_without_any_cleanup() -> TestResult {
    let mut live = Live::open()?;
    let (outcome, envelope) = unsealed_unknown_authentication(&mut live, 1, "sealer")?;
    let ready = ReadySeal::Start {
        request: live.sasl(AccountCarrierPhase::Start, envelope),
        outcome,
        account_id: None,
        login: NormalizedLogin::prepare("sealer")?,
        previous_value: None,
    };
    live.fixture.coordinator.ready_seals.push_back(ready);
    saturate_crypto(&mut live)?;
    let (coordinator, context) = live.fixture.parts()?;
    let completions = coordinator.progress(context);
    assert!(matches!(completions.as_slice(), [completion] if completion.close));
    assert!(coordinator.ready_seals.is_empty());
    assert!(coordinator.cleanup_queue.is_empty() && coordinator.pending_cleanups.is_empty());
    Ok(())
}
