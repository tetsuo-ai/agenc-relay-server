//! Durable admission of sealed START and FINISH outcomes: the retained
//! transaction limit, a response count that moved since sealing, a batch slot
//! that is already taken, and reservations that do not match the sealed intent
//! all refuse before any authority is staged.
#![forbid(unsafe_code)]

use super::harness::{
    Live, WALL, arm_sasl, arm_transfer, begin_creation, begin_unavailable_credential_change,
    commit_authentication_start, commit_credential_start, exhaust_transaction_capacity,
    rejected_authentication_finish, rejected_credential_finish, sealed_unknown_authentication,
    unsealed_unknown_authentication,
};
use super::invitation_window::{WorkerOutcome, commit_start, worker_finish};
use super::*;
use crate::account_service::ReadyStage;
use crate::test_support::TestResult;

const CREATE: AccountCarrierKind = AccountCarrierKind::Create;
const CREDENTIALS: AccountCarrierKind = AccountCarrierKind::Credentials;

fn assert_nothing_staged(live: &mut Live, pending: usize) -> TestResult {
    let (coordinator, context) = live.fixture.parts()?;
    assert!(coordinator.pending_authority.is_none());
    assert_eq!(context.pending_len(), pending);
    Ok(())
}

type Staged = TestResult<Result<(), RuntimeError>>;

fn stage_authentication_start(live: &mut Live, stale: u64) -> Staged {
    let (start, envelope) = unsealed_unknown_authentication(live, 1, "stager")?;
    let sealed = start.seal(live.response_count()?.saturating_add(stale))?;
    arm_sasl(&mut live.fixture, live.generation, false)?;
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let login = NormalizedLogin::prepare("stager")?;
    let (coordinator, context) = live.fixture.parts()?;
    Ok(coordinator.stage_start(context, request, sealed, None, login, None))
}

fn stage_creation_start(live: &mut Live, stale: u64) -> Staged {
    let (start, envelope) = begin_creation(live, 1, "stager", true)?;
    let sealed = start.seal(live.response_count()?.saturating_add(stale))?;
    arm_transfer(live, CREATE, AccountCarrierPhase::Start, &envelope)?;
    let request = live.account(CREATE, AccountCarrierPhase::Start, envelope);
    let (coordinator, context) = live.fixture.parts()?;
    Ok(coordinator.stage_creation_start(context, request, sealed))
}

fn stage_credential_start(live: &mut Live, account_id: AccountId, stale: u64) -> Staged {
    let (start, envelope) = begin_unavailable_credential_change(live, 1, account_id)?;
    let sealed = start.seal(live.response_count()?.saturating_add(stale))?;
    arm_transfer(live, CREDENTIALS, AccountCarrierPhase::Start, &envelope)?;
    let request = live.account(CREDENTIALS, AccountCarrierPhase::Start, envelope);
    let (coordinator, context) = live.fixture.parts()?;
    Ok(coordinator.stage_credential_start(context, request, sealed, None))
}

#[test]
fn an_authentication_start_at_the_retained_transaction_limit_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    exhaust_transaction_capacity(&mut live.fixture.coordinator);
    let staged = stage_authentication_start(&mut live, 0)?;
    assert_eq!(staged.err(), Some(RuntimeError::LimitExceeded));
    assert_nothing_staged(&mut live, 0)
}

#[test]
fn a_creation_start_at_the_retained_transaction_limit_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    exhaust_transaction_capacity(&mut live.fixture.coordinator);
    let staged = stage_creation_start(&mut live, 0)?;
    assert_eq!(staged.err(), Some(RuntimeError::LimitExceeded));
    assert_nothing_staged(&mut live, 0)
}

#[test]
fn a_credential_start_at_the_retained_transaction_limit_is_not_staged() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    exhaust_transaction_capacity(&mut live.fixture.coordinator);
    let staged = stage_credential_start(&mut live, account_id, 0)?;
    assert_eq!(staged.err(), Some(RuntimeError::LimitExceeded));
    assert_nothing_staged(&mut live, 0)
}

#[test]
fn an_authentication_start_sealed_against_a_stale_response_count_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    let staged = stage_authentication_start(&mut live, 1)?;
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[test]
fn a_creation_start_sealed_against_a_stale_response_count_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    let staged = stage_creation_start(&mut live, 1)?;
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[test]
fn a_credential_start_sealed_against_a_stale_response_count_is_not_staged() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let staged = stage_credential_start(&mut live, account_id, 1)?;
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[test]
fn an_authentication_start_behind_an_unsettled_batch_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    live.occupy_pending_batch()?;
    let staged = stage_authentication_start(&mut live, 0)?;
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 1)
}

#[test]
fn a_creation_start_behind_an_unsettled_batch_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    live.occupy_pending_batch()?;
    let staged = stage_creation_start(&mut live, 0)?;
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 1)
}

#[test]
fn a_credential_start_behind_an_unsettled_batch_is_not_staged() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    live.occupy_pending_batch()?;
    let staged = stage_credential_start(&mut live, account_id, 0)?;
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 1)
}

#[test]
fn a_ready_start_that_cannot_stage_closes_its_carrier_and_queues_no_cleanup() -> TestResult {
    let mut live = Live::open()?;
    let (sealed, envelope) = sealed_unknown_authentication(&mut live, 1, "stager")?;
    // The SASL carrier never reached its waiting phase, so no response can render.
    live.fixture.coordinator.ready_stage = Some(ReadyStage::Start {
        request: live.sasl(AccountCarrierPhase::Start, envelope),
        sealed,
        account_id: None,
        login: NormalizedLogin::prepare("stager")?,
        previous_value: None,
    });
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let completions = coordinator.progress(context);
    let [completion] = completions.as_slice() else {
        return Err("one carrier closes".into());
    };
    assert!(completion.close && completion.generation == generation);
    assert!(coordinator.cleanup_queue.is_empty() && coordinator.pending_cleanups.is_empty());
    assert_nothing_staged(&mut live, 0)
}

#[tokio::test]
async fn a_credential_start_without_an_admitted_account_releases_the_reservation() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let (start, envelope) = begin_unavailable_credential_change(&mut live, 1, account_id)?;
    let sealed = start.seal(live.response_count()?)?;
    assert!(sealed.credential_reservation_account_id().is_none());
    arm_transfer(
        &mut live,
        CREDENTIALS,
        AccountCarrierPhase::Start,
        &envelope,
    )?;
    let request = live.account(CREDENTIALS, AccountCarrierPhase::Start, envelope);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator
        .credential_reservations
        .insert(account_id, generation);
    coordinator.stage_credential_start(context, request, sealed, Some(account_id))?;
    assert!(coordinator.credential_reservations.is_empty());
    assert!(matches!(
        coordinator.pending_authority,
        Some(PendingAuthority::CredentialStart {
            reservation: None,
            ..
        })
    ));
    Ok(())
}

#[test]
fn a_credential_start_whose_reservation_another_connection_owns_is_not_staged() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let (start, envelope) = begin_unavailable_credential_change(&mut live, 1, account_id)?;
    let sealed = start.seal(live.response_count()?)?;
    let request = live.account(CREDENTIALS, AccountCarrierPhase::Start, envelope);
    let (coordinator, context) = live.fixture.parts()?;
    coordinator
        .credential_reservations
        .insert(account_id, ConnectionGeneration::new(44));
    let staged = coordinator.stage_credential_start(context, request, sealed, Some(account_id));
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[tokio::test]
async fn a_rejected_authentication_finish_deletes_the_transaction_and_reports_904() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "finisher").await?;
    let (outcome, envelope) = rejected_authentication_finish(&mut live, 2, transaction_id)?;
    let sealed = outcome.seal(live.response_count()?)?;
    arm_sasl_finish(&mut live)?;
    let request = live.sasl(AccountCarrierPhase::Finish, envelope);
    let login = NormalizedLogin::prepare("finisher")?;
    let (coordinator, context) = live.fixture.parts()?;
    let at = context.now();
    coordinator.stage_finish(
        context,
        request,
        transaction_id,
        sealed,
        None,
        login,
        None,
        at,
    )?;
    live.fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = live.fixture.parts()?;
    let completions = coordinator.batch_applied(context);
    let [completion] = completions.as_slice() else {
        return Err("one completion".into());
    };
    assert!(!completion.close);
    assert_eq!(completion.result, ResultClass::Rejected);
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    assert!(live.sink.lines().iter().any(|line| line.contains(" 904 ")));
    Ok(())
}

/// After a committed START the SASL carrier is receiving FINISH; feed it.
fn arm_sasl_finish(live: &mut Live) -> TestResult {
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let now = context.now().get();
    let connection = coordinator
        .connections
        .get_mut(&generation)
        .ok_or("connection")?;
    let mut request = "A".repeat(SASL_REQUEST_CHARACTERS - 2);
    request.push_str("==");
    for chunk in request.as_bytes().chunks(400) {
        let _actions = connection.sasl.client(std::str::from_utf8(chunk)?, now)?;
    }
    Ok(())
}

#[tokio::test]
async fn an_authentication_finish_sealed_against_a_stale_count_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "finisher").await?;
    let (outcome, envelope) = rejected_authentication_finish(&mut live, 2, transaction_id)?;
    let sealed = outcome.seal(live.response_count()?.saturating_add(1))?;
    arm_sasl_finish(&mut live)?;
    let request = live.sasl(AccountCarrierPhase::Finish, envelope);
    let login = NormalizedLogin::prepare("finisher")?;
    let (coordinator, context) = live.fixture.parts()?;
    let at = context.now();
    let staged = coordinator.stage_finish(
        context,
        request,
        transaction_id,
        sealed,
        None,
        login,
        None,
        at,
    );
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[tokio::test]
async fn an_authentication_finish_behind_an_unsettled_batch_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "finisher").await?;
    let (outcome, envelope) = rejected_authentication_finish(&mut live, 2, transaction_id)?;
    let sealed = outcome.seal(live.response_count()?)?;
    arm_sasl_finish(&mut live)?;
    let request = live.sasl(AccountCarrierPhase::Finish, envelope);
    let login = NormalizedLogin::prepare("finisher")?;
    live.occupy_pending_batch()?;
    let (coordinator, context) = live.fixture.parts()?;
    let at = context.now();
    let staged = coordinator.stage_finish(
        context,
        request,
        transaction_id,
        sealed,
        None,
        login,
        None,
        at,
    );
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 1)
}

#[tokio::test]
async fn a_ready_finish_that_cannot_stage_closes_its_carrier_and_queues_the_row() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "finisher").await?;
    let (outcome, envelope) = rejected_authentication_finish(&mut live, 2, transaction_id)?;
    let sealed = outcome.seal(live.response_count()?.saturating_add(1))?;
    live.fixture.coordinator.ready_stage = Some(ReadyStage::Finish {
        request: live.sasl(AccountCarrierPhase::Finish, envelope),
        transaction_id,
        sealed,
        account_id: None,
        login: NormalizedLogin::prepare("finisher")?,
        previous_value: None,
        authenticated_at: MonotonicTick::from_ticks(0),
    });
    let (coordinator, context) = live.fixture.parts()?;
    let completions = coordinator.progress(context);
    assert!(matches!(completions.as_slice(), [completion] if completion.close));
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    let cleanup = coordinator.pending_cleanups.first();
    assert!(cleanup.is_some_and(|cleanup| cleanup.transaction_id == transaction_id));
    Ok(())
}

async fn committed_worker_outcome(live: &mut Live) -> TestResult<Box<WorkerOutcome>> {
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
    worker_finish(
        &mut live.fixture,
        live.generation,
        live.route,
        2,
        transaction_id,
        WALL,
    )
}

fn stage_creation_finish(
    live: &mut Live,
    outcome: WorkerOutcome,
    reservation: Option<CreationReservation>,
) -> Result<(), RuntimeError> {
    let request = live.account(CREATE, AccountCarrierPhase::Finish, outcome.envelope);
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.stage_creation_finish(
        context,
        request,
        outcome.transaction_id,
        outcome.sealed,
        reservation,
    )
}

#[tokio::test]
async fn a_committed_creation_without_its_login_reservation_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    let outcome = *committed_worker_outcome(&mut live).await?;
    assert!(outcome.sealed.result().is_ok());
    let staged = stage_creation_finish(&mut live, outcome, None);
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[tokio::test]
async fn a_committed_creation_whose_reserved_login_key_differs_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    let outcome = *committed_worker_outcome(&mut live).await?;
    let generation = live.fixture.core.key_state.current_generation();
    let foreign =
        LoginIndexStoredKey::new(generation, LoginIndexDigest::from_storage_key([1; 32]))?
            .encode()?;
    let reservation = Some(CreationReservation {
        login_key: foreign,
        invitation_id: None,
    });
    let staged = stage_creation_finish(&mut live, outcome, reservation);
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[tokio::test]
async fn a_committed_open_creation_holding_an_invitation_reservation_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    let outcome = *committed_worker_outcome(&mut live).await?;
    let mut reservation = outcome.reservation.clone().ok_or("reservation")?;
    reservation.invitation_id = Some(InviteId::from_bytes([6; 16]));
    let staged = stage_creation_finish(&mut live, outcome, Some(reservation));
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[tokio::test]
async fn a_creation_finish_behind_an_unsettled_batch_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    let outcome = *committed_worker_outcome(&mut live).await?;
    let reservation = outcome.reservation.clone();
    live.occupy_pending_batch()?;
    let staged = stage_creation_finish(&mut live, outcome, reservation);
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 1)
}

#[tokio::test]
async fn a_creation_finish_sealed_before_another_response_committed_is_not_staged() -> TestResult {
    let mut live = Live::open()?;
    let outcome = *committed_worker_outcome(&mut live).await?;
    let reservation = outcome.reservation.clone();
    let _later = commit_authentication_start(&mut live, 3, "interleaved").await?;
    let staged = stage_creation_finish(&mut live, outcome, reservation);
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[tokio::test]
async fn a_committed_creation_for_an_account_that_already_has_a_login_closes() -> TestResult {
    let mut live = Live::open()?;
    let outcome = *committed_worker_outcome(&mut live).await?;
    let reservation = outcome.reservation.clone();
    let account_id = outcome
        .sealed
        .result()
        .map(agenc_relay_auth::CreateAccountIntent::account_id)
        .map_err(|_| "committed outcome")?;
    let foreign = StoredKey::new(vec![3; 40])?;
    stage_creation_finish(&mut live, outcome, reservation)?;
    live.fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator
        .config
        .live_login_keys
        .insert(account_id, foreign.clone());
    let completions = coordinator.batch_applied(context);
    assert!(matches!(completions.as_slice(), [completion] if completion.close));
    assert!(coordinator.config.live_login_keys.get(&account_id) == Some(&foreign));
    Ok(())
}

#[tokio::test]
async fn a_committed_creation_whose_transaction_owner_vanished_closes() -> TestResult {
    let mut live = Live::open()?;
    let outcome = *committed_worker_outcome(&mut live).await?;
    let reservation = outcome.reservation.clone();
    let transaction_id = outcome.transaction_id;
    stage_creation_finish(&mut live, outcome, reservation)?;
    live.fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.transaction_owners.remove(&transaction_id);
    let completions = coordinator.batch_applied(context);
    assert!(matches!(completions.as_slice(), [completion] if completion.close));
    Ok(())
}

#[tokio::test]
async fn a_rejected_credential_finish_deletes_the_transaction_and_reports_failure() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let transaction_id = commit_credential_start(&mut live, 1, account_id).await?;
    let (outcome, envelope) = rejected_credential_finish(&mut live, 2, transaction_id)?;
    let sealed = outcome.seal(live.response_count()?)?;
    arm_transfer(
        &mut live,
        CREDENTIALS,
        AccountCarrierPhase::Finish,
        &envelope,
    )?;
    let request = live.account(CREDENTIALS, AccountCarrierPhase::Finish, envelope);
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.stage_credential_finish(context, request, transaction_id, sealed, None)?;
    live.fixture.core.commit_staged_batch().await?;
    let (coordinator, context) = live.fixture.parts()?;
    let completions = coordinator.batch_applied(context);
    let [completion] = completions.as_slice() else {
        return Err("one completion".into());
    };
    assert!(!completion.close);
    assert_eq!(completion.result, ResultClass::Rejected);
    assert!(!coordinator.transaction_owners.contains_key(&transaction_id));
    let lines = live.sink.lines();
    assert!(lines.iter().any(|line| line.contains("FAIL ACCTCRED")));
    assert!(!lines.iter().any(|line| line.contains("CHANGED")));
    Ok(())
}

#[tokio::test]
async fn a_credential_finish_from_an_unregistered_connection_is_not_staged() -> TestResult {
    let (mut registered, account_id) = Live::open_registered()?;
    let transaction_id = commit_credential_start(&mut registered, 1, account_id).await?;
    let (outcome, envelope) = rejected_credential_finish(&mut registered, 2, transaction_id)?;
    let sealed = outcome.seal(registered.response_count()?)?;
    let mut request = registered.account(CREDENTIALS, AccountCarrierPhase::Finish, envelope);
    request.generation = ConnectionGeneration::new(77);
    let (coordinator, context) = registered.fixture.parts()?;
    let staged =
        coordinator.stage_credential_finish(context, request, transaction_id, sealed, None);
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut registered, 0)
}

#[tokio::test]
async fn a_credential_finish_sealed_against_a_stale_count_is_not_staged() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let transaction_id = commit_credential_start(&mut live, 1, account_id).await?;
    let (outcome, envelope) = rejected_credential_finish(&mut live, 2, transaction_id)?;
    let sealed = outcome.seal(live.response_count()?.saturating_add(1))?;
    arm_transfer(
        &mut live,
        CREDENTIALS,
        AccountCarrierPhase::Finish,
        &envelope,
    )?;
    let request = live.account(CREDENTIALS, AccountCarrierPhase::Finish, envelope);
    let (coordinator, context) = live.fixture.parts()?;
    let staged =
        coordinator.stage_credential_finish(context, request, transaction_id, sealed, None);
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 0)
}

#[tokio::test]
async fn a_credential_finish_behind_an_unsettled_batch_is_not_staged() -> TestResult {
    let (mut live, account_id) = Live::open_registered()?;
    let transaction_id = commit_credential_start(&mut live, 1, account_id).await?;
    let (outcome, envelope) = rejected_credential_finish(&mut live, 2, transaction_id)?;
    let sealed = outcome.seal(live.response_count()?)?;
    arm_transfer(
        &mut live,
        CREDENTIALS,
        AccountCarrierPhase::Finish,
        &envelope,
    )?;
    let request = live.account(CREDENTIALS, AccountCarrierPhase::Finish, envelope);
    live.occupy_pending_batch()?;
    let (coordinator, context) = live.fixture.parts()?;
    let staged =
        coordinator.stage_credential_finish(context, request, transaction_id, sealed, None);
    assert_eq!(staged.err(), Some(RuntimeError::InvalidValue));
    assert_nothing_staged(&mut live, 1)
}
