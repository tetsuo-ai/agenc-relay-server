//! Refusals decided when an opened account-service request meets the
//! connection's live state: unreadable requests, payloads on the wrong carrier
//! phase, exchanges already in progress, finishes without a live exchange, and
//! the per-connection and per-login attempt limits.
#![forbid(unsafe_code)]

use super::harness::{
    Live, arm_sasl, authentication_finish, authentication_start, commit_authentication_start,
    creation_finish, creation_start, credential_finish, credential_start,
};
use super::invitation_window::commit_start;
use super::*;
use crate::test_support::TestResult;
use agenc_ircd_auth::{AuthError, OpenedAccountServiceRequest};

fn assert_refused(live: &Live, completions: &[CarrierCompletion], line: &str) -> TestResult {
    let [completion] = completions else {
        return Err("a refusal completes exactly one carrier".into());
    };
    assert_eq!(completion.generation, live.generation);
    assert!(!completion.close);
    assert_eq!(completion.result, ResultClass::Rejected);
    assert!(live.fixture.coordinator.reads.is_empty());
    assert!(live.fixture.coordinator.crypto.is_empty());
    let lines = live.sink.lines();
    assert!(
        lines.iter().any(|sent| sent.contains(line)),
        "missing {line:?} in {lines:?}"
    );
    Ok(())
}

fn open(
    live: &mut Live,
    request: RequestContext,
    opened: Result<OpenedAccountServiceRequest, AuthError>,
) -> Result<Vec<CarrierCompletion>, RuntimeError> {
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.open_completed(context, request, opened)
}

#[test]
fn an_unreadable_sasl_request_is_answered_with_the_authentication_failure() -> TestResult {
    let mut live = Live::open()?;
    let (_, envelope) = authentication_start(&live.fixture.core.identity, 1, "reader")?;
    arm_sasl(&mut live.fixture, live.generation, false)?;
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let completions = open(&mut live, request, Err(AuthError::ContextMismatch))?;
    assert_refused(&live, &completions, " 904 tester ")
}

#[test]
fn an_unreadable_creation_request_is_answered_with_the_creation_failure() -> TestResult {
    let mut live = Live::open()?;
    let (_, envelope) = creation_start(&live.fixture.core.identity, 1, "reader")?;
    let request = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Start,
        envelope,
    );
    let completions = open(&mut live, request, Err(AuthError::InvalidEncoding))?;
    assert_refused(&live, &completions, "FAIL ACCTCREATE UNAVAILABLE")
}

#[test]
fn an_unreadable_credential_request_is_answered_with_the_credential_failure() -> TestResult {
    let mut live = Live::open()?;
    let (_, envelope) = credential_start(&live.fixture.core.identity, 1, account(4))?;
    let request = live.account(
        AccountCarrierKind::Credentials,
        AccountCarrierPhase::Start,
        envelope,
    );
    let completions = open(&mut live, request, Err(AuthError::InvalidEncoding))?;
    assert_refused(&live, &completions, "FAIL ACCTCRED UNAVAILABLE")
}

#[test]
fn a_refusal_whose_sasl_carrier_is_not_waiting_fails_the_continuation() -> TestResult {
    let mut live = Live::open()?;
    let (_, envelope) = authentication_start(&live.fixture.core.identity, 1, "reader")?;
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let refused = open(&mut live, request, Err(AuthError::ContextMismatch));
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    assert!(live.sink.lines().is_empty());
    Ok(())
}

#[test]
fn a_refusal_for_a_connection_that_already_closed_fails_the_continuation() -> TestResult {
    let mut live = Live::open()?;
    let (opened, envelope) = creation_start(&live.fixture.core.identity, 1, "reader")?;
    let request = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Start,
        envelope,
    );
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.connection_closed(context, generation);
    let refused = coordinator.open_completed(
        context,
        request,
        Ok(OpenedAccountServiceRequest::CreationStart(opened)),
    );
    assert_eq!(refused.err(), Some(RuntimeError::InvalidValue));
    assert!(coordinator.reads.is_empty());
    Ok(())
}

#[test]
fn a_creation_start_payload_on_a_finish_phase_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let (opened, envelope) = creation_start(&live.fixture.core.identity, 1, "phase-user")?;
    let request = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Finish,
        envelope,
    );
    let opened = OpenedAccountServiceRequest::CreationStart(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, "FAIL ACCTCREATE UNAVAILABLE")
}

#[test]
fn a_creation_finish_payload_on_a_start_phase_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([5; 16]);
    let (opened, envelope) = creation_finish(&live.fixture.core.identity, 1, transaction_id)?;
    let request = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Start,
        envelope,
    );
    let opened = OpenedAccountServiceRequest::CreationFinish(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, "FAIL ACCTCREATE UNAVAILABLE")
}

#[test]
fn a_credential_start_payload_on_a_finish_phase_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let (opened, envelope) = credential_start(&live.fixture.core.identity, 1, account(4))?;
    let request = live.account(
        AccountCarrierKind::Credentials,
        AccountCarrierPhase::Finish,
        envelope,
    );
    let opened = OpenedAccountServiceRequest::CredentialChangeStart(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, "FAIL ACCTCRED UNAVAILABLE")
}

#[test]
fn a_credential_finish_payload_on_a_start_phase_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([5; 16]);
    let (opened, envelope) = credential_finish(&live.fixture.core.identity, 1, transaction_id)?;
    let request = live.account(
        AccountCarrierKind::Credentials,
        AccountCarrierPhase::Start,
        envelope,
    );
    let opened = OpenedAccountServiceRequest::CredentialChangeFinish(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, "FAIL ACCTCRED UNAVAILABLE")
}

#[test]
fn an_authentication_start_payload_on_a_finish_phase_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let (opened, envelope) = authentication_start(&live.fixture.core.identity, 1, "phase-user")?;
    arm_sasl(&mut live.fixture, live.generation, true)?;
    let request = live.sasl(AccountCarrierPhase::Finish, envelope);
    let opened = OpenedAccountServiceRequest::AuthenticationStart(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, " 904 tester ")?;
    let connection = live.fixture.coordinator.connections.get(&live.generation);
    assert_eq!(
        connection.map(|connection| connection.opaque_attempts),
        Some(0)
    );
    Ok(())
}

#[test]
fn an_authentication_finish_payload_on_a_start_phase_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([5; 16]);
    let (opened, envelope) = authentication_finish(&live.fixture.core.identity, 1, transaction_id)?;
    arm_sasl(&mut live.fixture, live.generation, false)?;
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let opened = OpenedAccountServiceRequest::AuthenticationFinish(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, " 904 tester ")
}

#[tokio::test]
async fn a_second_creation_start_during_a_live_creation_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_start(
        &mut live.fixture,
        live.generation,
        live.route,
        1,
        "first-user",
        None,
        super::harness::WALL,
    )
    .await?;
    let (opened, envelope) = creation_start(&live.fixture.core.identity, 2, "second-user")?;
    let request = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Start,
        envelope,
    );
    let opened = OpenedAccountServiceRequest::CreationStart(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, "FAIL ACCTCREATE UNAVAILABLE")?;
    let owners = &live.fixture.coordinator.transaction_owners;
    assert!(owners.contains_key(&transaction_id));
    Ok(())
}

#[test]
fn a_creation_finish_without_a_live_creation_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([5; 16]);
    let (opened, envelope) = creation_finish(&live.fixture.core.identity, 1, transaction_id)?;
    let request = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Finish,
        envelope,
    );
    let opened = OpenedAccountServiceRequest::CreationFinish(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, "FAIL ACCTCREATE UNAVAILABLE")
}

#[test]
fn a_credential_finish_without_a_live_credential_change_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([5; 16]);
    let (opened, envelope) = credential_finish(&live.fixture.core.identity, 1, transaction_id)?;
    let request = live.account(
        AccountCarrierKind::Credentials,
        AccountCarrierPhase::Finish,
        envelope,
    );
    let opened = OpenedAccountServiceRequest::CredentialChangeFinish(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, "FAIL ACCTCRED UNAVAILABLE")
}

#[test]
fn an_authentication_finish_without_a_live_exchange_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([5; 16]);
    let (opened, envelope) = authentication_finish(&live.fixture.core.identity, 1, transaction_id)?;
    arm_sasl(&mut live.fixture, live.generation, true)?;
    let request = live.sasl(AccountCarrierPhase::Finish, envelope);
    let opened = OpenedAccountServiceRequest::AuthenticationFinish(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, " 904 tester ")
}

#[test]
fn a_third_login_on_one_connection_is_refused_with_the_attempt_limit() -> TestResult {
    let mut live = Live::open()?;
    let (opened, envelope) = authentication_start(&live.fixture.core.identity, 1, "limited")?;
    arm_sasl(&mut live.fixture, live.generation, false)?;
    live.fixture
        .coordinator
        .connections
        .get_mut(&live.generation)
        .ok_or("connection")?
        .opaque_attempts = MAX_OPAQUE_ATTEMPTS_PER_CONNECTION;
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let opened = OpenedAccountServiceRequest::AuthenticationStart(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, " 904 tester ")?;
    let connection = live.fixture.coordinator.connections.get(&live.generation);
    assert_eq!(
        connection.map(|connection| connection.opaque_attempts),
        Some(MAX_OPAQUE_ATTEMPTS_PER_CONNECTION)
    );
    Ok(())
}

#[test]
fn a_login_whose_keyed_bucket_is_spent_is_refused_before_any_lookup() -> TestResult {
    let mut live = Live::open()?;
    let (opened, envelope) = authentication_start(&live.fixture.core.identity, 1, "bursty")?;
    arm_sasl(&mut live.fixture, live.generation, false)?;
    let login = NormalizedLogin::prepare("bursty")?;
    let (coordinator, context) = live.fixture.parts()?;
    while coordinator.charge_opaque_attempt(context, &login).is_ok() {}
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let opened = OpenedAccountServiceRequest::AuthenticationStart(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, " 904 tester ")?;
    // The connection attempt was consumed before the keyed bucket refused.
    let connection = live.fixture.coordinator.connections.get(&live.generation);
    assert_eq!(
        connection.map(|connection| connection.opaque_attempts),
        Some(1)
    );
    Ok(())
}

#[test]
fn an_admitted_login_consumes_one_attempt_and_starts_the_current_index_lookup() -> TestResult {
    let mut live = Live::open()?;
    let (opened, envelope) = authentication_start(&live.fixture.core.identity, 1, "admitted")?;
    arm_sasl(&mut live.fixture, live.generation, false)?;
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let opened = OpenedAccountServiceRequest::AuthenticationStart(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert!(completions.is_empty());
    assert_eq!(live.fixture.coordinator.reads.len(), 1);
    assert!(live.sink.lines().is_empty());
    Ok(())
}

#[tokio::test]
async fn an_authentication_finish_consumes_the_live_exchange_and_its_timer() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = commit_authentication_start(&mut live, 1, "finisher").await?;
    let (opened, envelope) = authentication_finish(&live.fixture.core.identity, 2, transaction_id)?;
    let request = live.sasl(AccountCarrierPhase::Finish, envelope);
    let opened = OpenedAccountServiceRequest::AuthenticationFinish(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert!(completions.is_empty());
    let coordinator = &live.fixture.coordinator;
    assert!(matches!(
        coordinator.crypto.values().next(),
        Some(PendingCrypto::Finish { transaction_id: pending, .. }) if *pending == transaction_id
    ));
    let connection = coordinator.connections.get(&live.generation);
    assert!(connection.is_some_and(|connection| connection.transaction.is_none()));
    Ok(())
}

#[test]
fn a_refused_creation_spends_the_one_use_carrier() -> TestResult {
    let mut live = Live::open()?;
    let transaction_id = TransactionId::from_bytes([5; 16]);
    let (opened, envelope) = creation_finish(&live.fixture.core.identity, 1, transaction_id)?;
    let request = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Finish,
        envelope,
    );
    let opened = OpenedAccountServiceRequest::CreationFinish(opened);
    let completions = open(&mut live, request, Ok(opened))?;
    assert_refused(&live, &completions, "FAIL ACCTCREATE UNAVAILABLE")?;
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let retried = coordinator.route_account(
        context,
        generation,
        2,
        "tester",
        AccountCarrierKind::Create,
        parsed("ACCTCREATE START 4726")?,
    );
    assert!(matches!(
        retried,
        CarrierRoute::Finished {
            result: ResultClass::Rejected,
            ..
        }
    ));
    Ok(())
}
