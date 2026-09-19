//! Both carriers refuse an envelope that is the wrong width, unreadable or of
//! the wrong phase before any storage read is submitted.
#![forbid(unsafe_code)]

use super::harness::{Live, WALL, arm_sasl, authentication_start};
use super::*;
use crate::test_support::TestResult;
use agenc_ircd_auth::ACCOUNT_SERVICE_ENVELOPE_BYTES;

fn rejected(route: &CarrierRoute) -> bool {
    matches!(
        route,
        CarrierRoute::Finished {
            result: ResultClass::Rejected,
            ..
        }
    )
}

#[test]
fn a_sasl_envelope_of_the_wrong_width_closes_and_an_unreadable_one_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let (generation, route) = (live.generation, live.route);
    arm_sasl(&mut live.fixture, generation, false)?;
    let (coordinator, context) = live.fixture.parts()?;
    let short = SecretBytes::new(&[0; 16])?;
    assert!(matches!(
        coordinator.route_envelope(context, generation, 1, "*", route, false, short),
        CarrierRoute::Close
    ));
    let zeroed = SecretBytes::new(&[0; ACCOUNT_SERVICE_ENVELOPE_BYTES])?;
    assert!(rejected(&coordinator.route_envelope(
        context, generation, 1, "*", route, false, zeroed
    )));
    assert!(coordinator.reads.is_empty());
    Ok(())
}

#[test]
fn a_sasl_start_envelope_offered_as_a_finish_is_refused_for_its_phase() -> TestResult {
    let mut live = Live::open()?;
    let (generation, route) = (live.generation, live.route);
    let (_, envelope) = authentication_start(&live.fixture.core.identity, 1, "phased")?;
    let bytes = SecretBytes::new(envelope.as_bytes())?;
    arm_sasl(&mut live.fixture, generation, false)?;
    let (coordinator, context) = live.fixture.parts()?;
    assert!(rejected(&coordinator.route_envelope(
        context, generation, 1, "*", route, true, bytes
    )));
    assert!(coordinator.reads.is_empty());
    Ok(())
}

#[test]
fn an_account_envelope_of_the_wrong_width_unreadable_or_wrong_kind_is_refused() -> TestResult {
    let mut live = Live::open()?;
    let (generation, route) = (live.generation, live.route);
    let (_, envelope) = authentication_start(&live.fixture.core.identity, 1, "phased")?;
    let start = SecretBytes::new(envelope.as_bytes())?;
    let (coordinator, context) = live.fixture.parts()?;
    let kind = AccountCarrierKind::Create;
    let phase = AccountCarrierPhase::Start;
    let short = SecretBytes::new(&[0; 16])?;
    assert!(matches!(
        coordinator.route_account_envelope(context, generation, 1, "*", route, kind, phase, short),
        CarrierRoute::Close
    ));
    let zeroed = SecretBytes::new(&[0; ACCOUNT_SERVICE_ENVELOPE_BYTES])?;
    assert!(rejected(&coordinator.route_account_envelope(
        context, generation, 1, "*", route, kind, phase, zeroed
    )));
    assert!(rejected(&coordinator.route_account_envelope(
        context, generation, 1, "*", route, kind, phase, start
    )));
    assert!(coordinator.reads.is_empty());
    Ok(())
}

/// A sealed authentication START completing while an earlier ready stage
/// still waits for its batch closes its own carrier and leaves the stage alone.
#[test]
fn an_authentication_seal_completing_behind_a_ready_stage_closes_its_carrier() -> TestResult {
    use super::harness::sealed_unknown_authentication;
    use crate::account_service::ReadyStage;
    let mut live = Live::open()?;
    let (first, envelope_a) = sealed_unknown_authentication(&mut live, 1, "stager")?;
    let (second, envelope_b) = sealed_unknown_authentication(&mut live, 2, "stager")?;
    let request_a = live.sasl(AccountCarrierPhase::Start, envelope_a);
    let request_b = live.sasl(AccountCarrierPhase::Start, envelope_b);
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.ready_stage = Some(ReadyStage::Start {
        request: request_a,
        sealed: first,
        account_id: None,
        login: NormalizedLogin::prepare("stager")?,
        previous_value: None,
    });
    let job_id = CryptoJobId::new(77);
    coordinator.crypto.insert(
        job_id,
        PendingCrypto::StartSeal {
            request: request_b,
            account_id: None,
            login: NormalizedLogin::prepare("stager")?,
            previous_value: None,
        },
    );
    let completions = coordinator.crypto_completed(
        context,
        CryptoCompletionMessage {
            job_id,
            output: Ok(CryptoJobOutput::OpaqueStartSealed(Box::new(Ok(second)))),
        },
    );
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.generation == generation
    ));
    assert!(
        coordinator.ready_stage.is_some(),
        "the earlier stage is kept"
    );
    assert!(coordinator.crypto.is_empty());
    Ok(())
}

/// The same fence for a sealed creation START.
#[test]
fn a_creation_seal_completing_behind_a_ready_stage_closes_its_carrier() -> TestResult {
    use super::harness::begin_creation;
    use crate::account_service::ReadyStage;
    let mut live = Live::open()?;
    let (start_a, envelope_a) = begin_creation(&mut live, 3, "creator", true)?;
    let (start_b, envelope_b) = begin_creation(&mut live, 4, "creator", true)?;
    let request_a = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Start,
        envelope_a,
    );
    let request_b = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Start,
        envelope_b,
    );
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let count = context.head().account_service_response_count;
    coordinator.ready_stage = Some(ReadyStage::CreationStart {
        request: request_a,
        sealed: start_a.seal(count)?,
    });
    let job_id = CryptoJobId::new(78);
    coordinator.crypto.insert(
        job_id,
        PendingCrypto::CreationStartSeal { request: request_b },
    );
    let output = CryptoJobOutput::CreationStartSealed(Box::new(Ok(start_b.seal(count)?)));
    let completions = coordinator.crypto_completed(
        context,
        CryptoCompletionMessage {
            job_id,
            output: Ok(output),
        },
    );
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.generation == generation
    ));
    assert!(coordinator.ready_stage.is_some());
    Ok(())
}

/// The same fence for a sealed credential-change START.
#[test]
fn a_credential_seal_completing_behind_a_ready_stage_closes_its_carrier() -> TestResult {
    use super::harness::begin_unavailable_credential_change;
    use crate::account_service::ReadyStage;
    let (mut live, account_id) = Live::open_registered()?;
    let (start_a, envelope_a) = begin_unavailable_credential_change(&mut live, 5, account_id)?;
    let (start_b, envelope_b) = begin_unavailable_credential_change(&mut live, 6, account_id)?;
    let request_a = live.account(
        AccountCarrierKind::Credentials,
        AccountCarrierPhase::Start,
        envelope_a,
    );
    let request_b = live.account(
        AccountCarrierKind::Credentials,
        AccountCarrierPhase::Start,
        envelope_b,
    );
    let generation = live.generation;
    let (coordinator, context) = live.fixture.parts()?;
    let count = context.head().account_service_response_count;
    coordinator.ready_stage = Some(ReadyStage::CredentialStart {
        request: request_a,
        sealed: start_a.seal(count)?,
        reservation: None,
    });
    let job_id = CryptoJobId::new(79);
    coordinator.crypto.insert(
        job_id,
        PendingCrypto::CredentialStartSeal {
            request: request_b,
            reservation: None,
        },
    );
    let output = CryptoJobOutput::CredentialStartSealed(Box::new(Ok(start_b.seal(count)?)));
    let completions = coordinator.crypto_completed(
        context,
        CryptoCompletionMessage {
            job_id,
            output: Ok(output),
        },
    );
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.generation == generation
    ));
    assert!(coordinator.ready_stage.is_some());
    Ok(())
}

/// The same fence for a sealed creation FINISH, whose seal arrives with its
/// transaction and reservation.
#[tokio::test]
async fn a_creation_finish_seal_completing_behind_a_ready_stage_closes_its_carrier() -> TestResult {
    use super::invitation_window::{commit_start, open_connection, worker_finish};
    use crate::account_service::ReadyStage;
    let mut live = Live::open()?;
    let generation = live.generation;
    let route = live.route;
    let first = commit_start(
        &mut live.fixture,
        generation,
        route,
        1,
        "finisher",
        None,
        WALL,
    )
    .await?;
    let first = worker_finish(&mut live.fixture, generation, route, 2, first, WALL)?;
    // A second connection carries the second creation.
    let other = ConnectionGeneration::new(2);
    let (_other_sink, other_route) = open_connection(&mut live.fixture, other)?;
    let second = commit_start(
        &mut live.fixture,
        other,
        other_route,
        3,
        "finisher2",
        None,
        WALL,
    )
    .await?;
    let second = worker_finish(&mut live.fixture, other, other_route, 4, second, WALL)?;
    let (coordinator, context) = live.fixture.parts()?;
    coordinator.ready_stage = Some(ReadyStage::CreationFinish {
        request: live_request(generation, route, first.envelope),
        transaction_id: first.transaction_id,
        sealed: first.sealed,
        reservation: first.reservation,
    });
    let job_id = CryptoJobId::new(80);
    coordinator.crypto.insert(
        job_id,
        PendingCrypto::CreationFinishSeal {
            request: live_request(other, other_route, second.envelope),
            transaction_id: second.transaction_id,
            reservation: second.reservation,
        },
    );
    let output = CryptoJobOutput::CreationFinishSealed(Box::new(Ok(second.sealed)));
    let completions = coordinator.crypto_completed(
        context,
        CryptoCompletionMessage {
            job_id,
            output: Ok(output),
        },
    );
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.generation == other
    ));
    assert!(coordinator.ready_stage.is_some());
    Ok(())
}

fn live_request(
    generation: ConnectionGeneration,
    route: ConnectionRoute,
    envelope: AccountServiceEnvelope,
) -> RequestContext {
    super::harness::account_request(
        generation,
        2,
        route,
        AccountCarrierKind::Create,
        AccountCarrierPhase::Finish,
        envelope,
    )
}

/// A creation FINISH whose worker output carries another transaction than
/// the job was submitted for closes its carrier.
#[tokio::test]
async fn a_creation_finish_output_for_another_transaction_closes_its_carrier() -> TestResult {
    use super::harness::creation_finish;
    use super::invitation_window::commit_start;
    use crate::account_service::LiveCreation;
    use crate::bridge::crypto::CreationFinishOutput;
    let mut live = Live::open()?;
    let generation = live.generation;
    let route = live.route;
    let started = commit_start(
        &mut live.fixture,
        generation,
        route,
        1,
        "mismatch",
        None,
        WALL,
    )
    .await?;
    let (_, envelope) = creation_finish(&live.fixture.core.identity, 2, started)?;
    let request = live.account(
        AccountCarrierKind::Create,
        AccountCarrierPhase::Finish,
        envelope,
    );
    let (coordinator, context) = live.fixture.parts()?;
    let LiveCreation {
        transaction,
        reservation,
    } = coordinator
        .connections
        .get_mut(&generation)
        .ok_or("connection")?
        .creation_transaction
        .take()
        .ok_or("live creation transaction")?;
    let job_id = CryptoJobId::new(81);
    coordinator.crypto.insert(
        job_id,
        PendingCrypto::CreationFinish {
            request,
            transaction_id: TransactionId::from_bytes([9; 16]),
            reservation,
        },
    );
    let output = CryptoJobOutput::CreationFinish(Box::new(CreationFinishOutput {
        transaction,
        outcome: Err(agenc_ircd_auth::AuthError::InvalidEncoding),
    }));
    let completions = coordinator.crypto_completed(
        context,
        CryptoCompletionMessage {
            job_id,
            output: Ok(output),
        },
    );
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.generation == generation
    ));
    assert!(coordinator.ready_seals.is_empty());
    Ok(())
}

/// The same for a credential-change FINISH.
#[tokio::test]
async fn a_credential_finish_output_for_another_transaction_closes_its_carrier() -> TestResult {
    use super::harness::{commit_credential_start, credential_finish};
    use crate::account_service::LiveCredentialChange;
    use crate::bridge::crypto::CredentialFinishOutput;
    let (mut live, account_id) = Live::open_registered()?;
    let generation = live.generation;
    let started = commit_credential_start(&mut live, 1, account_id).await?;
    let (_, envelope) = credential_finish(&live.fixture.core.identity, 2, started)?;
    let request = live.account(
        AccountCarrierKind::Credentials,
        AccountCarrierPhase::Finish,
        envelope,
    );
    let (coordinator, context) = live.fixture.parts()?;
    let LiveCredentialChange { transaction, .. } = coordinator
        .connections
        .get_mut(&generation)
        .ok_or("connection")?
        .credential_transaction
        .take()
        .ok_or("live credential transaction")?;
    let job_id = CryptoJobId::new(82);
    coordinator.crypto.insert(
        job_id,
        PendingCrypto::CredentialFinish {
            request,
            transaction_id: TransactionId::from_bytes([9; 16]),
            reservation: None,
        },
    );
    let output = CryptoJobOutput::CredentialFinish(Box::new(CredentialFinishOutput {
        transaction,
        outcome: Err(agenc_ircd_auth::AuthError::InvalidEncoding),
    }));
    let completions = coordinator.crypto_completed(
        context,
        CryptoCompletionMessage {
            job_id,
            output: Ok(output),
        },
    );
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.generation == generation
    ));
    assert!(coordinator.ready_seals.is_empty());
    Ok(())
}

/// Ready seals queue up to their ceiling; the outcome that would exceed it
/// closes its carrier, and no seal moves while a ready stage waits.
#[tokio::test]
async fn ready_seals_stop_at_their_ceiling_and_wait_behind_a_ready_stage() -> TestResult {
    use super::harness::{sealed_unknown_authentication, unsealed_unknown_authentication};
    use crate::account_service::{MAX_READY_SEALS, ReadySeal, ReadyStage};
    let mut live = Live::open()?;
    for seed in 0..MAX_READY_SEALS {
        let seed = u8::try_from(seed % 200).unwrap_or_default();
        let (outcome, envelope) = unsealed_unknown_authentication(&mut live, seed, "queued")?;
        let ready = ReadySeal::Start {
            request: live.sasl(AccountCarrierPhase::Start, envelope),
            outcome,
            account_id: None,
            login: NormalizedLogin::prepare("queued")?,
            previous_value: None,
        };
        live.fixture.coordinator.ready_seals.push_back(ready);
    }
    assert_eq!(live.fixture.coordinator.ready_seals.len(), MAX_READY_SEALS);
    let (outcome, envelope) = unsealed_unknown_authentication(&mut live, 201, "queued")?;
    let request = live.sasl(AccountCarrierPhase::Start, envelope);
    let (stage, stage_envelope) = sealed_unknown_authentication(&mut live, 202, "queued")?;
    let stage_request = live.sasl(AccountCarrierPhase::Start, stage_envelope);
    let generation = live.generation;
    // A batch already pending keeps the ready stage from being staged below.
    live.occupy_pending_batch()?;
    let (coordinator, context) = live.fixture.parts()?;
    let job_id = CryptoJobId::new(83);
    coordinator.crypto.insert(
        job_id,
        PendingCrypto::Start {
            request,
            account_id: None,
            login: NormalizedLogin::prepare("queued")?,
            previous_value: None,
        },
    );
    let completions = coordinator.crypto_completed(
        context,
        CryptoCompletionMessage {
            job_id,
            output: Ok(CryptoJobOutput::OpaqueStart(Box::new(Ok(outcome)))),
        },
    );
    assert!(matches!(
        completions.as_slice(),
        [completion] if completion.close && completion.generation == generation
    ));
    assert_eq!(coordinator.ready_seals.len(), MAX_READY_SEALS);

    // A ready stage holds every queued seal in place.
    coordinator.ready_stage = Some(ReadyStage::Start {
        request: stage_request,
        sealed: stage,
        account_id: None,
        login: NormalizedLogin::prepare("queued")?,
        previous_value: None,
    });
    let held = coordinator.progress(context);
    assert!(held.is_empty(), "nothing moves behind the ready stage");
    assert_eq!(coordinator.ready_seals.len(), MAX_READY_SEALS);
    assert!(coordinator.ready_stage.is_some());
    Ok(())
}
