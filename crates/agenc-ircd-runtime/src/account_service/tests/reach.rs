//! Both carriers refuse an envelope that is the wrong width, unreadable or of
//! the wrong phase before any storage read is submitted.
#![forbid(unsafe_code)]

use super::harness::{Live, arm_sasl, authentication_start};
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
