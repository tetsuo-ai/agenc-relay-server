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
