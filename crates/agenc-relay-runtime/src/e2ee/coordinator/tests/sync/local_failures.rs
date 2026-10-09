#![forbid(unsafe_code)]

//! A fresh request this coordinator cannot stage for a reason of its own is
//! answered with its failed result, which consumes its operation sequence
//! and commits no semantic mutation (companion 12.5): `E2EE_SYNCING` when a
//! target's route state cannot take the request's events, a delivery
//! stream not past READY/ACTIVE or one at the unacknowledged-event ceiling
//! (12.5, 11.9).

use agenc_relay_e2ee::object::ArcWireObject;
use agenc_relay_e2ee::objects::federation::{ArcFederationResult, ArcFederationResultKind};
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};

use super::*;
use crate::e2ee::coordinator::execute::{BaseView, OriginFacts, Staged, run};

/// Runs `EKEY PUBLISH IDENTITY`, whose completion event targets the
/// requester's edge, through the executor and returns the code of the
/// failed result it staged.
fn failed_code(harness: &mut Harness) -> TestResult<String> {
    let root = wire(ArcWireObjectKind::RootIdentity, &harness.principal.root)?;
    let complete = harness.request(super::super::Op::PublishIdentity, &[], Some(&root))?;
    let mut fixture = crate::test_support::StateCoreFixture::new(vec![0; 65_536])?;
    let context = fixture.context_mut()?;
    context.set_wall_for_test(super::super::NOW);
    let view = BaseView {
        context,
        peers: vec![ServerId::from_bytes(HOME)],
        base_capacity: Box::new(|_, _, _| true),
    };
    let staged = run(
        &mut harness.coordinator,
        view,
        LinkId::new(1),
        ServerId::from_bytes(HOME),
        complete,
        &|_| OriginFacts::default(),
    )
    .map_err(|code| format!("the request was not answered: {code:?}"))?;
    assert!(matches!(staged, Staged::Batch));
    let Some(PendingWork::Request(pending)) = harness.coordinator.pending.as_ref() else {
        return Err("no staged request".into());
    };
    let mut budget = DecodeBudget::new(1 << 16, 4_096);
    let object = ArcWireObject::decode_kind(
        &pending.result,
        Some(ArcWireObjectKind::FederationResult),
        &mut budget,
    )?;
    let result = ArcFederationResult::decode_exact(object.body(), &mut budget)?;
    assert_eq!(result.result_kind, ArcFederationResultKind::Failed);
    let encoded = result.encoded_result.as_slice();
    let length = usize::from(*encoded.first().ok_or("code length")?);
    Ok(String::from_utf8(
        encoded.get(1..=length).ok_or("code")?.to_vec(),
    )?)
}

#[test]
fn a_completion_target_not_past_ready_answers_e2ee_syncing() -> TestResult {
    let mut harness = Harness::new()?;
    harness.coordinator.state.streams.clear();
    assert_eq!(failed_code(&mut harness)?, "E2EE_SYNCING");
    Ok(())
}

#[test]
fn a_completion_target_at_its_event_ceiling_answers_e2ee_syncing() -> TestResult {
    let mut harness = Harness::new()?;
    // The edge's stream reached the unacknowledged-event ceiling and was
    // marked blocked.
    let mut stream =
        crate::e2ee::coordinator::events::DeliveryStream::with_row_capacity(1, &harness.backing)
            .map_err(|fault| format!("{fault:?}"))?;
    stream.blocked = true;
    harness
        .coordinator
        .state
        .streams
        .insert(ServerId::from_bytes(HOME), stream);
    assert_eq!(failed_code(&mut harness)?, "E2EE_SYNCING");
    Ok(())
}
