//! The application handler already gives each delivery event its complete payload.
#![forbid(unsafe_code)]
use super::*;

#[test]
fn an_accepted_application_does_not_grow_the_global_object_cache() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    // This isolates the already-bound application's memory effect. The signed
    // bootstrap and receipt path have separate sequencer and actor coverage.
    harness
        .coordinator
        .state
        .lifecycles
        .get_mut(&conversation)
        .ok_or("lifecycle")?
        .bootstrap_activated()?;
    let aad = ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: channel_route_binding(&NETWORK, &INSTANCE)?,
        latest_state_id: [22; 32],
    }
    .encode()?;
    let bytes = wire_raw(
        ArcWireObjectKind::ApplicationMls,
        private_message_bytes(&GROUP, 1, &aad)?,
    )?;
    let mut params = conversation.to_vec();
    params.extend_from_slice(&INSTANCE);
    let before = harness.coordinator.state.object_bytes;
    let outcome = ok(harness.run(Op::ApplicationChannel, &params, Some(&bytes))?)?;
    assert_eq!(outcome.result, ResultBody::AcceptedEvent);
    assert!(!outcome.writes.is_empty());
    assert!(!outcome.events.is_empty());
    for event in outcome.events {
        assert_eq!(event.payload.as_deref(), Some(bytes.as_slice()));
    }
    assert_eq!(
        harness.coordinator.state.object_bytes, before,
        "the application effect retained a second copy outside delivery ownership"
    );
    assert!(
        !harness
            .coordinator
            .state
            .objects
            .contains_key(&object_id(&bytes))
    );
    Ok(())
}
