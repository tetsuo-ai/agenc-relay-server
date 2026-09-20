#![forbid(unsafe_code)]

//! A channel reservation needs the requester's membership, and a binding must name the
//! conversation its package verifies to.

use super::*;

#[test]
fn a_channel_is_reserved_only_by_one_of_its_members() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    harness.channel_member = false;
    let mut reserve = INSTANCE.to_vec();
    reserve.push(5);
    reserve.extend_from_slice(b"#room");
    assert_eq!(
        code(harness.run(Op::ReserveChannel, &reserve, None)?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    harness.channel_member = true;
    assert!(matches!(
        ok(harness.run(Op::ReserveChannel, &reserve, None)?)?.result,
        ResultBody::Reserved(..)
    ));
    Ok(())
}

#[test]
fn a_binding_must_name_the_conversation_its_package_verifies_to() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let mut reserve = INSTANCE.to_vec();
    reserve.push(5);
    reserve.extend_from_slice(b"#room");
    let outcome = ok(harness.run(Op::ReserveChannel, &reserve, None)?)?;
    let ResultBody::Reserved(reservation_id, _) = outcome.result else {
        return Err("expected a reservation".into());
    };
    let binding = harness.binding_bytes()?;
    let mut bind = reservation_id.to_vec();
    bind.extend_from_slice(&[9; 32]);
    bind.extend_from_slice(&[44; 32]);
    assert_eq!(
        code(harness.run(Op::BindGroup, &bind, Some(&binding))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let mut bind = reservation_id.to_vec();
    bind.extend_from_slice(&conversation_id(&NETWORK, &GROUP)?);
    bind.extend_from_slice(&[44; 32]);
    assert!(matches!(
        ok(harness.run(Op::BindGroup, &bind, Some(&binding))?)?.result,
        ResultBody::Bound { .. }
    ));
    Ok(())
}

#[test]
fn application_traffic_needs_a_bound_sender_and_the_conversations_own_instance() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    harness
        .coordinator
        .state
        .lifecycles
        .get_mut(&conversation)
        .ok_or("the bound lifecycle")?
        .bootstrap_activated()?;
    let aad = IrcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: channel_route_binding(&NETWORK, &INSTANCE)?,
        latest_state_id: [22; 32],
    }
    .encode()?;
    let message = wire_raw(
        IrcWireObjectKind::ApplicationMls,
        private_message_bytes(&GROUP, 1, &aad)?,
    )?;
    let mut other_instance = conversation.to_vec();
    other_instance.extend_from_slice(&[9; 16]);
    assert_eq!(
        code(harness.run(Op::ApplicationChannel, &other_instance, Some(&message))?),
        Some(E2eeReplyCode::RouteInvalid),
        "an instance that is not this conversation's channel"
    );
    let mut send = conversation.to_vec();
    send.extend_from_slice(&INSTANCE);
    harness.channel_member = false;
    assert_eq!(
        code(harness.run(Op::ApplicationChannel, &send, Some(&message))?),
        Some(E2eeReplyCode::RouteInvalid),
        "a sender the base profile does not hold in the channel"
    );
    harness.channel_member = true;
    assert_eq!(
        ok(harness.run(Op::ApplicationChannel, &send, Some(&message))?)?.result,
        ResultBody::AcceptedEvent
    );
    Ok(())
}
