//! A successor bind names exactly the conversation and group the activated
//! attempt authorized.

#![forbid(unsafe_code)]

use super::*;

const OTHER_GROUP: [u8; 32] = [12; 32];

#[test]
fn a_successor_bind_for_another_conversation_than_the_activated_one_is_refused() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let mut package = fixture.package.clone();
    let other = agenc_ircd_e2ee::ids::conversation_id(&NETWORK, &OTHER_GROUP)?;
    package.binding.tbs.group_id = Opaque::from_slice(&OTHER_GROUP)?;
    package.binding.tbs.conversation_id = other;
    let mut params = fixture.reservation.to_vec();
    params.extend_from_slice(&other);
    params.extend_from_slice(&CONTEXT);
    let bytes = wire(IrcWireObjectKind::ConversationBinding, &package)?;
    assert_eq!(
        code(fixture.harness.run(Op::BindGroup, &params, Some(&bytes))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let original = fixture.package.clone();
    ok(fixture.bind(&original, CONTEXT)?)?;
    Ok(())
}

#[test]
fn a_successor_bind_whose_group_differs_from_the_attempt_target_is_refused() -> TestResult {
    let mut harness = Harness::new()?;
    let old = harness.bind_channel()?;
    // The attempt targets the edited binding exactly, but keeps the group the
    // builder authorized, so only the group comparison can refuse the bind.
    let mut fixture = Fixture::prepare_bound_with(harness, old, |package, _| {
        package.binding.tbs.group_id = Opaque::from_slice(&OTHER_GROUP)?;
        package.binding.tbs.conversation_id =
            agenc_ircd_e2ee::ids::conversation_id(&NETWORK, &OTHER_GROUP)?;
        Ok(())
    })?;
    fixture.activate()?;
    let package = fixture.package.clone();
    assert_eq!(
        code(fixture.bind(&package, CONTEXT)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    Ok(())
}
