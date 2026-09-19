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
