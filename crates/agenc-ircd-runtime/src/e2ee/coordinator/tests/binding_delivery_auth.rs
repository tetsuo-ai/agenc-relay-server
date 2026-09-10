//! Binding delivery requires an approved participant at the ingress boundary.

#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::tests::support::principal;
use crate::e2ee::coordinator::tests::{account_bytes, origin_key};
use agenc_ircd_e2ee::object::IrcWireObject;
use agenc_ircd_e2ee::objects::attach::{IrcDeviceAttach, IrcDeviceAttachChallenge};
use agenc_ircd_e2ee::objects::conversation::IrcConversationBindingPackage;

const ATTACKER_DEVICE: u8 = 62;

#[test]
fn a_verified_participant_can_deliver_a_binding_before_the_route_is_bound() -> TestResult {
    let (mut fixture, _, _) = finalization_fixture()?;
    let binding = other_binding(&fixture)?;
    assert!(
        !fixture
            .coordinator
            .state
            .conversations
            .contains_key(&binding.conversation)
    );
    deliver_binding(&mut fixture, &binding.bytes)?;
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), 1);
    Ok(())
}

#[test]
fn a_claimed_participant_cannot_deliver_a_binding_with_a_forged_approval() -> TestResult {
    let (mut fixture, _, _) = finalization_fixture()?;
    let binding = fixture.binding_bytes()?;
    deliver_binding(&mut fixture, &binding)?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object = IrcWireObject::decode_kind(
        &binding,
        Some(IrcWireObjectKind::ConversationBinding),
        &mut budget,
    )?;
    let mut package = IrcConversationBindingPackage::decode_exact(object.body(), &mut budget)?;
    let mut approvals = package.binding.approvals.as_slice().to_vec();
    approvals
        .first_mut()
        .ok_or("binding approval")?
        .device_signature = [0; 64];
    package.binding.approvals = TlsVec::new(approvals)?;
    let forged = wire(IrcWireObjectKind::ConversationBinding, &package)?;
    let mut parameters = account_param(&fixture.account);
    parameters.extend_from_slice(&DEVICE_ID);
    let before = retained_state(&fixture)?;
    assert_eq!(
        code(evaluate_request(
            &mut fixture,
            Op::DeliverBinding,
            &parameters,
            Some(&forged)
        )?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_eq!(retained_state(&fixture)?, before);
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), 1);
    Ok(())
}

#[test]
fn an_attached_nonparticipant_cannot_deliver_an_unchanged_valid_binding() -> TestResult {
    let (mut fixture, _, _) = finalization_fixture()?;
    let binding = fixture.binding_bytes()?;
    let recipient = fixture.account;
    deliver_binding(&mut fixture, &binding)?;
    attach_unrelated_account(&mut fixture)?;
    let before = retained_state(&fixture)?;
    let count = fixture.coordinator.state.mailboxes.item_count();
    let mut parameters = account_param(&recipient);
    parameters.extend_from_slice(&DEVICE_ID);
    let outcome = evaluate_request(
        &mut fixture,
        Op::DeliverBinding,
        &parameters,
        Some(&binding),
    )?;
    let Err(failure) = outcome else {
        return Err("nonparticipant binding delivery was admitted".into());
    };
    assert_eq!(failure.code, E2eeReplyCode::BindingAuthInvalid);
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), count);
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

fn attach_unrelated_account(fixture: &mut Harness) -> TestResult {
    fixture.account = account_bytes(60)?;
    fixture.principal = principal(61, &fixture.account, &[ATTACKER_DEVICE])?;
    fixture.devices = vec![ATTACKER_DEVICE];
    let origin = fixture
        .coordinator
        .state
        .origins
        .get_mut(&origin_key())
        .ok_or("authenticated origin")?;
    origin.account_id = Some(fixture.account);
    origin.account_digest = Some(agenc_ircd_e2ee::ids::account_id_digest(
        &NETWORK,
        &fixture.account,
    )?);
    origin.device = None;
    fixture.publish_identity_and_roster()?;
    let device = [ATTACKER_DEVICE; 16];
    let challenge = ok(fixture.run(Op::AttachBegin, &device, None)?)?;
    let bytes = &challenge.responses.first().ok_or("attach challenge")?.bytes;
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let object = IrcWireObject::decode_kind(
        bytes,
        Some(IrcWireObjectKind::DeviceAttachChallenge),
        &mut budget,
    )?;
    let challenge = IrcDeviceAttachChallenge::decode_exact(object.body(), &mut budget)?;
    assert_eq!(challenge.tbs.account_id.as_slice(), fixture.account);
    assert_eq!(challenge.tbs.device_id, device);
    let signature = sign(
        &key(ATTACKER_DEVICE),
        SignatureDomain::DeviceAttachPossession,
        &challenge.tbs,
    )?;
    let attach = wire(
        IrcWireObjectKind::DeviceAttach,
        &IrcDeviceAttach {
            challenge,
            device_signature: signature,
        },
    )?;
    let attached = ok(fixture.run(Op::AttachFinish, &device, Some(&attach))?)?;
    let ResultBody::Attached(named, generation) = attached.result else {
        return Err("attacker's valid attachment was refused".into());
    };
    assert_eq!(named, device);
    fixture
        .coordinator
        .state
        .origins
        .get_mut(&origin_key())
        .ok_or("attached origin")?
        .device = Some((device, generation));
    Ok(())
}
