//! Admission of a new route for an existing group and reconstruction from the
//! authenticated old-group terminal, including a crash on either side of BIND.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::tests::sequence::recovery_pending::close_authorization::{
    binding_bytes, open_finalization,
};
use agenc_relay_e2ee::object::ArcWireObject;
use agenc_relay_e2ee::route::direct_route_binding;

fn package(bytes: &[u8]) -> TestResult<ArcConversationBindingPackage> {
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object = ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::ConversationBinding),
        &mut budget,
    )?;
    Ok(ArcConversationBindingPackage::decode_exact(
        object.body(),
        &mut budget,
    )?)
}

fn advance_to(
    previous: &Group,
    edit: impl FnOnce(
        &mut agenc_relay_e2ee::objects::conversation::ArcConversationBindingTbs,
    ) -> TestResult,
) -> TestResult<(Group, [u8; 32])> {
    let mut next = package(&previous.bytes)?;
    let tbs = &mut next.binding.tbs;
    tbs.previous_binding_id = semantic_id_of(SemanticHashDomain::BindingId, tbs)?;
    tbs.binding_generation = tbs.binding_generation.checked_add(1).ok_or("generation")?;
    edit(tbs)?;
    let target = semantic_id_of(SemanticHashDomain::BindingId, tbs)?;
    next.binding.approvals = TlsVec::new(Vec::new())?;
    next.root_binding_locks = TlsVec::new(Vec::new())?;
    Ok((
        Group {
            conversation: previous.conversation,
            bytes: wire(ArcWireObjectKind::ConversationBinding, &next)?,
            policies: previous.policies.clone(),
        },
        target,
    ))
}

fn advance(previous: &Group, nonce: [u8; 32]) -> TestResult<(Group, [u8; 32])> {
    advance_to(previous, |tbs| {
        tbs.conversation_nonce = Opaque::from_slice(&nonce)?;
        let route = &tbs.semantic_route;
        tbs.route_binding = direct_route_binding(
            &NETWORK,
            &nonce,
            &route.direct_account_a.as_slice().try_into()?,
            &route.direct_account_b.as_slice().try_into()?,
        )?;
        Ok(())
    })
}

fn direct() -> TestResult<(Harness, Group, [u8; 24])> {
    direct_with_devices(&[DEVICE])
}

fn direct_with_devices(devices: &[u8]) -> TestResult<(Harness, Group, [u8; 24])> {
    let mut h = Harness::with_devices(devices)?;
    h.publish_identity_and_roster()?;
    h.attach()?;
    let peer = direct_peer(&mut h)?;
    let account = peer.root.tbs.account_id.as_slice().try_into()?;
    let (grant, nonce) = ok_reservation(reserve_direct(&mut h, &account)?)?;
    let group = direct_group(&h, &peer, (0, [0; 32]), nonce, DIRECT_GROUP)?;
    bind_and_publish(&mut h, grant, &group)?;
    operate(&mut h, group.conversation, None)?;
    Ok((h, group, account))
}

fn wrong_approval(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object = ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    let mut request = ArcFinalizationRequest::decode_exact(object.body(), &mut budget)?;
    let mut approvals = request.proof.authorization.approvals.as_slice().to_vec();
    approvals
        .first_mut()
        .ok_or("controller signature")?
        .device_signature[0] ^= 1;
    request.proof.authorization.approvals = TlsVec::new(approvals)?;
    wire(ArcWireObjectKind::FinalizationRequest, &request)
}

fn approve(h: &mut Harness, id: [u8; 32], epoch: u64, target: [u8; 32]) -> TestResult<[u8; 32]> {
    let opened = open_finalization(h, id, epoch)?;
    let (bytes, terminal) = binding_bytes(h, &opened, target)?;
    let invalid = wrong_approval(&bytes)?;
    assert_eq!(
        code(h.run(Op::SubmitFinalization, &id, Some(&invalid))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let accepted = ok(h.run(Op::SubmitFinalization, &id, Some(&bytes))?)?;
    assert!(
        matches!(accepted.result, ResultBody::Finalized(c, e, t, _) if (c, e, t) == (id, epoch + 1, terminal))
    );
    Ok(terminal)
}

fn install(h: &mut Harness, grant: [u8; 16], next: &Group, target: [u8; 32]) -> TestResult {
    let mut params = grant.to_vec();
    params.extend_from_slice(&next.conversation);
    params.extend_from_slice(&[0; 32]);
    assert_eq!(
        code(h.run(Op::BindGroup, &params, Some(&next.bytes))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let object = object_id(&next.bytes);
    let out = ok(bind(h, grant, next)?)?;
    assert!(
        matches!(out.result, ResultBody::Bound { conversation_id, binding_id, binding_object_id }
        if (conversation_id, binding_id, binding_object_id) == (next.conversation, target, object))
    );
    Ok(())
}

fn assert_query(h: &mut Harness, peer: &[u8; 24], group: &Group, target: [u8; 32]) -> TestResult {
    let query = ok(h.run(Op::QueryDirect, &account_param(peer), None)?)?;
    assert!(
        matches!(query.result, ResultBody::Bound {conversation_id, binding_id, binding_object_id}
        if (conversation_id, binding_id, binding_object_id) == (group.conversation, target, object_id(&group.bytes)))
    );
    Ok(())
}

#[tokio::test]
async fn two_same_group_handoffs_restore_the_signed_history_at_every_boundary() -> TestResult {
    let (mut h, original, peer) = direct()?;
    let id = original.conversation;
    let (grant, nonce) = ok_reservation(reserve_direct(&mut h, &peer)?)?;
    let (first, target) = advance(&original, nonce)?;
    assert_eq!(
        code(bind(&mut h, grant, &first)?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    let terminal = approve(&mut h, id, 2, target)?;
    let mut h = sealed_restart(&h).await?;
    h.entropy.0 = 97;
    assert_eq!(
        code(application(&mut h, id, None)?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    let (other, _) = advance(&original, [74; 32])?;
    assert_eq!(
        code(bind(&mut h, grant, &other)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    install(&mut h, grant, &first, target)?;
    let mut h = sealed_restart(&h).await?;
    h.entropy.0 = 143;
    assert_query(&mut h, &peer, &first, target)?;
    assert_eq!(
        h.coordinator
            .state
            .logs
            .get(&id)
            .ok_or("log")?
            .accepted_state_id(),
        &terminal
    );
    traffic(&mut h, id, None, 3)?;

    let (grant, nonce) = ok_reservation(reserve_direct(&mut h, &peer)?)?;
    let (second, target) = advance(&first, nonce)?;
    approve(&mut h, id, 4, target)?;
    install(&mut h, grant, &second, target)?;
    let mut h = sealed_restart(&h).await?;
    assert_query(&mut h, &peer, &second, target)?;
    let state = h
        .coordinator
        .state
        .conversations
        .get(&id)
        .ok_or("conversation")?;
    let rows = &state.binding_admissions;
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.get(&1)
            .ok_or("first admission")?
            .previous_binding_object,
        object_id(&original.bytes)
    );
    let last = rows.get(&2).ok_or("second admission")?;
    assert_eq!(last.previous_binding_object, object_id(&first.bytes));
    assert_eq!(last.binding_object, object_id(&second.bytes));
    assert_eq!(
        state.binding_chain_bytes,
        original.bytes.len() + first.bytes.len() + second.bytes.len()
    );
    assert_eq!(state.context_digest, [44; 32]);
    traffic(&mut h, id, None, 5)?;
    let close_id = close(&mut h, id, 6)?;
    let closed = sealed_restart(&h).await?;
    assert_eq!(
        route_of(&closed, id)?.lifecycle,
        RouteLifecycle::Tombstone { close_id }
    );
    Ok(())
}

mod authority;
mod channels;
mod restore;
