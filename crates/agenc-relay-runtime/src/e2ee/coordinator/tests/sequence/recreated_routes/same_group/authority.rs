//! BIND's authority at the prior epoch and its independent admission limits.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_e2ee::limits::MAX_BINDING_CHAIN_BYTES;
use agenc_relay_e2ee::objects::conversation::{ArcCommitAuthorizationRule, action_bits};
use agenc_relay_e2ee::objects::sequencing::ArcFinalizationProof;

#[test]
fn old_group_controller_proof_binds_its_clock_candidate_policy_and_result() -> TestResult {
    let (mut h, original, peer) = direct()?;
    let (_, nonce) = ok_reservation(reserve_direct(&mut h, &peer)?)?;
    let (_, target) = advance(&original, nonce)?;
    let id = original.conversation;
    let opened = open_finalization(&mut h, id, 2)?;
    let (bytes, _) = binding_bytes(&h, &opened, target)?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let outer = ArcWireObject::decode_kind(
        &bytes,
        Some(ArcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    let proof = ArcFinalizationRequest::decode_exact(outer.body(), &mut budget)?.proof;
    let state = &h.coordinator.state;
    let group = state.conversations.get(&id).ok_or("old group")?;
    let pin = h
        .coordinator
        .key_set()
        .and_then(|keys| keys.credential(&group.sequencer_credential_id))
        .ok_or("pinned key")?;
    let policy = &group
        .policies
        .get(&group.current_policy_id)
        .ok_or("old policy")?
        .policy;
    let rosters = state
        .principals
        .values()
        .map(|(root, roster)| (root.account_id, (*root, roster.clone())))
        .collect();
    let approve = |candidate: &ArcFinalizationProof, previous, time| {
        crate::e2ee::coordinator::ops::binding_change::approved_target(
            candidate, policy, &rosters, pin, previous, time,
        )
    };
    let time = group.last_validation_time;
    assert_eq!(approve(&proof, group.binding, time), Some(target));
    assert!(approve(&proof, target, time).is_none());
    assert!(approve(&proof, group.binding, time + 1).is_none());
    type Edit = fn(&mut ArcFinalizationProof);
    let edits: [Edit; 10] = [
        |p| p.authorization.tbs.action_bits |= action_bits::POLICY,
        |p| {
            p.authorization.tbs.authorization_rule = ArcCommitAuthorizationRule::BootstrapActivation
        },
        |p| p.receipt.tbs.sequencer_key_id[0] ^= 1,
        |p| p.core.resulting_group_context_digest[0] ^= 1,
        |p| p.core.resulting_ratchet_tree_digest[0] ^= 1,
        |p| p.core.old_policy_id[0] ^= 1,
        |p| p.core.candidate_id[0] ^= 1,
        |p| p.core.commit_object_id[0] ^= 1,
        |p| p.core.commit_authorization_id[0] ^= 1,
        |p| p.authorization.tbs.transition_target_digest[0] ^= 1,
    ];
    for edit in edits {
        let mut changed = proof.clone();
        edit(&mut changed);
        assert!(approve(&changed, group.binding, time).is_none());
    }
    let mut outside = proof.clone();
    outside.authorization.tbs.canonical_validation_time = u64::MAX;
    assert!(approve(&outside, group.binding, u64::MAX).is_none());
    Ok(())
}

#[test]
fn only_the_granted_active_device_can_install_and_one_byte_over_the_chain_limit_is_refused()
-> TestResult {
    let (mut h, old, peer) = direct_with_devices(&[DEVICE, SECOND_DEVICE])?;
    let id = old.conversation;
    let (grant, nonce) = ok_reservation(reserve_direct(&mut h, &peer)?)?;
    // A properly root-signed genesis for the same pair, with the concrete
    // nonce from the grant, still cannot spend an operational binding grant.
    let counterparty = principal(PEER_ROOT_SEED, &peer, &[PEER_DEVICE])?;
    let genesis = direct_group(&h, &counterparty, (0, [0; 32]), nonce, SECOND_DIRECT_GROUP)?;
    assert_eq!(
        code(bind(&mut h, grant, &genesis)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let (next, target) = advance(&old, nonce)?;
    approve(&mut h, id, 2, target)?;
    let mut other = h.reloaded()?;
    other.attach_as(SECOND_DEVICE)?;
    assert_eq!(
        code(bind(&mut other, grant, &next)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let threshold = MAX_BINDING_CHAIN_BYTES
        .checked_sub(next.bytes.len())
        .ok_or("bounded package")?;
    let group = h
        .coordinator
        .state
        .conversations
        .get_mut(&id)
        .ok_or("conversation")?;
    group.binding_chain_bytes = threshold + 1;
    assert_eq!(
        code(bind(&mut h, grant, &next)?),
        Some(E2eeReplyCode::ObjectTooLarge)
    );
    h.coordinator
        .state
        .conversations
        .get_mut(&id)
        .ok_or("conversation")?
        .binding_chain_bytes = threshold;
    install(&mut h, grant, &next, target)?;
    assert_eq!(
        h.coordinator
            .state
            .conversations
            .get(&id)
            .ok_or("conversation")?
            .binding_chain_bytes,
        MAX_BINDING_CHAIN_BYTES
    );
    Ok(())
}
