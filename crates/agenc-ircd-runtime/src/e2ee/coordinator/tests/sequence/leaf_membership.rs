//! Leaf-membership admission (companion 13.7.3): stored proofs follow the
//! replacement and conflict rules, and every Commit ACK, standalone or
//! embedded in a finalization, is admitted only through the stored
//! `continuing` proof of the exact old leaf that signed it.

#![forbid(unsafe_code)]

use agenc_ircd_e2ee::objects::membership::IrcLeafMembershipProof;

use super::super::support::{MembershipSpec, membership_proof};
use super::super::{DEVICE_ID, LEAF_SEED, account_bytes, origin_key};
use super::*;

pub(in crate::e2ee::coordinator::tests::sequence) mod finalization;
mod restart;

/// The old leaf key `SECOND_DEVICE` holds.
pub(super) const SECOND_LEAF_SEED: u8 = 31;

/// Everything a refusal must leave untouched.
pub(super) struct Snapshot {
    pub(super) logs:
        std::collections::BTreeMap<[u8; 32], agenc_ircd_domain::e2ee::sequencer_log::SequencerLog>,
    pub(super) conversations:
        std::collections::BTreeMap<[u8; 32], super::super::super::ConversationState>,
    pub(super) objects: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    pub(super) writes: usize,
}

pub(super) fn snapshot(harness: &Harness) -> Snapshot {
    Snapshot {
        logs: harness.coordinator.state.logs.clone(),
        conversations: harness.coordinator.state.conversations.clone(),
        objects: harness.coordinator.state.objects.clone(),
        writes: harness.writes.len(),
    }
}

/// Runs a request that must be refused with `expected` and change nothing.
pub(super) fn refused(
    harness: &mut Harness,
    opcode: Op,
    conversation: &[u8; 32],
    payload: &[u8],
    expected: E2eeReplyCode,
) -> TestResult {
    let before = snapshot(harness);
    assert_eq!(
        code(harness.run(opcode, conversation, Some(payload))?),
        Some(expected)
    );
    assert!(harness.coordinator.state.logs == before.logs, "log changed");
    assert!(
        harness.coordinator.state.conversations == before.conversations,
        "conversation state changed"
    );
    assert!(
        harness.coordinator.state.objects == before.objects,
        "stored objects changed"
    );
    assert_eq!(harness.writes.len(), before.writes);
    Ok(())
}

pub(super) fn proof_bytes(proof: &IrcLeafMembershipProof) -> TestResult<Vec<u8>> {
    wire(IrcWireObjectKind::LeafMembershipProof, proof)
}

/// A Commit ACK for `leaf` naming `credential`, signed by `signer` under
/// `domain`.
// agenc-review: allow owner=tests reviewed=2026-09-15 reason=one ACK names its candidate position, old leaf, credential, signing key, and label together
#[allow(clippy::too_many_arguments)]
pub(super) fn commit_ack_as(
    conversation: [u8; 32],
    prior_epoch: u64,
    candidate_id: [u8; 32],
    commit_object_id: [u8; 32],
    leaf: u32,
    credential: [u8; 32],
    signer: u8,
    domain: SignatureDomain,
) -> TestResult<IrcCommitAck> {
    let tbs = IrcCommitAckTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_epoch,
        candidate_id,
        commit_object_id,
        old_leaf_index: leaf,
        old_credential_hash: credential,
        resulting_epoch: prior_epoch + 1,
        resulting_group_context_digest: [2; 32],
        resulting_ratchet_tree_digest: [3; 32],
        finalization_authenticator: [4; 32],
    };
    Ok(IrcCommitAck {
        old_leaf_signature: Opaque::from_slice(&sign(&key(signer), domain, &tbs)?)?,
        tbs,
    })
}

/// The credential hash `MembershipSpec::continuing` assigns to `leaf`.
pub(super) fn credential_of(leaf: u32) -> [u8; 32] {
    let tag = u8::try_from(leaf % 200).unwrap_or(0).wrapping_add(1);
    [tag; 32]
}

/// A bound channel whose second device also holds old leaf 1, with the
/// first device attached again.
pub(super) fn two_member_channel() -> TestResult<(Harness, [u8; 32])> {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    harness.attach_as(SECOND_DEVICE)?;
    let proof = harness.leaf_proof(conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1)?;
    harness.publish_membership(conversation, &proof)?;
    harness.attach_as(DEVICE)?;
    Ok((harness, conversation))
}

/// Attaches a healthy device of an account outside the binding.
fn attach_outsider(harness: &mut Harness) -> TestResult {
    let account = account_bytes(19)?;
    let principal = super::super::support::principal(29, &account, &[DEVICE])?;
    let digest = agenc_ircd_e2ee::ids::account_id_digest(&NETWORK, &account)?;
    let origin = harness
        .coordinator
        .state
        .origins
        .get_mut(&origin_key())
        .ok_or("origin")?;
    origin.account_id = Some(account);
    origin.account_digest = Some(digest);
    origin.device = None;
    let root = wire(IrcWireObjectKind::RootIdentity, &principal.root)?;
    ok(harness.run(Op::PublishIdentity, &[], Some(&root))?)?;
    let roster = wire(IrcWireObjectKind::DeviceRoster, &principal.roster)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&roster))?)?;
    harness.attach()?;
    Ok(())
}

fn resign(proof: &mut IrcLeafMembershipProof, device: u8, leaf_seed: u8) -> TestResult {
    proof.device_signature = sign(&key(device), SignatureDomain::LeafMembership, &proof.tbs)?;
    if !proof.possession_signature.is_empty() {
        proof.possession_signature = Opaque::from_slice(&sign(
            &key(leaf_seed),
            SignatureDomain::LeafMembershipPossession,
            &proof.tbs,
        )?)?;
    }
    Ok(())
}

#[test]
fn membership_proofs_follow_the_replacement_and_conflict_rules() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    finalization::finalize_both(&mut harness, conversation)?;
    let original = harness.leaf_proof(conversation, DEVICE, LEAF_SEED, 0)?;
    let bytes = proof_bytes(&original)?;
    // A byte-identical resubmission repeats the reply without any state change.
    let before = snapshot(&harness);
    let outcome = ok(harness.run(Op::SubmitMembership, &conversation, Some(&bytes))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::Membership, object_id(&bytes))
    );
    assert!(outcome.writes.is_empty() && outcome.events.is_empty());
    assert!(harness.coordinator.state.conversations == before.conversations);
    assert_eq!(harness.writes.len(), before.writes);
    // A differing proof for the same leaf at the same epoch is a conflict.
    let differing = membership_proof(&MembershipSpec::continuing(
        &harness.principal,
        conversation,
        DEVICE,
        SECOND_LEAF_SEED,
        0,
    ))?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &proof_bytes(&differing)?,
        E2eeReplyCode::OperationConflict,
    )?;
    // An epoch the conversation has not reached is not an old state.
    let mut future =
        MembershipSpec::continuing(&harness.principal, conversation, DEVICE, LEAF_SEED, 0);
    future.epoch = 2;
    let future = proof_bytes(&membership_proof(&future)?)?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &future,
        E2eeReplyCode::EpochStale,
    )?;
    // A later reached epoch from the same device replaces the stored proof.
    let mut later =
        MembershipSpec::continuing(&harness.principal, conversation, DEVICE, LEAF_SEED, 0);
    later.epoch = 1;
    let later = membership_proof(&later)?;
    let later_id = harness.publish_membership(conversation, &later)?;
    let state = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?;
    assert_eq!(state.memberships.len(), 2);
    assert_eq!(
        state
            .memberships
            .iter()
            .find(|entry| entry.proof.leaf_index == 0)
            .map(|entry| (entry.object_id, entry.proof.epoch)),
        Some((later_id, 1))
    );
    // The replaced earlier epoch cannot return.
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &bytes,
        E2eeReplyCode::OperationConflict,
    )?;
    // The replacing proof identifies the leaf's ACK at the new epoch.
    let (_, commit, candidate) = submit_candidate(&mut harness, conversation, 1, 40)?;
    let ack = commit_ack_as(
        conversation,
        1,
        candidate,
        commit,
        0,
        credential_of(0),
        LEAF_SEED,
        SignatureDomain::CommitProcessed,
    )?;
    ok(harness.run(
        Op::SubmitCommitAck,
        &conversation,
        Some(&wire(IrcWireObjectKind::CommitAck, &ack)?),
    )?)?;
    Ok(())
}

#[test]
fn membership_proofs_are_refused_for_a_foreign_device_signature_roster_or_shape() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    // The bound device's own leaf-0 proof; each case breaks one rule.
    let base = harness.leaf_proof(conversation, DEVICE, LEAF_SEED, 0)?;
    let cases: Vec<(&str, IrcLeafMembershipProof, E2eeReplyCode)> = vec![
        (
            "another device's proof",
            { harness.leaf_proof(conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1)? },
            E2eeReplyCode::DeviceRequired,
        ),
        (
            "corrupted device signature",
            {
                let mut proof = base.clone();
                if let Some(byte) = proof.device_signature.first_mut() {
                    *byte ^= 1;
                }
                proof
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "possession by another key",
            {
                let mut proof = base.clone();
                proof.possession_signature = Opaque::from_slice(&sign(
                    &key(99),
                    SignatureDomain::LeafMembershipPossession,
                    &proof.tbs,
                )?)?;
                proof
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "device label used for possession",
            {
                let mut proof = base.clone();
                proof.possession_signature = Opaque::from_slice(&sign(
                    &key(LEAF_SEED),
                    SignatureDomain::LeafMembership,
                    &proof.tbs,
                )?)?;
                proof
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "another roster",
            {
                let mut proof = base.clone();
                proof.tbs.roster_id = [9; 32];
                resign(&mut proof, DEVICE, LEAF_SEED)?;
                proof
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "another root generation",
            {
                let mut proof = base.clone();
                proof.tbs.root_generation = 1;
                resign(&mut proof, DEVICE, LEAF_SEED)?;
                proof
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "another conversation",
            {
                let mut proof = base.clone();
                proof.tbs.conversation_id = [8; 32];
                resign(&mut proof, DEVICE, LEAF_SEED)?;
                proof
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "continuing proof naming a removal",
            {
                let mut proof = base.clone();
                proof.tbs.removal_finalization_id = [5; 32];
                resign(&mut proof, DEVICE, LEAF_SEED)?;
                proof
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "removed proof with a possession signature",
            {
                let mut proof = base.clone();
                proof.tbs.disposition =
                    agenc_ircd_e2ee::objects::membership::IrcLeafDispositionKind::Removed;
                proof.tbs.removal_finalization_id = [5; 32];
                resign(&mut proof, DEVICE, LEAF_SEED)?;
                proof
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "removed proof naming no retained finalization",
            {
                let mut spec = MembershipSpec::continuing(
                    &harness.principal,
                    conversation,
                    DEVICE,
                    LEAF_SEED,
                    1,
                );
                spec.removed = Some([5; 32]);
                membership_proof(&spec)?
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "a leaf beyond the group ceiling",
            {
                let mut proof = base.clone();
                proof.tbs.leaf_index = agenc_ircd_e2ee::limits::MAX_GROUP_LEAVES;
                resign(&mut proof, DEVICE, LEAF_SEED)?;
                proof
            },
            E2eeReplyCode::InvalidFragment,
        ),
        (
            "another account's proof on this device",
            {
                let outside = super::super::support::principal(29, &account_bytes(19)?, &[DEVICE])?;
                membership_proof(&MembershipSpec::continuing(
                    &outside,
                    conversation,
                    DEVICE,
                    LEAF_SEED,
                    3,
                ))?
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "a non-Ed25519 leaf scheme",
            {
                let mut proof = base.clone();
                proof.tbs.leaf_signature_scheme = 0x0403;
                resign(&mut proof, DEVICE, LEAF_SEED)?;
                proof
            },
            E2eeReplyCode::BindingAuthInvalid,
        ),
    ];
    for (name, proof, expected) in cases {
        let before = snapshot(&harness);
        assert_eq!(
            code(harness.run(
                Op::SubmitMembership,
                &conversation,
                Some(&proof_bytes(&proof)?)
            )?),
            Some(expected),
            "{name}"
        );
        assert!(
            harness.coordinator.state.conversations == before.conversations,
            "{name}"
        );
        assert_eq!(harness.writes.len(), before.writes, "{name}");
    }
    // Only the leaf-membership kind travels on this command.
    let policy = wire(IrcWireObjectKind::Policy, &harness.initial_policy)?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &policy,
        E2eeReplyCode::InvalidFragment,
    )?;
    // An unattached origin and an outside account are refused before any state.
    let valid = proof_bytes(&base)?;
    let device = harness.device();
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key()) {
        origin.device = None;
    }
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &valid,
        E2eeReplyCode::DeviceRequired,
    )?;
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key()) {
        origin.device = device;
    }
    ok(harness.run(Op::SubmitMembership, &conversation, Some(&valid))?)?;
    attach_outsider(&mut harness)?;
    let outsider = membership_proof(&MembershipSpec::continuing(
        &harness.principal,
        conversation,
        DEVICE,
        LEAF_SEED,
        2,
    ))?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &proof_bytes(&outsider)?,
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn a_second_device_cannot_claim_a_retained_leaf_or_two_leaves_at_one_epoch() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    harness.attach_as(SECOND_DEVICE)?;
    // Device 8 claims leaf 0 and the credential device 7 already holds.
    let stolen = MembershipSpec::continuing(
        &harness.principal,
        conversation,
        SECOND_DEVICE,
        SECOND_LEAF_SEED,
        0,
    );
    let stolen = proof_bytes(&membership_proof(&stolen)?)?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &stolen,
        E2eeReplyCode::OperationConflict,
    )?;
    // Device 8 already holds leaf 1 at epoch 0; leaf 2 at the same epoch is a
    // duplicate continuing leaf.
    let second = harness.leaf_proof(conversation, SECOND_DEVICE, 32, 2)?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &proof_bytes(&second)?,
        E2eeReplyCode::OperationConflict,
    )?;
    let memberships = &harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?
        .memberships;
    let held: Vec<_> = memberships
        .iter()
        .map(|entry| (entry.proof.leaf_index, entry.proof.device_id))
        .collect();
    assert_eq!(held, vec![(0, DEVICE_ID), (1, [SECOND_DEVICE; 16])]);
    Ok(())
}

#[test]
fn a_commit_ack_is_admitted_only_through_its_stored_signing_leaf() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    let (_, commit, candidate) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let ack = |leaf: u32, credential: [u8; 32], signer: u8, domain: SignatureDomain| {
        commit_ack_as(
            conversation,
            0,
            candidate,
            commit,
            leaf,
            credential,
            signer,
            domain,
        )
    };
    let processed = SignatureDomain::CommitProcessed;
    let mut unsigned = ack(0, credential_of(0), LEAF_SEED, processed)?;
    unsigned.old_leaf_signature = Opaque::new(vec![0; 64])?;
    let cases = [
        ("unsigned", unsigned),
        (
            "incorrect domain",
            ack(
                0,
                credential_of(0),
                LEAF_SEED,
                SignatureDomain::ReinitProcessed,
            )?,
        ),
        (
            "valid signature by another leaf",
            ack(0, credential_of(0), SECOND_LEAF_SEED, processed)?,
        ),
        (
            "wrong index",
            ack(5, credential_of(0), LEAF_SEED, processed)?,
        ),
        (
            "wrong credential",
            ack(0, credential_of(3), LEAF_SEED, processed)?,
        ),
        (
            "another device's leaf while this device is attached",
            ack(1, credential_of(1), SECOND_LEAF_SEED, processed)?,
        ),
    ];
    for (name, ack) in cases {
        let bytes = wire(IrcWireObjectKind::CommitAck, &ack)?;
        let before = snapshot(&harness);
        assert_eq!(
            code(harness.run(Op::SubmitCommitAck, &conversation, Some(&bytes))?),
            Some(E2eeReplyCode::BindingAuthInvalid),
            "{name}"
        );
        assert!(
            harness.coordinator.state.conversations == before.conversations,
            "{name}"
        );
        assert_eq!(harness.writes.len(), before.writes, "{name}");
    }
    // Absent-signer control: the sequencer signer plays no part in an ACK.
    let signer = harness.coordinator.signer.take();
    let own = ack(0, credential_of(0), LEAF_SEED, processed)?;
    let own_bytes = wire(IrcWireObjectKind::CommitAck, &own)?;
    let outcome = ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&own_bytes))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::CommitAcked(conversation, candidate, object_id(&own_bytes))
    );
    harness.coordinator.signer = signer;
    // The second device acknowledges its own leaf once attached.
    harness.attach_as(SECOND_DEVICE)?;
    let second = ack(1, credential_of(1), SECOND_LEAF_SEED, processed)?;
    ok(harness.run(
        Op::SubmitCommitAck,
        &conversation,
        Some(&wire(IrcWireObjectKind::CommitAck, &second)?),
    )?)?;
    let state = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?;
    assert_eq!(
        state
            .acks
            .get(&candidate)
            .map(|acks| acks.keys().copied().collect::<Vec<_>>()),
        Some(vec![0, 1])
    );
    assert_eq!(
        state
            .ack_signers
            .get(&candidate)
            .map(|signers| signers.len()),
        Some(2)
    );
    Ok(())
}

#[test]
fn a_duplicate_leaf_is_idempotent_only_when_byte_identical() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    let (_, commit, candidate) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let first = commit_ack_as(
        conversation,
        0,
        candidate,
        commit,
        0,
        credential_of(0),
        LEAF_SEED,
        SignatureDomain::CommitProcessed,
    )?;
    let bytes = wire(IrcWireObjectKind::CommitAck, &first)?;
    ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&bytes))?)?;
    let acknowledged = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?
        .clone();
    // Receipt loss: the identical ACK repeats the same result and state.
    let again = ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&bytes))?)?;
    assert_eq!(
        again.result,
        ResultBody::CommitAcked(conversation, candidate, object_id(&bytes))
    );
    assert!(harness.coordinator.state.conversations.get(&conversation) == Some(&acknowledged));
    // A different ACK for the acknowledged leaf is a conflict.
    let mut differing = first.clone();
    differing.tbs.resulting_group_context_digest = [7; 32];
    differing.old_leaf_signature = Opaque::from_slice(&sign(
        &key(LEAF_SEED),
        SignatureDomain::CommitProcessed,
        &differing.tbs,
    )?)?;
    refused(
        &mut harness,
        Op::SubmitCommitAck,
        &conversation,
        &wire(IrcWireObjectKind::CommitAck, &differing)?,
        E2eeReplyCode::OperationConflict,
    )
}

#[test]
fn a_stored_proof_is_fetched_only_under_its_conversation_by_a_principal() -> TestResult {
    let other_group = [12; 32];
    let other = agenc_ircd_e2ee::ids::conversation_id(&NETWORK, &other_group)?;
    let mut harness =
        super::reinit::successor::reconstruction::independent_root_with_group(other, other_group)?;
    let room = agenc_ircd_e2ee::ids::conversation_id(&NETWORK, &GROUP)?;
    let proof = harness
        .coordinator
        .state
        .conversations
        .get(&room)
        .and_then(|state| state.memberships.iter().next())
        .map(|entry| entry.object_id)
        .ok_or("room proof")?;
    let fetch = |conversation: [u8; 32]| {
        let mut params = conversation.to_vec();
        params.extend_from_slice(&proof);
        params
    };
    let page = ok(harness.run(Op::FetchObject, &fetch(room), None)?)?;
    assert_eq!(page.result, ResultBody::ObjectPage);
    assert_eq!(
        page.responses
            .iter()
            .map(|response| object_id(&response.bytes))
            .collect::<Vec<_>>(),
        vec![proof]
    );
    // Under the other conversation the proof names a different route.
    let elsewhere = ok(harness.run(Op::FetchObject, &fetch(other), None)?)?;
    assert_eq!(elsewhere.result, ResultBody::Empty(EmptyKind::Objects));
    // An attached device of an account outside the binding reads nothing.
    attach_outsider(&mut harness)?;
    let outside = ok(harness.run(Op::FetchObject, &fetch(room), None)?)?;
    assert_eq!(outside.result, ResultBody::Empty(EmptyKind::Objects));
    Ok(())
}
