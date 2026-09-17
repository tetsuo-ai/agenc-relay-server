//! ReInit admission is bound to authenticated old and continuing leaves
//! (companion 11.4, 13.7.3, 13.8): attempts and aborts come from old-group
//! devices, activation from a continuing planned device, and every ReInit
//! ACK, standalone or embedded, from the proof-identified leaf of the plan
//! entry its role names, with exactly one ACK per plan entry and none
//! missing for a stored continuing leaf.

#![forbid(unsafe_code)]

use super::super::leaf_membership::finalization::{finalize_both, rotate_roster};
use super::super::leaf_membership::{
    SECOND_LEAF_SEED, credential_of, refused, snapshot, two_member_channel,
};
use super::*;
use crate::e2ee::coordinator::tests::support::{MembershipSpec, key, membership_proof, sign};
use crate::e2ee::coordinator::tests::{LEAF_SEED, TestResult as Result};

mod maximum;

const THIRD_DEVICE: u8 = 9;
const THIRD_LEAF_SEED: u8 = 32;

/// One planned member of the successor: its device, old leaf, leaf key,
/// and reserved KeyPackageRef byte (none for the creator).
#[derive(Clone, Copy)]
pub(super) struct Member {
    pub(super) device: u8,
    pub(super) leaf: u32,
    pub(super) leaf_seed: u8,
    pub(super) reference: Option<u8>,
}

pub(super) const CREATOR: Member = Member {
    device: DEVICE,
    leaf: 0,
    leaf_seed: LEAF_SEED,
    reference: None,
};

const JOINER: Member = Member {
    device: SECOND_DEVICE,
    leaf: 1,
    leaf_seed: SECOND_LEAF_SEED,
    reference: Some(88),
};

const THIRD: Member = Member {
    device: THIRD_DEVICE,
    leaf: 2,
    leaf_seed: THIRD_LEAF_SEED,
    reference: Some(89),
};

fn accepted_state(harness: &Harness, conversation: [u8; 32]) -> Result<[u8; 32]> {
    Ok(*harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id())
}

/// Stages an attempt whose KeyPackage plan carries `members`, the first
/// being the creator, and returns its receipt and attempt.
pub(super) fn stage(
    harness: &mut Harness,
    conversation: [u8; 32],
    members: &[Member],
) -> Result<(IrcReInitAttemptReceipt, IrcReInitAttempt)> {
    let old_state = accepted_state(harness, conversation)?;
    let (mut attempt, _) = attempt(harness, conversation, old_state, 0)?;
    let creator = attempt
        .key_package_plan
        .entries
        .as_slice()
        .first()
        .ok_or("creator entry")?
        .clone();
    let mut entries = vec![creator.clone()];
    for member in members.iter().skip(1) {
        let mut entry = creator.clone();
        entry.creator = 0;
        entry.device_id = [member.device; 16];
        entry.key_package_ref = Opaque::new(vec![member.reference.ok_or("joiner reference")?; 32])?;
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.device_id);
    attempt.key_package_plan.entries = TlsVec::new(entries)?;
    super::attempt_authority::authorize_attempt(harness, &mut attempt)?;
    let bytes = wire(IrcWireObjectKind::ReinitAttempt, &attempt)?;
    ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    Ok((staged_receipt(harness, conversation)?, attempt))
}

/// The ACK `member` issues for the staged attempt: `creator_state` for the
/// creator, `welcome_join` naming its reserved ref otherwise.
pub(super) fn member_ack(
    conversation: [u8; 32],
    receipt: &IrcReInitAttemptReceipt,
    member: Member,
) -> Result<IrcReInitAck> {
    let (mut ack, _) = ack(
        conversation,
        receipt.tbs.old_reinit_state_id,
        receipt.tbs.reinit_attempt_id,
    )?;
    ack.tbs.old_leaf_index = member.leaf;
    ack.tbs.old_credential_hash = credential_of(member.leaf);
    if let Some(reference) = member.reference {
        ack.tbs.ack_kind = IrcReInitAckKind::WelcomeJoin;
        ack.tbs.new_leaf_index = member.leaf;
        ack.tbs.key_package_ref = Opaque::new(vec![reference; 32])?;
    }
    signed_reinit_ack(ack, member.leaf_seed)
}

/// An activation request embedding `acks`, voted by `voters`.
pub(super) fn activation(
    harness: &Harness,
    receipt: &IrcReInitAttemptReceipt,
    attempt: &IrcReInitAttempt,
    mut acks: Vec<IrcReInitAck>,
    voters: &[u8],
) -> Result<Vec<u8>> {
    acks.sort_by_key(|ack| ack.tbs.old_leaf_index);
    let tbs: Vec<_> = acks.iter().map(|ack| ack.tbs.clone()).collect();
    let core = IrcReInitActivationCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: receipt.tbs.old_conversation_id,
        new_conversation_id: attempt.tbs.new_conversation_id,
        old_reinit_state_id: receipt.tbs.old_reinit_state_id,
        attempt_sequence: receipt.tbs.attempt_sequence,
        reinit_attempt_id: receipt.tbs.reinit_attempt_id,
        new_group_info_digest: attempt.tbs.new_group_info_digest,
        new_group_context_digest: attempt.tbs.new_group_context_digest,
        new_ratchet_tree_digest: attempt.tbs.new_ratchet_tree_digest,
        new_exporter_authenticator: attempt.tbs.new_exporter_authenticator,
        acknowledgement_set_digest: agenc_ircd_e2ee::ids::proof_set_digest(
            SemanticHashDomain::ReinitAcknowledgementSet,
            &tbs,
        )?,
    };
    let terminal = Terminal::finalize(semantic_id_of(
        SemanticHashDomain::ReinitActivationId,
        &core,
    )?);
    let votes = voters
        .iter()
        .map(|device| {
            reinit_vote(
                harness,
                *device,
                receipt,
                receipt.tbs.old_reinit_state_id,
                receipt.tbs.reinit_attempt_id,
                terminal,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    wire(
        IrcWireObjectKind::ReinitActivationRequest,
        &IrcReInitActivationRequest {
            core,
            receipt: receipt.clone(),
            attempt: attempt.clone(),
            acknowledgements: TlsVec::new(acks)?,
            votes: TlsVec::new(votes)?,
        },
    )
}

fn abort(
    harness: &Harness,
    receipt: &IrcReInitAttemptReceipt,
    attempt: &IrcReInitAttempt,
) -> Result<Vec<u8>> {
    let core = IrcReInitAbortCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: receipt.tbs.old_conversation_id,
        old_reinit_state_id: receipt.tbs.old_reinit_state_id,
        attempt_sequence: receipt.tbs.attempt_sequence,
        slot_predecessor_record_id: receipt.tbs.predecessor_record_id,
        reinit_attempt_id: receipt.tbs.reinit_attempt_id,
        reason_code: 1,
        evidence_digest: [0; 32],
    };
    let terminal = Terminal::abort(semantic_id_of(SemanticHashDomain::ReinitAbortId, &core)?, 1)?;
    let votes = harness
        .devices
        .iter()
        .map(|device| {
            reinit_vote(
                harness,
                *device,
                receipt,
                receipt.tbs.old_reinit_state_id,
                receipt.tbs.reinit_attempt_id,
                terminal,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    wire(
        IrcWireObjectKind::ReinitAbortRequest,
        &IrcReInitAbortRequest {
            core,
            receipt: receipt.clone(),
            attempt: attempt.clone(),
            votes: TlsVec::new(votes)?,
        },
    )
}

/// A two-device principal whose second device holds no proof, with the
/// payload of `opcode` prepared by the proven first device.
fn nonmember_case(opcode: Op) -> Result<(Harness, [u8; 32], Vec<u8>)> {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    if opcode == Op::SubmitReinitAttempt {
        let old_state = accepted_state(&harness, conversation)?;
        let (_, bytes) = attempt(&harness, conversation, old_state, 0)?;
        return Ok((harness, conversation, bytes));
    }
    let (receipt, attempt) = stage(&mut harness, conversation, &[CREATOR])?;
    let bytes = if opcode == Op::SubmitReinitAbort {
        abort(&harness, &receipt, &attempt)?
    } else {
        let acks = vec![member_ack(conversation, &receipt, CREATOR)?];
        activation(&harness, &receipt, &attempt, acks, &[DEVICE, SECOND_DEVICE])?
    };
    Ok((harness, conversation, bytes))
}

#[test]
fn a_nonmember_device_of_an_approved_account_cannot_attempt_activate_or_abort() -> Result {
    for opcode in [
        Op::SubmitReinitAttempt,
        Op::SubmitReinitActivate,
        Op::SubmitReinitAbort,
    ] {
        // Accepted-member control: the proven device succeeds.
        let (mut control, conversation, bytes) = nonmember_case(opcode)?;
        let accepted = ok(control.run(opcode, &conversation, Some(&bytes))?)?;
        assert!(accepted.security_mutation, "{opcode:?}");
        for with_signer in [true, false] {
            let (mut harness, conversation, bytes) = nonmember_case(opcode)?;
            // The same approved account's other active device is not an old leaf.
            harness.attach_as(SECOND_DEVICE)?;
            if !with_signer {
                harness.coordinator.signer = None;
            }
            refused(
                &mut harness,
                opcode,
                &conversation,
                &bytes,
                E2eeReplyCode::BindingAuthInvalid,
            )?;
        }
    }
    Ok(())
}

#[test]
fn activation_admits_the_creator_and_each_continuing_joiner() -> Result {
    for submitter in [DEVICE, SECOND_DEVICE] {
        let (mut harness, conversation) = two_member_channel()?;
        let (receipt, attempt) = stage(&mut harness, conversation, &[CREATOR, JOINER])?;
        // Both members acknowledge through their own proofs first.
        let creator = member_ack(conversation, &receipt, CREATOR)?;
        ok(harness.run(
            Op::SubmitReinitAck,
            &conversation,
            Some(&wire(IrcWireObjectKind::ReinitAck, &creator)?),
        )?)?;
        harness.attach_as(SECOND_DEVICE)?;
        let joiner = member_ack(conversation, &receipt, JOINER)?;
        ok(harness.run(
            Op::SubmitReinitAck,
            &conversation,
            Some(&wire(IrcWireObjectKind::ReinitAck, &joiner)?),
        )?)?;
        harness.attach_as(submitter)?;
        let request = activation(
            &harness,
            &receipt,
            &attempt,
            vec![creator, joiner],
            &[DEVICE, SECOND_DEVICE],
        )?;
        let outcome = ok(harness.run(Op::SubmitReinitActivate, &conversation, Some(&request))?)?;
        assert!(
            matches!(outcome.result, ResultBody::ReinitActivated(..)),
            "submitter {submitter}"
        );
    }
    Ok(())
}

/// A three-device principal: devices 7 and 8 hold leaves 0 and 1 and device
/// 9 holds leaf 2.
fn three_member_channel() -> Result<(Harness, [u8; 32])> {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE, THIRD_DEVICE])?;
    let conversation = harness.bind_channel()?;
    for member in [JOINER, THIRD] {
        harness.attach_as(member.device)?;
        let proof =
            harness.leaf_proof(conversation, member.device, member.leaf_seed, member.leaf)?;
        harness.publish_membership(conversation, &proof)?;
    }
    harness.attach_as(DEVICE)?;
    Ok((harness, conversation))
}

#[test]
fn activation_refuses_an_excluded_leaf_and_an_omitted_continuing_leaf() -> Result {
    let (mut harness, conversation) = three_member_channel()?;
    // The target plan carries devices 7 and 8 only.
    let (receipt, attempt) = stage(&mut harness, conversation, &[CREATOR, JOINER])?;
    let acks = vec![
        member_ack(conversation, &receipt, CREATOR)?,
        member_ack(conversation, &receipt, JOINER)?,
    ];
    let request = activation(&harness, &receipt, &attempt, acks, &[DEVICE, SECOND_DEVICE])?;
    // Device 9 holds an old leaf the successor excludes.
    harness.attach_as(THIRD_DEVICE)?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &request,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // Device 9's stored continuing leaf has no proof-backed ACK.
    harness.attach_as(DEVICE)?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &request,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // Once device 9 is revoked its proof no longer counts toward the set.
    rotate_roster(&mut harness, &[DEVICE, SECOND_DEVICE])?;
    let outcome = ok(harness.run(Op::SubmitReinitActivate, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitActivated(..)));
    Ok(())
}

#[test]
fn a_plan_entry_without_its_ack_cannot_activate() -> Result {
    let (mut harness, conversation) = three_member_channel()?;
    let (receipt, attempt) = stage(&mut harness, conversation, &[CREATOR, JOINER, THIRD])?;
    let acks = vec![
        member_ack(conversation, &receipt, CREATOR)?,
        member_ack(conversation, &receipt, JOINER)?,
    ];
    let partial = activation(
        &harness,
        &receipt,
        &attempt,
        acks.clone(),
        &[DEVICE, SECOND_DEVICE],
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &partial,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    let mut complete = acks;
    complete.push(member_ack(conversation, &receipt, THIRD)?);
    let request = activation(
        &harness,
        &receipt,
        &attempt,
        complete,
        &[DEVICE, SECOND_DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitReinitActivate, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitActivated(..)));
    Ok(())
}

fn resigned(
    mut ack: IrcReInitAck,
    change: impl FnOnce(&mut IrcReInitAck),
    seed: u8,
) -> Result<IrcReInitAck> {
    change(&mut ack);
    signed_reinit_ack(ack, seed)
}

#[test]
fn reinit_acks_are_refused_unless_signed_by_the_planned_leaf_standalone_and_embedded() -> Result {
    let (mut harness, conversation) = two_member_channel()?;
    let (receipt, attempt) = stage(&mut harness, conversation, &[CREATOR, JOINER])?;
    let creator = member_ack(conversation, &receipt, CREATOR)?;
    let joiner = member_ack(conversation, &receipt, JOINER)?;
    let mut unsigned = joiner.clone();
    unsigned.old_leaf_signature = Opaque::new(vec![0; 64])?;
    let mut wrong_domain = joiner.clone();
    wrong_domain.old_leaf_signature = Opaque::from_slice(&sign(
        &key(SECOND_LEAF_SEED),
        SignatureDomain::CommitProcessed,
        &wrong_domain.tbs,
    )?)?;
    let cases = [
        ("unsigned", unsigned),
        ("incorrect domain", wrong_domain),
        (
            "another leaf's signature",
            signed_reinit_ack(joiner.clone(), LEAF_SEED)?,
        ),
        (
            "wrong index",
            resigned(
                joiner.clone(),
                |ack| ack.tbs.old_leaf_index = 5,
                SECOND_LEAF_SEED,
            )?,
        ),
        (
            "creator disposition from a joiner",
            resigned(
                joiner.clone(),
                |ack| {
                    ack.tbs.ack_kind = IrcReInitAckKind::CreatorState;
                    if let Ok(empty) = Opaque::new(Vec::new()) {
                        ack.tbs.key_package_ref = empty;
                    }
                },
                SECOND_LEAF_SEED,
            )?,
        ),
        (
            "joined disposition naming the creator's ref",
            resigned(
                joiner.clone(),
                |ack| {
                    if let Ok(reference) = Opaque::new(vec![14; 32]) {
                        ack.tbs.key_package_ref = reference;
                    }
                },
                SECOND_LEAF_SEED,
            )?,
        ),
    ];
    harness.attach_as(SECOND_DEVICE)?;
    for (name, ack) in &cases {
        let before = snapshot(&harness);
        assert_eq!(
            code(harness.run(
                Op::SubmitReinitAck,
                &conversation,
                Some(&wire(IrcWireObjectKind::ReinitAck, ack)?)
            )?),
            Some(E2eeReplyCode::BindingAuthInvalid),
            "standalone {name}"
        );
        assert!(
            harness.coordinator.state.conversations == before.conversations,
            "standalone {name}"
        );
    }
    // The creator's device cannot submit the joiner's ACK or a joined
    // disposition for its own leaf.
    harness.attach_as(DEVICE)?;
    refused(
        &mut harness,
        Op::SubmitReinitAck,
        &conversation,
        &wire(IrcWireObjectKind::ReinitAck, &joiner)?,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    let joined_creator = resigned(
        creator.clone(),
        |ack| {
            ack.tbs.ack_kind = IrcReInitAckKind::WelcomeJoin;
            if let Ok(reference) = Opaque::new(vec![88; 32]) {
                ack.tbs.key_package_ref = reference;
            }
        },
        LEAF_SEED,
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitAck,
        &conversation,
        &wire(IrcWireObjectKind::ReinitAck, &joined_creator)?,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // Embedded, each bad ACK replaces the joiner's in an otherwise complete set.
    for (name, ack) in cases {
        let request = activation(
            &harness,
            &receipt,
            &attempt,
            vec![creator.clone(), ack],
            &[DEVICE, SECOND_DEVICE],
        )?;
        let before = snapshot(&harness);
        assert_eq!(
            code(harness.run(Op::SubmitReinitActivate, &conversation, Some(&request))?),
            Some(E2eeReplyCode::BindingAuthInvalid),
            "embedded {name}"
        );
        assert!(
            harness.coordinator.state.logs == before.logs,
            "embedded {name}"
        );
        assert!(
            harness.coordinator.state.conversations == before.conversations,
            "embedded {name}"
        );
    }
    let omitted = activation(
        &harness,
        &receipt,
        &attempt,
        vec![creator.clone()],
        &[DEVICE, SECOND_DEVICE],
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &omitted,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // A duplicate leaf breaks the canonical set before any signer is read.
    let duplicate_leaf = resigned(
        joiner.clone(),
        |ack| ack.tbs.new_leaf_index = 2,
        SECOND_LEAF_SEED,
    )?;
    let duplicated = activation(
        &harness,
        &receipt,
        &attempt,
        vec![creator.clone(), joiner.clone(), duplicate_leaf.clone()],
        &[DEVICE, SECOND_DEVICE],
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &duplicated,
        E2eeReplyCode::InvalidFragment,
    )?;
    // Standalone, a differing ACK for an acknowledged leaf is a conflict.
    harness.attach_as(SECOND_DEVICE)?;
    ok(harness.run(
        Op::SubmitReinitAck,
        &conversation,
        Some(&wire(IrcWireObjectKind::ReinitAck, &joiner)?),
    )?)?;
    refused(
        &mut harness,
        Op::SubmitReinitAck,
        &conversation,
        &wire(IrcWireObjectKind::ReinitAck, &duplicate_leaf)?,
        E2eeReplyCode::OperationConflict,
    )?;
    // The exact planned set activates.
    harness.attach_as(DEVICE)?;
    let request = activation(
        &harness,
        &receipt,
        &attempt,
        vec![creator, joiner],
        &[DEVICE, SECOND_DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitReinitActivate, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitActivated(..)));
    Ok(())
}

#[test]
fn one_device_cannot_act_for_another_leaf_or_count_twice() -> Result {
    let (mut harness, conversation) = two_member_channel()?;
    finalize_both(&mut harness, conversation)?;
    // At epoch 1 device 7 also attests to leaf 4 under another key.
    let mut second_leaf =
        MembershipSpec::continuing(&harness.principal, conversation, DEVICE, 34, 4);
    second_leaf.epoch = 1;
    let second_leaf = membership_proof(&second_leaf)?;
    harness.publish_membership(conversation, &second_leaf)?;
    let (receipt, attempt) = stage(&mut harness, conversation, &[CREATOR, JOINER])?;
    let creator = member_ack(conversation, &receipt, CREATOR)?;
    // Same device, different leaf: device 7's leaf 4 names device 8's entry.
    let impostor = member_ack(
        conversation,
        &receipt,
        Member {
            device: DEVICE,
            leaf: 4,
            leaf_seed: 34,
            reference: Some(88),
        },
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitAck,
        &conversation,
        &wire(IrcWireObjectKind::ReinitAck, &impostor)?,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    let request = activation(
        &harness,
        &receipt,
        &attempt,
        vec![creator.clone(), impostor],
        &[DEVICE, SECOND_DEVICE],
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &request,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // With its creator ACK stored, device 7 still cannot add the joiner's
    // role through its second leaf.
    ok(harness.run(
        Op::SubmitReinitAck,
        &conversation,
        Some(&wire(IrcWireObjectKind::ReinitAck, &creator)?),
    )?)?;
    let impostor = member_ack(
        conversation,
        &receipt,
        Member {
            device: DEVICE,
            leaf: 4,
            leaf_seed: 34,
            reference: Some(88),
        },
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitAck,
        &conversation,
        &wire(IrcWireObjectKind::ReinitAck, &impostor)?,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    Ok(())
}

#[test]
fn a_removed_leaf_shrinks_the_continuing_set_and_cannot_acknowledge() -> Result {
    let (mut harness, conversation) = two_member_channel()?;
    let removal = finalize_both(&mut harness, conversation)?;
    // Device 8's leaf 1 is gone after the retained finalization.
    harness.attach_as(SECOND_DEVICE)?;
    let mut removed = MembershipSpec::continuing(
        &harness.principal,
        conversation,
        SECOND_DEVICE,
        SECOND_LEAF_SEED,
        1,
    );
    removed.epoch = 1;
    removed.removed = Some(removal);
    harness.publish_membership(conversation, &membership_proof(&removed)?)?;
    harness.attach_as(DEVICE)?;
    let (receipt, attempt) = stage(&mut harness, conversation, &[CREATOR])?;
    let creator = member_ack(conversation, &receipt, CREATOR)?;
    // The removed leaf is not an ACK signer, standalone or embedded.
    let extra = member_ack(conversation, &receipt, JOINER)?;
    harness.attach_as(SECOND_DEVICE)?;
    refused(
        &mut harness,
        Op::SubmitReinitAck,
        &conversation,
        &wire(IrcWireObjectKind::ReinitAck, &extra)?,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    harness.attach_as(DEVICE)?;
    let with_removed = activation(
        &harness,
        &receipt,
        &attempt,
        vec![creator.clone(), extra],
        &[DEVICE, SECOND_DEVICE],
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &with_removed,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // The creator alone is the whole expected continuing set.
    let request = activation(
        &harness,
        &receipt,
        &attempt,
        vec![creator],
        &[DEVICE, SECOND_DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitReinitActivate, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitActivated(..)));
    Ok(())
}

#[test]
fn a_revoked_joiner_cannot_complete_an_activation() -> Result {
    let (mut harness, conversation) = three_member_channel()?;
    let (receipt, attempt) = stage(&mut harness, conversation, &[CREATOR, JOINER, THIRD])?;
    let acks = vec![
        member_ack(conversation, &receipt, CREATOR)?,
        member_ack(conversation, &receipt, JOINER)?,
        member_ack(conversation, &receipt, THIRD)?,
    ];
    // Device 9 is revoked after staging: its ACK no longer identifies a signer.
    rotate_roster(&mut harness, &[DEVICE, SECOND_DEVICE])?;
    let request = activation(&harness, &receipt, &attempt, acks, &[DEVICE, SECOND_DEVICE])?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &request,
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn an_ack_naming_another_members_plan_entry_is_refused() -> Result {
    let (mut harness, conversation) = three_member_channel()?;
    let (receipt, attempt) = stage(&mut harness, conversation, &[CREATOR, JOINER])?;
    // Device 9's leaf 2 signs a Welcome ACK naming device 8's reserved ref.
    let usurper = member_ack(
        conversation,
        &receipt,
        Member {
            device: THIRD_DEVICE,
            leaf: 2,
            leaf_seed: THIRD_LEAF_SEED,
            reference: JOINER.reference,
        },
    )?;
    let creator = member_ack(conversation, &receipt, CREATOR)?;
    let request = activation(
        &harness,
        &receipt,
        &attempt,
        vec![creator, usurper.clone()],
        &[DEVICE, SECOND_DEVICE],
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &request,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    harness.attach_as(THIRD_DEVICE)?;
    refused(
        &mut harness,
        Op::SubmitReinitAck,
        &conversation,
        &wire(IrcWireObjectKind::ReinitAck, &usurper)?,
        E2eeReplyCode::BindingAuthInvalid,
    )
}
