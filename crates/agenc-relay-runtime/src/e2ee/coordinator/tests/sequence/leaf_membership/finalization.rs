//! Embedded Commit ACKs: a finalization is certified only when every ACK it
//! carries is signed by a distinct, roster-active, proof-identified leaf,
//! and a removed leaf never acknowledges again.

#![forbid(unsafe_code)]

use super::*;

/// A finalization request carrying `acks` for the candidate, voted by the
/// harness principal's first device under the initial policy.
pub(in crate::e2ee::coordinator::tests) fn finalization_with(
    harness: &Harness,
    conversation: [u8; 32],
    receipt: &ArcCandidateReceipt,
    commit_object_id: [u8; 32],
    candidate_id: [u8; 32],
    mut acks: Vec<ArcCommitAck>,
) -> TestResult<Vec<u8>> {
    let policy = harness.initial_policy_id()?;
    let log = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?;
    acks.sort_by_key(|ack| ack.tbs.old_leaf_index);
    let mut tbs = authorization_tbs(
        conversation,
        policy,
        ArcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
    );
    tbs.resulting_policy_id = policy;
    let authorization = commit_authorization(tbs, &[(&harness.principal, DEVICE)])?;
    let acknowledgements: Vec<_> = acks.iter().map(|ack| ack.tbs.clone()).collect();
    let core = ArcFinalizationCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_epoch: receipt.tbs.prior_epoch,
        prior_state_id: *log.accepted_state_id(),
        candidate_id,
        commit_object_id,
        resulting_epoch: receipt.tbs.resulting_epoch,
        old_policy_id: policy,
        commit_authorization_id: semantic_id_of(
            SemanticHashDomain::CommitAuthorizationId,
            &authorization.tbs,
        )?,
        acknowledgement_set_digest: agenc_relay_e2ee::ids::proof_set_digest(
            SemanticHashDomain::AcknowledgementSet,
            &acknowledgements,
        )?,
        resulting_group_context_digest: [2; 32],
        resulting_ratchet_tree_digest: [3; 32],
        finalization_authenticator: [4; 32],
    };
    let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &core)?;
    // Every council device of the harness principal votes.
    let votes = harness
        .devices
        .iter()
        .map(|device| {
            vote(
                harness,
                *device,
                receipt,
                candidate_id,
                Terminal::finalize(finalization_id),
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    wire(
        ArcWireObjectKind::FinalizationRequest,
        &ArcFinalizationRequest {
            proof: ArcFinalizationProof {
                core,
                receipt: receipt.clone(),
                authorization,
                acknowledgements: TlsVec::new(acks)?,
            },
            votes: TlsVec::new(votes)?,
        },
    )
}

/// One candidate at the log's current epoch, with its receipt, Commit
/// object, candidate identifier, and prior epoch.
fn candidate(
    harness: &mut Harness,
    conversation: [u8; 32],
    validation_time: u64,
) -> TestResult<(ArcCandidateReceipt, [u8; 32], [u8; 32], u64)> {
    let epoch = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_epoch();
    let (receipt, commit, candidate) =
        submit_candidate(harness, conversation, epoch, validation_time)?;
    Ok((receipt, commit, candidate, epoch))
}

fn leaf_ack(
    conversation: [u8; 32],
    position: (u64, [u8; 32], [u8; 32]),
    leaf: u32,
    signer: u8,
) -> TestResult<ArcCommitAck> {
    let (epoch, candidate, commit) = position;
    commit_ack_as(
        conversation,
        epoch,
        candidate,
        commit,
        leaf,
        credential_of(leaf),
        signer,
        SignatureDomain::CommitProcessed,
    )
}

/// Finalizes the current candidate with ACKs from both members' leaves
/// and returns the finalization identifier.
pub(in crate::e2ee::coordinator::tests::sequence) fn finalize_both(
    harness: &mut Harness,
    conversation: [u8; 32],
) -> TestResult<[u8; 32]> {
    let (receipt, commit, candidate_id, epoch) = candidate(harness, conversation, 30)?;
    let position = (epoch, candidate_id, commit);
    let acks = vec![
        leaf_ack(conversation, position, 0, LEAF_SEED)?,
        leaf_ack(conversation, position, 1, SECOND_LEAF_SEED)?,
    ];
    let request = finalization_with(harness, conversation, &receipt, commit, candidate_id, acks)?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    let ResultBody::Finalized(_, _, finalization_id, _) = outcome.result else {
        return Err("expected a finalization".into());
    };
    Ok(finalization_id)
}

#[test]
fn a_finalization_authenticates_every_embedded_ack() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    let (receipt, commit, candidate_id, epoch) = candidate(&mut harness, conversation, 30)?;
    let position = (epoch, candidate_id, commit);
    let own = leaf_ack(conversation, position, 0, LEAF_SEED)?;
    let second = leaf_ack(conversation, position, 1, SECOND_LEAF_SEED)?;
    let mut wrong_domain = second.clone();
    wrong_domain.old_leaf_signature = Opaque::from_slice(&sign(
        &key(SECOND_LEAF_SEED),
        SignatureDomain::ReinitProcessed,
        &wrong_domain.tbs,
    )?)?;
    let cases = [
        (
            "a valid signature by another leaf",
            vec![own.clone(), leaf_ack(conversation, position, 1, LEAF_SEED)?],
        ),
        ("an incorrect label", vec![own.clone(), wrong_domain]),
        (
            "a leaf without a stored proof",
            vec![own.clone(), leaf_ack(conversation, position, 2, 32)?],
        ),
    ];
    for (name, acks) in cases {
        let request =
            finalization_with(&harness, conversation, &receipt, commit, candidate_id, acks)?;
        let before = snapshot(&harness);
        assert_eq!(
            code(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?),
            Some(E2eeReplyCode::BindingAuthInvalid),
            "{name}"
        );
        assert!(harness.coordinator.state.logs == before.logs, "{name}");
        assert!(
            harness.coordinator.state.conversations == before.conversations,
            "{name}"
        );
        assert_eq!(harness.writes.len(), before.writes, "{name}");
    }
    // Both proof-identified leaves certify the candidate.
    let request = finalization_with(
        &harness,
        conversation,
        &receipt,
        commit,
        candidate_id,
        vec![own, second],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(..)));
    Ok(())
}

#[test]
fn one_device_cannot_sign_two_embedded_acks() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    finalize_both(&mut harness, conversation)?;
    // At epoch 1 device 7 also attests to leaf 3; one device holding two
    // leaves across epochs cannot count twice in one ACK set.
    let mut later = MembershipSpec::continuing(&harness.principal, conversation, DEVICE, 33, 3);
    later.epoch = 1;
    harness.publish_membership(conversation, &membership_proof(&later)?)?;
    let (receipt, commit, candidate_id, epoch) = candidate(&mut harness, conversation, 40)?;
    let position = (epoch, candidate_id, commit);
    let request = finalization_with(
        &harness,
        conversation,
        &receipt,
        commit,
        candidate_id,
        vec![
            leaf_ack(conversation, position, 0, LEAF_SEED)?,
            leaf_ack(conversation, position, 3, 33)?,
        ],
    )?;
    refused(
        &mut harness,
        Op::SubmitFinalization,
        &conversation,
        &request,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // The same duplicate signer is refused on the standalone path.
    let first = wire(
        ArcWireObjectKind::CommitAck,
        &leaf_ack(conversation, position, 0, LEAF_SEED)?,
    )?;
    ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&first))?)?;
    refused(
        &mut harness,
        Op::SubmitCommitAck,
        &conversation,
        &wire(
            ArcWireObjectKind::CommitAck,
            &leaf_ack(conversation, position, 3, 33)?,
        )?,
        E2eeReplyCode::OperationConflict,
    )
}

#[test]
fn a_removed_leaf_never_acknowledges_after_its_removal() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    let removal = finalize_both(&mut harness, conversation)?;
    // Device 8 records that its leaf 1 is gone after the retained finalization.
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
    let (receipt, commit, candidate_id, epoch) = candidate(&mut harness, conversation, 40)?;
    let position = (epoch, candidate_id, commit);
    let extra = leaf_ack(conversation, position, 1, SECOND_LEAF_SEED)?;
    refused(
        &mut harness,
        Op::SubmitCommitAck,
        &conversation,
        &wire(ArcWireObjectKind::CommitAck, &extra)?,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    harness.attach_as(DEVICE)?;
    let own = leaf_ack(conversation, position, 0, LEAF_SEED)?;
    let with_removed = finalization_with(
        &harness,
        conversation,
        &receipt,
        commit,
        candidate_id,
        vec![own.clone(), extra],
    )?;
    refused(
        &mut harness,
        Op::SubmitFinalization,
        &conversation,
        &with_removed,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // The continuing leaf alone processes the removal Commit.
    let request = finalization_with(
        &harness,
        conversation,
        &receipt,
        commit,
        candidate_id,
        vec![own],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(..)));
    Ok(())
}

/// Publishes the principal's next roster with only `kept` devices active.
pub(in crate::e2ee::coordinator::tests) fn rotate_roster(
    harness: &mut Harness,
    kept: &[u8],
) -> TestResult {
    let certificates = harness
        .principal
        .roster
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .filter(|entry| kept.iter().any(|seed| entry.device_id == [*seed; 16]))
        .map(|entry| entry.certificate.clone())
        .collect();
    let successor = super::super::super::support::roster(
        &harness.principal.root_secret,
        &harness.principal.root,
        1,
        super::super::super::support::roster_id(&harness.principal.roster)?,
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    let bytes = wire(ArcWireObjectKind::DeviceRoster, &successor)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    Ok(())
}

#[test]
fn a_revoked_device_can_neither_prove_nor_acknowledge() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    let (receipt, commit, candidate_id, epoch) = candidate(&mut harness, conversation, 30)?;
    let position = (epoch, candidate_id, commit);
    rotate_roster(&mut harness, &[DEVICE])?;
    let second = leaf_ack(conversation, position, 1, SECOND_LEAF_SEED)?;
    let own = leaf_ack(conversation, position, 0, LEAF_SEED)?;
    let request = finalization_with(
        &harness,
        conversation,
        &receipt,
        commit,
        candidate_id,
        vec![own.clone(), second.clone()],
    )?;
    refused(
        &mut harness,
        Op::SubmitFinalization,
        &conversation,
        &request,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // Nor can another attached device submit the retired device's ACK.
    refused(
        &mut harness,
        Op::SubmitCommitAck,
        &conversation,
        &wire(ArcWireObjectKind::CommitAck, &second)?,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // The retired device can no longer act as an attached device at all.
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key()) {
        origin.device = Some(([SECOND_DEVICE; 16], 1));
    }
    refused(
        &mut harness,
        Op::SubmitCommitAck,
        &conversation,
        &wire(ArcWireObjectKind::CommitAck, &second)?,
        E2eeReplyCode::DeviceRequired,
    )?;
    let proof = harness.leaf_proof(conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1)?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &proof_bytes(&proof)?,
        E2eeReplyCode::DeviceRequired,
    )?;
    // The retained device's proof still identifies it after the roster
    // change, while the retired council member can no longer vote.
    harness.attach_as(DEVICE)?;
    let own_bytes = wire(ArcWireObjectKind::CommitAck, &own)?;
    let outcome = ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&own_bytes))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::CommitAcked(conversation, candidate_id, object_id(&own_bytes))
    );
    Ok(())
}
