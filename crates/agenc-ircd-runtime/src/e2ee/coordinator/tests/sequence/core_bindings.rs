#![forbid(unsafe_code)]

//! Every terminal and approval object names the conversation, network, epoch and policy it
//! binds to; a core or envelope that names another one is refused before any vote counts.

use super::*;

/// One consistent edit of a finalization core and its acknowledgement.
type CoreEdit = fn(&mut IrcFinalizationCoreTbs, &mut IrcCommitAckTbs);

/// One edit of an abort core and the code it earns.
type AbortEdit = (&'static str, fn(&mut IrcAbortCoreTbs), E2eeReplyCode);

fn decoded_finalization(bytes: &[u8]) -> TestResult<IrcFinalizationRequest> {
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        bytes,
        Some(IrcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    Ok(IrcFinalizationRequest::decode_exact(
        object.body(),
        &mut budget,
    )?)
}

/// A finalization request whose core and single ACK agree on `edit`, so the proof itself
/// stays consistent and only the slot binding disagrees.
fn consistently_edited(
    request: &IrcFinalizationRequest,
    edit: fn(&mut IrcFinalizationCoreTbs, &mut IrcCommitAckTbs),
) -> TestResult<IrcFinalizationRequest> {
    let mut edited = request.clone();
    let mut ack = edited
        .proof
        .acknowledgements
        .as_slice()
        .first()
        .cloned()
        .ok_or("one ACK")?;
    edit(&mut edited.proof.core, &mut ack.tbs);
    let ack = signed_commit_ack(ack)?;
    edited.proof.core.acknowledgement_set_digest = agenc_ircd_e2ee::ids::proof_set_digest(
        SemanticHashDomain::AcknowledgementSet,
        std::slice::from_ref(&ack.tbs),
    )?;
    edited.proof.acknowledgements = TlsVec::new(vec![ack])?;
    Ok(edited)
}

#[test]
fn a_finalization_core_bound_to_another_slot_is_stale() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    let valid = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    let request = decoded_finalization(&valid)?;
    let mut other_conversation = request.clone();
    other_conversation.proof.core.conversation_id = [9; 32];
    let mut other_state = request.clone();
    other_state.proof.core.prior_state_id = [9; 32];
    for (name, edited) in [
        ("conversation", other_conversation),
        ("prior state", other_state),
    ] {
        let bytes = wire(IrcWireObjectKind::FinalizationRequest, &edited)?;
        assert_eq!(
            code(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?),
            Some(E2eeReplyCode::EpochStale),
            "{name}"
        );
    }
    let edits: [(&str, CoreEdit); 4] = [
        ("profile version", |core, ack| {
            core.profile_version = 2;
            ack.profile_version = 2;
        }),
        ("network", |core, ack| {
            core.network_id = [9; 32];
            ack.network_id = [9; 32];
        }),
        ("prior epoch", |core, ack| {
            core.prior_epoch = 5;
            ack.prior_epoch = 5;
        }),
        ("resulting epoch", |core, ack| {
            core.resulting_epoch = 7;
            ack.resulting_epoch = 7;
        }),
    ];
    for (name, edit) in edits {
        let edited = consistently_edited(&request, edit)?;
        let bytes = wire(IrcWireObjectKind::FinalizationRequest, &edited)?;
        assert_eq!(
            code(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?),
            Some(E2eeReplyCode::BindingAuthInvalid),
            "{name}"
        );
    }
    let mut other_policy = request.clone();
    other_policy.proof.core.old_policy_id = [9; 32];
    let bytes = wire(IrcWireObjectKind::FinalizationRequest, &other_policy)?;
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?),
        Some(E2eeReplyCode::BindingAuthInvalid),
        "old policy"
    );
    assert!(matches!(
        ok(harness.run(Op::SubmitFinalization, &conversation, Some(&valid))?)?.result,
        ResultBody::Finalized(..)
    ));
    Ok(())
}

#[test]
fn an_abort_core_bound_to_another_slot_is_refused() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, _, candidate_id) = submit_candidate(&mut harness, conversation, 0, 10)?;
    let core = IrcAbortCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_state_id: receipt.tbs.prior_state_id,
        candidate_id,
        prior_epoch: 0,
        reason: IrcCommitAbortReason::SenderWithdrawn,
        evidence_digest: [0; 32],
    };
    let abort_id = semantic_id_of(SemanticHashDomain::AbortId, &core)?;
    let votes = vec![vote(
        &harness,
        DEVICE,
        &receipt,
        candidate_id,
        Terminal::abort(abort_id, 1)?,
    )?];
    let edits: [AbortEdit; 5] = [
        (
            "conversation",
            |core| core.conversation_id = [9; 32],
            E2eeReplyCode::EpochStale,
        ),
        (
            "prior state",
            |core| core.prior_state_id = [9; 32],
            E2eeReplyCode::EpochStale,
        ),
        (
            "profile version",
            |core| core.profile_version = 2,
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "network",
            |core| core.network_id = [9; 32],
            E2eeReplyCode::BindingAuthInvalid,
        ),
        (
            "prior epoch",
            |core| core.prior_epoch = 3,
            E2eeReplyCode::BindingAuthInvalid,
        ),
    ];
    for (name, edit, expected) in edits {
        let mut edited = core.clone();
        edit(&mut edited);
        let bytes = wire(
            IrcWireObjectKind::AbortRequest,
            &IrcAbortRequest {
                core: edited,
                receipt: receipt.clone(),
                votes: TlsVec::new(votes.clone())?,
            },
        )?;
        assert_eq!(
            code(harness.run(Op::SubmitAbort, &conversation, Some(&bytes))?),
            Some(expected),
            "{name}"
        );
    }
    let bytes = wire(
        IrcWireObjectKind::AbortRequest,
        &IrcAbortRequest {
            core,
            receipt,
            votes: TlsVec::new(votes)?,
        },
    )?;
    assert!(matches!(
        ok(harness.run(Op::SubmitAbort, &conversation, Some(&bytes))?)?.result,
        ResultBody::Finalized(..) | ResultBody::Aborted(..)
    ));
    Ok(())
}

#[test]
fn an_approval_envelope_must_name_this_conversation_network_and_signer() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    submit_candidate(&mut harness, conversation, 0, 10)?;
    let envelope = approval_envelope(
        authorization_tbs(
            conversation,
            [0; 32],
            IrcCommitAuthorizationRule::RoutineSelfUpdate,
            0,
        ),
        &harness.principal,
        DEVICE,
    )?;
    let mut other_conversation = envelope.clone();
    other_conversation.tbs.conversation_id = [9; 32];
    let mut other_network = envelope.clone();
    other_network.tbs.network_id = [9; 32];
    let mut other_signer = envelope.clone();
    other_signer.approval.signer_device_id = [9; 16];
    for (name, edited, expected) in [
        (
            "conversation",
            other_conversation,
            E2eeReplyCode::RouteInvalid,
        ),
        ("network", other_network, E2eeReplyCode::RouteInvalid),
        ("signer", other_signer, E2eeReplyCode::DeviceRequired),
    ] {
        let bytes = wire(IrcWireObjectKind::CommitApproval, &edited)?;
        assert_eq!(
            code(harness.run(Op::SubmitAuthorization, &conversation, Some(&bytes))?),
            Some(expected),
            "{name}"
        );
    }
    let bytes = wire(IrcWireObjectKind::CommitApproval, &envelope)?;
    assert!(matches!(
        ok(harness.run(Op::SubmitAuthorization, &conversation, Some(&bytes))?)?.result,
        ResultBody::Stored(StoreKind::Authorization, _)
    ));
    Ok(())
}
