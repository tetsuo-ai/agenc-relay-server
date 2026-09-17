#![forbid(unsafe_code)]

//! Sequencing tests: one bound channel carries a Commit candidate through
//! authorization, acknowledgement, finalization, and abort, and the
//! retained records page back out.

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_ircd_domain::e2ee::projection::{EmptyKind, EventKind, PendingKind, StoreKind};
use agenc_ircd_e2ee::finality::{ReinitVoteSlot, Terminal, VoteSlot, reinit_vote_tbs, vote_tbs};
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::object::IrcWireObjectKind;
use agenc_ircd_e2ee::objects::aad::IrcCommitAad;
use agenc_ircd_e2ee::objects::conversation::{IrcCommitAuthorizationRule, IrcConversationKind};
use agenc_ircd_e2ee::objects::federation::IrcFederationOpcode as Op;
use agenc_ircd_e2ee::objects::sequencing::{
    IrcAbortCoreTbs, IrcAbortRequest, IrcCandidateReceipt, IrcCommitAbortReason, IrcCommitAck,
    IrcCommitAckTbs, IrcDisposition, IrcFinalityVote, IrcFinalizationCoreTbs, IrcFinalizationProof,
    IrcFinalizationRequest,
};
use agenc_ircd_e2ee::route::channel_route_binding;
use agenc_ircd_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, TlsVec};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

use super::support::{
    PolicySpec, approval_envelope, authorization_tbs, certificate_id_of, commit_authorization,
    finality_vote, key, policy, policy_id_of, private_message_at_epoch, root_fingerprint, sign,
};
use super::{
    DEVICE, GROUP, Harness, INSTANCE, NETWORK, ResultBody, TestResult, code, object_id, ok, wire,
    wire_raw,
};

/// A second council device of the harness principal.
const SECOND_DEVICE: u8 = 8;

const COMMIT_CONTENT_TYPE: u8 = 3;

#[path = "restart.rs"]
mod restart;

#[path = "recovery_pending.rs"]
pub(super) mod recovery_pending;

#[path = "ack_context.rs"]
mod ack_context;

mod leaf_membership;
mod object_expiry;
mod owners;

mod sequencer_eligibility;

#[test]
fn finalization_rejects_substituted_receipts_and_acknowledgements() -> TestResult {
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
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        &valid,
        Some(IrcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    let request = IrcFinalizationRequest::decode_exact(object.body(), &mut budget)?;
    let mut receipt_substitution = request.clone();
    receipt_substitution.proof.receipt.sequencer_signature = [0; 64];
    let mut ack_substitution = request.clone();
    let mut acknowledgements = ack_substitution.proof.acknowledgements.as_slice().to_vec();
    acknowledgements
        .first_mut()
        .ok_or("one ACK")?
        .tbs
        .resulting_group_context_digest = [99; 32];
    ack_substitution.proof.acknowledgements = TlsVec::new(acknowledgements)?;
    let mut duplicate_ack = request.clone();
    duplicate_ack.proof.acknowledgements = TlsVec::new(
        request
            .proof
            .acknowledgements
            .as_slice()
            .iter()
            .chain(request.proof.acknowledgements.as_slice())
            .cloned()
            .collect(),
    )?;
    for (request, expected) in [
        (receipt_substitution, E2eeReplyCode::BindingAuthInvalid),
        (ack_substitution, E2eeReplyCode::BindingAuthInvalid),
        (duplicate_ack, E2eeReplyCode::InvalidFragment),
    ] {
        let bytes = wire(IrcWireObjectKind::FinalizationRequest, &request)?;
        assert_eq!(
            code(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?),
            Some(expected)
        );
    }
    assert!(matches!(
        ok(harness.run(Op::SubmitFinalization, &conversation, Some(&valid))?)?.result,
        ResultBody::Finalized(..)
    ));
    Ok(())
}

#[test]
fn finalization_rejects_authorization_substitution_without_new_votes() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    let bytes = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        &bytes,
        Some(IrcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    let mut request = IrcFinalizationRequest::decode_exact(object.body(), &mut budget)?;
    request.proof.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &request.proof.authorization.tbs,
    )?;
    let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &request.proof.core)?;
    request.votes = TlsVec::new(vec![vote(
        &harness,
        DEVICE,
        &receipt,
        candidate_id,
        Terminal::finalize(finalization_id),
    )?])?;
    let valid = wire(IrcWireObjectKind::FinalizationRequest, &request)?;
    request.proof.authorization.tbs.resulting_policy_id =
        policy_id_of(&harness.operational_policy)?;
    let substituted = wire(IrcWireObjectKind::FinalizationRequest, &request)?;
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&substituted))?),
        Some(E2eeReplyCode::BindingAuthInvalid),
    );
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&valid))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(..)));
    Ok(())
}

#[test]
fn reload_preserves_counted_votes_after_the_signer_retires() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    let first = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&first))?)?;
    assert!(matches!(outcome.result, ResultBody::Pending(..)));
    super::retire_council_device(&mut harness, [DEVICE; 16])?;
    let expected = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .and_then(|state| state.vote_ledgers.get(&candidate_id))
        .ok_or("ledger")?
        .clone();
    let mut reloaded = harness.reloaded()?;
    let actual = reloaded
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .and_then(|state| state.vote_ledgers.get(&candidate_id))
        .ok_or("restored ledger")?;
    assert_eq!(actual, &expected);
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
    let abort = wire(
        IrcWireObjectKind::AbortRequest,
        &IrcAbortRequest {
            core,
            receipt: receipt.clone(),
            votes: TlsVec::new(vec![vote(
                &reloaded,
                DEVICE,
                &receipt,
                candidate_id,
                Terminal::abort(abort_id, 1)?,
            )?])?,
        },
    )?;
    assert_eq!(
        code(reloaded.run(Op::SubmitAbort, &conversation, Some(&abort))?),
        Some(E2eeReplyCode::DeviceRequired)
    );
    let origin = reloaded
        .coordinator
        .state
        .origins
        .get_mut(&super::origin_key())
        .ok_or("origin")?;
    origin.device = Some(([SECOND_DEVICE; 16], 0));
    assert_eq!(
        code(reloaded.run(Op::SubmitFinalization, &conversation, Some(&first))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    Ok(())
}

/// Reads the signed certificate clients fetch and checks its complete vote vector.
fn assert_certificate_votes(
    harness: &Harness,
    result: &ResultBody,
    mut expected: Vec<IrcFinalityVote>,
) -> TestResult {
    use agenc_ircd_e2ee::objects::sequencing::IrcSequencerRecord;

    let (ResultBody::Finalized(_, _, _, record_id)
    | ResultBody::Aborted(_, _, _, record_id)
    | ResultBody::ReinitActivated(_, _, _, record_id)
    | ResultBody::ReinitAborted(_, _, _, record_id)) = result
    else {
        return Err("expected a terminal result".into());
    };
    let bytes = harness
        .coordinator
        .state
        .objects
        .get(record_id)
        .ok_or("the certificate object")?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        bytes,
        Some(IrcWireObjectKind::SequencerRecord),
        &mut budget,
    )?;
    let votes = match IrcSequencerRecord::decode_exact(object.body(), &mut budget)? {
        IrcSequencerRecord::Finalization(certificate) => certificate.tbs.request.votes,
        IrcSequencerRecord::Abort(certificate) => certificate.tbs.request.votes,
        IrcSequencerRecord::ReinitActivation(certificate) => certificate.tbs.request.votes,
        IrcSequencerRecord::ReinitAbort(certificate) => certificate.tbs.request.votes,
        _ => return Err("expected a terminal certificate".into()),
    };
    expected.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
    assert_eq!(votes.as_slice(), expected);
    Ok(())
}

fn commit_bytes(
    harness: &Harness,
    conversation: [u8; 32],
    epoch: u64,
    validation_time: u64,
) -> TestResult<Vec<u8>> {
    let log = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("the sequencer log")?;
    let aad = IrcCommitAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: channel_route_binding(&NETWORK, &INSTANCE)?,
        validation_time,
        prior_state_id: *log.accepted_state_id(),
    }
    .encode()?;
    wire_raw(
        IrcWireObjectKind::CommitMls,
        private_message_at_epoch(&GROUP, epoch, COMMIT_CONTENT_TYPE, &aad)?,
    )
}

/// Submits a candidate and returns its receipt, the commit object id, and
/// the candidate id.
fn submit_candidate(
    harness: &mut Harness,
    conversation: [u8; 32],
    epoch: u64,
    validation_time: u64,
) -> TestResult<(IrcCandidateReceipt, [u8; 32], [u8; 32])> {
    let commit = commit_bytes(harness, conversation, epoch, validation_time)?;
    let outcome = ok(harness.run(Op::SubmitCandidate, &conversation, Some(&commit))?)?;
    assert_eq!(outcome.result, ResultBody::AcceptedEvent);
    assert!(outcome.security_mutation);
    let event = outcome.events.first().ok_or("one candidate event")?;
    assert_eq!(event.planned.kind, EventKind::Candidate);
    assert_eq!(event.payload.as_deref(), Some(commit.as_slice()));
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let receipt = IrcCandidateReceipt::decode_exact(&event.encoded_result, &mut budget)?;
    let candidate_id = semantic_id_of(SemanticHashDomain::CandidateId, &receipt.tbs)?;
    Ok((receipt, object_id(&commit), candidate_id))
}

fn ack(
    conversation: [u8; 32],
    prior_epoch: u64,
    candidate_id: [u8; 32],
    commit_object_id: [u8; 32],
) -> TestResult<Vec<u8>> {
    let ack = IrcCommitAck {
        tbs: IrcCommitAckTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: conversation,
            prior_epoch,
            candidate_id,
            commit_object_id,
            old_leaf_index: 0,
            old_credential_hash: [1; 32],
            resulting_epoch: prior_epoch + 1,
            resulting_group_context_digest: [2; 32],
            resulting_ratchet_tree_digest: [3; 32],
            finalization_authenticator: [4; 32],
        },
        old_leaf_signature: Opaque::new(vec![0; 64])?,
    };
    wire(IrcWireObjectKind::CommitAck, &signed_commit_ack(ack)?)
}

/// Signs a Commit ACK with the attached device's old leaf key.
fn signed_commit_ack(mut ack: IrcCommitAck) -> TestResult<IrcCommitAck> {
    ack.old_leaf_signature = Opaque::from_slice(&sign(
        &key(super::LEAF_SEED),
        SignatureDomain::CommitProcessed,
        &ack.tbs,
    )?)?;
    Ok(ack)
}

/// One council vote of `device` over the exact slot the receipt names.
fn vote(
    harness: &Harness,
    device: u8,
    receipt: &IrcCandidateReceipt,
    candidate_id: [u8; 32],
    terminal: Terminal,
) -> TestResult<IrcFinalityVote> {
    let slot = VoteSlot {
        network_id: NETWORK,
        conversation_id: receipt.tbs.conversation_id,
        prior_epoch: receipt.tbs.prior_epoch,
        prior_state_id: receipt.tbs.prior_state_id,
        candidate_sequence: receipt.tbs.candidate_sequence,
        predecessor_record_id: receipt.tbs.predecessor_record_id,
    };
    Ok(finality_vote(
        &harness.principal,
        device,
        &vote_tbs(&slot, candidate_id, terminal),
    )?)
}

/// A finalization request under the binding's initial policy, voted by
/// `voters`.
fn finalization_request(
    harness: &Harness,
    conversation: [u8; 32],
    receipt: &IrcCandidateReceipt,
    commit_object_id: [u8; 32],
    candidate_id: [u8; 32],
    ack_bytes: &[u8],
    voters: &[u8],
) -> TestResult<Vec<u8>> {
    let initial = harness.initial_policy_id()?;
    finalization_request_under(
        harness,
        conversation,
        receipt,
        commit_object_id,
        candidate_id,
        ack_bytes,
        voters,
        (initial, initial),
    )
}

/// A finalization request whose authorization names `policies` as the old
/// and resulting policy, voted by `voters`.
// agenc-review: allow owner=tests reviewed=2026-09-04 reason=one request names the harness the conversation the receipt the commit the candidate the ack the voters and both policies together
#[allow(clippy::too_many_arguments)]
fn finalization_request_under(
    harness: &Harness,
    conversation: [u8; 32],
    receipt: &IrcCandidateReceipt,
    commit_object_id: [u8; 32],
    candidate_id: [u8; 32],
    ack_bytes: &[u8],
    voters: &[u8],
    policies: ([u8; 32], [u8; 32]),
) -> TestResult<Vec<u8>> {
    let (old_policy_id, resulting_policy_id) = policies;
    let log = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("the sequencer log")?;
    let mut core = IrcFinalizationCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_epoch: receipt.tbs.prior_epoch,
        prior_state_id: *log.accepted_state_id(),
        candidate_id,
        commit_object_id,
        resulting_epoch: receipt.tbs.resulting_epoch,
        old_policy_id,
        commit_authorization_id: [0; 32],
        acknowledgement_set_digest: [0; 32],
        resulting_group_context_digest: [2; 32],
        resulting_ratchet_tree_digest: [3; 32],
        finalization_authenticator: [4; 32],
    };
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let ack_object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        ack_bytes,
        Some(IrcWireObjectKind::CommitAck),
        &mut budget,
    )?;
    let ack = IrcCommitAck::decode_exact(ack_object.body(), &mut budget)?;
    let mut tbs = authorization_tbs(
        conversation,
        old_policy_id,
        IrcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
    );
    tbs.resulting_policy_id = resulting_policy_id;
    let authorization = commit_authorization(tbs, &[(&harness.principal, DEVICE)])?;
    core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &authorization.tbs,
    )?;
    core.acknowledgement_set_digest = agenc_ircd_e2ee::ids::proof_set_digest(
        SemanticHashDomain::AcknowledgementSet,
        std::slice::from_ref(&ack.tbs),
    )?;
    let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &core)?;
    let votes = voters
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
    let request = IrcFinalizationRequest {
        proof: IrcFinalizationProof {
            core,
            receipt: receipt.clone(),
            authorization,
            acknowledgements: TlsVec::new(vec![ack])?,
        },
        votes: TlsVec::new(votes)?,
    };
    wire(IrcWireObjectKind::FinalizationRequest, &request)
}

#[test]
fn a_candidate_is_sequenced_authorized_acknowledged_and_finalized() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    // A candidate at a stale epoch is refused; the open epoch is accepted.
    let stale = commit_bytes(&harness, conversation, 5, 10)?;
    assert_eq!(
        code(harness.run(Op::SubmitCandidate, &conversation, Some(&stale))?),
        Some(E2eeReplyCode::EpochStale)
    );
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    assert_eq!(receipt.tbs.route_sequence, 0);
    assert_eq!(receipt.tbs.resulting_epoch, 1);
    // A second candidate on the same epoch waits for the terminal record.
    let again = commit_bytes(&harness, conversation, 0, 11)?;
    assert_eq!(
        code(harness.run(Op::SubmitCandidate, &conversation, Some(&again))?),
        Some(E2eeReplyCode::CandidateActive)
    );

    // Authorization by the attached device is stored under the candidate
    // its TBS names.
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
    let envelope_bytes = wire(IrcWireObjectKind::CommitApproval, &envelope)?;
    let outcome = ok(harness.run(
        Op::SubmitAuthorization,
        &conversation,
        Some(&envelope_bytes),
    )?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::Authorization, object_id(&envelope_bytes))
    );
    let mut fetch = conversation.to_vec();
    fetch.extend_from_slice(&envelope.tbs.candidate_id);
    fetch.push(0);
    let page = ok(harness.run(Op::FetchAuthorizations, &fetch, None)?)?;
    assert_eq!(page.result, ResultBody::ObjectPage);
    assert_eq!(page.responses.len(), 1);
    let mut other = conversation.to_vec();
    other.extend_from_slice(&[9; 32]);
    other.push(0);
    let empty = ok(harness.run(Op::FetchAuthorizations, &other, None)?)?;
    assert_eq!(empty.result, ResultBody::Empty(EmptyKind::Authorizations));

    // The acknowledgement must name the active candidate.
    let wrong = ack(conversation, 0, [9; 32], commit_object_id)?;
    assert_eq!(
        code(harness.run(Op::SubmitCommitAck, &conversation, Some(&wrong))?),
        Some(E2eeReplyCode::FinalityRequired)
    );
    let stale_epoch = ack(conversation, 4, candidate_id, commit_object_id)?;
    assert_eq!(
        code(harness.run(Op::SubmitCommitAck, &conversation, Some(&stale_epoch))?),
        Some(E2eeReplyCode::EpochStale)
    );
    let ack_bytes = ack(conversation, 0, candidate_id, commit_object_id)?;
    let outcome = ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&ack_bytes))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::CommitAcked(conversation, candidate_id, object_id(&ack_bytes))
    );
    assert_eq!(
        outcome.events.first().map(|event| event.planned.kind),
        Some(EventKind::CommitAck)
    );
    let mut acks = conversation.to_vec();
    acks.extend_from_slice(&candidate_id);
    acks.push(0);
    let page = ok(harness.run(Op::FetchAcks, &acks, None)?)?;
    assert_eq!(page.result, ResultBody::ObjectPage);
    assert_eq!(
        page.responses
            .first()
            .map(|response| response.bytes.clone()),
        Some(ack_bytes.clone())
    );

    // A proof without votes is pending; a vote finalizes the epoch.
    let pending = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&pending))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Pending(conversation, PendingKind::Finalization, object_id(&pending))
    );
    let request = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    let ResultBody::Finalized(named, epoch, finalization_id, record_id) = outcome.result else {
        return Err("expected a finalized result".into());
    };
    assert_eq!((named, epoch), (conversation, 1));
    assert!(
        outcome
            .events
            .iter()
            .all(|event| event.planned.kind == EventKind::Finalized)
    );
    let log = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?;
    assert_eq!(log.accepted_epoch(), 1);
    assert_eq!(*log.accepted_state_id(), finalization_id);
    assert!(log.candidate().is_none());
    let state = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?;
    assert_eq!(state.records.get(&1), Some(&record_id));
    assert!(state.proofs.contains_key(&finalization_id));

    // The retained records page back in route order; the commit object is
    // fetchable, a sequencer record is not.
    let mut receipts = conversation.to_vec();
    receipts.extend_from_slice(&0_u64.to_be_bytes());
    receipts.push(0);
    let page = ok(harness.run(Op::FetchReceipts, &receipts, None)?)?;
    assert_eq!(page.result, ResultBody::ObjectPage);
    assert_eq!(page.responses.len(), 2);
    let mut fetch_object = conversation.to_vec();
    fetch_object.extend_from_slice(&commit_object_id);
    let page = ok(harness.run(Op::FetchObject, &fetch_object, None)?)?;
    assert_eq!(page.responses.len(), 1);
    let mut fetch_record = conversation.to_vec();
    fetch_record.extend_from_slice(&record_id);
    let page = ok(harness.run(Op::FetchObject, &fetch_record, None)?)?;
    assert_eq!(page.result, ResultBody::ObjectPage);
    let route_object = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .map(|state| state.route_object_id)
        .ok_or("state")?;
    let mut fetch_route = conversation.to_vec();
    fetch_route.extend_from_slice(&route_object);
    let page = ok(harness.run(Op::FetchObject, &fetch_route, None)?)?;
    assert_eq!(page.result, ResultBody::Empty(EmptyKind::Objects));

    // A finalized epoch accepts the next candidate, which an abort resets.
    let (receipt, _, candidate_id) = submit_candidate(&mut harness, conversation, 1, 12)?;
    assert_eq!(receipt.tbs.route_sequence, 2);
    let prior_state_id = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let core = IrcAbortCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_state_id,
        candidate_id,
        prior_epoch: 1,
        reason: IrcCommitAbortReason::SenderWithdrawn,
        evidence_digest: [0; 32],
    };
    let abort_id = semantic_id_of(SemanticHashDomain::AbortId, &core)?;
    let abort_vote = vote(
        &harness,
        DEVICE,
        &receipt,
        candidate_id,
        Terminal::abort(abort_id, 1)?,
    )?;
    let abort = |votes: Vec<IrcFinalityVote>| -> TestResult<Vec<u8>> {
        wire(
            IrcWireObjectKind::AbortRequest,
            &IrcAbortRequest {
                core: core.clone(),
                receipt: receipt.clone(),
                votes: TlsVec::new(votes)?,
            },
        )
    };
    let pending = abort(Vec::new())?;
    let outcome = ok(harness.run(Op::SubmitAbort, &conversation, Some(&pending))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Abort, _)
    ));
    let request = abort(vec![abort_vote])?;
    let outcome = ok(harness.run(Op::SubmitAbort, &conversation, Some(&request))?)?;
    assert!(
        matches!(outcome.result, ResultBody::Aborted(named, aborted, ..) if named == conversation && aborted == candidate_id)
    );
    assert!(
        outcome
            .events
            .iter()
            .all(|event| event.planned.kind == EventKind::Aborted)
    );
    let log = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?;
    assert_eq!(log.accepted_epoch(), 1);
    assert!(log.candidate().is_none());
    // The epoch stays open for a fresh candidate after the abort.
    let (receipt, _, _) = submit_candidate(&mut harness, conversation, 1, 13)?;
    assert_eq!(receipt.tbs.route_sequence, 4);
    assert_eq!(receipt.tbs.candidate_sequence, 1);
    Ok(())
}

mod reinit {
    mod ack_context;
    mod admission;
    mod attempt_authority;
    mod leaf_membership;
    pub(in crate::e2ee::coordinator::tests::sequence) mod successor;

    use agenc_ircd_crypto::SignatureDomain;
    use agenc_ircd_domain::e2ee::projection::{EventKind, PendingKind};
    use agenc_ircd_domain::e2ee::sequencer_log::Phase;
    use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
    use agenc_ircd_e2ee::objects::conversation::{IrcKeyPackagePlan, IrcKeyPackagePlanEntry};
    use agenc_ircd_e2ee::objects::federation::IrcFederationOpcode as Op;
    use agenc_ircd_e2ee::objects::reinit::{
        IrcReInitAbortCoreTbs, IrcReInitAbortRequest, IrcReInitAck, IrcReInitAckKind,
        IrcReInitAckTbs, IrcReInitActivationCoreTbs, IrcReInitActivationRequest, IrcReInitAttempt,
        IrcReInitAttemptAuthorization, IrcReInitAttemptAuthorizationTbs, IrcReInitAttemptReceipt,
        IrcReInitAttemptTbs,
    };
    use agenc_ircd_e2ee::objects::sequencing::IrcSequencerRecord;
    use agenc_ircd_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsVec};
    use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

    use super::super::support::{commit_approval, root_fingerprint};
    use super::super::{
        DEVICE, DEVICE_ID, Harness, NETWORK, ResultBody, TestResult, code, ok, wire,
    };
    use super::{
        SECOND_DEVICE, SemanticHashDomain, Terminal, assert_certificate_votes, reinit_vote,
        semantic_id_of,
    };

    const NEW_CONVERSATION: [u8; 32] = [77; 32];
    /// The old leaf key of `SECOND_DEVICE` when it joins a successor.
    const JOINER_LEAF_SEED: u8 = 31;

    #[test]
    fn reinit_abort_rejects_substituted_attempts_and_receipts() -> TestResult {
        let mut harness = Harness::new()?;
        let conversation = harness.bind_channel()?;
        let old_state = *harness
            .coordinator
            .state
            .logs
            .get(&conversation)
            .ok_or("log")?
            .accepted_state_id();
        let (attempt, bytes) = attempt(&harness, conversation, old_state, 0)?;
        ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
        let receipt = staged_receipt(&harness, conversation)?;
        let request = IrcReInitAbortRequest {
            core: IrcReInitAbortCoreTbs {
                profile_version: 1,
                network_id: NETWORK,
                old_conversation_id: conversation,
                old_reinit_state_id: old_state,
                attempt_sequence: 0,
                slot_predecessor_record_id: receipt.tbs.predecessor_record_id,
                reinit_attempt_id: receipt.tbs.reinit_attempt_id,
                reason_code: 1,
                evidence_digest: [0; 32],
            },
            receipt,
            attempt,
            votes: TlsVec::new(Vec::new())?,
        };
        let mut wrong_attempt = request.clone();
        wrong_attempt.attempt.creator_old_leaf_signature = Opaque::new(vec![0; 64])?;
        let mut wrong_receipt = request.clone();
        wrong_receipt.receipt.sequencer_signature = [0; 64];
        for substituted in [wrong_attempt, wrong_receipt] {
            let bytes = wire(IrcWireObjectKind::ReinitAbortRequest, &substituted)?;
            assert_eq!(
                code(harness.run(Op::SubmitReinitAbort, &conversation, Some(&bytes))?),
                Some(E2eeReplyCode::BindingAuthInvalid)
            );
        }
        let valid = wire(IrcWireObjectKind::ReinitAbortRequest, &request)?;
        assert!(matches!(
            ok(harness.run(Op::SubmitReinitAbort, &conversation, Some(&valid))?)?.result,
            ResultBody::Pending(..)
        ));
        Ok(())
    }

    pub(super) fn attempt(
        harness: &Harness,
        conversation: [u8; 32],
        old_state: [u8; 32],
        attempt_sequence: u32,
    ) -> TestResult<(IrcReInitAttempt, Vec<u8>)> {
        let fingerprint = root_fingerprint(&harness.principal.root)?;
        let authorization_tbs = IrcReInitAttemptAuthorizationTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: conversation,
            old_reinit_state_id: old_state,
            attempt_sequence,
            creator_old_leaf_index: 0,
            creator_old_credential_hash: [1; 32],
            new_conversation_id: NEW_CONVERSATION,
            target_context_digest: [2; 32],
            target_binding_id: [3; 32],
            initial_member_plan_id: [4; 32],
            key_package_plan_id: [5; 32],
            initial_commit_digest: [6; 32],
            new_group_info_digest: [7; 32],
            new_group_context_digest: [8; 32],
            new_ratchet_tree_digest: [9; 32],
            new_exporter_authenticator: [10; 32],
        };
        let approval = commit_approval(
            &harness.principal,
            DEVICE,
            &authorization_tbs,
            SignatureDomain::ReinitAttemptAuthorization,
        )?;
        let mut attempt = IrcReInitAttempt {
            tbs: IrcReInitAttemptTbs {
                profile_version: 1,
                network_id: NETWORK,
                old_conversation_id: conversation,
                new_conversation_id: NEW_CONVERSATION,
                old_reinit_state_id: old_state,
                attempt_sequence,
                creator_old_leaf_index: 0,
                creator_old_credential_hash: [1; 32],
                target_group_id: Opaque::new(vec![11; 32])?,
                target_version: 1,
                target_suite: 1,
                target_context_digest: [2; 32],
                target_binding_id: [3; 32],
                initial_member_plan_id: [4; 32],
                key_package_plan_id: [5; 32],
                initial_commit_digest: [6; 32],
                attempt_authorization_id: [12; 32],
                new_group_info_digest: [7; 32],
                new_group_context_digest: [8; 32],
                new_ratchet_tree_digest: [9; 32],
                new_exporter_authenticator: [10; 32],
            },
            key_package_plan: IrcKeyPackagePlan {
                entries: TlsVec::new(vec![IrcKeyPackagePlanEntry {
                    account_id: Opaque::from_slice(&harness.account)?,
                    root_fingerprint: fingerprint,
                    device_id: DEVICE_ID,
                    capability_id: [13; 32],
                    key_package_ref: Opaque::new(vec![14; 32])?,
                    leaf_signature_scheme: 0x0807,
                    leaf_signature_key_digest: [18; 32],
                    creator: 1,
                }])?,
            },
            initial_commit_bytes: Opaque::new(vec![15; 40])?,
            authorization: IrcReInitAttemptAuthorization {
                tbs: authorization_tbs,
                approvals: TlsVec::new(vec![approval])?,
            },
            creator_old_leaf_signature: Opaque::new(vec![16; 64])?,
        };
        attempt_authority::authorize_attempt(harness, &mut attempt)?;
        let bytes = wire(IrcWireObjectKind::ReinitAttempt, &attempt)?;
        Ok((attempt, bytes))
    }

    pub(super) fn staged_receipt(
        harness: &Harness,
        conversation: [u8; 32],
    ) -> TestResult<IrcReInitAttemptReceipt> {
        let state = harness
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .ok_or("state")?;
        let (_, record_id) = state.records.iter().next_back().ok_or("a record")?;
        let bytes = harness
            .coordinator
            .state
            .objects
            .get(record_id)
            .ok_or("the record object")?;
        let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
        let object = IrcWireObject::decode_kind(
            bytes,
            Some(IrcWireObjectKind::SequencerRecord),
            &mut budget,
        )?;
        match IrcSequencerRecord::decode_exact(object.body(), &mut budget)? {
            IrcSequencerRecord::ReinitAttempt(receipt) => Ok(receipt),
            _ => Err("expected a ReInit attempt record".into()),
        }
    }

    pub(super) fn ack(
        conversation: [u8; 32],
        old_state: [u8; 32],
        attempt_id: [u8; 32],
    ) -> TestResult<(IrcReInitAck, Vec<u8>)> {
        let ack = IrcReInitAck {
            tbs: IrcReInitAckTbs {
                profile_version: 1,
                network_id: NETWORK,
                old_conversation_id: conversation,
                new_conversation_id: NEW_CONVERSATION,
                old_reinit_state_id: old_state,
                reinit_attempt_id: attempt_id,
                ack_kind: IrcReInitAckKind::CreatorState,
                new_group_info_digest: [7; 32],
                new_group_context_digest: [8; 32],
                new_ratchet_tree_digest: [9; 32],
                new_exporter_authenticator: [10; 32],
                old_leaf_index: 0,
                old_credential_hash: [1; 32],
                new_leaf_index: 0,
                key_package_ref: Opaque::new(Vec::new())?,
            },
            old_leaf_signature: Opaque::new(vec![0; 64])?,
        };
        let ack = signed_reinit_ack(ack, super::super::LEAF_SEED)?;
        let bytes = wire(IrcWireObjectKind::ReinitAck, &ack)?;
        Ok((ack, bytes))
    }

    /// Signs a ReInit ACK with old leaf key `leaf_seed`.
    pub(super) fn signed_reinit_ack(
        mut ack: IrcReInitAck,
        leaf_seed: u8,
    ) -> TestResult<IrcReInitAck> {
        ack.old_leaf_signature = Opaque::from_slice(&super::super::support::sign(
            &super::super::support::key(leaf_seed),
            SignatureDomain::ReinitProcessed,
            &ack.tbs,
        )?)?;
        Ok(ack)
    }

    #[test]
    fn a_reinit_attempt_is_staged_acknowledged_aborted_and_finally_activated() -> TestResult {
        let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
        let conversation = harness.bind_channel()?;
        // A ReInit follows the finalized ReInit Commit whose finalization is
        // the accepted state; after the bootstrap that is the genesis anchor.
        let old_state = *harness
            .coordinator
            .state
            .logs
            .get(&conversation)
            .ok_or("log")?
            .accepted_state_id();
        let (_, first) = attempt(&harness, conversation, old_state, 0)?;
        let outcome = ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&first))?)?;
        let ResultBody::ReinitStaged(named, attempt_id, _) = outcome.result else {
            return Err("expected a staged attempt".into());
        };
        assert_eq!(named, conversation);
        assert!(
            outcome
                .events
                .iter()
                .all(|event| event.planned.kind == EventKind::ReinitStaged)
        );
        assert!(matches!(
            harness
                .coordinator
                .state
                .logs
                .get(&conversation)
                .map(|log| log.phase()),
            Some(Phase::Reinit { .. })
        ));
        // Only one attempt is open at a time.
        assert_eq!(
            code(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&first))?),
            Some(E2eeReplyCode::CandidateActive)
        );

        // The acknowledgement names the open attempt.
        let (_, wrong) = ack(conversation, old_state, [9; 32])?;
        assert_eq!(
            code(harness.run(Op::SubmitReinitAck, &conversation, Some(&wrong))?),
            Some(E2eeReplyCode::FinalityRequired)
        );
        let (ack_object, ack_bytes) = ack(conversation, old_state, attempt_id)?;
        let outcome = ok(harness.run(Op::SubmitReinitAck, &conversation, Some(&ack_bytes))?)?;
        assert!(
            matches!(outcome.result, ResultBody::ReinitAcked(named, acked, _) if named == conversation && acked == attempt_id)
        );

        // Each device submits separately; the certificate must include both.
        let receipt = staged_receipt(&harness, conversation)?;
        let (attempt_object, _) = attempt(&harness, conversation, old_state, 0)?;
        let abort_core = IrcReInitAbortCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: conversation,
            old_reinit_state_id: old_state,
            attempt_sequence: 0,
            slot_predecessor_record_id: receipt.tbs.predecessor_record_id,
            reinit_attempt_id: attempt_id,
            reason_code: 1,
            evidence_digest: [0; 32],
        };
        let abort_id = semantic_id_of(SemanticHashDomain::ReinitAbortId, &abort_core)?;
        let abort = |votes| -> TestResult<Vec<u8>> {
            wire(
                IrcWireObjectKind::ReinitAbortRequest,
                &IrcReInitAbortRequest {
                    core: abort_core.clone(),
                    receipt: receipt.clone(),
                    attempt: attempt_object.clone(),
                    votes: TlsVec::new(votes)?,
                },
            )
        };
        let outcome = ok(harness.run(
            Op::SubmitReinitAbort,
            &conversation,
            Some(&abort(Vec::new())?),
        )?)?;
        assert!(matches!(
            outcome.result,
            ResultBody::Pending(_, PendingKind::ReinitAbort, _)
        ));
        let abort_vote = reinit_vote(
            &harness,
            DEVICE,
            &receipt,
            old_state,
            attempt_id,
            Terminal::abort(abort_id, 1)?,
        )?;
        let outcome = ok(harness.run(
            Op::SubmitReinitAbort,
            &conversation,
            Some(&abort(vec![abort_vote.clone()])?),
        )?)?;
        assert!(matches!(outcome.result, ResultBody::Pending(..)));
        harness = harness.reloaded()?;
        let second_abort_vote = reinit_vote(
            &harness,
            SECOND_DEVICE,
            &receipt,
            old_state,
            attempt_id,
            Terminal::abort(abort_id, 1)?,
        )?;
        let outcome = ok(harness.run(
            Op::SubmitReinitAbort,
            &conversation,
            Some(&abort(vec![second_abort_vote.clone()])?),
        )?)?;
        assert_certificate_votes(
            &harness,
            &outcome.result,
            vec![abort_vote, second_abort_vote],
        )?;
        assert!(
            matches!(outcome.result, ResultBody::ReinitAborted(named, aborted, ..) if named == conversation && aborted == attempt_id)
        );
        assert!(
            outcome
                .events
                .iter()
                .all(|event| event.planned.kind == EventKind::ReinitAborted)
        );

        // A restart preserves the aborted attempt's next sequence.
        harness = harness.reloaded()?;
        // The next attempt activates the successor conversation.
        let (attempt_object, second) = attempt(&harness, conversation, old_state, 1)?;
        let outcome = ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&second))?)?;
        let ResultBody::ReinitStaged(_, attempt_id, _) = outcome.result else {
            return Err("expected a staged attempt".into());
        };
        let receipt = staged_receipt(&harness, conversation)?;
        let (ack_object_again, _) = ack(conversation, old_state, attempt_id)?;
        let activation_core = IrcReInitActivationCoreTbs {
            profile_version: 1,
            network_id: NETWORK,
            old_conversation_id: conversation,
            new_conversation_id: NEW_CONVERSATION,
            old_reinit_state_id: old_state,
            attempt_sequence: 1,
            reinit_attempt_id: attempt_id,
            new_group_info_digest: [7; 32],
            new_group_context_digest: [8; 32],
            new_ratchet_tree_digest: [9; 32],
            new_exporter_authenticator: [10; 32],
            acknowledgement_set_digest: agenc_ircd_e2ee::ids::proof_set_digest(
                SemanticHashDomain::ReinitAcknowledgementSet,
                std::slice::from_ref(&ack_object_again.tbs),
            )?,
        };
        let activation_id =
            semantic_id_of(SemanticHashDomain::ReinitActivationId, &activation_core)?;
        let activate = |votes| -> TestResult<Vec<u8>> {
            wire(
                IrcWireObjectKind::ReinitActivationRequest,
                &IrcReInitActivationRequest {
                    core: activation_core.clone(),
                    receipt: receipt.clone(),
                    attempt: attempt_object.clone(),
                    acknowledgements: TlsVec::new(vec![ack_object_again.clone()])?,
                    votes: TlsVec::new(votes)?,
                },
            )
        };
        let outcome = ok(harness.run(
            Op::SubmitReinitActivate,
            &conversation,
            Some(&activate(Vec::new())?),
        )?)?;
        assert!(matches!(
            outcome.result,
            ResultBody::Pending(_, PendingKind::ReinitActivate, _)
        ));
        let activate_vote = reinit_vote(
            &harness,
            DEVICE,
            &receipt,
            old_state,
            attempt_id,
            Terminal::finalize(activation_id),
        )?;
        let outcome = ok(harness.run(
            Op::SubmitReinitActivate,
            &conversation,
            Some(&activate(vec![activate_vote.clone()])?),
        )?)?;
        assert!(matches!(outcome.result, ResultBody::Pending(..)));
        harness = harness.reloaded()?;
        let second_activate_vote = reinit_vote(
            &harness,
            SECOND_DEVICE,
            &receipt,
            old_state,
            attempt_id,
            Terminal::finalize(activation_id),
        )?;
        let outcome = ok(harness.run(
            Op::SubmitReinitActivate,
            &conversation,
            Some(&activate(vec![second_activate_vote.clone()])?),
        )?)?;
        assert_certificate_votes(
            &harness,
            &outcome.result,
            vec![activate_vote, second_activate_vote],
        )?;
        assert!(matches!(
            outcome.result,
            ResultBody::ReinitActivated(old, new, ..) if old == conversation && new == NEW_CONVERSATION
        ));
        assert!(
            outcome
                .events
                .iter()
                .all(|event| event.planned.kind == EventKind::ReinitActivated)
        );
        assert!(matches!(
            harness
                .coordinator
                .state
                .logs
                .get(&conversation)
                .map(|log| log.phase()),
            Some(Phase::Migrated { .. })
        ));
        assert!(
            harness
                .coordinator
                .state
                .logs
                .contains_key(&NEW_CONVERSATION)
        );
        assert!(
            harness
                .coordinator
                .state
                .lifecycles
                .contains_key(&NEW_CONVERSATION)
        );
        harness = harness.reloaded()?;
        let old_log = harness
            .coordinator
            .state
            .logs
            .get(&conversation)
            .ok_or("old log")?;
        assert!(matches!(old_log.phase(), Phase::Migrated { .. }));
        assert!(!old_log.accepts_application());
        assert!(
            old_log
                .candidate_position(old_log.accepted_epoch())
                .is_err()
        );
        let successor = harness
            .coordinator
            .state
            .logs
            .get(&NEW_CONVERSATION)
            .ok_or("successor log")?;
        assert_eq!(successor.accepted_epoch(), 1);
        assert_eq!(successor.accepted_state_id(), &activation_id);
        assert!(
            harness
                .coordinator
                .state
                .lifecycles
                .contains_key(&NEW_CONVERSATION)
        );
        let _ = ack_object;
        Ok(())
    }
}

/// One council device's vote over a ReInit attempt's slot.
fn reinit_vote(
    harness: &Harness,
    device: u8,
    receipt: &agenc_ircd_e2ee::objects::reinit::IrcReInitAttemptReceipt,
    old_reinit_state_id: [u8; 32],
    attempt_id: [u8; 32],
    terminal: Terminal,
) -> TestResult<IrcFinalityVote> {
    let slot = ReinitVoteSlot {
        network_id: NETWORK,
        old_conversation_id: receipt.tbs.old_conversation_id,
        old_reinit_state_id,
        attempt_sequence: receipt.tbs.attempt_sequence,
        predecessor_record_id: receipt.tbs.predecessor_record_id,
    };
    let tbs = reinit_vote_tbs(&slot, attempt_id, terminal);
    Ok(IrcFinalityVote {
        signer_root_fingerprint: root_fingerprint(&harness.principal.root)?,
        signer_device_id: [device; 16],
        signer_device_certificate_id: certificate_id_of(&harness.principal, device)?,
        device_signature: sign(&key(device), SignatureDomain::ReinitDisposition, &tbs)?,
    })
}

/// Acknowledges the candidate and returns the encoded ACK.
fn acknowledge(
    harness: &mut Harness,
    conversation: [u8; 32],
    candidate_id: [u8; 32],
    commit_object_id: [u8; 32],
) -> TestResult<Vec<u8>> {
    let ack_bytes = ack(conversation, 0, candidate_id, commit_object_id)?;
    ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&ack_bytes))?)?;
    Ok(ack_bytes)
}

#[test]
fn a_terminal_without_a_published_policy_is_refused_until_it_is_published() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel_unpublished()?;
    harness.publish_leaf_zero(conversation)?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    let request = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?),
        Some(E2eeReplyCode::PolicyRequired)
    );
    let initial = harness.initial_policy.clone();
    harness.publish_policy(conversation, &initial)?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(..)));
    Ok(())
}

#[test]
fn published_policies_follow_the_binding_chain() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel_unpublished()?;
    let initial = harness.initial_policy.clone();
    let operational = harness.operational_policy.clone();
    // The successor cannot precede its predecessor.
    let successor_bytes = wire(IrcWireObjectKind::Policy, &operational)?;
    assert_eq!(
        code(harness.run(Op::SubmitPolicy, &conversation, Some(&successor_bytes))?),
        Some(E2eeReplyCode::PolicyInvalid)
    );
    // A generation-zero policy other than the binding's is refused.
    let other = policy(&PolicySpec {
        threshold: 1,
        ..PolicySpec::bootstrap(
            std::slice::from_ref(&harness.principal),
            conversation,
            IrcConversationKind::Direct,
        )
    })?;
    let other_bytes = wire(IrcWireObjectKind::Policy, &other)?;
    assert_eq!(
        code(harness.run(Op::SubmitPolicy, &conversation, Some(&other_bytes))?),
        Some(E2eeReplyCode::PolicyInvalid)
    );
    // The chain in order, and an identical resubmission answers the same.
    let first = harness.publish_policy(conversation, &initial)?;
    assert_eq!(harness.publish_policy(conversation, &initial)?, first);
    harness.publish_policy(conversation, &operational)?;
    let state = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?;
    assert_eq!(state.policies.len(), 2);
    assert_eq!(state.current_policy_id, policy_id_of(&initial)?);
    assert!(state.policies.contains_key(&policy_id_of(&operational)?));
    Ok(())
}

#[test]
fn a_finalization_waits_for_the_quorum_of_the_published_council() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    // Two council devices with fault bound zero need both votes.
    let one = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&one))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Finalization, _)
    ));
    // The second vote alone completes the quorum the first request began.
    let second = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[SECOND_DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&second))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(..)));
    let ResultBody::Finalized(_, _, finalization_id, _) = outcome.result else {
        return Err("expected finalization".into());
    };
    let expected = [DEVICE, SECOND_DEVICE]
        .into_iter()
        .map(|device| {
            vote(
                &harness,
                device,
                &receipt,
                candidate_id,
                Terminal::finalize(finalization_id),
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_certificate_votes(&harness, &outcome.result, expected)?;
    Ok(())
}

#[test]
fn a_council_vote_for_the_other_terminal_is_discarded() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    let finalize = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&finalize))?)?;
    assert!(matches!(outcome.result, ResultBody::Pending(..)));
    // The first device already stands for FINALIZE, so its ABORT vote is
    // discarded and the abort stays one vote short.
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
    let votes = [DEVICE, SECOND_DEVICE]
        .iter()
        .map(|device| {
            vote(
                &harness,
                *device,
                &receipt,
                candidate_id,
                Terminal::abort(abort_id, 1)?,
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    let abort = wire(
        IrcWireObjectKind::AbortRequest,
        &IrcAbortRequest {
            core,
            receipt: receipt.clone(),
            votes: TlsVec::new(votes)?,
        },
    )?;
    let outcome = ok(harness.run(Op::SubmitAbort, &conversation, Some(&abort))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Abort, _)
    ));
    // A vote that does not verify fails the whole request; the first device
    // still stands for FINALIZE, so its forged vote is verified, not
    // discarded.
    let mut forged = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    if let Some(last) = forged.last_mut() {
        *last ^= 1;
    }
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&forged))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    Ok(())
}

#[test]
fn an_abort_certificate_keeps_votes_from_separate_requests_and_a_reload() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
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
    let terminal = Terminal::abort(abort_id, 1)?;
    let votes = [DEVICE, SECOND_DEVICE]
        .into_iter()
        .map(|device| vote(&harness, device, &receipt, candidate_id, terminal))
        .collect::<TestResult<Vec<_>>>()?;
    for (index, vote) in votes.iter().enumerate() {
        let request = wire(
            IrcWireObjectKind::AbortRequest,
            &IrcAbortRequest {
                core: core.clone(),
                receipt: receipt.clone(),
                votes: TlsVec::new(vec![vote.clone()])?,
            },
        )?;
        let outcome = ok(harness.run(Op::SubmitAbort, &conversation, Some(&request))?)?;
        if index == 0 {
            assert!(matches!(outcome.result, ResultBody::Pending(..)));
            harness = harness.reloaded()?;
        } else {
            assert_certificate_votes(&harness, &outcome.result, votes.clone())?;
        }
    }
    Ok(())
}

#[test]
fn a_reloaded_coordinator_restores_the_policy_chain_and_the_current_policy() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    let request = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    let reloaded = harness.reloaded()?;
    let before = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?;
    let after = reloaded
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("reloaded state")?;
    assert_eq!(after.policies, before.policies);
    assert_eq!(after.policies.len(), 2);
    assert_eq!(after.current_policy_id, harness.initial_policy_id()?);
    assert_eq!(after.initial_policy_id, before.initial_policy_id);
    assert_eq!(
        after.required_operational_policy_id,
        before.required_operational_policy_id
    );
    assert_eq!(after.principal_accounts, before.principal_accounts);
    Ok(())
}

#[test]
fn a_policy_change_installs_only_the_retained_successor_of_the_old_policy() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let initial = harness.initial_policy_id()?;
    let operational = policy_id_of(&harness.operational_policy)?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    // An unretained resulting policy is required first.
    let unretained = finalization_request_under(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
        (initial, [90; 32]),
    )?;
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&unretained))?),
        Some(E2eeReplyCode::PolicyRequired)
    );
    // The retained successor installs and becomes current.
    let change = finalization_request_under(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
        (initial, operational),
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&change))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(..)));
    let state = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?;
    assert_eq!(state.current_policy_id, operational);
    // Under the new policy the old one is retained but neither current nor
    // its successor: naming it as old is stale, naming it as resulting is
    // a malformed transition.
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 1, 11)?;
    let ack_bytes = ack(conversation, 1, candidate_id, commit_object_id)?;
    ok(harness.run(Op::SubmitCommitAck, &conversation, Some(&ack_bytes))?)?;
    let stale = finalization_request_under(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
        (initial, initial),
    )?;
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&stale))?),
        Some(E2eeReplyCode::EpochStale)
    );
    let regress = finalization_request_under(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
        (operational, initial),
    )?;
    assert_eq!(
        code(harness.run(Op::SubmitFinalization, &conversation, Some(&regress))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    Ok(())
}

#[test]
fn a_reloaded_coordinator_keeps_the_votes_a_slot_had_gathered() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    let first = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&first))?)?;
    assert!(matches!(outcome.result, ResultBody::Pending(..)));
    // A conflicting abort from the first device is discarded live while the
    // second device's abort vote is counted; both requests are retained.
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
    let mut abort_votes = [DEVICE, SECOND_DEVICE]
        .iter()
        .map(|device| {
            vote(
                &harness,
                *device,
                &receipt,
                candidate_id,
                Terminal::abort(abort_id, 1)?,
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    abort_votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
    let both = wire(
        IrcWireObjectKind::AbortRequest,
        &IrcAbortRequest {
            core: core.clone(),
            receipt: receipt.clone(),
            votes: TlsVec::new(abort_votes)?,
        },
    )?;
    let outcome = ok(harness.run(Op::SubmitAbort, &conversation, Some(&both))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Abort, _)
    ));
    let standing = |harness: &Harness| -> TestResult<Vec<(u8, IrcDisposition)>> {
        let ledger = harness
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .and_then(|state| state.vote_ledgers.get(&candidate_id))
            .ok_or("the ledger")?;
        Ok(ledger
            .votes()
            .map(|((_, device), terminal)| (device[0], terminal.disposition))
            .collect())
    };
    let expected = vec![
        (DEVICE, IrcDisposition::Finalize),
        (SECOND_DEVICE, IrcDisposition::Abort),
    ];
    assert_eq!(standing(&harness)?, expected);
    // The reload restores each principal's decision from its durable vote
    // row, whatever order the retained requests are read back in.
    let mut reloaded = harness.reloaded()?;
    assert_eq!(standing(&reloaded)?, expected);
    // The second device's FINALIZE vote is now the conflicting one, so the
    // finalization stays one short; its earlier abort vote still stands.
    let crossed = finalization_request(
        &reloaded,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[SECOND_DEVICE],
    )?;
    let outcome = ok(reloaded.run(Op::SubmitFinalization, &conversation, Some(&crossed))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Finalization, _)
    ));
    assert_eq!(standing(&reloaded)?, expected);
    Ok(())
}

#[test]
fn a_reloaded_coordinator_completes_a_quorum_it_had_begun() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_object_id, candidate_id) =
        submit_candidate(&mut harness, conversation, 0, 10)?;
    let ack_bytes = acknowledge(&mut harness, conversation, candidate_id, commit_object_id)?;
    let first = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[DEVICE],
    )?;
    let outcome = ok(harness.run(Op::SubmitFinalization, &conversation, Some(&first))?)?;
    assert!(matches!(outcome.result, ResultBody::Pending(..)));
    let mut reloaded = harness.reloaded()?;
    let ledger = reloaded
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .and_then(|state| state.vote_ledgers.get(&candidate_id))
        .ok_or("the replayed ledger")?;
    assert_eq!(ledger.votes().count(), 1);
    // The first device's ABORT vote after the reload is still a sign-once
    // conflict, and the second device's FINALIZE vote alone completes the
    // quorum the first request began.
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
    let abort = wire(
        IrcWireObjectKind::AbortRequest,
        &IrcAbortRequest {
            core,
            receipt: receipt.clone(),
            votes: TlsVec::new(vec![vote(
                &reloaded,
                DEVICE,
                &receipt,
                candidate_id,
                Terminal::abort(abort_id, 1)?,
            )?])?,
        },
    )?;
    let outcome = ok(reloaded.run(Op::SubmitAbort, &conversation, Some(&abort))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Abort, _)
    ));
    let second = finalization_request(
        &reloaded,
        conversation,
        &receipt,
        commit_object_id,
        candidate_id,
        &ack_bytes,
        &[SECOND_DEVICE],
    )?;
    let outcome = ok(reloaded.run(Op::SubmitFinalization, &conversation, Some(&second))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(..)));
    let ResultBody::Finalized(_, _, finalization_id, _) = outcome.result else {
        return Err("expected finalization".into());
    };
    let expected = [DEVICE, SECOND_DEVICE]
        .into_iter()
        .map(|device| {
            vote(
                &reloaded,
                device,
                &receipt,
                candidate_id,
                Terminal::finalize(finalization_id),
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_certificate_votes(&reloaded, &outcome.result, expected)?;
    Ok(())
}

pub(super) fn fresh_fetch_fixture() -> TestResult<super::FreshFetchFixture> {
    recovery_pending::fresh_fetch_fixture()
}

#[test]
fn a_bootstrap_activation_needs_the_resulting_council_too() -> TestResult {
    // The bootstrap council is the first device alone; the operational
    // council the activation installs holds both devices with fault bound
    // zero, so the activation needs the old council's vote and both of the
    // resulting council's (companion 9.5).
    let mut harness = Harness::with_councils(
        &[DEVICE, SECOND_DEVICE],
        &[DEVICE],
        &[DEVICE, SECOND_DEVICE],
    )?;
    let conversation = harness.bind_channel()?;
    let opened =
        recovery_pending::close_authorization::open_finalization(&mut harness, conversation, 0)?;
    let (old_council_only, _) = recovery_pending::close_authorization::finalization_bytes(
        &harness,
        &opened,
        None,
        &[DEVICE],
    )?;
    let outcome = ok(harness.run(
        Op::SubmitFinalization,
        &conversation,
        Some(&old_council_only),
    )?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Pending(_, PendingKind::Finalization, _)
    ));
    // The second device sits on the resulting council alone; its vote is
    // counted there and completes both quorums.
    let (resulting_member, terminal) = recovery_pending::close_authorization::finalization_bytes(
        &harness,
        &opened,
        None,
        &[SECOND_DEVICE],
    )?;
    let outcome = ok(harness.run(
        Op::SubmitFinalization,
        &conversation,
        Some(&resulting_member),
    )?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal));
    Ok(())
}
