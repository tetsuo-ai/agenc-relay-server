#![forbid(unsafe_code)]

//! Sequencing tests: one bound channel carries a Commit candidate through
//! authorization, acknowledgement, finalization, and abort, and the
//! retained records page back out.

use agenc_ircd_crypto::SemanticHashDomain;
use agenc_ircd_domain::e2ee::projection::{EmptyKind, EventKind, PendingKind, StoreKind};
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::object::IrcWireObjectKind;
use agenc_ircd_e2ee::objects::aad::IrcCommitAad;
use agenc_ircd_e2ee::objects::conversation::IrcCommitAuthorizationRule;
use agenc_ircd_e2ee::objects::federation::IrcFederationOpcode as Op;
use agenc_ircd_e2ee::objects::sequencing::{
    IrcAbortCoreTbs, IrcAbortRequest, IrcCandidateReceipt, IrcCommitAbortReason, IrcCommitAck,
    IrcCommitAckTbs, IrcDisposition, IrcDispositionVoteTbs, IrcFinalizationCoreTbs,
    IrcFinalizationProof, IrcFinalizationRequest,
};
use agenc_ircd_e2ee::route::channel_route_binding;
use agenc_ircd_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, TlsVec};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

use super::support::{
    approval_envelope, authorization_tbs, commit_authorization, finality_vote,
    private_message_at_epoch,
};
use super::{
    DEVICE, GROUP, Harness, INSTANCE, NETWORK, ResultBody, TestResult, code, object_id, ok, wire,
    wire_raw,
};

const COMMIT_CONTENT_TYPE: u8 = 3;

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
        old_leaf_signature: Opaque::new(vec![5; 64])?,
    };
    wire(IrcWireObjectKind::CommitAck, &ack)
}

fn vote(
    harness: &Harness,
    conversation: [u8; 32],
    candidate_id: [u8; 32],
    disposition: IrcDisposition,
) -> TestResult<agenc_ircd_e2ee::objects::sequencing::IrcFinalityVote> {
    let tbs = IrcDispositionVoteTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_epoch: 0,
        prior_state_id: [0; 32],
        candidate_sequence: 0,
        slot_predecessor_record_id: [0; 32],
        candidate_id,
        disposition,
        terminal_id: [0; 32],
        reason_code: 0,
    };
    Ok(finality_vote(&harness.principal, DEVICE, &tbs)?)
}

fn finalization_request(
    harness: &Harness,
    conversation: [u8; 32],
    receipt: &IrcCandidateReceipt,
    commit_object_id: [u8; 32],
    candidate_id: [u8; 32],
    ack_bytes: &[u8],
    with_vote: bool,
) -> TestResult<Vec<u8>> {
    let log = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("the sequencer log")?;
    let core = IrcFinalizationCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_epoch: receipt.tbs.prior_epoch,
        prior_state_id: *log.accepted_state_id(),
        candidate_id,
        commit_object_id,
        resulting_epoch: receipt.tbs.resulting_epoch,
        old_policy_id: [0; 32],
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
    let authorization = commit_authorization(
        authorization_tbs(
            conversation,
            [0; 32],
            IrcCommitAuthorizationRule::RoutineSelfUpdate,
            0,
        ),
        &[(&harness.principal, DEVICE)],
    )?;
    let votes = if with_vote {
        vec![vote(
            harness,
            conversation,
            candidate_id,
            IrcDisposition::Finalize,
        )?]
    } else {
        Vec::new()
    };
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
        false,
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
        true,
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
    let abort_vote = vote(&harness, conversation, candidate_id, IrcDisposition::Abort)?;
    let abort =
        |votes: Vec<agenc_ircd_e2ee::objects::sequencing::IrcFinalityVote>| -> TestResult<Vec<u8>> {
            wire(
                IrcWireObjectKind::AbortRequest,
                &IrcAbortRequest {
                    core: IrcAbortCoreTbs {
                        profile_version: 1,
                        network_id: NETWORK,
                        conversation_id: conversation,
                        prior_state_id,
                        candidate_id,
                        prior_epoch: 1,
                        reason: IrcCommitAbortReason::SenderWithdrawn,
                        evidence_digest: [0; 32],
                    },
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
    use agenc_ircd_e2ee::objects::sequencing::{IrcDisposition, IrcSequencerRecord};
    use agenc_ircd_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsVec};
    use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

    use super::super::support::{commit_approval, root_fingerprint};
    use super::super::{
        DEVICE, DEVICE_ID, Harness, NETWORK, ResultBody, TestResult, code, ok, wire,
    };
    use super::vote;

    const NEW_CONVERSATION: [u8; 32] = [77; 32];

    fn attempt(
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
            SignatureDomain::CommitAuthorization,
        )?;
        let attempt = IrcReInitAttempt {
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
        let bytes = wire(IrcWireObjectKind::ReinitAttempt, &attempt)?;
        Ok((attempt, bytes))
    }

    fn staged_receipt(
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

    fn ack(
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
            old_leaf_signature: Opaque::new(vec![17; 64])?,
        };
        let bytes = wire(IrcWireObjectKind::ReinitAck, &ack)?;
        Ok((ack, bytes))
    }

    #[test]
    fn a_reinit_attempt_is_staged_acknowledged_aborted_and_finally_activated() -> TestResult {
        let mut harness = Harness::new()?;
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

        // Abort: a proof without votes is pending; a vote aborts the attempt.
        let receipt = staged_receipt(&harness, conversation)?;
        let (attempt_object, _) = attempt(&harness, conversation, old_state, 0)?;
        let abort = |votes| -> TestResult<Vec<u8>> {
            wire(
                IrcWireObjectKind::ReinitAbortRequest,
                &IrcReInitAbortRequest {
                    core: IrcReInitAbortCoreTbs {
                        profile_version: 1,
                        network_id: NETWORK,
                        old_conversation_id: conversation,
                        old_reinit_state_id: old_state,
                        attempt_sequence: 0,
                        slot_predecessor_record_id: [0; 32],
                        reinit_attempt_id: attempt_id,
                        reason_code: 1,
                        evidence_digest: [0; 32],
                    },
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
        let abort_vote = vote(&harness, conversation, attempt_id, IrcDisposition::Abort)?;
        let outcome = ok(harness.run(
            Op::SubmitReinitAbort,
            &conversation,
            Some(&abort(vec![abort_vote])?),
        )?)?;
        assert!(
            matches!(outcome.result, ResultBody::ReinitAborted(named, aborted, ..) if named == conversation && aborted == attempt_id)
        );
        assert!(
            outcome
                .events
                .iter()
                .all(|event| event.planned.kind == EventKind::ReinitAborted)
        );

        // The next attempt activates the successor conversation.
        let (attempt_object, second) = attempt(&harness, conversation, old_state, 1)?;
        let outcome = ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&second))?)?;
        let ResultBody::ReinitStaged(_, attempt_id, _) = outcome.result else {
            return Err("expected a staged attempt".into());
        };
        let receipt = staged_receipt(&harness, conversation)?;
        let (ack_object_again, _) = ack(conversation, old_state, attempt_id)?;
        let activate = |votes| -> TestResult<Vec<u8>> {
            wire(
                IrcWireObjectKind::ReinitActivationRequest,
                &IrcReInitActivationRequest {
                    core: IrcReInitActivationCoreTbs {
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
                        acknowledgement_set_digest: [0; 32],
                    },
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
        let activate_vote = vote(&harness, conversation, attempt_id, IrcDisposition::Finalize)?;
        let outcome = ok(harness.run(
            Op::SubmitReinitActivate,
            &conversation,
            Some(&activate(vec![activate_vote])?),
        )?)?;
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
        let _ = ack_object;
        Ok(())
    }
}
