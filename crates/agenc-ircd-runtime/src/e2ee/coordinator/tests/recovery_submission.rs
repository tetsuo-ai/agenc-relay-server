#![forbid(unsafe_code)]

//! Companion 13.7.4: a restored `pending` route adopts previously signed
//! evidence through signed recovery submissions and installs permanent
//! `closed` or `conflict` in one durable transaction, with every refusal
//! leaving the gate, head and submission set unchanged.

use super::super::{ack, finalization_request_under, submit_candidate, vote};
use super::*;
use crate::e2ee::coordinator::recovery_lineage::{references_at, resume};
use crate::e2ee::coordinator::tests::support::{account_field, commit_approval, key, sign};
use crate::e2ee::coordinator::tests::{DEVICE_ID, NOW, account_bytes, origin_key};
use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_ircd_domain::e2ee::RouteLifecycle;
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::limits::{MAX_OPEN_RECOVERY_SUBMISSIONS, MAX_RECOVERY_SUBMISSION_SECONDS};
use agenc_ircd_e2ee::object::IrcWireObjectKind;
use agenc_ircd_e2ee::objects::conversation::{
    IrcCloseAuthorization, IrcCloseAuthorizationTbs, IrcCloseIntent,
};
use agenc_ircd_e2ee::objects::recovery::{
    IrcRecoveryElementKind, IrcRecoverySubmission, IrcRecoverySubmissionTbs,
};
use agenc_ircd_e2ee::tls::TlsVec;
use agenc_ircd_storage::E2eeRecoveryKind;

/// `close_authorization::finish` at an explicit validation time.
fn finish_at(
    source: &mut Harness,
    conversation: [u8; 32],
    epoch: u64,
    closing: Option<[u8; 32]>,
    validation_time: u64,
) -> TestResult<[u8; 32]> {
    use crate::e2ee::coordinator::tests::support::commit_authorization;
    use agenc_ircd_e2ee::objects::conversation::{IrcCommitAuthorizationRule, action_bits};
    use agenc_ircd_e2ee::objects::sequencing::IrcFinalizationRequest;
    use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
    let state = source
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    let old_policy = state.current_policy_id;
    let resulting_policy = if epoch == 0 {
        state.required_operational_policy_id
    } else {
        old_policy
    };
    let (receipt, object, candidate) =
        submit_candidate(source, conversation, epoch, validation_time)?;
    let ack_bytes = ack(conversation, epoch, candidate, object)?;
    ok(source.run(Op::SubmitCommitAck, &conversation, Some(&ack_bytes))?)?;
    let bytes = finalization_request_under(
        source,
        conversation,
        &receipt,
        object,
        candidate,
        &ack_bytes,
        &[DEVICE],
        (old_policy, resulting_policy),
    )?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object = agenc_ircd_e2ee::object::IrcWireObject::decode_kind(
        &bytes,
        Some(IrcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    let mut request = IrcFinalizationRequest::decode_exact(object.body(), &mut budget)?;
    let core = &request.proof.core;
    let mut authorization = request.proof.authorization.tbs.clone();
    authorization.prior_epoch = core.prior_epoch;
    authorization.prior_state_id = core.prior_state_id;
    authorization.candidate_id = core.candidate_id;
    authorization.commit_object_id = core.commit_object_id;
    authorization.canonical_validation_time = validation_time;
    authorization.resulting_group_context_digest = core.resulting_group_context_digest;
    authorization.resulting_ratchet_tree_digest = core.resulting_ratchet_tree_digest;
    if epoch == 0 {
        authorization.authorization_rule = IrcCommitAuthorizationRule::BootstrapActivation;
        authorization.action_bits = action_bits::POLICY | action_bits::BOOTSTRAP;
    } else if let Some(intent) = closing {
        authorization.authorization_rule = IrcCommitAuthorizationRule::ControlledTransition;
        authorization.action_bits = action_bits::CLOSE_INTENT;
        authorization.transition_target_digest = intent;
    }
    request.proof.authorization =
        commit_authorization(authorization, &[(&source.principal, DEVICE)])?;
    request.proof.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &request.proof.authorization.tbs,
    )?;
    let terminal = semantic_id_of(SemanticHashDomain::FinalizationId, &request.proof.core)?;
    // Every device votes: the bootstrap activation needs the resulting
    // council's quorum as well as the old council's.
    let mut votes = source
        .devices
        .clone()
        .into_iter()
        .map(|device| {
            vote(
                source,
                device,
                &receipt,
                candidate,
                Terminal::finalize(terminal),
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
    request.votes = TlsVec::new(votes)?;
    let bytes = wire(IrcWireObjectKind::FinalizationRequest, &request)?;
    let outcome = ok(source.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(_, _, id, _) if id == terminal));
    Ok(terminal)
}

/// One way of tampering with a submission body.
type Mutation = Box<dyn Fn(&mut IrcRecoverySubmissionTbs)>;

/// A conversation whose complete lineage is known: the rows before any
/// record, every record in order, the close, and the objects records name.
struct Source {
    harness: Harness,
    conversation: [u8; 32],
    snapshot: Vec<Write>,
    after_activation: Vec<Write>,
    closing: Vec<Write>,
    records: Vec<(u64, Vec<u8>)>,
    close: Vec<u8>,
    close_id: [u8; 32],
    policy: Vec<u8>,
}

fn clone_writes(writes: &[Write]) -> TestResult<Vec<Write>> {
    writes
        .iter()
        .map(|write| match write {
            Write::Put {
                table,
                key,
                plaintext,
            } => Ok(Write::put(*table, key.clone(), plaintext.to_vec())?),
            Write::Delete { table, key } => Ok(Write::delete(*table, key.clone())?),
        })
        .collect()
}

fn records_of(harness: &Harness, conversation: &[u8; 32]) -> TestResult<Vec<(u64, Vec<u8>)>> {
    let state = harness
        .coordinator
        .state
        .conversations
        .get(conversation)
        .ok_or("conversation")?;
    state
        .records
        .iter()
        .map(|(sequence, id)| {
            Ok((
                *sequence,
                harness
                    .coordinator
                    .state
                    .objects
                    .get(id)
                    .ok_or("record object")?
                    .clone(),
            ))
        })
        .collect()
}

fn source() -> TestResult<Source> {
    source_with(&[DEVICE])
}

/// A source whose principal holds `devices`, with the durable writes
/// captured at the genesis, after the bootstrap activation and after the
/// closing finalization.
fn source_with(devices: &[u8]) -> TestResult<Source> {
    let mut harness = Harness::with_devices(devices)?;
    let conversation = harness.bind_channel()?;
    let snapshot = clone_writes(&harness.writes)?;
    // Validation times inside every retained roster window, as the
    // historical chain requires of adopted evidence.
    let intent = IrcCloseIntent {
        reason_code: 1,
        validation_time: 170,
    };
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?;
    finish_at(&mut harness, conversation, 0, None, 150)?;
    let after_activation = clone_writes(&harness.writes)?;
    let terminal = finish_at(&mut harness, conversation, 1, Some(intent_id), 160)?;
    let closing = clone_writes(&harness.writes)?;
    let binding = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?
        .binding;
    let tbs = IrcCloseAuthorizationTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        binding_id: binding,
        authorizing_terminal_id: terminal,
        close_intent: intent,
        close_intent_id: intent_id,
    };
    let close = IrcCloseAuthorization {
        approvals: TlsVec::new(vec![commit_approval(
            &harness.principal,
            DEVICE,
            &tbs,
            SignatureDomain::CloseAuthorization,
        )?])?,
        tbs,
    };
    let close_bytes = wire(IrcWireObjectKind::CloseAuthorization, &close)?;
    let records = records_of(&harness, &conversation)?;
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&1_u16.to_be_bytes());
    let outcome = ok(harness.run(Op::CloseGroup, &parameters, Some(&close_bytes))?)?;
    let ResultBody::Closed { close_id, .. } = outcome.result else {
        return Err("the source closes".into());
    };
    let policy = wire(IrcWireObjectKind::Policy, &harness.operational_policy)?;
    Ok(Source {
        harness,
        conversation,
        snapshot,
        after_activation,
        closing,
        records,
        close: close_bytes,
        close_id,
        policy,
    })
}

/// A coordinator restored from `writes` with the source's attached device.
fn restored_from(source: &Source, writes: &[Write], pending: bool) -> TestResult<Harness> {
    let mut staged = Harness::with_devices(&source.harness.devices)?;
    staged.writes = clone_writes(writes)?;
    staged.sequence = source.harness.sequence;
    let mut restored = if pending {
        restored_pending(&mut staged, source.conversation)?
    } else {
        staged.reloaded()?
    };
    attach(&mut restored, source);
    Ok(restored)
}

fn attach(harness: &mut Harness, source: &Source) {
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key()) {
        origin.device = source.harness.device();
    }
}

fn pending_from(source: &Source) -> TestResult<Harness> {
    restored_from(source, &source.snapshot, true)
}

/// The next chain position of the pending route.
fn next_position(pending: &Harness, conversation: &[u8; 32]) -> TestResult<(u64, [u8; 32])> {
    let lineage = resume(&pending.coordinator, conversation)
        .map_err(|code| format!("resume refused with {code:?}"))?;
    let position = lineage.chain.next_position()?;
    Ok((position.route_sequence, position.predecessor_record_id))
}

/// The head position of the pending route.
fn head_position(pending: &Harness, conversation: &[u8; 32]) -> TestResult<(u64, [u8; 32])> {
    let lineage = resume(&pending.coordinator, conversation)
        .map_err(|code| format!("resume refused with {code:?}"))?;
    let head = lineage.chain.head();
    Ok((
        head.sequence.ok_or("recorded head")?,
        head.predecessor_record_id,
    ))
}

struct Spec {
    route_sequence: u64,
    predecessor: [u8; 32],
    kind: IrcRecoveryElementKind,
    object_kind: IrcWireObjectKind,
    element_object_id: [u8; 32],
}

fn tbs_for(
    pending: &Harness,
    conversation: [u8; 32],
    spec: &Spec,
) -> TestResult<IrcRecoverySubmissionTbs> {
    let gate = pending
        .coordinator
        .state
        .recovery_gates
        .get(&conversation)
        .ok_or("gate")?;
    Ok(IrcRecoverySubmissionTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        recovery_epoch: *gate.recovery_epoch().as_bytes(),
        restored_binding_id: *gate.restored_binding_id().as_bytes(),
        restored_accepted_state_id: *gate.restored_accepted_state_id().as_bytes(),
        restored_sequencer_head_id: *gate.restored_sequencer_head_id().as_bytes(),
        source_rollback_guard_hash: *gate.source_rollback_guard_hash().as_bytes(),
        route_sequence: spec.route_sequence,
        predecessor_record_id: spec.predecessor,
        element_kind: spec.kind,
        element_object_kind: spec.object_kind,
        element_object_id: spec.element_object_id,
        account_id: account_field(&pending.account)?,
        device_id: DEVICE_ID,
    })
}

fn signed(tbs: IrcRecoverySubmissionTbs) -> TestResult<(Vec<u8>, [u8; 32])> {
    let submission_id = semantic_id_of(SemanticHashDomain::RecoverySubmissionId, &tbs)?;
    let device_signature = sign(&key(DEVICE), SignatureDomain::RecoverySubmission, &tbs)?;
    let bytes = wire(
        IrcWireObjectKind::RecoverySubmission,
        &IrcRecoverySubmission {
            tbs,
            device_signature,
        },
    )?;
    Ok((bytes, submission_id))
}

/// Submits `bytes` as an element of `kind` for the next position.
fn accept(
    pending: &mut Harness,
    conversation: [u8; 32],
    kind: IrcRecoveryElementKind,
    object_kind: IrcWireObjectKind,
    bytes: &[u8],
) -> TestResult<[u8; 32]> {
    let (route_sequence, predecessor) = next_position(pending, &conversation)?;
    accept_at(
        pending,
        conversation,
        route_sequence,
        predecessor,
        kind,
        object_kind,
        bytes,
    )
}

fn accept_at(
    pending: &mut Harness,
    conversation: [u8; 32],
    route_sequence: u64,
    predecessor: [u8; 32],
    kind: IrcRecoveryElementKind,
    object_kind: IrcWireObjectKind,
    bytes: &[u8],
) -> TestResult<[u8; 32]> {
    let spec = Spec {
        route_sequence,
        predecessor,
        kind,
        object_kind,
        element_object_id: object_id(bytes),
    };
    let (submission, submission_id) = signed(tbs_for(pending, conversation, &spec)?)?;
    let outcome = ok(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::RecoveryAccepted(conversation, submission_id)
    );
    Ok(submission_id)
}

fn element(
    pending: &mut Harness,
    conversation: [u8; 32],
    submission_id: [u8; 32],
    bytes: &[u8],
) -> TestResult<Result<Outcome, Fail>> {
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&submission_id);
    pending.run(Op::SubmitRecoveryElement, &parameters, Some(bytes))
}

fn deliver(
    pending: &mut Harness,
    conversation: [u8; 32],
    kind: IrcRecoveryElementKind,
    object_kind: IrcWireObjectKind,
    bytes: &[u8],
) -> TestResult<ResultBody> {
    let submission_id = accept(pending, conversation, kind, object_kind, bytes)?;
    Ok(ok(element(pending, conversation, submission_id, bytes)?)?.result)
}

/// Uploads every record of the source in order, with the bootstrap
/// activation's policy reference first, and returns the last reply.
fn replay_records(
    pending: &mut Harness,
    source: &Source,
    from: usize,
) -> TestResult<Vec<[u8; 32]>> {
    let conversation = source.conversation;
    let mut ids = Vec::new();
    for (sequence, bytes) in source.records.iter().skip(from) {
        if *sequence == 1 {
            let reply = deliver(
                pending,
                conversation,
                IrcRecoveryElementKind::ReferenceElement,
                IrcWireObjectKind::Policy,
                &source.policy,
            )?;
            assert!(matches!(reply, ResultBody::RecoveryExtended(_, 0, _)));
        }
        let reply = deliver(
            pending,
            conversation,
            IrcRecoveryElementKind::RecordElement,
            IrcWireObjectKind::SequencerRecord,
            bytes,
        )?;
        let ResultBody::RecoveryExtended(replied, replied_sequence, record_id) = reply else {
            return Err(format!("record {sequence} was not adopted: {reply:?}").into());
        };
        assert_eq!((replied, replied_sequence), (conversation, *sequence));
        ids.push(record_id);
    }
    Ok(ids)
}

fn gate_state(harness: &Harness, conversation: &[u8; 32]) -> Option<E2eeRecoveryKind> {
    harness
        .coordinator
        .state
        .recovery_gates
        .get(conversation)
        .map(|gate| gate.state())
}

fn assert_pending_unchanged(pending: &Harness, conversation: &[u8; 32]) {
    assert_eq!(
        gate_state(pending, conversation),
        Some(E2eeRecoveryKind::Pending)
    );
    let route = pending
        .coordinator
        .state
        .routes
        .route(&ConversationId(*conversation));
    assert!(route.is_some_and(|route| route.recovery == RecoveryState::Pending));
}

#[test]
fn a_restored_pending_route_adopts_a_preexisting_terminal_chain_and_closes() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    assert_eq!(source.records.len(), 4);
    let mut pending = pending_from(&source)?;
    assert_pending_unchanged(&pending, &conversation);
    let ids = replay_records(&mut pending, &source, 0)?;
    assert_eq!(ids.len(), 4);
    // The head record re-uploaded byte for byte repeats the prior reply.
    let (head_sequence, head_predecessor) = head_position(&pending, &conversation)?;
    let (sequence, last) = source.records.last().ok_or("records")?;
    assert_eq!(head_sequence, *sequence);
    let submission_id = accept_at(
        &mut pending,
        conversation,
        head_sequence,
        head_predecessor,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        last,
    )?;
    let reply = ok(element(&mut pending, conversation, submission_id, last)?)?;
    assert_eq!(
        reply.result,
        ResultBody::RecoveryExtended(
            conversation,
            head_sequence,
            ids.get(3).copied().ok_or("fourth record")?
        )
    );
    assert_pending_unchanged(&pending, &conversation);
    // The finalized close installs closed together with the tombstone.
    let reply = deliver(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::CloseElement,
        IrcWireObjectKind::CloseAuthorization,
        &source.close,
    )?;
    assert_eq!(
        reply,
        ResultBody::RecoveryClosed(conversation, source.close_id)
    );
    assert_eq!(
        gate_state(&pending, &conversation),
        Some(E2eeRecoveryKind::Closed)
    );
    let route = pending
        .coordinator
        .state
        .routes
        .route(&ConversationId(conversation))
        .ok_or("route")?;
    assert_eq!(route.recovery, RecoveryState::Closed);
    assert_eq!(
        route.lifecycle,
        RouteLifecycle::Tombstone {
            close_id: source.close_id
        }
    );
    // Closed is permanent and survives a reopen; nothing else is accepted.
    let mut reopened = pending.reloaded()?;
    attach(&mut reopened, &source);
    assert_eq!(
        gate_state(&reopened, &conversation),
        Some(E2eeRecoveryKind::Closed)
    );
    let route = reopened
        .coordinator
        .state
        .routes
        .route(&ConversationId(conversation))
        .ok_or("route")?;
    assert_eq!(route.recovery, RecoveryState::Closed);
    let spec = Spec {
        route_sequence: 5,
        predecessor: source.close_id,
        kind: IrcRecoveryElementKind::RecordElement,
        object_kind: IrcWireObjectKind::SequencerRecord,
        element_object_id: [7; 32],
    };
    let (submission, _) = signed(tbs_for(&reopened, conversation, &spec)?)?;
    assert_eq!(
        code(reopened.run(Op::SubmitRecovery, &conversation, Some(&submission))?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    Ok(())
}

#[test]
fn a_recovery_continues_after_a_reload_between_chunks() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    let mut pending = pending_from(&source)?;
    replay_records(&mut pending, &source, 0)?;
    // Reload with two records installed: the lineage replays from the rows.
    let mut halfway = pending_from(&source)?;
    let ids = replay_records(&mut halfway, &source, 0)?;
    let _ = ids;
    let mut resumed = Harness::with_devices(&source.harness.devices)?;
    resumed.writes = clone_writes(&halfway.writes)?;
    resumed.sequence = halfway.sequence;
    let mut resumed = resumed.reloaded()?;
    attach(&mut resumed, &source);
    assert_pending_unchanged(&resumed, &conversation);
    let (sequence, _) = next_position(&resumed, &conversation)?;
    assert_eq!(sequence, 4);
    let reply = deliver(
        &mut resumed,
        conversation,
        IrcRecoveryElementKind::CloseElement,
        IrcWireObjectKind::CloseAuthorization,
        &source.close,
    )?;
    assert_eq!(
        reply,
        ResultBody::RecoveryClosed(conversation, source.close_id)
    );
    Ok(())
}

#[test]
fn two_valid_successors_for_one_position_install_a_permanent_conflict() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    // A fork of the source signs a different candidate for position zero.
    let mut fork = restored_from(&source, &source.snapshot, false)?;
    let (_, _, candidate_b) = submit_candidate(&mut fork, conversation, 0, 21)?;
    let forked = records_of(&fork, &conversation)?;
    let (_, record_b) = forked.first().ok_or("forked record")?;
    let (_, record_a) = source.records.first().ok_or("record")?;
    assert_ne!(record_a, record_b);

    let mut pending = pending_from(&source)?;
    let reply = deliver(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        record_a,
    )?;
    let ResultBody::RecoveryExtended(_, 0, candidate_a) = reply else {
        return Err("candidate A extends".into());
    };
    let (head_sequence, head_predecessor) = head_position(&pending, &conversation)?;
    let submission_id = accept_at(
        &mut pending,
        conversation,
        head_sequence,
        head_predecessor,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        record_b,
    )?;
    let reply = ok(element(
        &mut pending,
        conversation,
        submission_id,
        record_b,
    )?)?;
    assert_eq!(
        reply.result,
        ResultBody::RecoveryConflict(conversation, 0, candidate_a, candidate_b)
    );
    assert_eq!(
        gate_state(&pending, &conversation),
        Some(E2eeRecoveryKind::Conflict)
    );
    let route = pending
        .coordinator
        .state
        .routes
        .route(&ConversationId(conversation))
        .ok_or("route")?;
    assert_eq!(route.recovery, RecoveryState::Conflict);
    // Both proofs are retained; nothing further is accepted, before or after a reopen.
    assert!(
        pending
            .coordinator
            .state
            .objects
            .contains_key(&object_id(record_a))
    );
    assert!(
        pending
            .coordinator
            .state
            .objects
            .contains_key(&object_id(record_b))
    );
    let (_, finalization) = source.records.get(1).ok_or("finalization")?;
    let spec = Spec {
        route_sequence: 1,
        predecessor: candidate_a,
        kind: IrcRecoveryElementKind::RecordElement,
        object_kind: IrcWireObjectKind::SequencerRecord,
        element_object_id: object_id(finalization),
    };
    let (submission, _) = signed(tbs_for(&pending, conversation, &spec)?)?;
    assert_eq!(
        code(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    let mut reopened = pending.reloaded()?;
    attach(&mut reopened, &source);
    assert_eq!(
        gate_state(&reopened, &conversation),
        Some(E2eeRecoveryKind::Conflict)
    );
    assert!(
        reopened
            .coordinator
            .state
            .objects
            .contains_key(&object_id(record_b))
    );
    Ok(())
}

#[test]
fn an_invalid_or_incomplete_second_record_installs_nothing() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    let mut pending = pending_from(&source)?;
    let (_, record_a) = source.records.first().ok_or("record")?;
    deliver(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        record_a,
    )?;
    let (head_sequence, head_predecessor) = head_position(&pending, &conversation)?;
    // A record whose bytes changed under the sequencer signature is invalid.
    let mut forged = record_a.clone();
    if let Some(byte) = forged.last_mut() {
        *byte ^= 0x01;
    }
    let submission_id = accept_at(
        &mut pending,
        conversation,
        head_sequence,
        head_predecessor,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        &forged,
    )?;
    assert_eq!(
        code(element(&mut pending, conversation, submission_id, &forged)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    assert_pending_unchanged(&pending, &conversation);
    // The submission stays open; the exact record still completes it as idempotent.
    assert_eq!(
        code(element(
            &mut pending,
            conversation,
            submission_id,
            record_a
        )?),
        Some(E2eeReplyCode::HashMismatch)
    );
    Ok(())
}

#[test]
fn a_submission_is_refused_for_a_wrong_gate_context_device_or_signature() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    let mut pending = pending_from(&source)?;
    let (route_sequence, predecessor) = next_position(&pending, &conversation)?;
    let (_, record) = source.records.first().ok_or("record")?;
    let spec = Spec {
        route_sequence,
        predecessor,
        kind: IrcRecoveryElementKind::RecordElement,
        object_kind: IrcWireObjectKind::SequencerRecord,
        element_object_id: object_id(record),
    };
    let base = tbs_for(&pending, conversation, &spec)?;
    let cases: Vec<(&str, Mutation, E2eeReplyCode)> = vec![
        (
            "epoch",
            Box::new(|tbs| tbs.recovery_epoch = [9; 16]),
            E2eeReplyCode::RouteInvalid,
        ),
        (
            "guard",
            Box::new(|tbs| tbs.source_rollback_guard_hash = [9; 32]),
            E2eeReplyCode::RouteInvalid,
        ),
        (
            "head",
            Box::new(|tbs| tbs.restored_sequencer_head_id = [9; 32]),
            E2eeReplyCode::RouteInvalid,
        ),
        (
            "binding",
            Box::new(|tbs| tbs.restored_binding_id = [9; 32]),
            E2eeReplyCode::RouteInvalid,
        ),
        (
            "position",
            Box::new(|tbs| tbs.route_sequence += 1),
            E2eeReplyCode::RouteInvalid,
        ),
        (
            "predecessor",
            Box::new(|tbs| tbs.predecessor_record_id = [9; 32]),
            E2eeReplyCode::RouteInvalid,
        ),
        (
            "network",
            Box::new(|tbs| tbs.network_id = [9; 32]),
            E2eeReplyCode::RouteInvalid,
        ),
        (
            "device",
            Box::new(|tbs| tbs.device_id = [9; 16]),
            E2eeReplyCode::DeviceRequired,
        ),
        (
            "element kind",
            Box::new(|tbs| tbs.element_object_kind = IrcWireObjectKind::Policy),
            E2eeReplyCode::InvalidFragment,
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut tbs = base.clone();
        mutate(&mut tbs);
        let (submission, _) = signed(tbs)?;
        assert_eq!(
            code(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?),
            Some(expected),
            "{name}"
        );
        assert_pending_unchanged(&pending, &conversation);
    }
    // Another account, even correctly signed by its own device, is not a principal.
    let mut foreign = base.clone();
    foreign.account_id = account_field(&account_bytes(3)?)?;
    let (submission, _) = signed(foreign)?;
    assert_eq!(
        code(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    // A corrupted device signature is refused.
    let (mut submission, _) = signed(base.clone())?;
    if let Some(byte) = submission.last_mut() {
        *byte ^= 0x01;
    }
    assert_eq!(
        code(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    // An element for an unknown submission, with wrong bytes, or of the
    // wrong kind is refused with its own code.
    assert_eq!(
        code(element(&mut pending, conversation, [5; 32], record)?),
        Some(E2eeReplyCode::ObjectNotFound)
    );
    let submission_id = accept(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        record,
    )?;
    let (_, other) = source.records.get(1).ok_or("record")?;
    assert_eq!(
        code(element(&mut pending, conversation, submission_id, other)?),
        Some(E2eeReplyCode::HashMismatch)
    );
    assert_eq!(
        code(element(
            &mut pending,
            conversation,
            submission_id,
            &source.policy
        )?),
        Some(E2eeReplyCode::InvalidFragment)
    );
    // An exact duplicate submission repeats the prior reply without a new row.
    let rows = pending
        .coordinator
        .state
        .recovery
        .submissions
        .get(&conversation)
        .map_or(0, std::collections::BTreeMap::len);
    let (submission, id) = signed(base)?;
    let outcome = ok(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::RecoveryAccepted(conversation, id)
    );
    assert!(outcome.writes.is_empty());
    assert_eq!(
        pending
            .coordinator
            .state
            .recovery
            .submissions
            .get(&conversation)
            .map_or(0, std::collections::BTreeMap::len),
        rows
    );
    assert_pending_unchanged(&pending, &conversation);
    Ok(())
}

#[test]
fn open_submissions_expire_and_are_bounded() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    let mut pending = pending_from(&source)?;
    let (route_sequence, predecessor) = next_position(&pending, &conversation)?;
    let (_, record) = source.records.first().ok_or("record")?;
    let submission_id = accept(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        record,
    )?;
    // Up to the ceiling of distinct open submissions at the position.
    for seed in 1..u8::try_from(MAX_OPEN_RECOVERY_SUBMISSIONS)? {
        let spec = Spec {
            route_sequence,
            predecessor,
            kind: IrcRecoveryElementKind::ReferenceElement,
            object_kind: IrcWireObjectKind::Policy,
            element_object_id: [seed; 32],
        };
        let (submission, _) = signed(tbs_for(&pending, conversation, &spec)?)?;
        ok(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?)?;
    }
    let spec = Spec {
        route_sequence,
        predecessor,
        kind: IrcRecoveryElementKind::ReferenceElement,
        object_kind: IrcWireObjectKind::Policy,
        element_object_id: [99; 32],
    };
    let (submission, _) = signed(tbs_for(&pending, conversation, &spec)?)?;
    assert_eq!(
        code(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?),
        Some(E2eeReplyCode::RateLimited)
    );
    // After the deadline the open submissions are discarded: the element is
    // unknown, the gate and head are unchanged, and new submissions fit.
    pending.now = NOW + MAX_RECOVERY_SUBMISSION_SECONDS + 1;
    assert_eq!(
        code(element(&mut pending, conversation, submission_id, record)?),
        Some(E2eeReplyCode::ObjectNotFound)
    );
    assert_pending_unchanged(&pending, &conversation);
    let outcome = ok(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?)?;
    assert!(matches!(outcome.result, ResultBody::RecoveryAccepted(..)));
    assert_eq!(
        pending
            .coordinator
            .state
            .recovery
            .submissions
            .get(&conversation)
            .map_or(0, std::collections::BTreeMap::len),
        1
    );
    let reply = deliver(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        record,
    )?;
    assert!(matches!(reply, ResultBody::RecoveryExtended(_, 0, _)));
    Ok(())
}

/// Signs `tbs` for `device`, which must be attached on the origin.
fn signed_by(device: u8, tbs: IrcRecoverySubmissionTbs) -> TestResult<(Vec<u8>, [u8; 32])> {
    let submission_id = semantic_id_of(SemanticHashDomain::RecoverySubmissionId, &tbs)?;
    let device_signature = sign(&key(device), SignatureDomain::RecoverySubmission, &tbs)?;
    let bytes = wire(
        IrcWireObjectKind::RecoverySubmission,
        &IrcRecoverySubmission {
            tbs,
            device_signature,
        },
    )?;
    Ok((bytes, submission_id))
}

fn attach_as(harness: &mut Harness, device: u8) -> TestResult {
    let origin = harness
        .coordinator
        .state
        .origins
        .get_mut(&origin_key())
        .ok_or("origin")?;
    let generation = origin.device.map_or(1, |(_, generation)| generation);
    origin.device = Some(([device; 16], generation));
    Ok(())
}

#[test]
fn a_submission_object_of_another_kind_is_refused() -> TestResult {
    let source = source()?;
    let mut pending = pending_from(&source)?;
    assert_eq!(
        code(pending.run(
            Op::SubmitRecovery,
            &source.conversation,
            Some(&source.policy)
        )?),
        Some(E2eeReplyCode::InvalidFragment)
    );
    assert_pending_unchanged(&pending, &source.conversation);
    Ok(())
}

#[test]
fn a_head_record_named_with_another_predecessor_is_refused() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    let mut pending = pending_from(&source)?;
    let (_, first) = source.records.first().ok_or("record")?;
    let reply = deliver(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        first,
    )?;
    assert!(matches!(reply, ResultBody::RecoveryExtended(_, 0, _)));
    let (head, _) = head_position(&pending, &conversation)?;
    let spec = Spec {
        route_sequence: head,
        predecessor: [9; 32],
        kind: IrcRecoveryElementKind::RecordElement,
        object_kind: IrcWireObjectKind::SequencerRecord,
        element_object_id: object_id(first),
    };
    let (submission, _) = signed(tbs_for(&pending, conversation, &spec)?)?;
    assert_eq!(
        code(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    Ok(())
}

#[test]
fn a_second_device_re_uploading_the_head_record_gets_the_prior_reply() -> TestResult {
    let second = super::super::SECOND_DEVICE;
    let source = source_with(&[DEVICE, second])?;
    let conversation = source.conversation;
    let mut pending = pending_from(&source)?;
    let (_, first) = source.records.first().ok_or("record")?;
    let reply = deliver(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        first,
    )?;
    let ResultBody::RecoveryExtended(_, 0, record_id) = reply else {
        return Err(format!("the first record was not adopted: {reply:?}").into());
    };
    // The other device names the head position with the same bytes: its
    // own submission is accepted and the element repeats the extension.
    attach_as(&mut pending, second)?;
    let (head, predecessor) = head_position(&pending, &conversation)?;
    let mut tbs = tbs_for(
        &pending,
        conversation,
        &Spec {
            route_sequence: head,
            predecessor,
            kind: IrcRecoveryElementKind::RecordElement,
            object_kind: IrcWireObjectKind::SequencerRecord,
            element_object_id: object_id(first),
        },
    )?;
    tbs.device_id = [second; 16];
    let (submission, submission_id) = signed_by(second, tbs)?;
    let outcome = ok(pending.run(Op::SubmitRecovery, &conversation, Some(&submission))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::RecoveryAccepted(conversation, submission_id)
    );
    let outcome = ok(element(&mut pending, conversation, submission_id, first)?)?;
    assert_eq!(
        outcome.result,
        ResultBody::RecoveryExtended(conversation, 0, record_id)
    );
    Ok(())
}

fn has_no_policy(references: &crate::e2ee::coordinator::recovery_lineage::References) -> bool {
    let (roots, rosters) = references.heads();
    references
        .record_references(&roots, &rosters)
        .policy_object
        .is_none()
}

#[test]
fn references_come_only_from_retained_reference_objects_at_the_position() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    let mut pending = pending_from(&source)?;
    assert!(has_no_policy(&references_at(
        &pending.coordinator.state,
        &[9; 32],
        1
    )));
    let row = agenc_ircd_storage::e2ee_records::RecoverySubmissionRow {
        account_id: pending.account,
        device_id: DEVICE_ID,
        element_kind: 1,
        element_object_kind: IrcWireObjectKind::Policy.value(),
        element_object_id: [4; 32],
        route_sequence: 1,
        predecessor_record_id: [5; 32],
        accepted_at: 6,
        submission_object_id: [7; 32],
        element_retained: true,
        outcome: agenc_ircd_storage::e2ee_records::RecoveryOutcome::Referenced,
    };
    pending
        .coordinator
        .state
        .recovery
        .insert_submission(conversation, [8; 32], row);
    // The row names an object the state does not retain.
    assert!(has_no_policy(&references_at(
        &pending.coordinator.state,
        &conversation,
        1
    )));
    pending
        .coordinator
        .state
        .recovery
        .remove_submission(&[9; 32], &[8; 32]);
    pending
        .coordinator
        .state
        .recovery
        .remove_submission(&conversation, &[8; 32]);
    assert_eq!(
        pending
            .coordinator
            .state
            .recovery
            .open_count(&conversation, NOW),
        0
    );
    Ok(())
}

#[test]
fn a_route_restored_at_a_recorded_head_resumes_from_that_record() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    let mut pending = restored_from(&source, &source.after_activation, true)?;
    let (route_sequence, _) = next_position(&pending, &conversation)?;
    assert_eq!(route_sequence, 2);
    replay_records(&mut pending, &source, 2)?;
    let reply = deliver(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::CloseElement,
        IrcWireObjectKind::CloseAuthorization,
        &source.close,
    )?;
    assert_eq!(
        reply,
        ResultBody::RecoveryClosed(conversation, source.close_id)
    );
    assert_eq!(
        gate_state(&pending, &conversation),
        Some(E2eeRecoveryKind::Closed)
    );
    Ok(())
}

#[test]
fn a_route_restored_while_closing_resumes_with_its_close_intent() -> TestResult {
    let source = source()?;
    let conversation = source.conversation;
    let mut pending = restored_from(&source, &source.closing, true)?;
    let (route_sequence, _) = next_position(&pending, &conversation)?;
    assert_eq!(route_sequence, 4);
    let reply = deliver(
        &mut pending,
        conversation,
        IrcRecoveryElementKind::CloseElement,
        IrcWireObjectKind::CloseAuthorization,
        &source.close,
    )?;
    assert_eq!(
        reply,
        ResultBody::RecoveryClosed(conversation, source.close_id)
    );
    Ok(())
}

#[test]
fn a_recovery_element_is_accepted_only_from_the_device_that_submitted_it() -> TestResult {
    let source = source_with(&[DEVICE, super::super::SECOND_DEVICE])?;
    let conversation = source.conversation;
    let mut pending = pending_from(&source)?;
    let (route_sequence, predecessor) = next_position(&pending, &conversation)?;
    let (_, first) = source.records.first().ok_or("records")?;
    let submission_id = accept_at(
        &mut pending,
        conversation,
        route_sequence,
        predecessor,
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        first,
    )?;
    let submitter = pending.device().ok_or("attached device")?;
    if let Some(origin) = pending.coordinator.state.origins.get_mut(&origin_key()) {
        origin.device = Some(([super::super::SECOND_DEVICE; 16], submitter.1));
    }
    assert_eq!(
        code(element(&mut pending, conversation, submission_id, first)?),
        Some(E2eeReplyCode::DeviceRequired)
    );
    assert_pending_unchanged(&pending, &conversation);
    if let Some(origin) = pending.coordinator.state.origins.get_mut(&origin_key()) {
        origin.device = Some(submitter);
    }
    assert!(matches!(
        ok(element(&mut pending, conversation, submission_id, first)?)?.result,
        ResultBody::RecoveryExtended(..)
    ));
    Ok(())
}
