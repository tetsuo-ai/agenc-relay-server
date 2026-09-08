//! Sequencing operations: candidates, approvals, ACKs, finalization and
//! abort, ReInit attempts and terminals, and the retained-record fetches
//! (companion Sections 12.1 to 12.4, 13.8).
//!
//! The sequencer certifies a finalization, abort, or ReInit terminal only
//! after it has verified at least the old policy's quorum `q` of distinct
//! council votes under the published policy (companion 12.4 and 13.8); a
//! request below `q` is retained and answered `PENDING`. Endpoints still
//! verify the quorum themselves before applying a state.

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_ircd_domain::e2ee::limits::MAX_BATCH_OBJECTS;
use agenc_ircd_domain::e2ee::projection::{EmptyKind, EventKind, PendingKind, StoreKind};
use agenc_ircd_domain::e2ee::sequencer_log::{CandidateSlot, SequencerLog};
use agenc_ircd_e2ee::E2eeError;
use agenc_ircd_e2ee::envelope::verify_commit_object;
use agenc_ircd_e2ee::finality::{
    QuorumLedger, ReinitVoteSlot, Terminal, VoteSlot, reinit_vote_tbs, vote_tbs,
};
use agenc_ircd_e2ee::limits::{
    MAX_ABORT_OBJECT, MAX_COMMIT_ACK_OBJECT, MAX_COMMIT_APPROVAL_OBJECT, MAX_FINALIZATION_OBJECT,
    MAX_LIVE_OBJECT, MAX_REINIT_ACK_OBJECT, MAX_REINIT_OBJECT,
};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::IrcCommitApprovalEnvelope;
use agenc_ircd_e2ee::objects::reinit::{
    IrcReInitAbortCertificate, IrcReInitAbortRequest, IrcReInitAbortTbs, IrcReInitAck,
    IrcReInitActivationCertificate, IrcReInitActivationRequest, IrcReInitActivationTbs,
    IrcReInitAttempt, IrcReInitAttemptReceipt, IrcReInitAttemptReceiptTbs,
};
use agenc_ircd_e2ee::objects::sequencing::{
    IrcAbortRequest, IrcCandidateReceipt, IrcCandidateReceiptTbs, IrcCommitAbortCertificate,
    IrcCommitAbortTbs, IrcCommitAck, IrcCommitFinalizationCertificate, IrcCommitFinalizationTbs,
    IrcFinalityVote, IrcFinalizationRequest, IrcSequencerRecord,
};
use agenc_ircd_e2ee::policy::VerifiedPolicy;
use agenc_ircd_e2ee::route::PrincipalRosters;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode, TlsEncode, TlsVec};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{
    CandidateState, ProofRole, SEQUENCER_ROW_KIND, SequencerRow,
};

use super::super::request::{Outcome, ResponseObject, ResultBody, state_row};
use super::super::{CompanionCoordinator, ConversationState};
use super::route::audience;
use super::{Exec, Fail, cursor};

fn log<'a>(exec: &Exec<'a>, conversation_id: &[u8; 32]) -> Result<&'a SequencerLog, Fail> {
    exec.coordinator
        .state
        .logs
        .get(conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, conversation_id))
}

fn wire(kind: IrcWireObjectKind, body: Vec<u8>) -> Result<Vec<u8>, Fail> {
    IrcWireObject::new(kind, body)
        .and_then(|object| object.encode())
        .map_err(|_| Fail::from(E2eeReplyCode::ObjectTooLarge))
}

pub(super) fn record_bytes(record: &IrcSequencerRecord) -> Result<Vec<u8>, Fail> {
    let body = record
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    wire(IrcWireObjectKind::SequencerRecord, body)
}

fn decode<T: TlsDecode>(bytes: &[u8], limit: usize) -> Result<T, Fail> {
    let mut budget = DecodeBudget::new(limit, 1 << 18);
    T::decode_exact(bytes, &mut budget).map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))
}

fn sequencer_row(
    conversation_id: &[u8; 32],
    route_sequence: u64,
    row: &SequencerRow,
) -> Result<crate::state_core::durable::AccountServiceDurableWrite, Fail> {
    state_row(
        TableId::E2eeState,
        SEQUENCER_ROW_KIND,
        SequencerRow::record_key(conversation_id, route_sequence)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        row.encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )
    .map_err(Fail::from)
}

fn ids(values: &[&[u8]]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.iter().copied())
        .collect()
}

fn conversation<'a>(
    exec: &Exec<'a>,
    conversation_id: &[u8; 32],
) -> Result<&'a ConversationState, Fail> {
    exec.coordinator
        .state
        .conversations
        .get(conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, conversation_id))
}

/// The council of a terminal request: the retained policy `policy_id`,
/// which must be the conversation's current policy, with the rosters of
/// the binding's principals. An unretained policy is `E2EE_POLICY_REQUIRED`
/// and a retained policy that is not current is `E2EE_EPOCH_STALE`.
fn council(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    policy_id: &[u8; 32],
) -> Result<(VerifiedPolicy, PrincipalRosters), Fail> {
    let state = conversation(exec, conversation_id)?;
    let retained = state
        .policies
        .get(policy_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::PolicyRequired, conversation_id))?;
    if *policy_id != state.current_policy_id {
        return Err(Fail::with(E2eeReplyCode::EpochStale, conversation_id));
    }
    let rosters = super::route::rosters_of(exec, &state.principal_accounts)?;
    Ok((retained.policy.clone(), rosters))
}

/// The votes counted for one subject so far, continued across requests,
/// and the signers this request newly counted.
struct Quorum {
    reached: bool,
    ledger: QuorumLedger,
    accepted: Vec<([u8; 32], [u8; 16])>,
}

/// The terminal a durable vote row stands for (`slot` of a vote proof row).
const VOTE_ROW_FINALIZE: u16 = 1;
const VOTE_ROW_ABORT: u16 = 2;

/// One durable `vote/v1/` row per newly counted principal, naming the
/// request that carried the vote and the terminal it stands for, so a
/// reload restores each principal's decision without depending on the
/// order the requests are read back in.
fn vote_rows(
    conversation_id: &[u8; 32],
    subject: &[u8; 32],
    request_object_id: [u8; 32],
    terminal: Terminal,
    accepted: &[([u8; 32], [u8; 16])],
) -> Result<Vec<crate::state_core::durable::AccountServiceDurableWrite>, Fail> {
    let slot = match terminal.disposition {
        agenc_ircd_e2ee::objects::sequencing::IrcDisposition::Finalize => VOTE_ROW_FINALIZE,
        agenc_ircd_e2ee::objects::sequencing::IrcDisposition::Abort => VOTE_ROW_ABORT,
    };
    let row = SequencerRow::Proof {
        role: ProofRole::Vote,
        object_id: request_object_id,
        slot,
    }
    .encode()
    .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    accepted
        .iter()
        .map(|(root, device)| {
            state_row(
                TableId::E2eeState,
                SEQUENCER_ROW_KIND,
                SequencerRow::proof_key(ProofRole::Vote, conversation_id, subject, root, device)
                    .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
                row.clone(),
            )
            .map_err(Fail::from)
        })
        .collect()
}

/// Counts `votes` for `terminal` into the subject's ledger: a vote whose
/// signer already stands for the other terminal of the slot is discarded
/// as a sign-once violation, any other invalid vote fails the request, and
/// the quorum is the policy's derived `q`.
fn count_votes(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    subject: &[u8; 32],
    policy: &VerifiedPolicy,
    votes: &[IrcFinalityVote],
    terminal: Terminal,
    mut record: impl FnMut(&mut QuorumLedger, &IrcFinalityVote) -> Result<(), E2eeError>,
) -> Result<Quorum, Fail> {
    agenc_ircd_e2ee::tls::ensure_canonical(votes, |vote| {
        (vote.signer_root_fingerprint, vote.signer_device_id)
    })
    .map_err(|_| Fail::with(E2eeReplyCode::InvalidFragment, conversation_id))?;
    let mut ledger = conversation(exec, conversation_id)?
        .vote_ledgers
        .get(subject)
        .cloned()
        .unwrap_or_default();
    let mut accepted = Vec::new();
    for vote in votes {
        let signer = (vote.signer_root_fingerprint, vote.signer_device_id);
        let known = ledger.votes().any(|(recorded, _)| *recorded == signer);
        let conflicting = ledger
            .votes()
            .any(|(recorded, stood)| *recorded == signer && *stood != terminal);
        if conflicting {
            continue;
        }
        record(&mut ledger, vote)
            .map_err(|_| Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation_id))?;
        if !known {
            accepted.push(signer);
        }
    }
    Ok(Quorum {
        reached: ledger.quorum_reached(policy, &terminal),
        ledger,
        accepted,
    })
}

/// The `PENDING` answer of a terminal request below quorum: the request is
/// retained and the counted votes are kept for the subject.
fn pending(
    conversation_id: [u8; 32],
    kind: PendingKind,
    request_object_id: [u8; 32],
    bytes: &[u8],
    subject: [u8; 32],
    terminal: Terminal,
    quorum: Quorum,
) -> Result<Outcome, Fail> {
    let mut outcome = Outcome::scalar(ResultBody::Pending(
        conversation_id,
        kind,
        request_object_id,
    ));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.extend(vote_rows(
        &conversation_id,
        &subject,
        request_object_id,
        terminal,
        &quorum.accepted,
    )?);
    let ledger = quorum.ledger;
    outcome.effects.push(Box::new(move |companion| {
        if let Some(state) = companion.conversations.get_mut(&conversation_id) {
            state.vote_ledgers.insert(subject, ledger);
        }
    }));
    Ok(outcome)
}

fn vote_slot(exec: &Exec<'_>, conversation_id: [u8; 32], slot: &CandidateSlot) -> VoteSlot {
    VoteSlot {
        network_id: exec.coordinator.network_id,
        conversation_id,
        prior_epoch: slot.position.prior_epoch,
        prior_state_id: slot.position.prior_state_id,
        candidate_sequence: slot.position.candidate_sequence,
        predecessor_record_id: slot.position.predecessor_record_id,
    }
}

/// Counts a ReInit terminal request's votes under the old conversation's
/// current policy over the attempt's sign-once slot (companion 13.8).
fn reinit_quorum(
    exec: &Exec<'_>,
    log: &SequencerLog,
    old_conversation_id: [u8; 32],
    old_reinit_state_id: [u8; 32],
    attempt_id: [u8; 32],
    votes: &[IrcFinalityVote],
    terminal: Terminal,
) -> Result<Quorum, Fail> {
    let attempt = log
        .reinit_attempt()
        .filter(|attempt| attempt.attempt_id == attempt_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::FinalityRequired, &old_conversation_id))?;
    let current_policy_id = conversation(exec, &old_conversation_id)?.current_policy_id;
    let (policy, rosters) = council(exec, &old_conversation_id, &current_policy_id)?;
    let slot = ReinitVoteSlot {
        network_id: exec.coordinator.network_id,
        old_conversation_id,
        old_reinit_state_id,
        attempt_sequence: attempt.attempt_sequence,
        predecessor_record_id: attempt.predecessor_record_id,
    };
    let tbs = reinit_vote_tbs(&slot, attempt_id, terminal);
    count_votes(
        exec,
        &old_conversation_id,
        &attempt_id,
        &policy,
        votes,
        terminal,
        |ledger, vote| ledger.record_reinit(&policy, &rosters, &tbs, vote),
    )
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the Commit object, records the candidate, signs the receipt, and stages the rows and events as one atomic set
/// `submit_candidate`.
pub fn submit_candidate(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &conversation_id)?;
    let lifecycle = exec
        .coordinator
        .state
        .lifecycles
        .get(&conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    lifecycle
        .check_candidate(log)
        .map_err(|_| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    let state = exec
        .coordinator
        .state
        .conversations
        .get(&conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    let mut budget = DecodeBudget::new(MAX_LIVE_OBJECT, 1 << 16);
    let expectation = super::route::expectation_for(exec, conversation_id)?;
    let envelope = verify_commit_object(
        object,
        &expectation,
        log.accepted_state_id(),
        state.last_validation_time,
        &mut budget,
    )
    .map_err(|_| Fail::with(E2eeReplyCode::EpochStale, &conversation_id))?;
    let prior_epoch = envelope.header.epoch;
    let position = log.candidate_position(prior_epoch).map_err(|error| {
        use agenc_ircd_domain::e2ee::sequencer_log::LogError;
        match error {
            LogError::CandidateActive => {
                Fail::with(E2eeReplyCode::CandidateActive, &conversation_id)
            }
            LogError::EpochStale => Fail::with(E2eeReplyCode::EpochStale, &conversation_id),
            _ => Fail::with(E2eeReplyCode::RateLimited, &conversation_id),
        }
    })?;
    let signer =
        super::super::sequencer_signing::at_time(exec.coordinator, envelope.aad.validation_time)
            .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let commit_object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let tbs = IrcCandidateReceiptTbs {
        profile_version: 1,
        network_id: exec.coordinator.network_id,
        conversation_id,
        route_sequence: position.route_sequence,
        prior_epoch,
        resulting_epoch: prior_epoch
            .checked_add(1)
            .ok_or_else(|| Fail::from(E2eeReplyCode::EpochStale))?,
        candidate_sequence: position.candidate_sequence,
        commit_object_id,
        prior_state_id: position.prior_state_id,
        predecessor_record_id: position.predecessor_record_id,
        sequenced_at: exec.now,
        sequencer_key_id: signer.credential_id,
    };
    let candidate_id = CompanionCoordinator::id_of(SemanticHashDomain::CandidateId, &tbs)?;
    let receipt = IrcCandidateReceipt {
        sequencer_signature: signer
            .sign(SignatureDomain::CandidateReceipt, &tbs)
            .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
        tbs,
    };
    let receipt_encoded = receipt
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let record = record_bytes(&IrcSequencerRecord::Candidate(receipt))?;
    let record_id = *agenc_ircd_e2ee::ObjectId::compute(&record).as_bytes();
    let mut next_log = log.clone();
    next_log
        .record_candidate(candidate_id, commit_object_id, position)
        .map_err(|_| Fail::with(E2eeReplyCode::CandidateActive, &conversation_id))?;
    let refresh = super::route::refresh_head(exec, conversation_id, state, &next_log)?;
    let mut outcome = Outcome::scalar(ResultBody::AcceptedEvent);
    outcome.security_mutation = true;
    outcome.writes.extend(refresh.writes);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(&record)?);
    outcome.writes.push(sequencer_row(
        &conversation_id,
        position.route_sequence,
        &SequencerRow::Record {
            record_object_id: record_id,
            record_id: candidate_id,
            record_kind: 1,
            terminal: false,
            security_proof: true,
            predecessor_record_id: position.predecessor_record_id,
        },
    )?);
    outcome.writes.push(state_row(
        TableId::E2eeState,
        SEQUENCER_ROW_KIND,
        SequencerRow::candidate_key(&conversation_id, prior_epoch)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        SequencerRow::Candidate {
            candidate_id,
            commit_object_id,
            route_sequence: position.route_sequence,
            candidate_sequence: position.candidate_sequence,
            attempts: 0,
            state: CandidateState::Active,
            terminal_id: None,
        }
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    for target in audience(exec, &conversation_id)? {
        outcome.events.push(exec.event(
            EventKind::Candidate,
            Some(conversation_id),
            target,
            position.route_sequence,
            receipt_encoded.clone(),
            Some(bytes.to_vec()),
        ));
    }
    let validation_time = envelope.aad.validation_time;
    let route_object_id = refresh.route_object_id;
    outcome.effects.push(Box::new(move |companion| {
        companion.logs.insert(conversation_id, next_log);
        if let Some(state) = companion.conversations.get_mut(&conversation_id) {
            state.records.insert(position.route_sequence, record_id);
            state.last_validation_time = validation_time;
            state.route_object_id = route_object_id;
        }
    }));
    Ok(outcome)
}

/// `submit_authorization`: the server bounds, stores, and groups identical
/// TBS bytes; controller validity is an endpoint matter.
pub fn submit_authorization(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    let (device, _) = exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    log(exec, &conversation_id)?;
    let envelope: IrcCommitApprovalEnvelope = decode(object.body(), MAX_COMMIT_APPROVAL_OBJECT)?;
    if envelope.tbs.conversation_id != conversation_id
        || envelope.tbs.network_id != exec.coordinator.network_id
    {
        return Err(Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id));
    }
    if envelope.approval.signer_device_id != device {
        return Err(Fail::with(E2eeReplyCode::DeviceRequired, &conversation_id));
    }
    let authorization_id =
        CompanionCoordinator::id_of(SemanticHashDomain::CommitAuthorizationId, &envelope.tbs)?;
    let candidate_id = envelope.tbs.candidate_id;
    let signer = (
        envelope.approval.signer_root_fingerprint,
        envelope.approval.signer_device_id,
    );
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let mut outcome = Outcome::scalar(ResultBody::Stored(StoreKind::Authorization, object_id));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(state_row(
        TableId::E2eeState,
        SEQUENCER_ROW_KIND,
        SequencerRow::proof_key(
            ProofRole::Approval,
            &conversation_id,
            &candidate_id,
            &signer.0,
            &signer.1,
        )
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        SequencerRow::Proof {
            role: ProofRole::Approval,
            object_id,
            slot: 0,
        }
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    outcome.effects.push(Box::new(move |companion| {
        if let Some(state) = companion.conversations.get_mut(&conversation_id) {
            state
                .approvals
                .entry(candidate_id)
                .or_default()
                .insert(signer, object_id);
            let _ = authorization_id;
        }
    }));
    Ok(outcome)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the ACK, merges it into the accumulator, and stages the row and event as one atomic set
/// `submit_commit_ack`.
pub fn submit_commit_ack(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &conversation_id)?;
    let ack: IrcCommitAck = decode(object.body(), MAX_COMMIT_ACK_OBJECT)?;
    let slot = log
        .candidate()
        .filter(|slot| {
            slot.candidate_id == ack.tbs.candidate_id
                && slot.commit_object_id == ack.tbs.commit_object_id
        })
        .ok_or_else(|| Fail::with(E2eeReplyCode::FinalityRequired, &conversation_id))?;
    super::ack_context::commit_submission(exec, &conversation_id, &ack.tbs, slot)?;
    let candidate_id = slot.candidate_id;
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let leaf = ack.tbs.old_leaf_index;
    let mut outcome = Outcome::scalar(ResultBody::CommitAcked(
        conversation_id,
        candidate_id,
        object_id,
    ));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(state_row(
        TableId::E2eeState,
        SEQUENCER_ROW_KIND,
        SequencerRow::proof_key(
            ProofRole::Ack,
            &conversation_id,
            &candidate_id,
            &[0; 32],
            &leaf_device(leaf),
        )
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        SequencerRow::Proof {
            role: ProofRole::Ack,
            object_id,
            slot: 0,
        }
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    for target in audience(exec, &conversation_id)? {
        outcome.events.push(exec.event(
            EventKind::CommitAck,
            Some(conversation_id),
            target,
            slot.position.route_sequence,
            candidate_id.to_vec(),
            Some(bytes.to_vec()),
        ));
    }
    outcome.effects.push(Box::new(move |companion| {
        if let Some(state) = companion.conversations.get_mut(&conversation_id) {
            state
                .acks
                .entry(candidate_id)
                .or_default()
                .insert(leaf, object_id);
        }
    }));
    Ok(outcome)
}

/// ACKs are keyed by old leaf index; the accumulator key uses it as a
/// synthetic device slot.
fn leaf_device(leaf: u32) -> [u8; 16] {
    let mut device = [0; 16];
    if let Some(tail) = device.get_mut(12..) {
        tail.copy_from_slice(&leaf.to_be_bytes());
    }
    device
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the finality votes, signs the finalization, advances the log, and stages the rows and events as one atomic set
/// `submit_finalization` and `submit_abort` share one shape: a request with
/// votes becomes the signed terminal certificate at the next position.
pub fn submit_finalization(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &conversation_id)?;
    let mut request: IrcFinalizationRequest = decode(object.body(), MAX_FINALIZATION_OBJECT)?;
    let core = request.proof.core.clone();
    let core = &core;
    let slot = log
        .candidate()
        .filter(|slot| {
            slot.candidate_id == core.candidate_id && slot.commit_object_id == core.commit_object_id
        })
        .ok_or_else(|| Fail::with(E2eeReplyCode::FinalityRequired, &conversation_id))?;
    if core.conversation_id != conversation_id
        || core.prior_state_id != slot.position.prior_state_id
    {
        return Err(Fail::with(E2eeReplyCode::EpochStale, &conversation_id));
    }
    super::terminal_proof::receipt(
        exec,
        &conversation_id,
        slot.position.route_sequence,
        &IrcSequencerRecord::Candidate(request.proof.receipt.clone()),
    )?;
    super::terminal_proof::finalization(&request.proof)?;
    if core.profile_version != 1
        || core.network_id != exec.coordinator.network_id
        || core.prior_epoch != slot.position.prior_epoch
        || Some(core.resulting_epoch) != core.prior_epoch.checked_add(1)
    {
        return Err(Fail::with(
            E2eeReplyCode::BindingAuthInvalid,
            &conversation_id,
        ));
    }
    let finalization_id = CompanionCoordinator::id_of(SemanticHashDomain::FinalizationId, core)?;
    let request_object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let authorization = &request.proof.authorization.tbs;
    if authorization.old_policy_id != core.old_policy_id {
        return Err(Fail::with(
            E2eeReplyCode::BindingAuthInvalid,
            &conversation_id,
        ));
    }
    let (policy, rosters) = council(exec, &conversation_id, &core.old_policy_id)?;
    let resulting_policy_id = authorization.resulting_policy_id;
    if resulting_policy_id != core.old_policy_id {
        // A policy change installs exactly the retained successor of the
        // old policy (companion 9.3 and 12.4): never an older generation,
        // never a skipped one.
        let successor = conversation(exec, &conversation_id)?
            .policies
            .get(&resulting_policy_id)
            .ok_or_else(|| Fail::with(E2eeReplyCode::PolicyRequired, &conversation_id))?;
        let adjacent = successor.policy.previous_policy_id == core.old_policy_id
            && successor.policy.generation == policy.generation.saturating_add(1);
        if !adjacent {
            return Err(Fail::with(
                E2eeReplyCode::BindingAuthInvalid,
                &conversation_id,
            ));
        }
    }
    let terminal = Terminal::finalize(finalization_id);
    let tbs = vote_tbs(
        &vote_slot(exec, conversation_id, slot),
        core.candidate_id,
        terminal,
    );
    let quorum = count_votes(
        exec,
        &conversation_id,
        &core.candidate_id,
        &policy,
        request.votes.as_slice(),
        terminal,
        |ledger, vote| ledger.record(&policy, &rosters, &tbs, vote),
    )?;
    if !quorum.reached {
        return pending(
            conversation_id,
            PendingKind::Finalization,
            request_object_id,
            bytes,
            core.candidate_id,
            terminal,
            quorum,
        );
    }
    let finalize_rows = vote_rows(
        &conversation_id,
        &core.candidate_id,
        request_object_id,
        terminal,
        &quorum.accepted,
    )?;
    request.votes = TlsVec::new(quorum.ledger.signed_votes(&terminal))
        .map_err(|_| Fail::from(E2eeReplyCode::ObjectTooLarge))?;
    let position = log
        .terminal_position(&core.candidate_id)
        .map_err(|_| Fail::with(E2eeReplyCode::FinalityRequired, &conversation_id))?;
    let signer = exec
        .coordinator
        .signer()
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let tbs = IrcCommitFinalizationTbs {
        profile_version: 1,
        network_id: exec.coordinator.network_id,
        conversation_id,
        route_sequence: position.route_sequence,
        predecessor_record_id: position.predecessor_record_id,
        finalization_id,
        sequencer_key_id: signer.credential_id,
        request,
    };
    let certificate = IrcCommitFinalizationCertificate {
        sequencer_signature: signer
            .sign(SignatureDomain::CommitFinalization, &tbs)
            .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
        tbs,
    };
    let resulting_epoch = certificate.tbs.request.proof.core.resulting_epoch;
    // The public authorization rule tells the route which lifecycle
    // transition this certificate completes (companion 13.2 step 8).
    let activates_bootstrap = certificate
        .tbs
        .request
        .proof
        .authorization
        .tbs
        .authorization_rule
        == agenc_ircd_e2ee::objects::conversation::IrcCommitAuthorizationRule::BootstrapActivation;
    let record = record_bytes(&IrcSequencerRecord::Finalization(certificate))?;
    let record_id = *agenc_ircd_e2ee::ObjectId::compute(&record).as_bytes();
    let mut next_log = log.clone();
    next_log
        .finalize(&core.candidate_id, finalization_id, resulting_epoch)
        .map_err(|_| Fail::with(E2eeReplyCode::EpochStale, &conversation_id))?;
    let refresh = super::route::refresh_head(
        exec,
        conversation_id,
        conversation(exec, &conversation_id)?,
        &next_log,
    )?;
    let mut outcome = Outcome::scalar(ResultBody::Finalized(
        conversation_id,
        resulting_epoch,
        finalization_id,
        record_id,
    ));
    outcome.security_mutation = true;
    outcome.writes.extend(refresh.writes);
    outcome.writes.extend(finalize_rows);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(&record)?);
    outcome.writes.push(sequencer_row(
        &conversation_id,
        position.route_sequence,
        &SequencerRow::Record {
            record_object_id: record_id,
            record_id: finalization_id,
            record_kind: 2,
            terminal: true,
            security_proof: true,
            predecessor_record_id: position.predecessor_record_id,
        },
    )?);
    let mut encoded = resulting_epoch.to_be_bytes().to_vec();
    encoded.extend_from_slice(&finalization_id);
    encoded.extend_from_slice(&record_id);
    for target in audience(exec, &conversation_id)? {
        outcome.events.push(exec.event(
            EventKind::Finalized,
            Some(conversation_id),
            target,
            position.route_sequence,
            encoded.clone(),
            None,
        ));
    }
    let candidate_id = core.candidate_id;
    let route_object_id = refresh.route_object_id;
    outcome.effects.push(Box::new(move |companion| {
        companion.logs.insert(conversation_id, next_log);
        if let Some(state) = companion.conversations.get_mut(&conversation_id) {
            state.records.insert(position.route_sequence, record_id);
            state.proofs.insert(finalization_id, request_object_id);
            state.acks.remove(&candidate_id);
            state.vote_ledgers.remove(&candidate_id);
            state.current_policy_id = resulting_policy_id;
            state.route_object_id = route_object_id;
        }
        if activates_bootstrap
            && let Some(lifecycle) = companion.lifecycles.get_mut(&conversation_id)
        {
            let _activated = lifecycle.bootstrap_activated();
        }
    }));
    Ok(outcome)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the abort votes, signs the abort, resets the candidate, and stages the rows and events as one atomic set
/// `submit_abort`.
pub fn submit_abort(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &conversation_id)?;
    let mut request: IrcAbortRequest = decode(object.body(), MAX_ABORT_OBJECT)?;
    let core = request.core.clone();
    let core = &core;
    let slot = log
        .candidate()
        .filter(|slot| slot.candidate_id == core.candidate_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::FinalityRequired, &conversation_id))?;
    if core.conversation_id != conversation_id
        || core.prior_state_id != slot.position.prior_state_id
    {
        return Err(Fail::with(E2eeReplyCode::EpochStale, &conversation_id));
    }
    super::terminal_proof::receipt(
        exec,
        &conversation_id,
        slot.position.route_sequence,
        &IrcSequencerRecord::Candidate(request.receipt.clone()),
    )?;
    if core.profile_version != 1
        || core.network_id != exec.coordinator.network_id
        || core.prior_epoch != slot.position.prior_epoch
    {
        return Err(Fail::with(
            E2eeReplyCode::BindingAuthInvalid,
            &conversation_id,
        ));
    }
    let abort_id = CompanionCoordinator::id_of(SemanticHashDomain::AbortId, core)?;
    let request_object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let current_policy_id = conversation(exec, &conversation_id)?.current_policy_id;
    let (policy, rosters) = council(exec, &conversation_id, &current_policy_id)?;
    let terminal = Terminal::abort(abort_id, u16::from(core.reason.value()))
        .map_err(|_| Fail::with(E2eeReplyCode::InvalidFragment, &conversation_id))?;
    let tbs = vote_tbs(
        &vote_slot(exec, conversation_id, slot),
        core.candidate_id,
        terminal,
    );
    let quorum = count_votes(
        exec,
        &conversation_id,
        &core.candidate_id,
        &policy,
        request.votes.as_slice(),
        terminal,
        |ledger, vote| ledger.record(&policy, &rosters, &tbs, vote),
    )?;
    if !quorum.reached {
        return pending(
            conversation_id,
            PendingKind::Abort,
            request_object_id,
            bytes,
            core.candidate_id,
            terminal,
            quorum,
        );
    }
    let abort_rows = vote_rows(
        &conversation_id,
        &core.candidate_id,
        request_object_id,
        terminal,
        &quorum.accepted,
    )?;
    request.votes = TlsVec::new(quorum.ledger.signed_votes(&terminal))
        .map_err(|_| Fail::from(E2eeReplyCode::ObjectTooLarge))?;
    let position = log
        .terminal_position(&core.candidate_id)
        .map_err(|_| Fail::with(E2eeReplyCode::FinalityRequired, &conversation_id))?;
    let signer = exec
        .coordinator
        .signer()
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let candidate_id = core.candidate_id;
    let tbs = IrcCommitAbortTbs {
        profile_version: 1,
        network_id: exec.coordinator.network_id,
        conversation_id,
        route_sequence: position.route_sequence,
        predecessor_record_id: position.predecessor_record_id,
        abort_id,
        sequencer_key_id: signer.credential_id,
        request,
    };
    let certificate = IrcCommitAbortCertificate {
        sequencer_signature: signer
            .sign(SignatureDomain::CandidateAbort, &tbs)
            .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
        tbs,
    };
    let record = record_bytes(&IrcSequencerRecord::Abort(certificate))?;
    let record_id = *agenc_ircd_e2ee::ObjectId::compute(&record).as_bytes();
    let mut next_log = log.clone();
    next_log
        .abort(&candidate_id, abort_id)
        .map_err(|_| Fail::with(E2eeReplyCode::EpochStale, &conversation_id))?;
    let refresh = super::route::refresh_head(
        exec,
        conversation_id,
        conversation(exec, &conversation_id)?,
        &next_log,
    )?;
    let mut outcome = Outcome::scalar(ResultBody::Aborted(
        conversation_id,
        candidate_id,
        abort_id,
        record_id,
    ));
    outcome.security_mutation = true;
    outcome.writes.extend(refresh.writes);
    outcome.writes.extend(abort_rows);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(&record)?);
    outcome.writes.push(sequencer_row(
        &conversation_id,
        position.route_sequence,
        &SequencerRow::Record {
            record_object_id: record_id,
            record_id: abort_id,
            record_kind: 3,
            terminal: true,
            security_proof: true,
            predecessor_record_id: position.predecessor_record_id,
        },
    )?);
    for target in audience(exec, &conversation_id)? {
        outcome.events.push(exec.event(
            EventKind::Aborted,
            Some(conversation_id),
            target,
            position.route_sequence,
            ids(&[&candidate_id, &abort_id, &record_id]),
            None,
        ));
    }
    let route_object_id = refresh.route_object_id;
    outcome.effects.push(Box::new(move |companion| {
        companion.logs.insert(conversation_id, next_log);
        if let Some(state) = companion.conversations.get_mut(&conversation_id) {
            state.records.insert(position.route_sequence, record_id);
            state.proofs.insert(abort_id, request_object_id);
            state.acks.remove(&candidate_id);
            state.vote_ledgers.remove(&candidate_id);
            state.route_object_id = route_object_id;
        }
    }));
    Ok(outcome)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the staged ReInit, records the attempt, signs the receipt, and stages the rows and events as one atomic set
/// `submit_reinit_attempt`.
pub fn submit_reinit_attempt(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let old_conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    super::route_successor::owner(exec, &old_conversation_id)?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &old_conversation_id)?;
    let attempt: IrcReInitAttempt = decode(object.body(), MAX_REINIT_OBJECT)?;
    let tbs = &attempt.tbs;
    if tbs.old_conversation_id != old_conversation_id
        || tbs.network_id != exec.coordinator.network_id
    {
        return Err(Fail::with(
            E2eeReplyCode::RouteInvalid,
            &old_conversation_id,
        ));
    }
    let mut next_log = log.clone();
    if !matches!(
        log.phase(),
        agenc_ircd_domain::e2ee::sequencer_log::Phase::Reinit { .. }
    ) {
        next_log
            .enter_reinit(tbs.old_reinit_state_id)
            .map_err(|_| Fail::with(E2eeReplyCode::FinalityRequired, &old_conversation_id))?;
    }
    let slot = next_log
        .attempt_position()
        .map_err(|_| Fail::with(E2eeReplyCode::CandidateActive, &old_conversation_id))?;
    if slot.attempt_sequence != tbs.attempt_sequence {
        return Err(Fail::with(E2eeReplyCode::EpochStale, &old_conversation_id));
    }
    super::reinit_authority::verify(exec, &attempt)?;
    let attempt_id = CompanionCoordinator::id_of(SemanticHashDomain::ReinitAttemptId, tbs)?;
    let attempt_object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let signer = exec
        .coordinator
        .signer()
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let receipt_tbs = IrcReInitAttemptReceiptTbs {
        profile_version: 1,
        network_id: exec.coordinator.network_id,
        old_conversation_id,
        old_reinit_state_id: tbs.old_reinit_state_id,
        route_sequence: slot.route_sequence,
        attempt_sequence: slot.attempt_sequence,
        predecessor_record_id: slot.predecessor_record_id,
        reinit_attempt_id: attempt_id,
        attempt_object_id,
        sequenced_at: exec.now,
        sequencer_key_id: signer.credential_id,
    };
    let receipt = IrcReInitAttemptReceipt {
        sequencer_signature: signer
            .sign(SignatureDomain::ReinitAttemptReceipt, &receipt_tbs)
            .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
        tbs: receipt_tbs,
    };
    let record = record_bytes(&IrcSequencerRecord::ReinitAttempt(receipt))?;
    let record_id = *agenc_ircd_e2ee::ObjectId::compute(&record).as_bytes();
    next_log
        .record_attempt(attempt_id)
        .map_err(|_| Fail::with(E2eeReplyCode::CandidateActive, &old_conversation_id))?;
    let refresh = super::route::refresh_head(
        exec,
        old_conversation_id,
        conversation(exec, &old_conversation_id)?,
        &next_log,
    )?;
    let mut outcome = Outcome::scalar(ResultBody::ReinitStaged(
        old_conversation_id,
        attempt_id,
        attempt_object_id,
    ));
    outcome.security_mutation = true;
    outcome.writes.extend(refresh.writes);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(&record)?);
    outcome.writes.push(sequencer_row(
        &old_conversation_id,
        slot.route_sequence,
        &SequencerRow::Record {
            record_object_id: record_id,
            record_id: attempt_id,
            record_kind: 4,
            terminal: false,
            security_proof: true,
            predecessor_record_id: slot.predecessor_record_id,
        },
    )?);
    for target in audience(exec, &old_conversation_id)? {
        outcome.events.push(exec.event(
            EventKind::ReinitStaged,
            Some(old_conversation_id),
            target,
            slot.route_sequence,
            ids(&[&attempt_id, &attempt_object_id]),
            None,
        ));
    }
    let route_object_id = refresh.route_object_id;
    outcome.effects.push(Box::new(move |companion| {
        companion.logs.insert(old_conversation_id, next_log);
        if let Some(state) = companion.conversations.get_mut(&old_conversation_id) {
            state.records.insert(slot.route_sequence, record_id);
            state.route_object_id = route_object_id;
        }
    }));
    Ok(outcome)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the ReInit ACK, merges it, and stages the row and event as one atomic set
/// `submit_reinit_ack`.
pub fn submit_reinit_ack(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let old_conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &old_conversation_id)?;
    let ack: IrcReInitAck = decode(object.body(), MAX_REINIT_ACK_OBJECT)?;
    let slot = log
        .reinit_attempt()
        .filter(|slot| slot.attempt_id == ack.tbs.reinit_attempt_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::FinalityRequired, &old_conversation_id))?;
    super::ack_context::reinit_submission(exec, &old_conversation_id, &ack.tbs, slot)?;
    let attempt_id = slot.attempt_id;
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let leaf = ack.tbs.old_leaf_index;
    let mut outcome = Outcome::scalar(ResultBody::ReinitAcked(
        old_conversation_id,
        attempt_id,
        object_id,
    ));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(state_row(
        TableId::E2eeState,
        SEQUENCER_ROW_KIND,
        SequencerRow::proof_key(
            ProofRole::Ack,
            &old_conversation_id,
            &attempt_id,
            &[0; 32],
            &leaf_device(leaf),
        )
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        SequencerRow::Proof {
            role: ProofRole::Ack,
            object_id,
            slot: 0,
        }
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    for target in audience(exec, &old_conversation_id)? {
        outcome.events.push(exec.event(
            EventKind::ReinitAck,
            Some(old_conversation_id),
            target,
            slot.route_sequence,
            attempt_id.to_vec(),
            Some(bytes.to_vec()),
        ));
    }
    outcome.effects.push(Box::new(move |companion| {
        if let Some(state) = companion.conversations.get_mut(&old_conversation_id) {
            state
                .acks
                .entry(attempt_id)
                .or_default()
                .insert(leaf, object_id);
        }
    }));
    Ok(outcome)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the terminal votes, signs activation or abort, migrates or resets the log, and stages the rows and events as one atomic set
/// `submit_reinit_activate` (`activate`) and `submit_reinit_abort`.
pub fn submit_reinit_terminal(exec: &mut Exec<'_>, activate: bool) -> Result<Outcome, Fail> {
    let old_conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    super::route_successor::owner(exec, &old_conversation_id)?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &old_conversation_id)?;
    let request_object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let signer = exec
        .coordinator
        .signer()
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let (attempt_id, quorum, terminal, terminal_id, new_conversation, record) = if activate {
        let mut request: IrcReInitActivationRequest = decode(object.body(), MAX_REINIT_OBJECT)?;
        super::terminal_proof::reinit_attempt(
            exec,
            &old_conversation_id,
            &request.receipt,
            &request.attempt,
        )?;
        super::terminal_proof::reinit_activation(&request)?;
        let core = request.core.clone();
        let core = &core;
        if core.old_conversation_id != old_conversation_id {
            return Err(Fail::with(
                E2eeReplyCode::RouteInvalid,
                &old_conversation_id,
            ));
        }
        let terminal_id =
            CompanionCoordinator::id_of(SemanticHashDomain::ReinitActivationId, core)?;
        let attempt_id = core.reinit_attempt_id;
        let new_conversation = core.new_conversation_id;
        let terminal = Terminal::finalize(terminal_id);
        let quorum = reinit_quorum(
            exec,
            log,
            old_conversation_id,
            core.old_reinit_state_id,
            attempt_id,
            request.votes.as_slice(),
            terminal,
        )?;
        request.votes = TlsVec::new(quorum.ledger.signed_votes(&terminal))
            .map_err(|_| Fail::from(E2eeReplyCode::ObjectTooLarge))?;
        let position = log
            .attempt_terminal_position(&attempt_id)
            .map_err(|_| Fail::with(E2eeReplyCode::FinalityRequired, &old_conversation_id))?;
        let tbs = IrcReInitActivationTbs {
            profile_version: 1,
            network_id: exec.coordinator.network_id,
            old_conversation_id,
            route_sequence: position.route_sequence,
            predecessor_record_id: position.predecessor_record_id,
            reinit_activation_id: terminal_id,
            sequencer_key_id: signer.credential_id,
            request,
        };
        let certificate = IrcReInitActivationCertificate {
            sequencer_signature: signer
                .sign(SignatureDomain::ReinitActivation, &tbs)
                .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
            tbs,
        };
        (
            attempt_id,
            quorum,
            terminal,
            terminal_id,
            Some(new_conversation),
            IrcSequencerRecord::ReinitActivation(certificate),
        )
    } else {
        let mut request: IrcReInitAbortRequest = decode(object.body(), MAX_REINIT_OBJECT)?;
        super::terminal_proof::reinit_attempt(
            exec,
            &old_conversation_id,
            &request.receipt,
            &request.attempt,
        )?;
        let core = request.core.clone();
        let core = &core;
        if core.profile_version != 1
            || core.network_id != exec.coordinator.network_id
            || core.attempt_sequence != request.receipt.tbs.attempt_sequence
            || core.slot_predecessor_record_id != request.receipt.tbs.predecessor_record_id
        {
            return Err(Fail::with(
                E2eeReplyCode::BindingAuthInvalid,
                &old_conversation_id,
            ));
        }
        if core.old_conversation_id != old_conversation_id {
            return Err(Fail::with(
                E2eeReplyCode::RouteInvalid,
                &old_conversation_id,
            ));
        }
        let terminal_id = CompanionCoordinator::id_of(SemanticHashDomain::ReinitAbortId, core)?;
        let attempt_id = core.reinit_attempt_id;
        let terminal = Terminal::abort(terminal_id, core.reason_code)
            .map_err(|_| Fail::with(E2eeReplyCode::InvalidFragment, &old_conversation_id))?;
        let quorum = reinit_quorum(
            exec,
            log,
            old_conversation_id,
            core.old_reinit_state_id,
            attempt_id,
            request.votes.as_slice(),
            terminal,
        )?;
        request.votes = TlsVec::new(quorum.ledger.signed_votes(&terminal))
            .map_err(|_| Fail::from(E2eeReplyCode::ObjectTooLarge))?;
        let position = log
            .attempt_terminal_position(&attempt_id)
            .map_err(|_| Fail::with(E2eeReplyCode::FinalityRequired, &old_conversation_id))?;
        let tbs = IrcReInitAbortTbs {
            profile_version: 1,
            network_id: exec.coordinator.network_id,
            old_conversation_id,
            route_sequence: position.route_sequence,
            predecessor_record_id: position.predecessor_record_id,
            reinit_abort_id: terminal_id,
            sequencer_key_id: signer.credential_id,
            request,
        };
        let certificate = IrcReInitAbortCertificate {
            sequencer_signature: signer
                .sign(SignatureDomain::ReinitAttemptAbort, &tbs)
                .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
            tbs,
        };
        (
            attempt_id,
            quorum,
            terminal,
            terminal_id,
            None,
            IrcSequencerRecord::ReinitAbort(certificate),
        )
    };
    if !quorum.reached {
        let kind = if activate {
            PendingKind::ReinitActivate
        } else {
            PendingKind::ReinitAbort
        };
        return pending(
            old_conversation_id,
            kind,
            request_object_id,
            bytes,
            attempt_id,
            terminal,
            quorum,
        );
    }
    let attempt_rows = vote_rows(
        &old_conversation_id,
        &attempt_id,
        request_object_id,
        terminal,
        &quorum.accepted,
    )?;
    let position = log
        .attempt_terminal_position(&attempt_id)
        .map_err(|_| Fail::with(E2eeReplyCode::FinalityRequired, &old_conversation_id))?;
    let record = record_bytes(&record)?;
    let record_id = *agenc_ircd_e2ee::ObjectId::compute(&record).as_bytes();
    let mut next_log = log.clone();
    let (result, event_kind, encoded) = match new_conversation {
        Some(new_conversation_id) => {
            next_log
                .activate(&attempt_id, terminal_id, new_conversation_id)
                .map_err(|_| Fail::with(E2eeReplyCode::EpochStale, &old_conversation_id))?;
            (
                ResultBody::ReinitActivated(
                    old_conversation_id,
                    new_conversation_id,
                    terminal_id,
                    record_id,
                ),
                EventKind::ReinitActivated,
                ids(&[&new_conversation_id, &terminal_id, &record_id]),
            )
        }
        None => {
            next_log
                .abort_attempt(&attempt_id, terminal_id)
                .map_err(|_| Fail::with(E2eeReplyCode::EpochStale, &old_conversation_id))?;
            (
                ResultBody::ReinitAborted(old_conversation_id, attempt_id, terminal_id, record_id),
                EventKind::ReinitAborted,
                ids(&[&attempt_id, &terminal_id, &record_id]),
            )
        }
    };
    let refresh = super::route::refresh_head(
        exec,
        old_conversation_id,
        conversation(exec, &old_conversation_id)?,
        &next_log,
    )?;
    let mut outcome = Outcome::scalar(result);
    outcome.writes.extend(refresh.writes);
    outcome.writes.extend(attempt_rows);
    outcome.security_mutation = true;
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(&record)?);
    outcome.writes.push(sequencer_row(
        &old_conversation_id,
        position.route_sequence,
        &SequencerRow::Record {
            record_object_id: record_id,
            record_id: terminal_id,
            record_kind: if activate { 5 } else { 6 },
            terminal: true,
            security_proof: true,
            predecessor_record_id: position.predecessor_record_id,
        },
    )?);
    for target in audience(exec, &old_conversation_id)? {
        outcome.events.push(exec.event(
            event_kind,
            Some(old_conversation_id),
            target,
            position.route_sequence,
            encoded.clone(),
            None,
        ));
    }
    let route_object_id = refresh.route_object_id;
    outcome.effects.push(Box::new(move |companion| {
        if let Some(new_conversation_id) = new_conversation {
            let successor = SequencerLog::from_activation(new_conversation_id, terminal_id);
            companion.logs.insert(new_conversation_id, successor);
            companion.lifecycles.insert(
                new_conversation_id,
                agenc_ircd_domain::e2ee::lifecycle::Lifecycle::successor(),
            );
        }
        companion.logs.insert(old_conversation_id, next_log);
        if let Some(state) = companion.conversations.get_mut(&old_conversation_id) {
            state.records.insert(position.route_sequence, record_id);
            state.proofs.insert(terminal_id, request_object_id);
            state.vote_ledgers.remove(&attempt_id);
            state.route_object_id = route_object_id;
        }
    }));
    Ok(outcome)
}

fn page(
    exec: &mut Exec<'_>,
    objects: Vec<Vec<u8>>,
    empty: EmptyKind,
    cursor_after: Option<[u8; 32]>,
) -> Result<Outcome, Fail> {
    if objects.is_empty() {
        return Ok(Outcome::scalar(ResultBody::Empty(empty)));
    }
    let mut outcome = Outcome::scalar(ResultBody::ObjectPage);
    outcome.snapshot_token = Some(exec.random()?);
    outcome.next_cursor = cursor_after;
    outcome.responses = objects
        .into_iter()
        .map(|bytes| ResponseObject {
            bytes,
            delivery_token: None,
            target_device_id: None,
        })
        .collect();
    Ok(outcome)
}

/// `fetch_object`.
pub fn fetch_object(exec: &mut Exec<'_>) -> Result<super::Prepared, Fail> {
    let (conversation_id, object_id) = exec
        .params()
        .read(|reader| Ok((reader.fixed::<32>()?, reader.fixed::<32>()?)))?;
    exec.attached_device()?;
    log(exec, &conversation_id)?;
    let request = super::super::object_read::Request {
        conversation_id,
        object_id,
    };
    let bytes = match exec.object_source {
        super::super::object_read::Source::Resolved(resolved) => resolved
            .lookup(request)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        super::super::object_read::Source::Unread => {
            let Some(bytes) = exec.coordinator.state.objects.get(&object_id) else {
                return Ok(super::Prepared::Read(request));
            };
            Some(bytes.as_slice())
        }
        #[cfg(test)]
        super::super::object_read::Source::CompleteMemory => exec
            .coordinator
            .state
            .objects
            .get(&object_id)
            .map(Vec::as_slice),
    };
    let bytes = bytes
        .filter(|bytes| super::recovery_read::permitted(exec, &conversation_id, bytes))
        .map(<[u8]>::to_vec);
    page(exec, bytes.into_iter().collect(), EmptyKind::Objects, None)
        .map(|outcome| super::Prepared::Complete(Box::new(outcome)))
}

/// A page of retained proof objects sorted by their accumulator key.
fn proof_page(
    exec: &mut Exec<'_>,
    ids: Vec<[u8; 32]>,
    cursor: Option<[u8; 32]>,
    empty: EmptyKind,
) -> Result<Outcome, Fail> {
    let start = cursor.map_or(0, |cursor| {
        ids.iter()
            .position(|id| *id == cursor)
            .map_or(ids.len(), |index| index + 1)
    });
    let window: Vec<[u8; 32]> = ids
        .iter()
        .skip(start)
        .take(MAX_BATCH_OBJECTS + 1)
        .copied()
        .collect();
    let next = window
        .get(MAX_BATCH_OBJECTS)
        .and_then(|_| window.get(MAX_BATCH_OBJECTS - 1).copied());
    let objects: Vec<Vec<u8>> = window
        .iter()
        .take(MAX_BATCH_OBJECTS)
        .filter_map(|id| exec.coordinator.state.objects.get(id).cloned())
        .collect();
    page(exec, objects, empty, next)
}

/// `fetch_authorizations`.
pub fn fetch_authorizations(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (conversation_id, candidate_id, cursor) = exec.params().read(|reader| {
        Ok((
            reader.fixed::<32>()?,
            reader.fixed::<32>()?,
            cursor(reader)?,
        ))
    })?;
    exec.attached_device()?;
    let ids: Vec<[u8; 32]> = exec
        .coordinator
        .state
        .conversations
        .get(&conversation_id)
        .and_then(|state| state.approvals.get(&candidate_id))
        .map(|approvals| approvals.values().copied().collect())
        .unwrap_or_default();
    proof_page(exec, ids, cursor, EmptyKind::Authorizations)
}

/// `fetch_acks`.
pub fn fetch_acks(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (conversation_id, selector, cursor) = exec.params().read(|reader| {
        Ok((
            reader.fixed::<32>()?,
            reader.fixed::<32>()?,
            cursor(reader)?,
        ))
    })?;
    exec.attached_device()?;
    let ids: Vec<[u8; 32]> = exec
        .coordinator
        .state
        .conversations
        .get(&conversation_id)
        .and_then(|state| state.acks.get(&selector))
        .map(|acks| acks.values().copied().collect())
        .unwrap_or_default();
    proof_page(exec, ids, cursor, EmptyKind::Acks)
}

/// `fetch_receipts`: contiguous records from the requested sequence.
pub fn fetch_receipts(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (conversation_id, first, cursor) = exec
        .params()
        .read(|reader| Ok((reader.fixed::<32>()?, reader.u64()?, cursor(reader)?)))?;
    exec.attached_device()?;
    let state = exec
        .coordinator
        .state
        .conversations
        .get(&conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    let start = cursor
        .and_then(|cursor| {
            state
                .records
                .iter()
                .find(|(_, id)| **id == cursor)
                .map(|(sequence, _)| sequence.saturating_add(1))
        })
        .unwrap_or(first);
    let mut objects = Vec::new();
    let mut next = None;
    let mut expected = start;
    for (sequence, id) in state.records.range(start..) {
        if *sequence != expected {
            break;
        }
        if objects.len() == MAX_BATCH_OBJECTS {
            next = objects
                .last()
                .and_then(|_| state.records.get(&(expected - 1)).copied());
            break;
        }
        if let Some(bytes) = exec.coordinator.state.objects.get(id) {
            objects.push(bytes.clone());
        }
        expected = expected.saturating_add(1);
    }
    page(exec, objects, EmptyKind::Receipts, next)
}
