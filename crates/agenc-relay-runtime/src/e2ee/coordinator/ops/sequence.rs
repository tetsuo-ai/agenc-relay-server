//! Sequencing operations: candidates, approvals, ACKs, finalization and
//! abort, ReInit attempts and terminals, and the retained-record fetches
//! (companion Sections 12.1 to 12.4, 13.8).
//!
//! The sequencer certifies a finalization, abort, or ReInit terminal only
//! after it has verified at least the old policy's quorum `q` of distinct
//! council votes under the published policy (companion 12.4 and 13.8); a
//! request below `q` is retained and answered `PENDING`. Endpoints still
//! verify the quorum themselves before applying a state.

use agenc_relay_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_relay_domain::e2ee::limits::MAX_BATCH_OBJECTS;
use agenc_relay_domain::e2ee::projection::{EmptyKind, EventKind, PendingKind, StoreKind};
use agenc_relay_domain::e2ee::sequencer_log::{CandidateSlot, SequencerLog};
use agenc_relay_e2ee::E2eeError;
use agenc_relay_e2ee::envelope::verify_commit_object;
use agenc_relay_e2ee::finality::{
    QuorumLedger, ReinitVoteSlot, Terminal, VoteSlot, reinit_vote_tbs, vote_tbs,
};
use agenc_relay_e2ee::limits::{
    MAX_ABORT_OBJECT, MAX_COMMIT_ACK_OBJECT, MAX_COMMIT_APPROVAL_OBJECT, MAX_FINALIZATION_OBJECT,
    MAX_LIVE_OBJECT, MAX_REINIT_ACK_OBJECT, MAX_REINIT_OBJECT,
};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::{ArcCommitApprovalEnvelope, action_bits};
use agenc_relay_e2ee::objects::reinit::{
    ArcReInitAbortCertificate, ArcReInitAbortRequest, ArcReInitAbortTbs, ArcReInitAck,
    ArcReInitActivationCertificate, ArcReInitActivationRequest, ArcReInitActivationTbs,
    ArcReInitAttempt, ArcReInitAttemptReceipt, ArcReInitAttemptReceiptTbs,
};
use agenc_relay_e2ee::objects::sequencing::{
    ArcAbortRequest, ArcCandidateReceipt, ArcCandidateReceiptTbs, ArcCommitAbortCertificate,
    ArcCommitAbortTbs, ArcCommitAck, ArcCommitFinalizationCertificate, ArcCommitFinalizationTbs,
    ArcFinalityVote, ArcFinalizationProof, ArcFinalizationRequest, ArcSequencerRecord,
};
use agenc_relay_e2ee::policy::VerifiedPolicy;
use agenc_relay_e2ee::reinit_target::AuthorizedReinit;
use agenc_relay_e2ee::route::PrincipalRosters;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode, TlsEncode, TlsVec};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::TableId;
use agenc_relay_storage::e2ee_records::{
    CandidateState, ProofRole, SEQUENCER_ROW_KIND, SequencerRow,
};

use super::super::request::{Outcome, ResponseObject, ResultBody, state_row};
use super::super::{CompanionCoordinator, ConversationState};
use super::ack_context::AckSigner;
use super::route::audience;
use super::{Exec, Fail, cursor};

fn log<'a>(exec: &Exec<'a>, conversation_id: &[u8; 32]) -> Result<&'a SequencerLog, Fail> {
    exec.coordinator
        .state
        .logs
        .get(conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, conversation_id))
}

fn wire(kind: ArcWireObjectKind, body: Vec<u8>) -> Result<Vec<u8>, Fail> {
    ArcWireObject::new(kind, body)
        .and_then(|object| object.encode())
        .map_err(|_| Fail::from(E2eeReplyCode::ObjectTooLarge))
}

pub(super) fn record_bytes(record: &ArcSequencerRecord) -> Result<Vec<u8>, Fail> {
    let body = record
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    wire(ArcWireObjectKind::SequencerRecord, body)
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
        agenc_relay_e2ee::objects::sequencing::ArcDisposition::Finalize => VOTE_ROW_FINALIZE,
        agenc_relay_e2ee::objects::sequencing::ArcDisposition::Abort => VOTE_ROW_ABORT,
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
    votes: &[ArcFinalityVote],
    terminal: Terminal,
    mut record: impl FnMut(&mut QuorumLedger, &ArcFinalityVote) -> Result<(), E2eeError>,
) -> Result<Quorum, Fail> {
    agenc_relay_e2ee::tls::ensure_canonical(votes, |vote| {
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

/// The credential a finalized `SEQUENCER` transition pins from now on: the
/// advertised credential whose predecessor is the conversation's current
/// pin (companion 9.2.1). Every later record signs under it; the receipt,
/// votes and this finalization stayed under the old credential.
fn sequencer_transition(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    authorization: &agenc_relay_e2ee::objects::conversation::ArcCommitAuthorizationTbs,
) -> Result<Option<[u8; 32]>, Fail> {
    if authorization.action_bits & action_bits::SEQUENCER == 0 {
        return Ok(None);
    }
    let pin = conversation(exec, conversation_id)?.sequencer_credential_id;
    exec.coordinator
        .key_set()
        .and_then(|set| {
            set.credentials
                .iter()
                .find(|credential| credential.previous_key_id == pin)
        })
        .map(|successor| Some(successor.credential_id))
        .ok_or_else(|| Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation_id))
}

/// The resulting council of a bootstrap activation, which votes beside the
/// old council (companion 9.5); every other rule has no second council.
fn resulting_council(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    authorization: &agenc_relay_e2ee::objects::conversation::ArcCommitAuthorizationTbs,
) -> Result<Option<VerifiedPolicy>, Fail> {
    use agenc_relay_e2ee::objects::conversation::ArcCommitAuthorizationRule;
    if authorization.authorization_rule != ArcCommitAuthorizationRule::BootstrapActivation {
        return Ok(None);
    }
    let retained = conversation(exec, conversation_id)?
        .policies
        .get(&authorization.resulting_policy_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::PolicyRequired, conversation_id))?;
    Ok(Some(retained.policy.clone()))
}

/// Whether the votes of `policy`'s own council members for `terminal` reach
/// its quorum.
fn council_reached(ledger: &QuorumLedger, policy: &VerifiedPolicy, terminal: &Terminal) -> bool {
    let count = ledger
        .votes()
        .filter(|(_, stood)| *stood == terminal)
        .filter(|(signer, _)| policy.council_member(&signer.0, &signer.1).is_some())
        .count();
    count >= usize::from(policy.quorum)
}

/// The root of a retained-request row. No root fingerprint is all zero, so
/// the row never reads back as a principal's vote.
pub(in crate::e2ee::coordinator) const REQUEST_ROW_ROOT: [u8; 32] = [0; 32];

/// The retained terminal requests one candidate or attempt may hold below
/// quorum: twice the largest council, since a useful request adds a vote.
const MAX_PENDING_TERMINAL_REQUESTS: usize = 2 * agenc_relay_e2ee::limits::MAX_FINALITY_PRINCIPALS;

/// The key of the row that owns one retained terminal request under its
/// conversation (companion 15 and 16): a vote-accumulator row under the
/// all-zero root, keyed by the leading bytes of the request identifier.
fn request_row_key(
    conversation_id: &[u8; 32],
    subject: &[u8; 32],
    request_object_id: &[u8; 32],
) -> Result<agenc_relay_storage::StoredKey, Fail> {
    let mut device = [0; 16];
    for (slot, byte) in device.iter_mut().zip(request_object_id) {
        *slot = *byte;
    }
    SequencerRow::proof_key(
        ProofRole::Vote,
        conversation_id,
        subject,
        &REQUEST_ROW_ROOT,
        &device,
    )
    .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))
}

/// The row that charges one retained terminal request to its conversation.
fn request_row(
    conversation_id: &[u8; 32],
    subject: &[u8; 32],
    request_object_id: [u8; 32],
    terminal: Terminal,
) -> Result<crate::state_core::durable::AccountServiceDurableWrite, Fail> {
    let slot = match terminal.disposition {
        agenc_relay_e2ee::objects::sequencing::ArcDisposition::Finalize => VOTE_ROW_FINALIZE,
        agenc_relay_e2ee::objects::sequencing::ArcDisposition::Abort => VOTE_ROW_ABORT,
    };
    state_row(
        TableId::E2eeState,
        SEQUENCER_ROW_KIND,
        request_row_key(conversation_id, subject, &request_object_id)?,
        SequencerRow::Proof {
            role: ProofRole::Vote,
            object_id: request_object_id,
            slot,
        }
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )
    .map_err(Fail::from)
}

/// Retires the retained-request rows of a slot that reached its terminal,
/// keeping the certifying request's. A request no vote row names is then
/// unowned and ages out through the expiry collector.
fn retire_requests(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    subject: &[u8; 32],
    certifying: &[u8; 32],
) -> Result<Vec<crate::state_core::durable::AccountServiceDurableWrite>, Fail> {
    conversation(exec, conversation_id)?
        .pending_requests
        .get(subject)
        .into_iter()
        .flatten()
        .filter(|request| *request != certifying)
        .map(|request| {
            crate::state_core::durable::AccountServiceDurableWrite::delete(
                TableId::E2eeState,
                request_row_key(conversation_id, subject, request)?,
            )
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))
        })
        .collect()
}

/// One terminal request that stayed below quorum.
struct PendingTerminal {
    conversation_id: [u8; 32],
    kind: PendingKind,
    request_object_id: [u8; 32],
    subject: [u8; 32],
    terminal: Terminal,
}

/// The `PENDING` answer of a terminal request below quorum: the request is
/// retained under a row that charges it to its conversation, and the
/// counted votes are kept for the subject. A slot that already retains its
/// ceiling of other requests refuses with `E2EE_RATE_LIMITED`.
fn pending(
    exec: &Exec<'_>,
    request: PendingTerminal,
    bytes: &[u8],
    quorum: Quorum,
) -> Result<Outcome, Fail> {
    let PendingTerminal {
        conversation_id,
        kind,
        request_object_id,
        subject,
        terminal,
    } = request;
    let retained = conversation(exec, &conversation_id)?
        .pending_requests
        .get(&subject);
    let known = retained.is_some_and(|requests| requests.contains(&request_object_id));
    if !known
        && retained.map_or(0, std::collections::BTreeSet::len) >= MAX_PENDING_TERMINAL_REQUESTS
    {
        return Err(Fail::with(E2eeReplyCode::RateLimited, &conversation_id));
    }
    let mut outcome = Outcome::scalar(ResultBody::Pending(
        conversation_id,
        kind,
        request_object_id,
    ));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(request_row(
        &conversation_id,
        &subject,
        request_object_id,
        terminal,
    )?);
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
            state
                .pending_requests
                .entry(subject)
                .or_default()
                .insert(request_object_id);
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
    votes: &[ArcFinalityVote],
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
        use agenc_relay_domain::e2ee::sequencer_log::LogError;
        match error {
            LogError::CandidateActive => {
                Fail::with(E2eeReplyCode::CandidateActive, &conversation_id)
            }
            LogError::EpochStale => Fail::with(E2eeReplyCode::EpochStale, &conversation_id),
            _ => Fail::with(E2eeReplyCode::RateLimited, &conversation_id),
        }
    })?;
    // A blocked route issues no receipt, and a receipt is signed only under
    // the credential the conversation pins while it covers the Commit's
    // canonical validation time (companion 9.2.1).
    state
        .blocked_credential_id
        .map_or(Ok(()), |_| Err(Fail::from(E2eeReplyCode::Syncing)))?;
    let signer = super::super::sequencer_signing::at_time(
        exec.coordinator,
        &state.sequencer_credential_id,
        envelope.aad.validation_time,
    )
    .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let commit_object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
    let tbs = ArcCandidateReceiptTbs {
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
    let receipt = ArcCandidateReceipt {
        sequencer_signature: signer
            .sign(SignatureDomain::CandidateReceipt, &tbs)
            .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
        tbs,
    };
    let receipt_encoded = receipt
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let record = record_bytes(&ArcSequencerRecord::Candidate(receipt))?;
    let record_id = *agenc_relay_e2ee::ObjectId::compute(&record).as_bytes();
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
    let envelope: ArcCommitApprovalEnvelope = decode(object.body(), MAX_COMMIT_APPROVAL_OBJECT)?;
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
    let object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
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
    let ack: ArcCommitAck = decode(object.body(), MAX_COMMIT_ACK_OBJECT)?;
    let slot = log
        .candidate()
        .filter(|slot| {
            slot.candidate_id == ack.tbs.candidate_id
                && slot.commit_object_id == ack.tbs.commit_object_id
        })
        .ok_or_else(|| Fail::with(E2eeReplyCode::FinalityRequired, &conversation_id))?;
    super::ack_context::commit_submission(exec, &conversation_id, &ack.tbs, slot)?;
    let signer = super::ack_context::identify_submitter(
        exec,
        &conversation_id,
        &AckSigner::commit(&ack),
        &ack.tbs,
    )?;
    let candidate_id = slot.candidate_id;
    let object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
    let leaf = ack.tbs.old_leaf_index;
    super::ack_context::admit_standalone(
        exec,
        &conversation_id,
        &candidate_id,
        leaf,
        &object_id,
        signer,
    )?;
    let signing_device = super::ack_context::signer_key(signer);
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
            state
                .ack_signers
                .entry(candidate_id)
                .or_default()
                .insert(signing_device, leaf);
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

/// Whether finalizing `proof` enters the ReInit phase, and with what: a
/// Commit whose authorization carries the ReInit bit closes the old group at
/// its finalization (companion 13.8 step 2), which records the authorized
/// target its proof binds, every later attempt's reference, or none when
/// `AuthorizedReinit::from_proof` refuses that proof, so no attempt can
/// follow it.
fn reinit_entry(proof: &ArcFinalizationProof) -> Option<Option<AuthorizedReinit>> {
    (proof.authorization.tbs.action_bits & action_bits::REINIT != 0)
        .then(|| AuthorizedReinit::from_proof(proof).ok())
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the finality votes, signs the finalization, advances the log, and stages the rows and events as one atomic set
/// `submit_finalization` and `submit_abort` share one shape: a request with
/// votes becomes the signed terminal certificate at the next position.
pub fn submit_finalization(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &conversation_id)?;
    let mut request: ArcFinalizationRequest = decode(object.body(), MAX_FINALIZATION_OBJECT)?;
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
        &ArcSequencerRecord::Candidate(request.proof.receipt.clone()),
    )?;
    super::terminal_proof::finalization(&request.proof)?;
    super::ack_context::identify_set(
        exec,
        &conversation_id,
        request
            .proof
            .acknowledgements
            .as_slice()
            .iter()
            .map(|ack| (AckSigner::commit(ack), &ack.tbs)),
    )?;
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
    let request_object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
    let reinit = reinit_entry(&request.proof);
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
    let next_pin = sequencer_transition(exec, &conversation_id, authorization)?;
    let terminal = Terminal::finalize(finalization_id);
    let tbs = vote_tbs(
        &vote_slot(exec, conversation_id, slot),
        core.candidate_id,
        terminal,
    );
    let resulting = resulting_council(exec, &conversation_id, authorization)?;
    let mut quorum = count_votes(
        exec,
        &conversation_id,
        &core.candidate_id,
        &policy,
        request.votes.as_slice(),
        terminal,
        |ledger, vote| {
            let council = resulting
                .as_ref()
                .filter(|council| {
                    let signer = (&vote.signer_root_fingerprint, &vote.signer_device_id);
                    policy.council_member(signer.0, signer.1).is_none()
                        && council.council_member(signer.0, signer.1).is_some()
                })
                .unwrap_or(&policy);
            ledger.record(council, &rosters, &tbs, vote)
        },
    )?;
    if let Some(council) = &resulting {
        quorum.reached = council_reached(&quorum.ledger, &policy, &terminal)
            && council_reached(&quorum.ledger, council, &terminal);
    }
    if !quorum.reached {
        return pending(
            exec,
            PendingTerminal {
                conversation_id,
                kind: PendingKind::Finalization,
                request_object_id,
                subject: core.candidate_id,
                terminal,
            },
            bytes,
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
    let signer = super::super::sequencer_signing::for_receipt(
        exec.coordinator,
        request.proof.receipt.tbs.sequencer_key_id,
    )
    .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let tbs = ArcCommitFinalizationTbs {
        profile_version: 1,
        network_id: exec.coordinator.network_id,
        conversation_id,
        route_sequence: position.route_sequence,
        predecessor_record_id: position.predecessor_record_id,
        finalization_id,
        sequencer_key_id: signer.credential_id,
        request,
    };
    let certificate = ArcCommitFinalizationCertificate {
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
        == agenc_relay_e2ee::objects::conversation::ArcCommitAuthorizationRule::BootstrapActivation;
    let record = record_bytes(&ArcSequencerRecord::Finalization(certificate))?;
    let record_id = *agenc_relay_e2ee::ObjectId::compute(&record).as_bytes();
    let mut next_log = log.clone();
    if reinit.is_some() {
        next_log.finalize_reinit(&core.candidate_id, finalization_id, resulting_epoch)
    } else {
        next_log.finalize(&core.candidate_id, finalization_id, resulting_epoch)
    }
    .map_err(|_| Fail::with(E2eeReplyCode::EpochStale, &conversation_id))?;
    // The finalized transition, if any, moves the pin before the route row
    // is refreshed so the row and the state agree in one batch.
    let mut pinned = conversation(exec, &conversation_id)?.clone();
    if let Some(pin) = next_pin {
        pinned.sequencer_credential_id = pin;
        pinned.blocked_credential_id = None;
    }
    let refresh = super::route::refresh_head(exec, conversation_id, &pinned, &next_log)?;
    let mut outcome = Outcome::scalar(ResultBody::Finalized(
        conversation_id,
        resulting_epoch,
        finalization_id,
        record_id,
    ));
    outcome.security_mutation = true;
    outcome.writes.extend(refresh.writes);
    outcome.writes.extend(finalize_rows);
    outcome.writes.extend(retire_requests(
        exec,
        &conversation_id,
        &core.candidate_id,
        &request_object_id,
    )?);
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
            state.ack_signers.remove(&candidate_id);
            state.vote_ledgers.remove(&candidate_id);
            state.pending_requests.remove(&candidate_id);
            state.current_policy_id = resulting_policy_id;
            state.route_object_id = route_object_id;
            state.reinit = reinit.flatten();
            if let Some(pin) = next_pin {
                state.sequencer_credential_id = pin;
                state.blocked_credential_id = None;
            }
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
    let mut request: ArcAbortRequest = decode(object.body(), MAX_ABORT_OBJECT)?;
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
        &ArcSequencerRecord::Candidate(request.receipt.clone()),
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
    let request_object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
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
            exec,
            PendingTerminal {
                conversation_id,
                kind: PendingKind::Abort,
                request_object_id,
                subject: core.candidate_id,
                terminal,
            },
            bytes,
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
    let signer = super::super::sequencer_signing::for_receipt(
        exec.coordinator,
        request.receipt.tbs.sequencer_key_id,
    )
    .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let candidate_id = core.candidate_id;
    let tbs = ArcCommitAbortTbs {
        profile_version: 1,
        network_id: exec.coordinator.network_id,
        conversation_id,
        route_sequence: position.route_sequence,
        predecessor_record_id: position.predecessor_record_id,
        abort_id,
        sequencer_key_id: signer.credential_id,
        request,
    };
    let certificate = ArcCommitAbortCertificate {
        sequencer_signature: signer
            .sign(SignatureDomain::CandidateAbort, &tbs)
            .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
        tbs,
    };
    let record = record_bytes(&ArcSequencerRecord::Abort(certificate))?;
    let record_id = *agenc_relay_e2ee::ObjectId::compute(&record).as_bytes();
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
    outcome.writes.extend(retire_requests(
        exec,
        &conversation_id,
        &candidate_id,
        &request_object_id,
    )?);
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
            state.ack_signers.remove(&candidate_id);
            state.vote_ledgers.remove(&candidate_id);
            state.pending_requests.remove(&candidate_id);
            state.route_object_id = route_object_id;
        }
    }));
    Ok(outcome)
}

/// `submit_reinit_attempt`: after the requester checks, an attempt on a
/// conversation whose accepted state is not the finalization of a ReInit
/// Commit is `E2EE_FINALITY_REQUIRED`, and an attempt that does not match
/// that finalization's authorized target is `E2EE_BINDING_AUTH_INVALID`,
/// both retaining nothing (companion 13.8; decision D-11a). Only then do the
/// attempt slot and the old-policy authorization decide.
// agenc-review: focus owner=runtime reviewed=2026-10-05 reason=one handler refuses an attempt outside the ReInit phase first, then checks the attempt and its carried target against the finalized ReInit Commit, records the attempt, signs the receipt, and stages the rows and events as one atomic set
pub fn submit_reinit_attempt(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let old_conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    super::route_successor::owner(exec, &old_conversation_id)?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &old_conversation_id)?;
    super::ack_context::old_group_device(exec, &old_conversation_id)?;
    let old_state = conversation(exec, &old_conversation_id)?;
    let authorized = super::reinit_authority::authorized(&old_conversation_id, log, old_state)?;
    let attempt: ArcReInitAttempt = decode(object.body(), MAX_REINIT_OBJECT)?;
    let tbs = &attempt.tbs;
    if tbs.old_conversation_id != old_conversation_id
        || tbs.network_id != exec.coordinator.network_id
    {
        return Err(Fail::with(
            E2eeReplyCode::RouteInvalid,
            &old_conversation_id,
        ));
    }
    let _work = super::reinit_authority::reserve_work(exec, &old_conversation_id, old_state)?;
    super::reinit_authority::check_attempt(&authorized, &attempt, old_state)?;
    super::recovery::vacant_successor(&exec.coordinator.state, &tbs.new_conversation_id)?;
    let mut next_log = log.clone();
    let slot = next_log
        .attempt_position()
        .map_err(|_| Fail::with(E2eeReplyCode::CandidateActive, &old_conversation_id))?;
    if slot.attempt_sequence != tbs.attempt_sequence {
        return Err(Fail::with(E2eeReplyCode::EpochStale, &old_conversation_id));
    }
    super::reinit_authority::verify(exec, &attempt)?;
    let attempt_id = CompanionCoordinator::id_of(SemanticHashDomain::ReinitAttemptId, tbs)?;
    let attempt_object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
    // The attempt receipt is signed under the old conversation's pin at the
    // attempt's trusted time; a blocked old group attempts nothing.
    old_state
        .blocked_credential_id
        .map_or(Ok(()), |_| Err(Fail::from(E2eeReplyCode::Syncing)))?;
    let signer = super::super::sequencer_signing::at_time(
        exec.coordinator,
        &old_state.sequencer_credential_id,
        exec.now,
    )
    .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let receipt_tbs = ArcReInitAttemptReceiptTbs {
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
    let receipt = ArcReInitAttemptReceipt {
        sequencer_signature: signer
            .sign(SignatureDomain::ReinitAttemptReceipt, &receipt_tbs)
            .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
        tbs: receipt_tbs,
    };
    let record = record_bytes(&ArcSequencerRecord::ReinitAttempt(receipt))?;
    let record_id = *agenc_relay_e2ee::ObjectId::compute(&record).as_bytes();
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
    let ack: ArcReInitAck = decode(object.body(), MAX_REINIT_ACK_OBJECT)?;
    let slot = log
        .reinit_attempt()
        .filter(|slot| slot.attempt_id == ack.tbs.reinit_attempt_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::FinalityRequired, &old_conversation_id))?;
    super::ack_context::reinit_submission(exec, &old_conversation_id, &ack.tbs)?;
    let signer = super::ack_context::identify_submitter(
        exec,
        &old_conversation_id,
        &AckSigner::reinit(&ack, log.accepted_epoch()),
        &ack.tbs,
    )?;
    super::ack_context::reinit_retained(exec, &old_conversation_id, &ack.tbs, slot, signer)?;
    let attempt_id = slot.attempt_id;
    let object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
    let leaf = ack.tbs.old_leaf_index;
    super::ack_context::admit_standalone(
        exec,
        &old_conversation_id,
        &attempt_id,
        leaf,
        &object_id,
        signer,
    )?;
    let signing_device = super::ack_context::signer_key(signer);
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
            state
                .ack_signers
                .entry(attempt_id)
                .or_default()
                .insert(signing_device, leaf);
        }
    }));
    Ok(outcome)
}

/// `submit_reinit_activate` (`activate`) and `submit_reinit_abort`. An
/// activation installs its successor in the same batch
/// (`reinit_install::prepare`), before any reply or event leaves.
// agenc-review: focus owner=runtime reviewed=2026-10-05 reason=one handler verifies the terminal votes, signs activation or abort, migrates or resets the log, installs an activated successor, and stages the rows and events as one atomic set
pub fn submit_reinit_terminal(exec: &mut Exec<'_>, activate: bool) -> Result<Outcome, Fail> {
    let old_conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    exec.attached_device()?;
    super::route_successor::owner(exec, &old_conversation_id)?;
    let (object, bytes) = exec.payload()?;
    let log = log(exec, &old_conversation_id)?;
    let accepted_epoch = log.accepted_epoch();
    super::ack_context::old_group_device(exec, &old_conversation_id)?;
    let request_object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
    let (attempt_id, quorum, terminal, terminal_id, activated, record) = if activate {
        let mut request: ArcReInitActivationRequest = decode(object.body(), MAX_REINIT_OBJECT)?;
        super::terminal_proof::reinit_attempt(
            exec,
            &old_conversation_id,
            &request.receipt,
            &request.attempt,
        )?;
        super::terminal_proof::reinit_activation(&request)?;
        super::ack_context::continuing_device(exec, &old_conversation_id, &request.attempt)?;
        super::ack_context::activation_coverage(
            exec,
            &old_conversation_id,
            accepted_epoch,
            &request,
        )?;
        let signer = super::super::sequencer_signing::for_receipt(
            exec.coordinator,
            request.receipt.tbs.sequencer_key_id,
        )
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
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
        let activated = request.attempt.clone();
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
        let tbs = ArcReInitActivationTbs {
            profile_version: 1,
            network_id: exec.coordinator.network_id,
            old_conversation_id,
            route_sequence: position.route_sequence,
            predecessor_record_id: position.predecessor_record_id,
            reinit_activation_id: terminal_id,
            sequencer_key_id: signer.credential_id,
            request,
        };
        let certificate = ArcReInitActivationCertificate {
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
            Some(activated),
            ArcSequencerRecord::ReinitActivation(certificate),
        )
    } else {
        let mut request: ArcReInitAbortRequest = decode(object.body(), MAX_REINIT_OBJECT)?;
        super::terminal_proof::reinit_attempt(
            exec,
            &old_conversation_id,
            &request.receipt,
            &request.attempt,
        )?;
        let signer = super::super::sequencer_signing::for_receipt(
            exec.coordinator,
            request.receipt.tbs.sequencer_key_id,
        )
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
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
        let tbs = ArcReInitAbortTbs {
            profile_version: 1,
            network_id: exec.coordinator.network_id,
            old_conversation_id,
            route_sequence: position.route_sequence,
            predecessor_record_id: position.predecessor_record_id,
            reinit_abort_id: terminal_id,
            sequencer_key_id: signer.credential_id,
            request,
        };
        let certificate = ArcReInitAbortCertificate {
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
            ArcSequencerRecord::ReinitAbort(certificate),
        )
    };
    if !quorum.reached {
        let kind = if activate {
            PendingKind::ReinitActivate
        } else {
            PendingKind::ReinitAbort
        };
        return pending(
            exec,
            PendingTerminal {
                conversation_id: old_conversation_id,
                kind,
                request_object_id,
                subject: attempt_id,
                terminal,
            },
            bytes,
            quorum,
        );
    }
    let old_state = conversation(exec, &old_conversation_id)?;
    // An activation installs its successor from the target the activated
    // attempt carries, in this batch (companion 13.8).
    let mut install = match activated.as_ref() {
        Some(attempt) => Some(super::reinit_install::prepare(
            exec,
            &old_conversation_id,
            old_state,
            attempt,
            terminal_id,
        )?),
        None => None,
    };
    let new_conversation = install.as_ref().map(|install| install.conversation_id);
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
    let record_id = *agenc_relay_e2ee::ObjectId::compute(&record).as_bytes();
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
    let refresh = super::route::refresh_head(exec, old_conversation_id, old_state, &next_log)?;
    let mut outcome = Outcome::scalar(result);
    outcome.writes.extend(refresh.writes);
    outcome.writes.extend(attempt_rows);
    outcome.writes.extend(retire_requests(
        exec,
        &old_conversation_id,
        &attempt_id,
        &request_object_id,
    )?);
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
    if let Some(install) = &mut install {
        outcome.writes.append(&mut install.writes);
        successor_route_events(exec, &mut outcome, old_conversation_id, install);
    }
    let route_object_id = refresh.route_object_id;
    let home = exec.home;
    outcome.effects.push(Box::new(move |companion| {
        if let Some(install) = install {
            install_successor(companion, old_conversation_id, install, home);
        }
        companion.logs.insert(old_conversation_id, next_log);
        if let Some(state) = companion.conversations.get_mut(&old_conversation_id) {
            state.records.insert(position.route_sequence, record_id);
            state.proofs.insert(terminal_id, request_object_id);
            state.vote_ledgers.remove(&attempt_id);
            state.pending_requests.remove(&attempt_id);
            state.route_object_id = route_object_id;
            // An activation ends the ReInit phase; an attempt abort keeps it.
            if new_conversation.is_some() {
                state.reinit = None;
            }
        }
    }));
    Ok(outcome)
}

/// The route events of an installed successor: the old route is hidden
/// from every edge entitled to it, and the successor's route state is sent
/// to every edge that holds its route, as a binding sends them.
fn successor_route_events(
    exec: &Exec<'_>,
    outcome: &mut Outcome,
    old: [u8; 32],
    install: &super::reinit_install::Install,
) {
    for target in exec
        .peers
        .iter()
        .copied()
        .filter(|peer| exec.coordinator.state.entitlements.entitled(*peer, &old))
    {
        outcome.events.push(exec.event(
            EventKind::RouteStateHidden,
            Some(old),
            target,
            0,
            Vec::new(),
            None,
        ));
    }
    for target in &install.hosts {
        outcome.events.push(exec.event(
            EventKind::RouteStateChanged,
            Some(install.conversation_id),
            *target,
            0,
            Vec::new(),
            Some(install.route_object.clone()),
        ));
    }
}

/// Applies an installed successor when its activation's batch commits: the
/// remapped route, the successor's log, lifecycle and retained facts, and
/// the delivery entitlements that send the route's traffic to it.
fn install_successor(
    companion: &mut super::super::CompanionState,
    old: [u8; 32],
    install: super::reinit_install::Install,
    home: agenc_relay_types::ServerId,
) {
    let new = install.conversation_id;
    companion.routes = install.routes;
    companion.entitlements.retire_conversation(old);
    companion.logs.insert(new, install.log);
    companion.lifecycles.insert(
        new,
        agenc_relay_domain::e2ee::lifecycle::Lifecycle::successor(),
    );
    companion.conversations.insert(new, install.state);
    if install.direct {
        let _ = companion.entitlements.require_direct(
            home,
            new,
            agenc_relay_domain::e2ee::projection::EntitlementReason::Operation,
        );
    } else {
        for host in install.hosts {
            companion.entitlements.set_channel(host, new, true);
        }
    }
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
        .filter(|bytes| {
            super::recovery_read::permitted(exec, &conversation_id, bytes)
                && super::membership::readable(exec, &conversation_id, bytes)
        })
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
