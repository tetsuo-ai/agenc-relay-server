//! The recovery submission carrier (companion 13.7.4): a pending route
//! accepts signed submissions from attached principal devices and, when
//! the named element arrives, extends the restored head, installs the
//! permanent `closed` gate with the finalized close, or installs the
//! permanent `conflict` gate for a second valid record at an installed
//! position. The restored server verifies every element through the
//! resumed historical chain and never signs a missing link.

#![forbid(unsafe_code)]

use agenc_relay_crypto::StorageDigest;
use agenc_relay_domain::e2ee::lifecycle::RecoveryGate;
use agenc_relay_domain::e2ee::projection::EventKind;
use agenc_relay_domain::e2ee::sequencer_log::{Head, Phase, SequencerLog};
use agenc_relay_domain::e2ee::{ConversationId, RecoveryState, RouteTarget};
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::history::{AlternativeRecord, ChainStep};
use agenc_relay_e2ee::limits::{
    MAX_OPEN_RECOVERY_SUBMISSIONS, MAX_RECOVERY_CHAIN_BYTES, MAX_RECOVERY_SUBMISSION_OBJECT,
};
use agenc_relay_e2ee::object::ArcWireObjectKind;
use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
use agenc_relay_e2ee::objects::federation::ArcRouteStateKind;
use agenc_relay_e2ee::objects::recovery::{ArcRecoveryElementKind, ArcRecoverySubmission};
use agenc_relay_e2ee::objects::sequencing::ArcSequencerRecord;
use agenc_relay_e2ee::recovery::{RecoveryRefusal, verify_recovery_submission};
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::e2ee_records::{
    RECOVERY_GATE_KIND, RECOVERY_RECORD_ROW_KIND, RECOVERY_SUBMISSION_ROW_KIND, ROUTE_ROW_KIND,
    RecoveryOutcome, RecoveryRecordRow, RecoverySubmissionRow, RouteLifecycle as RowLifecycle,
    RouteRow, recovery_gate_key,
};
use agenc_relay_storage::{E2eeRecoveryGate, E2eeRecoveryKind, TableId};

use super::super::recovery_lineage::{
    self, Lineage, advance, budget, element_kind, examine_alternative, references_at, resume,
};
use super::super::request::{Outcome, ResultBody, state_row};
use super::super::{CompanionCoordinator, CompanionState};
use super::{Exec, Fail};

type Write = crate::state_core::durable::AccountServiceDurableWrite;

fn fail(code: E2eeReplyCode, context: &[u8; 32]) -> Fail {
    Fail::with(code, context)
}

/// The durable gate of a `pending` route.
fn pending_gate(exec: &Exec<'_>, conversation_id: &[u8; 32]) -> Result<E2eeRecoveryGate, Fail> {
    exec.coordinator
        .state
        .recovery_gates
        .get(conversation_id)
        .filter(|gate| gate.state() == E2eeRecoveryKind::Pending)
        .ok_or_else(|| fail(E2eeReplyCode::RouteInvalid, conversation_id))
}

fn lineage(exec: &Exec<'_>, conversation_id: &[u8; 32]) -> Result<Lineage, Fail> {
    resume(exec.coordinator, conversation_id).map_err(|code| fail(code, conversation_id))
}

fn submission_write(
    conversation_id: &[u8; 32],
    submission_id: &[u8; 32],
    row: &RecoverySubmissionRow,
) -> Result<Write, Fail> {
    let encoding = || Fail::from(E2eeReplyCode::InvalidFragment);
    state_row(
        TableId::E2eeState,
        RECOVERY_SUBMISSION_ROW_KIND,
        RecoverySubmissionRow::key(conversation_id, submission_id).map_err(|_| encoding())?,
        row.encode().map_err(|_| encoding())?,
    )
    .map_err(Fail::from)
}

/// Drops every expired open submission of the conversation with this batch.
fn discard_expired(
    exec: &Exec<'_>,
    conversation_id: [u8; 32],
    outcome: &mut Outcome,
) -> Result<(), Fail> {
    let expired = exec
        .coordinator
        .state
        .recovery
        .expired(&conversation_id, exec.now);
    for id in &expired {
        let key = RecoverySubmissionRow::key(&conversation_id, id)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        outcome.writes.push(
            Write::delete(TableId::E2eeState, key)
                .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        );
    }
    if !expired.is_empty() {
        outcome.effects.push(Box::new(move |state| {
            for id in &expired {
                state.recovery.remove_submission(&conversation_id, id);
            }
        }));
    }
    Ok(())
}

/// `EGROUP SUBMIT RECOVERY`: accepts a signed submission for the next
/// chain position, or for the head position when it names a record.
pub(super) fn submit_recovery(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let conversation_id = exec.params().read(|reader| reader.fixed::<32>())?;
    let (device, _) = exec.attached_device()?;
    let gate = pending_gate(exec, &conversation_id)?;
    let (object, bytes) = exec.payload()?;
    let submission = decode_submission(object, &conversation_id)?;
    check_context(exec, &conversation_id, &gate, &submission)?;
    let (verified, account) = verify_submitter(exec, &conversation_id, device, &submission)?;
    let object_id = *ObjectId::compute(bytes).as_bytes();
    if let Some(prior) = duplicate(exec, &conversation_id, &verified, object_id)? {
        return Ok(prior);
    }
    let lineage = lineage(exec, &conversation_id)?;
    admit_position(&lineage, &verified, &conversation_id)?;
    admit_ceilings(exec, &lineage, &conversation_id, bytes.len())?;
    let row = RecoverySubmissionRow {
        account_id: account,
        device_id: device,
        element_kind: verified.element_kind.value(),
        element_object_kind: verified.element_object_kind.value(),
        element_object_id: verified.element_object_id,
        route_sequence: verified.route_sequence,
        predecessor_record_id: verified.predecessor_record_id,
        accepted_at: exec.now,
        submission_object_id: object_id,
        element_retained: false,
        outcome: RecoveryOutcome::Open,
    };
    let submission_id = verified.submission_id;
    let mut outcome = Outcome::scalar(ResultBody::RecoveryAccepted(conversation_id, submission_id));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome
        .writes
        .push(submission_write(&conversation_id, &submission_id, &row)?);
    discard_expired(exec, conversation_id, &mut outcome)?;
    outcome.effects.push(Box::new(move |state| {
        state
            .recovery
            .insert_submission(conversation_id, submission_id, row);
    }));
    Ok(outcome)
}

fn decode_submission(
    object: &agenc_relay_e2ee::object::ArcWireObject,
    conversation_id: &[u8; 32],
) -> Result<ArcRecoverySubmission, Fail> {
    let malformed = || fail(E2eeReplyCode::InvalidFragment, conversation_id);
    if object.kind() != ArcWireObjectKind::RecoverySubmission {
        return Err(malformed());
    }
    let mut decode = DecodeBudget::new(MAX_RECOVERY_SUBMISSION_OBJECT, 1 << 12);
    ArcRecoverySubmission::decode_exact(object.body(), &mut decode).map_err(|_| malformed())
}

/// The submission must name this network, conversation and exactly the
/// durable gate's epoch, guard and restored heads (`E2EE_ROUTE_INVALID`).
fn check_context(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    gate: &E2eeRecoveryGate,
    submission: &ArcRecoverySubmission,
) -> Result<(), Fail> {
    let tbs = &submission.tbs;
    let context = (
        tbs.network_id,
        tbs.conversation_id,
        tbs.recovery_epoch,
        tbs.restored_binding_id,
        tbs.restored_accepted_state_id,
        tbs.restored_sequencer_head_id,
        tbs.source_rollback_guard_hash,
    );
    let expected = (
        exec.coordinator.network_id,
        *conversation_id,
        *gate.recovery_epoch().as_bytes(),
        *gate.restored_binding_id().as_bytes(),
        *gate.restored_accepted_state_id().as_bytes(),
        *gate.restored_sequencer_head_id().as_bytes(),
        *gate.source_rollback_guard_hash().as_bytes(),
    );
    if context == expected {
        Ok(())
    } else {
        Err(fail(E2eeReplyCode::RouteInvalid, conversation_id))
    }
}

/// The submitter is the attached device of a binding principal whose
/// certificate is active in the account's retained roster, and the device
/// signature verifies.
fn verify_submitter(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    device: [u8; 16],
    submission: &ArcRecoverySubmission,
) -> Result<
    (
        agenc_relay_e2ee::recovery::VerifiedRecoverySubmission,
        [u8; 24],
    ),
    Fail,
> {
    let tbs = &submission.tbs;
    if tbs.device_id != device {
        return Err(fail(E2eeReplyCode::DeviceRequired, conversation_id));
    }
    let account = exec.account_id()?;
    let state = exec
        .coordinator
        .state
        .conversations
        .get(conversation_id)
        .ok_or_else(|| fail(E2eeReplyCode::RouteInvalid, conversation_id))?;
    // The attached account signs for itself and is a principal of the
    // restored binding.
    (tbs.account_id.as_slice() == account && state.principal_accounts.contains(&account))
        .then_some(())
        .ok_or_else(|| fail(E2eeReplyCode::BindingAuthInvalid, conversation_id))?;
    let (_, roster) = exec
        .coordinator
        .state
        .principals
        .get(&exec.account_digest()?)
        .ok_or_else(|| fail(E2eeReplyCode::BindingAuthInvalid, conversation_id))?;
    let verified = verify_recovery_submission(&exec.coordinator.network_id, submission, roster)
        .map_err(|refusal| match refusal {
            RecoveryRefusal::Invalid => fail(E2eeReplyCode::InvalidFragment, conversation_id),
            RecoveryRefusal::DeviceInactive => fail(E2eeReplyCode::DeviceRequired, conversation_id),
            RecoveryRefusal::SignatureInvalid => {
                fail(E2eeReplyCode::BindingAuthInvalid, conversation_id)
            }
        })?;
    Ok((verified, account))
}

/// An exact duplicate of a retained submission repeats the prior reply;
/// another object under the same identifier is refused.
fn duplicate(
    exec: &Exec<'_>,
    conversation_id: &[u8; 32],
    verified: &agenc_relay_e2ee::recovery::VerifiedRecoverySubmission,
    object_id: [u8; 32],
) -> Result<Option<Outcome>, Fail> {
    let Some(existing) = exec.coordinator.state.recovery.submission(
        conversation_id,
        &verified.submission_id,
        exec.now,
    ) else {
        return Ok(None);
    };
    // The identifier covers every signed field, so another object under it
    // can only differ in its signature bytes.
    (existing.submission_object_id == object_id)
        .then(|| {
            Some(Outcome::scalar(ResultBody::RecoveryAccepted(
                *conversation_id,
                verified.submission_id,
            )))
        })
        .ok_or_else(|| fail(E2eeReplyCode::BindingAuthInvalid, conversation_id))
}

/// A submission names the next position, or the head position when it
/// carries a record (a re-upload or a competing successor).
fn admit_position(
    lineage: &Lineage,
    verified: &agenc_relay_e2ee::recovery::VerifiedRecoverySubmission,
    conversation_id: &[u8; 32],
) -> Result<(), Fail> {
    let route_invalid = || fail(E2eeReplyCode::RouteInvalid, conversation_id);
    // A terminal chain only exists under a closed or conflict gate, which
    // the pending-gate check refused already.
    (!lineage.chain.is_terminal())
        .then_some(())
        .ok_or_else(route_invalid)?;
    let position = lineage.chain.next_position().map_err(|_| route_invalid())?;
    let head = lineage.chain.head();
    let at_next = verified.route_sequence == position.route_sequence
        && verified.predecessor_record_id == position.predecessor_record_id;
    let at_head = head.sequence == Some(verified.route_sequence)
        && verified.predecessor_record_id == head.predecessor_record_id
        && verified.element_kind == ArcRecoveryElementKind::RecordElement;
    if at_next || at_head {
        Ok(())
    } else {
        Err(route_invalid())
    }
}

/// The open-submission and chain-byte ceilings (`E2EE_RATE_LIMITED`).
fn admit_ceilings(
    exec: &Exec<'_>,
    lineage: &Lineage,
    conversation_id: &[u8; 32],
    bytes: usize,
) -> Result<(), Fail> {
    let size = u64::try_from(bytes).unwrap_or(u64::MAX);
    let open = exec
        .coordinator
        .state
        .recovery
        .open_count(conversation_id, exec.now);
    if open >= MAX_OPEN_RECOVERY_SUBMISSIONS {
        return Err(fail(E2eeReplyCode::RateLimited, conversation_id));
    }
    (lineage.chain_bytes.saturating_add(size) <= MAX_RECOVERY_CHAIN_BYTES)
        .then_some(())
        .ok_or_else(|| fail(E2eeReplyCode::RateLimited, conversation_id))
}

/// `EGROUP SUBMIT RECOVERY-ELEMENT`: delivers the element an accepted
/// submission names.
pub(super) fn submit_recovery_element(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (conversation_id, submission_id) = exec
        .params()
        .read(|reader| Ok((reader.fixed::<32>()?, reader.fixed::<32>()?)))?;
    let (device, _) = exec.attached_device()?;
    let gate = pending_gate(exec, &conversation_id)?;
    let row = *exec
        .coordinator
        .state
        .recovery
        .submission(&conversation_id, &submission_id, exec.now)
        .ok_or_else(|| fail(E2eeReplyCode::ObjectNotFound, &conversation_id))?;
    if row.device_id != device {
        return Err(fail(E2eeReplyCode::DeviceRequired, &conversation_id));
    }
    if row.account_id != exec.account_id()? {
        return Err(fail(E2eeReplyCode::BindingAuthInvalid, &conversation_id));
    }
    let (object, bytes) = exec.payload()?;
    if object.kind().value() != row.element_object_kind {
        return Err(fail(E2eeReplyCode::InvalidFragment, &conversation_id));
    }
    let object_id = *ObjectId::compute(bytes).as_bytes();
    if object_id != row.element_object_id {
        return Err(fail(E2eeReplyCode::HashMismatch, &conversation_id));
    }
    let lineage = lineage(exec, &conversation_id)?;
    // An exact duplicate of a completed element repeats the prior reply.
    if let Some(prior) = prior_reply(&conversation_id, &row, &lineage) {
        return Ok(Outcome::scalar(prior));
    }
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if lineage.chain_bytes.saturating_add(size) > MAX_RECOVERY_CHAIN_BYTES {
        return Err(fail(E2eeReplyCode::RateLimited, &conversation_id));
    }
    let element = Element {
        conversation_id,
        submission_id,
        row,
        bytes,
        gate,
    };
    match element_kind(&row)
        .ok_or_else(|| fail(E2eeReplyCode::InvalidFragment, &conversation_id))?
    {
        ArcRecoveryElementKind::ReferenceElement => element.reference(&lineage),
        ArcRecoveryElementKind::RecordElement => element.record(exec, &lineage),
        ArcRecoveryElementKind::CloseElement => element.close(exec, &lineage),
    }
}

/// The reply a completed submission's element already produced.
fn prior_reply(
    conversation_id: &[u8; 32],
    row: &RecoverySubmissionRow,
    lineage: &Lineage,
) -> Option<ResultBody> {
    Some(match row.outcome {
        RecoveryOutcome::Open => return None,
        RecoveryOutcome::Extended { record_id } => {
            ResultBody::RecoveryExtended(*conversation_id, row.route_sequence, record_id)
        }
        RecoveryOutcome::Closed { close_id } => {
            ResultBody::RecoveryClosed(*conversation_id, close_id)
        }
        RecoveryOutcome::Conflict {
            installed_record_id,
            conflicting_record_id,
        } => ResultBody::RecoveryConflict(
            *conversation_id,
            row.route_sequence,
            installed_record_id,
            conflicting_record_id,
        ),
        RecoveryOutcome::Referenced => {
            let head = lineage.chain.head();
            ResultBody::RecoveryExtended(
                *conversation_id,
                head.sequence.unwrap_or(0),
                head.record_id,
            )
        }
    })
}

/// The facts a verified close installs.
struct Closing {
    close_id: [u8; 32],
    route_sequence: u64,
    log: SequencerLog,
    route_object: Vec<u8>,
    row: RouteRow,
}

/// One arriving element with its accepted submission.
struct Element<'a> {
    conversation_id: [u8; 32],
    submission_id: [u8; 32],
    row: RecoverySubmissionRow,
    bytes: &'a [u8],
    gate: E2eeRecoveryGate,
}

impl Element<'_> {
    fn head_reply(&self, lineage: &Lineage) -> ResultBody {
        let head = lineage.chain.head();
        ResultBody::RecoveryExtended(
            self.conversation_id,
            head.sequence.unwrap_or(0),
            head.record_id,
        )
    }

    /// Retains the element under its row with `outcome`.
    fn retained(&self, outcome: RecoveryOutcome, result: ResultBody) -> Result<Outcome, Fail> {
        let conversation_id = self.conversation_id;
        let submission_id = self.submission_id;
        let row = RecoverySubmissionRow {
            element_retained: true,
            outcome,
            ..self.row
        };
        let mut prepared = Outcome::scalar(result);
        prepared
            .writes
            .push(CompanionCoordinator::object_write(self.bytes)?);
        prepared
            .writes
            .push(submission_write(&conversation_id, &submission_id, &row)?);
        prepared.effects.push(Box::new(move |state| {
            state
                .recovery
                .insert_submission(conversation_id, submission_id, row);
        }));
        Ok(prepared)
    }

    fn reference(&self, lineage: &Lineage) -> Result<Outcome, Fail> {
        self.retained(RecoveryOutcome::Referenced, self.head_reply(lineage))
    }

    fn record(&self, exec: &Exec<'_>, lineage: &Lineage) -> Result<Outcome, Fail> {
        let conversation_id = self.conversation_id;
        let head = *lineage.chain.head();
        let position = lineage
            .chain
            .next_position()
            .map_err(|_| fail(E2eeReplyCode::RouteInvalid, &conversation_id))?;
        let references = references_at(
            &exec.coordinator.state,
            &conversation_id,
            self.row.route_sequence,
        );
        let named = (self.row.route_sequence, self.row.predecessor_record_id);
        if named == (position.route_sequence, position.predecessor_record_id) {
            let mut next = lineage.chain.clone();
            let step = advance(&mut next, self.bytes, &references)
                .map_err(|_| fail(E2eeReplyCode::BindingAuthInvalid, &conversation_id))?;
            return self.extended(
                position.route_sequence,
                position.predecessor_record_id,
                step,
            );
        }
        // Admission accepted the submission at the next position or the
        // head, and the chain has not moved under an open submission.
        ((Some(named.0), named.1) == (head.sequence, head.predecessor_record_id))
            .then_some(())
            .ok_or_else(|| fail(E2eeReplyCode::RouteInvalid, &conversation_id))?;
        // The head position: a byte-identical re-upload repeats the prior
        // reply; a second valid record is a permanent conflict.
        if head.object_id == Some(ObjectId::compute(self.bytes)) {
            return self.retained(
                RecoveryOutcome::Extended {
                    record_id: head.record_id,
                },
                self.head_reply(lineage),
            );
        }
        let before = lineage
            .before_head
            .as_ref()
            .ok_or_else(|| fail(E2eeReplyCode::RouteInvalid, &conversation_id))?;
        match examine_alternative(&lineage.chain, before, self.bytes, &references)
            .map_err(|_| fail(E2eeReplyCode::BindingAuthInvalid, &conversation_id))?
        {
            AlternativeRecord::SameRecord { .. } => self.retained(
                RecoveryOutcome::Extended {
                    record_id: head.record_id,
                },
                self.head_reply(lineage),
            ),
            AlternativeRecord::Conflict {
                installed_record_id,
                conflicting_record_id,
                ..
            } => self.conflict(
                exec,
                self.row.route_sequence,
                installed_record_id,
                conflicting_record_id,
            ),
        }
    }

    fn extended(
        &self,
        route_sequence: u64,
        predecessor_record_id: [u8; 32],
        step: ChainStep,
    ) -> Result<Outcome, Fail> {
        let conversation_id = self.conversation_id;
        let record_id = match step {
            ChainStep::Candidate(open) => open.candidate_id,
            ChainStep::Finalized {
                finalization_id, ..
            } => finalization_id,
            ChainStep::Aborted { abort_id, .. } => abort_id,
            ChainStep::ReinitAttempted(attempt) => attempt.attempt_id,
            ChainStep::ReinitActivated {
                reinit_activation_id,
                ..
            } => reinit_activation_id,
            ChainStep::ReinitAborted {
                reinit_abort_id, ..
            } => reinit_abort_id,
        };
        let record_kind = record_kind_of(self.bytes)
            .ok_or_else(|| fail(E2eeReplyCode::InvalidFragment, &conversation_id))?;
        let record = RecoveryRecordRow {
            record_id,
            record_object_id: *ObjectId::compute(self.bytes).as_bytes(),
            predecessor_record_id,
            record_kind,
            submission_id: self.submission_id,
        };
        let mut outcome = self.retained(
            RecoveryOutcome::Extended { record_id },
            ResultBody::RecoveryExtended(conversation_id, route_sequence, record_id),
        )?;
        outcome.security_mutation = true;
        let encoding = || Fail::from(E2eeReplyCode::InvalidFragment);
        outcome.writes.push(
            state_row(
                TableId::E2eeState,
                RECOVERY_RECORD_ROW_KIND,
                RecoveryRecordRow::key(&conversation_id, route_sequence).map_err(|_| encoding())?,
                record.encode().map_err(|_| encoding())?,
            )
            .map_err(Fail::from)?,
        );
        outcome.effects.push(Box::new(move |state| {
            state
                .recovery
                .insert_record(conversation_id, route_sequence, record);
        }));
        Ok(outcome)
    }

    fn conflict(
        &self,
        exec: &Exec<'_>,
        route_sequence: u64,
        installed_record_id: [u8; 32],
        conflicting_record_id: [u8; 32],
    ) -> Result<Outcome, Fail> {
        let conversation_id = self.conversation_id;
        let gate = self.gate_with(E2eeRecoveryKind::Conflict);
        let mut outcome = self.retained(
            RecoveryOutcome::Conflict {
                installed_record_id,
                conflicting_record_id,
            },
            ResultBody::RecoveryConflict(
                conversation_id,
                route_sequence,
                installed_record_id,
                conflicting_record_id,
            ),
        )?;
        outcome.security_mutation = true;
        outcome.writes.push(gate_write(&conversation_id, gate)?);
        let _ = exec;
        outcome.effects.push(Box::new(move |state| {
            install_gate(state, conversation_id, gate, RecoveryState::Conflict, None);
        }));
        Ok(outcome)
    }

    fn close(&self, exec: &Exec<'_>, lineage: &Lineage) -> Result<Outcome, Fail> {
        let conversation_id = self.conversation_id;
        let route_invalid = || fail(E2eeReplyCode::RouteInvalid, &conversation_id);
        let position = lineage.chain.next_position().map_err(|_| route_invalid())?;
        // Admission accepted the close at the next position only.
        ((self.row.route_sequence, self.row.predecessor_record_id)
            == (position.route_sequence, position.predecessor_record_id))
            .then_some(())
            .ok_or_else(route_invalid)?;
        let mut closed = lineage.chain.clone();
        let close_id = closed
            .close(self.bytes, &mut budget())
            .map_err(|_| fail(E2eeReplyCode::BindingAuthInvalid, &conversation_id))?;
        let closing = self.tombstone(exec, &closed, close_id, position.route_sequence)?;
        self.closed(exec, closing)
    }

    /// The closed log, tombstone route object and route row the close installs.
    fn tombstone(
        &self,
        exec: &Exec<'_>,
        closed: &agenc_relay_e2ee::history::HistoricalChain,
        close_id: [u8; 32],
        route_sequence: u64,
    ) -> Result<Closing, Fail> {
        let conversation_id = self.conversation_id;
        let route_invalid = || fail(E2eeReplyCode::RouteInvalid, &conversation_id);
        let state = exec
            .coordinator
            .state
            .conversations
            .get(&conversation_id)
            .ok_or_else(route_invalid)?;
        let route = exec
            .coordinator
            .state
            .routes
            .route(&ConversationId(conversation_id))
            .ok_or_else(route_invalid)?;
        let (kind, instance) = match route.target {
            RouteTarget::Channel(channel) => {
                (ArcConversationKind::Channel, Some(*channel.as_bytes()))
            }
            RouteTarget::Direct(_) => (ArcConversationKind::Direct, None),
        };
        let log = SequencerLog::restore(
            conversation_id,
            Head {
                sequence: route_sequence,
                record_id: close_id,
                recorded: true,
            },
            *closed.accepted_state_id(),
            closed.epoch(),
            Phase::Closed { close_id },
        );
        let route_object = super::route::route_state_object(
            exec,
            state,
            &log,
            kind,
            instance,
            ArcRouteStateKind::EncryptedTombstone,
            exec.state_generation,
        )?;
        let row = RouteRow {
            route_state: route_object.clone(),
            lifecycle: RowLifecycle::Tombstone,
            binding_id: state.binding,
            lock_id: state.lock_id,
            accepted_state_id: *closed.accepted_state_id(),
            sequencer_head_id: close_id,
            route_sequence,
            close_id: Some(close_id),
            predecessor_close_id: state.predecessor_close_id,
            recovery_gate: false,
            stored_bytes: state.stored_bytes,
            sequencer_credential_id: Some(state.sequencer_credential_id),
            blocked_credential_id: None,
        };
        Ok(Closing {
            close_id,
            route_sequence,
            log,
            route_object,
            row,
        })
    }

    /// Stages the joint transaction: the close object, the tombstone route
    /// row and object, the `closed` gate and the completed submission; the
    /// records the recovery installed stay under their own rows, retained
    /// with the tombstone, and the restored route's own rows are untouched.
    fn closed(&self, exec: &Exec<'_>, closing: Closing) -> Result<Outcome, Fail> {
        let conversation_id = self.conversation_id;
        let Closing {
            close_id,
            route_sequence,
            log,
            route_object,
            row,
        } = closing;
        let gate = self.gate_with(E2eeRecoveryKind::Closed);
        let mut outcome = self.retained(
            RecoveryOutcome::Closed { close_id },
            ResultBody::RecoveryClosed(conversation_id, close_id),
        )?;
        outcome.security_mutation = true;
        let encoding = || Fail::from(E2eeReplyCode::InvalidFragment);
        outcome
            .writes
            .push(CompanionCoordinator::object_write(&route_object)?);
        outcome.writes.push(
            state_row(
                TableId::E2eeState,
                ROUTE_ROW_KIND,
                RouteRow::key(&conversation_id).map_err(|_| encoding())?,
                row.encode().map_err(|_| encoding())?,
            )
            .map_err(Fail::from)?,
        );
        outcome.writes.push(gate_write(&conversation_id, gate)?);
        for target in super::route::audience(exec, &conversation_id)? {
            outcome.events.push(exec.event(
                EventKind::RouteStateChanged,
                Some(conversation_id),
                target,
                route_sequence,
                Vec::new(),
                Some(route_object.clone()),
            ));
        }
        let route_object_id = *ObjectId::compute(&route_object).as_bytes();
        outcome.effects.push(Box::new(move |companion| {
            install_gate(
                companion,
                conversation_id,
                gate,
                RecoveryState::Closed,
                Some(close_id),
            );
            companion.logs.insert(conversation_id, log);
            companion
                .conversations
                .entry(conversation_id)
                .and_modify(|state| state.route_object_id = route_object_id);
        }));
        Ok(outcome)
    }

    fn gate_with(&self, kind: E2eeRecoveryKind) -> E2eeRecoveryGate {
        E2eeRecoveryGate::new(
            StorageDigest::from_bytes(self.conversation_id),
            kind,
            self.gate.recovery_epoch(),
            self.gate.restored_binding_id(),
            self.gate.restored_accepted_state_id(),
            self.gate.restored_sequencer_head_id(),
            self.gate.source_rollback_guard_hash(),
        )
    }
}

fn gate_write(conversation_id: &[u8; 32], gate: E2eeRecoveryGate) -> Result<Write, Fail> {
    let encoding = || Fail::from(E2eeReplyCode::InvalidFragment);
    state_row(
        TableId::E2eeState,
        RECOVERY_GATE_KIND,
        recovery_gate_key(conversation_id).map_err(|_| encoding())?,
        gate.encode().map_err(|_| encoding())?,
    )
    .map_err(Fail::from)
}

/// Installs a terminal gate in memory once its batch committed: the gate
/// row, the route entry and the lifecycle move together and never back.
fn install_gate(
    state: &mut CompanionState,
    conversation_id: [u8; 32],
    gate: E2eeRecoveryGate,
    outcome: RecoveryState,
    close_id: Option<[u8; 32]>,
) {
    state.recovery_gates.replace(&conversation_id, gate);
    let _ = state
        .routes
        .resolve_recovery(&ConversationId(conversation_id), outcome, close_id);
    let target = match outcome {
        RecoveryState::Closed => RecoveryGate::Closed,
        _ => RecoveryGate::Conflict,
    };
    state
        .lifecycles
        .entry(conversation_id)
        .and_modify(|lifecycle| {
            let _ = lifecycle.resolve_recovery(target);
        });
}

/// The `ArcSequencerRecordKind` wire value of a record object.
fn record_kind_of(bytes: &[u8]) -> Option<u8> {
    let mut decode = recovery_lineage::budget();
    let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::SequencerRecord),
        &mut decode,
    )
    .ok()?;
    ArcSequencerRecord::decode_exact(object.body(), &mut decode)
        .ok()
        .map(|record| record.kind().value())
}
