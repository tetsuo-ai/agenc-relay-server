//! The recovery lineage of a `pending` route (companion 13.7.1, 13.7.4):
//! the accepted submissions the gate retains, the records a recovery
//! installed beyond the restored head, and the historical chain resumed
//! from the authorizing prior state the restored server already holds.
//!
//! Nothing here consults a clock, signs, or mutates the restored route:
//! the resumed chain is derived from retained validated state and the
//! durable recovery rows on every use, so a restart rebuilds exactly the
//! lineage the last committed batch left.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use agenc_ircd_domain::e2ee::ConversationId;
use agenc_ircd_domain::e2ee::sequencer_log::Phase;
use agenc_ircd_e2ee::history::{
    ChainHead, ChainLimits, HistoricalChain, Lifecycle, OpenCandidate, RecordReferences,
    ResumedChain,
};
use agenc_ircd_e2ee::ids::account_id_digest;
use agenc_ircd_e2ee::limits::MAX_RECOVERY_SUBMISSION_SECONDS;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::{IrcConversationBindingPackage, action_bits};
use agenc_ircd_e2ee::objects::recovery::IrcRecoveryElementKind;
use agenc_ircd_e2ee::objects::sequencing::IrcSequencerRecord;
use agenc_ircd_e2ee::route::{PrincipalRosters, verify_binding_package};
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode as Code;
use agenc_ircd_storage::e2ee_records::{RecoveryOutcome, RecoveryRecordRow, RecoverySubmissionRow};

use super::{CompanionCoordinator, CompanionState};

/// Decode budget for one record, close, or reference object.
pub(crate) fn budget() -> DecodeBudget {
    DecodeBudget::new(1 << 20, 1 << 16)
}

/// The durable recovery rows, keyed by conversation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Recoveries {
    /// Accepted submissions by conversation and submission identifier.
    pub submissions: BTreeMap<[u8; 32], BTreeMap<[u8; 32], RecoverySubmissionRow>>,
    /// Installed records by conversation and route sequence.
    pub records: BTreeMap<[u8; 32], BTreeMap<u64, RecoveryRecordRow>>,
}

impl Recoveries {
    /// The submission, if it is retained and, when open, not expired.
    pub(crate) fn submission(
        &self,
        conversation: &[u8; 32],
        submission_id: &[u8; 32],
        now: u64,
    ) -> Option<&RecoverySubmissionRow> {
        self.submissions
            .get(conversation)?
            .get(submission_id)
            .filter(|row| !expired(row, now))
    }

    /// The open submissions of a conversation that have not expired.
    pub(crate) fn open_count(&self, conversation: &[u8; 32], now: u64) -> usize {
        self.submissions.get(conversation).map_or(0, |rows| {
            rows.values()
                .filter(|row| row.outcome == RecoveryOutcome::Open && !expired(row, now))
                .count()
        })
    }

    /// The identifiers of the submissions that expired.
    pub(crate) fn expired(&self, conversation: &[u8; 32], now: u64) -> Vec<[u8; 32]> {
        self.submissions
            .get(conversation)
            .map_or_else(Vec::new, |rows| {
                rows.iter()
                    .filter(|(_, row)| expired(row, now))
                    .map(|(id, _)| *id)
                    .collect()
            })
    }

    pub(crate) fn insert_submission(
        &mut self,
        conversation: [u8; 32],
        submission_id: [u8; 32],
        row: RecoverySubmissionRow,
    ) {
        self.submissions
            .entry(conversation)
            .or_default()
            .insert(submission_id, row);
    }

    pub(crate) fn remove_submission(&mut self, conversation: &[u8; 32], submission_id: &[u8; 32]) {
        self.submissions.entry(*conversation).and_modify(|rows| {
            rows.remove(submission_id);
        });
        self.submissions.retain(|_, rows| !rows.is_empty());
    }

    pub(crate) fn insert_record(
        &mut self,
        conversation: [u8; 32],
        route_sequence: u64,
        row: RecoveryRecordRow,
    ) {
        self.records
            .entry(conversation)
            .or_default()
            .insert(route_sequence, row);
    }
}

/// An open submission whose element did not arrive in time is discarded.
pub(crate) fn expired(row: &RecoverySubmissionRow, now: u64) -> bool {
    row.outcome == RecoveryOutcome::Open
        && now.saturating_sub(row.accepted_at) > MAX_RECOVERY_SUBMISSION_SECONDS
}

/// The lineage of one pending route, resumed and replayed.
pub(crate) struct Lineage {
    /// The chain at the current recovery head.
    pub(crate) chain: HistoricalChain,
    /// The chain before the head, when the head position can be examined
    /// for an alternative record.
    pub(crate) before_head: Option<HistoricalChain>,
    /// The bytes of every accepted submission and element.
    pub(crate) chain_bytes: u64,
}

/// The reference objects accepted for one route sequence, grouped as the
/// chain wants them.
#[derive(Default)]
pub(crate) struct References {
    policy: Option<Vec<u8>>,
    roots: Vec<Vec<u8>>,
    rosters: Vec<Vec<u8>>,
    binding: Option<Vec<u8>>,
    attempt: Option<Vec<u8>>,
}

impl References {
    /// The chain's view of these references.
    pub(crate) fn record_references<'a>(
        &'a self,
        roots: &'a [&'a [u8]],
        rosters: &'a [&'a [u8]],
    ) -> RecordReferences<'a> {
        RecordReferences {
            attempt_object: self.attempt.as_deref(),
            policy_object: self.policy.as_deref(),
            root_objects: roots,
            roster_objects: rosters,
            binding_object: self.binding.as_deref(),
            sequencer_credential: None,
            memberships: None,
        }
    }

    /// The root and roster slices the chain borrows.
    pub(crate) fn heads(&self) -> (Vec<&[u8]>, Vec<&[u8]>) {
        (
            self.roots.iter().map(Vec::as_slice).collect(),
            self.rosters.iter().map(Vec::as_slice).collect(),
        )
    }
}

/// Advances `chain` by one record with the references of its position.
pub(crate) fn advance(
    chain: &mut HistoricalChain,
    bytes: &[u8],
    references: &References,
) -> Result<agenc_ircd_e2ee::history::ChainStep, agenc_ircd_e2ee::E2eeError> {
    let (roots, rosters) = references.heads();
    chain.advance(
        bytes,
        &references.record_references(&roots, &rosters),
        &mut budget(),
    )
}

/// Examines `bytes` as an alternative record for the head position.
pub(crate) fn examine_alternative(
    chain: &HistoricalChain,
    before_head: &HistoricalChain,
    bytes: &[u8],
    references: &References,
) -> Result<agenc_ircd_e2ee::history::AlternativeRecord, agenc_ircd_e2ee::E2eeError> {
    let (roots, rosters) = references.heads();
    chain.examine_alternative(
        before_head,
        bytes,
        &references.record_references(&roots, &rosters),
        &mut budget(),
    )
}

/// The reference elements retained for `route_sequence`.
pub(crate) fn references_at(
    state: &CompanionState,
    conversation: &[u8; 32],
    route_sequence: u64,
) -> References {
    let mut references = References::default();
    let Some(rows) = state.recovery.submissions.get(conversation) else {
        return references;
    };
    for row in rows.values() {
        if row.outcome != RecoveryOutcome::Referenced || row.route_sequence != route_sequence {
            continue;
        }
        let Some(bytes) = state.objects.get(&row.element_object_id).cloned() else {
            continue;
        };
        match IrcWireObjectKind::from_value(row.element_object_kind).ok() {
            Some(IrcWireObjectKind::Policy) => references.policy = Some(bytes),
            Some(IrcWireObjectKind::RootIdentity | IrcWireObjectKind::RootIdentityChain) => {
                references.roots.push(bytes);
            }
            Some(IrcWireObjectKind::DeviceRoster) => references.rosters.push(bytes),
            Some(IrcWireObjectKind::ConversationBinding) => references.binding = Some(bytes),
            Some(IrcWireObjectKind::ReinitAttempt) => references.attempt = Some(bytes),
            _ => {}
        }
    }
    references
}

/// The head record's position facts: its predecessor and the credential
/// that signed it, and the transition target it committed.
struct HeadFacts {
    predecessor_record_id: [u8; 32],
    credential_id: [u8; 32],
    transition_target: Option<[u8; 32]>,
}

fn head_facts(bytes: &[u8]) -> Result<HeadFacts, Code> {
    let invalid = |_| Code::RouteInvalid;
    let mut budget = budget();
    let object =
        IrcWireObject::decode_kind(bytes, Some(IrcWireObjectKind::SequencerRecord), &mut budget)
            .map_err(invalid)?;
    let record = IrcSequencerRecord::decode_exact(object.body(), &mut budget).map_err(invalid)?;
    Ok(match record {
        IrcSequencerRecord::Candidate(receipt) => HeadFacts {
            predecessor_record_id: receipt.tbs.predecessor_record_id,
            credential_id: receipt.tbs.sequencer_key_id,
            transition_target: None,
        },
        IrcSequencerRecord::Finalization(certificate) => {
            let authorization = &certificate.tbs.request.proof.authorization.tbs;
            let bits = authorization.action_bits;
            // A head that committed a ReInit intent is not recoverable
            // through the carrier; a close intent is the chain's closing
            // phase.
            (bits & action_bits::REINIT == 0)
                .then_some(())
                .ok_or(Code::RouteInvalid)?;
            HeadFacts {
                predecessor_record_id: certificate.tbs.predecessor_record_id,
                credential_id: certificate.tbs.sequencer_key_id,
                transition_target: (bits & action_bits::CLOSE_INTENT != 0)
                    .then_some(authorization.transition_target_digest),
            }
        }
        IrcSequencerRecord::Abort(certificate) => HeadFacts {
            predecessor_record_id: certificate.tbs.predecessor_record_id,
            credential_id: certificate.tbs.sequencer_key_id,
            transition_target: None,
        },
        // A ReInit head is not resumable: the attempt object and successor
        // are not retained as positions, so the route stays pending.
        IrcSequencerRecord::ReinitAttempt(_)
        | IrcSequencerRecord::ReinitActivation(_)
        | IrcSequencerRecord::ReinitAbort(_) => return Err(Code::RouteInvalid),
    })
}

/// Resumes the chain at the restored head from retained validated state,
/// then replays every record the recovery installed.
pub(crate) fn resume(
    coordinator: &CompanionCoordinator,
    conversation: &[u8; 32],
) -> Result<Lineage, Code> {
    let state = &coordinator.state;
    let route_invalid = || Code::RouteInvalid;
    let conversation_state = state
        .conversations
        .get(conversation)
        .ok_or_else(route_invalid)?;
    let log = state.logs.get(conversation).ok_or_else(route_invalid)?;
    state
        .routes
        .route(&ConversationId(*conversation))
        .ok_or_else(route_invalid)?;
    let lifecycle = state
        .lifecycles
        .get(conversation)
        .ok_or_else(route_invalid)?;
    let network_id = &coordinator.network_id;

    let mut principals = PrincipalRosters::new();
    for account in &conversation_state.principal_accounts {
        let digest = account_id_digest(network_id, account).map_err(|_| Code::RouteInvalid)?;
        let (root, roster) = state.principals.get(&digest).ok_or_else(route_invalid)?;
        principals.insert(*account, (*root, roster.clone()));
    }
    let binding_bytes = state
        .objects
        .get(&conversation_state.binding_object_id)
        .ok_or_else(route_invalid)?;
    let mut decode = budget();
    let object = IrcWireObject::decode_kind(
        binding_bytes,
        Some(IrcWireObjectKind::ConversationBinding),
        &mut decode,
    )
    .map_err(|_| Code::RouteInvalid)?;
    let package = IrcConversationBindingPackage::decode_exact(object.body(), &mut decode)
        .map_err(|_| Code::RouteInvalid)?;
    let binding = verify_binding_package(network_id, &package, &principals)
        .map_err(|_| Code::RouteInvalid)?;
    let policy = conversation_state
        .policies
        .get(&conversation_state.current_policy_id)
        .ok_or_else(route_invalid)?
        .policy
        .clone();

    let head = log.head();
    let (chain_head, transition_target) = if head.recorded {
        let object_id = conversation_state
            .records
            .get(&head.sequence)
            .ok_or_else(route_invalid)?;
        let bytes = state.objects.get(object_id).ok_or_else(route_invalid)?;
        let facts = head_facts(bytes)?;
        (
            ChainHead {
                sequence: Some(head.sequence),
                record_id: head.record_id,
                object_id: Some(agenc_ircd_e2ee::ObjectId::compute(bytes)),
                predecessor_record_id: facts.predecessor_record_id,
                credential_id: facts.credential_id,
            },
            facts.transition_target,
        )
    } else {
        (
            ChainHead {
                sequence: None,
                record_id: head.record_id,
                object_id: None,
                predecessor_record_id: [0; 32],
                credential_id: binding.sequencer_credential_id,
            },
            None,
        )
    };
    // The credential committed for the next position: the one that signed
    // the head, or at the anchor the credential the binding pins, falling
    // back to the installed current credential the restored server holds.
    // A recorded head names the credential that signed it; the genesis
    // anchor takes the binding's credential, or the current one when the
    // restored state retains no credential under that identifier.
    let sequencer = if head.recorded {
        *coordinator
            .credential(&chain_head.credential_id)
            .ok_or_else(route_invalid)?
    } else {
        *coordinator
            .credential(&chain_head.credential_id)
            .or_else(|| coordinator.current_verified_credential())
            .ok_or_else(route_invalid)?
    };
    let chain_head = ChainHead {
        credential_id: sequencer.credential_id,
        ..chain_head
    };
    let candidate = log.candidate().map(|slot| OpenCandidate {
        candidate_id: slot.candidate_id,
        route_sequence: slot.position.route_sequence,
        candidate_sequence: slot.position.candidate_sequence,
        predecessor_record_id: slot.position.predecessor_record_id,
        commit_object_id: slot.commit_object_id,
        credential_id: chain_head.credential_id,
    });
    let next_candidate_sequence = match candidate {
        Some(open) => open.candidate_sequence.saturating_add(1),
        None => log
            .candidate_position(log.accepted_epoch())
            .map(|position| position.candidate_sequence)
            .unwrap_or(0),
    };
    // The head's own committed intent fixes the chain's phase, exactly as
    // adopting that head would have.
    let chain_lifecycle = match (log.phase(), transition_target) {
        (Phase::Open, Some(close_intent_id)) => Lifecycle::Closing { close_intent_id },
        (Phase::Open, None) => Lifecycle::Active,
        (Phase::Closed { close_id }, _) => Lifecycle::Closed { close_id },
        // ReInit lineages resume nothing: their attempt positions are not
        // retained as chain facts.
        (Phase::Reinit { .. } | Phase::Migrated { .. }, _) => return Err(Code::RouteInvalid),
    };
    let resumed = ResumedChain {
        binding,
        principals,
        policy,
        sequencer,
        required_operational_policy_id: conversation_state.required_operational_policy_id,
        bootstrap_pending: lifecycle.bootstrap_pending(),
        epoch: log.accepted_epoch(),
        accepted_state_id: *log.accepted_state_id(),
        head: chain_head,
        candidate,
        next_candidate_sequence,
        lifecycle: chain_lifecycle,
    };
    let before_head = candidate.map(|open| ResumedChain {
        head: ChainHead {
            sequence: open.route_sequence.checked_sub(1),
            record_id: open.predecessor_record_id,
            object_id: None,
            predecessor_record_id: [0; 32],
            credential_id: chain_head.credential_id,
        },
        candidate: None,
        next_candidate_sequence: open.candidate_sequence,
        ..resumed.clone()
    });
    let limits = ChainLimits::DEFAULT;
    let mut chain = HistoricalChain::resume(network_id, conversation, resumed, limits)
        .map_err(|_| Code::RouteInvalid)?;
    let mut before_head = before_head
        .map(|resumed| HistoricalChain::resume(network_id, conversation, resumed, limits))
        .transpose()
        .map_err(|_| Code::RouteInvalid)?;
    let mut chain_bytes = 0_u64;
    if let Some(rows) = state.recovery.submissions.get(conversation) {
        for row in rows.values() {
            let submission = state
                .objects
                .get(&row.submission_object_id)
                .map_or(0, Vec::len);
            let element = if row.element_retained {
                state
                    .objects
                    .get(&row.element_object_id)
                    .map_or(0, Vec::len)
            } else {
                0
            };
            chain_bytes = chain_bytes
                .saturating_add(u64::try_from(submission).unwrap_or(u64::MAX))
                .saturating_add(u64::try_from(element).unwrap_or(u64::MAX));
        }
    }
    if let Some(records) = state.recovery.records.get(conversation) {
        for (sequence, row) in records {
            let bytes = state
                .objects
                .get(&row.record_object_id)
                .ok_or_else(route_invalid)?;
            let references = references_at(state, conversation, *sequence);
            let previous = chain.clone();
            advance(&mut chain, bytes, &references).map_err(|_| Code::RouteInvalid)?;
            before_head = Some(previous);
        }
    }
    Ok(Lineage {
        chain,
        before_head,
        chain_bytes,
    })
}

/// The `IrcRecoveryElementKind` a row carries.
pub(crate) fn element_kind(row: &RecoverySubmissionRow) -> Option<IrcRecoveryElementKind> {
    match row.element_kind {
        1 => Some(IrcRecoveryElementKind::RecordElement),
        2 => Some(IrcRecoveryElementKind::CloseElement),
        3 => Some(IrcRecoveryElementKind::ReferenceElement),
        _ => None,
    }
}
