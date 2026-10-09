//! Historical public authority: one continuous chain from the independently
//! pinned genesis binding to a typed terminal (companion Sections 9.3 to
//! 9.5, 12.2 to 12.4, 13.7.1 to 13.7.2, and 13.8).
//!
//! [`HistoricalChain`] composes [`crate::initial_authority`] and
//! [`crate::record_authentication`] with the policy, roster, root, binding,
//! sequencer, finality, and close verifiers: every record is authenticated
//! at exactly the next position under the credential the validated history
//! committed for it, every transition it certifies is proved by the public
//! object the caller supplies, and every council quorum is recounted from
//! device signatures under the retained old policy, independently of the
//! sequencer signature. The result is an opaque typed value carrying the
//! exact validated anchors; a caller cannot manufacture recovery authority
//! from bare identifiers.
//!
//! Endpoint-only, never claimed here: MLS leaf membership behind an ACK, the
//! copath coverage of an ACK set, the staged result a voter compared, and
//! the exact continuing set of a ReInit. No clock, directory, storage owner,
//! signing secret, or MLS private state enters this module.

#![forbid(unsafe_code)]

mod finalization;
mod liveness;
mod membership;
mod reinit;

use crate::close::verify_close_approvals;
use crate::error::E2eeError;
use crate::ids::{SemanticId, semantic_id_of};
use crate::initial_authority::InitialAuthority;
use crate::object::{ArcWireObject, ArcWireObjectKind, ObjectId};
use crate::objects::conversation::{ArcCloseAuthorization, action_bits};
use crate::objects::reinit::ArcReInitTargetTbs;
use crate::objects::sequencing::{
    ArcCandidateReceipt, ArcCommitAbortCertificate, ArcGroupGenesisTbs, ArcSequencerRecord,
};
use crate::policy::VerifiedPolicy;
use crate::record_authentication::{ExpectedRecord, authenticate_decoded_record};
use crate::route::{PrincipalRosters, VerifiedBinding};
use crate::sequencer::VerifiedSequencerCredential;
use crate::tls::{DecodeBudget, Opaque, TlsDecode};
use agenc_relay_crypto::SemanticHashDomain;

/// Bounds on the work one chain may perform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainLimits {
    /// Records the chain may still adopt, terminal close included.
    pub max_records: u32,
}

impl ChainLimits {
    /// The profile default: one record per retained sequencer position of
    /// a conversation that lived through the maximum candidate churn.
    pub const DEFAULT: Self = Self {
        max_records: 65_536,
    };
}

/// The public objects a record may need beyond itself. Every entry is a
/// complete wire object of its existing kind; an entry that the record does
/// not name is an error, so evidence cannot be smuggled beside a record.
#[derive(Clone, Copy, Debug, Default)]
pub struct RecordReferences<'a> {
    /// The exact `reinit_attempt` object a ReInit attempt receipt names.
    pub attempt_object: Option<&'a [u8]>,
    /// The `policy` object a policy transition installs.
    pub policy_object: Option<&'a [u8]>,
    /// `root_identity` successors, at most one per account whose root the
    /// record continues; an exact repeat is installed once.
    pub root_objects: &'a [&'a [u8]],
    /// `device_roster` objects a roster transition installs, at most one per
    /// account; an exact repeat is installed once.
    pub roster_objects: &'a [&'a [u8]],
    /// The `conversation_binding` package a binding transition installs.
    pub binding_object: Option<&'a [u8]>,
    /// The exact `ArcSequencerCredential` bytes a sequencer transition
    /// installs (no wire arm, as in the initial authority).
    pub sequencer_credential: Option<&'a [u8]>,
    /// The validated leaf-membership facts the caller holds for this
    /// conversation (companion 13.7.3). When present, every Commit and
    /// ReInit ACK a finalization or activation embeds must be signed by the
    /// distinct continuing leaf a stored proof identifies; when absent, ACK
    /// signatures remain the endpoint's MLS check.
    pub memberships: Option<&'a crate::membership::LeafMembershipSet>,
}

/// One validated chain position: the exact position facts the record was
/// authenticated against and the identities it established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainHead {
    /// Route sequence of the head record; `None` at the external anchor.
    pub sequence: Option<u64>,
    /// Semantic record ID of the head, or the external anchor ID.
    pub record_id: SemanticId,
    /// Transport identity of the exact head record object, if any.
    pub object_id: Option<ObjectId>,
    /// Semantic ID the head record named as its predecessor.
    pub predecessor_record_id: SemanticId,
    /// Credential that signed the head record.
    pub credential_id: SemanticId,
}

/// The authorizing prior state a restored server resumes a chain from
/// (companion 13.7.2): the binding, principal rosters, policy and
/// sequencer credential the retained finalized history committed, and the
/// exact head position the durable gate pins.
#[derive(Clone, Debug)]
pub struct ResumedChain {
    /// The current verified binding.
    pub binding: VerifiedBinding,
    /// The current root and roster heads of the binding principals.
    pub principals: PrincipalRosters,
    /// The last finalized policy.
    pub policy: VerifiedPolicy,
    /// The credential committed for the next position.
    pub sequencer: VerifiedSequencerCredential,
    /// The binding's required operational policy.
    pub required_operational_policy_id: SemanticId,
    /// Whether the bootstrap has not completed.
    pub bootstrap_pending: bool,
    /// The accepted epoch.
    pub epoch: u64,
    /// The accepted state identifier.
    pub accepted_state_id: SemanticId,
    /// The head record, or the anchor when nothing is recorded.
    pub head: ChainHead,
    /// The open candidate at the head, if the head is one.
    pub candidate: Option<OpenCandidate>,
    /// The candidate sequence the next candidate must carry.
    pub next_candidate_sequence: u32,
    /// The lifecycle the finalized history reached.
    pub lifecycle: Lifecycle,
}

/// The open candidate of the current epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenCandidate {
    /// Candidate identifier.
    pub candidate_id: SemanticId,
    /// Route sequence of the candidate record.
    pub route_sequence: u64,
    /// Candidate sequence within the epoch.
    pub candidate_sequence: u32,
    /// Predecessor named by the receipt, the vote-slot predecessor.
    pub predecessor_record_id: SemanticId,
    /// Commit object identifier.
    pub commit_object_id: SemanticId,
    /// Credential that signed the receipt.
    pub credential_id: SemanticId,
}

/// The open ReInit attempt of a closed old group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenAttempt {
    /// ReInit attempt identifier.
    pub attempt_id: SemanticId,
    /// Route sequence of the attempt receipt.
    pub route_sequence: u64,
    /// Attempt sequence within the ReInit.
    pub attempt_sequence: u32,
    /// Predecessor named by the receipt, the vote-slot predecessor.
    pub predecessor_record_id: SemanticId,
    /// Transport identity of the exact attempt object.
    pub attempt_object_id: SemanticId,
    /// The successor conversation the attempt targets.
    pub new_conversation_id: SemanticId,
    /// Credential that signed the receipt.
    pub credential_id: SemanticId,
}

/// The ReInit the old group finalized and is waiting to activate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReinitState {
    /// The finalization of the old ReInit Commit.
    pub old_reinit_state_id: SemanticId,
    /// The target context digest the old authorization committed.
    pub target_context_digest: SemanticId,
    /// Attempt sequence the next attempt must carry.
    pub next_attempt_sequence: u32,
    /// The attempt awaiting a terminal, if any.
    pub attempt: Option<OpenAttempt>,
}

/// Where the lineage stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lifecycle {
    /// Ordinary candidates may follow.
    Active,
    /// The active-to-closing transition finalized; only a close follows.
    Closing {
        /// The committed close intent.
        close_intent_id: SemanticId,
    },
    /// The old ReInit Commit finalized; only attempts and their terminals follow.
    Reinit(ReinitState),
    /// A valid close authorization ended the lineage.
    Closed {
        /// Semantic close authorization identifier, the final head.
        close_id: SemanticId,
    },
    /// A ReInit activation ended this log; the successor continues elsewhere.
    Activated {
        /// The activation identifier, the successor's anchor.
        reinit_activation_id: SemanticId,
        /// The successor conversation.
        new_conversation_id: SemanticId,
    },
}

/// What a finalization changed, all proved by the referenced objects.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Transitions {
    /// The installed policy, if the policy changed.
    pub policy_id: Option<SemanticId>,
    /// Roster heads replaced, as `(account, roster_id)`.
    pub roster_heads: Vec<([u8; 24], SemanticId)>,
    /// Root continuations, as `(account, root_fingerprint)`.
    pub roots: Vec<([u8; 24], SemanticId)>,
    /// The installed binding, if the binding changed.
    pub binding_id: Option<SemanticId>,
    /// The installed sequencer credential, if the sequencer changed.
    pub sequencer_credential_id: Option<SemanticId>,
    /// Whether the generation-zero bootstrap was activated.
    pub bootstrap_activated: bool,
    /// The committed close intent, if the lifecycle entered closing.
    pub close_intent_id: Option<SemanticId>,
    /// The committed ReInit target digest, if the group entered ReInit.
    pub reinit_target_digest: Option<SemanticId>,
}

/// One adopted record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainStep {
    /// A candidate receipt opened a candidate.
    Candidate(OpenCandidate),
    /// A finalization certificate advanced the accepted state.
    Finalized {
        /// Finalization identifier, the new accepted state.
        finalization_id: SemanticId,
        /// Resulting epoch.
        resulting_epoch: u64,
        /// Distinct old-council principals that voted.
        quorum_votes: usize,
        /// What changed.
        transitions: Transitions,
    },
    /// An abort certificate discarded the candidate.
    Aborted {
        /// Abort identifier.
        abort_id: SemanticId,
        /// Distinct old-council principals that voted.
        quorum_votes: usize,
    },
    /// A ReInit attempt receipt opened an attempt.
    ReinitAttempted(OpenAttempt),
    /// A ReInit activation certificate ended this log.
    ReinitActivated {
        /// Activation identifier.
        reinit_activation_id: SemanticId,
        /// The successor conversation.
        new_conversation_id: SemanticId,
        /// Distinct old-council principals that voted.
        quorum_votes: usize,
    },
    /// A ReInit abort certificate discarded the attempt.
    ReinitAborted {
        /// Abort identifier.
        reinit_abort_id: SemanticId,
        /// Distinct old-council principals that voted.
        quorum_votes: usize,
    },
}

/// How a second record at the head position relates to the installed one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternativeRecord {
    /// Another valid proof of the same semantic record: alternative evidence
    /// for one identifier, never a fork.
    SameRecord {
        /// Transport identity of the alternative object.
        object_id: ObjectId,
    },
    /// A second valid successor of the same predecessor: two records the
    /// committed credential signed at one position, which is the conflict
    /// the recovery gate must preserve and block on.
    Conflict {
        /// Semantic ID of the installed record.
        installed_record_id: SemanticId,
        /// Semantic ID of the conflicting record.
        conflicting_record_id: SemanticId,
        /// Transport identity of the conflicting object.
        conflicting_object_id: ObjectId,
    },
}

/// A continuous, verified history from the pinned genesis binding.
#[derive(Clone, Debug)]
pub struct HistoricalChain {
    network_id: [u8; 32],
    conversation_id: SemanticId,
    binding: VerifiedBinding,
    principals: PrincipalRosters,
    policy: VerifiedPolicy,
    sequencer: VerifiedSequencerCredential,
    required_operational_policy_id: SemanticId,
    bootstrap_pending: bool,
    epoch: u64,
    accepted_state_id: SemanticId,
    head: ChainHead,
    candidate: Option<OpenCandidate>,
    next_candidate_sequence: u32,
    lifecycle: Lifecycle,
    reinit_target: Option<ArcReInitTargetTbs>,
    records_left: u32,
}

impl HistoricalChain {
    /// Opens the chain at the external genesis anchor of `initial`. The
    /// binding, principals, policy, and sequencer credential the initial
    /// authority revalidated under the independent pin are the only trusted
    /// inputs; `network_id` and `conversation_id` come from the caller's
    /// retained state, exactly as for the initial authority.
    pub fn open(
        network_id: &[u8; 32],
        conversation_id: &SemanticId,
        initial: &InitialAuthority,
        limits: ChainLimits,
    ) -> Result<Self, E2eeError> {
        let binding = initial.binding();
        if binding.conversation_id != *conversation_id
            || binding.generation != 0
            || binding.route.incarnation != 0
        {
            return Err(E2eeError::InvalidValue);
        }
        let genesis = ArcGroupGenesisTbs {
            network_id: *network_id,
            conversation_id: *conversation_id,
            group_id: Opaque::from_slice(&binding.group_id)?,
            binding_id: binding.binding_id,
            context_core_id: binding.context_core_id,
        };
        let anchor = semantic_id_of(SemanticHashDomain::GroupGenesisId, &genesis)?;
        let sequencer = *initial.sequencer();
        Ok(Self {
            network_id: *network_id,
            conversation_id: *conversation_id,
            binding: binding.clone(),
            principals: initial.principals().clone(),
            policy: initial.policy().clone(),
            sequencer,
            required_operational_policy_id: *initial.required_operational_policy_id(),
            bootstrap_pending: true,
            epoch: 0,
            accepted_state_id: anchor,
            head: ChainHead {
                sequence: None,
                record_id: anchor,
                object_id: None,
                predecessor_record_id: [0; 32],
                credential_id: sequencer.credential_id,
            },
            candidate: None,
            next_candidate_sequence: 0,
            lifecycle: Lifecycle::Active,
            reinit_target: None,
            records_left: limits.max_records,
        })
    }

    /// Resumes a chain at the authorizing prior state a restored server
    /// already holds (companion 13.7.2): every anchor is validated retained
    /// state derived from the durable gate, never an uploaded object. The
    /// resumed chain adopts records exactly as an opened one does.
    pub fn resume(
        network_id: &[u8; 32],
        conversation_id: &SemanticId,
        resumed: ResumedChain,
        limits: ChainLimits,
    ) -> Result<Self, E2eeError> {
        let head = resumed.head;
        let candidate_agrees = resumed.candidate.is_none_or(|candidate| {
            head.sequence == Some(candidate.route_sequence)
                && head.record_id == candidate.candidate_id
                && head.predecessor_record_id == candidate.predecessor_record_id
        });
        if resumed.binding.conversation_id != *conversation_id
            || !candidate_agrees
            || (head.sequence.is_none() && head.record_id != resumed.accepted_state_id)
        {
            return Err(E2eeError::InvalidValue);
        }
        Ok(Self {
            network_id: *network_id,
            conversation_id: *conversation_id,
            binding: resumed.binding,
            principals: resumed.principals,
            policy: resumed.policy,
            sequencer: resumed.sequencer,
            required_operational_policy_id: resumed.required_operational_policy_id,
            bootstrap_pending: resumed.bootstrap_pending,
            epoch: resumed.epoch,
            accepted_state_id: resumed.accepted_state_id,
            head,
            candidate: resumed.candidate,
            next_candidate_sequence: resumed.next_candidate_sequence,
            lifecycle: resumed.lifecycle,
            reinit_target: None,
            records_left: limits.max_records,
        })
    }

    /// The validated head.
    #[must_use]
    pub const fn head(&self) -> &ChainHead {
        &self.head
    }

    /// The accepted state the next candidate must name.
    #[must_use]
    pub const fn accepted_state_id(&self) -> &SemanticId {
        &self.accepted_state_id
    }

    /// The current MLS epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The policy in force, the old policy of the next terminal.
    #[must_use]
    pub const fn policy(&self) -> &VerifiedPolicy {
        &self.policy
    }

    /// The current roots and rosters of every binding principal.
    #[must_use]
    pub const fn principals(&self) -> &PrincipalRosters {
        &self.principals
    }

    /// The current binding.
    #[must_use]
    pub const fn binding(&self) -> &VerifiedBinding {
        &self.binding
    }

    /// The credential committed for the next position.
    #[must_use]
    pub const fn sequencer(&self) -> &VerifiedSequencerCredential {
        &self.sequencer
    }

    /// Whether the generation-zero bootstrap is still pending.
    #[must_use]
    pub const fn bootstrap_pending(&self) -> bool {
        self.bootstrap_pending
    }

    /// The open candidate, if any.
    #[must_use]
    pub const fn candidate(&self) -> Option<&OpenCandidate> {
        self.candidate.as_ref()
    }

    /// Where the lineage stands.
    #[must_use]
    pub const fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }

    /// Whether the lineage reached a terminal and accepts no further record.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.lifecycle,
            Lifecycle::Closed { .. } | Lifecycle::Activated { .. }
        )
    }

    /// The exact position the next record must occupy.
    pub fn next_position(&self) -> Result<ExpectedRecord, E2eeError> {
        let route_sequence = match self.head.sequence {
            None => 0,
            Some(sequence) => sequence.checked_add(1).ok_or(E2eeError::Overflow)?,
        };
        Ok(ExpectedRecord {
            network_id: self.network_id,
            conversation_id: self.conversation_id,
            route_sequence,
            predecessor_record_id: self.head.record_id,
            sequencer_credential_id: self.sequencer.credential_id,
        })
    }

    /// Adopts the complete `sequencer_record` at exactly the next position.
    /// On any error the chain is unchanged; the caller may retry with
    /// corrected evidence or stop. Every decode charges `budget`; the record
    /// and its references are released before this returns.
    pub fn advance(
        &mut self,
        record_bytes: &[u8],
        references: &RecordReferences<'_>,
        budget: &mut DecodeBudget,
    ) -> Result<ChainStep, E2eeError> {
        let mut next = self.clone();
        let step = next.adopt(record_bytes, references, budget)?;
        *self = next;
        Ok(step)
    }

    /// Adopts the `close_authorization` that ends the closing lineage at the
    /// position after the head finalization. On error the chain is unchanged.
    pub fn close(
        &mut self,
        close_bytes: &[u8],
        budget: &mut DecodeBudget,
    ) -> Result<SemanticId, E2eeError> {
        let mut next = self.clone();
        let close_id = next.adopt_close(close_bytes, budget)?;
        *self = next;
        Ok(close_id)
    }

    /// Examines a second record for the head position without changing the
    /// chain: it is re-verified from the state before the head, so only a
    /// record the committed credential signed as a complete valid successor
    /// of the same predecessor is a conflict. Malformed evidence, a wrong
    /// credential, an unreached quorum, or an alternative proof of the same
    /// semantic record is never classified as a fork.
    pub fn examine_alternative(
        &self,
        before_head: &Self,
        record_bytes: &[u8],
        references: &RecordReferences<'_>,
        budget: &mut DecodeBudget,
    ) -> Result<AlternativeRecord, E2eeError> {
        let Some(head_sequence) = self.head.sequence else {
            return Err(E2eeError::InvalidValue);
        };
        let installed = self.head;
        let mut branch = before_head.clone();
        let position = branch.next_position()?;
        if position.route_sequence != head_sequence
            || position.predecessor_record_id != installed.predecessor_record_id
            || position.sequencer_credential_id != installed.credential_id
        {
            return Err(E2eeError::InvalidValue);
        }
        branch.adopt(record_bytes, references, budget)?;
        let alternative = branch.head;
        let object_id = alternative.object_id.ok_or(E2eeError::InvalidValue)?;
        if alternative.record_id == installed.record_id {
            return Ok(AlternativeRecord::SameRecord { object_id });
        }
        Ok(AlternativeRecord::Conflict {
            installed_record_id: installed.record_id,
            conflicting_record_id: alternative.record_id,
            conflicting_object_id: object_id,
        })
    }

    fn adopt(
        &mut self,
        record_bytes: &[u8],
        references: &RecordReferences<'_>,
        budget: &mut DecodeBudget,
    ) -> Result<ChainStep, E2eeError> {
        self.charge_record()?;
        if self.is_terminal() {
            return Err(E2eeError::InvalidValue);
        }
        let position = self.next_position()?;
        let object = ArcWireObject::decode_kind(
            record_bytes,
            Some(ArcWireObjectKind::SequencerRecord),
            budget,
        )?;
        let record = ArcSequencerRecord::decode_exact(object.body(), budget)?;
        let attempt_object = match record {
            ArcSequencerRecord::ReinitAttempt(_) => references.attempt_object,
            _ => {
                if references.attempt_object.is_some() {
                    return Err(E2eeError::InvalidValue);
                }
                None
            }
        };
        let record_id = authenticate_decoded_record(
            &record,
            attempt_object,
            &position,
            &self.sequencer,
            budget,
        )?;
        let object_id = ObjectId::compute(record_bytes);
        let step = match &record {
            ArcSequencerRecord::Candidate(receipt) => {
                Self::require_no_references(references, true)?;
                self.adopt_candidate(receipt, record_id, position.route_sequence)?
            }
            ArcSequencerRecord::Finalization(certificate) => {
                self.adopt_finalization(certificate, record_id, references, budget)?
            }
            ArcSequencerRecord::Abort(certificate) => {
                Self::require_no_references(references, true)?;
                self.adopt_abort(certificate, record_id)?
            }
            ArcSequencerRecord::ReinitAttempt(receipt) => {
                Self::require_no_references(references, false)?;
                let attempt = attempt_object.ok_or(E2eeError::InvalidValue)?;
                self.adopt_reinit_attempt(
                    receipt,
                    record_id,
                    attempt,
                    position.route_sequence,
                    budget,
                )?
            }
            ArcSequencerRecord::ReinitActivation(certificate) => {
                Self::require_no_references(references, true)?;
                self.adopt_reinit_activation(certificate, record_id, references)?
            }
            ArcSequencerRecord::ReinitAbort(certificate) => {
                Self::require_no_references(references, true)?;
                self.adopt_reinit_abort(certificate, record_id)?
            }
        };
        self.head = ChainHead {
            sequence: Some(position.route_sequence),
            record_id,
            object_id: Some(object_id),
            predecessor_record_id: position.predecessor_record_id,
            credential_id: position.sequencer_credential_id,
        };
        Ok(step)
    }

    fn charge_record(&mut self) -> Result<(), E2eeError> {
        self.records_left = self
            .records_left
            .checked_sub(1)
            .ok_or(E2eeError::LimitExceeded)?;
        Ok(())
    }

    /// A record that installs nothing may carry no transition object.
    fn require_no_references(
        references: &RecordReferences<'_>,
        no_attempt: bool,
    ) -> Result<(), E2eeError> {
        let carried = references.policy_object.is_some()
            || !references.root_objects.is_empty()
            || !references.roster_objects.is_empty()
            || references.binding_object.is_some()
            || references.sequencer_credential.is_some()
            || (no_attempt && references.attempt_object.is_some());
        if carried {
            return Err(E2eeError::InvalidValue);
        }
        Ok(())
    }

    fn adopt_candidate(
        &mut self,
        receipt: &ArcCandidateReceipt,
        candidate_id: SemanticId,
        route_sequence: u64,
    ) -> Result<ChainStep, E2eeError> {
        if self.lifecycle != Lifecycle::Active || self.candidate.is_some() {
            return Err(E2eeError::InvalidValue);
        }
        let tbs = &receipt.tbs;
        let resulting = self.epoch.checked_add(1).ok_or(E2eeError::Overflow)?;
        if tbs.prior_epoch != self.epoch
            || tbs.resulting_epoch != resulting
            || tbs.candidate_sequence != self.next_candidate_sequence
            || tbs.prior_state_id != self.accepted_state_id
        {
            return Err(E2eeError::InvalidValue);
        }
        // A fresh epoch's first candidate names the accepted state as its
        // predecessor; after an abort the predecessor is that abort, which
        // the position check already required as the head.
        if tbs.candidate_sequence == 0 && tbs.predecessor_record_id != self.accepted_state_id {
            return Err(E2eeError::InvalidValue);
        }
        let open = OpenCandidate {
            candidate_id,
            route_sequence,
            candidate_sequence: tbs.candidate_sequence,
            predecessor_record_id: tbs.predecessor_record_id,
            commit_object_id: tbs.commit_object_id,
            credential_id: tbs.sequencer_key_id,
        };
        self.candidate = Some(open);
        Ok(ChainStep::Candidate(open))
    }

    fn adopt_abort(
        &mut self,
        certificate: &ArcCommitAbortCertificate,
        abort_id: SemanticId,
    ) -> Result<ChainStep, E2eeError> {
        let open = self.candidate.ok_or(E2eeError::InvalidValue)?;
        let request = &certificate.tbs.request;
        let core = &request.core;
        let receipt = &request.receipt.tbs;
        if core.candidate_id != open.candidate_id
            || core.prior_epoch != self.epoch
            || core.prior_state_id != self.accepted_state_id
            || receipt.route_sequence != open.route_sequence
            || receipt.candidate_sequence != open.candidate_sequence
            || receipt.predecessor_record_id != open.predecessor_record_id
            || receipt.commit_object_id != open.commit_object_id
            || semantic_id_of(SemanticHashDomain::CandidateId, receipt)? != open.candidate_id
        {
            return Err(E2eeError::InvalidValue);
        }
        let reason = u16::from(core.reason.value());
        let terminal = crate::finality::Terminal::abort(abort_id, reason)?;
        let quorum_votes = finalization::count_quorum(
            self,
            &open,
            terminal,
            request.votes.as_slice(),
            &self.policy,
        )?;
        self.candidate = None;
        self.next_candidate_sequence = open
            .candidate_sequence
            .checked_add(1)
            .ok_or(E2eeError::Overflow)?;
        Ok(ChainStep::Aborted {
            abort_id,
            quorum_votes,
        })
    }

    fn adopt_close(
        &mut self,
        close_bytes: &[u8],
        budget: &mut DecodeBudget,
    ) -> Result<SemanticId, E2eeError> {
        self.charge_record()?;
        let Lifecycle::Closing { close_intent_id } = self.lifecycle else {
            return Err(E2eeError::InvalidValue);
        };
        if self.candidate.is_some() {
            return Err(E2eeError::InvalidValue);
        }
        let object = ArcWireObject::decode_kind(
            close_bytes,
            Some(ArcWireObjectKind::CloseAuthorization),
            budget,
        )?;
        let close = ArcCloseAuthorization::decode_exact(object.body(), budget)?;
        let tbs = &close.tbs;
        if tbs.network_id != self.network_id
            || tbs.conversation_id != self.conversation_id
            || tbs.binding_id != self.binding.binding_id
            || tbs.authorizing_terminal_id != self.head.record_id
            || tbs.close_intent_id != close_intent_id
        {
            return Err(E2eeError::InvalidValue);
        }
        let close_id = verify_close_approvals(&close, &self.policy, &self.principals)?;
        let sequence = self
            .head
            .sequence
            .ok_or(E2eeError::InvalidValue)?
            .checked_add(1)
            .ok_or(E2eeError::Overflow)?;
        self.head = ChainHead {
            sequence: Some(sequence),
            record_id: close_id,
            object_id: Some(ObjectId::compute(close_bytes)),
            predecessor_record_id: tbs.authorizing_terminal_id,
            credential_id: self.sequencer.credential_id,
        };
        self.lifecycle = Lifecycle::Closed { close_id };
        Ok(close_id)
    }

    /// The action bits a bootstrap-pending group may finalize: the exact
    /// initial-plan Adds, their join confirmations, and the activation.
    const fn bootstrap_permits(bits: u32) -> bool {
        bits == action_bits::ADD_LEAF | action_bits::ROSTER | action_bits::PENDING_JOIN
            || bits == action_bits::PENDING_JOIN
            || bits == action_bits::POLICY | action_bits::BOOTSTRAP
    }
}
