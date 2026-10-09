//! Finalization certificates: the proof, the old-policy quorum, and every
//! transition the certified authorization commits.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use super::{
    ChainStep, HistoricalChain, Lifecycle, OpenCandidate, RecordReferences, ReinitState,
    Transitions,
};
use crate::authorization::{CandidateBinding, VerifiedAuthorization, verify_commit_authorization};
use crate::error::E2eeError;
use crate::finality::{QuorumLedger, Terminal, VoteSlot, vote_tbs};
use crate::identity::{
    AccountIdBytes, ValidationTime, restore_roster, verify_root_identity, verify_roster,
};
use crate::ids::{SemanticId, proof_set_digest, semantic_id_of};
use crate::object::{ArcWireObject, ArcWireObjectKind};
use crate::objects::account_id_bytes;
use crate::objects::conversation::{
    ArcCommitAuthorizationRule, ArcConversationBindingPackage, ArcPolicy, ArcSequencerCredential,
    action_bits,
};
use crate::objects::identity::{ArcDeviceRoster, ArcRootIdentity};
use crate::objects::sequencing::{
    ArcCommitFinalizationCertificate, ArcFinalityVote, ArcFinalizationProof,
};
use crate::policy::{VerifiedPolicy, verify_policy};
use crate::route::{is_binding_successor, verify_binding_package};
use crate::sequencer::verify_sequencer_credential;
use crate::tls::{DecodeBudget, TlsDecode, ensure_canonical};
use agenc_relay_crypto::SemanticHashDomain;

impl HistoricalChain {
    pub(super) fn adopt_finalization(
        &mut self,
        certificate: &ArcCommitFinalizationCertificate,
        finalization_id: SemanticId,
        references: &RecordReferences<'_>,
        budget: &mut DecodeBudget,
    ) -> Result<ChainStep, E2eeError> {
        let open = self.candidate.ok_or(E2eeError::InvalidValue)?;
        let request = &certificate.tbs.request;
        let proof = &request.proof;
        let core = &proof.core;
        self.check_proof_names_candidate(proof, &open)?;
        check_proof_links(proof)?;
        let acknowledged = super::membership::authenticate_finalization(references, proof)?;
        if core.old_policy_id != self.policy.policy_id
            || proof.authorization.tbs.old_policy_id != self.policy.policy_id
        {
            return Err(E2eeError::InvalidValue);
        }
        let authorization = verify_commit_authorization(
            &proof.authorization,
            &CandidateBinding {
                network_id: self.network_id,
                conversation_id: self.conversation_id,
                prior_epoch: self.epoch,
                prior_state_id: self.accepted_state_id,
                candidate_id: open.candidate_id,
                commit_object_id: open.commit_object_id,
            },
            &self.policy,
            &self.principals,
        )?;
        if core.commit_authorization_id != authorization.authorization_id
            || proof.authorization.tbs.resulting_group_context_digest
                != core.resulting_group_context_digest
            || proof.authorization.tbs.resulting_ratchet_tree_digest
                != core.resulting_ratchet_tree_digest
        {
            return Err(E2eeError::InvalidValue);
        }
        let time = ValidationTime(authorization.validation_time);
        // The credential committed for the position also has to cover the
        // Commit's canonical validation time (companion 9.2); the roots and
        // rosters the record uses are checked once its successors are known.
        if !self.sequencer.covers(time) {
            return Err(E2eeError::InvalidValue);
        }
        if self.bootstrap_pending && !Self::bootstrap_permits(authorization.action_bits) {
            return Err(E2eeError::InvalidValue);
        }
        let terminal = Terminal::finalize(finalization_id);
        let quorum_votes = self.finalization_quorum(
            &open,
            &authorization,
            terminal,
            request.votes.as_slice(),
            references,
            budget,
        )?;
        let held = self.principals.clone();
        let transitions =
            self.apply_transitions(&authorization, finalization_id, references, budget)?;
        self.check_liveness(&held, &authorization, request, &acknowledged, &transitions)?;
        self.candidate = None;
        self.next_candidate_sequence = 0;
        self.epoch = core.resulting_epoch;
        self.accepted_state_id = finalization_id;
        Ok(ChainStep::Finalized {
            finalization_id,
            resulting_epoch: core.resulting_epoch,
            quorum_votes,
            transitions,
        })
    }

    fn check_proof_names_candidate(
        &self,
        proof: &ArcFinalizationProof,
        open: &OpenCandidate,
    ) -> Result<(), E2eeError> {
        let core = &proof.core;
        let receipt = &proof.receipt.tbs;
        let resulting = self.epoch.checked_add(1).ok_or(E2eeError::Overflow)?;
        let named_core = (
            core.candidate_id,
            core.commit_object_id,
            core.prior_epoch,
            core.prior_state_id,
            core.resulting_epoch,
        );
        let expected_core = (
            open.candidate_id,
            open.commit_object_id,
            self.epoch,
            self.accepted_state_id,
            resulting,
        );
        let named_receipt = (
            receipt.route_sequence,
            receipt.candidate_sequence,
            receipt.predecessor_record_id,
            receipt.commit_object_id,
            receipt.prior_state_id,
            receipt.sequencer_key_id,
            semantic_id_of(SemanticHashDomain::CandidateId, receipt)?,
        );
        let expected_receipt = (
            open.route_sequence,
            open.candidate_sequence,
            open.predecessor_record_id,
            open.commit_object_id,
            self.accepted_state_id,
            open.credential_id,
            open.candidate_id,
        );
        if named_core == expected_core && named_receipt == expected_receipt {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// Recounts the old-policy quorum from the device signatures; a
    /// bootstrap activation additionally needs the resulting council's
    /// quorum over the same slot (companion 9.3 and 9.5).
    fn finalization_quorum(
        &self,
        open: &OpenCandidate,
        authorization: &VerifiedAuthorization,
        terminal: Terminal,
        votes: &[ArcFinalityVote],
        references: &RecordReferences<'_>,
        budget: &mut DecodeBudget,
    ) -> Result<usize, E2eeError> {
        if authorization.rule != ArcCommitAuthorizationRule::BootstrapActivation {
            return count_quorum(self, open, terminal, votes, &self.policy);
        }
        // The resulting policy is the one the transition installs; verify it
        // here without installing it so both councils can be counted.
        let resulting = self.verified_policy_reference(authorization, references, budget)?;
        ensure_canonical(votes, |vote| {
            (vote.signer_root_fingerprint, vote.signer_device_id)
        })?;
        let tbs = vote_tbs(&self.vote_slot(open), open.candidate_id, terminal);
        let mut old = QuorumLedger::new();
        let mut new = QuorumLedger::new();
        for vote in votes {
            let signer = (&vote.signer_root_fingerprint, &vote.signer_device_id);
            let on_old = self.policy.council_member(signer.0, signer.1).is_some();
            let on_new = resulting.council_member(signer.0, signer.1).is_some();
            if !on_old && !on_new {
                return Err(E2eeError::InvalidValue);
            }
            if on_old {
                old.record(&self.policy, &self.principals, &tbs, vote)?;
            }
            if on_new {
                new.record(&resulting, &self.principals, &tbs, vote)?;
            }
        }
        if !old.quorum_reached(&self.policy, &terminal)
            || !new.quorum_reached(&resulting, &terminal)
        {
            return Err(E2eeError::InvalidValue);
        }
        Ok(old.count(&terminal))
    }

    pub(super) fn vote_slot(&self, open: &OpenCandidate) -> VoteSlot {
        VoteSlot {
            network_id: self.network_id,
            conversation_id: self.conversation_id,
            prior_epoch: self.epoch,
            prior_state_id: self.accepted_state_id,
            candidate_sequence: open.candidate_sequence,
            predecessor_record_id: open.predecessor_record_id,
        }
    }

    fn verified_policy_reference(
        &self,
        authorization: &VerifiedAuthorization,
        references: &RecordReferences<'_>,
        budget: &mut DecodeBudget,
    ) -> Result<VerifiedPolicy, E2eeError> {
        let bytes = references.policy_object.ok_or(E2eeError::InvalidValue)?;
        let policy: ArcPolicy = decode_object(bytes, ArcWireObjectKind::Policy, budget)?;
        let verified = verify_policy(
            &self.network_id,
            &self.conversation_id,
            &policy,
            &self.principals,
            Some(&self.policy),
        )?;
        if verified.policy_id != authorization.resulting_policy_id {
            return Err(E2eeError::InvalidValue);
        }
        Ok(verified)
    }

    /// Installs every transition the action bits commit, each proved by the
    /// object the caller supplied for it; an object without its bit, or a
    /// bit without its object, is invalid.
    fn apply_transitions(
        &mut self,
        authorization: &VerifiedAuthorization,
        finalization_id: SemanticId,
        references: &RecordReferences<'_>,
        budget: &mut DecodeBudget,
    ) -> Result<Transitions, E2eeError> {
        let mut transitions = Transitions::default();
        // Roots and rosters first: later policy, binding, and sequencer
        // approvals resolve through the heads this record installs.
        self.apply_heads(authorization, references, &mut transitions, budget)?;
        self.apply_policy(authorization, references, &mut transitions, budget)?;
        self.apply_sequencer(authorization, references, &mut transitions, budget)?;
        self.apply_binding(authorization, references, &mut transitions, budget)?;
        self.apply_lifecycle(authorization, finalization_id, &mut transitions)?;
        Ok(transitions)
    }

    /// A roster proposal always carries the complete roster, even a
    /// reaffirmation of the stored one, once per account, and a record
    /// continues an account's root at most once (companion 9.3 and 13.7.2);
    /// root and roster objects without the roster bit are invalid.
    fn apply_heads(
        &mut self,
        authorization: &VerifiedAuthorization,
        references: &RecordReferences<'_>,
        transitions: &mut Transitions,
        budget: &mut DecodeBudget,
    ) -> Result<(), E2eeError> {
        if authorization.action_bits & action_bits::ROSTER == 0 {
            let supplied =
                !references.root_objects.is_empty() || !references.roster_objects.is_empty();
            return if supplied {
                Err(E2eeError::InvalidValue)
            } else {
                Ok(())
            };
        }
        if references.roster_objects.is_empty() {
            return Err(E2eeError::InvalidValue);
        }
        self.apply_roots(references.root_objects, transitions, budget)?;
        self.apply_rosters(references.roster_objects, transitions, budget)
    }

    /// Installs the authorized resulting policy; the bootstrap bit is valid
    /// only with the policy bit, once, and only for the binding's required
    /// operational policy. Without the policy bit the policy is unchanged.
    fn apply_policy(
        &mut self,
        authorization: &VerifiedAuthorization,
        references: &RecordReferences<'_>,
        transitions: &mut Transitions,
        budget: &mut DecodeBudget,
    ) -> Result<(), E2eeError> {
        let bits = authorization.action_bits;
        let bootstrap = bits & action_bits::BOOTSTRAP != 0;
        if bits & action_bits::POLICY == 0 {
            let unchanged = references.policy_object.is_none()
                && !bootstrap
                && authorization.resulting_policy_id == self.policy.policy_id;
            return if unchanged {
                Ok(())
            } else {
                Err(E2eeError::InvalidValue)
            };
        }
        let resulting = self.verified_policy_reference(authorization, references, budget)?;
        if bootstrap {
            if !self.bootstrap_pending || resulting.policy_id != self.required_operational_policy_id
            {
                return Err(E2eeError::InvalidValue);
            }
            self.bootstrap_pending = false;
            transitions.bootstrap_activated = true;
        }
        transitions.policy_id = Some(resulting.policy_id);
        self.policy = resulting;
        Ok(())
    }

    /// Installs the continuity-signed successor sequencer credential.
    fn apply_sequencer(
        &mut self,
        authorization: &VerifiedAuthorization,
        references: &RecordReferences<'_>,
        transitions: &mut Transitions,
        budget: &mut DecodeBudget,
    ) -> Result<(), E2eeError> {
        let supplied = references.sequencer_credential;
        if authorization.action_bits & action_bits::SEQUENCER == 0 {
            return supplied.map_or(Ok(()), |_| Err(E2eeError::InvalidValue));
        }
        let bytes = supplied.ok_or(E2eeError::InvalidValue)?;
        let credential = ArcSequencerCredential::decode_exact(bytes, budget)?;
        let successor =
            verify_sequencer_credential(&self.network_id, &credential, Some(&self.sequencer))?;
        transitions.sequencer_credential_id = Some(successor.credential_id);
        self.sequencer = successor;
        Ok(())
    }

    /// Installs the next-generation binding the authorization's target
    /// digest names, for the same conversation.
    fn apply_binding(
        &mut self,
        authorization: &VerifiedAuthorization,
        references: &RecordReferences<'_>,
        transitions: &mut Transitions,
        budget: &mut DecodeBudget,
    ) -> Result<(), E2eeError> {
        let supplied = references.binding_object;
        if authorization.action_bits & action_bits::BINDING == 0 {
            return supplied.map_or(Ok(()), |_| Err(E2eeError::InvalidValue));
        }
        let bytes = supplied.ok_or(E2eeError::InvalidValue)?;
        let package: ArcConversationBindingPackage =
            decode_object(bytes, ArcWireObjectKind::ConversationBinding, budget)?;
        let successor = verify_binding_package(&self.network_id, &package, &self.principals)?;
        let named = (successor.binding_id, successor.conversation_id);
        let expected = (authorization.transition_target_digest, self.conversation_id);
        if !is_binding_successor(&self.binding, &successor) || named != expected {
            return Err(E2eeError::InvalidValue);
        }
        transitions.binding_id = Some(successor.binding_id);
        self.binding = successor;
        Ok(())
    }

    /// A close intent or a ReInit moves an active conversation into its
    /// closing or ReInit lifecycle under the authorization's target digest.
    fn apply_lifecycle(
        &mut self,
        authorization: &VerifiedAuthorization,
        finalization_id: SemanticId,
        transitions: &mut Transitions,
    ) -> Result<(), E2eeError> {
        let target = authorization.transition_target_digest;
        let has = |bit: u32| authorization.action_bits & bit != 0;
        let moves = has(action_bits::CLOSE_INTENT) || has(action_bits::REINIT);
        if moves && (self.lifecycle != Lifecycle::Active || target == [0; 32]) {
            return Err(E2eeError::InvalidValue);
        }
        if has(action_bits::CLOSE_INTENT) {
            self.lifecycle = Lifecycle::Closing {
                close_intent_id: target,
            };
            transitions.close_intent_id = Some(target);
        }
        if has(action_bits::REINIT) {
            if self.lifecycle != Lifecycle::Active {
                return Err(E2eeError::InvalidValue);
            }
            self.lifecycle = Lifecycle::Reinit(ReinitState {
                old_reinit_state_id: finalization_id,
                target_context_digest: target,
                next_attempt_sequence: 0,
                attempt: None,
            });
            transitions.reinit_target_digest = Some(target);
        }
        Ok(())
    }

    fn apply_roots(
        &mut self,
        objects: &[&[u8]],
        transitions: &mut Transitions,
        budget: &mut DecodeBudget,
    ) -> Result<(), E2eeError> {
        let mut installed = BTreeMap::new();
        for &bytes in objects {
            let root: ArcRootIdentity =
                decode_object(bytes, ArcWireObjectKind::RootIdentity, budget)?;
            let account = account_id_bytes(&root.tbs.account_id)?;
            if repeats_installed(&mut installed, account, bytes)? {
                continue;
            }
            let (previous, _) = self
                .principals
                .get(&account)
                .ok_or(E2eeError::InvalidValue)?;
            let successor = verify_root_identity(&self.network_id, &root, Some(previous))?;
            transitions.roots.push((account, successor.fingerprint));
            let entry = self
                .principals
                .get_mut(&account)
                .ok_or(E2eeError::InvalidValue)?;
            entry.0 = successor;
        }
        Ok(())
    }

    fn apply_rosters(
        &mut self,
        objects: &[&[u8]],
        transitions: &mut Transitions,
        budget: &mut DecodeBudget,
    ) -> Result<(), E2eeError> {
        let mut installed = BTreeMap::new();
        for &bytes in objects {
            let roster: ArcDeviceRoster =
                decode_object(bytes, ArcWireObjectKind::DeviceRoster, budget)?;
            let account = account_id_bytes(&roster.tbs.account_id)?;
            if repeats_installed(&mut installed, account, bytes)? {
                continue;
            }
            let (root, previous) = self
                .principals
                .get(&account)
                .ok_or(E2eeError::InvalidValue)?;
            let roster_id = semantic_id_of(SemanticHashDomain::RosterId, &roster.tbs)?;
            let successor = if roster_id == previous.roster_id {
                // An identical current roster is a reaffirmation, re-verified
                // under its root without a lineage step.
                restore_roster(root, &roster)?
            } else if root.generation == previous.root_generation {
                verify_roster(root, &roster, Some(previous))?
            } else {
                // A continued root starts its own roster lineage; the
                // predecessor roster belongs to the retired root.
                verify_roster(root, &roster, None)?
            };
            transitions
                .roster_heads
                .push((account, successor.roster_id));
            let entry = self
                .principals
                .get_mut(&account)
                .ok_or(E2eeError::InvalidValue)?;
            entry.1 = successor;
        }
        // Every continued root must have received its roster.
        if self
            .principals
            .values()
            .any(|(root, roster)| root.generation != roster.root_generation)
        {
            return Err(E2eeError::InvalidValue);
        }
        crate::identity::ensure_distinct_device_keys(
            self.principals.values().map(|(_, roster)| roster),
        )?;
        Ok(())
    }
}

/// Whether `object` repeats the root or roster this record already installed
/// for `account`. A record carries at most one root continuation and one
/// roster per account (companion 9.3 and 13.7.2), so the roster it installs
/// is exactly the successor its context head names; a second, different
/// object for the account is invalid, and an exact repeat, as when two
/// submitters supply the same reference, is installed once.
fn repeats_installed<'a>(
    installed: &mut BTreeMap<AccountIdBytes, &'a [u8]>,
    account: AccountIdBytes,
    object: &'a [u8],
) -> Result<bool, E2eeError> {
    match installed.insert(account, object) {
        Some(earlier) if earlier != object => Err(E2eeError::InvalidValue),
        earlier => Ok(earlier.is_some()),
    }
}

/// The public hash links of a finalization proof (companion 12.4): the
/// authorization ID, the canonical ACK set and its digest, and every ACK's
/// agreement with the certified core. ACK signatures are endpoint leaf
/// signatures and are not claimed here.
pub(super) fn check_proof_links(proof: &ArcFinalizationProof) -> Result<(), E2eeError> {
    let core = &proof.core;
    let acks = proof.acknowledgements.as_slice();
    ensure_canonical(acks, |ack| ack.tbs.old_leaf_index)?;
    let tbs: Vec<_> = acks.iter().map(|ack| ack.tbs.clone()).collect();
    let digest = proof_set_digest(SemanticHashDomain::AcknowledgementSet, &tbs)?;
    let certified = (
        core.profile_version,
        core.network_id,
        core.conversation_id,
        core.prior_epoch,
        core.candidate_id,
        core.commit_object_id,
        core.resulting_epoch,
        core.resulting_group_context_digest,
        core.resulting_ratchet_tree_digest,
        core.finalization_authenticator,
    );
    let agrees = acks.iter().all(|ack| {
        let ack = &ack.tbs;
        let named = (
            ack.profile_version,
            ack.network_id,
            ack.conversation_id,
            ack.prior_epoch,
            ack.candidate_id,
            ack.commit_object_id,
            ack.resulting_epoch,
            ack.resulting_group_context_digest,
            ack.resulting_ratchet_tree_digest,
            ack.finalization_authenticator,
        );
        named == certified
    });
    if digest != core.acknowledgement_set_digest || !agrees {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

/// Counts a canonical vote vector for `terminal` over the candidate's slot
/// under `policy` and requires the derived quorum; returns the distinct
/// principals that voted.
pub(super) fn count_quorum(
    chain: &HistoricalChain,
    open: &OpenCandidate,
    terminal: Terminal,
    votes: &[ArcFinalityVote],
    policy: &VerifiedPolicy,
) -> Result<usize, E2eeError> {
    let tbs = vote_tbs(&chain.vote_slot(open), open.candidate_id, terminal);
    let mut ledger = QuorumLedger::new();
    crate::finality::record_vote_vector(&mut ledger, policy, &chain.principals, &tbs, votes)?;
    if !ledger.quorum_reached(policy, &terminal) {
        return Err(E2eeError::InvalidValue);
    }
    Ok(ledger.count(&terminal))
}

pub(super) fn decode_object<T: TlsDecode>(
    bytes: &[u8],
    kind: ArcWireObjectKind,
    budget: &mut DecodeBudget,
) -> Result<T, E2eeError> {
    let object = ArcWireObject::decode_kind(bytes, Some(kind), budget)?;
    T::decode_exact(object.body(), budget)
}
