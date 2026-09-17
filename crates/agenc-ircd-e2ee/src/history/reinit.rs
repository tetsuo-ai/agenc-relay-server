//! ReInit attempts and their terminals after the old group finalized its
//! ReInit Commit (companion Section 13.8).

#![forbid(unsafe_code)]

use super::finalization::decode_object;
use super::{ChainStep, HistoricalChain, Lifecycle, OpenAttempt, ReinitState};
use crate::error::E2eeError;
use crate::finality::{
    QuorumLedger, ReinitVoteSlot, Terminal, record_reinit_vote_vector, reinit_vote_tbs,
};
use crate::ids::{SemanticId, proof_set_digest, semantic_id_of};
use crate::object::{IrcWireObjectKind, ObjectId};
use crate::objects::reinit::{
    IrcReInitAbortCertificate, IrcReInitAckKind, IrcReInitActivationCertificate, IrcReInitAttempt,
    IrcReInitAttemptReceipt, IrcReInitAttemptReceiptTbs,
};
use crate::objects::sequencing::IrcFinalityVote;
use crate::reinit_authorization::verify_reinit_attempt_authorization;
use crate::tls::{DecodeBudget, TlsEncode, ensure_canonical};
use agenc_ircd_crypto::SemanticHashDomain;

impl HistoricalChain {
    fn reinit_state(&self) -> Result<ReinitState, E2eeError> {
        match self.lifecycle {
            Lifecycle::Reinit(state) => Ok(state),
            _ => Err(E2eeError::InvalidValue),
        }
    }

    pub(super) fn adopt_reinit_attempt(
        &mut self,
        receipt: &IrcReInitAttemptReceipt,
        attempt_id: SemanticId,
        attempt_bytes: &[u8],
        route_sequence: u64,
        budget: &mut DecodeBudget,
    ) -> Result<ChainStep, E2eeError> {
        let mut state = self.reinit_state()?;
        if state.attempt.is_some() || self.candidate.is_some() {
            return Err(E2eeError::InvalidValue);
        }
        let tbs = &receipt.tbs;
        let first_predecessor_ok =
            tbs.attempt_sequence != 0 || tbs.predecessor_record_id == state.old_reinit_state_id;
        let slot = (tbs.old_reinit_state_id, tbs.attempt_sequence);
        if slot != (state.old_reinit_state_id, state.next_attempt_sequence) || !first_predecessor_ok
        {
            return Err(E2eeError::InvalidValue);
        }
        // The attempt object was already proved to hash to the receipt's
        // object ID and to carry the receipt's attempt ID; decode it again
        // here for its authority and target.
        let attempt: IrcReInitAttempt =
            decode_object(attempt_bytes, IrcWireObjectKind::ReinitAttempt, budget)?;
        let core = &attempt.tbs;
        let named = (
            core.network_id,
            core.old_conversation_id,
            core.old_reinit_state_id,
            core.target_context_digest,
        );
        let expected = (
            self.network_id,
            self.conversation_id,
            state.old_reinit_state_id,
            state.target_context_digest,
        );
        if named != expected || core.new_conversation_id == self.conversation_id {
            return Err(E2eeError::InvalidValue);
        }
        verify_reinit_attempt_authorization(&attempt, &self.policy, &self.principals)?;
        let open = OpenAttempt {
            attempt_id,
            route_sequence,
            attempt_sequence: tbs.attempt_sequence,
            predecessor_record_id: tbs.predecessor_record_id,
            attempt_object_id: *ObjectId::compute(attempt_bytes).as_bytes(),
            new_conversation_id: core.new_conversation_id,
            credential_id: tbs.sequencer_key_id,
        };
        state.attempt = Some(open);
        self.lifecycle = Lifecycle::Reinit(state);
        Ok(ChainStep::ReinitAttempted(open))
    }

    pub(super) fn adopt_reinit_activation(
        &mut self,
        certificate: &IrcReInitActivationCertificate,
        activation_id: SemanticId,
        references: &super::RecordReferences<'_>,
    ) -> Result<ChainStep, E2eeError> {
        let state = self.reinit_state()?;
        let open = state.attempt.ok_or(E2eeError::InvalidValue)?;
        let request = &certificate.tbs.request;
        let core = &request.core;
        self.check_attempt_named(&request.receipt.tbs, &request.attempt, &open, &state)?;
        let attempt = &request.attempt.tbs;
        let named = (
            core.old_conversation_id,
            core.new_conversation_id,
            core.old_reinit_state_id,
            core.attempt_sequence,
            core.reinit_attempt_id,
        );
        let expected = (
            self.conversation_id,
            open.new_conversation_id,
            state.old_reinit_state_id,
            open.attempt_sequence,
            open.attempt_id,
        );
        if named != expected || staged_result(core) != attempt_result(attempt) {
            return Err(E2eeError::InvalidValue);
        }
        check_ack_set(request, core, &open.attempt_id)?;
        super::membership::authenticate_activation(references, request, self.epoch)?;
        let terminal = Terminal::finalize(activation_id);
        let quorum_votes = self.reinit_quorum(&state, &open, terminal, request.votes.as_slice())?;
        self.lifecycle = Lifecycle::Activated {
            reinit_activation_id: activation_id,
            new_conversation_id: open.new_conversation_id,
        };
        Ok(ChainStep::ReinitActivated {
            reinit_activation_id: activation_id,
            new_conversation_id: open.new_conversation_id,
            quorum_votes,
        })
    }

    pub(super) fn adopt_reinit_abort(
        &mut self,
        certificate: &IrcReInitAbortCertificate,
        abort_id: SemanticId,
    ) -> Result<ChainStep, E2eeError> {
        let mut state = self.reinit_state()?;
        let open = state.attempt.ok_or(E2eeError::InvalidValue)?;
        let request = &certificate.tbs.request;
        let core = &request.core;
        self.check_attempt_named(&request.receipt.tbs, &request.attempt, &open, &state)?;
        if core.old_conversation_id != self.conversation_id
            || core.old_reinit_state_id != state.old_reinit_state_id
            || core.attempt_sequence != open.attempt_sequence
            || core.slot_predecessor_record_id != open.predecessor_record_id
            || core.reinit_attempt_id != open.attempt_id
        {
            return Err(E2eeError::InvalidValue);
        }
        let terminal = Terminal::abort(abort_id, core.reason_code)?;
        let quorum_votes = self.reinit_quorum(&state, &open, terminal, request.votes.as_slice())?;
        state.attempt = None;
        state.next_attempt_sequence = open
            .attempt_sequence
            .checked_add(1)
            .ok_or(E2eeError::Overflow)?;
        self.lifecycle = Lifecycle::Reinit(state);
        Ok(ChainStep::ReinitAborted {
            reinit_abort_id: abort_id,
            quorum_votes,
        })
    }

    /// The terminal must carry the exact retained receipt and attempt.
    fn check_attempt_named(
        &self,
        receipt: &IrcReInitAttemptReceiptTbs,
        attempt: &IrcReInitAttempt,
        open: &OpenAttempt,
        state: &ReinitState,
    ) -> Result<(), E2eeError> {
        let attempt_bytes =
            crate::object::IrcWireObject::new(IrcWireObjectKind::ReinitAttempt, attempt.encode()?)?
                .encode()?;
        let named = (
            receipt.network_id,
            receipt.old_conversation_id,
            receipt.old_reinit_state_id,
            receipt.route_sequence,
            receipt.attempt_sequence,
            receipt.predecessor_record_id,
            receipt.reinit_attempt_id,
            receipt.attempt_object_id,
            receipt.sequencer_key_id,
        );
        let expected = (
            self.network_id,
            self.conversation_id,
            state.old_reinit_state_id,
            open.route_sequence,
            open.attempt_sequence,
            open.predecessor_record_id,
            open.attempt_id,
            open.attempt_object_id,
            open.credential_id,
        );
        let carried = (
            *ObjectId::compute(&attempt_bytes).as_bytes(),
            semantic_id_of(SemanticHashDomain::ReinitAttemptId, &attempt.tbs)?,
        );
        if named == expected && carried == (open.attempt_object_id, open.attempt_id) {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    fn reinit_quorum(
        &self,
        state: &ReinitState,
        open: &OpenAttempt,
        terminal: Terminal,
        votes: &[IrcFinalityVote],
    ) -> Result<usize, E2eeError> {
        let slot = ReinitVoteSlot {
            network_id: self.network_id,
            old_conversation_id: self.conversation_id,
            old_reinit_state_id: state.old_reinit_state_id,
            attempt_sequence: open.attempt_sequence,
            predecessor_record_id: open.predecessor_record_id,
        };
        let tbs = reinit_vote_tbs(&slot, open.attempt_id, terminal);
        let mut ledger = QuorumLedger::new();
        record_reinit_vote_vector(&mut ledger, &self.policy, &self.principals, &tbs, votes)?;
        if !ledger.quorum_reached(&self.policy, &terminal) {
            return Err(E2eeError::InvalidValue);
        }
        Ok(ledger.count(&terminal))
    }
}

/// The four staged-result fields an activation core certifies.
fn staged_result(
    core: &crate::objects::reinit::IrcReInitActivationCoreTbs,
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    (
        core.new_group_info_digest,
        core.new_group_context_digest,
        core.new_ratchet_tree_digest,
        core.new_exporter_authenticator,
    )
}

/// The four staged-result fields an attempt commits.
fn attempt_result(
    attempt: &crate::objects::reinit::IrcReInitAttemptTbs,
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    (
        attempt.new_group_info_digest,
        attempt.new_group_context_digest,
        attempt.new_ratchet_tree_digest,
        attempt.new_exporter_authenticator,
    )
}

/// The activation's ACK set is canonical by old leaf, hashes to the core's
/// set digest, and every ACK repeats the attempt and names a planned role.
fn check_ack_set(
    request: &crate::objects::reinit::IrcReInitActivationRequest,
    core: &crate::objects::reinit::IrcReInitActivationCoreTbs,
    attempt_id: &SemanticId,
) -> Result<(), E2eeError> {
    let acks = request.acknowledgements.as_slice();
    ensure_canonical(acks, |ack| ack.tbs.old_leaf_index)?;
    let tbs: Vec<_> = acks.iter().map(|ack| ack.tbs.clone()).collect();
    let digest = proof_set_digest(SemanticHashDomain::ReinitAcknowledgementSet, &tbs)?;
    let agree = acks
        .iter()
        .all(|ack| ack_agrees(&ack.tbs, &request.attempt, attempt_id));
    if digest != core.acknowledgement_set_digest || !agree {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

/// Whether a ReInit ACK repeats the attempt it acknowledges and names a
/// planned role (companion 13.8); the leaf signature is endpoint-only.
fn ack_agrees(
    ack: &crate::objects::reinit::IrcReInitAckTbs,
    attempt: &IrcReInitAttempt,
    attempt_id: &SemanticId,
) -> bool {
    let tbs = &attempt.tbs;
    let named = (
        ack.profile_version,
        ack.network_id,
        ack.old_conversation_id,
        ack.new_conversation_id,
        ack.old_reinit_state_id,
        ack.reinit_attempt_id,
    );
    let expected = (
        tbs.profile_version,
        tbs.network_id,
        tbs.old_conversation_id,
        tbs.new_conversation_id,
        tbs.old_reinit_state_id,
        *attempt_id,
    );
    let result = (
        ack.new_group_info_digest,
        ack.new_group_context_digest,
        ack.new_ratchet_tree_digest,
        ack.new_exporter_authenticator,
    );
    named == expected && result == attempt_result(tbs) && ack_role_planned(ack, attempt)
}

/// A `creator_state` ACK names the creator's old leaf with an empty
/// KeyPackageRef; a `welcome_join` ACK names another leaf and a reserved
/// non-creator plan entry's ref.
fn ack_role_planned(
    ack: &crate::objects::reinit::IrcReInitAckTbs,
    attempt: &IrcReInitAttempt,
) -> bool {
    let tbs = &attempt.tbs;
    let creator = (tbs.creator_old_leaf_index, tbs.creator_old_credential_hash);
    match ack.ack_kind {
        IrcReInitAckKind::CreatorState => {
            ack.key_package_ref.is_empty()
                && (ack.old_leaf_index, ack.old_credential_hash) == creator
        }
        IrcReInitAckKind::WelcomeJoin => {
            let planned = attempt
                .key_package_plan
                .entries
                .as_slice()
                .iter()
                .any(|entry| entry.creator == 0 && entry.key_package_ref == ack.key_package_ref);
            !ack.key_package_ref.is_empty() && ack.old_leaf_index != creator.0 && planned
        }
    }
}
