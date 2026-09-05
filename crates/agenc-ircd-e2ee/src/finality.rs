//! Finality votes and quorum accounting (companion Sections 12.4 and 13.8).
//!
//! The server reconstructs each vote's TBS from the receipt and the
//! terminal identifier, verifies the council device's signature, enforces
//! sign-once per slot, and counts distinct principals toward the derived
//! quorum; the sequencer signs a terminal certificate only once the quorum
//! is reached. Endpoint-only: the eligibility of a `FINALIZE` voter, which
//! needs the resulting tree and the voter's own staged state.

use std::collections::BTreeMap;

use agenc_ircd_crypto::SignatureDomain;

use crate::error::E2eeError;
use crate::ids::SemanticId;
use crate::limits::PROFILE_VERSION;
use crate::objects::reinit::{IrcReInitDisposition, IrcReInitDispositionVoteTbs};
use crate::objects::sequencing::{IrcDisposition, IrcDispositionVoteTbs, IrcFinalityVote};
use crate::policy::{VerifiedPolicy, active_device};
use crate::route::PrincipalRosters;
use crate::tls::{TlsEncode, ensure_canonical};

/// The durable sign-once slot of one candidate position.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VoteSlot {
    /// Network identity.
    pub network_id: [u8; 32],
    /// Conversation identifier.
    pub conversation_id: SemanticId,
    /// Prior epoch.
    pub prior_epoch: u64,
    /// Prior accepted state identifier.
    pub prior_state_id: SemanticId,
    /// Candidate sequence.
    pub candidate_sequence: u32,
    /// The receipt's predecessor record identifier.
    pub predecessor_record_id: SemanticId,
}

/// One terminal decision a vote can name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Terminal {
    /// Finalize or abort.
    pub disposition: IrcDisposition,
    /// The finalization or abort identifier.
    pub terminal_id: SemanticId,
    /// Reason code, zero for finalize.
    pub reason_code: u16,
}

impl Terminal {
    /// A finalize decision.
    #[must_use]
    pub const fn finalize(finalization_id: SemanticId) -> Self {
        Self {
            disposition: IrcDisposition::Finalize,
            terminal_id: finalization_id,
            reason_code: 0,
        }
    }

    /// An abort decision with its nonzero reason.
    pub const fn abort(abort_id: SemanticId, reason_code: u16) -> Result<Self, E2eeError> {
        if reason_code == 0 {
            return Err(E2eeError::InvalidValue);
        }
        Ok(Self {
            disposition: IrcDisposition::Abort,
            terminal_id: abort_id,
            reason_code,
        })
    }
}

/// Reconstructs the exact vote TBS a council device signed.
#[must_use]
pub fn vote_tbs(
    slot: &VoteSlot,
    candidate_id: SemanticId,
    terminal: Terminal,
) -> IrcDispositionVoteTbs {
    IrcDispositionVoteTbs {
        profile_version: PROFILE_VERSION,
        network_id: slot.network_id,
        conversation_id: slot.conversation_id,
        prior_epoch: slot.prior_epoch,
        prior_state_id: slot.prior_state_id,
        candidate_sequence: slot.candidate_sequence,
        slot_predecessor_record_id: slot.predecessor_record_id,
        candidate_id,
        disposition: terminal.disposition,
        terminal_id: terminal.terminal_id,
        reason_code: terminal.reason_code,
    }
}

/// The durable sign-once slot of one ReInit attempt (Section 13.8).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReinitVoteSlot {
    /// Network identity.
    pub network_id: [u8; 32],
    /// Old conversation identifier.
    pub old_conversation_id: SemanticId,
    /// The finalization of the ReInit Commit.
    pub old_reinit_state_id: SemanticId,
    /// Attempt sequence.
    pub attempt_sequence: u32,
    /// The attempt receipt's predecessor record identifier.
    pub predecessor_record_id: SemanticId,
}

/// Reconstructs the exact ReInit vote TBS a council device signed: an
/// activation is the finalize disposition, an attempt abort the abort one.
#[must_use]
pub fn reinit_vote_tbs(
    slot: &ReinitVoteSlot,
    reinit_attempt_id: SemanticId,
    terminal: Terminal,
) -> IrcReInitDispositionVoteTbs {
    let disposition = match terminal.disposition {
        IrcDisposition::Finalize => IrcReInitDisposition::ActivateReinit,
        IrcDisposition::Abort => IrcReInitDisposition::AbortReinitAttempt,
    };
    IrcReInitDispositionVoteTbs {
        profile_version: PROFILE_VERSION,
        network_id: slot.network_id,
        old_conversation_id: slot.old_conversation_id,
        old_reinit_state_id: slot.old_reinit_state_id,
        attempt_sequence: slot.attempt_sequence,
        slot_predecessor_record_id: slot.predecessor_record_id,
        reinit_attempt_id,
        disposition,
        terminal_id: terminal.terminal_id,
        reason_code: terminal.reason_code,
    }
}

/// The votes the server has accepted for one slot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QuorumLedger {
    votes: BTreeMap<(SemanticId, [u8; 16]), (Terminal, IrcFinalityVote)>,
}

impl QuorumLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one council vote over `tbs`, verifying the device signature
    /// through the rosters. A principal may vote once per slot; a repeat
    /// with the same terminal is idempotent and a different terminal is a
    /// sign-once violation.
    pub fn record(
        &mut self,
        policy: &VerifiedPolicy,
        rosters: &PrincipalRosters,
        tbs: &IrcDispositionVoteTbs,
        vote: &IrcFinalityVote,
    ) -> Result<(), E2eeError> {
        let terminal = Terminal {
            disposition: tbs.disposition,
            terminal_id: tbs.terminal_id,
            reason_code: tbs.reason_code,
        };
        self.record_encoded(policy, rosters, &tbs.encode()?, terminal, vote)
    }

    /// Records one ReInit council vote over `tbs` under the same rules.
    pub fn record_reinit(
        &mut self,
        policy: &VerifiedPolicy,
        rosters: &PrincipalRosters,
        tbs: &IrcReInitDispositionVoteTbs,
        vote: &IrcFinalityVote,
    ) -> Result<(), E2eeError> {
        let disposition = match tbs.disposition {
            IrcReInitDisposition::ActivateReinit => IrcDisposition::Finalize,
            IrcReInitDisposition::AbortReinitAttempt => IrcDisposition::Abort,
        };
        let terminal = Terminal {
            disposition,
            terminal_id: tbs.terminal_id,
            reason_code: tbs.reason_code,
        };
        self.record_encoded(policy, rosters, &tbs.encode()?, terminal, vote)
    }

    fn record_encoded(
        &mut self,
        policy: &VerifiedPolicy,
        rosters: &PrincipalRosters,
        encoded_tbs: &[u8],
        terminal: Terminal,
        vote: &IrcFinalityVote,
    ) -> Result<(), E2eeError> {
        let signer = (vote.signer_root_fingerprint, vote.signer_device_id);
        let member = policy
            .council_member(&signer.0, &signer.1)
            .ok_or(E2eeError::InvalidValue)?;
        let certificate = active_device(rosters, &signer.0, &signer.1)?;
        if certificate.certificate_id != member.certificate_id
            || certificate.certificate_id != vote.signer_device_certificate_id
        {
            return Err(E2eeError::InvalidValue);
        }
        certificate.key.verify(
            SignatureDomain::DispositionVote,
            encoded_tbs,
            &vote.device_signature,
        )?;
        match self.votes.get(&signer) {
            Some((existing, _)) if *existing != terminal => Err(E2eeError::InvalidValue),
            _ => {
                self.votes.insert(signer, (terminal, vote.clone()));
                Ok(())
            }
        }
    }

    /// Distinct principals that voted for `terminal`.
    #[must_use]
    pub fn count(&self, terminal: &Terminal) -> usize {
        self.votes
            .values()
            .filter(|(recorded, _)| recorded == terminal)
            .count()
    }

    /// Whether `terminal` reached the policy's quorum.
    #[must_use]
    pub fn quorum_reached(&self, policy: &VerifiedPolicy, terminal: &Terminal) -> bool {
        self.count(terminal) >= usize::from(policy.quorum)
    }

    /// Every recorded vote in canonical signer order.
    pub fn votes(&self) -> impl Iterator<Item = (&(SemanticId, [u8; 16]), &Terminal)> {
        self.votes
            .iter()
            .map(|(signer, (terminal, _))| (signer, terminal))
    }

    /// The verified signatures counted for `terminal`, in canonical signer
    /// order. A certificate includes these votes so endpoints can verify
    /// the same quorum even when the votes arrived in separate requests.
    #[must_use]
    pub fn signed_votes(&self, terminal: &Terminal) -> Vec<IrcFinalityVote> {
        self.votes
            .values()
            .filter(|(recorded, _)| recorded == terminal)
            .map(|(_, vote)| vote.clone())
            .collect()
    }
}

/// Records every vote of a submitted vector into `ledger` over one
/// reconstructed TBS; the vector must be canonical by principal.
pub fn record_vote_vector(
    ledger: &mut QuorumLedger,
    policy: &VerifiedPolicy,
    rosters: &PrincipalRosters,
    tbs: &IrcDispositionVoteTbs,
    votes: &[IrcFinalityVote],
) -> Result<(), E2eeError> {
    ensure_canonical(votes, |vote| {
        (vote.signer_root_fingerprint, vote.signer_device_id)
    })?;
    for vote in votes {
        ledger.record(policy, rosters, tbs, vote)?;
    }
    Ok(())
}

/// Records every ReInit vote of a submitted vector into `ledger` over one
/// reconstructed TBS; the vector must be canonical by principal.
pub fn record_reinit_vote_vector(
    ledger: &mut QuorumLedger,
    policy: &VerifiedPolicy,
    rosters: &PrincipalRosters,
    tbs: &IrcReInitDispositionVoteTbs,
    votes: &[IrcFinalityVote],
) -> Result<(), E2eeError> {
    ensure_canonical(votes, |vote| {
        (vote.signer_root_fingerprint, vote.signer_device_id)
    })?;
    for vote in votes {
        ledger.record_reinit(policy, rosters, tbs, vote)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/finality.rs"]
mod tests;
