//! Finality votes and quorum accounting (companion Sections 12.4 and 13.8).
//!
//! The server reconstructs each vote's TBS from the receipt and the
//! terminal identifier, verifies the council device's signature, enforces
//! sign-once per slot, and counts distinct principals toward the derived
//! quorum. Endpoint-only: the eligibility of a `FINALIZE` voter, which needs
//! the resulting tree and the voter's own staged state.

use std::collections::BTreeMap;

use agenc_ircd_crypto::SignatureDomain;

use crate::error::E2eeError;
use crate::ids::SemanticId;
use crate::limits::PROFILE_VERSION;
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

/// The votes the server has accepted for one slot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QuorumLedger {
    votes: BTreeMap<(SemanticId, [u8; 16]), Terminal>,
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
            &tbs.encode()?,
            &vote.device_signature,
        )?;
        let terminal = Terminal {
            disposition: tbs.disposition,
            terminal_id: tbs.terminal_id,
            reason_code: tbs.reason_code,
        };
        match self.votes.get(&signer) {
            Some(existing) if *existing != terminal => Err(E2eeError::InvalidValue),
            _ => {
                self.votes.insert(signer, terminal);
                Ok(())
            }
        }
    }

    /// Distinct principals that voted for `terminal`.
    #[must_use]
    pub fn count(&self, terminal: &Terminal) -> usize {
        self.votes.values().filter(|vote| *vote == terminal).count()
    }

    /// Whether `terminal` reached the policy's quorum.
    #[must_use]
    pub fn quorum_reached(&self, policy: &VerifiedPolicy, terminal: &Terminal) -> bool {
        self.count(terminal) >= usize::from(policy.quorum)
    }

    /// Every recorded vote in canonical signer order.
    pub fn votes(&self) -> impl Iterator<Item = (&(SemanticId, [u8; 16]), &Terminal)> {
        self.votes.iter()
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

#[cfg(test)]
#[path = "tests/finality.rs"]
mod tests;
