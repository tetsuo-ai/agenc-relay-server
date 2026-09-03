//! Candidate-specific commit authorization (companion Section 9.3).
//!
//! The server verifies the authorization's agreement with the receipt, the
//! legality of its rule and action bits, and the controller approvals under
//! the old policy. Endpoint-only: deriving the action bits and result
//! digests from the decrypted Commit; the server takes them as asserted and
//! checks that every endpoint proof carries the same values.

use std::collections::BTreeSet;

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};

use crate::error::E2eeError;
use crate::ids::{SemanticId, semantic_id_of};
use crate::limits::PROFILE_VERSION;
use crate::objects::conversation::{
    IrcCommitApproval, IrcCommitApprovalEnvelope, IrcCommitAuthorization,
    IrcCommitAuthorizationRule, IrcCommitAuthorizationTbs, IrcMembershipPolicy, action_bits,
};
use crate::policy::{VerifiedPolicy, active_device};
use crate::route::PrincipalRosters;
use crate::tls::{TlsEncode, ensure_canonical};

/// The receipt fields an authorization must repeat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateBinding {
    /// Network identity.
    pub network_id: [u8; 32],
    /// Conversation identifier.
    pub conversation_id: SemanticId,
    /// Prior epoch.
    pub prior_epoch: u64,
    /// Prior accepted state identifier.
    pub prior_state_id: SemanticId,
    /// Candidate identifier.
    pub candidate_id: SemanticId,
    /// Commit object identifier.
    pub commit_object_id: SemanticId,
}

/// The rules the Section 9.3 table names by exact bit pattern.
fn named_rule(bits: u32) -> Option<IrcCommitAuthorizationRule> {
    use action_bits::*;
    match bits {
        0 => Some(IrcCommitAuthorizationRule::RoutineSelfUpdate),
        bits if bits == ADD_LEAF | ROSTER | PENDING_JOIN => {
            Some(IrcCommitAuthorizationRule::OpenVisibleAdd)
        }
        PENDING_JOIN => Some(IrcCommitAuthorizationRule::JoinConfirmation),
        bits if bits == ROSTER || bits == ROSTER | REMOVE_LEAF => {
            Some(IrcCommitAuthorizationRule::RosterRecovery)
        }
        bits if bits == POLICY | BOOTSTRAP => Some(IrcCommitAuthorizationRule::BootstrapActivation),
        _ => None,
    }
}

/// Which rule a set of action bits selects, if any is legal. A transition
/// class (ReInit, binding, close intent) stands alone; every other legal
/// combination is a controlled transition.
#[must_use]
pub fn rule_for_bits(bits: u32) -> Option<IrcCommitAuthorizationRule> {
    use action_bits::*;
    if bits & !KNOWN != 0 {
        return None;
    }
    if let Some(rule) = named_rule(bits) {
        return Some(rule);
    }
    let classes = [REINIT, BINDING, CLOSE_INTENT];
    let set = classes.iter().filter(|class| bits & **class != 0).count();
    let standalone = classes.contains(&bits);
    if set == 0 || (set == 1 && standalone) {
        Some(IrcCommitAuthorizationRule::ControlledTransition)
    } else {
        None
    }
}

/// Whether `rule` is the exact rule the bits select. Every combination the
/// table lists selects one rule; a controlled transition is any other legal
/// combination, and misclassification is fatal.
#[must_use]
pub fn rule_matches_bits(rule: IrcCommitAuthorizationRule, bits: u32) -> bool {
    match rule_for_bits(bits) {
        Some(IrcCommitAuthorizationRule::RosterRecovery) => matches!(
            rule,
            IrcCommitAuthorizationRule::RosterRecovery
                | IrcCommitAuthorizationRule::ControlledTransition
        ),
        Some(IrcCommitAuthorizationRule::OpenVisibleAdd) => matches!(
            rule,
            IrcCommitAuthorizationRule::OpenVisibleAdd
                | IrcCommitAuthorizationRule::ControlledTransition
        ),
        Some(selected) => selected == rule,
        None => false,
    }
}

/// Whether the transition target digest must be present for `bits`.
#[must_use]
pub const fn needs_transition_target(bits: u32) -> bool {
    bits & (action_bits::REINIT | action_bits::BINDING | action_bits::CLOSE_INTENT) != 0
}

/// Whether the rule needs controller approvals under `policy`.
#[must_use]
pub fn needs_controller_approval(
    rule: IrcCommitAuthorizationRule,
    policy: &VerifiedPolicy,
) -> bool {
    match rule {
        IrcCommitAuthorizationRule::RoutineSelfUpdate
        | IrcCommitAuthorizationRule::JoinConfirmation
        | IrcCommitAuthorizationRule::RosterRecovery => false,
        IrcCommitAuthorizationRule::OpenVisibleAdd => {
            policy.membership_policy != IrcMembershipPolicy::OpenVisible
        }
        IrcCommitAuthorizationRule::ControlledTransition
        | IrcCommitAuthorizationRule::BootstrapActivation => true,
    }
}

/// A verified commit authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthorization {
    /// Authorization identifier.
    pub authorization_id: SemanticId,
    /// Rule.
    pub rule: IrcCommitAuthorizationRule,
    /// Action bits.
    pub action_bits: u32,
    /// Resulting policy identifier.
    pub resulting_policy_id: SemanticId,
    /// Transition target digest.
    pub transition_target_digest: SemanticId,
    /// Canonical validation time.
    pub validation_time: u64,
    /// Approving controller roots.
    pub approving_roots: BTreeSet<SemanticId>,
}

/// Verifies an authorization against the candidate it names, the old policy,
/// and the rosters holding the controller devices.
pub fn verify_commit_authorization(
    authorization: &IrcCommitAuthorization,
    candidate: &CandidateBinding,
    old_policy: &VerifiedPolicy,
    rosters: &PrincipalRosters,
) -> Result<VerifiedAuthorization, E2eeError> {
    let tbs = &authorization.tbs;
    check_authorization_shape(tbs, candidate, old_policy)?;
    let approvals = authorization.approvals.as_slice();
    ensure_canonical(approvals, |approval| {
        (approval.signer_root_fingerprint, approval.signer_device_id)
    })?;
    let encoded = tbs.encode()?;
    let mut approving_roots = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for approval in approvals {
        let key = verify_approval(approval, &encoded, old_policy, rosters)?;
        if !approving_roots.insert(approval.signer_root_fingerprint) || !keys.insert(key) {
            return Err(E2eeError::NonCanonical);
        }
    }
    let required = if needs_controller_approval(tbs.authorization_rule, old_policy) {
        usize::from(old_policy.controller_threshold)
    } else {
        0
    };
    if approving_roots.len() < required {
        return Err(E2eeError::InvalidValue);
    }
    Ok(VerifiedAuthorization {
        authorization_id: semantic_id_of(SemanticHashDomain::CommitAuthorizationId, tbs)?,
        rule: tbs.authorization_rule,
        action_bits: tbs.action_bits,
        resulting_policy_id: tbs.resulting_policy_id,
        transition_target_digest: tbs.transition_target_digest,
        validation_time: tbs.canonical_validation_time,
        approving_roots,
    })
}

fn check_authorization_shape(
    tbs: &IrcCommitAuthorizationTbs,
    candidate: &CandidateBinding,
    old_policy: &VerifiedPolicy,
) -> Result<(), E2eeError> {
    if tbs.profile_version != PROFILE_VERSION {
        return Err(E2eeError::ProfileMismatch);
    }
    let policy_unchanged = tbs.action_bits & action_bits::POLICY == 0;
    let consistent = names_candidate(tbs, candidate, old_policy)
        && rule_matches_bits(tbs.authorization_rule, tbs.action_bits)
        && needs_transition_target(tbs.action_bits) == (tbs.transition_target_digest != [0; 32])
        && policy_unchanged == (tbs.resulting_policy_id == old_policy.policy_id);
    if consistent {
        Ok(())
    } else {
        Err(E2eeError::InvalidValue)
    }
}

/// Whether the authorization repeats the receipt and old policy exactly.
fn names_candidate(
    tbs: &IrcCommitAuthorizationTbs,
    candidate: &CandidateBinding,
    old_policy: &VerifiedPolicy,
) -> bool {
    tbs.network_id == candidate.network_id
        && tbs.conversation_id == candidate.conversation_id
        && tbs.prior_epoch == candidate.prior_epoch
        && tbs.prior_state_id == candidate.prior_state_id
        && tbs.candidate_id == candidate.candidate_id
        && tbs.commit_object_id == candidate.commit_object_id
        && tbs.old_policy_id == old_policy.policy_id
}

/// Verifies one approval's signer and signature, returning the signer key.
fn verify_approval(
    approval: &IrcCommitApproval,
    encoded_tbs: &[u8],
    old_policy: &VerifiedPolicy,
    rosters: &PrincipalRosters,
) -> Result<[u8; 32], E2eeError> {
    if !old_policy.is_controller(&approval.signer_root_fingerprint) {
        return Err(E2eeError::InvalidValue);
    }
    let certificate = active_device(
        rosters,
        &approval.signer_root_fingerprint,
        &approval.signer_device_id,
    )?;
    if !certificate.may_approve_policy()
        || certificate.certificate_id != approval.signer_device_certificate_id
    {
        return Err(E2eeError::InvalidValue);
    }
    certificate.key.verify(
        SignatureDomain::CommitAuthorization,
        encoded_tbs,
        &approval.device_signature,
    )?;
    Ok(*certificate.key.as_bytes())
}

/// A verified single-approval envelope as submitted through
/// `EGROUP SUBMIT AUTHORIZATION`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedApprovalEnvelope {
    /// The authorization identifier the envelope's TBS hashes to.
    pub authorization_id: SemanticId,
    /// Signer root fingerprint.
    pub signer_root: SemanticId,
    /// Signer device identity.
    pub signer_device_id: [u8; 16],
}

/// Verifies an approval envelope: the TBS must be the same one every other
/// envelope for the candidate carries (its identifier), and the single
/// approval must come from an active controller device.
pub fn verify_approval_envelope(
    envelope: &IrcCommitApprovalEnvelope,
    candidate: &CandidateBinding,
    old_policy: &VerifiedPolicy,
    rosters: &PrincipalRosters,
) -> Result<VerifiedApprovalEnvelope, E2eeError> {
    check_authorization_shape(&envelope.tbs, candidate, old_policy)?;
    let encoded = envelope.tbs.encode()?;
    verify_approval(&envelope.approval, &encoded, old_policy, rosters)?;
    Ok(VerifiedApprovalEnvelope {
        authorization_id: semantic_id_of(SemanticHashDomain::CommitAuthorizationId, &envelope.tbs)?,
        signer_root: envelope.approval.signer_root_fingerprint,
        signer_device_id: envelope.approval.signer_device_id,
    })
}

#[cfg(test)]
#[path = "tests/authorization.rs"]
mod tests;
