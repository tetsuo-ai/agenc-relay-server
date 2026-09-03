//! Conversation policy validation and finality quorum arithmetic
//! (companion Section 9.3).
//!
//! The server checks the policy's closed shape, its controller and council
//! sets against the rosters it holds, the approval threshold, and the
//! generation chain. Endpoint-only: the in-MLS wholesale extension
//! replacement and the staged-state comparison.

use std::collections::BTreeSet;

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};

use crate::error::E2eeError;
use crate::identity::{VerifiedCertificate, VerifiedRoster};
use crate::ids::{SemanticId, semantic_id_of};
use crate::limits::{
    MAX_ACTIVE_DEVICES_PER_ACCOUNT, MAX_FINALITY_PRINCIPALS, MAX_GROUP_LEAVES, MAX_POLICY_BYTES,
    MLS_VERSION_MLS10, PROFILE_VERSION, SUITE_X25519_AES128GCM_SHA256_ED25519, suite_is_enabled,
};
use crate::objects::boolean;
use crate::objects::conversation::{
    IrcConversationKind, IrcFinalityPrincipal, IrcMembershipPolicy, IrcPolicy, IrcPolicyTbs,
};
use crate::route::PrincipalRosters;
use crate::tls::{TlsEncode, ensure_canonical};

/// The derived finality quorum `q = floor((n + f) / 2) + 1` for a council of
/// `n` principals tolerating `f` faults, with `n >= 3f + 1`.
pub fn finality_quorum(council_size: usize, fault_bound: u16) -> Result<u16, E2eeError> {
    let n = u16::try_from(council_size).map_err(|_| E2eeError::LimitExceeded)?;
    if n == 0 || council_size > MAX_FINALITY_PRINCIPALS {
        return Err(E2eeError::LimitExceeded);
    }
    let minimum = fault_bound
        .checked_mul(3)
        .and_then(|triple| triple.checked_add(1))
        .ok_or(E2eeError::Overflow)?;
    if n < minimum {
        return Err(E2eeError::InvalidValue);
    }
    let sum = n.checked_add(fault_bound).ok_or(E2eeError::Overflow)?;
    (sum / 2).checked_add(1).ok_or(E2eeError::Overflow)
}

/// One council principal resolved to its current certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CouncilMember {
    /// Root fingerprint.
    pub root_fingerprint: SemanticId,
    /// Device identity.
    pub device_id: [u8; 16],
    /// Certificate identifier.
    pub certificate_id: SemanticId,
}

/// A verified conversation policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPolicy {
    /// Policy identifier.
    pub policy_id: SemanticId,
    /// Policy generation.
    pub generation: u64,
    /// Previous policy identifier.
    pub previous_policy_id: SemanticId,
    /// Conversation identifier.
    pub conversation_id: SemanticId,
    /// Conversation kind.
    pub kind: IrcConversationKind,
    /// Membership policy.
    pub membership_policy: IrcMembershipPolicy,
    /// Selected suite.
    pub selected_suite: u16,
    /// Ordered allowed suites.
    pub allowed_suites: Vec<u16>,
    /// Controller root fingerprints, canonical.
    pub controllers: Vec<SemanticId>,
    /// Distinct controller roots required.
    pub controller_threshold: u16,
    /// Finality council, canonical.
    pub council: Vec<CouncilMember>,
    /// Byzantine fault bound.
    pub fault_bound: u16,
    /// Derived quorum.
    pub quorum: u16,
    /// Whether out-of-band verified roots are required.
    pub require_oob_verified_roots: bool,
    /// Device cap per account.
    pub max_devices_per_account: u16,
    /// Leaf cap.
    pub max_group_leaves: u32,
}

impl VerifiedPolicy {
    /// Whether `root` is a controller.
    #[must_use]
    pub fn is_controller(&self, root: &SemanticId) -> bool {
        self.controllers.binary_search(root).is_ok()
    }

    /// Whether the council names this device.
    #[must_use]
    pub fn council_member(
        &self,
        root: &SemanticId,
        device_id: &[u8; 16],
    ) -> Option<&CouncilMember> {
        self.council
            .iter()
            .find(|member| member.root_fingerprint == *root && member.device_id == *device_id)
    }

    /// Whether at least a quorum of `retained` principals stays on the
    /// council, the rule every removal must satisfy before it is proposed.
    #[must_use]
    pub fn retains_quorum(&self, retained: &BTreeSet<(SemanticId, [u8; 16])>) -> bool {
        let eligible = self
            .council
            .iter()
            .filter(|member| retained.contains(&(member.root_fingerprint, member.device_id)))
            .count();
        eligible >= usize::from(self.quorum)
    }
}

/// Verifies a policy against the rosters that must resolve its principals
/// and the policy it replaces, if any. Approvals are counted against the
/// governing controller set: the predecessor's for a change, the policy's
/// own for an initial policy.
pub fn verify_policy(
    network_id: &[u8; 32],
    conversation_id: &SemanticId,
    policy: &IrcPolicy,
    rosters: &PrincipalRosters,
    predecessor: Option<&VerifiedPolicy>,
) -> Result<VerifiedPolicy, E2eeError> {
    let tbs = &policy.tbs;
    if policy.encode()?.len() > MAX_POLICY_BYTES {
        return Err(E2eeError::LimitExceeded);
    }
    check_policy_profile(network_id, conversation_id, tbs)?;
    check_policy_lineage(tbs, predecessor)?;
    let controllers = controller_set(tbs)?;
    let council = resolve_council(tbs.finality_principals.as_slice(), rosters)?;
    let quorum = finality_quorum(council.len(), tbs.finality_fault_bound)?;
    check_policy_bounds(tbs, controllers.len())?;
    let governing: &[SemanticId] =
        predecessor.map_or(&controllers, |previous| &previous.controllers);
    let threshold = predecessor.map_or(tbs.controller_threshold, |previous| {
        previous.controller_threshold
    });
    count_approvals(policy, governing, threshold, rosters)?;
    Ok(VerifiedPolicy {
        policy_id: semantic_id_of(SemanticHashDomain::PolicyId, tbs)?,
        generation: tbs.policy_generation,
        previous_policy_id: tbs.previous_policy_id,
        conversation_id: *conversation_id,
        kind: tbs.kind,
        membership_policy: tbs.membership_policy,
        selected_suite: tbs.selected_suite,
        allowed_suites: tbs.allowed_suites.as_slice().to_vec(),
        controllers,
        controller_threshold: tbs.controller_threshold,
        council,
        fault_bound: tbs.finality_fault_bound,
        quorum,
        require_oob_verified_roots: boolean(tbs.require_oob_verified_roots)?,
        max_devices_per_account: tbs.max_devices_per_account,
        max_group_leaves: tbs.max_group_leaves,
    })
}

fn check_policy_profile(
    network_id: &[u8; 32],
    conversation_id: &SemanticId,
    tbs: &IrcPolicyTbs,
) -> Result<(), E2eeError> {
    if tbs.profile_version != PROFILE_VERSION || tbs.mls_version != MLS_VERSION_MLS10 {
        return Err(E2eeError::ProfileMismatch);
    }
    if tbs.network_id != *network_id || tbs.conversation_id != *conversation_id {
        return Err(E2eeError::InvalidValue);
    }
    let suites = tbs.allowed_suites.as_slice();
    let mut seen = BTreeSet::new();
    let well_formed = !suites.is_empty()
        && suites
            .iter()
            .all(|suite| suite_is_enabled(*suite) && seen.insert(*suite))
        && suites.contains(&SUITE_X25519_AES128GCM_SHA256_ED25519)
        && suites.contains(&tbs.selected_suite);
    if !well_formed {
        return Err(E2eeError::ProfileMismatch);
    }
    Ok(())
}

fn check_policy_lineage(
    tbs: &IrcPolicyTbs,
    predecessor: Option<&VerifiedPolicy>,
) -> Result<(), E2eeError> {
    match predecessor {
        None if tbs.policy_generation == 0 && tbs.previous_policy_id == [0; 32] => Ok(()),
        Some(previous)
            if previous.generation.checked_add(1) == Some(tbs.policy_generation)
                && tbs.previous_policy_id == previous.policy_id
                && previous.kind == tbs.kind =>
        {
            Ok(())
        }
        _ => Err(E2eeError::InvalidValue),
    }
}

fn controller_set(tbs: &IrcPolicyTbs) -> Result<Vec<SemanticId>, E2eeError> {
    let bytes = tbs.controller_root_fingerprints.as_slice();
    if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
        return Err(E2eeError::InvalidValue);
    }
    let controllers: Vec<SemanticId> = bytes.as_chunks::<32>().0.to_vec();
    ensure_canonical(&controllers, |root| *root)?;
    Ok(controllers)
}

fn resolve_council(
    principals: &[IrcFinalityPrincipal],
    rosters: &PrincipalRosters,
) -> Result<Vec<CouncilMember>, E2eeError> {
    ensure_canonical(principals, |principal| {
        (
            principal.root_fingerprint,
            principal.device_id,
            principal.device_certificate_id,
        )
    })?;
    let mut devices = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut council = Vec::new();
    council
        .try_reserve(principals.len())
        .map_err(|_| E2eeError::BudgetExceeded)?;
    for principal in principals {
        let certificate =
            active_device(rosters, &principal.root_fingerprint, &principal.device_id)?;
        if certificate.certificate_id != principal.device_certificate_id
            || !devices.insert(principal.device_id)
            || !keys.insert(*certificate.key.as_bytes())
        {
            return Err(E2eeError::InvalidValue);
        }
        council.push(CouncilMember {
            root_fingerprint: principal.root_fingerprint,
            device_id: principal.device_id,
            certificate_id: principal.device_certificate_id,
        });
    }
    Ok(council)
}

/// Finds the active certificate of `device_id` under the roster whose root
/// has `root_fingerprint`.
pub fn active_device<'a>(
    rosters: &'a PrincipalRosters,
    root_fingerprint: &SemanticId,
    device_id: &[u8; 16],
) -> Result<&'a VerifiedCertificate, E2eeError> {
    rosters
        .values()
        .find(|(root, _)| root.fingerprint == *root_fingerprint)
        .and_then(|(_, roster)| roster.device(device_id))
        .ok_or(E2eeError::InvalidValue)
}

/// The roster whose root has `root_fingerprint`.
pub fn roster_of<'a>(
    rosters: &'a PrincipalRosters,
    root_fingerprint: &SemanticId,
) -> Option<&'a VerifiedRoster> {
    rosters
        .values()
        .find(|(root, _)| root.fingerprint == *root_fingerprint)
        .map(|(_, roster)| roster)
}

fn check_policy_bounds(tbs: &IrcPolicyTbs, controller_count: usize) -> Result<(), E2eeError> {
    let threshold = usize::from(tbs.controller_threshold);
    if threshold == 0
        || threshold > controller_count
        || !fixed_direct_shape_ok(tbs, controller_count)
    {
        return Err(E2eeError::InvalidValue);
    }
    let devices_ok = (1..=MAX_ACTIVE_DEVICES_PER_ACCOUNT).contains(&tbs.max_devices_per_account);
    let leaves_ok = (1..=MAX_GROUP_LEAVES).contains(&tbs.max_group_leaves);
    if devices_ok && leaves_ok {
        Ok(())
    } else {
        Err(E2eeError::LimitExceeded)
    }
}

/// A `fixed_direct` policy has exactly the two bound roots, threshold two,
/// and the direct kind; other policies are unconstrained here.
fn fixed_direct_shape_ok(tbs: &IrcPolicyTbs, controller_count: usize) -> bool {
    tbs.membership_policy != IrcMembershipPolicy::FixedDirect
        || (controller_count == 2
            && tbs.controller_threshold == 2
            && tbs.kind == IrcConversationKind::Direct)
}

/// Counts distinct approving controller roots against `threshold`, verifying
/// every signature; at most one approval counts per root.
fn count_approvals(
    policy: &IrcPolicy,
    controllers: &[SemanticId],
    threshold: u16,
    rosters: &PrincipalRosters,
) -> Result<(), E2eeError> {
    let approvals = policy.approvals.as_slice();
    ensure_canonical(approvals, |approval| {
        (approval.signer_root_fingerprint, approval.signer_device_id)
    })?;
    let encoded = policy.tbs.encode()?;
    let mut roots = BTreeSet::new();
    for approval in approvals {
        if controllers
            .binary_search(&approval.signer_root_fingerprint)
            .is_err()
        {
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
            SignatureDomain::PolicyApproval,
            &encoded,
            &approval.device_signature,
        )?;
        roots.insert(approval.signer_root_fingerprint);
    }
    if roots.len() < usize::from(threshold) {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/policy.rs"]
mod tests;
