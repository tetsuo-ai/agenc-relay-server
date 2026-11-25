//! Unsigned generation-zero binding proposals for protected endpoint review (companion 9.4, 13.2 and 13.3).

use super::{ExpectedInitialAuthority, InitialAuthorityEvidence, anchors, decode_object};
use crate::context::verify_proposed_core;
use crate::identity::{Interval, ValidationTime};
use crate::limits::{MAX_BINDING_APPROVALS, MAX_BINDING_PRINCIPALS};
use crate::object::ArcWireObjectKind;
use crate::objects::conversation::{
    ArcContextCoreTbs, ArcConversationBindingPackage, ArcConversationBindingTbs,
    ArcInitialMemberPlan, ArcMembershipPolicy, ArcPolicy,
};
use crate::policy::{VerifiedPolicy, active_device, verify_policy};
use crate::route::{
    PrincipalRosters, SemanticRoute, SemanticRouteKey, check_binding_shape, check_principals,
    concrete_route, verify_initial_member_plan, verify_semantic_route,
};
use crate::sequencer::VerifiedSequencerCredential;
use crate::{DecodeBudget, E2eeError, TlsDecode};

/// Public material checked before any device or root has signed this binding.
/// It carries the unsigned TBS and plan, the two signed policies, and the
/// exact independently pinned directory. It cannot satisfy an API requiring
/// a verified binding or initial authority.
pub struct InitialBindingProposal {
    binding_id: [u8; 32],
    binding: ArcConversationBindingTbs,
    plan: ArcInitialMemberPlan,
    route: SemanticRoute,
    core: ArcContextCoreTbs,
    principals: PrincipalRosters,
    initial: VerifiedPolicy,
    operational: VerifiedPolicy,
    sequencer: VerifiedSequencerCredential,
    validity: Interval,
}

impl InitialBindingProposal {
    /// Independent semantic binding ID checked before processing the proposal.
    pub fn id(&self) -> [u8; 32] {
        self.binding_id
    }
    /// Exact canonical input to a device's conversation-binding signature.
    pub fn binding(&self) -> &ArcConversationBindingTbs {
        &self.binding
    }
    /// Proposed stable device and capability identities.
    pub fn plan(&self) -> &ArcInitialMemberPlan {
        &self.plan
    }
    /// Semantic namespace independent of a fresh group, channel instance or Direct nonce.
    pub fn route(&self) -> &SemanticRoute {
        &self.route
    }
    /// Context committed by the independently pinned binding.
    pub fn core(&self) -> &ArcContextCoreTbs {
        &self.core
    }
    /// Root and roster heads named in the unsigned TBS.
    pub fn principals(&self) -> &PrincipalRosters {
        &self.principals
    }
    /// Authenticated generation-zero policy.
    pub fn initial_policy(&self) -> &VerifiedPolicy {
        &self.initial
    }
    /// Authenticated generation-one policy committed by the same context.
    pub fn operational_policy(&self) -> &VerifiedPolicy {
        &self.operational
    }
    /// Sequencer credential committed by this proposal.
    pub fn sequencer(&self) -> &VerifiedSequencerCredential {
        &self.sequencer
    }
    /// Interval of the named directories, binding devices, policy signers, councils and sequencer.
    pub fn validity(&self) -> Interval {
        self.validity
    }
}

/// Checks an ordinary incarnation-zero proposal under a binding ID supplied by
/// the caller's independent source. Its binding package must have empty approval
/// and root-lock vectors. Both exact signed policies are verified in sequence.
/// The endpoint still verifies its current directory, capabilities, pinned
/// sequencer, protected grant, clock and local review before durably signing.
/// One caller-owned budget covers all decodes. The caller reserves verification
/// memory and retains a charge for the returned public material.
///
/// # Errors
/// Refuses a different pin, a fully or partially signed package, inconsistent
/// route, plan, context, policy, directory or timing, and exhausted decode budgets.
pub fn authenticate_initial_proposal(
    expected: &ExpectedInitialAuthority,
    evidence: &InitialAuthorityEvidence<'_>,
    operational_policy_object: &[u8],
    budget: &mut DecodeBudget,
) -> Result<InitialBindingProposal, E2eeError> {
    if evidence.principals.is_empty() || evidence.principals.len() > MAX_BINDING_PRINCIPALS {
        return Err(E2eeError::LimitExceeded);
    }
    let package: ArcConversationBindingPackage = decode_object(
        evidence.binding_object,
        ArcWireObjectKind::ConversationBinding,
        budget,
    )?;
    if !package.binding.approvals.is_empty() || !package.root_binding_locks.is_empty() {
        return Err(E2eeError::InvalidValue);
    }
    anchors::binding(expected, None, &package)?;
    let binding = &package.binding.tbs;
    let route = verify_semantic_route(&expected.network_id, &binding.semantic_route)?;
    check_binding_shape(&expected.network_id, binding, &route)?;
    concrete_route(&expected.network_id, binding, &route)?;
    if verify_initial_member_plan(&package.initial_member_plan)? != binding.initial_member_plan_id {
        return Err(E2eeError::InvalidValue);
    }
    let core = ArcContextCoreTbs::decode_exact(evidence.context_core, budget)?;
    verify_proposed_core(&expected.network_id, &core, binding)?;
    anchors::core(binding, &core)?;
    let time = ValidationTime(core.initial_validation_time);
    let principals = anchors::principals(expected, &package, evidence.principals, time, budget)?;
    check_principals(binding, &route, &principals)?;
    let sequencer = anchors::sequencer(expected, evidence.sequencer_credential, &core, budget)?;
    let mut validity = sequencer.interval;
    let mut remaining = MAX_BINDING_APPROVALS;
    for (root, roster) in principals.values() {
        intersect(&mut validity, root.interval);
        intersect(&mut validity, roster.interval);
        let mut count = 0;
        for device in roster.devices.values().filter(|device| device.may_bind()) {
            intersect(&mut validity, device.interval);
            count += 1;
        }
        if count == 0 {
            return Err(E2eeError::InvalidValue);
        }
        remaining = remaining
            .checked_sub(count)
            .ok_or(E2eeError::LimitExceeded)?;
    }
    let initial = policy(
        binding,
        &principals,
        evidence.initial_policy_object,
        None,
        &mut validity,
        budget,
    )?;
    anchors::bootstrap(&package, &initial, &principals)?;
    let operational = policy(
        binding,
        &principals,
        operational_policy_object,
        Some(&initial),
        &mut validity,
        budget,
    )?;
    let creator = initial.council.first().ok_or(E2eeError::InvalidValue)?;
    let creator_only = initial.controllers.as_slice() == [creator.root_fingerprint]
        && initial.controller_threshold == 1;
    let agreed = match &route.key {
        SemanticRouteKey::Channel { authority_root, .. } => principals.values().all(|(root, _)| {
            root.fingerprint == *authority_root || operational.is_controller(&root.fingerprint)
        }),
        SemanticRouteKey::Direct { account_a, .. } => {
            operational.membership_policy == ArcMembershipPolicy::FixedDirect
                && principals
                    .get(account_a)
                    .is_some_and(|(root, _)| root.fingerprint == creator.root_fingerprint)
                && principals
                    .values()
                    .all(|(root, _)| operational.is_controller(&root.fingerprint))
        }
    };
    check_plan(
        &package.initial_member_plan,
        &route.key,
        &principals,
        &initial,
        &operational,
        &mut validity,
    )?;
    let entries = package.initial_member_plan.entries.as_slice();
    let planned_council = operational.council.iter().all(|member| {
        let Some((account, _)) = principals
            .iter()
            .find(|(_, (root, _))| root.fingerprint == member.root_fingerprint)
        else {
            return false;
        };
        let expected = (
            account.as_slice(),
            &member.root_fingerprint,
            &member.device_id,
        );
        entries
            .binary_search_by(|entry| {
                (
                    entry.account_id.as_slice(),
                    &entry.root_fingerprint,
                    &entry.device_id,
                )
                    .cmp(&expected)
            })
            .is_ok()
    });
    if !creator_only || !agreed || !planned_council || !validity.covers(time) {
        return Err(E2eeError::InvalidValue);
    }
    Ok(InitialBindingProposal {
        binding_id: expected.binding_id,
        binding: package.binding.tbs,
        plan: package.initial_member_plan,
        route,
        core,
        principals,
        initial,
        operational,
        sequencer,
        validity,
    })
}

fn check_plan(
    plan: &ArcInitialMemberPlan,
    route: &SemanticRouteKey,
    principals: &PrincipalRosters,
    initial: &VerifiedPolicy,
    operational: &VerifiedPolicy,
    validity: &mut Interval,
) -> Result<(), E2eeError> {
    let entries = plan.entries.as_slice();
    let leaf_limit = initial.max_group_leaves.min(operational.max_group_leaves);
    let device_limit = initial
        .max_devices_per_account
        .min(operational.max_devices_per_account);
    if entries.len() > leaf_limit as usize {
        return Err(E2eeError::LimitExceeded);
    }
    for group in entries.chunk_by(|left, right| left.account_id == right.account_id) {
        if group.len() > usize::from(device_limit) {
            return Err(E2eeError::LimitExceeded);
        }
        let first = group.first().ok_or(E2eeError::InvalidValue)?;
        let account = crate::objects::account_id_bytes(&first.account_id)?;
        if let Some((root, roster)) = principals.get(&account) {
            for member in group {
                if member.root_fingerprint != root.fingerprint {
                    return Err(E2eeError::InvalidValue);
                }
                let device = roster
                    .device(&member.device_id)
                    .ok_or(E2eeError::InvalidValue)?;
                intersect(validity, device.interval);
            }
        } else if matches!(route, SemanticRouteKey::Direct { .. }) {
            return Err(E2eeError::InvalidValue);
        }
    }
    Ok(())
}

fn intersect(result: &mut Interval, interval: Interval) {
    result.not_before = result.not_before.max(interval.not_before);
    result.not_after = result.not_after.min(interval.not_after);
}

fn policy(
    binding: &ArcConversationBindingTbs,
    principals: &PrincipalRosters,
    bytes: &[u8],
    previous: Option<&VerifiedPolicy>,
    validity: &mut Interval,
    budget: &mut DecodeBudget,
) -> Result<VerifiedPolicy, E2eeError> {
    let signed: ArcPolicy = decode_object(bytes, ArcWireObjectKind::Policy, budget)?;
    let checked = verify_policy(
        &binding.network_id,
        &binding.conversation_id,
        &signed,
        principals,
        previous,
    )?;
    let expected = if previous.is_some() {
        binding.required_operational_policy_id
    } else {
        binding.initial_policy_id
    };
    if checked.policy_id != expected
        || checked.kind != binding.kind
        || checked.selected_suite != binding.cipher_suite
        || !checked
            .controllers
            .iter()
            .all(|id| principals.values().any(|(root, _)| root.fingerprint == *id))
    {
        return Err(E2eeError::InvalidValue);
    }
    for (root, device) in signed
        .approvals
        .as_slice()
        .iter()
        .map(|a| (&a.signer_root_fingerprint, &a.signer_device_id))
        .chain(
            checked
                .council
                .iter()
                .map(|c| (&c.root_fingerprint, &c.device_id)),
        )
    {
        intersect(validity, active_device(principals, root, device)?.interval);
    }
    Ok(checked)
}
