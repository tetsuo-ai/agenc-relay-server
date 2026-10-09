//! Checks reached only after comparing the binding to the independent pin.

#![forbid(unsafe_code)]

use super::{ExpectedInitialAuthority, InitialPrincipalEvidence, PriorTerminal, decode_object};
use crate::error::E2eeError;
use crate::identity::{
    Interval, ValidationTime, ensure_distinct_device_keys, restore_roster, verify_root_standalone,
};
use crate::ids::semantic_id_of;
use crate::limits::{MAX_BINDING_PRINCIPALS, PROFILE_VERSION};
use crate::object::ArcWireObjectKind;
use crate::objects::account_id_bytes;
use crate::objects::conversation::{
    ArcBindingPrincipal, ArcContextCoreTbs, ArcConversationBindingPackage,
    ArcConversationBindingTbs, ArcSequencerCredential,
};
use crate::objects::identity::{ArcDeviceRoster, ArcRootIdentity};
use crate::policy::VerifiedPolicy;
use crate::route::{PrincipalRosters, verify_semantic_route};
use crate::sequencer::VerifiedSequencerCredential;
use crate::signature::{RoleKey, SignerRole};
use crate::tls::{DecodeBudget, TlsDecode};
use agenc_relay_crypto::SemanticHashDomain;

pub(super) fn binding(
    expected: &ExpectedInitialAuthority,
    prior: Option<&PriorTerminal>,
    package: &ArcConversationBindingPackage,
) -> Result<(), E2eeError> {
    let tbs = &package.binding.tbs;
    if expected.binding_id == [0; 32]
        || tbs.network_id != expected.network_id
        || tbs.conversation_id != expected.conversation_id
        || semantic_id_of(SemanticHashDomain::BindingId, tbs)? != expected.binding_id
        || tbs.binding_generation != 0
    {
        return Err(E2eeError::InvalidValue);
    }
    // Incarnation zero opens its semantic route; a later incarnation opens
    // only after the exact close of the one before it (companion 9.4).
    let route = verify_semantic_route(&expected.network_id, &tbs.semantic_route)?;
    let anchored = match prior {
        None => route.incarnation == 0,
        Some(prior) => prior.precedes(&expected.network_id, &expected.conversation_id, &route),
    };
    if !anchored {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

pub(super) fn principals(
    expected: &ExpectedInitialAuthority,
    package: &ArcConversationBindingPackage,
    evidence: &[InitialPrincipalEvidence<'_>],
    time: ValidationTime,
    budget: &mut DecodeBudget,
) -> Result<PrincipalRosters, E2eeError> {
    let pins = package.binding.tbs.principals.as_slice();
    if pins.len() != evidence.len() || pins.len() > MAX_BINDING_PRINCIPALS {
        return Err(E2eeError::InvalidValue);
    }
    let mut result = PrincipalRosters::new();
    for (pin, pair) in pins.iter().zip(evidence) {
        let root: ArcRootIdentity =
            decode_object(pair.root_object, ArcWireObjectKind::RootIdentity, budget)?;
        let roster: ArcDeviceRoster =
            decode_object(pair.roster_object, ArcWireObjectKind::DeviceRoster, budget)?;
        let account = principal_pin(pin, &root, &roster)?;
        // Only the independently pinned binding permits these prefix omissions.
        let root = verify_root_standalone(&expected.network_id, &root)?;
        let roster = restore_roster(&root, &roster)?;
        if !root.interval.covers(time) || !roster.interval.covers(time) {
            return Err(E2eeError::InvalidValue);
        }
        if result.insert(account, (root, roster)).is_some() {
            return Err(E2eeError::NonCanonical);
        }
    }
    ensure_distinct_device_keys(result.values().map(|(_, roster)| roster))?;
    Ok(result)
}

fn principal_pin(
    pin: &ArcBindingPrincipal,
    root: &ArcRootIdentity,
    roster: &ArcDeviceRoster,
) -> Result<[u8; 24], E2eeError> {
    let account = account_id_bytes(&pin.account_id)?;
    if account_id_bytes(&root.tbs.account_id)? != account
        || semantic_id_of(SemanticHashDomain::RootFingerprint, &root.tbs)? != pin.root_fingerprint
        || semantic_id_of(SemanticHashDomain::RosterId, &roster.tbs)? != pin.roster_id
        || roster.tbs.roster_generation != pin.roster_generation
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(account)
}

pub(super) fn core(
    binding: &ArcConversationBindingTbs,
    core: &ArcContextCoreTbs,
) -> Result<(), E2eeError> {
    if core.mls_version != binding.mls_version
        || core.initial_policy_id != binding.initial_policy_id
        || core.required_operational_policy_id != binding.required_operational_policy_id
        || core.initial_policy_id == [0; 32]
        || core.required_operational_policy_id == [0; 32]
        || core.initial_policy_id == core.required_operational_policy_id
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

pub(super) fn bootstrap(
    package: &ArcConversationBindingPackage,
    policy: &VerifiedPolicy,
    principals: &PrincipalRosters,
) -> Result<(), E2eeError> {
    controller_roots(policy, principals)?;
    let [creator] = policy.council.as_slice() else {
        return Err(E2eeError::InvalidValue);
    };
    let (account, _) = principals
        .iter()
        .find(|(_, (root, _))| root.fingerprint == creator.root_fingerprint)
        .ok_or(E2eeError::InvalidValue)?;
    let planned = package
        .initial_member_plan
        .entries
        .as_slice()
        .iter()
        .any(|entry| {
            entry.root_fingerprint == creator.root_fingerprint
                && entry.device_id == creator.device_id
                && entry.account_id.as_slice() == account.as_slice()
        });
    if policy.kind != package.binding.tbs.kind
        || policy.selected_suite != package.binding.tbs.cipher_suite
        || policy.fault_bound != 0
        || !planned
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

fn controller_roots(
    policy: &VerifiedPolicy,
    principals: &PrincipalRosters,
) -> Result<(), E2eeError> {
    let resolved = policy.controllers.iter().all(|controller| {
        principals
            .values()
            .any(|(root, _)| root.fingerprint == *controller)
    });
    if !resolved {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

pub(super) fn sequencer(
    expected: &ExpectedInitialAuthority,
    bytes: &[u8],
    core: &ArcContextCoreTbs,
    budget: &mut DecodeBudget,
) -> Result<VerifiedSequencerCredential, E2eeError> {
    let credential = ArcSequencerCredential::decode_exact(bytes, budget)?;
    let tbs = &credential.tbs;
    let credential_id = semantic_id_of(SemanticHashDomain::SequencerKey, tbs)?;
    credential_shape(&credential)?;
    if credential_id != core.sequencer_credential_id
        || tbs.profile_version != PROFILE_VERSION
        || tbs.network_id != expected.network_id
        || tbs.not_before >= tbs.not_after
    {
        return Err(E2eeError::InvalidValue);
    }
    let interval = Interval {
        not_before: tbs.not_before,
        not_after: tbs.not_after,
    };
    if !interval.covers(ValidationTime(core.initial_validation_time)) {
        return Err(E2eeError::InvalidValue);
    }
    Ok(VerifiedSequencerCredential {
        credential_id,
        generation: tbs.key_generation,
        key: RoleKey::new(SignerRole::Sequencer, tbs.sequencer_public_key)?,
        interval,
        previous_key_id: tbs.previous_key_id,
    })
}

fn credential_shape(credential: &ArcSequencerCredential) -> Result<(), E2eeError> {
    let zero = credential.tbs.key_generation == 0;
    if zero != (credential.tbs.previous_key_id == [0; 32])
        || (zero && !credential.continuity_signature.is_empty())
        || (!zero && credential.continuity_signature.len() != 64)
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}
