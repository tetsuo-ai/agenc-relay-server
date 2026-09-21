//! Route identity and binding validation (companion Sections 9.1 and 9.4,
//! architecture Sections 18.1 and 18.3).
//!
//! A binding package is verified against the exact rosters its principals
//! name. Root-lock chain continuity per root is the caller's pin table
//! (`identity::AccountHeads`); the terminal-record authority of a
//! replacement binding is checked by the sequencer log. Endpoint-only: the
//! context core recomputation, which needs the full MLS context.

use std::collections::{BTreeMap, BTreeSet};

use agenc_relay_crypto::{SemanticHashDomain, SignatureDomain};

use crate::error::E2eeError;
use crate::identity::{AccountIdBytes, VerifiedRoot, VerifiedRoster};
use crate::ids::{SemanticId, canonical_channel_name_hash, conversation_id, semantic_id_of};
use crate::limits::{
    MAX_BINDING_APPROVALS, MAX_BINDING_PRINCIPALS, MLS_VERSION_MLS10, PROFILE_VERSION,
    suite_is_enabled,
};
use crate::objects::conversation::{
    ArcChannelRouteTbs, ArcCloseAuthorization, ArcConversationBindingPackage,
    ArcConversationBindingTbs, ArcConversationKind, ArcDirectRouteTbs, ArcInitialMemberPlan,
    ArcRootBindingLock, ArcSemanticRouteTbs,
};
use crate::objects::{account_id_bytes, group_id_bytes};
use crate::tls::{Opaque, TlsEncode, ensure_canonical};

/// Maximum canonical channel name length including `#`.
pub const MAX_CANONICAL_CHANNEL_NAME: usize = 64;

/// Canonicalizes an encrypted channel name under the Section 9.1 profile:
/// `#` plus 1 to 63 ASCII letters, digits, `.`, `_`, `-`, or `+`, with
/// uppercase letters lowered.
pub fn canonical_channel_name(name: &[u8]) -> Result<Vec<u8>, E2eeError> {
    let (first, rest) = name.split_first().ok_or(E2eeError::InvalidValue)?;
    if *first != b'#' || rest.is_empty() || name.len() > MAX_CANONICAL_CHANNEL_NAME {
        return Err(E2eeError::InvalidValue);
    }
    let mut canonical = Vec::new();
    canonical
        .try_reserve(name.len())
        .map_err(|_| E2eeError::BudgetExceeded)?;
    canonical.push(b'#');
    for byte in rest {
        let allowed = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+');
        if !allowed {
            return Err(E2eeError::InvalidValue);
        }
        canonical.push(byte.to_ascii_lowercase());
    }
    Ok(canonical)
}

/// The channel `route_binding`.
pub fn channel_route_binding(
    network_id: &[u8; 32],
    channel_instance_id: &[u8; 16],
) -> Result<SemanticId, E2eeError> {
    semantic_id_of(
        SemanticHashDomain::ChannelRoute,
        &ArcChannelRouteTbs {
            network_id: *network_id,
            channel_instance_id: *channel_instance_id,
        },
    )
}

/// The direct `route_binding`; the accounts are ordered by the caller.
pub fn direct_route_binding(
    network_id: &[u8; 32],
    conversation_nonce: &[u8; 32],
    account_a: &AccountIdBytes,
    account_b: &AccountIdBytes,
) -> Result<SemanticId, E2eeError> {
    if account_a >= account_b {
        return Err(E2eeError::InvalidValue);
    }
    semantic_id_of(
        SemanticHashDomain::DirectRoute,
        &ArcDirectRouteTbs {
            network_id: *network_id,
            conversation_nonce: *conversation_nonce,
            account_id_a: Opaque::from_slice(account_a)?,
            account_id_b: Opaque::from_slice(account_b)?,
        },
    )
}

/// The semantic anti-fork namespace of one conversation lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticRouteKey {
    /// A channel: canonical name plus the pinned authority root.
    Channel {
        /// Canonical channel name.
        canonical_name: Vec<u8>,
        /// Channel authority root fingerprint.
        authority_root: SemanticId,
    },
    /// A direct conversation: the ordered account pair.
    Direct {
        /// Smaller Account ID.
        account_a: AccountIdBytes,
        /// Larger Account ID.
        account_b: AccountIdBytes,
    },
}

/// A verified semantic route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticRoute {
    /// Conversation kind.
    pub kind: ArcConversationKind,
    /// The lock namespace key.
    pub key: SemanticRouteKey,
    /// Semantic incarnation.
    pub incarnation: u64,
    /// Predecessor close identifier, all zero at incarnation zero.
    pub predecessor_close_id: SemanticId,
    /// The semantic route lock identifier.
    pub lock_id: SemanticId,
}

/// Verifies the shape of a semantic route and computes its lock ID.
pub fn verify_semantic_route(
    network_id: &[u8; 32],
    tbs: &ArcSemanticRouteTbs,
) -> Result<SemanticRoute, E2eeError> {
    if tbs.profile_version != PROFILE_VERSION || tbs.network_id != *network_id {
        return Err(E2eeError::ProfileMismatch);
    }
    if (tbs.semantic_incarnation == 0) != (tbs.predecessor_close_id == [0; 32]) {
        return Err(E2eeError::InvalidValue);
    }
    let key = match tbs.kind {
        ArcConversationKind::Channel => {
            if !tbs.direct_account_a.is_empty()
                || !tbs.direct_account_b.is_empty()
                || tbs.channel_authority_root_fingerprint == [0; 32]
            {
                return Err(E2eeError::InvalidValue);
            }
            let canonical = canonical_channel_name(tbs.canonical_channel_name.as_slice())?;
            if canonical != tbs.canonical_channel_name.as_slice() {
                return Err(E2eeError::NonCanonical);
            }
            SemanticRouteKey::Channel {
                canonical_name: canonical,
                authority_root: tbs.channel_authority_root_fingerprint,
            }
        }
        ArcConversationKind::Direct => {
            if !tbs.canonical_channel_name.is_empty()
                || tbs.channel_authority_root_fingerprint != [0; 32]
            {
                return Err(E2eeError::InvalidValue);
            }
            let account_a = tbs.direct_account_a.exactly::<24>()?;
            let account_b = tbs.direct_account_b.exactly::<24>()?;
            if account_a >= account_b {
                return Err(E2eeError::NonCanonical);
            }
            SemanticRouteKey::Direct {
                account_a,
                account_b,
            }
        }
    };
    Ok(SemanticRoute {
        kind: tbs.kind,
        key,
        incarnation: tbs.semantic_incarnation,
        predecessor_close_id: tbs.predecessor_close_id,
        lock_id: semantic_id_of(SemanticHashDomain::SemanticRouteLock, tbs)?,
    })
}

/// One principal's verified root and roster, keyed by Account ID.
pub type PrincipalRosters = BTreeMap<AccountIdBytes, (VerifiedRoot, VerifiedRoster)>;

/// One verified root binding lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedLock {
    /// Account ID.
    pub account_id: AccountIdBytes,
    /// Root fingerprint.
    pub root_fingerprint: SemanticId,
    /// Global lock sequence for the root.
    pub sequence: u64,
    /// Previous lock identifier.
    pub previous_lock_id: SemanticId,
    /// This lock's identifier.
    pub lock_id: SemanticId,
}

/// A verified conversation binding package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBinding {
    /// Binding identifier.
    pub binding_id: SemanticId,
    /// Binding generation.
    pub generation: u64,
    /// Previous binding identifier, all zero at generation zero.
    pub previous_binding_id: SemanticId,
    /// The semantic route.
    pub route: SemanticRoute,
    /// Conversation identifier.
    pub conversation_id: SemanticId,
    /// Group identifier.
    pub group_id: [u8; 32],
    /// Concrete route binding.
    pub route_binding: SemanticId,
    /// Channel instance for a channel binding.
    pub channel_instance_id: Option<[u8; 16]>,
    /// Conversation nonce for a direct binding.
    pub conversation_nonce: Option<[u8; 32]>,
    /// Cipher suite.
    pub cipher_suite: u16,
    /// Initial member plan identifier.
    pub initial_member_plan_id: SemanticId,
    /// Context core identifier as carried.
    pub context_core_id: SemanticId,
    /// Sequencer credential identifier as carried.
    pub sequencer_credential_id: SemanticId,
    /// Principal Account IDs in canonical order.
    pub principals: Vec<AccountIdBytes>,
    /// Verified root locks, one per principal at generation zero.
    pub locks: Vec<VerifiedLock>,
}

/// Verifies a binding package against the rosters of its principals.
///
/// A generation-zero package needs unanimous approvals from every
/// binding-authorized device of every principal roster and one root lock
/// per principal; a replacement package carries empty vectors and derives
/// its authority from the referenced terminal record, which the caller
/// checks.
pub fn verify_binding_package(
    network_id: &[u8; 32],
    package: &ArcConversationBindingPackage,
    principals: &PrincipalRosters,
) -> Result<VerifiedBinding, E2eeError> {
    let tbs = &package.binding.tbs;
    let route = verify_semantic_route(network_id, &tbs.semantic_route)?;
    check_binding_shape(network_id, tbs, &route)?;
    let (group_id, route_binding, instance, nonce) = concrete_route(network_id, tbs, &route)?;
    let principal_ids = check_principals(tbs, &route, principals)?;
    let plan_id = verify_initial_member_plan(&package.initial_member_plan)?;
    if plan_id != tbs.initial_member_plan_id {
        return Err(E2eeError::InvalidValue);
    }
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, tbs)?;
    let locks = if tbs.binding_generation == 0 {
        check_unanimous_approvals(&package.binding, principals)?;
        verify_root_locks(
            tbs,
            binding_id,
            package.root_binding_locks.as_slice(),
            principals,
        )?
    } else {
        if !package.binding.approvals.is_empty() || !package.root_binding_locks.is_empty() {
            return Err(E2eeError::InvalidValue);
        }
        Vec::new()
    };
    Ok(VerifiedBinding {
        binding_id,
        generation: tbs.binding_generation,
        previous_binding_id: tbs.previous_binding_id,
        route,
        conversation_id: tbs.conversation_id,
        group_id,
        route_binding,
        channel_instance_id: instance,
        conversation_nonce: nonce,
        cipher_suite: tbs.cipher_suite,
        initial_member_plan_id: tbs.initial_member_plan_id,
        context_core_id: tbs.context_core_id,
        sequencer_credential_id: tbs.sequencer_credential_id,
        principals: principal_ids,
        locks,
    })
}

fn check_binding_shape(
    network_id: &[u8; 32],
    tbs: &ArcConversationBindingTbs,
    route: &SemanticRoute,
) -> Result<(), E2eeError> {
    if tbs.profile_version != PROFILE_VERSION
        || tbs.network_id != *network_id
        || tbs.mls_version != MLS_VERSION_MLS10
        || !suite_is_enabled(tbs.cipher_suite)
    {
        return Err(E2eeError::ProfileMismatch);
    }
    let zero = tbs.binding_generation == 0;
    if tbs.kind != route.kind
        || tbs.semantic_route_lock_id != route.lock_id
        || zero != (tbs.previous_binding_id == [0; 32])
        || tbs.context_core_id == [0; 32]
        || tbs.sequencer_credential_id == [0; 32]
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

type ConcreteRoute = ([u8; 32], SemanticId, Option<[u8; 16]>, Option<[u8; 32]>);

fn concrete_route(
    network_id: &[u8; 32],
    tbs: &ArcConversationBindingTbs,
    route: &SemanticRoute,
) -> Result<ConcreteRoute, E2eeError> {
    let group_id = group_id_bytes(&tbs.group_id)?;
    if tbs.conversation_id != conversation_id(network_id, &group_id)? {
        return Err(E2eeError::InvalidValue);
    }
    let instance = tbs.channel_instance_id.empty_or_fixed::<16>()?;
    let nonce = tbs.conversation_nonce.empty_or_fixed::<32>()?;
    let expected = match (&route.key, instance, nonce) {
        (SemanticRouteKey::Channel { .. }, Some(instance), None) => {
            channel_route_binding(network_id, &instance)?
        }
        (
            SemanticRouteKey::Direct {
                account_a,
                account_b,
            },
            None,
            Some(nonce),
        ) => direct_route_binding(network_id, &nonce, account_a, account_b)?,
        _ => return Err(E2eeError::InvalidValue),
    };
    if tbs.route_binding != expected {
        return Err(E2eeError::InvalidValue);
    }
    Ok((group_id, expected, instance, nonce))
}

fn check_principals(
    tbs: &ArcConversationBindingTbs,
    route: &SemanticRoute,
    principals: &PrincipalRosters,
) -> Result<Vec<AccountIdBytes>, E2eeError> {
    let entries = tbs.principals.as_slice();
    if entries.len() > MAX_BINDING_PRINCIPALS {
        return Err(E2eeError::LimitExceeded);
    }
    ensure_canonical(entries, |entry| entry.account_id.clone())?;
    let mut ids = Vec::new();
    ids.try_reserve(entries.len())
        .map_err(|_| E2eeError::BudgetExceeded)?;
    for entry in entries {
        let account_id = account_id_bytes(&entry.account_id)?;
        let (root, roster) = principals.get(&account_id).ok_or(E2eeError::InvalidValue)?;
        if entry.root_fingerprint != root.fingerprint
            || entry.roster_generation != roster.generation
            || entry.roster_id != roster.roster_id
        {
            return Err(E2eeError::InvalidValue);
        }
        ids.push(account_id);
    }
    match &route.key {
        SemanticRouteKey::Direct {
            account_a,
            account_b,
        } => {
            if ids != [*account_a, *account_b] {
                return Err(E2eeError::InvalidValue);
            }
        }
        SemanticRouteKey::Channel { authority_root, .. } => {
            let authority_present = principals
                .values()
                .any(|(root, _)| root.fingerprint == *authority_root);
            if !authority_present {
                return Err(E2eeError::InvalidValue);
            }
        }
    }
    Ok(ids)
}

/// Verifies the canonical shape of an initial member plan and returns its
/// identifier.
pub fn verify_initial_member_plan(plan: &ArcInitialMemberPlan) -> Result<SemanticId, E2eeError> {
    let entries = plan.entries.as_slice();
    ensure_canonical(entries, |entry| {
        (
            entry.account_id.clone(),
            entry.root_fingerprint,
            entry.device_id,
        )
    })?;
    let mut devices = BTreeSet::new();
    let mut capabilities = BTreeSet::new();
    for entry in entries {
        account_id_bytes(&entry.account_id)?;
        if !devices.insert(entry.device_id) || !capabilities.insert(entry.capability_id) {
            return Err(E2eeError::NonCanonical);
        }
    }
    semantic_id_of(SemanticHashDomain::InitialMemberPlanId, plan)
}

fn check_unanimous_approvals(
    binding: &crate::objects::conversation::ArcConversationBinding,
    principals: &PrincipalRosters,
) -> Result<(), E2eeError> {
    let approvals = binding.approvals.as_slice();
    if approvals.len() > MAX_BINDING_APPROVALS {
        return Err(E2eeError::LimitExceeded);
    }
    ensure_canonical(approvals, |approval| {
        (approval.signer_root_fingerprint, approval.signer_device_id)
    })?;
    let encoded = binding.tbs.encode()?;
    let mut required = BTreeSet::new();
    for (root, roster) in principals.values() {
        for certificate in roster.devices.values().filter(|device| device.may_bind()) {
            required.insert((root.fingerprint, certificate.device_id));
        }
    }
    if required.is_empty() {
        return Err(E2eeError::InvalidValue);
    }
    let mut seen = BTreeSet::new();
    for approval in approvals {
        let signer = (approval.signer_root_fingerprint, approval.signer_device_id);
        let (_, roster) = principals
            .values()
            .find(|(root, _)| root.fingerprint == signer.0)
            .ok_or(E2eeError::InvalidValue)?;
        let certificate = roster.device(&signer.1).ok_or(E2eeError::InvalidValue)?;
        if !certificate.may_bind()
            || certificate.certificate_id != approval.signer_device_certificate_id
        {
            return Err(E2eeError::InvalidValue);
        }
        certificate.key.verify(
            SignatureDomain::ConversationBinding,
            &encoded,
            &approval.device_signature,
        )?;
        seen.insert(signer);
    }
    if seen != required {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

fn verify_root_locks(
    tbs: &ArcConversationBindingTbs,
    binding_id: SemanticId,
    locks: &[ArcRootBindingLock],
    principals: &PrincipalRosters,
) -> Result<Vec<VerifiedLock>, E2eeError> {
    ensure_canonical(locks, |lock| lock.tbs.account_id.clone())?;
    if locks.len() != principals.len() {
        return Err(E2eeError::InvalidValue);
    }
    let mut verified = Vec::new();
    verified
        .try_reserve(locks.len())
        .map_err(|_| E2eeError::BudgetExceeded)?;
    for lock in locks {
        let account_id = account_id_bytes(&lock.tbs.account_id)?;
        let (root, roster) = principals.get(&account_id).ok_or(E2eeError::InvalidValue)?;
        let lock_tbs = &lock.tbs;
        if !lock_names_binding(lock_tbs, tbs, binding_id, root, roster) {
            return Err(E2eeError::InvalidValue);
        }
        root.key.verify(
            SignatureDomain::RootBindingLock,
            &lock_tbs.encode()?,
            &lock.root_signature,
        )?;
        verified.push(VerifiedLock {
            account_id,
            root_fingerprint: root.fingerprint,
            sequence: lock_tbs.root_binding_sequence,
            previous_lock_id: lock_tbs.previous_root_binding_lock_id,
            lock_id: semantic_id_of(SemanticHashDomain::RootBindingLockId, lock_tbs)?,
        });
    }
    Ok(verified)
}

/// Whether a root lock names exactly this binding, principal roster, and
/// lock namespace, with a lineage-consistent sequence.
fn lock_names_binding(
    lock: &crate::objects::conversation::ArcRootBindingLockTbs,
    tbs: &ArcConversationBindingTbs,
    binding_id: SemanticId,
    root: &VerifiedRoot,
    roster: &VerifiedRoster,
) -> bool {
    let sequence_zero = lock.root_binding_sequence == 0;
    lock.profile_version == PROFILE_VERSION
        && lock.network_id == tbs.network_id
        && lock.root_fingerprint == root.fingerprint
        && lock.semantic_route_lock_id == tbs.semantic_route_lock_id
        && lock.binding_id == binding_id
        && lock.roster_generation == roster.generation
        && lock.roster_id == roster.roster_id
        && sequence_zero == (lock.previous_root_binding_lock_id == [0; 32])
}

/// Whether `successor` may replace `current` in the same lineage: the next
/// generation naming the current binding, the same semantic route lock,
/// and the same conversation kind.
#[must_use]
pub fn is_binding_successor(current: &VerifiedBinding, successor: &VerifiedBinding) -> bool {
    current.generation.checked_add(1) == Some(successor.generation)
        && successor.previous_binding_id == current.binding_id
        && successor.route.lock_id == current.route.lock_id
        && successor.route.kind == current.route.kind
}

/// Whether `next` opens the next semantic incarnation after a lineage
/// closed with `close_id`.
#[must_use]
pub fn is_next_incarnation(
    closed: &SemanticRoute,
    close_id: SemanticId,
    next: &SemanticRoute,
) -> bool {
    closed.key == next.key
        && closed.incarnation.checked_add(1) == Some(next.incarnation)
        && next.predecessor_close_id == close_id
}

/// The channel-name hash carried in route state.
pub fn channel_name_hash(canonical_name: &[u8]) -> Result<SemanticId, E2eeError> {
    canonical_channel_name_hash(canonical_name)
}

/// The structural shape of a close authorization and its semantic close
/// identifier; controller signatures are checked by the policy validator.
pub fn close_authorization_id(close: &ArcCloseAuthorization) -> Result<SemanticId, E2eeError> {
    let tbs = &close.tbs;
    if tbs.profile_version != PROFILE_VERSION {
        return Err(E2eeError::ProfileMismatch);
    }
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &tbs.close_intent)?;
    if intent_id != tbs.close_intent_id {
        return Err(E2eeError::InvalidValue);
    }
    ensure_canonical(close.approvals.as_slice(), |approval| {
        (approval.signer_root_fingerprint, approval.signer_device_id)
    })?;
    semantic_id_of(SemanticHashDomain::CloseAuthorizationId, tbs)
}

#[cfg(test)]
#[path = "tests/route.rs"]
mod tests;
