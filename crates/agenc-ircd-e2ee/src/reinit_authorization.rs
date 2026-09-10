//! Public controller authority for one exact ReInit attempt (companion 13.8).
#![forbid(unsafe_code)]
use crate::E2eeError;
use crate::ids::{initial_commit_digest, semantic_id_of};
use crate::objects::reinit::{IrcReInitAttempt, IrcReInitAttemptAuthorizationTbs};
use crate::policy::{VerifiedPolicy, active_device};
use crate::route::PrincipalRosters;
use crate::tls::{TlsEncode, ensure_canonical};
use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};
use std::collections::BTreeSet;

/// The caller supplies the authenticated current policy and principal rosters.
/// This verifies public controller approval, not MLS creator membership or the target tree.
pub fn verify_reinit_attempt_authorization(
    attempt: &IrcReInitAttempt,
    policy: &VerifiedPolicy,
    rosters: &PrincipalRosters,
) -> Result<(), E2eeError> {
    check_public_links(attempt)?;
    if policy.conversation_id != attempt.tbs.old_conversation_id || policy.controller_threshold == 0
    {
        return Err(E2eeError::InvalidValue);
    }
    let approvals = attempt.authorization.approvals.as_slice();
    ensure_canonical(approvals, |approval| {
        (approval.signer_root_fingerprint, approval.signer_device_id)
    })?;
    let encoded = attempt.authorization.tbs.encode()?;
    let mut roots = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for approval in approvals {
        if !policy.is_controller(&approval.signer_root_fingerprint) {
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
            SignatureDomain::ReinitAttemptAuthorization,
            &encoded,
            &approval.device_signature,
        )?;
        if !roots.insert(approval.signer_root_fingerprint)
            || !keys.insert(*certificate.key.as_bytes())
        {
            return Err(E2eeError::NonCanonical);
        }
    }
    if roots.len() < usize::from(policy.controller_threshold) {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

fn check_public_links(attempt: &IrcReInitAttempt) -> Result<(), E2eeError> {
    let tbs = &attempt.tbs;
    if tbs.profile_version != 1
        || attempt.authorization.tbs != expected_authorization(attempt)
        || semantic_id_of(
            SemanticHashDomain::ReinitAttemptAuthorizationId,
            &attempt.authorization.tbs,
        )? != tbs.attempt_authorization_id
        || semantic_id_of(
            SemanticHashDomain::KeyPackagePlanId,
            &attempt.key_package_plan,
        )? != tbs.key_package_plan_id
        || initial_commit_digest(attempt.initial_commit_bytes.as_slice())?
            != tbs.initial_commit_digest
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

fn expected_authorization(attempt: &IrcReInitAttempt) -> IrcReInitAttemptAuthorizationTbs {
    let tbs = &attempt.tbs;
    IrcReInitAttemptAuthorizationTbs {
        profile_version: tbs.profile_version,
        network_id: tbs.network_id,
        old_conversation_id: tbs.old_conversation_id,
        old_reinit_state_id: tbs.old_reinit_state_id,
        attempt_sequence: tbs.attempt_sequence,
        creator_old_leaf_index: tbs.creator_old_leaf_index,
        creator_old_credential_hash: tbs.creator_old_credential_hash,
        new_conversation_id: tbs.new_conversation_id,
        target_context_digest: tbs.target_context_digest,
        target_binding_id: tbs.target_binding_id,
        initial_member_plan_id: tbs.initial_member_plan_id,
        key_package_plan_id: tbs.key_package_plan_id,
        initial_commit_digest: tbs.initial_commit_digest,
        new_group_info_digest: tbs.new_group_info_digest,
        new_group_context_digest: tbs.new_group_context_digest,
        new_ratchet_tree_digest: tbs.new_ratchet_tree_digest,
        new_exporter_authenticator: tbs.new_exporter_authenticator,
    }
}
