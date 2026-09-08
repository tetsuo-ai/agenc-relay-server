//! Public close approvals under the last finalized policy (companion 11.5).
//! The caller authenticates the referenced closing transition and its exact intent.
#![forbid(unsafe_code)]
use std::collections::BTreeSet;

use crate::E2eeError;
use crate::ids::SemanticId;
use crate::objects::conversation::IrcCloseAuthorization;
use crate::policy::{VerifiedPolicy, active_device};
use crate::route::{PrincipalRosters, close_authorization_id};
use crate::tls::TlsEncode;

#[cfg(test)]
#[path = "tests/close.rs"]
mod tests;
use agenc_ircd_crypto::SignatureDomain;

/// Checks the close shape, controller threshold and distinct authorized signing keys.
/// The policy and rosters must be authenticated for this conversation; this function
/// does not establish MLS membership or authenticate the referenced finalization.
pub fn verify_close_approvals(
    close: &IrcCloseAuthorization,
    policy: &VerifiedPolicy,
    rosters: &PrincipalRosters,
) -> Result<SemanticId, E2eeError> {
    let id = close_authorization_id(close)?;
    if policy.conversation_id != close.tbs.conversation_id || policy.controller_threshold == 0 {
        return Err(E2eeError::InvalidValue);
    }
    let encoded = close.tbs.encode()?;
    let mut roots = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for approval in close.approvals.as_slice() {
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
            SignatureDomain::CloseAuthorization,
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
    Ok(id)
}
