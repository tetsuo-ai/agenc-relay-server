//! Welcome delivery wrappers (companion Sections 12.4 and 13.8) and the join
//! transition proof bundle (Section 9.5).
//!
//! The server checks the wrapper's target and conversation, the size bounds,
//! the canonical proof bundle, and that the embedded MLS Welcome addresses
//! the delivered KeyPackage reference. Endpoint-only: consuming the Welcome,
//! tree and confirmation checks, and every referenced proof's verification.

use crate::error::E2eeError;
use crate::ids::SemanticId;
use crate::limits::{
    MAX_EMBEDDED_MLS_WELCOME_BYTES, MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES, PROFILE_VERSION,
};
use crate::mls_outer::{MlsOuterMessage, WelcomeHeader, parse_mls_message};
use crate::objects::conversation::{ArcJoinTransitionProofBundle, ArcJoinTransitionProofReference};
use crate::objects::reinit::ArcStagedReInit;
use crate::objects::sequencing::ArcDeliveredWelcome;
use crate::tls::{DecodeBudget, TlsEncode, ensure_canonical};

/// The mailbox target a wrapper must name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WelcomeTarget {
    /// The target account digest.
    pub account_id_digest: SemanticId,
    /// The target device identity.
    pub device_id: [u8; 16],
}

/// A verified normal Welcome wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWelcome {
    /// Conversation identifier.
    pub conversation_id: SemanticId,
    /// The finalization identifier that authorized the join.
    pub finalization_id: SemanticId,
    /// The finalization object identifier.
    pub finalization_object_id: SemanticId,
    /// The consumed KeyPackage reference.
    pub key_package_ref: Vec<u8>,
    /// The resulting leaf index.
    pub leaf_index: u32,
    /// The embedded Welcome header.
    pub welcome: WelcomeHeader,
    /// The proof references, canonical.
    pub references: Vec<ArcJoinTransitionProofReference>,
}

/// Verifies a delivered Welcome for `target` in `conversation_id`.
pub fn verify_delivered_welcome(
    network_id: &[u8; 32],
    welcome: &ArcDeliveredWelcome,
    conversation_id: &SemanticId,
    target: &WelcomeTarget,
    budget: &mut DecodeBudget,
) -> Result<VerifiedWelcome, E2eeError> {
    if welcome.profile_version != PROFILE_VERSION || welcome.network_id != *network_id {
        return Err(E2eeError::ProfileMismatch);
    }
    if welcome.conversation_id != *conversation_id
        || welcome.target_account_id_digest != target.account_id_digest
        || welcome.target_device_id != target.device_id
    {
        return Err(E2eeError::InvalidValue);
    }
    let references = verify_proof_bundle(&welcome.transition_proofs)?;
    let key_package_ref = welcome
        .authorization
        .added_key_package_ref
        .as_slice()
        .to_vec();
    let header = embedded_welcome(welcome.welcome_bytes.as_slice(), &key_package_ref, budget)?;
    Ok(VerifiedWelcome {
        conversation_id: welcome.conversation_id,
        finalization_id: welcome.authorization.finalization_id,
        finalization_object_id: welcome.authorization.finalization_object_id,
        key_package_ref,
        leaf_index: welcome.authorization.resulting_leaf_index,
        welcome: header,
        references,
    })
}

/// A verified staged ReInit wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStagedReInit {
    /// The old conversation identifier from the receipt.
    pub old_conversation_id: SemanticId,
    /// The new conversation identifier.
    pub new_conversation_id: SemanticId,
    /// The old ReInit finalization identifier.
    pub old_reinit_state_id: SemanticId,
    /// The attempt identifier from the receipt.
    pub reinit_attempt_id: SemanticId,
    /// The embedded Welcome header.
    pub welcome: WelcomeHeader,
    /// The proof references, canonical.
    pub references: Vec<ArcJoinTransitionProofReference>,
}

/// Verifies a staged ReInit wrapper for `target`, whose receipt names the
/// old conversation and the attempt being staged.
pub fn verify_staged_reinit(
    network_id: &[u8; 32],
    staged: &ArcStagedReInit,
    target: &WelcomeTarget,
    budget: &mut DecodeBudget,
) -> Result<VerifiedStagedReInit, E2eeError> {
    let receipt = &staged.receipt.tbs;
    if receipt.profile_version != PROFILE_VERSION || receipt.network_id != *network_id {
        return Err(E2eeError::ProfileMismatch);
    }
    if staged.target_account_id_digest != target.account_id_digest
        || staged.target_device_id != target.device_id
        || staged.old_reinit_state_id != receipt.old_reinit_state_id
        || staged.new_conversation_id == receipt.old_conversation_id
    {
        return Err(E2eeError::InvalidValue);
    }
    let references = verify_proof_bundle(&staged.transition_proofs)?;
    let header = welcome_header(staged.welcome_bytes.as_slice(), budget)?;
    Ok(VerifiedStagedReInit {
        old_conversation_id: receipt.old_conversation_id,
        new_conversation_id: staged.new_conversation_id,
        old_reinit_state_id: staged.old_reinit_state_id,
        reinit_attempt_id: receipt.reinit_attempt_id,
        welcome: header,
        references,
    })
}

/// Checks a proof bundle's canonical order, uniqueness, and size, returning
/// its references.
pub fn verify_proof_bundle(
    bundle: &ArcJoinTransitionProofBundle,
) -> Result<Vec<ArcJoinTransitionProofReference>, E2eeError> {
    if bundle.encode()?.len() > MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES {
        return Err(E2eeError::LimitExceeded);
    }
    let references = bundle.references.as_slice();
    ensure_canonical(references, |reference| {
        (
            reference.subject_kind,
            reference.subject_id,
            reference.proof_role,
        )
    })?;
    Ok(references.to_vec())
}

fn embedded_welcome(
    bytes: &[u8],
    key_package_ref: &[u8],
    budget: &mut DecodeBudget,
) -> Result<WelcomeHeader, E2eeError> {
    let header = welcome_header(bytes, budget)?;
    if !header
        .new_member_refs
        .iter()
        .any(|reference| reference.as_slice() == key_package_ref)
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(header)
}

fn welcome_header(bytes: &[u8], budget: &mut DecodeBudget) -> Result<WelcomeHeader, E2eeError> {
    if bytes.len() > MAX_EMBEDDED_MLS_WELCOME_BYTES {
        return Err(E2eeError::LimitExceeded);
    }
    match parse_mls_message(bytes, budget)? {
        MlsOuterMessage::Welcome(header) => Ok(header),
        _ => Err(E2eeError::WrongKind),
    }
}

#[cfg(test)]
#[path = "tests/welcome.rs"]
mod tests;
