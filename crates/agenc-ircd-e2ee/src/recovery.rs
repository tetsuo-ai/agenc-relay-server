//! Recovery submissions (companion Section 13.7.4): a device-signed carrier
//! that binds one uploaded element to the exact restored route a pending
//! gate pins, so a restored server adopts evidence only from an attached
//! principal device and only at the next chain position.

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};

use crate::error::E2eeError;
use crate::identity::VerifiedRoster;
use crate::ids::{SemanticId, semantic_id_of};
use crate::object::IrcWireObjectKind;
use crate::objects::account_id_bytes;
use crate::objects::recovery::{IrcRecoveryElementKind, IrcRecoverySubmission};
use crate::tls::TlsEncode;

/// The object kinds a `reference_element` may name: every public object a
/// submitted record can reference (companion 13.7.2).
pub const REFERENCE_ELEMENT_KINDS: [IrcWireObjectKind; 6] = [
    IrcWireObjectKind::Policy,
    IrcWireObjectKind::RootIdentity,
    IrcWireObjectKind::RootIdentityChain,
    IrcWireObjectKind::DeviceRoster,
    IrcWireObjectKind::ConversationBinding,
    IrcWireObjectKind::ReinitAttempt,
];

/// Why a submission was refused, in the Section 13.7.4 failure classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryRefusal {
    /// Malformed or inconsistent submission (`E2EE_INVALID_FRAGMENT`).
    Invalid,
    /// The submitting device is not active in the roster (`E2EE_DEVICE_REQUIRED`).
    DeviceInactive,
    /// The device signature does not verify (`E2EE_BINDING_AUTH_INVALID`).
    SignatureInvalid,
}

impl From<RecoveryRefusal> for E2eeError {
    fn from(refusal: RecoveryRefusal) -> Self {
        match refusal {
            RecoveryRefusal::Invalid => Self::InvalidValue,
            RecoveryRefusal::DeviceInactive => Self::KeyInvalid,
            RecoveryRefusal::SignatureInvalid => Self::SignatureInvalid,
        }
    }
}

/// A submission whose shape and device signature verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRecoverySubmission {
    /// `recovery_submission_id`, the Section 2.2 hash of the TBS.
    pub submission_id: SemanticId,
    /// The restored conversation.
    pub conversation_id: [u8; 32],
    /// The gate facts the submission binds to.
    pub recovery_epoch: [u8; 16],
    /// The gate's restored binding.
    pub restored_binding_id: [u8; 32],
    /// The gate's restored accepted state.
    pub restored_accepted_state_id: [u8; 32],
    /// The gate's restored sequencer head.
    pub restored_sequencer_head_id: [u8; 32],
    /// The gate's source rollback guard.
    pub source_rollback_guard_hash: [u8; 32],
    /// The route sequence the element occupies.
    pub route_sequence: u64,
    /// The record the element succeeds.
    pub predecessor_record_id: [u8; 32],
    /// What the element is.
    pub element_kind: IrcRecoveryElementKind,
    /// The element's wire kind.
    pub element_object_kind: IrcWireObjectKind,
    /// The element's object identifier.
    pub element_object_id: [u8; 32],
    /// The submitting account.
    pub account_id: [u8; 24],
    /// The submitting device.
    pub device_id: [u8; 16],
}

/// Whether `object_kind` is a valid element of `element_kind`.
#[must_use]
pub fn element_kind_accepts(
    element_kind: IrcRecoveryElementKind,
    object_kind: IrcWireObjectKind,
) -> bool {
    match element_kind {
        IrcRecoveryElementKind::RecordElement => object_kind == IrcWireObjectKind::SequencerRecord,
        IrcRecoveryElementKind::CloseElement => {
            object_kind == IrcWireObjectKind::CloseAuthorization
        }
        IrcRecoveryElementKind::ReferenceElement => REFERENCE_ELEMENT_KINDS.contains(&object_kind),
    }
}

/// Verifies a submission's shape against the network and the device
/// signature under the submitting device's certificate in `roster`, the
/// retained roster of the submitting account.
pub fn verify_recovery_submission(
    network_id: &[u8; 32],
    submission: &IrcRecoverySubmission,
    roster: &VerifiedRoster,
) -> Result<VerifiedRecoverySubmission, RecoveryRefusal> {
    let tbs = &submission.tbs;
    let account_id = account_id_bytes(&tbs.account_id).map_err(|_| RecoveryRefusal::Invalid)?;
    if tbs.profile_version != 1
        || tbs.network_id != *network_id
        || !element_kind_accepts(tbs.element_kind, tbs.element_object_kind)
        || tbs.element_object_id == [0; 32]
    {
        return Err(RecoveryRefusal::Invalid);
    }
    let certificate = roster
        .device(&tbs.device_id)
        .ok_or(RecoveryRefusal::DeviceInactive)?;
    let encoded = tbs.encode().map_err(|_| RecoveryRefusal::Invalid)?;
    certificate
        .key
        .verify(
            SignatureDomain::RecoverySubmission,
            &encoded,
            &submission.device_signature,
        )
        .map_err(|_| RecoveryRefusal::SignatureInvalid)?;
    let submission_id = semantic_id_of(SemanticHashDomain::RecoverySubmissionId, tbs)
        .map_err(|_| RecoveryRefusal::Invalid)?;
    Ok(VerifiedRecoverySubmission {
        submission_id,
        conversation_id: tbs.conversation_id,
        recovery_epoch: tbs.recovery_epoch,
        restored_binding_id: tbs.restored_binding_id,
        restored_accepted_state_id: tbs.restored_accepted_state_id,
        restored_sequencer_head_id: tbs.restored_sequencer_head_id,
        source_rollback_guard_hash: tbs.source_rollback_guard_hash,
        route_sequence: tbs.route_sequence,
        predecessor_record_id: tbs.predecessor_record_id,
        element_kind: tbs.element_kind,
        element_object_kind: tbs.element_object_kind,
        element_object_id: tbs.element_object_id,
        account_id,
        device_id: tbs.device_id,
    })
}

#[cfg(test)]
#[path = "tests/recovery.rs"]
mod tests;
