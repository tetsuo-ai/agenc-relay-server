//! Historical ACK authentication from validated leaf-membership facts
//! (companion 13.7.3). A caller that holds the conversation's verified
//! proofs passes them with a record; every ACK a finalization or ReInit
//! activation embeds must then be signed by the continuing leaf a stored
//! proof identifies, no device may sign twice, and a ReInit ACK must name
//! its signer's own plan entry. A finalization's identified signers are
//! returned, so their roots and rosters are checked against the record's
//! validation time with its other signers (`liveness`). Device activity at
//! record time and the exact continuing set stay the caller's and the
//! endpoint's checks.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use agenc_relay_crypto::SignatureDomain;

use super::RecordReferences;
use super::liveness::SigningDevices;
use crate::error::E2eeError;
use crate::membership::{LeafMembershipSet, planned_ack_device, signing_device};
use crate::objects::reinit::ArcReInitActivationRequest;
use crate::objects::sequencing::ArcFinalizationProof;

/// Applies the supplied facts, if any, to a finalization proof, returning
/// the signing devices they identify; without facts no ACK signer is known.
pub(super) fn authenticate_finalization(
    references: &RecordReferences<'_>,
    proof: &ArcFinalizationProof,
) -> Result<SigningDevices, E2eeError> {
    references
        .memberships
        .map_or(Ok(SigningDevices::new()), |memberships| {
            authenticate_commit_acks(memberships, proof)
        })
}

/// Applies the supplied facts, if any, to a ReInit activation request.
pub(super) fn authenticate_activation(
    references: &RecordReferences<'_>,
    request: &ArcReInitActivationRequest,
    epoch: u64,
) -> Result<(), E2eeError> {
    references.memberships.map_or(Ok(()), |memberships| {
        authenticate_reinit_acks(memberships, request, epoch)
    })
}

/// Every Commit ACK of a finalization proof is identified at its prior
/// epoch by a distinct signing device.
fn authenticate_commit_acks(
    memberships: &LeafMembershipSet,
    proof: &ArcFinalizationProof,
) -> Result<SigningDevices, E2eeError> {
    let mut signers = SigningDevices::new();
    for ack in proof.acknowledgements.as_slice() {
        memberships.identify_distinct(
            &mut signers,
            ack.tbs.old_leaf_index,
            &ack.tbs.old_credential_hash,
            ack.tbs.prior_epoch,
            SignatureDomain::CommitProcessed,
            &ack.tbs,
            ack.old_leaf_signature.as_slice(),
        )?;
    }
    Ok(signers)
}

/// Every ReInit ACK of an activation is identified against the old group's
/// accepted `epoch` by a distinct device that owns the plan entry its role
/// names.
fn authenticate_reinit_acks(
    memberships: &LeafMembershipSet,
    request: &ArcReInitActivationRequest,
    epoch: u64,
) -> Result<(), E2eeError> {
    let mut signers = BTreeSet::new();
    for ack in request.acknowledgements.as_slice() {
        let entry = memberships.identify_distinct(
            &mut signers,
            ack.tbs.old_leaf_index,
            &ack.tbs.old_credential_hash,
            epoch,
            SignatureDomain::ReinitProcessed,
            &ack.tbs,
            ack.old_leaf_signature.as_slice(),
        )?;
        if planned_ack_device(&ack.tbs, &request.attempt) != Some(signing_device(entry)) {
            return Err(E2eeError::InvalidValue);
        }
    }
    Ok(())
}
