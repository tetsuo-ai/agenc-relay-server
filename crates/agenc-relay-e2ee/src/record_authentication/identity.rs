//! Semantic IDs come from their registered TBS, including the referenced attempt.
#![forbid(unsafe_code)]

use crate::error::E2eeError;
use crate::ids::semantic_id_of;
use crate::object::{ArcWireObject, ArcWireObjectKind, ObjectId};
use crate::objects::reinit::{ArcReInitAttempt, ArcReInitAttemptReceipt};
use crate::objects::sequencing::ArcSequencerRecord;
use crate::tls::{DecodeBudget, TlsDecode};
use agenc_relay_crypto::SemanticHashDomain;

pub(super) fn verify(
    record: &ArcSequencerRecord,
    attempt_object: Option<&[u8]>,
    budget: &mut DecodeBudget,
) -> Result<[u8; 32], E2eeError> {
    if let ArcSequencerRecord::ReinitAttempt(receipt) = record {
        return attempt(
            receipt,
            attempt_object.ok_or(E2eeError::InvalidValue)?,
            budget,
        );
    }
    if attempt_object.is_some() {
        return Err(E2eeError::InvalidValue);
    }
    terminal_or_candidate(record)
}

fn terminal_or_candidate(record: &ArcSequencerRecord) -> Result<[u8; 32], E2eeError> {
    match record {
        ArcSequencerRecord::Candidate(value) => {
            semantic_id_of(SemanticHashDomain::CandidateId, &value.tbs)
        }
        ArcSequencerRecord::Finalization(value) => {
            let core = &value.tbs.request.proof.core;
            context(
                value.tbs.profile_version,
                &value.tbs.network_id,
                &value.tbs.conversation_id,
                core.profile_version,
                &core.network_id,
                &core.conversation_id,
            )?;
            asserted(
                value.tbs.finalization_id,
                semantic_id_of(SemanticHashDomain::FinalizationId, core)?,
            )
        }
        ArcSequencerRecord::Abort(value) => {
            let core = &value.tbs.request.core;
            context(
                value.tbs.profile_version,
                &value.tbs.network_id,
                &value.tbs.conversation_id,
                core.profile_version,
                &core.network_id,
                &core.conversation_id,
            )?;
            asserted(
                value.tbs.abort_id,
                semantic_id_of(SemanticHashDomain::AbortId, core)?,
            )
        }
        ArcSequencerRecord::ReinitActivation(value) => {
            let core = &value.tbs.request.core;
            context(
                value.tbs.profile_version,
                &value.tbs.network_id,
                &value.tbs.old_conversation_id,
                core.profile_version,
                &core.network_id,
                &core.old_conversation_id,
            )?;
            asserted(
                value.tbs.reinit_activation_id,
                semantic_id_of(SemanticHashDomain::ReinitActivationId, core)?,
            )
        }
        ArcSequencerRecord::ReinitAbort(value) => {
            let core = &value.tbs.request.core;
            context(
                value.tbs.profile_version,
                &value.tbs.network_id,
                &value.tbs.old_conversation_id,
                core.profile_version,
                &core.network_id,
                &core.old_conversation_id,
            )?;
            asserted(
                value.tbs.reinit_abort_id,
                semantic_id_of(SemanticHashDomain::ReinitAbortId, core)?,
            )
        }
        ArcSequencerRecord::ReinitAttempt(_) => Err(E2eeError::InvalidValue),
    }
}

fn asserted(expected: [u8; 32], computed: [u8; 32]) -> Result<[u8; 32], E2eeError> {
    if expected != computed {
        return Err(E2eeError::InvalidValue);
    }
    Ok(computed)
}

fn context(
    profile: u16,
    network: &[u8; 32],
    conversation: &[u8; 32],
    core_profile: u16,
    core_network: &[u8; 32],
    core_conversation: &[u8; 32],
) -> Result<(), E2eeError> {
    if (profile, network, conversation) != (core_profile, core_network, core_conversation) {
        return Err(E2eeError::ProfileMismatch);
    }
    Ok(())
}

fn attempt(
    receipt: &ArcReInitAttemptReceipt,
    bytes: &[u8],
    budget: &mut DecodeBudget,
) -> Result<[u8; 32], E2eeError> {
    let (kind, _) = ArcWireObject::peek(bytes)?;
    if kind != ArcWireObjectKind::ReinitAttempt {
        return Err(E2eeError::InvalidValue);
    }
    if ObjectId::compute(bytes).as_bytes() != &receipt.tbs.attempt_object_id {
        return Err(E2eeError::InvalidValue);
    }
    let object = ArcWireObject::decode_kind(bytes, Some(ArcWireObjectKind::ReinitAttempt), budget)?;
    let value = ArcReInitAttempt::decode_exact(object.body(), budget)?;
    let core = &value.tbs;
    let tbs = &receipt.tbs;
    context(
        tbs.profile_version,
        &tbs.network_id,
        &tbs.old_conversation_id,
        core.profile_version,
        &core.network_id,
        &core.old_conversation_id,
    )?;
    if tbs.old_reinit_state_id != core.old_reinit_state_id
        || tbs.attempt_sequence != core.attempt_sequence
    {
        return Err(E2eeError::InvalidValue);
    }
    asserted(
        tbs.reinit_attempt_id,
        semantic_id_of(SemanticHashDomain::ReinitAttemptId, core)?,
    )
}
