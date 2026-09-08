//! Semantic IDs come from their registered TBS, including the referenced attempt.
#![forbid(unsafe_code)]

use crate::error::E2eeError;
use crate::ids::semantic_id_of;
use crate::object::{IrcWireObject, IrcWireObjectKind, ObjectId};
use crate::objects::reinit::{IrcReInitAttempt, IrcReInitAttemptReceipt};
use crate::objects::sequencing::IrcSequencerRecord;
use crate::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_crypto::SemanticHashDomain;

pub(super) fn verify(
    record: &IrcSequencerRecord,
    attempt_object: Option<&[u8]>,
    budget: &mut DecodeBudget,
) -> Result<[u8; 32], E2eeError> {
    if let IrcSequencerRecord::ReinitAttempt(receipt) = record {
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

fn terminal_or_candidate(record: &IrcSequencerRecord) -> Result<[u8; 32], E2eeError> {
    match record {
        IrcSequencerRecord::Candidate(value) => {
            semantic_id_of(SemanticHashDomain::CandidateId, &value.tbs)
        }
        IrcSequencerRecord::Finalization(value) => {
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
        IrcSequencerRecord::Abort(value) => {
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
        IrcSequencerRecord::ReinitActivation(value) => {
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
        IrcSequencerRecord::ReinitAbort(value) => {
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
        IrcSequencerRecord::ReinitAttempt(_) => Err(E2eeError::InvalidValue),
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
    receipt: &IrcReInitAttemptReceipt,
    bytes: &[u8],
    budget: &mut DecodeBudget,
) -> Result<[u8; 32], E2eeError> {
    let (kind, _) = IrcWireObject::peek(bytes)?;
    if kind != IrcWireObjectKind::ReinitAttempt {
        return Err(E2eeError::InvalidValue);
    }
    if ObjectId::compute(bytes).as_bytes() != &receipt.tbs.attempt_object_id {
        return Err(E2eeError::InvalidValue);
    }
    let object = IrcWireObject::decode_kind(bytes, Some(IrcWireObjectKind::ReinitAttempt), budget)?;
    let value = IrcReInitAttempt::decode_exact(object.body(), budget)?;
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
