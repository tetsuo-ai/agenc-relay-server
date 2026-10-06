//! The requester's principal authority over a conversation, the retained
//! activation of a migrated predecessor, and, for tests, a conversation's
//! retained binding package.

#![forbid(unsafe_code)]

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_domain::e2ee::sequencer_log::Phase;
use agenc_relay_e2ee::E2eeError;
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::limits::MAX_SEQUENCER_RECORD_OBJECT;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::reinit::ArcReInitActivationCertificate;
use agenc_relay_e2ee::objects::sequencing::ArcSequencerRecord;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::super::CompanionState;
use super::{Exec, Fail};

/// The retained binding package object `id`, decoded, for the tests that
/// build bindings from it; no coordinator check reads a binding object.
#[cfg(test)]
pub(in crate::e2ee::coordinator) fn binding_object(
    state: &CompanionState,
    id: &[u8; 32],
) -> Option<agenc_relay_e2ee::objects::conversation::ArcConversationBindingPackage> {
    let bytes = state.objects.get(id)?;
    decode(
        bytes,
        ArcWireObjectKind::ConversationBinding,
        agenc_relay_e2ee::limits::MAX_BINDING_OBJECT,
    )
    .ok()
}

fn decode<T: TlsDecode>(
    bytes: &[u8],
    kind: ArcWireObjectKind,
    limit: usize,
) -> Result<T, E2eeError> {
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    let object = ArcWireObject::decode_kind(bytes, Some(kind), &mut budget)?;
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    T::decode_exact(object.body(), &mut budget)
}

pub(super) fn owner(exec: &Exec<'_>, conversation: &[u8; 32]) -> Result<(), Fail> {
    let account = exec.account_id()?;
    if !exec
        .coordinator
        .state
        .conversations
        .get(conversation)
        .is_some_and(|state| state.principal_accounts.contains(&account))
    {
        return Err(Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation));
    }
    Ok(())
}

/// Loads the exact terminal record referenced by the predecessor's migrated log.
pub(in crate::e2ee::coordinator) fn activation(
    state: &CompanionState,
    old: &[u8; 32],
) -> Result<ArcReInitActivationCertificate, E2eeError> {
    let log = state.logs.get(old).ok_or(E2eeError::InvalidValue)?;
    let Phase::Migrated {
        activation_id,
        new_conversation_id,
    } = log.phase()
    else {
        return Err(E2eeError::InvalidValue);
    };
    let id = state
        .conversations
        .get(old)
        .and_then(|value| value.records.get(&log.head().sequence))
        .ok_or(E2eeError::InvalidValue)?;
    let bytes = state.objects.get(id).ok_or(E2eeError::InvalidValue)?;
    let record: ArcSequencerRecord = decode(
        bytes,
        ArcWireObjectKind::SequencerRecord,
        MAX_SEQUENCER_RECORD_OBJECT,
    )?;
    let ArcSequencerRecord::ReinitActivation(certificate) = record else {
        return Err(E2eeError::InvalidValue);
    };
    let tbs = &certificate.tbs;
    let core = &tbs.request.core;
    if tbs.old_conversation_id != *old
        || tbs.route_sequence != log.head().sequence
        || tbs.reinit_activation_id != activation_id
        || core.old_conversation_id != *old
        || core.new_conversation_id != new_conversation_id
        || semantic_id_of(SemanticHashDomain::ReinitActivationId, core)? != activation_id
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(certificate)
}
