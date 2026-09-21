//! Public proof bindings checked before council votes can change server state.
//! MLS leaf signatures and controller authority remain endpoint checks.

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::ids::{proof_set_digest, semantic_id_of};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::reinit::{
    ArcReInitActivationRequest, ArcReInitAttempt, ArcReInitAttemptReceipt,
};
use agenc_relay_e2ee::objects::sequencing::{ArcFinalizationProof, ArcSequencerRecord};
use agenc_relay_e2ee::tls::TlsEncode;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::{Exec, Fail};

/// Requires the exact receipt this coordinator durably sequenced.
pub(super) fn receipt(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    sequence: u64,
    record: &ArcSequencerRecord,
) -> Result<(), Fail> {
    let bytes = super::sequence::record_bytes(record)?;
    let object_id = agenc_relay_e2ee::ObjectId::compute(&bytes);
    let retained = exec
        .coordinator
        .state
        .conversations
        .get(conversation)
        .and_then(|state| state.records.get(&sequence));
    if retained != Some(object_id.as_bytes()) {
        return Err(Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation));
    }
    Ok(())
}

/// Checks the public hash links. This does not assert MLS ACK coverage.
pub(super) fn finalization(proof: &ArcFinalizationProof) -> Result<(), Fail> {
    let core = &proof.core;
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, &core.conversation_id);
    let authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &proof.authorization.tbs,
    )
    .map_err(|_| invalid())?;
    let acks = proof.acknowledgements.as_slice();
    if acks.windows(2).any(
        |pair| matches!(pair, [left, right] if left.tbs.old_leaf_index >= right.tbs.old_leaf_index),
    ) {
        return Err(Fail::with(
            E2eeReplyCode::InvalidFragment,
            &core.conversation_id,
        ));
    }
    let tbs: Vec<_> = acks.iter().map(|ack| ack.tbs.clone()).collect();
    let acknowledgement_digest =
        proof_set_digest(SemanticHashDomain::AcknowledgementSet, &tbs).map_err(|_| invalid())?;
    if authorization_id != core.commit_authorization_id
        || acknowledgement_digest != core.acknowledgement_set_digest
        || acks
            .iter()
            .any(|ack| !super::ack_context::commit_finalization(&ack.tbs, core))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Binds a terminal request to the exact retained attempt and receipt.
pub(super) fn reinit_attempt(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    attempt_receipt: &ArcReInitAttemptReceipt,
    attempt: &ArcReInitAttempt,
) -> Result<(), Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation);
    let slot = exec
        .coordinator
        .state
        .logs
        .get(conversation)
        .and_then(|log| log.reinit_attempt())
        .ok_or_else(invalid)?;
    receipt(
        exec,
        conversation,
        slot.route_sequence,
        &ArcSequencerRecord::ReinitAttempt(attempt_receipt.clone()),
    )?;
    let bytes = attempt
        .encode()
        .and_then(|body| ArcWireObject::new(ArcWireObjectKind::ReinitAttempt, body))
        .and_then(|object| object.encode())
        .map_err(|_| invalid())?;
    let object_id = agenc_relay_e2ee::ObjectId::compute(&bytes);
    if object_id.as_bytes() != &attempt_receipt.tbs.attempt_object_id {
        return Err(invalid());
    }
    Ok(())
}

/// Checks the ACK digest and the public result repeated by the attempt.
pub(super) fn reinit_activation(request: &ArcReInitActivationRequest) -> Result<(), Fail> {
    let core = &request.core;
    let attempt = &request.attempt.tbs;
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, &core.old_conversation_id);
    let acks = request.acknowledgements.as_slice();
    if acks.windows(2).any(
        |pair| matches!(pair, [left, right] if left.tbs.old_leaf_index >= right.tbs.old_leaf_index),
    ) {
        return Err(Fail::with(
            E2eeReplyCode::InvalidFragment,
            &core.old_conversation_id,
        ));
    }
    let tbs: Vec<_> = acks.iter().map(|ack| ack.tbs.clone()).collect();
    let digest = proof_set_digest(SemanticHashDomain::ReinitAcknowledgementSet, &tbs)
        .map_err(|_| invalid())?;
    let named_attempt = (
        core.network_id,
        core.old_conversation_id,
        core.new_conversation_id,
        core.old_reinit_state_id,
        core.attempt_sequence,
    );
    let retained_attempt = (
        attempt.network_id,
        attempt.old_conversation_id,
        attempt.new_conversation_id,
        attempt.old_reinit_state_id,
        attempt.attempt_sequence,
    );
    let named_result = (
        core.new_group_info_digest,
        core.new_group_context_digest,
        core.new_ratchet_tree_digest,
        core.new_exporter_authenticator,
    );
    let retained_result = (
        attempt.new_group_info_digest,
        attempt.new_group_context_digest,
        attempt.new_ratchet_tree_digest,
        attempt.new_exporter_authenticator,
    );
    if core.profile_version != 1
        || named_attempt != retained_attempt
        || named_result != retained_result
        || core.reinit_attempt_id != request.receipt.tbs.reinit_attempt_id
        || core.acknowledgement_set_digest != digest
        || acks.iter().any(|ack| {
            !super::ack_context::reinit_attempt(
                &ack.tbs,
                &request.attempt,
                &request.receipt.tbs.reinit_attempt_id,
            )
        })
    {
        return Err(invalid());
    }
    Ok(())
}
