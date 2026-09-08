//! Close admission binds public controller approval to the currently accepted closing transition.
#![forbid(unsafe_code)]
use super::{Exec, Fail};
use agenc_ircd_crypto::SemanticHashDomain;
use agenc_ircd_e2ee::close::verify_close_approvals;
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::limits::{
    MAX_BINDING_PRINCIPALS, MAX_CLOSE_OBJECT, MAX_FINALIZATION_OBJECT, MAX_ROSTER_OBJECT,
};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::{
    IrcCloseAuthorization, IrcCommitAuthorizationRule, action_bits,
};
use agenc_ircd_e2ee::objects::sequencing::IrcFinalizationRequest;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

pub(super) fn verify(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    reason: u16,
    close: &IrcCloseAuthorization,
) -> Result<[u8; 32], Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation);
    let state = exec
        .coordinator
        .state
        .conversations
        .get(conversation)
        .ok_or_else(invalid)?;
    let log = exec
        .coordinator
        .state
        .logs
        .get(conversation)
        .ok_or_else(invalid)?;
    if close.tbs.network_id != exec.coordinator.network_id
        || close.tbs.conversation_id != *conversation
        || close.tbs.binding_id != state.binding
        || reason != close.tbs.close_intent.reason_code
        || close.tbs.authorizing_terminal_id != *log.accepted_state_id()
    {
        return Err(invalid());
    }
    let policy = &state
        .policies
        .get(&state.current_policy_id)
        .ok_or_else(invalid)?
        .policy;
    let proof_id = state
        .proofs
        .get(&close.tbs.authorizing_terminal_id)
        .ok_or_else(invalid)?;
    let bytes = exec
        .coordinator
        .state
        .objects
        .get(proof_id)
        .ok_or_else(invalid)?;
    let capacity =
        work_capacity(bytes.len(), state.principal_accounts.len()).ok_or_else(invalid)?;
    let _backing = exec
        .backing
        .reserve(capacity)
        .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?;
    if agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes() != proof_id {
        return Err(invalid());
    }
    let request = decode_terminal(bytes).map_err(|_| invalid())?;
    verify_terminal(
        &request,
        close,
        state.current_policy_id,
        log.accepted_epoch(),
    )
    .map_err(|_| invalid())?;
    let rosters = super::route::rosters_of(exec, &state.principal_accounts)?;
    verify_close_approvals(close, policy, &rosters).map_err(|_| invalid())
}

fn work_capacity(body_bytes: usize, principals: usize) -> Option<usize> {
    if body_bytes > MAX_FINALIZATION_OBJECT || principals > MAX_BINDING_PRINCIPALS {
        return None;
    }
    // Covers the decoded object/request, TBS encodings, controller sets and
    // cloned verified rosters until public validation has returned.
    body_bytes
        .checked_mul(4)?
        .checked_add(principals.checked_mul(MAX_ROSTER_OBJECT.checked_mul(4)?)?)?
        .checked_add(MAX_CLOSE_OBJECT.checked_mul(4)?)?
        .checked_add(16_384)
}

fn decode_terminal(bytes: &[u8]) -> Result<IrcFinalizationRequest, agenc_ircd_e2ee::E2eeError> {
    let mut budget = DecodeBudget::new(MAX_FINALIZATION_OBJECT, 1 << 16);
    let object = IrcWireObject::decode_kind(
        bytes,
        Some(IrcWireObjectKind::FinalizationRequest),
        &mut budget,
    )?;
    IrcFinalizationRequest::decode_exact(object.body(), &mut budget)
}

fn verify_terminal(
    request: &IrcFinalizationRequest,
    close: &IrcCloseAuthorization,
    policy: [u8; 32],
    epoch: u64,
) -> Result<(), agenc_ircd_e2ee::E2eeError> {
    let core = &request.proof.core;
    let authorization = &request.proof.authorization.tbs;
    let consistent = core.profile_version == 1
        && core.network_id == close.tbs.network_id
        && core.conversation_id == close.tbs.conversation_id
        && core.resulting_epoch == epoch
        && core.old_policy_id == policy
        && authorization.resulting_policy_id == policy
        && authorization.authorization_rule == IrcCommitAuthorizationRule::ControlledTransition
        && authorization.action_bits == action_bits::CLOSE_INTENT
        && authorization.transition_target_digest == close.tbs.close_intent_id;
    if !consistent
        || !authorization_matches_core(request)
        || semantic_id_of(SemanticHashDomain::FinalizationId, core)?
            != close.tbs.authorizing_terminal_id
        || semantic_id_of(SemanticHashDomain::CommitAuthorizationId, authorization)?
            != core.commit_authorization_id
    {
        return Err(agenc_ircd_e2ee::E2eeError::InvalidValue);
    }
    Ok(())
}

fn authorization_matches_core(request: &IrcFinalizationRequest) -> bool {
    let core = &request.proof.core;
    let authorization = &request.proof.authorization.tbs;
    authorization.profile_version == core.profile_version
        && authorization.network_id == core.network_id
        && authorization.conversation_id == core.conversation_id
        && authorization.prior_epoch == core.prior_epoch
        && authorization.prior_state_id == core.prior_state_id
        && authorization.candidate_id == core.candidate_id
        && authorization.commit_object_id == core.commit_object_id
        && authorization.old_policy_id == core.old_policy_id
        && authorization.resulting_group_context_digest == core.resulting_group_context_digest
        && authorization.resulting_ratchet_tree_digest == core.resulting_ratchet_tree_digest
}
