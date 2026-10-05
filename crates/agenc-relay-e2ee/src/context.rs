//! The required MLS context extension (companion Section 9.5) as the server
//! sees it: the committed policy, sequencer pin, binding, lifecycle, private
//! topic shape, roster heads, and pending join.
//!
//! Interpretation recorded for the completion notes: the private topic's
//! NFC requirement needs Unicode normalization tables the daemon does not
//! carry; the server enforces well-formed UTF-8, the byte ceiling, and the
//! closed control-code and bidi-formatting exclusions, and endpoints enforce
//! NFC. Endpoint-only: the wholesale extension replacement and the
//! GroupContext confirmation.

use agenc_relay_crypto::SemanticHashDomain;

use crate::error::E2eeError;
use crate::ids::{SemanticId, semantic_id_of};
use crate::limits::{MAX_ARC_MLS_CONTEXT_EXTENSION, MAX_PRIVATE_TOPIC_BYTES, PROFILE_VERSION};
use crate::objects::boolean;
use crate::objects::conversation::{
    ArcContextCoreTbs, ArcConversationKind, ArcConversationLifecycleKind, ArcMlsContext,
    ArcPendingJoin, ArcRosterHead,
};
use crate::policy::{VerifiedPolicy, verify_policy};
use crate::route::{PrincipalRosters, VerifiedBinding, verify_semantic_route};
use crate::sequencer::{VerifiedSequencerCredential, verify_sequencer_credential};
use crate::tls::{TlsEncode, ensure_canonical};

/// A verified context extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedContext {
    /// The context digest, the `EGROUP BIND` `context-digest` value.
    pub context_digest: SemanticId,
    /// Conversation identifier.
    pub conversation_id: SemanticId,
    /// Conversation kind.
    pub kind: ArcConversationKind,
    /// Concrete route binding.
    pub route_binding: SemanticId,
    /// The committed policy.
    pub policy: VerifiedPolicy,
    /// The pinned sequencer credential.
    pub sequencer: VerifiedSequencerCredential,
    /// The current binding identifier.
    pub binding_id: SemanticId,
    /// Whether the lifecycle is closing, with the close intent identifier.
    pub close_intent_id: Option<SemanticId>,
    /// The private topic bytes.
    pub private_topic: Vec<u8>,
    /// Whether a generation-zero bootstrap is in progress.
    pub bootstrap_pending: bool,
    /// Roster heads, canonical.
    pub roster_heads: Vec<ArcRosterHead>,
    /// The sole pending join, if any.
    pub pending_join: Option<ArcPendingJoin>,
}

/// Verifies a context extension. The policy and sequencer credential are
/// verified through the same chains the directory holds: `previous_policy`
/// is the policy this one replaced (none for a genesis policy) and
/// `previous_sequencer` the credential its sequencer continues.
pub fn verify_context(
    network_id: &[u8; 32],
    context: &ArcMlsContext,
    rosters: &PrincipalRosters,
    previous_policy: Option<&VerifiedPolicy>,
    previous_sequencer: Option<&VerifiedSequencerCredential>,
) -> Result<VerifiedContext, E2eeError> {
    if context.profile_version != PROFILE_VERSION || context.network_id != *network_id {
        return Err(E2eeError::ProfileMismatch);
    }
    if context.encode()?.len() > MAX_ARC_MLS_CONTEXT_EXTENSION {
        return Err(E2eeError::LimitExceeded);
    }
    let policy = verify_policy(
        network_id,
        &context.conversation_id,
        &context.policy,
        rosters,
        previous_policy,
    )?;
    let sequencer =
        verify_sequencer_credential(network_id, &context.sequencer, previous_sequencer)?;
    check_binding_agreement(network_id, context)?;
    let close_intent_id = lifecycle_close_intent(context)?;
    check_private_topic(context.kind, context.private_topic.as_slice())?;
    let bootstrap_pending = boolean(context.bootstrap_pending)?;
    ensure_canonical(context.roster_heads.as_slice(), |head| {
        (
            head.account_id_digest,
            head.root_generation,
            head.root_fingerprint,
        )
    })?;
    let pending_join = pending_join(context)?;
    if policy.kind != context.kind {
        return Err(E2eeError::InvalidValue);
    }
    Ok(VerifiedContext {
        context_digest: semantic_id_of(SemanticHashDomain::ContextHash, context)?,
        conversation_id: context.conversation_id,
        kind: context.kind,
        route_binding: context.route_binding,
        policy,
        sequencer,
        binding_id: semantic_id_of(SemanticHashDomain::BindingId, &context.current_binding.tbs)?,
        close_intent_id,
        private_topic: context.private_topic.as_slice().to_vec(),
        bootstrap_pending,
        roster_heads: context.roster_heads.as_slice().to_vec(),
        pending_join,
    })
}

/// The current binding names the context's kind, conversation, network and
/// concrete route, and its semantic route recomputes to the lock it names.
pub(crate) fn check_binding_agreement(
    network_id: &[u8; 32],
    context: &ArcMlsContext,
) -> Result<(), E2eeError> {
    let binding = &context.current_binding.tbs;
    let route = verify_semantic_route(network_id, &binding.semantic_route)?;
    let agrees = binding.kind == context.kind
        && binding.conversation_id == context.conversation_id
        && binding.route_binding == context.route_binding
        && binding.semantic_route_lock_id == route.lock_id
        && binding.network_id == *network_id;
    if agrees {
        Ok(())
    } else {
        Err(E2eeError::InvalidValue)
    }
}

fn lifecycle_close_intent(context: &ArcMlsContext) -> Result<Option<SemanticId>, E2eeError> {
    let intent = context.lifecycle.close_intent_id;
    match context.lifecycle.kind {
        ArcConversationLifecycleKind::ActiveConversation if intent == [0; 32] => Ok(None),
        ArcConversationLifecycleKind::ClosingConversation if intent != [0; 32] => Ok(Some(intent)),
        _ => Err(E2eeError::InvalidValue),
    }
}

/// Enforces the server-visible private topic rules.
pub fn check_private_topic(kind: ArcConversationKind, topic: &[u8]) -> Result<(), E2eeError> {
    if kind == ArcConversationKind::Direct && !topic.is_empty() {
        return Err(E2eeError::InvalidValue);
    }
    if topic.len() > MAX_PRIVATE_TOPIC_BYTES {
        return Err(E2eeError::LimitExceeded);
    }
    let text = std::str::from_utf8(topic).map_err(|_| E2eeError::InvalidValue)?;
    let forbidden = text.chars().any(|character| {
        character.is_control()
            || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    });
    if forbidden {
        Err(E2eeError::InvalidValue)
    } else {
        Ok(())
    }
}

fn pending_join(context: &ArcMlsContext) -> Result<Option<ArcPendingJoin>, E2eeError> {
    let joins = context.pending_joins.as_slice();
    match joins {
        [] => Ok(None),
        [only] => Ok(Some(only.clone())),
        _ => Err(E2eeError::InvalidValue),
    }
}

/// The context core identifier, recomputed by every verifier that holds
/// the required capabilities encoding.
pub fn context_core_id(core: &ArcContextCoreTbs) -> Result<SemanticId, E2eeError> {
    semantic_id_of(SemanticHashDomain::ContextCoreId, core)
}

/// Checks that a context core agrees with the verified binding it seals
/// and returns its identifier, which must equal the binding's.
pub fn verify_context_core(
    network_id: &[u8; 32],
    core: &ArcContextCoreTbs,
    binding: &VerifiedBinding,
) -> Result<SemanticId, E2eeError> {
    let group_id = crate::objects::group_id_bytes(&core.group_id)?;
    let agrees = core.profile_version == PROFILE_VERSION
        && core.network_id == *network_id
        && core.kind == binding.route.kind
        && group_id == binding.group_id
        && core.conversation_id == binding.conversation_id
        && core.semantic_route_lock_id == binding.route.lock_id
        && core.route_binding == binding.route_binding
        && core.cipher_suite == binding.cipher_suite
        && core.initial_member_plan_id == binding.initial_member_plan_id
        && core.sequencer_credential_id == binding.sequencer_credential_id
        && !core.encoded_required_capabilities.is_empty();
    if !agrees {
        return Err(E2eeError::InvalidValue);
    }
    let pending = boolean(core.initial_bootstrap_pending)?;
    if pending != (binding.generation == 0 && binding.route.incarnation == 0) {
        return Err(E2eeError::InvalidValue);
    }
    let id = context_core_id(core)?;
    if id != binding.context_core_id {
        return Err(E2eeError::InvalidValue);
    }
    Ok(id)
}

#[cfg(test)]
#[path = "tests/context.rs"]
mod tests;
