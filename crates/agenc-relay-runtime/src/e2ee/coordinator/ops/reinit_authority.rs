//! The sequencer's ReInit attempt checks (companion 13.8), in the order the
//! companion fixes: the old conversation's accepted state must be the
//! finalization of a ReInit Commit, then the attempt and the target it
//! carries must be the ones that finalization authorized, and its
//! authorization must satisfy the current old policy, all before any
//! sequencer signature.
#![forbid(unsafe_code)]
use super::super::ConversationState;
use super::{Exec, Fail};
use crate::budget::MemoryPermit;
use agenc_relay_domain::e2ee::sequencer_log::{Phase, SequencerLog};
use agenc_relay_e2ee::limits::{MAX_BINDING_PRINCIPALS, MAX_REINIT_OBJECT, MAX_ROSTER_OBJECT};
use agenc_relay_e2ee::objects::reinit::ArcReInitAttempt;
use agenc_relay_e2ee::reinit_authorization::verify_reinit_attempt_authorization;
use agenc_relay_e2ee::reinit_target::{AuthorizedReinit, CarriedTarget};
use agenc_relay_e2ee::tls::DecodeBudget;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

/// The work one binding principal may hold while an attempt is checked or
/// activated: its cloned verified current roster and the transient work of
/// verifying under it.
const PRINCIPAL_WORK_BYTES: usize = MAX_ROSTER_OBJECT * 4;

/// The finalized ReInit Commit an attempt on `conversation` follows: the
/// old group must be in its ReInit phase, and the authorized target recorded
/// when the finalization entered it (`AuthorizedReinit::from_proof`, or its
/// restored record) must be the one of the finalization that is the accepted
/// state. Any other accepted state is `E2EE_FINALITY_REQUIRED`, retaining
/// nothing; it is refused before every attempt check (companion 13.8;
/// decision D-11a).
pub(super) fn authorized(
    conversation: &[u8; 32],
    log: &SequencerLog,
    state: &ConversationState,
) -> Result<AuthorizedReinit, Fail> {
    let finality = || Fail::with(E2eeReplyCode::FinalityRequired, conversation);
    if !matches!(log.phase(), Phase::Reinit { .. }) {
        return Err(finality());
    }
    state
        .reinit
        .filter(|authorized| authorized.finalization_id() == log.accepted_state_id())
        .ok_or_else(finality)
}

/// The sequencer's checks of an attempt against the finalized ReInit
/// Commit (companion 13.8), each refused with `E2EE_BINDING_AUTH_INVALID`,
/// retaining nothing: the attempt names that finalization, the target it
/// carries hashes to its `target_context_digest`, which is the authorized
/// digest, the attempt's group, version, suite, successor conversation,
/// binding and plan are the carried target's, its KeyPackage plan forms the
/// target's semantic plan, and the carried target's extension list describes
/// the successor of the old conversation's current binding and yields the
/// target's derived IDs (`AuthorizedReinit::check_attempt_from`), checked
/// against the facts of the old conversation's current binding that the
/// coordinator retained when it verified that binding
/// ([`ConversationState::reinit_facts`]); no binding object or roster
/// snapshot is read. Returns the checked carried target. The caller holds
/// the work memory [`reserve_work`] reserved.
pub(super) fn check_attempt(
    authorized: &AuthorizedReinit,
    attempt: &ArcReInitAttempt,
    state: &ConversationState,
) -> Result<CarriedTarget, Fail> {
    let invalid = || {
        Fail::with(
            E2eeReplyCode::BindingAuthInvalid,
            &attempt.tbs.old_conversation_id,
        )
    };
    let facts = state.reinit_facts.as_ref().ok_or_else(invalid)?;
    let mut budget = DecodeBudget::new(MAX_REINIT_OBJECT, 1 << 18);
    authorized
        .check_attempt_from(attempt, facts, &mut budget)
        .map_err(|_| invalid())
}

/// The attempt authorization's approvals satisfy the old conversation's
/// current policy under its principals' rosters. The caller holds the work
/// memory [`reserve_work`] reserved.
pub(super) fn verify(exec: &Exec<'_>, attempt: &ArcReInitAttempt) -> Result<(), Fail> {
    let conversation = &attempt.tbs.old_conversation_id;
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation);
    let state = exec
        .coordinator
        .state
        .conversations
        .get(conversation)
        .ok_or_else(invalid)?;
    let policy = &state
        .policies
        .get(&state.current_policy_id)
        .ok_or_else(invalid)?
        .policy;
    let rosters = super::route::rosters_of(exec, &state.principal_accounts)?;
    verify_reinit_attempt_authorization(attempt, policy, &rosters).map_err(|_| invalid())
}

/// Reserves the bounded work memory of the attempt checks and the old-policy
/// authorization, which the caller holds until both are done: more
/// principals than a binding admits are `E2EE_BINDING_AUTH_INVALID` before
/// any work, and an exhausted backing budget is `E2EE_RATE_LIMITED`.
pub(super) fn reserve_work(
    exec: &Exec<'_>,
    conversation: &[u8; 32],
    state: &ConversationState,
) -> Result<MemoryPermit, Fail> {
    let capacity = work_capacity(state.principal_accounts.len())
        .ok_or_else(|| Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation))?;
    exec.backing
        .reserve(capacity)
        .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))
}

fn work_capacity(principals: usize) -> Option<usize> {
    if principals > MAX_BINDING_PRINCIPALS {
        return None;
    }
    // Covers cloned verified current rosters, bounded plan, target and TBS
    // encodings, and controller sets.
    principals
        .checked_mul(PRINCIPAL_WORK_BYTES)?
        .checked_add(MAX_REINIT_OBJECT.checked_mul(2)?)?
        .checked_add(16_384)
}
