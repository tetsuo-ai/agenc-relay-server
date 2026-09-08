//! ReInit controller checks use the current old policy before any sequencer signature.
#![forbid(unsafe_code)]
use super::{Exec, Fail};
use agenc_ircd_e2ee::limits::{MAX_BINDING_PRINCIPALS, MAX_REINIT_OBJECT, MAX_ROSTER_OBJECT};
use agenc_ircd_e2ee::objects::reinit::IrcReInitAttempt;
use agenc_ircd_e2ee::reinit_authorization::verify_reinit_attempt_authorization;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

pub(super) fn verify(exec: &Exec<'_>, attempt: &IrcReInitAttempt) -> Result<(), Fail> {
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
    let log = exec
        .coordinator
        .state
        .logs
        .get(conversation)
        .ok_or_else(invalid)?;
    if attempt.tbs.old_reinit_state_id != *log.accepted_state_id() {
        return Err(invalid());
    }
    let capacity = work_capacity(state.principal_accounts.len()).ok_or_else(invalid)?;
    let _memory = exec
        .backing
        .reserve(capacity)
        .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?;
    let rosters = super::route::rosters_of(exec, &state.principal_accounts)?;
    verify_reinit_attempt_authorization(attempt, policy, &rosters).map_err(|_| invalid())
}

fn work_capacity(principals: usize) -> Option<usize> {
    if principals > MAX_BINDING_PRINCIPALS {
        return None;
    }
    // Covers cloned verified rosters, bounded plan/TBS encodings and controller sets.
    principals
        .checked_mul(MAX_ROSTER_OBJECT.checked_mul(4)?)?
        .checked_add(MAX_REINIT_OBJECT.checked_mul(2)?)?
        .checked_add(16_384)
}
