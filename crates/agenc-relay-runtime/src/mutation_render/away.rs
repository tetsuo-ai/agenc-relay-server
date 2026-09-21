//! Private AWAY acknowledgments carried by the committed federation result.

use super::*;

pub(crate) fn away_result_replies(
    context: &StateCoreContext,
    bound: BoundSession,
    command: &CanonicalCommand,
    plan: &MutationPlan,
) -> Result<Vec<agenc_relay_federation_wire::SchemaObject>, RuntimeError> {
    let CanonicalCommandView::Presence(PresenceCommand::Away(away)) = command.view() else {
        return Ok(Vec::new());
    };
    if plan.expected_revision() != context.domain().revision() {
        return Err(RuntimeError::InvalidValue);
    }
    require_event(plan, DomainEvent::AwayChanged(bound.user_id))?;
    let session = context
        .domain()
        .session(bound.user_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let (code, text) = if away.is_some() {
        (306, "You have been marked as being away")
    } else {
        (305, "You are no longer marked as being away")
    };
    let frame = numeric(
        context.server_prefix(),
        code,
        session.nickname().presentation(),
        &[],
        Some(text),
    )?;
    Ok(vec![
        crate::federation::codec::results::reply_object(&frame)
            .map_err(|_| RuntimeError::InvalidValue)?,
    ])
}
