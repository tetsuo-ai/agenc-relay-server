//! Separates the requester's one JOIN response from the ordinary event fanout.

use super::*;

pub(crate) fn render_local_join_start(
    context: &StateCoreContext,
    bound: BoundSession,
    reply: ReplyInput<'_>,
    command: &CanonicalCommand,
    plan: &MutationPlan,
) -> Result<(FanoutRequest, Vec<WireMessage>), RuntimeError> {
    if plan.expected_revision() != context.domain().revision()
        || !matches!(command.view(), CanonicalCommandView::Join(_))
    {
        return Err(RuntimeError::InvalidValue);
    }
    let mut builder = FanoutBuilder::new(context, plan, Some(reply))?;
    builder.deferred_join_names = true;
    let session = context
        .domain()
        .session(bound.user_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let source = session_prefix(session)?;
    render_command(&mut builder, plan, bound.user_id, &source, command.view())?;
    builder.append_failures(plan)?;
    let fanout = FanoutRequest::new(builder.targets, builder.frames)?;
    Ok((fanout, builder.origin_semantic))
}
