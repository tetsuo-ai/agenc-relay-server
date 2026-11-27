//! Original message failures carried in the same B.6 result as the mutation.
use super::*;
use agenc_relay_domain::TargetFailure;
use agenc_relay_federation_wire::SchemaObject;

pub(crate) fn message_failure_replies(
    context: &StateCoreContext,
    bound: BoundSession,
    kind: MessageKind,
    failures: &[TargetFailure],
) -> Result<Vec<SchemaObject>, RuntimeError> {
    let command = match kind {
        MessageKind::Notice => return Ok(Vec::new()),
        MessageKind::Privmsg => "PRIVMSG",
        MessageKind::Tagmsg => "TAGMSG",
    };
    if failures.is_empty() {
        return Ok(Vec::new());
    }
    // The domain supplies each validated target. The common client renderer needs
    // only the operation name, never the original body or tags.
    let request = agenc_relay_client_wire::FramedLine::new(command)
        .ok()
        .and_then(|line| agenc_relay_client_wire::parse_message(line).ok().flatten())
        .ok_or(RuntimeError::InvalidValue)?;
    let nickname = crate::client_render::requester_nickname(context, bound.user_id);
    failures
        .iter()
        .map(|failure| {
            let frame = crate::client_render::failure_frame(
                &CapabilityState::default(),
                context.server_prefix(),
                &nickname,
                &request,
                failure.error(),
                Some(failure.target()),
            )?;
            crate::federation::codec::results::reply_object(&frame)
                .map_err(|_| RuntimeError::InvalidValue)
        })
        .collect()
}
