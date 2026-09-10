//! Bounded JOIN replies carried by the membership's committed result.

use super::*;

pub(crate) fn join_result_replies(
    context: &StateCoreContext,
    bound: BoundSession,
    command: &CanonicalCommand,
    plan: &MutationPlan,
) -> Result<Vec<agenc_ircd_federation_wire::SchemaObject>, RuntimeError> {
    super::join_result_frames(context, bound, command, plan)?
        .iter()
        .map(crate::federation::codec::results::reply_object)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RuntimeError::InvalidValue)
}

pub(crate) fn join_result_frames(
    context: &StateCoreContext,
    bound: BoundSession,
    command: &CanonicalCommand,
    plan: &MutationPlan,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let CanonicalCommandView::Join(targets) = command.view() else {
        return Ok(Vec::new());
    };
    if plan.expected_revision() != context.domain().revision() {
        return Err(RuntimeError::InvalidValue);
    }
    let nickname = crate::client_render::requester_nickname(context, bound.user_id);
    let mut joined = plan.events().iter().filter_map(|event| match event {
        DomainEvent::Joined(channel, user) if *user == bound.user_id => Some(*channel),
        _ => None,
    });
    let mut frames = Vec::new();
    let frame_limit = targets.len().checked_mul(2).ok_or(RuntimeError::Overflow)?;
    frames
        .try_reserve_exact(frame_limit)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for (index, target) in targets.iter().enumerate() {
        if plan
            .failures()
            .iter()
            .any(|failure| usize::from(failure.target_index()) == index)
        {
            continue;
        }
        let channel_id = joined.next().ok_or(RuntimeError::InvalidValue)?;
        let channel = context.domain().channel(channel_id);
        if channel.is_some_and(|channel| channel.name() != target.name()) {
            return Err(RuntimeError::InvalidValue);
        }
        frames.extend(topic_frames(
            context,
            &nickname,
            target.name(),
            bound.user_id,
            channel,
        )?);
    }
    if joined.next().is_some() {
        return Err(RuntimeError::InvalidValue);
    }
    append_failures(context, &nickname, plan, &mut frames)?;
    Ok(frames)
}

fn append_failures(
    context: &StateCoreContext,
    nickname: &str,
    plan: &MutationPlan,
    frames: &mut Vec<WireMessage>,
) -> Result<(), RuntimeError> {
    let capabilities = CapabilityState::default();
    for failure in plan.failures() {
        let name = failure
            .target()
            .channel()
            .ok_or(RuntimeError::InvalidValue)?;
        let line = format!("JOIN {}", name.presentation());
        let framed = agenc_ircd_client_wire::FramedLine::new(&line)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let request = agenc_ircd_client_wire::parse_message(framed)
            .map_err(|_| RuntimeError::InvalidValue)?
            .ok_or(RuntimeError::InvalidValue)?;
        frames.push(crate::client_render::failure_frame(
            &capabilities,
            context.server_prefix(),
            nickname,
            &request,
            failure.error(),
            Some(failure.target()),
        )?);
    }
    Ok(())
}

pub(super) fn topic_frames(
    context: &StateCoreContext,
    nickname: &str,
    name: &ChannelNameValue,
    _user_id: UserId,
    channel: Option<&agenc_ircd_domain::ChannelState>,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let prefix = context.server_prefix();
    if channel.is_some_and(|channel| {
        channel.content_policy() == agenc_ircd_domain::ContentPolicy::E2eeBound
    }) {
        return Ok(vec![numeric(
            prefix,
            332,
            nickname,
            &[name.presentation()],
            Some("Encrypted channel topic"),
        )?]);
    }
    let Some(topic) = channel.and_then(|channel| channel.topic()) else {
        return Ok(vec![numeric(
            prefix,
            331,
            nickname,
            &[name.presentation()],
            Some("No topic is set"),
        )?]);
    };
    let setter = context
        .domain()
        .session(topic.setter())
        .map(|session| session.nickname().presentation())
        .unwrap_or(prefix);
    Ok(vec![
        numeric(
            prefix,
            332,
            nickname,
            &[name.presentation()],
            Some(topic.text()),
        )?,
        numeric(
            prefix,
            333,
            nickname,
            &[
                name.presentation(),
                setter,
                &topic.set_at().get().to_string(),
            ],
            None,
        )?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        StateCoreFixture, apply_live_plan, plan_live, seed_account, seed_session,
    };
    use agenc_ircd_domain::{ChannelTarget, E2eeBindingProof, PlanDecision};

    #[test]
    fn encrypted_join_topic_is_a_placeholder_even_without_plaintext_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let context = fixture.context_mut()?;
        let account = seed_account(context, 11, 1)?;
        let owner = seed_session(context, 11, "owner", Some(account))?;
        let name = ChannelNameValue::parse("#encrypted")?;
        let PlanDecision::Mutation(join) = plan_live(context, owner, &|| {
            CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])
        })?
        else {
            return Err("join refused".into());
        };
        apply_live_plan(context, join)?;
        let channel_id = context
            .domain()
            .resolve_channel(&name)
            .ok_or("no channel")?;
        let PlanDecision::Mutation(register) = plan_live(context, owner, &|| {
            Ok(CanonicalCommand::channel(ChannelCommand::Register(
                channel_id,
            )))
        })?
        else {
            return Err("registration refused".into());
        };
        apply_live_plan(context, register)?;
        let channel = context.domain().channel(channel_id).ok_or("no channel")?;
        let proof = E2eeBindingProof::new(
            channel_id,
            channel.revision(),
            vec![(owner.user_id, account.0)],
        )?;
        let binding = context.domain().plan_e2ee_binding(owner.user_id, proof)?;
        apply_live_plan(context, binding)?;
        let channel = context
            .domain()
            .channel(channel_id)
            .ok_or("no bound channel")?;
        assert!(channel.topic().is_none());
        let frames = topic_frames(context, "owner", &name, owner.user_id, Some(channel))?;
        let replies = frames
            .iter()
            .map(crate::federation::codec::results::reply_object)
            .collect::<Result<Vec<_>, _>>()?;
        let parts = replies
            .iter()
            .map(crate::federation::codec::results::reply_parts_of)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(parts.len(), 1);
        let reply = parts.first().ok_or("missing encrypted topic reply")?;
        assert_eq!(reply.command, "332");
        assert_eq!(reply.trailing.as_deref(), Some("Encrypted channel topic"));
        Ok(())
    }
}
