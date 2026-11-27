//! The KICK wire operation names sorted physical users. Keep their original nickname
//! positions until the authenticated coordinator result and its projected removals agree.
use super::*;
use agenc_relay_client_wire::{MAX_KICK_TARGETS, WireMessage, numeric_reply};
use agenc_relay_domain::{NicknameValue, federation::SourceView};
use agenc_relay_types::ChannelInstanceId;

#[cfg(test)]
#[path = "tests/kick.rs"]
mod tests;

pub(crate) struct KickRequester {
    channel: ChannelInstanceId,
    revision: u64,
    origin: ReplyRequester,
    targets: [Option<UserId>; MAX_KICK_TARGETS],
}

pub(super) fn route(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    identity: (SessionId, UserId),
    command: &CanonicalCommand,
    message: Box<ParsedMessage>,
) -> Result<Routed, (Box<ParsedMessage>, DomainError)> {
    let (requester, operation) = match admit(edge, context, identity, command, &message) {
        Ok(admission) => admission,
        Err(error) => return Err((message, error)),
    };
    let Some(operation) = operation else {
        let frames = requester.local_refusals(context, identity.1, &message);
        return Routed::local(frames, message);
    };
    let Ok(prepared) = prepare_request(edge, context, generation, &operation) else {
        return Err((message, DomainError::ServerBusy));
    };
    register_request(
        edge,
        context,
        generation,
        prepared,
        PendingKind::Command {
            message,
            echo_channels: Some(EchoChannels::Kick(requester)),
        },
    );
    Ok(Routed::Forwarded)
}

fn admit(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    (session, actor): (SessionId, UserId),
    command: &CanonicalCommand,
    message: &ParsedMessage,
) -> Result<(KickRequester, Option<FederatedOperation>), DomainError> {
    let CanonicalCommandView::Kick(channel, targets, reason) = command.view() else {
        return Err(DomainError::InvariantViolation);
    };
    let detail = edge
        .replica
        .channel_by_name(channel)
        .ok_or(DomainError::SecretUnavailable)?;
    let (source, caps) = edge
        .replica
        .session(actor)
        .zip(context.sessions().capabilities_for_user(actor))
        .ok_or(DomainError::RegistrationRequired)?;
    let names = message
        .middle()
        .get(1)
        .ok_or(DomainError::InvariantViolation)?;
    let (positions, ids) = physical_targets(names, targets, |name| user_by_nickname(edge, name))?;
    let requester = KickRequester {
        channel: detail.channel_id,
        revision: detail.channel_revision.get(),
        origin: ReplyRequester::new(source.nickname.presentation(), caps)?,
        targets: positions,
    };
    if ids.is_empty() {
        // No physical ID exists to forward. Reflect target absence only to a current
        // channel moderator, under the same visibility and role floors as the domain.
        detail.visibility.authorize_kick_targets(
            edge.replica
                .membership(detail.channel_id, actor)
                .map(|record| record.role),
        )?;
        return Ok((requester, None));
    }
    let operation = FederatedOperation::Kick {
        session_id: session,
        channel_id: detail.channel_id,
        targets: ids,
        expected_channel_revision: detail.channel_revision.get(),
        reason: reason.map_or_else(String::new, |text| text.as_str().to_owned()),
    };
    Ok((requester, Some(operation)))
}

/// The B.6 failure code and first numeric must describe the same public outcome.
fn first_failure(code: &str, context: &str, frame: &WireMessage) -> bool {
    match frame.command() {
        "401" => {
            code == "STALE_STATE"
                && (context.is_empty()
                    || frame
                        .middle()
                        .last()
                        .is_some_and(|name| name.eq_ignore_ascii_case(context)))
        }
        "481" => matches!(code, "NOT_ALLOWED" | "BAD_STATE") && context.is_empty(),
        _ => false,
    }
}

fn covered_result(
    known: usize,
    arm: &ResultArm,
    replies: &[WireMessage],
) -> Result<bool, Violation> {
    match arm {
        // An old result or command-wide error has no authoritative target dispositions.
        ResultArm::Failed { .. } if replies.is_empty() => Ok(false),
        ResultArm::Failed { code, context }
            if replies.len() == known
                && replies
                    .first()
                    .is_some_and(|first| first_failure(code, context, first)) =>
        {
            Ok(true)
        }
        ResultArm::Committed { .. } if replies.len() < known => Ok(true),
        _ => Err(Violation::Consistency),
    }
}

fn confirmed_target<'a>(
    original: &str,
    reason: Option<&str>,
    frame: &'a WireMessage,
) -> Result<&'a str, Violation> {
    let [channel, name] = frame.middle() else {
        return Err(Violation::Consistency);
    };
    if frame.command() != "KICK"
        || !channel.eq_ignore_ascii_case(original)
        || frame.trailing().unwrap_or("") != reason.unwrap_or("")
    {
        return Err(Violation::Consistency);
    }
    Ok(name)
}

/// The B.5 body sorts by UserId, while a client attributes outcomes by original nickname.
fn physical_targets(
    names: &str,
    validated: &[NicknameValue],
    resolve: impl Fn(&NicknameValue) -> Option<UserId>,
) -> Result<([Option<UserId>; MAX_KICK_TARGETS], Vec<UserId>), DomainError> {
    let mut ids = Vec::new();
    ids.try_reserve_exact(validated.len())
        .map_err(|_| DomainError::ServerBusy)?;
    let mut positions = [None; MAX_KICK_TARGETS];
    for target in validated {
        if let Some(user) = resolve(target) {
            let index = names
                .split(',')
                .position(|name| name.eq_ignore_ascii_case(target.presentation()))
                .ok_or(DomainError::InvariantViolation)?;
            *positions
                .get_mut(index)
                .ok_or(DomainError::InvariantViolation)? = Some(user);
            ids.push(user);
        }
    }
    ids.sort_unstable();
    if ids
        .windows(2)
        .any(|pair| matches!(pair, [first, second] if first == second))
    {
        return Err(DomainError::StaleRevision);
    }
    Ok((positions, ids))
}

impl KickRequester {
    pub(in crate::federation::edge) fn echo_targets(
        &self,
        message: &ParsedMessage,
        channel: ChannelInstanceId,
        revision: u64,
        target: &SourceView,
        reason: &str,
    ) -> Option<usize> {
        if self.channel != channel
            || revision <= self.revision
            || message.trailing().unwrap_or("") != reason
        {
            return None;
        }
        let names = message.middle().get(1)?;
        let original = names
            .split(',')
            .position(|name| name.eq_ignore_ascii_case(target.nickname.presentation()))?;
        (self.targets.get(original) == Some(&Some(target.user_id)))
            .then(|| self.targets.iter().flatten().count())
    }

    fn local_refusals(
        &self,
        context: &StateCoreContext,
        user: UserId,
        message: &ParsedMessage,
    ) -> Result<Vec<WireMessage>, DomainError> {
        let caps = context
            .sessions()
            .capabilities_for_user(user)
            .ok_or(DomainError::RegistrationRequired)?;
        let mut frames = Vec::new();
        self.add_missing(context.server_prefix(), message, &mut frames)
            .map_err(|_| DomainError::ServerBusy)?;
        crate::client_render::logical_frames(context.server_prefix(), caps, message, frames)
            .map_err(|_| DomainError::ServerBusy)
    }

    fn add_missing(
        &self,
        prefix: &str,
        message: &ParsedMessage,
        replies: &mut Vec<WireMessage>,
    ) -> Result<(), Violation> {
        let names = message.middle().get(1).ok_or(Violation::Consistency)?;
        let nick = self.origin.nickname()?;
        let missing = names
            .split(',')
            .count()
            .checked_sub(self.targets.iter().flatten().count())
            .ok_or(Violation::Consistency)?;
        replies
            .try_reserve_exact(missing)
            .map_err(|_| Violation::Ceiling)?;
        for (name, id) in names.split(',').zip(self.targets) {
            if id.is_none() {
                replies.push(
                    numeric_reply(prefix, 401, nick, &[name], Some("No such nick"))
                        .map_err(|_| Violation::Codec)?,
                );
            }
        }
        if missing != 0 && replies.iter().all(|frame| frame.command() == "401") {
            // All refusals identify a nickname. Merge missing IDs with the original numeric
            // results in canonical name order. An unscoped policy refusal keeps its position.
            replies.sort_unstable_by(|left, right| {
                let canonical = |byte: u8| byte.to_ascii_lowercase();
                let ([_, first], [_, second]) = (left.middle(), right.middle()) else {
                    return std::cmp::Ordering::Equal;
                };
                first
                    .bytes()
                    .map(canonical)
                    .cmp(second.bytes().map(canonical))
            });
        }
        Ok(())
    }

    pub(super) fn project(
        &self,
        prefix: &str,
        message: &ParsedMessage,
        arm: &ResultArm,
        replies: &mut Vec<WireMessage>,
    ) -> Result<(), Violation> {
        let known = self.targets.iter().flatten().count();
        if !covered_result(known, arm, replies)? {
            return Ok(());
        }
        let names = message.middle().get(1).ok_or(Violation::Consistency)?;
        let recipient = self.origin.nickname()?;
        if !replies
            .iter()
            .all(|frame| self.original_refusal(names, recipient, frame))
        {
            return Err(Violation::Consistency);
        }
        self.add_missing(prefix, message, replies)
    }

    fn original_refusal(&self, names: &str, recipient: &str, frame: &WireMessage) -> bool {
        match (frame.command(), frame.middle(), frame.trailing()) {
            ("401", [nick, target], Some("No such nick")) => {
                recipient.eq_ignore_ascii_case(nick)
                    && names
                        .split(',')
                        .zip(self.targets)
                        .any(|(name, id)| id.is_some() && name.eq_ignore_ascii_case(target))
            }
            ("481", [nick], Some("Command is unavailable")) => recipient.eq_ignore_ascii_case(nick),
            _ => false,
        }
    }

    /// Check positive and negative per-target decisions in either delivery order.
    /// A generic 481 covers at most one original target which has no named outcome.
    pub(in crate::federation::edge) fn check_evidence<'a>(
        &self,
        message: &ParsedMessage,
        echoes: impl Iterator<Item = &'a WireMessage>,
        replies: &[WireMessage],
    ) -> Result<(), Violation> {
        let [original_channel, names] = message.middle() else {
            return Err(Violation::Consistency);
        };
        let count = names.split(',').count();
        let mut decided = 0u8;
        let mut mark = |target: &str, echo: bool| -> Result<(), Violation> {
            let index = names
                .split(',')
                .position(|name| name.eq_ignore_ascii_case(target))
                .ok_or(Violation::Consistency)?;
            let id = self.targets.get(index).ok_or(Violation::Consistency)?;
            let bit = 1 << index;
            if (echo && id.is_none()) || decided & bit != 0 {
                return Err(Violation::Consistency);
            }
            decided |= bit;
            Ok(())
        };
        for frame in echoes {
            mark(
                confirmed_target(original_channel, message.trailing(), frame)?,
                true,
            )?;
        }
        let mut generic = 0;
        for reply in replies {
            match (reply.command(), reply.middle()) {
                ("401", [_, name]) => mark(name, false)?,
                ("481", [_]) => generic += 1,
                _ => return Err(Violation::Consistency),
            }
        }
        if decided.count_ones() as usize + generic > count {
            return Err(Violation::Consistency);
        }
        Ok(())
    }
}
