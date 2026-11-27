//! Per-target message dispositions belong to one registered request. Nicknames
//! are always resolved by the coordinator. A missing local channel has no
//! instance ID to forward and shares the final response of the known targets.
use super::*;
use agenc_relay_client_wire::WireMessage;
use agenc_relay_domain::{ChannelNameValue, FailedTarget, MessageCommand, NicknameValue};

#[cfg(test)]
#[path = "tests/message_results.rs"]
mod tests;

pub(crate) struct MessageRequester {
    origin: ReplyRequester,
    // Bit positions use the canonical domain ordering of the original targets.
    absent: u8,
}

pub(super) fn route(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    (session, user): (SessionId, UserId),
    command: &MessageCommand,
    message: Box<ParsedMessage>,
) -> Result<Routed, (Box<ParsedMessage>, DomainError)> {
    let (operation, absent) = match message_operation(edge, session, &message, command) {
        Ok(parts) => parts,
        Err(error) => return Err((message, error)),
    };
    let Some((session, caps)) = edge
        .replica
        .session(user)
        .zip(context.sessions().capabilities_for_user(user))
    else {
        return Err((message, DomainError::RegistrationRequired));
    };
    let origin = match ReplyRequester::new(session.nickname.presentation(), caps) {
        Ok(origin) => origin,
        Err(error) => return Err((message, error)),
    };
    let requester = MessageRequester { origin, absent };
    let Some(operation) = operation else {
        let frames = requester
            .local_refusals(context.server_prefix(), &message, command)
            .and_then(|frames| {
                crate::client_render::logical_frames(
                    context.server_prefix(),
                    caps,
                    &message,
                    frames,
                )
            })
            .map_err(|_| DomainError::InvariantViolation);
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
            echo_channels: Some(EchoChannels::Message(requester)),
        },
    );
    Ok(Routed::Forwarded)
}

impl MessageRequester {
    fn local_refusals(
        &self,
        prefix: &str,
        request: &ParsedMessage,
        command: &MessageCommand,
    ) -> Result<Vec<WireMessage>, crate::RuntimeError> {
        if command.kind() == MessageKind::Notice {
            return Ok(Vec::new());
        }
        let nickname = self
            .origin
            .nickname()
            .map_err(|_| crate::RuntimeError::InvalidValue)?;
        command
            .targets()
            .iter()
            .map(|target| {
                let MessageTarget::Channel(name) = target else {
                    return Err(crate::RuntimeError::InvalidValue);
                };
                crate::client_render::projected_failure(
                    self.origin.dialect,
                    prefix,
                    nickname,
                    request,
                    DomainError::SecretUnavailable,
                    Some(&FailedTarget::Channel(name.clone())),
                )
            })
            .collect()
    }

    pub(super) fn project(
        &self,
        prefix: &str,
        request: &ParsedMessage,
        arm: &ResultArm,
        replies: &mut Vec<WireMessage>,
    ) -> Result<(), Violation> {
        let targets = original_targets(request)?;
        let remote_count = targets
            .len()
            .checked_sub(self.absent.count_ones() as usize)
            .ok_or(Violation::Consistency)?;
        if !covered_result(request.command(), arm, replies.len(), remote_count)? {
            return Ok(());
        }
        self.project_covered(prefix, request, targets, arm, replies)
    }

    fn project_covered(
        &self,
        prefix: &str,
        request: &ParsedMessage,
        targets: Vec<&str>,
        arm: &ResultArm,
        replies: &mut Vec<WireMessage>,
    ) -> Result<(), Violation> {
        let nick = self.origin.nickname()?;
        let mut remaining = replies.iter().peekable();
        let mut first = None;
        let mut projected = Vec::new();
        projected
            .try_reserve_exact(targets.len())
            .map_err(|_| Violation::Ceiling)?;
        for (index, name) in targets.into_iter().enumerate() {
            let error = if self.absent & (1 << index) != 0 {
                DomainError::SecretUnavailable
            } else if let Some(error) = remaining
                .peek()
                .and_then(|frame| covered_error(frame, nick, name))
            {
                if first.is_none() {
                    first = Some((name, error));
                }
                remaining.next();
                error
            } else {
                continue;
            };
            projected.push(self.refusal(prefix, request, name, error)?);
        }
        if remaining.next().is_some() {
            return Err(Violation::Consistency);
        }
        check_first_failure(arm, first)?;
        *replies = projected;
        Ok(())
    }
    fn refusal(
        &self,
        prefix: &str,
        request: &ParsedMessage,
        name: &str,
        error: DomainError,
    ) -> Result<WireMessage, Violation> {
        let target = if name.starts_with('#') {
            FailedTarget::Channel(
                ChannelNameValue::parse(name).map_err(|_| Violation::Consistency)?,
            )
        } else {
            FailedTarget::User(NicknameValue::parse(name).map_err(|_| Violation::Consistency)?)
        };
        crate::client_render::projected_failure(
            self.origin.dialect,
            prefix,
            self.origin.nickname()?,
            request,
            error,
            Some(&target),
        )
        .map_err(|_| Violation::Codec)
    }
}

fn covered_result(
    command: &str,
    arm: &ResultArm,
    received: usize,
    remote_count: usize,
) -> Result<bool, Violation> {
    if command == "NOTICE" {
        // A stored v1 refusal can predate the explicit no_content suppression.
        return match arm {
            ResultArm::NoContent | ResultArm::Committed { .. } | ResultArm::Failed { .. }
                if received == 0 =>
            {
                Ok(false)
            }
            _ => Err(Violation::Consistency),
        };
    }
    match arm {
        // An old failure or a command-level error cannot identify individual targets.
        ResultArm::Failed { .. } if received == 0 => Ok(false),
        ResultArm::Committed { .. } if received < remote_count => Ok(true),
        ResultArm::Failed { .. } if received == remote_count => Ok(true),
        _ => Err(Violation::Consistency),
    }
}

fn check_first_failure(
    arm: &ResultArm,
    first: Option<(&str, DomainError)>,
) -> Result<(), Violation> {
    if let ResultArm::Failed { code, context } = arm {
        let (name, error) = first.ok_or(Violation::Consistency)?;
        if code != crate::federation::codec::results::failure_code(error)
            || !(context.is_empty() || context.eq_ignore_ascii_case(name))
        {
            return Err(Violation::Consistency);
        }
    }
    Ok(())
}

// Only the closed public numeric and the original requester/target can be
// projected. A user policy refusal has no public target operand.
fn covered_error(frame: &WireMessage, nick: &str, target: &str) -> Option<DomainError> {
    let (recipient, middle) = frame.middle().split_first()?;
    if !recipient.eq_ignore_ascii_case(nick) {
        return None;
    }
    let channel = target.starts_with('#');
    if middle.is_empty() {
        return (!channel
            && frame.command() == "481"
            && frame.trailing() == Some("Command is unavailable"))
        .then_some(DomainError::Forbidden);
    }
    if !matches!(middle, [name] if name.eq_ignore_ascii_case(target)) {
        return None;
    }
    match (frame.command(), channel, frame.trailing()) {
        ("401", false, Some("No such nick")) => Some(DomainError::NotFound),
        ("403", true, Some("No such channel")) => Some(DomainError::SecretUnavailable),
        ("482", true, Some("Permission denied for channel")) => Some(DomainError::Forbidden),
        ("404", true, Some("Cannot send to channel")) => Some(DomainError::EncryptedRoute),
        _ => None,
    }
}

fn original_targets(request: &ParsedMessage) -> Result<Vec<&str>, Violation> {
    let names = request.middle().first().ok_or(Violation::Consistency)?;
    let mut targets = Vec::new();
    for name in names.split(',') {
        if targets.len() >= 4 || name.is_empty() {
            return Err(Violation::Consistency);
        }
        targets.push(name);
    }
    // Both names use ASCII lowercase canonical keys; all global channels sort
    // before all nicknames in the domain's MessageCommand.
    targets.sort_unstable_by(|a, b| {
        a.bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.bytes().map(|c| c.to_ascii_lowercase()))
    });
    Ok(targets)
}
