//! One explicit PART can contain both known instances and names absent from the edge.
//! Only admitted instance IDs go to the coordinator. Local refusals share the original
//! connection, response label and completion with every authoritative decision.
use super::*;
use crate::federation::codec::results::failure_code;
use agenc_relay_client_wire::{CapabilityState, WireMessage};
use agenc_relay_domain::{ChannelNameValue, FailedTarget};

#[cfg(test)]
#[path = "tests/departure.rs"]
mod tests;

pub(crate) struct PartRequester {
    origin: ReplyRequester,
    absent: u32,
}

impl PartRequester {
    pub(crate) fn new(
        nick: &str,
        caps: &CapabilityState,
        absent: u32,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            origin: ReplyRequester::new(nick, caps)?,
            absent,
        })
    }

    fn refusal(
        &self,
        prefix: &str,
        request: &ParsedMessage,
        target: &ChannelNameValue,
        error: DomainError,
    ) -> Result<WireMessage, Violation> {
        crate::client_render::projected_failure(
            self.origin.dialect,
            prefix,
            self.origin.nickname()?,
            request,
            error,
            Some(&FailedTarget::Channel(target.clone())),
        )
        .map_err(|_| Violation::Codec)
    }

    pub(super) fn project(
        &self,
        prefix: &str,
        request: &ParsedMessage,
        arm: &ResultArm,
        replies: &mut Vec<WireMessage>,
    ) -> Result<(), Violation> {
        let targets = crate::mutation_render::original_channel_targets(request)
            .map_err(|_| Violation::Consistency)?;
        let mut errors = [None; 20];
        if !self.validate_result(&targets, arm, replies, &mut errors)? {
            return Ok(());
        }
        let mut projected = Vec::new();
        projected
            .try_reserve_exact(targets.len())
            .map_err(|_| Violation::Ceiling)?;
        for (index, (target, error)) in targets.iter().zip(errors).enumerate() {
            let missing = (self.absent & (1 << index) != 0).then_some(DomainError::NotFound);
            if let Some(error) = missing.or(error) {
                projected.push(self.refusal(prefix, request, target, error)?);
            }
        }
        *replies = projected;
        Ok(())
    }

    fn validate_result(
        &self,
        targets: &[ChannelNameValue],
        arm: &ResultArm,
        replies: &[WireMessage],
        errors: &mut [Option<DomainError>; 20],
    ) -> Result<bool, Violation> {
        let known = targets
            .len()
            .checked_sub(self.absent.count_ones() as usize)
            .ok_or(Violation::Consistency)?;
        let mut previous = None;
        for frame in replies.iter() {
            let (index, error) = self.covered_target(frame, targets)?;
            if previous.is_some_and(|prior| prior >= index) || self.absent & (1 << index) != 0 {
                return Err(Violation::Consistency);
            }
            *errors.get_mut(index).ok_or(Violation::Consistency)? = Some(error);
            previous = Some(index);
        }
        match arm {
            ResultArm::Committed { .. } if replies.len() < known => {}
            ResultArm::Failed { code, context } if !replies.is_empty() => {
                validate_failed(targets, errors, known, replies.len(), code, context)?;
            }
            ResultArm::Failed { code, context } => {
                // Older peers return just the first canonical NOT_ALLOWED decision.
                // A stale instance or a service failure has no target-local disposition.
                if code != "NOT_ALLOWED" {
                    return Ok(false);
                }
                let (index, first) = targets
                    .iter()
                    .enumerate()
                    .find(|(i, _)| self.absent & (1 << i) == 0)
                    .ok_or(Violation::Consistency)?;
                if !context.is_empty() && !context.eq_ignore_ascii_case(first.presentation()) {
                    return Err(Violation::Consistency);
                }
                *errors.get_mut(index).ok_or(Violation::Consistency)? =
                    Some(DomainError::Forbidden);
            }
            _ => return Err(Violation::Consistency),
        }
        Ok(true)
    }

    fn covered_target(
        &self,
        frame: &WireMessage,
        targets: &[ChannelNameValue],
    ) -> Result<(usize, DomainError), Violation> {
        let [nick, target] = frame.middle() else {
            return Err(Violation::Consistency);
        };
        if !nick.eq_ignore_ascii_case(self.origin.nickname()?) {
            return Err(Violation::Consistency);
        }
        let error = match (frame.command(), frame.trailing()) {
            ("403", Some("No such channel")) => DomainError::NotFound,
            ("482", Some("Permission denied for channel")) => DomainError::Forbidden,
            _ => return Err(Violation::Consistency),
        };
        let index = targets
            .iter()
            .position(|name| name.presentation().eq_ignore_ascii_case(target))
            .ok_or(Violation::Consistency)?;
        Ok((index, error))
    }
}

fn validate_failed(
    targets: &[ChannelNameValue],
    errors: &[Option<DomainError>],
    known: usize,
    received: usize,
    code: &str,
    context: &str,
) -> Result<(), Violation> {
    let (first, error) = errors
        .iter()
        .enumerate()
        .find_map(|(i, error)| error.map(|e| (i, e)))
        .ok_or(Violation::Consistency)?;
    let name = targets.get(first).ok_or(Violation::Consistency)?;
    if received != known
        || code != failure_code(error)
        || !(context.is_empty() || context.eq_ignore_ascii_case(name.presentation()))
    {
        return Err(Violation::Consistency);
    }
    Ok(())
}

enum Admission {
    Local(Vec<WireMessage>),
    Forward {
        channels: Vec<agenc_relay_types::ChannelInstanceId>,
        reason: String,
        revision: u64,
        requester: PartRequester,
        backing: Option<MemoryPermitBatch>,
    },
}

pub(super) fn route(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    identity: (SessionId, UserId),
    command: &CanonicalCommand,
    message: Box<ParsedMessage>,
) -> Result<Routed, (Box<ParsedMessage>, DomainError)> {
    let (operation, requester, backing) = match admit(edge, context, identity.1, command, &message)
    {
        Err(error) => return Err((message, error)),
        Ok(Admission::Local(frames)) => return Ok(Routed::Local { frames, message }),
        Ok(Admission::Forward {
            channels,
            reason,
            revision,
            requester,
            backing,
        }) => (
            FederatedOperation::Part {
                channels,
                reason,
                session_id: identity.0,
                expected_session_revision: revision,
                all_channels: false,
            },
            requester,
            backing,
        ),
    };
    let Ok(prepared) = prepare_request(edge, context, generation, &operation) else {
        return Err((message, DomainError::ServerBusy));
    };
    let pending = PendingKind::for_operation(message, operation, Some((requester, backing)));
    register_request(edge, context, generation, prepared, pending);
    Ok(Routed::Forwarded)
}

fn admit(
    edge: &EdgeFederation,
    context: &mut StateCoreContext,
    user: UserId,
    command: &CanonicalCommand,
    message: &ParsedMessage,
) -> Result<Admission, DomainError> {
    let CanonicalCommandView::Part(targets, reason) = command.view() else {
        return Err(DomainError::InvariantViolation);
    };
    let mut channels = Vec::new();
    channels
        .try_reserve_exact(targets.len())
        .map_err(|_| DomainError::ServerBusy)?;
    let mut absent = 0;
    for (index, target) in targets.iter().enumerate() {
        if let Some(channel) = edge.replica.channel_by_name(target) {
            channels.push(channel.channel_id);
        } else {
            absent |= 1u32 << index;
        }
    }
    let session = edge
        .replica
        .session(user)
        .ok_or(DomainError::RegistrationRequired)?;
    let caps = context
        .sessions()
        .capabilities_for_user(user)
        .ok_or(DomainError::RegistrationRequired)?;
    let requester = PartRequester::new(session.nickname.presentation(), caps, absent)?;
    if channels.is_empty() {
        return local_refusals(context, user, message, targets, &requester).map(Admission::Local);
    }
    channels.sort_unstable();
    let reason = reason.map_or(String::new(), |reason| reason.as_str().to_owned());
    let labeled = caps.enabled("labeled-response")
        && message
            .tags()
            .iter()
            .any(|tag| tag.key() == "label" && tag.value().is_some());
    let backing = if labeled {
        Some(reserve_departure_backing(
            context,
            channels.capacity(),
            reason.capacity(),
        )?)
    } else {
        None
    };
    Ok(Admission::Forward {
        channels,
        reason,
        revision: session.session_revision.get(),
        requester,
        backing,
    })
}

fn local_refusals(
    context: &mut StateCoreContext,
    user: UserId,
    message: &ParsedMessage,
    targets: &[ChannelNameValue],
    requester: &PartRequester,
) -> Result<Vec<WireMessage>, DomainError> {
    let frames = targets
        .iter()
        .map(|target| {
            requester.refusal(
                context.server_prefix(),
                message,
                target,
                DomainError::NotFound,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DomainError::InvariantViolation)?;
    let caps = context
        .sessions()
        .capabilities_for_user(user)
        .ok_or(DomainError::RegistrationRequired)?;
    crate::client_render::logical_frames(context.server_prefix(), caps, message, frames)
        .map_err(|_| DomainError::InvariantViolation)
}
