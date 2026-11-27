//! Projection of a covered v1 JOIN result to the original physical requester.
use crate::RuntimeError;
use agenc_relay_client_wire::{ParsedMessage, StandardReplies, WireMessage};
use agenc_relay_domain::{ChannelNameValue, DomainError, FailedTarget, NicknameValue};

/// The nickname and public response dialect at the original request's admission.
pub(crate) struct JoinRequester {
    pub(crate) nickname: NicknameValue,
    pub(crate) replies: StandardReplies,
}

impl JoinRequester {
    /// Validate the complete result before publishing any of it. Previously stored results
    /// placed all topic replies before the failures. Both lists retain original target order.
    pub(crate) fn project_covered(
        &self,
        prefix: &str,
        request: &ParsedMessage,
        frames: &mut [WireMessage],
        first_failure: Option<(&str, &str)>,
    ) -> Result<(), RuntimeError> {
        let targets = original_targets(request)?;
        if let Some((_, context)) = first_failure {
            check_context(context, targets.first().ok_or(RuntimeError::InvalidValue)?)?;
        }
        let accepted = self.accepted(&targets, frames)?;
        if (accepted == 0) != first_failure.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        let mut refused = targets
            .iter()
            .enumerate()
            .filter(|(index, _)| accepted & (1 << index) == 0);
        let mut first = first_failure.map(|(code, _)| code);
        for frame in frames.iter_mut().filter(|frame| !is_topic(frame)) {
            let (_, target) = refused.next().ok_or(RuntimeError::InvalidValue)?;
            let error = target_error(frame, target, first.take())?;
            if self.replies.enabled() {
                *frame = crate::client_render::projected_failure(
                    self.replies,
                    prefix,
                    self.nickname.presentation(),
                    request,
                    error,
                    Some(&FailedTarget::Channel(target.clone())),
                )?;
            }
        }
        if refused.next().is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }

    /// Project a failed v1 result which predates the complete failure vector. Its
    /// arm carries only the first canonical failure. A source without a target-local
    /// decision is handled as the original command-level refusal.
    pub(crate) fn coarse(
        &self,
        prefix: &str,
        request: &ParsedMessage,
        code: &str,
        context: &str,
    ) -> Result<Option<WireMessage>, RuntimeError> {
        let error = match code {
            "SECRET_UNAVAILABLE" => DomainError::SecretUnavailable,
            "NOT_ALLOWED" => DomainError::Forbidden,
            "BAD_STATE" => DomainError::BadState,
            "E2EE_REQUIRED" => DomainError::EncryptedRoute,
            "TOO_LARGE" => DomainError::LimitExceeded,
            _ => return Ok(None),
        };
        let targets = original_targets(request)?;
        let first = targets.first().ok_or(RuntimeError::InvalidValue)?;
        check_context(context, first)?;
        crate::client_render::projected_failure(
            self.replies,
            prefix,
            self.nickname.presentation(),
            request,
            error,
            Some(&FailedTarget::Channel(first.clone())),
        )
        .map(Some)
    }

    fn accepted(
        &self,
        targets: &[ChannelNameValue],
        frames: &[WireMessage],
    ) -> Result<u32, RuntimeError> {
        let mut accepted = 0_u32;
        let mut next = 0;
        let mut metadata = None;
        for frame in frames {
            let (nick, params) = frame
                .middle()
                .split_first()
                .ok_or(RuntimeError::InvalidValue)?;
            if !nick.eq_ignore_ascii_case(self.nickname.presentation()) {
                return Err(RuntimeError::InvalidValue);
            }
            let preceding_topic = metadata.take();
            if frame.command() == "333" {
                check_metadata(
                    frame,
                    params,
                    preceding_topic.ok_or(RuntimeError::InvalidValue)?,
                )?;
                continue;
            }
            if is_topic(frame) {
                let [channel] = params else {
                    return Err(RuntimeError::InvalidValue);
                };
                if frame.trailing().is_none() {
                    return Err(RuntimeError::InvalidValue);
                }
                let index = targets
                    .iter()
                    .enumerate()
                    .skip(next)
                    .find(|(_, name)| channel.eq_ignore_ascii_case(name.presentation()))
                    .map(|(index, _)| index)
                    .ok_or(RuntimeError::InvalidValue)?;
                accepted |= 1 << index;
                next = index + 1;
                // An encrypted bound channel deliberately supplies only a 332 placeholder.
                // A setter row, when present, belongs to the immediately preceding 332.
                if frame.command() == "332" {
                    metadata = Some(channel.as_str());
                }
            }
        }
        Ok(accepted)
    }
}

pub(crate) fn original_targets(
    request: &ParsedMessage,
) -> Result<Vec<ChannelNameValue>, RuntimeError> {
    let mut targets = Vec::new();
    let names = request.middle().first().ok_or(RuntimeError::InvalidValue)?;
    for text in names.split(',') {
        let name = ChannelNameValue::parse(text).map_err(|_| RuntimeError::InvalidValue)?;
        if targets.len() >= 20 || targets.contains(&name) {
            return Err(RuntimeError::InvalidValue);
        }
        targets.push(name);
    }
    // operation.join sorts by canonical channel name after pairing each original key.
    targets.sort_unstable_by(|left, right| left.canonical().cmp(right.canonical()));
    Ok(targets)
}

fn check_context(context: &str, first: &ChannelNameValue) -> Result<(), RuntimeError> {
    if context.is_empty() || first.presentation().eq_ignore_ascii_case(context) {
        Ok(())
    } else {
        Err(RuntimeError::InvalidValue)
    }
}

fn check_metadata(frame: &WireMessage, params: &[String], name: &str) -> Result<(), RuntimeError> {
    if matches!(params, [channel, _, _] if channel.eq_ignore_ascii_case(name))
        && frame.trailing().is_none()
    {
        Ok(())
    } else {
        Err(RuntimeError::InvalidValue)
    }
}

fn is_topic(frame: &WireMessage) -> bool {
    matches!(frame.command(), "331" | "332" | "333")
}

fn target_error(
    frame: &WireMessage,
    target: &ChannelNameValue,
    first: Option<&str>,
) -> Result<DomainError, RuntimeError> {
    use DomainError::{BadState, EncryptedRoute, LimitExceeded, SecretUnavailable};
    // B.6 carries only the registered numeric. The original, ordered target set binds
    // the scope even for the unqualified legacy capacity numeric. Never parse public prose.
    let (error, allowed): (_, &[&str]) = match frame.command() {
        "403" => (SecretUnavailable, &["SECRET_UNAVAILABLE"]),
        "404" => (EncryptedRoute, &["E2EE_REQUIRED"]),
        "481" => (LimitExceeded, &["SERVER_BUSY", "TOO_LARGE"]),
        "482" => (BadState, &["BAD_STATE", "NOT_ALLOWED"]),
        _ => return Err(RuntimeError::InvalidValue),
    };
    // numeric_reply already checked the exact registered arity: 481 omits its
    // channel, and the other three numerics each carry just one after the nickname.
    let wrong_target = frame
        .middle()
        .get(1)
        .is_some_and(|name| !name.eq_ignore_ascii_case(target.presentation()));
    if wrong_target || first.is_some_and(|code| !allowed.contains(&code)) {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(error)
}

#[cfg(test)]
#[path = "tests/refusal.rs"]
mod tests;
