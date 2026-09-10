//! Public-safe replies for registered client commands.

use agenc_ircd_client_wire::{
    CapabilityState, ParsedMessage, ReplyKind, SafeReplyContext, SafeReplyDescription, WireMessage,
    labeled_response, numeric_reply, standard_reply,
};
use agenc_ircd_domain::{DomainError, FailedTarget, RejectedPlan};
use agenc_ircd_types::{ChannelName, PublicErrorCode, UserId};

use crate::RuntimeError;
use crate::connection::sink::{ConnectionGeneration, QuerySnapshotPermit};
use crate::state_core::StateCoreContext;

struct StandardFailure<'a> {
    operation: &'a str,
    code: PublicErrorCode,
    description: &'static str,
}

#[derive(Clone, Copy)]
pub(crate) struct ReplyInput<'a> {
    pub requester: UserId,
    pub generation: ConnectionGeneration,
    pub capabilities: &'a CapabilityState,
    pub request: &'a ParsedMessage,
}

pub(crate) fn render_domain_failure(
    context: &mut StateCoreContext,
    reply: ReplyInput<'_>,
    error: DomainError,
    silent: bool,
    target: Option<&FailedTarget>,
) -> Result<(), RuntimeError> {
    if silent {
        return Ok(());
    }
    let nickname = requester_nickname(context, reply.requester);
    let frame = failure_frame(
        reply.capabilities,
        context.server_prefix(),
        &nickname,
        reply.request,
        error,
        target,
    )?;
    send_logical(
        context,
        reply.generation,
        reply.capabilities,
        reply.request,
        vec![frame],
    )
}

pub(crate) fn render_rejected(
    context: &mut StateCoreContext,
    reply: ReplyInput<'_>,
    plan: &RejectedPlan,
) -> Result<(), RuntimeError> {
    if plan.is_silent() {
        return Ok(());
    }
    let nickname = requester_nickname(context, reply.requester);
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(plan.failures().len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for failure in plan.failures() {
        frames.push(failure_frame(
            reply.capabilities,
            context.server_prefix(),
            &nickname,
            reply.request,
            failure.error(),
            Some(failure.target()),
        )?);
    }
    send_logical(
        context,
        reply.generation,
        reply.capabilities,
        reply.request,
        frames,
    )
}

pub(crate) fn failure_frame(
    capabilities: &CapabilityState,
    prefix: &str,
    nickname: &str,
    request: &ParsedMessage,
    error: DomainError,
    target: Option<&FailedTarget>,
) -> Result<WireMessage, RuntimeError> {
    if error == DomainError::LimitExceeded
        && request.command() == "MONITOR"
        && let [operation, targets] = request.middle()
        && operation == "+"
    {
        let limit = agenc_ircd_domain::MAX_MONITORED_NICKNAMES.to_string();
        return numeric_reply(
            prefix,
            734,
            nickname,
            &[&limit, targets],
            Some("Monitor list is full"),
        )
        .map_err(|_| RuntimeError::InvalidValue);
    }
    if let Some(frame) = standard_failure(capabilities, prefix, request, error, target)? {
        return Ok(frame);
    }
    legacy_failure(prefix, nickname, request, error, target)
}

fn standard_failure(
    capabilities: &CapabilityState,
    prefix: &str,
    request: &ParsedMessage,
    error: DomainError,
    target: Option<&FailedTarget>,
) -> Result<Option<WireMessage>, RuntimeError> {
    if !capabilities.enabled("standard-replies") {
        return Ok(None);
    }
    let operation = request.command();
    if error == DomainError::SecretUnavailable {
        return standard_channel_failure(capabilities, prefix, request, target);
    }
    if error == DomainError::EncryptedRoute {
        return standard_e2ee_failure(capabilities, prefix, request, target);
    }
    let Some(failure) = plain_standard_failure(operation, error) else {
        return Ok(None);
    };
    let frame = standard_reply(
        capabilities,
        prefix,
        ReplyKind::Fail,
        failure.operation,
        failure.code,
        &[],
        description(failure.description)?,
    )
    .map_err(|_| RuntimeError::InvalidValue)?;
    Ok(Some(frame))
}

fn plain_standard_failure(operation: &str, error: DomainError) -> Option<StandardFailure<'_>> {
    let failure = match error {
        DomainError::InvalidArgument
        | DomainError::DuplicateTarget
        | DomainError::MixedAuthority => StandardFailure {
            operation,
            code: PublicErrorCode::INVALIDARGUMENT,
            description: "Invalid command argument",
        },
        DomainError::ServerBusy
        | DomainError::LimitExceeded
        | DomainError::AllocationFailed
        | DomainError::Overflow
        | DomainError::StaleGeneration
        | DomainError::StaleRevision
        | DomainError::WallClockUnavailable => StandardFailure {
            operation,
            code: PublicErrorCode::SERVERBUSY,
            description: "Server is busy",
        },
        DomainError::RegistrationRequired => StandardFailure {
            operation: "*",
            code: PublicErrorCode::REGISTRATIONREQUIRED,
            description: "An account is required",
        },
        DomainError::UnsafeCtcp if operation == "PRIVMSG" => StandardFailure {
            operation,
            code: PublicErrorCode::UNSAFECTCP,
            description: "Unsafe CTCP command refused",
        },
        DomainError::BadState
            if matches!(
                operation,
                "ACCT" | "ACCTCREATE" | "ACCTCRED" | "AUTHENTICATE"
            ) =>
        {
            StandardFailure {
                operation,
                code: PublicErrorCode::BADSTATE,
                description: "Command is not valid in the current state",
            }
        }
        _ => return None,
    };
    Some(failure)
}

fn standard_channel_failure(
    capabilities: &CapabilityState,
    prefix: &str,
    request: &ParsedMessage,
    target: Option<&FailedTarget>,
) -> Result<Option<WireMessage>, RuntimeError> {
    let operation = request.command();
    if !matches!(operation, "JOIN" | "MODE" | "NAMES" | "TOPIC") {
        return Ok(None);
    }
    let Some(channel) = failure_channel(request, target) else {
        return Ok(None);
    };
    standard_reply(
        capabilities,
        prefix,
        ReplyKind::Fail,
        operation,
        PublicErrorCode::SECRETUNAVAILABLE,
        &[SafeReplyContext::Channel(&channel)],
        description("Channel is unavailable")?,
    )
    .map(Some)
    .map_err(|_| RuntimeError::InvalidValue)
}

fn standard_e2ee_failure(
    capabilities: &CapabilityState,
    prefix: &str,
    request: &ParsedMessage,
    target: Option<&FailedTarget>,
) -> Result<Option<WireMessage>, RuntimeError> {
    let operation = request.command();
    let channel = failure_channel(request, target);
    let contexts = channel
        .as_ref()
        .map(|channel| [SafeReplyContext::Channel(channel)]);
    let context = contexts.as_ref().map_or(&[][..], |context| &context[..]);
    if operation != "JOIN" && !(operation == "PRIVMSG" && channel.is_some()) {
        return Ok(None);
    }
    standard_reply(
        capabilities,
        prefix,
        ReplyKind::Fail,
        operation,
        PublicErrorCode::E2EEREQUIRED,
        context,
        description("End-to-end encryption is required")?,
    )
    .map(Some)
    .map_err(|_| RuntimeError::InvalidValue)
}

fn legacy_failure(
    prefix: &str,
    nickname: &str,
    request: &ParsedMessage,
    error: DomainError,
    target: Option<&FailedTarget>,
) -> Result<WireMessage, RuntimeError> {
    let operation = request.command();
    let target_text = failure_target(request, target);
    let target_is_channel = target_text.starts_with(['#', '&']);
    let rendered = match error {
        DomainError::InvalidArgument
        | DomainError::DuplicateTarget
        | DomainError::MixedAuthority => numeric_reply(
            prefix,
            461,
            nickname,
            &[operation],
            Some("Invalid command arguments"),
        ),
        DomainError::NotFound | DomainError::SecretUnavailable if target_is_channel => {
            numeric_reply(
                prefix,
                403,
                nickname,
                &[target_text],
                Some("No such channel"),
            )
        }
        DomainError::NotFound => {
            numeric_reply(prefix, 401, nickname, &[target_text], Some("No such nick"))
        }
        DomainError::Forbidden | DomainError::BadState if target_is_channel => numeric_reply(
            prefix,
            482,
            nickname,
            &[target_text],
            Some("Permission denied for channel"),
        ),
        DomainError::UnsafeCtcp | DomainError::EncryptedRoute | DomainError::PlaintextRoute
            if target_is_channel =>
        {
            numeric_reply(
                prefix,
                404,
                nickname,
                &[target_text],
                Some("Cannot send to channel"),
            )
        }
        _ => numeric_reply(prefix, 481, nickname, &[], Some("Command is unavailable")),
    };
    rendered.map_err(|_| RuntimeError::InvalidValue)
}

fn failure_channel(request: &ParsedMessage, target: Option<&FailedTarget>) -> Option<ChannelName> {
    let text = target.and_then(FailedTarget::channel).map_or_else(
        || failure_target(request, target),
        |name| name.presentation(),
    );
    ChannelName::parse(text).ok()
}

fn failure_target<'a>(request: &'a ParsedMessage, target: Option<&'a FailedTarget>) -> &'a str {
    if let Some(target) = target {
        if let Some(channel) = target.channel() {
            return channel.presentation();
        }
        if let Some(nickname) = target.user() {
            return nickname.presentation();
        }
    }
    request
        .middle()
        .first()
        .and_then(|value| value.split(',').next())
        .unwrap_or("*")
}

pub(crate) fn requester_nickname(context: &StateCoreContext, requester: UserId) -> String {
    context
        .domain()
        .session(requester)
        .map(|session| session.nickname().presentation().to_owned())
        .unwrap_or_else(|| "*".to_owned())
}

fn description(text: &'static str) -> Result<SafeReplyDescription, RuntimeError> {
    SafeReplyDescription::new(text).map_err(|_| RuntimeError::InvalidValue)
}

pub(crate) fn send_logical(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    capabilities: &CapabilityState,
    request: &ParsedMessage,
    frames: Vec<WireMessage>,
) -> Result<(), RuntimeError> {
    let logical = logical_frames(context.server_prefix(), capabilities, request, frames)?;
    context
        .send_to(generation, logical)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    Ok(())
}

pub(crate) fn send_logical_query(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    capabilities: &CapabilityState,
    request: &ParsedMessage,
    frames: Vec<WireMessage>,
    snapshot: QuerySnapshotPermit,
) -> Result<(), RuntimeError> {
    let logical = logical_frames(context.server_prefix(), capabilities, request, frames)?;
    context
        .send_query_to(generation, logical, snapshot)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    Ok(())
}

pub(crate) fn logical_frames(
    prefix: &str,
    capabilities: &CapabilityState,
    request: &ParsedMessage,
    frames: Vec<WireMessage>,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let label = request
        .tags()
        .iter()
        .find(|tag| tag.key() == "label")
        .and_then(|tag| tag.value());
    let logical = labeled_response(capabilities, prefix, label, label, frames)
        .map_err(|_| RuntimeError::InvalidValue)?;
    Ok(logical.into_messages())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use agenc_ircd_client_wire::{
        CapRequestReply, CapabilityProfile, CapabilitySpec, FramedLine, OutputBudget, RenderError,
        parse_message,
    };

    use super::*;

    struct ExactBudget(usize);

    impl OutputBudget for ExactBudget {
        type Permit = ();

        fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
            (bytes == self.0)
                .then_some(())
                .ok_or(RenderError::ReservationFailed)
        }
    }

    fn parsed(line: &str) -> Result<ParsedMessage, Box<dyn Error>> {
        parse_message(FramedLine::new(line)?)?.ok_or_else(|| "empty message".into())
    }

    fn encoded(message: WireMessage) -> Result<Vec<u8>, Box<dyn Error>> {
        let measured = message.measure()?;
        let mut budget = ExactBudget(measured.bytes());
        Ok(measured.encode(&mut budget)?.as_bytes().to_vec())
    }

    fn standard_capabilities() -> Result<CapabilityState, Box<dyn Error>> {
        let advertised =
            CapabilityProfile::new(vec![CapabilitySpec::new("standard-replies", None)?])?;
        let mut capabilities = CapabilityState::default();
        capabilities.ls(Some("302"), &advertised)?;
        assert!(matches!(
            capabilities.request("standard-replies", &advertised)?,
            CapRequestReply::Ack(_)
        ));
        Ok(capabilities)
    }

    #[test]
    fn a_full_monitor_list_returns_its_limit_and_requested_targets() -> Result<(), Box<dyn Error>> {
        let request = parsed("MONITOR + alice,bob")?;
        for capabilities in [CapabilityState::default(), standard_capabilities()?] {
            let reply = failure_frame(
                &capabilities,
                "server",
                "requester",
                &request,
                DomainError::LimitExceeded,
                None,
            )?;
            assert_eq!(
                encoded(reply)?,
                b":server 734 requester 100 alice,bob :Monitor list is full\r\n"
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_arguments_use_standard_replies_when_negotiated() -> Result<(), Box<dyn Error>> {
        let request = parsed("MODE #chat +x")?;
        let frame = failure_frame(
            &standard_capabilities()?,
            "server",
            "requester",
            &request,
            DomainError::InvalidArgument,
            None,
        )?;
        assert_eq!(
            encoded(frame)?,
            b":server FAIL MODE INVALID_ARGUMENT :Invalid command argument\r\n"
        );
        Ok(())
    }

    #[test]
    fn durable_storage_rejections_use_bounded_standard_busy() -> Result<(), Box<dyn Error>> {
        let request = parsed("PRIVMSG #chat :hello")?;
        let frame = failure_frame(
            &standard_capabilities()?,
            "server",
            "requester",
            &request,
            DomainError::ServerBusy,
            None,
        )?;
        assert_eq!(
            encoded(frame)?,
            b":server FAIL PRIVMSG SERVER_BUSY :Server is busy\r\n"
        );
        Ok(())
    }

    #[test]
    fn legacy_failures_use_public_targets_without_internal_text() -> Result<(), Box<dyn Error>> {
        let request = parsed("JOIN #hidden")?;
        let frame = failure_frame(
            &CapabilityState::default(),
            "server",
            "requester",
            &request,
            DomainError::SecretUnavailable,
            None,
        )?;
        assert_eq!(
            encoded(frame)?,
            b":server 403 requester #hidden :No such channel\r\n"
        );
        Ok(())
    }

    #[test]
    fn standard_reply_matrix_covers_every_closed_failure_class() -> Result<(), Box<dyn Error>> {
        let capabilities = standard_capabilities()?;
        for (request, error, code) in [
            (
                "MODE #chat +x",
                DomainError::InvalidArgument,
                "INVALID_ARGUMENT",
            ),
            (
                "MODE #chat +x",
                DomainError::DuplicateTarget,
                "INVALID_ARGUMENT",
            ),
            (
                "MODE #chat +x",
                DomainError::MixedAuthority,
                "INVALID_ARGUMENT",
            ),
            (
                "PRIVMSG #chat :hello",
                DomainError::ServerBusy,
                "SERVER_BUSY",
            ),
            (
                "PRIVMSG #chat :hello",
                DomainError::LimitExceeded,
                "SERVER_BUSY",
            ),
            (
                "PRIVMSG #chat :hello",
                DomainError::AllocationFailed,
                "SERVER_BUSY",
            ),
            ("PRIVMSG #chat :hello", DomainError::Overflow, "SERVER_BUSY"),
            (
                "PRIVMSG #chat :hello",
                DomainError::StaleGeneration,
                "SERVER_BUSY",
            ),
            (
                "PRIVMSG #chat :hello",
                DomainError::StaleRevision,
                "SERVER_BUSY",
            ),
            (
                "PRIVMSG #chat :hello",
                DomainError::WallClockUnavailable,
                "SERVER_BUSY",
            ),
            (
                "PRIVMSG #chat :hello",
                DomainError::RegistrationRequired,
                "REGISTRATION_REQUIRED",
            ),
            (
                "PRIVMSG #chat :hello",
                DomainError::UnsafeCtcp,
                "UNSAFE_CTCP",
            ),
            ("AUTHENTICATE +", DomainError::BadState, "BAD_STATE"),
            ("ACCT LOGOUT", DomainError::BadState, "BAD_STATE"),
            ("ACCTCREATE START 4726", DomainError::BadState, "BAD_STATE"),
            ("ACCTCRED START 4726", DomainError::BadState, "BAD_STATE"),
        ] {
            let bytes = encoded(failure_frame(
                &capabilities,
                "server",
                "requester",
                &parsed(request)?,
                error,
                None,
            )?)?;
            let text = std::str::from_utf8(&bytes)?;
            assert!(text.starts_with(":server FAIL "));
            assert!(text.contains(code));
        }

        for operation in ["JOIN", "MODE", "NAMES", "TOPIC"] {
            let request = parsed(&format!("{operation} #secret"))?;
            let bytes = encoded(failure_frame(
                &capabilities,
                "server",
                "requester",
                &request,
                DomainError::SecretUnavailable,
                None,
            )?)?;
            assert!(std::str::from_utf8(&bytes)?.contains("SECRET_UNAVAILABLE"));
        }

        for request in [
            "JOIN #encrypted",
            "JOIN invalid",
            "PRIVMSG #encrypted :hello",
        ] {
            let bytes = encoded(failure_frame(
                &capabilities,
                "server",
                "requester",
                &parsed(request)?,
                DomainError::EncryptedRoute,
                None,
            )?)?;
            assert!(std::str::from_utf8(&bytes)?.contains("E2EE_REQUIRED"));
        }

        for (request, error) in [
            ("NOTICE #secret :hello", DomainError::SecretUnavailable),
            ("PRIVMSG User :hello", DomainError::EncryptedRoute),
            ("NOTICE #encrypted :hello", DomainError::EncryptedRoute),
            ("NOTICE User :hello", DomainError::UnsafeCtcp),
            ("MODE #chat +x", DomainError::BadState),
        ] {
            let bytes = encoded(failure_frame(
                &capabilities,
                "server",
                "requester",
                &parsed(request)?,
                error,
                None,
            )?)?;
            assert!(std::str::from_utf8(&bytes)?.starts_with(":server 4"));
        }
        Ok(())
    }

    #[test]
    fn legacy_reply_matrix_uses_only_public_channel_and_user_targets() -> Result<(), Box<dyn Error>>
    {
        let channel =
            FailedTarget::Channel(agenc_ircd_domain::ChannelNameValue::parse("#explicit")?);
        let user = FailedTarget::User(agenc_ircd_domain::NicknameValue::parse("ExplicitUser")?);
        for (request, error, target, numeric, public_target) in [
            (
                "MODE #chat +x",
                DomainError::InvalidArgument,
                None,
                " 461 ",
                "MODE",
            ),
            (
                "JOIN #hidden",
                DomainError::NotFound,
                Some(&channel),
                " 403 ",
                "#explicit",
            ),
            (
                "PRIVMSG Missing,Other :hello",
                DomainError::NotFound,
                Some(&user),
                " 401 ",
                "ExplicitUser",
            ),
            (
                "MODE #hidden +m",
                DomainError::Forbidden,
                None,
                " 482 ",
                "#hidden",
            ),
            (
                "MODE #hidden +m",
                DomainError::BadState,
                None,
                " 482 ",
                "#hidden",
            ),
            (
                "PRIVMSG #hidden :hello",
                DomainError::UnsafeCtcp,
                None,
                " 404 ",
                "#hidden",
            ),
            (
                "PRIVMSG #hidden :hello",
                DomainError::EncryptedRoute,
                None,
                " 404 ",
                "#hidden",
            ),
            (
                "PRIVMSG #hidden :hello",
                DomainError::PlaintextRoute,
                None,
                " 404 ",
                "#hidden",
            ),
            (
                "PING token",
                DomainError::InvariantViolation,
                None,
                " 481 ",
                "requester",
            ),
            (
                "PRIVMSG Missing,Other :hello",
                DomainError::NotFound,
                None,
                " 401 ",
                "Missing",
            ),
        ] {
            let bytes = encoded(failure_frame(
                &CapabilityState::default(),
                "server",
                "requester",
                &parsed(request)?,
                error,
                target,
            )?)?;
            let text = std::str::from_utf8(&bytes)?;
            assert!(text.contains(numeric));
            assert!(text.contains(public_target));
        }
        Ok(())
    }
}
