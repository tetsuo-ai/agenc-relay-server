//! Registered command execution through the pure domain authorization and
//! mutation pipeline.
//!
//! The complete Appendix-A converter is built here incrementally. The first
//! live slice owns nickname changes and durable session removal so transport
//! shutdown cannot leave a logical session behind.

use agenc_ircd_client_wire::{
    CapabilityState, ParsedMessage, RegisteredCommandHandoff, RegisteredCommandKind, WireMessage,
};
use agenc_ircd_domain::{
    AdmissionSnapshot, AuthorizationFailure, AuthorizedCommand, CanonicalCommand,
    CanonicalCommandView, CommandEnvelope, DomainError, EntropyPurpose, ExternalInputRequest,
    ExternalInputs, PlanDecision, StorageClass,
};
use agenc_ircd_types::{
    AccountDeletionToken, BoundedUtf8, ChannelInstanceId, ControlPolicy, EntryId, InviteId,
    MessageId,
};

use crate::RuntimeError;
use crate::connection::sink::ConnectionGeneration;
use crate::state_core::fanout::{FanoutFrame, FanoutRequest};
use crate::state_core::inbox::CloseReason;
use crate::state_core::session::BoundSession;
use crate::state_core::{RouteOutcome, StageRefused, StagedOrigin, StateCoreContext};

enum LifecycleRender {
    Nick(String),
    Quit(String),
    Silent,
}

#[derive(Clone, Copy)]
struct RetryCommand<'a> {
    kind: RegisteredCommandKind,
    message: &'a ParsedMessage,
}

#[derive(Clone, Copy)]
struct ClientReply<'a> {
    generation: ConnectionGeneration,
    capabilities: &'a CapabilityState,
    request: RetryCommand<'a>,
}

impl<'a> ClientReply<'a> {
    const fn render_input(
        self,
        requester: agenc_ircd_types::UserId,
    ) -> crate::client_render::ReplyInput<'a> {
        crate::client_render::ReplyInput {
            requester,
            generation: self.generation,
            capabilities: self.capabilities,
            request: self.request.message,
        }
    }
}

enum AuthorizationError {
    Rejected(AuthorizationFailure),
    Internal(RuntimeError),
}

enum SessionCommandError {
    Public { error: DomainError, silent: bool },
    Internal(RuntimeError),
}

impl From<RuntimeError> for SessionCommandError {
    fn from(error: RuntimeError) -> Self {
        Self::Internal(error)
    }
}

/// Executes one registered handoff or renders its closed public failure.
pub(crate) fn route_registered(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    bound: Option<BoundSession>,
    capabilities: &CapabilityState,
    current_nickname: &mut Option<String>,
    handoff: RegisteredCommandHandoff,
) -> Result<RouteOutcome, RuntimeError> {
    let Some(bound) = bound else {
        return Ok(RouteOutcome::Close(CloseReason::ProtocolError));
    };
    let (kind, message) = handoff.into_parts();
    let request = RetryCommand {
        kind,
        message: &message,
    };
    let reply = ClientReply {
        generation,
        capabilities,
        request,
    };
    let command = match crate::command_convert::convert(context.domain(), kind, &message) {
        Ok(command) => command,
        Err(RuntimeError::InvalidValue | RuntimeError::LimitExceeded) => {
            crate::client_render::render_domain_failure(
                context,
                crate::client_render::ReplyInput {
                    requester: bound.user_id,
                    generation: reply.generation,
                    capabilities: reply.capabilities,
                    request: reply.request.message,
                },
                DomainError::InvalidArgument,
                false,
                None,
            )?;
            return Ok(RouteOutcome::Continue);
        }
        Err(error) => return Err(error),
    };
    let next_nickname = match command.view() {
        CanonicalCommandView::Nick(nickname) => Some(nickname.presentation().to_owned()),
        _ => None,
    };
    let render = next_nickname
        .as_ref()
        .map_or(LifecycleRender::Silent, |nickname| {
            LifecycleRender::Nick(nickname.clone())
        });
    let accepted = execute_session_command(context, bound, Some(reply), command, render)?;
    if accepted && let Some(nickname) = next_nickname {
        *current_nickname = Some(nickname);
    }
    Ok(RouteOutcome::Continue)
}

/// Stages removal of one registered domain session after its transport ends.
pub(crate) fn close_registered(context: &mut StateCoreContext, bound: BoundSession, reason: &str) {
    let reason = BoundedUtf8::try_from_str(reason, ControlPolicy::RejectAll).ok();
    let wire_reason = reason
        .as_ref()
        .map_or("connection closed", BoundedUtf8::as_str)
        .to_owned();
    let _result = execute_session_command(
        context,
        bound,
        None,
        CanonicalCommand::quit(reason),
        LifecycleRender::Quit(wire_reason),
    );
}

fn execute_session_command(
    context: &mut StateCoreContext,
    bound: BoundSession,
    reply: Option<ClientReply<'_>>,
    command: CanonicalCommand,
    render: LifecycleRender,
) -> Result<bool, RuntimeError> {
    let decision = match plan_session_command(context, bound, command, reply.map(|r| r.request)) {
        Ok(decision) => decision,
        Err(SessionCommandError::Public { error, silent }) => {
            let reply = reply.ok_or(RuntimeError::InvalidValue)?;
            crate::client_render::render_domain_failure(
                context,
                reply.render_input(bound.user_id),
                error,
                silent,
                None,
            )?;
            return Ok(false);
        }
        Err(SessionCommandError::Internal(error)) => return Err(error),
    };
    let PlanDecision::Mutation(plan) = decision else {
        return complete_nonmutation(context, bound, reply, decision);
    };
    let fanout = lifecycle_fanout(context, bound, &plan, render)?;
    match plan.storage_class() {
        StorageClass::Ephemeral => context
            .apply_ephemeral(plan, fanout)
            .map(|_| true)
            .map_err(|_| RuntimeError::InvalidValue),
        StorageClass::Durable => context
            .stage_durable(
                plan,
                fanout,
                reply.map(|reply| StagedOrigin {
                    generation: reply.generation,
                }),
                0,
            )
            .map(|_| true)
            .map_err(stage_error),
    }
}

fn complete_nonmutation(
    context: &mut StateCoreContext,
    bound: BoundSession,
    reply: Option<ClientReply<'_>>,
    decision: PlanDecision,
) -> Result<bool, RuntimeError> {
    match decision {
        PlanDecision::Query(plan) => {
            let reply = reply.ok_or(RuntimeError::InvalidValue)?;
            crate::query_render::render_query(context, reply.render_input(bound.user_id), &plan)?;
            Ok(true)
        }
        PlanDecision::Rejected(plan) => {
            if let Some(reply) = reply {
                crate::client_render::render_rejected(
                    context,
                    reply.render_input(bound.user_id),
                    &plan,
                )?;
            }
            Ok(false)
        }
        PlanDecision::Mutation(_) | PlanDecision::NeedsExternal(_) => {
            Err(RuntimeError::InvalidValue)
        }
    }
}

fn plan_session_command(
    context: &mut StateCoreContext,
    bound: BoundSession,
    command: CanonicalCommand,
    retry: Option<RetryCommand<'_>>,
) -> Result<PlanDecision, SessionCommandError> {
    let (authorized, admission) = admit_command(context, bound, command)?;
    let decision = context
        .domain()
        .plan_authorized(authorized, None)
        .map_err(domain_plan_error)?;
    let PlanDecision::NeedsExternal(requests) = decision else {
        return Ok(decision);
    };
    complete_external_plan(context, bound, retry, &admission, &requests)
}

fn admit_command(
    context: &mut StateCoreContext,
    bound: BoundSession,
    command: CanonicalCommand,
) -> Result<(AuthorizedCommand, AdmissionSnapshot), SessionCommandError> {
    let buckets: Vec<_> = context
        .domain()
        .command_charges(bound.user_id, &command)
        .into_iter()
        .map(|charge| charge.bucket())
        .collect();
    let now = context.now();
    let admission = context
        .buckets_mut()
        .domain_snapshot(now, &buckets)
        .map_err(|_| RuntimeError::InvalidValue)?;
    let authorized = authorize_command(context, bound, command, &admission);
    let charges = match &authorized {
        Ok(authorized) => authorized.charges(),
        Err(AuthorizationError::Rejected(failure)) => failure.charges(),
        Err(AuthorizationError::Internal(error)) => return Err((*error).into()),
    };
    context
        .buckets_mut()
        .apply_domain_charges(now, charges)
        .map_err(|_| RuntimeError::LimitExceeded)?;
    match authorized {
        Ok(authorized) => Ok((authorized, admission)),
        Err(AuthorizationError::Rejected(failure)) => Err(SessionCommandError::Public {
            error: failure.error(),
            silent: failure.is_silent(),
        }),
        Err(AuthorizationError::Internal(error)) => Err(error.into()),
    }
}

fn authorize_command(
    context: &StateCoreContext,
    bound: BoundSession,
    command: CanonicalCommand,
    admission: &AdmissionSnapshot,
) -> Result<AuthorizedCommand, AuthorizationError> {
    let session = context
        .domain()
        .session(bound.user_id)
        .ok_or(AuthorizationError::Internal(RuntimeError::InvalidValue))?;
    let envelope = CommandEnvelope::new(
        bound.session_id,
        bound.user_id,
        session.generation(),
        context.domain().revision(),
        command,
    );
    context
        .domain()
        .authorize(envelope, admission)
        .map_err(AuthorizationError::Rejected)
}

fn complete_external_plan(
    context: &mut StateCoreContext,
    bound: BoundSession,
    retry: Option<RetryCommand<'_>>,
    admission: &AdmissionSnapshot,
    requests: &[ExternalInputRequest],
) -> Result<PlanDecision, SessionCommandError> {
    let retry = retry.ok_or(RuntimeError::InvalidValue)?;
    let command = crate::command_convert::convert(context.domain(), retry.kind, retry.message)?;
    let authorized = match authorize_command(context, bound, command, admission) {
        Ok(authorized) => authorized,
        Err(AuthorizationError::Rejected(failure)) => {
            return Err(SessionCommandError::Public {
                error: failure.error(),
                silent: failure.is_silent(),
            });
        }
        Err(AuthorizationError::Internal(error)) => return Err(error.into()),
    };
    let external = satisfy_external(context, requests)?;
    context
        .domain()
        .plan_authorized(authorized, Some(external))
        .map_err(domain_plan_error)
}

fn domain_plan_error(error: DomainError) -> SessionCommandError {
    match error {
        DomainError::ExternalInputMismatch | DomainError::InvariantViolation => {
            SessionCommandError::Internal(RuntimeError::InvalidValue)
        }
        error => SessionCommandError::Public {
            error,
            silent: false,
        },
    }
}

fn lifecycle_fanout(
    context: &StateCoreContext,
    bound: BoundSession,
    plan: &agenc_ircd_domain::MutationPlan,
    render: LifecycleRender,
) -> Result<FanoutRequest, RuntimeError> {
    let session = context
        .domain()
        .session(bound.user_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let prefix = session_prefix(session)?;
    let message = match render {
        LifecycleRender::Nick(nickname) => {
            if !plan
                .events()
                .contains(&agenc_ircd_domain::DomainEvent::NicknameChanged(
                    bound.user_id,
                ))
            {
                return Err(RuntimeError::InvalidValue);
            }
            WireMessage::new(&prefix, "NICK", &[], Some(&nickname))
        }
        LifecycleRender::Quit(reason) => {
            if !plan
                .events()
                .contains(&agenc_ircd_domain::DomainEvent::SessionHidden(
                    bound.user_id,
                ))
            {
                return Err(RuntimeError::InvalidValue);
            }
            WireMessage::new(&prefix, "QUIT", &[], Some(&reason))
        }
        LifecycleRender::Silent => return FanoutRequest::new(Vec::new(), Vec::new()),
    }
    .map_err(|_| RuntimeError::InvalidValue)?;
    let targets = context.targets_for(plan.recipients().iter());
    if targets.is_empty() {
        return FanoutRequest::new(Vec::new(), Vec::new());
    }
    let recipients = (0..targets.len()).collect();
    FanoutRequest::new(targets, vec![FanoutFrame::new(message, recipients)?])
}

fn satisfy_external(
    context: &mut StateCoreContext,
    requests: &[ExternalInputRequest],
) -> Result<ExternalInputs, RuntimeError> {
    let mut inputs = ExternalInputs::default();
    for request in requests {
        satisfy_one(context, &mut inputs, *request)?;
    }
    Ok(inputs)
}

fn satisfy_one(
    context: &mut StateCoreContext,
    inputs: &mut ExternalInputs,
    request: ExternalInputRequest,
) -> Result<(), RuntimeError> {
    match request {
        ExternalInputRequest::UtcNow { .. } => {
            inputs.utc_now = Some(context.utc_now().map_err(|_| RuntimeError::InvalidValue)?);
        }
        ExternalInputRequest::MonotonicNow { .. } => inputs.monotonic_now = Some(context.now()),
        ExternalInputRequest::ChannelKeyVerification { .. } => {
            reserve_one(&mut inputs.key_verdicts)?;
            inputs.key_verdicts.push(false);
        }
        ExternalInputRequest::Entropy { purpose, bytes, .. } => {
            if bytes != 16 {
                return Err(RuntimeError::InvalidValue);
            }
            let mut random = [0_u8; 16];
            context
                .entropy_mut()
                .fill_exact(&mut random)
                .map_err(|_| RuntimeError::InvalidValue)?;
            push_entropy(inputs, purpose, random)?;
        }
    }
    Ok(())
}

fn push_entropy(
    inputs: &mut ExternalInputs,
    purpose: EntropyPurpose,
    random: [u8; 16],
) -> Result<(), RuntimeError> {
    match purpose {
        EntropyPurpose::ChannelInstance(_) => {
            reserve_one(&mut inputs.channel_ids)?;
            inputs
                .channel_ids
                .push(ChannelInstanceId::from_bytes(random));
        }
        EntropyPurpose::Message(_) => {
            reserve_one(&mut inputs.message_ids)?;
            inputs.message_ids.push(MessageId::from_bytes(random));
        }
        EntropyPurpose::Invite => {
            reserve_one(&mut inputs.invite_ids)?;
            inputs.invite_ids.push(InviteId::from_bytes(random));
        }
        EntropyPurpose::MaskEntry(_) => {
            reserve_one(&mut inputs.entry_ids)?;
            inputs.entry_ids.push(EntryId::from_bytes(random));
        }
        EntropyPurpose::AccountDeletionChallenge => {
            reserve_one(&mut inputs.deletion_tokens)?;
            inputs
                .deletion_tokens
                .push(AccountDeletionToken::from_bytes(random));
        }
    }
    Ok(())
}

fn reserve_one<T>(values: &mut Vec<T>) -> Result<(), RuntimeError> {
    values
        .try_reserve(1)
        .map_err(|_| RuntimeError::MemoryExhausted)
}

fn session_prefix(session: &agenc_ircd_domain::SessionState) -> Result<String, RuntimeError> {
    let cloak = session.public_cloak();
    let user =
        std::str::from_utf8(cloak.user_component()).map_err(|_| RuntimeError::InvalidValue)?;
    let host =
        std::str::from_utf8(cloak.host_component()).map_err(|_| RuntimeError::InvalidValue)?;
    Ok(format!(
        "{}!{}@{}",
        session.nickname().presentation(),
        user,
        host
    ))
}

fn stage_error(error: StageRefused) -> RuntimeError {
    match error {
        StageRefused::Fanout(_) => RuntimeError::MemoryExhausted,
        StageRefused::Busy | StageRefused::Quiescing => RuntimeError::LimitExceeded,
        StageRefused::Domain(_) => RuntimeError::InvalidValue,
    }
}
