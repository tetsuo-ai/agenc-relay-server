//! Registered command execution through the pure domain authorization and
//! mutation pipeline.
//!
//! The complete Appendix-A converter is built here incrementally. The first
//! live slice owns nickname changes and durable session removal so transport
//! shutdown cannot leave a logical session behind.

use agenc_ircd_client_wire::{
    ParsedMessage, RegisteredCommandHandoff, RegisteredCommandKind, WireMessage, numeric_reply,
};
use agenc_ircd_domain::{
    AdmissionSnapshot, AuthorizedCommand, CanonicalCommand, CanonicalCommandView, CommandEnvelope,
    EntropyPurpose, ExternalInputRequest, ExternalInputs, PlanDecision, QueryPlan, StorageClass,
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

/// Executes one registered handoff or renders its closed public failure.
pub(crate) fn route_registered(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    bound: Option<BoundSession>,
    current_nickname: &mut Option<String>,
    handoff: RegisteredCommandHandoff,
) -> Result<RouteOutcome, RuntimeError> {
    let Some(bound) = bound else {
        return Ok(RouteOutcome::Close(CloseReason::ProtocolError));
    };
    let (kind, message) = handoff.into_parts();
    let command = crate::command_convert::convert(context.domain(), kind, &message)?;
    let next_nickname = match command.view() {
        CanonicalCommandView::Nick(nickname) => Some(nickname.presentation().to_owned()),
        _ => None,
    };
    let render = next_nickname
        .as_ref()
        .map_or(LifecycleRender::Silent, |nickname| {
            LifecycleRender::Nick(nickname.clone())
        });
    execute_session_command(
        context,
        bound,
        Some(generation),
        command,
        render,
        Some(RetryCommand {
            kind,
            message: &message,
        }),
    )?;
    if let Some(nickname) = next_nickname {
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
        None,
    );
}

fn execute_session_command(
    context: &mut StateCoreContext,
    bound: BoundSession,
    origin: Option<ConnectionGeneration>,
    command: CanonicalCommand,
    render: LifecycleRender,
    retry: Option<RetryCommand<'_>>,
) -> Result<(), RuntimeError> {
    let decision = plan_session_command(context, bound, command, retry)?;
    let plan = match decision {
        PlanDecision::Mutation(plan) => plan,
        PlanDecision::Query(plan) => {
            render_query(context, origin, &plan)?;
            return Ok(());
        }
        PlanDecision::Rejected(plan) => {
            if !plan.is_silent()
                && let Some(generation) = origin
            {
                render_unknown(context, generation, None, "*")?;
            }
            return Ok(());
        }
        PlanDecision::NeedsExternal(_) => return Err(RuntimeError::InvalidValue),
    };
    let fanout = lifecycle_fanout(context, bound, &plan, render)?;
    match plan.storage_class() {
        StorageClass::Ephemeral => context
            .apply_ephemeral(plan, fanout)
            .map(|_| ())
            .map_err(|_| RuntimeError::InvalidValue),
        StorageClass::Durable => context
            .stage_durable(
                plan,
                fanout,
                origin.map(|generation| StagedOrigin { generation }),
                0,
            )
            .map(|_| ())
            .map_err(stage_error),
    }
}

fn plan_session_command(
    context: &mut StateCoreContext,
    bound: BoundSession,
    command: CanonicalCommand,
    retry: Option<RetryCommand<'_>>,
) -> Result<PlanDecision, RuntimeError> {
    let (authorized, admission) = admit_command(context, bound, command)?;
    let decision = context
        .domain()
        .plan_authorized(authorized, None)
        .map_err(|_| RuntimeError::InvalidValue)?;
    let PlanDecision::NeedsExternal(requests) = decision else {
        return Ok(decision);
    };
    complete_external_plan(context, bound, retry, &admission, &requests)
}

fn admit_command(
    context: &mut StateCoreContext,
    bound: BoundSession,
    command: CanonicalCommand,
) -> Result<(AuthorizedCommand, AdmissionSnapshot), RuntimeError> {
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
    let authorized = authorize_command(context, bound, command, &admission)?;
    context
        .buckets_mut()
        .apply_domain_charges(now, authorized.charges())
        .map_err(|_| RuntimeError::LimitExceeded)?;
    Ok((authorized, admission))
}

fn authorize_command(
    context: &StateCoreContext,
    bound: BoundSession,
    command: CanonicalCommand,
    admission: &AdmissionSnapshot,
) -> Result<AuthorizedCommand, RuntimeError> {
    let session = context
        .domain()
        .session(bound.user_id)
        .ok_or(RuntimeError::InvalidValue)?;
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
        .map_err(|_| RuntimeError::InvalidValue)
}

fn complete_external_plan(
    context: &mut StateCoreContext,
    bound: BoundSession,
    retry: Option<RetryCommand<'_>>,
    admission: &AdmissionSnapshot,
    requests: &[ExternalInputRequest],
) -> Result<PlanDecision, RuntimeError> {
    let retry = retry.ok_or(RuntimeError::InvalidValue)?;
    let command = crate::command_convert::convert(context.domain(), retry.kind, retry.message)?;
    let authorized = authorize_command(context, bound, command, admission)?;
    let external = satisfy_external(context, requests)?;
    context
        .domain()
        .plan_authorized(authorized, Some(external))
        .map_err(|_| RuntimeError::InvalidValue)
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

fn render_query(
    context: &mut StateCoreContext,
    origin: Option<ConnectionGeneration>,
    plan: &QueryPlan,
) -> Result<(), RuntimeError> {
    let generation = origin.ok_or(RuntimeError::InvalidValue)?;
    let target = context
        .domain()
        .session(plan.requester())
        .map(|session| session.nickname().presentation())
        .unwrap_or("*");
    let frame = match plan.command().view() {
        CanonicalCommandView::Information(agenc_ircd_domain::InformationQuery::Motd) => {
            numeric_reply(
                context.server_prefix(),
                422,
                target,
                &[],
                Some("MOTD File is missing"),
            )
        }
        CanonicalCommandView::Information(agenc_ircd_domain::InformationQuery::Lusers) => {
            numeric_reply(
                context.server_prefix(),
                251,
                target,
                &[],
                Some("There are users on this server"),
            )
        }
        CanonicalCommandView::Information(agenc_ircd_domain::InformationQuery::Version) => {
            numeric_reply(
                context.server_prefix(),
                351,
                target,
                &["agenc-ircd"],
                Some("AgenC"),
            )
        }
        _ => numeric_reply(
            context.server_prefix(),
            421,
            target,
            &["QUERY"],
            Some("Unknown command"),
        ),
    }
    .map_err(|_| RuntimeError::InvalidValue)?;
    context
        .send_to(generation, vec![frame])
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    Ok(())
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

fn render_unknown(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    nickname: Option<&str>,
    command: &str,
) -> Result<(), RuntimeError> {
    let frame = numeric_reply(
        context.server_prefix(),
        421,
        nickname.unwrap_or("*"),
        &[command],
        Some("Unknown command"),
    )
    .map_err(|_| RuntimeError::InvalidValue)?;
    context
        .send_to(generation, vec![frame])
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    Ok(())
}

fn stage_error(error: StageRefused) -> RuntimeError {
    match error {
        StageRefused::Fanout(_) => RuntimeError::MemoryExhausted,
        StageRefused::Busy | StageRefused::Quiescing => RuntimeError::LimitExceeded,
        StageRefused::Domain(_) => RuntimeError::InvalidValue,
    }
}
