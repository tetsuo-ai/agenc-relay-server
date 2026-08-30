//! Registered command execution through the pure domain authorization and
//! mutation pipeline.
//!
//! The complete Appendix-A converter is built here incrementally. The first
//! live slice owns nickname changes and durable session removal so transport
//! shutdown cannot leave a logical session behind.

use agenc_ircd_client_wire::{
    RegisteredCommandHandoff, RegisteredCommandKind, WireMessage, numeric_reply,
};
use agenc_ircd_domain::{
    AdmissionSnapshot, CanonicalCommand, CanonicalCommandView, CommandEnvelope, NicknameValue,
    PlanDecision, RateBucket, StorageClass,
};
use agenc_ircd_types::{BoundedUtf8, ControlPolicy};

use crate::RuntimeError;
use crate::connection::sink::ConnectionGeneration;
use crate::state_core::fanout::{FanoutFrame, FanoutRequest};
use crate::state_core::inbox::CloseReason;
use crate::state_core::session::BoundSession;
use crate::state_core::{RouteOutcome, StageRefused, StagedOrigin, StateCoreContext};

enum LifecycleRender {
    Nick(String),
    Quit(String),
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
    let command = match kind {
        RegisteredCommandKind::Nickname => {
            let nickname = single_parameter(&message).ok_or(RuntimeError::InvalidValue)?;
            CanonicalCommand::nick(
                NicknameValue::parse(nickname).map_err(|_| RuntimeError::InvalidValue)?,
            )
        }
        RegisteredCommandKind::Public(_) => {
            render_unknown(
                context,
                generation,
                current_nickname.as_deref(),
                message.command(),
            )?;
            return Ok(RouteOutcome::Continue);
        }
    };
    let next_nickname = match command.view() {
        CanonicalCommandView::Nick(nickname) => nickname.presentation().to_owned(),
        _ => return Err(RuntimeError::InvalidValue),
    };
    execute_session_command(
        context,
        bound,
        Some(generation),
        command,
        LifecycleRender::Nick(next_nickname.clone()),
    )?;
    *current_nickname = Some(next_nickname);
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
    origin: Option<ConnectionGeneration>,
    command: CanonicalCommand,
    render: LifecycleRender,
) -> Result<(), RuntimeError> {
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
    let now = context.now();
    let bucket = RateBucket::RegisteredCommand(bound.user_id);
    let admission: AdmissionSnapshot = context
        .buckets_mut()
        .domain_snapshot(now, &[bucket])
        .map_err(|_| RuntimeError::InvalidValue)?;
    let authorized = context
        .domain()
        .authorize(envelope, &admission)
        .map_err(|_| RuntimeError::InvalidValue)?;
    context
        .buckets_mut()
        .apply_domain_charges(now, authorized.charges())
        .map_err(|_| RuntimeError::LimitExceeded)?;
    let decision = context
        .domain()
        .plan_authorized(authorized, None)
        .map_err(|_| RuntimeError::InvalidValue)?;
    let PlanDecision::Mutation(plan) = decision else {
        return Err(RuntimeError::InvalidValue);
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
    }
    .map_err(|_| RuntimeError::InvalidValue)?;
    let targets = context.targets_for(plan.recipients().iter());
    if targets.is_empty() {
        return FanoutRequest::new(Vec::new(), Vec::new());
    }
    let recipients = (0..targets.len()).collect();
    FanoutRequest::new(targets, vec![FanoutFrame::new(message, recipients)?])
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

fn single_parameter(message: &agenc_ircd_client_wire::ParsedMessage) -> Option<&str> {
    match (message.middle(), message.trailing()) {
        ([only], None) => Some(only),
        ([], Some(only)) => Some(only),
        _ => None,
    }
}

fn stage_error(error: StageRefused) -> RuntimeError {
    match error {
        StageRefused::Fanout(_) => RuntimeError::MemoryExhausted,
        StageRefused::Busy | StageRefused::Quiescing => RuntimeError::LimitExceeded,
        StageRefused::Domain(_) => RuntimeError::InvalidValue,
    }
}
