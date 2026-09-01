//! Registered command execution through the pure domain authorization and
//! mutation pipeline.
//!
//! This executor owns the complete registered-command path: admission,
//! authorization, external inputs, bounded channel-key crypto continuations,
//! commit-coupled rendering, and transport-safe session removal.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use agenc_ircd_client_wire::{
    CapabilityState, ParsedMessage, RegisteredCommandHandoff, RegisteredCommandKind,
};
use agenc_ircd_domain::{
    AdmissionSnapshot, AuthorizationFailure, AuthorizedCommand, CanonicalCommand,
    CanonicalCommandView, CommandEnvelope, DomainError, DomainEvent, EntropyPurpose,
    ExternalInputRequest, ExternalInputs, MessageKind, MutationPlan, PlanDecision, StorageClass,
};
use agenc_ircd_types::{
    AccountDeletionToken, AccountId, BoundedUtf8, ChannelInstanceId, ControlPolicy, EntryId,
    InviteId, MessageId,
};
use zeroize::Zeroizing;

use crate::RuntimeError;
use crate::account_service::AccountServiceCoordinator;
use crate::admission::{BucketDemand, BucketKey, BucketKind, domain_bucket};
use crate::bridge::crypto::{
    ChannelKeyConstructJob, ChannelKeyTarget, ChannelKeyVerifier, ChannelKeyVerifierRecord,
    CryptoJobOutput, RuntimeCryptoJob,
};
use crate::bridge::{CryptoCompletionMessage, CryptoJobId};
use crate::connection::sink::ConnectionGeneration;
use crate::observe::metrics::ResultClass;
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::CloseReason;
use crate::state_core::session::BoundSession;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use crate::state_core::{
    CommandObservation, RouteOutcome, StageRefused, StagedOrigin, StateCoreContext,
};
use crate::sync::Arc;

const COMMAND_DEADLINE_MILLIS: u64 = 30_000;

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

struct SessionCommandInput<'a> {
    reply: Option<ClientReply<'a>>,
    command: CanonicalCommand,
    close_reason: Option<&'a str>,
    metered: bool,
}

#[derive(Clone, Copy)]
struct DeferredOrigin<'a> {
    generation: ConnectionGeneration,
    bound: BoundSession,
    kind: RegisteredCommandKind,
    capabilities: &'a CapabilityState,
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

// agenc-review: allow owner=runtime reviewed=2026-08-29 reason=the hot ready path keeps its bounded plan inline while only the cold deferred crypto path allocates
#[allow(clippy::large_enum_variant)]
enum PlannedCommand {
    Ready(PlanDecision),
    Crypto(Box<DeferredPlan>),
}

struct DeferredPlan {
    authorized: AuthorizedCommand,
    external: ExternalInputs,
    requests: Vec<ExternalInputRequest>,
    render_command: CanonicalCommand,
}

enum CommandExecution {
    Complete(ResultClass),
    Crypto(Box<DeferredPlan>),
}

enum ConvertedCommand {
    Ready(CanonicalCommand),
    Rejected(ResultClass),
}

enum PreparedCryptoJob {
    Verify(crate::bridge::crypto::ChannelKeyVerifyJob),
    Construct(ChannelKeyConstructJob),
}

impl PreparedCryptoJob {
    const fn kind(&self) -> PendingCryptoKind {
        match self {
            Self::Verify(_) => PendingCryptoKind::Verify,
            Self::Construct(_) => PendingCryptoKind::Construct,
        }
    }

    fn into_runtime(self) -> RuntimeCryptoJob {
        match self {
            Self::Verify(job) => RuntimeCryptoJob::ChannelKeyVerify(job),
            Self::Construct(job) => RuntimeCryptoJob::ChannelKeyConstruct(job),
        }
    }
}

#[derive(Clone, Copy)]
enum PendingCryptoKind {
    Verify,
    Construct,
}

enum CryptoCompletionError {
    Busy,
    Internal(RuntimeError),
}

struct PendingCryptoCommand {
    sequence: u64,
    generation: ConnectionGeneration,
    bound: BoundSession,
    kind: RegisteredCommandKind,
    capabilities: CapabilityState,
    message: ParsedMessage,
    authorized: AuthorizedCommand,
    external: ExternalInputs,
    render_command: CanonicalCommand,
    current: PendingCryptoKind,
    remaining: VecDeque<PreparedCryptoJob>,
    observation: CommandObservation,
}

/// Bounded registered-command crypto continuations owned by StateCore's
/// router. The actual worker bridge remains in [`StateCoreContext`].
pub struct RegisteredCommandExecutor {
    verifier: Arc<dyn ChannelKeyVerifier>,
    dummy: ChannelKeyVerifierRecord,
    pending: BTreeMap<CryptoJobId, PendingCryptoCommand>,
    by_connection: BTreeMap<ConnectionGeneration, CryptoJobId>,
    by_sequence: BTreeMap<u64, CryptoJobId>,
    next_sequence: u64,
}

impl RegisteredCommandExecutor {
    /// Creates an empty continuation owner around the reviewed Argon2 adapter
    /// and process-local dummy verifier.
    #[must_use]
    pub fn new(verifier: Arc<dyn ChannelKeyVerifier>, dummy: ChannelKeyVerifierRecord) -> Self {
        Self {
            verifier,
            dummy,
            pending: BTreeMap::new(),
            by_connection: BTreeMap::new(),
            by_sequence: BTreeMap::new(),
            next_sequence: 1,
        }
    }

    /// Returns whether no deferred registered command spans a reload.
    pub(crate) fn reload_ready(&self) -> bool {
        self.pending.is_empty() && self.by_connection.is_empty() && self.by_sequence.is_empty()
    }
}

impl RegisteredCommandExecutor {
    // agenc-review: focus owner=runtime reviewed=2026-09-01 reason=one crypto deferral transaction validates ownership prepares bounded jobs installs every continuation index and accounts final command outcome
    fn defer(
        &mut self,
        context: &mut StateCoreContext,
        origin: DeferredOrigin<'_>,
        mut message: ParsedMessage,
        plan: Box<DeferredPlan>,
        observation: CommandObservation,
    ) -> Result<(), RuntimeError> {
        if self.by_connection.contains_key(&origin.generation) {
            let rendered = render_busy(
                context,
                origin.bound,
                origin.generation,
                origin.capabilities,
                &message,
            );
            context.complete_command_observation(
                observation,
                if rendered.is_ok() {
                    ResultClass::Busy
                } else {
                    ResultClass::Error
                },
            );
            return rendered;
        }
        let prepared = (|| {
            let mut jobs = prepare_crypto_jobs(
                context,
                origin.bound,
                &mut message,
                &plan.render_command,
                &plan.requests,
                &self.verifier,
                self.dummy,
            )?;
            let first = jobs.pop_front().ok_or(RuntimeError::InvalidValue)?;
            let sequence = self.next_sequence;
            let next_sequence = sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
            let capabilities = origin
                .capabilities
                .try_clone()
                .map_err(|_| RuntimeError::MemoryExhausted)?;
            let deadline = context
                .now()
                .checked_add(COMMAND_DEADLINE_MILLIS)
                .map_err(|_| RuntimeError::Overflow)?;
            context.timers_mut().schedule(
                deadline,
                TimerKind::CommandDeadline,
                TimedId::Sequence(sequence),
            )?;
            Ok((jobs, first, sequence, next_sequence, capabilities))
        })();
        let (jobs, first, sequence, next_sequence, capabilities) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                context.complete_command_observation(observation, ResultClass::Error);
                return Err(error);
            }
        };
        self.next_sequence = next_sequence;
        let DeferredPlan {
            authorized,
            external,
            render_command,
            ..
        } = *plan;
        let pending = PendingCryptoCommand {
            sequence,
            generation: origin.generation,
            bound: origin.bound,
            kind: origin.kind,
            capabilities,
            message,
            authorized,
            external,
            render_command,
            current: first.kind(),
            remaining: jobs,
            observation,
        };
        self.submit(context, pending, first)
    }

    fn submit(
        &mut self,
        context: &mut StateCoreContext,
        pending: PendingCryptoCommand,
        job: PreparedCryptoJob,
    ) -> Result<(), RuntimeError> {
        let generation = pending.generation;
        let sequence = pending.sequence;
        let submitted = context.crypto_mut().try_submit(job.into_runtime());
        let job_id = match submitted {
            Ok(job_id) => job_id,
            Err(_refused) => {
                cancel_command_timer(context, sequence);
                let rendered = render_pending_busy(context, &pending);
                context.complete_command_observation(
                    pending.observation,
                    if rendered.is_ok() {
                        ResultClass::Busy
                    } else {
                        ResultClass::Error
                    },
                );
                return rendered;
            }
        };
        if self.pending.contains_key(&job_id)
            || self.by_connection.contains_key(&generation)
            || self.by_sequence.contains_key(&sequence)
        {
            let _cancelled = context.crypto_mut().cancel(job_id);
            cancel_command_timer(context, sequence);
            context.complete_command_observation(pending.observation, ResultClass::Error);
            return Err(RuntimeError::InvalidValue);
        }
        self.by_connection.insert(generation, job_id);
        self.by_sequence.insert(sequence, job_id);
        self.pending.insert(job_id, pending);
        Ok(())
    }

    /// Resumes one matching deferred command; unrelated job IDs are ignored
    /// for the account-service dispatcher.
    pub(crate) fn crypto_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: CryptoCompletionMessage<CryptoJobOutput>,
    ) -> Result<(), (ConnectionGeneration, RuntimeError)> {
        let Some(mut pending) = self.take_pending(message.job_id) else {
            return Ok(());
        };
        let generation = pending.generation;
        match apply_crypto_output(pending.current, &mut pending.external, message.output) {
            Ok(()) => {}
            Err(CryptoCompletionError::Busy) => {
                cancel_command_timer(context, pending.sequence);
                let rendered = render_pending_busy(context, &pending);
                context.complete_command_observation(
                    pending.observation,
                    if rendered.is_ok() {
                        ResultClass::Busy
                    } else {
                        ResultClass::Error
                    },
                );
                return rendered.map_err(|error| (generation, error));
            }
            Err(CryptoCompletionError::Internal(error)) => {
                cancel_command_timer(context, pending.sequence);
                context.complete_command_observation(pending.observation, ResultClass::Error);
                return Err((generation, error));
            }
        }
        if let Some(next) = pending.remaining.pop_front() {
            pending.current = next.kind();
            return self
                .submit(context, pending, next)
                .map_err(|error| (generation, error));
        }
        cancel_command_timer(context, pending.sequence);
        finish_pending(context, pending).map_err(|error| (generation, error))
    }

    /// Drops one disconnected connection's side-effect-free continuation.
    pub(crate) fn connection_closed(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        let Some(job_id) = self.by_connection.get(&generation).copied() else {
            return;
        };
        if let Some(pending) = self.take_pending(job_id) {
            let _cancelled = context.crypto_mut().cancel(job_id);
            cancel_command_timer(context, pending.sequence);
            context.complete_command_observation(pending.observation, ResultClass::Closed);
        }
    }

    /// Applies the fixed pre-commit deadline to one deferred command.
    pub(crate) fn timer_fired(
        &mut self,
        context: &mut StateCoreContext,
        entry: TimerEntry,
    ) -> Result<bool, (ConnectionGeneration, RuntimeError)> {
        let TimedId::Sequence(sequence) = entry.id else {
            return Ok(false);
        };
        if entry.kind != TimerKind::CommandDeadline {
            return Ok(false);
        }
        let Some(job_id) = self.by_sequence.get(&sequence).copied() else {
            return Ok(true);
        };
        let Some(pending) = self.take_pending(job_id) else {
            return Ok(true);
        };
        let _cancelled = context.crypto_mut().cancel(job_id);
        let generation = pending.generation;
        let rendered = render_pending_busy(context, &pending);
        context.complete_command_observation(
            pending.observation,
            if rendered.is_ok() {
                ResultClass::Busy
            } else {
                ResultClass::Error
            },
        );
        rendered.map(|()| true).map_err(|error| (generation, error))
    }

    fn take_pending(&mut self, job_id: CryptoJobId) -> Option<PendingCryptoCommand> {
        let pending = self.pending.remove(&job_id)?;
        self.by_connection.remove(&pending.generation);
        self.by_sequence.remove(&pending.sequence);
        Some(pending)
    }
}

impl From<RuntimeError> for SessionCommandError {
    fn from(error: RuntimeError) -> Self {
        Self::Internal(error)
    }
}

impl RegisteredCommandExecutor {
    /// Executes one registered handoff or owns its deferred crypto continuation.
    // agenc-review: focus owner=runtime reviewed=2026-09-01 reason=registered routing retains one command observation through synchronous crypto and durable completion without copying input data
    // agenc-review: allow owner=runtime reviewed=2026-08-30 reason=registered routing binds the account deletion coordinator connection session capabilities nickname and owned handoff at one entry boundary
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn route_registered(
        &mut self,
        context: &mut StateCoreContext,
        accounts: &mut AccountServiceCoordinator,
        generation: ConnectionGeneration,
        bound: Option<BoundSession>,
        capabilities: &CapabilityState,
        current_nickname: &mut Option<String>,
        handoff: RegisteredCommandHandoff,
        observation: CommandObservation,
    ) -> Result<RouteOutcome, RuntimeError> {
        let Some(bound) = bound else {
            context.complete_command_observation(observation, ResultClass::Rejected);
            return Ok(RouteOutcome::Close(CloseReason::ProtocolError));
        };
        let mut observation = Some(observation);
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
        let command = match convert_registered_command(context, bound, reply, kind, &message) {
            Ok(ConvertedCommand::Ready(command)) => command,
            Ok(ConvertedCommand::Rejected(result)) => {
                complete_observation(context, &mut observation, result);
                return Ok(RouteOutcome::Continue);
            }
            Err(error) => {
                complete_observation(context, &mut observation, ResultClass::Error);
                return Err(error);
            }
        };
        let next_nickname = match command.view() {
            CanonicalCommandView::Nick(nickname) => Some(nickname.presentation().to_owned()),
            _ => None,
        };
        match execute_session_command(
            context,
            Some(accounts),
            bound,
            SessionCommandInput {
                reply: Some(reply),
                command,
                close_reason: None,
                metered: true,
            },
            &mut observation,
        ) {
            Ok(CommandExecution::Complete(result)) => {
                complete_observation(context, &mut observation, result);
                if result == ResultClass::Ok
                    && let Some(nickname) = next_nickname
                {
                    *current_nickname = Some(nickname);
                }
            }
            Ok(CommandExecution::Crypto(plan)) => {
                let Some(observation) = observation.take() else {
                    return Err(RuntimeError::InvalidValue);
                };
                self.defer(
                    context,
                    DeferredOrigin {
                        generation,
                        bound,
                        kind,
                        capabilities,
                    },
                    message,
                    plan,
                    observation,
                )?;
            }
            Err(error) => {
                complete_observation(context, &mut observation, ResultClass::Error);
                return Err(error);
            }
        }
        Ok(RouteOutcome::Continue)
    }
}

fn convert_registered_command(
    context: &mut StateCoreContext,
    bound: BoundSession,
    reply: ClientReply<'_>,
    kind: RegisteredCommandKind,
    message: &ParsedMessage,
) -> Result<ConvertedCommand, RuntimeError> {
    match crate::command_convert::convert(context.domain(), kind, message) {
        Ok(command) => Ok(ConvertedCommand::Ready(command)),
        Err(RuntimeError::InvalidValue | RuntimeError::LimitExceeded) => {
            let (error, silent, result) =
                if charge_registered_command_only(context, bound.user_id).is_ok() {
                    (DomainError::InvalidArgument, false, ResultClass::Rejected)
                } else {
                    (
                        DomainError::ServerBusy,
                        message.command() == "NOTICE",
                        ResultClass::Busy,
                    )
                };
            crate::client_render::render_domain_failure(
                context,
                reply.render_input(bound.user_id),
                error,
                silent,
                None,
            )?;
            Ok(ConvertedCommand::Rejected(result))
        }
        Err(error) => Err(error),
    }
}

fn prepare_crypto_jobs(
    context: &mut StateCoreContext,
    bound: BoundSession,
    message: &mut ParsedMessage,
    command: &CanonicalCommand,
    requests: &[ExternalInputRequest],
    verifier: &Arc<dyn ChannelKeyVerifier>,
    dummy: ChannelKeyVerifierRecord,
) -> Result<VecDeque<PreparedCryptoJob>, RuntimeError> {
    match command.view() {
        CanonicalCommandView::Join(targets) => {
            prepare_join_key_jobs(context, bound, message, targets, requests, verifier, dummy)
        }
        CanonicalCommandView::Mode(agenc_ircd_domain::ModeCommand::ChannelChange(_, _)) => {
            prepare_mode_key_jobs(context, message, requests, verifier)
        }
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn prepare_join_key_jobs(
    context: &StateCoreContext,
    bound: BoundSession,
    message: &mut ParsedMessage,
    targets: &[agenc_ircd_domain::ChannelTarget],
    requests: &[ExternalInputRequest],
    verifier: &Arc<dyn ChannelKeyVerifier>,
    dummy: ChannelKeyVerifierRecord,
) -> Result<VecDeque<PreparedCryptoJob>, RuntimeError> {
    let raw_keys = message
        .take_parameter(1)
        .ok_or(RuntimeError::InvalidValue)?;
    let raw_keys = Zeroizing::new(raw_keys);
    let mut jobs = VecDeque::new();
    jobs.try_reserve_exact(requests.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for request in requests {
        let ExternalInputRequest::ChannelKeyVerification { target_index, .. } = request else {
            return Err(RuntimeError::InvalidValue);
        };
        let target = targets
            .get(usize::from(*target_index))
            .ok_or(RuntimeError::InvalidValue)?;
        let candidate = raw_keys
            .split(',')
            .nth(usize::from(*target_index))
            .filter(|candidate| !candidate.is_empty())
            .ok_or(RuntimeError::InvalidValue)?;
        let candidate = copy_secret(candidate.as_bytes())?;
        let key_target = channel_key_target(context, bound, target, dummy);
        let job = crate::bridge::crypto::ChannelKeyVerifyJob::new(
            Arc::clone(verifier),
            key_target,
            candidate,
        )?;
        jobs.push_back(PreparedCryptoJob::Verify(job));
    }
    Ok(jobs)
}

fn prepare_mode_key_jobs(
    context: &mut StateCoreContext,
    message: &mut ParsedMessage,
    requests: &[ExternalInputRequest],
    verifier: &Arc<dyn ChannelKeyVerifier>,
) -> Result<VecDeque<PreparedCryptoJob>, RuntimeError> {
    let positions = crate::command_convert::channel_key_parameter_positions(message)?;
    let mut jobs = VecDeque::new();
    jobs.try_reserve_exact(requests.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for request in requests {
        let ExternalInputRequest::ChannelKeyConstruction { change_index, .. } = request else {
            return Err(RuntimeError::InvalidValue);
        };
        let parameter_index = positions
            .iter()
            .find_map(|(index, parameter)| (index == change_index).then_some(*parameter))
            .ok_or(RuntimeError::InvalidValue)?;
        let candidate = message
            .take_parameter(parameter_index)
            .ok_or(RuntimeError::InvalidValue)?;
        let candidate = Zeroizing::new(candidate);
        let mut salt = [0_u8; crate::bridge::crypto::CHANNEL_KEY_SALT_BYTES];
        context
            .entropy_mut()
            .fill_exact(&mut salt)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let job = ChannelKeyConstructJob::new(
            Arc::clone(verifier),
            salt,
            copy_secret(candidate.as_bytes())?,
        )?;
        jobs.push_back(PreparedCryptoJob::Construct(job));
    }
    Ok(jobs)
}

fn channel_key_target(
    context: &StateCoreContext,
    bound: BoundSession,
    target: &agenc_ircd_domain::ChannelTarget,
    dummy: ChannelKeyVerifierRecord,
) -> ChannelKeyTarget {
    let stored = context
        .domain()
        .resolve_channel(target.name())
        .and_then(|channel_id| context.domain().channel(channel_id))
        .filter(|channel| channel_key_route_available(context, bound, channel))
        .and_then(agenc_ircd_domain::ChannelState::key_verifier)
        .copied();
    stored.map_or(ChannelKeyTarget::Dummy(dummy), ChannelKeyTarget::Stored)
}

fn channel_key_route_available(
    context: &StateCoreContext,
    bound: BoundSession,
    channel: &agenc_ircd_domain::ChannelState,
) -> bool {
    context
        .domain()
        .session(bound.user_id)
        .is_some_and(|session| {
            session.account_id().is_some()
                || (channel.visibility() == agenc_ircd_domain::Visibility::Listed
                    && channel.content_policy() == agenc_ircd_domain::ContentPolicy::Plaintext)
        })
}

fn copy_secret(value: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    copied.extend_from_slice(value);
    Ok(copied)
}

fn apply_crypto_output(
    current: PendingCryptoKind,
    external: &mut ExternalInputs,
    output: Result<CryptoJobOutput, agenc_ircd_crypto::CryptoWorkerError>,
) -> Result<(), CryptoCompletionError> {
    let output = output.map_err(|_| CryptoCompletionError::Busy)?;
    match (current, output) {
        (PendingCryptoKind::Verify, CryptoJobOutput::ChannelKey(verdict)) => {
            reserve_one(&mut external.key_verdicts).map_err(CryptoCompletionError::Internal)?;
            external.key_verdicts.push(verdict.matches());
            Ok(())
        }
        (PendingCryptoKind::Construct, CryptoJobOutput::ChannelKeyConstruct(Ok(verifier))) => {
            reserve_one(&mut external.key_verifiers).map_err(CryptoCompletionError::Internal)?;
            external.key_verifiers.push(verifier);
            Ok(())
        }
        (PendingCryptoKind::Construct, CryptoJobOutput::ChannelKeyConstruct(Err(_))) => {
            Err(CryptoCompletionError::Busy)
        }
        _ => Err(CryptoCompletionError::Internal(RuntimeError::InvalidValue)),
    }
}

// agenc-review: focus owner=runtime reviewed=2026-09-01 reason=crypto completion validates the retained command once renders its bounded result and transfers observation ownership into the durable boundary
fn finish_pending(
    context: &mut StateCoreContext,
    pending: PendingCryptoCommand,
) -> Result<(), RuntimeError> {
    let PendingCryptoCommand {
        generation,
        bound,
        kind,
        capabilities,
        message,
        authorized,
        external,
        render_command,
        observation,
        ..
    } = pending;
    let mut observation = Some(observation);
    let reply = ClientReply {
        generation,
        capabilities: &capabilities,
        request: RetryCommand {
            kind,
            message: &message,
        },
    };
    let decision = match context.domain().plan_authorized(authorized, Some(external)) {
        Ok(decision) => decision,
        Err(error) => match domain_plan_error(error) {
            SessionCommandError::Public { error, silent } => {
                let rendered = crate::client_render::render_domain_failure(
                    context,
                    reply.render_input(bound.user_id),
                    error,
                    silent,
                    None,
                );
                complete_observation(
                    context,
                    &mut observation,
                    if rendered.is_ok() {
                        result_for_domain_error(error)
                    } else {
                        ResultClass::Error
                    },
                );
                rendered?;
                return Ok(());
            }
            SessionCommandError::Internal(error) => {
                complete_observation(context, &mut observation, ResultClass::Error);
                return Err(error);
            }
        },
    };
    match execute_planned_command(
        context,
        None,
        bound,
        Some(reply),
        &render_command,
        decision,
        &mut observation,
    ) {
        Ok(result) => {
            complete_observation(context, &mut observation, result);
            Ok(())
        }
        Err(error) => {
            complete_observation(context, &mut observation, ResultClass::Error);
            Err(error)
        }
    }
}

fn render_pending_busy(
    context: &mut StateCoreContext,
    pending: &PendingCryptoCommand,
) -> Result<(), RuntimeError> {
    render_busy(
        context,
        pending.bound,
        pending.generation,
        &pending.capabilities,
        &pending.message,
    )
}

fn render_busy(
    context: &mut StateCoreContext,
    bound: BoundSession,
    generation: ConnectionGeneration,
    capabilities: &CapabilityState,
    message: &ParsedMessage,
) -> Result<(), RuntimeError> {
    crate::client_render::render_domain_failure(
        context,
        crate::client_render::ReplyInput {
            requester: bound.user_id,
            generation,
            capabilities,
            request: message,
        },
        DomainError::ServerBusy,
        false,
        None,
    )
}

fn cancel_command_timer(context: &mut StateCoreContext, sequence: u64) {
    context
        .timers_mut()
        .cancel(TimerKind::CommandDeadline, TimedId::Sequence(sequence));
}

fn complete_observation(
    context: &StateCoreContext,
    observation: &mut Option<CommandObservation>,
    result: ResultClass,
) {
    if let Some(observation) = observation.take() {
        context.complete_command_observation(observation, result);
    }
}

const fn result_for_domain_error(error: DomainError) -> ResultClass {
    if matches!(error, DomainError::ServerBusy) {
        ResultClass::Busy
    } else {
        ResultClass::Rejected
    }
}

/// Stages removal of one registered domain session after its transport ends.
pub(crate) fn close_registered(context: &mut StateCoreContext, bound: BoundSession, reason: &str) {
    let reason = BoundedUtf8::try_from_str(reason, ControlPolicy::RejectAll).ok();
    let wire_reason = reason
        .as_ref()
        .map_or("connection closed", BoundedUtf8::as_str)
        .to_owned();
    let mut observation = None;
    let _result = execute_session_command(
        context,
        None,
        bound,
        SessionCommandInput {
            reply: None,
            command: CanonicalCommand::quit(reason),
            close_reason: Some(&wire_reason),
            metered: false,
        },
        &mut observation,
    );
}

fn execute_session_command(
    context: &mut StateCoreContext,
    accounts: Option<&mut AccountServiceCoordinator>,
    bound: BoundSession,
    input: SessionCommandInput<'_>,
    observation: &mut Option<CommandObservation>,
) -> Result<CommandExecution, RuntimeError> {
    let SessionCommandInput {
        reply,
        command,
        close_reason,
        metered,
    } = input;
    let planned =
        match plan_session_command(context, bound, command, reply.map(|r| r.request), metered) {
            Ok(planned) => planned,
            Err(SessionCommandError::Public { error, silent }) => {
                let reply = reply.ok_or(RuntimeError::InvalidValue)?;
                crate::client_render::render_domain_failure(
                    context,
                    reply.render_input(bound.user_id),
                    error,
                    silent,
                    None,
                )?;
                return Ok(CommandExecution::Complete(result_for_domain_error(error)));
            }
            Err(SessionCommandError::Internal(error)) => return Err(error),
        };
    let decision = match planned {
        PlannedCommand::Ready(decision) => decision,
        PlannedCommand::Crypto(plan) => return Ok(CommandExecution::Crypto(plan)),
    };
    let render_command = match reply {
        Some(reply) => crate::command_convert::convert(
            context.domain(),
            reply.request.kind,
            reply.request.message,
        )?,
        None => {
            let reason = close_reason.and_then(|reason| {
                BoundedUtf8::try_from_str(reason, ControlPolicy::RejectAll).ok()
            });
            CanonicalCommand::quit(reason)
        }
    };
    execute_planned_command(
        context,
        accounts,
        bound,
        reply,
        &render_command,
        decision,
        observation,
    )
    .map(CommandExecution::Complete)
}

fn execute_planned_command(
    context: &mut StateCoreContext,
    accounts: Option<&mut AccountServiceCoordinator>,
    bound: BoundSession,
    reply: Option<ClientReply<'_>>,
    render_command: &CanonicalCommand,
    decision: PlanDecision,
    observation: &mut Option<CommandObservation>,
) -> Result<ResultClass, RuntimeError> {
    let PlanDecision::Mutation(plan) = decision else {
        return complete_nonmutation(context, bound, reply, decision);
    };
    let fanout = crate::mutation_render::render_mutation(
        context,
        bound,
        reply.map(|reply| reply.render_input(bound.user_id)),
        render_command,
        &plan,
    )?;
    match plan.storage_class() {
        StorageClass::Ephemeral => match context.apply_ephemeral(plan, fanout) {
            Ok(_) => Ok(ResultClass::Ok),
            Err(error) => render_ephemeral_refusal(context, bound, reply, error),
        },
        StorageClass::Durable => {
            stage_durable_command(context, accounts, bound, plan, fanout, reply, observation)
        }
    }
}

fn render_ephemeral_refusal(
    context: &mut StateCoreContext,
    bound: BoundSession,
    reply: Option<ClientReply<'_>>,
    error: crate::state_core::EphemeralRefused,
) -> Result<ResultClass, RuntimeError> {
    let Some(reply) = reply else {
        return Err(match error {
            crate::state_core::EphemeralRefused::Fanout(_) => RuntimeError::MemoryExhausted,
            crate::state_core::EphemeralRefused::Domain(_) => RuntimeError::InvalidValue,
        });
    };
    let error = ephemeral_refusal_error(error)?;
    let result = result_for_domain_error(error);
    crate::client_render::render_domain_failure(
        context,
        reply.render_input(bound.user_id),
        error,
        reply.request.message.command() == "NOTICE",
        None,
    )?;
    Ok(result)
}

fn ephemeral_refusal_error(
    error: crate::state_core::EphemeralRefused,
) -> Result<DomainError, RuntimeError> {
    match error {
        crate::state_core::EphemeralRefused::Fanout(_) => Ok(DomainError::ServerBusy),
        crate::state_core::EphemeralRefused::Domain(error) => match domain_plan_error(error) {
            SessionCommandError::Public { error, .. } => Ok(error),
            SessionCommandError::Internal(error) => Err(error),
        },
    }
}

fn stage_durable_command(
    context: &mut StateCoreContext,
    accounts: Option<&mut AccountServiceCoordinator>,
    bound: BoundSession,
    plan: MutationPlan,
    fanout: crate::state_core::fanout::FanoutRequest,
    reply: Option<ClientReply<'_>>,
    observation: &mut Option<CommandObservation>,
) -> Result<ResultClass, RuntimeError> {
    let origin = durable_command_origin(context, bound, reply, observation)?;
    let Some(account_id) = deleted_account(&plan)? else {
        let staged = if reply.is_none() {
            context.stage_shutdown_session_close(plan, fanout)
        } else {
            context.stage_durable(plan, fanout, origin, 0)
        };
        return match staged {
            Ok(_) => Ok(ResultClass::Ok),
            Err(error) => render_durable_stage_refusal(context, bound, reply, error),
        };
    };
    let generation = reply
        .map(|reply| reply.generation)
        .ok_or(RuntimeError::InvalidValue)?;
    let accounts = accounts.ok_or(RuntimeError::InvalidValue)?;
    let writes = accounts.begin_account_deletion(context, generation, account_id)?;
    let staged = context.stage_durable_with_account_service(plan, fanout, origin, 0, writes);
    match staged {
        Ok(crate::state_core::StageAccepted::Staged { .. }) => Ok(ResultClass::Ok),
        Ok(crate::state_core::StageAccepted::AppliedInStep(_)) => {
            accounts.cancel_account_deletion(context, generation)?;
            Err(RuntimeError::InvalidValue)
        }
        Err(error) => {
            accounts.cancel_account_deletion(context, generation)?;
            render_durable_stage_refusal(context, bound, reply, error)
        }
    }
}

fn render_durable_stage_refusal(
    context: &mut StateCoreContext,
    bound: BoundSession,
    reply: Option<ClientReply<'_>>,
    error: StageRefused,
) -> Result<ResultClass, RuntimeError> {
    let Some(reply) = reply else {
        return Err(stage_error(error));
    };
    let error = durable_stage_refusal_error(error)?;
    let result = result_for_domain_error(error);
    crate::client_render::render_domain_failure(
        context,
        reply.render_input(bound.user_id),
        error,
        reply.request.message.command() == "NOTICE",
        None,
    )?;
    Ok(result)
}

fn durable_stage_refusal_error(error: StageRefused) -> Result<DomainError, RuntimeError> {
    match error {
        StageRefused::Fanout(_) | StageRefused::Busy | StageRefused::Quiescing => {
            Ok(DomainError::ServerBusy)
        }
        StageRefused::Domain(error) => match domain_plan_error(error) {
            SessionCommandError::Public { error, .. } => Ok(error),
            SessionCommandError::Internal(error) => Err(error),
        },
    }
}

fn durable_command_origin(
    context: &StateCoreContext,
    bound: BoundSession,
    reply: Option<ClientReply<'_>>,
    observation: &mut Option<CommandObservation>,
) -> Result<Option<StagedOrigin>, RuntimeError> {
    let Some(reply) = reply else {
        return Ok(None);
    };
    if reply.request.message.command() == "NOTICE" {
        return Ok(Some(
            StagedOrigin::silent(reply.generation).with_observation(observation.take()),
        ));
    }
    let nickname = crate::client_render::requester_nickname(context, bound.user_id);
    let frame = crate::client_render::failure_frame(
        reply.capabilities,
        context.server_prefix(),
        &nickname,
        reply.request.message,
        DomainError::ServerBusy,
        None,
    )?;
    let frames = crate::client_render::logical_frames(
        context.server_prefix(),
        reply.capabilities,
        reply.request.message,
        vec![frame],
    )?;
    Ok(Some(
        StagedOrigin::with_rejection_frames(reply.generation, frames)
            .with_observation(observation.take()),
    ))
}

fn deleted_account(plan: &MutationPlan) -> Result<Option<AccountId>, RuntimeError> {
    let mut deleted = plan.events().iter().filter_map(|event| match event {
        DomainEvent::AccountDeleted(account_id) => Some(*account_id),
        _ => None,
    });
    let account_id = deleted.next();
    if deleted.next().is_some() {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(account_id)
}

fn complete_nonmutation(
    context: &mut StateCoreContext,
    bound: BoundSession,
    reply: Option<ClientReply<'_>>,
    decision: PlanDecision,
) -> Result<ResultClass, RuntimeError> {
    match decision {
        PlanDecision::Query(plan) => {
            let reply = reply.ok_or(RuntimeError::InvalidValue)?;
            crate::query_render::render_query(context, reply.render_input(bound.user_id), &plan)?;
            Ok(ResultClass::Ok)
        }
        PlanDecision::Rejected(plan) => {
            if let Some(reply) = reply {
                crate::client_render::render_rejected(
                    context,
                    reply.render_input(bound.user_id),
                    &plan,
                )?;
            }
            let result = if plan
                .failures()
                .iter()
                .all(|failure| failure.error() == DomainError::ServerBusy)
            {
                ResultClass::Busy
            } else {
                ResultClass::Rejected
            };
            Ok(result)
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
    metered: bool,
) -> Result<PlannedCommand, SessionCommandError> {
    let (authorized, admission) = if metered {
        admit_command(context, bound, command)?
    } else {
        authorize_unmetered_command(context, bound, command)?
    };
    let decision = context
        .domain()
        .plan_authorized(authorized, None)
        .map_err(domain_plan_error)?;
    let PlanDecision::NeedsExternal(requests) = decision else {
        return Ok(PlannedCommand::Ready(decision));
    };
    complete_external_plan(context, bound, retry, &admission, &requests)
}

fn authorize_unmetered_command(
    context: &StateCoreContext,
    bound: BoundSession,
    command: CanonicalCommand,
) -> Result<(AuthorizedCommand, AdmissionSnapshot), SessionCommandError> {
    let buckets: BTreeSet<_> = context
        .domain()
        .command_charges(bound.user_id, &command)
        .into_iter()
        .map(|charge| charge.bucket())
        .collect();
    let admission = AdmissionSnapshot::new(
        buckets
            .into_iter()
            .map(|bucket| (bucket, u64::MAX))
            .collect(),
    )
    .map_err(|_| RuntimeError::InvalidValue)?;
    match authorize_command(context, bound, command, &admission) {
        Ok(authorized) => Ok((authorized, admission)),
        Err(AuthorizationError::Rejected(failure)) => Err(SessionCommandError::Public {
            error: failure.error(),
            silent: failure.is_silent(),
        }),
        Err(AuthorizationError::Internal(error)) => Err(error.into()),
    }
}

fn admit_command(
    context: &mut StateCoreContext,
    bound: BoundSession,
    command: CanonicalCommand,
) -> Result<(AuthorizedCommand, AdmissionSnapshot), SessionCommandError> {
    let charges = context.domain().command_charges(bound.user_id, &command);
    let buckets: Vec<_> = charges.iter().map(|charge| charge.bucket()).collect();
    let prefix = guest_key_prefix_demand(context, bound, &command)?;
    let silent = command_is_silent(&command);
    let now = context.now();
    let admission = context
        .buckets_mut()
        .domain_snapshot(now, &buckets)
        .map_err(|_| RuntimeError::InvalidValue)?;
    charge_command(context, now, &charges, prefix, silent)?;
    let authorized = authorize_command(context, bound, command, &admission);
    let authorized_charges = match &authorized {
        Ok(authorized) => authorized.charges(),
        Err(AuthorizationError::Rejected(failure)) => failure.charges(),
        Err(AuthorizationError::Internal(error)) => return Err((*error).into()),
    };
    if authorized_charges != charges {
        return Err(RuntimeError::InvalidValue.into());
    }
    match authorized {
        Ok(authorized) => Ok((authorized, admission)),
        Err(AuthorizationError::Rejected(failure)) => Err(SessionCommandError::Public {
            error: failure.error(),
            silent: failure.is_silent(),
        }),
        Err(AuthorizationError::Internal(error)) => Err(error.into()),
    }
}

fn charge_command(
    context: &mut StateCoreContext,
    now: agenc_ircd_types::MonotonicTick,
    charges: &[agenc_ircd_domain::RateCharge],
    prefix: Option<BucketDemand>,
    silent: bool,
) -> Result<(), SessionCommandError> {
    let demands = command_demands(charges, prefix)?;
    context
        .buckets_mut()
        .charge_all_or_nothing(now, &demands)
        .map_err(|_| SessionCommandError::Public {
            error: DomainError::ServerBusy,
            silent,
        })
}

fn charge_registered_command_only(
    context: &mut StateCoreContext,
    user_id: agenc_ircd_types::UserId,
) -> Result<(), RuntimeError> {
    let demand = BucketDemand::new(
        BucketKind::RegisteredCommand,
        BucketKey::Session(user_id),
        1,
    )?;
    let now = context.now();
    context
        .buckets_mut()
        .charge_all_or_nothing(now, &[demand])
        .map_err(|_| RuntimeError::LimitExceeded)
}

fn command_demands(
    charges: &[agenc_ircd_domain::RateCharge],
    prefix: Option<BucketDemand>,
) -> Result<Vec<BucketDemand>, RuntimeError> {
    let count = charges
        .len()
        .checked_add(usize::from(prefix.is_some()))
        .ok_or(RuntimeError::Overflow)?;
    let mut demands = Vec::new();
    demands
        .try_reserve_exact(count)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for charge in charges {
        let (kind, key) = domain_bucket(charge.bucket());
        demands.push(BucketDemand::new(kind, key, charge.tokens())?);
    }
    demands.extend(prefix);
    Ok(demands)
}

fn guest_key_prefix_demand(
    context: &StateCoreContext,
    bound: BoundSession,
    command: &CanonicalCommand,
) -> Result<Option<BucketDemand>, RuntimeError> {
    let CanonicalCommandView::Join(targets) = command.view() else {
        return Ok(None);
    };
    let tokens = targets
        .iter()
        .filter(|target| target.key_supplied())
        .count();
    if tokens == 0 {
        return Ok(None);
    }
    let session = context
        .domain()
        .session(bound.user_id)
        .ok_or(RuntimeError::InvalidValue)?;
    if session.account_id().is_some() {
        return Ok(None);
    }
    let generation = context
        .sessions()
        .generation_for_user(bound.user_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let connection = context
        .sessions()
        .connection(generation)
        .ok_or(RuntimeError::InvalidValue)?;
    let key = guest_prefix_bucket(connection.purpose(), connection.source_prefix())?;
    let tokens = u64::try_from(tokens).map_err(|_| RuntimeError::Overflow)?;
    BucketDemand::new(BucketKind::ChannelKeyAttempt, key, tokens).map(Some)
}

fn guest_prefix_bucket(
    purpose: ListenerPurpose,
    source_prefix: crate::state_core::inbox::SourceAddressKey,
) -> Result<BucketKey, RuntimeError> {
    match purpose {
        ListenerPurpose::ClientTls | ListenerPurpose::ClientWss => {
            Ok(BucketKey::Prefix(source_prefix))
        }
        ListenerPurpose::ClientOnion => Ok(BucketKey::OnionListener),
        ListenerPurpose::Federation | ListenerPurpose::AdminLocal | ListenerPurpose::AdminTls => {
            Err(RuntimeError::InvalidValue)
        }
    }
}

fn command_is_silent(command: &CanonicalCommand) -> bool {
    matches!(
        command.view(),
        CanonicalCommandView::Message(message) if message.kind() == MessageKind::Notice
    )
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
) -> Result<PlannedCommand, SessionCommandError> {
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
    let crypto_requests = crypto_requests(requests)?;
    if crypto_requests.is_empty() {
        return context
            .domain()
            .plan_authorized(authorized, Some(external))
            .map(PlannedCommand::Ready)
            .map_err(domain_plan_error);
    }
    let render_command =
        crate::command_convert::convert(context.domain(), retry.kind, retry.message)?;
    Ok(PlannedCommand::Crypto(Box::new(DeferredPlan {
        authorized,
        external,
        requests: crypto_requests,
        render_command,
    })))
}

fn crypto_requests(
    requests: &[ExternalInputRequest],
) -> Result<Vec<ExternalInputRequest>, RuntimeError> {
    let count = requests
        .iter()
        .filter(|request| {
            matches!(
                request,
                ExternalInputRequest::ChannelKeyVerification { .. }
                    | ExternalInputRequest::ChannelKeyConstruction { .. }
            )
        })
        .count();
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(count)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    selected.extend(requests.iter().copied().filter(|request| {
        matches!(
            request,
            ExternalInputRequest::ChannelKeyVerification { .. }
                | ExternalInputRequest::ChannelKeyConstruction { .. }
        )
    }));
    Ok(selected)
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
        ExternalInputRequest::ChannelKeyVerification { .. }
        | ExternalInputRequest::ChannelKeyConstruction { .. } => {}
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

fn stage_error(error: StageRefused) -> RuntimeError {
    match error {
        StageRefused::Fanout(_) => RuntimeError::MemoryExhausted,
        StageRefused::Busy | StageRefused::Quiescing => RuntimeError::LimitExceeded,
        StageRefused::Domain(_) => RuntimeError::InvalidValue,
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::{CryptoError, CryptoWorkerError};
    use agenc_ircd_domain::{MessageCommand, MessageTarget, NicknameValue, RateBucket, RateCharge};
    use agenc_ircd_types::{MonotonicTick, UserId};

    use super::*;
    use crate::admission::{BucketTable, RateLimits};
    use crate::bridge::crypto::ChannelKeyVerdict;
    use crate::state_core::EphemeralRefused;
    use crate::state_core::fanout::FanoutRefused;
    use crate::state_core::inbox::SourceAddressKey;

    struct TestVerifier;

    impl ChannelKeyVerifier for TestVerifier {
        fn derive(
            &self,
            _secret: &[u8],
            salt: &[u8; crate::bridge::crypto::CHANNEL_KEY_SALT_BYTES],
        ) -> Result<[u8; crate::bridge::crypto::CHANNEL_KEY_HASH_BYTES], CryptoError> {
            Ok([salt[0]; crate::bridge::crypto::CHANNEL_KEY_HASH_BYTES])
        }
    }

    #[test]
    fn ephemeral_refusals_are_public_only_when_safe() {
        assert!(matches!(
            ephemeral_refusal_error(EphemeralRefused::Fanout(FanoutRefused::MemoryExhausted)),
            Ok(DomainError::ServerBusy)
        ));
        assert!(matches!(
            ephemeral_refusal_error(EphemeralRefused::Domain(DomainError::Forbidden)),
            Ok(DomainError::Forbidden)
        ));
        assert!(matches!(
            ephemeral_refusal_error(EphemeralRefused::Domain(DomainError::InvariantViolation)),
            Err(RuntimeError::InvalidValue)
        ));
    }

    #[test]
    fn durable_stage_refusals_are_public_only_when_safe() {
        for refusal in [StageRefused::Busy, StageRefused::Quiescing] {
            assert!(matches!(
                durable_stage_refusal_error(refusal),
                Ok(DomainError::ServerBusy)
            ));
        }
        assert!(matches!(
            durable_stage_refusal_error(StageRefused::Domain(DomainError::StaleRevision)),
            Ok(DomainError::StaleRevision)
        ));
        assert!(matches!(
            durable_stage_refusal_error(StageRefused::Domain(DomainError::InvariantViolation)),
            Err(RuntimeError::InvalidValue)
        ));
    }

    #[test]
    fn crypto_completion_mapping_accepts_only_the_pending_output_kind() {
        let mut external = ExternalInputs::default();
        assert!(
            apply_crypto_output(
                PendingCryptoKind::Verify,
                &mut external,
                Ok(CryptoJobOutput::ChannelKey(ChannelKeyVerdict::for_test(
                    true
                ))),
            )
            .is_ok()
        );
        assert_eq!(external.key_verdicts, vec![true]);

        let verifier = ChannelKeyVerifierRecord::new([1; 16], [2; 32]);
        assert!(
            apply_crypto_output(
                PendingCryptoKind::Construct,
                &mut external,
                Ok(CryptoJobOutput::ChannelKeyConstruct(Ok(verifier))),
            )
            .is_ok()
        );
        assert_eq!(external.key_verifiers.len(), 1);
        assert_eq!(
            external
                .key_verifiers
                .first()
                .map(ChannelKeyVerifierRecord::salt),
            Some(&[1; 16])
        );
        assert_eq!(
            external
                .key_verifiers
                .first()
                .map(ChannelKeyVerifierRecord::hash),
            Some(&[2; 32])
        );

        assert!(matches!(
            apply_crypto_output(
                PendingCryptoKind::Construct,
                &mut external,
                Ok(CryptoJobOutput::ChannelKeyConstruct(Err(
                    CryptoError::LimitExceeded
                ))),
            ),
            Err(CryptoCompletionError::Busy)
        ));
        assert!(matches!(
            apply_crypto_output(
                PendingCryptoKind::Verify,
                &mut external,
                Ok(CryptoJobOutput::ChannelKeyConstruct(Ok(verifier))),
            ),
            Err(CryptoCompletionError::Internal(RuntimeError::InvalidValue))
        ));
        assert!(matches!(
            apply_crypto_output(
                PendingCryptoKind::Verify,
                &mut external,
                Err(CryptoWorkerError::WorkerPanicked),
            ),
            Err(CryptoCompletionError::Busy)
        ));
    }

    #[test]
    fn guest_prefix_and_session_key_charges_are_atomic() -> Result<(), RuntimeError> {
        let user = UserId::from_bytes([7; 16]);
        let charge = RateCharge::new(RateBucket::RegisteredCommand(user), 1)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let prefix = BucketKey::Prefix(SourceAddressKey::ipv4([192, 0, 2, 7]).prefix_key());
        let extra = BucketDemand::new(BucketKind::ChannelKeyAttempt, prefix, 5)?;
        let demands = command_demands(&[charge], Some(extra))?;
        let mut table = BucketTable::new(RateLimits::defaults());
        let now = MonotonicTick::from_ticks(0);
        assert!(table.charge_all_or_nothing(now, &demands).is_err());
        assert_eq!(
            table.available(now, BucketKind::RegisteredCommand, BucketKey::Session(user),),
            BucketKind::RegisteredCommand.default_rate().burst()
        );
        Ok(())
    }

    #[test]
    fn guest_prefix_keys_follow_the_transport_profile() -> Result<(), RuntimeError> {
        let direct = SourceAddressKey::ipv4([198, 51, 100, 8]);
        let direct_prefix = direct.prefix_key();
        for purpose in [ListenerPurpose::ClientTls, ListenerPurpose::ClientWss] {
            assert!(matches!(
                guest_prefix_bucket(purpose, direct_prefix)?,
                BucketKey::Prefix(prefix) if prefix == direct_prefix
            ));
        }
        assert!(matches!(
            guest_prefix_bucket(
                ListenerPurpose::ClientOnion,
                SourceAddressKey::onion_listener(),
            )?,
            BucketKey::OnionListener
        ));
        for purpose in [
            ListenerPurpose::Federation,
            ListenerPurpose::AdminLocal,
            ListenerPurpose::AdminTls,
        ] {
            assert!(guest_prefix_bucket(purpose, direct).is_err());
        }
        Ok(())
    }

    #[test]
    fn executor_reload_fence_checks_each_owned_index() {
        let verifier: Arc<dyn ChannelKeyVerifier> = Arc::new(TestVerifier);
        let dummy = ChannelKeyVerifierRecord::new([1; 16], [2; 32]);
        let mut executor = RegisteredCommandExecutor::new(verifier, dummy);
        assert!(executor.reload_ready());

        executor
            .by_connection
            .insert(ConnectionGeneration::new(1), CryptoJobId::new(1));
        assert!(!executor.reload_ready());
        executor.by_connection.clear();

        executor.by_sequence.insert(1, CryptoJobId::new(1));
        assert!(!executor.reload_ready());
        executor.by_sequence.clear();
        assert!(executor.reload_ready());
    }

    #[test]
    fn prepared_crypto_jobs_preserve_their_closed_runtime_kind() -> Result<(), RuntimeError> {
        let verifier: Arc<dyn ChannelKeyVerifier> = Arc::new(TestVerifier);
        let verify = PreparedCryptoJob::Verify(crate::bridge::crypto::ChannelKeyVerifyJob::new(
            Arc::clone(&verifier),
            ChannelKeyTarget::Dummy(ChannelKeyVerifierRecord::new([1; 16], [2; 32])),
            vec![3; crate::bridge::crypto::MIN_CHANNEL_KEY_BYTES],
        )?);
        assert!(matches!(verify.kind(), PendingCryptoKind::Verify));
        assert!(matches!(
            verify.into_runtime(),
            RuntimeCryptoJob::ChannelKeyVerify(_)
        ));

        let construct = PreparedCryptoJob::Construct(ChannelKeyConstructJob::new(
            verifier,
            [4; 16],
            vec![5; crate::bridge::crypto::MIN_CHANNEL_KEY_BYTES],
        )?);
        assert!(matches!(construct.kind(), PendingCryptoKind::Construct));
        assert!(matches!(
            construct.into_runtime(),
            RuntimeCryptoJob::ChannelKeyConstruct(_)
        ));
        Ok(())
    }

    #[test]
    fn external_request_selection_and_entropy_routing_cover_every_arm() -> Result<(), RuntimeError>
    {
        let requests = [
            ExternalInputRequest::UtcNow {
                request_sequence: 0,
            },
            ExternalInputRequest::MonotonicNow {
                request_sequence: 1,
            },
            ExternalInputRequest::Entropy {
                request_sequence: 2,
                purpose: EntropyPurpose::Invite,
                bytes: 16,
            },
            ExternalInputRequest::ChannelKeyVerification {
                request_sequence: 3,
                target_index: 0,
            },
            ExternalInputRequest::ChannelKeyConstruction {
                request_sequence: 4,
                change_index: 0,
            },
        ];
        assert_eq!(crypto_requests(&requests)?.len(), 2);
        assert!(crypto_requests(&requests[..3])?.is_empty());

        let mut inputs = ExternalInputs::default();
        for purpose in [
            EntropyPurpose::ChannelInstance(0),
            EntropyPurpose::Message(1),
            EntropyPurpose::Invite,
            EntropyPurpose::MaskEntry(2),
            EntropyPurpose::AccountDeletionChallenge,
        ] {
            push_entropy(&mut inputs, purpose, [9; 16])?;
        }
        assert_eq!(inputs.channel_ids.len(), 1);
        assert_eq!(inputs.message_ids.len(), 1);
        assert_eq!(inputs.invite_ids.len(), 1);
        assert_eq!(inputs.entry_ids.len(), 1);
        assert_eq!(inputs.deletion_tokens.len(), 1);
        Ok(())
    }

    #[test]
    fn closed_error_mappings_and_command_silence_are_exhaustive()
    -> Result<(), Box<dyn core::error::Error>> {
        assert!(matches!(
            domain_plan_error(DomainError::ExternalInputMismatch),
            SessionCommandError::Internal(RuntimeError::InvalidValue)
        ));
        assert!(matches!(
            domain_plan_error(DomainError::InvariantViolation),
            SessionCommandError::Internal(RuntimeError::InvalidValue)
        ));
        assert!(matches!(
            domain_plan_error(DomainError::Forbidden),
            SessionCommandError::Public {
                error: DomainError::Forbidden,
                silent: false,
            }
        ));

        assert_eq!(stage_error(StageRefused::Busy), RuntimeError::LimitExceeded);
        assert_eq!(
            stage_error(StageRefused::Quiescing),
            RuntimeError::LimitExceeded
        );
        assert_eq!(
            stage_error(StageRefused::Domain(DomainError::Forbidden)),
            RuntimeError::InvalidValue
        );
        assert_eq!(
            stage_error(StageRefused::Fanout(FanoutRefused::MemoryExhausted)),
            RuntimeError::MemoryExhausted
        );

        assert!(!command_is_silent(&CanonicalCommand::quit(None)));
        let notice = MessageCommand::new(
            MessageKind::Notice,
            vec![MessageTarget::User(NicknameValue::parse("target")?)],
            None,
        )?;
        assert!(command_is_silent(&CanonicalCommand::message(notice)));
        let privmsg = MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::User(NicknameValue::parse("target")?)],
            Some(agenc_ircd_domain::MessageText::parse("body")?),
        )?;
        assert!(!command_is_silent(&CanonicalCommand::message(privmsg)));

        assert_eq!(copy_secret(&[])?, Vec::<u8>::new());
        assert_eq!(copy_secret(b"secret")?, b"secret");
        Ok(())
    }

    #[test]
    fn crypto_output_rejects_both_crossed_result_kinds() {
        let verifier = ChannelKeyVerifierRecord::new([1; 16], [2; 32]);
        let mut external = ExternalInputs::default();
        assert!(matches!(
            apply_crypto_output(
                PendingCryptoKind::Construct,
                &mut external,
                Ok(CryptoJobOutput::ChannelKey(ChannelKeyVerdict::for_test(
                    false
                ))),
            ),
            Err(CryptoCompletionError::Internal(RuntimeError::InvalidValue))
        ));
        assert!(matches!(
            apply_crypto_output(
                PendingCryptoKind::Verify,
                &mut external,
                Ok(CryptoJobOutput::ChannelKeyConstruct(Err(
                    CryptoError::LimitExceeded
                ))),
            ),
            Err(CryptoCompletionError::Internal(RuntimeError::InvalidValue))
        ));
        assert!(matches!(
            apply_crypto_output(
                PendingCryptoKind::Verify,
                &mut external,
                Ok(CryptoJobOutput::ChannelKeyConstruct(Ok(verifier))),
            ),
            Err(CryptoCompletionError::Internal(RuntimeError::InvalidValue))
        ));
    }
}
