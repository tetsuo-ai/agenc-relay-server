//! Bounded direct-client history reads owned by the registered-command router.

use agenc_relay_client_wire::{CapabilityState, ParsedMessage};
use agenc_relay_domain::{CanonicalCommand, CanonicalCommandView, DomainError, HistoryPosition};

use crate::RuntimeError;
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::connection::sink::{ConnectionGeneration, QuerySnapshotPermit};
use crate::observe::metrics::ResultClass;
use crate::state_core::history::{HISTORY_PAGE_MESSAGES, HistorySnapshot};
use crate::state_core::session::BoundSession;
use crate::state_core::{CommandObservation, RouteOutcome, StateCoreContext};

use super::{
    ClientReply, DeferredOrigin, RegisteredCommandExecutor, RetryCommand, admit_command,
    complete_observation,
};

const CONTINUATION_BYTES: usize = 131_072;

pub(super) struct PendingHistory {
    generation: ConnectionGeneration,
    bound: BoundSession,
    snapshot: HistorySnapshot,
    positions: Vec<HistoryPosition>,
    offset: usize,
    batch_id: String,
    capabilities: CapabilityState,
    request: ParsedMessage,
    sequence: u64,
    deadline: u64,
    observation: Option<CommandObservation>,
    _permit: QuerySnapshotPermit,
}

impl RegisteredCommandExecutor {
    pub(super) fn start_history(
        &mut self,
        context: &mut StateCoreContext,
        origin: DeferredOrigin<'_>,
        message: ParsedMessage,
        command: CanonicalCommand,
        observation: &mut Option<CommandObservation>,
    ) -> Result<RouteOutcome, RuntimeError> {
        let bound = origin.bound;
        let reply = ClientReply {
            generation: origin.generation,
            capabilities: origin.capabilities,
            request: RetryCommand {
                kind: origin.kind,
                message: &message,
            },
        };
        let requested = match command.view() {
            CanonicalCommandView::Chathistory(channel, query) => (channel, query),
            _ => return Err(RuntimeError::InvalidValue),
        };
        let failure = self.history_admission(context, bound, &reply, command)?;
        if let Some(error) = failure {
            return reject(context, bound, reply, observation, error);
        }
        let Ok(snapshot) = context.history_select(bound, requested.0, requested.1) else {
            return reject(context, bound, reply, observation, DomainError::ServerBusy);
        };
        let (mut pending, deadline) = self.prepare_history(context, origin, message, snapshot)?;
        if pending.positions.is_empty() {
            let sent = send_page(context, &pending, &[], true);
            complete_observation(
                context,
                observation,
                if sent.is_ok() {
                    ResultClass::Ok
                } else {
                    ResultClass::Error
                },
            );
            sent?;
        } else {
            let read = context.history_read(&pending.snapshot, &pending.positions)?;
            context.timers_mut().schedule(
                deadline,
                crate::state_core::timers::TimerKind::CommandDeadline,
                crate::state_core::timers::TimedId::Sequence(pending.sequence),
            )?;
            pending.observation = observation.take();
            self.history.insert(read, pending);
        }
        Ok(RouteOutcome::Continue)
    }

    fn history_admission(
        &self,
        context: &mut StateCoreContext,
        bound: BoundSession,
        reply: &ClientReply<'_>,
        command: CanonicalCommand,
    ) -> Result<Option<DomainError>, RuntimeError> {
        let kind = command.kind();
        let admitted = admit_command(context, bound, command);
        let failure = match admitted {
            Err(super::SessionCommandError::Public { error, .. }) => Some(error),
            Err(super::SessionCommandError::Internal(error)) => return Err(error),
            // A history query is in the expensive query class of spec 19.1, so
            // the 80-percent class of spec 19.3 refuses it before any snapshot
            // is selected or any storage read is submitted.
            Ok(_) if super::expensive_query_is_stopped(context, kind) => {
                Some(DomainError::ServerBusy)
            }
            Ok(_)
                if !reply.capabilities.enabled("draft/chathistory")
                    || !context.history_enabled() =>
            {
                Some(DomainError::Forbidden)
            }
            Ok(_)
                if self
                    .history
                    .values()
                    .any(|pending| pending.generation == reply.generation) =>
            {
                Some(DomainError::ServerBusy)
            }
            Ok(_) => None,
        };
        Ok(failure)
    }

    fn prepare_history(
        &mut self,
        context: &mut StateCoreContext,
        origin: DeferredOrigin<'_>,
        message: ParsedMessage,
        snapshot: HistorySnapshot,
    ) -> Result<(PendingHistory, agenc_relay_types::MonotonicTick), RuntimeError> {
        let permit = context
            .prepare_query_snapshot(
                origin.generation,
                snapshot.selection.positions().len(),
                CONTINUATION_BYTES,
            )?
            .finish(snapshot.selection.positions().len(), CONTINUATION_BYTES)?;
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
        let batch_id = format!("h{sequence}");
        let positions = snapshot
            .selection
            .positions()
            .iter()
            .take(HISTORY_PAGE_MESSAGES)
            .copied()
            .collect();
        let deadline = context
            .now()
            .checked_add(super::COMMAND_DEADLINE_MILLIS)
            .map_err(|_| RuntimeError::Overflow)?;
        let pending = PendingHistory {
            generation: origin.generation,
            bound: origin.bound,
            snapshot,
            positions,
            offset: 0,
            batch_id,
            capabilities: origin
                .capabilities
                .try_clone()
                .map_err(|_| RuntimeError::MemoryExhausted)?,
            request: message,
            sequence,
            deadline: deadline.get(),
            observation: None,
            _permit: permit,
        };
        Ok((pending, deadline))
    }

    pub(crate) fn owns_history_read(&self, id: StorageReadId) -> bool {
        self.history.contains_key(&id)
    }

    pub(crate) fn history_read_completed(
        &mut self,
        context: &mut StateCoreContext,
        message: StorageReadCompletionMessage,
    ) -> Result<(), (ConnectionGeneration, RuntimeError)> {
        let Some(mut pending) = self.history.remove(&message.read_id) else {
            return Ok(());
        };
        let generation = pending.generation;
        let completed = continue_page(context, &mut pending, message);
        match completed {
            Ok(Some(read)) => {
                self.history.insert(read, pending);
                Ok(())
            }
            Ok(None) => {
                super::cancel_command_timer(context, pending.sequence);
                complete_observation(context, &mut pending.observation, ResultClass::Ok);
                Ok(())
            }
            Err(_) => {
                super::cancel_command_timer(context, pending.sequence);
                let result = expire(context, &pending);
                complete_observation(context, &mut pending.observation, ResultClass::Rejected);
                result.map_err(|error| (generation, error))
            }
        }
    }

    pub(super) fn close_history(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        let read = self
            .history
            .iter()
            .find_map(|(id, pending)| (pending.generation == generation).then_some(*id));
        if let Some(read) = read
            && let Some(mut pending) = self.history.remove(&read)
        {
            super::cancel_command_timer(context, pending.sequence);
            complete_observation(context, &mut pending.observation, ResultClass::Closed);
        }
    }

    pub(super) fn expire_history_timer(
        &mut self,
        context: &mut StateCoreContext,
        sequence: u64,
    ) -> Result<bool, (ConnectionGeneration, RuntimeError)> {
        let read = self
            .history
            .iter()
            .find_map(|(id, pending)| (pending.sequence == sequence).then_some(*id));
        let Some(read) = read else {
            return Ok(false);
        };
        let Some(mut pending) = self.history.remove(&read) else {
            return Ok(false);
        };
        let result = expire(context, &pending);
        complete_observation(context, &mut pending.observation, ResultClass::Rejected);
        result
            .map(|()| true)
            .map_err(|error| (pending.generation, error))
    }
}

fn continue_page(
    context: &mut StateCoreContext,
    pending: &mut PendingHistory,
    message: StorageReadCompletionMessage,
) -> Result<Option<StorageReadId>, RuntimeError> {
    if context.now().get() >= pending.deadline {
        return Err(RuntimeError::InvalidValue);
    }
    let result = message.result?;
    let materialized =
        context.history_materialize(&pending.snapshot, &pending.positions, &result)?;
    let next = pending
        .offset
        .checked_add(pending.positions.len())
        .ok_or(RuntimeError::Overflow)?;
    let last = next == pending.snapshot.selection.positions().len();
    send_page(context, pending, materialized.messages(), last)?;
    if last {
        return Ok(None);
    }
    pending.offset = next;
    pending.positions = pending
        .snapshot
        .selection
        .positions()
        .iter()
        .skip(next)
        .take(HISTORY_PAGE_MESSAGES)
        .copied()
        .collect();
    context
        .history_read(&pending.snapshot, &pending.positions)
        .map(Some)
}

fn send_page(
    context: &mut StateCoreContext,
    pending: &PendingHistory,
    messages: &[agenc_relay_storage::history_records::HistoryMessageRecord],
    last: bool,
) -> Result<(), RuntimeError> {
    context.history_recheck(&pending.snapshot)?;
    let permit = context
        .prepare_query_snapshot(pending.generation, messages.len(), CONTINUATION_BYTES)?
        .finish(messages.len(), CONTINUATION_BYTES)?;
    let label = pending
        .request
        .tags()
        .iter()
        .find(|tag| tag.key() == "label")
        .and_then(|tag| tag.value());
    let frames = crate::history_render::page(crate::history_render::PageInput {
        prefix: context.server_prefix(),
        capabilities: &pending.capabilities,
        batch_id: &pending.batch_id,
        channel: &pending.snapshot.channel_name,
        messages,
        first: pending.offset == 0,
        last,
        label,
    })?;
    context.history_recheck(&pending.snapshot)?;
    context
        .send_query_to(pending.generation, frames, permit)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    Ok(())
}

fn expire(context: &mut StateCoreContext, pending: &PendingHistory) -> Result<(), RuntimeError> {
    if pending.offset != 0 {
        let close = agenc_relay_client_wire::WireMessage::new(
            context.server_prefix(),
            "BATCH",
            &[&format!("-{}", pending.batch_id)],
            None,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        context
            .send_to(pending.generation, vec![close])
            .map_err(|_| RuntimeError::MemoryExhausted)?;
    }
    crate::client_render::render_domain_failure(
        context,
        crate::client_render::ReplyInput {
            requester: pending.bound.user_id,
            generation: pending.generation,
            capabilities: &pending.capabilities,
            request: &pending.request,
        },
        DomainError::ServerBusy,
        false,
        None,
    )
}

fn reject(
    context: &mut StateCoreContext,
    bound: BoundSession,
    reply: ClientReply<'_>,
    observation: &mut Option<CommandObservation>,
    error: DomainError,
) -> Result<RouteOutcome, RuntimeError> {
    crate::client_render::render_domain_failure(
        context,
        reply.render_input(bound.user_id),
        error,
        false,
        None,
    )?;
    complete_observation(context, observation, super::result_for_domain_error(error));
    Ok(RouteOutcome::Continue)
}
