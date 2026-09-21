//! Connection-owned JOIN response delivery (spec 14.2).

use super::{ActionStep, ConnectionState, RegistrationRouter, close_transport};
use crate::RuntimeError;
use crate::connection::sink::QuerySnapshotPermit;
use crate::connection::{ClientQueueSnapshot, ConnectionGeneration};
use crate::observe::metrics::ResultClass;
use crate::state_core::StateCoreContext;
use crate::state_core::local_join::{LocalJoinNames, LocalJoinNamesSeed};
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use crate::state_core::{CommandObservation, RouteOutcome};
use agenc_relay_client_wire::{ParsedMessage, RegisteredCommandHandoff, WireMessage};
use agenc_relay_domain::ChannelNameValue;
use agenc_relay_types::MonotonicTick;

const MAX_JOIN_CHANNELS: usize = 20;
const MAX_DEFERRED_JOIN_COMMANDS: usize = 32;
// One bounded batch ID stack, retained label, and generated response ID.
const JOIN_BATCH_BACKING_BYTES: usize = 1_024;
const QUEUE_CHECK_MILLIS: u64 = 50;
const IDLE_MILLIS: u64 = agenc_relay_types::QUERY_CURSOR_SECONDS * 1_000;
const ABSOLUTE_MILLIS: u64 = agenc_relay_types::QUERY_SNAPSHOT_ABSOLUTE_SECONDS * 1_000;

pub(super) struct JoinNamesContinuation {
    channels: Vec<ChannelNameValue>,
    request: Option<Box<ParsedMessage>>,
    cursor: Option<[u8; 32]>,
    page_sequence: u32,
    idle_deadline: u64,
    absolute_deadline: u64,
    source: JoinNamesSource,
    permit: Option<QuerySnapshotPermit>,
}

enum JoinNamesSource {
    Edge,
    Local(Box<LocalJoinNames>),
}

pub(super) struct DeferredJoinCommand {
    handoff: RegisteredCommandHandoff,
    pub(super) observation: CommandObservation,
    _permit: crate::budget::MemoryPermit,
}

impl JoinNamesContinuation {
    fn new(
        channels: Vec<ChannelNameValue>,
        request: Box<ParsedMessage>,
        now: MonotonicTick,
        permit: QuerySnapshotPermit,
    ) -> Result<Self, RuntimeError> {
        let deadlines = Self::deadlines(now)?;
        Ok(Self::assemble(
            channels,
            request,
            deadlines,
            JoinNamesSource::Edge,
            permit,
        ))
    }

    fn new_local(
        channels: Vec<ChannelNameValue>,
        request: Box<ParsedMessage>,
        now: MonotonicTick,
        mut source: Box<LocalJoinNames>,
    ) -> Result<Self, RuntimeError> {
        let deadlines = Self::deadlines(now)?;
        let permit = source.take_permit()?;
        Ok(Self::assemble(
            channels,
            request,
            deadlines,
            JoinNamesSource::Local(source),
            permit,
        ))
    }

    fn deadlines(now: MonotonicTick) -> Result<(u64, u64), RuntimeError> {
        Ok((
            now.get()
                .checked_add(IDLE_MILLIS)
                .ok_or(RuntimeError::Overflow)?,
            now.get()
                .checked_add(ABSOLUTE_MILLIS)
                .ok_or(RuntimeError::Overflow)?,
        ))
    }

    fn assemble(
        channels: Vec<ChannelNameValue>,
        mut request: Box<ParsedMessage>,
        deadlines: (u64, u64),
        source: JoinNamesSource,
        permit: QuerySnapshotPermit,
    ) -> Self {
        let _erased_key = request.take_parameter(1).map(zeroize::Zeroizing::new);
        Self {
            channels,
            request: Some(request),
            cursor: None,
            page_sequence: 0,
            idle_deadline: deadlines.0,
            absolute_deadline: deadlines.1,
            source,
            permit: Some(permit),
        }
    }

    fn expired(&self, now: MonotonicTick) -> bool {
        now.get() >= self.idle_deadline || now.get() >= self.absolute_deadline
    }

    fn accept_page(
        &mut self,
        page: (u32, bool),
        frames: &[WireMessage],
        now: MonotonicTick,
    ) -> Result<(), RuntimeError> {
        if self.request.is_some() || page.0 != self.page_sequence || self.expired(now) {
            return Err(RuntimeError::InvalidValue);
        }
        if !page.1 {
            validate_endings(&self.channels, frames)?;
        } else if frames.iter().any(|frame| frame.command() == "366") {
            return Err(RuntimeError::InvalidValue);
        }
        self.page_sequence = self
            .page_sequence
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        self.idle_deadline = now
            .get()
            .checked_add(IDLE_MILLIS)
            .ok_or(RuntimeError::Overflow)?;
        Ok(())
    }
}

impl RegistrationRouter {
    pub(super) fn defer_join_command(
        context: &StateCoreContext,
        state: &mut ConnectionState,
        handoff: RegisteredCommandHandoff,
        observation: CommandObservation,
    ) -> Result<ActionStep, RuntimeError> {
        if state.join_deferred.len() >= MAX_DEFERRED_JOIN_COMMANDS {
            context.complete_command_observation(observation, ResultClass::Closed);
            return Err(RuntimeError::LimitExceeded);
        }
        let reserved = context.reserve_output_backing(handoff.message().requested_backing_bytes());
        let permit = match reserved {
            Ok(permit) => permit,
            Err(error) => {
                context.complete_command_observation(observation, ResultClass::Error);
                return Err(error);
            }
        };
        if let Err(error) = state
            .join_deferred
            .reserve(MAX_DEFERRED_JOIN_COMMANDS, |bytes| {
                context.reserve_output_backing(bytes)
            })
        {
            context.complete_command_observation(observation, ResultClass::Error);
            return Err(error);
        }
        let entry = DeferredJoinCommand {
            handoff,
            observation,
            _permit: permit,
        };
        if let Err(entry) = state.join_deferred.push_back(entry) {
            context.complete_command_observation(entry.observation, ResultClass::Closed);
            return Err(RuntimeError::LimitExceeded);
        }
        Ok(ActionStep::Continue)
    }

    /// Resumes the commands one connection deferred, whatever deferred
    /// them: an open JOIN/NAMES continuation or a floored response.
    pub(super) fn resume_deferred_commands(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        self.resume_join_commands(context, generation);
    }

    fn resume_join_commands(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        let Some(mut state) = self.connections.remove(&generation) else {
            return;
        };
        let outcome = self.drive_join_commands(context, generation, &mut state);
        self.connections.insert(generation, state);
        if outcome.is_err() {
            self.abort_join_names(context, generation);
        }
    }

    fn drive_join_commands(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        state: &mut ConnectionState,
    ) -> Result<(), RuntimeError> {
        while state.join_names.is_none()
            && !context.has_local_join_seed(generation)
            && !context.secret_floor_pending(generation)
        {
            let Some(deferred) = state.join_deferred.pop_front() else {
                return Ok(());
            };
            let outcome = self.commands.route_registered(
                context,
                self.accounts.as_mut(),
                generation,
                state.bound,
                state.registration.capability_state(),
                &mut state.nickname,
                deferred.handoff,
                deferred.observation,
            )?;
            if matches!(outcome, RouteOutcome::Close(_)) {
                return Err(RuntimeError::InvalidValue);
            }
        }
        Ok(())
    }

    pub(super) fn resume_ready_join_commands(&mut self, context: &mut StateCoreContext) {
        loop {
            let ready = self
                .connections
                .iter()
                .find(|(generation, state)| {
                    state.join_names.is_none()
                        && !state.join_deferred.is_empty()
                        && !context.secret_floor_pending(**generation)
                        && context
                            .sessions()
                            .sink_for_generation(**generation)
                            .is_some()
                        && !context.has_local_join_seed(**generation)
                })
                .map(|(generation, _)| *generation);
            let Some(generation) = ready else {
                break;
            };
            self.resume_join_commands(context, generation);
        }
        self.drain_local_join_seeds(context);
    }

    pub(super) fn begin_join_names(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
        message: Box<ParsedMessage>,
    ) -> Result<(), RuntimeError> {
        let channels = accepted_channels(&frames)?;
        if channels.is_empty() {
            let frames = self.prepare_edge_replies(generation, frames, (0, None), &message)?;
            send_frames(context, generation, frames)?;
            self.finish_join_names(context, generation);
            return Ok(());
        }
        let backing = join_backing_bytes(&channels, &message)?;
        let permit = context
            .prepare_query_snapshot(generation, MAX_JOIN_CHANNELS, backing)?
            .finish(channels.len(), backing)?;
        context
            .sessions_mut()
            .begin_active_query(generation, permit.rows(), permit.bytes())?;
        let state = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        if state.join_names.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        let frames = state.reply_pages.start_continuation(
            state.registration.capability_state(),
            &self.config.server_prefix,
            &message,
            frames,
        )?;
        state.join_names = Some(JoinNamesContinuation::new(
            channels,
            message,
            context.now(),
            permit,
        )?);
        send_frames(context, generation, frames)?;
        self.pump_join_names(context, generation)
    }

    pub(super) fn deliver_join_names(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
        page: (u32, Option<[u8; 32]>),
        message: Box<ParsedMessage>,
    ) -> Result<(), RuntimeError> {
        let pending = self
            .connections
            .get_mut(&generation)
            .and_then(|state| state.join_names.as_mut())
            .ok_or(RuntimeError::InvalidValue)?;
        pending.cursor = page.1;
        self.deliver_join_page(
            context,
            generation,
            frames,
            (page.0, page.1.is_some()),
            message,
        )
    }

    fn deliver_join_page(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        frames: Vec<WireMessage>,
        page: (u32, bool),
        message: Box<ParsedMessage>,
    ) -> Result<(), RuntimeError> {
        let state = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        let pending = state
            .join_names
            .as_mut()
            .ok_or(RuntimeError::InvalidValue)?;
        pending.accept_page(page, &frames, context.now())?;
        let sequence = page.0.checked_add(1).ok_or(RuntimeError::Overflow)?;
        let frames = state.reply_pages.render(
            state.registration.capability_state(),
            &self.config.server_prefix,
            &message,
            frames,
            (sequence, page.1),
        )?;
        if !page.1 {
            pending.source = JoinNamesSource::Edge;
            let permit = pending.permit.take().ok_or(RuntimeError::InvalidValue)?;
            context.sessions_mut().end_active_query(generation);
            context
                .send_query_to(generation, frames, permit)
                .map_err(|_| RuntimeError::LimitExceeded)?;
            self.finish_join_names(context, generation);
            return Ok(());
        }
        pending.request = Some(message);
        send_frames(context, generation, frames)?;
        schedule_check(context, generation)
    }

    fn pump_join_names(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) -> Result<(), RuntimeError> {
        let queue = context
            .sessions()
            .sink_for_generation(generation)
            .ok_or(RuntimeError::InvalidValue)?
            .queue_snapshot();
        let state = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        let pending = state
            .join_names
            .as_mut()
            .ok_or(RuntimeError::InvalidValue)?;
        if pending.expired(context.now()) {
            return Err(RuntimeError::InvalidValue);
        }
        if !below_half(queue) {
            return schedule_check(context, generation);
        }
        let Some(message) = pending.request.take() else {
            return schedule_check(context, generation);
        };
        match &mut pending.source {
            JoinNamesSource::Edge => {
                let edge = self.edge.as_mut().ok_or(RuntimeError::InvalidValue)?;
                if !edge.continue_join_names(
                    context,
                    generation,
                    &pending.channels,
                    message,
                    pending.cursor.take(),
                ) {
                    return Err(RuntimeError::InvalidValue);
                }
                schedule_check(context, generation)
            }
            JoinNamesSource::Local(source) => {
                let (frames, has_next) = source.next_page()?;
                let sequence = pending.page_sequence;
                self.deliver_join_page(context, generation, frames, (sequence, has_next), message)
            }
        }
    }

    pub(super) fn drain_local_join_seeds(&mut self, context: &mut StateCoreContext) {
        while let Some((generation, seed)) = context.take_local_join_seed() {
            if seed
                .and_then(|seed| self.begin_local_join_names(context, generation, seed))
                .is_err()
            {
                self.abort_join_names(context, generation);
            }
        }
    }

    fn begin_local_join_names(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
        seed: LocalJoinNamesSeed,
    ) -> Result<(), RuntimeError> {
        if seed.generation != generation {
            return Err(RuntimeError::InvalidValue);
        }
        let channels = accepted_channels(&seed.frames)?;
        if channels.is_empty() {
            return Err(RuntimeError::InvalidValue);
        }
        let state = self
            .connections
            .get_mut(&generation)
            .ok_or(RuntimeError::InvalidValue)?;
        if state.join_names.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        let frames = state.reply_pages.start_continuation(
            state.registration.capability_state(),
            &self.config.server_prefix,
            &seed.request,
            seed.frames,
        )?;
        state.join_names = Some(JoinNamesContinuation::new_local(
            channels,
            seed.request,
            context.now(),
            Box::new(seed.source),
        )?);
        send_frames(context, generation, frames)?;
        self.pump_join_names(context, generation)
    }

    pub(super) fn join_names_timer(
        &mut self,
        context: &mut StateCoreContext,
        entry: TimerEntry,
    ) -> bool {
        let TimedId::Connection(generation) = entry.id else {
            return false;
        };
        if entry.kind != TimerKind::Batch {
            return false;
        }
        if self
            .connections
            .get(&generation)
            .is_some_and(|state| state.join_names.is_some())
            && self.pump_join_names(context, generation).is_err()
        {
            self.abort_join_names(context, generation);
        }
        self.drain_local_join_seeds(context);
        true
    }

    fn finish_join_names(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        context.sessions_mut().end_active_query(generation);
        if let Some(state) = self.connections.get_mut(&generation) {
            state.join_names = None;
        }
        context
            .timers_mut()
            .cancel(TimerKind::Batch, TimedId::Connection(generation));
        if let Some(edge) = self.edge.as_mut() {
            let completions = edge.finish_join_names(context, generation);
            for completion in completions {
                self.apply_edge_completion(context, completion);
            }
        } else {
            self.resume_join_commands(context, generation);
        }
    }

    pub(super) fn abort_join_names(
        &mut self,
        context: &mut StateCoreContext,
        generation: ConnectionGeneration,
    ) {
        context.sessions_mut().end_active_query(generation);
        if let Some(state) = self.connections.get_mut(&generation) {
            state.join_names = None;
        }
        context
            .timers_mut()
            .cancel(TimerKind::Batch, TimedId::Connection(generation));
        close_transport(context, generation);
    }
}

fn join_backing_bytes(
    channels: &[ChannelNameValue],
    message: &ParsedMessage,
) -> Result<usize, RuntimeError> {
    let fixed = size_of::<ParsedMessage>()
        + size_of::<JoinNamesContinuation>()
        + size_of::<super::replies::ReplyPages>()
        + MAX_JOIN_CHANNELS * size_of::<ChannelNameValue>()
        + JOIN_BATCH_BACKING_BYTES;
    let mut backing = message
        .requested_backing_bytes()
        .checked_add(fixed)
        .ok_or(RuntimeError::Overflow)?;
    for channel in channels {
        backing = backing
            .checked_add(channel.presentation().len())
            .and_then(|bytes| bytes.checked_add(channel.canonical().len()))
            .ok_or(RuntimeError::Overflow)?;
    }
    Ok(backing)
}

fn accepted_channels(frames: &[WireMessage]) -> Result<Vec<ChannelNameValue>, RuntimeError> {
    let mut channels = Vec::new();
    channels
        .try_reserve_exact(MAX_JOIN_CHANNELS)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for frame in frames
        .iter()
        .filter(|frame| matches!(frame.command(), "331" | "332"))
    {
        let name = frame.middle().get(1).ok_or(RuntimeError::InvalidValue)?;
        let name = ChannelNameValue::parse(name).map_err(|_| RuntimeError::InvalidValue)?;
        if channels.len() >= MAX_JOIN_CHANNELS || channels.contains(&name) {
            return Err(RuntimeError::InvalidValue);
        }
        channels.push(name);
    }
    Ok(channels)
}

fn validate_endings(
    channels: &[ChannelNameValue],
    frames: &[WireMessage],
) -> Result<(), RuntimeError> {
    let count = frames
        .iter()
        .filter(|frame| frame.command() == "366")
        .count();
    if count != channels.len() {
        return Err(RuntimeError::InvalidValue);
    }
    for channel in channels {
        let matching = frames
            .iter()
            .filter(|frame| frame.command() == "366")
            .filter(|frame| {
                frame
                    .middle()
                    .get(1)
                    .is_some_and(|name| name.eq_ignore_ascii_case(channel.canonical()))
            })
            .count();
        if matching != 1 {
            return Err(RuntimeError::InvalidValue);
        }
    }
    Ok(())
}

fn below_half(queue: ClientQueueSnapshot) -> bool {
    queue.queued_bytes() < queue.capacity_bytes().div_ceil(2)
}

fn schedule_check(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
) -> Result<(), RuntimeError> {
    let deadline = context
        .now()
        .get()
        .checked_add(QUEUE_CHECK_MILLIS)
        .ok_or(RuntimeError::Overflow)?;
    context.timers_mut().schedule(
        MonotonicTick::from_ticks(deadline),
        TimerKind::Batch,
        TimedId::Connection(generation),
    )?;
    Ok(())
}

fn send_frames(
    context: &mut StateCoreContext,
    generation: ConnectionGeneration,
    frames: Vec<WireMessage>,
) -> Result<(), RuntimeError> {
    if !frames.is_empty() {
        context
            .send_to(generation, frames)
            .map_err(|_| RuntimeError::LimitExceeded)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_relay_client_wire::numeric_reply;

    type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;

    #[test]
    fn a_large_valid_join_charges_its_retained_tags_and_all_channel_names() -> TestResult {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut tags = Vec::new();
        for index in 0..1_365 {
            let first = *ALPHABET
                .get(index / ALPHABET.len())
                .ok_or("tag high byte")?;
            let second = *ALPHABET.get(index % ALPHABET.len()).ok_or("tag low byte")?;
            tags.push(format!("{}{}", char::from(first), char::from(second)));
        }
        let names: Vec<_> = (0..MAX_JOIN_CHANNELS)
            .map(|index| format!("#{index:02}{}", "r".repeat(61)))
            .collect();
        let keys: Vec<_> = (0..MAX_JOIN_CHANNELS)
            .map(|index| format!("{index:02}{}", "k".repeat(62)))
            .collect();
        let line = format!(
            "@{} JOIN {} {}",
            tags.join(";"),
            names.join(","),
            keys.join(",")
        );
        let message = agenc_relay_client_wire::parse_message(
            agenc_relay_client_wire::FramedLine::new(&line)?,
        )?
        .ok_or("empty JOIN")?;
        agenc_relay_client_wire::validate_post_registration_command(&message)?;
        let channels = names
            .iter()
            .map(|name| ChannelNameValue::parse(name))
            .collect::<Result<Vec<_>, _>>()?;
        let retained = message.requested_backing_bytes()
            + size_of::<ParsedMessage>()
            + size_of::<JoinNamesContinuation>()
            + MAX_JOIN_CHANNELS * size_of::<ChannelNameValue>()
            + names.iter().map(|name| name.len() * 2).sum::<usize>();
        assert!(retained > 16_384);
        assert!(join_backing_bytes(&channels, &message)? >= retained);
        Ok(())
    }

    #[test]
    fn a_join_continuation_fetches_only_below_half_the_queue() {
        assert!(below_half(ClientQueueSnapshot::new(499, 1_000)));
        assert!(!below_half(ClientQueueSnapshot::new(500, 1_000)));
        assert!(!below_half(ClientQueueSnapshot::new(501, 1_000)));
        assert!(!below_half(ClientQueueSnapshot::new(0, 0)));
        assert!(below_half(ClientQueueSnapshot::new(2, 5)));
        assert!(!below_half(ClientQueueSnapshot::new(3, 5)));
    }

    #[test]
    fn join_endings_cover_every_accepted_channel_exactly_once() -> TestResult {
        let channels = vec![
            ChannelNameValue::parse("#one")?,
            ChannelNameValue::parse("#two")?,
        ];
        let one = || {
            numeric_reply(
                "edge.test",
                366,
                "sam",
                &["#one"],
                Some("End of NAMES list"),
            )
        };
        let two = || {
            numeric_reply(
                "edge.test",
                366,
                "sam",
                &["#two"],
                Some("End of NAMES list"),
            )
        };
        assert!(validate_endings(&channels, &[one()?, two()?]).is_ok());
        assert_eq!(
            validate_endings(&channels, &[one()?]),
            Err(RuntimeError::InvalidValue)
        );
        assert_eq!(
            validate_endings(&channels, &[one()?, one()?]),
            Err(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn accepted_join_names_are_bounded_and_exclude_failed_targets() -> TestResult {
        let frames = vec![
            numeric_reply(
                "edge.test",
                331,
                "sam",
                &["#accepted"],
                Some("No topic is set"),
            )?,
            numeric_reply(
                "edge.test",
                473,
                "sam",
                &["#refused"],
                Some("Cannot join channel"),
            )?,
        ];
        assert!(accepted_channels(&frames)? == vec![ChannelNameValue::parse("#accepted")?]);
        let mut many = Vec::new();
        for index in 0..=MAX_JOIN_CHANNELS {
            many.push(numeric_reply(
                "edge.test",
                331,
                "sam",
                &[&format!("#channel{index}")],
                Some("No topic is set"),
            )?);
        }
        assert!(matches!(
            accepted_channels(&many),
            Err(RuntimeError::InvalidValue)
        ));
        Ok(())
    }

    fn continuation(request: Option<Box<ParsedMessage>>) -> TestResult<JoinNamesContinuation> {
        Ok(JoinNamesContinuation {
            channels: vec![ChannelNameValue::parse("#one")?],
            request,
            cursor: None,
            page_sequence: 0,
            idle_deadline: 1_000,
            absolute_deadline: 5_000,
            source: JoinNamesSource::Edge,
            permit: None,
        })
    }

    fn join_request() -> TestResult<Box<ParsedMessage>> {
        Ok(Box::new(
            agenc_relay_client_wire::parse_message(agenc_relay_client_wire::FramedLine::new(
                "JOIN #one",
            )?)?
            .ok_or("empty JOIN")?,
        ))
    }

    fn ending(channel: &str) -> TestResult<WireMessage> {
        let frame = numeric_reply(
            "edge.test",
            366,
            "sam",
            &[channel],
            Some("End of NAMES list"),
        )?;
        Ok(frame)
    }

    #[test]
    fn a_join_continuation_expires_at_its_idle_or_absolute_deadline() -> TestResult {
        let mut pending = continuation(None)?;
        assert!(!pending.expired(MonotonicTick::from_ticks(999)));
        assert!(pending.expired(MonotonicTick::from_ticks(1_000)));
        pending.idle_deadline = 9_000;
        assert!(!pending.expired(MonotonicTick::from_ticks(4_999)));
        assert!(pending.expired(MonotonicTick::from_ticks(5_000)));
        Ok(())
    }

    #[test]
    fn a_page_is_refused_while_the_request_is_still_held() -> TestResult {
        let mut pending = continuation(Some(join_request()?))?;
        assert_eq!(
            pending.accept_page((0, true), &[], MonotonicTick::from_ticks(1)),
            Err(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn a_page_out_of_sequence_or_after_the_deadline_is_refused() -> TestResult {
        let mut pending = continuation(None)?;
        assert_eq!(
            pending.accept_page((1, true), &[], MonotonicTick::from_ticks(1)),
            Err(RuntimeError::InvalidValue)
        );
        assert_eq!(
            pending.accept_page((0, true), &[], MonotonicTick::from_ticks(1_000)),
            Err(RuntimeError::InvalidValue)
        );
        Ok(())
    }

    #[test]
    fn a_continued_page_may_not_end_any_names_list() -> TestResult {
        let mut pending = continuation(None)?;
        assert_eq!(
            pending.accept_page((0, true), &[ending("#one")?], MonotonicTick::from_ticks(1)),
            Err(RuntimeError::InvalidValue)
        );
        assert_eq!(
            pending.accept_page((0, false), &[], MonotonicTick::from_ticks(1)),
            Err(RuntimeError::InvalidValue),
            "the final page must end every accepted channel"
        );
        Ok(())
    }

    #[test]
    fn an_accepted_page_advances_the_sequence_and_the_idle_deadline() -> TestResult {
        let mut pending = continuation(None)?;
        pending.accept_page((0, true), &[], MonotonicTick::from_ticks(7))?;
        assert_eq!(pending.page_sequence, 1);
        assert_eq!(pending.idle_deadline, 7 + IDLE_MILLIS);
        pending.accept_page((1, false), &[ending("#ONE")?], MonotonicTick::from_ticks(8))?;
        assert_eq!(pending.page_sequence, 2);
        assert_eq!(pending.idle_deadline, 8 + IDLE_MILLIS);
        Ok(())
    }

    #[test]
    fn accepted_join_names_refuse_a_repeated_target() -> TestResult {
        let topic = || {
            numeric_reply(
                "edge.test",
                331,
                "sam",
                &["#twice"],
                Some("No topic is set"),
            )
        };
        assert!(matches!(
            accepted_channels(&[topic()?, topic()?]),
            Err(RuntimeError::InvalidValue)
        ));
        Ok(())
    }
}
