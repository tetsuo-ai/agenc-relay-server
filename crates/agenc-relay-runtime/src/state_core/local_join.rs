//! Bounded local JOIN snapshots prepared before admission and opened after commit.

use super::{StateCoreContext, session::BoundSession};
use crate::RuntimeError;
use crate::budget::{BoundedMemoryCharges, MemoryBudgetPort, MemoryCharge, MemoryPermit};
use crate::client_render::ReplyInput;
use crate::connection::{ConnectionGeneration, sink::QuerySnapshotPermit};
use crate::query_pages::{ReplySize, page_count};
use agenc_relay_client_wire::{ParsedMessage, WireMessage};
use agenc_relay_domain::{
    CanonicalCommand, CanonicalCommandView, ChannelNameValue, DomainEvent, MutationPlan,
};
use zeroize::Zeroizing;

const MAX_JOIN_CHANNELS: usize = 20;
const NAMES_CHUNK_BYTES: usize = 8_000;
// One role byte and the longest framed user mask: a 32-byte nickname, `!`,
// `u-<10>`, `@` and `h-<16>.invalid`, 73 bytes in all.
const MAX_NAMES_TOKEN_BYTES: usize = 1 + agenc_relay_client_wire::MAX_USER_MASK_BYTES;
// A chunk is flushed only when the next token and its separator overflow it,
// so every chunk but the last holds at least this many tokens.
const MIN_FULL_CHUNK_ROWS: usize = NAMES_CHUNK_BYTES / (MAX_NAMES_TOKEN_BYTES + 1);
// The bounded original parsed command, topic/failure prefix, and scratch chunks.
const FIXED_BACKING_BYTES: usize = 262_144;

#[derive(Default)]
pub(super) struct LocalJoins {
    pending: Vec<PreparedLocalJoin>,
    // Fields drop in declaration order: release the allocation before its charge.
    capacity_permit: Option<MemoryPermit>,
}

pub(crate) struct PreparedLocalJoin {
    generation: ConnectionGeneration,
    revision: agenc_relay_types::Revision,
    committed: bool,
    bound: BoundSession,
    channels: Vec<ChannelNameValue>,
    include_userhost: bool,
    request: Option<Box<ParsedMessage>>,
    pub(crate) frames: Vec<WireMessage>,
    permit: QuerySnapshotPermit,
    max_rows: usize,
    max_frames: usize,
}

pub(crate) struct LocalJoinNamesSeed {
    pub(crate) generation: ConnectionGeneration,
    pub(crate) request: Box<ParsedMessage>,
    pub(crate) frames: Vec<WireMessage>,
    pub(crate) source: LocalJoinNames,
}

pub(crate) struct LocalJoinNames {
    frames: Vec<WireMessage>,
    sizes: Vec<ReplySize>,
    terminal_count: usize,
    permit: Option<QuerySnapshotPermit>,
}

impl LocalJoins {
    fn reserve(&mut self, budget: &dyn MemoryBudgetPort) -> Result<(), RuntimeError> {
        if self.capacity_permit.is_some() {
            return Ok(());
        }
        let capacity = agenc_relay_storage::MAX_TRANSACTION_PLANS;
        let bytes = capacity
            .checked_mul(size_of::<PreparedLocalJoin>())
            .ok_or(RuntimeError::Overflow)?;
        let charge =
            MemoryCharge::allocation(u64::try_from(bytes).map_err(|_| RuntimeError::Overflow)?)?;
        let permit = budget
            .try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?
            .split_exact(charge.bytes())
            .ok_or(RuntimeError::InvalidValue)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(capacity)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        if pending.capacity() != capacity {
            return Err(RuntimeError::MemoryExhausted);
        }
        self.pending = pending;
        self.capacity_permit = Some(permit);
        Ok(())
    }

    pub(super) fn committed(&mut self, revision: agenc_relay_types::Revision) {
        for seed in &mut self.pending {
            if seed.revision == revision {
                seed.committed = true;
            }
        }
    }
}

impl LocalJoinNames {
    pub(crate) fn next_page(&mut self) -> Result<(Vec<WireMessage>, bool), RuntimeError> {
        let count = page_count(&self.sizes, self.terminal_count)?;
        if count == self.frames.len() {
            self.terminal_count = 0;
        }
        self.sizes.drain(..count);
        let frames = self.frames.drain(..count).collect();
        Ok((frames, !self.frames.is_empty()))
    }

    pub(crate) fn take_permit(&mut self) -> Result<QuerySnapshotPermit, RuntimeError> {
        self.permit.take().ok_or(RuntimeError::InvalidValue)
    }
}

impl StateCoreContext {
    pub(crate) fn has_local_join_seed(&self, generation: ConnectionGeneration) -> bool {
        self.local_joins
            .pending
            .iter()
            .any(|seed| seed.generation == generation)
    }

    pub(crate) fn prepare_local_join(
        &mut self,
        bound: BoundSession,
        reply: Option<ReplyInput<'_>>,
        command: &CanonicalCommand,
        plan: &MutationPlan,
    ) -> Result<Option<PreparedLocalJoin>, RuntimeError> {
        let Some(reply) = reply else {
            return Ok(None);
        };
        let channels = accepted_channels(command, plan, bound)?;
        if channels.is_empty() {
            return Ok(None);
        }
        if self.local_joins.pending.len() >= agenc_relay_storage::MAX_TRANSACTION_PLANS {
            return Err(RuntimeError::LimitExceeded);
        }
        let rows = maximum_rows(self, &channels)?;
        let max_frames = rows / MIN_FULL_CHUNK_ROWS + channels.len() * 2;
        let backing = backing_bytes(rows, max_frames)?;
        let permit = self
            .prepare_query_snapshot(reply.generation, rows, backing)?
            .finish(rows, backing)?;
        self.local_joins.reserve(self.budget.as_ref())?;
        self.sessions
            .begin_active_query(reply.generation, permit.rows(), permit.bytes())?;
        Ok(Some(PreparedLocalJoin {
            generation: reply.generation,
            revision: plan.resulting_revision(),
            committed: false,
            bound,
            channels,
            include_userhost: reply.capabilities.enabled("userhost-in-names"),
            request: None,
            frames: Vec::new(),
            permit,
            max_rows: rows,
            max_frames,
        }))
    }

    pub(crate) fn settle_local_join(
        &mut self,
        prepared: Option<PreparedLocalJoin>,
        accepted: bool,
    ) {
        let Some(prepared) = prepared else {
            return;
        };
        if accepted {
            self.local_joins.pending.push(prepared);
        } else {
            self.sessions.end_active_query(prepared.generation);
        }
    }

    /// Moves the original label context without retaining a second parsed command.
    pub(crate) fn attach_local_join_request(
        &mut self,
        generation: ConnectionGeneration,
        mut request: ParsedMessage,
    ) {
        let Some(seed) = self
            .local_joins
            .pending
            .iter_mut()
            .find(|seed| seed.generation == generation)
        else {
            return;
        };
        let _erased_key = request.take_parameter(1).map(Zeroizing::new);
        seed.request = Some(Box::new(request));
    }

    pub(crate) fn take_local_join_seed(
        &mut self,
    ) -> Option<(
        ConnectionGeneration,
        Result<LocalJoinNamesSeed, RuntimeError>,
    )> {
        let index = self
            .local_joins
            .pending
            .iter()
            .position(|seed| seed.committed)?;
        let prepared = self.local_joins.pending.remove(index);
        let generation = prepared.generation;
        let seed = prepared.open(self);
        if seed.is_err() {
            self.sessions.end_active_query(generation);
        }
        Some((generation, seed))
    }

    pub(crate) fn discard_local_join_seeds(&mut self) {
        for seed in self.local_joins.pending.drain(..) {
            self.sessions.end_active_query(seed.generation);
        }
    }

    pub(crate) fn close_local_join_seed(&mut self, generation: ConnectionGeneration) {
        self.local_joins
            .pending
            .retain(|seed| seed.generation != generation);
        self.sessions.end_active_query(generation);
    }
}

impl PreparedLocalJoin {
    fn open(mut self, context: &StateCoreContext) -> Result<LocalJoinNamesSeed, RuntimeError> {
        let bound = context
            .sessions
            .connection(self.generation)
            .and_then(|entry| entry.session());
        if bound != Some(self.bound) {
            return Err(RuntimeError::InvalidValue);
        }
        let nickname = crate::client_render::requester_nickname(context, self.bound.user_id);
        let frames = crate::query_render::render_names(
            context.domain(),
            context.server_prefix(),
            &nickname,
            self.bound.user_id,
            self.include_userhost,
            &self.channels,
        )?;
        if frames.len() > self.max_frames {
            return Err(RuntimeError::LimitExceeded);
        }
        let sizes = measure_names(&frames)?;
        let rows = sizes
            .iter()
            .try_fold(0_usize, |sum, size| sum.checked_add(size.names_users))
            .ok_or(RuntimeError::Overflow)?;
        if rows > self.max_rows {
            return Err(RuntimeError::LimitExceeded);
        }
        let terminal_count = self.channels.len();
        Ok(LocalJoinNamesSeed {
            generation: self.generation,
            request: self.request.take().ok_or(RuntimeError::InvalidValue)?,
            frames: self.frames,
            source: LocalJoinNames {
                frames,
                sizes,
                terminal_count,
                permit: Some(self.permit),
            },
        })
    }
}

fn accepted_channels(
    command: &CanonicalCommand,
    plan: &MutationPlan,
    bound: BoundSession,
) -> Result<Vec<ChannelNameValue>, RuntimeError> {
    let CanonicalCommandView::Join(targets) = command.view() else {
        return Ok(Vec::new());
    };
    let accepted = plan
        .events()
        .iter()
        .filter(|event| matches!(event, DomainEvent::Joined(_, user) if *user == bound.user_id))
        .count();
    if accepted == 0 {
        return Ok(Vec::new());
    }
    let mut channels = Vec::new();
    channels
        .try_reserve_exact(accepted)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for (index, target) in targets.iter().enumerate() {
        if !plan
            .failures()
            .iter()
            .any(|failure| usize::from(failure.target_index()) == index)
        {
            channels.push(target.name().clone());
        }
    }
    if channels.len() != accepted || channels.len() > MAX_JOIN_CHANNELS {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(channels)
}

fn maximum_rows(
    context: &StateCoreContext,
    channels: &[ChannelNameValue],
) -> Result<usize, RuntimeError> {
    channels.iter().try_fold(0_usize, |sum, name| {
        let members = context
            .domain()
            .resolve_channel(name)
            .and_then(|id| context.domain().channel(id))
            .map_or(0, |channel| channel.members().count());
        sum.checked_add(members)
            .and_then(|sum| sum.checked_add(1))
            .ok_or(RuntimeError::Overflow)
    })
}

fn backing_bytes(rows: usize, frames: usize) -> Result<usize, RuntimeError> {
    let frame_bytes = agenc_relay_client_wire::MAX_COMMAND_BYTES
        + 2 * std::mem::size_of::<WireMessage>()
        + 3 * std::mem::size_of::<String>()
        + std::mem::size_of::<ReplySize>();
    let projection_bytes = rows
        .checked_mul(2 * std::mem::size_of::<agenc_relay_domain::MemberProjection<'static>>())
        .ok_or(RuntimeError::Overflow)?;
    frames
        .checked_mul(frame_bytes)
        .and_then(|bytes| bytes.checked_add(projection_bytes))
        .and_then(|bytes| bytes.checked_add(FIXED_BACKING_BYTES))
        .ok_or(RuntimeError::Overflow)
}

fn measure_names(frames: &[WireMessage]) -> Result<Vec<ReplySize>, RuntimeError> {
    let mut sizes = Vec::new();
    sizes
        .try_reserve_exact(frames.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for frame in frames {
        sizes.push(ReplySize {
            encoded: 0,
            rendered: frame
                .measure()
                .map_err(|_| RuntimeError::InvalidValue)?
                .bytes(),
            names_users: if frame.command() == "353" {
                frame
                    .trailing()
                    .map_or(0, |text| text.split_ascii_whitespace().count())
            } else {
                0
            },
        });
    }
    Ok(sizes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_core::fanout::FanoutRequest;
    use crate::test_support::{self, StateCoreFixture, TestResult};
    use agenc_relay_client_wire::{FramedLine, parse_message};
    use agenc_relay_domain::{ChannelTarget, PlanDecision};

    struct JoinFixture {
        fixture: StateCoreFixture,
        prepared: PreparedLocalJoin,
        plan: MutationPlan,
        fanout: FanoutRequest,
        request: ParsedMessage,
        peer: agenc_relay_testkit::DomainTestIdentity,
        owner_sink: crate::sync::Arc<test_support::FrameSink>,
        peer_sink: crate::sync::Arc<test_support::FrameSink>,
    }

    async fn prepared_join() -> TestResult<JoinFixture> {
        let entropy = (0..8_192)
            .map(|value| u8::try_from(value % 251).unwrap_or(0))
            .collect();
        let mut fixture = StateCoreFixture::new(entropy)?;
        let context = fixture.context_mut()?;
        let owner = test_support::seed_session(context, 1, "NamesOwner", None)?;
        let peer = test_support::seed_session(context, 2, "NamesPeer", None)?;
        let channel = ChannelNameValue::parse("#local-names")?;
        let command = || CanonicalCommand::join(vec![ChannelTarget::new(channel.clone(), false)]);
        let PlanDecision::Mutation(plan) = test_support::plan_live(context, peer, &command)? else {
            return Err("peer JOIN plan".into());
        };
        context
            .stage_durable(plan, FanoutRequest::new(Vec::new(), Vec::new())?, None, 0)
            .map_err(|error| format!("peer stage: {error:?}"))?;
        fixture.commit_staged_batch().await?;
        let context = fixture.context_mut()?;
        let caps = || {
            test_support::negotiated_capabilities(&[
                "message-tags",
                "batch",
                "labeled-response",
                "account-notify",
                "extended-join",
            ])
        };
        let owner_sink = test_support::bind_live_session(context, 1, owner, caps()?, true)?;
        let peer_sink = test_support::bind_live_session(context, 2, peer, caps()?, true)?;
        let capabilities = caps()?;
        let request = parse_message(FramedLine::new(
            "@label=joining JOIN #local-names key-material",
        )?)?
        .ok_or("request")?;
        let reply = ReplyInput {
            requester: owner.user_id,
            generation: ConnectionGeneration::new(1),
            capabilities: &capabilities,
            request: &request,
        };
        let command = command()?;
        let PlanDecision::Mutation(plan) = test_support::plan_live(context, owner, &|| {
            CanonicalCommand::join(vec![ChannelTarget::new(channel.clone(), false)])
        })?
        else {
            return Err("owner JOIN plan".into());
        };
        let mut prepared = context
            .prepare_local_join(test_support::bound(owner), Some(reply), &command, &plan)?
            .ok_or("prepared snapshot")?;
        let (fanout, frames) = crate::mutation_render::render_local_join_start(
            context,
            test_support::bound(owner),
            reply,
            &command,
            &plan,
        )?;
        prepared.frames = frames;
        Ok(JoinFixture {
            fixture,
            prepared,
            plan,
            fanout,
            request,
            peer,
            owner_sink,
            peer_sink,
        })
    }

    #[tokio::test]
    async fn local_join_snapshot_opens_after_commit_and_keeps_its_membership_preimage() -> TestResult
    {
        let JoinFixture {
            mut fixture,
            prepared,
            plan,
            fanout,
            request,
            peer,
            owner_sink,
            peer_sink,
        } = prepared_join().await?;
        let generation = ConnectionGeneration::new(1);
        let context = fixture.context_mut()?;
        context
            .stage_durable(plan, fanout, None, 0)
            .map_err(|error| format!("owner stage: {error:?}"))?;
        context.settle_local_join(Some(prepared), true);
        context.attach_local_join_request(generation, request);
        assert!(context.take_local_join_seed().is_none());
        assert!(owner_sink.lines().is_empty());
        assert!(peer_sink.lines().is_empty());
        assert_eq!(context.sessions.queue_snapshot().query_snapshots(), 1);
        fixture.commit_staged_batch().await?;
        let context = fixture.context_mut()?;
        let (_, seed) = context.take_local_join_seed().ok_or("committed seed")?;
        let mut seed = seed?;
        assert!(
            owner_sink.lines().is_empty(),
            "the requester JOIN must join the logical response batch"
        );
        assert_eq!(peer_sink.lines().len(), 1);
        assert_eq!(
            seed.frames
                .iter()
                .map(WireMessage::command)
                .collect::<Vec<_>>(),
            vec!["JOIN", "331"]
        );
        assert_eq!(seed.request.middle().get(1).map(String::as_str), Some(""));
        let PlanDecision::Mutation(rename) = test_support::plan_live(context, peer, &|| {
            Ok(CanonicalCommand::nick(
                agenc_relay_domain::NicknameValue::parse("RenamedPeer")?,
            ))
        })?
        else {
            return Err("rename plan".into());
        };
        test_support::apply_live_plan(context, rename)?;
        let (page, more) = seed.source.next_page()?;
        assert!(!more);
        assert_eq!(
            page.iter().map(WireMessage::command).collect::<Vec<_>>(),
            vec!["353", "366"]
        );
        assert!(
            page.first()
                .and_then(WireMessage::trailing)
                .is_some_and(|text| text.contains("NamesPeer") && !text.contains("RenamedPeer"))
        );
        let permit = seed.source.take_permit()?;
        drop(seed);
        let before = context.budget.available();
        let bytes = permit.bytes();
        context.sessions.end_active_query(generation);
        drop(permit);
        assert_eq!(context.budget.available(), before + bytes);
        assert_eq!(context.sessions.queue_snapshot().query_snapshots(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_committed_local_join_opens_while_the_next_batch_is_pending() -> TestResult {
        let JoinFixture {
            mut fixture,
            prepared,
            plan,
            fanout,
            request,
            peer,
            owner_sink: _owner_sink,
            peer_sink: _peer_sink,
        } = prepared_join().await?;
        let generation = ConnectionGeneration::new(1);
        let context = fixture.context_mut()?;
        context
            .stage_durable(plan, fanout, None, 0)
            .map_err(|error| format!("JOIN stage: {error:?}"))?;
        context.settle_local_join(Some(prepared), true);
        context.attach_local_join_request(generation, request);
        assert!(context.take_local_join_seed().is_none());
        fixture.commit_staged_batch().await?;
        let context = fixture.context_mut()?;
        let PlanDecision::Mutation(next) = test_support::plan_live(context, peer, &|| {
            CanonicalCommand::presence(agenc_relay_domain::PresenceCommand::Away(Some(
                agenc_relay_domain::AwayText::try_from_str(
                    "next batch",
                    agenc_relay_types::ControlPolicy::RejectAll,
                )?,
            )))
        })?
        else {
            return Err("next plan".into());
        };
        context
            .stage_durable(next, FanoutRequest::new(Vec::new(), Vec::new())?, None, 0)
            .map_err(|error| format!("next stage: {error:?}"))?;
        assert_eq!(context.pending_len(), 1);
        let (_, seed) = context
            .take_local_join_seed()
            .ok_or("the JOIN is already committed")?;
        let mut seed = seed?;
        let (page, more) = seed.source.next_page()?;
        assert!(!more);
        assert_eq!(
            page.iter().map(WireMessage::command).collect::<Vec<_>>(),
            vec!["353", "366"]
        );
        context.sessions.end_active_query(generation);
        drop(seed);
        assert_eq!(context.pending_len(), 1);
        Ok(())
    }

    #[test]
    fn a_chained_join_cannot_grow_another_join_snapshot_in_the_same_batch() -> TestResult {
        use crate::state_core::fanout::FanoutReservation;
        use crate::state_core::pending::{PendingMutationBatch, StageRefusal, StagedPlan};
        use agenc_relay_domain::{DomainState, ExternalInputs};
        use agenc_relay_types::{MonotonicTick, UtcSecond};
        let mut state = DomainState::new()?;
        let owner = agenc_relay_testkit::open_session(&mut state, 1, "FirstJoin", None)?;
        let other = agenc_relay_testkit::open_session(&mut state, 2, "SecondJoin", None)?;
        let channel = ChannelNameValue::parse("#one-batch")?;
        let plan_join = |state: &DomainState, identity| -> TestResult<MutationPlan> {
            let PlanDecision::Mutation(plan) = agenc_relay_testkit::plan(
                state,
                identity,
                CanonicalCommand::join(vec![ChannelTarget::new(channel.clone(), false)])?,
                &agenc_relay_testkit::registered_admission(identity.user_id)?,
                Some(ExternalInputs {
                    utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_000)),
                    channel_ids: state
                        .resolve_channel(&channel)
                        .is_none()
                        .then(|| agenc_relay_testkit::channel_id(80))
                        .into_iter()
                        .collect(),
                    ..ExternalInputs::default()
                }),
            )?
            else {
                return Err("JOIN mutation".into());
            };
            Ok(plan)
        };
        let first = plan_join(&state, owner)?;
        let replay = plan_join(&state, owner)?;
        agenc_relay_testkit::apply_plan(&mut state, replay)?;
        let second = plan_join(&state, other)?;
        assert_eq!(first.resulting_revision(), second.expected_revision());
        let staged = |plan| {
            StagedPlan::with_account_service_writes(
                plan,
                FanoutReservation::empty(),
                None,
                0,
                Vec::new(),
            )
        };
        let mut batch = PendingMutationBatch::start(staged(first), MonotonicTick::from_ticks(0))
            .map_err(|_| "first staged JOIN")?;
        assert!(matches!(
            batch.try_stage(staged(second)),
            Err((StageRefusal::Incompatible, _))
        ));
        assert_eq!(batch.len(), 1);
        Ok(())
    }

    async fn refuse_retired_join_generation(replace: bool) -> TestResult {
        let JoinFixture {
            mut fixture,
            prepared,
            plan,
            fanout,
            request,
            peer: _peer,
            owner_sink,
            peer_sink: _peer_sink,
        } = prepared_join().await?;
        let generation = ConnectionGeneration::new(1);
        let context = fixture.context_mut()?;
        context
            .stage_durable(plan, fanout, None, 0)
            .map_err(|error| format!("JOIN stage: {error:?}"))?;
        context.settle_local_join(Some(prepared), true);
        context.attach_local_join_request(generation, request);
        fixture.commit_staged_batch().await?;
        let context = fixture.context_mut()?;
        let prepared = context.local_joins.pending.pop().ok_or("committed seed")?;
        assert!(prepared.committed);
        assert!(matches!(
            context
                .domain()
                .project_session(prepared.bound.user_id, prepared.bound.user_id),
            agenc_relay_domain::ProjectionDecision::Visible(_)
        ));
        let _closed = context.sessions.close(generation).ok_or("old connection")?;
        let replacement = if replace {
            let stranger = test_support::seed_session(context, 3, "NamesStranger", None)?;
            Some(test_support::bind_live_session(
                context,
                1,
                stranger,
                test_support::negotiated_capabilities(&[])?,
                true,
            )?)
        } else {
            None
        };
        let before = context.budget.available();
        let bytes = prepared.permit.bytes();
        assert!(matches!(
            prepared.open(context),
            Err(RuntimeError::InvalidValue)
        ));
        assert_eq!(context.budget.available(), before + bytes);
        assert_eq!(context.sessions.queue_snapshot().query_snapshots(), 0);
        assert!(owner_sink.lines().is_empty());
        assert!(replacement.is_none_or(|sink| sink.lines().is_empty()));
        Ok(())
    }

    #[tokio::test]
    async fn a_committed_local_join_refuses_closed_or_rebound_generations() -> TestResult {
        refuse_retired_join_generation(false).await?;
        refuse_retired_join_generation(true).await
    }

    #[tokio::test]
    async fn a_refused_local_join_releases_its_reserved_snapshot() -> TestResult {
        let JoinFixture {
            mut fixture,
            prepared,
            plan: _plan,
            fanout: _fanout,
            request: _request,
            peer: _peer,
            owner_sink,
            peer_sink,
        } = prepared_join().await?;
        let context = fixture.context_mut()?;
        let before = context.budget.available();
        let bytes = prepared.permit.bytes();
        context.settle_local_join(Some(prepared), false);
        assert_eq!(context.budget.available(), before + bytes);
        assert_eq!(context.sessions.queue_snapshot().query_snapshots(), 0);
        assert!(context.take_local_join_seed().is_none());
        assert!(owner_sink.lines().is_empty());
        assert!(peer_sink.lines().is_empty());
        Ok(())
    }

    fn prepare_repeated_local_join(
        context: &mut StateCoreContext,
        bound: BoundSession,
        plan: &MutationPlan,
        request: &ParsedMessage,
    ) -> TestResult<PreparedLocalJoin> {
        let capabilities = test_support::negotiated_capabilities(&[])?;
        let reply = ReplyInput {
            requester: bound.user_id,
            generation: ConnectionGeneration::new(1),
            capabilities: &capabilities,
            request,
        };
        let command = CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse("#local-names")?,
            false,
        )])?;
        context
            .prepare_local_join(bound, Some(reply), &command, plan)?
            .ok_or_else(|| "repeated snapshot".into())
    }

    #[tokio::test]
    async fn local_join_capacity_stays_charged_through_cleanup_and_reuse() -> TestResult {
        let mut fixture = prepared_join().await?;
        let context = fixture.fixture.context_mut()?;
        let bound = fixture.prepared.bound;
        let available_without_snapshot =
            context.budget.available() + fixture.prepared.permit.bytes();
        let allocation = context.local_joins.pending.as_ptr();
        context.settle_local_join(Some(fixture.prepared), false);
        for close in [true, false, true, false] {
            assert_eq!(context.budget.available(), available_without_snapshot);
            let prepared =
                prepare_repeated_local_join(context, bound, &fixture.plan, &fixture.request)?;
            context.settle_local_join(Some(prepared), true);
            assert_eq!(context.local_joins.pending.len(), 1);
            if close {
                context.close_local_join_seed(ConnectionGeneration::new(1));
            } else {
                context.discard_local_join_seeds();
            }
            assert!(context.local_joins.pending.is_empty());
            assert_eq!(context.local_joins.pending.as_ptr(), allocation);
            assert_eq!(context.sessions.queue_snapshot().query_snapshots(), 0);
        }
        let backing = context
            .local_joins
            .pending
            .capacity()
            .checked_mul(size_of::<PreparedLocalJoin>())
            .ok_or("capacity overflow")?;
        let retained_charge = MemoryCharge::allocation(u64::try_from(backing)?)?.bytes();
        assert!(retained_charge > 0);
        assert_eq!(context.budget.available(), available_without_snapshot);
        drop(std::mem::take(&mut context.local_joins));
        assert_eq!(
            context.budget.available(),
            available_without_snapshot + retained_charge,
            "the retained allocation must own its charge after every seed is gone"
        );
        assert!(fixture.owner_sink.lines().is_empty());
        assert!(fixture.peer_sink.lines().is_empty());
        Ok(())
    }

    /// AUD-18: with `userhost-in-names` a NAMES token is an optional role
    /// byte and a framed user mask, at most 73 bytes for a 32-byte nickname.
    /// Here only the founder's token carries a role byte, so 218 of the 219
    /// tokens are 72 bytes and the two full chunks hold 109 each. The channel
    /// needs three 353 chunks and the 366, and the snapshot's frame bound
    /// must admit all four; under the bare-cloak bound of 61 bytes it
    /// admitted three and refused the JOIN's NAMES with `LimitExceeded`. The
    /// next test holds the bound at its worst case, every token 73 bytes.
    #[test]
    fn a_local_join_of_the_longest_framed_tokens_fits_its_frame_bound() -> TestResult {
        let entropy = (0..8_192)
            .map(|value| u8::try_from(value % 251).unwrap_or(0))
            .collect();
        let mut fixture = StateCoreFixture::new(entropy)?;
        let context = fixture.context_mut()?;
        let channel = ChannelNameValue::parse("#longest-tokens")?;
        let command = || CanonicalCommand::join(vec![ChannelTarget::new(channel.clone(), false)]);
        for seed in 1..=218_u8 {
            let member = test_support::seed_session(context, seed, &format!("M{seed:031}"), None)?;
            let PlanDecision::Mutation(plan) = test_support::plan_live(context, member, &command)?
            else {
                return Err("member JOIN plan".into());
            };
            test_support::apply_live_plan(context, plan)?;
        }
        let requester = test_support::seed_session(context, 219, &format!("R{:031}", 219), None)?;
        let names_caps = || test_support::negotiated_capabilities(&["userhost-in-names"]);
        let _sink = test_support::bind_live_session(context, 1, requester, names_caps()?, true)?;
        let capabilities = names_caps()?;
        let request = parse_message(FramedLine::new("JOIN #longest-tokens")?)?.ok_or("request")?;
        let reply = ReplyInput {
            requester: requester.user_id,
            generation: ConnectionGeneration::new(1),
            capabilities: &capabilities,
            request: &request,
        };
        let PlanDecision::Mutation(plan) = test_support::plan_live(context, requester, &command)?
        else {
            return Err("requester JOIN plan".into());
        };
        let mut prepared = context
            .prepare_local_join(
                test_support::bound(requester),
                Some(reply),
                &command()?,
                &plan,
            )?
            .ok_or("prepared snapshot")?;
        let bounds = (prepared.max_rows, prepared.max_frames);
        test_support::apply_live_plan(context, plan)?;
        prepared.request = Some(Box::new(request));
        let seed = prepared.open(context)?;
        assert_eq!(bounds, (219, 4));
        let frames = &seed.source.frames;
        assert_eq!(
            frames.iter().map(WireMessage::command).collect::<Vec<_>>(),
            vec!["353", "353", "353", "366"]
        );
        let chunks: Vec<&str> = frames.iter().filter_map(WireMessage::trailing).collect();
        let tokens: Vec<&str> = chunks
            .iter()
            .take(3)
            .flat_map(|chunk| chunk.split(' '))
            .collect();
        assert_eq!(tokens.len(), 219);
        assert!(chunks.iter().all(|chunk| chunk.len() <= NAMES_CHUNK_BYTES));
        assert!(
            tokens
                .iter()
                .all(|token| token.len() <= MAX_NAMES_TOKEN_BYTES)
        );
        assert!(
            tokens
                .iter()
                .any(|token| token.len() == MAX_NAMES_TOKEN_BYTES)
        );
        assert!(
            tokens
                .iter()
                .all(|token| token.contains("!u-") && token.ends_with(".invalid"))
        );
        assert!(
            chunks
                .iter()
                .take(2)
                .all(|chunk| chunk.split(' ').count() >= MIN_FULL_CHUNK_ROWS)
        );
        Ok(())
    }

    /// AUD-18, the worst case of the page arithmetic: every member token
    /// carries a role byte and a framed mask for a 32-byte nickname, 73
    /// bytes, so with its separator an 8,000-byte chunk holds exactly 108 of
    /// them, `MIN_FULL_CHUNK_ROWS`. The founder and 215 voiced members, then
    /// the requester, are 217 rows rendered as chunks of 108, 108 and 1 and
    /// the 366, and the snapshot's frame bound, 217 / 108 + 2, admits all
    /// four. Counting 109 to a full chunk would bound it at three and refuse
    /// the JOIN's NAMES with `LimitExceeded`.
    #[test]
    fn a_local_join_of_role_prefixed_framed_tokens_fits_its_frame_bound() -> TestResult {
        let entropy = (0..8_192)
            .map(|value| u8::try_from(value % 251).unwrap_or(0))
            .collect();
        let mut fixture = StateCoreFixture::new(entropy)?;
        let context = fixture.context_mut()?;
        let channel = ChannelNameValue::parse("#voiced-tokens")?;
        let command = || CanonicalCommand::join(vec![ChannelTarget::new(channel.clone(), false)]);
        let mut founder = None;
        for seed in 1..=216_u8 {
            let nickname = format!("M{seed:031}");
            let member = test_support::seed_session(context, seed, &nickname, None)?;
            let PlanDecision::Mutation(plan) = test_support::plan_live(context, member, &command)?
            else {
                return Err("member JOIN plan".into());
            };
            test_support::apply_live_plan(context, plan)?;
            let Some(owner) = founder else {
                founder = Some(member);
                continue;
            };
            let target = agenc_relay_domain::NicknameValue::parse(&nickname)?;
            let voice = || {
                CanonicalCommand::mode(
                    channel.clone(),
                    vec![agenc_relay_domain::ModeChange::Role {
                        operation: agenc_relay_domain::ModeOperation::Add,
                        target: target.clone(),
                        role: agenc_relay_domain::Role::Voice,
                    }],
                )
            };
            let PlanDecision::Mutation(plan) = test_support::plan_live(context, owner, &voice)?
            else {
                return Err("voice plan".into());
            };
            test_support::apply_live_plan(context, plan)?;
        }
        let requester = test_support::seed_session(context, 217, &format!("R{:031}", 217), None)?;
        let names_caps = || test_support::negotiated_capabilities(&["userhost-in-names"]);
        let _sink = test_support::bind_live_session(context, 1, requester, names_caps()?, true)?;
        let capabilities = names_caps()?;
        let request = parse_message(FramedLine::new("JOIN #voiced-tokens")?)?.ok_or("request")?;
        let reply = ReplyInput {
            requester: requester.user_id,
            generation: ConnectionGeneration::new(1),
            capabilities: &capabilities,
            request: &request,
        };
        let PlanDecision::Mutation(plan) = test_support::plan_live(context, requester, &command)?
        else {
            return Err("requester JOIN plan".into());
        };
        let mut prepared = context
            .prepare_local_join(
                test_support::bound(requester),
                Some(reply),
                &command()?,
                &plan,
            )?
            .ok_or("prepared snapshot")?;
        let bounds = (prepared.max_rows, prepared.max_frames);
        test_support::apply_live_plan(context, plan)?;
        prepared.request = Some(Box::new(request));
        let seed = prepared
            .open(context)
            .map_err(|error| format!("open refused with bounds {bounds:?}: {error:?}"))?;
        assert_eq!(bounds, (217, 4));
        let frames = &seed.source.frames;
        assert_eq!(
            frames.iter().map(WireMessage::command).collect::<Vec<_>>(),
            vec!["353", "353", "353", "366"]
        );
        let chunks: Vec<&str> = frames.iter().filter_map(WireMessage::trailing).collect();
        assert_eq!(
            chunks
                .iter()
                .take(3)
                .map(|chunk| chunk.split(' ').count())
                .collect::<Vec<_>>(),
            vec![108, 108, 1]
        );
        let tokens: Vec<&str> = chunks
            .iter()
            .take(3)
            .flat_map(|chunk| chunk.split(' '))
            .collect();
        assert_eq!(
            tokens
                .iter()
                .filter(|token| token.len() == MAX_NAMES_TOKEN_BYTES)
                .count(),
            216
        );
        assert!(
            tokens
                .iter()
                .all(|token| token.contains("!u-") && token.ends_with(".invalid"))
        );
        assert!(chunks.iter().all(|chunk| chunk.len() <= NAMES_CHUNK_BYTES));
        assert_eq!((MAX_NAMES_TOKEN_BYTES, MIN_FULL_CHUNK_ROWS), (73, 108));
        Ok(())
    }

    #[test]
    fn local_join_capacity_refusal_precedes_allocation() -> TestResult {
        let bytes = agenc_relay_storage::MAX_TRANSACTION_PLANS
            .checked_mul(size_of::<PreparedLocalJoin>())
            .ok_or("capacity overflow")?;
        let charge = MemoryCharge::allocation(u64::try_from(bytes)?)?.bytes();
        let insufficient = crate::budget::MemoryBudget::new(charge - 1);
        let mut joins = LocalJoins::default();
        assert_eq!(
            joins.reserve(&insufficient),
            Err(RuntimeError::MemoryExhausted)
        );
        assert_eq!(joins.pending.capacity(), 0);
        assert!(joins.capacity_permit.is_none());
        assert_eq!(insufficient.available(), charge - 1);
        let exact = crate::budget::MemoryBudget::new(charge);
        joins.reserve(&exact)?;
        assert_eq!(
            joins.pending.capacity(),
            agenc_relay_storage::MAX_TRANSACTION_PLANS
        );
        assert_eq!(exact.available(), 0);
        joins.reserve(&exact)?;
        assert_eq!(exact.available(), 0);
        drop(joins);
        assert_eq!(exact.available(), charge);
        Ok(())
    }
}
