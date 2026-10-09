//! Bounded explicit-state exploration of the encrypted route model: the
//! route table, one sequencer log and lifecycle per conversation, and the
//! plaintext gate, driven by every action a client or a faulty sender can
//! attempt (companion 9.4, 12.1 to 12.4, 13.7, 13.8, 17). The explorer walks
//! every action sequence to the recorded depth, deduplicates states by their
//! observable shape, and checks the invariants after every transition. A
//! closed conversation's semantic route may be recreated at its next
//! incarnation on a fresh channel instance; each conversation slot then
//! holds the newest incarnation.
//!
//! The model is pure: it uses the domain crate only, and every identifier
//! is a deterministic function of the action that produced it, so a
//! duplicate, stale, reordered, or conflicting record is one more action
//! rather than a second copy of the world.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use agenc_relay_domain::e2ee::lifecycle::Lifecycle;
use agenc_relay_domain::e2ee::sequencer_log::{Head, Phase, SequencerLog};
use agenc_relay_domain::e2ee::{
    BindingSummary, ConversationId, ReservationId, RouteLifecycle, RouteTable, SemanticLockId,
};
use agenc_relay_types::{AccountId, ChannelInstanceId};

/// The explorer bounds, recorded in `conformance/stage-eight-model.toml`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct E2eeModelBounds {
    /// Conversations (each with its own channel instance and lock).
    pub conversations: u8,
    /// Accounts that may bind.
    pub accounts: u8,
    /// Search depth in actions.
    pub depth: u8,
}

/// One action a client, a sender, or the coordinator may attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Action {
    /// Reserve the channel route of a conversation.
    Reserve(u8),
    /// Bind the reserved route under the account.
    Bind(u8, u8),
    /// Send plaintext to the channel instance.
    Plaintext(u8),
    /// Submit a Commit candidate against the accepted epoch.
    Candidate(u8),
    /// Submit the same candidate again (a duplicate).
    DuplicateCandidate(u8),
    /// Submit a candidate against the previous epoch (stale).
    StaleCandidate(u8),
    /// Submit a second, conflicting candidate for the same epoch.
    ConflictingCandidate(u8),
    /// Finalize the active candidate.
    Finalize(u8),
    /// Finalize the active candidate as a ReInit Commit, whose authorization
    /// carries the ReInit bit: the old group closes in the same step
    /// (companion 13.8 step 2).
    ReinitFinalize(u8),
    /// Finalize a candidate that is not the active one (reordered).
    ReorderedFinalize(u8),
    /// Abort the active candidate.
    Abort(u8),
    /// Send application ciphertext.
    Application(u8),
    /// Close the conversation.
    Close(u8),
    /// Bind again after the close under the same lock (a reopen attempt).
    Reopen(u8),
    /// Reserve a fresh channel instance and bind the next semantic
    /// incarnation of the closed conversation's route there, under that
    /// incarnation's lock, naming the close (companion 9.4 and 11.3).
    Recreate(u8),
}

/// One conversation's state.
#[derive(Clone, Debug)]
struct Conversation {
    log: Option<SequencerLog>,
    lifecycle: Option<Lifecycle>,
    /// The candidate identifiers ever accepted, in order.
    candidates: Vec<[u8; 32]>,
    /// The record identifiers ever accepted, in order.
    records: Vec<[u8; 32]>,
    /// Whether the bootstrap finalized (application traffic may flow).
    activated: bool,
    /// Close identifier once closed.
    closed: Option<[u8; 32]>,
    /// Whether a ReInit Commit finalized, closing the old group.
    reinit: bool,
    /// The semantic incarnation the slot holds.
    incarnation: u64,
}

/// The explorable world.
#[derive(Clone, Debug)]
struct World {
    routes: RouteTable,
    conversations: Vec<Conversation>,
    /// Application messages accepted per conversation.
    applications: Vec<u32>,
    /// Plaintext lines accepted per conversation.
    plaintext: Vec<u32>,
    /// The action trace that produced this world.
    trace: Vec<Action>,
}

/// Why the exploration stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Violation {
    /// Two candidates were active in one epoch.
    TwoCandidates(Vec<Action>),
    /// A record position was skipped or repeated.
    Discontinuity(Vec<Action>),
    /// Two accepted records shared one identifier.
    DuplicateIdentifier(Vec<Action>),
    /// Plaintext reached a bound or tombstoned route.
    PlaintextLeak(Vec<Action>),
    /// Application traffic flowed before the bootstrap finalized or after close.
    UngatedApplication(Vec<Action>),
    /// A closed lineage reopened under the same lock.
    Reopened(Vec<Action>),
    /// An ordinary candidate, application object, or close was accepted
    /// after a ReInit Commit finalized and closed the old group.
    ReinitClosedGroup(Vec<Action>),
    /// The model itself could not build a fixture value.
    Model(&'static str),
}

/// The exploration result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Exploration {
    /// Distinct states reached.
    pub states: u64,
    /// Accepted transitions.
    pub transitions: u64,
    /// Action sequences explored to the depth or to a dead end.
    pub paths: u64,
    /// Refused actions.
    pub refusals: u64,
    /// Actions attempted.
    pub actions: u64,
    /// Invariant violations, empty when the model holds.
    pub violations: Vec<Violation>,
}

fn id(tag: u8, conversation: u8, sequence: u32, salt: u8) -> [u8; 32] {
    let mut value = [0; 32];
    let prefix = [tag, conversation];
    let sequence_bytes = sequence.to_be_bytes();
    let bytes = prefix
        .iter()
        .chain(sequence_bytes.iter())
        .chain(std::iter::once(&salt));
    for (slot, byte) in value.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    value
}

fn account(index: u8) -> Result<AccountId, Violation> {
    let mut bytes = *b"a_AAAAAAAAAAAAAAAAAAAAAA";
    // The last of the 22 Base64url characters carries two payload bits, so
    // only four alphabet characters are canonical there.
    let canonical = *b"AQgw";
    if let (Some(last), Some(byte)) = (bytes.last_mut(), canonical.get(usize::from(index))) {
        *last = *byte;
    }
    AccountId::parse_wire_bytes(&bytes).map_err(|_| Violation::Model("account"))
}

/// The identifier byte of a conversation's incarnation: the conversation
/// index itself at incarnation zero, so the first incarnation keeps its
/// identifiers.
fn slot(conversation: u8, incarnation: u64) -> u8 {
    let step = u8::try_from(incarnation % 16).unwrap_or_default();
    conversation.wrapping_add(step.wrapping_mul(16))
}

fn instance_at(conversation: u8, incarnation: u64) -> ChannelInstanceId {
    ChannelInstanceId::from_bytes([slot(conversation, incarnation).saturating_add(1); 16])
}

fn conversation_id_at(conversation: u8, incarnation: u64) -> ConversationId {
    ConversationId(id(1, slot(conversation, incarnation), 0, 0))
}

fn lock_at(conversation: u8, incarnation: u64) -> SemanticLockId {
    SemanticLockId(id(2, slot(conversation, incarnation), 0, 0))
}

/// The incarnation a conversation slot holds now.
fn incarnation_of(world: &World, conversation: u8) -> u64 {
    world
        .conversations
        .get(usize::from(conversation))
        .map_or(0, |state| state.incarnation)
}

impl World {
    fn new(bounds: E2eeModelBounds) -> Self {
        let count = usize::from(bounds.conversations);
        Self {
            routes: RouteTable::new(),
            conversations: (0..count)
                .map(|_| Conversation {
                    log: None,
                    lifecycle: None,
                    candidates: Vec::new(),
                    records: Vec::new(),
                    activated: false,
                    closed: None,
                    reinit: false,
                    incarnation: 0,
                })
                .collect(),
            applications: vec![0; count],
            plaintext: vec![0; count],
            trace: Vec::new(),
        }
    }

    /// The observable shape, for deduplication.
    fn key(&self) -> Vec<u8> {
        let mut key = Vec::new();
        for (index, conversation) in self.conversations.iter().enumerate() {
            key.push(u8::try_from(index).unwrap_or(u8::MAX));
            conversation.key_into(&mut key);
        }
        for route in self.routes.routes() {
            key.extend_from_slice(&route.conversation_id.0);
            key.extend_from_slice(&route.incarnation.to_be_bytes());
            key.push(u8::from(matches!(
                route.lifecycle,
                RouteLifecycle::Tombstone { .. }
            )));
        }
        key.push(u8::try_from(self.routes.reservations().count()).unwrap_or(u8::MAX));
        key
    }
}

impl Conversation {
    /// Appends the observable shape of one conversation.
    fn key_into(&self, key: &mut Vec<u8>) {
        match &self.log {
            None => key.push(0),
            Some(log) => {
                key.push(1);
                let head: Head = log.head();
                key.extend_from_slice(&head.sequence.to_be_bytes());
                key.extend_from_slice(&head.record_id);
                key.push(u8::from(head.recorded));
                key.extend_from_slice(&log.accepted_epoch().to_be_bytes());
                key.push(u8::from(log.has_candidate()));
                key.push(phase_tag(log.phase()));
            }
        }
        key.push(u8::from(self.activated));
        key.push(u8::from(self.closed.is_some()));
        key.push(u8::try_from(self.candidates.len()).unwrap_or(u8::MAX));
        key.extend_from_slice(&self.incarnation.to_be_bytes());
    }
}

const fn phase_tag(phase: Phase) -> u8 {
    match phase {
        Phase::Open => 0,
        Phase::Reinit { .. } => 1,
        Phase::Migrated { .. } => 2,
        Phase::Closed { .. } => 3,
        Phase::Retired => 4,
    }
}

/// Applies one action; `Ok(true)` is an accepted transition, `Ok(false)` a
/// refusal, `Err` an invariant violation.
// agenc-review: focus owner=testkit reviewed=2026-09-04 reason=the model's action table is one closed match whose arms the reviewer reads against companion 12.1 to 12.4 side by side
fn step(world: &mut World, action: Action, accounts: u8) -> Result<bool, Violation> {
    let before = world.trace.clone();
    let trace = move || {
        let mut trace = before.clone();
        trace.push(action);
        trace
    };
    match action {
        Action::Reserve(conversation) => {
            let owner = account(0)?;
            let incarnation = incarnation_of(world, conversation);
            Ok(world
                .routes
                .reserve_channel(
                    ReservationId([conversation; 16]),
                    instance_at(conversation, incarnation),
                    owner,
                    1_000,
                )
                .is_ok())
        }
        Action::Bind(conversation, who) => {
            if who >= accounts {
                return Ok(false);
            }
            let incarnation = incarnation_of(world, conversation);
            let binding = Binding {
                incarnation,
                predecessor_close_id: [0; 32],
                lock: lock_at(conversation, incarnation),
                instance: instance_at(conversation, incarnation),
                reservation: ReservationId([conversation; 16]),
            };
            bind(world, conversation, who, binding)
        }
        Action::Reopen(conversation) => {
            let Some(close_id) = world
                .conversations
                .get(usize::from(conversation))
                .and_then(|state| state.closed)
            else {
                return Ok(false);
            };
            // A reopen under the same lock needs a destroyed instance and the
            // next incarnation; the model offers the old instance again.
            let incarnation = incarnation_of(world, conversation);
            let old = instance_at(conversation, incarnation);
            let binding = Binding {
                incarnation: incarnation.saturating_add(1),
                predecessor_close_id: close_id,
                lock: lock_at(conversation, incarnation),
                instance: old,
                reservation: ReservationId([conversation; 16]),
            };
            let bound = bind(world, conversation, 0, binding)?;
            if bound && world.routes.channel_route(&old).is_some() {
                let reopened = world
                    .routes
                    .channel_route(&old)
                    .is_some_and(|route| route.incarnation == incarnation);
                if reopened {
                    return Err(Violation::Reopened(trace()));
                }
            }
            Ok(bound)
        }
        Action::Recreate(conversation) => recreate(world, conversation),
        Action::Plaintext(conversation) => {
            let instance = instance_at(conversation, incarnation_of(world, conversation));
            let allowed = world.routes.channel_plaintext_allowed(&instance);
            let bound_or_tombstoned = world.routes.channel_route(&instance).is_some();
            if allowed && bound_or_tombstoned {
                return Err(Violation::PlaintextLeak(trace()));
            }
            if allowed && let Some(count) = world.plaintext.get_mut(usize::from(conversation)) {
                *count = count.saturating_add(1);
            }
            Ok(allowed)
        }
        Action::Candidate(conversation) => {
            let accepted = submit_candidate(world, conversation, 0, 0)?;
            closed_group(world, conversation, accepted, trace)
        }
        Action::DuplicateCandidate(conversation) => {
            let Some(last) = world
                .conversations
                .get(usize::from(conversation))
                .and_then(|state| state.candidates.last().copied())
            else {
                return Ok(false);
            };
            // The same candidate object again: the log already holds it.
            let accepted = submit_candidate(world, conversation, 0, 0)?;
            let repeated = world
                .conversations
                .get(usize::from(conversation))
                .is_some_and(|state| {
                    state
                        .candidates
                        .iter()
                        .filter(|candidate| **candidate == last)
                        .count()
                        > 1
                });
            if repeated {
                return Err(Violation::DuplicateIdentifier(trace()));
            }
            Ok(accepted)
        }
        Action::StaleCandidate(conversation) => submit_candidate(world, conversation, 1, 1),
        Action::ConflictingCandidate(conversation) => {
            let had_candidate = world
                .conversations
                .get(usize::from(conversation))
                .and_then(|state| state.log.as_ref())
                .is_some_and(SequencerLog::has_candidate);
            let accepted = submit_candidate(world, conversation, 0, 2)?;
            if had_candidate && accepted {
                return Err(Violation::TwoCandidates(trace()));
            }
            Ok(accepted)
        }
        Action::Finalize(conversation) => terminal(world, conversation, Terminal::Finalize, false),
        Action::ReinitFinalize(conversation) => {
            terminal(world, conversation, Terminal::Reinit, false)
        }
        Action::ReorderedFinalize(conversation) => {
            terminal(world, conversation, Terminal::Finalize, true)
        }
        Action::Abort(conversation) => terminal(world, conversation, Terminal::Abort, false),
        Action::Application(conversation) => {
            let Some(state) = world.conversations.get(usize::from(conversation)) else {
                return Ok(false);
            };
            let (Some(log), Some(lifecycle)) = (&state.log, &state.lifecycle) else {
                return Ok(false);
            };
            let route_open = world
                .routes
                .route(&conversation_id_at(conversation, state.incarnation))
                .is_some_and(|route| route.accepts_traffic());
            let allowed = route_open && lifecycle.check_application(log).is_ok();
            if allowed && (!state.activated || state.closed.is_some()) {
                return Err(Violation::UngatedApplication(trace()));
            }
            if allowed && let Some(count) = world.applications.get_mut(usize::from(conversation)) {
                *count = count.saturating_add(1);
            }
            closed_group(world, conversation, allowed, trace)
        }
        Action::Close(conversation) => {
            let closed = close(world, conversation)?;
            closed_group(world, conversation, closed, trace)
        }
    }
}

/// An accepted ordinary record or application object after a ReInit
/// finalization is a violation: that finalization closed the old group.
fn closed_group(
    world: &World,
    conversation: u8,
    accepted: bool,
    trace: impl FnOnce() -> Vec<Action>,
) -> Result<bool, Violation> {
    let reinit = world
        .conversations
        .get(usize::from(conversation))
        .is_some_and(|state| state.reinit);
    if accepted && reinit {
        return Err(Violation::ReinitClosedGroup(trace()));
    }
    Ok(accepted)
}

/// What one bind attempt names.
struct Binding {
    incarnation: u64,
    predecessor_close_id: [u8; 32],
    lock: SemanticLockId,
    instance: ChannelInstanceId,
    reservation: ReservationId,
}

fn bind(world: &mut World, conversation: u8, who: u8, binding: Binding) -> Result<bool, Violation> {
    let actor = account(who)?;
    let tag = slot(conversation, binding.incarnation);
    let summary = BindingSummary {
        conversation_id: conversation_id_at(conversation, binding.incarnation),
        lock: binding.lock,
        lineage: lock_at(conversation, 0),
        incarnation: binding.incarnation,
        predecessor_close_id: binding.predecessor_close_id,
        binding_id: id(
            3,
            tag,
            u32::try_from(binding.incarnation).unwrap_or(u32::MAX),
            who,
        ),
        binding_generation: 0,
        previous_binding_id: [0; 32],
        channel_instance_id: Some(binding.instance),
        conversation_nonce: None,
    };
    let bound = world
        .routes
        .bind(binding.reservation, actor, summary, 1)
        .is_ok();
    if bound && let Some(state) = world.conversations.get_mut(usize::from(conversation)) {
        state.log = Some(SequencerLog::genesis(
            conversation_id_at(conversation, binding.incarnation).0,
            id(4, tag, 0, 0),
        ));
        state.lifecycle = Some(Lifecycle::bootstrap());
        state.activated = false;
        state.closed = None;
        state.reinit = false;
        state.candidates.clear();
        state.records.clear();
        state.incarnation = binding.incarnation;
    }
    Ok(bound)
}

/// Recreates the closed conversation's semantic route: a fresh channel
/// instance is reserved and bound at the next incarnation, under that
/// incarnation's lock, naming the close (companion 9.4 and 11.3).
fn recreate(world: &mut World, conversation: u8) -> Result<bool, Violation> {
    let Some(state) = world.conversations.get(usize::from(conversation)) else {
        return Ok(false);
    };
    let (Some(close_id), Some(next)) = (state.closed, state.incarnation.checked_add(1)) else {
        return Ok(false);
    };
    let fresh = instance_at(conversation, next);
    let reservation = ReservationId([slot(conversation, next); 16]);
    if world
        .routes
        .reserve_channel(reservation, fresh, account(0)?, 1_000)
        .is_err()
    {
        return Ok(false);
    }
    let binding = Binding {
        incarnation: next,
        predecessor_close_id: close_id,
        lock: lock_at(conversation, next),
        instance: fresh,
        reservation,
    };
    bind(world, conversation, 0, binding)
}

fn submit_candidate(
    world: &mut World,
    conversation: u8,
    epoch_lag: u64,
    salt: u8,
) -> Result<bool, Violation> {
    let Some(state) = world.conversations.get_mut(usize::from(conversation)) else {
        return Ok(false);
    };
    let (Some(log), Some(lifecycle)) = (state.log.as_mut(), state.lifecycle.as_ref()) else {
        return Ok(false);
    };
    if lifecycle.check_candidate(log).is_err() {
        return Ok(false);
    }
    let Some(prior_epoch) = log.accepted_epoch().checked_sub(epoch_lag) else {
        return Ok(false);
    };
    let Ok(position) = log.candidate_position(prior_epoch) else {
        return Ok(false);
    };
    let tag = slot(conversation, state.incarnation);
    let candidate_id = id(
        5,
        tag,
        u32::try_from(position.route_sequence).unwrap_or(u32::MAX),
        salt,
    );
    if log
        .record_candidate(candidate_id, id(6, tag, 0, salt), position)
        .is_err()
    {
        return Ok(false);
    }
    state.candidates.push(candidate_id);
    state.records.push(candidate_id);
    Ok(true)
}

/// The terminal a [`terminal`] action certifies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Terminal {
    /// An ordinary finalization.
    Finalize,
    /// The finalization of a ReInit Commit.
    Reinit,
    /// A candidate abort.
    Abort,
}

fn terminal(
    world: &mut World,
    conversation: u8,
    kind: Terminal,
    reordered: bool,
) -> Result<bool, Violation> {
    let Some(state) = world.conversations.get_mut(usize::from(conversation)) else {
        return Ok(false);
    };
    let Some(log) = state.log.as_mut() else {
        return Ok(false);
    };
    let Some(open) = log.candidate().copied() else {
        return Ok(false);
    };
    let incarnation_tag = slot(conversation, state.incarnation);
    let candidate_id = if reordered {
        id(5, incarnation_tag, 0, 9)
    } else {
        open.candidate_id
    };
    let sequence =
        u32::try_from(open.position.route_sequence.saturating_add(1)).unwrap_or(u32::MAX);
    let tag = match kind {
        Terminal::Finalize => 7,
        Terminal::Abort => 8,
        Terminal::Reinit => 10,
    };
    let terminal_id = id(tag, incarnation_tag, sequence, 0);
    let resulting_epoch = open.position.prior_epoch.saturating_add(1);
    let result = match kind {
        Terminal::Finalize => log.finalize(&candidate_id, terminal_id, resulting_epoch),
        Terminal::Reinit => log.finalize_reinit(&candidate_id, terminal_id, resulting_epoch),
        Terminal::Abort => log.abort(&candidate_id, terminal_id),
    };
    let Ok(position) = result else {
        return Ok(false);
    };
    if position.route_sequence != open.position.route_sequence.saturating_add(1) {
        return Err(Violation::Discontinuity(world.trace.clone()));
    }
    state.records.push(terminal_id);
    // A ReInit authorization is a controlled transition, never the
    // bootstrap activation, and it closes the old group.
    if kind == Terminal::Reinit {
        state.reinit = true;
    }
    if kind == Terminal::Finalize
        && let Some(lifecycle) = state.lifecycle.as_mut()
        && !state.activated
    {
        state.activated = lifecycle.bootstrap_activated().is_ok();
    }
    Ok(true)
}

fn close(world: &mut World, conversation: u8) -> Result<bool, Violation> {
    let Some(state) = world.conversations.get_mut(usize::from(conversation)) else {
        return Ok(false);
    };
    let Some(log) = state.log.as_mut() else {
        return Ok(false);
    };
    if !state.activated {
        return Ok(false);
    }
    let close_id = id(9, slot(conversation, state.incarnation), 0, 0);
    let Ok(_position) = log.close(close_id) else {
        return Ok(false);
    };
    let conversation_key = conversation_id_at(conversation, state.incarnation);
    let closed = world
        .routes
        .begin_close(&conversation_key)
        .and_then(|()| world.routes.close(&conversation_key, close_id))
        .is_ok();
    if closed {
        state.closed = Some(close_id);
        state.records.push(close_id);
    }
    Ok(closed)
}

fn check(world: &World) -> Result<(), Violation> {
    for state in &world.conversations {
        let mut seen = BTreeSet::new();
        for record in &state.records {
            if !seen.insert(*record) {
                return Err(Violation::DuplicateIdentifier(world.trace.clone()));
            }
        }
        if let Some(log) = &state.log {
            let expected = u64::try_from(state.records.len()).unwrap_or(u64::MAX);
            let head = log.head();
            let contiguous = if head.recorded {
                head.sequence.saturating_add(1) == expected
            } else {
                expected == 0
            };
            if !contiguous {
                return Err(Violation::Discontinuity(world.trace.clone()));
            }
        }
    }
    Ok(())
}

fn actions(bounds: E2eeModelBounds) -> Vec<Action> {
    let mut all = Vec::new();
    for conversation in 0..bounds.conversations {
        all.push(Action::Reserve(conversation));
        for who in 0..bounds.accounts {
            all.push(Action::Bind(conversation, who));
        }
        all.extend([
            Action::Plaintext(conversation),
            Action::Candidate(conversation),
            Action::DuplicateCandidate(conversation),
            Action::StaleCandidate(conversation),
            Action::ConflictingCandidate(conversation),
            Action::Finalize(conversation),
            Action::ReinitFinalize(conversation),
            Action::ReorderedFinalize(conversation),
            Action::Abort(conversation),
            Action::Application(conversation),
            Action::Close(conversation),
            Action::Reopen(conversation),
            Action::Recreate(conversation),
        ]);
    }
    all
}

/// What expanding one state produced.
enum Expanded {
    /// A violation ended the exploration.
    Violated(Violation),
    /// The accepted successors, with whether any action was accepted.
    Successors(Vec<World>, bool),
}

/// Applies every action to `world`, counting refusals and transitions.
fn expand(world: &World, table: &[Action], accounts: u8, result: &mut Exploration) -> Expanded {
    let mut successors = Vec::new();
    let mut advanced = false;
    for action in table {
        let mut next = world.clone();
        let outcome = step(&mut next, *action, accounts).and_then(|accepted| {
            check(&next)?;
            Ok(accepted)
        });
        match outcome {
            Err(violation) => return Expanded::Violated(violation),
            Ok(false) => result.refusals = result.refusals.saturating_add(1),
            Ok(true) => {
                advanced = true;
                result.transitions = result.transitions.saturating_add(1);
                next.trace.push(*action);
                successors.push(next);
            }
        }
    }
    Expanded::Successors(successors, advanced)
}

/// Replays one action sequence from the empty world, past any depth bound,
/// checking every invariant after each action as the explorer does: whether
/// each action was accepted, or the first violation. A refused action
/// leaves the world as it was.
pub fn replay_e2ee(bounds: E2eeModelBounds, script: &[Action]) -> Result<Vec<bool>, Violation> {
    let mut world = World::new(bounds);
    let mut accepted = Vec::with_capacity(script.len());
    for action in script {
        let mut next = world.clone();
        let outcome = step(&mut next, *action, bounds.accounts)?;
        check(&next)?;
        if outcome {
            next.trace.push(*action);
            world = next;
        }
        accepted.push(outcome);
    }
    Ok(accepted)
}

/// Explores every action sequence up to `bounds.depth`.
pub fn explore_e2ee(bounds: E2eeModelBounds) -> Exploration {
    let table = actions(bounds);
    let mut result = Exploration {
        actions: u64::try_from(table.len()).unwrap_or(u64::MAX),
        ..Exploration::default()
    };
    let start = World::new(bounds);
    let mut seen: BTreeMap<Vec<u8>, u8> = BTreeMap::new();
    seen.insert(start.key(), 0);
    let mut queue = VecDeque::from([(start, 0_u8)]);
    result.states = 1;
    while let Some((world, depth)) = queue.pop_front() {
        if depth >= bounds.depth {
            result.paths = result.paths.saturating_add(1);
            continue;
        }
        let (successors, advanced) = match expand(&world, &table, bounds.accounts, &mut result) {
            Expanded::Violated(violation) => {
                result.violations.push(violation);
                return result;
            }
            Expanded::Successors(successors, advanced) => (successors, advanced),
        };
        if !advanced {
            result.paths = result.paths.saturating_add(1);
        }
        let next_depth = depth.saturating_add(1);
        for next in successors {
            let key = next.key();
            if seen.get(&key).is_some_and(|known| *known <= next_depth) {
                continue;
            }
            if !seen.contains_key(&key) {
                result.states = result.states.saturating_add(1);
            }
            seen.insert(key, next_depth);
            queue.push_back((next, next_depth));
        }
    }
    result
}
