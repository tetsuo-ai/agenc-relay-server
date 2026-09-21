//! Bounded explicit-state exploration of the encrypted route model: the
//! route table, one sequencer log and lifecycle per conversation, and the
//! plaintext gate, driven by every action a client or a faulty sender can
//! attempt (companion 12.1 to 12.4, 13.7, 17). The explorer walks every
//! action sequence to the recorded depth, deduplicates states by their
//! observable shape, and checks the invariants after every transition.
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

fn instance(conversation: u8) -> ChannelInstanceId {
    ChannelInstanceId::from_bytes([conversation.saturating_add(1); 16])
}

fn conversation_id(conversation: u8) -> ConversationId {
    ConversationId(id(1, conversation, 0, 0))
}

fn lock(conversation: u8) -> SemanticLockId {
    SemanticLockId(id(2, conversation, 0, 0))
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
    }
}

const fn phase_tag(phase: Phase) -> u8 {
    match phase {
        Phase::Open => 0,
        Phase::Reinit { .. } => 1,
        Phase::Migrated { .. } => 2,
        Phase::Closed { .. } => 3,
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
            Ok(world
                .routes
                .reserve_channel(
                    ReservationId([conversation; 16]),
                    instance(conversation),
                    owner,
                    1_000,
                )
                .is_ok())
        }
        Action::Bind(conversation, who) => {
            if who >= accounts {
                return Ok(false);
            }
            bind(world, conversation, who, 0, [0; 32])
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
            let bound = bind(world, conversation, 0, 1, close_id)?;
            if bound
                && world
                    .routes
                    .channel_route(&instance(conversation))
                    .is_some()
            {
                let reopened = world
                    .routes
                    .channel_route(&instance(conversation))
                    .is_some_and(|route| route.incarnation == 0);
                if reopened {
                    return Err(Violation::Reopened(trace()));
                }
            }
            Ok(bound)
        }
        Action::Plaintext(conversation) => {
            let allowed = world
                .routes
                .channel_plaintext_allowed(&instance(conversation));
            let bound_or_tombstoned = world
                .routes
                .channel_route(&instance(conversation))
                .is_some();
            if allowed && bound_or_tombstoned {
                return Err(Violation::PlaintextLeak(trace()));
            }
            if allowed && let Some(count) = world.plaintext.get_mut(usize::from(conversation)) {
                *count = count.saturating_add(1);
            }
            Ok(allowed)
        }
        Action::Candidate(conversation) => submit_candidate(world, conversation, 0, 0),
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
        Action::Finalize(conversation) => terminal(world, conversation, true, false),
        Action::ReorderedFinalize(conversation) => terminal(world, conversation, true, true),
        Action::Abort(conversation) => terminal(world, conversation, false, false),
        Action::Application(conversation) => {
            let Some(state) = world.conversations.get(usize::from(conversation)) else {
                return Ok(false);
            };
            let (Some(log), Some(lifecycle)) = (&state.log, &state.lifecycle) else {
                return Ok(false);
            };
            let route_open = world
                .routes
                .route(&conversation_id(conversation))
                .is_some_and(|route| route.accepts_traffic());
            let allowed = route_open && lifecycle.check_application(log).is_ok();
            if allowed && (!state.activated || state.closed.is_some()) {
                return Err(Violation::UngatedApplication(trace()));
            }
            if allowed && let Some(count) = world.applications.get_mut(usize::from(conversation)) {
                *count = count.saturating_add(1);
            }
            Ok(allowed)
        }
        Action::Close(conversation) => close(world, conversation),
    }
}

fn bind(
    world: &mut World,
    conversation: u8,
    who: u8,
    incarnation: u64,
    predecessor_close_id: [u8; 32],
) -> Result<bool, Violation> {
    let actor = account(who)?;
    let summary = BindingSummary {
        conversation_id: conversation_id(conversation),
        lock: lock(conversation),
        incarnation,
        predecessor_close_id,
        binding_id: id(
            3,
            conversation,
            u32::try_from(incarnation).unwrap_or(u32::MAX),
            who,
        ),
        binding_generation: 0,
        previous_binding_id: [0; 32],
        channel_instance_id: Some(instance(conversation)),
        conversation_nonce: None,
    };
    let bound = world
        .routes
        .bind(ReservationId([conversation; 16]), actor, summary, 1)
        .is_ok();
    if bound && let Some(state) = world.conversations.get_mut(usize::from(conversation)) {
        state.log = Some(SequencerLog::genesis(
            conversation_id(conversation).0,
            id(4, conversation, 0, 0),
        ));
        state.lifecycle = Some(Lifecycle::bootstrap());
        state.activated = false;
        state.closed = None;
    }
    Ok(bound)
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
    let candidate_id = id(
        5,
        conversation,
        u32::try_from(position.route_sequence).unwrap_or(u32::MAX),
        salt,
    );
    if log
        .record_candidate(candidate_id, id(6, conversation, 0, salt), position)
        .is_err()
    {
        return Ok(false);
    }
    state.candidates.push(candidate_id);
    state.records.push(candidate_id);
    Ok(true)
}

fn terminal(
    world: &mut World,
    conversation: u8,
    finalize: bool,
    reordered: bool,
) -> Result<bool, Violation> {
    let Some(state) = world.conversations.get_mut(usize::from(conversation)) else {
        return Ok(false);
    };
    let Some(log) = state.log.as_mut() else {
        return Ok(false);
    };
    let Some(slot) = log.candidate().copied() else {
        return Ok(false);
    };
    let candidate_id = if reordered {
        id(5, conversation, 0, 9)
    } else {
        slot.candidate_id
    };
    let sequence =
        u32::try_from(slot.position.route_sequence.saturating_add(1)).unwrap_or(u32::MAX);
    let terminal_id = id(if finalize { 7 } else { 8 }, conversation, sequence, 0);
    let result = if finalize {
        log.finalize(
            &candidate_id,
            terminal_id,
            slot.position.prior_epoch.saturating_add(1),
        )
    } else {
        log.abort(&candidate_id, terminal_id)
    };
    let Ok(position) = result else {
        return Ok(false);
    };
    if position.route_sequence != slot.position.route_sequence.saturating_add(1) {
        return Err(Violation::Discontinuity(world.trace.clone()));
    }
    state.records.push(terminal_id);
    if finalize
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
    let close_id = id(9, conversation, 0, 0);
    let Ok(_position) = log.close(close_id) else {
        return Ok(false);
    };
    let conversation_key = conversation_id(conversation);
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
            Action::ReorderedFinalize(conversation),
            Action::Abort(conversation),
            Action::Application(conversation),
            Action::Close(conversation),
            Action::Reopen(conversation),
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
