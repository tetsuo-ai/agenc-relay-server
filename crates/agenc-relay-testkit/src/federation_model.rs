//! Bounded explicit-state exploration of base federation (spec 28.3 and
//! 28.5): every sequence of client actions up to a fixed depth runs through
//! the real domain planner, the coordinator projection, and one edge replica
//! per edge, and every reached state is checked against the invariants a
//! coordinator and its edges must keep.
//!
//! The explorer is exhaustive within its bounds: two edges, three clients,
//! two channels, and the open, close, join, part, message, and kick actions.
//! Duplicate, reordered, and lost deliveries are refused one layer down, by
//! the delivery-sequence check of the edge runtime, and are covered there.
//! Each path is re-executed from the empty network, so no state is cloned and
//! the domain stays the single source of truth. The distinct-state count is
//! recorded in `conformance/stage-seven-model.toml` and must not drift.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use agenc_relay_domain::federation::{
    CoordinatorProjection, EdgeReplica, MutationContext, ProjectionKey, ProjectionRecord,
};
use agenc_relay_domain::{
    AdmissionSnapshot, CanonicalCommand, ChannelNameValue, ChannelTarget, CommandEnvelope,
    DepartureReason, DisplayNameValue, DomainError, DomainState, EntropyPurpose,
    ExternalInputRequest, ExternalInputs, MessageCommand, MessageKind, MessageTarget, MessageText,
    MutationPlan, NicknameValue, PlanDecision, RateBucket, SessionSeed,
};
use agenc_relay_types::{
    ChannelInstanceId, ControlPolicy, EntryId, Generation, InviteId, MessageId, MonotonicTick,
    PublicCloak, ServerId, SessionId, UserId, UtcSecond,
};

const COORDINATOR: ServerId = ServerId::from_bytes([200; 16]);
const EDGE_A: ServerId = ServerId::from_bytes([10; 16]);
const EDGE_B: ServerId = ServerId::from_bytes([11; 16]);
const EDGES: [ServerId; 2] = [EDGE_A, EDGE_B];
const CLIENTS: [Client; 3] = [
    Client {
        index: 1,
        home: EDGE_A,
    },
    Client {
        index: 2,
        home: EDGE_B,
    },
    Client {
        index: 3,
        home: EDGE_A,
    },
];
const CHANNELS: [&str; 2] = ["#one", "#two"];

/// One modelled client: a fixed nickname on a fixed home edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Client {
    index: u8,
    home: ServerId,
}

/// One action of the closed alphabet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// A client registers on its home edge.
    Open(u8),
    /// A client disconnects.
    Close(u8),
    /// A client joins a channel by index.
    Join(u8, usize),
    /// A client parts a channel by index.
    Part(u8, usize),
    /// A client sends a channel message.
    Message(u8, usize),
    /// A client kicks another client from a channel.
    Kick(u8, u8, usize),
}

/// Why exploration stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// A domain operation failed where the model expected success.
    Domain(DomainError),
    /// An invariant failed on one path; the path is listed in order.
    Violation {
        /// The invariant that failed.
        invariant: &'static str,
        /// The actions leading to the failing state.
        path: Vec<Action>,
    },
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(error) => write!(formatter, "domain failure: {error:?}"),
            Self::Violation { invariant, path } => {
                write!(formatter, "{invariant} failed after {path:?}")
            }
        }
    }
}

impl std::error::Error for ModelError {}

impl From<DomainError> for ModelError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

/// The exploration bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelBounds {
    /// The longest action sequence explored.
    pub depth: usize,
}

/// What an exhaustive exploration found.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModelReport {
    /// Distinct reachable network states, the empty network included.
    pub states: usize,
    /// Executed actions across every path.
    pub transitions: usize,
    /// Complete paths of exactly the bound depth or ending in a dead end.
    pub paths: usize,
    /// Actions that the domain refused, which are legal dead ends.
    pub refusals: usize,
}

/// One network: the coordinator's domain, its projection index, and a
/// replica per edge, rebuilt from scratch for every explored path.
struct Network {
    state: DomainState,
    index: CoordinatorProjection,
    replicas: BTreeMap<ServerId, EdgeReplica>,
    next_id: u8,
}

impl Network {
    fn new() -> Result<Self, DomainError> {
        let mut replicas = BTreeMap::new();
        for edge in EDGES {
            replicas.insert(edge, EdgeReplica::new(edge));
        }
        Ok(Self {
            state: DomainState::new()?,
            index: CoordinatorProjection::new(COORDINATOR),
            replicas,
            next_id: 100,
        })
    }

    fn fresh_id(&mut self) -> [u8; 16] {
        self.next_id = self.next_id.wrapping_add(1);
        [self.next_id; 16]
    }

    fn user_of(client: Client) -> UserId {
        UserId::from_bytes([client.index.wrapping_add(64); 16])
    }

    fn seed(&self, client: Client) -> Result<SessionSeed, DomainError> {
        let n = client.index;
        // Cloak components use the lowercase base32 alphabet; the client
        // index selects one distinct letter.
        let letter = b'a'.wrapping_add(n % 26);
        let mut user = [b'a'; 10];
        let mut host = [b'b'; 16];
        if let Some(last) = user.last_mut() {
            *last = letter;
        }
        if let Some(last) = host.last_mut() {
            *last = letter;
        }
        Ok(SessionSeed {
            session_id: SessionId::from_bytes([n; 16]),
            user_id: Self::user_of(client),
            home_server_id: client.home,
            account_id: None,
            account_session_generation: Generation::new(0)?,
            generation: Generation::new(1)?,
            nickname: NicknameValue::parse(&format!("user{n}"))?,
            display_name: DisplayNameValue::prepare(&format!("User {n}"))?,
            public_cloak: PublicCloak::from_components(user, host)?,
            connection_nonce: [n; 32],
            negotiated_capability_hash: [n.wrapping_add(1); 32],
            created_at_utc: UtcSecond::from_unix_seconds(10),
            revision: self.state.revision(),
        })
    }

    fn is_open(&self, client: Client) -> bool {
        self.state.session(Self::user_of(client)).is_some()
    }

    /// Commits one plan: derive, apply, and replay every event copy onto
    /// the matching replica, then check the standing invariants.
    fn commit(
        &mut self,
        plan: MutationPlan,
        context: &MutationContext,
        path: &[Action],
    ) -> Result<(), ModelError> {
        let projection = self.index.derive(&self.state, &plan, context)?;
        let prepared = self.state.prepare_mutation(plan)?;
        let receipt = self.state.apply_prepared(prepared)?;
        self.index.apply(&projection);
        let generation = receipt.revision().get();
        for delta in &projection.edges {
            let replica = self
                .replicas
                .get_mut(&delta.target)
                .ok_or(DomainError::NotFound)?;
            for event in &delta.events {
                if replica.apply(event, generation).is_err() {
                    return Err(violation("FED-05 event application", path));
                }
            }
        }
        self.check_standing(path)
    }

    /// FED-05, FED-06, FED-07, and STA-01: every replica validates, its keys
    /// equal the coordinator's standing index for that edge, and its records
    /// equal the snapshot cut a fresh synchronization would install.
    fn check_standing(&self, path: &[Action]) -> Result<(), ModelError> {
        for (edge, replica) in &self.replicas {
            if replica.validate().is_err() {
                return Err(violation("FED-07 replica references", path));
            }
            let mut replica_keys: Vec<ProjectionKey> =
                replica.entries().map(|entry| entry.key()).collect();
            replica_keys.sort();
            let mut index_keys: Vec<ProjectionKey> = self
                .index
                .edge(*edge)
                .map(|standing| standing.keys().collect())
                .unwrap_or_default();
            index_keys.sort();
            if replica_keys != index_keys {
                return Err(violation("FED-06 standing index", path));
            }
            let cut = CoordinatorProjection::standing_of(&self.state, *edge);
            let mut entries: Vec<ProjectionRecord> = replica.entries().collect();
            entries.sort_by_key(ProjectionRecord::key);
            if cut != entries {
                return Err(violation("FED-05 snapshot cut", path));
            }
        }
        Ok(())
    }

    fn run(
        &mut self,
        client: Client,
        command: &dyn Fn() -> Result<CanonicalCommand, DomainError>,
        context: &MutationContext,
        path: &[Action],
    ) -> Result<bool, ModelError> {
        let user = Self::user_of(client);
        let Some(plan) = self.plan(user, command)? else {
            return Ok(false);
        };
        self.commit(plan, context, path)?;
        Ok(true)
    }

    /// Plans one authorized command, supplying deterministic external
    /// inputs; `None` means the domain refused it.
    fn plan(
        &mut self,
        user: UserId,
        command: &dyn Fn() -> Result<CanonicalCommand, DomainError>,
    ) -> Result<Option<MutationPlan>, DomainError> {
        let Some(session) = self.state.session(user) else {
            return Ok(None);
        };
        let built = command()?;
        let mut entries: Vec<(RateBucket, u64)> = self
            .state
            .command_charges(user, &built)
            .iter()
            .map(|charge| (charge.bucket(), 100))
            .collect();
        entries.sort_by_key(|(bucket, _)| format!("{bucket:?}"));
        entries.dedup_by_key(|(bucket, _)| format!("{bucket:?}"));
        let credit = AdmissionSnapshot::new(entries)?;
        let envelope = CommandEnvelope::new(
            session.session_id(),
            user,
            session.generation(),
            self.state.revision(),
            built,
        );
        let Ok(authorized) = self.state.authorize(envelope, &credit) else {
            return Ok(None);
        };
        let decision = self.state.plan_authorized(authorized, None)?;
        let requests = match decision {
            PlanDecision::Mutation(plan) => return Ok(Some(plan)),
            PlanDecision::NeedsExternal(requests) => requests,
            PlanDecision::Query(_) | PlanDecision::Rejected(_) => return Ok(None),
        };
        let inputs = self.inputs(&requests)?;
        let Some(session) = self.state.session(user) else {
            return Ok(None);
        };
        let envelope = CommandEnvelope::new(
            session.session_id(),
            user,
            session.generation(),
            self.state.revision(),
            command()?,
        );
        let Ok(authorized) = self.state.authorize(envelope, &credit) else {
            return Ok(None);
        };
        match self.state.plan_authorized(authorized, Some(inputs))? {
            PlanDecision::Mutation(plan) => Ok(Some(plan)),
            PlanDecision::NeedsExternal(_) | PlanDecision::Query(_) | PlanDecision::Rejected(_) => {
                Ok(None)
            }
        }
    }

    fn inputs(&mut self, requests: &[ExternalInputRequest]) -> Result<ExternalInputs, DomainError> {
        let mut inputs = ExternalInputs::default();
        for request in requests {
            match request {
                ExternalInputRequest::UtcNow { .. } => {
                    inputs.utc_now = Some(UtcSecond::from_unix_seconds(20));
                }
                ExternalInputRequest::MonotonicNow { .. } => {
                    inputs.monotonic_now = Some(MonotonicTick::from_ticks(20));
                }
                ExternalInputRequest::Entropy { purpose, .. } => {
                    self.entropy_input(purpose, &mut inputs)?;
                }
                ExternalInputRequest::ChannelKeyVerification { .. }
                | ExternalInputRequest::ChannelKeyConstruction { .. } => {
                    return Err(DomainError::InvariantViolation);
                }
            }
        }
        Ok(inputs)
    }

    fn entropy_input(
        &mut self,
        purpose: &EntropyPurpose,
        inputs: &mut ExternalInputs,
    ) -> Result<(), DomainError> {
        match purpose {
            EntropyPurpose::ChannelInstance(_) => inputs
                .channel_ids
                .push(ChannelInstanceId::from_bytes(self.fresh_id())),
            EntropyPurpose::Message(_) => inputs
                .message_ids
                .push(MessageId::from_bytes(self.fresh_id())),
            EntropyPurpose::Invite => inputs
                .invite_ids
                .push(InviteId::from_bytes(self.fresh_id())),
            EntropyPurpose::MaskEntry(_) => {
                inputs.entry_ids.push(EntryId::from_bytes(self.fresh_id()));
            }
            EntropyPurpose::AccountDeletionChallenge => {
                return Err(DomainError::InvariantViolation);
            }
        }
        Ok(())
    }

    /// Executes one action; `false` is a legal refusal (a dead end).
    fn step(&mut self, action: Action, path: &[Action]) -> Result<bool, ModelError> {
        match action {
            Action::Open(index) => self.open(index, path),
            Action::Close(index) => self.close(index, path),
            Action::Join(index, channel) => {
                let (Some(client), Some(name)) = (client(index), channel_name(channel)) else {
                    return Ok(false);
                };
                let command =
                    move || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
                self.run(client, &command, &MutationContext::default(), path)
            }
            Action::Part(index, channel) => {
                let (Some(client), Some(name)) = (client(index), channel_name(channel)) else {
                    return Ok(false);
                };
                let command = move || CanonicalCommand::part(vec![name.clone()], None);
                self.run(client, &command, &MutationContext::default(), path)
            }
            Action::Message(index, channel) => {
                let (Some(client), Some(name)) = (client(index), channel_name(channel)) else {
                    return Ok(false);
                };
                let command = move || {
                    Ok(CanonicalCommand::message(MessageCommand::new(
                        MessageKind::Privmsg,
                        vec![MessageTarget::Channel(name.clone())],
                        Some(MessageText::parse("hello")?),
                    )?))
                };
                self.run(client, &command, &MutationContext::default(), path)
            }
            Action::Kick(index, target, channel) => self.kick(index, target, channel, path),
        }
    }

    fn open(&mut self, index: u8, path: &[Action]) -> Result<bool, ModelError> {
        let Some(client) = client(index) else {
            return Ok(false);
        };
        if self.is_open(client) {
            return Ok(false);
        }
        let plan = self.state.plan_session_opened(self.seed(client)?)?;
        self.commit(plan, &MutationContext::default(), path)?;
        Ok(true)
    }

    fn close(&mut self, index: u8, path: &[Action]) -> Result<bool, ModelError> {
        let Some(client) = client(index) else {
            return Ok(false);
        };
        if !self.is_open(client) {
            return Ok(false);
        }
        let plan = self
            .state
            .plan_session_disconnected(Self::user_of(client))?;
        let context = MutationContext {
            reason: "closed".to_owned(),
            ..MutationContext::default()
        };
        self.commit(plan, &context, path)?;
        Ok(true)
    }

    fn kick(
        &mut self,
        index: u8,
        target: u8,
        channel: usize,
        path: &[Action],
    ) -> Result<bool, ModelError> {
        let (Some(actor), Some(victim), Some(name)) =
            (client(index), client(target), channel_name(channel))
        else {
            return Ok(false);
        };
        if index == target || !self.is_open(victim) {
            return Ok(false);
        }
        let nickname = NicknameValue::parse(&format!("user{}", victim.index))?;
        let command = move || {
            CanonicalCommand::kick(
                name.clone(),
                vec![nickname.clone()],
                Some(DepartureReason::try_from_str(
                    "out",
                    ControlPolicy::RejectAll,
                )?),
            )
        };
        let context = MutationContext {
            actor: Some(Self::user_of(actor)),
            kicked: true,
            reason: "out".to_owned(),
            ..MutationContext::default()
        };
        self.run(actor, &command, &context, path)
    }

    /// The canonical fingerprint of the network: every replica's sorted
    /// records plus the open sessions, which is exactly what the edges and
    /// their clients can observe.
    fn fingerprint(&self) -> Fingerprint {
        let mut replicas = Vec::new();
        for (edge, replica) in &self.replicas {
            let mut entries: Vec<ProjectionRecord> = replica.entries().collect();
            entries.sort_by_key(ProjectionRecord::key);
            replicas.push((*edge, entries));
        }
        let open: BTreeSet<UserId> = self.state.session_user_ids().collect();
        Fingerprint { replicas, open }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct Fingerprint {
    replicas: Vec<(ServerId, Vec<ProjectionRecord>)>,
    open: BTreeSet<UserId>,
}

fn client(index: u8) -> Option<Client> {
    CLIENTS.iter().copied().find(|client| client.index == index)
}

fn channel_name(index: usize) -> Option<ChannelNameValue> {
    CHANNELS
        .get(index)
        .and_then(|name| ChannelNameValue::parse(name).ok())
}

fn violation(invariant: &'static str, path: &[Action]) -> ModelError {
    ModelError::Violation {
        invariant,
        path: path.to_vec(),
    }
}

/// The closed action alphabet in a fixed order.
#[must_use]
pub fn alphabet() -> Vec<Action> {
    let mut actions = Vec::new();
    for client in CLIENTS {
        actions.push(Action::Open(client.index));
        actions.push(Action::Close(client.index));
        for channel in 0..CHANNELS.len() {
            channel_actions(client, channel, &mut actions);
        }
    }
    actions
}

fn channel_actions(client: Client, channel: usize, actions: &mut Vec<Action>) {
    actions.push(Action::Join(client.index, channel));
    actions.push(Action::Part(client.index, channel));
    actions.push(Action::Message(client.index, channel));
    for target in CLIENTS {
        if target.index != client.index {
            actions.push(Action::Kick(client.index, target.index, channel));
        }
    }
}

/// Distinct states seen so far, bucketed by a cheap summary so equality
/// checks stay local.
#[derive(Default)]
struct StateSet {
    buckets: BTreeMap<(usize, Vec<usize>), Vec<Fingerprint>>,
}

impl StateSet {
    fn insert(&mut self, fingerprint: Fingerprint) -> bool {
        let summary = (
            fingerprint.open.len(),
            fingerprint
                .replicas
                .iter()
                .map(|(_, entries)| entries.len())
                .collect(),
        );
        let bucket = self.buckets.entry(summary).or_default();
        if bucket.contains(&fingerprint) {
            return false;
        }
        bucket.push(fingerprint);
        true
    }

    fn len(&self) -> usize {
        self.buckets.values().map(Vec::len).sum()
    }
}

/// Explores every action sequence up to `bounds.depth`, re-executing each
/// path from the empty network, and reports the reachable state space.
pub fn explore(bounds: ModelBounds) -> Result<ModelReport, ModelError> {
    let actions = alphabet();
    let mut states = StateSet::default();
    let mut report = ModelReport::default();
    states.insert(Network::new()?.fingerprint());
    let mut path: Vec<Action> = Vec::new();
    explore_from(&actions, bounds.depth, &mut path, &mut states, &mut report)?;
    report.states = states.len();
    Ok(report)
}

fn explore_from(
    actions: &[Action],
    remaining: usize,
    path: &mut Vec<Action>,
    states: &mut StateSet,
    report: &mut ModelReport,
) -> Result<(), ModelError> {
    if remaining == 0 {
        report.paths = report.paths.saturating_add(1);
        return Ok(());
    }
    let mut extended = false;
    for action in actions {
        path.push(*action);
        let executed = replay(path)?;
        match executed {
            Some(network) => {
                extended = true;
                report.transitions = report.transitions.saturating_add(1);
                states.insert(network.fingerprint());
                explore_from(actions, remaining - 1, path, states, report)?;
            }
            None => report.refusals = report.refusals.saturating_add(1),
        }
        path.pop();
    }
    if !extended {
        report.paths = report.paths.saturating_add(1);
    }
    Ok(())
}

/// Re-executes one path from the empty network; `None` when its last action
/// was refused (an earlier refusal never reaches here because refused
/// prefixes are not extended).
fn replay(path: &[Action]) -> Result<Option<Network>, ModelError> {
    let mut network = Network::new()?;
    for (index, action) in path.iter().enumerate() {
        let prefix = path.get(..=index).unwrap_or(path);
        if !network.step(*action, prefix)? {
            return Ok(None);
        }
    }
    Ok(Some(network))
}
