//! The edge E2EE router (companion 11, 12.5, 13, 17): client `EGROUP`,
//! `EKEY`, `EDIRECT`, and bound-channel `TAGMSG` lines become companion
//! requests under the connection's origin; results render only after their
//! completion coverage; events project route state, fan out opaque objects
//! to attached local sessions, and are acknowledged after their durable
//! apply; and until the companion link reaches `STATE_ACTIVE` every E2EE
//! command fails with `E2EE_SYNCING`.

mod completion;
mod entitlement;
mod events;
mod origins;
mod projection;
mod response_validation;
mod result;
mod retry;
mod router;
mod snapshot;
mod startup;
mod sync;
#[cfg(test)]
mod tests;
mod witness_checkpoint;
mod witness_failure;
mod witness_recovery;
mod witness_resolution;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use agenc_ircd_client_wire::{CapabilityState, WireMessage};
use agenc_ircd_domain::e2ee::RouteTable;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::wire::assembly::{E2eeAssembler, QuotaLimits};
use agenc_ircd_federation_wire::FederationLineText;
use agenc_ircd_types::{ChannelInstanceId, ServerId, UserId};

use crate::connection::ConnectionGeneration;

use crate::federation::edge::EdgeFederation;
use crate::state_core::StateCoreContext;

pub use result::{DecodedResult, ResultValue, decode_result, decode_value};
pub use router::{E2EE_CAPABILITY, is_e2ee_line};

/// The fixed identities of the edge and its coordinator.
#[derive(Clone, Debug)]
pub struct E2eeEdgeConfig {
    /// Network identity.
    pub network_id: [u8; 32],
    /// This edge's Server ID.
    pub server_id: ServerId,
    /// The server name every client line carries as its prefix.
    pub server_name: String,
    /// The coordinator's Server ID.
    pub coordinator_server_id: ServerId,
    /// The sequencer key set this node negotiated on the companion link:
    /// the active credential and at most its overlapping successor. A
    /// witness resolution accepts a record only under one of them
    /// (companion 12.5.1).
    pub sequencer_key_set: Option<agenc_ircd_e2ee::sequencer::SequencerKeySet>,
    /// This edge's incarnation.
    pub incarnation: [u8; 16],
    /// The configured logical E2EE disk ceiling, reported by `STATS E2EE`.
    pub global_disk_bytes: u64,
}

/// What the registration router knows about the connection issuing a line.
pub struct SessionFacts<'a> {
    /// The bound session user.
    pub user_id: UserId,
    /// The authenticated Account ID in its 24-byte wire form.
    pub account: Option<[u8; 24]>,
    /// The negotiated capabilities.
    pub capabilities: &'a CapabilityState,
    /// The nickname, for failure lines.
    pub nickname: &'a str,
}

/// Lines for one client connection.
#[derive(Debug)]
pub struct ClientOutput {
    /// The connection.
    pub generation: ConnectionGeneration,
    /// The frames in order.
    pub frames: Vec<WireMessage>,
}

/// Where the companion link stands (12.5 STATE_ACTIVE).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// No companion link.
    Down,
    /// The profile is active; ERESUME went out.
    Resuming,
    /// `ERESUME OK` arrived while a durable `witness/v1` row is unresolved:
    /// only `EWITNESS` frames flow until every row resolves (12.5.1).
    Witness,
    /// An ESTATE transfer is in progress.
    Transferring,
    /// READY went out; ACTIVE is awaited.
    AwaitingActive,
    /// The origin set replays; EORIGIN READY is awaited.
    Origins,
    /// Requests and events flow.
    Active,
}

/// The companion origin of one local connection.
#[derive(Clone, Debug)]
pub(crate) struct LocalOrigin {
    /// The base origin identity.
    pub(crate) origin_id: [u8; 16],
    /// The base generation the last declaration mirrored.
    pub(crate) declared: Option<u64>,
    /// The generation the coordinator acknowledged.
    pub(crate) acked: Option<u64>,
    /// The acknowledged generation whose declaration predates the attached
    /// device; requests wait until a later generation is acknowledged.
    pub(crate) predates_device: Option<u64>,
    /// The next companion operation sequence.
    pub(crate) next_sequence: u64,
    /// The generation the operation sequence counts under; a fresh
    /// generation restarts it, a replayed declaration of the same
    /// generation continues it.
    pub(crate) sequenced: Option<u64>,
    /// The semantic identifier of the accepted declaration.
    pub(crate) state_id: [u8; 32],
    /// The last declaration's exact wire bytes, retained across link loss
    /// even when its acknowledgement has not arrived.
    pub(crate) declaration: Option<(u64, Vec<u8>)>,
    /// The bound user.
    pub(crate) user_id: Option<UserId>,
    /// The authenticated account.
    pub(crate) account: Option<[u8; 24]>,
    /// The attached device and its session generation.
    pub(crate) device: Option<([u8; 16], u64)>,
}

/// One request awaiting its result, its responses, and its completion.
pub(crate) struct PendingRequest {
    pub(super) reply_key: Option<retry::ReplyKey>,
    pub(super) echo_lines: Vec<String>,
    pub(super) retry_label: Option<Option<String>>,
    pub(crate) generation: ConnectionGeneration,
    pub(crate) label: Option<String>,
    pub(crate) command: router::Resolved,
    /// The candidate or policy identifier a `STORED` line names besides
    /// the object, taken from the payload at ingress.
    pub(crate) subject: Option<[u8; 32]>,
    pub(crate) request_object_id: [u8; 32],
    /// The operation sequence, for resending in order.
    pub(crate) sequence: u64,
    /// The request and payload frames exactly as first sent, resent after
    /// a resume while the result is outstanding.
    pub(crate) frames: Vec<agenc_ircd_e2ee::federation::frames::CompanionFrame>,
    pub(crate) result: Option<DecodedResult>,
    /// Exact result envelope identity, retained to reject conflicting duplicates.
    pub(super) result_object_id: Option<[u8; 32]>,
    pub(crate) responses: BTreeMap<u16, Vec<u8>>,
    pub(crate) completion_seen: bool,
    pub(crate) rendered: bool,
}

/// One local ingress assembly: one in-progress object per sender (11.8).
pub(crate) struct Ingress {
    pub(crate) key: agenc_ircd_e2ee::wire::assembly::AssemblyKey,
    pub(crate) command: router::Resolved,
}

/// The durable apply one event batch completes.
pub(crate) enum PendingCommit {
    /// An event applied; its EACK goes out on commit.
    Event {
        completion: completion::PreparedCompletion,
        position: agenc_ircd_e2ee::federation::frames::DeliveryPosition,
        outputs: Vec<ClientOutput>,
    },
    /// The READY of a snapshot was recorded.
    /// One accepted snapshot page is durable; the next page is fetched.
    SnapshotPage { cursor: [u8; 32] },
    /// The last page and the READY marker are durable.
    Ready,
    /// The ACTIVE marker and the new delivery cursor are durable.
    SnapshotActive,
    /// One migration or cleanup batch is durable.
    SnapshotStep {
        done: bool,
        switched_through: Option<[u8; 32]>,
    },
    /// A witness violation row awaits its exact durable receipt.
    Witness,
    /// An authenticated witness resolution installs its new head and
    /// deletes its row; `EWITNESS RESOLVED` follows the receipt (12.5.1).
    WitnessResolved {
        conversation: [u8; 32],
        token: [u8; 16],
        head: events::ChainHead,
    },
    /// An unresolvable fork marks its row `conflict` (12.5.1).
    WitnessConflict { conversation: [u8; 32] },
}

/// The companion parts of one open barrier by part index, each with its
/// payload when the event named one.
type BarrierParts = BTreeMap<u16, (events::OpenEvent, Option<Vec<u8>>)>;

/// The edge E2EE router.
pub struct E2eeEdge {
    projection_before: Option<projection::ProjectionBefore>,
    barrier_completions: Vec<completion::PreparedCompletion>,
    replies: retry::Replies,
    config: E2eeEdgeConfig,
    phase: Phase,
    delivery: sync::DeliveryState,
    witness_snapshot_required: bool,
    snapshot: Option<snapshot::SnapshotInstall>,
    snapshot_backing: Option<crate::budget::BackingReservationPort>,
    snapshot_strays: BTreeMap<u64, Vec<[u8; 32]>>,
    snapshot_stray_generations: BTreeMap<u64, Vec<[u8; 32]>>,
    origins: BTreeMap<ConnectionGeneration, LocalOrigin>,
    pending: BTreeMap<[u8; 16], PendingRequest>,
    by_completion: BTreeMap<[u8; 16], [u8; 16]>,
    covered: BTreeSet<[u8; 16]>,
    assembler: E2eeAssembler,
    ingress: BTreeMap<ConnectionGeneration, Ingress>,
    routes: RouteTable,
    route_objects: BTreeMap<[u8; 32], Vec<u8>>,
    conversations: BTreeMap<[u8; 32], events::Conversation>,
    commit: Option<PendingCommit>,
    /// The record-chain violation the witness found in the current frame,
    /// recorded durably before the link closes.
    witnessed: Option<([u8; 32], agenc_ircd_storage::e2ee_records::WitnessRow)>,
    witness_failure: witness_failure::WitnessFailure,
    witness_recovery: witness_recovery::WitnessRecovery,
    witness_resolution: Option<witness_resolution::OpenResolution>,
    witness_request_wake: Option<crate::state_core::timers::TimerEntry>,
    queued: VecDeque<(CompanionFrame, Vec<u8>)>,
    events_in: BTreeMap<[u8; 16], events::OpenEvent>,
    channel_names: BTreeMap<ChannelInstanceId, String>,
    attachments: Vec<(ConnectionGeneration, [u8; 16], u64)>,
    /// Companion parts of open cross-profile barriers by mutation and part
    /// index, applied when the base edge's barrier transaction stages.
    barrier_parts: BTreeMap<[u8; 16], BarrierParts>,
    /// Rendered lines of a staged barrier, released once its receipt stands.
    barrier_pending: Option<([u8; 16], Vec<ClientOutput>)>,
    counters: E2eeEdgeCounters,
}

/// Counters exposed through `STATS E2EE`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct E2eeEdgeCounters {
    /// Requests sent to the coordinator.
    pub requests_sent: u64,
    /// Results rendered to clients.
    pub results_rendered: u64,
    /// Events applied and acknowledged.
    pub events_applied: u64,
    /// Client lines refused with a companion reply code.
    pub refusals: u64,
    /// Protocol violations that closed the companion link.
    pub violations: u64,
    /// Sequencer record-chain violations the witness refused (12.5).
    pub chain_violations: u64,
}

impl E2eeEdge {
    /// Creates a router with no companion link.
    #[must_use]
    pub fn new(config: E2eeEdgeConfig) -> Self {
        Self {
            projection_before: None,
            barrier_completions: Vec::new(),
            replies: retry::Replies::default(),
            config,
            phase: Phase::Down,
            delivery: sync::DeliveryState::default(),
            witness_snapshot_required: true,
            snapshot: None,
            snapshot_backing: None,
            snapshot_strays: BTreeMap::new(),
            snapshot_stray_generations: BTreeMap::new(),
            origins: BTreeMap::new(),
            pending: BTreeMap::new(),
            by_completion: BTreeMap::new(),
            covered: BTreeSet::new(),
            assembler: E2eeAssembler::new(QuotaLimits::default()),
            ingress: BTreeMap::new(),
            routes: RouteTable::new(),
            route_objects: BTreeMap::new(),
            conversations: BTreeMap::new(),
            commit: None,
            witnessed: None,
            witness_failure: witness_failure::WitnessFailure::default(),
            witness_recovery: witness_recovery::WitnessRecovery::default(),
            witness_resolution: None,
            witness_request_wake: None,
            queued: VecDeque::new(),
            events_in: BTreeMap::new(),
            channel_names: BTreeMap::new(),
            attachments: Vec::new(),
            barrier_parts: BTreeMap::new(),
            barrier_pending: None,
            counters: E2eeEdgeCounters::default(),
        }
    }

    /// The counters.
    #[must_use]
    pub const fn counters(&self) -> E2eeEdgeCounters {
        self.counters
    }

    /// Where the companion link stands.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Whether requests and events flow.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.phase == Phase::Active && !self.witness_pending() && !self.witness_recovery_pending()
    }

    /// The projected route table, for downgrade checks.
    #[must_use]
    pub const fn routes(&self) -> &RouteTable {
        &self.routes
    }

    /// Whether the companion link and every retained assembly of a closed
    /// link are gone.
    pub fn link_down(&mut self) {
        self.barrier_completions.clear();
        self.phase = Phase::Down;
        // A resolution token belongs to one link incarnation (12.5.1).
        self.witness_resolution = None;
        self.snapshot_link_down();
        self.queued.clear();
        self.events_in.clear();
        self.barrier_pending = None;
        for origin in self.origins.values_mut() {
            origin.declared = None;
            origin.acked = None;
        }
    }

    /// A client connection ended: its origin, ingress, and pending
    /// requests are gone; a result that still arrives is dropped.
    pub fn connection_closed(&mut self, generation: ConnectionGeneration) {
        self.replies.disconnect(generation);
        self.origins.remove(&generation);
        if let Some(ingress) = self.ingress.remove(&generation) {
            self.assembler.discard(&ingress.key);
        }
        self.pending
            .retain(|_, pending| pending.generation != generation);
    }

    /// Remembers the presentation name of a channel the replica projects,
    /// so live copies can name it.
    pub fn remember_channel(&mut self, channel: ChannelInstanceId, name: &str) {
        self.channel_names.insert(channel, name.to_owned());
    }

    /// Whether `channel` is bound to an active encrypted route here.
    #[must_use]
    pub fn channel_bound(&self, channel: &ChannelInstanceId) -> bool {
        self.routes.channel_route(channel).is_some_and(|route| {
            !self.routes.channel_plaintext_allowed(channel) || route.accepts_traffic()
        })
    }

    /// The nine `STATS E2EE` values of an edge (spec 22.3): the enabled
    /// flag, the projected routes accepting traffic, and the configured
    /// disk ceiling; every coordinator-only counter stays zero.
    #[must_use]
    pub fn stats(&self) -> [u64; 9] {
        let active = self
            .routes
            .routes()
            .filter(|route| route.accepts_traffic())
            .count();
        [
            1,
            u64::try_from(active).unwrap_or(u64::MAX),
            0,
            0,
            0,
            0,
            0,
            self.config.global_disk_bytes,
            0,
        ]
    }

    /// The `FAIL <command> E2EE_RATE_LIMITED` line for a line the admission
    /// buckets refused before any parsing.
    #[must_use]
    pub fn rate_limited(
        &mut self,
        generation: ConnectionGeneration,
        message: &agenc_ircd_client_wire::ParsedMessage,
    ) -> Vec<ClientOutput> {
        self.counters.refusals = self.counters.refusals.saturating_add(1);
        self.refuse(
            generation,
            message,
            &agenc_ircd_e2ee::wire::reply::E2eeReplyCode::RateLimited.into(),
        )
    }

    /// Lines produced outside a frame or batch hook; none today, kept so the
    /// owner's drive order stays fixed.
    #[must_use]
    pub fn batch_applied_outputs(&mut self) -> Vec<ClientOutput> {
        Vec::new()
    }

    /// Applies the device attachments results announced since the last
    /// call: each advances the shared origin generation with its device.
    pub fn apply_attachments(&mut self, context: &mut StateCoreContext, edge: &mut EdgeFederation) {
        for (generation, device, session_generation) in std::mem::take(&mut self.attachments) {
            self.device_attached(context, edge, generation, device, session_generation);
        }
    }

    /// The `FAIL <command> E2EE_REQUIRED` line when a plaintext line targets
    /// a bound channel or a bound direct pair (companion 11.3, 11.4, 17).
    #[must_use]
    pub fn plaintext_refusal(
        &self,
        edge: &EdgeFederation,
        message: &agenc_ircd_client_wire::ParsedMessage,
        sender_account: Option<[u8; 24]>,
    ) -> Option<WireMessage> {
        let command = message.command();
        if !matches!(command, "PRIVMSG" | "NOTICE" | "TAGMSG" | "TOPIC") {
            return None;
        }
        let target = message.middle().first()?;
        let bound = if target.starts_with('#') {
            self.bound_channel(edge, target).is_some()
                || agenc_ircd_domain::ChannelNameValue::parse(target)
                    .ok()
                    .and_then(|name| edge.replica().channel_by_name(&name))
                    .is_some_and(|record| {
                        record.content_policy == agenc_ircd_domain::ContentPolicy::E2eeBound
                    })
        } else {
            self.direct_pair_bound(edge, target, sender_account?)
        };
        if !bound {
            return None;
        }
        let body = agenc_ircd_e2ee::wire::reply::E2eeReplyCode::Required
            .render_fail(command, Some(target));
        agenc_ircd_e2ee::wire::response::render_fail(&self.config.server_name, &body)
            .ok()
            .and_then(|line| WireMessage::extension_line(&line).ok())
    }

    /// Whether the sender's account and the account behind `nickname` hold
    /// a live direct binding.
    fn direct_pair_bound(&self, edge: &EdgeFederation, nickname: &str, sender: [u8; 24]) -> bool {
        let Some(peer) = edge
            .replica()
            .sessions()
            .find(|session| session.nickname.presentation() == nickname)
            .and_then(|session| session.account.map(|(account, _)| account))
        else {
            return false;
        };
        let Ok(sender) = agenc_ircd_types::AccountId::parse_wire_bytes(&sender) else {
            return false;
        };
        agenc_ircd_domain::e2ee::DirectPair::new(sender, peer)
            .ok()
            .and_then(|pair| self.routes.direct_route(&pair))
            .is_some_and(|route| route.accepts_traffic())
    }

    /// Sends companion lines over the base edge's live link.
    fn send(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        lines: Vec<FederationLineText>,
    ) -> bool {
        edge.send_companion_lines(context, lines)
    }
}
