//! Companion peer synchronization on the coordinator: EORIGIN mirroring of
//! the ACKed base origins, ERESUME against the retained delivery cursor,
//! and the ESTATE route-state transfer that opens a new delivery generation
//! (companion 12.5).
//!
//! The snapshot cut lives in memory until the edge's READY is recorded;
//! a coordinator restart mid-transfer therefore fails the edge's next FETCH,
//! which closes the link and restarts the transfer from a fresh cut.

use agenc_ircd_crypto::SemanticHashDomain;
use agenc_ircd_domain::e2ee::limits::MAX_BATCH_OBJECTS;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::ids::{account_id_digest, federation_snapshot_digest, semantic_id_of};
use agenc_ircd_e2ee::limits::{
    MAX_BATCH_DECODED_BYTES, MAX_FEDERATION_STATE_ENTRIES_PER_EDGE,
    MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE,
};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::IrcFederationOrigin;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::assembly::{AssemblyKey, Direction, Sender};
use agenc_ircd_e2ee::wire::carrier::CarrierCommand;
use agenc_ircd_e2ee::wire::fragment::{FragmentTag, fragment_object};
use agenc_ircd_federation_wire::FederationLineText;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{DELIVERY_ROW_KIND, DeliveryRow};
use agenc_ircd_types::{EntropySource, ServerId};

use super::events::{self, DeliveryStream};
use super::request::state_row;
use super::{
    CompanionCoordinator, CompanionFault, CompanionOrigin, CompanionOriginKey, CompleteRequest,
    PendingCompanion,
};
use crate::federation::LinkId;
use crate::state_core::durable::AccountServiceDurableWrite;

/// The fixed, nonextendable snapshot token lifetime.
pub const SNAPSHOT_TOKEN_MILLIS: u64 = 15 * 60 * 1_000;
const ORIGIN_DECODE_VALUES: usize = 64;

/// The ACKed base origin the companion object must mirror.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseOriginView {
    /// The base origin generation.
    pub generation: u64,
    /// The accepted transport identity.
    pub connection_id: [u8; 16],
    /// The connection nonce.
    pub connection_nonce: [u8; 32],
    /// The session and user identities, if registered.
    pub session: Option<([u8; 16], [u8; 16])>,
    /// The authenticated account and its session generation.
    pub account: Option<([u8; 24], u64)>,
}

/// The base facts the owner supplies while a companion frame is handled.
pub trait CompanionHost {
    /// The incarnation of the live link of `peer`.
    fn live_incarnation(&self, peer: ServerId) -> Option<[u8; 16]>;
    /// The ACKed base origin under `key`.
    fn base_origin(&self, key: &CompanionOriginKey) -> Option<BaseOriginView>;
    /// Whether the base origin set of `peer` is ready.
    fn base_origins_ready(&self, peer: ServerId) -> bool;
    /// The edge's durable client resync epoch, advanced by a base snapshot.
    fn base_resync_epoch(&self, peer: ServerId) -> u64;
    /// The committed coordinator state generation.
    fn state_generation(&self) -> u64;
    /// Whether the peer the frame came from holds the channel instance in
    /// the base projection (its route entitlement, companion 12.5).
    fn holds_channel(&self, instance: [u8; 16]) -> bool;
    /// Whether the peer the frame came from has a live base origin of
    /// `account`.
    fn hosts_account(&self, account: &[u8; 24]) -> bool;
}

/// What the owner does after one companion frame.
pub(crate) enum Action {
    /// Executes one complete request.
    Execute(CompleteRequest),
    /// Sends lines on the peer's link.
    Send(Vec<FederationLineText>),
    /// Stages one durable batch and marks the pending work.
    Stage {
        /// The rows.
        writes: Vec<AccountServiceDurableWrite>,
        /// What completes after commit.
        work: PendingWork,
    },
    /// Schedules the snapshot expiry timer of the peer.
    ScheduleExpiry {
        /// The absolute deadline in milliseconds.
        at_millis: u64,
    },
}

/// The work one companion batch completes on commit.
pub enum PendingWork {
    /// A request's result, responses, and event copies.
    Request(Box<PendingCompanion>),
    /// The recorded READY of a snapshot; ACTIVE goes out on commit.
    Activate {
        /// The peer.
        peer: ServerId,
        /// The link.
        link: LinkId,
    },
}

/// What went out of a committed companion batch.
pub enum Committed {
    /// A request completed.
    Request(Box<PendingCompanion>),
    /// Lines to send, each to its target's live link.
    Lines(Vec<(ServerId, FederationLineText)>),
}

/// One immutable snapshot cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cut {
    /// The token.
    pub token: [u8; 32],
    /// The coordinator state generation at the cut.
    pub state_generation: u64,
    /// The delivery generation the transfer opens.
    pub delivery_generation: u64,
    /// The snapshot digest.
    pub digest: [u8; 32],
    /// The entry count.
    pub entry_count: u32,
}

/// One snapshot entry: the conversation and its route state object.
type Entry = ([u8; 32], Vec<u8>);

/// One ESTATE transfer in progress.
pub struct Snapshot {
    /// The cut.
    pub cut: Cut,
    pages: Vec<Vec<Entry>>,
    cursors: Vec<[u8; 32]>,
    pages_sent: usize,
    expires_at_millis: u64,
}

/// The synchronization state of one edge.
#[derive(Default)]
pub struct PeerSync {
    /// The incarnation this scope belongs to.
    pub incarnation: Option<[u8; 16]>,
    /// The base resync epoch the last transfer covered.
    pub resync_epoch: u64,
    /// Whether EORIGIN RESET was accepted for the live incarnation.
    pub origins_reset: bool,
    /// Whether EORIGIN READY went out for the live incarnation.
    pub origins_ready: bool,
    /// Whether delivery flows: ERESUME OK or ACTIVE was sent.
    pub active: bool,
    /// Whether a transfer opened a generation that never reached ACTIVE.
    pub transfer_incomplete: bool,
    /// The transfer in progress.
    pub snapshot: Option<Snapshot>,
    /// The READY recorded durably, answered by the identical ACTIVE.
    pub ready_cut: Option<Cut>,
}

fn line(server_name: &str, frame: &CompanionFrame) -> Result<FederationLineText, CompanionFault> {
    events::line(server_name, frame).map_err(|_| CompanionFault::Protocol)
}

fn require_live(
    host: &dyn CompanionHost,
    peer: ServerId,
    incarnation: [u8; 16],
) -> Result<(), CompanionFault> {
    if host.live_incarnation(peer) == Some(incarnation) {
        Ok(())
    } else {
        Err(CompanionFault::Protocol)
    }
}

impl CompanionCoordinator {
    fn require_self(&self, coordinator_server_id: [u8; 16]) -> Result<(), CompanionFault> {
        if coordinator_server_id == *self.server_id.as_bytes() {
            Ok(())
        } else {
            Err(CompanionFault::Protocol)
        }
    }

    /// EORIGIN RESET: the peer replays its origin set for the live
    /// incarnation; older incarnations of that home are fenced.
    pub(super) fn origin_reset(
        &mut self,
        peer: ServerId,
        coordinator_server_id: [u8; 16],
        incarnation: [u8; 16],
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(coordinator_server_id)?;
        require_live(host, peer, incarnation)?;
        let home = *peer.as_bytes();
        for (key, origin) in self.state.origins.iter_mut() {
            if key.home_server_id != home {
                continue;
            }
            if key.server_incarnation == incarnation {
                origin.suspended = true;
            } else {
                origin.fenced = true;
            }
        }
        let sync = self.peers.entry(peer).or_default();
        sync.origins_reset = true;
        sync.origins_ready = false;
        if host.base_origins_ready(peer) {
            return self
                .origins_ready(peer, incarnation)
                .map(|line| line.map_or_else(Vec::new, |line| vec![Action::Send(vec![line])]));
        }
        Ok(Vec::new())
    }

    /// Sends EORIGIN READY once the base set is ready and the companion
    /// RESET was accepted; idempotent.
    pub fn origins_ready(
        &mut self,
        peer: ServerId,
        incarnation: [u8; 16],
    ) -> Result<Option<FederationLineText>, CompanionFault> {
        let sync = self.peers.entry(peer).or_default();
        if !sync.origins_reset || sync.origins_ready {
            return Ok(None);
        }
        sync.origins_ready = true;
        line(
            &self.server_name,
            &CompanionFrame::OriginReady {
                home_server_id: *peer.as_bytes(),
                server_incarnation: incarnation,
            },
        )
        .map(Some)
    }

    /// EORIGIN ADD or UPDATE: assembles the origin object and mirrors the
    /// ACKed base origin.
    // agenc-review: allow owner=runtime reviewed=2026-09-03 reason=an origin declaration carries its frame descriptor fields, fragment, clock, and host through one validation path
    #[allow(clippy::too_many_arguments)]
    pub(super) fn origin_state(
        &mut self,
        peer: ServerId,
        update: bool,
        descriptor: OriginDescriptor,
        fragment: FragmentTag,
        now_millis: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(descriptor.coordinator_server_id)?;
        require_live(host, peer, descriptor.server_incarnation)?;
        let command = CarrierCommand::Federation(IrcWireObjectKind::FederationOrigin);
        let mut route = [0; 32];
        if let Some(head) = route.get_mut(..16) {
            head.copy_from_slice(&descriptor.origin_id);
        }
        let key = AssemblyKey {
            direction: Direction::Remote,
            sender: Sender::Peer(*peer.as_bytes()),
            command,
            route,
            scope: None,
            object_id: agenc_ircd_e2ee::ObjectId::from_bytes(descriptor.object_id),
        };
        let bytes = match self.ingest(key, peer, command, &fragment, now_millis)? {
            super::Ingested::Complete(bytes) => bytes,
            super::Ingested::Pending => return Ok(Vec::new()),
            super::Ingested::Recent => return self.redeclared(peer, &descriptor),
        };
        let origin = decode_origin(&bytes)?;
        let object_id = *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes();
        let matches = origin.network_id == self.network_id
            && origin.home_server_id == *peer.as_bytes()
            && origin.server_incarnation == descriptor.server_incarnation
            && origin.origin_id == descriptor.origin_id
            && origin.origin_generation == descriptor.origin_generation
            && object_id == descriptor.object_id;
        if !matches {
            return Err(CompanionFault::Protocol);
        }
        let origin_key = CompanionOriginKey {
            home_server_id: origin.home_server_id,
            server_incarnation: origin.server_incarnation,
            origin_id: origin.origin_id,
        };
        let base = host
            .base_origin(&origin_key)
            .ok_or(CompanionFault::Protocol)?;
        let mirrored = self.mirror_origin(&origin, &bytes, &base)?;
        self.accept_origin(origin_key, mirrored, update)?;
        let ack = line(
            &self.server_name,
            &CompanionFrame::OriginAck {
                home_server_id: *peer.as_bytes(),
                server_incarnation: descriptor.server_incarnation,
                origin_id: descriptor.origin_id,
                origin_generation: descriptor.origin_generation,
                object_id: Some(object_id),
            },
        )?;
        Ok(vec![Action::Send(vec![ack])])
    }

    /// An origin object the assembler already completed: the identical
    /// declaration of the accepted state again is acknowledged again.
    fn redeclared(
        &mut self,
        peer: ServerId,
        descriptor: &OriginDescriptor,
    ) -> Result<Vec<Action>, CompanionFault> {
        let key = CompanionOriginKey {
            home_server_id: *peer.as_bytes(),
            server_incarnation: descriptor.server_incarnation,
            origin_id: descriptor.origin_id,
        };
        let reset = self.peers.get(&peer).is_some_and(|sync| sync.origins_reset);
        let existing = self
            .state
            .origins
            .get_mut(&key)
            .filter(|origin| {
                !origin.fenced
                    && origin.object_id == descriptor.object_id
                    && origin.generation == descriptor.origin_generation
            })
            .ok_or(CompanionFault::Protocol)?;
        if !reset {
            return Err(CompanionFault::Protocol);
        }
        existing.suspended = false;
        let ack = line(
            &self.server_name,
            &CompanionFrame::OriginAck {
                home_server_id: *peer.as_bytes(),
                server_incarnation: descriptor.server_incarnation,
                origin_id: descriptor.origin_id,
                origin_generation: descriptor.origin_generation,
                object_id: Some(descriptor.object_id),
            },
        )?;
        Ok(vec![Action::Send(vec![ack])])
    }

    /// Checks every mirrored field against the base origin and the device
    /// attachment against the directory.
    fn mirror_origin(
        &self,
        origin: &IrcFederationOrigin,
        bytes: &[u8],
        base: &BaseOriginView,
    ) -> Result<CompanionOrigin, CompanionFault> {
        if origin.profile_version != 1
            || origin.origin_generation != base.generation
            || origin.connection_id != base.connection_id
            || origin.connection_nonce != base.connection_nonce
        {
            return Err(CompanionFault::Protocol);
        }
        let account = mirrored_principal(origin, base)?;
        let account_digest = account
            .map(|account| account_id_digest(&self.network_id, &account))
            .transpose()
            .map_err(|_| CompanionFault::Protocol)?;
        let device = self.mirrored_device(origin, account_digest)?;
        let state_id = semantic_id_of(SemanticHashDomain::FederationOriginState, origin)
            .map_err(|_| CompanionFault::Protocol)?;
        Ok(CompanionOrigin {
            home_server_id: origin.home_server_id,
            server_incarnation: origin.server_incarnation,
            origin_id: origin.origin_id,
            generation: origin.origin_generation,
            next_sequence: 0,
            account_id: account,
            account_digest,
            device,
            connection_nonce: origin.connection_nonce,
            connection_id: origin.connection_id,
            object_id: *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes(),
            state_id,
            previous_state_id: origin.previous_origin_state_id,
            suspended: false,
            fenced: false,
        })
    }

    /// An attached device needs an account and the directory's current
    /// session generation; absence needs both fields empty.
    fn mirrored_device(
        &self,
        origin: &IrcFederationOrigin,
        account_digest: Option<[u8; 32]>,
    ) -> Result<Option<([u8; 16], u64)>, CompanionFault> {
        let generation = origin.device_session_generation;
        match (optional16(&origin.attached_device_id)?, account_digest) {
            (None, _) if generation == 0 => Ok(None),
            (Some(device), Some(digest))
                if generation != 0
                    && self.state.directory.session_generation(&digest, &device) == generation =>
            {
                Ok(Some((device, generation)))
            }
            _ => Err(CompanionFault::Protocol),
        }
    }

    /// Applies the generation rules: ADD opens generation zero, UPDATE
    /// advances by one naming its predecessor, and an identical
    /// re-declaration after reconnect is accepted without change.
    fn accept_origin(
        &mut self,
        key: CompanionOriginKey,
        mirrored: CompanionOrigin,
        update: bool,
    ) -> Result<(), CompanionFault> {
        let sync = self
            .peers
            .entry(ServerId::from_bytes(key.home_server_id))
            .or_default();
        if !sync.origins_reset {
            return Err(CompanionFault::Protocol);
        }
        match self.state.origins.get_mut(&key) {
            Some(existing) => accept_successor(existing, mirrored, update),
            None if !update
                && mirrored.generation == 0
                && mirrored.previous_state_id == [0; 32] =>
            {
                let mut mirrored = mirrored;
                mirrored.next_sequence = self.replayed_next_sequence(&key, mirrored.generation)?;
                self.state.origins.insert(key, mirrored);
                Ok(())
            }
            None if update && mirrored.generation != 0 => {
                // A coordinator that reloaded without its companion origins
                // (they are not durable) meets the replayed declaration of
                // an origin it acknowledged before. The matched base origin
                // anchors it; the operation sequence continues from its
                // durable floor even after replay results have expired.
                let mut mirrored = mirrored;
                mirrored.next_sequence = self.replayed_next_sequence(&key, mirrored.generation)?;
                self.state.origins.insert(key, mirrored);
                Ok(())
            }
            None => Err(CompanionFault::Protocol),
        }
    }

    /// Restores the durable sequence floor. Legacy replay rows cannot prove
    /// the latest sequence because their retention periods differ. A used
    /// generation with no matching floor must be replaced. Without any
    /// retained history, a never-used generation starts at zero.
    fn replayed_next_sequence(
        &self,
        key: &CompanionOriginKey,
        generation: u64,
    ) -> Result<u64, CompanionFault> {
        let floor = self.state.origin_sequences.get(key);
        let mut next_sequence = match floor {
            Some(row) if row.origin_generation > generation => {
                return Err(CompanionFault::Protocol);
            }
            Some(row) if row.origin_generation == generation => row.next_sequence,
            _ => 0,
        };
        for replay in self.state.replays.keys().filter(|replay| {
            replay.home_server_id == key.home_server_id
                && replay.server_incarnation == key.server_incarnation
                && replay.origin_id == key.origin_id
                && replay.origin_generation == generation
        }) {
            if !floor.is_some_and(|row| row.origin_generation == generation) {
                return Err(CompanionFault::Protocol);
            }
            next_sequence = next_sequence.max(
                replay
                    .operation_sequence
                    .checked_add(1)
                    .ok_or(CompanionFault::Protocol)?,
            );
        }
        Ok(next_sequence)
    }

    /// EORIGIN DEL: fences the origin at its next unused sequence.
    pub(super) fn origin_del(
        &mut self,
        peer: ServerId,
        descriptor: OriginDescriptor,
        next_operation_sequence: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(descriptor.coordinator_server_id)?;
        require_live(host, peer, descriptor.server_incarnation)?;
        let key = CompanionOriginKey {
            home_server_id: *peer.as_bytes(),
            server_incarnation: descriptor.server_incarnation,
            origin_id: descriptor.origin_id,
        };
        // An origin this coordinator never learned (its connection ended
        // while the coordinator was down) has nothing to fence: requests
        // under it are refused already.
        if let Some(origin) = self.state.origins.get_mut(&key) {
            if origin.generation != descriptor.origin_generation
                || origin.next_sequence != next_operation_sequence
            {
                return Err(CompanionFault::Protocol);
            }
            origin.fenced = true;
        }
        let ack = line(
            &self.server_name,
            &CompanionFrame::OriginAck {
                home_server_id: *peer.as_bytes(),
                server_incarnation: descriptor.server_incarnation,
                origin_id: descriptor.origin_id,
                origin_generation: descriptor.origin_generation,
                object_id: None,
            },
        )?;
        Ok(vec![Action::Send(vec![ack])])
    }

    /// ERESUME: an exact cursor resumes the retained stream; a new scope or
    /// a base-forced reset opens an ESTATE transfer.
    // agenc-review: allow owner=runtime reviewed=2026-09-03 reason=a resume carries the frame fields, the clock, the host, and entropy through one decision
    #[allow(clippy::too_many_arguments)]
    pub(super) fn resume(
        &mut self,
        peer: ServerId,
        coordinator_server_id: [u8; 16],
        incarnation: [u8; 16],
        delivery_generation: u64,
        last: Option<(u64, [u8; 16])>,
        now_millis: u64,
        host: &dyn CompanionHost,
        entropy: &mut dyn EntropySource,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(coordinator_server_id)?;
        require_live(host, peer, incarnation)?;
        let sync = self.peers.entry(peer).or_default();
        if sync.active || sync.snapshot.is_some() {
            return Err(CompanionFault::Protocol);
        }
        let same_scope =
            sync.incarnation == Some(incarnation) && self.state.streams.contains_key(&peer);
        let reset = host.base_resync_epoch(peer) > sync.resync_epoch || sync.transfer_incomplete;
        if !same_scope || reset {
            // A retired generation never restarts: the next one follows
            // the last stream this coordinator knows for the peer, which a
            // reload took from the durable cursor row.
            let generation = self
                .state
                .streams
                .get(&peer)
                .map_or(0, |stream| stream.generation.saturating_add(1));
            return self.begin_snapshot(peer, incarnation, generation, now_millis, host, entropy);
        }
        let stream = self
            .state
            .streams
            .get(&peer)
            .ok_or(CompanionFault::Protocol)?;
        if stream.generation != delivery_generation || stream.acked != last {
            return Err(CompanionFault::Protocol);
        }
        let next = stream
            .acked
            .map_or(Some(0), |(sequence, _)| sequence.checked_add(1))
            .ok_or(CompanionFault::Ceiling)?;
        let mut lines = vec![line(
            &self.server_name,
            &CompanionFrame::ResumeOk {
                target_server_id: *peer.as_bytes(),
                server_incarnation: incarnation,
                delivery_generation,
                next_delivery_sequence: next,
            },
        )?];
        lines.extend(retransmission(&self.server_name, peer, stream)?);
        let sync = self.peers.entry(peer).or_default();
        sync.active = true;
        Ok(vec![Action::Send(lines)])
    }

    /// Cuts the entitled route set of `peer` and sends page zero.
    fn begin_snapshot(
        &mut self,
        peer: ServerId,
        incarnation: [u8; 16],
        delivery_generation: u64,
        now_millis: u64,
        host: &dyn CompanionHost,
        entropy: &mut dyn EntropySource,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.refresh_entitlements(peer, host);
        let entries = self.entitled_entries(peer)?;
        let ids: Vec<[u8; 32]> = entries
            .iter()
            .map(|(_, bytes)| *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes())
            .collect();
        let state_generation = host.state_generation();
        let digest = federation_snapshot_digest(state_generation, delivery_generation, &ids)
            .map_err(|_| CompanionFault::Protocol)?;
        let mut token = [0; 32];
        entropy
            .fill_exact(&mut token)
            .map_err(|_| CompanionFault::Storage)?;
        let pages: Vec<Vec<Entry>> = if entries.is_empty() {
            vec![Vec::new()]
        } else {
            entries
                .chunks(MAX_BATCH_OBJECTS)
                .map(<[Entry]>::to_vec)
                .collect()
        };
        let mut cursors = Vec::with_capacity(pages.len().saturating_sub(1));
        for _ in 1..pages.len() {
            let mut cursor = [0; 32];
            entropy
                .fill_exact(&mut cursor)
                .map_err(|_| CompanionFault::Storage)?;
            cursors.push(cursor);
        }
        let cut = Cut {
            token,
            state_generation,
            delivery_generation,
            digest,
            entry_count: u32::try_from(entries.len()).map_err(|_| CompanionFault::Ceiling)?,
        };
        let expires_at_millis = now_millis.saturating_add(SNAPSHOT_TOKEN_MILLIS);
        let snapshot = Snapshot {
            cut,
            pages,
            cursors,
            pages_sent: 0,
            expires_at_millis,
        };
        let page = render_page(&self.server_name, peer, &snapshot, 0)?;
        self.state.streams.insert(
            peer,
            DeliveryStream {
                generation: delivery_generation,
                ..DeliveryStream::default()
            },
        );
        let sync = self.peers.entry(peer).or_default();
        sync.incarnation = Some(incarnation);
        sync.transfer_incomplete = true;
        sync.ready_cut = None;
        let mut snapshot = snapshot;
        snapshot.pages_sent = 1;
        sync.snapshot = Some(snapshot);
        Ok(vec![
            Action::ScheduleExpiry {
                at_millis: expires_at_millis,
            },
            Action::Send(page),
        ])
    }

    /// The entitled route states of `peer` in canonical conversation order.
    /// Brings the standing of `peer` in line with the base facts before a
    /// cut: channel routes follow the channel-detail entitlement, and a
    /// direct route is held by every edge with an attached device of one
    /// of its accounts. A reloaded coordinator has no standing until here.
    fn refresh_entitlements(&mut self, peer: ServerId, host: &dyn CompanionHost) {
        use agenc_ircd_domain::e2ee::RouteTarget;
        use agenc_ircd_domain::e2ee::projection::EntitlementReason;
        let routes: Vec<([u8; 32], RouteTarget)> = self
            .state
            .routes
            .routes()
            .filter(|route| self.state.routes.is_current(&route.conversation_id))
            .map(|route| (route.conversation_id.0, route.target))
            .collect();
        for (conversation, target) in routes {
            let entitled = match target {
                RouteTarget::Channel(instance) => {
                    let holds = host.holds_channel(*instance.as_bytes());
                    self.state
                        .entitlements
                        .set_channel(peer, conversation, holds);
                    continue;
                }
                RouteTarget::Direct(_) => self.state.entitlements.entitled(peer, &conversation),
            };
            if entitled || !self.hosts_direct_account(peer, &conversation, host) {
                continue;
            }
            let _ = self.state.entitlements.require_direct(
                peer,
                conversation,
                EntitlementReason::Operation,
            );
        }
    }

    /// Whether `peer` hosts one account of the direct conversation: a live
    /// base origin of the account, or an attached device declared to the
    /// companion profile.
    fn hosts_direct_account(
        &self,
        peer: ServerId,
        conversation: &[u8; 32],
        host: &dyn CompanionHost,
    ) -> bool {
        let Some((first, second)) = self
            .state
            .conversations
            .get(conversation)
            .and_then(|state| state.direct_accounts)
        else {
            return false;
        };
        if host.hosts_account(&first) || host.hosts_account(&second) {
            return true;
        }
        let digests: Vec<[u8; 32]> = [first, second]
            .iter()
            .filter_map(|account| {
                agenc_ircd_e2ee::ids::account_id_digest(&self.network_id, account).ok()
            })
            .collect();
        self.state.origins.values().any(|origin| {
            origin.home_server_id == *peer.as_bytes()
                && origin.device.is_some()
                && origin
                    .account_digest
                    .is_some_and(|digest| digests.contains(&digest))
        })
    }

    fn entitled_entries(&self, peer: ServerId) -> Result<Vec<Entry>, CompanionFault> {
        let mut entries = Vec::new();
        let mut bytes_total: u64 = 0;
        for conversation in self.state.entitlements.snapshot(peer) {
            let state = self
                .state
                .conversations
                .get(&conversation)
                .ok_or(CompanionFault::Protocol)?;
            let bytes = self
                .state
                .objects
                .get(&state.route_object_id)
                .cloned()
                .ok_or(CompanionFault::Protocol)?;
            bytes_total =
                bytes_total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            entries.push((conversation, bytes));
        }
        let too_many = u64::try_from(entries.len()).unwrap_or(u64::MAX)
            > MAX_FEDERATION_STATE_ENTRIES_PER_EDGE;
        if too_many || bytes_total > MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE {
            return Err(CompanionFault::Ceiling);
        }
        Ok(entries)
    }

    /// ESTATE FETCH: the next page, or the byte-identical last page again.
    pub(super) fn state_fetch(
        &mut self,
        peer: ServerId,
        coordinator_server_id: [u8; 16],
        token: [u8; 32],
        next_page_sequence: u32,
        cursor: [u8; 32],
        now_millis: u64,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(coordinator_server_id)?;
        let sync = self.peers.get_mut(&peer).ok_or(CompanionFault::Protocol)?;
        let snapshot = sync.snapshot.as_mut().ok_or(CompanionFault::Protocol)?;
        if snapshot.cut.token != token || now_millis >= snapshot.expires_at_millis {
            return Err(CompanionFault::Protocol);
        }
        let requested =
            usize::try_from(next_page_sequence).map_err(|_| CompanionFault::Protocol)?;
        let retry = requested.checked_add(1) == Some(snapshot.pages_sent);
        let advance = requested == snapshot.pages_sent;
        let expected_cursor = requested
            .checked_sub(1)
            .and_then(|previous| snapshot.cursors.get(previous));
        if !(retry || advance) || expected_cursor != Some(&cursor) {
            return Err(CompanionFault::Protocol);
        }
        let page = render_page(&self.server_name, peer, snapshot, requested)?;
        if advance {
            snapshot.pages_sent = requested.saturating_add(1);
        }
        Ok(vec![Action::Send(page)])
    }

    /// ESTATE READY: the edge staged the exact cut; its READY is recorded
    /// durably before ACTIVE. A repeated READY after the record is answered
    /// by the identical ACTIVE without a new batch.
    pub(super) fn state_ready(
        &mut self,
        link: LinkId,
        peer: ServerId,
        coordinator_server_id: [u8; 16],
        cut: Cut,
        now_millis: u64,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(coordinator_server_id)?;
        let sync = self.peers.get_mut(&peer).ok_or(CompanionFault::Protocol)?;
        if sync.ready_cut == Some(cut) {
            let active = active_line(&self.server_name, peer, &cut)?;
            return Ok(vec![Action::Send(vec![active])]);
        }
        let snapshot = sync.snapshot.as_ref().ok_or(CompanionFault::Protocol)?;
        let complete = snapshot.pages_sent == snapshot.pages.len();
        if snapshot.cut != cut || !complete || now_millis >= snapshot.expires_at_millis {
            return Err(CompanionFault::Protocol);
        }
        let expires_at = snapshot.expires_at_millis / 1_000;
        let stream = self
            .state
            .streams
            .get(&peer)
            .ok_or(CompanionFault::Protocol)?;
        let writes = vec![
            snapshot_write(peer, &cut, expires_at)?,
            events::cursor_write(peer, stream).map_err(|_| CompanionFault::Storage)?,
        ];
        Ok(vec![Action::Stage {
            writes,
            work: PendingWork::Activate { peer, link },
        }])
    }

    /// Finishes a committed READY: ACTIVE goes out first, then every row
    /// queued in the new generation since the cut.
    pub(super) fn activate_committed(
        &mut self,
        peer: ServerId,
        host_epoch: Option<u64>,
    ) -> Result<Vec<(ServerId, FederationLineText)>, CompanionFault> {
        let sync = self.peers.get_mut(&peer).ok_or(CompanionFault::Protocol)?;
        let snapshot = sync.snapshot.take().ok_or(CompanionFault::Protocol)?;
        sync.ready_cut = Some(snapshot.cut);
        sync.active = true;
        sync.transfer_incomplete = false;
        if let Some(epoch) = host_epoch {
            sync.resync_epoch = epoch;
        }
        let mut lines = vec![(peer, active_line(&self.server_name, peer, &snapshot.cut)?)];
        if let Some(stream) = self.state.streams.get(&peer) {
            for line in retransmission(&self.server_name, peer, stream)? {
                lines.push((peer, line));
            }
        }
        Ok(lines)
    }

    /// Whether the snapshot of `peer` expired at `now_millis`; an expired
    /// transfer is fatal for the link.
    pub fn snapshot_expired(&mut self, peer: ServerId, now_millis: u64) -> bool {
        let Some(sync) = self.peers.get_mut(&peer) else {
            return false;
        };
        let expired = sync
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| now_millis >= snapshot.expires_at_millis);
        if expired {
            sync.snapshot = None;
        }
        expired
    }

    /// The highest companion sequence `peer` acknowledged.
    #[must_use]
    pub fn acked_through(&self, peer: ServerId) -> Option<u64> {
        self.state
            .streams
            .get(&peer)
            .and_then(|stream| stream.acked)
            .map(|(sequence, _)| sequence)
    }

    /// The unacknowledged rows of `peer` after `sequence`, rendered for a
    /// barrier release.
    pub fn retransmit_after(
        &self,
        peer: ServerId,
        sequence: u64,
    ) -> Result<Vec<FederationLineText>, CompanionFault> {
        let Some(stream) = self.state.streams.get(&peer) else {
            return Ok(Vec::new());
        };
        let mut lines = Vec::new();
        for row in stream.unacked_rows() {
            if row.sequence <= sequence {
                continue;
            }
            let copy = events::CopyToSend {
                target: peer,
                row: row.clone(),
                generation: stream.generation,
            };
            lines.extend(
                events::render_copy(&self.server_name, &copy)
                    .map_err(|_| CompanionFault::Protocol)?,
            );
        }
        Ok(lines)
    }

    /// Whether event copies flow to `peer` now.
    #[must_use]
    pub fn delivering(&self, peer: ServerId) -> bool {
        self.peers.get(&peer).is_some_and(|sync| sync.active)
    }

    /// Whether requests from `peer` execute: its delivery is active and its
    /// origin set is ready.
    #[must_use]
    pub fn accepting_requests(&self, peer: ServerId) -> bool {
        self.peers
            .get(&peer)
            .is_some_and(|sync| sync.active && sync.origins_ready)
    }

    /// The synchronization state of `peer`.
    #[must_use]
    pub fn peer_sync(&self, peer: ServerId) -> Option<&PeerSync> {
        self.peers.get(&peer)
    }

    /// Link loss: delivery pauses, the transfer in progress is dropped, and
    /// every origin of the peer waits for its re-declaration.
    pub(super) fn link_lost(&mut self, peer: ServerId) {
        if let Some(sync) = self.peers.get_mut(&peer) {
            sync.active = false;
            sync.snapshot = None;
            sync.origins_reset = false;
            sync.origins_ready = false;
        }
        let home = *peer.as_bytes();
        for (key, origin) in self.state.origins.iter_mut() {
            if key.home_server_id == home {
                origin.suspended = true;
            }
        }
    }
}

impl CompanionCoordinator {
    /// Routes one synchronization frame to its handler.
    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match hands every synchronization frame to its handler with the exact descriptor fields the line carried
    pub(super) fn on_sync_frame(
        &mut self,
        link: LinkId,
        peer: ServerId,
        frame: CompanionFrame,
        now_millis: u64,
        host: &dyn CompanionHost,
        entropy: &mut dyn EntropySource,
    ) -> Result<Vec<Action>, CompanionFault> {
        match frame {
            CompanionFrame::OriginReset {
                coordinator_server_id,
                server_incarnation,
            } => self.origin_reset(peer, coordinator_server_id, server_incarnation, host),
            CompanionFrame::OriginState {
                update,
                coordinator_server_id,
                server_incarnation,
                origin_id,
                origin_generation,
                object_id,
                fragment,
            } => self.origin_state(
                peer,
                update,
                OriginDescriptor {
                    coordinator_server_id,
                    server_incarnation,
                    origin_id,
                    origin_generation,
                    object_id,
                },
                fragment,
                now_millis,
                host,
            ),
            CompanionFrame::OriginDel {
                coordinator_server_id,
                server_incarnation,
                origin_id,
                origin_generation,
                next_operation_sequence,
            } => self.origin_del(
                peer,
                OriginDescriptor {
                    coordinator_server_id,
                    server_incarnation,
                    origin_id,
                    origin_generation,
                    object_id: [0; 32],
                },
                next_operation_sequence,
                host,
            ),
            CompanionFrame::Resume {
                coordinator_server_id,
                server_incarnation,
                delivery_generation,
                last,
            } => self.resume(
                peer,
                coordinator_server_id,
                server_incarnation,
                delivery_generation,
                last,
                now_millis,
                host,
                entropy,
            ),
            CompanionFrame::StateFetch {
                coordinator_server_id,
                snapshot_token,
                next_page_sequence,
                cursor,
            } => self.state_fetch(
                peer,
                coordinator_server_id,
                snapshot_token,
                next_page_sequence,
                cursor,
                now_millis,
            ),
            CompanionFrame::StateCut {
                active: false,
                server_id,
                snapshot_token,
                state_generation,
                delivery_generation,
                snapshot_digest,
            } => {
                let entry_count = self
                    .peers
                    .get(&peer)
                    .and_then(|sync| {
                        sync.snapshot
                            .as_ref()
                            .map(|snapshot| snapshot.cut.entry_count)
                    })
                    .or_else(|| {
                        self.peers
                            .get(&peer)
                            .and_then(|sync| sync.ready_cut.map(|cut| cut.entry_count))
                    })
                    .ok_or(CompanionFault::Protocol)?;
                self.state_ready(
                    link,
                    peer,
                    server_id,
                    Cut {
                        token: snapshot_token,
                        state_generation,
                        delivery_generation,
                        digest: snapshot_digest,
                        entry_count,
                    },
                    now_millis,
                )
            }
            _ => Err(CompanionFault::Protocol),
        }
    }
}

/// Accepts a declaration over an existing origin: the identical state
/// again, or the next generation naming this one as its predecessor.
fn accept_successor(
    existing: &mut CompanionOrigin,
    mirrored: CompanionOrigin,
    update: bool,
) -> Result<(), CompanionFault> {
    if existing.fenced {
        return Err(CompanionFault::Protocol);
    }
    if existing.generation == mirrored.generation && existing.state_id == mirrored.state_id {
        existing.suspended = false;
        return Ok(());
    }
    let successor = update
        && mirrored.generation != 0
        && Some(mirrored.generation) == existing.generation.checked_add(1)
        && mirrored.previous_state_id == existing.state_id;
    if !successor {
        return Err(CompanionFault::Protocol);
    }
    *existing = mirrored;
    Ok(())
}

/// The session and account of the object must equal the base principal:
/// both session fields empty or both present, and an account exactly when
/// the base is authenticated, with its nonzero session generation.
fn mirrored_principal(
    origin: &IrcFederationOrigin,
    base: &BaseOriginView,
) -> Result<Option<[u8; 24]>, CompanionFault> {
    let session_id = optional16(&origin.session_id)?;
    let user_id = optional16(&origin.user_id)?;
    if session_id.is_some() != user_id.is_some() || session_id.zip(user_id) != base.session {
        return Err(CompanionFault::Protocol);
    }
    let account: Option<[u8; 24]> = match origin.account_id.as_slice() {
        [] => None,
        bytes => Some(bytes.try_into().map_err(|_| CompanionFault::Protocol)?),
    };
    let matches = match (account, base.account) {
        (None, None) => origin.account_session_generation == 0,
        (Some(mine), Some((theirs, generation))) => {
            mine == theirs && generation != 0 && origin.account_session_generation == generation
        }
        _ => false,
    };
    if matches {
        Ok(account)
    } else {
        Err(CompanionFault::Protocol)
    }
}

/// The descriptor fields an EORIGIN line names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginDescriptor {
    /// The coordinator named.
    pub coordinator_server_id: [u8; 16],
    /// Server incarnation.
    pub server_incarnation: [u8; 16],
    /// Origin identity.
    pub origin_id: [u8; 16],
    /// Origin generation.
    pub origin_generation: u64,
    /// The object identifier named, all zero on DEL.
    pub object_id: [u8; 32],
}

fn optional16(
    field: &agenc_ircd_e2ee::objects::OptionalId16,
) -> Result<Option<[u8; 16]>, CompanionFault> {
    match field.as_slice() {
        [] => Ok(None),
        bytes => bytes
            .try_into()
            .map(Some)
            .map_err(|_| CompanionFault::Protocol),
    }
}

fn decode_origin(bytes: &[u8]) -> Result<IrcFederationOrigin, CompanionFault> {
    let limit = IrcWireObjectKind::FederationOrigin.maximum_object_bytes();
    let mut budget = DecodeBudget::new(limit, ORIGIN_DECODE_VALUES);
    let object = IrcWireObject::decode_kind(
        bytes,
        Some(IrcWireObjectKind::FederationOrigin),
        &mut budget,
    )
    .map_err(|_| CompanionFault::Protocol)?;
    IrcFederationOrigin::decode_exact(object.body(), &mut budget)
        .map_err(|_| CompanionFault::Protocol)
}

fn active_line(
    server_name: &str,
    peer: ServerId,
    cut: &Cut,
) -> Result<FederationLineText, CompanionFault> {
    line(
        server_name,
        &CompanionFrame::StateCut {
            active: true,
            server_id: *peer.as_bytes(),
            snapshot_token: cut.token,
            state_generation: cut.state_generation,
            delivery_generation: cut.delivery_generation,
            snapshot_digest: cut.digest,
        },
    )
}

/// Every unacknowledged row of `stream`, byte for byte.
fn retransmission(
    server_name: &str,
    peer: ServerId,
    stream: &DeliveryStream,
) -> Result<Vec<FederationLineText>, CompanionFault> {
    let mut lines = Vec::new();
    for row in stream.unacked_rows() {
        let copy = events::CopyToSend {
            target: peer,
            row: row.clone(),
            generation: stream.generation,
        };
        lines
            .extend(events::render_copy(server_name, &copy).map_err(|_| CompanionFault::Protocol)?);
    }
    Ok(lines)
}

/// Renders one page: BEGIN, every ENTRY fragment in order, END.
fn render_page(
    server_name: &str,
    peer: ServerId,
    snapshot: &Snapshot,
    page_index: usize,
) -> Result<Vec<FederationLineText>, CompanionFault> {
    let entries = snapshot
        .pages
        .get(page_index)
        .ok_or(CompanionFault::Protocol)?;
    let page_sequence = u32::try_from(page_index).map_err(|_| CompanionFault::Protocol)?;
    let target = *peer.as_bytes();
    let cut = &snapshot.cut;
    let decoded: usize = entries.iter().map(|(_, bytes)| bytes.len()).sum();
    if decoded > MAX_BATCH_DECODED_BYTES {
        return Err(CompanionFault::Ceiling);
    }
    let mut lines = vec![line(
        server_name,
        &CompanionFrame::StateBegin {
            target_server_id: target,
            snapshot_token: cut.token,
            state_generation: cut.state_generation,
            delivery_generation: cut.delivery_generation,
            page_sequence,
            total_entry_count: cut.entry_count,
            page_entry_count: u32::try_from(entries.len()).map_err(|_| CompanionFault::Protocol)?,
            snapshot_digest: cut.digest,
        },
    )?];
    for (conversation_id, bytes) in entries {
        let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
        for fragment in fragment_object(bytes).map_err(|_| CompanionFault::Protocol)? {
            lines.push(line(
                server_name,
                &CompanionFrame::StateEntry {
                    target_server_id: target,
                    snapshot_token: cut.token,
                    page_sequence,
                    conversation_id: *conversation_id,
                    object_id,
                    fragment,
                },
            )?);
        }
    }
    lines.push(line(
        server_name,
        &CompanionFrame::StateEnd {
            target_server_id: target,
            snapshot_token: cut.token,
            page_sequence,
            next_cursor: snapshot.cursors.get(page_index).copied(),
        },
    )?);
    Ok(lines)
}

fn snapshot_write(
    peer: ServerId,
    cut: &Cut,
    expires_at: u64,
) -> Result<AccountServiceDurableWrite, CompanionFault> {
    let body = DeliveryRow::Snapshot {
        generation: cut.delivery_generation,
        token: cut.token,
        entry_count: cut.entry_count,
        digest: cut.digest,
        ready: true,
        expires_at,
    }
    .encode()
    .map_err(|_| CompanionFault::Storage)?;
    let key = DeliveryRow::snapshot_key(peer.as_bytes()).map_err(|_| CompanionFault::Storage)?;
    state_row(TableId::E2eeState, DELIVERY_ROW_KIND, key, body).map_err(|_| CompanionFault::Storage)
}
