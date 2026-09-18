//! Companion peer synchronization on the coordinator: EORIGIN mirroring of
//! the ACKed base origins, ERESUME against the retained delivery cursor,
//! and the ESTATE route-state transfer that opens a new delivery generation
//! (companion 12.5).
//!
//! Immutable pages and their original cut owner survive coordinator restart.
//! FETCH advances only through a durable owner receipt. Link loss does not
//! authorize a replacement generation or refresh the token deadline.

use agenc_ircd_crypto::SemanticHashDomain;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::ids::{account_id_digest, semantic_id_of};
use agenc_ircd_e2ee::limits::MAX_BATCH_DECODED_BYTES;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::IrcFederationOrigin;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::assembly::{AssemblyKey, Direction, Sender};
use agenc_ircd_e2ee::wire::carrier::CarrierCommand;
use agenc_ircd_e2ee::wire::fragment::{FragmentTag, fragment_object};
use agenc_ircd_federation_wire::FederationLineText;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{DeliveryOwner, DeliveryScope};
use agenc_ircd_types::{EntropySource, ServerId};

use super::events::{self, DeliveryStream};
use super::{
    CompanionCoordinator, CompanionFault, CompanionOrigin, CompanionOriginKey, CompleteRequest,
    PendingCompanion,
};
use crate::federation::LinkId;
use crate::state_core::durable::AccountServiceDurableWrite;

pub use super::delivery_owner::clock::Sample as CutClockSample;
pub use super::delivery_owner::fetch::Prepared as FetchPublication;
pub(crate) use super::delivery_owner::fetch::{
    Output as SnapshotPageOutput, Request as SnapshotPageRequest,
};
pub use super::delivery_owner::publication::Publication as SnapshotPublication;
pub(crate) use super::delivery_owner::retirement::RestoredWrite;

/// Exact page identity supplied by one already decoded FETCH frame.
pub(super) struct FetchPage {
    token: [u8; 32],
    sequence: u32,
    cursor: [u8; 32],
}

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
    /// Current UTC accepted by the existing drift monitor; absence cannot expire replay.
    fn trusted_ack_unix_seconds(&self) -> Option<u64> {
        None
    }
    /// Samples the absolute clock used only by a pending snapshot token.
    fn cut_clock_sample(
        &self,
    ) -> Result<CutClockSample, agenc_ircd_storage::e2ee_records::delivery_recovery::RetirementReason>
    {
        super::delivery_owner::clock::sample()
    }

    /// Reserves backing against the existing process memory budget before allocation.
    fn reserve_cut_backing(
        &self,
        _capacity: usize,
    ) -> Result<crate::budget::MemoryPermit, CompanionFault> {
        Err(CompanionFault::Ceiling)
    }

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

pub(crate) mod witness;

/// What the owner does after one companion frame.
pub(crate) enum Action {
    /// Executes one complete request.
    Execute(CompleteRequest),
    /// Sends lines on the peer's link.
    Send(Vec<FederationLineText>),
    /// Retains output backing until transfer to the authenticated link queue.
    SendPage(SnapshotPageOutput),
    /// Reads one exact immutable page under a submitted-result lease.
    ReadSnapshotPage(SnapshotPageRequest),
    /// Reads a bounded retained prefix before proposing a journal ACK.
    ReadAcknowledgement(Box<super::AckReadRequest>),
    /// Reads all required response bodies before replaying a retained result.
    ReadResponses(super::response_read::Identity),
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
        /// The exact accepted cut and historical scope.
        owner: DeliveryOwner,
    },
    /// One immutable page or its final owner awaits the exact receipt.
    Snapshot(Box<SnapshotPublication>),
    /// An offered-page boundary and its unpublished output await receipt.
    Fetch(Box<FetchPublication>),
    /// A cursor change that only its storage receipt may apply.
    Acknowledgement(super::delivery_owner::acknowledgement::PreparedAck),
}

/// What went out of a committed companion batch.
pub enum Committed {
    /// A request completed.
    Request(Box<PendingCompanion>),
    /// Lines to send, each to its target's live link.
    Lines(Vec<(ServerId, FederationLineText)>),
    /// Continue a cut only after the preceding page or owner is durable.
    Snapshot(Box<SnapshotPublication>),
    /// An offered-page boundary and its unpublished output await receipt.
    Fetch(Box<FetchPublication>),
    /// An EACK was recorded durably for this target.
    Acknowledged(ServerId),
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

/// One ESTATE transfer in progress.
pub struct Snapshot {
    /// The cut.
    pub cut: Cut,
    pub(super) scope: DeliveryScope,
    pub(super) capture: super::delivery_owner::snapshot::Pages,
    pub(super) pages_sent: usize,
    pub(super) expires_at_millis: u64,
    pub(super) deadline: agenc_ircd_storage::e2ee_records::delivery_recovery::PendingDeadline,
    pub(super) observed: Option<CutClockSample>,
    pub(super) stored_version: Option<(u64, u64)>,
    pub(super) retirement:
        Option<agenc_ircd_storage::e2ee_records::delivery_recovery::RetirementReason>,
}

/// The synchronization state of one edge.
#[derive(Default)]
pub struct PeerSync {
    /// The authenticated connection allowed to publish this process's replies.
    pub link: Option<LinkId>,
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
    /// The witness resolutions this link publishes (companion 12.5.1).
    pub witness: witness::Publication,
}

pub(super) fn line(
    server_name: &str,
    frame: &CompanionFrame,
) -> Result<FederationLineText, CompanionFault> {
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
        self.state
            .mailbox_snapshots
            .fence_incarnations(home, incarnation);
        let sync = self.peers.entry(peer).or_default();
        sync.origins_reset = true;
        sync.origins_ready = false;
        // A blocked edge dropped every delivery it received; once its rows
        // settle it replays its origins, and the unacknowledged rows go out
        // again (companion 12.5.1).
        let mut lines = Vec::new();
        if sync.witness.take_served()
            && let Some(stream) = self.state.streams.get(&peer)
        {
            lines.extend(retransmission(&self.server_name, peer, stream)?);
        }
        if host.base_origins_ready(peer) {
            lines.extend(self.origins_ready(peer, incarnation)?);
        }
        Ok(if lines.is_empty() {
            Vec::new()
        } else {
            vec![Action::Send(lines)]
        })
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
        // An origin the edge did not declare again is gone with its link.
        self.state.entitlements.mark_departure(peer);
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
        // These base facts can change while a link resets. Check them before
        // assembly can cache completion, including on a cached re-declaration.
        if !self.peers.get(&peer).is_some_and(|sync| sync.origins_reset) {
            return Err(CompanionFault::Protocol);
        }
        let origin_key = CompanionOriginKey {
            home_server_id: *peer.as_bytes(),
            server_incarnation: descriptor.server_incarnation,
            origin_id: descriptor.origin_id,
        };
        let base = host
            .base_origin(&origin_key)
            .filter(|base| base.generation == descriptor.origin_generation)
            .ok_or(CompanionFault::Protocol)?;
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
        let mirrored = self.mirror_origin(&origin, &bytes, &base)?;
        self.accept_origin(origin_key, mirrored, update)?;
        self.note_redeclared(peer, update);
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
            // The connection ended: the edge's direct standings await a
            // hosting check by the next mutation plan (12.5).
            self.state.entitlements.mark_departure(peer);
        }
        self.state
            .mailbox_snapshots
            .close_origin(key, descriptor.origin_generation);
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
        // A staged batch owns the peer table until it commits.
        self.pending
            .as_ref()
            .map_or(Ok(()), |_| Err(CompanionFault::Protocol))?;
        let sync = self.peers.entry(peer).or_default();
        if sync.active {
            return Err(CompanionFault::Protocol);
        }
        let same_scope =
            sync.incarnation == Some(incarnation) && self.state.streams.contains_key(&peer);
        if same_scope && host.base_resync_epoch(peer) < sync.resync_epoch {
            return Err(CompanionFault::Protocol);
        }
        let reset = host.base_resync_epoch(peer) > sync.resync_epoch;
        if !same_scope || reset {
            let generation = if same_scope {
                self.state
                    .streams
                    .get(&peer)
                    .and_then(|stream| stream.generation.checked_add(1))
                    .ok_or(CompanionFault::Ceiling)?
            } else {
                0
            };
            return self.begin_snapshot(peer, incarnation, generation, now_millis, host, entropy);
        }
        if let Some(snapshot) = sync.snapshot.as_ref() {
            // A second ERESUME on the link carrying the transfer is a
            // violation. After link loss the edge discarded its staged pages
            // with the link, and the pending cut is published again from its
            // first page on the new link, unless the edge stopped hosting a
            // direct pair it names: that cut is retired here.
            if snapshot.pages_sent != 0 {
                return Err(CompanionFault::Protocol);
            }
            if self.pending_cut_current(peer, host) {
                return self.restart_transfer(peer, now_millis, host);
            }
            if let Some(sync) = self.peers.get_mut(&peer) {
                sync.snapshot = None;
            }
        }
        let sync = self.peers.entry(peer).or_default();
        if sync.transfer_incomplete {
            // The pending cut expired or was retired: the scope resets to a
            // fresh cut in its next delivery generation.
            let generation = self
                .state
                .streams
                .get(&peer)
                .and_then(|stream| stream.generation.checked_add(1))
                .ok_or(CompanionFault::Ceiling)?;
            return self.begin_snapshot(peer, incarnation, generation, now_millis, host, entropy);
        }
        let stream = self
            .state
            .streams
            .get(&peer)
            .ok_or(CompanionFault::Protocol)?;
        if stream.generation != delivery_generation {
            return Err(CompanionFault::Protocol);
        }
        if stream.acked != last {
            let (sequence, event_id) = last.ok_or(CompanionFault::Protocol)?;
            return super::delivery_owner::acknowledgement::prepare_resume(
                self,
                peer,
                agenc_ircd_e2ee::federation::frames::DeliveryPosition {
                    server_id: coordinator_server_id,
                    delivery_generation,
                    delivery_sequence: sequence,
                    event_id,
                },
                host.trusted_ack_unix_seconds(),
            );
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
        if self
            .state
            .streams
            .get(&peer)
            .is_some_and(|stream| stream.hold_after.is_some())
        {
            return Err(CompanionFault::Protocol);
        }
        let scope = self.delivery_scope(peer, incarnation, host.base_resync_epoch(peer))?;
        self.refresh_entitlements(peer, host);
        let capture =
            super::delivery_owner::capture::Capture::new(&self.state, peer, host, entropy)?;
        let state_generation = host.state_generation();
        let digest = capture.digest(state_generation, delivery_generation, host)?;
        let mut token = [0; 32];
        entropy
            .fill_exact(&mut token)
            .map_err(|_| CompanionFault::Storage)?;
        let cut = Cut {
            token,
            state_generation,
            delivery_generation,
            digest,
            entry_count: capture.entry_count()?,
        };
        let observed = host
            .cut_clock_sample()
            .map_err(|_| CompanionFault::Protocol)?;
        let deadline = observed.deadline().map_err(|_| CompanionFault::Protocol)?;
        let snapshot = Snapshot {
            cut,
            scope,
            capture: super::delivery_owner::snapshot::Pages::Captured(capture),
            pages_sent: 0,
            expires_at_millis: now_millis
                .checked_add(SNAPSHOT_TOKEN_MILLIS)
                .ok_or(CompanionFault::Ceiling)?,
            deadline,
            observed: Some(observed),
            retirement: None,
            stored_version: None,
        };
        let link = self
            .peers
            .get(&peer)
            .and_then(|sync| sync.link)
            .ok_or(CompanionFault::Protocol)?;
        let publication =
            super::delivery_owner::publication::Publication::new(peer, link, snapshot)?;
        self.continue_snapshot_publication(publication, now_millis, host)
    }

    /// The entitled route states of `peer` in canonical conversation order.
    /// Brings the standing of `peer` in line with the base facts before a
    /// cut: channel routes follow the channel-detail entitlement, and a
    /// direct route is held by every edge with an attached device of one
    /// of its accounts. A reloaded coordinator has no standing until here.
    /// Every full cut follows a reset that fenced the origins and events an
    /// earlier direct reference stood for, so those references are dropped
    /// first: the cut names a direct route only for an account the edge
    /// hosts now, which is exactly what the edge verifies (ENC-15).
    fn refresh_entitlements(&mut self, peer: ServerId, host: &dyn CompanionHost) {
        use agenc_ircd_domain::e2ee::RouteTarget;
        use agenc_ircd_domain::e2ee::projection::EntitlementReason;
        self.state.entitlements.fence_direct(peer);
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
        super::direct_release::attached_at(
            &self.state,
            &self.network_id,
            (peer, self.origins_replayed(peer)),
            &[first, second],
        )
    }

    /// An `EORIGIN UPDATE` may be a logout, an account switch or a detach
    /// that ended hosting: the edge's direct standings await a hosting
    /// check. A first declaration ends nothing.
    fn note_redeclared(&mut self, peer: ServerId, update: bool) {
        if update {
            self.state.entitlements.mark_departure(peer);
        }
    }

    /// Whether `peer` replayed its origin set on the current link, so an
    /// origin still suspended was not declared again.
    pub(super) fn origins_replayed(&self, peer: ServerId) -> bool {
        self.peers.get(&peer).is_some_and(|sync| sync.origins_ready)
    }

    /// Whether the pending cut of `peer` still names only direct routes the
    /// edge hosts. A cut republished unchanged after its edge stopped
    /// hosting a named pair would be refused by that edge until the token
    /// expired (ENC-15), so such a cut is retired like an expired one and
    /// the scope takes a fresh cut in its next delivery generation.
    fn pending_cut_current(&self, peer: ServerId, host: &dyn CompanionHost) -> bool {
        use agenc_ircd_domain::e2ee::RouteTarget;
        self.state
            .entitlements
            .snapshot_iter(peer)
            .filter(|conversation| {
                self.state
                    .routes
                    .route(&agenc_ircd_domain::e2ee::ConversationId(*conversation))
                    .is_some_and(|route| matches!(route.target, RouteTarget::Direct(_)))
            })
            .all(|conversation| self.hosts_direct_account(peer, &conversation, host))
    }

    /// ESTATE FETCH: the next page, or the byte-identical last page again.
    pub(super) fn state_fetch(
        &mut self,
        peer: ServerId,
        coordinator_server_id: [u8; 16],
        page: FetchPage,
        now_millis: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(coordinator_server_id)?;
        self.prepare_snapshot_fetch(
            peer,
            page.token,
            page.sequence,
            page.cursor,
            now_millis,
            host,
        )
    }

    /// ESTATE READY: the edge staged the exact cut; its READY is recorded
    /// durably before ACTIVE. A repeated READY after the record is answered
    /// by the identical ACTIVE without a new batch.
    pub(super) fn state_ready(
        &mut self,
        peer: ServerId,
        coordinator_server_id: [u8; 16],
        cut: Cut,
        now_millis: u64,
        host: &dyn CompanionHost,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(coordinator_server_id)?;
        if self.pending.is_some() {
            return Err(CompanionFault::Ceiling);
        }
        if let Some(actions) = self.repeat_ready(peer, cut, host)? {
            return Ok(actions);
        }
        let sync = self.peers.get_mut(&peer).ok_or(CompanionFault::Protocol)?;
        let link = sync.link.ok_or(CompanionFault::Protocol)?;
        let snapshot = sync.snapshot.as_mut().ok_or(CompanionFault::Protocol)?;
        require_cut_scope(snapshot.scope, peer, host)?;
        if snapshot.expires_at_millis != 0 && now_millis >= snapshot.expires_at_millis {
            return Err(CompanionFault::Protocol);
        }
        snapshot
            .observe_at(now_millis, host)
            .map_err(|_| CompanionFault::Protocol)?;
        let complete = snapshot.pages_sent == snapshot.capture.page_count();
        if snapshot.cut != cut || !complete || now_millis >= snapshot.expires_at_millis {
            return Err(CompanionFault::Protocol);
        }
        let stream = self
            .state
            .streams
            .get(&peer)
            .ok_or(CompanionFault::Protocol)?;
        let owner = super::delivery_owner::ready(
            snapshot.scope,
            cut,
            snapshot.capture.total_object_bytes(),
            stream,
        )?;
        let writes = vec![super::delivery_owner::write(&owner)?];
        Ok(vec![Action::Stage {
            writes,
            work: PendingWork::Activate { peer, link, owner },
        }])
    }

    /// Finishes a committed READY: ACTIVE goes out first, then every row
    /// queued in the new generation since the cut.
    pub(super) fn activate_committed(
        &mut self,
        peer: ServerId,
        link: LinkId,
        owner: DeliveryOwner,
        host_epoch: Option<u64>,
    ) -> Result<Vec<(ServerId, FederationLineText)>, CompanionFault> {
        self.validate_delivery_scope(owner.scope())?;
        let stream = self
            .state
            .streams
            .get_mut(&peer)
            .ok_or(CompanionFault::Storage)?;
        if super::delivery_owner::cursor(stream)? != *owner.cursor() {
            return Err(CompanionFault::Storage);
        }
        let cut = super::delivery_owner::cut(&owner);
        stream.owner = Some(owner.clone());
        let sync = self.peers.get_mut(&peer).ok_or(CompanionFault::Protocol)?;
        sync.snapshot = None;
        sync.ready_cut = Some(cut);
        sync.active = sync.link == Some(link)
            && host_epoch == Some(owner.scope().covered_base_client_resync_epoch());
        sync.transfer_incomplete = false;
        sync.incarnation = Some(owner.scope().target_incarnation());
        sync.resync_epoch = owner.scope().covered_base_client_resync_epoch();
        if !sync.active {
            return Ok(Vec::new());
        }
        let mut lines = vec![(peer, active_line(&self.server_name, peer, &cut)?)];
        if let Some(stream) = self.state.streams.get(&peer) {
            for line in retransmission(&self.server_name, peer, stream)? {
                lines.push((peer, line));
            }
        }
        Ok(lines)
    }

    fn repeat_ready(
        &mut self,
        peer: ServerId,
        cut: Cut,
        host: &dyn CompanionHost,
    ) -> Result<Option<Vec<Action>>, CompanionFault> {
        let sync = self.peers.get_mut(&peer).ok_or(CompanionFault::Protocol)?;
        if sync.ready_cut != Some(cut) {
            return Ok(None);
        }
        let stream = self
            .state
            .streams
            .get(&peer)
            .ok_or(CompanionFault::Storage)?;
        let owner = stream.owner.as_ref().ok_or(CompanionFault::Storage)?;
        require_cut_scope(*owner.scope(), peer, host)?;
        let mut lines = vec![active_line(&self.server_name, peer, &cut)?];
        if !sync.active {
            lines.extend(retransmission(&self.server_name, peer, stream)?);
        }
        sync.active = true;
        Ok(Some(vec![Action::Send(lines)]))
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

    /// Link loss pauses delivery and preserves the durable cut and page index.
    /// Every origin waits for its re-declaration.
    pub(super) fn link_lost(&mut self, peer: ServerId) {
        if let Some(sync) = self.peers.get_mut(&peer) {
            sync.active = false;
            sync.link = None;
            if let Some(snapshot) = sync.snapshot.as_mut() {
                snapshot.pages_sent = 0;
            }
            sync.origins_reset = false;
            sync.origins_ready = false;
            sync.witness = witness::Publication::default();
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
                FetchPage {
                    token: snapshot_token,
                    sequence: next_page_sequence,
                    cursor,
                },
                now_millis,
                host,
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
                    host,
                )
            }
            CompanionFrame::WitnessRequest {
                coordinator_server_id,
                conversation_id,
                expected_sequence,
                expected_head_id,
            } => self.witness_request(
                peer,
                coordinator_server_id,
                witness::Request {
                    conversation: conversation_id,
                    expected_sequence,
                    expected_head_id,
                },
                entropy,
            ),
            CompanionFrame::WitnessResolved {
                coordinator_server_id,
                conversation_id,
                resolution_token,
                new_head_sequence,
                new_head_id,
            } => self.witness_resolved(
                peer,
                coordinator_server_id,
                (
                    conversation_id,
                    resolution_token,
                    (new_head_sequence, new_head_id),
                ),
                entropy,
            ),
            _ => Err(CompanionFault::Protocol),
        }
    }
}

pub(super) fn require_cut_scope(
    scope: DeliveryScope,
    peer: ServerId,
    host: &dyn CompanionHost,
) -> Result<(), CompanionFault> {
    if scope.target_server_id() != *peer.as_bytes()
        || host.live_incarnation(peer) != Some(scope.target_incarnation())
        || host.base_resync_epoch(peer) != scope.covered_base_client_resync_epoch()
    {
        return Err(CompanionFault::Protocol);
    }
    Ok(())
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
    for row in stream
        .rows
        .iter()
        .filter(|row| !row.acked())
        .take_while(|row| stream.hold_after.is_none_or(|last| row.sequence <= last))
    {
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
pub(super) fn render_page(
    server_name: &str,
    peer: ServerId,
    snapshot: &Snapshot,
    page_index: usize,
    state: &super::CompanionState,
) -> Result<Vec<FederationLineText>, CompanionFault> {
    let entries = snapshot.capture.page(page_index)?;
    let page_sequence = u32::try_from(page_index).map_err(|_| CompanionFault::Protocol)?;
    let target = *peer.as_bytes();
    let cut = &snapshot.cut;
    let decoded = entries
        .iter()
        .try_fold(0_usize, |total, entry| {
            total.checked_add(state.objects.get(&entry.object)?.len())
        })
        .ok_or(CompanionFault::Protocol)?;
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
    for entry in entries {
        let bytes = state
            .objects
            .get(&entry.object)
            .ok_or(CompanionFault::Protocol)?;
        let object_id = entry.object;
        for fragment in fragment_object(bytes).map_err(|_| CompanionFault::Protocol)? {
            lines.push(line(
                server_name,
                &CompanionFrame::StateEntry {
                    target_server_id: target,
                    snapshot_token: cut.token,
                    page_sequence,
                    conversation_id: entry.conversation,
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
            next_cursor: snapshot.capture.cursor(page_index),
        },
    )?);
    Ok(lines)
}

impl CompanionCoordinator {
    /// A resumed final ACK may activate only its still-current link after commit.
    pub(crate) fn resume_ack_committed(
        &mut self,
        peer: ServerId,
        link: crate::federation::LinkId,
    ) -> Result<Vec<FederationLineText>, CompanionFault> {
        let sync = self.peers.get(&peer).ok_or(CompanionFault::Protocol)?;
        if sync.link != Some(link) {
            return Ok(Vec::new());
        }
        if sync.active {
            return Err(CompanionFault::Protocol);
        }
        let stream = self
            .state
            .streams
            .get(&peer)
            .ok_or(CompanionFault::Storage)?;
        let owner = stream.owner.as_ref().ok_or(CompanionFault::Storage)?;
        let next = stream
            .acked
            .and_then(|(last, _)| last.checked_add(1))
            .ok_or(CompanionFault::Storage)?;
        let mut lines = vec![line(
            &self.server_name,
            &CompanionFrame::ResumeOk {
                target_server_id: *peer.as_bytes(),
                server_incarnation: owner.scope().target_incarnation(),
                delivery_generation: stream.generation,
                next_delivery_sequence: next,
            },
        )?];
        lines.extend(retransmission(&self.server_name, peer, stream)?);
        self.peers
            .get_mut(&peer)
            .ok_or(CompanionFault::Protocol)?
            .active = true;
        Ok(lines)
    }
}
