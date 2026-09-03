//! The coordinator side of the companion profile (companion Sections 11.5,
//! 11.6, 12, 13): every federation opcode executes here against the pure
//! domain models, produces one exact result with its response objects and
//! event copies, and commits as one durable batch beside the base state.
//!
//! The coordinator never decrypts. It sequences Commits by signing receipts
//! with the sequencer key, stores opaque objects under their IDs, dispenses
//! one-use KeyPackages, runs device mailboxes, and projects route state.

use std::collections::{BTreeMap, VecDeque};

use agenc_ircd_crypto::{Ed25519SecretKey, SemanticHashDomain, SignatureDomain, sign_canonical};
use agenc_ircd_domain::e2ee::RouteTable;
use agenc_ircd_domain::e2ee::directory::Directory;
use agenc_ircd_domain::e2ee::lifecycle::Lifecycle;
use agenc_ircd_domain::e2ee::mailbox::Mailboxes;
use agenc_ircd_domain::e2ee::projection::RouteEntitlements;
use agenc_ircd_domain::e2ee::sequencer_log::SequencerLog;
use agenc_ircd_e2ee::error::E2eeError;
use agenc_ircd_e2ee::federation::frames::{CompanionFrame, Correlation};
use agenc_ircd_e2ee::identity::{VerifiedCapabilities, VerifiedRoot, VerifiedRoster};
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::sequencer::SequencerKeySet;
use agenc_ircd_e2ee::tls::TlsEncode;
use agenc_ircd_e2ee::wire::assembly::{
    AssemblyKey, Direction, E2eeAssembler, Ingest, QuotaScopes, Sender,
};
use agenc_ircd_e2ee::wire::carrier::CarrierCommand;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_federation_wire::FederationLineText;
use agenc_ircd_storage::e2ee_records::ReplayRow;
use agenc_ircd_types::ServerId;

use crate::federation::LinkId;
use crate::state_core::durable::AccountServiceDurableWrite;

pub mod events;
pub mod execute;
pub mod ops;
pub mod request;
#[cfg(test)]
mod tests;

/// The largest retained in-memory object set, in bytes, before new objects
/// are refused with `E2EE_RATE_LIMITED`.
pub const MAX_RETAINED_OBJECT_BYTES: usize = 256 * 1024 * 1024;
/// Requests one peer may queue behind an in-flight batch.
pub const MAX_QUEUED_COMPANION_REQUESTS: usize = 64;

/// The signing material and identity of the logical sequencer.
pub struct SequencerSigner {
    /// The private key.
    pub key: Ed25519SecretKey,
    /// The credential identifier of the key.
    pub credential_id: [u8; 32],
}

impl SequencerSigner {
    /// Signs a TBS under `domain`.
    pub fn sign(
        &self,
        domain: SignatureDomain,
        tbs: &impl TlsEncode,
    ) -> Result<[u8; 64], E2eeError> {
        let encoded = tbs.encode()?;
        sign_canonical(&self.key, domain, &encoded)
            .map(|signature| *signature.as_bytes())
            .map_err(|_| E2eeError::SignatureInvalid)
    }
}

/// One attached companion origin mirrored from the base origin table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompanionOrigin {
    /// The home edge.
    pub home_server_id: [u8; 16],
    /// Server incarnation.
    pub server_incarnation: [u8; 16],
    /// Origin identity.
    pub origin_id: [u8; 16],
    /// Origin generation.
    pub generation: u64,
    /// The next expected operation sequence.
    pub next_sequence: u64,
    /// The authenticated Account ID, absent for a guest.
    pub account_id: Option<[u8; 24]>,
    /// The account digest.
    pub account_digest: Option<[u8; 32]>,
    /// The attached device and its session generation.
    pub device: Option<([u8; 16], u64)>,
    /// The connection nonce registered by the edge.
    pub connection_nonce: [u8; 32],
    /// The base connection identity, for attach challenges.
    pub connection_id: u64,
}

/// The origin key of one companion origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CompanionOriginKey {
    /// Home edge.
    pub home_server_id: [u8; 16],
    /// Server incarnation.
    pub server_incarnation: [u8; 16],
    /// Origin identity.
    pub origin_id: [u8; 16],
}

impl From<&Correlation> for CompanionOriginKey {
    fn from(correlation: &Correlation) -> Self {
        Self {
            home_server_id: correlation.peer_server_id,
            server_incarnation: correlation.server_incarnation,
            origin_id: correlation.origin_id,
        }
    }
}

/// The in-memory companion state the coordinator executes against.
#[derive(Default)]
pub struct CompanionState {
    /// Routes.
    pub routes: RouteTable,
    /// Sequencer logs by conversation.
    pub logs: BTreeMap<[u8; 32], SequencerLog>,
    /// Lifecycles by conversation.
    pub lifecycles: BTreeMap<[u8; 32], Lifecycle>,
    /// The directory.
    pub directory: Directory,
    /// Mailboxes.
    pub mailboxes: Mailboxes,
    /// Route entitlements per edge.
    pub entitlements: RouteEntitlements,
    /// Companion origins.
    pub origins: BTreeMap<CompanionOriginKey, CompanionOrigin>,
    /// Retained objects by identifier.
    pub objects: BTreeMap<[u8; 32], Vec<u8>>,
    /// Retained object bytes.
    pub object_bytes: usize,
    /// Replay rows by key.
    pub replays: BTreeMap<agenc_ircd_storage::e2ee_records::ReplayKey, ReplayRow>,
    /// Retained results and responses by request object identifier.
    pub results: BTreeMap<[u8; 32], StoredResult>,
    /// Per-conversation retained state the sequencer needs between records.
    pub conversations: BTreeMap<[u8; 32], ConversationState>,
    /// Delivery streams per target edge.
    pub streams: BTreeMap<ServerId, events::DeliveryStream>,
    /// Verified root and roster heads by account digest.
    pub principals: BTreeMap<[u8; 32], (VerifiedRoot, VerifiedRoster)>,
    /// Verified capability heads by account digest and device.
    pub capabilities: BTreeMap<([u8; 32], [u8; 16]), VerifiedCapabilities>,
    /// Roots published before their first roster.
    pub pending_roots: BTreeMap<[u8; 32], VerifiedRoot>,
    /// Outstanding attach challenges by account digest and device.
    pub challenges: BTreeMap<([u8; 32], [u8; 16]), [u8; 32]>,
    /// Binding lock object identifiers by account digest, root, and sequence.
    pub binding_locks: BTreeMap<([u8; 32], [u8; 32]), LockChain>,
}

/// Lock object IDs by sequence for one (account, root fingerprint).
pub type LockChain = BTreeMap<u64, [u8; 32]>;
/// Approval object IDs by (root fingerprint, device) for one candidate.
pub type ApprovalSlots = BTreeMap<([u8; 32], [u8; 16]), [u8; 32]>;

/// A committed result and its response objects, for exact replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredResult {
    /// The encoded `IrcFederationResult` wire object.
    pub result: Vec<u8>,
    /// Response object identifiers in descriptor order.
    pub responses: Vec<[u8; 32]>,
}

/// Retained per-conversation facts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConversationState {
    /// The current binding package object identifier.
    pub binding_object_id: [u8; 32],
    /// The current binding identifier.
    pub binding: [u8; 32],
    /// The current context core identifier.
    pub context_core_id: [u8; 32],
    /// The context digest carried on BIND.
    pub context_digest: [u8; 32],
    /// The binding's cipher suite.
    pub cipher_suite: u16,
    /// The MLS group identifier.
    pub group_id: Vec<u8>,
    /// The concrete route binding.
    pub route_binding: [u8; 32],
    /// The semantic route lock identifier.
    pub lock_id: [u8; 32],
    /// The channel name hash for a channel route.
    pub channel_name_hash: [u8; 32],
    /// The direct accounts for a direct route.
    pub direct_accounts: Option<([u8; 24], [u8; 24])>,
    /// Object identifiers of retained proofs per subject, canonical.
    pub approvals: BTreeMap<[u8; 32], ApprovalSlots>,
    /// ACK object identifiers per candidate or attempt.
    pub acks: BTreeMap<[u8; 32], BTreeMap<u32, [u8; 32]>>,
    /// Sequencer record object identifiers by route sequence.
    pub records: BTreeMap<u64, [u8; 32]>,
    /// The retained finality request object per terminal identifier.
    pub proofs: BTreeMap<[u8; 32], [u8; 32]>,
    /// Bytes stored for this conversation.
    pub stored_bytes: u64,
    /// The last validation time accepted on a Commit AAD.
    pub last_validation_time: u64,
}

/// An in-memory change applied when the batch commits.
pub type Effect = Box<dyn FnOnce(&mut CompanionState) + Send>;

/// The batch one companion request staged.
pub struct PendingCompanion {
    /// The link the result goes back on.
    pub link: LinkId,
    /// The home edge.
    pub peer: ServerId,
    /// The request correlation.
    pub correlation: Correlation,
    /// The request object identifier.
    pub request_object_id: [u8; 32],
    /// The encoded result object.
    pub result: Vec<u8>,
    /// Response objects in descriptor order.
    pub responses: Vec<Vec<u8>>,
    /// Event copies to deliver after commit.
    pub events: Vec<events::CopyToSend>,
    /// The in-memory effects to apply on commit.
    pub effects: Vec<Effect>,
}

/// A request waiting behind an in-flight batch.
pub struct QueuedCompanion {
    /// Link.
    pub link: LinkId,
    /// Home edge.
    pub peer: ServerId,
    /// Correlation.
    pub correlation: Correlation,
    /// The request object.
    pub request: Vec<u8>,
    /// The payload object, if any.
    pub payload: Option<Vec<u8>>,
}

/// One companion request with its optional payload, complete.
pub struct CompleteRequest {
    /// Correlation.
    pub correlation: Correlation,
    /// Request bytes.
    pub request: Vec<u8>,
    /// Payload bytes.
    pub payload: Option<Vec<u8>>,
}

/// An EREQUEST whose EPAYLOAD has not arrived.
struct OpenRequest {
    correlation: Correlation,
    request: Vec<u8>,
    payload_object_id: Option<[u8; 32]>,
}

/// The coordinator.
pub struct CompanionCoordinator {
    /// Network identity.
    pub network_id: [u8; 32],
    /// This server.
    pub server_id: ServerId,
    /// The local server name for rendered lines.
    pub server_name: String,
    signer: Option<SequencerSigner>,
    key_set: Option<SequencerKeySet>,
    current_credential: Option<agenc_ircd_e2ee::objects::conversation::IrcSequencerCredential>,
    assembler: E2eeAssembler,
    open: BTreeMap<(ServerId, [u8; 16]), OpenRequest>,
    queued: BTreeMap<ServerId, VecDeque<QueuedCompanion>>,
    /// The state.
    pub state: CompanionState,
    /// The batch in flight.
    pub pending: Option<PendingCompanion>,
    /// Lines to send, drained by the owner.
    pub outbound: VecDeque<(ServerId, FederationLineText)>,
}

/// Why a companion frame failed the link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompanionFault {
    /// The frame violated the companion federation grammar or order.
    Protocol,
    /// Reassembly refused the fragment.
    Assembly(E2eeReplyCode),
    /// A per-peer ceiling was crossed.
    Ceiling,
    /// The batch could not be staged.
    Storage,
}

impl CompanionCoordinator {
    /// A coordinator for `network_id` at `server_id`.
    #[must_use]
    pub fn new(network_id: [u8; 32], server_id: ServerId, server_name: String) -> Self {
        Self {
            network_id,
            server_id,
            server_name,
            signer: None,
            key_set: None,
            current_credential: None,
            assembler: E2eeAssembler::default(),
            open: BTreeMap::new(),
            queued: BTreeMap::new(),
            state: CompanionState::default(),
            pending: None,
            outbound: VecDeque::new(),
        }
    }

    /// Installs the sequencer key, the verified key set, and the raw current
    /// credential that reservations embed.
    pub fn install_sequencer(
        &mut self,
        key: Ed25519SecretKey,
        key_set: SequencerKeySet,
        current: agenc_ircd_e2ee::objects::conversation::IrcSequencerCredential,
    ) {
        let credential_id = key_set
            .current()
            .map_or([0; 32], |credential| credential.credential_id);
        self.signer = Some(SequencerSigner { key, credential_id });
        self.key_set = Some(key_set);
        self.current_credential = Some(current);
    }

    /// The raw current sequencer credential.
    #[must_use]
    pub const fn current_credential(
        &self,
    ) -> Option<&agenc_ircd_e2ee::objects::conversation::IrcSequencerCredential> {
        self.current_credential.as_ref()
    }

    /// The sequencer signer, if this node is the coordinator.
    #[must_use]
    pub const fn signer(&self) -> Option<&SequencerSigner> {
        self.signer.as_ref()
    }

    /// The key set.
    #[must_use]
    pub const fn key_set(&self) -> Option<&SequencerKeySet> {
        self.key_set.as_ref()
    }

    /// Restores one companion origin (startup reload or EORIGIN).
    pub fn restore_origin(&mut self, origin: CompanionOrigin) {
        let key = CompanionOriginKey {
            home_server_id: origin.home_server_id,
            server_incarnation: origin.server_incarnation,
            origin_id: origin.origin_id,
        };
        self.state.origins.insert(key, origin);
    }

    /// Handles one admitted companion frame from `peer` on `link`.
    pub fn on_frame(
        &mut self,
        link: LinkId,
        peer: ServerId,
        frame: CompanionFrame,
        now_millis: u64,
    ) -> Result<Option<CompleteRequest>, CompanionFault> {
        match frame {
            CompanionFrame::Request {
                correlation,
                object_id,
                fragment,
            } => self.on_request_fragment(link, peer, correlation, object_id, fragment, now_millis),
            CompanionFrame::Payload {
                correlation,
                object_id,
                fragment,
            } => self.on_payload_fragment(link, peer, correlation, object_id, fragment, now_millis),
            CompanionFrame::Ack(position) => {
                events::on_ack(self, peer, position)?;
                Ok(None)
            }
            _ => Err(CompanionFault::Protocol),
        }
    }

    fn assembly_key(
        peer: ServerId,
        correlation: &Correlation,
        command: CarrierCommand,
        object_id: [u8; 32],
    ) -> AssemblyKey {
        AssemblyKey {
            direction: Direction::Remote,
            sender: Sender::Origin(correlation.origin_id),
            command,
            route: correlation.request_id_route(),
            scope: None,
            object_id: agenc_ircd_e2ee::ObjectId::from_bytes(object_id),
        }
        .with_peer(peer)
    }

    fn ingest(
        &mut self,
        key: AssemblyKey,
        peer: ServerId,
        command: CarrierCommand,
        fragment: &agenc_ircd_e2ee::wire::fragment::FragmentTag,
        now_millis: u64,
    ) -> Result<Option<Vec<u8>>, CompanionFault> {
        let scopes = QuotaScopes {
            peer: Some(*peer.as_bytes()),
            ..QuotaScopes::default()
        };
        match self
            .assembler
            .ingest(key, scopes, command.limit(), fragment, now_millis / 1_000)
        {
            Ok(Ingest::Complete(bytes)) => Ok(Some(bytes)),
            Ok(Ingest::Incomplete | Ingest::Duplicate | Ingest::Recent) => Ok(None),
            Err(error) => Err(CompanionFault::Assembly(error.reply_code())),
        }
    }

    fn on_request_fragment(
        &mut self,
        link: LinkId,
        peer: ServerId,
        correlation: Correlation,
        object_id: [u8; 32],
        fragment: agenc_ircd_e2ee::wire::fragment::FragmentTag,
        now_millis: u64,
    ) -> Result<Option<CompleteRequest>, CompanionFault> {
        if correlation.peer_server_id != *self.server_id.as_bytes() {
            return Err(CompanionFault::Protocol);
        }
        let command = CarrierCommand::Federation(IrcWireObjectKind::FederationRequest);
        let key = Self::assembly_key(peer, &correlation, command, object_id);
        let Some(bytes) = self.ingest(key, peer, command, &fragment, now_millis)? else {
            return Ok(None);
        };
        let payload_object_id =
            request::payload_object_id(&bytes).map_err(|_| CompanionFault::Protocol)?;
        let open = OpenRequest {
            correlation,
            request: bytes,
            payload_object_id,
        };
        if open.payload_object_id.is_some() {
            if self.open.len() >= MAX_QUEUED_COMPANION_REQUESTS {
                return Err(CompanionFault::Ceiling);
            }
            self.open.insert((peer, correlation.request_id), open);
            return Ok(None);
        }
        let _ = link;
        Ok(Some(CompleteRequest {
            correlation: open.correlation,
            request: open.request,
            payload: None,
        }))
    }

    fn on_payload_fragment(
        &mut self,
        _link: LinkId,
        peer: ServerId,
        correlation: Correlation,
        object_id: [u8; 32],
        fragment: agenc_ircd_e2ee::wire::fragment::FragmentTag,
        now_millis: u64,
    ) -> Result<Option<CompleteRequest>, CompanionFault> {
        let expected = self
            .open
            .get(&(peer, correlation.request_id))
            .filter(|open| open.correlation == correlation)
            .and_then(|open| open.payload_object_id)
            .ok_or(CompanionFault::Protocol)?;
        if expected != object_id {
            return Err(CompanionFault::Protocol);
        }
        let command = CarrierCommand::Federation(IrcWireObjectKind::FederationRequest);
        let key = Self::assembly_key(peer, &correlation, command, object_id);
        let limit_command = CarrierCommand::DeliverWelcome;
        let Some(bytes) = self.ingest(key, peer, limit_command, &fragment, now_millis)? else {
            return Ok(None);
        };
        let open = self
            .open
            .remove(&(peer, correlation.request_id))
            .ok_or(CompanionFault::Protocol)?;
        Ok(Some(CompleteRequest {
            correlation: open.correlation,
            request: open.request,
            payload: Some(bytes),
        }))
    }

    /// Queues a complete request behind an in-flight batch.
    pub fn enqueue(
        &mut self,
        link: LinkId,
        peer: ServerId,
        request: CompleteRequest,
    ) -> Result<(), CompanionFault> {
        let queue = self.queued.entry(peer).or_default();
        if queue.len() >= MAX_QUEUED_COMPANION_REQUESTS {
            return Err(CompanionFault::Ceiling);
        }
        queue.push_back(QueuedCompanion {
            link,
            peer,
            correlation: request.correlation,
            request: request.request,
            payload: request.payload,
        });
        Ok(())
    }

    /// The next queued request once the batch slot is free.
    pub fn dequeue(&mut self) -> Option<QueuedCompanion> {
        if self.pending.is_some() {
            return None;
        }
        self.queued.values_mut().find_map(VecDeque::pop_front)
    }

    /// Whether `peer` has a queued request.
    #[must_use]
    pub fn has_queued(&self, peer: ServerId) -> bool {
        self.queued
            .get(&peer)
            .is_some_and(|queue| !queue.is_empty())
    }

    /// Whether a staged batch awaits its commit.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Drops every open assembly and queued request of `peer`.
    pub fn link_closed(&mut self, peer: ServerId) {
        self.open.retain(|(open_peer, _), _| *open_peer != peer);
        self.queued.remove(&peer);
        self.assembler
            .discard_sender(&Sender::Peer(*peer.as_bytes()));
    }

    /// Applies the committed batch's effects and hands back what to send.
    pub fn batch_applied(&mut self) -> Option<PendingCompanion> {
        let pending = self.pending.take()?;
        let mut effects = Vec::new();
        let mut committed = PendingCompanion {
            link: pending.link,
            peer: pending.peer,
            correlation: pending.correlation,
            request_object_id: pending.request_object_id,
            result: pending.result,
            responses: pending.responses,
            events: pending.events,
            effects: Vec::new(),
        };
        std::mem::swap(&mut effects, &mut committed.effects);
        for effect in pending.effects {
            effect(&mut self.state);
        }
        Some(committed)
    }

    /// Drops the batch behind a rejected commit; in-memory state is
    /// untouched because effects apply only on commit.
    pub fn batch_rejected(&mut self) {
        self.pending = None;
    }

    /// Retains an object in memory under the retained-bytes ceiling.
    pub(crate) fn retain_object(
        state: &mut CompanionState,
        bytes: Vec<u8>,
    ) -> Result<[u8; 32], E2eeReplyCode> {
        let object_id = *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes();
        if state.objects.contains_key(&object_id) {
            return Ok(object_id);
        }
        let total = state
            .object_bytes
            .checked_add(bytes.len())
            .ok_or(E2eeReplyCode::RateLimited)?;
        if total > MAX_RETAINED_OBJECT_BYTES {
            return Err(E2eeReplyCode::RateLimited);
        }
        state.object_bytes = total;
        state.objects.insert(object_id, bytes);
        Ok(object_id)
    }

    /// The durable row of a retained object.
    pub(crate) fn object_write(bytes: &[u8]) -> Result<AccountServiceDurableWrite, E2eeReplyCode> {
        let row = agenc_ircd_storage::e2ee_records::ObjectRow::new(bytes.to_vec())
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let key = row.key().map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let body = row.encode().map_err(|_| E2eeReplyCode::InvalidFragment)?;
        request::state_row(
            agenc_ircd_storage::TableId::E2eeObject,
            agenc_ircd_storage::e2ee_records::OBJECT_RECORD_KIND,
            key,
            body,
        )
    }

    /// The semantic identifier of an encoded TBS.
    pub(crate) fn id_of(
        domain: SemanticHashDomain,
        tbs: &impl TlsEncode,
    ) -> Result<[u8; 32], E2eeReplyCode> {
        semantic_id_of(domain, tbs).map_err(|_| E2eeReplyCode::InvalidFragment)
    }

    /// Peeks the kind of retained object bytes.
    pub(crate) fn kind_of(bytes: &[u8]) -> Option<IrcWireObjectKind> {
        IrcWireObject::peek(bytes).ok().map(|(kind, _)| kind)
    }
}

trait AssemblyKeyExt {
    fn with_peer(self, peer: ServerId) -> Self;
}

impl AssemblyKeyExt for AssemblyKey {
    fn with_peer(mut self, peer: ServerId) -> Self {
        self.sender = Sender::Peer(*peer.as_bytes());
        self
    }
}

trait CorrelationExt {
    fn request_id_route(&self) -> [u8; 32];
}

impl CorrelationExt for Correlation {
    /// Object assembly is keyed per request; the request identifier fills
    /// the route slot of the assembly tuple.
    fn request_id_route(&self) -> [u8; 32] {
        let mut route = [0; 32];
        if let Some(head) = route.get_mut(..16) {
            head.copy_from_slice(&self.request_id);
        }
        route
    }
}
