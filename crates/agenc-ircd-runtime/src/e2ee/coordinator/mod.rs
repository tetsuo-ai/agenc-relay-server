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

mod delivery_owner;
pub mod events;
pub mod execute;
mod mailbox_restore;
pub mod ops;
pub mod request;
mod startup;
pub mod sync;
#[cfg(test)]
pub(crate) mod tests;

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
    pub connection_id: [u8; 16],
    /// The object identifier of the accepted origin state object.
    pub object_id: [u8; 32],
    /// The semantic identifier of the accepted origin state object.
    pub state_id: [u8; 32],
    /// The predecessor state identifier the object named.
    pub previous_state_id: [u8; 32],
    /// Set while the link is down or before the origin is re-declared.
    pub suspended: bool,
    /// Set by EORIGIN DEL or an incarnation change; never cleared.
    pub fenced: bool,
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
    /// Process-local cuts; opaque mailbox cursors never survive reconstruction.
    pub(crate) mailbox_snapshots: ops::mailbox_snapshot::Store,
    /// Scheduled expiry ownership is independent of candidate snapshot effects.
    pub(crate) mailbox_expiry_armed: Option<u64>,
    /// Monotonic receipt time used before publishing a prepared mailbox cut.
    pub(crate) mailbox_snapshot_now: u64,
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
    /// Durable next-sequence floors, independent of replay result retention.
    pub origin_sequences:
        BTreeMap<CompanionOriginKey, agenc_ircd_storage::e2ee_records::origin::OriginSequenceRow>,
    /// Retained results and responses by request object identifier.
    pub results: BTreeMap<[u8; 32], StoredResult>,
    /// Per-conversation retained state the sequencer needs between records.
    pub conversations: BTreeMap<[u8; 32], ConversationState>,
    /// Gates awaiting the outer owner's independent base-stream validation.
    pub(crate) restored_barriers:
        BTreeMap<ServerId, agenc_ircd_storage::e2ee_records::delivery_recovery::DeliveryBarrier>,
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

/// The root binding locks of one (account, root fingerprint) by sequence.
pub type LockChain = BTreeMap<u64, LockEntry>;

/// One retained root binding lock: its semantic identifier, which the next
/// lock of the chain names, and its retained object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockEntry {
    /// The lock identifier.
    pub lock_id: [u8; 32],
    /// The retained lock object.
    pub object_id: [u8; 32],
}
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
    /// The current route state object identifier.
    pub route_object_id: [u8; 32],
    /// Bytes stored for this conversation.
    pub stored_bytes: u64,
    /// The last validation time accepted on a Commit AAD.
    pub last_validation_time: u64,
    /// The binding's principal accounts, whose rosters resolve policy
    /// approvals and finality votes.
    pub principal_accounts: Vec<[u8; 24]>,
    /// The binding's generation-zero policy identifier.
    pub initial_policy_id: [u8; 32],
    /// The binding's required operational policy identifier.
    pub required_operational_policy_id: [u8; 32],
    /// The policy the last finalization installed: the binding's initial
    /// policy before the first, and the old policy of the next candidate.
    pub current_policy_id: [u8; 32],
    /// The close this incarnation succeeds, for the route row.
    pub predecessor_close_id: Option<[u8; 32]>,
    /// Published policies by policy identifier (companion 9.3).
    pub policies: BTreeMap<[u8; 32], RetainedPolicy>,
    /// Council votes counted so far per candidate or attempt (12.4).
    pub vote_ledgers: BTreeMap<[u8; 32], agenc_ircd_e2ee::finality::QuorumLedger>,
}

/// One published policy the sequencer retains for its quorum check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedPolicy {
    /// The retained `policy` object identifier.
    pub object_id: [u8; 32],
    /// The complete object length, counted against `MAX_POLICY_CHAIN_BYTES`.
    pub object_bytes: usize,
    /// The verified policy.
    pub policy: agenc_ircd_e2ee::policy::VerifiedPolicy,
}

impl ConversationState {
    /// Retained policy bytes of the conversation.
    #[must_use]
    pub fn policy_bytes(&self) -> usize {
        self.policies.values().fold(0, |total, retained| {
            total.saturating_add(retained.object_bytes)
        })
    }
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
    /// The cross-profile barriers the batch opens.
    pub barriers: Vec<execute::BarrierPlanned>,
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

/// What one fragment did to its assembly.
enum Ingested {
    /// The object is complete.
    Complete(Vec<u8>),
    /// More fragments are needed, or this one repeated.
    Pending,
    /// The object completed recently; the prior outcome applies.
    Recent,
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
    delivery_identity: Option<delivery_owner::LocalIdentity>,
    signer: Option<SequencerSigner>,
    key_set: Option<SequencerKeySet>,
    current_credential: Option<agenc_ircd_e2ee::objects::conversation::IrcSequencerCredential>,
    global_disk_bytes: u64,
    assembler: E2eeAssembler,
    open: BTreeMap<(ServerId, [u8; 16]), OpenRequest>,
    queued: BTreeMap<ServerId, VecDeque<QueuedCompanion>>,
    /// The state.
    pub state: CompanionState,
    /// The batch in flight.
    pub pending: Option<sync::PendingWork>,
    /// The synchronization state of every edge.
    pub peers: BTreeMap<ServerId, sync::PeerSync>,
    /// Lines to send, drained by the owner.
    pub outbound: VecDeque<(ServerId, FederationLineText)>,
    /// Durable rows collected during the startup reload.
    restore: startup::Restore,
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

impl std::fmt::Display for CompanionFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol => {
                formatter.write_str("companion frame violated the federation grammar")
            }
            Self::Assembly(code) => write!(formatter, "reassembly refused: {}", code.token()),
            Self::Ceiling => formatter.write_str("companion per-peer ceiling crossed"),
            Self::Storage => formatter.write_str("companion batch could not be staged"),
        }
    }
}

impl std::error::Error for CompanionFault {}

impl CompanionCoordinator {
    /// A coordinator for `network_id` at `server_id`.
    #[must_use]
    pub fn new(network_id: [u8; 32], server_id: ServerId, server_name: String) -> Self {
        Self {
            network_id,
            server_id,
            server_name,
            delivery_identity: None,
            signer: None,
            key_set: None,
            global_disk_bytes: 0,
            current_credential: None,
            assembler: E2eeAssembler::default(),
            open: BTreeMap::new(),
            queued: BTreeMap::new(),
            state: CompanionState::default(),
            pending: None,
            peers: BTreeMap::new(),
            outbound: VecDeque::new(),
            restore: startup::Restore::default(),
        }
    }

    /// Collects one durable E2EE row during the coordinator's startup
    /// reload; the state is rebuilt by [`Self::finish_restore`].
    pub fn admit_restored(
        &mut self,
        table: agenc_ircd_storage::TableId,
        key: &agenc_ircd_storage::StoredKey,
        value: &agenc_ircd_storage::PersistentRecordValue,
    ) {
        self.restore.admit(table, key, value);
    }

    /// Rebuilds the companion state from the collected rows.
    pub fn finish_restore(&mut self) -> Result<(), CompanionFault> {
        let restore = std::mem::take(&mut self.restore);
        startup::rebuild(self, restore)
    }

    /// Records the configured logical E2EE disk ceiling for `STATS E2EE`.
    pub fn set_global_disk_bytes(&mut self, bytes: u64) {
        self.global_disk_bytes = bytes;
    }

    /// The nine `STATS E2EE` values (spec 22.3, companion 17): counts and
    /// bytes only.
    #[must_use]
    pub fn stats(&self) -> [u64; 9] {
        use agenc_ircd_domain::e2ee::RecoveryState;
        let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        let active = self
            .state
            .routes
            .routes()
            .filter(|route| route.accepts_traffic())
            .count();
        let recovery_pending = self
            .state
            .routes
            .routes()
            .filter(|route| route.recovery == RecoveryState::Pending)
            .count();
        let pending_candidates = self
            .state
            .logs
            .values()
            .filter(|log| log.has_candidate())
            .count();
        [
            1,
            count(active),
            count(recovery_pending),
            count(self.state.directory.entry_count()),
            count(self.state.mailboxes.item_count()),
            count(self.state.objects.len()),
            count(self.state.object_bytes),
            self.global_disk_bytes,
            count(pending_candidates),
        ]
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
    pub(crate) fn on_frame(
        &mut self,
        link: LinkId,
        peer: ServerId,
        frame: CompanionFrame,
        now_millis: u64,
        host: &dyn sync::CompanionHost,
        entropy: &mut dyn agenc_ircd_types::EntropySource,
    ) -> Result<Vec<sync::Action>, CompanionFault> {
        let sync = self.peers.entry(peer).or_default();
        if sync.link.is_some_and(|current| current != link) {
            return Err(CompanionFault::Protocol);
        }
        sync.link = Some(link);
        match frame {
            CompanionFrame::Request {
                correlation,
                object_id,
                fragment,
            } => self.on_request_fragment(peer, correlation, object_id, fragment, now_millis),
            CompanionFrame::Payload {
                correlation,
                object_id,
                fragment,
            } => self.on_payload_fragment(peer, correlation, object_id, fragment, now_millis),
            CompanionFrame::Ack(position) => {
                events::on_ack(self, link, peer, position, host.trusted_ack_unix_seconds())
            }
            other => self.on_sync_frame(peer, other, now_millis, host, entropy),
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
    ) -> Result<Ingested, CompanionFault> {
        let scopes = QuotaScopes {
            peer: Some(*peer.as_bytes()),
            ..QuotaScopes::default()
        };
        match self
            .assembler
            .ingest(key, scopes, command.limit(), fragment, now_millis / 1_000)
        {
            Ok(Ingest::Complete(bytes)) => Ok(Ingested::Complete(bytes)),
            Ok(Ingest::Incomplete | Ingest::Duplicate) => Ok(Ingested::Pending),
            Ok(Ingest::Recent) => Ok(Ingested::Recent),
            Err(error) => Err(CompanionFault::Assembly(error.reply_code())),
        }
    }

    /// EREQUEST: a complete request executes; a retransmitted request the
    /// coordinator already answered replays its stored result.
    fn on_request_fragment(
        &mut self,
        peer: ServerId,
        correlation: Correlation,
        object_id: [u8; 32],
        fragment: agenc_ircd_e2ee::wire::fragment::FragmentTag,
        now_millis: u64,
    ) -> Result<Vec<sync::Action>, CompanionFault> {
        if correlation.peer_server_id != *self.server_id.as_bytes() {
            return Err(CompanionFault::Protocol);
        }
        // On the wire the request names this coordinator; inside, every
        // correlation names the home edge the request came from.
        let correlation = Correlation {
            peer_server_id: *peer.as_bytes(),
            ..correlation
        };
        let command = CarrierCommand::Federation(IrcWireObjectKind::FederationRequest);
        let key = Self::assembly_key(peer, &correlation, command, object_id);
        let bytes = match self.ingest(key, peer, command, &fragment, now_millis)? {
            Ingested::Complete(bytes) => bytes,
            Ingested::Pending => return Ok(Vec::new()),
            Ingested::Recent => return self.replay_recent(peer, &correlation, object_id),
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
            return Ok(Vec::new());
        }
        Ok(vec![sync::Action::Execute(CompleteRequest {
            correlation: open.correlation,
            request: open.request,
            payload: None,
        })])
    }

    /// The stored answer of a request object the assembler already saw;
    /// its replay row must name this object under this correlation.
    fn replay_recent(
        &self,
        peer: ServerId,
        correlation: &Correlation,
        object_id: [u8; 32],
    ) -> Result<Vec<sync::Action>, CompanionFault> {
        let home = *peer.as_bytes();
        let key = agenc_ircd_storage::e2ee_records::ReplayKey {
            home_server_id: home,
            server_incarnation: correlation.server_incarnation,
            origin_id: correlation.origin_id,
            origin_generation: correlation.origin_generation,
            operation_sequence: correlation.operation_sequence,
        };
        let row = self
            .state
            .replays
            .get(&key)
            .filter(|row| {
                row.request_object_id == object_id && row.request_id == correlation.request_id
            })
            .ok_or(CompanionFault::Protocol)?;
        let stored = self
            .state
            .results
            .get(&row.request_object_id)
            .ok_or(CompanionFault::Protocol)?;
        let responses: Vec<Vec<u8>> = stored
            .responses
            .iter()
            .filter_map(|id| self.state.objects.get(id).cloned())
            .collect();
        let lines = execute::replay_lines(self, correlation, home, &stored.result, &responses)
            .map_err(|_| CompanionFault::Protocol)?;
        Ok(vec![sync::Action::Send(lines)])
    }

    /// EPAYLOAD: completes the open request; a retransmitted payload the
    /// coordinator retains completes it from the retained bytes.
    fn on_payload_fragment(
        &mut self,
        peer: ServerId,
        correlation: Correlation,
        object_id: [u8; 32],
        fragment: agenc_ircd_e2ee::wire::fragment::FragmentTag,
        now_millis: u64,
    ) -> Result<Vec<sync::Action>, CompanionFault> {
        if correlation.peer_server_id != *self.server_id.as_bytes() {
            return Err(CompanionFault::Protocol);
        }
        let correlation = Correlation {
            peer_server_id: *peer.as_bytes(),
            ..correlation
        };
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
        let bytes = match self.ingest(key, peer, limit_command, &fragment, now_millis)? {
            Ingested::Complete(bytes) => bytes,
            Ingested::Pending => return Ok(Vec::new()),
            Ingested::Recent => self
                .state
                .objects
                .get(&object_id)
                .cloned()
                .ok_or(CompanionFault::Protocol)?,
        };
        let open = self
            .open
            .remove(&(peer, correlation.request_id))
            .ok_or(CompanionFault::Protocol)?;
        Ok(vec![sync::Action::Execute(CompleteRequest {
            correlation: open.correlation,
            request: open.request,
            payload: Some(bytes),
        })])
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
        self.link_lost(peer);
        self.open.retain(|(open_peer, _), _| *open_peer != peer);
        self.queued.remove(&peer);
        self.assembler
            .discard_sender(&Sender::Peer(*peer.as_bytes()));
    }

    /// Marks the batch the owner just staged for this executor.
    pub fn set_pending(&mut self, work: sync::PendingWork) {
        self.pending = Some(work);
    }

    /// Applies the committed batch's effects and hands back what to send.
    /// The historical base epoch is part of the captured durable owner.
    pub fn batch_applied(
        &mut self,
        resync_epoch: Option<u64>,
    ) -> Result<Option<sync::Committed>, CompanionFault> {
        match self.pending.take() {
            None => Ok(None),
            Some(sync::PendingWork::Activate { peer, link, owner }) => self
                .activate_committed(peer, link, owner, resync_epoch)
                .map(|lines| Some(sync::Committed::Lines(lines))),
            Some(sync::PendingWork::Snapshot(publication)) => {
                Ok(Some(sync::Committed::Snapshot(publication)))
            }
            Some(sync::PendingWork::Fetch(publication)) => {
                Ok(Some(sync::Committed::Fetch(publication)))
            }
            Some(sync::PendingWork::Acknowledgement(ack)) => {
                let peer = ack.peer();
                ack.apply(self)?;
                Ok(Some(sync::Committed::Acknowledged(peer)))
            }
            Some(sync::PendingWork::Request(mut pending)) => {
                for effect in std::mem::take(&mut pending.effects) {
                    effect(&mut self.state);
                }
                Ok(Some(sync::Committed::Request(pending)))
            }
        }
    }

    /// Drops the staged batch after a rejected commit.
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
