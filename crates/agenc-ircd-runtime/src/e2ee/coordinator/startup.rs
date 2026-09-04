//! Reload of the companion state from its durable rows at coordinator
//! startup (companion Section 18.1). The rows are collected while the base
//! loader pages the E2EE tables, then rebuilt in dependency order: retained
//! objects, the directory (root chains re-verified, rosters and
//! capabilities re-verified without their retired predecessors), the
//! KeyPackage stock and claims, mailboxes, replay rows, and finally every
//! route with its sequencer log, lifecycle, and per-conversation facts.
//!
//! Not restored, by design or deferral: route reservations (short-lived and
//! not reconstructible without the owner's Account ID), delivery streams
//! (a reconnecting edge opens a fresh `ESTATE` scope), companion origins
//! (edges re-declare them), the context digest carried on `BIND`, and the
//! last accepted Commit validation time.

use std::collections::BTreeMap;

use agenc_ircd_crypto::SemanticHashDomain;
use agenc_ircd_domain::e2ee::directory::{
    AccountEntry, Attachment, CapabilityHead, Challenge, ClaimOutcome, ClaimParameters, Package,
    RootHead, RosterHead,
};
use agenc_ircd_domain::e2ee::lifecycle::{Lifecycle, RecoveryGate};
use agenc_ircd_domain::e2ee::mailbox::{Grant, Item, MailboxKind, Target};
use agenc_ircd_domain::e2ee::sequencer_log::{
    CandidatePosition, CandidateSlot, Head, Phase, SequencerLog,
};
use agenc_ircd_domain::e2ee::{
    ConversationId, DirectPair, RecoveryState, RouteEntry, RouteLifecycle, RouteTarget,
    SemanticLockId,
};
use agenc_ircd_e2ee::E2eeError;
use agenc_ircd_e2ee::finality::{
    QuorumLedger, ReinitVoteSlot, Terminal, VoteSlot, reinit_vote_tbs, vote_tbs,
};
use agenc_ircd_e2ee::identity::{
    VerifiedRoot, restore_capabilities, restore_roster, verify_root_identity,
};
use agenc_ircd_e2ee::limits::{
    MAX_ABORT_OBJECT, MAX_BINDING_OBJECT, MAX_CAPABILITY_OBJECT, MAX_FEDERATION_CONTROL_OBJECT,
    MAX_FINALIZATION_OBJECT, MAX_IDENTITY_OBJECT, MAX_POLICY_OBJECT, MAX_REINIT_OBJECT,
    MAX_ROSTER_OBJECT, MAX_SEQUENCER_RECORD_OBJECT,
};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::{
    IrcCommitAuthorizationRule, IrcConversationBindingPackage, IrcConversationKind, IrcPolicy,
};
use agenc_ircd_e2ee::objects::federation::IrcFederationRouteState;
use agenc_ircd_e2ee::objects::identity::{IrcDeviceCapabilities, IrcDeviceRoster, IrcRootIdentity};
use agenc_ircd_e2ee::objects::reinit::{IrcReInitAbortRequest, IrcReInitActivationRequest};
use agenc_ircd_e2ee::objects::sequencing::{
    IrcAbortRequest, IrcFinalityVote, IrcFinalizationRequest, IrcSequencerRecord,
};
use agenc_ircd_e2ee::policy::verify_policy;
use agenc_ircd_e2ee::route::PrincipalRosters;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_storage::e2ee_records::{
    ATTACH_ROW_KIND, AttachRow, DELIVERY_ROW_KIND, DIRECTORY_ROW_KIND, DeliveryRow, DirectoryRow,
    MAILBOX_ROW_KIND, MailboxKind as RowMailboxKind, MailboxRow, OBJECT_RECORD_KIND, ObjectRow,
    PACKAGE_ROW_KIND, PackageRow, PackageState, ProofKeyParts, ProofRole, REPLAY_ROW_KIND,
    ROUTE_ROW_KIND, ReplayRow, RouteLifecycle as RowLifecycle, RouteRow, SEQUENCER_ROW_KIND,
    SequencerRow,
};
use agenc_ircd_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_ircd_types::{AccountId, ChannelInstanceId, ServerId};

use super::events::DeliveryStream;
use super::{
    CompanionCoordinator, CompanionState, ConversationState, LockEntry, RetainedPolicy,
    StoredResult,
};

const CANDIDATE_RECORD: u16 = 1;
const FINALIZATION_RECORD: u16 = 2;

/// One sequencer record position.
struct RecordRow {
    record_object_id: [u8; 32],
    record_kind: u16,
    predecessor_record_id: [u8; 32],
}

/// The candidate slot row of one epoch.
struct CandidateRow {
    candidate_id: [u8; 32],
    commit_object_id: [u8; 32],
    route_sequence: u64,
    candidate_sequence: u32,
}

/// One published policy row: the retained object and its chain facts.
struct PolicyRow {
    object_id: [u8; 32],
    generation: u64,
}

/// The durable rows collected during the reload.
#[derive(Default)]
pub(super) struct Restore {
    objects: Vec<Vec<u8>>,
    routes: BTreeMap<[u8; 32], RouteRow>,
    records: BTreeMap<([u8; 32], u64), RecordRow>,
    candidates: BTreeMap<([u8; 32], u64), CandidateRow>,
    proofs: Vec<(ProofKeyParts, [u8; 32])>,
    policies: BTreeMap<([u8; 32], [u8; 32]), PolicyRow>,
    directory: Vec<(StoredKey, DirectoryRow)>,
    packages: Vec<(StoredKey, PackageRow)>,
    attachments: Vec<(StoredKey, AttachRow)>,
    mailbox: Vec<(StoredKey, MailboxRow)>,
    replays: Vec<(StoredKey, ReplayRow)>,
    cursors: Vec<(StoredKey, DeliveryRow)>,
}

impl Restore {
    /// Collects one row of an E2EE table.
    pub(super) fn admit(&mut self, table: TableId, key: &StoredKey, value: &PersistentRecordValue) {
        match table {
            TableId::E2eeObject => self.admit_object(value),
            TableId::E2eeState => self.admit_state(key, value),
            _ => {}
        }
    }

    fn admit_object(&mut self, value: &PersistentRecordValue) {
        if value.record_kind() != OBJECT_RECORD_KIND {
            return;
        }
        if let Ok(row) = ObjectRow::decode(value.body()) {
            self.objects.push(row.bytes);
        }
    }

    fn admit_state(&mut self, key: &StoredKey, value: &PersistentRecordValue) {
        let body = value.body();
        match value.record_kind() {
            ROUTE_ROW_KIND => {
                if let (Ok(id), Ok(row)) = (RouteRow::parse_key(key), RouteRow::decode(body)) {
                    self.routes.insert(id, row);
                }
            }
            SEQUENCER_ROW_KIND => self.admit_sequencer(key, body),
            DIRECTORY_ROW_KIND => push(&mut self.directory, key, DirectoryRow::decode(body)),
            PACKAGE_ROW_KIND => push(&mut self.packages, key, PackageRow::decode(body)),
            ATTACH_ROW_KIND => push(&mut self.attachments, key, AttachRow::decode(body)),
            MAILBOX_ROW_KIND => push(&mut self.mailbox, key, MailboxRow::decode(body)),
            REPLAY_ROW_KIND => push(&mut self.replays, key, ReplayRow::decode(body)),
            DELIVERY_ROW_KIND => push(&mut self.cursors, key, DeliveryRow::decode(body)),
            _ => {}
        }
    }

    fn admit_sequencer(&mut self, key: &StoredKey, body: &[u8]) {
        match SequencerRow::decode(body) {
            Ok(SequencerRow::Record {
                record_object_id,
                record_kind,
                predecessor_record_id,
                ..
            }) => self.admit_record(
                key,
                RecordRow {
                    record_object_id,
                    record_kind,
                    predecessor_record_id,
                },
            ),
            Ok(SequencerRow::Candidate {
                candidate_id,
                commit_object_id,
                route_sequence,
                candidate_sequence,
                ..
            }) => self.admit_candidate(
                key,
                CandidateRow {
                    candidate_id,
                    commit_object_id,
                    route_sequence,
                    candidate_sequence,
                },
            ),
            Ok(SequencerRow::Proof { object_id, .. }) => self.admit_proof(key, object_id),
            Ok(SequencerRow::Policy {
                object_id,
                generation,
                ..
            }) => self.admit_policy(
                key,
                PolicyRow {
                    object_id,
                    generation,
                },
            ),
            Err(_) => {}
        }
    }

    fn admit_policy(&mut self, key: &StoredKey, row: PolicyRow) {
        if let Ok(ids) = SequencerRow::parse_policy_key(key) {
            self.policies.insert(ids, row);
        }
    }

    fn admit_record(&mut self, key: &StoredKey, row: RecordRow) {
        if let Ok(position) = SequencerRow::parse_record_key(key) {
            self.records.insert(position, row);
        }
    }

    fn admit_candidate(&mut self, key: &StoredKey, row: CandidateRow) {
        if let Ok(epoch) = SequencerRow::parse_candidate_key(key) {
            self.candidates.insert(epoch, row);
        }
    }

    fn admit_proof(&mut self, key: &StoredKey, object_id: [u8; 32]) {
        if let Ok(parts) = SequencerRow::parse_proof_key(key) {
            self.proofs.push((parts, object_id));
        }
    }
}

fn push<T, E>(rows: &mut Vec<(StoredKey, T)>, key: &StoredKey, row: Result<T, E>) {
    if let Ok(row) = row {
        rows.push((key.clone(), row));
    }
}

/// Decodes the body of a retained wire object of `kind`.
fn decode_body<T: TlsDecode>(bytes: &[u8], kind: IrcWireObjectKind, limit: usize) -> Option<T> {
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    let object = IrcWireObject::decode_exact(bytes, &mut budget).ok()?;
    if object.kind() != kind {
        return None;
    }
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    T::decode_exact(object.body(), &mut budget).ok()
}

/// Decodes the retained object `object_id` as `kind`.
fn decode_object<T: TlsDecode>(
    state: &CompanionState,
    object_id: &[u8; 32],
    kind: IrcWireObjectKind,
    limit: usize,
) -> Option<T> {
    let bytes = state.objects.get(object_id)?;
    decode_body(bytes, kind, limit)
}

/// Retained objects indexed by what the routes need from them.
#[derive(Default)]
struct ObjectIndex {
    /// Binding packages by binding identifier, with the object identifier.
    bindings: BTreeMap<[u8; 32], ([u8; 32], IrcConversationBindingPackage)>,
    /// Published policies by object identifier, with the object length.
    policies: BTreeMap<[u8; 32], (IrcPolicy, usize)>,
    /// Finality request objects by conversation and finalization identifier.
    proofs: BTreeMap<[u8; 32], BTreeMap<[u8; 32], [u8; 32]>>,
    /// Retained terminal requests by the candidate or attempt they vote on.
    terminal_requests: BTreeMap<[u8; 32], Vec<TerminalRequest>>,
}

/// The votes one retained terminal request carries for its subject.
enum TerminalRequest {
    /// A finalization request and its finalization identifier.
    Finalize([u8; 32], Vec<IrcFinalityVote>),
    /// An abort request, its abort identifier, and its reason code.
    Abort([u8; 32], u16, Vec<IrcFinalityVote>),
    /// A ReInit activation request and its activation identifier.
    Activate([u8; 32], Vec<IrcFinalityVote>),
    /// A ReInit abort request, its abort identifier, and its reason code.
    AbortAttempt([u8; 32], u16, Vec<IrcFinalityVote>),
}

impl ObjectIndex {
    fn build(state: &CompanionState) -> Self {
        let mut index = Self::default();
        for (object_id, bytes) in &state.objects {
            let Ok((kind, _)) = IrcWireObject::peek(bytes) else {
                continue;
            };
            index.index_object(kind, *object_id, bytes);
        }
        index
    }

    fn index_object(&mut self, kind: IrcWireObjectKind, object_id: [u8; 32], bytes: &[u8]) {
        match kind {
            IrcWireObjectKind::ConversationBinding => {
                let Some(package) =
                    decode_body::<IrcConversationBindingPackage>(bytes, kind, MAX_BINDING_OBJECT)
                else {
                    return;
                };
                let Ok(binding_id) = CompanionCoordinator::id_of(
                    SemanticHashDomain::BindingId,
                    &package.binding.tbs,
                ) else {
                    return;
                };
                self.bindings.insert(binding_id, (object_id, package));
            }
            IrcWireObjectKind::FinalizationRequest => {
                let Some(request) =
                    decode_body::<IrcFinalizationRequest>(bytes, kind, MAX_FINALIZATION_OBJECT)
                else {
                    return;
                };
                let core = &request.proof.core;
                let Ok(finalization_id) =
                    CompanionCoordinator::id_of(SemanticHashDomain::FinalizationId, core)
                else {
                    return;
                };
                self.proofs
                    .entry(core.conversation_id)
                    .or_default()
                    .insert(finalization_id, object_id);
                self.terminal_requests
                    .entry(core.candidate_id)
                    .or_default()
                    .push(TerminalRequest::Finalize(
                        finalization_id,
                        request.votes.as_slice().to_vec(),
                    ));
            }
            IrcWireObjectKind::AbortRequest => self.index_abort(bytes),
            IrcWireObjectKind::ReinitActivationRequest => self.index_activation(bytes),
            IrcWireObjectKind::ReinitAbortRequest => self.index_attempt_abort(bytes),
            IrcWireObjectKind::Policy => {
                if let Some(policy) = decode_body::<IrcPolicy>(bytes, kind, MAX_POLICY_OBJECT) {
                    self.policies.insert(object_id, (policy, bytes.len()));
                }
            }
            _ => {}
        }
    }
}

impl ObjectIndex {
    fn index_abort(&mut self, bytes: &[u8]) {
        let kind = IrcWireObjectKind::AbortRequest;
        let Some(request) = decode_body::<IrcAbortRequest>(bytes, kind, MAX_ABORT_OBJECT) else {
            return;
        };
        let Ok(abort_id) = CompanionCoordinator::id_of(SemanticHashDomain::AbortId, &request.core)
        else {
            return;
        };
        self.terminal_requests
            .entry(request.core.candidate_id)
            .or_default()
            .push(TerminalRequest::Abort(
                abort_id,
                u16::from(request.core.reason.value()),
                request.votes.as_slice().to_vec(),
            ));
    }

    fn index_activation(&mut self, bytes: &[u8]) {
        let kind = IrcWireObjectKind::ReinitActivationRequest;
        let Some(request) =
            decode_body::<IrcReInitActivationRequest>(bytes, kind, MAX_REINIT_OBJECT)
        else {
            return;
        };
        let Ok(activation_id) =
            CompanionCoordinator::id_of(SemanticHashDomain::ReinitActivationId, &request.core)
        else {
            return;
        };
        self.terminal_requests
            .entry(request.core.reinit_attempt_id)
            .or_default()
            .push(TerminalRequest::Activate(
                activation_id,
                request.votes.as_slice().to_vec(),
            ));
    }

    fn index_attempt_abort(&mut self, bytes: &[u8]) {
        let kind = IrcWireObjectKind::ReinitAbortRequest;
        let Some(request) = decode_body::<IrcReInitAbortRequest>(bytes, kind, MAX_REINIT_OBJECT)
        else {
            return;
        };
        let Ok(abort_id) =
            CompanionCoordinator::id_of(SemanticHashDomain::ReinitAbortId, &request.core)
        else {
            return;
        };
        self.terminal_requests
            .entry(request.core.reinit_attempt_id)
            .or_default()
            .push(TerminalRequest::AbortAttempt(
                abort_id,
                request.core.reason_code,
                request.votes.as_slice().to_vec(),
            ));
    }
}

/// Rebuilds the companion state from the collected rows.
pub(super) fn rebuild(coordinator: &mut CompanionCoordinator, restore: Restore) {
    let network_id = coordinator.network_id;
    let state = &mut coordinator.state;
    for bytes in restore.objects {
        let _ = CompanionCoordinator::retain_object(state, bytes);
    }
    restore_directory(state, &network_id, restore.directory, restore.attachments);
    restore_packages(state, restore.packages);
    restore_mailboxes(state, restore.mailbox);
    restore_replays(state, restore.replays);
    restore_cursors(state, restore.cursors);
    let index = ObjectIndex::build(state);
    let rows = SequencerRows {
        records: restore.records,
        candidates: restore.candidates,
        proofs: restore.proofs,
        policies: restore.policies,
    };
    for (conversation_id, row) in restore.routes {
        restore_route(state, &network_id, &index, &rows, conversation_id, &row);
    }
}

// ---------------------------------------------------------------------------
// Directory.

fn restore_directory(
    state: &mut CompanionState,
    network_id: &[u8; 32],
    rows: Vec<(StoredKey, DirectoryRow)>,
    attachments: Vec<(StoredKey, AttachRow)>,
) {
    let mut entries: BTreeMap<[u8; 32], AccountEntry> = BTreeMap::new();
    let mut roots: BTreeMap<[u8; 32], VerifiedRoot> = BTreeMap::new();
    let mut later = Vec::new();
    for (key, row) in rows {
        match row {
            identity @ DirectoryRow::Identity { .. } => {
                if let Some((digest, root, head)) =
                    restore_identity(state, network_id, &key, identity)
                {
                    entries.entry(digest).or_default().root = Some(head);
                    roots.insert(digest, root);
                }
            }
            other => later.push((key, other)),
        }
    }
    for (key, row) in &later {
        if let DirectoryRow::Roster { .. } = row {
            restore_roster_row(state, &roots, &mut entries, key, row);
        }
    }
    for (digest, root) in roots {
        if !state.principals.contains_key(&digest) {
            state.pending_roots.insert(digest, root);
        }
    }
    for (key, row) in &later {
        match row {
            DirectoryRow::Capability { .. } => {
                restore_capability_row(state, &mut entries, key, row);
            }
            DirectoryRow::BindingLock { .. } => {
                restore_lock_row(state, &mut entries, key, row);
            }
            DirectoryRow::Identity { .. } | DirectoryRow::Roster { .. } => {}
        }
    }
    for (key, row) in attachments {
        restore_attachment(state, &mut entries, &key, row);
    }
    for (digest, entry) in entries {
        state.directory.restore_account(digest, entry);
    }
}

/// Re-verifies one root chain oldest first.
fn restore_identity(
    state: &CompanionState,
    network_id: &[u8; 32],
    key: &StoredKey,
    row: DirectoryRow,
) -> Option<([u8; 32], VerifiedRoot, RootHead)> {
    let digest = DirectoryRow::parse_identity_key(key).ok()?;
    let DirectoryRow::Identity {
        root_generation,
        root_fingerprint,
        chain_object_ids,
        ..
    } = row
    else {
        return None;
    };
    let mut verified: Option<VerifiedRoot> = None;
    for object_id in &chain_object_ids {
        let root: IrcRootIdentity = decode_object(
            state,
            object_id,
            IrcWireObjectKind::RootIdentity,
            MAX_IDENTITY_OBJECT,
        )?;
        verified = Some(verify_root_identity(network_id, &root, verified.as_ref()).ok()?);
    }
    let verified = verified.filter(|root| {
        root.fingerprint == root_fingerprint && root.generation == root_generation
    })?;
    let head = RootHead {
        generation: root_generation,
        fingerprint: root_fingerprint,
        chain: chain_object_ids,
    };
    Some((digest, verified, head))
}

fn restore_roster_row(
    state: &mut CompanionState,
    roots: &BTreeMap<[u8; 32], VerifiedRoot>,
    entries: &mut BTreeMap<[u8; 32], AccountEntry>,
    key: &StoredKey,
    row: &DirectoryRow,
) -> Option<()> {
    let DirectoryRow::Roster {
        roster_generation,
        roster_id,
        root_fingerprint,
        object_id,
        ..
    } = row
    else {
        return None;
    };
    let digest = DirectoryRow::parse_roster_key(key).ok()?;
    let root = roots.get(&digest)?;
    let roster: IrcDeviceRoster = decode_object(
        state,
        object_id,
        IrcWireObjectKind::DeviceRoster,
        MAX_ROSTER_OBJECT,
    )?;
    let verified = restore_roster(root, &roster).ok()?;
    if verified.roster_id != *roster_id || root.fingerprint != *root_fingerprint {
        return None;
    }
    entries.entry(digest).or_default().roster = Some(RosterHead {
        generation: *roster_generation,
        roster_id: *roster_id,
        root_fingerprint: *root_fingerprint,
        object_id: *object_id,
        active_devices: verified.devices.keys().copied().collect(),
    });
    state.principals.insert(digest, (*root, verified));
    Some(())
}

fn restore_capability_row(
    state: &mut CompanionState,
    entries: &mut BTreeMap<[u8; 32], AccountEntry>,
    key: &StoredKey,
    row: &DirectoryRow,
) -> Option<()> {
    let DirectoryRow::Capability {
        generation,
        capability_id,
        roster_id,
        object_id,
    } = row
    else {
        return None;
    };
    let (digest, device_id) = DirectoryRow::parse_capability_key(key).ok()?;
    let roster = state
        .principals
        .get(&digest)
        .map(|(_, roster)| roster.clone())?;
    let capabilities: IrcDeviceCapabilities = decode_object(
        state,
        object_id,
        IrcWireObjectKind::DeviceCapabilities,
        MAX_CAPABILITY_OBJECT,
    )?;
    let verified = restore_capabilities(&roster, &capabilities).ok()?;
    if verified.capability_id != *capability_id || verified.device_id != device_id {
        return None;
    }
    entries.entry(digest).or_default().capabilities.insert(
        device_id,
        CapabilityHead {
            generation: *generation,
            capability_id: *capability_id,
            roster_id: *roster_id,
            object_id: *object_id,
        },
    );
    state.capabilities.insert((digest, device_id), verified);
    Some(())
}

fn restore_lock_row(
    state: &mut CompanionState,
    entries: &mut BTreeMap<[u8; 32], AccountEntry>,
    key: &StoredKey,
    row: &DirectoryRow,
) -> Option<()> {
    let DirectoryRow::BindingLock {
        lock_id, object_id, ..
    } = row
    else {
        return None;
    };
    let (digest, root, sequence) = DirectoryRow::parse_binding_lock_key(key).ok()?;
    state
        .binding_locks
        .entry((digest, root))
        .or_default()
        .insert(
            sequence,
            LockEntry {
                lock_id: *lock_id,
                object_id: *object_id,
            },
        );
    let next = entries
        .entry(digest)
        .or_default()
        .lock_sequences
        .entry(root)
        .or_insert(0);
    *next = (*next).max(sequence.saturating_add(1));
    Some(())
}

fn restore_attachment(
    state: &mut CompanionState,
    entries: &mut BTreeMap<[u8; 32], AccountEntry>,
    key: &StoredKey,
    row: AttachRow,
) -> Option<()> {
    let (digest, device_id) = AttachRow::parse_key(key).ok()?;
    let challenge = row.challenge.as_ref().map(|challenge| Challenge {
        connection_id: challenge.connection_id,
        reserved_generation: challenge.reserved_generation,
        expires_at: challenge.expires_at,
    });
    entries.entry(digest).or_default().attachments.insert(
        device_id,
        Attachment {
            session_generation: row.session_generation,
            challenge,
        },
    );
    if let Some(challenge) = row.challenge {
        state
            .challenges
            .insert((digest, device_id), challenge.server_challenge);
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Packages, mailboxes, replays.

fn restore_packages(state: &mut CompanionState, rows: Vec<(StoredKey, PackageRow)>) {
    for (key, row) in rows {
        match row {
            PackageRow::Package { .. } => restore_package_row(state, &key, row),
            PackageRow::Claim { .. } => restore_claim_row(state, &key, row),
        }
    }
}

fn restore_package_row(state: &mut CompanionState, key: &StoredKey, row: PackageRow) {
    let PackageRow::Package {
        account_digest,
        device_id,
        suite,
        expires_at,
        object_id,
        state: PackageState::Published,
        ..
    } = row
    else {
        return;
    };
    let Ok(reference) = PackageRow::parse_package_key(key) else {
        return;
    };
    state.directory.restore_package(
        reference,
        Package {
            account_digest,
            device_id,
            suite,
            expires_at,
            object_id,
        },
    );
}

fn restore_claim_row(state: &mut CompanionState, key: &StoredKey, row: PackageRow) {
    let PackageRow::Claim {
        target_account_digest,
        target_device_id,
        suite,
        key_package_ref,
        object_id,
        retain_until,
        ..
    } = row
    else {
        return;
    };
    let Ok((claimant, operation)) = PackageRow::parse_claim_key(key) else {
        return;
    };
    let outcome = object_id.map_or(ClaimOutcome::Unavailable, |object_id| {
        ClaimOutcome::Claimed {
            key_package_ref,
            object_id,
        }
    });
    state.directory.restore_claim(
        claimant,
        operation,
        ClaimParameters {
            target_account_digest,
            target_device_id,
            suite,
        },
        outcome,
        retain_until,
    );
}

const fn mailbox_kind(kind: RowMailboxKind) -> MailboxKind {
    match kind {
        RowMailboxKind::Application => MailboxKind::Application,
        RowMailboxKind::Binding => MailboxKind::Binding,
        RowMailboxKind::Welcome => MailboxKind::Welcome,
        RowMailboxKind::StagedReinit => MailboxKind::StagedReinit,
    }
}

type ItemSlot = (Target, MailboxKind, u64);

/// The mailbox rows sorted by what they restore.
#[derive(Default)]
struct MailboxRows {
    items: BTreeMap<ItemSlot, Item>,
    grants: Vec<(ItemSlot, Grant)>,
    acks: Vec<(Target, [u8; 32], [u8; 32], u64)>,
}

impl MailboxRows {
    fn admit(&mut self, key: &StoredKey, row: MailboxRow) {
        match row {
            MailboxRow::Item { .. } => self.admit_item(key, row),
            MailboxRow::Token { .. } => self.admit_token(key, row),
            MailboxRow::Ack { .. } => self.admit_ack(key, row),
        }
    }

    fn admit_item(&mut self, key: &StoredKey, row: MailboxRow) {
        let MailboxRow::Item {
            object_id,
            conversation_id,
            inserted_at,
            expires_at,
            ..
        } = row
        else {
            return;
        };
        let Ok(parts) = MailboxRow::parse_item_key(key) else {
            return;
        };
        let target = Target {
            account_digest: parts.account_digest,
            device_id: parts.device_id,
        };
        self.items.insert(
            (target, mailbox_kind(parts.kind), parts.sequence),
            Item {
                object_id,
                conversation_id,
                inserted_at,
                expires_at,
                grant: None,
            },
        );
    }

    fn admit_token(&mut self, key: &StoredKey, row: MailboxRow) {
        let MailboxRow::Token {
            account_digest,
            device_id,
            kind,
            sequence,
            session_generation,
            expires_at,
            ..
        } = row
        else {
            return;
        };
        let Ok(token) = MailboxRow::parse_token_key(key) else {
            return;
        };
        let target = Target {
            account_digest,
            device_id,
        };
        self.grants.push((
            (target, mailbox_kind(kind), sequence),
            Grant {
                token,
                session_generation,
                expires_at,
            },
        ));
    }

    fn admit_ack(&mut self, key: &StoredKey, row: MailboxRow) {
        let MailboxRow::Ack {
            object_id,
            retain_until,
            ..
        } = row
        else {
            return;
        };
        let Ok((account_digest, device_id, token)) = MailboxRow::parse_ack_key(key) else {
            return;
        };
        let target = Target {
            account_digest,
            device_id,
        };
        self.acks.push((target, token, object_id, retain_until));
    }
}

fn restore_mailboxes(state: &mut CompanionState, rows: Vec<(StoredKey, MailboxRow)>) {
    let mut sorted = MailboxRows::default();
    for (key, row) in rows {
        sorted.admit(&key, row);
    }
    for (slot, grant) in sorted.grants {
        if let Some(item) = sorted.items.get_mut(&slot) {
            item.grant = Some(grant);
        }
    }
    for ((target, kind, sequence), item) in sorted.items {
        state.mailboxes.restore_item(target, kind, sequence, item);
    }
    for (target, token, object_id, retain_until) in sorted.acks {
        state
            .mailboxes
            .restore_ack(target, token, object_id, retain_until);
    }
}

fn restore_replays(state: &mut CompanionState, rows: Vec<(StoredKey, ReplayRow)>) {
    for (key, row) in rows {
        let Ok(parts) = ReplayRow::parse_key(&key) else {
            continue;
        };
        let result = row
            .result_object_id
            .and_then(|object_id| state.objects.get(&object_id).cloned());
        if let Some(result) = result {
            state.results.insert(
                row.request_object_id,
                StoredResult {
                    result,
                    responses: row.response_object_ids.clone(),
                },
            );
        }
        state.replays.insert(parts, row);
    }
}

/// Restores the delivery position of every target from its cursor row; the
/// queued rows are not reloaded, so a reconnecting edge always opens the
/// next generation with a fresh `ESTATE` scope.
fn restore_cursors(state: &mut CompanionState, rows: Vec<(StoredKey, DeliveryRow)>) {
    for (key, row) in rows {
        let DeliveryRow::Cursor {
            generation,
            next_sequence,
            acked_sequence,
            acked_event_id,
            ..
        } = row
        else {
            continue;
        };
        let Ok(target) = DeliveryRow::parse_cursor_key(&key) else {
            continue;
        };
        state.streams.insert(
            ServerId::from_bytes(target),
            DeliveryStream {
                generation,
                next_sequence,
                acked: (next_sequence > 0).then_some((acked_sequence, acked_event_id)),
                ..DeliveryStream::default()
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Routes.

/// The sequencer rows of every conversation.
struct SequencerRows {
    records: BTreeMap<([u8; 32], u64), RecordRow>,
    candidates: BTreeMap<([u8; 32], u64), CandidateRow>,
    proofs: Vec<(ProofKeyParts, [u8; 32])>,
    policies: BTreeMap<([u8; 32], [u8; 32]), PolicyRow>,
}

impl SequencerRows {
    fn records_of(&self, conversation_id: [u8; 32]) -> BTreeMap<u64, &RecordRow> {
        self.records
            .range((conversation_id, 0)..=(conversation_id, u64::MAX))
            .map(|((_, sequence), row)| (*sequence, row))
            .collect()
    }
}

fn route_target(route: &IrcFederationRouteState) -> Option<RouteTarget> {
    match route.conversation_kind {
        IrcConversationKind::Channel => {
            let instance = <[u8; 16]>::try_from(route.channel_instance_id.as_slice()).ok()?;
            Some(RouteTarget::Channel(ChannelInstanceId::from_bytes(
                instance,
            )))
        }
        IrcConversationKind::Direct => {
            let (first, second) = direct_accounts(route)?;
            let pair = DirectPair::new(
                AccountId::parse_wire_bytes(&first).ok()?,
                AccountId::parse_wire_bytes(&second).ok()?,
            )
            .ok()?;
            Some(RouteTarget::Direct(pair))
        }
    }
}

fn direct_accounts(route: &IrcFederationRouteState) -> Option<([u8; 24], [u8; 24])> {
    let first = <[u8; 24]>::try_from(route.direct_account_a.as_slice()).ok()?;
    let second = <[u8; 24]>::try_from(route.direct_account_b.as_slice()).ok()?;
    Some((first, second))
}

fn route_lifecycle(row: &RouteRow) -> RouteLifecycle {
    match row.lifecycle {
        RowLifecycle::Active => RouteLifecycle::Active,
        RowLifecycle::Closing => RouteLifecycle::Closing,
        RowLifecycle::Tombstone => RouteLifecycle::Tombstone {
            close_id: row.close_id.unwrap_or(row.sequencer_head_id),
        },
    }
}

/// Restores the log of one route: the head from the route row, the epoch
/// from the route state object, and the epoch position from the record
/// rows since the last finalization.
fn restore_log(
    conversation_id: [u8; 32],
    row: &RouteRow,
    route: &IrcFederationRouteState,
    records: &BTreeMap<u64, &RecordRow>,
    candidate: Option<&CandidateRow>,
) -> SequencerLog {
    let head = Head {
        sequence: row.route_sequence,
        record_id: row.sequencer_head_id,
        recorded: !records.is_empty() || row.close_id.is_some(),
    };
    let phase = row
        .close_id
        .map_or(Phase::Open, |close_id| Phase::Closed { close_id });
    let mut log = SequencerLog::restore(
        conversation_id,
        head,
        row.accepted_state_id,
        route.finalized_epoch,
        phase,
    );
    let last_finalization = records
        .iter()
        .filter(|(_, record)| record.record_kind == FINALIZATION_RECORD)
        .map(|(sequence, _)| *sequence)
        .max();
    let attempts = records
        .iter()
        .filter(|(sequence, record)| {
            record.record_kind == CANDIDATE_RECORD
                && last_finalization.is_none_or(|last| **sequence > last)
        })
        .count();
    let active = records
        .get(&row.route_sequence)
        .filter(|record| record.record_kind == CANDIDATE_RECORD)
        .zip(candidate)
        .filter(|(_, candidate)| candidate.candidate_id == row.sequencer_head_id)
        .map(|(record, candidate)| CandidateSlot {
            candidate_id: candidate.candidate_id,
            commit_object_id: candidate.commit_object_id,
            position: CandidatePosition {
                route_sequence: candidate.route_sequence,
                prior_epoch: route.finalized_epoch,
                prior_state_id: row.accepted_state_id,
                candidate_sequence: candidate.candidate_sequence,
                predecessor_record_id: record.predecessor_record_id,
            },
        });
    log.restore_epoch(active, u32::try_from(attempts).unwrap_or(u32::MAX));
    log
}

/// Whether a retained finalization record activated the bootstrap.
/// The principal accounts of a binding package, in package order.
fn principal_accounts(package: &IrcConversationBindingPackage) -> Vec<[u8; 24]> {
    package
        .binding
        .tbs
        .principals
        .as_slice()
        .iter()
        .filter_map(|principal| <[u8; 24]>::try_from(principal.account_id.as_slice()).ok())
        .collect()
}

/// The policy the newest finalization record installed, or the binding's
/// initial policy before any finalization.
fn current_policy(
    state: &CompanionState,
    records: &BTreeMap<u64, &RecordRow>,
    initial_policy_id: [u8; 32],
) -> [u8; 32] {
    records
        .values()
        .rev()
        .filter(|record| record.record_kind == FINALIZATION_RECORD)
        .find_map(|record| {
            let decoded: Option<IrcSequencerRecord> = decode_object(
                state,
                &record.record_object_id,
                IrcWireObjectKind::SequencerRecord,
                MAX_SEQUENCER_RECORD_OBJECT,
            );
            match decoded {
                Some(IrcSequencerRecord::Finalization(certificate)) => Some(
                    certificate
                        .tbs
                        .request
                        .proof
                        .authorization
                        .tbs
                        .resulting_policy_id,
                ),
                _ => None,
            }
        })
        .unwrap_or(initial_policy_id)
}

/// Re-verifies the conversation's published policy chain in generation
/// order from the retained objects; a policy that no longer verifies, or
/// whose predecessor is missing, is dropped with its successors.
fn restore_policies(
    state: &CompanionState,
    network_id: &[u8; 32],
    index: &ObjectIndex,
    rows: &SequencerRows,
    conversation: &mut ConversationState,
    conversation_id: [u8; 32],
) {
    let rosters = principal_rosters(state, network_id, conversation);
    let mut ordered: Vec<(&[u8; 32], &PolicyRow)> = rows
        .policies
        .range((conversation_id, [0; 32])..=(conversation_id, [u8::MAX; 32]))
        .map(|((_, policy_id), row)| (policy_id, row))
        .collect();
    ordered.sort_by_key(|(_, row)| row.generation);
    for (policy_id, row) in ordered {
        let Some((policy, object_bytes)) = index.policies.get(&row.object_id) else {
            continue;
        };
        let predecessor = conversation
            .policies
            .get(&policy.tbs.previous_policy_id)
            .map(|retained| &retained.policy);
        let chained = if policy.tbs.policy_generation == 0 {
            *policy_id == conversation.initial_policy_id
        } else {
            predecessor.is_some()
        };
        if !chained {
            continue;
        }
        let Ok(verified) =
            verify_policy(network_id, &conversation_id, policy, &rosters, predecessor)
        else {
            continue;
        };
        conversation.policies.insert(
            *policy_id,
            RetainedPolicy {
                object_id: row.object_id,
                object_bytes: *object_bytes,
                policy: verified,
            },
        );
    }
}

/// The rosters of the conversation's principals, keyed by Account ID.
fn principal_rosters(
    state: &CompanionState,
    network_id: &[u8; 32],
    conversation: &ConversationState,
) -> PrincipalRosters {
    let mut rosters = PrincipalRosters::new();
    for account in &conversation.principal_accounts {
        let Ok(digest) = agenc_ircd_e2ee::ids::account_id_digest(network_id, account) else {
            continue;
        };
        if let Some((root, roster)) = state.principals.get(&digest) {
            rosters.insert(*account, (*root, roster.clone()));
        }
    }
    rosters
}

/// The terminal and votes of one retained request for a candidate slot.
fn candidate_terminal(request: &TerminalRequest) -> Option<(Terminal, &[IrcFinalityVote])> {
    match request {
        TerminalRequest::Finalize(id, votes) => Some((Terminal::finalize(*id), votes)),
        TerminalRequest::Abort(id, reason, votes) => Terminal::abort(*id, *reason)
            .ok()
            .map(|terminal| (terminal, votes.as_slice())),
        _ => None,
    }
}

/// The terminal and votes of one retained request for a ReInit attempt.
fn attempt_terminal(request: &TerminalRequest) -> Option<(Terminal, &[IrcFinalityVote])> {
    match request {
        TerminalRequest::Activate(id, votes) => Some((Terminal::finalize(*id), votes)),
        TerminalRequest::AbortAttempt(id, reason, votes) => Terminal::abort(*id, *reason)
            .ok()
            .map(|terminal| (terminal, votes.as_slice())),
        _ => None,
    }
}

/// Replays the votes of every retained terminal request of the open
/// candidate or ReInit attempt into its ledger under the current policy, so
/// a reload keeps the count and the sign-once memory the slot had gathered
/// (companion 12.4).
fn restore_ledgers(
    state: &CompanionState,
    network_id: &[u8; 32],
    index: &ObjectIndex,
    conversation: &mut ConversationState,
    log: &SequencerLog,
) {
    let Some(policy) = conversation
        .policies
        .get(&conversation.current_policy_id)
        .map(|retained| retained.policy.clone())
    else {
        return;
    };
    let rosters = principal_rosters(state, network_id, conversation);
    let conversation_id = *log.conversation_id();
    if let Some(slot) = log.candidate() {
        let vote_slot = VoteSlot {
            network_id: *network_id,
            conversation_id,
            prior_epoch: slot.position.prior_epoch,
            prior_state_id: slot.position.prior_state_id,
            candidate_sequence: slot.position.candidate_sequence,
            predecessor_record_id: slot.position.predecessor_record_id,
        };
        let mut ledger = QuorumLedger::new();
        let requests = index.terminal_requests.get(&slot.candidate_id);
        for (terminal, votes) in requests
            .into_iter()
            .flatten()
            .filter_map(candidate_terminal)
        {
            let tbs = vote_tbs(&vote_slot, slot.candidate_id, terminal);
            replay_votes(&mut ledger, terminal, votes, |ledger, vote| {
                ledger.record(&policy, &rosters, &tbs, vote)
            });
        }
        conversation.vote_ledgers.insert(slot.candidate_id, ledger);
    }
    let (
        Some(attempt),
        Phase::Reinit {
            old_reinit_state_id,
        },
    ) = (log.reinit_attempt(), log.phase())
    else {
        return;
    };
    let reinit_slot = ReinitVoteSlot {
        network_id: *network_id,
        old_conversation_id: conversation_id,
        old_reinit_state_id,
        attempt_sequence: attempt.attempt_sequence,
        predecessor_record_id: attempt.predecessor_record_id,
    };
    let mut ledger = QuorumLedger::new();
    let requests = index.terminal_requests.get(&attempt.attempt_id);
    for (terminal, votes) in requests.into_iter().flatten().filter_map(attempt_terminal) {
        let tbs = reinit_vote_tbs(&reinit_slot, attempt.attempt_id, terminal);
        replay_votes(&mut ledger, terminal, votes, |ledger, vote| {
            ledger.record_reinit(&policy, &rosters, &tbs, vote)
        });
    }
    conversation.vote_ledgers.insert(attempt.attempt_id, ledger);
}

/// Replays one retained vote vector with the live counting rule: a vote
/// standing for the other terminal is skipped, and a vote that no longer
/// verifies (a roster moved on) is dropped rather than trusted.
fn replay_votes(
    ledger: &mut QuorumLedger,
    terminal: Terminal,
    votes: &[IrcFinalityVote],
    mut record: impl FnMut(&mut QuorumLedger, &IrcFinalityVote) -> Result<(), E2eeError>,
) {
    for vote in votes {
        let signer = (vote.signer_root_fingerprint, vote.signer_device_id);
        let conflicting = ledger
            .votes()
            .any(|(recorded, stood)| *recorded == signer && *stood != terminal);
        if conflicting {
            continue;
        }
        let _ = record(ledger, vote);
    }
}

fn activates_bootstrap(state: &CompanionState, record: &RecordRow) -> bool {
    if record.record_kind != FINALIZATION_RECORD {
        return false;
    }
    let decoded: Option<IrcSequencerRecord> = decode_object(
        state,
        &record.record_object_id,
        IrcWireObjectKind::SequencerRecord,
        MAX_SEQUENCER_RECORD_OBJECT,
    );
    match decoded {
        Some(IrcSequencerRecord::Finalization(certificate)) => {
            certificate
                .tbs
                .request
                .proof
                .authorization
                .tbs
                .authorization_rule
                == IrcCommitAuthorizationRule::BootstrapActivation
        }
        _ => false,
    }
}

fn leaf_of(device_id: &[u8; 16]) -> Option<u32> {
    device_id
        .get(12..)
        .and_then(|tail| <[u8; 4]>::try_from(tail).ok())
        .map(u32::from_be_bytes)
}

fn fill_proofs(conversation: &mut ConversationState, proofs: &[(ProofKeyParts, [u8; 32])]) {
    let conversation_id = conversation.binding;
    let _ = conversation_id;
    for (parts, object_id) in proofs {
        match parts.role {
            ProofRole::Approval => {
                conversation
                    .approvals
                    .entry(parts.subject_id)
                    .or_default()
                    .insert((parts.root_fingerprint, parts.device_id), *object_id);
            }
            ProofRole::Ack => {
                if let Some(leaf) = leaf_of(&parts.device_id) {
                    conversation
                        .acks
                        .entry(parts.subject_id)
                        .or_default()
                        .insert(leaf, *object_id);
                }
            }
            ProofRole::Vote => {}
        }
    }
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one route is rebuilt from its row, its state object, and its binding package in one pass so the entry, log, lifecycle, and conversation facts agree
fn restore_route(
    state: &mut CompanionState,
    network_id: &[u8; 32],
    index: &ObjectIndex,
    rows: &SequencerRows,
    conversation_id: [u8; 32],
    row: &RouteRow,
) -> Option<()> {
    let route: IrcFederationRouteState = decode_body(
        &row.route_state,
        IrcWireObjectKind::FederationState,
        MAX_FEDERATION_CONTROL_OBJECT,
    )?;
    let (binding_object_id, package) = index.bindings.get(&row.binding_id)?;
    let target = route_target(&route)?;
    let recovery = if row.recovery_gate {
        (RecoveryState::Pending, RecoveryGate::Pending)
    } else {
        (RecoveryState::Normal, RecoveryGate::Normal)
    };
    let tbs = &package.binding.tbs;
    let entry = RouteEntry {
        conversation_id: ConversationId(conversation_id),
        target,
        lock: SemanticLockId(row.lock_id),
        incarnation: u64::from(row.predecessor_close_id.is_some()),
        binding_id: row.binding_id,
        binding_generation: tbs.binding_generation,
        lifecycle: route_lifecycle(row),
        recovery: recovery.0,
    };
    let records = rows.records_of(conversation_id);
    let candidate = rows
        .candidates
        .get(&(conversation_id, route.finalized_epoch));
    let log = restore_log(conversation_id, row, &route, &records, candidate);
    let activated = records
        .values()
        .any(|record| activates_bootstrap(state, record));
    let lifecycle = Lifecycle::restore(recovery.1, !activated, false);
    let direct = matches!(target, RouteTarget::Direct(_));
    let mut conversation = ConversationState {
        binding_object_id: *binding_object_id,
        binding: row.binding_id,
        context_core_id: tbs.context_core_id,
        cipher_suite: tbs.cipher_suite,
        group_id: tbs.group_id.as_slice().to_vec(),
        route_binding: route.route_binding,
        lock_id: route.semantic_route_lock_id,
        channel_name_hash: route.canonical_channel_name_hash,
        direct_accounts: direct.then(|| direct_accounts(&route)).flatten(),
        records: records
            .iter()
            .map(|(sequence, record)| (*sequence, record.record_object_id))
            .collect(),
        proofs: index
            .proofs
            .get(&conversation_id)
            .cloned()
            .unwrap_or_default(),
        route_object_id: *agenc_ircd_e2ee::ObjectId::compute(&row.route_state).as_bytes(),
        stored_bytes: row.stored_bytes,
        principal_accounts: principal_accounts(package),
        initial_policy_id: tbs.initial_policy_id,
        required_operational_policy_id: tbs.required_operational_policy_id,
        current_policy_id: current_policy(state, &records, tbs.initial_policy_id),
        predecessor_close_id: row.predecessor_close_id,
        ..ConversationState::default()
    };
    restore_policies(
        state,
        network_id,
        index,
        rows,
        &mut conversation,
        conversation_id,
    );
    restore_ledgers(state, network_id, index, &mut conversation, &log);
    let proofs: Vec<(ProofKeyParts, [u8; 32])> = rows
        .proofs
        .iter()
        .filter(|(parts, _)| parts.conversation_id == conversation_id)
        .cloned()
        .collect();
    fill_proofs(&mut conversation, &proofs);
    state.routes.restore_entry(entry);
    state.logs.insert(conversation_id, log);
    state.lifecycles.insert(conversation_id, lifecycle);
    state.conversations.insert(conversation_id, conversation);
    Some(())
}
