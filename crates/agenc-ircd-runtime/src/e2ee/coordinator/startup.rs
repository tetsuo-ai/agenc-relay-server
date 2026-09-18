//! Reload of the companion state from its durable rows at coordinator
//! startup (companion Section 18.1). The rows are collected while the base
//! loader pages the E2EE tables, then rebuilt in dependency order: retained
//! objects, the directory (root chains re-verified, rosters and
//! capabilities re-verified without their retired predecessors), the
//! KeyPackage stock and claims, mailboxes, replay rows, and finally every
//! route with its sequencer log, lifecycle, and per-conversation facts,
//! followed by the scoped delivery streams and unfinished barriers.
//!
//! Not restored, by design or deferral: route reservations (short-lived and
//! not reconstructible without the owner's Account ID), companion origins
//! (edges re-declare them), and the context digest carried on `BIND`.

use std::collections::BTreeMap;

mod objects;

#[cfg(test)]
#[path = "tests/startup_objects.rs"]
mod object_tests;

use agenc_ircd_crypto::SemanticHashDomain;
use agenc_ircd_domain::e2ee::directory::{
    AccountEntry, Attachment, CapabilityHead, Challenge, ClaimOutcome, ClaimParameters, Package,
    RootHead, RosterHead,
};
use agenc_ircd_domain::e2ee::lifecycle::{Lifecycle, RecoveryGate};
use agenc_ircd_domain::e2ee::mailbox::{Grant, Item, MailboxKind, Target};
use agenc_ircd_domain::e2ee::sequencer_log::{
    AttemptSlot, CandidatePosition, CandidateSlot, Head, Phase, SequencerLog,
};
use agenc_ircd_domain::e2ee::{
    ConversationId, DirectPair, RecoveryState, RouteEntry, RouteLifecycle, RouteTarget,
    SemanticLockId,
};
use agenc_ircd_e2ee::E2eeError;
use agenc_ircd_e2ee::envelope::{RouteExpectation, verify_commit_object};
use agenc_ircd_e2ee::finality::{
    QuorumLedger, ReinitVoteSlot, Terminal, VoteSlot, reinit_vote_tbs, vote_tbs,
};
use agenc_ircd_e2ee::identity::{
    VerifiedRoot, VerifiedRoster, restore_capabilities, restore_roster, verify_root_identity,
};
use agenc_ircd_e2ee::limits::{
    MAX_ABORT_OBJECT, MAX_BINDING_OBJECT, MAX_CAPABILITY_OBJECT, MAX_FEDERATION_CONTROL_OBJECT,
    MAX_FINALIZATION_OBJECT, MAX_IDENTITY_OBJECT, MAX_LIVE_OBJECT, MAX_POLICY_OBJECT,
    MAX_REINIT_OBJECT, MAX_ROSTER_OBJECT, MAX_SEQUENCER_RECORD_OBJECT,
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
use agenc_ircd_storage::e2ee_records::origin::OriginSequenceRow;
use agenc_ircd_storage::e2ee_records::{
    ATTACH_ROW_KIND, AttachRow, DELIVERY_ROW_KIND, DIRECTORY_ROW_KIND, DirectoryRow,
    MAILBOX_ROW_KIND, MailboxKind as RowMailboxKind, MailboxRow, PACKAGE_ROW_KIND, PackageRow,
    PackageState, ProofKeyParts, ProofRole, REPLAY_ROW_KIND, ROUTE_ROW_KIND, ReplayRow,
    RouteLifecycle as RowLifecycle, RouteRow, SEQUENCER_ROW_KIND, SequencerRow,
};
use agenc_ircd_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_ircd_types::{AccountId, ChannelInstanceId};

use super::{
    CompanionCoordinator, CompanionOriginKey, CompanionState, ConversationState, LockEntry,
    RetainedPolicy,
};

const CANDIDATE_RECORD: u16 = 1;
const FINALIZATION_RECORD: u16 = 2;
const REINIT_ATTEMPT_RECORD: u16 = 4;
const REINIT_ACTIVATION_RECORD: u16 = 5;
const REINIT_ABORT_RECORD: u16 = 6;

/// One sequencer record position.
struct RecordRow {
    record_object_id: [u8; 32],
    /// The record's semantic identifier.
    record_id: [u8; 32],
    record_kind: u16,
    /// Whether the record certifies a terminal.
    terminal: bool,
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
    backing: Option<crate::budget::BackingReservationPort>,
    objects: objects::Restore,
    gates: super::recovery_gates::Gates,
    routes: BTreeMap<[u8; 32], RouteRow>,
    records: BTreeMap<([u8; 32], u64), RecordRow>,
    candidates: BTreeMap<([u8; 32], u64), CandidateRow>,
    proofs: Vec<(ProofKeyParts, [u8; 32])>,
    policies: BTreeMap<([u8; 32], [u8; 32]), PolicyRow>,
    memberships: super::membership_restore::Rows,
    directory: Vec<(StoredKey, DirectoryRow)>,
    packages: Vec<(StoredKey, PackageRow)>,
    attachments: Vec<(StoredKey, AttachRow)>,
    mailbox: Vec<(StoredKey, MailboxRow)>,
    mailbox_sequences: super::mailbox_restore::Restore,
    replays: Vec<(StoredKey, ReplayRow)>,
    origin_sequences: Vec<(StoredKey, OriginSequenceRow)>,
    pub(super) delivery: super::delivery_owner::restore::Restore,
    owners: super::owners::Rebuild,
    object_expiry: Option<super::object_expiry::Progress>,
    recovery: super::recovery_lineage::Recoveries,
    key_set: Option<agenc_ircd_storage::e2ee_records::KeySetRow>,
    history: BTreeMap<[u8; 32], agenc_ircd_storage::e2ee_records::SequencerHistoryRow>,
}

impl Restore {
    pub(super) fn set_backing(&mut self, backing: crate::budget::BackingReservationPort) {
        self.delivery.set_backing(backing.clone());
        self.backing = Some(backing);
    }

    /// Collects one row of an E2EE table.
    pub(super) fn admit(&mut self, table: TableId, key: &StoredKey, value: &PersistentRecordValue) {
        match table {
            TableId::E2eeObject => self.admit_object(key, value),
            TableId::E2eeState => self.admit_state(key, value),
            _ => {}
        }
    }

    fn admit_object(&mut self, key: &StoredKey, value: &PersistentRecordValue) {
        self.objects.admit(key, value);
        self.owners.admit_object(key, value);
    }

    fn admit_state(&mut self, key: &StoredKey, value: &PersistentRecordValue) {
        if self.objects.selected() {
            self.objects.poison();
            return;
        }
        self.owners.admit_row(key, value);
        let body = value.body();
        match value.record_kind() {
            agenc_ircd_storage::e2ee_records::RECOVERY_GATE_KIND => self.objects.poison(),
            ROUTE_ROW_KIND => {
                if let (Ok(id), Ok(row)) = (RouteRow::parse_key(key), RouteRow::decode(body)) {
                    self.routes.insert(id, row);
                }
            }
            SEQUENCER_ROW_KIND => self.admit_sequencer(key, body),
            DIRECTORY_ROW_KIND => push(&mut self.directory, key, DirectoryRow::decode(body)),
            PACKAGE_ROW_KIND => push(&mut self.packages, key, PackageRow::decode(body)),
            ATTACH_ROW_KIND => push(&mut self.attachments, key, AttachRow::decode(body)),
            MAILBOX_ROW_KIND => {
                if let Some(row) = self.mailbox_sequences.admit_mailbox(key, body) {
                    self.mailbox.push((key.clone(), row));
                }
            }
            agenc_ircd_storage::e2ee_records::MAILBOX_SEQUENCE_ROW_KIND => {
                self.mailbox_sequences.admit(key, body);
            }
            agenc_ircd_storage::e2ee_records::EXPIRY_PROGRESS_ROW_KIND => {
                self.admit_expiry_progress(body);
            }
            REPLAY_ROW_KIND => {
                if key
                    .as_bytes()
                    .starts_with(agenc_ircd_storage::e2ee_records::prefix::ORIGIN_SEQUENCE)
                {
                    push(
                        &mut self.origin_sequences,
                        key,
                        OriginSequenceRow::decode(body),
                    );
                } else {
                    push(&mut self.replays, key, ReplayRow::decode(body));
                }
            }
            DELIVERY_ROW_KIND => self.objects.poison(),
            agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND => {
                self.delivery.admit_owner(key, value);
            }
            agenc_ircd_storage::e2ee_records::RECOVERY_SUBMISSION_ROW_KIND => {
                use agenc_ircd_storage::e2ee_records::RecoverySubmissionRow;
                if let (Ok((conversation, submission)), Ok(row)) = (
                    RecoverySubmissionRow::parse_key(key),
                    RecoverySubmissionRow::decode(body),
                ) {
                    self.recovery
                        .insert_submission(conversation, submission, row);
                }
            }
            agenc_ircd_storage::e2ee_records::KEYSET_ROW_KIND
            | agenc_ircd_storage::e2ee_records::SEQUENCER_HISTORY_ROW_KIND => {
                self.admit_signer_row(value.record_kind(), key, body);
            }
            agenc_ircd_storage::e2ee_records::RECOVERY_RECORD_ROW_KIND => {
                use agenc_ircd_storage::e2ee_records::RecoveryRecordRow;
                if let (Ok((conversation, sequence)), Ok(row)) = (
                    RecoveryRecordRow::parse_key(key),
                    RecoveryRecordRow::decode(body),
                ) {
                    self.recovery.insert_record(conversation, sequence, row);
                }
            }
            _ => {}
        }
    }

    /// The collector's durable continuation; a malformed row poisons the
    /// reload rather than restarting the sweep at an invented position.
    fn admit_expiry_progress(&mut self, body: &[u8]) {
        use agenc_ircd_storage::e2ee_records::ObjectExpiryProgressRow;
        match ObjectExpiryProgressRow::decode(body) {
            Ok(row) => self.object_expiry = Some(super::object_expiry::Progress::from_row(row)),
            Err(_) => self.objects.poison(),
        }
    }

    pub(super) fn admit_gate(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
        backing: &crate::budget::BackingReservationPort,
    ) {
        if self.objects.selected() || self.gates.admit(key, value, backing).is_err() {
            self.objects.poison();
        }
    }

    /// The accepted key set and the credential history rows (companion
    /// 9.2.1); a malformed row poisons the reload.
    fn admit_signer_row(&mut self, kind: u16, key: &StoredKey, body: &[u8]) {
        use agenc_ircd_storage::e2ee_records::{KeySetRow, SequencerHistoryRow};
        if kind == agenc_ircd_storage::e2ee_records::KEYSET_ROW_KIND {
            match KeySetRow::decode(body) {
                Ok(row) => self.key_set = Some(row),
                Err(_) => self.objects.poison(),
            }
            return;
        }
        match (
            SequencerHistoryRow::parse_key(key),
            SequencerHistoryRow::decode(body),
        ) {
            (Ok(id), Ok(row)) => {
                self.history.insert(id, row);
            }
            _ => self.objects.poison(),
        }
    }

    fn admit_sequencer(&mut self, key: &StoredKey, body: &[u8]) {
        match SequencerRow::decode(body) {
            Ok(SequencerRow::Record {
                record_object_id,
                record_id,
                record_kind,
                terminal,
                predecessor_record_id,
                ..
            }) => self.admit_record(
                key,
                RecordRow {
                    record_object_id,
                    record_id,
                    record_kind,
                    terminal,
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
            Ok(SequencerRow::Membership {
                object_id,
                epoch,
                device_id,
                disposition,
            }) => self
                .memberships
                .admit(key, object_id, epoch, device_id, disposition),
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
    /// Retained roster snapshots by signing root fingerprint.
    rosters: BTreeMap<[u8; 32], Vec<IrcDeviceRoster>>,
    /// Retained terminal request objects by conversation and terminal
    /// identifier, certified or not; a route keeps only the certified ones.
    proofs: BTreeMap<[u8; 32], BTreeMap<[u8; 32], [u8; 32]>>,
    /// Retained terminal requests by object identifier.
    terminal_requests: BTreeMap<[u8; 32], TerminalRequest>,
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
                self.terminal_requests.insert(
                    object_id,
                    TerminalRequest::Finalize(finalization_id, request.votes.as_slice().to_vec()),
                );
            }
            IrcWireObjectKind::AbortRequest => self.index_abort(object_id, bytes),
            IrcWireObjectKind::ReinitActivationRequest => self.index_activation(object_id, bytes),
            IrcWireObjectKind::ReinitAbortRequest => self.index_attempt_abort(object_id, bytes),
            IrcWireObjectKind::Policy => {
                if let Some(policy) = decode_body::<IrcPolicy>(bytes, kind, MAX_POLICY_OBJECT) {
                    self.policies.insert(object_id, (policy, bytes.len()));
                }
            }
            IrcWireObjectKind::DeviceRoster => {
                if let Some(roster) = decode_body::<IrcDeviceRoster>(bytes, kind, MAX_ROSTER_OBJECT)
                {
                    self.rosters
                        .entry(roster.tbs.root_fingerprint)
                        .or_default()
                        .push(roster);
                }
            }
            _ => {}
        }
    }
}

impl ObjectIndex {
    fn index_proof(&mut self, conversation: [u8; 32], terminal_id: [u8; 32], object_id: [u8; 32]) {
        self.proofs
            .entry(conversation)
            .or_default()
            .insert(terminal_id, object_id);
    }

    /// The retained request of every terminal `records` certified. A request
    /// the sequencer never certified, such as one still below quorum, names
    /// no terminal of the conversation (companion 12.4).
    fn certified_proofs(
        &self,
        conversation: &[u8; 32],
        records: &BTreeMap<u64, &RecordRow>,
    ) -> BTreeMap<[u8; 32], [u8; 32]> {
        let Some(retained) = self.proofs.get(conversation) else {
            return BTreeMap::new();
        };
        records
            .values()
            .filter(|record| record.terminal)
            .filter_map(|record| Some((record.record_id, *retained.get(&record.record_id)?)))
            .collect()
    }

    fn index_abort(&mut self, object_id: [u8; 32], bytes: &[u8]) {
        let kind = IrcWireObjectKind::AbortRequest;
        let Some(request) = decode_body::<IrcAbortRequest>(bytes, kind, MAX_ABORT_OBJECT) else {
            return;
        };
        let Ok(abort_id) = CompanionCoordinator::id_of(SemanticHashDomain::AbortId, &request.core)
        else {
            return;
        };
        self.index_proof(request.core.conversation_id, abort_id, object_id);
        self.terminal_requests.insert(
            object_id,
            TerminalRequest::Abort(
                abort_id,
                u16::from(request.core.reason.value()),
                request.votes.as_slice().to_vec(),
            ),
        );
    }

    fn index_activation(&mut self, object_id: [u8; 32], bytes: &[u8]) {
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
        self.index_proof(request.core.old_conversation_id, activation_id, object_id);
        self.terminal_requests.insert(
            object_id,
            TerminalRequest::Activate(activation_id, request.votes.as_slice().to_vec()),
        );
    }

    fn index_attempt_abort(&mut self, object_id: [u8; 32], bytes: &[u8]) {
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
        self.index_proof(request.core.old_conversation_id, abort_id, object_id);
        self.terminal_requests.insert(
            object_id,
            TerminalRequest::AbortAttempt(
                abort_id,
                request.core.reason_code,
                request.votes.as_slice().to_vec(),
            ),
        );
    }
}

/// Rebuilds the companion state from the collected rows.
pub(super) fn rebuild(
    coordinator: &mut CompanionCoordinator,
    restore: Restore,
) -> Result<(), super::CompanionFault> {
    restore.gates.validate(
        &restore.routes,
        coordinator
            .delivery_identity
            .map(super::delivery_owner::LocalIdentity::recovery_epoch),
    )?;
    let network_id = coordinator.network_id;
    let state = &mut coordinator.state;
    restore.objects.apply(state)?;
    restore_directory(state, &network_id, restore.directory, restore.attachments);
    restore_packages(state, restore.packages);
    restore_mailboxes(state, restore.mailbox)?;
    restore.mailbox_sequences.apply(&mut state.mailboxes)?;
    restore_replays(state, restore.replays, restore.backing.as_ref())?;
    restore_origin_sequences(state, restore.origin_sequences);
    let index = ObjectIndex::build(state);
    let rows = SequencerRows {
        records: restore.records,
        candidates: restore.candidates,
        proofs: restore.proofs,
        policies: restore.policies,
        memberships: restore.memberships,
    };
    for (conversation_id, row) in restore.routes {
        restore_route(state, &network_id, &index, &rows, conversation_id, &row);
    }
    restore_successors(state, &index)?;
    restore.gates.install(state)?;
    coordinator.owner_reconstruction = restore.owners.finish(state);
    state.object_expiry = restore.object_expiry.unwrap_or_default();
    state.recovery = restore.recovery;
    coordinator.signer_history = restore.history.clone();
    // A coordinator without an installed key set (no signer configured)
    // has no signer ownership to reconcile.
    coordinator.signer_startup = coordinator.key_set().is_some().then(|| {
        Box::new(signer_proposal(
            coordinator,
            restore.key_set,
            restore.history,
        ))
    });
    restore.delivery.apply(coordinator)
}

/// What the startup signer reconciliation compares: the durable set and
/// history, the credential every `normal` live route pins, and the
/// credentials the unfinished receipts name (companion 9.2.1).
fn signer_proposal(
    coordinator: &CompanionCoordinator,
    accepted: Option<agenc_ircd_storage::e2ee_records::KeySetRow>,
    history: BTreeMap<[u8; 32], agenc_ircd_storage::e2ee_records::SequencerHistoryRow>,
) -> super::signer_startup::Proposal {
    use agenc_ircd_domain::e2ee::{RecoveryState, RouteLifecycle};
    let state = &coordinator.state;
    let mut pins = BTreeMap::new();
    let mut receipts = std::collections::BTreeSet::new();
    for (conversation_id, conversation) in &state.conversations {
        let live = state
            .routes
            .route(&ConversationId(*conversation_id))
            .is_some_and(|route| {
                route.recovery == RecoveryState::Normal
                    && !matches!(route.lifecycle, RouteLifecycle::Tombstone { .. })
            });
        if !live {
            continue;
        }
        pins.insert(*conversation_id, conversation.sequencer_credential_id);
        if let Some(credential) = open_receipt_credential(coordinator, conversation_id) {
            receipts.insert(credential);
        }
    }
    super::signer_startup::Proposal {
        accepted,
        history,
        pins,
        receipts,
    }
}

/// The credential the unfinished candidate or ReInit-attempt receipt of a
/// conversation names: the head record is that receipt while a candidate
/// or an attempt is open.
fn open_receipt_credential(
    coordinator: &CompanionCoordinator,
    conversation_id: &[u8; 32],
) -> Option<[u8; 32]> {
    let log = coordinator.state.logs.get(conversation_id)?;
    if !log.has_candidate() && log.reinit_attempt().is_none() {
        return None;
    }
    let head = log.head();
    let object_id = coordinator
        .state
        .conversations
        .get(conversation_id)?
        .records
        .get(&head.sequence)?;
    let bytes = coordinator.state.objects.get(object_id)?;
    let mut budget = DecodeBudget::new(MAX_FEDERATION_CONTROL_OBJECT, 1 << 16);
    let object =
        IrcWireObject::decode_kind(bytes, Some(IrcWireObjectKind::SequencerRecord), &mut budget)
            .ok()?;
    match IrcSequencerRecord::decode_exact(object.body(), &mut budget).ok()? {
        IrcSequencerRecord::Candidate(receipt) => Some(receipt.tbs.sequencer_key_id),
        IrcSequencerRecord::ReinitAttempt(receipt) => Some(receipt.tbs.sequencer_key_id),
        _ => None,
    }
}

/// Activation creates a successor anchor before that conversation has its
/// own route. Restore these anchors after every existing route has loaded.
fn restore_successors(
    state: &mut CompanionState,
    index: &ObjectIndex,
) -> Result<(), super::CompanionFault> {
    let mut verified = std::collections::BTreeSet::new();
    let mut successors: Vec<_> = state
        .logs
        .iter()
        .filter_map(|(old, log)| match log.phase() {
            Phase::Migrated {
                activation_id,
                new_conversation_id,
            } => Some((*old, new_conversation_id, activation_id)),
            _ => None,
        })
        .collect();
    successors.sort_unstable_by_key(|(_, target, _)| *target);
    if successors
        .windows(2)
        .any(|pair| matches!(pair, [left, right] if left.1 == right.1))
    {
        return Err(super::CompanionFault::Storage);
    }
    // Keep the original predecessor ordering after the allocation-free check.
    successors.sort_unstable_by_key(|(old, _, _)| *old);
    for (old, conversation_id, activation_id) in successors {
        if state.conversations.contains_key(&conversation_id) {
            restore_successor_binding(state, old, conversation_id)
                .ok_or(super::CompanionFault::Storage)?;
            verified.insert(conversation_id);
        } else {
            if state.logs.contains_key(&conversation_id)
                || state.lifecycles.contains_key(&conversation_id)
                || state
                    .routes
                    .route(&ConversationId(conversation_id))
                    .is_some()
            {
                return Err(super::CompanionFault::Storage);
            }
            state.logs.insert(
                conversation_id,
                SequencerLog::from_activation(conversation_id, activation_id),
            );
            state
                .lifecycles
                .insert(conversation_id, Lifecycle::successor());
        }
    }
    discard_unanchored_successors(state, index, &verified);
    Ok(())
}

/// A missing predecessor or activation invalidates every dependent successor.
fn discard_unanchored_successors(
    state: &mut CompanionState,
    index: &ObjectIndex,
    verified: &std::collections::BTreeSet<[u8; 32]>,
) {
    let mut successors: Vec<_> = state
        .conversations
        .iter()
        .filter_map(|(id, value)| {
            let (_, package) = index.bindings.get(&value.binding)?;
            let tbs = &package.binding.tbs;
            if tbs.binding_generation == 0 {
                return None;
            }
            let predecessor = index
                .bindings
                .get(&tbs.previous_binding_id)
                .map(|(_, package)| package.binding.tbs.conversation_id);
            Some((tbs.binding_generation, *id, predecessor))
        })
        .collect();
    successors.sort_by_key(|(generation, _, _)| *generation);
    for (_, id, predecessor) in successors {
        if predecessor == Some(id) {
            continue;
        }
        if !verified.contains(&id)
            || predecessor.is_none_or(|old| !state.conversations.contains_key(&old))
        {
            discard_route(state, id);
        }
    }
}

fn discard_route(state: &mut CompanionState, conversation: [u8; 32]) {
    state
        .routes
        .remove_projection(&ConversationId(conversation));
    state.conversations.remove(&conversation);
    state.logs.remove(&conversation);
    state.lifecycles.remove(&conversation);
}

/// Rechecks activation-bound metadata and selects the successor's route indexes
/// after all route rows have loaded, independent of conversation-ID ordering.
fn restore_successor_binding(
    state: &mut CompanionState,
    old: [u8; 32],
    new: [u8; 32],
) -> Option<()> {
    use super::ops::route_successor;
    let certificate = route_successor::activation(state, &old).ok()?;
    let context_digest = certificate.tbs.request.attempt.tbs.target_context_digest;
    let package = route_successor::binding(state, &new).ok()?;
    let activation_id = route_successor::verify(
        state,
        &certificate.tbs.network_id,
        &old,
        &package,
        &context_digest,
    )
    .ok()?;
    let log = state.logs.get(&new)?;
    if log.accepted_epoch() < 1
        || (!log.head().recorded
            && (log.accepted_state_id() != &activation_id
                || log.head().record_id != activation_id
                || log.accepted_epoch() != 1))
    {
        return None;
    }
    state
        .routes
        .select_restored_successor(ConversationId(old), ConversationId(new))
        .ok()?;
    let lifecycle = state.lifecycles.get(&new)?;
    state.lifecycles.insert(
        new,
        Lifecycle::restore(lifecycle.gate(), false, lifecycle.removal_pending()),
    );
    state.conversations.get_mut(&new)?.context_digest = context_digest;
    Some(())
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
    super::roster_snapshots::rebuild(state);
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
    grants: Vec<(ItemSlot, [u8; 32], Grant)>,
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
            grant,
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
                grant: grant.map(|grant| Grant {
                    token: grant.token,
                    session_generation: grant.session_generation,
                    expires_at: grant.expires_at,
                }),
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
            object_id,
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
            object_id,
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

fn restore_mailboxes(
    state: &mut CompanionState,
    rows: Vec<(StoredKey, MailboxRow)>,
) -> Result<(), super::CompanionFault> {
    let mut sorted = MailboxRows::default();
    for (key, row) in rows {
        sorted.admit(&key, row);
    }
    sorted.grants.sort_unstable_by_key(|(slot, _, _)| *slot);
    validate_mailbox_grants(&sorted)?;
    for ((target, kind, sequence), item) in sorted.items {
        state.mailboxes.restore_item(target, kind, sequence, item);
    }
    for (target, token, object_id, retain_until) in sorted.acks {
        state
            .mailboxes
            .restore_ack(target, token, object_id, retain_until);
    }
    Ok(())
}

fn validate_mailbox_grants(rows: &MailboxRows) -> Result<(), super::CompanionFault> {
    if rows.grants.windows(2).any(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(left, right)| left.0 == right.0)
    }) {
        return Err(super::CompanionFault::Storage);
    }
    for (slot, object, grant) in &rows.grants {
        let valid = rows
            .items
            .get(slot)
            .is_some_and(|item| item.object_id == *object && item.grant == Some(*grant));
        if !valid {
            return Err(super::CompanionFault::Storage);
        }
    }
    for (slot, item) in &rows.items {
        if item.grant.is_some()
            && rows
                .grants
                .binary_search_by_key(slot, |(slot, _, _)| *slot)
                .is_err()
        {
            return Err(super::CompanionFault::Storage);
        }
    }
    Ok(())
}

fn restore_origin_sequences(state: &mut CompanionState, rows: Vec<(StoredKey, OriginSequenceRow)>) {
    for (key, row) in rows {
        let Ok(key) = OriginSequenceRow::parse_key(&key) else {
            continue;
        };
        state.origin_sequences.insert(
            CompanionOriginKey {
                home_server_id: key.home_server_id,
                server_incarnation: key.server_incarnation,
                origin_id: key.origin_id,
            },
            row,
        );
    }
}

fn restore_replays(
    state: &mut CompanionState,
    rows: Vec<(StoredKey, ReplayRow)>,
    backing: Option<&crate::budget::BackingReservationPort>,
) -> Result<(), super::CompanionFault> {
    let mut prepared = super::results::Store::default();
    for (key, row) in &rows {
        if ReplayRow::parse_key(key).is_err() {
            continue;
        }
        let result = row
            .result_object_id
            .and_then(|object_id| state.objects.get(&object_id));
        if let Some(result) = result {
            super::results::Prepared::capture(
                result,
                row.response_object_ids.iter().copied(),
                backing.ok_or(super::CompanionFault::Ceiling)?,
            )?
            .apply(&mut prepared, row.request_object_id);
        }
    }
    for (key, row) in rows {
        let Ok(parts) = ReplayRow::parse_key(&key) else {
            continue;
        };
        state.replays.insert(parts, row);
    }
    state.results.append(&mut prepared);
    Ok(())
}

// ---------------------------------------------------------------------------
// Routes.

/// The sequencer rows of every conversation.
struct SequencerRows {
    records: BTreeMap<([u8; 32], u64), RecordRow>,
    candidates: BTreeMap<([u8; 32], u64), CandidateRow>,
    proofs: Vec<(ProofKeyParts, [u8; 32])>,
    policies: BTreeMap<([u8; 32], [u8; 32]), PolicyRow>,
    memberships: super::membership_restore::Rows,
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

/// The phase and attempt position recovered from the durable head record.
struct RestoredLogPhase {
    phase: Phase,
    attempt: Option<AttemptSlot>,
    next_attempt_sequence: u32,
}

/// A ReInit receipt or terminal at the durable head determines whether an
/// attempt is still open, another attempt may follow, or the group migrated.
// agenc-review: focus owner=runtime reviewed=2026-09-04 reason=the head receipt and terminal alternatives restore the phase together with exact durable row identity checks
fn restore_log_phase(
    state: &CompanionState,
    conversation_id: [u8; 32],
    row: &RouteRow,
    records: &BTreeMap<u64, &RecordRow>,
) -> Option<RestoredLogPhase> {
    let mut restored = RestoredLogPhase {
        phase: row
            .close_id
            .map_or(Phase::Open, |close_id| Phase::Closed { close_id }),
        attempt: None,
        next_attempt_sequence: 0,
    };
    let Some(record) = records.get(&row.route_sequence).filter(|record| {
        matches!(
            record.record_kind,
            REINIT_ATTEMPT_RECORD | REINIT_ACTIVATION_RECORD | REINIT_ABORT_RECORD
        )
    }) else {
        return Some(restored);
    };
    let decoded: IrcSequencerRecord = decode_object(
        state,
        &record.record_object_id,
        IrcWireObjectKind::SequencerRecord,
        MAX_SEQUENCER_RECORD_OBJECT,
    )?;
    match decoded {
        IrcSequencerRecord::ReinitAttempt(receipt) => {
            let tbs = receipt.tbs;
            if record.record_kind != REINIT_ATTEMPT_RECORD
                || tbs.old_conversation_id != conversation_id
                || tbs.predecessor_record_id != record.predecessor_record_id
                || tbs.old_reinit_state_id != row.accepted_state_id
                || tbs.reinit_attempt_id != row.sequencer_head_id
                || tbs.route_sequence != row.route_sequence
            {
                return None;
            }
            restored.phase = Phase::Reinit {
                old_reinit_state_id: tbs.old_reinit_state_id,
            };
            restored.attempt = Some(AttemptSlot {
                attempt_id: tbs.reinit_attempt_id,
                route_sequence: tbs.route_sequence,
                attempt_sequence: tbs.attempt_sequence,
                predecessor_record_id: tbs.predecessor_record_id,
            });
            restored.next_attempt_sequence = tbs.attempt_sequence;
        }
        IrcSequencerRecord::ReinitAbort(certificate) => {
            let tbs = certificate.tbs;
            if record.record_kind != REINIT_ABORT_RECORD
                || tbs.old_conversation_id != conversation_id
                || tbs.predecessor_record_id != record.predecessor_record_id
                || tbs.request.core.old_reinit_state_id != row.accepted_state_id
                || tbs.reinit_abort_id != row.sequencer_head_id
                || tbs.route_sequence != row.route_sequence
            {
                return None;
            }
            restored.phase = Phase::Reinit {
                old_reinit_state_id: tbs.request.core.old_reinit_state_id,
            };
            restored.next_attempt_sequence = tbs.request.core.attempt_sequence.checked_add(1)?;
        }
        IrcSequencerRecord::ReinitActivation(certificate) => {
            let tbs = certificate.tbs;
            if record.record_kind != REINIT_ACTIVATION_RECORD
                || tbs.old_conversation_id != conversation_id
                || tbs.predecessor_record_id != record.predecessor_record_id
                || tbs.request.core.old_reinit_state_id != row.accepted_state_id
                || tbs.reinit_activation_id != row.sequencer_head_id
                || tbs.route_sequence != row.route_sequence
            {
                return None;
            }
            restored.phase = Phase::Migrated {
                activation_id: tbs.reinit_activation_id,
                new_conversation_id: tbs.request.core.new_conversation_id,
            };
        }
        _ => return None,
    }
    Some(restored)
}

/// Restores the log head, epoch position, and ReInit phase from retained rows.
fn restore_log(
    state: &CompanionState,
    conversation_id: [u8; 32],
    row: &RouteRow,
    route: &IrcFederationRouteState,
    records: &BTreeMap<u64, &RecordRow>,
    candidate: Option<&CandidateRow>,
) -> Option<SequencerLog> {
    let head = Head {
        sequence: row.route_sequence,
        record_id: row.sequencer_head_id,
        recorded: !records.is_empty() || row.close_id.is_some(),
    };
    let restored = restore_log_phase(state, conversation_id, row, records)?;
    let mut log = SequencerLog::restore(
        conversation_id,
        head,
        row.accepted_state_id,
        route.finalized_epoch,
        restored.phase,
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
    if matches!(restored.phase, Phase::Reinit { .. }) {
        log.restore_reinit(restored.attempt, restored.next_attempt_sequence)
            .ok()?;
    }
    Some(log)
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

/// Recovers the validation-time floor from every accepted candidate,
/// including candidates that were later aborted or finalized.
fn restore_validation_time(
    state: &CompanionState,
    expected: RouteExpectation,
    records: &BTreeMap<u64, &RecordRow>,
) -> Option<u64> {
    let mut validation_time = 0;
    for (sequence, record) in records {
        if record.record_kind != CANDIDATE_RECORD {
            continue;
        }
        let decoded = decode_object::<IrcSequencerRecord>(
            state,
            &record.record_object_id,
            IrcWireObjectKind::SequencerRecord,
            MAX_SEQUENCER_RECORD_OBJECT,
        )?;
        let IrcSequencerRecord::Candidate(receipt) = decoded else {
            return None;
        };
        if receipt.tbs.network_id != expected.network_id
            || receipt.tbs.conversation_id != expected.conversation_id
            || receipt.tbs.route_sequence != *sequence
        {
            return None;
        }
        let bytes = state.objects.get(&receipt.tbs.commit_object_id)?;
        let mut budget = DecodeBudget::new(MAX_LIVE_OBJECT, 1 << 16);
        let object =
            IrcWireObject::decode_kind(bytes, Some(IrcWireObjectKind::CommitMls), &mut budget)
                .ok()?;
        let mut budget = DecodeBudget::new(MAX_LIVE_OBJECT, 1 << 16);
        let envelope = verify_commit_object(
            &object,
            &expected,
            &receipt.tbs.prior_state_id,
            validation_time,
            &mut budget,
        )
        .ok()?;
        if envelope.header.epoch != receipt.tbs.prior_epoch {
            return None;
        }
        validation_time = envelope.aad.validation_time;
    }
    Some(validation_time)
}

/// Re-verifies published policies against retained roster snapshots and
/// their original certificate references. A later roster or root rotation
/// must not erase a policy that was valid when the server accepted it.
fn restore_policies(
    historical: &[(VerifiedRoot, VerifiedRoster)],
    network_id: &[u8; 32],
    index: &ObjectIndex,
    rows: &SequencerRows,
    conversation: &mut ConversationState,
    conversation_id: [u8; 32],
) {
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
        let Some(rosters) = policy_rosters(historical, policy) else {
            continue;
        };
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

/// Re-verifies each principal's retained root chain and roster snapshots.
/// These snapshots are used only to restore previously admitted facts.
fn principal_rosters(
    state: &CompanionState,
    network_id: &[u8; 32],
    conversation: &ConversationState,
    index: &ObjectIndex,
) -> Vec<(VerifiedRoot, VerifiedRoster)> {
    let mut rosters = Vec::new();
    for account in &conversation.principal_accounts {
        let Some(roots) = principal_roots(state, network_id, account) else {
            continue;
        };
        for root in roots {
            let Some(snapshots) = index.rosters.get(&root.fingerprint) else {
                continue;
            };
            for snapshot in snapshots {
                if let Ok(roster) = restore_roster(&root, snapshot) {
                    rosters.push((root, roster));
                }
            }
        }
    }
    rosters
}

pub(super) fn principal_roots(
    state: &CompanionState,
    network_id: &[u8; 32],
    account: &[u8; 24],
) -> Option<Vec<VerifiedRoot>> {
    let digest = agenc_ircd_e2ee::ids::account_id_digest(network_id, account).ok()?;
    let head = state.directory.account(&digest)?.root.as_ref()?;
    let mut roots = Vec::new();
    for object_id in &head.chain {
        let identity: IrcRootIdentity = decode_object(
            state,
            object_id,
            IrcWireObjectKind::RootIdentity,
            MAX_IDENTITY_OBJECT,
        )?;
        let root = verify_root_identity(network_id, &identity, roots.last()).ok()?;
        if root.account_id != *account {
            return None;
        }
        roots.push(root);
    }
    let last = roots.last()?;
    (last.fingerprint == head.fingerprint && last.generation == head.generation).then_some(roots)
}

type CertificateReferences = BTreeMap<[u8; 32], Vec<([u8; 16], [u8; 32])>>;

/// Selects complete snapshots that contain every certificate a policy
/// names for a root. The ordinary verifier still checks all signatures,
/// council rules, and the predecessor's approval threshold.
fn policy_rosters(
    historical: &[(VerifiedRoot, VerifiedRoster)],
    policy: &IrcPolicy,
) -> Option<PrincipalRosters> {
    let mut required = CertificateReferences::new();
    for principal in policy.tbs.finality_principals.as_slice() {
        required
            .entry(principal.root_fingerprint)
            .or_default()
            .push((principal.device_id, principal.device_certificate_id));
    }
    for approval in policy.approvals.as_slice() {
        required
            .entry(approval.signer_root_fingerprint)
            .or_default()
            .push((
                approval.signer_device_id,
                approval.signer_device_certificate_id,
            ));
    }
    let mut rosters = PrincipalRosters::new();
    for (fingerprint, certificates) in required {
        let (root, roster) = historical.iter().find(|(root, roster)| {
            root.fingerprint == fingerprint
                && certificates.iter().all(|(device, id)| {
                    roster
                        .device(device)
                        .is_some_and(|certificate| certificate.certificate_id == *id)
                })
        })?;
        if rosters
            .insert(root.account_id, (*root, roster.clone()))
            .is_some()
        {
            return None;
        }
    }
    Some(rosters)
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

/// Restores the vote ledger of the open candidate or ReInit attempt from
/// its durable per-principal vote rows: each row names the request that
/// carried the principal's counted vote, so the decision each principal
/// stands for comes back exactly once and in no particular order
/// (companion 12.4).
fn restore_ledgers(
    historical: &[(VerifiedRoot, VerifiedRoster)],
    network_id: &[u8; 32],
    index: &ObjectIndex,
    rows: &SequencerRows,
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
        for (parts, object_id) in vote_rows_of(rows, conversation_id, slot.candidate_id) {
            let Some((terminal, votes)) = index
                .terminal_requests
                .get(&object_id)
                .and_then(candidate_terminal)
            else {
                continue;
            };
            let tbs = vote_tbs(&vote_slot, slot.candidate_id, terminal);
            replay_vote(
                &mut ledger,
                historical,
                parts,
                votes,
                |ledger, rosters, vote| ledger.record(&policy, rosters, &tbs, vote),
            );
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
    for (parts, object_id) in vote_rows_of(rows, conversation_id, attempt.attempt_id) {
        let Some((terminal, votes)) = index
            .terminal_requests
            .get(&object_id)
            .and_then(attempt_terminal)
        else {
            continue;
        };
        let tbs = reinit_vote_tbs(&reinit_slot, attempt.attempt_id, terminal);
        replay_vote(
            &mut ledger,
            historical,
            parts,
            votes,
            |ledger, rosters, vote| ledger.record_reinit(&policy, rosters, &tbs, vote),
        );
    }
    conversation.vote_ledgers.insert(attempt.attempt_id, ledger);
}

/// The durable vote rows of one subject: the request each principal's
/// counted vote arrived in.
fn vote_rows_of(
    rows: &SequencerRows,
    conversation_id: [u8; 32],
    subject: [u8; 32],
) -> impl Iterator<Item = (&ProofKeyParts, [u8; 32])> {
    rows.proofs.iter().filter_map(move |(parts, object_id)| {
        (parts.role == ProofRole::Vote
            && parts.conversation_id == conversation_id
            && parts.subject_id == subject)
            .then_some((parts, *object_id))
    })
}

/// Replays a counted vote using its exact retained certificate, including
/// when the device was retired after the vote was committed.
fn replay_vote(
    ledger: &mut QuorumLedger,
    historical: &[(VerifiedRoot, VerifiedRoster)],
    parts: &ProofKeyParts,
    votes: &[IrcFinalityVote],
    mut record: impl FnMut(
        &mut QuorumLedger,
        &PrincipalRosters,
        &IrcFinalityVote,
    ) -> Result<(), E2eeError>,
) {
    let vote = votes.iter().find(|vote| {
        vote.signer_root_fingerprint == parts.root_fingerprint
            && vote.signer_device_id == parts.device_id
    });
    if let Some(vote) = vote {
        let Some((root, roster)) = historical.iter().find(|(root, roster)| {
            root.fingerprint == vote.signer_root_fingerprint
                && roster
                    .device(&vote.signer_device_id)
                    .is_some_and(|certificate| {
                        certificate.certificate_id == vote.signer_device_certificate_id
                    })
        }) else {
            return;
        };
        let rosters = PrincipalRosters::from([(root.account_id, (*root, roster.clone()))]);
        let _ = record(ledger, &rosters, vote);
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
    let log = restore_log(state, conversation_id, row, &route, &records, candidate)?;
    let activated = records
        .values()
        .any(|record| activates_bootstrap(state, record));
    let lifecycle = Lifecycle::restore(recovery.1, !activated, false);
    let direct = matches!(target, RouteTarget::Direct(_));
    let last_validation_time = restore_validation_time(
        state,
        RouteExpectation {
            network_id: *network_id,
            conversation_id,
            route_binding: route.route_binding,
            group_id: tbs.group_id.as_slice().try_into().ok()?,
        },
        &records,
    )?;
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
        proofs: index.certified_proofs(&conversation_id, &records),
        route_object_id: *agenc_ircd_e2ee::ObjectId::compute(&row.route_state).as_bytes(),
        stored_bytes: row.stored_bytes,
        principal_accounts: principal_accounts(package),
        initial_policy_id: tbs.initial_policy_id,
        required_operational_policy_id: tbs.required_operational_policy_id,
        current_policy_id: current_policy(state, &records, tbs.initial_policy_id),
        sequencer_credential_id: row
            .sequencer_credential_id
            .unwrap_or(tbs.sequencer_credential_id),
        blocked_credential_id: row.blocked_credential_id,
        predecessor_close_id: row.predecessor_close_id,
        last_validation_time,
        ..ConversationState::default()
    };
    let historical = principal_rosters(state, network_id, &conversation, index);
    restore_policies(
        &historical,
        network_id,
        index,
        rows,
        &mut conversation,
        conversation_id,
    );
    super::membership_restore::restore(
        &historical,
        network_id,
        &state.objects,
        &rows.memberships,
        &mut conversation,
        conversation_id,
    );
    restore_ledgers(
        &historical,
        network_id,
        index,
        rows,
        &mut conversation,
        &log,
    );
    let proofs: Vec<(ProofKeyParts, [u8; 32])> = rows
        .proofs
        .iter()
        .filter(|(parts, _)| parts.conversation_id == conversation_id)
        .cloned()
        .collect();
    fill_proofs(&mut conversation, &proofs);
    super::membership_restore::restore_signers(&state.objects, &mut conversation);
    state.routes.restore_entry(entry);
    state.logs.insert(conversation_id, log);
    state.lifecycles.insert(conversation_id, lifecycle);
    state.conversations.insert(conversation_id, conversation);
    Some(())
}

impl Restore {
    pub(super) fn select_objects(
        &mut self,
        backing: crate::budget::BackingReservationPort,
    ) -> Result<(), super::CompanionFault> {
        self.objects.select(&self.mailbox, &self.replays, backing)
    }
}
