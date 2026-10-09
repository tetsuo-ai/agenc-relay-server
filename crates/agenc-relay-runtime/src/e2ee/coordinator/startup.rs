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

#[cfg(test)]
#[path = "tests/startup_rows.rs"]
mod row_tests;

#[cfg(test)]
#[path = "tests/startup_directory.rs"]
mod directory_tests;

#[cfg(test)]
#[path = "tests/startup_routes.rs"]
mod route_tests;

#[cfg(test)]
#[path = "tests/startup_heads.rs"]
mod head_tests;

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_domain::e2ee::directory::{
    AccountEntry, Attachment, CapabilityHead, Challenge, ClaimOutcome, ClaimParameters, Package,
    RootHead, RosterHead,
};
use agenc_relay_domain::e2ee::lifecycle::{Lifecycle, RecoveryGate};
use agenc_relay_domain::e2ee::mailbox::{Grant, Item, MailboxKind, Target};
use agenc_relay_domain::e2ee::sequencer_log::{
    AttemptSlot, CandidatePosition, CandidateSlot, Head, Phase, SequencerLog,
};
use agenc_relay_domain::e2ee::{
    ConversationId, DirectPair, RecoveryState, RouteEntry, RouteLifecycle, RouteTarget,
    SemanticLockId,
};
use agenc_relay_e2ee::E2eeError;
use agenc_relay_e2ee::envelope::{RouteExpectation, verify_commit_object};
use agenc_relay_e2ee::finality::{
    QuorumLedger, ReinitVoteSlot, Terminal, VoteSlot, reinit_vote_tbs, vote_tbs,
};
use agenc_relay_e2ee::identity::{
    VerifiedRoot, VerifiedRoster, restore_capabilities, restore_roster, verify_root_identity,
};
use agenc_relay_e2ee::limits::{
    MAX_ABORT_OBJECT, MAX_BINDING_OBJECT, MAX_CAPABILITY_OBJECT, MAX_FEDERATION_CONTROL_OBJECT,
    MAX_FINALIZATION_OBJECT, MAX_IDENTITY_OBJECT, MAX_LIVE_OBJECT, MAX_POLICY_OBJECT,
    MAX_REINIT_OBJECT, MAX_ROSTER_OBJECT, MAX_SEQUENCER_RECORD_OBJECT,
};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::{
    ArcCommitAuthorizationRule, ArcConversationBindingPackage, ArcConversationKind, ArcPolicy,
    action_bits,
};
use agenc_relay_e2ee::objects::federation::ArcFederationRouteState;
use agenc_relay_e2ee::objects::identity::{
    ArcDeviceCapabilities, ArcDeviceRoster, ArcRootIdentity,
};
use agenc_relay_e2ee::objects::reinit::{ArcReInitAbortRequest, ArcReInitActivationRequest};
use agenc_relay_e2ee::objects::sequencing::{
    ArcAbortRequest, ArcFinalityVote, ArcFinalizationRequest, ArcSequencerRecord,
};
use agenc_relay_e2ee::policy::verify_policy;
use agenc_relay_e2ee::reinit_target::AuthorizedReinit;
use agenc_relay_e2ee::route::PrincipalRosters;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_storage::e2ee_records::origin::OriginSequenceRow;
use agenc_relay_storage::e2ee_records::{
    ATTACH_ROW_KIND, AttachRow, DELIVERY_ROW_KIND, DIRECTORY_ROW_KIND, DirectoryRow,
    MAILBOX_ROW_KIND, MailboxKind as RowMailboxKind, MailboxRow, PACKAGE_ROW_KIND, PackageRow,
    PackageState, ProofKeyParts, ProofRole, REPLAY_ROW_KIND, ROUTE_ROW_KIND, ReplayRow,
    RouteLifecycle as RowLifecycle, RouteRow, SEQUENCER_ROW_KIND, SequencerRow,
};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_relay_types::{AccountId, ChannelInstanceId};

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
    key_set: Option<agenc_relay_storage::e2ee_records::KeySetRow>,
    history: BTreeMap<[u8; 32], agenc_relay_storage::e2ee_records::SequencerHistoryRow>,
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
            agenc_relay_storage::e2ee_records::RECOVERY_GATE_KIND => self.objects.poison(),
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
            agenc_relay_storage::e2ee_records::MAILBOX_SEQUENCE_ROW_KIND => {
                self.mailbox_sequences.admit(key, body);
            }
            agenc_relay_storage::e2ee_records::EXPIRY_PROGRESS_ROW_KIND => {
                self.admit_expiry_progress(body);
            }
            REPLAY_ROW_KIND => {
                if key
                    .as_bytes()
                    .starts_with(agenc_relay_storage::e2ee_records::prefix::ORIGIN_SEQUENCE)
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
            agenc_relay_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND => {
                self.delivery.admit_owner(key, value);
            }
            agenc_relay_storage::e2ee_records::RECOVERY_SUBMISSION_ROW_KIND => {
                use agenc_relay_storage::e2ee_records::RecoverySubmissionRow;
                if let (Ok((conversation, submission)), Ok(row)) = (
                    RecoverySubmissionRow::parse_key(key),
                    RecoverySubmissionRow::decode(body),
                ) {
                    self.recovery
                        .insert_submission(conversation, submission, row);
                }
            }
            agenc_relay_storage::e2ee_records::KEYSET_ROW_KIND
            | agenc_relay_storage::e2ee_records::SEQUENCER_HISTORY_ROW_KIND => {
                self.admit_signer_row(value.record_kind(), key, body);
            }
            agenc_relay_storage::e2ee_records::RECOVERY_RECORD_ROW_KIND => {
                use agenc_relay_storage::e2ee_records::RecoveryRecordRow;
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
        use agenc_relay_storage::e2ee_records::ObjectExpiryProgressRow;
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
        use agenc_relay_storage::e2ee_records::{KeySetRow, SequencerHistoryRow};
        if kind == agenc_relay_storage::e2ee_records::KEYSET_ROW_KIND {
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
fn decode_body<T: TlsDecode>(bytes: &[u8], kind: ArcWireObjectKind, limit: usize) -> Option<T> {
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    let object = ArcWireObject::decode_exact(bytes, &mut budget).ok()?;
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
    kind: ArcWireObjectKind,
    limit: usize,
) -> Option<T> {
    let bytes = state.objects.get(object_id)?;
    decode_body(bytes, kind, limit)
}

/// Retained objects indexed by what the routes need from them.
#[derive(Default)]
struct ObjectIndex {
    /// Binding packages by binding identifier, with the object identifier.
    bindings: BTreeMap<[u8; 32], ([u8; 32], ArcConversationBindingPackage)>,
    /// Published policies by object identifier, with the object length.
    policies: BTreeMap<[u8; 32], (ArcPolicy, usize)>,
    /// Retained roster snapshots by signing root fingerprint.
    rosters: BTreeMap<[u8; 32], Vec<ArcDeviceRoster>>,
    /// Retained terminal request objects by conversation and terminal
    /// identifier, certified or not; a route keeps only the certified ones.
    proofs: BTreeMap<[u8; 32], BTreeMap<[u8; 32], [u8; 32]>>,
    /// Retained terminal requests by object identifier.
    terminal_requests: BTreeMap<[u8; 32], TerminalRequest>,
}

/// The votes one retained terminal request carries for its subject.
enum TerminalRequest {
    /// A finalization request, its finalization identifier, and the
    /// resulting policy whose council votes beside the old one when the
    /// request is a bootstrap activation (companion 9.5).
    Finalize([u8; 32], Vec<ArcFinalityVote>, Option<[u8; 32]>),
    /// An abort request, its abort identifier, and its reason code.
    Abort([u8; 32], u16, Vec<ArcFinalityVote>),
    /// A ReInit activation request and its activation identifier.
    Activate([u8; 32], Vec<ArcFinalityVote>),
    /// A ReInit abort request, its abort identifier, and its reason code.
    AbortAttempt([u8; 32], u16, Vec<ArcFinalityVote>),
}

impl ObjectIndex {
    fn build(state: &CompanionState) -> Self {
        let mut index = Self::default();
        for (object_id, bytes) in &state.objects {
            let Ok((kind, _)) = ArcWireObject::peek(bytes) else {
                continue;
            };
            index.index_object(kind, *object_id, bytes);
        }
        index
    }

    fn index_object(&mut self, kind: ArcWireObjectKind, object_id: [u8; 32], bytes: &[u8]) {
        match kind {
            ArcWireObjectKind::ConversationBinding => {
                let Some(package) =
                    decode_body::<ArcConversationBindingPackage>(bytes, kind, MAX_BINDING_OBJECT)
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
            ArcWireObjectKind::FinalizationRequest => {
                let Some(request) =
                    decode_body::<ArcFinalizationRequest>(bytes, kind, MAX_FINALIZATION_OBJECT)
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
                let authorization = &request.proof.authorization.tbs;
                let resulting = (authorization.authorization_rule
                    == ArcCommitAuthorizationRule::BootstrapActivation)
                    .then_some(authorization.resulting_policy_id);
                self.terminal_requests.insert(
                    object_id,
                    TerminalRequest::Finalize(
                        finalization_id,
                        request.votes.as_slice().to_vec(),
                        resulting,
                    ),
                );
            }
            ArcWireObjectKind::AbortRequest => self.index_abort(object_id, bytes),
            ArcWireObjectKind::ReinitActivationRequest => self.index_activation(object_id, bytes),
            ArcWireObjectKind::ReinitAbortRequest => self.index_attempt_abort(object_id, bytes),
            ArcWireObjectKind::Policy => {
                if let Some(policy) = decode_body::<ArcPolicy>(bytes, kind, MAX_POLICY_OBJECT) {
                    self.policies.insert(object_id, (policy, bytes.len()));
                }
            }
            ArcWireObjectKind::DeviceRoster => {
                if let Some(roster) = decode_body::<ArcDeviceRoster>(bytes, kind, MAX_ROSTER_OBJECT)
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
        let kind = ArcWireObjectKind::AbortRequest;
        let Some(request) = decode_body::<ArcAbortRequest>(bytes, kind, MAX_ABORT_OBJECT) else {
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
        let kind = ArcWireObjectKind::ReinitActivationRequest;
        let Some(request) =
            decode_body::<ArcReInitActivationRequest>(bytes, kind, MAX_REINIT_OBJECT)
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
        let kind = ArcWireObjectKind::ReinitAbortRequest;
        let Some(request) = decode_body::<ArcReInitAbortRequest>(bytes, kind, MAX_REINIT_OBJECT)
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
    restore_successors(state, &network_id, &index)?;
    restore.gates.install(state)?;
    coordinator.owner_reconstruction = restore.owners.for_network(network_id).finish(state);
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
    accepted: Option<agenc_relay_storage::e2ee_records::KeySetRow>,
    history: BTreeMap<[u8; 32], agenc_relay_storage::e2ee_records::SequencerHistoryRow>,
) -> super::signer_startup::Proposal {
    use agenc_relay_domain::e2ee::{RecoveryState, RouteLifecycle};
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
        ArcWireObject::decode_kind(bytes, Some(ArcWireObjectKind::SequencerRecord), &mut budget)
            .ok()?;
    match ArcSequencerRecord::decode_exact(object.body(), &mut budget).ok()? {
        ArcSequencerRecord::Candidate(receipt) => Some(receipt.tbs.sequencer_key_id),
        ArcSequencerRecord::ReinitAttempt(receipt) => Some(receipt.tbs.sequencer_key_id),
        _ => None,
    }
}

/// An activation installs its successor in the transaction that stores the
/// activation certificate (companion 13.8), so the successor of every
/// migrated predecessor restores from its own route row, binding and policy
/// rows like any route. Once every route has loaded, each is checked against
/// the target its predecessor's activated attempt carries, and a migrated
/// predecessor without its installed successor is a storage fault.
fn restore_successors(
    state: &mut CompanionState,
    network_id: &[u8; 32],
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
        restore_successor(state, network_id, old, conversation_id, activation_id)
            .ok_or(super::CompanionFault::Storage)?;
        verified.insert(conversation_id);
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
        // A successor of a retired predecessor, bound under the previous
        // profile, is retired with it: its activation cannot be checked.
        let retired = |old: &[u8; 32]| {
            state
                .logs
                .get(old)
                .is_some_and(|log| log.phase() == Phase::Retired)
        };
        if !verified.contains(&id) && predecessor.as_ref().is_some_and(retired) {
            retire_route(state, id);
            continue;
        }
        if !verified.contains(&id)
            || predecessor.is_none_or(|old| !state.conversations.contains_key(&old))
        {
            discard_route(state, id);
        }
    }
}

/// Retires the restored route of `conversation`: its log keeps its head and
/// accepted state in the retired phase.
fn retire_route(state: &mut CompanionState, conversation: [u8; 32]) {
    if let Some(log) = state.logs.get_mut(&conversation) {
        *log = SequencerLog::restore(
            conversation,
            log.head(),
            *log.accepted_state_id(),
            log.accepted_epoch(),
            Phase::Retired,
        );
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

/// Checks the restored successor `new` of `old` against the target the
/// activated attempt carries, checked against the predecessor's retained
/// binding facts: its binding package is the one the activation installs
/// and its log is anchored at the activation or continues from it.
/// Then selects its route over the predecessor's, whatever the read order,
/// restores its lifecycle without a bootstrap, and gives it the context
/// digest of the target's context (companion 2.2), not the target's digest.
fn restore_successor(
    state: &mut CompanionState,
    network_id: &[u8; 32],
    old: [u8; 32],
    new: [u8; 32],
    activation_id: [u8; 32],
) -> Option<()> {
    use super::ops::{reinit_install, route_successor};
    let certificate = route_successor::activation(state, &old).ok()?;
    let attempt = &certificate.tbs.request.attempt;
    let old_facts = state.conversations.get(&old)?.reinit_facts?;
    let mut budget = DecodeBudget::new(MAX_REINIT_OBJECT, 1 << 18);
    let carried = agenc_relay_e2ee::reinit_target::check_carried_target_from(
        network_id,
        &old_facts,
        &attempt.target,
        &mut budget,
    )
    .ok()?;
    let package = reinit_install::package(carried.context(), &attempt.key_package_plan).ok()?;
    let bytes =
        reinit_install::wire_object(ArcWireObjectKind::ConversationBinding, &package).ok()?;
    let installed = state.conversations.get(&new)?.binding_object_id;
    let log = state.logs.get(&new)?;
    if installed != *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes()
        || log.accepted_epoch() < 1
        || (!log.head().recorded
            && (log.accepted_state_id() != &activation_id
                || log.head().record_id != activation_id
                || log.accepted_epoch() != 1))
    {
        return None;
    }
    let context_digest =
        agenc_relay_e2ee::ids::semantic_id_of(SemanticHashDomain::ContextHash, carried.context())
            .ok()?;
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
    let mut chains: BTreeMap<[u8; 32], Vec<VerifiedRoot>> = BTreeMap::new();
    let mut newest: BTreeMap<[u8; 32], VerifiedRoot> = BTreeMap::new();
    let mut later = Vec::new();
    for (key, row) in rows {
        match row {
            identity @ DirectoryRow::Identity { .. } => {
                if let Some((digest, chain, head)) =
                    restore_identity(state, network_id, &key, identity)
                {
                    entries.entry(digest).or_default().root = Some(head);
                    newest.insert(digest, chain.newest);
                    chains.insert(digest, chain.roots);
                }
            }
            other => later.push((key, other)),
        }
    }
    for (key, row) in &later {
        if let DirectoryRow::Roster { .. } = row {
            restore_roster_row(state, &chains, &mut entries, key, row);
        }
    }
    for (digest, root) in newest {
        pend_newest_root(state, digest, root);
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

/// A root newer than the root of the account's current roster awaits its
/// first roster, and so does the root of an account without one, as live
/// publication leaves them (companion 8.2 and 14).
fn pend_newest_root(state: &mut CompanionState, digest: [u8; 32], newest: VerifiedRoot) {
    let current = state
        .principals
        .get(&digest)
        .map(|(root, _)| root.fingerprint);
    if current != Some(newest.fingerprint) {
        state.pending_roots.insert(digest, newest);
    }
}

/// An account's re-verified root chain, oldest first, and its newest root.
struct RootChain {
    roots: Vec<VerifiedRoot>,
    newest: VerifiedRoot,
}

/// Re-verifies one root chain oldest first, returning every root of it.
fn restore_identity(
    state: &CompanionState,
    network_id: &[u8; 32],
    key: &StoredKey,
    row: DirectoryRow,
) -> Option<([u8; 32], RootChain, RootHead)> {
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
    let mut chain: Vec<VerifiedRoot> = Vec::new();
    for object_id in &chain_object_ids {
        let root: ArcRootIdentity = decode_object(
            state,
            object_id,
            ArcWireObjectKind::RootIdentity,
            MAX_IDENTITY_OBJECT,
        )?;
        chain.push(verify_root_identity(network_id, &root, chain.last()).ok()?);
    }
    let newest = *chain.last().filter(|root| {
        root.fingerprint == root_fingerprint && root.generation == root_generation
    })?;
    let head = RootHead {
        generation: root_generation,
        fingerprint: root_fingerprint,
        chain: chain_object_ids,
    };
    let chain = RootChain {
        roots: chain,
        newest,
    };
    Some((digest, chain, head))
}

/// Restores an account's current roster under the root that signed it: its
/// newest root, or an earlier root of its chain while a newer one awaits its
/// first roster.
fn restore_roster_row(
    state: &mut CompanionState,
    chains: &BTreeMap<[u8; 32], Vec<VerifiedRoot>>,
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
    let root = chains
        .get(&digest)?
        .iter()
        .find(|root| root.fingerprint == *root_fingerprint)?;
    let roster: ArcDeviceRoster = decode_object(
        state,
        object_id,
        ArcWireObjectKind::DeviceRoster,
        MAX_ROSTER_OBJECT,
    )?;
    let verified = restore_roster(root, &roster).ok()?;
    if verified.roster_id != *roster_id {
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
    let capabilities: ArcDeviceCapabilities = decode_object(
        state,
        object_id,
        ArcWireObjectKind::DeviceCapabilities,
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

fn route_target(route: &ArcFederationRouteState) -> Option<RouteTarget> {
    match route.conversation_kind {
        ArcConversationKind::Channel => {
            let instance = <[u8; 16]>::try_from(route.channel_instance_id.as_slice()).ok()?;
            Some(RouteTarget::Channel(ChannelInstanceId::from_bytes(
                instance,
            )))
        }
        ArcConversationKind::Direct => {
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

fn direct_accounts(route: &ArcFederationRouteState) -> Option<([u8; 24], [u8; 24])> {
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

/// The phase the durable head restores (`head_log_phase`), except that a
/// group the head leaves open while any retained finalization is that of a
/// ReInit Commit is retired (`reinit_finalized`). A route row whose head is
/// not its last retained record restores nothing.
fn restore_log_phase(
    state: &CompanionState,
    conversation_id: [u8; 32],
    row: &RouteRow,
    records: &BTreeMap<u64, &RecordRow>,
) -> Option<RestoredLogPhase> {
    if !head_is_last_record(row, records) {
        return None;
    }
    let mut restored = head_log_phase(state, conversation_id, row, records)?;
    if restored.phase == Phase::Open && reinit_finalized(state, records) {
        restored.phase = Phase::Retired;
    }
    Some(restored)
}

/// Whether the head that route `row` names is its last retained record, at
/// that record's route sequence and under its identifier. A closed route's
/// head is its close, which is not a retained record, and a route without a
/// retained record has no recorded head.
fn head_is_last_record(row: &RouteRow, records: &BTreeMap<u64, &RecordRow>) -> bool {
    row.close_id.is_some()
        || records.last_key_value().is_none_or(|(sequence, record)| {
            *sequence == row.route_sequence && record.record_id == row.sequencer_head_id
        })
}

/// The finalization of a ReInit Commit, or a ReInit receipt or terminal, at
/// the durable head determines whether the old group is closed with an
/// attempt still to come, open, or followed by another, or migrated; a
/// ReInit terminal of the previous profile retires it.
// agenc-review: focus owner=runtime reviewed=2026-10-05 reason=the head finalization, receipt and terminal alternatives restore the phase together with exact durable row identity checks
fn head_log_phase(
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
            FINALIZATION_RECORD
                | REINIT_ATTEMPT_RECORD
                | REINIT_ACTIVATION_RECORD
                | REINIT_ABORT_RECORD
        )
    }) else {
        return Some(restored);
    };
    let Some(decoded) = decode_object::<ArcSequencerRecord>(
        state,
        &record.record_object_id,
        ArcWireObjectKind::SequencerRecord,
        MAX_SEQUENCER_RECORD_OBJECT,
    ) else {
        // A ReInit terminal of the previous profile, which this profile does
        // not read, retires the route; any other undecodable head refuses.
        previous_profile_terminal(state, row, records, record)?;
        restored.phase = Phase::Retired;
        return Some(restored);
    };
    match decoded {
        ArcSequencerRecord::Finalization(certificate) => {
            if let Some(phase) =
                finalization_head_phase(conversation_id, row, record, &certificate.tbs)?
            {
                restored.phase = phase;
            }
        }
        ArcSequencerRecord::ReinitAttempt(receipt) => {
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
        ArcSequencerRecord::ReinitAbort(certificate) => {
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
        ArcSequencerRecord::ReinitActivation(certificate) => {
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

/// The phase a finalization at the durable head restores: the finalization
/// of a ReInit Commit, whose authorization carries the ReInit bit, closed
/// the old group and entered the ReInit phase at that finalization
/// (companion 13.8 step 2), and must be exactly the record its route row
/// names; any other finalization leaves the phase the row gives (`Some(None)`).
fn finalization_head_phase(
    conversation_id: [u8; 32],
    row: &RouteRow,
    record: &RecordRow,
    tbs: &agenc_relay_e2ee::objects::sequencing::ArcCommitFinalizationTbs,
) -> Option<Option<Phase>> {
    if tbs.request.proof.authorization.tbs.action_bits & action_bits::REINIT == 0 {
        return Some(None);
    }
    let exact = record.record_kind == FINALIZATION_RECORD
        && tbs.conversation_id == conversation_id
        && tbs.predecessor_record_id == record.predecessor_record_id
        && tbs.finalization_id == row.accepted_state_id
        && tbs.finalization_id == row.sequencer_head_id
        && tbs.route_sequence == row.route_sequence;
    exact.then_some(Some(Phase::Reinit {
        old_reinit_state_id: tbs.finalization_id,
    }))
}

/// Whether `record`, the head its route `row` names, is a ReInit activation
/// or abort record of the previous profile. Such a record embeds an attempt
/// of the previous layout, which this profile neither parses nor
/// reinterprets (companion 2.3), so only its rows are compared: the head's
/// record row is a terminal of one of those kinds whose identifier is the
/// route row's head and whose predecessor is the attempt receipt before it,
/// and its retained object is a sequencer record, which the caller found
/// does not decode under this profile. `None` refuses the route.
fn previous_profile_terminal(
    state: &CompanionState,
    row: &RouteRow,
    records: &BTreeMap<u64, &RecordRow>,
    record: &RecordRow,
) -> Option<()> {
    let receipt = row
        .route_sequence
        .checked_sub(1)
        .and_then(|sequence| records.get(&sequence))?;
    let bytes = state.objects.get(&record.record_object_id)?;
    let envelope = ArcWireObject::peek(bytes).ok().map(|(kind, _)| kind);
    (matches!(
        record.record_kind,
        REINIT_ACTIVATION_RECORD | REINIT_ABORT_RECORD
    ) && record.terminal
        && record.record_id == row.sequencer_head_id
        && record.predecessor_record_id == receipt.record_id
        && receipt.record_kind == REINIT_ATTEMPT_RECORD
        && envelope == Some(ArcWireObjectKind::SequencerRecord))
    .then_some(())
}

/// Whether any retained finalization is that of a ReInit Commit, whose
/// authorization carries the ReInit bit. Such a finalization closes the old
/// group for good (companion 13.8 step 2), so a head that would leave the
/// group open cannot be continued: under this profile no open head follows
/// one, and under the previous profile, whose ReInit phase began only at the
/// first attempt, ordinary records could.
fn reinit_finalized(state: &CompanionState, records: &BTreeMap<u64, &RecordRow>) -> bool {
    records.values().any(|record| {
        record.record_kind == FINALIZATION_RECORD
            && matches!(
                decode_object(
                    state,
                    &record.record_object_id,
                    ArcWireObjectKind::SequencerRecord,
                    MAX_SEQUENCER_RECORD_OBJECT,
                ),
                Some(ArcSequencerRecord::Finalization(certificate))
                    if certificate.tbs.request.proof.authorization.tbs.action_bits
                        & action_bits::REINIT
                        != 0
            )
    })
}

/// The authorized ReInit of the finalization that entered a restored ReInit
/// phase, from its retained record (companion 13.8): `None` when no
/// retained finalization record names that state or its proof binds no
/// authorized target, so no attempt follows it. An authority whose proof
/// names another finalization than the accepted state admits no attempt
/// either (`ops::reinit_authority::authorized`).
fn restored_authority(
    state: &CompanionState,
    records: &BTreeMap<u64, &RecordRow>,
    finalization_id: &[u8; 32],
) -> Option<AuthorizedReinit> {
    let record = records.values().find(|record| {
        record.record_kind == FINALIZATION_RECORD && record.record_id == *finalization_id
    })?;
    let decoded: ArcSequencerRecord = decode_object(
        state,
        &record.record_object_id,
        ArcWireObjectKind::SequencerRecord,
        MAX_SEQUENCER_RECORD_OBJECT,
    )?;
    let ArcSequencerRecord::Finalization(certificate) = decoded else {
        return None;
    };
    AuthorizedReinit::from_proof(&certificate.tbs.request.proof).ok()
}

/// Restores the log head, epoch position, and ReInit phase from retained rows.
fn restore_log(
    state: &CompanionState,
    conversation_id: [u8; 32],
    row: &RouteRow,
    route: &ArcFederationRouteState,
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
fn principal_accounts(package: &ArcConversationBindingPackage) -> Vec<[u8; 24]> {
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
            let decoded: Option<ArcSequencerRecord> = decode_object(
                state,
                &record.record_object_id,
                ArcWireObjectKind::SequencerRecord,
                MAX_SEQUENCER_RECORD_OBJECT,
            );
            match decoded {
                Some(ArcSequencerRecord::Finalization(certificate)) => Some(
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
/// including candidates that were later aborted or finalized. A later
/// candidate of the same epoch replaces an aborted one in that epoch's
/// candidate slot row, the only durable row that names a candidate's
/// Commit, so the replaced Commit is ordinary unowned material that object
/// expiry may collect (companion 15 and 16); the replacing candidate's
/// validation time is at least the replaced one's, so a replaced candidate
/// whose Commit is gone adds nothing to the floor. A Commit its epoch's slot
/// still names is retained, and its absence refuses the route.
fn restore_validation_time(
    state: &CompanionState,
    expected: RouteExpectation,
    records: &BTreeMap<u64, &RecordRow>,
    slots: &BTreeMap<([u8; 32], u64), CandidateRow>,
) -> Option<u64> {
    let mut validation_time = 0;
    for (sequence, record) in records {
        if record.record_kind != CANDIDATE_RECORD {
            continue;
        }
        let decoded = decode_object::<ArcSequencerRecord>(
            state,
            &record.record_object_id,
            ArcWireObjectKind::SequencerRecord,
            MAX_SEQUENCER_RECORD_OBJECT,
        )?;
        let ArcSequencerRecord::Candidate(receipt) = decoded else {
            return None;
        };
        if receipt.tbs.network_id != expected.network_id
            || receipt.tbs.conversation_id != expected.conversation_id
            || receipt.tbs.route_sequence != *sequence
        {
            return None;
        }
        let Some(bytes) = state.objects.get(&receipt.tbs.commit_object_id) else {
            let replaced = slots
                .get(&(expected.conversation_id, receipt.tbs.prior_epoch))
                .is_some_and(|slot| slot.commit_object_id != receipt.tbs.commit_object_id);
            if replaced {
                continue;
            }
            return None;
        };
        let mut budget = DecodeBudget::new(MAX_LIVE_OBJECT, 1 << 16);
        let object =
            ArcWireObject::decode_kind(bytes, Some(ArcWireObjectKind::CommitMls), &mut budget)
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
    let digest = agenc_relay_e2ee::ids::account_id_digest(network_id, account).ok()?;
    let head = state.directory.account(&digest)?.root.as_ref()?;
    let mut roots = Vec::new();
    for object_id in &head.chain {
        let identity: ArcRootIdentity = decode_object(
            state,
            object_id,
            ArcWireObjectKind::RootIdentity,
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
    policy: &ArcPolicy,
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

/// A candidate terminal, its votes, and the bootstrap resulting policy.
type CandidateTerminal<'a> = (Terminal, &'a [ArcFinalityVote], Option<[u8; 32]>);

/// The terminal, votes, and bootstrap resulting policy of one retained
/// request for a candidate slot.
fn candidate_terminal(request: &TerminalRequest) -> Option<CandidateTerminal<'_>> {
    match request {
        TerminalRequest::Finalize(id, votes, resulting) => {
            Some((Terminal::finalize(*id), votes, *resulting))
        }
        TerminalRequest::Abort(id, reason, votes) => Terminal::abort(*id, *reason)
            .ok()
            .map(|terminal| (terminal, votes.as_slice(), None)),
        _ => None,
    }
}

/// The terminal and votes of one retained request for a ReInit attempt.
fn attempt_terminal(request: &TerminalRequest) -> Option<(Terminal, &[ArcFinalityVote])> {
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
    let mut unreplayed = 0_u32;
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
            let Some((terminal, votes, resulting)) = index
                .terminal_requests
                .get(&object_id)
                .and_then(candidate_terminal)
            else {
                unreplayed += 1;
                continue;
            };
            // A bootstrap activation counted this signer under the council
            // it sits on, the old one first (companion 9.5).
            let resulting = resulting
                .and_then(|policy_id| conversation.policies.get(&policy_id))
                .map(|retained| &retained.policy);
            let tbs = vote_tbs(&vote_slot, slot.candidate_id, terminal);
            let replayed = replay_vote(
                &mut ledger,
                historical,
                parts,
                votes,
                |ledger, rosters, vote| {
                    let signer = (&vote.signer_root_fingerprint, &vote.signer_device_id);
                    let council = resulting
                        .filter(|council| {
                            policy.council_member(signer.0, signer.1).is_none()
                                && council.council_member(signer.0, signer.1).is_some()
                        })
                        .unwrap_or(&policy);
                    ledger.record(council, rosters, &tbs, vote)
                },
            );
            unreplayed += u32::from(!replayed);
        }
        conversation.vote_ledgers.insert(slot.candidate_id, ledger);
        conversation.unreplayed_votes = unreplayed;
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
            unreplayed += 1;
            continue;
        };
        let tbs = reinit_vote_tbs(&reinit_slot, attempt.attempt_id, terminal);
        let replayed = replay_vote(
            &mut ledger,
            historical,
            parts,
            votes,
            |ledger, rosters, vote| ledger.record_reinit(&policy, rosters, &tbs, vote),
        );
        unreplayed += u32::from(!replayed);
    }
    conversation.vote_ledgers.insert(attempt.attempt_id, ledger);
    conversation.unreplayed_votes = unreplayed;
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
            && parts.root_fingerprint != super::ops::sequence::REQUEST_ROW_ROOT
            && parts.conversation_id == conversation_id
            && parts.subject_id == subject)
            .then_some((parts, *object_id))
    })
}

/// Replays a counted vote using its exact retained certificate, including
/// when the device was retired after the vote was committed. Returns whether
/// the durable row came back as a counted vote.
fn replay_vote(
    ledger: &mut QuorumLedger,
    historical: &[(VerifiedRoot, VerifiedRoster)],
    parts: &ProofKeyParts,
    votes: &[ArcFinalityVote],
    mut record: impl FnMut(
        &mut QuorumLedger,
        &PrincipalRosters,
        &ArcFinalityVote,
    ) -> Result<(), E2eeError>,
) -> bool {
    let vote = votes.iter().find(|vote| {
        vote.signer_root_fingerprint == parts.root_fingerprint
            && vote.signer_device_id == parts.device_id
    });
    vote.is_some_and(|vote| {
        let Some((root, roster)) = historical.iter().find(|(root, roster)| {
            root.fingerprint == vote.signer_root_fingerprint
                && roster
                    .device(&vote.signer_device_id)
                    .is_some_and(|certificate| {
                        certificate.certificate_id == vote.signer_device_certificate_id
                    })
        }) else {
            return false;
        };
        let rosters = PrincipalRosters::from([(root.account_id, (*root, roster.clone()))]);
        record(ledger, &rosters, vote).is_ok()
    })
}

fn activates_bootstrap(state: &CompanionState, record: &RecordRow) -> bool {
    if record.record_kind != FINALIZATION_RECORD {
        return false;
    }
    let decoded: Option<ArcSequencerRecord> = decode_object(
        state,
        &record.record_object_id,
        ArcWireObjectKind::SequencerRecord,
        MAX_SEQUENCER_RECORD_OBJECT,
    );
    match decoded {
        Some(ArcSequencerRecord::Finalization(certificate)) => {
            certificate
                .tbs
                .request
                .proof
                .authorization
                .tbs
                .authorization_rule
                == ArcCommitAuthorizationRule::BootstrapActivation
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
            // A retained-request row owns a request below quorum.
            ProofRole::Vote if parts.root_fingerprint == super::ops::sequence::REQUEST_ROW_ROOT => {
                conversation
                    .pending_requests
                    .entry(parts.subject_id)
                    .or_default()
                    .insert(*object_id);
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
    let route: ArcFederationRouteState = decode_body(
        &row.route_state,
        ArcWireObjectKind::FederationState,
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
    let reinit = match log.phase() {
        Phase::Reinit {
            old_reinit_state_id,
        } => restored_authority(state, &records, &old_reinit_state_id),
        _ => None,
    };
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
        &rows.candidates,
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
        route_object_id: *agenc_relay_e2ee::ObjectId::compute(&row.route_state).as_bytes(),
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
        reinit,
        reinit_facts: Some(
            agenc_relay_e2ee::reinit_target::ReinitPredecessor::of_binding_tbs(tbs).ok()?,
        ),
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
