//! The device rosters a live conversation's statements name (companion
//! 9.3, 9.4, 13.7.3 and 15).
//!
//! A roster stops being its account's current one at the next publication,
//! but a conversation's statements go on naming it: its binding names each
//! principal's roster head, each stored leaf-membership proof names the
//! roster its credential was authorized under, and each retained policy's
//! approvals and finality principals verify only under a roster that holds
//! their certificates. Every vote a policy's council casts carries the
//! certificate that policy names for the voting device, so a roster that
//! verifies the policy verifies the vote too. The conversation's route row
//! holds these rosters as security proofs charged to the conversation
//! (`owners`) from the batch that stores the statement until the row's
//! deletion, so a replaced roster stays retained while a live
//! conversation's statement names it, and also after a later proof
//! replaces the proof that named it. A device's capability row also holds
//! the roster its head names (`owners`). A replaced roster that no route
//! row and no capability row holds is collected once the retention window
//! has passed, and a first proof that names it after that is refused.
//!
//! For each root a policy names, the roster held is the earliest retained
//! one of that root, by roster generation, that verifies under the root and
//! holds every certificate the policy names for it. A certificate first
//! appears at the generation its enrollment targeted and no roster below
//! that generation verifies with it, and a roster that is held is not
//! collected, so later publications never change which roster that is: the
//! batch that stores the policy and every restart choose the same one. One
//! derivation serves the live batch, from the statements it stores, and
//! startup, from the statements each restored route holds; startup also
//! keeps the route rows each roster's stored account records as holders
//! (`owners`), so a roster that only a replaced proof named stays held
//! across a restart.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::identity::{VerifiedRoot, restore_roster};
use agenc_relay_e2ee::ids::{account_id_digest, semantic_id_of};
use agenc_relay_e2ee::limits::{
    MAX_BINDING_OBJECT, MAX_LEAF_MEMBERSHIP_OBJECT, MAX_POLICY_OBJECT, MAX_ROSTER_OBJECT,
};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::{ArcConversationBindingPackage, ArcPolicy};
use agenc_relay_e2ee::objects::identity::ArcDeviceRoster;
use agenc_relay_e2ee::objects::membership::ArcLeafMembershipProof;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_storage::e2ee_records::{
    ObjectRow, ROUTE_ROW_KIND, RouteRow, SEQUENCER_ROW_KIND, SequencerRow,
};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};

use super::{CompanionState, ConversationState};
use crate::state_core::durable::AccountServiceDurableWrite as Write;

/// The certificates a statement names for one root, as `(device,
/// certificate identifier)`.
type Certificates = BTreeSet<([u8; 16], [u8; 32])>;

/// The roster each root and certificate set resolved to, so one batch or
/// one restart resolves a council many policies share once.
pub(super) type Resolved = BTreeMap<([u8; 32], Certificates), Option<[u8; 32]>>;

fn decode<T: TlsDecode>(bytes: &[u8], kind: ArcWireObjectKind, limit: usize) -> Option<T> {
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    let object = ArcWireObject::decode_kind(bytes, Some(kind), &mut budget).ok()?;
    T::decode_exact(object.body(), &mut budget).ok()
}

/// The binding package in `bytes`.
pub(super) fn package(bytes: &[u8]) -> Option<ArcConversationBindingPackage> {
    decode(
        bytes,
        ArcWireObjectKind::ConversationBinding,
        MAX_BINDING_OBJECT,
    )
}

/// The roster identifier the leaf-membership proof in `bytes` names.
pub(super) fn proof_roster(bytes: &[u8]) -> Option<[u8; 32]> {
    decode::<ArcLeafMembershipProof>(
        bytes,
        ArcWireObjectKind::LeafMembershipProof,
        MAX_LEAF_MEMBERSHIP_OBJECT,
    )
    .map(|proof| proof.tbs.roster_id)
}

/// The policy in `bytes`.
pub(super) fn policy(bytes: &[u8]) -> Option<ArcPolicy> {
    decode(bytes, ArcWireObjectKind::Policy, MAX_POLICY_OBJECT)
}

/// The resident roster object whose roster identifier is `roster_id`.
pub(super) fn named(state: &CompanionState, roster_id: &[u8; 32]) -> Option<[u8; 32]> {
    let object = state.roster_snapshots.get(roster_id)?;
    state.objects.contains_key(object).then_some(*object)
}

/// The resident rosters `package`'s binding names as its principals' heads.
pub(super) fn of_binding(
    state: &CompanionState,
    package: &ArcConversationBindingPackage,
) -> BTreeSet<[u8; 32]> {
    let principals = package.binding.tbs.principals.as_slice();
    principals
        .iter()
        .filter_map(|principal| named(state, &principal.roster_id))
        .collect()
}

/// For each root `policy` names, the earliest resident roster of that root
/// that verifies under it and holds every certificate the policy names for
/// it. Only the roots of `principals` are considered, as the policy's own
/// verification considers only theirs.
pub(super) fn of_policy(
    state: &CompanionState,
    network_id: &[u8; 32],
    principals: &[[u8; 24]],
    policy: &ArcPolicy,
    resolved: &mut Resolved,
) -> BTreeSet<[u8; 32]> {
    let mut held = BTreeSet::new();
    for (fingerprint, certificates) in certificates_of(policy) {
        let roster = root_of(state, network_id, principals, &fingerprint).and_then(|root| {
            *resolved
                .entry((fingerprint, certificates))
                .or_insert_with_key(|(_, certificates)| earliest(state, &root, certificates))
        });
        held.extend(roster);
    }
    held
}

/// The rosters the statements one batch stores name, as `(conversation,
/// roster object)`: a route row written with the binding package its batch
/// stages names that binding's roster heads, a membership row the roster its
/// proof names, and a policy row the rosters its policy verifies under. A
/// statement of a conversation that has no route row once the batch commits
/// names nothing.
pub(super) fn of_batch(
    state: &CompanionState,
    network_id: &[u8; 32],
    writes: &[Write],
) -> BTreeSet<([u8; 32], [u8; 32])> {
    let batch = Batch::read(writes);
    let mut resolved = Resolved::new();
    let mut held = BTreeSet::new();
    for (conversation, package) in &batch.packages {
        let heads = of_binding(state, package);
        held.extend(heads.into_iter().map(|roster| (*conversation, roster)));
    }
    for (conversation, object) in &batch.proofs {
        let named = batch
            .object(state, object)
            .and_then(proof_roster)
            .and_then(|roster_id| named(state, &roster_id));
        held.extend(named.map(|roster| (*conversation, roster)));
    }
    for (conversation, object) in &batch.policies {
        let principals = batch.principals(state, conversation);
        let verifying = batch
            .object(state, object)
            .and_then(policy)
            .map(|policy| of_policy(state, network_id, &principals, &policy, &mut resolved));
        let rosters = verifying.into_iter().flatten();
        held.extend(rosters.map(|roster| (*conversation, roster)));
    }
    held.retain(|(conversation, _)| batch.routed(state, conversation));
    held
}

/// The statements of one batch that name rosters. Rows that do not decode
/// are left to the ownership derivation, which refuses them.
#[derive(Default)]
struct Batch {
    /// The staged binding, proof and policy objects, by object identifier.
    objects: BTreeMap<[u8; 32], Vec<u8>>,
    /// The binding each route row the batch writes names, by conversation.
    routes: BTreeMap<[u8; 32], [u8; 32]>,
    /// The conversations whose route rows the batch deletes.
    deleted: BTreeSet<[u8; 32]>,
    /// The binding package the batch stages for a route row it writes.
    packages: BTreeMap<[u8; 32], ArcConversationBindingPackage>,
    /// The proof object of each membership row the batch writes.
    proofs: Vec<([u8; 32], [u8; 32])>,
    /// The policy object of each policy row the batch writes.
    policies: Vec<([u8; 32], [u8; 32])>,
}

impl Batch {
    /// Reads the route, membership and policy rows of `writes`, then, when
    /// there are any, the staged objects they name.
    fn read(writes: &[Write]) -> Self {
        let mut batch = Self::default();
        for write in writes {
            batch.note(write);
        }
        if batch.routes.is_empty() && batch.proofs.is_empty() && batch.policies.is_empty() {
            return batch;
        }
        for write in writes {
            batch.stage(write);
        }
        batch.bind_packages();
        batch
    }

    /// Records a route, membership or policy row the write puts, or a route
    /// row it deletes.
    fn note(&mut self, write: &Write) {
        match write {
            Write::Put { table, key, .. } if *table == TableId::E2eeState => {
                self.row(write, key);
            }
            Write::Delete { table, key } if *table == TableId::E2eeState => {
                self.deleted.extend(RouteRow::parse_key(key).ok());
            }
            _ => {}
        }
    }

    /// Pairs each route row with the binding package the batch stages for
    /// the binding it names.
    fn bind_packages(&mut self) {
        let staged: Vec<([u8; 32], ArcConversationBindingPackage)> = self
            .objects
            .values()
            .filter_map(|bytes| package(bytes))
            .filter_map(|package| {
                let binding_id =
                    semantic_id_of(SemanticHashDomain::BindingId, &package.binding.tbs).ok()?;
                Some((binding_id, package))
            })
            .collect();
        for (binding_id, package) in staged {
            let bound = self
                .routes
                .iter()
                .filter(|(_, named)| **named == binding_id);
            let conversations: Vec<[u8; 32]> =
                bound.map(|(conversation, _)| *conversation).collect();
            for conversation in conversations {
                self.packages.insert(conversation, package.clone());
            }
        }
    }

    /// Keeps a staged binding, proof or policy object.
    fn stage(&mut self, write: &Write) {
        let Some((TableId::E2eeObject, _, encoded)) = write.encoded_record() else {
            return;
        };
        let Some(row) = PersistentRecordValue::decode(TableId::E2eeObject, encoded)
            .ok()
            .and_then(|value| ObjectRow::decode(value.body()).ok())
        else {
            return;
        };
        let statement = matches!(
            row.kind(),
            Ok(ArcWireObjectKind::ConversationBinding
                | ArcWireObjectKind::LeafMembershipProof
                | ArcWireObjectKind::Policy)
        );
        if statement {
            let id = *agenc_relay_e2ee::ObjectId::compute(&row.bytes).as_bytes();
            self.objects.insert(id, row.bytes);
        }
    }

    /// Records a route, membership or policy row.
    fn row(&mut self, write: &Write, key: &StoredKey) {
        let Some((_, _, encoded)) = write.encoded_record() else {
            return;
        };
        let Ok(value) = PersistentRecordValue::decode(TableId::E2eeState, encoded) else {
            return;
        };
        match value.record_kind() {
            ROUTE_ROW_KIND => self.route(key, value.body()),
            SEQUENCER_ROW_KIND => self.statement(key, value.body()),
            _ => {}
        }
    }

    /// Records the binding a route row names.
    fn route(&mut self, key: &StoredKey, body: &[u8]) {
        if let (Ok(conversation), Ok(row)) = (RouteRow::parse_key(key), RouteRow::decode(body)) {
            self.routes.insert(conversation, row.binding_id);
        }
    }

    /// Records the proof a membership row names or the policy a policy row
    /// names.
    fn statement(&mut self, key: &StoredKey, body: &[u8]) {
        match SequencerRow::decode(body) {
            Ok(SequencerRow::Membership { object_id, .. }) => {
                let conversation = SequencerRow::parse_membership_key(key).ok();
                let proof = conversation.map(|(conversation, ..)| (conversation, object_id));
                self.proofs.extend(proof);
            }
            Ok(SequencerRow::Policy { object_id, .. }) => {
                let conversation = SequencerRow::parse_policy_key(key).ok();
                let policy = conversation.map(|(conversation, _)| (conversation, object_id));
                self.policies.extend(policy);
            }
            _ => {}
        }
    }

    /// A statement object the batch stages, or one already resident.
    fn object<'a>(&'a self, state: &'a CompanionState, id: &[u8; 32]) -> Option<&'a [u8]> {
        self.objects
            .get(id)
            .or_else(|| state.objects.get(id))
            .map(Vec::as_slice)
    }

    /// The principal accounts of `conversation`'s binding: the package this
    /// batch stages for it, or the retained conversation's.
    fn principals(&self, state: &CompanionState, conversation: &[u8; 32]) -> Vec<[u8; 24]> {
        match self.packages.get(conversation) {
            Some(package) => principal_accounts(package),
            None => state
                .conversations
                .get(conversation)
                .map(|retained| retained.principal_accounts.clone())
                .unwrap_or_default(),
        }
    }

    /// Whether `conversation` has a route row once the batch commits.
    fn routed(&self, state: &CompanionState, conversation: &[u8; 32]) -> bool {
        !self.deleted.contains(conversation)
            && (self.routes.contains_key(conversation)
                || state.conversations.contains_key(conversation))
    }
}

/// The principal accounts `package`'s binding names.
fn principal_accounts(package: &ArcConversationBindingPackage) -> Vec<[u8; 24]> {
    let principals = package.binding.tbs.principals.as_slice();
    principals
        .iter()
        .filter_map(|principal| <[u8; 24]>::try_from(principal.account_id.as_slice()).ok())
        .collect()
}

/// Every resident roster a restored conversation's binding, stored proofs
/// and retained policies name.
pub(super) fn of_conversation(
    state: &CompanionState,
    network_id: &[u8; 32],
    conversation: &ConversationState,
    resolved: &mut Resolved,
) -> BTreeSet<[u8; 32]> {
    let mut held = state
        .objects
        .get(&conversation.binding_object_id)
        .and_then(|bytes| package(bytes))
        .map(|package| of_binding(state, &package))
        .unwrap_or_default();
    let proofs = conversation.memberships.iter();
    held.extend(proofs.filter_map(|entry| named(state, &entry.proof.roster_id)));
    let principals = &conversation.principal_accounts;
    for retained in conversation.policies.values() {
        let policy = state
            .objects
            .get(&retained.object_id)
            .and_then(|bytes| policy(bytes));
        let verifying =
            policy.map(|policy| of_policy(state, network_id, principals, &policy, resolved));
        held.extend(verifying.into_iter().flatten());
    }
    held
}

/// The certificates `policy` names, by root: its finality principals' and
/// its approvals' (companion 9.3), as the policy's verification requires
/// them of one roster per root.
fn certificates_of(policy: &ArcPolicy) -> BTreeMap<[u8; 32], Certificates> {
    let mut required: BTreeMap<[u8; 32], Certificates> = BTreeMap::new();
    for principal in policy.tbs.finality_principals.as_slice() {
        required
            .entry(principal.root_fingerprint)
            .or_default()
            .insert((principal.device_id, principal.device_certificate_id));
    }
    for approval in policy.approvals.as_slice() {
        required
            .entry(approval.signer_root_fingerprint)
            .or_default()
            .insert((
                approval.signer_device_id,
                approval.signer_device_certificate_id,
            ));
    }
    required
}

/// The verified root `fingerprint` names among `principals`' root chains:
/// an account's current root, or an earlier root of its re-verified chain.
fn root_of(
    state: &CompanionState,
    network_id: &[u8; 32],
    principals: &[[u8; 24]],
    fingerprint: &[u8; 32],
) -> Option<VerifiedRoot> {
    principals.iter().find_map(|account| {
        let digest = account_id_digest(network_id, account).ok()?;
        let current = state.principals.get(&digest).map(|(root, _)| *root);
        if let Some(root) = current.filter(|root| root.fingerprint == *fingerprint) {
            return Some(root);
        }
        let roots = super::startup::principal_roots(state, network_id, account)?;
        roots
            .into_iter()
            .find(|root| root.fingerprint == *fingerprint)
    })
}

/// The earliest resident roster of `root`, by roster generation, that holds
/// every certificate in `certificates` and verifies under `root`. The scan
/// starts at the latest generation an enrollment of these certificates
/// targeted, as the account's current roster records it; no roster below
/// that generation verifies with them, so the start changes only the work.
fn earliest(
    state: &CompanionState,
    root: &VerifiedRoot,
    certificates: &Certificates,
) -> Option<[u8; 32]> {
    let floor = enrollment_floor(state, root, certificates);
    let first = (root.fingerprint, floor, [0; 32]);
    let last = (root.fingerprint, u64::MAX, [u8::MAX; 32]);
    state
        .roster_generations
        .range(first..=last)
        .find_map(|(_, _, object)| {
            let roster: ArcDeviceRoster = decode(
                state.objects.get(object)?,
                ArcWireObjectKind::DeviceRoster,
                MAX_ROSTER_OBJECT,
            )?;
            if !holds_all(&roster, certificates) {
                return None;
            }
            let verified = restore_roster(root, &roster).ok()?;
            let held = |(device, id): &([u8; 16], [u8; 32])| {
                verified
                    .device(device)
                    .is_some_and(|certificate| certificate.certificate_id == *id)
            };
            certificates.iter().all(held).then_some(*object)
        })
}

/// The latest roster generation an enrollment of `certificates` targeted,
/// read from the account's current roster when it holds them all under
/// `root`, else zero.
fn enrollment_floor(
    state: &CompanionState,
    root: &VerifiedRoot,
    certificates: &Certificates,
) -> u64 {
    let current = account_id_digest(&root.network_id, &root.account_id)
        .ok()
        .and_then(|digest| state.principals.get(&digest))
        .filter(|(_, roster)| roster.root_fingerprint == root.fingerprint);
    let targeted = current.and_then(|(_, roster)| {
        let enrolled = certificates.iter().map(|(device, id)| {
            roster
                .device(device)
                .filter(|certificate| certificate.certificate_id == *id)
                .map(|certificate| certificate.target_roster_generation)
        });
        enrolled.collect::<Option<Vec<u64>>>()
    });
    targeted
        .and_then(|generations| generations.into_iter().max())
        .unwrap_or(0)
}

/// Whether `roster` lists every certificate in `certificates` as active,
/// before the roster is verified.
fn holds_all(roster: &ArcDeviceRoster, certificates: &Certificates) -> bool {
    let active = roster.tbs.active_devices.as_slice();
    certificates.iter().all(|(device, id)| {
        active.iter().any(|entry| {
            entry.device_id == *device
                && semantic_id_of(
                    SemanticHashDomain::DeviceCertificateId,
                    &entry.certificate.tbs,
                )
                .is_ok_and(|computed| computed == *id)
        })
    })
}
