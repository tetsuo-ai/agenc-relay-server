//! Rebuild a group's concrete route from the exact packages and the old
//! sequencer positions that authorized them. Every candidate preceding the
//! handoff is checked against the former route, including its final Commit.

use std::collections::BTreeMap;

use crate::budget::{BackingReservationPort, MemoryPermit};
use agenc_relay_e2ee::limits::MAX_BINDING_CHAIN_BYTES;
use agenc_relay_e2ee::objects::conversation::ArcConversationBindingTbs;
use agenc_relay_e2ee::route::{continues_admitted_group_binding, verify_replacement_binding};
use agenc_relay_storage::e2ee_records::binding_admission::BindingAdmissionRow;

use super::super::CompanionFault;
use super::{
    ArcConversationBindingPackage, ArcWireObjectKind, CompanionState, MAX_BINDING_OBJECT,
    StoredKey, decode_object,
};

type Id = [u8; 32];
pub(super) type Admissions = BTreeMap<u64, BindingAdmissionRow>;

#[derive(Default)]
pub(super) struct Rows {
    groups: BTreeMap<Id, Admissions>,
    memory: BTreeMap<(Id, u64), MemoryPermit>,
}

impl Rows {
    pub(super) fn admit(
        &mut self,
        key: &StoredKey,
        bytes: &[u8],
        port: Option<&BackingReservationPort>,
    ) -> Result<(), CompanionFault> {
        let row =
            BindingAdmissionRow::decode_keyed(key, bytes).map_err(|_| CompanionFault::Storage)?;
        let group = self.groups.entry(row.conversation_id).or_default();
        if group.contains_key(&row.generation) {
            return Err(CompanionFault::Storage);
        }
        if let Some(port) = port {
            let permit = port
                .reserve(super::super::ops::binding_change::ADMISSION_BACKING)
                .map_err(|_| CompanionFault::Ceiling)?;
            self.memory
                .insert((row.conversation_id, row.generation), permit);
        }
        group.insert(row.generation, row);
        Ok(())
    }

    /// Restore only admissions belonging to a durable route, retaining their
    /// memory charges alongside the reconstructed coordinator state.
    pub(super) fn restore(
        self,
        state: &mut CompanionState,
        routes: &BTreeMap<Id, super::RouteRow>,
    ) -> Result<BTreeMap<Id, Admissions>, CompanionFault> {
        if self.groups.keys().any(|id| !routes.contains_key(id)) {
            return Err(CompanionFault::Storage);
        }
        state.binding_memory = self.memory;
        Ok(self.groups)
    }
}

struct Step {
    route: Id,
    target: Id,
    pin: Id,
    record: Id,
}

pub(super) struct Path {
    anchor_binding: Id,
    anchor_pin: Id,
    generation: u64,
    pub(super) previous: Id,
    network: Id,
    conversation: Id,
    retired: Vec<agenc_relay_types::ChannelInstanceId>,
    initial_route: Id,
    // A terminal at sequence N still belongs to the previous binding.
    changes: BTreeMap<u64, Step>,
    pub(super) bytes: usize,
}

impl Path {
    pub(super) fn load(
        state: &CompanionState,
        network: &Id,
        current: Id,
        conversation: Id,
        admissions: Option<&Admissions>,
    ) -> Option<Self> {
        let first = admissions
            .and_then(|m| m.first_key_value())
            .map_or(current, |(_, row)| row.previous_binding_object);
        let mut package = package(state, &first)?;
        if package.binding.tbs.network_id != *network
            || package.binding.tbs.conversation_id != conversation
        {
            return None;
        }
        let mut previous = first;
        let mut path = Self {
            anchor_binding: agenc_relay_e2ee::ids::semantic_id_of(
                super::SemanticHashDomain::BindingId,
                &package.binding.tbs,
            )
            .ok()?,
            anchor_pin: package.binding.tbs.sequencer_credential_id,
            generation: package.binding.tbs.binding_generation,
            previous: package.binding.tbs.previous_binding_id,
            network: *network,
            conversation,
            retired: Vec::new(),
            initial_route: package.binding.tbs.route_binding,
            changes: BTreeMap::new(),
            bytes: state.objects.get(&first)?.len(),
        };
        for row in admissions.into_iter().flat_map(|m| m.values()) {
            if row.previous_binding_object != previous {
                return None;
            }
            package = path.append(state, row, &package.binding.tbs)?;
            previous = row.binding_object;
        }
        (previous == current).then_some(path)
    }

    fn append(
        &mut self,
        state: &CompanionState,
        row: &BindingAdmissionRow,
        old: &ArcConversationBindingTbs,
    ) -> Option<ArcConversationBindingPackage> {
        if row.context_digest == [0; 32]
            || self
                .changes
                .last_key_value()
                .is_some_and(|(prior, _)| *prior >= row.route_sequence)
        {
            return None;
        }
        let next = package(state, &row.binding_object)?;
        let verified = verify_replacement_binding(&self.network, &next).ok()?;
        if verified.generation != row.generation
            || verified.conversation_id != self.conversation
            || !continues_admitted_group_binding(
                &self.network,
                old,
                &verified,
                &verified.binding_id,
            )
            .ok()?
            || !super::super::ops::binding_change::preserves_bootstrap(old, &next.binding.tbs)
        {
            return None;
        }
        self.bytes = self
            .bytes
            .checked_add(state.objects.get(&row.binding_object)?.len())?;
        if self.bytes > MAX_BINDING_CHAIN_BYTES {
            return None;
        }
        let step = Step {
            route: verified.route_binding,
            target: verified.binding_id,
            pin: verified.sequencer_credential_id,
            record: row.terminal_record_object,
        };
        self.changes.insert(row.route_sequence, step);
        if old.channel_instance_id != next.binding.tbs.channel_instance_id {
            let id = old.channel_instance_id.as_slice().try_into().ok()?;
            self.retired
                .push(agenc_relay_types::ChannelInstanceId::from_bytes(id));
        }
        Some(next)
    }

    pub(super) fn route_at(&self, sequence: u64) -> Id {
        self.changes
            .range(..sequence)
            .next_back()
            .map_or(self.initial_route, |(_, step)| step.route)
    }

    pub(super) fn restore_guards(
        &self,
        table: &mut agenc_relay_domain::e2ee::RouteTable,
    ) -> Option<()> {
        for old in &self.retired {
            table
                .retire_binding_channel(
                    agenc_relay_domain::e2ee::ConversationId(self.conversation),
                    *old,
                )
                .ok()?;
        }
        Some(())
    }
}

pub(super) fn package(state: &CompanionState, id: &Id) -> Option<ArcConversationBindingPackage> {
    let bytes = state.objects.get(id)?;
    if agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes() != id {
        return None;
    }
    decode_object(
        state,
        id,
        ArcWireObjectKind::ConversationBinding,
        MAX_BINDING_OBJECT,
    )
}

/// Historical signing credentials may outlive the advertised overlap set.
#[derive(Default)]
pub(super) struct Keys {
    pub(super) active: Option<agenc_relay_e2ee::sequencer::SequencerKeySet>,
    pub(super) history: BTreeMap<Id, agenc_relay_storage::e2ee_records::SequencerHistoryRow>,
}

impl Keys {
    fn credential(
        &self,
        id: &Id,
    ) -> Option<agenc_relay_e2ee::sequencer::VerifiedSequencerCredential> {
        self.active
            .as_ref()
            .and_then(|keys| keys.credential(id))
            .copied()
            .or_else(|| super::super::signer_startup::credential_of(self.history.get(id)?, *id))
    }

    fn successor(&self, id: Id) -> Option<Id> {
        let mut found = None;
        let old = self.credential(&id)?;
        let archived = self
            .history
            .iter()
            .filter(|(_, row)| row.previous_key_id == id)
            .map(|(next, _)| *next);
        let active = self
            .active
            .iter()
            .flat_map(|keys| &keys.credentials)
            .filter(|key| key.previous_key_id == id)
            .map(|key| key.credential_id);
        for next in archived.chain(active) {
            let key = self.credential(&next)?;
            if found.is_some_and(|prior| prior != next)
                || Some(key.generation) != old.generation.checked_add(1)
                || key.key == old.key
            {
                return None;
            }
            found = Some(next);
        }
        found
    }
}

fn finalization(
    state: &CompanionState,
    row: &super::RecordRow,
) -> Option<agenc_relay_e2ee::objects::sequencing::ArcCommitFinalizationCertificate> {
    if row.record_kind != super::FINALIZATION_RECORD {
        return None;
    }
    let record = decode_object(
        state,
        &row.record_object_id,
        ArcWireObjectKind::SequencerRecord,
        super::MAX_SEQUENCER_RECORD_OBJECT,
    )?;
    match record {
        super::ArcSequencerRecord::Finalization(cert) => Some(cert),
        _ => None,
    }
}

/// Compare the separately serialized outward-facing route to the admitted
/// binding and durable sequencer row before indexing any of its targets.
pub(super) fn projection_matches(
    network: &Id,
    conversation: Id,
    row: &super::RouteRow,
    projection: &super::ArcFederationRouteState,
    binding: &ArcConversationBindingTbs,
) -> bool {
    projection.profile_version == 1
        && projection.network_id == *network
        && projection.conversation_id == conversation
        && projection.binding_id == row.binding_id
        && projection.semantic_route_lock_id == row.lock_id
        && matches_concrete_target(projection, binding)
        && matches_row_head(projection, row)
}

fn matches_concrete_target(
    projection: &super::ArcFederationRouteState,
    binding: &ArcConversationBindingTbs,
) -> bool {
    let route = &binding.semantic_route;
    let name_hash = match binding.kind {
        super::ArcConversationKind::Direct => Some([0; 32]),
        super::ArcConversationKind::Channel => {
            agenc_relay_e2ee::route::channel_name_hash(route.canonical_channel_name.as_slice()).ok()
        }
    };
    projection.route_binding == binding.route_binding
        && projection.conversation_kind == binding.kind
        && projection.channel_instance_id.as_slice() == binding.channel_instance_id.as_slice()
        && Some(projection.canonical_channel_name_hash) == name_hash
        && projection.direct_account_a.as_slice() == route.direct_account_a.as_slice()
        && projection.direct_account_b.as_slice() == route.direct_account_b.as_slice()
}

fn matches_row_head(projection: &super::ArcFederationRouteState, row: &super::RouteRow) -> bool {
    use agenc_relay_e2ee::objects::federation::ArcRouteStateKind;
    let kind = match row.lifecycle {
        super::RowLifecycle::Tombstone => ArcRouteStateKind::EncryptedTombstone,
        super::RowLifecycle::Active | super::RowLifecycle::Closing => {
            ArcRouteStateKind::ActiveRoute
        }
    };
    projection.accepted_state_id == row.accepted_state_id
        && projection.sequencer_record_head_id == row.sequencer_head_id
        && projection.sequencer_record_head_sequence == row.route_sequence
        && projection.state == kind
}

pub(super) fn requires_handoff(
    state: &CompanionState,
    index: &super::ObjectIndex,
    rows: &super::SequencerRows,
    id: Id,
    row: &super::RouteRow,
) -> bool {
    let same_group_previous = index
        .bindings
        .get(&row.binding_id)
        .and_then(|(_, current)| index.bindings.get(&current.binding.tbs.previous_binding_id))
        .is_some_and(|(_, previous)| previous.binding.tbs.conversation_id == id);
    same_group_previous
        || rows
            .records
            .range((id, 0)..=(id, u64::MAX))
            .any(|(_, row)| {
                finalization(state, row).is_some_and(|cert| {
                    cert.tbs.request.proof.authorization.tbs.action_bits
                        & super::action_bits::BINDING
                        != 0
                })
            })
}

pub(super) fn anchor(
    state: &CompanionState,
    index: &super::ObjectIndex,
    current: &super::ConversationState,
) -> Option<ArcConversationBindingTbs> {
    if let Some((_, row)) = current.binding_admissions.first_key_value() {
        return Some(package(state, &row.previous_binding_object)?.binding.tbs);
    }
    index
        .bindings
        .get(&current.binding)
        .map(|(_, p)| p.binding.tbs.clone())
}

type Records<'a> = BTreeMap<u64, &'a super::RecordRow>;
type Historical = [(super::VerifiedRoot, super::VerifiedRoster)];

struct Authority {
    policy: Id,
    binding: Id,
    pin: Id,
    operational: bool,
}

pub(super) fn restore_finality(
    state: &CompanionState,
    keys: &Keys,
    records: &Records<'_>,
    path: &Path,
    historical: &Historical,
    head: (u64, Id),
    group: &mut super::ConversationState,
) -> Option<()> {
    let mut authority = Authority {
        policy: group.initial_policy_id,
        binding: path.anchor_binding,
        pin: path.anchor_pin,
        operational: path.generation > 0,
    };
    let mut used = 0;
    let mut accepted = None;
    for (&sequence, &row) in records {
        if row.record_kind != super::FINALIZATION_RECORD {
            continue;
        }
        let cert = finalization(state, row)?;
        if cert.tbs.finalization_id != row.record_id {
            return None;
        }
        accepted = Some((
            cert.tbs.request.proof.core.resulting_epoch,
            cert.tbs.finalization_id,
        ));
        let auth = &cert.tbs.request.proof.authorization.tbs;
        if auth.action_bits & super::action_bits::BINDING != 0 {
            let witness = Witness {
                state,
                keys,
                records,
                path,
                historical,
                sequence,
                row,
                cert: &cert,
            };
            used += usize::from(witness.admit(group, &mut authority)?);
        }
        authority.operational |=
            auth.authorization_rule == super::ArcCommitAuthorizationRule::BootstrapActivation;
        authority.policy = auth.resulting_policy_id;
        if auth.action_bits & super::action_bits::SEQUENCER != 0 {
            authority.pin = keys.successor(authority.pin)?;
        }
    }
    (accepted == Some(head)
        && used == path.changes.len()
        && authority.binding == group.binding
        && authority.pin == group.sequencer_credential_id)
        .then_some(())
}

struct Witness<'a> {
    state: &'a CompanionState,
    keys: &'a Keys,
    records: &'a Records<'a>,
    path: &'a Path,
    historical: &'a Historical,
    sequence: u64,
    row: &'a super::RecordRow,
    cert: &'a agenc_relay_e2ee::objects::sequencing::ArcCommitFinalizationCertificate,
}

impl Witness<'_> {
    fn admit(
        &self,
        group: &mut super::ConversationState,
        authority: &mut Authority,
    ) -> Option<bool> {
        if !authority.operational || group.pending_binding.is_some() {
            return None;
        }
        let target = self.check(group, authority)?;
        if let Some(step) = self.path.changes.get(&self.sequence) {
            if step.target != target
                || step.pin != authority.pin
                || step.record != self.row.record_object_id
            {
                return None;
            }
            authority.binding = target;
            return Some(true);
        }
        if self.records.last_key_value()?.0 != &self.sequence {
            return None;
        }
        group.pending_binding = Some(super::super::BindingFinality {
            target,
            sequence: self.sequence,
            record_object: self.row.record_object_id,
        });
        Some(false)
    }

    fn check(&self, group: &super::ConversationState, authority: &Authority) -> Option<Id> {
        let proof = &self.cert.tbs.request.proof;
        let core = &proof.core;
        let receipt = &proof.receipt.tbs;
        if authority.policy != core.old_policy_id
            || core.commit_object_id != receipt.commit_object_id
            || core.prior_epoch != receipt.prior_epoch
            || core.prior_state_id != receipt.prior_state_id
            || Some(core.resulting_epoch) != core.prior_epoch.checked_add(1)
            || Some(self.sequence) != receipt.route_sequence.checked_add(1)
        {
            return None;
        }
        let key = self.keys.credential(&authority.pin)?;
        self.check_record_pair(&key)?;
        super::super::ops::terminal_proof::finalization(proof).ok()?;
        let policy = &group.policies.get(&core.old_policy_id)?.policy;
        let rosters = self.rosters()?;
        self.quorum(policy, &rosters)?;
        super::super::ops::binding_change::approved_target(
            proof,
            policy,
            &rosters,
            &key,
            authority.binding,
            self.validation_time(group)?,
        )
    }

    fn check_record_pair(
        &self,
        key: &agenc_relay_e2ee::sequencer::VerifiedSequencerCredential,
    ) -> Option<()> {
        let proof = &self.cert.tbs.request.proof;
        let core = &proof.core;
        let receipt = &proof.receipt.tbs;
        let expected = agenc_relay_e2ee::record_authentication::ExpectedRecord {
            network_id: self.path.network,
            conversation_id: self.path.conversation,
            route_sequence: self.sequence,
            predecessor_record_id: core.candidate_id,
            sequencer_credential_id: key.credential_id,
        };
        let candidate = self.records.get(&receipt.route_sequence)?;
        if candidate.record_kind != super::CANDIDATE_RECORD
            || candidate.record_id != core.candidate_id
            || self.row.predecessor_record_id != candidate.record_id
            || !self.row.terminal
            || !self.signed_record(&expected, self.row, key)
        {
            return None;
        }
        let candidate_position = agenc_relay_e2ee::record_authentication::ExpectedRecord {
            route_sequence: receipt.route_sequence,
            predecessor_record_id: candidate.predecessor_record_id,
            ..expected
        };
        let encoded = super::super::ops::sequence::record_bytes(
            &super::ArcSequencerRecord::Candidate(proof.receipt.clone()),
        )
        .ok()?;
        if agenc_relay_e2ee::ObjectId::compute(&encoded).as_bytes() != &candidate.record_object_id
            || !self.signed_record(&candidate_position, candidate, key)
        {
            return None;
        }
        Some(())
    }

    fn signed_record(
        &self,
        expected: &agenc_relay_e2ee::record_authentication::ExpectedRecord,
        row: &super::RecordRow,
        key: &agenc_relay_e2ee::sequencer::VerifiedSequencerCredential,
    ) -> bool {
        let Some(bytes) = self.state.objects.get(&row.record_object_id) else {
            return false;
        };
        let mut budget = super::DecodeBudget::new(super::MAX_SEQUENCER_RECORD_OBJECT, 1 << 18);
        agenc_relay_e2ee::record_authentication::authenticate_record(
            bytes,
            None,
            expected,
            key,
            &mut budget,
        )
        .is_ok_and(|v| {
            v.semantic_id() == &row.record_id && v.object_id().as_bytes() == &row.record_object_id
        })
    }

    fn validation_time(&self, group: &super::ConversationState) -> Option<u64> {
        let core = &self.cert.tbs.request.proof.core;
        let bytes = self.state.objects.get(&core.commit_object_id)?;
        let mut budget = super::DecodeBudget::new(super::MAX_LIVE_OBJECT, 1 << 16);
        let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
            bytes,
            Some(ArcWireObjectKind::CommitMls),
            &mut budget,
        )
        .ok()?;
        let expected = super::RouteExpectation {
            network_id: core.network_id,
            conversation_id: core.conversation_id,
            route_binding: self.path.route_at(self.sequence),
            group_id: group.group_id.as_slice().try_into().ok()?,
        };
        let mut budget = super::DecodeBudget::new(super::MAX_LIVE_OBJECT, 1 << 16);
        let envelope =
            super::verify_commit_object(&object, &expected, &core.prior_state_id, 0, &mut budget)
                .ok()?;
        (envelope.header.epoch == core.prior_epoch).then_some(envelope.aad.validation_time)
    }

    fn rosters(&self) -> Option<super::PrincipalRosters> {
        let request = &self.cert.tbs.request;
        let mut required = super::CertificateReferences::new();
        for approval in request.proof.authorization.approvals.as_slice() {
            required
                .entry(approval.signer_root_fingerprint)
                .or_default()
                .push((
                    approval.signer_device_id,
                    approval.signer_device_certificate_id,
                ));
        }
        for vote in request.votes.as_slice() {
            required
                .entry(vote.signer_root_fingerprint)
                .or_default()
                .push((vote.signer_device_id, vote.signer_device_certificate_id));
        }
        super::with_certificates(self.historical, required)
    }

    fn quorum(
        &self,
        policy: &agenc_relay_e2ee::policy::VerifiedPolicy,
        rosters: &super::PrincipalRosters,
    ) -> Option<()> {
        let receipt = &self.cert.tbs.request.proof.receipt.tbs;
        let slot = super::VoteSlot {
            network_id: receipt.network_id,
            conversation_id: receipt.conversation_id,
            prior_epoch: receipt.prior_epoch,
            prior_state_id: receipt.prior_state_id,
            candidate_sequence: receipt.candidate_sequence,
            predecessor_record_id: receipt.predecessor_record_id,
        };
        let terminal = super::Terminal::finalize(self.cert.tbs.finalization_id);
        let tbs = super::vote_tbs(
            &slot,
            self.cert.tbs.request.proof.core.candidate_id,
            terminal,
        );
        let mut ledger = super::QuorumLedger::new();
        let votes = self.cert.tbs.request.votes.as_slice();
        for vote in votes {
            ledger.record(policy, rosters, &tbs, vote).ok()?;
        }
        (ledger.votes().count() == votes.len() && ledger.quorum_reached(policy, &terminal))
            .then_some(())
    }
}
