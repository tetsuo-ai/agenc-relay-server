//! The old controllers authorize the exact binding before the relay signs its
//! terminal. BIND subsequently installs that target under a registered grant.
#![forbid(unsafe_code)]

use super::super::request::{Outcome, ResultBody, state_row};
use super::super::{CompanionCoordinator, ConversationState};
use agenc_relay_domain::e2ee::projection::EventKind;
use agenc_relay_domain::e2ee::sequencer_log::{Phase, SequencerLog};
use agenc_relay_domain::e2ee::{ConversationId, ReservationId, RouteEntry, RouteTarget};
use agenc_relay_e2ee::authorization::{CandidateBinding, verify_commit_authorization};
use agenc_relay_e2ee::identity::ValidationTime;
use agenc_relay_e2ee::limits::{MAX_BINDING_CHAIN_BYTES, MAX_BINDING_OBJECT};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::{ArcCommitAuthorizationRule, action_bits};
use agenc_relay_e2ee::objects::conversation::{
    ArcConversationBindingPackage, ArcConversationBindingTbs,
};
use agenc_relay_e2ee::objects::sequencing::ArcFinalizationProof;
use agenc_relay_e2ee::policy::VerifiedPolicy;
use agenc_relay_e2ee::route::PrincipalRosters;
use agenc_relay_e2ee::route::VerifiedBinding;
use agenc_relay_e2ee::route::{continues_admitted_group_binding, verify_replacement_binding};
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::TableId;
use agenc_relay_storage::e2ee_records::binding_admission::{BindingAdmissionRow, KIND};
use agenc_relay_types::{AccountId, ChannelInstanceId, ServerId};

use super::{Exec, Fail};

/// Checks the old group's authorization separately from the council disposition
/// votes. A vote on a candidate cannot substitute for a controller approval.
pub(super) fn finalized_target(
    exec: &Exec<'_>,
    proof: &ArcFinalizationProof,
    policy: &VerifiedPolicy,
    rosters: &PrincipalRosters,
) -> Result<Option<[u8; 32]>, Fail> {
    let tbs = &proof.authorization.tbs;
    if tbs.action_bits & action_bits::BINDING == 0 {
        return Ok(None);
    }
    let core = &proof.core;
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, &core.conversation_id);
    let state = exec
        .coordinator
        .state
        .conversations
        .get(&core.conversation_id)
        .ok_or_else(invalid)?;
    let lifecycle = exec
        .coordinator
        .state
        .lifecycles
        .get(&core.conversation_id)
        .ok_or_else(invalid)?;
    let key = exec
        .coordinator
        .key_set()
        .and_then(|set| set.credential(&state.sequencer_credential_id))
        .ok_or_else(invalid)?;
    if lifecycle.bootstrap_pending()
        || lifecycle.pending_join().is_some()
        || lifecycle.removal_pending()
        || state.pending_binding.is_some()
        || state.blocked_credential_id.is_some()
    {
        return Err(invalid());
    }
    approved_target(
        proof,
        policy,
        rosters,
        key,
        state.binding,
        state.last_validation_time,
    )
    .ok_or_else(invalid)
    .map(Some)
}

/// Checks the same controller proof and bound clock at admission and on restart.
pub(in crate::e2ee::coordinator) fn approved_target(
    proof: &ArcFinalizationProof,
    policy: &VerifiedPolicy,
    rosters: &PrincipalRosters,
    key: &agenc_relay_e2ee::sequencer::VerifiedSequencerCredential,
    previous_binding: [u8; 32],
    validation_time: u64,
) -> Option<[u8; 32]> {
    let core = &proof.core;
    let tbs = &proof.authorization.tbs;
    if tbs.action_bits != action_bits::BINDING
        || tbs.authorization_rule != ArcCommitAuthorizationRule::ControlledTransition
        || tbs.transition_target_digest == previous_binding
        || tbs.canonical_validation_time != validation_time
        || proof.receipt.tbs.sequencer_key_id != key.credential_id
        || !key.covers(ValidationTime(validation_time))
        || tbs.resulting_group_context_digest != core.resulting_group_context_digest
        || tbs.resulting_ratchet_tree_digest != core.resulting_ratchet_tree_digest
        || tbs.old_policy_id != core.old_policy_id
    {
        return None;
    }
    let candidate = CandidateBinding {
        network_id: core.network_id,
        conversation_id: core.conversation_id,
        prior_epoch: core.prior_epoch,
        prior_state_id: core.prior_state_id,
        candidate_id: core.candidate_id,
        commit_object_id: core.commit_object_id,
    };
    let auth =
        verify_commit_authorization(&proof.authorization, &candidate, policy, rosters).ok()?;
    (auth.authorization_id == core.commit_authorization_id).then_some(tbs.transition_target_digest)
}

/// An operational route may grant its creator a new nonce or concrete channel
/// without vacating its lock. A closed Direct may follow its normal recreation
/// path. A pending ReInit or recovery can never enter this alternative.
pub(super) fn reservation_group(
    exec: &Exec<'_>,
    target: RouteTarget,
) -> Result<Option<ConversationId>, Fail> {
    let state = &exec.coordinator.state;
    let current = match target {
        RouteTarget::Channel(instance) => state.routes.channel_route(&instance),
        RouteTarget::Direct(pair) => state.routes.direct_route(&pair),
    };
    let Some(entry) = current.filter(|entry| entry.authorized_close().is_none()) else {
        return Ok(None);
    };
    let conversation = entry.conversation_id;
    let denied = || Fail::with(E2eeReplyCode::GroupConflict, &conversation.0);
    let group = state
        .conversations
        .get(&conversation.0)
        .ok_or_else(denied)?;
    if !entry.accepts_traffic()
        || !state.routes.is_current(&conversation)
        || !operational(state, &conversation)
        || group.blocked_credential_id.is_some()
        || !group.principal_accounts.contains(&exec.account_id()?)
    {
        return Err(denied());
    }
    if let RouteTarget::Channel(instance) = target {
        let facts = (exec.binding_channel)(instance).ok_or_else(denied)?;
        if !facts.matches_protected_owner(group) {
            return Err(denied());
        }
    }
    Ok(Some(conversation))
}

fn operational(state: &super::super::CompanionState, id: &ConversationId) -> bool {
    let ready = state.lifecycles.get(&id.0).is_some_and(|l| {
        !l.bootstrap_pending() && l.pending_join().is_none() && !l.removal_pending()
    });
    ready
        && state
            .logs
            .get(&id.0)
            .is_some_and(|log| log.phase() == Phase::Open)
}

impl super::BindingChannel {
    fn matches_protected_owner(&self, group: &ConversationState) -> bool {
        self.owner && self.protected && self.name_hash == group.channel_name_hash
    }
}

/// Includes both B-tree entries, the fixed admission and one retired channel.
pub(in crate::e2ee::coordinator) const ADMISSION_BACKING: usize = 1024;

fn accepted_package(bytes: &[u8]) -> Option<ArcConversationBindingPackage> {
    let mut budget = DecodeBudget::new(MAX_BINDING_OBJECT, 1 << 16);
    let object = ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::ConversationBinding),
        &mut budget,
    )
    .ok()?;
    let mut budget = DecodeBudget::new(MAX_BINDING_OBJECT, 1 << 16);
    ArcConversationBindingPackage::decode_exact(object.body(), &mut budget).ok()
}

/// Immutable bootstrap facts also checked when reopening a binding admission.
pub(in crate::e2ee::coordinator) fn preserves_bootstrap(
    old: &ArcConversationBindingTbs,
    next: &ArcConversationBindingTbs,
) -> bool {
    old.initial_policy_id == next.initial_policy_id
        && old.required_operational_policy_id == next.required_operational_policy_id
        && old.initial_member_plan_id == next.initial_member_plan_id
        && old.principals == next.principals
}

struct Handoff<'a> {
    known: &'a ConversationState,
    log: &'a SequencerLog,
    approved: super::super::BindingFinality,
    next: VerifiedBinding,
    chain_bytes: usize,
}

fn current_terminal(
    known: &ConversationState,
    log: &SequencerLog,
    approved: super::super::BindingFinality,
) -> bool {
    log.head().sequence == approved.sequence
        && log.accepted_state_id() == &log.head().record_id
        && known.records.get(&approved.sequence) == Some(&approved.record_object)
        && log.phase() == Phase::Open
}

fn handoff<'a>(
    exec: &Exec<'a>,
    conversation: [u8; 32],
    context: [u8; 32],
    package: &ArcConversationBindingPackage,
    size: usize,
) -> Result<Handoff<'a>, Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, &conversation);
    let state = &exec.coordinator.state;
    let known = state.conversations.get(&conversation).ok_or_else(invalid)?;
    let log = state.logs.get(&conversation).ok_or_else(invalid)?;
    let approved = known
        .pending_binding
        .ok_or_else(|| Fail::with(E2eeReplyCode::FinalityRequired, &conversation))?;
    let previous = state
        .objects
        .get(&known.binding_object_id)
        .and_then(|bytes| accepted_package(bytes))
        .ok_or_else(invalid)?;
    let next =
        verify_replacement_binding(&exec.coordinator.network_id, package).map_err(|_| invalid())?;
    let old = &previous.binding.tbs;
    let tbs = &package.binding.tbs;
    if next.conversation_id != conversation
        || next.previous_binding_id != known.binding
        || !continues_admitted_group_binding(
            &exec.coordinator.network_id,
            old,
            &next,
            &approved.target,
        )
        .map_err(|_| invalid())?
        || !current_terminal(known, log, approved)
        || known.blocked_credential_id.is_some()
        || next.sequencer_credential_id != known.sequencer_credential_id
        || !preserves_bootstrap(old, tbs)
        || context == [0; 32]
        || !known.principal_accounts.contains(&exec.account_id()?)
    {
        return Err(invalid());
    }
    let chain_bytes = known
        .binding_chain_bytes
        .checked_add(size)
        .filter(|n| *n <= MAX_BINDING_CHAIN_BYTES)
        .ok_or_else(|| Fail::with(E2eeReplyCode::ObjectTooLarge, &conversation))?;
    Ok(Handoff {
        known,
        log,
        approved,
        next,
        chain_bytes,
    })
}

/// Install only the exact package authorized at the current sequencer head.
/// The BIND context hash is the authenticated endpoint's assertion about its
/// private group context. It is distinct from the public GroupContext hash.
pub(super) fn install(
    exec: &Exec<'_>,
    grant: [u8; 16],
    conversation: [u8; 32],
    context: [u8; 32],
    package: &ArcConversationBindingPackage,
    bytes: &[u8],
) -> Result<Outcome, Fail> {
    let Handoff {
        known,
        log,
        approved,
        next,
        chain_bytes,
    } = handoff(exec, conversation, context, package, bytes.len())?;
    let state = &exec.coordinator.state;
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, &conversation);
    let owner = AccountId::parse_wire_bytes(&exec.account_id()?).map_err(|_| invalid())?;
    let summary = super::route::binding_summary(&next, &exec.coordinator.network_id)?;
    let mut routes = state.routes.clone();
    state
        .reservations
        .prepare_bind(&mut routes, grant, owner, exec, &summary)
        .ok_or_else(invalid)?;
    let entry = routes
        .replace_reserved_binding(ReservationId(grant), owner, summary, exec.now)
        .map_err(|_| invalid())?;
    let mut replacement = super::route::bound_state(&next, package, bytes)?;
    replacement.stored_bytes = known.stored_bytes;
    replacement.sequencer_credential_id = known.sequencer_credential_id;
    let updated = super::route::refresh_entry(exec, conversation, &replacement, log, &entry)?;
    let row = BindingAdmissionRow {
        conversation_id: conversation,
        generation: next.generation,
        route_sequence: approved.sequence,
        previous_binding_object: known.binding_object_id,
        binding_object: replacement.binding_object_id,
        terminal_record_object: approved.record_object,
        context_digest: context,
        request_object: exec.decoded.request_object_id,
    };
    let mut outcome = Outcome::scalar(ResultBody::Bound {
        conversation_id: conversation,
        binding_id: next.binding_id,
        binding_object_id: row.binding_object,
    });
    outcome.security_mutation = true;
    let channel_entitlements = notify_routes(
        exec,
        &entry,
        &next,
        known,
        &row,
        &updated.route_object,
        &mut outcome,
    )?;
    let permit = exec
        .backing
        .reserve(ADMISSION_BACKING)
        .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?;
    super::super::direct_renewal::forget(exec, &mut outcome, conversation)?;
    outcome.writes.extend(updated.writes);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(state_row(
        TableId::E2eeState,
        KIND,
        row.key().map_err(|_| invalid())?,
        row.encode().map_err(|_| invalid())?,
    )?);
    outcome
        .writes
        .push(super::super::reservations::delete(grant).map_err(|_| invalid())?);
    outcome.effects.push(Box::new(move |state| {
        state.routes = routes;
        state.reservations.remove(grant);
        if let Some(current) = state.conversations.get_mut(&conversation) {
            current.install_binding(replacement, updated.route_object_id, row, chain_bytes);
        }
        state
            .binding_memory
            .insert((conversation, row.generation), permit);
        for (peer, hosts) in channel_entitlements {
            state.entitlements.set_channel(peer, conversation, hosts);
        }
    }));
    Ok(outcome)
}

fn notify_routes(
    exec: &Exec<'_>,
    entry: &RouteEntry,
    next: &VerifiedBinding,
    known: &ConversationState,
    row: &BindingAdmissionRow,
    route: &[u8],
    outcome: &mut Outcome,
) -> Result<Vec<(ServerId, bool)>, Fail> {
    let id = row.conversation_id;
    let channel = match entry.target {
        RouteTarget::Channel(instance) => {
            prepare_channel(exec, instance, next, known, &id, outcome)?;
            Some(instance)
        }
        RouteTarget::Direct(_) => None,
    };
    let mut entitlements = Vec::new();
    for &peer in exec.peers {
        let previous = exec.coordinator.state.entitlements.entitled(peer, &id);
        let visible = match channel {
            Some(instance) => {
                let hosts = (exec.holds_channel)(peer, instance);
                entitlements.push((peer, hosts));
                hosts
            }
            None => previous || peer == exec.home,
        };
        if visible {
            outcome.events.push(exec.event(
                EventKind::RouteStateChanged,
                Some(id),
                peer,
                row.route_sequence,
                Vec::new(),
                Some(route.to_vec()),
            ));
        } else if previous
            && let Some(event) = super::super::direct_release::hidden_copy(exec, peer, id)
        {
            outcome.events.push(event);
        }
    }
    Ok(entitlements)
}

fn prepare_channel(
    exec: &Exec<'_>,
    instance: ChannelInstanceId,
    next: &VerifiedBinding,
    known: &ConversationState,
    id: &[u8; 32],
    outcome: &mut Outcome,
) -> Result<(), Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, id);
    let scope = (exec.binding_channel)(instance).ok_or_else(invalid)?;
    let old = exec
        .coordinator
        .state
        .routes
        .route(&ConversationId(*id))
        .ok_or_else(invalid)?;
    let RouteTarget::Channel(previous) = old.target else {
        return Err(invalid());
    };
    if previous == instance {
        return scope
            .matches_protected_owner(known)
            .then_some(())
            .ok_or_else(invalid);
    }
    if !scope.owner
        || scope.name_hash != known.channel_name_hash
        || scope.protected
        || (exec.binding_channel)(previous).is_some()
    {
        return Err(invalid());
    }
    outcome.base_plan =
        (exec.plan_binding)(instance, &next.principals).map_err(|code| Fail::with(code, id))?;
    Ok(())
}

impl ConversationState {
    fn install_binding(
        &mut self,
        replacement: Self,
        route_object: [u8; 32],
        row: BindingAdmissionRow,
        chain_bytes: usize,
    ) {
        self.binding = replacement.binding;
        self.binding_object_id = row.binding_object;
        self.context_core_id = replacement.context_core_id;
        self.context_digest = row.context_digest;
        self.route_binding = replacement.route_binding;
        self.route_object_id = route_object;
        self.reinit_facts = replacement.reinit_facts;
        self.pending_binding = None;
        self.binding_chain_bytes = chain_bytes;
        self.binding_admissions.insert(row.generation, row);
    }
}
