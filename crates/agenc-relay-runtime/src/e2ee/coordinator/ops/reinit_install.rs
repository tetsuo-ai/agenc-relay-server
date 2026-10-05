//! The successor a quorum-activated ReInit installs (companion 13.8): the
//! target the activated attempt carries names the successor's binding,
//! published policy and sequencer credential, and the coordinator stores
//! them with the remapped route in the transaction that stores the
//! activation certificate, before any reply or event for that activation.
//! No `EGROUP RESERVE` or `EGROUP BIND` precedes the successor's traffic.

#![forbid(unsafe_code)]

use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_domain::e2ee::sequencer_log::SequencerLog;
use agenc_relay_domain::e2ee::{ConversationId, RouteTable, RouteTarget};
use agenc_relay_e2ee::E2eeError;
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::limits::MAX_REINIT_OBJECT;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::{
    ArcConversationBindingPackage, ArcInitialMemberPlan, ArcInitialMemberPlanEntry,
    ArcKeyPackagePlan, ArcMlsContext,
};
use agenc_relay_e2ee::objects::federation::ArcRouteStateKind;
use agenc_relay_e2ee::objects::reinit::ArcReInitAttempt;
use agenc_relay_e2ee::policy::verify_policy;
use agenc_relay_e2ee::route::verify_binding_package;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsEncode, TlsVec};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::TableId;
use agenc_relay_storage::e2ee_records::{
    ROUTE_ROW_KIND, RouteLifecycle as RowLifecycle, RouteRow, SEQUENCER_ROW_KIND, SequencerRow,
};
use agenc_relay_types::ServerId;

use super::super::request::state_row;
use super::super::{CompanionCoordinator, ConversationState, RetainedPolicy};
use super::{Exec, Fail};
use crate::state_core::durable::AccountServiceDurableWrite;

/// The successor one activation installs, staged for the activation's batch.
pub(super) struct Install {
    /// The successor conversation.
    pub(super) conversation_id: [u8; 32],
    /// The route table with the old route remapped to the successor.
    pub(super) routes: RouteTable,
    /// The successor's retained facts.
    pub(super) state: ConversationState,
    /// The successor's log, anchored at the activation.
    pub(super) log: SequencerLog,
    /// The successor's rows and objects.
    pub(super) writes: Vec<AccountServiceDurableWrite>,
    /// The successor's route state object.
    pub(super) route_object: Vec<u8>,
    /// The edges the successor's route is delivered to: the edges holding
    /// the channel, or the home edge of a direct conversation.
    pub(super) hosts: Vec<ServerId>,
    /// Whether the successor is a direct conversation.
    pub(super) direct: bool,
}

/// The binding package a successor's activation installs: the binding the
/// target's context names as current, with the initial member plan the
/// attempt's KeyPackage plan forms (its device tuples and capability IDs in
/// the plan's order) and no root binding lock (companion 13.8).
pub(in crate::e2ee::coordinator) fn package(
    context: &ArcMlsContext,
    plan: &ArcKeyPackagePlan,
) -> Result<ArcConversationBindingPackage, E2eeError> {
    let entries = plan
        .entries
        .as_slice()
        .iter()
        .map(|entry| ArcInitialMemberPlanEntry {
            account_id: entry.account_id.clone(),
            root_fingerprint: entry.root_fingerprint,
            device_id: entry.device_id,
            capability_id: entry.capability_id,
        })
        .collect();
    Ok(ArcConversationBindingPackage {
        binding: context.current_binding.clone(),
        initial_member_plan: ArcInitialMemberPlan {
            entries: TlsVec::new(entries)?,
        },
        root_binding_locks: TlsVec::new(Vec::new())?,
    })
}

/// The complete wire object of `body` under `kind`.
pub(in crate::e2ee::coordinator) fn wire_object(
    kind: ArcWireObjectKind,
    body: &impl TlsEncode,
) -> Result<Vec<u8>, E2eeError> {
    ArcWireObject::new(kind, body.encode()?)?.encode()
}

// agenc-review: focus owner=runtime reviewed=2026-10-05 reason=one activation re-checks the carried target, re-verifies the successor binding and policy, pins an issuing credential, remaps the route and stages every successor row before any reply or event
/// Prepares the installation of the successor of the activation
/// `activation_id`, which completes `attempt` on `old`, whose retained facts
/// are `old_state`: the attempt and the
/// target it carries are checked again against the finalized ReInit Commit
/// and the old binding, the successor's binding package and published
/// policy are the target context's, verified under the rosters the
/// successor binding names, and its pin is that context's sequencer
/// credential, one this coordinator issues receipts under. Any refusal is
/// `E2EE_BINDING_AUTH_INVALID` and retains nothing; an old group without a
/// recorded authority is `E2EE_FINALITY_REQUIRED`.
pub(super) fn prepare(
    exec: &Exec<'_>,
    old: &[u8; 32],
    old_state: &ConversationState,
    attempt: &ArcReInitAttempt,
    activation_id: [u8; 32],
) -> Result<Install, Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, old);
    let companion = &exec.coordinator.state;
    let network_id = &exec.coordinator.network_id;
    let authorized = old_state
        .reinit
        .ok_or_else(|| Fail::with(E2eeReplyCode::FinalityRequired, old))?;
    let _work = super::reinit_authority::reserve_work(exec, old, old_state)?;
    let old_binding = super::reinit_authority::current_binding(companion, network_id, old_state)
        .ok_or_else(invalid)?;
    let mut budget = DecodeBudget::new(MAX_REINIT_OBJECT, 1 << 18);
    let carried = authorized
        .check_attempt(attempt, &old_binding, &mut budget)
        .map_err(|_| invalid())?;
    let context = carried.context();
    let package = package(context, &attempt.key_package_plan).map_err(|_| invalid())?;
    let rosters = super::reinit_authority::named_rosters(companion, network_id, &package)
        .ok_or_else(invalid)?;
    let verified = verify_binding_package(network_id, &package, &rosters).map_err(|_| invalid())?;
    exec.coordinator
        .signers()
        .and_then(|signers| signers.issuing_owner(&verified.sequencer_credential_id))
        .ok_or_else(invalid)?;
    let conversation_id = verified.conversation_id;
    let policy = verify_policy(
        network_id,
        &conversation_id,
        &context.policy,
        &rosters,
        None,
    )
    .map_err(|_| invalid())?;
    let (generation, previous_policy_id) = (policy.generation, policy.previous_policy_id);
    let policy_id = CompanionCoordinator::id_of(SemanticHashDomain::PolicyId, &context.policy.tbs)?;
    let binding_bytes =
        wire_object(ArcWireObjectKind::ConversationBinding, &package).map_err(|_| invalid())?;
    let policy_bytes =
        wire_object(ArcWireObjectKind::Policy, &context.policy).map_err(|_| invalid())?;
    let mut routes = companion.routes.clone();
    let entry = routes
        .install_successor(
            ConversationId(*old),
            super::route::binding_summary(&verified),
        )
        .map_err(|_| invalid())?;
    let log = SequencerLog::from_activation(conversation_id, activation_id);
    let mut state = super::route::bound_state(&verified, &package, &binding_bytes)?;
    state.context_digest =
        semantic_id_of(SemanticHashDomain::ContextHash, context).map_err(|_| invalid())?;
    let policy_object_id = *agenc_relay_e2ee::ObjectId::compute(&policy_bytes).as_bytes();
    state.policies.insert(
        policy_id,
        RetainedPolicy {
            object_id: policy_object_id,
            object_bytes: policy_bytes.len(),
            policy,
        },
    );
    let route_object = super::route::route_state_object(
        exec,
        &state,
        &log,
        verified.route.kind,
        verified.channel_instance_id,
        ArcRouteStateKind::ActiveRoute,
        exec.state_generation,
    )?;
    state.route_object_id = *agenc_relay_e2ee::ObjectId::compute(&route_object).as_bytes();
    let row = RouteRow {
        route_state: route_object.clone(),
        lifecycle: RowLifecycle::Active,
        binding_id: verified.binding_id,
        lock_id: verified.route.lock_id,
        accepted_state_id: activation_id,
        sequencer_head_id: activation_id,
        route_sequence: 0,
        close_id: None,
        predecessor_close_id: state.predecessor_close_id,
        recovery_gate: false,
        stored_bytes: u64::try_from(binding_bytes.len()).unwrap_or(u64::MAX),
        sequencer_credential_id: Some(verified.sequencer_credential_id),
        blocked_credential_id: None,
    };
    let writes = vec![
        CompanionCoordinator::object_write(&binding_bytes)?,
        CompanionCoordinator::object_write(&policy_bytes)?,
        CompanionCoordinator::object_write(&route_object)?,
        state_row(
            TableId::E2eeState,
            ROUTE_ROW_KIND,
            RouteRow::key(&conversation_id).map_err(row_error)?,
            row.encode().map_err(row_error)?,
        )?,
        state_row(
            TableId::E2eeState,
            SEQUENCER_ROW_KIND,
            SequencerRow::policy_key(&conversation_id, &policy_id).map_err(row_error)?,
            SequencerRow::Policy {
                object_id: policy_object_id,
                generation,
                previous_policy_id,
            }
            .encode()
            .map_err(row_error)?,
        )?,
    ];
    let hosts = match entry.target {
        RouteTarget::Channel(channel) => exec
            .peers
            .iter()
            .copied()
            .filter(|peer| (exec.holds_channel)(*peer, channel))
            .collect(),
        RouteTarget::Direct(_) => vec![exec.home],
    };
    Ok(Install {
        conversation_id,
        routes,
        direct: state.direct_accounts.is_some(),
        state,
        log,
        writes,
        route_object,
        hosts,
    })
}

/// A row that does not encode.
fn row_error<E>(_: E) -> Fail {
    Fail::from(E2eeReplyCode::InvalidFragment)
}
