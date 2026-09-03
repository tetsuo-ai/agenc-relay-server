//! Route operations: application fanout, reservations, binding, queries,
//! and close (companion Sections 11.3 to 11.5, 12.5).

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_ircd_domain::e2ee::lifecycle::Lifecycle;
use agenc_ircd_domain::e2ee::projection::{EntitlementReason, EventKind};
use agenc_ircd_domain::e2ee::sequencer_log::SequencerLog;
use agenc_ircd_domain::e2ee::{
    BindingSummary, ConversationId, DirectPair, ReservationId, SemanticLockId,
};
use agenc_ircd_e2ee::envelope::{RouteExpectation, verify_application_object};
use agenc_ircd_e2ee::limits::{
    MAX_ABORT_OBJECT, MAX_APPLICATION_MLS_OBJECT, MAX_BINDING_OBJECT, MAX_CAPABILITY_OBJECT,
    MAX_CLOSE_OBJECT, MAX_COMMIT_ACK_OBJECT, MAX_COMMIT_APPROVAL_OBJECT, MAX_FINALIZATION_OBJECT,
    MAX_IDENTITY_OBJECT, MAX_KEY_PACKAGE_OBJECT, MAX_LIVE_FRAGMENT_COUNT, MAX_LIVE_OBJECT,
    MAX_MAILBOX_FRAGMENT_COUNT, MAX_REINIT_OBJECT, MAX_ROOT_CHAIN_OBJECT, MAX_ROSTER_OBJECT,
    MAX_WELCOME_MAILBOX_OBJECT, RESERVATION_TIMEOUT_SECONDS,
};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::{
    IrcCloseAuthorization, IrcConversationBindingPackage, IrcConversationKind, IrcReservation,
    IrcReservationTbs,
};
use agenc_ircd_e2ee::objects::federation::{IrcFederationRouteState, IrcRouteStateKind};
use agenc_ircd_e2ee::objects::sequencing::IrcGroupGenesisTbs;
use agenc_ircd_e2ee::route::{
    PrincipalRosters, channel_name_hash, channel_route_binding, close_authorization_id,
    direct_route_binding, verify_binding_package,
};
use agenc_ircd_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{
    CLAIM_ROW_KIND, ClaimRow, ROUTE_ROW_KIND, RouteLifecycle as RowLifecycle, RouteRow,
};
use agenc_ircd_types::{AccountId, ChannelInstanceId, ServerId};

use super::super::request::{Outcome, ResponseObject, ResultBody, state_row};
use super::super::{CompanionCoordinator, ConversationState};
use super::{Exec, Fail, account};

fn conversation_state<'a>(
    exec: &Exec<'a>,
    conversation_id: &[u8; 32],
) -> Result<&'a ConversationState, Fail> {
    exec.coordinator
        .state
        .conversations
        .get(conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, conversation_id))
}

/// The route expectation every object on `conversation_id` must name.
pub fn expectation_for(
    exec: &Exec<'_>,
    conversation_id: [u8; 32],
) -> Result<RouteExpectation, Fail> {
    expectation(exec, conversation_id)
}

fn expectation(exec: &Exec<'_>, conversation_id: [u8; 32]) -> Result<RouteExpectation, Fail> {
    let state = conversation_state(exec, &conversation_id)?;
    let group_id: [u8; 32] = state
        .group_id
        .as_slice()
        .try_into()
        .map_err(|_| Fail::from(E2eeReplyCode::RouteInvalid))?;
    Ok(RouteExpectation {
        network_id: exec.coordinator.network_id,
        conversation_id,
        route_binding: state.route_binding,
        group_id,
    })
}

/// The audience of a semantic event on `conversation_id`.
pub fn audience(exec: &Exec<'_>, conversation_id: &[u8; 32]) -> Result<Vec<ServerId>, Fail> {
    let route = exec
        .coordinator
        .state
        .routes
        .route(&ConversationId(*conversation_id))
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, conversation_id))?;
    Ok(match route.target {
        agenc_ircd_domain::e2ee::RouteTarget::Channel(channel) => (exec.hosting)(channel),
        agenc_ircd_domain::e2ee::RouteTarget::Direct(_) => {
            let state = conversation_state(exec, conversation_id)?;
            let (a, b) = state
                .direct_accounts
                .ok_or_else(|| Fail::from(E2eeReplyCode::RouteInvalid))?;
            let mut edges = (exec.attached_edges)(&digest(exec, &a)?);
            edges.extend((exec.attached_edges)(&digest(exec, &b)?));
            edges.sort();
            edges.dedup();
            edges
        }
    })
}

fn digest(exec: &Exec<'_>, account: &[u8; 24]) -> Result<[u8; 32], Fail> {
    agenc_ircd_e2ee::ids::account_id_digest(&exec.coordinator.network_id, account)
        .map_err(|_| E2eeReplyCode::InvalidFragment.into())
}

/// Whether the requester's account is bound to `conversation_id`.
fn sender_bound(exec: &Exec<'_>, conversation_id: &[u8; 32]) -> Result<(), Fail> {
    let account = exec.account_id()?;
    let route = exec
        .coordinator
        .state
        .routes
        .route(&ConversationId(*conversation_id))
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, conversation_id))?;
    let bound = match route.target {
        agenc_ircd_domain::e2ee::RouteTarget::Channel(channel) => (exec.channel_member)(channel),
        agenc_ircd_domain::e2ee::RouteTarget::Direct(_) => {
            conversation_state(exec, conversation_id)?
                .direct_accounts
                .is_some_and(|(a, b)| a == account || b == account)
        }
    };
    if !bound || !route.accepts_traffic() {
        return Err(Fail::with(E2eeReplyCode::RouteInvalid, conversation_id));
    }
    Ok(())
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the application envelope against route state and stages the object, the replay row, and the fanout events as one atomic set
/// `application_channel` and `application_direct`.
pub fn application(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let channel = exec.opcode()
        == agenc_ircd_e2ee::objects::federation::IrcFederationOpcode::ApplicationChannel;
    let (conversation_id, instance) = exec.params().read(|reader| {
        let conversation = reader.fixed::<32>()?;
        let instance = if channel {
            Some(reader.fixed::<16>()?)
        } else {
            None
        };
        Ok((conversation, instance))
    })?;
    exec.attached_device()?;
    sender_bound(exec, &conversation_id)?;
    let (object, bytes) = exec.payload()?;
    let log = exec
        .coordinator
        .state
        .logs
        .get(&conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    let lifecycle = exec
        .coordinator
        .state
        .lifecycles
        .get(&conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    lifecycle
        .check_application(log)
        .map_err(|_| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    if let Some(instance) = instance {
        let matches = exec
            .coordinator
            .state
            .routes
            .channel_route(&ChannelInstanceId::from_bytes(instance))
            .is_some_and(|route| route.conversation_id.0 == conversation_id);
        if !matches {
            return Err(Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id));
        }
    }
    let mut budget = DecodeBudget::new(MAX_APPLICATION_MLS_OBJECT, 4_096);
    verify_application_object(object, &expectation(exec, conversation_id)?, &mut budget)
        .map_err(|_| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    let kind = if channel {
        EventKind::ChannelApplication
    } else {
        EventKind::DirectApplication
    };
    let mut outcome = Outcome::scalar(ResultBody::AcceptedEvent);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    for target in audience(exec, &conversation_id)? {
        outcome.events.push(exec.event(
            kind,
            Some(conversation_id),
            target,
            log.head().sequence,
            Vec::new(),
            Some(bytes.to_vec()),
        ));
    }
    let retained = bytes.to_vec();
    outcome.effects.push(Box::new(move |state| {
        let _ = CompanionCoordinator::retain_object(state, retained);
    }));
    Ok(outcome)
}

fn reservation_tbs(
    exec: &mut Exec<'_>,
    reservation_id: [u8; 16],
    kind: IrcConversationKind,
    route_binding: [u8; 32],
    instance: Option<[u8; 16]>,
    nonce: Option<[u8; 32]>,
) -> Result<IrcReservationTbs, Fail> {
    let sequencer = exec
        .coordinator
        .current_credential()
        .cloned()
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let limit = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
    Ok(IrcReservationTbs {
        profile_version: 1,
        network_id: exec.coordinator.network_id,
        reservation_id,
        kind,
        route_binding,
        channel_instance_id: Opaque::new(instance.map_or_else(Vec::new, |id| id.to_vec()))
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        conversation_nonce: Opaque::new(nonce.map_or_else(Vec::new, |id| id.to_vec()))
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        sequencer,
        application_object_limit: limit(MAX_APPLICATION_MLS_OBJECT),
        live_object_limit: limit(MAX_LIVE_OBJECT),
        key_package_object_limit: limit(MAX_KEY_PACKAGE_OBJECT),
        identity_object_limit: limit(MAX_IDENTITY_OBJECT),
        root_chain_object_limit: limit(MAX_ROOT_CHAIN_OBJECT),
        roster_object_limit: limit(MAX_ROSTER_OBJECT),
        capability_object_limit: limit(MAX_CAPABILITY_OBJECT),
        binding_object_limit: limit(MAX_BINDING_OBJECT),
        commit_approval_object_limit: limit(MAX_COMMIT_APPROVAL_OBJECT),
        commit_ack_object_limit: limit(MAX_COMMIT_ACK_OBJECT),
        finalization_object_limit: limit(MAX_FINALIZATION_OBJECT),
        abort_object_limit: limit(MAX_ABORT_OBJECT),
        reinit_object_limit: limit(MAX_REINIT_OBJECT),
        close_object_limit: limit(MAX_CLOSE_OBJECT),
        welcome_object_limit: limit(MAX_WELCOME_MAILBOX_OBJECT),
        live_part_limit: u16::try_from(MAX_LIVE_FRAGMENT_COUNT).unwrap_or(u16::MAX),
        mailbox_part_limit: u16::try_from(MAX_MAILBOX_FRAGMENT_COUNT).unwrap_or(u16::MAX),
        expires_at: exec
            .now
            .checked_add(RESERVATION_TIMEOUT_SECONDS)
            .ok_or_else(|| Fail::from(E2eeReplyCode::RateLimited))?,
    })
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler validates the reservation, checks the lock slot, and stages the reservation and lock rows as one atomic set
/// `reserve_channel` and `reserve_direct`.
pub fn reserve(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let channel =
        exec.opcode() == agenc_ircd_e2ee::objects::federation::IrcFederationOpcode::ReserveChannel;
    let requester = exec.account_id()?;
    exec.attached_device()?;
    let reservation_id: [u8; 16] = exec.random()?;
    let (kind, route_binding, instance, nonce, pair) = if channel {
        let (instance, name) = exec.params().read(|reader| {
            let instance = reader.fixed::<16>()?;
            let name = reader.opaque(1, 255)?;
            Ok((instance, name))
        })?;
        agenc_ircd_e2ee::route::canonical_channel_name(&name)
            .map_err(|_| Fail::from(E2eeReplyCode::RouteInvalid))?;
        if !(exec.channel_member)(ChannelInstanceId::from_bytes(instance)) {
            return Err(Fail::with(E2eeReplyCode::RouteInvalid, &instance));
        }
        let binding = channel_route_binding(&exec.coordinator.network_id, &instance)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        (
            IrcConversationKind::Channel,
            binding,
            Some(instance),
            None,
            None,
        )
    } else {
        let peer = exec.params().read(account)?;
        let nonce: [u8; 32] = exec.random()?;
        let first = AccountId::parse_wire_bytes(&requester)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        let second = AccountId::parse_wire_bytes(&peer)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        let pair =
            DirectPair::new(first, second).map_err(|_| Fail::from(E2eeReplyCode::RouteInvalid))?;
        let (a, b) = if requester <= peer {
            (requester, peer)
        } else {
            (peer, requester)
        };
        let binding = direct_route_binding(&exec.coordinator.network_id, &nonce, &a, &b)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        (
            IrcConversationKind::Direct,
            binding,
            None,
            Some(nonce),
            Some(pair),
        )
    };
    let tbs = reservation_tbs(exec, reservation_id, kind, route_binding, instance, nonce)?;
    let signer = exec
        .coordinator
        .signer()
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let reservation = IrcReservation {
        sequencer_signature: signer
            .sign(SignatureDomain::Reservation, &tbs)
            .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
        tbs,
    };
    let body = reservation
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let bytes = IrcWireObject::new(IrcWireObjectKind::Reservation, body)
        .and_then(|object| object.encode())
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes();
    let expires_at = reservation.tbs.expires_at;
    let owner = AccountId::parse_wire_bytes(&requester)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let mut probe = exec.coordinator.state.routes.clone();
    let claim = match (instance, pair) {
        (Some(instance), None) => probe.reserve_channel(
            ReservationId(reservation_id),
            ChannelInstanceId::from_bytes(instance),
            owner,
            expires_at,
        ),
        (None, Some(pair)) => probe.reserve_direct(
            ReservationId(reservation_id),
            pair,
            nonce.unwrap_or([0; 32]),
            owner,
            expires_at,
        ),
        _ => return Err(E2eeReplyCode::InvalidFragment.into()),
    };
    claim.map_err(|_| Fail::from(E2eeReplyCode::GroupConflict))?;
    let mut outcome = Outcome::scalar(ResultBody::Reserved(reservation_id, object_id));
    outcome.snapshot_token = Some(exec.random()?);
    outcome.responses.push(ResponseObject {
        bytes: bytes.clone(),
        delivery_token: None,
        target_device_id: None,
    });
    outcome
        .writes
        .push(CompanionCoordinator::object_write(&bytes)?);
    let row = ClaimRow::Reservation {
        owner_account_digest: exec.account_digest()?,
        owner_device_id: exec.attached_device()?.0,
        kind: u16::from(kind.value()),
        lock_id: [0; 32],
        route_binding,
        reservation_object_id: object_id,
        expires_at,
    };
    outcome.writes.push(state_row(
        TableId::E2eeState,
        CLAIM_ROW_KIND,
        ClaimRow::reservation_key(&reservation_id)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        row.encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    outcome.effects.push(Box::new(move |state| {
        state.routes = probe;
        let _ = CompanionCoordinator::retain_object(state, bytes);
    }));
    Ok(outcome)
}

fn principals(
    exec: &Exec<'_>,
    package: &IrcConversationBindingPackage,
) -> Result<PrincipalRosters, Fail> {
    let mut rosters = PrincipalRosters::new();
    for principal in package.binding.tbs.principals.as_slice() {
        let account: [u8; 24] = principal
            .account_id
            .as_slice()
            .try_into()
            .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
        let (root, roster) = exec
            .coordinator
            .state
            .principals
            .get(&digest(exec, &account)?)
            .ok_or_else(|| Fail::with(E2eeReplyCode::BindingAuthInvalid, &account))?;
        rosters.insert(account, (*root, roster.clone()));
    }
    Ok(rosters)
}

fn route_state_object(
    exec: &Exec<'_>,
    state: &ConversationState,
    log: &SequencerLog,
    kind: IrcConversationKind,
    instance: Option<[u8; 16]>,
    route_kind: IrcRouteStateKind,
    state_generation: u64,
) -> Result<Vec<u8>, Fail> {
    let (a, b) = state.direct_accounts.unwrap_or(([0; 24], [0; 24]));
    let direct = state.direct_accounts.is_some();
    let route = IrcFederationRouteState {
        profile_version: 1,
        network_id: exec.coordinator.network_id,
        state_generation,
        conversation_id: *log.conversation_id(),
        conversation_kind: kind,
        route_binding: state.route_binding,
        semantic_route_lock_id: state.lock_id,
        channel_instance_id: Opaque::new(instance.map_or_else(Vec::new, |id| id.to_vec()))
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        canonical_channel_name_hash: state.channel_name_hash,
        direct_account_a: Opaque::new(if direct { a.to_vec() } else { Vec::new() })
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        direct_account_b: Opaque::new(if direct { b.to_vec() } else { Vec::new() })
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        binding_id: state.binding_id(),
        finalized_epoch: log.accepted_epoch(),
        accepted_state_id: *log.accepted_state_id(),
        sequencer_record_head_sequence: log.head().sequence,
        sequencer_record_head_id: log.head().record_id,
        state: route_kind,
    };
    let body = route
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    IrcWireObject::new(IrcWireObjectKind::FederationState, body)
        .and_then(|object| object.encode())
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the binding package, derives genesis, and stages the route row, objects, events, and commit effects as one atomic set
/// `bind_group`.
pub fn bind(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (reservation_id, conversation_id, context_digest) = exec.params().read(|reader| {
        Ok((
            reader.fixed::<16>()?,
            reader.fixed::<32>()?,
            reader.fixed::<32>()?,
        ))
    })?;
    let account = exec.account_id()?;
    exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    let mut budget = DecodeBudget::new(MAX_BINDING_OBJECT, 1 << 16);
    let package = IrcConversationBindingPackage::decode_exact(object.body(), &mut budget)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    let rosters = principals(exec, &package)?;
    let verified = verify_binding_package(&exec.coordinator.network_id, &package, &rosters)
        .map_err(|_| Fail::with(E2eeReplyCode::BindingAuthInvalid, &conversation_id))?;
    if verified.conversation_id != conversation_id {
        return Err(Fail::with(
            E2eeReplyCode::BindingAuthInvalid,
            &conversation_id,
        ));
    }
    let owner = AccountId::parse_wire_bytes(&account)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let summary = BindingSummary {
        conversation_id: ConversationId(conversation_id),
        lock: SemanticLockId(verified.route.lock_id),
        incarnation: verified.route.incarnation,
        predecessor_close_id: verified.route.predecessor_close_id,
        binding_id: verified.binding_id,
        binding_generation: verified.generation,
        previous_binding_id: verified.previous_binding_id,
        channel_instance_id: verified
            .channel_instance_id
            .map(ChannelInstanceId::from_bytes),
        conversation_nonce: verified.conversation_nonce,
    };
    let mut routes = exec.coordinator.state.routes.clone();
    let entry = routes
        .bind(ReservationId(reservation_id), owner, summary, exec.now)
        .map_err(|conflict| match conflict {
            agenc_ircd_domain::e2ee::RouteConflict::GroupConflict
            | agenc_ircd_domain::e2ee::RouteConflict::ForkedLineage => {
                Fail::with(E2eeReplyCode::GroupConflict, &conversation_id)
            }
            _ => Fail::with(E2eeReplyCode::BindingAuthInvalid, &conversation_id),
        })?;
    let genesis = IrcGroupGenesisTbs {
        network_id: exec.coordinator.network_id,
        conversation_id,
        group_id: package.binding.tbs.group_id.clone(),
        binding_id: verified.binding_id,
        context_core_id: verified.context_core_id,
    };
    let genesis_id = CompanionCoordinator::id_of(SemanticHashDomain::GroupGenesisId, &genesis)?;
    let log = SequencerLog::genesis(conversation_id, genesis_id);
    let kind = verified.route.kind;
    let direct_accounts = match verified.principals.as_slice() {
        [a, b] if kind == IrcConversationKind::Direct => Some((*a, *b)),
        _ => None,
    };
    let channel_name_hash = match &verified.route.key {
        agenc_ircd_e2ee::route::SemanticRouteKey::Channel { canonical_name, .. } => {
            channel_name_hash(canonical_name)
                .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?
        }
        agenc_ircd_e2ee::route::SemanticRouteKey::Direct { .. } => [0; 32],
    };
    let state = ConversationState {
        binding_object_id: *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes(),
        context_core_id: verified.context_core_id,
        context_digest,
        cipher_suite: verified.cipher_suite,
        group_id: package.binding.tbs.group_id.as_slice().to_vec(),
        route_binding: verified.route_binding,
        lock_id: verified.route.lock_id,
        channel_name_hash,
        direct_accounts,
        binding: verified.binding_id,
        ..ConversationState::default()
    };
    let route_object = route_state_object(
        exec,
        &state,
        &log,
        kind,
        verified.channel_instance_id,
        IrcRouteStateKind::ActiveRoute,
        exec.state_generation,
    )?;
    let mut outcome = Outcome::scalar(ResultBody::Bound {
        conversation_id,
        binding_id: verified.binding_id,
        binding_object_id: state.binding_object_id,
    });
    outcome.security_mutation = true;
    if let Some(instance) = verified.channel_instance_id {
        outcome.base_plan = (exec.plan_binding)(
            ChannelInstanceId::from_bytes(instance),
            &verified.principals,
        )
        .map_err(|code| Fail::with(code, &conversation_id))?;
    }
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(&route_object)?);
    let row = RouteRow {
        route_state: route_object.clone(),
        lifecycle: RowLifecycle::Active,
        binding_id: verified.binding_id,
        lock_id: verified.route.lock_id,
        accepted_state_id: genesis_id,
        sequencer_head_id: genesis_id,
        route_sequence: 0,
        close_id: None,
        predecessor_close_id: (verified.route.incarnation > 0)
            .then_some(verified.route.predecessor_close_id),
        recovery_gate: false,
        stored_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    };
    outcome.writes.push(state_row(
        TableId::E2eeState,
        ROUTE_ROW_KIND,
        RouteRow::key(&conversation_id).map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        row.encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    let targets: Vec<ServerId> = match entry.target {
        agenc_ircd_domain::e2ee::RouteTarget::Channel(channel) => exec
            .peers
            .iter()
            .copied()
            .filter(|peer| (exec.holds_channel)(*peer, channel))
            .collect(),
        agenc_ircd_domain::e2ee::RouteTarget::Direct(_) => vec![exec.home],
    };
    for target in targets {
        outcome.events.push(exec.event(
            EventKind::RouteStateChanged,
            Some(conversation_id),
            target,
            0,
            Vec::new(),
            Some(route_object.clone()),
        ));
    }
    let home = exec.home;
    let retained = bytes.to_vec();
    outcome.effects.push(Box::new(move |companion| {
        companion.routes = routes;
        companion.logs.insert(conversation_id, log);
        companion
            .lifecycles
            .insert(conversation_id, Lifecycle::bootstrap());
        companion.conversations.insert(conversation_id, state);
        let _ = CompanionCoordinator::retain_object(companion, retained);
        let _ = CompanionCoordinator::retain_object(companion, route_object);
        if direct_accounts.is_some() {
            let _ = companion.entitlements.require_direct(
                home,
                conversation_id,
                EntitlementReason::Operation,
            );
        }
    }));
    Ok(outcome)
}

/// `query_channel` and `query_direct`.
pub fn query(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let channel =
        exec.opcode() == agenc_ircd_e2ee::objects::federation::IrcFederationOpcode::QueryChannel;
    let requester = exec.account_id()?;
    let route = if channel {
        let (instance, _name) = exec
            .params()
            .read(|reader| Ok((reader.fixed::<16>()?, reader.opaque(1, 255)?)))?;
        exec.coordinator
            .state
            .routes
            .channel_route(&ChannelInstanceId::from_bytes(instance))
    } else {
        let peer = exec.params().read(account)?;
        let first = AccountId::parse_wire_bytes(&requester)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        let second = AccountId::parse_wire_bytes(&peer)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        let pair =
            DirectPair::new(first, second).map_err(|_| Fail::from(E2eeReplyCode::RouteInvalid))?;
        exec.coordinator.state.routes.direct_route(&pair)
    };
    let Some(route) = route.filter(|route| route.accepts_traffic()) else {
        return Ok(Outcome::scalar(ResultBody::Empty(
            agenc_ircd_domain::e2ee::projection::EmptyKind::Binding,
        )));
    };
    let conversation_id = route.conversation_id.0;
    let state = conversation_state(exec, &conversation_id)?;
    let bytes = exec
        .coordinator
        .state
        .objects
        .get(&state.binding_object_id)
        .cloned()
        .ok_or_else(|| Fail::from(E2eeReplyCode::ObjectNotFound))?;
    let mut outcome = Outcome::scalar(ResultBody::Bound {
        conversation_id,
        binding_id: route.binding_id,
        binding_object_id: state.binding_object_id,
    });
    outcome.snapshot_token = Some(exec.random()?);
    outcome.responses.push(ResponseObject {
        bytes,
        delivery_token: None,
        target_device_id: None,
    });
    Ok(outcome)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the close authorization, tombstones the route, and stages the rows, events, and commit effects as one atomic set
/// `close_group`.
pub fn close(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (conversation_id, _reason) = exec
        .params()
        .read(|reader| Ok((reader.fixed::<32>()?, reader.u16()?)))?;
    exec.attached_device()?;
    sender_bound(exec, &conversation_id)?;
    let (object, bytes) = exec.payload()?;
    let mut budget = DecodeBudget::new(MAX_CLOSE_OBJECT, 1 << 16);
    let close = IrcCloseAuthorization::decode_exact(object.body(), &mut budget)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    let close_id = close_authorization_id(&close)
        .map_err(|_| Fail::with(E2eeReplyCode::BindingAuthInvalid, &conversation_id))?;
    let state = conversation_state(exec, &conversation_id)?;
    let log = exec
        .coordinator
        .state
        .logs
        .get(&conversation_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    let tbs = &close.tbs;
    let authorized = tbs.network_id == exec.coordinator.network_id
        && tbs.conversation_id == conversation_id
        && tbs.binding_id == state.binding
        && state.proofs.contains_key(&tbs.authorizing_terminal_id);
    if !authorized {
        return Err(Fail::with(
            E2eeReplyCode::FinalityRequired,
            &conversation_id,
        ));
    }
    let mut log = log.clone();
    let position = log
        .close(close_id)
        .map_err(|_| Fail::with(E2eeReplyCode::CandidateActive, &conversation_id))?;
    let mut routes = exec.coordinator.state.routes.clone();
    routes
        .begin_close(&ConversationId(conversation_id))
        .and_then(|()| routes.close(&ConversationId(conversation_id), close_id))
        .map_err(|_| Fail::with(E2eeReplyCode::RouteInvalid, &conversation_id))?;
    let kind = if state.direct_accounts.is_some() {
        IrcConversationKind::Direct
    } else {
        IrcConversationKind::Channel
    };
    let instance = exec
        .coordinator
        .state
        .routes
        .route(&ConversationId(conversation_id))
        .and_then(|route| match route.target {
            agenc_ircd_domain::e2ee::RouteTarget::Channel(channel) => Some(*channel.as_bytes()),
            agenc_ircd_domain::e2ee::RouteTarget::Direct(_) => None,
        });
    let route_object = route_state_object(
        exec,
        state,
        &log,
        kind,
        instance,
        IrcRouteStateKind::EncryptedTombstone,
        exec.state_generation,
    )?;
    let mut outcome = Outcome::scalar(ResultBody::Closed {
        conversation_id,
        close_id,
    });
    outcome.security_mutation = true;
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome
        .writes
        .push(CompanionCoordinator::object_write(&route_object)?);
    let row = RouteRow {
        route_state: route_object.clone(),
        lifecycle: RowLifecycle::Tombstone,
        binding_id: state.binding,
        lock_id: state.lock_id,
        accepted_state_id: *log.accepted_state_id(),
        sequencer_head_id: close_id,
        route_sequence: position.route_sequence,
        close_id: Some(close_id),
        predecessor_close_id: None,
        recovery_gate: false,
        stored_bytes: state.stored_bytes,
    };
    outcome.writes.push(state_row(
        TableId::E2eeState,
        ROUTE_ROW_KIND,
        RouteRow::key(&conversation_id).map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        row.encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    let mut encoded = Vec::with_capacity(32);
    encoded.extend_from_slice(&close_id);
    for target in audience(exec, &conversation_id)? {
        outcome.events.push(exec.event(
            EventKind::RouteStateChanged,
            Some(conversation_id),
            target,
            position.route_sequence,
            Vec::new(),
            Some(route_object.clone()),
        ));
        outcome.events.push(exec.event(
            EventKind::Closed,
            Some(conversation_id),
            target,
            position.route_sequence,
            encoded.clone(),
            None,
        ));
    }
    let retained = bytes.to_vec();
    outcome.effects.push(Box::new(move |companion| {
        companion.routes = routes;
        companion.logs.insert(conversation_id, log);
        let _ = CompanionCoordinator::retain_object(companion, retained);
        let route_object_id = *agenc_ircd_e2ee::ObjectId::compute(&route_object).as_bytes();
        let _ = CompanionCoordinator::retain_object(companion, route_object);
        if let Some(state) = companion.conversations.get_mut(&conversation_id) {
            state.route_object_id = route_object_id;
        }
    }));
    Ok(outcome)
}

impl ConversationState {
    /// The binding identifier.
    #[must_use]
    pub const fn binding_id(&self) -> [u8; 32] {
        self.binding
    }
}
