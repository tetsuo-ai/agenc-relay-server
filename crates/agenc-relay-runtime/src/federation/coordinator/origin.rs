//! FORIGIN RESET, ADD, UPDATE, DEL, and READY on the coordinator (spec 20.5).

use agenc_relay_domain::federation::{
    OriginBinding, OriginDeclaration, OriginError, OriginKey, OriginPrincipal, OriginStatus,
};
use agenc_relay_federation_wire::{
    AssembledObject, DecodeBudget, FederationFrame, OriginDescriptor, OriginRecord, SchemaObject,
};
use agenc_relay_storage::TableId;
use agenc_relay_storage::federation_records::{
    FederationOriginRecord, ORIGIN_RECORD_KIND, OriginRowStatus, origin_key,
};
use agenc_relay_types::{Generation, ServerId, ServerIncarnation};

use super::{FederationCoordinator, PendingCommit, Violation, grace, request};
use crate::federation::{IngressCharge, LinkId};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;

const ORIGIN_DECODE_BYTES: usize = 4_096;
const ORIGIN_DECODE_VALUES: usize = 64;

/// Accepts FORIGIN RESET for the live incarnation.
pub(super) fn reset(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    incarnation: ServerIncarnation,
) -> Result<(), Violation> {
    let state = coordinator
        .peers
        .get_mut(&peer)
        .ok_or(Violation::Misaddressed)?;
    let live = state.live.as_ref().ok_or(Violation::Phase)?;
    if live.incarnation != incarnation {
        return Err(Violation::Misaddressed);
    }
    context.suspend_federation_peer(peer);
    if state.fence_pending
        || state.phase == agenc_relay_storage::federation_records::PeerPhase::Expired
    {
        return Err(Violation::Origin);
    }
    if state
        .incarnation
        .is_some_and(|previous| previous != incarnation)
        && state.phase != agenc_relay_storage::federation_records::PeerPhase::Clean
    {
        state.fence_pending = true;
        state.grace_deadline = None;
        coordinator.origins.fence_edge(peer);
        grace::cancel_grace(context, peer);
        super::authority::continue_fence(coordinator, context, peer);
        return Err(Violation::Origin);
    }
    coordinator.origins.reset(peer, incarnation);
    if !coordinator.origins.is_resetting(peer, incarnation) {
        return Err(Violation::Origin);
    }
    state.incarnation = Some(incarnation);
    state.phase = agenc_relay_storage::federation_records::PeerPhase::Suspended;
    continue_ready(coordinator, context, peer);
    Ok(())
}

/// Accepts one FORIGIN ADD or UPDATE object.
// agenc-review: allow owner=runtime reviewed=2026-09-02 reason=an origin declaration carries its link peer descriptor object charge and update flag through one validation path
#[allow(clippy::too_many_arguments)]
pub(super) fn declare(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    descriptor: OriginDescriptor,
    object: &AssembledObject,
    charge: Option<IngressCharge>,
    update: bool,
) -> Result<(), Violation> {
    if coordinator.pending.is_some() {
        return Err(Violation::Ceiling);
    }
    let mut budget = DecodeBudget::new(ORIGIN_DECODE_BYTES, ORIGIN_DECODE_VALUES);
    let record = SchemaObject::decode_exact("FederationOrigin", object.as_slice(), &mut budget)
        .and_then(|object| OriginRecord::from_object(&object))
        .map_err(|_| Violation::Codec)?;
    let key = OriginKey {
        home_server_id: peer,
        server_incarnation: record.server_incarnation,
        origin_id: record.origin_id,
    };
    check_descriptor(coordinator, peer, &descriptor, &record, object)?;
    let declaration = OriginDeclaration {
        origin: key,
        generation: record.generation,
        previous_object_id: record.previous_origin_object_id,
        binding: OriginBinding {
            connection_id: record.connection_id,
            connection_nonce: record.connection_nonce,
        },
        principal: principal_of(context, peer, &record)?,
        object_id: *object.object_id().as_bytes(),
    };
    let accepted = if update {
        coordinator.origins.update(declaration)
    } else {
        coordinator.origins.add(declaration)
    };
    accepted.map_err(|_| Violation::Origin)?;
    coordinator
        .origin_objects
        .insert(key, object.as_slice().to_vec());
    let frame = FederationFrame::OriginAck {
        edge_server_id: peer,
        server_incarnation: record.server_incarnation,
        origin_id: record.origin_id,
        generation: record.generation,
        object_id: Some(object.object_id()),
    };
    stage_origin(coordinator, context, link, peer, key, frame, charge)
}

fn check_descriptor(
    coordinator: &FederationCoordinator,
    peer: ServerId,
    descriptor: &OriginDescriptor,
    record: &OriginRecord,
    object: &AssembledObject,
) -> Result<(), Violation> {
    let live_incarnation = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.live.as_ref())
        .map(|live| live.incarnation)
        .ok_or(Violation::Phase)?;
    let matches = record.network_id == coordinator.config.network_id
        && record.home_server_id == peer
        && record.server_incarnation == live_incarnation
        && descriptor.coordinator_server_id == coordinator.config.server_id
        && descriptor.server_incarnation == record.server_incarnation
        && descriptor.origin_id == record.origin_id
        && descriptor.generation == record.generation
        && descriptor.object_id == object.object_id();
    if matches {
        Ok(())
    } else {
        Err(Violation::Misaddressed)
    }
}

/// Validates the declared principal against live sessions hosted by the edge.
fn principal_of(
    context: &StateCoreContext,
    peer: ServerId,
    record: &OriginRecord,
) -> Result<OriginPrincipal, Violation> {
    let session = match record.session {
        None => None,
        Some(session) => {
            let live = context
                .domain()
                .user_for_session(session.session_id)
                .and_then(|user_id| context.domain().session(user_id))
                .ok_or(Violation::Origin)?;
            if live.user_id() != session.user_id || live.home_server_id() != peer {
                return Err(Violation::Origin);
            }
            Some((session.session_id, session.user_id))
        }
    };
    let account = record
        .account
        .map(|account| {
            Generation::new(account.account_session_generation)
                .map(|generation| (account.account_id, generation))
        })
        .transpose()
        .map_err(|_| Violation::Codec)?;
    // A declared account must be the one the live session authenticated;
    // an unauthenticated declaration may omit it.
    if let Some((account_id, _)) = account {
        let live_account = session
            .and_then(|(_, user_id)| context.domain().session(user_id))
            .and_then(|live| live.account_id());
        if live_account != Some(account_id) {
            return Err(Violation::Origin);
        }
    }
    Ok(OriginPrincipal { session, account })
}

/// Accepts FORIGIN DEL.
// agenc-review: allow owner=runtime reviewed=2026-09-02 reason=an origin declaration carries its link peer descriptor object charge and update flag through one validation path
#[allow(clippy::too_many_arguments)]
pub(super) fn delete(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    key: OriginKey,
    generation: u64,
    next_sequence: u64,
) -> Result<(), Violation> {
    if coordinator.pending.is_some() {
        return Err(Violation::Ceiling);
    }
    let frame = FederationFrame::OriginAck {
        edge_server_id: peer,
        server_incarnation: key.server_incarnation,
        origin_id: key.origin_id,
        generation,
        object_id: None,
    };
    match coordinator.origins.delete(key, generation, next_sequence) {
        Ok(()) => {
            // The connection behind the origin is gone, so nobody can close
            // its session any more. The edge's session close normally
            // precedes the DEL; when it never arrived, or storage refused
            // it, the session would keep its nickname until the next reset.
            let session = coordinator
                .origins
                .origin(&key)
                .and_then(|entry| entry.principal.session)
                .map(|(_, user_id)| user_id)
                .filter(|user_id| {
                    context
                        .domain()
                        .session(*user_id)
                        .is_some_and(|session| session.home_server_id() == peer)
                });
            if let Some(user_id) = session
                && let Some(state) = coordinator.peers.get_mut(&peer)
            {
                state.cleanup.push_back(user_id);
            }
            if let Some(registered) = coordinator.registered_sessions.get(&key)
                && let Some(state) = coordinator.peers.get_mut(&peer)
            {
                state.cleanup.extend(registered.iter().copied());
            }
        }
        Err(OriginError::UnknownOrigin)
            if coordinator.peers.get(&peer).is_some_and(|state| {
                state.incarnation == Some(key.server_incarnation) && state.live.is_some()
            }) =>
        {
            // A DEL replayed after a reset for an origin whose declaration
            // this coordinator never committed: there is nothing to delete
            // or record, and the acknowledgement lets the edge drop it.
            let _sent = coordinator.send_frame(context, link, peer, &frame);
            return Ok(());
        }
        Err(_) => return Err(Violation::Origin),
    }
    stage_origin(coordinator, context, link, peer, key, frame, None)
}

fn stage_origin(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    key: OriginKey,
    frame: FederationFrame,
    charge: Option<IngressCharge>,
) -> Result<(), Violation> {
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let entry = coordinator.origins.origin(&key).ok_or(Violation::Origin)?;
    let closed_carrier = (entry.status == OriginStatus::Deleted)
        .then(|| coordinator.remote_carrier_for_origin(peer, *key.origin_id.as_bytes()))
        .flatten();
    let writes = vec![
        origin_row(coordinator, key, entry.next_sequence, revision)?,
        coordinator
            .peer_row(peer, revision)
            .map_err(|_| Violation::Codec)?,
    ];
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|_| Violation::Ceiling)?;
    coordinator.pending = Some(PendingCommit::OriginAck {
        peer,
        link,
        frame,
        closed_carrier,
        _charge: charge,
    });
    Ok(())
}

/// Persists coordinator readiness after every retained origin was replayed.
pub(super) fn ready(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    incarnation: ServerIncarnation,
) -> Result<(), Violation> {
    coordinator
        .origins
        .ready(peer, incarnation)
        .map_err(|_| Violation::Origin)?;
    let mut bound: std::collections::BTreeSet<agenc_relay_types::UserId> = coordinator
        .origins
        .origins_of(peer, incarnation)
        .filter(|(_, entry)| entry.status == OriginStatus::Live)
        .filter_map(|(_, entry)| entry.principal.session.map(|(_, user_id)| user_id))
        .collect();
    for (key, users) in &coordinator.registered_sessions {
        if key.home_server_id == peer
            && key.server_incarnation == incarnation
            && coordinator
                .origins
                .origin(key)
                .is_some_and(|entry| entry.status == OriginStatus::Live)
        {
            bound.extend(users);
        }
    }
    let orphans: Vec<agenc_relay_types::UserId> = context
        .domain()
        .session_user_ids()
        .filter(|user_id| {
            !bound.contains(user_id)
                && context
                    .domain()
                    .session(*user_id)
                    .is_some_and(|session| session.home_server_id() == peer)
        })
        .collect();
    let state = coordinator
        .peers
        .get_mut(&peer)
        .ok_or(Violation::Misaddressed)?;
    state.phase = agenc_relay_storage::federation_records::PeerPhase::Ready;
    state.grace_deadline = None;
    grace::cancel_grace(context, peer);
    state.cleanup.extend(orphans);
    let link = state.live.as_ref().ok_or(Violation::Phase)?.link;
    coordinator
        .stage_rows(
            context,
            Vec::new(),
            PendingCommit::OriginReady { peer, link },
            Some(peer),
        )
        .map_err(|_| Violation::Ceiling)
}

/// Encodes the durable row of one origin at its current entry.
pub(super) fn origin_row(
    coordinator: &FederationCoordinator,
    key: OriginKey,
    next_sequence: u64,
    revision: u64,
) -> Result<AccountServiceDurableWrite, Violation> {
    let entry = coordinator.origins.origin(&key).ok_or(Violation::Origin)?;
    let object = coordinator
        .origin_objects
        .get(&key)
        .ok_or(Violation::Origin)?;
    let status = match entry.status {
        OriginStatus::Live => OriginRowStatus::Live,
        OriginStatus::Suspended => OriginRowStatus::Suspended,
        OriginStatus::Blocked => OriginRowStatus::Blocked,
        OriginStatus::Deleted => OriginRowStatus::Deleted,
        OriginStatus::Fenced => OriginRowStatus::Fenced,
    };
    let body = FederationOriginRecord {
        origin_object: object.clone(),
        origin_object_id: entry.object_id,
        // A deleted origin is recorded at the sequence its edge deleted it,
        // so a restart fences everything that would follow.
        next_sequence: entry.deleted_after.unwrap_or(next_sequence),
        status,
        flags: 0,
    }
    .encode()
    .map_err(|_| Violation::Codec)?;
    let stored = origin_key(
        key.home_server_id,
        key.server_incarnation,
        *key.origin_id.as_bytes(),
        entry.generation,
    )
    .map_err(|_| Violation::Codec)?;
    request::row(
        TableId::FederationOrigin,
        ORIGIN_RECORD_KIND,
        stored,
        revision,
        body,
    )
}

/// The coordinator knows replay is complete when no retained origin remains suspended.
pub(super) fn continue_ready(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    if coordinator.pending.is_some() || context.in_flight() || context.pending_len() != 0 {
        return;
    }
    let Some((incarnation, link)) = coordinator.peers.get(&peer).and_then(|state| {
        state
            .live
            .as_ref()
            .map(|live| (live.incarnation, live.link))
    }) else {
        return;
    };
    if !coordinator.origins.is_resetting(peer, incarnation)
        || coordinator
            .origins
            .origins_of(peer, incarnation)
            .any(|(_, entry)| {
                matches!(
                    entry.status,
                    OriginStatus::Suspended | OriginStatus::Blocked
                )
            })
    {
        return;
    }
    if let Err(violation) = ready(coordinator, context, peer, incarnation) {
        coordinator.fail_link(context, link, peer, violation);
    }
}
