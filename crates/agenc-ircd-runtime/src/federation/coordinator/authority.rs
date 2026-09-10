//! Constant-size durable peer authority fences precede bounded session cleanup.

use agenc_ircd_storage::TableId;
use agenc_ircd_storage::federation_records::{PEER_RECORD_KIND, PeerPhase, peer_key};
use agenc_ircd_types::ServerId;

use super::{FederationCoordinator, PendingCommit, Violation, grace, request};
use crate::state_core::{StateCoreContext, projector::EdgeDelivery};

pub(super) fn continue_fence(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    if coordinator.pending.is_some() || context.in_flight() || context.pending_len() != 0 {
        return;
    }
    if !coordinator
        .peers
        .get(&peer)
        .is_some_and(|state| state.fence_pending)
    {
        return;
    }
    if let Err(violation) = stage(coordinator, context, peer)
        && let Some(link) = coordinator
            .peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .map(|live| live.link)
    {
        coordinator.fail_link(context, link, peer, violation);
    }
}

fn stage(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) -> Result<(), Violation> {
    let state = coordinator
        .peers
        .get(&peer)
        .ok_or(Violation::Misaddressed)?;
    let generation = state
        .projection_generation
        .checked_add(1)
        .ok_or(Violation::Ceiling)?;
    let cursor = context
        .domain()
        .retained_peer_sessions(peer)
        .next()
        .map(|(session, _)| *session.as_bytes());
    let mut record = coordinator
        .peer_record_at(peer, None)
        .map_err(|_| Violation::Codec)?;
    record.phase = PeerPhase::Expired;
    record.projection_generation = generation;
    record.next_delivery_sequence = 0;
    record.snapshot_required = true;
    record.cleanup_cursor = cursor;
    let revision = context
        .domain()
        .revision()
        .get()
        .checked_add(1)
        .ok_or(Violation::Ceiling)?;
    let write = request::row(
        TableId::FederationPeer,
        PEER_RECORD_KIND,
        peer_key(peer).map_err(|_| Violation::Codec)?,
        revision,
        record.encode().map_err(|_| Violation::Codec)?,
    )?;
    coordinator
        .stage_rows(
            context,
            vec![write],
            PendingCommit::AuthorityFence {
                peer,
                generation,
                cursor,
            },
            None,
        )
        .map_err(|_| Violation::Ceiling)
}

pub(super) fn committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    generation: u64,
    cursor: Option<[u8; 16]>,
) {
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    state.phase = PeerPhase::Expired;
    state.fence_pending = false;
    state.cleanup_cursor = cursor;
    state.projection_generation = generation;
    state.outbox = super::OutboxState {
        snapshot_required: true,
        ..super::OutboxState::default()
    };
    state.active = false;
    state.snapshot = None;
    state.resend = None;
    context.fence_federation_peer(peer);
    if let Some(projector) = context.federation_mut() {
        projector.set_edge(
            peer,
            EdgeDelivery {
                projection_generation: generation,
                next_delivery_sequence: 0,
            },
        );
        projector.require_snapshot(peer);
    }
    grace::queue_hosted_cleanup(coordinator, context, peer);
}

/// The next Session ID and peer phase commit with the physical hide.
pub(super) fn cleanup_writes(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    peer: ServerId,
    user: agenc_ircd_types::UserId,
    revision: u64,
) -> Result<Vec<crate::state_core::durable::AccountServiceDurableWrite>, Violation> {
    let state = coordinator
        .peers
        .get(&peer)
        .ok_or(Violation::Misaddressed)?;
    let mut record = coordinator
        .peer_record_at(peer, state.outbox.cursor)
        .map_err(|_| Violation::Codec)?;
    record.cleanup_cursor = state
        .cleanup
        .get(1)
        .and_then(|next| context.domain().retained_session(*next))
        .map(|session| *session.session_id().as_bytes());
    if state.phase == PeerPhase::Expired && record.cleanup_cursor.is_none() {
        record.phase = PeerPhase::Clean;
    }
    let mut writes = vec![request::row(
        TableId::FederationPeer,
        PEER_RECORD_KIND,
        peer_key(peer).map_err(|_| Violation::Codec)?,
        revision,
        record.encode().map_err(|_| Violation::Codec)?,
    )?];
    for key in coordinator
        .origin_objects
        .keys()
        .copied()
        .filter(|key| key.home_server_id == peer)
    {
        let Some(entry) = coordinator.origins.origin(&key) else {
            continue;
        };
        if entry
            .principal
            .session
            .is_some_and(|(_, owner)| owner == user)
            || coordinator
                .registered_sessions
                .get(&key)
                .is_some_and(|users| users.contains(&user))
        {
            writes.push(super::origin::origin_row(
                coordinator,
                key,
                entry.next_sequence,
                revision,
            )?);
        }
    }
    Ok(writes)
}

pub(super) fn cleanup_committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    if let Some(state) = coordinator.peers.get_mut(&peer) {
        let removed = state.cleanup.pop_front();
        state.cleanup_cursor = state
            .cleanup
            .front()
            .and_then(|user| context.domain().retained_session(*user))
            .map(|session| *session.session_id().as_bytes());
        if state.phase == PeerPhase::Expired && state.cleanup.is_empty() {
            state.phase = PeerPhase::Clean;
        }
        if let Some(user) = removed {
            for users in coordinator.registered_sessions.values_mut() {
                users.remove(&user);
            }
        }
    }
    grace::continue_cleanup(coordinator, context, peer);
}

/// Empty cleanup also has a durable terminal state, including after restart.
pub(super) fn continue_clean(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    if coordinator.pending.is_some() || context.in_flight() || context.pending_len() != 0 {
        return;
    }
    let Some(state) = coordinator.peers.get(&peer) else {
        return;
    };
    if state.phase != PeerPhase::Expired
        || state.fence_pending
        || !state.cleanup.is_empty()
        || context
            .domain()
            .retained_peer_sessions(peer)
            .next()
            .is_some()
    {
        return;
    }
    let Ok(mut record) = coordinator.peer_record_at(peer, state.outbox.cursor) else {
        return;
    };
    record.phase = PeerPhase::Clean;
    record.cleanup_cursor = None;
    let Some(revision) = context.domain().revision().get().checked_add(1) else {
        return;
    };
    let write = peer_key(peer)
        .and_then(|key| record.encode().map(|body| (key, body)))
        .map_err(|_| Violation::Codec)
        .and_then(|(key, body)| {
            request::row(
                TableId::FederationPeer,
                PEER_RECORD_KIND,
                key,
                revision,
                body,
            )
        });
    if let Ok(write) = write {
        let _staged = coordinator.stage_rows(
            context,
            vec![write],
            PendingCommit::CleanupFinished { peer },
            None,
        );
    }
}
