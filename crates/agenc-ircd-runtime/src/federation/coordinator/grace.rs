//! Link loss, the fixed origin grace interval, and bounded expiry cleanup
//! (spec 20.5 and 20.10).

use agenc_ircd_domain::federation::{MutationContext, SessionHideKind};
use agenc_ircd_storage::federation_records::PeerPhase;
use agenc_ircd_types::{ServerId, UserId};

use super::{FederationCoordinator, PendingCommit};
use crate::state_core::StateCoreContext;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};

/// Records link loss: origins suspend and the grace timer starts.
pub(super) fn link_lost(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    let Some(incarnation) = state.incarnation else {
        return;
    };
    let now = context.now();
    let Ok(deadline) = coordinator.origins.link_lost(peer, incarnation, now) else {
        return;
    };
    context.suspend_federation_peer(peer);
    state.grace_deadline = Some(deadline);
    state.phase = PeerPhase::Suspended;
    let _scheduled =
        context
            .timers_mut()
            .schedule(deadline, TimerKind::FederationGrace, TimedId::Peer(peer));
}

/// Applies link loss to every peer the reload restored without a live link.
/// The grace timer does not survive a restart, so the interval restarts
/// here; an incarnation already expired resumes its interrupted cleanup.
pub(super) fn restored(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    let restored: Vec<(ServerId, PeerPhase)> = coordinator
        .peers
        .iter()
        .filter(|(_, state)| state.live.is_none() && state.incarnation.is_some())
        .map(|(peer, state)| (*peer, state.phase))
        .collect();
    for (peer, phase) in restored {
        match phase {
            PeerPhase::Ready | PeerPhase::Suspended => link_lost(coordinator, context, peer),
            PeerPhase::Expired => queue_hosted_cleanup(coordinator, context, peer),
            PeerPhase::Clean => {}
        }
    }
}

/// Queues every session the edge still hosts for hiding and starts on it.
pub(super) fn queue_hosted_cleanup(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let hosted: Vec<(agenc_ircd_types::SessionId, UserId)> =
        context.domain().retained_peer_sessions(peer).collect();
    if let Some(state) = coordinator.peers.get_mut(&peer) {
        state.cleanup_cursor = hosted.first().map(|(session, _)| *session.as_bytes());
        state.cleanup = hosted.into_iter().map(|(_, user)| user).collect();
    }
    continue_cleanup(coordinator, context, peer);
}

/// Cancels a pending grace timer when the edge reconnects in time.
pub(super) fn cancel_grace(context: &mut StateCoreContext, peer: ServerId) {
    let _cancelled = context
        .timers_mut()
        .cancel(TimerKind::FederationGrace, TimedId::Peer(peer));
}

/// Handles the grace timer: the incarnation is fenced and every session
/// the edge hosted is queued for cleanup.
pub(super) fn timer_fired(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    entry: TimerEntry,
) -> bool {
    let (TimerKind::FederationGrace, TimedId::Peer(peer)) = (entry.kind, entry.id) else {
        return false;
    };
    // The heap only pops a due entry, so the deadline itself is the instant
    // the grace interval ended; using it keeps expiry exact under any clock.
    if coordinator.origins.expire(peer, entry.deadline).is_none() {
        return true;
    }
    if let Some(state) = coordinator.peers.get_mut(&peer) {
        state.fence_pending = true;
        state.grace_deadline = None;
    }
    super::authority::continue_fence(coordinator, context, peer);
    true
}

/// Hides the next queued session of one edge as its own durable plan.
/// Each commit re-enters here until the queue is empty; another edge whose
/// queue filled meanwhile is taken up once this one is drained.
pub(super) fn continue_cleanup(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    if coordinator.pending.is_some() || hide_next(coordinator, context, peer) {
        return;
    }
    let waiting = coordinator
        .peers
        .iter()
        .find(|(other, state)| **other != peer && !state.cleanup.is_empty())
        .map(|(other, _)| *other);
    if let Some(next) = waiting {
        let _staged = hide_next(coordinator, context, next);
    }
}

/// Stages the hide plan of the next queued session; returns whether one
/// batch is now pending.
fn hide_next(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) -> bool {
    loop {
        let Some(state) = coordinator.peers.get(&peer) else {
            return false;
        };
        if state.fence_pending {
            return false;
        }
        let Some(user_id) = state.cleanup.front().copied() else {
            return false;
        };
        if context.domain().retained_session(user_id).is_none() {
            if let Some(state) = coordinator.peers.get_mut(&peer) {
                state.cleanup.pop_front();
            }
            continue;
        }
        let Ok(plan) = context.domain().plan_session_disconnected(user_id) else {
            return false;
        };
        let Ok(fanout) = crate::mutation_render::render_federation_expiry(context, user_id, &plan)
        else {
            return false;
        };
        let Ok(writes) = super::authority::cleanup_writes(
            coordinator,
            context,
            peer,
            user_id,
            plan.resulting_revision().get(),
        ) else {
            return false;
        };
        context.set_mutation_context(MutationContext {
            hide_kind: Some(SessionHideKind::OriginExpired),
            reason: SessionHideKind::OriginExpired.generic_reason().to_owned(),
            ..MutationContext::default()
        });
        if context
            .stage_durable_with_account_service(plan, fanout, None, 0, writes)
            .is_ok()
        {
            coordinator.counters.sessions_expired =
                coordinator.counters.sessions_expired.saturating_add(1);
            coordinator.pending = Some(PendingCommit::Cleanup { peer });
            return true;
        }
        return false;
    }
}
