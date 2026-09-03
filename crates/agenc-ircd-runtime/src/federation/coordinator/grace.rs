//! Link loss, the fixed origin grace interval, and bounded expiry cleanup
//! (spec 20.5 and 20.10).

use agenc_ircd_domain::CanonicalCommand;
use agenc_ircd_domain::federation::{MutationContext, SessionHideKind};
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
    state.grace_deadline = Some(deadline);
    state.phase = agenc_ircd_storage::federation_records::PeerPhase::Suspended;
    let _scheduled =
        context
            .timers_mut()
            .schedule(deadline, TimerKind::FederationGrace, TimedId::Peer(peer));
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
    let hosted: Vec<UserId> = context
        .domain()
        .session_user_ids()
        .filter(|user_id| {
            context
                .domain()
                .session(*user_id)
                .is_some_and(|session| session.home_server_id() == peer)
        })
        .collect();
    if let Some(state) = coordinator.peers.get_mut(&peer) {
        state.phase = agenc_ircd_storage::federation_records::PeerPhase::Expired;
        state.grace_deadline = None;
        state.cleanup.extend(hosted);
    }
    continue_cleanup(coordinator, context, peer);
    true
}

/// Hides the next queued session of one edge as its own durable plan.
/// Each commit re-enters here until the queue is empty.
pub(super) fn continue_cleanup(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    if coordinator.pending.is_some() {
        return;
    }
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    while let Some(user_id) = state.cleanup.pop_front() {
        let Some(bound) = super::request::bound_for(context, user_id) else {
            continue;
        };
        let Ok(plan) = context.domain().plan_session_disconnected(user_id) else {
            continue;
        };
        let command = CanonicalCommand::quit(None);
        let Ok(fanout) =
            crate::mutation_render::render_mutation(context, bound, None, &command, &plan)
        else {
            continue;
        };
        context.set_mutation_context(MutationContext {
            hide_kind: Some(SessionHideKind::OriginExpired),
            reason: SessionHideKind::OriginExpired.generic_reason().to_owned(),
            ..MutationContext::default()
        });
        if context.stage_durable(plan, fanout, None, 0).is_ok() {
            coordinator.counters.sessions_expired =
                coordinator.counters.sessions_expired.saturating_add(1);
            coordinator.pending = Some(PendingCommit::Cleanup { peer });
            return;
        }
        state.cleanup.push_front(user_id);
        return;
    }
}
