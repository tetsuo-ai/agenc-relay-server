//! Companion request execution on the coordinator owner: admitted `E*`
//! frames feed the executor, each complete request runs against the state
//! core as one batch, and the committed lines go out over the live links.

use agenc_ircd_domain::federation::OriginKey;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_federation_wire::FederationLineText;
use agenc_ircd_types::ServerId;

use super::{FederationCoordinator, PendingCommit, SendFailure, Violation};
use crate::e2ee::coordinator::execute::{self, BaseView, OriginFacts, Staged};
use crate::e2ee::coordinator::{CompanionFault, CompleteRequest};
use crate::e2ee::link::{CompanionViolation, tick_millis};
use crate::federation::LinkId;
use crate::state_core::StateCoreContext;

fn fault_violation(fault: CompanionFault) -> Violation {
    match fault {
        CompanionFault::Protocol | CompanionFault::Assembly(_) => {
            Violation::Companion(CompanionViolation::Request)
        }
        CompanionFault::Ceiling => Violation::Ceiling,
        CompanionFault::Storage => Violation::Companion(CompanionViolation::Executor),
    }
}

fn code_violation(code: E2eeReplyCode) -> Violation {
    match code {
        E2eeReplyCode::RateLimited => Violation::Companion(CompanionViolation::Executor),
        _ => Violation::Companion(CompanionViolation::Request),
    }
}

/// Feeds one admitted frame to the executor and runs the request it
/// completes, or queues it behind the batch in flight.
pub(super) fn admitted(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    frame: CompanionFrame,
) -> Result<(), Violation> {
    let now = tick_millis(context.now());
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return Err(Violation::Companion(CompanionViolation::Unsupported));
    };
    let Some(complete) = executor
        .on_frame(link, peer, frame, now)
        .map_err(fault_violation)?
    else {
        return Ok(());
    };
    if coordinator.pending.is_some() || executor.has_pending() {
        return executor
            .enqueue(link, peer, complete)
            .map_err(fault_violation);
    }
    run(coordinator, context, link, peer, complete)
}

fn run(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    complete: CompleteRequest,
) -> Result<(), Violation> {
    let peers: Vec<ServerId> = coordinator.peers.keys().copied().collect();
    let origins = &coordinator.origins;
    let facts_for = |key: OriginKey| OriginFacts {
        user_id: origins
            .origin(&key)
            .and_then(|entry| entry.principal.session)
            .map(|(_, user_id)| user_id),
    };
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return Err(Violation::Companion(CompanionViolation::Unsupported));
    };
    let view = BaseView { context, peers };
    let staged =
        execute::run(executor, view, link, peer, complete, &facts_for).map_err(code_violation)?;
    match staged {
        Staged::Batch => {
            coordinator.pending = Some(PendingCommit::Companion { peer, link });
            Ok(())
        }
        Staged::Replay(lines) => {
            coordinator.counters.requests_replayed =
                coordinator.counters.requests_replayed.saturating_add(1);
            send_lines(coordinator, context, link, peer, lines);
            Ok(())
        }
    }
}

/// Sends `lines` to the live link of `peer`, retiring the link on refusal.
fn send_lines(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    lines: Vec<FederationLineText>,
) {
    for line in lines {
        let Some(live) = coordinator
            .peers
            .get(&peer)
            .and_then(|state| state.live.as_ref())
            .filter(|live| live.link == link)
        else {
            return;
        };
        if let Err(refusal) = live.handle.try_send(line) {
            coordinator.send_failed(context, link, peer, SendFailure::from(refusal));
            return;
        }
    }
}

/// Finishes the companion batch that just committed: applies its effects,
/// answers the requester, and delivers the event copies to every live
/// target whose companion profile is active.
pub(super) fn committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
) {
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return;
    };
    let Some(pending) = executor.batch_applied() else {
        return;
    };
    coordinator.counters.requests_committed =
        coordinator.counters.requests_committed.saturating_add(1);
    let Ok(lines) = execute::committed_lines(&*executor, &pending) else {
        coordinator.fail_link(
            context,
            link,
            peer,
            Violation::Companion(CompanionViolation::Executor),
        );
        return;
    };
    for (target, line) in lines {
        let Some(target_link) = coordinator
            .peers
            .get(&target)
            .and_then(|state| state.live.as_ref())
            .map(|live| live.link)
        else {
            continue;
        };
        if target != peer && !coordinator.companion.profile_active(target_link) {
            continue;
        }
        if target != peer {
            coordinator.counters.events_sent = coordinator.counters.events_sent.saturating_add(1);
        }
        send_lines(coordinator, context, target_link, target, vec![line]);
    }
}

/// Runs queued companion requests while no batch is in flight.
pub(super) fn drain_queued(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
) {
    while coordinator.pending.is_none() {
        let Some(queued) = coordinator
            .companion_exec
            .as_mut()
            .and_then(|executor| executor.dequeue())
        else {
            return;
        };
        if !coordinator.link_is_live(queued.link, queued.peer) {
            continue;
        }
        let complete = CompleteRequest {
            correlation: queued.correlation,
            request: queued.request,
            payload: queued.payload,
        };
        if let Err(violation) = run(coordinator, context, queued.link, queued.peer, complete) {
            coordinator.fail_link(context, queued.link, queued.peer, violation);
        }
    }
}
