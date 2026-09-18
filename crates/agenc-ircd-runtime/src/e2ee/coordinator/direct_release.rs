//! Live release of a direct route projection (companion 12.5): a direct
//! route stands at an edge only while that edge hosts a session or an
//! attached device of one of its two accounts. When a companion origin is
//! deleted or re-declared, the edge's direct standings are marked departing
//! (`RouteEntitlements::mark_departure`). The coordinator has no mutation of
//! its own to carry an event, so the next committed mutation plan that
//! already delivers events looks at a bounded number of departing standings:
//! one the edge no longer hosts is hidden from it by a `route_state_hidden`
//! copy in that plan and its references are dropped with the commit, so a
//! later event projects the route again first; one still hosted keeps its
//! reference and leaves the queue after a few looks.

#![forbid(unsafe_code)]

use agenc_ircd_domain::e2ee::projection::EventKind;
use agenc_ircd_types::ServerId;

use super::events::EventContent;
use super::ops::Exec;
use super::request::Outcome;
use super::{CompanionState, ConversationState};

/// Departing standings one mutation plan examines.
const RELEASES_PER_PLAN: usize = 16;

/// Whether `peer` hosts `account` in the base profile.
pub(super) type HostsBase<'a> = dyn Fn(ServerId, &[u8; 24]) -> bool + 'a;

/// Whether a live companion origin of `peer` holds an attached device of
/// one of `accounts`. A fenced origin's connection has ended, and so has one
/// still suspended once the edge `replayed` its origin set after a link
/// loss: it was not declared again.
pub(super) fn attached_at(
    state: &CompanionState,
    network_id: &[u8; 32],
    (peer, replayed): (ServerId, bool),
    accounts: &[[u8; 24]; 2],
) -> bool {
    let digests: Vec<[u8; 32]> = accounts
        .iter()
        .filter_map(|account| agenc_ircd_e2ee::ids::account_id_digest(network_id, account).ok())
        .collect();
    state.origins.values().any(|origin| {
        origin.home_server_id == *peer.as_bytes()
            && !origin.fenced
            && !(origin.suspended && replayed)
            && origin.device.is_some()
            && origin
                .account_digest
                .is_some_and(|digest| digests.contains(&digest))
    })
}

/// The two accounts of a current direct conversation.
fn direct_accounts(known: Option<&ConversationState>) -> Option<[[u8; 24]; 2]> {
    known?
        .direct_accounts
        .map(|(first, second)| [first, second])
}

/// Whether `edge` still has a reason to hold `conversation`: the plan
/// delivers it an event of the conversation, or it hosts one of the pair.
fn still_held(
    exec: &Exec<'_>,
    hosts_base: &HostsBase<'_>,
    outcome: &Outcome,
    (edge, conversation): (ServerId, [u8; 32]),
) -> bool {
    let state = &exec.coordinator.state;
    let in_plan = outcome.events.iter().any(|content| {
        content.planned.target == edge && content.planned.conversation_id == Some(conversation)
    });
    let replayed = exec.coordinator.origins_replayed(edge);
    in_plan
        || direct_accounts(state.conversations.get(&conversation)).is_some_and(|accounts| {
            attached_at(
                state,
                &exec.coordinator.network_id,
                (edge, replayed),
                &accounts,
            ) || accounts.iter().any(|account| hosts_base(edge, account))
        })
}

/// The `route_state_hidden` copy that removes `conversation` from `edge`,
/// naming the route object the edge last held; `None` for a conversation
/// the coordinator no longer retains, whose standing is dropped silently.
fn hidden_copy(exec: &Exec<'_>, edge: ServerId, conversation: [u8; 32]) -> Option<EventContent> {
    let state = &exec.coordinator.state;
    let known = state.conversations.get(&conversation)?;
    let sequence = state
        .logs
        .get(&conversation)
        .map_or(0, |log| log.head().sequence);
    Some(exec.event(
        EventKind::RouteStateHidden,
        Some(conversation),
        edge,
        sequence,
        known.route_object_id.to_vec(),
        None,
    ))
}

/// Adds the `route_state_hidden` copies of the departing direct standings
/// their edge no longer hosts to a plan that already delivers events.
pub(super) fn plan_releases(exec: &Exec<'_>, hosts_base: &HostsBase<'_>, outcome: &mut Outcome) {
    if outcome.events.is_empty() {
        return;
    }
    let mut released = Vec::new();
    let mut hosted = Vec::new();
    let departing = exec
        .coordinator
        .state
        .entitlements
        .departing(RELEASES_PER_PLAN);
    for (edge, conversation) in departing {
        if still_held(exec, hosts_base, outcome, (edge, conversation)) {
            hosted.push((edge, conversation));
            continue;
        }
        outcome.events.extend(hidden_copy(exec, edge, conversation));
        released.push((edge, conversation));
    }
    if released.is_empty() && hosted.is_empty() {
        return;
    }
    outcome.effects.push(Box::new(move |companion| {
        for (edge, conversation) in hosted {
            companion.entitlements.still_hosted(edge, conversation);
        }
        for (edge, conversation) in released {
            let _dropped = companion.entitlements.release_departed(edge, conversation);
        }
    }));
}
