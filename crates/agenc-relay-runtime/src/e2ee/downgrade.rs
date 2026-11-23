//! The refusal of plaintext between the accounts of an encrypted direct pair
//! (companion 11.4): while a live, closing or closed binding exists for an
//! Account-ID pair, a plaintext `PRIVMSG` or `NOTICE` between that pair is
//! refused with `E2EE_REQUIRED`, whatever nickname, session or edge carries
//! it, until the pair's next semantic incarnation binds and keeps it again.
//!
//! The coordinator decides every line (companion 12.5: it "remains
//! authoritative ... for every base direct-message downgrade check, so
//! absence from this cache never authorizes plaintext"): it resolves each
//! nickname target to its current session's account before planning a
//! plaintext message, from its own clients and from every edge alike. An
//! edge refuses earlier whatever its own projection shows. Both decide with
//! the route table's one predicate
//! (`RouteTable::plaintext_allowed_between`).

#![forbid(unsafe_code)]

use agenc_relay_client_wire::WireMessage;
use agenc_relay_domain::e2ee::RouteTable;
use agenc_relay_domain::{
    CanonicalCommand, CanonicalCommandView, DomainState, MessageTarget, NicknameValue,
    TagmsgClassification,
};
use agenc_relay_types::UserId;

/// The `FAIL <command> E2EE_REQUIRED <context> :<description>` line a node
/// sends for a plaintext line it refuses, with the target exactly as the
/// requester supplied it as its context (companion 11.9).
pub(crate) fn refusal_line(server_name: &str, command: &str, context: &str) -> Option<WireMessage> {
    let body =
        agenc_relay_e2ee::wire::reply::E2eeReplyCode::Required.render_fail(command, Some(context));
    agenc_relay_e2ee::wire::response::render_fail(server_name, &body)
        .ok()
        .and_then(|line| WireMessage::extension_line(&line).ok())
}

// agenc-review: focus owner=runtime reviewed=2026-10-09 reason=the coordinator resolves every nickname target of a plaintext message to its current session's account and refuses the line when the shared predicate keeps that pair encrypted
/// The first nickname target, in the command's canonical target order, of a
/// plaintext `PRIVMSG`, `NOTICE` or client-only `TAGMSG` from `sender` whose
/// current session's account forms, with the sender's account, a pair the
/// route table keeps encrypted. The line is refused whole: none of its
/// targets receives it (companion 11.4; architecture 18.2 gives the
/// companion's rules precedence over the base per-target rule for an
/// encrypted route's targets). A guest on either side, one account messaging
/// itself, an unrelated pair and a channel target are left to the plan.
pub(crate) fn refused_direct_target<'a>(
    domain: &DomainState,
    routes: &RouteTable,
    sender: UserId,
    command: &'a CanonicalCommand,
) -> Option<&'a NicknameValue> {
    let CanonicalCommandView::Message(message) = command.view() else {
        return None;
    };
    // An encrypted application object never names a user: the plan refuses
    // one that does.
    if matches!(
        message.tagmsg_classification(),
        Some(TagmsgClassification::E2eeApplication(_))
    ) {
        return None;
    }
    let account = |user: UserId| {
        domain
            .session(user)
            .and_then(|session| session.account_id())
    };
    let sender = account(sender)?;
    message.targets().iter().find_map(|target| match target {
        MessageTarget::User(nickname) => {
            let target = domain.resolve_nickname(nickname).and_then(account);
            (!routes.plaintext_allowed_between(Some(sender), target)).then_some(nickname)
        }
        MessageTarget::Channel(_) => None,
    })
}

#[cfg(test)]
#[path = "tests/downgrade.rs"]
mod tests;
