//! Restore of route stores written before recreated routes (G-08, storage
//! generation 5): the rows of `test-data/stage-ten/recreated-routes/`,
//! written by the test harness of the start commit (`0825eea`), which this
//! tree seals into a storage fixture and restores through the storage reads
//! a restart uses, and reloads into the coordinator harness for the requests
//! that follow.
//!
//! Each route restores at incarnation zero in its own lineage, as the start
//! commit held it; a closed direct pair it stored is reserved again and a
//! closed channel route it stored binds its next incarnation, naming the
//! stored close (companion 9.4 and 11.4); and a live pair it stored keeps
//! the pair and its traffic.

#![forbid(unsafe_code)]

use super::super::retention::earlier_stores::{restarted_from, rows_of};
use super::*;

/// The stores of this topic's fixtures.
const STORES: [&str; 3] = ["closed-channel", "live-direct", "closed-direct"];

fn rows(name: &str) -> TestResult<Vec<crate::state_core::durable::AccountServiceDurableWrite>> {
    rows_of("recreated-routes", name)
}

/// The store `name` restarted, with the device attached again.
fn restarted(name: &str) -> TestResult<Harness> {
    let mut harness = restarted_from(rows(name)?)?;
    harness.attach()?;
    Ok(harness)
}

/// The direct peer of the fixtures, whose root and roster they stored.
fn stored_peer() -> TestResult<(Principal, [u8; 24])> {
    let account = account_bytes(10)?;
    Ok((
        principal(PEER_ROOT_SEED, &account, &[PEER_DEVICE])?,
        account,
    ))
}

/// The one route of `harness` whose target is a direct pair, or a channel.
fn only_route(harness: &Harness, direct: bool) -> TestResult<agenc_relay_domain::e2ee::RouteEntry> {
    let mut routes = harness.coordinator.state.routes.routes().filter(|route| {
        matches!(
            route.target,
            agenc_relay_domain::e2ee::RouteTarget::Direct(_)
        ) == direct
    });
    let route = *routes.next().ok_or("a route")?;
    assert!(routes.next().is_none(), "one route");
    Ok(route)
}

#[tokio::test]
async fn stores_written_before_recreated_routes_restore_at_incarnation_zero() -> TestResult {
    for name in STORES {
        let (restored, result) = Box::pin(reconstruct(&rows(name)?)).await?;
        assert!(result.is_ok(), "{name}: {result:?}");
        let routes: Vec<_> = restored.state.routes.routes().copied().collect();
        assert_eq!(routes.len(), 1, "{name}");
        for route in routes {
            assert_eq!(route.incarnation, 0, "{name}");
            assert_eq!(route.lineage, route.lock, "{name}");
            assert!(restored.state.routes.is_current(&route.conversation_id));
            let conversation = restored
                .state
                .conversations
                .get(&route.conversation_id.0)
                .ok_or("conversation")?;
            assert_eq!(conversation.predecessor_close_id, None, "{name}");
        }
    }
    Ok(())
}

#[test]
fn an_earlier_closed_direct_pair_is_reserved_and_bound_again() -> TestResult {
    let mut harness = restarted("closed-direct")?;
    let closed = only_route(&harness, true)?;
    let RouteLifecycle::Tombstone { close_id } = closed.lifecycle else {
        return Err("the stored pair is closed".into());
    };
    let (peer, peer_account) = stored_peer()?;
    let (reservation, nonce) = ok_reservation(reserve_direct(&mut harness, &peer_account)?)?;
    let replay = direct_group(&harness, &peer, (0, [0; 32]), nonce, SECOND_DIRECT_GROUP)?;
    assert_eq!(
        code(bind(&mut harness, reservation, &replay)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let next = direct_group(&harness, &peer, (1, close_id), nonce, SECOND_DIRECT_GROUP)?;
    bind_and_publish(&mut harness, reservation, &next)?;
    let second = route_of(&harness, next.conversation)?;
    assert_eq!(second.lineage, closed.lock);
    operate(&mut harness, next.conversation, None)?;
    let mut harness = harness.reloaded()?;
    assert_eq!(route_of(&harness, next.conversation)?, second);
    assert_eq!(route_of(&harness, closed.conversation_id.0)?, closed);
    traffic(&mut harness, next.conversation, None, 2)
}

#[test]
fn an_earlier_closed_channel_route_binds_its_next_incarnation() -> TestResult {
    let mut harness = restarted("closed-channel")?;
    let closed = only_route(&harness, false)?;
    let RouteLifecycle::Tombstone { close_id } = closed.lifecycle else {
        return Err("the stored channel is closed".into());
    };
    let reservation = ok_reservation(reserve_channel(&mut harness, SECOND_INSTANCE)?)?;
    let next = next_channel(&harness, 1, close_id)?;
    bind_and_publish(&mut harness, reservation, &next)?;
    assert_eq!(route_of(&harness, next.conversation)?.lineage, closed.lock);
    operate(&mut harness, next.conversation, Some(SECOND_INSTANCE))?;
    let mut harness = harness.reloaded()?;
    traffic(&mut harness, next.conversation, Some(SECOND_INSTANCE), 2)
}

#[test]
fn an_earlier_live_direct_pair_keeps_its_pair_and_traffic() -> TestResult {
    let mut harness = restarted("live-direct")?;
    let live = only_route(&harness, true)?;
    let (_, peer_account) = stored_peer()?;
    assert_eq!(
        refusal(reserve_direct(&mut harness, &peer_account)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    traffic(&mut harness, live.conversation_id.0, None, 2)
}
