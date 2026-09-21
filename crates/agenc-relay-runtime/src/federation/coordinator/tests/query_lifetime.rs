//! Real rendered pages retain one owner through continuation and expiry.

#![forbid(unsafe_code)]

use super::*;
use crate::state_core::timers::{TimerHeap, TimerKind};

pub(in crate::federation::coordinator) fn fixture()
-> TestResult<(StateCoreFixture, QueryIdentity, QueryPlan)> {
    let mut fixture = StateCoreFixture::new(vec![7; 256])?;
    let config = test_support::golden_snapshot("directory-lifetime", None)?;
    let _reload = fixture.install_reload_port(RuntimeConfigHandle::new(config))?;
    let context = fixture.context_mut()?;
    let channels = (0..20)
        .map(|index| agenc_relay_domain::ChannelNameValue::parse(&format!("#quota{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut first = None;
    for seed in 1..=26 {
        let user = test_support::seed_session(context, seed, &format!("Paged{seed}"), None)?;
        first.get_or_insert(user);
        let PlanDecision::Mutation(plan) = test_support::plan_live(context, user, &|| {
            CanonicalCommand::join(
                channels
                    .iter()
                    .map(|name| agenc_relay_domain::ChannelTarget::new(name.clone(), false))
                    .collect(),
            )
        })?
        else {
            return Err("JOIN fixture plan".into());
        };
        test_support::apply_live_plan(context, plan)?;
    }
    let user = first.ok_or("query requester")?;
    let PlanDecision::Query(plan) =
        test_support::plan_live(context, user, &|| CanonicalCommand::names(channels.clone()))?
    else {
        return Err("NAMES query plan".into());
    };
    let identity = QueryIdentity {
        session_id: user.session_id,
        user_id: user.user_id,
        account: None,
        kind: FederationDirectoryQueryKind::Names,
        arm: Vec::new(),
    };
    Ok((fixture, identity, plan))
}

fn scope() -> CursorScope {
    CursorScope {
        coordinator: ServerId::from_bytes([2; 16]),
        network_id: NetworkId::from_bytes([3; 32]),
    }
}

fn cursor(page: &Page) -> TestResult<[u8; 32]> {
    match page.arm {
        ResultArm::ReplyPage {
            next_cursor: Some(cursor),
            ..
        } => Ok(cursor),
        _ => Err("expected a retained successor".into()),
    }
}

fn usage(context: &StateCoreContext) -> (u64, u64, u64) {
    let usage = context.sessions().queue_snapshot();
    (
        usage.query_snapshots(),
        usage.query_rows(),
        usage.query_bytes(),
    )
}

#[test]
fn a_directory_query_owner_lasts_through_its_final_page() -> TestResult {
    let (mut fixture, identity, plan) = fixture()?;
    let context = fixture.context_mut()?;
    let mut queries = Queries::new([4; 32], [5; 16]);
    let first = queries.first_page(context, &scope(), &identity, &plan)?;
    let cursor = cursor(&first)?;
    let reserved = usage(context);
    assert_eq!((reserved.0, reserved.1), (1, 540));
    assert_eq!(first.replies.len(), 19);
    drop(first);
    assert_eq!(usage(context), reserved);
    let final_page = queries
        .next_page(context, &scope(), &identity, cursor)
        .map_err(|error| format!("query continuation: {error:?}"))?;
    assert_eq!(final_page.replies.len(), 21);
    assert_eq!(queries.live_cursors(), 0);
    assert_eq!(usage(context), reserved);
    drop(queries);
    assert_eq!(usage(context), reserved);
    drop(final_page);
    assert_eq!(usage(context), (0, 0, 0));
    Ok(())
}

#[test]
fn a_quiet_directory_cursor_expires_and_a_stale_timer_cannot_expire_its_replacement() -> TestResult
{
    let (mut fixture, identity, plan) = fixture()?;
    let context = fixture.context_mut()?;
    let mut queries = Queries::new([4; 32], [5; 16]);
    let first = queries.first_page(context, &scope(), &identity, &plan)?;
    drop(first);
    let deadline = MonotonicTick::from_ticks(60_010);
    let entry = context
        .timers_mut()
        .pop_due(deadline)
        .ok_or("expiry timer")?;
    assert_eq!(entry.kind, TimerKind::DirectoryQueryExpiry);
    assert!(queries.timer_fired(context, entry));
    assert_eq!(queries.live_cursors(), 0);
    assert_eq!(usage(context), (0, 0, 0));
    drop(queries.first_page(context, &scope(), &identity, &plan)?);
    assert!(queries.timer_fired(context, entry));
    assert_eq!(queries.live_cursors(), 1);
    assert_eq!(usage(context).0, 1);
    Ok(())
}

#[test]
fn a_directory_query_refused_by_the_timer_ceiling_returns_all_query_usage() -> TestResult {
    let (mut fixture, identity, plan) = fixture()?;
    let context = fixture.context_mut()?;
    *context.timers_mut() = TimerHeap::with_ceiling(0);
    let mut queries = Queries::new([4; 32], [5; 16]);
    assert!(matches!(
        queries.first_page(context, &scope(), &identity, &plan),
        Err(DomainError::ServerBusy)
    ));
    assert_eq!(queries.live_cursors(), 0);
    assert_eq!(usage(context), (0, 0, 0));
    *context.timers_mut() = TimerHeap::new();
    drop(queries.first_page(context, &scope(), &identity, &plan)?);
    assert_eq!(queries.live_cursors(), 1);
    Ok(())
}

#[test]
fn directory_preparation_refuses_real_backing_exhaustion_and_refunds_its_slot() -> TestResult {
    let (mut fixture, identity, plan) = fixture()?;
    let context = fixture.context_mut()?;
    drop(
        context
            .query_reservations(identity.user_id)
            .reserve_snapshot(1, 0)?,
    );
    let port = context.backing_reservations();
    let mut held = Vec::new();
    for _ in 0..64 {
        match port.reserve(8 * 1_024 * 1_024) {
            Ok(permit) => held.push(permit),
            Err(_) => break,
        }
    }
    for _ in 0..8 {
        match port.reserve(1_024 * 1_024) {
            Ok(permit) => held.push(permit),
            Err(_) => break,
        }
    }
    let mut queries = Queries::new([4; 32], [5; 16]);
    assert!(matches!(
        queries.first_page(context, &scope(), &identity, &plan),
        Err(DomainError::ServerBusy)
    ));
    assert_eq!(queries.live_cursors(), 0);
    assert_eq!(usage(context), (0, 0, 0));
    drop(held);
    drop(queries.first_page(context, &scope(), &identity, &plan)?);
    assert_eq!(usage(context).0, 1);
    Ok(())
}

#[test]
fn a_directory_rejection_releases_only_its_exact_successor_owner() -> TestResult {
    let (mut fixture, identity, plan) = fixture()?;
    let context = fixture.context_mut()?;
    let mut queries = Queries::new([4; 32], [5; 16]);
    let first = queries.first_page(context, &scope(), &identity, &plan)?;
    let Page {
        replies, receipt, ..
    } = first;
    drop(replies);
    let receipt = receipt.ok_or("query receipt")?;
    let old_cursor = receipt.successor.ok_or("successor")?;
    drop(queries.first_page(context, &scope(), &identity, &plan)?);
    assert_eq!(usage(context).0, 2);
    queries.reject_page(receipt, context.now());
    assert_eq!(usage(context).0, 1);
    assert!(!queries.cursors.contains(&old_cursor));
    assert_eq!(queries.live_cursors(), 1);
    drop(queries);
    assert_eq!(usage(context), (0, 0, 0));
    Ok(())
}

fn available_backing(context: &StateCoreContext) -> u64 {
    let port = context.backing_reservations();
    let mut held = Vec::new();
    for power in (12..=29).rev() {
        let capacity = (1_usize << power) - 256;
        if let Ok(permit) = port.reserve(capacity) {
            held.push(permit);
        }
    }
    assert!(port.reserve(1).is_err());
    held.iter().map(crate::budget::MemoryPermit::bytes).sum()
}

#[test]
fn empty_directory_trees_keep_their_backing_until_the_query_owner_drops() -> TestResult {
    let (mut fixture, identity, plan) = fixture()?;
    let context = fixture.context_mut()?;
    // The shared ledger's own empty metadata is independent of these two trees.
    drop(
        context
            .query_reservations(identity.user_id)
            .reserve_snapshot(1, 0)?,
    );
    let before = available_backing(context);
    let mut queries = Queries::new([4; 32], [5; 16]);
    let page = queries.first_page(context, &scope(), &identity, &plan)?;
    let next = cursor(&page)?;
    drop(page);
    drop(
        queries
            .next_page(context, &scope(), &identity, next)
            .map_err(|error| format!("final page: {error:?}"))?,
    );
    assert_eq!(usage(context), (0, 0, 0));
    assert_eq!(queries.live_cursors(), 0);
    let empty = available_backing(context);
    assert!(
        empty < before,
        "empty BTree roots still own allocated backing"
    );
    let Page {
        replies, receipt, ..
    } = queries.first_page(context, &scope(), &identity, &plan)?;
    drop(replies);
    queries.reject_page(receipt.ok_or("query receipt")?, context.now());
    assert_eq!(usage(context), (0, 0, 0));
    assert_eq!(available_backing(context), empty);
    drop(queries.first_page(context, &scope(), &identity, &plan)?);
    queries.expire(MonotonicTick::from_ticks(60_010));
    assert_eq!(usage(context), (0, 0, 0));
    assert_eq!(available_backing(context), empty);
    drop(queries);
    assert_eq!(available_backing(context), before);
    Ok(())
}
