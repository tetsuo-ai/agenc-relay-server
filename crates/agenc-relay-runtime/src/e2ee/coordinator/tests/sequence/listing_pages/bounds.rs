#![forbid(unsafe_code)]

//! A listing cut is bounded and released (companion 16; architecture 19.2):
//! it holds at most the query snapshot row ceiling, is charged one query row
//! per entry, counts as one of its session's query snapshots, reserves its
//! memory before any entropy, and is released by its last page, its expiry,
//! its origin's deletion, a fenced incarnation and a closed link; a prepared
//! page whose origin, attachment or lifetime ended before its receipt
//! publishes no cut.

use agenc_relay_config::LimitKey;
use agenc_relay_e2ee::limits::{MAX_BATCH_DECODED_BYTES, MAX_BATCH_OBJECTS};

use super::super::super::{HOME, INCARNATION, NOW};
use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::coordinator::sync::{CompanionHost, OriginDescriptor};
use crate::runtime_config::{ConfigRevision, RuntimeConfigSnapshot, RuntimeResourceLimits};
use crate::sync::Arc;
use crate::test_support;

/// The query ceilings of the golden configuration with `values` in place.
pub(super) fn limits(values: &[(LimitKey, u64)]) -> TestResult<RuntimeResourceLimits> {
    let mut config = test_support::golden_config()?;
    for (key, value) in values {
        config.limits.values = config.limits.values.with(*key, *value);
    }
    RuntimeConfigSnapshot::from_parts(
        ConfigRevision::INITIAL,
        config,
        test_support::golden_parts("listing-test", None)?,
    )
    .runtime_resource_limits()
    .ok_or_else(|| "query limits".into())
}

/// A bound conversation holding `count` small receipts from sequence zero.
pub(super) fn receipts(count: u64) -> TestResult<(Harness, [u8; 32])> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    for sequence in 0..count {
        seed_record(&mut harness, conversation, sequence, 900)?;
    }
    Ok((harness, conversation))
}

/// The query snapshot count, rows and bytes the harness sessions hold.
pub(super) fn usage(harness: &Harness) -> (u64, u64, u64) {
    let usage = harness.query_sessions.queue_snapshot();
    (
        usage.query_snapshots(),
        usage.query_rows(),
        usage.query_bytes(),
    )
}

/// Pages the receipts of `conversation` from `first` with the row ceiling
/// at `rows`; requires one snapshot token and returns the page sizes.
fn receipt_pages(
    harness: &mut Harness,
    conversation: [u8; 32],
    first: u64,
    rows: u64,
) -> TestResult<Vec<usize>> {
    harness.query_limits = limits(&[(LimitKey::QuerySnapshotRows, rows)])?;
    let pages = pages(
        harness,
        Op::FetchReceipts,
        &receipts_from(conversation, first),
    )?;
    assert_eq!(usage(harness), (0, 0, 0), "the last page released its cut");
    Ok(counts(&pages))
}

#[test]
fn a_run_longer_than_the_row_ceiling_ends_its_cut_there_and_the_next_request_continues()
-> TestResult {
    let (mut harness, conversation) = receipts(50)?;
    // A cut of the 40 records the ceiling admits, paged at the count limit.
    assert_eq!(
        receipt_pages(&mut harness, conversation, 0, 40)?,
        vec![32, 8]
    );
    assert_eq!(receipt_pages(&mut harness, conversation, 40, 40)?, vec![10]);
    // A cut the ceiling ends within one page is that one final page; a run
    // that fits one page needs no cut, whatever the ceiling.
    assert_eq!(receipt_pages(&mut harness, conversation, 0, 20)?, vec![20]);
    assert_eq!(receipt_pages(&mut harness, conversation, 20, 20)?, vec![30]);
    Ok(())
}

/// A root's binding locks are a contiguous run as well: a lock run longer
/// than the row ceiling ends its cut there, and the next request continues
/// it from the following sequence.
#[test]
fn a_binding_lock_run_longer_than_the_row_ceiling_ends_its_cut_there() -> TestResult {
    let mut harness = Harness::new()?;
    harness.bind_channel()?;
    // The bound channel's lock is sequence zero; 49 more follow it.
    let seeded = super::directory::seed_locks(&mut harness, 1, 49)?;
    harness.query_limits = limits(&[(LimitKey::QuerySnapshotRows, 40)])?;
    let prefix = super::directory::locks_from(&harness, 0)?;
    let first = pages(&mut harness, Op::FetchBindingLocks, &prefix)?;
    assert_eq!(counts(&first), vec![32, 8]);
    assert_eq!(objects(&first).get(1..), seeded.get(..39));
    assert_eq!(usage(&harness), (0, 0, 0), "the last page released its cut");
    let prefix = super::directory::locks_from(&harness, 40)?;
    let rest = pages(&mut harness, Op::FetchBindingLocks, &prefix)?;
    assert_eq!(counts(&rest), vec![10]);
    assert_eq!(Some(objects(&rest).as_slice()), seeded.get(39..));
    Ok(())
}

#[test]
fn a_set_longer_than_the_row_ceiling_is_refused_before_entropy() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let selector = [0x31; 32];
    for leaf in 0..41_u32 {
        let id = retain(
            &mut harness,
            object_of(ArcWireObjectKind::CommitAck, 600, u64::from(leaf))?,
        );
        harness
            .coordinator
            .state
            .conversations
            .get_mut(&conversation)
            .ok_or("a bound conversation")?
            .acks
            .entry(selector)
            .or_default()
            .insert(leaf, id);
    }
    harness.query_limits = limits(&[(LimitKey::QuerySnapshotRows, 40)])?;
    let params = [conversation.to_vec(), selector.to_vec(), vec![0]].concat();
    let (outcome, drew) = evaluate(&harness, &Requester::of(&harness)?, Op::FetchAcks, &params)?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    assert!(!drew);
    assert_eq!(usage(&harness), (0, 0, 0));
    harness.query_limits = limits(&[(LimitKey::QuerySnapshotRows, 41)])?;
    let all = pages(
        &mut harness,
        Op::FetchAcks,
        &[conversation.to_vec(), selector.to_vec()].concat(),
    )?;
    assert_eq!(counts(&all), vec![32, 9]);
    Ok(())
}

#[test]
fn a_cut_is_one_of_its_sessions_query_snapshots() -> TestResult {
    let (mut harness, conversation) = receipts(ENTRIES as u64)?;
    harness.query_limits = limits(&[(LimitKey::QuerySnapshotsPerSession, 1)])?;
    let held = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    assert_eq!(usage(&harness).0, 1);
    // A second cut of the session is refused before entropy; a listing that
    // fits one page needs no cut and is still served.
    let second = [receipts_from(conversation, 1), vec![0]].concat();
    let (outcome, drew) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &second,
    )?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    assert!(!drew);
    let short = pages(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 30),
    )?;
    assert_eq!(counts(&short), vec![10]);
    // Another session holds its own.
    let other = Requester {
        user: [0x64; 16],
        ..Requester::of(&harness)?
    };
    let (outcome, _) = evaluate(&harness, &other, Op::FetchReceipts, &second)?;
    assert_eq!(
        outcome.map(|outcome| outcome.result).ok(),
        Some(ResultBody::ObjectPage)
    );
    // The last page releases the cut, and the session may capture again.
    page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        held.next,
    )?;
    assert_eq!(usage(&harness), (0, 0, 0));
    let next = pages(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 1),
    )?;
    assert_eq!(
        counts(&next),
        vec![MAX_BATCH_OBJECTS, ENTRIES - 1 - MAX_BATCH_OBJECTS]
    );
    Ok(())
}

/// A cut is charged one query row for each entry it holds, so the global
/// row ceiling bounds the cuts of every session together: another
/// session's cut that would take the rows one past it is refused before
/// entropy, and one that reaches it exactly is kept.
#[test]
fn a_cut_charges_one_query_row_per_entry_against_the_global_row_ceiling() -> TestResult {
    let (mut harness, conversation) = receipts(ENTRIES as u64)?;
    let held = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    assert!(
        held.next.is_some(),
        "a run longer than one page keeps a cut"
    );
    let rows = ENTRIES as u64;
    let (snapshots, charged, _) = usage(&harness);
    assert_eq!((snapshots, charged), (1, rows), "one query row per entry");
    let other = Requester {
        user: [0x61; 16],
        ..Requester::of(&harness)?
    };
    let params = [receipts_from(conversation, 0), vec![0]].concat();
    harness.query_limits = limits(&[
        (LimitKey::QuerySnapshotRows, rows),
        (LimitKey::QuerySnapshotRowsGlobal, 2 * rows - 1),
    ])?;
    let (outcome, drew) = evaluate(&harness, &other, Op::FetchReceipts, &params)?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    assert!(!drew);
    assert_eq!(usage(&harness).1, rows, "a refused cut keeps no rows");
    harness.query_limits = limits(&[
        (LimitKey::QuerySnapshotRows, rows),
        (LimitKey::QuerySnapshotRowsGlobal, 2 * rows),
    ])?;
    let (outcome, _) = evaluate(&harness, &other, Op::FetchReceipts, &params)?;
    let kept = outcome.map_err(|fail| format!("{:?}", fail.code))?;
    assert!(
        kept.next_cursor.is_some(),
        "the other session keeps its cut"
    );
    assert_eq!(usage(&harness).1, 2 * rows);
    drop(kept);
    Ok(())
}

#[test]
fn a_cut_reserves_its_memory_before_entropy_and_returns_it_when_released() -> TestResult {
    let (mut harness, conversation) = receipts(ENTRIES as u64)?;
    let params = [receipts_from(conversation, 0), vec![0]].concat();
    harness.backing = BackingReservationPort::new(Arc::new(MemoryBudget::new(0)));
    let (outcome, drew) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &params,
    )?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    assert!(!drew);
    let budget = Arc::new(MemoryBudget::new(64 * 1024 * 1024));
    harness.backing = BackingReservationPort::new(Arc::clone(&budget));
    // The shared query ledger keeps its own owner once it is first used.
    let port = harness.query_sessions.query_reservations(
        UserId::from_bytes(ORIGIN),
        harness.query_limits,
        harness.backing.clone(),
    );
    drop((port.reserve_snapshot(1, 0)?, port.reserve_index(0)?));
    let ledger = budget.charged();
    let first = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    assert!(
        budget.charged() > ledger,
        "the cut and its cursor are charged"
    );
    page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        first.next,
    )?;
    assert_eq!(budget.charged(), ledger, "the last page released the cut");
    page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    assert!(budget.charged() > ledger);
    harness
        .coordinator
        .state
        .listing_snapshots
        .expire(harness.monotonic_millis + 600_000);
    assert_eq!(budget.charged(), ledger, "expiry released the cut");
    assert_eq!(usage(&harness), (0, 0, 0));
    Ok(())
}

#[test]
fn a_page_that_keeps_a_cut_names_its_expiry_and_a_single_page_names_none() -> TestResult {
    let (harness, conversation) = receipts(ENTRIES as u64)?;
    let requester = Requester::of(&harness)?;
    let (kept, _) = evaluate(
        &harness,
        &requester,
        Op::FetchReceipts,
        &[receipts_from(conversation, 0), vec![0]].concat(),
    )?;
    let kept = kept.map_err(|fail| format!("{:?}", fail.code))?;
    assert_eq!(
        kept.listing_expiry,
        Some(harness.monotonic_millis + 600_000)
    );
    let (single, _) = evaluate(
        &harness,
        &requester,
        Op::FetchReceipts,
        &[receipts_from(conversation, 30), vec![0]].concat(),
    )?;
    assert_eq!(
        single
            .map_err(|fail| format!("{:?}", fail.code))?
            .listing_expiry,
        None
    );
    Ok(())
}

struct Host([u8; 16]);

impl CompanionHost for Host {
    fn live_incarnation(&self, _: ServerId) -> Option<[u8; 16]> {
        Some(self.0)
    }
    fn base_origin(
        &self,
        _: &crate::e2ee::coordinator::CompanionOriginKey,
    ) -> Option<crate::e2ee::coordinator::sync::BaseOriginView> {
        None
    }
    fn base_origins_ready(&self, _: ServerId) -> bool {
        false
    }
    fn base_resync_epoch(&self, _: ServerId) -> u64 {
        0
    }
    fn state_generation(&self) -> u64 {
        1
    }
    fn holds_channel(&self, _: [u8; 16]) -> bool {
        false
    }
    fn hosts_account(&self, _: &[u8; 24]) -> bool {
        false
    }
}

fn descriptor(harness: &Harness, origin_id: [u8; 16]) -> OriginDescriptor {
    OriginDescriptor {
        coordinator_server_id: *harness.coordinator.server_id.as_bytes(),
        server_incarnation: INCARNATION,
        origin_id,
        origin_generation: 0,
        object_id: [0; 32],
    }
}

/// A harness holding one receipt cut of its origin.
fn holding() -> TestResult<Harness> {
    let (mut harness, conversation) = receipts(ENTRIES as u64)?;
    page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 1);
    Ok(harness)
}

#[test]
fn an_origins_deletion_releases_its_cut_and_no_other() -> TestResult {
    let mut harness = holding()?;
    harness.coordinator.origin_del(
        ServerId::from_bytes(HOME),
        descriptor(&harness, [0x5e; 16]),
        0,
        &Host(INCARNATION),
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 1);
    let sequence = harness.sequence;
    harness.coordinator.origin_del(
        ServerId::from_bytes(HOME),
        descriptor(&harness, ORIGIN),
        sequence,
        &Host(INCARNATION),
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 0);
    assert_eq!(usage(&harness), (0, 0, 0));
    // A deletion naming another generation closes the origin where it
    // stands, and releases its cut as well.
    let mut harness = holding()?;
    harness.coordinator.origin_del(
        ServerId::from_bytes(HOME),
        OriginDescriptor {
            origin_generation: 1,
            ..descriptor(&harness, ORIGIN)
        },
        0,
        &Host(INCARNATION),
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 0);
    Ok(())
}

/// A deletion releases every cut of its origin, one bound to a generation
/// the origin has since left included: none of them can continue.
#[test]
fn an_origins_deletion_releases_its_cuts_of_every_generation() -> TestResult {
    let mut harness = holding()?;
    let origin = harness
        .coordinator
        .state
        .origins
        .get_mut(&origin_key())
        .ok_or("the harness origin")?;
    origin.generation = 1;
    origin.next_sequence = 0;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 1);
    harness.coordinator.origin_del(
        ServerId::from_bytes(HOME),
        OriginDescriptor {
            origin_generation: 1,
            ..descriptor(&harness, ORIGIN)
        },
        0,
        &Host(INCARNATION),
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 0);
    assert_eq!(usage(&harness), (0, 0, 0));
    Ok(())
}

#[test]
fn a_new_incarnation_of_the_edge_releases_its_cuts() -> TestResult {
    let mut harness = holding()?;
    let coordinator = *harness.coordinator.server_id.as_bytes();
    harness.coordinator.origin_reset(
        ServerId::from_bytes(HOME),
        coordinator,
        INCARNATION,
        &Host(INCARNATION),
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 1);
    harness.coordinator.origin_reset(
        ServerId::from_bytes([0x65; 16]),
        coordinator,
        [0x66; 16],
        &Host([0x66; 16]),
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 1);
    harness.coordinator.origin_reset(
        ServerId::from_bytes(HOME),
        coordinator,
        [0x66; 16],
        &Host([0x66; 16]),
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 0);
    assert_eq!(usage(&harness), (0, 0, 0));
    Ok(())
}

#[test]
fn a_closed_link_releases_the_cuts_of_its_origins_alone() -> TestResult {
    let mut harness = holding()?;
    harness
        .coordinator
        .link_closed(ServerId::from_bytes([0x67; 16]));
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 1);
    harness.coordinator.link_closed(ServerId::from_bytes(HOME));
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 0);
    assert_eq!(usage(&harness), (0, 0, 0));
    Ok(())
}

/// Applies a prepared page's receipt.
fn apply(harness: &mut Harness, mut outcome: Outcome) {
    for effect in std::mem::take(&mut outcome.effects) {
        effect(&mut harness.coordinator.state);
    }
}

#[test]
fn a_prepared_page_publishes_no_cut_its_origin_or_lifetime_no_longer_holds() -> TestResult {
    for case in [
        "deleted",
        "suspended",
        "expired",
        "reattached",
        "advanced",
        "rebound",
    ] {
        let (mut harness, conversation) = receipts(ENTRIES as u64)?;
        // An account-bound cut names no attachment, so only its account
        // check can drop it when the origin's account changes.
        let (op, params) = if case == "rebound" {
            super::directory::seed_locks(&mut harness, 1, ENTRIES as u64)?;
            (
                Op::FetchBindingLocks,
                [super::directory::locks_from(&harness, 0)?, vec![0]].concat(),
            )
        } else {
            (
                Op::FetchReceipts,
                [receipts_from(conversation, 0), vec![0]].concat(),
            )
        };
        let (prepared, _) = evaluate(&harness, &Requester::of(&harness)?, op, &params)?;
        let prepared = prepared.map_err(|fail| format!("{case}: {:?}", fail.code))?;
        assert_eq!(usage(&harness).0, 1, "{case}: the pending page is charged");
        match case {
            "deleted" => {
                let sequence = harness.sequence;
                harness.coordinator.origin_del(
                    ServerId::from_bytes(HOME),
                    descriptor(&harness, ORIGIN),
                    sequence,
                    &Host(INCARNATION),
                )?;
            }
            "suspended" => harness.coordinator.link_closed(ServerId::from_bytes(HOME)),
            "expired" => {
                harness.coordinator.state.mailbox_snapshot_now = harness.monotonic_millis + 600_000;
            }
            "reattached" => {
                harness.attach()?;
            }
            held => {
                let origin = harness
                    .coordinator
                    .state
                    .origins
                    .get_mut(&origin_key())
                    .ok_or("the harness origin")?;
                if held == "advanced" {
                    origin.generation += 1;
                } else {
                    origin.account_digest = Some([0x69; 32]);
                }
            }
        }
        apply(&mut harness, prepared);
        assert_eq!(
            harness.coordinator.state.listing_snapshots.cursors(),
            0,
            "{case}"
        );
        assert_eq!(usage(&harness), (0, 0, 0), "{case}");
    }
    Ok(())
}

#[test]
fn the_listing_expiry_wake_keeps_the_earliest_deadline_and_refuses_exhaustion() -> TestResult {
    use crate::e2ee::coordinator::ops::listing_snapshot::reserve_expiry;
    use crate::state_core::timers::{TimedId, TimerHeap, TimerKind};
    use agenc_relay_types::MonotonicTick;
    let deadline = NOW * 1_000 + 600_000;
    let mut unavailable = TimerHeap::with_ceiling(0);
    let mut armed = None;
    assert!(reserve_expiry(&mut unavailable, deadline, &mut armed).is_err());
    assert_eq!(armed, None);
    let mut timers = TimerHeap::with_ceiling(1);
    reserve_expiry(&mut timers, deadline, &mut armed).map_err(|code| format!("{code:?}"))?;
    reserve_expiry(&mut timers, deadline + 1, &mut armed).map_err(|code| format!("{code:?}"))?;
    assert_eq!(timers.len(), 1);
    assert_eq!(armed, Some(deadline));
    assert!(
        timers
            .pop_due(MonotonicTick::from_ticks(deadline - 1))
            .is_none()
    );
    let due = timers
        .pop_due(MonotonicTick::from_ticks(deadline))
        .ok_or("a due wake")?;
    assert_eq!(
        (due.kind, due.id),
        (TimerKind::ListingSnapshotExpiry, TimedId::Global)
    );
    Ok(())
}

/// An object no page can hold, which no retained kind reaches, is refused
/// rather than answered alone.
#[test]
fn a_listed_object_larger_than_any_page_is_refused() -> TestResult {
    let (mut harness, conversation) = receipts(2)?;
    let oversized = vec![0x5b; MAX_BATCH_DECODED_BYTES + 1];
    let id = object_id(&oversized);
    harness.coordinator.state.objects.insert(id, oversized);
    harness
        .coordinator
        .state
        .conversations
        .get_mut(&conversation)
        .ok_or("a bound conversation")?
        .records
        .insert(0, id);
    let (outcome, drew) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &[receipts_from(conversation, 0), vec![0]].concat(),
    )?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::RateLimited)
    );
    assert!(!drew);
    Ok(())
}

/// A requester without a base session holds no query snapshot: a listing
/// longer than one page is refused before entropy, a cursor its origin's
/// session holds is refused to it, and a listing that fits a page is
/// answered.
#[test]
fn a_requester_without_a_session_takes_no_cut() -> TestResult {
    let (mut harness, conversation) = receipts(ENTRIES as u64)?;
    let requester = Requester {
        session: false,
        ..Requester::of(&harness)?
    };
    let (outcome, drew) = evaluate(
        &harness,
        &requester,
        Op::FetchReceipts,
        &[receipts_from(conversation, 0), vec![0]].concat(),
    )?;
    assert_eq!(
        outcome
            .map(|outcome| outcome.result)
            .map_err(|fail| fail.code),
        Err(E2eeReplyCode::ObjectNotFound)
    );
    assert!(!drew);
    let (outcome, _) = evaluate(
        &harness,
        &requester,
        Op::FetchReceipts,
        &[receipts_from(conversation, 30), vec![0]].concat(),
    )?;
    assert_eq!(
        outcome.map(|outcome| outcome.responses.len()).ok(),
        Some(10)
    );
    let held = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    refused_as(
        &harness,
        &requester,
        Op::FetchReceipts,
        &[receipts_from(conversation, 0), cursor_param(held.next)].concat(),
    )?;
    Ok(())
}
