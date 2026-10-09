#![forbid(unsafe_code)]

//! A page that cannot be prepared whole is refused for its request alone
//! and keeps nothing (companion 11.7, 16): a listed object that is not
//! retained as a complete encoded object, a refused memory or query
//! reservation, a lifetime the clock cannot represent and a token that
//! cannot be drawn each refuse the page; no new cut is then kept, and a
//! refused continuation leaves its cursor live for the next request.

use agenc_relay_config::LimitKey;
use agenc_relay_e2ee::limits::MAX_BATCH_OBJECTS;
use agenc_relay_types::EntropyError;

use super::bounds::{limits, receipts, usage};
use super::*;
use crate::budget::{BackingReservationPort, MEMORY_QUANTUM_BYTES, MemoryBudget};
use crate::sync::Arc;

/// The parameters of `EGROUP FETCH RECEIPTS` from `first` with `cursor`.
fn receipts_page(conversation: [u8; 32], first: u64, cursor: Option<[u8; 32]>) -> Vec<u8> {
    [receipts_from(conversation, first), cursor_param(cursor)].concat()
}

/// The reply code of a refused page.
fn refusal(outcome: Result<Outcome, Fail>) -> Option<E2eeReplyCode> {
    outcome.err().map(|fail| fail.code)
}

/// The identifier of the record at `sequence` of `conversation`.
fn record_id(harness: &Harness, conversation: [u8; 32], sequence: u64) -> TestResult<[u8; 32]> {
    harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .and_then(|known| known.records.get(&sequence))
        .copied()
        .ok_or_else(|| "a record".into())
}

/// Entropy that answers `draws` more draws and then fails.
struct Rationed {
    draws: usize,
    counter: Counter,
}

impl Rationed {
    const fn new(draws: usize) -> Self {
        Self {
            draws,
            counter: Counter(0),
        }
    }
}

impl EntropySource for Rationed {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        let Some(left) = self.draws.checked_sub(1) else {
            return Err(EntropyError::Unavailable);
        };
        self.draws = left;
        self.counter.fill_exact(destination)
    }
}

/// A listed object that is gone, or is no complete encoded object, is
/// refused rather than skipped wherever its page falls: at the first page,
/// at the capture of the cut beyond it, and at the later page that holds
/// it, whose cursor stays live.
#[test]
fn a_listed_object_not_retained_as_an_encoded_object_is_refused() -> TestResult {
    let later = MAX_BATCH_OBJECTS as u64 + 3;
    for (sequence, emptied) in [
        (0, false),
        (0, true),
        (ENTRIES as u64 - 1, false),
        (later, true),
    ] {
        let (mut harness, conversation) = receipts(ENTRIES as u64)?;
        let id = record_id(&harness, conversation, sequence)?;
        let objects = &mut harness.coordinator.state.objects;
        if emptied {
            objects.insert(id, Vec::new());
        } else {
            objects.remove(&id);
        }
        if sequence == later {
            let held = page(
                &mut harness,
                Op::FetchReceipts,
                &receipts_from(conversation, 0),
                None,
            )?;
            assert_eq!(held.objects.len(), MAX_BATCH_OBJECTS);
            refused(
                &harness,
                Op::FetchReceipts,
                &receipts_page(conversation, 0, held.next),
            )?;
            assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 1);
        } else {
            refused(
                &harness,
                Op::FetchReceipts,
                &receipts_page(conversation, 0, None),
            )?;
            assert_eq!(usage(&harness), (0, 0, 0));
        }
    }
    Ok(())
}

/// Every token is drawn after every reservation: a page that cannot draw
/// its snapshot token or its cursor is refused with `RATE_LIMITED` and keeps
/// nothing, and a continuation that cannot draw its successor leaves its
/// cursor live.
#[test]
fn a_page_without_entropy_for_its_tokens_is_refused_and_keeps_nothing() -> TestResult {
    let (mut harness, conversation) = receipts(80)?;
    // A page that fits alone draws its snapshot token; a cut draws its
    // snapshot token and then its cursor.
    for (first, draws) in [(70, 0), (0, 0), (0, 1)] {
        let outcome = evaluate_with(
            &harness,
            &Requester::of(&harness)?,
            Op::FetchReceipts,
            &receipts_page(conversation, first, None),
            &mut Rationed::new(draws),
        )?;
        assert_eq!(refusal(outcome), Some(E2eeReplyCode::RateLimited));
        assert_eq!(usage(&harness), (0, 0, 0));
        assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 0);
    }
    let prefix = receipts_from(conversation, 0);
    let held = page(&mut harness, Op::FetchReceipts, &prefix, None)?;
    let charged = usage(&harness);
    let outcome = evaluate_with(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &receipts_page(conversation, 0, held.next),
        &mut Rationed::new(0),
    )?;
    assert_eq!(refusal(outcome), Some(E2eeReplyCode::RateLimited));
    assert_eq!(usage(&harness), charged);
    let next = page(&mut harness, Op::FetchReceipts, &prefix, held.next)?;
    assert_eq!(next.snapshot, held.snapshot);
    assert_eq!(next.objects.len(), MAX_BATCH_OBJECTS);
    assert!(next.next.is_some());
    Ok(())
}

/// Grows a fresh memory budget one quantum at a time from nothing until
/// `params` is served, requiring every smaller budget to refuse it with
/// `RATE_LIMITED` before entropy, with nothing left charged to it and the
/// cuts as they stand; returns how many budgets refused.
fn sweep(harness: &mut Harness, params: &[u8]) -> TestResult<u64> {
    let cursors = harness.coordinator.state.listing_snapshots.cursors();
    for refusals in 0..16 {
        let budget = Arc::new(MemoryBudget::new(refusals * MEMORY_QUANTUM_BYTES));
        harness.backing = BackingReservationPort::new(Arc::clone(&budget));
        let (outcome, drew) =
            evaluate(harness, &Requester::of(harness)?, Op::FetchReceipts, params)?;
        let Err(fail) = outcome else {
            return Ok(refusals);
        };
        assert_eq!(fail.code, E2eeReplyCode::RateLimited);
        assert!(!drew, "a refused reservation drew entropy");
        assert_eq!(budget.charged(), 0, "a refused page kept memory");
        assert_eq!(
            harness.coordinator.state.listing_snapshots.cursors(),
            cursors
        );
    }
    Err("no budget served the page".into())
}

/// A memory budget that refuses any of a cut's reservations refuses the
/// page before entropy and keeps nothing charged, and a continuation whose
/// successor's index is refused leaves its cursor live.
#[test]
fn a_cut_refused_at_any_memory_reservation_keeps_nothing_charged() -> TestResult {
    let (mut harness, conversation) = receipts(80)?;
    let generous = BackingReservationPort::new(Arc::new(MemoryBudget::new(64 << 20)));
    harness.backing = generous.clone();
    // The shared query ledger keeps its owner and its record capacity once
    // first used.
    let port = harness.query_sessions.query_reservations(
        UserId::from_bytes(ORIGIN),
        harness.query_limits,
        harness.backing.clone(),
    );
    drop((
        port.reserve_snapshot(1, 0)?,
        port.reserve_index(0)?,
        port.reserve_index(0)?,
    ));
    // The cut's entries, its owner and its cursor index are each refused
    // once.
    assert_eq!(
        sweep(&mut harness, &receipts_page(conversation, 0, None))?,
        3
    );
    harness.backing = generous;
    let held = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    // A continuation reserves its successor's index alone.
    assert_eq!(
        sweep(&mut harness, &receipts_page(conversation, 0, held.next))?,
        1
    );
    Ok(())
}

/// A cut whose cursor index would take the query bytes over their global
/// ceiling is refused before entropy and keeps nothing; at exactly the
/// ceiling it is served.
#[test]
fn a_cut_whose_index_exceeds_the_query_bytes_ceiling_is_refused_before_entropy() -> TestResult {
    let (mut harness, conversation) = receipts(ENTRIES as u64)?;
    let params = receipts_page(conversation, 0, None);
    let (outcome, _) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &params,
    )?;
    let prepared = outcome.map_err(|fail| format!("{:?}", fail.code))?;
    // The cut's snapshot and its cursor index.
    let (snapshots, _, bytes) = usage(&harness);
    assert_eq!(snapshots, 1);
    drop(prepared);
    harness.query_limits = limits(&[(LimitKey::QuerySnapshotBytesGlobal, bytes - 1)])?;
    let (outcome, drew) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &params,
    )?;
    assert_eq!(refusal(outcome), Some(E2eeReplyCode::RateLimited));
    assert!(!drew);
    assert_eq!(usage(&harness), (0, 0, 0));
    harness.query_limits = limits(&[(LimitKey::QuerySnapshotBytesGlobal, bytes)])?;
    let (outcome, _) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &params,
    )?;
    assert_eq!(
        outcome.map(|outcome| outcome.result).ok(),
        Some(ResultBody::ObjectPage)
    );
    Ok(())
}

/// A continuation that names a successor charges the successor's cursor
/// index to the query bytes on top of the cut and the index it consumes:
/// under a global byte ceiling of exactly what the cut holds, a middle page
/// is refused before entropy and its cursor still continues once the
/// ceiling allows; the page's receipt returns the consumed cursor's index,
/// and the last page, which names no successor, is served at that ceiling.
#[test]
fn a_continuation_whose_successor_index_exceeds_the_query_bytes_ceiling_is_refused_before_entropy()
-> TestResult {
    // Three pages: 32, 32 and 8 records.
    let (mut harness, conversation) = receipts(72)?;
    let unlimited = harness.query_limits;
    let first = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    let (snapshots, _, held) = usage(&harness);
    assert_eq!(snapshots, 1);
    let at_held = limits(&[(LimitKey::QuerySnapshotBytesGlobal, held)])?;
    let middle = receipts_page(conversation, 0, first.next);
    harness.query_limits = at_held;
    let (outcome, drew) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &middle,
    )?;
    assert_eq!(refusal(outcome), Some(E2eeReplyCode::RateLimited));
    assert!(!drew);
    assert_eq!(usage(&harness).2, held, "a refused page keeps no index");
    harness.query_limits = unlimited;
    let (outcome, _) = evaluate(
        &harness,
        &Requester::of(&harness)?,
        Op::FetchReceipts,
        &middle,
    )?;
    let prepared = outcome.map_err(|fail| format!("{:?}", fail.code))?;
    assert!(
        prepared.next_cursor.is_some(),
        "a middle page names a successor"
    );
    assert!(
        usage(&harness).2 > held,
        "the successor's index is charged on top of the cut's"
    );
    drop(prepared);
    let second = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        first.next,
    )?;
    assert_eq!(second.objects.len(), MAX_BATCH_OBJECTS);
    assert_eq!(
        usage(&harness).2,
        held,
        "the receipt returned the consumed cursor's index"
    );
    harness.query_limits = at_held;
    let last = page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        second.next,
    )?;
    assert_eq!((last.objects.len(), last.next), (8, None));
    assert_eq!(usage(&harness), (0, 0, 0));
    Ok(())
}

/// A cut whose lifetime would end past the clock's last instant is refused
/// before entropy; one that ends at that instant is kept.
#[test]
fn a_cut_whose_lifetime_cannot_be_represented_is_refused_before_entropy() -> TestResult {
    let (harness, conversation) = receipts(ENTRIES as u64)?;
    let params = receipts_page(conversation, 0, None);
    let late = Requester {
        monotonic_millis: u64::MAX - 599_999,
        ..Requester::of(&harness)?
    };
    let (outcome, drew) = evaluate(&harness, &late, Op::FetchReceipts, &params)?;
    assert_eq!(refusal(outcome), Some(E2eeReplyCode::RateLimited));
    assert!(!drew);
    assert_eq!(usage(&harness), (0, 0, 0));
    let latest = Requester {
        monotonic_millis: u64::MAX - 600_000,
        ..Requester::of(&harness)?
    };
    let (outcome, _) = evaluate(&harness, &latest, Op::FetchReceipts, &params)?;
    assert_eq!(
        outcome.ok().and_then(|outcome| outcome.listing_expiry),
        Some(u64::MAX)
    );
    Ok(())
}

/// A cut expired at the next request's time is left out of the replacement
/// that request prepares, before its wake releases it: the page names the
/// new cut's expiry alone.
#[test]
fn an_expired_cut_is_left_out_of_the_next_replacement() -> TestResult {
    let (mut harness, conversation) = receipts(ENTRIES as u64)?;
    page(
        &mut harness,
        Op::FetchReceipts,
        &receipts_from(conversation, 0),
        None,
    )?;
    assert_eq!(harness.coordinator.state.listing_snapshots.cursors(), 1);
    let later = Requester {
        monotonic_millis: harness.monotonic_millis + 600_000,
        ..Requester::of(&harness)?
    };
    let (outcome, _) = evaluate(
        &harness,
        &later,
        Op::FetchReceipts,
        &receipts_page(conversation, 1, None),
    )?;
    let outcome = outcome.map_err(|fail| format!("{:?}", fail.code))?;
    assert_eq!(
        outcome.listing_expiry,
        Some(later.monotonic_millis + 600_000)
    );
    Ok(())
}
