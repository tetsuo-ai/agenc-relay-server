//! Cursor scope, authority, expiry and reservation boundaries use real mailbox objects.

#![forbid(unsafe_code)]

use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::sync::Arc;

#[path = "mailbox_query_usage.rs"]
mod query_usage;

fn refusal(source: &Harness, entropy: &mut ScriptedEntropy, params: &[u8]) -> TestResult {
    let before = retained_state(source)?;
    let remaining = entropy.remaining();
    assert!(
        evaluate_request_with_entropy(source, Op::FetchMailbox, params, None, entropy)?.is_err()
    );
    assert_eq!(retained_state(source)?, before);
    assert_eq!(entropy.remaining(), remaining);
    Ok(())
}

#[test]
fn mailbox_cursor_refuses_a_changed_kind_or_attachment_before_entropy() -> TestResult {
    let (mut source, _, first, mut entropy) = paged_mailbox()?;
    let parameters = continuation(first.next_cursor.ok_or("cursor")?);
    let mut other_kind = parameters.clone();
    *other_kind.first_mut().ok_or("kind")? = 3;
    refusal(&source, &mut entropy, &other_kind)?;
    source.attach()?;
    refusal(&source, &mut entropy, &parameters)
}

#[test]
fn mailbox_cursor_rechecks_pending_authority_without_altering_the_cut() -> TestResult {
    let (mut source, _, first, mut entropy) = paged_mailbox()?;
    let conversation = *source
        .coordinator
        .state
        .conversations
        .keys()
        .next()
        .ok_or("conversation")?;
    set_recovery(
        &mut source,
        conversation,
        RecoveryState::Pending,
        RecoveryGate::Pending,
    )?;
    refusal(
        &source,
        &mut entropy,
        &continuation(first.next_cursor.ok_or("cursor")?),
    )
}

#[test]
fn mailbox_cursor_replay_keeps_the_same_bytes_and_delivery_token() -> TestResult {
    let (mut source, _, first, mut entropy) = paged_mailbox()?;
    let parameters = continuation(first.next_cursor.ok_or("cursor")?);
    let page = fetch(&mut source, &mut entropy, &parameters)?;
    let remaining = entropy.remaining();
    let repeat = fetch(&mut source, &mut entropy, &parameters)?;
    assert_eq!(page.snapshot_token, repeat.snapshot_token);
    assert_eq!(page.next_cursor, repeat.next_cursor);
    let original = page.responses.first().ok_or("page row")?;
    let repeated = repeat.responses.first().ok_or("repeated row")?;
    assert_eq!(original.bytes, repeated.bytes);
    assert_eq!(original.delivery_token, repeated.delivery_token);
    assert_eq!(entropy.remaining(), remaining);
    Ok(())
}

#[test]
fn mailbox_cursors_expire_at_the_exact_monotonic_boundary_and_do_not_restore() -> TestResult {
    let (mut source, _, first, mut entropy) = paged_mailbox()?;
    let parameters = continuation(first.next_cursor.ok_or("cursor")?);
    let mut restored = source.reloaded()?;
    restored.monotonic_millis = source.monotonic_millis;
    refusal(&restored, &mut entropy, &parameters)?;
    source.monotonic_millis = source
        .monotonic_millis
        .checked_add(599_999)
        .ok_or("clock")?;
    assert!(
        evaluate_request_with_entropy(&source, Op::FetchMailbox, &parameters, None, &mut entropy)?
            .is_ok()
    );
    source.monotonic_millis += 1;
    refusal(&source, &mut entropy, &parameters)?;
    source
        .coordinator
        .state
        .mailbox_snapshots
        .expire(source.monotonic_millis);
    assert_eq!(
        source.coordinator.state.mailbox_snapshots.next_expiry(),
        None
    );
    Ok(())
}

fn budget_fixture() -> TestResult<(Harness, Arc<MemoryBudget>, ScriptedEntropy)> {
    let (mut source, _, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    for _ in 0..33 {
        deliver_binding(&mut source, &binding)?;
    }
    let budget = Arc::new(MemoryBudget::new(64 * 1024 * 1024));
    source.backing = BackingReservationPort::new(Arc::clone(&budget));
    let initial = source
        .query_sessions
        .query_reservations(
            agenc_ircd_types::UserId::from_bytes(crate::e2ee::coordinator::tests::ORIGIN),
            source.query_limits,
            source.backing.clone(),
        )
        .reserve_snapshot(1, 0)?;
    drop(initial);
    let entropy = ScriptedEntropy::new((1..=128_u8).flat_map(|byte| [byte; 32]).collect())?;
    Ok((source, budget, entropy))
}

#[test]
fn mailbox_snapshot_backing_is_released_on_rejection_and_expiry() -> TestResult {
    let (mut source, budget, mut entropy) = budget_fixture()?;
    let retained_ledger = budget.charged();
    let candidate = ok(evaluate_request_with_entropy(
        &source,
        Op::FetchMailbox,
        &[2, 0],
        None,
        &mut entropy,
    )?)?;
    assert!(budget.charged() > 0);
    assert_eq!(
        source.coordinator.state.mailbox_snapshots.next_expiry(),
        None
    );
    drop(candidate);
    assert_eq!(budget.charged(), retained_ledger);
    fetch(&mut source, &mut entropy, &[2, 0])?;
    assert!(budget.charged() > 0);
    source
        .coordinator
        .state
        .mailbox_snapshots
        .expire(source.monotonic_millis + 600_000);
    assert_eq!(budget.charged(), retained_ledger);
    Ok(())
}

#[test]
fn mailbox_snapshot_budget_refusal_precedes_tokens_and_grants() -> TestResult {
    let (mut source, _, mut entropy) = budget_fixture()?;
    source.backing = BackingReservationPort::new(Arc::new(MemoryBudget::new(0)));
    refusal(&source, &mut entropy, &[2, 0])
}

#[test]
fn mailbox_snapshot_timer_refuses_exhaustion_and_preserves_exact_expiry() -> TestResult {
    use crate::e2ee::coordinator::ops::mailbox_snapshot::reserve_expiry;
    use crate::state_core::timers::{TimedId, TimerHeap, TimerKind};
    use agenc_ircd_types::MonotonicTick;
    let mut unavailable = TimerHeap::with_ceiling(0);
    let mut armed = None;
    assert!(reserve_expiry(&mut unavailable, 600_000, &mut armed).is_err());
    assert_eq!(armed, None);
    let mut timers = TimerHeap::with_ceiling(1);
    reserve_expiry(&mut timers, 600_000, &mut armed).map_err(|code| format!("timer: {code:?}"))?;
    reserve_expiry(&mut timers, 600_000, &mut armed)
        .map_err(|code| format!("same timer: {code:?}"))?;
    reserve_expiry(&mut timers, 600_001, &mut armed)
        .map_err(|code| format!("later timer: {code:?}"))?;
    assert_eq!(timers.len(), 1);
    assert_eq!(armed, Some(600_000));
    assert!(timers.pop_due(MonotonicTick::from_ticks(599_999)).is_none());
    let due = timers
        .pop_due(MonotonicTick::from_ticks(600_000))
        .ok_or("due timer")?;
    assert_eq!(due.kind, TimerKind::MailboxSnapshotExpiry);
    assert_eq!(due.id, TimedId::Global);
    Ok(())
}
