//! Both companion expiry timers are dispatched off the owner's own heap.
//!
//! Every case here arms a real entry, pops it with `pop_due` the way
//! `StateCore::step_wake` does, and hands it to `FederationCoordinator::
//! timer_fired`, so what is proved is that the path is reachable in the
//! composed owner and not merely that the handler computes.
#![forbid(unsafe_code)]

use super::*;
use crate::state_core::timers::TimerHeap;

/// Runs the owner's heap forward to the first entry of `kind` and dispatches
/// it the way `StateCore::step_wake` does. Wakes of other kinds are dropped
/// rather than fired, so each case observes only its own handler.
fn fire(transfer: &mut Transfer, kind: TimerKind) -> TestResult<(bool, TimerEntry)> {
    for _ in 0..32 {
        let context = transfer.core.context_mut()?;
        let now = context.now();
        match context.timers_mut().pop_due(now) {
            Some(entry) if entry.kind == kind => {
                return Ok((transfer.coordinator.timer_fired(context, entry), entry));
            }
            Some(_) => {}
            None => {
                let next = context
                    .timers_mut()
                    .next_deadline()
                    .ok_or("an armed timer")?;
                context.set_monotonic_for_test(next.get());
            }
        }
    }
    Err("no due timer of that kind".into())
}

/// Whether a live entry for `(kind, id)` remains on the owner's heap.
fn armed(timers: &mut TimerHeap, kind: TimerKind, id: TimedId) -> bool {
    timers.cancel(kind, id)
}

fn arm_mailbox_expiry(transfer: &mut Transfer, deadline: u64) -> TestResult {
    let executor = transfer
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("installed executor")?;
    let mut armed_at = executor.state.mailbox_expiry_armed;
    crate::e2ee::coordinator::ops::mailbox_snapshot::reserve_expiry(
        transfer.core.context_mut()?.timers_mut(),
        deadline,
        &mut armed_at,
    )
    .map_err(|code| format!("mailbox expiry reservation refused: {code:?}"))?;
    transfer
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("installed executor")?
        .state
        .mailbox_expiry_armed = armed_at;
    Ok(())
}

/// A due mailbox cut expiry disarms the owner's reservation and, with no cut
/// left to release, cancels the heap entry instead of rearming it.
#[tokio::test]
async fn a_due_mailbox_expiry_releases_its_reservation_through_the_owner() -> TestResult {
    let mut transfer = Transfer::open(2, 1 << 20).await?;
    let deadline = transfer.core.context_mut()?.now().get().saturating_add(50);
    arm_mailbox_expiry(&mut transfer, deadline)?;
    assert_eq!(
        transfer
            .coordinator
            .companion_exec
            .as_ref()
            .and_then(|executor| executor.state.mailbox_expiry_armed),
        Some(deadline)
    );
    transfer
        .core
        .context_mut()?
        .set_monotonic_for_test(deadline);
    let (handled, entry) = fire(&mut transfer, TimerKind::MailboxSnapshotExpiry)?;
    assert!(handled, "the composed owner declined its own mailbox timer");
    assert_eq!(entry.id, TimedId::Global);
    assert_eq!(
        transfer
            .coordinator
            .companion_exec
            .as_ref()
            .and_then(|executor| executor.state.mailbox_expiry_armed),
        None
    );
    assert!(
        !armed(
            transfer.core.context_mut()?.timers_mut(),
            TimerKind::MailboxSnapshotExpiry,
            TimedId::Global
        ),
        "no cut remained yet the owner left an expiry armed"
    );
    Ok(())
}

/// A node with no companion executor still owns the timer: it is accepted and
/// retires without touching any other owner's state.
#[tokio::test]
async fn a_due_mailbox_expiry_without_an_executor_is_still_owned() -> TestResult {
    let mut transfer = Transfer::open(2, 1 << 20).await?;
    let deadline = transfer.core.context_mut()?.now().get().saturating_add(50);
    arm_mailbox_expiry(&mut transfer, deadline)?;
    let executor = transfer.coordinator.companion_exec.take();
    assert!(executor.is_some());
    transfer
        .core
        .context_mut()?
        .set_monotonic_for_test(deadline);
    let violations = transfer.coordinator.counters().violations;
    let (handled, _) = fire(&mut transfer, TimerKind::MailboxSnapshotExpiry)?;
    assert!(handled);
    assert_eq!(transfer.coordinator.counters().violations, violations);
    Ok(())
}

/// Neither handler claims an entry whose kind and identity it does not own,
/// so the owner's chain keeps looking.
#[tokio::test]
async fn neither_companion_timer_claims_an_entry_it_does_not_own() -> TestResult {
    let mut transfer = Transfer::open(2, 1 << 20).await?;
    let deadline = transfer.core.context_mut()?.now().get().saturating_add(50);
    for (kind, id) in [
        (TimerKind::MailboxSnapshotExpiry, TimedId::Peer(PEER)),
        (TimerKind::CompanionSnapshotExpiry, TimedId::Global),
    ] {
        transfer.core.context_mut()?.timers_mut().schedule(
            MonotonicTick::from_ticks(deadline),
            kind,
            id,
        )?;
        transfer
            .core
            .context_mut()?
            .set_monotonic_for_test(deadline);
        let violations = transfer.coordinator.counters().violations;
        let (handled, entry) = fire(&mut transfer, kind)?;
        assert!(
            !handled,
            "the owner claimed a {kind:?} entry addressed to {id:?}"
        );
        assert_eq!(entry.id, id);
        assert_eq!(transfer.coordinator.counters().violations, violations);
    }
    Ok(())
}

/// The ESTATE token lifetime is fatal for the link that holds it: the due
/// entry releases the cut and retires the exact live link it was armed for.
#[tokio::test]
async fn an_expired_estate_token_retires_its_live_link_from_the_owner_heap() -> TestResult {
    let mut transfer = Transfer::open(2, 1 << 20).await?;
    assert!(transfer.cut_is_live()?);
    let (handled, entry) = fire(&mut transfer, TimerKind::CompanionSnapshotExpiry)?;
    assert!(handled);
    assert_eq!(entry.id, TimedId::Peer(PEER));
    assert_eq!(transfer.coordinator.counters().violations, 1);
    assert!(
        transfer
            .coordinator
            .peers
            .get(&PEER)
            .is_some_and(|state| state.live.is_none()),
        "the expired transfer kept its live link"
    );
    assert!(!transfer.cut_is_live()?);
    assert!(
        transfer.queue.recv().await.is_none(),
        "the retired link writer was not closed"
    );
    Ok(())
}

/// The same due entry with no live link releases the cut and reports the
/// timer handled, without inventing a link to retire.
#[tokio::test]
async fn an_expired_estate_token_without_a_live_link_retires_nothing() -> TestResult {
    let mut transfer = Transfer::open(2, 1 << 20).await?;
    transfer
        .coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("configured peer")?
        .live = None;
    let (handled, _) = fire(&mut transfer, TimerKind::CompanionSnapshotExpiry)?;
    assert!(handled);
    assert_eq!(transfer.coordinator.counters().violations, 0);
    assert!(!transfer.cut_is_live()?);
    Ok(())
}

/// An entry for a peer holding no cut expires nothing and retires no link,
/// so a stale wake cannot take a healthy transfer down.
#[tokio::test]
async fn a_due_entry_for_a_peer_holding_no_cut_retires_no_link() -> TestResult {
    let mut transfer = Transfer::open(2, 1 << 20).await?;
    transfer
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("installed executor")?
        .peers
        .remove(&PEER);
    let (handled, _) = fire(&mut transfer, TimerKind::CompanionSnapshotExpiry)?;
    assert!(handled);
    assert_eq!(transfer.coordinator.counters().violations, 0);
    assert!(
        transfer
            .coordinator
            .peers
            .get(&PEER)
            .is_some_and(|state| state.live.is_some()),
        "a wake for a peer with no cut retired its link anyway"
    );
    Ok(())
}
