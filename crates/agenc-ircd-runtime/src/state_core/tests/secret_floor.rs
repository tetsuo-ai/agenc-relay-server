#![forbid(unsafe_code)]

//! The configured secret-lookup response floor (architecture 13.5).

use super::*;
use agenc_ircd_client_wire::WireMessage;
use agenc_ircd_types::MonotonicTick;

use crate::connection::sink::ConnectionGeneration;
use crate::state_core::inbox::SourceAddressKey;
use crate::state_core::timers::{TimedId, TimerKind};
use crate::sync::Arc;
use crate::test_support::{FrameSink, StateCoreFixture, TestResult};

fn generation(value: u64) -> ConnectionGeneration {
    ConnectionGeneration::new(value)
}

fn tick(value: u64) -> MonotonicTick {
    MonotonicTick::from_ticks(value)
}

fn frame() -> Result<WireMessage, Box<dyn std::error::Error>> {
    Ok(WireMessage::new(
        "server.example",
        "NOTICE",
        &["nick"],
        Some("No such channel #secret"),
    )?)
}

fn open_sink(
    context: &mut crate::state_core::StateCoreContext,
    value: u64,
) -> TestResult<Arc<FrameSink>> {
    let generation = generation(value);
    let sink = FrameSink::new(generation, true);
    let now = context.now();
    context.sessions_mut().open(
        generation,
        crate::purpose::ListenerPurpose::ClientTls,
        SourceAddressKey::onion_listener(),
        Arc::clone(&sink) as Arc<dyn crate::connection::ClientSink>,
        now,
    )?;
    Ok(sink)
}

/// The floor is measured from the command's start, so work that already
/// took longer than the floor adds no delay.
#[test]
fn the_deadline_follows_the_command_start() {
    for millis in [1_u64, 5, 50] {
        let mut floor = SecretFloor::new(millis);
        floor.begin(generation(1), tick(100));
        assert_eq!(
            floor.deadline(generation(1), tick(100)),
            Some(tick(100 + millis))
        );
        assert_eq!(floor.deadline(generation(1), tick(100 + millis)), None);
        // Work that already took longer than the floor adds no delay.
        assert_eq!(floor.deadline(generation(1), tick(100 + millis + 1)), None);
    }
    let mut floor = SecretFloor::new(5);
    floor.begin(generation(1), tick(100));
    assert_eq!(floor.deadline(generation(1), tick(100)), Some(tick(105)));
    assert_eq!(floor.deadline(generation(1), tick(104)), Some(tick(105)));
    // At and beyond the deadline nothing is held.
    assert_eq!(floor.deadline(generation(1), tick(105)), None);
    assert_eq!(floor.deadline(generation(1), tick(500)), None);
    // Another connection's command start never shortens this one's floor.
    assert_eq!(floor.deadline(generation(2), tick(100)), Some(tick(105)));
    // A zero floor holds nothing at all.
    let mut disabled = SecretFloor::new(0);
    disabled.begin(generation(1), tick(100));
    assert_eq!(disabled.deadline(generation(1), tick(100)), None);
}

/// One connection holds one response, released only at its deadline and
/// dropped with the connection.
#[test]
fn a_hold_is_released_once_at_its_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let budget = crate::sync::Arc::new(crate::budget::MemoryBudget::new(1 << 20));
    let port = crate::budget::BackingReservationPort::new(budget);
    let mut floor = SecretFloor::new(5);
    assert!(!floor.pending(generation(1)));
    floor
        .hold(generation(1), tick(105), vec![frame()?], port.reserve(64)?)
        .map_err(|()| "hold")?;
    assert!(floor.pending(generation(1)));
    // A second hold for the same connection is refused, and nothing is
    // released before the deadline.
    assert!(
        floor
            .hold(generation(1), tick(105), vec![frame()?], port.reserve(64)?)
            .is_err()
    );
    assert!(floor.take_due(generation(1), tick(104)).is_none());
    assert!(floor.take_due(generation(2), tick(200)).is_none());
    assert_eq!(
        floor
            .take_due(generation(1), tick(105))
            .map(|frames| frames.len()),
        Some(1)
    );
    assert!(!floor.pending(generation(1)));
    assert!(floor.take_due(generation(1), tick(200)).is_none());
    // A closed connection drops its hold and its command start.
    floor.begin(generation(3), tick(100));
    floor
        .hold(generation(3), tick(105), vec![frame()?], port.reserve(64)?)
        .map_err(|()| "hold")?;
    floor.discard(generation(3));
    assert!(!floor.pending(generation(3)));
    assert_eq!(floor.deadline(generation(3), tick(100)), Some(tick(105)));
    Ok(())
}

/// A floored response waits for its deadline, leaves its connection owing
/// an answer meanwhile, and goes out exactly once.
#[tokio::test]
async fn a_held_response_reaches_its_connection_only_after_the_floor() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let sink = open_sink(fixture.context_mut()?, 1)?;
    let context = fixture.context_mut()?;
    context.set_monotonic_for_test(100);
    context.begin_secret_floor(generation(1));
    assert!(
        context
            .hold_secret_floor(generation(1), vec![frame()?])
            .is_ok()
    );
    assert!(context.secret_floor_pending(generation(1)));
    assert!(sink.lines().is_empty());
    // Its timer names the exact connection and deadline.
    assert!(context.timers_mut().pop_due(tick(104)).is_none());
    let due = context
        .timers_mut()
        .pop_due(tick(105))
        .ok_or("the floor timer")?;
    assert_eq!(due.kind, TimerKind::SecretChannelFloor);
    assert_eq!(due.id, TimedId::Connection(generation(1)));
    // Before the deadline nothing is released.
    context.set_monotonic_for_test(104);
    assert!(!context.release_secret_floor(generation(1)));
    assert!(sink.lines().is_empty());
    // Anything the connection is told meanwhile queues behind it.
    assert!(context.send_to(generation(1), vec![frame()?]).is_ok());
    assert!(sink.lines().is_empty());
    context.set_monotonic_for_test(105);
    assert!(context.release_secret_floor(generation(1)));
    assert_eq!(sink.lines().len(), 2);
    assert!(
        sink.lines()
            .first()
            .is_some_and(|line| line.contains("NOTICE") && line.contains("#secret"))
    );
    // The response goes out once, and its connection owes nothing more:
    // a later frame is published immediately again.
    assert!(!context.secret_floor_pending(generation(1)));
    assert!(!context.release_secret_floor(generation(1)));
    assert!(context.send_to(generation(1), vec![frame()?]).is_ok());
    assert_eq!(sink.lines().len(), 3);
    Ok(())
}

/// Work that already exceeded the floor is answered at once, and a closed
/// connection's retained response is dropped rather than published.
#[tokio::test]
async fn slow_work_is_not_delayed_and_a_closed_connection_drops_its_hold() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let sink = open_sink(fixture.context_mut()?, 1)?;
    let context = fixture.context_mut()?;
    context.set_monotonic_for_test(100);
    context.begin_secret_floor(generation(1));
    context.set_monotonic_for_test(120);
    let frames = context
        .hold_secret_floor(generation(1), vec![frame()?])
        .err()
        .ok_or("a passed floor holds nothing")?;
    assert_eq!(frames.len(), 1);
    assert!(!context.secret_floor_pending(generation(1)));
    assert!(sink.lines().is_empty());
    // A hold that a close discards is never published.
    context.set_monotonic_for_test(200);
    context.begin_secret_floor(generation(1));
    assert!(
        context
            .hold_secret_floor(generation(1), vec![frame()?])
            .is_ok()
    );
    context.discard_secret_floor(generation(1));
    assert!(!context.secret_floor_pending(generation(1)));
    context.set_monotonic_for_test(300);
    assert!(!context.release_secret_floor(generation(1)));
    assert!(sink.lines().is_empty());
    Ok(())
}
