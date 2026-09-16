//! STA-10: bounded per-connection delivery, fairness, and reservation ownership.

#![forbid(unsafe_code)]

use super::*;
use crate::budget::MemoryBudget;
use crate::state_core::inbox::{CloseReason, SignalEvent};
use crate::test_support::TestResult;
use agenc_ircd_client_wire::{FramedLine, MAX_PHYSICAL_LINE_BYTES, parse_message};
use std::sync::atomic::AtomicU64;
use std::time::Duration;

fn inputs(capacity: usize) -> TestResult<(ClientInputs, Arc<MemoryBudget>)> {
    let budget = Arc::new(MemoryBudget::new(16 * 1_048_576));
    Ok((
        ClientInputs::new(capacity, BackingReservationPort::new(Arc::clone(&budget)))?,
        budget,
    ))
}

fn line(generation: u64, sequence: u64) -> TestResult<StateCoreMessage> {
    Ok(StateCoreMessage::Line {
        generation: ConnectionGeneration::new(generation),
        sequence,
        message: Box::new(parse_message(FramedLine::new("PING :queued")?)?.ok_or("empty line")?),
    })
}

fn assert_line(message: StateCoreMessage, generation: u64, sequence: u64) -> TestResult {
    match message {
        StateCoreMessage::Line {
            generation: actual,
            sequence: number,
            ..
        }
        | StateCoreMessage::QueuedLine {
            generation: actual,
            sequence: number,
            ..
        } => {
            assert_eq!(actual, ConnectionGeneration::new(generation));
            assert_eq!(number, sequence);
            Ok(())
        }
        _ => Err("unexpected queue message".into()),
    }
}

#[tokio::test]
async fn independent_connections_exceed_shared_64_bound_and_dispatch_round_robin() -> TestResult {
    let (inputs, budget) = inputs(2)?;
    let a = inputs.open(ConnectionGeneration::new(1))?;
    let b = inputs.open(ConnectionGeneration::new(2))?;
    for sequence in 1..=128 {
        a.send(line(1, sequence)?)?;
    }
    assert!(matches!(a.send(line(1, 129)?), Err(InputRefusal::Closed)));
    for sequence in 1..=40 {
        b.send(line(2, sequence)?)?;
    }
    assert_eq!(inputs.len(), 168);
    for sequence in 1..=40 {
        assert_line(inputs.recv().await, 1, sequence)?;
        assert_line(inputs.recv().await, 2, sequence)?;
    }
    for sequence in 41..=128 {
        assert_line(inputs.recv().await, 1, sequence)?;
    }
    assert_eq!(inputs.len(), 0);
    assert!(inputs.take().is_none());
    b.send(line(2, 41)?)?;
    assert_line(inputs.recv().await, 2, 41)?;
    drop((a, b, inputs));
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[tokio::test]
async fn producer_drop_keeps_queued_lines_and_slot_reserved_until_drain() -> TestResult {
    let (inputs, budget) = inputs(1)?;
    let baseline = budget.charged();
    let a = inputs.open(ConnectionGeneration::new(1))?;
    assert_eq!(budget.charged(), baseline, "an idle port holds no charge");
    a.send(line(1, 1)?)?;
    drop(a);
    assert!(matches!(
        inputs.open(ConnectionGeneration::new(2)),
        Err(RuntimeError::LimitExceeded)
    ));
    assert_line(inputs.recv().await, 1, 1)?;
    assert_eq!(budget.charged(), baseline);
    drop(inputs.open(ConnectionGeneration::new(2))?);
    assert_eq!(budget.charged(), baseline);
    drop(inputs);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[tokio::test]
async fn invalid_authority_and_consumer_close_refuse_publication_and_wake_waiters() -> TestResult {
    let (inputs, budget) = inputs(1)?;
    let a = inputs.open(ConnectionGeneration::new(1))?;
    assert!(matches!(a.send(line(2, 1)?), Err(InputRefusal::Closed)));
    assert!(matches!(
        a.send(StateCoreMessage::Signal(SignalEvent::Reload)),
        Err(InputRefusal::Closed)
    ));
    assert_eq!(inputs.len(), 0);
    a.send(line(1, 1)?)?;
    {
        let closed = a.closed();
        tokio::pin!(closed);
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut closed)
                .await
                .is_err()
        );
        drop(inputs);
        tokio::time::timeout(Duration::from_secs(1), closed).await?;
    }
    assert!(lock(&a.queue.state).is_empty());
    tokio::time::timeout(Duration::from_secs(1), a.closed()).await?;
    assert!(matches!(a.send(line(1, 2)?), Err(InputRefusal::Closed)));
    drop(a);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn invalid_capacity_and_unfunded_backing_refuse_without_leaking_reservations() -> TestResult {
    let empty = Arc::new(MemoryBudget::new(0));
    let backing = BackingReservationPort::new(Arc::clone(&empty));
    for capacity in [0, MAX_TRACKED_CONNECTIONS + 1] {
        assert!(matches!(
            ClientInputs::new(capacity, backing.clone()),
            Err(RuntimeError::InvalidValue)
        ));
    }
    assert!(matches!(
        ClientInputs::new(1, backing),
        Err(RuntimeError::MemoryExhausted)
    ));
    assert_eq!(empty.charged(), 0);
    let (funded, budget) = inputs(1)?;
    let exact = Arc::new(MemoryBudget::new(budget.charged()));
    let unfunded = ClientInputs::new(1, BackingReservationPort::new(Arc::clone(&exact)))?;
    let port = unfunded.open(ConnectionGeneration::new(1))?;
    port.send(line(1, 1)?)?;
    for _ in 0..2 {
        let Err(InputRefusal::MemoryExhausted(returned)) = port.send(line(1, 2)?) else {
            return Err("overflow storage was not refused".into());
        };
        assert_line(returned, 1, 2)?;
        assert_eq!(unfunded.len(), 1, "a refused line publishes nothing");
        assert_eq!(unfunded.slots.available_permits(), 0);
    }
    assert_line(unfunded.take().ok_or("queued line")?, 1, 1)?;
    drop((funded, port, unfunded));
    assert_eq!(exact.charged(), 0);
    Ok(())
}

/// Exact input permits: idle is free, the second outstanding line brings one
/// quantum, growth replaces it with the request maximum, and the overflow's
/// allocation and charge leave together when it drains.
#[tokio::test]
async fn input_overflow_is_charged_on_demand_and_released_when_drained() -> TestResult {
    let (inputs, budget) = inputs(1)?;
    let fixed = budget.charged();
    let port = inputs.open(ConnectionGeneration::new(3))?;
    assert_eq!(FIRST_OVERFLOW_SLOTS, 68);
    assert_eq!(MAX_OVERFLOW_SLOTS, 127);
    port.send(line(3, 1)?)?;
    assert_eq!(budget.charged(), fixed, "one line waits inline");
    port.send(line(3, 2)?)?;
    assert_eq!(
        budget.charged(),
        fixed + 4_096,
        "the first overflow is one quantum"
    );
    for sequence in 3..=69 {
        port.send(line(3, sequence)?)?;
    }
    assert_eq!(
        budget.charged(),
        fixed + 4_096,
        "68 overflow lines fit one quantum"
    );
    port.send(line(3, 70)?)?;
    assert_eq!(
        budget.charged(),
        fixed + 8_192,
        "growth replaced the quantum with the request maximum"
    );
    for sequence in 71..=128 {
        port.send(line(3, sequence)?)?;
    }
    assert_eq!(budget.charged(), fixed + 8_192);
    assert!(matches!(
        port.send(line(3, 129)?),
        Err(InputRefusal::Closed)
    ));
    for sequence in 1..=127 {
        assert_line(inputs.recv().await, 3, sequence)?;
        assert_eq!(
            budget.charged(),
            fixed + 8_192,
            "partial drain keeps the storage"
        );
    }
    assert_line(inputs.recv().await, 3, 128)?;
    assert_eq!(
        budget.charged(),
        fixed,
        "the drained overflow released its charge"
    );
    port.send(line(3, 129)?)?;
    assert_eq!(budget.charged(), fixed, "an emptied queue is inline again");
    drop((port, inputs));
    assert_eq!(budget.charged(), 0);
    Ok(())
}

/// Arrival order holds across the inline slot and the overflow: after the
/// inline line drains, new lines follow the overflow rather than jump ahead.
#[tokio::test]
async fn inline_and_overflow_lines_keep_arrival_order() -> TestResult {
    let (inputs, budget) = inputs(1)?;
    let fixed = budget.charged();
    let port = inputs.open(ConnectionGeneration::new(4))?;
    for sequence in 1..=3 {
        port.send(line(4, sequence)?)?;
    }
    assert_line(inputs.recv().await, 4, 1)?;
    port.send(line(4, 4)?)?;
    for sequence in 2..=4 {
        assert_line(inputs.recv().await, 4, sequence)?;
    }
    assert_eq!(budget.charged(), fixed);
    Ok(())
}

/// A reader whose overflow cannot be charged stays paused, retries, and
/// delivers once memory returns; a starved reader closes after the stall
/// budget without publishing a partial line.
#[tokio::test(start_paused = true)]
async fn exhausted_input_storage_pauses_the_reader_until_memory_returns_or_the_stall_ends()
-> TestResult {
    let (inputs, budget) = inputs(2)?;
    let spare = budget.available();
    let hold = BackingReservationPort::new(Arc::clone(&budget))
        .reserve(usize::try_from(spare).map_err(|_| "spare")? - 256)?;
    assert_eq!(budget.available(), 0);
    let port = inputs.open(ConnectionGeneration::new(5))?;
    let task = tokio::spawn(crate::connection::reader::run_reader_sequenced(
        &b"PING :one\r\nPING :two\r\n"[..],
        ConnectionGeneration::new(5),
        crate::connection::ReaderLimits::new(4, 131_072)?,
        None,
        port,
        crate::cancel::CancellationToken::root(),
        Arc::new(AtomicU64::new(0)),
    ));
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(
        inputs.len(),
        1,
        "the second line waits for overflow storage"
    );
    assert!(!task.is_finished());
    drop(hold);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(inputs.len(), 2);
    assert_line(inputs.recv().await, 5, 1)?;
    assert_line(inputs.recv().await, 5, 2)?;

    let hold = BackingReservationPort::new(Arc::clone(&budget))
        .reserve(usize::try_from(budget.available()).map_err(|_| "spare")? - 256)?;
    let starved = inputs.open(ConnectionGeneration::new(6))?;
    let task_two = tokio::spawn(crate::connection::reader::run_reader_sequenced(
        &b"PING :one\r\nPING :two\r\n"[..],
        ConnectionGeneration::new(6),
        crate::connection::ReaderLimits::new(4, 131_072)?,
        None,
        starved,
        crate::cancel::CancellationToken::root(),
        Arc::new(AtomicU64::new(0)),
    ));
    assert_eq!(task_two.await?, CloseReason::ReadStall);
    assert_line(inputs.recv().await, 6, 1)?;
    assert_eq!(inputs.len(), 0);
    drop((hold, task));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn reader_ledger_stays_charged_after_dequeue_and_close_wakes_paused_reader() -> TestResult {
    let (inputs, budget) = inputs(1)?;
    let port = inputs.open(ConnectionGeneration::new(7))?;
    let task = tokio::spawn(crate::connection::reader::run_reader_sequenced(
        &b"PING :one\r\nPING :two\r\nPING :three\r\n"[..],
        ConnectionGeneration::new(7),
        crate::connection::ReaderLimits::new(1, 131_072)?,
        None,
        port,
        crate::cancel::CancellationToken::root(),
        Arc::new(AtomicU64::new(0)),
    ));
    let first = inputs.recv().await;
    tokio::time::advance(Duration::from_secs(29)).await;
    assert_eq!(inputs.len(), 0);
    assert!(!task.is_finished());
    assert_line(first, 7, 1)?;
    let second = inputs.recv().await;
    assert_line(second, 7, 2)?;
    drop(inputs);
    assert_eq!(task.await?, CloseReason::Shutdown);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn reader_byte_ceiling_times_out_without_consuming_another_connections_slots() -> TestResult {
    let (inputs, _) = inputs(2)?;
    let port = inputs.open(ConnectionGeneration::new(7))?;
    let other = inputs.open(ConnectionGeneration::new(8))?;
    let wire = format!(
        "PING :{}\r\nPING :next\r\n",
        "a".repeat(MAX_PHYSICAL_LINE_BYTES - 8)
    );
    let result = crate::connection::reader::run_reader_sequenced(
        wire.as_bytes(),
        ConnectionGeneration::new(7),
        crate::connection::ReaderLimits::new(128, MAX_PHYSICAL_LINE_BYTES)?,
        None,
        port,
        crate::cancel::CancellationToken::root(),
        Arc::new(AtomicU64::new(0)),
    )
    .await;
    assert_eq!(result, CloseReason::ReadStall);
    other.send(line(8, 1)?)?;
    assert_line(inputs.recv().await, 7, 1)?;
    assert_line(inputs.recv().await, 8, 1)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_producers_and_consumer_preserve_every_line_without_lost_wakes() -> TestResult {
    let (inputs, _) = inputs(8)?;
    let mut tasks = Vec::new();
    for generation in 1..=8 {
        let port = inputs.open(ConnectionGeneration::new(generation))?;
        tasks.push(tokio::spawn(async move {
            for sequence in 1..=128 {
                port.send(line(generation, sequence).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
                tokio::task::yield_now().await;
            }
            Result::<(), String>::Ok(())
        }));
    }
    let mut observed = std::collections::BTreeMap::new();
    for _ in 0..1024 {
        let message = tokio::time::timeout(Duration::from_secs(5), inputs.recv()).await?;
        let StateCoreMessage::Line {
            generation,
            sequence,
            ..
        } = message
        else {
            return Err("unexpected message".into());
        };
        let previous = observed.entry(generation).or_insert(0);
        assert_eq!(sequence, *previous + 1);
        *previous = sequence;
    }
    for task in tasks {
        task.await??;
    }
    assert_eq!(observed.len(), 8);
    assert!(observed.values().all(|sequence| *sequence == 128));
    assert_eq!(inputs.len(), 0);
    Ok(())
}

#[tokio::test]
async fn continuously_ready_input_yields_to_other_runtime_tasks() -> TestResult {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (inputs, _) = inputs(1)?;
    let port = inputs.open(ConnectionGeneration::new(1))?;
    port.send(line(1, 1)?)?;
    let observed = Arc::new(AtomicBool::new(false));
    let running = Arc::clone(&observed);
    let task = tokio::spawn(async move {
        running.store(true, Ordering::Release);
    });
    for sequence in 1..=512 {
        assert_line(inputs.recv().await, 1, sequence)?;
        port.send(line(1, sequence + 1)?)?;
    }
    assert!(
        observed.load(Ordering::Acquire),
        "ready input monopolized the runtime worker"
    );
    task.await?;
    Ok(())
}

/// The queue state's own rules, driven directly: a line arriving after the
/// consumer drained the queue discards the storage prepared for it, a full
/// overflow or a missing one refuses a push, and the inline slot returns
/// after every drain.
#[test]
fn queue_state_discards_unneeded_growth_and_refuses_pushes_without_room() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(16 * 1_048_576));
    let backing = BackingReservationPort::new(Arc::clone(&budget));
    let mut state = QueueState {
        inline: None,
        overflow: None,
        scheduled: false,
    };
    assert_eq!(state.growth(), None, "an empty queue needs no storage");
    state.push(line(1, 1)?).map_err(|_| "inline push")?;
    assert_eq!(state.growth(), Some(FIRST_OVERFLOW_SLOTS));
    let prepared = Overflow::reserve(&backing, FIRST_OVERFLOW_SLOTS)?;
    assert_eq!(budget.charged(), 4_096);
    assert_line(state.pop().ok_or("inline line")?, 1, 1)?;
    state.install(prepared);
    assert!(
        state.overflow.is_none(),
        "growth computed before a drain is not installed"
    );
    assert_eq!(
        budget.charged(),
        0,
        "the unneeded storage returned its charge"
    );

    state.push(line(1, 2)?).map_err(|_| "inline push")?;
    let refused = state.push(line(1, 3)?).err().ok_or("no overflow refuses")?;
    assert_line(refused, 1, 3)?;
    state.install(Overflow::reserve(&backing, 1)?);
    state.push(line(1, 3)?).map_err(|_| "overflow push")?;
    let refused = state
        .push(line(1, 4)?)
        .err()
        .ok_or("a full overflow refuses")?;
    assert_line(refused, 1, 4)?;
    assert_eq!(state.growth(), Some(MAX_OVERFLOW_SLOTS));
    state.install(Overflow::reserve(&backing, MAX_OVERFLOW_SLOTS)?);
    assert_eq!(
        budget.charged(),
        8_192,
        "the replaced storage returned its charge"
    );
    assert_line(state.pop().ok_or("line 2")?, 1, 2)?;
    assert_line(state.pop().ok_or("line 3")?, 1, 3)?;
    assert!(state.pop().is_none());
    assert_eq!(budget.charged(), 0);
    Ok(())
}

/// The reader inbox reports a closed port at once and keeps retrying a port
/// whose overflow storage the budget refuses until the line is published.
#[tokio::test(start_paused = true)]
async fn reader_inbox_reports_closed_ports_and_retries_exhausted_overflow() -> TestResult {
    use crate::connection::reader::inbox::ReaderInbox;
    let (inputs, budget) = inputs(1)?;
    let inbox = ReaderInbox::from(inputs.open(ConnectionGeneration::new(9))?);
    inbox.send(line(9, 1)?).await.map_err(|()| "first line")?;
    let hold = BackingReservationPort::new(Arc::clone(&budget))
        .reserve(usize::try_from(budget.available()).map_err(|_| "spare")? - 256)?;
    let retrying = tokio::spawn(async move {
        let outcome = inbox
            .send(line(9, 2).map_err(|error| error.to_string())?)
            .await;
        Ok::<_, String>((inbox, outcome))
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!retrying.is_finished(), "the exhausted line waits");
    drop(hold);
    let (inbox, outcome) = retrying.await??;
    assert_eq!(outcome, Ok(()));
    assert_line(inputs.recv().await, 9, 1)?;
    assert_line(inputs.recv().await, 9, 2)?;
    drop(inputs);
    assert_eq!(inbox.send(line(9, 3)?).await, Err(()));
    Ok(())
}
