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
    assert!(matches!(
        a.send(line(1, 129)?),
        Err(RuntimeError::LimitExceeded)
    ));
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
    assert!(budget.charged() > baseline);
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
    assert!(matches!(
        a.send(line(2, 1)?),
        Err(RuntimeError::InvalidValue)
    ));
    assert!(matches!(
        a.send(StateCoreMessage::Signal(SignalEvent::Reload)),
        Err(RuntimeError::InvalidValue)
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
    assert!(lock(&a.queue.state).messages.is_empty());
    tokio::time::timeout(Duration::from_secs(1), a.closed()).await?;
    assert!(matches!(
        a.send(line(1, 2)?),
        Err(RuntimeError::LimitExceeded)
    ));
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
    for _ in 0..2 {
        assert!(matches!(
            unfunded.open(ConnectionGeneration::new(1)),
            Err(RuntimeError::MemoryExhausted)
        ));
        assert_eq!(unfunded.slots.available_permits(), 1);
    }
    drop((funded, unfunded));
    assert_eq!(exact.charged(), 0);
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
