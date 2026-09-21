//! Actual awaited link writes retain page backing after queue removal.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};
use crate::test_support::TestResult;
use std::future::Future as _;
use std::task::Poll;

fn writer(stream: tokio::io::DuplexStream) -> LinkLoop<tokio::io::DuplexStream> {
    let started = Instant::now();
    let timing = LinkTiming::SPEC;
    let (inbound, _receiver) = mpsc::channel(1);
    LinkLoop {
        writer: stream,
        keepalive: Keepalive {
            idle: timing.keepalive_idle,
            timeout: timing.keepalive_timeout,
            idle_deadline: started + timing.keepalive_idle,
            outstanding: None,
        },
        assembler: FragmentAssembler::new(),
        reservations: BTreeMap::new(),
        next_sweep: started + timing.assembly_sweep,
        started,
        context: LinkContext {
            link: LinkId::new(71),
            peer: ServerId::from_bytes([71; 16]),
            local_name: "edge.example".to_owned(),
            inbound,
            budget: ingress_budget(),
            token: CancellationToken::root(),
            timing,
            observer: None,
        },
    }
}

fn enqueue(budget: &MemoryBudget, handle: &LinkHandle) -> TestResult {
    let line = FederationLineText::from_rendered(":edge.example FPONG :held\r\n".to_owned())?;
    let charge = MemoryCharge::allocation(u64::try_from(line.backing_capacity())?)?;
    let permit = budget
        .try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?
        .split_exact(charge.bytes())
        .ok_or("missing output permit")?;
    handle.try_send_backed(line, Arc::new(permit))?;
    Ok(())
}

#[tokio::test]
async fn a_cancelled_pending_write_keeps_backing_until_the_actual_future_drops() -> TestResult {
    let budget = MemoryBudget::new(1 << 20);
    let (handle, mut queue) = link_queue(1 << 20);
    enqueue(&budget, &handle)?;
    let charged = budget.charged();
    let queued = handle.queued_bytes();
    assert!(charged > 0 && queued > 0);
    let item = queue.receiver.recv().await.ok_or("missing backed output")?;
    assert_eq!(budget.charged(), charged);
    assert_eq!(handle.queued_bytes(), queued);
    let (stream, _stalled_peer) = tokio::io::duplex(1);
    let mut link = writer(stream);
    let mut write = Box::pin(link.on_outbound(item, &queue));
    std::future::poll_fn(|cx| {
        assert!(matches!(write.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    assert_eq!(budget.charged(), charged);
    assert_eq!(handle.queued_bytes(), queued);
    drop(write);
    assert_eq!(budget.charged(), 0);
    assert_eq!(handle.queued_bytes(), 0);
    Ok(())
}

#[tokio::test]
async fn a_completed_actual_write_returns_its_output_backing_once() -> TestResult {
    let budget = MemoryBudget::new(1 << 20);
    let (handle, mut queue) = link_queue(1 << 20);
    enqueue(&budget, &handle)?;
    let item = queue.receiver.recv().await.ok_or("missing backed output")?;
    let (stream, mut peer) = tokio::io::duplex(512);
    let mut link = writer(stream);
    assert_eq!(link.on_outbound(item, &queue).await, Ok(()));
    assert_eq!(budget.charged(), 0);
    assert_eq!(handle.queued_bytes(), 0);
    let expected = b":edge.example FPONG :held\r\n";
    let mut received = vec![0; expected.len()];
    peer.read_exact(&mut received).await?;
    assert_eq!(received, expected);
    Ok(())
}

#[tokio::test]
async fn a_failed_actual_write_returns_its_output_backing_once() -> TestResult {
    let budget = MemoryBudget::new(1 << 20);
    let (handle, mut queue) = link_queue(1 << 20);
    enqueue(&budget, &handle)?;
    let item = queue.receiver.recv().await.ok_or("missing backed output")?;
    let (stream, peer) = tokio::io::duplex(1);
    drop(peer);
    let mut link = writer(stream);
    assert_eq!(
        link.on_outbound(item, &queue).await,
        Err(LinkCloseReason::Transport)
    );
    assert_eq!(budget.charged(), 0);
    assert_eq!(handle.queued_bytes(), 0);
    Ok(())
}
