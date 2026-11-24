//! Actual awaited link writes retain page backing after queue removal.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use crate::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge, MemoryPermit,
};
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

/// A single link slot and its byte window span a legal transfer much larger
/// than the queue. Retrying the same source starts from the original part zero.
#[tokio::test]
async fn large_companion_transfers_keep_fifo_and_budget_through_the_socket() -> TestResult {
    use crate::e2ee::outbound::{Reply, Transfer};
    use agenc_relay_e2ee::federation::frames::Correlation;
    use agenc_relay_e2ee::limits::MAX_FRAGMENT_RAW;
    use std::sync::Arc;

    let budget = MemoryBudget::new(32 << 20);
    let permit = |size| -> TestResult<MemoryPermit> {
        Ok(budget
            .try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(size)])?)?
            .split_exact(size)
            .ok_or("missing test permit")?)
    };
    let correlation = Correlation {
        peer_server_id: [2; 16],
        server_incarnation: [4; 16],
        origin_id: [8; 16],
        origin_generation: 3,
        operation_sequence: 71,
        request_id: [5; 16],
    };
    let small = vec![13; 51];
    let big = vec![29; 3 * 1024 * 1024 + 17];
    let size = u64::try_from(small.len() + big.len() + 2048)?;
    let make = |reply| -> TestResult<Arc<Transfer>> {
        let source = Some(Arc::new(permit(size)?));
        if reply {
            Reply::new(
                "edge.example",
                correlation,
                correlation.peer_server_id,
                small.clone(),
                vec![big.clone()],
                source,
            )
            .into_backed()
            .map_err(|e| e.to_string().into())
        } else {
            Transfer::request(
                "edge.example".to_owned(),
                correlation,
                small.clone(),
                Some(big.clone()),
                source,
            )
            .map_err(|e| e.to_string().into())
        }
    };
    let small_id = agenc_relay_e2ee::ObjectId::compute(&small);
    let big_id = agenc_relay_e2ee::ObjectId::compute(&big);
    for reply in [false, true] {
        let transfer = make(reply)?;
        let window = transfer.window();
        assert!((2940..8704).contains(&window));
        let (rejected, _closed) = link_queue(window - 1);
        assert_eq!(
            rejected.try_send_transfer(&transfer, permit(transfer.render_backing())?),
            Err(SendRefusal::QueueFull)
        );
        assert_eq!(rejected.queued_bytes(), 0);
        {
            let (handle, mut queue) = link_queue(window);
            handle
                .try_send_transfer(&transfer, permit(transfer.render_backing())?)
                .map_err(|_| "enqueue abandoned attempt")?;
            let first = queue.next_output().await.ok_or("abandoned beginning")?;
            let (stream, failed) = tokio::io::duplex(1);
            drop(failed);
            assert_eq!(
                writer(stream).on_outbound(first, &queue).await,
                Err(LinkCloseReason::Transport)
            );
            drop(queue);
            assert_eq!(handle.queued_bytes(), 0);
            assert_eq!(budget.charged(), size);
        }
        let (handle, mut queue) = link_queue(window + 128);
        handle
            .try_send_transfer(&transfer, permit(transfer.render_backing())?)
            .map_err(|_| "enqueue retry")?;
        let marker = FederationFrame::Pong {
            peer_server_id: ServerId::from_bytes([2; 16]),
            nonce: [72; 32],
        };
        let sentinel = marker.render("edge.example")?;
        let sentinel_len = u64::try_from(sentinel.len())?;
        handle.try_send(sentinel).map_err(|_| "enqueue sentinel")?;
        let (stream, peer) = tokio::io::duplex(512);
        let mut link = writer(stream);
        let mut reader = FrameReader::new(peer, "edge.example")?;
        let count = big.len().div_ceil(MAX_FRAGMENT_RAW);
        assert!(count > 1024);
        tokio::time::timeout(std::time::Duration::from_secs(25), async {
            for n in 0..=count {
                let item = queue
                    .next_output()
                    .await
                    .ok_or("missing physical fragment")?;
                assert_eq!(handle.queued_bytes(), window + sentinel_len);
                assert_eq!(budget.charged(), size + transfer.render_backing());
                let (sent, read) = tokio::join!(link.on_outbound(item, &queue), reader.next_line());
                assert_eq!(sent, Ok(()));
                let ParsedLine::Companion(frame) = read.map_err(|_| "S2S wire parse")? else {
                    return Err("interleaved normal output".into());
                };
                let fragment = match (reply, n, frame) {
                    (
                        true,
                        0,
                        CompanionFrame::Result {
                            correlation: got,
                            fragment,
                            ..
                        },
                    )
                    | (
                        true,
                        1..,
                        CompanionFrame::Response {
                            correlation: got,
                            response_index: 0,
                            fragment,
                            ..
                        },
                    )
                    | (
                        false,
                        0,
                        CompanionFrame::Request {
                            correlation: got,
                            fragment,
                            ..
                        },
                    )
                    | (
                        false,
                        1..,
                        CompanionFrame::Payload {
                            correlation: got,
                            fragment,
                            ..
                        },
                    ) => {
                        assert_eq!(got, correlation);
                        fragment
                    }
                    _ => return Err("correlation or carrier ordering".into()),
                };
                if n == 0 {
                    assert_eq!(fragment.object_id, small_id);
                    assert_eq!(fragment.segment, small);
                } else {
                    let start = (n - 1) * MAX_FRAGMENT_RAW;
                    assert_eq!(fragment.part as usize, n - 1);
                    assert_eq!(fragment.count as usize, count);
                    assert_eq!(fragment.total as usize, big.len());
                    assert_eq!(fragment.object_id, big_id);
                    assert_eq!(
                        Some(fragment.segment.as_slice()),
                        big.get(start..(start + MAX_FRAGMENT_RAW).min(big.len()))
                    );
                }
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await??;
        assert_eq!(handle.queued_bytes(), sentinel_len);
        assert_eq!(budget.charged(), size);
        let item = queue
            .next_output()
            .await
            .ok_or("missing trailing ordinary frame")?;
        let (sent, read) = tokio::join!(link.on_outbound(item, &queue), reader.next_line());
        assert_eq!(sent, Ok(()));
        assert!(
            matches!(read, Ok(ParsedLine::Base(FederationFrame::Pong { peer_server_id, nonce })) if peer_server_id == ServerId::from_bytes([2; 16]) && nonce == [72; 32])
        );
        assert_eq!(handle.queued_bytes(), 0);
        drop(transfer);
        assert_eq!(budget.charged(), 0);
    }
    Ok(())
}
