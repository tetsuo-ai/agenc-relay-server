//! The companion fetch continuation, driven through the owner's own commit
//! receipt: only a publication that still matches its private owner and its
//! exact live link is applied, and the page boundary the receipt advanced
//! survives every refusal.
#![forbid(unsafe_code)]

use super::*;

/// The page sequences the edge saw an `ESTATE END` for since the last drain.
async fn pages(transfer: &mut Transfer) -> TestResult<Vec<u32>> {
    let before: Vec<u32> = transfer.cursors.keys().copied().collect();
    transfer.read_pages().await?;
    Ok(transfer
        .cursors
        .keys()
        .copied()
        .filter(|page| !before.contains(page))
        .collect())
}

/// A continuation the receipt accepts publishes exactly the next page to the
/// link the fetch named, and the cut runs to its final page that way.
#[tokio::test]
async fn a_committed_continuation_publishes_the_next_page_to_its_exact_link() -> TestResult {
    let mut transfer = Transfer::open(3, 1 << 20).await?;
    assert_eq!(
        transfer.cursors.keys().copied().collect::<Vec<_>>(),
        vec![0]
    );
    transfer.fetch(1)?;
    assert!(transfer.coordinator.pending.is_some());
    transfer.settle().await?;
    assert_eq!(pages(&mut transfer).await?, vec![1]);
    assert_eq!(transfer.coordinator.counters().violations, 0);
    assert!(transfer.cut_is_live()?);
    transfer.fetch(2)?;
    transfer.settle().await?;
    transfer.read_pages().await?;
    assert_eq!(
        transfer.final_page,
        Some(2),
        "the cut never reached a page that ends without a cursor"
    );
    assert_eq!(transfer.coordinator.counters().violations, 0);
    Ok(())
}

/// A link queue that cannot hold the whole page stops the publication at the
/// byte boundary and retires the link rather than sending a partial page on.
#[tokio::test]
async fn a_continuation_that_overruns_the_link_queue_stops_at_the_byte_boundary() -> TestResult {
    let mut transfer = Transfer::open(3, 1 << 20).await?;
    let narrow = transfer.relink(LINK, 1_024)?;
    drop(narrow);
    transfer.fetch(1)?;
    transfer.settle().await?;
    assert_eq!(
        transfer.coordinator.counters().violations,
        1,
        "an overrun page was published whole"
    );
    assert!(
        transfer
            .coordinator
            .peers
            .get(&PEER)
            .is_some_and(|state| state.live.is_none()),
        "the overrun link was left live"
    );
    assert!(
        transfer.handle.queued_bytes() <= 1_024,
        "the queue accepted more than its own ceiling"
    );
    Ok(())
}

/// A continuation interrupted by a reconnection publishes nothing to the link
/// that is gone. The page the receipt committed is not lost: the edge fetches
/// the same page again over its new link and receives it.
#[tokio::test]
async fn a_continuation_interrupted_by_a_restart_resumes_at_the_last_committed_page() -> TestResult
{
    let mut transfer = Transfer::open(3, 1 << 20).await?;
    transfer.fetch(1)?;
    let retired = transfer.relink(LinkId::new(12), 1 << 20)?;
    drop(retired);
    transfer.settle().await?;
    assert_eq!(
        transfer.handle.queued_bytes(),
        0,
        "a page went out over a link the fetch never named"
    );
    assert_eq!(transfer.coordinator.counters().violations, 0);
    assert!(transfer.cut_is_live()?);
    transfer.fetch(1)?;
    assert!(
        transfer.coordinator.pending.is_none(),
        "a repeated page staged a second durable boundary"
    );
    assert_eq!(pages(&mut transfer).await?, vec![1]);
    assert_eq!(transfer.coordinator.counters().violations, 0);
    Ok(())
}

/// The owner the fetch named is the only publication the receipt may apply.
/// One that no longer matches retires the exact live link it was staged for.
#[tokio::test]
async fn a_continuation_whose_owner_moved_retires_its_exact_live_link() -> TestResult {
    let mut transfer = Transfer::open(3, 1 << 20).await?;
    transfer.fetch(1)?;
    transfer.drop_owner()?;
    transfer.settle().await?;
    assert_eq!(transfer.coordinator.counters().violations, 1);
    assert!(
        transfer
            .coordinator
            .peers
            .get(&PEER)
            .is_some_and(|state| state.live.is_none())
    );
    assert_eq!(transfer.handle.queued_bytes(), 0);
    assert!(transfer.queue.recv().await.is_none());
    Ok(())
}

/// The same refusal on a link that is already gone retires nothing, so a
/// reconnection that arrived first is not taken down by a stale receipt.
#[tokio::test]
async fn a_continuation_whose_owner_moved_on_a_lost_link_retires_nothing() -> TestResult {
    let mut transfer = Transfer::open(3, 1 << 20).await?;
    transfer.fetch(1)?;
    transfer.drop_owner()?;
    transfer
        .coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("configured peer")?
        .live = None;
    transfer.settle().await?;
    assert_eq!(
        transfer.coordinator.counters().violations,
        0,
        "a receipt for a link that was already gone retired one anyway"
    );
    Ok(())
}

/// A node with no companion executor holds no publication authority: the
/// continuation is discarded without a line, a link retirement or a counter.
#[tokio::test]
async fn a_continuation_without_an_executor_publishes_nothing() -> TestResult {
    let mut transfer = Transfer::open(3, 1 << 20).await?;
    transfer.fetch(1)?;
    transfer.settle_without_executor().await?;
    assert_eq!(transfer.handle.queued_bytes(), 0);
    assert_eq!(transfer.coordinator.counters().violations, 0);
    assert!(
        transfer
            .coordinator
            .peers
            .get(&PEER)
            .is_some_and(|state| state.live.is_some())
    );
    Ok(())
}
