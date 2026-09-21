//! RUN-04: exact on-demand output backing. An idle queue holds nothing; a
//! single-frame demand uses its ring entry; a larger demand's one storage
//! allocation is charged before `prepare` creates it and released with its
//! final frame, on close, or when the reservation never commits.

#![forbid(unsafe_code)]

use agenc_relay_client_wire::{RenderedMessage, WireMessage};

use super::*;
use crate::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge, PermitCursor,
};

type TestResult<T = ()> = Result<T, RuntimeError>;

fn frame(budget: &MemoryBudget, text: &str) -> TestResult<SharedClientFrame> {
    let message = WireMessage::new("server.test", "NOTICE", &["*"], Some(text))
        .map_err(|_| RuntimeError::InvalidValue)?;
    let measured = message.measure().map_err(|_| RuntimeError::InvalidValue)?;
    let bytes = u64::try_from(measured.bytes()).map_err(|_| RuntimeError::Overflow)?;
    let mut batch =
        budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::allocation(
            bytes,
        )?])?)?;
    let rendered: RenderedMessage<MemoryPermit> = measured
        .encode(&mut PermitCursor::new(&mut batch))
        .map_err(|_| RuntimeError::InvalidValue)?;
    Ok(Arc::new(rendered))
}

fn backing(budget: &MemoryBudget, charge: u64) -> TestResult<Option<MemoryPermit>> {
    if charge == 0 {
        return Ok(None);
    }
    let mut batch =
        budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(charge)])?)?;
    Ok(Some(
        batch
            .split_exact(charge)
            .ok_or(RuntimeError::InvalidValue)?,
    ))
}

fn demand_of(frames: &[SharedClientFrame]) -> TestResult<ClientQueueDemand> {
    ClientQueueDemand::new(frames.iter().map(|frame| frame.as_bytes().len()).collect())
}

fn prepare(
    budget: &MemoryBudget,
    queue: &WriterQueue,
    frames: &[SharedClientFrame],
) -> TestResult<ClientQueueReservation> {
    let tentative = queue
        .try_reserve(demand_of(frames)?)
        .map_err(|_| RuntimeError::LimitExceeded)?;
    let permit = backing(budget, tentative.backing_charge())?;
    queue
        .prepare(tentative, permit)
        .map_err(|_| RuntimeError::InvalidValue)
}

fn commit(budget: &MemoryBudget, queue: &WriterQueue, frames: &[SharedClientFrame]) -> TestResult {
    let prepared = prepare(budget, queue, frames)?;
    let bound = BoundedSharedClientFrames::for_reservation(&prepared, frames.to_vec())?;
    queue.commit(prepared, bound);
    Ok(())
}

fn drain(queue: &WriterQueue) -> Vec<SharedClientFrame> {
    let mut drained = Vec::new();
    while let QueuePop::Frame(frame) = queue.pop() {
        drained.push(frame);
    }
    drained
}

#[test]
fn frame_storage_charges_follow_the_allocation_table_at_every_boundary() -> TestResult {
    assert_eq!(frame_storage_charge(0), 0);
    assert_eq!(frame_storage_charge(1), 0, "one frame waits in its entry");
    for frames in [2_usize, 479, 480, 481, 991, 992, 993, 1_024] {
        let bytes = u64::try_from(frames * size_of::<SharedClientFrame>())
            .map_err(|_| RuntimeError::Overflow)?;
        assert_eq!(
            frame_storage_charge(frames),
            MemoryCharge::allocation(bytes)?.bytes(),
            "{frames}"
        );
    }
    assert_eq!(frame_storage_charge(2), 4_096);
    assert_eq!(frame_storage_charge(480), 4_096);
    assert_eq!(frame_storage_charge(481), 8_192);
    assert_eq!(frame_storage_charge(992), 8_192);
    assert_eq!(frame_storage_charge(993), 12_288);
    assert_eq!(frame_storage_charge(MAX_DEMAND_FRAMES), 12_288);
    assert_eq!(
        frame_storage_charge(usize::MAX),
        u64::MAX,
        "saturated, never wrapped"
    );
    Ok(())
}

#[test]
fn an_empty_queue_takes_its_first_storage_only_for_a_multi_frame_demand() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let one = frame(&budget, "one")?;
    let two = frame(&budget, "two")?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let idle = budget.charged();

    commit(&budget, &queue, std::slice::from_ref(&one))?;
    assert_eq!(budget.charged(), idle, "a single frame needs no storage");
    commit(&budget, &queue, &[one.clone(), two.clone()])?;
    assert_eq!(budget.charged(), idle + 4_096, "the first storage");
    let drained = drain(&queue);
    assert_eq!(drained.len(), 3);
    assert!(
        drained
            .iter()
            .zip([&one, &one, &two])
            .all(|(a, b)| Arc::ptr_eq(a, b))
    );
    assert_eq!(
        budget.charged(),
        idle,
        "the drained storage left with its frames"
    );
    Ok(())
}

#[test]
fn partial_drain_keeps_storage_until_the_final_frame_of_its_demand() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let shared = frame(&budget, "shared")?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let idle = budget.charged();
    let frames = vec![shared.clone(); 481];
    commit(&budget, &queue, &frames)?;
    commit(
        &budget,
        &queue,
        frames.get(..2).ok_or(RuntimeError::InvalidValue)?,
    )?;
    assert_eq!(budget.charged(), idle + 8_192 + 4_096);
    for remaining in (1..481).rev() {
        assert!(matches!(queue.pop(), QueuePop::Frame(_)));
        assert_eq!(budget.charged(), idle + 8_192 + 4_096, "{remaining} remain");
    }
    assert!(matches!(queue.pop(), QueuePop::Frame(_)));
    assert_eq!(budget.charged(), idle + 4_096, "the first demand drained");
    assert_eq!(drain(&queue).len(), 2);
    assert_eq!(budget.charged(), idle);
    assert_eq!(queue.normal_bytes(), 0);
    Ok(())
}

#[test]
fn default_and_hard_maxima_admit_every_batch_with_exact_storage_charges() -> TestResult {
    for (limits, batches) in [
        (QueueLimits::DEFAULT, 4_usize),
        (
            QueueLimits::new(MAX_OUTPUT_BYTES, MAX_CONTROL_OUTPUT_BYTES, MAX_QUEUE_ITEMS)?,
            MAX_RESPONSE_BATCHES,
        ),
    ] {
        let budget = MemoryBudget::new(64 * 1_048_576);
        let queue = WriterQueue::new(ConnectionGeneration::new(1), limits)?;
        let mut held = Vec::new();
        for _ in 0..batches {
            let tentative = queue
                .try_reserve(ClientQueueDemand::new(vec![1; MAX_DEMAND_FRAMES])?)
                .map_err(|_| RuntimeError::LimitExceeded)?;
            assert_eq!(tentative.backing_charge(), 12_288);
            let permit = backing(&budget, tentative.backing_charge())?;
            held.push(
                queue
                    .prepare(tentative, permit)
                    .map_err(|_| RuntimeError::InvalidValue)?,
            );
        }
        assert_eq!(
            budget.charged(),
            12_288 * u64::try_from(batches).map_err(|_| RuntimeError::Overflow)?
        );
        assert_eq!(
            queue.try_reserve(ClientQueueDemand::new(vec![1])?).err(),
            Some(SinkReserveError::Full),
            "every response batch is open"
        );
        drop(held);
        assert_eq!(
            budget.charged(),
            0,
            "prepared storage left with its permits"
        );
        assert_eq!(queue.normal_bytes(), 0);
    }
    Ok(())
}

#[test]
fn a_configured_item_ceiling_refuses_before_any_storage_is_charged() -> TestResult {
    let limits = QueueLimits::new(400_000, 100, 2 + CONTROL_ITEM_SLOTS)?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), limits)?;
    assert_eq!(
        queue.try_reserve(ClientQueueDemand::new(vec![1; 3])?).err(),
        Some(SinkReserveError::Full)
    );
    let fits = queue
        .try_reserve(ClientQueueDemand::new(vec![1; 2])?)
        .map_err(|_| RuntimeError::LimitExceeded)?;
    assert_eq!(fits.backing_charge(), 4_096);
    Ok(())
}

#[test]
fn cancellation_before_and_after_prepare_returns_counts_permit_and_storage() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let text = frame(&budget, "cancel")?;
    let frames = vec![text.clone(); 3];
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let idle = budget.charged();

    let tentative = queue
        .try_reserve(demand_of(&frames)?)
        .map_err(|_| RuntimeError::LimitExceeded)?;
    assert_eq!(queue.normal_bytes(), text.as_bytes().len() * 3);
    drop(tentative);
    assert_eq!(queue.normal_bytes(), 0);
    assert_eq!(budget.charged(), idle, "nothing was charged before prepare");

    let prepared = prepare(&budget, &queue, &frames)?;
    assert_eq!(budget.charged(), idle + 4_096);
    drop(prepared);
    assert_eq!(queue.normal_bytes(), 0);
    assert_eq!(
        budget.charged(),
        idle,
        "the prepared storage and permit returned"
    );

    let wrong = queue
        .try_reserve(demand_of(&frames)?)
        .map_err(|_| RuntimeError::LimitExceeded)?;
    assert_eq!(
        queue.prepare(wrong, None).err(),
        Some(QueueAllocationError::PermitMismatch)
    );
    assert_eq!(queue.normal_bytes(), 0, "a mismatch rolled the demand back");
    Ok(())
}

#[test]
fn consumer_drop_releases_every_queued_storage_and_shared_frame_charge_once() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let shared = frame(&budget, "fanout")?;
    let frame_charge = budget.charged();
    let first = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let second = WriterQueue::new(ConnectionGeneration::new(2), QueueLimits::DEFAULT)?;
    commit(&budget, &first, &[shared.clone(), shared.clone()])?;
    commit(&budget, &second, &[shared.clone(), shared.clone()])?;
    commit(&budget, &second, std::slice::from_ref(&shared))?;
    assert_eq!(
        budget.charged(),
        frame_charge + 2 * 4_096,
        "the shared frame is charged once; each queue owns its storage"
    );
    drop(shared);
    drop(first);
    assert_eq!(budget.charged(), frame_charge + 4_096);
    drop(second);
    assert_eq!(budget.charged(), 0, "the last reference returned the frame");
    Ok(())
}

#[test]
fn a_query_snapshot_on_charged_storage_drains_with_the_final_frame() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let row = frame(&budget, "row")?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let frames = vec![row.clone(); 3];
    let snapshot = backing(&budget, 8_192)?.ok_or(RuntimeError::InvalidValue)?;
    let prepared = prepare(&budget, &queue, &frames)?
        .with_query_snapshot(QuerySnapshotPermit::new(9, snapshot));
    let bound = BoundedSharedClientFrames::for_reservation(&prepared, frames)?;
    queue.commit(prepared, bound);
    let with_snapshot = budget.charged();
    assert_eq!(queue.queue_snapshot().query_rows(), 9);
    for _ in 0..2 {
        assert!(matches!(queue.pop(), QueuePop::Frame(_)));
        assert_eq!(budget.charged(), with_snapshot);
    }
    assert!(matches!(queue.pop(), QueuePop::Frame(_)));
    assert_eq!(budget.charged(), with_snapshot - 4_096 - 8_192);
    assert_eq!(queue.queue_snapshot().query_snapshots(), 0);
    Ok(())
}

#[test]
fn a_commit_to_another_generation_or_after_close_discards_its_storage() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let text = frame(&budget, "fence")?;
    let frames = vec![text.clone(); 2];
    let earlier = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let later = WriterQueue::new(ConnectionGeneration::new(2), QueueLimits::DEFAULT)?;
    let idle = budget.charged();

    let prepared = prepare(&budget, &earlier, &frames)?;
    let bound = BoundedSharedClientFrames::for_reservation(&prepared, frames.clone())?;
    later.commit(prepared, bound);
    assert!(matches!(later.pop(), QueuePop::Empty));
    assert_eq!(earlier.normal_bytes(), 0, "the foreign commit rolled back");
    assert_eq!(budget.charged(), idle);

    let prepared = prepare(&budget, &earlier, &frames)?;
    let bound = BoundedSharedClientFrames::for_reservation(&prepared, frames)?;
    earlier.close(CloseReason::TransportLoss, ClosePolicy::Immediate);
    earlier.commit(prepared, bound);
    assert_eq!(budget.charged(), idle);
    assert!(matches!(
        earlier.pop(),
        QueuePop::Closed(CloseReason::TransportLoss)
    ));
    Ok(())
}

#[test]
fn a_multi_frame_reservation_without_prepared_storage_excludes_the_whole_sink() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let text = frame(&budget, "foreign")?;
    let frames = vec![text.clone(); 2];
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let ledger: Arc<dyn QueueReservationLedger> = queue.shared.clone();
    {
        let mut state = lock(&queue.shared.state);
        assert_eq!(
            WriterQueue::admit_normal(&mut state, &demand_of(&frames)?, QueueLimits::DEFAULT, 4),
            Some(Placement::Ring)
        );
    }
    let tentative = TentativeClientQueueReservation::new(
        ConnectionGeneration::new(1),
        demand_of(&frames)?,
        0,
        ledger,
    );
    let prepared =
        ClientQueueReservation::prepare(tentative, None).map_err(|_| RuntimeError::InvalidValue)?;
    let bound = BoundedSharedClientFrames::for_reservation(&prepared, frames)?;
    queue.commit(prepared, bound);
    assert_eq!(queue.closed_reason(), Some(CloseReason::SlowConsumer));
    assert_eq!(queue.normal_bytes(), 0);
    assert!(matches!(
        queue.pop(),
        QueuePop::Closed(CloseReason::SlowConsumer)
    ));
    Ok(())
}

#[test]
fn a_full_entry_ring_excludes_the_sink_instead_of_dropping_a_frame() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let text = frame(&budget, "ring")?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let prepared = prepare(&budget, &queue, std::slice::from_ref(&text))?;
    {
        let mut state = lock(&queue.shared.state);
        while state
            .entries
            .push_back(Entry::Control(0, text.clone()))
            .is_ok()
        {}
        assert_eq!(state.entries.len, QUEUE_ENTRY_SLOTS);
    }
    let bound = BoundedSharedClientFrames::for_reservation(&prepared, vec![text])?;
    queue.commit(prepared, bound);
    assert_eq!(queue.closed_reason(), Some(CloseReason::SlowConsumer));
    assert_eq!(queue.normal_bytes(), 0);
    Ok(())
}

#[test]
fn the_ring_holds_every_admissible_batch_and_the_control_reserve() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let small = frame(&budget, "s")?;
    let limits = QueueLimits::new(MAX_OUTPUT_BYTES, MAX_CONTROL_OUTPUT_BYTES, MAX_QUEUE_ITEMS)?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), limits)?;
    for _ in 0..MAX_RESPONSE_BATCHES {
        let prepared = prepare(&budget, &queue, &[small.clone(), small.clone()])?;
        assert!(prepared.cell_is_absent(), "the ring holds this demand");
        let frames = vec![small.clone(), small.clone()];
        let bound = BoundedSharedClientFrames::for_reservation(&prepared, frames)?;
        queue.commit(prepared, bound);
    }
    let next = queue
        .try_reserve(ClientQueueDemand::new(vec![1])?)
        .map_err(|_| RuntimeError::LimitExceeded)?;
    assert_eq!(next.backing_charge(), OVERFLOW_CELL_CHARGE);
    drop(next);
    for _ in 0..CONTROL_ITEM_SLOTS {
        queue
            .push_control(small.clone())
            .map_err(|_| RuntimeError::LimitExceeded)?;
    }
    assert_eq!(
        queue.push_control(small.clone()).err(),
        Some(SinkReserveError::Full)
    );
    assert_eq!(
        drain(&queue).len(),
        2 * MAX_RESPONSE_BATCHES + CONTROL_ITEM_SLOTS
    );
    Ok(())
}

#[test]
fn the_emergency_control_frame_needs_no_storage_under_normal_exhaustion() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let text = frame(&budget, "fatal")?;
    let limits = QueueLimits::new(1_200, 400, 2 + CONTROL_ITEM_SLOTS)?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), limits)?;
    commit(&budget, &queue, &[text.clone(), text.clone()])?;
    assert_eq!(
        queue.try_reserve(ClientQueueDemand::new(vec![1])?).err(),
        Some(SinkReserveError::Full)
    );
    let charged = budget.charged();
    queue
        .push_control(text.clone())
        .map_err(|_| RuntimeError::LimitExceeded)?;
    assert_eq!(
        budget.charged(),
        charged,
        "control frames use their ring entry"
    );
    Ok(())
}

#[tokio::test]
async fn shutdown_after_flush_delivers_charged_storage_then_releases_it() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let text = frame(&budget, "flush")?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let idle = budget.charged();
    commit(&budget, &queue, &[text.clone(), text.clone(), text.clone()])?;
    let acknowledgement = queue.shutdown_after_flush();
    assert_eq!(
        budget.charged(),
        idle + 4_096,
        "accepted frames stay charged"
    );
    assert_eq!(drain(&queue).len(), 3);
    assert_eq!(budget.charged(), idle);
    assert!(matches!(
        queue.pop(),
        QueuePop::Closed(CloseReason::Shutdown)
    ));
    queue.acknowledge_flush();
    acknowledgement.wait().await;

    let immediate = WriterQueue::new(ConnectionGeneration::new(2), QueueLimits::DEFAULT)?;
    commit(&budget, &immediate, &[text.clone(), text.clone()])?;
    assert_eq!(budget.charged(), idle + 4_096);
    immediate.close(CloseReason::SlowConsumer, ClosePolicy::Immediate);
    assert_eq!(
        budget.charged(),
        idle,
        "an immediate close released the storage"
    );
    Ok(())
}

#[test]
fn a_frame_group_bound_to_another_reservation_is_discarded_whole() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let text = frame(&budget, "token")?;
    let frames = vec![text.clone(); 2];
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let idle = budget.charged();
    let first = prepare(&budget, &queue, &frames)?;
    let second = prepare(&budget, &queue, &frames)?;
    let bound_to_first = BoundedSharedClientFrames::for_reservation(&first, frames)?;
    queue.commit(second, bound_to_first);
    assert!(
        matches!(queue.pop(), QueuePop::Empty),
        "nothing was delivered"
    );
    assert!(!queue.is_closed());
    assert_eq!(
        budget.charged(),
        idle + 4_096,
        "only the first reservation remains"
    );
    drop(first);
    assert_eq!(budget.charged(), idle);
    assert_eq!(queue.normal_bytes(), 0);
    Ok(())
}

#[test]
fn draining_a_smaller_query_snapshot_first_keeps_the_largest_until_it_drains() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let row = frame(&budget, "row")?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    for rows in [9_u64, 20] {
        let frames = vec![row.clone(); 2];
        let snapshot = backing(&budget, 4_096)?.ok_or(RuntimeError::InvalidValue)?;
        let prepared = prepare(&budget, &queue, &frames)?
            .with_query_snapshot(QuerySnapshotPermit::new(rows, snapshot));
        let bound = BoundedSharedClientFrames::for_reservation(&prepared, frames)?;
        queue.commit(prepared, bound);
    }
    assert_eq!(queue.queue_snapshot().largest_query_rows(), 20);
    assert!(matches!(queue.pop(), QueuePop::Frame(_)));
    assert!(matches!(queue.pop(), QueuePop::Frame(_)));
    let after_smaller = queue.queue_snapshot();
    assert_eq!(after_smaller.query_snapshots(), 1);
    assert_eq!(
        after_smaller.largest_query_rows(),
        20,
        "the smaller drain leaves the largest"
    );
    assert_eq!(drain(&queue).len(), 2);
    assert_eq!(queue.queue_snapshot().largest_query_rows(), 0);
    Ok(())
}

fn texts(frames: &[SharedClientFrame]) -> Vec<String> {
    frames
        .iter()
        .map(|frame| String::from_utf8_lossy(frame.as_bytes()).into_owned())
        .collect()
}

/// RUN-10: a sink is full at its byte or item ceiling, never at a count of
/// small demands. Thirty-two one-frame demands, a control frame, and one
/// multi-frame demand queue with no pop between them and drain in commit
/// order, and every charge returns with the last frame.
#[test]
fn small_demands_beyond_the_ring_queue_in_order_and_return_every_charge() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let idle = budget.charged();
    let mut expected = Vec::new();
    for index in 0..32 {
        let line = frame(&budget, &format!("burst-{index:02}"))?;
        expected.extend(texts(std::slice::from_ref(&line)));
        commit(&budget, &queue, &[line])?;
    }
    let control = frame(&budget, "control")?;
    expected.extend(texts(std::slice::from_ref(&control)));
    queue
        .push_control(control)
        .map_err(|_| RuntimeError::LimitExceeded)?;
    let pair = [frame(&budget, "pair-a")?, frame(&budget, "pair-b")?];
    expected.extend(texts(&pair));
    commit(&budget, &queue, &pair)?;
    drop(pair);
    assert_eq!(queue.closed_reason(), None);
    assert_eq!(texts(&drain(&queue)), expected);
    assert_eq!(queue.normal_bytes(), 0);
    assert_eq!(budget.charged(), idle, "cells, storage and frames returned");
    Ok(())
}

/// A ring demand committed after a demand beyond the ring still drains
/// after it: placement never reorders output.
#[test]
fn a_ring_demand_committed_after_an_overflow_demand_drains_after_it() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let lines: Vec<SharedClientFrame> = (0..6)
        .map(|index| frame(&budget, &format!("line-{index}")))
        .collect::<TestResult<_>>()?;
    for line in lines.iter().take(5) {
        commit(&budget, &queue, std::slice::from_ref(line))?;
    }
    assert!(matches!(queue.pop(), QueuePop::Frame(_)));
    assert!(matches!(queue.pop(), QueuePop::Frame(_)));
    let last = lines.last().ok_or(RuntimeError::InvalidValue)?;
    let prepared = prepare(&budget, &queue, std::slice::from_ref(last))?;
    assert!(prepared.cell_is_absent(), "a ring entry is free again");
    let bound = BoundedSharedClientFrames::for_reservation(&prepared, vec![last.clone()])?;
    queue.commit(prepared, bound);
    assert_eq!(texts(&drain(&queue)), texts(lines.get(2..).unwrap_or(&[])));
    Ok(())
}

/// The item ceiling is still the hard limit: the demand that crosses it is
/// refused whole and the sink joins the slow-consumer close list.
#[test]
fn the_item_ceiling_still_refuses_the_demand_that_crosses_it() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let limits = QueueLimits::new(4_096, 1_024, 6 + CONTROL_ITEM_SLOTS)?;
    let queue = WriterQueue::new(ConnectionGeneration::new(1), limits)?;
    let line = frame(&budget, "x")?;
    for _ in 0..6 {
        commit(&budget, &queue, std::slice::from_ref(&line))?;
    }
    assert_eq!(
        queue
            .try_reserve(demand_of(std::slice::from_ref(&line))?)
            .err(),
        Some(SinkReserveError::Full)
    );
    Ok(())
}

/// A slow-consumer close destroys the normal queue and leaves exactly the
/// armed `ERROR` line for the writer, then reports the close.
#[test]
fn a_slow_consumer_close_delivers_only_the_armed_error_line() -> TestResult {
    let budget = MemoryBudget::new(64 * 1_048_576);
    let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
    let notice = frame(&budget, "ERROR notice")?;
    queue.arm_slow_consumer_notice(notice.clone());
    for _ in 0..8 {
        commit(&budget, &queue, &[frame(&budget, "queued")?])?;
    }
    queue.begin_slow_consumer_close();
    assert_eq!(queue.normal_bytes(), 0);
    assert_eq!(texts(&drain(&queue)), texts(&[notice]));
    assert!(matches!(
        queue.pop(),
        QueuePop::Closed(CloseReason::SlowConsumer)
    ));
    queue.begin_slow_consumer_close();
    assert!(matches!(queue.pop(), QueuePop::Closed(_)), "sent once");
    Ok(())
}
