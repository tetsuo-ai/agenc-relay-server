#![forbid(unsafe_code)]

//! A limit change wakes the owner through the same two-entry request queue that carries the
//! commit which follows it, so replacing a reservation may queue one notice, not two.

use super::*;
use crate::engine::tests::EngineFixture;

const FIRST: TransactionId = TransactionId::from_bytes([1; 16]);
const SECOND: TransactionId = TransactionId::from_bytes([2; 16]);

/// A writer holding one reservation over a live engine's published sizes, with the owner's
/// side of the request queue left undrained.
fn undrained_writer() -> Result<
    (
        EngineFixture,
        StorageLimitWriter,
        Receiver<StorageRequest>,
        StorageRuntimeLimits,
    ),
    StorageError,
> {
    let mut fixture = EngineFixture::create()?;
    let engine = fixture.engine_mut()?;
    let statistics = engine.statistics()?;
    let values = statistics.values();
    let limits = StorageRuntimeLimits::new(values[2], values[4], 10_000)?;
    let (cell, reader) = storage_limit_pair(limits);
    engine.replace_runtime_limit_reader(reader);
    let (requests, receiver) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
    let writer = StorageLimitWriter {
        limits: cell,
        requests,
    };
    writer.reserve(FIRST, limits, 0, 0)?;
    assert!(matches!(
        receiver.try_recv(),
        Ok(StorageRequest::LimitsChanged)
    ));
    Ok((fixture, writer, receiver, limits))
}

#[test]
fn replacing_a_reservation_leaves_a_request_slot_for_the_outcome_commit() -> Result<(), StorageError>
{
    let (_fixture, writer, receiver, limits) = undrained_writer()?;
    writer.replace_reservation(FIRST, SECOND, limits, 0, 0)?;
    // The owner has drained nothing. The request that follows still finds a slot.
    assert!(
        writer
            .requests
            .try_send(StorageRequest::LimitsChanged)
            .is_ok()
    );
    assert!(matches!(
        receiver.try_recv(),
        Ok(StorageRequest::LimitsChanged)
    ));
    writer.rollback(SECOND)
}

#[test]
fn a_rollback_and_a_reserve_fill_the_request_queue_by_themselves() -> Result<(), StorageError> {
    let (_fixture, writer, _receiver, limits) = undrained_writer()?;
    writer.rollback(FIRST)?;
    writer.reserve(SECOND, limits, 0, 0)?;
    assert!(matches!(
        writer.requests.try_send(StorageRequest::LimitsChanged),
        Err(TrySendError::Full(_))
    ));
    Ok(())
}

#[test]
fn replacing_an_unknown_reservation_is_refused_and_queues_nothing() -> Result<(), StorageError> {
    let (_fixture, writer, receiver, limits) = undrained_writer()?;
    assert!(
        writer
            .replace_reservation(SECOND, FIRST, limits, 0, 0)
            .is_err()
    );
    assert!(receiver.try_recv().is_err());
    Ok(())
}
