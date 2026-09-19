//! Every runtime-limit bound, and the reservation, checkpoint and poison
//! states of the shared limit cell.
#![forbid(unsafe_code)]

use super::*;

#[test]
fn runtime_limits_reject_each_bound_violation() -> Result<(), StorageError> {
    let too_large = MAX_STORAGE_BYTES.saturating_add(1);
    assert!(
        StorageRuntimeLimits::new(
            MIN_STORAGE_BYTES,
            MIN_STORAGE_BYTES,
            MIN_CHECKPOINT_MANIFESTS
        )
        .is_ok()
    );
    for (database, backup, manifests) in [
        (
            MIN_STORAGE_BYTES - 1,
            MIN_STORAGE_BYTES,
            MIN_CHECKPOINT_MANIFESTS,
        ),
        (too_large, too_large, MIN_CHECKPOINT_MANIFESTS),
        (
            MIN_STORAGE_BYTES,
            MIN_STORAGE_BYTES - 1,
            MIN_CHECKPOINT_MANIFESTS,
        ),
        (MIN_STORAGE_BYTES, too_large, MIN_CHECKPOINT_MANIFESTS),
        (
            MIN_STORAGE_BYTES + 1,
            MIN_STORAGE_BYTES,
            MIN_CHECKPOINT_MANIFESTS,
        ),
        (
            MIN_STORAGE_BYTES,
            MIN_STORAGE_BYTES,
            MIN_CHECKPOINT_MANIFESTS - 1,
        ),
        (
            MIN_STORAGE_BYTES,
            MIN_STORAGE_BYTES,
            MAX_RETAINED_MANIFESTS + 1,
        ),
    ] {
        assert_eq!(
            StorageRuntimeLimits::new(database, backup, manifests).err(),
            Some(StorageError::LimitExceeded)
        );
    }
    Ok(())
}

#[test]
fn limit_reservations_bind_to_their_token_and_respect_checkpoints_and_poison()
-> Result<(), StorageError> {
    let initial = StorageRuntimeLimits::new(
        MIN_STORAGE_BYTES * 4,
        MIN_STORAGE_BYTES * 8,
        MIN_CHECKPOINT_MANIFESTS,
    )?;
    let candidate = StorageRuntimeLimits::new(
        MIN_STORAGE_BYTES * 2,
        MIN_STORAGE_BYTES * 4,
        MIN_CHECKPOINT_MANIFESTS,
    )?;
    let (cell, reader) = storage_limit_pair(initial);
    let token = TransactionId::from_bytes([1; 16]);
    let other = TransactionId::from_bytes([2; 16]);
    assert_eq!(cell.finalize(token).err(), Some(StorageError::StaleState));
    assert_eq!(cell.rollback(token).err(), Some(StorageError::StaleState));
    assert_eq!(
        cell.activate(candidate).err(),
        Some(StorageError::Unavailable)
    );
    reader.publish_facts(1, 1, 1, 1);
    assert_eq!(
        cell.reserve(token, candidate, candidate.database_max_bytes + 1, 1)
            .err(),
        Some(StorageError::LimitExceeded)
    );
    assert_eq!(
        cell.reserve(token, candidate, 1, candidate.backup_max_bytes + 1)
            .err(),
        Some(StorageError::LimitExceeded)
    );
    cell.reserve(token, candidate, 1, 1)?;
    assert_eq!(
        cell.activate(candidate).err(),
        Some(StorageError::QueueFull)
    );
    assert_eq!(
        reader.begin_checkpoint().err(),
        Some(StorageError::QueueFull)
    );
    cell.restore_unreserved(initial);
    assert_eq!(
        reader.load().database_max_bytes,
        candidate.database_max_bytes
    );
    assert_eq!(cell.finalize(other).err(), Some(StorageError::StaleState));
    assert_eq!(cell.rollback(other).err(), Some(StorageError::StaleState));
    cell.rollback(token)?;
    assert_eq!(reader.load().database_max_bytes, initial.database_max_bytes);
    cell.restore_unreserved(candidate);
    assert_eq!(
        reader.load().database_max_bytes,
        candidate.database_max_bytes
    );

    reader.publish_facts(candidate.database_max_bytes + 1, 1, 1, 1);
    assert_eq!(
        cell.activate(candidate).err(),
        Some(StorageError::LimitExceeded)
    );
    reader.publish_facts(1, candidate.backup_max_bytes + 1, 1, 1);
    assert_eq!(
        cell.activate(candidate).err(),
        Some(StorageError::LimitExceeded)
    );
    reader.publish_facts(1, 1, 1, 1);
    let _checkpoint_limits = reader.begin_checkpoint()?;
    assert_eq!(
        cell.activate(candidate).err(),
        Some(StorageError::QueueFull)
    );
    assert_eq!(
        reader.begin_checkpoint().err(),
        Some(StorageError::QueueFull)
    );
    reader.finish_checkpoint();

    cell.reserve(token, candidate, 1, 1)?;
    cell.finalize(token)?;
    cell.reserve(token, initial, 1, 1)?;
    reader.poison_checkpoint();
    assert_eq!(cell.finalize(token).err(), Some(StorageError::Unavailable));
    assert_eq!(cell.rollback(token).err(), Some(StorageError::Unavailable));
    reader.publish_facts(7, 7, 7, 7);
    assert_eq!(
        reader.begin_checkpoint().err(),
        Some(StorageError::Unavailable)
    );
    Ok(())
}
