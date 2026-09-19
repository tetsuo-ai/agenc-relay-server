//! The completion ledger admits one identity per read and checkpoint, keeps a
//! checkpoint exclusive of every other in-flight operation, and stays failed
//! once any identity is duplicated or answered twice.
#![forbid(unsafe_code)]

use super::storage::{BridgeFailure, CompletionLedger};
use super::{StorageCheckpointId, StorageReadId};
use agenc_ircd_storage::StorageError;
use agenc_ircd_types::TransactionId;

#[test]
fn a_read_identity_is_admitted_once_and_never_while_a_checkpoint_is_in_flight() {
    let ledger = CompletionLedger::new();
    let read = StorageReadId::new(7);
    assert!(ledger.begin_read(read).is_ok());
    assert_eq!(
        ledger.begin_read(read).err(),
        Some(StorageError::Unavailable),
        "a duplicate read fails the ledger"
    );
    assert_eq!(
        ledger.finish_read(read).err(),
        Some(BridgeFailure::DuplicateTransaction),
        "the failed ledger answers every later call with its failure"
    );
    assert_eq!(
        ledger.begin_checkpoint(StorageCheckpointId::new(1)).err(),
        Some(StorageError::Unavailable)
    );

    let ledger = CompletionLedger::new();
    assert!(ledger.begin_checkpoint(StorageCheckpointId::new(1)).is_ok());
    assert_eq!(
        ledger.begin_read(read).err(),
        Some(StorageError::QueueFull),
        "reads wait for the checkpoint"
    );
    assert_eq!(
        ledger.begin_checkpoint(StorageCheckpointId::new(2)).err(),
        Some(StorageError::QueueFull),
        "one checkpoint at a time"
    );
    ledger.abandon_checkpoint(StorageCheckpointId::new(2));
    assert_eq!(
        ledger.begin_read(read).err(),
        Some(StorageError::QueueFull),
        "abandoning another identity keeps the checkpoint"
    );
    ledger.abandon_checkpoint(StorageCheckpointId::new(1));
    assert!(ledger.begin_read(read).is_ok());
    ledger.abandon_read(read);
    assert!(
        ledger.begin_read(read).is_ok(),
        "an abandoned read frees its identity"
    );
}

#[test]
fn a_checkpoint_waits_for_in_flight_work_and_must_finish_under_its_own_identity() {
    let ledger = CompletionLedger::new();
    let transaction = TransactionId::from_bytes([3; 16]);
    assert!(ledger.begin(transaction).is_ok());
    assert_eq!(
        ledger.begin_checkpoint(StorageCheckpointId::new(1)).err(),
        Some(StorageError::QueueFull),
        "a batch in flight blocks the checkpoint"
    );
    ledger.abandon(transaction);
    let read = StorageReadId::new(9);
    assert!(ledger.begin_read(read).is_ok());
    assert_eq!(
        ledger.begin_checkpoint(StorageCheckpointId::new(1)).err(),
        Some(StorageError::QueueFull),
        "a read in flight blocks the checkpoint"
    );
    assert!(ledger.finish_read(read).is_ok());
    assert_eq!(
        ledger.finish_read(read).err(),
        Some(BridgeFailure::DuplicateTransaction),
        "a read answered twice fails the ledger"
    );

    let ledger = CompletionLedger::new();
    assert!(ledger.begin_checkpoint(StorageCheckpointId::new(1)).is_ok());
    assert_eq!(
        ledger.finish_checkpoint(StorageCheckpointId::new(2)).err(),
        Some(BridgeFailure::DuplicateTransaction),
        "a checkpoint answered under another identity fails the ledger"
    );
    assert_eq!(
        ledger.finish_checkpoint(StorageCheckpointId::new(1)).err(),
        Some(BridgeFailure::DuplicateTransaction)
    );

    let ledger = CompletionLedger::new();
    assert!(ledger.begin_checkpoint(StorageCheckpointId::new(1)).is_ok());
    assert!(
        ledger
            .finish_checkpoint(StorageCheckpointId::new(1))
            .is_ok()
    );
    assert!(
        ledger.begin_checkpoint(StorageCheckpointId::new(2)).is_ok(),
        "a finished checkpoint frees the slot"
    );
}
