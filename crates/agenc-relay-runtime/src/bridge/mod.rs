//! Messages crossing from the storage thread and crypto workers into
//! StateCore (spec 21.5, lines 4178-4194 and 4203-4210).

pub mod crypto;
pub mod storage;

use agenc_relay_crypto::CryptoWorkerError;
use agenc_relay_storage::{CheckpointOutcome, CommitOutcome, ReadResult, StorageError};
use agenc_relay_types::TransactionId;

/// Completions queued from the storage bridge to StateCore (spec line 4084).
pub const STORAGE_COMPLETION_CHANNEL_CAPACITY: usize = 2;
/// Read completions queued from the storage bridge to StateCore.
pub const STORAGE_READ_COMPLETION_CHANNEL_CAPACITY: usize = 2;
/// Checkpoint completions queued from the storage bridge to StateCore.
pub const STORAGE_CHECKPOINT_COMPLETION_CHANNEL_CAPACITY: usize = 1;

/// Process-local identity of one submitted crypto job.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CryptoJobId(u64);

impl CryptoJobId {
    /// Wraps a job identity issued by the crypto bridge.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the primitive identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Process-local identity of one submitted storage read.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageReadId(u64);

impl StorageReadId {
    /// Wraps a read identity issued by the storage bridge.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the primitive identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Process-local identity of one submitted integrity checkpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageCheckpointId(u64);

impl StorageCheckpointId {
    /// Wraps a checkpoint identity issued by the storage bridge.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the primitive identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One storage outcome forwarded to the sole StateCore receiver.
///
/// StateCore compares `transaction_id` with its in-flight batch before it
/// consumes the outcome; a mismatch is `Indeterminate` and closes the state
/// owner (spec line 4209).
pub struct StorageCompletionMessage {
    /// The transaction the storage owner reports on.
    pub transaction_id: TransactionId,
    /// The closed storage outcome.
    pub outcome: CommitOutcome,
}

/// One bounded read result forwarded to StateCore.
pub struct StorageReadCompletionMessage {
    /// The process-local read identity.
    pub read_id: StorageReadId,
    /// The complete read or its determinate storage failure.
    pub result: Result<ReadResult, StorageError>,
}

/// One integrity-checkpoint result forwarded to StateCore.
pub struct StorageCheckpointCompletionMessage {
    /// The process-local checkpoint identity.
    pub checkpoint_id: StorageCheckpointId,
    /// The closed storage outcome.
    pub outcome: CheckpointOutcome,
}

/// One crypto job outcome forwarded to StateCore.
pub struct CryptoCompletionMessage<O> {
    /// The job the bridge submitted.
    pub job_id: CryptoJobId,
    /// The worker output or the closed worker failure.
    pub output: Result<O, CryptoWorkerError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_ids_round_trip_and_the_completion_capacity_is_two() {
        assert_eq!(CryptoJobId::new(42).get(), 42);
        assert!(CryptoJobId::new(1) < CryptoJobId::new(2));
        assert_eq!(STORAGE_COMPLETION_CHANNEL_CAPACITY, 2);
        assert_eq!(STORAGE_READ_COMPLETION_CHANNEL_CAPACITY, 2);
        assert_eq!(STORAGE_CHECKPOINT_COMPLETION_CHANNEL_CAPACITY, 1);
        assert_eq!(StorageReadId::new(8).get(), 8);
        assert_eq!(StorageCheckpointId::new(10).get(), 10);
        let message = CryptoCompletionMessage::<u8> {
            job_id: CryptoJobId::new(9),
            output: Err(CryptoWorkerError::QueueFull),
        };
        assert_eq!(message.job_id.get(), 9);
        assert_eq!(message.output, Err(CryptoWorkerError::QueueFull));
    }
}

#[cfg(test)]
#[path = "tests/ledger_reach.rs"]
mod ledger_reach;
