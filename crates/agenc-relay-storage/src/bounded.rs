//! One physical growth allowance for one durable storage operation.
//!
//! Section 19.3 fixes `MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH = G` as the combined physical
//! growth allowance of one legal redb transaction, its guard temporary and replacement file, and
//! the directory metadata they need. The `R(F) + G` free-space gate makes room for `G` before an
//! operation starts; the [`OperationAllowance`] here is what makes `G` exact. Every redb
//! allocation of the operation is charged to it through the fork's bounded write transaction,
//! which debits each page extent and file extension before allocating it, and the guard
//! temporaries and their directory and inode headroom are charged at filesystem block
//! granularity before the first transaction begins. Nothing is refunded, so the allowance bounds
//! the operation's physical growth from above.
//!
//! A charge the allowance cannot admit is a determinate refusal with no side effects: the
//! refused transaction is aborted before its irreversible commit began, every earlier root stays
//! valid, an already burned nonce reservation stays burned, and the next writer is unaffected. A
//! refusal is never an I/O failure, never stale state and never the indeterminate outcome, and a
//! real uncertain I/O failure keeps Section 21.5's indeterminate reconciliation exactly as before.
//!
//! The sibling durable operations of this crate (recovery and reference scratch, backup, restore
//! and rekey construction) derive their own allowances from the same type and map their refusals
//! through the same helpers, so that one operation is always charged against one ledger.

use redb::{AllocationPhase, AllowanceRefusal, CommitError};

use crate::redb_store::RedbCommitFailure;
use crate::{
    AllowancePhase, FilesystemCause, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, ROLLBACK_GUARD_BYTES,
    StorageError,
};

/// Bytes charged for the inode one guard temporary may allocate: one inode-table chunk on a
/// filesystem that allocates inode tables dynamically (sixty-four 512-byte inodes on XFS),
/// which bounds a preallocated inode table from above.
pub(crate) const GUARD_INODE_HEADROOM_BYTES: u64 = 32_768;

/// Filesystem blocks charged for the directory entry one guard temporary adds: one block, the
/// most a single new entry can extend the state directory by before the rename replaces the
/// guard's own entry.
pub(crate) const GUARD_DIRECTORY_HEADROOM_BLOCKS: u64 = 1;

/// Region size every live database is created with, in bytes.
///
/// redb lays a file out in regions and, once the first region is full, extends it by up to two
/// regions at a time; below one region the file doubles. The bounded account charges every
/// extension at its full length, so a region may be at most half of `G` or the first extension
/// past the allowance would be refused and the database could never grow. Sixty-four MiB keeps
/// every growth step at or below 128 MiB, half the allowance, with room for the transaction
/// that needed it. The size is fixed at creation and recorded in the file header; a database
/// laid out with larger regions is refused at open with [`StorageError::UnboundedRegion`].
pub const LIVE_DATABASE_REGION_BYTES: u64 = 64 * 1024 * 1024;

/// The redb builder every live database is created and opened with: the configured cache
/// and the bounded region size, which only a creation applies.
///
/// The sibling construction paths that create a future live database must build it through
/// this helper so the file they install can be opened bounded.
#[must_use]
pub(crate) fn live_database_builder(cache_bytes: usize) -> redb::Builder {
    let mut builder = redb::Builder::new();
    builder.set_cache_size(cache_bytes);
    builder.set_region_size(LIVE_DATABASE_REGION_BYTES);
    builder
}

/// Greatest number of freed-page records one deferred reclamation removes.
///
/// Each record names at most one page of page numbers, so this bounds the reclamation to the
/// handful of freed-table pages it rewrites, while a backlog that one maximum deletion leaves
/// still drains within a few later operations.
pub(crate) const MAX_DEFERRED_RECLAIM_RECORDS: usize = 64;

/// The unspent physical growth allowance of one durable operation, derived from `G`.
///
/// The allowance is created once per admitted operation, hands its remainder to every redb
/// transaction of that operation in turn, and is debited by exactly the bytes each transaction
/// reports charging, so nonce reservation, the main transaction and the deferred cleanup share
/// one bound rather than three.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OperationAllowance {
    remaining: u64,
    charged: u64,
}

impl OperationAllowance {
    /// Derives the allowance of one durable operation on a filesystem with `block_size` bytes
    /// per block, charging `guard_replacements` guard temporaries first.
    ///
    /// A guard replacement always costs the same fixed headroom, so it is charged before the
    /// first transaction rather than measured afterwards; the redb transactions receive what
    /// remains of `G`.
    pub(crate) fn new(block_size: u64, guard_replacements: u64) -> Result<Self, StorageError> {
        let guards = guard_replacement_charge(block_size)?
            .checked_mul(guard_replacements)
            .ok_or(StorageError::Overflow)?;
        let remaining = MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH
            .checked_sub(guards)
            .ok_or(StorageError::Overflow)?;
        Ok(Self {
            remaining,
            charged: guards,
        })
    }

    /// Lowers the remaining allowance to `cap` bytes of redb allocation.
    ///
    /// The cap exists for the qualification campaign and the test suites, which reach the
    /// allowance boundary without a 256 MiB transaction. It can only lower the Section 19.3
    /// allowance, never raise it, and it leaves the `R(F) + G` gate untouched.
    #[must_use]
    pub(crate) fn capped(self, cap: Option<u64>) -> Self {
        match cap {
            Some(cap) if cap < self.remaining => Self {
                remaining: cap,
                charged: self.charged,
            },
            _ => self,
        }
    }

    /// The bytes charged so far, including the guard headroom.
    pub(crate) const fn charged(self) -> u64 {
        self.charged
    }

    /// The remainder as the allowance of the next redb transaction of this operation.
    pub(crate) const fn allowance(self) -> redb::AllocationAllowance {
        redb::AllocationAllowance::new(self.remaining)
    }

    /// Debits the bytes one redb transaction of this operation reported charging.
    ///
    /// The transaction was bounded by [`Self::allowance`], so its charge never exceeds the
    /// remainder; a debit that would is an accounting contradiction and is refused as an
    /// overflow rather than absorbed.
    pub(crate) fn charge(&mut self, bytes: u64) -> Result<(), StorageError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(StorageError::Overflow)?;
        self.charged = self
            .charged
            .checked_add(bytes)
            .ok_or(StorageError::Overflow)?;
        Ok(())
    }
}

/// Bytes one guard replacement is charged: the guard temporary at block granularity, the
/// directory block its entry may add, and the inode headroom at block granularity.
///
/// The rename that publishes the temporary replaces the previous guard's entry and frees that
/// guard's block afterwards, but nothing is refunded: the charge is the growth the replacement
/// can cause while both files exist.
pub fn guard_replacement_charge(block_size: u64) -> Result<u64, StorageError> {
    let guard_bytes = u64::try_from(ROLLBACK_GUARD_BYTES).map_err(|_| StorageError::Overflow)?;
    let guard = round_up_to_blocks(guard_bytes, block_size)?;
    let directory = block_size
        .checked_mul(GUARD_DIRECTORY_HEADROOM_BLOCKS)
        .ok_or(StorageError::Overflow)?;
    let inode = round_up_to_blocks(GUARD_INODE_HEADROOM_BYTES, block_size)?;
    guard
        .checked_add(directory)
        .and_then(|bytes| bytes.checked_add(inode))
        .ok_or(StorageError::Overflow)
}

/// Rounds `bytes` up to a whole number of filesystem blocks, the granularity at which a file
/// grows. A zero block size is not a qualified filesystem.
pub(crate) fn round_up_to_blocks(bytes: u64, block_size: u64) -> Result<u64, StorageError> {
    if block_size == 0 {
        return Err(StorageError::FilesystemRejected(
            FilesystemCause::Unqualified,
        ));
    }
    let blocks = bytes
        .checked_add(block_size.saturating_sub(1))
        .ok_or(StorageError::Overflow)?
        / block_size;
    blocks.checked_mul(block_size).ok_or(StorageError::Overflow)
}

/// The closed phase in which a redb refusal was raised.
///
/// A refusal after the account froze names an allocation that publication must never make; it
/// is reported as preparation, the last phase in which the transaction could allocate.
pub(crate) fn refusal_phase(refusal: AllowanceRefusal) -> AllowancePhase {
    match refusal.phase() {
        AllocationPhase::Mutation => AllowancePhase::Mutation,
        AllocationPhase::Preparation | AllocationPhase::Frozen => AllowancePhase::Preparation,
        AllocationPhase::Cleanup => AllowancePhase::Cleanup,
        AllocationPhase::Close => AllowancePhase::Close,
    }
}

/// Maps a redb storage error raised by a table write inside a bounded transaction.
///
/// A refusal is the determinate allowance refusal; every other failure before the commit is the
/// ordinary determinate database rejection. Neither has written anything.
pub(crate) fn map_write_error(error: redb::StorageError) -> StorageError {
    match error {
        redb::StorageError::Allowance(refusal) => {
            StorageError::AllowanceRefused(refusal_phase(refusal))
        }
        _ => StorageError::DatabaseRejected,
    }
}

/// Maps a redb table error raised when a bounded transaction opens a table for writing, which
/// may itself allocate and be refused.
pub(crate) fn map_table_error(error: redb::TableError) -> StorageError {
    match error {
        redb::TableError::Storage(error) => map_write_error(error),
        _ => StorageError::DatabaseRejected,
    }
}

/// Maps the failure of a bounded transaction's preparation.
///
/// A refusal aborted the transaction cleanly, so it is the determinate allowance refusal. A
/// poisoned transaction was rolled back, so it is the determinate database rejection. Any other
/// failure may have latched the database, and Section 21.5 keeps it indeterminate.
pub(crate) fn map_preparation_error(error: CommitError) -> RedbCommitFailure {
    match error {
        CommitError::Allowance(refusal) => {
            RedbCommitFailure::Rejected(StorageError::AllowanceRefused(refusal_phase(refusal)))
        }
        CommitError::TransactionPoisoned => {
            RedbCommitFailure::Rejected(StorageError::DatabaseRejected)
        }
        _ => RedbCommitFailure::Indeterminate,
    }
}

/// Maps the failure of a prepared transaction's publication, which writes only the header
/// slots: nothing about a failed publication is certain, whatever error redb reports.
pub(crate) fn map_publication_error(_error: CommitError) -> RedbCommitFailure {
    RedbCommitFailure::Indeterminate
}

/// The outcome of one bounded maintenance publication: deferred cleanup or the close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MaintenanceOutcome<T> {
    /// The publication completed within its allowance.
    Completed(T),
    /// The allowance refused the publication before it wrote anything; the database stays
    /// usable and the work waits for a later operation or the next open.
    Refused(AllowancePhase),
}

#[cfg(test)]
impl<T> MaintenanceOutcome<T> {
    /// The completed value, or nothing when the allowance refused the publication.
    pub(crate) fn completed(self) -> Option<T> {
        match self {
            Self::Completed(value) => Some(value),
            Self::Refused(_) => None,
        }
    }
}

/// Maps the result of a bounded maintenance publication. A refusal reclaimed or persisted
/// nothing and is reported as such; any other failure is uncertain.
pub(crate) fn map_maintenance<T>(
    result: Result<T, redb::Error>,
) -> Result<MaintenanceOutcome<T>, RedbCommitFailure> {
    match result {
        Ok(value) => Ok(MaintenanceOutcome::Completed(value)),
        Err(redb::Error::Allowance(refusal)) => {
            Ok(MaintenanceOutcome::Refused(refusal_phase(refusal)))
        }
        Err(_) => Err(RedbCommitFailure::Indeterminate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: u64 = MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH;

    #[test]
    fn guard_replacements_are_charged_at_block_granularity() -> Result<(), StorageError> {
        assert_eq!(guard_replacement_charge(4_096)?, 4_096 + 4_096 + 32_768);
        assert_eq!(guard_replacement_charge(512)?, 512 + 512 + 32_768);
        assert_eq!(guard_replacement_charge(65_536)?, 65_536 * 3);
        assert_eq!(round_up_to_blocks(0, 4_096)?, 0);
        assert_eq!(round_up_to_blocks(1, 4_096)?, 4_096);
        assert_eq!(round_up_to_blocks(4_096, 4_096)?, 4_096);
        assert_eq!(round_up_to_blocks(4_097, 4_096)?, 8_192);
        assert_eq!(
            round_up_to_blocks(1, 0),
            Err(StorageError::FilesystemRejected(
                FilesystemCause::Unqualified
            ))
        );
        assert_eq!(
            round_up_to_blocks(u64::MAX, 4_096),
            Err(StorageError::Overflow)
        );
        Ok(())
    }

    #[test]
    fn an_operation_allowance_is_g_minus_its_guards_and_is_exact_at_the_boundary()
    -> Result<(), StorageError> {
        let guards = 2 * guard_replacement_charge(4_096)?;
        let mut allowance = OperationAllowance::new(4_096, 2)?;
        assert_eq!(allowance.allowance().bytes(), G - guards);
        assert_eq!(allowance.charged(), guards);
        assert_eq!(allowance.allowance().bytes(), G - guards);

        allowance.charge(G - guards - 1)?;
        assert_eq!(allowance.allowance().bytes(), 1);
        allowance.charge(1)?;
        assert_eq!(allowance.allowance().bytes(), 0);
        assert_eq!(allowance.charged(), G);
        assert_eq!(allowance.charge(1), Err(StorageError::Overflow));
        assert_eq!(allowance.allowance().bytes(), 0);

        let no_guards = OperationAllowance::new(4_096, 0)?;
        assert_eq!(no_guards.allowance().bytes(), G);
        assert_eq!(no_guards.charged(), 0);
        assert_eq!(
            OperationAllowance::new(4_096, u64::MAX),
            Err(StorageError::Overflow)
        );
        Ok(())
    }

    #[test]
    fn a_cap_only_lowers_the_allowance() -> Result<(), StorageError> {
        let allowance = OperationAllowance::new(4_096, 2)?;
        assert_eq!(allowance.capped(None), allowance);
        assert_eq!(allowance.capped(Some(u64::MAX)), allowance);
        assert_eq!(
            allowance.capped(Some(allowance.allowance().bytes())),
            allowance
        );
        let capped = allowance.capped(Some(10));
        assert_eq!(capped.allowance().bytes(), 10);
        assert_eq!(capped.charged(), allowance.charged());
        Ok(())
    }

    #[test]
    fn every_refusal_maps_to_a_determinate_phase_and_every_uncertainty_stays_indeterminate() {
        let phases = [
            (AllocationPhase::Mutation, AllowancePhase::Mutation),
            (AllocationPhase::Preparation, AllowancePhase::Preparation),
            (AllocationPhase::Frozen, AllowancePhase::Preparation),
            (AllocationPhase::Cleanup, AllowancePhase::Cleanup),
            (AllocationPhase::Close, AllowancePhase::Close),
        ];
        for (phase, expected) in phases {
            let refusal = AllowanceRefusal::Latched { phase };
            assert_eq!(refusal_phase(refusal), expected);
            assert_eq!(
                map_write_error(redb::StorageError::Allowance(refusal)),
                StorageError::AllowanceRefused(expected)
            );
            assert!(matches!(
                map_preparation_error(CommitError::Allowance(refusal)),
                RedbCommitFailure::Rejected(StorageError::AllowanceRefused(found)) if found == expected
            ));
            assert!(matches!(
                map_maintenance::<()>(Err(redb::Error::Allowance(refusal))),
                Ok(MaintenanceOutcome::Refused(found)) if found == expected
            ));
        }
        assert_eq!(
            refusal_phase(AllowanceRefusal::Frozen),
            AllowancePhase::Preparation
        );
        assert_eq!(
            map_write_error(redb::StorageError::PreviousIo),
            StorageError::DatabaseRejected
        );
        assert_eq!(
            map_table_error(redb::TableError::TableDoesNotExist("meta".to_owned())),
            StorageError::DatabaseRejected
        );
        assert_eq!(
            map_table_error(redb::TableError::Storage(redb::StorageError::Allowance(
                AllowanceRefusal::Frozen
            ))),
            StorageError::AllowanceRefused(AllowancePhase::Preparation)
        );
        assert!(matches!(
            map_preparation_error(CommitError::TransactionPoisoned),
            RedbCommitFailure::Rejected(StorageError::DatabaseRejected)
        ));
        assert!(matches!(
            map_preparation_error(CommitError::Storage(redb::StorageError::PreviousIo)),
            RedbCommitFailure::Indeterminate
        ));
        assert!(matches!(
            map_publication_error(CommitError::Allowance(AllowanceRefusal::Frozen)),
            RedbCommitFailure::Indeterminate
        ));
        assert!(matches!(
            map_maintenance::<()>(Err(redb::Error::PreviousIo)),
            Err(RedbCommitFailure::Indeterminate)
        ));
        assert!(matches!(
            map_maintenance(Ok(7_u8)),
            Ok(MaintenanceOutcome::Completed(7))
        ));
    }
}
