//! Descriptor-bound `R(F) + G` admission for every scratch-plan and target-construction
//! transaction of the offline restore and rekey commands.
//!
//! Architecture Section 19.3 lets a live write start only when the filesystem that holds the
//! affected file has at least `R(F) + G` bytes available, and requires restore, rekey,
//! scratch-plan and target-construction databases to apply that same gate independently
//! before every scratch or target redb transaction rather than trusting the space preflight
//! observed. Each [`ConstructionAdmission`] samples the filesystem of one open descriptor
//! immediately before the transaction it admits, and every admitted scratch transaction then
//! runs under the fixed [`ConstructionAdmission::allowance`] through the fork's bounded write
//! transaction, so `G` bounds the transaction's physical growth from above as well.

use std::fs::File;
use std::sync::Arc;

use redb::AllocationAllowance;
use rustix::fs::{StatVfs, fstatvfs};

use crate::{
    FilesystemCapacity, FilesystemCause, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH,
    StorageEngineLimits, StorageError,
};

/// One admitted construction transaction, named so an observer can tell them apart and a
/// resumed construction can prove it restarts at exactly the transaction that stopped it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstructionTransaction {
    /// Creation of the scratch plan database: redb's metadata initialization.
    ScratchCreate,
    /// The first bounded scratch transaction, which creates and resets every plan table.
    ScratchReset,
    /// One bounded slice of source observation and auxiliary indexing, numbered from one.
    ScratchObserve(u64),
    /// One bounded slice of restore reverse replay, numbered from one.
    ScratchVerify(u64),
    /// One bounded slice of the unsorted-to-ordered plan copy, numbered from one.
    ScratchOrder(u64),
    /// One bounded reclamation of pages the scratch transactions freed, numbered from one.
    ScratchReclaim(u64),
    /// The bounded allocator-state persistence before the scratch database closes.
    ScratchClose,
    /// The sequence-zero initialization of a fresh target database.
    TargetInitialize,
    /// One target batch; the value is the number of target records committed before it.
    TargetBatch(u64),
    /// The finalization commit that replaces the marker with the completion record.
    TargetFinalize,
    /// The checkpoint installed after finalization.
    TargetCheckpoint,
}

/// Test-only observation of every admission sample, with the power to stand in for an
/// external writer that consumes the sampled filesystem between the sample and the gate.
///
/// The daemon never installs an observer: a production policy samples the live filesystem
/// and nothing else. Every observer call receives the live sample and returns the capacity
/// the gate must use, so a test can simulate external consumption at exactly one named
/// transaction or record the whole admitted sequence without changing it.
pub trait ConstructionCapacityObserver: Send + Sync {
    /// Returns the capacity the gate must use in place of the live sample.
    fn observe(
        &self,
        transaction: ConstructionTransaction,
        sampled: FilesystemCapacity,
    ) -> Result<FilesystemCapacity, StorageError>;
}

/// The reserve policy one construction admits every transaction under.
#[derive(Clone)]
pub struct ConstructionAdmissionPolicy {
    fixed_reserve_bytes: u64,
    reserve_percent: u8,
    observer: Option<Arc<dyn ConstructionCapacityObserver>>,
}

impl ConstructionAdmissionPolicy {
    /// Takes the reserve from validated runtime limits and samples the live filesystem only.
    pub fn new(limits: StorageEngineLimits) -> Result<Self, StorageError> {
        Self::build(limits, None)
    }

    /// Takes the reserve from validated runtime limits and routes every sample through
    /// `observer`; test suites only.
    pub fn observed(
        limits: StorageEngineLimits,
        observer: Arc<dyn ConstructionCapacityObserver>,
    ) -> Result<Self, StorageError> {
        Self::build(limits, Some(observer))
    }

    fn build(
        limits: StorageEngineLimits,
        observer: Option<Arc<dyn ConstructionCapacityObserver>>,
    ) -> Result<Self, StorageError> {
        let limits = limits.validate()?;
        Ok(Self {
            fixed_reserve_bytes: limits.fixed_reserve_bytes,
            reserve_percent: limits.reserve_percent,
            observer,
        })
    }

    /// Binds the policy to the open descriptor whose filesystem every admission samples.
    #[must_use]
    pub fn bind(&self, descriptor: File) -> ConstructionAdmission {
        ConstructionAdmission {
            descriptor,
            policy: self.clone(),
        }
    }
}

/// One descriptor-bound admission authority: the policy plus the open directory or file
/// whose filesystem it samples immediately before every transaction it admits.
pub struct ConstructionAdmission {
    descriptor: File,
    policy: ConstructionAdmissionPolicy,
}

impl ConstructionAdmission {
    /// Binds `policy` to `descriptor`, the open directory or file that holds the scratch
    /// plan or the target database.
    #[must_use]
    pub fn new(descriptor: File, policy: ConstructionAdmissionPolicy) -> Self {
        policy.bind(descriptor)
    }

    #[cfg(test)]
    pub(crate) fn descriptor_metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.descriptor.metadata()
    }

    /// The fixed physical allowance every admitted scratch transaction runs under: `G`.
    #[must_use]
    pub const fn allowance() -> AllocationAllowance {
        AllocationAllowance::new(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
    }

    /// Names a target transaction to an installed test observer and enforces the gate on
    /// what it returns; without an observer this samples nothing, because the engine's own
    /// gate and bounded allowance are the one admission of every target transaction.
    pub(crate) fn recheck_observed(
        &self,
        transaction: ConstructionTransaction,
    ) -> Result<(), StorageError> {
        match self.policy.observer {
            Some(_) => self.admit(transaction).map(|_| ()),
            None => Ok(()),
        }
    }

    /// Enforces `R(F) + G` on a fresh sample of the bound filesystem for `transaction`.
    ///
    /// A refusal is determinate and writes nothing: the transaction it would have admitted
    /// has not begun. The reserve is never lowered to admit a transaction.
    pub fn admit(
        &self,
        transaction: ConstructionTransaction,
    ) -> Result<FilesystemCapacity, StorageError> {
        let statistics = fstatvfs(&self.descriptor).map_err(crate::filesystem_rejected)?;
        let sampled = capacity_from_statistics(
            &statistics,
            self.policy.fixed_reserve_bytes,
            self.policy.reserve_percent,
        )?;
        let capacity = match &self.policy.observer {
            Some(observer) => observer.observe(transaction, sampled)?,
            None => sampled,
        };
        let required = capacity
            .reserve_bytes
            .checked_add(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
            .ok_or(StorageError::Overflow)?;
        if capacity.available_bytes < required {
            return Err(StorageError::FilesystemRejected(
                FilesystemCause::InsufficientCapacity,
            ));
        }
        Ok(capacity)
    }
}

/// Computes UID-available bytes and the effective reserve
/// `max(fixed, ceil(total * percent / 100))` from one `statvfs` sample.
///
/// This is the Section 19.3 arithmetic the state directory applies to the live database
/// (`platform::capacity_from_statistics`); it is repeated here so the offline commands
/// sample the scratch and staging filesystems through their own descriptors without
/// reaching into the live write path.
fn capacity_from_statistics(
    statistics: &StatVfs,
    fixed_reserve_bytes: u64,
    reserve_percent: u8,
) -> Result<FilesystemCapacity, StorageError> {
    let block_size = statistics.f_frsize;
    let available_bytes = statistics
        .f_bavail
        .checked_mul(block_size)
        .ok_or(StorageError::Overflow)?;
    let total_bytes = statistics
        .f_blocks
        .checked_mul(block_size)
        .ok_or(StorageError::Overflow)?;
    let percentage_reserve = total_bytes
        .checked_mul(u64::from(reserve_percent))
        .and_then(|bytes| bytes.checked_add(99))
        .ok_or(StorageError::Overflow)?
        / 100;
    Ok(FilesystemCapacity {
        available_bytes,
        reserve_bytes: fixed_reserve_bytes.max(percentage_reserve),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct BoundaryObserver {
        transaction: ConstructionTransaction,
        delta: i64,
        seen: Mutex<Vec<ConstructionTransaction>>,
    }

    impl ConstructionCapacityObserver for BoundaryObserver {
        fn observe(
            &self,
            transaction: ConstructionTransaction,
            sampled: FilesystemCapacity,
        ) -> Result<FilesystemCapacity, StorageError> {
            self.seen
                .lock()
                .map_err(|_| StorageError::Unavailable)?
                .push(transaction);
            if transaction != self.transaction {
                return Ok(sampled);
            }
            let exact = sampled
                .reserve_bytes
                .checked_add(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
                .ok_or(StorageError::Overflow)?;
            let available_bytes = exact
                .checked_add_signed(self.delta)
                .ok_or(StorageError::Overflow)?;
            Ok(FilesystemCapacity {
                available_bytes,
                reserve_bytes: sampled.reserve_bytes,
            })
        }
    }

    fn limits() -> StorageEngineLimits {
        StorageEngineLimits {
            redb_cache_bytes: 8 * 1_024 * 1_024,
            fixed_reserve_bytes: 64 * 1_024 * 1_024,
            reserve_percent: 1,
            database_max_bytes: 1_073_741_824,
            backup_max_bytes: 1_073_741_824,
            integrity_checkpoint_manifests: 10_000,
        }
    }

    fn descriptor() -> Result<File, StorageError> {
        File::open(std::env::temp_dir()).map_err(crate::filesystem_rejected)
    }

    #[test]
    fn the_live_sample_admits_and_reports_the_configured_reserve() -> Result<(), StorageError> {
        let admission =
            ConstructionAdmission::new(descriptor()?, ConstructionAdmissionPolicy::new(limits())?);
        let capacity = admission.admit(ConstructionTransaction::ScratchCreate)?;
        assert!(capacity.available_bytes >= capacity.reserve_bytes);
        assert!(capacity.reserve_bytes >= 64 * 1_024 * 1_024);
        assert_eq!(
            ConstructionAdmission::allowance().bytes(),
            MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH
        );
        assert_eq!(
            ConstructionAdmissionPolicy::new(StorageEngineLimits {
                reserve_percent: 0,
                ..limits()
            })
            .err(),
            Some(StorageError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn the_gate_refuses_one_byte_below_the_boundary_and_admits_at_and_above_it()
    -> Result<(), StorageError> {
        for (delta, admitted) in [(-1_i64, false), (0, true), (1, true)] {
            let observer = Arc::new(BoundaryObserver {
                transaction: ConstructionTransaction::TargetBatch(7),
                delta,
                seen: Mutex::new(Vec::new()),
            });
            let admission = ConstructionAdmissionPolicy::observed(limits(), observer.clone())?
                .bind(descriptor()?);
            admission.admit(ConstructionTransaction::ScratchReset)?;
            let outcome = admission.admit(ConstructionTransaction::TargetBatch(7));
            assert_eq!(
                outcome.is_ok(),
                admitted,
                "delta {delta} produced {outcome:?}"
            );
            if !admitted {
                assert_eq!(
                    outcome,
                    Err(StorageError::FilesystemRejected(
                        FilesystemCause::InsufficientCapacity
                    ))
                );
            }
            assert_eq!(
                *observer
                    .seen
                    .lock()
                    .map_err(|_| StorageError::Unavailable)?,
                [
                    ConstructionTransaction::ScratchReset,
                    ConstructionTransaction::TargetBatch(7)
                ]
            );
        }
        Ok(())
    }

    #[test]
    fn the_reserve_arithmetic_takes_the_greater_reserve_and_rounds_the_percentage_up()
    -> Result<(), StorageError> {
        let statistics = fstatvfs(&descriptor()?).map_err(crate::filesystem_rejected)?;
        let block_size = statistics.f_frsize;
        let total = statistics
            .f_blocks
            .checked_mul(block_size)
            .ok_or(StorageError::Overflow)?;
        let one_percent = total.checked_add(99).ok_or(StorageError::Overflow)? / 100;
        let fixed_wins = capacity_from_statistics(&statistics, u64::MAX / 2, 1)?;
        assert_eq!(fixed_wins.reserve_bytes, u64::MAX / 2);
        let percent_wins = capacity_from_statistics(&statistics, 0, 1)?;
        assert_eq!(percent_wins.reserve_bytes, one_percent);
        assert_eq!(
            percent_wins.available_bytes,
            statistics
                .f_bavail
                .checked_mul(block_size)
                .ok_or(StorageError::Overflow)?
        );
        Ok(())
    }
}
