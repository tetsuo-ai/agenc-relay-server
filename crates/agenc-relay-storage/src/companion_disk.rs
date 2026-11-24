//! Logical disk admission shared by sealed companion rows and authenticated
//! transient spool extents (architecture Appendix C.7).

pub(crate) mod accounting;
pub use accounting::CompanionDiskAccounting;

use agenc_relay_crypto::DatabaseBinding;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::{CommitOutcome, RecordMutation, StorageError, TableId};

const BLOCK: u64 = 4096;

fn rounded(bytes: u64) -> Result<u64, StorageError> {
    bytes
        .checked_add(BLOCK - 1)
        .map(|value| value / BLOCK * BLOCK)
        .ok_or(StorageError::Overflow)
}

pub(crate) fn row_charge(table: TableId, key: usize, envelope: usize) -> Result<u64, StorageError> {
    if !matches!(table, TableId::E2eeObject | TableId::E2eeState) {
        return Ok(0);
    }
    let key = u64::try_from(key).map_err(|_| StorageError::Overflow)?;
    let envelope = u64::try_from(envelope).map_err(|_| StorageError::Overflow)?;
    rounded(
        key.checked_add(envelope)
            .and_then(|v| v.checked_add(256))
            .ok_or(StorageError::Overflow)?,
    )
}

#[derive(Debug, Default)]
struct Usage {
    accounting: CompanionDiskAccounting,
    binding: Option<DatabaseBinding>,
    writer_attached: bool,
    reserved: u64,
    uncertain: bool,
}

/// A single daemon's configured companion disk allowance. A sealed-row
/// transaction and all open extents compete for the same available bytes.
#[derive(Clone, Debug)]
pub struct CompanionDisk {
    limit: u64,
    usage: Arc<Mutex<Usage>>,
}

impl CompanionDisk {
    /// Creates an allowance. The storage owner installs the authenticated
    /// startup scan before the daemon begins admitting input.
    pub fn new(limit: u64) -> Result<Self, StorageError> {
        if limit == 0 {
            return Err(StorageError::LimitExceeded);
        }
        Ok(Self {
            limit,
            usage: Arc::default(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Usage> {
        self.usage.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn attach(
        &self,
        accounting: CompanionDiskAccounting,
        binding: DatabaseBinding,
    ) -> Result<DiskWriter, StorageError> {
        let mut usage = self.lock();
        if usage.writer_attached || usage.binding.is_some_and(|previous| previous != binding) {
            return Err(StorageError::StaleState);
        }
        if accounting
            .sealed
            .checked_add(usage.reserved)
            .ok_or(StorageError::Overflow)?
            > self.limit
        {
            return Err(StorageError::LimitExceeded);
        }
        usage.accounting = accounting;
        usage.binding = Some(binding);
        usage.writer_attached = true;
        // Only a complete authenticated startup scan can settle an
        // indeterminate durable write and admit new allocations again.
        usage.uncertain = false;
        Ok(DiskWriter(self.clone()))
    }

    fn reserve_locked(&self, usage: &mut Usage, charge: u64) -> Result<(), StorageError> {
        if usage.uncertain {
            return Err(StorageError::Unavailable);
        }
        let reserved = usage
            .reserved
            .checked_add(charge)
            .ok_or(StorageError::Overflow)?;
        if usage
            .accounting
            .sealed
            .checked_add(reserved)
            .ok_or(StorageError::Overflow)?
            > self.limit
        {
            return Err(StorageError::LimitExceeded);
        }
        usage.reserved = reserved;
        Ok(())
    }

    /// Charges an extent, rounded to 4 KiB, before its file is allocated.
    pub fn reserve_extent(&self, length: u64) -> Result<ExtentReservation, StorageError> {
        let charge = rounded(length)?;
        self.reserve_locked(&mut self.lock(), charge)?;
        Ok(ExtentReservation {
            disk: self.clone(),
            charge,
        })
    }
}

/// A startup scan is valid for one serialized storage writer and database.
pub(crate) struct DiskWriter(CompanionDisk);

impl DiskWriter {
    pub(crate) fn stage(
        &self,
        mutations: &[RecordMutation],
        revision: u64,
    ) -> Result<PendingDiskWrite, StorageError> {
        let mut usage = self.0.lock();
        let sealed_after = usage.accounting.checked_update(mutations, revision)?;
        let growth = sealed_after.sealed.saturating_sub(usage.accounting.sealed);
        self.0.reserve_locked(&mut usage, growth)?;
        Ok(PendingDiskWrite {
            disk: self.0.clone(),
            growth,
            sealed_after,
        })
    }
}

impl Drop for DiskWriter {
    fn drop(&mut self) {
        self.0.lock().writer_attached = false;
    }
}

/// The disk charge for one anonymous extent. The file owner drops this
/// reservation after closing the file.
#[derive(Debug)]
pub struct ExtentReservation {
    disk: CompanionDisk,
    charge: u64,
}

impl Drop for ExtentReservation {
    fn drop(&mut self) {
        let mut usage = self.disk.lock();
        usage.reserved -= self.charge;
    }
}

pub(crate) struct PendingDiskWrite {
    disk: CompanionDisk,
    growth: u64,
    sealed_after: CompanionDiskAccounting,
}

impl PendingDiskWrite {
    // The storage owner serializes durable mutations. Other threads can only
    // acquire or return extent reservations while the transaction runs.
    pub(crate) fn finish(self, outcome: &CommitOutcome) {
        let mut usage = self.disk.lock();
        match outcome {
            CommitOutcome::Committed(_) => usage.accounting = self.sealed_after,
            CommitOutcome::Rejected(_) => {}
            CommitOutcome::Indeterminate => usage.uncertain = true,
        }
        usage.reserved -= self.growth;
    }
}
