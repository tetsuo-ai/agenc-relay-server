//! Logical disk admission shared by sealed companion rows and authenticated
//! transient spool extents (architecture Appendix C.7).

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
    sealed: u64,
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

    pub(crate) fn restore(&self, sealed: u64) -> Result<(), StorageError> {
        if sealed > self.limit {
            return Err(StorageError::LimitExceeded);
        }
        self.lock().sealed = sealed;
        Ok(())
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

    pub(crate) fn stage(
        &self,
        mutations: &[RecordMutation],
    ) -> Result<PendingDiskWrite, StorageError> {
        let mut removed = 0u64;
        let mut added = 0u64;
        for m in mutations
            .iter()
            .filter(|m| matches!(m.table(), TableId::E2eeObject | TableId::E2eeState))
        {
            let key = m.key().as_bytes().len();
            if let Some(before) = m.before() {
                let bytes = usize::try_from(before.sealed_record_bytes())
                    .map_err(|_| StorageError::Overflow)?;
                removed = removed
                    .checked_add(row_charge(m.table(), key, bytes)?)
                    .ok_or(StorageError::Overflow)?;
            }
            if let Some(bytes) = m.resulting_sealed_bytes()? {
                added = added
                    .checked_add(row_charge(m.table(), key, bytes)?)
                    .ok_or(StorageError::Overflow)?;
            }
        }
        let mut usage = self.lock();
        let sealed_after = usage
            .sealed
            .checked_sub(removed)
            .ok_or(StorageError::StaleState)?
            .checked_add(added)
            .ok_or(StorageError::Overflow)?;
        let growth = added.saturating_sub(removed);
        self.reserve_locked(&mut usage, growth)?;
        Ok(PendingDiskWrite {
            disk: self.clone(),
            growth,
            sealed_after,
        })
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
    sealed_after: u64,
}

impl PendingDiskWrite {
    // The storage owner serializes durable mutations. Other threads can only
    // acquire or return extent reservations while the transaction runs.
    pub(crate) fn finish(self, outcome: &CommitOutcome) {
        let mut usage = self.disk.lock();
        match outcome {
            CommitOutcome::Committed(_) => usage.sealed = self.sealed_after,
            CommitOutcome::Rejected(_) => {}
            CommitOutcome::Indeterminate => usage.uncertain = true,
        }
        usage.reserved -= self.growth;
    }
}
