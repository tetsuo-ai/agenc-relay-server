//! Exhaustive deterministic fault schedules for storage qualification.

use std::sync::{Arc, Mutex};

use crate::{StorageError, StorageError::DatabaseRejected};

/// Closed logical storage boundary registry exercised by the fault campaign.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum StorageFaultSite {
    /// Source or database record read.
    RecordRead = 1,
    /// Record insertion, replacement, or deletion.
    RecordWrite = 2,
    /// Bounded allocation or reserve.
    Allocation = 3,
    /// redb write-transaction creation.
    TransactionBegin = 4,
    /// First durable flush inside one redb two-phase commit: the secondary header slot.
    TransactionPhaseOne = 5,
    /// Second durable flush inside one redb two-phase commit: the primary slot swap.
    TransactionPhaseTwo = 6,
    /// Every database file sync, inside a commit or not (creation, open, repair, shutdown).
    DatabaseSync = 7,
    /// Guard temporary-file creation.
    GuardTemporaryCreate = 8,
    /// Guard temporary-file write.
    GuardWrite = 9,
    /// Guard temporary-file sync.
    GuardFileSync = 10,
    /// Guard atomic rename.
    GuardRename = 11,
    /// Guard parent-directory sync.
    GuardDirectorySync = 12,
    /// Reserved 192-bit nonce draw.
    NonceDraw = 13,
    /// Manifest construction or write.
    Manifest = 14,
    /// Bounded checkpoint snapshot slice.
    CheckpointScan = 15,
    /// Checkpoint control transaction.
    CheckpointInstall = 16,
    /// Checkpoint manifest/ancestor pruning.
    CheckpointPrune = 17,
    /// Migration profile and registry validation.
    MigrationProfile = 18,
    /// Construction-plan deterministic rebuild.
    ConstructionPlanRebuild = 19,
    /// Construction target batch.
    ConstructionBatch = 20,
    /// Construction cursor successor.
    ConstructionCursor = 21,
    /// Marker-to-completion replacement.
    ConstructionCompletion = 22,
    /// Backup input record.
    BackupRecord = 23,
    /// Backup file sync.
    BackupFileSync = 24,
    /// Backup no-replace rename.
    BackupRename = 25,
    /// Backup parent-directory sync.
    BackupDirectorySync = 26,
    /// Login-index rotation start.
    LoginIndexRotationStart = 27,
    /// Successful-login lazy index migration.
    LoginIndexLazyMigration = 28,
    /// Login-index rotation finish.
    LoginIndexRotationFinish = 29,
    /// Exclusive writer-lock acquisition.
    WriterLock = 30,
    /// Exact free-space sample/admission.
    CapacityAdmission = 31,
    /// Staging-directory installation rename.
    ConstructionDirectoryRename = 32,
}

impl StorageFaultSite {
    /// Returns every version-one site in numeric order.
    #[must_use]
    pub const fn all() -> [Self; 32] {
        [
            Self::RecordRead,
            Self::RecordWrite,
            Self::Allocation,
            Self::TransactionBegin,
            Self::TransactionPhaseOne,
            Self::TransactionPhaseTwo,
            Self::DatabaseSync,
            Self::GuardTemporaryCreate,
            Self::GuardWrite,
            Self::GuardFileSync,
            Self::GuardRename,
            Self::GuardDirectorySync,
            Self::NonceDraw,
            Self::Manifest,
            Self::CheckpointScan,
            Self::CheckpointInstall,
            Self::CheckpointPrune,
            Self::MigrationProfile,
            Self::ConstructionPlanRebuild,
            Self::ConstructionBatch,
            Self::ConstructionCursor,
            Self::ConstructionCompletion,
            Self::BackupRecord,
            Self::BackupFileSync,
            Self::BackupRename,
            Self::BackupDirectorySync,
            Self::LoginIndexRotationStart,
            Self::LoginIndexLazyMigration,
            Self::LoginIndexRotationFinish,
            Self::WriterLock,
            Self::CapacityAdmission,
            Self::ConstructionDirectoryRename,
        ]
    }
}

/// Failure immediately before or immediately after one logical boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StorageFaultBoundary {
    /// Fail before the boundary can change state.
    Before,
    /// Fail after the boundary may have changed state.
    After,
}

/// One deterministic campaign case.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageFaultCase {
    /// Logical injection site.
    pub site: StorageFaultSite,
    /// Before/after side of the site.
    pub boundary: StorageFaultBoundary,
}

impl StorageFaultCase {
    /// Returns the complete before/after matrix in stable order.
    pub fn all() -> Result<Vec<Self>, StorageError> {
        let sites = StorageFaultSite::all();
        let capacity = sites.len().checked_mul(2).ok_or(StorageError::Overflow)?;
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(capacity)
            .map_err(|_| StorageError::AllocationFailed)?;
        for site in sites {
            cases.push(Self {
                site,
                boundary: StorageFaultBoundary::Before,
            });
            cases.push(Self {
                site,
                boundary: StorageFaultBoundary::After,
            });
        }
        Ok(cases)
    }
}

/// One-shot occurrence-aware deterministic fault injector.
#[derive(Debug)]
pub struct StorageFaultSchedule {
    case: StorageFaultCase,
    occurrence: u64,
    observed: u64,
    fired: bool,
}

impl StorageFaultSchedule {
    /// Selects the nonzero occurrence of one exact site/boundary pair.
    pub fn new(case: StorageFaultCase, occurrence: u64) -> Result<Self, StorageError> {
        if occurrence == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            case,
            occurrence,
            observed: 0,
            fired: false,
        })
    }

    /// Fails exactly once when the configured occurrence is reached.
    pub fn check(
        &mut self,
        site: StorageFaultSite,
        boundary: StorageFaultBoundary,
    ) -> Result<(), StorageError> {
        if self.fired || self.case.site != site || self.case.boundary != boundary {
            return Ok(());
        }
        self.observed = self.observed.checked_add(1).ok_or(StorageError::Overflow)?;
        if self.observed != self.occurrence {
            return Ok(());
        }
        self.fired = true;
        Err(DatabaseRejected)
    }

    /// Runs one real boundary and distinguishes pre-effect from post-effect failure.
    pub fn run<T>(
        &mut self,
        site: StorageFaultSite,
        operation: impl FnOnce() -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.check(site, StorageFaultBoundary::Before)?;
        let result = operation()?;
        self.check(site, StorageFaultBoundary::After)?;
        Ok(result)
    }

    /// Proves that the selected injection point was actually exercised.
    pub fn finish(self) -> Result<(), StorageError> {
        if self.fired {
            Ok(())
        } else {
            Err(StorageError::StaleState)
        }
    }
}

/// Cloneable qualification handle shared by the real database and filesystem adapters.
///
/// Normal storage opens use [`Self::disabled`]. Qualification opens use one shared
/// handle so a selected occurrence is counted across every adapter involved in the
/// storage operation.
///
/// An enabled handle exists for the qualification campaign and the test suites only. The
/// daemon must never construct one: an armed schedule turns one real boundary into an injected
/// failure, and the fault-labeled file backend it selects is not the production backend.
#[derive(Clone, Debug, Default)]
pub struct StorageFaultInjector {
    schedule: Option<Arc<Mutex<StorageFaultSchedule>>>,
}

impl StorageFaultInjector {
    /// Creates the no-fault production controller.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { schedule: None }
    }

    /// Creates one occurrence-aware qualification controller.
    pub fn new(case: StorageFaultCase, occurrence: u64) -> Result<Self, StorageError> {
        Ok(Self {
            schedule: Some(Arc::new(Mutex::new(StorageFaultSchedule::new(
                case, occurrence,
            )?))),
        })
    }

    /// Returns whether this handle can inject a fault.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.schedule.is_some()
    }

    /// Fails at the configured side of the selected logical boundary.
    pub fn check(
        &self,
        site: StorageFaultSite,
        boundary: StorageFaultBoundary,
    ) -> Result<(), StorageError> {
        let Some(schedule) = &self.schedule else {
            return Ok(());
        };
        schedule
            .lock()
            .map_err(|_| StorageError::Unavailable)?
            .check(site, boundary)
    }

    /// Runs one real boundary with before/after injection.
    pub fn run<T>(
        &self,
        site: StorageFaultSite,
        operation: impl FnOnce() -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.check(site, StorageFaultBoundary::Before)?;
        let result = operation()?;
        self.check(site, StorageFaultBoundary::After)?;
        Ok(result)
    }

    /// Arms this qualification controller relative to observations already made.
    ///
    /// Tests create the controller with an unreachable initial occurrence, open and fully
    /// reconstruct storage, then arm the next matching boundary. This prevents startup I/O from
    /// consuming a fault intended for the following mutation or maintenance operation.
    pub fn arm_after_current(&self, relative_occurrence: u64) -> Result<(), StorageError> {
        if relative_occurrence == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        let schedule = self
            .schedule
            .as_ref()
            .ok_or(StorageError::InvalidEncoding)?;
        let mut schedule = schedule.lock().map_err(|_| StorageError::Unavailable)?;
        if schedule.fired {
            return Err(StorageError::StaleState);
        }
        schedule.occurrence = schedule
            .observed
            .checked_add(relative_occurrence)
            .ok_or(StorageError::Overflow)?;
        Ok(())
    }

    /// Proves that the configured point fired; disabled handles succeed trivially.
    pub fn verify_fired(&self) -> Result<(), StorageError> {
        let Some(schedule) = &self.schedule else {
            return Ok(());
        };
        if schedule
            .lock()
            .map_err(|_| StorageError::Unavailable)?
            .fired
        {
            Ok(())
        } else {
            Err(StorageError::StaleState)
        }
    }
}
