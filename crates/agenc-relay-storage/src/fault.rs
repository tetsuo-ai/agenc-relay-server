//! Exhaustive deterministic fault schedules for storage qualification.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::qualification::StorageGrowthProbe;
use crate::{FilesystemCapacity, StorageError, StorageError::DatabaseRejected};

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
    /// Returns the fixed lowercase label used in qualification case names.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RecordRead => "record-read",
            Self::RecordWrite => "record-write",
            Self::Allocation => "allocation",
            Self::TransactionBegin => "transaction-begin",
            Self::TransactionPhaseOne => "transaction-phase-one",
            Self::TransactionPhaseTwo => "transaction-phase-two",
            Self::DatabaseSync => "database-sync",
            Self::GuardTemporaryCreate => "guard-temporary-create",
            Self::GuardWrite => "guard-write",
            Self::GuardFileSync => "guard-file-sync",
            Self::GuardRename => "guard-rename",
            Self::GuardDirectorySync => "guard-directory-sync",
            Self::NonceDraw => "nonce-draw",
            Self::Manifest => "manifest",
            Self::CheckpointScan => "checkpoint-scan",
            Self::CheckpointInstall => "checkpoint-install",
            Self::CheckpointPrune => "checkpoint-prune",
            Self::ConstructionPlanRebuild => "construction-plan-rebuild",
            Self::ConstructionBatch => "construction-batch",
            Self::ConstructionCursor => "construction-cursor",
            Self::ConstructionCompletion => "construction-completion",
            Self::BackupRecord => "backup-record",
            Self::BackupFileSync => "backup-file-sync",
            Self::BackupRename => "backup-rename",
            Self::BackupDirectorySync => "backup-directory-sync",
            Self::LoginIndexRotationStart => "login-index-rotation-start",
            Self::LoginIndexLazyMigration => "login-index-lazy-migration",
            Self::LoginIndexRotationFinish => "login-index-rotation-finish",
            Self::WriterLock => "writer-lock",
            Self::CapacityAdmission => "capacity-admission",
            Self::ConstructionDirectoryRename => "construction-directory-rename",
        }
    }

    /// Returns every version-one site in numeric order.
    #[must_use]
    pub const fn all() -> [Self; 31] {
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
    probe: Option<Arc<StorageGrowthProbe>>,
    growth_cap: Option<u64>,
    capacity_headroom: Option<Arc<AtomicU64>>,
}

impl StorageFaultInjector {
    /// Creates the no-fault production controller.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            schedule: None,
            probe: None,
            growth_cap: None,
            capacity_headroom: None,
        }
    }

    /// Creates one occurrence-aware qualification controller.
    pub fn new(case: StorageFaultCase, occurrence: u64) -> Result<Self, StorageError> {
        Ok(Self {
            schedule: Some(Arc::new(Mutex::new(StorageFaultSchedule::new(
                case, occurrence,
            )?))),
            probe: None,
            growth_cap: None,
            capacity_headroom: None,
        })
    }

    /// Observes every boundary without injecting anything.
    ///
    /// The handle is not enabled, so the production redb backend stays
    /// selected; only the stopped-daemon growth qualification uses it.
    #[must_use]
    pub const fn probing(probe: Arc<StorageGrowthProbe>) -> Self {
        Self {
            schedule: None,
            probe: Some(probe),
            growth_cap: None,
            capacity_headroom: None,
        }
    }

    /// Lowers every durable operation's physical growth allowance to `bytes` of redb
    /// allocation, after the guard headroom of the operation is charged.
    ///
    /// The cap exists for the qualification campaign and the test suites, which reach the
    /// Section 19.3 allowance boundary without a 256 MiB transaction. It can only lower the
    /// allowance, never raise it, it leaves the `R(F) + G` gate untouched, and it does not
    /// enable the handle, so the production redb backend stays selected.
    #[must_use]
    pub fn with_growth_cap(mut self, bytes: u64) -> Self {
        self.growth_cap = Some(bytes);
        self
    }

    /// Returns the qualification cap on each operation's redb allocation, when one is set.
    #[must_use]
    pub const fn growth_cap(&self) -> Option<u64> {
        self.growth_cap
    }

    /// Replaces every capacity sample the admission sites take through this handle: available bytes become the computed reserve `R(F)` plus
    /// `headroom`, whatever the live filesystem reports.
    ///
    /// A reserve boundary is one byte wide, and a test that places it on the live free
    /// space loses to any other writer on the same filesystem. With the sample injected,
    /// `headroom` equal to the admitted quantity is exactly the boundary, deterministically.
    /// The override does not enable fault injection, so on a disabled handle the production
    /// redb backend stays selected. It exists for tests only; the daemon never constructs one, and a
    /// disabled handle leaves every admission site reading `fstatvfs` unchanged.
    #[must_use]
    pub fn with_capacity_headroom(mut self, headroom: u64) -> Self {
        self.capacity_headroom = Some(Arc::new(AtomicU64::new(headroom)));
        self
    }

    /// Moves the injected headroom, as space returning to or leaving the filesystem would.
    /// A handle created without an override refuses.
    pub fn set_capacity_headroom(&self, headroom: u64) -> Result<(), StorageError> {
        self.capacity_headroom
            .as_ref()
            .ok_or(StorageError::InvalidEncoding)?
            .store(headroom, Ordering::Release);
        Ok(())
    }

    /// Returns the capacity an admission site must use: the live sample, or, under a
    /// test-installed override, the sample's reserve plus the injected headroom.
    pub(crate) fn observed_capacity(
        &self,
        sampled: FilesystemCapacity,
    ) -> Result<FilesystemCapacity, StorageError> {
        let Some(headroom) = &self.capacity_headroom else {
            return Ok(sampled);
        };
        Ok(FilesystemCapacity {
            available_bytes: sampled
                .reserve_bytes
                .checked_add(headroom.load(Ordering::Acquire))
                .ok_or(StorageError::Overflow)?,
            reserve_bytes: sampled.reserve_bytes,
        })
    }

    /// Returns whether this handle can inject a fault.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.schedule.is_some()
    }

    /// Records the boundary for a growth probe, then fails at the configured side of
    /// the selected logical boundary.
    pub fn check(
        &self,
        site: StorageFaultSite,
        boundary: StorageFaultBoundary,
    ) -> Result<(), StorageError> {
        if let Some(probe) = &self.probe {
            probe.observe(site, boundary)?;
        }
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
