//! Authenticated storage transaction state machine owned by one blocking thread.

pub(crate) mod backup_job;
mod stopped;

use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use agenc_ircd_crypto::{
    DatabaseBinding, LoginIndexKey, LoginIndexKeyId, OsEntropy, RollbackGuardRootKey,
    StorageDigest, StorageIntegrityContext, StorageIntegrityKeys, StorageMasterKey, StorageTable,
    TrackedStateHasher, derive_storage_index, derive_storage_integrity_keys,
    tracked_record_commitment,
};
#[cfg(test)]
use agenc_ircd_types::ChannelName;
use agenc_ircd_types::{NetworkId, Nickname, RecoveryEpoch, ServerId, TransactionId};
use redb::AllocationAllowance;
use subtle::ConstantTimeEq as _;

use crate::bounded::{MaintenanceOutcome, OperationAllowance};
use crate::mutation::ReadPlanKind;
use crate::redb_store::{
    HEADER_META_KEY, RESERVATION_META_KEY, RecoveryScratch, RedbCommitFailure, RedbStore,
    RedbWrite, ReferenceScratch, SnapshotScan,
};
use crate::scratch::{ScratchAdmission, ScratchLocation, ScratchUsage};
use crate::{
    BACKUP_FIXED_STREAM_BYTES, ChannelNameRecordBody, CommitOutcome, CommitReceipt, DatabaseHeader,
    ExistingRecord, FilesystemCapacity, InspectionStateDirectory, IntegrityCheckpoint,
    IntegrityCheckpointTbs, IntegrityManifest, IntegrityManifestTbs, IntegrityRecordMutation,
    IntegrityRecordVersion, LoginIndexKeyState, LoginIndexStoredKey, LoginIndexValueKind,
    NonceReservationState, NonceReservationTbs, ROLLBACK_GUARD_BYTES, ReadPlan, ReadRecord,
    ReadResult, RecordReference, RecoveryDisposition, RollbackGuard, RollbackGuardPhase,
    RollbackGuardTbs, SealedRecord, StateDirectory, StateMeta, StateMetaTbs,
    StorageAccountingLimits, StorageConstruction, StorageConstructionSource, StorageError,
    StorageFaultBoundary, StorageFaultInjector, StorageFaultSite, StorageMutationBatch,
    StorageMutationHead, StorageOperationCompletion, StorageOperationIdentity, StorageSealContext,
    StoredKey, TableId, classify_recovery_state, logical_meta_charge, logical_record_charge,
    verify_guard_pair,
};

const KEY_CHECK_KEY: &[u8] = b"agenc-chat/key-check/v1";
const STATE_META_KEY: &[u8] = b"agenc-chat/state-meta/v1";
const MAX_RETAINED_MANIFESTS: u64 = 1_000_000;
const MAX_RETAINED_MANIFEST_BYTES: u64 = 4_294_967_296;
const MIN_STORAGE_BYTES: u64 = 1_073_741_824;
const MAX_STORAGE_BYTES: u64 = 1_099_511_627_776;
const MIN_FIXED_RESERVE_BYTES: u64 = 67_108_864;
const MIN_CHECKPOINT_MANIFESTS: u64 = 10_000;
const CHECKPOINT_SLICE_RECORDS: usize = 4_096;
const CHECKPOINT_SLICE_BYTES: usize = 16_777_216;
/// Length prefix the backup stream adds ahead of every logical record charge.
const BACKUP_RECORD_LENGTH_PREFIX_BYTES: u64 = 8;

/// Bounded state reconstructed before the storage owner accepts requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredStorageState {
    table_record_counts: [u64; 27],
    state_generation: u64,
    account_service_response_count: u64,
    storage_commit_sequence: u64,
    manifest_sequence: u64,
    nonce_draw_high_water: u64,
    maximum_record_revision: u64,
    logical_database_bytes: u64,
    backup_stream_bytes: u64,
    database_binding: DatabaseBinding,
    storage_key_generation: u32,
    recovery_epoch: RecoveryEpoch,
    capacity: FilesystemCapacity,
    database_repaired: bool,
    verification_scratch: ScratchUsage,
    reference_scratch: ScratchUsage,
}

/// One coherent, input-free storage-owner sample for authenticated
/// administrative statistics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageStatistics {
    logical_database_bytes: u64,
    database_file_bytes: u64,
    database_max_bytes: u64,
    backup_stream_bytes: u64,
    backup_max_bytes: u64,
    state_generation: u64,
    manifest_sequence: u64,
    storage_commit_sequence: u64,
    account_service_response_count: u64,
    nonce_draw_high_water: u64,
    checkpoint_manifest_sequence: u64,
    filesystem_available_bytes: u64,
    filesystem_reserve_bytes: u64,
    pending_storage_constructions: u64,
    last_operation_charged_bytes: u64,
    deferred_cleanup_pending: bool,
    reclaimed_pages_since_open: u64,
}

impl StorageStatistics {
    /// Returns the exact committed logical database charge.
    #[must_use]
    pub const fn logical_database_bytes(self) -> u64 {
        self.logical_database_bytes
    }

    /// Returns the exact encoded backup-stream length.
    #[must_use]
    pub const fn backup_stream_bytes(self) -> u64 {
        self.backup_stream_bytes
    }

    /// Returns the fresh filesystem-availability sample.
    #[must_use]
    pub const fn filesystem_available_bytes(self) -> u64 {
        self.filesystem_available_bytes
    }

    /// Returns the effective filesystem reserve.
    #[must_use]
    pub const fn filesystem_reserve_bytes(self) -> u64 {
        self.filesystem_reserve_bytes
    }

    /// Returns the bytes the last completed durable operation charged against the Section 19.3
    /// allowance `G`: its guard headroom and every redb allocation of its transactions.
    #[must_use]
    pub const fn last_operation_charged_bytes(self) -> u64 {
        self.last_operation_charged_bytes
    }

    /// Reports whether freed-page records eligible for reclaiming may remain: true from the
    /// open until a deferred cleanup proves that nothing eligible is left, and true again after
    /// a cleanup was refused or stopped at its record bound. Records a live reader still needs
    /// are not eligible; they are reclaimed by the first cleanup after the reader releases.
    #[must_use]
    pub const fn deferred_cleanup_pending(self) -> bool {
        self.deferred_cleanup_pending
    }

    /// Returns the pages the deferred cleanups of this open returned to the allocator.
    #[must_use]
    pub const fn reclaimed_pages_since_open(self) -> u64 {
        self.reclaimed_pages_since_open
    }

    /// Returns values in the normative `STATS STORAGE` field order.
    #[must_use]
    pub const fn values(self) -> [u64; 14] {
        [
            self.logical_database_bytes,
            self.database_file_bytes,
            self.database_max_bytes,
            self.backup_stream_bytes,
            self.backup_max_bytes,
            self.state_generation,
            self.manifest_sequence,
            self.storage_commit_sequence,
            self.account_service_response_count,
            self.nonce_draw_high_water,
            self.checkpoint_manifest_sequence,
            self.filesystem_available_bytes,
            self.filesystem_reserve_bytes,
            self.pending_storage_constructions,
        ]
    }
}

/// Exact counters committed by one installed integrity checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointReceipt {
    /// Manifest sequence covered by the immutable checkpoint cut.
    pub cut_manifest_sequence: u64,
    /// Manifest sequence present when the checkpoint was installed.
    pub installation_manifest_sequence: u64,
    /// Resulting authenticated storage commit sequence.
    pub storage_commit_sequence: u64,
    /// Unchanged logical state generation at installation.
    pub state_generation: u64,
    /// Unchanged account-service response count at installation.
    pub account_service_response_count: u64,
    /// Resulting exact logical database charge.
    pub logical_database_bytes: u64,
    /// Resulting exact encoded backup-stream length.
    pub backup_stream_bytes: u64,
    /// Complete committed rollback-guard hash.
    pub rollback_guard_hash: StorageDigest,
    /// Metered scratch of the readback that proved the cut before the checkpoint was published.
    pub readback_scratch: ScratchUsage,
}

/// Closed result of one explicit integrity-checkpoint request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointOutcome {
    /// The active checkpoint already covers the current manifest head.
    NotNeeded,
    /// The checkpoint transaction and committed guard are durable.
    Installed(CheckpointReceipt),
    /// The irreversible checkpoint transaction was proven not to have begun.
    Rejected(StorageError),
    /// Persistence may have occurred and startup reconciliation is required.
    Indeterminate,
}

impl RecoveredStorageState {
    /// Returns the exact committed logical database charge.
    #[must_use]
    pub const fn logical_database_bytes(&self) -> u64 {
        self.logical_database_bytes
    }

    /// Returns the exact committed backup stream length.
    #[must_use]
    pub const fn backup_stream_bytes(&self) -> u64 {
        self.backup_stream_bytes
    }

    /// Returns the immutable record-encryption binding of the open database.
    #[must_use]
    pub const fn database_binding(&self) -> DatabaseBinding {
        self.database_binding
    }

    /// Returns the current record-key generation of the open database.
    #[must_use]
    pub const fn storage_key_generation(&self) -> u32 {
        self.storage_key_generation
    }

    /// Returns the authenticated recovery epoch advertised during onboarding.
    #[must_use]
    pub const fn recovery_epoch(&self) -> RecoveryEpoch {
        self.recovery_epoch
    }

    /// Reports whether this open had to repair the database's allocator state, which a close
    /// that persisted it within its allowance makes unnecessary and a refused or interrupted
    /// close leaves to the open, exactly as a crash does.
    #[must_use]
    pub const fn database_repaired(&self) -> bool {
        self.database_repaired
    }

    /// Returns the exact row count reconstructed for one numbered table.
    #[must_use]
    pub fn table_record_count(&self, table: TableId) -> u64 {
        self.table_record_counts
            .get(usize::from(table.as_u16()))
            .copied()
            .unwrap_or(0)
    }

    /// Returns the durable logical state generation.
    #[must_use]
    pub const fn state_generation(&self) -> u64 {
        self.state_generation
    }

    /// Returns the durable account-service response count.
    #[must_use]
    pub const fn account_service_response_count(&self) -> u64 {
        self.account_service_response_count
    }

    /// Returns the durable storage commit sequence.
    #[must_use]
    pub const fn storage_commit_sequence(&self) -> u64 {
        self.storage_commit_sequence
    }

    /// Returns the durable integrity-manifest sequence.
    #[must_use]
    pub const fn manifest_sequence(&self) -> u64 {
        self.manifest_sequence
    }

    /// Returns the committed storage nonce high-water mark.
    #[must_use]
    pub const fn nonce_draw_high_water(&self) -> u64 {
        self.nonce_draw_high_water
    }

    /// Returns the greatest authenticated domain-record revision observed.
    #[must_use]
    pub const fn maximum_record_revision(&self) -> u64 {
        self.maximum_record_revision
    }

    /// Returns the startup filesystem capacity sample.
    #[must_use]
    pub const fn capacity(&self) -> FilesystemCapacity {
        self.capacity
    }

    /// Returns the metered scratch of the startup integrity reconstruction.
    #[must_use]
    pub const fn verification_scratch(&self) -> ScratchUsage {
        self.verification_scratch
    }

    /// Returns the metered scratch of the startup reference validation.
    #[must_use]
    pub const fn reference_scratch(&self) -> ScratchUsage {
        self.reference_scratch
    }
}

/// Runtime limits enforced at the final durable storage boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageEngineLimits {
    /// redb cache allocation in bytes.
    pub redb_cache_bytes: usize,
    /// Fixed free-space reserve.
    pub fixed_reserve_bytes: u64,
    /// Percentage free-space reserve.
    pub reserve_percent: u8,
    /// Logical database maximum.
    pub database_max_bytes: u64,
    /// Exact backup-stream maximum.
    pub backup_max_bytes: u64,
    /// Soft manifest count that starts a checkpoint scan.
    pub integrity_checkpoint_manifests: u64,
}

/// The storage ceilings that may change at a StateCore reload safe point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageRuntimeLimits {
    database_max_bytes: u64,
    backup_max_bytes: u64,
    integrity_checkpoint_manifests: u64,
}

impl StorageRuntimeLimits {
    /// Validates one coherent live storage-limit view.
    pub const fn new(
        database_max_bytes: u64,
        backup_max_bytes: u64,
        integrity_checkpoint_manifests: u64,
    ) -> Result<Self, StorageError> {
        let candidate = Self {
            database_max_bytes,
            backup_max_bytes,
            integrity_checkpoint_manifests,
        };
        if candidate.database_max_bytes < MIN_STORAGE_BYTES
            || candidate.database_max_bytes > MAX_STORAGE_BYTES
            || candidate.backup_max_bytes < MIN_STORAGE_BYTES
            || candidate.backup_max_bytes > MAX_STORAGE_BYTES
            || candidate.database_max_bytes > candidate.backup_max_bytes
            || candidate.integrity_checkpoint_manifests < MIN_CHECKPOINT_MANIFESTS
            || candidate.integrity_checkpoint_manifests > MAX_RETAINED_MANIFESTS
        {
            return Err(StorageError::LimitExceeded);
        }
        Ok(candidate)
    }

    pub(crate) const fn from_engine(limits: StorageEngineLimits) -> Result<Self, StorageError> {
        Self::new(
            limits.database_max_bytes,
            limits.backup_max_bytes,
            limits.integrity_checkpoint_manifests,
        )
    }

    const fn install_into(self, limits: &mut StorageEngineLimits) {
        limits.database_max_bytes = self.database_max_bytes;
        limits.backup_max_bytes = self.backup_max_bytes;
        limits.integrity_checkpoint_manifests = self.integrity_checkpoint_manifests;
    }

    /// Returns the logical database ceiling.
    #[must_use]
    pub const fn database_max_bytes(self) -> u64 {
        self.database_max_bytes
    }

    /// Returns the exact backup-stream ceiling.
    #[must_use]
    pub const fn backup_max_bytes(self) -> u64 {
        self.backup_max_bytes
    }

    /// Returns the retained-manifest checkpoint target.
    #[must_use]
    pub const fn integrity_checkpoint_manifests(self) -> u64 {
        self.integrity_checkpoint_manifests
    }
}

#[derive(Clone, Copy)]
struct StorageLimitReservation {
    token: TransactionId,
    previous: StorageRuntimeLimits,
}

struct StorageLimitState {
    current: StorageRuntimeLimits,
    logical_database_bytes: Option<u64>,
    backup_stream_bytes: Option<u64>,
    retained_manifest_count: Option<u64>,
    retained_manifest_bytes: Option<u64>,
    checkpoint_due: Option<bool>,
    checkpoint_active: bool,
    poisoned: bool,
    limit_change_pending: bool,
    reservation: Option<StorageLimitReservation>,
}

#[derive(Clone)]
pub(crate) struct StorageLimitReader {
    state: Arc<Mutex<StorageLimitState>>,
}

#[derive(Clone)]
pub(crate) struct StorageLimitCell {
    state: Arc<Mutex<StorageLimitState>>,
}

pub(crate) fn storage_limit_pair(
    initial: StorageRuntimeLimits,
) -> (StorageLimitCell, StorageLimitReader) {
    let state = Arc::new(Mutex::new(StorageLimitState {
        current: initial,
        logical_database_bytes: None,
        backup_stream_bytes: None,
        retained_manifest_count: None,
        retained_manifest_bytes: None,
        checkpoint_due: None,
        checkpoint_active: false,
        poisoned: false,
        limit_change_pending: false,
        reservation: None,
    }));
    (
        StorageLimitCell {
            state: Arc::clone(&state),
        },
        StorageLimitReader { state },
    )
}

fn recover_limit_lock(limits: &Mutex<StorageLimitState>) -> MutexGuard<'_, StorageLimitState> {
    match limits.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl StorageLimitCell {
    pub(crate) fn activate(
        &self,
        candidate: StorageRuntimeLimits,
    ) -> Result<StorageRuntimeLimits, StorageError> {
        let mut state = recover_limit_lock(&self.state);
        validate_limit_activation(&state, candidate, None)?;
        let previous = state.current;
        state.current = candidate;
        refresh_checkpoint_due(&mut state);
        state.limit_change_pending = true;
        Ok(previous)
    }

    pub(crate) fn reserve(
        &self,
        token: TransactionId,
        candidate: StorageRuntimeLimits,
        projected_logical_database_bytes: u64,
        projected_backup_stream_bytes: u64,
    ) -> Result<(), StorageError> {
        let mut state = recover_limit_lock(&self.state);
        validate_limit_activation(
            &state,
            candidate,
            Some((
                projected_logical_database_bytes,
                projected_backup_stream_bytes,
            )),
        )?;
        let previous = state.current;
        state.current = candidate;
        refresh_checkpoint_due(&mut state);
        state.limit_change_pending = true;
        state.reservation = Some(StorageLimitReservation { token, previous });
        Ok(())
    }

    pub(crate) fn finalize(&self, token: TransactionId) -> Result<(), StorageError> {
        let mut state = recover_limit_lock(&self.state);
        if state.poisoned {
            return Err(StorageError::Unavailable);
        }
        let Some(reservation) = state.reservation else {
            return Err(StorageError::StaleState);
        };
        if reservation.token != token {
            return Err(StorageError::StaleState);
        }
        validate_usage_floor(&state, state.current)?;
        state.reservation = None;
        state.limit_change_pending = true;
        Ok(())
    }

    pub(crate) fn rollback(&self, token: TransactionId) -> Result<(), StorageError> {
        let mut state = recover_limit_lock(&self.state);
        if state.poisoned {
            return Err(StorageError::Unavailable);
        }
        let Some(reservation) = state.reservation else {
            return Err(StorageError::StaleState);
        };
        if reservation.token != token {
            return Err(StorageError::StaleState);
        }
        state.current = reservation.previous;
        state.reservation = None;
        refresh_checkpoint_due(&mut state);
        state.limit_change_pending = true;
        Ok(())
    }

    pub(crate) fn restore_unreserved(&self, previous: StorageRuntimeLimits) {
        let mut state = recover_limit_lock(&self.state);
        if state.reservation.is_none() {
            state.current = previous;
            refresh_checkpoint_due(&mut state);
            state.limit_change_pending = true;
        }
    }

    pub(crate) fn checkpoint_due(&self) -> Result<bool, StorageError> {
        let state = recover_limit_lock(&self.state);
        if state.poisoned {
            return Err(StorageError::Unavailable);
        }
        state.checkpoint_due.ok_or(StorageError::Unavailable)
    }
}

fn validate_limit_activation(
    state: &StorageLimitState,
    candidate: StorageRuntimeLimits,
    projected: Option<(u64, u64)>,
) -> Result<(), StorageError> {
    if state.poisoned {
        return Err(StorageError::Unavailable);
    }
    if state.reservation.is_some() || state.checkpoint_active {
        return Err(StorageError::QueueFull);
    }
    validate_usage_floor(state, candidate)?;
    if let Some((logical, backup)) = projected
        && (logical > candidate.database_max_bytes || backup > candidate.backup_max_bytes)
    {
        return Err(StorageError::LimitExceeded);
    }
    Ok(())
}

fn validate_usage_floor(
    state: &StorageLimitState,
    candidate: StorageRuntimeLimits,
) -> Result<(), StorageError> {
    let logical = state
        .logical_database_bytes
        .ok_or(StorageError::Unavailable)?;
    let backup = state.backup_stream_bytes.ok_or(StorageError::Unavailable)?;
    if logical > candidate.database_max_bytes || backup > candidate.backup_max_bytes {
        return Err(StorageError::LimitExceeded);
    }
    Ok(())
}

impl StorageLimitReader {
    fn load(&self) -> StorageRuntimeLimits {
        recover_limit_lock(&self.state).current
    }

    fn begin_checkpoint(&self) -> Result<StorageRuntimeLimits, StorageError> {
        let mut state = recover_limit_lock(&self.state);
        if state.poisoned {
            return Err(StorageError::Unavailable);
        }
        if state.reservation.is_some() || state.checkpoint_active {
            return Err(StorageError::QueueFull);
        }
        state.checkpoint_active = true;
        Ok(state.current)
    }

    fn publish_facts(
        &self,
        logical_database_bytes: u64,
        backup_stream_bytes: u64,
        retained_manifest_count: u64,
        retained_manifest_bytes: u64,
    ) {
        let mut state = recover_limit_lock(&self.state);
        if state.poisoned {
            return;
        }
        state.logical_database_bytes = Some(logical_database_bytes);
        state.backup_stream_bytes = Some(backup_stream_bytes);
        state.retained_manifest_count = Some(retained_manifest_count);
        state.retained_manifest_bytes = Some(retained_manifest_bytes);
        refresh_checkpoint_due(&mut state);
    }

    fn finish_checkpoint(&self) {
        recover_limit_lock(&self.state).checkpoint_active = false;
    }

    fn poison_checkpoint(&self) {
        let mut state = recover_limit_lock(&self.state);
        state.poisoned = true;
        state.checkpoint_due = None;
        state.limit_change_pending = false;
    }

    fn has_reservation(&self) -> bool {
        recover_limit_lock(&self.state).reservation.is_some()
    }

    fn take_limit_change(&self) -> bool {
        let mut state = recover_limit_lock(&self.state);
        let pending = state.limit_change_pending;
        state.limit_change_pending = false;
        pending
    }
}

fn refresh_checkpoint_due(state: &mut StorageLimitState) {
    state.checkpoint_due = match (state.retained_manifest_count, state.retained_manifest_bytes) {
        (Some(count), Some(bytes)) => Some(checkpoint_is_due(state.current, count, bytes)),
        _ => None,
    };
}

const fn checkpoint_is_due(
    limits: StorageRuntimeLimits,
    retained_manifest_count: u64,
    retained_manifest_bytes: u64,
) -> bool {
    retained_manifest_count >= limits.integrity_checkpoint_manifests
        || retained_manifest_count >= MAX_RETAINED_MANIFESTS
        || retained_manifest_bytes >= MAX_RETAINED_MANIFEST_BYTES
}

impl StorageEngineLimits {
    /// Validates the complete Appendix-C.5 storage limit profile.
    pub const fn validate(self) -> Result<Self, StorageError> {
        if !storage_limits_are_valid(self)
            || !reserve_limits_are_valid(self)
            || !checkpoint_limit_is_valid(self)
        {
            return Err(StorageError::LimitExceeded);
        }
        Ok(self)
    }
}

const fn storage_limits_are_valid(limits: StorageEngineLimits) -> bool {
    limits.redb_cache_bytes != 0
        && limits.database_max_bytes >= MIN_STORAGE_BYTES
        && limits.database_max_bytes <= MAX_STORAGE_BYTES
        && limits.backup_max_bytes >= MIN_STORAGE_BYTES
        && limits.backup_max_bytes <= MAX_STORAGE_BYTES
        && limits.database_max_bytes <= limits.backup_max_bytes
}

const fn reserve_limits_are_valid(limits: StorageEngineLimits) -> bool {
    limits.fixed_reserve_bytes >= MIN_FIXED_RESERVE_BYTES
        && limits.fixed_reserve_bytes <= MAX_STORAGE_BYTES
        && limits.reserve_percent != 0
        && limits.reserve_percent <= 25
}

const fn checkpoint_limit_is_valid(limits: StorageEngineLimits) -> bool {
    limits.integrity_checkpoint_manifests >= MIN_CHECKPOINT_MANIFESTS
        && limits.integrity_checkpoint_manifests <= MAX_RETAINED_MANIFESTS
}

/// Secret-bearing startup inputs moved directly onto the storage thread.
pub struct StorageOpenConfig {
    /// Expected permanent network identity from validated configuration.
    pub expected_network_id: NetworkId,
    /// Expected permanent server identity from validated configuration.
    pub expected_server_id: ServerId,
    /// Validated state-directory authority and writer lock.
    pub state_directory: StateDirectory,
    /// Active external storage master key.
    pub storage_master_key: StorageMasterKey,
    /// Independently provisioned rollback-guard root.
    pub rollback_guard_root_key: RollbackGuardRootKey,
    /// Configured current login-index key.
    pub login_index_key: LoginIndexKey,
    /// Configured previous login-index key, present only during a transition.
    pub previous_login_index_key: Option<LoginIndexKey>,
    /// Final storage and filesystem limits.
    pub limits: StorageEngineLimits,
}

/// Secret-bearing inputs for one non-mutating stopped-daemon inspection.
pub struct StorageInspectionConfig {
    /// Expected permanent network identity from validated configuration.
    pub expected_network_id: NetworkId,
    /// Expected permanent server identity from validated configuration.
    pub expected_server_id: ServerId,
    /// Existing state directory opened without writer authority.
    pub state_directory: InspectionStateDirectory,
    /// Active external storage master key.
    pub storage_master_key: StorageMasterKey,
    /// Independently provisioned rollback-guard root.
    pub rollback_guard_root_key: RollbackGuardRootKey,
    /// Configured current login-index key.
    pub login_index_key: LoginIndexKey,
    /// Configured previous login-index key, present only during a transition.
    pub previous_login_index_key: Option<LoginIndexKey>,
    /// Final storage and filesystem limits.
    pub limits: StorageEngineLimits,
}

struct EngineOpenConfig {
    expected_schema_generation: u64,
    expected_network_id: NetworkId,
    expected_server_id: ServerId,
    state_directory: EngineStateDirectory,
    storage_master_key: StorageMasterKey,
    rollback_guard_root_key: RollbackGuardRootKey,
    login_index_key: LoginIndexKey,
    previous_login_index_key: Option<LoginIndexKey>,
    limits: StorageEngineLimits,
}

struct AuthenticatedOpenState {
    integrity_keys: StorageIntegrityKeys,
    header: DatabaseHeader,
    binding: DatabaseBinding,
    state_meta: StateMeta,
    state_meta_record_id: StorageDigest,
    reservation: NonceReservationState,
    guard: RollbackGuard,
    retained_manifest_count: u64,
    retained_manifest_bytes: u64,
}

enum EngineStateDirectory {
    Writable(StateDirectory),
    Inspection(InspectionStateDirectory),
}

impl EngineStateDirectory {
    fn open_store(&self, cache_bytes: usize) -> Result<RedbStore, StorageError> {
        match self {
            Self::Writable(directory) => RedbStore::open_with_faults(
                directory.open_database_file()?,
                cache_bytes,
                directory.faults(),
            ),
            Self::Inspection(directory) => {
                RedbStore::open_read_only(&directory.database_descriptor_path(), cache_bytes)
            }
        }
    }

    fn open_database_file(&self) -> Result<File, StorageError> {
        match self {
            Self::Writable(directory) => directory.open_database_file(),
            Self::Inspection(directory) => directory.open_database_file(),
        }
    }

    fn faults(&self) -> StorageFaultInjector {
        match self {
            Self::Writable(directory) => directory.faults(),
            Self::Inspection(_) => StorageFaultInjector::disabled(),
        }
    }

    fn read_guard(&self, expected_bytes: usize) -> Result<Vec<u8>, StorageError> {
        match self {
            Self::Writable(directory) => directory.read_guard(expected_bytes),
            Self::Inspection(directory) => directory.read_guard(expected_bytes),
        }
    }

    fn replace_guard(&self, bytes: &[u8]) -> Result<(), StorageError> {
        match self {
            Self::Writable(directory) => directory.replace_guard(bytes),
            Self::Inspection(_) => Err(StorageError::FilesystemRejected(
                crate::FilesystemCause::PermissionRejected,
            )),
        }
    }

    fn capacity(
        &self,
        fixed_reserve_bytes: u64,
        reserve_percent: u8,
    ) -> Result<FilesystemCapacity, StorageError> {
        match self {
            Self::Writable(directory) => directory.capacity(fixed_reserve_bytes, reserve_percent),
            Self::Inspection(directory) => directory.capacity(fixed_reserve_bytes, reserve_percent),
        }
    }

    fn pending_construction(&self) -> Result<u64, StorageError> {
        match self {
            Self::Writable(directory) => directory.pending_construction(),
            Self::Inspection(directory) => directory.pending_construction(),
        }
    }

    /// The fundamental block size of the qualified filesystem, the granularity at which the
    /// guard temporaries and the database file grow.
    fn block_size(&self) -> u64 {
        match self {
            Self::Writable(directory) => directory.tuple().block_size,
            Self::Inspection(directory) => directory.tuple().block_size,
        }
    }

    fn admit_transaction(
        &self,
        fixed_reserve_bytes: u64,
        reserve_percent: u8,
    ) -> Result<FilesystemCapacity, StorageError> {
        match self {
            Self::Writable(directory) => {
                directory.admit_transaction(fixed_reserve_bytes, reserve_percent)
            }
            Self::Inspection(_) => Err(StorageError::FilesystemRejected(
                crate::FilesystemCause::PermissionRejected,
            )),
        }
    }

    /// Creates the private scratch entry a verification writes: a create-exclusive mode-0600
    /// file of the state directory removed through its retained descriptor, or, without
    /// writer authority, an anonymous inode on the same qualified filesystem.
    fn scratch_location(&self) -> Result<ScratchLocation, StorageError> {
        match self {
            Self::Writable(directory) => {
                let (file, scratch_directory, name) = directory.create_recovery_scratch()?;
                Ok(ScratchLocation::Exclusive {
                    file,
                    directory: scratch_directory,
                    name,
                })
            }
            Self::Inspection(directory) => Ok(ScratchLocation::Anonymous {
                file: directory.create_anonymous_scratch()?,
            }),
        }
    }

    const fn installs_repairable_guard(&self) -> bool {
        matches!(self, Self::Writable(_))
    }
}

/// Progress of the deferred freed-page reclamation across the operations of one open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeferredCleanup {
    /// Whether records that need reclaiming may remain: true from the open until a cleanup
    /// reports that nothing eligible is left.
    pending: bool,
    /// Pages returned to the allocator since the open.
    reclaimed_pages: u64,
}

/// The exact-filesystem gate every scratch transaction passes immediately before it begins:
/// a fresh sample of the state filesystem must hold `R(F)` plus the transaction's allowance.
///
/// This repeats the arithmetic of [`StateDirectory::admit_transaction`] for an explicit
/// allowance and for both directory authorities, because inspection samples capacity without
/// holding the writer lock.
struct ScratchGate<'a> {
    directory: &'a EngineStateDirectory,
    fixed_reserve_bytes: u64,
    reserve_percent: u8,
}

impl ScratchAdmission for ScratchGate<'_> {
    fn admit_scratch(&self, allowance: AllocationAllowance) -> Result<(), StorageError> {
        let capacity = self
            .directory
            .capacity(self.fixed_reserve_bytes, self.reserve_percent)?;
        let required = capacity
            .reserve_bytes
            .checked_add(allowance.bytes())
            .ok_or(StorageError::Overflow)?;
        if capacity.available_bytes < required {
            return Err(StorageError::FilesystemRejected(
                crate::FilesystemCause::InsufficientCapacity,
            ));
        }
        Ok(())
    }
}

/// The read-only half of the ledger verification: what the control chain proves without any
/// scratch, and which manifests the record-set reconstruction has to reverse.
struct LedgerChain {
    tracked_record_count: u64,
    tracked_state_digest: StorageDigest,
    replay: Option<std::ops::RangeInclusive<u64>>,
}

/// One tracked-state reconstruction from the current records back to a cut, with the metered
/// scratch that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrackedStateReconstruction {
    record_count: u64,
    digest: StorageDigest,
    scratch: ScratchUsage,
}

pub(crate) struct StorageEngine {
    store: RedbStore,
    state_directory: EngineStateDirectory,
    master_key: StorageMasterKey,
    guard_root_key: RollbackGuardRootKey,
    login_index_key: LoginIndexKey,
    previous_login_index_key: Option<LoginIndexKey>,
    integrity_keys: StorageIntegrityKeys,
    header: DatabaseHeader,
    binding: DatabaseBinding,
    state_meta: StateMeta,
    state_meta_record_id: StorageDigest,
    reservation: NonceReservationState,
    guard: RollbackGuard,
    limits: StorageEngineLimits,
    runtime_limits: StorageLimitReader,
    retained_manifest_count: u64,
    retained_manifest_bytes: u64,
    checkpoint_job: Option<CheckpointJob>,
    backup_job: Option<backup_job::BackupJob>,
    /// Whether the scratch half of the startup verification is still owed: the filesystem could
    /// not admit it when the owner opened, so the owner opened with every durable write refused
    /// until a write finds the space to run it first.
    verification_deferred: AtomicBool,
    cleanup: DeferredCleanup,
    last_operation_charged_bytes: u64,
    close_handled: bool,
}

/// Authenticates and reconstructs an existing database without taking writer
/// authority or changing persistent state.
pub fn inspect_storage(
    config: StorageInspectionConfig,
) -> Result<RecoveredStorageState, StorageError> {
    StorageEngine::open_inspection(config)?.startup_scan()
}

fn authenticate_open_state(
    config: &EngineOpenConfig,
    store: &RedbStore,
    limits: StorageEngineLimits,
) -> Result<AuthenticatedOpenState, StorageError> {
    let header = DatabaseHeader::decode(&require_meta(store, HEADER_META_KEY)?)?;
    if header.tbs().schema_generation != config.expected_schema_generation {
        return Err(StorageError::UnsupportedVersion);
    }
    if header.tbs().network_id != config.expected_network_id
        || header.tbs().server_id != config.expected_server_id
    {
        return Err(StorageError::AuthenticationFailed);
    }
    let context = StorageIntegrityContext::new(
        header.tbs().network_id,
        header.tbs().server_id,
        header.tbs().database_instance_id,
    );
    let integrity_keys = derive_storage_integrity_keys(&config.rollback_guard_root_key, context)?;
    let reservation = NonceReservationState::decode_and_verify(
        &require_meta(store, RESERVATION_META_KEY)?,
        &integrity_keys,
    )?;
    let guard = RollbackGuard::decode_and_verify(
        &config.state_directory.read_guard(ROLLBACK_GUARD_BYTES)?,
        &integrity_keys,
    )?;
    let binding = database_binding(&header);
    verify_key_check(store, &config.storage_master_key, binding, &header)?;
    let (state_meta, state_meta_record_id) = read_state_meta(
        store,
        &config.storage_master_key,
        binding,
        &header,
        &integrity_keys,
    )?;
    let guard = reconcile_open_guard(
        &config.state_directory,
        &header,
        &state_meta,
        state_meta_record_id,
        &reservation,
        guard,
        &integrity_keys,
    )?;
    let (retained_manifest_count, retained_manifest_bytes) =
        validate_open_accounting(store, &state_meta, limits)?;
    Ok(AuthenticatedOpenState {
        integrity_keys,
        header,
        binding,
        state_meta,
        state_meta_record_id,
        reservation,
        guard,
        retained_manifest_count,
        retained_manifest_bytes,
    })
}

fn validate_open_schema(config: &EngineOpenConfig) -> Result<(), StorageError> {
    let guard = RollbackGuard::decode_with_root(
        &config.state_directory.read_guard(ROLLBACK_GUARD_BYTES)?,
        &config.rollback_guard_root_key,
    )?;
    if guard.tbs().network_id != config.expected_network_id
        || guard.tbs().server_id != config.expected_server_id
    {
        return Err(StorageError::AuthenticationFailed);
    }
    if guard.tbs().schema_generation != config.expected_schema_generation {
        return Err(StorageError::UnsupportedVersion);
    }
    Ok(())
}

fn reconcile_open_guard(
    directory: &EngineStateDirectory,
    header: &DatabaseHeader,
    state_meta: &StateMeta,
    state_meta_record_id: StorageDigest,
    reservation: &NonceReservationState,
    guard: RollbackGuard,
    integrity_keys: &StorageIntegrityKeys,
) -> Result<RollbackGuard, StorageError> {
    match classify_recovery_state(
        header,
        state_meta,
        state_meta_record_id,
        reservation,
        &guard,
    )? {
        RecoveryDisposition::ExactCommitted | RecoveryDisposition::ExactReserved => Ok(guard),
        RecoveryDisposition::InstallReservedGuard | RecoveryDisposition::InstallCommittedGuard => {
            let replacement = guard_for_reservation(header, reservation, integrity_keys)?;
            if directory.installs_repairable_guard() {
                directory.replace_guard(&replacement.encode()?)?;
            }
            Ok(replacement)
        }
    }
}

fn validate_open_accounting(
    store: &RedbStore,
    state_meta: &StateMeta,
    limits: StorageEngineLimits,
) -> Result<(u64, u64), StorageError> {
    if state_meta.tbs().logical_database_bytes > limits.database_max_bytes
        || state_meta.tbs().backup_stream_bytes > limits.backup_max_bytes
    {
        return Err(StorageError::LimitExceeded);
    }
    let usage = store.table_usage(TableId::IntegrityManifest, MAX_RETAINED_MANIFEST_BYTES)?;
    let expected_manifest_count = state_meta
        .tbs()
        .manifest_sequence
        .checked_sub(state_meta.tbs().checkpoint_manifest_sequence)
        .ok_or(StorageError::StaleState)?;
    if usage.0 != expected_manifest_count || usage.0 > MAX_RETAINED_MANIFESTS {
        return Err(StorageError::StaleState);
    }
    Ok(usage)
}

impl StorageEngine {
    // agenc-review: focus owner=storage reviewed=2026-08-27 reason=startup orders identity key guard recovery and ceiling validation before ownership
    pub(crate) fn open(config: StorageOpenConfig) -> Result<Self, StorageError> {
        let initial = StorageRuntimeLimits::from_engine(config.limits)?;
        let (_writer, reader) = storage_limit_pair(initial);
        Self::open_with_runtime_limits(config, reader)
    }

    pub(crate) fn open_with_runtime_limits(
        config: StorageOpenConfig,
        runtime_limits: StorageLimitReader,
    ) -> Result<Self, StorageError> {
        Self::open_authenticated(
            EngineOpenConfig {
                expected_schema_generation: crate::SCHEMA_GENERATION,
                expected_network_id: config.expected_network_id,
                expected_server_id: config.expected_server_id,
                state_directory: EngineStateDirectory::Writable(config.state_directory),
                storage_master_key: config.storage_master_key,
                rollback_guard_root_key: config.rollback_guard_root_key,
                login_index_key: config.login_index_key,
                previous_login_index_key: config.previous_login_index_key,
                limits: config.limits,
            },
            runtime_limits,
        )
    }

    fn open_inspection(config: StorageInspectionConfig) -> Result<Self, StorageError> {
        let initial = StorageRuntimeLimits::from_engine(config.limits)?;
        let (_writer, reader) = storage_limit_pair(initial);
        Self::open_authenticated(
            EngineOpenConfig {
                expected_schema_generation: crate::SCHEMA_GENERATION,
                expected_network_id: config.expected_network_id,
                expected_server_id: config.expected_server_id,
                state_directory: EngineStateDirectory::Inspection(config.state_directory),
                storage_master_key: config.storage_master_key,
                rollback_guard_root_key: config.rollback_guard_root_key,
                login_index_key: config.login_index_key,
                previous_login_index_key: config.previous_login_index_key,
                limits: config.limits,
            },
            reader,
        )
    }

    fn open_authenticated(
        config: EngineOpenConfig,
        runtime_limits: StorageLimitReader,
    ) -> Result<Self, StorageError> {
        let limits = config.limits.validate()?;
        validate_open_schema(&config)?;
        let store = config.state_directory.open_store(limits.redb_cache_bytes)?;
        let authenticated = authenticate_open_state(&config, &store, limits)?;
        let engine = Self {
            store,
            state_directory: config.state_directory,
            master_key: config.storage_master_key,
            guard_root_key: config.rollback_guard_root_key,
            login_index_key: config.login_index_key,
            previous_login_index_key: config.previous_login_index_key,
            integrity_keys: authenticated.integrity_keys,
            header: authenticated.header,
            binding: authenticated.binding,
            state_meta: authenticated.state_meta,
            state_meta_record_id: authenticated.state_meta_record_id,
            reservation: authenticated.reservation,
            guard: authenticated.guard,
            limits,
            runtime_limits,
            retained_manifest_count: authenticated.retained_manifest_count,
            retained_manifest_bytes: authenticated.retained_manifest_bytes,
            checkpoint_job: None,
            backup_job: None,
            verification_deferred: AtomicBool::new(false),
            cleanup: DeferredCleanup {
                pending: true,
                reclaimed_pages: 0,
            },
            last_operation_charged_bytes: 0,
            close_handled: false,
        };
        engine.publish_runtime_facts();
        Ok(engine)
    }

    pub(crate) fn refresh_runtime_limits(&mut self) {
        self.runtime_limits.load().install_into(&mut self.limits);
    }

    pub(crate) fn take_runtime_limit_change(&mut self) -> bool {
        let changed = self.runtime_limits.take_limit_change();
        if changed {
            self.refresh_runtime_limits();
            self.publish_runtime_facts();
        }
        changed
    }

    pub(crate) fn statistics(&self) -> Result<StorageStatistics, StorageError> {
        let database_file_bytes = self
            .state_directory
            .open_database_file()?
            .metadata()
            .map_err(crate::filesystem_rejected)?
            .len();
        let capacity = self
            .state_directory
            .capacity(self.limits.fixed_reserve_bytes, self.limits.reserve_percent)?;
        Ok(StorageStatistics {
            logical_database_bytes: self.state_meta.tbs().logical_database_bytes,
            database_file_bytes,
            database_max_bytes: self.limits.database_max_bytes,
            backup_stream_bytes: self.state_meta.tbs().backup_stream_bytes,
            backup_max_bytes: self.limits.backup_max_bytes,
            state_generation: self.state_meta.tbs().state_generation,
            manifest_sequence: self.state_meta.tbs().manifest_sequence,
            storage_commit_sequence: self.state_meta.tbs().storage_commit_sequence,
            account_service_response_count: self.state_meta.tbs().account_service_response_count,
            nonce_draw_high_water: self.state_meta.tbs().nonce_draw_high_water,
            checkpoint_manifest_sequence: self.state_meta.tbs().checkpoint_manifest_sequence,
            filesystem_available_bytes: capacity.available_bytes,
            filesystem_reserve_bytes: capacity.reserve_bytes,
            pending_storage_constructions: self.state_directory.pending_construction()?,
            last_operation_charged_bytes: self.last_operation_charged_bytes,
            deferred_cleanup_pending: self.cleanup.pending,
            reclaimed_pages_since_open: self.cleanup.reclaimed_pages,
        })
    }

    // agenc-review: focus owner=storage reviewed=2026-09-04 reason=closed exact indexed-or-range dispatch preserves one immutable read transaction contract
    pub(crate) fn read(&self, plan: &ReadPlan) -> Result<ReadResult, StorageError> {
        let (records, truncated) = match plan.kind() {
            ReadPlanKind::Exact { table, key } => {
                let records = match self.store.read_record(*table, key.as_bytes())? {
                    Some(sealed_record) => vec![ReadRecord {
                        table: *table,
                        key: StoredKey::new(key.as_bytes().to_vec())?,
                        sealed_record,
                    }],
                    None => Vec::new(),
                };
                (records, false)
            }
            ReadPlanKind::ExactKeys { table, keys } => {
                let records = self
                    .store
                    .read_exact_keys(*table, keys)?
                    .into_iter()
                    .map(|(key, sealed_record)| {
                        Ok(ReadRecord {
                            table: *table,
                            key: StoredKey::new(key)?,
                            sealed_record,
                        })
                    })
                    .collect::<Result<Vec<_>, StorageError>>()?;
                (records, false)
            }
            ReadPlanKind::Range {
                table,
                start,
                end,
                limit,
            } => {
                let (rows, truncated) = self.store.read_range(
                    *table,
                    start.as_bytes(),
                    end.as_bytes(),
                    usize::from(*limit),
                )?;
                let records = rows
                    .into_iter()
                    .map(|(key, sealed_record)| {
                        Ok(ReadRecord {
                            table: *table,
                            key: StoredKey::new(key)?,
                            sealed_record,
                        })
                    })
                    .collect::<Result<Vec<_>, StorageError>>()?;
                (records, truncated)
            }
        };
        Ok(ReadResult {
            storage_commit_sequence: self.state_meta.tbs().storage_commit_sequence,
            records,
            truncated,
        })
    }

    pub(crate) fn construction_marker(&self) -> Result<StorageConstruction, StorageError> {
        let encoded = self
            .store
            .read_record(
                TableId::StorageConstruction,
                crate::STORAGE_CONSTRUCTION_KEY,
            )?
            .ok_or(StorageError::StaleState)?;
        let key = StoredKey::new(crate::STORAGE_CONSTRUCTION_KEY.to_vec())?;
        let sealed = SealedRecord::decode(&encoded)?;
        let plaintext = sealed.open(
            &self.master_key,
            self.binding,
            TableId::StorageConstruction,
            1,
            self.header.tbs().storage_key_generation,
            &key,
        )?;
        StorageConstruction::decode(plaintext.expose_for_storage_codec())
    }

    pub(crate) fn construction_existing(
        &self,
        table: TableId,
        key: &StoredKey,
    ) -> Result<Option<ExistingRecord>, StorageError> {
        self.store
            .read_record(table, key.as_bytes())?
            .map(|encoded| {
                let sealed = SealedRecord::decode(&encoded)?;
                ExistingRecord::new(sealed.record_schema(), sealed.record_id()?, encoded.len())
            })
            .transpose()
    }

    pub(crate) fn completed_construction(
        &self,
        expected_identity: StorageOperationIdentity,
    ) -> Result<StorageOperationCompletion, StorageError> {
        let completion = self.read_completed_construction(expected_identity)?;
        self.verify_completed_construction_boundary(&completion)?;
        Ok(completion)
    }

    pub(crate) fn resume_completed_construction(
        &mut self,
        expected_identity: StorageOperationIdentity,
    ) -> Result<StorageOperationCompletion, StorageError> {
        let completion = self.read_completed_construction(expected_identity)?;
        if self
            .verify_completed_construction_boundary(&completion)
            .is_ok()
        {
            return Ok(completion);
        }
        self.verify_uncheckpointed_completion(&completion)?;
        self.checkpoint_for_shutdown()
            .map_err(|error| match error {
                EngineCommitFailure::Rejected(error) => error,
                EngineCommitFailure::Indeterminate => StorageError::Unavailable,
            })?;
        let _capacity = self.startup_scan()?;
        self.completed_construction(expected_identity)
    }

    fn read_completed_construction(
        &self,
        expected_identity: StorageOperationIdentity,
    ) -> Result<StorageOperationCompletion, StorageError> {
        expected_identity.validate()?;
        let operation_id = expected_identity.operation_id()?;
        let key = StoredKey::new(operation_id.as_bytes().to_vec())?;
        let encoded = self
            .store
            .read_record(TableId::StorageOperation, key.as_bytes())?
            .ok_or(StorageError::StaleState)?;
        let sealed = SealedRecord::decode(&encoded)?;
        let plaintext = sealed.open(
            &self.master_key,
            self.binding,
            TableId::StorageOperation,
            1,
            self.header.tbs().storage_key_generation,
            &key,
        )?;
        let completion = StorageOperationCompletion::decode(plaintext.expose_for_storage_codec())?;
        if (
            completion.identity,
            expected_identity.target_database_header_hash,
            expected_identity.target_database_instance_id,
        ) != (
            expected_identity,
            self.header.complete_hash()?,
            self.header.tbs().database_instance_id,
        ) {
            return Err(StorageError::ResumeMismatch);
        }
        Ok(completion)
    }

    fn verify_uncheckpointed_completion(
        &self,
        completion: &StorageOperationCompletion,
    ) -> Result<(), StorageError> {
        let state = self.state_meta.tbs();
        if state.storage_commit_sequence != completion.finalization_storage_commit_sequence
            || state.manifest_sequence != completion.finalization_manifest_sequence
            || state.state_generation != completion.finalization_state_generation
            || state.account_service_response_count
                != completion.finalization_account_service_response_count
            || state.nonce_draw_high_water != completion.finalization_nonce_draw_high_water
            || state.checkpoint_manifest_sequence >= completion.finalization_manifest_sequence
        {
            return Err(StorageError::ResumeMismatch);
        }
        Ok(())
    }

    pub(crate) fn login_index_transition_preflight(
        &self,
        new_key_id: LoginIndexKeyId,
    ) -> Result<LoginIndexKeyState, StorageError> {
        let state = self.read_login_index_key_state()?;
        let mut preflight = crate::LoginIndexTransitionPreflight::new(state, new_key_id)?;
        self.store.visit_table(
            TableId::LoginIndex,
            self.limits.database_max_bytes,
            |key, encoded| {
                let stored_key = LoginIndexStoredKey::decode(key)?;
                let record_key = StoredKey::new(key.to_vec())?;
                let sealed = SealedRecord::decode(encoded)?;
                let plaintext = sealed.open(
                    &self.master_key,
                    self.binding,
                    TableId::LoginIndex,
                    1,
                    self.header.tbs().storage_key_generation,
                    &record_key,
                )?;
                let value = crate::LoginIndexValue::decode(
                    plaintext.expose_for_storage_codec(),
                    &stored_key,
                )?;
                preflight.observe(&stored_key, &value)
            },
        )?;
        preflight.finish()
    }

    fn verify_completed_construction_boundary(
        &self,
        completion: &StorageOperationCompletion,
    ) -> Result<(), StorageError> {
        let state = self.state_meta.tbs();
        let key = StoredKey::new(state.checkpoint_manifest_sequence.to_be_bytes().to_vec())?;
        let encoded = self
            .store
            .read_record(TableId::IntegrityCheckpoint, key.as_bytes())?
            .ok_or(StorageError::StaleState)?;
        let sealed = SealedRecord::decode(&encoded)?;
        let plaintext = sealed.open(
            &self.master_key,
            self.binding,
            TableId::IntegrityCheckpoint,
            1,
            self.header.tbs().storage_key_generation,
            &key,
        )?;
        let checkpoint = IntegrityCheckpoint::decode(plaintext.expose_for_storage_codec())?;
        verify_completion_cut(completion, checkpoint.tbs())?;
        verify_completion_installation(completion, checkpoint.tbs(), state)
    }

    pub(crate) const fn construction_source_header(&self) -> DatabaseHeader {
        self.header
    }

    pub(crate) const fn construction_source_state(&self) -> StateMetaTbs {
        *self.state_meta.tbs()
    }

    pub(crate) fn construction_source_guard_hash(&self) -> Result<StorageDigest, StorageError> {
        self.guard.complete_hash()
    }

    pub(crate) const fn construction_source_master_key(&self) -> &StorageMasterKey {
        &self.master_key
    }

    pub(crate) const fn construction_source_binding(&self) -> DatabaseBinding {
        self.binding
    }

    pub(crate) fn check_construction_fault(
        &self,
        site: StorageFaultSite,
        boundary: StorageFaultBoundary,
    ) -> Result<(), StorageError> {
        self.state_directory.faults().check(site, boundary)
    }

    pub(crate) fn visit_construction_source_records<F>(
        &self,
        mut visitor: F,
    ) -> Result<(), StorageError>
    where
        F: FnMut(
            StorageConstructionSource,
            crate::ConstructionSourceRecord,
        ) -> Result<(), StorageError>,
    {
        for number in 1_u16..=26 {
            if matches!(number, 14..=16 | 25) {
                continue;
            }
            let table = TableId::from_u16(number)?;
            self.store
                .visit_table(table, self.limits.database_max_bytes, |key, encoded| {
                    let sealed = SealedRecord::decode(encoded)?;
                    let source = StorageConstructionSource::new(
                        crate::StorageConstructionSourceKind::DatabaseRecord,
                        table,
                        StoredKey::new(key.to_vec())?,
                        sealed.record_schema(),
                        sealed.record_id()?,
                        0,
                    )?;
                    let record = crate::ConstructionSourceRecord::open(
                        &source,
                        encoded,
                        &self.master_key,
                        self.binding,
                        self.header.tbs().storage_key_generation,
                    )?;
                    visitor(source, record)
                })?;
        }
        Ok(())
    }

    pub(crate) fn open_construction_source_record(
        &self,
        reference: &StorageConstructionSource,
    ) -> Result<crate::ConstructionSourceRecord, StorageError> {
        if reference.kind() != crate::StorageConstructionSourceKind::DatabaseRecord {
            return Err(StorageError::InvalidEncoding);
        }
        let encoded = self
            .store
            .read_record(reference.table(), reference.key().as_bytes())?
            .ok_or(StorageError::StaleState)?;
        crate::ConstructionSourceRecord::open(
            reference,
            &encoded,
            &self.master_key,
            self.binding,
            self.header.tbs().storage_key_generation,
        )
    }

    pub(crate) fn construction_accounting(&self) -> StorageAccountingLimits {
        StorageAccountingLimits {
            current_logical_database_bytes: self.state_meta.tbs().logical_database_bytes,
            current_backup_stream_bytes: self.state_meta.tbs().backup_stream_bytes,
            database_max_bytes: self.limits.database_max_bytes,
            backup_max_bytes: self.limits.backup_max_bytes,
        }
    }

    pub(crate) fn construction_head(
        &self,
        transaction_id: agenc_ircd_types::TransactionId,
    ) -> StorageMutationHead {
        StorageMutationHead {
            transaction_id,
            expected_storage_commit_sequence: self.state_meta.tbs().storage_commit_sequence,
            expected_state_generation: self.state_meta.tbs().state_generation,
            resulting_state_generation: self.state_meta.tbs().state_generation,
            state_advancing_plan_count: 0,
            expected_account_service_response_count: self
                .state_meta
                .tbs()
                .account_service_response_count,
            resulting_account_service_response_count: self
                .state_meta
                .tbs()
                .account_service_response_count,
        }
    }

    pub(crate) fn construction_commit(
        &mut self,
        batch: StorageMutationBatch,
    ) -> Result<CommitReceipt, StorageError> {
        match self.commit(batch) {
            CommitOutcome::Committed(receipt) => Ok(receipt),
            CommitOutcome::Rejected(error) => Err(error),
            CommitOutcome::Indeterminate => Err(StorageError::Unavailable),
        }
    }

    pub(crate) fn construction_counters(
        &self,
    ) -> Result<crate::ConstructionFinalizationCounters, StorageError> {
        Ok(crate::ConstructionFinalizationCounters {
            storage_commit_sequence: self
                .state_meta
                .tbs()
                .storage_commit_sequence
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
            manifest_sequence: self
                .state_meta
                .tbs()
                .manifest_sequence
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
            state_generation: self.state_meta.tbs().state_generation,
            account_service_response_count: self.state_meta.tbs().account_service_response_count,
            nonce_draw_high_water: self
                .reservation
                .tbs()
                .nonce_draw_high_water
                .checked_add(3)
                .ok_or(StorageError::Overflow)?,
        })
    }

    pub(crate) const fn construction_committed_counters(
        &self,
    ) -> crate::ConstructionFinalizationCounters {
        crate::ConstructionFinalizationCounters {
            storage_commit_sequence: self.state_meta.tbs().storage_commit_sequence,
            manifest_sequence: self.state_meta.tbs().manifest_sequence,
            state_generation: self.state_meta.tbs().state_generation,
            account_service_response_count: self.state_meta.tbs().account_service_response_count,
            nonce_draw_high_water: self.state_meta.tbs().nonce_draw_high_water,
        }
    }

    pub(crate) fn finish_construction(&mut self) -> Result<(), StorageError> {
        self.checkpoint_for_shutdown()
            .map_err(|error| match error {
                EngineCommitFailure::Rejected(error) => error,
                EngineCommitFailure::Indeterminate => StorageError::Unavailable,
            })?;
        self.startup_scan().map(|_| ())
    }

    pub(crate) fn commit(&mut self, batch: StorageMutationBatch) -> CommitOutcome {
        let outcome = match self.commit_inner(&batch) {
            Ok(receipt) => CommitOutcome::Committed(receipt),
            Err(EngineCommitFailure::Rejected(error)) => CommitOutcome::Rejected(error),
            Err(EngineCommitFailure::Indeterminate) => CommitOutcome::Indeterminate,
        };
        if matches!(outcome, CommitOutcome::Committed(_)) {
            self.publish_runtime_facts();
        }
        outcome
    }

    fn publish_runtime_facts(&self) {
        self.runtime_limits.publish_facts(
            self.state_meta.tbs().logical_database_bytes,
            self.state_meta.tbs().backup_stream_bytes,
            self.retained_manifest_count,
            self.retained_manifest_bytes,
        );
    }

    /// Reports whether retained manifests reached the configured or protocol ceiling.
    #[cfg(test)]
    pub(crate) fn checkpoint_due(&self) -> bool {
        checkpoint_is_due(
            StorageRuntimeLimits {
                database_max_bytes: self.limits.database_max_bytes,
                backup_max_bytes: self.limits.backup_max_bytes,
                integrity_checkpoint_manifests: self.limits.integrity_checkpoint_manifests,
            },
            self.retained_manifest_count,
            self.retained_manifest_bytes,
        )
    }

    pub(crate) fn checkpoint_cut_would_advance(&self) -> bool {
        self.state_meta.tbs().manifest_sequence
            != self.state_meta.tbs().checkpoint_manifest_sequence
    }

    pub(crate) fn checkpoint_is_active(&self) -> bool {
        self.checkpoint_job.is_some()
    }

    /// Drops a checkpoint job whose scan or installation was rejected before its transaction.
    ///
    /// A nonce block reserved for the installation stays reserved; the next commit or
    /// checkpoint burns it exactly as it would after a rejected commit.
    pub(crate) fn abandon_checkpoint(&mut self) {
        self.checkpoint_job = None;
        self.runtime_limits.finish_checkpoint();
    }

    pub(crate) fn runtime_limit_reservation_active(&self) -> bool {
        self.runtime_limits.has_reservation()
    }

    #[cfg(test)]
    pub(crate) fn replace_runtime_limit_reader(&mut self, reader: StorageLimitReader) {
        self.runtime_limits = reader;
        self.publish_runtime_facts();
    }

    /// Makes the next idle owner iteration start a checkpoint without ten thousand commits.
    #[cfg(test)]
    pub(crate) fn mark_checkpoint_due(&mut self) {
        self.retained_manifest_count = self.limits.integrity_checkpoint_manifests;
    }

    pub(crate) fn start_checkpoint(&mut self) -> Result<(), StorageError> {
        if self.checkpoint_job.is_some() || self.backup_job.is_some() {
            return Err(StorageError::QueueFull);
        }
        let limits = self.runtime_limits.begin_checkpoint()?;
        let started = (|| {
            let cut = *self.state_meta.tbs();
            let scan = self.store.snapshot_scan()?;
            self.checkpoint_job = Some(CheckpointJob::new(cut, scan, limits));
            Ok(())
        })();
        if started.is_err() {
            self.runtime_limits.finish_checkpoint();
        }
        started
    }

    pub(crate) fn service_checkpoint(
        &mut self,
    ) -> Result<Option<CheckpointReceipt>, EngineCommitFailure> {
        self.state_directory
            .faults()
            .check(
                StorageFaultSite::CheckpointScan,
                StorageFaultBoundary::Before,
            )
            .map_err(rejected)?;
        let Some(job) = self.checkpoint_job.as_mut() else {
            return Ok(None);
        };
        let completed = job
            .service(
                &self.master_key,
                self.binding,
                self.header.tbs().storage_key_generation,
            )
            .map_err(rejected)?;
        self.state_directory
            .faults()
            .check(
                StorageFaultSite::CheckpointScan,
                StorageFaultBoundary::After,
            )
            .map_err(rejected)?;
        let Some(completed) = completed else {
            return Ok(None);
        };
        self.checkpoint_job = None;
        match self.install_scanned_checkpoint(completed) {
            Ok(receipt) => {
                self.publish_runtime_facts();
                self.runtime_limits.finish_checkpoint();
                Ok(Some(receipt))
            }
            Err(EngineCommitFailure::Rejected(error)) => Err(EngineCommitFailure::Rejected(error)),
            Err(EngineCommitFailure::Indeterminate) => {
                self.runtime_limits.poison_checkpoint();
                Err(EngineCommitFailure::Indeterminate)
            }
        }
    }

    fn install_scanned_checkpoint(
        &mut self,
        completed: CompletedCheckpointScan,
    ) -> Result<CheckpointReceipt, EngineCommitFailure> {
        self.state_directory
            .faults()
            .check(
                StorageFaultSite::CheckpointInstall,
                StorageFaultBoundary::Before,
            )
            .map_err(rejected)?;
        self.verify_checkpoint_cut(&completed.cut)
            .map_err(rejected)?;
        // Every fallible resource the checkpoint's readback needs is spent here, before the
        // reservation guard, the transaction or the committed guard exist: the scratch that
        // reverses the current records to the cut is admitted slice by slice against the same
        // reserve the transaction is admitted against, and a refusal leaves nothing written.
        self.ensure_verified().map_err(readback_failure)?;
        let readback = self
            .readback_checkpoint_cut(&completed)
            .map_err(readback_failure)?;
        let _capacity = self
            .state_directory
            .admit_transaction(self.limits.fixed_reserve_bytes, self.limits.reserve_percent)
            .map_err(rejected)?;
        let mut allowance = self.operation_allowance(2).map_err(rejected)?;
        let installation = *self.state_meta.tbs();
        let previous_checkpoint_key = installation.checkpoint_manifest_sequence.to_be_bytes();
        let retired_charges = self
            .checkpoint_retired_charges(
                previous_checkpoint_key,
                completed.cut.manifest_sequence,
                completed.limits,
            )
            .map_err(rejected)?;
        let (reserved, reservation_charge) = self.reserve_nonce_block(2, allowance.allowance())?;
        let reserved_guard = self.install_reserved_guard(&reserved)?;
        self.reservation = reserved;
        self.guard = reserved_guard;
        allowance.charge(reservation_charge).map_err(rejected)?;
        let nonces = checkpoint_nonces(
            draw_nonces_with_faults(2, &self.state_directory.faults()).map_err(rejected)?,
        )
        .map_err(rejected)?;
        let prepared = self
            .prepare_checkpoint(&completed, installation, retired_charges, nonces)
            .map_err(rejected)?;
        self.commit_prepared_checkpoint(prepared, previous_checkpoint_key, allowance, readback)?;
        self.state_directory
            .faults()
            .check(
                StorageFaultSite::CheckpointInstall,
                StorageFaultBoundary::After,
            )
            .map_err(indeterminate)?;
        Ok(CheckpointReceipt {
            cut_manifest_sequence: completed.cut.manifest_sequence,
            installation_manifest_sequence: installation.manifest_sequence,
            storage_commit_sequence: self.state_meta.tbs().storage_commit_sequence,
            state_generation: self.state_meta.tbs().state_generation,
            account_service_response_count: self.state_meta.tbs().account_service_response_count,
            logical_database_bytes: self.state_meta.tbs().logical_database_bytes,
            backup_stream_bytes: self.state_meta.tbs().backup_stream_bytes,
            rollback_guard_hash: self.guard.complete_hash().map_err(indeterminate)?,
            readback_scratch: readback.scratch,
        })
    }

    /// Reads the cut back before anything is published: the current tracked records, reversed
    /// through every manifest after the cut, must reproduce the count and digest the scan
    /// recorded at the cut. The scratch is admitted and bounded slice by slice and is gone
    /// before this returns; only its metered usage is kept for the receipt.
    fn readback_checkpoint_cut(
        &self,
        completed: &CompletedCheckpointScan,
    ) -> Result<TrackedStateReconstruction, StorageError> {
        let head = self.state_meta.tbs().manifest_sequence;
        let replay = if completed.cut.manifest_sequence < head {
            Some(
                completed
                    .cut
                    .manifest_sequence
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?..=head,
            )
        } else {
            None
        };
        let reconstruction = self.reconstruct_tracked_state(replay)?;
        if (reconstruction.record_count, reconstruction.digest)
            != (
                completed.tracked_record_count,
                completed.tracked_state_digest,
            )
        {
            return Err(StorageError::StaleState);
        }
        Ok(reconstruction)
    }

    fn verify_checkpoint_cut(&self, cut: &StateMetaTbs) -> Result<(), StorageError> {
        if cut.manifest_sequence > self.state_meta.tbs().manifest_sequence
            || cut.checkpoint_manifest_sequence
                != self.state_meta.tbs().checkpoint_manifest_sequence
            || cut.checkpoint_hash != self.state_meta.tbs().checkpoint_hash
        {
            return Err(StorageError::StaleState);
        }
        if cut.manifest_sequence == 0 {
            if cut.latest_manifest_hash == StorageDigest::from_bytes([0; 32]) {
                return Ok(());
            }
            return Err(StorageError::StaleState);
        }
        let manifest = self.read_manifest(cut.manifest_sequence)?;
        if manifest.manifest_hash() == cut.latest_manifest_hash {
            Ok(())
        } else {
            Err(StorageError::StaleState)
        }
    }

    pub(crate) fn checkpoint_for_shutdown(&mut self) -> Result<(), EngineCommitFailure> {
        if !self.checkpoint_cut_would_advance() {
            return Ok(());
        }
        self.start_checkpoint().map_err(rejected)?;
        while self.checkpoint_is_active() {
            self.service_checkpoint()?;
        }
        Ok(())
    }

    fn prepare_checkpoint(
        &self,
        completed: &CompletedCheckpointScan,
        installation: StateMetaTbs,
        retired_charges: (u64, u64),
        nonces: [[u8; 24]; 2],
    ) -> Result<PreparedCheckpoint, StorageError> {
        let [checkpoint_nonce, state_meta_nonce] = nonces;
        let (checkpoint, checkpoint_key, checkpoint_record) = self.seal_checkpoint(
            completed.cut,
            installation,
            completed.tracked_record_count,
            completed.tracked_state_digest,
            checkpoint_nonce,
        )?;
        let (logical_database_bytes, backup_stream_bytes) = self.checkpoint_accounting(
            installation,
            &checkpoint_record,
            retired_charges,
            completed.limits,
        )?;
        let (state_meta, state_meta_record, state_meta_record_id) = self
            .seal_checkpoint_state_meta(
                installation,
                completed.cut.manifest_sequence,
                checkpoint.checkpoint_hash(),
                logical_database_bytes,
                backup_stream_bytes,
                state_meta_nonce,
            )?;
        let committed_reservation = self.checkpoint_committed_reservation(
            installation,
            state_meta.tbs().storage_commit_sequence,
            state_meta_record_id,
        )?;
        let committed_guard =
            guard_for_reservation(&self.header, &committed_reservation, &self.integrity_keys)?;
        Ok(PreparedCheckpoint {
            checkpoint_key,
            checkpoint_record,
            state_meta,
            state_meta_record,
            state_meta_record_id,
            committed_reservation,
            committed_guard,
        })
    }

    fn seal_checkpoint(
        &self,
        cut: StateMetaTbs,
        installation: StateMetaTbs,
        tracked_record_count: u64,
        tracked_state_digest: StorageDigest,
        nonce: [u8; 24],
    ) -> Result<(IntegrityCheckpoint, [u8; 8], Vec<u8>), StorageError> {
        let installation_storage_commit_sequence = installation
            .storage_commit_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let checkpoint = IntegrityCheckpoint::new(IntegrityCheckpointTbs {
            database_instance_id: self.header.tbs().database_instance_id,
            cut_storage_commit_sequence: cut.storage_commit_sequence,
            cut_manifest_sequence: cut.manifest_sequence,
            cut_state_generation: cut.state_generation,
            cut_account_service_response_count: cut.account_service_response_count,
            cut_nonce_draw_high_water: cut.nonce_draw_high_water,
            cut_manifest_hash: cut.latest_manifest_hash,
            tracked_record_count,
            tracked_state_digest,
            previous_checkpoint_hash: cut.checkpoint_hash,
            installation_storage_commit_sequence,
            installation_manifest_sequence: installation.manifest_sequence,
            installation_nonce_reservation_start: self.guard.tbs().nonce_reservation_start,
            installation_nonce_draw_high_water: self.guard.tbs().nonce_draw_high_water,
        })?;
        let checkpoint_key = cut.manifest_sequence.to_be_bytes();
        let seal_context = StorageSealContext::new(
            &self.master_key,
            self.binding,
            self.header.tbs().storage_key_generation,
        )?;
        let checkpoint_stored_key = StoredKey::new(checkpoint_key.to_vec())?;
        let checkpoint_record = seal_context
            .seal(
                TableId::IntegrityCheckpoint,
                1,
                nonce,
                &checkpoint_stored_key,
                &checkpoint.encode()?,
            )
            .and_then(|record| record.encode())?;
        Ok((checkpoint, checkpoint_key, checkpoint_record))
    }

    fn checkpoint_accounting(
        &self,
        cut: StateMetaTbs,
        checkpoint_record: &[u8],
        retired_charges: (u64, u64),
        limits: StorageRuntimeLimits,
    ) -> Result<(u64, u64), StorageError> {
        let new_checkpoint_logical =
            logical_record_charge(u64::BITS as usize / 8, checkpoint_record.len())?;
        let new_checkpoint_backup = backup_charge(new_checkpoint_logical)?;
        let logical_database_bytes = cut
            .logical_database_bytes
            .checked_add(new_checkpoint_logical)
            .and_then(|value| value.checked_sub(retired_charges.0))
            .ok_or(StorageError::Overflow)?;
        let backup_stream_bytes = cut
            .backup_stream_bytes
            .checked_add(new_checkpoint_backup)
            .and_then(|value| value.checked_sub(retired_charges.1))
            .ok_or(StorageError::Overflow)?;
        if logical_database_bytes > limits.database_max_bytes
            || backup_stream_bytes > limits.backup_max_bytes
        {
            return Err(StorageError::LimitExceeded);
        }
        Ok((logical_database_bytes, backup_stream_bytes))
    }

    fn seal_checkpoint_state_meta(
        &self,
        installation: StateMetaTbs,
        checkpoint_manifest_sequence: u64,
        checkpoint_hash: StorageDigest,
        logical_database_bytes: u64,
        backup_stream_bytes: u64,
        nonce: [u8; 24],
    ) -> Result<(StateMeta, Vec<u8>, StorageDigest), StorageError> {
        let state_meta = StateMeta::authenticate(
            StateMetaTbs {
                storage_commit_sequence: installation
                    .storage_commit_sequence
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?,
                manifest_sequence: installation.manifest_sequence,
                state_generation: installation.state_generation,
                account_service_response_count: installation.account_service_response_count,
                nonce_draw_high_water: self.guard.tbs().nonce_draw_high_water,
                logical_database_bytes,
                backup_stream_bytes,
                checkpoint_manifest_sequence,
                latest_manifest_hash: installation.latest_manifest_hash,
                checkpoint_hash,
                previous_rollback_guard_hash: self.guard.complete_hash()?,
            },
            self.header.complete_hash()?,
            &self.integrity_keys,
        )?;
        let seal_context = StorageSealContext::new(
            &self.master_key,
            self.binding,
            self.header.tbs().storage_key_generation,
        )?;
        let state_meta_key = StoredKey::new(STATE_META_KEY.to_vec())?;
        let state_meta_record = seal_context
            .seal(
                TableId::StateMeta,
                1,
                nonce,
                &state_meta_key,
                &state_meta.encode()?,
            )
            .and_then(|record| record.encode())?;
        let state_meta_record_id =
            SealedRecord::decode(&state_meta_record).and_then(|record| record.record_id())?;
        Ok((state_meta, state_meta_record, state_meta_record_id))
    }

    fn checkpoint_committed_reservation(
        &self,
        installation: StateMetaTbs,
        storage_commit_sequence: u64,
        state_meta_record_id: StorageDigest,
    ) -> Result<NonceReservationState, StorageError> {
        NonceReservationState::authenticate(
            NonceReservationTbs {
                database_instance_id: self.header.tbs().database_instance_id,
                reservation_sequence: self.reservation.tbs().reservation_sequence,
                phase: RollbackGuardPhase::Committed,
                nonce_reservation_start: self.reservation.tbs().nonce_draw_high_water,
                nonce_draw_high_water: self.reservation.tbs().nonce_draw_high_water,
                storage_commit_sequence,
                manifest_sequence: installation.manifest_sequence,
                state_generation: installation.state_generation,
                database_header_hash: self.header.complete_hash()?,
                state_meta_record_id,
                previous_guard_hash: self.guard.complete_hash()?,
            },
            &self.integrity_keys,
        )
    }

    fn commit_prepared_checkpoint(
        &mut self,
        prepared: PreparedCheckpoint,
        previous_checkpoint_key: [u8; 8],
        mut allowance: OperationAllowance,
        readback: TrackedStateReconstruction,
    ) -> Result<(), EngineCommitFailure> {
        self.state_directory
            .faults()
            .check(
                StorageFaultSite::CheckpointPrune,
                StorageFaultBoundary::Before,
            )
            .map_err(rejected)?;
        let committed_reservation_bytes =
            prepared.committed_reservation.encode().map_err(rejected)?;
        let charged = match self.store.commit_checkpoint(
            &prepared.checkpoint_key,
            &prepared.checkpoint_record,
            &previous_checkpoint_key,
            &prepared.state_meta_record,
            &committed_reservation_bytes,
            allowance.allowance(),
        ) {
            Ok(charged) => charged,
            Err(RedbCommitFailure::Rejected(error)) => return Err(rejected(error)),
            Err(RedbCommitFailure::Indeterminate) => {
                return Err(EngineCommitFailure::Indeterminate);
            }
        };
        self.state_directory
            .faults()
            .check(
                StorageFaultSite::CheckpointPrune,
                StorageFaultBoundary::After,
            )
            .map_err(indeterminate)?;
        self.state_directory
            .replace_guard(&prepared.committed_guard.encode().map_err(indeterminate)?)
            .map_err(indeterminate)?;
        self.state_meta = prepared.state_meta;
        self.state_meta_record_id = prepared.state_meta_record_id;
        self.reservation = prepared.committed_reservation;
        self.guard = prepared.committed_guard;
        let (retained_manifest_count, retained_manifest_bytes) = self
            .store
            .table_usage(TableId::IntegrityManifest, MAX_RETAINED_MANIFEST_BYTES)
            .map_err(indeterminate)?;
        self.retained_manifest_count = retained_manifest_count;
        self.retained_manifest_bytes = retained_manifest_bytes;
        allowance.charge(charged).map_err(indeterminate)?;
        self.finish_operation(allowance)?;
        // The published control chain is read back without any scratch: the record set was
        // proven against the cut before publication and no tracked table changed since. A
        // chain that does not reproduce that proof is a durable state this owner cannot vouch
        // for, exactly as before.
        let chain = self.verify_integrity_chain().map_err(indeterminate)?;
        if (chain.tracked_record_count, chain.tracked_state_digest)
            != (readback.record_count, readback.digest)
        {
            return Err(EngineCommitFailure::Indeterminate);
        }
        Ok(())
    }

    fn checkpoint_retired_charges(
        &self,
        active_checkpoint_key: [u8; 8],
        cut_manifest_sequence: u64,
        limits: StorageRuntimeLimits,
    ) -> Result<(u64, u64), StorageError> {
        let mut logical = 0_u64;
        let mut backup = 0_u64;
        let cut_manifest_key = cut_manifest_sequence.to_be_bytes();
        self.store.visit_table(
            TableId::IntegrityManifest,
            limits.database_max_bytes,
            |key, value| {
                if key <= cut_manifest_key.as_slice() {
                    add_retired_charge(&mut logical, &mut backup, key, value)
                } else {
                    Ok(())
                }
            },
        )?;
        self.store.visit_table(
            TableId::IntegrityCheckpoint,
            limits.database_max_bytes,
            |key, value| {
                if key == active_checkpoint_key {
                    Ok(())
                } else {
                    add_retired_charge(&mut logical, &mut backup, key, value)
                }
            },
        )?;
        Ok((logical, backup))
    }

    // agenc-review: focus owner=storage reviewed=2026-09-18 reason=linear immediate transaction transcript binds one physical allowance to reservation sealing database commit guard installation and deferred cleanup
    fn commit_inner(
        &mut self,
        batch: &StorageMutationBatch,
    ) -> Result<CommitReceipt, EngineCommitFailure> {
        if self.retained_manifest_count >= MAX_RETAINED_MANIFESTS
            || self.retained_manifest_bytes >= MAX_RETAINED_MANIFEST_BYTES
        {
            return Err(rejected(StorageError::LimitExceeded));
        }
        self.validate_batch_head(batch).map_err(rejected)?;
        if let Some(site) = batch.fault_site() {
            self.state_directory
                .faults()
                .check(site, StorageFaultBoundary::Before)
                .map_err(rejected)?;
        }
        self.ensure_verified().map_err(readback_failure)?;
        let _capacity = self
            .state_directory
            .admit_transaction(self.limits.fixed_reserve_bytes, self.limits.reserve_percent)
            .map_err(rejected)?;
        let mut allowance = self.operation_allowance(2).map_err(rejected)?;
        self.validate_existing_records(batch).map_err(rejected)?;
        let (reserved, reservation_charge) =
            self.reserve_nonce_block(batch.seal_count(), allowance.allowance())?;
        let reserved_guard = self.install_reserved_guard(&reserved)?;
        self.reservation = reserved;
        self.guard = reserved_guard;
        allowance.charge(reservation_charge).map_err(rejected)?;

        let nonces = draw_nonces_with_faults(batch.seal_count(), &self.state_directory.faults())
            .map_err(rejected)?;
        self.state_directory
            .faults()
            .check(StorageFaultSite::Manifest, StorageFaultBoundary::Before)
            .map_err(rejected)?;
        let prepared = self.prepare_application(batch, &nonces).map_err(rejected)?;
        verify_prepared_accounting(batch, &prepared).map_err(rejected)?;
        let manifest_row_bytes = u64::try_from(
            prepared
                .manifest_key
                .len()
                .checked_add(prepared.manifest_record.len())
                .ok_or(StorageError::Overflow)
                .map_err(rejected)?,
        )
        .map_err(|_| rejected(StorageError::Overflow))?;
        let resulting_manifest_count = self
            .retained_manifest_count
            .checked_add(1)
            .ok_or(StorageError::Overflow)
            .map_err(rejected)?;
        let resulting_manifest_bytes = self
            .retained_manifest_bytes
            .checked_add(manifest_row_bytes)
            .ok_or(StorageError::Overflow)
            .map_err(rejected)?;
        if resulting_manifest_bytes > MAX_RETAINED_MANIFEST_BYTES {
            return Err(rejected(StorageError::LimitExceeded));
        }
        let committed_reservation = self.committed_reservation(&prepared).map_err(rejected)?;
        let committed_guard =
            guard_for_reservation(&self.header, &committed_reservation, &self.integrity_keys)
                .map_err(rejected)?;
        let mut writes = prepared
            .records
            .iter()
            .map(|record| RedbWrite {
                table: record.table,
                key: record.key.as_bytes(),
                value: record.value.as_deref(),
            })
            .collect::<Vec<_>>();
        writes.push(RedbWrite {
            table: TableId::IntegrityManifest,
            key: &prepared.manifest_key,
            value: Some(&prepared.manifest_record),
        });
        writes.push(RedbWrite {
            table: TableId::StateMeta,
            key: STATE_META_KEY,
            value: Some(&prepared.state_meta_record),
        });
        let committed_reservation_bytes = committed_reservation.encode().map_err(rejected)?;
        let charged = match self.store.commit_records(
            &writes,
            &committed_reservation_bytes,
            allowance.allowance(),
        ) {
            Ok(charged) => charged,
            Err(RedbCommitFailure::Rejected(error)) => {
                return Err(EngineCommitFailure::Rejected(error));
            }
            Err(RedbCommitFailure::Indeterminate) => {
                return Err(EngineCommitFailure::Indeterminate);
            }
        };
        let committed_guard_bytes = committed_guard.encode().map_err(indeterminate)?;
        self.state_directory
            .replace_guard(&committed_guard_bytes)
            .map_err(indeterminate)?;
        let rollback_guard_hash = committed_guard.complete_hash().map_err(indeterminate)?;
        self.state_meta = prepared.state_meta;
        self.state_meta_record_id = prepared.state_meta_record_id;
        self.reservation = committed_reservation;
        self.guard = committed_guard;
        self.retained_manifest_count = resulting_manifest_count;
        self.retained_manifest_bytes = resulting_manifest_bytes;
        allowance.charge(charged).map_err(indeterminate)?;
        self.finish_operation(allowance)?;
        self.state_directory
            .faults()
            .check(StorageFaultSite::Manifest, StorageFaultBoundary::After)
            .map_err(indeterminate)?;
        if let Some(site) = batch.fault_site() {
            self.state_directory
                .faults()
                .check(site, StorageFaultBoundary::After)
                .map_err(indeterminate)?;
        }
        Ok(CommitReceipt {
            transaction_id: batch.transaction_id(),
            storage_commit_sequence: self.state_meta.tbs().storage_commit_sequence,
            state_generation: self.state_meta.tbs().state_generation,
            rollback_guard_hash,
        })
    }

    fn validate_batch_head(&self, batch: &StorageMutationBatch) -> Result<(), StorageError> {
        let state = self.state_meta.tbs();
        if batch.expected_storage_commit_sequence() != state.storage_commit_sequence
            || batch.expected_state_generation() != state.state_generation
            || batch.expected_account_service_response_count()
                != state.account_service_response_count
            || batch.expected_logical_database_bytes() != state.logical_database_bytes
            || batch.expected_backup_stream_bytes() != state.backup_stream_bytes
            || batch.resulting_logical_database_bytes() > self.limits.database_max_bytes
            || batch.resulting_backup_stream_bytes() > self.limits.backup_max_bytes
        {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    fn validate_existing_records(&self, batch: &StorageMutationBatch) -> Result<(), StorageError> {
        for mutation in batch.mutations() {
            let current = self
                .store
                .read_record(mutation.table(), mutation.key().as_bytes())?;
            match (mutation.before(), current) {
                (None, None) => {}
                (Some(expected), Some(encoded)) => verify_existing(expected, &encoded)?,
                _ => return Err(StorageError::StaleState),
            }
        }
        let next_manifest = self
            .state_meta
            .tbs()
            .manifest_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        if self
            .store
            .read_record(TableId::IntegrityManifest, &next_manifest.to_be_bytes())?
            .is_some()
        {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    /// Makes the next nonce-reservation record durable within `allowance` and returns it with
    /// the bytes its transaction charged; the caller records the burned block before debiting.
    fn reserve_nonce_block(
        &self,
        seal_count: u32,
        allowance: redb::AllocationAllowance,
    ) -> Result<(NonceReservationState, u64), EngineCommitFailure> {
        let previous_guard_hash = self.guard.complete_hash().map_err(rejected)?;
        let start = self.reservation.tbs().nonce_draw_high_water;
        let end = start
            .checked_add(u64::from(seal_count))
            .ok_or_else(|| rejected(StorageError::Overflow))?;
        let tbs = NonceReservationTbs {
            database_instance_id: self.header.tbs().database_instance_id,
            reservation_sequence: self
                .reservation
                .tbs()
                .reservation_sequence
                .checked_add(1)
                .ok_or_else(|| rejected(StorageError::Overflow))?,
            phase: RollbackGuardPhase::NonceReserved,
            nonce_reservation_start: start,
            nonce_draw_high_water: end,
            storage_commit_sequence: self.state_meta.tbs().storage_commit_sequence,
            manifest_sequence: self.state_meta.tbs().manifest_sequence,
            state_generation: self.state_meta.tbs().state_generation,
            database_header_hash: self.header.complete_hash().map_err(rejected)?,
            state_meta_record_id: self.state_meta_record_id,
            previous_guard_hash,
        };
        let reservation =
            NonceReservationState::authenticate(tbs, &self.integrity_keys).map_err(rejected)?;
        let bytes = reservation.encode().map_err(rejected)?;
        match self
            .store
            .write_meta(RESERVATION_META_KEY, &bytes, allowance)
        {
            Ok(charged) => Ok((reservation, charged)),
            Err(RedbCommitFailure::Rejected(error)) => Err(EngineCommitFailure::Rejected(error)),
            Err(RedbCommitFailure::Indeterminate) => Err(EngineCommitFailure::Indeterminate),
        }
    }

    /// Derives one durable operation's allowance from Section 19.3's `G`, with its guard
    /// replacements charged first and any qualification cap applied.
    fn operation_allowance(
        &self,
        guard_replacements: u64,
    ) -> Result<OperationAllowance, StorageError> {
        Ok(
            OperationAllowance::new(self.state_directory.block_size(), guard_replacements)?
                .capped(self.state_directory.faults().growth_cap()),
        )
    }

    /// Completes one durable operation after its committed guard is published: records the
    /// bytes it charged against `G` and runs its deferred cleanup with what remains.
    ///
    /// The operation is already durable here, so nothing determinate can be reported any more:
    /// a refused cleanup waits for a later operation, and an uncertain one is indeterminate.
    fn finish_operation(
        &mut self,
        allowance: OperationAllowance,
    ) -> Result<(), EngineCommitFailure> {
        self.last_operation_charged_bytes = allowance.charged();
        match self.store.reclaim_deferred(allowance.allowance()) {
            Ok(MaintenanceOutcome::Completed(progress)) => {
                self.cleanup.pending = progress.remaining;
                self.cleanup.reclaimed_pages = self
                    .cleanup
                    .reclaimed_pages
                    .saturating_add(u64::try_from(progress.pages).unwrap_or(u64::MAX));
                Ok(())
            }
            Ok(MaintenanceOutcome::Refused(_)) => {
                self.cleanup.pending = true;
                Ok(())
            }
            Err(_) => Err(EngineCommitFailure::Indeterminate),
        }
    }

    /// Reports whether the bounded close already ran for this engine.
    pub(crate) const fn close_handled(&self) -> bool {
        self.close_handled
    }

    /// Persists the allocator state within one admitted allowance and takes the close duty
    /// from the drop path, so that no database close allocates outside Section 19.3's `G`.
    ///
    /// Whatever the outcome, the next open repairs exactly as after a crash: a refused
    /// admission or allowance persists nothing, and a refused admission still hands the close
    /// an empty allowance so the drop path cannot run its own unmetered transaction. A database
    /// already latched by an earlier uncertain failure cannot persist either, and that failure
    /// was reported when it happened, so the close itself never fails a shutdown.
    ///
    /// A clean stop reclaims first. The persisting transaction frees the pages of the state it
    /// replaces and, being bounded, never reclaims them itself, so a close that only persisted
    /// grew an idle database by six pages at every open and close. The reclamation and the
    /// persistence each receive half of the close's one allowance, because the fork does not
    /// report what a reclamation charged. An owner stopped by an uncertain outcome only
    /// persists; its freed pages wait for the first operation after the restart.
    pub(crate) fn close_bounded(&mut self, reclaim: bool) {
        self.close_handled = true;
        let admitted = self
            .state_directory
            .admit_transaction(self.limits.fixed_reserve_bytes, self.limits.reserve_percent)
            .is_ok();
        let bytes = match self.operation_allowance(0) {
            Ok(allowance) if admitted => allowance.allowance().bytes(),
            _ => 0,
        };
        let half = redb::AllocationAllowance::new(bytes / 2);
        if reclaim {
            let _reclaimed = self.store.reclaim_deferred(half);
        }
        let _persisted = self.store.persist_for_close(half);
    }

    fn install_reserved_guard(
        &self,
        reservation: &NonceReservationState,
    ) -> Result<RollbackGuard, EngineCommitFailure> {
        let guard = guard_for_reservation(&self.header, reservation, &self.integrity_keys)
            .map_err(rejected)?;
        self.state_directory
            .replace_guard(&guard.encode().map_err(rejected)?)
            .map_err(indeterminate)?;
        let verified = RollbackGuard::decode_and_verify(
            &self
                .state_directory
                .read_guard(ROLLBACK_GUARD_BYTES)
                .map_err(indeterminate)?,
            &self.integrity_keys,
        )
        .map_err(indeterminate)?;
        verify_guard_pair(&self.header, reservation, &verified).map_err(indeterminate)?;
        Ok(verified)
    }

    fn prepare_application(
        &self,
        batch: &StorageMutationBatch,
        nonces: &[[u8; 24]],
    ) -> Result<PreparedApplication, StorageError> {
        if nonces.len()
            != usize::try_from(batch.seal_count()).map_err(|_| StorageError::Overflow)?
        {
            return Err(StorageError::InvalidEncoding);
        }
        let mut nonce_cursor = 0_usize;
        let seal_context = StorageSealContext::new(
            &self.master_key,
            self.binding,
            self.header.tbs().storage_key_generation,
        )?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(batch.mutations().len())
            .map_err(|_| StorageError::AllocationFailed)?;
        let mut integrity_mutations = Vec::new();
        integrity_mutations
            .try_reserve_exact(batch.mutations().len())
            .map_err(|_| StorageError::AllocationFailed)?;
        for mutation in batch.mutations() {
            let before = mutation
                .before()
                .map_or(IntegrityRecordVersion::Absent, |record| {
                    IntegrityRecordVersion::Present {
                        record_schema: record.record_schema(),
                        sealed_record_id: record.sealed_record_id(),
                    }
                });
            let value = if let Some(plaintext) = mutation.plaintext() {
                crate::validate_record_plaintext(
                    mutation.table(),
                    mutation.key(),
                    mutation.record_schema(),
                    plaintext,
                )?;
                let nonce = *nonces
                    .get(nonce_cursor)
                    .ok_or(StorageError::InvalidEncoding)?;
                nonce_cursor = nonce_cursor.checked_add(1).ok_or(StorageError::Overflow)?;
                Some(
                    seal_context
                        .seal(
                            mutation.table(),
                            mutation.record_schema(),
                            nonce,
                            mutation.key(),
                            plaintext,
                        )?
                        .encode()?,
                )
            } else {
                None
            };
            if mutation.table().is_integrity_tracked() {
                let after = match &value {
                    Some(encoded) => IntegrityRecordVersion::Present {
                        record_schema: mutation.record_schema(),
                        sealed_record_id: SealedRecord::decode(encoded)?.record_id()?,
                    },
                    None => IntegrityRecordVersion::Absent,
                };
                integrity_mutations.push(IntegrityRecordMutation::new(
                    mutation.table(),
                    StoredKey::new(mutation.key().as_bytes().to_vec())?,
                    before,
                    after,
                )?);
            }
            records.push(PreparedRecord {
                table: mutation.table(),
                key: StoredKey::new(mutation.key().as_bytes().to_vec())?,
                value,
            });
        }
        let manifest_sequence = self
            .state_meta
            .tbs()
            .manifest_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let storage_commit_sequence = self
            .state_meta
            .tbs()
            .storage_commit_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let manifest = IntegrityManifest::new(IntegrityManifestTbs::new(
            self.header.tbs().database_instance_id,
            manifest_sequence,
            storage_commit_sequence,
            self.state_meta.tbs().state_generation,
            batch.resulting_state_generation(),
            self.state_meta.tbs().account_service_response_count,
            batch.resulting_account_service_response_count(),
            self.state_meta.tbs().nonce_draw_high_water,
            self.guard.tbs().nonce_reservation_start,
            self.guard.tbs().nonce_draw_high_water,
            batch.seal_count(),
            self.state_meta.tbs().latest_manifest_hash,
            integrity_mutations,
        )?)?;
        let manifest_key = manifest_sequence.to_be_bytes();
        let manifest_nonce = *nonces
            .get(nonce_cursor)
            .ok_or(StorageError::InvalidEncoding)?;
        nonce_cursor = nonce_cursor.checked_add(1).ok_or(StorageError::Overflow)?;
        let manifest_record = seal_context
            .seal(
                TableId::IntegrityManifest,
                1,
                manifest_nonce,
                &StoredKey::new(manifest_key.to_vec())?,
                &manifest.encode()?,
            )?
            .encode()?;
        let state_meta = StateMeta::authenticate(
            StateMetaTbs {
                storage_commit_sequence,
                manifest_sequence,
                state_generation: batch.resulting_state_generation(),
                account_service_response_count: batch.resulting_account_service_response_count(),
                nonce_draw_high_water: self.guard.tbs().nonce_draw_high_water,
                logical_database_bytes: batch.resulting_logical_database_bytes(),
                backup_stream_bytes: batch.resulting_backup_stream_bytes(),
                checkpoint_manifest_sequence: self.state_meta.tbs().checkpoint_manifest_sequence,
                latest_manifest_hash: manifest.manifest_hash(),
                checkpoint_hash: self.state_meta.tbs().checkpoint_hash,
                previous_rollback_guard_hash: self.guard.complete_hash()?,
            },
            self.header.complete_hash()?,
            &self.integrity_keys,
        )?;
        let state_meta_nonce = *nonces
            .get(nonce_cursor)
            .ok_or(StorageError::InvalidEncoding)?;
        nonce_cursor = nonce_cursor.checked_add(1).ok_or(StorageError::Overflow)?;
        if nonce_cursor != nonces.len() {
            return Err(StorageError::InvalidEncoding);
        }
        let state_meta_record = seal_context
            .seal(
                TableId::StateMeta,
                1,
                state_meta_nonce,
                &StoredKey::new(STATE_META_KEY.to_vec())?,
                &state_meta.encode()?,
            )?
            .encode()?;
        let state_meta_record_id = SealedRecord::decode(&state_meta_record)?.record_id()?;
        Ok(PreparedApplication {
            records,
            manifest_key,
            manifest_record,
            state_meta_record,
            state_meta,
            state_meta_record_id,
        })
    }

    fn committed_reservation(
        &self,
        prepared: &PreparedApplication,
    ) -> Result<NonceReservationState, StorageError> {
        NonceReservationState::authenticate(
            NonceReservationTbs {
                database_instance_id: self.header.tbs().database_instance_id,
                reservation_sequence: self.reservation.tbs().reservation_sequence,
                phase: RollbackGuardPhase::Committed,
                nonce_reservation_start: self.reservation.tbs().nonce_draw_high_water,
                nonce_draw_high_water: self.reservation.tbs().nonce_draw_high_water,
                storage_commit_sequence: prepared.state_meta.tbs().storage_commit_sequence,
                manifest_sequence: prepared.state_meta.tbs().manifest_sequence,
                state_generation: prepared.state_meta.tbs().state_generation,
                database_header_hash: self.header.complete_hash()?,
                state_meta_record_id: prepared.state_meta_record_id,
                previous_guard_hash: self.guard.complete_hash()?,
            },
            &self.integrity_keys,
        )
    }

    // agenc-review: focus owner=storage reviewed=2026-08-27 reason=one canonical table walk shares global charge and singleton accumulators
    pub(crate) fn startup_scan(&self) -> Result<RecoveredStorageState, StorageError> {
        self.store.validate_inventory()?;
        self.store.validate_meta_membership()?;
        // Section 19.3: below the reserve durable mutation is disabled, the node is not. A
        // scratch the filesystem cannot admit never refuses the open of a writer: the control
        // chain and the complete domain scan below still run, the scratch half is owed, and
        // `ensure_verified` pays it before the first durable write is accepted. An inspection
        // has no later write to gate, so it is refused instead of skipping verification.
        let may_defer = self.state_directory.installs_repairable_guard();
        let mut deferred = false;
        let verification_scratch = match self.verify_integrity_ledger_metered() {
            Ok(usage) => usage,
            Err(error) if may_defer && scratch_unadmitted(error) => {
                deferred = true;
                ScratchUsage::default()
            }
            Err(error) => return Err(error),
        };
        let gate = self.scratch_gate();
        let mut reference_scratch = if deferred {
            None
        } else {
            match ReferenceScratch::create(self.state_directory.scratch_location()?, &gate) {
                Ok(scratch) => Some(scratch),
                Err(error) if may_defer && scratch_unadmitted(error) => {
                    deferred = true;
                    None
                }
                Err(error) => return Err(error),
            }
        };
        let mut reference_writer = reference_scratch.as_mut().map(ReferenceScratch::begin);
        let mut logical_bytes =
            logical_meta_charge(HEADER_META_KEY.len(), crate::DATABASE_HEADER_BYTES)?
                .checked_add(logical_meta_charge(
                    RESERVATION_META_KEY.len(),
                    crate::NONCE_RESERVATION_BYTES,
                )?)
                .ok_or(StorageError::Overflow)?;
        let mut backup_bytes = BACKUP_FIXED_STREAM_BYTES;
        let mut key_check_count = 0_u64;
        let mut state_meta_count = 0_u64;
        let mut login_key_state_count = 0_u64;
        let mut construction_count = 0_u64;
        let login_key_state = self.read_login_index_key_state()?;
        login_key_state.validate_configured_keys(
            self.header.tbs().network_id,
            &self.login_index_key,
            self.previous_login_index_key.as_ref(),
        )?;
        let current_login_generation = login_key_state.current_generation();
        let previous_login_generation = login_key_state.previous();
        let mut previous_login_entries = 0_u64;
        let mut table_record_counts = [0_u64; 27];
        let mut maximum_record_revision = 0_u64;
        let mut history_inventory =
            crate::history_records::HistoryInventory::new(self.limits.database_max_bytes / 4);
        for number in 0_u16..=26 {
            let table = TableId::from_u16(number)?;
            self.store
                .visit_table(table, self.limits.database_max_bytes, |key, encoded| {
                    let stored_key = StoredKey::new(key.to_vec())?;
                    let sealed = SealedRecord::decode(encoded)?;
                    let plaintext = sealed.open(
                        &self.master_key,
                        self.binding,
                        table,
                        sealed.record_schema(),
                        self.header.tbs().storage_key_generation,
                        &stored_key,
                    )?;
                    crate::validate_record_plaintext(
                        table,
                        &stored_key,
                        sealed.record_schema(),
                        plaintext.expose_for_storage_codec(),
                    )?;
                    history_inventory.observe(
                        table,
                        &stored_key,
                        encoded.len(),
                        plaintext.expose_for_storage_codec(),
                    )?;
                    let count = table_record_counts
                        .get_mut(usize::from(table.as_u16()))
                        .ok_or(StorageError::InvalidEncoding)?;
                    *count = count.checked_add(1).ok_or(StorageError::Overflow)?;
                    if crate::table_schema(table).codec() == crate::RecordCodecKind::Domain {
                        let value = crate::PersistentRecordValue::decode(
                            table,
                            plaintext.expose_for_storage_codec(),
                        )?;
                        validate_recovered_domain_record(table, &value)?;
                        self.validate_recovered_index_binding(table, &stored_key, &value)?;
                        maximum_record_revision = maximum_record_revision.max(value.revision());
                    }
                    if table.is_integrity_tracked() {
                        let references = record_references(
                            table,
                            &stored_key,
                            plaintext.expose_for_storage_codec(),
                        )?;
                        let inserted = reference_writer.as_mut().map_or(Ok(()), |writer| {
                            writer.insert(table, &stored_key, &references)
                        });
                        match inserted {
                            Ok(()) => {}
                            Err(error) if may_defer && scratch_unadmitted(error) => {
                                reference_writer = None;
                                deferred = true;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    logical_bytes = logical_bytes
                        .checked_add(logical_record_charge(key.len(), encoded.len())?)
                        .ok_or(StorageError::Overflow)?;
                    backup_bytes = backup_bytes
                        .checked_add(
                            logical_record_charge(key.len(), encoded.len())?
                                .checked_add(8)
                                .ok_or(StorageError::Overflow)?,
                        )
                        .ok_or(StorageError::Overflow)?;
                    match table {
                        TableId::KeyCheck => {
                            key_check_count = key_check_count
                                .checked_add(1)
                                .ok_or(StorageError::Overflow)?;
                        }
                        TableId::StateMeta => {
                            state_meta_count = state_meta_count
                                .checked_add(1)
                                .ok_or(StorageError::Overflow)?;
                        }
                        TableId::IntegrityManifest => {
                            let _manifest =
                                IntegrityManifest::decode(plaintext.expose_for_storage_codec())?;
                        }
                        TableId::IntegrityCheckpoint => {
                            let _checkpoint =
                                IntegrityCheckpoint::decode(plaintext.expose_for_storage_codec())?;
                        }
                        TableId::LoginIndex => {
                            let login_key = LoginIndexStoredKey::decode(key)?;
                            if login_key.generation() != current_login_generation {
                                if previous_login_generation.is_some_and(|(generation, _)| {
                                    generation == login_key.generation()
                                }) {
                                    previous_login_entries = previous_login_entries
                                        .checked_add(1)
                                        .ok_or(StorageError::Overflow)?;
                                } else {
                                    return Err(StorageError::StaleState);
                                }
                            }
                            let _value = crate::LoginIndexValue::decode(
                                plaintext.expose_for_storage_codec(),
                                &login_key,
                            )?;
                        }
                        TableId::LoginIndexKeyState => {
                            login_key_state_count = login_key_state_count
                                .checked_add(1)
                                .ok_or(StorageError::Overflow)?;
                            let _key_state =
                                LoginIndexKeyState::decode(plaintext.expose_for_storage_codec())?;
                        }
                        TableId::StorageConstruction => {
                            construction_count = construction_count
                                .checked_add(1)
                                .ok_or(StorageError::Overflow)?;
                            let _marker =
                                StorageConstruction::decode(plaintext.expose_for_storage_codec())?;
                        }
                        TableId::StorageOperation => {
                            let _operation = StorageOperationCompletion::decode(
                                plaintext.expose_for_storage_codec(),
                            )?;
                        }
                        _ => {}
                    }
                    Ok(())
                })?;
        }
        history_inventory.finish()?;
        match reference_writer
            .take()
            .map_or(Ok(()), |writer| writer.finish())
        {
            Ok(()) => {}
            Err(error) if may_defer && scratch_unadmitted(error) => deferred = true,
            Err(error) => return Err(error),
        }
        let reference_scratch = match reference_scratch {
            Some(scratch) if !deferred => {
                scratch.validate()?;
                scratch.close()
            }
            _ => ScratchUsage::default(),
        };
        if deferred {
            self.verification_deferred.store(true, Ordering::Release);
        }
        let expected_previous_login_entries =
            previous_login_generation.map_or(0, |(_, count)| count);
        if (
            key_check_count,
            state_meta_count,
            login_key_state_count,
            construction_count,
            previous_login_entries,
            logical_bytes,
            backup_bytes,
        ) != (
            1,
            1,
            1,
            0,
            expected_previous_login_entries,
            self.state_meta.tbs().logical_database_bytes,
            self.state_meta.tbs().backup_stream_bytes,
        ) {
            return Err(StorageError::StaleState);
        }
        let capacity = self
            .state_directory
            .capacity(self.limits.fixed_reserve_bytes, self.limits.reserve_percent)?;
        Ok(RecoveredStorageState {
            table_record_counts,
            state_generation: self.state_meta.tbs().state_generation,
            account_service_response_count: self.state_meta.tbs().account_service_response_count,
            storage_commit_sequence: self.state_meta.tbs().storage_commit_sequence,
            manifest_sequence: self.state_meta.tbs().manifest_sequence,
            nonce_draw_high_water: self.state_meta.tbs().nonce_draw_high_water,
            maximum_record_revision,
            logical_database_bytes: self.state_meta.tbs().logical_database_bytes,
            backup_stream_bytes: self.state_meta.tbs().backup_stream_bytes,
            database_binding: self.binding,
            storage_key_generation: self.header.tbs().storage_key_generation,
            recovery_epoch: self.header.tbs().recovery_epoch,
            capacity,
            database_repaired: self.store.opened_after_repair(),
            verification_scratch,
            reference_scratch,
        })
    }

    fn validate_recovered_index_binding(
        &self,
        table: TableId,
        stored_key: &StoredKey,
        value: &crate::PersistentRecordValue,
    ) -> Result<(), StorageError> {
        let semantic_key = match (table, value.record_kind()) {
            (TableId::NicknameReservation, 1) => Nickname::parse(
                std::str::from_utf8(value.body()).map_err(|_| StorageError::InvalidEncoding)?,
            )
            .map_err(|_| StorageError::InvalidEncoding)?
            .canonical()
            .as_bytes()
            .to_vec(),
            (TableId::ChannelName, 1) => ChannelNameRecordBody::decode(value.body())?
                .name
                .canonical()
                .as_bytes()
                .to_vec(),
            _ => return Ok(()),
        };
        let expected = derive_storage_index(
            &self.master_key,
            self.binding,
            StorageTable::new(table.as_u16())?,
            self.header.tbs().storage_key_generation,
            &semantic_key,
        )?;
        if bool::from(
            expected
                .expose_for_storage_key()
                .ct_eq(stored_key.as_bytes()),
        ) {
            Ok(())
        } else {
            Err(StorageError::AuthenticationFailed)
        }
    }

    // agenc-review: focus owner=storage reviewed=2026-08-28 reason=canonical construction scan validates every target table with shared exact charge and singleton accumulators
    pub(crate) fn construction_scan(&self) -> Result<StorageConstruction, StorageError> {
        self.store.validate_inventory()?;
        self.store.validate_meta_membership()?;
        self.verify_integrity_ledger()?;
        let mut logical_bytes =
            logical_meta_charge(HEADER_META_KEY.len(), crate::DATABASE_HEADER_BYTES)?
                .checked_add(logical_meta_charge(
                    RESERVATION_META_KEY.len(),
                    crate::NONCE_RESERVATION_BYTES,
                )?)
                .ok_or(StorageError::Overflow)?;
        let mut backup_bytes = BACKUP_FIXED_STREAM_BYTES;
        let mut key_check_count = 0_u8;
        let mut state_meta_count = 0_u8;
        let mut login_key_state_count = 0_u8;
        let mut marker = None;
        for number in 0_u16..=26 {
            let table = TableId::from_u16(number)?;
            self.store
                .visit_table(table, self.limits.database_max_bytes, |key, encoded| {
                    let stored_key = StoredKey::new(key.to_vec())?;
                    let sealed = crate::validate_sealed_record(table, &stored_key, encoded)?;
                    let plaintext = sealed.open(
                        &self.master_key,
                        self.binding,
                        table,
                        sealed.record_schema(),
                        self.header.tbs().storage_key_generation,
                        &stored_key,
                    )?;
                    crate::validate_record_plaintext(
                        table,
                        &stored_key,
                        sealed.record_schema(),
                        plaintext.expose_for_storage_codec(),
                    )?;
                    let charge = logical_record_charge(key.len(), encoded.len())?;
                    logical_bytes = logical_bytes
                        .checked_add(charge)
                        .ok_or(StorageError::Overflow)?;
                    backup_bytes = backup_bytes
                        .checked_add(charge.checked_add(8).ok_or(StorageError::Overflow)?)
                        .ok_or(StorageError::Overflow)?;
                    match table {
                        TableId::KeyCheck => {
                            key_check_count = key_check_count
                                .checked_add(1)
                                .ok_or(StorageError::Overflow)?;
                        }
                        TableId::StateMeta => {
                            state_meta_count = state_meta_count
                                .checked_add(1)
                                .ok_or(StorageError::Overflow)?;
                        }
                        TableId::LoginIndexKeyState => {
                            login_key_state_count = login_key_state_count
                                .checked_add(1)
                                .ok_or(StorageError::Overflow)?;
                            LoginIndexKeyState::decode(plaintext.expose_for_storage_codec())?
                                .validate_configured_keys(
                                    self.header.tbs().network_id,
                                    &self.login_index_key,
                                    self.previous_login_index_key.as_ref(),
                                )?;
                        }
                        TableId::StorageConstruction => {
                            marker = Some(StorageConstruction::decode(
                                plaintext.expose_for_storage_codec(),
                            )?);
                        }
                        TableId::StorageOperation => {
                            let _operation = StorageOperationCompletion::decode(
                                plaintext.expose_for_storage_codec(),
                            )?;
                        }
                        _ => {}
                    }
                    Ok(())
                })?;
        }
        if (
            key_check_count,
            state_meta_count,
            login_key_state_count > 1,
            logical_bytes,
            backup_bytes,
        ) != (
            1,
            1,
            false,
            self.state_meta.tbs().logical_database_bytes,
            self.state_meta.tbs().backup_stream_bytes,
        ) {
            return Err(StorageError::StaleState);
        }
        let marker = marker.ok_or(StorageError::StaleState)?;
        if (
            marker.identity.target_database_header_hash,
            marker.identity.target_database_instance_id,
            marker.identity.target_schema_generation,
        ) != (
            self.header.complete_hash()?,
            self.header.tbs().database_instance_id,
            self.header.tbs().schema_generation,
        ) {
            return Err(StorageError::ResumeMismatch);
        }
        Ok(marker)
    }

    fn read_login_index_key_state(&self) -> Result<LoginIndexKeyState, StorageError> {
        let key = StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
        let encoded = self
            .store
            .read_record(TableId::LoginIndexKeyState, key.as_bytes())?
            .ok_or(StorageError::InvalidEncoding)?;
        let sealed = SealedRecord::decode(&encoded)?;
        let plaintext = sealed.open(
            &self.master_key,
            self.binding,
            TableId::LoginIndexKeyState,
            1,
            self.header.tbs().storage_key_generation,
            &key,
        )?;
        LoginIndexKeyState::decode(plaintext.expose_for_storage_codec())
    }

    /// Verifies the complete ledger: the control chain, then the tracked record set
    /// reconstructed in bounded scratch back to the checkpoint cut.
    fn verify_integrity_ledger(&self) -> Result<(), StorageError> {
        self.verify_integrity_ledger_metered().map(|_usage| ())
    }

    /// Whether the scratch half of the startup verification is still owed.
    pub(crate) fn verification_is_deferred(&self) -> bool {
        self.verification_deferred.load(Ordering::Acquire)
    }

    /// Pays a deferred startup verification before a durable write is accepted: the bounded
    /// ledger reconstruction and the complete reference validation, exactly what the open would
    /// have run. While the filesystem still cannot admit the scratch this refuses with the same
    /// capacity rejection the write itself would get; a verification that fails is the fatal
    /// ledger mismatch it would have been at startup. Nothing is ever written on unverified
    /// state and nothing is skipped.
    fn ensure_verified(&self) -> Result<(), StorageError> {
        if !self.verification_is_deferred() {
            return Ok(());
        }
        let _ledger = self.verify_integrity_ledger_metered()?;
        let _references = self.verify_references()?;
        self.verification_deferred.store(false, Ordering::Release);
        Ok(())
    }

    /// Validates every record reference in a bounded scratch of its own, as the startup scan
    /// does while it walks the tables.
    fn verify_references(&self) -> Result<ScratchUsage, StorageError> {
        let gate = self.scratch_gate();
        let mut scratch =
            ReferenceScratch::create(self.state_directory.scratch_location()?, &gate)?;
        let mut writer = scratch.begin();
        for number in 0_u16..=26 {
            let table = TableId::from_u16(number)?;
            if !table.is_integrity_tracked() {
                continue;
            }
            self.store
                .visit_table(table, self.limits.database_max_bytes, |key, encoded| {
                    let stored_key = StoredKey::new(key.to_vec())?;
                    let sealed = SealedRecord::decode(encoded)?;
                    let plaintext = sealed.open(
                        &self.master_key,
                        self.binding,
                        table,
                        sealed.record_schema(),
                        self.header.tbs().storage_key_generation,
                        &stored_key,
                    )?;
                    let references = record_references(
                        table,
                        &stored_key,
                        plaintext.expose_for_storage_codec(),
                    )?;
                    writer.insert(table, &stored_key, &references)
                })?;
        }
        writer.finish()?;
        scratch.validate()?;
        Ok(scratch.close())
    }

    /// Verifies the complete ledger and reports the metered scratch its reconstruction used.
    fn verify_integrity_ledger_metered(&self) -> Result<ScratchUsage, StorageError> {
        let chain = self.verify_integrity_chain()?;
        let reconstruction = self.reconstruct_tracked_state(chain.replay)?;
        if (reconstruction.record_count, reconstruction.digest)
            != (chain.tracked_record_count, chain.tracked_state_digest)
        {
            return Err(StorageError::StaleState);
        }
        Ok(reconstruction.scratch)
    }

    /// The gate every scratch transaction of this engine passes: the state filesystem sampled
    /// afresh against the configured reserve plus the transaction's allowance.
    fn scratch_gate(&self) -> ScratchGate<'_> {
        ScratchGate {
            directory: &self.state_directory,
            fixed_reserve_bytes: self.limits.fixed_reserve_bytes,
            reserve_percent: self.limits.reserve_percent,
        }
    }

    /// Rebuilds the tracked record set in bounded scratch: every current tracked row in
    /// admitted slices, then every manifest of `replay` reversed newest first, then the
    /// canonical count and digest. The scratch is removed before this returns; nothing of it
    /// is trusted afterwards except the count, the digest and the metered usage.
    fn reconstruct_tracked_state(
        &self,
        replay: Option<std::ops::RangeInclusive<u64>>,
    ) -> Result<TrackedStateReconstruction, StorageError> {
        let gate = self.scratch_gate();
        let mut scratch = RecoveryScratch::create(self.state_directory.scratch_location()?, &gate)?;
        self.index_current_tracked_records(&mut scratch)?;
        if let Some(replay) = replay {
            for sequence in replay.rev() {
                let manifest = self.read_manifest(sequence)?;
                scratch.apply_reverse(manifest.tbs().mutations())?;
            }
        }
        let (record_count, digest) = scratch.digest()?;
        Ok(TrackedStateReconstruction {
            record_count,
            digest,
            scratch: scratch.close(),
        })
    }

    /// Indexes every current tracked row: table by table in canonical order, published in
    /// bounded slices as the writer fills.
    fn index_current_tracked_records(
        &self,
        scratch: &mut RecoveryScratch<'_>,
    ) -> Result<(), StorageError> {
        let mut writer = scratch.begin_current();
        for number in 0_u16..=26 {
            let table = TableId::from_u16(number)?;
            if !table.is_integrity_tracked() {
                continue;
            }
            self.store
                .visit_table(table, self.limits.database_max_bytes, |key, encoded| {
                    let stored_key = StoredKey::new(key.to_vec())?;
                    let sealed = SealedRecord::decode(encoded)?;
                    writer.insert_current(
                        table,
                        &stored_key,
                        sealed.record_schema(),
                        sealed.record_id()?,
                    )
                })?;
        }
        writer.finish()
    }

    // agenc-review: focus owner=storage reviewed=2026-09-18 reason=checkpoint-to-head control chain keeps its accumulators in one auditable scope; the record set is reconstructed separately in bounded scratch
    fn verify_integrity_chain(&self) -> Result<LedgerChain, StorageError> {
        let state = self.state_meta.tbs();
        let checkpoint_key =
            StoredKey::new(state.checkpoint_manifest_sequence.to_be_bytes().to_vec())?;
        let checkpoint_encoded = self
            .store
            .read_record(TableId::IntegrityCheckpoint, checkpoint_key.as_bytes())?
            .ok_or(StorageError::InvalidEncoding)?;
        let checkpoint_sealed = SealedRecord::decode(&checkpoint_encoded)?;
        let checkpoint_plaintext = checkpoint_sealed.open(
            &self.master_key,
            self.binding,
            TableId::IntegrityCheckpoint,
            1,
            self.header.tbs().storage_key_generation,
            &checkpoint_key,
        )?;
        let checkpoint =
            IntegrityCheckpoint::decode(checkpoint_plaintext.expose_for_storage_codec())?;
        if (
            checkpoint.checkpoint_hash(),
            checkpoint.tbs().cut_manifest_sequence,
            checkpoint.tbs().cut_manifest_sequence > state.manifest_sequence,
            checkpoint.tbs().installation_manifest_sequence > state.manifest_sequence,
        ) != (
            state.checkpoint_hash,
            state.checkpoint_manifest_sequence,
            false,
            false,
        ) {
            return Err(StorageError::StaleState);
        }
        let zero = StorageDigest::from_bytes([0_u8; 32]);
        let genesis = (
            checkpoint.tbs().cut_manifest_sequence,
            checkpoint.tbs().installation_manifest_sequence,
            checkpoint.tbs().cut_storage_commit_sequence,
            checkpoint.tbs().installation_storage_commit_sequence,
        ) == (0, 0, 0, 0);
        if genesis {
            let expected_high_water = checkpoint
                .tbs()
                .tracked_record_count
                .checked_add(3)
                .ok_or(StorageError::Overflow)?;
            if (
                checkpoint.tbs().previous_checkpoint_hash,
                checkpoint.tbs().cut_manifest_hash,
                checkpoint.tbs().cut_nonce_draw_high_water,
                checkpoint.tbs().installation_nonce_draw_high_water,
            ) != (zero, zero, expected_high_water, expected_high_water)
            {
                return Err(StorageError::StaleState);
            }
        } else if (
            checkpoint.tbs().cut_manifest_sequence == 0,
            checkpoint.tbs().installation_storage_commit_sequence == 0,
            checkpoint.tbs().previous_checkpoint_hash == zero,
        ) != (false, false, false)
        {
            return Err(StorageError::StaleState);
        }
        let mut checkpoint_count = 0_u64;
        self.store.visit_table(
            TableId::IntegrityCheckpoint,
            self.limits.database_max_bytes,
            |_key, _value| {
                checkpoint_count = checkpoint_count
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?;
                if checkpoint_count > 2 {
                    return Err(StorageError::LimitExceeded);
                }
                Ok(())
            },
        )?;
        let expected_manifest_count = state
            .manifest_sequence
            .checked_sub(state.checkpoint_manifest_sequence)
            .ok_or(StorageError::StaleState)?;
        if expected_manifest_count > MAX_RETAINED_MANIFESTS {
            return Err(StorageError::LimitExceeded);
        }
        let mut actual_manifest_count = 0_u64;
        self.store.visit_table(
            TableId::IntegrityManifest,
            MAX_RETAINED_MANIFEST_BYTES,
            |_key, _value| {
                actual_manifest_count = actual_manifest_count
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?;
                Ok(())
            },
        )?;
        if actual_manifest_count != expected_manifest_count {
            return Err(StorageError::StaleState);
        }
        let mut previous_hash = checkpoint.tbs().cut_manifest_hash;
        let mut last_state_generation = checkpoint.tbs().cut_state_generation;
        let mut last_response_count = checkpoint.tbs().cut_account_service_response_count;
        let mut last_storage_commit = checkpoint.tbs().cut_storage_commit_sequence;
        let mut last_nonce_high_water = checkpoint.tbs().cut_nonce_draw_high_water;
        let mut checkpoint_installation_applied = genesis;
        if (
            genesis,
            checkpoint.tbs().installation_manifest_sequence
                == checkpoint.tbs().cut_manifest_sequence,
        ) == (false, true)
        {
            apply_checkpoint_installation(
                checkpoint.tbs(),
                &mut last_storage_commit,
                &mut last_nonce_high_water,
            )?;
            checkpoint_installation_applied = true;
        }
        let first_manifest = if expected_manifest_count == 0 {
            None
        } else {
            Some(
                state
                    .checkpoint_manifest_sequence
                    .checked_add(1)
                    .ok_or(StorageError::Overflow)?,
            )
        };
        if let Some(first_manifest) = first_manifest {
            for sequence in first_manifest..=state.manifest_sequence {
                let manifest = self.read_manifest(sequence)?;
                let fields = manifest.tbs();
                if fields.database_instance_id != self.header.tbs().database_instance_id
                    || fields.manifest_sequence != sequence
                    || fields.previous_manifest_hash != previous_hash
                    || fields.previous_state_generation != last_state_generation
                    || fields.previous_account_service_response_count != last_response_count
                    || fields.storage_commit_sequence
                        != last_storage_commit
                            .checked_add(1)
                            .ok_or(StorageError::Overflow)?
                    || fields.previous_nonce_draw_high_water != last_nonce_high_water
                    || fields.resulting_state_generation < fields.previous_state_generation
                    || fields
                        .resulting_state_generation
                        .checked_sub(fields.previous_state_generation)
                        .ok_or(StorageError::Overflow)?
                        > u64::try_from(crate::MAX_TRANSACTION_PLANS)
                            .map_err(|_| StorageError::Overflow)?
                    || fields.resulting_account_service_response_count
                        < fields.previous_account_service_response_count
                {
                    return Err(StorageError::StaleState);
                }
                previous_hash = manifest.manifest_hash();
                last_state_generation = fields.resulting_state_generation;
                last_response_count = fields.resulting_account_service_response_count;
                last_storage_commit = fields.storage_commit_sequence;
                last_nonce_high_water = fields.resulting_nonce_draw_high_water;
                if sequence == checkpoint.tbs().installation_manifest_sequence {
                    if checkpoint_installation_applied {
                        return Err(StorageError::StaleState);
                    }
                    apply_checkpoint_installation(
                        checkpoint.tbs(),
                        &mut last_storage_commit,
                        &mut last_nonce_high_water,
                    )?;
                    checkpoint_installation_applied = true;
                }
            }
        }
        if (
            previous_hash,
            last_state_generation,
            last_response_count,
            last_storage_commit,
            last_nonce_high_water,
            checkpoint_installation_applied,
        ) != (
            state.latest_manifest_hash,
            state.state_generation,
            state.account_service_response_count,
            state.storage_commit_sequence,
            state.nonce_draw_high_water,
            true,
        ) {
            return Err(StorageError::StaleState);
        }
        Ok(LedgerChain {
            tracked_record_count: checkpoint.tbs().tracked_record_count,
            tracked_state_digest: checkpoint.tbs().tracked_state_digest,
            replay: first_manifest.map(|first| first..=state.manifest_sequence),
        })
    }

    fn read_manifest(&self, sequence: u64) -> Result<IntegrityManifest, StorageError> {
        let key = StoredKey::new(sequence.to_be_bytes().to_vec())?;
        let encoded = self
            .store
            .read_record(TableId::IntegrityManifest, key.as_bytes())?
            .ok_or(StorageError::InvalidEncoding)?;
        let sealed = SealedRecord::decode(&encoded)?;
        let plaintext = sealed.open(
            &self.master_key,
            self.binding,
            TableId::IntegrityManifest,
            1,
            self.header.tbs().storage_key_generation,
            &key,
        )?;
        IntegrityManifest::decode(plaintext.expose_for_storage_codec())
    }
}

fn record_references(
    table: TableId,
    stored_key: &StoredKey,
    plaintext: &[u8],
) -> Result<Vec<RecordReference>, StorageError> {
    if table == TableId::LoginIndex {
        let login_key = LoginIndexStoredKey::decode(stored_key.as_bytes())?;
        let value = crate::LoginIndexValue::decode(plaintext, &login_key)?;
        return match value.kind() {
            LoginIndexValueKind::Live { account_id, .. } => Ok(vec![
                RecordReference::new(
                    TableId::Account,
                    StoredKey::new(account_id.to_text().as_bytes().to_vec())?,
                )?,
                RecordReference::new(
                    TableId::OpaqueRecord,
                    StoredKey::new(account_id.to_text().as_bytes().to_vec())?,
                )?,
            ]),
            LoginIndexValueKind::CreationReservation { transaction_id, .. } => {
                Ok(vec![RecordReference::new(
                    TableId::AuthTransaction,
                    StoredKey::new(transaction_id.as_bytes().to_vec())?,
                )?])
            }
            LoginIndexValueKind::DeletionTombstone {
                deleted_account_id, ..
            } => Ok(vec![RecordReference::new(
                TableId::Account,
                StoredKey::new(deleted_account_id.to_text().as_bytes().to_vec())?,
            )?]),
        };
    }
    if crate::table_schema(table).codec() == crate::RecordCodecKind::Domain {
        return Ok(crate::PersistentRecordValue::decode(table, plaintext)?
            .references()
            .to_vec());
    }
    Ok(Vec::new())
}

fn validate_recovered_domain_record(
    table: TableId,
    value: &crate::PersistentRecordValue,
) -> Result<(), StorageError> {
    if (
        value.table() != table,
        value
            .references()
            .iter()
            .any(|reference| !reference_is_legal(table, reference.table())),
    ) != (false, false)
    {
        return Err(StorageError::StaleState);
    }
    let required_reference = match (table, value.record_kind()) {
        (TableId::NicknameReservation, 1) => Some(TableId::Account),
        (TableId::ChannelName, 1) => Some(TableId::Channel),
        _ => None,
    };
    if let Some(required) = required_reference {
        let matching_count = value
            .references()
            .iter()
            .filter(|reference| reference.table() == required)
            .count();
        if matching_count != 1 {
            return Err(StorageError::StaleState);
        }
    }
    let tombstone_references_valid = match (table, value.record_kind()) {
        (TableId::Account | TableId::Session, 2) => value.references().is_empty(),
        (TableId::RegistrationInvite, 2) => matches!(
            value.references(),
            [reference] if reference.table() == TableId::Account
        ),
        _ => true,
    };
    if !tombstone_references_valid {
        return Err(StorageError::StaleState);
    }
    Ok(())
}

// agenc-review: focus owner=storage reviewed=2026-08-29 reason=closed table-reference matrix is reviewed against every normative schema edge as one exhaustive matcher
const fn reference_is_legal(source: TableId, target: TableId) -> bool {
    match source {
        TableId::Account => matches!(target, TableId::OpaqueRecord),
        TableId::OpaqueRecord | TableId::NicknameReservation => {
            matches!(target, TableId::Account)
        }
        TableId::AuthTransaction => matches!(
            target,
            TableId::Account | TableId::OpaqueRecord | TableId::RegistrationInvite
        ),
        TableId::RegistrationInvite => {
            matches!(target, TableId::Account | TableId::AuthTransaction)
        }
        TableId::Session => matches!(target, TableId::Account | TableId::Channel),
        TableId::Channel => matches!(
            target,
            TableId::Account | TableId::Session | TableId::RegistrationInvite
        ),
        TableId::ChannelName | TableId::History => matches!(target, TableId::Channel),
        TableId::Sanction => matches!(
            target,
            TableId::Account | TableId::Session | TableId::Channel
        ),
        TableId::FederationPeer => matches!(target, TableId::E2eeState),
        TableId::FederationOrigin => matches!(target, TableId::FederationPeer),
        TableId::RequestResult => matches!(
            target,
            TableId::FederationPeer
                | TableId::FederationOrigin
                | TableId::EdgeOutbox
                | TableId::E2eeState
        ),
        TableId::EdgeOutbox => matches!(
            target,
            TableId::FederationPeer
                | TableId::RequestResult
                | TableId::E2eeObject
                | TableId::E2eeState
        ),
        TableId::EdgeProjection => matches!(
            target,
            TableId::FederationPeer
                | TableId::Account
                | TableId::Session
                | TableId::Channel
                | TableId::E2eeState
        ),
        TableId::Audit => matches!(
            target,
            TableId::Account
                | TableId::Session
                | TableId::Channel
                | TableId::Sanction
                | TableId::FederationPeer
                | TableId::E2eeState
        ),
        TableId::AuditCheckpoint => matches!(target, TableId::Audit),
        TableId::E2eeObject => matches!(
            target,
            TableId::Account | TableId::Channel | TableId::E2eeState
        ),
        TableId::E2eeState => matches!(
            target,
            TableId::Account
                | TableId::Channel
                | TableId::FederationPeer
                | TableId::E2eeObject
                | TableId::E2eeState
        ),
        TableId::KeyCheck
        | TableId::LoginIndex
        | TableId::StateMeta
        | TableId::IntegrityManifest
        | TableId::IntegrityCheckpoint
        | TableId::LoginIndexKeyState
        | TableId::StorageConstruction
        | TableId::StorageOperation => false,
    }
}

/// Converts one logical record charge into its backup stream charge.
fn backup_charge(logical_charge: u64) -> Result<u64, StorageError> {
    logical_charge
        .checked_add(BACKUP_RECORD_LENGTH_PREFIX_BYTES)
        .ok_or(StorageError::Overflow)
}

/// Rejects a prepared application whose exact sealed bytes disagree with the batch estimate.
///
/// `StorageMutationBatch` predicts the successor accounting from the envelope and manifest
/// layouts before anything is sealed. Startup and backup later require byte-exact equality
/// between StateMeta and the stored rows, so a wrong prediction must fail here instead of
/// producing an authenticated StateMeta that no later open can reconcile.
fn verify_prepared_accounting(
    batch: &StorageMutationBatch,
    prepared: &PreparedApplication,
) -> Result<(), StorageError> {
    let mut logical = batch.expected_logical_database_bytes();
    let mut backup = batch.expected_backup_stream_bytes();
    for (mutation, record) in batch.mutations().iter().zip(&prepared.records) {
        let key_bytes = record.key.as_bytes().len();
        if let Some(before) = mutation.before() {
            let before_bytes = usize::try_from(before.sealed_record_bytes())
                .map_err(|_| StorageError::Overflow)?;
            let charge = logical_record_charge(key_bytes, before_bytes)?;
            logical = logical
                .checked_sub(charge)
                .ok_or(StorageError::StaleState)?;
            backup = backup
                .checked_sub(backup_charge(charge)?)
                .ok_or(StorageError::StaleState)?;
        }
        if let Some(value) = &record.value {
            let charge = logical_record_charge(key_bytes, value.len())?;
            logical = logical.checked_add(charge).ok_or(StorageError::Overflow)?;
            backup = backup
                .checked_add(backup_charge(charge)?)
                .ok_or(StorageError::Overflow)?;
        }
    }
    let manifest_charge =
        logical_record_charge(prepared.manifest_key.len(), prepared.manifest_record.len())?;
    logical = logical
        .checked_add(manifest_charge)
        .ok_or(StorageError::Overflow)?;
    backup = backup
        .checked_add(backup_charge(manifest_charge)?)
        .ok_or(StorageError::Overflow)?;
    if (logical, backup)
        != (
            batch.resulting_logical_database_bytes(),
            batch.resulting_backup_stream_bytes(),
        )
    {
        return Err(StorageError::StaleState);
    }
    Ok(())
}

fn add_retired_charge(
    logical: &mut u64,
    backup: &mut u64,
    key: &[u8],
    value: &[u8],
) -> Result<(), StorageError> {
    let charge = logical_record_charge(key.len(), value.len())?;
    *logical = logical.checked_add(charge).ok_or(StorageError::Overflow)?;
    *backup = backup
        .checked_add(charge.checked_add(8).ok_or(StorageError::Overflow)?)
        .ok_or(StorageError::Overflow)?;
    Ok(())
}

fn checkpoint_nonces(nonces: Vec<[u8; 24]>) -> Result<[[u8; 24]; 2], StorageError> {
    nonces.try_into().map_err(|_| StorageError::InvalidEncoding)
}

fn tracked_commitment_tuple(
    table: TableId,
    stored_key: &StoredKey,
    record_schema: u32,
    sealed_record_id: StorageDigest,
) -> Result<Vec<u8>, StorageError> {
    let mut encoded = Vec::new();
    let capacity = 42_usize
        .checked_add(stored_key.as_bytes().len())
        .ok_or(StorageError::Overflow)?;
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| StorageError::AllocationFailed)?;
    encoded.extend_from_slice(&table.as_u16().to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(stored_key.as_bytes().len())
            .map_err(|_| StorageError::Overflow)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(stored_key.as_bytes());
    encoded.extend_from_slice(&record_schema.to_be_bytes());
    encoded.extend_from_slice(sealed_record_id.as_bytes());
    Ok(encoded)
}

fn apply_checkpoint_installation(
    checkpoint: &crate::IntegrityCheckpointTbs,
    storage_commit_sequence: &mut u64,
    nonce_high_water: &mut u64,
) -> Result<(), StorageError> {
    let expected_commit = storage_commit_sequence
        .checked_add(1)
        .ok_or(StorageError::Overflow)?;
    if checkpoint.installation_storage_commit_sequence != expected_commit
        || checkpoint.installation_nonce_reservation_start < *nonce_high_water
        || checkpoint.installation_nonce_draw_high_water
            != checkpoint
                .installation_nonce_reservation_start
                .checked_add(2)
                .ok_or(StorageError::Overflow)?
    {
        return Err(StorageError::StaleState);
    }
    *storage_commit_sequence = checkpoint.installation_storage_commit_sequence;
    *nonce_high_water = checkpoint.installation_nonce_draw_high_water;
    Ok(())
}

fn verify_completion_cut(
    completion: &StorageOperationCompletion,
    checkpoint: &IntegrityCheckpointTbs,
) -> Result<(), StorageError> {
    if checkpoint.cut_storage_commit_sequence != completion.finalization_storage_commit_sequence
        || checkpoint.cut_manifest_sequence != completion.finalization_manifest_sequence
        || checkpoint.cut_state_generation != completion.finalization_state_generation
        || checkpoint.cut_account_service_response_count
            != completion.finalization_account_service_response_count
        || checkpoint.cut_nonce_draw_high_water != completion.finalization_nonce_draw_high_water
    {
        return Err(StorageError::ResumeMismatch);
    }
    Ok(())
}

fn verify_completion_installation(
    completion: &StorageOperationCompletion,
    checkpoint: &IntegrityCheckpointTbs,
    state: &StateMetaTbs,
) -> Result<(), StorageError> {
    let expected_storage_commit = completion
        .finalization_storage_commit_sequence
        .checked_add(1)
        .ok_or(StorageError::Overflow)?;
    if checkpoint.installation_storage_commit_sequence != expected_storage_commit
        || checkpoint.installation_manifest_sequence != completion.finalization_manifest_sequence
        || checkpoint.installation_nonce_reservation_start
            < completion.finalization_nonce_draw_high_water
        || checkpoint.installation_nonce_draw_high_water
            != checkpoint
                .installation_nonce_reservation_start
                .checked_add(2)
                .ok_or(StorageError::Overflow)?
    {
        return Err(StorageError::ResumeMismatch);
    }
    if state.storage_commit_sequence != checkpoint.installation_storage_commit_sequence
        || state.manifest_sequence != completion.finalization_manifest_sequence
        || state.state_generation != completion.finalization_state_generation
        || state.account_service_response_count
            != completion.finalization_account_service_response_count
        || state.nonce_draw_high_water != checkpoint.installation_nonce_draw_high_water
    {
        return Err(StorageError::ResumeMismatch);
    }
    Ok(())
}

struct PreparedRecord {
    table: TableId,
    key: StoredKey,
    value: Option<Vec<u8>>,
}

struct PreparedApplication {
    records: Vec<PreparedRecord>,
    manifest_key: [u8; 8],
    manifest_record: Vec<u8>,
    state_meta_record: Vec<u8>,
    state_meta: StateMeta,
    state_meta_record_id: StorageDigest,
}

struct PreparedCheckpoint {
    checkpoint_key: [u8; 8],
    checkpoint_record: Vec<u8>,
    state_meta: StateMeta,
    state_meta_record: Vec<u8>,
    state_meta_record_id: StorageDigest,
    committed_reservation: NonceReservationState,
    committed_guard: RollbackGuard,
}

struct CheckpointJob {
    cut: StateMetaTbs,
    scan: SnapshotScan,
    limits: StorageRuntimeLimits,
    phase: CheckpointScanPhase,
    tracked_record_count: u64,
}

enum CheckpointScanPhase {
    Count,
    Digest(TrackedStateHasher),
}

struct CompletedCheckpointScan {
    cut: StateMetaTbs,
    limits: StorageRuntimeLimits,
    tracked_record_count: u64,
    tracked_state_digest: StorageDigest,
}

impl CheckpointJob {
    fn new(cut: StateMetaTbs, scan: SnapshotScan, limits: StorageRuntimeLimits) -> Self {
        Self {
            cut,
            scan,
            limits,
            phase: CheckpointScanPhase::Count,
            tracked_record_count: 0,
        }
    }

    fn service(
        &mut self,
        master_key: &StorageMasterKey,
        binding: DatabaseBinding,
        storage_key_generation: u32,
    ) -> Result<Option<CompletedCheckpointScan>, StorageError> {
        let slice = self
            .scan
            .next_tracked_slice(CHECKPOINT_SLICE_RECORDS, CHECKPOINT_SLICE_BYTES)?;
        match &mut self.phase {
            CheckpointScanPhase::Count => {
                self.tracked_record_count = self
                    .tracked_record_count
                    .checked_add(
                        u64::try_from(slice.rows.len()).map_err(|_| StorageError::Overflow)?,
                    )
                    .ok_or(StorageError::Overflow)?;
                if slice.complete {
                    self.scan.reset();
                    self.phase = CheckpointScanPhase::Digest(TrackedStateHasher::new(
                        self.tracked_record_count,
                    ));
                }
                Ok(None)
            }
            CheckpointScanPhase::Digest(hasher) => {
                for (table, key, encoded) in slice.rows {
                    let stored_key = StoredKey::new(key)?;
                    let sealed = SealedRecord::decode(&encoded)?;
                    let plaintext = sealed.open(
                        master_key,
                        binding,
                        table,
                        sealed.record_schema(),
                        storage_key_generation,
                        &stored_key,
                    )?;
                    crate::validate_record_plaintext(
                        table,
                        &stored_key,
                        sealed.record_schema(),
                        plaintext.expose_for_storage_codec(),
                    )?;
                    let tuple = tracked_commitment_tuple(
                        table,
                        &stored_key,
                        sealed.record_schema(),
                        sealed.record_id()?,
                    )?;
                    hasher.update(tracked_record_commitment(&tuple)?)?;
                }
                if !slice.complete {
                    return Ok(None);
                }
                let phase = std::mem::replace(&mut self.phase, CheckpointScanPhase::Count);
                let CheckpointScanPhase::Digest(hasher) = phase else {
                    return Err(StorageError::StaleState);
                };
                Ok(Some(CompletedCheckpointScan {
                    cut: self.cut,
                    limits: self.limits,
                    tracked_record_count: self.tracked_record_count,
                    tracked_state_digest: hasher.finalize()?,
                }))
            }
        }
    }
}

pub(crate) enum EngineCommitFailure {
    Rejected(StorageError),
    Indeterminate,
}

fn rejected(error: StorageError) -> EngineCommitFailure {
    EngineCommitFailure::Rejected(error)
}

fn indeterminate(_error: StorageError) -> EngineCommitFailure {
    EngineCommitFailure::Indeterminate
}

/// Whether a scratch was refused because the filesystem is below `R(F)` plus its allowance:
/// the one condition Section 19.3 answers with disabled durable mutation rather than a closed
/// owner. A failed sample, a refused allowance or a scratch I/O failure is not low disk.
fn scratch_unadmitted(error: StorageError) -> bool {
    error == StorageError::FilesystemRejected(crate::FilesystemCause::InsufficientCapacity)
}

/// Classifies a readback failure raised before anything was published. A resource refusal is a
/// determinate rejection: the scratch was refused its admission or its allowance, or the scratch
/// or a store read failed, and the caller may retry once the resource is back. Anything else
/// means the durable ledger does not reproduce the scan, a state this owner cannot vouch for,
/// and closes it through the same exit the post-publication verification always used.
fn readback_failure(error: StorageError) -> EngineCommitFailure {
    match error {
        StorageError::AllocationFailed
        | StorageError::AllowanceRefused(_)
        | StorageError::UnboundedRegion(_)
        | StorageError::FilesystemRejected(_)
        | StorageError::DatabaseRejected
        | StorageError::QueueFull
        | StorageError::Unavailable => EngineCommitFailure::Rejected(error),
        StorageError::InvalidEncoding
        | StorageError::UnsupportedVersion
        | StorageError::LimitExceeded
        | StorageError::Overflow
        | StorageError::AuthenticationFailed
        | StorageError::StaleState
        | StorageError::WriterLocked
        | StorageError::ResumeMismatch => EngineCommitFailure::Indeterminate,
    }
}

fn require_meta(store: &RedbStore, key: &[u8]) -> Result<Vec<u8>, StorageError> {
    store.read_meta(key)?.ok_or(StorageError::InvalidEncoding)
}

fn database_binding(header: &DatabaseHeader) -> DatabaseBinding {
    DatabaseBinding::new(
        header.tbs().network_id,
        header.tbs().server_id,
        header.tbs().server_incarnation,
        header.tbs().database_instance_id,
    )
}

fn verify_key_check(
    store: &RedbStore,
    master_key: &StorageMasterKey,
    binding: DatabaseBinding,
    header: &DatabaseHeader,
) -> Result<(), StorageError> {
    let key = StoredKey::new(KEY_CHECK_KEY.to_vec())?;
    let encoded = store
        .read_record(TableId::KeyCheck, key.as_bytes())?
        .ok_or(StorageError::InvalidEncoding)?;
    let record = SealedRecord::decode(&encoded)?;
    if record.record_id()? != header.key_check_object_id() {
        return Err(StorageError::AuthenticationFailed);
    }
    let plaintext = record.open(
        master_key,
        binding,
        TableId::KeyCheck,
        1,
        header.tbs().storage_key_generation,
        &key,
    )?;
    if plaintext.expose_for_storage_codec() != header.tbs().key_check_plaintext()?.as_bytes() {
        return Err(StorageError::AuthenticationFailed);
    }
    Ok(())
}

fn read_state_meta(
    store: &RedbStore,
    master_key: &StorageMasterKey,
    binding: DatabaseBinding,
    header: &DatabaseHeader,
    keys: &StorageIntegrityKeys,
) -> Result<(StateMeta, StorageDigest), StorageError> {
    let key = StoredKey::new(STATE_META_KEY.to_vec())?;
    let encoded = store
        .read_record(TableId::StateMeta, key.as_bytes())?
        .ok_or(StorageError::InvalidEncoding)?;
    let sealed = SealedRecord::decode(&encoded)?;
    let record_id = sealed.record_id()?;
    let plaintext = sealed.open(
        master_key,
        binding,
        TableId::StateMeta,
        1,
        header.tbs().storage_key_generation,
        &key,
    )?;
    let state_meta = StateMeta::decode_and_verify(
        plaintext.expose_for_storage_codec(),
        header.complete_hash()?,
        keys,
    )?;
    Ok((state_meta, record_id))
}

fn verify_existing(expected: ExistingRecord, encoded: &[u8]) -> Result<(), StorageError> {
    if usize::try_from(expected.sealed_record_bytes()).map_err(|_| StorageError::Overflow)?
        != encoded.len()
    {
        return Err(StorageError::StaleState);
    }
    let sealed = SealedRecord::decode(encoded)?;
    if sealed.record_schema() != expected.record_schema()
        || sealed.record_id()? != expected.sealed_record_id()
    {
        return Err(StorageError::StaleState);
    }
    Ok(())
}

fn guard_for_reservation(
    header: &DatabaseHeader,
    reservation: &NonceReservationState,
    keys: &StorageIntegrityKeys,
) -> Result<RollbackGuard, StorageError> {
    let source = reservation.tbs();
    RollbackGuard::authenticate(
        RollbackGuardTbs {
            network_id: header.tbs().network_id,
            server_id: header.tbs().server_id,
            database_instance_id: header.tbs().database_instance_id,
            storage_key_generation: header.tbs().storage_key_generation,
            schema_generation: header.tbs().schema_generation,
            recovery_epoch: header.tbs().recovery_epoch,
            storage_commit_sequence: source.storage_commit_sequence,
            manifest_sequence: source.manifest_sequence,
            state_generation: source.state_generation,
            phase: source.phase,
            reservation_sequence: source.reservation_sequence,
            nonce_reservation_start: source.nonce_reservation_start,
            nonce_draw_high_water: source.nonce_draw_high_water,
            database_header_hash: source.database_header_hash,
            state_meta_record_id: source.state_meta_record_id,
            nonce_reservation_state_hash: reservation.complete_hash()?,
            previous_guard_hash: source.previous_guard_hash,
        },
        keys,
    )
}

pub(crate) fn draw_nonces_with_faults(
    count: u32,
    faults: &StorageFaultInjector,
) -> Result<Vec<[u8; 24]>, StorageError> {
    let count = usize::try_from(count).map_err(|_| StorageError::Overflow)?;
    let mut nonces = Vec::new();
    nonces
        .try_reserve_exact(count)
        .map_err(|_| StorageError::AllocationFailed)?;
    for _ in 0..count {
        let mut nonce = [0_u8; 24];
        faults.check(StorageFaultSite::NonceDraw, StorageFaultBoundary::Before)?;
        OsEntropy::fill(&mut nonce)?;
        faults.check(StorageFaultSite::NonceDraw, StorageFaultBoundary::After)?;
        nonces.push(nonce);
    }
    Ok(nonces)
}

#[cfg(test)]
pub(crate) mod tests {
    mod bounded_scratch;
    mod history_reads;
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use agenc_ircd_crypto::{Ed25519SecretKey, StorageDigest, derive_login_index};
    use agenc_ircd_types::{
        AccountRandomId, DatabaseId, NetworkId, NormalizedLogin, OpaqueCredentialId, RecoveryEpoch,
        ServerIncarnation, TransactionId,
    };

    use super::*;
    use crate::BackupDestination;
    use crate::{
        AllowancePhase, InitialStorageRecord, LoginIndexValue, PersistentRecordValue,
        QualificationTarget, RecordMutation, SCHEMA_GENERATION, StorageConstructionKind,
        StorageFaultCase, StorageGrowthCase, StorageInitializationConfig,
        StorageInitializationMode, StorageInitializationOutcome, StorageQualification,
        StorageQualificationReport, StorageQualificationReportTbs, initialize_storage,
    };

    const ZERO: StorageDigest = StorageDigest::from_bytes([0; 32]);
    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct EngineFixture {
        engine: Option<StorageEngine>,
        path: PathBuf,
    }

    impl EngineFixture {
        pub(crate) fn create() -> Result<Self, StorageError> {
            Self::create_with_faults(StorageFaultInjector::disabled())
        }

        /// Opens the engine through one qualification fault schedule after a clean initialization.
        pub(crate) fn create_with_faults(
            faults: StorageFaultInjector,
        ) -> Result<Self, StorageError> {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::current_dir()
                .map_err(crate::filesystem_rejected)?
                .join("target")
                .join("engine-unit-tests")
                .join(format!("{}-{sequence}", std::process::id()));
            std::fs::create_dir_all(&path).map_err(crate::filesystem_rejected)?;
            std::fs::set_permissions(
                &path,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
            )
            .map_err(crate::filesystem_rejected)?;
            let qualifications = vec![test_qualification(&path)?];
            let network = NetworkId::from_bytes([21; 32]);
            let server = ServerId::from_bytes([22; 16]);
            let login_key = LoginIndexKey::from_bytes([23; 32]);
            let login_state = LoginIndexKeyState::stable(1, login_key.key_id(network))?;
            let initial = InitialStorageRecord::new(
                TableId::LoginIndexKeyState,
                StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
                1,
                login_state.encode()?,
            )?;
            let limits = engine_limits();
            let outcome = initialize_storage(StorageInitializationConfig {
                state_directory: StateDirectory::open(&path, &qualifications)?,
                header_tbs: crate::DatabaseHeaderTbs::new(
                    network,
                    server,
                    ServerIncarnation::from_bytes([24; 16]),
                    DatabaseId::from_bytes([25; 16]),
                    1,
                    SCHEMA_GENERATION,
                    RecoveryEpoch::from_bytes([26; 16]),
                )?,
                storage_master_key: StorageMasterKey::from_bytes([27; 32]),
                rollback_guard_root_key: RollbackGuardRootKey::from_bytes([28; 32]),
                mode: StorageInitializationMode::Live,
                initial_records: vec![initial],
                account_service_response_count: 0,
                state_generation: 0,
                predecessor_guard_hash: ZERO,
                limits,
            })?;
            if !matches!(outcome, StorageInitializationOutcome::Complete { .. }) {
                return Err(StorageError::Unavailable);
            }
            let engine = open_fixture_engine(&path, &qualifications, faults)?;
            Ok(Self {
                engine: Some(engine),
                path,
            })
        }

        /// Closes the engine and opens the same directory again, as a restart does.
        pub(crate) fn reopen(&mut self) -> Result<(), StorageError> {
            drop(self.engine.take());
            let qualifications = vec![test_qualification(&self.path)?];
            self.engine = Some(open_fixture_engine(
                &self.path,
                &qualifications,
                StorageFaultInjector::disabled(),
            )?);
            Ok(())
        }

        fn engine(&self) -> Result<&StorageEngine, StorageError> {
            self.engine.as_ref().ok_or(StorageError::Unavailable)
        }

        pub(crate) fn engine_mut(&mut self) -> Result<&mut StorageEngine, StorageError> {
            self.engine.as_mut().ok_or(StorageError::Unavailable)
        }

        /// Returns the private mode-0700 directory that holds this fixture's state.
        pub(crate) fn path(&self) -> &std::path::Path {
            &self.path
        }

        /// Returns the account key that [`Self::advancing_batch`] writes for `byte`.
        pub(crate) fn account_key(byte: u8) -> Result<StoredKey, StorageError> {
            account_key_for_test(byte)
        }

        /// Builds one state-advancing account insertion against the engine's current head.
        pub(crate) fn advancing_batch(
            engine: &StorageEngine,
            byte: u8,
        ) -> Result<StorageMutationBatch, StorageError> {
            advancing_batch(engine, byte)
        }

        /// Builds a batch whose expected sequence is one ahead of the engine's head.
        pub(crate) fn stale_batch(
            engine: &StorageEngine,
            byte: u8,
        ) -> Result<StorageMutationBatch, StorageError> {
            let mut head = current_head(engine);
            head.expected_storage_commit_sequence = head
                .expected_storage_commit_sequence
                .checked_add(1)
                .ok_or(StorageError::Overflow)?;
            StorageMutationBatch::new(
                head,
                1,
                current_accounting(engine),
                vec![RecordMutation::put(
                    TableId::Account,
                    account_key_for_test(byte)?,
                    1,
                    None,
                    account_plaintext(1)?,
                )?],
            )
        }
    }

    impl Drop for EngineFixture {
        fn drop(&mut self) {
            drop(self.engine.take());
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn open_fixture_engine(
        path: &std::path::Path,
        qualifications: &[StorageQualification],
        faults: StorageFaultInjector,
    ) -> Result<StorageEngine, StorageError> {
        StorageEngine::open(StorageOpenConfig {
            expected_network_id: NetworkId::from_bytes([21; 32]),
            expected_server_id: ServerId::from_bytes([22; 16]),
            state_directory: StateDirectory::open_with_faults(path, qualifications, faults)?,
            storage_master_key: StorageMasterKey::from_bytes([27; 32]),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes([28; 32]),
            login_index_key: LoginIndexKey::from_bytes([23; 32]),
            previous_login_index_key: None,
            limits: engine_limits(),
        })
    }

    const fn engine_limits() -> StorageEngineLimits {
        StorageEngineLimits {
            redb_cache_bytes: 8 * 1_024 * 1_024,
            fixed_reserve_bytes: MIN_FIXED_RESERVE_BYTES,
            reserve_percent: 1,
            database_max_bytes: MIN_STORAGE_BYTES,
            backup_max_bytes: MIN_STORAGE_BYTES,
            integrity_checkpoint_manifests: MIN_CHECKPOINT_MANIFESTS,
        }
    }

    fn test_qualification(path: &std::path::Path) -> Result<StorageQualification, StorageError> {
        let tuple = StateDirectory::probe(path)?;
        let target = match tuple.target {
            "x86_64-unknown-linux-gnu" => QualificationTarget::X86_64UnknownLinuxGnu,
            "aarch64-unknown-linux-gnu" => QualificationTarget::Aarch64UnknownLinuxGnu,
            _ => {
                return Err(StorageError::FilesystemRejected(
                    crate::FilesystemCause::Unqualified,
                ));
            }
        };
        let mut cases = crate::REQUIRED_QUALIFICATION_CASES
            .iter()
            .map(|name| StorageGrowthCase::new((*name).to_owned(), 1_000, 1_001))
            .collect::<Result<Vec<_>, _>>()?;
        cases.sort_by(|left, right| left.name().cmp(right.name()));
        let key = Ed25519SecretKey::from_bytes([30; 32]);
        let report = StorageQualificationReport::sign(
            StorageQualificationReportTbs {
                target,
                filesystem_type: tuple.filesystem_type,
                block_size: tuple.block_size,
                mount_flags: tuple.mount_flags,
                kernel_release: "engine-test-kernel".to_owned(),
                redb_features_hash: StorageDigest::from_bytes([1; 32]),
                release_profile_hash: StorageDigest::from_bytes([2; 32]),
                corpus_hash: StorageDigest::from_bytes([3; 32]),
                cases,
                maximum_observed_growth: 1,
                raw_log_hash: StorageDigest::from_bytes([4; 32]),
            },
            &key,
        )?;
        StorageQualificationReport::decode_and_verify(&report.encode()?, key.public_key())?
            .qualification_for(tuple)
    }

    #[derive(Debug, Eq, PartialEq)]
    struct DirectoryFingerprint {
        directory_inode: u64,
        directory_mtime: i64,
        directory_mtime_nanoseconds: i64,
        entries: Vec<FileFingerprint>,
    }

    #[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct FileFingerprint {
        name: String,
        inode: u64,
        mtime: i64,
        mtime_nanoseconds: i64,
        bytes: Vec<u8>,
    }

    fn directory_fingerprint(path: &Path) -> Result<DirectoryFingerprint, StorageError> {
        let directory = std::fs::symlink_metadata(path).map_err(crate::filesystem_rejected)?;
        let mut entries = std::fs::read_dir(path)
            .map_err(crate::filesystem_rejected)?
            .map(|entry| {
                let entry = entry.map_err(crate::filesystem_rejected)?;
                let name = entry.file_name().into_string().map_err(|_| {
                    StorageError::FilesystemRejected(crate::FilesystemCause::UnsafePath)
                })?;
                let metadata = entry.metadata().map_err(crate::filesystem_rejected)?;
                let bytes = std::fs::read(entry.path()).map_err(crate::filesystem_rejected)?;
                Ok(FileFingerprint {
                    name,
                    inode: metadata.ino(),
                    mtime: metadata.mtime(),
                    mtime_nanoseconds: metadata.mtime_nsec(),
                    bytes,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        entries.sort();
        Ok(DirectoryFingerprint {
            directory_inode: directory.ino(),
            directory_mtime: directory.mtime(),
            directory_mtime_nanoseconds: directory.mtime_nsec(),
            entries,
        })
    }

    fn inspection_config(path: &Path) -> Result<StorageInspectionConfig, StorageError> {
        let qualification = test_qualification(path)?;
        Ok(StorageInspectionConfig {
            expected_network_id: NetworkId::from_bytes([21; 32]),
            expected_server_id: ServerId::from_bytes([22; 16]),
            state_directory: InspectionStateDirectory::open(path, &[qualification])?,
            storage_master_key: StorageMasterKey::from_bytes([27; 32]),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes([28; 32]),
            login_index_key: LoginIndexKey::from_bytes([23; 32]),
            previous_login_index_key: None,
            limits: engine_limits(),
        })
    }

    fn assert_recovered_durable_facts_match(
        actual: RecoveredStorageState,
        expected: RecoveredStorageState,
    ) {
        assert_eq!(actual.table_record_counts, expected.table_record_counts);
        assert_eq!(actual.state_generation, expected.state_generation);
        assert_eq!(
            actual.account_service_response_count,
            expected.account_service_response_count
        );
        assert_eq!(
            actual.storage_commit_sequence,
            expected.storage_commit_sequence
        );
        assert_eq!(actual.manifest_sequence, expected.manifest_sequence);
        assert_eq!(actual.nonce_draw_high_water, expected.nonce_draw_high_water);
        assert_eq!(
            actual.maximum_record_revision,
            expected.maximum_record_revision
        );
        assert_eq!(
            actual.logical_database_bytes,
            expected.logical_database_bytes
        );
        assert_eq!(actual.backup_stream_bytes, expected.backup_stream_bytes);
        assert_eq!(actual.database_binding, expected.database_binding);
        assert_eq!(
            actual.storage_key_generation,
            expected.storage_key_generation
        );
        assert_eq!(actual.recovery_epoch, expected.recovery_epoch);
    }

    fn authenticate_state(
        engine: &mut StorageEngine,
        state: StateMetaTbs,
    ) -> Result<(), StorageError> {
        engine.state_meta = StateMeta::authenticate(
            state,
            engine.header.complete_hash()?,
            &engine.integrity_keys,
        )?;
        Ok(())
    }

    fn active_checkpoint(engine: &StorageEngine) -> Result<IntegrityCheckpointTbs, StorageError> {
        let sequence = engine.state_meta.tbs().checkpoint_manifest_sequence;
        let key = StoredKey::new(sequence.to_be_bytes().to_vec())?;
        let encoded = engine
            .store
            .read_record(TableId::IntegrityCheckpoint, key.as_bytes())?
            .ok_or(StorageError::InvalidEncoding)?;
        let sealed = SealedRecord::decode(&encoded)?;
        let plaintext = sealed.open(
            &engine.master_key,
            engine.binding,
            TableId::IntegrityCheckpoint,
            1,
            engine.header.tbs().storage_key_generation,
            &key,
        )?;
        Ok(*IntegrityCheckpoint::decode(plaintext.expose_for_storage_codec())?.tbs())
    }

    fn replace_checkpoint(
        engine: &mut StorageEngine,
        key_sequence: u64,
        tbs: IntegrityCheckpointTbs,
    ) -> Result<(), StorageError> {
        let checkpoint = IntegrityCheckpoint::new(tbs)?;
        let key = StoredKey::new(key_sequence.to_be_bytes().to_vec())?;
        let encoded = StorageSealContext::new(
            &engine.master_key,
            engine.binding,
            engine.header.tbs().storage_key_generation,
        )?
        .seal(
            TableId::IntegrityCheckpoint,
            1,
            [29; 24],
            &key,
            &checkpoint.encode()?,
        )?
        .encode()?;
        commit_rows(
            engine,
            &[RedbWrite {
                table: TableId::IntegrityCheckpoint,
                key: key.as_bytes(),
                value: Some(&encoded),
            }],
        )?;
        let mut state = *engine.state_meta.tbs();
        state.checkpoint_manifest_sequence = key_sequence;
        state.checkpoint_hash = checkpoint.checkpoint_hash();
        authenticate_state(engine, state)
    }

    fn active_manifest(engine: &StorageEngine) -> Result<IntegrityManifestTbs, StorageError> {
        let sequence = engine.state_meta.tbs().manifest_sequence;
        let key = StoredKey::new(sequence.to_be_bytes().to_vec())?;
        let encoded = engine
            .store
            .read_record(TableId::IntegrityManifest, key.as_bytes())?
            .ok_or(StorageError::InvalidEncoding)?;
        let sealed = SealedRecord::decode(&encoded)?;
        let plaintext = sealed.open(
            &engine.master_key,
            engine.binding,
            TableId::IntegrityManifest,
            1,
            engine.header.tbs().storage_key_generation,
            &key,
        )?;
        let manifest = IntegrityManifest::decode(plaintext.expose_for_storage_codec())?;
        let fields = manifest.tbs();
        IntegrityManifestTbs::new(
            fields.database_instance_id,
            fields.manifest_sequence,
            fields.storage_commit_sequence,
            fields.previous_state_generation,
            fields.resulting_state_generation,
            fields.previous_account_service_response_count,
            fields.resulting_account_service_response_count,
            fields.previous_nonce_draw_high_water,
            fields.transaction_nonce_reservation_start,
            fields.resulting_nonce_draw_high_water,
            fields.transaction_seal_count,
            fields.previous_manifest_hash,
            fields.mutations().to_vec(),
        )
    }

    fn replace_manifest(
        engine: &mut StorageEngine,
        tbs: IntegrityManifestTbs,
    ) -> Result<(), StorageError> {
        let manifest = IntegrityManifest::new(tbs)?;
        let sequence = engine.state_meta.tbs().manifest_sequence;
        let key = StoredKey::new(sequence.to_be_bytes().to_vec())?;
        let encoded = StorageSealContext::new(
            &engine.master_key,
            engine.binding,
            engine.header.tbs().storage_key_generation,
        )?
        .seal(
            TableId::IntegrityManifest,
            1,
            [30; 24],
            &key,
            &manifest.encode()?,
        )?
        .encode()?;
        commit_rows(
            engine,
            &[RedbWrite {
                table: TableId::IntegrityManifest,
                key: key.as_bytes(),
                value: Some(&encoded),
            }],
        )?;
        let mut state = *engine.state_meta.tbs();
        state.latest_manifest_hash = manifest.manifest_hash();
        authenticate_state(engine, state)
    }

    fn mutation_batch(
        head: StorageMutationHead,
        accounting: StorageAccountingLimits,
    ) -> Result<StorageMutationBatch, StorageError> {
        let key = StoredKey::new(AccountRandomId::from_bytes([40; 16]).to_text().into_bytes())?;
        let plaintext = PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            1,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?
        .encode()?;
        StorageMutationBatch::new(
            head,
            1,
            accounting,
            vec![RecordMutation::put(
                TableId::Account,
                key,
                1,
                None,
                plaintext,
            )?],
        )
    }

    fn advancing_batch(
        engine: &StorageEngine,
        byte: u8,
    ) -> Result<StorageMutationBatch, StorageError> {
        let mut head = current_head(engine);
        head.transaction_id = TransactionId::from_bytes([byte; 16]);
        head.resulting_state_generation = head
            .expected_state_generation
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        head.state_advancing_plan_count = 1;
        head.resulting_account_service_response_count = head
            .expected_account_service_response_count
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        StorageMutationBatch::new(
            head,
            1,
            current_accounting(engine),
            vec![RecordMutation::put(
                TableId::Account,
                account_key_for_test(byte)?,
                1,
                None,
                account_plaintext(1)?,
            )?],
        )
    }

    fn current_head(engine: &StorageEngine) -> StorageMutationHead {
        let state = engine.state_meta.tbs();
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([41; 16]),
            expected_storage_commit_sequence: state.storage_commit_sequence,
            expected_state_generation: state.state_generation,
            resulting_state_generation: state.state_generation,
            state_advancing_plan_count: 0,
            expected_account_service_response_count: state.account_service_response_count,
            resulting_account_service_response_count: state.account_service_response_count,
        }
    }

    fn current_accounting(engine: &StorageEngine) -> StorageAccountingLimits {
        StorageAccountingLimits {
            current_logical_database_bytes: engine.state_meta.tbs().logical_database_bytes,
            current_backup_stream_bytes: engine.state_meta.tbs().backup_stream_bytes,
            database_max_bytes: engine.limits.database_max_bytes,
            backup_max_bytes: engine.limits.backup_max_bytes,
        }
    }

    fn account_plaintext(revision: u64) -> Result<Vec<u8>, StorageError> {
        PersistentRecordValue::new(
            TableId::Account,
            1,
            revision,
            1,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?
        .encode()
    }

    fn existing_record(
        engine: &StorageEngine,
        table: TableId,
        key: &StoredKey,
    ) -> Result<ExistingRecord, StorageError> {
        let encoded = engine
            .store
            .read_record(table, key.as_bytes())?
            .ok_or(StorageError::StaleState)?;
        let sealed = SealedRecord::decode(&encoded)?;
        ExistingRecord::new(sealed.record_schema(), sealed.record_id()?, encoded.len())
    }

    fn batch_with(
        engine: &StorageEngine,
        mutation: RecordMutation,
    ) -> Result<StorageMutationBatch, StorageError> {
        StorageMutationBatch::new(
            current_head(engine),
            1,
            current_accounting(engine),
            vec![mutation],
        )
    }

    /// The whole Section 19.3 allowance, which every test row set fits.
    fn full_allowance() -> redb::AllocationAllowance {
        redb::AllocationAllowance::new(crate::MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
    }

    /// Writes rows past the engine's own accounting, repeating its current reservation record.
    fn commit_rows(engine: &StorageEngine, writes: &[RedbWrite<'_>]) -> Result<(), StorageError> {
        let reservation = engine.reservation.encode()?;
        engine
            .store
            .commit_records(writes, &reservation, full_allowance())
            .map(|_| ())
            .map_err(|failure| match failure {
                RedbCommitFailure::Rejected(error) => error,
                RedbCommitFailure::Indeterminate => StorageError::Unavailable,
            })
    }

    fn reopen_config(
        path: &std::path::Path,
        network: NetworkId,
        server: ServerId,
    ) -> Result<StorageOpenConfig, StorageError> {
        let qualifications = vec![test_qualification(path)?];
        Ok(StorageOpenConfig {
            expected_network_id: network,
            expected_server_id: server,
            state_directory: StateDirectory::open(path, &qualifications)?,
            storage_master_key: StorageMasterKey::from_bytes([27; 32]),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes([28; 32]),
            login_index_key: LoginIndexKey::from_bytes([23; 32]),
            previous_login_index_key: None,
            limits: engine_limits(),
        })
    }

    fn checkpoint() -> IntegrityCheckpointTbs {
        IntegrityCheckpointTbs {
            database_instance_id: DatabaseId::from_bytes([1; 16]),
            cut_storage_commit_sequence: 7,
            cut_manifest_sequence: 8,
            cut_state_generation: 9,
            cut_account_service_response_count: 10,
            cut_nonce_draw_high_water: 11,
            cut_manifest_hash: StorageDigest::from_bytes([2; 32]),
            tracked_record_count: 12,
            tracked_state_digest: StorageDigest::from_bytes([3; 32]),
            previous_checkpoint_hash: StorageDigest::from_bytes([4; 32]),
            installation_storage_commit_sequence: 8,
            installation_manifest_sequence: 8,
            installation_nonce_reservation_start: 11,
            installation_nonce_draw_high_water: 13,
        }
    }

    fn completion() -> StorageOperationCompletion {
        StorageOperationCompletion {
            identity: StorageOperationIdentity {
                kind: StorageConstructionKind::Rekey,
                command_version: 1,
                source_database_header_hash: StorageDigest::from_bytes([5; 32]),
                target_database_header_hash: StorageDigest::from_bytes([6; 32]),
                source_rollback_guard_hash: StorageDigest::from_bytes([7; 32]),
                source_stream_digest: None,
                source_schema_generation: crate::SCHEMA_GENERATION,
                target_schema_generation: crate::SCHEMA_GENERATION,
                transform_profile_hash: StorageDigest::from_bytes([8; 32]),
                target_database_instance_id: DatabaseId::from_bytes([9; 16]),
                source_master_key_id: StorageDigest::from_bytes([10; 32]),
                source_guard_root_key_id: StorageDigest::from_bytes([11; 32]),
                target_master_key_id: StorageDigest::from_bytes([12; 32]),
                target_guard_root_key_id: StorageDigest::from_bytes([13; 32]),
                planned_entry_count: 1,
                construction_plan_hash: StorageDigest::from_bytes([14; 32]),
            },
            storage_operation_id: StorageDigest::from_bytes([15; 32]),
            target_records_committed: 1,
            finalization_storage_commit_sequence: 7,
            finalization_manifest_sequence: 8,
            finalization_state_generation: 9,
            finalization_account_service_response_count: 10,
            finalization_nonce_draw_high_water: 11,
        }
    }

    fn state() -> StateMetaTbs {
        StateMetaTbs {
            storage_commit_sequence: 8,
            manifest_sequence: 8,
            state_generation: 9,
            account_service_response_count: 10,
            nonce_draw_high_water: 13,
            logical_database_bytes: 1,
            backup_stream_bytes: 1,
            checkpoint_manifest_sequence: 8,
            latest_manifest_hash: ZERO,
            checkpoint_hash: ZERO,
            previous_rollback_guard_hash: ZERO,
        }
    }

    #[test]
    fn checkpoint_installation_rejects_each_counter_mismatch() {
        let valid = checkpoint();
        let mut commit = 7;
        let mut nonce = 11;
        assert_eq!(
            apply_checkpoint_installation(&valid, &mut commit, &mut nonce),
            Ok(())
        );
        assert_eq!((commit, nonce), (8, 13));

        for changed in 0..3 {
            let mut invalid = valid;
            match changed {
                0 => invalid.installation_storage_commit_sequence = 9,
                1 => invalid.installation_nonce_reservation_start = 10,
                _ => invalid.installation_nonce_draw_high_water = 14,
            }
            let mut commit = 7;
            let mut nonce = 11;
            assert_eq!(
                apply_checkpoint_installation(&invalid, &mut commit, &mut nonce),
                Err(StorageError::StaleState)
            );
        }

        let mut commit = u64::MAX;
        let mut nonce = 11;
        assert_eq!(
            apply_checkpoint_installation(&valid, &mut commit, &mut nonce),
            Err(StorageError::Overflow)
        );
    }

    #[test]
    fn completion_checkpoint_binding_rejects_every_cut_and_installation_mismatch() {
        let completion = completion();
        let valid_checkpoint = checkpoint();
        let valid_state = state();
        assert_eq!(
            verify_completion_cut(&completion, &valid_checkpoint),
            Ok(())
        );
        assert_eq!(
            verify_completion_installation(&completion, &valid_checkpoint, &valid_state),
            Ok(())
        );

        for changed in 0..5 {
            let mut invalid = valid_checkpoint;
            match changed {
                0 => invalid.cut_storage_commit_sequence = 6,
                1 => invalid.cut_manifest_sequence = 7,
                2 => invalid.cut_state_generation = 8,
                3 => invalid.cut_account_service_response_count = 9,
                _ => invalid.cut_nonce_draw_high_water = 10,
            }
            assert_eq!(
                verify_completion_cut(&completion, &invalid),
                Err(StorageError::ResumeMismatch)
            );
        }

        for changed in 0..4 {
            let mut invalid = valid_checkpoint;
            match changed {
                0 => invalid.installation_storage_commit_sequence = 9,
                1 => invalid.installation_manifest_sequence = 9,
                2 => invalid.installation_nonce_reservation_start = 10,
                _ => invalid.installation_nonce_draw_high_water = 14,
            }
            assert_eq!(
                verify_completion_installation(&completion, &invalid, &valid_state),
                Err(StorageError::ResumeMismatch)
            );
        }

        for changed in 0..5 {
            let mut invalid = valid_state;
            match changed {
                0 => invalid.storage_commit_sequence = 9,
                1 => invalid.manifest_sequence = 9,
                2 => invalid.state_generation = 10,
                3 => invalid.account_service_response_count = 11,
                _ => invalid.nonce_draw_high_water = 14,
            }
            assert_eq!(
                verify_completion_installation(&completion, &valid_checkpoint, &invalid),
                Err(StorageError::ResumeMismatch)
            );
        }
    }

    #[test]
    fn recovered_domain_validation_rejects_cross_table_reference_and_tombstone_errors()
    -> Result<(), StorageError> {
        let account_key =
            StoredKey::new(AccountRandomId::from_bytes([16; 16]).to_text().into_bytes())?;
        let channel_key = StoredKey::new(vec![1; 16])?;
        let account_reference = RecordReference::new(
            TableId::Account,
            StoredKey::new(account_key.as_bytes().to_vec())?,
        )?;
        let channel_reference = RecordReference::new(
            TableId::Channel,
            StoredKey::new(channel_key.as_bytes().to_vec())?,
        )?;

        let account = PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            1,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?;
        assert_eq!(
            validate_recovered_domain_record(TableId::Channel, &account),
            Err(StorageError::StaleState)
        );

        let illegal = PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            1,
            None,
            vec![channel_reference],
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?;
        assert_eq!(
            validate_recovered_domain_record(TableId::Account, &illegal),
            Err(StorageError::StaleState)
        );

        let missing_required = PersistentRecordValue::new(
            TableId::NicknameReservation,
            1,
            1,
            1,
            None,
            Vec::new(),
            b"nickname".to_vec(),
        )?;
        assert_eq!(
            validate_recovered_domain_record(TableId::NicknameReservation, &missing_required),
            Err(StorageError::StaleState)
        );

        let duplicate_required = PersistentRecordValue::new(
            TableId::NicknameReservation,
            1,
            1,
            1,
            None,
            vec![
                account_reference,
                RecordReference::new(
                    TableId::Account,
                    StoredKey::new(AccountRandomId::from_bytes([17; 16]).to_text().into_bytes())?,
                )?,
            ],
            b"nickname".to_vec(),
        )?;
        assert_eq!(
            validate_recovered_domain_record(TableId::NicknameReservation, &duplicate_required),
            Err(StorageError::StaleState)
        );

        let tombstone = PersistentRecordValue::new(
            TableId::Account,
            2,
            1,
            1,
            None,
            vec![RecordReference::new(
                TableId::OpaqueRecord,
                StoredKey::new(account_key.as_bytes().to_vec())?,
            )?],
            vec![1],
        )?;
        assert_eq!(
            validate_recovered_domain_record(TableId::Account, &tombstone),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn retired_charge_and_checkpoint_nonce_helpers_cover_exact_failures() {
        let mut logical = 0;
        let mut backup = 0;
        let sealed = vec![0; crate::MIN_SEALED_RECORD_BYTES];
        assert_eq!(
            add_retired_charge(&mut logical, &mut backup, b"key", &sealed),
            Ok(())
        );
        assert!(logical > 0 && backup > logical);

        let mut overflowed = u64::MAX;
        let mut backup = 0;
        assert_eq!(
            add_retired_charge(&mut overflowed, &mut backup, b"key", &sealed),
            Err(StorageError::Overflow)
        );
        let mut logical = 0;
        let mut overflowed = u64::MAX;
        assert_eq!(
            add_retired_charge(&mut logical, &mut overflowed, b"key", &sealed),
            Err(StorageError::Overflow)
        );
        assert_eq!(
            checkpoint_nonces(vec![[1; 24], [2; 24]]),
            Ok([[1; 24], [2; 24]])
        );
        assert_eq!(
            checkpoint_nonces(vec![[1; 24]]),
            Err(StorageError::InvalidEncoding)
        );
    }

    #[test]
    fn storage_engine_limits_reject_every_independent_profile_boundary() {
        assert_eq!(engine_limits().validate(), Ok(engine_limits()));
        let cases = [
            StorageEngineLimits {
                redb_cache_bytes: 0,
                ..engine_limits()
            },
            StorageEngineLimits {
                database_max_bytes: MIN_STORAGE_BYTES - 1,
                ..engine_limits()
            },
            StorageEngineLimits {
                database_max_bytes: MAX_STORAGE_BYTES + 1,
                backup_max_bytes: MAX_STORAGE_BYTES + 1,
                ..engine_limits()
            },
            StorageEngineLimits {
                backup_max_bytes: MIN_STORAGE_BYTES - 1,
                ..engine_limits()
            },
            StorageEngineLimits {
                database_max_bytes: MIN_STORAGE_BYTES + 1,
                backup_max_bytes: MIN_STORAGE_BYTES,
                ..engine_limits()
            },
            StorageEngineLimits {
                fixed_reserve_bytes: MIN_FIXED_RESERVE_BYTES - 1,
                ..engine_limits()
            },
            StorageEngineLimits {
                fixed_reserve_bytes: MAX_STORAGE_BYTES + 1,
                ..engine_limits()
            },
            StorageEngineLimits {
                reserve_percent: 0,
                ..engine_limits()
            },
            StorageEngineLimits {
                reserve_percent: 26,
                ..engine_limits()
            },
            StorageEngineLimits {
                integrity_checkpoint_manifests: MIN_CHECKPOINT_MANIFESTS - 1,
                ..engine_limits()
            },
            StorageEngineLimits {
                integrity_checkpoint_manifests: MAX_RETAINED_MANIFESTS + 1,
                ..engine_limits()
            },
        ];
        for limits in cases {
            assert_eq!(limits.validate(), Err(StorageError::LimitExceeded));
        }
    }

    #[test]
    fn live_storage_limits_replace_one_view_and_active_jobs_keep_their_starting_view()
    -> Result<(), StorageError> {
        let initial = StorageRuntimeLimits::new(
            MIN_STORAGE_BYTES * 2,
            MIN_STORAGE_BYTES * 3,
            MIN_CHECKPOINT_MANIFESTS + 1,
        )?;
        let replacement = StorageRuntimeLimits::new(
            MIN_STORAGE_BYTES,
            MIN_STORAGE_BYTES,
            MIN_CHECKPOINT_MANIFESTS,
        )?;
        let (writer, reader) = storage_limit_pair(initial);
        let mut fixture = EngineFixture::create()?;
        let backup_directory = fixture.path().join("live-limit-backups");
        std::fs::create_dir(&backup_directory).map_err(crate::filesystem_rejected)?;
        std::fs::set_permissions(
            &backup_directory,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .map_err(crate::filesystem_rejected)?;
        let engine = fixture.engine_mut()?;
        engine.runtime_limits = reader;
        engine.publish_runtime_facts();
        engine.refresh_runtime_limits();
        assert_eq!(
            engine.limits.database_max_bytes,
            initial.database_max_bytes()
        );

        engine.start_backup(
            BackupDestination::new(&backup_directory, "frozen.backup")?,
            Ed25519SecretKey::from_bytes([91; 32]),
            1,
            [92; 16],
        )?;
        writer.activate(replacement)?;
        engine.refresh_runtime_limits();
        assert_eq!(
            engine.limits.database_max_bytes,
            replacement.database_max_bytes()
        );
        assert_eq!(
            engine
                .backup_job
                .as_ref()
                .ok_or(StorageError::StaleState)?
                .maximum_bytes(),
            initial.backup_max_bytes()
        );
        engine.backup_job = None;

        writer.activate(initial)?;
        engine.refresh_runtime_limits();
        engine.start_checkpoint()?;
        assert_eq!(writer.activate(replacement), Err(StorageError::QueueFull));
        assert_eq!(
            engine
                .checkpoint_job
                .as_ref()
                .ok_or(StorageError::StaleState)?
                .limits,
            initial
        );
        engine.abandon_checkpoint();
        writer.activate(replacement)?;
        engine.refresh_runtime_limits();
        engine.start_checkpoint()?;
        assert_eq!(
            engine
                .checkpoint_job
                .as_ref()
                .ok_or(StorageError::StaleState)?
                .limits,
            replacement
        );
        Ok(())
    }

    #[test]
    fn shared_checkpoint_fact_tracks_limits_completion_and_poisoning() -> Result<(), StorageError> {
        let initial = StorageRuntimeLimits::new(
            MIN_STORAGE_BYTES,
            MIN_STORAGE_BYTES,
            MIN_CHECKPOINT_MANIFESTS + 1,
        )?;
        let due = StorageRuntimeLimits::new(
            MIN_STORAGE_BYTES,
            MIN_STORAGE_BYTES,
            MIN_CHECKPOINT_MANIFESTS,
        )?;
        let (writer, reader) = storage_limit_pair(initial);
        reader.publish_facts(1, 1, MIN_CHECKPOINT_MANIFESTS, 1);
        assert_eq!(writer.checkpoint_due(), Ok(false));

        writer.activate(due)?;
        assert_eq!(writer.checkpoint_due(), Ok(true));
        let _frozen = reader.begin_checkpoint()?;
        reader.publish_facts(1, 1, 0, 0);
        assert_eq!(writer.checkpoint_due(), Ok(false));
        reader.finish_checkpoint();

        let _frozen = reader.begin_checkpoint()?;
        reader.poison_checkpoint();
        assert_eq!(writer.checkpoint_due(), Err(StorageError::Unavailable));
        assert_eq!(writer.activate(initial), Err(StorageError::Unavailable));
        Ok(())
    }

    #[test]
    fn integrity_ledger_rejects_each_genesis_anchor_mismatch() -> Result<(), StorageError> {
        let baseline = EngineFixture::create()?;
        baseline.engine()?.verify_integrity_ledger()?;
        drop(baseline);

        for changed in 0..4 {
            let mut fixture = EngineFixture::create()?;
            let mut checkpoint = active_checkpoint(fixture.engine()?)?;
            match changed {
                0 => checkpoint.previous_checkpoint_hash = StorageDigest::from_bytes([31; 32]),
                1 => checkpoint.cut_manifest_hash = StorageDigest::from_bytes([32; 32]),
                2 => checkpoint.cut_nonce_draw_high_water += 1,
                _ => {
                    checkpoint.installation_nonce_reservation_start += 1;
                    checkpoint.installation_nonce_draw_high_water += 1;
                }
            }
            replace_checkpoint(fixture.engine_mut()?, 0, checkpoint)?;
            assert_eq!(
                fixture.engine()?.verify_integrity_ledger(),
                Err(StorageError::StaleState)
            );
        }
        Ok(())
    }

    #[test]
    fn integrity_ledger_rejects_each_checkpoint_to_state_anchor_mismatch()
    -> Result<(), StorageError> {
        for changed in 0..5 {
            let mut fixture = EngineFixture::create()?;
            let engine = fixture.engine_mut()?;
            let mut state = *engine.state_meta.tbs();
            match changed {
                0 => state.latest_manifest_hash = StorageDigest::from_bytes([33; 32]),
                1 => state.state_generation += 1,
                2 => state.account_service_response_count += 1,
                3 => state.storage_commit_sequence += 1,
                _ => state.nonce_draw_high_water += 1,
            }
            authenticate_state(engine, state)?;
            assert_eq!(
                engine.verify_integrity_ledger(),
                Err(StorageError::StaleState)
            );
        }

        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let mut state = *engine.state_meta.tbs();
        state.checkpoint_hash = StorageDigest::from_bytes([34; 32]);
        authenticate_state(engine, state)?;
        assert_eq!(
            engine.verify_integrity_ledger(),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn integrity_ledger_rejects_non_genesis_shape_and_tracked_digest_mismatches()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let mut checkpoint = active_checkpoint(fixture.engine()?)?;
        checkpoint.installation_storage_commit_sequence = 1;
        replace_checkpoint(fixture.engine_mut()?, 0, checkpoint)?;
        assert_eq!(
            fixture.engine()?.verify_integrity_ledger(),
            Err(StorageError::StaleState)
        );
        drop(fixture);

        for missing_installation_or_predecessor in [true, false] {
            let mut fixture = EngineFixture::create()?;
            let engine = fixture.engine_mut()?;
            let mut state = *engine.state_meta.tbs();
            state.manifest_sequence = 1;
            authenticate_state(engine, state)?;
            let mut checkpoint = active_checkpoint(fixture.engine()?)?;
            checkpoint.cut_storage_commit_sequence = 1;
            checkpoint.cut_manifest_sequence = 1;
            checkpoint.installation_manifest_sequence = 1;
            checkpoint.previous_checkpoint_hash = if missing_installation_or_predecessor {
                StorageDigest::from_bytes([35; 32])
            } else {
                ZERO
            };
            checkpoint.installation_storage_commit_sequence = if missing_installation_or_predecessor
            {
                0
            } else {
                1
            };
            replace_checkpoint(fixture.engine_mut()?, 1, checkpoint)?;
            assert_eq!(
                fixture.engine()?.verify_integrity_ledger(),
                Err(StorageError::StaleState)
            );
        }

        let mut fixture = EngineFixture::create()?;
        let mut checkpoint = active_checkpoint(fixture.engine()?)?;
        checkpoint.tracked_state_digest = StorageDigest::from_bytes([36; 32]);
        replace_checkpoint(fixture.engine_mut()?, 0, checkpoint)?;
        assert_eq!(
            fixture.engine()?.verify_integrity_ledger(),
            Err(StorageError::StaleState)
        );
        drop(fixture);

        let mut fixture = EngineFixture::create()?;
        let mut checkpoint = active_checkpoint(fixture.engine()?)?;
        checkpoint.tracked_record_count += 1;
        checkpoint.cut_nonce_draw_high_water += 1;
        checkpoint.installation_nonce_reservation_start += 1;
        checkpoint.installation_nonce_draw_high_water += 1;
        replace_checkpoint(fixture.engine_mut()?, 0, checkpoint)?;
        let engine = fixture.engine_mut()?;
        let mut state = *engine.state_meta.tbs();
        state.nonce_draw_high_water += 1;
        authenticate_state(engine, state)?;
        assert_eq!(
            engine.verify_integrity_ledger(),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn integrity_ledger_rejects_installation_sequence_beyond_the_state_head()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let mut checkpoint = active_checkpoint(fixture.engine()?)?;
        checkpoint.installation_manifest_sequence = 1;
        replace_checkpoint(fixture.engine_mut()?, 0, checkpoint)?;
        assert_eq!(
            fixture.engine()?.verify_integrity_ledger(),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn batch_head_validation_binds_every_authenticated_counter_and_ceiling()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let head = current_head(engine);
        let accounting = current_accounting(engine);
        let valid = mutation_batch(head, accounting)?;
        engine.validate_batch_head(&valid)?;

        let mut wrong = head;
        wrong.expected_storage_commit_sequence += 1;
        let batch = mutation_batch(wrong, accounting)?;
        assert_eq!(
            engine.validate_batch_head(&batch),
            Err(StorageError::StaleState)
        );

        let mut wrong = head;
        wrong.expected_state_generation += 1;
        wrong.resulting_state_generation += 1;
        let batch = mutation_batch(wrong, accounting)?;
        assert_eq!(
            engine.validate_batch_head(&batch),
            Err(StorageError::StaleState)
        );

        let mut wrong = head;
        wrong.expected_account_service_response_count += 1;
        wrong.resulting_account_service_response_count += 1;
        let batch = mutation_batch(wrong, accounting)?;
        assert_eq!(
            engine.validate_batch_head(&batch),
            Err(StorageError::StaleState)
        );

        let logical_mismatch = StorageAccountingLimits {
            current_logical_database_bytes: accounting.current_logical_database_bytes + 1,
            ..accounting
        };
        let batch = mutation_batch(head, logical_mismatch)?;
        assert_eq!(
            engine.validate_batch_head(&batch),
            Err(StorageError::StaleState)
        );
        let backup_mismatch = StorageAccountingLimits {
            current_backup_stream_bytes: accounting.current_backup_stream_bytes + 1,
            ..accounting
        };
        let batch = mutation_batch(head, backup_mismatch)?;
        assert_eq!(
            engine.validate_batch_head(&batch),
            Err(StorageError::StaleState)
        );

        engine.limits.database_max_bytes = valid.resulting_logical_database_bytes() - 1;
        assert_eq!(
            engine.validate_batch_head(&valid),
            Err(StorageError::StaleState)
        );
        engine.limits.database_max_bytes = accounting.database_max_bytes;
        engine.limits.backup_max_bytes = valid.resulting_backup_stream_bytes() - 1;
        assert_eq!(
            engine.validate_batch_head(&valid),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn checkpoint_service_covers_idle_busy_due_and_clean_installation() -> Result<(), StorageError>
    {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        assert!(!engine.checkpoint_due());
        assert!(matches!(engine.service_checkpoint(), Ok(None)));

        let batch = mutation_batch(current_head(engine), current_accounting(engine))?;
        assert!(matches!(engine.commit(batch), CommitOutcome::Committed(_)));
        let retained_manifest_count = engine.retained_manifest_count;
        let retained_manifest_bytes = engine.retained_manifest_bytes;

        engine.retained_manifest_count = engine.limits.integrity_checkpoint_manifests;
        assert!(engine.checkpoint_due());
        engine.retained_manifest_count = retained_manifest_count;
        engine.retained_manifest_bytes = MAX_RETAINED_MANIFEST_BYTES;
        assert!(engine.checkpoint_due());
        engine.retained_manifest_bytes = retained_manifest_bytes;

        engine.start_checkpoint()?;
        assert_eq!(engine.start_checkpoint(), Err(StorageError::QueueFull));
        loop {
            match engine.service_checkpoint() {
                Ok(Some(_receipt)) => break,
                Ok(None) => {}
                Err(EngineCommitFailure::Rejected(error)) => return Err(error),
                Err(EngineCommitFailure::Indeterminate) => {
                    let _integrity_result = engine.verify_integrity_ledger();
                    let _startup_result = engine.startup_scan();
                    return Err(StorageError::Unavailable);
                }
            }
        }
        assert!(!engine.checkpoint_is_active());
        engine.verify_integrity_ledger()?;
        Ok(())
    }

    #[test]
    fn checkpoint_cut_and_accounting_reject_each_independent_mismatch() -> Result<(), StorageError>
    {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let state = *engine.state_meta.tbs();
        engine.verify_checkpoint_cut(&state)?;

        let mut cut = state;
        cut.manifest_sequence += 1;
        assert_eq!(
            engine.verify_checkpoint_cut(&cut),
            Err(StorageError::StaleState)
        );
        let mut cut = state;
        cut.checkpoint_manifest_sequence += 1;
        assert_eq!(
            engine.verify_checkpoint_cut(&cut),
            Err(StorageError::StaleState)
        );
        let mut cut = state;
        cut.checkpoint_hash = StorageDigest::from_bytes([42; 32]);
        assert_eq!(
            engine.verify_checkpoint_cut(&cut),
            Err(StorageError::StaleState)
        );
        let mut cut = state;
        cut.latest_manifest_hash = StorageDigest::from_bytes([43; 32]);
        assert_eq!(
            engine.verify_checkpoint_cut(&cut),
            Err(StorageError::StaleState)
        );

        let checkpoint_record = vec![0; crate::MIN_SEALED_RECORD_BYTES];
        let limits = StorageRuntimeLimits::from_engine(engine.limits)?;
        assert!(
            engine
                .checkpoint_accounting(state, &checkpoint_record, (0, 0), limits)
                .is_ok()
        );
        let mut overflowing = state;
        overflowing.logical_database_bytes = u64::MAX;
        assert_eq!(
            engine.checkpoint_accounting(overflowing, &checkpoint_record, (0, 0), limits),
            Err(StorageError::Overflow)
        );
        assert_eq!(
            engine.checkpoint_accounting(state, &checkpoint_record, (u64::MAX, 0), limits),
            Err(StorageError::Overflow)
        );
        let database_too_small = StorageRuntimeLimits {
            database_max_bytes: 1,
            ..limits
        };
        assert_eq!(
            engine.checkpoint_accounting(state, &checkpoint_record, (0, 0), database_too_small,),
            Err(StorageError::LimitExceeded)
        );
        let backup_too_small = StorageRuntimeLimits {
            backup_max_bytes: 1,
            ..limits
        };
        assert_eq!(
            engine.checkpoint_accounting(state, &checkpoint_record, (0, 0), backup_too_small),
            Err(StorageError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn existing_record_verification_rejects_length_schema_and_identifier_mismatches()
    -> Result<(), StorageError> {
        let master = StorageMasterKey::from_bytes([44; 32]);
        let binding = DatabaseBinding::new(
            NetworkId::from_bytes([45; 32]),
            ServerId::from_bytes([46; 16]),
            ServerIncarnation::from_bytes([47; 16]),
            DatabaseId::from_bytes([48; 16]),
        );
        let key = StoredKey::new(AccountRandomId::from_bytes([49; 16]).to_text().into_bytes())?;
        let encoded = StorageSealContext::new(&master, binding, 1)?
            .seal(TableId::Account, 1, [50; 24], &key, b"record")?
            .encode()?;
        let sealed = SealedRecord::decode(&encoded)?;
        let expected = ExistingRecord::new(1, sealed.record_id()?, encoded.len())?;
        verify_existing(expected, &encoded)?;
        assert_eq!(
            verify_existing(
                ExistingRecord::new(1, sealed.record_id()?, encoded.len() + 1)?,
                &encoded,
            ),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            verify_existing(
                ExistingRecord::new(2, sealed.record_id()?, encoded.len())?,
                &encoded,
            ),
            Err(StorageError::StaleState)
        );
        assert_eq!(
            verify_existing(
                ExistingRecord::new(1, StorageDigest::from_bytes([51; 32]), encoded.len(),)?,
                &encoded,
            ),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn read_only_inspection_matches_startup_without_persistent_changes() -> Result<(), StorageError>
    {
        let mut fixture = EngineFixture::create()?;
        let expected = fixture.engine()?.startup_scan()?;
        drop(fixture.engine.take());
        let writer_lock = fixture.path.join("writer.lock");
        std::fs::remove_file(&writer_lock).map_err(crate::filesystem_rejected)?;
        for name in [
            format!(".agenc-recovery-scratch-v1-{}", "a".repeat(32)),
            format!(".rollback.guard.agenc-tmp-v1-{}", "b".repeat(32)),
        ] {
            let _file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(fixture.path.join(name))
                .map_err(crate::filesystem_rejected)?;
        }
        let before = directory_fingerprint(&fixture.path)?;

        let inspected = inspect_storage(inspection_config(&fixture.path)?)?;
        assert_recovered_durable_facts_match(inspected, expected);
        let first = StorageEngine::open_inspection(inspection_config(&fixture.path)?)?;
        let second = StorageEngine::open_inspection(inspection_config(&fixture.path)?)?;
        assert_recovered_durable_facts_match(first.startup_scan()?, expected);
        assert_recovered_durable_facts_match(second.startup_scan()?, expected);
        drop(first);
        drop(second);

        assert_eq!(directory_fingerprint(&fixture.path)?, before);
        assert!(!writer_lock.exists());
        Ok(())
    }

    #[test]
    fn read_only_inspection_rejects_a_live_writer() -> Result<(), StorageError> {
        let fixture = EngineFixture::create()?;
        assert_eq!(
            inspect_storage(inspection_config(&fixture.path)?).err(),
            Some(StorageError::DatabaseRejected)
        );
        Ok(())
    }

    #[test]
    fn read_only_inspection_validates_both_guard_successors_without_installing_them()
    -> Result<(), StorageError> {
        for (guard_occurrence, expected_commit_sequence) in [(1, 0), (2, 1)] {
            let faults = StorageFaultInjector::new(
                StorageFaultCase {
                    site: StorageFaultSite::GuardTemporaryCreate,
                    boundary: StorageFaultBoundary::Before,
                },
                u64::MAX,
            )?;
            let mut fixture = EngineFixture::create_with_faults(faults.clone())?;
            faults.arm_after_current(guard_occurrence)?;
            let batch = EngineFixture::advancing_batch(fixture.engine()?, 91)?;
            assert!(!matches!(
                fixture.engine_mut()?.commit(batch),
                CommitOutcome::Committed(_)
            ));
            faults.verify_fired()?;
            drop(fixture.engine.take());
            let guard_path = fixture.path.join("rollback.guard");
            let guard_before = std::fs::read(&guard_path).map_err(crate::filesystem_rejected)?;

            let recovered = inspect_storage(inspection_config(&fixture.path)?)?;
            assert_eq!(
                recovered.storage_commit_sequence(),
                expected_commit_sequence
            );
            assert_eq!(
                std::fs::read(guard_path).map_err(crate::filesystem_rejected)?,
                guard_before
            );
        }
        Ok(())
    }

    #[test]
    fn startup_scan_rejects_authenticated_accounting_and_untracked_singleton_corruption()
    -> Result<(), StorageError> {
        for logical in [true, false] {
            let mut fixture = EngineFixture::create()?;
            let engine = fixture.engine_mut()?;
            let mut state = *engine.state_meta.tbs();
            if logical {
                state.logical_database_bytes += 1;
            } else {
                state.backup_stream_bytes += 1;
            }
            authenticate_state(engine, state)?;
            assert_eq!(engine.startup_scan(), Err(StorageError::StaleState));
        }

        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        commit_rows(
            engine,
            &[RedbWrite {
                table: TableId::KeyCheck,
                key: KEY_CHECK_KEY,
                value: None,
            }],
        )?;
        assert_eq!(engine.startup_scan(), Err(StorageError::StaleState));
        Ok(())
    }

    #[test]
    fn recovered_private_index_binding_authenticates_both_semantic_key_types()
    -> Result<(), StorageError> {
        let fixture = EngineFixture::create()?;
        let engine = fixture.engine()?;
        for (table, spelling) in [
            (TableId::NicknameReservation, b"Nickname".as_slice()),
            (TableId::ChannelName, b"#Channel".as_slice()),
        ] {
            let body = if table == TableId::ChannelName {
                crate::domain_records::fixtures::channel_name_body(1, "#Channel")?
            } else {
                spelling.to_vec()
            };
            let value = PersistentRecordValue::new(table, 1, 1, 0, None, Vec::new(), body)?;
            let semantic = if table == TableId::NicknameReservation {
                Nickname::parse(
                    std::str::from_utf8(spelling).map_err(|_| StorageError::InvalidEncoding)?,
                )
                .map_err(|_| StorageError::InvalidEncoding)?
                .canonical()
                .as_bytes()
                .to_vec()
            } else {
                ChannelName::parse(
                    std::str::from_utf8(spelling).map_err(|_| StorageError::InvalidEncoding)?,
                )
                .map_err(|_| StorageError::InvalidEncoding)?
                .canonical()
                .as_bytes()
                .to_vec()
            };
            let expected = derive_storage_index(
                &engine.master_key,
                engine.binding,
                StorageTable::new(table.as_u16())?,
                engine.header.tbs().storage_key_generation,
                &semantic,
            )?;
            let key = StoredKey::new(expected.expose_for_storage_key().to_vec())?;
            engine.validate_recovered_index_binding(table, &key, &value)?;
            assert_eq!(
                engine.validate_recovered_index_binding(
                    table,
                    &StoredKey::new(vec![0; 32])?,
                    &value,
                ),
                Err(StorageError::AuthenticationFailed)
            );
        }
        let account = PersistentRecordValue::new(
            TableId::Account,
            1,
            1,
            1,
            None,
            Vec::new(),
            crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
        )?;
        let account_key =
            StoredKey::new(AccountRandomId::from_bytes([1; 16]).to_text().into_bytes())?;
        engine.validate_recovered_index_binding(TableId::Account, &account_key, &account)?;
        Ok(())
    }

    #[test]
    fn reference_authority_matrix_is_closed_for_every_table_pair() -> Result<(), StorageError> {
        let legal = [
            (TableId::Account, TableId::OpaqueRecord),
            (TableId::OpaqueRecord, TableId::Account),
            (TableId::AuthTransaction, TableId::Account),
            (TableId::AuthTransaction, TableId::OpaqueRecord),
            (TableId::AuthTransaction, TableId::RegistrationInvite),
            (TableId::NicknameReservation, TableId::Account),
            (TableId::RegistrationInvite, TableId::Account),
            (TableId::RegistrationInvite, TableId::AuthTransaction),
            (TableId::Session, TableId::Account),
            (TableId::Session, TableId::Channel),
            (TableId::Channel, TableId::Account),
            (TableId::Channel, TableId::Session),
            (TableId::Channel, TableId::RegistrationInvite),
            (TableId::ChannelName, TableId::Channel),
            (TableId::Sanction, TableId::Account),
            (TableId::Sanction, TableId::Session),
            (TableId::Sanction, TableId::Channel),
            (TableId::FederationPeer, TableId::E2eeState),
            (TableId::FederationOrigin, TableId::FederationPeer),
            (TableId::RequestResult, TableId::FederationPeer),
            (TableId::RequestResult, TableId::FederationOrigin),
            (TableId::RequestResult, TableId::EdgeOutbox),
            (TableId::RequestResult, TableId::E2eeState),
            (TableId::EdgeOutbox, TableId::FederationPeer),
            (TableId::EdgeOutbox, TableId::RequestResult),
            (TableId::EdgeOutbox, TableId::E2eeObject),
            (TableId::EdgeOutbox, TableId::E2eeState),
            (TableId::EdgeProjection, TableId::FederationPeer),
            (TableId::EdgeProjection, TableId::Account),
            (TableId::EdgeProjection, TableId::Session),
            (TableId::EdgeProjection, TableId::Channel),
            (TableId::EdgeProjection, TableId::E2eeState),
            (TableId::History, TableId::Channel),
            (TableId::Audit, TableId::Account),
            (TableId::Audit, TableId::Session),
            (TableId::Audit, TableId::Channel),
            (TableId::Audit, TableId::Sanction),
            (TableId::Audit, TableId::FederationPeer),
            (TableId::Audit, TableId::E2eeState),
            (TableId::AuditCheckpoint, TableId::Audit),
            (TableId::E2eeObject, TableId::Account),
            (TableId::E2eeObject, TableId::Channel),
            (TableId::E2eeObject, TableId::E2eeState),
            (TableId::E2eeState, TableId::Account),
            (TableId::E2eeState, TableId::Channel),
            (TableId::E2eeState, TableId::FederationPeer),
            (TableId::E2eeState, TableId::E2eeObject),
            (TableId::E2eeState, TableId::E2eeState),
        ];
        for source in 0_u16..=26 {
            let source = TableId::from_u16(source)?;
            for target in 0_u16..=26 {
                let target = TableId::from_u16(target)?;
                assert_eq!(
                    std::hint::black_box(reference_is_legal(source, target)),
                    legal.contains(&(source, target)),
                    "unexpected reference authority: {source:?} -> {target:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn record_reference_decoder_covers_every_login_arm_and_non_domain_table()
    -> Result<(), StorageError> {
        let network = NetworkId::from_bytes([61; 32]);
        let login_key = LoginIndexKey::from_bytes([62; 32]);
        let normalized = NormalizedLogin::prepare("reference-matrix")
            .map_err(|_| StorageError::InvalidEncoding)?;
        let stored = LoginIndexStoredKey::new(
            1,
            derive_login_index(&login_key, network, &normalized).map_err(StorageError::from)?,
        )?;
        let stored_key = stored.encode()?;
        let account = AccountRandomId::from_bytes([63; 16]).to_account_id();
        let values = [
            LoginIndexValue::new(
                &stored,
                LoginIndexValueKind::Live {
                    account_id: account,
                    opaque_credential_id: OpaqueCredentialId::from_bytes([64; 32]),
                },
            )?,
            LoginIndexValue::new(
                &stored,
                LoginIndexValueKind::CreationReservation {
                    transaction_id: TransactionId::from_bytes([65; 16]),
                    expires_at: 1,
                },
            )?,
            LoginIndexValue::new(
                &stored,
                LoginIndexValueKind::DeletionTombstone {
                    deleted_account_id: account,
                    expires_at: 2,
                },
            )?,
        ];
        assert_eq!(
            record_references(TableId::LoginIndex, &stored_key, &values[0].encode()?)?.len(),
            2
        );
        assert_eq!(
            record_references(TableId::LoginIndex, &stored_key, &values[1].encode()?)?.len(),
            1
        );
        assert_eq!(
            record_references(TableId::LoginIndex, &stored_key, &values[2].encode()?)?.len(),
            1
        );
        assert!(
            record_references(
                TableId::KeyCheck,
                &StoredKey::new(KEY_CHECK_KEY.to_vec())?,
                &[0; 32]
            )?
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn engine_read_construction_source_and_completion_helpers_cover_live_state()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let batch = mutation_batch(current_head(engine), current_accounting(engine))?;
        assert!(matches!(engine.commit(batch), CommitOutcome::Committed(_)));

        let key = StoredKey::new(AccountRandomId::from_bytes([40; 16]).to_text().into_bytes())?;
        assert_eq!(
            engine
                .read(&ReadPlan::exact(
                    TableId::Account,
                    StoredKey::new(key.as_bytes().to_vec())?
                ))?
                .records
                .len(),
            1
        );
        assert!(
            engine
                .read(&ReadPlan::exact(
                    TableId::Account,
                    account_key_for_test(66)?
                ))?
                .records
                .is_empty()
        );
        let range = ReadPlan::range(
            TableId::Account,
            StoredKey::new(vec![0])?,
            StoredKey::new(vec![u8::MAX; 64])?,
            4,
        )?;
        assert_eq!(engine.read(&range)?.records.len(), 1);
        assert!(
            engine
                .construction_existing(TableId::Account, &key)?
                .is_some()
        );
        assert!(
            engine
                .construction_existing(TableId::Account, &account_key_for_test(67)?)?
                .is_none()
        );
        assert_eq!(
            engine.construction_marker().map(|_| ()),
            Err(StorageError::StaleState)
        );

        let mut visited = 0_u64;
        let mut captured = None;
        engine.visit_construction_source_records(|source, _record| {
            visited = visited.checked_add(1).ok_or(StorageError::Overflow)?;
            if captured.is_none() {
                captured = Some(source);
            }
            Ok(())
        })?;
        assert!(visited >= 2);
        let source = captured.ok_or(StorageError::StaleState)?;
        engine.open_construction_source_record(&source)?;
        let missing = StorageConstructionSource::new(
            crate::StorageConstructionSourceKind::DatabaseRecord,
            TableId::Account,
            account_key_for_test(68)?,
            1,
            ZERO,
            0,
        )?;
        assert_eq!(
            engine.open_construction_source_record(&missing).map(|_| ()),
            Err(StorageError::StaleState)
        );
        let backup_source = StorageConstructionSource::new(
            crate::StorageConstructionSourceKind::BackupRecord,
            TableId::Account,
            account_key_for_test(69)?,
            1,
            ZERO,
            1,
        )?;
        assert_eq!(
            engine
                .open_construction_source_record(&backup_source)
                .map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );

        assert!(
            engine
                .login_index_transition_preflight(
                    LoginIndexKey::from_bytes([70; 32]).key_id(engine.header.tbs().network_id)
                )
                .is_ok()
        );
        let mut expected_identity = completion().identity;
        expected_identity.transform_profile_hash =
            agenc_ircd_crypto::rekey_transform_profile_hash()?;
        expected_identity.target_database_header_hash = engine.header.complete_hash()?;
        expected_identity.target_database_instance_id = engine.header.tbs().database_instance_id;
        assert_eq!(
            engine.completed_construction(expected_identity).map(|_| ()),
            Err(StorageError::StaleState)
        );

        let state = *engine.state_meta.tbs();
        let mut valid = completion();
        valid.finalization_storage_commit_sequence = state.storage_commit_sequence;
        valid.finalization_manifest_sequence = state.manifest_sequence;
        valid.finalization_state_generation = state.state_generation;
        valid.finalization_account_service_response_count = state.account_service_response_count;
        valid.finalization_nonce_draw_high_water = state.nonce_draw_high_water;
        engine.verify_uncheckpointed_completion(&valid)?;
        let mut invalid = completion();
        for changed in 0..6 {
            invalid.finalization_storage_commit_sequence = state.storage_commit_sequence;
            invalid.finalization_manifest_sequence = state.manifest_sequence;
            invalid.finalization_state_generation = state.state_generation;
            invalid.finalization_account_service_response_count =
                state.account_service_response_count;
            invalid.finalization_nonce_draw_high_water = state.nonce_draw_high_water;
            match changed {
                0 => invalid.finalization_storage_commit_sequence += 1,
                1 => invalid.finalization_manifest_sequence += 1,
                2 => invalid.finalization_state_generation += 1,
                3 => invalid.finalization_account_service_response_count += 1,
                4 => invalid.finalization_nonce_draw_high_water += 1,
                _ => invalid.finalization_manifest_sequence = state.checkpoint_manifest_sequence,
            }
            assert_eq!(
                engine.verify_uncheckpointed_completion(&invalid),
                Err(StorageError::ResumeMismatch)
            );
        }
        engine.finish_construction()?;
        Ok(())
    }

    #[test]
    fn open_rejects_each_expected_server_identity_mismatch() -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        drop(fixture.engine.take());
        let correct_network = NetworkId::from_bytes([21; 32]);
        let correct_server = ServerId::from_bytes([22; 16]);
        assert!(matches!(
            StorageEngine::open(reopen_config(
                &fixture.path,
                NetworkId::from_bytes([90; 32]),
                correct_server,
            )?),
            Err(StorageError::AuthenticationFailed)
        ));
        assert!(matches!(
            StorageEngine::open(reopen_config(
                &fixture.path,
                correct_network,
                ServerId::from_bytes([91; 16]),
            )?),
            Err(StorageError::AuthenticationFailed)
        ));
        assert!(
            StorageEngine::open(reopen_config(
                &fixture.path,
                correct_network,
                correct_server,
            )?)
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn prepare_application_covers_replacement_deletion_and_nonce_mismatch()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let key = account_key_for_test(92)?;
        let initial = batch_with(
            engine,
            RecordMutation::put(
                TableId::Account,
                StoredKey::new(key.as_bytes().to_vec())?,
                1,
                None,
                account_plaintext(1)?,
            )?,
        )?;
        assert_eq!(
            engine.prepare_application(&initial, &[]).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        assert!(matches!(
            engine.commit(initial),
            CommitOutcome::Committed(_)
        ));

        let existing = existing_record(engine, TableId::Account, &key)?;
        let replacement = batch_with(
            engine,
            RecordMutation::put(
                TableId::Account,
                StoredKey::new(key.as_bytes().to_vec())?,
                1,
                Some(existing),
                account_plaintext(2)?,
            )?,
        )?;
        engine.validate_existing_records(&replacement)?;
        assert!(matches!(
            engine.commit(replacement),
            CommitOutcome::Committed(_)
        ));

        let existing = existing_record(engine, TableId::Account, &key)?;
        let deletion = batch_with(
            engine,
            RecordMutation::delete(
                TableId::Account,
                StoredKey::new(key.as_bytes().to_vec())?,
                existing,
            ),
        )?;
        engine.validate_existing_records(&deletion)?;
        assert!(matches!(
            engine.commit(deletion),
            CommitOutcome::Committed(_)
        ));
        Ok(())
    }

    #[test]
    fn prepared_accounting_verification_rejects_a_drifted_sealed_length() -> Result<(), StorageError>
    {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let batch = mutation_batch(current_head(engine), current_accounting(engine))?;
        let nonces =
            draw_nonces_with_faults(batch.seal_count(), &StorageFaultInjector::disabled())?;
        // Preparation binds the manifest to the reserved nonce block, so reserve it first.
        let (reserved, _charged) = engine
            .reserve_nonce_block(batch.seal_count(), full_allowance())
            .map_err(|_| StorageError::Unavailable)?;
        let reserved_guard = engine
            .install_reserved_guard(&reserved)
            .map_err(|_| StorageError::Unavailable)?;
        engine.reservation = reserved;
        engine.guard = reserved_guard;
        let mut prepared = engine.prepare_application(&batch, &nonces)?;
        verify_prepared_accounting(&batch, &prepared)?;
        prepared.manifest_record.push(0);
        assert_eq!(
            verify_prepared_accounting(&batch, &prepared),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn existing_record_validation_rejects_both_presence_mismatches_and_manifest_collision()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let key = account_key_for_test(95)?;
        let before_insert = batch_with(
            engine,
            RecordMutation::put(
                TableId::Account,
                StoredKey::new(key.as_bytes().to_vec())?,
                1,
                None,
                account_plaintext(1)?,
            )?,
        )?;
        let committed = batch_with(
            engine,
            RecordMutation::put(
                TableId::Account,
                StoredKey::new(key.as_bytes().to_vec())?,
                1,
                None,
                account_plaintext(1)?,
            )?,
        )?;
        assert!(matches!(
            engine.commit(committed),
            CommitOutcome::Committed(_)
        ));
        assert_eq!(
            engine.validate_existing_records(&before_insert),
            Err(StorageError::StaleState)
        );

        let existing = existing_record(engine, TableId::Account, &key)?;
        let missing = account_key_for_test(96)?;
        let expects_present = batch_with(
            engine,
            RecordMutation::delete(TableId::Account, missing, existing),
        )?;
        assert_eq!(
            engine.validate_existing_records(&expects_present),
            Err(StorageError::StaleState)
        );

        let next_manifest = engine.state_meta.tbs().manifest_sequence + 1;
        commit_rows(
            engine,
            &[RedbWrite {
                table: TableId::IntegrityManifest,
                key: &next_manifest.to_be_bytes(),
                value: Some(b"collision"),
            }],
        )?;
        let valid_existing = existing_record(engine, TableId::Account, &key)?;
        let otherwise_valid = batch_with(
            engine,
            RecordMutation::delete(
                TableId::Account,
                StoredKey::new(key.as_bytes().to_vec())?,
                valid_existing,
            ),
        )?;
        assert_eq!(
            engine.validate_existing_records(&otherwise_valid),
            Err(StorageError::StaleState)
        );
        Ok(())
    }

    #[test]
    fn manifest_ceiling_and_construction_counter_overflows_fail_closed() -> Result<(), StorageError>
    {
        for use_bytes in [false, true] {
            let mut fixture = EngineFixture::create()?;
            let engine = fixture.engine_mut()?;
            let batch = mutation_batch(current_head(engine), current_accounting(engine))?;
            if use_bytes {
                engine.retained_manifest_bytes = MAX_RETAINED_MANIFEST_BYTES;
            } else {
                engine.retained_manifest_count = MAX_RETAINED_MANIFESTS;
                engine.limits.integrity_checkpoint_manifests = MAX_RETAINED_MANIFESTS + 1;
                assert!(engine.checkpoint_due());
            }
            assert!(matches!(
                engine.commit(batch),
                CommitOutcome::Rejected(StorageError::LimitExceeded)
            ));
        }

        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let original_state = *engine.state_meta.tbs();
        let mut overflow = original_state;
        overflow.storage_commit_sequence = u64::MAX;
        assert_eq!(authenticate_state(engine, overflow), Ok(()));
        assert_eq!(engine.construction_counters(), Err(StorageError::Overflow));
        overflow = original_state;
        overflow.manifest_sequence = u64::MAX;
        assert_eq!(authenticate_state(engine, overflow), Ok(()));
        assert_eq!(engine.construction_counters(), Err(StorageError::Overflow));
        assert_eq!(authenticate_state(engine, original_state), Ok(()));
        Ok(())
    }

    #[test]
    fn integrity_ledger_rejects_every_manifest_chain_field_independently()
    -> Result<(), StorageError> {
        for changed in 0..10 {
            let mut fixture = EngineFixture::create()?;
            let engine = fixture.engine_mut()?;
            let first = advancing_batch(engine, 247)?;
            assert!(matches!(engine.commit(first), CommitOutcome::Committed(_)));
            let second = advancing_batch(engine, 248)?;
            assert!(matches!(engine.commit(second), CommitOutcome::Committed(_)));
            let mut manifest = active_manifest(engine)?;
            match changed {
                0 => manifest.database_instance_id = DatabaseId::from_bytes([249; 16]),
                1 => manifest.manifest_sequence += 1,
                2 => manifest.previous_manifest_hash = StorageDigest::from_bytes([250; 32]),
                3 => manifest.previous_state_generation += 1,
                4 => manifest.previous_account_service_response_count += 1,
                5 => manifest.storage_commit_sequence += 1,
                6 => manifest.previous_nonce_draw_high_water = 0,
                7 => {
                    manifest.resulting_state_generation = manifest
                        .previous_state_generation
                        .checked_sub(1)
                        .ok_or(StorageError::Overflow)?;
                }
                8 => {
                    manifest.resulting_state_generation = manifest
                        .previous_state_generation
                        .checked_add(
                            u64::try_from(crate::MAX_TRANSACTION_PLANS)
                                .map_err(|_| StorageError::Overflow)?,
                        )
                        .and_then(|value| value.checked_add(1))
                        .ok_or(StorageError::Overflow)?;
                }
                _ => {
                    manifest.resulting_account_service_response_count = manifest
                        .previous_account_service_response_count
                        .checked_sub(1)
                        .ok_or(StorageError::Overflow)?;
                }
            }
            replace_manifest(engine, manifest)?;
            assert_eq!(
                engine.verify_integrity_ledger(),
                Err(StorageError::StaleState)
            );
        }
        Ok(())
    }

    #[test]
    fn storage_engine_limits_reject_backup_maximum_above_protocol_ceiling() {
        assert_eq!(
            StorageEngineLimits {
                backup_max_bytes: MAX_STORAGE_BYTES + 1,
                ..engine_limits()
            }
            .validate(),
            Err(StorageError::LimitExceeded)
        );
    }

    fn account_key_for_test(byte: u8) -> Result<StoredKey, StorageError> {
        StoredKey::new(
            AccountRandomId::from_bytes([byte; 16])
                .to_text()
                .into_bytes(),
        )
    }

    #[test]
    fn active_backup_rejects_competing_backup_and_checkpoint_jobs() -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let backup_directory = fixture.path.join("backups");
        std::fs::create_dir(&backup_directory).map_err(crate::filesystem_rejected)?;
        std::fs::set_permissions(
            &backup_directory,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .map_err(crate::filesystem_rejected)?;
        let engine = fixture.engine_mut()?;
        engine.start_backup(
            BackupDestination::new(&backup_directory, "first.backup")?,
            Ed25519SecretKey::from_bytes([101; 32]),
            1,
            [102; 16],
        )?;
        assert_eq!(
            engine.start_backup(
                BackupDestination::new(&backup_directory, "second.backup")?,
                Ed25519SecretKey::from_bytes([103; 32]),
                2,
                [104; 16],
            ),
            Err(StorageError::QueueFull),
        );
        assert_eq!(engine.start_checkpoint(), Err(StorageError::QueueFull));
        Ok(())
    }

    #[test]
    fn checkpoint_retirement_and_ledger_inventory_fail_closed_at_exact_boundaries()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let batch = advancing_batch(engine, 105)?;
        assert!(matches!(engine.commit(batch), CommitOutcome::Committed(_)));
        let cut = *engine.state_meta.tbs();
        engine.verify_checkpoint_cut(&cut)?;
        let mut wrong_hash = cut;
        wrong_hash.latest_manifest_hash = StorageDigest::from_bytes([106; 32]);
        assert_eq!(
            engine.verify_checkpoint_cut(&wrong_hash),
            Err(StorageError::StaleState),
        );

        let second_manifest_key = 2_u64.to_be_bytes();
        let second_checkpoint_key = 1_u64.to_be_bytes();
        let placeholder = vec![0_u8; crate::MIN_SEALED_RECORD_BYTES];
        commit_rows(
            engine,
            &[
                RedbWrite {
                    table: TableId::IntegrityManifest,
                    key: &second_manifest_key,
                    value: Some(&placeholder),
                },
                RedbWrite {
                    table: TableId::IntegrityCheckpoint,
                    key: &second_checkpoint_key,
                    value: Some(&placeholder),
                },
            ],
        )?;
        let limits = StorageRuntimeLimits::from_engine(engine.limits)?;
        let retired = engine.checkpoint_retired_charges(0_u64.to_be_bytes(), 1, limits)?;
        assert!(retired.0 > 0);
        assert!(retired.1 > retired.0);
        drop(fixture);

        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let first_extra_key = 1_u64.to_be_bytes();
        let second_extra_key = 2_u64.to_be_bytes();
        let placeholder = vec![0_u8; crate::MIN_SEALED_RECORD_BYTES];
        commit_rows(
            engine,
            &[
                RedbWrite {
                    table: TableId::IntegrityCheckpoint,
                    key: &first_extra_key,
                    value: Some(&placeholder),
                },
                RedbWrite {
                    table: TableId::IntegrityCheckpoint,
                    key: &second_extra_key,
                    value: Some(&placeholder),
                },
            ],
        )?;
        assert_eq!(
            engine.verify_integrity_ledger(),
            Err(StorageError::LimitExceeded),
        );
        Ok(())
    }

    #[test]
    fn open_rejects_manifest_inventory_and_key_check_identifier_corruption()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let manifest_key = 1_u64.to_be_bytes();
        let placeholder = vec![0_u8; crate::MIN_SEALED_RECORD_BYTES];
        commit_rows(
            engine,
            &[RedbWrite {
                table: TableId::IntegrityManifest,
                key: &manifest_key,
                value: Some(&placeholder),
            }],
        )?;
        drop(fixture.engine.take());
        assert!(matches!(
            StorageEngine::open(reopen_config(
                &fixture.path,
                NetworkId::from_bytes([21; 32]),
                ServerId::from_bytes([22; 16]),
            )?),
            Err(StorageError::StaleState),
        ));
        drop(fixture);

        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let key = StoredKey::new(KEY_CHECK_KEY.to_vec())?;
        let replacement = StorageSealContext::new(
            &StorageMasterKey::from_bytes([27; 32]),
            engine.binding,
            engine.header.tbs().storage_key_generation,
        )?
        .seal(TableId::KeyCheck, 1, [107; 24], &key, &[108; 32])?
        .encode()?;
        commit_rows(
            engine,
            &[RedbWrite {
                table: TableId::KeyCheck,
                key: KEY_CHECK_KEY,
                value: Some(&replacement),
            }],
        )?;
        drop(fixture.engine.take());
        assert!(matches!(
            StorageEngine::open(reopen_config(
                &fixture.path,
                NetworkId::from_bytes([21; 32]),
                ServerId::from_bytes([22; 16]),
            )?),
            Err(StorageError::AuthenticationFailed),
        ));
        Ok(())
    }

    /// Reopens a fixture's directory with a qualification growth cap on every operation.
    fn reopen_with_cap(path: &std::path::Path, cap: u64) -> Result<StorageEngine, StorageError> {
        let qualifications = vec![test_qualification(path)?];
        StorageEngine::open(StorageOpenConfig {
            expected_network_id: NetworkId::from_bytes([21; 32]),
            expected_server_id: ServerId::from_bytes([22; 16]),
            state_directory: StateDirectory::open_with_faults(
                path,
                &qualifications,
                StorageFaultInjector::disabled().with_growth_cap(cap),
            )?,
            storage_master_key: StorageMasterKey::from_bytes([27; 32]),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes([28; 32]),
            login_index_key: LoginIndexKey::from_bytes([23; 32]),
            previous_login_index_key: None,
            limits: engine_limits(),
        })
    }

    fn reopen(path: &std::path::Path) -> Result<StorageEngine, StorageError> {
        StorageEngine::open(reopen_config(
            path,
            NetworkId::from_bytes([21; 32]),
            ServerId::from_bytes([22; 16]),
        )?)
    }

    fn commit_advancing(
        engine: &mut StorageEngine,
        byte: u8,
    ) -> Result<CommitReceipt, StorageError> {
        let batch = EngineFixture::advancing_batch(engine, byte)?;
        match engine.commit(batch) {
            CommitOutcome::Committed(receipt) => Ok(receipt),
            CommitOutcome::Rejected(error) => Err(error),
            CommitOutcome::Indeterminate => Err(StorageError::Unavailable),
        }
    }

    /// The redb bytes a fresh engine's first state-advancing commit charges, measured once so
    /// the same deterministic commit can be replayed against exactly that cap and one byte less.
    fn first_commit_redb_charge() -> Result<u64, StorageError> {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        commit_advancing(engine, 1)?;
        let guards = crate::bounded::guard_replacement_charge(engine.state_directory.block_size())?
            .checked_mul(2)
            .ok_or(StorageError::Overflow)?;
        engine
            .last_operation_charged_bytes
            .checked_sub(guards)
            .ok_or(StorageError::Overflow)
    }

    #[test]
    fn a_durable_operation_is_charged_against_one_allowance_and_cleans_up()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        let before = engine.statistics()?;
        assert_eq!(before.last_operation_charged_bytes(), 0);
        assert!(before.deferred_cleanup_pending());
        assert_eq!(before.reclaimed_pages_since_open(), 0);

        commit_advancing(engine, 1)?;
        let after = engine.statistics()?;
        let guards = crate::bounded::guard_replacement_charge(engine.state_directory.block_size())?
            .checked_mul(2)
            .ok_or(StorageError::Overflow)?;
        assert!(after.last_operation_charged_bytes() > guards);
        assert!(
            after.last_operation_charged_bytes() <= crate::MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH
        );
        assert!(!after.deferred_cleanup_pending());
        assert!(after.reclaimed_pages_since_open() >= 1);

        // A checkpoint is one more operation under its own allowance with its own cleanup.
        engine.start_checkpoint()?;
        while engine.checkpoint_is_active() {
            engine
                .service_checkpoint()
                .map_err(|_| StorageError::Unavailable)?;
        }
        let checkpointed = engine.statistics()?;
        assert!(checkpointed.last_operation_charged_bytes() > guards);
        assert!(!checkpointed.deferred_cleanup_pending());
        assert!(checkpointed.reclaimed_pages_since_open() > after.reclaimed_pages_since_open());
        Ok(())
    }

    #[test]
    fn the_allowance_boundary_is_exact_and_a_refusal_keeps_the_burned_block()
    -> Result<(), StorageError> {
        let charge = first_commit_redb_charge()?;

        // Exactly the charge fits; nothing remains for the deferred cleanup, which is refused
        // and waits for a later operation.
        let mut exact = EngineFixture::create_with_faults(
            StorageFaultInjector::disabled().with_growth_cap(charge),
        )?;
        let engine = exact.engine_mut()?;
        commit_advancing(engine, 1)?;
        let statistics = engine.statistics()?;
        assert!(statistics.deferred_cleanup_pending());
        assert_eq!(statistics.reclaimed_pages_since_open(), 0);

        // One byte less refuses during preparation: nothing is written, the reserved nonce
        // block is burned exactly as after any rejection past the reservation, and the engine
        // reports no charge for the refused operation.
        let mut short = EngineFixture::create_with_faults(
            StorageFaultInjector::disabled().with_growth_cap(charge - 1),
        )?;
        let engine = short.engine_mut()?;
        let high_water_before = engine.reservation.tbs().nonce_draw_high_water;
        let sequence_before = engine.reservation.tbs().reservation_sequence;
        let batch = EngineFixture::advancing_batch(engine, 1)?;
        let seal_count = u64::from(batch.seal_count());
        assert!(matches!(
            engine.commit(batch),
            CommitOutcome::Rejected(StorageError::AllowanceRefused(AllowancePhase::Preparation))
        ));
        assert_eq!(engine.state_meta.tbs().storage_commit_sequence, 0);
        assert_eq!(
            engine.reservation.tbs().phase,
            RollbackGuardPhase::NonceReserved
        );
        assert_eq!(
            engine.reservation.tbs().reservation_sequence,
            sequence_before + 1
        );
        assert_eq!(
            engine.reservation.tbs().nonce_draw_high_water,
            high_water_before + seal_count
        );
        assert!(
            engine
                .read(&ReadPlan::exact(
                    TableId::Account,
                    EngineFixture::account_key(1)?
                ))?
                .records
                .is_empty()
        );
        assert_eq!(engine.statistics()?.last_operation_charged_bytes(), 0);

        // The reopen reconciles the burned reservation and the next writer starts after it.
        let path = short.path().to_path_buf();
        drop(short.engine.take());
        let mut engine = reopen(&path)?;
        commit_advancing(&mut engine, 1)?;
        assert_eq!(
            engine.reservation.tbs().nonce_draw_high_water,
            high_water_before + seal_count + seal_count
        );
        assert_eq!(engine.state_meta.tbs().storage_commit_sequence, 1);
        Ok(())
    }

    #[test]
    fn an_allowance_that_cannot_hold_the_reservation_burns_nothing() -> Result<(), StorageError> {
        let mut fixture =
            EngineFixture::create_with_faults(StorageFaultInjector::disabled().with_growth_cap(0))?;
        let engine = fixture.engine_mut()?;
        let reservation_before = engine.reservation.encode()?;
        let guard_before = engine.guard.encode()?;
        assert!(matches!(
            commit_advancing(engine, 1),
            Err(StorageError::AllowanceRefused(AllowancePhase::Mutation))
        ));
        assert_eq!(engine.reservation.encode()?, reservation_before);
        assert_eq!(engine.guard.encode()?, guard_before);
        assert_eq!(
            engine.store.read_meta(RESERVATION_META_KEY)?,
            Some(reservation_before)
        );
        assert_eq!(engine.statistics()?.last_operation_charged_bytes(), 0);
        Ok(())
    }

    #[test]
    fn a_checkpoint_refused_by_its_allowance_installs_nothing() -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let path = fixture.path().to_path_buf();
        commit_advancing(fixture.engine_mut()?, 1)?;
        drop(fixture.engine.take());

        let mut engine = reopen_with_cap(&path, 0)?;
        let checkpoint_before = engine.state_meta.tbs().checkpoint_manifest_sequence;
        engine.start_checkpoint()?;
        let outcome = loop {
            match engine.service_checkpoint() {
                Ok(None) => {}
                other => break other,
            }
        };
        assert!(matches!(
            outcome,
            Err(EngineCommitFailure::Rejected(
                StorageError::AllowanceRefused(AllowancePhase::Mutation)
            ))
        ));
        engine.abandon_checkpoint();
        assert_eq!(
            engine.state_meta.tbs().checkpoint_manifest_sequence,
            checkpoint_before
        );
        assert_eq!(engine.state_meta.tbs().storage_commit_sequence, 1);
        Ok(())
    }

    #[test]
    fn deferred_cleanup_waits_for_a_live_reader_and_resumes_after_a_reopen()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let path = fixture.path().to_path_buf();
        let engine = fixture.engine_mut()?;
        commit_advancing(engine, 1)?;
        assert!(!engine.statistics()?.deferred_cleanup_pending());

        // A reader pins the pages the next operation frees: its cleanup reclaims none of them,
        // and they are not eligible, so nothing eligible is reported pending either.
        let reader = engine.store.snapshot()?;
        let reclaimed_before = engine.statistics()?.reclaimed_pages_since_open();
        commit_advancing(engine, 2)?;
        let pinned = engine.statistics()?;
        assert!(!pinned.deferred_cleanup_pending());
        assert_eq!(pinned.reclaimed_pages_since_open(), reclaimed_before);
        drop(reader);

        // An owner that stops without a clean shutdown only persists, so the reopen finds the
        // backlog and the first reclamation drains it.
        engine.close_bounded(false);
        drop(fixture.engine.take());
        let engine = reopen(&path)?;
        assert!(engine.statistics()?.deferred_cleanup_pending());
        let progress = engine
            .store
            .reclaim_deferred(engine.operation_allowance(0)?.allowance())
            .ok()
            .and_then(MaintenanceOutcome::completed)
            .ok_or(StorageError::StaleState)?;
        assert!(progress.records >= 1 && progress.pages >= 1);
        assert!(!progress.remaining);
        Ok(())
    }

    #[test]
    fn a_bounded_close_persists_the_allocator_state_or_leaves_the_repair_to_the_next_open()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let path = fixture.path().to_path_buf();
        let engine = fixture.engine_mut()?;
        commit_advancing(engine, 1)?;
        engine.close_bounded(true);
        drop(fixture.engine.take());

        // A close within its allowance leaves the next open clean.
        let engine = reopen(&path)?;
        assert!(!engine.startup_scan()?.database_repaired());
        drop(engine);

        // A close the free-space gate refuses receives no allowance at all, so it persists
        // nothing and the drop path cannot run its own unmetered transaction; the next open
        // repairs exactly as after a crash and finds the committed state intact.
        let mut engine = reopen(&path)?;
        commit_advancing(&mut engine, 2)?;
        engine.limits.fixed_reserve_bytes =
            u64::MAX - crate::MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH;
        engine.close_bounded(true);
        drop(engine);
        let engine = reopen(&path)?;
        let recovered = engine.startup_scan()?;
        assert!(recovered.database_repaired());
        assert_eq!(recovered.storage_commit_sequence(), 2);
        assert_eq!(engine.state_meta.tbs().storage_commit_sequence, 2);
        Ok(())
    }

    #[test]
    fn idle_open_and_clean_close_cycles_do_not_grow_the_database() -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let path = fixture.path().to_path_buf();
        commit_advancing(fixture.engine_mut()?, 1)?;
        fixture.engine_mut()?.close_bounded(true);
        drop(fixture.engine.take());

        // Every clean close reclaims what the previous close freed before it persists, so a
        // database nobody writes to keeps its length however often it is opened and closed.
        let mut lengths = Vec::new();
        for _ in 0..6 {
            let mut engine = reopen(&path)?;
            assert!(!engine.startup_scan()?.database_repaired());
            engine.close_bounded(true);
            drop(engine);
            lengths.push(
                std::fs::metadata(path.join("database.redb"))
                    .map_err(crate::filesystem_rejected)?
                    .len(),
            );
        }
        let settled = lengths.get(1).copied().ok_or(StorageError::StaleState)?;
        assert!(
            lengths.iter().skip(1).all(|length| *length == settled),
            "idle cycles changed the database length: {lengths:?}"
        );
        Ok(())
    }
}
