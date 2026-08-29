//! Stopped-daemon backup restore composition.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use agenc_ircd_crypto::{
    DatabaseBinding, Ed25519PublicKey, LoginIndexKey, OsEntropy, RollbackGuardRootKey,
    StorageDigest, StorageMasterKey, restore_transform_profile_hash,
};
use agenc_ircd_types::{DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};
use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{
    BackupTrustKey, ConstructionDirectory, ConstructionDirectoryPhase, ConstructionExecutor,
    ConstructionLimits, ConstructionSourceDatabase, ConstructionSourceFacts, ConstructionTarget,
    DatabaseHeader, DatabaseHeaderTbs, InitialStorageRecord, RecoveryTransformV1,
    SCHEMA_GENERATION, StateDirectory, StorageConstruction, StorageConstructionCursor,
    StorageConstructionKind, StorageEngineLimits, StorageError, StorageInitializationConfig,
    StorageInitializationMode, StorageInitializationOutcome, StorageOpenConfig,
    StorageOperationIdentity, StorageQualification, StoredKey, TableId, initialize_storage,
};

const RESTORE_BATCH_RECORDS: usize = 1_000;
const RESTORE_BATCH_BYTES: usize = 16_777_216;
const MAX_RANDOM_ATTEMPTS: usize = 8;

/// One public trust-manifest row admitted by the restore command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreTrustKey {
    key_id: [u8; 32],
    public_key: [u8; 32],
    not_before: u64,
    not_after: u64,
}

impl RestoreTrustKey {
    /// Creates one bounded row for cryptographic validation inside storage.
    pub const fn new(
        key_id: [u8; 32],
        public_key: [u8; 32],
        not_before: u64,
        not_after: u64,
    ) -> Self {
        Self {
            key_id,
            public_key,
            not_before,
            not_after,
        }
    }

    fn validate(self) -> Result<BackupTrustKey, StorageError> {
        BackupTrustKey::with_validity(
            StorageDigest::from_bytes(self.key_id),
            Ed25519PublicKey::from_bytes(self.public_key)?,
            self.not_before,
            self.not_after,
        )
    }
}

/// Complete path and policy input for one stopped-daemon restore.
pub struct RestoreCommandRequest {
    /// Validated permanent network identity.
    pub network_id: NetworkId,
    /// Validated permanent server identity.
    pub server_id: ServerId,
    /// Configured current state directory, compared with the signed backup when readable.
    pub current_state_directory: PathBuf,
    /// Configured current storage master-key file.
    pub current_master_key_file: PathBuf,
    /// Configured current rollback-guard root-key file.
    pub current_rollback_guard_key_file: PathBuf,
    /// Signed backup input.
    pub backup_path: PathBuf,
    /// Source storage master-key file.
    pub source_master_key_file: PathBuf,
    /// Source rollback-guard root-key file.
    pub source_rollback_guard_key_file: PathBuf,
    /// Configured current login-index key file.
    pub login_index_key_file: PathBuf,
    /// Configured previous login-index key file during a transition.
    pub login_index_previous_key_file: Option<PathBuf>,
    /// New output state directory.
    pub output_state_directory: PathBuf,
    /// Target rollback-guard root-key file.
    pub target_rollback_guard_key_file: PathBuf,
    /// Optional new target storage master-key file.
    pub target_master_key_file: Option<PathBuf>,
    /// Resume the exact sibling staging directory or verify an installed output.
    pub resume: bool,
    /// Required acknowledgement that a fresh recovery epoch will be declared.
    pub declare_recovery_epoch: bool,
    /// Offline-authorized backup signing keys.
    pub trusted_backup_keys: Vec<RestoreTrustKey>,
    /// Runtime storage limits reused by construction.
    pub limits: StorageEngineLimits,
}

/// Durable result of a completed or reverified restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreCommandReceipt {
    /// Installed output directory.
    pub output_state_directory: PathBuf,
    /// Permanent authenticated restore operation ID.
    pub storage_operation_id: StorageDigest,
    /// Recovery epoch authenticated by the source backup.
    pub source_recovery_epoch: RecoveryEpoch,
    /// Fresh recovery epoch installed in the target.
    pub target_recovery_epoch: RecoveryEpoch,
    /// Server incarnation authenticated by the source backup.
    pub source_server_incarnation: ServerIncarnation,
    /// Fresh server incarnation installed in the target.
    pub target_server_incarnation: ServerIncarnation,
    /// State generation authenticated by the source backup.
    pub source_state_generation: u64,
    /// State generation of the readable configured database, when one was available.
    pub current_state_generation: Option<u64>,
    /// State generation installed for the new recovery epoch.
    pub target_state_generation: u64,
}

/// Runs the complete resumable restore protocol and installs only a verified output.
pub fn execute_restore_command(
    request: RestoreCommandRequest,
    qualifications: &[StorageQualification],
) -> Result<RestoreCommandReceipt, StorageError> {
    if !request.declare_recovery_epoch
        || request.trusted_backup_keys.is_empty()
        || request.trusted_backup_keys.len() > 1_024
    {
        return Err(StorageError::InvalidEncoding);
    }
    let limits = request.limits.validate()?;
    let construction_limits = construction_limits(limits)?;
    let source_master_bytes = read_secret_key(&request.source_master_key_file)?;
    let source_guard_bytes = read_secret_key(&request.source_rollback_guard_key_file)?;
    let login_key_bytes = read_secret_key(&request.login_index_key_file)?;
    let previous_login_key_bytes = request
        .login_index_previous_key_file
        .as_deref()
        .map(read_secret_key)
        .transpose()?;
    let target_master_bytes = request
        .target_master_key_file
        .as_deref()
        .map(read_secret_key)
        .transpose()?
        .unwrap_or_else(|| Zeroizing::new(*source_master_bytes));
    let target_guard_bytes = read_secret_key(&request.target_rollback_guard_key_file)?;
    if bool::from(
        source_guard_bytes
            .as_ref()
            .ct_eq(target_guard_bytes.as_ref()),
    ) {
        return Err(StorageError::AuthenticationFailed);
    }
    let trusted_keys = request
        .trusted_backup_keys
        .iter()
        .copied()
        .map(RestoreTrustKey::validate)
        .collect::<Result<Vec<_>, _>>()?;
    let backup = open_private_regular(&request.backup_path, Mode::RUSR | Mode::WUSR)?;
    let mut source = crate::RestoreBackupSource::open(
        backup,
        StorageMasterKey::from_bytes(*source_master_bytes),
        RollbackGuardRootKey::from_bytes(*source_guard_bytes),
        LoginIndexKey::from_bytes(*login_key_bytes),
        previous_login_key_bytes
            .as_ref()
            .map(|bytes| LoginIndexKey::from_bytes(**bytes)),
        &trusted_keys,
        limits.backup_max_bytes,
    )?;
    let source_facts = source.facts()?;
    let source_header = source_facts.header;
    if source_header.tbs().network_id != request.network_id
        || source_header.tbs().server_id != request.server_id
    {
        return Err(StorageError::AuthenticationFailed);
    }
    let current_facts = read_current_boundary(
        &request,
        qualifications,
        &login_key_bytes,
        previous_login_key_bytes.as_deref(),
        limits,
    )?;
    if current_facts.is_some_and(|current| !same_restore_boundary(current, source_facts)) {
        return Err(StorageError::StaleState);
    }
    let directory = ConstructionDirectory::open(&request.output_state_directory, request.resume)?;
    let target = select_target_identity(
        &request,
        &directory,
        qualifications,
        source_header,
        &source_master_bytes,
        &target_master_bytes,
        &target_guard_bytes,
        &login_key_bytes,
        previous_login_key_bytes.as_deref(),
        limits,
    )?;
    let target_binding = DatabaseBinding::new(
        request.network_id,
        request.server_id,
        target.header.tbs().server_incarnation,
        target.header.tbs().database_instance_id,
    );
    let plan_file = match directory.phase() {
        ConstructionDirectoryPhase::Staging => directory.rebuild_plan_file()?,
        ConstructionDirectoryPhase::Installed => anonymous_plan_file()?,
    };
    let plan = source.rebuild_restore_plan(
        plan_file,
        &StorageMasterKey::from_bytes(*target_master_bytes),
        target_binding,
        target.header.tbs().storage_key_generation,
        construction_limits,
    )?;
    let mut identity = restore_identity(
        &source,
        &source_master_bytes,
        &source_guard_bytes,
        &target_master_bytes,
        &target_guard_bytes,
        &target.header,
        plan.entry_count(),
        plan.hash(),
    )?;
    if target.fresh {
        identity.target_database_header_hash = StorageDigest::from_bytes([0_u8; 32]);
    }
    if directory.phase() == ConstructionDirectoryPhase::Installed {
        let verification = ConstructionTarget::verify_completed(
            target_open_config(
                &request,
                &directory,
                qualifications,
                &target_master_bytes,
                &target_guard_bytes,
                &login_key_bytes,
                previous_login_key_bytes.as_deref(),
                limits,
            )?,
            identity,
            directory.output_path_hash(),
        )?;
        return Ok(restore_receipt(
            directory.output_path(),
            verification.completion().storage_operation_id,
            source_facts,
            current_facts,
            target.header,
        ));
    }
    let initial_marker = StorageConstruction {
        identity,
        output_path_hash: directory.output_path_hash(),
        next_target: StorageConstructionCursor::BeforeFirst,
        target_records_committed: 0,
    };
    if target.fresh {
        initialize_restore_target(
            &directory,
            qualifications,
            &target,
            &initial_marker,
            &target_master_bytes,
            &target_guard_bytes,
            source_facts.rollback_guard_hash,
            limits,
        )?;
    }
    let mut target_writer = ConstructionTarget::open(target_open_config(
        &request,
        &directory,
        qualifications,
        &target_master_bytes,
        &target_guard_bytes,
        &login_key_bytes,
        previous_login_key_bytes.as_deref(),
        limits,
    )?)?;
    let marker = target_writer.marker()?;
    if !target.fresh && marker.identity != identity {
        return Err(StorageError::ResumeMismatch);
    }
    let expected_identity = marker.identity;
    let preflight_marker = StorageConstruction {
        identity: expected_identity,
        output_path_hash: directory.output_path_hash(),
        next_target: StorageConstructionCursor::BeforeFirst,
        target_records_committed: 0,
    };
    let mut transformer = RecoveryTransformV1::new(
        target.header.tbs().recovery_epoch,
        source_facts.rollback_guard_hash,
    );
    let _preflight = plan.preflight(
        &preflight_marker,
        0,
        0,
        &mut source,
        &mut transformer,
        construction_limits,
    )?;
    let mut executor = ConstructionExecutor::resume(marker, plan, construction_limits)?;
    while executor.service_batch(&mut source, &mut transformer, &mut target_writer)? != 0 {}
    let operation_id = executor.finalize(&mut target_writer)?;
    drop(executor);
    drop(target_writer);
    directory.remove_plan_file()?;
    let verification = ConstructionTarget::verify_completed(
        target_open_config(
            &request,
            &directory,
            qualifications,
            &target_master_bytes,
            &target_guard_bytes,
            &login_key_bytes,
            previous_login_key_bytes.as_deref(),
            limits,
        )?,
        expected_identity,
        directory.output_path_hash(),
    )?;
    if verification.completion().storage_operation_id != operation_id {
        return Err(StorageError::StaleState);
    }
    let output = directory.install(verification)?;
    Ok(restore_receipt(
        output,
        operation_id,
        source_facts,
        current_facts,
        target.header,
    ))
}

fn read_current_boundary(
    request: &RestoreCommandRequest,
    qualifications: &[StorageQualification],
    login_key_bytes: &[u8; 32],
    previous_login_key_bytes: Option<&[u8; 32]>,
    limits: StorageEngineLimits,
) -> Result<Option<ConstructionSourceFacts>, StorageError> {
    let Ok(master) = read_secret_key(&request.current_master_key_file) else {
        return Ok(None);
    };
    let Ok(guard) = read_secret_key(&request.current_rollback_guard_key_file) else {
        return Ok(None);
    };
    let state_directory =
        match StateDirectory::open(&request.current_state_directory, qualifications) {
            Ok(directory) => directory,
            Err(StorageError::WriterLocked) => return Err(StorageError::WriterLocked),
            Err(_) => return Ok(None),
        };
    let Ok(source) = ConstructionSourceDatabase::open(StorageOpenConfig {
        expected_network_id: request.network_id,
        expected_server_id: request.server_id,
        state_directory,
        storage_master_key: StorageMasterKey::from_bytes(*master),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(*guard),
        login_index_key: LoginIndexKey::from_bytes(*login_key_bytes),
        previous_login_index_key: previous_login_key_bytes
            .map(|bytes| LoginIndexKey::from_bytes(*bytes)),
        limits,
    }) else {
        return Ok(None);
    };
    Ok(source.facts().ok())
}

fn same_restore_boundary(
    current: ConstructionSourceFacts,
    source: ConstructionSourceFacts,
) -> bool {
    current.header.tbs().recovery_epoch == source.header.tbs().recovery_epoch
        && current.header.tbs().server_incarnation == source.header.tbs().server_incarnation
        && current.rollback_guard_hash == source.rollback_guard_hash
        && current.state.state_generation == source.state.state_generation
}

fn restore_receipt(
    output_state_directory: PathBuf,
    storage_operation_id: StorageDigest,
    source: ConstructionSourceFacts,
    current: Option<ConstructionSourceFacts>,
    target: DatabaseHeader,
) -> RestoreCommandReceipt {
    RestoreCommandReceipt {
        output_state_directory,
        storage_operation_id,
        source_recovery_epoch: source.header.tbs().recovery_epoch,
        target_recovery_epoch: target.tbs().recovery_epoch,
        source_server_incarnation: source.header.tbs().server_incarnation,
        target_server_incarnation: target.tbs().server_incarnation,
        source_state_generation: source.state.state_generation,
        current_state_generation: current.map(|facts| facts.state.state_generation),
        target_state_generation: 0,
    }
}

struct TargetIdentity {
    header: DatabaseHeader,
    fresh: bool,
}

#[expect(
    clippy::too_many_arguments,
    reason = "target selection binds every source and target secret authority before construction"
)]
fn select_target_identity(
    request: &RestoreCommandRequest,
    directory: &ConstructionDirectory,
    qualifications: &[StorageQualification],
    source_header: DatabaseHeader,
    source_master_bytes: &[u8; 32],
    target_master_bytes: &[u8; 32],
    target_guard_bytes: &[u8; 32],
    login_key_bytes: &[u8; 32],
    previous_login_key_bytes: Option<&[u8; 32]>,
    limits: StorageEngineLimits,
) -> Result<TargetIdentity, StorageError> {
    if request.resume {
        let header = match directory.phase() {
            ConstructionDirectoryPhase::Staging => {
                let target = ConstructionTarget::open(target_open_config(
                    request,
                    directory,
                    qualifications,
                    target_master_bytes,
                    target_guard_bytes,
                    login_key_bytes,
                    previous_login_key_bytes,
                    limits,
                )?)?;
                target.header()
            }
            ConstructionDirectoryPhase::Installed => {
                ConstructionTarget::completed_header(target_open_config(
                    request,
                    directory,
                    qualifications,
                    target_master_bytes,
                    target_guard_bytes,
                    login_key_bytes,
                    previous_login_key_bytes,
                    limits,
                )?)?
            }
        };
        validate_target_header(
            header,
            source_header,
            source_master_bytes,
            target_master_bytes,
        )?;
        return Ok(TargetIdentity {
            header,
            fresh: false,
        });
    }
    let target_generation = if secret_bytes_match(source_master_bytes, target_master_bytes) {
        source_header
            .tbs()
            .storage_key_generation
            .checked_add(1)
            .ok_or(StorageError::LimitExceeded)?
    } else {
        1
    };
    let incarnation = ServerIncarnation::from_bytes(fresh_distinct_16(
        source_header.tbs().server_incarnation.as_bytes(),
    )?);
    let database_id = DatabaseId::from_bytes(fresh_distinct_16(
        source_header.tbs().database_instance_id.as_bytes(),
    )?);
    let recovery_epoch = RecoveryEpoch::from_bytes(fresh_distinct_16(
        source_header.tbs().recovery_epoch.as_bytes(),
    )?);
    let tbs = DatabaseHeaderTbs::new(
        request.network_id,
        request.server_id,
        incarnation,
        database_id,
        target_generation,
        SCHEMA_GENERATION,
        recovery_epoch,
    )?;
    Ok(TargetIdentity {
        header: DatabaseHeader::new(tbs, StorageDigest::from_bytes([0_u8; 32])),
        fresh: true,
    })
}

fn validate_target_header(
    target: DatabaseHeader,
    source: DatabaseHeader,
    source_master_bytes: &[u8; 32],
    target_master_bytes: &[u8; 32],
) -> Result<(), StorageError> {
    let expected_generation = if secret_bytes_match(source_master_bytes, target_master_bytes) {
        source
            .tbs()
            .storage_key_generation
            .checked_add(1)
            .ok_or(StorageError::LimitExceeded)?
    } else {
        1
    };
    if target.tbs().network_id != source.tbs().network_id
        || target.tbs().server_id != source.tbs().server_id
        || target.tbs().server_incarnation == source.tbs().server_incarnation
        || target.tbs().database_instance_id == source.tbs().database_instance_id
        || target.tbs().recovery_epoch == source.tbs().recovery_epoch
        || target.tbs().schema_generation != source.tbs().schema_generation
        || target.tbs().storage_key_generation != expected_generation
    {
        return Err(StorageError::ResumeMismatch);
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the operation identity authenticates all four independent source and target key roles"
)]
fn restore_identity<R: std::io::Read + std::io::Seek>(
    source: &crate::RestoreBackupSource<R>,
    source_master_bytes: &[u8; 32],
    source_guard_bytes: &[u8; 32],
    target_master_bytes: &[u8; 32],
    target_guard_bytes: &[u8; 32],
    target_header: &DatabaseHeader,
    planned_entry_count: u64,
    construction_plan_hash: StorageDigest,
) -> Result<StorageOperationIdentity, StorageError> {
    let facts = source.facts()?;
    Ok(StorageOperationIdentity {
        kind: StorageConstructionKind::Restore,
        command_version: 1,
        source_database_header_hash: facts.header.complete_hash()?,
        target_database_header_hash: target_header.complete_hash()?,
        source_rollback_guard_hash: facts.rollback_guard_hash,
        source_stream_digest: Some(source.verified().trailer.stream_digest),
        source_schema_generation: facts.header.tbs().schema_generation,
        target_schema_generation: target_header.tbs().schema_generation,
        transform_profile_hash: restore_transform_profile_hash()?,
        target_database_instance_id: target_header.tbs().database_instance_id,
        source_master_key_id: StorageMasterKey::from_bytes(*source_master_bytes)
            .source_operation_key_id()?,
        source_guard_root_key_id: RollbackGuardRootKey::from_bytes(*source_guard_bytes)
            .source_operation_key_id()?,
        target_master_key_id: StorageMasterKey::from_bytes(*target_master_bytes)
            .target_operation_key_id()?,
        target_guard_root_key_id: RollbackGuardRootKey::from_bytes(*target_guard_bytes)
            .target_operation_key_id()?,
        planned_entry_count,
        construction_plan_hash,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "initialization requires the complete target identity and each independent key role"
)]
fn initialize_restore_target(
    directory: &ConstructionDirectory,
    qualifications: &[StorageQualification],
    target: &TargetIdentity,
    marker: &StorageConstruction,
    target_master_bytes: &[u8; 32],
    target_guard_bytes: &[u8; 32],
    predecessor_guard_hash: StorageDigest,
    limits: StorageEngineLimits,
) -> Result<(), StorageError> {
    let outcome = initialize_storage(StorageInitializationConfig {
        state_directory: StateDirectory::open(&directory.selected_path(), qualifications)?,
        header_tbs: *target.header.tbs(),
        storage_master_key: StorageMasterKey::from_bytes(*target_master_bytes),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(*target_guard_bytes),
        mode: StorageInitializationMode::Construction,
        initial_records: vec![InitialStorageRecord::new(
            TableId::StorageConstruction,
            StoredKey::new(crate::STORAGE_CONSTRUCTION_KEY.to_vec())?,
            1,
            marker.encode()?,
        )?],
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash,
        limits,
    })?;
    if matches!(outcome, StorageInitializationOutcome::Complete { .. }) {
        Ok(())
    } else {
        Err(StorageError::Unavailable)
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "open configuration keeps each independent restore key role explicit"
)]
fn target_open_config(
    request: &RestoreCommandRequest,
    directory: &ConstructionDirectory,
    qualifications: &[StorageQualification],
    target_master_bytes: &[u8; 32],
    target_guard_bytes: &[u8; 32],
    login_key_bytes: &[u8; 32],
    previous_login_key_bytes: Option<&[u8; 32]>,
    limits: StorageEngineLimits,
) -> Result<StorageOpenConfig, StorageError> {
    Ok(StorageOpenConfig {
        expected_network_id: request.network_id,
        expected_server_id: request.server_id,
        state_directory: StateDirectory::open(&directory.selected_path(), qualifications)?,
        storage_master_key: StorageMasterKey::from_bytes(*target_master_bytes),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(*target_guard_bytes),
        login_index_key: LoginIndexKey::from_bytes(*login_key_bytes),
        previous_login_index_key: previous_login_key_bytes
            .map(|bytes| LoginIndexKey::from_bytes(*bytes)),
        limits,
    })
}

fn construction_limits(limits: StorageEngineLimits) -> Result<ConstructionLimits, StorageError> {
    ConstructionLimits {
        source_database_bytes: limits.database_max_bytes,
        source_backup_bytes: limits.backup_max_bytes,
        target_database_bytes: limits.database_max_bytes,
        target_backup_bytes: limits.backup_max_bytes,
        plan_bytes: limits.backup_max_bytes,
        batch_records: RESTORE_BATCH_RECORDS,
        batch_bytes: RESTORE_BATCH_BYTES,
    }
    .validate()
}

fn fresh_distinct_16(source: &[u8; 16]) -> Result<[u8; 16], StorageError> {
    for _attempt in 0..MAX_RANDOM_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        OsEntropy::fill(&mut bytes)?;
        if &bytes != source {
            return Ok(bytes);
        }
    }
    Err(StorageError::Unavailable)
}

fn secret_bytes_match(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

fn read_secret_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, StorageError> {
    let file = open_private_regular(path, Mode::RUSR | Mode::WUSR)?;
    let metadata = file
        .metadata()
        .map_err(|_| StorageError::FilesystemRejected)?;
    if metadata.len() != 32 {
        return Err(StorageError::InvalidEncoding);
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    use std::io::Read as _;
    (&file)
        .read_exact(bytes.as_mut())
        .map_err(|_| StorageError::FilesystemRejected)?;
    Ok(bytes)
}

fn open_private_regular(path: &Path, mode: Mode) -> Result<File, StorageError> {
    if !path.is_absolute() {
        return Err(StorageError::FilesystemRejected);
    }
    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StorageError::FilesystemRejected)?;
    let metadata = fstat(&fd).map_err(|_| StorageError::FilesystemRejected)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || Mode::from_raw_mode(metadata.st_mode) != mode
    {
        return Err(StorageError::FilesystemRejected);
    }
    Ok(File::from(fd))
}

fn anonymous_plan_file() -> Result<File, StorageError> {
    let mut random = [0_u8; 16];
    OsEntropy::fill(&mut random)?;
    let mut suffix = String::with_capacity(32);
    for byte in random {
        use std::fmt::Write as _;
        write!(suffix, "{byte:02x}").map_err(|_| StorageError::AllocationFailed)?;
    }
    let path = std::env::temp_dir().join(format!("agenc-restore-plan-{suffix}"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| StorageError::FilesystemRejected)?;
    std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
    Ok(file)
}
