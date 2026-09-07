//! Stopped-daemon backup restore composition.

use std::fs::File;
use std::path::{Path, PathBuf};

use agenc_ircd_crypto::{
    DatabaseBinding, Ed25519PublicKey, LoginIndexKey, OsEntropy, RollbackGuardRootKey,
    StorageDigest, StorageMasterKey, restore_transform_profile_hash,
};
use agenc_ircd_types::{DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};
use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::construction_runtime::RestoreSourceAdmission;
use crate::construction_schema::ConstructionSchema;
use crate::{
    BackupTrustKey, ConstructionDirectory, ConstructionDirectoryPhase, ConstructionExecutor,
    ConstructionLimits, ConstructionPlan, ConstructionSourceDatabase, ConstructionSourceFacts,
    ConstructionTarget, DatabaseHeader, DatabaseHeaderTbs, InitialStorageRecord,
    RecoveryTransformV1, RestoreBackupSourceConfig, SourceRecordValidator, StateDirectory,
    StorageConstruction, StorageConstructionCursor, StorageConstructionKind, StorageEngineLimits,
    StorageError, StorageInitializationConfig, StorageInitializationMode,
    StorageInitializationOutcome, StorageOpenConfig, StorageOperationIdentity,
    StorageQualification, StoredKey, TableId,
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
    /// Configured current state directory. When it exists it must open, and its lineage
    /// must match the signed backup; when absent the comparison is skipped and the receipt
    /// reports the current generation as unknown.
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
    /// Schema generation preserved by restore. Legacy output requires explicit migration.
    pub schema_generation: u64,
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
    execute_restore_admitted(request, qualifications, RestoreSourceAdmission::Current)
}

/// Requires complete semantic admission of a schema-two signed source before any output.
/// A legacy restore preserves schema two and must be migrated separately before service.
pub fn execute_validated_restore_command(
    request: RestoreCommandRequest,
    qualifications: &[StorageQualification],
    validator: &mut dyn SourceRecordValidator,
) -> Result<RestoreCommandReceipt, StorageError> {
    execute_restore_admitted(
        request,
        qualifications,
        RestoreSourceAdmission::WithLegacy(validator),
    )
}

fn execute_restore_admitted(
    request: RestoreCommandRequest,
    qualifications: &[StorageQualification],
    admission: RestoreSourceAdmission<'_>,
) -> Result<RestoreCommandReceipt, StorageError> {
    validate_restore_request(&request)?;
    let limits = request.limits.validate()?;
    let construction_limits = construction_limits(limits)?;
    let secrets = RestoreSecrets::load(&request)?;
    let trusted_keys = trusted_restore_keys(&request)?;
    let mut source = secrets.open_source(&request, &trusted_keys, limits, admission)?;
    let source_facts = source.facts()?;
    let source_header = source_facts.header;
    if (
        source_header.tbs().network_id,
        source_header.tbs().server_id,
    ) != (request.network_id, request.server_id)
    {
        return Err(StorageError::AuthenticationFailed);
    }
    let current_facts = read_current_boundary(
        &request,
        qualifications,
        &secrets.login_index,
        secrets.previous_login_index.as_deref(),
        limits,
        ConstructionSchema::from_generation(source_header.tbs().schema_generation)?,
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
        &secrets.source_master,
        &secrets.target_master,
        &secrets.target_guard,
        &secrets.login_index,
        secrets.previous_login_index.as_deref(),
        limits,
    )?;
    RestoreExecution {
        request: &request,
        qualifications,
        secrets,
        limits,
        construction_limits,
        directory,
        target,
        source_facts,
        current_facts,
    }
    .run(&mut source)
}

fn validate_restore_request(request: &RestoreCommandRequest) -> Result<(), StorageError> {
    if !request.declare_recovery_epoch {
        return Err(StorageError::InvalidEncoding);
    }
    if (
        request.trusted_backup_keys.is_empty(),
        request.trusted_backup_keys.len() > crate::MAX_BACKUP_TRUST_KEYS,
    ) != (false, false)
    {
        return Err(StorageError::LimitExceeded);
    }
    Ok(())
}

fn trusted_restore_keys(
    request: &RestoreCommandRequest,
) -> Result<Vec<BackupTrustKey>, StorageError> {
    request
        .trusted_backup_keys
        .iter()
        .copied()
        .map(RestoreTrustKey::validate)
        .collect()
}

struct RestoreSecrets {
    source_master: Zeroizing<[u8; 32]>,
    source_guard: Zeroizing<[u8; 32]>,
    login_index: Zeroizing<[u8; 32]>,
    previous_login_index: Option<Zeroizing<[u8; 32]>>,
    target_master: Zeroizing<[u8; 32]>,
    target_guard: Zeroizing<[u8; 32]>,
}

pub(crate) fn maintenance_backup_trust_keys(
    rows: &[RestoreTrustKey],
) -> Result<Vec<BackupTrustKey>, StorageError> {
    if rows.is_empty() || rows.len() > crate::MAX_BACKUP_TRUST_KEYS {
        return Err(StorageError::LimitExceeded);
    }
    rows.iter()
        .copied()
        .map(RestoreTrustKey::validate)
        .collect()
}

impl RestoreSecrets {
    fn load(request: &RestoreCommandRequest) -> Result<Self, StorageError> {
        let source_master = read_secret_key(&request.source_master_key_file)?;
        let source_guard = read_secret_key(&request.source_rollback_guard_key_file)?;
        let login_index = read_secret_key(&request.login_index_key_file)?;
        let previous_login_index = request
            .login_index_previous_key_file
            .as_deref()
            .map(read_secret_key)
            .transpose()?;
        let target_master = request
            .target_master_key_file
            .as_deref()
            .map(read_secret_key)
            .transpose()?
            .unwrap_or_else(|| Zeroizing::new(*source_master));
        let target_guard = read_secret_key(&request.target_rollback_guard_key_file)?;
        if bool::from(source_guard.as_ref().ct_eq(target_guard.as_ref())) {
            return Err(StorageError::AuthenticationFailed);
        }
        Ok(Self {
            source_master,
            source_guard,
            login_index,
            previous_login_index,
            target_master,
            target_guard,
        })
    }

    fn open_source(
        &self,
        request: &RestoreCommandRequest,
        trusted_keys: &[BackupTrustKey],
        limits: StorageEngineLimits,
        admission: RestoreSourceAdmission<'_>,
    ) -> Result<crate::RestoreBackupSource<File>, StorageError> {
        let backup = open_private_regular(&request.backup_path, Mode::RUSR | Mode::WUSR)?;
        crate::RestoreBackupSource::open_admitted(
            backup,
            RestoreBackupSourceConfig {
                source_master_key: StorageMasterKey::from_bytes(*self.source_master),
                source_guard_root: RollbackGuardRootKey::from_bytes(*self.source_guard),
                login_index_key: LoginIndexKey::from_bytes(*self.login_index),
                previous_login_index_key: self
                    .previous_login_index
                    .as_ref()
                    .map(|bytes| LoginIndexKey::from_bytes(**bytes)),
                trusted_keys,
                maximum_bytes: limits.backup_max_bytes,
            },
            admission,
        )
    }
}

struct RestoreExecution<'a> {
    request: &'a RestoreCommandRequest,
    qualifications: &'a [StorageQualification],
    secrets: RestoreSecrets,
    limits: StorageEngineLimits,
    construction_limits: ConstructionLimits,
    directory: ConstructionDirectory,
    target: TargetIdentity,
    source_facts: ConstructionSourceFacts,
    current_facts: Option<ConstructionSourceFacts>,
}

impl RestoreExecution<'_> {
    fn run(
        self,
        source: &mut crate::RestoreBackupSource<File>,
    ) -> Result<RestoreCommandReceipt, StorageError> {
        let (plan, identity) = self.rebuild_plan(source)?;
        if self.directory.phase() == ConstructionDirectoryPhase::Installed {
            self.verify_installed(identity)
        } else {
            self.install_staging(source, plan, identity)
        }
    }

    fn rebuild_plan(
        &self,
        source: &mut crate::RestoreBackupSource<File>,
    ) -> Result<(ConstructionPlan, StorageOperationIdentity), StorageError> {
        let target_binding = DatabaseBinding::new(
            self.request.network_id,
            self.request.server_id,
            self.target.header.tbs().server_incarnation,
            self.target.header.tbs().database_instance_id,
        );
        let plan_file = match self.directory.phase() {
            ConstructionDirectoryPhase::Staging => self.directory.rebuild_plan_file()?,
            ConstructionDirectoryPhase::Installed => self.directory.anonymous_plan_file()?,
        };
        let plan = source.rebuild_restore_plan(
            plan_file,
            &StorageMasterKey::from_bytes(*self.secrets.target_master),
            target_binding,
            self.target.header.tbs().storage_key_generation,
            self.construction_limits,
        )?;
        let mut identity = restore_identity(
            source,
            &self.secrets.source_master,
            &self.secrets.source_guard,
            &self.secrets.target_master,
            &self.secrets.target_guard,
            &self.target.header,
            plan.entry_count(),
            plan.hash(),
        )?;
        if self.target.fresh {
            identity.target_database_header_hash = StorageDigest::from_bytes([0_u8; 32]);
        }
        Ok((plan, identity))
    }

    fn verify_installed(
        &self,
        identity: StorageOperationIdentity,
    ) -> Result<RestoreCommandReceipt, StorageError> {
        let verification = ConstructionTarget::verify_completed(
            self.target_config()?,
            identity,
            self.directory.output_path_hash(),
        )?;
        Ok(restore_receipt(
            self.directory.output_path(),
            verification.completion().storage_operation_id,
            self.source_facts,
            self.current_facts,
            self.target.header,
        ))
    }

    fn install_staging(
        self,
        source: &mut crate::RestoreBackupSource<File>,
        plan: ConstructionPlan,
        identity: StorageOperationIdentity,
    ) -> Result<RestoreCommandReceipt, StorageError> {
        let initial_marker = StorageConstruction {
            identity,
            output_path_hash: self.directory.output_path_hash(),
            next_target: StorageConstructionCursor::BeforeFirst,
            target_records_committed: 0,
        };
        if self.target.fresh {
            initialize_restore_target(
                &self.directory,
                self.qualifications,
                &self.target,
                &initial_marker,
                &self.secrets.target_master,
                &self.secrets.target_guard,
                self.source_facts.rollback_guard_hash,
                self.limits,
            )?;
        }
        let mut target_writer = match ConstructionTarget::open_stopped(
            self.target_config()?,
            ConstructionSchema::from_generation(self.target.header.tbs().schema_generation)?,
        ) {
            Ok(target_writer) => target_writer,
            // A construction that was finalized but never renamed into place
            // has no marker row left to reopen; install it from its completion.
            Err(open_error) if !self.target.fresh => {
                return self.install_finalized(identity, open_error);
            }
            Err(error) => return Err(error),
        };
        let marker = target_writer.marker()?;
        if (self.target.fresh, marker.identity != identity) == (false, true) {
            return Err(StorageError::ResumeMismatch);
        }
        let expected_identity = marker.identity;
        let operation_id = self.execute_plan(source, plan, marker, &mut target_writer)?;
        drop(target_writer);
        self.directory.remove_plan_file()?;
        let verification = ConstructionTarget::verify_completed(
            self.target_config()?,
            expected_identity,
            self.directory.output_path_hash(),
        )?;
        if verification.completion().storage_operation_id != operation_id {
            return Err(StorageError::StaleState);
        }
        let output = self.directory.install(verification)?;
        Ok(restore_receipt(
            output,
            operation_id,
            self.source_facts,
            self.current_facts,
            self.target.header,
        ))
    }

    /// Resumes a staging database whose construction already committed its
    /// completion row (the process died between finalization and the rename).
    /// The completion is reverified exactly as a fresh installation would be;
    /// any other open failure keeps the original error.
    fn install_finalized(
        self,
        identity: StorageOperationIdentity,
        open_error: StorageError,
    ) -> Result<RestoreCommandReceipt, StorageError> {
        let Ok(verification) = ConstructionTarget::verify_completed(
            self.target_config()?,
            identity,
            self.directory.output_path_hash(),
        ) else {
            return Err(open_error);
        };
        let operation_id = identity.operation_id()?;
        if verification.completion().storage_operation_id != operation_id {
            return Err(StorageError::StaleState);
        }
        self.directory.remove_plan_file()?;
        let output = self.directory.install(verification)?;
        Ok(restore_receipt(
            output,
            operation_id,
            self.source_facts,
            self.current_facts,
            self.target.header,
        ))
    }

    fn execute_plan(
        &self,
        source: &mut crate::RestoreBackupSource<File>,
        plan: ConstructionPlan,
        marker: StorageConstruction,
        target_writer: &mut ConstructionTarget,
    ) -> Result<StorageDigest, StorageError> {
        let preflight_marker = StorageConstruction {
            identity: marker.identity,
            output_path_hash: self.directory.output_path_hash(),
            next_target: StorageConstructionCursor::BeforeFirst,
            target_records_committed: 0,
        };
        let mut transformer = RecoveryTransformV1::new(
            self.target.header.tbs().recovery_epoch,
            self.source_facts.rollback_guard_hash,
        );
        let _preflight = plan.preflight(
            &preflight_marker,
            0,
            0,
            source,
            &mut transformer,
            self.construction_limits,
        )?;
        let mut executor = ConstructionExecutor::resume(marker, plan, self.construction_limits)?;
        while executor.service_batch(source, &mut transformer, target_writer)? != 0 {}
        executor.finalize(target_writer)
    }

    fn target_config(&self) -> Result<StorageOpenConfig, StorageError> {
        target_open_config(
            self.request,
            &self.directory,
            self.qualifications,
            &self.secrets.target_master,
            &self.secrets.target_guard,
            &self.secrets.login_index,
            self.secrets.previous_login_index.as_deref(),
            self.limits,
        )
    }
}

fn read_current_boundary(
    request: &RestoreCommandRequest,
    qualifications: &[StorageQualification],
    login_key_bytes: &[u8; 32],
    previous_login_key_bytes: Option<&[u8; 32]>,
    limits: StorageEngineLimits,
    schema: ConstructionSchema,
) -> Result<Option<ConstructionSourceFacts>, StorageError> {
    if !current_state_directory_exists(&request.current_state_directory)? {
        return Ok(None);
    }
    let master = read_secret_key(&request.current_master_key_file)?;
    let guard = read_secret_key(&request.current_rollback_guard_key_file)?;
    let state_directory = StateDirectory::open(&request.current_state_directory, qualifications)?;
    let source = ConstructionSourceDatabase::open_restore_boundary(
        StorageOpenConfig {
            expected_network_id: request.network_id,
            expected_server_id: request.server_id,
            state_directory,
            storage_master_key: StorageMasterKey::from_bytes(*master),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(*guard),
            login_index_key: LoginIndexKey::from_bytes(*login_key_bytes),
            previous_login_index_key: previous_login_key_bytes
                .map(|bytes| LoginIndexKey::from_bytes(*bytes)),
            limits,
        },
        schema,
    )?;
    Ok(Some(source.facts()?))
}

/// Distinguishes an absent configured database from one that exists but cannot be read.
fn current_state_directory_exists(path: &Path) -> Result<bool, StorageError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(StorageError::FilesystemRejected),
    }
}

fn same_restore_boundary(
    current: ConstructionSourceFacts,
    source: ConstructionSourceFacts,
) -> bool {
    (
        current.header.tbs().recovery_epoch,
        current.header.tbs().server_incarnation,
        current.rollback_guard_hash,
        current.state.state_generation,
    ) == (
        source.header.tbs().recovery_epoch,
        source.header.tbs().server_incarnation,
        source.rollback_guard_hash,
        source.state.state_generation,
    )
}

fn restore_receipt(
    output_state_directory: PathBuf,
    storage_operation_id: StorageDigest,
    source: ConstructionSourceFacts,
    current: Option<ConstructionSourceFacts>,
    target: DatabaseHeader,
) -> RestoreCommandReceipt {
    RestoreCommandReceipt {
        schema_generation: target.tbs().schema_generation,
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
    let schema = ConstructionSchema::from_generation(source_header.tbs().schema_generation)?;
    if request.resume {
        let header = match directory.phase() {
            ConstructionDirectoryPhase::Staging => {
                let config = || {
                    target_open_config(
                        request,
                        directory,
                        qualifications,
                        target_master_bytes,
                        target_guard_bytes,
                        login_key_bytes,
                        previous_login_key_bytes,
                        limits,
                    )
                };
                match ConstructionTarget::open_stopped(config()?, schema) {
                    Ok(target) => target.header(),
                    // A finalized construction that was never renamed has no
                    // marker row; its completed header is the target identity.
                    Err(open_error) => {
                        ConstructionTarget::completed_header_stopped(config()?, schema)
                            .map_err(|_| open_error)?
                    }
                }
            }
            ConstructionDirectoryPhase::Installed => ConstructionTarget::completed_header_stopped(
                target_open_config(
                    request,
                    directory,
                    qualifications,
                    target_master_bytes,
                    target_guard_bytes,
                    login_key_bytes,
                    previous_login_key_bytes,
                    limits,
                )?,
                schema,
            )?,
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
    let tbs = DatabaseHeaderTbs {
        server_incarnation: incarnation,
        recovery_epoch,
        ..schema.header(source_header.tbs(), database_id, target_generation)?
    };
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
    if (
        target.tbs().network_id,
        target.tbs().server_id,
        target.tbs().server_incarnation == source.tbs().server_incarnation,
        target.tbs().database_instance_id == source.tbs().database_instance_id,
        target.tbs().recovery_epoch == source.tbs().recovery_epoch,
        target.tbs().schema_generation,
        target.tbs().storage_key_generation,
    ) != (
        source.tbs().network_id,
        source.tbs().server_id,
        false,
        false,
        false,
        source.tbs().schema_generation,
        expected_generation,
    ) {
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
    let outcome =
        crate::initialize::initialize_stopped_construction(StorageInitializationConfig {
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

pub(crate) fn read_secret_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, StorageError> {
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
    if (
        FileType::from_raw_mode(metadata.st_mode),
        Mode::from_raw_mode(metadata.st_mode),
    ) != (FileType::RegularFile, mode)
    {
        return Err(StorageError::FilesystemRejected);
    }
    Ok(File::from(fd))
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::StateMetaTbs;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    const ZERO: StorageDigest = StorageDigest::from_bytes([0; 32]);

    #[derive(Clone, Copy)]
    struct HeaderFixture {
        network: NetworkId,
        server: ServerId,
        incarnation: ServerIncarnation,
        database: DatabaseId,
        generation: u32,
        schema: u64,
        recovery: RecoveryEpoch,
    }

    fn database_header(fixture: HeaderFixture) -> DatabaseHeader {
        DatabaseHeader::new(
            DatabaseHeaderTbs {
                network_id: fixture.network,
                server_id: fixture.server,
                server_incarnation: fixture.incarnation,
                database_instance_id: fixture.database,
                storage_key_generation: fixture.generation,
                schema_generation: fixture.schema,
                recovery_epoch: fixture.recovery,
            },
            ZERO,
        )
    }

    fn source_facts(fixture: HeaderFixture, state_generation: u64) -> ConstructionSourceFacts {
        ConstructionSourceFacts {
            header: database_header(fixture),
            state: StateMetaTbs {
                storage_commit_sequence: 0,
                manifest_sequence: 0,
                state_generation,
                account_service_response_count: 0,
                nonce_draw_high_water: 0,
                logical_database_bytes: 0,
                backup_stream_bytes: 0,
                checkpoint_manifest_sequence: 0,
                latest_manifest_hash: ZERO,
                checkpoint_hash: ZERO,
                previous_rollback_guard_hash: ZERO,
            },
            rollback_guard_hash: StorageDigest::from_bytes([9; 32]),
        }
    }

    fn engine_limits() -> StorageEngineLimits {
        StorageEngineLimits {
            redb_cache_bytes: 8 * 1_024 * 1_024,
            fixed_reserve_bytes: 64 * 1_024 * 1_024,
            reserve_percent: 1,
            database_max_bytes: 1_073_741_824,
            backup_max_bytes: 1_073_741_824,
            integrity_checkpoint_manifests: 10_000,
        }
    }

    fn request(declare: bool, trust_count: usize) -> RestoreCommandRequest {
        let trust = RestoreTrustKey::new([1; 32], [2; 32], 1, 2);
        RestoreCommandRequest {
            network_id: NetworkId::from_bytes([1; 32]),
            server_id: ServerId::from_bytes([2; 16]),
            current_state_directory: PathBuf::from("/nonexistent/current"),
            current_master_key_file: PathBuf::from("/nonexistent/current-master"),
            current_rollback_guard_key_file: PathBuf::from("/nonexistent/current-guard"),
            backup_path: PathBuf::from("/nonexistent/backup"),
            source_master_key_file: PathBuf::from("/nonexistent/source-master"),
            source_rollback_guard_key_file: PathBuf::from("/nonexistent/source-guard"),
            login_index_key_file: PathBuf::from("/nonexistent/login"),
            login_index_previous_key_file: None,
            output_state_directory: PathBuf::from("/nonexistent/output"),
            target_rollback_guard_key_file: PathBuf::from("/nonexistent/target-guard"),
            target_master_key_file: None,
            resume: false,
            declare_recovery_epoch: declare,
            trusted_backup_keys: vec![trust; trust_count],
            limits: engine_limits(),
        }
    }

    fn unique_temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agenc-restore-command-test-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn command_preconditions_reject_missing_acknowledgement_and_trust_bounds() {
        assert_eq!(
            execute_restore_command(request(false, 1), &[]),
            Err(StorageError::InvalidEncoding)
        );
        for request in [
            request(true, 0),
            request(true, crate::MAX_BACKUP_TRUST_KEYS + 1),
        ] {
            assert_eq!(
                execute_restore_command(request, &[]),
                Err(StorageError::LimitExceeded)
            );
        }
    }

    #[test]
    fn current_boundary_is_skipped_only_when_the_configured_directory_is_absent()
    -> Result<(), StorageError> {
        let directory = unique_temp_directory();
        std::fs::create_dir(&directory).map_err(|_| StorageError::FilesystemRejected)?;
        let limits = engine_limits();
        let absent = request(true, 1);
        assert_eq!(
            read_current_boundary(
                &absent,
                &[],
                &[0; 32],
                None,
                limits,
                ConstructionSchema::Three
            )
            .map(|facts| facts.is_some()),
            Ok(false)
        );

        let mut unreadable_keys = request(true, 1);
        unreadable_keys.current_state_directory = directory.clone();
        assert_eq!(
            read_current_boundary(
                &unreadable_keys,
                &[],
                &[0; 32],
                None,
                limits,
                ConstructionSchema::Three
            )
            .map(|facts| facts.is_some()),
            Err(StorageError::FilesystemRejected)
        );

        let file_path = directory.join("file");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file_path)
            .map_err(|_| StorageError::FilesystemRejected)?;
        let mut below_file = request(true, 1);
        below_file.current_state_directory = file_path.join("child");
        assert_eq!(
            read_current_boundary(
                &below_file,
                &[],
                &[0; 32],
                None,
                limits,
                ConstructionSchema::Three
            )
            .map(|facts| facts.is_some()),
            Err(StorageError::FilesystemRejected)
        );

        std::fs::remove_dir_all(directory).map_err(|_| StorageError::FilesystemRejected)?;
        Ok(())
    }

    #[test]
    fn restore_boundary_compares_each_authenticated_lineage_field() {
        let fixture = HeaderFixture {
            network: NetworkId::from_bytes([1; 32]),
            server: ServerId::from_bytes([2; 16]),
            incarnation: ServerIncarnation::from_bytes([3; 16]),
            database: DatabaseId::from_bytes([4; 16]),
            generation: 1,
            schema: 1,
            recovery: RecoveryEpoch::from_bytes([5; 16]),
        };
        let source = source_facts(fixture, 7);
        assert!(same_restore_boundary(source, source));

        let mut changed = source;
        changed.header = database_header(HeaderFixture {
            recovery: RecoveryEpoch::from_bytes([6; 16]),
            ..fixture
        });
        assert!(!same_restore_boundary(changed, source));
        let mut changed = source;
        changed.header = database_header(HeaderFixture {
            incarnation: ServerIncarnation::from_bytes([7; 16]),
            ..fixture
        });
        assert!(!same_restore_boundary(changed, source));
        let mut changed = source;
        changed.rollback_guard_hash = StorageDigest::from_bytes([8; 32]);
        assert!(!same_restore_boundary(changed, source));
        let changed = source_facts(fixture, 8);
        assert!(!same_restore_boundary(changed, source));
    }

    #[test]
    fn target_header_validation_rejects_each_identity_and_generation_mismatch() {
        let source_fixture = HeaderFixture {
            network: NetworkId::from_bytes([1; 32]),
            server: ServerId::from_bytes([2; 16]),
            incarnation: ServerIncarnation::from_bytes([3; 16]),
            database: DatabaseId::from_bytes([4; 16]),
            generation: 1,
            schema: 1,
            recovery: RecoveryEpoch::from_bytes([5; 16]),
        };
        let target_fixture = HeaderFixture {
            incarnation: ServerIncarnation::from_bytes([6; 16]),
            database: DatabaseId::from_bytes([7; 16]),
            generation: 2,
            recovery: RecoveryEpoch::from_bytes([8; 16]),
            ..source_fixture
        };
        let source = database_header(source_fixture);
        let secret = [9; 32];
        assert_eq!(
            validate_target_header(database_header(target_fixture), source, &secret, &secret,),
            Ok(())
        );
        assert_eq!(
            validate_target_header(
                database_header(HeaderFixture {
                    generation: 1,
                    ..target_fixture
                }),
                source,
                &secret,
                &[10; 32],
            ),
            Ok(())
        );

        let mismatches = [
            HeaderFixture {
                network: NetworkId::from_bytes([11; 32]),
                ..target_fixture
            },
            HeaderFixture {
                server: ServerId::from_bytes([12; 16]),
                ..target_fixture
            },
            HeaderFixture {
                incarnation: source_fixture.incarnation,
                ..target_fixture
            },
            HeaderFixture {
                database: source_fixture.database,
                ..target_fixture
            },
            HeaderFixture {
                recovery: source_fixture.recovery,
                ..target_fixture
            },
            HeaderFixture {
                schema: 2,
                ..target_fixture
            },
            HeaderFixture {
                generation: 3,
                ..target_fixture
            },
        ];
        for mismatch in mismatches {
            assert_eq!(
                validate_target_header(database_header(mismatch), source, &secret, &secret),
                Err(StorageError::ResumeMismatch)
            );
        }

        let maximum_source = database_header(HeaderFixture {
            generation: u32::MAX,
            ..source_fixture
        });
        assert_eq!(
            validate_target_header(
                database_header(target_fixture),
                maximum_source,
                &secret,
                &secret,
            ),
            Err(StorageError::LimitExceeded)
        );
    }

    #[test]
    fn construction_limits_and_secret_comparison_preserve_exact_bounds() -> Result<(), StorageError>
    {
        let limits = construction_limits(engine_limits())?;
        assert_eq!(limits.batch_records, RESTORE_BATCH_RECORDS);
        assert_eq!(limits.batch_bytes, RESTORE_BATCH_BYTES);
        assert!(secret_bytes_match(&[1; 32], &[1; 32]));
        assert!(!secret_bytes_match(&[1; 32], &[2; 32]));

        let mut invalid = engine_limits();
        invalid.backup_max_bytes = 0;
        assert_eq!(
            construction_limits(invalid),
            Err(StorageError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn secret_files_require_absolute_regular_mode_0600_and_exact_length() -> Result<(), StorageError>
    {
        let directory = unique_temp_directory();
        std::fs::create_dir(&directory).map_err(|_| StorageError::FilesystemRejected)?;
        let key_path = directory.join("key");
        let mut key = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|_| StorageError::FilesystemRejected)?;
        key.write_all(&[1; 32])
            .map_err(|_| StorageError::FilesystemRejected)?;
        drop(key);
        assert_eq!(*read_secret_key(&key_path)?, [1; 32]);

        let short_path = directory.join("short");
        let mut short = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&short_path)
            .map_err(|_| StorageError::FilesystemRejected)?;
        short
            .write_all(&[2; 31])
            .map_err(|_| StorageError::FilesystemRejected)?;
        drop(short);
        assert_eq!(
            read_secret_key(&short_path).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );

        let public_path = directory.join("public");
        let mut public = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&public_path)
            .map_err(|_| StorageError::FilesystemRejected)?;
        public
            .write_all(&[3; 32])
            .map_err(|_| StorageError::FilesystemRejected)?;
        drop(public);
        std::fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o644))
            .map_err(|_| StorageError::FilesystemRejected)?;
        assert_eq!(
            read_secret_key(&public_path).map(|_| ()),
            Err(StorageError::FilesystemRejected)
        );

        let link_path = directory.join("link");
        symlink(&key_path, &link_path).map_err(|_| StorageError::FilesystemRejected)?;
        assert_eq!(
            read_secret_key(&link_path).map(|_| ()),
            Err(StorageError::FilesystemRejected)
        );
        assert_eq!(
            read_secret_key(Path::new("relative-key")).map(|_| ()),
            Err(StorageError::FilesystemRejected)
        );
        std::fs::remove_dir_all(directory).map_err(|_| StorageError::FilesystemRejected)?;
        Ok(())
    }
}
