//! Stopped, authenticated copy-on-write immediate-successor migration.

mod admission;

use crate::construction_schema::ConstructionSchema;
use crate::migration_profile::MigrationProfile;
use admission::SourceAdmission;

use std::path::{Path, PathBuf};

use agenc_ircd_crypto::{
    DatabaseBinding, Ed25519SecretKey, LoginIndexKey, OsEntropy, RollbackGuardRootKey,
    StorageDigest, StorageMasterKey,
};
use agenc_ircd_types::{DatabaseId, NetworkId, ServerId};
use zeroize::Zeroizing;

use crate::{
    BackupDestination, ConstructionDirectory, ConstructionDirectoryPhase, ConstructionExecutor,
    ConstructionLimits, ConstructionPlan, ConstructionSourceDatabase, ConstructionSourceFacts,
    ConstructionTarget, DatabaseHeader, InitialStorageRecord, StateDirectory, StorageConstruction,
    StorageConstructionCursor, StorageConstructionKind, StorageEngineLimits, StorageError,
    StorageInitializationConfig, StorageInitializationMode, StorageInitializationOutcome,
    StorageOpenConfig, StorageOperationIdentity, StorageQualification, StoredKey, TableId,
};

/// Exact existing configuration plus the closed migration command arguments.
pub struct MigrationCommandRequest {
    /// Permanent network identity.
    pub network_id: NetworkId,
    /// Permanent local server identity.
    pub server_id: ServerId,
    /// Continuously locked source directory.
    pub source_state_directory: PathBuf,
    /// Configured storage master key, reused for the new generation.
    pub master_key_file: PathBuf,
    /// Configured rollback root, reused under the fresh target binding.
    pub rollback_guard_key_file: PathBuf,
    /// Current login-index key.
    pub login_index_key_file: PathBuf,
    /// Previous login-index key during a transition.
    pub previous_login_index_key_file: Option<PathBuf>,
    /// Existing private backup directory.
    pub backup_directory: PathBuf,
    /// Configured backup signing key.
    pub backup_signing_key_file: PathBuf,
    /// Offline-authorized backup trust keys.
    pub trusted_backup_keys: Vec<crate::RestoreTrustKey>,
    /// Wall time used only for the newly created signed source backup.
    pub created_at: u64,
    /// Literal successor selected by the admitted command profile, two or three.
    pub target_schema_generation: u64,
    /// New output directory, installed by no-replace atomic rename.
    pub output_state_directory: PathBuf,
    /// Resume only an exactly matching authenticated target.
    pub resume: bool,
    /// Existing storage and filesystem ceilings.
    pub limits: StorageEngineLimits,
}

/// Verified installed target and retained rollback backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationCommandReceipt {
    /// Installed target state directory.
    pub output_state_directory: PathBuf,
    /// Newly created and reverified source backup.
    pub source_backup: PathBuf,
    /// Permanent authenticated operation identifier.
    pub storage_operation_id: StorageDigest,
    /// Preserved logical state generation.
    pub state_generation: u64,
}

/// Migrates only a fully authenticated generation-one source into a new directory.
pub fn execute_migration_command(
    request: MigrationCommandRequest,
    qualifications: &[StorageQualification],
) -> Result<MigrationCommandReceipt, StorageError> {
    execute_migration_with_faults(
        request,
        qualifications,
        crate::StorageFaultInjector::disabled(),
    )
}

/// Migrates a generation-two source only after its required semantic scan.
///
/// Composition must supply a validator for the frozen source command grammar,
/// audit signatures and complete chain. The scan precedes all backup and target
/// creation, including on resumed and already-installed invocations.
pub fn execute_validated_migration_command(
    request: MigrationCommandRequest,
    qualifications: &[StorageQualification],
    validator: &mut dyn crate::SourceRecordValidator,
) -> Result<MigrationCommandReceipt, StorageError> {
    execute_migration_inner(
        request,
        qualifications,
        crate::StorageFaultInjector::disabled(),
        SourceAdmission::SchemaTwo(validator),
    )
}

pub(crate) fn execute_migration_with_faults(
    request: MigrationCommandRequest,
    qualifications: &[StorageQualification],
    faults: crate::StorageFaultInjector,
) -> Result<MigrationCommandReceipt, StorageError> {
    execute_migration_inner(request, qualifications, faults, SourceAdmission::LegacyOne)
}

fn execute_migration_inner(
    request: MigrationCommandRequest,
    qualifications: &[StorageQualification],
    faults: crate::StorageFaultInjector,
    mut admission: SourceAdmission<'_>,
) -> Result<MigrationCommandReceipt, StorageError> {
    let profile = admission.profile();
    if request.target_schema_generation != profile.target_generation() || request.created_at == 0 {
        return Err(StorageError::UnsupportedMigration);
    }
    let limits = request.limits.validate()?;
    let _trusted =
        crate::restore_command::maintenance_backup_trust_keys(&request.trusted_backup_keys)?;
    let mut secrets = Secrets::load(&request)?;
    secrets.faults = faults.clone();
    let mut source = ConstructionSourceDatabase::open_migration_profile(
        secrets.config(&request, &request.source_state_directory, qualifications)?,
        profile,
    )?;
    checkpoint_source(&mut source)?;
    admission.validate(&source)?;
    let source_backup = backup_source(&request, &secrets, &mut source, profile)?;
    let facts = source.facts()?;
    let directory = ConstructionDirectory::open_with_faults(
        &request.output_state_directory,
        request.resume,
        faults,
    )?;
    let target = select_target(&request, &secrets, &directory, qualifications, facts.header)?;
    let construction_limits = ConstructionLimits {
        source_database_bytes: limits.database_max_bytes,
        source_backup_bytes: limits.backup_max_bytes,
        target_database_bytes: limits.database_max_bytes,
        target_backup_bytes: limits.backup_max_bytes,
        plan_bytes: limits.backup_max_bytes,
        batch_records: 1_000,
        batch_bytes: 16_777_216,
    }
    .validate()?;
    let execution = Execution {
        profile,
        request: &request,
        qualifications,
        secrets,
        directory,
        target,
        facts,
        construction_limits,
        source_backup,
    };
    execution.run(&mut source)
}

struct Secrets {
    faults: crate::StorageFaultInjector,
    master: Zeroizing<[u8; 32]>,
    guard: Zeroizing<[u8; 32]>,
    login: Zeroizing<[u8; 32]>,
    previous_login: Option<Zeroizing<[u8; 32]>>,
}

impl Secrets {
    fn load(request: &MigrationCommandRequest) -> Result<Self, StorageError> {
        use crate::restore_command::read_secret_key;
        Ok(Self {
            faults: crate::StorageFaultInjector::disabled(),
            master: read_secret_key(&request.master_key_file)?,
            guard: read_secret_key(&request.rollback_guard_key_file)?,
            login: read_secret_key(&request.login_index_key_file)?,
            previous_login: request
                .previous_login_index_key_file
                .as_deref()
                .map(read_secret_key)
                .transpose()?,
        })
    }

    fn config(
        &self,
        request: &MigrationCommandRequest,
        path: &Path,
        qualifications: &[StorageQualification],
    ) -> Result<StorageOpenConfig, StorageError> {
        Ok(StorageOpenConfig {
            expected_network_id: request.network_id,
            expected_server_id: request.server_id,
            state_directory: StateDirectory::open_with_faults(
                path,
                qualifications,
                self.faults.clone(),
            )?,
            storage_master_key: StorageMasterKey::from_bytes(*self.master),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(*self.guard),
            login_index_key: LoginIndexKey::from_bytes(*self.login),
            previous_login_index_key: self
                .previous_login
                .as_deref()
                .map(|key| LoginIndexKey::from_bytes(*key)),
            limits: request.limits,
        })
    }
}

fn backup_source(
    request: &MigrationCommandRequest,
    secrets: &Secrets,
    source: &mut ConstructionSourceDatabase,
    profile: MigrationProfile,
) -> Result<PathBuf, StorageError> {
    let signing_bytes = crate::restore_command::read_secret_key(&request.backup_signing_key_file)?;
    let id = fresh_id(&[0; 16])?;
    let name = format!(
        "migration-{}-to-{}-{}.backup",
        profile.source_generation(),
        profile.target_generation(),
        DatabaseId::from_bytes(id).to_base64url()
    );
    source.engine.start_backup(
        BackupDestination::new(&request.backup_directory, &name)?,
        Ed25519SecretKey::from_bytes(*signing_bytes),
        request.created_at,
        id,
    )?;
    while source.engine.service_backup()?.is_none() {}
    let path = request.backup_directory.join(name);
    let file = open_backup(&path)?;
    let verified = crate::verify_backup(
        file,
        &StorageMasterKey::from_bytes(*secrets.master),
        &RollbackGuardRootKey::from_bytes(*secrets.guard),
        &crate::restore_command::maintenance_backup_trust_keys(&request.trusted_backup_keys)?,
        request.limits.backup_max_bytes,
    )?;
    let facts = source.facts()?;
    if verified.header.source_header() != &facts.header
        || verified.state_meta.tbs() != &facts.state
        || verified.header.source_rollback_guard().complete_hash()? != facts.rollback_guard_hash
    {
        return Err(StorageError::StaleState);
    }
    Ok(path)
}

fn checkpoint_source(source: &mut ConstructionSourceDatabase) -> Result<(), StorageError> {
    source
        .engine
        .checkpoint_for_shutdown()
        .map_err(|error| match error {
            crate::engine::EngineCommitFailure::Rejected(error) => error,
            crate::engine::EngineCommitFailure::Indeterminate => StorageError::Unavailable,
        })?;
    Ok(())
}

fn open_backup(path: &Path) -> Result<std::fs::File, StorageError> {
    use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StorageError::FilesystemRejected)?;
    let stat = fstat(&fd).map_err(|_| StorageError::FilesystemRejected)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_mode & 0o777 != 0o600
    {
        return Err(StorageError::FilesystemRejected);
    }
    Ok(std::fs::File::from(fd))
}

fn fresh_id(source: &[u8; 16]) -> Result<[u8; 16], StorageError> {
    for _ in 0..8 {
        let mut bytes = [0; 16];
        OsEntropy::fill(&mut bytes)?;
        if &bytes != source {
            return Ok(bytes);
        }
    }
    Err(StorageError::Unavailable)
}

fn select_target(
    request: &MigrationCommandRequest,
    secrets: &Secrets,
    directory: &ConstructionDirectory,
    qualifications: &[StorageQualification],
    source: DatabaseHeader,
) -> Result<DatabaseHeader, StorageError> {
    let schema = ConstructionSchema::from_generation(request.target_schema_generation)?;
    let generation = source
        .tbs()
        .storage_key_generation
        .checked_add(1)
        .ok_or(StorageError::Overflow)?;
    if request.resume {
        let config = || secrets.config(request, &directory.selected_path(), qualifications);
        let target = match ConstructionTarget::open_stopped(config()?, schema) {
            Ok(target) => target.header(),
            Err(error) => ConstructionTarget::completed_header_stopped(config()?, schema)
                .map_err(|_| error)?,
        };
        let expected =
            schema.header(source.tbs(), target.tbs().database_instance_id, generation)?;
        if target.tbs() != &expected
            || target.tbs().database_instance_id == source.tbs().database_instance_id
        {
            return Err(StorageError::ResumeMismatch);
        }
        return Ok(target);
    }
    let tbs = schema.header(
        source.tbs(),
        DatabaseId::from_bytes(fresh_id(source.tbs().database_instance_id.as_bytes())?),
        generation,
    )?;
    Ok(DatabaseHeader::new(tbs, StorageDigest::from_bytes([0; 32])))
}

struct Execution<'a> {
    profile: MigrationProfile,
    request: &'a MigrationCommandRequest,
    qualifications: &'a [StorageQualification],
    secrets: Secrets,
    directory: ConstructionDirectory,
    target: DatabaseHeader,
    facts: ConstructionSourceFacts,
    construction_limits: ConstructionLimits,
    source_backup: PathBuf,
}

impl Execution<'_> {
    fn config(&self) -> Result<StorageOpenConfig, StorageError> {
        self.secrets.config(
            self.request,
            &self.directory.selected_path(),
            self.qualifications,
        )
    }

    fn run(
        self,
        source: &mut ConstructionSourceDatabase,
    ) -> Result<MigrationCommandReceipt, StorageError> {
        let file = if self.directory.phase() == ConstructionDirectoryPhase::Installed {
            self.directory.anonymous_plan_file()?
        } else {
            self.directory.rebuild_plan_file()?
        };
        let plan = source.rebuild_migration_profile_plan(
            self.profile,
            file,
            &StorageMasterKey::from_bytes(*self.secrets.master),
            DatabaseBinding::new(
                self.request.network_id,
                self.request.server_id,
                self.target.tbs().server_incarnation,
                self.target.tbs().database_instance_id,
            ),
            self.target.tbs().storage_key_generation,
            self.construction_limits,
        )?;
        let identity = self.identity(&plan)?;
        if self.directory.phase() == ConstructionDirectoryPhase::Installed {
            let verified = ConstructionTarget::verify_completed(
                self.config()?,
                identity,
                self.directory.output_path_hash(),
            )?;
            return Ok(self.receipt(verified.completion().storage_operation_id));
        }
        self.install(source, plan, identity)
    }

    fn identity(&self, plan: &ConstructionPlan) -> Result<StorageOperationIdentity, StorageError> {
        Ok(StorageOperationIdentity {
            kind: StorageConstructionKind::Migrate,
            command_version: 1,
            source_database_header_hash: self.facts.header.complete_hash()?,
            target_database_header_hash: if self.request.resume {
                self.target.complete_hash()?
            } else {
                StorageDigest::from_bytes([0; 32])
            },
            source_rollback_guard_hash: self.facts.rollback_guard_hash,
            source_stream_digest: None,
            source_schema_generation: self.profile.source_generation(),
            target_schema_generation: self.profile.target_generation(),
            transform_profile_hash: self.profile.hash()?,
            target_database_instance_id: self.target.tbs().database_instance_id,
            source_master_key_id: StorageMasterKey::from_bytes(*self.secrets.master)
                .source_operation_key_id()?,
            source_guard_root_key_id: RollbackGuardRootKey::from_bytes(*self.secrets.guard)
                .source_operation_key_id()?,
            target_master_key_id: StorageMasterKey::from_bytes(*self.secrets.master)
                .target_operation_key_id()?,
            target_guard_root_key_id: RollbackGuardRootKey::from_bytes(*self.secrets.guard)
                .target_operation_key_id()?,
            planned_entry_count: plan.entry_count(),
            construction_plan_hash: plan.hash(),
        })
    }

    fn initialize(&self, marker: &StorageConstruction) -> Result<(), StorageError> {
        let result =
            crate::initialize::initialize_stopped_construction(StorageInitializationConfig {
                state_directory: StateDirectory::open(
                    &self.directory.selected_path(),
                    self.qualifications,
                )?,
                header_tbs: *self.target.tbs(),
                storage_master_key: StorageMasterKey::from_bytes(*self.secrets.master),
                rollback_guard_root_key: RollbackGuardRootKey::from_bytes(*self.secrets.guard),
                mode: StorageInitializationMode::Construction,
                initial_records: vec![InitialStorageRecord::new(
                    TableId::StorageConstruction,
                    StoredKey::new(crate::STORAGE_CONSTRUCTION_KEY.to_vec())?,
                    1,
                    marker.encode()?,
                )?],
                account_service_response_count: self.facts.state.account_service_response_count,
                state_generation: self.facts.state.state_generation,
                predecessor_guard_hash: self.facts.rollback_guard_hash,
                limits: self.request.limits,
            })?;
        if matches!(result, StorageInitializationOutcome::Complete { .. }) {
            Ok(())
        } else {
            Err(StorageError::Unavailable)
        }
    }

    fn install(
        self,
        source: &mut ConstructionSourceDatabase,
        plan: ConstructionPlan,
        identity: StorageOperationIdentity,
    ) -> Result<MigrationCommandReceipt, StorageError> {
        let initial = StorageConstruction {
            identity,
            output_path_hash: self.directory.output_path_hash(),
            next_target: StorageConstructionCursor::BeforeFirst,
            target_records_committed: 0,
        };
        if !self.request.resume {
            self.initialize(&initial)?;
        }
        let schema = ConstructionSchema::from_generation(self.profile.target_generation())?;
        let mut target = match ConstructionTarget::open_stopped(self.config()?, schema) {
            Ok(target) => target,
            Err(error) if self.request.resume => return self.install_finalized(identity, error),
            Err(error) => return Err(error),
        };
        let marker = target.marker()?;
        if self.request.resume && marker.identity != identity {
            return Err(StorageError::ResumeMismatch);
        }
        let mut transform = self.profile.transformer(self.facts.state.state_generation);
        let preflight = StorageConstruction {
            identity: marker.identity,
            ..initial
        };
        let _admission = plan.preflight(
            &preflight,
            self.facts.state.state_generation,
            self.facts.state.account_service_response_count,
            source,
            &mut transform,
            self.construction_limits,
        )?;
        let expected = marker.identity;
        let mut executor = ConstructionExecutor::resume(marker, plan, self.construction_limits)?;
        while executor.service_batch(source, &mut transform, &mut target)? != 0 {}
        let operation = executor.finalize(&mut target)?;
        drop(target);
        self.finish_install(expected, operation)
    }

    fn install_finalized(
        self,
        identity: StorageOperationIdentity,
        original: StorageError,
    ) -> Result<MigrationCommandReceipt, StorageError> {
        let verified = ConstructionTarget::verify_completed(
            self.config()?,
            identity,
            self.directory.output_path_hash(),
        )
        .map_err(|_| original)?;
        self.finish_install(identity, verified.completion().storage_operation_id)
    }

    fn finish_install(
        self,
        identity: StorageOperationIdentity,
        operation: StorageDigest,
    ) -> Result<MigrationCommandReceipt, StorageError> {
        self.directory.remove_plan_file()?;
        let verification = ConstructionTarget::verify_completed(
            self.config()?,
            identity,
            self.directory.output_path_hash(),
        )?;
        if verification.completion().storage_operation_id != operation {
            return Err(StorageError::StaleState);
        }
        let receipt = self.receipt(operation);
        self.directory.install(verification)?;
        Ok(receipt)
    }

    fn receipt(&self, operation: StorageDigest) -> MigrationCommandReceipt {
        MigrationCommandReceipt {
            output_state_directory: self.directory.output_path().to_path_buf(),
            source_backup: self.source_backup.clone(),
            storage_operation_id: operation,
            state_generation: self.facts.state.state_generation,
        }
    }
}
