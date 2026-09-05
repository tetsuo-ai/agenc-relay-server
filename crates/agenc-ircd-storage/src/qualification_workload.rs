//! Production-path physical growth qualification driven by a stopped daemon.
//!
//! The workload opens the real storage owner on a fresh database, commits
//! every required Section 28.7 mutation shape through the production engine
//! with a measurement-only boundary probe attached, and measures allocated
//! blocks around each case and around every guard, backup, and checkpoint
//! phase. Reserve boundaries are reached with the real `R(F) + G` and
//! `R(F) + O` admission checks, using a fallocated ballast file when the
//! filesystem has more free space than the greatest configurable reserve.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agenc_ircd_crypto::{
    Ed25519SecretKey, LoginIndexKey, OsEntropy, RollbackGuardRootKey, StorageDigest,
    StorageMasterKey, storage_qualification_component_hash,
};
use agenc_ircd_types::{
    DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation, TransactionId,
};
use rustix::fs::{FallocateFlags, fallocate};

use crate::qualification::{
    MAX_QUALIFIED_OBSERVED_GROWTH, PhaseGrowth, QualificationTarget, REQUIRED_QUALIFICATION_CASES,
    StorageGrowthCase, StorageGrowthProbe, StorageGrowthRecorder, StorageQualificationReportTbs,
    allocated_directory_bytes, phase_growth,
};
use crate::{
    BackupDestination, CheckpointOutcome, CommitOutcome, CommitReceipt, DatabaseHeaderTbs,
    ExistingRecord, FilesystemTuple, InitialStorageRecord, LOGIN_INDEX_KEY_STATE_KEY,
    LoginIndexKeyState, MAX_DOMAIN_RECORD_BODY_BYTES, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH,
    MAX_STORED_KEY_BYTES, MAX_TRACKED_MUTATIONS, PersistentRecordValue, ReadPlan, RecordMutation,
    SCHEMA_GENERATION, SealedRecord, StateDirectory, StorageAccountingLimits, StorageEngineLimits,
    StorageError, StorageFaultInjector, StorageFaultSite, StorageInitializationConfig,
    StorageInitializationMode, StorageInitializationOutcome, StorageMutationBatch,
    StorageMutationHead, StorageOpenConfig, StorageOwner, StoragePort, StorageQualification,
    StorageStatistics, StoredKey, TableId, initialize_storage,
};

/// Fixed description of the generated boundary corpus, hashed into every report.
pub const WORKLOAD_DESCRIPTION: &[u8] = b"agenc-ircd production storage qualification workload v1\n\
table=sanction record_kind=2 key_bytes=18 max_key_bytes=4096\n\
small_body_bytes=40 tree_body_bytes=512 tree_records=4096\n\
max_body_bytes=16760000 max_replace_body_bytes=8380000 max_records=65535 mixed_shape_records=21845\n\
cases=insert-empty,insert-one,replace-min,delete-one,insert-max-value,replace-max-value,\
delete-max-value,insert-max-key,insert-max-records,delete-max-records,mixed-max-records,\
btree-split,btree-merge,fragmented,checkpoint,guard-temp-fsync,guard-rename,\
guard-directory-fsync,reserve-minus-one,reserve-equal,reserve-plus-one\n\
phases=every StorageFaultSite before/after pair on the production path\n\
boundaries=reserve and backup admission one byte below, at, and above the reserve\n";
const REDB_FEATURES: &[u8] = b"redb=4.2.0;default-features=false;features=std\n";
const RELEASE_PROFILE: &[u8] =
    include_bytes!("../../../conformance/stage-five-storage-profile.toml");
const WORKLOAD_TABLE: TableId = TableId::Sanction;
const WORKLOAD_KIND: u16 = 2;
const KEY_BYTES: usize = 18;
const SMALL_BODY_BYTES: usize = 40;
const TREE_BODY_BYTES: usize = 512;
const TREE_RECORDS: u64 = 4_096;
const MAX_RECORDS: u64 = MAX_TRACKED_MUTATIONS as u64;
/// Largest body a replacement may carry: the tracked-byte ceiling counts the
/// replaced and the replacing sealed records together.
const MAX_REPLACE_BODY_BYTES: usize = 8_380_000;
const MIXED_SHAPE_RECORDS: u64 = MAX_RECORDS / 3;
const BOUNDARY_ATTEMPTS: u32 = 5;
const BOUNDARY_RESERVE_PERCENT: u8 = 1;
/// Free space left below the greatest configurable reserve after ballast.
const BALLAST_MARGIN_BYTES: u64 = 256 * 1_024 * 1_024;
const MIN_FIXED_RESERVE_BYTES: u64 = 67_108_864;
const MAX_FIXED_RESERVE_BYTES: u64 = 1_099_511_627_776;
const RANGE_PAGE: u16 = 4_096;
const BACKUP_CREATED_AT: u64 = 1_700_000_000;

/// Inputs of one production storage qualification run.
pub struct QualificationRequest<'a> {
    /// Empty, mode 0700, freshly created state directory on the tuple under test.
    pub state_directory: &'a Path,
    /// Empty, mode 0700 sibling directory on the same filesystem for backups and ballast.
    pub scratch_directory: &'a Path,
    /// Qualifications the running binary accepts for the probed tuple.
    pub qualifications: &'a [StorageQualification],
    /// Engine limits of the main session; boundary sessions override the reserve.
    pub limits: StorageEngineLimits,
    /// Printable kernel release recorded in the report.
    pub kernel_release: String,
}

/// A failed run keeps the raw log written before the failing step.
#[derive(Debug)]
pub struct QualificationFailure {
    /// The storage error that stopped the run.
    pub error: StorageError,
    /// Raw log lines recorded before the failure.
    pub raw_log: Vec<u8>,
}

impl std::fmt::Display for QualificationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "storage qualification failed: {}", self.error)
    }
}

impl std::error::Error for QualificationFailure {}

/// Complete unsigned measurement plus its raw log.
pub struct QualificationOutcome {
    /// Validated unsigned report.
    pub report: StorageQualificationReportTbs,
    /// Immutable raw measurement log the report hashes.
    pub raw_log: Vec<u8>,
    /// Probed filesystem tuple.
    pub tuple: FilesystemTuple,
    /// Boundary samples the probe retained.
    pub sample_count: usize,
    /// Ballast bytes fallocated to reach the reserve boundary, zero when unneeded.
    pub ballast_bytes: u64,
    /// Whether every observed growth stayed at or below the qualified ceiling.
    /// When false the report cannot be encoded or signed; the summary and raw
    /// log remain the evidence of the failed qualification.
    pub within_ceiling: bool,
}

/// Runs the complete workload and returns the validated unsigned report.
pub fn qualify_production_storage(
    request: QualificationRequest<'_>,
) -> Result<QualificationOutcome, QualificationFailure> {
    let mut log = RawLog::default();
    match qualify_inner(request, &mut log) {
        Ok(outcome) => Ok(outcome),
        Err(error) => Err(QualificationFailure {
            error,
            raw_log: log.finish(),
        }),
    }
}

fn qualify_inner(
    request: QualificationRequest<'_>,
    log: &mut RawLog,
) -> Result<QualificationOutcome, StorageError> {
    require_empty_private_directory(request.state_directory)?;
    require_empty_private_directory(request.scratch_directory)?;
    let tuple = StateDirectory::probe(request.state_directory)?;
    let probe = Arc::new(StorageGrowthProbe::new(request.state_directory)?);
    let identity = Identity::random()?;
    let mut recorder = StorageGrowthRecorder::new();
    initialize_database(&request, &identity, &probe)?;
    let mut session = Session::open(&request, &identity, &probe, request.limits)?;
    run_growth_cases(&mut session, &mut recorder, log, request.state_directory)?;
    session.shutdown()?;
    record_phase_cases(&probe, &mut recorder, log)?;
    let ballast = Ballast::ensure(&request, &probe)?;
    let ballast_bytes = ballast.as_ref().map_or(0, |ballast| ballast.bytes);
    log.line(&format!("ballast|{ballast_bytes}"));
    run_boundary_cases(&request, &mut recorder, log)?;
    drop(ballast);
    let (cases, maximum_observed_growth) = recorder.finish()?;
    let sample_count = probe.samples()?.len();
    let names = cases
        .iter()
        .map(StorageGrowthCase::name)
        .collect::<std::collections::BTreeSet<_>>();
    if REQUIRED_QUALIFICATION_CASES
        .iter()
        .any(|name| !names.contains(name))
    {
        return Err(StorageError::StaleState);
    }
    let within_ceiling = maximum_observed_growth <= MAX_QUALIFIED_OBSERVED_GROWTH;
    log.line(&format!(
        "maximum|{maximum_observed_growth}|{MAX_QUALIFIED_OBSERVED_GROWTH}|{}",
        if within_ceiling { "within" } else { "exceeded" }
    ));
    let raw_log = log.snapshot();
    let report = StorageQualificationReportTbs {
        target: QualificationTarget::native(),
        filesystem_type: tuple.filesystem_type,
        block_size: tuple.block_size,
        mount_flags: tuple.mount_flags,
        kernel_release: request.kernel_release,
        redb_features_hash: storage_qualification_component_hash(b"redb-features", REDB_FEATURES)?,
        release_profile_hash: storage_qualification_component_hash(
            b"release-profile",
            RELEASE_PROFILE,
        )?,
        corpus_hash: storage_qualification_component_hash(
            b"boundary-corpus",
            WORKLOAD_DESCRIPTION,
        )?,
        cases,
        maximum_observed_growth,
        raw_log_hash: storage_qualification_component_hash(b"raw-log", &raw_log)?,
    };
    Ok(QualificationOutcome {
        report,
        raw_log,
        tuple,
        sample_count,
        ballast_bytes,
        within_ceiling,
    })
}

fn require_empty_private_directory(path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StorageError::FilesystemRejected)?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
        || fs::read_dir(path)
            .map_err(|_| StorageError::FilesystemRejected)?
            .next()
            .is_some()
    {
        return Err(StorageError::FilesystemRejected);
    }
    Ok(())
}

/// Bounded ASCII raw log.
#[derive(Default)]
struct RawLog {
    lines: Vec<u8>,
}

impl RawLog {
    fn line(&mut self, text: &str) {
        self.lines.extend_from_slice(text.as_bytes());
        self.lines.push(b'\n');
    }

    fn snapshot(&self) -> Vec<u8> {
        self.lines.clone()
    }

    fn finish(self) -> Vec<u8> {
        self.lines
    }
}

/// Fresh random identity and keys; nothing here is derived from a real deployment.
struct Identity {
    network: NetworkId,
    server: ServerId,
    incarnation: ServerIncarnation,
    database: DatabaseId,
    epoch: RecoveryEpoch,
    master: [u8; 32],
    guard_root: [u8; 32],
    login_key: [u8; 32],
}

impl Identity {
    fn random() -> Result<Self, StorageError> {
        let mut network = [0_u8; 32];
        let mut server = [0_u8; 16];
        let mut incarnation = [0_u8; 16];
        let mut database = [0_u8; 16];
        let mut epoch = [0_u8; 16];
        let mut master = [0_u8; 32];
        let mut guard_root = [0_u8; 32];
        let mut login_key = [0_u8; 32];
        for buffer in [
            &mut network[..],
            &mut master[..],
            &mut guard_root[..],
            &mut login_key[..],
        ] {
            OsEntropy::fill(buffer).map_err(|_| StorageError::Unavailable)?;
        }
        for buffer in [
            &mut server[..],
            &mut incarnation[..],
            &mut database[..],
            &mut epoch[..],
        ] {
            OsEntropy::fill(buffer).map_err(|_| StorageError::Unavailable)?;
        }
        Ok(Self {
            network: NetworkId::from_bytes(network),
            server: ServerId::from_bytes(server),
            incarnation: ServerIncarnation::from_bytes(incarnation),
            database: DatabaseId::from_bytes(database),
            epoch: RecoveryEpoch::from_bytes(epoch),
            master,
            guard_root,
            login_key,
        })
    }

    fn state_directory(
        &self,
        request: &QualificationRequest<'_>,
        probe: &Arc<StorageGrowthProbe>,
    ) -> Result<StateDirectory, StorageError> {
        StateDirectory::open_with_faults(
            request.state_directory,
            request.qualifications,
            StorageFaultInjector::probing(Arc::clone(probe)),
        )
    }
}

fn initialize_database(
    request: &QualificationRequest<'_>,
    identity: &Identity,
    probe: &Arc<StorageGrowthProbe>,
) -> Result<(), StorageError> {
    let login_key = LoginIndexKey::from_bytes(identity.login_key);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(identity.network))?;
    let initial = InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let outcome = initialize_storage(StorageInitializationConfig {
        state_directory: identity.state_directory(request, probe)?,
        header_tbs: DatabaseHeaderTbs::new(
            identity.network,
            identity.server,
            identity.incarnation,
            identity.database,
            1,
            SCHEMA_GENERATION,
            identity.epoch,
        )?,
        storage_master_key: StorageMasterKey::from_bytes(identity.master),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(identity.guard_root),
        mode: StorageInitializationMode::Live,
        initial_records: vec![initial],
        account_service_response_count: 0,
        state_generation: 0,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: request.limits,
    })?;
    match outcome {
        StorageInitializationOutcome::Complete { .. } => Ok(()),
        StorageInitializationOutcome::Indeterminate => Err(StorageError::Unavailable),
    }
}

/// One open production owner with the accounting every batch head must carry.
struct Session {
    owner: StorageOwner,
    port: StoragePort,
    commit_sequence: u64,
    generation: u64,
    response_count: u64,
    logical_bytes: u64,
    backup_bytes: u64,
    next_transaction: u64,
    limits: StorageEngineLimits,
}

impl Session {
    fn open(
        request: &QualificationRequest<'_>,
        identity: &Identity,
        probe: &Arc<StorageGrowthProbe>,
        limits: StorageEngineLimits,
    ) -> Result<Self, StorageError> {
        let owner = StorageOwner::start(StorageOpenConfig {
            expected_network_id: identity.network,
            expected_server_id: identity.server,
            state_directory: identity.state_directory(request, probe)?,
            storage_master_key: StorageMasterKey::from_bytes(identity.master),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(identity.guard_root),
            login_index_key: LoginIndexKey::from_bytes(identity.login_key),
            previous_login_index_key: None,
            limits,
        })?;
        let recovered = owner.recovered_state();
        let port = owner.port();
        Ok(Self {
            commit_sequence: recovered.storage_commit_sequence(),
            generation: recovered.state_generation(),
            response_count: recovered.account_service_response_count(),
            logical_bytes: recovered.logical_database_bytes(),
            backup_bytes: recovered.backup_stream_bytes(),
            next_transaction: 1,
            limits,
            owner,
            port,
        })
    }

    fn statistics(&self) -> Result<StorageStatistics, StorageError> {
        self.port.try_statistics()?.wait()
    }

    /// Commits one state-advancing batch and refreshes the accounting from the owner.
    fn commit(&mut self, mutations: Vec<RecordMutation>) -> Result<CommitReceipt, StorageError> {
        let mut transaction = [0_u8; 16];
        for (slot, byte) in transaction
            .iter_mut()
            .skip(8)
            .zip(self.next_transaction.to_be_bytes())
        {
            *slot = byte;
        }
        self.next_transaction = self
            .next_transaction
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let head = StorageMutationHead {
            transaction_id: TransactionId::from_bytes(transaction),
            expected_storage_commit_sequence: self.commit_sequence,
            expected_state_generation: self.generation,
            resulting_state_generation: self
                .generation
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: self.response_count,
            resulting_account_service_response_count: self.response_count,
        };
        let batch = StorageMutationBatch::new(
            head,
            1,
            StorageAccountingLimits {
                current_logical_database_bytes: self.logical_bytes,
                current_backup_stream_bytes: self.backup_bytes,
                database_max_bytes: self.limits.database_max_bytes,
                backup_max_bytes: self.limits.backup_max_bytes,
            },
            mutations,
        )?;
        let receipt = match self.port.try_commit(batch)?.wait()? {
            CommitOutcome::Committed(receipt) => receipt,
            CommitOutcome::Rejected(error) => return Err(error),
            CommitOutcome::Indeterminate => return Err(StorageError::Unavailable),
        };
        self.commit_sequence = receipt.storage_commit_sequence;
        self.generation = receipt.state_generation;
        let statistics = self.statistics()?;
        self.logical_bytes = statistics.logical_database_bytes();
        self.backup_bytes = statistics.backup_stream_bytes();
        Ok(receipt)
    }

    fn checkpoint(&self) -> Result<(), StorageError> {
        match self.port.try_checkpoint()?.wait()? {
            CheckpointOutcome::Installed(_) | CheckpointOutcome::NotNeeded => Ok(()),
            CheckpointOutcome::Rejected(error) => Err(error),
            CheckpointOutcome::Indeterminate => Err(StorageError::Unavailable),
        }
    }

    /// Reads every current row whose key starts with `prefix`, in key order.
    fn existing_with_prefix(
        &self,
        prefix: u8,
    ) -> Result<Vec<(StoredKey, ExistingRecord)>, StorageError> {
        let mut rows = Vec::new();
        let mut start = key(prefix, 0)?;
        let end = key(prefix.checked_add(1).ok_or(StorageError::Overflow)?, 0)?;
        loop {
            let page = self
                .port
                .try_read(ReadPlan::range(
                    WORKLOAD_TABLE,
                    start,
                    end.clone(),
                    RANGE_PAGE,
                )?)?
                .wait()?;
            let Some(last) = page.records.last().map(|record| record.key.clone()) else {
                break;
            };
            rows.try_reserve(page.records.len())
                .map_err(|_| StorageError::AllocationFailed)?;
            for record in page.records {
                let sealed = SealedRecord::decode(&record.sealed_record)?;
                rows.push((
                    record.key,
                    ExistingRecord::new(1, sealed.record_id()?, record.sealed_record.len())?,
                ));
            }
            if !page.truncated {
                break;
            }
            let mut successor = last.as_bytes().to_vec();
            successor.push(0);
            start = StoredKey::new(successor)?;
        }
        Ok(rows)
    }

    fn shutdown(self) -> Result<(), StorageError> {
        drop(self.port);
        self.owner.shutdown()
    }
}

fn key(prefix: u8, index: u64) -> Result<StoredKey, StorageError> {
    let mut bytes = vec![prefix; KEY_BYTES - 8];
    bytes.extend_from_slice(&index.to_be_bytes());
    StoredKey::new(bytes)
}

fn body(fill: u8, len: usize) -> Result<Vec<u8>, StorageError> {
    let value = PersistentRecordValue::new(
        WORKLOAD_TABLE,
        WORKLOAD_KIND,
        1,
        0,
        None,
        Vec::new(),
        vec![fill; len],
    )?;
    value.encode()
}

fn put(
    key: StoredKey,
    before: Option<ExistingRecord>,
    plaintext: Vec<u8>,
) -> Result<RecordMutation, StorageError> {
    RecordMutation::put(WORKLOAD_TABLE, key, 1, before, plaintext)
}

fn puts(prefix: u8, count: u64, fill: u8, len: usize) -> Result<Vec<RecordMutation>, StorageError> {
    let mut mutations = Vec::new();
    mutations
        .try_reserve_exact(usize::try_from(count).map_err(|_| StorageError::Overflow)?)
        .map_err(|_| StorageError::AllocationFailed)?;
    for index in 0..count {
        mutations.push(put(key(prefix, index)?, None, body(fill, len)?)?);
    }
    Ok(mutations)
}

fn deletes(rows: Vec<(StoredKey, ExistingRecord)>) -> Vec<RecordMutation> {
    rows.into_iter()
        .map(|(key, before)| RecordMutation::delete(WORKLOAD_TABLE, key, before))
        .collect()
}

fn single_existing(
    session: &Session,
    prefix: u8,
) -> Result<(StoredKey, ExistingRecord), StorageError> {
    let mut rows = session.existing_with_prefix(prefix)?;
    if rows.len() != 1 {
        return Err(StorageError::StaleState);
    }
    rows.pop().ok_or(StorageError::StaleState)
}

fn first_existing(
    session: &Session,
    prefix: u8,
) -> Result<(StoredKey, ExistingRecord), StorageError> {
    session
        .existing_with_prefix(prefix)?
        .into_iter()
        .next()
        .ok_or(StorageError::StaleState)
}

/// Measures allocated state-directory bytes around one case.
fn measure<T>(
    recorder: &mut StorageGrowthRecorder,
    log: &mut RawLog,
    state: &Path,
    name: &str,
    operation: impl FnOnce() -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    log.line(&format!("begin|{name}"));
    let before = allocated_directory_bytes(state)?;
    let result = operation()?;
    let after = allocated_directory_bytes(state)?;
    let case = StorageGrowthCase::new(name.to_owned(), before, after)?;
    log.line(&format!(
        "case|{name}|{before}|{after}|{}",
        case.positive_delta()
    ));
    recorder.record_observed(case)?;
    Ok(result)
}

// agenc-review: focus owner=storage reviewed=2026-09-05 reason=the fixed Section 28.7 mutation corpus is one ordered sequence whose shapes depend on the rows earlier cases left behind
fn run_growth_cases(
    session: &mut Session,
    recorder: &mut StorageGrowthRecorder,
    log: &mut RawLog,
    state: &Path,
) -> Result<(), StorageError> {
    measure(recorder, log, state, "insert-empty", || {
        session.commit(vec![put(key(0x10, 0)?, None, body(1, SMALL_BODY_BYTES)?)?])
    })?;
    measure(recorder, log, state, "insert-one", || {
        session.commit(vec![put(key(0x10, 1)?, None, body(2, SMALL_BODY_BYTES)?)?])
    })?;
    let (first_key, first) = first_existing(session, 0x10)?;
    measure(recorder, log, state, "replace-min", || {
        session.commit(vec![put(
            first_key,
            Some(first),
            body(3, SMALL_BODY_BYTES)?,
        )?])
    })?;
    let (delete_key, delete_before) = first_existing(session, 0x10)?;
    measure(recorder, log, state, "delete-one", || {
        session.commit(vec![RecordMutation::delete(
            WORKLOAD_TABLE,
            delete_key,
            delete_before,
        )])
    })?;
    measure(recorder, log, state, "insert-max-value", || {
        session.commit(vec![put(
            key(0x11, 0)?,
            None,
            body(4, MAX_DOMAIN_RECORD_BODY_BYTES)?,
        )?])
    })?;
    session.commit(vec![put(
        key(0x13, 0)?,
        None,
        body(5, MAX_REPLACE_BODY_BYTES)?,
    )?])?;
    let (replace_key, replace_before) = single_existing(session, 0x13)?;
    measure(recorder, log, state, "replace-max-value", || {
        session.commit(vec![put(
            replace_key,
            Some(replace_before),
            body(15, MAX_REPLACE_BODY_BYTES)?,
        )?])
    })?;
    let (max_key, max_before) = single_existing(session, 0x11)?;
    measure(recorder, log, state, "delete-max-value", || {
        session.commit(vec![RecordMutation::delete(
            WORKLOAD_TABLE,
            max_key,
            max_before,
        )])
    })?;
    measure(recorder, log, state, "insert-max-key", || {
        let key = StoredKey::new(vec![0x05; MAX_STORED_KEY_BYTES])?;
        session.commit(vec![put(key, None, body(6, SMALL_BODY_BYTES)?)?])
    })?;
    measure(recorder, log, state, "insert-max-records", || {
        session.commit(puts(0x12, MAX_RECORDS, 7, SMALL_BODY_BYTES)?)
    })?;
    let rows = session.existing_with_prefix(0x12)?;
    if rows.len() != usize::try_from(MAX_RECORDS).map_err(|_| StorageError::Overflow)? {
        return Err(StorageError::StaleState);
    }
    measure(recorder, log, state, "delete-max-records", || {
        session.commit(deletes(rows))
    })?;
    run_mixed_and_tree_cases(session, recorder, log, state)?;
    measure(recorder, log, state, "checkpoint", || session.checkpoint())?;
    Ok(())
}

fn run_mixed_and_tree_cases(
    session: &mut Session,
    recorder: &mut StorageGrowthRecorder,
    log: &mut RawLog,
    state: &Path,
) -> Result<(), StorageError> {
    session.commit(puts(0x20, MIXED_SHAPE_RECORDS, 8, SMALL_BODY_BYTES)?)?;
    session.commit(puts(0x21, MIXED_SHAPE_RECORDS, 9, SMALL_BODY_BYTES)?)?;
    let replaced = session.existing_with_prefix(0x20)?;
    let deleted = session.existing_with_prefix(0x21)?;
    let mut mixed = puts(0x22, MIXED_SHAPE_RECORDS, 10, SMALL_BODY_BYTES)?;
    for (key, before) in replaced {
        mixed.push(put(key, Some(before), body(11, SMALL_BODY_BYTES)?)?);
    }
    mixed.extend(deletes(deleted));
    if mixed.len() != usize::try_from(MAX_RECORDS).map_err(|_| StorageError::Overflow)? {
        return Err(StorageError::StaleState);
    }
    measure(recorder, log, state, "mixed-max-records", || {
        session.commit(mixed)
    })?;
    measure(recorder, log, state, "btree-split", || {
        session.commit(puts(0x30, TREE_RECORDS, 12, TREE_BODY_BYTES)?)
    })?;
    let rows = session.existing_with_prefix(0x30)?;
    let (even, odd): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .enumerate()
        .partition(|(index, _)| index % 2 == 0);
    let even = even.into_iter().map(|(_, row)| row).collect::<Vec<_>>();
    if even.len() != usize::try_from(TREE_RECORDS / 2).map_err(|_| StorageError::Overflow)?
        || odd.is_empty()
    {
        return Err(StorageError::StaleState);
    }
    measure(recorder, log, state, "btree-merge", || {
        session.commit(deletes(even))
    })?;
    measure(recorder, log, state, "fragmented", || {
        let mut gaps = Vec::new();
        for index in (0..TREE_RECORDS).step_by(4) {
            gaps.push(put(key(0x30, index)?, None, body(13, TREE_BODY_BYTES)?)?);
        }
        session.commit(gaps)
    })?;
    Ok(())
}

/// Maps guard phases onto their required case names and records every observed phase.
fn record_phase_cases(
    probe: &StorageGrowthProbe,
    recorder: &mut StorageGrowthRecorder,
    log: &mut RawLog,
) -> Result<(), StorageError> {
    let growth = phase_growth(&probe.samples()?)?;
    let required = [
        ("guard-temp-fsync", StorageFaultSite::GuardFileSync),
        ("guard-rename", StorageFaultSite::GuardRename),
        (
            "guard-directory-fsync",
            StorageFaultSite::GuardDirectorySync,
        ),
    ];
    for (name, site) in required {
        let phase = growth.get(&site).copied().ok_or(StorageError::StaleState)?;
        record_phase(recorder, log, name.to_owned(), site, phase)?;
    }
    for (site, phase) in growth {
        record_phase(
            recorder,
            log,
            format!("phase-{}", site.label()),
            site,
            phase,
        )?;
    }
    Ok(())
}

fn record_phase(
    recorder: &mut StorageGrowthRecorder,
    log: &mut RawLog,
    name: String,
    site: StorageFaultSite,
    phase: PhaseGrowth,
) -> Result<(), StorageError> {
    if phase.pairs == 0 {
        return Err(StorageError::StaleState);
    }
    log.line(&format!(
        "phase|{name}|{}|{}|{}|{}|{}",
        site.label(),
        phase.pairs,
        phase.allocated_before,
        phase.allocated_after,
        phase.maximum_delta
    ));
    recorder.record_observed(StorageGrowthCase::new(
        name,
        phase.allocated_before,
        phase.allocated_after,
    )?)
}

/// Fallocated file that brings free space under the greatest configurable reserve.
struct Ballast {
    path: PathBuf,
    bytes: u64,
}

impl Ballast {
    fn ensure(
        request: &QualificationRequest<'_>,
        probe: &Arc<StorageGrowthProbe>,
    ) -> Result<Option<Self>, StorageError> {
        let available = sample_available(request, probe)?;
        let ceiling = MAX_FIXED_RESERVE_BYTES
            .saturating_sub(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
            .saturating_sub(BALLAST_MARGIN_BYTES);
        if available <= ceiling {
            return Ok(None);
        }
        let bytes = available.saturating_sub(ceiling);
        let path = request.scratch_directory.join("qualification-ballast");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| StorageError::FilesystemRejected)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| StorageError::FilesystemRejected)?;
        let ballast = Self { path, bytes };
        fallocate(&file, FallocateFlags::empty(), 0, bytes)
            .map_err(|_| StorageError::FilesystemRejected)?;
        file.sync_all()
            .map_err(|_| StorageError::FilesystemRejected)?;
        Ok(Some(ballast))
    }
}

impl Drop for Ballast {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn sample_available(
    request: &QualificationRequest<'_>,
    probe: &Arc<StorageGrowthProbe>,
) -> Result<u64, StorageError> {
    let directory = StateDirectory::open_with_faults(
        request.state_directory,
        request.qualifications,
        StorageFaultInjector::probing(Arc::clone(probe)),
    )?;
    Ok(directory
        .capacity(MIN_FIXED_RESERVE_BYTES, BOUNDARY_RESERVE_PERCENT)?
        .available_bytes)
}

#[derive(Clone, Copy)]
enum BoundaryOffset {
    MinusOne,
    Equal,
    PlusOne,
}

impl BoundaryOffset {
    const fn suffix(self) -> &'static str {
        match self {
            Self::MinusOne => "minus-one",
            Self::Equal => "equal",
            Self::PlusOne => "plus-one",
        }
    }

    fn reserve(self, available: u64, required: u64) -> Result<u64, StorageError> {
        let base = available
            .checked_sub(required)
            .ok_or(StorageError::LimitExceeded)?;
        let reserve = match self {
            Self::MinusOne => base.checked_sub(1),
            Self::Equal => Some(base),
            Self::PlusOne => base.checked_add(1),
        }
        .ok_or(StorageError::Overflow)?;
        if !(MIN_FIXED_RESERVE_BYTES..=MAX_FIXED_RESERVE_BYTES).contains(&reserve) {
            return Err(StorageError::LimitExceeded);
        }
        Ok(reserve)
    }

    const fn admits(self) -> bool {
        !matches!(self, Self::PlusOne)
    }
}

#[derive(Clone, Copy)]
enum BoundaryKind {
    Transaction,
    Backup,
}

/// A fresh minimal database used only for admission boundaries, so startup
/// replay of the growth workload's large manifests cannot disturb the
/// byte-exact free-space samples.
struct BoundaryDatabase {
    directory: PathBuf,
    backups: PathBuf,
    identity: Identity,
    probe: Arc<StorageGrowthProbe>,
}

impl BoundaryDatabase {
    fn create(request: &QualificationRequest<'_>) -> Result<Self, StorageError> {
        let directory = request.scratch_directory.join("boundary-state");
        let backups = request.scratch_directory.join("boundary-backups");
        for path in [&directory, &backups] {
            fs::create_dir(path).map_err(|_| StorageError::FilesystemRejected)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| StorageError::FilesystemRejected)?;
        }
        let probe = Arc::new(StorageGrowthProbe::new(&directory)?);
        let identity = Identity::random()?;
        let database = Self {
            directory,
            backups,
            identity,
            probe,
        };
        initialize_database(
            &database.request(request),
            &database.identity,
            &database.probe,
        )?;
        Ok(database)
    }

    /// The same qualifications and limits, rooted at the boundary directory.
    fn request<'a>(&'a self, request: &'a QualificationRequest<'_>) -> QualificationRequest<'a> {
        QualificationRequest {
            state_directory: &self.directory,
            scratch_directory: request.scratch_directory,
            qualifications: request.qualifications,
            limits: request.limits,
            kernel_release: String::new(),
        }
    }

    /// Free space and backup length as the engine itself samples them in a
    /// steady open session; a later session's admission sees the same state.
    fn steady_sample(
        &self,
        request: &QualificationRequest<'_>,
    ) -> Result<(u64, u64), StorageError> {
        let session = Session::open(
            &self.request(request),
            &self.identity,
            &self.probe,
            request.limits,
        )?;
        let statistics = session.statistics()?;
        let sample = (
            statistics.filesystem_available_bytes(),
            statistics.backup_stream_bytes(),
        );
        session.shutdown()?;
        Ok(sample)
    }
}

fn run_boundary_cases(
    request: &QualificationRequest<'_>,
    recorder: &mut StorageGrowthRecorder,
    log: &mut RawLog,
) -> Result<(), StorageError> {
    let database = BoundaryDatabase::create(request)?;
    for kind in [BoundaryKind::Transaction, BoundaryKind::Backup] {
        for offset in [
            BoundaryOffset::MinusOne,
            BoundaryOffset::Equal,
            BoundaryOffset::PlusOne,
        ] {
            boundary_case(request, &database, recorder, log, kind, offset)?;
        }
    }
    Ok(())
}

// agenc-review: focus owner=storage reviewed=2026-09-05 reason=one bounded retry loop proves the exact admission boundary against the engine's own free-space samples and refuses to record an unstable attempt
fn boundary_case(
    request: &QualificationRequest<'_>,
    database: &BoundaryDatabase,
    recorder: &mut StorageGrowthRecorder,
    log: &mut RawLog,
    kind: BoundaryKind,
    offset: BoundaryOffset,
) -> Result<(), StorageError> {
    let name = match kind {
        BoundaryKind::Transaction => format!("reserve-{}", offset.suffix()),
        BoundaryKind::Backup => format!("backup-reserve-{}", offset.suffix()),
    };
    for attempt in 1..=BOUNDARY_ATTEMPTS {
        // Two agreeing engine samples prove the filesystem is quiet; a
        // preceding session's shutdown checkpoint otherwise shifts the base.
        let first = database.steady_sample(request)?;
        let (available, backup_bytes) = database.steady_sample(request)?;
        if first != (available, backup_bytes) {
            log.line(&format!(
                "boundary-unstable|{name}|{attempt}|{}|{available}",
                first.0
            ));
            continue;
        }
        let required = match kind {
            BoundaryKind::Transaction => MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH,
            BoundaryKind::Backup => backup_bytes,
        };
        let reserve = offset.reserve(available, required)?;
        let mut limits = request.limits;
        limits.fixed_reserve_bytes = reserve;
        limits.reserve_percent = BOUNDARY_RESERVE_PERCENT;
        let before = allocated_directory_bytes(&database.directory)?;
        let sequence = offset.sequence(kind, attempt);
        let outcome = boundary_attempt(request, database, limits, kind, sequence);
        let after = allocated_directory_bytes(&database.directory)?;
        let (admitted, step) = match outcome.admission {
            Ok(()) => (true, "admitted"),
            Err(StorageError::FilesystemRejected) => (false, outcome.step),
            Err(error) => {
                log.line(&format!(
                    "boundary-error|{name}|{attempt}|{}|{error}",
                    outcome.step
                ));
                return Err(error);
            }
        };
        let shutdown = match outcome.shutdown {
            Ok(()) => "clean",
            // The shutdown checkpoint is itself admitted against the reserve, so
            // a boundary session that admitted its one write refuses it; the
            // next open reconciles and checkpoints under the normal reserve.
            Err(StorageError::FilesystemRejected) => "checkpoint-refused",
            Err(error) => {
                log.line(&format!("boundary-error|{name}|{attempt}|shutdown|{error}"));
                return Err(error);
            }
        };
        let (available_after, _) = database.steady_sample(request)?;
        log.line(&format!(
            "boundary|{name}|{attempt}|{available}|{required}|{reserve}|{}|{step}|{shutdown}|{available_after}",
            if admitted { "admitted" } else { "refused" }
        ));
        let stable = admitted || available_after == available;
        if admitted == offset.admits() && stable {
            recorder.record_observed(StorageGrowthCase::new(name, before, after)?)?;
            return Ok(());
        }
    }
    Err(StorageError::StaleState)
}

impl BoundaryOffset {
    /// A key or backup name that no other attempt of any boundary case reuses.
    fn sequence(self, kind: BoundaryKind, attempt: u32) -> u64 {
        let offset = match self {
            Self::MinusOne => 0,
            Self::Equal => 1,
            Self::PlusOne => 2,
        };
        let kind = match kind {
            BoundaryKind::Transaction => 0,
            BoundaryKind::Backup => 1,
        };
        (kind * 3 + offset) * u64::from(BOUNDARY_ATTEMPTS + 1) + u64::from(attempt)
    }
}

/// The admission result of one boundary session and its separate shutdown result.
struct BoundaryOutcome {
    admission: Result<(), StorageError>,
    step: &'static str,
    shutdown: Result<(), StorageError>,
}

/// Runs one admission attempt on a fresh session and reports which step decided it.
fn boundary_attempt(
    request: &QualificationRequest<'_>,
    database: &BoundaryDatabase,
    limits: StorageEngineLimits,
    kind: BoundaryKind,
    sequence: u64,
) -> BoundaryOutcome {
    let boundary_request = database.request(request);
    let mut session = match Session::open(
        &boundary_request,
        &database.identity,
        &database.probe,
        limits,
    ) {
        Ok(session) => session,
        Err(error) => {
            return BoundaryOutcome {
                admission: Err(error),
                step: "open",
                shutdown: Ok(()),
            };
        }
    };
    let (admission, step) = match kind {
        BoundaryKind::Transaction => {
            let mutation = key(0x40, sequence)
                .and_then(|key| body(14, SMALL_BODY_BYTES).map(|body| (key, body)))
                .and_then(|(key, body)| put(key, None, body));
            match mutation {
                Ok(mutation) => (session.commit(vec![mutation]).map(|_| ()), "commit"),
                Err(error) => (Err(error), "prepare"),
            }
        }
        BoundaryKind::Backup => (backup_attempt(&session, database, sequence), "backup"),
    };
    let shutdown = session.shutdown();
    BoundaryOutcome {
        admission,
        step,
        shutdown,
    }
}

fn backup_attempt(
    session: &Session,
    database: &BoundaryDatabase,
    sequence: u64,
) -> Result<(), StorageError> {
    let mut signing_key = [0_u8; 32];
    OsEntropy::fill(&mut signing_key).map_err(|_| StorageError::Unavailable)?;
    let mut backup_id = [0_u8; 16];
    for (slot, byte) in backup_id.iter_mut().skip(8).zip(sequence.to_be_bytes()) {
        *slot = byte;
    }
    session
        .port
        .try_backup(
            BackupDestination::new(&database.backups, &format!("boundary-{sequence}.backup"))?,
            Ed25519SecretKey::from_bytes(signing_key),
            BACKUP_CREATED_AT,
            backup_id,
        )?
        .wait()
        .map(|_| ())
}

/// Names every case a complete report must contain; used by callers that validate output.
#[must_use]
pub fn required_case_names() -> &'static [&'static str; 21] {
    &REQUIRED_QUALIFICATION_CASES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_reserves_land_one_byte_around_the_admission_point() -> Result<(), StorageError> {
        let available = 8 * 1_024 * 1_024 * 1_024;
        let required = MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH;
        let equal = BoundaryOffset::Equal.reserve(available, required)?;
        assert_eq!(equal, available - required);
        assert_eq!(
            BoundaryOffset::MinusOne.reserve(available, required)?,
            equal - 1
        );
        assert_eq!(
            BoundaryOffset::PlusOne.reserve(available, required)?,
            equal + 1
        );
        // Below the smallest legal fixed reserve, at the exact boundary, and past
        // the largest legal reserve are all refused instead of clamped.
        assert!(BoundaryOffset::Equal.reserve(required, required).is_err());
        assert!(
            BoundaryOffset::Equal
                .reserve(required + MIN_FIXED_RESERVE_BYTES - 1, required)
                .is_err()
        );
        assert!(BoundaryOffset::PlusOne.reserve(u64::MAX, 0).is_err());
        assert!(
            BoundaryOffset::PlusOne
                .reserve(MAX_FIXED_RESERVE_BYTES + required, required)
                .is_err()
        );
        assert!(BoundaryOffset::MinusOne.admits());
        assert!(!BoundaryOffset::PlusOne.admits());
        Ok(())
    }

    #[test]
    fn workload_description_binds_every_required_case_name() {
        let text = std::str::from_utf8(WORKLOAD_DESCRIPTION).unwrap_or_default();
        for name in required_case_names() {
            assert!(text.contains(name), "{name}");
        }
        assert_eq!(
            MAX_QUALIFIED_OBSERVED_GROWTH.checked_mul(2),
            Some(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
        );
    }
}
