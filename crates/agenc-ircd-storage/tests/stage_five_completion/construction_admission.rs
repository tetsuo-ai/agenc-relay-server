//! Every restore and rekey scratch-plan and target-construction transaction is admitted
//! against the live `R(F) + G` gate immediately before it runs (STO-07, issue #69).
#![forbid(unsafe_code)]

use std::iter::Peekable;
use std::sync::{Arc, Mutex};

use agenc_ircd_domain::{
    DirectMessagePolicy, DurableAccount, GuestDirectMessagePolicy, PresencePolicy,
};
use agenc_ircd_storage::{
    AccountRecordBody, ConstructionTransaction, FilesystemCapacity, FilesystemCause,
    MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, RestoreCommandReceipt,
    execute_restore_command_with_observer,
};
use agenc_ircd_types::{Generation, Revision};

use super::*;

/// Accounts committed to the restore source, one commit each: more target records than
/// the command's fixed 1,000-record batch and two manifests for the reverse replay.
const SOURCE_COMMITS: [u32; 2] = [700, 500];
/// Target records the restore command commits per batch.
const RESTORE_BATCH_RECORDS: u64 = 1_000;
const INSUFFICIENT: StorageError =
    StorageError::FilesystemRejected(FilesystemCause::InsufficientCapacity);

/// Records every admitted transaction and, at one named transaction, stands in for an
/// external writer that leaves exactly `reserve + G + delta` bytes available.
struct AdmissionScript {
    log: Mutex<Vec<ConstructionTransaction>>,
    boundary: Option<(ConstructionTransaction, i64)>,
}

impl AdmissionScript {
    fn recording() -> Arc<Self> {
        Arc::new(Self {
            log: Mutex::new(Vec::new()),
            boundary: None,
        })
    }

    fn consuming_at(transaction: ConstructionTransaction, delta: i64) -> Arc<Self> {
        Arc::new(Self {
            log: Mutex::new(Vec::new()),
            boundary: Some((transaction, delta)),
        })
    }

    fn log(&self) -> Result<Vec<ConstructionTransaction>, Box<dyn Error>> {
        Ok(self
            .log
            .lock()
            .map_err(|_| "admission log poisoned")?
            .clone())
    }
}

impl ConstructionCapacityObserver for AdmissionScript {
    fn observe(
        &self,
        transaction: ConstructionTransaction,
        sampled: FilesystemCapacity,
    ) -> Result<FilesystemCapacity, StorageError> {
        self.log
            .lock()
            .map_err(|_| StorageError::Unavailable)?
            .push(transaction);
        match self.boundary {
            Some((at, delta)) if at == transaction => {
                let exact = sampled
                    .reserve_bytes
                    .checked_add(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
                    .ok_or(StorageError::Overflow)?;
                Ok(FilesystemCapacity {
                    available_bytes: exact
                        .checked_add_signed(delta)
                        .ok_or(StorageError::Overflow)?,
                    reserve_bytes: sampled.reserve_bytes,
                })
            }
            _ => Ok(sampled),
        }
    }
}

/// The admitted sequence of one command: the slice count of each scratch phase, in the
/// order the phases run, and the target transactions verbatim.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AdmittedShape {
    observe: u64,
    verify: u64,
    order: u64,
    reclaim: u64,
    target: Vec<ConstructionTransaction>,
}

fn expect(
    log: &mut Peekable<impl Iterator<Item = ConstructionTransaction>>,
    transaction: ConstructionTransaction,
) -> Result<(), Box<dyn Error>> {
    match log.next() {
        Some(actual) if actual == transaction => Ok(()),
        actual => Err(format!("expected {transaction:?}, found {actual:?}").into()),
    }
}

fn phase_run(
    log: &mut Peekable<impl Iterator<Item = ConstructionTransaction>>,
    phase: fn(u64) -> ConstructionTransaction,
) -> Result<u64, Box<dyn Error>> {
    let mut count = 0_u64;
    loop {
        let next = count.checked_add(1).ok_or("slice count overflow")?;
        if log.peek() != Some(&phase(next)) {
            return Ok(count);
        }
        log.next();
        count = next;
    }
}

fn shape(log: &[ConstructionTransaction]) -> Result<AdmittedShape, Box<dyn Error>> {
    let mut log = log.iter().copied().peekable();
    expect(&mut log, ConstructionTransaction::ScratchCreate)?;
    expect(&mut log, ConstructionTransaction::ScratchReset)?;
    let observe = phase_run(&mut log, ConstructionTransaction::ScratchObserve)?;
    let verify = phase_run(&mut log, ConstructionTransaction::ScratchVerify)?;
    let order = phase_run(&mut log, ConstructionTransaction::ScratchOrder)?;
    let reclaim = phase_run(&mut log, ConstructionTransaction::ScratchReclaim)?;
    expect(&mut log, ConstructionTransaction::ScratchClose)?;
    Ok(AdmittedShape {
        observe,
        verify,
        order,
        reclaim,
        target: log.collect(),
    })
}

fn account_record(index: u32) -> Result<(StoredKey, Vec<u8>), Box<dyn Error>> {
    let mut random = [0_u8; 16];
    let (head, _) = random.split_at_mut(4);
    head.copy_from_slice(&index.to_be_bytes());
    let account_id = AccountRandomId::from_bytes(random).to_account_id();
    let body = AccountRecordBody::encode(&DurableAccount {
        account_id,
        label: None,
        presence: PresencePolicy::Private,
        guest_direct_messages: GuestDirectMessagePolicy::Allow,
        direct_messages: DirectMessagePolicy::Allow,
        contacts: Vec::new(),
        reserved_nicknames: Vec::new(),
        session_generation: Generation::new(1)?,
        revision: Revision::new(1)?,
        admin_suspension_expires_at: None,
    })?;
    let plaintext =
        PersistentRecordValue::new(TableId::Account, 1, 1, 1, None, Vec::new(), body)?.encode()?;
    Ok((
        StoredKey::new(account_id.to_text().into_bytes())?,
        plaintext,
    ))
}

fn commit_accounts(
    port: &StoragePort,
    accounting: &mut StorageAccountingLimits,
    sequence: u64,
    first: u32,
    count: u32,
) -> Result<(), Box<dyn Error>> {
    let last = first.checked_add(count).ok_or("account index overflow")?;
    let mutations = (first..last)
        .map(|index| {
            let (key, plaintext) = account_record(index)?;
            Ok(RecordMutation::put(
                TableId::Account,
                key,
                1,
                None,
                plaintext,
            )?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([u8::try_from(sequence)?; 16]),
            expected_storage_commit_sequence: sequence,
            expected_state_generation: sequence,
            resulting_state_generation: sequence.checked_add(1).ok_or("generation overflow")?,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        },
        1,
        *accounting,
        mutations,
    )?;
    accounting.current_logical_database_bytes = batch.resulting_logical_database_bytes();
    accounting.current_backup_stream_bytes = batch.resulting_backup_stream_bytes();
    match port.try_commit(batch)?.wait()? {
        CommitOutcome::Committed(_) => Ok(()),
        CommitOutcome::Rejected(error) => Err(error.into()),
        CommitOutcome::Indeterminate => Err("source commit was indeterminate".into()),
    }
}

/// A signed backup of a live source with two committed manifests, plus every key file the
/// restore command reads, ready to be restored into any number of output directories.
struct RestoreCommand {
    source: InitializedLiveFixture,
    _backup_directory: TestDirectory,
    backup_path: PathBuf,
    command_directory: TestDirectory,
    source_master: PathBuf,
    source_guard: PathBuf,
    login_key: PathBuf,
    target_guard: PathBuf,
    trusted: RestoreTrustKey,
    entry_count: u64,
}

impl RestoreCommand {
    fn create() -> Result<Self, Box<dyn Error>> {
        let source = initialized_live_fixture()?;
        let owner = StorageOwner::start(live_open_config(StateDirectory::open(
            source.directory.path(),
            &[source.qualification],
        )?))?;
        let port = owner.port();
        let mut accounting = source.accounting();
        let mut next = 0_u32;
        let mut entry_count = 1_u64;
        for (sequence, count) in SOURCE_COMMITS.iter().enumerate() {
            commit_accounts(
                &port,
                &mut accounting,
                u64::try_from(sequence)?,
                next,
                *count,
            )?;
            next = next.checked_add(*count).ok_or("account index overflow")?;
            entry_count = entry_count
                .checked_add(u64::from(*count))
                .ok_or("entry count overflow")?;
        }
        let backup_directory = TestDirectory::create()?;
        let signing_key = Ed25519SecretKey::from_bytes([151; 32]);
        let public_key = signing_key.public_key();
        let backup_name = "admission-source.agenc";
        port.try_backup(
            BackupDestination::new(backup_directory.path(), backup_name)?,
            signing_key,
            1_000,
            [152; 16],
        )?
        .wait()?;
        owner.shutdown()?;
        let command_directory = TestDirectory::create()?;
        let source_master =
            protected_key_file(command_directory.path(), "source-master.key", [207; 32])?;
        let source_guard =
            protected_key_file(command_directory.path(), "source-guard.key", [208; 32])?;
        let login_key = protected_key_file(command_directory.path(), "login.key", [203; 32])?;
        let target_guard =
            protected_key_file(command_directory.path(), "target-guard.key", [153; 32])?;
        let trusted = BackupTrustKey::new(public_key)?.key_id;
        Ok(Self {
            source,
            backup_path: backup_directory.path().join(backup_name),
            _backup_directory: backup_directory,
            command_directory,
            source_master,
            source_guard,
            login_key,
            target_guard,
            trusted: RestoreTrustKey::new(*trusted.as_bytes(), *public_key.as_bytes(), 900, 1_100),
            entry_count,
        })
    }

    fn output(&self, name: &str) -> PathBuf {
        self.command_directory.path().join(name)
    }

    fn staging(&self, name: &str) -> PathBuf {
        self.command_directory
            .path()
            .join(format!(".{name}.agenc-construction-v1"))
    }

    fn request(&self, output: &Path, resume: bool) -> RestoreCommandRequest {
        RestoreCommandRequest {
            network_id: NetworkId::from_bytes([201; 32]),
            server_id: ServerId::from_bytes([202; 16]),
            // The source's shutdown checkpoint moved it past the backup's boundary, so the
            // configured current directory is absent and the lineage comparison is skipped.
            current_state_directory: self.command_directory.path().join("absent-current"),
            current_master_key_file: self.source_master.clone(),
            current_rollback_guard_key_file: self.source_guard.clone(),
            backup_path: self.backup_path.clone(),
            source_master_key_file: self.source_master.clone(),
            source_rollback_guard_key_file: self.source_guard.clone(),
            login_index_key_file: self.login_key.clone(),
            login_index_previous_key_file: None,
            output_state_directory: output.to_path_buf(),
            target_rollback_guard_key_file: self.target_guard.clone(),
            target_master_key_file: None,
            resume,
            declare_recovery_epoch: true,
            trusted_backup_keys: vec![self.trusted],
            limits: test_limits(),
        }
    }

    fn run(
        &self,
        name: &str,
        resume: bool,
        script: &Arc<AdmissionScript>,
    ) -> Result<RestoreCommandReceipt, StorageError> {
        execute_restore_command_with_observer(
            self.request(&self.output(name), resume),
            &[self.source.qualification],
            script.clone(),
        )
    }

    /// The source is never mutated by a construction: the backup and the source database
    /// keep their exact bytes.
    fn source_bytes(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        Ok((
            fs::read(&self.backup_path)?,
            fs::read(self.source.directory.path().join("database.redb"))?,
        ))
    }

    fn full_shape(&self) -> Result<AdmittedShape, Box<dyn Error>> {
        let script = AdmissionScript::recording();
        self.run("shape", false, &script)?;
        let full = shape(&script.log()?)?;
        assert!(full.observe >= 2, "{full:?}");
        assert!(full.verify >= 1, "{full:?}");
        assert_eq!(full.order, 2, "{full:?}");
        assert!(full.reclaim >= 1, "{full:?}");
        assert_eq!(
            full.target,
            [
                ConstructionTransaction::TargetInitialize,
                ConstructionTransaction::TargetBatch(0),
                ConstructionTransaction::TargetBatch(RESTORE_BATCH_RECORDS),
                ConstructionTransaction::TargetFinalize,
                ConstructionTransaction::TargetCheckpoint,
            ]
        );
        Ok(full)
    }
}

#[test]
fn restore_admits_every_scratch_and_target_transaction_in_order() -> Result<(), Box<dyn Error>> {
    let command = RestoreCommand::create()?;
    assert!(command.entry_count > RESTORE_BATCH_RECORDS);
    let before = command.source_bytes()?;
    let script = AdmissionScript::recording();
    let receipt = command.run("ordered", false, &script)?;
    let ordered = shape(&script.log()?)?;
    assert_eq!(ordered, command.full_shape()?);
    assert_eq!(command.source_bytes()?, before);
    assert!(command.output("ordered").join("database.redb").is_file());

    // An installed output is only reverified: its anonymous plan is admitted in the parent
    // directory and no target transaction runs.
    let verification = AdmissionScript::recording();
    assert_eq!(command.run("ordered", true, &verification)?, receipt);
    let verified = shape(&verification.log()?)?;
    assert_eq!(
        (verified.observe, verified.verify, verified.order),
        (ordered.observe, ordered.verify, ordered.order)
    );
    assert!(verified.target.is_empty(), "{verified:?}");
    Ok(())
}

#[test]
fn restore_refused_at_each_scratch_transaction_writes_no_target_and_resumes()
-> Result<(), Box<dyn Error>> {
    let command = RestoreCommand::create()?;
    let full = command.full_shape()?;
    let before = command.source_bytes()?;
    let refusals = [
        ConstructionTransaction::ScratchReset,
        ConstructionTransaction::ScratchObserve(2),
        ConstructionTransaction::ScratchVerify(1),
        ConstructionTransaction::ScratchOrder(2),
        ConstructionTransaction::ScratchReclaim(1),
        ConstructionTransaction::ScratchClose,
        ConstructionTransaction::TargetInitialize,
    ];
    for (attempt, refused) in refusals.iter().enumerate() {
        let script = AdmissionScript::consuming_at(*refused, -1);
        assert_eq!(
            command.run("scratch", attempt != 0, &script),
            Err(INSUFFICIENT),
            "{refused:?}"
        );
        let log = script.log()?;
        assert_eq!(log.last(), Some(refused), "{log:?}");
        assert!(command.staging("scratch").is_dir());
        assert!(!command.staging("scratch").join("database.redb").exists());
        assert!(!command.output("scratch").exists());
        assert_eq!(command.source_bytes()?, before);
    }
    let script = AdmissionScript::recording();
    let receipt = command.run("scratch", true, &script)?;
    assert_eq!(shape(&script.log()?)?, full);
    assert_eq!(receipt.output_state_directory, command.output("scratch"));
    assert!(command.output("scratch").join("database.redb").is_file());
    assert!(!command.staging("scratch").exists());
    Ok(())
}

#[test]
fn restore_refused_at_a_target_transaction_resumes_at_exactly_that_transaction()
-> Result<(), Box<dyn Error>> {
    let command = RestoreCommand::create()?;
    let full = command.full_shape()?;
    let before = command.source_bytes()?;
    let cases = [
        (
            "second-batch",
            ConstructionTransaction::TargetBatch(RESTORE_BATCH_RECORDS),
            vec![
                ConstructionTransaction::TargetBatch(RESTORE_BATCH_RECORDS),
                ConstructionTransaction::TargetFinalize,
                ConstructionTransaction::TargetCheckpoint,
            ],
        ),
        (
            "finalize",
            ConstructionTransaction::TargetFinalize,
            vec![
                ConstructionTransaction::TargetFinalize,
                ConstructionTransaction::TargetCheckpoint,
            ],
        ),
        // A refusal after the completion record is durable leaves a finalized staging
        // directory: the resume reverifies the completion and installs it without another
        // target transaction.
        (
            "checkpoint",
            ConstructionTransaction::TargetCheckpoint,
            Vec::new(),
        ),
    ];
    for (name, refused, remainder) in cases {
        let script = AdmissionScript::consuming_at(refused, -1);
        assert_eq!(
            command.run(name, false, &script),
            Err(INSUFFICIENT),
            "{name}"
        );
        let log = script.log()?;
        assert_eq!(log.last(), Some(&refused), "{log:?}");
        assert!(command.staging(name).join("database.redb").is_file());
        assert!(!command.output(name).exists());
        assert_eq!(command.source_bytes()?, before);

        let resumed = AdmissionScript::recording();
        let receipt = command.run(name, true, &resumed)?;
        let continued = shape(&resumed.log()?)?;
        assert_eq!(
            (
                continued.observe,
                continued.verify,
                continued.order,
                continued.reclaim
            ),
            (full.observe, full.verify, full.order, full.reclaim),
            "{name}: {continued:?}"
        );
        assert_eq!(continued.target, remainder, "{name}");
        assert_eq!(receipt.output_state_directory, command.output(name));
        assert!(command.output(name).join("database.redb").is_file());
        assert_eq!(
            command.run(name, true, &AdmissionScript::recording())?,
            receipt
        );
    }
    Ok(())
}

#[test]
fn restore_rechecks_the_exact_boundary_at_the_first_scratch_and_target_transactions()
-> Result<(), Box<dyn Error>> {
    let command = RestoreCommand::create()?;
    for (transaction, label) in [
        (ConstructionTransaction::ScratchObserve(1), "observe"),
        (ConstructionTransaction::TargetBatch(0), "batch"),
    ] {
        for (case, (delta, admitted)) in [(-1_i64, false), (0, true), (1, true)]
            .into_iter()
            .enumerate()
        {
            let name = format!("{label}-{case}");
            let script = AdmissionScript::consuming_at(transaction, delta);
            let outcome = command.run(&name, false, &script);
            let log = script.log()?;
            if admitted {
                outcome?;
                assert!(command.output(&name).join("database.redb").is_file());
            } else {
                assert_eq!(outcome, Err(INSUFFICIENT), "{name}");
                assert_eq!(log.last(), Some(&transaction), "{log:?}");
                assert!(!command.output(&name).exists());
            }
            // The external consumption arrived after every earlier admission; a target batch
            // is rechecked after the target was initialized and preflight ran with room.
            if transaction == ConstructionTransaction::TargetBatch(0) {
                assert!(log.contains(&ConstructionTransaction::TargetInitialize));
            }
        }
    }
    Ok(())
}

#[test]
fn rekey_scratch_and_target_transactions_are_admitted_and_refused_at_the_exact_boundary()
-> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    let source = ConstructionSourceDatabase::open(live_open_config(StateDirectory::open(
        fixture.directory.path(),
        &[fixture.qualification],
    )?))?;
    let plans = TestDirectory::create()?;
    let target_binding = DatabaseBinding::new(
        NetworkId::from_bytes([201; 32]),
        ServerId::from_bytes([202; 16]),
        ServerIncarnation::from_bytes([61; 16]),
        DatabaseId::from_bytes([62; 16]),
    );
    for (delta, admitted) in [(-1_i64, false), (0, true), (1, true)] {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(plans.path().join(format!("rekey-plan-{}.redb", delta + 1)))?;
        let script =
            AdmissionScript::consuming_at(ConstructionTransaction::ScratchObserve(1), delta);
        let admission = ConstructionAdmissionPolicy::observed(test_limits(), script.clone())?
            .bind(file.try_clone()?);
        let outcome = source.rebuild_rekey_plan(
            file,
            &StorageMasterKey::from_bytes([79; 32]),
            target_binding,
            1,
            construction_limits(),
            admission,
        );
        let log = script.log()?;
        if admitted {
            assert_eq!(outcome?.entry_count(), 1);
            assert_eq!(
                shape(&log)?,
                AdmittedShape {
                    observe: 1,
                    verify: 0,
                    order: 1,
                    reclaim: 1,
                    target: Vec::new(),
                }
            );
        } else {
            assert_eq!(outcome.err(), Some(INSUFFICIENT));
            assert_eq!(
                log,
                [
                    ConstructionTransaction::ScratchCreate,
                    ConstructionTransaction::ScratchReset,
                    ConstructionTransaction::ScratchObserve(1),
                ]
            );
        }
    }
    drop(source);

    let limits = ConstructionLimits {
        batch_records: 1,
        ..construction_limits()
    };
    for (delta, admitted) in [(-1_i64, false), (0, true), (1, true)] {
        let fixture = RekeyConstructionFixture::create()?;
        let script = AdmissionScript::consuming_at(ConstructionTransaction::TargetBatch(0), delta);
        let (mut target, mut executor, mut source) =
            fixture.execution_observed(script.clone(), limits)?;
        let outcome = executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target);
        assert_eq!(script.log()?, [ConstructionTransaction::TargetBatch(0)]);
        if admitted {
            assert_eq!(outcome?, 1);
        } else {
            assert_eq!(outcome, Err(INSUFFICIENT));
        }
    }

    // A refusal at the second batch leaves the marker at that batch; the resumed executor
    // admits exactly it first and finishes the same plan.
    let fixture = RekeyConstructionFixture::create()?;
    let script = AdmissionScript::consuming_at(ConstructionTransaction::TargetBatch(1), -1);
    let (mut target, mut executor, mut source) =
        fixture.execution_observed(script.clone(), limits)?;
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
        1
    );
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target),
        Err(INSUFFICIENT)
    );
    assert_eq!(
        script.log()?,
        [
            ConstructionTransaction::TargetBatch(0),
            ConstructionTransaction::TargetBatch(1),
        ]
    );
    let expected_identity = executor.marker().identity;
    drop(executor);
    drop(target);

    let resumed = AdmissionScript::recording();
    let (mut target, mut executor, mut source) =
        fixture.execution_observed(resumed.clone(), limits)?;
    assert_eq!(executor.marker().target_records_committed, 1);
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
        1
    );
    assert_eq!(
        executor.service_batch(&mut source, &mut ExactCopyTransformer, &mut target)?,
        0
    );
    let operation_id = executor.finalize(&mut target)?;
    assert_eq!(
        resumed.log()?,
        [
            ConstructionTransaction::TargetBatch(1),
            ConstructionTransaction::TargetFinalize,
            ConstructionTransaction::TargetCheckpoint,
        ]
    );
    drop(executor);
    drop(target);
    let verification = fixture.verify_completed(expected_identity)?;
    assert_eq!(verification.completion().storage_operation_id, operation_id);
    Ok(())
}
