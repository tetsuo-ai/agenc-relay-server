#![forbid(unsafe_code)]

//! Native allocated-block measurement harness for release storage qualification.

use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use agenc_ircd_crypto::{OsEntropy, storage_qualification_component_hash};
use agenc_ircd_storage::{
    QualificationTarget, REQUIRED_QUALIFICATION_CASES, StateDirectory, StorageError,
    StorageGrowthCase, StorageGrowthRecorder, StorageQualificationReportTbs,
};
use redb::{Database, Durability, TableDefinition};

const VALUES: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("qualification");
const MAX_TRACKED_BYTES: usize = 16_777_216;
const MAX_TRACKED_MUTATIONS: u64 = 65_535;
const MIN_SEALED_RECORD_BYTES: usize = 56;
const MAX_COUNT_VALUE_BYTES: usize = 248;
const MAX_KEY_BYTES: usize = 4_096;
const TREE_VALUE_BYTES: usize = 512;
const TREE_RECORDS: u64 = 4_096;
const MIXED_RECORDS_PER_SHAPE: u64 = MAX_TRACKED_MUTATIONS / 3;
const REDB_FEATURES: &[u8] = b"redb=4.2.0;default-features=false;features=std\n";

fn main() -> Result<(), Box<dyn Error>> {
    let (report_path, raw_log_path) = qualification_paths()?;
    qualify(&report_path, &raw_log_path)
}

fn qualification_paths() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let report_path = arguments.next().ok_or("missing unsigned report path")?;
    let raw_log_path = arguments.next().ok_or("missing raw log path")?;
    if arguments.next().is_some() {
        return Err("usage: storage-qualification <unsigned-report> <raw-log>".into());
    }
    Ok((report_path.into(), raw_log_path.into()))
}

fn qualify(report_path: &Path, raw_log_path: &Path) -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDirectory::create()?;
    let database_path = scratch.path().join("database.redb");
    let guard_path = scratch.path().join("rollback.guard");
    let guard_temporary_path = scratch.path().join("rollback.guard.tmp");
    let database = create_measurement_database(&database_path)?;
    let _guard_file = create_private_file(&guard_path)?;
    let participant_paths = [
        database_path.as_path(),
        guard_path.as_path(),
        guard_temporary_path.as_path(),
        scratch.path(),
    ];
    let (cases, maximum_observed_growth) = measure_growth(
        &database,
        scratch.path(),
        &guard_path,
        &guard_temporary_path,
        &participant_paths,
    )?;
    let raw_log = encode_raw_log(&cases)?;
    write_private_file(raw_log_path, raw_log.as_bytes())?;
    let report = qualification_report(
        scratch.path(),
        cases,
        maximum_observed_growth,
        raw_log.as_bytes(),
    )?;
    write_private_file(report_path, &report.encode_unsigned()?)?;
    Ok(())
}

fn create_measurement_database(path: &Path) -> Result<Database, Box<dyn Error>> {
    let database_file = create_private_file(path)?;
    let mut builder = redb::Builder::new();
    builder.set_cache_size(64 * 1_024 * 1_024);
    let database = builder.create_file(database_file)?;
    initialize_table(&database)?;
    Ok(database)
}

fn measure_growth(
    database: &Database,
    directory: &Path,
    guard: &Path,
    guard_temporary: &Path,
    participant_paths: &[&Path],
) -> Result<(Vec<StorageGrowthCase>, u64), StorageError> {
    let mut recorder = StorageGrowthRecorder::new();
    for name in REQUIRED_QUALIFICATION_CASES {
        prepare_case(name, database)?;
        recorder.measure_path_set(name, participant_paths, || {
            run_case(name, database, directory, guard, guard_temporary)
        })?;
    }
    recorder.finish()
}

fn qualification_report(
    directory: &Path,
    cases: Vec<StorageGrowthCase>,
    maximum_observed_growth: u64,
    raw_log: &[u8],
) -> Result<StorageQualificationReportTbs, Box<dyn Error>> {
    let profile = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/stage-five-storage-profile.toml"),
    )?;
    let corpus = qualification_corpus()?;
    let tuple = StateDirectory::probe(directory)?;
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    Ok(StorageQualificationReportTbs {
        target: QualificationTarget::native(),
        filesystem_type: tuple.filesystem_type,
        block_size: tuple.block_size,
        mount_flags: tuple.mount_flags,
        kernel_release,
        redb_features_hash: storage_qualification_component_hash(b"redb-features", REDB_FEATURES)?,
        release_profile_hash: storage_qualification_component_hash(b"release-profile", &profile)?,
        corpus_hash: storage_qualification_component_hash(b"boundary-corpus", &corpus)?,
        cases,
        maximum_observed_growth,
        raw_log_hash: storage_qualification_component_hash(b"raw-log", raw_log)?,
    })
}

fn initialize_table(database: &Database) -> Result<(), StorageError> {
    let mut transaction = database
        .begin_write()
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction.set_two_phase_commit(true);
    {
        let _table = transaction
            .open_table(VALUES)
            .map_err(|_| StorageError::DatabaseRejected)?;
    }
    transaction
        .commit()
        .map_err(|_| StorageError::DatabaseRejected)
}

fn prepare_case(name: &str, database: &Database) -> Result<(), StorageError> {
    if name == "mixed-max-records" {
        insert_range(
            database,
            0x20,
            MIXED_RECORDS_PER_SHAPE,
            MIN_SEALED_RECORD_BYTES,
        )?;
        insert_range(
            database,
            0x21,
            MIXED_RECORDS_PER_SHAPE,
            MIN_SEALED_RECORD_BYTES,
        )?;
    }
    Ok(())
}

fn run_case(
    name: &str,
    database: &Database,
    directory: &Path,
    guard: &Path,
    guard_temporary: &Path,
) -> Result<(), StorageError> {
    match name {
        "insert-empty" => insert_value(database, &[0], &[0; MIN_SEALED_RECORD_BYTES]),
        "insert-one" => insert_value(database, &[1], &[1; MIN_SEALED_RECORD_BYTES]),
        "replace-min" => insert_value(database, &[1], &[2; MIN_SEALED_RECORD_BYTES]),
        "delete-one" => delete_value(database, &[1]),
        "insert-max-value" => insert_value(database, &[2], &vec![3; MAX_TRACKED_BYTES - 1]),
        "replace-max-value" => insert_value(database, &[2], &vec![4; MAX_TRACKED_BYTES - 1]),
        "delete-max-value" => delete_value(database, &[2]),
        "insert-max-key" => insert_value(
            database,
            &vec![5; MAX_KEY_BYTES],
            &[5; MIN_SEALED_RECORD_BYTES],
        ),
        "insert-max-records" => {
            insert_range(database, 0x10, MAX_TRACKED_MUTATIONS, MAX_COUNT_VALUE_BYTES)
        }
        "delete-max-records" => delete_range(database, 0x10, MAX_TRACKED_MUTATIONS),
        "mixed-max-records" => mixed_max_records(database),
        "btree-split" => insert_range(database, 0x30, TREE_RECORDS, TREE_VALUE_BYTES),
        "btree-merge" => delete_range(database, 0x30, TREE_RECORDS / 2),
        "fragmented" => fragment_tree(database),
        "checkpoint" => insert_value(database, &[0xff; 8], &[6; TREE_VALUE_BYTES]),
        "guard-temp-fsync" => write_private_file(
            guard_temporary,
            &[7; agenc_ircd_storage::ROLLBACK_GUARD_BYTES],
        )
        .map_err(agenc_ircd_storage::filesystem_rejected),
        "guard-rename" => {
            fs::rename(guard_temporary, guard).map_err(agenc_ircd_storage::filesystem_rejected)
        }
        "guard-directory-fsync" => File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(agenc_ircd_storage::filesystem_rejected),
        "reserve-minus-one" => insert_value(database, &[0x40], &[8; MIN_SEALED_RECORD_BYTES]),
        "reserve-equal" => insert_value(database, &[0x41], &[9; MIN_SEALED_RECORD_BYTES]),
        "reserve-plus-one" => insert_value(database, &[0x42], &[10; MIN_SEALED_RECORD_BYTES]),
        _ => Err(StorageError::InvalidEncoding),
    }
}

fn insert_value(database: &Database, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
    let mut transaction = database
        .begin_write()
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction.set_two_phase_commit(true);
    {
        let mut table = transaction
            .open_table(VALUES)
            .map_err(|_| StorageError::DatabaseRejected)?;
        table
            .insert(key, value)
            .map_err(|_| StorageError::DatabaseRejected)?;
    }
    transaction
        .commit()
        .map_err(|_| StorageError::DatabaseRejected)
}

fn delete_value(database: &Database, key: &[u8]) -> Result<(), StorageError> {
    let mut transaction = database
        .begin_write()
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction.set_two_phase_commit(true);
    {
        let mut table = transaction
            .open_table(VALUES)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let _removed = table
            .remove(key)
            .map_err(|_| StorageError::DatabaseRejected)?;
    }
    transaction
        .commit()
        .map_err(|_| StorageError::DatabaseRejected)
}

fn insert_range(
    database: &Database,
    namespace: u8,
    count: u64,
    value_bytes: usize,
) -> Result<(), StorageError> {
    let value = vec![namespace; value_bytes];
    let mut transaction = database
        .begin_write()
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction.set_two_phase_commit(true);
    {
        let mut table = transaction
            .open_table(VALUES)
            .map_err(|_| StorageError::DatabaseRejected)?;
        for index in 0..count {
            table
                .insert(record_key(namespace, index).as_slice(), value.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
    }
    transaction
        .commit()
        .map_err(|_| StorageError::DatabaseRejected)
}

fn delete_range(database: &Database, namespace: u8, count: u64) -> Result<(), StorageError> {
    let mut transaction = database
        .begin_write()
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction.set_two_phase_commit(true);
    {
        let mut table = transaction
            .open_table(VALUES)
            .map_err(|_| StorageError::DatabaseRejected)?;
        for index in 0..count {
            let _removed = table
                .remove(record_key(namespace, index).as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
    }
    transaction
        .commit()
        .map_err(|_| StorageError::DatabaseRejected)
}

fn mixed_max_records(database: &Database) -> Result<(), StorageError> {
    let value = [0x22; MIN_SEALED_RECORD_BYTES];
    let mut transaction = database
        .begin_write()
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction.set_two_phase_commit(true);
    {
        let mut table = transaction
            .open_table(VALUES)
            .map_err(|_| StorageError::DatabaseRejected)?;
        for index in 0..MIXED_RECORDS_PER_SHAPE {
            table
                .insert(record_key(0x22, index).as_slice(), value.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
            table
                .insert(record_key(0x20, index).as_slice(), value.as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
            let _removed = table
                .remove(record_key(0x21, index).as_slice())
                .map_err(|_| StorageError::DatabaseRejected)?;
        }
    }
    transaction
        .commit()
        .map_err(|_| StorageError::DatabaseRejected)
}

fn fragment_tree(database: &Database) -> Result<(), StorageError> {
    let value = [0x31; TREE_VALUE_BYTES];
    let mut transaction = database
        .begin_write()
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction
        .set_durability(Durability::Immediate)
        .map_err(|_| StorageError::DatabaseRejected)?;
    transaction.set_two_phase_commit(true);
    {
        let mut table = transaction
            .open_table(VALUES)
            .map_err(|_| StorageError::DatabaseRejected)?;
        for index in TREE_RECORDS / 2..TREE_RECORDS {
            if index % 2 == 0 {
                let _removed = table
                    .remove(record_key(0x30, index).as_slice())
                    .map_err(|_| StorageError::DatabaseRejected)?;
            } else {
                table
                    .insert(record_key(0x31, index).as_slice(), value.as_slice())
                    .map_err(|_| StorageError::DatabaseRejected)?;
            }
        }
    }
    transaction
        .commit()
        .map_err(|_| StorageError::DatabaseRejected)
}

fn record_key(namespace: u8, index: u64) -> [u8; 8] {
    let mut key = index.to_be_bytes();
    key[0] = namespace;
    key
}

fn qualification_corpus() -> Result<Vec<u8>, StorageError> {
    let mut corpus = Vec::new();
    for name in REQUIRED_QUALIFICATION_CASES {
        corpus
            .try_reserve(name.len().saturating_add(1))
            .map_err(|_| StorageError::AllocationFailed)?;
        corpus.extend_from_slice(name.as_bytes());
        corpus.push(b'\n');
    }
    Ok(corpus)
}

fn encode_raw_log(cases: &[agenc_ircd_storage::StorageGrowthCase]) -> Result<String, StorageError> {
    let mut output = String::new();
    output
        .try_reserve_exact(cases.len().saturating_mul(96))
        .map_err(|_| StorageError::AllocationFailed)?;
    for case in cases {
        use std::fmt::Write as _;
        writeln!(
            output,
            "{}|{}|{}|{}",
            case.name(),
            case.allocated_before(),
            case.allocated_after(),
            case.positive_delta()
        )
        .map_err(|_| StorageError::AllocationFailed)?;
    }
    Ok(output)
}

fn create_private_file(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = create_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

struct ScratchDirectory {
    path: PathBuf,
}

impl ScratchDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let mut random = [0_u8; 16];
        OsEntropy::fill(&mut random)?;
        let mut suffix = String::with_capacity(32);
        for byte in random {
            use std::fmt::Write as _;
            write!(suffix, "{byte:02x}")?;
        }
        let path = std::env::temp_dir().join(format!("agenc-storage-qualification-{suffix}"));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        for name in ["database.redb", "rollback.guard", "rollback.guard.tmp"] {
            let _result = fs::remove_file(self.path.join(name));
        }
        let _result = fs::remove_dir(&self.path);
    }
}
