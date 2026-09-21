#![forbid(unsafe_code)]

//! The production growth workload runs to completion on a scratch tuple.

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use agenc_relay_crypto::{Ed25519SecretKey, StorageDigest};
use agenc_relay_storage::{
    MAX_QUALIFIED_OBSERVED_GROWTH, QualificationRequest, QualificationTarget,
    REQUIRED_QUALIFICATION_CASES, StateDirectory, StorageEngineLimits, StorageGrowthCase,
    StorageQualification, StorageQualificationReport, StorageQualificationReportTbs,
    qualify_production_storage,
};

type TestResult = Result<(), Box<dyn Error>>;

const LIMITS: StorageEngineLimits = StorageEngineLimits {
    redb_cache_bytes: 64 * 1_024 * 1_024,
    fixed_reserve_bytes: 64 * 1_024 * 1_024,
    reserve_percent: 1,
    database_max_bytes: 4_294_967_296,
    backup_max_bytes: 8_589_934_592,
    integrity_checkpoint_manifests: 100_000,
};

fn scratch_qualification(
    directory: &std::path::Path,
) -> Result<StorageQualification, Box<dyn Error>> {
    let tuple = StateDirectory::probe(directory)?;
    let target = match tuple.target {
        "x86_64-unknown-linux-gnu" => QualificationTarget::X86_64UnknownLinuxGnu,
        "aarch64-unknown-linux-gnu" => QualificationTarget::Aarch64UnknownLinuxGnu,
        _ => return Err("unsupported test target".into()),
    };
    let mut cases = REQUIRED_QUALIFICATION_CASES
        .iter()
        .map(|name| StorageGrowthCase::new((*name).to_owned(), 1, 1))
        .collect::<Result<Vec<_>, _>>()?;
    cases.sort_by(|left, right| left.name().cmp(right.name()));
    let key = Ed25519SecretKey::from_bytes([77; 32]);
    let report = StorageQualificationReport::sign(
        StorageQualificationReportTbs {
            target,
            filesystem_type: tuple.filesystem_type,
            block_size: tuple.block_size,
            mount_flags: tuple.mount_flags,
            kernel_release: "test".to_owned(),
            redb_features_hash: StorageDigest::from_bytes([1; 32]),
            release_profile_hash: StorageDigest::from_bytes([2; 32]),
            corpus_hash: StorageDigest::from_bytes([3; 32]),
            cases,
            maximum_observed_growth: 0,
            raw_log_hash: StorageDigest::from_bytes([4; 32]),
        },
        &key,
    )?;
    let verified =
        StorageQualificationReport::decode_and_verify(&report.encode()?, key.public_key())?;
    Ok(verified.qualification_for(tuple)?)
}

struct Scratch(PathBuf);

impl Scratch {
    fn create(name: &str) -> Result<Self, Box<dyn Error>> {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{name}-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self(root))
    }

    fn private(&self, name: &str) -> Result<PathBuf, Box<dyn Error>> {
        let path = self.0.join(name);
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn production_workload_measures_every_required_case_and_phase() -> TestResult {
    let scratch = Scratch::create("agenc-qualification-workload")?;
    let state = scratch.private("state")?;
    let extra = scratch.private("scratch")?;
    let qualification = scratch_qualification(&state)?;
    let outcome = qualify_production_storage(QualificationRequest {
        state_directory: &state,
        scratch_directory: &extra,
        qualifications: &[qualification],
        limits: LIMITS,
        kernel_release: "test-kernel".to_owned(),
    })?;
    let names = outcome
        .report
        .cases
        .iter()
        .map(|case| case.name().to_owned())
        .collect::<Vec<_>>();
    for required in REQUIRED_QUALIFICATION_CASES {
        assert!(names.iter().any(|name| name == required), "{required}");
    }
    for extra_case in [
        "backup-reserve-minus-one",
        "backup-reserve-equal",
        "backup-reserve-plus-one",
        "phase-guard-rename",
        "phase-transaction-begin",
        "phase-checkpoint-install",
    ] {
        assert!(names.iter().any(|name| name == extra_case), "{extra_case}");
    }
    assert!(outcome.report.maximum_observed_growth > 0);
    assert!(outcome.sample_count > 100);
    assert_eq!(
        outcome.within_ceiling,
        outcome.report.maximum_observed_growth <= MAX_QUALIFIED_OBSERVED_GROWTH
    );
    // The unsigned encoding exists exactly when the measurement is signable.
    assert_eq!(
        outcome.report.encode_unsigned().is_ok(),
        outcome.within_ceiling
    );
    if outcome.within_ceiling {
        let encoded = outcome.report.encode_unsigned()?;
        assert_eq!(
            StorageQualificationReportTbs::decode_unsigned(&encoded)?.encode_unsigned()?,
            encoded
        );
    }
    let log = String::from_utf8(outcome.raw_log)?;
    assert!(
        log.lines()
            .last()
            .is_some_and(|line| line.starts_with("maximum|"))
    );
    for line in log.lines().filter(|line| !line.starts_with("begin|")) {
        println!("{line}");
    }
    assert!(log.contains("case|insert-max-value|"));
    assert!(log.contains("boundary|reserve-plus-one|"));
    assert!(log.contains("boundary|backup-reserve-equal|"));
    assert!(fs::read_dir(&extra)?.all(|entry| {
        entry
            .map(|entry| entry.file_name() != "qualification-ballast")
            .unwrap_or(false)
    }));
    Ok(())
}
