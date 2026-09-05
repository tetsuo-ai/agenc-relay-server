//! Stopped-daemon production storage growth qualification.
//!
//! The command runs the storage crate's qualification workload through this
//! binary's own production engine and embedded tuple admission. It writes the
//! unsigned measurement, its raw log, and a JSON summary; signing stays a
//! separate offline step with the release key.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use agenc_ircd_runtime::offline::default_storage_limits;
use agenc_ircd_storage::{
    MAX_QUALIFIED_OBSERVED_GROWTH, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, QualificationOutcome,
    QualificationRequest, embedded_storage_qualifications, qualify_production_storage,
};

use super::options::{OptionSpec, ParsedOptions};
use super::{CliFailure, EXIT_USAGE};

pub(super) const USAGE: &str = "usage: agenc-ircd storage qualify --state-dir <new-directory> \
--scratch-dir <new-directory> --unsigned-report <file> --raw-log <file> [--json <file>]";
const MAX_KERNEL_RELEASE_BYTES: usize = 256;

struct QualifyOptions {
    state_dir: PathBuf,
    scratch_dir: PathBuf,
    unsigned_report: PathBuf,
    raw_log: PathBuf,
    json: Option<PathBuf>,
}

impl QualifyOptions {
    fn parse(arguments: &[OsString]) -> Result<Self, ()> {
        let mut parsed = ParsedOptions::parse(
            arguments,
            &[
                OptionSpec::value("--state-dir"),
                OptionSpec::value("--scratch-dir"),
                OptionSpec::value("--unsigned-report"),
                OptionSpec::value("--raw-log"),
                OptionSpec::value("--json"),
            ],
        )?;
        Ok(Self {
            state_dir: parsed.required_path("--state-dir")?,
            scratch_dir: parsed.required_path("--scratch-dir")?,
            unsigned_report: parsed.required_path("--unsigned-report")?,
            raw_log: parsed.required_path("--raw-log")?,
            json: parsed.optional_path("--json"),
        })
    }
}

pub(super) fn run(arguments: &[OsString]) -> Result<(), CliFailure> {
    let options = QualifyOptions::parse(arguments).map_err(|()| CliFailure::usage(USAGE))?;
    qualify(&options).map_err(|error| {
        CliFailure::command(EXIT_USAGE, format!("storage qualify failed: {error}"))
    })
}

fn qualify(options: &QualifyOptions) -> Result<(), Box<dyn std::error::Error>> {
    create_private_directory(&options.state_dir)?;
    create_private_directory(&options.scratch_dir)?;
    let qualifications = embedded_storage_qualifications()?;
    let kernel_release = kernel_release()?;
    let request = QualificationRequest {
        state_directory: &options.state_dir,
        scratch_directory: &options.scratch_dir,
        qualifications: &qualifications,
        limits: default_storage_limits(),
        kernel_release,
    };
    let outcome = match qualify_production_storage(request) {
        Ok(outcome) => outcome,
        Err(failure) => {
            write_private_file(&options.raw_log, &failure.raw_log)?;
            return Err(Box::new(failure));
        }
    };
    write_private_file(&options.raw_log, &outcome.raw_log)?;
    if let Some(path) = &options.json {
        write_private_file(path, summary_json(&outcome)?.as_bytes())?;
    }
    println!(
        "storage qualify: {} cases, maximum growth {} bytes, ceiling {} bytes, {} boundary samples",
        outcome.report.cases.len(),
        outcome.report.maximum_observed_growth,
        MAX_QUALIFIED_OBSERVED_GROWTH,
        outcome.sample_count,
    );
    if !outcome.within_ceiling {
        return Err(format!(
            "maximum observed growth {} bytes exceeds the qualified ceiling of {} bytes; \
the raw log and summary retain the failed measurement and no unsigned report was written",
            outcome.report.maximum_observed_growth, MAX_QUALIFIED_OBSERVED_GROWTH
        )
        .into());
    }
    write_private_file(&options.unsigned_report, &outcome.report.encode_unsigned()?)?;
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn kernel_release() -> Result<String, Box<dyn std::error::Error>> {
    let text = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let release = text.trim_end_matches(['\r', '\n']).to_owned();
    if release.is_empty()
        || release.len() > MAX_KERNEL_RELEASE_BYTES
        || !release.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err("kernel release is not a printable ASCII identifier".into());
    }
    Ok(release)
}

/// Fixed-schema JSON; every string field is validated ASCII without quotes.
fn summary_json(outcome: &QualificationOutcome) -> Result<String, Box<dyn std::error::Error>> {
    let report = &outcome.report;
    let mut text = format!(
        "{{\"schema_version\":1,\"target\":\"{}\",\"filesystem_type\":{},\"block_size\":{},\
\"mount_flags\":{},\"kernel_release\":\"{}\",\"maximum_observed_growth\":{},\
\"qualified_growth_ceiling\":{},\"physical_growth_reserve\":{},\"sample_count\":{},\
\"ballast_bytes\":{},\"cases\":[",
        report.target.as_str(),
        report.filesystem_type,
        report.block_size,
        report.mount_flags,
        report.kernel_release,
        report.maximum_observed_growth,
        MAX_QUALIFIED_OBSERVED_GROWTH,
        MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH,
        outcome.sample_count,
        outcome.ballast_bytes,
    );
    for (index, case) in report.cases.iter().enumerate() {
        if index > 0 {
            text.push(',');
        }
        write!(
            text,
            "{{\"name\":\"{}\",\"allocated_before\":{},\"allocated_after\":{},\"positive_delta\":{}}}",
            case.name(),
            case.allocated_before(),
            case.allocated_after(),
            case.positive_delta(),
        )?;
    }
    text.push_str("]}\n");
    Ok(text)
}
