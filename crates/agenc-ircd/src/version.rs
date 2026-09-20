//! Local build identification; completed qualification is a detached decision.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use agenc_ircd_config::MAX_RELEASE_PUBLIC_KEY_BYTES;
use agenc_ircd_runtime::release::{
    CompiledIdentity, ReleaseCoverage, ReleaseGrant, hexadecimal, inspect_release_decision,
};

use super::options::{OptionSpec, ParsedOptions};
use super::{CliFailure, EXIT_USAGE};

const COMMIT: &str = env!("AGENC_BUILD_COMMIT");
const SOURCE: &str = env!("AGENC_BUILD_SOURCE_SHA256");
const LOCK: &str = env!("AGENC_BUILD_LOCK_SHA256");
const TARGET: &str = env!("AGENC_BUILD_TARGET");
const COMPILER: &str = env!("AGENC_BUILD_COMPILER");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const CONFORMANCE_USAGE: &str = "usage: agenc-ircd conformance --json \
[--release-decision <directory> --trusted-public-key <pem>]";
const SELF_EXECUTABLE: &str = "/proc/self/exe";

pub(super) fn version(arguments: &[OsString]) -> Result<(), CliFailure> {
    match arguments {
        [] => println!("{} {VERSION} ({COMMIT}; {TARGET})", super::command_name()),
        [argument] if argument == "--json" => println!("{}", metadata(None)),
        _ => return Err(CliFailure::usage("usage: agenc-ircd version [--json]")),
    }
    Ok(())
}

pub(super) fn conformance(arguments: &[OsString]) -> Result<(), CliFailure> {
    let mut parsed = ParsedOptions::parse(
        arguments,
        &[
            OptionSpec::flag("--json"),
            OptionSpec::value("--release-decision"),
            OptionSpec::value("--trusted-public-key"),
        ],
    )
    .map_err(|()| CliFailure::usage(CONFORMANCE_USAGE))?;
    if !parsed.flag("--json") {
        return Err(CliFailure::usage(CONFORMANCE_USAGE));
    }
    let coverage = match (
        parsed.optional_path("--release-decision"),
        parsed.optional_path("--trusted-public-key"),
    ) {
        (None, None) => None,
        (Some(directory), Some(key)) => Some(inspect(&directory, &key)?),
        _ => return Err(CliFailure::usage(CONFORMANCE_USAGE)),
    };
    println!("{}", metadata(Some(coverage.as_ref())));
    Ok(())
}

/// Verifies an operator-supplied decision against this running executable.
fn inspect(directory: &Path, key: &Path) -> Result<ReleaseCoverage, CliFailure> {
    let pem = read_public_key(key).ok_or_else(|| {
        CliFailure::command(
            EXIT_USAGE,
            "release decision rejected: trusted public key is unreadable or exceeds its limit",
        )
    })?;
    let identity = CompiledIdentity {
        source_commit: COMMIT,
        target: TARGET,
        executable: Path::new(SELF_EXECUTABLE),
    };
    inspect_release_decision(directory, &pem, identity).map_err(|error| {
        CliFailure::command(
            EXIT_USAGE,
            format!("release decision rejected: {}", error.label()),
        )
    })
}

fn read_public_key(path: &Path) -> Option<Vec<u8>> {
    let file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_RELEASE_PUBLIC_KEY_BYTES)
        .ok()?
        .checked_add(1)?;
    file.take(limit).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= MAX_RELEASE_PUBLIC_KEY_BYTES).then_some(bytes)
}

/// Renders the metadata document. `None` is the `version` shape; `Some`
/// adds the conformance fields, with any inspected decision.
fn metadata(conformance: Option<Option<&ReleaseCoverage>>) -> String {
    // All interpolated strings are Cargo constants, closed protocol constants,
    // ASCII values validated by build.rs, or decision fields the config crate
    // restricted to fixed hexadecimal, timestamp, and target alphabets.
    let mut output = format!(
        "{{\"schema_version\":1,\"name\":\"agenc-ircd\",\"version\":\"{VERSION}\",\"source_commit\":\"{COMMIT}\",\"source_sha256\":\"{SOURCE}\",\"cargo_lock_sha256\":\"{LOCK}\",\"target\":\"{TARGET}\",\"compiler\":\"{COMPILER}\",\"features\":{{\"history\":{},\"wss\":{}}},\"storage_schema_generation\":{}",
        cfg!(feature = "history"),
        cfg!(feature = "wss"),
        agenc_ircd_storage::SCHEMA_GENERATION,
    );
    if let Some(coverage) = conformance {
        let profiles = agenc_ircd_runtime::release::RELEASE_PROFILES;
        output.push_str(&format!(
            ",\"architecture_document_sha256\":\"{}\",\"base_profile_sha256\":\"{}\",\"encrypted_document_sha256\":\"{}\",\"encrypted_profile_sha256\":\"{}\"",
            hexadecimal(&profiles.architecture_document),
            hexadecimal(&profiles.base_profile),
            hexadecimal(&profiles.encrypted_document),
            hexadecimal(&profiles.encrypted_profile),
        ));
        output.push_str(&format!(
            ",\"profiles\":{{\"base_sha256_base64url\":\"{}\",\"encrypted_sha256_base64url\":\"{}\"}},\"compiled\":{{\"core-v1\":true,\"federated-v1\":true,\"encrypted-v1\":true,\"history\":{},\"wss\":{}}}",
            agenc_ircd_config::BASE_PROFILE_SHA256_TOKEN,
            agenc_ircd_config::E2EE_PROFILE_SHA256_TOKEN,
            cfg!(feature = "history"),
            cfg!(feature = "wss"),
        ));
        output.push_str(&qualification_json(coverage));
        output.push_str(&storage_qualification_json());
    }
    output.push('}');
    output
}

/// The claim fields: empty without a decision, and empty with a fixed reason
/// when a verified decision describes another executable.
fn qualification_json(coverage: Option<&ReleaseCoverage>) -> String {
    match coverage {
        None => String::from(
            ",\"qualified_claims\":[],\"qualification\":\"requires detached signed release decision\"",
        ),
        Some(ReleaseCoverage::Excluded(reason)) => {
            format!(
                ",\"qualified_claims\":[],\"qualification\":\"{}\"",
                reason.label()
            )
        }
        Some(ReleaseCoverage::Covered(grant)) => granted_json(grant),
    }
}

fn granted_json(grant: &ReleaseGrant) -> String {
    let claims = grant
        .claims
        .iter()
        .map(|claim| format!("\"{}\"", claim.name()))
        .collect::<Vec<_>>()
        .join(",");
    let targets = grant
        .targets
        .iter()
        .map(|target| format!("\"{target}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        ",\"qualified_claims\":[{claims}],\"qualification\":\"detached signed release decision\",\"release_decision\":{{\"candidate_sha256\":\"{}\",\"decided_at\":\"{}\",\"public_key_sha256\":\"{}\",\"targets\":[{targets}]}}",
        hexadecimal(&grant.candidate_sha256),
        grant.decided_at,
        hexadecimal(&grant.public_key_sha256),
    )
}

/// The signed storage tuples compiled into this binary, as startup admits them.
/// A verification failure is reported as an empty list rather than a claim.
fn storage_qualification_json() -> String {
    let tuples = agenc_ircd_storage::embedded_storage_qualifications().unwrap_or_default();
    let mut output = String::from(",\"storage_qualification\":{\"tuples\":[");
    for (index, qualification) in tuples.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let tuple = qualification.tuple();
        output.push_str(&format!(
            "{{\"target\":\"{}\",\"filesystem_type\":{},\"block_size\":{},\"mount_flags\":{},\"maximum_observed_growth\":{}}}",
            tuple.target,
            tuple.filesystem_type,
            tuple.block_size,
            tuple.mount_flags,
            qualification.maximum_observed_growth(),
        ));
    }
    output.push_str("]}");
    output
}
