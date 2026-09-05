//! Local build identification; completed qualification is a detached decision.

use std::ffi::OsString;

use super::CliFailure;

const COMMIT: &str = env!("AGENC_BUILD_COMMIT");
const SOURCE: &str = env!("AGENC_BUILD_SOURCE_SHA256");
const LOCK: &str = env!("AGENC_BUILD_LOCK_SHA256");
const TARGET: &str = env!("AGENC_BUILD_TARGET");
const COMPILER: &str = env!("AGENC_BUILD_COMPILER");
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(super) fn version(arguments: &[OsString]) -> Result<(), CliFailure> {
    match arguments {
        [] => println!("agenc-ircd {VERSION} ({COMMIT}; {TARGET})"),
        [argument] if argument == "--json" => println!("{}", metadata(false)),
        _ => return Err(CliFailure::usage("usage: agenc-ircd version [--json]")),
    }
    Ok(())
}

pub(super) fn conformance(arguments: &[OsString]) -> Result<(), CliFailure> {
    match arguments {
        [argument] if argument == "--json" => println!("{}", metadata(true)),
        _ => return Err(CliFailure::usage("usage: agenc-ircd conformance --json")),
    }
    Ok(())
}

fn metadata(conformance: bool) -> String {
    // All interpolated strings are Cargo constants, closed protocol constants,
    // or ASCII values validated by build.rs. Runtime inputs never enter JSON.
    let mut output = format!(
        "{{\"schema_version\":1,\"name\":\"agenc-ircd\",\"version\":\"{VERSION}\",\"source_commit\":\"{COMMIT}\",\"source_sha256\":\"{SOURCE}\",\"cargo_lock_sha256\":\"{LOCK}\",\"target\":\"{TARGET}\",\"compiler\":\"{COMPILER}\",\"features\":{{\"history\":{},\"wss\":{}}},\"storage_schema_generation\":{}",
        cfg!(feature = "history"),
        cfg!(feature = "wss"),
        agenc_ircd_storage::SCHEMA_GENERATION,
    );
    if conformance {
        let profiles = agenc_ircd_runtime::release::RELEASE_PROFILES;
        output.push_str(&format!(
            ",\"architecture_document_sha256\":\"{}\",\"base_profile_sha256\":\"{}\",\"encrypted_document_sha256\":\"{}\",\"encrypted_profile_sha256\":\"{}\"",
            hexadecimal(&profiles.architecture_document),
            hexadecimal(&profiles.base_profile),
            hexadecimal(&profiles.encrypted_document),
            hexadecimal(&profiles.encrypted_profile),
        ));
        output.push_str(&format!(
            ",\"profiles\":{{\"base_sha256_base64url\":\"{}\",\"encrypted_sha256_base64url\":\"{}\"}},\"compiled\":{{\"core-v1\":true,\"federated-v1\":true,\"encrypted-v1\":true,\"history\":{},\"wss\":{}}},\"qualified_claims\":[],\"qualification\":\"requires detached signed release decision\"",
            agenc_ircd_config::BASE_PROFILE_SHA256_TOKEN,
            agenc_ircd_config::E2EE_PROFILE_SHA256_TOKEN,
            cfg!(feature = "history"), cfg!(feature = "wss"),
        ));
    }
    output.push('}');
    output
}

fn hexadecimal(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
