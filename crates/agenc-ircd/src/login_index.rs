//! Closed command grammar for stopped login-index rotation.
#![forbid(unsafe_code)]

use crate::options::{OptionSpec, ParsedOptions};
use crate::{CliFailure, EXIT_USAGE};
use agenc_ircd_config::encode_base64url_32;
use agenc_ircd_runtime::offline::{
    LoginIndexRotationReceipt, execute_login_index_finish, execute_login_index_start,
};
use agenc_ircd_storage::LoginIndexKeyState;
use std::ffi::OsString;

pub(crate) const START_USAGE: &str =
    "usage: agenc-ircd storage login-index-rotate-start --config <file> --new-key-file <file>";
pub(crate) const FINISH_USAGE: &str =
    "usage: agenc-ircd storage login-index-rotate-finish --config <file>";

pub(crate) fn run_start(arguments: &[OsString]) -> Result<(), CliFailure> {
    let specs = [
        OptionSpec::value("--config"),
        OptionSpec::value("--new-key-file"),
    ];
    let mut parsed =
        ParsedOptions::parse(arguments, &specs).map_err(|()| CliFailure::usage(START_USAGE))?;
    let config = parsed
        .required_path("--config")
        .map_err(|()| CliFailure::usage(START_USAGE))?;
    let new_key = parsed
        .required_path("--new-key-file")
        .map_err(|()| CliFailure::usage(START_USAGE))?;
    let receipt = execute_login_index_start(&config, &new_key)
        .map_err(|error| CliFailure::command(EXIT_USAGE, error.to_string()))?;
    print_receipt(&receipt);
    println!(
        "Before restart, atomically configure the new key as current and the old key as previous."
    );
    Ok(())
}

pub(crate) fn run_finish(arguments: &[OsString]) -> Result<(), CliFailure> {
    let config = crate::one_config(arguments, FINISH_USAGE)?;
    let receipt = execute_login_index_finish(&config)
        .map_err(|error| CliFailure::command(EXIT_USAGE, error.to_string()))?;
    print_receipt(&receipt);
    println!(
        "Before restart, atomically remove the previous-key setting and retain the same current key."
    );
    Ok(())
}

fn print_receipt(receipt: &LoginIndexRotationReceipt) {
    println!(
        "current generation: {}; current key ID: {}",
        receipt.key_state.current_generation(),
        encode_base64url_32(receipt.key_state.current_key_id().as_bytes())
    );
    match receipt.key_state {
        LoginIndexKeyState::Stable { .. } => {
            println!("previous generation: absent; previous entries: 0")
        }
        LoginIndexKeyState::Transition {
            previous_generation,
            previous_key_id,
            previous_entry_count,
            ..
        } => {
            println!(
                "previous generation: {}; previous key ID: {}; previous entries: {}",
                previous_generation,
                encode_base64url_32(previous_key_id.as_bytes()),
                previous_entry_count
            );
        }
    }
    println!(
        "state generation: {}; storage commit sequence: {}; rollback guard hash: {}",
        receipt.storage.state_generation,
        receipt.storage.storage_commit_sequence,
        encode_base64url_32(receipt.storage.rollback_guard_hash.as_bytes())
    );
    println!(
        "audit sequence: {}; audit event hash: {}",
        receipt.audit.tbs().position().audit_sequence(),
        encode_base64url_32(&receipt.audit.event_hash())
    );
}
