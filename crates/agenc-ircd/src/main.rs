#![forbid(unsafe_code)]

//! AgenC daemon composition entry point.

use std::process::ExitCode;

const STAGE_ZERO_MESSAGE: &str =
    "agenc-ircd: daemon behavior is unavailable until the Stage 06 runtime is implemented";

fn main() -> ExitCode {
    eprintln!("{STAGE_ZERO_MESSAGE}");
    ExitCode::FAILURE
}
