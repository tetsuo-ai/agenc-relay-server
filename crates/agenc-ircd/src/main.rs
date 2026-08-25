#![forbid(unsafe_code)]

//! AgenC daemon composition entry point.

use std::process::ExitCode;

const STAGE_ZERO_MESSAGE: &str =
    "agenc-ircd: daemon behavior is unavailable until its implementation stages are complete";

fn main() -> ExitCode {
    eprintln!("{STAGE_ZERO_MESSAGE}");
    ExitCode::FAILURE
}
