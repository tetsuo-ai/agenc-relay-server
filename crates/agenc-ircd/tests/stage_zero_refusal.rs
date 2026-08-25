#![forbid(unsafe_code)]

//! Verifies that the Phase-00 binary cannot be mistaken for a daemon.

use std::error::Error;
use std::process::Command;

const EXPECTED_MESSAGE: &str =
    "agenc-ircd: daemon behavior is unavailable until its implementation stages are complete\n";

#[test]
fn binary_refuses_to_impersonate_an_implemented_daemon() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_agenc-ircd")).output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, EXPECTED_MESSAGE.as_bytes());

    Ok(())
}
