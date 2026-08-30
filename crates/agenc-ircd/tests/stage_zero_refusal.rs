#![forbid(unsafe_code)]

//! Verifies that the command surface cannot be mistaken for a running daemon.

use std::error::Error;
use std::process::Command;

const EXPECTED_MESSAGE: &str = "agenc-ircd: usage: agenc-ircd <command> [options]\ncommands:\n  serve --config <file>\n  check-config --config <file>\n  init --config <file> --profile <public|onion|dual> [options]\n  print-onboarding --config <file>\n  account-invite create --descriptor <file> --signing-key-file <file> --expires-in <seconds>\n  storage restore --config <file> --backup <file> [restore options]\n";

#[test]
fn binary_refuses_to_impersonate_an_implemented_daemon() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_agenc-ircd")).output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, EXPECTED_MESSAGE.as_bytes());

    Ok(())
}
