#![forbid(unsafe_code)]

//! Verifies that the command surface cannot be mistaken for a running daemon.

use std::error::Error;
use std::process::Command;

const EXPECTED_MESSAGE: &str = "arcd: usage: arcd <command> [options]\ncommands:\n  version [--json]\n  conformance --json [--release-decision <directory> --trusted-public-key <pem>]\n  serve --config <file>\n  check-config --config <file> [--service-user <name>]\n  init --config <file> --profile <public|onion|dual> [options]\n  print-onboarding --config <file> [--service-user <name>]\n  account-invite create --descriptor <file> --signing-key-file <file> --expires-in <seconds> [--service-user <name>]\n  sequencer-credentials create --config <file> --sequencer-key-file <file> --not-before <unix-seconds> --not-after <unix-seconds> --output <new-file> [--service-user <name>]\n  storage restore --config <file> --backup <file> [restore options]\n  storage login-index-rotate-start --config <file> --new-key-file <file>\n  storage login-index-rotate-finish --config <file>\n  storage qualify --state-dir <new-directory> --scratch-dir <new-directory> --unsigned-report <file> --raw-log <file> [--json <file>]\n";

#[test]
fn binary_refuses_to_impersonate_an_implemented_daemon() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_arcd")).output()?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, EXPECTED_MESSAGE.as_bytes());

    Ok(())
}

#[test]
fn storage_subcommands_without_their_arguments_print_usage() -> Result<(), Box<dyn Error>> {
    for arguments in [["storage", "qualify"], ["storage", "unknown"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_arcd"))
            .args(arguments)
            .output()?;
        assert!(!output.status.success(), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("usage"),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
