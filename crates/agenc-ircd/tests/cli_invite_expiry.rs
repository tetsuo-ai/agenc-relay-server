//! Canonical command-line expiry validation happens before descriptor reads.

#![forbid(unsafe_code)]

use std::error::Error;
use std::process::Command;

#[test]
fn invite_expiry_rejects_noncanonical_decimal_before_opening_inputs() -> Result<(), Box<dyn Error>>
{
    let missing = std::env::temp_dir().join(format!(
        "agenc-invite-expiry-missing-{}",
        std::process::id()
    ));
    assert!(!missing.exists());
    for expiry in [
        "+1",
        "01",
        "-1",
        " 1",
        "1 ",
        "١",
        "18446744073709551616",
        "184467440737095516150",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
            .args(["account-invite", "create", "--descriptor"])
            .arg(&missing)
            .arg("--signing-key-file")
            .arg(&missing)
            .args(["--expires-in", expiry])
            .output()?;
        assert!(!output.status.success(), "{expiry:?}");
        assert!(output.stdout.is_empty(), "{expiry:?}");
        let error = String::from_utf8(output.stderr)?;
        assert!(
            error.starts_with("agenc-ircd: usage:"),
            "{expiry:?}: {error}"
        );
    }
    Ok(())
}
