#![forbid(unsafe_code)]

//! Local metadata must identify compiled behavior without granting release claims.

use std::process::Command;

type TestResult = Result<(), Box<dyn core::error::Error>>;

#[test]
fn local_metadata_requires_exact_options_and_reports_optional_features() -> TestResult {
    for command in ["version", "conformance"] {
        let output = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
            .args([command, "--json"])
            .output()?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.starts_with("{\"schema_version\":1,"));
        assert!(text.ends_with("}\n"));
        assert!(text.contains(&format!("\"history\":{}", cfg!(feature = "history"))));
        assert!(text.contains(&format!("\"wss\":{}", cfg!(feature = "wss"))));
        if command == "conformance" {
            assert!(text.contains("\"qualified_claims\":[]"));
        }
    }
    for args in [
        vec!["--version", "extra"],
        vec!["version", "--json", "extra"],
        vec!["conformance"],
        vec!["conformance", "--json", "--json"],
    ] {
        assert!(
            !Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
                .args(args)
                .output()?
                .status
                .success()
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
        .arg("--version")
        .output()?;
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)?.starts_with("agenc-ircd "));
    Ok(())
}
