#![forbid(unsafe_code)]

//! Local metadata must identify compiled behavior without granting release claims.

use std::process::Command;

type TestResult = Result<(), Box<dyn core::error::Error>>;

#[test]
fn arcd_metadata_uses_current_command_name() -> TestResult {
    let binary = env!("CARGO_BIN_EXE_arcd");
    let output = Command::new(binary).arg("--version").output()?;
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)?.starts_with("arcd "));
    for command in ["version", "conformance"] {
        let output = Command::new(binary).args([command, "--json"]).output()?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("\"name\":\"arcd\""));
        if command == "conformance" {
            assert!(text.contains("\"qualified_claims\":[]"));
        }
    }
    Ok(())
}

#[test]
fn local_metadata_requires_exact_options_and_reports_optional_features() -> TestResult {
    for command in ["version", "conformance"] {
        let output = Command::new(env!("CARGO_BIN_EXE_arcd"))
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
            assert!(text.contains("\"storage_qualification\":{\"tuples\":[{\"target\":\""));
            assert!(text.contains("\"filesystem_type\":61267,\"block_size\":4096,"));
        }
    }
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-data/release-decision"
    );
    let trusted = format!("{fixture}/release-public.pem");
    let untrusted = format!("{fixture}/untrusted-public.pem");
    for args in [
        vec!["--version", "extra"],
        vec!["version", "--json", "extra"],
        vec!["conformance"],
        vec!["conformance", "--json", "--json"],
        vec!["conformance", "--json", "--release-decision", fixture],
        vec!["conformance", "--json", "--trusted-public-key", &trusted],
        vec![
            "conformance",
            "--json",
            "--release-decision",
            fixture,
            "--trusted-public-key",
            &untrusted,
        ],
        vec![
            "conformance",
            "--json",
            "--release-decision",
            "/nonexistent-agenc-decision",
            "--trusted-public-key",
            &trusted,
        ],
    ] {
        assert!(
            !Command::new(env!("CARGO_BIN_EXE_arcd"))
                .args(args)
                .output()?
                .status
                .success()
        );
    }
    // A verified decision for another source commit grants this binary nothing.
    let output = Command::new(env!("CARGO_BIN_EXE_arcd"))
        .args([
            "conformance",
            "--json",
            "--release-decision",
            fixture,
            "--trusted-public-key",
            &trusted,
        ])
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("\"qualified_claims\":[]"));
    assert!(
        text.contains("\"qualification\":\"signed release decision names another source commit\"")
    );
    assert!(!text.contains("\"release_decision\":"));
    let output = Command::new(env!("CARGO_BIN_EXE_arcd"))
        .arg("--version")
        .output()?;
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)?.starts_with("arcd "));
    Ok(())
}
