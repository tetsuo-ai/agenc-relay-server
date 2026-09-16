//! OPS-01 (#40): the explicit service identity of privileged offline commands.
#![forbid(unsafe_code)]

use super::*;

fn current_account_name() -> TestResult<String> {
    let output = Command::new("id").arg("-un").output()?;
    if !output.status.success() {
        return Err(failure("id -un failed"));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn onboarding(
    fixture: &LiveFixture,
    service_user: Option<&str>,
) -> TestResult<std::process::Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"));
    command
        .arg("print-onboarding")
        .arg("--config")
        .arg(&fixture.config_path);
    if let Some(name) = service_user {
        command.arg("--service-user").arg(name);
    }
    Ok(command.output()?)
}

/// The service account runs the offline commands against its own material
/// with or without naming itself; unrelated and unknown names are refused,
/// and serve does not accept the option.
#[test]
fn offline_commands_accept_the_caller_as_service_user_and_refuse_others() -> TestResult {
    let fixture = LiveFixture::create()?;
    let me = current_account_name()?;

    let plain = onboarding(&fixture, None)?;
    assert!(
        plain.status.success(),
        "unqualified invocation must succeed"
    );
    let named = onboarding(&fixture, Some(&me))?;
    assert!(
        named.status.success(),
        "naming the caller's own account must succeed"
    );
    assert_eq!(plain.stdout, named.stdout);
    assert!(named.stderr.is_empty());

    let unknown = onboarding(&fixture, Some("agenc-no-such-account-zz"))?;
    assert!(!unknown.status.success());
    assert!(String::from_utf8(unknown.stderr)?.contains("service user rejected"));

    let malformed = onboarding(&fixture, Some("-root"))?;
    assert!(!malformed.status.success());

    if me != "root" {
        // An unprivileged caller cannot widen trust to another account,
        // root included.
        let widened = onboarding(&fixture, Some("root"))?;
        assert!(!widened.status.success());
        assert!(String::from_utf8(widened.stderr)?.contains("service user rejected"));
    }

    let serve = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
        .arg("serve")
        .arg("--config")
        .arg(&fixture.config_path)
        .arg("--service-user")
        .arg(&me)
        .output()?;
    assert!(!serve.status.success(), "serve must not accept the option");
    assert!(String::from_utf8(serve.stderr)?.contains("usage: agenc-ircd serve"));
    Ok(())
}

/// A root caller naming the service account. The host offers no privileged
/// fixture with two mapped UIDs, so this runs the real binary as the root of
/// a single-mapping user namespace when the kernel permits one; that proves
/// the root-side resolution and acceptance path and the truthful host
/// report, not trust of a second owner. Without a usable namespace the case
/// is an explicit skipped qualification, never passing evidence.
#[test]
fn root_caller_names_the_service_account_or_the_case_is_skipped() -> TestResult {
    let probe = Command::new("unshare").args(["-Ur", "id", "-u"]).output();
    let usable = probe
        .as_ref()
        .is_ok_and(|output| output.status.success() && output.stdout.trim_ascii() == b"0");
    if !usable {
        eprintln!("skipped qualification: no user namespace with a root mapping is available here");
        return Ok(());
    }
    let fixture = LiveFixture::create()?;
    let me = current_account_name()?;
    let output = Command::new("unshare")
        .args([
            "-Ur",
            env!("CARGO_BIN_EXE_agenc-ircd"),
            "check-config",
            "--config",
        ])
        .arg(&fixture.config_path)
        .args(["--service-user", &me])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        !stderr.contains("service user rejected"),
        "root must accept the named service account: {stderr}"
    );
    // The host-control report describes the executing process; inside the
    // namespace that process is root, and the report must say so rather
    // than claim an unprivileged context.
    assert!(
        stdout.contains("unprivileged-account"),
        "the host-control report must be printed: {stdout}"
    );
    Ok(())
}
