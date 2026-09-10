//! Real conventional-client sessions. The qualification runner supplies the image.
#![forbid(unsafe_code)]

use super::*;

fn tool_image() -> TestResult<String> {
    let image = std::env::var("AGENC_STAGE10_TOOL_IMAGE")?;
    let hash = image
        .strip_prefix("sha256:")
        .ok_or_else(|| failure("qualification tool image must use a local content digest"))?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(failure("qualification tool image digest is malformed"));
    }
    Ok(image)
}

fn public_client_fixture(fixture: &LiveFixture) -> TestResult<PathBuf> {
    let path = fixture._root.path().join("client-public");
    create_directory(&path, 0o755)?;
    let encoded = STANDARD.encode(fixture.tls.ca_certificate_der());
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line)?);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    fs::write(path.join("ca.pem"), pem)?;
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-conventional-client.py"),
        path.join("client.py"),
    )?;
    Ok(path)
}

fn run_client(image: &str, name: &str, fixture: &LiveFixture, public: &Path) -> TestResult {
    let owner = public.metadata()?;
    let output = Command::new("docker")
        .args(["run", "--user"])
        .arg(format!("{}:{}", owner.uid(), owner.gid()))
        .args([
            "--rm",
            "--pull=never",
            "--network=host",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=32m",
            "--add-host",
            "node.test:127.0.0.1",
            "--mount",
        ])
        .arg(format!(
            "type=bind,src={},dst=/fixture,readonly",
            public.display()
        ))
        .args([image, "python3", "/fixture/client.py", name])
        .arg(fixture.public_address.port().to_string())
        .output()?;
    println!(
        "{name} terminal transcript:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    if !output.status.success() {
        return Err(failure(format!(
            "{name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned Stage 10 conventional-client container"]
fn conventional_clients_exchange_public_messages_and_cannot_enter_secret_channels() -> TestResult {
    let image = tool_image()?;
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let (mut observer, _) = exercise_account_client(&fixture)?;
    for channel in ["#qual-public", "#qual-secret"] {
        assert_contains(
            &observer.send_until(&format!("JOIN {channel}"), " 366 ")?,
            " 366 ",
        )?;
    }
    assert_contains(
        &observer.send_until("MODE #qual-secret +s", " MODE #qual-secret ")?,
        "+s",
    )?;
    let public = public_client_fixture(&fixture)?;
    for name in ["weechat", "irssi"] {
        run_client(&image, name, &fixture, &public)?;
        let transcript = read_until(&mut observer.reader, |line| {
            line.contains(" QUIT :qualification-complete")
        })?;
        assert_contains(
            &transcript,
            &format!(" PRIVMSG #qual-public :{name}-public-proof"),
        )?;
        if transcript.iter().any(|line| line.contains("#qual-secret")) {
            return Err(failure(
                "a conventional guest entered or sent to the secret channel",
            ));
        }
        println!("{name} observer transcript: {transcript:?}");
    }
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :client qualification complete")?;
    assert!(daemon.wait()?.success());
    Ok(())
}
