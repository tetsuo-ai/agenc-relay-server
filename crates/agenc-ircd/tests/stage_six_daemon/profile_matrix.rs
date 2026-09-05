//! Each compiled profile set checks all four runtime configurations.
#![forbid(unsafe_code)]

use super::*;
use std::collections::BTreeMap;

fn state_image(directory: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut image = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            image.extend(state_image(&path)?);
        } else {
            image.insert(path.clone(), fs::read(path)?);
        }
    }
    Ok(image)
}

fn configure(fixture: &LiveFixture, websocket: bool, history: bool) -> TestResult {
    let mut text = fs::read_to_string(&fixture.config_path)?;
    if websocket {
        replace_once(
            &mut text,
            "purpose = \"client_tls\"",
            "purpose = \"client_wss\"\nallowed_origins = [\"https://chat.example\"]",
        )?;
    }
    if history {
        replace_once(
            &mut text,
            "history_enabled = false",
            "history_enabled = true",
        )?;
    }
    fs::write(&fixture.config_path, text)?;
    Ok(())
}

fn refuse_before_storage(fixture: &LiveFixture, directory: &Path) -> TestResult {
    let before = state_image(directory)?;
    let mut process = DaemonProcess::start(&fixture.config_path)?;
    assert!(!process.wait()?.success());
    assert_eq!(state_image(directory)?, before);
    Ok(())
}

fn serve_compiled_profile(fixture: &LiveFixture, websocket: bool, history: bool) -> TestResult {
    let mut process = DaemonProcess::start(&fixture.config_path)?;
    let transport = ClientTransport::Tcp;
    #[cfg(feature = "wss")]
    let transport = if websocket {
        ClientTransport::TextWebSocket
    } else {
        transport
    };
    #[cfg(not(feature = "wss"))]
    assert!(!websocket);
    let mut client = IrcClient::connect_transport(fixture, transport)?;
    client.send("CAP LS 302")?;
    let capabilities = read_until(&mut client.reader, |line| {
        line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :")
    })?;
    assert_eq!(
        capabilities
            .iter()
            .any(|line| line.contains("draft/chathistory")),
        history
    );
    let welcome = client.complete_registration("MatrixUser")?;
    assert_eq!(
        welcome.iter().any(|line| line.contains("CHATHISTORY=100")),
        history
    );
    assert_eq!(
        welcome
            .iter()
            .any(|line| line.contains("MSGREFTYPES=msgid,timestamp")),
        history
    );
    let mut admin = AdminClient::connect(fixture)?;
    admin.confirm_process("DIE :optional profile matrix complete")?;
    assert!(process.wait()?.success());
    Ok(())
}

fn configuration_admitted(output: &std::process::Output) -> bool {
    // check-config reports deployment controls after authenticating the configuration.
    // This fixture does not install a service cgroup; daemon startup remains mandatory below.
    output.status.success()
        || (output.status.code() == Some(2)
            && output.stderr == b"agenc-ircd: one or more required host controls are absent\n"
            && output.stdout.starts_with(b"control="))
}

#[test]
fn optional_profile_configuration_matrix_resolves_before_storage_writes() -> TestResult {
    for (websocket, history) in [(false, false), (true, false), (false, true), (true, true)] {
        let fixture = LiveFixture::create()?;
        let original = load_config(&fixture.config_path, ValidationDepth::Host)?;
        configure(&fixture, websocket, history)?;
        let compiled =
            (!websocket || cfg!(feature = "wss")) && (!history || cfg!(feature = "history"));
        assert_eq!(
            load_config(&fixture.config_path, ValidationDepth::Host).is_ok(),
            compiled
        );
        let checked = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
            .args(["check-config", "--config"])
            .arg(&fixture.config_path)
            .output()?;
        assert_eq!(
            configuration_admitted(&checked),
            compiled,
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
        if compiled {
            serve_compiled_profile(&fixture, websocket, history)?;
        } else {
            refuse_before_storage(&fixture, &original.storage.state_dir)?;
        }
    }
    Ok(())
}
