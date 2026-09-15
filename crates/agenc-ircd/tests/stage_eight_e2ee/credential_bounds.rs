//! ENC-13 (#39): an oversized or sparse sequencer credentials file refuses
//! real startup before any listener opens, without leaking its path or bytes.
#![forbid(unsafe_code)]

use super::*;
use std::collections::BTreeMap;

/// The architecture Appendix C.7 credentials-file ceiling, equal to
/// `agenc_ircd_e2ee::sequencer::MAX_SEQUENCER_CREDENTIALS_FILE_BYTES`; the
/// integration crate has no direct dependency on the E2EE crate.
const MAX_SEQUENCER_CREDENTIALS_FILE_BYTES: usize = 4_096;

/// Every regular file below `root`, keyed by its relative path, with its
/// exact bytes.
fn directory_image(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut image = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| failure("image path escapes its root"))?
                    .to_path_buf();
                image.insert(relative, fs::read(&path)?);
            }
        }
    }
    Ok(image)
}

fn contains_run(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn oversized_sequencer_credentials_refuse_startup_before_listening() -> TestResult {
    let coordinator = NodeIdentity::new(20, NodeRole::Coordinator, "core.test")?;
    let edge = NodeIdentity::new(40, NodeRole::Edge, "edge-a.test")?;
    let federation_address = reserve_loopback_address()?;
    let fixture = NodeFixture::create(&NodePlan {
        identity: &coordinator,
        coordinator: &coordinator,
        federation_address: Some(federation_address),
        peers: &[&edge],
        capacity: None,
    })?;
    let credentials_path = fixture
        .data_dir
        .join("keys")
        .join("sequencer-credentials.bin");
    let state_dir = fixture.data_dir.join("state");
    let before = directory_image(&state_dir)?;
    let stderr_dir = fixture.data_dir.join("stderr");
    create_directory(&stderr_dir, 0o700)?;
    let oversize = MAX_SEQUENCER_CREDENTIALS_FILE_BYTES + 1;
    let pattern = vec![0x5a_u8; oversize];
    let path_text = credentials_path.to_string_lossy().into_owned();

    for (label, sparse) in [("oversized", false), ("sparse", true)] {
        fs::remove_file(&credentials_path)?;
        if sparse {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let file = options.open(&credentials_path)?;
            file.set_len(u64::try_from(oversize)?)?;
            file.sync_all()?;
        } else {
            write_private(&credentials_path, &pattern)?;
        }
        let stderr_log = stderr_dir.join(format!("{label}.stderr"));
        let mut daemon =
            DaemonProcess::start_logged(&fixture.config_path, None, Some(&stderr_log))?;
        let status = daemon.wait_within(NETWORK_WAIT)?;
        assert!(
            !status.success(),
            "{label}: the daemon must refuse the credentials file"
        );
        assert!(
            TcpStream::connect_timeout(&fixture.public_address, Duration::from_millis(250))
                .is_err(),
            "{label}: no listener may be open after the refusal"
        );
        // redb rewrites its header slot when the database is opened, so the
        // database file is compared by name and length; every other state
        // file is compared byte for byte, and the positive control below
        // proves the logical state still starts and serves.
        let after = directory_image(&state_dir)?;
        assert_eq!(
            after.keys().collect::<Vec<_>>(),
            before.keys().collect::<Vec<_>>(),
            "{label}: the refusal must add or remove no state file"
        );
        for (name, bytes) in &before {
            let observed = after
                .get(name)
                .ok_or_else(|| failure("state file vanished"))?;
            if name.file_name().is_some_and(|file| file == "database.redb") {
                assert_eq!(
                    observed.len(),
                    bytes.len(),
                    "{label}: database length changed"
                );
            } else {
                assert_eq!(
                    observed,
                    bytes,
                    "{label}: state file {} changed",
                    name.display()
                );
            }
        }
        let stderr_bytes = fs::read(&stderr_log)?;
        let stderr_text = String::from_utf8_lossy(&stderr_bytes);
        let log_text = fixture.log_text();
        assert!(
            !stderr_text.contains(&path_text),
            "{label}: stderr names the path"
        );
        assert!(
            !log_text.contains(&path_text),
            "{label}: the log names the path"
        );
        let sample = pattern.get(..64).ok_or_else(|| failure("pattern sample"))?;
        assert!(
            !contains_run(&stderr_bytes, sample) && !contains_run(log_text.as_bytes(), sample),
            "{label}: document bytes must not be echoed"
        );
    }

    // Positive control: the original document admits the same node.
    fs::remove_file(&credentials_path)?;
    let sequencer = Ed25519SecretKey::from_bytes([coordinator.seed.wrapping_add(15); 32]);
    let credentials = builders::sequencer_credentials_document(
        *NETWORK_ID.as_bytes(),
        &sequencer,
        (0, 4_000_000_000),
    )?;
    write_private(&credentials_path, &credentials)?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    drop(IrcClient::connect(&fixture)?);
    let status = daemon.stop()?;
    assert!(
        status.success(),
        "the restored credentials must start and stop cleanly"
    );
    Ok(())
}
