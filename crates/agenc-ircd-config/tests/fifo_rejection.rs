//! Host readers reject named pipes before waiting for another process.

#![forbid(unsafe_code)]

mod support;

use std::fs;
use std::sync::mpsc::sync_channel;
use std::thread;
use std::time::Duration;

use agenc_ircd_config::{
    ConfigError, SecretLength, open_secret_file_with_hook, read_protected_bytes,
};
use rustix::fs::{CWD, Mode, OFlags, mkfifoat, openat};
use support::Sandbox;

#[test]
fn protected_read_and_secret_replacement_reject_fifos_without_a_writer()
-> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::create()?;
    for secret in [false, true] {
        let path = sandbox
            .root()
            .join(if secret { "secret.key" } else { "config.toml" });
        let fifo = sandbox.root().join("replacement.pipe");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR)?;
        if secret {
            fs::write(&path, [7; 32])?;
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        } else {
            fs::rename(&fifo, &path)?;
        }
        let (sender, receiver) = sync_channel(1);
        let worker_path = path.clone();
        let worker = thread::spawn(move || {
            let error = if secret {
                open_secret_file_with_hook(&worker_path, SecretLength::Exact(32), || {
                    assert!(fs::rename(&fifo, &worker_path).is_ok());
                })
                .err()
            } else {
                read_protected_bytes(&worker_path, 32).err()
            };
            let _sent = sender.send(error);
        });
        let result = receiver.recv_timeout(Duration::from_secs(2));
        // A regressed blocking open is released before joining the worker.
        let _release = if result.is_err() {
            Some(openat(
                CWD,
                &path,
                OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?)
        } else {
            None
        };
        worker.join().map_err(|_| "file-reader worker panicked")?;
        assert_eq!(result?, Some(ConfigError::FileRejected), "secret={secret}");
        fs::remove_file(&path)?;
    }
    Ok(())
}
