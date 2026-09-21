#![forbid(unsafe_code)]
// agenc-review: allow owner=config reviewed=2026-08-29 reason=each integration test binary uses a different subset of these shared fixtures
#![allow(dead_code)]

//! Shared fixtures for the configuration crate tests.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agenc_relay_config::{Config, ConfigReport, PathResolver, ValidationDepth};

/// The checked-in golden `public` profile document.
pub(crate) const PUBLIC: &str = include_str!("../golden/public.toml");
/// The checked-in golden `onion` profile document.
pub(crate) const ONION: &str = include_str!("../golden/onion.toml");
/// The checked-in golden `dual` profile document.
pub(crate) const DUAL: &str = include_str!("../golden/dual.toml");

/// Parses at document depth with no resolver base.
pub(crate) fn parse(text: &str) -> Result<Config, ConfigReport> {
    Config::parse_text(text, &PathResolver::none(), ValidationDepth::Document)
}

/// Replaces exactly one occurrence of `old` with `new`, failing loudly otherwise.
pub(crate) fn mutate(text: &str, old: &str, new: &str) -> String {
    assert_eq!(
        text.matches(old).count(),
        1,
        "fixture edit is ambiguous: {old}"
    );
    text.replacen(old, new, 1)
}

/// Appends `line` at the end of the named table (before the next header).
pub(crate) fn append_to_table(text: &str, table: &str, line: &str) -> String {
    let header = format!("[{table}]\n");
    let start = text.find(&header).map(|position| position + header.len());
    assert!(start.is_some(), "fixture table missing: {table}");
    let start = start.unwrap_or(0);
    let rest = &text[start..];
    let end = rest
        .find("\n[")
        .map_or(text.len(), |offset| start + offset + 1);
    let mut out = String::with_capacity(text.len() + line.len() + 1);
    out.push_str(&text[..end]);
    out.push_str(line);
    out.push('\n');
    out.push_str(&text[end..]);
    out
}

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// Candidate sandbox bases in preference order; each must exist (or be creatable)
/// with no group- or world-writable ancestor, which rules out `/tmp` itself.
fn protected_base() -> Option<PathBuf> {
    let candidates = [
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        std::env::var_os("CARGO_TARGET_TMPDIR").map(PathBuf::from),
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")),
        Some(std::env::temp_dir()),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|base| fs::create_dir_all(base).is_ok() && ancestors_are_protected(base))
}

fn ancestors_are_protected(base: &Path) -> bool {
    let mut cursor = PathBuf::new();
    base.components().all(|component| {
        cursor.push(component);
        fs::symlink_metadata(&cursor)
            .is_ok_and(|meta| meta.file_type().is_dir() && meta.permissions().mode() & 0o022 == 0)
    })
}

/// A private temporary directory tree that mirrors the golden path layout.
pub(crate) struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    /// Creates `<base>/agenc-config-<pid>-<n>` with mode 0700 under the first base
    /// whose ancestors are all private enough to hold secret files (spec 4330).
    pub(crate) fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let sequence = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let base = protected_base().ok_or("no directory with protected ancestors is available")?;
        let root = base.join(format!("agenc-config-{}-{sequence}", std::process::id()));
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self { root })
    }

    /// The sandbox root.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Creates a directory under the root with the given mode.
    pub(crate) fn dir(
        &self,
        relative: &str,
        mode: u32,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = self.root.join(relative);
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        Ok(path)
    }

    /// Writes a file under the root with the given mode.
    pub(crate) fn file(
        &self,
        relative: &str,
        contents: &[u8],
        mode: u32,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            create_private_parent_directories(&self.root, parent)?;
        }
        fs::write(&path, contents)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        Ok(path)
    }

    /// Rewrites the golden `/srv/agenc`, `/srv/agenc-backups`, `/run/arcd`, and
    /// `/etc/arcd` prefixes to live under this sandbox.
    pub(crate) fn localize(&self, text: &str) -> String {
        let root = self.root.display().to_string();
        text.replace("/srv/agenc-backups", &format!("{root}/backups"))
            .replace("/srv/agenc", &format!("{root}/data"))
            .replace("/run/arcd", &format!("{root}/run"))
            .replace("/etc/arcd", &format!("{root}/etc"))
    }

    /// Materializes the host layout the golden documents name: directories, secret
    /// files with 32 distinct bytes, trust manifests, and TLS files.
    pub(crate) fn populate_host_layout(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.dir("data", 0o700)?;
        self.dir("data/state", 0o700)?;
        self.dir("backups", 0o700)?;
        self.dir("run", 0o750)?;
        self.dir("etc", 0o755)?;
        self.dir("etc/keys", 0o700)?;
        self.dir("etc/trust", 0o755)?;
        self.dir("etc/tls", 0o755)?;
        let secrets = [
            "storage-master.key",
            "rollback-guard.key",
            "login-index-g1.key",
            "backup-signing.key",
            "audit-signing.key",
            "account-service-hpke.key",
            "opaque-fake-credential.key",
            "federation-signing.key",
            "sequencer.key",
        ];
        for (index, name) in secrets.iter().enumerate() {
            let byte = u8::try_from(index + 1)?;
            self.file(&format!("etc/keys/{name}"), &[byte; 32], 0o600)?;
        }
        self.file("etc/keys/opaque-server-setup.key", &[0x42; 200], 0o600)?;
        self.file("etc/keys/invite-verification.pub", &[0x11; 32], 0o644)?;
        for (index, stem) in ["server", "onion", "federation", "admin"]
            .into_iter()
            .enumerate()
        {
            let byte = u8::try_from(0x70 + index)?;
            self.file(&format!("etc/tls/{stem}.crt"), b"certificate", 0o644)?;
            self.file(&format!("etc/tls/{stem}.key"), &[byte; 48], 0o600)?;
        }
        self.file("etc/tls/federation-ca.pem", b"ca", 0o644)?;
        self.file("etc/tls/admin-ca.pem", b"ca", 0o644)?;
        self.file(
            "etc/trust/backup-trust.toml",
            trust_manifest("backup_trust_version").as_bytes(),
            0o644,
        )?;
        self.file(
            "etc/trust/audit-trust.toml",
            trust_manifest("audit_trust_version").as_bytes(),
            0o644,
        )?;
        self.file(
            "etc/trust/sequencer-credentials.toml",
            b"credentials = 1\n",
            0o644,
        )?;
        Ok(())
    }

    /// Writes a protected configuration file and returns its path.
    pub(crate) fn config_file(&self, text: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.file("etc/config.toml", text.as_bytes(), 0o600)
    }
}

fn create_private_parent_directories(
    root: &Path,
    parent: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let relative = parent.strip_prefix(root)?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        cursor.push(component);
        match fs::create_dir(&cursor) {
            Ok(()) => fs::set_permissions(&cursor, fs::Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A one-key trust manifest under the given root key.
pub(crate) fn trust_manifest(version_key: &str) -> String {
    format!(
        "{version_key} = 1\n\n[[key]]\nkey_id = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\"\n\
         ed25519_public_key = \"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg\"\n\
         not_before = 1\nnot_after = 4102444800\n"
    )
}

/// The peer identifier used by the edge derivation.
pub(crate) const SRV3: &str = "AwMDAwMDAwMDAwMDAwMDAw";

/// A valid edge node derived from the dual golden: it federates with a coordinator
/// through one TCP endpoint and holds no coordinator-only material.
pub(crate) fn edge() -> String {
    let text = mutate(DUAL, "role = \"coordinator\"", "role = \"edge\"");
    let text = mutate(
        &text,
        "coordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\ndns_name",
        &format!("coordinator_server_id = \"{SRV3}\"\ndns_name"),
    );
    let text = mutate(
        &text,
        "coordinator_server_id = \"AgICAgICAgICAgICAgICAg\"\nsequencer_private_key_file = \"/etc/arcd/keys/sequencer.key\"\n",
        &format!("coordinator_server_id = \"{SRV3}\"\n"),
    );
    let text = mutate(
        &text,
        "account_service_hpke_private_key_file = \"/etc/arcd/keys/account-service-hpke.key\"\nopaque_server_setup_file = \"/etc/arcd/keys/opaque-server-setup.key\"\nopaque_fake_credential_key_file = \"/etc/arcd/keys/opaque-fake-credential.key\"\n",
        "",
    );
    let text = mutate(
        &text,
        "name = \"federation\"\nenabled = true",
        "name = \"federation\"\nenabled = false",
    );
    let text = mutate(
        &text,
        "server_id = \"AwMDAwMDAwMDAwMDAwMDAw\"\nserver_name = \"edge.example\"\nrole = \"edge\"",
        &format!("server_id = \"{SRV3}\"\nserver_name = \"hub.example\"\nrole = \"coordinator\""),
    );
    mutate(
        &text,
        "endpoints = []",
        "endpoints = [\"tcp:203.0.113.5:7000\"]",
    )
}
