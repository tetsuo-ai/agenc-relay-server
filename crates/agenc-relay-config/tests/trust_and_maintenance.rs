#![forbid(unsafe_code)]

//! Trust manifests and the preserved stopped-daemon maintenance projection.

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use agenc_relay_config::{
    ConfigError, DEFAULT_REDB_CACHE_BYTES, MAX_CONFIG_BYTES, ValidationDepth,
    load_audit_trust_manifest, load_backup_trust_manifest, load_config, load_maintenance_config,
    parse_audit_trust_manifest, parse_backup_trust_manifest,
};
use agenc_relay_types::{NetworkId, ServerId};
use support::{PUBLIC, Sandbox, mutate, trust_manifest};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn trust_manifests_parse_and_reject_every_malformed_shape() -> TestResult {
    let backup = parse_backup_trust_manifest(&trust_manifest("backup_trust_version"))?;
    assert_eq!(backup.len(), 1);
    assert_eq!(backup.first().map(|entry| entry.not_before), Some(1));
    let audit = parse_audit_trust_manifest(&trust_manifest("audit_trust_version"))?;
    assert_eq!(audit.first().map(|entry| entry.key_id), Some([7; 32]));
    assert!(parse_backup_trust_manifest(&trust_manifest("audit_trust_version")).is_err());
    assert!(parse_audit_trust_manifest(&trust_manifest("backup_trust_version")).is_err());
    let row = "[[key]]\nkey_id = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\"\ned25519_public_key = \"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg\"\nnot_before = 1\nnot_after = 2\n";
    let bad = [
        "backup_trust_version = 1\n".to_owned(),
        format!("backup_trust_version = 2\n{row}"),
        format!("backup_trust_version = 1\n{row}{row}"),
        format!("backup_trust_version = 1\n{row}unknown = 1\n"),
        format!("backup_trust_version = 1\nextra = 1\n{row}"),
        "backup_trust_version = 1\nkey = []\n".to_owned(),
        "backup_trust_version = 1\nkey = 5\n".to_owned(),
        "backup_trust_version = 1\nkey = [1]\n".to_owned(),
        format!(
            "backup_trust_version = 1\n{}",
            row.replace("not_after = 2", "not_after = 1")
        ),
        format!(
            "backup_trust_version = 1\n{}",
            row.replace("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc", "short")
        ),
        format!(
            "backup_trust_version = 1\n{}",
            row.replace("not_before = 1\n", "")
        ),
    ];
    for text in bad {
        assert!(parse_backup_trust_manifest(&text).is_err(), "{text}");
    }
    let one = "{ key_id = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\", ed25519_public_key = \"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg\", not_before = 1, not_after = 2 }";
    let oversized = format!(
        "backup_trust_version = 1\nkey = [{}]\n",
        std::iter::repeat_n(one, 1_025)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        parse_backup_trust_manifest(&oversized).err(),
        Some(ConfigError::InvalidValue)
    );
    Ok(())
}

#[test]
fn trust_manifest_files_must_be_protected() -> TestResult {
    let sandbox = Sandbox::create()?;
    let backup = sandbox.file(
        "trust/backup.toml",
        trust_manifest("backup_trust_version").as_bytes(),
        0o600,
    )?;
    assert_eq!(load_backup_trust_manifest(&backup)?.len(), 1);
    let audit = sandbox.file(
        "trust/audit.toml",
        trust_manifest("audit_trust_version").as_bytes(),
        0o644,
    )?;
    assert_eq!(load_audit_trust_manifest(&audit)?.len(), 1);
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o622))?;
    assert_eq!(
        load_backup_trust_manifest(&backup).err(),
        Some(ConfigError::FileRejected)
    );
    assert_eq!(
        load_audit_trust_manifest(Path::new("relative.toml")).err(),
        Some(ConfigError::FileRejected)
    );
    assert_eq!(
        load_audit_trust_manifest(Path::new("/tmp/../x.toml")).err(),
        Some(ConfigError::FileRejected)
    );
    let big = sandbox.file("trust/big.toml", b"", 0o600)?;
    fs::File::create(&big)?.set_len(MAX_CONFIG_BYTES + 1)?;
    fs::set_permissions(&big, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        load_backup_trust_manifest(&big).err(),
        Some(ConfigError::FileRejected)
    );
    assert_eq!(
        load_backup_trust_manifest(sandbox.root()).err(),
        Some(ConfigError::FileRejected)
    );
    Ok(())
}

#[test]
fn maintenance_projection_preserves_the_stopped_daemon_contract() -> TestResult {
    let sandbox = Sandbox::create()?;
    let text = sandbox.localize(PUBLIC);
    let path = sandbox.config_file(&text)?;
    let config = load_maintenance_config(&path)?;
    assert_eq!(config.network_id, NetworkId::from_bytes([1; 32]));
    assert_eq!(config.server_id, ServerId::from_bytes([2; 16]));
    assert_eq!(config.redb_cache_bytes, DEFAULT_REDB_CACHE_BYTES);
    assert_eq!(config.reserve_percent, 5);
    assert_eq!(config.database_max_bytes, 85_899_345_920);
    assert_eq!(config.backup_max_bytes, 107_374_182_400);
    assert_eq!(config.integrity_checkpoint_manifests, 100_000);
    assert!(config.login_index_previous_key_file.is_none());
    assert!(config.state_directory.ends_with("data/state"));
    assert!(
        config
            .backup_trust_manifest_file
            .ends_with("etc/trust/backup-trust.toml")
    );

    let previous = mutate(
        &text,
        "login_index_key_file = ",
        "login_index_previous_key_file = \"/etc/previous.key\"\nlogin_index_key_file = ",
    );
    let path = sandbox.config_file(&previous)?;
    assert!(
        load_maintenance_config(&path)?
            .login_index_previous_key_file
            .is_some()
    );

    let invalid = mutate(&text, "config_version = 1", "config_version = 2");
    let path = sandbox.config_file(&invalid)?;
    assert_eq!(
        load_maintenance_config(&path).err(),
        Some(ConfigError::InvalidValue)
    );
    let unknown = mutate(&text, "[tls]", "[tls]\nkey_log_file = \"/x\"");
    let path = sandbox.config_file(&unknown)?;
    assert_eq!(
        load_maintenance_config(&path).err(),
        Some(ConfigError::UnknownKey)
    );
    assert_eq!(
        load_maintenance_config(Path::new("relative.toml")).err(),
        Some(ConfigError::FileRejected)
    );
    assert_eq!(
        load_maintenance_config(Path::new("/config.toml")).err(),
        Some(ConfigError::FileRejected)
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
    assert_eq!(
        load_maintenance_config(&path).err(),
        Some(ConfigError::FileRejected)
    );
    Ok(())
}

#[test]
fn load_config_resolves_relative_paths_against_the_file_parent() -> TestResult {
    let sandbox = Sandbox::create()?;
    let text = sandbox.localize(PUBLIC);
    let root = sandbox.root().display().to_string();
    let relative = text.replace(&format!("{root}/etc/keys/"), "keys/");
    let path = sandbox.config_file(&relative)?;
    let config = load_config(&path, ValidationDepth::Document)?;
    assert!(
        config
            .storage
            .master_key_file
            .starts_with(sandbox.root().join("etc/keys"))
    );
    let missing = sandbox.root().join("etc/missing.toml");
    assert!(load_config(&missing, ValidationDepth::Document).is_err());
    Ok(())
}
