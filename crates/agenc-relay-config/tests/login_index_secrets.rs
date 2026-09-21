#![forbid(unsafe_code)]

//! Stopped rotation retains the complete configured secret-purpose inventory.

mod support;

use std::fs;
use std::os::unix::fs::symlink;

use agenc_relay_config::{Config, ConfigError, PathResolver, SecretSet, ValidationDepth};
use support::{DUAL, Sandbox};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(Sandbox, Config), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let resolver = PathResolver::with_base(sandbox.root().join("etc"))?;
    let config = Config::parse_text(&sandbox.localize(DUAL), &resolver, ValidationDepth::Host)?;
    Ok((sandbox, config))
}

#[test]
fn rotation_secret_loading_preserves_the_current_storage_key() -> TestResult {
    let (sandbox, config) = fixture()?;
    let new_key = sandbox.file("etc/keys/new-index.key", &[0x91; 32], 0o600)?;
    let (secrets, next) = SecretSet::load_for_login_index_start(&config, &new_key)?;
    assert_eq!(secrets.login_index().expose(), &[3; 32]);
    assert!(secrets.login_index_previous().is_none());
    assert_eq!(next.expose(), &[0x91; 32]);
    assert!(secrets.federation_signing().is_some());
    assert!(secrets.sequencer_private().is_some());
    Ok(())
}

#[test]
fn rotation_secret_loading_rejects_every_configured_purpose_and_identity() -> TestResult {
    let (sandbox, config) = fixture()?;
    let mut purposes = vec![
        &config.storage.master_key_file,
        &config.storage.rollback_guard_key_file,
        &config.storage.login_index_key_file,
        &config.storage.backup_signing_private_key_file,
        &config.moderation.audit_signing_private_key_file,
    ];
    purposes.extend(config.federation.signing_private_key_file.as_ref());
    purposes.extend(
        config
            .accounts
            .account_service_hpke_private_key_file
            .as_ref(),
    );
    purposes.extend(config.accounts.opaque_fake_credential_key_file.as_ref());
    purposes.extend(config.accounts.invite_verification_key_file.as_ref());
    purposes.extend(config.e2ee.sequencer_private_key_file.as_ref());
    for path in purposes {
        assert!(SecretSet::load_for_login_index_start(&config, path).is_err());
        let copy = sandbox.file("etc/keys/new-index.key", &fs::read(path)?, 0o600)?;
        let report = SecretSet::load_for_login_index_start(&config, &copy).err();
        assert!(
            report.is_some_and(|report| report.issues().iter().any(|issue| {
                issue.key.field() == "new_login_index_key_file"
                    && issue.error == ConfigError::InvalidValue
            }))
        );
    }
    Ok(())
}

#[test]
fn rotation_secret_loading_checks_previous_keys_and_tls_backing() -> TestResult {
    let (sandbox, mut config) = fixture()?;
    let previous = sandbox.file("etc/keys/previous-index.key", &[0x44; 32], 0o600)?;
    config.storage.login_index_previous_key_file = Some(previous);
    let copied_previous = sandbox.file("etc/keys/new-index.key", &[0x44; 32], 0o600)?;
    assert!(SecretSet::load_for_login_index_start(&config, &copied_previous).is_err());
    let tls = config
        .listeners
        .iter()
        .find_map(|listener| listener.tls.as_ref())
        .ok_or("missing TLS fixture")?;
    fs::write(&tls.private_key_file, [0x45; 32])?;
    let copied_tls = sandbox.file("etc/keys/new-index.key", &[0x45; 32], 0o600)?;
    let report = SecretSet::load_for_login_index_start(&config, &copied_tls).err();
    assert!(
        report.is_some_and(|report| report.issues().iter().any(|issue| {
            issue.key.field() == "new_login_index_key_file"
                && issue.error == ConfigError::InvalidValue
        }))
    );
    Ok(())
}

#[test]
fn rotation_secret_loading_checks_the_access_key_and_opaque_blob_identity() -> TestResult {
    let (sandbox, mut config) = fixture()?;
    let access = sandbox.file("etc/keys/access.key", &[0x46; 32], 0o600)?;
    config.accounts.access_token_key_file = Some(access);
    let proposed = sandbox.file("etc/keys/new-index.key", &[0x46; 32], 0o600)?;
    let report = SecretSet::load_for_login_index_start(&config, &proposed).err();
    assert!(
        report.is_some_and(|report| report.issues().iter().any(|issue| {
            issue.key.field() == "new_login_index_key_file"
                && issue.error == ConfigError::InvalidValue
        }))
    );
    let setup = config
        .accounts
        .opaque_server_setup_file
        .as_ref()
        .ok_or("missing OPAQUE fixture")?;
    assert!(SecretSet::load_for_login_index_start(&config, setup).is_err());
    Ok(())
}

#[test]
fn rotation_secret_loading_applies_file_rules_and_retains_configured_failures() -> TestResult {
    let (sandbox, config) = fixture()?;
    for (size, mode) in [(31, 0o600), (33, 0o600), (32, 0o640)] {
        let path = sandbox.file("etc/keys/new-index.key", &vec![0x91; size], mode)?;
        assert!(SecretSet::load_for_login_index_start(&config, &path).is_err());
    }
    let path = sandbox.file("etc/keys/new-index.key", &[0x91; 32], 0o600)?;
    let link = sandbox.root().join("etc/keys/new-index-link.key");
    symlink(&path, &link)?;
    assert!(SecretSet::load_for_login_index_start(&config, &link).is_err());
    assert!(
        SecretSet::load_for_login_index_start(&config, std::path::Path::new("relative.key"))
            .is_err()
    );
    sandbox.file("etc/keys/rollback-guard.key", &[1; 32], 0o600)?;
    let report = SecretSet::load_for_login_index_start(&config, &path).err();
    assert!(
        report.is_some_and(|report| report.issues().iter().any(|issue| {
            issue.key.field() == "rollback_guard_key_file"
                && issue.error == ConfigError::InvalidValue
        }))
    );
    Ok(())
}
