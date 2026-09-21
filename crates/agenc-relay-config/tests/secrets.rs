#![forbid(unsafe_code)]

//! Secret-file rules, host-depth path checks, and the loaded secret set.

mod support;

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use agenc_relay_config::{
    Config, ConfigError, PathResolver, SecretLength, SecretSet, ValidationDepth, ValidationStage,
    open_secret_file, open_secret_file_with_hook,
};
use support::{DUAL, PUBLIC, Sandbox, mutate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn disabled_listener_material_is_not_required_until_enablement() -> TestResult {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let text = format!(
        "{PUBLIC}\n[[listeners.endpoint]]\nname = \"dormant\"\nenabled = false\npurpose = \"client_tls\"\nbind = \"127.0.0.1:6698\"\nmax_connections = 1\ntls_certificate_file = \"/etc/arcd/tls/dormant.crt\"\ntls_private_key_file = \"/etc/arcd/tls/dormant.key\"\n"
    );
    let config = host_config(&sandbox, &text)?;
    let secrets = SecretSet::load(&config)?;
    assert!(
        secrets
            .tls_private_key(&agenc_relay_config::ListenerName::parse("dormant")?)
            .is_none()
    );
    let enabled = mutate(
        &text,
        "name = \"dormant\"\nenabled = false",
        "name = \"dormant\"\nenabled = true",
    );
    assert!(host_config(&sandbox, &enabled).is_err());
    Ok(())
}

#[test]
fn same_class_tls_key_aliases_preserve_cross_purpose_secret_separation() -> TestResult {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let text = mutate(DUAL, "/etc/arcd/tls/onion.key", "/etc/arcd/tls/server.key");
    let config = host_config(&sandbox, &text)?;
    let secrets = SecretSet::load(&config)?;
    let public = agenc_relay_config::ListenerName::parse("public")?;
    let onion = agenc_relay_config::ListenerName::parse("onion")?;
    assert_eq!(
        secrets
            .tls_private_key(&public)
            .ok_or("missing public key")?
            .expose(),
        secrets
            .tls_private_key(&onion)
            .ok_or("missing onion key")?
            .expose()
    );
    // A copied key is the same TLS identity even when the files have distinct inodes.
    sandbox.file("etc/tls/onion.key", &[0x70; 48], 0o600)?;
    let copied = host_config(&sandbox, DUAL)?;
    assert!(SecretSet::load(&copied).is_ok());
    // The loader also enforces separation for callers holding an edited typed config.
    let mut cross_class = config.clone();
    let public_path = cross_class
        .listeners
        .iter()
        .find(|listener| listener.name == public)
        .and_then(|listener| listener.tls.as_ref())
        .ok_or("missing public TLS material")?
        .private_key_file
        .clone();
    cross_class
        .listeners
        .iter_mut()
        .find(|listener| listener.purpose == agenc_relay_config::ListenerPurpose::Federation)
        .and_then(|listener| listener.tls.as_mut())
        .ok_or("missing federation TLS material")?
        .private_key_file = public_path;
    assert!(SecretSet::load(&cross_class).is_err());
    sandbox.file("etc/tls/federation.key", &[0x70; 48], 0o600)?;
    assert!(SecretSet::load(&config).is_err());
    sandbox.file("etc/tls/federation.key", &[0x72; 48], 0o600)?;
    sandbox.file("etc/tls/server.key", &[1; 32], 0o600)?;
    assert!(SecretSet::load(&config).is_err());
    Ok(())
}

#[test]
fn secret_files_must_be_private_regular_and_exactly_sized() -> TestResult {
    let sandbox = Sandbox::create()?;
    let good = sandbox.file("keys/good.key", &[7; 32], 0o600)?;
    let (bytes, identity) = open_secret_file(&good, SecretLength::Exact(32))?;
    assert_eq!(bytes.len(), 32);
    assert!(identity.inode != 0);
    let loose = sandbox.file("keys/loose.key", &[7; 32], 0o640)?;
    assert_eq!(
        open_secret_file(&loose, SecretLength::Exact(32)).err(),
        Some(ConfigError::FileRejected)
    );
    let short = sandbox.file("keys/short.key", &[7; 31], 0o600)?;
    assert_eq!(
        open_secret_file(&short, SecretLength::Exact(32)).err(),
        Some(ConfigError::FileRejected)
    );
    let long = sandbox.file("keys/long.key", &[7; 33], 0o600)?;
    assert_eq!(
        open_secret_file(&long, SecretLength::Exact(32)).err(),
        Some(ConfigError::FileRejected)
    );
    let link = sandbox.root().join("keys/link.key");
    symlink(&good, &link)?;
    assert_eq!(
        open_secret_file(&link, SecretLength::Exact(32)).err(),
        Some(ConfigError::FileRejected)
    );
    let directory = sandbox.dir("keys/dir.key", 0o600)?;
    assert_eq!(
        open_secret_file(&directory, SecretLength::Exact(32)).err(),
        Some(ConfigError::FileRejected)
    );
    assert_eq!(
        open_secret_file(
            std::path::Path::new("relative.key"),
            SecretLength::Exact(32)
        )
        .err(),
        Some(ConfigError::FileRejected)
    );
    let empty = sandbox.file("keys/empty.blob", &[], 0o600)?;
    assert_eq!(
        open_secret_file(&empty, SecretLength::AtMost(64)).err(),
        Some(ConfigError::FileRejected)
    );
    let blob = sandbox.file("keys/blob", &[1; 40], 0o600)?;
    assert_eq!(
        open_secret_file(&blob, SecretLength::AtMost(64))?.0.len(),
        40
    );
    assert_eq!(
        open_secret_file(&blob, SecretLength::AtMost(39)).err(),
        Some(ConfigError::FileRejected)
    );
    Ok(())
}

#[test]
fn a_file_swapped_between_stat_and_open_is_rejected() -> TestResult {
    let sandbox = Sandbox::create()?;
    let path = sandbox.file("keys/swap.key", &[7; 32], 0o600)?;
    let replacement = sandbox.file("keys/other.key", &[8; 32], 0o600)?;
    let swap = || {
        let _ = fs::rename(&replacement, &path);
    };
    assert_eq!(
        open_secret_file_with_hook(&path, SecretLength::Exact(32), swap).err(),
        Some(ConfigError::FileRejected)
    );
    let stable = sandbox.file("keys/stable.key", &[9; 32], 0o600)?;
    assert!(open_secret_file_with_hook(&stable, SecretLength::Exact(32), || {}).is_ok());
    Ok(())
}

fn host_config(sandbox: &Sandbox, golden: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let text = sandbox.localize(golden);
    let resolver = PathResolver::with_base(sandbox.root().join("etc"))?;
    Ok(Config::parse_text(&text, &resolver, ValidationDepth::Host)?)
}

#[test]
fn host_depth_accepts_the_populated_layout_and_loads_every_secret() -> TestResult {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let config = host_config(&sandbox, PUBLIC)?;
    let secrets = SecretSet::load(&config)?;
    assert_eq!(secrets.storage_master().expose(), &[1; 32]);
    assert_eq!(secrets.rollback_guard_root().expose(), &[2; 32]);
    assert_eq!(secrets.login_index().expose(), &[3; 32]);
    assert!(secrets.login_index_previous().is_none());
    assert_eq!(secrets.backup_signing().expose(), &[4; 32]);
    assert_eq!(secrets.audit_signing().expose(), &[5; 32]);
    assert!(secrets.federation_signing().is_none());
    assert!(secrets.access_token().is_none());
    assert_eq!(
        secrets.invitation_verification().map(|key| key.expose()),
        Some(&[0x11; 32])
    );
    assert_eq!(
        secrets
            .account_service_hpke_private()
            .map(|key| key.expose()),
        Some(&[6; 32])
    );
    assert_eq!(
        secrets.opaque_fake_credential().map(|key| key.expose()),
        Some(&[7; 32])
    );
    assert_eq!(
        secrets
            .opaque_server_setup()
            .map(|blob| blob.expose().len()),
        Some(200)
    );
    assert!(secrets.sequencer_private().is_none());
    let name = config
        .listeners
        .first()
        .map(|listener| listener.name.clone());
    assert!(
        name.as_ref()
            .and_then(|name| secrets.tls_private_key(name))
            .is_some()
    );
    let dual = host_config(&sandbox, DUAL)?;
    let secrets = SecretSet::load(&dual)?;
    assert!(secrets.federation_signing().is_some() && secrets.sequencer_private().is_some());
    Ok(())
}

#[test]
fn secret_set_rejects_shared_bytes_and_shared_identities() -> TestResult {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let config = host_config(&sandbox, PUBLIC)?;
    sandbox.file("etc/keys/rollback-guard.key", &[1; 32], 0o600)?;
    let report = SecretSet::load(&config).err();
    assert!(
        report
            .as_ref()
            .is_some_and(|report| report.issues().iter().any(|issue| {
                issue.stage == ValidationStage::KeyParsing
                    && issue.key.field() == "rollback_guard_key_file"
                    && issue.error == ConfigError::InvalidValue
            }))
    );
    sandbox.file("etc/keys/rollback-guard.key", &[2; 32], 0o600)?;
    fs::remove_file(sandbox.root().join("etc/keys/login-index-g1.key"))?;
    fs::hard_link(
        sandbox.root().join("etc/keys/storage-master.key"),
        sandbox.root().join("etc/keys/login-index-g1.key"),
    )?;
    let report = SecretSet::load(&config).err();
    assert!(report.as_ref().is_some_and(|report| {
        report
            .issues()
            .iter()
            .any(|issue| issue.key.field() == "login_index_key_file")
    }));
    fs::remove_file(sandbox.root().join("etc/keys/login-index-g1.key"))?;
    let report = SecretSet::load(&config).err();
    assert!(
        report
            .as_ref()
            .is_some_and(|report| report.issues().iter().any(|issue| {
                issue.key.field() == "login_index_key_file"
                    && issue.error == ConfigError::FileRejected
            }))
    );
    Ok(())
}

#[test]
fn host_depth_reports_directory_permission_and_public_text_problems() -> TestResult {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let text = sandbox.localize(PUBLIC);
    let resolver = PathResolver::with_base(sandbox.root().join("etc"))?;
    let expect = |text: &str, field: &str, error: ConfigError| {
        let report = Config::parse_text(text, &resolver, ValidationDepth::Host).err();
        assert!(
            report
                .as_ref()
                .is_some_and(|report| report.issues().iter().any(|issue| {
                    issue.stage == ValidationStage::PathsAndFileTypes
                        && issue.key.field() == field
                        && issue.error == error
                })),
            "{field}: {report:?}"
        );
    };
    fs::set_permissions(
        sandbox.root().join("data/state"),
        fs::Permissions::from_mode(0o755),
    )?;
    expect(&text, "state_dir", ConfigError::FileRejected);
    fs::set_permissions(
        sandbox.root().join("data/state"),
        fs::Permissions::from_mode(0o700),
    )?;
    fs::set_permissions(
        sandbox.root().join("etc/keys"),
        fs::Permissions::from_mode(0o770),
    )?;
    expect(&text, "master_key_file", ConfigError::FileRejected);
    fs::set_permissions(
        sandbox.root().join("etc/keys"),
        fs::Permissions::from_mode(0o700),
    )?;
    fs::remove_dir_all(sandbox.root().join("backups"))?;
    expect(&text, "backup_dir", ConfigError::FileRejected);
    sandbox.dir("backups", 0o700)?;
    let long_motd = "line\n".repeat(257);
    sandbox.file("etc/motd.txt", long_motd.as_bytes(), 0o644)?;
    let with_motd = text.replace(
        "[privacy]\n",
        &format!(
            "[privacy]\nmotd_file = \"{}/etc/motd.txt\"\n",
            sandbox.root().display()
        ),
    );
    expect(&with_motd, "motd_file", ConfigError::InvalidValue);
    fs::set_permissions(
        sandbox.root().join("etc/trust/backup-trust.toml"),
        fs::Permissions::from_mode(0o666),
    )?;
    expect(
        &text,
        "backup_trust_manifest_file",
        ConfigError::FileRejected,
    );
    fs::set_permissions(
        sandbox.root().join("etc/trust/backup-trust.toml"),
        fs::Permissions::from_mode(0o644),
    )?;
    fs::remove_dir_all(sandbox.root().join("run"))?;
    expect(&text, "bind", ConfigError::FileRejected);
    Ok(())
}

#[test]
fn host_depth_protects_listener_directories_and_tls_material() -> TestResult {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let resolver = PathResolver::with_base(sandbox.root().join("etc"))?;
    let text = sandbox.localize(PUBLIC);

    fs::set_permissions(
        sandbox.root().join("run"),
        fs::Permissions::from_mode(0o755),
    )?;
    let report = Config::parse_text(&text, &resolver, ValidationDepth::Host).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.stage == ValidationStage::PathsAndFileTypes
                && issue.key.field() == "bind"
                && issue.error == ConfigError::FileRejected
        })
    }));

    fs::set_permissions(
        sandbox.root().join("run"),
        fs::Permissions::from_mode(0o750),
    )?;
    sandbox.file("etc/tls/server.ocsp", b"bounded-der-response", 0o644)?;
    let with_ocsp = mutate(
        &text,
        &format!(
            "tls_certificate_file = \"{}/etc/tls/server.crt\"",
            sandbox.root().display()
        ),
        &format!(
            "tls_certificate_file = \"{0}/etc/tls/server.crt\"\n\
             tls_ocsp_staple_file = \"{0}/etc/tls/server.ocsp\"",
            sandbox.root().display()
        ),
    );
    assert!(Config::parse_text(&with_ocsp, &resolver, ValidationDepth::Host).is_ok());

    fs::set_permissions(
        sandbox.root().join("etc/tls/server.ocsp"),
        fs::Permissions::from_mode(0o666),
    )?;
    let report = Config::parse_text(&with_ocsp, &resolver, ValidationDepth::Host).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.stage == ValidationStage::PathsAndFileTypes
                && issue.key.field() == "tls_ocsp_staple_file"
                && issue.error == ConfigError::FileRejected
        })
    }));
    Ok(())
}

#[test]
fn host_depth_rejects_writable_directories_and_symlinked_ancestors() -> TestResult {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let text = sandbox.localize(PUBLIC);
    let resolver = PathResolver::with_base(sandbox.root().join("etc"))?;

    fs::set_permissions(
        sandbox.root().join("data"),
        fs::Permissions::from_mode(0o770),
    )?;
    let report = Config::parse_text(&text, &resolver, ValidationDepth::Host).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.stage == ValidationStage::PathsAndFileTypes
                && issue.key.field() == "data_dir"
                && issue.error == ConfigError::FileRejected
        })
    }));

    fs::set_permissions(
        sandbox.root().join("data"),
        fs::Permissions::from_mode(0o700),
    )?;
    let physical_backup = sandbox.dir("physical-backup/nested", 0o700)?;
    let backup_alias = sandbox.root().join("backup-alias");
    symlink(
        physical_backup
            .parent()
            .ok_or("physical backup has no parent")?,
        &backup_alias,
    )?;
    let aliased = mutate(
        &text,
        &format!("backup_dir = \"{}/backups\"", sandbox.root().display()),
        &format!(
            "backup_dir = \"{}/backup-alias/nested\"",
            sandbox.root().display()
        ),
    );
    let report = Config::parse_text(&aliased, &resolver, ValidationDepth::Host).err();
    assert!(report.as_ref().is_some_and(|report| {
        report.issues().iter().any(|issue| {
            issue.stage == ValidationStage::PathsAndFileTypes
                && issue.key.field() == "backup_dir"
                && issue.error == ConfigError::FileRejected
        })
    }));
    Ok(())
}

#[test]
fn host_depth_rejects_hard_links_and_material_under_protected_roots() -> TestResult {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    let text = sandbox.localize(PUBLIC);
    let resolver = PathResolver::with_base(sandbox.root().join("etc"))?;
    let expect = |document: &str, field: &str, error: ConfigError| {
        let report = Config::parse_text(document, &resolver, ValidationDepth::Host).err();
        assert!(report.as_ref().is_some_and(|report| {
            report.issues().iter().any(|issue| {
                issue.stage == ValidationStage::PathsAndFileTypes
                    && issue.key.field() == field
                    && issue.error == error
            })
        }));
    };

    let master = sandbox.root().join("etc/keys/storage-master.key");
    let master_alias = sandbox.root().join("etc/keys/storage-master-alias.key");
    fs::hard_link(&master, &master_alias)?;
    let hard_linked = mutate(
        &text,
        &format!("master_key_file = \"{}\"", master.display()),
        &format!("master_key_file = \"{}\"", master_alias.display()),
    );
    expect(&hard_linked, "master_key_file", ConfigError::FileRejected);
    fs::remove_file(master_alias)?;

    let backup_trust = sandbox.root().join("backups/backup-trust.toml");
    fs::copy(
        sandbox.root().join("etc/trust/backup-trust.toml"),
        &backup_trust,
    )?;
    fs::set_permissions(&backup_trust, fs::Permissions::from_mode(0o600))?;
    let trust_under_backup = mutate(
        &text,
        &format!(
            "backup_trust_manifest_file = \"{}/etc/trust/backup-trust.toml\"",
            sandbox.root().display()
        ),
        &format!(
            "backup_trust_manifest_file = \"{}\"",
            backup_trust.display()
        ),
    );
    expect(
        &trust_under_backup,
        "backup_trust_manifest_file",
        ConfigError::Topology,
    );

    let certificate = sandbox.root().join("backups/server.crt");
    fs::copy(sandbox.root().join("etc/tls/server.crt"), &certificate)?;
    fs::set_permissions(&certificate, fs::Permissions::from_mode(0o600))?;
    let listener_under_backup = mutate(
        &text,
        &format!(
            "tls_certificate_file = \"{}/etc/tls/server.crt\"",
            sandbox.root().display()
        ),
        &format!("tls_certificate_file = \"{}\"", certificate.display()),
    );
    expect(
        &listener_under_backup,
        "tls_certificate_file",
        ConfigError::Topology,
    );
    Ok(())
}

#[test]
fn secret_files_reject_unprotected_ancestors_and_hard_links() -> TestResult {
    let sandbox = Sandbox::create()?;
    let loose = sandbox.dir("loose", 0o770)?;
    let under_loose = loose.join("key.key");
    fs::write(&under_loose, [7; 32])?;
    fs::set_permissions(&under_loose, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        open_secret_file(&under_loose, SecretLength::Exact(32)).err(),
        Some(ConfigError::FileRejected)
    );

    let linked = sandbox.file("keys/linked.key", &[7; 32], 0o600)?;
    let alias = sandbox.root().join("keys/alias.key");
    fs::hard_link(&linked, &alias)?;
    assert_eq!(
        open_secret_file(&linked, SecretLength::Exact(32)).err(),
        Some(ConfigError::FileRejected)
    );
    assert_eq!(
        open_secret_file(&alias, SecretLength::Exact(32)).err(),
        Some(ConfigError::FileRejected)
    );
    Ok(())
}
