#![forbid(unsafe_code)]

//! The three sequencer signer key paths load as distinct secrets and refuse
//! shared bytes (architecture 9457, companion 9.2.1).

mod support;

use agenc_relay_config::{Config, ConfigError, PathResolver, SecretSet, ValidationDepth};
use support::{DUAL, Sandbox, append_to_table};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(
    successor: &[u8; 32],
    retired: &[u8; 32],
) -> Result<(Sandbox, Config), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::create()?;
    sandbox.populate_host_layout()?;
    sandbox.file("etc/keys/sequencer-successor.key", successor, 0o600)?;
    sandbox.file("etc/keys/sequencer-retired.key", retired, 0o600)?;
    let text = append_to_table(
        DUAL,
        "e2ee",
        "sequencer_successor_private_key_file = \"/etc/agenc/keys/sequencer-successor.key\"\nsequencer_retired_private_key_file = \"/etc/agenc/keys/sequencer-retired.key\"",
    );
    let resolver = PathResolver::with_base(sandbox.root().join("etc"))?;
    let config = Config::parse_text(&sandbox.localize(&text), &resolver, ValidationDepth::Host)?;
    Ok((sandbox, config))
}

#[test]
fn distinct_signer_keys_load_by_role() -> TestResult {
    let (_sandbox, config) = fixture(&[0x21; 32], &[0x22; 32])?;
    let secrets = SecretSet::load(&config)?;
    assert_eq!(
        secrets.sequencer_private().map(|key| key.expose()),
        Some(&[9; 32])
    );
    assert_eq!(
        secrets
            .sequencer_successor_private()
            .map(|key| key.expose()),
        Some(&[0x21; 32])
    );
    assert_eq!(
        secrets.sequencer_retired_private().map(|key| key.expose()),
        Some(&[0x22; 32])
    );
    Ok(())
}

#[test]
fn signer_keys_sharing_bytes_with_any_other_secret_are_refused() -> TestResult {
    // The successor repeats the active key; the retired key repeats the
    // audit signing key.
    let (_sandbox, config) = fixture(&[9; 32], &[5; 32])?;
    let report = SecretSet::load(&config)
        .err()
        .ok_or("shared bytes must be refused")?;
    for field in [
        "sequencer_successor_private_key_file",
        "sequencer_retired_private_key_file",
    ] {
        assert!(
            report.issues().iter().any(|issue| {
                issue.key.field() == field && issue.error == ConfigError::InvalidValue
            }),
            "{field} must be reported: {report:?}"
        );
    }
    // Two optional signer paths sharing bytes with each other are refused too.
    let (_sandbox, config) = fixture(&[0x23; 32], &[0x23; 32])?;
    let report = SecretSet::load(&config)
        .err()
        .ok_or("shared bytes must be refused")?;
    assert!(report.issues().iter().any(|issue| {
        issue.key.field() == "sequencer_retired_private_key_file"
            && issue.error == ConfigError::InvalidValue
    }));
    Ok(())
}
