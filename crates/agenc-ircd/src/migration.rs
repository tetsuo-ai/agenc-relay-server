//! Composition of the closed stopped-daemon migration command.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use agenc_ircd_config::{load_backup_trust_manifest, load_maintenance_config};
use agenc_ircd_runtime::offline::{execute_schema_four_migration, execute_schema_three_migration};
use agenc_ircd_storage::{
    MigrationCommandRequest, RestoreTrustKey, StorageEngineLimits, embedded_storage_qualifications,
    execute_migration_command,
};

use crate::options::{OptionSpec, ParsedOptions};
use crate::{CliFailure, EXIT_USAGE};

pub(crate) const USAGE: &str = "usage: agenc-ircd storage migrate --config <file> --target-schema-generation <2|3|4> --output-state-directory <new-directory> [--resume]";
const SPECS: &[OptionSpec] = &[
    OptionSpec::value("--config"),
    OptionSpec::value("--target-schema-generation"),
    OptionSpec::value("--output-state-directory"),
    OptionSpec::flag("--resume"),
];

struct Options {
    config: PathBuf,
    output: PathBuf,
    resume: bool,
    target_generation: u64,
}

impl Options {
    fn parse(arguments: &[OsString]) -> Result<Self, ()> {
        let mut parsed = ParsedOptions::parse(arguments, SPECS)?;
        let target_generation = match parsed.required_text("--target-schema-generation")?.as_str() {
            "2" => 2,
            "3" => 3,
            "4" => 4,
            _ => return Err(()),
        };
        Ok(Self {
            config: parsed.required_path("--config")?,
            output: parsed.required_path("--output-state-directory")?,
            resume: parsed.flag("--resume"),
            target_generation,
        })
    }
}

pub(crate) fn run(arguments: &[OsString]) -> Result<(), CliFailure> {
    let options = Options::parse(arguments).map_err(|()| CliFailure::usage(USAGE))?;
    execute(options).map_err(|error| {
        CliFailure::command(EXIT_USAGE, format!("storage migrate failed: {error}"))
    })
}

fn execute(options: Options) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_maintenance_config(&options.config)?;
    let trusted_backup_keys = load_backup_trust_manifest(&config.backup_trust_manifest_file)?
        .into_iter()
        .map(|entry| {
            RestoreTrustKey::new(
                entry.key_id,
                entry.ed25519_public_key,
                entry.not_before,
                entry.not_after,
            )
        })
        .collect();
    let request = MigrationCommandRequest {
        network_id: config.network_id,
        server_id: config.server_id,
        source_state_directory: config.state_directory.clone(),
        master_key_file: config.storage_master_key_file.clone(),
        rollback_guard_key_file: config.rollback_guard_key_file.clone(),
        login_index_key_file: config.login_index_key_file.clone(),
        previous_login_index_key_file: config.login_index_previous_key_file.clone(),
        backup_directory: config.backup_directory.clone(),
        backup_signing_key_file: config.backup_signing_private_key_file.clone(),
        trusted_backup_keys,
        created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        target_schema_generation: options.target_generation,
        output_state_directory: options.output,
        resume: options.resume,
        limits: StorageEngineLimits {
            redb_cache_bytes: config.redb_cache_bytes,
            fixed_reserve_bytes: config.fixed_reserve_bytes,
            reserve_percent: config.reserve_percent,
            database_max_bytes: config.database_max_bytes,
            backup_max_bytes: config.backup_max_bytes,
            integrity_checkpoint_manifests: config.integrity_checkpoint_manifests,
        },
    };
    let qualifications = embedded_storage_qualifications()?;
    let receipt = match options.target_generation {
        2 => execute_migration_command(request, &qualifications)?,
        3 => execute_schema_three_migration(request, &config, &qualifications)?,
        4 => execute_schema_four_migration(request, &config, &qualifications)?,
        _ => return Err("unsupported migration target".into()),
    };
    println!(
        "schema generation: {} -> {}; state generation preserved: {}",
        options.target_generation - 1,
        options.target_generation,
        receipt.state_generation
    );
    println!(
        "verified source backup: {}",
        receipt.source_backup.display()
    );
    println!(
        "installed state directory: {}",
        receipt.output_state_directory.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_arguments_accept_only_the_exact_successor_and_closed_options() -> Result<(), ()> {
        let args = |generation: &str| {
            [
                "--config",
                "/config",
                "--target-schema-generation",
                generation,
                "--output-state-directory",
                "/new",
            ]
            .map(OsString::from)
            .to_vec()
        };
        assert!(!Options::parse(&args("2"))?.resume);
        assert_eq!(Options::parse(&args("3"))?.target_generation, 3);
        assert_eq!(Options::parse(&args("4"))?.target_generation, 4);
        for invalid in ["1", "5", "02", "03", "04", "+2", "+3", "+4", "0"] {
            assert!(Options::parse(&args(invalid)).is_err());
        }
        let mut duplicate = args("2");
        duplicate.extend([OsString::from("--config"), OsString::from("/other")]);
        assert!(Options::parse(&duplicate).is_err());
        let mut resume = args("2");
        resume.push(OsString::from("--resume"));
        assert!(Options::parse(&resume)?.resume);
        Ok(())
    }
}
