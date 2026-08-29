#![forbid(unsafe_code)]

//! AgenC daemon composition entry point.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use agenc_ircd_config::{
    BackupTrustManifestEntry, MaintenanceStorageConfig, load_backup_trust_manifest,
    load_maintenance_config,
};
use agenc_ircd_storage::{
    RestoreCommandReceipt, RestoreCommandRequest, RestoreTrustKey, StorageEngineLimits,
    embedded_storage_qualifications, execute_restore_command,
};

const DAEMON_UNAVAILABLE_MESSAGE: &str =
    "daemon behavior is unavailable until the Stage 06 runtime is implemented";
const RESTORE_USAGE: &str = "usage: agenc-ircd storage restore --config <file> --backup <file> \
--source-master-key-file <file> --source-rollback-guard-key-file <file> \
--output-state-directory <new-directory> --target-rollback-guard-key-file <file> \
[--target-master-key-file <file>] [--resume] --declare-recovery-epoch";

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("agenc-ircd: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<(), String> {
    let Some(first) = arguments.first().and_then(|value| value.to_str()) else {
        return Err(DAEMON_UNAVAILABLE_MESSAGE.to_owned());
    };
    if first != "storage" {
        return Err(DAEMON_UNAVAILABLE_MESSAGE.to_owned());
    }
    if arguments.get(1).and_then(|value| value.to_str()) != Some("restore") {
        return Err(RESTORE_USAGE.to_owned());
    }
    let option_arguments = arguments.get(2..).ok_or_else(|| RESTORE_USAGE.to_owned())?;
    let options = RestoreOptions::parse(option_arguments).map_err(|()| RESTORE_USAGE.to_owned())?;
    // Storage and configuration errors display fixed, secret-free messages, so the
    // operator sees which stage of the restore refused the command.
    restore(options).map_err(|error| format!("storage restore failed: {error}"))
}

fn restore(options: RestoreOptions) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_maintenance_config(&options.config)?;
    let trusted_backup_keys = restore_trust_keys(load_backup_trust_manifest(
        &config.backup_trust_manifest_file,
    )?);
    let qualifications = embedded_storage_qualifications()?;
    let receipt = execute_restore_command(
        restore_request(options, config, trusted_backup_keys),
        &qualifications,
    )?;
    print_restore_receipt(&receipt);
    Ok(())
}

fn restore_trust_keys(entries: Vec<BackupTrustManifestEntry>) -> Vec<RestoreTrustKey> {
    entries
        .into_iter()
        .map(|entry| {
            RestoreTrustKey::new(
                entry.key_id,
                entry.ed25519_public_key,
                entry.not_before,
                entry.not_after,
            )
        })
        .collect()
}

fn restore_request(
    options: RestoreOptions,
    config: MaintenanceStorageConfig,
    trusted_backup_keys: Vec<RestoreTrustKey>,
) -> RestoreCommandRequest {
    RestoreCommandRequest {
        network_id: config.network_id,
        server_id: config.server_id,
        current_state_directory: config.state_directory,
        current_master_key_file: config.storage_master_key_file,
        current_rollback_guard_key_file: config.rollback_guard_key_file,
        backup_path: options.backup,
        source_master_key_file: options.source_master_key_file,
        source_rollback_guard_key_file: options.source_rollback_guard_key_file,
        login_index_key_file: config.login_index_key_file,
        login_index_previous_key_file: config.login_index_previous_key_file,
        output_state_directory: options.output_state_directory,
        target_rollback_guard_key_file: options.target_rollback_guard_key_file,
        target_master_key_file: options.target_master_key_file,
        resume: options.resume,
        declare_recovery_epoch: options.declare_recovery_epoch,
        trusted_backup_keys,
        limits: StorageEngineLimits {
            redb_cache_bytes: config.redb_cache_bytes,
            fixed_reserve_bytes: config.fixed_reserve_bytes,
            reserve_percent: config.reserve_percent,
            database_max_bytes: config.database_max_bytes,
            backup_max_bytes: config.backup_max_bytes,
            integrity_checkpoint_manifests: config.integrity_checkpoint_manifests,
        },
    }
}

fn print_restore_receipt(receipt: &RestoreCommandReceipt) {
    println!(
        "recovery epoch changed: {} -> {}",
        receipt.source_recovery_epoch.to_base64url(),
        receipt.target_recovery_epoch.to_base64url()
    );
    println!(
        "server incarnation changed: {} -> {}",
        receipt.source_server_incarnation.to_base64url(),
        receipt.target_server_incarnation.to_base64url()
    );
    match receipt.current_state_generation {
        Some(current) => println!(
            "state generation: source={}, current={}, target={}",
            receipt.source_state_generation, current, receipt.target_state_generation
        ),
        None => println!(
            "state generation: source={}, current=unknown, target={}",
            receipt.source_state_generation, receipt.target_state_generation
        ),
    }
}

struct RestoreOptions {
    config: PathBuf,
    backup: PathBuf,
    source_master_key_file: PathBuf,
    source_rollback_guard_key_file: PathBuf,
    output_state_directory: PathBuf,
    target_rollback_guard_key_file: PathBuf,
    target_master_key_file: Option<PathBuf>,
    resume: bool,
    declare_recovery_epoch: bool,
}

impl RestoreOptions {
    fn parse(arguments: &[OsString]) -> Result<Self, ()> {
        let mut parser = OptionParser::new(arguments);
        while parser.advance()? {}
        if !parser.declare_recovery_epoch {
            return Err(());
        }
        Ok(Self {
            config: parser.config.ok_or(())?,
            backup: parser.backup.ok_or(())?,
            source_master_key_file: parser.source_master_key_file.ok_or(())?,
            source_rollback_guard_key_file: parser.source_rollback_guard_key_file.ok_or(())?,
            output_state_directory: parser.output_state_directory.ok_or(())?,
            target_rollback_guard_key_file: parser.target_rollback_guard_key_file.ok_or(())?,
            target_master_key_file: parser.target_master_key_file,
            resume: parser.resume,
            declare_recovery_epoch: parser.declare_recovery_epoch,
        })
    }
}

struct OptionParser<'a> {
    arguments: &'a [OsString],
    cursor: usize,
    config: Option<PathBuf>,
    backup: Option<PathBuf>,
    source_master_key_file: Option<PathBuf>,
    source_rollback_guard_key_file: Option<PathBuf>,
    output_state_directory: Option<PathBuf>,
    target_rollback_guard_key_file: Option<PathBuf>,
    target_master_key_file: Option<PathBuf>,
    resume: bool,
    declare_recovery_epoch: bool,
}

impl<'a> OptionParser<'a> {
    const fn new(arguments: &'a [OsString]) -> Self {
        Self {
            arguments,
            cursor: 0,
            config: None,
            backup: None,
            source_master_key_file: None,
            source_rollback_guard_key_file: None,
            output_state_directory: None,
            target_rollback_guard_key_file: None,
            target_master_key_file: None,
            resume: false,
            declare_recovery_epoch: false,
        }
    }

    fn advance(&mut self) -> Result<bool, ()> {
        let Some(value) = self.arguments.get(self.cursor) else {
            return Ok(false);
        };
        let option = value.to_str().ok_or(())?;
        self.cursor = self.cursor.checked_add(1).ok_or(())?;
        match option {
            "--config" => {
                let value = self.take_value()?;
                Self::set_path(&mut self.config, value)?;
            }
            "--backup" => {
                let value = self.take_value()?;
                Self::set_path(&mut self.backup, value)?;
            }
            "--source-master-key-file" => {
                let value = self.take_value()?;
                Self::set_path(&mut self.source_master_key_file, value)?;
            }
            "--source-rollback-guard-key-file" => {
                let value = self.take_value()?;
                Self::set_path(&mut self.source_rollback_guard_key_file, value)?;
            }
            "--output-state-directory" => {
                let value = self.take_value()?;
                Self::set_path(&mut self.output_state_directory, value)?;
            }
            "--target-rollback-guard-key-file" => {
                let value = self.take_value()?;
                Self::set_path(&mut self.target_rollback_guard_key_file, value)?;
            }
            "--target-master-key-file" => {
                let value = self.take_value()?;
                Self::set_path(&mut self.target_master_key_file, value)?;
            }
            "--resume" if !self.resume => self.resume = true,
            "--declare-recovery-epoch" if !self.declare_recovery_epoch => {
                self.declare_recovery_epoch = true;
            }
            _ => return Err(()),
        }
        Ok(self.cursor < self.arguments.len())
    }

    fn take_value(&mut self) -> Result<PathBuf, ()> {
        let value = self.arguments.get(self.cursor).ok_or(())?;
        if value.to_str().is_some_and(|text| text.starts_with("--")) {
            return Err(());
        }
        self.cursor = self.cursor.checked_add(1).ok_or(())?;
        Ok(PathBuf::from(value))
    }

    fn set_path(slot: &mut Option<PathBuf>, value: PathBuf) -> Result<(), ()> {
        if slot.is_some() || value.as_os_str().is_empty() {
            return Err(());
        }
        *slot = Some(value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn complete_options() -> Vec<OsString> {
        arguments(&[
            "--config",
            "/config.toml",
            "--backup",
            "/backup.bin",
            "--source-master-key-file",
            "/source-master.key",
            "--source-rollback-guard-key-file",
            "/source-guard.key",
            "--output-state-directory",
            "/restored",
            "--target-rollback-guard-key-file",
            "/target-guard.key",
            "--target-master-key-file",
            "/target-master.key",
            "--resume",
            "--declare-recovery-epoch",
        ])
    }

    #[test]
    fn restore_option_parser_accepts_complete_command_in_any_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let options = RestoreOptions::parse(&complete_options())
            .map_err(|()| "complete restore options were rejected")?;
        assert_eq!(options.config, PathBuf::from("/config.toml"));
        assert_eq!(
            options.target_master_key_file,
            Some(PathBuf::from("/target-master.key"))
        );
        assert!(options.resume);
        assert!(options.declare_recovery_epoch);

        let mut reversed = complete_options();
        reversed.reverse();
        assert!(RestoreOptions::parse(&reversed).is_err());
        Ok(())
    }

    #[test]
    fn restore_option_parser_rejects_missing_duplicate_and_unknown_arguments() {
        assert!(RestoreOptions::parse(&[]).is_err());
        for invalid in [
            arguments(&["--config"]),
            arguments(&["--config", "--backup"]),
            arguments(&["--unknown"]),
            arguments(&["--resume", "--resume"]),
            arguments(&["--declare-recovery-epoch", "--declare-recovery-epoch"]),
            arguments(&["--config", "/a", "--config", "/b"]),
            vec![OsString::from("--config"), OsString::new()],
        ] {
            assert!(RestoreOptions::parse(&invalid).is_err());
        }
        let mut without_acknowledgement = complete_options();
        without_acknowledgement.pop();
        assert!(RestoreOptions::parse(&without_acknowledgement).is_err());
    }

    #[test]
    fn command_dispatch_keeps_daemon_closed_and_restore_usage_exact() {
        assert_eq!(
            run(Vec::new()).err().as_deref(),
            Some(DAEMON_UNAVAILABLE_MESSAGE)
        );
        assert_eq!(
            run(arguments(&["serve"])).err().as_deref(),
            Some(DAEMON_UNAVAILABLE_MESSAGE)
        );
        assert_eq!(
            run(arguments(&["storage"])).err().as_deref(),
            Some(RESTORE_USAGE)
        );
        assert_eq!(
            run(arguments(&["storage", "unknown"])).err().as_deref(),
            Some(RESTORE_USAGE)
        );
        assert_eq!(
            run(arguments(&["storage", "restore"])).err().as_deref(),
            Some(RESTORE_USAGE)
        );
        let mut without_acknowledgement = arguments(&["storage", "restore"]);
        without_acknowledgement.extend(complete_options());
        without_acknowledgement.pop();
        assert_eq!(
            run(without_acknowledgement).err().as_deref(),
            Some(RESTORE_USAGE)
        );
    }

    #[test]
    fn restore_failures_report_the_refusing_stage() {
        let mut command = arguments(&["storage", "restore"]);
        command.extend(complete_options());
        assert_eq!(
            run(command).err().as_deref(),
            Some("storage restore failed: configuration file rejected")
        );
    }
}
