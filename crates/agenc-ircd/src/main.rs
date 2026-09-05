#![forbid(unsafe_code)]

//! AgenC daemon and stopped-daemon command entry point.

mod migration;
mod options;
mod storage_qualify;
mod version;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use agenc_ircd_config::{
    BackupTrustManifestEntry, DisplayLabel, DnsName, InitProfile, MaintenanceStorageConfig,
    SecretSet, SystemHostReader, ValidationDepth, load_backup_trust_manifest, load_config,
    load_maintenance_config, probe_host_controls,
};
use agenc_ircd_runtime::offline::{
    InitMode, InitReceipt, InitRequest, create_account_invite, initialize_node, parse_network_id,
    parse_server_id, render_onboarding, verify_database_header,
};
use agenc_ircd_storage::{
    RestoreCommandReceipt, RestoreCommandRequest, RestoreTrustKey, StorageEngineLimits,
    embedded_storage_qualifications, execute_restore_command,
};
use options::{OptionSpec, ParsedOptions};

const EXIT_USAGE: u8 = 1;
const EXIT_HOST_CONTROL: u8 = 2;
const EXIT_PARTIAL_INIT: u8 = 3;

const USAGE: &str = concat!(
    "usage: agenc-ircd <command> [options]\n",
    "commands:\n",
    "  version [--json]\n",
    "  conformance --json [--release-decision <directory> --trusted-public-key <pem>]\n",
    "  serve --config <file>\n",
    "  check-config --config <file>\n",
    "  init --config <file> --profile <public|onion|dual> [options]\n",
    "  print-onboarding --config <file>\n",
    "  account-invite create --descriptor <file> --signing-key-file <file> --expires-in <seconds>\n",
    "  storage restore --config <file> --backup <file> [restore options]\n",
    "  storage migrate --config <file> --target-schema-generation 2 --output-state-directory <new-directory> [--resume]\n",
    "  storage qualify --state-dir <new-directory> --scratch-dir <new-directory> --unsigned-report <file> --raw-log <file> [--json <file>]",
);
const RESTORE_USAGE: &str = "usage: agenc-ircd storage restore --config <file> --backup <file> \
--source-master-key-file <file> --source-rollback-guard-key-file <file> \
--output-state-directory <new-directory> --target-rollback-guard-key-file <file> \
[--target-master-key-file <file>] [--resume] --declare-recovery-epoch";

struct CliFailure {
    code: u8,
    message: String,
}

impl CliFailure {
    fn usage(message: &str) -> Self {
        Self {
            code: EXIT_USAGE,
            message: message.to_owned(),
        }
    }

    fn command(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("agenc-ircd: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<(), CliFailure> {
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return Err(CliFailure::usage(USAGE));
    };
    if command == "--help" {
        println!("{USAGE}");
        return Ok(());
    }
    let rest = arguments.get(1..).ok_or_else(|| CliFailure::usage(USAGE))?;
    match command {
        "--version" if rest.is_empty() => version::version(rest),
        "version" => version::version(rest),
        "conformance" => version::conformance(rest),
        "serve" => serve(rest),
        "check-config" => check_config(rest),
        "init" => init(rest),
        "print-onboarding" => print_onboarding(rest),
        "account-invite" => account_invite(rest),
        "storage" => storage(rest),
        _ => Err(CliFailure::usage(USAGE)),
    }
}

fn one_config(arguments: &[OsString], usage: &str) -> Result<PathBuf, CliFailure> {
    let mut parsed = ParsedOptions::parse(arguments, &[OptionSpec::value("--config")])
        .map_err(|()| CliFailure::usage(usage))?;
    parsed
        .required_path("--config")
        .map_err(|()| CliFailure::usage(usage))
}

fn serve(arguments: &[OsString]) -> Result<(), CliFailure> {
    let config = one_config(arguments, "usage: agenc-ircd serve --config <file>")?;
    match agenc_ircd_runtime::daemon::serve(&config) {
        Ok(agenc_ircd_runtime::daemon::DaemonExit::Stopped) => Ok(()),
        Ok(agenc_ircd_runtime::daemon::DaemonExit::RestartRequested) => Err(CliFailure::command(
            agenc_ircd_runtime::daemon::RESTART_EXIT_CODE,
            "service restart requested",
        )),
        Err(error) => Err(CliFailure::command(EXIT_USAGE, error.to_string())),
    }
}

fn check_config(arguments: &[OsString]) -> Result<(), CliFailure> {
    let path = one_config(arguments, "usage: agenc-ircd check-config --config <file>")?;
    let config = load_config(&path, ValidationDepth::Host)
        .map_err(|report| CliFailure::command(EXIT_USAGE, report.to_string()))?;
    harden_offline_process();
    let secrets = SecretSet::load(&config)
        .map_err(|report| CliFailure::command(EXIT_USAGE, report.to_string()))?;
    agenc_ircd_runtime::daemon::check_configuration(&config, &secrets)
        .map_err(|error| CliFailure::command(EXIT_USAGE, error.to_string()))?;
    verify_database_header(&config, &secrets)
        .map_err(|error| CliFailure::command(EXIT_USAGE, error.to_string()))?;
    let report = probe_host_controls(&SystemHostReader, config.server.memory_budget_bytes);
    print!("{report}");
    if report.absent().is_empty() {
        Ok(())
    } else {
        Err(CliFailure::command(
            EXIT_HOST_CONTROL,
            "one or more required host controls are absent",
        ))
    }
}

const INIT_SPECS: &[OptionSpec] = &[
    OptionSpec::value("--config"),
    OptionSpec::value("--profile"),
    OptionSpec::value("--network-id"),
    OptionSpec::value("--coordinator-descriptor"),
    OptionSpec::value("--coordinator-server-id"),
    OptionSpec::value("--data-dir"),
    OptionSpec::value("--runtime-dir"),
    OptionSpec::value("--operator-signing-key-file"),
    OptionSpec::value("--server-name"),
    OptionSpec::value("--display-name"),
    OptionSpec::value("--dns-name"),
];

fn init(arguments: &[OsString]) -> Result<(), CliFailure> {
    let usage = "usage: agenc-ircd init --config <file> --profile <public|onion|dual> [options]";
    let mut parsed =
        ParsedOptions::parse(arguments, INIT_SPECS).map_err(|()| CliFailure::usage(usage))?;
    let request = init_request(&mut parsed).map_err(|()| CliFailure::usage(usage))?;
    match initialize_node(request) {
        Ok(receipt) => {
            print_init_receipt(&receipt);
            Ok(())
        }
        Err(error) => {
            let code = if error.is_partial_initialization() {
                EXIT_PARTIAL_INIT
            } else {
                EXIT_USAGE
            };
            Err(CliFailure::command(code, error.to_string()))
        }
    }
}

fn init_request(parsed: &mut ParsedOptions) -> Result<InitRequest, ()> {
    let config_path = parsed.required_path("--config")?;
    let profile = InitProfile::parse(&parsed.required_text("--profile")?).map_err(|_| ())?;
    let network_id = parsed
        .optional_text("--network-id")?
        .map(|value| parse_network_id(&value).map_err(|_| ()))
        .transpose()?;
    let coordinator_descriptor = parsed.optional_path("--coordinator-descriptor");
    let coordinator_server_id = parsed
        .optional_text("--coordinator-server-id")?
        .map(|value| parse_server_id(&value).map_err(|_| ()))
        .transpose()?;
    let mode = match (network_id, coordinator_descriptor, coordinator_server_id) {
        (network_id, None, None) => InitMode::Coordinator { network_id },
        (None, Some(coordinator_descriptor), Some(coordinator_server_id)) => InitMode::Edge {
            coordinator_descriptor,
            coordinator_server_id,
        },
        _ => return Err(()),
    };
    let data_dir = parsed
        .optional_path("--data-dir")
        .unwrap_or_else(|| PathBuf::from("/var/lib/agenc-ircd"));
    let runtime_dir = parsed
        .optional_path("--runtime-dir")
        .unwrap_or_else(|| PathBuf::from("/run/agenc-ircd"));
    let operator_signing_key_file = parsed
        .optional_path("--operator-signing-key-file")
        .unwrap_or_else(|| PathBuf::from("/var/lib/agenc-ircd-operator/operator-signing.key"));
    let server_name = DnsName::parse(
        &parsed
            .optional_text("--server-name")?
            .unwrap_or_else(|| "chat.local".to_owned()),
    )
    .map_err(|_| ())?;
    let display_name = DisplayLabel::parse(
        &parsed
            .optional_text("--display-name")?
            .unwrap_or_else(|| "AgenC".to_owned()),
    )
    .map_err(|_| ())?;
    let dns_name = init_dns_name(parsed, profile, &server_name)?;
    Ok(InitRequest {
        config_path,
        profile,
        mode,
        data_dir,
        runtime_dir,
        operator_signing_key_file,
        server_name,
        display_name,
        dns_name,
    })
}

fn init_dns_name(
    parsed: &mut ParsedOptions,
    profile: InitProfile,
    server_name: &DnsName,
) -> Result<Option<DnsName>, ()> {
    let configured = parsed
        .optional_text("--dns-name")?
        .map(|value| DnsName::parse(&value).map_err(|_| ()))
        .transpose()?;
    Ok(match (profile, configured) {
        (InitProfile::Onion, None) => None,
        (_, Some(name)) => Some(name),
        _ => Some(server_name.clone()),
    })
}

fn print_init_receipt(receipt: &InitReceipt) {
    println!("network-id={}", receipt.network_id.to_base64url());
    println!("server-id={}", receipt.server_id.to_base64url());
    println!("operator-id={}", receipt.operator_id.to_base64url());
    println!(
        "operator-signing-key-file={}",
        receipt.operator_signing_key_file.display()
    );
    print!("{}", receipt.tor_snippet);
    print!("{}", receipt.systemd_snippet);
    print!("{}", receipt.certificate_instructions);
}

fn print_onboarding(arguments: &[OsString]) -> Result<(), CliFailure> {
    let path = one_config(
        arguments,
        "usage: agenc-ircd print-onboarding --config <file>",
    )?;
    harden_offline_process();
    let descriptor = render_onboarding(&path)
        .map_err(|error| CliFailure::command(EXIT_USAGE, error.to_string()))?;
    print!("{descriptor}");
    Ok(())
}

/// Disables core dumps and locks memory before an offline command reads
/// secret material; a failed lock is not fatal offline, but the process
/// never stays dumpable with keys in memory.
fn harden_offline_process() {
    let _outcome = agenc_ircd_config::apply_process_hardening(false);
}

fn account_invite(arguments: &[OsString]) -> Result<(), CliFailure> {
    harden_offline_process();
    let usage = "usage: agenc-ircd account-invite create --descriptor <file> --signing-key-file <file> --expires-in <seconds>";
    if arguments.first().and_then(|value| value.to_str()) != Some("create") {
        return Err(CliFailure::usage(usage));
    }
    let rest = arguments.get(1..).ok_or_else(|| CliFailure::usage(usage))?;
    let specs = [
        OptionSpec::value("--descriptor"),
        OptionSpec::value("--signing-key-file"),
        OptionSpec::value("--expires-in"),
    ];
    let mut parsed = ParsedOptions::parse(rest, &specs).map_err(|()| CliFailure::usage(usage))?;
    let descriptor = parsed
        .required_path("--descriptor")
        .map_err(|()| CliFailure::usage(usage))?;
    let key = parsed
        .required_path("--signing-key-file")
        .map_err(|()| CliFailure::usage(usage))?;
    let expires = parsed
        .required_text("--expires-in")
        .and_then(|value| value.parse::<u64>().map_err(|_| ()))
        .map_err(|()| CliFailure::usage(usage))?;
    let envelope = create_account_invite(&descriptor, &key, expires)
        .map_err(|error| CliFailure::command(EXIT_USAGE, error.to_string()))?;
    print!("{envelope}");
    Ok(())
}

fn storage(arguments: &[OsString]) -> Result<(), CliFailure> {
    if arguments.first().and_then(|value| value.to_str()) == Some("migrate") {
        return migration::run(
            arguments
                .get(1..)
                .ok_or_else(|| CliFailure::usage(migration::USAGE))?,
        );
    }
    if arguments.first().and_then(|value| value.to_str()) == Some("qualify") {
        return storage_qualify::run(
            arguments
                .get(1..)
                .ok_or_else(|| CliFailure::usage(storage_qualify::USAGE))?,
        );
    }
    if arguments.first().and_then(|value| value.to_str()) != Some("restore") {
        return Err(CliFailure::usage(RESTORE_USAGE));
    }
    let rest = arguments
        .get(1..)
        .ok_or_else(|| CliFailure::usage(RESTORE_USAGE))?;
    let options = RestoreOptions::parse(rest).map_err(|()| CliFailure::usage(RESTORE_USAGE))?;
    restore(options).map_err(|error| {
        CliFailure::command(EXIT_USAGE, format!("storage restore failed: {error}"))
    })
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

const RESTORE_SPECS: &[OptionSpec] = &[
    OptionSpec::value("--config"),
    OptionSpec::value("--backup"),
    OptionSpec::value("--source-master-key-file"),
    OptionSpec::value("--source-rollback-guard-key-file"),
    OptionSpec::value("--output-state-directory"),
    OptionSpec::value("--target-rollback-guard-key-file"),
    OptionSpec::value("--target-master-key-file"),
    OptionSpec::flag("--resume"),
    OptionSpec::flag("--declare-recovery-epoch"),
];

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
        let mut parsed = ParsedOptions::parse(arguments, RESTORE_SPECS)?;
        if !parsed.flag("--declare-recovery-epoch") {
            return Err(());
        }
        Ok(Self {
            config: parsed.required_path("--config")?,
            backup: parsed.required_path("--backup")?,
            source_master_key_file: parsed.required_path("--source-master-key-file")?,
            source_rollback_guard_key_file: parsed
                .required_path("--source-rollback-guard-key-file")?,
            output_state_directory: parsed.required_path("--output-state-directory")?,
            target_rollback_guard_key_file: parsed
                .required_path("--target-rollback-guard-key-file")?,
            target_master_key_file: parsed.optional_path("--target-master-key-file"),
            resume: parsed.flag("--resume"),
            declare_recovery_epoch: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_ircd_runtime::offline::OfflineError;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn complete_restore_options() -> Vec<OsString> {
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
    fn dispatch_lists_help_and_keeps_serve_closed() {
        assert_eq!(
            run(Vec::new()).err().map(|failure| failure.message),
            Some(USAGE.to_owned())
        );
        assert!(run(arguments(&["--help"])).is_ok());
        assert!(run(arguments(&["serve", "--config", "/config.toml"])).is_err());
        assert!(run(arguments(&["serve", "--config", "--bad"])).is_err());
    }

    #[test]
    fn init_parser_accepts_reordered_options_and_rejects_bad_values() -> Result<(), ()> {
        let mut parsed = ParsedOptions::parse(
            &arguments(&[
                "--display-name",
                "Example",
                "--profile",
                "public",
                "--config",
                "/etc/agenc-ircd/config.toml",
                "--server-name",
                "chat.example",
            ]),
            INIT_SPECS,
        )?;
        let request = init_request(&mut parsed)?;
        assert_eq!(request.profile, InitProfile::Public);
        assert!(request.dns_name.is_some());
        for invalid in [
            arguments(&["init"]),
            arguments(&["init", "--config", "/a"]),
            arguments(&["init", "--config", "/a", "--profile", "bad"]),
        ] {
            assert!(run(invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn init_parser_requires_one_complete_coordinator_or_edge_mode() -> Result<(), ()> {
        const NETWORK_ID: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
        const COORDINATOR_ID: &str = "AgICAgICAgICAgICAgICAg";
        let parse = |specific: &[&str]| {
            let mut values = vec![
                "--config",
                "/etc/agenc-ircd/config.toml",
                "--profile",
                "public",
            ];
            values.extend_from_slice(specific);
            let mut parsed = ParsedOptions::parse(&arguments(&values), INIT_SPECS)?;
            init_request(&mut parsed)
        };

        let coordinator = parse(&["--network-id", NETWORK_ID])?;
        assert!(matches!(
            coordinator.mode,
            InitMode::Coordinator {
                network_id: Some(network_id)
            } if network_id.to_base64url() == NETWORK_ID
        ));
        let edge = parse(&[
            "--coordinator-descriptor",
            "/trusted/connect.txt",
            "--coordinator-server-id",
            COORDINATOR_ID,
        ])?;
        assert!(matches!(
            edge.mode,
            InitMode::Edge {
                coordinator_descriptor,
                coordinator_server_id,
            } if coordinator_descriptor == std::path::Path::new("/trusted/connect.txt")
                && coordinator_server_id.to_base64url() == COORDINATOR_ID
        ));

        for invalid in [
            vec!["--coordinator-descriptor", "/trusted/connect.txt"],
            vec!["--coordinator-server-id", COORDINATOR_ID],
            vec![
                "--network-id",
                NETWORK_ID,
                "--coordinator-descriptor",
                "/trusted/connect.txt",
                "--coordinator-server-id",
                COORDINATOR_ID,
            ],
            vec![
                "--coordinator-descriptor",
                "/trusted/connect.txt",
                "--coordinator-server-id",
                "invalid",
            ],
        ] {
            assert!(parse(&invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn restore_parser_preserves_every_required_acknowledgement() -> Result<(), ()> {
        let options = RestoreOptions::parse(&complete_restore_options())?;
        assert_eq!(options.config, PathBuf::from("/config.toml"));
        assert!(options.resume);
        let mut missing = complete_restore_options();
        missing.pop();
        assert!(RestoreOptions::parse(&missing).is_err());
        Ok(())
    }

    #[test]
    fn invite_dispatch_rejects_missing_and_out_of_range_values() {
        assert!(run(arguments(&["account-invite"])).is_err());
        assert!(
            run(arguments(&[
                "account-invite",
                "create",
                "--descriptor",
                "/missing",
                "--signing-key-file",
                "/missing",
                "--expires-in",
                "0",
            ]))
            .is_err()
        );
    }

    #[test]
    fn offline_error_statuses_distinguish_partial_initialization() {
        let status = |error: OfflineError| {
            if error.is_partial_initialization() {
                EXIT_PARTIAL_INIT
            } else {
                EXIT_USAGE
            }
        };
        assert_eq!(
            status(OfflineError::PartialInitialization),
            EXIT_PARTIAL_INIT
        );
        assert_eq!(status(OfflineError::Indeterminate), EXIT_PARTIAL_INIT);
        assert_eq!(status(OfflineError::ExistingTarget), EXIT_USAGE);
    }
}
