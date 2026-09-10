//! Exclusive stopped-daemon login-index rotation and its signed durable receipt.
#![forbid(unsafe_code)]

mod cleanup;
mod scan;
#[cfg(test)]
mod tests;
mod transaction;

use super::*;
use crate::state_core::timers::DriftMonitor;
use agenc_ircd_admin::{MaintenanceAuditEvent, MaintenanceOperation};
use agenc_ircd_storage::{CommitReceipt, LoginIndexKeyState};

/// Public evidence from one committed and read-back key transition.
pub struct LoginIndexRotationReceipt {
    /// The exact authenticated resulting key mapping and remaining old-entry count.
    pub key_state: LoginIndexKeyState,
    /// The exact storage commit, logical generation and rollback-guard hash.
    pub storage: CommitReceipt,
    /// The signed maintenance append committed atomically with the key mapping.
    pub audit: MaintenanceAuditEvent,
}

/// Closed outcomes distinguish refusal from possible or confirmed persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginIndexRotationError {
    /// Configuration, authenticated state or pre-commit storage admission refused.
    Refused,
    /// A submitted durable operation may have committed.
    Indeterminate,
    /// The rotation committed, but readback or final owner shutdown failed.
    CommittedVerificationFailed,
}

impl fmt::Display for LoginIndexRotationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Refused => "login-index rotation refused",
            Self::Indeterminate => "login-index maintenance outcome is indeterminate; inspect authenticated storage before retrying",
            Self::CommittedVerificationFailed => "login-index rotation committed but final verification failed; inspect authenticated storage before retrying",
        })
    }
}

impl Error for LoginIndexRotationError {}

impl From<StorageError> for LoginIndexRotationError {
    fn from(_: StorageError) -> Self {
        Self::Refused
    }
}

impl From<RuntimeError> for LoginIndexRotationError {
    fn from(_: RuntimeError) -> Self {
        Self::Refused
    }
}

impl From<DaemonError> for LoginIndexRotationError {
    fn from(_: DaemonError) -> Self {
        Self::Refused
    }
}

/// Starts an exact old/new overlap without rewriting entries or configuration.
pub fn execute_login_index_start(
    config_path: &Path,
    new_key_file: &Path,
) -> Result<LoginIndexRotationReceipt, LoginIndexRotationError> {
    execute(config_path, Some(new_key_file))
}

/// Removes previous-key authority only after a complete zero-count scan.
pub fn execute_login_index_finish(
    config_path: &Path,
) -> Result<LoginIndexRotationReceipt, LoginIndexRotationError> {
    execute(config_path, None)
}

fn execute(
    config_path: &Path,
    new_key_file: Option<&Path>,
) -> Result<LoginIndexRotationReceipt, LoginIndexRotationError> {
    let config = load_config(config_path, ValidationDepth::Host)
        .map_err(|_| LoginIndexRotationError::Refused)?;
    harden_process(&config)?;
    let (secrets, new_key) = load_secrets(&config, new_key_file)?;
    check_configuration(&config, &secrets)?;
    let operators = operator_registry(&config)?;
    let clock = SystemMonotonicClock::start();
    let wall = SystemWallClock
        .utc_now()
        .map_err(|_| LoginIndexRotationError::Refused)?;
    let mut drift = DriftMonitor::new(clock.now(), wall);
    let mut live = LiveStorage::open(&config, &secrets, &operators, clock)?;
    let result = rotate(&mut live, &config, new_key.as_ref(), clock, &mut drift);
    let closed = live.owner.shutdown();
    match result {
        Err(error) => Err(error),
        Ok(receipt) => {
            closed.map_err(|_| LoginIndexRotationError::CommittedVerificationFailed)?;
            Ok(receipt)
        }
    }
}

fn load_secrets(
    config: &Config,
    new_key_file: Option<&Path>,
) -> Result<(SecretSet, Option<SecretBytes32>), LoginIndexRotationError> {
    match new_key_file {
        Some(path) => SecretSet::load_for_login_index_start(config, path)
            .map(|(secrets, key)| (secrets, Some(key))),
        None => SecretSet::load(config).map(|secrets| (secrets, None)),
    }
    .map_err(|_| LoginIndexRotationError::Refused)
}

fn rotate(
    live: &mut LiveStorage,
    config: &Config,
    new_key: Option<&SecretBytes32>,
    clock: SystemMonotonicClock,
    drift: &mut DriftMonitor,
) -> Result<LoginIndexRotationReceipt, LoginIndexRotationError> {
    if !live.audit.is_reconciled() {
        return Err(LoginIndexRotationError::Refused);
    }
    cleanup::cleanup_transactions(live, config)?;
    let before = live.reconstruction.account_service.login_index_key_state();
    let new_id = new_key
        .map(|key| LoginIndexKey::from_bytes(*key.expose()).key_id(config.network.network_id));
    let after = scan::scan_login_index(live, before, new_id)?;
    let now = SystemWallClock
        .utc_now()
        .map_err(|_| LoginIndexRotationError::Refused)?;
    let monotonic = clock.now();
    drift.observe(monotonic, Some(now));
    if !drift.accepts_wall(monotonic, now) {
        return Err(LoginIndexRotationError::Refused);
    }
    let operation = if new_id.is_some() {
        MaintenanceOperation::LoginIndexRotateStart
    } else {
        MaintenanceOperation::LoginIndexRotateFinish
    };
    transaction::commit_rotation(live, config, operation, before, after, now.get())
}
