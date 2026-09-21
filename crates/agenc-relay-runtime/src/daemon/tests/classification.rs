//! Daemon failures keep their class: reload preparation, shutdown phases and
//! startup conversions each print and map to exactly one operator meaning.
#![forbid(unsafe_code)]

use super::*;
use crate::federation::edge::{EdgeRestoreCause, EdgeRestoreRefusal, EdgeRestoreStep};

#[test]
fn only_budget_refusals_prepare_as_a_resource_floor() {
    for error in [
        RuntimeError::BudgetArithmetic,
        RuntimeError::BudgetBelowWorkingSet,
        RuntimeError::MemoryExhausted,
    ] {
        assert_eq!(
            reload_prepare_failure(DaemonError::Runtime(error)),
            ReloadPrepareFailure::ResourceFloor
        );
    }
    for error in [
        DaemonError::Runtime(RuntimeError::InvalidValue),
        DaemonError::Storage(StorageError::LimitExceeded),
        DaemonError::UnsupportedProfile,
        DaemonError::Cryptography(CryptoError::AuthenticationFailed),
    ] {
        assert_eq!(
            reload_prepare_failure(error),
            ReloadPrepareFailure::InvalidConfig
        );
    }
}

#[test]
fn reload_storage_refusals_distinguish_busy_floor_and_unavailable() {
    assert_eq!(
        map_reload_storage_error(StorageError::QueueFull),
        ReloadPrepareFailure::Busy
    );
    assert_eq!(
        map_reload_storage_error(StorageError::LimitExceeded),
        ReloadPrepareFailure::StorageFloor
    );
    for error in [StorageError::Unavailable, StorageError::StaleState] {
        assert_eq!(
            map_reload_storage_error(error),
            ReloadPrepareFailure::Unavailable
        );
    }
}

#[test]
fn admin_lifecycle_failures_name_the_owner_that_refused() {
    assert_eq!(
        map_admin_lifecycle(AdminLifecycleFailure::Writer),
        ShutdownFailure::Writer
    );
    assert_eq!(
        map_admin_lifecycle(AdminLifecycleFailure::Audit),
        ShutdownFailure::Audit
    );
    for failure in [
        AdminLifecycleFailure::Unavailable,
        AdminLifecycleFailure::Busy,
    ] {
        assert_eq!(map_admin_lifecycle(failure), ShutdownFailure::StateCore);
    }
}

#[test]
fn every_shutdown_failure_prints_its_phase_and_closed_owner_label() {
    let owners = [
        (ShutdownFailure::Listener, "listener"),
        (ShutdownFailure::StateCore, "state_core"),
        (ShutdownFailure::Writer, "writer"),
        (ShutdownFailure::Audit, "audit"),
        (ShutdownFailure::Storage, "storage"),
        (ShutdownFailure::Join, "join"),
    ];
    for phase in ShutdownPhase::ALL {
        for (failure, owner) in owners {
            assert_eq!(
                DaemonError::ShutdownFailed(phase, failure).to_string(),
                format!(
                    "daemon shutdown failed: phase={} owner={owner}",
                    phase.label()
                )
            );
        }
        assert_eq!(
            DaemonError::ShutdownPhaseTimeout(phase).to_string(),
            format!(
                "daemon shutdown exceeded its deadline: phase={}",
                phase.label()
            )
        );
    }
    assert_eq!(
        DaemonError::ShutdownTimeout.to_string(),
        "daemon shutdown exceeded its deadline"
    );
}

#[test]
fn input_free_daemon_failures_print_fixed_operator_lines() {
    let lines = [
        (
            DaemonError::UnsupportedProfile,
            "enabled listener or node profile is not available in core-v1",
        ),
        (DaemonError::RuntimeStart, "Tokio runtime startup failed"),
        (DaemonError::TaskFailed, "a supervised daemon owner failed"),
        (
            DaemonError::E2eeCredentials,
            "E2EE sequencer credentials file is invalid or does not match the sequencer key",
        ),
        (
            DaemonError::Cryptography(CryptoError::AuthenticationFailed),
            "cryptographic startup failed: cryptographic authentication failed",
        ),
    ];
    for (error, line) in lines {
        assert_eq!(error.to_string(), line);
        assert_eq!(format!("{error:?}"), line, "Debug must not leak more");
    }
}

#[test]
fn startup_errors_convert_into_the_class_that_names_their_owner() {
    assert!(matches!(
        DaemonError::from(StorageError::StaleState),
        DaemonError::Storage(StorageError::StaleState)
    ));
    assert!(matches!(
        DaemonError::from(RuntimeError::InvalidValue),
        DaemonError::Runtime(RuntimeError::InvalidValue)
    ));
    assert!(matches!(
        DaemonError::from(CryptoError::InvalidEncoding),
        DaemonError::Cryptography(CryptoError::InvalidEncoding)
    ));
    assert!(matches!(
        DaemonError::from(TlsConfigError::ClientAuthMismatch),
        DaemonError::Tls(TlsConfigError::ClientAuthMismatch)
    ));
    assert!(matches!(
        DaemonError::from(ConfigError::HostControl),
        DaemonError::HostControl(ConfigError::HostControl)
    ));
}

#[test]
fn an_edge_restore_refusal_keeps_its_step_cause_and_error() {
    let refusal = EdgeRestoreRefusal {
        step: EdgeRestoreStep::PeerRecord,
        cause: EdgeRestoreCause::CompanionCeiling,
        error: RuntimeError::Storage(StorageError::StaleState),
    };
    let error = DaemonError::from(refusal);
    assert!(matches!(
        error,
        DaemonError::Reconstruction(
            ReconstructionSurface::EdgeFederation(
                EdgeRestoreStep::PeerRecord,
                EdgeRestoreCause::CompanionCeiling
            ),
            RuntimeError::Storage(StorageError::StaleState)
        )
    ));
    let line = error.to_string();
    assert!(line.starts_with("runtime startup failed: edge federation restore at "));
    assert!(line.contains(EdgeRestoreStep::PeerRecord.label()));
    assert!(line.ends_with(
        "refused the recovered state: storage owner failed: \
         storage state is stale or inconsistent"
    ));
}

#[test]
fn a_public_identity_cannot_serve_two_purposes() {
    let mut identities = PublicIdentitySet::default();
    assert!(
        identities
            .insert([1; 32], PublicIdentityPurpose::AuditSigning)
            .is_ok()
    );
    assert!(matches!(
        identities.insert([1; 32], PublicIdentityPurpose::BackupSigning),
        Err(DaemonError::Runtime(RuntimeError::InvalidValue))
    ));
    assert!(matches!(
        identities.insert([1; 32], PublicIdentityPurpose::AuditSigning),
        Err(DaemonError::Runtime(RuntimeError::InvalidValue))
    ));
    assert!(
        identities
            .insert_alias([2; 32], PublicIdentityPurpose::FederationPeer)
            .is_ok()
    );
    assert!(
        identities
            .insert_alias([2; 32], PublicIdentityPurpose::FederationPeer)
            .is_ok()
    );
    assert!(matches!(
        identities.insert_alias([2; 32], PublicIdentityPurpose::AdminOperator),
        Err(DaemonError::Runtime(RuntimeError::InvalidValue))
    ));
}
