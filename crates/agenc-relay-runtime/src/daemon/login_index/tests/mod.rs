//! Real storage faults preserve the stopped driver's distinct outcome classes.
#![forbid(unsafe_code)]
#![cfg(test)]

mod fixture;
mod invitation_restart;
mod proof;
mod stale_start;

use super::*;
use crate::test_support::{
    TEST_STORAGE_LIMITS, TestDirectory, TestResult, signed_test_qualification,
};
use agenc_relay_admin::{AuditChainCursor, AuditEvent, MaintenanceKeyState, MaintenanceTransition};
use agenc_relay_config::{AuditTrustManifestEntry, PathResolver};
use agenc_relay_crypto::{LoginIndexKeyId, audit_signing_key_id};
use agenc_relay_storage::{
    PersistentRecordValue, SealedRecord, StorageFaultBoundary, StorageFaultCase,
    StorageFaultInjector, StorageFaultSite, StoredKey,
};
use agenc_relay_types::{
    DatabaseId, MonotonicTick, RecoveryEpoch, ServerIncarnation, TransactionId, UtcSecond,
};

const MASTER: [u8; 32] = [35; 32];
const GUARD: [u8; 32] = [36; 32];
const OLD_KEY: [u8; 32] = [37; 32];
const NEW_KEY: [u8; 32] = [92; 32];
const AUDIT_KEY: [u8; 32] = [4; 32];

fn key_tuple(state: LoginIndexKeyState) -> TestResult<MaintenanceKeyState> {
    let (generation, key, count) = match state {
        LoginIndexKeyState::Stable { .. } => (0, [0; 32], 0),
        LoginIndexKeyState::Transition {
            previous_generation,
            previous_key_id,
            previous_entry_count,
            ..
        } => (
            previous_generation,
            *previous_key_id.as_bytes(),
            previous_entry_count,
        ),
    };
    Ok(MaintenanceKeyState::new(
        state.current_generation(),
        *state.current_key_id().as_bytes(),
        generation,
        key,
        count,
    )?)
}

fn expected_event(
    live: &LiveStorage,
    config: &Config,
    operation: MaintenanceOperation,
    before: LoginIndexKeyState,
    after: LoginIndexKeyState,
) -> TestResult<MaintenanceAuditEvent> {
    let recovered = live.seed.storage();
    let scope = MaintenanceAuditScope::new(
        config.network.network_id,
        config.server.server_id,
        recovered.database_binding().database_instance_id(),
        recovered.database_binding().server_incarnation(),
        recovered.recovery_epoch(),
    );
    Ok(live
        .audit
        .prepare_maintenance_event(
            scope,
            MaintenanceTransition::new(operation, key_tuple(before)?, key_tuple(after)?)?,
            live.reconstruction.head,
            TransactionId::from_bytes([90; 16]),
            60,
        )?
        .event()
        .clone())
}

#[test]
fn start_before_fault_is_a_definite_refusal_with_no_maintenance_append() -> TestResult {
    proof::run(
        MaintenanceOperation::LoginIndexRotateStart,
        StorageFaultBoundary::Before,
    )
}

#[test]
fn start_after_fault_is_indeterminate_and_reopens_to_the_exact_committed_append() -> TestResult {
    proof::run(
        MaintenanceOperation::LoginIndexRotateStart,
        StorageFaultBoundary::After,
    )
}

#[test]
fn finish_before_fault_is_a_definite_refusal_with_the_original_transition_retained() -> TestResult {
    proof::run(
        MaintenanceOperation::LoginIndexRotateFinish,
        StorageFaultBoundary::Before,
    )
}

#[test]
fn finish_after_fault_is_indeterminate_and_reopens_to_the_exact_finished_mapping() -> TestResult {
    proof::run(
        MaintenanceOperation::LoginIndexRotateFinish,
        StorageFaultBoundary::After,
    )
}
