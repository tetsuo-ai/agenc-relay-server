//! Recovery metadata and lifecycle transitions, independently of signed chain verification.
#![forbid(unsafe_code)]
use super::*;
use crate::budget::MemoryBudget;
use crate::sync::Arc;
use agenc_ircd_crypto::StorageDigest;
use agenc_ircd_storage::TableId;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn gate(kind: E2eeRecoveryKind) -> E2eeRecoveryGate {
    E2eeRecoveryGate::new(
        StorageDigest::from_bytes([1; 32]),
        kind,
        RecoveryEpoch::from_bytes([2; 16]),
        StorageDigest::from_bytes([3; 32]),
        StorageDigest::from_bytes([4; 32]),
        StorageDigest::from_bytes([5; 32]),
        StorageDigest::from_bytes([6; 32]),
    )
}

fn value(row: E2eeRecoveryGate) -> Result<PersistentRecordValue, agenc_ircd_storage::StorageError> {
    PersistentRecordValue::new(
        TableId::E2eeState,
        RECOVERY_GATE_KIND,
        1,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )
}

#[test]
fn retained_gate_owns_its_reservation_through_replacement_and_drop() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(16_384));
    let backing = BackingReservationPort::new(budget.clone());
    let mut gates = Gates::default();
    let key = recovery_gate_key(&[1; 32])?;
    let first = gate(E2eeRecoveryKind::Pending);
    gates.admit(&key, &value(first)?, &backing)?;
    assert_eq!(gates.get(&[1; 32]), Some(first));
    assert_eq!(budget.charged(), 8192);
    let replacement = gate(E2eeRecoveryKind::Conflict);
    gates.admit(&key, &value(replacement)?, &backing)?;
    assert_eq!(gates.get(&[1; 32]), Some(replacement));
    assert_eq!(budget.charged(), 8192);
    let held = backing.reserve(4096)?;
    assert!(gates.admit(&key, &value(first)?, &backing).is_err());
    assert_eq!(gates.get(&[1; 32]), Some(replacement));
    drop(held);
    drop(gates);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn another_conversation_key_is_refused_before_reserving_memory() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(8192));
    let backing = BackingReservationPort::new(budget.clone());
    let mut gates = Gates::default();
    assert!(
        gates
            .admit(
                &recovery_gate_key(&[9; 32])?,
                &value(gate(E2eeRecoveryKind::Pending))?,
                &backing
            )
            .is_err()
    );
    assert_eq!(budget.charged(), 0);
    assert!(gates.get(&[1; 32]).is_none());
    Ok(())
}

#[test]
fn malformed_gate_bodies_are_refused_by_the_storage_wrapper() -> TestResult {
    let bytes = gate(E2eeRecoveryKind::Pending).encode()?;
    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut version = bytes.clone();
    *version.get_mut(1).ok_or("version byte")? = 2;
    let mut state = bytes.clone();
    *state.get_mut(35).ok_or("state byte")? = 255;
    let truncated = bytes.get(..179).ok_or("truncated body")?.to_vec();
    for invalid in [truncated, trailing, version, state] {
        assert!(
            PersistentRecordValue::new(
                TableId::E2eeState,
                RECOVERY_GATE_KIND,
                1,
                0,
                None,
                Vec::new(),
                invalid
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn terminal_metadata_keeps_its_source_epoch_and_requires_a_closed_tombstone() -> TestResult {
    // Only the typed metadata predicate is exercised here. The opaque route bytes
    // do not represent a signed close and are never admitted to reconstruction.
    let mut route = RouteRow {
        route_state: vec![1],
        lifecycle: RouteLifecycle::Tombstone,
        binding_id: [11; 32],
        lock_id: [12; 32],
        accepted_state_id: [13; 32],
        sequencer_head_id: [14; 32],
        route_sequence: 9,
        close_id: Some([15; 32]),
        predecessor_close_id: None,
        recovery_gate: true,
        stored_bytes: 0,
    };
    let closed = gate(E2eeRecoveryKind::Closed);
    let later_epoch = Some(RecoveryEpoch::from_bytes([17; 16]));
    assert!(validate_row(closed, &route, later_epoch).is_ok());
    route.close_id = None;
    assert!(validate_row(closed, &route, later_epoch).is_err());
    route.close_id = Some([15; 32]);
    route.lifecycle = RouteLifecycle::Active;
    assert!(validate_row(closed, &route, later_epoch).is_err());
    assert!(validate_row(gate(E2eeRecoveryKind::Conflict), &route, later_epoch).is_ok());
    Ok(())
}

#[test]
fn every_gate_transition_preserves_join_bootstrap_and_removal_state() -> TestResult {
    let kinds = [
        RecoveryGate::Normal,
        RecoveryGate::Pending,
        RecoveryGate::Closed,
        RecoveryGate::Conflict,
    ];
    for current_gate in kinds {
        let mut current = Lifecycle::restore(RecoveryGate::Normal, true, true);
        current.add_finalized(5, vec![8; 32], [9; 32], 10)?;
        if current_gate != RecoveryGate::Normal {
            current.restore_pending()?;
            if current_gate != RecoveryGate::Pending {
                current.resolve_recovery(current_gate)?;
            }
        }
        for next_gate in kinds {
            let allowed = current_gate == next_gate
                || (current_gate == RecoveryGate::Normal && next_gate != RecoveryGate::Normal)
                || (current_gate == RecoveryGate::Pending
                    && matches!(next_gate, RecoveryGate::Closed | RecoveryGate::Conflict));
            let next = restored_lifecycle(&current, next_gate);
            assert_eq!(next.is_ok(), allowed, "{current_gate:?} -> {next_gate:?}");
            if let Ok(next) = next {
                assert_eq!(next.gate(), next_gate);
                assert_eq!(next.pending_join(), current.pending_join());
                assert_eq!(next.bootstrap_pending(), current.bootstrap_pending());
                assert_eq!(next.removal_pending(), current.removal_pending());
            }
            assert_eq!(current.gate(), current_gate);
        }
    }
    Ok(())
}
