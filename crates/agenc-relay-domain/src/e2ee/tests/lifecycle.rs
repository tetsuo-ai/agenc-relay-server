#![forbid(unsafe_code)]

//! The group lifecycle.

use super::*;

fn open_log() -> Result<SequencerLog, Box<dyn std::error::Error>> {
    let mut log = SequencerLog::genesis([1; 32], [2; 32]);
    let position = log.candidate_position(0)?;
    log.record_candidate([3; 32], [4; 32], position)?;
    log.finalize(&[3; 32], [5; 32], 1)?;
    Ok(log)
}

#[test]
fn bootstrap_joins_and_removals_gate_application_traffic() -> Result<(), Box<dyn std::error::Error>>
{
    let log = open_log()?;
    let mut lifecycle = Lifecycle::bootstrap();
    assert!(lifecycle.bootstrap_pending());
    assert_eq!(
        lifecycle.check_application(&log),
        Err(LifecycleError::BootstrapPending)
    );
    assert_eq!(lifecycle.check_candidate(&log), Ok(()));
    lifecycle.add_finalized(1, vec![9; 32], [5; 32], 100)?;
    assert_eq!(
        lifecycle.add_finalized(2, vec![9; 32], [5; 32], 100),
        Err(LifecycleError::JoinPending)
    );
    assert_eq!(
        lifecycle.bootstrap_activated(),
        Err(LifecycleError::JoinPending)
    );
    assert!(!lifecycle.join_overdue(3_699));
    assert!(lifecycle.join_overdue(3_700));
    assert_eq!(
        lifecycle.join_confirmed(2),
        Err(LifecycleError::NoPendingJoin)
    );
    assert!(lifecycle.pending_join().is_some());
    let join = lifecycle.join_confirmed(1)?;
    assert_eq!(join.key_package_ref, vec![9; 32]);
    assert_eq!(
        lifecycle.join_confirmed(1),
        Err(LifecycleError::NoPendingJoin)
    );
    lifecycle.bootstrap_activated()?;
    assert_eq!(
        lifecycle.bootstrap_activated(),
        Err(LifecycleError::GateTransition)
    );
    assert_eq!(lifecycle.check_application(&log), Ok(()));
    lifecycle.removal_requested()?;
    assert!(lifecycle.removal_pending());
    assert_eq!(
        lifecycle.check_application(&log),
        Err(LifecycleError::RemovalPending)
    );
    lifecycle.removal_finalized();
    assert_eq!(lifecycle.check_application(&log), Ok(()));
    lifecycle.add_finalized(2, vec![8; 32], [5; 32], 200)?;
    lifecycle.pending_leaf_removed(2)?;
    assert!(lifecycle.pending_join().is_none());
    let successor = Lifecycle::successor();
    assert!(!successor.bootstrap_pending());
    assert_eq!(successor.check_application(&log), Ok(()));
    assert!(!successor.is_tombstone(&log));
    Ok(())
}

#[test]
fn the_recovery_gate_only_moves_forward() -> Result<(), Box<dyn std::error::Error>> {
    let log = open_log()?;
    let mut lifecycle = Lifecycle::successor();
    assert_eq!(
        lifecycle.resolve_recovery(RecoveryGate::Closed),
        Err(LifecycleError::GateTransition)
    );
    lifecycle.restore_pending()?;
    assert_eq!(lifecycle.gate(), RecoveryGate::Pending);
    assert_eq!(
        lifecycle.restore_pending(),
        Err(LifecycleError::GateTransition)
    );
    assert_eq!(
        lifecycle.check_application(&log),
        Err(LifecycleError::RecoveryPending)
    );
    assert_eq!(
        lifecycle.check_candidate(&log),
        Err(LifecycleError::RecoveryPending)
    );
    assert_eq!(
        lifecycle.check_security_mutation(),
        Err(LifecycleError::RecoveryPending)
    );
    assert_eq!(
        lifecycle.removal_requested(),
        Err(LifecycleError::RecoveryPending)
    );
    assert_eq!(
        lifecycle.add_finalized(1, Vec::new(), [5; 32], 1),
        Err(LifecycleError::RecoveryPending)
    );
    assert_eq!(
        lifecycle.resolve_recovery(RecoveryGate::Normal),
        Err(LifecycleError::GateTransition)
    );
    assert_eq!(
        lifecycle.resolve_recovery(RecoveryGate::Pending),
        Err(LifecycleError::GateTransition)
    );
    assert!(!lifecycle.is_tombstone(&log));
    lifecycle.resolve_recovery(RecoveryGate::Conflict)?;
    assert!(lifecycle.is_tombstone(&log));
    assert_eq!(
        lifecycle.resolve_recovery(RecoveryGate::Closed),
        Err(LifecycleError::GateTransition)
    );
    let restored = Lifecycle::restore(RecoveryGate::Closed, false, true);
    assert!(restored.is_tombstone(&log));
    assert!(restored.removal_pending());
    let mut closed_log = open_log()?;
    closed_log.close([9; 32])?;
    let live = Lifecycle::successor();
    assert!(live.is_tombstone(&closed_log));
    assert_eq!(
        live.check_application(&closed_log),
        Err(LifecycleError::Closed)
    );
    assert_eq!(
        live.check_candidate(&closed_log),
        Err(LifecycleError::Closed)
    );
    assert!(!LifecycleError::Overflow.to_string().is_empty());
    Ok(())
}
