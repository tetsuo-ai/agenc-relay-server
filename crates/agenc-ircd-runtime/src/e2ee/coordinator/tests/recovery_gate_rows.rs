//! Declared recovery provenance must agree with the exact restored route and daemon epoch.
#![forbid(unsafe_code)]
use super::*;
use agenc_ircd_crypto::StorageDigest;
use agenc_ircd_storage::e2ee_records::{RECOVERY_GATE_KIND, recovery_gate_key};
use agenc_ircd_storage::{E2eeRecoveryGate, E2eeRecoveryKind};
use agenc_ircd_types::RecoveryEpoch;

#[path = "recovery_gate_cases.rs"]
mod cases;

#[test]
fn a_matching_declared_pending_gate_keeps_both_recovery_guards_pending() -> TestResult {
    let (source, conversation) = with_gate(None)?;
    let restored = source.reloaded()?;
    let state = &restored.coordinator.state;
    assert_eq!(
        state
            .routes
            .route(&ConversationId(conversation))
            .ok_or("route")?
            .recovery,
        RecoveryState::Pending
    );
    assert_eq!(
        state
            .lifecycles
            .get(&conversation)
            .ok_or("lifecycle")?
            .gate(),
        RecoveryGate::Pending
    );
    Ok(())
}

#[test]
fn a_declared_gate_with_another_restored_binding_refuses_reconstruction() -> TestResult {
    refuses(Some(0))
}

#[test]
fn a_declared_gate_with_another_accepted_state_refuses_reconstruction() -> TestResult {
    refuses(Some(1))
}

#[test]
fn a_declared_gate_with_another_sequencer_head_refuses_reconstruction() -> TestResult {
    refuses(Some(2))
}

#[test]
fn a_declared_gate_from_another_recovery_epoch_refuses_reconstruction() -> TestResult {
    refuses(Some(3))
}

fn refuses(change: Option<usize>) -> TestResult {
    let (source, _) = with_gate(change)?;
    assert!(
        source.reloaded().is_err(),
        "startup discarded contradictory declared recovery provenance"
    );
    Ok(())
}

fn with_gate(change: Option<usize>) -> TestResult<(Harness, [u8; 32])> {
    let (mut source, conversation, _) = finalization_fixture()?;
    // The control already verifies a valid finalization on the normal route.
    let _pending_control = restored_pending(&mut source, conversation)?;
    let key = RouteRow::key(&conversation)?;
    let mut current = None;
    for write in &source.writes {
        if let Some((table, stored_key, encoded)) = write.encoded_record()
            && table == TableId::E2eeState
            && stored_key == &key
        {
            current = Some(RouteRow::decode(
                PersistentRecordValue::decode(table, encoded)?.body(),
            )?);
        }
    }
    let row = current.ok_or("route row")?;
    let mut heads = [row.binding_id, row.accepted_state_id, row.sequencer_head_id];
    let mut epoch = [92; 16];
    if let Some(index) = change {
        if let Some(head) = heads.get_mut(index) {
            head[0] ^= 1;
        } else {
            epoch[0] ^= 1;
        }
    }
    let gate = E2eeRecoveryGate::new(
        StorageDigest::from_bytes(conversation),
        E2eeRecoveryKind::Pending,
        RecoveryEpoch::from_bytes(epoch),
        StorageDigest::from_bytes(heads[0]),
        StorageDigest::from_bytes(heads[1]),
        StorageDigest::from_bytes(heads[2]),
        StorageDigest::from_bytes([201; 32]),
    );
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        RECOVERY_GATE_KIND,
        1,
        0,
        None,
        Vec::new(),
        gate.encode()?,
    )?;
    source.writes.push(Write::put(
        TableId::E2eeState,
        recovery_gate_key(&conversation)?,
        value.encode()?,
    )?);
    Ok((source, conversation))
}
