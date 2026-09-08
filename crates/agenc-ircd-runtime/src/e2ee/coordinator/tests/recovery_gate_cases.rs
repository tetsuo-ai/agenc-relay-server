//! Collector failures and retained provenance using a valid signed conversation fixture.
#![forbid(unsafe_code)]
use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::sync::Arc;
use agenc_ircd_storage::StoredKey;

fn declared(source: &Harness) -> TestResult<(StoredKey, PersistentRecordValue)> {
    for write in source.writes.iter().rev() {
        if let Some((table, key, bytes)) = write.encoded_record()
            && table == TableId::E2eeState
        {
            let value = PersistentRecordValue::decode(table, bytes)?;
            if value.record_kind() == RECOVERY_GATE_KIND {
                return Ok((key.clone(), value));
            }
        }
    }
    Err("declared gate missing".into())
}

fn collect(source: &Harness, fresh: &mut Harness, include_gate: bool) -> TestResult {
    for write in &source.writes {
        if let Some((table, key, bytes)) = write.encoded_record() {
            let value = PersistentRecordValue::decode(table, bytes)?;
            if !include_gate
                && table == TableId::E2eeState
                && value.record_kind() == RECOVERY_GATE_KIND
            {
                continue;
            }
            fresh
                .coordinator
                .admit_restored_with_backing(table, key, &value, &fresh.backing);
        }
    }
    Ok(())
}

fn append_gate(
    source: &mut Harness,
    state: E2eeRecoveryKind,
    epoch: [u8; 16],
) -> TestResult<E2eeRecoveryGate> {
    let (key, value) = declared(source)?;
    let previous = E2eeRecoveryGate::decode(value.body())?;
    let next = E2eeRecoveryGate::new(
        previous.conversation_id(),
        state,
        RecoveryEpoch::from_bytes(epoch),
        previous.restored_binding_id(),
        previous.restored_accepted_state_id(),
        previous.restored_sequencer_head_id(),
        previous.source_rollback_guard_hash(),
    );
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        RECOVERY_GATE_KIND,
        1,
        0,
        None,
        Vec::new(),
        next.encode()?,
    )?;
    source
        .writes
        .push(Write::put(TableId::E2eeState, key, value.encode()?)?);
    Ok(next)
}

fn change_route(
    source: &mut Harness,
    conversation: [u8; 32],
    change: impl FnOnce(&mut RouteRow),
) -> TestResult {
    let key = RouteRow::key(&conversation)?;
    let mut row = None;
    for write in &source.writes {
        if let Some((table, stored_key, bytes)) = write.encoded_record()
            && table == TableId::E2eeState
            && stored_key == &key
        {
            row = Some(RouteRow::decode(
                PersistentRecordValue::decode(table, bytes)?.body(),
            )?);
        }
    }
    let mut row = row.ok_or("route")?;
    change(&mut row);
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        ROUTE_ROW_KIND,
        1,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?;
    source
        .writes
        .push(Write::put(TableId::E2eeState, key, value.encode()?)?);
    Ok(())
}

#[test]
fn restored_provenance_and_its_memory_live_until_the_coordinator_is_dropped() -> TestResult {
    let (source, conversation) = with_gate(None)?;
    let (_, value) = declared(&source)?;
    let expected = E2eeRecoveryGate::decode(value.body())?;
    let budget = Arc::new(MemoryBudget::new(512 * 1024 * 1024));
    let mut fresh = Harness::new()?;
    fresh.backing = BackingReservationPort::new(budget.clone());
    collect(&source, &mut fresh, true)?;
    assert_eq!(budget.charged(), 8192);
    fresh
        .coordinator
        .finish_restore_with_backing(fresh.backing.clone())?;
    assert_eq!(
        fresh.coordinator.state.recovery_gates.get(&conversation),
        Some(expected)
    );
    assert_eq!(expected.source_rollback_guard_hash().as_bytes(), &[201; 32]);
    assert!(budget.charged() >= 8192);
    drop(fresh);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn matching_normal_declaration_keeps_the_route_normal() -> TestResult {
    let (mut source, conversation) = with_gate(None)?;
    change_route(&mut source, conversation, |row| row.recovery_gate = false)?;
    let expected = append_gate(&mut source, E2eeRecoveryKind::Normal, [92; 16])?;
    let fresh = source.reloaded()?;
    assert_eq!(
        fresh.coordinator.state.recovery_gates.get(&conversation),
        Some(expected)
    );
    assert_eq!(
        fresh
            .coordinator
            .state
            .routes
            .route(&ConversationId(conversation))
            .ok_or("route")?
            .recovery,
        RecoveryState::Normal
    );
    assert_eq!(
        fresh
            .coordinator
            .state
            .lifecycles
            .get(&conversation)
            .ok_or("lifecycle")?
            .gate(),
        RecoveryGate::Normal
    );
    Ok(())
}

#[test]
fn conflict_declaration_preserves_the_original_epoch_and_both_guards() -> TestResult {
    let (mut source, conversation) = with_gate(None)?;
    let expected = append_gate(&mut source, E2eeRecoveryKind::Conflict, [93; 16])?;
    let fresh = source.reloaded()?;
    assert_eq!(
        fresh.coordinator.state.recovery_gates.get(&conversation),
        Some(expected)
    );
    assert_eq!(
        fresh
            .coordinator
            .state
            .routes
            .route(&ConversationId(conversation))
            .ok_or("route")?
            .recovery,
        RecoveryState::Conflict
    );
    assert_eq!(
        fresh
            .coordinator
            .state
            .lifecycles
            .get(&conversation)
            .ok_or("lifecycle")?
            .gate(),
        RecoveryGate::Conflict
    );
    Ok(())
}

#[test]
fn contradictory_route_boolean_and_missing_local_epoch_refuse_startup() -> TestResult {
    let (mut source, conversation) = with_gate(None)?;
    let mut fresh = Harness::new()?;
    collect(&source, &mut fresh, true)?;
    fresh.coordinator.delivery_identity = None;
    assert!(
        fresh
            .coordinator
            .finish_restore_with_backing(fresh.backing.clone())
            .is_err()
    );
    change_route(&mut source, conversation, |row| row.recovery_gate = false)?;
    assert!(source.reloaded().is_err());
    Ok(())
}

#[test]
fn absent_route_and_unreconstructible_route_refuse_declared_recovery() -> TestResult {
    let (mut source, conversation) = with_gate(None)?;
    change_route(&mut source, conversation, |row| row.route_state = vec![1])?;
    assert!(source.reloaded().is_err());
    let route_key = RouteRow::key(&conversation)?;
    source.writes.retain(|write| {
        !write
            .encoded_record()
            .is_some_and(|(table, key, _)| table == TableId::E2eeState && key == &route_key)
    });
    assert!(source.reloaded().is_err());
    Ok(())
}

#[test]
fn a_wrong_key_or_refused_capture_stays_failed_after_valid_rows_arrive() -> TestResult {
    let (source, _) = with_gate(None)?;
    let (key, value) = declared(&source)?;
    for wrong_key in [false, true] {
        let mut fresh = Harness::new()?;
        if wrong_key {
            fresh.coordinator.admit_restored_with_backing(
                TableId::E2eeState,
                &recovery_gate_key(&[202; 32])?,
                &value,
                &fresh.backing,
            );
        } else {
            let refused = BackingReservationPort::new(Arc::new(MemoryBudget::new(0)));
            fresh.coordinator.admit_restored_with_backing(
                TableId::E2eeState,
                &key,
                &value,
                &refused,
            );
        }
        collect(&source, &mut fresh, true)?;
        assert!(
            fresh
                .coordinator
                .finish_restore_with_backing(fresh.backing.clone())
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn supplying_memory_at_finish_cannot_repair_unbudgeted_gate_capture() -> TestResult {
    let (source, _) = with_gate(None)?;
    let (key, value) = declared(&source)?;
    let mut fresh = Harness::new()?;
    collect(&source, &mut fresh, false)?;
    fresh
        .coordinator
        .admit_restored(TableId::E2eeState, &key, &value);
    assert!(
        fresh
            .coordinator
            .finish_restore_with_backing(fresh.backing.clone())
            .is_err()
    );
    Ok(())
}

#[test]
fn a_gate_after_object_selection_refuses_startup() -> TestResult {
    let (source, _) = with_gate(None)?;
    let (key, value) = declared(&source)?;
    let mut fresh = Harness::new()?;
    for write in &source.writes {
        if let Some((table, key, bytes)) = write.encoded_record()
            && table == TableId::E2eeState
        {
            let value = PersistentRecordValue::decode(table, bytes)?;
            if value.record_kind() != RECOVERY_GATE_KIND {
                fresh
                    .coordinator
                    .admit_restored_with_backing(table, key, &value, &fresh.backing);
            }
        }
    }
    fresh
        .coordinator
        .select_restored_objects(fresh.backing.clone())?;
    fresh
        .coordinator
        .admit_restored_with_backing(TableId::E2eeState, &key, &value, &fresh.backing);
    assert!(
        fresh
            .coordinator
            .finish_restore_with_backing(fresh.backing.clone())
            .is_err()
    );
    Ok(())
}

#[test]
fn a_legacy_pending_route_has_no_invented_source_guard() -> TestResult {
    let (mut source, conversation, _) = finalization_fixture()?;
    let fresh = restored_pending(&mut source, conversation)?;
    assert!(
        fresh
            .coordinator
            .state
            .recovery_gates
            .get(&conversation)
            .is_none()
    );
    assert_eq!(
        fresh
            .coordinator
            .state
            .routes
            .route(&ConversationId(conversation))
            .ok_or("route")?
            .recovery,
        RecoveryState::Pending
    );
    Ok(())
}

#[test]
fn a_normal_declaration_does_not_freeze_the_heads_of_a_live_route() -> TestResult {
    let (mut source, conversation, request) = finalization_fixture()?;
    let mut heads = None;
    change_route(&mut source, conversation, |row| {
        assert!(!row.recovery_gate);
        heads = Some([row.binding_id, row.accepted_state_id, row.sequencer_head_id]);
    })?;
    let [binding, accepted, head] = heads.ok_or("heads")?;
    let gate = E2eeRecoveryGate::new(
        StorageDigest::from_bytes(conversation),
        E2eeRecoveryKind::Normal,
        RecoveryEpoch::from_bytes([92; 16]),
        StorageDigest::from_bytes(binding),
        StorageDigest::from_bytes(accepted),
        StorageDigest::from_bytes(head),
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
    let control = source.reloaded()?;
    assert_eq!(
        control.coordinator.state.recovery_gates.get(&conversation),
        Some(gate)
    );
    let outcome = ok(source.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::Finalized(..)));
    let expected = source
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("live log")?;
    assert_ne!(expected.accepted_state_id(), &accepted);
    let fresh = source.reloaded()?;
    assert_eq!(
        fresh.coordinator.state.logs.get(&conversation),
        Some(expected)
    );
    assert_eq!(
        fresh.coordinator.state.recovery_gates.get(&conversation),
        Some(gate)
    );
    Ok(())
}

#[test]
fn a_normal_declaration_still_requires_the_current_epoch_and_normal_route_flag() -> TestResult {
    for epoch in [[92; 16], [93; 16]] {
        let (mut source, conversation) = with_gate(None)?;
        if epoch == [93; 16] {
            change_route(&mut source, conversation, |row| row.recovery_gate = false)?;
        }
        append_gate(&mut source, E2eeRecoveryKind::Normal, epoch)?;
        assert!(source.reloaded().is_err());
    }
    Ok(())
}
