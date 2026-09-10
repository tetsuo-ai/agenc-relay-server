//! Ordinary route declarations share the route's private outcome and receipt.
#![forbid(unsafe_code)]
use super::*;
use agenc_ircd_crypto::StorageDigest;
use agenc_ircd_e2ee::ids::conversation_id;
use agenc_ircd_storage::e2ee_records::{RECOVERY_GATE_KIND, recovery_gate_key};
use agenc_ircd_storage::{E2eeRecoveryGate, E2eeRecoveryKind};
use agenc_ircd_types::RecoveryEpoch;

#[path = "recovery_normal_storage.rs"]
mod storage;

fn written_gate(writes: &[Write], id: [u8; 32]) -> TestResult<Option<E2eeRecoveryGate>> {
    let key = recovery_gate_key(&id)?;
    let mut found = None;
    for write in writes {
        if let Some((table, stored_key, bytes)) = write.encoded_record()
            && table == TableId::E2eeState
            && stored_key == &key
        {
            let value = PersistentRecordValue::decode(table, bytes)?;
            assert_eq!(value.record_kind(), RECOVERY_GATE_KIND);
            found = Some(E2eeRecoveryGate::decode(value.body())?);
        }
    }
    Ok(found)
}

#[test]
fn a_live_bound_route_persists_its_normal_recovery_epoch() -> TestResult {
    let mut harness = Harness::new()?;
    let id = harness.bind_channel()?;
    let row = written_gate(&harness.writes, id)?.ok_or("missing live Normal gate")?;
    assert_eq!(row.state(), E2eeRecoveryKind::Normal);
    assert_eq!(row.recovery_epoch(), RecoveryEpoch::from_bytes([92; 16]));
    assert_eq!(row.conversation_id(), StorageDigest::from_bytes(id));
    assert_eq!(
        row.source_rollback_guard_hash(),
        StorageDigest::from_bytes([0; 32])
    );
    assert_eq!(harness.coordinator.state.recovery_gates.get(&id), Some(row));
    let reloaded = harness.reloaded()?;
    assert_eq!(
        reloaded.coordinator.state.recovery_gates.get(&id),
        Some(row)
    );
    Ok(())
}

struct Binding {
    harness: Harness,
    id: [u8; 32],
    parameters: Vec<u8>,
    bytes: Vec<u8>,
}

fn binding() -> TestResult<Binding> {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let mut reserve = INSTANCE.to_vec();
    reserve.push(5);
    reserve.extend_from_slice(b"#room");
    let reserved = ok(harness.run(Op::ReserveChannel, &reserve, None)?)?;
    let ResultBody::Reserved(reservation_id, _) = reserved.result else {
        return Err("reservation".into());
    };
    let id = conversation_id(&NETWORK, &GROUP)?;
    let mut parameters = reservation_id.to_vec();
    parameters.extend_from_slice(&id);
    parameters.extend_from_slice(&[44; 32]);
    let bytes = harness.binding_bytes()?;
    Ok(Binding {
        harness,
        id,
        parameters,
        bytes,
    })
}

#[test]
fn a_prepared_binding_holds_its_normal_gate_until_receipt() -> TestResult {
    let mut fixture = binding()?;
    let outcome = ok(evaluate_request(
        &mut fixture.harness,
        Op::BindGroup,
        &fixture.parameters,
        Some(&fixture.bytes),
    )?)?;
    let row = written_gate(&outcome.writes, fixture.id)?.ok_or("missing prepared Normal gate")?;
    assert_eq!(row.state(), E2eeRecoveryKind::Normal);
    assert!(
        fixture
            .harness
            .coordinator
            .state
            .recovery_gates
            .get(&fixture.id)
            .is_none()
    );
    assert!(
        !fixture
            .harness
            .coordinator
            .state
            .conversations
            .contains_key(&fixture.id)
    );
    drop(outcome);
    assert!(
        fixture
            .harness
            .coordinator
            .state
            .recovery_gates
            .get(&fixture.id)
            .is_none()
    );
    assert!(written_gate(&fixture.harness.writes, fixture.id)?.is_none());
    Ok(())
}

#[test]
fn normal_heads_can_advance_without_rewriting_restore_provenance() -> TestResult {
    let mut harness = Harness::new()?;
    let id = harness.bind_channel()?;
    let original = written_gate(&harness.writes, id)?.ok_or("gate")?;
    submit_candidate(&mut harness, id, 0, 20)?;
    let head = harness.coordinator.state.logs.get(&id).ok_or("log")?.head();
    assert_ne!(
        &head.record_id,
        original.restored_sequencer_head_id().as_bytes()
    );
    assert_eq!(written_gate(&harness.writes, id)?, Some(original));
    assert_eq!(
        harness
            .reloaded()?
            .coordinator
            .state
            .recovery_gates
            .get(&id),
        Some(original)
    );
    Ok(())
}

#[test]
fn a_binding_without_the_daemon_epoch_cannot_create_normal_authority() -> TestResult {
    let mut fixture = binding()?;
    fixture.harness.coordinator.delivery_identity = None;
    let outcome = evaluate_request(
        &mut fixture.harness,
        Op::BindGroup,
        &fixture.parameters,
        Some(&fixture.bytes),
    )?;
    assert_eq!(code(outcome), Some(E2eeReplyCode::RouteInvalid));
    assert!(
        fixture
            .harness
            .coordinator
            .state
            .recovery_gates
            .get(&fixture.id)
            .is_none()
    );
    assert!(written_gate(&fixture.harness.writes, fixture.id)?.is_none());
    Ok(())
}

#[test]
fn normal_gate_memory_follows_the_private_outcome_and_committed_owner() -> TestResult {
    use crate::budget::{BackingReservationPort, MemoryBudget};
    use crate::sync::Arc;
    let mut fixture = binding()?;
    let budget = Arc::new(MemoryBudget::new(4 * 1024 * 1024));
    fixture.harness.backing = BackingReservationPort::new(budget.clone());
    for commit in [false, true] {
        let mut outcome = ok(evaluate_request(
            &mut fixture.harness,
            Op::BindGroup,
            &fixture.parameters,
            Some(&fixture.bytes),
        )?)?;
        assert_eq!(budget.charged(), 8192);
        if commit {
            for effect in outcome.effects.drain(..) {
                effect(&mut fixture.harness.coordinator.state);
            }
        }
        drop(outcome);
        assert_eq!(budget.charged(), if commit { 8192 } else { 0 });
    }
    drop(fixture);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn normal_gate_budget_refusal_keeps_the_route_unbound() -> TestResult {
    use crate::budget::{BackingReservationPort, MemoryBudget};
    use crate::sync::Arc;
    let mut fixture = binding()?;
    let budget = Arc::new(MemoryBudget::new(0));
    fixture.harness.backing = BackingReservationPort::new(budget.clone());
    let outcome = evaluate_request(
        &mut fixture.harness,
        Op::BindGroup,
        &fixture.parameters,
        Some(&fixture.bytes),
    )?;
    assert_eq!(code(outcome), Some(E2eeReplyCode::RateLimited));
    assert!(
        !fixture
            .harness
            .coordinator
            .state
            .conversations
            .contains_key(&fixture.id)
    );
    assert!(
        fixture
            .harness
            .coordinator
            .state
            .recovery_gates
            .get(&fixture.id)
            .is_none()
    );
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn startup_refuses_a_live_route_without_its_committed_declaration() -> TestResult {
    let mut harness = Harness::new()?;
    let id = harness.bind_channel()?;
    let key = recovery_gate_key(&id)?;
    harness.writes.retain(|write| {
        !write
            .encoded_record()
            .is_some_and(|(table, stored, _)| table == TableId::E2eeState && stored == &key)
    });
    assert!(harness.reloaded().is_err());
    Ok(())
}

#[test]
fn an_existing_route_cannot_recreate_a_missing_declaration_during_a_write() -> TestResult {
    let mut harness = Harness::new()?;
    let id = harness.bind_channel()?;
    let before = harness.coordinator.state.logs.get(&id).ok_or("log")?.head();
    let count = harness.writes.len();
    harness.coordinator.state.recovery_gates = Default::default();
    let commit = commit_bytes(&harness, id, 0, 20)?;
    let outcome = evaluate_request(&mut harness, Op::SubmitCandidate, &id, Some(&commit))?;
    assert_eq!(code(outcome), Some(E2eeReplyCode::RouteInvalid));
    assert_eq!(
        harness.coordinator.state.logs.get(&id).ok_or("log")?.head(),
        before
    );
    assert_eq!(harness.writes.len(), count);
    assert!(harness.coordinator.state.recovery_gates.get(&id).is_none());
    Ok(())
}
