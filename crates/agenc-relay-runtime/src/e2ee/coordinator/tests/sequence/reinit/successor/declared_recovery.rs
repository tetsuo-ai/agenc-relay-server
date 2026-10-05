//! A declared recovery owner cannot survive removal of its activation lineage.
#![forbid(unsafe_code)]
use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_crypto::StorageDigest;
use agenc_relay_storage::e2ee_records::{
    RECOVERY_GATE_KIND, ROUTE_ROW_KIND, RouteRow, recovery_gate_key,
};
use agenc_relay_storage::{E2eeRecoveryGate, E2eeRecoveryKind, PersistentRecordValue, TableId};

#[test]
fn a_declared_successor_gate_refuses_the_loss_of_its_predecessor() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let key = RouteRow::key(&fixture.new)?;
    let mut row = None;
    for write in &fixture.harness.writes {
        if let Some((table, stored_key, bytes)) = write.encoded_record()
            && table == TableId::E2eeState
            && stored_key == &key
        {
            row = Some(RouteRow::decode(
                PersistentRecordValue::decode(table, bytes)?.body(),
            )?);
        }
    }
    let mut row = row.ok_or("successor row")?;
    row.recovery_gate = true;
    let gate = E2eeRecoveryGate::new(
        StorageDigest::from_bytes(fixture.new),
        E2eeRecoveryKind::Pending,
        agenc_relay_types::RecoveryEpoch::from_bytes([92; 16]),
        StorageDigest::from_bytes(row.binding_id),
        StorageDigest::from_bytes(row.accepted_state_id),
        StorageDigest::from_bytes(row.sequencer_head_id),
        StorageDigest::from_bytes([201; 32]),
    );
    for (key, kind, body) in [
        (key, ROUTE_ROW_KIND, row.encode()?),
        (
            recovery_gate_key(&fixture.new)?,
            RECOVERY_GATE_KIND,
            gate.encode()?,
        ),
    ] {
        let value =
            PersistentRecordValue::new(TableId::E2eeState, kind, 1, 0, None, Vec::new(), body)?;
        fixture
            .harness
            .writes
            .push(Write::put(TableId::E2eeState, key, value.encode()?)?);
    }
    let normal = fixture.harness.reloaded()?;
    assert_eq!(
        normal.coordinator.state.recovery_gates.get(&fixture.new),
        Some(gate)
    );
    // The pending successor's recovery lineage resumes at its activation
    // anchor, while the migrated predecessor, whose head is the ReInit
    // activation, resumes nothing (companion 13.7.4 and 13.8).
    let lineage =
        crate::e2ee::coordinator::recovery_lineage::resume(&normal.coordinator, &fixture.new);
    assert!(lineage.is_ok());
    assert!(matches!(
        crate::e2ee::coordinator::recovery_lineage::resume(&normal.coordinator, &fixture.old),
        Err(E2eeReplyCode::RouteInvalid)
    ));
    assert!(
        normal
            .coordinator
            .state
            .routes
            .route(&ConversationId(fixture.new))
            .is_some()
    );
    let old_key = RouteRow::key(&fixture.old)?;
    fixture.harness.writes.retain(|write| {
        !write
            .encoded_record()
            .is_some_and(|(table, key, _)| table == TableId::E2eeState && key == &old_key)
    });
    assert!(
        fixture.harness.reloaded().is_err(),
        "declared recovery was installed before its route was discarded"
    );
    Ok(())
}
