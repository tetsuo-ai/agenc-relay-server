//! Exact source pairing in the restore planner and transformer. Source records
//! are typed fixtures here; signed backup and composed startup are separate checks.
#![forbid(unsafe_code)]
use super::*;
use crate::{E2eeRecoveryGate, E2eeRecoveryKind};

#[path = "recovery_provenance_cases.rs"]
mod cases;

const CONVERSATION: [u8; 32] = [21; 32];

fn route_source(row: &RouteRow) -> Result<RecoveryRow, StorageError> {
    Ok(RecoveryRow {
        label: "cap73-provenance-route",
        kind: ROUTE_ROW_KIND,
        key: RouteRow::key(&CONVERSATION)?,
        body: row.encode()?,
    })
}

fn gate_source(route: &RouteRow, state: E2eeRecoveryKind) -> Result<RecoveryRow, StorageError> {
    let gate = E2eeRecoveryGate::new(
        StorageDigest::from_bytes(CONVERSATION),
        state,
        RecoveryEpoch::from_bytes([225; 16]),
        StorageDigest::from_bytes(route.binding_id),
        StorageDigest::from_bytes(route.accepted_state_id),
        StorageDigest::from_bytes(route.sequencer_head_id),
        StorageDigest::from_bytes([226; 32]),
    );
    Ok(RecoveryRow {
        label: "cap73-provenance-gate",
        kind: crate::e2ee_records::RECOVERY_GATE_KIND,
        key: crate::e2ee_records::recovery_gate_key(&CONVERSATION)?,
        body: gate.encode()?,
    })
}

fn plan_rows(rows: &[RecoveryRow]) -> Result<Vec<StorageConstructionPlanEntry>, StorageError> {
    let (file, path) = scratch_file("cap73-provenance")?;
    let result = (|| {
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            maximum_limits(),
        )?;
        builder.push(restore_entry(
            TableId::LoginIndexKeyState,
            StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            StorageConstructionAction::RestoreCopy,
        )?)?;
        let master = StorageMasterKey::from_bytes([181; 32]);
        let binding = DatabaseBinding::new(
            NetworkId::from_bytes([182; 32]),
            ServerId::from_bytes([183; 16]),
            ServerIncarnation::from_bytes([184; 16]),
            DatabaseId::from_bytes([185; 16]),
        );
        let context = RekeyContext {
            source_master_key: &master,
            source_binding: binding,
            source_generation: 1,
            target_master_key: &master,
            target_binding: binding,
            target_generation: 1,
        };
        for (index, row) in rows.iter().enumerate() {
            let offset = u64::try_from(index)
                .map_err(|_| StorageError::Overflow)?
                .checked_add(1)
                .ok_or(StorageError::Overflow)?;
            push_restore_record(
                &mut builder,
                backup_source(TableId::E2eeState, &row.key, offset)?,
                &recovery_record(row)?,
                &context,
            )?;
        }
        let plan = builder.finish()?;
        let mut entries = Vec::new();
        for index in 0..plan.entry_count() {
            let entry = plan.entry(index)?.ok_or(StorageError::StaleState)?;
            if entry.target_table() == TableId::E2eeState {
                entries.push(entry);
            }
        }
        Ok(entries)
    })();
    std::fs::remove_file(path).map_err(|_| StorageError::FilesystemRejected)?;
    result
}

fn restored_gate(
    rows: &[RecoveryRow],
    entries: &[StorageConstructionPlanEntry],
) -> Result<E2eeRecoveryGate, StorageError> {
    let key = crate::e2ee_records::recovery_gate_key(&CONVERSATION)?;
    let entry = entries
        .iter()
        .find(|entry| entry.target_key() == &key)
        .ok_or(StorageError::StaleState)?;
    let sources = entry
        .sources()
        .iter()
        .map(|source| {
            recovery_record(
                rows.iter()
                    .find(|row| row.key == *source.key())
                    .ok_or(StorageError::StaleState)?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut transform = RecoveryTransformV1::new(
        RecoveryEpoch::from_bytes([231; 16]),
        StorageDigest::from_bytes([232; 32]),
    );
    let encoded = transform.transform(StorageConstructionKind::Restore, entry, &sources)?;
    let row = PersistentRecordValue::decode(TableId::E2eeState, &encoded)?;
    E2eeRecoveryGate::decode(row.body())
}

fn assert_pending_source(gate: E2eeRecoveryGate, route: &RouteRow) {
    assert_eq!(gate.state(), E2eeRecoveryKind::Pending);
    assert_eq!(gate.recovery_epoch(), RecoveryEpoch::from_bytes([231; 16]));
    assert_eq!(gate.source_rollback_guard_hash().as_bytes(), &[232; 32]);
    assert_eq!(gate.restored_binding_id().as_bytes(), &route.binding_id);
    assert_eq!(
        gate.restored_accepted_state_id().as_bytes(),
        &route.accepted_state_id
    );
    assert_eq!(
        gate.restored_sequencer_head_id().as_bytes(),
        &route.sequencer_head_id
    );
}

#[test]
fn restore_provenance_uses_current_source_heads_when_a_normal_gate_is_older()
-> Result<(), StorageError> {
    let current = route_row(CONVERSATION, RouteLifecycle::Active)?;
    let mut older = current.clone();
    older.binding_id = [81; 32];
    older.accepted_state_id = [82; 32];
    older.sequencer_head_id = [83; 32];
    let rows = [
        gate_source(&older, E2eeRecoveryKind::Normal)?,
        route_source(&current)?,
    ];
    let entries = plan_rows(&rows)?;
    assert_pending_source(restored_gate(&rows, &entries)?, &current);
    Ok(())
}

#[test]
fn restore_provenance_refuses_a_normal_source_without_its_declaration() -> Result<(), StorageError>
{
    let current = route_row(CONVERSATION, RouteLifecycle::Active)?;
    assert!(plan_rows(&[route_source(&current)?]).is_err());
    Ok(())
}

#[test]
fn restore_provenance_preserves_a_matching_pending_declaration() -> Result<(), StorageError> {
    let mut current = route_row(CONVERSATION, RouteLifecycle::Active)?;
    current.recovery_gate = true;
    let rows = [
        gate_source(&current, E2eeRecoveryKind::Pending)?,
        route_source(&current)?,
    ];
    let entries = plan_rows(&rows)?;
    assert_pending_source(restored_gate(&rows, &entries)?, &current);
    Ok(())
}

#[test]
fn restore_provenance_refuses_a_pending_source_without_its_declaration() -> Result<(), StorageError>
{
    let mut current = route_row(CONVERSATION, RouteLifecycle::Active)?;
    current.recovery_gate = true;
    assert!(plan_rows(&[route_source(&current)?]).is_err());
    Ok(())
}

#[test]
fn restore_provenance_rejects_a_declared_gate_without_its_source_route() -> Result<(), StorageError>
{
    let current = route_row(CONVERSATION, RouteLifecycle::Active)?;
    let rows = [gate_source(&current, E2eeRecoveryKind::Pending)?];
    assert!(
        plan_rows(&rows).is_err(),
        "an orphan gate cannot form a restore plan"
    );
    Ok(())
}

#[test]
fn restore_provenance_preserves_closed_source_provenance() -> Result<(), StorageError> {
    let current = route_row(CONVERSATION, RouteLifecycle::Tombstone)?;
    let rows = [
        gate_source(&current, E2eeRecoveryKind::Closed)?,
        route_source(&current)?,
    ];
    let entries = plan_rows(&rows)?;
    assert_eq!(restored_gate(&rows, &entries)?.encode()?, rows[0].body);
    Ok(())
}
