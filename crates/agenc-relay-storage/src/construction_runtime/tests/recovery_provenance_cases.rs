//! Refused source substitutions and bounded plan index behavior.
#![forbid(unsafe_code)]
use super::*;

#[test]
fn restore_provenance_resets_pending_sources_when_reusing_a_scratch_database()
-> Result<(), StorageError> {
    let (file, path) = scratch_file("cap73-provenance-reuse")?;
    let result = (|| {
        let route = route_row(CONVERSATION, RouteLifecycle::Active)?;
        let gate = gate_source(&route, E2eeRecoveryKind::Normal)?;
        let admission = scratch_admission(&file)?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            maximum_limits(),
            admission,
        )?;
        crate::construction_runtime::recovery_plan::push(
            &mut builder,
            &backup_source(TableId::E2eeState, &gate.key, 1)?,
            &recovery_record(&gate)?,
        )?;
        // Preserve a published but unfinished scratch index as if an earlier process
        // stopped after its slice was published.
        builder.publish_slice()?;
        drop(builder);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(crate::filesystem_rejected)?;
        let admission = scratch_admission(&file)?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            maximum_limits(),
            admission,
        )?;
        assert_eq!(
            crate::construction_runtime::recovery_plan::pending_bytes(builder.slice()?)?,
            0
        );
        builder.push(restore_entry(
            TableId::LoginIndexKeyState,
            StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            StorageConstructionAction::RestoreCopy,
        )?)?;
        let plan = builder.finish()?;
        assert_eq!(plan.entry_count(), 1);
        Ok(())
    })();
    std::fs::remove_file(path).map_err(crate::filesystem_rejected)?;
    result
}

#[test]
fn restore_provenance_rejects_each_changed_pending_head_and_a_cleared_route_guard()
-> Result<(), StorageError> {
    for fault in 0..4 {
        let mut route = route_row(CONVERSATION, RouteLifecycle::Active)?;
        route.recovery_gate = true;
        let mut declared = route.clone();
        match fault {
            0 => declared.binding_id = [81; 32],
            1 => declared.accepted_state_id = [82; 32],
            2 => declared.sequencer_head_id = [83; 32],
            _ => route.recovery_gate = false,
        }
        let rows = [
            gate_source(&declared, E2eeRecoveryKind::Pending)?,
            route_source(&route)?,
        ];
        let entries = plan_rows(&rows)?;
        assert!(restored_gate(&rows, &entries).is_err());
    }
    Ok(())
}

#[test]
fn restore_provenance_retains_a_conflict_and_refuses_a_normal_route_under_it()
-> Result<(), StorageError> {
    let mut route = route_row(CONVERSATION, RouteLifecycle::Active)?;
    route.recovery_gate = true;
    let mut original = route.clone();
    original.accepted_state_id = [82; 32];
    let rows = [
        gate_source(&original, E2eeRecoveryKind::Conflict)?,
        route_source(&route)?,
    ];
    let entries = plan_rows(&rows)?;
    assert_eq!(restored_gate(&rows, &entries)?.encode()?, rows[0].body);
    route.recovery_gate = false;
    let rows = [
        gate_source(&original, E2eeRecoveryKind::Conflict)?,
        route_source(&route)?,
    ];
    let entries = plan_rows(&rows)?;
    assert!(restored_gate(&rows, &entries).is_err());
    Ok(())
}

#[test]
fn restore_provenance_refuses_a_terminal_source_without_its_declaration() -> Result<(), StorageError>
{
    let route = route_row(CONVERSATION, RouteLifecycle::Tombstone)?;
    assert!(plan_rows(&[route_source(&route)?]).is_err());
    Ok(())
}

#[test]
fn restore_provenance_refuses_standalone_gate_transforms_in_every_state() -> Result<(), StorageError>
{
    for state in [
        E2eeRecoveryKind::Normal,
        E2eeRecoveryKind::Pending,
        E2eeRecoveryKind::Closed,
        E2eeRecoveryKind::Conflict,
    ] {
        let route = route_row(CONVERSATION, RouteLifecycle::Active)?;
        let row = gate_source(&route, state)?;
        let entry = restore_entry(
            TableId::E2eeState,
            StoredKey::new(row.key.as_bytes().to_vec())?,
            StorageConstructionAction::RestoreE2eeState,
        )?;
        let result = RecoveryTransformV1::new(
            RecoveryEpoch::from_bytes([231; 16]),
            StorageDigest::from_bytes([232; 32]),
        )
        .transform(
            StorageConstructionKind::Restore,
            &entry,
            &[recovery_record(&row)?],
        );
        assert!(result.is_err());
    }
    Ok(())
}

#[test]
fn restore_provenance_charges_pending_sources_and_output_entries_together()
-> Result<(), StorageError> {
    let route = route_row(CONVERSATION, RouteLifecycle::Active)?;
    let gate = gate_source(&route, E2eeRecoveryKind::Normal)?;
    let entry = restore_entry(
        TableId::Account,
        account_key(7)?,
        StorageConstructionAction::RestoreAccount,
    )?;
    let limit = u64::try_from(entry.encode()?.len()).map_err(|_| StorageError::Overflow)? + 127;
    let (file, path) = scratch_file("cap73-provenance-budget")?;
    let result = (|| {
        let admission = scratch_admission(&file)?;
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            ConstructionLimits {
                plan_bytes: limit,
                ..maximum_limits()
            },
            admission,
        )?;
        assert!(crate::construction_runtime::recovery_plan::push(
            &mut builder,
            &backup_source(TableId::E2eeState, &gate.key, 1)?,
            &recovery_record(&gate)?
        )?);
        assert_eq!(builder.push(entry), Err(StorageError::LimitExceeded));
        Ok(())
    })();
    std::fs::remove_file(path).map_err(crate::filesystem_rejected)?;
    result
}

#[test]
fn restore_provenance_rejects_duplicate_declared_sources() -> Result<(), StorageError> {
    let route = route_row(CONVERSATION, RouteLifecycle::Active)?;
    let rows = [
        gate_source(&route, E2eeRecoveryKind::Normal)?,
        gate_source(&route, E2eeRecoveryKind::Normal)?,
        route_source(&route)?,
    ];
    assert!(plan_rows(&rows).is_err());
    Ok(())
}

#[test]
fn restore_provenance_rejects_changed_source_descriptors_and_target_identity()
-> Result<(), StorageError> {
    let route = route_row(CONVERSATION, RouteLifecycle::Active)?;
    let rows = [
        gate_source(&route, E2eeRecoveryKind::Normal)?,
        route_source(&route)?,
    ];
    for fault in 0..5 {
        let gate_key = if fault == 0 {
            crate::e2ee_records::recovery_gate_key(&[55; 32])?
        } else {
            StoredKey::new(rows[0].key.as_bytes().to_vec())?
        };
        let sources = vec![
            backup_source(TableId::E2eeState, &rows[0].key, 1)?,
            backup_source(TableId::E2eeState, &rows[1].key, 2)?,
        ];
        let entry = StorageConstructionPlanEntry::new(
            StorageConstructionKind::Restore,
            sources,
            TableId::E2eeState,
            gate_key,
            1,
            StorageConstructionAction::RestoreE2eeState,
            0,
        )?;
        let mut opened = vec![recovery_record(&rows[0])?, recovery_record(&rows[1])?];
        match fault {
            0 => {}
            1 => opened.reverse(),
            2 => {
                opened.pop();
            }
            3 => {
                opened
                    .first_mut()
                    .ok_or(StorageError::StaleState)?
                    .record_schema = 2
            }
            _ => {
                opened.first_mut().ok_or(StorageError::StaleState)?.key =
                    crate::e2ee_records::recovery_gate_key(&[55; 32])?
            }
        }
        let result = RecoveryTransformV1::new(
            RecoveryEpoch::from_bytes([231; 16]),
            StorageDigest::from_bytes([232; 32]),
        )
        .transform(StorageConstructionKind::Restore, &entry, &opened);
        assert!(result.is_err());
    }
    Ok(())
}
