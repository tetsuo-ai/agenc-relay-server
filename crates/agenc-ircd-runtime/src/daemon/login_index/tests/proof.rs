//! The actual driver result and authenticated restart are checked independently.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;

pub(super) fn run(operation: MaintenanceOperation, boundary: StorageFaultBoundary) -> TestResult {
    let fixture = fixture::FaultFixture::new()?;
    let site = match operation {
        MaintenanceOperation::LoginIndexRotateStart => StorageFaultSite::LoginIndexRotationStart,
        MaintenanceOperation::LoginIndexRotateFinish => StorageFaultSite::LoginIndexRotationFinish,
    };
    let faults = StorageFaultInjector::new(StorageFaultCase { site, boundary }, u64::MAX)?;
    let (mut live, before, mut events) = prepare(&fixture, operation, faults.clone())?;
    let after = match operation {
        MaintenanceOperation::LoginIndexRotateStart => {
            before.start_rotation(fixture.new_key_id(), 0)?
        }
        MaintenanceOperation::LoginIndexRotateFinish => before.finish()?,
    };
    let head = live.reconstruction.head;
    let expected = expected_event(&live, &fixture.config, operation, before, after)?;
    faults.arm_after_current(1)?;
    let result =
        transaction::commit_rotation(&mut live, &fixture.config, operation, before, after, 60);
    let error = match boundary {
        StorageFaultBoundary::Before => LoginIndexRotationError::Refused,
        StorageFaultBoundary::After => LoginIndexRotationError::Indeterminate,
    };
    assert_eq!(
        result.err(),
        Some(error),
        "no successful receipt may escape the failed commit"
    );
    faults.verify_fired()?;
    assert_eq!(
        expected_event(&live, &fixture.config, operation, before, after)?,
        expected,
        "the old authority must not accept the unreceived event into its cursor"
    );
    live.owner.shutdown()?;
    let persisted = match boundary {
        StorageFaultBoundary::Before => before,
        StorageFaultBoundary::After => {
            events.push(expected);
            after
        }
    };
    let reopened = fixture.open(persisted, StorageFaultInjector::disabled())?;
    let advancement = u64::from(boundary == StorageFaultBoundary::After);
    assert_eq!(
        reopened.reconstruction.head.state_generation,
        head.state_generation
            .checked_add(advancement)
            .ok_or("generation overflow")?
    );
    // A clean owner shutdown may also checkpoint; it does not advance logical state.
    assert!(
        reopened.reconstruction.head.storage_commit_sequence
            >= head
                .storage_commit_sequence
                .checked_add(advancement)
                .ok_or("commit overflow")?
    );
    verify_records(&reopened, &fixture.config, persisted, &events)?;
    reopened.owner.shutdown()?;
    Ok(())
}

fn prepare(
    fixture: &fixture::FaultFixture,
    operation: MaintenanceOperation,
    faults: StorageFaultInjector,
) -> TestResult<(LiveStorage, LoginIndexKeyState, Vec<MaintenanceAuditEvent>)> {
    let stable = fixture.stable()?;
    let mut live = fixture.open(stable, faults.clone())?;
    if operation == MaintenanceOperation::LoginIndexRotateStart {
        return Ok((live, stable, Vec::new()));
    }
    let transition = stable.start_rotation(fixture.new_key_id(), 0)?;
    let receipt = transaction::commit_rotation(
        &mut live,
        &fixture.config,
        MaintenanceOperation::LoginIndexRotateStart,
        stable,
        transition,
        60,
    )?;
    assert_eq!(receipt.key_state, transition);
    live.owner.shutdown()?;
    let live = fixture.open(transition, faults)?;
    Ok((live, transition, vec![receipt.audit]))
}

fn verify_records(
    live: &LiveStorage,
    config: &Config,
    expected_state: LoginIndexKeyState,
    expected_events: &[MaintenanceAuditEvent],
) -> TestResult {
    let key = StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
    let rows = live
        .owner
        .port()
        .try_read(ReadPlan::exact(TableId::LoginIndexKeyState, key.clone()))?
        .wait()?;
    assert!(!rows.truncated);
    assert_eq!(rows.records.len(), 1);
    let row = rows.records.first().ok_or("missing key state")?;
    let plaintext = live.keys.open(
        TableId::LoginIndexKeyState,
        &key,
        &SealedRecord::decode(&row.sealed_record)?,
    )?;
    assert_eq!(
        LoginIndexKeyState::decode(plaintext.expose_for_storage_codec())?,
        expected_state
    );
    let rows = live
        .owner
        .port()
        .try_read(ReadPlan::range(
            TableId::Audit,
            StoredKey::new(0_u64.to_be_bytes().to_vec())?,
            StoredKey::new(u64::MAX.to_be_bytes().to_vec())?,
            4,
        )?)?
        .wait()?;
    assert!(!rows.truncated);
    assert_eq!(rows.records.len(), expected_events.len());
    let mut cursor = AuditChainCursor::genesis();
    for (row, expected) in rows.records.iter().zip(expected_events) {
        let sequence = expected.tbs().position().audit_sequence();
        assert_eq!(row.key.as_bytes(), &sequence.to_be_bytes());
        let opened = live.keys.open(
            TableId::Audit,
            &row.key,
            &SealedRecord::decode(&row.sealed_record)?,
        )?;
        let value =
            PersistentRecordValue::decode(TableId::Audit, opened.expose_for_storage_codec())?;
        assert_eq!(value.record_kind(), 2);
        assert_eq!(
            value.revision(),
            sequence.checked_add(1).ok_or("revision overflow")?
        );
        assert_eq!(value.generation(), 0);
        assert!(value.expires_at().is_none() && value.references().is_empty());
        assert_eq!(value.body(), expected.encode()?);
        let event = MaintenanceAuditEvent::decode_exact(value.body())?;
        event.verify(
            config.network.network_id,
            config.server.server_id,
            Ed25519SecretKey::from_bytes(AUDIT_KEY).public_key(),
        )?;
        cursor = cursor.advance_event(&AuditEvent::Maintenance(event))?;
    }
    assert_eq!(cursor.next_sequence, u64::try_from(expected_events.len())?);
    Ok(())
}
