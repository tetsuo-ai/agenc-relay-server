//! Real storage scope isolation and receipt-owned ACK retention metadata.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{Acknowledgement, outbox};

async fn activate_new_incarnation(
    fixture: &mut RestartFixture,
    incarnation: [u8; 16],
) -> TestResult {
    fixture.coordinator.link_closed(home());
    fixture.host.incarnation = Some(incarnation);
    let actions = fixture.frame(CompanionFrame::Resume {
        coordinator_server_id: *fixture.storage.identity.server_id.as_bytes(),
        server_incarnation: incarnation,
        delivery_generation: 0,
        last: None,
    })?;
    let (cut, _, _) = begin_cut(&fixture.publish_cut(actions).await?)?;
    assert_eq!(
        cut.delivery_generation, 0,
        "a new incarnation starts generation zero"
    );
    let actions = fixture.frame(CompanionFrame::StateCut {
        active: false,
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        snapshot_token: cut.token,
        state_generation: cut.state_generation,
        delivery_generation: cut.delivery_generation,
        snapshot_digest: cut.digest,
    })?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("new scope must stage".into());
    };
    fixture.coordinator.set_pending(work);
    fixture.commit(writes).await?;
    assert!(matches!(
        fixture.coordinator.batch_applied(Some(0))?,
        Some(Committed::Lines(_))
    ));
    Ok(())
}

#[tokio::test]
async fn a_new_incarnation_restarts_at_zero_without_rebinding_retained_old_scope_rows() -> TestResult
{
    let mut fixture = RestartFixture::new().await?;
    let old_ids: Vec<_> = fixture
        .copies
        .iter()
        .map(|copy| copy.row.event_id)
        .collect();
    let old_keys: Vec<_> = fixture
        .keys
        .iter()
        .filter(|(_, key)| key.as_bytes().starts_with(outbox::OUTBOX_PREFIX))
        .cloned()
        .collect();
    assert_eq!(old_keys.len(), 2);
    activate_new_incarnation(&mut fixture, [99; 16]).await?;
    fixture.append().await?;
    let new_ids: Vec<_> = fixture
        .copies
        .iter()
        .map(|copy| copy.row.event_id)
        .collect();
    assert_ne!(new_ids, old_ids);
    assert_eq!(
        fixture
            .copies
            .iter()
            .map(|copy| (copy.generation, copy.row.sequence))
            .collect::<Vec<_>>(),
        [(0, 0), (0, 1)]
    );
    assert_eq!(
        fixture
            .keys
            .iter()
            .filter(|(_, key)| key.as_bytes().starts_with(outbox::OUTBOX_PREFIX))
            .count(),
        4
    );
    for key in old_keys {
        assert!(fixture.keys.contains(&key));
    }
    fixture.restart().await?;
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("new scope")?;
    assert_eq!(
        stream
            .owner
            .as_ref()
            .ok_or("owner")?
            .scope()
            .target_incarnation(),
        [99; 16]
    );
    assert_eq!(stream.generation, 0);
    assert_eq!(
        stream
            .rows
            .iter()
            .map(|row| row.event_id)
            .collect::<Vec<_>>(),
        new_ids
    );
    assert_eq!(stream.rows.len(), 2);
    Ok(())
}

fn position(fixture: &RestartFixture, index: usize) -> TestResult<DeliveryPosition> {
    let copy = fixture.copies.get(index).ok_or("event")?;
    Ok(DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: copy.generation,
        delivery_sequence: copy.row.sequence,
        event_id: copy.row.event_id,
    })
}

async fn acknowledge(
    fixture: &mut RestartFixture,
    position: DeliveryPosition,
    at: Option<u64>,
) -> TestResult {
    // This calls the same frame-owner preparation with explicit accepted wall facts.
    let actions = events::on_ack(
        &mut fixture.coordinator,
        LinkId::new(1),
        home(),
        position,
        at,
    )?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("ACK must stage".into());
    };
    fixture.coordinator.set_pending(work);
    fixture.commit(writes).await?;
    assert!(matches!(
        fixture.coordinator.batch_applied(Some(0))?,
        Some(Committed::Acknowledged(_))
    ));
    Ok(())
}

#[tokio::test]
async fn acknowledged_outbox_restart_preserves_first_time_and_unknown_clock_metadata() -> TestResult
{
    let mut fixture = RestartFixture::new().await?;
    let first = position(&fixture, 0)?;
    let second = position(&fixture, 1)?;
    acknowledge(&mut fixture, first, Some(100)).await?;
    assert!(
        events::on_ack(
            &mut fixture.coordinator,
            LinkId::new(1),
            home(),
            first,
            Some(999)
        )?
        .is_empty()
    );
    acknowledge(&mut fixture, second, None).await?;
    fixture.restart().await?;
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("restored stream")?;
    assert_eq!(
        stream
            .rows
            .iter()
            .map(|row| row.acknowledgement)
            .collect::<Vec<_>>(),
        [
            Acknowledgement::AcknowledgedAt {
                received_unix_seconds: 100,
                retain_until_unix_seconds: 86500
            },
            Acknowledgement::AcknowledgedTimeUnknown,
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_refused_ack_does_not_persist_prepared_retention_time() -> TestResult {
    use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::ReplayLedgerRow;
    let mut fixture = RestartFixture::new().await?;
    let first = position(&fixture, 0)?;
    let actions = events::on_ack(
        &mut fixture.coordinator,
        LinkId::new(1),
        home(),
        first,
        Some(100),
    )?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("ACK stage".into());
    };
    let staged_rows = writes.iter().filter_map(|write| match write {
        AccountServiceDurableWrite::Put { table, key, plaintext } => PersistentRecordValue::decode(*table, plaintext)
            .ok().and_then(|value| ReplayLedgerRow::decode_at(key, value.body()).ok()),
        _ => None,
    }).filter(|row| matches!(row, ReplayLedgerRow::Range(row) if row.fields().acknowledgement == Acknowledgement::received_at(Some(100)))).count();
    assert_eq!(staged_rows, 1);
    fixture.coordinator.set_pending(work);
    stage_ack_for_rejection(&mut fixture, writes)?;
    fixture
        .storage
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_ircd_storage::StorageError::QueueFull)?;
    fixture.coordinator.batch_rejected();
    fixture.restart().await?;
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("restored stream")?;
    assert_eq!(stream.acked, None);
    assert!(stream.replay.is_none());
    assert!(
        stream
            .rows
            .iter()
            .all(|row| row.acknowledgement == Acknowledgement::Unacknowledged)
    );
    Ok(())
}

#[tokio::test]
async fn an_unbound_legacy_outbox_is_not_given_the_current_owner_scope_on_restart() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let copy = fixture.copies.first().ok_or("event")?;
    let body = agenc_ircd_storage::e2ee_records::DeliveryRow::Outbox {
        event_id: copy.row.event_id,
        event_object_id: *agenc_ircd_e2ee::ObjectId::compute(&copy.row.event).as_bytes(),
        payload_object_id: None,
        payload_bytes: 0,
        acked: false,
        cross_profile: None,
    }
    .encode()?;
    let key = agenc_ircd_storage::e2ee_records::DeliveryRow::outbox_key(home().as_bytes(), 0, 0)?;
    let write = super::super::super::super::request::state_row(TableId::E2eeState, 10, key, body)
        .map_err(|error| format!("legacy fixture: {error:?}"))?;
    fixture.commit(vec![write]).await?;
    let Err(error) = fixture.restart().await else {
        return Err("legacy outbox inherited current owner scope".into());
    };
    assert!(matches!(
        error.downcast_ref::<CompanionFault>(),
        Some(CompanionFault::Storage)
    ));
    Ok(())
}
