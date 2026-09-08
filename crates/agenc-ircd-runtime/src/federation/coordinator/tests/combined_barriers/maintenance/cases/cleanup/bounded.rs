//! A partially deleted prefix remains restartable and cannot consume an overlapping ACK range.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::IrcFederationEvent;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode, TlsEncode};
use agenc_ircd_storage::StoredKey;
use agenc_ircd_storage::e2ee_records::delivery_recovery::Acknowledgement;
use replay::{AckRange, AckRangeFields, ReplayLedgerRow, ReplayOwner, ReplayOwnerFields};

fn event_id(sequence: u64) -> [u8; 16] {
    let mut id = [81; 16];
    for (target, value) in id.iter_mut().zip(sequence.to_be_bytes()) {
        *target = value;
    }
    id
}

fn stored(body: Vec<u8>, key: StoredKey) -> TestResult<AccountServiceDurableWrite> {
    crate::e2ee::coordinator::request::state_row(
        TableId::E2eeState,
        agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND,
        key,
        body,
    )
    .map_err(|e| format!("metadata: {e:?}").into())
}

async fn seed() -> TestResult<(Fixture, StoredKey)> {
    let mut fixture = Box::pin(Fixture::new()).await?;
    fixture.core.context_mut()?.set_wall_for_test(100);
    fixture.stage_base_ack()?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    fixture.stage_companion_ack()?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    let owner = stream(&fixture)?.owner.as_ref().ok_or("owner")?.clone();
    let object = IrcWireObject::decode_exact(
        &stream(&fixture)?.rows.front().ok_or("row")?.event,
        &mut DecodeBudget::new(1 << 20, 256),
    )?;
    let mut template =
        IrcFederationEvent::decode_exact(object.body(), &mut DecodeBudget::new(1 << 20, 256))?;
    template.cross_profile_mutation_id = agenc_ircd_e2ee::tls::Opaque::new(Vec::new())?;
    template.cross_profile_part_index = 0;
    template.cross_profile_part_count = 0;
    let range = AckRange::new(AckRangeFields {
        scope: *owner.scope(),
        generation: 0,
        first: 0,
        last: 1,
        event_id: fixture.gate.companion().final_event_id(),
        acknowledgement: Acknowledgement::received_at(Some(100)),
    })?;
    let mut writes = vec![AccountServiceDurableWrite::delete(
        TableId::E2eeState,
        ReplayLedgerRow::Range(range).key()?,
    )?];
    let backing = fixture.core.context_mut()?.backing_reservations();
    let mut retained_bytes = 0;
    let mut first_object = None;
    for sequence in 0..132 {
        let mut event = template.clone();
        event.delivery_sequence = sequence;
        event.event_id = event_id(sequence);
        let body =
            IrcWireObject::new(IrcWireObjectKind::FederationEvent, event.encode()?)?.encode()?;
        if (129..=130).contains(&sequence) {
            retained_bytes += u64::try_from(body.len())?;
        }
        if sequence == 0 {
            first_object = Some(agenc_ircd_storage::e2ee_records::object_key(
                agenc_ircd_e2ee::ObjectId::compute(&body).as_bytes(),
            )?);
        }
        let row = events::StreamRow {
            sequence,
            event_id: event_id(sequence),
            event: events::SharedBytes::from_owned(body, &backing)?,
            payload: None,
            acknowledgement: Acknowledgement::Unacknowledged,
        };
        writes.push(
            CompanionCoordinator::object_write(&row.event).map_err(|e| format!("body: {e:?}"))?,
        );
        let metadata =
            DeliveryRecoveryRow::Outbox(outbox::ScopedOutbox::new(outbox::ScopedOutboxFields {
                scope: *owner.scope(),
                generation: 0,
                sequence,
                event_id: row.event_id,
                event_object_id: *agenc_ircd_e2ee::ObjectId::compute(&row.event).as_bytes(),
                event_bytes: u32::try_from(row.event.len())?,
                payload_object_id: None,
                payload_bytes: 0,
                acknowledgement: Acknowledgement::Unacknowledged,
                cross_profile: None,
            })?);
        writes.push(stored(metadata.encode()?, metadata.key()?)?);
    }
    let current = DeliveryRecoveryRow::Owner(DeliveryOwner::new(
        *owner.scope(),
        DeliveryCursor::new(
            0,
            132,
            LastAcknowledged::At {
                sequence: 130,
                event_id: event_id(130),
            },
        )?,
        *owner.cut(),
        CutPhase::Ready,
    )?);
    writes.push(stored(current.encode()?, current.key()?)?);
    for row in [
        ReplayLedgerRow::Owner(ReplayOwner::new(ReplayOwnerFields {
            scope: *owner.scope(),
            generation: 0,
            baseline: LastAcknowledged::BeforeFirst,
            through: 130,
            event_id: event_id(130),
            first_retained: 129,
            retained_rows: 2,
            retained_bytes,
            trusted_unix_seconds: Some(100),
        })?),
        ReplayLedgerRow::Range(AckRange::new(AckRangeFields {
            scope: *owner.scope(),
            generation: 0,
            first: 0,
            last: 130,
            event_id: event_id(130),
            acknowledgement: Acknowledgement::received_at(Some(100)),
        })?),
    ] {
        writes.push(stored(row.encode()?, row.key()?)?);
    }
    Box::pin(fixture.commit(writes)).await?;
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    assert_eq!(stream(&fixture)?.rows.len(), 3);
    Ok((fixture, first_object.ok_or("first object")?))
}

async fn positions(fixture: &mut Fixture) -> TestResult<Vec<u64>> {
    let mut rows = Vec::new();
    let mut from = 0;
    for _ in 0..3 {
        let plan = outbox::outbox_from(fixture.gate.scope(), 0, from, 128)?;
        let id = fixture.core.context_mut()?.submit_storage_read(plan)?;
        let message = fixture.core.next_storage_read().await?;
        assert_eq!(id, message.read_id);
        let result = message.result?;
        for row in result.records {
            let (_, _, sequence) = outbox::parse_outbox_key(&row.key)?;
            rows.push(sequence);
            from = sequence.checked_add(1).ok_or("position")?;
        }
        if !result.truncated {
            return Ok(rows);
        }
    }
    Err("test prefix exceeded its bound".into())
}

#[tokio::test]
async fn bounded_cleanup_restarts_mid_prefix_and_preserves_overlap_unacked_tail_and_shared_body()
-> TestResult {
    let (mut fixture, object_key) = Box::pin(seed()).await?;
    assert_eq!(positions(&mut fixture).await?.len(), 132);
    wake(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 2);
    let deletes = fixture.core.context_mut()?.staged_rows_for_test()?;
    assert_eq!(deletes.len(), 128);
    assert!(deletes.iter().all(|write| matches!(
        write,
        AccountServiceDurableWrite::Delete {
            table: TableId::E2eeState,
            ..
        }
    )));
    fixture.core.commit_staged_batch().await?;
    fixture.restart().await?;
    assert_eq!(positions(&mut fixture).await?, vec![128, 129, 130, 131]);
    wake(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 2);
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert_eq!(positions(&mut fixture).await?, vec![129, 130, 131]);
    retry(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 3);
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(physical_rows(&mut fixture, true).await?, 1);
    retry(&mut fixture)?;
    assert!(
        !fixture.coordinator.replay_maintenance.busy(),
        "the cleaned floor was scanned again"
    );
    assert!(!stream(&fixture)?.rows.back().ok_or("tail")?.acked());
    let id =
        fixture
            .core
            .context_mut()?
            .submit_storage_read(agenc_ircd_storage::ReadPlan::exact(
                TableId::E2eeObject,
                object_key,
            ))?;
    let message = fixture.core.next_storage_read().await?;
    assert_eq!(id, message.read_id);
    assert_eq!(
        message.result?.records.len(),
        1,
        "metadata trimming deleted a shared body"
    );
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    assert_eq!(stream(&fixture)?.acked.map(|last| last.0), Some(130));
    assert_eq!(stream(&fixture)?.rows.len(), 3);
    Ok(())
}
