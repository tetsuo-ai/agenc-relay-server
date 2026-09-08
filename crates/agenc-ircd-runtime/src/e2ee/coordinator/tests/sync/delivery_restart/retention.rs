//! A committed ACK must keep replay references below all published limits.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::delivery_owner;
use crate::e2ee::coordinator::events::{DeliveryStream, StreamRow};
use agenc_ircd_e2ee::object::IrcWireObject;
use agenc_ircd_e2ee::tls::TlsEncode;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    Acknowledgement, DeliveryOwner, DeliveryRecoveryRow, outbox,
};

fn row(
    template: &StreamRow,
    sequence: u64,
    backing: &crate::budget::BackingReservationPort,
) -> TestResult<StreamRow> {
    let mut event = delivery_owner::restore::decode_event(&template.event)?;
    let mut event_id = [71; 16];
    event_id
        .get_mut(..8)
        .ok_or("event id prefix")?
        .copy_from_slice(&sequence.to_be_bytes());
    event.delivery_sequence = sequence;
    event.event_id = event_id;
    Ok(StreamRow {
        sequence,
        event_id,
        event: events::SharedBytes::from_owned(
            IrcWireObject::new(IrcWireObjectKind::FederationEvent, event.encode()?)?.encode()?,
            backing,
        )?,
        payload: None,
        acknowledgement: if sequence < 4096 {
            Acknowledgement::received_at(Some(100))
        } else {
            Acknowledgement::Unacknowledged
        },
    })
}

async fn seed(fixture: &mut RestartFixture) -> TestResult<DeliveryPosition> {
    let backing = fixture.storage.context_mut()?.backing_reservations();
    let original = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("stream")?;
    let mut stream = DeliveryStream {
        owner: original.owner.clone(),
        generation: original.generation,
        next_sequence: 4097,
        ..DeliveryStream::with_row_capacity(4097, &backing)?
    };
    let owner = stream.owner.as_ref().ok_or("owner")?.clone();
    let template = original.rows.front().ok_or("template")?;
    let mut writes = Vec::new();
    for sequence in 0..4097 {
        let row = row(template, sequence, &backing)?;
        writes.push(
            CompanionCoordinator::object_write(&row.event).map_err(|e| format!("object: {e:?}"))?,
        );
        writes.push(
            events::outbox_write(owner.scope(), stream.generation, &row, row.acknowledgement)
                .map_err(|e| format!("outbox: {e:?}"))?,
        );
        if sequence == 4095 {
            stream.acked = Some((sequence, row.event_id));
        }
        stream.rows.push_back(row);
    }
    stream.owner = Some(DeliveryOwner::new(
        *owner.scope(),
        delivery_owner::cursor(&stream)?,
        *owner.cut(),
        owner.phase(),
    )?);
    writes.push(events::cursor_write(home(), &stream).map_err(|e| format!("cursor: {e:?}"))?);
    let last = stream.rows.back().ok_or("last")?;
    let position = DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: stream.generation,
        delivery_sequence: last.sequence,
        event_id: last.event_id,
    };
    fixture.commit(writes).await?;
    fixture.coordinator.state.streams.insert(home(), stream);
    Box::pin(fixture.restart()).await?;
    let last = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("restored legacy stream")?
        .acked;
    let actions = fixture.frame(CompanionFrame::Resume {
        coordinator_server_id: *fixture.storage.identity.server_id.as_bytes(),
        server_incarnation: INCARNATION,
        delivery_generation: position.delivery_generation,
        last,
    })?;
    assert!(matches!(
        frames(&actions)?.first(),
        Some(CompanionFrame::ResumeOk { .. })
    ));
    Ok(position)
}

async fn durable_count(fixture: &mut RestartFixture) -> TestResult<(usize, usize)> {
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("stream")?;
    let scope = *stream.owner.as_ref().ok_or("owner")?.scope();
    let generation = stream.generation;
    let mut first = 0;
    let mut count = 0;
    let mut acknowledged = 0;
    let mut commit = None;
    loop {
        let plan = outbox::outbox_from(&scope, generation, first, 100)?;
        let id = fixture.storage.context_mut()?.submit_storage_read(plan)?;
        let completion = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.storage.next_storage_read(),
        )
        .await??;
        assert_eq!(completion.read_id, id);
        let result = completion.result?;
        assert_eq!(
            *commit.get_or_insert(result.storage_commit_sequence),
            result.storage_commit_sequence
        );
        for record in result.records {
            let plaintext = fixture.storage.context_mut()?.open_storage_plaintext(
                TableId::E2eeState,
                &record.key,
                &record.sealed_record,
            )?;
            let value = PersistentRecordValue::decode(
                TableId::E2eeState,
                plaintext.expose_for_storage_codec(),
            )?;
            let DeliveryRecoveryRow::Outbox(row) =
                DeliveryRecoveryRow::decode_at(&record.key, value.body())?
            else {
                return Err("unexpected scoped record".into());
            };
            first = row.sequence().checked_add(1).ok_or("sequence overflow")?;
            count += 1;
            acknowledged += usize::from(row.acknowledgement().is_acknowledged());
        }
        if !result.truncated {
            return Ok((count, acknowledged));
        }
    }
}

#[tokio::test]
async fn acknowledged_replay_retains_4097_rows_in_sealed_storage() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let position = seed(&mut fixture).await?;
    assert_eq!(durable_count(&mut fixture).await?, (4097, 4096));
    let actions = events::on_ack(
        &mut fixture.coordinator,
        LinkId::new(1),
        home(),
        position,
        Some(200),
    )?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("ACK was not staged".into());
    };
    assert_eq!(writes.len(), 3);
    fixture.coordinator.set_pending(work);
    stage_ack_for_rejection(&mut fixture, writes)?;
    fixture.storage.commit_staged_batch().await?;
    assert!(matches!(
        fixture.coordinator.batch_applied(Some(0))?,
        Some(Committed::Acknowledged(_))
    ));
    assert_eq!(
        durable_count(&mut fixture).await?,
        (4097, 4096),
        "the journal ACK must preserve all references and original per-row ACK fields"
    );
    let restored = Box::pin(super::replay_startup::outer(&mut fixture)).await?;
    assert!(restored.loaded());
    let stream = restored
        .companion_executor()
        .ok_or("restored companion")?
        .state
        .streams
        .get(&home())
        .ok_or("restored stream")?;
    let (replay, persisted) = stream.replay.ok_or("durable replay owner")?.inspected();
    assert!(persisted);
    assert_eq!(replay.fields().retained_rows, 4097);
    assert_eq!(replay.fields().first_retained, 0);
    assert_eq!(replay.fields().through, position.delivery_sequence);
    assert_eq!(replay.fields().event_id, position.event_id);
    assert_eq!(replay.fields().trusted_unix_seconds, Some(200));
    assert!(matches!(
        replay.fields().baseline,
        agenc_ircd_storage::e2ee_records::delivery_recovery::LastAcknowledged::At {
            sequence: 4095,
            ..
        }
    ));
    assert_eq!(stream.rows.len(), 4096);
    assert!(stream.rows.iter().all(StreamRow::acked));
    assert_eq!(stream.rows.front().ok_or("hot head")?.sequence, 1);
    assert_eq!(
        stream.rows.back().ok_or("new ACK")?.acknowledgement,
        Acknowledgement::received_at(Some(200))
    );
    Ok(())
}
