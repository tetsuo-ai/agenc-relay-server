//! Actual sealed bodies are checked before a paged recovery job yields a stream.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::delivery_owner;
use agenc_ircd_e2ee::object::IrcWireObject;
use agenc_ircd_e2ee::tls::TlsEncode;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::{
    AckRange, AckRangeFields, ReplayLedgerRow, ReplayOwner, ReplayOwnerFields,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    Acknowledgement, DeliveryCursor, DeliveryOwner, LastAcknowledged,
};
use delivery_owner::restore::replay::{Job, Loaded, Request};
mod prefix;

async fn drive(fixture: &mut RestartFixture, owner: DeliveryOwner) -> TestResult<Loaded> {
    let context = fixture.storage.context_mut()?;
    let pinned = context.head().storage_commit_sequence;
    let mut job = Job::new(owner, None, Some(pinned), context.backing_reservations())?;
    while let Some(request) = job.next()? {
        read(fixture, &mut job, &request).await?;
    }
    Ok(job.finish()?)
}

async fn read(fixture: &mut RestartFixture, job: &mut Job, request: &Request) -> TestResult {
    // The raw result and decoded bodies are destroyed before these reservations.
    let _raw = fixture
        .storage
        .context_mut()?
        .reserve_output_backing(agenc_ircd_storage::MAX_SEALED_RECORD_BYTES + 65_536)?;
    let _decode = fixture
        .storage
        .context_mut()?
        .reserve_output_backing(64 * 1024 * 1024)?;
    let id = fixture
        .storage
        .context_mut()?
        .submit_storage_read(request.plan()?)?;
    let completion = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.storage.next_storage_read(),
    )
    .await??;
    assert_eq!(completion.read_id, id);
    let result = completion.result?;
    assert!(result.records.len() <= 128);
    let mut records = Vec::new();
    for record in &result.records {
        assert_eq!(record.table, request.table());
        let limit = if record.table == TableId::E2eeState {
            8_192
        } else {
            4_194_304 + 8_192
        };
        assert!(record.sealed_record.len() <= limit);
        let plaintext = fixture.storage.context_mut()?.open_storage_plaintext(
            record.table,
            &record.key,
            &record.sealed_record,
        )?;
        records.push((
            record.key.clone(),
            PersistentRecordValue::decode(record.table, plaintext.expose_for_storage_codec())?,
        ));
    }
    job.admit(
        request,
        result.storage_commit_sequence,
        result.truncated,
        records,
    )?;
    Ok(())
}

async fn commit(
    fixture: &mut RestartFixture,
    writes: Vec<AccountServiceDurableWrite>,
) -> TestResult {
    let context = fixture.storage.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let mut writes = writes;
    let owners = fixture
        .coordinator
        .stage_owners(&mut writes, super::NOW_MILLIS / 1_000, false, revision)
        .map_err(|code| format!("owner staging: {code:?}"))?;
    let writes = writes
        .into_iter()
        .map(|write| write.at_revision(revision))
        .collect::<Result<Vec<_>, _>>()?;
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|error| format!("stage replay inventory: {error:?}"))?;
    Box::pin(fixture.storage.commit_staged_batch()).await?;
    owners.apply(&mut fixture.coordinator.state);
    Ok(())
}

fn id(sequence: u64) -> [u8; 16] {
    let mut result = [91; 16];
    for (byte, value) in result.iter_mut().zip(sequence.to_be_bytes()) {
        *byte = value;
    }
    result
}

async fn seed_retained(fixture: &mut RestartFixture) -> TestResult<(DeliveryOwner, StoredKey)> {
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("source stream")?;
    let owner = stream.owner.as_ref().ok_or("owner")?.clone();
    let template =
        delivery_owner::restore::decode_event(&stream.rows.front().ok_or("event")?.event)?;
    let backing = fixture.storage.context_mut()?.backing_reservations();
    let mut writes = Vec::new();
    let mut bytes = 0_u64;
    let mut first_key = None;
    for sequence in 0..4099 {
        let mut event = template.clone();
        event.delivery_sequence = sequence;
        event.event_id = id(sequence);
        let event =
            IrcWireObject::new(IrcWireObjectKind::FederationEvent, event.encode()?)?.encode()?;
        let row = events::StreamRow {
            sequence,
            event_id: id(sequence),
            event: events::SharedBytes::from_owned(event, &backing)?,
            payload: None,
            acknowledgement: Acknowledgement::Unacknowledged,
        };
        if sequence <= 4096 {
            bytes += u64::try_from(row.event.len())?;
        }
        if sequence == 0 {
            first_key = Some(StoredKey::new(
                agenc_ircd_e2ee::ObjectId::compute(&row.event)
                    .as_bytes()
                    .to_vec(),
            )?);
        }
        writes.push(
            CompanionCoordinator::object_write(&row.event)
                .map_err(|error| format!("object: {error:?}"))?,
        );
        writes.push(
            events::outbox_write(owner.scope(), 0, &row, Acknowledgement::Unacknowledged)
                .map_err(|error| format!("outbox: {error:?}"))?,
        );
    }
    let current = DeliveryOwner::new(
        *owner.scope(),
        DeliveryCursor::new(
            0,
            4099,
            LastAcknowledged::At {
                sequence: 4096,
                event_id: id(4096),
            },
        )?,
        *owner.cut(),
        owner.phase(),
    )?;
    writes.push(delivery_owner::write(&current)?);
    for row in [
        ReplayLedgerRow::Owner(ReplayOwner::new(ReplayOwnerFields {
            scope: *owner.scope(),
            generation: 0,

            through: 4096,
            event_id: id(4096),
            first_retained: 0,
            retained_rows: 4097,
            retained_bytes: bytes,
            trusted_unix_seconds: Some(100),
        })?),
        ReplayLedgerRow::Range(AckRange::new(AckRangeFields {
            scope: *owner.scope(),
            generation: 0,
            first: 0,
            last: 4096,
            event_id: id(4096),
            acknowledgement: Acknowledgement::received_at(Some(100)),
        })?),
    ] {
        writes.push(
            crate::e2ee::coordinator::request::state_row(
                TableId::E2eeState,
                agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND,
                row.key()?,
                row.encode()?,
            )
            .map_err(|error| format!("ledger: {error:?}"))?,
        );
    }
    commit(fixture, writes).await?;
    Ok((current, first_key.ok_or("oldest body key")?))
}

#[tokio::test]
async fn paged_body_recovery_preserves_the_complete_legacy_unacknowledged_tail() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let backing = fixture.storage.context_mut()?.backing_reservations();
    let expected = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("stream")?
        .try_clone(0, &backing)?;
    let loaded = drive(
        &mut fixture,
        expected.owner.as_ref().ok_or("owner")?.clone(),
    )
    .await?;
    assert_eq!(loaded.stream, expected);
    assert!(loaded.owner.is_none());
    assert!(!loaded.has_retained_head());
    Ok(())
}

#[tokio::test]
async fn paged_recovery_validates_4097_acknowledged_bodies_with_only_4096_cached() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let (owner, _) = seed_retained(&mut fixture).await?;
    let loaded = drive(&mut fixture, owner).await?;
    assert_eq!(
        loaded
            .owner
            .ok_or("retention owner")?
            .fields()
            .retained_rows,
        4097
    );
    assert!(loaded.has_retained_head());
    assert_eq!(
        loaded.stream.rows.iter().filter(|row| row.acked()).count(),
        4096
    );
    assert_eq!(
        loaded.stream.rows.iter().filter(|row| !row.acked()).count(),
        2
    );
    assert_eq!(loaded.stream.rows.front().ok_or("hot head")?.sequence, 1);
    assert_eq!(
        loaded
            .stream
            .rows
            .back()
            .ok_or("unacknowledged tail")?
            .sequence,
        4098
    );
    Ok(())
}

#[tokio::test]
async fn a_missing_body_older_than_the_hot_cache_refuses_the_whole_recovery_job() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let (owner, key) = seed_retained(&mut fixture).await?;
    commit(
        &mut fixture,
        vec![AccountServiceDurableWrite::Delete {
            table: TableId::E2eeObject,
            key,
        }],
    )
    .await?;
    assert!(drive(&mut fixture, owner).await.is_err());
    Ok(())
}

#[tokio::test]
async fn composed_startup_recovers_journal_coverage_beyond_the_body_cache() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let (owner, _) = seed_retained(&mut fixture).await?;
    let coordinator = Box::pin(super::replay_startup::outer(&mut fixture)).await?;
    assert!(coordinator.loaded());
    assert_eq!(coordinator.counters().violations, 0);
    let stream = coordinator
        .companion_executor()
        .ok_or("companion executor")?
        .state
        .streams
        .get(&home())
        .ok_or("reconstructed stream")?;
    assert_eq!(stream.owner.as_ref(), Some(&owner));
    let replay = stream.replay.ok_or("replay inventory")?.inspected();
    assert_eq!(replay.fields().retained_rows, 4097);
    assert_eq!(replay.fields().first_retained, 0);
    assert_eq!(stream.rows.iter().filter(|row| row.acked()).count(), 4096);
    assert_eq!(stream.rows.iter().filter(|row| !row.acked()).count(), 2);
    assert_eq!(stream.rows.front().ok_or("hot head")?.sequence, 1);
    assert_eq!(
        stream.rows.back().ok_or("unacknowledged tail")?.sequence,
        4098
    );
    Ok(())
}

#[tokio::test]
async fn composed_startup_refuses_a_missing_body_outside_the_cache_without_publishing_a_stream()
-> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let (_, key) = seed_retained(&mut fixture).await?;
    commit(
        &mut fixture,
        vec![AccountServiceDurableWrite::Delete {
            table: TableId::E2eeObject,
            key,
        }],
    )
    .await?;
    let coordinator = Box::pin(super::replay_startup::outer(&mut fixture)).await?;
    assert!(!coordinator.loaded());
    assert_eq!(coordinator.counters().violations, 1);
    assert!(
        coordinator
            .companion_executor()
            .ok_or("companion executor")?
            .state
            .streams
            .is_empty()
    );
    Ok(())
}
