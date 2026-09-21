//! A prefix scan uses sealed metadata after complete body recovery established its prior inventory.
#![forbid(unsafe_code)]

use super::*;
use delivery_owner::retention::prefix::{Next, Prefix};

async fn read_prefix(fixture: &mut RestartFixture, prefix: &mut Prefix) -> TestResult<usize> {
    let mut reads = 0;
    loop {
        let request = match prefix.next()? {
            Next::Read(request) => request,
            Next::Done => return Ok(reads),
        };
        let backing = fixture.storage.context_mut()?.backing_reservations();
        let _raw = backing.reserve(agenc_relay_storage::MAX_SEALED_RECORD_BYTES + 131_072)?;
        let _decode = backing.reserve(8 * 1024 * 1024)?;
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
            assert_eq!(record.table, TableId::E2eeState);
            assert!(record.sealed_record.len() <= 8192);
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
        prefix.admit(
            &request,
            result.storage_commit_sequence,
            result.truncated,
            records,
        )?;
        reads += 1;
        assert!(reads <= 64);
    }
}

#[tokio::test]
async fn sealed_prefix_expiry_reads_beyond_the_cache_without_reloading_bodies_or_publishing_an_ack()
-> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let (owner, _) = seed_retained(&mut fixture).await?;
    Box::pin(fixture.restart()).await?;
    let context = fixture.storage.context_mut()?;
    let backing = context.backing_reservations();
    let commit = context.head().storage_commit_sequence;
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("restored stream")?;
    let before = stream.replay.ok_or("complete body inventory")?;
    assert_eq!(stream.rows.front().ok_or("hot head")?.sequence, 1);
    let position = DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: 0,
        delivery_sequence: 4097,
        event_id: id(4097),
    };
    let mut prefix = Prefix::for_ack(stream, position, Some(86_500), None, Some(commit), &backing)?;
    assert_eq!(read_prefix(&mut fixture, &mut prefix).await?, 35);
    let (replay, range) = prefix.finish_ledger()?;
    assert_eq!(replay.fields().first_retained, 4097);
    assert_eq!(replay.fields().retained_rows, 1);
    assert_eq!(replay.fields().through, 4097);
    assert_eq!(replay.fields().event_id, id(4097));
    assert_eq!(replay.fields().trusted_unix_seconds, Some(86_500));
    let range = range.ok_or("new ACK range")?;
    assert_eq!(range.fields().first, 4097);
    assert_eq!(range.last(), 4097);
    assert_eq!(
        range.fields().acknowledgement,
        Acknowledgement::received_at(Some(86_500))
    );
    let after = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("unchanged stream")?;
    assert_eq!(after.owner.as_ref(), Some(&owner));
    assert_eq!(after.replay, Some(before));
    assert_eq!(after.rows.iter().filter(|row| !row.acked()).count(), 2);
    Ok(())
}

#[tokio::test]
async fn an_ack_prefix_refuses_a_position_from_another_server_or_generation() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let _seeded = seed_retained(&mut fixture).await?;
    Box::pin(fixture.restart()).await?;
    let context = fixture.storage.context_mut()?;
    let backing = context.backing_reservations();
    let commit = context.head().storage_commit_sequence;
    let server_id = *fixture.storage.identity.server_id.as_bytes();
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("restored stream")?;
    for (name, position) in [
        (
            "another coordinator",
            DeliveryPosition {
                server_id: [9; 16],
                delivery_generation: 0,
                delivery_sequence: 4097,
                event_id: id(4097),
            },
        ),
        (
            "another delivery generation",
            DeliveryPosition {
                server_id,
                delivery_generation: 1,
                delivery_sequence: 4097,
                event_id: id(4097),
            },
        ),
    ] {
        assert!(
            Prefix::for_ack(stream, position, Some(86_500), None, Some(commit), &backing).is_err(),
            "{name}"
        );
    }
    Ok(())
}
