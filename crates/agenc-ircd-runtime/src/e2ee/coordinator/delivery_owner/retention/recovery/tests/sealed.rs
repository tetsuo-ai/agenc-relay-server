//! Actual storage owner reads exercise range keys and commit binding on sealed metadata.
#![forbid(unsafe_code)]

use super::*;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::fanout::FanoutRequest;
use crate::test_support::StateCoreFixture;

async fn seed(storage: &mut StateCoreFixture, fixture: &Fixture) -> TestResult {
    let context = storage.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let writes = fixture
        .owner
        .iter()
        .chain(&fixture.ranges)
        .chain(&fixture.rows)
        .map(|(key, value)| {
            AccountServiceDurableWrite::put(TableId::E2eeState, key.clone(), value.encode()?)?
                .at_revision(revision)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|error| format!("stage metadata: {error:?}"))?;
    storage.commit_staged_batch().await
}

async fn page(storage: &mut StateCoreFixture, reader: &mut Reader, request: &Query) -> TestResult {
    // These guards precede the raw result, so every raw/decoded value drops first.
    let _raw = storage
        .context_mut()?
        .reserve_output_backing(agenc_ircd_storage::MAX_SEALED_RECORD_BYTES + 65_536)?;
    let _decode = storage.context_mut()?.reserve_output_backing(2_097_152)?;
    let id = storage
        .context_mut()?
        .submit_storage_read(request.plan()?)?;
    let message = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        storage.next_storage_read(),
    )
    .await??;
    assert_eq!(message.read_id, id);
    let result = message.result?;
    assert!(result.records.len() <= PAGE_ROWS as usize);
    let mut values = Vec::new();
    for record in &result.records {
        assert_eq!(record.table, TableId::E2eeState);
        assert!(record.sealed_record.len() < 8_192);
        let plaintext = storage.context_mut()?.open_storage_plaintext(
            record.table,
            &record.key,
            &record.sealed_record,
        )?;
        let value =
            PersistentRecordValue::decode(record.table, plaintext.expose_for_storage_codec())?;
        values.push((record.key.clone(), value));
    }
    reader.admit(
        request,
        result.storage_commit_sequence,
        result.truncated,
        values,
    )?;
    Ok(())
}

#[tokio::test]
async fn sealed_outbox_and_ack_journal_pages_reconstruct_without_all_row_metadata_resident()
-> TestResult {
    for legacy in [false, true] {
        let fixture = Fixture::new(legacy)?;
        let mut storage = StateCoreFixture::new(vec![44; 65_536])?;
        seed(&mut storage, &fixture).await?;
        let mut reader = Reader::new(
            fixture.current.clone(),
            None,
            &storage.context_mut()?.backing_reservations(),
        )?;
        let mut count = 0;
        let mut reads = 0;
        loop {
            match reader.next()? {
                Next::Read(request) => {
                    page(&mut storage, &mut reader, &request).await?;
                    reads += 1;
                }
                Next::Row(row) => {
                    assert_eq!(row.sequence(), count);
                    assert_eq!(row.acknowledgement().is_acknowledged(), count < 257);
                    count += 1;
                }
                Next::Done => break,
            }
        }
        assert_eq!((count, reads), (258, if legacy { 5 } else { 7 }));
        assert_eq!(
            reader
                .finish()?
                .owner
                .ok_or("owner")?
                .fields()
                .retained_bytes,
            257 * 1024
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_real_commit_between_pages_cannot_be_merged_into_the_captured_history() -> TestResult {
    let fixture = Fixture::new(false)?;
    let mut storage = StateCoreFixture::new(vec![44; 65_536])?;
    seed(&mut storage, &fixture).await?;
    let mut reader = Reader::new(
        fixture.current.clone(),
        None,
        &storage.context_mut()?.backing_reservations(),
    )?;
    let request = query(&mut reader)?;
    page(&mut storage, &mut reader, &request).await?;
    seed(&mut storage, &fixture).await?;
    let request = query(&mut reader)?;
    assert!(page(&mut storage, &mut reader, &request).await.is_err());
    assert!(reader.next().is_err());
    assert!(reader.finish().is_err());
    Ok(())
}
