//! A stored snapshot page read is single-flight, waits for a quiet coordinator, and accepts only
//! the exact sealed row it asked for while its link is still live.
#![forbid(unsafe_code)]

use super::*;
use crate::bridge::StorageReadCompletionMessage;
use crate::e2ee::coordinator::sync::SnapshotPageRequest;
use crate::federation::coordinator::companion::page_read;
use agenc_relay_storage::{ReadRecord, StorageError};

fn request(fixture: &Fixture, page: usize) -> TestResult<SnapshotPageRequest> {
    let owner = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .and_then(|stream| stream.owner.clone())
        .ok_or("owner")?;
    Ok(SnapshotPageRequest::for_test(
        PEER,
        LinkId::new(1),
        owner,
        page,
        [3; 32],
    ))
}

fn make_live(fixture: &mut Fixture) -> TestResult<crate::federation::link::LinkQueue> {
    let (handle, queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        incarnation: INCARNATION,
    });
    Ok(queue)
}

fn submit(fixture: &mut Fixture, page: usize) -> TestResult<Result<(), Violation>> {
    let request = request(fixture, page)?;
    Ok(page_read::submit(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        request,
    ))
}

async fn settled(fixture: &mut Fixture) -> TestResult<StorageReadCompletionMessage> {
    let message = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.core.next_storage_read(),
    )
    .await??;
    assert!(fixture.coordinator.owns_storage_read(message.read_id));
    Ok(message)
}

fn complete(fixture: &mut Fixture, message: StorageReadCompletionMessage) -> TestResult {
    page_read::completed(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        message,
    );
    assert!(fixture.coordinator.companion_page_read.is_none());
    Ok(())
}

#[tokio::test]
async fn a_page_read_is_single_flight_and_refuses_a_different_page_while_pending() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    let _queue = make_live(&mut fixture)?;
    assert!(submit(&mut fixture, 0)?.is_ok());
    assert!(
        submit(&mut fixture, 0)?.is_ok(),
        "the identical request joins the pending read"
    );
    assert!(matches!(submit(&mut fixture, 1)?, Err(Violation::Ceiling)));
    let message = settled(&mut fixture).await?;
    let foreign = StorageReadCompletionMessage {
        read_id: crate::bridge::StorageReadId::new(message.read_id.get().wrapping_add(7)),
        result: Err(StorageError::Unavailable),
    };
    page_read::completed(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        foreign,
    );
    assert!(
        fixture.coordinator.companion_page_read.is_some(),
        "another read's completion leaves the page read pending"
    );
    complete(&mut fixture, message)?;
    Ok(())
}

#[tokio::test]
async fn a_page_read_waits_for_a_quiet_coordinator() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    let _queue = make_live(&mut fixture)?;
    fixture.core.context_mut()?.quiesce_for_test();
    assert!(matches!(submit(&mut fixture, 0)?, Err(Violation::Ceiling)));
    assert!(fixture.coordinator.companion_page_read.is_none());
    Ok(())
}

#[tokio::test]
async fn a_page_read_settling_after_its_link_closed_is_dropped_without_a_fault() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    let queue = make_live(&mut fixture)?;
    assert!(submit(&mut fixture, 0)?.is_ok());
    let message = settled(&mut fixture).await?;
    drop(queue);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = None;
    complete(&mut fixture, message)?;
    assert!(fixture.coordinator.peers.contains_key(&PEER));
    Ok(())
}

#[tokio::test]
async fn a_page_read_answered_with_anything_but_its_row_fails_the_link() -> TestResult {
    type Tamper = fn(&mut StorageReadCompletionMessage) -> TestResult;
    let tampers: [Tamper; 5] = [
        |message| {
            message.result = Err(StorageError::Unavailable);
            Ok(())
        },
        |message| {
            message.result.as_mut().map_err(|_| "read")?.truncated = true;
            Ok(())
        },
        |message| {
            message.result.as_mut().map_err(|_| "read")?.records.clear();
            Ok(())
        },
        |message| {
            let result = message.result.as_mut().map_err(|_| "read")?;
            let copy = result.records.first().map(|record| ReadRecord {
                table: record.table,
                key: record.key.clone(),
                sealed_record: record.sealed_record.clone(),
            });
            result.records.extend(copy);
            Ok(())
        },
        |message| {
            for record in &mut message.result.as_mut().map_err(|_| "read")?.records {
                record.table = TableId::E2eeObject;
            }
            Ok(())
        },
    ];
    for tamper in tampers {
        let mut fixture = Box::pin(Fixture::new()).await?;
        let _queue = make_live(&mut fixture)?;
        assert!(submit(&mut fixture, 0)?.is_ok());
        let mut message = settled(&mut fixture).await?;
        tamper(&mut message)?;
        complete(&mut fixture, message)?;
        assert!(
            !fixture.coordinator.link_is_live(LinkId::new(1), PEER),
            "the tampered answer failed the link"
        );
    }
    Ok(())
}
