//! A stored snapshot page read is single-flight, waits for a quiet coordinator, and accepts only
//! the exact sealed row it asked for while its link is still live.
#![forbid(unsafe_code)]

use super::*;
use crate::bridge::StorageReadCompletionMessage;
use crate::e2ee::coordinator::sync::SnapshotPageRequest;
use crate::federation::coordinator::companion::page_read;
use agenc_relay_storage::{ReadRecord, StorageError};

fn request(fixture: &Fixture, page: usize) -> TestResult<SnapshotPageRequest> {
    request_on(fixture, page, LinkId::new(1))
}

fn request_on(fixture: &Fixture, page: usize, link: LinkId) -> TestResult<SnapshotPageRequest> {
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
        PEER, link, owner, page, [3; 32],
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

/// A read of page 0 over link 2, which is not the peer's link: it settles
/// with no output and no fault.
fn submit_replaced(fixture: &mut Fixture) -> TestResult {
    let request = request_on(fixture, 0, LinkId::new(2))?;
    page_read::submit(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        request,
    )
    .map_err(|error| format!("page read: {error:?}"))?;
    Ok(())
}

fn base_ack(fixture: &Fixture) -> crate::federation::FederationInbound {
    crate::federation::FederationInbound {
        link: LinkId::new(1),
        peer: PEER,
        event: crate::federation::LinkEvent::Frame(FederationFrame::Ack {
            coordinator_server_id: COORDINATOR,
            delivery_sequence: fixture.gate.base().last(),
            event_id: agenc_relay_types::EventId::from_bytes(fixture.gate.base().final_event_id()),
        }),
        charge: None,
    }
}

/// A page read is companion work: link traffic that arrives while it is in
/// flight waits in the backlog and runs once it completes.
#[tokio::test]
async fn link_traffic_waits_for_a_page_read_and_runs_at_its_completion() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    let _queue = make_live(&mut fixture)?;
    submit_replaced(&mut fixture)?;
    let ack = base_ack(&fixture);
    fixture
        .coordinator
        .inbound(fixture.core.context_mut()?, ack);
    assert_eq!(fixture.coordinator.backlog.len(), 1, "the ACK waits");
    assert!(fixture.coordinator.pending.is_none());
    let message = settled(&mut fixture).await?;
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(fixture.coordinator.companion_page_read.is_none());
    assert!(fixture.coordinator.backlog.is_empty(), "the ACK ran");
    assert!(matches!(
        fixture.coordinator.pending,
        Some(PendingCommit::DeliveryAcknowledged { .. })
    ));
    assert!(fixture.coordinator.link_is_live(LinkId::new(1), PEER));
    assert_eq!(fixture.coordinator.counters.violations, 0);
    Ok(())
}

/// A page read's completion waits while a batch is open and continues at
/// that batch's receipt.
#[tokio::test]
async fn a_page_read_completion_waits_for_an_open_batch() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    let _queue = make_live(&mut fixture)?;
    submit_replaced(&mut fixture)?;
    let message = settled(&mut fixture).await?;
    let context = fixture.core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let write = fixture.coordinator.peer_row_at(PEER, revision, None)?;
    context
        .stage_durable_with_account_service(
            plan,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            vec![write],
        )
        .map_err(|error| format!("other batch: {error:?}"))?;
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(fixture.coordinator.parked_read.is_some());
    assert!(fixture.coordinator.companion_page_read.is_some());
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert!(fixture.coordinator.parked_read.is_none());
    assert!(fixture.coordinator.companion_page_read.is_none());
    assert!(fixture.coordinator.link_is_live(LinkId::new(1), PEER));
    assert_eq!(fixture.coordinator.counters.violations, 0);
    Ok(())
}

/// The base request queue waits while a page read is in flight and is
/// visited once it completes. The queued request here belongs to a link
/// that is gone, so the visit drops it without running it.
#[tokio::test]
async fn the_base_request_queue_waits_for_a_page_read_and_drains_at_its_completion() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    let _queue = make_live(&mut fixture)?;
    submit_replaced(&mut fixture)?;
    let (inbox, _receiver) = tokio::sync::mpsc::channel(1);
    let mut edge = super::super::Edge::new(inbox, 50);
    let origin = super::super::Origin::new(70);
    super::super::enqueue(
        &mut fixture.coordinator,
        &mut edge,
        &origin,
        LinkId::new(2),
        71,
    )?;
    let queued = |fixture: &Fixture| -> TestResult<usize> {
        Ok(fixture
            .coordinator
            .peers
            .get(&PEER)
            .ok_or("peer")?
            .queued
            .len())
    };
    request::drain_queued(&mut fixture.coordinator, fixture.core.context_mut()?);
    assert_eq!(queued(&fixture)?, 1, "the queue waits for the page read");
    let message = settled(&mut fixture).await?;
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert_eq!(queued(&fixture)?, 0, "the queue was visited");
    assert!(fixture.coordinator.link_is_live(LinkId::new(1), PEER));
    assert_eq!(fixture.coordinator.counters.violations, 0);
    Ok(())
}
