//! Local write contention never fails a federation link: link traffic waits
//! in the backlog while any router's batch is open, and a companion batch
//! that finds a batch open is held and staged once it settles.
#![forbid(unsafe_code)]

use super::*;
use crate::federation::{FederationInbound, LinkEvent};

fn live(fixture: &mut Fixture) -> TestResult<crate::federation::link::LinkQueue> {
    let (handle, queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        incarnation: INCARNATION,
    });
    Ok(queue)
}

/// Another router's batch opens in the state core: the coordinator's own
/// slot is free, and its plan could not join that batch.
fn open_other_batch(fixture: &mut Fixture) -> TestResult {
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
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 1);
    Ok(())
}

/// Commits the open batch and runs the coordinator's receipt.
async fn settle(fixture: &mut Fixture) -> TestResult {
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    Ok(())
}

fn row_id(fixture: &Fixture, sequence: u64) -> TestResult<[u8; 16]> {
    fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?
        .rows
        .iter()
        .find(|row| row.sequence == sequence)
        .map(|row| row.event_id)
        .ok_or_else(|| "row".into())
}

fn resume_frame(fixture: &Fixture, sequence: u64) -> TestResult<CompanionFrame> {
    Ok(CompanionFrame::Resume {
        coordinator_server_id: *COORDINATOR.as_bytes(),
        server_incarnation: *INCARNATION.as_bytes(),
        delivery_generation: 0,
        last: Some((sequence, row_id(fixture, sequence)?)),
    })
}

async fn sent(queue: &mut crate::federation::link::LinkQueue) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(Some(line)) =
        tokio::time::timeout(std::time::Duration::from_millis(50), queue.recv()).await
    {
        lines.push(line.as_str().trim_end().to_owned());
    }
    lines
}

fn live_and_clean(fixture: &Fixture) -> TestResult<bool> {
    Ok(fixture.coordinator.counters().violations == 0
        && fixture
            .coordinator
            .peers
            .get(&PEER)
            .ok_or("peer")?
            .live
            .is_some())
}

#[tokio::test]
async fn a_base_ack_waits_while_another_router_has_a_batch_open() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    let _queue = live(&mut fixture)?;
    open_other_batch(&mut fixture)?;
    let ack = FederationInbound {
        link: LinkId::new(1),
        peer: PEER,
        event: LinkEvent::Frame(FederationFrame::Ack {
            coordinator_server_id: COORDINATOR,
            delivery_sequence: fixture.gate.base().last(),
            event_id: agenc_relay_types::EventId::from_bytes(fixture.gate.base().final_event_id()),
        }),
        charge: None,
    };
    fixture
        .coordinator
        .inbound(fixture.core.context_mut()?, ack);
    assert_eq!(fixture.coordinator.backlog.len(), 1, "the ACK waits");
    assert!(fixture.coordinator.pending.is_none());
    assert!(live_and_clean(&fixture)?);
    // The other batch's receipt replays the ACK, which stages its own batch.
    settle(&mut fixture).await?;
    assert!(fixture.coordinator.backlog.is_empty());
    assert!(matches!(
        fixture.coordinator.pending,
        Some(PendingCommit::DeliveryAcknowledged { .. })
    ));
    settle(&mut fixture).await?;
    let gate = fixture.stored_gate().await?.ok_or("gate")?;
    assert!(gate.base_acked(), "the ACK committed");
    assert!(live_and_clean(&fixture)?);
    Ok(())
}

#[tokio::test]
async fn a_companion_frame_waits_while_another_router_has_a_batch_open() -> TestResult {
    let mut fixture = Box::pin(Fixture::seed(true)).await?;
    let mut queue = live(&mut fixture)?;
    open_other_batch(&mut fixture)?;
    let frame = resume_frame(&fixture, 1)?;
    // The companion link hands the coordinator its admitted frames; while a
    // batch is open they wait in the backlog.
    fixture.coordinator.inbound(
        fixture.core.context_mut()?,
        FederationInbound {
            link: LinkId::new(1),
            peer: PEER,
            event: LinkEvent::Companion(frame),
            charge: None,
        },
    );
    assert_eq!(fixture.coordinator.backlog.len(), 1, "the frame waits");
    assert!(live_and_clean(&fixture)?);
    assert!(sent(&mut queue).await.is_empty());
    assert!(fixture.coordinator.companion_held.is_none());
    assert_eq!(
        fixture.core.context_mut()?.pending_len(),
        1,
        "only the other batch"
    );
    Ok(())
}

#[tokio::test]
async fn a_companion_batch_that_finds_a_batch_open_is_staged_when_it_settles() -> TestResult {
    for refused in [false, true] {
        let mut fixture = Box::pin(Fixture::seed(true)).await?;
        let mut queue = live(&mut fixture)?;
        open_other_batch(&mut fixture)?;
        let frame = resume_frame(&fixture, 1)?;
        companion::admitted(
            &mut fixture.coordinator,
            fixture.core.context_mut()?,
            LinkId::new(1),
            PEER,
            frame,
        )
        .map_err(|violation| format!("held, not refused: {violation:?}"))?;
        assert!(fixture.coordinator.companion_held.is_some(), "{refused}");
        assert_eq!(
            fixture.core.context_mut()?.pending_len(),
            1,
            "only the other batch"
        );
        assert!(sent(&mut queue).await.is_empty());
        // While it is held, link traffic waits behind it.
        assert!(
            fixture
                .coordinator
                .holds_traffic(fixture.core.context_mut()?)
        );
        assert!(!fixture.coordinator.reload_ready(), "no reload drops it");
        if refused {
            // Storage refuses the other batch; the held batch is staged at
            // that receipt.
            fixture
                .core
                .state_mut()?
                .reject_fixture_batch_before_submission(
                    agenc_relay_storage::StorageError::QueueFull,
                )?;
            fixture
                .coordinator
                .batch_rejected(fixture.core.context_mut()?);
        } else {
            settle(&mut fixture).await?;
        }
        assert!(fixture.coordinator.companion_held.is_none(), "{refused}");
        assert!(matches!(
            fixture.coordinator.pending,
            Some(PendingCommit::Companion { resume: true, .. })
        ));
        assert!(sent(&mut queue).await.is_empty(), "nothing before commit");
        settle(&mut fixture).await?;
        let lines = sent(&mut queue).await;
        let first = lines.first().ok_or("ERESUME OK")?;
        assert!(
            first.contains(" ERESUME OK ") && first.ends_with(" 0 2"),
            "{first}"
        );
        assert!(live_and_clean(&fixture)?);
    }
    Ok(())
}

#[tokio::test]
async fn a_held_batch_stays_held_while_another_batch_opens_at_its_receipt() -> TestResult {
    let mut fixture = Box::pin(Fixture::seed(true)).await?;
    let mut queue = live(&mut fixture)?;
    open_other_batch(&mut fixture)?;
    let frame = resume_frame(&fixture, 1)?;
    companion::admitted(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        LinkId::new(1),
        PEER,
        frame,
    )
    .map_err(|violation| format!("held: {violation:?}"))?;
    assert!(fixture.coordinator.companion_held.is_some());
    // That batch commits, and another router stages its next batch before
    // the coordinator's receipt runs, as an earlier role's receipt may.
    fixture.core.commit_staged_batch().await?;
    open_other_batch(&mut fixture)?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert!(
        fixture.coordinator.companion_held.is_some(),
        "the held batch waits for that batch too"
    );
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 1);
    assert!(live_and_clean(&fixture)?);
    // Its receipt stages the held batch, whose own receipt resumes the link.
    settle(&mut fixture).await?;
    assert!(fixture.coordinator.companion_held.is_none());
    settle(&mut fixture).await?;
    let lines = sent(&mut queue).await;
    let first = lines.first().ok_or("ERESUME OK")?;
    assert!(
        first.contains(" ERESUME OK ") && first.ends_with(" 0 2"),
        "{first}"
    );
    assert!(live_and_clean(&fixture)?);
    Ok(())
}

#[tokio::test]
async fn a_quarantine_is_refused_while_a_batch_is_open_and_changes_nothing() -> TestResult {
    for held in [false, true] {
        let mut fixture = Box::pin(Fixture::seed(true)).await?;
        let _queue = live(&mut fixture)?;
        open_other_batch(&mut fixture)?;
        if held {
            let frame = resume_frame(&fixture, 1)?;
            companion::admitted(
                &mut fixture.coordinator,
                fixture.core.context_mut()?,
                LinkId::new(1),
                PEER,
                frame,
            )
            .map_err(|violation| format!("held: {violation:?}"))?;
            assert!(fixture.coordinator.companion_held.is_some());
            // The other batch commits; the held batch now waits for the
            // next receipt.
            fixture.core.commit_staged_batch().await?;
        }
        assert_eq!(
            fixture
                .coordinator
                .admin_quarantine_peer(fixture.core.context_mut()?, PEER),
            Err(PeerQuarantineRefusal::Busy),
            "held={held}"
        );
        let state = fixture.coordinator.peers.get(&PEER).ok_or("peer")?;
        assert!(!state.quarantined, "held={held}");
        assert!(live_and_clean(&fixture)?, "held={held}");
        assert_eq!(
            fixture.core.context_mut()?.pending_len(),
            usize::from(!held)
        );
    }
    Ok(())
}
