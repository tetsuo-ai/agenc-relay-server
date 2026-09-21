//! A companion ACK must come from the active link, name this coordinator, its
//! stream generation and a retained event, and a pending ACK admits only its
//! own repeat.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::CompanionFault;
use crate::e2ee::coordinator::sync::Action;
use agenc_relay_e2ee::federation::frames::DeliveryPosition;

fn position(fixture: &Fixture, sequence: u64) -> TestResult<DeliveryPosition> {
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    let row = stream
        .rows
        .iter()
        .find(|row| row.sequence == sequence)
        .ok_or("row")?;
    Ok(DeliveryPosition {
        server_id: *COORDINATOR.as_bytes(),
        delivery_generation: stream.generation,
        delivery_sequence: sequence,
        event_id: row.event_id,
    })
}

fn on_ack(
    fixture: &mut Fixture,
    link: LinkId,
    position: DeliveryPosition,
) -> TestResult<Result<Vec<Action>, CompanionFault>> {
    Ok(events::on_ack(
        fixture
            .coordinator
            .companion_exec
            .as_mut()
            .ok_or("executor")?,
        link,
        PEER,
        position,
        Some(100),
    ))
}

async fn resumed() -> TestResult<(Fixture, crate::federation::link::LinkQueue)> {
    let mut fixture = Box::pin(Fixture::seed(true)).await?;
    let (handle, queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        incarnation: INCARNATION,
    });
    companion::admitted(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        LinkId::new(1),
        PEER,
        CompanionFrame::Resume {
            coordinator_server_id: *COORDINATOR.as_bytes(),
            server_incarnation: *INCARNATION.as_bytes(),
            delivery_generation: 0,
            last: None,
        },
    )
    .map_err(|e| format!("resume: {e:?}"))?;
    Ok((fixture, queue))
}

#[tokio::test]
async fn an_ack_must_name_the_active_link_this_coordinator_and_a_retained_event() -> TestResult {
    let (mut fixture, _queue) = Box::pin(resumed()).await?;
    let good = position(&fixture, 0)?;
    assert!(matches!(
        on_ack(&mut fixture, LinkId::new(2), good)?,
        Err(CompanionFault::Protocol)
    ));
    let foreign = DeliveryPosition {
        server_id: [0; 16],
        ..good
    };
    assert!(matches!(
        on_ack(&mut fixture, LinkId::new(1), foreign)?,
        Err(CompanionFault::Protocol)
    ));
    let other_generation = DeliveryPosition {
        delivery_generation: good.delivery_generation + 1,
        ..good
    };
    assert!(matches!(
        on_ack(&mut fixture, LinkId::new(1), other_generation)?,
        Err(CompanionFault::Protocol)
    ));
    let unknown_event = DeliveryPosition {
        event_id: [0xEE; 16],
        ..good
    };
    assert!(on_ack(&mut fixture, LinkId::new(1), unknown_event)?.is_err());
    assert!(
        fixture
            .coordinator
            .companion_exec
            .as_ref()
            .ok_or("executor")?
            .pending
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn a_pending_ack_admits_only_its_own_repeat() -> TestResult {
    let (mut fixture, _queue) = Box::pin(resumed()).await?;
    let first = position(&fixture, 0)?;
    let actions = on_ack(&mut fixture, LinkId::new(1), first)?.map_err(|e| format!("{e:?}"))?;
    assert!(!actions.is_empty());
    for action in actions {
        companion::apply(
            &mut fixture.coordinator,
            fixture.core.context_mut()?,
            LinkId::new(1),
            PEER,
            action,
        )
        .map_err(|e| format!("apply ACK: {e:?}"))?;
    }
    assert!(
        fixture
            .coordinator
            .companion_exec
            .as_ref()
            .ok_or("executor")?
            .pending
            .is_some()
    );
    let repeat = on_ack(&mut fixture, LinkId::new(1), first)?.map_err(|e| format!("{e:?}"))?;
    assert!(repeat.is_empty(), "the same ACK joins the pending work");
    let second = position(&fixture, 1)?;
    assert!(matches!(
        on_ack(&mut fixture, LinkId::new(1), second)?,
        Err(CompanionFault::Protocol)
    ));
    Ok(())
}
