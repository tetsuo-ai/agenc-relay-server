//! Real replay pages cannot publish rows beyond an unfinished combined barrier.
#![forbid(unsafe_code)]

use super::*;
use crate::federation::link::{ParsedLine, parse_line};
use std::collections::{BTreeMap, BTreeSet};

async fn append_later(fixture: &mut Fixture) -> TestResult {
    fixture.core.context_mut()?.install_federation_projector(
        crate::state_core::projector::FederationProjector::new(NETWORK, COORDINATOR),
    );
    let event = PlannedEvent {
        kind: EventKind::RouteStateHidden,
        conversation_id: Some([9; 32]),
        target: PEER,
        payload_object_id: None,
        completion: false,
        route_sequence: 0,
        bytes: 1024,
    };
    let plan = EventPlan::order(vec![event.clone()])?;
    let contents = vec![EventContent {
        planned: event,
        origin: None,
        source_view: Vec::new(),
        correlation: None,
        encoded_result: Vec::new(),
        payload: None,
    }];
    let sequenced = events::sequence_copies(
        fixture
            .coordinator
            .companion_exec
            .as_ref()
            .ok_or("executor")?,
        &plan,
        &contents,
        2,
        fixture.core.context_mut()?.entropy_mut(),
        &BTreeMap::new(),
    )
    .map_err(|e| format!("later companion: {e:?}"))?;
    assert_eq!(
        sequenced.copies.first().ok_or("later copy")?.row.sequence,
        2
    );
    let mut writes = sequenced.writes;
    let event = ProjectedEvent::NetworkNotice {
        code: "LATER".to_owned(),
        text: "after the barrier".to_owned(),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: PEER,
        projection_generation: 0,
        coordinator_state_generation: 2,
        delivery_sequence: 2,
        event_id: agenc_ircd_types::EventId::from_bytes([63; 16]),
        event_kind: event.kind(),
        correlation: None,
        cross_profile: None,
    };
    let arm = crate::federation::codec::events::event_arm_object(&event)?;
    let bytes = header.build(&arm)?.encode_canonical()?.as_slice().to_vec();
    let record = OutboxEventRecord {
        event_id: *header.event_id.as_bytes(),
        event_object_id: *federation_object_id(&bytes).as_bytes(),
        event_object: bytes,
        coordinator_state_generation: 2,
        acknowledged: false,
        completion_replay_key: None,
    };
    let value = PersistentRecordValue::new(
        TableId::EdgeOutbox,
        OUTBOX_EVENT_KIND,
        2,
        0,
        None,
        Vec::new(),
        record.encode()?,
    )?;
    writes.push(AccountServiceDurableWrite::put(
        TableId::EdgeOutbox,
        outbox_key(PEER, 0, 2)?,
        value.encode()?,
    )?);
    fixture
        .coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .outbox
        .reserved_next = 3;
    writes.push(fixture.coordinator.peer_row_at(PEER, 2, None)?);
    fixture.commit(writes).await?;
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    Ok(())
}

async fn finish_base_reads(fixture: &mut Fixture) -> TestResult {
    for _ in 0..8 {
        if fixture
            .coordinator
            .peers
            .get(&PEER)
            .ok_or("peer")?
            .resend
            .is_none()
        {
            return Ok(());
        }
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fixture.core.next_storage_read(),
        )
        .await??;
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, message);
    }
    Err("bounded resend did not finish".into())
}

async fn positions(
    queue: &mut crate::federation::link::LinkQueue,
) -> TestResult<(BTreeSet<u64>, BTreeSet<u64>)> {
    let mut base = BTreeSet::new();
    let mut companion = BTreeSet::new();
    while let Ok(Some(line)) =
        tokio::time::timeout(std::time::Duration::from_millis(10), queue.recv()).await
    {
        match parse_line(
            line.as_str().strip_suffix("\r\n").ok_or("line ending")?,
            COORDINATOR_NAME,
        )
        .map_err(|e| format!("parse: {e:?}"))?
        {
            ParsedLine::Base(FederationFrame::Event { descriptor, .. }) => {
                base.insert(descriptor.delivery_sequence);
            }
            ParsedLine::Companion(CompanionFrame::Event { position, .. }) => {
                companion.insert(position.delivery_sequence);
            }
            _ => {}
        }
    }
    Ok((base, companion))
}

#[tokio::test]
async fn replay_holds_later_rows_on_both_streams_until_the_second_receipt() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    append_later(&mut fixture).await?;
    let (handle, mut queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        incarnation: INCARNATION,
    });
    snapshot::resume(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        LinkId::new(1),
        PEER,
        0,
        agenc_ircd_federation_wire::DeliveryCursor::Empty,
    )
    .map_err(|e| format!("base resume: {e:?}"))?;
    finish_base_reads(&mut fixture).await?;
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
    .map_err(|e| format!("companion resume: {e:?}"))?;
    assert_eq!(
        positions(&mut queue).await?,
        (BTreeSet::from([0, 1]), BTreeSet::from([0, 1]))
    );
    fixture.stage_base_ack()?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert_eq!(
        positions(&mut queue).await?,
        (BTreeSet::new(), BTreeSet::new())
    );
    companion::admitted(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        LinkId::new(1),
        PEER,
        CompanionFrame::Ack(agenc_ircd_e2ee::federation::frames::DeliveryPosition {
            server_id: *COORDINATOR.as_bytes(),
            delivery_generation: 0,
            delivery_sequence: 1,
            event_id: fixture.gate.companion().final_event_id(),
        }),
    )
    .map_err(|e| format!("companion ACK: {e:?}"))?;
    fixture.core.commit_staged_batch().await?;
    assert_eq!(
        positions(&mut queue).await?,
        (BTreeSet::new(), BTreeSet::new())
    );
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    finish_base_reads(&mut fixture).await?;
    assert_eq!(
        positions(&mut queue).await?,
        (BTreeSet::from([2]), BTreeSet::from([2]))
    );
    assert!(fixture.stored_gate().await?.is_none());
    Ok(())
}
