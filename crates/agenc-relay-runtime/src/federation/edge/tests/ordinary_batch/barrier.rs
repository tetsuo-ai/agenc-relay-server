#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn an_ordinary_prefix_stops_before_a_cross_profile_part() -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    for sequence in 0..=2 {
        fixture.receive(sequence)?;
    }
    let event = ProjectedEvent::NetworkNotice {
        code: "TEST".to_owned(),
        text: "cross profile boundary".to_owned(),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: 13,
        delivery_sequence: 3,
        event_id: event_identity(3)?,
        event_kind: event.kind(),
        correlation: None,
        cross_profile: Some(agenc_relay_federation_wire::CrossProfilePart {
            mutation_id: [81; 16],
            part_index: 0,
            part_count: 2,
        }),
    };
    let bytes = header
        .build(&event_arm_object(&event)?)?
        .encode_canonical()?;
    let descriptor = agenc_relay_federation_wire::EventDescriptor {
        target_server_id: EDGE,
        delivery_sequence: 3,
        event_id: header.event_id,
        object_id: federation_object_id(bytes.as_slice()),
    };
    let object = resync_assembled(bytes.as_slice(), |fragment| FederationFrame::Event {
        descriptor,
        fragment,
    })?;
    events::receive(
        &mut fixture.edge,
        fixture.core.context_mut()?,
        descriptor,
        &object,
    )
    .map_err(|error| format!("barrier event: {error:?}"))?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    let Some(PendingCommit::OrdinaryBatch(pending)) = &fixture.edge.commit else {
        return Err("ordinary prefix missing".into());
    };
    assert_eq!(pending.receipts.len(), 2);
    assert_eq!(fixture.edge.queued_events.len(), 1);
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    assert_next_ack(&mut fixture.queue, 2).await?;
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::BarrierPart(_))
    ));
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_no_ack(&mut fixture.queue).await?;
    assert_outputs(&fixture.sink, 3);
    assert_eq!(fixture.edge.cursor, Some((2, event_identity(2)?)));
    assert!(fixture.edge.barrier.is_open());
    Ok(())
}
