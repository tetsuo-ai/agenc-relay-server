//! Retained acknowledged barrier events survive the production storage loader.
#![forbid(unsafe_code)]

use super::*;

pub(super) async fn acknowledge_copy(fixture: &mut RestartFixture, index: usize) -> TestResult {
    let copy = fixture.copies.get(index).ok_or("copy")?;
    let position = DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: copy.generation,
        delivery_sequence: copy.row.sequence,
        event_id: copy.row.event_id,
    };
    let actions = fixture.frame(CompanionFrame::Ack(position))?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("acknowledgement must stage".into());
    };
    fixture.coordinator.set_pending(work);
    fixture.commit(writes).await?;
    assert!(matches!(
        fixture.coordinator.batch_applied(Some(0))?,
        Some(Committed::Acknowledged(_))
    ));
    Ok(())
}

pub(super) async fn append_barrier(fixture: &mut RestartFixture) -> TestResult {
    let plan = EventPlan::order(
        [7, 8]
            .into_iter()
            .map(|seed| PlannedEvent {
                kind: EventKind::RouteStateHidden,
                conversation_id: Some([seed; 32]),
                target: home(),
                payload_object_id: None,
                completion: false,
                route_sequence: 0,
                bytes: 1024,
            })
            .collect(),
    )?;
    let contents = plan
        .events()
        .iter()
        .cloned()
        .map(|planned| EventContent {
            planned,
            origin: None,
            source_view: Vec::new(),
            correlation: None,
            encoded_result: Vec::new(),
            payload: None,
        })
        .collect::<Vec<_>>();
    let assignments = BTreeMap::from([(
        home(),
        events::BarrierAssignment {
            mutation_id: [91; 16],
            base_parts: 1,
            part_count: 3,
        },
    )]);
    let sequenced = events::sequence_copies(
        &fixture.coordinator,
        &plan,
        &contents,
        42,
        &mut fixture.entropy,
        &assignments,
        &fixture.storage.context_mut()?.backing_reservations(),
    )
    .map_err(|error| format!("barrier sequence: {error:?}"))?;
    fixture.commit(sequenced.writes).await?;
    fixture.coordinator.state.streams.extend(sequenced.streams);
    fixture.copies = sequenced.copies;
    Ok(())
}

#[tokio::test]
async fn acknowledged_barrier_rows_restart_with_exact_bytes_and_receipt_coverage() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    acknowledge_copy(&mut fixture, 0).await?;
    acknowledge_copy(&mut fixture, 1).await?;
    append_barrier(&mut fixture).await?;
    assert!(acknowledge_copy(&mut fixture, 0).await.is_err());
    acknowledge_copy(&mut fixture, 1).await?;
    let backing = fixture.storage.context_mut()?.backing_reservations();
    let expected = fixture
        .coordinator
        .state
        .streams
        .iter()
        .map(|(peer, stream)| stream.try_clone(0, &backing).map(|stream| (*peer, stream)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    fixture.restart().await?;
    assert_eq!(fixture.coordinator.state.streams, expected);
    assert!(!fixture.coordinator.delivering(home()));
    let last = fixture.copies.last().ok_or("last barrier part")?;
    let actions = fixture.frame(CompanionFrame::Resume {
        coordinator_server_id: *fixture.storage.identity.server_id.as_bytes(),
        server_incarnation: INCARNATION,
        delivery_generation: last.generation,
        last: Some((last.row.sequence, last.row.event_id)),
    })?;
    assert!(matches!(
        frames(&actions)?.first(),
        Some(CompanionFrame::ResumeOk { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn an_unacknowledged_barrier_without_its_combined_owner_still_refuses_restart() -> TestResult
{
    let mut fixture = RestartFixture::new().await?;
    acknowledge_copy(&mut fixture, 0).await?;
    acknowledge_copy(&mut fixture, 1).await?;
    append_barrier(&mut fixture).await?;
    assert!(fixture.restart().await.is_err());
    Ok(())
}
