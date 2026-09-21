#![forbid(unsafe_code)]

use super::*;

fn receive_projected(
    fixture: &mut PrefixFixture,
    sequence: u64,
    projected: ProjectedEvent,
) -> TestResult {
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: sequence.checked_add(10).ok_or("generation")?,
        delivery_sequence: sequence,
        event_id: event_identity(sequence)?,
        event_kind: projected.kind(),
        correlation: None,
        cross_profile: None,
    };
    let bytes = header
        .build(&event_arm_object(&projected)?)?
        .encode_canonical()?;
    let descriptor = agenc_relay_federation_wire::EventDescriptor {
        target_server_id: EDGE,
        delivery_sequence: sequence,
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
    .map_err(|error| format!("projected event: {error:?}"))?;
    Ok(())
}

#[tokio::test]
async fn an_ordinary_prefix_coalesces_repeated_projection_keys_at_one_revision() -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    fixture.receive(0)?;
    for sequence in 1_u64..=2 {
        let mut record = fixture
            .edge
            .replica
            .session(fixture.recipient)
            .ok_or("session")?
            .clone();
        record.session_revision = Revision::new(sequence.checked_add(10).ok_or("revision")?)?;
        record.user_mode_bits = if sequence == 1 { 3 } else { 1 };
        receive_projected(
            &mut fixture,
            sequence,
            ProjectedEvent::UserModesChanged(record),
        )?;
    }
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::OrdinaryBatch(_))
    ));
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    assert_next_ack(&mut fixture.queue, 2).await?;
    let record = fixture
        .edge
        .replica
        .session(fixture.recipient)
        .ok_or("session")?;
    assert_eq!(record.session_revision, Revision::new(12)?);
    assert_eq!(record.user_mode_bits, 1);
    Ok(())
}

#[tokio::test]
async fn a_created_then_removed_projection_never_deletes_an_absent_durable_row() -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    fixture.receive(0)?;
    let channel_id = ChannelInstanceId::from_bytes([73; 16]);
    receive_projected(
        &mut fixture,
        1,
        ProjectedEvent::ChannelVisible(ChannelDetailRecord {
            channel_id,
            name: ChannelNameValue::parse("#temporary")?,
            channel_revision: Revision::new(11)?,
            visibility: Visibility::Listed,
            content_policy: ContentPolicy::Plaintext,
            persistence: PersistencePolicy::Ephemeral,
            simple_mode_bits: 4,
            history: HistoryPolicy::Off,
            e2ee_route_binding: None,
        }),
    )?;
    receive_projected(
        &mut fixture,
        2,
        ProjectedEvent::ChannelHidden {
            channel_id,
            last_revision: Revision::new(11)?,
        },
    )?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    assert_next_ack(&mut fixture.queue, 2).await?;
    assert!(fixture.edge.replica.channel(channel_id).is_none());
    let key = agenc_relay_storage::federation_records::projection_entry_key(
        EDGE,
        1,
        agenc_relay_domain::federation::ProjectionKey::CHANNEL_DETAIL,
        channel_id.as_bytes(),
    )?;
    assert!(
        fixture
            .core
            .context_mut()?
            .index()
            .existing(agenc_relay_storage::TableId::EdgeProjection, &key)?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn a_malformed_later_ordinary_event_rolls_back_the_whole_tentative_prefix() -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    fixture.receive(0)?;
    let before = fixture.edge.replica.clone();
    let mut record = fixture
        .edge
        .replica
        .session(fixture.recipient)
        .ok_or("session")?
        .clone();
    record.session_revision = Revision::new(11)?;
    record.user_mode_bits = 3;
    receive_projected(&mut fixture, 1, ProjectedEvent::UserModesChanged(record))?;
    receive_projected(
        &mut fixture,
        2,
        ProjectedEvent::ChannelHidden {
            channel_id: ChannelInstanceId::from_bytes([74; 16]),
            last_revision: Revision::new(11)?,
        },
    )?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert_outputs(&fixture.sink, 1);
    assert!(fixture.edge.replica == before);
    assert_eq!(fixture.edge.phase, Phase::Down);
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_eq!(fixture.edge.cursor, Some((0, event_identity(0)?)));
    Ok(())
}

#[tokio::test]
async fn exhausted_aggregate_backing_falls_back_to_single_event_admission_and_refunds() -> TestResult
{
    let mut fixture = PrefixFixture::new()?;
    let baseline = fixture_backing_available(fixture.core.context_mut()?);
    fixture.receive(0)?;
    fixture.receive(1)?;
    fixture.receive(2)?;
    fixture.core.commit_staged_batch().await?;
    let mut held = exhaust_fixture_backing(fixture.core.context_mut()?);
    let largest = held.first().ok_or("fixture permit")?.bytes();
    let remainder = largest
        .checked_sub(16_384 + 256)
        .ok_or("fixture allowance")?;
    drop(held.remove(0));
    held.push(
        fixture
            .core
            .context_mut()?
            .reserve_output_backing(usize::try_from(remainder)?)?,
    );
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::Event { .. })
    ));
    assert_eq!(fixture.edge.phase, Phase::Active);
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 2).await?;
    assert_outputs(&fixture.sink, 3);
    drop(held);
    assert_eq!(
        fixture_backing_available(fixture.core.context_mut()?),
        baseline
    );
    Ok(())
}
