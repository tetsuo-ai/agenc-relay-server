#![forbid(unsafe_code)]

use super::*;
use crate::federation::codec::operations::JoinTarget;

const JOIN_CHANNEL: ChannelInstanceId = ChannelInstanceId::from_bytes([80; 16]);

async fn join_fixture() -> TestResult<(PrefixFixture, RequestHeader)> {
    let mut fixture = PrefixFixture::new()?;
    let session = fixture
        .edge
        .replica
        .session(fixture.recipient)
        .ok_or("session")?
        .clone();
    fixture.edge.phase = Phase::Down;
    let generation = ConnectionGeneration::new(1);
    fixture
        .edge
        .connection_opened(fixture.core.context_mut()?, generation);
    let previous = journal::origin_record(&fixture.edge, generation)
        .map_err(|error| format!("initial origin: {error:?}"))?;
    let origin = fixture.edge.origins.get_mut(&generation).ok_or("origin")?;
    origin.generation = 1;
    origin.previous_object_id = previous.origin_object_id;
    origin.session = Some((session.session_id, session.user_id));
    origin.acked_generation = Some(1);
    journal::origin_record(&fixture.edge, generation)
        .map_err(|error| format!("session origin: {error:?}"))?;
    let operation = FederatedOperation::Join {
        session_id: session.session_id,
        expected_session_revision: 1,
        targets: vec![JoinTarget {
            channel_name: "#joined".to_owned(),
            join_key: zeroize::Zeroizing::new(Vec::new()),
        }],
    };
    let prepared = request::prepare_request(
        &mut fixture.edge,
        fixture.core.context_mut()?,
        generation,
        &operation,
    )
    .map_err(|error| format!("request preparation: {error:?}"))?;
    let header = prepared.1;
    let message = parse_message(FramedLine::new("JOIN #joined")?)?.ok_or("JOIN")?;
    request::register_request(
        &mut fixture.edge,
        fixture.core.context_mut()?,
        generation,
        prepared,
        request::PendingKind::Command {
            message: Box::new(message),
        },
    );
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    fixture.edge.phase = Phase::Active;
    assert!(fixture.edge.commit.is_none());
    assert!(journal::is_durable(
        &fixture.edge,
        journal::Identity::Request(header.request_id)
    ));
    assert_no_ack(&mut fixture.queue).await?;
    Ok((fixture, header))
}

fn joined(recipient: UserId, generation: u64) -> TestResult<ProjectedEvent> {
    Ok(ProjectedEvent::MemberJoined {
        view: MembershipView {
            membership: MembershipRecord {
                channel_id: JOIN_CHANNEL,
                user_id: recipient,
                role: Role::Owner,
                membership_revision: Revision::new(generation)?,
                joined_at: UtcSecond::from_unix_seconds(5),
            },
            source: source(recipient, "recipient", 1)?,
        },
        home_session_revision: Some(Revision::new(generation)?),
        display_name: DisplayNameValue::prepare("Recipient")?,
    })
}

fn join_event(
    fixture: &mut PrefixFixture,
    sequence: u64,
    generation: u64,
    projected: ProjectedEvent,
    request: Option<RequestHeader>,
) -> TestResult {
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: generation,
        delivery_sequence: sequence,
        event_id: event_identity(sequence)?,
        event_kind: projected.kind(),
        correlation: request.map(|request| RequestCorrelation {
            replay_key: request.replay_key,
            request_id: request.request_id,
        }),
        cross_profile: None,
    };
    let bytes = header
        .build(&event_arm_object(&projected)?)?
        .encode_canonical()?;
    let descriptor = agenc_ircd_federation_wire::EventDescriptor {
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
    .map_err(|error| format!("JOIN event: {error:?}"))?;
    Ok(())
}

#[tokio::test]
async fn a_tentative_join_echo_requires_the_same_completion_generation_before_staging() -> TestResult
{
    for valid in [false, true] {
        let (mut fixture, header) = join_fixture().await?;
        fixture.receive(0)?;
        join_event(&mut fixture, 1, 11, visible(11)?, None)?;
        let event = joined(fixture.recipient, 11)?;
        join_event(&mut fixture, 2, 11, event, None)?;
        let generation = if valid { 11 } else { 12 };
        join_event(
            &mut fixture,
            3,
            generation,
            ProjectedEvent::RequestCompleted {
                resulting_state_generation: generation,
            },
            Some(header),
        )?;
        fixture.core.commit_staged_batch().await?;
        fixture.settle_edge()?;
        assert_next_ack(&mut fixture.queue, 0).await?;
        assert_outputs(&fixture.sink, 1);
        assert_eq!(
            matches!(fixture.edge.commit, Some(PendingCommit::OrdinaryBatch(_))),
            valid
        );
        if valid {
            fixture.core.commit_staged_batch().await?;
            fixture.settle_edge()?;
            assert_next_ack(&mut fixture.queue, 1).await?;
            assert_next_ack(&mut fixture.queue, 2).await?;
            assert_next_ack(&mut fixture.queue, 3).await?;
            assert_eq!(
                fixture
                    .edge
                    .pending
                    .get(&header.request_id)
                    .ok_or("pending")?
                    .join_echoes
                    .len(),
                1
            );
        } else {
            assert_eq!(fixture.edge.phase, Phase::Down);
            assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_join_echo_cannot_follow_its_completion_in_the_same_prefix() -> TestResult {
    let (mut fixture, header) = join_fixture().await?;
    fixture.receive(0)?;
    join_event(&mut fixture, 1, 11, visible(11)?, None)?;
    join_event(
        &mut fixture,
        2,
        11,
        ProjectedEvent::RequestCompleted {
            resulting_state_generation: 11,
        },
        Some(header),
    )?;
    let event = joined(fixture.recipient, 11)?;
    join_event(&mut fixture, 3, 11, event, None)?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert_eq!(fixture.edge.phase, Phase::Down);
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_outputs(&fixture.sink, 1);
    Ok(())
}

fn visible(generation: u64) -> TestResult<ProjectedEvent> {
    Ok(ProjectedEvent::ChannelVisible(ChannelDetailRecord {
        channel_id: JOIN_CHANNEL,
        name: ChannelNameValue::parse("#joined")?,
        channel_revision: Revision::new(generation)?,
        visibility: Visibility::Listed,
        content_policy: ContentPolicy::Plaintext,
        persistence: PersistencePolicy::Ephemeral,
        simple_mode_bits: 4,
        history: HistoryPolicy::Off,
        e2ee_route_binding: None,
    }))
}

#[tokio::test]
async fn a_join_echo_cannot_follow_an_already_durable_completion() -> TestResult {
    let (mut fixture, header) = join_fixture().await?;
    join_event(
        &mut fixture,
        0,
        10,
        ProjectedEvent::RequestCompleted {
            resulting_state_generation: 10,
        },
        Some(header),
    )?;
    join_event(&mut fixture, 1, 10, visible(10)?, None)?;
    let event = joined(fixture.recipient, 10)?;
    join_event(&mut fixture, 2, 10, event, None)?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert_eq!(fixture.edge.phase, Phase::Down);
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_outputs(&fixture.sink, 0);
    Ok(())
}

fn receive_join_result(
    fixture: &mut PrefixFixture,
    request: RequestHeader,
    generation: u64,
) -> TestResult<Vec<EdgeCompletion>> {
    let pending = fixture
        .edge
        .pending
        .get(&request.request_id)
        .ok_or("pending")?;
    let header = ResultHeader {
        network_id: NETWORK,
        replay_key: request.replay_key,
        request_id: request.request_id,
        request_object_id: federation_object_id(&pending.bytes),
        completion_event_id: Some(event_identity(3)?),
        result_kind: agenc_ircd_types::FederationResultKind::Committed,
    };
    let frame = agenc_ircd_client_wire::numeric_reply(
        COORDINATOR_NAME,
        331,
        "recipient",
        &["#joined"],
        Some("No topic is set"),
    )?;
    let bytes = header
        .build(
            &ResultArm::Committed {
                resulting_state_generation: generation,
            }
            .to_object()?,
            vec![reply_object(&frame)?],
        )?
        .encode_canonical()?;
    let descriptor = OperationDescriptor {
        addressed_server_id: EDGE,
        server_incarnation: request.replay_key.server_incarnation,
        origin_id: request.replay_key.origin_id,
        origin_generation: request.replay_key.origin_generation,
        operation_sequence: request.replay_key.operation_sequence,
        request_id: request.request_id,
        object_id: federation_object_id(bytes.as_slice()),
    };
    let object = resync_assembled(bytes.as_slice(), |fragment| FederationFrame::Result {
        descriptor,
        fragment,
    })?;
    request::receive_result(
        &mut fixture.edge,
        fixture.core.context_mut()?,
        descriptor,
        &object,
    )
    .map_err(|error| format!("JOIN result: {error:?}").into())
}

#[tokio::test]
async fn a_batched_join_meets_results_before_or_after_its_receipt_exactly_once() -> TestResult {
    for early in [true, false] {
        let (mut fixture, request) = join_fixture().await?;
        fixture.receive(0)?;
        join_event(&mut fixture, 1, 11, visible(11)?, None)?;
        let event = joined(fixture.recipient, 11)?;
        join_event(&mut fixture, 2, 11, event, None)?;
        join_event(
            &mut fixture,
            3,
            11,
            ProjectedEvent::RequestCompleted {
                resulting_state_generation: 11,
            },
            Some(request),
        )?;
        fixture.core.commit_staged_batch().await?;
        fixture.settle_edge()?;
        assert_next_ack(&mut fixture.queue, 0).await?;
        if early {
            assert!(receive_join_result(&mut fixture, request, 11)?.is_empty());
        }
        assert_outputs(&fixture.sink, 1);
        fixture.core.commit_staged_batch().await?;
        let mut completions = fixture.edge.batch_applied(fixture.core.context_mut()?);
        for sequence in 1..=3 {
            assert_next_ack(&mut fixture.queue, sequence).await?;
        }
        if !early {
            completions.extend(receive_join_result(&mut fixture, request, 11)?);
        }
        for _ in 0..3 {
            if fixture.core.context_mut()?.pending_len() == 0 {
                break;
            }
            fixture.core.commit_staged_batch().await?;
            completions.extend(fixture.edge.batch_applied(fixture.core.context_mut()?));
        }
        assert_eq!(completions.len(), 1);
        let Some(EdgeCompletion::JoinCommitted {
            frames,
            echo_permits,
            ..
        }) = completions.first()
        else {
            return Err("covered JOIN response missing".into());
        };
        assert_eq!(
            frames.iter().map(WireMessage::command).collect::<Vec<_>>(),
            ["JOIN", "331"]
        );
        assert_eq!(echo_permits.len(), 1);
        assert!(!fixture.edge.pending.contains_key(&request.request_id));
        assert_outputs(&fixture.sink, 1);
        assert_eq!(fixture.edge.phase, Phase::Active);
    }
    Ok(())
}

#[tokio::test]
async fn a_durable_join_echo_requires_the_same_batched_completion_generation() -> TestResult {
    let (mut fixture, request) = join_fixture().await?;
    fixture.receive(0)?;
    join_event(&mut fixture, 1, 11, visible(11)?, None)?;
    let event = joined(fixture.recipient, 11)?;
    join_event(&mut fixture, 2, 11, event, None)?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    assert_next_ack(&mut fixture.queue, 2).await?;
    assert_eq!(
        fixture
            .edge
            .pending
            .get(&request.request_id)
            .ok_or("pending")?
            .join_echoes
            .len(),
        1
    );
    fixture.receive(3)?;
    assert!(
        join_event(
            &mut fixture,
            4,
            14,
            ProjectedEvent::RequestCompleted {
                resulting_state_generation: 14,
            },
            Some(request),
        )
        .is_err()
    );
    assert!(fixture.edge.queued_events.is_empty());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 1);
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 3).await?;
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_eq!(fixture.sink.lines().len(), 2);
    assert_no_ack(&mut fixture.queue).await?;
    Ok(())
}

#[tokio::test]
async fn a_single_completion_cannot_bypass_durable_join_echo_validation() -> TestResult {
    let (mut fixture, request) = join_fixture().await?;
    join_event(&mut fixture, 0, 11, visible(11)?, None)?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    let event = joined(fixture.recipient, 11)?;
    join_event(&mut fixture, 1, 11, event, None)?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    assert_eq!(
        fixture
            .edge
            .pending
            .get(&request.request_id)
            .ok_or("pending")?
            .join_echoes
            .len(),
        1
    );
    assert!(
        join_event(
            &mut fixture,
            2,
            12,
            ProjectedEvent::RequestCompleted {
                resulting_state_generation: 12,
            },
            Some(request)
        )
        .is_err()
    );
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_eq!(fixture.sink.lines().len(), 0);
    assert_no_ack(&mut fixture.queue).await?;
    Ok(())
}

#[tokio::test]
async fn coalescing_cannot_hide_a_repeated_requester_join_echo() -> TestResult {
    let (mut fixture, _) = join_fixture().await?;
    fixture.receive(0)?;
    join_event(&mut fixture, 1, 11, visible(11)?, None)?;
    let event = joined(fixture.recipient, 11)?;
    join_event(&mut fixture, 2, 11, event, None)?;
    let departed = ProjectedEvent::MemberParted {
        channel_id: JOIN_CHANNEL,
        source: source(fixture.recipient, "recipient", 1)?,
        resulting_revision: Revision::new(11)?,
        home_session_revision: Some(Revision::new(11)?),
        reason: String::new(),
    };
    join_event(&mut fixture, 3, 11, departed, None)?;
    let event = joined(fixture.recipient, 11)?;
    join_event(&mut fixture, 4, 11, event, None)?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert_eq!(fixture.edge.phase, Phase::Down);
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_outputs(&fixture.sink, 1);
    let close =
        tokio::time::timeout(std::time::Duration::from_secs(1), fixture.queue.recv()).await?;
    assert!(
        close.is_none(),
        "a refused prefix published a frame before closing"
    );
    assert_eq!(fixture.handle.queued_bytes(), 0);
    Ok(())
}
