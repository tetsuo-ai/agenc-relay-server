#![forbid(unsafe_code)]

//! Event receipts must persist every revision changed by a membership event.

use super::*;
use agenc_ircd_domain::federation::{DeliveredMessageRecord, DeliveryTarget, ProjectionRecord};
use agenc_ircd_types::MessageId;

const MEMBER: UserId = UserId::from_bytes([71; 16]);
const CHANNEL: ChannelInstanceId = ChannelInstanceId::from_bytes([72; 16]);

fn deliver(
    edge: &mut EdgeFederation,
    core: &mut StateCoreFixture,
    sequence: u64,
    event: ProjectedEvent,
) -> TestResult {
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: sequence + 10,
        delivery_sequence: sequence,
        event_id: EventId::from_bytes([u8::try_from(sequence)? + 80; 16]),
        event_kind: event.kind(),
        correlation: None,
        cross_profile: None,
    };
    let bytes = header
        .build(&event_arm_object(&event)?)?
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
    events::receive(edge, core.context_mut()?, descriptor, &object)
        .map_err(|error| format!("delivery {sequence}: {error:?}"))?;
    Ok(())
}

fn notice() -> ProjectedEvent {
    ProjectedEvent::NetworkNotice {
        code: "TEST".to_owned(),
        text: "checkpoint".to_owned(),
    }
}

async fn joined_restart(coalesce: bool) -> TestResult<(StateCoreFixture, EdgeFederation)> {
    let mut core = StateCoreFixture::new(entropy_script())?;
    let mut edge = resync_edge();
    edge.replica.install(1, Vec::<ProjectionRecord>::new())?;
    let _queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Active;
    edge.accepted_epoch = Some(COORDINATOR_EPOCH);
    edge.installed_epoch = Some(COORDINATOR_EPOCH);
    edge.installed_incarnation = Some(HUB_INCARNATION);
    assert!(!edge.peer_record(None).snapshot_required);
    deliver(
        &mut edge,
        &mut core,
        0,
        ProjectedEvent::SessionVisible(SessionEventView {
            source: source(MEMBER, "kept", 1)?,
            home_projection: Some(session_record(
                SessionId::from_bytes([73; 16]),
                MEMBER,
                "kept",
                10,
                1,
            )?),
        }),
    )?;
    commit_edge_batches(&mut edge, &mut core).await?;
    deliver(
        &mut edge,
        &mut core,
        1,
        ProjectedEvent::ChannelVisible(ChannelDetailRecord {
            channel_id: CHANNEL,
            name: ChannelNameValue::parse("#kept")?,
            channel_revision: Revision::new(11)?,
            visibility: Visibility::Listed,
            content_policy: ContentPolicy::Plaintext,
            persistence: PersistencePolicy::Ephemeral,
            simple_mode_bits: 4,
            history: HistoryPolicy::Off,
            e2ee_route_binding: None,
        }),
    )?;
    commit_edge_batches(&mut edge, &mut core).await?;
    deliver(&mut edge, &mut core, 2, notice())?;
    if !coalesce {
        commit_edge_batches(&mut edge, &mut core).await?;
    }
    deliver(
        &mut edge,
        &mut core,
        3,
        ProjectedEvent::MemberJoined {
            view: MembershipView {
                membership: MembershipRecord {
                    channel_id: CHANNEL,
                    user_id: MEMBER,
                    role: Role::Owner,
                    membership_revision: Revision::new(13)?,
                    joined_at: UtcSecond::from_unix_seconds(5),
                },
                source: source(MEMBER, "kept", 1)?,
            },
            home_session_revision: Some(Revision::new(13)?),
            display_name: DisplayNameValue::prepare("Kept")?,
        },
    )?;
    if !coalesce {
        commit_edge_batches(&mut edge, &mut core).await?;
    }
    deliver(&mut edge, &mut core, 4, notice())?;
    if coalesce {
        core.commit_staged_batch().await?;
        edge.batch_applied(core.context_mut()?);
        assert!(matches!(edge.commit, Some(PendingCommit::OrdinaryBatch(_))));
    }
    commit_edge_batches(&mut edge, &mut core).await?;
    assert_eq!(
        edge.replica
            .channel(CHANNEL)
            .ok_or("live channel")?
            .channel_revision,
        Revision::new(13)?
    );
    assert_eq!(
        edge.replica
            .session(MEMBER)
            .ok_or("live session")?
            .session_revision,
        Revision::new(13)?
    );
    let mut restarted = resync_edge();
    core.restore_edge_state(&mut restarted, None)?;
    assert_eq!(restarted.cursor, edge.cursor);
    assert!(restarted.replica.membership(CHANNEL, MEMBER).is_some());
    Ok((core, restarted))
}

async fn message_after_restart(coalesce: bool) -> TestResult {
    let (mut core, mut edge) = joined_restart(coalesce).await?;
    let _queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Origins;
    deliver(
        &mut edge,
        &mut core,
        5,
        ProjectedEvent::MessageDelivered(DeliveredMessageRecord {
            message_id: MessageId::from_bytes([74; 16]),
            kind: agenc_ircd_domain::MessageKind::Privmsg,
            target: DeliveryTarget::Channel(CHANNEL),
            sender: source(MEMBER, "kept", 1)?,
            target_revision: Revision::new(13)?,
            channel_event_sequence: 1,
            received_unix_milliseconds: 1_000,
            tags: Vec::new(),
            body: "after restart".to_owned(),
        }),
    )?;
    commit_edge_batches(&mut edge, &mut core).await?;
    assert_eq!(edge.cursor.map(|(sequence, _)| sequence), Some(5));
    Ok(())
}

#[tokio::test]
async fn a_single_join_receipt_preserves_the_channel_revision_for_replay() -> TestResult {
    message_after_restart(false).await
}

#[tokio::test]
async fn a_batched_join_receipt_preserves_the_channel_revision_for_replay() -> TestResult {
    message_after_restart(true).await
}

#[tokio::test]
async fn a_single_join_receipt_preserves_the_home_session_revision() -> TestResult {
    let (_core, edge) = joined_restart(false).await?;
    assert_eq!(
        edge.replica
            .session(MEMBER)
            .ok_or("restored session")?
            .session_revision,
        Revision::new(13)?
    );
    Ok(())
}

#[tokio::test]
async fn a_batched_join_receipt_preserves_the_home_session_revision() -> TestResult {
    let (_core, edge) = joined_restart(true).await?;
    assert_eq!(
        edge.replica
            .session(MEMBER)
            .ok_or("restored session")?
            .session_revision,
        Revision::new(13)?
    );
    Ok(())
}
