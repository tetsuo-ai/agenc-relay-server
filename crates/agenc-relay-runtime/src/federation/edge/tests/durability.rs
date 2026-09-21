#![forbid(unsafe_code)]

//! Base event output must remain behind the durable batch.

use agenc_relay_client_wire::CapabilityState;
use agenc_relay_domain::federation::{DeliveredMessageRecord, DeliveryTarget, ProjectionRecord};
use agenc_relay_types::MessageId;

use super::*;
use crate::state_core::inbox::SignalEvent;
use crate::test_support::{bind_live_session, seed_session};

mod completion;

fn event_object(
    event: &ProjectedEvent,
) -> TestResult<(
    agenc_relay_federation_wire::EventDescriptor,
    AssembledObject,
)> {
    let event_id = EventId::from_bytes([17; 16]);
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: 10,
        delivery_sequence: 0,
        event_id,
        event_kind: event.kind(),
        correlation: None,
        cross_profile: None,
    };
    let arm = event_arm_object(event).map_err(|error| format!("event arm: {error:?}"))?;
    let encoded = header
        .build(&arm)
        .map_err(|error| format!("event header: {error:?}"))?
        .encode_canonical()?;
    let object_id = federation_object_id(encoded.as_slice());
    let descriptor = agenc_relay_federation_wire::EventDescriptor {
        target_server_id: EDGE,
        delivery_sequence: 0,
        event_id,
        object_id,
    };
    let mut assembler = FragmentAssembler::new();
    for fragment in split_fragments(object_id, encoded.as_slice())? {
        let frame = FederationFrame::Event {
            descriptor,
            fragment,
        };
        let (_, key) = carrier_of(&frame).map_err(|error| error.to_string())?;
        if let AssemblyProgress::Complete(object) =
            assembler.admit(key, frame.fragment().ok_or("fragment")?, 0)?
        {
            return Ok((descriptor, object));
        }
    }
    Err("event did not assemble".into())
}

async fn delivery_before_commit(quiesce: bool) -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let identity = seed_session(context, 1, "recipient", None)?;
    let sink = bind_live_session(context, 1, identity, CapabilityState::default(), true)?;
    let mut edge = EdgeFederation::new(EdgeConfig {
        network_id: NETWORK,
        server_id: EDGE,
        server_name: EDGE_NAME.to_owned(),
        incarnation: EDGE_INCARNATION,
        coordinator: coordinator_identity(),
    });
    edge.phase = Phase::Active;
    edge.replica
        .install(
            1,
            vec![ProjectionRecord::Session(session_record(
                identity.session_id,
                identity.user_id,
                "recipient",
                1,
                1,
            )?)],
        )
        .map_err(|error| format!("replica: {error:?}"))?;
    let event = ProjectedEvent::MessageDelivered(DeliveredMessageRecord {
        message_id: MessageId::from_bytes([18; 16]),
        kind: agenc_relay_domain::MessageKind::Privmsg,
        target: DeliveryTarget::User(identity.user_id),
        sender: source(UserId::from_bytes([19; 16]), "sender", 2)?,
        target_revision: Revision::new(1)?,
        channel_event_sequence: 0,
        received_unix_milliseconds: 1_000,
        tags: Vec::new(),
        body: "must wait for storage".to_owned(),
    });
    let (descriptor, object) = event_object(&event)?;
    if quiesce {
        fixture
            .state_mut()?
            .step_message(StateCoreMessage::Signal(SignalEvent::Terminate));
    }
    let result = events::receive(&mut edge, fixture.context_mut()?, descriptor, &object);
    assert_eq!(result.is_err(), quiesce);
    assert!(
        sink.lines().is_empty(),
        "client output escaped before durable acceptance"
    );
    drop(fixture);
    assert!(
        sink.lines().is_empty(),
        "cancelled storage work delivered client output"
    );
    Ok(())
}

#[tokio::test]
async fn an_event_waits_for_storage_and_cancellation_discards_its_output() -> TestResult {
    delivery_before_commit(false).await
}

#[tokio::test]
async fn rejected_durable_admission_does_not_deliver_event_output() -> TestResult {
    delivery_before_commit(true).await
}

fn edge_with_projection() -> TestResult<EdgeFederation> {
    let mut edge = EdgeFederation::new(EdgeConfig {
        network_id: NETWORK,
        server_id: EDGE,
        server_name: EDGE_NAME.to_owned(),
        incarnation: EDGE_INCARNATION,
        coordinator: coordinator_identity(),
    });
    let session = session_record(
        SessionId::from_bytes([21; 16]),
        UserId::from_bytes([22; 16]),
        "before",
        1,
        1,
    )?;
    edge.nicknames
        .insert(session.user_id, session.nickname.clone());
    edge.replica
        .install(1, vec![ProjectionRecord::Session(session)])?;
    edge.phase = Phase::Active;
    Ok(edge)
}

fn projection_changes() -> TestResult<Vec<ProjectedEvent>> {
    let visible = session_record(
        SessionId::from_bytes([23; 16]),
        UserId::from_bytes([24; 16]),
        "new-session",
        10,
        2,
    )?;
    let renamed = session_record(
        SessionId::from_bytes([21; 16]),
        UserId::from_bytes([22; 16]),
        "after",
        10,
        1,
    )?;
    Ok(vec![
        ProjectedEvent::SessionVisible(SessionEventView {
            source: source(visible.user_id, "new-session", 2)?,
            home_projection: Some(visible),
        }),
        ProjectedEvent::NicknameChanged {
            old_nickname: NicknameValue::parse("before")?,
            view: SessionEventView {
                source: source(renamed.user_id, "after", 1)?,
                home_projection: Some(renamed),
            },
        },
    ])
}

fn assert_original_projection(edge: &EdgeFederation) -> TestResult {
    let original = edge_with_projection()?;
    assert!(
        edge.replica.entries().collect::<Vec<_>>()
            == original.replica.entries().collect::<Vec<_>>(),
        "refused event changed the committed projection"
    );
    assert!(
        edge.nicknames == original.nicknames,
        "nickname map was not restored"
    );
    assert_eq!(edge.replica.projection_generation(), 1);
    assert_eq!(edge.cursor, None);
    assert_eq!(edge.counters.events_applied, 0);
    assert!(edge.commit.is_none());
    assert!(edge.event_before.is_none());
    Ok(())
}

fn accept_and_complete_event(
    edge: &mut EdgeFederation,
    fixture: &mut StateCoreFixture,
    event: &ProjectedEvent,
) -> TestResult {
    let original = edge.replica.entries().collect::<Vec<_>>();
    let (descriptor, object) = event_object(event)?;
    assert!(
        events::receive(edge, fixture.context_mut()?, descriptor, &object)
            .is_ok_and(|completions| completions.is_empty())
    );
    let applied = edge.replica.entries().collect::<Vec<_>>();
    assert!(
        applied != original,
        "accepted event did not change the projection"
    );
    if matches!(event, ProjectedEvent::NicknameChanged { .. }) {
        assert!(
            edge.nicknames.get(&UserId::from_bytes([22; 16]))
                == Some(&NicknameValue::parse("after")?)
        );
    }
    let nicknames = edge.nicknames.clone();
    assert_eq!(edge.cursor, None);
    assert_eq!(edge.counters.events_applied, 0);
    assert!(edge.event_before.is_some());
    // Model the storage owner's committed-batch callback.
    assert!(edge.batch_applied(fixture.context_mut()?).is_empty());
    assert!(edge.replica.entries().collect::<Vec<_>>() == applied);
    assert!(edge.nicknames == nicknames);
    assert_eq!(edge.cursor, Some((0, descriptor.event_id)));
    assert_eq!(edge.counters.events_applied, 1);
    assert!(edge.commit.is_none());
    assert!(edge.event_before.is_none());
    Ok(())
}

#[tokio::test]
async fn refused_event_admission_restores_projection_and_accepts_retry() -> TestResult {
    for event in projection_changes()? {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = edge_with_projection()?;
        let (descriptor, object) = event_object(&event)?;
        fixture
            .state_mut()?
            .step_message(StateCoreMessage::Signal(SignalEvent::Terminate));
        assert!(matches!(
            events::receive(&mut edge, fixture.context_mut()?, descriptor, &object),
            Err(Violation::Ceiling)
        ));
        assert_original_projection(&edge)?;
        drop(fixture);

        let mut recovered = StateCoreFixture::new(entropy_script())?;
        accept_and_complete_event(&mut edge, &mut recovered, &event)?;
    }
    Ok(())
}

#[tokio::test]
async fn rejected_event_batch_restores_projection_and_accepts_retry() -> TestResult {
    for event in projection_changes()? {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = edge_with_projection()?;
        let (descriptor, object) = event_object(&event)?;
        assert!(
            events::receive(&mut edge, fixture.context_mut()?, descriptor, &object)
                .is_ok_and(|completions| completions.is_empty())
        );
        assert!(edge.event_before.is_some());
        assert!(
            edge.replica.entries().collect::<Vec<_>>()
                != edge_with_projection()?
                    .replica
                    .entries()
                    .collect::<Vec<_>>()
        );
        drop(fixture);

        let mut recovered = StateCoreFixture::new(entropy_script())?;
        edge.batch_rejected(recovered.context_mut()?);
        assert_original_projection(&edge)?;
        accept_and_complete_event(&mut edge, &mut recovered, &event)?;
    }
    Ok(())
}
