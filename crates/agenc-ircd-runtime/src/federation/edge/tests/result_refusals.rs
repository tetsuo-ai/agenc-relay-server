#![forbid(unsafe_code)]

//! A result whose carrier, identity or completion disagrees with the pending request is refused
//! and the request keeps waiting for its honest answer.

use super::*;

type Forge = fn(&mut ResultHeader, &mut OperationDescriptor, &mut SessionRegistered);

struct Scene {
    fixture: StateCoreFixture,
    edge: EdgeFederation,
    request_id: agenc_ircd_types::RequestId,
}

async fn scene() -> TestResult<Scene> {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = resync_edge();
    let connection = ConnectionGeneration::new(1);
    edge.connection_opened(fixture.context_mut()?, connection);
    request::send_session_open(
        &mut edge,
        fixture.context_mut()?,
        connection,
        1,
        "pending",
        "Pending",
        [1; 32],
        None,
    )
    .map_err(|error| format!("{error:?}"))?;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let request_id = *edge.pending.keys().next().ok_or("request")?;
    Ok(Scene {
        fixture,
        edge,
        request_id,
    })
}

impl Scene {
    fn deliver(&mut self, forge: Forge) -> TestResult<Result<Vec<EdgeCompletion>, Violation>> {
        let pending = self.edge.pending.get(&self.request_id).ok_or("pending")?;
        let mut header = ResultHeader {
            network_id: NETWORK,
            replay_key: pending.header.replay_key,
            request_id: self.request_id,
            request_object_id: federation_object_id(&pending.bytes),
            completion_event_id: Some(EventId::from_bytes([76; 16])),
            result_kind: agenc_ircd_types::FederationResultKind::SessionRegistered,
        };
        let mut descriptor = OperationDescriptor {
            addressed_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id: header.replay_key.origin_id,
            origin_generation: 0,
            operation_sequence: 0,
            request_id: self.request_id,
            object_id: federation_object_id(&[]),
        };
        let mut registered = SessionRegistered {
            session_id: SessionId::from_bytes([77; 16]),
            user_id: UserId::from_bytes([78; 16]),
            session_revision: 9,
            account: None,
            resulting_state_generation: 9,
        };
        let honest_id = descriptor.object_id;
        forge(&mut header, &mut descriptor, &mut registered);
        let bytes = header
            .build(
                &ResultArm::SessionRegistered(registered).to_object()?,
                Vec::new(),
            )?
            .encode_canonical()?
            .as_slice()
            .to_vec();
        if descriptor.object_id == honest_id {
            descriptor.object_id = federation_object_id(&bytes);
        }
        let object = resync_assembled(&bytes, |fragment| FederationFrame::Result {
            descriptor,
            fragment,
        })?;
        Ok(request::receive_result(
            &mut self.edge,
            self.fixture.context_mut()?,
            descriptor,
            &object,
        ))
    }

    fn unanswered(&self) -> bool {
        self.edge
            .pending
            .get(&self.request_id)
            .is_some_and(|pending| pending.result.is_none())
            && self.edge.commit.is_none()
    }
}

#[tokio::test]
async fn a_result_that_disagrees_with_its_carrier_or_request_leaves_it_unanswered() -> TestResult {
    let forgeries: [Forge; 4] = [
        |_, descriptor, _| descriptor.request_id = agenc_ircd_types::RequestId::from_bytes([9; 16]),
        |_, descriptor, _| {
            descriptor.object_id =
                agenc_ircd_federation_wire::FederationHash32::from_bytes([9; 32]);
        },
        |header, _, _| header.replay_key.operation_sequence = 9,
        |header, _, _| {
            header.request_object_id =
                agenc_ircd_federation_wire::FederationHash32::from_bytes([9; 32]);
        },
    ];
    for forge in forgeries {
        let mut scene = scene().await?;
        assert_eq!(scene.deliver(forge)?.err(), Some(Violation::Consistency));
        assert!(scene.unanswered());
    }
    Ok(())
}

#[tokio::test]
async fn a_result_for_a_request_the_edge_no_longer_holds_is_dropped_quietly() -> TestResult {
    let mut scene = scene().await?;
    let outcome = scene.deliver(|header, descriptor, _| {
        header.request_id = agenc_ircd_types::RequestId::from_bytes([9; 16]);
        descriptor.request_id = header.request_id;
    })?;
    assert!(outcome.is_ok_and(|completions| completions.is_empty()));
    assert!(scene.unanswered());
    Ok(())
}

#[tokio::test]
async fn a_second_answer_must_repeat_the_first_byte_for_byte() -> TestResult {
    let changes: [Forge; 2] = [
        |_, _, registered| registered.session_revision = 10,
        |header, _, _| header.completion_event_id = Some(EventId::from_bytes([75; 16])),
    ];
    for change in changes {
        let mut scene = scene().await?;
        assert!(scene.deliver(|_, _, _| {})?.is_ok());
        commit_edge_batches(&mut scene.edge, &mut scene.fixture).await?;
        let first = scene
            .edge
            .pending
            .get(&scene.request_id)
            .ok_or("answered request")?
            .result_bytes
            .clone();
        assert!(!first.is_empty());
        assert_eq!(scene.deliver(change)?.err(), Some(Violation::Consistency));
        assert!(
            scene
                .deliver(|_, _, _| {})?
                .is_ok_and(|done| done.is_empty())
        );
        let kept = scene.edge.pending.get(&scene.request_id).ok_or("request")?;
        assert_eq!(kept.result_bytes, first);
    }
    Ok(())
}
