#![forbid(unsafe_code)]

//! What each finished request hands the router, once its answer is durable.

use super::request_refusals::{CONNECTION, command, registered_edge, sealed_envelope};
use super::*;
use agenc_relay_domain::DomainError;
use agenc_relay_types::FederationOpcode;

struct Scene {
    fixture: StateCoreFixture,
    edge: EdgeFederation,
}

impl Scene {
    /// A registered connection whose one request is durable and unanswered.
    async fn with_command(line: &str) -> TestResult<(Self, RequestId)> {
        let mut fixture = StateCoreFixture::new(entropy_script())?;
        let mut edge = registered_edge(fixture.context_mut()?)?;
        assert_eq!(command(&mut edge, fixture.context_mut()?, line)?, Ok(()));
        commit_edge_batches(&mut edge, &mut fixture).await?;
        let request_id = *edge.pending.keys().next().ok_or("request")?;
        Ok((Self { fixture, edge }, request_id))
    }

    /// Records `result` for the request and settles it through the journal.
    async fn answer(
        &mut self,
        request_id: RequestId,
        result: ResultArm,
        replies: Vec<WireMessage>,
    ) -> TestResult<Vec<EdgeCompletion>> {
        let pending = self.edge.pending.get_mut(&request_id).ok_or("pending")?;
        pending.result = Some(result);
        pending.replies = replies;
        let early = request::completed(&mut self.edge, self.fixture.context_mut()?, request_id);
        assert!(
            early.is_empty(),
            "the answer is journaled before it renders"
        );
        assert!(self.edge.pending.contains_key(&request_id));
        commit_edge_batches(&mut self.edge, &mut self.fixture).await
    }
}

fn failed(code: &str) -> ResultArm {
    ResultArm::Failed {
        code: code.to_owned(),
        context: String::new(),
    }
}

fn who_reply() -> TestResult<WireMessage> {
    Ok(agenc_relay_client_wire::numeric_reply(
        EDGE_NAME,
        315,
        "member",
        &["#bridge"],
        Some("End of WHO list"),
    )?)
}

#[tokio::test]
async fn a_failed_command_carries_its_mapped_error_or_server_busy() -> TestResult {
    for (code, expected) in [
        ("CHANNEL_FULL", DomainError::Forbidden),
        ("NOT_A_REGISTERED_CODE", DomainError::ServerBusy),
    ] {
        let (mut scene, request_id) = Scene::with_command("WHO #bridge").await?;
        let completions = scene.answer(request_id, failed(code), Vec::new()).await?;
        assert!(matches!(
            completions.as_slice(),
            [EdgeCompletion::CommandFailed { generation: CONNECTION, error, message }]
                if *error == expected && message.command() == "WHO"
        ));
        assert!(scene.edge.pending.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn a_reply_page_with_a_cursor_keeps_later_commands_deferred() -> TestResult {
    for (next_cursor, dispatched) in [(Some([7; 32]), false), (None, true)] {
        let (mut scene, request_id) = Scene::with_command("WHO #bridge").await?;
        let context = scene.fixture.context_mut()?;
        assert_eq!(command(&mut scene.edge, context, "WHO #later")?, Ok(()));
        assert_eq!(scene.edge.pending.len(), 1, "the second command waits");
        let page = ResultArm::ReplyPage {
            snapshot_token: [6; 32],
            page_sequence: 2,
            next_cursor,
        };
        let completions = scene.answer(request_id, page, vec![who_reply()?]).await?;
        assert!(matches!(
            completions.as_slice(),
            [EdgeCompletion::Replies { generation: CONNECTION, frames, page_sequence: 2, next_cursor: cursor, .. }]
                if frames.len() == 1 && *cursor == next_cursor
        ));
        assert_eq!(scene.edge.pending.len(), usize::from(dispatched));
        let waiting = scene
            .edge
            .deferred
            .get(&CONNECTION)
            .map_or(0, crate::budget::RetainedQueue::len);
        assert_eq!(waiting, usize::from(!dispatched));
    }
    Ok(())
}

#[tokio::test]
async fn a_command_without_a_page_renders_its_replies_or_plain_completion() -> TestResult {
    let committed = || ResultArm::Committed {
        resulting_state_generation: 4,
    };
    let (mut scene, request_id) = Scene::with_command("WHO #bridge").await?;
    let completions = scene.answer(request_id, committed(), Vec::new()).await?;
    assert!(matches!(
        completions.as_slice(),
        [EdgeCompletion::CommandCompleted { generation: CONNECTION, message }]
            if message.command() == "WHO"
    ));
    let (mut scene, request_id) = Scene::with_command("WHO #bridge").await?;
    let completions = scene
        .answer(request_id, committed(), vec![who_reply()?])
        .await?;
    assert!(matches!(
        completions.as_slice(),
        [EdgeCompletion::Replies { frames, page_sequence: 0, next_cursor: None, .. }]
            if frames.len() == 1
    ));
    let (mut scene, request_id) = Scene::with_command("WHO #bridge").await?;
    let completions = scene
        .answer(request_id, ResultArm::NoContent, Vec::new())
        .await?;
    assert!(matches!(
        completions.as_slice(),
        [EdgeCompletion::Replies { frames, page_sequence: 0, next_cursor: None, .. }]
            if frames.is_empty()
    ));
    Ok(())
}

#[tokio::test]
async fn a_revoked_session_is_reported_after_its_last_completion() -> TestResult {
    let (mut scene, request_id) = Scene::with_command("WHO #bridge").await?;
    scene
        .edge
        .origins
        .get_mut(&CONNECTION)
        .ok_or("origin")?
        .revoked = true;
    let completions = scene
        .answer(request_id, ResultArm::NoContent, Vec::new())
        .await?;
    assert!(matches!(
        completions.as_slice(),
        [
            EdgeCompletion::Replies { .. },
            EdgeCompletion::SessionRevoked {
                generation: CONNECTION
            }
        ]
    ));
    Ok(())
}

#[tokio::test]
async fn a_request_whose_client_left_completes_silently_and_forgets_its_event() -> TestResult {
    let (mut scene, request_id) = Scene::with_command("WHO #bridge").await?;
    let event = EventId::from_bytes([76; 16]);
    let pending = scene.edge.pending.get_mut(&request_id).ok_or("pending")?;
    pending.sink_gone = true;
    pending.completion = Some(event);
    pending.completion_generation = Some(4);
    scene.edge.by_completion.insert(event, request_id);
    scene.edge.applied_completions.insert(event);
    let completions = scene
        .answer(request_id, ResultArm::NoContent, Vec::new())
        .await?;
    assert!(completions.is_empty());
    assert!(scene.edge.pending.is_empty());
    assert!(scene.edge.by_completion.is_empty());
    assert!(scene.edge.applied_completions.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_refused_registration_names_the_connection_and_its_event_generation() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut edge = resync_edge();
    edge.connection_opened(fixture.context_mut()?, CONNECTION);
    request::send_session_open(
        &mut edge,
        fixture.context_mut()?,
        CONNECTION,
        5,
        "taken",
        "Taken",
        [1; 32],
        None,
    )
    .map_err(|violation| format!("{violation:?}"))?;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let request_id = *edge.pending.keys().next().ok_or("request")?;
    let mut scene = Scene { fixture, edge };
    let completions = scene
        .answer(request_id, failed("NICK_IN_USE"), Vec::new())
        .await?;
    assert!(matches!(
        completions.as_slice(),
        [EdgeCompletion::RegistrationRefused {
            generation: CONNECTION,
            event_generation: 5
        }]
    ));
    assert!(
        scene
            .edge
            .origins
            .get(&CONNECTION)
            .is_some_and(|origin| origin.session.is_none())
    );
    Ok(())
}

#[tokio::test]
async fn completing_a_request_the_edge_does_not_hold_yields_nothing() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    let unknown = RequestId::from_bytes([9; 16]);
    assert!(request::completed(&mut edge, context, unknown).is_empty());
    assert!(
        request::dispatch_deferred(&mut edge, context, ConnectionGeneration::new(9)).is_empty()
    );
    assert!(edge.deferred.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_deferred_command_that_can_no_longer_be_sent_fails_to_its_client() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.join_names_pending = true;
    assert_eq!(command(&mut edge, context, "WHO #first")?, Ok(()));
    assert_eq!(command(&mut edge, context, "WHO #second")?, Ok(()));
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.join_names_pending = false;
    origin.sequence = u64::MAX;
    let completions = request::dispatch_deferred(&mut edge, context, CONNECTION);
    assert!(matches!(
        completions.as_slice(),
        [
            EdgeCompletion::CommandFailed { error: DomainError::ServerBusy, message: first, .. },
            EdgeCompletion::CommandFailed { error: DomainError::ServerBusy, message: second, .. },
        ] if first.middle() == ["#first"] && second.middle() == ["#second"]
    ));
    assert!(edge.pending.is_empty());
    assert!(!edge.deferred.contains_key(&CONNECTION));
    Ok(())
}

#[tokio::test]
async fn a_held_carrier_that_can_no_longer_be_sent_fails_to_its_client() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    edge.session_bound(context, CONNECTION);
    request::send_account_carrier(
        &mut edge,
        context,
        CONNECTION,
        FederationOpcode::OpaqueAuthStart,
        &sealed_envelope()?,
        true,
        3,
    )
    .map_err(|violation| format!("{violation:?}"))?;
    assert!(request::dispatch_deferred(&mut edge, context, CONNECTION).is_empty());
    assert!(
        edge.deferred_carriers.contains_key(&CONNECTION),
        "the update is still unacknowledged"
    );
    let origin = edge.origins.get_mut(&CONNECTION).ok_or("origin")?;
    origin.pending_updates.clear();
    edge.phase = Phase::Origins;
    let completions = request::dispatch_deferred(&mut edge, context, CONNECTION);
    assert!(matches!(
        completions.as_slice(),
        [EdgeCompletion::AccountCarrier {
            generation: CONNECTION,
            carrier_generation: 3,
            sasl: true,
            finish: true,
            outcome: request::RemoteCarrierOutcome::Failed { chunks },
        }] if chunks.is_empty()
    ));
    assert!(edge.deferred_carriers.is_empty());
    assert!(edge.pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_mode_query_for_another_nickname_is_forbidden_locally() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = registered_edge(context)?;
    let user_id = UserId::from_bytes([42; 16]);
    let record = session_record(SessionId::from_bytes([41; 16]), user_id, "member", 1, 42)?;
    edge.replica.install_recovered(
        1,
        vec![agenc_relay_domain::federation::ProjectionRecord::Session(
            record,
        )],
    )?;
    assert_eq!(
        command(&mut edge, context, "MODE someoneelse")?,
        Err(DomainError::Forbidden)
    );
    assert!(edge.pending.is_empty(), "the read never leaves the edge");
    Ok(())
}
