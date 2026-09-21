//! Production coordinator paging and immutable replay through the owner and storage.
#![forbid(unsafe_code)]
use super::*;
use crate::test_support::{apply_live_plan, seed_account, seed_session};
use agenc_relay_domain::{
    CanonicalCommand, ChannelCommand, ChannelNameValue, ChannelTarget, ExternalInputs,
    HistoryPolicy, HistorySelector, MessageKind, PlanDecision,
};

#[path = "history/refusals.rs"]
mod refusals;
#[path = "history/replay_concurrency.rs"]
mod replay_concurrency;

fn seed_history(context: &mut StateCoreContext) -> TestResult {
    context.enable_history_for_test(true);
    let account = seed_account(context, 180, 1)?;
    let identity = seed_session(context, 181, "HistoryOwner", Some(account))?;
    let channel = agenc_relay_types::ChannelInstanceId::from_bytes([182; 16]);
    let commands = [
        CanonicalCommand::join(vec![ChannelTarget::new(
            ChannelNameValue::parse("#history")?,
            false,
        )])?,
        CanonicalCommand::channel(ChannelCommand::Register(channel)),
        CanonicalCommand::channel(ChannelCommand::History(channel, HistoryPolicy::OneHour)),
    ];
    for (index, command) in commands.into_iter().enumerate() {
        let inputs = ExternalInputs {
            utc_now: Some(agenc_relay_types::UtcSecond::from_unix_seconds(1_000)),
            channel_ids: vec![channel],
            ..ExternalInputs::default()
        };
        let decision = agenc_relay_testkit::plan(
            context.domain(),
            identity,
            command,
            &agenc_relay_testkit::registered_admission(identity.user_id)?,
            (index == 0).then_some(inputs),
        )
        .map_err(|error| format!("seed {index}: {error:?}"))?;
        let PlanDecision::Mutation(plan) = decision else {
            return Err("seed mutation".into());
        };
        apply_live_plan(context, plan)?;
    }
    Ok(())
}

async fn run_history<Driver, Output>(
    driver: impl FnOnce(mpsc::Sender<FederationInbound>) -> Driver,
) -> TestResult<Output>
where
    Driver: Future<Output = TestResult<Output>>,
{
    let peer = peer_identity(ServerId::from_bytes([41; 16]), "edge.example");
    let mut fixture = StateCoreFixture::with_federation_coordinator(entropy_script(), vec![peer])?;
    seed_history(fixture.context_mut()?)?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (federation, receiver) = mpsc::channel(64);
    parts.state.install_federation_inbox(receiver)?;
    let (_close, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let driven = async move {
        let result = driver(federation).await;
        let _stopped = lifecycle.request(LifecyclePhase::Stop).await;
        drop(inbox);
        result
    };
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        CancellationToken::root(),
    );
    let (exit, output) = tokio::join!(run, driven);
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    output
}

async fn complete(
    edge: &mut Edge,
    origin: &mut Origin,
    operation: &FederatedOperation,
) -> TestResult<Answer> {
    request(edge, origin, operation).await?;
    let mut events = Vec::new();
    let result = answer(edge, &mut events).await?;
    origin.sequence += 1;
    if let Some(completion) = result.header.completion_event_id {
        while !events
            .iter()
            .any(|(header, _)| header.event_id == completion)
        {
            events.push(next_event(edge).await?);
        }
    }
    Ok(result)
}

async fn retry(edge: &mut Edge, bytes: &[u8]) -> TestResult<Answer> {
    let object =
        SchemaObject::decode_exact("FederationRequest", bytes, &mut DecodeBudget::new(2048, 64))?;
    send_request(edge, &RequestHeader::from_object(&object)?, bytes).await?;
    let mut events = Vec::new();
    let result = answer(edge, &mut events).await?;
    assert!(events.is_empty(), "read-only replay emitted an event");
    assert!(result.header.completion_event_id.is_none());
    Ok(result)
}

#[tokio::test]
async fn history_pages_replay_the_original_selection_and_persist_terminal_authority_loss()
-> TestResult {
    run_history(|inbox| async move {
        let mut edge = Edge::new(inbox, 41);
        let mut origin = Origin::new(61);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let (session, _, revision) =
            open_session(&mut edge, &mut origin, "reader", &mut Vec::new()).await?;
        let channel = join_channel(&mut edge, &mut origin, session, revision, "#history").await?;
        let joined_revision = *edge
            .channel_revisions
            .get(&channel)
            .ok_or("join revision")?;
        for number in 0..10 {
            let expected_revision = *edge
                .channel_revisions
                .get(&channel)
                .ok_or("channel revision")?;
            let result = complete(
                &mut edge,
                &mut origin,
                &FederatedOperation::Message {
                    session_id: session,
                    kind: MessageKind::Privmsg,
                    targets: vec![MessageTargetArg::Channel {
                        channel_id: channel,
                        expected_revision,
                    }],
                    tags: Vec::new(),
                    body: format!("original-{number}"),
                },
            )
            .await?;
            assert_eq!(result.header.result_kind, FederationResultKind::Committed);
        }
        let query = FederatedOperation::HistoryQuery {
            session_id: session,
            channel_id: channel,
            selector: crate::federation::codec::history::selector_object(HistorySelector::Latest(
                None,
            ))?,
            limit: 100,
            cursor: None,
        };
        let original_request = request(&mut edge, &mut origin, &query).await?;
        let mut events = Vec::new();
        let first = answer(&mut edge, &mut events).await?;
        origin.sequence += 1;
        assert!(events.is_empty());
        assert!(first.header.completion_event_id.is_none());
        let ResultArm::HistoryPage(first_page) = &first.arm else {
            return Err(format!("not history page: {:?}", first.header.result_kind).into());
        };
        assert_eq!(first_page.messages()?.len(), 7);
        let cursor = first_page.next_cursor()?.ok_or("next cursor")?;
        let second = complete(
            &mut edge,
            &mut origin,
            &FederatedOperation::HistoryQuery {
                session_id: session,
                channel_id: channel,
                selector: crate::federation::codec::history::selector_object(
                    HistorySelector::Latest(None),
                )?,
                limit: 100,
                cursor: Some(cursor),
            },
        )
        .await?;
        let ResultArm::HistoryPage(second_page) = &second.arm else {
            return Err("second page".into());
        };
        assert_eq!(second_page.messages()?.len(), 3);
        assert!(second_page.next_cursor()?.is_none());
        let stale = complete(
            &mut edge,
            &mut origin,
            &FederatedOperation::HistoryQuery {
                session_id: session,
                channel_id: channel,
                selector: crate::federation::codec::history::selector_object(
                    HistorySelector::Latest(None),
                )?,
                limit: 100,
                cursor: Some(cursor),
            },
        )
        .await?;
        assert!(matches!(stale.arm, ResultArm::Failed { ref code, .. } if code == "QUERY_EXPIRED"));
        assert_eq!(
            retry(&mut edge, &original_request).await?.bytes,
            first.bytes
        );
        let parted = complete(
            &mut edge,
            &mut origin,
            &FederatedOperation::Part {
                session_id: session,
                expected_session_revision: joined_revision,
                all_channels: false,
                channels: vec![channel],
                reason: "done".into(),
            },
        )
        .await?;
        assert_eq!(parted.header.result_kind, FederationResultKind::Committed);
        let expired = retry(&mut edge, &original_request).await?;
        let ResultArm::HistoryExpired {
            original_result_object_id,
        } = expired.arm
        else {
            return Err("expected terminal expiry".into());
        };
        assert_eq!(
            original_result_object_id,
            *federation_object_id(&first.bytes).as_bytes()
        );
        let parted_revision = *edge
            .channel_revisions
            .get(&channel)
            .ok_or("part revision")?;
        join_channel(&mut edge, &mut origin, session, parted_revision, "#history").await?;
        assert_eq!(
            retry(&mut edge, &original_request).await?.bytes,
            expired.bytes
        );
        Ok(())
    })
    .await
}
