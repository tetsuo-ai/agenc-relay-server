//! Replay metadata reads retain exclusive history ownership until body delivery.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_domain::federation::{
    EdgeLink, EdgePhase, OperationKey, OriginBinding, OriginEntry, OriginKey, OriginPrincipal,
    OriginStatus, RetainedRequest,
};

fn retain_request(coordinator: &mut FederationCoordinator, header: RequestHeader, bytes: &[u8]) {
    let replay = header.replay_key;
    let origin = OriginKey {
        home_server_id: replay.home_server_id,
        server_incarnation: replay.server_incarnation,
        origin_id: replay.origin_id,
    };
    coordinator.origins.restore_edge(
        replay.home_server_id,
        EdgeLink {
            server_incarnation: replay.server_incarnation,
            phase: EdgePhase::Ready,
        },
    );
    coordinator.origins.restore_origin(
        origin,
        OriginEntry {
            generation: replay.origin_generation,
            next_sequence: replay.operation_sequence.saturating_add(1),
            object_id: [1; 32],
            binding: OriginBinding {
                connection_id: ConnectionId::from_bytes([2; 16]),
                connection_nonce: [3; 32],
            },
            principal: OriginPrincipal::UNREGISTERED,
            status: OriginStatus::Live,
            deleted_after: None,
        },
    );
    coordinator.retained.insert(
        OperationKey {
            origin,
            generation: replay.origin_generation,
            sequence: replay.operation_sequence,
        },
        RetainedRequest {
            request_id: header.request_id,
            request_object_id: *federation_object_id(bytes).as_bytes(),
        },
    );
}

#[tokio::test]
async fn history_duplicate_waits_while_the_original_metadata_read_is_pending() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let (inbox, mut receiver) = mpsc::channel(8);
    let mut edge = Edge::new(inbox, 41);
    let mut origin = Origin::new(61);
    let operation = FederatedOperation::HistoryQuery {
        session_id: SessionId::from_bytes([70; 16]),
        channel_id: agenc_relay_types::ChannelInstanceId::from_bytes([71; 16]),
        selector: crate::federation::codec::history::selector_object(HistorySelector::Latest(
            None,
        ))?,
        limit: 1,
        cursor: None,
    };
    let bytes = request(&mut edge, &mut origin, &operation).await?;
    let header = RequestHeader::from_object(&SchemaObject::decode_exact(
        "FederationRequest",
        &bytes,
        &mut DecodeBudget::new(2048, 64),
    )?)?;
    send_request(&mut edge, &header, &bytes).await?;
    let mut coordinator = standalone_coordinator(edge.server_id);
    retain_request(&mut coordinator, header, &bytes);
    for _ in 0..2 {
        let message = receiver.recv().await.ok_or("request object")?;
        let LinkEvent::Object {
            carrier: ObjectCarrier::Request(descriptor),
            object,
        } = message.event
        else {
            return Err("request carrier".into());
        };
        crate::federation::coordinator::request::receive(
            &mut coordinator,
            fixture.context_mut()?,
            message.link,
            message.peer,
            descriptor,
            object,
            None,
        )
        .map_err(|error| format!("{error:?}"))?;
    }
    assert_eq!(
        coordinator.replays.len(),
        1,
        "a second metadata read must stay queued"
    );
    assert_eq!(
        coordinator
            .peers
            .get(&edge.server_id)
            .ok_or("peer")?
            .queued
            .len(),
        1
    );
    assert!(coordinator.history.busy());
    Ok(())
}

#[tokio::test]
async fn concurrent_history_retries_each_receive_the_original_page() -> TestResult {
    run_history(|inbox| async move {
        let mut edge = Edge::new(inbox, 41);
        let mut origin = Origin::new(61);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let (session, _, revision) =
            open_session(&mut edge, &mut origin, "reader", &mut Vec::new()).await?;
        let channel = join_channel(&mut edge, &mut origin, session, revision, "#history").await?;
        let expected_revision = *edge
            .channel_revisions
            .get(&channel)
            .ok_or("channel revision")?;
        complete(
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
                body: "immutable concurrent replay".into(),
            },
        )
        .await?;
        let bytes = request(
            &mut edge,
            &mut origin,
            &FederatedOperation::HistoryQuery {
                session_id: session,
                channel_id: channel,
                selector: crate::federation::codec::history::selector_object(
                    HistorySelector::Latest(None),
                )?,
                limit: 1,
                cursor: None,
            },
        )
        .await?;
        let mut events = Vec::new();
        let original = answer(&mut edge, &mut events).await?;
        assert!(matches!(original.arm, ResultArm::HistoryPage(_)));
        let header = RequestHeader::from_object(&SchemaObject::decode_exact(
            "FederationRequest",
            &bytes,
            &mut DecodeBudget::new(2048, 64),
        )?)?;
        send_request(&mut edge, &header, &bytes).await?;
        send_request(&mut edge, &header, &bytes).await?;
        for _ in 0..2 {
            let replay = answer(&mut edge, &mut events).await?;
            assert_eq!(replay.bytes, original.bytes);
            assert!(replay.header.completion_event_id.is_none());
        }
        assert!(events.is_empty());
        Ok(())
    })
    .await
}

fn expired_metadata(header: RequestHeader, bytes: &[u8]) -> TestResult<InitialStorageRecord> {
    use agenc_relay_storage::history_records::{
        HISTORY_COORDINATOR_RESULT_KIND, HistoryAuthorizationBinding,
        HistoryCoordinatorResultRecord, HistoryPageMetadata, HistoryRequestIdentity,
        HistoryResultStatus,
    };
    let record = HistoryCoordinatorResultRecord {
        request: HistoryRequestIdentity {
            replay_key: header.replay_key.to_bytes(),
            request_id: *header.request_id.as_bytes(),
            request_object_id: *federation_object_id(bytes).as_bytes(),
            request_object: bytes.to_vec(),
        },
        original_result_object_id: [20; 32],
        status: HistoryResultStatus::Expired {
            result_object_id: [21; 32],
        },
        page: HistoryPageMetadata {
            authorization: HistoryAuthorizationBinding {
                session_id: [70; 16],
                user_id: [71; 16],
                session_generation: 1,
                account_id: None,
                account_session_generation: 0,
                membership_revision: 1,
                history_authorization_generation: 1,
            },
            channel_id: [72; 16],
            channel_name: "#history".into(),
            snapshot_token: [22; 32],
            state_cut: 1,
            page_sequence: 0,
            next_cursor: None,
            selected: Vec::new(),
            created_unix_milliseconds: 1,
            deadline_unix_milliseconds: 2,
        },
    };
    let plaintext = PersistentRecordValue::new(
        TableId::RequestResult,
        HISTORY_COORDINATOR_RESULT_KIND,
        1,
        0,
        Some(1),
        Vec::new(),
        record.encode()?,
    )?
    .encode()?;
    Ok(InitialStorageRecord::new(
        TableId::RequestResult,
        agenc_relay_storage::federation_records::request_result_key(header.replay_key.to_bytes())?,
        1,
        plaintext,
    )?)
}

#[tokio::test]
async fn committed_history_retirement_releases_the_exact_request_identity() -> TestResult {
    let (inbox, _receiver) = mpsc::channel(8);
    let mut edge = Edge::new(inbox, 41);
    let mut origin = Origin::new(61);
    let bytes = request(
        &mut edge,
        &mut origin,
        &FederatedOperation::HistoryQuery {
            session_id: SessionId::from_bytes([70; 16]),
            channel_id: agenc_relay_types::ChannelInstanceId::from_bytes([72; 16]),
            selector: crate::federation::codec::history::selector_object(HistorySelector::Latest(
                None,
            ))?,
            limit: 1,
            cursor: None,
        },
    )
    .await?;
    let header = RequestHeader::from_object(&SchemaObject::decode_exact(
        "FederationRequest",
        &bytes,
        &mut DecodeBudget::new(2048, 64),
    )?)?;
    let mut fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        vec![expired_metadata(header, &bytes)?],
    )?;
    let mut coordinator = standalone_coordinator(edge.server_id);
    retain_request(&mut coordinator, header, &bytes);
    let key = *coordinator.retained.keys().next().ok_or("retained")?;
    coordinator
        .origins
        .restore_request_id(header.request_id, key);
    let read = agenc_relay_storage::ReadPlan::exact(
        TableId::RequestResult,
        agenc_relay_storage::federation_records::request_result_key(header.replay_key.to_bytes())?,
    );
    fixture.context_mut()?.submit_storage_read(read)?;
    let result = fixture.next_storage_read().await?.result?;
    let cleanup = crate::federation::history_retention::Retention::default().prepare(
        fixture.context_mut()?,
        &result,
        2,
        agenc_relay_storage::history_records::HISTORY_COORDINATOR_RESULT_KIND,
        |_| true,
    )?;
    assert_eq!(cleanup.deleted, vec![header.replay_key.to_bytes()]);
    let next = OperationKey { sequence: 1, ..key };
    assert_eq!(
        coordinator
            .origins
            .classify_request(next, header.request_id, [30; 32], None)?,
        agenc_relay_domain::federation::ReplayDecision::RequestIdReuse
    );
    crate::federation::coordinator::history::cleanup_committed(
        &mut coordinator,
        fixture.context_mut()?,
        cleanup,
    );
    assert!(coordinator.retained.is_empty());
    assert_eq!(
        coordinator
            .origins
            .origin(&key.origin)
            .ok_or("origin")?
            .next_sequence,
        1
    );
    assert_eq!(
        coordinator
            .origins
            .classify_request(next, header.request_id, [30; 32], None)?,
        agenc_relay_domain::federation::ReplayDecision::Fresh
    );
    Ok(())
}
