#![forbid(unsafe_code)]
//! History output reservations do not publish before the accepted rendering callback.

use super::*;
use crate::sync::Arc;
use crate::test_support::{FrameSink, StateCoreFixture, bind_live_session, seed_session};
use agenc_ircd_client_wire::{
    CapabilityProfile, CapabilitySpec, CapabilityState, FramedLine, parse_message,
};
use agenc_ircd_domain::federation::{
    ChannelDetailRecord, MembershipRecord, ProjectionRecord, SessionRecord, SourceView,
};
use agenc_ircd_domain::{ChannelNameValue, MessageKind, NicknameValue, Role};
use agenc_ircd_federation_wire::{CanonicalEncode, ReplayKey};
use agenc_ircd_storage::history_records::{
    HistoryMessageRecord, HistoryPageMetadata, HistoryRowReference,
};
use agenc_ircd_types::{
    FederationOpcode, FederationRole, MessageId, NetworkId, OriginId, RecoveryEpoch, Revision,
    ServerId, ServerIncarnation, UtcSecond,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ID: RequestId = RequestId::from_bytes([9; 16]);
const CHANNEL: ChannelInstanceId = ChannelInstanceId::from_bytes([10; 16]);

#[path = "encrypted.rs"]
mod encrypted;

fn capabilities() -> TestResult<CapabilityState> {
    let names = [
        "message-tags",
        "server-time",
        "message-ids",
        "batch",
        "draft/chathistory",
        "labeled-response",
    ];
    let profile = CapabilityProfile::new(
        names
            .iter()
            .map(|name| CapabilitySpec::new(name, None))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let mut state = CapabilityState::default();
    state.ls(None, &profile)?;
    state.request(&names.join(" "), &profile)?;
    Ok(state)
}

fn fixture() -> TestResult<(
    StateCoreFixture,
    EdgeFederation,
    Arc<FrameSink>,
    HistoryPage,
)> {
    fixture_with_options(true, true)
}

fn fixture_with_options(
    enabled: bool,
    negotiated: bool,
) -> TestResult<(
    StateCoreFixture,
    EdgeFederation,
    Arc<FrameSink>,
    HistoryPage,
)> {
    let mut fixture = StateCoreFixture::new(vec![7; 65_536])?;
    let context = fixture.context_mut()?;
    if enabled {
        context.enable_history_for_test(false);
    }
    let identity = seed_session(context, 1, "reader", None)?;
    let caps = if negotiated {
        capabilities()?
    } else {
        CapabilityState::default()
    };
    let sink = bind_live_session(context, 1, identity, caps, true)?;
    let server = ServerId::from_bytes([2; 16]);
    let coordinator = crate::federation::PeerIdentity::new(
        ServerId::from_bytes([3; 16]),
        "hub.example",
        FederationRole::Coordinator,
        RecoveryEpoch::from_bytes([0; 16]),
        agenc_ircd_crypto::Ed25519SecretKey::from_bytes([4; 32]).public_key(),
        [5; 32],
    );
    let mut edge = EdgeFederation::new(super::super::EdgeConfig {
        network_id: NetworkId::from_bytes([1; 32]),
        server_id: server,
        server_name: "edge.example".into(),
        incarnation: ServerIncarnation::from_bytes([6; 16]),
        coordinator,
    });
    let generation = ConnectionGeneration::new(1);
    let session = context
        .domain()
        .session(identity.user_id)
        .ok_or("session")?;
    let projected = SessionRecord {
        session_id: identity.session_id,
        user_id: identity.user_id,
        home_server_id: server,
        session_revision: Revision::new(1)?,
        account: None,
        nickname: NicknameValue::parse("reader")?,
        display_name: agenc_ircd_domain::DisplayNameValue::prepare("reader")?,
        public_cloak: session.public_cloak(),
        account_label: None,
        user_mode_bits: 1,
        away: None,
    };
    let channel = ChannelNameValue::parse("#room")?;
    edge.replica.install(
        1,
        vec![
            ProjectionRecord::Session(projected),
            ProjectionRecord::ChannelDetail(ChannelDetailRecord {
                channel_id: CHANNEL,
                name: channel.clone(),
                channel_revision: Revision::new(20)?,
                visibility: Visibility::Listed,
                content_policy: ContentPolicy::Plaintext,
                persistence: PersistencePolicy::Registered,
                simple_mode_bits: 4,
                history: HistoryPolicy::OneHour,
                e2ee_route_binding: None,
            }),
            ProjectionRecord::Membership(MembershipRecord {
                channel_id: CHANNEL,
                user_id: identity.user_id,
                role: Role::Member,
                membership_revision: Revision::new(1)?,
                joined_at: UtcSecond::from_unix_seconds(1),
            }),
        ],
    )?;
    edge.phase = Phase::Active;
    edge.origins.insert(
        generation,
        super::super::ConnectionOrigin {
            revoked: false,
            pending_updates: std::collections::VecDeque::new(),
            origin_id: OriginId::from_bytes([8; 16]),
            connection_id: agenc_ircd_types::ConnectionId::from_bytes([7; 16]),
            connection_nonce: [7; 32],
            generation: 0,
            sequence: 1,
            object_id: [1; 32],
            previous_object_id: [0; 32],
            session: Some((identity.session_id, identity.user_id)),
            account: None,
            acked_generation: Some(0),
            ever_acked: true,
            join_names_pending: false,
            del_acked: false,
            deleted: false,
        },
    );
    let query = HistoryQuery::new(agenc_ircd_domain::HistorySelector::Latest(None), 7)?;
    let operation = FederatedOperation::HistoryQuery {
        session_id: identity.session_id,
        channel_id: CHANNEL,
        selector: codec::selector_object(query.selector())?,
        limit: 7,
        cursor: None,
    };
    let header = RequestHeader {
        network_id: edge.config.network_id,
        replay_key: ReplayKey {
            home_server_id: server,
            server_incarnation: edge.config.incarnation,
            origin_id: OriginId::from_bytes([8; 16]),
            origin_generation: 0,
            operation_sequence: 0,
        },
        request_id: ID,
        opcode: FederationOpcode::HistoryQuery,
    };
    let bytes = header
        .build(&operation.to_object()?)?
        .encode_canonical()?
        .as_slice()
        .to_vec();
    let auth = HistoryAuthorizationBinding {
        session_id: *identity.session_id.as_bytes(),
        user_id: *identity.user_id.as_bytes(),
        session_generation: 1,
        account_id: None,
        account_session_generation: 0,
        membership_revision: 1,
        history_authorization_generation: 1,
    };
    let record = HistoryEdgeRequestRecord {
        request: HistoryRequestIdentity {
            replay_key: header.replay_key.to_bytes(),
            request_id: *ID.as_bytes(),
            request_object_id: *federation_object_id(&bytes).as_bytes(),
            request_object: bytes.clone(),
        },
        original_result_object_id: None,
        expired_result_object_id: None,
        authorization: None,
        deadline_unix_milliseconds: 1_600_000,
        phase: HistoryEdgePhase::Pending,
        sink_gone: false,
    };
    edge.history.records.insert(ID, record);
    edge.history.batches.insert(
        generation,
        Batch {
            channel: CHANNEL,
            query,
            id: "history-test".into(),
            token: None,
            authorization: None,
            page: 0,
            count: 0,
            last_sequence: 0,
            deadline: 600_000,
        },
    );
    edge.pending.insert(
        ID,
        request::PendingRequest {
            sink_gone: false,
            result_bytes: Vec::new(),
            generation,
            kind: PendingKind::Command {
                message: Box::new(
                    parse_message(FramedLine::new(
                        "@label=original CHATHISTORY LATEST #room * 7",
                    )?)?
                    .ok_or("message")?,
                ),
            },
            header,
            bytes,
            sent: true,
            result: None,
            replies: Vec::new(),
            join_echoes: Vec::new(),
            completion: None,
            completion_generation: None,
            completion_coverage: None,
        },
    );
    let message = HistoryMessageRecord {
        channel_id: CHANNEL,
        channel_name: channel,
        channel_sequence: 20,
        message_id: MessageId::from_bytes([12; 16]),
        received_unix_milliseconds: 1_000_000,
        expires_unix_milliseconds: 4_600_000,
        retention_seconds: 3_600,
        sender: SourceView {
            user_id: UserId::from_bytes([13; 16]),
            nickname: NicknameValue::parse("old-sender")?,
            public_cloak: session.public_cloak(),
            account_label: None,
        },
        kind: MessageKind::Privmsg,
        tags: Vec::new(),
        body: "history must wait".into(),
    };
    let metadata = HistoryPageMetadata {
        authorization: auth,
        channel_id: *CHANNEL.as_bytes(),
        channel_name: "#room".into(),
        snapshot_token: [11; 32],
        state_cut: 20,
        page_sequence: 0,
        next_cursor: None,
        selected: vec![HistoryRowReference {
            channel_sequence: 20,
            message_id: [12; 16],
            received_unix_milliseconds: 1_000_000,
            expires_unix_milliseconds: 4_600_000,
        }],
        created_unix_milliseconds: 1_000_000,
        deadline_unix_milliseconds: 1_600_000,
    };
    let page = codec::page_object(&metadata, &[message])?;
    Ok((fixture, edge, sink, page))
}

#[tokio::test]
async fn reserved_history_is_discarded_when_its_metadata_admission_fails() -> TestResult {
    let (mut fixture, mut edge, sink, page) = fixture()?;
    let record = edge.history.records.get(&ID).ok_or("record")?.clone();
    let prepared = prepare_page(
        &edge,
        fixture.context_mut()?,
        ConnectionGeneration::new(1),
        record,
        FederationHash32::from_bytes([14; 32]),
        &page,
    )
    .map_err(|error| format!("prepare: {error:?}"))?;
    assert!(sink.lines().is_empty());
    fixture
        .state_mut()?
        .step_message(crate::state_core::inbox::StateCoreMessage::Signal(
            crate::state_core::inbox::SignalEvent::Terminate,
        ));
    assert!(stage(&mut edge, fixture.context_mut()?, prepared).is_err());
    assert!(sink.lines().is_empty());
    assert!(edge.pending.contains_key(&ID));
    assert_eq!(
        edge.history.records.get(&ID).ok_or("record")?.phase,
        HistoryEdgePhase::Pending
    );
    Ok(())
}

#[tokio::test]
async fn rendering_callback_rechecks_link_state_and_preserves_original_tags() -> TestResult {
    for valid in [false, true] {
        let (mut fixture, mut edge, sink, page) = fixture()?;
        let record = edge.history.records.get(&ID).ok_or("record")?.clone();
        let mut prepared = prepare_page(
            &edge,
            fixture.context_mut()?,
            ConnectionGeneration::new(1),
            record,
            FederationHash32::from_bytes([14; 32]),
            &page,
        )
        .map_err(|error| format!("prepare: {error:?}"))?;
        prepared.record.phase = HistoryEdgePhase::Rendered;
        if !valid {
            edge.phase = Phase::Down;
        }
        assert!(sink.lines().is_empty());
        committed(&mut edge, fixture.context_mut()?, prepared);
        assert_eq!(sink.lines().len(), if valid { 3 } else { 1 });
        if !valid {
            assert!(
                sink.lines()
                    .first()
                    .is_some_and(|line| line.contains("QUERY_EXPIRED"))
            );
        }
        if valid {
            let lines = sink.lines();
            assert!(
                lines
                    .first()
                    .ok_or("batch start")?
                    .contains("label=original")
            );
            assert!(lines.get(1).ok_or("message")?.contains("old-sender!"));
            assert!(lines.get(1).ok_or("message")?.contains("msgid="));
            assert!(lines.get(1).ok_or("message")?.contains("time="));
            assert!(lines.get(1).ok_or("message")?.contains("history must wait"));
        }
        assert!(!edge.pending.contains_key(&ID));
    }
    Ok(())
}

#[tokio::test]
async fn persisted_edge_receipt_restores_no_socket_or_history_body() -> TestResult {
    for phase in [HistoryEdgePhase::Received, HistoryEdgePhase::Rendered] {
        let (mut fixture, edge, sink, page) = fixture()?;
        let record = edge.history.records.get(&ID).ok_or("record")?.clone();
        let mut prepared = prepare_page(
            &edge,
            fixture.context_mut()?,
            ConnectionGeneration::new(1),
            record,
            FederationHash32::from_bytes([14; 32]),
            &page,
        )
        .map_err(|error| format!("prepare: {error:?}"))?;
        prepared.record.phase = phase;
        let body = prepared.record.encode()?;
        assert!(
            !body
                .windows(b"history must wait".len())
                .any(|bytes| bytes == b"history must wait")
        );
        let key = agenc_ircd_storage::federation_records::request_result_key(
            prepared.record.request.replay_key,
        )?;
        let revision = fixture
            .context_mut()?
            .domain()
            .revision()
            .get()
            .checked_add(1)
            .ok_or("revision")?;
        let plaintext = PersistentRecordValue::new(
            TableId::RequestResult,
            HISTORY_EDGE_REQUEST_KIND,
            revision,
            0,
            None,
            Vec::new(),
            body,
        )?
        .encode()?;
        let write =
            AccountServiceDurableWrite::put(TableId::RequestResult, key.clone(), plaintext)?;
        drop(prepared);
        let mut restarted = EdgeFederation::new(edge.config);
        fixture.commit_and_restore_edge(vec![write], &mut restarted, None)?;
        assert!(fixture.stored_row_exists(TableId::RequestResult, key)?);
        assert!(restarted.pending.is_empty());
        assert!(restarted.history.records.is_empty());
        assert!(restarted.history.batches.is_empty());
        assert!(sink.lines().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn a_revoked_history_page_cancels_only_its_query_after_metadata_commit() -> TestResult {
    let (mut fixture, mut edge, sink, page) = fixture()?;
    let record = edge.history.records.get(&ID).ok_or("record")?.clone();
    edge.replica.install(2, Vec::new())?;
    let prepared = prepare_page(
        &edge,
        fixture.context_mut()?,
        ConnectionGeneration::new(1),
        record,
        FederationHash32::from_bytes([14; 32]),
        &page,
    )
    .map_err(|error| format!("prepare: {error:?}"))?;
    assert!(prepared.record.sink_gone);
    assert!(sink.lines().is_empty());
    assert!(edge.pending.contains_key(&ID));
    committed(&mut edge, fixture.context_mut()?, prepared);
    assert_eq!(edge.phase, Phase::Active);
    assert!(!edge.pending.contains_key(&ID));
    let lines = sink.lines();
    assert_eq!(lines.len(), 1);
    assert!(lines.first().ok_or("failure")?.contains("QUERY_EXPIRED"));
    assert!(!lines.iter().any(|line| line.contains("history must wait")));
    Ok(())
}

#[tokio::test]
async fn disabled_or_unnegotiated_history_never_allocates_a_federation_request() -> TestResult {
    for (enabled, negotiated) in [(false, true), (true, false)] {
        let (mut fixture, mut edge, sink, _) = fixture_with_options(enabled, negotiated)?;
        let pending = edge.pending.remove(&ID).ok_or("pending")?;
        let PendingKind::Command { message } = pending.kind else {
            return Err("command".into());
        };
        edge.history.records.clear();
        edge.history.batches.clear();
        let generation = ConnectionGeneration::new(1);
        let origin = edge.origins.get(&generation).ok_or("origin")?;
        let sequence = origin.sequence;
        let operation = FederatedOperation::HistoryQuery {
            session_id: origin.session.ok_or("session")?.0,
            channel_id: CHANNEL,
            selector: codec::selector_object(agenc_ircd_domain::HistorySelector::Latest(None))?,
            limit: 7,
            cursor: None,
        };
        assert!(
            begin(
                &mut edge,
                fixture.context_mut()?,
                generation,
                message,
                operation
            )
            .is_ok()
        );
        assert_eq!(
            edge.origins.get(&generation).ok_or("origin")?.sequence,
            sequence
        );
        assert!(edge.pending.is_empty());
        assert!(edge.commit.is_none());
        assert!(edge.history.batches.is_empty());
        assert_eq!(edge.phase, Phase::Active);
        assert!(
            sink.lines()
                .first()
                .is_some_and(|line| line.contains("FAIL CHATHISTORY UNAVAILABLE"))
        );
    }
    Ok(())
}

#[path = "refusals.rs"]
mod refusals;

#[path = "lifecycle.rs"]
mod lifecycle;

#[path = "restored.rs"]
mod restored;

#[path = "retention.rs"]
mod retention;
