#![forbid(unsafe_code)]

//! In-process coordinator tests: scripted edges speak the federation frames
//! over the state owner's inbox and read the rendered lines from the link
//! queue, so every path runs through the real actor loop and storage.

use std::error::Error;
use std::future::Future;

use agenc_ircd_domain::federation::ProjectedEvent;
use agenc_ircd_federation_wire::{
    AssembledObject, AssemblyProgress, CanonicalEncode, DecodeBudget, EventHeader, FederationFrame,
    FragmentAssembler, OperationDescriptor, OriginDescriptor, OriginRecord, OriginSession,
    ReplayKey, RequestHeader, ResultHeader, SchemaObject, decode_event_arm, decode_result_arm,
    federation_object_id, split_fragments,
};
use agenc_ircd_types::{
    ConnectionId, FederationResultKind, FederationRole, NetworkId, ORIGIN_DISCONNECT_GRACE_SECONDS,
    OriginId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation, SessionId, UserId,
};
use tokio::sync::mpsc;

use super::*;
use crate::cancel::CancellationToken;
use crate::federation::codec::events::projected_event_of;
use crate::federation::codec::operations::{FederatedOperation, JoinTarget, MessageTargetArg};
use crate::federation::codec::results::ResultArm;
use crate::federation::link::{LinkQueue, carrier_of, link_queue, parse_frame};
use crate::state_core::StateCoreExit;
use crate::state_core::inbox::{LifecyclePhase, connection_close_channel, lifecycle_channel};
use crate::test_support::StateCoreFixture;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const NETWORK: NetworkId = NetworkId::from_bytes([31; 32]);
const COORDINATOR: ServerId = ServerId::from_bytes([32; 16]);
const COORDINATOR_NAME: &str = "server.example";

fn entropy_script() -> Vec<u8> {
    (0_u32..1_048_576)
        .map(|index| u8::try_from((index.wrapping_mul(7).wrapping_add(3)) % 256).unwrap_or(0))
        .collect()
}

fn peer_identity(server_id: ServerId, name: &str) -> PeerIdentity {
    PeerIdentity::new(
        server_id,
        name,
        FederationRole::Edge,
        RecoveryEpoch::from_bytes([0; 16]),
        agenc_ircd_crypto::Ed25519SecretKey::from_bytes([9; 32]).public_key(),
        [8; 32],
    )
}

/// One scripted edge.
struct Edge {
    server_id: ServerId,
    incarnation: ServerIncarnation,
    link: LinkId,
    handle: LinkHandle,
    queue: LinkQueue,
    assembler: FragmentAssembler,
    inbox: mpsc::Sender<FederationInbound>,
    next_link: u64,
    /// The last event this edge acknowledged.
    last_ack: Option<(u64, agenc_ircd_types::EventId)>,
    /// The projection generation this edge has active.
    projection_generation: u64,
    /// The channel revisions this edge last learned from events.
    channel_revisions: std::collections::BTreeMap<agenc_ircd_types::ChannelInstanceId, u64>,
}

impl Edge {
    fn new(inbox: mpsc::Sender<FederationInbound>, seed: u8) -> Self {
        let (handle, queue) = link_queue(1 << 20);
        Self {
            server_id: ServerId::from_bytes([seed; 16]),
            incarnation: ServerIncarnation::from_bytes([seed.wrapping_add(1); 16]),
            link: LinkId::new(u64::from(seed)),
            handle,
            queue,
            assembler: FragmentAssembler::new(),
            inbox,
            next_link: u64::from(seed).saturating_add(100),
            last_ack: None,
            projection_generation: 1,
            channel_revisions: std::collections::BTreeMap::new(),
        }
    }

    async fn send(&self, event: LinkEvent) -> TestResult {
        self.inbox
            .send(FederationInbound {
                link: self.link,
                peer: self.server_id,
                event,
                charge: None,
            })
            .await
            .map_err(|_| "coordinator inbox closed")?;
        Ok(())
    }

    async fn establish(&mut self) -> TestResult {
        let (handle, queue) = link_queue(1 << 20);
        self.handle = handle;
        self.queue = queue;
        self.link = LinkId::new(self.next_link);
        self.next_link = self.next_link.saturating_add(1);
        let session = LinkSession {
            link: self.link,
            peer: self.server_id,
            peer_incarnation: self.incarnation,
            peer_recovery_epoch: RecoveryEpoch::from_bytes([0; 16]),
            transition: agenc_ircd_federation_wire::EpochTransition::Initial,
        };
        self.send(LinkEvent::Established {
            session,
            handle: self.handle.clone(),
        })
        .await
    }

    async fn frame(&self, frame: FederationFrame) -> TestResult {
        self.send(LinkEvent::Frame(frame)).await
    }

    /// Splits and locally reassembles an object exactly as the link would,
    /// then hands the coordinator the assembled object.
    async fn object(
        &mut self,
        encoded: &[u8],
        frame: impl Fn(agenc_ircd_federation_wire::FederationFragment) -> FederationFrame,
    ) -> TestResult {
        let object_id = federation_object_id(encoded);
        let mut assembled = None;
        let mut carrier = None;
        for fragment in split_fragments(object_id, encoded)? {
            let built = frame(fragment);
            let (this_carrier, key) = carrier_of(&built).map_err(|error| error.to_string())?;
            let fragment = built.fragment().ok_or("frame without fragment")?;
            carrier = Some(this_carrier);
            if let AssemblyProgress::Complete(object) = self.assembler.admit(key, fragment, 0)? {
                assembled = Some(object);
            }
        }
        let (Some(object), Some(carrier)) = (assembled, carrier) else {
            return Err("scripted object did not assemble".into());
        };
        self.send(LinkEvent::Object { carrier, object }).await
    }

    async fn close(&self) -> TestResult {
        self.send(LinkEvent::Closed(LinkCloseReason::PeerClosed))
            .await
    }

    async fn next_frame(&mut self) -> TestResult<FederationFrame> {
        let line = tokio::time::timeout(std::time::Duration::from_secs(20), self.queue.recv())
            .await
            .map_err(|_| "no line from the coordinator")?
            .ok_or("coordinator closed the link")?;
        let text = line.as_str().trim_end_matches("\r\n").to_owned();
        Ok(parse_frame(&text, COORDINATOR_NAME).map_err(|error| format!("{error:?}: {text}"))?)
    }

    async fn next_object(&mut self) -> TestResult<(ObjectCarrier, AssembledObject)> {
        loop {
            let frame = self.next_frame().await?;
            let (carrier, key) = carrier_of(&frame).map_err(|error| error.to_string())?;
            let fragment = frame.fragment().ok_or("frame without fragment")?;
            if let AssemblyProgress::Complete(object) = self.assembler.admit(key, fragment, 0)? {
                return Ok((carrier, object));
            }
        }
    }

    /// Drains whatever the coordinator queued before it noticed the fault,
    /// then requires the close request.
    async fn expect_closed(&mut self) -> TestResult {
        loop {
            let line = tokio::time::timeout(std::time::Duration::from_secs(20), self.queue.recv())
                .await
                .map_err(|_| "link stayed open")?;
            if line.is_none() {
                return Ok(());
            }
        }
    }
}

/// One scripted origin of an edge.
struct Origin {
    id: OriginId,
    generation: u64,
    sequence: u64,
    previous_object_id: [u8; 32],
    object_id: [u8; 32],
    connection_id: ConnectionId,
    session: Option<(SessionId, UserId)>,
}

impl Origin {
    fn new(seed: u8) -> Self {
        Self {
            id: OriginId::from_bytes([seed; 16]),
            generation: 0,
            sequence: 0,
            previous_object_id: [0; 32],
            object_id: [0; 32],
            connection_id: ConnectionId::from_bytes([seed.wrapping_add(50); 16]),
            session: None,
        }
    }

    /// Moves to the next generation; the accepted object becomes the
    /// predecessor of the next declaration.
    fn advance_generation(&mut self) {
        self.generation += 1;
        self.previous_object_id = self.object_id;
        self.sequence = 0;
    }

    fn record(&self, edge: &Edge) -> OriginRecord {
        OriginRecord {
            network_id: NETWORK,
            home_server_id: edge.server_id,
            server_incarnation: edge.incarnation,
            origin_id: self.id,
            generation: self.generation,
            previous_origin_object_id: self.previous_object_id,
            connection_id: self.connection_id,
            session: self.session.map(|(session_id, user_id)| OriginSession {
                session_id,
                user_id,
            }),
            account: None,
            connection_nonce: [5; 32],
        }
    }

    fn replay_key(&self, edge: &Edge) -> ReplayKey {
        ReplayKey {
            home_server_id: edge.server_id,
            server_incarnation: edge.incarnation,
            origin_id: self.id,
            origin_generation: self.generation,
            operation_sequence: self.sequence,
        }
    }
}

async fn declare(edge: &mut Edge, origin: &mut Origin, update: bool) -> TestResult {
    let encoded = origin.record(edge).to_object()?.encode_canonical()?;
    let bytes = encoded.as_slice().to_vec();
    let object_id = federation_object_id(&bytes);
    let descriptor = OriginDescriptor {
        coordinator_server_id: COORDINATOR,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
        generation: origin.generation,
        object_id,
    };
    edge.object(&bytes, |fragment| {
        if update {
            FederationFrame::OriginUpdate {
                descriptor,
                fragment,
            }
        } else {
            FederationFrame::OriginAdd {
                descriptor,
                fragment,
            }
        }
    })
    .await?;
    match edge.next_frame().await? {
        FederationFrame::OriginAck {
            origin_id,
            generation,
            object_id: acked,
            ..
        } if origin_id == origin.id && generation == origin.generation => {
            if acked != Some(object_id) {
                return Err("origin ack named another object".into());
            }
        }
        other => return Err(format!("expected origin ack, got {:?}", other.kind()).into()),
    }
    origin.object_id = *object_id.as_bytes();
    Ok(())
}

/// Replays the origins and resumes from the edge's last acknowledged
/// cursor, returning the coordinator's FRESUME reply.
async fn synchronize(edge: &mut Edge, origins: &mut [&mut Origin]) -> TestResult<FederationFrame> {
    edge.frame(FederationFrame::OriginReset {
        coordinator_server_id: COORDINATOR,
        server_incarnation: edge.incarnation,
    })
    .await?;
    for origin in origins.iter_mut() {
        // A replayed declaration is the exact current object: ADD for a
        // generation-zero origin, UPDATE for a later generation.
        let update = origin.generation > 0;
        declare(edge, origin, update).await?;
    }
    edge.frame(FederationFrame::OriginReady {
        edge_server_id: edge.server_id,
        server_incarnation: edge.incarnation,
    })
    .await?;
    let cursor = match edge.last_ack {
        Some((delivery_sequence, event_id)) => agenc_ircd_federation_wire::DeliveryCursor::At {
            delivery_sequence,
            event_id,
        },
        None => agenc_ircd_federation_wire::DeliveryCursor::Empty,
    };
    edge.frame(FederationFrame::Resume {
        coordinator_server_id: COORDINATOR,
        projection_generation: edge.projection_generation,
        cursor,
    })
    .await?;
    edge.next_frame().await
}

/// Synchronizes and requires FRESUME OK.
async fn synchronize_ok(edge: &mut Edge, origins: &mut [&mut Origin]) -> TestResult {
    match synchronize(edge, origins).await? {
        FederationFrame::ResumeOk { .. } => Ok(()),
        other => Err(format!("expected FRESUME OK, got {:?}", other.kind()).into()),
    }
}

/// The decoded answer to one request: the result arm plus the events the
/// requesting edge received before or after it, in order.
struct Answer {
    header: ResultHeader,
    arm: ResultArm,
    bytes: Vec<u8>,
}

async fn request(
    edge: &mut Edge,
    origin: &mut Origin,
    operation: &FederatedOperation,
) -> TestResult<Vec<u8>> {
    let request_id = RequestId::from_bytes({
        let mut id = [0_u8; 16];
        id[..8].copy_from_slice(&origin.sequence.to_be_bytes());
        id[8..].copy_from_slice(&origin.generation.to_be_bytes());
        // Test sequences stay far below 2^56, so the high byte is free to
        // keep request identities distinct across origins.
        id[0] = origin.id.as_bytes()[0];
        id
    });
    let header = RequestHeader {
        network_id: NETWORK,
        replay_key: origin.replay_key(edge),
        request_id,
        opcode: operation.opcode(),
    };
    let object = header.build(&operation.to_object()?)?;
    let bytes = object.encode_canonical()?.as_slice().to_vec();
    send_request(edge, &header, &bytes).await?;
    Ok(bytes)
}

async fn send_request(edge: &mut Edge, header: &RequestHeader, bytes: &[u8]) -> TestResult {
    let descriptor = OperationDescriptor {
        addressed_server_id: COORDINATOR,
        server_incarnation: header.replay_key.server_incarnation,
        origin_id: header.replay_key.origin_id,
        origin_generation: header.replay_key.origin_generation,
        operation_sequence: header.replay_key.operation_sequence,
        request_id: header.request_id,
        object_id: federation_object_id(bytes),
    };
    edge.object(bytes, |fragment| FederationFrame::Request {
        descriptor,
        fragment,
    })
    .await
}

/// Reads frames until the result for the request arrives, acknowledging
/// every event in between and collecting them.
async fn answer(
    edge: &mut Edge,
    events: &mut Vec<(EventHeader, ProjectedEvent)>,
) -> TestResult<Answer> {
    loop {
        let (carrier, object) = edge.next_object().await?;
        match carrier {
            ObjectCarrier::Result(_) => {
                let mut budget = DecodeBudget::new(1 << 20, 4_096);
                let result =
                    SchemaObject::decode_exact("FederationResult", object.as_slice(), &mut budget)?;
                let header = ResultHeader::from_object(&result)?;
                let arm = ResultArm::from_object(
                    header.result_kind,
                    &decode_result_arm(&result, &mut budget)?,
                )?;
                return Ok(Answer {
                    header,
                    arm,
                    bytes: object.as_slice().to_vec(),
                });
            }
            ObjectCarrier::Event(descriptor) => {
                events.push(decode_event(edge, descriptor.delivery_sequence, &object).await?);
            }
            _ => return Err("unexpected object from the coordinator".into()),
        }
    }
}

async fn decode_event(
    edge: &mut Edge,
    delivery_sequence: u64,
    object: &AssembledObject,
) -> TestResult<(EventHeader, ProjectedEvent)> {
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let event = SchemaObject::decode_exact("FederationEvent", object.as_slice(), &mut budget)?;
    let header = EventHeader::from_object(&event)?;
    if header.delivery_sequence != delivery_sequence || header.target_server_id != edge.server_id {
        return Err("event descriptor disagrees with its object".into());
    }
    let arm = decode_event_arm(&event, &mut budget)?;
    let projected = projected_event_of(header.event_kind, &arm, &mut budget)?;
    match &projected {
        ProjectedEvent::ChannelVisible(detail) => {
            edge.channel_revisions
                .insert(detail.channel_id, detail.channel_revision.get());
        }
        ProjectedEvent::MemberJoined { view, .. } => {
            edge.channel_revisions.insert(
                view.membership.channel_id,
                view.membership.membership_revision.get(),
            );
        }
        ProjectedEvent::MemberParted {
            channel_id,
            resulting_revision,
            ..
        }
        | ProjectedEvent::TopicChanged {
            channel_id,
            resulting_revision,
            ..
        } => {
            edge.channel_revisions
                .insert(*channel_id, resulting_revision.get());
        }
        _ => {}
    }
    edge.frame(FederationFrame::Ack {
        coordinator_server_id: COORDINATOR,
        delivery_sequence,
        event_id: header.event_id,
    })
    .await?;
    edge.last_ack = Some((delivery_sequence, header.event_id));
    Ok((header, projected))
}

async fn next_event(edge: &mut Edge) -> TestResult<(EventHeader, ProjectedEvent)> {
    let (carrier, object) = edge.next_object().await?;
    let ObjectCarrier::Event(descriptor) = carrier else {
        return Err("expected an event".into());
    };
    decode_event(edge, descriptor.delivery_sequence, &object).await
}

async fn run_coordinator<Driver, Output>(
    edges: &[PeerIdentity],
    driver: impl FnOnce(mpsc::Sender<FederationInbound>) -> Driver,
) -> TestResult<Output>
where
    Driver: Future<Output = TestResult<Output>>,
{
    let mut fixture =
        StateCoreFixture::with_federation_coordinator(entropy_script(), edges.to_vec())?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (federation, federation_receiver) = mpsc::channel(64);
    parts.state.install_federation_inbox(federation_receiver)?;
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let token = CancellationToken::root();
    let driven = async move {
        let output = driver(federation).await;
        let _stopped = lifecycle.request(LifecyclePhase::Stop).await;
        drop(inbox);
        output
    };
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        token,
    );
    let (exit, output) = tokio::join!(run, driven);
    if !matches!(exit, StateCoreExit::Stopped) {
        return Err(format!("coordinator exited with {exit:?}").into());
    }
    output
}

fn session_open(seed: u8, nickname: &str) -> FederatedOperation {
    FederatedOperation::SessionOpen {
        connection_id: ConnectionId::from_bytes([seed; 16]),
        auth_grant_id: None,
        nickname: nickname.to_owned(),
        realname: "Real Name".to_owned(),
        capability_hash: [1; 32],
        connection_nonce: [2; 32],
    }
}

/// Opens a session for the origin and binds it through FORIGIN UPDATE.
async fn open_session(
    edge: &mut Edge,
    origin: &mut Origin,
    nickname: &str,
    events: &mut Vec<(EventHeader, ProjectedEvent)>,
) -> TestResult<(SessionId, UserId, u64)> {
    request(
        edge,
        origin,
        &session_open(origin.id.as_bytes()[0], nickname),
    )
    .await?;
    let answer = answer(edge, events).await?;
    let ResultArm::SessionRegistered(registered) = answer.arm else {
        return Err(format!(
            "expected session_registered, got {:?}",
            answer.header.result_kind
        )
        .into());
    };
    origin.sequence += 1;
    let completion = answer
        .header
        .completion_event_id
        .ok_or("committed result without completion")?;
    let mut saw_completion = false;
    while !saw_completion {
        if events
            .iter()
            .any(|(header, _)| header.event_id == completion)
        {
            saw_completion = true;
        } else {
            events.push(next_event(edge).await?);
        }
    }
    origin.session = Some((registered.session_id, registered.user_id));
    origin.advance_generation();
    declare(edge, origin, true).await?;
    Ok((
        registered.session_id,
        registered.user_id,
        registered.session_revision,
    ))
}

#[tokio::test]
async fn origin_exchange_and_session_open_commit_result_then_events() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([40; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 40);
        let mut origin = Origin::new(60);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let mut events = Vec::new();
        let (session_id, user_id, revision) =
            open_session(&mut edge, &mut origin, "alice", &mut events).await?;
        let kinds: Vec<_> = events.iter().map(|(header, _)| header.event_kind).collect();
        assert_eq!(
            kinds,
            vec![
                agenc_ircd_types::FederationEventKind::SessionVisible,
                agenc_ircd_types::FederationEventKind::RequestCompleted
            ]
        );
        let Some((visible_header, ProjectedEvent::SessionVisible(view))) = events.first() else {
            return Err("first event is not session_visible".into());
        };
        let projection = view
            .home_projection
            .as_ref()
            .ok_or("home edge lacks projection")?;
        assert_eq!(projection.session_id, session_id);
        assert_eq!(projection.user_id, user_id);
        assert_eq!(projection.session_revision.get(), revision);
        assert_eq!(visible_header.delivery_sequence, 0);
        let Some((
            completion,
            ProjectedEvent::RequestCompleted {
                resulting_state_generation,
            },
        )) = events.get(1)
        else {
            return Err("second event is not request_completed".into());
        };
        assert_eq!(*resulting_state_generation, revision);
        assert_eq!(completion.coordinator_state_generation, revision);
        let correlation = completion
            .correlation
            .ok_or("completion lacks correlation")?;
        assert_eq!(correlation.replay_key.operation_sequence, 0);
        assert_eq!(completion.delivery_sequence, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_duplicate_replays_identical_result_bytes_from_storage() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([41; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 41);
        let mut origin = Origin::new(61);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let operation = session_open(61, "bob");
        let bytes = request(&mut edge, &mut origin, &operation).await?;
        let mut events = Vec::new();
        let first = answer(&mut edge, &mut events).await?;
        while events.len() < 2 {
            events.push(next_event(&mut edge).await?);
        }
        let header = RequestHeader::from_object(&SchemaObject::decode_exact(
            "FederationRequest",
            &bytes,
            &mut DecodeBudget::new(1 << 20, 4_096),
        )?)?;
        send_request(&mut edge, &header, &bytes).await?;
        let mut replayed_events = Vec::new();
        let second = answer(&mut edge, &mut replayed_events).await?;
        assert!(
            replayed_events.is_empty(),
            "a replay produces no new events"
        );
        assert_eq!(first.bytes, second.bytes);
        assert_eq!(
            first.header.result_kind,
            FederationResultKind::SessionRegistered
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn sequence_gap_closes_the_link() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([42; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 42);
        let mut origin = Origin::new(62);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        origin.sequence = 3;
        request(&mut edge, &mut origin, &session_open(62, "carol")).await?;
        edge.expect_closed().await
    })
    .await
}

#[tokio::test]
async fn stale_expected_revision_yields_a_failed_result() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([43; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 43);
        let mut origin = Origin::new(63);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let mut events = Vec::new();
        let (session_id, _, revision) =
            open_session(&mut edge, &mut origin, "dave", &mut events).await?;
        request(
            &mut edge,
            &mut origin,
            &FederatedOperation::NickChange {
                session_id,
                expected_session_revision: revision + 7,
                nickname: "dave2".to_owned(),
            },
        )
        .await?;
        let answer = answer(&mut edge, &mut events).await?;
        assert_eq!(answer.header.result_kind, FederationResultKind::Failed);
        assert!(answer.header.completion_event_id.is_none());
        let ResultArm::Failed { code, .. } = answer.arm else {
            return Err("expected failed arm".into());
        };
        assert_eq!(code, "STALE_STATE");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn joins_and_messages_project_across_two_edges() -> TestResult {
    let a = peer_identity(ServerId::from_bytes([44; 16]), "edge-a.example");
    let b = peer_identity(ServerId::from_bytes([45; 16]), "edge-b.example");
    run_coordinator(&[a, b], |inbox| async move {
        let mut edge_a = Edge::new(inbox.clone(), 44);
        let mut edge_b = Edge::new(inbox, 45);
        let mut origin_a = Origin::new(64);
        let mut origin_b = Origin::new(65);
        edge_a.establish().await?;
        edge_b.establish().await?;
        synchronize_ok(&mut edge_a, &mut [&mut origin_a]).await?;
        synchronize_ok(&mut edge_b, &mut [&mut origin_b]).await?;
        let mut events_a = Vec::new();
        let mut events_b = Vec::new();
        let (session_a, user_a, revision_a) =
            open_session(&mut edge_a, &mut origin_a, "erin", &mut events_a).await?;
        let (session_b, _user_b, revision_b) =
            open_session(&mut edge_b, &mut origin_b, "frank", &mut events_b).await?;
        events_a.clear();
        events_b.clear();
        // Erin creates #chat.
        request(
            &mut edge_a,
            &mut origin_a,
            &FederatedOperation::Join {
                session_id: session_a,
                expected_session_revision: revision_a,
                targets: vec![JoinTarget {
                    channel_name: "#chat".to_owned(),
                    join_key: zeroize::Zeroizing::new(Vec::new()),
                }],
            },
        )
        .await?;
        let joined = answer(&mut edge_a, &mut events_a).await?;
        assert_eq!(joined.header.result_kind, FederationResultKind::Committed);
        let completion = joined.header.completion_event_id.ok_or("no completion")?;
        while !events_a
            .iter()
            .any(|(header, _)| header.event_id == completion)
        {
            events_a.push(next_event(&mut edge_a).await?);
        }
        let kinds_a: Vec<_> = events_a
            .iter()
            .map(|(header, _)| header.event_kind)
            .collect();
        assert_eq!(
            kinds_a,
            vec![
                agenc_ircd_types::FederationEventKind::ChannelVisible,
                agenc_ircd_types::FederationEventKind::MemberJoined,
                agenc_ircd_types::FederationEventKind::RequestCompleted,
            ]
        );
        let channel_id = match events_a.first().map(|(_, event)| event) {
            Some(ProjectedEvent::ChannelVisible(detail)) => detail.channel_id,
            _ => return Err("expected channel_visible".into()),
        };
        events_a.clear();
        // Frank joins from the other edge; Erin's edge learns of the member.
        request(
            &mut edge_b,
            &mut origin_b,
            &FederatedOperation::Join {
                session_id: session_b,
                expected_session_revision: revision_b,
                targets: vec![JoinTarget {
                    channel_name: "#chat".to_owned(),
                    join_key: zeroize::Zeroizing::new(Vec::new()),
                }],
            },
        )
        .await?;
        let joined_b = answer(&mut edge_b, &mut events_b).await?;
        origin_b.sequence += 1;
        assert_eq!(joined_b.header.result_kind, FederationResultKind::Committed);
        let completion_b = joined_b.header.completion_event_id.ok_or("no completion")?;
        while !events_b
            .iter()
            .any(|(header, _)| header.event_id == completion_b)
        {
            events_b.push(next_event(&mut edge_b).await?);
        }
        let (_, event) = next_event(&mut edge_a).await?;
        let ProjectedEvent::MemberJoined {
            view,
            home_session_revision,
            ..
        } = event
        else {
            return Err("edge a expected member_joined".into());
        };
        assert_eq!(view.membership.channel_id, channel_id);
        assert_eq!(view.source.nickname.presentation(), "frank");
        assert!(
            home_session_revision.is_none(),
            "frank is not homed on edge a"
        );
        // Frank speaks; Erin's edge receives the delivered message and the
        // channel revision Frank's edge named was exact.
        let channel_revision = events_b
            .iter()
            .find_map(|(_, event)| match event {
                ProjectedEvent::MemberJoined { view, .. } => {
                    Some(view.membership.membership_revision)
                }
                _ => None,
            })
            .ok_or("frank's edge saw no member_joined")?;
        let _ = channel_revision;
        let _ = user_a;
        request(
            &mut edge_b,
            &mut origin_b,
            &FederatedOperation::Message {
                session_id: session_b,
                kind: agenc_ircd_domain::MessageKind::Privmsg,
                targets: vec![MessageTargetArg::Channel {
                    channel_id,
                    expected_revision: joined_b_channel_revision(&events_b)?,
                }],
                tags: Vec::new(),
                body: "hello erin".to_owned(),
            },
        )
        .await?;
        let mut spoke_events = Vec::new();
        let spoke = answer(&mut edge_b, &mut spoke_events).await?;
        if let ResultArm::Failed { code, .. } = &spoke.arm {
            return Err(format!("message failed with {code}").into());
        }
        assert_eq!(spoke.header.result_kind, FederationResultKind::Committed);
        let (_, delivered) = next_event(&mut edge_a).await?;
        let ProjectedEvent::MessageDelivered(record) = delivered else {
            return Err("edge a expected message_delivered".into());
        };
        assert_eq!(record.body, "hello erin");
        assert_eq!(record.sender.nickname.presentation(), "frank");
        Ok(())
    })
    .await
}

/// The channel revision the joining edge observed in its own join events.
fn joined_b_channel_revision(events: &[(EventHeader, ProjectedEvent)]) -> TestResult<u64> {
    events
        .iter()
        .find_map(|(_, event)| match event {
            ProjectedEvent::ChannelVisible(detail) => Some(detail.channel_revision.get()),
            _ => None,
        })
        .ok_or_else(|| "joining edge saw no channel_visible".into())
}

#[tokio::test]
async fn wrong_acknowledgement_closes_the_link() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([46; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 46);
        let mut origin = Origin::new(66);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        request(&mut edge, &mut origin, &session_open(66, "gina")).await?;
        // Read the result and first event without acknowledging, then ack
        // the wrong sequence.
        let mut saw_event = false;
        while !saw_event {
            let (carrier, _) = edge.next_object().await?;
            saw_event = matches!(carrier, ObjectCarrier::Event(_));
        }
        edge.frame(FederationFrame::Ack {
            coordinator_server_id: COORDINATOR,
            delivery_sequence: 7,
            event_id: agenc_ircd_types::EventId::from_bytes([0; 16]),
        })
        .await?;
        edge.expect_closed().await
    })
    .await
}

#[tokio::test]
async fn session_close_hides_the_session_on_every_sharing_edge() -> TestResult {
    let a = peer_identity(ServerId::from_bytes([47; 16]), "edge-a.example");
    let b = peer_identity(ServerId::from_bytes([48; 16]), "edge-b.example");
    run_coordinator(&[a, b], |inbox| async move {
        let mut edge_a = Edge::new(inbox.clone(), 47);
        let mut edge_b = Edge::new(inbox, 48);
        let mut origin_a = Origin::new(67);
        let mut origin_b = Origin::new(68);
        edge_a.establish().await?;
        edge_b.establish().await?;
        synchronize_ok(&mut edge_a, &mut [&mut origin_a]).await?;
        synchronize_ok(&mut edge_b, &mut [&mut origin_b]).await?;
        let mut events_a = Vec::new();
        let mut events_b = Vec::new();
        let (session_a, _, revision_a) =
            open_session(&mut edge_a, &mut origin_a, "hana", &mut events_a).await?;
        let (session_b, _, revision_b) =
            open_session(&mut edge_b, &mut origin_b, "ivan", &mut events_b).await?;
        for (edge, origin, session, revision) in [
            (&mut edge_a, &mut origin_a, session_a, revision_a),
            (&mut edge_b, &mut origin_b, session_b, revision_b),
        ] {
            let mut events = Vec::new();
            request(
                edge,
                origin,
                &FederatedOperation::Join {
                    session_id: session,
                    expected_session_revision: revision,
                    targets: vec![JoinTarget {
                        channel_name: "#room".to_owned(),
                        join_key: zeroize::Zeroizing::new(Vec::new()),
                    }],
                },
            )
            .await?;
            let joined = answer(edge, &mut events).await?;
            origin.sequence += 1;
            let completion = joined.header.completion_event_id.ok_or("no completion")?;
            while !events
                .iter()
                .any(|(header, _)| header.event_id == completion)
            {
                events.push(next_event(edge).await?);
            }
        }
        // Edge a also sees Ivan join.
        let (_, joined) = next_event(&mut edge_a).await?;
        assert!(matches!(joined, ProjectedEvent::MemberJoined { .. }));
        // Ivan's connection ends.
        request(
            &mut edge_b,
            &mut origin_b,
            &FederatedOperation::SessionClose {
                session_id: session_b,
                reason_code: 2,
            },
        )
        .await?;
        let mut close_events = Vec::new();
        let closed = answer(&mut edge_b, &mut close_events).await?;
        assert_eq!(closed.header.result_kind, FederationResultKind::Committed);
        let (_, hidden) = next_event(&mut edge_a).await?;
        let ProjectedEvent::SessionHidden {
            source,
            channels,
            kind,
            ..
        } = hidden
        else {
            return Err("edge a expected session_hidden".into());
        };
        assert_eq!(source.nickname.presentation(), "ivan");
        assert_eq!(channels.len(), 1);
        assert_eq!(
            kind,
            agenc_ircd_domain::federation::SessionHideKind::TransportLost
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconnect_replays_origins_and_continues_the_sequence() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([49; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 49);
        let mut origin = Origin::new(69);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let mut events = Vec::new();
        let (session_id, _, revision) =
            open_session(&mut edge, &mut origin, "june", &mut events).await?;
        edge.close().await?;
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        request(
            &mut edge,
            &mut origin,
            &FederatedOperation::Setname {
                session_id,
                expected_session_revision: revision,
                display_name: "June Doe".to_owned(),
            },
        )
        .await?;
        let mut after = Vec::new();
        let renamed = answer(&mut edge, &mut after).await?;
        assert_eq!(renamed.header.result_kind, FederationResultKind::Committed);
        assert_eq!(renamed.header.replay_key.origin_generation, 1);
        assert_eq!(renamed.header.replay_key.operation_sequence, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn synchronous_grace_expiry_hides_every_hosted_session() -> TestResult {
    use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = FederationCoordinator::new(
        CoordinatorConfig {
            network_id: NETWORK,
            server_id: COORDINATOR,
            server_name: COORDINATOR_NAME.to_owned(),
            recovery_epoch: RecoveryEpoch::from_bytes([34; 16]),
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        vec![peer_identity(peer, "edge.example")],
        std::sync::Arc::new(crate::test_support::TestChannelKeyVerifier),
        ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    );
    let (handle, _queue) = link_queue(1 << 20);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    coordinator.inbound(
        context,
        FederationInbound {
            link: LinkId::new(1),
            peer,
            event: LinkEvent::Established {
                session: LinkSession {
                    link: LinkId::new(1),
                    peer,
                    peer_incarnation: incarnation,
                    peer_recovery_epoch: RecoveryEpoch::from_bytes([0; 16]),
                    transition: agenc_ircd_federation_wire::EpochTransition::Initial,
                },
                handle,
            },
            charge: None,
        },
    );
    coordinator.inbound(
        context,
        FederationInbound {
            link: LinkId::new(1),
            peer,
            event: LinkEvent::Frame(FederationFrame::OriginReset {
                coordinator_server_id: COORDINATOR,
                server_incarnation: incarnation,
            }),
            charge: None,
        },
    );
    // A session hosted by the edge exists in the live domain.
    let seed = crate::test_support::remote_session_seed(context, peer, "kate")?;
    let user_id = seed.user_id;
    let plan = context.domain().plan_session_opened(seed)?;
    crate::test_support::apply_live_plan(context, plan)?;
    coordinator.inbound(
        context,
        FederationInbound {
            link: LinkId::new(1),
            peer,
            event: LinkEvent::Closed(LinkCloseReason::PeerClosed),
            charge: None,
        },
    );
    let deadline = context
        .now()
        .checked_add(ORIGIN_DISCONNECT_GRACE_SECONDS.saturating_mul(1_000))?;
    let entry: TimerEntry = context
        .timers_mut()
        .pop_due(deadline)
        .ok_or("link loss scheduled no grace timer")?;
    assert_eq!(entry.kind, TimerKind::FederationGrace);
    assert_eq!(entry.id, TimedId::Peer(peer));
    assert_eq!(entry.deadline, deadline);
    let handled = coordinator.timer_fired(context, entry);
    assert!(handled);
    assert_eq!(coordinator.counters().sessions_expired, 1);
    assert_eq!(
        context.pending_len(),
        1,
        "the hide plan is staged for commit"
    );
    assert!(
        context.domain().session(user_id).is_some(),
        "the session hides only after commit"
    );
    Ok(())
}

/// Joins one channel from the origin and reads its own events through the
/// completion, returning the channel identity.
async fn join_channel(
    edge: &mut Edge,
    origin: &mut Origin,
    session_id: SessionId,
    revision: u64,
    channel_name: &str,
) -> TestResult<agenc_ircd_types::ChannelInstanceId> {
    let mut events = Vec::new();
    request(
        edge,
        origin,
        &FederatedOperation::Join {
            session_id,
            expected_session_revision: revision,
            targets: vec![JoinTarget {
                channel_name: channel_name.to_owned(),
                join_key: zeroize::Zeroizing::new(Vec::new()),
            }],
        },
    )
    .await?;
    let joined = answer(edge, &mut events).await?;
    origin.sequence += 1;
    if joined.header.result_kind != FederationResultKind::Committed {
        return Err("join was not committed".into());
    }
    let completion = joined.header.completion_event_id.ok_or("no completion")?;
    while !events
        .iter()
        .any(|(header, _)| header.event_id == completion)
    {
        events.push(next_event(edge).await?);
    }
    events
        .iter()
        .find_map(|(_, event)| match event {
            ProjectedEvent::ChannelVisible(detail) => Some(detail.channel_id),
            _ => None,
        })
        .ok_or_else(|| "join produced no channel_visible".into())
}

#[tokio::test]
async fn resume_with_the_retained_cursor_replays_events_reserved_while_away() -> TestResult {
    let a = peer_identity(ServerId::from_bytes([52; 16]), "edge-a.example");
    let b = peer_identity(ServerId::from_bytes([53; 16]), "edge-b.example");
    run_coordinator(&[a, b], |inbox| async move {
        let mut edge_a = Edge::new(inbox.clone(), 52);
        let mut edge_b = Edge::new(inbox, 53);
        let mut origin_a = Origin::new(72);
        let mut origin_b = Origin::new(73);
        for (edge, origin) in [(&mut edge_a, &mut origin_a), (&mut edge_b, &mut origin_b)] {
            edge.establish().await?;
            let FederationFrame::ResumeOk {
                next_delivery_sequence,
                ..
            } = synchronize(edge, &mut [origin]).await?
            else {
                return Err("expected FRESUME OK on an empty projection".into());
            };
            assert_eq!(next_delivery_sequence, 0);
        }
        let mut events_a = Vec::new();
        let mut events_b = Vec::new();
        let (session_a, _, revision_a) =
            open_session(&mut edge_a, &mut origin_a, "lena", &mut events_a).await?;
        let (session_b, _, revision_b) =
            open_session(&mut edge_b, &mut origin_b, "milo", &mut events_b).await?;
        join_channel(&mut edge_a, &mut origin_a, session_a, revision_a, "#away").await?;
        // Edge a drops its link with everything acknowledged so far.
        let cursor_a = edge_a.last_ack;
        edge_a.close().await?;
        // Milo joins while edge a is away; the member_joined is reserved.
        let channel =
            join_channel(&mut edge_b, &mut origin_b, session_b, revision_b, "#away").await?;
        // Edge a reconnects and resumes from its exact cursor.
        edge_a.establish().await?;
        let (sequence, _) = cursor_a.ok_or("edge a acknowledged nothing")?;
        let FederationFrame::ResumeOk {
            next_delivery_sequence,
            projection_generation,
            ..
        } = synchronize(&mut edge_a, &mut [&mut origin_a]).await?
        else {
            return Err("expected FRESUME OK".into());
        };
        assert_eq!(projection_generation, 1);
        assert_eq!(next_delivery_sequence, sequence + 1);
        let (header, event) = next_event(&mut edge_a).await?;
        assert_eq!(header.delivery_sequence, sequence + 1);
        let ProjectedEvent::MemberJoined { view, .. } = event else {
            return Err("expected the reserved member_joined after resume".into());
        };
        assert_eq!(view.membership.channel_id, channel);
        assert_eq!(view.source.nickname.presentation(), "milo");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unknown_cursor_triggers_a_verified_snapshot_and_active_swap() -> TestResult {
    let a = peer_identity(ServerId::from_bytes([54; 16]), "edge-a.example");
    let b = peer_identity(ServerId::from_bytes([55; 16]), "edge-b.example");
    run_coordinator(&[a, b], |inbox| async move {
        let mut edge_a = Edge::new(inbox.clone(), 54);
        let mut edge_b = Edge::new(inbox, 55);
        let mut origin_a = Origin::new(74);
        let mut origin_b = Origin::new(75);
        for (edge, origin) in [(&mut edge_a, &mut origin_a), (&mut edge_b, &mut origin_b)] {
            edge.establish().await?;
            synchronize_ok(edge, &mut [origin]).await?;
        }
        let mut events_a = Vec::new();
        let mut events_b = Vec::new();
        let (session_a, user_a, revision_a) =
            open_session(&mut edge_a, &mut origin_a, "nora", &mut events_a).await?;
        let (session_b, _, revision_b) =
            open_session(&mut edge_b, &mut origin_b, "omar", &mut events_b).await?;
        let channel =
            join_channel(&mut edge_a, &mut origin_a, session_a, revision_a, "#snap").await?;
        join_channel(&mut edge_b, &mut origin_b, session_b, revision_b, "#snap").await?;
        let (_, joined) = next_event(&mut edge_a).await?;
        assert!(matches!(joined, ProjectedEvent::MemberJoined { .. }));
        // Edge a loses its durable cursor and resumes from a stale one.
        edge_a.close().await?;
        edge_a.establish().await?;
        edge_a.last_ack = Some((0, agenc_ircd_types::EventId::from_bytes([1; 16])));
        let FederationFrame::ResumeSnapshot { .. } =
            synchronize(&mut edge_a, &mut [&mut origin_a]).await?
        else {
            return Err("expected FRESUME SNAPSHOT".into());
        };
        let FederationFrame::SnapshotBegin {
            identity,
            entry_count,
            ..
        } = edge_a.next_frame().await?
        else {
            return Err("expected FSNAPSHOT BEGIN".into());
        };
        assert_eq!(identity.projection_generation, 2);
        assert_eq!(identity.recovery_epoch, RecoveryEpoch::from_bytes([34; 16]));
        let mut ids = Vec::new();
        let mut keys = Vec::new();
        for index in 0..entry_count {
            let (carrier, object) = edge_a.next_object().await?;
            let ObjectCarrier::SnapshotEntry {
                entry_index,
                snapshot_token,
                object_id,
                ..
            } = carrier
            else {
                return Err("expected a snapshot entry".into());
            };
            assert_eq!(u64::from(entry_index), index);
            assert_eq!(snapshot_token, identity.snapshot_token);
            assert_eq!(object_id, object.object_id());
            let mut budget = DecodeBudget::new(1 << 20, 4_096);
            let entry = SchemaObject::decode_exact(
                "FederationProjectionEntry",
                object.as_slice(),
                &mut budget,
            )?;
            let (_, key) = agenc_ircd_federation_wire::decode_projection_arm(&entry, &mut budget)?;
            keys.push(key);
            ids.push(object.object_id());
        }
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            keys, sorted,
            "entries are strictly ordered by (kind, primary)"
        );
        assert_eq!(
            agenc_ircd_federation_wire::snapshot_digest(
                &identity.recovery_epoch,
                2,
                identity.state_generation,
                &ids
            )?,
            identity.snapshot_digest
        );
        // Nora's session, the channel, her membership: three entries.
        assert_eq!(entry_count, 3);
        let FederationFrame::SnapshotEnd { cursor, .. } = edge_a.next_frame().await? else {
            return Err("expected FSNAPSHOT END".into());
        };
        assert_eq!(cursor, agenc_ircd_federation_wire::DeliveryCursor::Empty);
        edge_a
            .frame(FederationFrame::SnapshotReady {
                coordinator_server_id: COORDINATOR,
                identity,
            })
            .await?;
        let FederationFrame::SnapshotActive {
            identity: active, ..
        } = edge_a.next_frame().await?
        else {
            return Err("expected FSNAPSHOT ACTIVE".into());
        };
        assert_eq!(active, identity);
        // A re-sent READY is answered with the byte-identical ACTIVE.
        edge_a
            .frame(FederationFrame::SnapshotReady {
                coordinator_server_id: COORDINATOR,
                identity,
            })
            .await?;
        let FederationFrame::SnapshotActive {
            identity: again, ..
        } = edge_a.next_frame().await?
        else {
            return Err("expected the repeated FSNAPSHOT ACTIVE".into());
        };
        assert_eq!(again, identity);
        // Live events now arrive under generation 2 from sequence zero.
        let mut spoke = Vec::new();
        let expected_revision = *edge_b
            .channel_revisions
            .get(&channel)
            .ok_or("edge b never learned the channel revision")?;
        request(
            &mut edge_b,
            &mut origin_b,
            &FederatedOperation::Message {
                session_id: session_b,
                kind: agenc_ircd_domain::MessageKind::Privmsg,
                targets: vec![MessageTargetArg::Channel {
                    channel_id: channel,
                    expected_revision,
                }],
                tags: Vec::new(),
                body: "after the snapshot".to_owned(),
            },
        )
        .await?;
        let result = answer(&mut edge_b, &mut spoke).await?;
        assert_eq!(result.header.result_kind, FederationResultKind::Committed);
        let (header, event) = next_event(&mut edge_a).await?;
        assert_eq!(header.projection_generation, 2);
        assert_eq!(header.delivery_sequence, 0);
        let ProjectedEvent::MessageDelivered(record) = event else {
            return Err("expected message_delivered under the new generation".into());
        };
        assert_eq!(record.body, "after the snapshot");
        let _ = user_a;
        Ok(())
    })
    .await
}

fn directory_query(
    session_id: SessionId,
    kind: agenc_ircd_types::FederationDirectoryQueryKind,
    arm: SchemaObject,
    cursor: Option<[u8; 32]>,
) -> TestResult<FederatedOperation> {
    let cursor_bytes: &[u8] = cursor.as_ref().map_or(&[], |cursor| cursor);
    let query = SchemaObject::new(
        "DirectoryQuery",
        vec![
            agenc_ircd_federation_wire::WireValue::Unsigned(u64::from(kind.wire_value())),
            agenc_ircd_federation_wire::access::opaque(arm.encode_canonical()?.as_slice())?,
            agenc_ircd_federation_wire::access::opaque(cursor_bytes)?,
        ],
    )?;
    Ok(FederatedOperation::DirectoryQuery { session_id, query })
}

#[tokio::test]
async fn names_query_answers_one_reply_page_and_a_bad_cursor_expires() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([56; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 56);
        let mut origin = Origin::new(76);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let mut events = Vec::new();
        let (session_id, _, revision) =
            open_session(&mut edge, &mut origin, "pia", &mut events).await?;
        join_channel(&mut edge, &mut origin, session_id, revision, "#names").await?;
        let arm = SchemaObject::new(
            "directory.names",
            vec![agenc_ircd_federation_wire::WireValue::Vector(vec![
                agenc_ircd_federation_wire::SchemaObject::new(
                    "FederationChannelName",
                    vec![agenc_ircd_federation_wire::access::opaque(b"#names")?],
                )?,
            ])],
        )?;
        let operation = directory_query(
            session_id,
            agenc_ircd_types::FederationDirectoryQueryKind::Names,
            arm,
            None,
        )?;
        request(&mut edge, &mut origin, &operation).await?;
        origin.sequence += 1;
        let page = answer(&mut edge, &mut events).await?;
        assert_eq!(page.header.result_kind, FederationResultKind::ReplyPage);
        let ResultArm::ReplyPage {
            page_sequence,
            next_cursor,
            ..
        } = page.arm
        else {
            return Err("expected reply_page".into());
        };
        assert_eq!(page_sequence, 0);
        assert!(next_cursor.is_none(), "one page holds the NAMES reply");
        let mut budget = DecodeBudget::new(1 << 20, 4_096);
        let result = SchemaObject::decode_exact("FederationResult", &page.bytes, &mut budget)?;
        let replies = agenc_ircd_federation_wire::access::vector(&result, "replies")?;
        let commands: Vec<String> = replies
            .iter()
            .map(crate::federation::codec::results::reply_parts_of)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|parts| parts.command)
            .collect();
        assert_eq!(commands, vec!["353".to_owned(), "366".to_owned()]);
        // A cursor the coordinator never issued expires the query.
        let arm = SchemaObject::new(
            "directory.list",
            vec![agenc_ircd_federation_wire::WireValue::Vector(Vec::new())],
        )?;
        let operation = directory_query(
            session_id,
            agenc_ircd_types::FederationDirectoryQueryKind::List,
            arm,
            Some([9; 32]),
        )?;
        request(&mut edge, &mut origin, &operation).await?;
        let expired = answer(&mut edge, &mut events).await?;
        let ResultArm::Failed { code, .. } = expired.arm else {
            return Err("expected failed for an unknown cursor".into());
        };
        assert_eq!(code, "QUERY_EXPIRED");
        Ok(())
    })
    .await
}
