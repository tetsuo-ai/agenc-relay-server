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
use agenc_ircd_storage::federation_records::{
    FederationPeerRecord, PEER_RECORD_KIND, PeerPhase, peer_key,
};
use agenc_ircd_storage::{InitialStorageRecord, PersistentRecordValue, TableId};
use agenc_ircd_types::{
    ConnectionId, FederationResultKind, FederationRole, NetworkId, ORIGIN_DISCONNECT_GRACE_SECONDS,
    OriginId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation, SessionId, UserId,
};
use tokio::sync::mpsc;

use super::*;
use agenc_ircd_admin::StatsSelector;

use crate::cancel::CancellationToken;
use crate::federation::codec::events::projected_event_of;
use crate::federation::codec::operations::{FederatedOperation, JoinTarget, MessageTargetArg};
use crate::federation::codec::results::ResultArm;
use crate::federation::link::{
    LinkQueue, ParsedLine, carrier_of, link_queue, parse_frame, parse_line,
};
use crate::state_core::admin::AdminCorePort;
use crate::state_core::inbox::{LifecyclePhase, connection_close_channel, lifecycle_channel};
use crate::state_core::{AdminCoreFailure, StateCoreExit};
use crate::test_support::StateCoreFixture;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[path = "join_results.rs"]
mod join_results;

#[path = "away_results.rs"]
mod away_results;

#[path = "account_shutdown.rs"]
mod account_shutdown;

#[path = "retained_resume.rs"]
mod retained_resume;

#[path = "ordinary_acks.rs"]
mod ordinary_acks;

#[path = "startup_cross_profile.rs"]
mod startup_cross_profile;

#[path = "query_receipt.rs"]
mod query_receipt;

const NETWORK: NetworkId = NetworkId::from_bytes([31; 32]);
const COORDINATOR: ServerId = ServerId::from_bytes([32; 16]);
const COORDINATOR_NAME: &str = "server.example";

fn entropy_script() -> Vec<u8> {
    // A xorshift stream: one megabyte with no repeating sixteen-byte window
    // in practice, so request and origin identifiers never collide.
    let mut state: u32 = 0x2545_f491;
    (0..1_048_576)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            u8::try_from(state & 0xff).unwrap_or(0)
        })
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
    buffered_events: std::collections::VecDeque<FederationFrame>,
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
            buffered_events: std::collections::VecDeque::new(),
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

    async fn companion(&self, frame: CompanionFrame) -> TestResult {
        self.send(LinkEvent::Companion(frame)).await
    }

    /// The next line, base or companion.
    async fn next_parsed(&mut self) -> TestResult<ParsedLine> {
        let line = tokio::time::timeout(std::time::Duration::from_secs(20), self.queue.recv())
            .await
            .map_err(|_| "no line from the coordinator")?
            .ok_or("coordinator closed the link")?;
        let text = line.as_str().trim_end_matches("\r\n").to_owned();
        Ok(parse_line(&text, COORDINATOR_NAME).map_err(|error| format!("{error:?}: {text}"))?)
    }

    /// The next companion frame, skipping base lines.
    async fn next_companion(&mut self) -> TestResult<CompanionFrame> {
        loop {
            if let ParsedLine::Companion(frame) = self.next_parsed().await? {
                return Ok(frame);
            }
        }
    }

    /// Splits and locally reassembles an object exactly as the link would,
    /// then hands the coordinator the assembled object.
    async fn object(
        &mut self,
        encoded: &[u8],
        frame: impl Fn(agenc_ircd_federation_wire::FederationFragment) -> FederationFrame,
    ) -> TestResult {
        let (carrier, object) = self.assemble(encoded, frame)?;
        self.send(LinkEvent::Object { carrier, object }).await
    }

    /// Splits and locally reassembles an object exactly as the link would,
    /// returning what the coordinator would receive.
    fn assemble(
        &mut self,
        encoded: &[u8],
        frame: impl Fn(agenc_ircd_federation_wire::FederationFragment) -> FederationFrame,
    ) -> TestResult<(ObjectCarrier, AssembledObject)> {
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
        match (assembled, carrier) {
            (Some(object), Some(carrier)) => Ok((carrier, object)),
            _ => Err("scripted object did not assemble".into()),
        }
    }

    async fn close(&self) -> TestResult {
        self.send(LinkEvent::Closed(LinkCloseReason::PeerClosed))
            .await
    }

    async fn next_frame(&mut self) -> TestResult<FederationFrame> {
        if let Some(frame) = self.buffered_events.pop_front() {
            return Ok(frame);
        }
        self.next_wire_frame().await
    }

    async fn next_wire_frame(&mut self) -> TestResult<FederationFrame> {
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

async fn declare(edge: &mut Edge, origin: &mut Origin, update: bool) -> TestResult<bool> {
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
    let mut ready = false;
    loop {
        match edge.next_wire_frame().await? {
            FederationFrame::OriginReady {
                edge_server_id,
                server_incarnation,
            } if edge_server_id == edge.server_id && server_incarnation == edge.incarnation => {
                ready = true
            }
            FederationFrame::OriginAck {
                origin_id,
                generation,
                object_id: acked,
                ..
            } if origin_id == origin.id && generation == origin.generation => {
                if acked != Some(object_id) {
                    return Err("origin ack named another object".into());
                }
                break;
            }
            frame @ FederationFrame::Event { .. } => {
                if edge.buffered_events.len() >= 4096 {
                    return Err("scripted replay ceiling".into());
                }
                edge.buffered_events.push_back(frame);
            }
            other => return Err(format!("expected origin ack, got {:?}", other.kind()).into()),
        }
    }
    origin.object_id = *object_id.as_bytes();
    Ok(ready)
}

/// Replays the origins and resumes from the edge's last acknowledged
/// cursor, returning the coordinator's FRESUME reply.
async fn synchronize(edge: &mut Edge, origins: &mut [&mut Origin]) -> TestResult<FederationFrame> {
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
    let answer = edge.next_wire_frame().await?;
    if matches!(answer, FederationFrame::ResumeOk { .. }) {
        edge.frame(FederationFrame::OriginReset {
            coordinator_server_id: COORDINATOR,
            server_incarnation: edge.incarnation,
        })
        .await?;
        let mut ready = false;
        for origin in origins.iter_mut() {
            ready |= declare(edge, origin, origin.generation > 0).await?;
        }
        while !ready {
            let frame = edge.next_wire_frame().await?;
            if matches!(frame, FederationFrame::Event { .. }) {
                if edge.buffered_events.len() >= 4096 {
                    return Err("scripted replay ceiling".into());
                }
                edge.buffered_events.push_back(frame);
                continue;
            }
            if !matches!(frame, FederationFrame::OriginReady { edge_server_id, server_incarnation }
                if edge_server_id == edge.server_id && server_incarnation == edge.incarnation)
            {
                return Err(format!("expected coordinator READY, got {:?}", frame.kind()).into());
            }
            ready = true;
        }
    }
    Ok(answer)
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

/// Like `run_coordinator`, with the private admin port installed so the
/// driver can issue `PEER QUARANTINE` and read `STATS FEDERATION`.
async fn run_coordinator_with_admin<Driver, Output>(
    edges: &[PeerIdentity],
    driver: impl FnOnce(mpsc::Sender<FederationInbound>, AdminCorePort) -> Driver,
) -> TestResult<Output>
where
    Driver: Future<Output = TestResult<Output>>,
{
    let mut fixture =
        StateCoreFixture::with_federation_coordinator(entropy_script(), edges.to_vec())?;
    let port = fixture.install_admin_port()?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (federation, federation_receiver) = mpsc::channel(64);
    parts.state.install_federation_inbox(federation_receiver)?;
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let token = CancellationToken::root();
    let driven = async move {
        let output = driver(federation, port).await;
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

#[tokio::test]
async fn peer_quarantine_closes_the_link_and_stats_report_it() -> TestResult {
    let peer = ServerId::from_bytes([49; 16]);
    let identity = peer_identity(peer, "edge.example");
    run_coordinator_with_admin(&[identity], |inbox, port| async move {
        let token = CancellationToken::root();
        let mut edge = Edge::new(inbox.clone(), 49);
        let mut origin = Origin::new(69);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let before = port
            .snapshot(&token)
            .await
            .map_err(|failure| format!("{failure:?}"))?;
        assert_eq!(
            before.values(StatsSelector::Federation),
            &[1, 1, 0, 0, 0, 0, 0]
        );
        port.peer_quarantine(peer, &token)
            .await
            .map_err(|failure| format!("{failure:?}"))?;
        edge.expect_closed().await?;
        let after = port
            .snapshot(&token)
            .await
            .map_err(|failure| format!("{failure:?}"))?;
        assert_eq!(
            after.values(StatsSelector::Federation),
            &[1, 0, 1, 0, 0, 0, 0]
        );
        // The fence holds: a fresh link is closed at once and the second
        // quarantine names no valid target.
        let mut again = Edge::new(inbox, 49);
        again.establish().await?;
        again.expect_closed().await?;
        assert_eq!(
            port.peer_quarantine(peer, &token).await,
            Err(AdminCoreFailure::InvalidTarget)
        );
        assert_eq!(
            port.peer_quarantine(ServerId::from_bytes([50; 16]), &token)
                .await,
            Err(AdminCoreFailure::InvalidTarget)
        );
        Ok(())
    })
    .await
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

#[tokio::test]
async fn resync_del_hides_a_session_registered_before_origin_update() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([40; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 40);
        let mut origin = Origin::new(60);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        request(&mut edge, &mut origin, &session_open(60, "unbound")).await?;
        let mut events = Vec::new();
        let accepted = answer(&mut edge, &mut events).await?;
        let ResultArm::SessionRegistered(registered) = accepted.arm else {
            return Err("registration refused".into());
        };
        let completion = accepted.header.completion_event_id.ok_or("completion")?;
        while !events
            .iter()
            .any(|(header, _)| header.event_id == completion)
        {
            events.push(next_event(&mut edge).await?);
        }
        edge.frame(FederationFrame::OriginDel {
            coordinator_server_id: COORDINATOR,
            server_incarnation: edge.incarnation,
            origin_id: origin.id,
            generation: 0,
            next_operation_sequence: 1,
        })
        .await?;
        assert!(matches!(
            edge.next_frame().await?,
            FederationFrame::OriginAck {
                object_id: None,
                ..
            }
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let (_, event) = next_event(&mut edge).await?;
                if let ProjectedEvent::SessionHidden { source, .. } = event
                    && source.user_id == registered.user_id
                {
                    return Ok::<(), Box<dyn Error>>(());
                }
            }
        })
        .await
        .map_err(|_| "DEL left the unbound registered session visible")??;
        Ok(())
    })
    .await
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
async fn resync_coordinator_sends_ready_after_the_origin_reset_commits() -> TestResult {
    let peer = ServerId::from_bytes([40; 16]);
    run_coordinator(&[peer_identity(peer, "edge.example")], |inbox| async move {
        let mut edge = Edge::new(inbox, 40);
        edge.establish().await?;
        edge.frame(FederationFrame::Resume {
            coordinator_server_id: COORDINATOR,
            projection_generation: edge.projection_generation,
            cursor: agenc_ircd_federation_wire::DeliveryCursor::Empty,
        })
        .await?;
        assert!(matches!(
            edge.next_frame().await?,
            FederationFrame::ResumeOk { .. }
        ));
        edge.frame(FederationFrame::OriginReset {
            coordinator_server_id: COORDINATOR,
            server_incarnation: edge.incarnation,
        })
        .await?;
        let answer =
            tokio::time::timeout(std::time::Duration::from_secs(2), edge.next_frame()).await;
        assert!(
            answer.is_ok(),
            "the coordinator must acknowledge origin readiness"
        );
        let frame = answer??;
        assert!(
            matches!(frame, FederationFrame::OriginReady { edge_server_id, server_incarnation }
            if edge_server_id == peer && server_incarnation == edge.incarnation)
        );
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

#[tokio::test]
async fn a_channel_message_with_an_older_expected_revision_still_commits() -> TestResult {
    let a = peer_identity(ServerId::from_bytes([46; 16]), "edge-a.example");
    let b = peer_identity(ServerId::from_bytes([47; 16]), "edge-b.example");
    run_coordinator(&[a, b], |inbox| async move {
        let mut edge_a = Edge::new(inbox.clone(), 46);
        let mut edge_b = Edge::new(inbox, 47);
        let mut origin_a = Origin::new(66);
        let mut origin_b = Origin::new(67);
        edge_a.establish().await?;
        edge_b.establish().await?;
        synchronize_ok(&mut edge_a, &mut [&mut origin_a]).await?;
        synchronize_ok(&mut edge_b, &mut [&mut origin_b]).await?;
        let mut events_a = Vec::new();
        let mut events_b = Vec::new();
        let (session_a, _, revision_a) =
            open_session(&mut edge_a, &mut origin_a, "gina", &mut events_a).await?;
        let (session_b, _, revision_b) =
            open_session(&mut edge_b, &mut origin_b, "hugo", &mut events_b).await?;
        events_a.clear();
        events_b.clear();
        let channel_id =
            join_channel(&mut edge_a, &mut origin_a, session_a, revision_a, "#lag").await?;
        join_channel(&mut edge_b, &mut origin_b, session_b, revision_b, "#lag").await?;
        let (_, joined) = next_event(&mut edge_a).await?;
        assert!(matches!(joined, ProjectedEvent::MemberJoined { .. }));
        // Gina changes the topic at the exact revision; the channel revision
        // moves on, and Hugo's edge has not applied that event yet.
        let before_topic = events_b_channel_revision(&mut edge_b, channel_id).await?;
        request(
            &mut edge_a,
            &mut origin_a,
            &FederatedOperation::Topic {
                session_id: session_a,
                channel_id,
                expected_channel_revision: before_topic,
                topic: "moved on".to_owned(),
            },
        )
        .await?;
        let topic = answer(&mut edge_a, &mut events_a).await?;
        assert_eq!(topic.header.result_kind, FederationResultKind::Committed);
        // Hugo speaks naming the revision his edge last applied, one behind
        // the coordinator. Authorization and the recipient set come from the
        // coordinator's current revision, so the message commits.
        request(
            &mut edge_b,
            &mut origin_b,
            &FederatedOperation::Message {
                session_id: session_b,
                kind: agenc_ircd_domain::MessageKind::Privmsg,
                targets: vec![MessageTargetArg::Channel {
                    channel_id,
                    expected_revision: before_topic,
                }],
                tags: Vec::new(),
                body: "still here".to_owned(),
            },
        )
        .await?;
        let mut spoke_events = Vec::new();
        let spoke = answer(&mut edge_b, &mut spoke_events).await?;
        if let ResultArm::Failed { code, .. } = &spoke.arm {
            return Err(format!("message with an older revision failed with {code}").into());
        }
        assert_eq!(spoke.header.result_kind, FederationResultKind::Committed);
        origin_b.sequence += 1;
        // A revision the coordinator has not reached is still refused.
        request(
            &mut edge_b,
            &mut origin_b,
            &FederatedOperation::Message {
                session_id: session_b,
                kind: agenc_ircd_domain::MessageKind::Privmsg,
                targets: vec![MessageTargetArg::Channel {
                    channel_id,
                    expected_revision: before_topic + 1_000,
                }],
                tags: Vec::new(),
                body: "from the future".to_owned(),
            },
        )
        .await?;
        let ahead = answer(&mut edge_b, &mut spoke_events).await?;
        let ResultArm::Failed { code, .. } = ahead.arm else {
            return Err("expected the message ahead of the coordinator to fail".into());
        };
        assert_eq!(code, "STALE_STATE");
        Ok(())
    })
    .await
}

/// The channel revision one edge last applied for `channel_id`, taken from
/// the channel_visible or state-changing events it received so far.
async fn events_b_channel_revision(
    edge: &mut Edge,
    channel_id: agenc_ircd_types::ChannelInstanceId,
) -> TestResult<u64> {
    edge.channel_revisions
        .get(&channel_id)
        .copied()
        .ok_or_else(|| "the edge learned no channel revision".into())
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

/// A deleted origin's session is hidden with the deletion. The edge's
/// session close normally precedes the DEL; when the link lost it or
/// storage refused it, the session would otherwise keep its nickname until
/// the next reset (finding CAP-18).
#[tokio::test]
async fn deleting_an_origin_hides_the_session_its_close_never_reached() -> TestResult {
    let a = peer_identity(ServerId::from_bytes([49; 16]), "edge-a.example");
    let b = peer_identity(ServerId::from_bytes([50; 16]), "edge-b.example");
    run_coordinator(&[a, b], |inbox| async move {
        let mut edge_a = Edge::new(inbox.clone(), 49);
        let mut edge_b = Edge::new(inbox, 50);
        let mut origin_a = Origin::new(69);
        let mut origin_b = Origin::new(70);
        edge_a.establish().await?;
        edge_b.establish().await?;
        synchronize_ok(&mut edge_a, &mut [&mut origin_a]).await?;
        synchronize_ok(&mut edge_b, &mut [&mut origin_b]).await?;
        let mut events_a = Vec::new();
        let mut events_b = Vec::new();
        open_session(&mut edge_a, &mut origin_a, "kira", &mut events_a).await?;
        open_session(&mut edge_b, &mut origin_b, "lior", &mut events_b).await?;
        drop(events_b);
        // Kira's connection ended and its close never arrived: only the DEL.
        edge_a
            .frame(FederationFrame::OriginDel {
                coordinator_server_id: COORDINATOR,
                server_incarnation: edge_a.incarnation,
                origin_id: origin_a.id,
                generation: origin_a.generation,
                next_operation_sequence: origin_a.sequence,
            })
            .await?;
        let ack = edge_a.next_frame().await?;
        assert!(
            matches!(
                ack,
                FederationFrame::OriginAck {
                    object_id: None,
                    ..
                }
            ),
            "{:?}",
            ack.kind()
        );
        // Kira's edge sees the session hidden as an expired origin.
        let (_, hidden) = next_event(&mut edge_a).await?;
        let ProjectedEvent::SessionHidden { source, kind, .. } = hidden else {
            return Err("edge a expected session_hidden".into());
        };
        assert_eq!(source.nickname.presentation(), "kira");
        assert_eq!(
            kind,
            agenc_ircd_domain::federation::SessionHideKind::OriginExpired
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

/// Builds a coordinator outside the actor loop for exact timer assertions.
fn standalone_coordinator(peer: ServerId) -> FederationCoordinator {
    FederationCoordinator::new(
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
    )
}

#[tokio::test]
async fn resync_outbox_overflow_retires_active_and_resuming_links() -> TestResult {
    for active in [false, true] {
        let peer = ServerId::from_bytes([50; 16]);
        let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
        let context = fixture.context_mut()?;
        let mut coordinator = standalone_coordinator(peer);
        coordinator.config.outbox_objects_per_edge = 0;
        let (handle, _queue) = link_queue(1 << 20);
        coordinator.inbound(
            context,
            established(1, peer, ServerIncarnation::from_bytes([51; 16]), handle),
        );
        coordinator.peers.get_mut(&peer).ok_or("peer")?.active = active;
        coordinator.deliver(
            context,
            vec![OutboundEvent {
                target: peer,
                projection_generation: 1,
                delivery_sequence: 0,
                event_id: agenc_ircd_types::EventId::from_bytes([61; 16]),
                object_id: FederationHash32::from_bytes([62; 32]),
                encoded: vec![1; 128],
            }],
        );
        let state = coordinator.peers.get(&peer).ok_or("peer")?;
        assert!(
            state.live.is_none(),
            "overflow must retire even a resuming link"
        );
        assert!(state.outbox.snapshot_required);
    }
    Ok(())
}

#[tokio::test]
async fn resync_overflow_stops_further_outbox_reservations() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![peer_identity(peer, "edge.example")],
    )?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    coordinator.config.outbox_objects_per_edge = 0;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(
        context,
        established(1, peer, ServerIncarnation::from_bytes([51; 16]), handle),
    );
    coordinator.deliver(
        context,
        vec![OutboundEvent {
            target: peer,
            projection_generation: 1,
            delivery_sequence: 0,
            event_id: agenc_ircd_types::EventId::from_bytes([61; 16]),
            object_id: FederationHash32::from_bytes([62; 32]),
            encoded: vec![1; 128],
        }],
    );
    let domain = agenc_ircd_domain::DomainState::new()?;
    let plan = domain.plan_account_service_checkpoint()?;
    let binding = crate::state_core::projector::RequestBinding {
        home: peer,
        correlation: agenc_ircd_federation_wire::RequestCorrelation {
            replay_key: agenc_ircd_federation_wire::ReplayKey {
                home_server_id: peer,
                server_incarnation: ServerIncarnation::from_bytes([51; 16]),
                origin_id: agenc_ircd_types::OriginId::from_bytes([60; 16]),
                origin_generation: 0,
                operation_sequence: 0,
            },
            request_id: RequestId::from_bytes([63; 16]),
        },
        completion_event_id: agenc_ircd_types::EventId::from_bytes([64; 16]),
    };
    let output = context.federation().ok_or("projector")?.project(
        &domain,
        &plan,
        &agenc_ircd_domain::federation::MutationContext::default(),
        Some(&binding),
        &mut agenc_ircd_testkit::ScriptedEntropy::new(entropy_script())?,
        1,
        &std::collections::BTreeMap::new(),
        &crate::state_core::durable::DurableIndex::new(),
    )?;
    assert!(
        output.is_none_or(|(_, pending)| pending.event_count() == 0),
        "a snapshot-required edge must not keep growing its durable outbox"
    );
    coordinator.continue_background(context);
    assert!(
        coordinator.pending.is_some(),
        "snapshot-required status needs a durable continuation"
    );
    Ok(())
}

#[tokio::test]
async fn resync_outbox_limit_fences_in_the_mutation_batch_before_append() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![peer_identity(peer, "edge.example")],
    )?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    coordinator.config.outbox_objects_per_edge = 0;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(
        context,
        established(1, peer, ServerIncarnation::from_bytes([51; 16]), handle),
    );
    let domain = agenc_ircd_domain::DomainState::new()?;
    let plan = domain.plan_account_service_checkpoint()?;
    let binding = crate::state_core::projector::RequestBinding {
        home: peer,
        correlation: agenc_ircd_federation_wire::RequestCorrelation {
            replay_key: agenc_ircd_federation_wire::ReplayKey {
                home_server_id: peer,
                server_incarnation: ServerIncarnation::from_bytes([51; 16]),
                origin_id: agenc_ircd_types::OriginId::from_bytes([60; 16]),
                origin_generation: 0,
                operation_sequence: 0,
            },
            request_id: RequestId::from_bytes([63; 16]),
        },
        completion_event_id: agenc_ircd_types::EventId::from_bytes([64; 16]),
    };
    let (writes, pending) = context
        .federation()
        .ok_or("projector")?
        .project(
            &domain,
            &plan,
            &agenc_ircd_domain::federation::MutationContext::default(),
            Some(&binding),
            &mut agenc_ircd_testkit::ScriptedEntropy::new(entropy_script())?,
            1,
            &std::collections::BTreeMap::new(),
            &crate::state_core::durable::DurableIndex::new(),
        )?
        .ok_or("projection")?;
    assert_eq!(
        pending.event_count(),
        0,
        "the overflowing event must never be appended"
    );
    assert!(writes.iter().any(|write| matches!(write,
        crate::state_core::durable::AccountServiceDurableWrite::Put { table: TableId::FederationPeer, plaintext, .. }
        if agenc_ircd_storage::PersistentRecordValue::decode(TableId::FederationPeer, plaintext)
            .ok().and_then(|value| FederationPeerRecord::decode(value.body()).ok())
            .is_some_and(|record| record.snapshot_required))), "the mutation must durably fence its target generation");
    let events = context
        .federation_mut()
        .ok_or("projector")?
        .committed(pending);
    coordinator.deliver(context, events);
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.live.is_none())
    );
    Ok(())
}

#[tokio::test]
async fn resync_startup_restores_the_outbox_ceiling() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let records = vec![
        restored_peer_record(
            peer,
            ServerIncarnation::from_bytes([51; 16]),
            PeerPhase::Ready,
        )?,
        resync_outbox_record(peer)?,
    ];
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    let mut coordinator = standalone_coordinator(peer);
    coordinator.config.outbox_objects_per_edge = 0;
    coordinator.startup(fixture.context_mut()?);
    while !coordinator.loaded() {
        let message = fixture.next_storage_read().await?;
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.outbox.snapshot_required),
        "restart must not erase retained outbox pressure"
    );
    Ok(())
}

#[tokio::test]
async fn resync_expired_request_fences_without_rewinding_the_origin() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let (inbox, _receiver) = mpsc::channel(1);
    let mut edge = Edge::new(inbox, 50);
    let origin = Origin::new(72);
    coordinator.inbound(
        context,
        established(50, peer, edge.incarnation, edge.handle.clone()),
    );
    coordinator.origins.reset(peer, edge.incarnation);
    let record = origin.record(&edge);
    let bytes = record.to_object()?.encode_canonical()?.as_slice().to_vec();
    let key = OriginKey {
        home_server_id: peer,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
    };
    coordinator
        .origins
        .add(agenc_ircd_domain::federation::OriginDeclaration {
            origin: key,
            generation: 0,
            previous_object_id: [0; 32],
            binding: agenc_ircd_domain::federation::OriginBinding {
                connection_id: record.connection_id,
                connection_nonce: record.connection_nonce,
            },
            principal: agenc_ircd_domain::federation::OriginPrincipal::UNREGISTERED,
            object_id: *federation_object_id(&bytes).as_bytes(),
        })?;
    coordinator.origin_objects.insert(key, bytes);
    coordinator.origins.ready(peer, edge.incarnation)?;
    for sequence in 0..3 {
        coordinator.origins.commit_request(
            OperationKey {
                origin: key,
                generation: 0,
                sequence,
            },
            RequestId::from_bytes([80 + u8::try_from(sequence)?; 16]),
        )?;
    }
    let (descriptor, bytes) = encoded_request(&edge, &origin, 73)?;
    inbound_object(&mut coordinator, context, &mut edge, &bytes, |fragment| {
        FederationFrame::Request {
            descriptor,
            fragment,
        }
    })?;
    let entry = coordinator.origins.origin(&key).ok_or("origin")?;
    assert_eq!(
        entry.status,
        agenc_ircd_domain::federation::OriginStatus::Fenced
    );
    assert_eq!(entry.next_sequence, 3);
    assert_eq!(
        context.pending_len(),
        1,
        "the fence must be durable before its answer"
    );
    Ok(())
}

#[tokio::test]
async fn resync_rejected_batch_drains_requests_waiting_behind_crypto() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let refused_peer = ServerId::from_bytes([52; 16]);
    let refused_incarnation = ServerIncarnation::from_bytes([53; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator_pair(peer, refused_peer);
    let (refused_handle, _refused_queue) = link_queue(1 << 20);
    coordinator.inbound(
        context,
        established(1, refused_peer, refused_incarnation, refused_handle),
    );
    let (inbox, _receiver) = mpsc::channel(1);
    let mut edge = Edge::new(inbox, 50);
    let origin = Origin::new(72);
    coordinator.inbound(
        context,
        established(50, peer, edge.incarnation, edge.handle.clone()),
    );
    coordinator.origins.reset(peer, edge.incarnation);
    let record = origin.record(&edge);
    let bytes = record.to_object()?.encode_canonical()?.as_slice().to_vec();
    let key = OriginKey {
        home_server_id: peer,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
    };
    coordinator
        .origins
        .add(agenc_ircd_domain::federation::OriginDeclaration {
            origin: key,
            generation: 0,
            previous_object_id: [0; 32],
            binding: agenc_ircd_domain::federation::OriginBinding {
                connection_id: record.connection_id,
                connection_nonce: record.connection_nonce,
            },
            principal: agenc_ircd_domain::federation::OriginPrincipal::UNREGISTERED,
            object_id: *federation_object_id(&bytes).as_bytes(),
        })?;
    coordinator.origin_objects.insert(key, bytes);
    coordinator.origins.ready(peer, edge.incarnation)?;
    let link = edge.link;
    enqueue(&mut coordinator, &mut edge, &origin, link, 73)?;
    // The owner has settled the first request's rejected batch. Its protocol
    // callback must now resume the different origin still waiting in RAM.
    coordinator.pending = Some(staged_request(refused_peer, refused_incarnation));
    coordinator.batch_rejected(context);
    assert_eq!(
        context.pending_len(),
        1,
        "the waiting request must be staged"
    );
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.queued.is_empty())
    );
    assert!(
        matches!(coordinator.pending, Some(PendingCommit::Request { request_id, .. })
        if request_id == RequestId::from_bytes([73; 16]))
    );
    Ok(())
}

#[tokio::test]
async fn resync_rejected_cleanup_keeps_its_session_until_commit() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let user = host_session(context, peer, "retained")?;
    grace::queue_hosted_cleanup(&mut coordinator, context, peer);
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::Cleanup { .. })
    ));
    coordinator.batch_rejected(context);
    let state = coordinator.peers.get(&peer).ok_or("peer")?;
    assert!(
        state.cleanup.contains(&user),
        "storage refusal must not forget this hide"
    );
    assert!(context.domain().session(user).is_some());
    Ok(())
}

async fn replay_failure_retires_link(fail_read: bool) -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![peer_identity(peer, "edge.example")],
    )?;
    let mut coordinator = standalone_coordinator(peer);
    let (handle, _queue) = link_queue(1 << 20);
    let context = fixture.context_mut()?;
    coordinator.inbound(
        context,
        established(1, peer, ServerIncarnation::from_bytes([51; 16]), handle),
    );
    context.federation_mut().ok_or("projector")?.set_edge(
        peer,
        crate::state_core::projector::EdgeDelivery {
            projection_generation: 0,
            next_delivery_sequence: 1,
        },
    );
    snapshot::start_resend(&mut coordinator, context, peer, 0);
    let mut completion = loop {
        let message = fixture.next_storage_read().await?;
        if snapshot::owns_read(&coordinator, message.read_id) {
            break message;
        }
    };
    if fail_read {
        completion.result = Err(agenc_ircd_storage::StorageError::QueueFull);
    } else {
        assert!(
            completion
                .result
                .as_ref()
                .is_ok_and(|page| page.records.is_empty())
        );
    }
    coordinator.storage_read_completed(fixture.context_mut()?, completion);
    let state = coordinator.peers.get(&peer).ok_or("peer")?;
    assert!(
        state.live.is_none(),
        "failed or missing replay must retire the link"
    );
    assert!(
        !state.active,
        "a missing sequence must never activate delivery"
    );
    Ok(())
}

#[tokio::test]
async fn resync_failed_outbox_read_retires_the_link() -> TestResult {
    replay_failure_retires_link(true).await
}

#[tokio::test]
async fn resync_failed_startup_read_cannot_admit_a_partial_coordinator() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut coordinator = standalone_coordinator(peer);
    coordinator.startup(fixture.context_mut()?);
    let mut completion = loop {
        let message = fixture.next_storage_read().await?;
        if coordinator.loader.owns(message.read_id) {
            break message;
        }
    };
    completion.result = Err(agenc_ircd_storage::StorageError::QueueFull);
    coordinator.storage_read_completed(fixture.context_mut()?, completion);
    assert!(
        !coordinator.loaded(),
        "failed reads must not declare reconstruction complete"
    );
    for _ in 0..16 {
        if coordinator.loaded() {
            return Ok(());
        }
        let message = fixture.next_storage_read().await?;
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    Err("startup did not retry the refused page".into())
}

#[tokio::test]
async fn resync_link_admission_waits_for_complete_reconstruction() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut coordinator = standalone_coordinator(peer);
    coordinator.startup(fixture.context_mut()?);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(
        fixture.context_mut()?,
        established(1, peer, ServerIncarnation::from_bytes([51; 16]), handle),
    );
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.live.is_none()),
        "an incomplete origin table must not admit link traffic"
    );
    while !coordinator.loaded() {
        let message = fixture.next_storage_read().await?;
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.live.is_some())
    );
    Ok(())
}

#[tokio::test]
async fn resync_invalid_outbox_row_fences_coordinator_startup() -> TestResult {
    use agenc_ircd_storage::federation_records::{
        OUTBOX_EVENT_KIND, OutboxEventRecord, outbox_key,
    };
    let peer = ServerId::from_bytes([50; 16]);
    let body = OutboxEventRecord {
        event_id: [61; 16],
        event_object_id: [62; 32],
        event_object: vec![1, 2, 3],
        coordinator_state_generation: 1,
        acknowledged: false,
        completion_replay_key: None,
    }
    .encode()?;
    let value = PersistentRecordValue::new(
        TableId::EdgeOutbox,
        OUTBOX_EVENT_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?
    .encode()?;
    let record = InitialStorageRecord::new(TableId::EdgeOutbox, outbox_key(peer, 0, 0)?, 1, value)?;
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), vec![record])?;
    let mut coordinator = standalone_coordinator(peer);
    coordinator.startup(fixture.context_mut()?);
    for _ in 0..16 {
        if coordinator.loaded()
            || coordinator
                .peers
                .get(&peer)
                .is_some_and(|state| state.quarantined)
        {
            break;
        }
        let message = fixture.next_storage_read().await?;
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    assert!(
        !coordinator.loaded(),
        "invalid outbox bytes were silently skipped"
    );
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.quarantined)
    );
    Ok(())
}

#[tokio::test]
async fn resync_missing_outbox_sequence_never_counts_as_acknowledged() -> TestResult {
    replay_failure_retires_link(false).await
}

fn resync_outbox_record(peer: ServerId) -> TestResult<InitialStorageRecord> {
    use agenc_ircd_storage::federation_records::{
        OUTBOX_EVENT_KIND, OutboxEventRecord, outbox_key,
    };
    let event = ProjectedEvent::NetworkNotice {
        code: "REPLAY".to_owned(),
        text: "committed while disconnected".to_owned(),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: peer,
        projection_generation: 0,
        coordinator_state_generation: 1,
        delivery_sequence: 0,
        event_id: agenc_ircd_types::EventId::from_bytes([61; 16]),
        event_kind: event.kind(),
        correlation: None,
        cross_profile: None,
    };
    let arm = crate::federation::codec::events::event_arm_object(&event)
        .map_err(|error| format!("{error:?}"))?;
    let bytes = header.build(&arm)?.encode_canonical()?.as_slice().to_vec();
    let body = OutboxEventRecord {
        event_id: *header.event_id.as_bytes(),
        event_object_id: *federation_object_id(&bytes).as_bytes(),
        event_object: bytes,
        coordinator_state_generation: 1,
        acknowledged: false,
        completion_replay_key: None,
    }
    .encode()?;
    let value = PersistentRecordValue::new(
        TableId::EdgeOutbox,
        OUTBOX_EVENT_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?
    .encode()?;
    Ok(InitialStorageRecord::new(
        TableId::EdgeOutbox,
        outbox_key(peer, 0, 0)?,
        1,
        value,
    )?)
}

/// The account service keeps its per-request results in the same table and
/// under the same record kind as coordinator results, keyed by the client's
/// 16-byte request id. The reload must leave those rows to their owner
/// instead of judging them as invalid coordinator results, which quarantined
/// every peer at any restart after the first account request (CAP-41).
#[tokio::test]
async fn resync_reload_leaves_account_service_results_to_their_owner() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let records = vec![
        restored_peer_record(peer, incarnation, PeerPhase::Ready)?,
        account_service_result_record()?,
    ];
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    let mut coordinator = standalone_coordinator(peer);
    coordinator.startup(fixture.context_mut()?);
    for _ in 0..64 {
        if coordinator.loaded() {
            break;
        }
        let Ok(Ok(message)) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.next_storage_read(),
        )
        .await
        else {
            break;
        };
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    assert!(
        coordinator.loaded(),
        "the reload must complete past a foreign row"
    );
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| !state.quarantined),
        "a foreign row must not quarantine the peers"
    );
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(
        fixture.context_mut()?,
        established(1, peer, incarnation, handle),
    );
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.live.is_some()),
        "the restored peer must link again"
    );
    Ok(())
}

/// Bytes shaped like the account service's request result: the coordinator's
/// record kind over a body that is not a coordinator result, under the
/// 16-byte client request id.
fn account_service_result_record() -> TestResult<InitialStorageRecord> {
    let body = agenc_ircd_storage::ProtocolRecordBody::new(
        TableId::RequestResult,
        agenc_ircd_storage::federation_records::COORDINATOR_RESULT_KIND,
        1,
        vec![7; 48],
    )?;
    let value = PersistentRecordValue::new(
        TableId::RequestResult,
        agenc_ircd_storage::federation_records::COORDINATOR_RESULT_KIND,
        1,
        0,
        None,
        Vec::new(),
        body.encode()?,
    )?
    .encode()?;
    Ok(InitialStorageRecord::new(
        TableId::RequestResult,
        agenc_ircd_storage::StoredKey::new(vec![41; 16])?,
        1,
        value,
    )?)
}

#[tokio::test]
async fn resync_restart_recovers_the_delivery_head_from_committed_outbox_rows() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let records = vec![
        restored_peer_record(peer, incarnation, PeerPhase::Ready)?,
        resync_outbox_record(peer)?,
    ];
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    fixture.context_mut()?.install_federation_projector(
        crate::state_core::projector::FederationProjector::new(NETWORK, COORDINATOR),
    );
    let mut coordinator = standalone_coordinator(peer);
    coordinator.startup(fixture.context_mut()?);
    while !coordinator.loaded() {
        let message = fixture.next_storage_read().await?;
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    let delivery = fixture
        .context_mut()?
        .federation()
        .and_then(|projector| projector.edge(peer))
        .ok_or("restored delivery")?;
    assert_eq!(
        delivery.next_delivery_sequence, 1,
        "never reuse a committed outbox key"
    );
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(
        fixture.context_mut()?,
        established(1, peer, incarnation, handle),
    );
    snapshot::start_resend(&mut coordinator, fixture.context_mut()?, peer, 0);
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.resend.is_some() && !state.active),
        "the missing peer-head checkpoint must not skip delivery"
    );
    Ok(())
}

#[tokio::test]
async fn resync_acknowledgement_does_not_advance_before_its_commit() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let records = vec![
        restored_peer_record(peer, incarnation, PeerPhase::Ready)?,
        resync_outbox_record(peer)?,
    ];
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    let state = coordinator.peers.get_mut(&peer).ok_or("peer")?;
    state.projection_generation = 0;
    let event_id = agenc_ircd_types::EventId::from_bytes([61; 16]);
    state.outbox.unacked.push_back((0, event_id, 128));
    state.outbox.unacked_bytes = 128;
    coordinator
        .acknowledge(context, peer, 0, event_id)
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(context.pending_len(), 1);
    let state = coordinator.peers.get(&peer).ok_or("peer")?;
    assert_eq!(
        state.outbox.cursor, None,
        "an admitted ACK is not committed coverage"
    );
    assert_eq!(state.outbox.unacked.len(), 1);
    coordinator.batch_rejected(context);
    let state = coordinator.peers.get(&peer).ok_or("peer")?;
    assert_eq!(state.outbox.cursor, None);
    assert_eq!(
        state.outbox.unacked.len(),
        1,
        "refusal retains the deletion obligation"
    );
    assert!(
        state.live.is_none(),
        "resume must reconcile refused ACK coverage"
    );
    Ok(())
}

#[tokio::test]
async fn resync_refused_request_retires_the_link_without_consuming_its_sequence() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    coordinator.pending = Some(staged_request(peer, incarnation));
    coordinator.batch_rejected(context);
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.live.is_none()),
        "the edge must retain and resend the exact refused request"
    );
    assert!(coordinator.retained.is_empty());
    assert_eq!(context.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn resync_callback_cannot_settle_a_request_staged_after_its_receipt() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let (inbox, _receiver) = mpsc::channel(1);
    let mut edge = Edge::new(inbox, 50);
    let origin = Origin::new(72);
    coordinator.inbound(
        context,
        established(50, peer, edge.incarnation, edge.handle.clone()),
    );
    coordinator.origins.reset(peer, edge.incarnation);
    let record = origin.record(&edge);
    let bytes = record.to_object()?.encode_canonical()?.as_slice().to_vec();
    let key = OriginKey {
        home_server_id: peer,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
    };
    coordinator
        .origins
        .add(agenc_ircd_domain::federation::OriginDeclaration {
            origin: key,
            generation: 0,
            previous_object_id: [0; 32],
            binding: agenc_ircd_domain::federation::OriginBinding {
                connection_id: record.connection_id,
                connection_nonce: record.connection_nonce,
            },
            principal: agenc_ircd_domain::federation::OriginPrincipal::UNREGISTERED,
            object_id: *federation_object_id(&bytes).as_bytes(),
        })?;
    coordinator.origin_objects.insert(key, bytes);
    coordinator.origins.ready(peer, edge.incarnation)?;
    let (descriptor, bytes) = encoded_request(&edge, &origin, 73)?;
    inbound_object(&mut coordinator, context, &mut edge, &bytes, |fragment| {
        FederationFrame::Request {
            descriptor,
            fragment,
        }
    })?;
    assert_eq!(context.pending_len(), 1);
    // An account callback can stage its outer federation checkpoint before
    // the router forwards the earlier account receipt to this callback.
    coordinator.batch_applied(context);
    assert!(
        matches!(coordinator.pending, Some(PendingCommit::Request { .. })),
        "the earlier receipt cannot consume newly staged request ownership"
    );
    assert_eq!(
        coordinator
            .origins
            .origin(&key)
            .ok_or("origin")?
            .next_sequence,
        0
    );
    assert!(coordinator.retained.is_empty());
    Ok(())
}

fn established(
    link: u64,
    peer: ServerId,
    incarnation: ServerIncarnation,
    handle: LinkHandle,
) -> FederationInbound {
    FederationInbound {
        link: LinkId::new(link),
        peer,
        event: LinkEvent::Established {
            session: LinkSession {
                link: LinkId::new(link),
                peer,
                peer_incarnation: incarnation,
                peer_recovery_epoch: RecoveryEpoch::from_bytes([0; 16]),
                transition: agenc_ircd_federation_wire::EpochTransition::Initial,
            },
            handle,
        },
        charge: None,
    }
}

fn reset_frame(link: u64, peer: ServerId, incarnation: ServerIncarnation) -> FederationInbound {
    FederationInbound {
        link: LinkId::new(link),
        peer,
        event: LinkEvent::Frame(FederationFrame::OriginReset {
            coordinator_server_id: COORDINATOR,
            server_incarnation: incarnation,
        }),
        charge: None,
    }
}

fn closed(link: u64, peer: ServerId) -> FederationInbound {
    FederationInbound {
        link: LinkId::new(link),
        peer,
        event: LinkEvent::Closed(LinkCloseReason::PeerClosed),
        charge: None,
    }
}

/// Opens one session hosted by `peer` in the live domain.
fn host_session(
    context: &mut crate::state_core::StateCoreContext,
    peer: ServerId,
    nickname: &str,
) -> TestResult<UserId> {
    let seed = crate::test_support::remote_session_seed(context, peer, nickname)?;
    let user_id = seed.user_id;
    let plan = context.domain().plan_session_opened(seed)?;
    crate::test_support::apply_live_plan(context, plan)?;
    Ok(user_id)
}

/// The exclusive end of a grace interval that starts now.
fn grace_deadline(
    context: &crate::state_core::StateCoreContext,
) -> TestResult<agenc_ircd_types::MonotonicTick> {
    Ok(context
        .now()
        .checked_add(ORIGIN_DISCONNECT_GRACE_SECONDS.saturating_mul(1_000))?)
}

/// Pops the grace timer of `peer` due exactly at `deadline`.
fn pop_grace_timer(
    context: &mut crate::state_core::StateCoreContext,
    peer: ServerId,
    deadline: agenc_ircd_types::MonotonicTick,
) -> TestResult<crate::state_core::timers::TimerEntry> {
    use crate::state_core::timers::{TimedId, TimerKind};
    let entry = context
        .timers_mut()
        .pop_due(deadline)
        .ok_or("no grace timer was scheduled")?;
    assert_eq!(entry.kind, TimerKind::FederationGrace);
    assert_eq!(entry.id, TimedId::Peer(peer));
    assert_eq!(entry.deadline, deadline);
    Ok(entry)
}

#[tokio::test]
async fn synchronous_grace_expiry_hides_every_hosted_session() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let (handle, _queue) = link_queue(1 << 20);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    // A session hosted by the edge exists in the live domain.
    let user_id = host_session(context, peer, "kate")?;
    coordinator.inbound(context, closed(1, peer));
    let deadline = grace_deadline(context)?;
    let entry = pop_grace_timer(context, peer, deadline)?;
    let handled = coordinator.timer_fired(context, entry);
    assert!(handled);
    assert_eq!(coordinator.counters().sessions_expired, 0);
    assert_eq!(
        context.pending_len(),
        1,
        "the authority fence is staged before cleanup"
    );
    assert!(
        context.domain().session(user_id).is_some(),
        "the session hides only after commit"
    );
    Ok(())
}

#[tokio::test]
async fn a_link_that_returns_before_its_grace_passes_is_not_fenced() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    let user_id = host_session(context, peer, "kate")?;
    // The link drops: a disconnect grace interval starts.
    coordinator.inbound(context, closed(1, peer));
    let deadline = grace_deadline(context)?;
    let entry = pop_grace_timer(context, peer, deadline)?;
    // The same incarnation reconnects before the grace passes. A link that is
    // back but resyncs slowly must not be fenced as if it were gone.
    let (handle_again, _queue_again) = link_queue(1 << 20);
    coordinator.inbound(context, established(2, peer, incarnation, handle_again));
    // The stale grace, fired now, finds no pending interval and fences nothing.
    let handled = coordinator.timer_fired(context, entry);
    assert!(handled);
    assert_eq!(
        context.pending_len(),
        0,
        "a reconnected edge must not stage an authority fence from its previous link's grace"
    );
    assert_eq!(coordinator.counters().sessions_expired, 0);
    assert!(
        context.domain().session(user_id).is_some(),
        "the hosted session survives the returned link"
    );
    Ok(())
}

#[tokio::test]
async fn a_closed_queue_retires_the_link_without_a_violation() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    // The link task is already gone when the coordinator first writes.
    let (handle, queue) = link_queue(1 << 20);
    drop(queue);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    coordinator.inbound(
        context,
        FederationInbound {
            link: LinkId::new(1),
            peer,
            event: LinkEvent::Frame(FederationFrame::Resume {
                coordinator_server_id: COORDINATOR,
                projection_generation: 1,
                cursor: agenc_ircd_federation_wire::DeliveryCursor::Empty,
            }),
            charge: None,
        },
    );
    assert_eq!(coordinator.counters().violations, 0);
    // The refused FRESUME OK retired the link at once: grace is running.
    let deadline = grace_deadline(context)?;
    let _entry = pop_grace_timer(context, peer, deadline)?;
    // The owner's own Closed event then finds nothing live.
    coordinator.inbound(context, closed(1, peer));
    assert_eq!(coordinator.counters().violations, 0);
    assert!(context.timers_mut().pop_due(deadline).is_none());
    Ok(())
}

#[tokio::test]
async fn a_closed_queue_under_a_snapshot_announcement_is_not_a_violation() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let (handle, queue) = link_queue(1 << 20);
    drop(queue);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    // A generation the coordinator does not retain forces the snapshot route.
    coordinator.inbound(
        context,
        FederationInbound {
            link: LinkId::new(1),
            peer,
            event: LinkEvent::Frame(FederationFrame::Resume {
                coordinator_server_id: COORDINATOR,
                projection_generation: 0,
                cursor: agenc_ircd_federation_wire::DeliveryCursor::Empty,
            }),
            charge: None,
        },
    );
    assert_eq!(coordinator.counters().violations, 0);
    assert_eq!(
        context.pending_len(),
        0,
        "no marker is staged for a dead link"
    );
    let deadline = grace_deadline(context)?;
    let _entry = pop_grace_timer(context, peer, deadline)?;
    Ok(())
}

#[tokio::test]
async fn a_rejected_snapshot_marker_retires_the_link_instead_of_waiting_for_expiry() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let (handle, mut queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    // A generation the coordinator does not retain forces the snapshot route;
    // the announcement and the empty cut leave before the marker row is
    // durable.
    coordinator.inbound(
        context,
        FederationInbound {
            link: LinkId::new(1),
            peer,
            event: LinkEvent::Frame(FederationFrame::Resume {
                coordinator_server_id: COORDINATOR,
                projection_generation: 0,
                cursor: agenc_ircd_federation_wire::DeliveryCursor::Empty,
            }),
            charge: None,
        },
    );
    assert_eq!(coordinator.counters().violations, 0);
    assert_eq!(context.pending_len(), 1, "the marker row is staged");
    let mut identity = None;
    for expected in ["FRESUME SNAPSHOT", "FSNAPSHOT BEGIN", "FSNAPSHOT END"] {
        let line = queue
            .recv()
            .await
            .ok_or("the announcement was not queued")?;
        let text = line.as_str().trim_end_matches("\r\n").to_owned();
        let frame =
            parse_frame(&text, COORDINATOR_NAME).map_err(|error| format!("{error:?}: {text}"))?;
        let announced = match frame {
            FederationFrame::ResumeSnapshot { .. } => "FRESUME SNAPSHOT",
            FederationFrame::SnapshotBegin {
                identity: begun, ..
            } => {
                identity = Some(begun);
                "FSNAPSHOT BEGIN"
            }
            FederationFrame::SnapshotEnd { .. } => "FSNAPSHOT END",
            _ => "another frame",
        };
        assert_eq!(announced, expected, "{text}");
    }
    let identity = identity.ok_or("FSNAPSHOT BEGIN carried no identity")?;
    // The edge answers READY while the marker batch is still in flight; the
    // frame waits in the backlog behind that batch.
    coordinator.inbound(
        context,
        FederationInbound {
            link: LinkId::new(1),
            peer,
            event: LinkEvent::Frame(FederationFrame::SnapshotReady {
                coordinator_server_id: COORDINATOR,
                identity,
            }),
            charge: None,
        },
    );
    // Storage refuses the marker batch, as it does under disk pressure. No
    // later event re-stages the marker, so the coordinator must retire the
    // link instead of leaving the edge in the snapshot phase for the whole
    // token lifetime, and the replayed READY finds no live link.
    coordinator.batch_rejected(context);
    assert_eq!(coordinator.counters().violations, 1);
    let state = coordinator.peers.get(&peer).ok_or("peer state missing")?;
    assert!(
        state.snapshot.is_none(),
        "the unfinished generation is dropped"
    );
    assert!(state.live.is_none(), "the link is retired");
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv())
        .await
        .map_err(|_| "the link writer received no close request")?;
    assert!(closed.is_none(), "the close request ends the queue");
    // Grace runs for the peer and the snapshot expiry no longer waits.
    let deadline = grace_deadline(context)?;
    let _entry = pop_grace_timer(context, peer, deadline)?;
    assert!(
        context
            .timers_mut()
            .pop_due(agenc_ircd_types::MonotonicTick::from_ticks(u64::MAX / 2))
            .is_none(),
        "the snapshot expiry timer is cancelled with its generation"
    );
    Ok(())
}

/// A request batch the coordinator staged for `peer` on link 1 at origin
/// sequence 3, as it waits for the storage receipt.
fn staged_request(peer: ServerId, incarnation: ServerIncarnation) -> PendingCommit {
    let origin_id = OriginId::from_bytes([77; 16]);
    let request_id = RequestId::from_bytes([78; 16]);
    PendingCommit::Request {
        query: None,
        staged_after: 0,
        peer,
        link: LinkId::new(1),
        key: OperationKey {
            origin: OriginKey {
                home_server_id: peer,
                server_incarnation: incarnation,
                origin_id,
            },
            generation: 1,
            sequence: 3,
        },
        request_id,
        request_object_id: FederationHash32::from_bytes([79; 32]),
        result: Vec::new(),
        descriptor: OperationDescriptor {
            addressed_server_id: COORDINATOR,
            server_incarnation: incarnation,
            origin_id,
            origin_generation: 1,
            operation_sequence: 3,
            request_id,
            object_id: FederationHash32::from_bytes([79; 32]),
        },
        header: RequestHeader {
            network_id: NETWORK,
            replay_key: ReplayKey {
                home_server_id: peer,
                server_incarnation: incarnation,
                origin_id,
                origin_generation: 1,
                operation_sequence: 3,
            },
            request_id,
            opcode: agenc_ircd_types::FederationOpcode::Message,
        },
        _charge: None,
    }
}

#[tokio::test]
async fn an_origin_acknowledgement_whose_batch_storage_refused_retires_the_link() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let (handle, mut queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    coordinator.inbound(context, reset_frame(1, peer, incarnation));
    coordinator.pending = Some(PendingCommit::OriginAck {
        peer,
        link: LinkId::new(1),
        frame: FederationFrame::OriginAck {
            edge_server_id: peer,
            server_incarnation: incarnation,
            origin_id: OriginId::from_bytes([77; 16]),
            generation: 1,
            object_id: None,
        },
        closed_carrier: None,
        _charge: None,
    });
    coordinator.batch_rejected(context);
    // The declaration was never acknowledged durably; the edge declares
    // again on its next link instead of waiting for an answer.
    assert_eq!(coordinator.counters().violations, 1);
    assert!(
        coordinator
            .peers
            .get(&peer)
            .is_some_and(|state| state.live.is_none())
    );
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv())
        .await
        .map_err(|_| "the link writer received no close request")?;
    assert!(closed.is_none(), "the close request ends the queue");
    Ok(())
}

/// Hands the coordinator one object as if the link had assembled it.
fn inbound_object(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    edge: &mut Edge,
    encoded: &[u8],
    frame: impl Fn(agenc_ircd_federation_wire::FederationFragment) -> FederationFrame,
) -> TestResult {
    let (carrier, object) = edge.assemble(encoded, frame)?;
    coordinator.inbound(
        context,
        FederationInbound {
            link: edge.link,
            peer: edge.server_id,
            event: LinkEvent::Object { carrier, object },
            charge: None,
        },
    );
    Ok(())
}

#[tokio::test]
async fn a_request_waits_while_another_router_has_a_batch_open() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let (unused_inbox, _unused_receiver) = mpsc::channel(1);
    let mut edge = Edge::new(unused_inbox, 50);
    let origin = Origin::new(70);
    coordinator.inbound(
        context,
        established(50, peer, edge.incarnation, edge.handle.clone()),
    );
    coordinator.origins.reset(peer, edge.incarnation);
    // The origin declaration stages its acknowledgement row; the
    // coordinator's own slot frees when that batch applies, but the plan
    // stays open in the state core, as another router's plan would.
    let encoded = origin.record(&edge).to_object()?.encode_canonical()?;
    let bytes = encoded.as_slice().to_vec();
    let descriptor = OriginDescriptor {
        coordinator_server_id: COORDINATOR,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
        generation: origin.generation,
        object_id: federation_object_id(&bytes),
    };
    inbound_object(&mut coordinator, context, &mut edge, &bytes, |fragment| {
        FederationFrame::OriginAdd {
            descriptor,
            fragment,
        }
    })?;
    coordinator.batch_applied(context);
    assert!(coordinator.pending.is_none());
    assert_eq!(
        context.pending_len(),
        1,
        "the acknowledgement row stays staged"
    );
    let acked = edge.next_frame().await?;
    assert!(matches!(acked, FederationFrame::OriginAck { .. }));
    coordinator.origins.ready(peer, edge.incarnation)?;
    let operation = session_open(70, "olga");
    let request_id = RequestId::from_bytes([71; 16]);
    let header = RequestHeader {
        network_id: NETWORK,
        replay_key: origin.replay_key(&edge),
        request_id,
        opcode: operation.opcode(),
    };
    let object = header.build(&operation.to_object()?)?;
    let bytes = object.encode_canonical()?.as_slice().to_vec();
    let descriptor = OperationDescriptor {
        addressed_server_id: COORDINATOR,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
        origin_generation: origin.generation,
        operation_sequence: origin.sequence,
        request_id,
        object_id: federation_object_id(&bytes),
    };
    inbound_object(&mut coordinator, context, &mut edge, &bytes, |fragment| {
        FederationFrame::Request {
            descriptor,
            fragment,
        }
    })?;
    // The request waits for the open batch instead of planning against a
    // state that is about to change and being refused as busy.
    let state = coordinator.peers.get(&peer).ok_or("peer state missing")?;
    assert_eq!(state.queued.len(), 1, "the request is queued");
    assert!(state.live.is_some(), "the link stays live");
    assert_eq!(coordinator.counters().violations, 0);
    let answered =
        tokio::time::timeout(std::time::Duration::from_millis(500), edge.next_frame()).await;
    assert!(
        answered.is_err(),
        "nothing is answered while the batch is open"
    );
    Ok(())
}

/// A coordinator with two configured edges and no running loop.
fn standalone_coordinator_pair(first: ServerId, second: ServerId) -> FederationCoordinator {
    FederationCoordinator::new(
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
        vec![
            peer_identity(first, "edge-a.example"),
            peer_identity(second, "edge-b.example"),
        ],
        std::sync::Arc::new(crate::test_support::TestChannelKeyVerifier),
        ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    )
}

/// An encoded session-open request from `origin` at its current sequence,
/// with the descriptor its link would carry.
fn encoded_request(
    edge: &Edge,
    origin: &Origin,
    seed: u8,
) -> TestResult<(OperationDescriptor, Vec<u8>)> {
    let operation = session_open(seed, "queued");
    let request_id = RequestId::from_bytes([seed; 16]);
    let header = RequestHeader {
        network_id: NETWORK,
        replay_key: origin.replay_key(edge),
        request_id,
        opcode: operation.opcode(),
    };
    let object = header.build(&operation.to_object()?)?;
    let bytes = object.encode_canonical()?.as_slice().to_vec();
    let descriptor = OperationDescriptor {
        addressed_server_id: COORDINATOR,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
        origin_generation: origin.generation,
        operation_sequence: origin.sequence,
        request_id,
        object_id: federation_object_id(&bytes),
    };
    Ok((descriptor, bytes))
}

/// Places one already-assembled request in `peer`'s queue on `link`.
fn enqueue(
    coordinator: &mut FederationCoordinator,
    edge: &mut Edge,
    origin: &Origin,
    link: LinkId,
    seed: u8,
) -> TestResult {
    let (descriptor, bytes) = encoded_request(edge, origin, seed)?;
    let (_, object) = edge.assemble(&bytes, |fragment| FederationFrame::Request {
        descriptor,
        fragment,
    })?;
    coordinator
        .peers
        .get_mut(&edge.server_id)
        .ok_or("peer state missing")?
        .queued
        .push_back(QueuedRequest {
            link,
            descriptor,
            object,
            charge: None,
        });
    Ok(())
}

#[tokio::test]
async fn a_request_queues_behind_its_peers_queued_requests_even_when_idle() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let (unused_inbox, _unused_receiver) = mpsc::channel(1);
    let mut edge = Edge::new(unused_inbox, 50);
    let origin = Origin::new(72);
    coordinator.inbound(
        context,
        established(50, peer, edge.incarnation, edge.handle.clone()),
    );
    synchronized_peer_fixture(&mut coordinator, peer, edge.incarnation)?;
    assert_eq!(
        context.pending_len(),
        0,
        "nothing is staged: the coordinator is idle"
    );
    // An earlier request of this link still waits in the queue.
    let link = edge.link;
    enqueue(&mut coordinator, &mut edge, &origin, link, 73)?;
    // The next one must wait behind it rather than execute first, or the
    // origin's operation sequence would arrive out of order.
    let (descriptor, bytes) = encoded_request(&edge, &origin, 74)?;
    inbound_object(&mut coordinator, context, &mut edge, &bytes, |fragment| {
        FederationFrame::Request {
            descriptor,
            fragment,
        }
    })?;
    let state = coordinator.peers.get(&peer).ok_or("peer state missing")?;
    assert_eq!(
        state.queued.len(),
        2,
        "the request queued behind the earlier one"
    );
    assert!(state.live.is_some(), "the link stays live");
    assert_eq!(coordinator.counters().violations, 0);
    Ok(())
}

#[tokio::test]
async fn queued_requests_drain_peer_by_peer_and_drop_a_dead_link() -> TestResult {
    let (a, b) = (
        ServerId::from_bytes([50; 16]),
        ServerId::from_bytes([60; 16]),
    );
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator_pair(a, b);
    let (unused_inbox, _unused_receiver) = mpsc::channel(1);
    let mut edge_a = Edge::new(unused_inbox.clone(), 50);
    let mut edge_b = Edge::new(unused_inbox, 60);
    let origin_a = Origin::new(75);
    let origin_b = Origin::new(76);
    for edge in [&edge_a, &edge_b] {
        coordinator.inbound(
            context,
            established(
                u64::from(edge.server_id.as_bytes()[0]),
                edge.server_id,
                edge.incarnation,
                edge.handle.clone(),
            ),
        );
        coordinator.inbound(
            context,
            reset_frame(
                u64::from(edge.server_id.as_bytes()[0]),
                edge.server_id,
                edge.incarnation,
            ),
        );
    }
    // Two requests wait for edge a, one for edge b, and one for edge b from
    // a link that is gone.
    let link = edge_a.link;
    enqueue(&mut coordinator, &mut edge_a, &origin_a, link, 77)?;
    let link = edge_a.link;
    enqueue(&mut coordinator, &mut edge_a, &origin_a, link, 78)?;
    enqueue(
        &mut coordinator,
        &mut edge_b,
        &origin_b,
        LinkId::new(999),
        79,
    )?;
    let link = edge_b.link;
    enqueue(&mut coordinator, &mut edge_b, &origin_b, link, 80)?;
    let first = request::next_queued(&mut coordinator).ok_or("no first request")?;
    assert_eq!(first.0, a, "the first turn goes to the first peer");
    coordinator.drain_cursor = Some(first.0);
    let second = request::next_queued(&mut coordinator).ok_or("no second request")?;
    assert_eq!(second.0, b, "the next turn goes to the other peer");
    assert_eq!(
        second.1.descriptor.request_id,
        RequestId::from_bytes([80; 16]),
        "the entry from the dead link was dropped first"
    );
    coordinator.drain_cursor = Some(second.0);
    let third = request::next_queued(&mut coordinator).ok_or("no third request")?;
    assert_eq!(third.0, a, "the turn comes back to the first peer");
    assert!(
        request::next_queued(&mut coordinator).is_none(),
        "every queue is empty"
    );
    Ok(())
}

#[tokio::test]
async fn a_new_incarnation_hides_the_sessions_of_the_previous_one() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let first = ServerIncarnation::from_bytes([51; 16]);
    let second = ServerIncarnation::from_bytes([52; 16]);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, first, handle));
    synchronized_peer_fixture(&mut coordinator, peer, first)?;
    let user_id = host_session(context, peer, "kate")?;
    coordinator.inbound(context, closed(1, peer));
    let deadline = grace_deadline(context)?;
    // The edge returns restarted, well inside the grace interval.
    let (again, _queue_again) = link_queue(1 << 20);
    coordinator.inbound(context, established(2, peer, second, again));
    assert_eq!(coordinator.counters().sessions_expired, 0);
    coordinator.inbound(context, reset_frame(2, peer, second));
    assert_eq!(coordinator.counters().sessions_expired, 0);
    assert_eq!(
        context.pending_len(),
        1,
        "the authority fence is staged before cleanup"
    );
    assert!(context.domain().session(user_id).is_some());
    assert!(
        context.timers_mut().pop_due(deadline).is_none(),
        "the returning link cancelled the grace timer"
    );
    Ok(())
}

/// The peer row a previous process left behind for `peer`.
fn restored_peer_record(
    peer: ServerId,
    incarnation: ServerIncarnation,
    phase: PeerPhase,
) -> TestResult<InitialStorageRecord> {
    let body = FederationPeerRecord {
        fenced_incarnations: Vec::new(),
        server_incarnation: *incarnation.as_bytes(),
        recovery_epoch: [0; 16],
        accepted_epochs: Vec::new(),
        phase,
        projection_generation: 0,
        next_delivery_sequence: 0,
        cursor: None,
        active_entry_count: 0,
        active_entry_bytes: 0,
        pending_generation: None,
        snapshot_required: false,
        cleanup_cursor: None,
        quarantined: false,
        client_resync_epoch: 0,
    }
    .encode()?;
    let value = PersistentRecordValue::new(
        TableId::FederationPeer,
        PEER_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?
    .encode()?;
    Ok(InitialStorageRecord::new(
        TableId::FederationPeer,
        peer_key(peer)?,
        1,
        value,
    )?)
}

/// Boots a coordinator over storage holding one peer row from a previous
/// process while a session that peer hosted is still live.
async fn boot_restored(
    peer: ServerId,
    phase: PeerPhase,
) -> TestResult<(StateCoreFixture, FederationCoordinator)> {
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let record = restored_peer_record(peer, incarnation, phase)?;
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), vec![record])?;
    let mut coordinator = standalone_coordinator(peer);
    host_session(fixture.context_mut()?, peer, "kate")?;
    coordinator.startup(fixture.context_mut()?);
    while !coordinator.loaded() {
        let message = fixture.next_storage_read().await?;
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    Ok((fixture, coordinator))
}

#[tokio::test]
async fn a_restart_starts_a_fresh_grace_interval_for_a_restored_peer() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let (mut fixture, mut coordinator) = boot_restored(peer, PeerPhase::Ready).await?;
    let context = fixture.context_mut()?;
    assert_eq!(coordinator.counters().sessions_expired, 0);
    let deadline = grace_deadline(context)?;
    let entry = pop_grace_timer(context, peer, deadline)?;
    assert!(coordinator.timer_fired(context, entry));
    assert_eq!(coordinator.counters().sessions_expired, 0);
    assert_eq!(
        context.pending_len(),
        1,
        "the authority fence is staged before cleanup"
    );
    Ok(())
}

#[tokio::test]
async fn a_restart_resumes_an_interrupted_expiry_cleanup() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let (mut fixture, mut coordinator) = boot_restored(peer, PeerPhase::Expired).await?;
    let context = fixture.context_mut()?;
    assert_eq!(coordinator.counters().sessions_expired, 1);
    assert_eq!(context.pending_len(), 1, "the hide plan is staged");
    let deadline = grace_deadline(context)?;
    assert!(
        context.timers_mut().pop_due(deadline).is_none(),
        "an expired incarnation gets no second grace interval"
    );
    let _ = &mut coordinator;
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

#[test]
fn a_refused_cut_page_stays_queued_at_its_position() -> TestResult {
    let a = ServerId::from_bytes([57; 16]);
    let b = ServerId::from_bytes([58; 16]);
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![
            peer_identity(a, "edge-a.example"),
            peer_identity(b, "edge-b.example"),
        ],
    )?;
    let mut parts = fixture.take_run_parts()?;
    let context = parts.state.context_mut();
    let mut coordinator = standalone_coordinator_pair(a, b);
    // One session homed at edge a stands in its cut.
    let seed = crate::test_support::remote_session_seed(context, a, "rae")?;
    let plan = context.domain().plan_session_opened(seed)?;
    crate::test_support::apply_live_plan(context, plan)?;
    let records =
        agenc_ircd_domain::federation::CoordinatorProjection::standing_of(context.domain(), a);
    assert!(!records.is_empty(), "the session stands for edge a");
    let projector = context.federation_mut().ok_or("no projector")?;
    projector.set_edge(
        a,
        crate::state_core::projector::EdgeDelivery {
            projection_generation: 2,
            next_delivery_sequence: 0,
        },
    );
    projector.install_edge(a, &records);
    let state = coordinator
        .peers
        .get_mut(&a)
        .ok_or("peer a is configured")?;
    state.projection_generation = 2;
    let page_rows = records.len();
    state.snapshot = Some(snapshot::Snapshot {
        identity: agenc_ircd_federation_wire::SnapshotIdentity {
            snapshot_token: FederationHash32::from_bytes([61; 32]),
            recovery_epoch: RecoveryEpoch::from_bytes([34; 16]),
            projection_generation: 2,
            state_generation: context.domain().revision().get(),
            snapshot_digest: FederationHash32::from_bytes([62; 32]),
        },
        entries: Vec::new(),
        records,
        next_send: 0,
        next_write: 0,
        end_sent: false,
        ready: false,
        link: crate::federation::LinkId::new(1),
    });
    // Another batch is with storage, so staging the page is refused.
    let account = agenc_ircd_domain::AccountState::new(
        agenc_ircd_testkit::account_id(9),
        agenc_ircd_testkit::generation(1)?,
        context.domain().revision(),
    );
    let plan = context.domain().plan_account_created(account)?;
    let request = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?;
    context
        .stage_durable(plan, request, None, 0)
        .map_err(|_| "staging was refused")?;
    std::thread::sleep(std::time::Duration::from_millis(5));
    context
        .drive_batch()
        .map_err(|_| "the batch did not submit")?;
    assert!(context.in_flight());
    let step = snapshot::write_batch(&mut coordinator, context, a);
    assert!(
        matches!(step, snapshot::WriteStep::Done),
        "a refused page ends this write pass"
    );
    assert!(coordinator.pending.is_none());
    let next_write = coordinator
        .peers
        .get(&a)
        .and_then(|state| state.snapshot.as_ref())
        .map(|snapshot| snapshot.next_write);
    assert_eq!(
        next_write,
        Some(0),
        "the refused page of {page_rows} rows is written again later"
    );
    Ok(())
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

/// The companion executor of the fixture coordinator with a sequencer.
fn companion_setup() -> TestResult<crate::test_support::CompanionSetup> {
    use crate::e2ee::coordinator::tests::support::{key, sequencer_credential_in};
    use agenc_ircd_e2ee::profile::EcapTuple;
    use agenc_ircd_e2ee::sequencer::SequencerKeySet;
    use agenc_ircd_e2ee::wire::tokens::base64url_encode;
    let network = *NETWORK.as_bytes();
    let mut executor = crate::e2ee::coordinator::CompanionCoordinator::new(
        network,
        COORDINATOR,
        COORDINATOR_NAME.to_owned(),
    );
    let sequencer = key(90);
    let credential = sequencer_credential_in(network, &sequencer, 0, (0, 4_000_000_000), None)?;
    let key_set = SequencerKeySet::verify(&network, std::slice::from_ref(&credential), 0, None)?;
    let tuple = EcapTuple::local(
        &base64url_encode(&network),
        &base64url_encode(COORDINATOR.as_bytes()),
        key_set.set_generation,
        &base64url_encode(&key_set.digest),
    )?;
    executor.install_sequencer(sequencer, key_set, credential);
    Ok(crate::test_support::CompanionSetup {
        profile: crate::e2ee::link::CompanionProfile { local: tuple },
        executor,
    })
}

/// Runs the coordinator with the companion executor installed.
async fn run_companion_coordinator<Driver, Output>(
    edges: &[PeerIdentity],
    driver: impl FnOnce(mpsc::Sender<FederationInbound>) -> Driver,
) -> TestResult<Output>
where
    Driver: Future<Output = TestResult<Output>>,
{
    let mut fixture = StateCoreFixture::with_companion_coordinator(
        entropy_script(),
        edges.to_vec(),
        companion_setup()?,
    )?;
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

/// Answers the coordinator's ECAP OFFER with the edge's own OFFER and ACK,
/// and consumes the coordinator's ACK.
async fn negotiate_companion(edge: &mut Edge) -> TestResult {
    let CompanionFrame::EcapOffer(tuple) = edge.next_companion().await? else {
        return Err("expected ECAP OFFER".into());
    };
    edge.companion(CompanionFrame::EcapOffer(tuple.clone()))
        .await?;
    edge.companion(CompanionFrame::EcapAck(tuple)).await?;
    match edge.next_companion().await? {
        CompanionFrame::EcapAck(_) => Ok(()),
        other => Err(format!("expected ECAP ACK, got {}", other.command()).into()),
    }
}

/// Sends one companion object as its fragments.
async fn companion_object(
    edge: &mut Edge,
    bytes: &[u8],
    frame: impl Fn(agenc_ircd_e2ee::wire::fragment::FragmentTag) -> CompanionFrame,
) -> TestResult {
    for fragment in agenc_ircd_e2ee::wire::fragment::fragment_object(bytes)? {
        edge.companion(frame(fragment)).await?;
    }
    Ok(())
}

#[tokio::test]
async fn companion_requests_execute_after_negotiation_and_synchronization() -> TestResult {
    use agenc_ircd_e2ee::federation::frames::Correlation;
    use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
    use agenc_ircd_e2ee::objects::federation::{
        IrcFederationOpcode, IrcFederationOrigin, IrcFederationRequest,
    };
    use agenc_ircd_e2ee::tls::{Opaque, TlsEncode};

    let edge_identity = peer_identity(ServerId::from_bytes([3; 16]), "edge.example");
    run_companion_coordinator(&[edge_identity], |federation| async move {
        let mut edge = Edge::new(federation, 3);
        let mut origin = Origin::new(9);
        edge.establish().await?;
        negotiate_companion(&mut edge).await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let incarnation = *edge.incarnation.as_bytes();
        let coordinator = *COORDINATOR.as_bytes();

        // ERESUME on a fresh scope opens the empty ESTATE transfer; READY
        // records the cut and ACTIVE follows.
        edge.companion(CompanionFrame::Resume {
            coordinator_server_id: coordinator,
            server_incarnation: incarnation,
            delivery_generation: 0,
            last: None,
        })
        .await?;
        let CompanionFrame::StateBegin {
            snapshot_token,
            state_generation,
            delivery_generation,
            total_entry_count,
            snapshot_digest,
            ..
        } = edge.next_companion().await?
        else {
            return Err("expected ESTATE BEGIN".into());
        };
        assert_eq!(total_entry_count, 0);
        let CompanionFrame::StateEnd {
            next_cursor: None, ..
        } = edge.next_companion().await?
        else {
            return Err("expected the final ESTATE END".into());
        };
        edge.companion(CompanionFrame::StateCut {
            active: false,
            server_id: coordinator,
            snapshot_token,
            state_generation,
            delivery_generation,
            snapshot_digest,
        })
        .await?;
        let CompanionFrame::StateCut { active: true, .. } = edge.next_companion().await? else {
            return Err("expected ESTATE ACTIVE".into());
        };

        // The companion origin set mirrors the ACKed base origin.
        edge.companion(CompanionFrame::OriginReset {
            coordinator_server_id: coordinator,
            server_incarnation: incarnation,
        })
        .await?;
        let CompanionFrame::OriginReady { .. } = edge.next_companion().await? else {
            return Err("expected EORIGIN READY".into());
        };
        let record = origin.record(&edge);
        let companion_origin = IrcFederationOrigin {
            profile_version: 1,
            network_id: *NETWORK.as_bytes(),
            home_server_id: *edge.server_id.as_bytes(),
            server_incarnation: incarnation,
            origin_id: *origin.id.as_bytes(),
            origin_generation: 0,
            previous_origin_state_id: [0; 32],
            connection_id: *record.connection_id.as_bytes(),
            session_id: Opaque::new(Vec::new())?,
            user_id: Opaque::new(Vec::new())?,
            account_id: Opaque::new(Vec::new())?,
            account_session_generation: 0,
            connection_nonce: record.connection_nonce,
            attached_device_id: Opaque::new(Vec::new())?,
            device_session_generation: 0,
        };
        let origin_bytes = IrcWireObject::new(
            IrcWireObjectKind::FederationOrigin,
            companion_origin.encode()?,
        )?
        .encode()?;
        let origin_object = *agenc_ircd_e2ee::ObjectId::compute(&origin_bytes).as_bytes();
        let origin_id = *origin.id.as_bytes();
        companion_object(&mut edge, &origin_bytes, |fragment| {
            CompanionFrame::OriginState {
                update: false,
                coordinator_server_id: coordinator,
                server_incarnation: incarnation,
                origin_id,
                origin_generation: 0,
                object_id: origin_object,
                fragment,
            }
        })
        .await?;
        let CompanionFrame::OriginAck {
            object_id: Some(acked),
            ..
        } = edge.next_companion().await?
        else {
            return Err("expected EORIGIN ACK".into());
        };
        assert_eq!(acked, origin_object);

        // A guest origin asking `whoami` is answered with the failed result;
        // a failed result completes nothing, so no event follows it.
        let request = IrcFederationRequest {
            profile_version: 1,
            network_id: *NETWORK.as_bytes(),
            home_server_id: *edge.server_id.as_bytes(),
            server_incarnation: incarnation,
            origin_id,
            origin_generation: 0,
            operation_sequence: 0,
            request_id: [1; 16],
            opcode: IrcFederationOpcode::Whoami,
            encoded_parameters: Opaque::new(Vec::new())?,
            payload_object_id: Opaque::new(Vec::new())?,
        };
        let request_bytes =
            IrcWireObject::new(IrcWireObjectKind::FederationRequest, request.encode()?)?
                .encode()?;
        let request_object = *agenc_ircd_e2ee::ObjectId::compute(&request_bytes).as_bytes();
        let correlation = Correlation {
            peer_server_id: coordinator,
            server_incarnation: incarnation,
            origin_id,
            origin_generation: 0,
            operation_sequence: 0,
            request_id: [1; 16],
        };
        companion_object(&mut edge, &request_bytes, |fragment| {
            CompanionFrame::Request {
                correlation,
                object_id: request_object,
                fragment,
            }
        })
        .await?;
        let CompanionFrame::Result {
            correlation: answered,
            ..
        } = edge.next_companion().await?
        else {
            return Err("expected ERESULT".into());
        };
        assert_eq!(answered.request_id, [1; 16]);

        // The identical request again replays the stored result.
        companion_object(&mut edge, &request_bytes, |fragment| {
            CompanionFrame::Request {
                correlation,
                object_id: request_object,
                fragment,
            }
        })
        .await?;
        let CompanionFrame::Result {
            correlation: replayed,
            ..
        } = edge.next_companion().await?
        else {
            return Err("expected the replayed ERESULT".into());
        };
        assert_eq!(replayed.request_id, [1; 16]);
        Ok(())
    })
    .await
}

// ---------------------------------------------------------------------------
// Remote account carriers (spec 22.2).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_forwarded_authentication_start_is_answered_through_a_virtual_connection() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([44; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 44);
        let mut origin = Origin::new(64);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let mut events = Vec::new();
        let envelope = crate::test_support::sealed_authentication_start(
            NETWORK,
            RecoveryEpoch::from_bytes([34; 16]),
            "quinn-account",
            71,
        )?;
        let mut budget = DecodeBudget::new(8_192, 64);
        let envelope = SchemaObject::decode_exact("AccountServiceEnvelope", &envelope, &mut budget)
            .map_err(|error| format!("envelope decode: {error:?}"))?;
        let operation = FederatedOperation::AccountService {
            opcode: agenc_ircd_types::FederationOpcode::OpaqueAuthStart,
            session_id: None,
            envelope,
        };
        let _probe = operation
            .to_object()
            .map_err(|error| format!("operation object: {error:?}"))?;
        request(&mut edge, &mut origin, &operation)
            .await
            .map_err(|error| format!("request: {error}"))?;
        // The virtual connection ran the SASL carrier; an unknown login still
        // receives its sealed challenge so logins cannot be enumerated.
        let challenge = answer(&mut edge, &mut events).await?;
        if let ResultArm::Failed { code, context } = &challenge.arm {
            return Err(format!("start refused: {code} {context}").into());
        }
        assert_eq!(
            challenge.header.result_kind,
            FederationResultKind::AuthChallenge
        );
        assert!(challenge.header.completion_event_id.is_none());
        let ResultArm::AuthChallenge(response) = challenge.arm else {
            return Err("expected the sealed challenge".into());
        };
        assert_eq!(
            response.encode_canonical()?.as_slice().len(),
            agenc_ircd_auth::ACCOUNT_SERVICE_RESPONSE_BYTES
        );

        // A session open naming a grant nobody holds is refused, and the
        // link stays up for ordinary work afterwards.
        origin.sequence += 1;
        let connection_id = origin.connection_id;
        request(
            &mut edge,
            &mut origin,
            &FederatedOperation::SessionOpen {
                connection_id,
                auth_grant_id: Some([9; 32]),
                nickname: "quinn".to_owned(),
                realname: "Quinn".to_owned(),
                capability_hash: [0; 32],
                connection_nonce: [1; 32],
            },
        )
        .await?;
        let refused = answer(&mut edge, &mut events).await?;
        assert_eq!(refused.header.result_kind, FederationResultKind::Failed);
        origin.sequence += 1;
        let (_session_id, _, _) =
            open_session(&mut edge, &mut origin, "quinn", &mut events).await?;
        Ok(())
    })
    .await
}

#[cfg(feature = "history")]
#[path = "history.rs"]
mod history_tests;

fn synchronized_peer_fixture(
    coordinator: &mut FederationCoordinator,
    peer: ServerId,
    incarnation: ServerIncarnation,
) -> TestResult {
    coordinator.origins.reset(peer, incarnation);
    coordinator.origins.ready(peer, incarnation)?;
    let state = coordinator.peers.get_mut(&peer).ok_or("peer")?;
    state.incarnation = Some(incarnation);
    state.phase = PeerPhase::Ready;
    Ok(())
}

#[tokio::test]
async fn resync_resume_preserves_the_retained_outbox_budget() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(
        context,
        established(1, peer, ServerIncarnation::from_bytes([51; 16]), handle),
    );
    let state = coordinator.peers.get_mut(&peer).ok_or("peer")?;
    state
        .outbox
        .unacked
        .push_back((0, agenc_ircd_types::EventId::from_bytes([80; 16]), 128));
    state.outbox.unacked_bytes = 128;
    snapshot::resume(
        &mut coordinator,
        context,
        LinkId::new(1),
        peer,
        1,
        agenc_ircd_federation_wire::DeliveryCursor::Empty,
    )
    .map_err(|error| format!("resume {error:?}"))?;
    assert_eq!(
        coordinator
            .peers
            .get(&peer)
            .ok_or("peer")?
            .outbox
            .unacked_bytes,
        128,
        "resume cannot erase already committed retention pressure"
    );
    Ok(())
}

#[tokio::test]
async fn resync_expiry_stages_the_authority_fence_before_any_hide() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let (handle, _queue) = link_queue(1 << 20);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    let user = host_session(context, peer, "kate")?;
    coordinator.inbound(context, closed(1, peer));
    let deadline = grace_deadline(context)?;
    let timer = pop_grace_timer(context, peer, deadline)?;
    assert!(coordinator.timer_fired(context, timer));
    assert_eq!(
        coordinator.counters().sessions_expired,
        0,
        "the first transaction fences authority before staging individual hides"
    );
    assert!(
        context.domain().session(user).is_some(),
        "visibility changes when the fence commits"
    );
    assert_eq!(context.pending_len(), 1);
    fixture.commit_staged_batch().await?;
    let context = fixture.context_mut()?;
    coordinator.batch_applied(context);
    assert!(
        context.domain().session(user).is_none(),
        "the committed fence excludes the uncollected session"
    );
    assert!(
        context.domain().durable_session(user).is_some(),
        "cleanup still owns the physical session row"
    );
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.cleanup.front(),
        Some(&user),
        "fenced rows remain owned until their hide commits"
    );
    assert!(
        context
            .index()
            .holds(TableId::FederationPeer, &peer_key(peer)?)
    );
    assert_eq!(
        coordinator
            .peers
            .get(&peer)
            .ok_or("peer")?
            .projection_generation,
        2
    );
    Ok(())
}

#[tokio::test]
async fn resync_a_new_incarnation_fences_before_cleaning_the_previous_one() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let first = ServerIncarnation::from_bytes([51; 16]);
    let second = ServerIncarnation::from_bytes([52; 16]);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, first, handle));
    synchronized_peer_fixture(&mut coordinator, peer, first)?;
    host_session(context, peer, "kate")?;
    coordinator.inbound(context, closed(1, peer));
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(2, peer, second, handle));
    coordinator.inbound(context, reset_frame(2, peer, second));
    assert_eq!(
        coordinator.counters().sessions_expired,
        0,
        "replacement first stages a peer fence"
    );
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.incarnation,
        Some(first),
        "new authority waits for the prior incarnation's cleanup"
    );
    assert_eq!(context.pending_len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_replacement_incarnation_is_admitted_after_cleanup_and_snapshot() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let first = ServerIncarnation::from_bytes([51; 16]);
    let second = ServerIncarnation::from_bytes([52; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let user = resync_persist_session(&mut fixture, peer, 1, 9, "kate").await?;
    let mut coordinator = standalone_coordinator(peer);
    let context = fixture.context_mut()?;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, first, handle));
    synchronized_peer_fixture(&mut coordinator, peer, first)?;
    coordinator.inbound(context, closed(1, peer));
    let (handle, _queue_again) = link_queue(1 << 20);
    coordinator.inbound(context, established(2, peer, second, handle));
    coordinator.inbound(context, reset_frame(2, peer, second));
    assert!(context.domain().session(user).is_some());
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.incarnation,
        Some(first)
    );

    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    let context = fixture.context_mut()?;
    assert!(context.domain().session(user).is_none());
    assert!(context.domain().durable_session(user).is_some());
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.phase,
        PeerPhase::Expired
    );
    let (handle, _queue_during_cleanup) = link_queue(1 << 20);
    let LinkEvent::Established { session, handle } = established(3, peer, second, handle).event
    else {
        return Err("establishment fixture".into());
    };
    coordinator.link_established(context, session, handle);
    assert!(coordinator.peers.get(&peer).ok_or("peer")?.live.is_none());

    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert!(
        fixture
            .context_mut()?
            .domain()
            .durable_session(user)
            .is_none()
    );
    assert_eq!(
        resync_read_peer(&mut fixture, peer).await?.phase,
        PeerPhase::Clean
    );

    let (handle, _queue_after_cleanup) = link_queue(1 << 20);
    coordinator.inbound(fixture.context_mut()?, established(4, peer, second, handle));
    complete_replacement_snapshot(&mut fixture, &mut coordinator, peer).await?;
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.phase,
        PeerPhase::Clean,
        "snapshot activation preserves the completed authority cleanup"
    );
    assert_eq!(
        resync_read_peer(&mut fixture, peer).await?.phase,
        PeerPhase::Clean
    );
    let violations = coordinator.counters().violations;
    coordinator.inbound(fixture.context_mut()?, reset_frame(4, peer, second));
    assert_eq!(coordinator.counters().violations, violations);
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.incarnation,
        Some(second)
    );
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::OriginReady { .. })
    ));
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    let record = resync_read_peer(&mut fixture, peer).await?;
    assert_eq!(record.phase, PeerPhase::Ready);
    assert_eq!(record.server_incarnation, *second.as_bytes());
    assert!(coordinator.link_is_live(LinkId::new(4), peer));
    assert_eq!(
        coordinator
            .origins
            .fenced_incarnations_of(peer)
            .collect::<Vec<_>>(),
        vec![first]
    );
    Ok(())
}

/// Commits the base snapshot that precedes a replacement's origin reset.
async fn complete_replacement_snapshot(
    fixture: &mut StateCoreFixture,
    coordinator: &mut FederationCoordinator,
    peer: ServerId,
) -> TestResult {
    snapshot::resume(
        coordinator,
        fixture.context_mut()?,
        LinkId::new(4),
        peer,
        0,
        agenc_ircd_federation_wire::DeliveryCursor::Empty,
    )
    .map_err(|error| format!("snapshot resume: {error:?}"))?;
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    let snapshot = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.snapshot.as_ref())
        .ok_or("snapshot")?;
    assert!(snapshot.end_sent);
    let identity = snapshot.identity;
    snapshot::ready(
        coordinator,
        fixture.context_mut()?,
        LinkId::new(4),
        peer,
        identity,
    )
    .map_err(|error| format!("snapshot ready: {error:?}"))?;
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.ready_identity,
        Some(identity)
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_activation_keeps_same_incarnation_origins_suspended() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut coordinator = standalone_coordinator(peer);
    let context = fixture.context_mut()?;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    coordinator.inbound(context, closed(1, peer));
    let (handle, _queue_again) = link_queue(1 << 20);
    coordinator.inbound(context, established(4, peer, incarnation, handle));
    complete_replacement_snapshot(&mut fixture, &mut coordinator, peer).await?;
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.phase,
        PeerPhase::Suspended,
        "projection activation cannot complete origin replay"
    );
    assert_eq!(
        resync_read_peer(&mut fixture, peer).await?.phase,
        PeerPhase::Suspended
    );
    assert!(coordinator.link_is_live(LinkId::new(4), peer));
    Ok(())
}

#[tokio::test]
async fn resync_restart_keeps_the_replaced_incarnation_fenced() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let first = ServerIncarnation::from_bytes([51; 16]);
    let second = ServerIncarnation::from_bytes([52; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut coordinator = standalone_coordinator(peer);
    synchronized_peer_fixture(&mut coordinator, peer, first)?;
    synchronized_peer_fixture(&mut coordinator, peer, second)?;
    coordinator.stage_rows(
        fixture.context_mut()?,
        Vec::new(),
        PendingCommit::Acknowledged,
        Some(peer),
    )?;
    fixture.commit_staged_batch().await?;
    let mut restored = standalone_coordinator(peer);
    restored.startup(fixture.context_mut()?);
    while !restored.loaded() {
        let message = fixture.next_storage_read().await?;
        restored.storage_read_completed(fixture.context_mut()?, message);
    }
    restored.origins.reset(peer, first);
    assert!(
        !restored.origins.is_resetting(peer, first),
        "a peer checkpoint retains earlier incarnation fences"
    );
    Ok(())
}

#[tokio::test]
async fn resync_an_empty_expiry_cleanup_commits_the_clean_phase() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut coordinator = standalone_coordinator(peer);
    let (handle, _queue) = link_queue(1 << 20);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let context = fixture.context_mut()?;
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    coordinator.inbound(context, closed(1, peer));
    let deadline = grace_deadline(context)?;
    let timer = pop_grace_timer(context, peer, deadline)?;
    coordinator.timer_fired(context, timer);
    for _ in 0..4 {
        if fixture.context_mut()?.pending_len() == 0 {
            break;
        }
        fixture.commit_staged_batch().await?;
        coordinator.batch_applied(fixture.context_mut()?);
    }
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.phase,
        PeerPhase::Clean,
        "an empty cleanup still needs a durable terminal checkpoint"
    );
    Ok(())
}

#[tokio::test]
async fn resync_a_fenced_incarnation_cannot_open_a_base_link() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut coordinator = standalone_coordinator(peer);
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    coordinator.origins.fence_edge(peer);
    coordinator.peers.get_mut(&peer).ok_or("peer")?.phase = PeerPhase::Clean;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(
        fixture.context_mut()?,
        established(1, peer, incarnation, handle),
    );
    assert!(
        coordinator.peers.get(&peer).ok_or("peer")?.live.is_none(),
        "base resume cannot bypass the permanent incarnation fence"
    );
    Ok(())
}

fn resync_message_authorization(
    context: &StateCoreContext,
    user: UserId,
    target: &str,
) -> Result<(), agenc_ircd_domain::DomainError> {
    use agenc_ircd_domain::{
        AdmissionSnapshot, CanonicalCommand, CommandEnvelope, MessageCommand, MessageKind,
        MessageTarget, MessageText, NicknameValue,
    };
    let session = context
        .domain()
        .retained_session(user)
        .ok_or(agenc_ircd_domain::DomainError::NotFound)?;
    let command = CanonicalCommand::message(MessageCommand::new(
        MessageKind::Privmsg,
        vec![MessageTarget::User(NicknameValue::parse(target)?)],
        Some(MessageText::parse("hello")?),
    )?);
    let mut charges: Vec<_> = context
        .domain()
        .command_charges(user, &command)
        .iter()
        .map(|charge| (charge.bucket(), 10_000))
        .collect();
    charges.sort_by_key(|(bucket, _)| format!("{bucket:?}"));
    charges.dedup_by_key(|(bucket, _)| format!("{bucket:?}"));
    let envelope = CommandEnvelope::new(
        session.session_id(),
        user,
        session.generation(),
        context.domain().revision(),
        command,
    );
    let authorized = context
        .domain()
        .authorize(envelope, &AdmissionSnapshot::new(charges)?)
        .map_err(|failure| failure.error())?;
    match context.domain().plan_authorized(authorized, None)? {
        agenc_ircd_domain::PlanDecision::Rejected(rejected) => {
            Err(rejected.failures().first().map_or(
                agenc_ircd_domain::DomainError::InvariantViolation,
                |failure| failure.error(),
            ))
        }
        _ => Ok(()),
    }
}

#[tokio::test]
async fn resync_suspended_sessions_cannot_send_or_be_new_direct_message_targets() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    let kate = host_session(context, peer, "kate")?;
    let bob = host_session(context, ServerId::from_bytes([60; 16]), "bob")?;
    assert!(resync_message_authorization(context, bob, "kate").is_ok());
    coordinator.inbound(context, closed(1, peer));
    assert!(
        resync_message_authorization(context, bob, "kate").is_err(),
        "suspended sessions cannot become new direct-message targets"
    );
    assert!(
        resync_message_authorization(context, kate, "bob").is_err(),
        "suspended sessions cannot execute mutations"
    );
    assert!(
        context.domain().session(kate).is_some(),
        "grace retains visible membership and session state"
    );
    Ok(())
}

#[tokio::test]
async fn resync_startup_backlog_overflow_closes_the_queued_link() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(peer);
    coordinator.startup(context);
    let (handle, mut queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    for _ in 0..MAX_BACKLOG {
        coordinator.inbound(context, reset_frame(1, peer, incarnation));
    }
    assert!(
        coordinator.backlog.is_empty(),
        "the failed link's queued establishment and frames must retire together"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), queue.recv())
            .await?
            .is_none()
    );
    Ok(())
}

async fn resync_persist_session(
    fixture: &mut StateCoreFixture,
    peer: ServerId,
    session_byte: u8,
    user_byte: u8,
    name: &str,
) -> TestResult<UserId> {
    let context = fixture
        .context_mut()
        .map_err(|error| format!("context: {error}"))?;
    let mut seed = crate::test_support::remote_session_seed(context, peer, name)?;
    seed.session_id = SessionId::from_bytes([session_byte; 16]);
    seed.user_id = UserId::from_bytes([user_byte; 16]);
    seed.connection_nonce = [session_byte; 32];
    seed.public_cloak = agenc_ircd_testkit::deterministic_cloak(user_byte)?;
    let user = seed.user_id;
    let plan = context
        .domain()
        .plan_session_opened(seed)
        .map_err(|error| format!("open {name}: {error:?}"))?;
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?;
    context
        .stage_durable(plan, fanout, None, 0)
        .map_err(|error| format!("stage session: {error:?}"))?;
    fixture
        .commit_staged_batch()
        .await
        .map_err(|error| format!("persist {name}: {error}"))?;
    Ok(user)
}

async fn resync_read_peer(
    fixture: &mut StateCoreFixture,
    peer: ServerId,
) -> TestResult<FederationPeerRecord> {
    let key = peer_key(peer)?;
    let id = fixture
        .context_mut()
        .map_err(|error| format!("context: {error}"))?
        .submit_storage_read(agenc_ircd_storage::ReadPlan::exact(
            TableId::FederationPeer,
            key.clone(),
        ))?;
    let message = fixture.next_storage_read().await?;
    assert_eq!(message.read_id, id);
    let result = message
        .result
        .map_err(|error| format!("peer read: {error:?}"))?;
    let row = result.records.first().ok_or("peer row missing")?;
    let opened = fixture
        .context_mut()
        .map_err(|error| format!("context: {error}"))?
        .open_storage_plaintext(TableId::FederationPeer, &key, &row.sealed_record)
        .map_err(|error| format!("open peer: {error:?}"))?;
    let value = agenc_ircd_storage::PersistentRecordValue::decode(
        TableId::FederationPeer,
        opened.expose_for_storage_codec(),
    )
    .map_err(|error| format!("peer envelope: {error:?}"))?;
    Ok(FederationPeerRecord::decode(value.body())
        .map_err(|error| format!("peer body: {error:?}"))?)
}

#[tokio::test]
async fn resync_cleanup_cursor_commits_with_the_hide_and_restarts_in_session_order() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let later = resync_persist_session(&mut fixture, peer, 2, 8, "later").await?;
    let first = resync_persist_session(&mut fixture, peer, 1, 9, "first").await?;
    let context = fixture
        .context_mut()
        .map_err(|error| format!("context: {error}"))?;
    let mut coordinator = standalone_coordinator(peer);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, peer, incarnation, handle));
    synchronized_peer_fixture(&mut coordinator, peer, incarnation)?;
    coordinator.inbound(context, closed(1, peer));
    let deadline = grace_deadline(context)?;
    let timer = pop_grace_timer(context, peer, deadline)?;
    coordinator.timer_fired(context, timer);
    fixture
        .commit_staged_batch()
        .await
        .map_err(|error| format!("cleanup commit: {error}"))?;
    coordinator.batch_applied(
        fixture
            .context_mut()
            .map_err(|error| format!("context: {error}"))?,
    );
    assert_eq!(
        coordinator.peers.get(&peer).ok_or("peer")?.cleanup.front(),
        Some(&first)
    );
    fixture
        .commit_staged_batch()
        .await
        .map_err(|error| format!("cleanup commit: {error}"))?;
    assert!(
        fixture
            .context_mut()
            .map_err(|error| format!("context: {error}"))?
            .domain()
            .durable_session(first)
            .is_none()
    );
    let record = resync_read_peer(&mut fixture, peer).await?;
    assert_eq!(
        record.cleanup_cursor,
        Some([2; 16]),
        "the committed hide advances the persisted Session-ID cursor"
    );
    let mut restarted = standalone_coordinator(peer);
    restarted.startup(
        fixture
            .context_mut()
            .map_err(|error| format!("context: {error}"))?,
    );
    while !restarted.loaded() {
        let message = fixture.next_storage_read().await?;
        restarted.storage_read_completed(
            fixture
                .context_mut()
                .map_err(|error| format!("context: {error}"))?,
            message,
        );
    }
    assert_eq!(
        restarted.peers.get(&peer).ok_or("peer")?.cleanup.front(),
        Some(&later)
    );
    fixture
        .commit_staged_batch()
        .await
        .map_err(|error| format!("cleanup commit: {error}"))?;
    restarted.batch_applied(
        fixture
            .context_mut()
            .map_err(|error| format!("context: {error}"))?,
    );
    assert!(
        fixture
            .context_mut()
            .map_err(|error| format!("context: {error}"))?
            .domain()
            .durable_session(later)
            .is_none()
    );
    let record = resync_read_peer(&mut fixture, peer).await?;
    assert_eq!(record.phase, PeerPhase::Clean);
    assert_eq!(record.cleanup_cursor, None);
    Ok(())
}

#[tokio::test]
async fn resync_account_transaction_contains_its_exact_federation_response() -> TestResult {
    let peer = ServerId::from_bytes([50; 16]);
    let incarnation = ServerIncarnation::from_bytes([51; 16]);
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let PendingCommit::Request {
        mut header,
        request_object_id,
        ..
    } = staged_request(peer, incarnation)
    else {
        return Err("request".into());
    };
    header.opcode = agenc_ircd_types::FederationOpcode::OpaqueAuthFinish;
    let generation = crate::connection::ConnectionGeneration::new(1 << 62);
    let context = fixture.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let origin = request::row(
        TableId::FederationOrigin,
        agenc_ircd_storage::federation_records::ORIGIN_RECORD_KIND,
        agenc_ircd_storage::federation_records::origin_key(
            peer,
            incarnation,
            *header.replay_key.origin_id.as_bytes(),
            header.replay_key.origin_generation,
        )?,
        revision,
        agenc_ircd_storage::federation_records::FederationOriginRecord {
            origin_object: vec![1],
            origin_object_id: [2; 32],
            next_sequence: 4,
            status: agenc_ircd_storage::federation_records::OriginRowStatus::Live,
            flags: 0,
        }
        .encode()?,
    )
    .map_err(|error| format!("{error:?}"))?;
    context.bind_remote_account_result(generation, header, request_object_id, origin);
    let arm = ResultArm::Failed {
        code: "NOT_ALLOWED".to_owned(),
        context: String::new(),
    };
    let writes = context.remote_account_result_writes(generation, revision, &arm, Vec::new())?;
    assert_eq!(
        writes.len(),
        2,
        "the account transaction must include its exact result and origin successor"
    );
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|error| format!("stage: {error:?}"))?;
    fixture.commit_staged_batch().await?;
    let key =
        agenc_ircd_storage::federation_records::request_result_key(header.replay_key.to_bytes())?;
    let context = fixture.context_mut()?;
    assert!(
        context.index().holds(TableId::RequestResult, &key),
        "the account receipt must already cover the outer replay row"
    );
    let read = context.submit_storage_read(agenc_ircd_storage::ReadPlan::exact(
        TableId::RequestResult,
        key.clone(),
    ))?;
    let message = fixture.next_storage_read().await?;
    assert_eq!(message.read_id, read);
    let result = message.result?;
    let row = result.records.first().ok_or("result missing")?;
    let opened = fixture.context_mut()?.open_storage_plaintext(
        TableId::RequestResult,
        &key,
        &row.sealed_record,
    )?;
    let value = agenc_ircd_storage::PersistentRecordValue::decode(
        TableId::RequestResult,
        opened.expose_for_storage_codec(),
    )?;
    let record =
        agenc_ircd_storage::federation_records::CoordinatorResultRecord::decode(value.body())?;
    assert_eq!(record.request_object_id, *request_object_id.as_bytes());
    assert_eq!(record.resulting_state_generation, revision);
    assert_eq!(
        record.result_object_id,
        *federation_object_id(&record.result_object).as_bytes()
    );
    Ok(())
}

/// Supplies a live origin to the staging boundary without running a client handshake.
fn remote_account_staging_request(
    coordinator: &mut FederationCoordinator,
    context: &mut crate::state_core::StateCoreContext,
) -> TestResult<(crate::federation::coordinator::FreshRequest, Edge)> {
    let (inbox, _receiver) = mpsc::channel(1);
    let edge = Edge::new(inbox, 50);
    let origin = Origin::new(72);
    let peer = edge.server_id;
    coordinator.inbound(
        context,
        established(50, peer, edge.incarnation, edge.handle.clone()),
    );
    coordinator.origins.reset(peer, edge.incarnation);
    let record = origin.record(&edge);
    let bytes = record.to_object()?.encode_canonical()?.as_slice().to_vec();
    let key = OriginKey {
        home_server_id: peer,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
    };
    coordinator
        .origins
        .add(agenc_ircd_domain::federation::OriginDeclaration {
            origin: key,
            generation: 0,
            previous_object_id: [0; 32],
            binding: agenc_ircd_domain::federation::OriginBinding {
                connection_id: record.connection_id,
                connection_nonce: record.connection_nonce,
            },
            principal: agenc_ircd_domain::federation::OriginPrincipal::UNREGISTERED,
            object_id: *federation_object_id(&bytes).as_bytes(),
        })?;
    coordinator.origin_objects.insert(key, bytes);
    coordinator.origins.ready(peer, edge.incarnation)?;
    let request_id = RequestId::from_bytes([73; 16]);
    let request_object_id = FederationHash32::from_bytes([74; 32]);
    let fresh = crate::federation::coordinator::FreshRequest {
        key: OperationKey {
            origin: key,
            generation: 0,
            sequence: 0,
        },
        header: RequestHeader {
            network_id: NETWORK,
            replay_key: origin.replay_key(&edge),
            request_id,
            opcode: agenc_ircd_types::FederationOpcode::AccountSettings,
        },
        descriptor: OperationDescriptor {
            addressed_server_id: COORDINATOR,
            server_incarnation: edge.incarnation,
            origin_id: origin.id,
            origin_generation: 0,
            operation_sequence: 0,
            request_id,
            object_id: request_object_id,
        },
        request_object_id,
        bound: None,
        command: Some(agenc_ircd_domain::CanonicalCommand::account(
            agenc_ircd_domain::AccountCommand::DeleteConfirm(
                agenc_ircd_types::AccountDeletionToken::from_bytes([75; 16]),
            ),
        )),
        mutation: agenc_ircd_domain::federation::MutationContext::default(),
        charge: None,
    };
    Ok((fresh, edge))
}

#[tokio::test]
async fn a_refused_remote_deletion_cancels_its_account_authority_barrier() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut config = crate::test_support::account_service_config(
        &fixture.identity,
        &fixture.opaque,
        fixture.key_state,
    )?;
    let context = fixture.context_mut()?;
    let (account, generation) = crate::test_support::seed_account(context, 213, 1)?;
    let session = crate::test_support::seed_session(
        context,
        215,
        "delete-test",
        Some((account, generation)),
    )?;
    let login_key = agenc_ircd_storage::LoginIndexStoredKey::new(
        1,
        agenc_ircd_crypto::LoginIndexDigest::from_storage_key([214; 32]),
    )?
    .encode()?;
    config.live_login_keys.insert(account, login_key);
    let mut accounts = crate::account_service::AccountServiceCoordinator::new(config)?;
    let peer = ServerId::from_bytes([50; 16]);
    let mut coordinator = standalone_coordinator(peer);
    let (fresh, _edge) = remote_account_staging_request(&mut coordinator, context)?;
    let deletion = context.domain().plan_account_deleted(account, generation)?;
    let agenc_ircd_domain::PlanDecision::Mutation(other) =
        crate::test_support::plan_live(context, session, &|| {
            Ok(agenc_ircd_domain::CanonicalCommand::account(
                agenc_ircd_domain::AccountCommand::Presence(
                    agenc_ircd_domain::PresencePolicy::Public,
                ),
            ))
        })?
    else {
        return Err("account update plan missing".into());
    };
    // Another admitted write owns the account in this batch. Neither the
    // deletion nor its failure checkpoint can join that revision chain.
    context
        .stage_durable(
            other,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
        )
        .map_err(|error| format!("competing account write: {error:?}"))?;
    let result = coordinator.execute_remote_account(
        context,
        &mut accounts,
        LinkId::new(50),
        peer,
        Box::new(fresh),
        Box::new(deletion),
    );
    assert_eq!(result, Err(Violation::Ceiling));
    let owner = crate::connection::ConnectionGeneration::new(1 << 62);
    assert!(
        !accounts.registered_authority_fenced(context, owner),
        "a refused mutation must not retain its account deletion barrier"
    );
    assert!(context.domain().account(account).is_some());
    assert_eq!(coordinator.take_closed_remote_carriers(), vec![owner]);
    assert!(coordinator.pending.is_none());
    assert_eq!(context.pending_len(), 1);
    let retry = crate::connection::ConnectionGeneration::new((1 << 62) + 1);
    let _writes = accounts.begin_account_deletion(context, retry, account)?;
    accounts.cancel_account_deletion(context, retry)?;
    Ok(())
}

struct StagedRemoteDeletion {
    fixture: StateCoreFixture,
    coordinator: FederationCoordinator,
    accounts: crate::account_service::AccountServiceCoordinator,
    edge: Edge,
    account: agenc_ircd_types::AccountId,
    key: agenc_ircd_domain::federation::OperationKey,
}

async fn staged_remote_deletion() -> TestResult<StagedRemoteDeletion> {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut config = crate::test_support::account_service_config(
        &fixture.identity,
        &fixture.opaque,
        fixture.key_state,
    )?;
    let (account, generation, login_key) = persist_remote_deletion_account(&mut fixture).await?;
    let context = fixture.context_mut()?;
    let _session = crate::test_support::seed_session(
        context,
        215,
        "delete-test",
        Some((account, generation)),
    )?;
    config.live_login_keys.insert(account, login_key);
    let mut accounts = crate::account_service::AccountServiceCoordinator::new(config)?;
    let peer = ServerId::from_bytes([50; 16]);
    let mut coordinator = standalone_coordinator(peer);
    let (fresh, edge) = remote_account_staging_request(&mut coordinator, context)?;
    let key = fresh.key;
    let deletion = context.domain().plan_account_deleted(account, generation)?;
    coordinator
        .execute_remote_account(
            context,
            &mut accounts,
            edge.link,
            peer,
            Box::new(fresh),
            Box::new(deletion),
        )
        .map_err(|error| format!("stage remote deletion: {error:?}"))?;
    let owner = crate::connection::ConnectionGeneration::new(1 << 62);
    assert!(accounts.registered_authority_fenced(context, owner));
    assert_eq!(context.pending_len(), 1);
    assert!(context.domain().account(account).is_some());
    Ok(StagedRemoteDeletion {
        fixture,
        coordinator,
        accounts,
        edge,
        account,
        key,
    })
}

async fn persist_remote_deletion_account(
    fixture: &mut StateCoreFixture,
) -> TestResult<(
    agenc_ircd_types::AccountId,
    agenc_ircd_types::Generation,
    agenc_ircd_storage::StoredKey,
)> {
    use agenc_ircd_storage::{LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind};
    let credential = fixture.opaque.expose_fake_record_for_persistence().to_vec();
    let context = fixture.context_mut()?;
    let account = agenc_ircd_testkit::account_id(213);
    let generation = agenc_ircd_testkit::generation(1)?;
    let plan = context
        .domain()
        .plan_account_created(agenc_ircd_domain::AccountState::new(
            account,
            generation,
            context.domain().revision(),
        ))?;
    let login_key = LoginIndexStoredKey::new(
        1,
        agenc_ircd_crypto::LoginIndexDigest::from_storage_key([214; 32]),
    )?;
    let login = LoginIndexValue::new(
        &login_key,
        LoginIndexValueKind::Live {
            account_id: account,
            opaque_credential_id: agenc_ircd_types::OpaqueCredentialId::from_bytes([216; 32]),
        },
    )?;
    let credential = agenc_ircd_storage::PersistentRecordValue::new(
        TableId::OpaqueRecord,
        agenc_ircd_storage::LIVE_RECORD_KIND,
        plan.resulting_revision().get(),
        generation.get(),
        None,
        vec![agenc_ircd_storage::RecordReference::new(
            TableId::Account,
            crate::state_core::durable::KeyDeriver::account_key(account)?,
        )?],
        credential,
    )?;
    let writes = vec![
        crate::state_core::durable::AccountServiceDurableWrite::put(
            TableId::LoginIndex,
            login_key.encode()?,
            login.encode()?,
        )?,
        crate::state_core::durable::AccountServiceDurableWrite::put(
            TableId::OpaqueRecord,
            agenc_ircd_storage::StoredKey::new(account.to_text().into_bytes())?,
            credential.encode()?,
        )?,
    ];
    context
        .stage_durable_with_account_service(
            plan,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|error| format!("seed durable account: {error:?}"))?;
    fixture.commit_staged_batch().await?;
    Ok((account, generation, login_key.encode()?))
}

#[tokio::test]
async fn a_rejected_remote_deletion_releases_its_tombstone_and_carrier() -> TestResult {
    let StagedRemoteDeletion {
        mut fixture,
        mut coordinator,
        mut accounts,
        edge: _edge,
        account,
        key,
    } = staged_remote_deletion().await?;
    let context = fixture.context_mut()?;
    let owner = crate::connection::ConnectionGeneration::new(1 << 62);
    let head = context.head();
    // Deliver the same determinate storage refusal callback that the router
    // receives. No domain plan or credential deletion has become visible.
    coordinator.batch_rejected(context);
    crate::remote_accounts::batch_settled(context, &mut accounts, &mut coordinator);
    assert_eq!(context.head(), head);
    assert!(context.domain().account(account).is_some());
    assert!(!accounts.registered_authority_fenced(context, owner));
    assert!(coordinator.take_rejected_deletion().is_none());
    assert!(coordinator.remote_carrier_peer(owner).is_none());
    assert!(!coordinator.retained.contains_key(&key));
    // A fresh attempt must be able to reserve the same account and tombstone.
    let retry = crate::connection::ConnectionGeneration::new((1 << 62) + 1);
    let _writes = accounts.begin_account_deletion(context, retry, account)?;
    accounts.cancel_account_deletion(context, retry)?;
    assert!(!accounts.registered_authority_fenced(context, retry));
    Ok(())
}

#[tokio::test]
async fn a_remote_deletion_keeps_its_commit_barrier_after_link_loss() -> TestResult {
    let StagedRemoteDeletion {
        mut fixture,
        mut coordinator,
        mut accounts,
        edge,
        account,
        key,
    } = staged_remote_deletion().await?;
    let owner = crate::connection::ConnectionGeneration::new(1 << 62);
    {
        let context = fixture.context_mut()?;
        coordinator.inbound(context, closed(edge.link.get(), edge.server_id));
        crate::remote_accounts::drive(context, &mut accounts, &mut coordinator);
        assert!(coordinator.remote_carrier_peer(owner).is_none());
        assert!(accounts.registered_authority_fenced(context, owner));
        assert!(context.domain().account(account).is_some());
    }
    fixture.commit_staged_batch().await?;
    let context = fixture.context_mut()?;
    let _completions = accounts.batch_applied(context);
    coordinator.batch_applied(context);
    crate::remote_accounts::batch_settled(context, &mut accounts, &mut coordinator);
    assert!(context.domain().account(account).is_none());
    assert!(!accounts.registered_authority_fenced(context, owner));
    assert!(coordinator.pending.is_none());
    assert!(coordinator.retained.contains_key(&key));
    assert!(coordinator.remote_carrier_peer(owner).is_none());
    assert!(
        accounts
            .begin_account_deletion(context, owner, account)
            .is_err()
    );
    Ok(())
}
