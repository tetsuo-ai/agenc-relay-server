#![forbid(unsafe_code)]

//! Edge tests: a scripted coordinator on the link and a scripted client
//! connection drive the real registration router in edge mode through the
//! actor loop and storage.

use std::error::Error;
use std::future::Future;

use agenc_ircd_client_wire::{FramedLine, WireMessage, parse_message};
use agenc_ircd_domain::federation::{
    ChannelDetailRecord, MembershipRecord, MembershipView, ProjectedEvent, SessionEventView,
    SessionRecord, SourceView,
};
use agenc_ircd_domain::{
    ChannelNameValue, ContentPolicy, DisplayNameValue, HistoryPolicy, NicknameValue,
    PersistencePolicy, Role, Visibility,
};
use agenc_ircd_federation_wire::{
    AssembledObject, AssemblyProgress, CanonicalEncode, DecodeBudget, EventHeader, FederationFrame,
    FragmentAssembler, OperationDescriptor, RequestCorrelation, RequestHeader, ResultHeader,
    SchemaObject, decode_request_operation, federation_object_id, split_fragments,
};
use agenc_ircd_types::{
    ChannelInstanceId, EventId, FederationRole, NetworkId, PublicCloak, RecoveryEpoch, Revision,
    ServerId, ServerIncarnation, SessionId, UserId, UtcSecond,
};
use tokio::sync::{mpsc, oneshot};

use super::*;
use crate::connection::sink::ClientSink;
use crate::federation::codec::events::event_arm_object;
use crate::federation::codec::operations::FederatedOperation;
use crate::federation::codec::results::{ResultArm, SessionRegistered, reply_object};
use crate::federation::link::{LinkQueue, carrier_of, link_queue, parse_frame};
use crate::purpose::ListenerPurpose;
use crate::state_core::StateCoreExit;
use crate::state_core::inbox::{
    LifecyclePhase, SourceAddressKey, StateCoreMessage, connection_close_channel, lifecycle_channel,
};
use crate::test_support::{FrameSink, StateCoreFixture};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

mod durability;
mod restart;

const NETWORK: NetworkId = NetworkId::from_bytes([31; 32]);
const EDGE: ServerId = ServerId::from_bytes([36; 16]);
const EDGE_NAME: &str = "edge.example";
const EDGE_INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([35; 16]);
/// The coordinator fixture's own identity.
const HUB: ServerId = ServerId::from_bytes([32; 16]);
const HUB_NAME: &str = "server.example";
const HUB_INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([33; 16]);
const HUB_EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([34; 16]);
const COORDINATOR: ServerId = ServerId::from_bytes([90; 16]);
const COORDINATOR_NAME: &str = "hub.example";
const COORDINATOR_EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([91; 16]);

fn entropy_script() -> Vec<u8> {
    // A xorshift stream: one megabyte with no repeating sixteen-byte window
    // in practice, so request and origin identifiers never collide.
    let mut state: u32 = 0x9e37_79b9;
    (0..1_048_576)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            u8::try_from(state & 0xff).unwrap_or(0)
        })
        .collect()
}

fn coordinator_identity() -> PeerIdentity {
    PeerIdentity::new(
        COORDINATOR,
        COORDINATOR_NAME,
        FederationRole::Coordinator,
        COORDINATOR_EPOCH,
        agenc_ircd_crypto::Ed25519SecretKey::from_bytes([12; 32]).public_key(),
        [13; 32],
    )
}

/// The scripted coordinator side of the link.
struct Hub {
    link: LinkId,
    handle: LinkHandle,
    queue: LinkQueue,
    assembler: FragmentAssembler,
    inbox: mpsc::Sender<FederationInbound>,
    next_sequence: u64,
    state_generation: u64,
}

impl Hub {
    fn new(inbox: mpsc::Sender<FederationInbound>) -> Self {
        let (handle, queue) = link_queue(1 << 20);
        Self {
            link: LinkId::new(7),
            handle,
            queue,
            assembler: FragmentAssembler::new(),
            inbox,
            next_sequence: 0,
            state_generation: 10,
        }
    }

    async fn send(&self, event: LinkEvent) -> TestResult {
        self.inbox
            .send(FederationInbound {
                link: self.link,
                peer: COORDINATOR,
                event,
                charge: None,
            })
            .await
            .map_err(|_| "edge inbox closed")?;
        Ok(())
    }

    async fn establish(&mut self) -> TestResult {
        let session = LinkSession {
            link: self.link,
            peer: COORDINATOR,
            peer_incarnation: ServerIncarnation::from_bytes([92; 16]),
            peer_recovery_epoch: COORDINATOR_EPOCH,
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

    async fn next_frame(&mut self) -> TestResult<FederationFrame> {
        let line = tokio::time::timeout(std::time::Duration::from_secs(20), self.queue.recv())
            .await
            .map_err(|_| "no line from the edge")?
            .ok_or("edge closed the link")?;
        let text = line.as_str().trim_end_matches("\r\n").to_owned();
        Ok(parse_frame(&text, EDGE_NAME).map_err(|error| format!("{error:?}: {text}"))?)
    }

    /// Reads frames until one satisfies `accept`, assembling objects.
    async fn expect_frame(
        &mut self,
        accept: impl Fn(&FederationFrame, Option<&AssembledObject>) -> bool,
    ) -> TestResult<(FederationFrame, Option<AssembledObject>)> {
        for _ in 0..512 {
            let frame = self.next_frame().await?;
            let object = match frame.fragment() {
                Some(fragment) => {
                    let (_, key) = carrier_of(&frame).map_err(|error| error.to_string())?;
                    match self.assembler.admit(key, fragment, 0)? {
                        AssemblyProgress::Complete(object) => Some(object),
                        AssemblyProgress::Incomplete { .. } => continue,
                    }
                }
                None => None,
            };
            if accept(&frame, object.as_ref()) {
                return Ok((frame, object));
            }
        }
        Err("the edge never sent the expected frame".into())
    }

    /// Reads the next request and returns its header and decoded operation.
    async fn next_request(&mut self) -> TestResult<(RequestHeader, FederatedOperation, Vec<u8>)> {
        let (_, object) = self
            .expect_frame(|frame, object| {
                matches!(frame, FederationFrame::Request { .. }) && object.is_some()
            })
            .await?;
        let object = object.ok_or("request without object")?;
        let mut budget = DecodeBudget::new(1 << 20, 4_096);
        let request =
            SchemaObject::decode_exact("FederationRequest", object.as_slice(), &mut budget)?;
        let header = RequestHeader::from_object(&request)?;
        let arm = decode_request_operation(&request, &mut budget)?;
        let operation = FederatedOperation::from_object(header.opcode, &arm)?;
        Ok((header, operation, object.as_slice().to_vec()))
    }

    /// Sends one event to the edge and waits for its ACK.
    async fn event(
        &mut self,
        event: &ProjectedEvent,
        correlation: Option<RequestCorrelation>,
    ) -> TestResult<EventId> {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let mut id = [0_u8; 16];
        id[..8].copy_from_slice(&sequence.to_be_bytes());
        id[15] = 1;
        let event_id = EventId::from_bytes(id);
        let header = EventHeader {
            network_id: NETWORK,
            target_server_id: EDGE,
            projection_generation: 1,
            coordinator_state_generation: self.state_generation,
            delivery_sequence: sequence,
            event_id,
            event_kind: event.kind(),
            correlation,
            cross_profile: None,
        };
        let arm = event_arm_object(event).map_err(|error| format!("event arm: {error:?}"))?;
        let object = header
            .build(&arm)
            .map_err(|error| format!("event header: {error:?}"))?;
        let encoded = object
            .encode_canonical()
            .map_err(|error| format!("event encode: {error:?}"))?
            .as_slice()
            .to_vec();
        let descriptor = agenc_ircd_federation_wire::EventDescriptor {
            target_server_id: EDGE,
            delivery_sequence: sequence,
            event_id,
            object_id: federation_object_id(&encoded),
        };
        self.object(&encoded, |fragment| FederationFrame::Event {
            descriptor,
            fragment,
        })
        .await?;
        let (frame, _) = self
            .expect_frame(|frame, _| matches!(frame, FederationFrame::Ack { .. }))
            .await?;
        let FederationFrame::Ack {
            delivery_sequence,
            event_id: acked,
            ..
        } = frame
        else {
            return Err("expected FACK".into());
        };
        assert_eq!(delivery_sequence, sequence);
        assert_eq!(acked, event_id);
        Ok(event_id)
    }

    /// Sends one base event carrying a cross-profile tuple and expects no
    /// acknowledgement: the barrier waits for its companion parts.
    async fn barrier_part(
        &mut self,
        event: &ProjectedEvent,
        tuple: agenc_ircd_federation_wire::CrossProfilePart,
    ) -> TestResult {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let mut id = [0_u8; 16];
        id[..8].copy_from_slice(&sequence.to_be_bytes());
        id[15] = 2;
        let event_id = EventId::from_bytes(id);
        let header = EventHeader {
            network_id: NETWORK,
            target_server_id: EDGE,
            projection_generation: 1,
            coordinator_state_generation: self.state_generation,
            delivery_sequence: sequence,
            event_id,
            event_kind: event.kind(),
            correlation: None,
            cross_profile: Some(tuple),
        };
        let arm = event_arm_object(event).map_err(|error| format!("event arm: {error:?}"))?;
        let encoded = header
            .build(&arm)
            .map_err(|error| format!("part header {tuple:?}: {error:?}"))?
            .encode_canonical()
            .map_err(|error| format!("event encode: {error:?}"))?
            .as_slice()
            .to_vec();
        let descriptor = agenc_ircd_federation_wire::EventDescriptor {
            target_server_id: EDGE,
            delivery_sequence: sequence,
            event_id,
            object_id: federation_object_id(&encoded),
        };
        self.object(&encoded, |fragment| FederationFrame::Event {
            descriptor,
            fragment,
        })
        .await
    }

    /// Drains whatever the edge queued before it noticed the fault, then
    /// requires the close request.
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

    /// Sends one result for a request.
    async fn result(
        &mut self,
        header: &RequestHeader,
        request_bytes: &[u8],
        arm: &ResultArm,
        replies: Vec<WireMessage>,
        completion: Option<EventId>,
    ) -> TestResult {
        let result_header = ResultHeader {
            network_id: NETWORK,
            replay_key: header.replay_key,
            request_id: header.request_id,
            request_object_id: federation_object_id(request_bytes),
            completion_event_id: completion,
            result_kind: arm.kind(),
        };
        let mut reply_objects = Vec::new();
        for reply in &replies {
            reply_objects.push(reply_object(reply)?);
        }
        let arm_object = arm
            .to_object()
            .map_err(|error| format!("result arm: {error:?}"))?;
        let encoded = result_header
            .build(&arm_object, reply_objects)
            .map_err(|error| format!("result header: {error:?}"))?
            .encode_canonical()
            .map_err(|error| format!("result encode: {error:?}"))?
            .as_slice()
            .to_vec();
        let descriptor = OperationDescriptor {
            addressed_server_id: COORDINATOR,
            server_incarnation: header.replay_key.server_incarnation,
            origin_id: header.replay_key.origin_id,
            origin_generation: header.replay_key.origin_generation,
            operation_sequence: header.replay_key.operation_sequence,
            request_id: header.request_id,
            object_id: federation_object_id(&encoded),
        };
        self.object(&encoded, |fragment| FederationFrame::Result {
            descriptor,
            fragment,
        })
        .await
    }

    /// Answers the origin exchange and FRESUME on a fresh link.
    async fn synchronize(&mut self) -> TestResult {
        self.expect_frame(|frame, _| matches!(frame, FederationFrame::OriginReset { .. }))
            .await?;
        self.expect_frame(|frame, _| matches!(frame, FederationFrame::OriginReady { .. }))
            .await?;
        let (frame, _) = self
            .expect_frame(|frame, _| matches!(frame, FederationFrame::Resume { .. }))
            .await?;
        let FederationFrame::Resume {
            projection_generation,
            ..
        } = frame
        else {
            return Err("expected FRESUME".into());
        };
        self.frame(FederationFrame::ResumeOk {
            edge_server_id: EDGE,
            projection_generation,
            next_delivery_sequence: self.next_sequence,
        })
        .await
    }

    /// Acknowledges an origin declaration.
    async fn ack_origin(&mut self) -> TestResult {
        let (frame, object) = self
            .expect_frame(|frame, object| {
                matches!(
                    frame,
                    FederationFrame::OriginAdd { .. } | FederationFrame::OriginUpdate { .. }
                ) && object.is_some()
            })
            .await?;
        let (FederationFrame::OriginAdd { descriptor, .. }
        | FederationFrame::OriginUpdate { descriptor, .. }) = frame
        else {
            return Err("expected an origin declaration".into());
        };
        let object = object.ok_or("origin without object")?;
        self.frame(FederationFrame::OriginAck {
            edge_server_id: EDGE,
            server_incarnation: descriptor.server_incarnation,
            origin_id: descriptor.origin_id,
            generation: descriptor.generation,
            object_id: Some(object.object_id()),
        })
        .await
    }
}

fn cloak(seed: u8) -> TestResult<PublicCloak> {
    Ok(agenc_ircd_testkit::deterministic_cloak(seed)?)
}

fn source(user_id: UserId, nickname: &str, seed: u8) -> TestResult<SourceView> {
    Ok(SourceView {
        user_id,
        nickname: NicknameValue::parse(nickname)?,
        public_cloak: cloak(seed)?,
        account_label: None,
    })
}

fn session_record(
    session_id: SessionId,
    user_id: UserId,
    nickname: &str,
    revision: u64,
    seed: u8,
) -> TestResult<SessionRecord> {
    Ok(SessionRecord {
        session_id,
        user_id,
        home_server_id: EDGE,
        session_revision: Revision::new(revision)?,
        account: None,
        nickname: NicknameValue::parse(nickname)?,
        display_name: DisplayNameValue::prepare("Real Name")?,
        public_cloak: cloak(seed)?,
        account_label: None,
        user_mode_bits: 1,
        away: None,
    })
}

async fn run_edge<Driver, Output>(
    driver: impl FnOnce(mpsc::Sender<FederationInbound>, mpsc::Sender<StateCoreMessage>) -> Driver,
) -> TestResult<Output>
where
    Driver: Future<Output = TestResult<Output>>,
{
    let mut fixture = StateCoreFixture::with_edge(entropy_script(), coordinator_identity())?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (federation, federation_receiver) = mpsc::channel(64);
    parts.state.install_federation_inbox(federation_receiver)?;
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let token = crate::cancel::CancellationToken::root();
    let driven = async move {
        let output = driver(federation, inbox).await;
        let _stopped = lifecycle.request(LifecyclePhase::Stop).await;
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
        return Err(format!("edge exited with {exit:?}").into());
    }
    output
}

/// One scripted client.
struct Client {
    generation: ConnectionGeneration,
    sink: std::sync::Arc<FrameSink>,
    inbox: mpsc::Sender<StateCoreMessage>,
    sequence: u64,
}

impl Client {
    async fn open(inbox: mpsc::Sender<StateCoreMessage>, number: u64) -> TestResult<Self> {
        let generation = ConnectionGeneration::new(number);
        let sink = FrameSink::new(generation, true);
        let (acknowledgement, accepted) = oneshot::channel();
        inbox
            .send(StateCoreMessage::Opened {
                generation,
                purpose: ListenerPurpose::ClientOnion,
                source: SourceAddressKey::onion_listener(),
                sink: std::sync::Arc::clone(&sink) as std::sync::Arc<dyn ClientSink>,
                acknowledgement,
            })
            .await
            .map_err(|_| "edge inbox closed")?;
        let _outcome = accepted.await?;
        Ok(Self {
            generation,
            sink,
            inbox,
            sequence: 0,
        })
    }

    async fn line(&mut self, line: &str) -> TestResult {
        self.sequence += 1;
        let message = parse_message(FramedLine::new(line)?)?.ok_or("empty line")?;
        self.inbox
            .send(StateCoreMessage::Line {
                generation: self.generation,
                sequence: self.sequence,
                message: Box::new(message),
            })
            .await
            .map_err(|_| "edge inbox closed")?;
        Ok(())
    }

    async fn wait_for_any(&self, needles: &[&str]) -> TestResult<Vec<String>> {
        for _ in 0..5_000 {
            let lines = self.sink.lines();
            if lines
                .iter()
                .any(|line| needles.iter().any(|needle| line.contains(needle)))
            {
                return Ok(lines);
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        Err(format!("client never received {needles:?}: {:?}", self.sink.lines()).into())
    }

    async fn wait_for(&self, needle: &str) -> TestResult<Vec<String>> {
        for _ in 0..5_000 {
            let lines = self.sink.lines();
            if lines.iter().any(|line| line.contains(needle)) {
                return Ok(lines);
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        Err(format!("client never received {needle:?}: {:?}", self.sink.lines()).into())
    }
}

#[tokio::test]
async fn edge_registers_joins_and_relays_names_through_the_coordinator() -> TestResult {
    run_edge(|federation, inbox| async move {
        let mut hub = Hub::new(federation);
        hub.establish().await?;
        hub.synchronize().await?;
        let mut client = Client::open(inbox, 1).await?;
        hub.ack_origin().await?;
        client.line("NICK quinn").await?;
        client.line("USER quinn 0 * :Quinn Real").await?;
        // The edge asks the coordinator for the session.
        let (header, operation, bytes) = hub.next_request().await?;
        let FederatedOperation::SessionOpen { nickname, .. } = &operation else {
            return Err("expected session_open".into());
        };
        assert_eq!(nickname, "quinn");
        let session_id = SessionId::from_bytes([61; 16]);
        let user_id = UserId::from_bytes([62; 16]);
        hub.state_generation += 1;
        let generation = hub.state_generation;
        let visible = hub
            .event(
                &ProjectedEvent::SessionVisible(SessionEventView {
                    source: source(user_id, "quinn", 1)?,
                    home_projection: Some(session_record(
                        session_id, user_id, "quinn", generation, 1,
                    )?),
                }),
                None,
            )
            .await?;
        let _ = visible;
        let completion = hub
            .event(
                &ProjectedEvent::RequestCompleted {
                    resulting_state_generation: generation,
                },
                Some(RequestCorrelation {
                    replay_key: header.replay_key,
                    request_id: header.request_id,
                }),
            )
            .await?;
        hub.result(
            &header,
            &bytes,
            &ResultArm::SessionRegistered(SessionRegistered {
                session_id,
                user_id,
                session_revision: generation,
                account: None,
                resulting_state_generation: generation,
            }),
            Vec::new(),
            Some(completion),
        )
        .await?;
        client.wait_for(" 001 quinn ").await?;
        // The origin now carries the session.
        hub.ack_origin().await?;
        // JOIN goes to the coordinator; the events render the JOIN echo and
        // the NAMES page follows from a directory query.
        client.line("JOIN #edge").await?;
        let (join_header, join_operation, join_bytes) = hub.next_request().await?;
        let FederatedOperation::Join { targets, .. } = &join_operation else {
            return Err("expected join".into());
        };
        assert_eq!(targets.len(), 1);
        let channel_id = ChannelInstanceId::from_bytes([63; 16]);
        hub.state_generation += 1;
        let generation = hub.state_generation;
        hub.event(
            &ProjectedEvent::ChannelVisible(ChannelDetailRecord {
                channel_id,
                name: ChannelNameValue::parse("#edge")?,
                channel_revision: Revision::new(generation)?,
                visibility: Visibility::Listed,
                content_policy: ContentPolicy::Plaintext,
                persistence: PersistencePolicy::Ephemeral,
                simple_mode_bits: 4,
                history: HistoryPolicy::Off,
                e2ee_route_binding: None,
            }),
            None,
        )
        .await?;
        hub.event(
            &ProjectedEvent::MemberJoined {
                view: MembershipView {
                    membership: MembershipRecord {
                        channel_id,
                        user_id,
                        role: Role::Owner,
                        membership_revision: Revision::new(generation)?,
                        joined_at: UtcSecond::from_unix_seconds(5),
                    },
                    source: source(user_id, "quinn", 1)?,
                },
                home_session_revision: Some(Revision::new(generation)?),
                display_name: DisplayNameValue::prepare("Quinn Real")?,
            },
            None,
        )
        .await?;
        let completion = hub
            .event(
                &ProjectedEvent::RequestCompleted {
                    resulting_state_generation: generation,
                },
                Some(RequestCorrelation {
                    replay_key: join_header.replay_key,
                    request_id: join_header.request_id,
                }),
            )
            .await?;
        hub.result(
            &join_header,
            &join_bytes,
            &ResultArm::Committed {
                resulting_state_generation: generation,
            },
            Vec::new(),
            Some(completion),
        )
        .await?;
        client.wait_for(" JOIN #edge").await?;
        let (names_header, names_operation, names_bytes) = hub.next_request().await?;
        assert!(matches!(
            names_operation,
            FederatedOperation::DirectoryQuery { .. }
        ));
        let replies = vec![
            agenc_ircd_client_wire::numeric_reply(
                COORDINATOR_NAME,
                353,
                "quinn",
                &["=", "#edge"],
                Some("~quinn"),
            )?,
            agenc_ircd_client_wire::numeric_reply(
                COORDINATOR_NAME,
                366,
                "quinn",
                &["#edge"],
                Some("End of NAMES list"),
            )?,
        ];
        hub.result(
            &names_header,
            &names_bytes,
            &ResultArm::ReplyPage {
                snapshot_token: [3; 32],
                page_sequence: 0,
                next_cursor: None,
            },
            replies,
            None,
        )
        .await?;
        let lines = client.wait_for(" 366 quinn #edge ").await?;
        assert!(
            lines
                .iter()
                .any(|line| line.contains(" 353 quinn = #edge :~quinn"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with(":edge.example 353")),
            "{lines:?}"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn global_commands_fail_closed_while_the_link_is_down() -> TestResult {
    run_edge(|federation, inbox| async move {
        let mut hub = Hub::new(federation);
        hub.establish().await?;
        hub.synchronize().await?;
        let mut client = Client::open(inbox, 1).await?;
        hub.ack_origin().await?;
        client.line("NICK rosa").await?;
        client.line("USER rosa 0 * :Rosa Real").await?;
        let (header, _, bytes) = hub.next_request().await?;
        let session_id = SessionId::from_bytes([71; 16]);
        let user_id = UserId::from_bytes([72; 16]);
        hub.state_generation += 1;
        let generation = hub.state_generation;
        hub.event(
            &ProjectedEvent::SessionVisible(SessionEventView {
                source: source(user_id, "rosa", 2)?,
                home_projection: Some(session_record(session_id, user_id, "rosa", generation, 2)?),
            }),
            None,
        )
        .await?;
        let completion = hub
            .event(
                &ProjectedEvent::RequestCompleted {
                    resulting_state_generation: generation,
                },
                Some(RequestCorrelation {
                    replay_key: header.replay_key,
                    request_id: header.request_id,
                }),
            )
            .await?;
        hub.result(
            &header,
            &bytes,
            &ResultArm::SessionRegistered(SessionRegistered {
                session_id,
                user_id,
                session_revision: generation,
                account: None,
                resulting_state_generation: generation,
            }),
            Vec::new(),
            Some(completion),
        )
        .await?;
        client.wait_for(" 001 rosa ").await?;
        hub.ack_origin().await?;
        // The coordinator link drops; global work fails closed, PING works.
        hub.send(LinkEvent::Closed(
            crate::federation::LinkCloseReason::PeerClosed,
        ))
        .await?;
        client.line("PRIVMSG #edge :anyone").await?;
        let lines = client.wait_for("FAIL PRIVMSG NETWORK_UNAVAILABLE").await?;
        assert!(
            lines
                .iter()
                .any(|line| line.contains("NETWORK_UNAVAILABLE"))
        );
        client.line("PING :still-here").await?;
        client.wait_for("PONG").await?;
        Ok(())
    })
    .await
}

/// Pumps rendered lines from one side's link queue into the other side's
/// inbox exactly as the link task would, assembling objects on the way.
async fn pump(
    mut queue: LinkQueue,
    expected_prefix: &str,
    inbox: mpsc::Sender<FederationInbound>,
    link: LinkId,
    peer: ServerId,
) {
    let mut assembler = FragmentAssembler::new();
    while let Some(line) = queue.recv().await {
        let text = line.as_str().trim_end_matches("\r\n").to_owned();
        let Ok(frame) = parse_frame(&text, expected_prefix) else {
            break;
        };
        let event = match frame.fragment() {
            Some(fragment) => {
                let Ok((carrier, key)) = carrier_of(&frame) else {
                    break;
                };
                match assembler.admit(key, fragment, 0) {
                    Ok(AssemblyProgress::Complete(object)) => LinkEvent::Object { carrier, object },
                    Ok(AssemblyProgress::Incomplete { .. }) => continue,
                    Err(_) => break,
                }
            }
            None => LinkEvent::Frame(frame),
        };
        if inbox
            .send(FederationInbound {
                link,
                peer,
                event,
                charge: None,
            })
            .await
            .is_err()
        {
            break;
        }
    }
    let _closed = inbox
        .send(FederationInbound {
            link,
            peer,
            event: LinkEvent::Closed(crate::federation::LinkCloseReason::PeerClosed),
            charge: None,
        })
        .await;
}

/// A running state owner with its inboxes.
struct Node {
    federation: mpsc::Sender<FederationInbound>,
    inbox: mpsc::Sender<StateCoreMessage>,
    lifecycle: crate::state_core::inbox::LifecycleControl,
}

fn start_node(
    fixture: &mut StateCoreFixture,
) -> TestResult<(Node, impl Future<Output = StateCoreExit> + use<>)> {
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (federation, federation_receiver) = mpsc::channel(64);
    parts.state.install_federation_inbox(federation_receiver)?;
    let (close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let token = crate::cancel::CancellationToken::root();
    let run = async move {
        let _keep = close_port;
        parts
            .state
            .run(
                inbox_receiver,
                close_inbox,
                lifecycle_receiver,
                parts.storage,
                parts.storage_reads,
                parts.checkpoints,
                parts.crypto,
                token,
            )
            .await
    };
    Ok((
        Node {
            federation,
            inbox,
            lifecycle,
        },
        run,
    ))
}

fn hub_identity() -> PeerIdentity {
    PeerIdentity::new(
        HUB,
        HUB_NAME,
        FederationRole::Coordinator,
        HUB_EPOCH,
        agenc_ircd_crypto::Ed25519SecretKey::from_bytes([16; 32]).public_key(),
        [17; 32],
    )
}

fn edge_identity() -> PeerIdentity {
    PeerIdentity::new(
        EDGE,
        EDGE_NAME,
        FederationRole::Edge,
        RecoveryEpoch::from_bytes([0; 16]),
        agenc_ircd_crypto::Ed25519SecretKey::from_bytes([14; 32]).public_key(),
        [15; 32],
    )
}

/// Registers a fresh connection once the edge reports the network as
/// available; the link synchronizes concurrently with the first client.
async fn register_when_available(
    inbox: &mpsc::Sender<StateCoreMessage>,
    first_number: u64,
    nickname: &str,
    capabilities: Option<&str>,
) -> TestResult<Client> {
    let mut number = first_number;
    for _ in 0..50 {
        let mut client = Client::open(inbox.clone(), number).await?;
        if let Some(capabilities) = capabilities {
            client.line("CAP LS 302").await?;
            client.line(&format!("CAP REQ :{capabilities}")).await?;
        }
        client.line(&format!("NICK {nickname}")).await?;
        client
            .line(&format!("USER {nickname} 0 * :{nickname} Real"))
            .await?;
        if capabilities.is_some() {
            client.line("CAP END").await?;
        }
        for _ in 0..500 {
            let lines = client.sink.lines();
            if lines.iter().any(|line| line.contains(" 001 ")) {
                return Ok(client);
            }
            if lines
                .iter()
                .any(|line| line.contains("NETWORK_UNAVAILABLE"))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        number = number.saturating_add(100);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err("the edge never reported the network as available".into())
}

async fn register(client: &mut Client, nickname: &str) -> TestResult {
    client.line(&format!("NICK {nickname}")).await?;
    client
        .line(&format!("USER {nickname} 0 * :{nickname} Real"))
        .await?;
    client.wait_for(&format!(" 001 {nickname} ")).await?;
    Ok(())
}

#[tokio::test]
async fn edge_and_coordinator_interoperate_over_a_bridged_link() -> TestResult {
    let mut coordinator_fixture =
        StateCoreFixture::with_federation_coordinator(entropy_script(), vec![edge_identity()])?;
    let mut edge_fixture = StateCoreFixture::with_edge(entropy_script(), hub_identity())?;
    let (hub, hub_run) = start_node(&mut coordinator_fixture)?;
    let (edge, edge_run) = start_node(&mut edge_fixture)?;
    let hub_task = tokio::spawn(hub_run);
    let edge_task = tokio::spawn(edge_run);
    let hub_lifecycle = hub.lifecycle.clone();
    let edge_lifecycle = edge.lifecycle.clone();
    // The coordinator serves no clients here; its inbox stays open until stop.
    let _hub_inbox = hub.inbox.clone();
    let outcome = drive_bridge(hub, edge).await;
    let _stop_edge = edge_lifecycle.request(LifecyclePhase::Stop).await;
    let _stop_hub = hub_lifecycle.request(LifecyclePhase::Stop).await;
    let hub_exit = tokio::time::timeout(std::time::Duration::from_secs(10), hub_task).await??;
    let edge_exit = tokio::time::timeout(std::time::Duration::from_secs(10), edge_task).await??;
    outcome?;
    assert!(matches!(hub_exit, StateCoreExit::Stopped), "{hub_exit:?}");
    assert!(matches!(edge_exit, StateCoreExit::Stopped), "{edge_exit:?}");
    Ok(())
}

/// Establishes the bridged link and exercises two clients on the edge.
async fn drive_bridge(hub: Node, edge: Node) -> TestResult {
    let (to_edge_handle, to_edge_queue) = link_queue(1 << 20);
    let (to_hub_handle, to_hub_queue) = link_queue(1 << 20);
    let hub_link = LinkId::new(1);
    let edge_link = LinkId::new(2);
    hub.federation
        .send(FederationInbound {
            link: hub_link,
            peer: EDGE,
            event: LinkEvent::Established {
                session: LinkSession {
                    link: hub_link,
                    peer: EDGE,
                    peer_incarnation: EDGE_INCARNATION,
                    peer_recovery_epoch: RecoveryEpoch::from_bytes([0; 16]),
                    transition: agenc_ircd_federation_wire::EpochTransition::Initial,
                },
                handle: to_edge_handle,
            },
            charge: None,
        })
        .await
        .map_err(|_| "hub inbox closed")?;
    edge.federation
        .send(FederationInbound {
            link: edge_link,
            peer: HUB,
            event: LinkEvent::Established {
                session: LinkSession {
                    link: edge_link,
                    peer: HUB,
                    peer_incarnation: HUB_INCARNATION,
                    peer_recovery_epoch: HUB_EPOCH,
                    transition: agenc_ircd_federation_wire::EpochTransition::Initial,
                },
                handle: to_hub_handle,
            },
            charge: None,
        })
        .await
        .map_err(|_| "edge inbox closed")?;
    let pumps = tokio::spawn(async move {
        tokio::join!(
            pump(to_edge_queue, HUB_NAME, edge.federation, edge_link, HUB),
            pump(to_hub_queue, EDGE_NAME, hub.federation, hub_link, EDGE),
        );
    });
    let outcome = exchange_over_bridge(edge.inbox).await;
    pumps.abort();
    outcome
}

/// Registers two clients on the edge and relays a channel conversation.
async fn exchange_over_bridge(inbox: mpsc::Sender<StateCoreMessage>) -> TestResult {
    let mut sam = register_when_available(
        &inbox,
        1,
        "sam",
        Some("away-notify setname extended-join account-notify"),
    )
    .await?;
    let mut tess = Client::open(inbox, 2).await?;
    register(&mut tess, "tess").await?;
    sam.line("JOIN #bridge").await?;
    sam.wait_for(" JOIN #bridge").await?;
    sam.wait_for(" 366 sam #bridge ").await?;
    tess.line("JOIN #bridge").await?;
    let lines = sam.wait_for(":tess!").await?;
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with(":tess!") && line.contains(" JOIN #bridge")),
        "{lines:?}"
    );
    tess.line("PRIVMSG #bridge :hello sam").await?;
    let lines = sam.wait_for("PRIVMSG #bridge :hello sam").await?;
    assert!(lines.iter().any(|line| line.starts_with(":tess!")));
    assert!(
        !tess
            .sink
            .lines()
            .iter()
            .any(|line| line.contains("PRIVMSG #bridge :hello sam")),
        "no echo without echo-message"
    );
    tess.line("PART #bridge :done").await?;
    sam.wait_for(" PART #bridge :done").await?;
    exchange_more_over_bridge(&mut sam, &mut tess).await
}

/// Topic, mode, invite, away, setname, nick, and quit traffic between the
/// two clients, with the recipient holding the capabilities that render the
/// optional lines.
async fn exchange_more_over_bridge(sam: &mut Client, tess: &mut Client) -> TestResult {
    sam.line("TOPIC #bridge :bridged topic").await?;
    sam.wait_for("TOPIC #bridge :bridged topic").await?;
    sam.line("MODE #bridge +m").await?;
    sam.wait_for("MODE #bridge +m").await?;
    sam.line("INVITE tess #bridge").await?;
    let lines = sam
        .wait_for_any(&[
            " 341 ",
            "FAIL INVITE",
            " 401 ",
            " 442 ",
            " 443 ",
            " 482 ",
            " 481 ",
        ])
        .await?;
    assert!(
        lines
            .iter()
            .any(|line| line.contains(" 341 sam tess #bridge")),
        "{lines:?}"
    );
    tess.wait_for("INVITE tess").await?;
    tess.line("JOIN #bridge").await?;
    tess.wait_for(" 366 tess #bridge ").await?;
    sam.wait_for(":tess!").await?;
    tess.line("AWAY :back later").await?;
    sam.wait_for("AWAY :back later").await?;
    tess.line("SETNAME :Tess Renamed").await?;
    sam.wait_for("SETNAME :Tess Renamed").await?;
    tess.line("NICK tessa").await?;
    sam.wait_for("NICK :tessa").await?;
    sam.line("MODE #bridge -m").await?;
    sam.wait_for("MODE #bridge -m").await?;
    tess.line("PRIVMSG sam :direct hello").await?;
    let lines = sam.wait_for("PRIVMSG sam :direct hello").await?;
    assert!(lines.iter().any(|line| line.starts_with(":tessa!")));
    // The in-process harness has no connection task, so a client QUIT
    // never reaches the router as a closed connection; the three-process
    // daemon test covers the QUIT relay.
    Ok(())
}

#[tokio::test]
async fn a_closed_queue_retires_the_link_without_a_violation() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut edge = EdgeFederation::new(EdgeConfig {
        network_id: NETWORK,
        server_id: EDGE,
        server_name: EDGE_NAME.to_owned(),
        incarnation: EDGE_INCARNATION,
        coordinator: coordinator_identity(),
    });
    // The link task is already gone when the edge writes its FORIGIN RESET.
    let (handle, queue) = link_queue(1 << 20);
    drop(queue);
    let link = LinkId::new(7);
    let session = LinkSession {
        link,
        peer: COORDINATOR,
        peer_incarnation: ServerIncarnation::from_bytes([92; 16]),
        peer_recovery_epoch: COORDINATOR_EPOCH,
        transition: agenc_ircd_federation_wire::EpochTransition::Initial,
    };
    edge.inbound(
        context,
        FederationInbound {
            link,
            peer: COORDINATOR,
            event: LinkEvent::Established { session, handle },
            charge: None,
        },
    );
    assert_eq!(edge.counters().violations, 0);
    assert!(edge.live.is_none(), "the dead link is retired at once");
    assert_eq!(edge.phase, Phase::Down);
    Ok(())
}

#[tokio::test]
async fn a_barrier_part_is_staged_and_an_ordinary_event_behind_it_is_fatal() -> TestResult {
    run_edge(|federation, inbox| async move {
        // The client inbox stays open for the whole exchange.
        let _clients = inbox;
        let mut hub = Hub::new(federation);
        hub.establish().await?;
        hub.synchronize().await?;
        hub.state_generation += 1;
        let generation = hub.state_generation;
        let tuple = agenc_ircd_federation_wire::CrossProfilePart {
            mutation_id: [7; 16],
            part_index: 0,
            part_count: 3,
        };
        let hidden = ProjectedEvent::ChannelHidden {
            channel_id: ChannelInstanceId::from_bytes([14; 16]),
            last_revision: Revision::new(generation)?,
        };
        hub.barrier_part(&hidden, tuple).await?;
        // A second part of the same barrier is staged too; still no FACK.
        hub.barrier_part(
            &hidden,
            agenc_ircd_federation_wire::CrossProfilePart {
                part_index: 1,
                ..tuple
            },
        )
        .await?;
        // An ordinary event before the barrier finishes closes the link.
        let sequence = hub.next_sequence;
        hub.next_sequence += 1;
        let event_id = EventId::from_bytes([u8::try_from(sequence)? + 40; 16]);
        let completed = ProjectedEvent::ChannelHidden {
            channel_id: ChannelInstanceId::from_bytes([15; 16]),
            last_revision: Revision::new(generation)?,
        };
        let header = EventHeader {
            network_id: NETWORK,
            target_server_id: EDGE,
            projection_generation: 1,
            coordinator_state_generation: generation,
            delivery_sequence: sequence,
            event_id,
            event_kind: completed.kind(),
            correlation: None,
            cross_profile: None,
        };
        let arm = event_arm_object(&completed).map_err(|error| format!("event arm: {error:?}"))?;
        let encoded = header
            .build(&arm)
            .map_err(|error| format!("event header: {error:?}"))?
            .encode_canonical()
            .map_err(|error| format!("event encode: {error:?}"))?
            .as_slice()
            .to_vec();
        let descriptor = agenc_ircd_federation_wire::EventDescriptor {
            target_server_id: EDGE,
            delivery_sequence: sequence,
            event_id,
            object_id: federation_object_id(&encoded),
        };
        hub.object(&encoded, |fragment| FederationFrame::Event {
            descriptor,
            fragment,
        })
        .await?;
        hub.expect_closed().await
    })
    .await
}

// ---------------------------------------------------------------------------
// Edge E2EE router (Stage 08 slice 14).
// ---------------------------------------------------------------------------

mod e2ee {
    use super::*;
    use agenc_ircd_e2ee::federation::frames::{CompanionFrame, Correlation};
    use agenc_ircd_e2ee::ids::federation_snapshot_digest;
    use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
    use agenc_ircd_e2ee::objects::federation::{
        IrcFederationOpcode, IrcFederationRequest, IrcFederationResult, IrcFederationResultKind,
    };
    use agenc_ircd_e2ee::tls::{Opaque, TlsDecode, TlsEncode, TlsVec, Writer};
    use agenc_ircd_e2ee::wire::fragment::{FragmentTag, fragment_object};
    use agenc_ircd_types::AccountId;
    use std::collections::VecDeque;

    use crate::federation::link::{ParsedLine, parse_line};

    const SNAPSHOT_TOKEN: [u8; 32] = [77; 32];
    const STATE_GENERATION: u64 = 1;

    /// The companion profile both ends offer: the coordinator's identity and
    /// a one-credential sequencer key set.
    fn companion_profile() -> TestResult<crate::e2ee::link::CompanionProfile> {
        use crate::e2ee::coordinator::tests::support::{key, sequencer_credential_in};
        use agenc_ircd_e2ee::profile::EcapTuple;
        use agenc_ircd_e2ee::sequencer::SequencerKeySet;
        use agenc_ircd_e2ee::wire::tokens::base64url_encode;
        let network = *NETWORK.as_bytes();
        let sequencer = key(90);
        let credential = sequencer_credential_in(network, &sequencer, 0, (0, 4_000_000_000), None)?;
        let key_set =
            SequencerKeySet::verify(&network, std::slice::from_ref(&credential), 0, None)?;
        let tuple = EcapTuple::local(
            &base64url_encode(&network),
            &base64url_encode(COORDINATOR.as_bytes()),
            key_set.set_generation,
            &base64url_encode(&key_set.digest),
        )?;
        Ok(crate::e2ee::link::CompanionProfile { local: tuple })
    }

    /// Runs an E2EE-enabled edge under `driver`.
    async fn run_e2ee_edge<Driver, Output>(
        driver: impl FnOnce(mpsc::Sender<FederationInbound>, mpsc::Sender<StateCoreMessage>) -> Driver,
    ) -> TestResult<Output>
    where
        Driver: Future<Output = TestResult<Output>>,
    {
        let mut fixture = StateCoreFixture::with_e2ee_edge(
            entropy_script(),
            coordinator_identity(),
            companion_profile()?,
        )?;
        let mut parts = fixture.take_run_parts()?;
        let (inbox, inbox_receiver) = mpsc::channel(8);
        let (federation, federation_receiver) = mpsc::channel(64);
        parts.state.install_federation_inbox(federation_receiver)?;
        let (_close_port, close_inbox) = connection_close_channel();
        let (lifecycle, lifecycle_receiver) = lifecycle_channel();
        let token = crate::cancel::CancellationToken::root();
        let driven = async move {
            let output = driver(federation, inbox).await;
            let _stopped = lifecycle.request(LifecyclePhase::Stop).await;
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
            return Err(format!("edge exited with {exit:?}").into());
        }
        output
    }

    /// The scripted coordinator over both profiles: base frames and
    /// companion frames share one link, so each reader keeps the other
    /// kind in a backlog.
    struct CompanionHub {
        base: Hub,
        base_backlog: VecDeque<FederationFrame>,
        companion_backlog: VecDeque<CompanionFrame>,
        assembling: Vec<FragmentTag>,
    }

    impl CompanionHub {
        fn new(inbox: mpsc::Sender<FederationInbound>) -> Self {
            Self {
                base: Hub::new(inbox),
                base_backlog: VecDeque::new(),
                companion_backlog: VecDeque::new(),
                assembling: Vec::new(),
            }
        }

        async fn next_line(&mut self) -> TestResult<ParsedLine> {
            let line =
                tokio::time::timeout(std::time::Duration::from_secs(20), self.base.queue.recv())
                    .await
                    .map_err(|_| "no line from the edge")?
                    .ok_or("edge closed the link")?;
            let text = line.as_str().trim_end_matches("\r\n").to_owned();
            Ok(parse_line(&text, EDGE_NAME).map_err(|error| format!("{error:?}: {text}"))?)
        }

        /// The next base frame, keeping companion lines for later.
        async fn next_base(&mut self) -> TestResult<FederationFrame> {
            if let Some(frame) = self.base_backlog.pop_front() {
                return Ok(frame);
            }
            loop {
                match self.next_line().await? {
                    ParsedLine::Base(frame) => return Ok(frame),
                    ParsedLine::Companion(frame) => self.companion_backlog.push_back(frame),
                }
            }
        }

        /// The next companion frame, keeping base lines for later.
        async fn next_companion(&mut self) -> TestResult<CompanionFrame> {
            if let Some(frame) = self.companion_backlog.pop_front() {
                return Ok(frame);
            }
            loop {
                match self.next_line().await? {
                    ParsedLine::Companion(frame) => return Ok(frame),
                    ParsedLine::Base(frame) => self.base_backlog.push_back(frame),
                }
            }
        }

        /// Reads base frames until one satisfies `accept`, assembling objects.
        async fn expect_base(
            &mut self,
            accept: impl Fn(&FederationFrame, Option<&AssembledObject>) -> bool,
        ) -> TestResult<(FederationFrame, Option<AssembledObject>)> {
            for _ in 0..512 {
                let frame = self.next_base().await?;
                let object = match frame.fragment() {
                    Some(fragment) => {
                        let (_, key) = carrier_of(&frame).map_err(|error| error.to_string())?;
                        match self.base.assembler.admit(key, fragment, 0)? {
                            AssemblyProgress::Complete(object) => Some(object),
                            AssemblyProgress::Incomplete { .. } => continue,
                        }
                    }
                    None => None,
                };
                if accept(&frame, object.as_ref()) {
                    return Ok((frame, object));
                }
            }
            Err("the edge never sent the expected base frame".into())
        }

        async fn companion(&self, frame: CompanionFrame) -> TestResult {
            self.base.send(LinkEvent::Companion(frame)).await
        }

        async fn companion_object(
            &mut self,
            bytes: &[u8],
            frame: impl Fn(FragmentTag) -> CompanionFrame,
        ) -> TestResult {
            for fragment in fragment_object(bytes)? {
                self.companion(frame(fragment)).await?;
            }
            Ok(())
        }

        /// Answers the edge's ECAP OFFER with the coordinator's OFFER and
        /// ACK and consumes the edge's ACK.
        async fn negotiate(&mut self) -> TestResult {
            let CompanionFrame::EcapOffer(tuple) = self.next_companion().await? else {
                return Err("expected ECAP OFFER".into());
            };
            self.companion(CompanionFrame::EcapOffer(tuple.clone()))
                .await?;
            self.companion(CompanionFrame::EcapAck(tuple)).await?;
            match self.next_companion().await? {
                CompanionFrame::EcapAck(_) => Ok(()),
                other => Err(format!("expected ECAP ACK, got {}", other.command()).into()),
            }
        }

        /// Synchronizes the base profile the way `Hub::synchronize` does,
        /// through the companion-aware reader.
        async fn synchronize_base(&mut self) -> TestResult {
            self.expect_base(|frame, _| matches!(frame, FederationFrame::OriginReset { .. }))
                .await?;
            self.expect_base(|frame, _| matches!(frame, FederationFrame::OriginReady { .. }))
                .await?;
            let (frame, _) = self
                .expect_base(|frame, _| matches!(frame, FederationFrame::Resume { .. }))
                .await?;
            let FederationFrame::Resume {
                projection_generation,
                ..
            } = frame
            else {
                return Err("expected FRESUME".into());
            };
            self.base
                .frame(FederationFrame::ResumeOk {
                    edge_server_id: EDGE,
                    projection_generation,
                    next_delivery_sequence: self.base.next_sequence,
                })
                .await
        }

        /// Waits for the edge's ERESUME on a fresh scope.
        async fn expect_resume(&mut self) -> TestResult {
            match self.next_companion().await? {
                CompanionFrame::Resume {
                    delivery_generation: 0,
                    last: None,
                    ..
                } => Ok(()),
                other => Err(format!("expected ERESUME, got {}", other.command()).into()),
            }
        }

        /// Transfers the empty state, activates it, and answers the origin
        /// reset.
        async fn activate(&mut self) -> TestResult {
            let digest = federation_snapshot_digest(STATE_GENERATION, 0, &[])?;
            let edge = *EDGE.as_bytes();
            self.companion(CompanionFrame::StateBegin {
                target_server_id: edge,
                snapshot_token: SNAPSHOT_TOKEN,
                state_generation: STATE_GENERATION,
                delivery_generation: 0,
                page_sequence: 0,
                total_entry_count: 0,
                page_entry_count: 0,
                snapshot_digest: digest,
            })
            .await?;
            self.companion(CompanionFrame::StateEnd {
                target_server_id: edge,
                snapshot_token: SNAPSHOT_TOKEN,
                page_sequence: 0,
                next_cursor: None,
            })
            .await?;
            match self.next_companion().await? {
                CompanionFrame::StateCut { active: false, .. } => {}
                other => {
                    return Err(format!("expected ESTATE READY, got {}", other.command()).into());
                }
            }
            self.companion(CompanionFrame::StateCut {
                active: true,
                server_id: *COORDINATOR.as_bytes(),
                snapshot_token: SNAPSHOT_TOKEN,
                state_generation: STATE_GENERATION,
                delivery_generation: 0,
                snapshot_digest: digest,
            })
            .await?;
            match self.next_companion().await? {
                CompanionFrame::OriginReset { .. } => {}
                other => {
                    return Err(format!("expected EORIGIN RESET, got {}", other.command()).into());
                }
            }
            self.companion(CompanionFrame::OriginReady {
                home_server_id: edge,
                server_incarnation: *EDGE_INCARNATION.as_bytes(),
            })
            .await
        }

        /// Acknowledges one companion origin declaration and returns the
        /// origin it declared.
        async fn ack_companion_origin(&mut self) -> TestResult<[u8; 16]> {
            loop {
                match self.next_companion().await? {
                    CompanionFrame::OriginState {
                        origin_id,
                        origin_generation,
                        object_id,
                        fragment,
                        ..
                    } => {
                        if fragment.part.saturating_add(1) < fragment.count {
                            continue;
                        }
                        self.companion(CompanionFrame::OriginAck {
                            home_server_id: *EDGE.as_bytes(),
                            server_incarnation: *EDGE_INCARNATION.as_bytes(),
                            origin_id,
                            origin_generation,
                            object_id: Some(object_id),
                        })
                        .await?;
                        return Ok(origin_id);
                    }
                    other => {
                        return Err(format!("expected EORIGIN ADD, got {}", other.command()).into());
                    }
                }
            }
        }

        /// Assembles the next EREQUEST and decodes it.
        async fn next_request(
            &mut self,
        ) -> TestResult<(Correlation, IrcFederationRequest, [u8; 32])> {
            loop {
                let CompanionFrame::Request {
                    correlation,
                    object_id,
                    fragment,
                } = self.next_companion().await?
                else {
                    return Err("expected EREQUEST".into());
                };
                let count = fragment.count;
                self.assembling.push(fragment);
                if self.assembling.len() < count as usize {
                    continue;
                }
                let mut parts = std::mem::take(&mut self.assembling);
                parts.sort_by_key(|part| part.part);
                let bytes: Vec<u8> = parts.into_iter().flat_map(|part| part.segment).collect();
                let mut budget = agenc_ircd_e2ee::tls::DecodeBudget::new(1 << 16, 1_024);
                let object = IrcWireObject::decode_kind(
                    &bytes,
                    Some(IrcWireObjectKind::FederationRequest),
                    &mut budget,
                )?;
                let request = IrcFederationRequest::decode_exact(object.body(), &mut budget)?;
                return Ok((correlation, request, object_id));
            }
        }

        /// Answers `request` with an `Account` result.
        async fn account_result(
            &mut self,
            correlation: Correlation,
            request_object_id: [u8; 32],
            account: &AccountId,
        ) -> TestResult {
            let mut writer = Writer::new();
            writer.opaque(account.to_text().as_bytes(), 1, 255)?;
            writer.u64(3)?;
            let result = IrcFederationResult {
                profile_version: 1,
                network_id: *NETWORK.as_bytes(),
                home_server_id: *EDGE.as_bytes(),
                server_incarnation: correlation.server_incarnation,
                origin_id: correlation.origin_id,
                origin_generation: correlation.origin_generation,
                operation_sequence: correlation.operation_sequence,
                request_id: correlation.request_id,
                request_object_id,
                coordinator_state_generation: STATE_GENERATION,
                completion_event_id: Opaque::new(Vec::new())?,
                result_kind: IrcFederationResultKind::Account,
                encoded_result: Opaque::new(writer.into_bytes())?,
                snapshot_token: Opaque::new(Vec::new())?,
                next_cursor: Opaque::new(Vec::new())?,
                responses: TlsVec::new(Vec::new())?,
            };
            let bytes = IrcWireObject::new(IrcWireObjectKind::FederationResult, result.encode()?)?
                .encode()?;
            let object_id = *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes();
            self.companion_object(&bytes, |fragment| CompanionFrame::Result {
                correlation,
                object_id,
                fragment,
            })
            .await
        }

        /// Registers `client` as `nickname` with an authenticated session.
        async fn register(
            &mut self,
            client: &mut Client,
            nickname: &str,
            account: AccountId,
        ) -> TestResult<UserId> {
            client.line("CAP LS 302").await?;
            client
                .line(
                    "CAP REQ :message-tags echo-message batch labeled-response standard-replies account-tag agenc.ag/e2ee-mls",
                )
                .await?;
            client.line(&format!("NICK {nickname}")).await?;
            client
                .line(&format!("USER {nickname} 0 * :{nickname} Real"))
                .await?;
            client.line("CAP END").await?;
            let (_, object) = self
                .expect_base(|frame, object| {
                    matches!(frame, FederationFrame::Request { .. }) && object.is_some()
                })
                .await?;
            let object = object.ok_or("request without object")?;
            let mut budget = DecodeBudget::new(1 << 20, 4_096);
            let request =
                SchemaObject::decode_exact("FederationRequest", object.as_slice(), &mut budget)?;
            let header = RequestHeader::from_object(&request)?;
            let bytes = object.as_slice().to_vec();
            let session_id = SessionId::from_bytes([61; 16]);
            let user_id = UserId::from_bytes([62; 16]);
            self.base.state_generation += 1;
            let generation = self.base.state_generation;
            let mut record = session_record(session_id, user_id, nickname, generation, 1)?;
            record.account = Some((account, agenc_ircd_types::Generation::new(1)?));
            self.base
                .event(
                    &ProjectedEvent::SessionVisible(SessionEventView {
                        source: source(user_id, nickname, 1)?,
                        home_projection: Some(record),
                    }),
                    None,
                )
                .await?;
            let completion = self
                .base
                .event(
                    &ProjectedEvent::RequestCompleted {
                        resulting_state_generation: generation,
                    },
                    Some(RequestCorrelation {
                        replay_key: header.replay_key,
                        request_id: header.request_id,
                    }),
                )
                .await?;
            self.base
                .result(
                    &header,
                    &bytes,
                    &ResultArm::SessionRegistered(SessionRegistered {
                        session_id,
                        user_id,
                        session_revision: generation,
                        account: None,
                        resulting_state_generation: generation,
                    }),
                    Vec::new(),
                    Some(completion),
                )
                .await?;
            client.wait_for(&format!(" 001 {nickname} ")).await?;
            Ok(user_id)
        }

        /// Acknowledges the base origin declaration through the
        /// companion-aware reader.
        async fn ack_base_origin(&mut self) -> TestResult {
            let (frame, object) = self
                .expect_base(|frame, object| {
                    matches!(
                        frame,
                        FederationFrame::OriginAdd { .. } | FederationFrame::OriginUpdate { .. }
                    ) && object.is_some()
                })
                .await?;
            let (FederationFrame::OriginAdd { descriptor, .. }
            | FederationFrame::OriginUpdate { descriptor, .. }) = frame
            else {
                return Err("expected an origin declaration".into());
            };
            let object = object.ok_or("origin without object")?;
            self.base
                .frame(FederationFrame::OriginAck {
                    edge_server_id: EDGE,
                    server_incarnation: descriptor.server_incarnation,
                    origin_id: descriptor.origin_id,
                    generation: descriptor.generation,
                    object_id: Some(object.object_id()),
                })
                .await
        }
    }

    #[tokio::test]
    async fn e2ee_lines_wait_for_the_companion_state_and_then_reach_the_coordinator() -> TestResult
    {
        run_e2ee_edge(|federation, inbox| async move {
            let mut hub = CompanionHub::new(federation);
            hub.base.establish().await?;
            hub.synchronize_base().await?;
            hub.negotiate().await?;
            hub.expect_resume().await?;

            // A registered client with the capability is refused while the
            // companion state is still transferring.
            let account = AccountId::parse("a_AAAAAAAAAAAAAAAAAAAAAA")?;
            let mut client = Client::open(inbox, 1).await?;
            hub.register(&mut client, "quinn", account).await?;
            hub.ack_base_origin().await?;
            client.line("@label=one EKEY WHOAMI").await?;
            let lines = client.wait_for("E2EE_SYNCING").await?;
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("FAIL EKEY E2EE_SYNCING"))
            );

            // The empty state activates, the origin mirrors, and the same
            // line becomes a companion request the coordinator answers.
            hub.activate().await?;
            let origin_id = hub.ack_companion_origin().await?;
            client.line("@label=two EKEY WHOAMI").await?;
            let (correlation, request, request_object_id) = hub.next_request().await?;
            assert_eq!(request.opcode, IrcFederationOpcode::Whoami);
            assert_eq!(request.origin_id, origin_id);
            assert_eq!(correlation.origin_id, origin_id);
            hub.account_result(correlation, request_object_id, &account)
                .await?;
            let lines = client.wait_for("label=two").await?;
            let answer = lines
                .iter()
                .find(|line| line.contains("label=two"))
                .ok_or("no labeled answer")?;
            assert!(answer.contains("EKEY"), "{answer}");
            let token =
                agenc_ircd_e2ee::wire::tokens::base64url_encode(account.to_text().as_bytes());
            assert!(
                answer.contains(&format!("EKEY ACCOUNT {token} 3")),
                "{answer}"
            );

            // A plaintext line to an unbound channel is not the router's
            // business: the base path answers it without an E2EE refusal.
            client.line("PRIVMSG #edge :hello").await?;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let lines = client.sink.lines();
            assert!(lines.iter().all(|line| !line.contains("E2EE_REQUIRED")));
            Ok(())
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// Remote account carriers (spec 22.2).
// ---------------------------------------------------------------------------

mod accounts {
    use super::*;
    use agenc_ircd_client_wire::{AUTH_CHUNK_CHARACTERS, encode_sasl_payload};
    use agenc_ircd_federation_wire::WireValue;
    use agenc_ircd_types::{AccountId, FederationOpcode};

    /// A schema-valid sealed response: the header names the challenge kind
    /// and the ciphertext has its exact length.
    fn challenge_response() -> TestResult<SchemaObject> {
        let header = SchemaObject::new(
            "AccountServiceResponseHeader",
            vec![
                WireValue::Unsigned(1),
                WireValue::Opaque(vec![0; 32]),
                WireValue::Opaque(vec![0; 32]),
                WireValue::Opaque(vec![0; 16]),
                WireValue::Unsigned(2),
                WireValue::Opaque(vec![0; 32]),
            ],
        )?;
        Ok(SchemaObject::new(
            "AccountServiceResponse",
            vec![
                WireValue::Structure(header),
                WireValue::Opaque(vec![0; 4224]),
            ],
        )?)
    }

    /// The SASL chunk frames of one sealed response, as the coordinator
    /// relays them in the reply block.
    fn response_chunks(response: &SchemaObject) -> TestResult<Vec<WireMessage>> {
        let bytes = response.encode_canonical()?;
        let encoded = encode_sasl_payload(bytes.as_slice());
        let mut frames = Vec::new();
        for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
            frames.push(WireMessage::new(
                COORDINATOR_NAME,
                "AUTHENTICATE",
                &[std::str::from_utf8(chunk)?],
                None,
            )?);
        }
        Ok(frames)
    }

    /// Sends one sealed envelope as the client's SASL chunks.
    async fn send_envelope(client: &mut Client, envelope: &[u8]) -> TestResult {
        let encoded = encode_sasl_payload(envelope);
        for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
            client
                .line(&format!("AUTHENTICATE {}", std::str::from_utf8(chunk)?))
                .await?;
        }
        Ok(())
    }

    /// Waits until the client received `count` payload chunks after `skip`
    /// earlier AUTHENTICATE lines.
    async fn wait_for_chunks(
        client: &Client,
        skip: usize,
        count: usize,
    ) -> TestResult<Vec<String>> {
        for _ in 0..500 {
            let chunks: Vec<String> = client
                .sink
                .lines()
                .into_iter()
                .filter(|line| {
                    line.contains(" AUTHENTICATE ") && !line.ends_with(" AUTHENTICATE +")
                })
                .skip(skip)
                .collect();
            if chunks.len() >= count {
                return Ok(chunks);
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        Err("the edge never relayed the response chunks".into())
    }

    #[tokio::test]
    async fn sasl_crosses_the_federation_and_its_grant_opens_the_session() -> TestResult {
        run_edge(|federation, inbox| async move {
            let mut hub = Hub::new(federation);
            hub.establish().await?;
            hub.synchronize().await?;
            let mut client = Client::open(inbox, 1).await?;
            hub.ack_origin().await?;
            client.line("CAP LS 302").await?;
            client.line("CAP REQ :sasl").await?;
            client.line("AUTHENTICATE AGENC-OPAQUE").await?;
            client.wait_for(" AUTHENTICATE +").await?;

            // The start envelope leaves as one federated request and the
            // sealed challenge comes back through the edge transport.
            let envelope = crate::test_support::sealed_authentication_start(
                NETWORK,
                RecoveryEpoch::from_bytes([34; 16]),
                "quinn-account",
                71,
            )?;
            send_envelope(&mut client, &envelope).await?;
            let (header, operation, bytes) = match hub.next_request().await {
                Ok(request) => request,
                Err(error) => {
                    return Err(format!("{error}; client saw {:?}", client.sink.lines()).into());
                }
            };
            let FederatedOperation::AccountService {
                opcode: FederationOpcode::OpaqueAuthStart,
                session_id: None,
                ..
            } = operation
            else {
                return Err("expected a forwarded authentication start".into());
            };
            let response = challenge_response()?;
            hub.result(
                &header,
                &bytes,
                &ResultArm::AuthChallenge(response.try_clone()?),
                Vec::new(),
                None,
            )
            .await?;
            let chunks = wait_for_chunks(&client, 0, 15).await?;
            assert_eq!(chunks.len(), 15);

            // The finish envelope is answered with the grant and the sealed
            // completion in the reply block; the client sees 903.
            let finish = crate::test_support::sealed_authentication_finish(
                NETWORK,
                RecoveryEpoch::from_bytes([34; 16]),
                72,
            )?;
            send_envelope(&mut client, &finish).await?;
            let (header, operation, bytes) = match hub.next_request().await {
                Ok(request) => request,
                Err(error) => {
                    let lines = client.sink.lines();
                    let tail: Vec<&String> = lines.iter().rev().take(3).collect();
                    return Err(format!("finish: {error}; client tail {tail:?}").into());
                }
            };
            let FederatedOperation::AccountService {
                opcode: FederationOpcode::OpaqueAuthFinish,
                ..
            } = operation
            else {
                return Err("expected a forwarded authentication finish".into());
            };
            let account = AccountId::parse("a_AAAAAAAAAAAAAAAAAAAAAA")?;
            hub.result(
                &header,
                &bytes,
                &ResultArm::Authenticated {
                    account_id: account,
                    account_session_generation: 1,
                    auth_grant_id: [9; 32],
                },
                response_chunks(&response)?,
                None,
            )
            .await?;
            let chunks = wait_for_chunks(&client, 15, 15).await?;
            assert_eq!(chunks.len(), 15);
            client.wait_for(" 903 ").await?;

            // Registration presents the grant in the session open.
            client.line("NICK quinn").await?;
            client.line("USER quinn 0 * :Quinn Real").await?;
            client.line("CAP END").await?;
            let (_, operation, _) = match hub.next_request().await {
                Ok(request) => request,
                Err(error) => {
                    return Err(
                        format!("open: {error}; client saw {:?}", client.sink.lines()).into(),
                    );
                }
            };
            let FederatedOperation::SessionOpen { auth_grant_id, .. } = operation else {
                return Err("expected session_open".into());
            };
            assert_eq!(auth_grant_id, Some([9; 32]));
            Ok(())
        })
        .await
    }
}
