//! Stage 07 link transport: mutual TLS identity, the hello matrix, the link
//! loop with fragmented objects, and keepalive, all over in-process
//! transports under virtual time.

#![forbid(unsafe_code)]

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use agenc_ircd_crypto::Ed25519SecretKey;
use agenc_ircd_federation_wire::{
    CanonicalEncode as _, DecodeBudget, EpochTransition, EventDescriptor,
    FEDERATION_EXPORTER_LABEL, FederationFrame, FederationHash32, HelloRejection,
    OperationDescriptor, PeerContinuity, ReplayKey, ResultHeader, SchemaObject, WireValue,
    exporter_context, federation_object_id, split_fragments,
};
use agenc_ircd_runtime::cancel::CancellationToken;
use agenc_ircd_runtime::federation::hello::{
    HelloFailure, PeerHistory, build_hello, exchange_hello,
};
use agenc_ircd_runtime::federation::link::{
    FrameReader, LinkContext, LinkHandle, LinkTiming, SendRefusal, ingress_budget, link_queue,
    notify, run_link, write_line,
};
use agenc_ircd_runtime::federation::{
    FederationInbound, LinkCloseReason, LinkEvent, LinkId, LocalIdentity, ObjectCarrier,
    PeerIdentity,
};
use agenc_ircd_runtime::tls::ClientTlsStream;
use agenc_ircd_runtime::tls::{
    CLIENT_ALPN, CertChain, ClientAuth, FEDERATION_ALPN, PrivateKey, TlsEndpointProfile,
    TlsHandshakeError, TlsServerPolicy, TlsStream, TrustStore, build_client_config,
    build_federation_client_config, build_server_config_with_policy_blocking,
};
use agenc_ircd_testkit::TlsFixture;
use agenc_ircd_types::{
    EntropyError, EntropySource, EventId, FederationResultKind, FederationRole, NetworkId,
    OriginId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation,
};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncWriteExt as _, DuplexStream, duplex};
use tokio::sync::mpsc;

type TestResult = Result<(), Box<dyn Error>>;

const NETWORK: NetworkId = NetworkId::from_bytes([1; 32]);
const COORDINATOR_ID: ServerId = ServerId::from_bytes([10; 16]);
const EDGE_ID: ServerId = ServerId::from_bytes([20; 16]);
const COORDINATOR_NAME: &str = "core.example";
const EDGE_NAME: &str = "edge.example";
const EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([5; 16]);

struct CountingEntropy(u8);

impl EntropySource for CountingEntropy {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        self.0 = self.0.wrapping_add(1);
        destination.fill(self.0);
        Ok(())
    }
}

struct Node {
    local: LocalIdentity,
    as_peer: PeerIdentity,
    fixture: TlsFixture,
    signing: Arc<Ed25519SecretKey>,
}

fn node(
    seed: u8,
    server_id: ServerId,
    name: &str,
    role: FederationRole,
) -> Result<Node, Box<dyn Error>> {
    let signing = Arc::new(Ed25519SecretKey::from_bytes([seed; 32]));
    let fixture = TlsFixture::mint_federation([seed; 32], server_id)?;
    let local = LocalIdentity::new(
        NETWORK,
        server_id,
        name,
        ServerIncarnation::from_bytes([seed.wrapping_add(1); 16]),
        EPOCH,
        role,
        Arc::clone(&signing),
    )?;
    let as_peer = PeerIdentity::new(
        server_id,
        name,
        role,
        EPOCH,
        signing.public_key(),
        *fixture.leaf_spki_sha256(),
    );
    Ok(Node {
        local,
        as_peer,
        fixture,
        signing,
    })
}

fn coordinator() -> Result<Node, Box<dyn Error>> {
    node(
        1,
        COORDINATOR_ID,
        COORDINATOR_NAME,
        FederationRole::Coordinator,
    )
}

fn edge() -> Result<Node, Box<dyn Error>> {
    node(2, EDGE_ID, EDGE_NAME, FederationRole::Edge)
}

fn trust(fixture: &TlsFixture) -> Result<TrustStore, Box<dyn Error>> {
    Ok(TrustStore::parse(fixture.ca_certificate_der())?)
}

fn material(fixture: &TlsFixture) -> Result<(CertChain, PrivateKey), Box<dyn Error>> {
    Ok((
        CertChain::parse(fixture.leaf_certificate_der())?,
        PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
    ))
}

/// Both fixtures share one deterministic CA seed only when minted from the
/// same seed, so the server trusts a store built from the edge's CA and vice
/// versa by minting both nodes from one CA-bearing fixture set.
struct Pair {
    coordinator: Node,
    edge: Node,
}

fn make_pair() -> Result<Pair, Box<dyn Error>> {
    Ok(Pair {
        coordinator: coordinator()?,
        edge: edge()?,
    })
}

async fn connect(
    pair: &Pair,
    coordinator_peer: &PeerIdentity,
) -> Result<(TlsStream<DuplexStream>, ClientTlsStream<DuplexStream>), Box<dyn Error>> {
    let (chain, key) = material(&pair.coordinator.fixture)?;
    let server = build_server_config_with_policy_blocking(
        TlsEndpointProfile::Federation,
        chain,
        key,
        ClientAuth::MutualTls(trust(&pair.edge.fixture)?),
        TlsServerPolicy::new(
            agenc_ircd_config::GroupPolicy::HybridPreferred,
            false,
            false,
        ),
        None,
    )?;
    let client = build_federation_client_config(
        trust(&pair.coordinator.fixture)?,
        material(&pair.edge.fixture)?,
        *coordinator_peer.certificate_spki_sha256(),
        coordinator_peer.server_id(),
    )?;
    let (server_side, client_side) = duplex(1 << 16);
    let server_name = ServerName::try_from(COORDINATOR_NAME.to_owned())?;
    let (server, client) = tokio::join!(
        TlsStream::handshake(
            server_side,
            server,
            FEDERATION_ALPN,
            Duration::from_secs(10)
        ),
        ClientTlsStream::handshake(client_side, client, server_name, FEDERATION_ALPN),
    );
    Ok((server?, client?))
}

fn exporter_of<F>(export: F) -> Result<[u8; 32], Box<dyn Error>>
where
    F: FnOnce(&mut [u8; 32], &[u8], &[u8]) -> Result<(), agenc_ircd_runtime::RuntimeError>,
{
    let context = exporter_context(&NETWORK, &COORDINATOR_ID, &EDGE_ID);
    let mut output = [0_u8; 32];
    export(&mut output, FEDERATION_EXPORTER_LABEL, &context)?;
    Ok(output)
}

fn history() -> PeerHistory<'static> {
    PeerHistory {
        continuity: PeerContinuity {
            last_accepted: None,
        },
        accepted_epochs: &[],
    }
}

#[tokio::test]
async fn mutual_tls_binds_pin_uri_and_alpn() -> TestResult {
    let pair = make_pair()?;
    let (server, client) = connect(&pair, &pair.coordinator.as_peer).await?;
    let server_exporter =
        exporter_of(|out, label, context| server.export_keying_material(out, label, context))?;
    let client_exporter =
        exporter_of(|out, label, context| client.export_keying_material(out, label, context))?;
    assert_eq!(server_exporter, client_exporter);
    let peer_certificate = server
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or("no client certificate")?;
    agenc_ircd_runtime::federation::certificate::verify_peer_certificate(
        peer_certificate.as_ref(),
        &pair.edge.as_peer,
    )?;

    let wrong_pin = PeerIdentity::new(
        COORDINATOR_ID,
        COORDINATOR_NAME,
        FederationRole::Coordinator,
        EPOCH,
        pair.coordinator.signing.public_key(),
        [0xAB; 32],
    );
    assert!(connect(&pair, &wrong_pin).await.is_err());
    let wrong_id = PeerIdentity::new(
        ServerId::from_bytes([11; 16]),
        COORDINATOR_NAME,
        FederationRole::Coordinator,
        EPOCH,
        pair.coordinator.signing.public_key(),
        *pair.coordinator.fixture.leaf_spki_sha256(),
    );
    assert!(connect(&pair, &wrong_id).await.is_err());

    let (chain, key) = material(&pair.coordinator.fixture)?;
    let server = build_server_config_with_policy_blocking(
        TlsEndpointProfile::Federation,
        chain,
        key,
        ClientAuth::MutualTls(trust(&pair.edge.fixture)?),
        TlsServerPolicy::new(
            agenc_ircd_config::GroupPolicy::HybridPreferred,
            false,
            false,
        ),
        None,
    )?;
    let client_alpn = build_client_config(
        trust(&pair.coordinator.fixture)?,
        Some(CLIENT_ALPN),
        Some(material(&pair.edge.fixture)?),
    )?;
    let (server_side, client_side) = duplex(1 << 16);
    let (server_result, _client_result) = tokio::join!(
        TlsStream::handshake(
            server_side,
            server,
            FEDERATION_ALPN,
            Duration::from_secs(10)
        ),
        ClientTlsStream::handshake(
            client_side,
            client_alpn,
            ServerName::try_from(COORDINATOR_NAME.to_owned())?,
            CLIENT_ALPN
        ),
    );
    assert!(matches!(
        server_result.err(),
        Some(
            TlsHandshakeError::AlpnMismatch
                | TlsHandshakeError::Protocol
                | TlsHandshakeError::PeerClosed
        )
    ));
    Ok(())
}

#[tokio::test]
async fn hello_exchange_authenticates_both_directions() -> TestResult {
    let pair = make_pair()?;
    let (server, client) = connect(&pair, &pair.coordinator.as_peer).await?;
    let exporter =
        exporter_of(|out, label, context| server.export_keying_material(out, label, context))?;
    let mut coordinator_reader = FrameReader::new(server, EDGE_NAME)?;
    let mut edge_reader = FrameReader::new(client, COORDINATOR_NAME)?;
    let mut coordinator_entropy = CountingEntropy(0);
    let mut edge_entropy = CountingEntropy(100);
    let (coordinator_outcome, edge_outcome) = tokio::join!(
        exchange_hello(
            &mut coordinator_reader,
            &pair.coordinator.local,
            &pair.edge.as_peer,
            exporter,
            history(),
            &mut coordinator_entropy,
        ),
        exchange_hello(
            &mut edge_reader,
            &pair.edge.local,
            &pair.coordinator.as_peer,
            exporter,
            history(),
            &mut edge_entropy,
        ),
    );
    let coordinator_outcome = coordinator_outcome?;
    let edge_outcome = edge_outcome?;
    assert_eq!(coordinator_outcome.transition, EpochTransition::Initial);
    assert_eq!(
        coordinator_outcome.peer_incarnation,
        pair.edge.local.incarnation()
    );
    assert_eq!(
        edge_outcome.peer_incarnation,
        pair.coordinator.local.incarnation()
    );
    assert_eq!(coordinator_outcome.local_nonce, edge_outcome.peer_nonce);
    assert_eq!(coordinator_outcome.peer_nonce, edge_outcome.local_nonce);
    Ok(())
}

/// Runs the coordinator side of the hello against a scripted edge that sends
/// `hello` (or nothing) followed by `after`.
async fn coordinator_hello_against(
    pair: &Pair,
    coordinator_peer_view_of_edge: &PeerIdentity,
    script: impl FnOnce([u8; 32]) -> Vec<FederationFrame>,
) -> Result<HelloFailure, Box<dyn Error>> {
    let (server, client) = connect(pair, &pair.coordinator.as_peer).await?;
    let exporter =
        exporter_of(|out, label, context| server.export_keying_material(out, label, context))?;
    let mut coordinator_reader = FrameReader::new(server, EDGE_NAME)?;
    let mut entropy = CountingEntropy(0);
    let frames = script(exporter);
    // The scripted edge writes its frames, then drains the coordinator's
    // output in the background so the coordinator's writes never block.
    let drain = tokio::spawn(async move {
        let mut stream = client;
        for frame in frames {
            let Ok(line) = frame.render(EDGE_NAME) else {
                return;
            };
            if write_line(&mut stream, &line).await.is_err() {
                return;
            }
        }
        let mut sink = [0_u8; 4096];
        loop {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        exchange_hello(
            &mut coordinator_reader,
            &pair.coordinator.local,
            coordinator_peer_view_of_edge,
            exporter,
            history(),
            &mut entropy,
        ),
    )
    .await;
    drop(coordinator_reader);
    let _ = drain.await;
    match outcome {
        Ok(Ok(_)) => Err("hello unexpectedly succeeded".into()),
        Ok(Err(failure)) => Ok(failure),
        Err(_) => Err("hello never finished".into()),
    }
}

fn edge_identity_with(
    epoch: RecoveryEpoch,
    role: FederationRole,
    key: [u8; 32],
) -> Result<LocalIdentity, Box<dyn Error>> {
    Ok(LocalIdentity::new(
        NETWORK,
        EDGE_ID,
        EDGE_NAME,
        ServerIncarnation::from_bytes([3; 16]),
        epoch,
        role,
        Arc::new(Ed25519SecretKey::from_bytes(key)),
    )?)
}

fn hello_frame(local: &LocalIdentity, exporter: [u8; 32]) -> Vec<FederationFrame> {
    let coordinator_view = match coordinator() {
        Ok(node) => node.as_peer,
        Err(_) => return Vec::new(),
    };
    build_hello(local, &coordinator_view, exporter, [9; 32])
        .map(|hello| FederationFrame::Hello {
            peer_server_id: COORDINATOR_ID,
            hello,
        })
        .into_iter()
        .collect()
}

async fn expect_hello_failure(
    script: impl FnOnce([u8; 32]) -> Vec<FederationFrame>,
    expected: HelloFailure,
) -> TestResult {
    let pair = make_pair()?;
    let edge_view = pair.edge.as_peer.clone();
    let failure = coordinator_hello_against(&pair, &edge_view, script).await?;
    assert_eq!(failure, expected);
    assert!(!failure.to_string().is_empty());
    Ok(())
}

#[tokio::test]
async fn hello_rejects_a_frame_before_hello() -> TestResult {
    expect_hello_failure(
        |_| {
            vec![FederationFrame::Ack {
                coordinator_server_id: COORDINATOR_ID,
                delivery_sequence: 1,
                event_id: EventId::from_bytes([1; 16]),
            }]
        },
        HelloFailure::UnexpectedFrame,
    )
    .await
}

#[tokio::test]
async fn hello_times_out_without_a_peer_hello() -> TestResult {
    expect_hello_failure(|_| Vec::new(), HelloFailure::Timeout).await
}

#[tokio::test]
async fn hello_rejects_the_wrong_addressee() -> TestResult {
    let edge = edge()?;
    expect_hello_failure(
        move |exporter| {
            let mut frames = hello_frame(&edge.local, exporter);
            if let Some(FederationFrame::Hello { peer_server_id, .. }) = frames.first_mut() {
                *peer_server_id = EDGE_ID;
            }
            frames
        },
        HelloFailure::WrongAddressee,
    )
    .await
}

#[tokio::test]
async fn hello_rejects_a_bad_signature() -> TestResult {
    let edge = edge()?;
    expect_hello_failure(
        move |exporter| {
            let mut frames = hello_frame(&edge.local, exporter);
            if let Some(FederationFrame::Hello { hello, .. }) = frames.first_mut() {
                hello.signature = [0; 64];
            }
            frames
        },
        HelloFailure::Signature,
    )
    .await
}

#[tokio::test]
async fn hello_rejects_an_exporter_mismatch() -> TestResult {
    let edge = edge()?;
    expect_hello_failure(
        move |_| hello_frame(&edge.local, [0xEE; 32]),
        HelloFailure::Tuple(HelloRejection::Exporter),
    )
    .await
}

#[tokio::test]
async fn hello_rejects_an_impostor_key() -> TestResult {
    let impostor = edge_identity_with(EPOCH, FederationRole::Edge, [77; 32])?;
    expect_hello_failure(
        move |exporter| hello_frame(&impostor, exporter),
        HelloFailure::Signature,
    )
    .await
}

#[tokio::test]
async fn hello_rejects_the_wrong_role() -> TestResult {
    let wrong_role = edge_identity_with(EPOCH, FederationRole::Coordinator, [2; 32])?;
    expect_hello_failure(
        move |exporter| hello_frame(&wrong_role, exporter),
        HelloFailure::Tuple(HelloRejection::Role),
    )
    .await
}

#[tokio::test]
async fn hello_rejects_an_unpinned_epoch() -> TestResult {
    let other_epoch = edge_identity_with(
        RecoveryEpoch::from_bytes([6; 16]),
        FederationRole::Edge,
        [2; 32],
    )?;
    expect_hello_failure(
        move |exporter| hello_frame(&other_epoch, exporter),
        HelloFailure::Tuple(HelloRejection::RecoveryEpochPin),
    )
    .await
}

#[tokio::test]
async fn hello_rejects_a_wrong_ready_nonce() -> TestResult {
    let edge = edge()?;
    expect_hello_failure(
        move |exporter| {
            let mut frames = hello_frame(&edge.local, exporter);
            frames.push(FederationFrame::Ready {
                peer_server_id: COORDINATOR_ID,
                hello_nonce: [0; 32],
            });
            frames
        },
        HelloFailure::NonceMismatch,
    )
    .await
}

#[tokio::test]
async fn hello_rejects_a_duplicate_hello() -> TestResult {
    let edge = edge()?;
    expect_hello_failure(
        move |exporter| {
            let mut frames = hello_frame(&edge.local, exporter);
            frames.extend(hello_frame(&edge.local, exporter));
            frames
        },
        HelloFailure::UnexpectedFrame,
    )
    .await
}

struct RunningLink {
    handle: LinkHandle,
    inbound: mpsc::Receiver<FederationInbound>,
    task: tokio::task::JoinHandle<LinkCloseReason>,
    token: CancellationToken,
}

fn start_link<R, W>(
    id: u64,
    peer: ServerId,
    local_name: &str,
    reader: FrameReader<R>,
    writer: W,
    entropy_seed: u8,
) -> RunningLink
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (handle, queue) = link_queue(1 << 20);
    let (inbound_sender, inbound) = mpsc::channel(256);
    let token = CancellationToken::root();
    let context = LinkContext {
        link: LinkId::new(id),
        peer,
        local_name: local_name.to_owned(),
        inbound: inbound_sender,
        budget: ingress_budget(),
        token: token.clone(),
        timing: LinkTiming {
            keepalive_idle: Duration::from_millis(400),
            keepalive_timeout: Duration::from_millis(300),
            assembly_sweep: Duration::from_millis(200),
        },
    };
    let task = tokio::spawn(async move {
        let mut entropy = CountingEntropy(entropy_seed);
        run_link(reader, writer, queue, context, &mut entropy).await
    });
    RunningLink {
        handle,
        inbound,
        task,
        token,
    }
}

fn large_result() -> Result<(OperationDescriptor, Vec<u8>), Box<dyn Error>> {
    let replay_key = ReplayKey {
        home_server_id: EDGE_ID,
        server_incarnation: ServerIncarnation::from_bytes([3; 16]),
        origin_id: OriginId::from_bytes([4; 16]),
        origin_generation: 1,
        operation_sequence: 2,
    };
    let header = ResultHeader {
        network_id: NETWORK,
        replay_key,
        request_id: RequestId::from_bytes([5; 16]),
        request_object_id: FederationHash32::from_bytes([6; 32]),
        completion_event_id: None,
        result_kind: FederationResultKind::NoContent,
    };
    let mut replies = Vec::new();
    for _ in 0..40 {
        replies.push(SchemaObject::new(
            "FederationReply",
            vec![
                WireValue::Opaque(b"NOTICE".to_vec()),
                WireValue::Vector(Vec::new()),
                WireValue::Unsigned(1),
                WireValue::Opaque(vec![b'a'; 4_000]),
            ],
        )?);
    }
    let result = header.build(
        &SchemaObject::new("result.no_content", Vec::new())?,
        replies,
    )?;
    let encoded = result.encode_canonical()?.as_slice().to_vec();
    let descriptor = OperationDescriptor {
        addressed_server_id: EDGE_ID,
        server_incarnation: replay_key.server_incarnation,
        origin_id: replay_key.origin_id,
        origin_generation: replay_key.origin_generation,
        operation_sequence: replay_key.operation_sequence,
        request_id: header.request_id,
        object_id: federation_object_id(&encoded),
    };
    Ok((descriptor, encoded))
}

#[tokio::test]
async fn link_loop_carries_frames_objects_and_keepalive() -> TestResult {
    let pair = make_pair()?;
    let (server, client) = connect(&pair, &pair.coordinator.as_peer).await?;
    let (server_read, server_write) = tokio::io::split(server);
    let (client_read, client_write) = tokio::io::split(client);
    let coordinator_reader = FrameReader::new(server_read, EDGE_NAME)?;
    let edge_reader = FrameReader::new(client_read, COORDINATOR_NAME)?;
    let mut coordinator = start_link(
        1,
        EDGE_ID,
        COORDINATOR_NAME,
        coordinator_reader,
        server_write,
        0,
    );
    let mut edge = start_link(2, COORDINATOR_ID, EDGE_NAME, edge_reader, client_write, 50);

    let ack = FederationFrame::Ack {
        coordinator_server_id: COORDINATOR_ID,
        delivery_sequence: 7,
        event_id: EventId::from_bytes([1; 16]),
    };
    edge.handle.try_send(ack.render(EDGE_NAME)?)?;
    let received = tokio::time::timeout(Duration::from_secs(5), coordinator.inbound.recv())
        .await?
        .ok_or("coordinator inbound closed")?;
    assert_eq!(received.link, LinkId::new(1));
    assert_eq!(received.peer, EDGE_ID);
    let Some(charge) = &received.charge else {
        return Err("control frame carried no charge".into());
    };
    assert_eq!(charge.bytes(), 1_024);
    match received.event {
        LinkEvent::Frame(FederationFrame::Ack {
            delivery_sequence, ..
        }) => assert_eq!(delivery_sequence, 7),
        _ => return Err("expected an ACK frame".into()),
    }
    drop(received);

    let (descriptor, encoded) = large_result()?;
    let fragments = split_fragments(descriptor.object_id, &encoded)?;
    assert!(fragments.len() > 3);
    for fragment in fragments {
        let frame = FederationFrame::Result {
            descriptor,
            fragment,
        };
        coordinator
            .handle
            .try_send(frame.render(COORDINATOR_NAME)?)?;
    }
    let received = tokio::time::timeout(Duration::from_secs(5), edge.inbound.recv())
        .await?
        .ok_or("edge inbound closed")?;
    match &received.event {
        LinkEvent::Object { carrier, object } => {
            assert_eq!(*carrier, ObjectCarrier::Result(descriptor));
            assert_eq!(object.as_slice(), encoded.as_slice());
            assert_eq!(object.object_id(), descriptor.object_id);
            let mut budget = DecodeBudget::new(1 << 20, 100_000);
            let decoded =
                SchemaObject::decode_exact("FederationResult", object.as_slice(), &mut budget)?;
            assert_eq!(decoded.schema().name, "FederationResult");
        }
        _ => return Err("expected an object".into()),
    }
    assert_eq!(
        received.charge.as_ref().map(|charge| charge.bytes()),
        Some(u32::try_from(encoded.len())?)
    );
    drop(received);
    assert_eq!(coordinator.handle.queued_bytes(), 0);

    // Idle keepalive: after the idle interval each side pings, the other
    // answers, and the link survives several intervals.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(!coordinator.task.is_finished());
    assert!(!edge.task.is_finished());

    let event_frame = FederationFrame::Event {
        descriptor: EventDescriptor {
            target_server_id: EDGE_ID,
            delivery_sequence: 0,
            event_id: EventId::from_bytes([2; 16]),
            object_id: FederationHash32::from_bytes([3; 32]),
        },
        fragment: agenc_ircd_federation_wire::FederationFragment::new(
            FederationHash32::from_bytes([3; 32]),
            0,
            1,
            3,
            b"abc",
        )?,
    };
    coordinator
        .handle
        .try_send(event_frame.render(COORDINATOR_NAME)?)?;
    let reason = tokio::time::timeout(Duration::from_secs(5), edge.task).await??;
    assert!(matches!(reason, LinkCloseReason::Assembly(_)), "{reason}");
    let closed = tokio::time::timeout(Duration::from_secs(5), coordinator.task).await??;
    assert!(
        matches!(
            closed,
            LinkCloseReason::PeerClosed | LinkCloseReason::Transport
        ),
        "{closed}"
    );
    coordinator.token.cancel();
    edge.token.cancel();
    Ok(())
}

#[tokio::test]
async fn keepalive_silence_and_unsolicited_pong_close_the_link() -> TestResult {
    let pair = make_pair()?;
    let (server, client) = connect(&pair, &pair.coordinator.as_peer).await?;
    let (server_read, server_write) = tokio::io::split(server);
    let coordinator_reader = FrameReader::new(server_read, EDGE_NAME)?;
    let coordinator = start_link(
        1,
        EDGE_ID,
        COORDINATOR_NAME,
        coordinator_reader,
        server_write,
        0,
    );
    let mut scripted = FrameReader::new(client, COORDINATOR_NAME)?;
    let frame = tokio::time::timeout(Duration::from_secs(5), scripted.next_frame())
        .await?
        .map_err(|failure| format!("{failure:?}"))?;
    assert!(matches!(frame, FederationFrame::Ping { .. }));
    let reason = tokio::time::timeout(Duration::from_secs(5), coordinator.task).await??;
    assert_eq!(reason, LinkCloseReason::KeepaliveTimeout);
    coordinator.token.cancel();

    let pair = make_pair()?;
    let (server, client) = connect(&pair, &pair.coordinator.as_peer).await?;
    let (server_read, server_write) = tokio::io::split(server);
    let coordinator_reader = FrameReader::new(server_read, EDGE_NAME)?;
    let coordinator = start_link(
        2,
        EDGE_ID,
        COORDINATOR_NAME,
        coordinator_reader,
        server_write,
        0,
    );
    let mut stream = client;
    let pong = FederationFrame::Pong {
        peer_server_id: COORDINATOR_ID,
        nonce: [1; 32],
    }
    .render(EDGE_NAME)?;
    write_line(&mut stream, &pong)
        .await
        .map_err(|_| "write failed")?;
    let reason = tokio::time::timeout(Duration::from_secs(5), coordinator.task).await??;
    assert!(matches!(reason, LinkCloseReason::Protocol(_)), "{reason}");
    coordinator.token.cancel();

    let pair = make_pair()?;
    let (server, client) = connect(&pair, &pair.coordinator.as_peer).await?;
    let (server_read, server_write) = tokio::io::split(server);
    let coordinator_reader = FrameReader::new(server_read, EDGE_NAME)?;
    let coordinator = start_link(
        3,
        EDGE_ID,
        COORDINATOR_NAME,
        coordinator_reader,
        server_write,
        0,
    );
    let mut stream = client;
    stream.write_all(b"garbage line\r\n").await?;
    stream.flush().await?;
    let reason = tokio::time::timeout(Duration::from_secs(5), coordinator.task).await??;
    assert_eq!(reason, LinkCloseReason::Framing);

    let (sender, mut receiver) = mpsc::channel(1);
    assert!(
        notify(
            &sender,
            LinkId::new(9),
            EDGE_ID,
            LinkEvent::Closed(LinkCloseReason::Cancelled)
        )
        .await
    );
    let notice = receiver.recv().await.ok_or("no notice")?;
    assert!(notice.charge.is_none());
    assert!(matches!(
        notice.event,
        LinkEvent::Closed(LinkCloseReason::Cancelled)
    ));
    Ok(())
}

#[tokio::test]
async fn server_reader_accepts_a_scripted_client_line() -> TestResult {
    let pair = make_pair()?;
    let (server, client) = connect(&pair, &pair.coordinator.as_peer).await?;
    let mut server_reader = FrameReader::new(server, EDGE_NAME)?;
    let ack = FederationFrame::Ack {
        coordinator_server_id: COORDINATOR_ID,
        delivery_sequence: 1,
        event_id: EventId::from_bytes([1; 16]),
    };
    let line = ack.render(EDGE_NAME)?;
    let writer = tokio::spawn(async move {
        let mut stream = client;
        let outcome = write_line(&mut stream, &line).await;
        (stream, outcome)
    });
    let frame = tokio::time::timeout(Duration::from_secs(3), server_reader.next_frame()).await;
    let (_client, written) = tokio::time::timeout(Duration::from_secs(3), writer).await??;
    assert!(written.is_ok(), "scripted write failed");
    let frame = frame.map_err(|_| "server read timed out")?;
    assert!(
        matches!(frame, Ok(FederationFrame::Ack { .. })),
        "server read the wrong frame"
    );
    Ok(())
}

#[tokio::test]
async fn the_queue_names_a_full_ceiling_and_a_closed_link_apart() -> TestResult {
    let ready = FederationFrame::OriginReady {
        edge_server_id: ServerId::from_bytes([2; 16]),
        server_incarnation: ServerIncarnation::from_bytes([3; 16]),
    };
    let (tiny, _queue) = link_queue(1);
    assert_eq!(
        tiny.try_send(ready.render(EDGE_NAME)?),
        Err(SendRefusal::QueueFull)
    );
    assert_eq!(tiny.queued_bytes(), 0);
    let (handle, queue) = link_queue(1 << 20);
    drop(queue);
    assert_eq!(
        handle.try_send(ready.render(EDGE_NAME)?),
        Err(SendRefusal::Closed)
    );
    assert_eq!(handle.queued_bytes(), 0, "a refused line holds no bytes");
    Ok(())
}
