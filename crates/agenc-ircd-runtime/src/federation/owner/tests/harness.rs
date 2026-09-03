#![forbid(unsafe_code)]
//! Both link owners over a loopback TCP listener with real mutual TLS.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use agenc_ircd_config::PeerEndpoint;
use agenc_ircd_crypto::Ed25519SecretKey;
use agenc_ircd_testkit::TlsFixture;
use agenc_ircd_types::{FederationRole, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};
use tokio::sync::{Semaphore, mpsc};

use super::super::{
    ControlRefusal, DialOwnerPlan, FederationControl, LinkOwnerShared, run_accept_owner,
    run_dial_owner,
};
use crate::cancel::CancellationToken;
use crate::federation::link::LinkTiming;
use crate::federation::{
    AcceptedFederationSocket, FederationInbound, LinkCloseReason, LinkEvent, LocalIdentity,
    PeerIdentity,
};
use crate::tls::{
    CertChain, ClientAuth, PrivateKey, TlsEndpointProfile, TlsServerPolicy, TrustStore,
    build_federation_client_config, build_server_config_with_policy_blocking,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const NETWORK: NetworkId = NetworkId::from_bytes([1; 32]);
const COORDINATOR_ID: ServerId = ServerId::from_bytes([10; 16]);
const EDGE_ID: ServerId = ServerId::from_bytes([20; 16]);
const EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([5; 16]);

struct Node {
    local: LocalIdentity,
    as_peer: PeerIdentity,
    fixture: TlsFixture,
}

fn node(seed: u8, server_id: ServerId, name: &str, role: FederationRole) -> TestResult<Node> {
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
    })
}

fn trust(fixture: &TlsFixture) -> TestResult<TrustStore> {
    Ok(TrustStore::parse(fixture.ca_certificate_der())?)
}

fn material(fixture: &TlsFixture) -> TestResult<(CertChain, PrivateKey)> {
    Ok((
        CertChain::parse(fixture.leaf_certificate_der())?,
        PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
    ))
}

const TIMING: LinkTiming = LinkTiming {
    keepalive_idle: Duration::from_millis(200),
    keepalive_timeout: Duration::from_millis(200),
    assembly_sweep: Duration::from_millis(100),
};

async fn next_event(
    inbox: &mut mpsc::Receiver<FederationInbound>,
) -> TestResult<(ServerId, LinkEvent)> {
    let message = tokio::time::timeout(Duration::from_secs(10), inbox.recv())
        .await?
        .ok_or("inbox closed")?;
    Ok((message.peer, message.event))
}

#[tokio::test]
async fn accept_and_dial_owners_establish_squit_and_reconnect() -> TestResult {
    let coordinator = node(
        1,
        COORDINATOR_ID,
        "core.example",
        FederationRole::Coordinator,
    )?;
    let edge = node(2, EDGE_ID, "edge.example", FederationRole::Edge)?;
    let (chain, key) = material(&coordinator.fixture)?;
    let server_tls = build_server_config_with_policy_blocking(
        TlsEndpointProfile::Federation,
        chain,
        key,
        ClientAuth::MutualTls(trust(&edge.fixture)?),
        TlsServerPolicy::new(
            agenc_ircd_config::GroupPolicy::HybridPreferred,
            false,
            false,
        ),
        None,
    )?;
    let client_tls = build_federation_client_config(
        trust(&coordinator.fixture)?,
        material(&edge.fixture)?,
        *coordinator.as_peer.certificate_spki_sha256(),
        coordinator.as_peer.server_id(),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    let (coordinator_inbound, mut coordinator_inbox) = mpsc::channel(64);
    let (edge_inbound, mut edge_inbox) = mpsc::channel(64);
    let coordinator_shared = Arc::new(
        LinkOwnerShared::new(
            coordinator.local,
            vec![edge.as_peer.clone()],
            coordinator_inbound,
            None,
            1 << 20,
        )
        .with_timing(TIMING),
    );
    let edge_shared = Arc::new(
        LinkOwnerShared::new(
            edge.local,
            vec![coordinator.as_peer.clone()],
            edge_inbound,
            None,
            1 << 20,
        )
        .with_timing(TIMING),
    );
    let coordinator_control = FederationControl::new(FederationRole::Coordinator, [EDGE_ID]);
    let edge_control = FederationControl::new(FederationRole::Edge, [COORDINATOR_ID]);
    let root = CancellationToken::root();

    // The listener stand-in admits sockets the way the federation listener
    // does: before TLS, holding one listener slot per socket.
    let (sockets, socket_receiver) = mpsc::channel(4);
    let slots = Arc::new(Semaphore::new(4));
    let accept_token = root.child()?;
    let acceptor = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = accept_token.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else { break };
            let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                break;
            };
            let socket = AcceptedFederationSocket::new(stream, Arc::clone(&server_tls), slot, None);
            if sockets.send(socket).await.is_err() {
                break;
            }
        }
    });
    let accept_owner = tokio::spawn(run_accept_owner(
        socket_receiver,
        Arc::clone(&coordinator_shared),
        coordinator_control.clone(),
        root.child()?,
    ));
    let dial_owner = tokio::spawn(run_dial_owner(
        DialOwnerPlan {
            peer: coordinator.as_peer.clone(),
            endpoints: vec![PeerEndpoint::Tcp(address)],
            tls: client_tls,
            connect_timeout: Duration::from_secs(5),
            reconnect_max: Duration::from_millis(300),
            tor_proxy: None,
        },
        Arc::clone(&edge_shared),
        edge_control.clone(),
        root.child()?,
    ));

    let (peer, event) = next_event(&mut coordinator_inbox).await?;
    assert_eq!(peer, EDGE_ID);
    let LinkEvent::Established { session, .. } = event else {
        return Err("coordinator saw no Established".into());
    };
    assert_eq!(
        session.peer_incarnation,
        ServerIncarnation::from_bytes([3; 16])
    );
    let (peer, event) = next_event(&mut edge_inbox).await?;
    assert_eq!(peer, COORDINATOR_ID);
    assert!(matches!(event, LinkEvent::Established { .. }));
    assert!(coordinator_control.is_live(EDGE_ID));
    assert!(edge_control.is_live(COORDINATOR_ID));

    // Control refusals are closed and role-bound.
    assert_eq!(
        coordinator_control.connect(EDGE_ID),
        Err(ControlRefusal::WrongRole)
    );
    assert_eq!(
        edge_control.squit(EDGE_ID),
        Err(ControlRefusal::UnknownPeer)
    );

    // SQUIT on the edge closes the link and suspends redialing.
    edge_control.squit(COORDINATOR_ID)?;
    let (_, event) = next_event(&mut edge_inbox).await?;
    assert!(matches!(
        event,
        LinkEvent::Closed(LinkCloseReason::Cancelled)
    ));
    let (_, event) = next_event(&mut coordinator_inbox).await?;
    assert!(matches!(event, LinkEvent::Closed(_)));
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(edge_inbox.try_recv().is_err(), "no redial while suspended");

    // CONNECT lifts the suspension and the link comes back.
    edge_control.connect(COORDINATOR_ID)?;
    let (_, event) = next_event(&mut edge_inbox).await?;
    assert!(matches!(event, LinkEvent::Established { .. }));
    let (_, event) = next_event(&mut coordinator_inbox).await?;
    assert!(matches!(event, LinkEvent::Established { .. }));

    // SQUIT on the coordinator closes its side; the edge redials on its own.
    coordinator_control.squit(EDGE_ID)?;
    let (_, event) = next_event(&mut coordinator_inbox).await?;
    assert!(matches!(
        event,
        LinkEvent::Closed(LinkCloseReason::Cancelled)
    ));
    let (_, event) = next_event(&mut edge_inbox).await?;
    assert!(matches!(event, LinkEvent::Closed(_)));
    let (_, event) = next_event(&mut edge_inbox).await?;
    assert!(matches!(event, LinkEvent::Established { .. }));
    assert_eq!(
        coordinator_control.squit(COORDINATOR_ID),
        Err(ControlRefusal::UnknownPeer)
    );

    root.cancel();
    let _acceptor = tokio::time::timeout(Duration::from_secs(5), acceptor).await;
    let accept_exit = tokio::time::timeout(Duration::from_secs(5), accept_owner).await??;
    let dial_exit = tokio::time::timeout(Duration::from_secs(5), dial_owner).await??;
    assert!(accept_exit.is_ok());
    assert!(dial_exit.is_ok());
    Ok(())
}

#[tokio::test]
async fn unknown_peer_certificates_never_reach_the_state_owner() -> TestResult {
    let coordinator = node(
        1,
        COORDINATOR_ID,
        "core.example",
        FederationRole::Coordinator,
    )?;
    let edge = node(2, EDGE_ID, "edge.example", FederationRole::Edge)?;
    let stranger = node(
        3,
        ServerId::from_bytes([30; 16]),
        "other.example",
        FederationRole::Edge,
    )?;
    let (chain, key) = material(&coordinator.fixture)?;
    let server_tls = build_server_config_with_policy_blocking(
        TlsEndpointProfile::Federation,
        chain,
        key,
        ClientAuth::MutualTls(trust(&stranger.fixture)?),
        TlsServerPolicy::new(
            agenc_ircd_config::GroupPolicy::HybridPreferred,
            false,
            false,
        ),
        None,
    )?;
    let client_tls = build_federation_client_config(
        trust(&coordinator.fixture)?,
        material(&stranger.fixture)?,
        *coordinator.as_peer.certificate_spki_sha256(),
        coordinator.as_peer.server_id(),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (coordinator_inbound, mut coordinator_inbox) = mpsc::channel(8);
    let (edge_inbound, mut edge_inbox) = mpsc::channel(8);
    let coordinator_shared = Arc::new(LinkOwnerShared::new(
        coordinator.local,
        vec![edge.as_peer.clone()],
        coordinator_inbound,
        None,
        1 << 20,
    ));
    let stranger_shared = Arc::new(LinkOwnerShared::new(
        stranger.local,
        vec![coordinator.as_peer.clone()],
        edge_inbound,
        None,
        1 << 20,
    ));
    let root = CancellationToken::root();
    let (sockets, socket_receiver) = mpsc::channel(4);
    let slots = Arc::new(Semaphore::new(4));
    let accept_token = root.child()?;
    let acceptor = tokio::spawn(async move {
        let accepted = tokio::select! {
            () = accept_token.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else { return };
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        let _sent = sockets
            .send(AcceptedFederationSocket::new(
                stream, server_tls, slot, None,
            ))
            .await;
    });
    let accept_owner = tokio::spawn(run_accept_owner(
        socket_receiver,
        coordinator_shared,
        FederationControl::new(FederationRole::Coordinator, [EDGE_ID]),
        root.child()?,
    ));
    let dial_owner = tokio::spawn(run_dial_owner(
        DialOwnerPlan {
            peer: coordinator.as_peer.clone(),
            endpoints: vec![PeerEndpoint::Tcp(address)],
            tls: client_tls,
            connect_timeout: Duration::from_secs(5),
            reconnect_max: Duration::from_millis(200),
            tor_proxy: None,
        },
        stranger_shared,
        FederationControl::new(FederationRole::Edge, [COORDINATOR_ID]),
        root.child()?,
    ));
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(coordinator_inbox.try_recv().is_err());
    assert!(edge_inbox.try_recv().is_err());
    root.cancel();
    let _acceptor = tokio::time::timeout(Duration::from_secs(5), acceptor).await;
    let _accept = tokio::time::timeout(Duration::from_secs(5), accept_owner).await??;
    let _dial = tokio::time::timeout(Duration::from_secs(5), dial_owner).await??;
    Ok(())
}
