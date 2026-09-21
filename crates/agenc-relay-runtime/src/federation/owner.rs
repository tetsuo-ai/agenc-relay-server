//! The federation link owners: the coordinator's accept owner turns every
//! socket the federation listener admitted into one authenticated link, and
//! the edge's dial owner keeps exactly one link to its coordinator alive
//! with full-jitter reconnects (spec 20.2, 20.3, 20.10).
//!
//! Both owners run one link task per peer. A task completes the TLS
//! handshake, verifies the peer certificate against the static peer entry,
//! runs the signed hello, hands `LinkEvent::Established` to the state owner,
//! and then drives the framed link loop until it closes. The state owner
//! sees exactly one `Closed` per `Established`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agenc_relay_config::{PeerEndpoint, SocksEndpoint};
use agenc_relay_crypto::OsEntropy;
use agenc_relay_federation_wire::{FEDERATION_EXPORTER_LABEL, PeerContinuity, exporter_context};
use agenc_relay_types::{FederationRole, ServerId};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinSet;

use super::certificate::{server_id_from_certificate, verify_peer_certificate};
use super::dial::{DialPlan, dial, reconnect_delay};
use super::hello::{HELLO_DEADLINE, PeerHistory, exchange_hello};
use super::link::{FrameReader, LinkContext, LinkTiming, ingress_budget, link_queue, run_link};
use super::{
    AcceptedFederationSocket, FederationInbound, LinkCloseReason, LinkEvent, LinkId, LinkSession,
    LocalIdentity, MAX_FEDERATION_PEERS, PeerIdentity,
};
use crate::RuntimeError;
use crate::cancel::CancellationToken;
use crate::observe::adapter::RuntimeObserver;
use crate::tls::{FEDERATION_ALPN, TlsStream};

/// What every link task shares: the local identity, the static peer table,
/// the state owner's inbound queue, and the link policy.
pub struct LinkOwnerShared {
    local: LocalIdentity,
    peers: BTreeMap<ServerId, PeerIdentity>,
    inbound: mpsc::Sender<FederationInbound>,
    observer: Option<Arc<RuntimeObserver>>,
    timing: LinkTiming,
    outbound_bytes: u64,
    next_link: AtomicU64,
}

impl LinkOwnerShared {
    /// Builds the shared link policy.
    #[must_use]
    pub fn new(
        local: LocalIdentity,
        peers: Vec<PeerIdentity>,
        inbound: mpsc::Sender<FederationInbound>,
        observer: Option<Arc<RuntimeObserver>>,
        outbound_bytes: u64,
    ) -> Self {
        Self {
            local,
            peers: peers
                .into_iter()
                .map(|peer| (peer.server_id(), peer))
                .collect(),
            inbound,
            observer,
            timing: LinkTiming::SPEC,
            outbound_bytes,
            next_link: AtomicU64::new(1),
        }
    }

    /// Overrides the keepalive and sweep intervals, for tests.
    #[must_use]
    pub fn with_timing(mut self, timing: LinkTiming) -> Self {
        self.timing = timing;
        self
    }

    /// Records a link attempt that ended before the hello completed, under
    /// the same closed event as a failed link.
    fn setup_failed(&self) {
        if let Some(observer) = &self.observer {
            observer.federation_link(false, true);
        }
    }

    fn next_link(&self) -> LinkId {
        LinkId::new(self.next_link.fetch_add(1, Ordering::Relaxed))
    }

    fn history() -> PeerHistory<'static> {
        // The durable peer history is enforced by the state owner when it
        // receives `Established`; the hello itself fences only the static
        // pin and the wire rules.
        PeerHistory {
            continuity: PeerContinuity {
                last_accepted: None,
            },
            accepted_epochs: &[],
        }
    }
}

/// Why an operator link command was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlRefusal {
    /// The Server ID is not a configured peer.
    UnknownPeer,
    /// The command is not valid for this node's role.
    WrongRole,
    /// No link to that peer is live.
    NoLink,
}

impl std::fmt::Display for ControlRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnknownPeer => "unknown peer",
            Self::WrongRole => "command not valid for this role",
            Self::NoLink => "no live link",
        })
    }
}

impl std::error::Error for ControlRefusal {}

struct ControlState {
    role: FederationRole,
    peers: BTreeSet<ServerId>,
    live: Mutex<BTreeMap<ServerId, CancellationToken>>,
    suspended: Mutex<BTreeSet<ServerId>>,
    connect: Notify,
}

/// The operator's handle over the link owners: `CONNECT` and `SQUIT`
/// (spec 22.3). Cloning shares the same state.
#[derive(Clone)]
pub struct FederationControl {
    state: Arc<ControlState>,
}

impl FederationControl {
    /// Creates the control surface for one role and its configured peers.
    #[must_use]
    pub fn new(role: FederationRole, peers: impl IntoIterator<Item = ServerId>) -> Self {
        Self {
            state: Arc::new(ControlState {
                role,
                peers: peers.into_iter().collect(),
                live: Mutex::new(BTreeMap::new()),
                suspended: Mutex::new(BTreeSet::new()),
                connect: Notify::new(),
            }),
        }
    }

    /// `CONNECT`: on an edge, lifts a `SQUIT` suspension and wakes the dial
    /// owner at once. Invalid on a coordinator, which never dials.
    pub fn connect(&self, peer: ServerId) -> Result<(), ControlRefusal> {
        if self.state.role != FederationRole::Edge {
            return Err(ControlRefusal::WrongRole);
        }
        if !self.state.peers.contains(&peer) {
            return Err(ControlRefusal::UnknownPeer);
        }
        lock(&self.state.suspended).remove(&peer);
        self.state.connect.notify_waiters();
        self.state.connect.notify_one();
        Ok(())
    }

    /// `SQUIT`: closes the live link to one peer without touching its
    /// identity. An edge also stops redialing until `CONNECT` or restart.
    pub fn squit(&self, peer: ServerId) -> Result<(), ControlRefusal> {
        if !self.state.peers.contains(&peer) {
            return Err(ControlRefusal::UnknownPeer);
        }
        if self.state.role == FederationRole::Edge {
            lock(&self.state.suspended).insert(peer);
        }
        let token = lock(&self.state.live).get(&peer).cloned();
        let Some(token) = token else {
            return if self.state.role == FederationRole::Edge {
                Ok(())
            } else {
                Err(ControlRefusal::NoLink)
            };
        };
        token.cancel();
        Ok(())
    }

    /// Reports whether a link to the peer is live.
    #[must_use]
    pub fn is_live(&self, peer: ServerId) -> bool {
        lock(&self.state.live).contains_key(&peer)
    }

    fn is_suspended(&self, peer: ServerId) -> bool {
        lock(&self.state.suspended).contains(&peer)
    }

    /// Waits out a `SQUIT` suspension; `false` means the owner was cancelled.
    async fn wait_until_wanted(&self, peer: ServerId, token: &CancellationToken) -> bool {
        while self.is_suspended(peer) {
            tokio::select! {
                () = token.cancelled() => return false,
                () = self.state.connect.notified() => {}
            }
        }
        true
    }

    fn register(&self, peer: ServerId, token: CancellationToken) -> bool {
        let mut live = lock(&self.state.live);
        if live.contains_key(&peer) {
            return false;
        }
        live.insert(peer, token);
        true
    }

    fn unregister(&self, peer: ServerId) {
        lock(&self.state.live).remove(&peer);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Why a link attempt ended before the framed loop started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkSetupFailure {
    /// TLS did not complete or the client certificate was absent.
    Tls,
    /// The certificate named no configured peer or failed its pin.
    Certificate,
    /// The exporter could not be derived.
    Exporter,
    /// The hello exchange failed.
    Hello,
    /// A link to the same peer is already live.
    Duplicate,
}

/// Runs the coordinator's accept owner until cancelled: every admitted
/// socket becomes at most one link task, bounded by the peer ceiling.
pub async fn run_accept_owner(
    mut sockets: mpsc::Receiver<AcceptedFederationSocket>,
    shared: Arc<LinkOwnerShared>,
    control: FederationControl,
    token: CancellationToken,
) -> Result<(), RuntimeError> {
    let mut links: JoinSet<()> = JoinSet::new();
    loop {
        let socket = tokio::select! {
            () = token.cancelled() => break,
            socket = sockets.recv() => socket,
        };
        let Some(socket) = socket else { break };
        admit(socket, &mut links, &shared, &control, &token).await;
    }
    links.shutdown().await;
    Ok(())
}

/// Spawns one link task for an admitted socket once a peer slot is free.
async fn admit(
    socket: AcceptedFederationSocket,
    links: &mut JoinSet<()>,
    shared: &Arc<LinkOwnerShared>,
    control: &FederationControl,
    token: &CancellationToken,
) {
    while links.len() >= MAX_FEDERATION_PEERS {
        let _finished = links.join_next().await;
    }
    let Ok(child) = token.child() else {
        return;
    };
    let shared = Arc::clone(shared);
    let control = control.clone();
    links.spawn(async move {
        if accept_link(socket, Arc::clone(&shared), control, child)
            .await
            .is_err()
        {
            shared.setup_failed();
        }
    });
}

/// Authenticates one accepted socket and runs its link.
async fn accept_link(
    socket: AcceptedFederationSocket,
    shared: Arc<LinkOwnerShared>,
    control: FederationControl,
    token: CancellationToken,
) -> Result<LinkCloseReason, LinkSetupFailure> {
    let (stream, tls, mut slots) = socket.into_parts();
    let tls = tokio::time::timeout(
        HELLO_DEADLINE,
        TlsStream::handshake(stream, tls, FEDERATION_ALPN, HELLO_DEADLINE),
    )
    .await
    .map_err(|_| LinkSetupFailure::Tls)?
    .map_err(|_| LinkSetupFailure::Tls)?;
    slots.handshake_finished();
    let peer = {
        let certificate = tls
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or(LinkSetupFailure::Tls)?;
        let server_id =
            server_id_from_certificate(certificate).ok_or(LinkSetupFailure::Certificate)?;
        let peer = shared
            .peers
            .get(&server_id)
            .ok_or(LinkSetupFailure::Certificate)?;
        verify_peer_certificate(certificate, peer).map_err(|_| LinkSetupFailure::Certificate)?;
        peer
    };
    let mut exporter = [0_u8; 32];
    let context = exporter_context(
        &shared.local.network_id(),
        &shared.local.server_id(),
        &peer.server_id(),
    );
    tls.export_keying_material(&mut exporter, FEDERATION_EXPORTER_LABEL, &context)
        .map_err(|_| LinkSetupFailure::Exporter)?;
    let reader = FrameReader::new(tls, peer.server_name()).map_err(|_| LinkSetupFailure::Tls)?;
    let reason = run_authenticated(reader, exporter, peer, &shared, &control, token).await?;
    drop(slots);
    Ok(reason)
}

/// Everything the edge's dial owner needs for its coordinator.
pub struct DialOwnerPlan {
    /// The coordinator entry.
    pub peer: PeerIdentity,
    /// The configured endpoints, tried in order per attempt.
    pub endpoints: Vec<PeerEndpoint>,
    /// The mutual-TLS client configuration bound to the coordinator.
    pub tls: Arc<ClientConfig>,
    /// The configured connect timeout.
    pub connect_timeout: Duration,
    /// The reconnect ceiling from configuration.
    pub reconnect_max: Duration,
    /// The local Tor proxy for onion endpoints.
    pub tor_proxy: Option<SocksEndpoint>,
}

/// Runs the edge's dial owner until cancelled: one live attempt at a time,
/// full-jitter reconnects, and `CONNECT`/`SQUIT` control.
pub async fn run_dial_owner(
    plan: DialOwnerPlan,
    shared: Arc<LinkOwnerShared>,
    control: FederationControl,
    token: CancellationToken,
) -> Result<(), RuntimeError> {
    let peer_id = plan.peer.server_id();
    let mut attempt: u32 = 0;
    let mut entropy = OsEntropy;
    loop {
        if token.is_cancelled() || !control.wait_until_wanted(peer_id, &token).await {
            return Ok(());
        }
        let outcome = match token.child() {
            Ok(child) => dial_once(&plan, attempt, &shared, &control, child).await,
            Err(_) => Err(LinkSetupFailure::Duplicate),
        };
        attempt = match outcome {
            Ok(_reason) => 0,
            Err(_failure) => {
                shared.setup_failed();
                attempt.saturating_add(1)
            }
        };
        let delay = reconnect_delay(attempt, &mut entropy).min(plan.reconnect_max);
        tokio::select! {
            () = token.cancelled() => return Ok(()),
            () = tokio::time::sleep(delay) => {}
            () = control.state.connect.notified() => {}
        }
    }
}

/// One dial attempt: endpoint selection, TLS, exporter, hello, and the link.
async fn dial_once(
    plan: &DialOwnerPlan,
    attempt: u32,
    shared: &Arc<LinkOwnerShared>,
    control: &FederationControl,
    token: CancellationToken,
) -> Result<LinkCloseReason, LinkSetupFailure> {
    let index = usize::try_from(attempt).unwrap_or(usize::MAX) % plan.endpoints.len().max(1);
    let endpoint = plan.endpoints.get(index).ok_or(LinkSetupFailure::Tls)?;
    let mut entropy = OsEntropy;
    let stream = dial(
        DialPlan {
            endpoint,
            peer: &plan.peer,
            tls: Arc::clone(&plan.tls),
            connect_timeout: plan.connect_timeout,
            tor_proxy: plan.tor_proxy.as_ref(),
        },
        &mut entropy,
    )
    .await
    .map_err(|_| LinkSetupFailure::Tls)?;
    let context = exporter_context(
        &shared.local.network_id(),
        &shared.local.server_id(),
        &plan.peer.server_id(),
    );
    let exporter = stream
        .exporter(FEDERATION_EXPORTER_LABEL, &context)
        .map_err(|_| LinkSetupFailure::Exporter)?;
    let reader =
        FrameReader::new(stream, plan.peer.server_name()).map_err(|_| LinkSetupFailure::Tls)?;
    run_authenticated(reader, exporter, &plan.peer, shared, control, token).await
}

/// Runs the hello and then the framed loop over one authenticated
/// transport, reporting `Established` and `Closed` to the state owner.
async fn run_authenticated<S>(
    mut reader: FrameReader<S>,
    exporter: [u8; 32],
    peer: &PeerIdentity,
    shared: &Arc<LinkOwnerShared>,
    control: &FederationControl,
    token: CancellationToken,
) -> Result<LinkCloseReason, LinkSetupFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut entropy = OsEntropy;
    let outcome = exchange_hello(
        &mut reader,
        &shared.local,
        peer,
        exporter,
        LinkOwnerShared::history(),
        &mut entropy,
    )
    .await
    .map_err(|_| LinkSetupFailure::Hello)?;
    if !control.register(peer.server_id(), token.clone()) {
        return Err(LinkSetupFailure::Duplicate);
    }
    let link = shared.next_link();
    let session = LinkSession {
        link,
        peer: peer.server_id(),
        peer_incarnation: outcome.peer_incarnation,
        peer_recovery_epoch: outcome.peer_recovery_epoch,
        transition: outcome.transition,
    };
    let (handle, queue) = link_queue(shared.outbound_bytes);
    let established = shared
        .inbound
        .send(FederationInbound {
            link,
            peer: peer.server_id(),
            event: LinkEvent::Established { session, handle },
            charge: None,
        })
        .await
        .is_ok();
    if let Some(observer) = &shared.observer {
        observer.federation_link(true, false);
    }
    let reason = if established {
        let (reader, writer) = reader.split();
        let context = LinkContext {
            link,
            peer: peer.server_id(),
            local_name: shared.local.server_name().to_owned(),
            inbound: shared.inbound.clone(),
            budget: ingress_budget(),
            observer: shared.observer.clone(),
            token,
            timing: shared.timing,
        };
        run_link(reader, writer, queue, context, &mut entropy).await
    } else {
        LinkCloseReason::QueueClosed
    };
    control.unregister(peer.server_id());
    let _closed = shared
        .inbound
        .send(FederationInbound {
            link,
            peer: peer.server_id(),
            event: LinkEvent::Closed(reason),
            charge: None,
        })
        .await;
    if let Some(observer) = &shared.observer {
        observer.federation_link(
            false,
            !matches!(
                reason,
                LinkCloseReason::Cancelled | LinkCloseReason::PeerClosed
            ),
        );
    }
    Ok(reason)
}

#[cfg(test)]
mod tests {
    mod harness;
}
