//! Listener set for the TLS, onion, and administrative endpoints (spec 6,
//! 8.5, 19.2 accept path at lines 2784-2790, and 21.2 at lines 4071-4073).
//!
//! Every listener runs one accept loop. Before it accepts, it holds one of
//! its own connection slots and one global handshake slot, so both ceilings
//! pause accepts instead of growing tasks. After it accepts, it needs the
//! global client-count slot, the admission hook's verdict, and the fixed
//! memory charges; any failure closes the just-accepted socket before TLS
//! begins and never spawns a task. The raw address is reduced to its
//! admission key inside this module and goes nowhere else.

pub mod prefix;
pub mod socket;
pub mod spki;

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;

pub use prefix::{PREFIX_ERASURE_DELAY, source_key};
pub use socket::{
    BoundAddress, ListenerError, ListenerSource, UNIX_SOCKET_DIRECTORY_MODE, UNIX_SOCKET_MODE,
};
pub use spki::spki_sha256;

use self::socket::BoundListener;
use crate::RuntimeError;
use crate::budget::{
    ADMIN_CONNECTION_BASE_BYTES, BoundedMemoryCharges, CLIENT_CONNECTION_BASE_BYTES, MemoryBudget,
    MemoryBudgetPort as _, MemoryCharge, MemoryPermitBatch, TLS_SETUP_INCREMENT_BYTES,
};
use crate::cancel::CancellationToken;
use crate::connection::{
    AdmittedConnection, ConnectionExit, ConnectionGeneration, ConnectionLimits,
    ConnectionResources, PeerIdentity, run_connection,
};
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::{SourceAddressKey, StateCoreMessage};
use crate::sync::Arc;
use crate::tls::{
    ACCEPT_TO_TLS_DEADLINE, HandshakeLimiter, TlsEndpointProfile, TlsHandshakeError, TlsStream,
};

/// Hard maximum client connections (spec line 2641).
pub const MAX_CLIENT_CONNECTIONS: usize = 250_000;
/// Hard maximum connections on one administrative listener (Appendix C.3).
pub const MAX_ADMIN_CONNECTIONS: usize = 64;
/// Pause after a transient accept failure so a descriptor shortage cannot
/// spin the listener.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Whether the admission hook lets an accepted socket proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionVerdict {
    /// Proceed to the memory charges and the connection supervisor.
    Admit,
    /// Close the socket before TLS begins.
    Refuse,
}

/// The rate and quota hook consulted for every accepted socket (spec 19.1).
///
/// The admission module supplies the bucket-backed implementation; until it
/// is composed, [`PermissiveAdmission`] admits everything.
pub trait AcceptAdmission: Send + Sync {
    /// Decides whether a socket from `source` may proceed on `purpose`.
    fn admit(&self, purpose: ListenerPurpose, source: SourceAddressKey) -> AdmissionVerdict;

    /// Records that a connection from `source` closed.
    fn released(&self, purpose: ListenerPurpose, source: SourceAddressKey) {
        let _ = (purpose, source);
    }
}

/// Admits every socket; the default before admission buckets exist.
pub struct PermissiveAdmission;

impl AcceptAdmission for PermissiveAdmission {
    fn admit(&self, _: ListenerPurpose, _: SourceAddressKey) -> AdmissionVerdict {
        AdmissionVerdict::Admit
    }
}

/// Why an accepted socket was closed before a connection existed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalReason {
    /// The global client-count ceiling was reached.
    GlobalCeiling,
    /// The admission hook refused the source.
    Admission,
    /// The memory budget refused the fixed charges.
    MemoryExhausted,
    /// The TLS handshake failed, timed out, or negotiated the wrong ALPN.
    TlsHandshake(TlsHandshakeError),
    /// The local peer's credentials could not be read.
    PeerCredentials,
    /// The mutual-TLS peer presented no usable certificate.
    ClientCertificate,
    /// The cancellation tree could not admit another child.
    TaskTree,
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GlobalCeiling => formatter.write_str("global connection ceiling reached"),
            Self::Admission => formatter.write_str("admission refused the source"),
            Self::MemoryExhausted => formatter.write_str("memory budget refused the connection"),
            Self::TlsHandshake(error) => write!(formatter, "TLS handshake refused: {error}"),
            Self::PeerCredentials => formatter.write_str("peer credentials unavailable"),
            Self::ClientCertificate => formatter.write_str("client certificate unusable"),
            Self::TaskTree => formatter.write_str("task tree is full"),
        }
    }
}

impl Error for RefusalReason {}

/// Observes admissions, refusals, and closes for logging and metrics.
pub trait ConnectionObserver: Send + Sync {
    /// A connection was admitted and its supervisor started.
    fn admitted(&self, connection: &AdmittedConnection) {
        let _ = connection;
    }

    /// An accepted socket was closed before a connection existed.
    fn refused(&self, purpose: ListenerPurpose, reason: RefusalReason) {
        let _ = (purpose, reason);
    }

    /// A connection ended.
    fn closed(&self, exit: &ConnectionExit) {
        let _ = exit;
    }
}

/// Observes nothing.
pub struct NoObserver;

impl ConnectionObserver for NoObserver {}

/// One configured endpoint.
pub struct ListenerSpec {
    /// The listener purpose.
    pub purpose: ListenerPurpose,
    /// Where its socket comes from.
    pub source: ListenerSource,
    /// The listener's own connection ceiling.
    pub max_connections: usize,
    /// The TLS configuration; required for TLS purposes, forbidden for
    /// local administration.
    pub tls: Option<Arc<ServerConfig>>,
}

/// Everything listeners share with the rest of the runtime.
pub struct ListenerContext {
    /// The process-wide memory budget.
    pub budget: Arc<MemoryBudget>,
    /// The global handshake semaphore.
    pub handshakes: HandshakeLimiter,
    /// The global client-count ceiling.
    pub client_slots: Arc<Semaphore>,
    /// The admission hook.
    pub admission: Arc<dyn AcceptAdmission>,
    /// The observer for admissions, refusals, and closes.
    pub observer: Arc<dyn ConnectionObserver>,
    /// The StateCore inbox.
    pub inbox: mpsc::Sender<StateCoreMessage>,
    /// Per-connection reader and queue ceilings.
    pub limits: ConnectionLimits,
}

/// How one listener task ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerExit {
    /// The listener purpose.
    pub purpose: ListenerPurpose,
    /// Connections that reached their supervisor over the listener's
    /// lifetime; counted when the supervisor exits.
    pub admitted: u64,
    /// Sockets refused before a connection existed, handshake failures
    /// included.
    pub refused: u64,
}

struct ListenerShared {
    budget: Arc<MemoryBudget>,
    handshakes: HandshakeLimiter,
    client_slots: Arc<Semaphore>,
    admission: Arc<dyn AcceptAdmission>,
    observer: Arc<dyn ConnectionObserver>,
    inbox: mpsc::Sender<StateCoreMessage>,
    limits: ConnectionLimits,
    generations: AtomicU64,
}

struct ValidatedSpec {
    purpose: ListenerPurpose,
    max_connections: usize,
    tls: Option<Arc<ServerConfig>>,
    profile: Option<TlsEndpointProfile>,
}

/// The set of open listeners and their connection supervisors.
pub struct ListenerSet {
    tasks: JoinSet<ListenerExit>,
    addresses: Vec<(ListenerPurpose, BoundAddress)>,
    accept_token: CancellationToken,
    connection_token: CancellationToken,
}

/// Cloneable shutdown authority for a listener set owned by another task.
#[derive(Clone)]
pub struct ListenerControl {
    accept_token: CancellationToken,
    connection_token: CancellationToken,
}

impl ListenerControl {
    /// Stops every accept loop while existing connections continue.
    pub fn stop_accepting(&self) {
        self.accept_token.cancel();
    }

    /// Cancels every connection supervisor in the set.
    pub fn cancel_connections(&self) {
        self.connection_token.cancel();
    }
}

impl ListenerSet {
    /// Binds every source first, then starts one accept loop per listener.
    ///
    /// Binding all sockets before any accept means a configuration that
    /// cannot open fails without ever admitting a connection.
    pub fn start(
        specs: Vec<ListenerSpec>,
        context: ListenerContext,
        parent: &CancellationToken,
    ) -> Result<Self, ListenerError> {
        if parent.is_cancelled() {
            return Err(ListenerError::Cancelled);
        }
        let accept_token = parent.child().map_err(|_| ListenerError::Cancelled)?;
        let connection_token = parent.child().map_err(|_| ListenerError::Cancelled)?;
        let shared = Arc::new(ListenerShared {
            budget: context.budget,
            handshakes: context.handshakes,
            client_slots: context.client_slots,
            admission: context.admission,
            observer: context.observer,
            inbox: context.inbox,
            limits: context.limits,
            generations: AtomicU64::new(1),
        });
        let mut bound = Vec::with_capacity(specs.len());
        for spec in specs {
            let validated = validate_spec(&spec)?;
            let (listener, address) = socket::bind(spec.source)?;
            if listener.is_unix() != uses_unix_socket(validated.purpose) {
                return Err(ListenerError::SourceMismatch);
            }
            bound.push((validated, listener, address));
        }
        let mut tasks = JoinSet::new();
        let mut addresses = Vec::with_capacity(bound.len());
        for (spec, listener, address) in bound {
            addresses.push((spec.purpose, address));
            tasks.spawn(run_listener(
                listener,
                spec,
                Arc::clone(&shared),
                accept_token.clone(),
                connection_token.clone(),
            ));
        }
        Ok(Self {
            tasks,
            addresses,
            accept_token,
            connection_token,
        })
    }

    /// Returns the bound address of every listener in configuration order.
    #[must_use]
    pub fn addresses(&self) -> &[(ListenerPurpose, BoundAddress)] {
        &self.addresses
    }

    /// Returns shutdown authority that may outlive this owner handle.
    #[must_use]
    pub fn control(&self) -> ListenerControl {
        ListenerControl {
            accept_token: self.accept_token.clone(),
            connection_token: self.connection_token.clone(),
        }
    }

    /// Stops every accept loop; connections keep running (quiesce, spec
    /// line 4256).
    pub fn stop_accepting(&self) {
        self.accept_token.cancel();
    }

    /// Cancels every connection supervisor (stop, spec line 4261).
    pub fn cancel_connections(&self) {
        self.connection_token.cancel();
    }

    /// Waits for every listener task, each of which joins its connections.
    pub async fn join(mut self) -> Vec<ListenerExit> {
        let mut exits = Vec::with_capacity(self.addresses.len());
        while let Some(joined) = self.tasks.join_next().await {
            if let Ok(exit) = joined {
                exits.push(exit);
            }
        }
        exits
    }
}

fn uses_unix_socket(purpose: ListenerPurpose) -> bool {
    matches!(
        purpose,
        ListenerPurpose::ClientOnion | ListenerPurpose::AdminLocal
    )
}

fn validate_spec(spec: &ListenerSpec) -> Result<ValidatedSpec, ListenerError> {
    let ceiling = match spec.purpose {
        ListenerPurpose::ClientTls | ListenerPurpose::ClientOnion => MAX_CLIENT_CONNECTIONS,
        ListenerPurpose::AdminLocal | ListenerPurpose::AdminTls => MAX_ADMIN_CONNECTIONS,
        ListenerPurpose::ClientWss | ListenerPurpose::Federation => {
            return Err(ListenerError::UnsupportedPurpose);
        }
    };
    if spec.max_connections == 0 || spec.max_connections > ceiling {
        return Err(ListenerError::ConnectionCeiling);
    }
    let profile = TlsEndpointProfile::for_purpose(spec.purpose);
    match (profile, &spec.tls) {
        (Some(_), None) => return Err(ListenerError::MissingTls),
        (None, Some(_)) => return Err(ListenerError::UnexpectedTls),
        _ => {}
    }
    Ok(ValidatedSpec {
        purpose: spec.purpose,
        max_connections: spec.max_connections,
        tls: spec.tls.clone(),
        profile,
    })
}

/// A socket accepted with the listener and handshake slots already held.
struct Accepted {
    transport: AcceptedTransport,
    listener_slot: OwnedSemaphorePermit,
    handshake_slot: Option<OwnedSemaphorePermit>,
}

enum AcceptedTransport {
    Tcp(TcpStream, SourceAddressKey),
    Unix(UnixStream),
}

enum ListenerStep {
    Stop,
    Joined(Option<ConnectionOutcome>),
    Accepted(Option<Accepted>),
}

async fn run_listener(
    listener: BoundListener,
    spec: ValidatedSpec,
    shared: Arc<ListenerShared>,
    accept_token: CancellationToken,
    connection_token: CancellationToken,
) -> ListenerExit {
    let slots = Arc::new(Semaphore::new(spec.max_connections));
    let mut connections: JoinSet<ConnectionOutcome> = JoinSet::new();
    let mut exit = ListenerExit {
        purpose: spec.purpose,
        admitted: 0,
        refused: 0,
    };
    loop {
        let step = tokio::select! {
            () = accept_token.cancelled() => ListenerStep::Stop,
            Some(outcome) = connections.join_next() => ListenerStep::Joined(outcome.ok()),
            accepted = next_accept(&listener, &slots, &shared.handshakes, spec.tls.is_some()) => {
                ListenerStep::Accepted(accepted)
            }
        };
        match step {
            ListenerStep::Stop => break,
            ListenerStep::Joined(outcome) => {
                record_outcome(&shared, spec.purpose, outcome, &mut exit)
            }
            ListenerStep::Accepted(Some(accepted)) => {
                admit(
                    accepted,
                    &spec,
                    &shared,
                    &connection_token,
                    &mut connections,
                    &mut exit,
                );
            }
            ListenerStep::Accepted(None) => tokio::time::sleep(ACCEPT_BACKOFF).await,
        }
    }
    drop(listener);
    while let Some(outcome) = connections.join_next().await {
        record_outcome(&shared, spec.purpose, outcome.ok(), &mut exit);
    }
    exit
}

fn record_outcome(
    shared: &ListenerShared,
    purpose: ListenerPurpose,
    outcome: Option<ConnectionOutcome>,
    exit: &mut ListenerExit,
) {
    match outcome {
        Some(ConnectionOutcome::Served(connection, source)) => {
            exit.admitted = exit.admitted.saturating_add(1);
            shared.observer.closed(&connection);
            shared.admission.released(purpose, source);
        }
        Some(ConnectionOutcome::Refused(reason)) => {
            exit.refused = exit.refused.saturating_add(1);
            shared.observer.refused(purpose, reason);
        }
        None => exit.refused = exit.refused.saturating_add(1),
    }
}

/// Holds a listener slot and, for TLS listeners, a handshake slot, then
/// accepts one socket; `None` means a transient accept failure.
async fn next_accept(
    listener: &BoundListener,
    slots: &Arc<Semaphore>,
    handshakes: &HandshakeLimiter,
    tls: bool,
) -> Option<Accepted> {
    let listener_slot = Arc::clone(slots).acquire_owned().await.ok()?;
    let handshake_slot = if tls {
        Some(handshakes.acquire().await.ok()?)
    } else {
        None
    };
    let transport = match listener {
        BoundListener::Tcp(listener) => {
            let (stream, peer) = listener.accept().await.ok()?;
            AcceptedTransport::Tcp(stream, source_key(peer))
        }
        BoundListener::Unix(listener) => {
            let (stream, _) = listener.accept().await.ok()?;
            AcceptedTransport::Unix(stream)
        }
    };
    Some(Accepted {
        transport,
        listener_slot,
        handshake_slot,
    })
}

/// The accept-path checks of spec lines 2784-2790; a refusal drops the
/// socket here, before TLS and before any task exists.
fn admit(
    accepted: Accepted,
    spec: &ValidatedSpec,
    shared: &Arc<ListenerShared>,
    connection_token: &CancellationToken,
    connections: &mut JoinSet<ConnectionOutcome>,
    exit: &mut ListenerExit,
) {
    let source = match &accepted.transport {
        AcceptedTransport::Tcp(_, source) => *source,
        AcceptedTransport::Unix(_) => SourceAddressKey::onion_listener(),
    };
    let admission = match prepare_admission(shared, spec, connection_token, source) {
        Ok(admission) => admission,
        Err(reason) => {
            exit.refused = exit.refused.saturating_add(1);
            shared.observer.refused(spec.purpose, reason);
            return;
        }
    };
    let generation = ConnectionGeneration::new(shared.generations.fetch_add(1, Ordering::Relaxed));
    let admitted = AdmittedConnection {
        generation,
        purpose: spec.purpose,
        source,
        peer: PeerIdentity::Anonymous,
    };
    let endpoint = Endpoint {
        tls: spec.tls.clone(),
        profile: spec.profile,
        shared: Arc::clone(shared),
    };
    connections.spawn(serve(accepted, admitted, admission, endpoint));
}

/// The global slot, admission verdict, memory charges, and child token an
/// admitted socket needs, acquired in spec order.
struct Admission {
    global_slot: Option<OwnedSemaphorePermit>,
    permits: MemoryPermitBatch,
    token: CancellationToken,
}

fn prepare_admission(
    shared: &ListenerShared,
    spec: &ValidatedSpec,
    connection_token: &CancellationToken,
    source: SourceAddressKey,
) -> Result<Admission, RefusalReason> {
    let global_slot = global_slot(shared, spec.purpose)?;
    if shared.admission.admit(spec.purpose, source) == AdmissionVerdict::Refuse {
        return Err(RefusalReason::Admission);
    }
    let permits = acquire_charges(shared, spec).map_err(|_| RefusalReason::MemoryExhausted)?;
    let token = connection_token
        .child()
        .map_err(|_| RefusalReason::TaskTree)?;
    Ok(Admission {
        global_slot,
        permits,
        token,
    })
}

fn global_slot(
    shared: &ListenerShared,
    purpose: ListenerPurpose,
) -> Result<Option<OwnedSemaphorePermit>, RefusalReason> {
    if !matches!(
        purpose,
        ListenerPurpose::ClientTls | ListenerPurpose::ClientOnion
    ) {
        return Ok(None);
    }
    Arc::clone(&shared.client_slots)
        .try_acquire_owned()
        .map(Some)
        .map_err(|_| RefusalReason::GlobalCeiling)
}

fn acquire_charges(
    shared: &ListenerShared,
    spec: &ValidatedSpec,
) -> Result<MemoryPermitBatch, RuntimeError> {
    let base = match spec.purpose {
        ListenerPurpose::AdminLocal | ListenerPurpose::AdminTls => ADMIN_CONNECTION_BASE_BYTES,
        _ => CLIENT_CONNECTION_BASE_BYTES,
    };
    let mut charges = vec![
        MemoryCharge::fixed(base),
        shared.limits.queue.backing_charge()?,
    ];
    if spec.tls.is_some() {
        charges.push(MemoryCharge::fixed(TLS_SETUP_INCREMENT_BYTES));
    }
    Ok(shared
        .budget
        .try_acquire_batch(BoundedMemoryCharges::new(charges)?)?)
}

enum ConnectionOutcome {
    Served(ConnectionExit, SourceAddressKey),
    Refused(RefusalReason),
}

/// The listener facts one connection task carries.
struct Endpoint {
    tls: Option<Arc<ServerConfig>>,
    profile: Option<TlsEndpointProfile>,
    shared: Arc<ListenerShared>,
}

async fn serve(
    accepted: Accepted,
    admitted: AdmittedConnection,
    admission: Admission,
    endpoint: Endpoint,
) -> ConnectionOutcome {
    let source = admitted.source;
    match serve_inner(accepted, admitted, admission, endpoint).await {
        Ok(exit) => ConnectionOutcome::Served(exit, source),
        Err(reason) => ConnectionOutcome::Refused(reason),
    }
}

async fn serve_inner(
    accepted: Accepted,
    mut admitted: AdmittedConnection,
    admission: Admission,
    endpoint: Endpoint,
) -> Result<ConnectionExit, RefusalReason> {
    let Accepted {
        transport,
        listener_slot,
        handshake_slot,
    } = accepted;
    let Admission {
        global_slot,
        mut permits,
        token,
    } = admission;
    let queue_backing = endpoint
        .shared
        .limits
        .queue
        .backing_charge()
        .ok()
        .and_then(|charge| permits.split_exact(charge.bytes()))
        .ok_or(RefusalReason::MemoryExhausted)?;
    let resources = move |permits| ConnectionResources {
        permits,
        global_slot,
        listener_slot,
        queue_backing,
    };
    match (transport, endpoint.tls, endpoint.profile) {
        (AcceptedTransport::Tcp(stream, _), Some(config), Some(profile)) => {
            let stream = negotiate(stream, config, profile, handshake_slot, &mut permits).await?;
            admitted.peer = tls_peer_identity(&stream, profile)?;
            Ok(finish_serving(stream, admitted, resources(permits), endpoint.shared, token).await)
        }
        (AcceptedTransport::Unix(stream), Some(config), Some(profile)) => {
            let stream = negotiate(stream, config, profile, handshake_slot, &mut permits).await?;
            Ok(finish_serving(stream, admitted, resources(permits), endpoint.shared, token).await)
        }
        (AcceptedTransport::Unix(stream), None, None) => {
            admitted.peer = local_peer_identity(&stream)?;
            Ok(finish_serving(stream, admitted, resources(permits), endpoint.shared, token).await)
        }
        _ => Err(RefusalReason::TlsHandshake(TlsHandshakeError::Protocol)),
    }
}

/// Completes the handshake, then releases the handshake slot and the TLS
/// setup increment (spec lines 2788-2789).
async fn negotiate<S>(
    stream: S,
    config: Arc<ServerConfig>,
    profile: TlsEndpointProfile,
    handshake_slot: Option<OwnedSemaphorePermit>,
    permits: &mut MemoryPermitBatch,
) -> Result<TlsStream<S>, RefusalReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream = TlsStream::handshake(stream, config, profile.alpn(), ACCEPT_TO_TLS_DEADLINE)
        .await
        .map_err(RefusalReason::TlsHandshake)?;
    drop(handshake_slot);
    drop(permits.split_exact(TLS_SETUP_INCREMENT_BYTES));
    Ok(stream)
}

fn tls_peer_identity<S>(
    stream: &TlsStream<S>,
    profile: TlsEndpointProfile,
) -> Result<PeerIdentity, RefusalReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !profile.requires_client_certificate() {
        return Ok(PeerIdentity::Anonymous);
    }
    stream
        .peer_certificates()
        .and_then(|chain| chain.first())
        .and_then(|leaf| spki_sha256(leaf.as_ref()))
        .map(|spki_sha256| PeerIdentity::ClientCertificate { spki_sha256 })
        .ok_or(RefusalReason::ClientCertificate)
}

fn local_peer_identity(stream: &UnixStream) -> Result<PeerIdentity, RefusalReason> {
    let credentials = stream
        .peer_cred()
        .map_err(|_| RefusalReason::PeerCredentials)?;
    Ok(PeerIdentity::LocalCredentials {
        uid: credentials.uid(),
        gid: credentials.gid(),
    })
}

async fn finish_serving<T>(
    transport: T,
    admitted: AdmittedConnection,
    resources: ConnectionResources,
    shared: Arc<ListenerShared>,
    token: CancellationToken,
) -> ConnectionExit
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    shared.observer.admitted(&admitted);
    run_connection(
        transport,
        admitted,
        resources,
        shared.limits,
        shared.inbox.clone(),
        token,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_pair_purposes_with_transports_and_ceilings() {
        let tcp = || ListenerSource::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
        let plain = ListenerSpec {
            purpose: ListenerPurpose::ClientTls,
            source: tcp(),
            max_connections: 1,
            tls: None,
        };
        assert_eq!(validate_spec(&plain).err(), Some(ListenerError::MissingTls));
        let wss = ListenerSpec {
            purpose: ListenerPurpose::ClientWss,
            source: tcp(),
            max_connections: 1,
            tls: None,
        };
        assert_eq!(
            validate_spec(&wss).err(),
            Some(ListenerError::UnsupportedPurpose)
        );
        let federation = ListenerSpec {
            purpose: ListenerPurpose::Federation,
            source: tcp(),
            max_connections: 1,
            tls: None,
        };
        assert_eq!(
            validate_spec(&federation).err(),
            Some(ListenerError::UnsupportedPurpose)
        );
        let zero = ListenerSpec {
            purpose: ListenerPurpose::AdminLocal,
            source: ListenerSource::Unix("/tmp/x".into()),
            max_connections: 0,
            tls: None,
        };
        assert_eq!(
            validate_spec(&zero).err(),
            Some(ListenerError::ConnectionCeiling)
        );
        let too_many = ListenerSpec {
            purpose: ListenerPurpose::AdminLocal,
            source: ListenerSource::Unix("/tmp/x".into()),
            max_connections: MAX_ADMIN_CONNECTIONS + 1,
            tls: None,
        };
        assert_eq!(
            validate_spec(&too_many).err(),
            Some(ListenerError::ConnectionCeiling)
        );
        let admin = ListenerSpec {
            purpose: ListenerPurpose::AdminLocal,
            source: ListenerSource::Unix("/tmp/x".into()),
            max_connections: MAX_ADMIN_CONNECTIONS,
            tls: None,
        };
        let validated = validate_spec(&admin).ok();
        assert!(validated.is_some_and(|spec| spec.profile.is_none() && spec.tls.is_none()));
        assert!(uses_unix_socket(ListenerPurpose::ClientOnion));
        assert!(!uses_unix_socket(ListenerPurpose::AdminTls));
        assert_eq!(
            PermissiveAdmission.admit(
                ListenerPurpose::ClientTls,
                SourceAddressKey::onion_listener()
            ),
            AdmissionVerdict::Admit
        );
        PermissiveAdmission.released(
            ListenerPurpose::ClientTls,
            SourceAddressKey::onion_listener(),
        );
        for reason in [
            RefusalReason::GlobalCeiling,
            RefusalReason::Admission,
            RefusalReason::MemoryExhausted,
            RefusalReason::TlsHandshake(TlsHandshakeError::Timeout),
            RefusalReason::PeerCredentials,
            RefusalReason::ClientCertificate,
            RefusalReason::TaskTree,
        ] {
            assert!(reason.to_string().is_ascii());
        }
    }
}
