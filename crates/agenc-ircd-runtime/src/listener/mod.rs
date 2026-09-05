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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::{JoinError, JoinSet};

use agenc_ircd_admin::{
    ADMIN_CHALLENGE_BYTES, ADMIN_SESSION_ID_BYTES, ADMIN_TRANSPORT_BINDING_BYTES, AdminChallenge,
    AdminSessionId, Challenge, PeerIdentity as AdminPeerIdentity, TransportBinding, TransportKind,
};
use agenc_ircd_config::ListenerName;
use agenc_ircd_types::{EntropySource as _, MonotonicTick};

pub use prefix::{PREFIX_ERASURE_DELAY, source_key};
pub use socket::{
    BoundAddress, ListenerError, ListenerSource, UNIX_SOCKET_DIRECTORY_MODE, UNIX_SOCKET_MODE,
};
pub use spki::spki_sha256;

use self::socket::BoundListener;
use crate::RuntimeError;
use crate::admin::{
    ADMIN_EXPORTER_LABEL, AdminConnectionStart, AdminTransportPort, run_admin_connection,
};
use crate::budget::{
    ADMIN_CONNECTION_BASE_BYTES, BoundedMemoryCharges, CLIENT_CONNECTION_BASE_BYTES, MemoryBudget,
    MemoryBudgetPort as _, MemoryCharge, MemoryPermitBatch, TLS_SETUP_INCREMENT_BYTES,
    WEBSOCKET_SETUP_INCREMENT_BYTES,
};
use crate::cancel::CancellationToken;
use crate::connection::supervisor::AdmissionLease;
use crate::connection::{
    AdmittedConnection, ConnectionExit, ConnectionGeneration, ConnectionLimits, ConnectionPolicy,
    ConnectionResources, PeerIdentity, run_connection,
};
use crate::federation::{AcceptedFederationSocket, MAX_FEDERATION_PEERS};
use crate::purpose::ListenerPurpose;
use crate::runtime_config::RuntimeConfigHandle;
use crate::state_core::inbox::{
    CloseReason, ConnectionClosePort, SourceAddressKey, StateCoreMessage,
};
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

/// Listener-local operating-system credential admission for `admin_local`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAdminAdmission {
    allowed_uids: Vec<u32>,
    allowed_gids: Vec<u32>,
}

impl LocalAdminAdmission {
    /// Validates the Appendix C.3 bounds and uniqueness rules.
    pub fn new(
        mut allowed_uids: Vec<u32>,
        mut allowed_gids: Vec<u32>,
    ) -> Result<Self, ListenerError> {
        if allowed_uids.is_empty()
            || allowed_uids.len() > MAX_ADMIN_CONNECTIONS
            || allowed_gids.len() > MAX_ADMIN_CONNECTIONS
        {
            return Err(ListenerError::AdminPolicy);
        }
        allowed_uids.sort_unstable();
        allowed_gids.sort_unstable();
        if allowed_uids
            .windows(2)
            .any(|pair| pair.first() == pair.get(1))
            || allowed_gids
                .windows(2)
                .any(|pair| pair.first() == pair.get(1))
        {
            return Err(ListenerError::AdminPolicy);
        }
        Ok(Self {
            allowed_uids,
            allowed_gids,
        })
    }

    fn admits(&self, uid: u32, gid: u32) -> bool {
        self.allowed_uids.binary_search(&uid).is_ok()
            || self.allowed_gids.binary_search(&gid).is_ok()
    }
}

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

    /// Records that a connection from `source` closed and returns the
    /// admission owner's physical-close tick when it owns one.
    fn released(
        &self,
        purpose: ListenerPurpose,
        source: SourceAddressKey,
    ) -> Option<MonotonicTick> {
        let _ = (purpose, source);
        None
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
    /// Administrative session entropy was unavailable.
    Entropy,
    /// No isolated administrative owner was available.
    AdminOwner,
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
            Self::Entropy => formatter.write_str("administrative session entropy unavailable"),
            Self::AdminOwner => formatter.write_str("administrative owner unavailable"),
            Self::TaskTree => formatter.write_str("task tree is full"),
        }
    }
}

impl Error for RefusalReason {}

/// Closed outcome of a completed TLS handshake attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsOutcome {
    /// TLS 1.3 and the exact listener ALPN completed.
    Established,
    /// The handshake timed out, failed, or negotiated the wrong ALPN.
    Refused,
}

/// Observes admissions, refusals, and closes for logging and metrics.
pub trait ConnectionObserver: Send + Sync {
    /// A configured listener began accepting its closed purpose.
    fn listener_opened(&self, purpose: ListenerPurpose) {
        let _ = purpose;
    }

    /// A configured listener stopped accepting and joined its children.
    fn listener_closed(&self, purpose: ListenerPurpose) {
        let _ = purpose;
    }

    /// A TLS handshake began after the global permit was acquired.
    fn tls_started(&self, purpose: ListenerPurpose) {
        let _ = purpose;
    }

    /// A TLS handshake released its permit, successfully or otherwise.
    fn tls_finished(&self, purpose: ListenerPurpose, elapsed_millis: u64, outcome: TlsOutcome) {
        let _ = (purpose, elapsed_millis, outcome);
    }

    /// A connection was admitted and its supervisor started.
    fn admitted(&self, connection: &AdmittedConnection) {
        let _ = connection;
    }

    /// An administrative connection was admitted after its raw source key
    /// had been discarded.
    fn admin_admitted(&self, purpose: ListenerPurpose, peer: PeerIdentity) {
        let _ = (purpose, peer);
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

/// One configured endpoint.
pub struct ListenerSpec {
    /// Stable configured name used to select live listener policy.
    pub name: ListenerName,
    /// The listener purpose.
    pub purpose: ListenerPurpose,
    /// Where its socket comes from.
    pub source: ListenerSource,
    /// The listener's own connection ceiling.
    pub max_connections: usize,
    /// The TLS configuration; required for TLS purposes, forbidden for
    /// local administration.
    pub tls: Option<Arc<ServerConfig>>,
    /// UID/GID admission for `admin_local`; absent for every other purpose.
    pub local_admin: Option<LocalAdminAdmission>,
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
    /// Reserved physical-close delivery to StateCore.
    pub connection_closes: ConnectionClosePort,
    /// Isolated administrative owner, absent when no admin listener is enabled.
    pub admin: Option<AdminTransportPort>,
    /// Per-connection reader and queue ceilings.
    pub limits: ConnectionLimits,
    /// Published live policy; absent only at an embedding or test seam.
    pub runtime_config: Option<RuntimeConfigHandle>,
    /// The federation link owner's accept queue; absent when no federation
    /// listener is enabled, in which case a federation socket is refused.
    pub federation_accepts: Option<mpsc::Sender<AcceptedFederationSocket>>,
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
    /// A connection task panicked or was aborted.
    pub task_failed: bool,
}

struct ListenerShared {
    budget: Arc<MemoryBudget>,
    handshakes: HandshakeLimiter,
    client_slots: Arc<Semaphore>,
    client_slot_capacity: usize,
    admission: Arc<dyn AcceptAdmission>,
    observer: Arc<dyn ConnectionObserver>,
    inbox: mpsc::Sender<StateCoreMessage>,
    connection_closes: ConnectionClosePort,
    admin: Option<AdminTransportPort>,
    limits: ConnectionLimits,
    runtime_config: Option<RuntimeConfigHandle>,
    federation_accepts: Option<mpsc::Sender<AcceptedFederationSocket>>,
    generations: AtomicU64,
}

struct ValidatedSpec {
    name: ListenerName,
    purpose: ListenerPurpose,
    max_connections: usize,
    tls: Option<Arc<ServerConfig>>,
    profile: Option<TlsEndpointProfile>,
    local_admin: Option<LocalAdminAdmission>,
}

/// The set of open listeners and their connection supervisors.
pub struct ListenerSet {
    tasks: JoinSet<ListenerExit>,
    addresses: Vec<(ListenerPurpose, BoundAddress)>,
    accept_token: CancellationToken,
    connection_token: CancellationToken,
    accept_barrier: Arc<AcceptBarrier>,
}

/// Cloneable shutdown authority for a listener set owned by another task.
#[derive(Clone)]
pub struct ListenerControl {
    accept_token: CancellationToken,
    connection_token: CancellationToken,
    accept_barrier: Arc<AcceptBarrier>,
}

struct AcceptBarrier {
    remaining: AtomicUsize,
    notify: tokio::sync::Notify,
}

impl AcceptBarrier {
    fn new(listeners: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(listeners),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn arrived(&self) {
        let previous =
            self.remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_sub(1)
                });
        if previous == Ok(1) {
            self.notify.notify_waiters();
        }
    }

    async fn wait(&self) {
        while self.remaining.load(Ordering::Acquire) != 0 {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.remaining.load(Ordering::Acquire) != 0 {
                notified.await;
            }
        }
    }
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

    /// Waits until every accept loop has dropped its listening socket.
    pub async fn wait_accept_stopped(&self) {
        self.accept_barrier.wait().await;
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
            client_slot_capacity: context.client_slots.available_permits(),
            client_slots: context.client_slots,
            admission: context.admission,
            observer: context.observer,
            inbox: context.inbox,
            connection_closes: context.connection_closes,
            admin: context.admin,
            limits: context.limits,
            runtime_config: context.runtime_config,
            federation_accepts: context.federation_accepts,
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
        let accept_barrier = Arc::new(AcceptBarrier::new(bound.len()));
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
                Arc::clone(&accept_barrier),
            ));
        }
        Ok(Self {
            tasks,
            addresses,
            accept_token,
            connection_token,
            accept_barrier,
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
            accept_barrier: Arc::clone(&self.accept_barrier),
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
    pub async fn join(mut self) -> Result<Vec<ListenerExit>, RuntimeError> {
        let mut exits = Vec::with_capacity(self.addresses.len());
        while let Some(joined) = self.tasks.join_next().await {
            let exit = joined.map_err(|_| RuntimeError::InvalidValue)?;
            exits.push(exit);
        }
        Ok(exits)
    }
}

fn uses_unix_socket(purpose: ListenerPurpose) -> bool {
    matches!(
        purpose,
        ListenerPurpose::ClientOnion | ListenerPurpose::AdminLocal
    )
}

fn validate_spec(spec: &ListenerSpec) -> Result<ValidatedSpec, ListenerError> {
    let ceiling = purpose_ceiling(spec.purpose)?;
    if spec.max_connections == 0 || spec.max_connections > ceiling {
        return Err(ListenerError::ConnectionCeiling);
    }
    let profile = TlsEndpointProfile::for_purpose(spec.purpose);
    match (profile, &spec.tls) {
        (Some(_), None) => return Err(ListenerError::MissingTls),
        (None, Some(_)) => return Err(ListenerError::UnexpectedTls),
        _ => {}
    }
    match (spec.purpose, &spec.local_admin) {
        (ListenerPurpose::AdminLocal, Some(_)) => {}
        (ListenerPurpose::AdminLocal, None) | (_, Some(_)) => {
            return Err(ListenerError::AdminPolicy);
        }
        (_, None) => {}
    }
    Ok(ValidatedSpec {
        name: spec.name.clone(),
        purpose: spec.purpose,
        max_connections: spec.max_connections,
        tls: spec.tls.clone(),
        profile,
        local_admin: spec.local_admin.clone(),
    })
}

fn purpose_ceiling(purpose: ListenerPurpose) -> Result<usize, ListenerError> {
    match purpose {
        ListenerPurpose::ClientTls | ListenerPurpose::ClientOnion => Ok(MAX_CLIENT_CONNECTIONS),
        ListenerPurpose::AdminLocal | ListenerPurpose::AdminTls => Ok(MAX_ADMIN_CONNECTIONS),
        ListenerPurpose::Federation => Ok(MAX_FEDERATION_PEERS),
        ListenerPurpose::ClientWss if cfg!(feature = "wss") => Ok(MAX_CLIENT_CONNECTIONS),
        ListenerPurpose::ClientWss => Err(ListenerError::UnsupportedPurpose),
    }
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
    Joined(Result<ConnectionOutcome, JoinError>),
    Accepted(Option<Accepted>),
}

// agenc-review: focus owner=runtime reviewed=2026-08-31 reason=the bounded listener loop keeps cancellation accept and joined-child outcomes in one closed dispatcher
async fn run_listener(
    listener: BoundListener,
    spec: ValidatedSpec,
    shared: Arc<ListenerShared>,
    accept_token: CancellationToken,
    connection_token: CancellationToken,
    accept_barrier: Arc<AcceptBarrier>,
) -> ListenerExit {
    shared.observer.listener_opened(spec.purpose);
    let slot_capacity = if shared.runtime_config.is_some() {
        purpose_ceiling(spec.purpose).unwrap_or(spec.max_connections)
    } else {
        spec.max_connections
    };
    let slots = Arc::new(Semaphore::new(slot_capacity));
    let mut connections: JoinSet<ConnectionOutcome> = JoinSet::new();
    let mut exit = ListenerExit {
        purpose: spec.purpose,
        admitted: 0,
        refused: 0,
        task_failed: false,
    };
    loop {
        let step = tokio::select! {
            () = accept_token.cancelled() => ListenerStep::Stop,
            Some(outcome) = connections.join_next() => ListenerStep::Joined(outcome),
            accepted = next_accept(&listener, &slots, slot_capacity, &shared, &spec) => {
                ListenerStep::Accepted(accepted)
            }
        };
        match step {
            ListenerStep::Stop => break,
            ListenerStep::Joined(outcome) => {
                if record_outcome(&shared, spec.purpose, outcome, &mut exit) {
                    accept_token.cancel();
                    connection_token.cancel();
                    break;
                }
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
    accept_barrier.arrived();
    while let Some(outcome) = connections.join_next().await {
        let _failed = record_outcome(&shared, spec.purpose, outcome, &mut exit);
    }
    shared.observer.listener_closed(spec.purpose);
    exit
}

fn record_outcome(
    shared: &ListenerShared,
    purpose: ListenerPurpose,
    outcome: Result<ConnectionOutcome, JoinError>,
    exit: &mut ListenerExit,
) -> bool {
    match outcome {
        Ok(ConnectionOutcome::Served(connection)) => {
            exit.admitted = exit.admitted.saturating_add(1);
            shared.observer.closed(&connection);
            false
        }
        Ok(ConnectionOutcome::Refused(reason)) => {
            exit.refused = exit.refused.saturating_add(1);
            shared.observer.refused(purpose, reason);
            false
        }
        Err(_error) => {
            exit.refused = exit.refused.saturating_add(1);
            exit.task_failed = true;
            shared.observer.refused(purpose, RefusalReason::TaskTree);
            true
        }
    }
}

/// Holds a listener slot and, for TLS listeners, a handshake slot, then
/// accepts one socket; `None` means a transient accept failure.
async fn next_accept(
    listener: &BoundListener,
    slots: &Arc<Semaphore>,
    slot_capacity: usize,
    shared: &ListenerShared,
    spec: &ValidatedSpec,
) -> Option<Accepted> {
    let listener_slot = Arc::clone(slots).acquire_owned().await.ok()?;
    if let Some(runtime) = &shared.runtime_config {
        let active = slot_capacity.saturating_sub(slots.available_permits());
        let ceiling = runtime.load().listener_ceiling(&spec.name)?;
        if active > ceiling {
            return None;
        }
    }
    let handshake_slot = if spec.tls.is_some() {
        let permit = shared.handshakes.acquire().await.ok()?;
        if let Some(runtime) = &shared.runtime_config {
            let active = shared
                .handshakes
                .capacity()
                .saturating_sub(shared.handshakes.available());
            let ceiling = runtime.load().tls_handshake_ceiling()?;
            if active > ceiling {
                return None;
            }
        }
        Some(permit)
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
    if spec.purpose == ListenerPurpose::Federation {
        hand_off_federation(accepted, spec, shared, exit);
        return;
    }
    let source = match &accepted.transport {
        AcceptedTransport::Tcp(_, source) => *source,
        AcceptedTransport::Unix(_) => SourceAddressKey::onion_listener(),
    };
    let (tls, limits) = match connection_policy(shared, spec) {
        Ok(policy) => policy,
        Err(reason) => {
            exit.refused = exit.refused.saturating_add(1);
            shared.observer.refused(spec.purpose, reason);
            return;
        }
    };
    let admission = match prepare_admission(
        shared,
        spec,
        connection_token,
        source,
        limits,
        tls.is_some(),
    ) {
        Ok(admission) => admission,
        Err(AdmissionFailure { reason, lease }) => {
            drop(accepted);
            drop(lease);
            exit.refused = exit.refused.saturating_add(1);
            shared.observer.refused(spec.purpose, reason);
            return;
        }
    };
    let accepted = accepted;
    let generation = ConnectionGeneration::new(shared.generations.fetch_add(1, Ordering::Relaxed));
    let mut admission = admission;
    if let Some(lease) = admission.lease.as_mut() {
        lease.assign_generation(generation);
    }
    let admitted = AdmittedConnection {
        generation,
        purpose: spec.purpose,
        source: source.prefix_key(),
        peer: PeerIdentity::Anonymous,
    };
    let endpoint = Endpoint {
        #[cfg(feature = "wss")]
        name: spec.name.clone(),
        tls,
        profile: spec.profile,
        shared: Arc::clone(shared),
        local_admin: spec.local_admin.clone(),
        limits,
    };
    connections.spawn(serve(accepted, admitted, admission, endpoint));
}

/// Hands an accepted federation socket to the link owner before TLS; the
/// owner completes the handshake, the hello, and every later frame.
fn hand_off_federation(
    accepted: Accepted,
    spec: &ValidatedSpec,
    shared: &Arc<ListenerShared>,
    exit: &mut ListenerExit,
) {
    let refuse = |exit: &mut ListenerExit, reason: RefusalReason| {
        exit.refused = exit.refused.saturating_add(1);
        shared.observer.refused(spec.purpose, reason);
    };
    let (Some(sink), Some(tls)) = (&shared.federation_accepts, spec.tls.clone()) else {
        refuse(exit, RefusalReason::PeerCredentials);
        return;
    };
    let AcceptedTransport::Tcp(stream, _) = accepted.transport else {
        refuse(exit, RefusalReason::Admission);
        return;
    };
    let socket =
        AcceptedFederationSocket::new(stream, tls, accepted.listener_slot, accepted.handshake_slot);
    if sink.try_send(socket).is_err() {
        refuse(exit, RefusalReason::GlobalCeiling);
        return;
    }
    exit.admitted = exit.admitted.saturating_add(1);
}

fn connection_policy(
    shared: &ListenerShared,
    spec: &ValidatedSpec,
) -> Result<(Option<Arc<ServerConfig>>, ConnectionLimits), RefusalReason> {
    let Some(runtime) = &shared.runtime_config else {
        return Ok((spec.tls.clone(), shared.limits));
    };
    let snapshot = runtime.load();
    let tls = match spec.profile {
        Some(_) => Some(
            snapshot
                .tls_endpoint(&spec.name)
                .ok_or(RefusalReason::TlsHandshake(TlsHandshakeError::Protocol))?,
        ),
        None => None,
    };
    Ok((tls, snapshot.connection_limits()))
}

/// The global slot, admission verdict, memory charges, and child token an
/// admitted socket needs, acquired in spec order.
struct Admission {
    global_slot: Option<OwnedSemaphorePermit>,
    permits: MemoryPermitBatch,
    token: CancellationToken,
    lease: Option<AdmissionLease>,
}

struct AdmissionFailure {
    reason: RefusalReason,
    lease: Option<AdmissionLease>,
}

fn prepare_admission(
    shared: &ListenerShared,
    spec: &ValidatedSpec,
    connection_token: &CancellationToken,
    source: SourceAddressKey,
    limits: ConnectionLimits,
    tls: bool,
) -> Result<Admission, AdmissionFailure> {
    let global_slot = global_slot(shared, spec.purpose).map_err(|reason| AdmissionFailure {
        reason,
        lease: None,
    })?;
    let address_accounted = !matches!(
        spec.purpose,
        ListenerPurpose::AdminLocal | ListenerPurpose::AdminTls
    );
    let purpose = spec.purpose;
    let close_permit = if address_accounted {
        Some(
            shared
                .connection_closes
                .try_reserve()
                .map_err(|_| AdmissionFailure {
                    reason: RefusalReason::TaskTree,
                    lease: None,
                })?,
        )
    } else {
        None
    };
    let Ok(permits) = acquire_charges(shared, spec.purpose, limits, tls) else {
        return Err(AdmissionFailure {
            reason: RefusalReason::MemoryExhausted,
            lease: None,
        });
    };
    let Ok(token) = connection_token.child() else {
        return Err(AdmissionFailure {
            reason: RefusalReason::TaskTree,
            lease: None,
        });
    };
    let lease = if let Some(close_permit) = close_permit {
        if shared.admission.admit(spec.purpose, source) == AdmissionVerdict::Refuse {
            return Err(AdmissionFailure {
                reason: RefusalReason::Admission,
                lease: None,
            });
        }
        let admission = Arc::clone(&shared.admission);
        Some(AdmissionLease::new(
            Box::new(move || admission.released(purpose, source)),
            close_permit,
        ))
    } else {
        None
    };
    Ok(Admission {
        global_slot,
        permits,
        token,
        lease,
    })
}

fn global_slot(
    shared: &ListenerShared,
    purpose: ListenerPurpose,
) -> Result<Option<OwnedSemaphorePermit>, RefusalReason> {
    if !matches!(
        purpose,
        ListenerPurpose::ClientTls | ListenerPurpose::ClientOnion | ListenerPurpose::ClientWss
    ) {
        return Ok(None);
    }
    let permit = Arc::clone(&shared.client_slots)
        .try_acquire_owned()
        .map_err(|_| RefusalReason::GlobalCeiling)?;
    if let Some(runtime) = &shared.runtime_config {
        let active = shared
            .client_slot_capacity
            .saturating_sub(shared.client_slots.available_permits());
        let ceiling = runtime
            .load()
            .client_connection_ceiling()
            .ok_or(RefusalReason::GlobalCeiling)?;
        if active > ceiling {
            return Err(RefusalReason::GlobalCeiling);
        }
    }
    Ok(Some(permit))
}

fn acquire_charges(
    shared: &ListenerShared,
    purpose: ListenerPurpose,
    limits: ConnectionLimits,
    tls: bool,
) -> Result<MemoryPermitBatch, RuntimeError> {
    shared
        .budget
        .try_acquire_batch(connection_charges(purpose, limits, tls)?)
        .map_err(Into::into)
}

fn connection_charges(
    purpose: ListenerPurpose,
    limits: ConnectionLimits,
    tls: bool,
) -> Result<BoundedMemoryCharges, RuntimeError> {
    let base = match purpose {
        ListenerPurpose::AdminLocal | ListenerPurpose::AdminTls => ADMIN_CONNECTION_BASE_BYTES,
        _ => CLIENT_CONNECTION_BASE_BYTES,
    };
    let base = MemoryCharge::fixed(base);
    let queue = limits.queue.backing_charge()?;
    let charges = if purpose == ListenerPurpose::ClientWss {
        BoundedMemoryCharges::new(&[
            base,
            queue,
            MemoryCharge::fixed(TLS_SETUP_INCREMENT_BYTES),
            MemoryCharge::fixed(WEBSOCKET_SETUP_INCREMENT_BYTES),
        ])?
    } else if tls {
        BoundedMemoryCharges::new(&[base, queue, MemoryCharge::fixed(TLS_SETUP_INCREMENT_BYTES)])?
    } else {
        BoundedMemoryCharges::new(&[base, queue])?
    };
    Ok(charges)
}

enum ConnectionOutcome {
    Served(ConnectionExit),
    Refused(RefusalReason),
}

/// The listener facts one connection task carries.
struct Endpoint {
    #[cfg(feature = "wss")]
    name: ListenerName,
    tls: Option<Arc<ServerConfig>>,
    profile: Option<TlsEndpointProfile>,
    shared: Arc<ListenerShared>,
    local_admin: Option<LocalAdminAdmission>,
    limits: ConnectionLimits,
}

async fn serve(
    accepted: Accepted,
    admitted: AdmittedConnection,
    admission: Admission,
    endpoint: Endpoint,
) -> ConnectionOutcome {
    match serve_inner(accepted, admitted, admission, endpoint).await {
        Ok(exit) => ConnectionOutcome::Served(exit),
        Err(reason) => ConnectionOutcome::Refused(reason),
    }
}

// agenc-review: focus owner=runtime reviewed=2026-08-30 reason=closed transport profile dispatch separates authenticated admin and public ownership while retaining bounded connection resources
async fn serve_inner(
    accepted: Accepted,
    mut admitted: AdmittedConnection,
    admission: Admission,
    endpoint: Endpoint,
) -> Result<ConnectionExit, RefusalReason> {
    let Admission {
        global_slot,
        mut permits,
        token,
        mut lease,
    } = admission;
    let Accepted {
        transport,
        listener_slot,
        handshake_slot,
    } = accepted;
    let queue_backing = endpoint
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
            endpoint.shared.observer.tls_started(admitted.purpose);
            let handshake_started = Instant::now();
            let negotiated = negotiate(stream, config, profile, handshake_slot, &mut permits).await;
            endpoint.shared.observer.tls_finished(
                admitted.purpose,
                u64::try_from(handshake_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                if negotiated.is_ok() {
                    TlsOutcome::Established
                } else {
                    TlsOutcome::Refused
                },
            );
            let stream = negotiated?;
            #[cfg(feature = "wss")]
            let tls_completed = Instant::now();
            admitted.peer = tls_peer_identity(&stream, profile)?;
            #[cfg(feature = "wss")]
            if admitted.purpose == ListenerPurpose::ClientWss {
                let origin_allowed = |origin: Option<&str>| {
                    let Some(runtime) = endpoint.shared.runtime_config.as_ref() else {
                        return false;
                    };
                    let snapshot = runtime.load();
                    let Some(policy) = snapshot
                        .config()
                        .listeners
                        .iter()
                        .find(|listener| listener.name == endpoint.name)
                        .and_then(|listener| listener.wss.as_ref())
                    else {
                        return false;
                    };
                    match origin {
                        Some(origin) => policy
                            .allowed_origins
                            .iter()
                            .any(|allowed| allowed.as_str() == origin),
                        None => policy.allow_missing_origin,
                    }
                };
                let stream = crate::wss::upgrade(
                    stream,
                    tls_completed,
                    &endpoint.shared.budget,
                    origin_allowed,
                    &token,
                )
                .await?;
                // The upgrade future and its header buffer are gone now.
                drop(permits.split_exact(WEBSOCKET_SETUP_INCREMENT_BYTES));
                let lease = lease.take().ok_or(RefusalReason::Admission)?;
                endpoint.shared.observer.admitted(&admitted);
                let policy =
                    ConnectionPolicy::new(endpoint.limits, endpoint.shared.runtime_config.clone())
                        .with_registration_started(tls_completed);
                return Ok(run_connection(
                    stream,
                    admitted,
                    resources(permits),
                    policy,
                    endpoint.shared.inbox.clone(),
                    token,
                    lease,
                )
                .await);
            }
            if admitted.purpose == ListenerPurpose::AdminTls {
                let port = endpoint
                    .shared
                    .admin
                    .clone()
                    .ok_or(RefusalReason::AdminOwner)?;
                let challenge = tls_admin_challenge(&stream, &port)?;
                return Ok(finish_admin_serving(
                    stream,
                    admitted,
                    resources(permits),
                    endpoint.shared,
                    token,
                    challenge,
                    port,
                )
                .await);
            }
            let lease = lease.take().ok_or(RefusalReason::Admission)?;
            Ok(finish_serving(
                stream,
                admitted,
                resources(permits),
                endpoint.shared,
                endpoint.limits,
                token,
                lease,
            )
            .await)
        }
        (AcceptedTransport::Unix(stream), Some(config), Some(profile)) => {
            endpoint.shared.observer.tls_started(admitted.purpose);
            let handshake_started = Instant::now();
            let negotiated = negotiate(stream, config, profile, handshake_slot, &mut permits).await;
            endpoint.shared.observer.tls_finished(
                admitted.purpose,
                u64::try_from(handshake_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                if negotiated.is_ok() {
                    TlsOutcome::Established
                } else {
                    TlsOutcome::Refused
                },
            );
            let stream = negotiated?;
            let lease = lease.take().ok_or(RefusalReason::Admission)?;
            Ok(finish_serving(
                stream,
                admitted,
                resources(permits),
                endpoint.shared,
                endpoint.limits,
                token,
                lease,
            )
            .await)
        }
        (AcceptedTransport::Unix(stream), None, None) => {
            admitted.peer = local_peer_identity(&stream)?;
            if admitted.purpose == ListenerPurpose::AdminLocal {
                let PeerIdentity::LocalCredentials { uid, gid } = admitted.peer else {
                    return Err(RefusalReason::PeerCredentials);
                };
                if !endpoint
                    .local_admin
                    .as_ref()
                    .is_some_and(|policy| policy.admits(uid, gid))
                {
                    return Err(RefusalReason::PeerCredentials);
                }
                let port = endpoint
                    .shared
                    .admin
                    .clone()
                    .ok_or(RefusalReason::AdminOwner)?;
                let challenge = local_admin_challenge()?;
                return Ok(finish_admin_serving(
                    stream,
                    admitted,
                    resources(permits),
                    endpoint.shared,
                    token,
                    challenge,
                    port,
                )
                .await);
            }
            let lease = lease.take().ok_or(RefusalReason::Admission)?;
            Ok(finish_serving(
                stream,
                admitted,
                resources(permits),
                endpoint.shared,
                endpoint.limits,
                token,
                lease,
            )
            .await)
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

fn fresh_admin_material<const N: usize>() -> Result<[u8; N], RefusalReason> {
    let mut bytes = [0_u8; N];
    let mut entropy = agenc_ircd_crypto::OsEntropy;
    entropy
        .fill_exact(&mut bytes)
        .map_err(|_| RefusalReason::Entropy)?;
    Ok(bytes)
}

fn local_admin_challenge() -> Result<AdminChallenge, RefusalReason> {
    Ok(AdminChallenge::new(
        AdminSessionId::from_bytes(fresh_admin_material::<ADMIN_SESSION_ID_BYTES>()?),
        Challenge::from_bytes(fresh_admin_material::<ADMIN_CHALLENGE_BYTES>()?),
        TransportKind::Local,
        TransportBinding::from_bytes(fresh_admin_material::<ADMIN_TRANSPORT_BINDING_BYTES>()?),
    ))
}

fn tls_admin_challenge<S>(
    stream: &TlsStream<S>,
    port: &AdminTransportPort,
) -> Result<AdminChallenge, RefusalReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session_id = AdminSessionId::from_bytes(fresh_admin_material::<ADMIN_SESSION_ID_BYTES>()?);
    let binding = port.binding();
    let mut context = [0_u8; 32 + 16 + ADMIN_SESSION_ID_BYTES];
    context[..32].copy_from_slice(binding.network_id.as_bytes());
    context[32..48].copy_from_slice(binding.server_id.as_bytes());
    context[48..].copy_from_slice(session_id.as_bytes());
    let mut exporter = [0_u8; ADMIN_TRANSPORT_BINDING_BYTES];
    stream
        .export_keying_material(&mut exporter, ADMIN_EXPORTER_LABEL, &context)
        .map_err(|_| RefusalReason::TlsHandshake(TlsHandshakeError::Protocol))?;
    Ok(AdminChallenge::new(
        session_id,
        Challenge::from_bytes(fresh_admin_material::<ADMIN_CHALLENGE_BYTES>()?),
        TransportKind::Tls,
        TransportBinding::from_bytes(exporter),
    ))
}

async fn finish_admin_serving<T>(
    transport: T,
    admitted: AdmittedConnection,
    resources: ConnectionResources,
    shared: Arc<ListenerShared>,
    token: CancellationToken,
    challenge: AdminChallenge,
    port: AdminTransportPort,
) -> ConnectionExit
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let AdmittedConnection {
        generation,
        purpose,
        source: _,
        peer,
    } = admitted;
    shared.observer.admin_admitted(purpose, peer);
    let peer = match peer {
        PeerIdentity::LocalCredentials { uid, gid } => AdminPeerIdentity::Local { uid, gid },
        PeerIdentity::ClientCertificate { spki_sha256 } => AdminPeerIdentity::Pin(spki_sha256),
        PeerIdentity::Anonymous => {
            return ConnectionExit {
                generation,
                purpose,
                reason: CloseReason::ProtocolError,
            };
        }
    };
    run_admin_connection(
        transport,
        AdminConnectionStart {
            generation,
            purpose,
            resources,
            challenge,
            peer,
            port,
            token,
        },
    )
    .await
}

async fn finish_serving<T>(
    transport: T,
    admitted: AdmittedConnection,
    resources: ConnectionResources,
    shared: Arc<ListenerShared>,
    limits: ConnectionLimits,
    token: CancellationToken,
    lease: AdmissionLease,
) -> ConnectionExit
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    shared.observer.admitted(&admitted);
    let policy = ConnectionPolicy::new(limits, shared.runtime_config.clone());
    run_connection(
        transport,
        admitted,
        resources,
        policy,
        shared.inbox.clone(),
        token,
        lease,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "wss")]
    fn websocket_setup_is_reserved_before_spawn_and_released_after_upgrade()
    -> Result<(), RuntimeError> {
        let limits = ConnectionLimits::DEFAULT;
        let queue = limits.queue.backing_charge()?.bytes();
        let budget = MemoryBudget::new(16 * 1_048_576);
        let charges = connection_charges(ListenerPurpose::ClientWss, limits, true)?;
        assert_eq!(
            charges.total(),
            CLIENT_CONNECTION_BASE_BYTES
                + queue
                + TLS_SETUP_INCREMENT_BYTES
                + WEBSOCKET_SETUP_INCREMENT_BYTES
        );
        let mut held = budget.try_acquire_batch(charges)?;
        let tls = held
            .split_exact(TLS_SETUP_INCREMENT_BYTES)
            .ok_or(RuntimeError::InvalidValue)?;
        drop(tls);
        let upgrade = held
            .split_exact(WEBSOCKET_SETUP_INCREMENT_BYTES)
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            budget.charged(),
            CLIENT_CONNECTION_BASE_BYTES + queue + WEBSOCKET_SETUP_INCREMENT_BYTES
        );
        drop(upgrade);
        assert_eq!(budget.charged(), CLIENT_CONNECTION_BASE_BYTES + queue);
        drop(held);
        assert_eq!(budget.charged(), 0);
        let insufficient = MemoryBudget::new(charges.total() - 1);
        assert!(insufficient.try_acquire_batch(charges).is_err());
        assert_eq!(insufficient.charged(), 0);
        Ok(())
    }

    #[test]
    fn specs_pair_purposes_with_transports_and_ceilings() -> Result<(), Box<dyn std::error::Error>>
    {
        let tcp = || ListenerSource::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
        let local_policy = || LocalAdminAdmission {
            allowed_uids: vec![1],
            allowed_gids: Vec::new(),
        };
        let plain = ListenerSpec {
            name: ListenerName::parse("test")?,
            purpose: ListenerPurpose::ClientTls,
            source: tcp(),
            max_connections: 1,
            tls: None,
            local_admin: None,
        };
        assert_eq!(validate_spec(&plain).err(), Some(ListenerError::MissingTls));
        let wss = ListenerSpec {
            name: ListenerName::parse("test")?,
            purpose: ListenerPurpose::ClientWss,
            source: tcp(),
            max_connections: 1,
            tls: None,
            local_admin: None,
        };
        assert_eq!(
            validate_spec(&wss).err(),
            Some(if cfg!(feature = "wss") {
                ListenerError::MissingTls
            } else {
                ListenerError::UnsupportedPurpose
            })
        );
        let federation = ListenerSpec {
            name: ListenerName::parse("test")?,
            purpose: ListenerPurpose::Federation,
            source: tcp(),
            max_connections: 1,
            tls: None,
            local_admin: None,
        };
        assert_eq!(
            validate_spec(&federation).err(),
            Some(ListenerError::MissingTls)
        );
        let oversized_federation = ListenerSpec {
            max_connections: MAX_FEDERATION_PEERS + 1,
            ..federation
        };
        assert_eq!(
            validate_spec(&oversized_federation).err(),
            Some(ListenerError::ConnectionCeiling)
        );
        let zero = ListenerSpec {
            name: ListenerName::parse("test")?,
            purpose: ListenerPurpose::AdminLocal,
            source: ListenerSource::Unix("/tmp/x".into()),
            max_connections: 0,
            tls: None,
            local_admin: Some(local_policy()),
        };
        assert_eq!(
            validate_spec(&zero).err(),
            Some(ListenerError::ConnectionCeiling)
        );
        let too_many = ListenerSpec {
            name: ListenerName::parse("test")?,
            purpose: ListenerPurpose::AdminLocal,
            source: ListenerSource::Unix("/tmp/x".into()),
            max_connections: MAX_ADMIN_CONNECTIONS + 1,
            tls: None,
            local_admin: Some(local_policy()),
        };
        assert_eq!(
            validate_spec(&too_many).err(),
            Some(ListenerError::ConnectionCeiling)
        );
        let admin = ListenerSpec {
            name: ListenerName::parse("test")?,
            purpose: ListenerPurpose::AdminLocal,
            source: ListenerSource::Unix("/tmp/x".into()),
            max_connections: MAX_ADMIN_CONNECTIONS,
            tls: None,
            local_admin: Some(local_policy()),
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
        let _closed_at = PermissiveAdmission.released(
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
        Ok(())
    }
}
