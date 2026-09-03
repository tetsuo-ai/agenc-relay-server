//! Federation link ownership: identities, transport, the authenticated hello,
//! and the bounded reader and writer loops (spec 20.2 to 20.4, 21.2, 21.3).
//!
//! A link is one TLS connection between this node and one configured peer.
//! The link task owns the socket, framing, fragment reassembly, and the
//! keepalive; it hands complete typed frames and objects to the state owner
//! through one bounded channel and takes rendered lines back through another.
//! Nothing here executes protocol state: that is `StateCore`'s job.

pub mod certificate;
pub mod dial;
pub mod hello;
pub mod line;
pub mod link;

use std::fmt;
use std::sync::Arc;

use agenc_ircd_config::{NodeRole, PeerConfig};
use agenc_ircd_crypto::{Ed25519PublicKey, Ed25519SecretKey};
use agenc_ircd_federation_wire::{
    AssembledObject, AssemblyError, EpochTransition, EventDescriptor, FederationFrame,
    FederationFrameKind, FederationHash32, OperationDescriptor, OriginDescriptor,
};
use agenc_ircd_types::{
    FederationRole, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation, ServerName,
};
use rustls::ServerConfig;
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;

use crate::RuntimeError;
use crate::federation::hello::HelloFailure;

/// The fixed version-1 ceiling on configured peers and therefore on
/// simultaneously accepted federation sockets (spec C.4).
pub const MAX_FEDERATION_PEERS: usize = 64;

/// One TCP socket accepted on the federation listener, handed to the link
/// owner before TLS with the listener and handshake slots it already holds.
pub struct AcceptedFederationSocket {
    stream: TcpStream,
    tls: Arc<ServerConfig>,
    _listener_slot: OwnedSemaphorePermit,
    _handshake_slot: Option<OwnedSemaphorePermit>,
}

impl AcceptedFederationSocket {
    pub(crate) fn new(
        stream: TcpStream,
        tls: Arc<ServerConfig>,
        listener_slot: OwnedSemaphorePermit,
        handshake_slot: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            stream,
            tls,
            _listener_slot: listener_slot,
            _handshake_slot: handshake_slot,
        }
    }

    /// Splits the socket from its TLS configuration; the slots stay held by
    /// the returned guard until the link owner drops it.
    pub fn into_parts(self) -> (TcpStream, Arc<ServerConfig>, FederationSocketSlots) {
        (
            self.stream,
            self.tls,
            FederationSocketSlots {
                _listener_slot: self._listener_slot,
                _handshake_slot: self._handshake_slot,
            },
        )
    }
}

/// The listener and handshake permits of one accepted federation socket.
pub struct FederationSocketSlots {
    _listener_slot: OwnedSemaphorePermit,
    _handshake_slot: Option<OwnedSemaphorePermit>,
}

impl FederationSocketSlots {
    /// Releases the handshake slot once TLS finished, keeping the listener slot.
    pub fn handshake_finished(&mut self) {
        self._handshake_slot = None;
    }
}

/// The identity of one link attempt; a reconnect is a new link.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LinkId(u64);

impl LinkId {
    /// Wraps one attempt counter value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the attempt counter value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Everything this node asserts and signs in its own hello.
pub struct LocalIdentity {
    network_id: NetworkId,
    server_id: ServerId,
    server_name: String,
    incarnation: ServerIncarnation,
    recovery_epoch: RecoveryEpoch,
    role: FederationRole,
    signing_key: Arc<Ed25519SecretKey>,
}

impl LocalIdentity {
    /// Validates the configured name and binds the signing key.
    pub fn new(
        network_id: NetworkId,
        server_id: ServerId,
        server_name: &str,
        incarnation: ServerIncarnation,
        recovery_epoch: RecoveryEpoch,
        role: FederationRole,
        signing_key: Arc<Ed25519SecretKey>,
    ) -> Result<Self, RuntimeError> {
        let server_name = ServerName::parse(server_name).map_err(|_| RuntimeError::InvalidValue)?;
        Ok(Self {
            network_id,
            server_id,
            server_name: server_name.as_str().to_owned(),
            incarnation,
            recovery_epoch,
            role,
            signing_key,
        })
    }

    /// Returns the network identity.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Returns the local Server ID.
    #[must_use]
    pub const fn server_id(&self) -> ServerId {
        self.server_id
    }

    /// Returns the configured server name used as the line prefix.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Returns the current incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> ServerIncarnation {
        self.incarnation
    }

    /// Returns the current recovery epoch.
    #[must_use]
    pub const fn recovery_epoch(&self) -> RecoveryEpoch {
        self.recovery_epoch
    }

    /// Returns the configured role.
    #[must_use]
    pub const fn role(&self) -> FederationRole {
        self.role
    }

    /// Borrows the hello signing key.
    #[must_use]
    pub fn signing_key(&self) -> &Ed25519SecretKey {
        &self.signing_key
    }
}

/// The static expectation of one configured peer.
#[derive(Clone)]
pub struct PeerIdentity {
    server_id: ServerId,
    server_name: String,
    role: FederationRole,
    recovery_epoch_pin: RecoveryEpoch,
    signing_key: Ed25519PublicKey,
    certificate_spki_sha256: [u8; 32],
}

impl PeerIdentity {
    /// Builds the expectation from one validated peer record.
    pub fn from_config(peer: &PeerConfig) -> Result<Self, RuntimeError> {
        let role = match peer.role {
            NodeRole::Coordinator => FederationRole::Coordinator,
            NodeRole::Edge => FederationRole::Edge,
        };
        Ok(Self {
            server_id: peer.server_id,
            server_name: peer.server_name.as_str().to_owned(),
            role,
            recovery_epoch_pin: peer.recovery_epoch,
            signing_key: Ed25519PublicKey::from_bytes(peer.signing_public_key)
                .map_err(|_| RuntimeError::InvalidValue)?,
            certificate_spki_sha256: peer.certificate_spki_sha256,
        })
    }

    /// Builds the expectation from explicit values.
    #[must_use]
    pub fn new(
        server_id: ServerId,
        server_name: &str,
        role: FederationRole,
        recovery_epoch_pin: RecoveryEpoch,
        signing_key: Ed25519PublicKey,
        certificate_spki_sha256: [u8; 32],
    ) -> Self {
        Self {
            server_id,
            server_name: server_name.to_owned(),
            role,
            recovery_epoch_pin,
            signing_key,
            certificate_spki_sha256,
        }
    }

    /// Returns the peer Server ID.
    #[must_use]
    pub const fn server_id(&self) -> ServerId {
        self.server_id
    }

    /// Returns the peer's configured name, the only prefix its lines may use.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Returns the peer's configured role.
    #[must_use]
    pub const fn role(&self) -> FederationRole {
        self.role
    }

    /// Returns the pinned recovery epoch.
    #[must_use]
    pub const fn recovery_epoch_pin(&self) -> RecoveryEpoch {
        self.recovery_epoch_pin
    }

    /// Returns the independent hello signing key.
    #[must_use]
    pub const fn signing_key(&self) -> Ed25519PublicKey {
        self.signing_key
    }

    /// Returns the certificate SPKI pin.
    #[must_use]
    pub const fn certificate_spki_sha256(&self) -> &[u8; 32] {
        &self.certificate_spki_sha256
    }
}

/// The authenticated facts of one established link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkSession {
    /// The link attempt.
    pub link: LinkId,
    /// The authenticated peer.
    pub peer: ServerId,
    /// The peer's incarnation from its hello.
    pub peer_incarnation: ServerIncarnation,
    /// The peer's recovery epoch from its hello.
    pub peer_recovery_epoch: RecoveryEpoch,
    /// How the epoch relates to the durable peer history.
    pub transition: EpochTransition,
}

/// The descriptor of one complete object handed to the state owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectCarrier {
    /// FREQUEST.
    Request(OperationDescriptor),
    /// FRESULT.
    Result(OperationDescriptor),
    /// FEVENT.
    Event(EventDescriptor),
    /// FORIGIN ADD.
    OriginAdd(OriginDescriptor),
    /// FORIGIN UPDATE.
    OriginUpdate(OriginDescriptor),
    /// FSNAPSHOT ENTRY.
    SnapshotEntry {
        /// The edge addressed.
        edge_server_id: ServerId,
        /// The snapshot token.
        snapshot_token: FederationHash32,
        /// The zero-based entry index.
        entry_index: u32,
        /// The object identity.
        object_id: FederationHash32,
    },
}

/// Why a link ended; every value is safe to log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkCloseReason {
    /// The owning token was cancelled.
    Cancelled,
    /// The peer closed the transport.
    PeerClosed,
    /// The transport failed.
    Transport,
    /// A line violated framing or the federation grammar.
    Framing,
    /// A frame was not permitted in the link's state.
    Protocol(FederationFrameKind),
    /// The hello exchange failed.
    Hello(HelloFailure),
    /// The peer did not answer a keepalive in time.
    KeepaliveTimeout,
    /// The state owner did not drain the link within the stall budget.
    IngressStall,
    /// The outbound queue was closed by its owner.
    QueueClosed,
    /// Fragment reassembly failed.
    Assembly(AssemblyError),
    /// A later link to the same peer replaced this one.
    Superseded,
}

impl fmt::Display for LinkCloseReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("link cancelled"),
            Self::PeerClosed => formatter.write_str("peer closed the link"),
            Self::Transport => formatter.write_str("link transport failed"),
            Self::Framing => formatter.write_str("link framing violation"),
            Self::Protocol(kind) => write!(formatter, "unexpected {} frame", kind.form()),
            Self::Hello(failure) => write!(formatter, "hello failed: {failure}"),
            Self::KeepaliveTimeout => formatter.write_str("keepalive timed out"),
            Self::IngressStall => formatter.write_str("state owner stalled link ingress"),
            Self::QueueClosed => formatter.write_str("link outbound queue closed"),
            Self::Assembly(error) => write!(formatter, "reassembly failed: {error}"),
            Self::Superseded => formatter.write_str("link superseded"),
        }
    }
}

/// Bytes charged against the per-link ingress budget until the state owner
/// drops the carrying message.
pub struct IngressCharge {
    _permit: OwnedSemaphorePermit,
    bytes: u32,
}

impl IngressCharge {
    pub(crate) const fn new(permit: OwnedSemaphorePermit, bytes: u32) -> Self {
        Self {
            _permit: permit,
            bytes,
        }
    }

    /// Returns the charged byte count.
    #[must_use]
    pub const fn bytes(&self) -> u32 {
        self.bytes
    }
}

/// One item a link delivers to the state owner.
pub enum LinkEvent {
    /// The hello completed and the link is authenticated.
    Established(LinkSession),
    /// A complete control frame.
    Frame(FederationFrame),
    /// A complete reassembled object with its carrier descriptor.
    Object {
        /// The descriptor every fragment repeated.
        carrier: ObjectCarrier,
        /// The verified object bytes.
        object: AssembledObject,
    },
    /// The link ended.
    Closed(LinkCloseReason),
}

/// The message a link task submits to the state owner.
pub struct FederationInbound {
    /// The link attempt.
    pub link: LinkId,
    /// The configured peer the link belongs to.
    pub peer: ServerId,
    /// The delivered item.
    pub event: LinkEvent,
    /// The ingress charge released when this message is dropped.
    pub charge: Option<IngressCharge>,
}
