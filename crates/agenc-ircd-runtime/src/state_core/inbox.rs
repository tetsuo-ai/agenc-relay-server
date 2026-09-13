//! Messages that reach StateCore through its bounded inbox (spec 21.3).

use agenc_ircd_client_wire::ParsedMessage;
use agenc_ircd_types::MonotonicTick;
use tokio::sync::{mpsc, oneshot};

use crate::budget::MemoryPermit;
use crate::connection::sink::{ClientSink, ConnectionGeneration};
use crate::purpose::ListenerPurpose;
use crate::state_core::session::MAX_TRACKED_CONNECTIONS;
use crate::sync::Arc;

/// Signal and maintenance events queued ahead of StateCore (spec line 4086).
pub const SIGNAL_EVENT_CAPACITY: usize = 64;
/// Maintenance ticks have reserved capacity independent of client traffic.
pub const MAINTENANCE_EVENT_CAPACITY: usize = 64;
/// Connection-open/control notices and explicit in-process fixture input.
pub const CLIENT_EVENT_CAPACITY: usize = 64;
/// Lifecycle commands queued independently of the public protocol inbox.
///
/// The dedicated channel remains selectable while a durable batch is in
/// flight, so shutdown cannot be held behind client work (spec 21.8).
pub const LIFECYCLE_EVENT_CAPACITY: usize = 8;
/// One reserved physical-close slot for every tracked client connection.
pub const CONNECTION_CLOSE_CAPACITY: usize = MAX_TRACKED_CONNECTIONS;
/// Mutation batches queued from StateCore to storage (spec line 4083).
pub const STORAGE_BATCH_CAPACITY: usize = 2;
/// Completions queued from storage back to StateCore (spec line 4084).
pub const STORAGE_COMPLETION_CAPACITY: usize = 2;
/// Crypto completion slots per worker (spec line 4085).
pub const CRYPTO_COMPLETION_SLOTS_PER_WORKER: usize = 2;
/// Hard maximum outstanding requests per connection (spec line 2657).
pub const MAX_REQUESTS_PER_CONNECTION: usize = 128;
/// Hard maximum parsed command arena per connection (spec line 2672).
pub const MAX_PARSED_ARENA_BYTES: usize = 131_072;

/// Sender used only by connection admission leases.
#[derive(Clone)]
pub struct ConnectionClosePort {
    sender: mpsc::Sender<PhysicalCloseNotice>,
}

/// StateCore's sole receiver for physical connection-close notices.
pub struct ConnectionCloseInbox {
    receiver: mpsc::Receiver<PhysicalCloseNotice>,
}

pub(crate) type ConnectionClosePermit = mpsc::OwnedPermit<PhysicalCloseNotice>;

/// Client base charge transferred to StateCore for close reconciliation.
/// Dropping the guard returns the charge to the connection task when it is
/// still live, including during abnormal StateCore exit.
pub(crate) struct ConnectionStatePermit {
    permit: Option<MemoryPermit>,
    return_permit: Option<oneshot::Sender<MemoryPermit>>,
}

impl ConnectionStatePermit {
    pub(crate) fn new(permit: MemoryPermit, return_permit: oneshot::Sender<MemoryPermit>) -> Self {
        Self {
            permit: Some(permit),
            return_permit: Some(return_permit),
        }
    }
}

impl Drop for ConnectionStatePermit {
    fn drop(&mut self) {
        if let (Some(permit), Some(return_permit)) = (self.permit.take(), self.return_permit.take())
        {
            let _returned = return_permit.send(permit);
        }
    }
}

/// Constructs the bounded physical-close channel.
#[must_use]
pub fn connection_close_channel() -> (ConnectionClosePort, ConnectionCloseInbox) {
    let (sender, receiver) = mpsc::channel(CONNECTION_CLOSE_CAPACITY);
    (
        ConnectionClosePort { sender },
        ConnectionCloseInbox { receiver },
    )
}

impl ConnectionClosePort {
    pub(crate) fn try_reserve(&self) -> Result<ConnectionClosePermit, ()> {
        self.sender.clone().try_reserve_owned().map_err(|_| ())
    }
}

impl ConnectionCloseInbox {
    pub(crate) async fn recv(&mut self) -> Option<PhysicalCloseNotice> {
        self.receiver.recv().await
    }

    pub(crate) fn len(&self) -> usize {
        self.receiver.len()
    }
}

pub(crate) struct PhysicalCloseNotice {
    pub(crate) generation: ConnectionGeneration,
    pub(crate) reason: CloseReason,
    pub(crate) closed_at: Option<MonotonicTick>,
    pub(crate) final_line_sequence: u64,
    pub(crate) state_permit: ConnectionStatePermit,
}

/// StateCore's closed response to one connection-open request.
#[derive(Debug)]
pub enum ConnectionOpenOutcome {
    /// The session and its source-prefix state are installed.
    Accepted,
    /// Session state and an independently bounded reader queue are installed.
    AcceptedInput(super::client_input::ClientInputPort),
    /// The generation was refused without installing session state.
    Refused,
}

/// Address family of an admitted transport peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressFamily {
    /// A direct IPv4 peer.
    Ipv4,
    /// A direct IPv6 peer.
    Ipv6,
    /// A peer of the onion listener; Tor hides the address.
    OnionListener,
}

/// The rate-prefix key a raw source address is reduced to (spec ID-04, line
/// 6858).
///
/// Direct transport admission may keep an IPv4 /32 or IPv6 /64 host key;
/// only the /24 or /56 result of [`Self::prefix_key`] may cross into protocol
/// state. Onion peers share one key. The type deliberately has no `Debug` or
/// `Display`.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SourceAddressKey {
    family: AddressFamily,
    host: [u8; 16],
}

impl SourceAddressKey {
    /// Keys a direct IPv4 peer by its /32 host address.
    #[must_use]
    pub const fn ipv4(octets: [u8; 4]) -> Self {
        let [a, b, c, d] = octets;
        Self {
            family: AddressFamily::Ipv4,
            host: [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Keys a direct IPv6 peer by its /64 prefix; the lower 64 bits are
    /// discarded so a single host cannot spread across interface identifiers.
    #[must_use]
    pub const fn ipv6(octets: [u8; 16]) -> Self {
        let [a, b, c, d, e, f, g, h, ..] = octets;
        Self {
            family: AddressFamily::Ipv6,
            host: [a, b, c, d, e, f, g, h, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Keys every peer of the onion listener identically.
    #[must_use]
    pub const fn onion_listener() -> Self {
        Self {
            family: AddressFamily::OnionListener,
            host: [0_u8; 16],
        }
    }

    /// Returns the address family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        self.family
    }

    /// Returns the per-host key (IPv4 /32, IPv6 /64) used by connection
    /// count limits (spec line 2643).
    #[must_use]
    pub const fn host_key(self) -> Self {
        self
    }

    /// Returns the bucket prefix key (IPv4 /24, IPv6 /56) used by the
    /// new-connection and handshake buckets (spec lines 2597 and 2599).
    #[must_use]
    pub const fn prefix_key(self) -> Self {
        let [a, b, c, d, e, f, g, ..] = self.host;
        let host = match self.family {
            AddressFamily::Ipv4 => [a, b, c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            AddressFamily::Ipv6 => [a, b, c, d, e, f, g, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            AddressFamily::OnionListener => [0_u8; 16],
        };
        Self {
            family: self.family,
            host,
        }
    }
}

/// Why a connection left the transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    /// The client sent QUIT.
    ClientQuit,
    /// The transport ended without a protocol close.
    TransportLoss,
    /// The reader rejected an over-budget or malformed line.
    ProtocolError,
    /// The output queue reached its hard limit.
    SlowConsumer,
    /// The reader stayed paused past the 30-second inbox stall (spec line 4079).
    ReadStall,
    /// A write stalled past its 30-second grace (spec line 522).
    WriteStall,
    /// A registration, handshake, or keepalive deadline expired.
    Deadline,
    /// Memory overload evicted the whole connection (spec line 2825).
    Overload,
    /// The daemon is shutting down.
    Shutdown,
}

/// Process signals delivered to StateCore (spec 21.8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalEvent {
    /// First termination request: begin the four-phase shutdown.
    Terminate,
    /// Second termination request: skip to the stop phase.
    Interrupt,
    /// Reload request (spec 22.6).
    Reload,
}

/// An ordered phase requested by the daemon shutdown driver.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LifecyclePhase {
    /// Stop accepting work and reject new protocol messages.
    Quiesce,
    /// Finish every mutation accepted before quiescence.
    Drain,
    /// Reach a storage-safe point for owner flushes and checkpoints.
    Flush,
    /// End the StateCore task.
    Stop,
}

/// A closed failure returned by the lifecycle owner boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleFailure {
    /// The StateCore lifecycle receiver is no longer available.
    Unavailable,
    /// Another request is already waiting for the same safe point.
    Busy,
    /// Stop superseded an earlier request before its safe point.
    Superseded,
}

/// Cloneable request handle held by the shutdown driver.
#[derive(Clone)]
pub struct LifecycleControl {
    sender: mpsc::Sender<LifecycleRequest>,
}

impl LifecycleControl {
    /// Requests one phase and waits for StateCore to acknowledge it.
    pub async fn request(&self, phase: LifecyclePhase) -> Result<(), LifecycleFailure> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(LifecycleRequest { phase, reply })
            .await
            .map_err(|_| LifecycleFailure::Unavailable)?;
        response.await.unwrap_or(Err(LifecycleFailure::Unavailable))
    }

    /// Attempts to request stop without waiting for channel capacity.
    pub fn try_stop(&self) -> Result<oneshot::Receiver<LifecycleResult>, LifecycleFailure> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(LifecycleRequest {
                phase: LifecyclePhase::Stop,
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => LifecycleFailure::Busy,
                mpsc::error::TrySendError::Closed(_) => LifecycleFailure::Unavailable,
            })?;
        Ok(response)
    }
}

/// Result carried by a lifecycle acknowledgement.
pub type LifecycleResult = Result<(), LifecycleFailure>;

/// One lifecycle request consumed only by StateCore.
pub struct LifecycleRequest {
    phase: LifecyclePhase,
    reply: oneshot::Sender<LifecycleResult>,
}

impl LifecycleRequest {
    /// Splits a request into its closed phase and response owner.
    pub(super) fn into_parts(self) -> (LifecyclePhase, oneshot::Sender<LifecycleResult>) {
        (self.phase, self.reply)
    }
}

/// Constructs the one bounded lifecycle channel for a StateCore owner.
#[must_use]
pub fn lifecycle_channel() -> (LifecycleControl, mpsc::Receiver<LifecycleRequest>) {
    let (sender, receiver) = mpsc::channel(LIFECYCLE_EVENT_CAPACITY);
    (LifecycleControl { sender }, receiver)
}

/// Maintenance ticks that StateCore coalesces when identical (spec line
/// 4086).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceEvent {
    /// Bounded retention deletion is due (spec 17, line 2458).
    RetentionSweep,
    /// The minute wall-versus-monotonic comparison is due (spec line 4229).
    ClockDriftCheck,
    /// Idle prefix buckets older than ten minutes must be erased (spec line 293).
    PrefixErasure,
    /// The storage checkpoint threshold was reached.
    CheckpointDue,
}

/// One message on the bounded StateCore inbox.
pub enum StateCoreMessage {
    /// A connection was admitted and its sink is ready.
    Opened {
        /// The queue generation of the new connection.
        generation: ConnectionGeneration,
        /// The listener that accepted it.
        purpose: ListenerPurpose,
        /// The already-masked rate-prefix or onion key. Raw host keys never
        /// enter StateCore.
        source: SourceAddressKey,
        /// The output owner StateCore reserves against.
        sink: Arc<dyn ClientSink>,
        /// Completed only after StateCore accepts or rejects the generation.
        acknowledgement: oneshot::Sender<ConnectionOpenOutcome>,
    },
    /// One complete parsed line injected by a trusted in-process caller.
    Line {
        /// The queue generation the line arrived on.
        generation: ConnectionGeneration,
        /// Per-connection order assigned after the inbox accepts the line.
        sequence: u64,
        /// The parsed message; boxed to keep the inbox item small.
        message: Box<ParsedMessage>,
    },
    /// A transport line retaining its per-connection charge through dispatch.
    QueuedLine {
        /// The queue generation the line arrived on.
        generation: ConnectionGeneration,
        /// Per-connection order assigned after inbox acceptance.
        sequence: u64,
        /// Bounded parsed message.
        message: Box<ParsedMessage>,
        /// Request and arena charge acquired before parsing.
        permit: crate::connection::reader::ClientLinePermit,
    },
    /// A process signal.
    Signal(SignalEvent),
    /// A maintenance tick.
    Maintenance(MaintenanceEvent),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_keys_mask_to_the_spec_prefixes_and_stay_distinct_per_family() {
        let v4 = SourceAddressKey::ipv4([203, 0, 113, 77]);
        let v4_sibling = SourceAddressKey::ipv4([203, 0, 113, 78]);
        assert!(v4.host_key() != v4_sibling.host_key());
        assert!(v4.prefix_key() == v4_sibling.prefix_key());
        assert_eq!(v4.family(), AddressFamily::Ipv4);

        let v6 = SourceAddressKey::ipv6([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 9, 9, 9, 9, 9, 9, 9, 9,
        ]);
        let v6_same_host = SourceAddressKey::ipv6([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 1, 1, 1, 1, 1, 1, 1, 1,
        ]);
        let v6_sibling = SourceAddressKey::ipv6([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert!(v6.host_key() == v6_same_host.host_key());
        assert!(v6.host_key() != v6_sibling.host_key());
        assert!(v6.prefix_key() == v6_sibling.prefix_key());

        let onion = SourceAddressKey::onion_listener();
        assert!(onion.prefix_key() == onion);
        assert_eq!(onion.family(), AddressFamily::OnionListener);
        assert!(onion != SourceAddressKey::ipv4([0, 0, 0, 0]));
    }

    #[test]
    fn inbox_capacities_match_the_channel_table() {
        assert_eq!(SIGNAL_EVENT_CAPACITY, 64);
        assert_eq!(LIFECYCLE_EVENT_CAPACITY, 8);
        assert_eq!(CONNECTION_CLOSE_CAPACITY, MAX_TRACKED_CONNECTIONS);
        assert_eq!(STORAGE_BATCH_CAPACITY, 2);
        assert_eq!(STORAGE_COMPLETION_CAPACITY, 2);
        assert_eq!(CRYPTO_COMPLETION_SLOTS_PER_WORKER, 2);
        assert_eq!(MAX_REQUESTS_PER_CONNECTION, 128);
        assert_eq!(MAX_PARSED_ARENA_BYTES, 131_072);
    }
}
