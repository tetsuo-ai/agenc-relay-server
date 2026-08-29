//! Messages that reach StateCore through its bounded inbox (spec 21.3).

use agenc_ircd_client_wire::ParsedMessage;

use crate::connection::sink::{ClientSink, ConnectionGeneration};
use crate::purpose::ListenerPurpose;
use crate::sync::Arc;

/// Signal and maintenance events queued ahead of StateCore (spec line 4086).
pub const SIGNAL_EVENT_CAPACITY: usize = 64;
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
/// Direct peers keep the IPv4 /32 or IPv6 /64 host key; the /24 and /56
/// bucket prefixes are derived by masking. Onion peers share one key. The
/// type deliberately has no `Debug` or `Display`: the address never leaves
/// the transport and admission owners.
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
        /// The admission key derived from the raw address.
        source: SourceAddressKey,
        /// The output owner StateCore reserves against.
        sink: Arc<dyn ClientSink>,
    },
    /// One complete parsed line from an admitted connection.
    Line {
        /// The queue generation the line arrived on.
        generation: ConnectionGeneration,
        /// The parsed message; boxed to keep the inbox item small.
        message: Box<ParsedMessage>,
    },
    /// A connection left the transport.
    Closed {
        /// The queue generation that ended.
        generation: ConnectionGeneration,
        /// Why it ended.
        reason: CloseReason,
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
        assert_eq!(STORAGE_BATCH_CAPACITY, 2);
        assert_eq!(STORAGE_COMPLETION_CAPACITY, 2);
        assert_eq!(CRYPTO_COMPLETION_SLOTS_PER_WORKER, 2);
        assert_eq!(MAX_REQUESTS_PER_CONNECTION, 128);
        assert_eq!(MAX_PARSED_ARENA_BYTES, 131_072);
    }
}
