//! Reduction of a raw source address to its admission key (spec 6.1, lines
//! 290-295; ID-04, line 6858).
//!
//! The socket address exists only inside the listener task. This module
//! turns it into a [`SourceAddressKey`] and nothing else in the runtime ever
//! sees the address, so it cannot reach protocol state, persistence, logs,
//! metrics, replies, or audit events.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::state_core::inbox::SourceAddressKey;

/// A direct prefix bucket is erased no later than ten minutes after the
/// last connection using it closes (spec line 294).
pub const PREFIX_ERASURE_DELAY: Duration = Duration::from_secs(600);

/// Reduces a direct peer address to its host key; IPv4-mapped IPv6 peers
/// are keyed as IPv4 so a dual-stack listener cannot split one host across
/// two families.
#[must_use]
pub fn source_key(peer: SocketAddr) -> SourceAddressKey {
    match peer.ip() {
        IpAddr::V4(address) => SourceAddressKey::ipv4(address.octets()),
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => SourceAddressKey::ipv4(mapped.octets()),
            None => SourceAddressKey::ipv6(address.octets()),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::state_core::inbox::AddressFamily;

    #[test]
    fn keys_follow_the_family_and_collapse_mapped_addresses() {
        let v4 = source_key(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 6697)));
        assert_eq!(v4.family(), AddressFamily::Ipv4);
        let mapped = source_key(SocketAddr::from((
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x7109),
            6697,
        )));
        assert!(mapped == v4, "mapped addresses key as their IPv4 host");
        let v6 = source_key(SocketAddr::from((
            Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 5),
            6697,
        )));
        assert_eq!(v6.family(), AddressFamily::Ipv6);
        assert!(v6 != v4);
        assert_eq!(PREFIX_ERASURE_DELAY, Duration::from_secs(600));
    }
}
