//! Listener purposes shared by admission, budgeting, and observability.

/// The six closed listener purposes of Appendix C.3 (spec lines 8920-8961).
///
/// The configuration crate parses the keyword; every runtime owner keys its
/// per-purpose policy on this enum so a purpose can never be a free string.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ListenerPurpose {
    /// Direct TLS client listener.
    ClientTls,
    /// Browser-facing WebSocket client listener (transport deferred to Stage 09).
    ClientWss,
    /// Tor onion client listener on a daemon-owned Unix socket.
    ClientOnion,
    /// Mutually authenticated federation listener.
    Federation,
    /// Local administrative Unix socket.
    AdminLocal,
    /// Remote administrative listener with pinned mutual TLS.
    AdminTls,
}

impl ListenerPurpose {
    /// Every purpose in configuration order.
    pub const ALL: [Self; 6] = [
        Self::ClientTls,
        Self::ClientWss,
        Self::ClientOnion,
        Self::Federation,
        Self::AdminLocal,
        Self::AdminTls,
    ];

    /// Returns the fixed configuration keyword, also used as the log label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ClientTls => "client_tls",
            Self::ClientWss => "client_wss",
            Self::ClientOnion => "client_onion",
            Self::Federation => "federation",
            Self::AdminLocal => "admin_local",
            Self::AdminTls => "admin_tls",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn labels_are_the_six_distinct_configuration_keywords() {
        let labels: BTreeSet<&str> = ListenerPurpose::ALL
            .iter()
            .map(|purpose| purpose.label())
            .collect();
        assert_eq!(labels.len(), 6);
        assert!(labels.contains("client_tls"));
        assert!(labels.contains("admin_tls"));
        assert!(labels.iter().all(|label| {
            label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        }));
    }
}
