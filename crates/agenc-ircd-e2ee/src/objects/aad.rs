//! The server-visible MLS `authenticated_data` structures (companion
//! Section 10). They are the only part of an encrypted object whose
//! contents the daemon reads.

use crate::tls::tls_struct;

tls_struct! {
    /// `IrcApplicationAad`.
    pub struct IrcApplicationAad {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Concrete route binding.
        pub route_binding: [u8; 32],
        /// The sender's accepted state anchor.
        pub latest_state_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcCommitAad`.
    pub struct IrcCommitAad {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Concrete route binding.
        pub route_binding: [u8; 32],
        /// Canonical validation time.
        pub validation_time: u64,
        /// Prior accepted state identifier.
        pub prior_state_id: [u8; 32],
    }
}
