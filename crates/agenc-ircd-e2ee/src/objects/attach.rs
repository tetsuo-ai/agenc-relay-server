//! Device attachment objects (companion Section 11.6).

use crate::tls::tls_struct;

use super::AccountIdField;

tls_struct! {
    /// `IrcDeviceAttachTBS` (11.6).
    pub struct IrcDeviceAttachTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Device identity.
        pub device_id: [u8; 16],
        /// Edge-chosen connection nonce.
        pub connection_nonce: [u8; 32],
        /// Coordinator-chosen challenge.
        pub server_challenge: [u8; 32],
        /// The reserved next session generation.
        pub session_generation: u64,
        /// Issue second.
        pub issued_at: u64,
        /// Expiry second.
        pub expires_at: u64,
    }
}

tls_struct! {
    /// `IrcDeviceAttachChallenge` (11.6), the `device_attach_challenge` body.
    pub struct IrcDeviceAttachChallenge {
        /// Signed fields.
        pub tbs: IrcDeviceAttachTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcDeviceAttach` (11.6), the `device_attach` body.
    pub struct IrcDeviceAttach {
        /// The exact challenge.
        pub challenge: IrcDeviceAttachChallenge,
        /// Device possession signature over the same TBS.
        pub device_signature: [u8; 64],
    }
}
