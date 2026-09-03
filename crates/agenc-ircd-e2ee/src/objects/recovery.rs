//! The server-side backup-restore gate (architecture Section 18.4,
//! companion Section 13.7.1). The storage crate keeps the durable record;
//! this is the same structure in its TLS presentation form.

use crate::tls::{tls_enum, tls_struct};

tls_enum! {
    /// `E2eeServerRecoveryKind`.
    pub enum E2eeServerRecoveryKind: u8 {
        /// An ordinary live route.
        Normal = 1,
        /// Restored and awaiting exact evidence.
        Pending = 2,
        /// Two valid successors at one position.
        Conflict = 3,
        /// Terminal close proven after restore.
        Closed = 4,
    }
}

tls_struct! {
    /// `E2eeServerRecoveryGate`.
    pub struct E2eeServerRecoveryGate {
        /// Gate version, 1.
        pub recovery_gate_version: u16,
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Gate state.
        pub state: E2eeServerRecoveryKind,
        /// Recovery epoch the gate was written under.
        pub recovery_epoch: [u8; 16],
        /// Restored binding identifier.
        pub restored_binding_id: [u8; 32],
        /// Restored accepted state identifier.
        pub restored_accepted_state_id: [u8; 32],
        /// Restored sequencer head identifier.
        pub restored_sequencer_head_id: [u8; 32],
        /// Source rollback guard hash.
        pub source_rollback_guard_hash: [u8; 32],
    }
}
