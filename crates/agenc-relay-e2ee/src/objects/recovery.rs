//! The server-side backup-restore gate (architecture Section 18.4,
//! companion Section 13.7.1). The storage crate keeps the durable record;
//! this is the same structure in its TLS presentation form.

use crate::object::ArcWireObjectKind;
use crate::objects::AccountIdField;
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

tls_enum! {
    /// The element one recovery submission names (companion 13.7.4).
    pub enum ArcRecoveryElementKind: u8 {
        /// A `sequencer_record` that extends the restored head.
        RecordElement = 1,
        /// A `close_authorization` naming the head finalization.
        CloseElement = 2,
        /// An object, in its existing kind, that a submitted record references.
        ReferenceElement = 3,
    }
}

tls_struct! {
    /// The signed body of a recovery submission (companion 13.7.4).
    pub struct ArcRecoverySubmissionTbs {
        /// Profile version, 1.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// The restored conversation.
        pub conversation_id: [u8; 32],
        /// The daemon recovery epoch of the durable gate.
        pub recovery_epoch: [u8; 16],
        /// The gate's restored binding identifier.
        pub restored_binding_id: [u8; 32],
        /// The gate's restored accepted state identifier.
        pub restored_accepted_state_id: [u8; 32],
        /// The gate's restored sequencer head identifier.
        pub restored_sequencer_head_id: [u8; 32],
        /// The gate's source rollback guard hash.
        pub source_rollback_guard_hash: [u8; 32],
        /// The route sequence the element occupies.
        pub route_sequence: u64,
        /// The record the element succeeds.
        pub predecessor_record_id: [u8; 32],
        /// What the element is.
        pub element_kind: ArcRecoveryElementKind,
        /// The element's wire kind.
        pub element_object_kind: ArcWireObjectKind,
        /// The element's object identifier.
        pub element_object_id: [u8; 32],
        /// The submitting account.
        pub account_id: AccountIdField,
        /// The submitting device.
        pub device_id: [u8; 16],
    }
}

tls_struct! {
    /// A recovery submission: the TBS under the submitting device's
    /// `ARC-MLS/1 recovery submission` signature.
    pub struct ArcRecoverySubmission {
        /// The signed body.
        pub tbs: ArcRecoverySubmissionTbs,
        /// The device signature over the encoded body.
        pub device_signature: [u8; 64],
    }
}
