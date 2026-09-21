//! Leaf-membership proofs (companion Section 13.7.3): a public,
//! device-attested mapping from an attached device to one old MLS leaf, so
//! a server can identify the signer of a Commit or ReInit ACK without any
//! private MLS state.

use crate::objects::AccountIdField;
use crate::tls::{Opaque, tls_enum, tls_struct};

tls_enum! {
    /// `ArcLeafDispositionKind`.
    pub enum ArcLeafDispositionKind: u8 {
        /// The leaf continues into the next accepted state.
        Continuing = 1,
        /// The leaf is gone after the named finalized record.
        Removed = 2,
    }
}

tls_struct! {
    /// `ArcLeafMembershipProofTBS`.
    pub struct ArcLeafMembershipProofTbs {
        /// Profile version, 1.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identity.
        pub conversation_id: [u8; 32],
        /// The MLS epoch in which the leaf holds the named credential.
        pub epoch: u64,
        /// The old leaf index.
        pub leaf_index: u32,
        /// `SHA256("ARC-MLS/1 old credential hash" || encoded_BasicCredential)`.
        pub old_credential_hash: [u8; 32],
        /// The leaf signature scheme.
        pub leaf_signature_scheme: u16,
        /// The raw public leaf signature key.
        pub leaf_signature_key: Opaque<1, 255>,
        /// The account of the attesting device.
        pub account_id: AccountIdField,
        /// The attesting device.
        pub device_id: [u8; 16],
        /// The root generation of the leaf authorization.
        pub root_generation: u64,
        /// The root fingerprint of the leaf authorization.
        pub root_fingerprint: [u8; 32],
        /// The roster generation of the leaf authorization.
        pub roster_generation: u64,
        /// The roster identifier of the leaf authorization.
        pub roster_id: [u8; 32],
        /// The credential generation, zero in profile version 1.
        pub credential_generation: u64,
        /// Whether the leaf continues or is removed.
        pub disposition: ArcLeafDispositionKind,
        /// The finalized record after which a removed leaf is gone; all
        /// zero for a continuing leaf.
        pub removal_finalization_id: [u8; 32],
    }
}

tls_struct! {
    /// `ArcLeafMembershipProof`, the `leaf_membership_proof` body.
    pub struct ArcLeafMembershipProof {
        /// The signed statement.
        pub tbs: ArcLeafMembershipProofTbs,
        /// The device signature with label `ARC-MLS/1 leaf membership`.
        pub device_signature: [u8; 64],
        /// The old-leaf signature with label
        /// `ARC-MLS/1 leaf membership possession`; empty for a removed leaf.
        pub possession_signature: Opaque<0, 255>,
    }
}
