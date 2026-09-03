//! Identity, device, and credential objects (companion Section 8).

use crate::tls::{Opaque, TlsVec, tls_struct};

use super::AccountIdField;

tls_struct! {
    /// `IrcRootIdentityTBS` (8.2).
    pub struct IrcRootIdentityTbs {
        /// Profile version, 1.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root generation.
        pub root_generation: u64,
        /// Root public key.
        pub root_public_key: [u8; 32],
        /// Earliest valid second.
        pub not_before: u64,
        /// Latest valid second.
        pub not_after: u64,
        /// Predecessor fingerprint, all zero at generation zero.
        pub previous_root_fingerprint: [u8; 32],
    }
}

tls_struct! {
    /// `IrcRootIdentity` (8.2).
    pub struct IrcRootIdentity {
        /// Signed fields.
        pub tbs: IrcRootIdentityTbs,
        /// New-root self signature.
        pub self_signature: [u8; 64],
        /// Previous-root continuity signature, empty at generation zero.
        pub continuity_signature: Opaque<0, 64>,
    }
}

/// `IrcRootDescriptor` repeats every TBS field, so its encoding is the TBS
/// encoding; the fingerprint hashes it under its own label.
pub type IrcRootDescriptor = IrcRootIdentityTbs;

tls_struct! {
    /// `IrcDeviceEnrollmentTBS` (8.3).
    pub struct IrcDeviceEnrollmentTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root generation.
        pub root_generation: u64,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Roster generation the enrollment targets.
        pub target_roster_generation: u64,
        /// Root-chosen challenge.
        pub enrollment_challenge: [u8; 32],
        /// Device identity.
        pub device_id: [u8; 16],
        /// Device authorization key.
        pub device_authorization_key: [u8; 32],
        /// Issue second.
        pub issued_at: u64,
        /// Expiry second.
        pub expires_at: u64,
    }
}

tls_struct! {
    /// `IrcDeviceEnrollment` (8.3).
    pub struct IrcDeviceEnrollment {
        /// Signed fields.
        pub tbs: IrcDeviceEnrollmentTbs,
        /// Possession proof by the new device.
        pub new_device_signature: [u8; 64],
        /// Approval by the root.
        pub root_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcDeviceCertificateTBS` (8.3).
    pub struct IrcDeviceCertificateTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root generation.
        pub root_generation: u64,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Device identity.
        pub device_id: [u8; 16],
        /// Device authorization key.
        pub device_authorization_key: [u8; 32],
        /// Roster generation the enrollment targeted.
        pub target_roster_generation: u64,
        /// The consumed challenge.
        pub enrollment_challenge: [u8; 32],
        /// TBS-only enrollment identifier.
        pub enrollment_id: [u8; 32],
        /// Certificate serial.
        pub certificate_serial: u64,
        /// Authorization flag bits.
        pub authorization_flags: u32,
        /// Earliest valid second.
        pub not_before: u64,
        /// Latest valid second.
        pub not_after: u64,
    }
}

/// Bit 0 of `authorization_flags`: may sign conversation bindings.
pub const FLAG_BINDING_AUTHORITY: u32 = 0x1;
/// Bit 1 of `authorization_flags`: may sign policy and controller approvals.
pub const FLAG_POLICY_AUTHORITY: u32 = 0x2;
/// Every flag bit defined in profile version 1.
pub const KNOWN_AUTHORIZATION_FLAGS: u32 = FLAG_BINDING_AUTHORITY | FLAG_POLICY_AUTHORITY;

tls_struct! {
    /// `IrcDeviceCertificate` (8.3).
    pub struct IrcDeviceCertificate {
        /// Signed fields.
        pub tbs: IrcDeviceCertificateTbs,
        /// The complete enrollment proof.
        pub enrollment_proof: IrcDeviceEnrollment,
        /// Root signature over the TBS.
        pub root_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcActiveDevice` (8.4).
    pub struct IrcActiveDevice {
        /// Device identity.
        pub device_id: [u8; 16],
        /// Its certificate.
        pub certificate: IrcDeviceCertificate,
    }
}

tls_struct! {
    /// `IrcDeviceRevocation` (8.4).
    pub struct IrcDeviceRevocation {
        /// Device identity.
        pub device_id: [u8; 16],
        /// Revoked certificate serial.
        pub certificate_serial: u64,
        /// Roster generation the revocation entered.
        pub revoked_in_generation: u64,
        /// Reason code.
        pub reason_code: u16,
    }
}

tls_struct! {
    /// `IrcDeviceRosterTBS` (8.4).
    pub struct IrcDeviceRosterTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root generation.
        pub root_generation: u64,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Roster generation.
        pub roster_generation: u64,
        /// Earliest valid second.
        pub not_before: u64,
        /// Latest valid second.
        pub not_after: u64,
        /// Previous roster identifier, all zero at generation zero.
        pub previous_roster_id: [u8; 32],
        /// Complete active device set, canonical by Device ID.
        pub active_devices: TlsVec<IrcActiveDevice, 0, 65_535>,
        /// Append-only revocations, canonical by Device ID.
        pub revocations: TlsVec<IrcDeviceRevocation, 0, 65_535>,
    }
}

tls_struct! {
    /// `IrcDeviceRoster` (8.4).
    pub struct IrcDeviceRoster {
        /// Signed fields.
        pub tbs: IrcDeviceRosterTbs,
        /// Root signature.
        pub root_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcDeviceCapabilitiesTBS` (8.5).
    pub struct IrcDeviceCapabilitiesTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Roster generation the statement is valid for.
        pub roster_generation: u64,
        /// That roster's identifier.
        pub roster_id: [u8; 32],
        /// Device identity.
        pub device_id: [u8; 16],
        /// Capability generation.
        pub capability_generation: u64,
        /// Previous capability identifier, all zero at generation zero.
        pub previous_capability_id: [u8; 32],
        /// Earliest valid second.
        pub not_before: u64,
        /// Latest valid second.
        pub not_after: u64,
        /// Supported protocol versions.
        pub versions: TlsVec<u16, 2, 32>,
        /// Supported cipher suites.
        pub cipher_suites: TlsVec<u16, 2, 64>,
        /// Supported extensions.
        pub extensions: TlsVec<u16, 0, 128>,
        /// Supported proposals.
        pub proposals: TlsVec<u16, 0, 128>,
        /// Supported credential types.
        pub credentials: TlsVec<u16, 2, 32>,
    }
}

tls_struct! {
    /// `IrcDeviceCapabilities` (8.5).
    pub struct IrcDeviceCapabilities {
        /// Signed fields.
        pub tbs: IrcDeviceCapabilitiesTbs,
        /// Device signature.
        pub device_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcLeafAuthorizationTBS` (8.5).
    pub struct IrcLeafAuthorizationTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root generation.
        pub root_generation: u64,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Roster generation.
        pub roster_generation: u64,
        /// Roster identifier.
        pub roster_id: [u8; 32],
        /// Device identity.
        pub device_id: [u8; 16],
        /// Credential generation, zero in version 1.
        pub credential_generation: u64,
        /// MLS protocol version.
        pub mls_version: u16,
        /// MLS cipher suite.
        pub cipher_suite: u16,
        /// Leaf signature scheme.
        pub leaf_signature_scheme: u16,
        /// Leaf signature key.
        pub leaf_signature_key: Opaque<1, 255>,
        /// Digest of the LeafNode capabilities.
        pub leaf_capabilities_hash: [u8; 32],
        /// Fresh package nonce.
        pub package_nonce: [u8; 32],
        /// Must be zero.
        pub last_resort: u8,
        /// Earliest valid second.
        pub not_before: u64,
        /// Latest valid second.
        pub not_after: u64,
    }
}

tls_struct! {
    /// `IrcLeafAuthorization` (8.5).
    pub struct IrcLeafAuthorization {
        /// Signed fields.
        pub tbs: IrcLeafAuthorizationTbs,
        /// Device signature.
        pub device_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcCredentialBundle` (8.5), the exact `BasicCredential.identity`.
    pub struct IrcCredentialBundle {
        /// Root identity.
        pub root: IrcRootIdentity,
        /// Device certificate.
        pub device_certificate: IrcDeviceCertificate,
        /// Leaf authorization.
        pub leaf_authorization: IrcLeafAuthorization,
    }
}

tls_struct! {
    /// `IrcAccountRootChain` (9.5), the `root_identity_chain` body.
    pub struct IrcAccountRootChain {
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Consecutive roots, oldest first.
        pub roots: TlsVec<IrcRootIdentity, 1, 1_048_576>,
    }
}
