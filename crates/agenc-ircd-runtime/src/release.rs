//! Public profile identities composed by local release metadata commands.

/// Normative document and negotiated-profile digests compiled into the daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseProfiles {
    /// Raw architecture document SHA-256.
    pub architecture_document: [u8; 32],
    /// Appendix-B base federation profile SHA-256.
    pub base_profile: [u8; 32],
    /// Raw companion document SHA-256.
    pub encrypted_document: [u8; 32],
    /// Negotiated companion profile SHA-256.
    pub encrypted_profile: [u8; 32],
}

/// Compiled identities, independent of any untrusted runtime configuration.
pub const RELEASE_PROFILES: ReleaseProfiles = ReleaseProfiles {
    architecture_document: agenc_ircd_federation_wire::ARCHITECTURE_DOCUMENT_SHA256,
    base_profile: agenc_ircd_federation_wire::BASE_FEDERATION_PROFILE_SHA256,
    encrypted_document: agenc_ircd_federation_wire::E2EE_DOCUMENT_SHA256,
    encrypted_profile: agenc_ircd_federation_wire::E2EE_PROFILE_SHA256,
};
