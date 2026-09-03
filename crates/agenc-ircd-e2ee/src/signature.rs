//! Registered-label signature verification (companion Sections 2 and 2.1)
//! and RFC 9420 `SignWithLabel` verification for public MLS objects.
//!
//! This module verifies only. It holds no signing key; the coordinator's
//! sequencer signatures are produced by the runtime through the crypto
//! crate's own signing entry point.

use agenc_ircd_crypto::{Ed25519PublicKey, Ed25519Signature, SignatureDomain, verify_canonical};

use crate::error::E2eeError;

/// Which key holder the registry names for one label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerRole {
    /// An account root identity key.
    Root,
    /// A device authorization key.
    Device,
    /// The network sequencer key.
    Sequencer,
    /// An MLS leaf signature key.
    Leaf,
}

/// Returns the registry's signer for a label, or `None` for a label the
/// companion does not register (base-profile domains).
#[must_use]
pub const fn expected_signer(domain: SignatureDomain) -> Option<SignerRole> {
    match domain {
        SignatureDomain::RootIdentity
        | SignatureDomain::RootContinuity
        | SignatureDomain::DeviceEnrollmentApproval
        | SignatureDomain::DeviceCertificate
        | SignatureDomain::DeviceRoster
        | SignatureDomain::RootBindingLock => Some(SignerRole::Root),
        SignatureDomain::DeviceEnrollmentPossession
        | SignatureDomain::DeviceCapabilities
        | SignatureDomain::LeafAuthorization
        | SignatureDomain::PolicyApproval
        | SignatureDomain::ConversationBinding
        | SignatureDomain::CommitAuthorization
        | SignatureDomain::ReinitAttemptAuthorization
        | SignatureDomain::CloseAuthorization
        | SignatureDomain::DeviceAttachPossession
        | SignatureDomain::DispositionVote
        | SignatureDomain::ReinitDisposition => Some(SignerRole::Device),
        SignatureDomain::SequencerContinuity
        | SignatureDomain::Reservation
        | SignatureDomain::DeviceAttachChallenge
        | SignatureDomain::CandidateReceipt
        | SignatureDomain::CommitFinalization
        | SignatureDomain::CandidateAbort
        | SignatureDomain::ReinitAttemptReceipt
        | SignatureDomain::ReinitActivation
        | SignatureDomain::ReinitAttemptAbort => Some(SignerRole::Sequencer),
        SignatureDomain::CommitProcessed
        | SignatureDomain::ReinitAttempt
        | SignatureDomain::ReinitProcessed
        | SignatureDomain::MlsKeyPackageTbs
        | SignatureDomain::MlsLeafNodeTbs => Some(SignerRole::Leaf),
        _ => None,
    }
}

/// A public Ed25519 key together with the role it is trusted for.
///
/// The role is fixed at construction so a device key can never satisfy a
/// root-label check merely because both are Ed25519 points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleKey {
    key: Ed25519PublicKey,
    role: SignerRole,
}

impl RoleKey {
    /// Validates the point and binds it to one role.
    pub fn new(role: SignerRole, bytes: [u8; 32]) -> Result<Self, E2eeError> {
        let key = Ed25519PublicKey::from_bytes(bytes).map_err(|_| E2eeError::KeyInvalid)?;
        Ok(Self { key, role })
    }

    /// Binds an MLS leaf signature key given in its suite encoding, which
    /// for both enabled suites is the raw 32-byte Ed25519 point.
    pub fn leaf(encoded: &[u8]) -> Result<Self, E2eeError> {
        let bytes: [u8; 32] = encoded.try_into().map_err(|_| E2eeError::KeyInvalid)?;
        Self::new(SignerRole::Leaf, bytes)
    }

    /// The role this key may sign for.
    #[must_use]
    pub const fn role(&self) -> SignerRole {
        self.role
    }

    /// The raw public key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.key.as_bytes()
    }

    /// Verifies a signature over `tbs` under `domain`, refusing a label
    /// whose registered signer is not this key's role.
    pub fn verify(
        &self,
        domain: SignatureDomain,
        tbs: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), E2eeError> {
        if expected_signer(domain) != Some(self.role) {
            return Err(E2eeError::SignatureInvalid);
        }
        verify_canonical(
            self.key,
            domain,
            tbs,
            Ed25519Signature::from_bytes(*signature),
        )
        .map_err(|_| E2eeError::SignatureInvalid)
    }

    /// Verifies a suite-encoded signature: the enabled suites use Ed25519,
    /// so the encoding is exactly 64 bytes.
    pub fn verify_suite_encoded(
        &self,
        domain: SignatureDomain,
        tbs: &[u8],
        signature: &[u8],
    ) -> Result<(), E2eeError> {
        let fixed: [u8; 64] = signature
            .try_into()
            .map_err(|_| E2eeError::SignatureInvalid)?;
        self.verify(domain, tbs, &fixed)
    }
}
