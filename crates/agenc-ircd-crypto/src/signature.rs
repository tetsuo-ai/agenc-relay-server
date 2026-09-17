//! Strict Ed25519 signing under closed protocol domains.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use crate::secret::SecretBytes;
use crate::{CryptoError, OsEntropy};

const MAX_SIGNATURE_CONTENT_BYTES: usize = 16_777_215;

#[derive(Clone, Copy)]
enum SignatureEncoding {
    IrcSignatureInput,
    DirectPrefix,
    /// RFC 9420 `SignWithLabel`: `SignContent { "MLS 1.0 " || label, content }`
    /// with QUIC-style variable-length vector prefixes.
    MlsSignWithLabel,
}

/// Exhaustive set of protocol domains that use Ed25519.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureDomain {
    /// Account-creation invitation authority.
    AccountCreationInvite,
    /// Federation hello identity proof.
    FederationHello,
    /// Administrator session proof over the challenge and transport binding.
    AdminSession,
    /// Post-authentication administrator command.
    AdminCommand,
    /// Server audit-event signature over an event hash.
    AdminAuditEvent,
    /// Server maintenance-event signature over the dedicated event hash.
    MaintenanceAuditEvent,
    /// Server audit-checkpoint signature over a checkpoint hash.
    AdminAuditCheckpoint,
    /// Offline database-backup signature over the stream digest.
    BackupSignature,
    /// Release storage-growth qualification report.
    StorageQualificationReport,
    /// Detached release decision over the canonical decision document.
    ReleaseDecision,
    /// E2EE root identity.
    RootIdentity,
    /// E2EE root continuity.
    RootContinuity,
    /// New-device possession proof.
    DeviceEnrollmentPossession,
    /// Root approval of device enrollment.
    DeviceEnrollmentApproval,
    /// Root-issued device certificate.
    DeviceCertificate,
    /// Root-issued device roster.
    DeviceRoster,
    /// Device capability declaration.
    DeviceCapabilities,
    /// Device authorization of one leaf.
    LeafAuthorization,
    /// Prior-sequencer continuity proof.
    SequencerContinuity,
    /// Device policy approval.
    PolicyApproval,
    /// Device conversation binding.
    ConversationBinding,
    /// Root binding lock.
    RootBindingLock,
    /// Controller authorization of a commit.
    CommitAuthorization,
    /// Controller authorization of a reinitialization attempt.
    ReinitAttemptAuthorization,
    /// Sequencer reservation.
    Reservation,
    /// Controller authorization of conversation closure.
    CloseAuthorization,
    /// Sequencer device-attach challenge.
    DeviceAttachChallenge,
    /// Device-attach possession proof.
    DeviceAttachPossession,
    /// Sequencer candidate receipt.
    CandidateReceipt,
    /// Old-leaf commit processing acknowledgement.
    CommitProcessed,
    /// Finality-device disposition vote.
    DispositionVote,
    /// Sequencer commit finalization.
    CommitFinalization,
    /// Sequencer candidate abort.
    CandidateAbort,
    /// Old-leaf reinitialization attempt.
    ReinitAttempt,
    /// Sequencer reinitialization-attempt receipt.
    ReinitAttemptReceipt,
    /// Old-leaf reinitialization processing acknowledgement.
    ReinitProcessed,
    /// Finality-device reinitialization disposition.
    ReinitDisposition,
    /// Sequencer reinitialization activation.
    ReinitActivation,
    /// Sequencer reinitialization-attempt abort.
    ReinitAttemptAbort,
    /// Device attestation of one old MLS leaf (companion 13.7.3).
    LeafMembership,
    /// Old-leaf possession proof inside a leaf-membership proof.
    LeafMembershipPossession,
    /// Device attestation of one recovery submission (companion 13.7.4).
    RecoverySubmission,
    /// RFC 9420 `KeyPackageTBS`, signed by the leaf signature key.
    MlsKeyPackageTbs,
    /// RFC 9420 `LeafNodeTBS`, signed by the leaf signature key.
    MlsLeafNodeTbs,
}

impl SignatureDomain {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::AccountCreationInvite => b"agenc-chat account creation invite v1",
            Self::FederationHello => b"agenc-chat federation hello v1",
            Self::AdminSession => b"agenc-chat admin session v1",
            Self::AdminCommand => b"agenc-chat admin command v1",
            Self::AdminAuditEvent => b"agenc-chat admin audit signature v1",
            Self::MaintenanceAuditEvent => b"agenc-chat maintenance audit signature v1",
            Self::AdminAuditCheckpoint => b"agenc-chat admin audit checkpoint signature v1",
            Self::BackupSignature => b"agenc-chat backup signature v1",
            Self::StorageQualificationReport => b"agenc-chat storage qualification report v1",
            Self::ReleaseDecision => b"agenc-chat release decision v1",
            Self::RootIdentity => b"IRC-MLS/1 root identity",
            Self::RootContinuity => b"IRC-MLS/1 root continuity",
            Self::DeviceEnrollmentPossession => b"IRC-MLS/1 device enrollment possession",
            Self::DeviceEnrollmentApproval => b"IRC-MLS/1 device enrollment approval",
            Self::DeviceCertificate => b"IRC-MLS/1 device certificate",
            Self::DeviceRoster => b"IRC-MLS/1 device roster",
            Self::DeviceCapabilities => b"IRC-MLS/1 device capabilities",
            Self::LeafAuthorization => b"IRC-MLS/1 leaf authorization",
            Self::SequencerContinuity => b"IRC-MLS/1 sequencer continuity",
            Self::PolicyApproval => b"IRC-MLS/1 policy approval",
            Self::ConversationBinding => b"IRC-MLS/1 conversation binding",
            Self::RootBindingLock => b"IRC-MLS/1 root binding lock",
            Self::CommitAuthorization => b"IRC-MLS/1 commit authorization",
            Self::ReinitAttemptAuthorization => b"IRC-MLS/1 reinit attempt authorization",
            Self::Reservation => b"IRC-MLS/1 reservation",
            Self::CloseAuthorization => b"IRC-MLS/1 close authorization",
            Self::DeviceAttachChallenge => b"IRC-MLS/1 device attach challenge",
            Self::DeviceAttachPossession => b"IRC-MLS/1 device attach possession",
            Self::CandidateReceipt => b"IRC-MLS/1 candidate receipt",
            Self::CommitProcessed => b"IRC-MLS/1 commit processed",
            Self::DispositionVote => b"IRC-MLS/1 disposition vote",
            Self::CommitFinalization => b"IRC-MLS/1 commit finalization",
            Self::CandidateAbort => b"IRC-MLS/1 candidate abort",
            Self::ReinitAttempt => b"IRC-MLS/1 reinit attempt",
            Self::ReinitAttemptReceipt => b"IRC-MLS/1 reinit attempt receipt",
            Self::ReinitProcessed => b"IRC-MLS/1 reinit processed",
            Self::ReinitDisposition => b"IRC-MLS/1 reinit disposition",
            Self::ReinitActivation => b"IRC-MLS/1 reinit activation",
            Self::ReinitAttemptAbort => b"IRC-MLS/1 reinit attempt abort",
            Self::LeafMembership => b"IRC-MLS/1 leaf membership",
            Self::LeafMembershipPossession => b"IRC-MLS/1 leaf membership possession",
            Self::RecoverySubmission => b"IRC-MLS/1 recovery submission",
            Self::MlsKeyPackageTbs => b"MLS 1.0 KeyPackageTBS",
            Self::MlsLeafNodeTbs => b"MLS 1.0 LeafNodeTBS",
        }
    }

    const fn encoding(self) -> SignatureEncoding {
        match self {
            Self::RootIdentity
            | Self::RootContinuity
            | Self::DeviceEnrollmentPossession
            | Self::DeviceEnrollmentApproval
            | Self::DeviceCertificate
            | Self::DeviceRoster
            | Self::DeviceCapabilities
            | Self::LeafAuthorization
            | Self::SequencerContinuity
            | Self::PolicyApproval
            | Self::ConversationBinding
            | Self::RootBindingLock
            | Self::CommitAuthorization
            | Self::ReinitAttemptAuthorization
            | Self::Reservation
            | Self::CloseAuthorization
            | Self::DeviceAttachChallenge
            | Self::DeviceAttachPossession
            | Self::CandidateReceipt
            | Self::CommitProcessed
            | Self::DispositionVote
            | Self::CommitFinalization
            | Self::CandidateAbort
            | Self::ReinitAttempt
            | Self::ReinitAttemptReceipt
            | Self::ReinitProcessed
            | Self::ReinitDisposition
            | Self::ReinitActivation
            | Self::ReinitAttemptAbort
            | Self::LeafMembership
            | Self::LeafMembershipPossession
            | Self::RecoverySubmission => SignatureEncoding::IrcSignatureInput,
            Self::AccountCreationInvite
            | Self::FederationHello
            | Self::AdminSession
            | Self::AdminCommand
            | Self::AdminAuditEvent
            | Self::MaintenanceAuditEvent
            | Self::AdminAuditCheckpoint
            | Self::BackupSignature
            | Self::StorageQualificationReport
            | Self::ReleaseDecision => SignatureEncoding::DirectPrefix,
            Self::MlsKeyPackageTbs | Self::MlsLeafNodeTbs => SignatureEncoding::MlsSignWithLabel,
        }
    }
}

/// A move-only Ed25519 signing key.
///
/// The type intentionally provides no formatting, cloning, serialization, or
/// unrestricted byte-exposure operation.
///
/// ```compile_fail
/// use agenc_ircd_crypto::Ed25519SecretKey;
/// fn require_clone<T: Clone>() {}
/// require_clone::<Ed25519SecretKey>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_crypto::Ed25519SecretKey;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<Ed25519SecretKey>();
/// ```
pub struct Ed25519SecretKey(SecretBytes<32>);

impl Ed25519SecretKey {
    /// Takes ownership of an externally provisioned key seed.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// Generates a signing key seed from the production OS authority.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Self(SecretBytes::new([0_u8; 32]));
        OsEntropy::fill(key.0.as_mut_bytes())?;
        Ok(key)
    }

    /// Derives the corresponding public verification key.
    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        let signing_key = SigningKey::from_bytes(self.0.as_bytes());
        Ed25519PublicKey(signing_key.verifying_key().to_bytes())
    }
}

/// A canonical Ed25519 public key encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// Validates a canonical compressed Edwards point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidEncoding)?;
        Ok(Self(bytes))
    }

    /// Returns the complete public encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A fixed-width Ed25519 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519Signature {
    /// Constructs a signature for strict verification.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the complete signature encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Signs the canonical content under exactly one registered domain.
pub fn sign_canonical(
    key: &Ed25519SecretKey,
    domain: SignatureDomain,
    canonical_content: &[u8],
) -> Result<Ed25519Signature, CryptoError> {
    let input = signature_input(domain, canonical_content)?;
    let signing_key = SigningKey::from_bytes(key.0.as_bytes());
    Ok(Ed25519Signature(signing_key.sign(&input).to_bytes()))
}

/// Applies strict RFC 8032 verification to one registered domain.
pub fn verify_canonical(
    key: Ed25519PublicKey,
    domain: SignatureDomain,
    canonical_content: &[u8],
    signature: Ed25519Signature,
) -> Result<(), CryptoError> {
    let input = signature_input(domain, canonical_content)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key.0).map_err(|_| CryptoError::InvalidEncoding)?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature.0);
    verifying_key
        .verify_strict(&input, &signature)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn signature_input(domain: SignatureDomain, content: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if content.len() > MAX_SIGNATURE_CONTENT_BYTES {
        return Err(CryptoError::LimitExceeded);
    }
    let label = domain.label();
    match domain.encoding() {
        SignatureEncoding::DirectPrefix => concatenate_direct(label, content),
        SignatureEncoding::IrcSignatureInput => encode_irc_signature_input(label, content),
        SignatureEncoding::MlsSignWithLabel => encode_mls_sign_content(label, content),
    }
}

/// Encodes the RFC 9420 `SignContent` structure: two variable-length
/// vectors whose prefixes are the Section 2.1.3 QUIC-style integers.
fn encode_mls_sign_content(label: &[u8], content: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let capacity = label
        .len()
        .checked_add(content.len())
        .and_then(|length| length.checked_add(8))
        .ok_or(CryptoError::Overflow)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(capacity)
        .map_err(|_| CryptoError::AllocationFailed)?;
    push_mls_varint(&mut input, label.len())?;
    input.extend_from_slice(label);
    push_mls_varint(&mut input, content.len())?;
    input.extend_from_slice(content);
    Ok(input)
}

/// Appends the minimal RFC 9420 variable-length integer for `value`.
fn push_mls_varint(output: &mut Vec<u8>, value: usize) -> Result<(), CryptoError> {
    let value = u32::try_from(value).map_err(|_| CryptoError::LimitExceeded)?;
    if value < 0x40 {
        output.extend_from_slice(&[u8::try_from(value).map_err(|_| CryptoError::Overflow)?]);
    } else if value < 0x4000 {
        output.extend_from_slice((value | 0x4000).to_be_bytes().get(2..).unwrap_or_default());
    } else if value < 0x4000_0000 {
        output.extend_from_slice(&(value | 0x8000_0000).to_be_bytes());
    } else {
        return Err(CryptoError::LimitExceeded);
    }
    Ok(())
}

fn concatenate_direct(label: &[u8], content: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let capacity = label
        .len()
        .checked_add(content.len())
        .ok_or(CryptoError::Overflow)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(capacity)
        .map_err(|_| CryptoError::AllocationFailed)?;
    input.extend_from_slice(label);
    input.extend_from_slice(content);
    Ok(input)
}

fn encode_irc_signature_input(label: &[u8], content: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let label_length = u8::try_from(label.len()).map_err(|_| CryptoError::LimitExceeded)?;
    let content_length = u32::try_from(content.len()).map_err(|_| CryptoError::LimitExceeded)?;
    let capacity = label
        .len()
        .checked_add(content.len())
        .and_then(|length| length.checked_add(4))
        .ok_or(CryptoError::Overflow)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(capacity)
        .map_err(|_| CryptoError::AllocationFailed)?;
    input.push(label_length);
    input.extend_from_slice(label);
    let length_bytes = content_length.to_be_bytes();
    let Some(uint24) = length_bytes.get(1..) else {
        return Err(CryptoError::InvalidEncoding);
    };
    input.extend_from_slice(uint24);
    input.extend_from_slice(content);
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::{Ed25519SecretKey, SignatureDomain, sign_canonical, verify_canonical};

    #[test]
    fn mls_sign_with_label_uses_every_varint_width() -> Result<(), Box<dyn core::error::Error>> {
        let key = Ed25519SecretKey::from_bytes([12_u8; 32]);
        for length in [1_usize, 63, 64, 16_383, 16_384, 70_000] {
            let content = vec![7_u8; length];
            let signature = sign_canonical(&key, SignatureDomain::MlsKeyPackageTbs, &content)?;
            verify_canonical(
                key.public_key(),
                SignatureDomain::MlsKeyPackageTbs,
                &content,
                signature,
            )?;
            assert!(
                verify_canonical(
                    key.public_key(),
                    SignatureDomain::MlsLeafNodeTbs,
                    &content,
                    signature,
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn strict_verification_rejects_domain_substitution() -> Result<(), Box<dyn core::error::Error>>
    {
        let key = Ed25519SecretKey::from_bytes([11_u8; 32]);
        let signature = sign_canonical(&key, SignatureDomain::PolicyApproval, b"canonical")?;
        verify_canonical(
            key.public_key(),
            SignatureDomain::PolicyApproval,
            b"canonical",
            signature,
        )?;
        assert!(
            verify_canonical(
                key.public_key(),
                SignatureDomain::ConversationBinding,
                b"canonical",
                signature,
            )
            .is_err()
        );
        Ok(())
    }
}
