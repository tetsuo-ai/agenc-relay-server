//! Closed hash, HMAC, and HKDF domains.

use agenc_ircd_types::{NetworkId, NormalizedLogin, OpaqueCredentialId};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::secret::SecretBytes;

mod snapshot;
pub use snapshot::FederationSnapshotHash;

const LOGIN_INDEX_LABEL: &[u8] = b"agenc-chat login index v1";
const LOGIN_INDEX_KEY_ID_LABEL: &[u8] = b"agenc-chat login index key id v1";
const FAKE_CREDENTIAL_LABEL: &[u8] = b"agenc-chat fake opaque credential id v1";
const MAX_SEMANTIC_HASH_INPUT_BYTES: usize = 16_777_215;

/// A full SHA-256 result with no truncation operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// Returns the complete digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An unkeyed streaming SHA-256 over bytes the caller bounds, used for
/// artifact identities such as the running executable.
pub struct Sha256Stream {
    hasher: Sha256,
}

impl Sha256Stream {
    /// Starts an empty digest.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Absorbs the next chunk.
    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    /// Finishes the digest.
    #[must_use]
    pub fn finish(self) -> Digest32 {
        Digest32(self.hasher.finalize().into())
    }
}

impl Default for Sha256Stream {
    fn default() -> Self {
        Self::new()
    }
}

/// An independent keyed-login lookup secret.
pub struct LoginIndexKey(SecretBytes<32>);

impl LoginIndexKey {
    /// Takes ownership of an externally provisioned key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Computes the network-bound public identifier of this secret key.
    #[must_use]
    pub fn key_id(&self, network_id: NetworkId) -> LoginIndexKeyId {
        let mut hasher = Sha256::new();
        hasher.update(LOGIN_INDEX_KEY_ID_LABEL);
        hasher.update(network_id.as_bytes());
        hasher.update(self.secret_bytes());
        LoginIndexKeyId(hasher.finalize().into())
    }
}

/// A network-bound identifier for one login-index key generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LoginIndexKeyId([u8; 32]);

impl LoginIndexKeyId {
    /// Constructs an identifier decoded from authenticated storage.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete identifier.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The independent secret used for stable unknown-account credential IDs.
pub struct OpaqueFakeCredentialKey(SecretBytes<32>);

impl OpaqueFakeCredentialKey {
    /// Takes ownership of an externally provisioned key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// A complete keyed login digest.
///
/// The lookup value deliberately has no formatting or cloning surface because
/// logs must never contain keyed login hashes.
///
/// ```compile_fail
/// use agenc_ircd_crypto::LoginIndexDigest;
/// fn require_clone<T: Clone>() {}
/// require_clone::<LoginIndexDigest>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_crypto::LoginIndexDigest;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<LoginIndexDigest>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_crypto::LoginIndexDigest;
/// fn require_hash<T: core::hash::Hash>() {}
/// require_hash::<LoginIndexDigest>();
/// ```
pub struct LoginIndexDigest(Zeroizing<[u8; 32]>);

impl LoginIndexDigest {
    /// Restores one digest from an authenticated private storage record.
    #[must_use]
    pub fn from_storage_key(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrows the complete digest only for the private storage lookup key.
    #[must_use]
    pub fn expose_for_storage_key(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compares two private lookup digests without data-dependent early exit.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.0.as_ref().ct_eq(other.0.as_ref()))
    }
}

impl PartialEq for LoginIndexDigest {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl Eq for LoginIndexDigest {}

/// Computes the protocol login-index HMAC.
pub fn derive_login_index(
    key: &LoginIndexKey,
    network_id: NetworkId,
    login: &NormalizedLogin,
) -> Result<LoginIndexDigest, CryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.secret_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    mac.update(LOGIN_INDEX_LABEL);
    mac.update(network_id.as_bytes());
    mac.update(login.as_str().as_bytes());
    Ok(LoginIndexDigest(Zeroizing::new(
        mac.finalize().into_bytes().into(),
    )))
}

/// Computes the stable private credential ID for an unknown login.
pub fn derive_fake_credential_id(
    key: &OpaqueFakeCredentialKey,
    network_id: NetworkId,
    login: &NormalizedLogin,
) -> Result<OpaqueCredentialId, CryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.secret_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    mac.update(FAKE_CREDENTIAL_LABEL);
    mac.update(network_id.as_bytes());
    mac.update(login.as_str().as_bytes());
    Ok(OpaqueCredentialId::from_bytes(
        mac.finalize().into_bytes().into(),
    ))
}

/// Exhaustive version-one E2EE semantic-hash registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticHashDomain {
    /// Root descriptor fingerprint.
    RootFingerprint,
    /// Network-scoped account identifier digest.
    AccountId,
    /// Device enrollment identifier.
    EnrollmentId,
    /// Device certificate identifier.
    DeviceCertificateId,
    /// Device roster identifier.
    RosterId,
    /// Device capability identifier.
    CapabilityId,
    /// Leaf signature-key digest.
    LeafSignatureKey,
    /// Leaf capabilities digest.
    LeafCapabilities,
    /// Human-comparable safety number.
    SafetyNumber,
    /// Network-scoped conversation identifier.
    Conversation,
    /// Channel route binding.
    ChannelRoute,
    /// Direct-message route binding.
    DirectRoute,
    /// Conversation policy identifier.
    PolicyId,
    /// Conversation binding identifier.
    BindingId,
    /// Root-binding lock identifier.
    RootBindingLockId,
    /// Semantic-route lock identifier.
    SemanticRouteLock,
    /// Sequencer credential identifier.
    SequencerKey,
    /// Sequencer key-set digest.
    SequencerKeySet,
    /// Initial member-plan identifier.
    InitialMemberPlanId,
    /// Key-package plan identifier.
    KeyPackagePlanId,
    /// Context-core identifier.
    ContextCoreId,
    /// Full MLS context digest.
    ContextHash,
    /// Close intent identifier.
    CloseIntentId,
    /// Close authorization identifier.
    CloseAuthorizationId,
    /// Commit authorization identifier.
    CommitAuthorizationId,
    /// Group genesis state identifier.
    GroupGenesisId,
    /// Candidate receipt identifier.
    CandidateId,
    /// Group-context digest.
    GroupContextDigest,
    /// Ratchet-tree digest.
    RatchetTreeDigest,
    /// Group-info digest.
    GroupInfoDigest,
    /// Prior credential digest.
    OldCredentialHash,
    /// Resulting leaf credential digest.
    ResultingLeafCredential,
    /// Commit finalization identifier.
    FinalizationId,
    /// Commit abort identifier.
    AbortId,
    /// Reinitialization target digest.
    ReinitTarget,
    /// Reinitialization initial-commit digest.
    ReinitInitialCommit,
    /// Reinitialization-attempt authorization identifier.
    ReinitAttemptAuthorizationId,
    /// Reinitialization-attempt identifier.
    ReinitAttemptId,
    /// Reinitialization activation identifier.
    ReinitActivationId,
    /// Reinitialization abort identifier.
    ReinitAbortId,
    /// Federation origin state identifier.
    FederationOriginState,
    /// Canonical channel-name digest.
    CanonicalChannelName,
    /// Federation snapshot digest.
    FederationSnapshot,
    /// Commit acknowledgement-set digest.
    AcknowledgementSet,
    /// Reinitialization acknowledgement-set digest.
    ReinitAcknowledgementSet,
}

impl SemanticHashDomain {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::RootFingerprint => b"IRC-MLS/1 root fingerprint",
            Self::AccountId => b"IRC-MLS/1 account id",
            Self::EnrollmentId => b"IRC-MLS/1 enrollment id",
            Self::DeviceCertificateId => b"IRC-MLS/1 device certificate id",
            Self::RosterId => b"IRC-MLS/1 roster id",
            Self::CapabilityId => b"IRC-MLS/1 capability id",
            Self::LeafSignatureKey => b"IRC-MLS/1 leaf signature key",
            Self::LeafCapabilities => b"IRC-MLS/1 leaf capabilities",
            Self::SafetyNumber => b"IRC-MLS/1 safety number",
            Self::Conversation => b"IRC-MLS/1 conversation",
            Self::ChannelRoute => b"IRC-MLS/1 channel route",
            Self::DirectRoute => b"IRC-MLS/1 direct route",
            Self::PolicyId => b"IRC-MLS/1 policy id",
            Self::BindingId => b"IRC-MLS/1 binding id",
            Self::RootBindingLockId => b"IRC-MLS/1 root binding lock id",
            Self::SemanticRouteLock => b"IRC-MLS/1 semantic route lock",
            Self::SequencerKey => b"IRC-MLS/1 sequencer key",
            Self::SequencerKeySet => b"IRC-MLS/1 sequencer key set",
            Self::InitialMemberPlanId => b"IRC-MLS/1 initial member plan id",
            Self::KeyPackagePlanId => b"IRC-MLS/1 key package plan id",
            Self::ContextCoreId => b"IRC-MLS/1 context core id",
            Self::ContextHash => b"IRC-MLS/1 context hash",
            Self::CloseIntentId => b"IRC-MLS/1 close intent id",
            Self::CloseAuthorizationId => b"IRC-MLS/1 close authorization id",
            Self::CommitAuthorizationId => b"IRC-MLS/1 commit authorization id",
            Self::GroupGenesisId => b"IRC-MLS/1 group genesis id",
            Self::CandidateId => b"IRC-MLS/1 candidate id",
            Self::GroupContextDigest => b"IRC-MLS/1 group context digest",
            Self::RatchetTreeDigest => b"IRC-MLS/1 ratchet tree digest",
            Self::GroupInfoDigest => b"IRC-MLS/1 group info digest",
            Self::OldCredentialHash => b"IRC-MLS/1 old credential hash",
            Self::ResultingLeafCredential => b"IRC-MLS/1 resulting leaf credential",
            Self::FinalizationId => b"IRC-MLS/1 finalization id",
            Self::AbortId => b"IRC-MLS/1 abort id",
            Self::ReinitTarget => b"IRC-MLS/1 reinit target",
            Self::ReinitInitialCommit => b"IRC-MLS/1 reinit initial commit",
            Self::ReinitAttemptAuthorizationId => b"IRC-MLS/1 reinit attempt authorization id",
            Self::ReinitAttemptId => b"IRC-MLS/1 reinit attempt id",
            Self::ReinitActivationId => b"IRC-MLS/1 reinit activation id",
            Self::ReinitAbortId => b"IRC-MLS/1 reinit abort id",
            Self::FederationOriginState => b"IRC-MLS/1 federation origin state",
            Self::CanonicalChannelName => b"IRC-MLS/1 canonical channel name",
            Self::FederationSnapshot => b"IRC-MLS/1 federation snapshot",
            Self::AcknowledgementSet => b"IRC-MLS/1 commit acknowledgement set",
            Self::ReinitAcknowledgementSet => b"IRC-MLS/1 reinit acknowledgement set",
        }
    }
}

/// Hashes a canonical encoding under one registered semantic domain.
pub fn semantic_digest(
    domain: SemanticHashDomain,
    canonical_encoding: &[u8],
) -> Result<Digest32, CryptoError> {
    if canonical_encoding.len() > MAX_SEMANTIC_HASH_INPUT_BYTES {
        return Err(CryptoError::LimitExceeded);
    }
    let mut hasher = Sha256::new();
    hasher.update(domain.label());
    hasher.update(canonical_encoding);
    Ok(Digest32(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use agenc_ircd_types::{NetworkId, NormalizedLogin};

    use super::{
        LoginIndexKey, OpaqueFakeCredentialKey, SemanticHashDomain, derive_fake_credential_id,
        derive_login_index, semantic_digest,
    };

    #[test]
    fn keyed_login_domains_cannot_be_substituted() -> Result<(), Box<dyn core::error::Error>> {
        let login = NormalizedLogin::prepare("alice")?;
        let network = NetworkId::from_bytes([3_u8; 32]);
        let login_digest =
            derive_login_index(&LoginIndexKey::from_bytes([7_u8; 32]), network, &login)?;
        let fake = derive_fake_credential_id(
            &OpaqueFakeCredentialKey::from_bytes([7_u8; 32]),
            network,
            &login,
        )?;
        assert_ne!(
            login_digest.expose_for_storage_key(),
            fake.expose_for_account_service()
        );
        Ok(())
    }

    #[test]
    fn semantic_domains_produce_distinct_results() -> Result<(), Box<dyn core::error::Error>> {
        let first = semantic_digest(SemanticHashDomain::PolicyId, b"same")?;
        let second = semantic_digest(SemanticHashDomain::BindingId, b"same")?;
        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn semantic_hashing_enforces_the_canonical_content_bound() {
        let maximum = vec![0_u8; super::MAX_SEMANTIC_HASH_INPUT_BYTES];
        assert!(semantic_digest(SemanticHashDomain::PolicyId, &maximum).is_ok());

        let maximum_plus_one = vec![0_u8; super::MAX_SEMANTIC_HASH_INPUT_BYTES + 1];
        assert_eq!(
            semantic_digest(SemanticHashDomain::PolicyId, &maximum_plus_one).err(),
            Some(crate::CryptoError::LimitExceeded)
        );
    }
}
