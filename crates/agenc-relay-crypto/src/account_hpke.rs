//! Fixed account-service HPKE recipient and response-exporter adapter.

use agenc_relay_types::{
    AccountServiceMessageKind, AccountServiceResponseKind, NetworkId, RecoveryEpoch, RequestId,
};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305 as ResponseCipher, Nonce};
use hpke::aead::{AeadCtxR, AeadCtxS, ChaCha20Poly1305 as HpkeChaCha20Poly1305};
use hpke::kdf::HkdfSha256;
use hpke::kem::{Kem as _, X25519HkdfSha256};
use hpke::{
    Deserializable as _, OpModeR, OpModeS, Serializable as _, setup_receiver, setup_sender_with_rng,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::secret::SecretBytes;
use crate::{CryptoError, OsEntropy};

type RequestReceiverContext = AeadCtxR<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>;
type RequestSenderContext = AeadCtxS<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>;

struct ResponseMaterial {
    key: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 12]>,
}

const PROFILE_VERSION: u16 = 1;
const REQUEST_INFO_LABEL: &[u8] = b"agenc-chat account service hpke request v1";
const REQUEST_AAD_LABEL: &[u8] = b"agenc-chat account service request aad v1";
const RESPONSE_KEY_LABEL: &[u8] = b"agenc-chat account service response key v1";
const RESPONSE_NONCE_LABEL: &[u8] = b"agenc-chat account service response nonce v1";
const RESPONSE_AAD_LABEL: &[u8] = b"agenc-chat account service response aad v1";
const KEY_ID_LABEL: &[u8] = b"agenc-chat account service hpke key v1";

/// Serialized X25519 encapsulated-key length.
pub const ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES: usize = 32;
/// Exact padded request-plaintext length.
pub const ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES: usize = 4_592;
/// Exact authenticated request-ciphertext length.
pub const ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES: usize = 4_608;
/// Exact padded response-plaintext length.
pub const ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES: usize = 4_208;
/// Exact authenticated response-ciphertext length.
pub const ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES: usize = 4_224;

/// The domain-separated identifier of an account-service HPKE key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AccountHpkeKeyId([u8; 32]);

impl AccountHpkeKeyId {
    /// Constructs the key identifier carried by a validated configuration pin.
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

/// A canonical X25519 HPKE public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountHpkePublicKey([u8; 32]);

impl AccountHpkePublicKey {
    /// Validates a serialized key and rejects malformed encodings.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&bytes)
            .map_err(|_| CryptoError::InvalidEncoding)?;
        Ok(Self(bytes))
    }

    /// Returns the complete serialized key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes the exact onboarding key identifier.
    #[must_use]
    pub fn key_id(self) -> AccountHpkeKeyId {
        let mut hash = Sha256::new();
        hash.update(KEY_ID_LABEL);
        hash.update(self.0);
        AccountHpkeKeyId(hash.finalize().into())
    }
}

/// A move-only X25519 HPKE recipient private key.
///
/// ```compile_fail
/// use agenc_relay_crypto::AccountHpkePrivateKey;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<AccountHpkePrivateKey>();
/// ```
pub struct AccountHpkePrivateKey(SecretBytes<32>);

impl AccountHpkePrivateKey {
    /// Takes ownership of a canonical serialized private key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&bytes)
            .map_err(|_| CryptoError::InvalidEncoding)?;
        Ok(Self(SecretBytes::new(bytes)))
    }

    /// Generates a key through the fallible operating-system entropy adapter.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut input_key_material = Zeroizing::new([0_u8; 32]);
        OsEntropy::fill(input_key_material.as_mut())?;
        let (private_key, _) = X25519HkdfSha256::derive_keypair(input_key_material.as_ref());
        let serialized = Zeroizing::new(<[u8; 32]>::from(private_key.to_bytes()));
        let mut key = Self(SecretBytes::new([0_u8; 32]));
        key.0.as_mut_bytes().copy_from_slice(serialized.as_ref());
        Ok(key)
    }

    /// Derives the pinned public key.
    pub fn public_key(&self) -> Result<AccountHpkePublicKey, CryptoError> {
        let private_key =
            <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(self.0.as_bytes())
                .map_err(|_| CryptoError::InvalidEncoding)?;
        let public_key = X25519HkdfSha256::sk_to_pk(&private_key);
        AccountHpkePublicKey::from_bytes(public_key.to_bytes().into())
    }
}

/// Authenticated fields that bind one request and its one response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountRequestBinding {
    network_id: NetworkId,
    recovery_epoch: RecoveryEpoch,
    recipient_key_id: AccountHpkeKeyId,
    client_request_id: RequestId,
    message_kind: AccountServiceMessageKind,
}

impl AccountRequestBinding {
    /// Constructs the fixed version-one request binding.
    #[must_use]
    pub const fn new(
        network_id: NetworkId,
        recovery_epoch: RecoveryEpoch,
        recipient_key_id: AccountHpkeKeyId,
        client_request_id: RequestId,
        message_kind: AccountServiceMessageKind,
    ) -> Self {
        Self {
            network_id,
            recovery_epoch,
            recipient_key_id,
            client_request_id,
            message_kind,
        }
    }

    /// Returns the network identity.
    #[must_use]
    pub const fn network_id(self) -> NetworkId {
        self.network_id
    }

    /// Returns the recovery epoch authenticated by the HPKE request context.
    #[must_use]
    pub const fn recovery_epoch(self) -> RecoveryEpoch {
        self.recovery_epoch
    }

    /// Returns the pinned recipient key identifier.
    #[must_use]
    pub const fn recipient_key_id(self) -> AccountHpkeKeyId {
        self.recipient_key_id
    }

    /// Returns the client request identity.
    #[must_use]
    pub const fn client_request_id(self) -> RequestId {
        self.client_request_id
    }

    /// Returns the routed request kind.
    #[must_use]
    pub const fn message_kind(self) -> AccountServiceMessageKind {
        self.message_kind
    }
}

/// An authenticated fixed-size request plaintext.
pub struct OpenedAccountRequest(Zeroizing<[u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES]>);

impl OpenedAccountRequest {
    /// Borrows the padded plaintext at the account-protocol parser boundary.
    #[must_use]
    pub fn expose_for_account_parser(&self) -> &[u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES] {
        &self.0
    }
}

/// One newly sealed fixed-size request and its encapsulated X25519 key.
pub struct SealedAccountRequest {
    binding: AccountRequestBinding,
    encapsulated_key: [u8; ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES],
    ciphertext: [u8; ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES],
}

impl SealedAccountRequest {
    /// Returns the authenticated request fields.
    #[must_use]
    pub const fn binding(&self) -> AccountRequestBinding {
        self.binding
    }

    /// Returns the serialized ephemeral X25519 public key.
    #[must_use]
    pub const fn encapsulated_key(&self) -> &[u8; ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES] {
        &self.encapsulated_key
    }

    /// Returns the complete sequence-zero HPKE ciphertext and tag.
    #[must_use]
    pub const fn ciphertext(&self) -> &[u8; ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES] {
        &self.ciphertext
    }
}

/// One-use client authority for opening the response to a sealed request.
pub struct AccountResponseOpenToken {
    context: RequestSenderContext,
    binding: AccountRequestBinding,
}

impl AccountResponseOpenToken {
    /// Returns the authenticated request fields expected in the response header.
    #[must_use]
    pub const fn request_binding(&self) -> AccountRequestBinding {
        self.binding
    }
}

/// Authenticated fixed-size response plaintext.
pub struct OpenedAccountResponse(Zeroizing<[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES]>);

impl OpenedAccountResponse {
    /// Borrows the padded plaintext at the account-response parser boundary.
    #[must_use]
    pub fn expose_for_account_parser(&self) -> &[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES] {
        &self.0
    }
}

/// One-use response authority retained from a successfully opened request.
pub struct AccountResponseSealToken {
    context: RequestReceiverContext,
    binding: AccountRequestBinding,
}

struct OneShotHpkeRng {
    bytes: Zeroizing<[u8; 32]>,
    used: bool,
    invalid_usage: bool,
}

impl OneShotHpkeRng {
    fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self {
            bytes,
            used: false,
            invalid_usage: false,
        }
    }
}

impl hpke::rand_core::TryRng for OneShotHpkeRng {
    type Error = hpke::rand_core::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.invalid_usage = true;
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.invalid_usage = true;
        Ok(0)
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        if self.used || destination.len() != self.bytes.len() {
            destination.fill(0);
            self.invalid_usage = true;
            return Ok(());
        }
        destination.copy_from_slice(self.bytes.as_ref());
        self.used = true;
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for OneShotHpkeRng {}

/// Seals one request with a fresh HPKE sender context and retains its exporter.
pub fn seal_account_request(
    public_key: AccountHpkePublicKey,
    binding: AccountRequestBinding,
    plaintext: &[u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES],
) -> Result<(SealedAccountRequest, AccountResponseOpenToken), CryptoError> {
    if public_key.key_id() != binding.recipient_key_id {
        return Err(CryptoError::AuthenticationFailed);
    }
    let public_key = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key.as_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let mut ephemeral_input = Zeroizing::new([0_u8; 32]);
    OsEntropy::fill(ephemeral_input.as_mut())?;
    let mut rng = OneShotHpkeRng::new(ephemeral_input);
    let info = request_info(binding)?;
    let (encapsulated_key, mut context) = setup_sender_with_rng::<
        HpkeChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
    >(&OpModeS::Base, &public_key, &info, &mut rng)
    .map_err(|_| CryptoError::AuthenticationFailed)?;
    if rng.invalid_usage || !rng.used {
        return Err(CryptoError::InvalidEncoding);
    }
    let encapsulated_key_bytes: [u8; ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES] =
        encapsulated_key.to_bytes().into();
    let aad = request_aad(binding, &encapsulated_key_bytes)?;
    let ciphertext = context
        .seal(plaintext, &aad)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let ciphertext = ciphertext
        .try_into()
        .map_err(|_| CryptoError::InvalidEncoding)?;
    Ok((
        SealedAccountRequest {
            binding,
            encapsulated_key: encapsulated_key_bytes,
            ciphertext,
        },
        AccountResponseOpenToken { context, binding },
    ))
}

/// A newly sealed fixed-size response and its authenticated header fields.
pub struct SealedAccountResponse {
    binding: AccountRequestBinding,
    response_kind: AccountServiceResponseKind,
    response_salt: [u8; 32],
    ciphertext: [u8; ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES],
    next_response_count: u64,
}

impl SealedAccountResponse {
    /// Returns the originating request binding.
    #[must_use]
    pub const fn request_binding(&self) -> AccountRequestBinding {
        self.binding
    }

    /// Returns the registered response kind.
    #[must_use]
    pub const fn response_kind(&self) -> AccountServiceResponseKind {
        self.response_kind
    }

    /// Returns the fresh public salt authenticated by the response AAD.
    #[must_use]
    pub const fn response_salt(&self) -> &[u8; 32] {
        &self.response_salt
    }

    /// Returns the complete ciphertext and tag.
    #[must_use]
    pub const fn ciphertext(&self) -> &[u8; ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES] {
        &self.ciphertext
    }

    /// Returns the checked counter value to commit with this first response.
    #[must_use]
    pub const fn next_response_count(&self) -> u64 {
        self.next_response_count
    }
}

/// Opens the fixed request and returns its one-use response authority.
pub fn open_account_request(
    private_key: &AccountHpkePrivateKey,
    binding: AccountRequestBinding,
    encapsulated_key: &[u8; ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES],
    ciphertext: &[u8; ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES],
) -> Result<(OpenedAccountRequest, AccountResponseSealToken), CryptoError> {
    let expected_key_id = private_key.public_key()?.key_id();
    if expected_key_id != binding.recipient_key_id {
        return Err(CryptoError::AuthenticationFailed);
    }
    let private_key =
        <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(private_key.0.as_bytes())
            .map_err(|_| CryptoError::InvalidEncoding)?;
    let encapsulated_key =
        <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(encapsulated_key)
            .map_err(|_| CryptoError::InvalidEncoding)?;
    let info = request_info(binding)?;
    let mut context = setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private_key,
        &encapsulated_key,
        &info,
    )
    .map_err(|_| CryptoError::AuthenticationFailed)?;
    let aad = request_aad(binding, encapsulated_key.to_bytes().as_slice())?;
    let plaintext = Zeroizing::new(
        context
            .open(ciphertext, &aad)
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    if plaintext.len() != ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES {
        return Err(CryptoError::InvalidEncoding);
    }
    let mut opened = Zeroizing::new([0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES]);
    opened.copy_from_slice(plaintext.as_slice());
    Ok((
        OpenedAccountRequest(opened),
        AccountResponseSealToken { context, binding },
    ))
}

impl AccountResponseSealToken {
    /// Seals exactly one matching response and returns the counter to commit.
    pub fn seal_response(
        self,
        current_response_count: u64,
        response_kind: AccountServiceResponseKind,
        plaintext: &[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES],
    ) -> Result<SealedAccountResponse, CryptoError> {
        let mut response_salt = [0_u8; 32];
        OsEntropy::fill(&mut response_salt)?;
        self.seal_response_with_salt(
            current_response_count,
            response_kind,
            response_salt,
            plaintext,
        )
    }

    /// Seals with a caller-supplied salt so reference vectors can bind this path.
    ///
    /// Production callers must use [`Self::seal_response`]: a repeated salt
    /// repeats the response key and nonce for the same exporter context.
    #[doc(hidden)]
    pub fn seal_response_with_salt(
        self,
        current_response_count: u64,
        response_kind: AccountServiceResponseKind,
        response_salt: [u8; 32],
        plaintext: &[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES],
    ) -> Result<SealedAccountResponse, CryptoError> {
        if expected_response_kind(self.binding.message_kind) != response_kind {
            return Err(CryptoError::KindMismatch);
        }
        let next_response_count = current_response_count
            .checked_add(1)
            .ok_or(CryptoError::Overflow)?;
        let response_material =
            export_response_material(&self.context, self.binding, &response_salt)?;
        let aad = response_aad(self.binding, response_kind, &response_salt)?;
        let cipher = ResponseCipher::new_from_slice(response_material.key.as_ref())
            .map_err(|_| CryptoError::InvalidEncoding)?;
        let nonce_array = Nonce::try_from(response_material.nonce.as_ref())
            .map_err(|_| CryptoError::InvalidEncoding)?;
        let ciphertext = cipher
            .encrypt(
                &nonce_array,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let ciphertext = ciphertext
            .try_into()
            .map_err(|_| CryptoError::InvalidEncoding)?;
        Ok(SealedAccountResponse {
            binding: self.binding,
            response_kind,
            response_salt,
            ciphertext,
            next_response_count,
        })
    }
}

impl AccountResponseOpenToken {
    /// Opens exactly one matching response and consumes the exporter authority.
    pub fn open_response(
        self,
        response_kind: AccountServiceResponseKind,
        response_salt: &[u8; 32],
        ciphertext: &[u8; ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES],
    ) -> Result<OpenedAccountResponse, CryptoError> {
        if expected_response_kind(self.binding.message_kind) != response_kind {
            return Err(CryptoError::KindMismatch);
        }
        let response_material =
            export_client_response_material(&self.context, self.binding, response_salt)?;
        let aad = response_aad(self.binding, response_kind, response_salt)?;
        let cipher = ResponseCipher::new_from_slice(response_material.key.as_ref())
            .map_err(|_| CryptoError::InvalidEncoding)?;
        let nonce_array = Nonce::try_from(response_material.nonce.as_ref())
            .map_err(|_| CryptoError::InvalidEncoding)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce_array,
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );
        if plaintext.len() != ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES {
            return Err(CryptoError::InvalidEncoding);
        }
        let mut opened = Zeroizing::new([0_u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES]);
        opened.copy_from_slice(plaintext.as_slice());
        Ok(OpenedAccountResponse(opened))
    }
}

fn expected_response_kind(kind: AccountServiceMessageKind) -> AccountServiceResponseKind {
    match kind {
        AccountServiceMessageKind::AccountCreateStart => {
            AccountServiceResponseKind::AccountCreateChallenge
        }
        AccountServiceMessageKind::AccountCreateFinish => {
            AccountServiceResponseKind::AccountCreateComplete
        }
        AccountServiceMessageKind::OpaqueAuthStart => {
            AccountServiceResponseKind::OpaqueAuthChallenge
        }
        AccountServiceMessageKind::OpaqueAuthFinish => {
            AccountServiceResponseKind::OpaqueAuthComplete
        }
        AccountServiceMessageKind::CredentialChangeStart => {
            AccountServiceResponseKind::CredentialChangeChallenge
        }
        AccountServiceMessageKind::CredentialChangeFinish => {
            AccountServiceResponseKind::CredentialChangeComplete
        }
    }
}

fn request_info(binding: AccountRequestBinding) -> Result<Vec<u8>, CryptoError> {
    let capacity = REQUEST_INFO_LABEL
        .len()
        .checked_add(100)
        .ok_or(CryptoError::Overflow)?;
    let mut info = Vec::new();
    info.try_reserve_exact(capacity)
        .map_err(|_| CryptoError::AllocationFailed)?;
    info.extend_from_slice(REQUEST_INFO_LABEL);
    info.extend_from_slice(binding.recovery_epoch.as_bytes());
    info.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    info.extend_from_slice(binding.network_id.as_bytes());
    info.extend_from_slice(binding.recipient_key_id.as_bytes());
    info.extend_from_slice(binding.client_request_id.as_bytes());
    info.extend_from_slice(&binding.message_kind.wire_value().to_be_bytes());
    Ok(info)
}

fn request_aad(
    binding: AccountRequestBinding,
    encapsulated_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if encapsulated_key.len() != ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES {
        return Err(CryptoError::InvalidEncoding);
    }
    let mut aad = Vec::new();
    aad.try_reserve_exact(REQUEST_AAD_LABEL.len() + 116)
        .map_err(|_| CryptoError::AllocationFailed)?;
    aad.extend_from_slice(REQUEST_AAD_LABEL);
    encode_request_header(&mut aad, binding);
    aad.extend_from_slice(encapsulated_key);
    Ok(aad)
}

fn encode_request_header(output: &mut Vec<u8>, binding: AccountRequestBinding) {
    output.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    output.extend_from_slice(binding.network_id.as_bytes());
    output.extend_from_slice(binding.recipient_key_id.as_bytes());
    output.extend_from_slice(binding.client_request_id.as_bytes());
    output.extend_from_slice(&binding.message_kind.wire_value().to_be_bytes());
}

fn export_response_material(
    context: &RequestReceiverContext,
    binding: AccountRequestBinding,
    salt: &[u8; 32],
) -> Result<ResponseMaterial, CryptoError> {
    let key_context = response_export_context(RESPONSE_KEY_LABEL, binding, salt)?;
    let nonce_context = response_export_context(RESPONSE_NONCE_LABEL, binding, salt)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    let mut nonce = Zeroizing::new([0_u8; 12]);
    context
        .export(&key_context, key.as_mut())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    context
        .export(&nonce_context, nonce.as_mut())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(ResponseMaterial { key, nonce })
}

fn export_client_response_material(
    context: &RequestSenderContext,
    binding: AccountRequestBinding,
    salt: &[u8; 32],
) -> Result<ResponseMaterial, CryptoError> {
    let key_context = response_export_context(RESPONSE_KEY_LABEL, binding, salt)?;
    let nonce_context = response_export_context(RESPONSE_NONCE_LABEL, binding, salt)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    let mut nonce = Zeroizing::new([0_u8; 12]);
    context
        .export(&key_context, key.as_mut())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    context
        .export(&nonce_context, nonce.as_mut())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(ResponseMaterial { key, nonce })
}

fn response_export_context(
    label: &[u8],
    binding: AccountRequestBinding,
    salt: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let capacity = label.len().checked_add(48).ok_or(CryptoError::Overflow)?;
    let mut context = Vec::new();
    context
        .try_reserve_exact(capacity)
        .map_err(|_| CryptoError::AllocationFailed)?;
    context.extend_from_slice(label);
    context.extend_from_slice(binding.recovery_epoch.as_bytes());
    context.extend_from_slice(salt);
    Ok(context)
}

fn response_aad(
    binding: AccountRequestBinding,
    response_kind: AccountServiceResponseKind,
    salt: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let mut aad = Vec::new();
    aad.try_reserve_exact(RESPONSE_AAD_LABEL.len() + 116)
        .map_err(|_| CryptoError::AllocationFailed)?;
    aad.extend_from_slice(RESPONSE_AAD_LABEL);
    aad.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    aad.extend_from_slice(binding.network_id.as_bytes());
    aad.extend_from_slice(binding.recipient_key_id.as_bytes());
    aad.extend_from_slice(binding.client_request_id.as_bytes());
    aad.extend_from_slice(&response_kind.wire_value().to_be_bytes());
    aad.extend_from_slice(salt);
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use agenc_relay_types::{
        AccountServiceMessageKind, AccountServiceResponseKind, NetworkId, RecoveryEpoch, RequestId,
    };
    use zeroize::Zeroizing;

    use super::{
        ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES, ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES,
        AccountHpkeKeyId, AccountHpkePrivateKey, AccountRequestBinding, OneShotHpkeRng,
        open_account_request, request_aad, seal_account_request,
    };

    #[test]
    fn generated_private_key_has_a_stable_public_key() -> Result<(), Box<dyn core::error::Error>> {
        let private_key = AccountHpkePrivateKey::generate()?;
        let public_key = private_key.public_key()?;
        assert_ne!(public_key.as_bytes(), &[0_u8; 32]);
        assert_ne!(public_key.key_id().as_bytes(), &[0_u8; 32]);
        assert_eq!(ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES, 4_592);
        Ok(())
    }

    #[test]
    fn fixed_request_and_exported_response_round_trip() -> Result<(), Box<dyn core::error::Error>> {
        let private_key = AccountHpkePrivateKey::generate()?;
        let public_key = private_key.public_key()?;
        let binding = AccountRequestBinding::new(
            NetworkId::from_bytes([1_u8; 32]),
            RecoveryEpoch::from_bytes([2_u8; 16]),
            public_key.key_id(),
            RequestId::from_bytes([3_u8; 16]),
            AccountServiceMessageKind::OpaqueAuthStart,
        );
        let mut request_plaintext = [0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES];
        request_plaintext.fill(7);
        let (sealed_request, client_token) =
            seal_account_request(public_key, binding, &request_plaintext)?;
        let (opened_request, server_token) = open_account_request(
            &private_key,
            binding,
            sealed_request.encapsulated_key(),
            sealed_request.ciphertext(),
        )?;
        assert_eq!(
            opened_request.expose_for_account_parser(),
            &request_plaintext
        );

        let mut response_plaintext = [0_u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES];
        response_plaintext.fill(9);
        let sealed_response = server_token.seal_response(
            0,
            AccountServiceResponseKind::OpaqueAuthChallenge,
            &response_plaintext,
        )?;
        assert_eq!(sealed_response.next_response_count(), 1);
        let opened_response = client_token.open_response(
            sealed_response.response_kind(),
            sealed_response.response_salt(),
            sealed_response.ciphertext(),
        )?;
        assert_eq!(
            opened_response.expose_for_account_parser(),
            &response_plaintext
        );
        Ok(())
    }

    #[test]
    fn one_shot_rng_and_aad_length_fail_closed() {
        let input = [7_u8; 32];
        let mut rng = OneShotHpkeRng::new(Zeroizing::new(input));
        let mut exact = [0_u8; 32];
        assert!(hpke::rand_core::TryRng::try_fill_bytes(&mut rng, &mut exact).is_ok());
        assert_eq!(exact, input);
        let mut reused = [9_u8; 32];
        assert!(hpke::rand_core::TryRng::try_fill_bytes(&mut rng, &mut reused).is_ok());
        assert_eq!(reused, [0_u8; 32]);

        let mut wrong_length_rng = OneShotHpkeRng::new(Zeroizing::new(input));
        let mut wrong_length = [9_u8; 31];
        assert!(
            hpke::rand_core::TryRng::try_fill_bytes(&mut wrong_length_rng, &mut wrong_length)
                .is_ok()
        );
        assert_eq!(wrong_length, [0_u8; 31]);

        let binding = AccountRequestBinding::new(
            NetworkId::from_bytes([1_u8; 32]),
            RecoveryEpoch::from_bytes([2_u8; 16]),
            AccountHpkeKeyId::from_bytes([3_u8; 32]),
            RequestId::from_bytes([4_u8; 16]),
            AccountServiceMessageKind::OpaqueAuthStart,
        );
        assert_eq!(
            request_aad(binding, &[0_u8; 31]).err(),
            Some(crate::CryptoError::InvalidEncoding)
        );
    }
}
