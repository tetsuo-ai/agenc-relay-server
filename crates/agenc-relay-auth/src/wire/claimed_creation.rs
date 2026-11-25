//! The opted-in account creation START and its independently authenticated OPAQUE challenge.

use agenc_relay_crypto::{
    AccountHpkeExchange, AccountHpkePrivateKey, AccountHpkePublicKey, AccountRequestBinding,
    AccountResponseOpenToken, AccountResponseSealToken, Digest32, InitialRootExchange,
    InitialRootPrecommit, InitialRootSecret, Sha256Stream, seal_account_request,
};
use agenc_relay_types::{NetworkId, OpaqueCredentialId, RecoveryEpoch, TransactionId};
use zeroize::Zeroizing;

use super::{
    AuthError, CreationStart, Cursor, InitialRootServiceEnvelope, InitialRootServiceResponse,
    OpaqueRegistrationResponse, encode_challenge, encode_creation_start, padding, parse_challenge,
    parse_creation_start,
};

const START_MIN: usize = 104;
const START_MAX: usize = 297;
const CHALLENGE_BYTES: usize = 2 + 16 + 32 + 2 + 64;

/// Private check on the guarded creation response that belongs to the original client request.
pub struct CreationChallengeToken(AccountResponseOpenToken<InitialRootExchange>);

/// The authenticated guarded creation and its exact opaque challenge.
pub struct VerifiedCreationChallenge {
    /// Network, recipient, recovery epoch and original guarded request identity.
    binding: AccountRequestBinding<InitialRootExchange>,
    /// The coordinator's one-use server transaction.
    transaction_id: TransactionId,
    /// The OPAQUE credential identity bound to this registration.
    credential_id: OpaqueCredentialId,
    /// Actual OPAQUE challenge used to finish the user's original registration.
    response: OpaqueRegistrationResponse,
}

impl VerifiedCreationChallenge {
    /// The only originating HPKE exchange that could authenticate this challenge.
    #[must_use]
    pub const fn binding(&self) -> AccountRequestBinding<InitialRootExchange> {
        self.binding
    }

    /// Hands the verified registration fields to the initial caller's OPAQUE continuation.
    #[must_use]
    pub fn into_registration(
        self,
    ) -> (
        TransactionId,
        OpaqueCredentialId,
        OpaqueRegistrationResponse,
    ) {
        (self.transaction_id, self.credential_id, self.response)
    }
}

/// Builds the protected START from the saved bootstrap secret and exact original creation.
pub fn seal_start(
    recipient: AccountHpkePublicKey,
    binding: AccountRequestBinding<InitialRootExchange>,
    request: &CreationStart,
    secret: &InitialRootSecret,
) -> Result<(InitialRootServiceEnvelope, CreationChallengeToken), AuthError> {
    if binding.message_kind() != InitialRootExchange::ClaimedCreateStart
        || request.network_id != binding.network_id()
    {
        return Err(AuthError::ContextMismatch);
    }
    let commitment = secret.precommit(
        binding.network_id(),
        binding.recovery_epoch(),
        binding.client_request_id(),
    );
    let mut fields = Zeroizing::new(Vec::new());
    fields
        .try_reserve_exact(START_MAX)
        .map_err(|_| AuthError::AllocationFailed)?;
    fields.extend_from_slice(&InitialRootExchange::VERSION.to_be_bytes());
    encode_creation_start(&mut fields, request)?;
    fields.extend_from_slice(commitment.expose_for_protection());
    let wrapped = padding::encode(&fields, START_MIN..=START_MAX)?;
    let (sealed, token) = seal_account_request(recipient, binding, &wrapped)?;
    Ok((
        InitialRootServiceEnvelope::from_sealed(sealed)?,
        CreationChallengeToken(token),
    ))
}

impl CreationChallengeToken {
    /// Decodes the challenge only after verifying its originating private exporter and exact tag.
    pub fn open(
        self,
        response: &InitialRootServiceResponse,
    ) -> Result<VerifiedCreationChallenge, AuthError> {
        let binding = self.0.request_binding();
        let plaintext = response.open(self.0)?;
        let fields = padding::decode(
            plaintext.expose_for_account_parser(),
            CHALLENGE_BYTES..=CHALLENGE_BYTES,
        )?;
        let mut cursor = Cursor::new(fields);
        if cursor.read_u16()? != InitialRootExchange::VERSION {
            return Err(AuthError::InvalidEncoding);
        }
        let (transaction_id, credential_id, bytes) = parse_challenge(&mut cursor)?;
        if !cursor.is_finished() {
            return Err(AuthError::InvalidEncoding);
        }
        let response = OpaqueRegistrationResponse::from_bytes(
            bytes.try_into().map_err(|_| AuthError::InvalidEncoding)?,
        )?;
        Ok(VerifiedCreationChallenge {
            binding,
            transaction_id,
            credential_id,
            response,
        })
    }
}

/// A parsed original creation remains paired with the commitment and its one-use response authority.
pub struct OpenedGuardedStart {
    pub(crate) request_digest: Digest32,
    pub(crate) binding: AccountRequestBinding<InitialRootExchange>,
    pub(crate) request: CreationStart,
    pub(crate) precommit: InitialRootPrecommit,
    pub(crate) token: AccountResponseSealToken<InitialRootExchange>,
}

impl OpenedGuardedStart {
    /// Borrows the parsed registration only for the coordinator's ordinary admission lookups.
    #[must_use]
    pub const fn request(&self) -> &CreationStart {
        &self.request
    }
}

/// Opens and fully validates the negotiated guarded START using the pinned account-service key.
pub fn open_start(
    private: &AccountHpkePrivateKey,
    network: NetworkId,
    epoch: RecoveryEpoch,
    envelope: &InitialRootServiceEnvelope,
) -> Result<OpenedGuardedStart, AuthError> {
    let (plaintext, token) = envelope.open(
        private,
        epoch,
        network,
        InitialRootExchange::ClaimedCreateStart,
    )?;
    let fields = padding::decode(plaintext.expose_for_account_parser(), START_MIN..=START_MAX)?;
    let mut cursor = Cursor::new(fields);
    if cursor.read_u16()? != InitialRootExchange::VERSION {
        return Err(AuthError::InvalidEncoding);
    }
    if NetworkId::from_bytes(cursor.read_array()?) != network {
        return Err(AuthError::ContextMismatch);
    }
    let request = parse_creation_start(network, &mut cursor)?;
    let precommit = InitialRootPrecommit::from_protected_bytes(cursor.read_array()?);
    if !cursor.is_finished() {
        return Err(AuthError::InvalidEncoding);
    }
    let mut digest = Sha256Stream::new();
    digest.update(envelope.as_bytes());
    Ok(OpenedGuardedStart {
        request_digest: digest.finish(),
        binding: envelope.binding(epoch),
        request,
        precommit,
        token,
    })
}

pub(crate) fn seal_challenge(
    token: AccountResponseSealToken<InitialRootExchange>,
    transaction: TransactionId,
    credential: &OpaqueCredentialId,
    response: &OpaqueRegistrationResponse,
    response_count: u64,
) -> Result<(InitialRootServiceResponse, u64), AuthError> {
    let mut fields = Zeroizing::new(Vec::new());
    fields
        .try_reserve_exact(CHALLENGE_BYTES)
        .map_err(|_| AuthError::AllocationFailed)?;
    fields.extend_from_slice(&InitialRootExchange::VERSION.to_be_bytes());
    encode_challenge(
        &mut fields,
        transaction,
        credential,
        response.expose_for_account_response(),
    )?;
    let wrapped = padding::encode(&fields, CHALLENGE_BYTES..=CHALLENGE_BYTES)?;
    let sealed = token.seal_response(
        response_count,
        InitialRootExchange::ClaimedCreateStart,
        &wrapped,
    )?;
    let count = sealed.next_response_count();
    Ok((InitialRootServiceResponse::from_sealed(sealed)?, count))
}
