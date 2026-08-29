//! Fixed account-service request and response codecs.

use agenc_ircd_crypto::{
    ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES, ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES,
    ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES, ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES,
    ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES, AccountHpkeKeyId, AccountHpkePrivateKey,
    AccountRequestBinding, AccountResponseOpenToken, AccountResponseSealToken,
    OpenedAccountRequest as OpenedHpkeRequest, OpenedAccountResponse, SealedAccountRequest,
    SealedAccountResponse, open_account_request,
};
use agenc_ircd_types::{
    AccountId, AccountServiceCompletionStatus, AccountServiceMessageKind,
    AccountServiceResponseKind, NetworkId, OpaqueCredentialId, RecoveryEpoch, RequestId,
    TransactionId,
};
use zeroize::Zeroizing;

use crate::AuthError;
use crate::invitation::{ACCOUNT_CREATION_INVITE_BYTES, AccountCreationInvite};
use crate::opaque::{
    OPAQUE_KE1_BYTES, OPAQUE_KE2_BYTES, OPAQUE_KE3_BYTES, OPAQUE_REGISTRATION_RECORD_BYTES,
    OPAQUE_REGISTRATION_REQUEST_BYTES, OPAQUE_REGISTRATION_RESPONSE_BYTES, OpaqueKe1, OpaqueKe2,
    OpaqueKe3, OpaqueRegistrationRecord, OpaqueRegistrationRequest, OpaqueRegistrationResponse,
};

const PROFILE_VERSION: u16 = 1;
const PADDING_VERSION: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 84;
const RESPONSE_HEADER_BYTES: usize = 116;
const REQUEST_INNER_MIN_BYTES: usize = 72;
/// Login byte bounds mirror `NormalizedLogin`, which accepts 3 through 64 bytes.
const MIN_LOGIN_BYTES: usize = 3;
const MAX_LOGIN_BYTES: usize = 64;
const REQUEST_INNER_MAX_BYTES: usize = 265;
const REQUEST_PADDING_BASE: usize = 4_586;
const RESPONSE_PAYLOAD_MIN_BYTES: usize = 52;
const RESPONSE_PAYLOAD_MAX_BYTES: usize = 372;
const RESPONSE_PADDING_BASE: usize = 4_202;

/// Exact encoded request-envelope length.
pub const ACCOUNT_SERVICE_ENVELOPE_BYTES: usize = 4_726;
/// Exact encoded response-envelope length.
pub const ACCOUNT_SERVICE_RESPONSE_BYTES: usize = 4_342;

/// Authenticated request lineage and its one-use response authority.
///
/// This value has no public constructor or authority-splitting accessor. It
/// stays attached to the parsed request until the account state machine binds
/// an exact response payload to it.
pub(crate) struct AccountRequestLineage {
    binding: AccountRequestBinding,
    response_token: AccountResponseSealToken,
}

impl AccountRequestLineage {
    #[must_use]
    pub(crate) const fn binding(&self) -> AccountRequestBinding {
        self.binding
    }

    pub(crate) fn seal_response(
        self,
        current_response_count: u64,
        response_kind: AccountServiceResponseKind,
        plaintext: &[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES],
    ) -> Result<SealedAccountResponse, AuthError> {
        Ok(self
            .response_token
            .seal_response(current_response_count, response_kind, plaintext)?)
    }
}

/// A parsed request that cannot be detached from its authenticated HPKE
/// request lineage or one-use response authority.
///
/// ```compile_fail
/// use agenc_ircd_auth::{AuthenticatedAccountRequest, CreationStart};
/// fn require_clone<T: Clone>() {}
/// require_clone::<AuthenticatedAccountRequest<CreationStart>>();
/// ```
#[must_use = "an opened request retains its one-use response authority"]
pub struct AuthenticatedAccountRequest<T> {
    payload: T,
    lineage: AccountRequestLineage,
}

impl<T> AuthenticatedAccountRequest<T> {
    /// Borrows the authenticated payload for policy decisions and storage lookup.
    #[must_use]
    pub const fn payload(&self) -> &T {
        &self.payload
    }

    /// Returns the authenticated outer request fields retained with this arm.
    #[must_use]
    pub const fn request_binding(&self) -> AccountRequestBinding {
        self.lineage.binding()
    }

    pub(crate) fn into_parts(self) -> (T, AccountRequestLineage) {
        (self.payload, self.lineage)
    }
}

/// Closed set of successfully opened, fully parsed account-service requests.
#[must_use = "an opened request must enter its typed protocol handler"]
pub enum OpenedAccountServiceRequest {
    /// Account-creation registration start and its response authority.
    CreationStart(AuthenticatedAccountRequest<CreationStart>),
    /// Account-creation registration finish and its response authority.
    CreationFinish(AuthenticatedAccountRequest<CreationFinish>),
    /// OPAQUE authentication start and its response authority.
    AuthenticationStart(AuthenticatedAccountRequest<AuthenticationStart>),
    /// OPAQUE authentication finish and its response authority.
    AuthenticationFinish(AuthenticatedAccountRequest<AuthenticationFinish>),
    /// Credential-replacement registration start and its response authority.
    CredentialChangeStart(AuthenticatedAccountRequest<CredentialChangeStart>),
    /// Credential-replacement registration finish and its response authority.
    CredentialChangeFinish(AuthenticatedAccountRequest<CredentialChangeFinish>),
}

impl OpenedAccountServiceRequest {
    /// Returns the authenticated outer request fields for this typed arm.
    #[must_use]
    pub const fn request_binding(&self) -> AccountRequestBinding {
        match self {
            Self::CreationStart(request) => request.request_binding(),
            Self::CreationFinish(request) => request.request_binding(),
            Self::AuthenticationStart(request) => request.request_binding(),
            Self::AuthenticationFinish(request) => request.request_binding(),
            Self::CredentialChangeStart(request) => request.request_binding(),
            Self::CredentialChangeFinish(request) => request.request_binding(),
        }
    }

    /// Returns the authenticated operation kind selecting this typed arm.
    #[must_use]
    pub const fn message_kind(&self) -> AccountServiceMessageKind {
        self.request_binding().message_kind()
    }
}

/// Move-only, fixed-size request plaintext erased after HPKE sealing.
///
/// ```compile_fail
/// use agenc_ircd_auth::EncodedAccountRequestPlaintext;
/// fn require_clone<T: Clone>() {}
/// require_clone::<EncodedAccountRequestPlaintext>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_auth::EncodedAccountRequestPlaintext;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<EncodedAccountRequestPlaintext>();
/// ```
pub struct EncodedAccountRequestPlaintext(Zeroizing<[u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES]>);

impl EncodedAccountRequestPlaintext {
    /// Borrows the plaintext only for the one matching HPKE seal operation.
    #[must_use]
    pub fn expose_for_hpke(&self) -> &[u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES] {
        &self.0
    }
}

/// Move-only, fixed-size response plaintext erased after response sealing.
///
/// ```compile_fail
/// use agenc_ircd_auth::EncodedAccountResponsePlaintext;
/// fn require_clone<T: Clone>() {}
/// require_clone::<EncodedAccountResponsePlaintext>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_auth::EncodedAccountResponsePlaintext;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<EncodedAccountResponsePlaintext>();
/// ```
pub struct EncodedAccountResponsePlaintext(Zeroizing<[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES]>);

impl EncodedAccountResponsePlaintext {
    /// Borrows the plaintext only for the one matching response seal operation.
    #[must_use]
    pub fn expose_for_hpke(&self) -> &[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES] {
        &self.0
    }
}

/// Canonical outer request that an edge may validate and forward unchanged.
pub struct AccountServiceEnvelope {
    encoded: [u8; ACCOUNT_SERVICE_ENVELOPE_BYTES],
    network_id: NetworkId,
    recipient_key_id: AccountHpkeKeyId,
    client_request_id: RequestId,
    message_kind: AccountServiceMessageKind,
    encapsulated_key: [u8; ACCOUNT_HPKE_ENCAPSULATED_KEY_BYTES],
    ciphertext: [u8; ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES],
}

impl AccountServiceEnvelope {
    /// Encodes one freshly sealed request in its exact outer wrapper.
    pub fn from_sealed(sealed: SealedAccountRequest) -> Result<Self, AuthError> {
        let binding = sealed.binding();
        let mut encoded = [0_u8; ACCOUNT_SERVICE_ENVELOPE_BYTES];
        let mut writer = Writer::new(&mut encoded);
        writer.write(&PROFILE_VERSION.to_be_bytes())?;
        writer.write(binding.network_id().as_bytes())?;
        writer.write(binding.recipient_key_id().as_bytes())?;
        writer.write(binding.client_request_id().as_bytes())?;
        writer.write(&binding.message_kind().wire_value().to_be_bytes())?;
        writer.write(sealed.encapsulated_key())?;
        writer.write(
            &u16::try_from(ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES)
                .map_err(|_| AuthError::Overflow)?
                .to_be_bytes(),
        )?;
        writer.write(sealed.ciphertext())?;
        Self::parse(encoded)
    }

    /// Parses and fully consumes the exact fixed-width envelope.
    pub fn parse(encoded: [u8; ACCOUNT_SERVICE_ENVELOPE_BYTES]) -> Result<Self, AuthError> {
        let mut cursor = Cursor::new(&encoded);
        if cursor.read_u16()? != PROFILE_VERSION {
            return Err(AuthError::InvalidEncoding);
        }
        let network_id = NetworkId::from_bytes(cursor.read_array()?);
        let recipient_key_id = AccountHpkeKeyId::from_bytes(cursor.read_array()?);
        let client_request_id = RequestId::from_bytes(cursor.read_array()?);
        let message_kind = AccountServiceMessageKind::from_wire(cursor.read_u16()?)
            .map_err(|_| AuthError::InvalidEncoding)?;
        let encapsulated_key = cursor.read_array()?;
        if usize::from(cursor.read_u16()?) != ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES {
            return Err(AuthError::InvalidEncoding);
        }
        let ciphertext = cursor.read_array()?;
        if !cursor.is_finished() || cursor.position() != ACCOUNT_SERVICE_ENVELOPE_BYTES {
            return Err(AuthError::InvalidEncoding);
        }
        Ok(Self {
            encoded,
            network_id,
            recipient_key_id,
            client_request_id,
            message_kind,
            encapsulated_key,
            ciphertext,
        })
    }

    /// Borrows the byte-identical envelope for routing and idempotent replay.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ACCOUNT_SERVICE_ENVELOPE_BYTES] {
        &self.encoded
    }

    /// Returns the only operation detail visible to an edge.
    #[must_use]
    pub const fn message_kind(&self) -> AccountServiceMessageKind {
        self.message_kind
    }

    /// Returns the client request identity used by idempotency storage.
    #[must_use]
    pub const fn client_request_id(&self) -> RequestId {
        self.client_request_id
    }

    fn binding(&self, recovery_epoch: RecoveryEpoch) -> AccountRequestBinding {
        AccountRequestBinding::new(
            self.network_id,
            recovery_epoch,
            self.recipient_key_id,
            self.client_request_id,
            self.message_kind,
        )
    }
}

/// Checks the routed outer context, then HPKE-opens and completely parses one
/// fixed padded request.
pub fn open_and_parse_request(
    private_key: &AccountHpkePrivateKey,
    recovery_epoch: RecoveryEpoch,
    expected_network: NetworkId,
    expected_message_kind: AccountServiceMessageKind,
    envelope: &AccountServiceEnvelope,
) -> Result<OpenedAccountServiceRequest, AuthError> {
    if envelope.network_id != expected_network || envelope.message_kind != expected_message_kind {
        return Err(AuthError::ContextMismatch);
    }
    let binding = envelope.binding(recovery_epoch);
    let (plaintext, response_token) = open_account_request(
        private_key,
        binding,
        &envelope.encapsulated_key,
        &envelope.ciphertext,
    )?;
    let payload = parse_request_plaintext(&plaintext, envelope.message_kind, envelope.network_id)?;
    let lineage = AccountRequestLineage {
        binding,
        response_token,
    };
    Ok(match payload {
        AccountRequestPayload::CreationStart(payload) => {
            OpenedAccountServiceRequest::CreationStart(AuthenticatedAccountRequest {
                payload,
                lineage,
            })
        }
        AccountRequestPayload::CreationFinish(payload) => {
            OpenedAccountServiceRequest::CreationFinish(AuthenticatedAccountRequest {
                payload,
                lineage,
            })
        }
        AccountRequestPayload::AuthenticationStart(payload) => {
            OpenedAccountServiceRequest::AuthenticationStart(AuthenticatedAccountRequest {
                payload,
                lineage,
            })
        }
        AccountRequestPayload::AuthenticationFinish(payload) => {
            OpenedAccountServiceRequest::AuthenticationFinish(AuthenticatedAccountRequest {
                payload,
                lineage,
            })
        }
        AccountRequestPayload::CredentialChangeStart(payload) => {
            OpenedAccountServiceRequest::CredentialChangeStart(AuthenticatedAccountRequest {
                payload,
                lineage,
            })
        }
        AccountRequestPayload::CredentialChangeFinish(payload) => {
            OpenedAccountServiceRequest::CredentialChangeFinish(AuthenticatedAccountRequest {
                payload,
                lineage,
            })
        }
    })
}

fn parse_request_plaintext(
    plaintext: &OpenedHpkeRequest,
    message_kind: AccountServiceMessageKind,
    expected_network: NetworkId,
) -> Result<AccountRequestPayload, AuthError> {
    let mut cursor = Cursor::new(plaintext.expose_for_account_parser());
    if cursor.read_u16()? != PADDING_VERSION {
        return Err(AuthError::InvalidEncoding);
    }
    let inner_length = usize::from(cursor.read_u16()?);
    if !(REQUEST_INNER_MIN_BYTES..=REQUEST_INNER_MAX_BYTES).contains(&inner_length) {
        return Err(AuthError::InvalidEncoding);
    }
    let inner = cursor.read_slice(inner_length)?;
    let padding_length = usize::from(cursor.read_u16()?);
    let expected_padding = REQUEST_PADDING_BASE
        .checked_sub(inner_length)
        .ok_or(AuthError::InvalidEncoding)?;
    if padding_length != expected_padding {
        return Err(AuthError::InvalidEncoding);
    }
    let padding = cursor.read_slice(padding_length)?;
    if !cursor.is_finished() || padding.iter().any(|byte| *byte != 0) {
        return Err(AuthError::InvalidEncoding);
    }
    parse_inner_request(message_kind, expected_network, inner)
}

fn parse_inner_request(
    message_kind: AccountServiceMessageKind,
    expected_network: NetworkId,
    inner: &[u8],
) -> Result<AccountRequestPayload, AuthError> {
    let mut cursor = Cursor::new(inner);
    if cursor.read_u16()? != PROFILE_VERSION {
        return Err(AuthError::InvalidEncoding);
    }
    let network_id = NetworkId::from_bytes(cursor.read_array()?);
    if network_id != expected_network {
        return Err(AuthError::ContextMismatch);
    }
    let payload = match message_kind {
        AccountServiceMessageKind::AccountCreateStart => {
            parse_creation_start(network_id, &mut cursor)?
        }
        AccountServiceMessageKind::AccountCreateFinish => {
            parse_creation_finish(network_id, &mut cursor)?
        }
        AccountServiceMessageKind::OpaqueAuthStart => {
            parse_authentication_start(network_id, &mut cursor)?
        }
        AccountServiceMessageKind::OpaqueAuthFinish => {
            parse_authentication_finish(network_id, &mut cursor)?
        }
        AccountServiceMessageKind::CredentialChangeStart => {
            parse_credential_change_start(network_id, &mut cursor)?
        }
        AccountServiceMessageKind::CredentialChangeFinish => {
            parse_credential_change_finish(network_id, &mut cursor)?
        }
    };
    if !cursor.is_finished() {
        return Err(AuthError::InvalidEncoding);
    }
    Ok(payload)
}

fn parse_creation_start(
    network_id: NetworkId,
    cursor: &mut Cursor<'_>,
) -> Result<AccountRequestPayload, AuthError> {
    let login = parse_login(cursor.read_vector_u8(MIN_LOGIN_BYTES, MAX_LOGIN_BYTES)?)?;
    let registration_request = read_registration_request(cursor)?;
    let invitation = match cursor.read_vector_u8(0, ACCOUNT_CREATION_INVITE_BYTES)? {
        [] => None,
        bytes if bytes.len() == ACCOUNT_CREATION_INVITE_BYTES => {
            let bytes: &[u8; ACCOUNT_CREATION_INVITE_BYTES] =
                bytes.try_into().map_err(|_| AuthError::InvalidEncoding)?;
            Some(AccountCreationInvite::parse(bytes)?)
        }
        _ => return Err(AuthError::InvalidEncoding),
    };
    Ok(AccountRequestPayload::CreationStart(CreationStart {
        network_id,
        login,
        registration_request,
        invitation,
    }))
}

fn parse_creation_finish(
    network_id: NetworkId,
    cursor: &mut Cursor<'_>,
) -> Result<AccountRequestPayload, AuthError> {
    let transaction_id = TransactionId::from_bytes(cursor.read_array()?);
    let registration_record = read_registration_record(cursor)?;
    Ok(AccountRequestPayload::CreationFinish(CreationFinish {
        network_id,
        transaction_id,
        registration_record,
    }))
}

fn parse_authentication_start(
    network_id: NetworkId,
    cursor: &mut Cursor<'_>,
) -> Result<AccountRequestPayload, AuthError> {
    let login = parse_login(cursor.read_vector_u8(MIN_LOGIN_BYTES, MAX_LOGIN_BYTES)?)?;
    let bytes = cursor.read_vector_u8(OPAQUE_KE1_BYTES, OPAQUE_KE1_BYTES)?;
    let ke1 = OpaqueKe1::from_bytes(bytes.try_into().map_err(|_| AuthError::InvalidEncoding)?)?;
    Ok(AccountRequestPayload::AuthenticationStart(
        AuthenticationStart {
            network_id,
            login,
            ke1,
        },
    ))
}

fn parse_authentication_finish(
    network_id: NetworkId,
    cursor: &mut Cursor<'_>,
) -> Result<AccountRequestPayload, AuthError> {
    let transaction_id = TransactionId::from_bytes(cursor.read_array()?);
    let bytes = cursor.read_vector_u8(OPAQUE_KE3_BYTES, OPAQUE_KE3_BYTES)?;
    let ke3 = OpaqueKe3::from_bytes(bytes.try_into().map_err(|_| AuthError::InvalidEncoding)?)?;
    Ok(AccountRequestPayload::AuthenticationFinish(
        AuthenticationFinish {
            network_id,
            transaction_id,
            ke3,
        },
    ))
}

fn parse_credential_change_start(
    network_id: NetworkId,
    cursor: &mut Cursor<'_>,
) -> Result<AccountRequestPayload, AuthError> {
    let account_bytes: [u8; 24] = cursor.read_array()?;
    let account_id =
        AccountId::parse_wire_bytes(&account_bytes).map_err(|_| AuthError::InvalidEncoding)?;
    let registration_request = read_registration_request(cursor)?;
    Ok(AccountRequestPayload::CredentialChangeStart(
        CredentialChangeStart {
            network_id,
            account_id,
            registration_request,
        },
    ))
}

fn parse_credential_change_finish(
    network_id: NetworkId,
    cursor: &mut Cursor<'_>,
) -> Result<AccountRequestPayload, AuthError> {
    let transaction_id = TransactionId::from_bytes(cursor.read_array()?);
    let registration_record = read_registration_record(cursor)?;
    Ok(AccountRequestPayload::CredentialChangeFinish(
        CredentialChangeFinish {
            network_id,
            transaction_id,
            registration_record,
        },
    ))
}

fn parse_login(bytes: &[u8]) -> Result<agenc_ircd_types::NormalizedLogin, AuthError> {
    let text = std::str::from_utf8(bytes).map_err(|_| AuthError::InvalidEncoding)?;
    let login =
        agenc_ircd_types::NormalizedLogin::prepare(text).map_err(|_| AuthError::InvalidEncoding)?;
    if login.as_str().as_bytes() != bytes {
        return Err(AuthError::InvalidEncoding);
    }
    Ok(login)
}

fn read_registration_request(
    cursor: &mut Cursor<'_>,
) -> Result<OpaqueRegistrationRequest, AuthError> {
    let bytes = cursor.read_vector_u8(
        OPAQUE_REGISTRATION_REQUEST_BYTES,
        OPAQUE_REGISTRATION_REQUEST_BYTES,
    )?;
    OpaqueRegistrationRequest::from_bytes(bytes.try_into().map_err(|_| AuthError::InvalidEncoding)?)
}

fn read_registration_record(
    cursor: &mut Cursor<'_>,
) -> Result<OpaqueRegistrationRecord, AuthError> {
    let bytes = cursor.read_vector_u8(
        OPAQUE_REGISTRATION_RECORD_BYTES,
        OPAQUE_REGISTRATION_RECORD_BYTES,
    )?;
    OpaqueRegistrationRecord::from_bytes(bytes.try_into().map_err(|_| AuthError::InvalidEncoding)?)
}

/// Decrypted and fully validated request selected by the authenticated kind.
pub enum AccountRequestPayload {
    /// Account-creation registration start.
    CreationStart(CreationStart),
    /// Account-creation registration finish.
    CreationFinish(CreationFinish),
    /// OPAQUE authentication start.
    AuthenticationStart(AuthenticationStart),
    /// OPAQUE authentication finish.
    AuthenticationFinish(AuthenticationFinish),
    /// Credential replacement registration start.
    CredentialChangeStart(CredentialChangeStart),
    /// Credential replacement registration finish.
    CredentialChangeFinish(CredentialChangeFinish),
}

impl AccountRequestPayload {
    /// Returns the authenticated outer discriminant required by this inner arm.
    #[must_use]
    pub const fn message_kind(&self) -> AccountServiceMessageKind {
        match self {
            Self::CreationStart(_) => AccountServiceMessageKind::AccountCreateStart,
            Self::CreationFinish(_) => AccountServiceMessageKind::AccountCreateFinish,
            Self::AuthenticationStart(_) => AccountServiceMessageKind::OpaqueAuthStart,
            Self::AuthenticationFinish(_) => AccountServiceMessageKind::OpaqueAuthFinish,
            Self::CredentialChangeStart(_) => AccountServiceMessageKind::CredentialChangeStart,
            Self::CredentialChangeFinish(_) => AccountServiceMessageKind::CredentialChangeFinish,
        }
    }
}

/// Encodes one canonical inner request into the exact all-zero-padded HPKE plaintext.
pub fn encode_request_plaintext(
    payload: &AccountRequestPayload,
) -> Result<EncodedAccountRequestPlaintext, AuthError> {
    let inner = encode_inner_request(payload)?;
    if !(REQUEST_INNER_MIN_BYTES..=REQUEST_INNER_MAX_BYTES).contains(&inner.len()) {
        return Err(AuthError::InvalidEncoding);
    }
    let padding_length = REQUEST_PADDING_BASE
        .checked_sub(inner.len())
        .ok_or(AuthError::InvalidEncoding)?;
    let inner_length = u16::try_from(inner.len()).map_err(|_| AuthError::Overflow)?;
    let padding_length_u16 = u16::try_from(padding_length).map_err(|_| AuthError::Overflow)?;
    let mut plaintext = Zeroizing::new([0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES]);
    let mut writer = Writer::new(plaintext.as_mut());
    writer.write(&PADDING_VERSION.to_be_bytes())?;
    writer.write(&inner_length.to_be_bytes())?;
    writer.write(&inner)?;
    writer.write(&padding_length_u16.to_be_bytes())?;
    writer.write_zeros(padding_length)?;
    if !writer.is_finished() {
        return Err(AuthError::InvalidEncoding);
    }
    Ok(EncodedAccountRequestPlaintext(plaintext))
}

fn encode_inner_request(payload: &AccountRequestPayload) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(REQUEST_INNER_MAX_BYTES)
        .map_err(|_| AuthError::AllocationFailed)?;
    encoded.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    match payload {
        AccountRequestPayload::CreationStart(request) => {
            encoded.extend_from_slice(request.network_id.as_bytes());
            encode_vector_u8(&mut encoded, request.login.as_str().as_bytes())?;
            encode_vector_u8(
                &mut encoded,
                request.registration_request.expose_for_account_request(),
            )?;
            encode_optional_invitation(&mut encoded, request.invitation.as_ref())?;
        }
        AccountRequestPayload::CreationFinish(request) => {
            encoded.extend_from_slice(request.network_id.as_bytes());
            encoded.extend_from_slice(request.transaction_id.as_bytes());
            encode_vector_u8(
                &mut encoded,
                request.registration_record.expose_for_persistence(),
            )?;
        }
        AccountRequestPayload::AuthenticationStart(request) => {
            encoded.extend_from_slice(request.network_id.as_bytes());
            encode_vector_u8(&mut encoded, request.login.as_str().as_bytes())?;
            encode_vector_u8(&mut encoded, request.ke1.expose_for_account_request())?;
        }
        AccountRequestPayload::AuthenticationFinish(request) => {
            encoded.extend_from_slice(request.network_id.as_bytes());
            encoded.extend_from_slice(request.transaction_id.as_bytes());
            encode_vector_u8(&mut encoded, request.ke3.expose_for_account_request())?;
        }
        AccountRequestPayload::CredentialChangeStart(request) => {
            encoded.extend_from_slice(request.network_id.as_bytes());
            encoded.extend_from_slice(request.account_id.to_text().as_bytes());
            encode_vector_u8(
                &mut encoded,
                request.registration_request.expose_for_account_request(),
            )?;
        }
        AccountRequestPayload::CredentialChangeFinish(request) => {
            encoded.extend_from_slice(request.network_id.as_bytes());
            encoded.extend_from_slice(request.transaction_id.as_bytes());
            encode_vector_u8(
                &mut encoded,
                request.registration_record.expose_for_persistence(),
            )?;
        }
    }
    Ok(encoded)
}

fn encode_vector_u8(encoded: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthError> {
    let length = u8::try_from(value.len()).map_err(|_| AuthError::InvalidEncoding)?;
    encoded.push(length);
    encoded.extend_from_slice(value);
    Ok(())
}

fn encode_optional_invitation(
    encoded: &mut Vec<u8>,
    invitation: Option<&AccountCreationInvite>,
) -> Result<(), AuthError> {
    if let Some(invitation) = invitation {
        return encode_vector_u8(encoded, invitation.expose_for_account_request());
    }
    encoded.push(0);
    Ok(())
}

/// Validated account-creation start fields.
pub struct CreationStart {
    /// Repeated authenticated network identity.
    pub network_id: NetworkId,
    /// Canonical private login identifier.
    pub login: agenc_ircd_types::NormalizedLogin,
    /// Exact OPAQUE registration request.
    pub registration_request: OpaqueRegistrationRequest,
    /// Optional signed invitation, subject to deployment policy.
    pub invitation: Option<AccountCreationInvite>,
}

/// Validated account-creation finish fields.
pub struct CreationFinish {
    /// Repeated authenticated network identity.
    pub network_id: NetworkId,
    /// One-use creation transaction identity.
    pub transaction_id: TransactionId,
    /// Exact candidate OPAQUE record.
    pub registration_record: OpaqueRegistrationRecord,
}

/// Validated OPAQUE authentication start fields.
pub struct AuthenticationStart {
    /// Repeated authenticated network identity.
    pub network_id: NetworkId,
    /// Canonical private login identifier.
    pub login: agenc_ircd_types::NormalizedLogin,
    /// Exact KE1 request.
    pub ke1: OpaqueKe1,
}

/// Validated OPAQUE authentication finish fields.
pub struct AuthenticationFinish {
    /// Repeated authenticated network identity.
    pub network_id: NetworkId,
    /// One-use authentication transaction identity.
    pub transaction_id: TransactionId,
    /// Exact KE3 finalization.
    pub ke3: OpaqueKe3,
}

/// Validated credential-change start fields.
pub struct CredentialChangeStart {
    /// Repeated authenticated network identity.
    pub network_id: NetworkId,
    /// Account required to match the fresh proof.
    pub account_id: AccountId,
    /// Exact replacement registration request.
    pub registration_request: OpaqueRegistrationRequest,
}

/// Validated credential-change finish fields.
pub struct CredentialChangeFinish {
    /// Repeated authenticated network identity.
    pub network_id: NetworkId,
    /// One-use credential-change transaction identity.
    pub transaction_id: TransactionId,
    /// Exact replacement OPAQUE record.
    pub registration_record: OpaqueRegistrationRecord,
}

/// Exact account-service completion fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    transaction_id: TransactionId,
    status: AccountServiceCompletionStatus,
    account_id: Option<AccountId>,
    account_session_generation: u64,
}

impl Completion {
    /// Constructs the single canonical rejected completion.
    #[must_use]
    pub const fn rejected(transaction_id: TransactionId) -> Self {
        Self {
            transaction_id,
            status: AccountServiceCompletionStatus::Rejected,
            account_id: None,
            account_session_generation: 0,
        }
    }

    /// Constructs a committed completion for later kind-specific validation.
    #[must_use]
    pub const fn committed(
        transaction_id: TransactionId,
        account_id: AccountId,
        account_session_generation: u64,
    ) -> Self {
        Self {
            transaction_id,
            status: AccountServiceCompletionStatus::Committed,
            account_id: Some(account_id),
            account_session_generation,
        }
    }

    /// Returns the one-use transaction completed by this receipt.
    #[must_use]
    pub const fn transaction_id(self) -> TransactionId {
        self.transaction_id
    }

    /// Returns whether the coordinator rejected or committed the operation.
    #[must_use]
    pub const fn status(self) -> AccountServiceCompletionStatus {
        self.status
    }

    /// Returns the committed account, or `None` for a rejected receipt.
    #[must_use]
    pub const fn account_id(self) -> Option<AccountId> {
        self.account_id
    }

    /// Returns the authenticated resulting account-session generation.
    #[must_use]
    pub const fn account_session_generation(self) -> u64 {
        self.account_session_generation
    }
}

/// Exact payload selected by one registered response kind.
pub enum AccountServiceResponsePayload {
    /// OPAQUE registration challenge for account creation.
    CreationChallenge {
        /// One-use transaction identity.
        transaction_id: TransactionId,
        /// Private OPAQUE credential identity.
        credential_id: OpaqueCredentialId,
        /// Exact registration response.
        response: OpaqueRegistrationResponse,
    },
    /// OPAQUE KE2 authentication challenge.
    AuthenticationChallenge {
        /// One-use transaction identity.
        transaction_id: TransactionId,
        /// Real or stable fake private credential identity.
        credential_id: OpaqueCredentialId,
        /// Exact KE2 response.
        ke2: Box<OpaqueKe2>,
    },
    /// OPAQUE registration challenge for credential replacement.
    CredentialChangeChallenge {
        /// One-use transaction identity.
        transaction_id: TransactionId,
        /// Existing private credential identity.
        credential_id: OpaqueCredentialId,
        /// Exact registration response.
        response: OpaqueRegistrationResponse,
    },
    /// Account-creation completion.
    CreationCompletion(Completion),
    /// OPAQUE-authentication completion.
    AuthenticationCompletion(Completion),
    /// Credential-change completion.
    CredentialChangeCompletion(Completion),
}

impl AccountServiceResponsePayload {
    /// Returns the exact authenticated response discriminant.
    #[must_use]
    pub const fn response_kind(&self) -> AccountServiceResponseKind {
        match self {
            Self::CreationChallenge { .. } => AccountServiceResponseKind::AccountCreateChallenge,
            Self::AuthenticationChallenge { .. } => AccountServiceResponseKind::OpaqueAuthChallenge,
            Self::CredentialChangeChallenge { .. } => {
                AccountServiceResponseKind::CredentialChangeChallenge
            }
            Self::CreationCompletion(_) => AccountServiceResponseKind::AccountCreateComplete,
            Self::AuthenticationCompletion(_) => AccountServiceResponseKind::OpaqueAuthComplete,
            Self::CredentialChangeCompletion(_) => {
                AccountServiceResponseKind::CredentialChangeComplete
            }
        }
    }

    /// Returns the transaction repeated by this challenge or completion.
    #[must_use]
    pub(crate) const fn transaction_id(&self) -> TransactionId {
        match self {
            Self::CreationChallenge { transaction_id, .. }
            | Self::AuthenticationChallenge { transaction_id, .. }
            | Self::CredentialChangeChallenge { transaction_id, .. } => *transaction_id,
            Self::CreationCompletion(completion)
            | Self::AuthenticationCompletion(completion)
            | Self::CredentialChangeCompletion(completion) => completion.transaction_id,
        }
    }

    /// Checks the closed request/response-kind mapping before response sealing.
    #[must_use]
    pub(crate) const fn matches_request_kind(
        &self,
        request_kind: AccountServiceMessageKind,
    ) -> bool {
        matches!(
            (request_kind, self.response_kind()),
            (
                AccountServiceMessageKind::AccountCreateStart,
                AccountServiceResponseKind::AccountCreateChallenge
            ) | (
                AccountServiceMessageKind::AccountCreateFinish,
                AccountServiceResponseKind::AccountCreateComplete
            ) | (
                AccountServiceMessageKind::OpaqueAuthStart,
                AccountServiceResponseKind::OpaqueAuthChallenge
            ) | (
                AccountServiceMessageKind::OpaqueAuthFinish,
                AccountServiceResponseKind::OpaqueAuthComplete
            ) | (
                AccountServiceMessageKind::CredentialChangeStart,
                AccountServiceResponseKind::CredentialChangeChallenge
            ) | (
                AccountServiceMessageKind::CredentialChangeFinish,
                AccountServiceResponseKind::CredentialChangeComplete
            )
        )
    }
}

/// Encodes the exact 4,208-byte all-zero-padded response plaintext.
pub fn encode_response_plaintext(
    payload: &AccountServiceResponsePayload,
) -> Result<EncodedAccountResponsePlaintext, AuthError> {
    let payload_bytes = encode_response_payload(payload)?;
    if !(RESPONSE_PAYLOAD_MIN_BYTES..=RESPONSE_PAYLOAD_MAX_BYTES).contains(&payload_bytes.len()) {
        return Err(AuthError::InvalidEncoding);
    }
    let padding_length = RESPONSE_PADDING_BASE
        .checked_sub(payload_bytes.len())
        .ok_or(AuthError::InvalidEncoding)?;
    let payload_length = u16::try_from(payload_bytes.len()).map_err(|_| AuthError::Overflow)?;
    let padding_length_u16 = u16::try_from(padding_length).map_err(|_| AuthError::Overflow)?;
    let mut plaintext = Zeroizing::new([0_u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES]);
    let mut writer = Writer::new(plaintext.as_mut());
    writer.write(&PADDING_VERSION.to_be_bytes())?;
    writer.write(&payload_length.to_be_bytes())?;
    writer.write(&payload_bytes)?;
    writer.write(&padding_length_u16.to_be_bytes())?;
    writer.write_zeros(padding_length)?;
    if !writer.is_finished() {
        return Err(AuthError::InvalidEncoding);
    }
    Ok(EncodedAccountResponsePlaintext(plaintext))
}

/// Opens a response only when its public header matches the originating request.
pub fn open_and_parse_response(
    token: AccountResponseOpenToken,
    response: &AccountServiceResponse,
) -> Result<AccountServiceResponsePayload, AuthError> {
    let binding = token.request_binding();
    if response.network_id != binding.network_id()
        || response.recipient_key_id != binding.recipient_key_id()
        || response.client_request_id != binding.client_request_id()
    {
        return Err(AuthError::ContextMismatch);
    }
    let plaintext = token.open_response(
        response.response_kind,
        &response.response_salt,
        &response.ciphertext,
    )?;
    parse_response_plaintext(&plaintext, response.response_kind)
}

fn parse_response_plaintext(
    plaintext: &OpenedAccountResponse,
    response_kind: AccountServiceResponseKind,
) -> Result<AccountServiceResponsePayload, AuthError> {
    let mut cursor = Cursor::new(plaintext.expose_for_account_parser());
    if cursor.read_u16()? != PADDING_VERSION {
        return Err(AuthError::InvalidEncoding);
    }
    let payload_length = usize::from(cursor.read_u16()?);
    if !(RESPONSE_PAYLOAD_MIN_BYTES..=RESPONSE_PAYLOAD_MAX_BYTES).contains(&payload_length) {
        return Err(AuthError::InvalidEncoding);
    }
    let payload = cursor.read_slice(payload_length)?;
    let padding_length = usize::from(cursor.read_u16()?);
    let expected_padding = RESPONSE_PADDING_BASE
        .checked_sub(payload_length)
        .ok_or(AuthError::InvalidEncoding)?;
    if padding_length != expected_padding {
        return Err(AuthError::InvalidEncoding);
    }
    let padding = cursor.read_slice(padding_length)?;
    if !cursor.is_finished() || padding.iter().any(|byte| *byte != 0) {
        return Err(AuthError::InvalidEncoding);
    }
    parse_response_payload(response_kind, payload)
}

fn parse_response_payload(
    response_kind: AccountServiceResponseKind,
    payload: &[u8],
) -> Result<AccountServiceResponsePayload, AuthError> {
    let mut cursor = Cursor::new(payload);
    if cursor.read_u16()? != PROFILE_VERSION {
        return Err(AuthError::InvalidEncoding);
    }
    let parsed = match response_kind {
        AccountServiceResponseKind::AccountCreateChallenge => {
            let (transaction_id, credential_id, opaque_message) = parse_challenge(&mut cursor)?;
            let response = OpaqueRegistrationResponse::from_bytes(
                opaque_message
                    .try_into()
                    .map_err(|_| AuthError::InvalidEncoding)?,
            )?;
            AccountServiceResponsePayload::CreationChallenge {
                transaction_id,
                credential_id,
                response,
            }
        }
        AccountServiceResponseKind::OpaqueAuthChallenge => {
            let (transaction_id, credential_id, opaque_message) = parse_challenge(&mut cursor)?;
            let ke2 = OpaqueKe2::from_bytes(
                opaque_message
                    .try_into()
                    .map_err(|_| AuthError::InvalidEncoding)?,
            )?;
            AccountServiceResponsePayload::AuthenticationChallenge {
                transaction_id,
                credential_id,
                ke2: Box::new(ke2),
            }
        }
        AccountServiceResponseKind::CredentialChangeChallenge => {
            let (transaction_id, credential_id, opaque_message) = parse_challenge(&mut cursor)?;
            let response = OpaqueRegistrationResponse::from_bytes(
                opaque_message
                    .try_into()
                    .map_err(|_| AuthError::InvalidEncoding)?,
            )?;
            AccountServiceResponsePayload::CredentialChangeChallenge {
                transaction_id,
                credential_id,
                response,
            }
        }
        AccountServiceResponseKind::AccountCreateComplete => {
            AccountServiceResponsePayload::CreationCompletion(parse_completion(
                &mut cursor,
                CompletionRule::Creation,
            )?)
        }
        AccountServiceResponseKind::OpaqueAuthComplete => {
            AccountServiceResponsePayload::AuthenticationCompletion(parse_completion(
                &mut cursor,
                CompletionRule::Session,
            )?)
        }
        AccountServiceResponseKind::CredentialChangeComplete => {
            AccountServiceResponsePayload::CredentialChangeCompletion(parse_completion(
                &mut cursor,
                CompletionRule::Session,
            )?)
        }
    };
    if !cursor.is_finished() {
        return Err(AuthError::InvalidEncoding);
    }
    Ok(parsed)
}

fn parse_challenge<'a>(
    cursor: &mut Cursor<'a>,
) -> Result<(TransactionId, OpaqueCredentialId, &'a [u8]), AuthError> {
    let transaction_id = TransactionId::from_bytes(cursor.read_array()?);
    let credential_id = OpaqueCredentialId::from_bytes(cursor.read_array()?);
    let opaque_message =
        cursor.read_vector_u16(OPAQUE_REGISTRATION_RESPONSE_BYTES, OPAQUE_KE2_BYTES)?;
    Ok((transaction_id, credential_id, opaque_message))
}

fn parse_completion(
    cursor: &mut Cursor<'_>,
    rule: CompletionRule,
) -> Result<Completion, AuthError> {
    let transaction_id = TransactionId::from_bytes(cursor.read_array()?);
    let status = AccountServiceCompletionStatus::from_wire(cursor.read_u16()?)
        .map_err(|_| AuthError::InvalidEncoding)?;
    let account_bytes: [u8; 24] = cursor.read_array()?;
    let account_session_generation = cursor.read_u64()?;
    let account_id = match status {
        AccountServiceCompletionStatus::Rejected
            if account_bytes == [0_u8; 24] && account_session_generation == 0 =>
        {
            None
        }
        AccountServiceCompletionStatus::Committed => Some(
            AccountId::parse_wire_bytes(&account_bytes).map_err(|_| AuthError::InvalidEncoding)?,
        ),
        _ => return Err(AuthError::InvalidEncoding),
    };
    let valid_generation = match rule {
        CompletionRule::Creation => account_session_generation == 0,
        CompletionRule::Session => account_session_generation != 0,
    };
    if status == AccountServiceCompletionStatus::Committed && !valid_generation {
        return Err(AuthError::InvalidEncoding);
    }
    Ok(Completion {
        transaction_id,
        status,
        account_id,
        account_session_generation,
    })
}

fn encode_response_payload(
    payload: &AccountServiceResponsePayload,
) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(RESPONSE_PAYLOAD_MAX_BYTES)
        .map_err(|_| AuthError::AllocationFailed)?;
    encoded.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    match payload {
        AccountServiceResponsePayload::CreationChallenge {
            transaction_id,
            credential_id,
            response,
        }
        | AccountServiceResponsePayload::CredentialChangeChallenge {
            transaction_id,
            credential_id,
            response,
        } => encode_challenge(
            &mut encoded,
            *transaction_id,
            credential_id,
            response.expose_for_account_response(),
        )?,
        AccountServiceResponsePayload::AuthenticationChallenge {
            transaction_id,
            credential_id,
            ke2,
        } => encode_challenge(
            &mut encoded,
            *transaction_id,
            credential_id,
            ke2.expose_for_account_response(),
        )?,
        AccountServiceResponsePayload::CreationCompletion(completion) => {
            encode_completion(&mut encoded, completion, CompletionRule::Creation)?;
        }
        AccountServiceResponsePayload::AuthenticationCompletion(completion) => {
            encode_completion(&mut encoded, completion, CompletionRule::Session)?;
        }
        AccountServiceResponsePayload::CredentialChangeCompletion(completion) => {
            encode_completion(&mut encoded, completion, CompletionRule::Session)?;
        }
    }
    Ok(encoded)
}

fn encode_challenge(
    encoded: &mut Vec<u8>,
    transaction_id: TransactionId,
    credential_id: &OpaqueCredentialId,
    opaque_message: &[u8],
) -> Result<(), AuthError> {
    if opaque_message.len() != OPAQUE_REGISTRATION_RESPONSE_BYTES
        && opaque_message.len() != OPAQUE_KE2_BYTES
    {
        return Err(AuthError::InvalidEncoding);
    }
    encoded.extend_from_slice(transaction_id.as_bytes());
    encoded.extend_from_slice(credential_id.expose_for_account_service());
    let length = u16::try_from(opaque_message.len()).map_err(|_| AuthError::Overflow)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(opaque_message);
    Ok(())
}

#[derive(Clone, Copy)]
enum CompletionRule {
    Creation,
    Session,
}

fn encode_completion(
    encoded: &mut Vec<u8>,
    completion: &Completion,
    rule: CompletionRule,
) -> Result<(), AuthError> {
    let valid_committed_generation = match rule {
        CompletionRule::Creation => completion.account_session_generation == 0,
        CompletionRule::Session => completion.account_session_generation != 0,
    };
    match (completion.status, completion.account_id) {
        (AccountServiceCompletionStatus::Rejected, None)
            if completion.account_session_generation == 0 => {}
        (AccountServiceCompletionStatus::Committed, Some(_)) if valid_committed_generation => {}
        _ => return Err(AuthError::InvalidEncoding),
    }
    encoded.extend_from_slice(completion.transaction_id.as_bytes());
    encoded.extend_from_slice(&completion.status.wire_value().to_be_bytes());
    if let Some(account_id) = completion.account_id {
        encoded.extend_from_slice(account_id.to_text().as_bytes());
    } else {
        encoded.extend_from_slice(&[0_u8; 24]);
    }
    encoded.extend_from_slice(&completion.account_session_generation.to_be_bytes());
    Ok(())
}

/// Canonical outer response stored and replayed byte-for-byte.
pub struct AccountServiceResponse {
    encoded: [u8; ACCOUNT_SERVICE_RESPONSE_BYTES],
    network_id: NetworkId,
    recipient_key_id: AccountHpkeKeyId,
    response_kind: AccountServiceResponseKind,
    client_request_id: RequestId,
    response_salt: [u8; 32],
    ciphertext: [u8; ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES],
}

impl AccountServiceResponse {
    /// Encodes a newly sealed response without resealing it.
    pub fn from_sealed(sealed: SealedAccountResponse) -> Result<Self, AuthError> {
        let binding = sealed.request_binding();
        let mut encoded = [0_u8; ACCOUNT_SERVICE_RESPONSE_BYTES];
        let mut writer = Writer::new(&mut encoded);
        writer.write(&PROFILE_VERSION.to_be_bytes())?;
        writer.write(binding.network_id().as_bytes())?;
        writer.write(binding.recipient_key_id().as_bytes())?;
        writer.write(binding.client_request_id().as_bytes())?;
        writer.write(&sealed.response_kind().wire_value().to_be_bytes())?;
        writer.write(sealed.response_salt())?;
        writer.write(
            &u16::try_from(ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES)
                .map_err(|_| AuthError::Overflow)?
                .to_be_bytes(),
        )?;
        writer.write(sealed.ciphertext())?;
        Self::parse(encoded)
    }

    /// Parses an exact stored or forwarded response.
    pub fn parse(encoded: [u8; ACCOUNT_SERVICE_RESPONSE_BYTES]) -> Result<Self, AuthError> {
        let mut cursor = Cursor::new(&encoded);
        if cursor.read_u16()? != PROFILE_VERSION {
            return Err(AuthError::InvalidEncoding);
        }
        let network_id = NetworkId::from_bytes(cursor.read_array()?);
        let recipient_key_id = AccountHpkeKeyId::from_bytes(cursor.read_array()?);
        let client_request_id = RequestId::from_bytes(cursor.read_array()?);
        let response_kind = AccountServiceResponseKind::from_wire(cursor.read_u16()?)
            .map_err(|_| AuthError::InvalidEncoding)?;
        let response_salt = cursor.read_array()?;
        if usize::from(cursor.read_u16()?) != ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES {
            return Err(AuthError::InvalidEncoding);
        }
        let ciphertext = cursor.read_array()?;
        if !cursor.is_finished() {
            return Err(AuthError::InvalidEncoding);
        }
        Ok(Self {
            encoded,
            network_id,
            recipient_key_id,
            response_kind,
            client_request_id,
            response_salt,
            ciphertext,
        })
    }

    /// Borrows the byte-identical response for storage, replay, or forwarding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ACCOUNT_SERVICE_RESPONSE_BYTES] {
        &self.encoded
    }

    /// Returns the response kind visible to an edge.
    #[must_use]
    pub const fn response_kind(&self) -> AccountServiceResponseKind {
        self.response_kind
    }

    /// Returns the client request ID matched by this response.
    #[must_use]
    pub const fn client_request_id(&self) -> RequestId {
        self.client_request_id
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn read_array<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], AuthError> {
        self.read_slice(SIZE)?
            .try_into()
            .map_err(|_| AuthError::InvalidEncoding)
    }

    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], AuthError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(AuthError::InvalidEncoding)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(AuthError::InvalidEncoding)?;
        self.position = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, AuthError> {
        let [value] = self.read_array()?;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, AuthError> {
        self.read_array().map(u16::from_be_bytes)
    }

    fn read_u64(&mut self) -> Result<u64, AuthError> {
        self.read_array().map(u64::from_be_bytes)
    }

    fn read_vector_u8(&mut self, minimum: usize, maximum: usize) -> Result<&'a [u8], AuthError> {
        let length = usize::from(self.read_u8()?);
        if !(minimum..=maximum).contains(&length) {
            return Err(AuthError::InvalidEncoding);
        }
        self.read_slice(length)
    }

    fn read_vector_u16(&mut self, minimum: usize, maximum: usize) -> Result<&'a [u8], AuthError> {
        let length = usize::from(self.read_u16()?);
        if !(minimum..=maximum).contains(&length) {
            return Err(AuthError::InvalidEncoding);
        }
        self.read_slice(length)
    }

    const fn position(&self) -> usize {
        self.position
    }

    const fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }
}

struct Writer<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), AuthError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(AuthError::Overflow)?;
        let destination = self
            .output
            .get_mut(self.position..end)
            .ok_or(AuthError::InvalidEncoding)?;
        destination.copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn write_zeros(&mut self, length: usize) -> Result<(), AuthError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(AuthError::Overflow)?;
        let destination = self
            .output
            .get_mut(self.position..end)
            .ok_or(AuthError::InvalidEncoding)?;
        destination.fill(0);
        self.position = end;
        Ok(())
    }

    const fn is_finished(&self) -> bool {
        self.position == self.output.len()
    }
}

const _: () = {
    // agenc-review: internal-assert owner=auth reviewed=2026-08-27 reason=fixed-request-wrapper-arithmetic
    assert!(
        REQUEST_HEADER_BYTES + 32 + 2 + ACCOUNT_HPKE_REQUEST_CIPHERTEXT_BYTES
            == ACCOUNT_SERVICE_ENVELOPE_BYTES
    );
    // agenc-review: internal-assert owner=auth reviewed=2026-08-27 reason=fixed-response-wrapper-arithmetic
    assert!(
        RESPONSE_HEADER_BYTES + 2 + ACCOUNT_HPKE_RESPONSE_CIPHERTEXT_BYTES
            == ACCOUNT_SERVICE_RESPONSE_BYTES
    );
};

#[cfg(test)]
mod tests {
    use super::{AuthError, Cursor, Writer};

    #[test]
    fn cursor_rejects_truncation_invalid_vectors_and_position_overflow() {
        let mut truncated = Cursor::new(&[0]);
        assert_eq!(truncated.read_u16().err(), Some(AuthError::InvalidEncoding));

        let mut missing_vector = Cursor::new(&[2, 1]);
        assert_eq!(
            missing_vector.read_vector_u8(1, 3).err(),
            Some(AuthError::InvalidEncoding)
        );
        let mut short_vector = Cursor::new(&[0]);
        assert_eq!(
            short_vector.read_vector_u8(1, 3).err(),
            Some(AuthError::InvalidEncoding)
        );
        let mut long_vector = Cursor::new(&[4, 0, 0, 0, 0]);
        assert_eq!(
            long_vector.read_vector_u8(1, 3).err(),
            Some(AuthError::InvalidEncoding)
        );
        let mut short_wide_vector = Cursor::new(&[0, 1, 0]);
        assert_eq!(
            short_wide_vector.read_vector_u16(2, 3).err(),
            Some(AuthError::InvalidEncoding)
        );
        let mut long_wide_vector = Cursor::new(&[0, 4, 0, 0, 0, 0]);
        assert_eq!(
            long_wide_vector.read_vector_u16(2, 3).err(),
            Some(AuthError::InvalidEncoding)
        );

        let mut overflowing = Cursor::new(&[]);
        overflowing.position = usize::MAX;
        assert_eq!(
            overflowing.read_slice(1).err(),
            Some(AuthError::InvalidEncoding)
        );
    }

    #[test]
    fn writer_rejects_capacity_and_position_overflow_without_partial_output() {
        let mut output = [7_u8; 1];
        let mut writer = Writer::new(&mut output);
        assert_eq!(
            writer.write(&[1, 2]).err(),
            Some(AuthError::InvalidEncoding)
        );
        assert_eq!(
            writer.write_zeros(2).err(),
            Some(AuthError::InvalidEncoding)
        );
        assert_eq!(output, [7]);

        let mut output = [7_u8; 1];
        let mut writer = Writer::new(&mut output);
        writer.position = usize::MAX;
        assert_eq!(writer.write(&[1]).err(), Some(AuthError::Overflow));
        assert_eq!(writer.write_zeros(1).err(), Some(AuthError::Overflow));
        assert_eq!(output, [7]);
    }
}
