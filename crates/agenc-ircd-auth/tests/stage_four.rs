#![forbid(unsafe_code)]

//! End-to-end Stage-04 account-protocol and malicious-edge tests.

use agenc_ircd_auth::{
    ACCOUNT_CREATION_INVITE_BYTES, ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES,
    AccountAuthenticationState, AccountCreationStartParameters, AccountCreationState,
    AccountCredentialRecord, AccountOperationContext, AccountRequestPayload, AccountRouteBinding,
    AccountServiceEnvelope, AccountServiceResponse, AccountServiceResponsePayload,
    AccountTransaction, AccountTransactionBinding, AuthError, AuthenticatedAccountRequest,
    AuthenticationFinish, AuthenticationLookup, AuthenticationStart, AuthenticationStartParameters,
    Completion, CreationAdmission, CreationFinish, CreationStart, CredentialChangeFinish,
    CredentialChangeStart, CredentialChangeState, OPAQUE_KE2_BYTES, OpaqueKe1, OpaqueKe2,
    OpaqueKe3, OpaqueProfile, OpaqueRegistrationRecord, OpaqueRegistrationRequest,
    OpaqueRegistrationResponse, OpenedAccountServiceRequest, SealedAccountStart, TransactionClass,
    authentication_completion, begin_account_creation, begin_authentication,
    encode_request_plaintext as encode_secret_request_plaintext,
    encode_response_plaintext as encode_secret_response_plaintext, finish_account_authentication,
    finish_account_creation, finish_registration, open_and_parse_request, open_and_parse_response,
};
use agenc_ircd_crypto::{
    ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES, AccountHpkePrivateKey, AccountRequestBinding,
    AccountResponseOpenToken, Ed25519SecretKey, LoginIndexKey, OpaqueFakeCredentialKey, OsEntropy,
    SignatureDomain, derive_login_index, open_account_request, seal_account_request,
    sign_canonical,
};
use agenc_ircd_types::{
    AccountId, AccountRandomId, AccountServiceCompletionStatus, AccountServiceMessageKind,
    AccountServiceResponseKind, ConnectionId, Generation, InviteId, MonotonicTick, NetworkId,
    NormalizedLogin, OpaqueCredentialId, OriginId, RecoveryEpoch, RequestId, Revision, ServerId,
    ServerIncarnation, TransactionId, UtcSecond,
};
use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::errors::InternalError;
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::rand::{CryptoRng, Error as RandError, RngCore};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
    Ristretto255, TripleDh,
};

const TEST_NETWORK: NetworkId = NetworkId::from_bytes([21_u8; 32]);
const TEST_RECOVERY_EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([25_u8; 16]);
const TEST_ARGON2_SALT: [u8; 16] = [0_u8; 16];

struct TestOpaqueSuite;

impl CipherSuite for TestOpaqueSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, opaque_sha2::Sha512>;
    type Ksf = TestArgon2id;
}

#[derive(Default)]
struct TestArgon2id;

impl Ksf for TestArgon2id {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        if input.len() != 64 {
            return Err(InternalError::KsfError);
        }
        let parameters =
            Params::new(65_536, 3, 4, Some(64)).map_err(|_| InternalError::KsfError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
        let mut output = GenericArray::default();
        argon2
            .hash_password_into(&input, &TEST_ARGON2_SALT, &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

struct TestRng {
    failed: bool,
}

impl TestRng {
    const fn new() -> Self {
        Self { failed: false }
    }

    const fn succeeded(&self) -> bool {
        !self.failed
    }

    fn fill_or_latch(&mut self, destination: &mut [u8]) {
        if self.failed || OsEntropy::fill(destination).is_err() {
            destination.fill(0);
            self.failed = true;
        }
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_or_latch(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_or_latch(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.fill_or_latch(destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_or_latch(destination);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

struct ProtocolFixture {
    registration_request: OpaqueRegistrationRequest,
    registration_response: OpaqueRegistrationResponse,
    record: OpaqueRegistrationRecord,
    ke1: OpaqueKe1,
    ke2: OpaqueKe2,
    ke3: OpaqueKe3,
}

struct StoredAccountFixture {
    account_id: AccountId,
    account_revision: Revision,
    generation: Generation,
    credential_bytes: [u8; 32],
    record: OpaqueRegistrationRecord,
}

fn credential(seed: u8) -> OpaqueCredentialId {
    OpaqueCredentialId::from_bytes([seed; 32])
}

fn operation_context(
    now: u64,
) -> Result<AccountOperationContext, agenc_ircd_types::ValidationError> {
    operation_context_for_network(TEST_NETWORK, now)
}

fn operation_route() -> Result<AccountRouteBinding, agenc_ircd_types::ValidationError> {
    Ok(AccountRouteBinding::new(
        ServerId::from_bytes([26_u8; 16]),
        ServerIncarnation::from_bytes([27_u8; 16]),
        OriginId::from_bytes([22_u8; 16]),
        Generation::new(24)?,
        ConnectionId::from_bytes([23_u8; 16]),
        [28_u8; 32],
    ))
}

fn operation_context_for_network(
    network_id: NetworkId,
    now: u64,
) -> Result<AccountOperationContext, agenc_ircd_types::ValidationError> {
    Ok(AccountOperationContext::new(
        network_id,
        operation_route()?,
        MonotonicTick::from_ticks(now),
        UtcSecond::from_unix_seconds(now),
    ))
}

fn opaque_context(network_id: NetworkId) -> Vec<u8> {
    let mut context = b"agenc-chat account authentication v1".to_vec();
    context.extend_from_slice(network_id.as_bytes());
    context
}

fn identifiers<'a>(
    network_id: &'a NetworkId,
    credential_id: &'a OpaqueCredentialId,
) -> Identifiers<'a> {
    Identifiers {
        client: Some(credential_id.expose_for_account_service()),
        server: Some(network_id.as_bytes()),
    }
}

fn protocol_fixture(
    profile: &OpaqueProfile,
    credential_id: &OpaqueCredentialId,
    password: &[u8],
) -> Result<ProtocolFixture, Box<dyn core::error::Error>> {
    let mut rng = TestRng::new();
    let registration = ClientRegistration::<TestOpaqueSuite>::start(&mut rng, password)?;
    let registration_request = OpaqueRegistrationRequest::from_bytes(
        registration.message.serialize().as_slice().try_into()?,
    )?;
    let registration_response = profile.registration_start(credential_id, &registration_request)?;
    let registration_finish = registration.state.finish(
        &mut rng,
        password,
        RegistrationResponse::<TestOpaqueSuite>::deserialize(
            registration_response.expose_for_account_response(),
        )?,
        ClientRegistrationFinishParameters::new(
            identifiers(&TEST_NETWORK, credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let record = finish_registration(
        registration_finish
            .message
            .serialize()
            .as_slice()
            .try_into()?,
    )?;
    let login = ClientLogin::<TestOpaqueSuite>::start(&mut rng, password)?;
    let ke1 = OpaqueKe1::from_bytes(login.message.serialize().as_slice().try_into()?)?;
    let (ke2, state) =
        profile.authentication_start(TEST_NETWORK, credential_id, Some(&record), &ke1)?;
    let context = opaque_context(TEST_NETWORK);
    let login_finish = login.state.finish(
        &mut rng,
        password,
        CredentialResponse::<TestOpaqueSuite>::deserialize(ke2.expose_for_account_response())?,
        ClientLoginFinishParameters::new(
            Some(&context),
            identifiers(&TEST_NETWORK, credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let ke3 = OpaqueKe3::from_bytes(login_finish.message.serialize().as_slice().try_into()?)?;
    agenc_ircd_auth::finish_authentication(TEST_NETWORK, credential_id, state, &ke3)?
        .authorize_account_transition();
    assert!(
        rng.succeeded(),
        "test entropy failed inside protocol_fixture"
    );
    Ok(ProtocolFixture {
        registration_request,
        registration_response,
        record,
        ke1,
        ke2,
        ke3,
    })
}

fn copy_request(
    request: &OpaqueRegistrationRequest,
) -> Result<OpaqueRegistrationRequest, AuthError> {
    OpaqueRegistrationRequest::from_bytes(*request.expose_for_account_request())
}

fn copy_record(record: &OpaqueRegistrationRecord) -> Result<OpaqueRegistrationRecord, AuthError> {
    OpaqueRegistrationRecord::from_bytes(*record.expose_for_persistence())
}

fn encode_request_plaintext(
    payload: &AccountRequestPayload,
) -> Result<[u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES], AuthError> {
    let encoded = encode_secret_request_plaintext(payload)?;
    Ok(*encoded.expose_for_hpke())
}

fn encode_response_plaintext(
    payload: &AccountServiceResponsePayload,
) -> Result<[u8; agenc_ircd_crypto::ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES], AuthError> {
    let encoded = encode_secret_response_plaintext(payload)?;
    Ok(*encoded.expose_for_hpke())
}

fn request_round_trip(
    private_key: &AccountHpkePrivateKey,
    request_id: RequestId,
    payload: AccountRequestPayload,
) -> Result<OpenedAccountServiceRequest, Box<dyn core::error::Error>> {
    let (request, _response_token) =
        request_round_trip_with_token(private_key, request_id, payload)?;
    Ok(request)
}

fn request_round_trip_with_token(
    private_key: &AccountHpkePrivateKey,
    request_id: RequestId,
    payload: AccountRequestPayload,
) -> Result<(OpenedAccountServiceRequest, AccountResponseOpenToken), Box<dyn core::error::Error>> {
    let plaintext = encode_request_plaintext(&payload)?;
    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        TEST_NETWORK,
        TEST_RECOVERY_EPOCH,
        public_key.key_id(),
        request_id,
        payload.message_kind(),
    );
    let (sealed, open_token) = seal_account_request(public_key, binding, &plaintext)?;
    let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
    let envelope = AccountServiceEnvelope::parse(*envelope.as_bytes())?;
    let parsed = open_and_parse_request(
        private_key,
        TEST_RECOVERY_EPOCH,
        TEST_NETWORK,
        payload.message_kind(),
        &envelope,
    )?;
    Ok((parsed, open_token))
}

fn request_round_trip_in_context(
    private_key: &AccountHpkePrivateKey,
    network_id: NetworkId,
    recovery_epoch: RecoveryEpoch,
    request_id: RequestId,
    payload: AccountRequestPayload,
) -> Result<OpenedAccountServiceRequest, Box<dyn core::error::Error>> {
    let message_kind = payload.message_kind();
    let plaintext = encode_request_plaintext(&payload)?;
    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        network_id,
        recovery_epoch,
        public_key.key_id(),
        request_id,
        message_kind,
    );
    let (sealed, _response_token) = seal_account_request(public_key, binding, &plaintext)?;
    let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
    open_and_parse_request(
        private_key,
        recovery_epoch,
        network_id,
        message_kind,
        &envelope,
    )
    .map_err(Into::into)
}

fn authenticated_creation_start(
    request_id: u8,
    request: CreationStart,
) -> Result<AuthenticatedAccountRequest<CreationStart>, Box<dyn core::error::Error>> {
    let private_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    match request_round_trip(
        &private_key,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::CreationStart(request),
    )? {
        OpenedAccountServiceRequest::CreationStart(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

fn authenticated_creation_start_with_token(
    request_id: u8,
    request: CreationStart,
) -> Result<
    (
        AuthenticatedAccountRequest<CreationStart>,
        AccountResponseOpenToken,
    ),
    Box<dyn core::error::Error>,
> {
    let private_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    let (request, response_token) = request_round_trip_with_token(
        &private_key,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::CreationStart(request),
    )?;
    match request {
        OpenedAccountServiceRequest::CreationStart(request) => Ok((request, response_token)),
        _ => Err("opened request kind changed".into()),
    }
}

fn authenticated_creation_finish(
    request_id: u8,
    request: CreationFinish,
) -> Result<AuthenticatedAccountRequest<CreationFinish>, Box<dyn core::error::Error>> {
    let private_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    match request_round_trip(
        &private_key,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::CreationFinish(request),
    )? {
        OpenedAccountServiceRequest::CreationFinish(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

fn authenticated_creation_finish_with_token(
    request_id: u8,
    request: CreationFinish,
) -> Result<
    (
        AuthenticatedAccountRequest<CreationFinish>,
        AccountResponseOpenToken,
    ),
    Box<dyn core::error::Error>,
> {
    let private_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    let (request, response_token) = request_round_trip_with_token(
        &private_key,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::CreationFinish(request),
    )?;
    match request {
        OpenedAccountServiceRequest::CreationFinish(request) => Ok((request, response_token)),
        _ => Err("opened request kind changed".into()),
    }
}

fn authenticated_authentication_start(
    request_id: u8,
    request: AuthenticationStart,
) -> Result<AuthenticatedAccountRequest<AuthenticationStart>, Box<dyn core::error::Error>> {
    let private_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    match request_round_trip(
        &private_key,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::AuthenticationStart(request),
    )? {
        OpenedAccountServiceRequest::AuthenticationStart(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

fn authenticated_authentication_start_with_token(
    request_id: u8,
    request: AuthenticationStart,
) -> Result<
    (
        AuthenticatedAccountRequest<AuthenticationStart>,
        AccountResponseOpenToken,
    ),
    Box<dyn core::error::Error>,
> {
    let private_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    let (request, response_token) = request_round_trip_with_token(
        &private_key,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::AuthenticationStart(request),
    )?;
    match request {
        OpenedAccountServiceRequest::AuthenticationStart(request) => Ok((request, response_token)),
        _ => Err("opened request kind changed".into()),
    }
}

fn authenticated_authentication_finish(
    request_id: u8,
    request: AuthenticationFinish,
) -> Result<AuthenticatedAccountRequest<AuthenticationFinish>, Box<dyn core::error::Error>> {
    let private_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    match request_round_trip(
        &private_key,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::AuthenticationFinish(request),
    )? {
        OpenedAccountServiceRequest::AuthenticationFinish(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

fn authenticated_authentication_finish_with_token(
    request_id: u8,
    request: AuthenticationFinish,
) -> Result<
    (
        AuthenticatedAccountRequest<AuthenticationFinish>,
        AccountResponseOpenToken,
    ),
    Box<dyn core::error::Error>,
> {
    let private_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    let (request, response_token) = request_round_trip_with_token(
        &private_key,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::AuthenticationFinish(request),
    )?;
    match request {
        OpenedAccountServiceRequest::AuthenticationFinish(request) => Ok((request, response_token)),
        _ => Err("opened request kind changed".into()),
    }
}

fn authenticated_creation_finish_in_context(
    private_key: &AccountHpkePrivateKey,
    network_id: NetworkId,
    recovery_epoch: RecoveryEpoch,
    request_id: u8,
    request: CreationFinish,
) -> Result<AuthenticatedAccountRequest<CreationFinish>, Box<dyn core::error::Error>> {
    match request_round_trip_in_context(
        private_key,
        network_id,
        recovery_epoch,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::CreationFinish(request),
    )? {
        OpenedAccountServiceRequest::CreationFinish(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

fn authenticated_authentication_finish_in_context(
    private_key: &AccountHpkePrivateKey,
    network_id: NetworkId,
    recovery_epoch: RecoveryEpoch,
    request_id: u8,
    request: AuthenticationFinish,
) -> Result<AuthenticatedAccountRequest<AuthenticationFinish>, Box<dyn core::error::Error>> {
    match request_round_trip_in_context(
        private_key,
        network_id,
        recovery_epoch,
        RequestId::from_bytes([request_id; 16]),
        AccountRequestPayload::AuthenticationFinish(request),
    )? {
        OpenedAccountServiceRequest::AuthenticationFinish(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

fn response_round_trip(
    private_key: &AccountHpkePrivateKey,
    request_id: RequestId,
    request_kind: AccountServiceMessageKind,
    payload: &AccountServiceResponsePayload,
) -> Result<AccountServiceResponsePayload, Box<dyn core::error::Error>> {
    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        TEST_NETWORK,
        TEST_RECOVERY_EPOCH,
        public_key.key_id(),
        request_id,
        request_kind,
    );
    let request_plaintext = [0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES];
    let (sealed_request, open_token) =
        seal_account_request(public_key, binding, &request_plaintext)?;
    let (_opened, seal_token) = open_account_request(
        private_key,
        binding,
        sealed_request.encapsulated_key(),
        sealed_request.ciphertext(),
    )?;
    let plaintext = encode_response_plaintext(payload)?;
    let sealed_response = seal_token.seal_response(0, payload.response_kind(), &plaintext)?;
    let response = AccountServiceResponse::from_sealed(sealed_response)?;
    Ok(open_and_parse_response(open_token, &response)?)
}

fn parse_authenticated_plaintext(
    private_key: &AccountHpkePrivateKey,
    request_kind: AccountServiceMessageKind,
    plaintext: &[u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES],
) -> Result<OpenedAccountServiceRequest, AuthError> {
    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        TEST_NETWORK,
        TEST_RECOVERY_EPOCH,
        public_key.key_id(),
        RequestId::from_bytes([91_u8; 16]),
        request_kind,
    );
    let (sealed, _open_token) = seal_account_request(public_key, binding, plaintext)?;
    let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
    open_and_parse_request(
        private_key,
        TEST_RECOVERY_EPOCH,
        TEST_NETWORK,
        request_kind,
        &envelope,
    )
}

fn parse_authenticated_response(
    private_key: &AccountHpkePrivateKey,
    request_kind: AccountServiceMessageKind,
    response_kind: AccountServiceResponseKind,
    plaintext: &[u8; agenc_ircd_crypto::ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES],
) -> Result<AccountServiceResponsePayload, AuthError> {
    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        TEST_NETWORK,
        TEST_RECOVERY_EPOCH,
        public_key.key_id(),
        RequestId::from_bytes([92_u8; 16]),
        request_kind,
    );
    let request_plaintext = [0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES];
    let (sealed_request, open_token) =
        seal_account_request(public_key, binding, &request_plaintext)?;
    let (_opened, seal_token) = open_account_request(
        private_key,
        binding,
        sealed_request.encapsulated_key(),
        sealed_request.ciphertext(),
    )?;
    let sealed_response = seal_token.seal_response(0, response_kind, plaintext)?;
    let response = AccountServiceResponse::from_sealed(sealed_response)?;
    open_and_parse_response(open_token, &response)
}

fn replace_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), &'static str> {
    let end = offset.checked_add(2).ok_or("u16 offset overflow")?;
    let destination = bytes.get_mut(offset..end).ok_or("u16 slot is absent")?;
    destination.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn signed_invitation(
    network_id: NetworkId,
    not_before: u64,
    expires_at: u64,
) -> Result<(agenc_ircd_auth::AccountCreationInvite, Ed25519SecretKey), Box<dyn core::error::Error>>
{
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&1_u16.to_be_bytes());
    tbs.extend_from_slice(network_id.as_bytes());
    tbs.extend_from_slice(&[93_u8; 16]);
    tbs.extend_from_slice(&not_before.to_be_bytes());
    tbs.extend_from_slice(&expires_at.to_be_bytes());
    tbs.extend_from_slice(&1_u16.to_be_bytes());
    let authority = Ed25519SecretKey::from_bytes([94_u8; 32]);
    let signature = sign_canonical(&authority, SignatureDomain::AccountCreationInvite, &tbs)?;
    let mut encoded = [0_u8; ACCOUNT_CREATION_INVITE_BYTES];
    let tbs_slot = encoded
        .get_mut(..tbs.len())
        .ok_or("invitation TBS slot is absent")?;
    tbs_slot.copy_from_slice(&tbs);
    let signature_slot = encoded
        .get_mut(tbs.len()..)
        .ok_or("invitation signature slot is absent")?;
    signature_slot.copy_from_slice(signature.as_bytes());
    Ok((
        agenc_ircd_auth::AccountCreationInvite::parse(&encoded)?,
        authority,
    ))
}

fn authenticate_account(
    profile: &OpaqueProfile,
    login_key: &LoginIndexKey,
    fake_key: &OpaqueFakeCredentialKey,
    password: &[u8],
    stored: StoredAccountFixture,
) -> Result<
    agenc_ircd_auth::SealedAccountFinishOutcome<agenc_ircd_auth::AuthenticationGrant>,
    Box<dyn core::error::Error>,
> {
    let context = operation_context(100)?;
    let login_name = NormalizedLogin::prepare("alice")?;
    let login_digest = derive_login_index(login_key, TEST_NETWORK, &login_name)?;
    let mut rng = TestRng::new();
    let client = ClientLogin::<TestOpaqueSuite>::start(&mut rng, password)?;
    let ke1 = OpaqueKe1::from_bytes(client.message.serialize().as_slice().try_into()?)?;
    let record = AccountCredentialRecord::new(
        stored.account_id,
        stored.account_revision,
        stored.generation,
        login_digest,
        OpaqueCredentialId::from_bytes(stored.credential_bytes),
        stored.record,
    );
    let start = begin_authentication(
        profile,
        login_key,
        fake_key,
        AuthenticationStartParameters {
            context,
            request: authenticated_authentication_start(
                201,
                AuthenticationStart {
                    network_id: TEST_NETWORK,
                    login: login_name,
                    ke1,
                },
            )?,
            lookup: AuthenticationLookup::Known(Box::new(record)),
        },
    )?;
    let transaction_id = start.transaction_id();
    let AccountServiceResponsePayload::AuthenticationChallenge {
        credential_id, ke2, ..
    } = start.response_plan().payload()
    else {
        return Err("authentication returned the wrong challenge".into());
    };
    let context_bytes = opaque_context(TEST_NETWORK);
    let finish = client.state.finish(
        &mut rng,
        password,
        CredentialResponse::<TestOpaqueSuite>::deserialize(ke2.expose_for_account_response())?,
        ClientLoginFinishParameters::new(
            Some(&context_bytes),
            identifiers(&TEST_NETWORK, credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let ke3 = OpaqueKe3::from_bytes(finish.message.serialize().as_slice().try_into()?)?;
    let mut transaction = start.seal(0)?.into_transaction_after_commit(1)?;
    let outcome = finish_account_authentication(
        &mut transaction,
        context,
        authenticated_authentication_finish(
            202,
            AuthenticationFinish {
                network_id: TEST_NETWORK,
                transaction_id,
                ke3,
            },
        )?,
    )?;
    assert!(
        rng.succeeded(),
        "test entropy failed inside authenticate_account"
    );
    Ok(outcome.seal(1)?)
}

struct RejectedCreationCase {
    request_id: u8,
    invitation: Option<agenc_ircd_auth::AccountCreationInvite>,
    admission: CreationAdmission,
    login_is_available: bool,
    invitation_is_available: bool,
    expected_error: AuthError,
}

/// Downstream composition holds sealed starts in owned state, so the state
/// type must be nameable outside this crate.
struct HeldCreationStart {
    start: SealedAccountStart<AccountCreationState>,
}

fn assert_rejected_creation_exchange(
    profile: &OpaqueProfile,
    login_key: &LoginIndexKey,
    fixture: &ProtocolFixture,
    case: RejectedCreationCase,
) -> Result<(), Box<dyn core::error::Error>> {
    let RejectedCreationCase {
        request_id,
        invitation,
        admission,
        login_is_available,
        invitation_is_available,
        expected_error,
    } = case;
    let (request, challenge_token) = authenticated_creation_start_with_token(
        request_id,
        CreationStart {
            network_id: TEST_NETWORK,
            login: NormalizedLogin::prepare("alice")?,
            registration_request: copy_request(&fixture.registration_request)?,
            invitation,
        },
    )?;
    let start = begin_account_creation(
        profile,
        login_key,
        AccountCreationStartParameters {
            context: operation_context(10)?,
            request,
            admission,
            login_is_available,
            invitation_is_available,
        },
    )?;
    let transaction_id = start.transaction_id();
    let start = start.seal(0)?;
    assert_eq!(
        start.response_intent().response().as_bytes().len(),
        ACCOUNT_SERVICE_RESPONSE_BYTES
    );
    assert!(matches!(
        open_and_parse_response(challenge_token, start.response_intent().response())?,
        AccountServiceResponsePayload::CreationChallenge { transaction_id: found, .. }
            if found == transaction_id
    ));
    let (finish, completion_token) = authenticated_creation_finish_with_token(
        request_id.wrapping_add(1),
        CreationFinish {
            network_id: TEST_NETWORK,
            transaction_id,
            registration_record: copy_record(&fixture.record)?,
        },
    )?;
    let mut transaction = start.into_transaction_after_commit(1)?;
    let outcome = finish_account_creation(&mut transaction, operation_context(11)?, finish)?;
    assert_eq!(outcome.result().err(), Some(expected_error));
    let outcome = outcome.seal(1)?;
    assert_eq!(
        outcome.response_intent().response().as_bytes().len(),
        ACCOUNT_SERVICE_RESPONSE_BYTES
    );
    assert!(matches!(
        open_and_parse_response(completion_token, outcome.response_intent().response())?,
        AccountServiceResponsePayload::CreationCompletion(completion)
            if completion.status() == AccountServiceCompletionStatus::Rejected
                && completion.transaction_id() == transaction_id
    ));
    Ok(())
}

fn assert_rejected_authentication_exchange(
    profile: &OpaqueProfile,
    login_key: &LoginIndexKey,
    fake_key: &OpaqueFakeCredentialKey,
    fixture: &ProtocolFixture,
    lookup: AuthenticationLookup,
    request_id: u8,
) -> Result<(), Box<dyn core::error::Error>> {
    let (request, challenge_token) = authenticated_authentication_start_with_token(
        request_id,
        AuthenticationStart {
            network_id: TEST_NETWORK,
            login: NormalizedLogin::prepare("alice")?,
            ke1: OpaqueKe1::from_bytes(*fixture.ke1.expose_for_account_request())?,
        },
    )?;
    let start = begin_authentication(
        profile,
        login_key,
        fake_key,
        AuthenticationStartParameters {
            context: operation_context(100)?,
            request,
            lookup,
        },
    )?;
    let transaction_id = start.transaction_id();
    let start = start.seal(0)?;
    assert_eq!(
        start.response_intent().response().as_bytes().len(),
        ACCOUNT_SERVICE_RESPONSE_BYTES
    );
    assert!(matches!(
        open_and_parse_response(challenge_token, start.response_intent().response())?,
        AccountServiceResponsePayload::AuthenticationChallenge { transaction_id: found, .. }
            if found == transaction_id
    ));
    let (finish, completion_token) = authenticated_authentication_finish_with_token(
        request_id.wrapping_add(1),
        AuthenticationFinish {
            network_id: TEST_NETWORK,
            transaction_id,
            ke3: OpaqueKe3::from_bytes([0_u8; 64])?,
        },
    )?;
    let mut transaction = start.into_transaction_after_commit(1)?;
    let outcome = finish_account_authentication(&mut transaction, operation_context(101)?, finish)?;
    assert_eq!(
        outcome.result().err(),
        Some(AuthError::AuthenticationFailed)
    );
    let outcome = outcome.seal(1)?;
    assert_eq!(
        outcome.response_intent().response().as_bytes().len(),
        ACCOUNT_SERVICE_RESPONSE_BYTES
    );
    assert!(matches!(
        open_and_parse_response(completion_token, outcome.response_intent().response())?,
        AccountServiceResponsePayload::AuthenticationCompletion(completion)
            if completion.status() == AccountServiceCompletionStatus::Rejected
                && completion.transaction_id() == transaction_id
    ));
    Ok(())
}

#[derive(Clone, Copy)]
enum CreationFinishContextCase {
    InnerNetwork,
    RecoveryEpoch,
    RecipientKey,
    ReusedRequestId,
}

fn assert_creation_finish_context_rejected(
    profile: &OpaqueProfile,
    login_key: &LoginIndexKey,
    fixture: &ProtocolFixture,
    request_id: u8,
    case: CreationFinishContextCase,
) -> Result<(), Box<dyn core::error::Error>> {
    let start = begin_account_creation(
        profile,
        login_key,
        AccountCreationStartParameters {
            context: operation_context(10)?,
            request: authenticated_creation_start(
                request_id,
                CreationStart {
                    network_id: TEST_NETWORK,
                    login: NormalizedLogin::prepare(&format!("lineage{request_id}"))?,
                    registration_request: copy_request(&fixture.registration_request)?,
                    invitation: None,
                },
            )?,
            admission: CreationAdmission::Open,
            login_is_available: true,
            invitation_is_available: true,
        },
    )?;
    let transaction_id = start.transaction_id();
    let finish_network = if matches!(case, CreationFinishContextCase::InnerNetwork) {
        NetworkId::from_bytes([request_id.wrapping_add(31); 32])
    } else {
        TEST_NETWORK
    };
    let finish_recovery = if matches!(case, CreationFinishContextCase::RecoveryEpoch) {
        RecoveryEpoch::from_bytes([request_id.wrapping_add(32); 16])
    } else {
        TEST_RECOVERY_EPOCH
    };
    let finish_request_id = if matches!(case, CreationFinishContextCase::ReusedRequestId) {
        request_id
    } else {
        request_id.wrapping_add(1)
    };
    let finish_key_seed = if matches!(case, CreationFinishContextCase::RecipientKey) {
        8
    } else {
        7
    };
    let finish_key = AccountHpkePrivateKey::from_bytes([finish_key_seed; 32])?;
    let finish = authenticated_creation_finish_in_context(
        &finish_key,
        finish_network,
        finish_recovery,
        finish_request_id,
        CreationFinish {
            network_id: finish_network,
            transaction_id,
            registration_record: copy_record(&fixture.record)?,
        },
    )?;
    let mut transaction = start.seal(0)?.into_transaction_after_commit(1)?;
    let outcome = finish_account_creation(&mut transaction, operation_context(11)?, finish)?;
    assert_eq!(outcome.result().err(), Some(AuthError::ContextMismatch));
    let sealed = outcome.seal(1)?;
    assert_eq!(sealed.result().err(), Some(AuthError::ContextMismatch));
    Ok(())
}

#[derive(Clone, Copy)]
enum AuthenticationFinishContextCase {
    InnerNetwork,
    RecoveryEpoch,
    InvalidAuthenticator,
}

fn assert_authentication_finish_rejected(
    profile: &OpaqueProfile,
    login_key: &LoginIndexKey,
    fake_key: &OpaqueFakeCredentialKey,
    fixture: &ProtocolFixture,
    credential_id: &OpaqueCredentialId,
    request_id: u8,
    case: AuthenticationFinishContextCase,
) -> Result<(), Box<dyn core::error::Error>> {
    let login = NormalizedLogin::prepare(&format!("authlineage{request_id}"))?;
    let lookup = if matches!(case, AuthenticationFinishContextCase::InvalidAuthenticator) {
        AuthenticationLookup::Known(Box::new(AccountCredentialRecord::new(
            AccountRandomId::from_bytes([request_id; 16]).to_account_id(),
            Revision::new(1)?,
            Generation::new(1)?,
            derive_login_index(login_key, TEST_NETWORK, &login)?,
            OpaqueCredentialId::from_bytes(*credential_id.expose_for_account_service()),
            copy_record(&fixture.record)?,
        )))
    } else {
        AuthenticationLookup::Unknown
    };
    let start = begin_authentication(
        profile,
        login_key,
        fake_key,
        AuthenticationStartParameters {
            context: operation_context(100)?,
            request: authenticated_authentication_start(
                request_id,
                AuthenticationStart {
                    network_id: TEST_NETWORK,
                    login,
                    ke1: OpaqueKe1::from_bytes(*fixture.ke1.expose_for_account_request())?,
                },
            )?,
            lookup,
        },
    )?;
    let transaction_id = start.transaction_id();
    let finish_network = if matches!(case, AuthenticationFinishContextCase::InnerNetwork) {
        NetworkId::from_bytes([request_id.wrapping_add(31); 32])
    } else {
        TEST_NETWORK
    };
    let finish_recovery = if matches!(case, AuthenticationFinishContextCase::RecoveryEpoch) {
        RecoveryEpoch::from_bytes([request_id.wrapping_add(32); 16])
    } else {
        TEST_RECOVERY_EPOCH
    };
    let finish_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    let finish = authenticated_authentication_finish_in_context(
        &finish_key,
        finish_network,
        finish_recovery,
        request_id.wrapping_add(1),
        AuthenticationFinish {
            network_id: finish_network,
            transaction_id,
            ke3: OpaqueKe3::from_bytes([0_u8; 64])?,
        },
    )?;
    let mut transaction = start.seal(0)?.into_transaction_after_commit(1)?;
    let outcome = finish_account_authentication(&mut transaction, operation_context(101)?, finish)?;
    assert_eq!(
        outcome.result().err(),
        Some(AuthError::AuthenticationFailed)
    );
    let sealed = outcome.seal(1)?;
    assert_eq!(sealed.result().err(), Some(AuthError::AuthenticationFailed));
    Ok(())
}

#[test]
fn fixed_profile_and_all_wire_arms_reject_substitution() -> Result<(), Box<dyn core::error::Error>>
{
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let credential_id = credential(31);
    let fixture = protocol_fixture(&profile, &credential_id, b"wire matrix")?;
    let setup = *profile.expose_setup_for_persistence();
    let fake_record = *profile.expose_fake_record_for_persistence();
    let restored = OpaqueProfile::from_serialized(TEST_NETWORK, setup, fake_record)?;
    assert_eq!(restored.expose_setup_for_persistence(), &setup);
    assert_eq!(restored.expose_fake_record_for_persistence(), &fake_record);
    let private_key = AccountHpkePrivateKey::generate()?;
    let account_id = AccountRandomId::from_bytes([32_u8; 16]).to_account_id();

    let requests = vec![
        AccountRequestPayload::CreationStart(CreationStart {
            network_id: TEST_NETWORK,
            login: NormalizedLogin::prepare("alice")?,
            registration_request: copy_request(&fixture.registration_request)?,
            invitation: None,
        }),
        AccountRequestPayload::CreationFinish(CreationFinish {
            network_id: TEST_NETWORK,
            transaction_id: TransactionId::from_bytes([33_u8; 16]),
            registration_record: copy_record(&fixture.record)?,
        }),
        AccountRequestPayload::AuthenticationStart(AuthenticationStart {
            network_id: TEST_NETWORK,
            login: NormalizedLogin::prepare("alice")?,
            ke1: OpaqueKe1::from_bytes(*fixture.ke1.expose_for_account_request())?,
        }),
        AccountRequestPayload::AuthenticationFinish(AuthenticationFinish {
            network_id: TEST_NETWORK,
            transaction_id: TransactionId::from_bytes([34_u8; 16]),
            ke3: OpaqueKe3::from_bytes(*fixture.ke3.expose_for_account_request())?,
        }),
        AccountRequestPayload::CredentialChangeStart(CredentialChangeStart {
            network_id: TEST_NETWORK,
            account_id,
            registration_request: copy_request(&fixture.registration_request)?,
        }),
        AccountRequestPayload::CredentialChangeFinish(CredentialChangeFinish {
            network_id: TEST_NETWORK,
            transaction_id: TransactionId::from_bytes([35_u8; 16]),
            registration_record: copy_record(&fixture.record)?,
        }),
    ];
    for (index, payload) in requests.into_iter().enumerate() {
        let kind = payload.message_kind();
        let parsed = request_round_trip(
            &private_key,
            RequestId::from_bytes([u8::try_from(index + 1)?; 16]),
            payload,
        )?;
        assert_eq!(parsed.message_kind(), kind);
    }

    let responses = vec![
        (
            AccountServiceMessageKind::AccountCreateStart,
            AccountServiceResponsePayload::CreationChallenge {
                transaction_id: TransactionId::from_bytes([41_u8; 16]),
                credential_id: credential(42),
                response: OpaqueRegistrationResponse::from_bytes(
                    *fixture.registration_response.expose_for_account_response(),
                )?,
            },
        ),
        (
            AccountServiceMessageKind::OpaqueAuthStart,
            AccountServiceResponsePayload::AuthenticationChallenge {
                transaction_id: TransactionId::from_bytes([43_u8; 16]),
                credential_id: credential(44),
                ke2: Box::new(OpaqueKe2::from_bytes(
                    *fixture.ke2.expose_for_account_response(),
                )?),
            },
        ),
        (
            AccountServiceMessageKind::CredentialChangeStart,
            AccountServiceResponsePayload::CredentialChangeChallenge {
                transaction_id: TransactionId::from_bytes([45_u8; 16]),
                credential_id: credential(46),
                response: OpaqueRegistrationResponse::from_bytes(
                    *fixture.registration_response.expose_for_account_response(),
                )?,
            },
        ),
        (
            AccountServiceMessageKind::AccountCreateFinish,
            AccountServiceResponsePayload::CreationCompletion(Completion::committed(
                TransactionId::from_bytes([47_u8; 16]),
                account_id,
                0,
            )),
        ),
        (
            AccountServiceMessageKind::OpaqueAuthFinish,
            AccountServiceResponsePayload::AuthenticationCompletion(Completion::committed(
                TransactionId::from_bytes([48_u8; 16]),
                account_id,
                1,
            )),
        ),
        (
            AccountServiceMessageKind::CredentialChangeFinish,
            AccountServiceResponsePayload::CredentialChangeCompletion(Completion::rejected(
                TransactionId::from_bytes([49_u8; 16]),
            )),
        ),
    ];
    for (index, (request_kind, payload)) in responses.into_iter().enumerate() {
        let expected_kind = payload.response_kind();
        let parsed = response_round_trip(
            &private_key,
            RequestId::from_bytes([u8::try_from(index + 51)?; 16]),
            request_kind,
            &payload,
        )?;
        assert_eq!(parsed.response_kind(), expected_kind);
    }

    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        TEST_NETWORK,
        TEST_RECOVERY_EPOCH,
        public_key.key_id(),
        RequestId::from_bytes([71_u8; 16]),
        AccountServiceMessageKind::OpaqueAuthFinish,
    );
    let request_plaintext = [0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES];
    let (sealed_request, open_token) =
        seal_account_request(public_key, binding, &request_plaintext)?;
    let (_opened, seal_token) = open_account_request(
        &private_key,
        binding,
        sealed_request.encapsulated_key(),
        sealed_request.ciphertext(),
    )?;
    let payload = AccountServiceResponsePayload::AuthenticationCompletion(Completion::rejected(
        TransactionId::from_bytes([72_u8; 16]),
    ));
    let plaintext = encode_response_plaintext(&payload)?;
    let sealed_response = seal_token.seal_response(0, payload.response_kind(), &plaintext)?;
    let response = AccountServiceResponse::from_sealed(sealed_response)?;
    let mut changed = *response.as_bytes();
    let request_id_byte = changed.get_mut(70).ok_or("response header is too short")?;
    *request_id_byte ^= 1;
    let changed = AccountServiceResponse::parse(changed)?;
    assert!(matches!(
        open_and_parse_response(open_token, &changed),
        Err(AuthError::ContextMismatch)
    ));
    Ok(())
}

#[test]
fn finish_handlers_reject_inner_and_outer_lineage_substitutions()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([176_u8; 32]);
    let fake_key = OpaqueFakeCredentialKey::from_bytes([177_u8; 32]);
    let credential_id = credential(178);
    let fixture = protocol_fixture(&profile, &credential_id, b"finish lineage matrix")?;

    for (request_id, case) in [
        (179, CreationFinishContextCase::InnerNetwork),
        (181, CreationFinishContextCase::RecoveryEpoch),
        (183, CreationFinishContextCase::RecipientKey),
        (185, CreationFinishContextCase::ReusedRequestId),
    ] {
        assert_creation_finish_context_rejected(&profile, &login_key, &fixture, request_id, case)?;
    }
    for (request_id, case) in [
        (187, AuthenticationFinishContextCase::InnerNetwork),
        (189, AuthenticationFinishContextCase::RecoveryEpoch),
        (191, AuthenticationFinishContextCase::InvalidAuthenticator),
    ] {
        assert_authentication_finish_rejected(
            &profile,
            &login_key,
            &fake_key,
            &fixture,
            &credential_id,
            request_id,
            case,
        )?;
    }
    Ok(())
}

#[test]
fn account_creation_and_authentication_complete_with_bound_receipts()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([51_u8; 32]);
    let fake_key = OpaqueFakeCredentialKey::from_bytes([52_u8; 32]);
    let mut rng = TestRng::new();
    let registration = ClientRegistration::<TestOpaqueSuite>::start(&mut rng, b"first password")?;
    let registration_request = OpaqueRegistrationRequest::from_bytes(
        registration.message.serialize().as_slice().try_into()?,
    )?;
    let creation_start = begin_account_creation(
        &profile,
        &login_key,
        AccountCreationStartParameters {
            context: operation_context(10)?,
            request: authenticated_creation_start(
                53,
                CreationStart {
                    network_id: TEST_NETWORK,
                    login: NormalizedLogin::prepare("alice")?,
                    registration_request,
                    invitation: None,
                },
            )?,
            admission: CreationAdmission::Open,
            login_is_available: true,
            invitation_is_available: true,
        },
    )?;
    let transaction_id = creation_start.transaction_id();
    let AccountServiceResponsePayload::CreationChallenge {
        credential_id,
        response,
        ..
    } = creation_start.response_plan().payload()
    else {
        return Err("creation returned the wrong challenge".into());
    };
    let credential_bytes = *credential_id.expose_for_account_service();
    let registration_finish = registration.state.finish(
        &mut rng,
        b"first password",
        RegistrationResponse::<TestOpaqueSuite>::deserialize(
            response.expose_for_account_response(),
        )?,
        ClientRegistrationFinishParameters::new(
            identifiers(&TEST_NETWORK, credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let record = finish_registration(
        registration_finish
            .message
            .serialize()
            .as_slice()
            .try_into()?,
    )?;
    assert!(rng.succeeded(), "test entropy failed during registration");
    let mut creation_transaction = creation_start.seal(0)?.into_transaction_after_commit(1)?;
    let creation_outcome = finish_account_creation(
        &mut creation_transaction,
        operation_context(11)?,
        authenticated_creation_finish(
            54,
            CreationFinish {
                network_id: TEST_NETWORK,
                transaction_id,
                registration_record: record,
            },
        )?,
    )?;
    let creation_outcome = creation_outcome.seal(1)?;
    let creation_intent = creation_outcome.result()?;
    let account_id = creation_intent.account_id();
    assert_eq!(creation_intent.invitation_id(), None);
    assert_eq!(creation_intent.invitation_expires_at(), None);
    let grant = authenticate_account(
        &profile,
        &login_key,
        &fake_key,
        b"first password",
        StoredAccountFixture {
            account_id,
            account_revision: Revision::new(7)?,
            generation: Generation::new(9)?,
            credential_bytes,
            record: copy_record(creation_intent.record())?,
        },
    )?;
    let completion =
        authentication_completion(TransactionId::from_bytes([56_u8; 16]), grant.result()?);
    assert_eq!(
        completion.response_kind(),
        AccountServiceResponseKind::OpaqueAuthComplete
    );
    let uncommitted_grant = authenticate_account(
        &profile,
        &login_key,
        &fake_key,
        b"first password",
        StoredAccountFixture {
            account_id,
            account_revision: Revision::new(7)?,
            generation: Generation::new(9)?,
            credential_bytes,
            record: copy_record(creation_intent.record())?,
        },
    )?;
    assert!(matches!(
        uncommitted_grant.into_result_after_commit(1),
        Err(AuthError::ContextMismatch)
    ));
    let grant = grant.into_result_after_commit(2)??;
    assert_eq!(grant.account_id(), account_id);
    assert_eq!(grant.account_session_generation(), Generation::new(9)?);
    assert_eq!(grant.network_id(), TEST_NETWORK);
    assert_eq!(grant.edge_server_id(), ServerId::from_bytes([26_u8; 16]));
    assert_eq!(
        grant.edge_incarnation(),
        ServerIncarnation::from_bytes([27_u8; 16])
    );
    assert_eq!(grant.origin_id(), OriginId::from_bytes([22_u8; 16]));
    assert_eq!(grant.origin_generation(), Generation::new(24)?);
    assert_eq!(grant.connection_id(), ConnectionId::from_bytes([23_u8; 16]));
    assert_eq!(
        grant.connection_nonce_for_persistence_or_session_open(),
        &[28_u8; 32]
    );
    assert_eq!(
        grant.process_expires_at(),
        MonotonicTick::from_ticks(30_100)
    );
    assert_eq!(
        grant.durable_expires_at_utc(),
        UtcSecond::from_unix_seconds(130)
    );
    assert_eq!(
        grant.fresh_authentication_expires_at(),
        MonotonicTick::from_ticks(300_100)
    );
    assert_eq!(
        grant
            .grant_id_for_persistence_or_session_open()
            .expose_for_session_open()
            .len(),
        32
    );
    Ok(())
}

#[test]
fn sealed_start_rejects_a_response_count_that_has_not_committed()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([57_u8; 32]);
    let fixture = protocol_fixture(&profile, &credential(58), b"commit gate")?;
    let start = begin_account_creation(
        &profile,
        &login_key,
        AccountCreationStartParameters {
            context: operation_context(10)?,
            request: authenticated_creation_start(
                59,
                CreationStart {
                    network_id: TEST_NETWORK,
                    login: NormalizedLogin::prepare("commit-gate")?,
                    registration_request: copy_request(&fixture.registration_request)?,
                    invitation: None,
                },
            )?,
            admission: CreationAdmission::Open,
            login_is_available: true,
            invitation_is_available: true,
        },
    )?;
    let sealed = start.seal(7)?;
    assert_eq!(sealed.response_intent().next_response_count(), 8);
    assert!(matches!(
        sealed.into_transaction_after_commit(7),
        Err(AuthError::ContextMismatch)
    ));
    Ok(())
}

#[test]
fn same_kind_finish_swap_is_rejected_and_exact_finish_token_seals_response()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([160_u8; 32]);
    let fixture = protocol_fixture(&profile, &credential(161), b"lineage swap")?;
    let creation_parameters = |request_id| {
        Ok::<_, Box<dyn core::error::Error>>(AccountCreationStartParameters {
            context: operation_context(10)?,
            request: authenticated_creation_start(
                request_id,
                CreationStart {
                    network_id: TEST_NETWORK,
                    login: NormalizedLogin::prepare(&format!("user{request_id}"))?,
                    registration_request: copy_request(&fixture.registration_request)?,
                    invitation: None,
                },
            )?,
            admission: CreationAdmission::Open,
            login_is_available: true,
            invitation_is_available: true,
        })
    };
    let first = begin_account_creation(&profile, &login_key, creation_parameters(162)?)?;
    let second = begin_account_creation(&profile, &login_key, creation_parameters(163)?)?;
    let second_transaction_id = second.transaction_id();
    let first = first.seal(0)?;
    let second = second.seal(1)?;
    let (swapped_finish, swapped_token) = authenticated_creation_finish_with_token(
        164,
        CreationFinish {
            network_id: TEST_NETWORK,
            transaction_id: second_transaction_id,
            registration_record: copy_record(&fixture.record)?,
        },
    )?;
    let (_unused_finish, wrong_same_kind_token) = authenticated_creation_finish_with_token(
        165,
        CreationFinish {
            network_id: TEST_NETWORK,
            transaction_id: second_transaction_id,
            registration_record: copy_record(&fixture.record)?,
        },
    )?;
    let mut first_transaction = first.into_transaction_after_commit(2)?;
    let rejected = finish_account_creation(
        &mut first_transaction,
        operation_context(11)?,
        swapped_finish,
    )?;
    assert_eq!(rejected.result().err(), Some(AuthError::ContextMismatch));
    let rejected = rejected.seal(2)?;
    assert!(
        open_and_parse_response(wrong_same_kind_token, rejected.response_intent().response())
            .is_err()
    );
    assert!(matches!(
        open_and_parse_response(swapped_token, rejected.response_intent().response())?,
        AccountServiceResponsePayload::CreationCompletion(completion)
            if completion.status() == AccountServiceCompletionStatus::Rejected
                && completion.transaction_id() == second_transaction_id
    ));

    let (valid_finish, valid_token) = authenticated_creation_finish_with_token(
        166,
        CreationFinish {
            network_id: TEST_NETWORK,
            transaction_id: second_transaction_id,
            registration_record: copy_record(&fixture.record)?,
        },
    )?;
    let mut second_transaction = second.into_transaction_after_commit(2)?;
    let committed = finish_account_creation(
        &mut second_transaction,
        operation_context(11)?,
        valid_finish,
    )?;
    assert!(committed.result().is_ok());
    let committed = committed.seal(3)?;
    assert_eq!(
        committed.response_intent().response().client_request_id(),
        RequestId::from_bytes([166_u8; 16])
    );
    assert!(matches!(
        open_and_parse_response(valid_token, committed.response_intent().response())?,
        AccountServiceResponsePayload::CreationCompletion(completion)
            if completion.status() == AccountServiceCompletionStatus::Committed
                && completion.transaction_id() == second_transaction_id
    ));
    Ok(())
}

#[test]
fn opened_finish_context_failure_seals_for_the_exact_request()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([167_u8; 32]);
    let fixture = protocol_fixture(&profile, &credential(168), b"context lineage")?;
    let start = begin_account_creation(
        &profile,
        &login_key,
        AccountCreationStartParameters {
            context: operation_context(10)?,
            request: authenticated_creation_start(
                169,
                CreationStart {
                    network_id: TEST_NETWORK,
                    login: NormalizedLogin::prepare("context-user")?,
                    registration_request: copy_request(&fixture.registration_request)?,
                    invitation: None,
                },
            )?,
            admission: CreationAdmission::Open,
            login_is_available: true,
            invitation_is_available: true,
        },
    )?;
    let transaction_id = start.transaction_id();
    let (finish, response_token) = authenticated_creation_finish_with_token(
        170,
        CreationFinish {
            network_id: TEST_NETWORK,
            transaction_id,
            registration_record: copy_record(&fixture.record)?,
        },
    )?;
    let start = start.seal(0)?;
    let mut transaction = start.into_transaction_after_commit(1)?;
    let rejected = finish_account_creation(
        &mut transaction,
        operation_context_for_network(NetworkId::from_bytes([171_u8; 32]), 11)?,
        finish,
    )?;
    assert_eq!(rejected.result().err(), Some(AuthError::ContextMismatch));
    let rejected = rejected.seal(1)?;
    assert!(matches!(
        open_and_parse_response(response_token, rejected.response_intent().response())?,
        AccountServiceResponsePayload::CreationCompletion(completion)
            if completion.status() == AccountServiceCompletionStatus::Rejected
                && completion.transaction_id() == transaction_id
    ));
    Ok(())
}

#[test]
fn opaque_serializations_reject_corruption_before_protocol_state()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let fixture = protocol_fixture(&profile, &credential(121), b"serialization matrix")?;
    assert_eq!(
        OpaqueRegistrationRequest::from_bytes([0_u8; 32]).err(),
        Some(AuthError::InvalidEncoding)
    );
    assert_eq!(
        OpaqueRegistrationResponse::from_bytes([0_u8; 64]).err(),
        Some(AuthError::InvalidEncoding)
    );
    assert_eq!(
        OpaqueKe1::from_bytes([0_u8; 96]).err(),
        Some(AuthError::InvalidEncoding)
    );
    assert_eq!(
        OpaqueKe2::from_bytes([0_u8; OPAQUE_KE2_BYTES]).err(),
        Some(AuthError::InvalidEncoding)
    );
    let structurally_valid_ke3 = OpaqueKe3::from_bytes([0_u8; 64])?;
    let (_ke2, server_state) = profile.authentication_start(
        TEST_NETWORK,
        &credential(121),
        Some(&fixture.record),
        &fixture.ke1,
    )?;
    assert_eq!(
        agenc_ircd_auth::finish_authentication(
            TEST_NETWORK,
            &credential(121),
            server_state,
            &structurally_valid_ke3,
        )
        .err(),
        Some(AuthError::AuthenticationFailed)
    );
    let structurally_valid_state =
        agenc_ircd_auth::OpaqueServerLoginState::from_persisted_bytes([0_u8; 128])?;
    assert_eq!(
        agenc_ircd_auth::finish_authentication(
            TEST_NETWORK,
            &credential(121),
            structurally_valid_state,
            &fixture.ke3,
        )
        .err(),
        Some(AuthError::AuthenticationFailed)
    );
    assert_eq!(
        finish_registration([0_u8; 192]).err(),
        Some(AuthError::InvalidEncoding)
    );
    let setup = *profile.expose_setup_for_persistence();
    let mut fake_record = *profile.expose_fake_record_for_persistence();
    let fake_public_key_byte = fake_record
        .first_mut()
        .ok_or("fake record public key is absent")?;
    *fake_public_key_byte ^= 1;
    assert_eq!(
        OpaqueProfile::from_serialized(TEST_NETWORK, setup, fake_record).err(),
        Some(AuthError::InvalidEncoding)
    );
    let other_profile = OpaqueProfile::generate(TEST_NETWORK)?;
    assert_eq!(
        OpaqueProfile::from_serialized(
            TEST_NETWORK,
            setup,
            *other_profile.expose_fake_record_for_persistence(),
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );
    let mut nonzero_fake_envelope = *profile.expose_fake_record_for_persistence();
    nonzero_fake_envelope[96] = 1;
    assert_eq!(
        OpaqueProfile::from_serialized(TEST_NETWORK, setup, nonzero_fake_envelope).err(),
        Some(AuthError::InvalidEncoding)
    );
    let mut corrupted_record = *fixture.record.expose_for_persistence();
    corrupted_record[..32].fill(u8::MAX);
    assert!(OpaqueRegistrationRecord::from_bytes(corrupted_record).is_err());
    Ok(())
}

#[test]
fn unknown_login_runs_fake_record_and_dummy_finish_work() -> Result<(), Box<dyn core::error::Error>>
{
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([61_u8; 32]);
    let fake_key = OpaqueFakeCredentialKey::from_bytes([62_u8; 32]);
    let fixture = protocol_fixture(&profile, &credential(63), b"known password")?;
    let mut rng = TestRng::new();
    let client = ClientLogin::<TestOpaqueSuite>::start(&mut rng, b"unknown password")?;
    let ke1 = OpaqueKe1::from_bytes(client.message.serialize().as_slice().try_into()?)?;
    assert!(rng.succeeded(), "test entropy failed for the unknown login");
    let (request, challenge_token) = authenticated_authentication_start_with_token(
        64,
        AuthenticationStart {
            network_id: TEST_NETWORK,
            login: NormalizedLogin::prepare("missing")?,
            ke1,
        },
    )?;
    let start = begin_authentication(
        &profile,
        &login_key,
        &fake_key,
        AuthenticationStartParameters {
            context: operation_context(5)?,
            request,
            lookup: AuthenticationLookup::Unknown,
        },
    )?;
    let transaction_id = start.transaction_id();
    let AccountServiceResponsePayload::AuthenticationChallenge { ke2, .. } =
        start.response_plan().payload()
    else {
        return Err("unknown login did not receive a protocol-shaped challenge".into());
    };
    assert_eq!(ke2.expose_for_account_response().len(), OPAQUE_KE2_BYTES);
    let start = start.seal(0)?;
    assert_eq!(
        start.response_intent().response().as_bytes().len(),
        ACCOUNT_SERVICE_RESPONSE_BYTES
    );
    assert!(matches!(
        open_and_parse_response(challenge_token, start.response_intent().response())?,
        AccountServiceResponsePayload::AuthenticationChallenge { transaction_id: found, .. }
            if found == transaction_id
    ));
    let (finish, response_token) = authenticated_authentication_finish_with_token(
        65,
        AuthenticationFinish {
            network_id: TEST_NETWORK,
            transaction_id,
            ke3: OpaqueKe3::from_bytes([0_u8; 64])?,
        },
    )?;
    let mut transaction = start.into_transaction_after_commit(1)?;
    let outcome = finish_account_authentication(&mut transaction, operation_context(6)?, finish)?;
    assert_eq!(
        outcome.result().err(),
        Some(AuthError::AuthenticationFailed)
    );
    assert!(matches!(
        outcome.response_plan().payload(),
        AccountServiceResponsePayload::AuthenticationCompletion(completion)
            if completion.status() == AccountServiceCompletionStatus::Rejected
    ));
    let sealed = outcome.seal(1)?;
    assert_eq!(
        sealed.response_intent().response().as_bytes().len(),
        ACCOUNT_SERVICE_RESPONSE_BYTES
    );
    assert_eq!(
        sealed.response_intent().response().client_request_id(),
        RequestId::from_bytes([65_u8; 16])
    );
    assert!(matches!(
        open_and_parse_response(response_token, sealed.response_intent().response())?,
        AccountServiceResponsePayload::AuthenticationCompletion(completion)
            if completion.status() == AccountServiceCompletionStatus::Rejected
                && completion.transaction_id() == transaction_id
    ));
    assert_eq!(
        profile.dummy_finish_work(TEST_NETWORK, &credential(63), &fixture.ke3),
        AuthError::AuthenticationFailed
    );
    Ok(())
}

#[test]
fn opened_start_rejections_return_challenges_then_rejected_completions()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([66_u8; 32]);
    let fake_key = OpaqueFakeCredentialKey::from_bytes([67_u8; 32]);
    let credential_id = credential(68);
    let fixture = protocol_fixture(&profile, &credential_id, b"latent rejection")?;

    assert_rejected_creation_exchange(
        &profile,
        &login_key,
        &fixture,
        RejectedCreationCase {
            request_id: 69,
            invitation: None,
            admission: CreationAdmission::Open,
            login_is_available: false,
            invitation_is_available: true,
            expected_error: AuthError::WrongState,
        },
    )?;
    assert_rejected_creation_exchange(
        &profile,
        &login_key,
        &fixture,
        RejectedCreationCase {
            request_id: 71,
            invitation: None,
            admission: CreationAdmission::Closed,
            login_is_available: false,
            invitation_is_available: true,
            expected_error: AuthError::InvitationRejected,
        },
    )?;
    let (unexpected_invitation, _authority) = signed_invitation(TEST_NETWORK, 10, 20)?;
    assert_rejected_creation_exchange(
        &profile,
        &login_key,
        &fixture,
        RejectedCreationCase {
            request_id: 73,
            invitation: Some(unexpected_invitation),
            admission: CreationAdmission::Open,
            login_is_available: true,
            invitation_is_available: true,
            expected_error: AuthError::InvitationRejected,
        },
    )?;
    let (_unused_invitation, authority) = signed_invitation(TEST_NETWORK, 10, 20)?;
    assert_rejected_creation_exchange(
        &profile,
        &login_key,
        &fixture,
        RejectedCreationCase {
            request_id: 75,
            invitation: None,
            admission: CreationAdmission::Invitation {
                authority: authority.public_key(),
                now: UtcSecond::from_unix_seconds(10),
            },
            login_is_available: true,
            invitation_is_available: true,
            expected_error: AuthError::InvitationRejected,
        },
    )?;

    let (invalid_signature, authority) = signed_invitation(TEST_NETWORK, 10, 20)?;
    let mut invalid_signature = *invalid_signature.expose_for_account_request();
    let signature_byte = invalid_signature
        .last_mut()
        .ok_or("invitation signature is absent")?;
    *signature_byte ^= 1;
    assert_rejected_creation_exchange(
        &profile,
        &login_key,
        &fixture,
        RejectedCreationCase {
            request_id: 77,
            invitation: Some(agenc_ircd_auth::AccountCreationInvite::parse(
                &invalid_signature,
            )?),
            admission: CreationAdmission::Invitation {
                authority: authority.public_key(),
                now: UtcSecond::from_unix_seconds(10),
            },
            login_is_available: true,
            invitation_is_available: true,
            expected_error: AuthError::InvitationRejected,
        },
    )?;
    let (expired_invitation, authority) = signed_invitation(TEST_NETWORK, 10, 20)?;
    assert_rejected_creation_exchange(
        &profile,
        &login_key,
        &fixture,
        RejectedCreationCase {
            request_id: 79,
            invitation: Some(expired_invitation),
            admission: CreationAdmission::Invitation {
                authority: authority.public_key(),
                now: UtcSecond::from_unix_seconds(20),
            },
            login_is_available: true,
            invitation_is_available: true,
            expected_error: AuthError::InvitationRejected,
        },
    )?;
    let wrong_network = NetworkId::from_bytes([81_u8; 32]);
    let (wrong_network_invitation, authority) = signed_invitation(wrong_network, 10, 20)?;
    assert_rejected_creation_exchange(
        &profile,
        &login_key,
        &fixture,
        RejectedCreationCase {
            request_id: 81,
            invitation: Some(wrong_network_invitation),
            admission: CreationAdmission::Invitation {
                authority: authority.public_key(),
                now: UtcSecond::from_unix_seconds(10),
            },
            login_is_available: true,
            invitation_is_available: true,
            expected_error: AuthError::InvitationRejected,
        },
    )?;

    let (reserved_invitation, authority) = signed_invitation(TEST_NETWORK, 10, 20)?;
    assert_rejected_creation_exchange(
        &profile,
        &login_key,
        &fixture,
        RejectedCreationCase {
            request_id: 83,
            invitation: Some(reserved_invitation),
            admission: CreationAdmission::Invitation {
                authority: authority.public_key(),
                now: UtcSecond::from_unix_seconds(10),
            },
            login_is_available: true,
            invitation_is_available: false,
            expected_error: AuthError::InvitationRejected,
        },
    )?;
    assert_rejected_creation_exchange(
        &profile,
        &login_key,
        &fixture,
        RejectedCreationCase {
            request_id: 85,
            invitation: None,
            admission: CreationAdmission::Open,
            login_is_available: false,
            invitation_is_available: false,
            expected_error: AuthError::WrongState,
        },
    )?;

    let wrong_digest =
        derive_login_index(&login_key, TEST_NETWORK, &NormalizedLogin::prepare("bob")?)?;
    let account_id = AccountRandomId::from_bytes([83_u8; 16]).to_account_id();
    assert_rejected_authentication_exchange(
        &profile,
        &login_key,
        &fake_key,
        &fixture,
        AuthenticationLookup::Known(Box::new(AccountCredentialRecord::new(
            account_id,
            Revision::new(7)?,
            Generation::new(9)?,
            wrong_digest,
            OpaqueCredentialId::from_bytes([68_u8; 32]),
            copy_record(&fixture.record)?,
        ))),
        83,
    )?;
    let matching_digest = derive_login_index(
        &login_key,
        TEST_NETWORK,
        &NormalizedLogin::prepare("alice")?,
    )?;
    assert_rejected_authentication_exchange(
        &profile,
        &login_key,
        &fake_key,
        &fixture,
        AuthenticationLookup::Known(Box::new(AccountCredentialRecord::new(
            account_id,
            Revision::new(7)?,
            Generation::new(0)?,
            matching_digest,
            OpaqueCredentialId::from_bytes([68_u8; 32]),
            copy_record(&fixture.record)?,
        ))),
        85,
    )?;
    Ok(())
}

#[test]
fn authenticated_wire_rejects_malformed_headers_padding_and_selected_arms()
-> Result<(), Box<dyn core::error::Error>> {
    assert_eq!(ACCOUNT_SERVICE_ENVELOPE_BYTES, 4_726);
    assert_eq!(ACCOUNT_SERVICE_RESPONSE_BYTES, 4_342);
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let fixture = protocol_fixture(&profile, &credential(101), b"malformed matrix")?;
    let private_key = AccountHpkePrivateKey::generate()?;
    let (invitation, _authority) = signed_invitation(TEST_NETWORK, 10, 20)?;
    let invited_request = AccountRequestPayload::CreationStart(CreationStart {
        network_id: TEST_NETWORK,
        login: NormalizedLogin::prepare("invited")?,
        registration_request: copy_request(&fixture.registration_request)?,
        invitation: Some(invitation),
    });
    assert!(matches!(
        request_round_trip(
            &private_key,
            RequestId::from_bytes([100_u8; 16]),
            invited_request,
        )?,
        OpenedAccountServiceRequest::CreationStart(request)
            if matches!(request.payload(), CreationStart {
            invitation: Some(_),
            ..
        })
    ));
    let payload = AccountRequestPayload::AuthenticationStart(AuthenticationStart {
        network_id: TEST_NETWORK,
        login: NormalizedLogin::prepare("alice")?,
        ke1: OpaqueKe1::from_bytes(*fixture.ke1.expose_for_account_request())?,
    });
    let request_plaintext = encode_request_plaintext(&payload)?;

    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        TEST_NETWORK,
        TEST_RECOVERY_EPOCH,
        public_key.key_id(),
        RequestId::from_bytes([102_u8; 16]),
        AccountServiceMessageKind::OpaqueAuthStart,
    );
    let (sealed, _token) = seal_account_request(public_key, binding, &request_plaintext)?;
    let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
    assert_eq!(
        envelope.message_kind(),
        AccountServiceMessageKind::OpaqueAuthStart
    );
    assert_eq!(envelope.client_request_id(), binding.client_request_id());
    let encoded_envelope = *envelope.as_bytes();
    for (offset, value) in [(0_usize, 0_u16), (82, u16::MAX), (116, 0)] {
        let mut changed = encoded_envelope;
        replace_u16(&mut changed, offset, value)?;
        assert_eq!(
            AccountServiceEnvelope::parse(changed).err(),
            Some(AuthError::InvalidEncoding)
        );
    }
    assert_eq!(
        open_and_parse_request(
            &private_key,
            RecoveryEpoch::from_bytes([103_u8; 16]),
            TEST_NETWORK,
            AccountServiceMessageKind::OpaqueAuthStart,
            &envelope,
        )
        .err(),
        Some(AuthError::AuthenticationFailed)
    );
    assert_eq!(
        open_and_parse_request(
            &private_key,
            TEST_RECOVERY_EPOCH,
            NetworkId::from_bytes([103_u8; 32]),
            AccountServiceMessageKind::OpaqueAuthStart,
            &envelope,
        )
        .err(),
        Some(AuthError::ContextMismatch)
    );
    assert_eq!(
        open_and_parse_request(
            &private_key,
            TEST_RECOVERY_EPOCH,
            TEST_NETWORK,
            AccountServiceMessageKind::OpaqueAuthFinish,
            &envelope,
        )
        .err(),
        Some(AuthError::ContextMismatch)
    );

    let mut malformed_requests = Vec::new();
    let mut changed = request_plaintext;
    replace_u16(&mut changed, 0, 0)?;
    malformed_requests.push(changed);
    let mut changed = request_plaintext;
    replace_u16(&mut changed, 2, 1)?;
    malformed_requests.push(changed);
    let inner_length_bytes = request_plaintext
        .get(2..4)
        .ok_or("request inner length is absent")?;
    let inner_length = usize::from(u16::from_be_bytes(inner_length_bytes.try_into()?));
    let padding_length_offset = 4_usize
        .checked_add(inner_length)
        .ok_or("request padding offset overflow")?;
    let mut changed = request_plaintext;
    replace_u16(&mut changed, padding_length_offset, 0)?;
    malformed_requests.push(changed);
    let request_padding_length = usize::from(u16::from_be_bytes(
        request_plaintext
            .get(padding_length_offset..padding_length_offset + 2)
            .ok_or("request padding length is absent")?
            .try_into()?,
    ));
    let mut changed = request_plaintext;
    replace_u16(&mut changed, 2, u16::try_from(inner_length + 1)?)?;
    let extra_inner_byte = changed
        .get_mut(padding_length_offset)
        .ok_or("request trailing inner byte is absent")?;
    *extra_inner_byte = 0;
    replace_u16(
        &mut changed,
        padding_length_offset + 1,
        u16::try_from(request_padding_length - 1)?,
    )?;
    malformed_requests.push(changed);
    let mut changed = request_plaintext;
    let final_padding_byte = changed.last_mut().ok_or("request plaintext is empty")?;
    *final_padding_byte = 1;
    malformed_requests.push(changed);
    let mut changed = request_plaintext;
    replace_u16(&mut changed, 4, 0)?;
    malformed_requests.push(changed);
    let mut changed = request_plaintext;
    let network_byte = changed
        .get_mut(6)
        .ok_or("request network field is absent")?;
    *network_byte ^= 1;
    malformed_requests.push(changed);
    let mut changed = request_plaintext;
    let login_byte = changed.get_mut(39).ok_or("request login field is absent")?;
    *login_byte = b'A';
    malformed_requests.push(changed);
    let mut changed = request_plaintext;
    let login_length = changed
        .get_mut(38)
        .ok_or("request login length is absent")?;
    *login_length = 2;
    malformed_requests.push(changed);
    let ke1_length_offset = 39_usize
        .checked_add("alice".len())
        .ok_or("KE1 length offset overflow")?;
    let mut changed = request_plaintext;
    let ke1_length = changed
        .get_mut(ke1_length_offset)
        .ok_or("request KE1 length is absent")?;
    *ke1_length = 95;
    malformed_requests.push(changed);
    let mut malformed_ke1 = request_plaintext;
    let ke1_start = ke1_length_offset
        .checked_add(1)
        .ok_or("KE1 start offset overflow")?;
    let ke1_group_element_end = ke1_start
        .checked_add(32)
        .ok_or("KE1 element offset overflow")?;
    malformed_ke1
        .get_mut(ke1_start..ke1_group_element_end)
        .ok_or("request KE1 element is absent")?
        .fill(u8::MAX);
    assert_eq!(
        parse_authenticated_plaintext(
            &private_key,
            AccountServiceMessageKind::OpaqueAuthStart,
            &malformed_ke1,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );
    for malformed in malformed_requests {
        assert!(matches!(
            parse_authenticated_plaintext(
                &private_key,
                AccountServiceMessageKind::OpaqueAuthStart,
                &malformed,
            ),
            Err(AuthError::InvalidEncoding | AuthError::ContextMismatch)
        ));
    }
    assert!(
        parse_authenticated_plaintext(
            &private_key,
            AccountServiceMessageKind::AccountCreateFinish,
            &request_plaintext,
        )
        .is_err()
    );

    let completion = AccountServiceResponsePayload::AuthenticationCompletion(Completion::rejected(
        TransactionId::from_bytes([104_u8; 16]),
    ));
    let response_plaintext = encode_response_plaintext(&completion)?;
    let mut malformed_responses = Vec::new();
    let mut changed = response_plaintext;
    replace_u16(&mut changed, 0, 0)?;
    malformed_responses.push(changed);
    let mut changed = response_plaintext;
    replace_u16(&mut changed, 2, 1)?;
    malformed_responses.push(changed);
    let response_payload_length_bytes = response_plaintext
        .get(2..4)
        .ok_or("response payload length is absent")?;
    let response_payload_length = usize::from(u16::from_be_bytes(
        response_payload_length_bytes.try_into()?,
    ));
    let response_padding_offset = 4_usize
        .checked_add(response_payload_length)
        .ok_or("response padding offset overflow")?;
    let mut changed = response_plaintext;
    replace_u16(&mut changed, response_padding_offset, 0)?;
    malformed_responses.push(changed);
    let response_padding_length = usize::from(u16::from_be_bytes(
        response_plaintext
            .get(response_padding_offset..response_padding_offset + 2)
            .ok_or("response padding length is absent")?
            .try_into()?,
    ));
    let mut changed = response_plaintext;
    replace_u16(&mut changed, 2, u16::try_from(response_payload_length + 1)?)?;
    let extra_payload_byte = changed
        .get_mut(response_padding_offset)
        .ok_or("response trailing payload byte is absent")?;
    *extra_payload_byte = 0;
    replace_u16(
        &mut changed,
        response_padding_offset + 1,
        u16::try_from(response_padding_length - 1)?,
    )?;
    malformed_responses.push(changed);
    let mut changed = response_plaintext;
    let final_padding_byte = changed.last_mut().ok_or("response plaintext is empty")?;
    *final_padding_byte = 1;
    malformed_responses.push(changed);
    let mut changed = response_plaintext;
    replace_u16(&mut changed, 4, 0)?;
    malformed_responses.push(changed);
    let mut changed = response_plaintext;
    replace_u16(&mut changed, 22, u16::MAX)?;
    malformed_responses.push(changed);
    let mut changed = response_plaintext;
    let rejected_account_byte = changed
        .get_mut(24)
        .ok_or("completion account field is absent")?;
    *rejected_account_byte = 1;
    malformed_responses.push(changed);
    let mut changed = response_plaintext;
    let rejected_generation_byte = changed
        .get_mut(55)
        .ok_or("completion generation field is absent")?;
    *rejected_generation_byte = 1;
    malformed_responses.push(changed);
    for malformed in malformed_responses {
        assert_eq!(
            parse_authenticated_response(
                &private_key,
                AccountServiceMessageKind::OpaqueAuthFinish,
                AccountServiceResponseKind::OpaqueAuthComplete,
                &malformed,
            )
            .err(),
            Some(AuthError::InvalidEncoding)
        );
    }
    let wrong_generation = encode_response_plaintext(
        &AccountServiceResponsePayload::CreationCompletion(Completion::committed(
            TransactionId::from_bytes([105_u8; 16]),
            AccountRandomId::from_bytes([106_u8; 16]).to_account_id(),
            0,
        )),
    )?;
    assert_eq!(
        parse_authenticated_response(
            &private_key,
            AccountServiceMessageKind::OpaqueAuthFinish,
            AccountServiceResponseKind::OpaqueAuthComplete,
            &wrong_generation,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );
    let valid_session_completion = encode_response_plaintext(
        &AccountServiceResponsePayload::AuthenticationCompletion(Completion::committed(
            TransactionId::from_bytes([105_u8; 16]),
            AccountRandomId::from_bytes([106_u8; 16]).to_account_id(),
            1,
        )),
    )?;
    assert_eq!(
        parse_authenticated_response(
            &private_key,
            AccountServiceMessageKind::AccountCreateFinish,
            AccountServiceResponseKind::AccountCreateComplete,
            &valid_session_completion,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );
    let mut invalid_account = valid_session_completion;
    invalid_account
        .get_mut(24..48)
        .ok_or("completion account slot is absent")?
        .fill(0);
    assert_eq!(
        parse_authenticated_response(
            &private_key,
            AccountServiceMessageKind::OpaqueAuthFinish,
            AccountServiceResponseKind::OpaqueAuthComplete,
            &invalid_account,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );
    let wrong_challenge =
        encode_response_plaintext(&AccountServiceResponsePayload::CreationChallenge {
            transaction_id: TransactionId::from_bytes([107_u8; 16]),
            credential_id: credential(108),
            response: OpaqueRegistrationResponse::from_bytes(
                *fixture.registration_response.expose_for_account_response(),
            )?,
        })?;
    assert!(
        parse_authenticated_response(
            &private_key,
            AccountServiceMessageKind::OpaqueAuthStart,
            AccountServiceResponseKind::OpaqueAuthChallenge,
            &wrong_challenge,
        )
        .is_err()
    );
    let auth_challenge =
        encode_response_plaintext(&AccountServiceResponsePayload::AuthenticationChallenge {
            transaction_id: TransactionId::from_bytes([107_u8; 16]),
            credential_id: credential(108),
            ke2: Box::new(OpaqueKe2::from_bytes(
                *fixture.ke2.expose_for_account_response(),
            )?),
        })?;
    assert_eq!(
        parse_authenticated_response(
            &private_key,
            AccountServiceMessageKind::AccountCreateStart,
            AccountServiceResponseKind::AccountCreateChallenge,
            &auth_challenge,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );
    let mut invalid_challenge = wrong_challenge;
    invalid_challenge
        .get_mut(56..120)
        .ok_or("creation challenge message slot is absent")?
        .fill(0);
    assert_eq!(
        parse_authenticated_response(
            &private_key,
            AccountServiceMessageKind::AccountCreateStart,
            AccountServiceResponseKind::AccountCreateChallenge,
            &invalid_challenge,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );

    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        TEST_NETWORK,
        TEST_RECOVERY_EPOCH,
        public_key.key_id(),
        RequestId::from_bytes([109_u8; 16]),
        AccountServiceMessageKind::OpaqueAuthFinish,
    );
    let (sealed_request, _open_token) = seal_account_request(
        public_key,
        binding,
        &[0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES],
    )?;
    let (_opened, seal_token) = open_account_request(
        &private_key,
        binding,
        sealed_request.encapsulated_key(),
        sealed_request.ciphertext(),
    )?;
    let sealed_response = seal_token.seal_response(
        0,
        AccountServiceResponseKind::OpaqueAuthComplete,
        &response_plaintext,
    )?;
    let response = AccountServiceResponse::from_sealed(sealed_response)?;
    assert_eq!(
        response.response_kind(),
        AccountServiceResponseKind::OpaqueAuthComplete
    );
    assert_eq!(response.client_request_id(), binding.client_request_id());
    let encoded_response = *response.as_bytes();
    for (offset, value) in [(0_usize, 0_u16), (82, u16::MAX), (116, 0)] {
        let mut changed = encoded_response;
        replace_u16(&mut changed, offset, value)?;
        assert_eq!(
            AccountServiceResponse::parse(changed).err(),
            Some(AuthError::InvalidEncoding)
        );
    }
    for (index, offset) in [2_usize, 34].into_iter().enumerate() {
        let binding = AccountRequestBinding::new(
            TEST_NETWORK,
            TEST_RECOVERY_EPOCH,
            private_key.public_key()?.key_id(),
            RequestId::from_bytes([u8::try_from(110 + index)?; 16]),
            AccountServiceMessageKind::OpaqueAuthFinish,
        );
        let (sealed_request, open_token) = seal_account_request(
            private_key.public_key()?,
            binding,
            &[0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES],
        )?;
        let (_opened, seal_token) = open_account_request(
            &private_key,
            binding,
            sealed_request.encapsulated_key(),
            sealed_request.ciphertext(),
        )?;
        let sealed_response = seal_token.seal_response(
            0,
            AccountServiceResponseKind::OpaqueAuthComplete,
            &response_plaintext,
        )?;
        let response = AccountServiceResponse::from_sealed(sealed_response)?;
        let mut changed = *response.as_bytes();
        let header_byte = changed
            .get_mut(offset)
            .ok_or("response binding field is absent")?;
        *header_byte ^= 1;
        let changed = AccountServiceResponse::parse(changed)?;
        assert_eq!(
            open_and_parse_response(open_token, &changed).err(),
            Some(AuthError::ContextMismatch)
        );
    }
    Ok(())
}

#[test]
fn authenticated_wire_rejects_noncanonical_variable_lengths_and_completion_rules()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let fixture = protocol_fixture(&profile, &credential(141), b"length matrix")?;
    let private_key = AccountHpkePrivateKey::generate()?;

    let creation = AccountRequestPayload::CreationStart(CreationStart {
        network_id: TEST_NETWORK,
        login: NormalizedLogin::prepare("invited")?,
        registration_request: copy_request(&fixture.registration_request)?,
        invitation: None,
    });
    let mut malformed_invitation = encode_request_plaintext(&creation)?;
    let inner_length = usize::from(u16::from_be_bytes(
        malformed_invitation
            .get(2..4)
            .ok_or("creation inner length is absent")?
            .try_into()?,
    ));
    let padding_length_offset = 4_usize
        .checked_add(inner_length)
        .ok_or("creation padding offset overflow")?;
    let padding_length = usize::from(u16::from_be_bytes(
        malformed_invitation
            .get(padding_length_offset..padding_length_offset + 2)
            .ok_or("creation padding length is absent")?
            .try_into()?,
    ));
    *malformed_invitation
        .get_mut(79)
        .ok_or("creation invitation length is absent")? = 1;
    *malformed_invitation
        .get_mut(padding_length_offset)
        .ok_or("creation invitation byte is absent")? = 0;
    replace_u16(
        &mut malformed_invitation,
        2,
        u16::try_from(inner_length + 1)?,
    )?;
    replace_u16(
        &mut malformed_invitation,
        padding_length_offset + 1,
        u16::try_from(padding_length - 1)?,
    )?;
    assert_eq!(
        parse_authenticated_plaintext(
            &private_key,
            AccountServiceMessageKind::AccountCreateStart,
            &malformed_invitation,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );

    assert_eq!(
        encode_response_plaintext(&AccountServiceResponsePayload::CreationCompletion(
            Completion::committed(
                TransactionId::from_bytes([142_u8; 16]),
                AccountRandomId::from_bytes([143_u8; 16]).to_account_id(),
                1,
            ),
        ))
        .err(),
        Some(AuthError::InvalidEncoding)
    );
    assert_eq!(
        encode_response_plaintext(&AccountServiceResponsePayload::AuthenticationCompletion(
            Completion::committed(
                TransactionId::from_bytes([144_u8; 16]),
                AccountRandomId::from_bytes([145_u8; 16]).to_account_id(),
                0,
            ),
        ))
        .err(),
        Some(AuthError::InvalidEncoding)
    );

    let mut short_challenge =
        encode_response_plaintext(&AccountServiceResponsePayload::CreationChallenge {
            transaction_id: TransactionId::from_bytes([146_u8; 16]),
            credential_id: credential(147),
            response: OpaqueRegistrationResponse::from_bytes(
                *fixture.registration_response.expose_for_account_response(),
            )?,
        })?;
    replace_u16(&mut short_challenge, 54, 63)?;
    assert_eq!(
        parse_authenticated_response(
            &private_key,
            AccountServiceMessageKind::AccountCreateStart,
            AccountServiceResponseKind::AccountCreateChallenge,
            &short_challenge,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn authenticated_wire_rejects_both_vector_bounds_and_noncanonical_rejections()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let fixture = protocol_fixture(&profile, &credential(156), b"boundary matrix")?;
    let private_key = AccountHpkePrivateKey::generate()?;

    let creation = AccountRequestPayload::CreationStart(CreationStart {
        network_id: TEST_NETWORK,
        login: NormalizedLogin::prepare("invited")?,
        registration_request: copy_request(&fixture.registration_request)?,
        invitation: None,
    });
    let mut oversized_invitation = encode_request_plaintext(&creation)?;
    *oversized_invitation
        .get_mut(79)
        .ok_or("creation invitation length is absent")? =
        u8::try_from(ACCOUNT_CREATION_INVITE_BYTES + 1)?;
    assert_eq!(
        parse_authenticated_plaintext(
            &private_key,
            AccountServiceMessageKind::AccountCreateStart,
            &oversized_invitation,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );

    let authentication = AccountRequestPayload::AuthenticationStart(AuthenticationStart {
        network_id: TEST_NETWORK,
        login: NormalizedLogin::prepare("alice")?,
        ke1: OpaqueKe1::from_bytes(*fixture.ke1.expose_for_account_request())?,
    });
    let authentication_plaintext = encode_request_plaintext(&authentication)?;
    for invalid_login_length in [2_u8, 65] {
        let mut changed = authentication_plaintext;
        *changed
            .get_mut(38)
            .ok_or("authentication login length is absent")? = invalid_login_length;
        assert_eq!(
            parse_authenticated_plaintext(
                &private_key,
                AccountServiceMessageKind::OpaqueAuthStart,
                &changed,
            )
            .err(),
            Some(AuthError::InvalidEncoding)
        );
    }

    let mut oversized_challenge =
        encode_response_plaintext(&AccountServiceResponsePayload::CreationChallenge {
            transaction_id: TransactionId::from_bytes([157_u8; 16]),
            credential_id: credential(158),
            response: OpaqueRegistrationResponse::from_bytes(
                *fixture.registration_response.expose_for_account_response(),
            )?,
        })?;
    replace_u16(&mut oversized_challenge, 54, 321)?;
    assert_eq!(
        parse_authenticated_response(
            &private_key,
            AccountServiceMessageKind::AccountCreateStart,
            AccountServiceResponseKind::AccountCreateChallenge,
            &oversized_challenge,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );

    let rejected = AccountServiceResponsePayload::CreationCompletion(Completion::rejected(
        TransactionId::from_bytes([159_u8; 16]),
    ));
    let rejected_plaintext = encode_response_plaintext(&rejected)?;
    for offset in [24_usize, 55] {
        let mut changed = rejected_plaintext;
        *changed
            .get_mut(offset)
            .ok_or("rejected completion field is absent")? = 1;
        assert_eq!(
            parse_authenticated_response(
                &private_key,
                AccountServiceMessageKind::AccountCreateFinish,
                AccountServiceResponseKind::AccountCreateComplete,
                &changed,
            )
            .err(),
            Some(AuthError::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn invitation_and_transaction_rejections_cover_every_bound_context()
-> Result<(), Box<dyn core::error::Error>> {
    let (invitation, authority) = signed_invitation(TEST_NETWORK, 10, 20)?;
    invitation.verify(
        authority.public_key(),
        TEST_NETWORK,
        UtcSecond::from_unix_seconds(10),
    )?;
    assert_eq!(invitation.expires_at(), UtcSecond::from_unix_seconds(20));
    assert_eq!(
        invitation.expose_for_account_request().len(),
        ACCOUNT_CREATION_INVITE_BYTES
    );
    for (network, now) in [
        (NetworkId::from_bytes([110_u8; 32]), 10_u64),
        (TEST_NETWORK, 9),
        (TEST_NETWORK, 20),
    ] {
        assert_eq!(
            invitation
                .verify(
                    authority.public_key(),
                    network,
                    UtcSecond::from_unix_seconds(now)
                )
                .err(),
            Some(AuthError::InvitationRejected)
        );
    }
    assert_eq!(
        invitation
            .verify(
                Ed25519SecretKey::from_bytes([111_u8; 32]).public_key(),
                TEST_NETWORK,
                UtcSecond::from_unix_seconds(10),
            )
            .err(),
        Some(AuthError::InvitationRejected)
    );
    for (not_before, expires_at) in [(20_u64, 10_u64), (10, 10), (0, 2_592_001)] {
        let (invalid_time, invalid_authority) =
            signed_invitation(TEST_NETWORK, not_before, expires_at)?;
        assert_eq!(
            invalid_time
                .verify(
                    invalid_authority.public_key(),
                    TEST_NETWORK,
                    UtcSecond::from_unix_seconds(not_before),
                )
                .err(),
            Some(AuthError::InvitationRejected)
        );
    }
    let mut wrong_profile = *invitation.expose_for_account_request();
    replace_u16(&mut wrong_profile, 0, 0)?;
    assert_eq!(
        agenc_ircd_auth::AccountCreationInvite::parse(&wrong_profile).err(),
        Some(AuthError::InvalidEncoding)
    );
    let mut wrong_limit = *invitation.expose_for_account_request();
    replace_u16(&mut wrong_limit, 66, 2)?;
    assert_eq!(
        agenc_ircd_auth::AccountCreationInvite::parse(&wrong_limit).err(),
        Some(AuthError::InvalidEncoding)
    );

    let transaction_id = TransactionId::from_bytes([112_u8; 16]);
    let route = operation_route()?;
    for (class, timeout) in [
        (TransactionClass::AccountCreation, 60_000_u64),
        (TransactionClass::Authentication, 30_000),
        (TransactionClass::CredentialChange, 60_000),
        (TransactionClass::AccountDeletion, 60_000),
    ] {
        let binding = AccountTransactionBinding::new(
            transaction_id,
            class,
            TEST_NETWORK,
            route,
            MonotonicTick::from_ticks(1),
        )?;
        assert_eq!(binding.transaction_id(), transaction_id);
        assert_eq!(binding.expires_at(), MonotonicTick::from_ticks(timeout + 1));
    }
    assert_eq!(
        AccountTransactionBinding::new(
            transaction_id,
            TransactionClass::AccountCreation,
            TEST_NETWORK,
            route,
            MonotonicTick::from_ticks(u64::MAX),
        )
        .err(),
        Some(AuthError::Overflow)
    );
    let binding = AccountTransactionBinding::new(
        transaction_id,
        TransactionClass::Authentication,
        TEST_NETWORK,
        route,
        MonotonicTick::from_ticks(0),
    )?;
    let cases = [
        (
            TransactionClass::AccountCreation,
            TEST_NETWORK,
            route,
            MonotonicTick::from_ticks(1),
            AuthError::ContextMismatch,
        ),
        (
            TransactionClass::Authentication,
            NetworkId::from_bytes([115_u8; 32]),
            route,
            MonotonicTick::from_ticks(1),
            AuthError::ContextMismatch,
        ),
        (
            TransactionClass::Authentication,
            TEST_NETWORK,
            AccountRouteBinding::new(
                ServerId::from_bytes([116_u8; 16]),
                ServerIncarnation::from_bytes([27_u8; 16]),
                OriginId::from_bytes([22_u8; 16]),
                Generation::new(24)?,
                ConnectionId::from_bytes([23_u8; 16]),
                [28_u8; 32],
            ),
            MonotonicTick::from_ticks(1),
            AuthError::ContextMismatch,
        ),
        (
            TransactionClass::Authentication,
            TEST_NETWORK,
            AccountRouteBinding::new(
                ServerId::from_bytes([26_u8; 16]),
                ServerIncarnation::from_bytes([117_u8; 16]),
                OriginId::from_bytes([22_u8; 16]),
                Generation::new(24)?,
                ConnectionId::from_bytes([23_u8; 16]),
                [28_u8; 32],
            ),
            MonotonicTick::from_ticks(1),
            AuthError::ContextMismatch,
        ),
        (
            TransactionClass::Authentication,
            TEST_NETWORK,
            AccountRouteBinding::new(
                ServerId::from_bytes([26_u8; 16]),
                ServerIncarnation::from_bytes([27_u8; 16]),
                OriginId::from_bytes([118_u8; 16]),
                Generation::new(24)?,
                ConnectionId::from_bytes([23_u8; 16]),
                [28_u8; 32],
            ),
            MonotonicTick::from_ticks(1),
            AuthError::WrongOrigin,
        ),
        (
            TransactionClass::Authentication,
            TEST_NETWORK,
            AccountRouteBinding::new(
                ServerId::from_bytes([26_u8; 16]),
                ServerIncarnation::from_bytes([27_u8; 16]),
                OriginId::from_bytes([22_u8; 16]),
                Generation::new(119)?,
                ConnectionId::from_bytes([23_u8; 16]),
                [28_u8; 32],
            ),
            MonotonicTick::from_ticks(1),
            AuthError::WrongOrigin,
        ),
        (
            TransactionClass::Authentication,
            TEST_NETWORK,
            AccountRouteBinding::new(
                ServerId::from_bytes([26_u8; 16]),
                ServerIncarnation::from_bytes([27_u8; 16]),
                OriginId::from_bytes([22_u8; 16]),
                Generation::new(24)?,
                ConnectionId::from_bytes([120_u8; 16]),
                [28_u8; 32],
            ),
            MonotonicTick::from_ticks(1),
            AuthError::WrongConnection,
        ),
        (
            TransactionClass::Authentication,
            TEST_NETWORK,
            AccountRouteBinding::new(
                ServerId::from_bytes([26_u8; 16]),
                ServerIncarnation::from_bytes([27_u8; 16]),
                OriginId::from_bytes([22_u8; 16]),
                Generation::new(24)?,
                ConnectionId::from_bytes([23_u8; 16]),
                [121_u8; 32],
            ),
            MonotonicTick::from_ticks(1),
            AuthError::WrongConnection,
        ),
        (
            TransactionClass::Authentication,
            TEST_NETWORK,
            route,
            MonotonicTick::from_ticks(30_000),
            AuthError::Expired,
        ),
    ];
    for (class, network, candidate_route, now, expected) in cases {
        let mut transaction = AccountTransaction::new(binding, 7_u8);
        assert_eq!(
            transaction
                .consume(class, network, candidate_route, now)
                .err(),
            Some(expected)
        );
        assert_eq!(
            transaction
                .consume(
                    TransactionClass::Authentication,
                    TEST_NETWORK,
                    route,
                    MonotonicTick::from_ticks(1),
                )
                .err(),
            Some(AuthError::Consumed)
        );
    }
    let mut accepted = AccountTransaction::new(binding, 9_u8);
    assert_eq!(
        accepted.consume(
            TransactionClass::Authentication,
            TEST_NETWORK,
            route,
            MonotonicTick::from_ticks(29_999),
        )?,
        9
    );
    let mut disconnected = AccountTransaction::new(binding, 8_u8);
    disconnected.consume_on_disconnect();
    assert_eq!(
        disconnected
            .consume(
                TransactionClass::Authentication,
                TEST_NETWORK,
                route,
                MonotonicTick::from_ticks(1),
            )
            .err(),
        Some(AuthError::Consumed)
    );
    Ok(())
}

#[test]
fn account_service_guards_reject_every_context_and_state_substitution()
-> Result<(), Box<dyn core::error::Error>> {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([122_u8; 32]);
    let fake_key = OpaqueFakeCredentialKey::from_bytes([123_u8; 32]);
    let credential_bytes = [124_u8; 32];
    let password = b"service guard password";
    let fixture = protocol_fixture(&profile, &credential(124), password)?;
    let account_id = AccountRandomId::from_bytes([125_u8; 16]).to_account_id();
    let account_revision = Revision::new(7)?;
    let generation = Generation::new(9)?;
    let login = NormalizedLogin::prepare("alice")?;
    let wrong_network = NetworkId::from_bytes([126_u8; 32]);

    let creation_parameters = |context_network, login_is_available, request_id| {
        Ok::<_, Box<dyn core::error::Error>>(AccountCreationStartParameters {
            context: operation_context_for_network(context_network, 10)?,
            request: authenticated_creation_start(
                request_id,
                CreationStart {
                    network_id: TEST_NETWORK,
                    login: NormalizedLogin::prepare("alice")?,
                    registration_request: copy_request(&fixture.registration_request)?,
                    invitation: None,
                },
            )?,
            admission: CreationAdmission::Open,
            login_is_available,
            invitation_is_available: true,
        })
    };
    assert_eq!(
        begin_account_creation(
            &profile,
            &login_key,
            creation_parameters(wrong_network, true, 127)?,
        )
        .err(),
        Some(AuthError::ContextMismatch)
    );
    let (invitation, authority) = signed_invitation(TEST_NETWORK, 10, 20)?;
    let invited = AccountCreationStartParameters {
        request: authenticated_creation_start(
            133,
            CreationStart {
                network_id: TEST_NETWORK,
                login: NormalizedLogin::prepare("alice")?,
                registration_request: copy_request(&fixture.registration_request)?,
                invitation: Some(invitation),
            },
        )?,
        admission: CreationAdmission::Invitation {
            authority: authority.public_key(),
            now: UtcSecond::from_unix_seconds(10),
        },
        ..creation_parameters(TEST_NETWORK, true, 134)?
    };
    let invited_start = begin_account_creation(&profile, &login_key, invited)?;
    let invited_transaction_id = invited_start.transaction_id();
    let held = HeldCreationStart {
        start: invited_start.seal(0)?,
    };
    let mut invited_transaction = held.start.into_transaction_after_commit(1)?;
    let invited_outcome = finish_account_creation(
        &mut invited_transaction,
        operation_context(11)?,
        authenticated_creation_finish(
            135,
            CreationFinish {
                network_id: TEST_NETWORK,
                transaction_id: invited_transaction_id,
                registration_record: copy_record(&fixture.record)?,
            },
        )?,
    )?;
    let invited_outcome = invited_outcome.seal(1)?;
    let invited_intent = invited_outcome.result()?;
    assert_eq!(
        invited_intent.invitation_id(),
        Some(InviteId::from_bytes([93_u8; 16]))
    );
    assert_eq!(
        invited_intent.invitation_expires_at(),
        Some(UtcSecond::from_unix_seconds(20))
    );

    for (wrong_context, wrong_transaction, request_id) in
        [(true, false, 136_u8), (false, true, 138_u8)]
    {
        let start = begin_account_creation(
            &profile,
            &login_key,
            creation_parameters(TEST_NETWORK, true, request_id)?,
        )?;
        let transaction_id = if wrong_transaction {
            TransactionId::from_bytes([request_id.wrapping_add(1); 16])
        } else {
            start.transaction_id()
        };
        let finish_context = if wrong_context {
            operation_context_for_network(wrong_network, 11)?
        } else {
            operation_context(11)?
        };
        let mut transaction = start.seal(0)?.into_transaction_after_commit(1)?;
        let outcome = finish_account_creation(
            &mut transaction,
            finish_context,
            authenticated_creation_finish(
                request_id.wrapping_add(1),
                CreationFinish {
                    network_id: TEST_NETWORK,
                    transaction_id,
                    registration_record: copy_record(&fixture.record)?,
                },
            )?,
        )?;
        assert_eq!(outcome.result().err(), Some(AuthError::ContextMismatch));
        let sealed = outcome.seal(1)?;
        assert!(sealed.result().is_err());
    }

    let auth_request = |request_id| {
        authenticated_authentication_start(
            request_id,
            AuthenticationStart {
                network_id: TEST_NETWORK,
                login: NormalizedLogin::prepare("alice")?,
                ke1: OpaqueKe1::from_bytes(*fixture.ke1.expose_for_account_request())?,
            },
        )
    };
    assert_eq!(
        begin_authentication(
            &profile,
            &login_key,
            &fake_key,
            AuthenticationStartParameters {
                context: operation_context_for_network(wrong_network, 100)?,
                request: auth_request(140)?,
                lookup: AuthenticationLookup::Unknown,
            },
        )
        .err(),
        Some(AuthError::AuthenticationFailed)
    );
    for (wrong_context, wrong_transaction, request_id) in
        [(true, false, 142_u8), (false, true, 144_u8)]
    {
        let start = begin_authentication(
            &profile,
            &login_key,
            &fake_key,
            AuthenticationStartParameters {
                context: operation_context(100)?,
                request: auth_request(request_id)?,
                lookup: AuthenticationLookup::Known(Box::new(AccountCredentialRecord::new(
                    account_id,
                    account_revision,
                    generation,
                    derive_login_index(&login_key, TEST_NETWORK, &login)?,
                    OpaqueCredentialId::from_bytes(credential_bytes),
                    copy_record(&fixture.record)?,
                ))),
            },
        )?;
        let transaction_id = if wrong_transaction {
            TransactionId::from_bytes([request_id.wrapping_add(1); 16])
        } else {
            start.transaction_id()
        };
        let finish_context = if wrong_context {
            operation_context_for_network(wrong_network, 101)?
        } else {
            operation_context(101)?
        };
        let mut transaction = start.seal(0)?.into_transaction_after_commit(1)?;
        let outcome = finish_account_authentication(
            &mut transaction,
            finish_context,
            authenticated_authentication_finish(
                request_id.wrapping_add(1),
                AuthenticationFinish {
                    network_id: TEST_NETWORK,
                    transaction_id,
                    ke3: OpaqueKe3::from_bytes(*fixture.ke3.expose_for_account_request())?,
                },
            )?,
        )?;
        assert!(outcome.result().is_err());
        let sealed = outcome.seal(1)?;
        assert!(sealed.result().is_err());
    }

    Ok(())
}

#[test]
fn transaction_state_types_are_nameable_by_downstream_composition() {
    let cases = [
        (
            core::any::type_name::<SealedAccountStart<AccountCreationState>>(),
            "AccountCreationState>",
        ),
        (
            core::any::type_name::<SealedAccountStart<AccountAuthenticationState>>(),
            "AccountAuthenticationState>",
        ),
        (
            core::any::type_name::<AccountTransaction<CredentialChangeState>>(),
            "CredentialChangeState>",
        ),
    ];
    for (name, suffix) in cases {
        assert!(
            name.ends_with(suffix),
            "{name} is not the expected state type"
        );
    }
}
