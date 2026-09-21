#![forbid(unsafe_code)]

//! Durable transaction-record capture, restore, and credential-change context
//! checks reachable only through the public account-service surface.
//!
//! The record layouts below mirror the private writer order in
//! `service.rs`. The layout guard test pins every assumed offset to the
//! exported record sizes so a layout change fails loudly here.

use agenc_relay_auth::{
    ACCOUNT_CREATION_TIMEOUT_TICKS, AUTHENTICATION_TIMEOUT_TICKS,
    AUTHENTICATION_TRANSACTION_RECORD_BYTES, AccountAuthenticationState, AccountCreationInvite,
    AccountCreationStartParameters, AccountCreationState, AccountCredentialRecord,
    AccountOperationContext, AccountRequestPayload, AccountRouteBinding, AccountServiceEnvelope,
    AccountServiceResponsePayload, AccountTransaction, AccountTransactionBinding, AuthError,
    AuthenticatedAccountRequest, AuthenticationFinish, AuthenticationLookup, AuthenticationStart,
    AuthenticationStartParameters, AuthenticationTransactionRecord,
    CREATION_TRANSACTION_RECORD_BYTES, CREDENTIAL_CHANGE_TIMEOUT_TICKS,
    CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES, CreationAdmission, CreationFinish, CreationStart,
    CreationTransactionRecord, CredentialChangeFinish, CredentialChangeStart,
    CredentialChangeStartParameters, CredentialChangeState, CredentialChangeTransactionRecord,
    DestructiveAccountSnapshot, OPAQUE_SERVER_LOGIN_STATE_BYTES, OpaqueKe1, OpaqueKe3,
    OpaqueProfile, OpaqueRegistrationRecord, OpaqueRegistrationRequest,
    OpenedAccountServiceRequest, SealedAccountStart, TransactionClass, begin_account_creation,
    begin_authentication, begin_credential_change, encode_request_plaintext,
    finish_account_authentication, finish_account_creation, finish_credential_change,
    open_and_parse_request, open_and_parse_response,
};
use agenc_relay_crypto::{
    AccountHpkePrivateKey, AccountRequestBinding, AccountResponseOpenToken, Ed25519SecretKey,
    LoginIndexKey, OpaqueFakeCredentialKey, derive_login_index, seal_account_request,
};
use agenc_relay_types::{
    AccountId, AccountRandomId, AccountServiceCompletionStatus, AccountServiceMessageKind,
    ConnectionId, Generation, InviteId, MonotonicTick, NetworkId, NormalizedLogin,
    OpaqueCredentialId, OriginId, RecoveryEpoch, RequestId, Revision, ServerId, ServerIncarnation,
    TransactionId, UtcSecond,
};

type TestResult = Result<(), Box<dyn core::error::Error>>;

const TEST_NETWORK: NetworkId = NetworkId::from_bytes([21_u8; 32]);
const TEST_RECOVERY_EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([25_u8; 16]);
const TEST_LOGIN: &str = "restart-user";
const OPAQUE_VECTORS: &str =
    include_str!("../../../test-data/vectors/stage-four-opaque-v1.vectors");

// Shared durable-record header: version u16, class u16, transaction ID 16,
// network ID 32, route (edge 16, incarnation 16, origin 16, origin generation
// u64, connection 16, nonce 32), durable expiry u64, then the START request
// binding (network 32, recovery epoch 16, recipient key 32, request 16,
// message kind u16).
const VERSION_OFFSET: usize = 0;
const CLASS_OFFSET: usize = 2;
const ROUTE_ORIGIN_GENERATION_OFFSET: usize = 2 + 2 + 16 + 32 + 16 + 16 + 16;
const BINDING_NETWORK_OFFSET: usize = ROUTE_ORIGIN_GENERATION_OFFSET + 8 + 16 + 32 + 8;
const BINDING_KIND_OFFSET: usize = BINDING_NETWORK_OFFSET + 32 + 16 + 32 + 16;
const BODY_OFFSET: usize = BINDING_KIND_OFFSET + 2;
// Authentication body: candidate tag 1, account 24, revision u64,
// generation u64, credential 32, OPAQUE server login state.
const CANDIDATE_ACCOUNT_OFFSET: usize = BODY_OFFSET + 1;
const CANDIDATE_REVISION_OFFSET: usize = CANDIDATE_ACCOUNT_OFFSET + 24;
const CANDIDATE_GENERATION_OFFSET: usize = CANDIDATE_REVISION_OFFSET + 8;
// Creation body: disposition u16, login digest 32, credential 32,
// invitation tag 1, invite ID 16, invitation not_before u64, invitation
// expiry u64.
const INVITATION_TAG_OFFSET: usize = BODY_OFFSET + 2 + 32 + 32;
const INVITATION_ID_OFFSET: usize = INVITATION_TAG_OFFSET + 1;
const INVITATION_NOT_BEFORE_OFFSET: usize = INVITATION_ID_OFFSET + 16;
const INVITATION_EXPIRY_OFFSET: usize = INVITATION_NOT_BEFORE_OFFSET + 8;
// Credential-change body: disposition u16, account 24, revision u64,
// generation u64, credential 32.
const CREDENTIAL_GENERATION_OFFSET: usize = BODY_OFFSET + 2 + 24 + 8;

const ZERO_U64: [u8; 8] = [0_u8; 8];
const ONE_U64: [u8; 8] = 1_u64.to_be_bytes();

fn hex_nibble(byte: u8) -> Result<u8, Box<dyn core::error::Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("OPAQUE vector is not lowercase hexadecimal".into()),
    }
}

fn vector<const N: usize>(name: &str) -> Result<[u8; N], Box<dyn core::error::Error>> {
    let record = OPAQUE_VECTORS
        .lines()
        .find(|line| line.starts_with("VEC-S04-007-OPAQUE|"))
        .ok_or("OPAQUE vector record is absent")?;
    let encoded = record
        .split('|')
        .skip(3)
        .find_map(|item| {
            item.split_once('=')
                .filter(|(candidate, _)| *candidate == name)
                .map(|(_, value)| value)
        })
        .ok_or("OPAQUE vector field is absent")?;
    let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() || pairs.len() != N {
        return Err("OPAQUE vector length does not match the requested size".into());
    }
    let mut decoded = [0_u8; N];
    for (slot, [high, low]) in decoded.iter_mut().zip(pairs) {
        *slot = (hex_nibble(*high)? << 4) | hex_nibble(*low)?;
    }
    Ok(decoded)
}

fn operation_route() -> Result<AccountRouteBinding, agenc_relay_types::ValidationError> {
    Ok(AccountRouteBinding::new(
        ServerId::from_bytes([26_u8; 16]),
        ServerIncarnation::from_bytes([27_u8; 16]),
        OriginId::from_bytes([22_u8; 16]),
        Generation::new(24)?,
        ConnectionId::from_bytes([23_u8; 16]),
        [28_u8; 32],
    ))
}

fn operation_context(
    now: u64,
) -> Result<AccountOperationContext, agenc_relay_types::ValidationError> {
    Ok(AccountOperationContext::new(
        TEST_NETWORK,
        operation_route()?,
        MonotonicTick::from_ticks(now),
        UtcSecond::from_unix_seconds(now),
    ))
}

fn account_id() -> AccountId {
    AccountRandomId::from_bytes([29_u8; 16]).to_account_id()
}

fn destructive_account() -> Result<DestructiveAccountSnapshot, agenc_relay_types::ValidationError> {
    Ok(DestructiveAccountSnapshot::new(
        account_id(),
        Revision::new(7)?,
        Generation::new(9)?,
    ))
}

fn open_request(
    network_id: NetworkId,
    request_id: u8,
    payload: AccountRequestPayload,
) -> Result<(OpenedAccountServiceRequest, AccountResponseOpenToken), Box<dyn core::error::Error>> {
    let private_key = AccountHpkePrivateKey::from_bytes([7_u8; 32])?;
    let public_key = private_key.public_key()?;
    let message_kind = payload.message_kind();
    let binding = AccountRequestBinding::new(
        network_id,
        TEST_RECOVERY_EPOCH,
        public_key.key_id(),
        RequestId::from_bytes([request_id; 16]),
        message_kind,
    );
    let plaintext = encode_request_plaintext(&payload)?;
    let (sealed, token) = seal_account_request(public_key, binding, plaintext.expose_for_hpke())?;
    let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
    let request = open_and_parse_request(
        &private_key,
        TEST_RECOVERY_EPOCH,
        network_id,
        message_kind,
        &envelope,
    )?;
    Ok((request, token))
}

fn creation_start(
    request_id: u8,
) -> Result<AuthenticatedAccountRequest<CreationStart>, Box<dyn core::error::Error>> {
    let payload = CreationStart {
        network_id: TEST_NETWORK,
        login: NormalizedLogin::prepare(TEST_LOGIN)?,
        registration_request: OpaqueRegistrationRequest::from_bytes(vector(
            "registration_request",
        )?)?,
        invitation: None,
    };
    match open_request(
        TEST_NETWORK,
        request_id,
        AccountRequestPayload::CreationStart(payload),
    )?
    .0
    {
        OpenedAccountServiceRequest::CreationStart(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

fn invited_creation_start(
    request_id: u8,
    invitation: AccountCreationInvite,
) -> Result<AuthenticatedAccountRequest<CreationStart>, Box<dyn core::error::Error>> {
    let payload = CreationStart {
        network_id: TEST_NETWORK,
        login: NormalizedLogin::prepare(TEST_LOGIN)?,
        registration_request: OpaqueRegistrationRequest::from_bytes(vector(
            "registration_request",
        )?)?,
        invitation: Some(invitation),
    };
    match open_request(
        TEST_NETWORK,
        request_id,
        AccountRequestPayload::CreationStart(payload),
    )?
    .0
    {
        OpenedAccountServiceRequest::CreationStart(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

fn creation_finish(
    request_id: u8,
    transaction_id: TransactionId,
) -> Result<
    (
        AuthenticatedAccountRequest<CreationFinish>,
        AccountResponseOpenToken,
    ),
    Box<dyn core::error::Error>,
> {
    let payload = CreationFinish {
        network_id: TEST_NETWORK,
        transaction_id,
        registration_record: OpaqueRegistrationRecord::from_bytes(vector("registration_record")?)?,
    };
    let (request, token) = open_request(
        TEST_NETWORK,
        request_id,
        AccountRequestPayload::CreationFinish(payload),
    )?;
    match request {
        OpenedAccountServiceRequest::CreationFinish(request) => Ok((request, token)),
        _ => Err("opened request kind changed".into()),
    }
}

fn authentication_start(
    request_id: u8,
) -> Result<AuthenticatedAccountRequest<AuthenticationStart>, Box<dyn core::error::Error>> {
    let payload = AuthenticationStart {
        network_id: TEST_NETWORK,
        login: NormalizedLogin::prepare(TEST_LOGIN)?,
        ke1: OpaqueKe1::from_bytes(vector("ke1")?)?,
    };
    match open_request(
        TEST_NETWORK,
        request_id,
        AccountRequestPayload::AuthenticationStart(payload),
    )?
    .0
    {
        OpenedAccountServiceRequest::AuthenticationStart(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

/// Opens an OPAQUE FINISH whose all-zero KE3 can never authenticate.
fn authentication_finish(
    request_id: u8,
    transaction_id: TransactionId,
) -> Result<
    (
        AuthenticatedAccountRequest<AuthenticationFinish>,
        AccountResponseOpenToken,
    ),
    Box<dyn core::error::Error>,
> {
    let payload = AuthenticationFinish {
        network_id: TEST_NETWORK,
        transaction_id,
        ke3: OpaqueKe3::from_bytes([0_u8; 64])?,
    };
    let (request, token) = open_request(
        TEST_NETWORK,
        request_id,
        AccountRequestPayload::AuthenticationFinish(payload),
    )?;
    match request {
        OpenedAccountServiceRequest::AuthenticationFinish(request) => Ok((request, token)),
        _ => Err("opened request kind changed".into()),
    }
}

fn credential_start(
    network_id: NetworkId,
    request_id: u8,
) -> Result<AuthenticatedAccountRequest<CredentialChangeStart>, Box<dyn core::error::Error>> {
    let payload = CredentialChangeStart {
        network_id,
        account_id: account_id(),
        registration_request: OpaqueRegistrationRequest::from_bytes(vector(
            "registration_request",
        )?)?,
    };
    match open_request(
        network_id,
        request_id,
        AccountRequestPayload::CredentialChangeStart(payload),
    )?
    .0
    {
        OpenedAccountServiceRequest::CredentialChangeStart(request) => Ok(request),
        _ => Err("opened request kind changed".into()),
    }
}

fn credential_finish(
    network_id: NetworkId,
    request_id: u8,
    transaction_id: TransactionId,
) -> Result<
    (
        AuthenticatedAccountRequest<CredentialChangeFinish>,
        AccountResponseOpenToken,
    ),
    Box<dyn core::error::Error>,
> {
    let payload = CredentialChangeFinish {
        network_id,
        transaction_id,
        registration_record: OpaqueRegistrationRecord::from_bytes(vector("registration_record")?)?,
    };
    let (request, token) = open_request(
        network_id,
        request_id,
        AccountRequestPayload::CredentialChangeFinish(payload),
    )?;
    match request {
        OpenedAccountServiceRequest::CredentialChangeFinish(request) => Ok((request, token)),
        _ => Err("opened request kind changed".into()),
    }
}

fn sealed_creation_start(
    profile: &OpaqueProfile,
    login_key: &LoginIndexKey,
    request_id: u8,
) -> Result<SealedAccountStart<AccountCreationState>, Box<dyn core::error::Error>> {
    let start = begin_account_creation(
        profile,
        login_key,
        AccountCreationStartParameters {
            context: operation_context(10)?,
            request: creation_start(request_id)?,
            admission: CreationAdmission::Open,
            login_is_available: true,
            invitation_is_available: true,
        },
    )?;
    Ok(start.seal(0)?)
}

fn sealed_authentication_start(
    profile: &OpaqueProfile,
    login_key: &LoginIndexKey,
    fake_key: &OpaqueFakeCredentialKey,
    request_id: u8,
    lookup: AuthenticationLookup,
) -> Result<SealedAccountStart<AccountAuthenticationState>, Box<dyn core::error::Error>> {
    let start = begin_authentication(
        profile,
        login_key,
        fake_key,
        AuthenticationStartParameters {
            context: operation_context(100)?,
            request: authentication_start(request_id)?,
            lookup,
        },
    )?;
    Ok(start.seal(0)?)
}

/// Starts a credential change without a fresh-auth proof, so START admits a
/// challenge whose FINISH is latently rejected.
fn sealed_credential_start(
    profile: &OpaqueProfile,
    request_id: u8,
) -> Result<SealedAccountStart<CredentialChangeState>, Box<dyn core::error::Error>> {
    let start = begin_credential_change(
        profile,
        CredentialChangeStartParameters {
            context: operation_context(10)?,
            proof: None,
            account: destructive_account()?,
            credential_id: OpaqueCredentialId::from_bytes([40_u8; 32]),
            request: credential_start(TEST_NETWORK, request_id)?,
            operation_is_available: true,
        },
    )?;
    Ok(start.seal(0)?)
}

fn known_lookup(
    login_key: &LoginIndexKey,
) -> Result<AuthenticationLookup, Box<dyn core::error::Error>> {
    let login = NormalizedLogin::prepare(TEST_LOGIN)?;
    Ok(AuthenticationLookup::Known(Box::new(
        AccountCredentialRecord::new(
            account_id(),
            Revision::new(7)?,
            Generation::new(9)?,
            derive_login_index(login_key, TEST_NETWORK, &login)?,
            OpaqueCredentialId::from_bytes([41_u8; 32]),
            OpaqueRegistrationRecord::from_bytes(vector("registration_record")?)?,
        ),
    )))
}

fn with_bytes<const N: usize>(
    record: &[u8; N],
    offset: usize,
    replacement: &[u8],
) -> Result<[u8; N], Box<dyn core::error::Error>> {
    let mut copy = *record;
    let end = offset
        .checked_add(replacement.len())
        .ok_or("corruption offset overflow")?;
    copy.get_mut(offset..end)
        .ok_or("corruption slot is out of bounds")?
        .copy_from_slice(replacement);
    Ok(copy)
}

fn foreign_kind(kind: AccountServiceMessageKind) -> [u8; 2] {
    kind.wire_value().to_be_bytes()
}

#[test]
fn record_layout_offsets_match_the_exported_sizes() {
    assert_eq!(
        AUTHENTICATION_TRANSACTION_RECORD_BYTES,
        CANDIDATE_GENERATION_OFFSET + 8 + 32 + OPAQUE_SERVER_LOGIN_STATE_BYTES
    );
    assert_eq!(
        CREATION_TRANSACTION_RECORD_BYTES,
        INVITATION_EXPIRY_OFFSET + 8
    );
    assert_eq!(
        CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES,
        CREDENTIAL_GENERATION_OFFSET + 8 + 32
    );
}

#[test]
fn authentication_capture_rejects_expired_subsecond_and_foreign_class_transactions() -> TestResult {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([30_u8; 32]);
    let fake_key = OpaqueFakeCredentialKey::from_bytes([31_u8; 32]);
    let sealed = sealed_authentication_start(
        &profile,
        &login_key,
        &fake_key,
        32,
        AuthenticationLookup::Unknown,
    )?;
    let expires_at = 100 + AUTHENTICATION_TIMEOUT_TICKS;
    let now_utc = UtcSecond::from_unix_seconds(500);
    assert_eq!(
        sealed
            .authentication_transaction_record(MonotonicTick::from_ticks(expires_at), now_utc)
            .err(),
        Some(AuthError::Expired)
    );
    assert_eq!(
        sealed
            .authentication_transaction_record(MonotonicTick::from_ticks(expires_at - 999), now_utc)
            .err(),
        Some(AuthError::Expired)
    );
    let one_second_left = sealed.authentication_transaction_record(
        MonotonicTick::from_ticks(expires_at - 1_000),
        now_utc,
    )?;
    assert_eq!(
        one_second_left.durable_expires_at_utc()?,
        UtcSecond::from_unix_seconds(501)
    );

    let mut transaction = sealed.into_transaction_after_commit(1)?;
    assert_eq!(
        transaction.binding().expires_at(),
        MonotonicTick::from_ticks(expires_at)
    );
    let transaction_id = transaction.binding().transaction_id();
    let state = transaction.consume(
        TransactionClass::Authentication,
        TEST_NETWORK,
        operation_route()?,
        MonotonicTick::from_ticks(200),
    )?;
    let foreign_class = AccountTransaction::new(
        AccountTransactionBinding::new(
            transaction_id,
            TransactionClass::AccountCreation,
            TEST_NETWORK,
            operation_route()?,
            MonotonicTick::from_ticks(200),
        )?,
        state,
    );
    assert_eq!(
        AuthenticationTransactionRecord::capture(
            &foreign_class,
            MonotonicTick::from_ticks(300),
            now_utc
        )
        .err(),
        Some(AuthError::Expired)
    );
    Ok(())
}

#[test]
fn authentication_record_rejects_header_route_binding_and_generation_corruption() -> TestResult {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([33_u8; 32]);
    let fake_key = OpaqueFakeCredentialKey::from_bytes([34_u8; 32]);
    let sealed = sealed_authentication_start(
        &profile,
        &login_key,
        &fake_key,
        35,
        known_lookup(&login_key)?,
    )?;
    let transaction_id = sealed.transaction_id();
    let record = sealed.authentication_transaction_record(
        MonotonicTick::from_ticks(1_100),
        UtcSecond::from_unix_seconds(500),
    )?;
    let bytes = record.expose_for_persistence();
    let restore = |bytes: &[u8]| -> Result<_, AuthError> {
        AuthenticationTransactionRecord::parse(bytes)?.restore(
            MonotonicTick::from_ticks(0),
            UtcSecond::from_unix_seconds(501),
        )
    };
    assert_eq!(restore(bytes)?.binding().transaction_id(), transaction_id);

    let wrong_version = with_bytes(bytes, VERSION_OFFSET, &2_u16.to_be_bytes())?;
    assert_eq!(
        AuthenticationTransactionRecord::parse(&wrong_version)?
            .durable_expires_at_utc()
            .err(),
        Some(AuthError::InvalidEncoding)
    );
    let wrong_class = with_bytes(bytes, CLASS_OFFSET, &1_u16.to_be_bytes())?;
    assert_eq!(
        AuthenticationTransactionRecord::parse(&wrong_class)?
            .durable_expires_at_utc()
            .err(),
        Some(AuthError::InvalidEncoding)
    );
    assert_eq!(
        restore(&wrong_class).err(),
        Some(AuthError::InvalidEncoding)
    );

    let zero_origin_generation = with_bytes(bytes, ROUTE_ORIGIN_GENERATION_OFFSET, &ZERO_U64)?;
    assert_eq!(
        AuthenticationTransactionRecord::parse(&zero_origin_generation)?
            .durable_expires_at_utc()
            .err(),
        Some(AuthError::InvalidEncoding)
    );
    assert_eq!(
        restore(&zero_origin_generation).err(),
        Some(AuthError::InvalidEncoding)
    );

    let foreign_binding_network = with_bytes(bytes, BINDING_NETWORK_OFFSET, &[22_u8])?;
    assert_eq!(
        restore(&foreign_binding_network).err(),
        Some(AuthError::ContextMismatch)
    );
    let foreign_binding_kind = with_bytes(
        bytes,
        BINDING_KIND_OFFSET,
        &foreign_kind(AccountServiceMessageKind::AccountCreateStart),
    )?;
    assert_eq!(
        restore(&foreign_binding_kind).err(),
        Some(AuthError::ContextMismatch)
    );

    let zero_known_generation = with_bytes(bytes, CANDIDATE_GENERATION_OFFSET, &ZERO_U64)?;
    assert_eq!(
        restore(&zero_known_generation).err(),
        Some(AuthError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn rejected_candidate_record_restores_to_a_rejecting_finish_and_rejects_nonzero_fields()
-> TestResult {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([36_u8; 32]);
    let fake_key = OpaqueFakeCredentialKey::from_bytes([37_u8; 32]);
    let sealed = sealed_authentication_start(
        &profile,
        &login_key,
        &fake_key,
        38,
        AuthenticationLookup::Unknown,
    )?;
    let transaction_id = sealed.transaction_id();
    let record = sealed.authentication_transaction_record(
        MonotonicTick::from_ticks(1_100),
        UtcSecond::from_unix_seconds(600),
    )?;
    let bytes = record.expose_for_persistence();
    let restore = |bytes: &[u8]| -> Result<_, AuthError> {
        AuthenticationTransactionRecord::parse(bytes)?.restore(
            MonotonicTick::from_ticks(5_000),
            UtcSecond::from_unix_seconds(601),
        )
    };

    let mut restored = restore(bytes)?;
    assert_eq!(restored.binding().transaction_id(), transaction_id);
    let (finish, token) = authentication_finish(39, transaction_id)?;
    let outcome = finish_account_authentication(&mut restored, operation_context(5_001)?, finish)?;
    assert_eq!(
        outcome.result().err(),
        Some(AuthError::AuthenticationFailed)
    );
    let sealed_outcome = outcome.seal(1)?;
    assert!(matches!(
        open_and_parse_response(token, sealed_outcome.response_intent().response())?,
        AccountServiceResponsePayload::AuthenticationCompletion(completion)
            if completion.status() == AccountServiceCompletionStatus::Rejected
                && completion.transaction_id() == transaction_id
    ));

    for (offset, replacement) in [
        (CANDIDATE_ACCOUNT_OFFSET, &[1_u8][..]),
        (CANDIDATE_REVISION_OFFSET, &ONE_U64[..]),
        (CANDIDATE_GENERATION_OFFSET, &ONE_U64[..]),
    ] {
        let nonzero = with_bytes(bytes, offset, replacement)?;
        assert_eq!(restore(&nonzero).err(), Some(AuthError::InvalidEncoding));
    }
    Ok(())
}

#[test]
fn creation_record_rejects_deadlines_headers_bindings_and_invitation_corruption() -> TestResult {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([42_u8; 32]);
    let sealed = sealed_creation_start(&profile, &login_key, 43)?;
    let transaction_id = sealed.transaction_id();
    let expires_at = 10 + ACCOUNT_CREATION_TIMEOUT_TICKS;
    let now_utc = UtcSecond::from_unix_seconds(500);
    assert_eq!(
        sealed
            .creation_transaction_record(MonotonicTick::from_ticks(expires_at), now_utc)
            .err(),
        Some(AuthError::Expired)
    );
    assert_eq!(
        sealed
            .creation_transaction_record(MonotonicTick::from_ticks(expires_at - 999), now_utc)
            .err(),
        Some(AuthError::Expired)
    );
    assert_eq!(
        sealed
            .creation_transaction_record(MonotonicTick::from_ticks(expires_at - 1_000), now_utc)?
            .durable_expires_at_utc()?,
        UtcSecond::from_unix_seconds(501)
    );

    let record = sealed.creation_transaction_record(MonotonicTick::from_ticks(1_010), now_utc)?;
    let bytes = record.expose_for_persistence();
    let metadata = CreationTransactionRecord::parse(bytes)?.into_restart_cleanup_metadata()?;
    assert_eq!(metadata.transaction_id(), transaction_id);
    assert_eq!(
        metadata.durable_expires_at_utc(),
        UtcSecond::from_unix_seconds(559)
    );
    assert!(metadata.reservation_login_digest().is_some());
    assert!(metadata.reservation_invitation().is_none());
    let restore = |bytes: &[u8]| -> Result<_, AuthError> {
        CreationTransactionRecord::parse(bytes)?.restore(
            MonotonicTick::from_ticks(0),
            UtcSecond::from_unix_seconds(501),
        )
    };

    let wrong_version = with_bytes(bytes, VERSION_OFFSET, &2_u16.to_be_bytes())?;
    assert_eq!(
        CreationTransactionRecord::parse(&wrong_version)?
            .durable_expires_at_utc()
            .err(),
        Some(AuthError::InvalidEncoding)
    );
    let wrong_class = with_bytes(bytes, CLASS_OFFSET, &3_u16.to_be_bytes())?;
    assert_eq!(
        CreationTransactionRecord::parse(&wrong_class)?
            .into_restart_cleanup_metadata()
            .err(),
        Some(AuthError::InvalidEncoding)
    );
    let foreign_binding_network = with_bytes(bytes, BINDING_NETWORK_OFFSET, &[22_u8])?;
    assert_eq!(
        restore(&foreign_binding_network).err(),
        Some(AuthError::ContextMismatch)
    );
    let foreign_binding_kind = with_bytes(
        bytes,
        BINDING_KIND_OFFSET,
        &foreign_kind(AccountServiceMessageKind::OpaqueAuthStart),
    )?;
    assert_eq!(
        restore(&foreign_binding_kind).err(),
        Some(AuthError::ContextMismatch)
    );

    let absent_with_invite_id = with_bytes(bytes, INVITATION_ID_OFFSET, &[1_u8])?;
    assert_eq!(
        restore(&absent_with_invite_id).err(),
        Some(AuthError::InvalidEncoding)
    );
    let absent_with_expiry = with_bytes(bytes, INVITATION_EXPIRY_OFFSET, &ONE_U64)?;
    assert_eq!(
        restore(&absent_with_expiry).err(),
        Some(AuthError::InvalidEncoding)
    );
    let absent_with_not_before = with_bytes(bytes, INVITATION_NOT_BEFORE_OFFSET, &ONE_U64)?;
    assert_eq!(
        restore(&absent_with_not_before).err(),
        Some(AuthError::InvalidEncoding)
    );
    let present_without_expiry = with_bytes(bytes, INVITATION_TAG_OFFSET, &[1_u8])?;
    assert_eq!(
        restore(&present_without_expiry).err(),
        Some(AuthError::InvalidEncoding)
    );
    Ok(())
}

/// ZDH-A1 (issue #38): a sealed invitation-admitted START survives restart
/// with its exact interval, and the restored transaction rechecks that
/// interval at FINISH.
#[test]
fn restored_invited_creation_rechecks_the_invitation_interval_at_finish() -> TestResult {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([45_u8; 32]);
    let invite_id = InviteId::from_bytes([46_u8; 16]);
    let authority = Ed25519SecretKey::from_bytes([47_u8; 32]);
    let not_before = UtcSecond::from_unix_seconds(100);
    let expires_at = UtcSecond::from_unix_seconds(200);
    let invitation =
        AccountCreationInvite::issue(TEST_NETWORK, invite_id, not_before, expires_at, &authority)?;
    let start = begin_account_creation(
        &profile,
        &login_key,
        AccountCreationStartParameters {
            context: operation_context(150)?,
            request: invited_creation_start(48, invitation)?,
            admission: CreationAdmission::Invitation {
                authority: authority.public_key(),
                now: UtcSecond::from_unix_seconds(150),
            },
            login_is_available: true,
            invitation_is_available: true,
        },
    )?;
    let transaction_id = start.transaction_id();
    let sealed = start.seal(0)?;
    assert_eq!(
        sealed.creation_reservation_invitation(),
        Some((invite_id, expires_at))
    );
    let record = sealed.creation_transaction_record(
        MonotonicTick::from_ticks(1_150),
        UtcSecond::from_unix_seconds(150),
    )?;
    let bytes = record.expose_for_persistence();
    assert_eq!(
        bytes.get(INVITATION_NOT_BEFORE_OFFSET..INVITATION_EXPIRY_OFFSET),
        Some(100_u64.to_be_bytes().as_slice())
    );
    assert_eq!(
        bytes.get(INVITATION_EXPIRY_OFFSET..),
        Some(200_u64.to_be_bytes().as_slice())
    );

    // (a) restart cleanup reports the admitted invitation reservation.
    let metadata = CreationTransactionRecord::parse(bytes)?.into_restart_cleanup_metadata()?;
    assert_eq!(metadata.transaction_id(), transaction_id);
    assert_eq!(
        metadata.durable_expires_at_utc(),
        UtcSecond::from_unix_seconds(209)
    );
    assert!(metadata.reservation_login_digest().is_some());
    assert_eq!(
        metadata.reservation_invitation(),
        Some((invite_id, expires_at))
    );

    // (b) restore then FINISH inside the interval commits; at or after
    // expires_at and before not_before it rejects with InvitationRejected.
    let finish_after_restore = |now_utc: u64, request_id: u8| -> TestResult {
        let mut restored = CreationTransactionRecord::parse(bytes)?.restore(
            MonotonicTick::from_ticks(0),
            UtcSecond::from_unix_seconds(now_utc),
        )?;
        let (finish, _token) = creation_finish(request_id, transaction_id)?;
        let outcome = finish_account_creation(&mut restored, operation_context(now_utc)?, finish)?;
        let inside = (100..200).contains(&now_utc);
        if inside {
            let intent = outcome.result()?;
            assert_eq!(intent.invitation_id(), Some(invite_id));
            assert_eq!(intent.invitation_interval(), Some((not_before, expires_at)));
            assert!(outcome.seal(1)?.result().is_ok());
        } else {
            assert_eq!(
                outcome.result().err(),
                Some(AuthError::InvitationRejected),
                "restored FINISH at UTC {now_utc} must reject"
            );
            assert!(outcome.seal(1)?.result().is_err());
        }
        Ok(())
    };
    finish_after_restore(199, 49)?;
    finish_after_restore(100, 50)?;
    finish_after_restore(200, 51)?;
    finish_after_restore(205, 52)?;
    finish_after_restore(99, 53)?;

    // (c) interval corruption fails restore with InvalidEncoding.
    let restore = |bytes: &[u8]| -> Result<_, AuthError> {
        CreationTransactionRecord::parse(bytes)?.restore(
            MonotonicTick::from_ticks(0),
            UtcSecond::from_unix_seconds(150),
        )
    };
    for not_before in [200_u64, 201, u64::MAX] {
        let corrupted = with_bytes(
            bytes,
            INVITATION_NOT_BEFORE_OFFSET,
            &not_before.to_be_bytes(),
        )?;
        assert_eq!(restore(&corrupted).err(), Some(AuthError::InvalidEncoding));
        assert_eq!(
            CreationTransactionRecord::parse(&corrupted)?
                .into_restart_cleanup_metadata()
                .err(),
            Some(AuthError::InvalidEncoding)
        );
    }
    let oversized = with_bytes(
        bytes,
        INVITATION_EXPIRY_OFFSET,
        &(100 + 2_592_001_u64).to_be_bytes(),
    )?;
    assert_eq!(restore(&oversized).err(), Some(AuthError::InvalidEncoding));
    let present_without_not_before = with_bytes(bytes, INVITATION_NOT_BEFORE_OFFSET, &ZERO_U64)?;
    assert!(restore(&present_without_not_before).is_ok());
    Ok(())
}

#[test]
fn credential_change_record_rejects_deadlines_headers_bindings_and_zero_generation() -> TestResult {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let sealed = sealed_credential_start(&profile, 44)?;
    let transaction_id = sealed.transaction_id();
    let expires_at = 10 + CREDENTIAL_CHANGE_TIMEOUT_TICKS;
    let now_utc = UtcSecond::from_unix_seconds(700);
    assert_eq!(
        sealed
            .credential_change_transaction_record(MonotonicTick::from_ticks(expires_at), now_utc)
            .err(),
        Some(AuthError::Expired)
    );
    assert_eq!(
        sealed
            .credential_change_transaction_record(
                MonotonicTick::from_ticks(expires_at - 999),
                now_utc
            )
            .err(),
        Some(AuthError::Expired)
    );

    let record =
        sealed.credential_change_transaction_record(MonotonicTick::from_ticks(1_010), now_utc)?;
    let bytes = record.expose_for_persistence();
    let metadata =
        CredentialChangeTransactionRecord::parse(bytes)?.into_restart_cleanup_metadata()?;
    assert_eq!(metadata.transaction_id(), transaction_id);
    assert_eq!(
        metadata.durable_expires_at_utc(),
        UtcSecond::from_unix_seconds(759)
    );
    assert!(metadata.reservation_account_id().is_none());
    let restore = |bytes: &[u8]| -> Result<_, AuthError> {
        CredentialChangeTransactionRecord::parse(bytes)?.restore(
            MonotonicTick::from_ticks(0),
            UtcSecond::from_unix_seconds(701),
        )
    };
    assert_eq!(restore(bytes)?.binding().transaction_id(), transaction_id);

    let wrong_version = with_bytes(bytes, VERSION_OFFSET, &2_u16.to_be_bytes())?;
    assert_eq!(
        CredentialChangeTransactionRecord::parse(&wrong_version)?
            .durable_expires_at_utc()
            .err(),
        Some(AuthError::InvalidEncoding)
    );
    let wrong_class = with_bytes(bytes, CLASS_OFFSET, &1_u16.to_be_bytes())?;
    assert_eq!(
        restore(&wrong_class).err(),
        Some(AuthError::InvalidEncoding)
    );
    let foreign_binding_network = with_bytes(bytes, BINDING_NETWORK_OFFSET, &[22_u8])?;
    assert_eq!(
        restore(&foreign_binding_network).err(),
        Some(AuthError::ContextMismatch)
    );
    let foreign_binding_kind = with_bytes(
        bytes,
        BINDING_KIND_OFFSET,
        &foreign_kind(AccountServiceMessageKind::AccountCreateStart),
    )?;
    assert_eq!(
        restore(&foreign_binding_kind).err(),
        Some(AuthError::ContextMismatch)
    );
    let zero_generation = with_bytes(bytes, CREDENTIAL_GENERATION_OFFSET, &ZERO_U64)?;
    assert_eq!(
        restore(&zero_generation).err(),
        Some(AuthError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn credential_change_start_rejects_a_foreign_request_network() -> TestResult {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let foreign_network = NetworkId::from_bytes([45_u8; 32]);
    assert_eq!(
        begin_credential_change(
            &profile,
            CredentialChangeStartParameters {
                context: operation_context(10)?,
                proof: None,
                account: destructive_account()?,
                credential_id: OpaqueCredentialId::from_bytes([40_u8; 32]),
                request: credential_start(foreign_network, 46)?,
                operation_is_available: true,
            },
        )
        .err(),
        Some(AuthError::ContextMismatch)
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum CredentialFinishContextCase {
    InnerNetwork,
    WrongTransaction,
    ReusedRequestId,
}

#[test]
fn credential_change_finish_rejects_every_context_substitution_with_a_bound_receipt() -> TestResult
{
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    for (request_id, case) in [
        (50_u8, CredentialFinishContextCase::InnerNetwork),
        (52, CredentialFinishContextCase::WrongTransaction),
        (54, CredentialFinishContextCase::ReusedRequestId),
    ] {
        let sealed = sealed_credential_start(&profile, request_id)?;
        let transaction_id = sealed.transaction_id();
        let finish_network = match case {
            CredentialFinishContextCase::InnerNetwork => NetworkId::from_bytes([request_id; 32]),
            _ => TEST_NETWORK,
        };
        let claimed_transaction = match case {
            CredentialFinishContextCase::WrongTransaction => {
                TransactionId::from_bytes([request_id; 16])
            }
            _ => transaction_id,
        };
        let finish_request_id = match case {
            CredentialFinishContextCase::ReusedRequestId => request_id,
            _ => request_id.wrapping_add(1),
        };
        let (finish, token) =
            credential_finish(finish_network, finish_request_id, claimed_transaction)?;
        let mut transaction = sealed.into_transaction_after_commit(1)?;
        let outcome = finish_credential_change(&mut transaction, operation_context(11)?, finish)?;
        assert_eq!(outcome.result().err(), Some(AuthError::ContextMismatch));
        let sealed_outcome = outcome.seal(1)?;
        assert_eq!(
            sealed_outcome.result().err(),
            Some(AuthError::ContextMismatch)
        );
        assert!(matches!(
            open_and_parse_response(token, sealed_outcome.response_intent().response())?,
            AccountServiceResponsePayload::CredentialChangeCompletion(completion)
                if completion.status() == AccountServiceCompletionStatus::Rejected
                    && completion.transaction_id() == claimed_transaction
        ));
    }
    Ok(())
}

#[test]
fn unavailable_rejection_leaves_available_and_already_rejected_logins_unchanged() -> TestResult {
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let login_key = LoginIndexKey::from_bytes([56_u8; 32]);
    let fake_key = OpaqueFakeCredentialKey::from_bytes([57_u8; 32]);
    let sealed = sealed_authentication_start(
        &profile,
        &login_key,
        &fake_key,
        58,
        AuthenticationLookup::Unknown,
    )?;
    let transaction_id = sealed.transaction_id();
    let mut transaction = sealed.into_transaction_after_commit(1)?;
    let (finish, token) = authentication_finish(59, transaction_id)?;
    let outcome = finish_account_authentication(&mut transaction, operation_context(101)?, finish)?;
    assert_eq!(
        outcome.result().err(),
        Some(AuthError::AuthenticationFailed)
    );

    let available = outcome.reject_when_unavailable(true)?;
    assert_eq!(
        available.result().err(),
        Some(AuthError::AuthenticationFailed)
    );
    assert_eq!(available.response_plan().transaction_id(), transaction_id);
    let already_rejected = available.reject_when_unavailable(false)?;
    assert_eq!(
        already_rejected.result().err(),
        Some(AuthError::AuthenticationFailed)
    );
    let sealed_outcome = already_rejected.seal(1)?;
    assert_eq!(
        sealed_outcome.result().err(),
        Some(AuthError::AuthenticationFailed)
    );
    assert!(matches!(
        open_and_parse_response(token, sealed_outcome.response_intent().response())?,
        AccountServiceResponsePayload::AuthenticationCompletion(completion)
            if completion.status() == AccountServiceCompletionStatus::Rejected
                && completion.transaction_id() == transaction_id
    ));
    Ok(())
}
