#![forbid(unsafe_code)]

//! Immutable Stage-04 OPAQUE, account-envelope, and padding vector checks.

use std::io;

use agenc_relay_auth::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES, AccountServiceEnvelope,
    AccountServiceResponse, AuthError, OPAQUE_KE1_BYTES, OPAQUE_KE2_BYTES, OPAQUE_KE3_BYTES,
    OPAQUE_REGISTRATION_RECORD_BYTES, OPAQUE_REGISTRATION_REQUEST_BYTES,
    OPAQUE_REGISTRATION_RESPONSE_BYTES, OPAQUE_SERVER_LOGIN_STATE_BYTES, OPAQUE_SERVER_SETUP_BYTES,
    OpaqueKe1, OpaqueKe2, OpaqueKe3, OpaqueProfile, OpaqueRegistrationRecord,
    OpaqueRegistrationRequest, OpaqueRegistrationResponse, OpaqueServerLoginState,
    finish_authentication, finish_registration, open_and_parse_request, open_and_parse_response,
};
use agenc_relay_crypto::{
    ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES, ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES,
    AccountHpkePrivateKey, AccountRequestBinding, open_account_request, seal_account_request,
};
use agenc_relay_types::{
    AccountServiceMessageKind, AccountServiceResponseKind, NetworkId, OpaqueCredentialId,
    RecoveryEpoch, RequestId,
};

const OPAQUE_VECTORS: &str =
    include_str!("../../../test-data/vectors/stage-four-opaque-v1.vectors");
const CRYPTO_VECTORS: &str =
    include_str!("../../../test-data/vectors/stage-four-crypto-v1.vectors");

fn vector_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn record(vectors: &'static str, id: &str) -> Result<&'static str, io::Error> {
    vectors
        .lines()
        .find(|line| line.split('|').next() == Some(id))
        .ok_or_else(|| vector_error("required vector record is absent"))
}

fn field<'a>(record: &'a str, name: &str) -> Result<&'a str, io::Error> {
    record
        .split('|')
        .skip(3)
        .find_map(|item| {
            item.split_once('=')
                .filter(|(candidate, _)| *candidate == name)
                .map(|(_, value)| value)
        })
        .ok_or_else(|| vector_error("required vector field is absent"))
}

fn hex_nibble(byte: u8) -> Result<u8, io::Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(vector_error("vector contains non-lowercase hexadecimal")),
    }
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, io::Error> {
    let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(vector_error("vector hexadecimal length is odd"));
    }
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(encoded.len() / 2)
        .map_err(|_| vector_error("vector allocation failed"))?;
    for [high, low] in pairs {
        decoded.push((hex_nibble(*high)? << 4) | hex_nibble(*low)?);
    }
    Ok(decoded)
}

fn fixed<const SIZE: usize>(record: &str, name: &str) -> Result<[u8; SIZE], io::Error> {
    decode_hex(field(record, name)?)?
        .try_into()
        .map_err(|_| vector_error("fixed vector field has the wrong length"))
}

#[test]
fn immutable_opaque_profile_matches_exact_setup_messages_and_lengths()
-> Result<(), Box<dyn core::error::Error>> {
    assert_eq!(OPAQUE_SERVER_SETUP_BYTES, 128);
    assert_eq!(OPAQUE_REGISTRATION_REQUEST_BYTES, 32);
    assert_eq!(OPAQUE_REGISTRATION_RESPONSE_BYTES, 64);
    assert_eq!(OPAQUE_REGISTRATION_RECORD_BYTES, 192);
    assert_eq!(OPAQUE_KE1_BYTES, 96);
    assert_eq!(OPAQUE_KE2_BYTES, 320);
    assert_eq!(OPAQUE_KE3_BYTES, 64);
    assert_eq!(OPAQUE_SERVER_LOGIN_STATE_BYTES, 128);

    let vector = record(OPAQUE_VECTORS, "VEC-S04-007-OPAQUE")?;
    assert_eq!(field(vector, "argon2_memory_kib_decimal")?, "65536");
    assert_eq!(field(vector, "argon2_iterations_decimal")?, "3");
    assert_eq!(field(vector, "argon2_lanes_decimal")?, "4");
    assert_eq!(field(vector, "argon2_output_bytes_decimal")?, "64");
    assert_eq!(
        field(vector, "lengths_decimal")?,
        "128,32,64,192,96,320,64,128"
    );

    let network = NetworkId::from_bytes(fixed(vector, "network")?);
    let credential = OpaqueCredentialId::from_bytes(fixed(vector, "credential_id")?);
    let setup = fixed(vector, "setup")?;
    let fake_record = fixed(vector, "fake_record")?;
    assert_eq!(&setup[96..128], &fake_record[..32]);
    assert!(fake_record[96..].iter().all(|byte| *byte == 0));
    let profile = OpaqueProfile::from_serialized(network, setup, fake_record)?;
    assert_eq!(profile.expose_setup_for_persistence(), &setup);
    assert_eq!(profile.expose_fake_record_for_persistence(), &fake_record);

    let request = OpaqueRegistrationRequest::from_bytes(fixed(vector, "registration_request")?)?;
    let response = profile.registration_start(&credential, &request)?;
    assert_eq!(
        response.expose_for_account_response(),
        &fixed::<OPAQUE_REGISTRATION_RESPONSE_BYTES>(vector, "registration_response")?
    );
    let checked_response =
        OpaqueRegistrationResponse::from_bytes(fixed(vector, "registration_response")?)?;
    assert_eq!(
        checked_response.expose_for_account_response(),
        response.expose_for_account_response()
    );
    let record = finish_registration(fixed(vector, "registration_upload")?)?;
    assert_eq!(
        record.expose_for_persistence(),
        &fixed::<OPAQUE_REGISTRATION_RECORD_BYTES>(vector, "registration_record")?
    );
    let checked_record =
        OpaqueRegistrationRecord::from_bytes(fixed(vector, "registration_record")?)?;
    assert_eq!(
        checked_record.expose_for_persistence(),
        record.expose_for_persistence()
    );

    let ke1 = OpaqueKe1::from_bytes(fixed(vector, "ke1")?)?;
    let ke2 = OpaqueKe2::from_bytes(fixed(vector, "ke2")?)?;
    let ke3 = OpaqueKe3::from_bytes(fixed(vector, "ke3")?)?;
    assert_eq!(
        ke1.expose_for_account_request(),
        &fixed::<KE1_BYTES>(vector, "ke1")?
    );
    assert_eq!(
        ke2.expose_for_account_response(),
        &fixed::<KE2_BYTES>(vector, "ke2")?
    );
    assert_eq!(
        ke3.expose_for_account_request(),
        &fixed::<KE3_BYTES>(vector, "ke3")?
    );
    let state = OpaqueServerLoginState::from_persisted_bytes(fixed(vector, "server_login_state")?)?;
    finish_authentication(network, &credential, state, &ke3)?.authorize_account_transition();
    Ok(())
}

const KE1_BYTES: usize = 96;
const KE2_BYTES: usize = 320;
const KE3_BYTES: usize = 64;

#[test]
fn immutable_opaque_vector_rejects_setup_record_identity_and_ke3_substitution()
-> Result<(), Box<dyn core::error::Error>> {
    let vector = record(OPAQUE_VECTORS, "VEC-S04-007-OPAQUE")?;
    let network = NetworkId::from_bytes(fixed(vector, "network")?);
    let credential = OpaqueCredentialId::from_bytes(fixed(vector, "credential_id")?);
    let fake_credential = OpaqueCredentialId::from_bytes(fixed(vector, "fake_credential_id")?);
    let setup = fixed(vector, "setup")?;
    let fake_record = fixed(vector, "fake_record")?;
    let profile = OpaqueProfile::from_serialized(network, setup, fake_record)?;
    let ke3 = OpaqueKe3::from_bytes(fixed(vector, "ke3")?)?;

    let wrong_network = NetworkId::from_bytes([0x53; 32]);
    let stored_record =
        OpaqueRegistrationRecord::from_bytes(fixed(vector, "registration_record")?)?;
    let ke1 = OpaqueKe1::from_bytes(fixed(vector, "ke1")?)?;
    let (_challenge, state) =
        profile.authentication_start(wrong_network, &credential, Some(&stored_record), &ke1)?;
    assert_eq!(
        finish_authentication(wrong_network, &credential, state, &ke3).err(),
        Some(AuthError::AuthenticationFailed)
    );
    let (_challenge, state) =
        profile.authentication_start(network, &fake_credential, Some(&stored_record), &ke1)?;
    assert_eq!(
        finish_authentication(network, &fake_credential, state, &ke3).err(),
        Some(AuthError::AuthenticationFailed)
    );
    let mut tampered_ke3 = fixed(vector, "ke3")?;
    let first = tampered_ke3
        .first_mut()
        .ok_or_else(|| vector_error("KE3 is empty"))?;
    *first ^= 1;
    let tampered_ke3 = OpaqueKe3::from_bytes(tampered_ke3)?;
    let state = OpaqueServerLoginState::from_persisted_bytes(fixed(vector, "server_login_state")?)?;
    assert_eq!(
        finish_authentication(network, &credential, state, &tampered_ke3).err(),
        Some(AuthError::AuthenticationFailed)
    );

    let fake_state =
        OpaqueServerLoginState::from_persisted_bytes(fixed(vector, "fake_server_login_state")?)?;
    assert_eq!(
        finish_authentication(network, &fake_credential, fake_state, &ke3).err(),
        Some(AuthError::AuthenticationFailed)
    );
    let dummy_state =
        OpaqueServerLoginState::from_persisted_bytes(fixed(vector, "dummy_server_login_state")?)?;
    let zero_credential = OpaqueCredentialId::from_bytes([0_u8; 32]);
    assert_eq!(
        finish_authentication(network, &zero_credential, dummy_state, &ke3).err(),
        Some(AuthError::AuthenticationFailed)
    );
    assert_eq!(
        profile.dummy_finish_work(network, &fake_credential, &ke3),
        AuthError::AuthenticationFailed
    );

    let mut substituted_fake_record = fake_record;
    let first = substituted_fake_record
        .first_mut()
        .ok_or_else(|| vector_error("fake record is empty"))?;
    *first ^= 1;
    assert!(OpaqueProfile::from_serialized(network, setup, substituted_fake_record).is_err());

    let mut nonzero_fake_envelope = fake_record;
    nonzero_fake_envelope[96] = 1;
    assert!(OpaqueProfile::from_serialized(network, setup, nonzero_fake_envelope).is_err());

    let mut tampered_request = fixed(vector, "registration_request")?;
    let first = tampered_request
        .first_mut()
        .ok_or_else(|| vector_error("registration request is empty"))?;
    *first ^= 1;
    if let Ok(tampered_request) = OpaqueRegistrationRequest::from_bytes(tampered_request) {
        let tampered_response = profile.registration_start(&credential, &tampered_request)?;
        assert_ne!(
            tampered_response.expose_for_account_response(),
            &fixed::<OPAQUE_REGISTRATION_RESPONSE_BYTES>(vector, "registration_response")?
        );
    }
    Ok(())
}

fn parse_fixed_request_plaintext(
    private_key: &AccountHpkePrivateKey,
    network: NetworkId,
    epoch: RecoveryEpoch,
    request_id: RequestId,
    plaintext: &[u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES],
) -> Result<AuthError, Box<dyn core::error::Error>> {
    let public_key = private_key.public_key()?;
    let kind = AccountServiceMessageKind::OpaqueAuthStart;
    let binding = AccountRequestBinding::new(network, epoch, public_key.key_id(), request_id, kind);
    let (sealed, _token) = seal_account_request(public_key, binding, plaintext)?;
    let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
    open_and_parse_request(private_key, epoch, network, kind, &envelope)
        .map(|_| AuthError::WrongState)
        .or_else(Ok)
}

fn parse_fixed_response_plaintext(
    private_key: &AccountHpkePrivateKey,
    network: NetworkId,
    epoch: RecoveryEpoch,
    request_id: RequestId,
    plaintext: &[u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES],
) -> Result<AuthError, Box<dyn core::error::Error>> {
    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        network,
        epoch,
        public_key.key_id(),
        request_id,
        AccountServiceMessageKind::OpaqueAuthStart,
    );
    let request_plaintext = [0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES];
    let (sealed_request, client_token) =
        seal_account_request(public_key, binding, &request_plaintext)?;
    let (_opened, server_token) = open_account_request(
        private_key,
        binding,
        sealed_request.encapsulated_key(),
        sealed_request.ciphertext(),
    )?;
    let sealed_response = server_token.seal_response(
        0,
        AccountServiceResponseKind::OpaqueAuthChallenge,
        plaintext,
    )?;
    let response = AccountServiceResponse::from_sealed(sealed_response)?;
    open_and_parse_response(client_token, &response)
        .map(|_| AuthError::WrongState)
        .or_else(Ok)
}

#[test]
fn immutable_account_envelopes_and_padding_boundaries_fail_closed()
-> Result<(), Box<dyn core::error::Error>> {
    let vector = record(CRYPTO_VECTORS, "VEC-S04-006-HPKE")?;
    let private_key = AccountHpkePrivateKey::from_bytes(fixed(vector, "private")?)?;
    let network = NetworkId::from_bytes(fixed(vector, "network")?);
    let epoch = RecoveryEpoch::from_bytes(fixed(vector, "epoch")?);
    let request_id = RequestId::from_bytes(fixed(vector, "request_id")?);
    let request_kind = AccountServiceMessageKind::OpaqueAuthStart;

    let request_envelope = AccountServiceEnvelope::parse(fixed(vector, "request_envelope")?)?;
    assert_eq!(
        request_envelope.as_bytes().len(),
        ACCOUNT_SERVICE_ENVELOPE_BYTES
    );
    assert_eq!(
        open_and_parse_request(
            &private_key,
            epoch,
            network,
            request_kind,
            &request_envelope,
        )
        .err(),
        Some(AuthError::InvalidEncoding)
    );
    let nonzero_padding =
        AccountServiceEnvelope::parse(fixed(vector, "nonzero_padding_request_envelope")?)?;
    assert_eq!(
        open_and_parse_request(&private_key, epoch, network, request_kind, &nonzero_padding,).err(),
        Some(AuthError::InvalidEncoding)
    );

    let response = AccountServiceResponse::parse(fixed(vector, "response_envelope")?)?;
    assert_eq!(response.as_bytes().len(), ACCOUNT_SERVICE_RESPONSE_BYTES);
    for name in [
        "request_below_min_plaintext",
        "request_max_plaintext",
        "request_above_max_plaintext",
    ] {
        let plaintext = fixed(vector, name)?;
        assert_eq!(
            parse_fixed_request_plaintext(&private_key, network, epoch, request_id, &plaintext,)?,
            AuthError::InvalidEncoding
        );
    }
    for name in [
        "response_below_min_plaintext",
        "response_max_plaintext",
        "response_above_max_plaintext",
    ] {
        let plaintext = fixed(vector, name)?;
        assert_eq!(
            parse_fixed_response_plaintext(&private_key, network, epoch, request_id, &plaintext,)?,
            AuthError::InvalidEncoding
        );
    }

    let mut wrong_request_padding_length: [u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES] =
        fixed(vector, "request_plaintext")?;
    let request_padding_offset = 4_usize
        .checked_add(72)
        .ok_or_else(|| vector_error("request padding offset overflow"))?;
    wrong_request_padding_length
        .get_mut(request_padding_offset..request_padding_offset + 2)
        .ok_or_else(|| vector_error("request padding length is absent"))?
        .copy_from_slice(&0_u16.to_be_bytes());
    assert_eq!(
        parse_fixed_request_plaintext(
            &private_key,
            network,
            epoch,
            request_id,
            &wrong_request_padding_length,
        )?,
        AuthError::InvalidEncoding
    );

    let mut nonzero_response_padding: [u8; ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES] =
        fixed(vector, "response_plaintext")?;
    let last = nonzero_response_padding
        .last_mut()
        .ok_or_else(|| vector_error("response plaintext is empty"))?;
    *last = 1;
    assert_eq!(
        parse_fixed_response_plaintext(
            &private_key,
            network,
            epoch,
            request_id,
            &nonzero_response_padding,
        )?,
        AuthError::InvalidEncoding
    );
    Ok(())
}
