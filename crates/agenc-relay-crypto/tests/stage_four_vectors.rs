#![forbid(unsafe_code)]

//! Immutable Stage-04 primitive and account-HPKE golden-vector checks.

use std::io;

use agenc_relay_crypto::{
    ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES, AccountHpkeKeyId, AccountHpkePrivateKey,
    AccountRequestBinding, CryptoError, DatabaseBinding, Ed25519PublicKey, Ed25519SecretKey,
    Ed25519Signature, LoginIndexKey, OpaqueFakeCredentialKey, SealedStorageRecord,
    SemanticHashDomain, SignatureDomain, StorageMasterKey, StorageNonce, StorageTable,
    derive_fake_credential_id, derive_login_index, derive_storage_index, derive_storage_record_key,
    open_account_request, open_storage_record, seal_storage_record, semantic_digest,
    sign_canonical, verify_canonical,
};
use agenc_relay_types::{
    AccountServiceMessageKind, AccountServiceResponseKind, DatabaseId, NetworkId, NormalizedLogin,
    RecoveryEpoch, RequestId, ServerId, ServerIncarnation,
};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable as _, OpModeR, setup_receiver};
use sha2::{Digest as _, Sha256};

const VECTORS: &str = include_str!("../../../test-data/vectors/stage-four-crypto-v1.vectors");

const STORAGE_SALT_LABEL: &[u8] = b"agenc-chat storage salt v1";
const STORAGE_RECORD_KEY_LABEL: &[u8] = b"agenc-chat storage record key v1";
const STORAGE_INDEX_KEY_LABEL: &[u8] = b"agenc-chat storage table index key v1";
const REQUEST_INFO_LABEL: &[u8] = b"agenc-chat account service hpke request v1";
const RESPONSE_KEY_LABEL: &[u8] = b"agenc-chat account service response key v1";
const RESPONSE_NONCE_LABEL: &[u8] = b"agenc-chat account service response nonce v1";
const RESPONSE_AAD_LABEL: &[u8] = b"agenc-chat account service response aad v1";

fn vector_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn record(id: &str) -> Result<&'static str, io::Error> {
    VECTORS
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

fn storage_binding() -> DatabaseBinding {
    DatabaseBinding::new(
        NetworkId::from_bytes([0x21; 32]),
        ServerId::from_bytes([0x22; 16]),
        ServerIncarnation::from_bytes([0x23; 16]),
        DatabaseId::from_bytes([0x24; 16]),
    )
}

fn reference_storage_subkey(
    master_key: &[u8; 32],
    binding: &[u8],
    label: &[u8],
) -> Result<[u8; 32], io::Error> {
    let mut salt_hash = Sha256::new();
    salt_hash.update(STORAGE_SALT_LABEL);
    salt_hash.update(binding);
    let salt = salt_hash.finalize();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), master_key);
    let mut info = Vec::new();
    info.extend_from_slice(label);
    info.extend_from_slice(&3_u16.to_be_bytes());
    info.extend_from_slice(&7_u32.to_be_bytes());
    let mut output = [0_u8; 32];
    hkdf.expand(&info, &mut output)
        .map_err(|_| vector_error("reference HKDF expansion failed"))?;
    Ok(output)
}

#[test]
fn immutable_hash_hmac_hkdf_and_storage_vectors_match_adapters()
-> Result<(), Box<dyn core::error::Error>> {
    let hash = record("VEC-S04-003-SHA256")?;
    let input = decode_hex(field(hash, "input")?)?;
    let expected: [u8; 32] = fixed(hash, "expected")?;
    assert_eq!(
        semantic_digest(SemanticHashDomain::PolicyId, &input)?.as_bytes(),
        &expected
    );

    let login_vector = record("VEC-S04-003-LOGIN-HMAC")?;
    let login = NormalizedLogin::prepare(std::str::from_utf8(&decode_hex(field(
        login_vector,
        "login",
    )?)?)?)?;
    let login_digest = derive_login_index(
        &LoginIndexKey::from_bytes(fixed(login_vector, "key")?),
        NetworkId::from_bytes(fixed(login_vector, "network")?),
        &login,
    )?;
    assert_eq!(
        login_digest.expose_for_storage_key(),
        &fixed::<32>(login_vector, "expected")?
    );

    let fake_vector = record("VEC-S04-003-FAKE-HMAC")?;
    let fake_credential = derive_fake_credential_id(
        &OpaqueFakeCredentialKey::from_bytes(fixed(fake_vector, "key")?),
        NetworkId::from_bytes(fixed(fake_vector, "network")?),
        &login,
    )?;
    assert_eq!(
        fake_credential.expose_for_account_service(),
        &fixed::<32>(fake_vector, "expected")?
    );

    let storage = record("VEC-S04-003-004-STORAGE")?;
    let master_bytes = fixed(storage, "master")?;
    let binding_bytes = decode_hex(field(storage, "binding")?)?;
    assert_eq!(storage_binding().encode()?.as_slice(), binding_bytes);
    assert_eq!(
        reference_storage_subkey(&master_bytes, &binding_bytes, STORAGE_RECORD_KEY_LABEL)?,
        fixed::<32>(storage, "record_key")?
    );
    assert_eq!(
        reference_storage_subkey(&master_bytes, &binding_bytes, STORAGE_INDEX_KEY_LABEL)?,
        fixed::<32>(storage, "index_key")?
    );
    let master = StorageMasterKey::from_bytes(master_bytes);
    let table = StorageTable::new(3)?;
    let index = derive_storage_index(
        &master,
        storage_binding(),
        table,
        7,
        &decode_hex(field(storage, "semantic_key")?)?,
    )?;
    assert_eq!(
        index.expose_for_storage_key(),
        &fixed::<32>(storage, "index")?
    );
    let key = derive_storage_record_key(&master, storage_binding(), table, 7)?;
    let nonce = StorageNonce::from_reserved_bytes(fixed(storage, "nonce")?);
    let stored_key = decode_hex(field(storage, "stored_key")?)?;
    let plaintext = decode_hex(field(storage, "plaintext")?)?;
    let sealed = seal_storage_record(&key, nonce, 9, &stored_key, &plaintext)?;
    assert_eq!(
        sealed.as_bytes(),
        decode_hex(field(storage, "ciphertext")?)?
    );
    let opened = open_storage_record(
        &key,
        &StorageNonce::from_reserved_bytes(fixed(storage, "nonce")?),
        9,
        &stored_key,
        &sealed,
    )?;
    assert_eq!(opened.expose_for_storage_codec(), plaintext);
    Ok(())
}

#[test]
fn immutable_storage_vector_rejects_tamper_and_context_substitution()
-> Result<(), Box<dyn core::error::Error>> {
    let vector = record("VEC-S04-003-004-STORAGE")?;
    let master = StorageMasterKey::from_bytes(fixed(vector, "master")?);
    let table = StorageTable::new(3)?;
    let key = derive_storage_record_key(&master, storage_binding(), table, 7)?;
    let nonce_bytes = fixed(vector, "nonce")?;
    let stored_key = decode_hex(field(vector, "stored_key")?)?;
    let mut ciphertext = decode_hex(field(vector, "ciphertext")?)?;
    let first = ciphertext
        .first_mut()
        .ok_or_else(|| vector_error("storage ciphertext is empty"))?;
    *first ^= 1;
    let tampered = SealedStorageRecord::from_bytes(ciphertext)?;
    assert_eq!(
        open_storage_record(
            &key,
            &StorageNonce::from_reserved_bytes(nonce_bytes),
            9,
            &stored_key,
            &tampered,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );

    let sealed = SealedStorageRecord::from_bytes(decode_hex(field(vector, "ciphertext")?)?)?;
    assert_eq!(
        open_storage_record(
            &key,
            &StorageNonce::from_reserved_bytes([0x26; 24]),
            9,
            &stored_key,
            &sealed,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        open_storage_record(
            &key,
            &StorageNonce::from_reserved_bytes(nonce_bytes),
            8,
            &stored_key,
            &sealed,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        open_storage_record(
            &key,
            &StorageNonce::from_reserved_bytes(nonce_bytes),
            9,
            b"substituted database key",
            &sealed,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let wrong_generation = derive_storage_record_key(&master, storage_binding(), table, 8)?;
    assert_eq!(
        open_storage_record(
            &wrong_generation,
            &StorageNonce::from_reserved_bytes(nonce_bytes),
            9,
            &stored_key,
            &sealed,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    Ok(())
}

#[test]
fn immutable_strict_ed25519_vector_matches_and_rejects_substitution()
-> Result<(), Box<dyn core::error::Error>> {
    let vector = record("VEC-S04-005-ED25519")?;
    let content = decode_hex(field(vector, "content")?)?;
    let secret = Ed25519SecretKey::from_bytes(fixed(vector, "seed")?);
    let public = Ed25519PublicKey::from_bytes(fixed(vector, "public")?)?;
    let expected = Ed25519Signature::from_bytes(fixed(vector, "signature")?);
    assert_eq!(secret.public_key(), public);
    assert_eq!(
        sign_canonical(&secret, SignatureDomain::AccountCreationInvite, &content)?,
        expected
    );
    verify_canonical(
        public,
        SignatureDomain::AccountCreationInvite,
        &content,
        expected,
    )?;
    assert_eq!(
        verify_canonical(public, SignatureDomain::FederationHello, &content, expected).err(),
        Some(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        verify_canonical(
            public,
            SignatureDomain::AccountCreationInvite,
            b"substituted content",
            expected,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let mut tampered = *expected.as_bytes();
    let first = tampered
        .first_mut()
        .ok_or_else(|| vector_error("signature is empty"))?;
    *first ^= 1;
    assert_eq!(
        verify_canonical(
            public,
            SignatureDomain::AccountCreationInvite,
            &content,
            Ed25519Signature::from_bytes(tampered),
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let substituted_public = Ed25519SecretKey::from_bytes([0x31; 32]).public_key();
    assert_eq!(
        verify_canonical(
            substituted_public,
            SignatureDomain::AccountCreationInvite,
            &content,
            expected,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let noncanonical_signature = Ed25519Signature::from_bytes([0xff; 64]);
    assert_eq!(
        verify_canonical(
            public,
            SignatureDomain::AccountCreationInvite,
            &content,
            noncanonical_signature,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct ReferenceHpkeBinding {
    network: [u8; 32],
    epoch: [u8; 16],
    key_id: [u8; 32],
    request_id: [u8; 16],
    request_kind: u16,
    response_kind: u16,
}

fn reference_hpke_binding(vector: &str) -> Result<ReferenceHpkeBinding, io::Error> {
    Ok(ReferenceHpkeBinding {
        network: fixed(vector, "network")?,
        epoch: fixed(vector, "epoch")?,
        key_id: fixed(vector, "key_id")?,
        request_id: fixed(vector, "request_id")?,
        request_kind: u16::from_str_radix(field(vector, "request_kind")?, 16)
            .map_err(|_| vector_error("request kind is not hexadecimal"))?,
        response_kind: u16::from_str_radix(field(vector, "response_kind")?, 16)
            .map_err(|_| vector_error("response kind is not hexadecimal"))?,
    })
}

fn reference_request_info(binding: ReferenceHpkeBinding) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(REQUEST_INFO_LABEL);
    info.extend_from_slice(&binding.epoch);
    info.extend_from_slice(&1_u16.to_be_bytes());
    info.extend_from_slice(&binding.network);
    info.extend_from_slice(&binding.key_id);
    info.extend_from_slice(&binding.request_id);
    info.extend_from_slice(&binding.request_kind.to_be_bytes());
    info
}

fn reference_response_context(
    label: &[u8],
    binding: ReferenceHpkeBinding,
    salt: &[u8; 32],
) -> Vec<u8> {
    let mut context = Vec::new();
    context.extend_from_slice(label);
    context.extend_from_slice(&binding.epoch);
    context.extend_from_slice(salt);
    context
}

fn reference_response_aad(binding: ReferenceHpkeBinding, salt: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(RESPONSE_AAD_LABEL);
    aad.extend_from_slice(&1_u16.to_be_bytes());
    aad.extend_from_slice(&binding.network);
    aad.extend_from_slice(&binding.key_id);
    aad.extend_from_slice(&binding.request_id);
    aad.extend_from_slice(&binding.response_kind.to_be_bytes());
    aad.extend_from_slice(salt);
    aad
}

fn reference_open_response(
    vector: &str,
    binding: ReferenceHpkeBinding,
    salt: [u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
    let private =
        <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&fixed::<32>(vector, "private")?)?;
    let encapsulated = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&fixed::<32>(
        vector,
        "encapsulated",
    )?)?;
    let receiver = setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private,
        &encapsulated,
        &reference_request_info(binding),
    )?;
    let mut key = [0_u8; 32];
    let mut nonce = [0_u8; 12];
    receiver.export(
        &reference_response_context(RESPONSE_KEY_LABEL, binding, &salt),
        &mut key,
    )?;
    receiver.export(
        &reference_response_context(RESPONSE_NONCE_LABEL, binding, &salt),
        &mut nonce,
    )?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
    Ok(cipher.decrypt(
        &Nonce::from(nonce),
        Payload {
            msg: ciphertext,
            aad: &reference_response_aad(binding, &salt),
        },
    )?)
}

fn production_binding(binding: ReferenceHpkeBinding) -> AccountRequestBinding {
    AccountRequestBinding::new(
        NetworkId::from_bytes(binding.network),
        RecoveryEpoch::from_bytes(binding.epoch),
        AccountHpkeKeyId::from_bytes(binding.key_id),
        RequestId::from_bytes(binding.request_id),
        AccountServiceMessageKind::OpaqueAuthStart,
    )
}

#[test]
fn immutable_hpke_request_response_and_exporter_vectors_match()
-> Result<(), Box<dyn core::error::Error>> {
    let vector = record("VEC-S04-006-HPKE")?;
    let binding = reference_hpke_binding(vector)?;
    assert_eq!(binding.request_kind, 3);
    assert_eq!(binding.response_kind, 2);
    let private = AccountHpkePrivateKey::from_bytes(fixed(vector, "private")?)?;
    assert_eq!(
        private.public_key()?.as_bytes(),
        &fixed::<32>(vector, "public")?
    );
    assert_eq!(private.public_key()?.key_id().as_bytes(), &binding.key_id);
    let encapsulated = fixed(vector, "encapsulated")?;
    let ciphertext = fixed(vector, "request_ciphertext")?;
    let (opened, response_token) = open_account_request(
        &private,
        production_binding(binding),
        &encapsulated,
        &ciphertext,
    )?;
    assert_eq!(
        opened.expose_for_account_parser(),
        &fixed::<4_592>(vector, "request_plaintext")?
    );
    let response_ciphertext = decode_hex(field(vector, "response_ciphertext")?)?;
    let response_salt = fixed(vector, "response_salt")?;
    let response_plaintext =
        fixed::<ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES>(vector, "response_plaintext")?;
    let sealed_response = response_token.seal_response_with_salt(
        0,
        AccountServiceResponseKind::OpaqueAuthChallenge,
        response_salt,
        &response_plaintext,
    )?;
    assert_eq!(
        sealed_response.ciphertext().as_slice(),
        response_ciphertext.as_slice()
    );
    assert_eq!(sealed_response.response_salt(), &response_salt);
    assert_eq!(sealed_response.next_response_count(), 1);
    let private_reference =
        <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&fixed::<32>(vector, "private")?)?;
    let encapsulated_reference = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(
        &fixed::<32>(vector, "encapsulated")?,
    )?;
    let receiver = setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private_reference,
        &encapsulated_reference,
        &reference_request_info(binding),
    )?;
    let mut response_key = [0_u8; 32];
    let mut response_nonce = [0_u8; 12];
    receiver.export(
        &reference_response_context(RESPONSE_KEY_LABEL, binding, &response_salt),
        &mut response_key,
    )?;
    receiver.export(
        &reference_response_context(RESPONSE_NONCE_LABEL, binding, &response_salt),
        &mut response_nonce,
    )?;
    assert_eq!(response_key, fixed::<32>(vector, "response_key")?);
    assert_eq!(response_nonce, fixed::<12>(vector, "response_nonce")?);
    assert_eq!(
        reference_open_response(vector, binding, response_salt, &response_ciphertext)?,
        decode_hex(field(vector, "response_plaintext")?)?
    );
    assert_eq!(decode_hex(field(vector, "request_envelope")?)?.len(), 4_726);
    assert_eq!(
        decode_hex(field(vector, "response_envelope")?)?.len(),
        4_342
    );
    Ok(())
}

#[test]
fn immutable_hpke_vector_rejects_binding_substitution_and_tamper()
-> Result<(), Box<dyn core::error::Error>> {
    let vector = record("VEC-S04-006-HPKE")?;
    let original = reference_hpke_binding(vector)?;
    let private = AccountHpkePrivateKey::from_bytes(fixed(vector, "private")?)?;
    let encapsulated = fixed(vector, "encapsulated")?;
    let ciphertext = fixed(vector, "request_ciphertext")?;

    let mut substituted = original;
    substituted.network = [0x60; 32];
    assert_eq!(
        open_account_request(
            &private,
            production_binding(substituted),
            &encapsulated,
            &ciphertext,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    substituted = original;
    substituted.epoch = [0x61; 16];
    assert_eq!(
        open_account_request(
            &private,
            production_binding(substituted),
            &encapsulated,
            &ciphertext,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    substituted = original;
    substituted.key_id = [0x62; 32];
    assert_eq!(
        open_account_request(
            &private,
            production_binding(substituted),
            &encapsulated,
            &ciphertext,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    substituted = original;
    substituted.request_id = [0x63; 16];
    assert_eq!(
        open_account_request(
            &private,
            production_binding(substituted),
            &encapsulated,
            &ciphertext,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let kind_substitution = AccountRequestBinding::new(
        NetworkId::from_bytes(original.network),
        RecoveryEpoch::from_bytes(original.epoch),
        AccountHpkeKeyId::from_bytes(original.key_id),
        RequestId::from_bytes(original.request_id),
        AccountServiceMessageKind::OpaqueAuthFinish,
    );
    assert_eq!(
        open_account_request(&private, kind_substitution, &encapsulated, &ciphertext).err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let mut tampered_encapsulated = encapsulated;
    let first = tampered_encapsulated
        .first_mut()
        .ok_or_else(|| vector_error("HPKE encapsulated key is empty"))?;
    *first ^= 1;
    assert_eq!(
        open_account_request(
            &private,
            production_binding(original),
            &tampered_encapsulated,
            &ciphertext,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );
    let mut tampered_ciphertext = ciphertext;
    let first = tampered_ciphertext
        .first_mut()
        .ok_or_else(|| vector_error("HPKE ciphertext is empty"))?;
    *first ^= 1;
    assert_eq!(
        open_account_request(
            &private,
            production_binding(original),
            &encapsulated,
            &tampered_ciphertext,
        )
        .err(),
        Some(CryptoError::AuthenticationFailed)
    );

    let response_ciphertext = decode_hex(field(vector, "response_ciphertext")?)?;
    let response_salt = fixed(vector, "response_salt")?;
    substituted = original;
    substituted.response_kind = 3;
    assert!(
        reference_open_response(vector, substituted, response_salt, &response_ciphertext).is_err()
    );
    substituted = original;
    substituted.request_id = [0x64; 16];
    assert!(
        reference_open_response(vector, substituted, response_salt, &response_ciphertext).is_err()
    );
    let mut wrong_salt = response_salt;
    let first = wrong_salt
        .first_mut()
        .ok_or_else(|| vector_error("response salt is empty"))?;
    *first ^= 1;
    assert!(reference_open_response(vector, original, wrong_salt, &response_ciphertext).is_err());
    let mut tampered_response = response_ciphertext;
    let first = tampered_response
        .first_mut()
        .ok_or_else(|| vector_error("response ciphertext is empty"))?;
    *first ^= 1;
    assert!(reference_open_response(vector, original, response_salt, &tampered_response).is_err());
    Ok(())
}
