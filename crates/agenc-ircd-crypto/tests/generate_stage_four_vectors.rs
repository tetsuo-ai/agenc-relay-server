#![forbid(unsafe_code)]

//! Manual reference generator for the checked-in Stage-04 crypto vectors.
//!
//! This target calls the pinned primitive crates directly. It does not call an
//! `agenc-ircd-crypto` adapter when it computes an expected value. The test is
//! ignored so ordinary test runs only consume the checked-in output.

use std::fmt::Write as _;
use std::io;

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer as _, SigningKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as _};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::{Kem as _, X25519HkdfSha256};
use hpke::{
    Deserializable as _, OpModeR, OpModeS, Serializable as _, setup_receiver, setup_sender_with_rng,
};
use sha2::{Digest as _, Sha256};

const PROFILE_VERSION: u16 = 1;
const REQUEST_PLAINTEXT_BYTES: usize = 4_592;
const RESPONSE_PLAINTEXT_BYTES: usize = 4_208;
const REQUEST_CIPHERTEXT_BYTES: usize = 4_608;
const RESPONSE_CIPHERTEXT_BYTES: usize = 4_224;

const LOGIN_INDEX_LABEL: &[u8] = b"agenc-chat login index v1";
const FAKE_CREDENTIAL_LABEL: &[u8] = b"agenc-chat fake opaque credential id v1";
const STORAGE_SALT_LABEL: &[u8] = b"agenc-chat storage salt v1";
const STORAGE_RECORD_KEY_LABEL: &[u8] = b"agenc-chat storage record key v1";
const STORAGE_INDEX_KEY_LABEL: &[u8] = b"agenc-chat storage table index key v1";
const SEALED_RECORD_LABEL: &[u8] = b"agenc-chat sealed record v1";
const SIGNATURE_LABEL: &[u8] = b"agenc-chat account creation invite v1";
const HPKE_KEY_ID_LABEL: &[u8] = b"agenc-chat account service hpke key v1";
const REQUEST_INFO_LABEL: &[u8] = b"agenc-chat account service hpke request v1";
const REQUEST_AAD_LABEL: &[u8] = b"agenc-chat account service request aad v1";
const RESPONSE_KEY_LABEL: &[u8] = b"agenc-chat account service response key v1";
const RESPONSE_NONCE_LABEL: &[u8] = b"agenc-chat account service response nonce v1";
const RESPONSE_AAD_LABEL: &[u8] = b"agenc-chat account service response aad v1";

const DATABASE_MAGIC: &[u8; 16] = b"AGENC-IRCD-DB\0\0\0";
const DATABASE_FORMAT: u16 = 1;

type ReferenceSender = hpke::aead::AeadCtxS<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>;

struct FixedHpkeRng {
    bytes: [u8; 32],
    used: bool,
    invalid_usage: bool,
}

impl FixedHpkeRng {
    const fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            used: false,
            invalid_usage: false,
        }
    }
}

impl hpke::rand_core::TryRng for FixedHpkeRng {
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
        destination.copy_from_slice(&self.bytes);
        self.used = true;
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for FixedHpkeRng {}

#[derive(Clone, Copy)]
struct HpkeBinding {
    network_id: [u8; 32],
    recovery_epoch: [u8; 16],
    key_id: [u8; 32],
    request_id: [u8; 16],
    request_kind: u16,
    response_kind: u16,
}

struct HpkeVector {
    binding: HpkeBinding,
    private_key: [u8; 32],
    public_key: [u8; 32],
    ephemeral_input: [u8; 32],
    encapsulated_key: [u8; 32],
    request_plaintext: [u8; REQUEST_PLAINTEXT_BYTES],
    request_ciphertext: [u8; REQUEST_CIPHERTEXT_BYTES],
    response_salt: [u8; 32],
    response_key: [u8; 32],
    response_nonce: [u8; 12],
    response_plaintext: [u8; RESPONSE_PLAINTEXT_BYTES],
    response_ciphertext: [u8; RESPONSE_CIPHERTEXT_BYTES],
    request_envelope: Vec<u8>,
    response_envelope: Vec<u8>,
    request_below_min_plaintext: [u8; REQUEST_PLAINTEXT_BYTES],
    request_max_plaintext: [u8; REQUEST_PLAINTEXT_BYTES],
    request_above_max_plaintext: [u8; REQUEST_PLAINTEXT_BYTES],
    response_below_min_plaintext: [u8; RESPONSE_PLAINTEXT_BYTES],
    response_max_plaintext: [u8; RESPONSE_PLAINTEXT_BYTES],
    response_above_max_plaintext: [u8; RESPONSE_PLAINTEXT_BYTES],
    nonzero_padding_ephemeral_input: [u8; 32],
    nonzero_padding_encapsulated_key: [u8; 32],
    nonzero_padding_ciphertext: [u8; REQUEST_CIPHERTEXT_BYTES],
    nonzero_padding_request_envelope: Vec<u8>,
}

struct StorageVector {
    binding: Vec<u8>,
    record_key: [u8; 32],
    index_key: [u8; 32],
    index: [u8; 32],
    ciphertext: Vec<u8>,
}

fn reference_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn lowercase_hex(bytes: &[u8]) -> Result<String, io::Error> {
    let capacity = bytes
        .len()
        .checked_mul(2)
        .ok_or_else(|| reference_error("hex capacity overflow"))?;
    let mut encoded = String::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| reference_error("hex allocation failed"))?;
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").map_err(|_| reference_error("hex formatting failed"))?;
    }
    Ok(encoded)
}

fn sha256_hex(bytes: &[u8]) -> Result<String, io::Error> {
    lowercase_hex(&Sha256::digest(bytes))
}

fn database_binding() -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(DATABASE_MAGIC);
    encoded.extend_from_slice(&DATABASE_FORMAT.to_be_bytes());
    encoded.extend_from_slice(&[0x21; 32]);
    encoded.extend_from_slice(&[0x22; 16]);
    encoded.extend_from_slice(&[0x23; 16]);
    encoded.extend_from_slice(&[0x24; 16]);
    encoded
}

fn storage_subkey(
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
        .map_err(|_| reference_error("storage HKDF expansion failed"))?;
    Ok(output)
}

fn storage_vector() -> Result<StorageVector, io::Error> {
    let master_key = [0x20; 32];
    let binding = database_binding();
    let record_key = storage_subkey(&master_key, &binding, STORAGE_RECORD_KEY_LABEL)?;
    let index_key = storage_subkey(&master_key, &binding, STORAGE_INDEX_KEY_LABEL)?;
    let semantic_key = b"stage-four/storage/key";
    let mut index_mac = Hmac::<Sha256>::new_from_slice(&index_key)
        .map_err(|_| reference_error("storage index HMAC rejected its key"))?;
    index_mac.update(semantic_key);
    let index: [u8; 32] = index_mac.finalize().into_bytes().into();

    let stored_database_key = b"stage-four/stored/database-key";
    let plaintext = b"stage-four fixed storage plaintext";
    let mut aad = Vec::new();
    aad.extend_from_slice(SEALED_RECORD_LABEL);
    aad.extend_from_slice(&binding);
    aad.extend_from_slice(&3_u16.to_be_bytes());
    aad.extend_from_slice(&9_u32.to_be_bytes());
    aad.extend_from_slice(&7_u32.to_be_bytes());
    aad.extend_from_slice(&Sha256::digest(stored_database_key));
    let cipher = XChaCha20Poly1305::new_from_slice(&record_key)
        .map_err(|_| reference_error("XChaCha20-Poly1305 rejected its key"))?;
    let nonce = XNonce::from([0x25; 24]);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| reference_error("XChaCha20-Poly1305 reference seal failed"))?;
    Ok(StorageVector {
        binding,
        record_key,
        index_key,
        index,
        ciphertext,
    })
}

fn request_info(binding: HpkeBinding) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(REQUEST_INFO_LABEL);
    info.extend_from_slice(&binding.recovery_epoch);
    info.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    info.extend_from_slice(&binding.network_id);
    info.extend_from_slice(&binding.key_id);
    info.extend_from_slice(&binding.request_id);
    info.extend_from_slice(&binding.request_kind.to_be_bytes());
    info
}

fn request_aad(binding: HpkeBinding, encapsulated_key: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(REQUEST_AAD_LABEL);
    aad.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    aad.extend_from_slice(&binding.network_id);
    aad.extend_from_slice(&binding.key_id);
    aad.extend_from_slice(&binding.request_id);
    aad.extend_from_slice(&binding.request_kind.to_be_bytes());
    aad.extend_from_slice(encapsulated_key);
    aad
}

fn response_export_context(label: &[u8], binding: HpkeBinding, salt: &[u8; 32]) -> Vec<u8> {
    let mut context = Vec::new();
    context.extend_from_slice(label);
    context.extend_from_slice(&binding.recovery_epoch);
    context.extend_from_slice(salt);
    context
}

fn response_aad(binding: HpkeBinding, salt: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(RESPONSE_AAD_LABEL);
    aad.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    aad.extend_from_slice(&binding.network_id);
    aad.extend_from_slice(&binding.key_id);
    aad.extend_from_slice(&binding.request_id);
    aad.extend_from_slice(&binding.response_kind.to_be_bytes());
    aad.extend_from_slice(salt);
    aad
}

fn padded_plaintext<const SIZE: usize>(
    payload_bytes: usize,
    fill: u8,
) -> Result<[u8; SIZE], io::Error> {
    let padding_base = SIZE
        .checked_sub(6)
        .ok_or_else(|| reference_error("padded plaintext size is too small"))?;
    let padding_bytes = padding_base
        .checked_sub(payload_bytes)
        .ok_or_else(|| reference_error("padded payload is too large"))?;
    let payload_length = u16::try_from(payload_bytes)
        .map_err(|_| reference_error("padded payload length does not fit u16"))?;
    let padding_length = u16::try_from(padding_bytes)
        .map_err(|_| reference_error("padding length does not fit u16"))?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&payload_length.to_be_bytes());
    encoded.resize(
        encoded
            .len()
            .checked_add(payload_bytes)
            .ok_or_else(|| reference_error("payload resize overflow"))?,
        fill,
    );
    encoded.extend_from_slice(&padding_length.to_be_bytes());
    encoded.resize(SIZE, 0);
    encoded
        .try_into()
        .map_err(|_| reference_error("padded plaintext length mismatch"))
}

fn setup_sender(
    public_key: &<X25519HkdfSha256 as hpke::Kem>::PublicKey,
    binding: HpkeBinding,
    ephemeral_input: [u8; 32],
) -> Result<([u8; 32], ReferenceSender), io::Error> {
    let mut rng = FixedHpkeRng::new(ephemeral_input);
    let (encapsulated_key, context) =
        setup_sender_with_rng::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            public_key,
            &request_info(binding),
            &mut rng,
        )
        .map_err(|_| reference_error("HPKE sender setup failed"))?;
    if rng.invalid_usage || !rng.used {
        return Err(reference_error("HPKE sender used an unexpected RNG shape"));
    }
    Ok((encapsulated_key.to_bytes().into(), context))
}

fn hpke_vector() -> Result<HpkeVector, io::Error> {
    let private_key = [0x40; 32];
    let private = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&private_key)
        .map_err(|_| reference_error("HPKE private key is invalid"))?;
    let public = X25519HkdfSha256::sk_to_pk(&private);
    let public_key: [u8; 32] = public.to_bytes().into();
    let mut key_id_hash = Sha256::new();
    key_id_hash.update(HPKE_KEY_ID_LABEL);
    key_id_hash.update(public_key);
    let binding = HpkeBinding {
        network_id: [0x41; 32],
        recovery_epoch: [0x42; 16],
        key_id: key_id_hash.finalize().into(),
        request_id: [0x43; 16],
        request_kind: 3,
        response_kind: 2,
    };
    let ephemeral_input = [0x44; 32];
    let (encapsulated_key, mut sender) = setup_sender(&public, binding, ephemeral_input)?;
    let request_plaintext = padded_plaintext::<REQUEST_PLAINTEXT_BYTES>(72, 0x45)?;
    let request_ciphertext: [u8; REQUEST_CIPHERTEXT_BYTES] = sender
        .seal(&request_plaintext, &request_aad(binding, &encapsulated_key))
        .map_err(|_| reference_error("HPKE request seal failed"))?
        .try_into()
        .map_err(|_| reference_error("HPKE request ciphertext length mismatch"))?;

    let receiver = setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private,
        &<X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&encapsulated_key)
            .map_err(|_| reference_error("HPKE encapsulated key is invalid"))?,
        &request_info(binding),
    )
    .map_err(|_| reference_error("HPKE receiver setup failed"))?;
    let response_salt = [0x46; 32];
    let mut response_key = [0_u8; 32];
    let mut response_nonce = [0_u8; 12];
    sender
        .export(
            &response_export_context(RESPONSE_KEY_LABEL, binding, &response_salt),
            &mut response_key,
        )
        .map_err(|_| reference_error("HPKE sender response-key export failed"))?;
    sender
        .export(
            &response_export_context(RESPONSE_NONCE_LABEL, binding, &response_salt),
            &mut response_nonce,
        )
        .map_err(|_| reference_error("HPKE sender response-nonce export failed"))?;
    let mut receiver_key = [0_u8; 32];
    receiver
        .export(
            &response_export_context(RESPONSE_KEY_LABEL, binding, &response_salt),
            &mut receiver_key,
        )
        .map_err(|_| reference_error("HPKE receiver response-key export failed"))?;
    if receiver_key != response_key {
        return Err(reference_error("HPKE exporter contexts disagree"));
    }
    let response_plaintext = padded_plaintext::<RESPONSE_PLAINTEXT_BYTES>(52, 0x47)?;
    let response_cipher = ChaCha20Poly1305::new_from_slice(&response_key)
        .map_err(|_| reference_error("response cipher rejected exporter key"))?;
    let response_ciphertext: [u8; RESPONSE_CIPHERTEXT_BYTES] = response_cipher
        .encrypt(
            &Nonce::from(response_nonce),
            Payload {
                msg: &response_plaintext,
                aad: &response_aad(binding, &response_salt),
            },
        )
        .map_err(|_| reference_error("response reference seal failed"))?
        .try_into()
        .map_err(|_| reference_error("response ciphertext length mismatch"))?;

    let mut request_envelope = Vec::new();
    request_envelope.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    request_envelope.extend_from_slice(&binding.network_id);
    request_envelope.extend_from_slice(&binding.key_id);
    request_envelope.extend_from_slice(&binding.request_id);
    request_envelope.extend_from_slice(&binding.request_kind.to_be_bytes());
    request_envelope.extend_from_slice(&encapsulated_key);
    request_envelope.extend_from_slice(
        &u16::try_from(REQUEST_CIPHERTEXT_BYTES)
            .map_err(|_| reference_error("request ciphertext length does not fit u16"))?
            .to_be_bytes(),
    );
    request_envelope.extend_from_slice(&request_ciphertext);

    let mut response_envelope = Vec::new();
    response_envelope.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    response_envelope.extend_from_slice(&binding.network_id);
    response_envelope.extend_from_slice(&binding.key_id);
    response_envelope.extend_from_slice(&binding.request_id);
    response_envelope.extend_from_slice(&binding.response_kind.to_be_bytes());
    response_envelope.extend_from_slice(&response_salt);
    response_envelope.extend_from_slice(
        &u16::try_from(RESPONSE_CIPHERTEXT_BYTES)
            .map_err(|_| reference_error("response ciphertext length does not fit u16"))?
            .to_be_bytes(),
    );
    response_envelope.extend_from_slice(&response_ciphertext);

    let nonzero_padding_ephemeral_input = [0x48; 32];
    let (nonzero_padding_encapsulated_key, mut invalid_sender) =
        setup_sender(&public, binding, nonzero_padding_ephemeral_input)?;
    let mut nonzero_padding_plaintext = request_plaintext;
    let last = nonzero_padding_plaintext
        .last_mut()
        .ok_or_else(|| reference_error("request plaintext is empty"))?;
    *last = 1;
    let nonzero_padding_ciphertext: [u8; REQUEST_CIPHERTEXT_BYTES] = invalid_sender
        .seal(
            &nonzero_padding_plaintext,
            &request_aad(binding, &nonzero_padding_encapsulated_key),
        )
        .map_err(|_| reference_error("nonzero-padding request seal failed"))?
        .try_into()
        .map_err(|_| reference_error("nonzero-padding ciphertext length mismatch"))?;

    let mut nonzero_padding_request_envelope = Vec::new();
    nonzero_padding_request_envelope.extend_from_slice(&PROFILE_VERSION.to_be_bytes());
    nonzero_padding_request_envelope.extend_from_slice(&binding.network_id);
    nonzero_padding_request_envelope.extend_from_slice(&binding.key_id);
    nonzero_padding_request_envelope.extend_from_slice(&binding.request_id);
    nonzero_padding_request_envelope.extend_from_slice(&binding.request_kind.to_be_bytes());
    nonzero_padding_request_envelope.extend_from_slice(&nonzero_padding_encapsulated_key);
    nonzero_padding_request_envelope.extend_from_slice(
        &u16::try_from(REQUEST_CIPHERTEXT_BYTES)
            .map_err(|_| reference_error("request ciphertext length does not fit u16"))?
            .to_be_bytes(),
    );
    nonzero_padding_request_envelope.extend_from_slice(&nonzero_padding_ciphertext);

    Ok(HpkeVector {
        binding,
        private_key,
        public_key,
        ephemeral_input,
        encapsulated_key,
        request_plaintext,
        request_ciphertext,
        response_salt,
        response_key,
        response_nonce,
        response_plaintext,
        response_ciphertext,
        request_envelope,
        response_envelope,
        request_below_min_plaintext: padded_plaintext::<REQUEST_PLAINTEXT_BYTES>(71, 0x49)?,
        request_max_plaintext: padded_plaintext::<REQUEST_PLAINTEXT_BYTES>(265, 0x4a)?,
        request_above_max_plaintext: padded_plaintext::<REQUEST_PLAINTEXT_BYTES>(266, 0x4b)?,
        response_below_min_plaintext: padded_plaintext::<RESPONSE_PLAINTEXT_BYTES>(51, 0x4c)?,
        response_max_plaintext: padded_plaintext::<RESPONSE_PLAINTEXT_BYTES>(372, 0x4d)?,
        response_above_max_plaintext: padded_plaintext::<RESPONSE_PLAINTEXT_BYTES>(373, 0x4e)?,
        nonzero_padding_ephemeral_input,
        nonzero_padding_encapsulated_key,
        nonzero_padding_ciphertext,
        nonzero_padding_request_envelope,
    })
}

#[test]
#[ignore = "manual reviewed golden-vector generation"]
fn emit_stage_four_crypto_vectors() -> Result<(), Box<dyn core::error::Error>> {
    println!("# agenc-ircd Stage-04 cryptographic vectors v1");
    println!("# generated by crates/agenc-ircd-crypto/tests/generate_stage_four_vectors.rs");
    println!("# fields are lowercase hexadecimal unless stated otherwise");

    let semantic_input = b"stage-four semantic hash input";
    let mut semantic_hash = Sha256::new();
    semantic_hash.update(b"IRC-MLS/1 policy id");
    semantic_hash.update(semantic_input);
    let semantic_expected = semantic_hash.finalize();
    println!(
        "VEC-S04-003-SHA256|semantic_hash|project-reference|domain=policy_id|input={}|expected={}|output_sha256={}",
        lowercase_hex(semantic_input)?,
        lowercase_hex(&semantic_expected)?,
        sha256_hex(&semantic_expected)?,
    );

    let login_key = [0x10; 32];
    let login_network = [0x11; 32];
    let login = b"vector-user";
    let mut login_mac = Hmac::<Sha256>::new_from_slice(&login_key)?;
    login_mac.update(LOGIN_INDEX_LABEL);
    login_mac.update(&login_network);
    login_mac.update(login);
    let login_expected = login_mac.finalize().into_bytes();
    println!(
        "VEC-S04-003-LOGIN-HMAC|login_hmac|project-reference|key={}|network={}|login={}|expected={}|output_sha256={}",
        lowercase_hex(&login_key)?,
        lowercase_hex(&login_network)?,
        lowercase_hex(login)?,
        lowercase_hex(&login_expected)?,
        sha256_hex(&login_expected)?,
    );

    let fake_key = [0x12; 32];
    let mut fake_mac = Hmac::<Sha256>::new_from_slice(&fake_key)?;
    fake_mac.update(FAKE_CREDENTIAL_LABEL);
    fake_mac.update(&login_network);
    fake_mac.update(login);
    let fake_expected = fake_mac.finalize().into_bytes();
    println!(
        "VEC-S04-003-FAKE-HMAC|fake_credential_hmac|project-reference|key={}|network={}|login={}|expected={}|output_sha256={}",
        lowercase_hex(&fake_key)?,
        lowercase_hex(&login_network)?,
        lowercase_hex(login)?,
        lowercase_hex(&fake_expected)?,
        sha256_hex(&fake_expected)?,
    );

    let storage = storage_vector()?;
    let mut storage_outputs = Vec::new();
    storage_outputs.extend_from_slice(&storage.record_key);
    storage_outputs.extend_from_slice(&storage.index_key);
    storage_outputs.extend_from_slice(&storage.index);
    storage_outputs.extend_from_slice(&storage.ciphertext);
    println!(
        "VEC-S04-003-004-STORAGE|storage_xchacha_hkdf_hmac|project-reference|master={}|binding={}|table=0003|generation=00000007|schema=00000009|semantic_key={}|stored_key={}|nonce={}|plaintext={}|record_key={}|index_key={}|index={}|ciphertext={}|output_sha256={}",
        lowercase_hex(&[0x20; 32])?,
        lowercase_hex(&storage.binding)?,
        lowercase_hex(b"stage-four/storage/key")?,
        lowercase_hex(b"stage-four/stored/database-key")?,
        lowercase_hex(&[0x25; 24])?,
        lowercase_hex(b"stage-four fixed storage plaintext")?,
        lowercase_hex(&storage.record_key)?,
        lowercase_hex(&storage.index_key)?,
        lowercase_hex(&storage.index)?,
        lowercase_hex(&storage.ciphertext)?,
        sha256_hex(&storage_outputs)?,
    );

    let signing_seed = [0x30; 32];
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let signature_content = b"stage-four strict signature input";
    let mut signature_input = Vec::new();
    signature_input.extend_from_slice(SIGNATURE_LABEL);
    signature_input.extend_from_slice(signature_content);
    let signature = signing_key.sign(&signature_input).to_bytes();
    println!(
        "VEC-S04-005-ED25519|ed25519_strict|project-reference|seed={}|public={}|domain=account_creation_invite|content={}|signature={}|output_sha256={}",
        lowercase_hex(&signing_seed)?,
        lowercase_hex(&signing_key.verifying_key().to_bytes())?,
        lowercase_hex(signature_content)?,
        lowercase_hex(&signature)?,
        sha256_hex(&signature)?,
    );

    let hpke = hpke_vector()?;
    let mut hpke_outputs = Vec::new();
    hpke_outputs.extend_from_slice(&hpke.encapsulated_key);
    hpke_outputs.extend_from_slice(&hpke.request_ciphertext);
    hpke_outputs.extend_from_slice(&hpke.response_salt);
    hpke_outputs.extend_from_slice(&hpke.response_key);
    hpke_outputs.extend_from_slice(&hpke.response_nonce);
    hpke_outputs.extend_from_slice(&hpke.response_ciphertext);
    println!(
        "VEC-S04-006-HPKE|hpke_request_response|project-reference|private={}|public={}|network={}|epoch={}|key_id={}|request_id={}|request_kind={:04x}|response_kind={:04x}|ephemeral_input={}|encapsulated={}|request_plaintext={}|request_ciphertext={}|response_salt={}|response_key={}|response_nonce={}|response_plaintext={}|response_ciphertext={}|request_envelope={}|response_envelope={}|request_below_min_plaintext={}|request_max_plaintext={}|request_above_max_plaintext={}|response_below_min_plaintext={}|response_max_plaintext={}|response_above_max_plaintext={}|nonzero_padding_ephemeral_input={}|nonzero_padding_encapsulated={}|nonzero_padding_ciphertext={}|nonzero_padding_request_envelope={}|output_sha256={}",
        lowercase_hex(&hpke.private_key)?,
        lowercase_hex(&hpke.public_key)?,
        lowercase_hex(&hpke.binding.network_id)?,
        lowercase_hex(&hpke.binding.recovery_epoch)?,
        lowercase_hex(&hpke.binding.key_id)?,
        lowercase_hex(&hpke.binding.request_id)?,
        hpke.binding.request_kind,
        hpke.binding.response_kind,
        lowercase_hex(&hpke.ephemeral_input)?,
        lowercase_hex(&hpke.encapsulated_key)?,
        lowercase_hex(&hpke.request_plaintext)?,
        lowercase_hex(&hpke.request_ciphertext)?,
        lowercase_hex(&hpke.response_salt)?,
        lowercase_hex(&hpke.response_key)?,
        lowercase_hex(&hpke.response_nonce)?,
        lowercase_hex(&hpke.response_plaintext)?,
        lowercase_hex(&hpke.response_ciphertext)?,
        lowercase_hex(&hpke.request_envelope)?,
        lowercase_hex(&hpke.response_envelope)?,
        lowercase_hex(&hpke.request_below_min_plaintext)?,
        lowercase_hex(&hpke.request_max_plaintext)?,
        lowercase_hex(&hpke.request_above_max_plaintext)?,
        lowercase_hex(&hpke.response_below_min_plaintext)?,
        lowercase_hex(&hpke.response_max_plaintext)?,
        lowercase_hex(&hpke.response_above_max_plaintext)?,
        lowercase_hex(&hpke.nonzero_padding_ephemeral_input)?,
        lowercase_hex(&hpke.nonzero_padding_encapsulated_key)?,
        lowercase_hex(&hpke.nonzero_padding_ciphertext)?,
        lowercase_hex(&hpke.nonzero_padding_request_envelope)?,
        sha256_hex(&hpke_outputs)?,
    );
    Ok(())
}
