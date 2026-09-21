#![forbid(unsafe_code)]

//! Manual reference generator for the checked-in Stage-04 OPAQUE vectors.
//!
//! This target calls the pinned `opaque-ke` and Argon2 crates directly. It
//! does not call an `agenc-relay-auth` adapter when it computes expected bytes.
//! The target is ignored so ordinary test runs only consume immutable input.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io;

use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::errors::InternalError;
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::rand::{CryptoRng, Error as RandError, RngCore};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup, TripleDh,
};
use opaque_sha2::{Digest as _, Sha256, Sha512};

const SERVER_SETUP_BYTES: usize = 128;
const REGISTRATION_REQUEST_BYTES: usize = 32;
const REGISTRATION_RESPONSE_BYTES: usize = 64;
const REGISTRATION_RECORD_BYTES: usize = 192;
const KE1_BYTES: usize = 96;
const KE2_BYTES: usize = 320;
const KE3_BYTES: usize = 64;
const SERVER_LOGIN_STATE_BYTES: usize = 128;

const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 4;
const ARGON2_OUTPUT_BYTES: usize = 64;
const ARGON2_SALT: [u8; 16] = [0_u8; 16];
const OPAQUE_CONTEXT_LABEL: &[u8] = b"agenc-chat account authentication v1";
const DUMMY_CLIENT_PASSWORD: &[u8] = b"agenc-chat internal dummy OPAQUE client v1";

struct ReferenceOpaqueSuite;

impl CipherSuite for ReferenceOpaqueSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, opaque_sha2::Sha512>;
    type Ksf = ReferenceArgon2id;
}

#[derive(Default)]
struct ReferenceArgon2id;

impl Ksf for ReferenceArgon2id {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        if input.len() != ARGON2_OUTPUT_BYTES {
            return Err(InternalError::KsfError);
        }
        let parameters = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_LANES,
            Some(ARGON2_OUTPUT_BYTES),
        )
        .map_err(|_| InternalError::KsfError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
        let mut output = GenericArray::default();
        argon2
            .hash_password_into(&input, &ARGON2_SALT, &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

/// SHA-512 counter stream used only to make this manual generator repeatable.
struct ReferenceRng {
    seed: [u8; 32],
    counter: u64,
    buffered: VecDeque<u8>,
    failed: bool,
}

impl ReferenceRng {
    fn new(seed: u8) -> Self {
        Self {
            seed: [seed; 32],
            counter: 0,
            buffered: VecDeque::new(),
            failed: false,
        }
    }

    const fn succeeded(&self) -> bool {
        !self.failed
    }

    fn refill(&mut self) {
        let Some(next_counter) = self.counter.checked_add(1) else {
            self.failed = true;
            return;
        };
        let mut digest = Sha512::new();
        digest.update(b"arcd Stage-04 OPAQUE vector RNG v1");
        digest.update(self.seed);
        digest.update(self.counter.to_be_bytes());
        self.buffered.extend(digest.finalize());
        self.counter = next_counter;
    }

    fn next_byte(&mut self) -> u8 {
        if self.buffered.is_empty() {
            self.refill();
        }
        self.buffered.pop_front().unwrap_or_default()
    }
}

impl RngCore for ReferenceRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for byte in destination {
            *byte = self.next_byte();
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for ReferenceRng {}

struct OpaqueVector {
    setup: [u8; SERVER_SETUP_BYTES],
    fake_record: [u8; REGISTRATION_RECORD_BYTES],
    registration_request: [u8; REGISTRATION_REQUEST_BYTES],
    registration_response: [u8; REGISTRATION_RESPONSE_BYTES],
    registration_upload: [u8; REGISTRATION_RECORD_BYTES],
    registration_record: [u8; REGISTRATION_RECORD_BYTES],
    ke1: [u8; KE1_BYTES],
    ke2: [u8; KE2_BYTES],
    ke3: [u8; KE3_BYTES],
    server_login_state: [u8; SERVER_LOGIN_STATE_BYTES],
    session_key: [u8; 64],
    fake_ke1: [u8; KE1_BYTES],
    fake_ke2: [u8; KE2_BYTES],
    fake_server_login_state: [u8; SERVER_LOGIN_STATE_BYTES],
    dummy_ke1: [u8; KE1_BYTES],
    dummy_ke2: [u8; KE2_BYTES],
    dummy_server_login_state: [u8; SERVER_LOGIN_STATE_BYTES],
    dummy_ke3: [u8; KE3_BYTES],
}

fn reference_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn fixed<const SIZE: usize>(bytes: &[u8], message: &'static str) -> Result<[u8; SIZE], io::Error> {
    bytes.try_into().map_err(|_| reference_error(message))
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

fn context(network_id: &[u8; 32]) -> Vec<u8> {
    let mut context = OPAQUE_CONTEXT_LABEL.to_vec();
    context.extend_from_slice(network_id);
    context
}

fn identifiers<'a>(network_id: &'a [u8; 32], credential_id: &'a [u8; 32]) -> Identifiers<'a> {
    Identifiers {
        client: Some(credential_id),
        server: Some(network_id),
    }
}

fn server_parameters<'a>(
    network_id: &'a [u8; 32],
    credential_id: &'a [u8; 32],
    context: &'a [u8],
) -> ServerLoginParameters<'a, 'a> {
    ServerLoginParameters {
        context: Some(context),
        identifiers: identifiers(network_id, credential_id),
    }
}

fn fake_record(
    setup_bytes: &[u8; SERVER_SETUP_BYTES],
    rng: &mut ReferenceRng,
) -> Result<[u8; REGISTRATION_RECORD_BYTES], Box<dyn core::error::Error>> {
    let public_key = setup_bytes
        .get(96..128)
        .ok_or_else(|| reference_error("setup has no dummy public key"))?;
    let mut record = [0_u8; REGISTRATION_RECORD_BYTES];
    record
        .get_mut(..32)
        .ok_or_else(|| reference_error("fake record has no public-key field"))?
        .copy_from_slice(public_key);
    rng.fill_bytes(
        record
            .get_mut(32..96)
            .ok_or_else(|| reference_error("fake record has no random field"))?,
    );
    if !rng.succeeded() {
        return Err(reference_error("fake-record RNG counter overflow").into());
    }
    let _validated = ServerRegistration::<ReferenceOpaqueSuite>::deserialize(&record)?;
    Ok(record)
}

struct RegistrationVector {
    request: [u8; REGISTRATION_REQUEST_BYTES],
    response: [u8; REGISTRATION_RESPONSE_BYTES],
    upload: [u8; REGISTRATION_RECORD_BYTES],
    record: [u8; REGISTRATION_RECORD_BYTES],
}

fn registration(
    setup: &ServerSetup<ReferenceOpaqueSuite>,
    credential_id: &[u8; 32],
    network_id: &[u8; 32],
    password: &[u8],
) -> Result<RegistrationVector, Box<dyn core::error::Error>> {
    let mut start_rng = ReferenceRng::new(0xa2);
    let client_start = ClientRegistration::<ReferenceOpaqueSuite>::start(&mut start_rng, password)?;
    if !start_rng.succeeded() {
        return Err(reference_error("registration-start RNG counter overflow").into());
    }
    let request = fixed(
        client_start.message.serialize().as_slice(),
        "registration request length mismatch",
    )?;
    let server_start = ServerRegistration::<ReferenceOpaqueSuite>::start(
        setup,
        RegistrationRequest::deserialize(&request)?,
        credential_id,
    )?;
    let response = fixed(
        server_start.message.serialize().as_slice(),
        "registration response length mismatch",
    )?;
    let mut finish_rng = ReferenceRng::new(0xa3);
    let client_finish = client_start.state.finish(
        &mut finish_rng,
        password,
        RegistrationResponse::deserialize(&response)?,
        ClientRegistrationFinishParameters::new(
            identifiers(network_id, credential_id),
            Some(&ReferenceArgon2id),
        ),
    )?;
    if !finish_rng.succeeded() {
        return Err(reference_error("registration-finish RNG counter overflow").into());
    }
    let upload = fixed(
        client_finish.message.serialize().as_slice(),
        "registration upload length mismatch",
    )?;
    let record = ServerRegistration::<ReferenceOpaqueSuite>::finish(
        RegistrationUpload::deserialize(&upload)?,
    );
    let record = fixed(
        record.serialize().as_slice(),
        "registration record length mismatch",
    )?;
    Ok(RegistrationVector {
        request,
        response,
        upload,
        record,
    })
}

struct LoginVector {
    ke1: [u8; KE1_BYTES],
    ke2: [u8; KE2_BYTES],
    ke3: [u8; KE3_BYTES],
    server_state: [u8; SERVER_LOGIN_STATE_BYTES],
    session_key: [u8; 64],
}

fn real_login(
    setup: &ServerSetup<ReferenceOpaqueSuite>,
    record: &[u8; REGISTRATION_RECORD_BYTES],
    credential_id: &[u8; 32],
    network_id: &[u8; 32],
    password: &[u8],
) -> Result<LoginVector, Box<dyn core::error::Error>> {
    let login_context = context(network_id);
    let mut client_start_rng = ReferenceRng::new(0xa4);
    let client_start = ClientLogin::<ReferenceOpaqueSuite>::start(&mut client_start_rng, password)?;
    if !client_start_rng.succeeded() {
        return Err(reference_error("client-login-start RNG counter overflow").into());
    }
    let ke1 = fixed(
        client_start.message.serialize().as_slice(),
        "KE1 length mismatch",
    )?;
    let mut server_rng = ReferenceRng::new(0xa6);
    let server_start = ServerLogin::<ReferenceOpaqueSuite>::start(
        &mut server_rng,
        setup,
        Some(ServerRegistration::deserialize(record)?),
        CredentialRequest::deserialize(&ke1)?,
        credential_id,
        server_parameters(network_id, credential_id, &login_context),
    )?;
    if !server_rng.succeeded() {
        return Err(reference_error("server-login-start RNG counter overflow").into());
    }
    let ke2 = fixed(
        server_start.message.serialize().as_slice(),
        "KE2 length mismatch",
    )?;
    let server_state = fixed(
        server_start.state.serialize().as_slice(),
        "server-login state length mismatch",
    )?;
    let mut client_finish_rng = ReferenceRng::new(0xa5);
    let client_finish = client_start.state.finish(
        &mut client_finish_rng,
        password,
        CredentialResponse::deserialize(&ke2)?,
        ClientLoginFinishParameters::new(
            Some(&login_context),
            identifiers(network_id, credential_id),
            Some(&ReferenceArgon2id),
        ),
    )?;
    if !client_finish_rng.succeeded() {
        return Err(reference_error("client-login-finish RNG counter overflow").into());
    }
    let ke3 = fixed(
        client_finish.message.serialize().as_slice(),
        "KE3 length mismatch",
    )?;
    let client_session_key: [u8; 64] = fixed(
        client_finish.session_key.as_slice(),
        "client session-key length mismatch",
    )?;
    let server_finish = server_start.state.finish(
        CredentialFinalization::deserialize(&ke3)?,
        server_parameters(network_id, credential_id, &login_context),
    )?;
    let server_session_key: [u8; 64] = fixed(
        server_finish.session_key.as_slice(),
        "server session-key length mismatch",
    )?;
    if client_session_key != server_session_key {
        return Err(reference_error("client and server session keys disagree").into());
    }
    Ok(LoginVector {
        ke1,
        ke2,
        ke3,
        server_state,
        session_key: client_session_key,
    })
}

struct RejectionVector {
    ke1: [u8; KE1_BYTES],
    ke2: [u8; KE2_BYTES],
    server_state: [u8; SERVER_LOGIN_STATE_BYTES],
}

fn fake_login(
    setup: &ServerSetup<ReferenceOpaqueSuite>,
    fake_record: &[u8; REGISTRATION_RECORD_BYTES],
    fake_credential_id: &[u8; 32],
    network_id: &[u8; 32],
) -> Result<RejectionVector, Box<dyn core::error::Error>> {
    let password = b"stage-four unknown-account password";
    let login_context = context(network_id);
    let mut client_rng = ReferenceRng::new(0xa7);
    let client_start = ClientLogin::<ReferenceOpaqueSuite>::start(&mut client_rng, password)?;
    let ke1 = fixed(
        client_start.message.serialize().as_slice(),
        "fake-path KE1 length mismatch",
    )?;
    let mut server_rng = ReferenceRng::new(0xa8);
    let server_start = ServerLogin::<ReferenceOpaqueSuite>::start(
        &mut server_rng,
        setup,
        Some(ServerRegistration::deserialize(fake_record)?),
        CredentialRequest::deserialize(&ke1)?,
        fake_credential_id,
        server_parameters(network_id, fake_credential_id, &login_context),
    )?;
    let ke2 = fixed(
        server_start.message.serialize().as_slice(),
        "fake-path KE2 length mismatch",
    )?;
    let server_state = fixed(
        server_start.state.serialize().as_slice(),
        "fake-path server state length mismatch",
    )?;
    let mut finish_rng = ReferenceRng::new(0xaa);
    let rejected = client_start
        .state
        .finish(
            &mut finish_rng,
            password,
            CredentialResponse::deserialize(&ke2)?,
            ClientLoginFinishParameters::new(
                Some(&login_context),
                identifiers(network_id, fake_credential_id),
                Some(&ReferenceArgon2id),
            ),
        )
        .is_err();
    if !client_rng.succeeded() || !server_rng.succeeded() || !finish_rng.succeeded() {
        return Err(reference_error("fake-path RNG counter overflow").into());
    }
    if !rejected {
        return Err(reference_error("fake OPAQUE record unexpectedly authenticated").into());
    }
    Ok(RejectionVector {
        ke1,
        ke2,
        server_state,
    })
}

fn dummy_finish(
    setup: &ServerSetup<ReferenceOpaqueSuite>,
    fake_record: &[u8; REGISTRATION_RECORD_BYTES],
    network_id: &[u8; 32],
    ke3: &[u8; KE3_BYTES],
) -> Result<RejectionVector, Box<dyn core::error::Error>> {
    let credential_id = [0_u8; 32];
    let login_context = context(network_id);
    let mut rng = ReferenceRng::new(0xa9);
    let client_start = ClientLogin::<ReferenceOpaqueSuite>::start(&mut rng, DUMMY_CLIENT_PASSWORD)?;
    let ke1 = fixed(
        client_start.message.serialize().as_slice(),
        "dummy-path KE1 length mismatch",
    )?;
    let server_start = ServerLogin::<ReferenceOpaqueSuite>::start(
        &mut rng,
        setup,
        Some(ServerRegistration::deserialize(fake_record)?),
        CredentialRequest::deserialize(&ke1)?,
        &credential_id,
        server_parameters(network_id, &credential_id, &login_context),
    )?;
    let ke2 = fixed(
        server_start.message.serialize().as_slice(),
        "dummy-path KE2 length mismatch",
    )?;
    let server_state = fixed(
        server_start.state.serialize().as_slice(),
        "dummy-path server state length mismatch",
    )?;
    let rejected = server_start
        .state
        .finish(
            CredentialFinalization::deserialize(ke3)?,
            server_parameters(network_id, &credential_id, &login_context),
        )
        .is_err();
    if !rng.succeeded() {
        return Err(reference_error("dummy-path RNG counter overflow").into());
    }
    if !rejected {
        return Err(reference_error("dummy OPAQUE state accepted an unrelated KE3").into());
    }
    Ok(RejectionVector {
        ke1,
        ke2,
        server_state,
    })
}

fn opaque_vector() -> Result<OpaqueVector, Box<dyn core::error::Error>> {
    let network_id = [0x50; 32];
    let credential_id = [0x51; 32];
    let fake_credential_id = [0x52; 32];
    let password = b"stage-four fixed OPAQUE password";

    let mut setup_rng = ReferenceRng::new(0xa0);
    let setup = ServerSetup::<ReferenceOpaqueSuite>::new(&mut setup_rng);
    if !setup_rng.succeeded() {
        return Err(reference_error("setup RNG counter overflow").into());
    }
    let setup_bytes = fixed(setup.serialize().as_slice(), "server setup length mismatch")?;
    let mut fake_record_rng = ReferenceRng::new(0xa1);
    let fake_record = fake_record(&setup_bytes, &mut fake_record_rng)?;
    let registration = registration(&setup, &credential_id, &network_id, password)?;
    let login = real_login(
        &setup,
        &registration.record,
        &credential_id,
        &network_id,
        password,
    )?;
    let fake = fake_login(&setup, &fake_record, &fake_credential_id, &network_id)?;
    let dummy = dummy_finish(&setup, &fake_record, &network_id, &login.ke3)?;

    Ok(OpaqueVector {
        setup: setup_bytes,
        fake_record,
        registration_request: registration.request,
        registration_response: registration.response,
        registration_upload: registration.upload,
        registration_record: registration.record,
        ke1: login.ke1,
        ke2: login.ke2,
        ke3: login.ke3,
        server_login_state: login.server_state,
        session_key: login.session_key,
        fake_ke1: fake.ke1,
        fake_ke2: fake.ke2,
        fake_server_login_state: fake.server_state,
        dummy_ke1: dummy.ke1,
        dummy_ke2: dummy.ke2,
        dummy_server_login_state: dummy.server_state,
        dummy_ke3: login.ke3,
    })
}

#[test]
#[ignore = "manual reviewed golden-vector generation"]
fn emit_stage_four_opaque_vectors() -> Result<(), Box<dyn core::error::Error>> {
    println!("# arcd Stage-04 OPAQUE vectors v1");
    println!("# generated by crates/agenc-relay-auth/tests/generate_stage_four_vectors.rs");
    println!("# fields are lowercase hexadecimal unless named *_decimal");

    let vector = opaque_vector()?;
    let network_id = [0x50; 32];
    let credential_id = [0x51; 32];
    let fake_credential_id = [0x52; 32];
    let password = b"stage-four fixed OPAQUE password";
    let login_context = context(&network_id);
    let mut outputs = Vec::new();
    outputs.extend_from_slice(&vector.setup);
    outputs.extend_from_slice(&vector.fake_record);
    outputs.extend_from_slice(&vector.registration_request);
    outputs.extend_from_slice(&vector.registration_response);
    outputs.extend_from_slice(&vector.registration_upload);
    outputs.extend_from_slice(&vector.registration_record);
    outputs.extend_from_slice(&vector.ke1);
    outputs.extend_from_slice(&vector.ke2);
    outputs.extend_from_slice(&vector.ke3);
    outputs.extend_from_slice(&vector.server_login_state);
    outputs.extend_from_slice(&vector.session_key);
    outputs.extend_from_slice(&vector.fake_ke1);
    outputs.extend_from_slice(&vector.fake_ke2);
    outputs.extend_from_slice(&vector.fake_server_login_state);
    outputs.extend_from_slice(&vector.dummy_ke1);
    outputs.extend_from_slice(&vector.dummy_ke2);
    outputs.extend_from_slice(&vector.dummy_server_login_state);
    outputs.extend_from_slice(&vector.dummy_ke3);
    println!(
        "VEC-S04-007-OPAQUE|opaque_exact_profile|opaque-ke-4.0.1-reference|network={}|credential_id={}|fake_credential_id={}|password={}|context={}|argon2_salt={}|argon2_memory_kib_decimal={ARGON2_MEMORY_KIB}|argon2_iterations_decimal={ARGON2_ITERATIONS}|argon2_lanes_decimal={ARGON2_LANES}|argon2_output_bytes_decimal={ARGON2_OUTPUT_BYTES}|rng_seeds=a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,aa|lengths_decimal=128,32,64,192,96,320,64,128|setup={}|fake_record={}|registration_request={}|registration_response={}|registration_upload={}|registration_record={}|ke1={}|ke2={}|ke3={}|server_login_state={}|session_key={}|fake_ke1={}|fake_ke2={}|fake_server_login_state={}|dummy_ke1={}|dummy_ke2={}|dummy_server_login_state={}|dummy_ke3={}|fake_login_rejected=01|dummy_finish_rejected=01|output_sha256={}",
        lowercase_hex(&network_id)?,
        lowercase_hex(&credential_id)?,
        lowercase_hex(&fake_credential_id)?,
        lowercase_hex(password)?,
        lowercase_hex(&login_context)?,
        lowercase_hex(&ARGON2_SALT)?,
        lowercase_hex(&vector.setup)?,
        lowercase_hex(&vector.fake_record)?,
        lowercase_hex(&vector.registration_request)?,
        lowercase_hex(&vector.registration_response)?,
        lowercase_hex(&vector.registration_upload)?,
        lowercase_hex(&vector.registration_record)?,
        lowercase_hex(&vector.ke1)?,
        lowercase_hex(&vector.ke2)?,
        lowercase_hex(&vector.ke3)?,
        lowercase_hex(&vector.server_login_state)?,
        lowercase_hex(&vector.session_key)?,
        lowercase_hex(&vector.fake_ke1)?,
        lowercase_hex(&vector.fake_ke2)?,
        lowercase_hex(&vector.fake_server_login_state)?,
        lowercase_hex(&vector.dummy_ke1)?,
        lowercase_hex(&vector.dummy_ke2)?,
        lowercase_hex(&vector.dummy_server_login_state)?,
        lowercase_hex(&vector.dummy_ke3)?,
        sha256_hex(&outputs)?,
    );
    Ok(())
}
