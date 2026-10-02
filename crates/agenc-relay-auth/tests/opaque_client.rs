#![forbid(unsafe_code)]

//! The public OPAQUE profile and client modules against the immutable
//! `VEC-S04-007-OPAQUE` vector and the coordinator's server half.

use std::collections::VecDeque;
use std::io;

use agenc_relay_auth::client::{
    OpaqueClientError, login_finish, login_start, registration_finish, registration_start,
};
use agenc_relay_auth::profile::{
    AgencOpaqueSuite, FallibleOpaqueRng, FixedArgon2id, OPAQUE_ARGON2_ITERATIONS,
    OPAQUE_ARGON2_LANES, OPAQUE_ARGON2_MEMORY_KIB, OPAQUE_ARGON2_OUTPUT_BYTES, OPAQUE_ARGON2_SALT,
    opaque_context, opaque_identifiers,
};
use agenc_relay_auth::{
    OPAQUE_KE1_BYTES, OPAQUE_KE2_BYTES, OPAQUE_KE3_BYTES, OPAQUE_REGISTRATION_RECORD_BYTES,
    OPAQUE_REGISTRATION_REQUEST_BYTES, OPAQUE_REGISTRATION_RESPONSE_BYTES,
    OPAQUE_SERVER_LOGIN_STATE_BYTES, OPAQUE_SERVER_SETUP_BYTES, OpaqueKe1, OpaqueKe3,
    OpaqueProfile, OpaqueRegistrationRecord, OpaqueRegistrationRequest, finish_authentication,
    finish_registration,
};
use agenc_relay_crypto::OsEntropy;
use agenc_relay_types::{EntropyError, EntropySource, NetworkId, OpaqueCredentialId};
use opaque_ke::rand::RngCore as _;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use opaque_sha2::{Digest as _, Sha256, Sha512};

const OPAQUE_VECTORS: &str =
    include_str!("../../../test-data/vectors/stage-four-opaque-v1.vectors");
const VECTOR_PASSWORD: &str = "stage-four fixed OPAQUE password";
const UNKNOWN_ACCOUNT_PASSWORD: &str = "stage-four unknown-account password";
const DUMMY_CLIENT_PASSWORD: &str = "agenc-chat internal dummy OPAQUE client v1";

type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;

/// The generator's SHA-512 counter stream (`ReferenceRng` in
/// `generate_stage_four_vectors.rs`) as an entropy source.
struct VectorEntropy {
    seed: [u8; 32],
    counter: u64,
    buffered: VecDeque<u8>,
}

impl VectorEntropy {
    fn new(seed: u8) -> Self {
        Self {
            seed: [seed; 32],
            counter: 0,
            buffered: VecDeque::new(),
        }
    }
}

impl EntropySource for VectorEntropy {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            if self.buffered.is_empty() {
                let next = self
                    .counter
                    .checked_add(1)
                    .ok_or(EntropyError::Unavailable)?;
                let mut digest = Sha512::new();
                digest.update(b"arcd Stage-04 OPAQUE vector RNG v1");
                digest.update(self.seed);
                digest.update(self.counter.to_be_bytes());
                self.buffered.extend(digest.finalize());
                self.counter = next;
            }
            *byte = self.buffered.pop_front().ok_or(EntropyError::Unavailable)?;
        }
        Ok(())
    }
}

/// Fills from the operating system for a fixed number of draws, then fails.
struct FailsAfter {
    remaining: usize,
}

/// Fails its first draw, then fills from a counter.
struct RecoversAfterOneFailure {
    failed_once: bool,
    next: u8,
}

impl EntropySource for RecoversAfterOneFailure {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        if !self.failed_once {
            self.failed_once = true;
            return Err(EntropyError::Unavailable);
        }
        for byte in destination {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
        Ok(())
    }
}

/// A generator whose source has already failed once.
fn latched_generator() -> FallibleOpaqueRng<FailsAfter> {
    let mut rng = FallibleOpaqueRng::new(FailsAfter { remaining: 0 });
    rng.fill_bytes(&mut [0_u8; 1]);
    rng
}

impl EntropySource for FailsAfter {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(EntropyError::Unavailable)?;
        OsEntropy::fill(destination).map_err(|_| EntropyError::Unavailable)
    }
}

fn seeded(seed: u8) -> FallibleOpaqueRng<VectorEntropy> {
    FallibleOpaqueRng::new(VectorEntropy::new(seed))
}

fn vector_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn record() -> Result<&'static str, io::Error> {
    OPAQUE_VECTORS
        .lines()
        .find(|line| line.split('|').next() == Some("VEC-S04-007-OPAQUE"))
        .ok_or_else(|| vector_error("the OPAQUE vector record is absent"))
}

fn field(name: &str) -> Result<&'static str, io::Error> {
    record()?
        .split('|')
        .skip(3)
        .find_map(|item| {
            item.split_once('=')
                .filter(|(candidate, _)| *candidate == name)
                .map(|(_, value)| value)
        })
        .ok_or_else(|| vector_error("a required vector field is absent"))
}

fn hex_nibble(byte: u8) -> Result<u8, io::Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(vector_error("vector contains non-lowercase hexadecimal")),
    }
}

fn bytes(name: &str) -> Result<Vec<u8>, io::Error> {
    let (pairs, remainder) = field(name)?.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(vector_error("vector hexadecimal length is odd"));
    }
    pairs
        .iter()
        .map(|[high, low]| Ok((hex_nibble(*high)? << 4) | hex_nibble(*low)?))
        .collect()
}

fn fixed<const SIZE: usize>(name: &str) -> Result<[u8; SIZE], io::Error> {
    bytes(name)?
        .try_into()
        .map_err(|_| vector_error("a fixed vector field has the wrong length"))
}

fn server_parameters<'a>(
    network: &'a NetworkId,
    credential: &'a OpaqueCredentialId,
    context: &'a [u8],
) -> ServerLoginParameters<'a, 'a> {
    ServerLoginParameters {
        context: Some(context),
        identifiers: opaque_identifiers(network, credential),
    }
}

fn text(name: &str) -> Result<String, Box<dyn core::error::Error>> {
    Ok(String::from_utf8(bytes(name)?)?)
}

/// The vector's eleven generator seeds, in the generator's order.
fn seeds() -> Result<[u8; 11], Box<dyn core::error::Error>> {
    let seeds = field("rng_seeds")?
        .split(',')
        .map(|seed| u8::from_str_radix(seed, 16))
        .collect::<Result<Vec<u8>, _>>()?;
    seeds
        .try_into()
        .map_err(|_| vector_error("the vector does not list eleven seeds").into())
}

#[test]
fn the_vector_records_the_public_profile_constants() -> TestResult {
    assert_eq!(
        field("argon2_memory_kib_decimal")?,
        OPAQUE_ARGON2_MEMORY_KIB.to_string()
    );
    assert_eq!(
        field("argon2_iterations_decimal")?,
        OPAQUE_ARGON2_ITERATIONS.to_string()
    );
    assert_eq!(
        field("argon2_lanes_decimal")?,
        OPAQUE_ARGON2_LANES.to_string()
    );
    assert_eq!(
        field("argon2_output_bytes_decimal")?,
        OPAQUE_ARGON2_OUTPUT_BYTES.to_string()
    );
    assert_eq!(fixed::<16>("argon2_salt")?, OPAQUE_ARGON2_SALT);
    let network = NetworkId::from_bytes(fixed("network")?);
    assert_eq!(bytes("context")?, opaque_context(&network));
    assert_eq!(text("password")?, VECTOR_PASSWORD);
    Ok(())
}

/// Every field of `VEC-S04-007-OPAQUE`, from the vector's own seeds, through
/// the public profile (suite, key-stretching function, context, identities
/// and the latched random-number adapter) and the public client calls; the
/// server half calls the pinned library with the public profile. The export
/// keys, which the vector does not record, are the pinned library's own for
/// the same seeds and agree between registration and login.
#[test]
fn public_modules_reproduce_vec_s04_007_opaque_byte_for_byte() -> TestResult {
    let [
        setup_seed,
        fake_record_seed,
        registration_start_seed,
        registration_finish_seed,
        login_start_seed,
        login_finish_seed,
        server_login_seed,
        fake_login_start_seed,
        fake_server_login_seed,
        dummy_seed,
        fake_login_finish_seed,
    ] = seeds()?;
    let lengths = [
        OPAQUE_SERVER_SETUP_BYTES,
        OPAQUE_REGISTRATION_REQUEST_BYTES,
        OPAQUE_REGISTRATION_RESPONSE_BYTES,
        OPAQUE_REGISTRATION_RECORD_BYTES,
        OPAQUE_KE1_BYTES,
        OPAQUE_KE2_BYTES,
        OPAQUE_KE3_BYTES,
        OPAQUE_SERVER_LOGIN_STATE_BYTES,
    ];
    let lengths: Vec<String> = lengths.iter().map(usize::to_string).collect();
    assert_eq!(field("lengths_decimal")?, lengths.join(","));
    let network = NetworkId::from_bytes(fixed("network")?);
    let credential = OpaqueCredentialId::from_bytes(fixed("credential_id")?);
    let fake_credential = OpaqueCredentialId::from_bytes(fixed("fake_credential_id")?);
    let context = opaque_context(&network);
    let mut outputs = Vec::new();

    let mut setup_rng = seeded(setup_seed);
    let setup = ServerSetup::<AgencOpaqueSuite>::new(&mut setup_rng);
    assert!(setup_rng.succeeded());
    let setup_bytes = setup.serialize();
    assert_eq!(setup_bytes.as_slice(), bytes("setup")?);
    outputs.extend_from_slice(&setup_bytes);

    let mut fake_record = [0_u8; 192];
    fake_record
        .get_mut(..32)
        .ok_or_else(|| vector_error("fake record has no public-key field"))?
        .copy_from_slice(
            setup_bytes
                .get(96..128)
                .ok_or_else(|| vector_error("setup has no dummy public key"))?,
        );
    let mut fake_rng = seeded(fake_record_seed);
    fake_rng.fill_bytes(&mut fake_record[32..96]);
    assert!(fake_rng.succeeded());
    assert_eq!(fake_record, fixed::<192>("fake_record")?);
    outputs.extend_from_slice(&fake_record);

    let registration = registration_start(&mut seeded(registration_start_seed), VECTOR_PASSWORD)?;
    assert_eq!(registration.request, fixed::<32>("registration_request")?);
    outputs.extend_from_slice(&registration.request);
    let response = ServerRegistration::<AgencOpaqueSuite>::start(
        &setup,
        RegistrationRequest::deserialize(&registration.request)?,
        credential.expose_for_account_service(),
    )?
    .message
    .serialize();
    let response: [u8; 64] = response.as_slice().try_into()?;
    assert_eq!(response, fixed::<64>("registration_response")?);
    outputs.extend_from_slice(&response);
    let registered = registration_finish(
        &mut seeded(registration_finish_seed),
        registration.state,
        VECTOR_PASSWORD,
        &response,
        &network,
        &credential,
    )?;
    assert_eq!(*registered.record, fixed::<192>("registration_upload")?);
    let record = finish_registration(*registered.record)?;
    assert_eq!(
        record.expose_for_persistence(),
        &fixed::<192>("registration_record")?
    );
    outputs.extend_from_slice(&*registered.record);
    outputs.extend_from_slice(record.expose_for_persistence());
    let library_registration = ClientRegistration::<AgencOpaqueSuite>::start(
        &mut seeded(registration_start_seed),
        VECTOR_PASSWORD.as_bytes(),
    )?
    .state
    .finish(
        &mut seeded(registration_finish_seed),
        VECTOR_PASSWORD.as_bytes(),
        RegistrationResponse::deserialize(&response)?,
        ClientRegistrationFinishParameters::new(
            opaque_identifiers(&network, &credential),
            Some(&FixedArgon2id),
        ),
    )?;
    assert_eq!(
        library_registration.export_key.as_slice(),
        &registered.export_key[..]
    );

    let login = login_start(&mut seeded(login_start_seed), VECTOR_PASSWORD)?;
    assert_eq!(login.ke1, fixed::<96>("ke1")?);
    let server = ServerLogin::<AgencOpaqueSuite>::start(
        &mut seeded(server_login_seed),
        &setup,
        Some(ServerRegistration::deserialize(
            record.expose_for_persistence(),
        )?),
        CredentialRequest::deserialize(&login.ke1)?,
        credential.expose_for_account_service(),
        server_parameters(&network, &credential, &context),
    )?;
    let ke2: [u8; 320] = server.message.serialize().as_slice().try_into()?;
    let server_state = server.state.serialize();
    assert_eq!(ke2, fixed::<320>("ke2")?);
    assert_eq!(server_state.as_slice(), bytes("server_login_state")?);
    let finished = login_finish(
        &mut seeded(login_finish_seed),
        login.state,
        VECTOR_PASSWORD,
        &ke2,
        &network,
        &credential,
    )?;
    assert_eq!(finished.ke3, fixed::<64>("ke3")?);
    assert_eq!(*finished.session_key, fixed::<64>("session_key")?);
    let library_login = ClientLogin::<AgencOpaqueSuite>::start(
        &mut seeded(login_start_seed),
        VECTOR_PASSWORD.as_bytes(),
    )?
    .state
    .finish(
        &mut seeded(login_finish_seed),
        VECTOR_PASSWORD.as_bytes(),
        CredentialResponse::deserialize(&ke2)?,
        ClientLoginFinishParameters::new(
            Some(&context),
            opaque_identifiers(&network, &credential),
            Some(&FixedArgon2id),
        ),
    )?;
    assert_eq!(
        library_login.session_key.as_slice(),
        &finished.session_key[..]
    );
    assert_eq!(
        library_login.export_key.as_slice(),
        &finished.export_key[..]
    );
    assert_eq!(*finished.export_key, *registered.export_key);
    assert_ne!(*finished.export_key, *finished.session_key);
    outputs.extend_from_slice(&login.ke1);
    outputs.extend_from_slice(&ke2);
    outputs.extend_from_slice(&finished.ke3);
    outputs.extend_from_slice(&server_state);
    outputs.extend_from_slice(&*finished.session_key);

    let fake = login_start(&mut seeded(fake_login_start_seed), UNKNOWN_ACCOUNT_PASSWORD)?;
    assert_eq!(fake.ke1, fixed::<96>("fake_ke1")?);
    let fake_server = ServerLogin::<AgencOpaqueSuite>::start(
        &mut seeded(fake_server_login_seed),
        &setup,
        Some(ServerRegistration::deserialize(&fake_record)?),
        CredentialRequest::deserialize(&fake.ke1)?,
        fake_credential.expose_for_account_service(),
        server_parameters(&network, &fake_credential, &context),
    )?;
    let fake_ke2: [u8; 320] = fake_server.message.serialize().as_slice().try_into()?;
    let fake_state = fake_server.state.serialize();
    assert_eq!(fake_ke2, fixed::<320>("fake_ke2")?);
    assert_eq!(fake_state.as_slice(), bytes("fake_server_login_state")?);
    assert_eq!(field("fake_login_rejected")?, "01");
    assert_eq!(
        login_finish(
            &mut seeded(fake_login_finish_seed),
            fake.state,
            UNKNOWN_ACCOUNT_PASSWORD,
            &fake_ke2,
            &network,
            &fake_credential,
        )
        .err(),
        Some(OpaqueClientError::InvalidLogin)
    );
    outputs.extend_from_slice(&fake.ke1);
    outputs.extend_from_slice(&fake_ke2);
    outputs.extend_from_slice(&fake_state);

    // The coordinator's internal dummy client draws its KE1 and the server
    // start from one stream (seed a9).
    let zero_credential = OpaqueCredentialId::from_bytes([0_u8; 32]);
    let mut dummy_rng = seeded(dummy_seed);
    let dummy = login_start(&mut dummy_rng, DUMMY_CLIENT_PASSWORD)?;
    assert_eq!(dummy.ke1, fixed::<96>("dummy_ke1")?);
    let dummy_server = ServerLogin::<AgencOpaqueSuite>::start(
        &mut dummy_rng,
        &setup,
        Some(ServerRegistration::deserialize(&fake_record)?),
        CredentialRequest::deserialize(&dummy.ke1)?,
        zero_credential.expose_for_account_service(),
        server_parameters(&network, &zero_credential, &context),
    )?;
    assert!(dummy_rng.succeeded());
    let dummy_ke2 = dummy_server.message.serialize();
    let dummy_state = dummy_server.state.serialize();
    assert_eq!(dummy_ke2.as_slice(), bytes("dummy_ke2")?);
    assert_eq!(dummy_state.as_slice(), bytes("dummy_server_login_state")?);
    assert_eq!(fixed::<64>("dummy_ke3")?, finished.ke3);
    // The dummy state refuses the real login's KE3.
    assert_eq!(field("dummy_finish_rejected")?, "01");
    assert!(
        dummy_server
            .state
            .finish(
                CredentialFinalization::deserialize(&finished.ke3)?,
                server_parameters(&network, &zero_credential, &context),
            )
            .is_err()
    );
    outputs.extend_from_slice(&dummy.ke1);
    outputs.extend_from_slice(&dummy_ke2);
    outputs.extend_from_slice(&dummy_state);
    outputs.extend_from_slice(&finished.ke3);

    let digest: Vec<u8> = Sha256::digest(&outputs).to_vec();
    assert_eq!(digest, bytes("output_sha256")?);
    Ok(())
}

/// The client calls against the coordinator's own server half: the right
/// password authenticates on both ends; a wrong password, an unknown login
/// (the fixed fake record) and a client bound to another network are the
/// library's invalid login, never a protocol-shaped success.
#[test]
fn client_calls_interoperate_with_the_coordinator_profile() -> TestResult {
    let network = NetworkId::from_bytes([0x33; 32]);
    let profile = OpaqueProfile::generate(network)?;
    let credential = OpaqueCredentialId::from_bytes([0x44; 32]);
    let password = "correct horse battery staple";
    let mut rng = FallibleOpaqueRng::new(OsEntropy);

    let registration = registration_start(&mut rng, password)?;
    let request = OpaqueRegistrationRequest::from_bytes(registration.request)?;
    let response = profile.registration_start(&credential, &request)?;
    let registered = registration_finish(
        &mut rng,
        registration.state,
        password,
        response.expose_for_account_response(),
        &network,
        &credential,
    )?;
    assert_ne!(*registered.export_key, [0_u8; 64]);
    let record = OpaqueRegistrationRecord::from_bytes(*registered.record)?;
    assert_eq!(
        finish_registration(*registered.record)?.expose_for_persistence(),
        record.expose_for_persistence()
    );

    let attempt = |password: &str, record: Option<&OpaqueRegistrationRecord>, client_network| {
        let mut rng = FallibleOpaqueRng::new(OsEntropy);
        let login = login_start(&mut rng, password)?;
        let ke1 = OpaqueKe1::from_bytes(login.ke1)?;
        let (ke2, state) = profile.authentication_start(network, &credential, record, &ke1)?;
        let finished = login_finish(
            &mut rng,
            login.state,
            password,
            ke2.expose_for_account_response(),
            &client_network,
            &credential,
        );
        Ok::<_, Box<dyn core::error::Error>>((finished, state))
    };

    let (finished, state) = attempt(password, Some(&record), network)?;
    let finished = finished?;
    assert_ne!(*finished.session_key, [0_u8; 64]);
    // The login recovers the export key the registration produced, and it is
    // not the session key.
    assert_eq!(*finished.export_key, *registered.export_key);
    assert_ne!(*finished.export_key, *finished.session_key);
    let ke3 = OpaqueKe3::from_bytes(finished.ke3)?;
    finish_authentication(network, &credential, state, &ke3)?.authorize_account_transition();

    for (password, record, client_network) in [
        ("the wrong password entirely", Some(&record), network),
        (password, None, network),
        (password, Some(&record), NetworkId::from_bytes([0x34; 32])),
    ] {
        let (finished, _state) = attempt(password, record, client_network)?;
        assert_eq!(finished.err(), Some(OpaqueClientError::InvalidLogin));
    }
    Ok(())
}

/// A KE2 or registration response that reflects the client's blinded element,
/// or whose evaluated element does not decode, is an invalid server message,
/// never the invalid-login path that leads to the dummy finish.
#[test]
fn reflected_or_undecodable_server_messages_are_refused() -> TestResult {
    let network = NetworkId::from_bytes([0x55; 32]);
    let credential = OpaqueCredentialId::from_bytes([0x66; 32]);
    let profile = OpaqueProfile::generate(network)?;
    let password = "a password of some length";
    let mut rng = FallibleOpaqueRng::new(OsEntropy);

    let login = login_start(&mut rng, password)?;
    let (ke2, _state) = profile.authentication_start(
        network,
        &credential,
        None,
        &OpaqueKe1::from_bytes(login.ke1)?,
    )?;
    let mut reflected = *ke2.expose_for_account_response();
    reflected[..32].copy_from_slice(&login.ke1[..32]);
    assert_eq!(
        login_finish(
            &mut rng,
            login.state,
            password,
            &reflected,
            &network,
            &credential
        )
        .err(),
        Some(OpaqueClientError::InvalidServerMessage)
    );
    let login = login_start(&mut rng, password)?;
    let mut undecodable = *ke2.expose_for_account_response();
    undecodable[..32].fill(0xff);
    assert_eq!(
        login_finish(
            &mut rng,
            login.state,
            password,
            &undecodable,
            &network,
            &credential
        )
        .err(),
        Some(OpaqueClientError::InvalidServerMessage)
    );

    let registration = registration_start(&mut rng, password)?;
    let request = OpaqueRegistrationRequest::from_bytes(registration.request)?;
    let response = profile.registration_start(&credential, &request)?;
    let mut reflected = *response.expose_for_account_response();
    reflected[..32].copy_from_slice(&registration.request);
    assert_eq!(
        registration_finish(
            &mut rng,
            registration.state,
            password,
            &reflected,
            &network,
            &credential
        )
        .err(),
        Some(OpaqueClientError::InvalidServerMessage)
    );
    let registration = registration_start(&mut rng, password)?;
    let mut undecodable = *response.expose_for_account_response();
    undecodable[..32].fill(0xff);
    assert_eq!(
        registration_finish(
            &mut rng,
            registration.state,
            password,
            &undecodable,
            &network,
            &credential
        )
        .err(),
        Some(OpaqueClientError::InvalidServerMessage)
    );
    assert!(rng.succeeded());
    Ok(())
}

/// A failed draw discards the library's result at every call, and a password
/// outside Section 11.1 is refused before any library work.
#[test]
fn failed_entropy_and_out_of_profile_passwords_are_refused() -> TestResult {
    let network = NetworkId::from_bytes([0x77; 32]);
    let credential = OpaqueCredentialId::from_bytes([0x78; 32]);
    let profile = OpaqueProfile::generate(network)?;
    let password = "a password of some length";

    let mut exhausted = FallibleOpaqueRng::new(FailsAfter { remaining: 0 });
    assert_eq!(
        registration_start(&mut exhausted, password).err(),
        Some(OpaqueClientError::EntropyUnavailable)
    );
    assert_eq!(
        login_start(&mut exhausted, password).err(),
        Some(OpaqueClientError::EntropyUnavailable)
    );

    // Registration finish seals the envelope with a fresh nonce; a source
    // that fails there discards the record.
    let mut rng = FallibleOpaqueRng::new(OsEntropy);
    let registration = registration_start(&mut rng, password)?;
    let request = OpaqueRegistrationRequest::from_bytes(registration.request)?;
    let response = profile.registration_start(&credential, &request)?;
    assert_eq!(
        registration_finish(
            &mut FallibleOpaqueRng::new(FailsAfter { remaining: 0 }),
            registration.state,
            password,
            response.expose_for_account_response(),
            &network,
            &credential,
        )
        .err(),
        Some(OpaqueClientError::EntropyUnavailable)
    );

    // A generator that already latched discards even a finish that draws
    // nothing.
    let login = login_start(&mut rng, password)?;
    let (ke2, _state) = profile.authentication_start(
        network,
        &credential,
        None,
        &OpaqueKe1::from_bytes(login.ke1)?,
    )?;
    let mut latched = FallibleOpaqueRng::new(FailsAfter { remaining: 0 });
    latched.fill_bytes(&mut [0_u8; 1]);
    assert_eq!(
        login_finish(
            &mut latched,
            login.state,
            password,
            ke2.expose_for_account_response(),
            &network,
            &credential,
        )
        .err(),
        Some(OpaqueClientError::EntropyUnavailable)
    );

    let short = "eleven byte";
    let long = "x".repeat(1_025);
    for refused in [short, long.as_str(), ""] {
        assert_eq!(
            registration_start(&mut rng, refused).err(),
            Some(OpaqueClientError::InvalidPassword)
        );
        assert_eq!(
            login_start(&mut rng, refused).err(),
            Some(OpaqueClientError::InvalidPassword)
        );
    }
    let registration = registration_start(&mut rng, password)?;
    assert_eq!(
        registration_finish(
            &mut rng,
            registration.state,
            short,
            response.expose_for_account_response(),
            &network,
            &credential,
        )
        .err(),
        Some(OpaqueClientError::InvalidPassword)
    );
    let login = login_start(&mut rng, password)?;
    assert_eq!(
        login_finish(
            &mut rng,
            login.state,
            &long,
            ke2.expose_for_account_response(),
            &network,
            &credential,
        )
        .err(),
        Some(OpaqueClientError::InvalidPassword)
    );
    assert!(rng.succeeded());
    Ok(())
}

/// A generator that has already latched is refused before any work: before
/// the password bounds, before a server message is decoded and before the
/// library runs, so no finish derives keys under a failed generator, even a
/// login finish, which draws nothing.
#[test]
fn a_latched_generator_is_refused_before_any_work() -> TestResult {
    let network = NetworkId::from_bytes([0x79; 32]);
    let credential = OpaqueCredentialId::from_bytes([0x7a; 32]);
    let profile = OpaqueProfile::generate(network)?;
    let password = "a password of some length";
    let mut rng = FallibleOpaqueRng::new(OsEntropy);

    for refused in ["eleven byte", password] {
        assert_eq!(
            registration_start(&mut latched_generator(), refused).err(),
            Some(OpaqueClientError::EntropyUnavailable)
        );
        assert_eq!(
            login_start(&mut latched_generator(), refused).err(),
            Some(OpaqueClientError::EntropyUnavailable)
        );
    }

    let registration = registration_start(&mut rng, password)?;
    let mut undecodable = [0_u8; 64];
    undecodable[..32].fill(0xff);
    assert_eq!(
        registration_finish(
            &mut latched_generator(),
            registration.state,
            password,
            &undecodable,
            &network,
            &credential,
        )
        .err(),
        Some(OpaqueClientError::EntropyUnavailable)
    );
    let login = login_start(&mut rng, password)?;
    let mut undecodable = [0_u8; 320];
    undecodable[..32].fill(0xff);
    assert_eq!(
        login_finish(
            &mut latched_generator(),
            login.state,
            password,
            &undecodable,
            &network,
            &credential,
        )
        .err(),
        Some(OpaqueClientError::EntropyUnavailable)
    );

    // A KE2 for the real record would authenticate with a working generator.
    let registration = registration_start(&mut rng, password)?;
    let request = OpaqueRegistrationRequest::from_bytes(registration.request)?;
    let response = profile.registration_start(&credential, &request)?;
    let registered = registration_finish(
        &mut rng,
        registration.state,
        password,
        response.expose_for_account_response(),
        &network,
        &credential,
    )?;
    let record = OpaqueRegistrationRecord::from_bytes(*registered.record)?;
    let login = login_start(&mut rng, password)?;
    let (ke2, _state) = profile.authentication_start(
        network,
        &credential,
        Some(&record),
        &OpaqueKe1::from_bytes(login.ke1)?,
    )?;
    assert_eq!(
        login_finish(
            &mut latched_generator(),
            login.state,
            password,
            ke2.expose_for_account_response(),
            &network,
            &credential,
        )
        .err(),
        Some(OpaqueClientError::EntropyUnavailable)
    );
    let login = login_start(&mut rng, password)?;
    let (ke2, state) = profile.authentication_start(
        network,
        &credential,
        Some(&record),
        &OpaqueKe1::from_bytes(login.ke1)?,
    )?;
    let finished = login_finish(
        &mut rng,
        login.state,
        password,
        ke2.expose_for_account_response(),
        &network,
        &credential,
    )?;
    finish_authentication(
        network,
        &credential,
        state,
        &OpaqueKe3::from_bytes(finished.ke3)?,
    )?
    .authorize_account_transition();
    assert!(rng.succeeded());
    Ok(())
}

/// The adapter latches its first failure. A source that recovers afterwards
/// supplies no more bytes: every later draw is the nonzero sentinel,
/// `succeeded` stays false, and a call cannot proceed on it.
#[test]
fn the_adapter_stays_latched_after_its_source_recovers() -> TestResult {
    let mut source = RecoversAfterOneFailure {
        failed_once: false,
        next: 7,
    };
    assert!(source.fill_exact(&mut [0_u8; 1]).is_err());
    let mut recovered = [0_u8; 2];
    source.fill_exact(&mut recovered)?;
    assert_eq!(recovered, [7, 8]);

    let mut rng = FallibleOpaqueRng::new(RecoversAfterOneFailure {
        failed_once: false,
        next: 7,
    });
    assert!(rng.succeeded());
    for _ in 0..3 {
        let mut bytes = [9_u8; 4];
        rng.fill_bytes(&mut bytes);
        assert_eq!(bytes, [1, 0, 0, 0]);
        assert!(!rng.succeeded());
        let mut bytes = [9_u8; 4];
        assert!(rng.try_fill_bytes(&mut bytes).is_ok());
        assert_eq!(bytes, [1, 0, 0, 0]);
    }
    assert_eq!(rng.next_u32(), u32::from_be_bytes([1, 0, 0, 0]));
    assert_eq!(rng.next_u64(), u64::from_be_bytes([1, 0, 0, 0, 0, 0, 0, 0]));
    assert!(!rng.succeeded());
    assert_eq!(
        registration_start(&mut rng, "a password of some length").err(),
        Some(OpaqueClientError::EntropyUnavailable)
    );
    Ok(())
}
