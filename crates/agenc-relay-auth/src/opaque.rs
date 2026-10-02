//! Exact RFC 9807 OPAQUE profile for coordinator-owned account records.

use agenc_relay_crypto::OsEntropy;
use agenc_relay_types::{EntropySource, NetworkId, OpaqueCredentialId};
use opaque_ke::rand::RngCore as _;
use opaque_ke::{
    ClientLogin, CredentialFinalization, CredentialRequest, CredentialResponse,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::AuthError;
use crate::profile::{AgencOpaqueSuite, FallibleOpaqueRng, opaque_context, opaque_identifiers};

const DUMMY_CLIENT_PASSWORD: &[u8] = b"agenc-chat internal dummy OPAQUE client v1";
const FAKE_ENVELOPE_RANGE: core::ops::RangeFrom<usize> = 96..;

/// Exact serialized OPAQUE setup length for the pinned suite.
pub const OPAQUE_SERVER_SETUP_BYTES: usize = 128;
/// Exact serialized registration request length.
pub const OPAQUE_REGISTRATION_REQUEST_BYTES: usize = 32;
/// Exact serialized registration response length.
pub const OPAQUE_REGISTRATION_RESPONSE_BYTES: usize = 64;
/// Exact serialized registration record length.
pub const OPAQUE_REGISTRATION_RECORD_BYTES: usize = 192;
/// Exact serialized KE1 length.
pub const OPAQUE_KE1_BYTES: usize = 96;
/// Exact serialized KE2 length.
pub const OPAQUE_KE2_BYTES: usize = 320;
/// Exact serialized KE3 length.
pub const OPAQUE_KE3_BYTES: usize = 64;
/// Exact serialized server-login state length.
pub const OPAQUE_SERVER_LOGIN_STATE_BYTES: usize = 128;

/// Validates a serialized server setup and returns its pinned-suite AKE public key.
pub fn opaque_server_public_key(
    setup_bytes: &[u8; OPAQUE_SERVER_SETUP_BYTES],
) -> Result<[u8; 32], AuthError> {
    let setup = deserialize_setup(setup_bytes)?;
    setup
        .keypair()
        .public()
        .serialize()
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidEncoding)
}

/// Coordinator OPAQUE setup, stable fake record, and dummy-finish work state.
pub struct OpaqueProfile {
    setup: Zeroizing<[u8; OPAQUE_SERVER_SETUP_BYTES]>,
    fake_record: Zeroizing<[u8; OPAQUE_REGISTRATION_RECORD_BYTES]>,
    dummy_login_state: Zeroizing<[u8; OPAQUE_SERVER_LOGIN_STATE_BYTES]>,
}

impl OpaqueProfile {
    /// Generates independently random setup material and one fixed fake record.
    pub fn generate(network_id: NetworkId) -> Result<Self, AuthError> {
        let mut rng = FallibleOpaqueRng::new(OsEntropy);
        let setup = ServerSetup::<AgencOpaqueSuite>::new(&mut rng);
        if !rng.succeeded() {
            return Err(AuthError::EntropyUnavailable);
        }
        let serialized_setup = Zeroizing::new(setup.serialize());
        let setup_bytes: Zeroizing<[u8; OPAQUE_SERVER_SETUP_BYTES]> = Zeroizing::new(
            serialized_setup
                .as_slice()
                .try_into()
                .map_err(|_| AuthError::InvalidEncoding)?,
        );
        let fake_record = build_fixed_fake_record(&setup_bytes, &mut rng)?;
        let dummy_login_state =
            build_dummy_login_state(&setup, &fake_record, network_id, &mut rng)?;
        if !rng.succeeded() {
            return Err(AuthError::EntropyUnavailable);
        }
        Ok(Self {
            setup: setup_bytes,
            fake_record,
            dummy_login_state,
        })
    }

    /// Restores validated setup and fake-record bytes, then refreshes dummy work state.
    pub fn from_serialized(
        network_id: NetworkId,
        setup_bytes: [u8; OPAQUE_SERVER_SETUP_BYTES],
        fake_record: [u8; OPAQUE_REGISTRATION_RECORD_BYTES],
    ) -> Result<Self, AuthError> {
        let setup_bytes = Zeroizing::new(setup_bytes);
        let fake_record = Zeroizing::new(fake_record);
        let setup = deserialize_setup(setup_bytes.as_ref())?;
        validate_fixed_fake_record(&fake_record)?;
        let dummy_public_key = setup_bytes.get(96..128).ok_or(AuthError::InvalidEncoding)?;
        let fake_public_key = fake_record.get(..32).ok_or(AuthError::InvalidEncoding)?;
        if !bool::from(dummy_public_key.ct_eq(fake_public_key)) {
            return Err(AuthError::InvalidEncoding);
        }
        let mut rng = FallibleOpaqueRng::new(OsEntropy);
        let dummy_login_state =
            build_dummy_login_state(&setup, &fake_record, network_id, &mut rng)?;
        if !rng.succeeded() {
            return Err(AuthError::EntropyUnavailable);
        }
        Ok(Self {
            setup: setup_bytes,
            fake_record,
            dummy_login_state,
        })
    }

    /// Borrows the setup bytes only for encrypted persistence.
    #[must_use]
    pub fn expose_setup_for_persistence(&self) -> &[u8; OPAQUE_SERVER_SETUP_BYTES] {
        &self.setup
    }

    /// Borrows the stable fake record only for encrypted persistence.
    #[must_use]
    pub fn expose_fake_record_for_persistence(&self) -> &[u8; OPAQUE_REGISTRATION_RECORD_BYTES] {
        &self.fake_record
    }

    /// Creates the exact registration response under this setup and credential ID.
    pub fn registration_start(
        &self,
        credential_id: &OpaqueCredentialId,
        request: &OpaqueRegistrationRequest,
    ) -> Result<OpaqueRegistrationResponse, AuthError> {
        let setup = deserialize_setup(self.setup.as_ref())?;
        let request = RegistrationRequest::<AgencOpaqueSuite>::deserialize(&request.0)
            .map_err(|_| AuthError::InvalidEncoding)?;
        let result = ServerRegistration::<AgencOpaqueSuite>::start(
            &setup,
            request,
            credential_id.expose_for_account_service(),
        )
        .map_err(|_| AuthError::AuthenticationFailed)?;
        let bytes = result
            .message
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidEncoding)?;
        Ok(OpaqueRegistrationResponse(bytes))
    }

    /// Starts one real-or-fake login through the same protocol-shaped path.
    pub fn authentication_start(
        &self,
        network_id: NetworkId,
        credential_id: &OpaqueCredentialId,
        record: Option<&OpaqueRegistrationRecord>,
        ke1: &OpaqueKe1,
    ) -> Result<(OpaqueKe2, OpaqueServerLoginState), AuthError> {
        let setup = deserialize_setup(self.setup.as_ref())?;
        let record_bytes = record.map_or(self.fake_record.as_ref(), |record| record.0.as_ref());
        let record = deserialize_record(record_bytes)?;
        let request = CredentialRequest::<AgencOpaqueSuite>::deserialize(&ke1.0)
            .map_err(|_| AuthError::InvalidEncoding)?;
        let context = opaque_context(&network_id);
        let parameters = server_parameters(&network_id, credential_id, &context);
        let mut rng = FallibleOpaqueRng::new(OsEntropy);
        let result = ServerLogin::<AgencOpaqueSuite>::start(
            &mut rng,
            &setup,
            Some(record),
            request,
            credential_id.expose_for_account_service(),
            parameters,
        );
        let result = opaque_rng_result(&rng, result)?;
        let message = result
            .message
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidEncoding)?;
        let serialized_state = Zeroizing::new(result.state.serialize());
        let state: Zeroizing<[u8; OPAQUE_SERVER_LOGIN_STATE_BYTES]> = Zeroizing::new(
            serialized_state
                .as_slice()
                .try_into()
                .map_err(|_| AuthError::InvalidEncoding)?,
        );
        Ok((OpaqueKe2(message), OpaqueServerLoginState(state)))
    }

    /// Performs indistinguishable KE3 verification for a missing transaction.
    pub fn dummy_finish_work(
        &self,
        network_id: NetworkId,
        credential_id: &OpaqueCredentialId,
        ke3: &OpaqueKe3,
    ) -> AuthError {
        let state = OpaqueServerLoginState(Zeroizing::new(*self.dummy_login_state));
        let _result = finish_authentication(network_id, credential_id, state, ke3);
        AuthError::AuthenticationFailed
    }
}

fn build_fixed_fake_record(
    setup_bytes: &[u8; OPAQUE_SERVER_SETUP_BYTES],
    rng: &mut FallibleOpaqueRng<OsEntropy>,
) -> Result<Zeroizing<[u8; OPAQUE_REGISTRATION_RECORD_BYTES]>, AuthError> {
    let dummy_public_key = setup_bytes.get(96..128).ok_or(AuthError::InvalidEncoding)?;
    let mut fake_record = Zeroizing::new([0_u8; OPAQUE_REGISTRATION_RECORD_BYTES]);
    let public_key = fake_record
        .get_mut(..32)
        .ok_or(AuthError::InvalidEncoding)?;
    public_key.copy_from_slice(dummy_public_key);
    let masking_key = fake_record
        .get_mut(32..96)
        .ok_or(AuthError::InvalidEncoding)?;
    rng.fill_bytes(masking_key);
    if !rng.succeeded() {
        return Err(AuthError::EntropyUnavailable);
    }
    validate_fixed_fake_record(&fake_record)?;
    Ok(fake_record)
}

fn validate_fixed_fake_record(
    fake_record: &[u8; OPAQUE_REGISTRATION_RECORD_BYTES],
) -> Result<(), AuthError> {
    let _record = deserialize_record(fake_record)?;
    let envelope = fake_record
        .get(FAKE_ENVELOPE_RANGE)
        .ok_or(AuthError::InvalidEncoding)?;
    if envelope.iter().any(|byte| *byte != 0) {
        return Err(AuthError::InvalidEncoding);
    }
    Ok(())
}

fn build_dummy_login_state(
    setup: &ServerSetup<AgencOpaqueSuite>,
    fake_record: &[u8; OPAQUE_REGISTRATION_RECORD_BYTES],
    network_id: NetworkId,
    rng: &mut FallibleOpaqueRng<OsEntropy>,
) -> Result<Zeroizing<[u8; OPAQUE_SERVER_LOGIN_STATE_BYTES]>, AuthError> {
    let client = ClientLogin::<AgencOpaqueSuite>::start(rng, DUMMY_CLIENT_PASSWORD);
    let client = opaque_rng_result(rng, client)?;
    let credential_id = OpaqueCredentialId::from_bytes([0_u8; 32]);
    let context = opaque_context(&network_id);
    let parameters = server_parameters(&network_id, &credential_id, &context);
    let result = ServerLogin::<AgencOpaqueSuite>::start(
        rng,
        setup,
        Some(deserialize_record(fake_record)?),
        client.message,
        credential_id.expose_for_account_service(),
        parameters,
    );
    let result = opaque_rng_result(rng, result)?;
    let serialized_state = Zeroizing::new(result.state.serialize());
    Ok(Zeroizing::new(
        serialized_state
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidEncoding)?,
    ))
}

fn opaque_rng_result<T, E, S: EntropySource>(
    rng: &FallibleOpaqueRng<S>,
    result: Result<T, E>,
) -> Result<T, AuthError> {
    if !rng.succeeded() {
        return Err(AuthError::EntropyUnavailable);
    }
    result.map_err(|_| AuthError::AuthenticationFailed)
}

fn deserialize_setup(bytes: &[u8]) -> Result<ServerSetup<AgencOpaqueSuite>, AuthError> {
    if bytes.len() != OPAQUE_SERVER_SETUP_BYTES {
        return Err(AuthError::InvalidEncoding);
    }
    ServerSetup::<AgencOpaqueSuite>::deserialize(bytes).map_err(|_| AuthError::InvalidEncoding)
}

fn deserialize_record(bytes: &[u8]) -> Result<ServerRegistration<AgencOpaqueSuite>, AuthError> {
    if bytes.len() != OPAQUE_REGISTRATION_RECORD_BYTES {
        return Err(AuthError::InvalidEncoding);
    }
    ServerRegistration::<AgencOpaqueSuite>::deserialize(bytes)
        .map_err(|_| AuthError::InvalidEncoding)
}

fn server_parameters<'a>(
    network_id: &'a NetworkId,
    credential_id: &'a OpaqueCredentialId,
    context: &'a [u8],
) -> ServerLoginParameters<'a, 'a> {
    ServerLoginParameters {
        context: Some(context),
        identifiers: opaque_identifiers(network_id, credential_id),
    }
}

/// Finishes one OPAQUE authentication and consumes its server state on any result.
pub fn finish_authentication(
    network_id: NetworkId,
    credential_id: &OpaqueCredentialId,
    state: OpaqueServerLoginState,
    ke3: &OpaqueKe3,
) -> Result<OpaqueAuthentication, AuthError> {
    let state = ServerLogin::<AgencOpaqueSuite>::deserialize(state.0.as_ref())
        .map_err(|_| AuthError::InvalidEncoding)?;
    let message = CredentialFinalization::<AgencOpaqueSuite>::deserialize(&ke3.0)
        .map_err(|_| AuthError::InvalidEncoding)?;
    let context = opaque_context(&network_id);
    let parameters = server_parameters(&network_id, credential_id, &context);
    let result = state
        .finish(message, parameters)
        .map_err(|_| AuthError::AuthenticationFailed)?;
    // The pinned suite hash fixes the session key at exactly 64 bytes, so the
    // copy below cannot mismatch; the library result zeroizes its own copy on
    // drop, and the owned array zeroizes with the authentication token.
    let mut session_key = Zeroizing::new([0_u8; 64]);
    session_key
        .as_mut()
        .copy_from_slice(result.session_key.as_slice());
    Ok(OpaqueAuthentication(session_key))
}

/// Validated exact registration request.
pub struct OpaqueRegistrationRequest([u8; OPAQUE_REGISTRATION_REQUEST_BYTES]);

impl OpaqueRegistrationRequest {
    /// Validates the canonical RFC 9807 serialization.
    pub fn from_bytes(bytes: [u8; OPAQUE_REGISTRATION_REQUEST_BYTES]) -> Result<Self, AuthError> {
        RegistrationRequest::<AgencOpaqueSuite>::deserialize(&bytes)
            .map_err(|_| AuthError::InvalidEncoding)?;
        Ok(Self(bytes))
    }

    /// Borrows the request only for the encrypted account-request codec.
    #[must_use]
    pub const fn expose_for_account_request(&self) -> &[u8; OPAQUE_REGISTRATION_REQUEST_BYTES] {
        &self.0
    }
}

/// Exact registration response carried only inside encrypted account-service data.
pub struct OpaqueRegistrationResponse([u8; OPAQUE_REGISTRATION_RESPONSE_BYTES]);

impl OpaqueRegistrationResponse {
    /// Validates the canonical RFC 9807 response serialization.
    pub fn from_bytes(bytes: [u8; OPAQUE_REGISTRATION_RESPONSE_BYTES]) -> Result<Self, AuthError> {
        RegistrationResponse::<AgencOpaqueSuite>::deserialize(&bytes)
            .map_err(|_| AuthError::InvalidEncoding)?;
        Ok(Self(bytes))
    }

    /// Borrows the response at the account-response codec boundary.
    #[must_use]
    pub const fn expose_for_account_response(&self) -> &[u8; OPAQUE_REGISTRATION_RESPONSE_BYTES] {
        &self.0
    }
}

/// Validated password file stored only inside encrypted coordinator records.
pub struct OpaqueRegistrationRecord(Zeroizing<[u8; OPAQUE_REGISTRATION_RECORD_BYTES]>);

impl OpaqueRegistrationRecord {
    /// Validates and takes ownership of the canonical RFC 9807 record.
    pub fn from_bytes(bytes: [u8; OPAQUE_REGISTRATION_RECORD_BYTES]) -> Result<Self, AuthError> {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }

    fn from_zeroizing(
        bytes: Zeroizing<[u8; OPAQUE_REGISTRATION_RECORD_BYTES]>,
    ) -> Result<Self, AuthError> {
        let _record = deserialize_record(bytes.as_ref())?;
        Ok(Self(bytes))
    }

    /// Borrows the record only for encrypted persistence.
    #[must_use]
    pub fn expose_for_persistence(&self) -> &[u8; OPAQUE_REGISTRATION_RECORD_BYTES] {
        &self.0
    }
}

/// Converts a validated registration upload into its stored password file.
pub fn finish_registration(
    upload: [u8; OPAQUE_REGISTRATION_RECORD_BYTES],
) -> Result<OpaqueRegistrationRecord, AuthError> {
    let upload = Zeroizing::new(upload);
    let upload = RegistrationUpload::<AgencOpaqueSuite>::deserialize(upload.as_ref())
        .map_err(|_| AuthError::InvalidEncoding)?;
    let record = ServerRegistration::<AgencOpaqueSuite>::finish(upload);
    let serialized_record = Zeroizing::new(record.serialize());
    OpaqueRegistrationRecord::from_zeroizing(Zeroizing::new(
        serialized_record
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidEncoding)?,
    ))
}

/// Validated exact KE1 request.
pub struct OpaqueKe1([u8; OPAQUE_KE1_BYTES]);

impl OpaqueKe1 {
    /// Validates the canonical RFC 9807 serialization.
    pub fn from_bytes(bytes: [u8; OPAQUE_KE1_BYTES]) -> Result<Self, AuthError> {
        CredentialRequest::<AgencOpaqueSuite>::deserialize(&bytes)
            .map_err(|_| AuthError::InvalidEncoding)?;
        Ok(Self(bytes))
    }

    /// Borrows KE1 only for the encrypted account-request codec.
    #[must_use]
    pub const fn expose_for_account_request(&self) -> &[u8; OPAQUE_KE1_BYTES] {
        &self.0
    }
}

/// Exact KE2 challenge carried only inside encrypted account-service data.
pub struct OpaqueKe2([u8; OPAQUE_KE2_BYTES]);

impl OpaqueKe2 {
    /// Validates the canonical RFC 9807 KE2 serialization.
    pub fn from_bytes(bytes: [u8; OPAQUE_KE2_BYTES]) -> Result<Self, AuthError> {
        CredentialResponse::<AgencOpaqueSuite>::deserialize(&bytes)
            .map_err(|_| AuthError::InvalidEncoding)?;
        Ok(Self(bytes))
    }

    /// Borrows the challenge at the account-response codec boundary.
    #[must_use]
    pub const fn expose_for_account_response(&self) -> &[u8; OPAQUE_KE2_BYTES] {
        &self.0
    }
}

/// Validated exact KE3 finalization message.
pub struct OpaqueKe3([u8; OPAQUE_KE3_BYTES]);

impl OpaqueKe3 {
    /// Validates the canonical RFC 9807 serialization.
    pub fn from_bytes(bytes: [u8; OPAQUE_KE3_BYTES]) -> Result<Self, AuthError> {
        CredentialFinalization::<AgencOpaqueSuite>::deserialize(&bytes)
            .map_err(|_| AuthError::InvalidEncoding)?;
        Ok(Self(bytes))
    }

    /// Borrows KE3 only for the encrypted account-request codec.
    #[must_use]
    pub const fn expose_for_account_request(&self) -> &[u8; OPAQUE_KE3_BYTES] {
        &self.0
    }
}

/// Move-only server state consumed by one authentication finish attempt.
pub struct OpaqueServerLoginState(Zeroizing<[u8; OPAQUE_SERVER_LOGIN_STATE_BYTES]>);

impl OpaqueServerLoginState {
    /// Validates restored encrypted transaction state.
    pub fn from_persisted_bytes(
        bytes: [u8; OPAQUE_SERVER_LOGIN_STATE_BYTES],
    ) -> Result<Self, AuthError> {
        let bytes = Zeroizing::new(bytes);
        ServerLogin::<AgencOpaqueSuite>::deserialize(bytes.as_ref())
            .map_err(|_| AuthError::InvalidEncoding)?;
        Ok(Self(bytes))
    }

    /// Borrows the state only for encrypted transaction persistence.
    #[must_use]
    pub fn expose_for_persistence(&self) -> &[u8; OPAQUE_SERVER_LOGIN_STATE_BYTES] {
        &self.0
    }
}

/// Proof that the coordinator completed and verified one OPAQUE exchange.
pub struct OpaqueAuthentication(Zeroizing<[u8; 64]>);

impl OpaqueAuthentication {
    /// Consumes the proof when authorizing the corresponding account transition.
    pub fn authorize_account_transition(self) {
        let _session_key = self.0;
    }
}

#[cfg(test)]
mod tests {
    use agenc_relay_crypto::OsEntropy;
    use agenc_relay_types::{EntropyError, EntropySource};
    use opaque_ke::rand::RngCore as _;

    use super::{
        AuthError, FallibleOpaqueRng, deserialize_record, deserialize_setup, opaque_rng_result,
    };

    struct Exhausted;

    impl EntropySource for Exhausted {
        fn fill_exact(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::Unavailable)
        }
    }

    #[test]
    fn latched_entropy_and_internal_lengths_fail_closed() {
        let mut rng = FallibleOpaqueRng::new(Exhausted);
        let mut bytes = [9_u8; 8];
        rng.fill_bytes(&mut bytes);
        assert!(!rng.succeeded());
        assert_eq!(
            opaque_rng_result::<(), (), _>(&rng, Ok(())).err(),
            Some(AuthError::EntropyUnavailable)
        );
        assert_eq!(
            opaque_rng_result::<(), (), _>(&rng, Err(())).err(),
            Some(AuthError::EntropyUnavailable)
        );
        let fresh = FallibleOpaqueRng::new(OsEntropy);
        assert_eq!(
            opaque_rng_result::<(), (), _>(&fresh, Err(())).err(),
            Some(AuthError::AuthenticationFailed)
        );

        assert_eq!(
            deserialize_setup(&[0_u8; 127]).err(),
            Some(AuthError::InvalidEncoding)
        );
        assert_eq!(
            deserialize_record(&[0_u8; 191]).err(),
            Some(AuthError::InvalidEncoding)
        );
    }
}
