//! The client half of the exact OPAQUE profile.
//!
//! Registration and login start and finish over exact-size arrays. Every
//! message these calls produce is the exact RFC 9807 serialization that the
//! coordinator's validators take ([`crate::OpaqueRegistrationRequest`],
//! [`crate::OpaqueKe1`], [`crate::OpaqueKe3`] and
//! [`crate::OpaqueRegistrationRecord`]), and every server message they take
//! has the exact length of [`crate::OpaqueRegistrationResponse`] or
//! [`crate::OpaqueKe2`]. The suite, key-stretching function, context and
//! identities are the [`crate::profile`] ones.
//!
//! Passwords follow Architecture Section 11.1: valid UTF-8 (enforced by the
//! type) of 12 through 1,024 bytes, used exactly as given. The pinned library
//! zeroizes its client states when they drop but not the export and session
//! keys it returns, so each finish copies those keys into zeroizing arrays
//! and wipes the library's copies before it returns. Randomness comes from a
//! [`FallibleOpaqueRng`]; every call checks its latch after the library
//! returns and discards the library's result when a draw failed.

use std::error::Error;
use std::fmt;

use agenc_relay_types::{EntropySource, NetworkId, OpaqueCredentialId};
use opaque_ke::errors::ProtocolError;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use zeroize::{Zeroize as _, Zeroizing};

use crate::profile::{
    AgencOpaqueSuite, FallibleOpaqueRng, FixedArgon2id, OPAQUE_EXPORT_KEY_BYTES,
    OPAQUE_SESSION_KEY_BYTES, opaque_context, opaque_identifiers,
};
use crate::{
    OPAQUE_KE1_BYTES, OPAQUE_KE2_BYTES, OPAQUE_KE3_BYTES, OPAQUE_REGISTRATION_RECORD_BYTES,
    OPAQUE_REGISTRATION_REQUEST_BYTES, OPAQUE_REGISTRATION_RESPONSE_BYTES,
};

/// Fewest password bytes a native client accepts (Architecture Section 11.1).
pub const OPAQUE_PASSWORD_MIN_BYTES: usize = 12;
/// Most password bytes a native client accepts (Architecture Section 11.1).
pub const OPAQUE_PASSWORD_MAX_BYTES: usize = 1_024;

/// Closed, payload-free failures of the client OPAQUE calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpaqueClientError {
    /// The password is outside the 12 through 1,024 bytes of Section 11.1.
    InvalidPassword,
    /// The entropy source failed; the library's result was discarded.
    EntropyUnavailable,
    /// A server message is not its canonical RFC 9807 encoding, or it
    /// reflects the client's own blinded element.
    InvalidServerMessage,
    /// The library's invalid-login result for an authenticated, well-formed
    /// KE2: an unknown login or a wrong password. Section 11.4 requires the
    /// caller to send 64 fresh uniform bytes as the KE3 of the ordinary finish
    /// rather than abort the exchange.
    InvalidLogin,
    /// The pinned library or the key-stretching function failed internally.
    Internal,
}

impl fmt::Display for OpaqueClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPassword => "OPAQUE client password is outside the profile bounds",
            Self::EntropyUnavailable => "OPAQUE client entropy is unavailable",
            Self::InvalidServerMessage => "OPAQUE server message is invalid",
            Self::InvalidLogin => "OPAQUE login is invalid",
            Self::Internal => "OPAQUE client computation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for OpaqueClientError {}

/// Client registration state between [`registration_start`] and
/// [`registration_finish`]. Move-only; the library zeroizes it on drop.
pub struct OpaqueClientRegistration(ClientRegistration<AgencOpaqueSuite>);

/// Client login state between [`login_start`] and [`login_finish`].
/// Move-only; the library zeroizes it on drop.
pub struct OpaqueClientLogin(ClientLogin<AgencOpaqueSuite>);

/// A started registration (account creation or credential change).
pub struct ClientRegistrationStart {
    /// The exact 32-byte `RegistrationRequest` to send.
    pub request: [u8; OPAQUE_REGISTRATION_REQUEST_BYTES],
    /// The state that [`registration_finish`] consumes.
    pub state: OpaqueClientRegistration,
}

/// A finished registration.
pub struct ClientRegistrationFinish {
    /// The exact 192-byte `RegistrationRecord` (the library's
    /// `RegistrationUpload`) to send as the finish message.
    pub record: Zeroizing<[u8; OPAQUE_REGISTRATION_RECORD_BYTES]>,
    /// The client export key.
    pub export_key: Zeroizing<[u8; OPAQUE_EXPORT_KEY_BYTES]>,
}

/// A started login.
pub struct ClientLoginStart {
    /// The exact 96-byte KE1 to send.
    pub ke1: [u8; OPAQUE_KE1_BYTES],
    /// The state that [`login_finish`] consumes.
    pub state: OpaqueClientLogin,
}

/// A finished login in which the client authenticated the coordinator.
pub struct ClientLoginFinish {
    /// The exact 64-byte KE3 to send.
    pub ke3: [u8; OPAQUE_KE3_BYTES],
    /// The session key both halves derived.
    pub session_key: Zeroizing<[u8; OPAQUE_SESSION_KEY_BYTES]>,
    /// The client export key.
    pub export_key: Zeroizing<[u8; OPAQUE_EXPORT_KEY_BYTES]>,
}

/// Starts a registration with one password.
pub fn registration_start<E: EntropySource>(
    rng: &mut FallibleOpaqueRng<E>,
    password: &str,
) -> Result<ClientRegistrationStart, OpaqueClientError> {
    let password = profile_password(password)?;
    let started = ClientRegistration::<AgencOpaqueSuite>::start(rng, password);
    let started = latched(rng, started)?;
    Ok(ClientRegistrationStart {
        request: exact(started.message.serialize().as_slice())?,
        state: OpaqueClientRegistration(started.state),
    })
}

/// Finishes a registration against the coordinator's `RegistrationResponse`
/// for the credential ID the coordinator assigned.
pub fn registration_finish<E: EntropySource>(
    rng: &mut FallibleOpaqueRng<E>,
    state: OpaqueClientRegistration,
    password: &str,
    response: &[u8; OPAQUE_REGISTRATION_RESPONSE_BYTES],
    network_id: &NetworkId,
    credential_id: &OpaqueCredentialId,
) -> Result<ClientRegistrationFinish, OpaqueClientError> {
    let password = profile_password(password)?;
    let response = RegistrationResponse::<AgencOpaqueSuite>::deserialize(response)
        .map_err(|_| OpaqueClientError::InvalidServerMessage)?;
    let finished = state.0.finish(
        rng,
        password,
        response,
        ClientRegistrationFinishParameters::new(
            opaque_identifiers(network_id, credential_id),
            Some(&FixedArgon2id),
        ),
    );
    let mut finished = latched(rng, finished)?;
    let export_key = zeroizing_copy(finished.export_key.as_slice());
    finished.export_key.as_mut_slice().zeroize();
    let serialized = Zeroizing::new(finished.message.serialize());
    let record = Zeroizing::new(exact(serialized.as_slice())?);
    Ok(ClientRegistrationFinish {
        record,
        export_key: export_key?,
    })
}

/// Starts a login with one password.
pub fn login_start<E: EntropySource>(
    rng: &mut FallibleOpaqueRng<E>,
    password: &str,
) -> Result<ClientLoginStart, OpaqueClientError> {
    let password = profile_password(password)?;
    let started = ClientLogin::<AgencOpaqueSuite>::start(rng, password);
    let started = latched(rng, started)?;
    Ok(ClientLoginStart {
        ke1: exact(started.message.serialize().as_slice())?,
        state: OpaqueClientLogin(started.state),
    })
}

/// Finishes a login against the coordinator's KE2 for the credential ID the
/// coordinator returned with it.
///
/// An authenticated, well-formed KE2 that does not open under this password,
/// credential ID and Network ID is [`OpaqueClientError::InvalidLogin`]; a KE2
/// that does not decode or reflects the client's blinded element is
/// [`OpaqueClientError::InvalidServerMessage`].
pub fn login_finish<E: EntropySource>(
    rng: &mut FallibleOpaqueRng<E>,
    state: OpaqueClientLogin,
    password: &str,
    ke2: &[u8; OPAQUE_KE2_BYTES],
    network_id: &NetworkId,
    credential_id: &OpaqueCredentialId,
) -> Result<ClientLoginFinish, OpaqueClientError> {
    let password = profile_password(password)?;
    let response = CredentialResponse::<AgencOpaqueSuite>::deserialize(ke2)
        .map_err(|_| OpaqueClientError::InvalidServerMessage)?;
    let context = opaque_context(network_id);
    let finished = state.0.finish(
        rng,
        password,
        response,
        ClientLoginFinishParameters::new(
            Some(&context),
            opaque_identifiers(network_id, credential_id),
            Some(&FixedArgon2id),
        ),
    );
    let mut finished = latched(rng, finished)?;
    let session_key = zeroizing_copy(finished.session_key.as_slice());
    let export_key = zeroizing_copy(finished.export_key.as_slice());
    finished.session_key.as_mut_slice().zeroize();
    finished.export_key.as_mut_slice().zeroize();
    Ok(ClientLoginFinish {
        ke3: exact(finished.message.serialize().as_slice())?,
        session_key: session_key?,
        export_key: export_key?,
    })
}

fn profile_password(password: &str) -> Result<&[u8], OpaqueClientError> {
    let bytes = password.as_bytes();
    if (OPAQUE_PASSWORD_MIN_BYTES..=OPAQUE_PASSWORD_MAX_BYTES).contains(&bytes.len()) {
        Ok(bytes)
    } else {
        Err(OpaqueClientError::InvalidPassword)
    }
}

fn latched<T, E: EntropySource>(
    rng: &FallibleOpaqueRng<E>,
    result: Result<T, ProtocolError>,
) -> Result<T, OpaqueClientError> {
    if !rng.succeeded() {
        return Err(OpaqueClientError::EntropyUnavailable);
    }
    result.map_err(|error| match error {
        ProtocolError::InvalidLoginError => OpaqueClientError::InvalidLogin,
        ProtocolError::LibraryError(_) => OpaqueClientError::Internal,
        _ => OpaqueClientError::InvalidServerMessage,
    })
}

fn exact<const SIZE: usize>(bytes: &[u8]) -> Result<[u8; SIZE], OpaqueClientError> {
    bytes.try_into().map_err(|_| OpaqueClientError::Internal)
}

fn zeroizing_copy<const SIZE: usize>(
    bytes: &[u8],
) -> Result<Zeroizing<[u8; SIZE]>, OpaqueClientError> {
    if bytes.len() != SIZE {
        return Err(OpaqueClientError::Internal);
    }
    let mut copy = Zeroizing::new([0_u8; SIZE]);
    for (slot, byte) in copy.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    Ok(copy)
}

#[cfg(test)]
mod tests {
    use opaque_ke::errors::{InternalError, ProtocolError};

    use super::{
        OPAQUE_PASSWORD_MAX_BYTES, OPAQUE_PASSWORD_MIN_BYTES, OpaqueClientError, exact,
        profile_password, zeroizing_copy,
    };

    #[test]
    fn password_bounds_are_the_section_eleven_one_bounds() {
        let shortest = "a".repeat(OPAQUE_PASSWORD_MIN_BYTES);
        let longest = "a".repeat(OPAQUE_PASSWORD_MAX_BYTES);
        assert!(profile_password(&shortest).is_ok());
        assert!(profile_password(&longest).is_ok());
        for refused in [
            String::new(),
            "a".repeat(OPAQUE_PASSWORD_MIN_BYTES - 1),
            "a".repeat(OPAQUE_PASSWORD_MAX_BYTES + 1),
        ] {
            assert_eq!(
                profile_password(&refused).err(),
                Some(OpaqueClientError::InvalidPassword)
            );
        }
        // Bytes, not characters: six two-byte characters reach the minimum
        // and 513 exceed the maximum.
        assert!(profile_password(&"é".repeat(6)).is_ok());
        assert!(profile_password(&"é".repeat(513)).is_err());
    }

    #[test]
    fn library_results_map_to_closed_client_failures() {
        let rng = crate::profile::FallibleOpaqueRng::new(agenc_relay_crypto::OsEntropy);
        let classify = |error: ProtocolError| super::latched::<(), _>(&rng, Err(error)).err();
        assert_eq!(
            classify(ProtocolError::InvalidLoginError),
            Some(OpaqueClientError::InvalidLogin)
        );
        assert_eq!(
            classify(ProtocolError::LibraryError(InternalError::KsfError)),
            Some(OpaqueClientError::Internal)
        );
        for error in [
            ProtocolError::ReflectedValueError,
            ProtocolError::SerializationError,
            ProtocolError::SizeError {
                name: "test",
                len: 1,
                actual_len: 2,
            },
        ] {
            assert_eq!(
                classify(error),
                Some(OpaqueClientError::InvalidServerMessage)
            );
        }
        assert_eq!(
            exact::<4>(&[1, 2, 3]).err(),
            Some(OpaqueClientError::Internal)
        );
        assert!(zeroizing_copy::<4>(&[1, 2, 3]).is_err());
        assert_eq!(
            zeroizing_copy::<3>(&[1, 2, 3]).map(|copy| *copy).ok(),
            Some([1, 2, 3])
        );
        for error in [
            OpaqueClientError::InvalidPassword,
            OpaqueClientError::EntropyUnavailable,
            OpaqueClientError::InvalidServerMessage,
            OpaqueClientError::InvalidLogin,
            OpaqueClientError::Internal,
        ] {
            assert!(error.to_string().starts_with("OPAQUE "));
        }
    }
}
