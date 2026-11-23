//! The shared endpoint names and public onboarding address types.

use agenc_relay_types::ServerName;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::ClientSupportError;

/// A validated lowercase DNS name (Section 7.4 server name grammar, spec 458-460).
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct DnsName(String);

impl DnsName {
    /// Parses through the shared `ServerName` grammar.
    pub fn parse(text: &str) -> Result<Self, ClientSupportError> {
        ServerName::parse(text).map_err(|_| ClientSupportError::InvalidValue)?;
        Ok(Self(text.to_owned()))
    }

    /// Borrows the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated version-3 onion address: 56 lowercase base32 characters and `.onion`.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct OnionAddress(String);

/// Length of the base32 label of a version-3 onion address (spec 8897).
pub const ONION_LABEL_BYTES: usize = 56;

impl OnionAddress {
    /// Parses the exact lowercase `<56 base32>.onion` form (spec 8897, 309-312).
    pub fn parse(text: &str) -> Result<Self, ClientSupportError> {
        let label = text
            .strip_suffix(".onion")
            .ok_or(ClientSupportError::InvalidValue)?;
        if label.len() != ONION_LABEL_BYTES
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        {
            return Err(ClientSupportError::InvalidValue);
        }
        Ok(Self(text.to_owned()))
    }

    /// Borrows the full address including `.onion`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The public DNS onboarding endpoint (spec 8895-8896).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsEndpoint {
    /// Lowercase RFC 9525 reference name.
    pub name: DnsName,
    /// TCP port, default 6697.
    pub port: u16,
}

/// The onion onboarding endpoint with its pinned SPKI hash (spec 8897-8899).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionEndpoint {
    /// Version-3 onion address.
    pub address: OnionAddress,
    /// Virtual port, default 6697.
    pub port: u16,
    /// Pinned certificate SPKI SHA-256.
    pub tls_spki_sha256: [u8; 32],
}

/// Parses a port in `1..=65_535`.
pub fn port(value: u64) -> Result<u16, ClientSupportError> {
    match u16::try_from(value) {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(ClientSupportError::InvalidValue),
    }
}

/// Parses a 43-character canonical unpadded base64url encoding of 32 bytes.
pub fn base64url_32(text: &str) -> Result<[u8; 32], ClientSupportError> {
    if text.len() != 43 {
        return Err(ClientSupportError::InvalidValue);
    }
    let mut bytes = [0_u8; 32];
    let decoded = URL_SAFE_NO_PAD
        .decode_slice(text, &mut bytes)
        .map_err(|_| ClientSupportError::InvalidValue)?;
    if decoded != bytes.len() || URL_SAFE_NO_PAD.encode(bytes) != text {
        return Err(ClientSupportError::InvalidValue);
    }
    Ok(bytes)
}

/// Encodes 32 bytes as the 43-character canonical unpadded base64url text.
#[must_use]
pub fn encode_base64url_32(bytes: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
