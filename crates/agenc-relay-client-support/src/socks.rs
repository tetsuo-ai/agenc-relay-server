//! Bounded SOCKS5 wire helpers for username/password stream isolation.
//!
//! The caller owns socket I/O, timeouts, and selection of a validated
//! destination. These helpers never resolve or dial a destination.

use std::fmt;

use agenc_relay_types::EntropySource;
use zeroize::Zeroizing;

const SOCKS_VERSION: u8 = 5;
const SOCKS_USERNAME_PASSWORD: u8 = 2;
const SOCKS_CONNECT: u8 = 1;
const SOCKS_HOSTNAME: u8 = 3;
const USERNAME_PASSWORD_VERSION: u8 = 1;
const ISOLATION_CREDENTIAL_BYTES: u8 = 32;
const MAX_SOCKS_HOSTNAME_BYTES: usize = 255;
const PORT_BYTES: usize = 2;

/// The greeting offers only username/password stream isolation.
pub const ISOLATION_GREETING: [u8; 3] = [SOCKS_VERSION, 1, SOCKS_USERNAME_PASSWORD];
/// Space for the largest domain-form reply tail, including its port.
pub const MAX_DOMAIN_REPLY_TAIL_BYTES: usize = 255 + PORT_BYTES;

/// Bounded, content-free failures in the SOCKS codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksError {
    /// Fresh isolation credentials could not be obtained.
    EntropyUnavailable,
    /// A bounded allocation could not be reserved.
    ResourceUnavailable,
    /// The proxy bytes or destination arguments do not satisfy the grammar.
    InvalidReply,
    /// The proxy rejected the isolation method or credentials.
    AuthenticationRefused,
    /// Tor refused the destination.
    TargetRefused,
}

impl fmt::Display for SocksError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EntropyUnavailable => "SOCKS isolation entropy unavailable",
            Self::ResourceUnavailable => "SOCKS resources unavailable",
            Self::InvalidReply => "invalid SOCKS request or reply",
            Self::AuthenticationRefused => "SOCKS isolation refused",
            Self::TargetRefused => "SOCKS destination refused",
        })
    }
}

impl std::error::Error for SocksError {}

/// An opaque, wipe-on-drop username and password for one isolation context.
pub struct IsolationCredentials {
    username: Zeroizing<[u8; ISOLATION_CREDENTIAL_BYTES as usize]>,
    password: Zeroizing<[u8; ISOLATION_CREDENTIAL_BYTES as usize]>,
}

impl IsolationCredentials {
    /// Draws the exact independent credential fields from the caller's entropy.
    pub fn draw(entropy: &mut impl EntropySource) -> Result<Self, SocksError> {
        let mut username = Zeroizing::new([0_u8; ISOLATION_CREDENTIAL_BYTES as usize]);
        let mut password = Zeroizing::new([0_u8; ISOLATION_CREDENTIAL_BYTES as usize]);
        entropy
            .fill_exact(username.as_mut())
            .map_err(|_| SocksError::EntropyUnavailable)?;
        entropy
            .fill_exact(password.as_mut())
            .map_err(|_| SocksError::EntropyUnavailable)?;
        Ok(Self { username, password })
    }

    /// Checks whether a candidate duplicates a credential the caller owns.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.username.as_ref() == other.username.as_ref()
            && self.password.as_ref() == other.password.as_ref()
    }

    /// Builds the RFC 1929 request into a wipe-on-drop buffer.
    pub fn authentication_request(&self) -> Result<AuthenticationRequest, SocksError> {
        let mut request = Zeroizing::new(Vec::new());
        request
            .try_reserve_exact(3 + (2 * usize::from(ISOLATION_CREDENTIAL_BYTES)))
            .map_err(|_| SocksError::ResourceUnavailable)?;
        request.push(USERNAME_PASSWORD_VERSION);
        request.push(ISOLATION_CREDENTIAL_BYTES);
        request.extend_from_slice(self.username.as_ref());
        request.push(ISOLATION_CREDENTIAL_BYTES);
        request.extend_from_slice(self.password.as_ref());
        Ok(AuthenticationRequest(request))
    }
}

/// Encoded secret authentication bytes, kept only while the caller writes them.
pub struct AuthenticationRequest(Zeroizing<Vec<u8>>);

impl AuthenticationRequest {
    /// Borrows the authentication packet for transmission to the local proxy.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Requires the proxy to select the offered username/password method.
pub const fn check_method_selection([version, method]: [u8; 2]) -> Result<(), SocksError> {
    if version != SOCKS_VERSION {
        return Err(SocksError::InvalidReply);
    }
    if method != SOCKS_USERNAME_PASSWORD {
        return Err(SocksError::AuthenticationRefused);
    }
    Ok(())
}

/// Requires the RFC 1929 success response.
pub const fn check_authentication_reply([version, status]: [u8; 2]) -> Result<(), SocksError> {
    if version != USERNAME_PASSWORD_VERSION {
        return Err(SocksError::InvalidReply);
    }
    if status != 0 {
        return Err(SocksError::AuthenticationRefused);
    }
    Ok(())
}

/// Encodes a hostname-form SOCKS5 CONNECT for a validated destination.
pub fn hostname_request(hostname: &str, port: u16) -> Result<Vec<u8>, SocksError> {
    let hostname = hostname.as_bytes();
    if hostname.is_empty()
        || hostname.len() > MAX_SOCKS_HOSTNAME_BYTES
        || !hostname.is_ascii()
        || port == 0
    {
        return Err(SocksError::InvalidReply);
    }
    let hostname_length = u8::try_from(hostname.len()).map_err(|_| SocksError::InvalidReply)?;
    let mut request = Vec::new();
    request
        .try_reserve_exact(7 + hostname.len())
        .map_err(|_| SocksError::ResourceUnavailable)?;
    request.extend_from_slice(&[
        SOCKS_VERSION,
        SOCKS_CONNECT,
        0,
        SOCKS_HOSTNAME,
        hostname_length,
    ]);
    request.extend_from_slice(hostname);
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

/// The address form on a successful CONNECT reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectReplyTail {
    /// Four address octets and two port octets.
    Ipv4,
    /// Sixteen address octets and two port octets.
    Ipv6,
    /// A length octet, that many domain octets, and two port octets.
    Domain,
}

/// Interprets the fixed CONNECT response header before reading its bounded tail.
pub const fn check_connect_reply(
    [version, reply, reserved, address_type]: [u8; 4],
) -> Result<ConnectReplyTail, SocksError> {
    if version != SOCKS_VERSION || reserved != 0 || reply > 8 {
        return Err(SocksError::InvalidReply);
    }
    if reply != 0 {
        return Err(SocksError::TargetRefused);
    }
    match address_type {
        1 => Ok(ConnectReplyTail::Ipv4),
        4 => Ok(ConnectReplyTail::Ipv6),
        SOCKS_HOSTNAME => Ok(ConnectReplyTail::Domain),
        _ => Err(SocksError::InvalidReply),
    }
}

/// Returns the bounded length of the domain and port after the length octet.
pub fn domain_reply_tail_length(length: u8) -> Result<usize, SocksError> {
    if length == 0 {
        return Err(SocksError::InvalidReply);
    }
    Ok(usize::from(length) + PORT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_relay_types::EntropyError;

    struct FixtureEntropy(u8);

    impl EntropySource for FixtureEntropy {
        fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.0);
            self.0 ^= 0xff;
            Ok(())
        }
    }

    #[test]
    fn isolation_authentication_is_the_exact_username_password_packet() -> Result<(), SocksError> {
        let credentials = IsolationCredentials::draw(&mut FixtureEntropy(0x51))?;
        let same = IsolationCredentials::draw(&mut FixtureEntropy(0x51))?;
        let different = IsolationCredentials::draw(&mut FixtureEntropy(0x52))?;
        assert!(credentials.matches(&same));
        assert!(!credentials.matches(&different));
        assert_eq!(ISOLATION_GREETING, [5, 1, 2]);
        let request = credentials.authentication_request()?;
        let mut expected = vec![1, 32];
        expected.extend([0x51; 32]);
        expected.push(32);
        expected.extend([0xae; 32]);
        assert_eq!(request.as_bytes(), &expected);
        Ok(())
    }

    #[test]
    fn connect_has_the_hostname_address_type_and_network_order_port() -> Result<(), SocksError> {
        let mut expected = vec![5, 1, 0, 3, 12];
        expected.extend_from_slice(b"chat.example");
        expected.extend_from_slice(&[0x1a, 0x29]);
        assert_eq!(hostname_request("chat.example", 6697)?, expected);
        assert_eq!(hostname_request("", 6697), Err(SocksError::InvalidReply));
        assert_eq!(
            hostname_request(&"x".repeat(256), 6697),
            Err(SocksError::InvalidReply)
        );
        assert_eq!(
            hostname_request("chat.example", 0),
            Err(SocksError::InvalidReply)
        );
        Ok(())
    }

    #[test]
    fn reply_validators_keep_malformed_and_refused_results_distinct() {
        assert_eq!(check_method_selection([5, 2]), Ok(()));
        assert_eq!(
            check_method_selection([5, 0]),
            Err(SocksError::AuthenticationRefused)
        );
        assert_eq!(
            check_method_selection([4, 2]),
            Err(SocksError::InvalidReply)
        );
        assert_eq!(check_authentication_reply([1, 0]), Ok(()));
        assert_eq!(
            check_authentication_reply([1, 1]),
            Err(SocksError::AuthenticationRefused)
        );
        assert_eq!(
            check_connect_reply([5, 0, 0, 1]),
            Ok(ConnectReplyTail::Ipv4)
        );
        assert_eq!(
            check_connect_reply([5, 0, 0, 4]),
            Ok(ConnectReplyTail::Ipv6)
        );
        assert_eq!(
            check_connect_reply([5, 0, 0, 3]),
            Ok(ConnectReplyTail::Domain)
        );
        assert_eq!(
            check_connect_reply([5, 1, 0, 0]),
            Err(SocksError::TargetRefused)
        );
        assert_eq!(
            check_connect_reply([5, 0, 1, 1]),
            Err(SocksError::InvalidReply)
        );
        assert_eq!(domain_reply_tail_length(0), Err(SocksError::InvalidReply));
        assert_eq!(domain_reply_tail_length(255), Ok(257));
    }
}
