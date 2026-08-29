//! Canonical scalar parsers shared by every table module.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use agenc_ircd_types::ServerName;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::ConfigError;

/// An inclusive unsigned range with its default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bound {
    /// The value used when the key is omitted.
    pub default: u64,
    /// The inclusive minimum.
    pub minimum: u64,
    /// The inclusive maximum.
    pub maximum: u64,
}

impl Bound {
    /// Builds one closed range.
    #[must_use]
    pub const fn new(minimum: u64, default: u64, maximum: u64) -> Self {
        Self {
            default,
            minimum,
            maximum,
        }
    }

    /// Returns the default when the value is absent, or the range-checked value.
    pub fn resolve(self, value: Option<u64>) -> Result<u64, ConfigError> {
        let value = value.unwrap_or(self.default);
        if !(self.minimum..=self.maximum).contains(&value) {
            return Err(ConfigError::InvalidValue);
        }
        Ok(value)
    }

    /// Requires an optional value to equal the fixed default when present.
    pub fn fixed(self, value: Option<u64>) -> Result<u64, ConfigError> {
        match value {
            None => Ok(self.default),
            Some(value) if value == self.default => Ok(value),
            Some(_) => Err(ConfigError::InvalidValue),
        }
    }
}

/// Parses a 43-character canonical unpadded base64url encoding of 32 bytes.
pub(crate) fn base64url_32(text: &str) -> Result<[u8; 32], ConfigError> {
    if text.len() != 43 {
        return Err(ConfigError::InvalidValue);
    }
    let mut bytes = [0_u8; 32];
    let decoded = URL_SAFE_NO_PAD
        .decode_slice(text, &mut bytes)
        .map_err(|_| ConfigError::InvalidValue)?;
    if decoded != bytes.len() || URL_SAFE_NO_PAD.encode(bytes) != text {
        return Err(ConfigError::InvalidValue);
    }
    Ok(bytes)
}

/// Encodes 32 bytes as the 43-character canonical unpadded base64url text.
#[must_use]
pub fn encode_base64url_32(bytes: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Validates an ASCII identifier of `[A-Za-z0-9._-]` within a byte range.
pub(crate) fn ascii_identifier(
    text: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ConfigError> {
    if !(minimum..=maximum).contains(&text.len()) {
        return Err(ConfigError::InvalidValue);
    }
    if text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(ConfigError::InvalidValue)
    }
}

/// A validated lowercase DNS name (Section 7.4 server name grammar, spec 458-460).
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct DnsName(String);

impl DnsName {
    /// Parses through the shared `ServerName` grammar.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        ServerName::parse(text).map_err(|_| ConfigError::InvalidValue)?;
        Ok(Self(text.to_owned()))
    }

    /// Borrows the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Parses a lowercase RFC 9525 reference DNS name through the shared grammar.
pub(crate) fn dns_name(text: &str) -> Result<DnsName, ConfigError> {
    DnsName::parse(text)
}

/// A validated version-3 onion address: 56 lowercase base32 characters and `.onion`.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct OnionAddress(String);

/// Length of the base32 label of a version-3 onion address (spec 8897).
pub const ONION_LABEL_BYTES: usize = 56;

impl OnionAddress {
    /// Parses the exact lowercase `<56 base32>.onion` form (spec 8897, 309-312).
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let label = text
            .strip_suffix(".onion")
            .ok_or(ConfigError::InvalidValue)?;
        if label.len() != ONION_LABEL_BYTES
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        {
            return Err(ConfigError::InvalidValue);
        }
        Ok(Self(text.to_owned()))
    }

    /// Borrows the full address including `.onion`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Parses an exact literal unicast IP and port (spec 8951-8953).
pub(crate) fn socket_bind(text: &str) -> Result<SocketAddr, ConfigError> {
    let address: SocketAddr = text.parse().map_err(|_| ConfigError::InvalidValue)?;
    if address.port() == 0 || !is_unicast_literal(address.ip()) {
        return Err(ConfigError::InvalidValue);
    }
    Ok(address)
}

/// Rejects unspecified, multicast, and IPv4 broadcast addresses.
fn is_unicast_literal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_multicast() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

/// Parses a port in `1..=65_535`.
pub(crate) fn port(value: u64) -> Result<u16, ConfigError> {
    match u16::try_from(value) {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(ConfigError::InvalidValue),
    }
}

/// A validated exact HTTPS origin such as `https://chat.example` (spec 8935, 531).
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct HttpsOrigin(String);

impl HttpsOrigin {
    /// Parses `https://<lowercase host>[:port]` with no path, query, or userinfo.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let authority = text
            .strip_prefix("https://")
            .ok_or(ConfigError::InvalidValue)?;
        let (host, port_text) = split_authority(authority);
        if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(ConfigError::InvalidValue);
        }
        origin_host(host)?;
        if let Some(port_text) = port_text {
            let parsed: u64 = port_text.parse().map_err(|_| ConfigError::InvalidValue)?;
            port(parsed)?;
        }
        Ok(Self(text.to_owned()))
    }

    /// Borrows the exact origin text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A federation peer dial endpoint (spec 2944-2945).
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum PeerEndpoint {
    /// `tcp:<literal-ip>:<port>` with IPv6 in brackets.
    Tcp(SocketAddr),
    /// `onion:<56-character-v3-name>.onion:<port>`.
    Onion {
        /// The version-3 onion name.
        address: OnionAddress,
        /// The virtual port.
        port: u16,
    },
}

impl PeerEndpoint {
    /// Parses the exact Section 20.2 endpoint grammar.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        if let Some(rest) = text.strip_prefix("tcp:") {
            return socket_bind(rest).map(Self::Tcp);
        }
        let rest = text
            .strip_prefix("onion:")
            .ok_or(ConfigError::InvalidValue)?;
        let (name, port_text) = rest.rsplit_once(':').ok_or(ConfigError::InvalidValue)?;
        let parsed: u64 = port_text.parse().map_err(|_| ConfigError::InvalidValue)?;
        Ok(Self::Onion {
            address: OnionAddress::parse(name)?,
            port: port(parsed)?,
        })
    }
}

/// The local Tor SOCKS proxy endpoint (spec 8977).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SocksEndpoint {
    /// A loopback IP and port.
    Loopback(SocketAddr),
    /// An absolute Unix socket path.
    Unix(std::path::PathBuf),
}

/// Splits `host[:port]`; a bracketed IPv6 literal without a port keeps its colons.
fn split_authority(authority: &str) -> (&str, Option<&str>) {
    match authority.rsplit_once(':') {
        Some((host, port_text)) if !port_text.contains(']') => (host, Some(port_text)),
        _ => (authority, None),
    }
}

/// An origin host is a lowercase DNS name, an IPv4 literal, or a bracketed IPv6 literal.
fn origin_host(host: &str) -> Result<(), ConfigError> {
    if let Some(inner) = host.strip_prefix('[') {
        let literal = inner.strip_suffix(']').ok_or(ConfigError::InvalidValue)?;
        return literal
            .parse::<Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| ConfigError::InvalidValue);
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    dns_name(host).map(|_| ())
}

impl SocksEndpoint {
    /// Parses a loopback `ip:port` or an absolute Unix path.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        if text.starts_with('/') {
            return crate::paths::absolute_path(text).map(Self::Unix);
        }
        let address = socket_bind(text)?;
        if !address.ip().is_loopback() {
            return Err(ConfigError::InvalidValue);
        }
        Ok(Self::Loopback(address))
    }
}

/// Parses a closed lowercase enumeration by exact name.
pub(crate) fn closed_enum<T: Copy>(text: &str, choices: &[(&str, T)]) -> Result<T, ConfigError> {
    choices
        .iter()
        .find(|(name, _)| *name == text)
        .map(|(_, value)| *value)
        .ok_or(ConfigError::InvalidValue)
}

/// Converts a bounded unsigned value into `u32`.
pub(crate) fn as_u32(value: u64) -> Result<u32, ConfigError> {
    u32::try_from(value).map_err(|_| ConfigError::InvalidValue)
}

/// Rejects duplicate elements in a small unsigned array.
pub(crate) fn unique_unsigned(values: &[u64]) -> Result<(), ConfigError> {
    for (position, value) in values.iter().enumerate() {
        if values
            .get(..position)
            .is_some_and(|earlier| earlier.contains(value))
        {
            return Err(ConfigError::InvalidValue);
        }
    }
    Ok(())
}
