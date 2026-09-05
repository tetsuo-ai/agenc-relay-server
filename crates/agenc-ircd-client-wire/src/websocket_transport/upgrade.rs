use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::WebSocketSubprotocol;

/// Maximum backing capacity for the request line, headers, and delimiters.
pub const HTTP_UPGRADE_BYTES: usize = 2_048 + 16_384 + 4;
const REQUEST_LINE_BYTES: usize = 2_048;
const HEADER_LINE_BYTES: usize = 4_096;
const HEADER_BYTES: usize = 16_384;
const HEADER_FIELDS: usize = 64;

/// Closed rejection without retaining peer-supplied text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeError {
    /// Invalid request or forbidden HTTP feature.
    Malformed,
    /// Origin policy refused the request.
    Origin,
    /// Request target differs from `/irc`.
    Endpoint,
    /// The request method is not GET.
    Method,
    /// The peer did not request WebSocket version 13.
    Version,
    /// A header line, total block, or field count exceeds its limit.
    Headers,
    /// The request line exceeds its limit.
    RequestLine,
    /// The five-second upgrade deadline expired.
    Timeout,
}

impl UpgradeError {
    /// Fixed HTTP response, without peer values, cookies, or redirects.
    #[must_use]
    pub const fn response(self) -> &'static [u8] {
        match self {
            Self::Malformed => b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            Self::Origin => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            Self::Endpoint => b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            Self::Method => b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            Self::Version => b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            Self::Headers => b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            Self::RequestLine => b"HTTP/1.1 414 URI Too Long\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            Self::Timeout => b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        }
    }
}

/// Borrowed upgrade facts. The runtime evaluates Origin against its live policy.
pub struct UpgradeRequest<'a> {
    key: &'a [u8; 24],
    origin: Option<&'a str>,
    protocol: WebSocketSubprotocol,
}

impl UpgradeRequest<'_> {
    /// Validated standard-base64 nonce text used by the accept digest.
    #[must_use]
    pub const fn key(&self) -> &[u8; 24] {
        self.key
    }
    /// Exact Origin field after HTTP optional whitespace is removed.
    #[must_use]
    pub const fn origin(&self) -> Option<&str> {
        self.origin
    }
    /// First supported subprotocol in the client's preference order.
    #[must_use]
    pub const fn subprotocol(&self) -> WebSocketSubprotocol {
        self.protocol
    }
}

#[derive(Default)]
struct Fields<'a> {
    seen: u16,
    host: bool,
    upgrade: bool,
    connection: bool,
    key: Option<&'a [u8; 24]>,
    version: bool,
    origin: Option<&'a str>,
    protocol: Option<WebSocketSubprotocol>,
}

/// Parses one bounded HTTP request. `None` means more bytes are needed.
/// Request-line and field-line ceilings exclude CRLF; the total header
/// budget includes each field's CRLF and the final empty line.
pub fn parse_upgrade(input: &[u8]) -> Result<Option<UpgradeRequest<'_>>, UpgradeError> {
    let Some(end) = request_line(input)? else {
        return Ok(None);
    };
    let start = end + 2;
    let mut offset = start;
    let mut fields = Fields::default();
    let mut count = 0_usize;
    loop {
        let remaining = input.get(offset..).ok_or(UpgradeError::Malformed)?;
        if input.len().saturating_sub(start) > HEADER_BYTES {
            return Err(UpgradeError::Headers);
        }
        let Some(length) = line_end(remaining)? else {
            return if remaining.len() > HEADER_LINE_BYTES + 1 {
                Err(UpgradeError::Headers)
            } else {
                Ok(None)
            };
        };
        if length > HEADER_LINE_BYTES {
            return Err(UpgradeError::Headers);
        }
        offset += length + 2;
        if length == 0 {
            if offset != input.len() {
                return Err(UpgradeError::Malformed);
            }
            break;
        }
        count += 1;
        if count > HEADER_FIELDS {
            return Err(UpgradeError::Headers);
        }
        fields.accept(remaining.get(..length).ok_or(UpgradeError::Malformed)?)?;
    }
    fields.finish().map(Some)
}

fn request_line(input: &[u8]) -> Result<Option<usize>, UpgradeError> {
    let Some(end) = line_end(input)? else {
        return if input.len() > REQUEST_LINE_BYTES + 1 {
            Err(UpgradeError::RequestLine)
        } else {
            Ok(None)
        };
    };
    if end > REQUEST_LINE_BYTES {
        return Err(UpgradeError::RequestLine);
    }
    let line = input.get(..end).ok_or(UpgradeError::Malformed)?;
    let mut parts = line.split(|byte| *byte == b' ');
    if parts.next() != Some(b"GET".as_slice()) {
        return Err(UpgradeError::Method);
    }
    if parts.next() != Some(b"/irc".as_slice()) {
        return Err(UpgradeError::Endpoint);
    }
    if parts.next() != Some(b"HTTP/1.1".as_slice()) || parts.next().is_some() {
        return Err(UpgradeError::Malformed);
    }
    Ok(Some(end))
}

fn line_end(bytes: &[u8]) -> Result<Option<usize>, UpgradeError> {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            return Err(UpgradeError::Malformed);
        }
        if *byte == b'\r' {
            return match bytes.get(index + 1) {
                Some(b'\n') => Ok(Some(index)),
                Some(_) => Err(UpgradeError::Malformed),
                None => Ok(None),
            };
        }
    }
    Ok(None)
}

impl<'a> Fields<'a> {
    fn finish(self) -> Result<UpgradeRequest<'a>, UpgradeError> {
        if !self.host || !self.upgrade || !self.connection {
            return Err(UpgradeError::Malformed);
        }
        if !self.version {
            return Err(UpgradeError::Version);
        }
        Ok(UpgradeRequest {
            key: self.key.ok_or(UpgradeError::Malformed)?,
            origin: self.origin,
            protocol: self.protocol.ok_or(UpgradeError::Malformed)?,
        })
    }

    fn protocols(&mut self, value: &[u8]) -> Result<(), UpgradeError> {
        for token in tokens(value)? {
            let selected = match token {
                b"text.ircv3.net" => Some(WebSocketSubprotocol::TextIrcv3),
                b"binary.ircv3.net" => Some(WebSocketSubprotocol::BinaryIrcv3),
                _ => None,
            };
            if self.protocol.is_none() {
                self.protocol = selected;
            }
        }
        Ok(())
    }

    fn singleton(&mut self, bit: u16) -> Result<(), UpgradeError> {
        if self.seen & bit != 0 {
            return Err(UpgradeError::Malformed);
        }
        self.seen |= bit;
        Ok(())
    }

    fn accept(&mut self, line: &'a [u8]) -> Result<(), UpgradeError> {
        let (name, value) = header_field(line)?;
        reject_http_authority(name)?;
        if name.eq_ignore_ascii_case(b"host") {
            self.singleton(1)?;
            validate_host(value)?;
            self.host = true;
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            self.upgrade |= tokens(value)?.any(|token| token.eq_ignore_ascii_case(b"websocket"));
        } else if name.eq_ignore_ascii_case(b"connection") {
            self.connection |= tokens(value)?.any(|token| token.eq_ignore_ascii_case(b"upgrade"));
        } else if name.eq_ignore_ascii_case(b"sec-websocket-key") {
            self.singleton(2)?;
            let key = decode_key(value)?;
            self.key = Some(key);
        } else if name.eq_ignore_ascii_case(b"sec-websocket-version") {
            self.singleton(4)?;
            require_version(value)?;
            self.version = true;
        } else if name.eq_ignore_ascii_case(b"origin") {
            self.singleton(8)?;
            self.origin = Some(std::str::from_utf8(value).map_err(|_| UpgradeError::Malformed)?);
        } else if name.eq_ignore_ascii_case(b"sec-websocket-protocol") {
            self.protocols(value)?;
        } else if name.eq_ignore_ascii_case(b"content-length") {
            self.singleton(16)?;
            if value != b"0" {
                return Err(UpgradeError::Malformed);
            }
        }
        // Extension offers and unrelated headers are discarded. No extension is negotiated.
        Ok(())
    }
}

fn require_version(value: &[u8]) -> Result<(), UpgradeError> {
    if value != b"13" {
        return Err(UpgradeError::Version);
    }
    Ok(())
}

fn validate_host(value: &[u8]) -> Result<(), UpgradeError> {
    let value = std::str::from_utf8(value).map_err(|_| UpgradeError::Malformed)?;
    if let Some(literal) = value.strip_prefix('[') {
        let (address, suffix) = literal.split_once(']').ok_or(UpgradeError::Malformed)?;
        address
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| UpgradeError::Malformed)?;
        return host_port(suffix);
    }
    let (host, port) = value.split_once(':').map_or((value, ""), |(host, _)| {
        (host, value.get(host.len()..).unwrap_or_default())
    });
    host_port(port)?;
    if host.is_empty() || host.len() > 253 {
        return Err(UpgradeError::Malformed);
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.split('.').any(|label| !host_label(label)) {
        return Err(UpgradeError::Malformed);
    }
    Ok(())
}

fn host_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn host_port(suffix: &str) -> Result<(), UpgradeError> {
    if suffix.is_empty() {
        return Ok(());
    }
    let port = suffix.strip_prefix(':').ok_or(UpgradeError::Malformed)?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UpgradeError::Malformed);
    }
    port.parse::<u16>().map_err(|_| UpgradeError::Malformed)?;
    Ok(())
}

fn decode_key(value: &[u8]) -> Result<&[u8; 24], UpgradeError> {
    let key: &[u8; 24] = value.try_into().map_err(|_| UpgradeError::Malformed)?;
    let mut decoded = [0_u8; 16];
    if STANDARD
        .decode_slice(key, &mut decoded)
        .map_err(|_| UpgradeError::Malformed)?
        != 16
    {
        return Err(UpgradeError::Malformed);
    }
    Ok(key)
}

fn reject_http_authority(name: &[u8]) -> Result<(), UpgradeError> {
    if [
        b"cookie".as_slice(),
        b"authorization",
        b"proxy-authorization",
        b"transfer-encoding",
    ]
    .iter()
    .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
    {
        return Err(UpgradeError::Malformed);
    }
    Ok(())
}

fn header_field(line: &[u8]) -> Result<(&[u8], &[u8]), UpgradeError> {
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(UpgradeError::Malformed)?;
    let name = line.get(..colon).ok_or(UpgradeError::Malformed)?;
    if name.is_empty() || !name.iter().copied().all(token_byte) {
        return Err(UpgradeError::Malformed);
    }
    let value = trim(line.get(colon + 1..).ok_or(UpgradeError::Malformed)?);
    if value
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(UpgradeError::Malformed);
    }
    Ok((name, value))
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while let Some((b' ' | b'\t', rest)) = bytes.split_first() {
        bytes = rest;
    }
    while let Some((b' ' | b'\t', rest)) = bytes.split_last() {
        bytes = rest;
    }
    bytes
}

fn tokens(bytes: &[u8]) -> Result<impl Iterator<Item = &[u8]>, UpgradeError> {
    if bytes
        .split(|byte| *byte == b',')
        .map(trim)
        .any(|token| token.is_empty() || !token.iter().copied().all(token_byte))
    {
        return Err(UpgradeError::Malformed);
    }
    Ok(bytes.split(|byte| *byte == b',').map(trim))
}

/// Fixed-capacity successful upgrade response.
pub struct UpgradeResponse {
    bytes: [u8; 256],
    len: usize,
}
impl UpgradeResponse {
    /// Borrows only initialized response bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

/// Renders the RFC 6455 response using a digest from the crypto adapter.
pub fn upgrade_response(
    digest: &[u8; 20],
    protocol: WebSocketSubprotocol,
) -> Result<UpgradeResponse, UpgradeError> {
    let mut encoded = [0_u8; 28];
    STANDARD
        .encode_slice(digest, &mut encoded)
        .map_err(|_| UpgradeError::Malformed)?;
    let protocol = match protocol {
        WebSocketSubprotocol::TextIrcv3 => b"text.ircv3.net".as_slice(),
        WebSocketSubprotocol::BinaryIrcv3 => b"binary.ircv3.net".as_slice(),
    };
    let mut result = UpgradeResponse {
        bytes: [0; 256],
        len: 0,
    };
    for part in [b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ".as_slice(), &encoded,
        b"\r\nSec-WebSocket-Protocol: ", protocol, b"\r\n\r\n"] {
        let end = result.len.checked_add(part.len()).ok_or(UpgradeError::Malformed)?;
        result.bytes.get_mut(result.len..end).ok_or(UpgradeError::Malformed)?.copy_from_slice(part);
        result.len = end;
    }
    Ok(result)
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebSocket HTTP upgrade refused")
    }
}
impl std::error::Error for UpgradeError {}
