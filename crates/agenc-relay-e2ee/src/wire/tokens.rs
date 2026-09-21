//! Canonical wire tokens (companion Section 11.10): unpadded base64url with
//! canonical unused bits, fixed-width identifier tokens, and decimals without
//! a leading zero.

use crate::error::E2eeError;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Characters in a 16-byte identifier token.
pub const ID16_CHARS: usize = 22;
/// Characters in a 32-byte hash token.
pub const HASH_CHARS: usize = 43;
/// Characters in a 24-byte Account ID token.
pub const ACCOUNT_CHARS: usize = 32;
/// The longest `key-package-ref` token (255 decoded bytes).
pub const MAX_KEY_PACKAGE_REF_CHARS: usize = 340;
/// The longest `safe-label` and `batch-id`.
pub const MAX_LABEL_CHARS: usize = 64;

/// Whether `byte` is in the base64url alphabet.
#[must_use]
pub const fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

const fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn alphabet_char(index: u32) -> char {
    ALPHABET
        .get((index & 63) as usize)
        .map_or('A', |byte| char::from(*byte))
}

fn push_word(out: &mut String, word: u32, chars: usize) {
    for shift in [18, 12, 6, 0].into_iter().take(chars) {
        out.push(alphabet_char(word >> shift));
    }
}

/// Encodes `bytes` as unpadded base64url.
#[must_use]
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let (chunks, tail) = bytes.as_chunks::<3>();
    for [a, b, c] in chunks {
        let word = u32::from(*a) << 16 | u32::from(*b) << 8 | u32::from(*c);
        push_word(&mut out, word, 4);
    }
    match tail {
        [a] => push_word(&mut out, u32::from(*a) << 16, 2),
        [a, b] => push_word(&mut out, u32::from(*a) << 16 | u32::from(*b) << 8, 3),
        _ => {}
    }
    out
}

/// Decodes unpadded base64url, refusing padding, a one-character tail, and
/// nonzero unused bits, so that re-encoding reproduces `text` exactly.
pub fn base64url_decode(text: &str) -> Result<Vec<u8>, E2eeError> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(E2eeError::NonCanonical);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    let (chunks, tail) = bytes.as_chunks::<4>();
    for chunk in chunks {
        let word = word_of(chunk)?;
        out.extend_from_slice(&[(word >> 16) as u8, (word >> 8) as u8, word as u8]);
    }
    let unused_bits = match tail.len() {
        0 => 0,
        2 => 4,
        _ => 2,
    };
    if tail.is_empty() {
        return Ok(out);
    }
    let word = word_of(tail)?;
    let shift = 6 * u32::try_from(tail.len()).map_err(|_| E2eeError::Overflow)?;
    if word & ((1 << unused_bits) - 1) != 0 {
        return Err(E2eeError::NonCanonical);
    }
    let value = word >> unused_bits;
    let width = (shift - unused_bits) / 8;
    for index in (0..width).rev() {
        out.push((value >> (8 * index)) as u8);
    }
    Ok(out)
}

fn word_of(chars: &[u8]) -> Result<u32, E2eeError> {
    chars.iter().try_fold(0_u32, |word, byte| {
        let value = sextet(*byte).ok_or(E2eeError::InvalidValue)?;
        Ok(word << 6 | u32::from(value))
    })
}

/// Decodes a token that must hold exactly `N` bytes.
pub fn decode_fixed<const N: usize>(text: &str) -> Result<[u8; N], E2eeError> {
    if text.len() != (N * 8).div_ceil(6) {
        return Err(E2eeError::LengthOutOfRange);
    }
    let bytes = base64url_decode(text)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| E2eeError::LengthOutOfRange)
}

/// Parses an `id16-token`.
pub fn parse_id16(text: &str) -> Result<[u8; 16], E2eeError> {
    decode_fixed::<16>(text)
}

/// Parses a `hash-token`.
pub fn parse_hash(text: &str) -> Result<[u8; 32], E2eeError> {
    decode_fixed::<32>(text)
}

/// Parses an `account-token`.
pub fn parse_account(text: &str) -> Result<[u8; 24], E2eeError> {
    decode_fixed::<24>(text)
}

/// Parses a `key-package-ref` token of 1 to 255 decoded bytes.
pub fn parse_key_package_ref(text: &str) -> Result<Vec<u8>, E2eeError> {
    if text.is_empty() || text.len() > MAX_KEY_PACKAGE_REF_CHARS {
        return Err(E2eeError::LengthOutOfRange);
    }
    let bytes = base64url_decode(text)?;
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(E2eeError::LengthOutOfRange);
    }
    Ok(bytes)
}

/// Parses a `cursor`: `*` or a hash token.
pub fn parse_cursor(text: &str) -> Result<Option<[u8; 32]>, E2eeError> {
    if text == "*" {
        return Ok(None);
    }
    parse_hash(text).map(Some)
}

fn parse_decimal(text: &str, max_digits: usize) -> Result<u64, E2eeError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > max_digits || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(E2eeError::InvalidValue);
    }
    if bytes.len() > 1 && bytes.first() == Some(&b'0') {
        return Err(E2eeError::NonCanonical);
    }
    text.parse::<u64>().map_err(|_| E2eeError::Overflow)
}

/// Parses a `uint16-dec`.
pub fn parse_u16(text: &str) -> Result<u16, E2eeError> {
    u16::try_from(parse_decimal(text, 5)?).map_err(|_| E2eeError::Overflow)
}

/// Parses a `uint32-dec`.
pub fn parse_u32(text: &str) -> Result<u32, E2eeError> {
    u32::try_from(parse_decimal(text, 10)?).map_err(|_| E2eeError::Overflow)
}

/// Parses a `uint64-dec`.
pub fn parse_u64(text: &str) -> Result<u64, E2eeError> {
    parse_decimal(text, 20)
}

/// Whether a raw `label` value is a `safe-label` (no escape can expand it).
#[must_use]
pub fn is_safe_label(raw: &str) -> bool {
    !raw.is_empty() && raw.len() <= MAX_LABEL_CHARS && raw.bytes().all(is_base64url_byte)
}

/// Whether `text` is a `batch-id`.
#[must_use]
pub fn is_batch_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_LABEL_CHARS
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Renders a cursor.
#[must_use]
pub fn render_cursor(cursor: Option<&[u8; 32]>) -> String {
    cursor.map_or_else(|| "*".to_owned(), |hash| base64url_encode(hash))
}

#[cfg(test)]
#[path = "../tests/tokens.rs"]
mod tests;
