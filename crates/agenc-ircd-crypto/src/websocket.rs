//! RFC 6455 upgrade digest over a public nonce and the fixed handshake GUID.
//!
//! This adapter is limited to the HTTP handshake. Authentication and protocol
//! identifiers continue to use their registered cryptographic profiles.

/// Computes only the RFC 6455 accept digest for a validated 24-byte key.
#[must_use]
pub fn websocket_accept_digest(key: &[u8; 24]) -> [u8; 20] {
    const GUID: &[u8; 36] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = [0_u8; 60];
    let (nonce, suffix) = input.split_at_mut(24);
    nonce.copy_from_slice(key);
    suffix.copy_from_slice(GUID);
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    let mut result = [0_u8; 20];
    result.copy_from_slice(digest.as_ref());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_upgrade_digest_matches_the_published_example() {
        assert_eq!(
            websocket_accept_digest(b"dGhlIHNhbXBsZSBub25jZQ=="),
            [
                0xb3, 0x7a, 0x4f, 0x2c, 0xc0, 0x62, 0x4f, 0x16, 0x90, 0xf6, 0x46, 0x06, 0xcf, 0x38,
                0x59, 0x45, 0xb2, 0xbe, 0xc4, 0xea,
            ]
        );
    }
}
