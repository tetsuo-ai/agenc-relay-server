//! Canonical unpadded URL-safe base64 for fixed-width administrative tokens.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::AdminError;

/// Encodes bytes in the canonical unpadded URL-safe alphabet.
#[must_use]
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Unpadded base64 text length for a fixed byte width.
pub(crate) const fn unpadded_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

/// Decodes exactly `N` bytes, accepting only the one canonical text form.
///
/// A decoded value must re-encode to the input bytes, so a token with
/// nonzero trailing bits or padding is rejected rather than normalized.
pub fn decode_fixed_base64url<const N: usize>(text: &[u8]) -> Result<[u8; N], AdminError> {
    if text.len() != unpadded_len(N) {
        return Err(AdminError::Token);
    }
    let mut bytes = [0_u8; N];
    let decoded = URL_SAFE_NO_PAD
        .decode_slice(text, &mut bytes)
        .map_err(|_| AdminError::Token)?;
    if decoded != N || encode_base64url(&bytes).as_bytes() != text {
        return Err(AdminError::Token);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{decode_fixed_base64url, encode_base64url, unpadded_len};
    use crate::AdminError;

    #[test]
    fn fixed_widths_round_trip_and_reject_noncanonical_forms() -> Result<(), AdminError> {
        assert_eq!(unpadded_len(16), 22);
        assert_eq!(unpadded_len(32), 43);
        assert_eq!(unpadded_len(64), 86);
        let token = [7_u8; 16];
        let text = encode_base64url(&token);
        assert_eq!(text.len(), 22);
        assert_eq!(decode_fixed_base64url::<16>(text.as_bytes())?, token);
        assert_eq!(
            decode_fixed_base64url::<16>(b"AAAAAAAAAAAAAAAAAAAAAB"),
            Err(AdminError::Token)
        );
        assert_eq!(
            decode_fixed_base64url::<16>(b"AAAAAAAAAAAAAAAAAAAAA"),
            Err(AdminError::Token)
        );
        assert_eq!(
            decode_fixed_base64url::<16>(b"AAAAAAAAAAAAAAAAAAAA=="),
            Err(AdminError::Token)
        );
        assert_eq!(
            decode_fixed_base64url::<16>(b"AAAAAAAAAAAAAAAAAAAA+/"),
            Err(AdminError::Token)
        );
        Ok(())
    }
}
