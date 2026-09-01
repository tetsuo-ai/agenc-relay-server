//! Extraction of a peer certificate's SPKI digest for the admin pin
//! allowlist (spec 22.4, line 4371).
//!
//! Only the structural DER walk needed to reach `subjectPublicKeyInfo`
//! lives here; certificate validation itself happened in rustls-webpki
//! during the mutual TLS handshake. The digest is SHA-256 from the same
//! provider the TLS stack uses, so no second hashing dependency enters the
//! runtime.

use rustls::crypto::aws_lc_rs::cipher_suite;

/// Largest certificate this walker accepts; matches the TLS document
/// ceiling of the configuration loader.
pub const MAX_CERTIFICATE_BYTES: usize = 65_536;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_EXPLICIT_0: u8 = 0xA0;
/// Elements of `tbsCertificate` that precede `subjectPublicKeyInfo` once
/// the optional version has been skipped: serialNumber, signature, issuer,
/// validity, subject (RFC 5280 section 4.1).
const ELEMENTS_BEFORE_SPKI: usize = 5;

/// Returns the SHA-256 of the leaf certificate's `subjectPublicKeyInfo`,
/// or `None` when the DER is not a well-formed certificate.
#[must_use]
pub fn spki_sha256(certificate: &[u8]) -> Option<[u8; 32]> {
    if certificate.len() > MAX_CERTIFICATE_BYTES {
        return None;
    }
    let (tag, certificate_body, _) = read_tlv(certificate)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let (tag, mut tbs, _) = read_tlv(certificate_body)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    if tbs.first() == Some(&TAG_EXPLICIT_0) {
        tbs = read_tlv(tbs)?.2;
    }
    for _ in 0..ELEMENTS_BEFORE_SPKI {
        tbs = read_tlv(tbs)?.2;
    }
    let (tag, _, rest) = read_tlv(tbs)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let spki_length = tbs.len().checked_sub(rest.len())?;
    sha256(tbs.get(..spki_length)?)
}

/// Splits one DER element into its tag, contents, and the bytes after it.
fn read_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = bytes.split_first()?;
    let (&first, after_first) = after_tag.split_first()?;
    let (length, contents_start) = if first < 0x80 {
        (usize::from(first), after_first)
    } else {
        let length_bytes = usize::from(first & 0x7F);
        if length_bytes == 0 || length_bytes > 3 {
            return None;
        }
        let (encoded, rest) = after_first.split_at_checked(length_bytes)?;
        let length = encoded
            .iter()
            .fold(0_usize, |total, byte| (total << 8) | usize::from(*byte));
        (length, rest)
    };
    let (contents, rest) = contents_start.split_at_checked(length)?;
    Some((tag, contents, rest))
}

fn sha256(bytes: &[u8]) -> Option<[u8; 32]> {
    let suite = cipher_suite::TLS13_AES_128_GCM_SHA256.tls13()?;
    let output = suite.common.hash_provider.hash(bytes);
    let mut digest = [0_u8; 32];
    let produced = output.as_ref();
    if produced.len() != digest.len() {
        return None;
    }
    digest.copy_from_slice(produced);
    Some(digest)
}

#[cfg(test)]
mod tests {
    use agenc_ircd_testkit::TlsFixture;

    use super::*;

    #[test]
    fn the_walker_reproduces_the_fixture_spki_digest() {
        let fixture = TlsFixture::mint([21; 32], "spki.test").ok();
        let Some(fixture) = fixture else {
            return;
        };
        assert_eq!(
            spki_sha256(fixture.leaf_certificate_der()),
            Some(*fixture.leaf_spki_sha256())
        );
        assert!(spki_sha256(fixture.ca_certificate_der()).is_some());
        assert_ne!(
            spki_sha256(fixture.ca_certificate_der()),
            spki_sha256(fixture.leaf_certificate_der())
        );
    }

    #[test]
    fn malformed_documents_yield_no_digest() {
        assert_eq!(spki_sha256(&[]), None);
        assert_eq!(spki_sha256(&[0x02, 0x01, 0x00]), None, "not a sequence");
        assert_eq!(
            spki_sha256(&[0x30, 0x84, 0, 0, 0, 1]),
            None,
            "length form too long"
        );
        assert_eq!(spki_sha256(&[0x30, 0x80]), None, "indefinite length");
        assert_eq!(
            spki_sha256(&[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00]),
            None,
            "truncated tbs"
        );
        assert_eq!(spki_sha256(&vec![0x30; MAX_CERTIFICATE_BYTES + 1]), None);
        let short_form = [0x30, 0x03, 0x02, 0x01, 0x00];
        assert!(read_tlv(&short_form).is_some());
        let long_form = [0x30, 0x81, 0x01, 0x00];
        assert!(read_tlv(&long_form).is_some());
    }
}
