//! Federation peer certificate identity: the single `urn:agenc-chat:server:`
//! subjectAltName URI and the independent SPKI pin (spec 20.2).
//!
//! Chain validation against the private CA happens in rustls during the
//! handshake. This module walks only the DER needed to read the one URI and
//! compares it, together with the pin, to the configured peer; it never
//! trusts a certificate on its own.

use std::error::Error;
use std::fmt;

use agenc_relay_federation_wire::FederationId16;
use agenc_relay_types::ServerId;
use subtle::ConstantTimeEq as _;

use crate::federation::PeerIdentity;
use crate::listener::spki::{MAX_CERTIFICATE_BYTES, spki_sha256};

/// The URI prefix every federation certificate carries in its one SAN.
pub const FEDERATION_SAN_URI_PREFIX: &str = "urn:agenc-chat:server:";

const TAG_SEQUENCE: u8 = 0x30;
const TAG_OID: u8 = 0x06;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_EXPLICIT_0: u8 = 0xA0;
const TAG_EXPLICIT_1: u8 = 0xA1;
const TAG_EXPLICIT_2: u8 = 0xA2;
const TAG_EXPLICIT_3: u8 = 0xA3;
/// `GeneralName` choice `uniformResourceIdentifier [6] IMPLICIT IA5String`.
const TAG_GENERAL_NAME_URI: u8 = 0x86;
/// `id-ce-subjectAltName` (2.5.29.17) contents.
const OID_SUBJECT_ALT_NAME: [u8; 3] = [0x55, 0x1D, 0x11];
/// Elements of `tbsCertificate` after the optional version and before the
/// optional issuer/subject unique identifiers and extensions.
const ELEMENTS_BEFORE_OPTIONALS: usize = 6;

/// Why a presented certificate is not the configured peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerCertificateError {
    /// The DER did not carry exactly one readable federation URI.
    Malformed,
    /// The SPKI digest differs from the configured pin.
    SpkiPin,
    /// The URI names another Server ID.
    SubjectAltName,
}

impl fmt::Display for PeerCertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Malformed => "federation certificate has no single server URI",
            Self::SpkiPin => "federation certificate SPKI pin mismatch",
            Self::SubjectAltName => "federation certificate names another server",
        };
        formatter.write_str(message)
    }
}

impl Error for PeerCertificateError {}

/// Reads the Server ID from the certificate's single SAN URI.
#[must_use]
pub fn server_id_from_certificate(certificate: &[u8]) -> Option<ServerId> {
    if certificate.len() > MAX_CERTIFICATE_BYTES {
        return None;
    }
    let extensions = tbs_extensions(certificate)?;
    let (tag, mut list, _) = read_tlv(extensions)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let mut found = None;
    while !list.is_empty() {
        let (tag, extension, rest) = read_tlv(list)?;
        if tag != TAG_SEQUENCE {
            return None;
        }
        list = rest;
        if let Some(value) = subject_alt_name_value(extension)? {
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    parse_single_uri(found?)
}

/// Walks to the `[3] extensions` element of `tbsCertificate`.
fn tbs_extensions(certificate: &[u8]) -> Option<&[u8]> {
    let (tag, body, _) = read_tlv(certificate)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let (tag, mut tbs, _) = read_tlv(body)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    if tbs.first() == Some(&TAG_EXPLICIT_0) {
        tbs = read_tlv(tbs)?.2;
    }
    for _ in 0..ELEMENTS_BEFORE_OPTIONALS {
        tbs = read_tlv(tbs)?.2;
    }
    loop {
        let (tag, contents, rest) = read_tlv(tbs)?;
        match tag {
            TAG_EXPLICIT_1 | TAG_EXPLICIT_2 => tbs = rest,
            TAG_EXPLICIT_3 => return Some(contents),
            _ => return None,
        }
    }
}

/// Returns the SAN extension value when `extension` is `subjectAltName`.
fn subject_alt_name_value(extension: &[u8]) -> Option<Option<&[u8]>> {
    let (tag, oid, mut rest) = read_tlv(extension)?;
    if tag != TAG_OID {
        return None;
    }
    if oid != OID_SUBJECT_ALT_NAME {
        return Some(None);
    }
    if rest.first() == Some(&TAG_BOOLEAN) {
        rest = read_tlv(rest)?.2;
    }
    let (tag, value, trailing) = read_tlv(rest)?;
    if tag != TAG_OCTET_STRING || !trailing.is_empty() {
        return None;
    }
    Some(Some(value))
}

fn parse_single_uri(value: &[u8]) -> Option<ServerId> {
    let (tag, names, trailing) = read_tlv(value)?;
    if tag != TAG_SEQUENCE || !trailing.is_empty() {
        return None;
    }
    let (tag, uri, rest) = read_tlv(names)?;
    if tag != TAG_GENERAL_NAME_URI || !rest.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(uri).ok()?;
    let encoded = text.strip_prefix(FEDERATION_SAN_URI_PREFIX)?;
    let id = FederationId16::parse(encoded).ok()?;
    Some(ServerId::from_bytes(*id.as_bytes()))
}

/// Checks the pin and the SAN URI of a chain-validated peer certificate.
pub fn verify_peer_certificate(
    certificate: &[u8],
    peer: &PeerIdentity,
) -> Result<(), PeerCertificateError> {
    let digest = spki_sha256(certificate).ok_or(PeerCertificateError::Malformed)?;
    if !bool::from(digest.ct_eq(peer.certificate_spki_sha256())) {
        return Err(PeerCertificateError::SpkiPin);
    }
    let server_id =
        server_id_from_certificate(certificate).ok_or(PeerCertificateError::Malformed)?;
    if server_id != peer.server_id() {
        return Err(PeerCertificateError::SubjectAltName);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use agenc_relay_crypto::Ed25519SecretKey;
    use agenc_relay_testkit::TlsFixture;
    use agenc_relay_types::{FederationRole, RecoveryEpoch};

    use super::*;

    fn peer(fixture: &TlsFixture, server_id: ServerId) -> PeerIdentity {
        PeerIdentity::new(
            server_id,
            "core.example",
            FederationRole::Coordinator,
            RecoveryEpoch::from_bytes([1; 16]),
            Ed25519SecretKey::from_bytes([2; 32]).public_key(),
            *fixture.leaf_spki_sha256(),
        )
    }

    #[test]
    fn federation_fixture_carries_exactly_one_server_uri() -> Result<(), Box<dyn Error>> {
        let server_id = ServerId::from_bytes([7; 16]);
        let fixture = TlsFixture::mint_federation([3; 32], server_id)?;
        assert_eq!(
            server_id_from_certificate(fixture.leaf_certificate_der()),
            Some(server_id)
        );
        assert_eq!(
            server_id_from_certificate(fixture.ca_certificate_der()),
            None
        );
        verify_peer_certificate(fixture.leaf_certificate_der(), &peer(&fixture, server_id))?;
        let other = peer(&fixture, ServerId::from_bytes([8; 16]));
        assert_eq!(
            verify_peer_certificate(fixture.leaf_certificate_der(), &other),
            Err(PeerCertificateError::SubjectAltName)
        );
        let dns = TlsFixture::mint([4; 32], "node.test")?;
        assert_eq!(server_id_from_certificate(dns.leaf_certificate_der()), None);
        assert_eq!(
            verify_peer_certificate(dns.leaf_certificate_der(), &peer(&fixture, server_id)),
            Err(PeerCertificateError::SpkiPin)
        );
        let pinned_dns = PeerIdentity::new(
            server_id,
            "core.example",
            FederationRole::Coordinator,
            RecoveryEpoch::from_bytes([1; 16]),
            Ed25519SecretKey::from_bytes([2; 32]).public_key(),
            *dns.leaf_spki_sha256(),
        );
        assert_eq!(
            verify_peer_certificate(dns.leaf_certificate_der(), &pinned_dns),
            Err(PeerCertificateError::Malformed)
        );
        assert_eq!(
            verify_peer_certificate(&[0x30, 0x01], &pinned_dns),
            Err(PeerCertificateError::Malformed)
        );
        assert!(!PeerCertificateError::Malformed.to_string().is_empty());
        assert!(!PeerCertificateError::SpkiPin.to_string().is_empty());
        assert!(!PeerCertificateError::SubjectAltName.to_string().is_empty());
        Ok(())
    }

    #[test]
    fn malformed_der_yields_no_identity() {
        assert_eq!(server_id_from_certificate(&[]), None);
        assert_eq!(server_id_from_certificate(&[0x30, 0x80]), None);
        assert_eq!(server_id_from_certificate(&[0x30, 0x02, 0x30, 0x00]), None);
        let oversized = vec![0x30; MAX_CERTIFICATE_BYTES + 1];
        assert_eq!(server_id_from_certificate(&oversized), None);
        assert_eq!(parse_single_uri(&[0x30, 0x00]), None);
        assert_eq!(parse_single_uri(&[0x30, 0x02, 0x86, 0x00]), None);
        assert_eq!(subject_alt_name_value(&[0x04, 0x00]), None);
        assert_eq!(
            subject_alt_name_value(&[0x06, 0x03, 0x55, 0x1D, 0x11, 0x05, 0x00]),
            None
        );
    }
}
