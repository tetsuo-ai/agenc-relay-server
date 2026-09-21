//! Deterministic Ed25519 X.509 material for TLS tests.
//!
//! No pinned production crate mints certificates, so this module writes the
//! few DER structures a rustls-webpki server chain needs: a self-signed CA
//! and one CA-signed leaf carrying a DNS subjectAltName (RFC 5280 profile,
//! RFC 8410 Ed25519 identifiers). Everything derives from one seed so a
//! fixture is reproducible across runs and hosts.

use std::error::Error;
use std::fmt;

use agenc_relay_types::ServerId;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

/// Maximum DNS name accepted by the fixture (RFC 1035 total length).
pub const MAX_FIXTURE_DNS_NAME_BYTES: usize = 253;

/// Longest DER structure this writer produces; every length fits two bytes.
const MAX_DER_BYTES: usize = 65_535;

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_EXPLICIT_0: u8 = 0xA0;
const TAG_EXPLICIT_3: u8 = 0xA3;
const TAG_SAN_DNS_NAME: u8 = 0x82;
/// `GeneralName` choice `uniformResourceIdentifier [6]`.
const TAG_SAN_URI: u8 = 0x86;
/// The federation identity URI prefix (spec 20.2).
const FEDERATION_URI_PREFIX: &str = "urn:agenc-chat:server:";

/// `1.3.101.112`, the Ed25519 algorithm identifier (RFC 8410 section 3).
const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];
/// `2.5.4.3`, commonName.
const OID_COMMON_NAME: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];
/// `2.5.29.19`, basicConstraints.
const OID_BASIC_CONSTRAINTS: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x13];
/// `2.5.29.15`, keyUsage.
const OID_KEY_USAGE: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x0F];
/// `2.5.29.17`, subjectAltName.
const OID_SUBJECT_ALT_NAME: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x11];

/// Validity start, 2026-01-01T00:00:00Z as UTCTime.
const NOT_BEFORE: &[u8] = b"260101000000Z";
/// Validity end, 2049-12-31T23:59:59Z, the last instant UTCTime can express
/// before the RFC 5280 GeneralizedTime cutover.
const NOT_AFTER: &[u8] = b"491231235959Z";

/// keyUsage `keyCertSign | cRLSign` with one unused trailing bit.
const CA_KEY_USAGE: [u8; 2] = [0x01, 0x06];
/// keyUsage `digitalSignature` with seven unused trailing bits.
const LEAF_KEY_USAGE: [u8; 2] = [0x07, 0x80];

const CA_COMMON_NAME: &[u8] = b"arcd testkit ca";
const CA_SEED_LABEL: &[u8] = b"arcd testkit tls ca v1";
const LEAF_SEED_LABEL: &[u8] = b"arcd testkit tls leaf v1";

/// The fixture could not be minted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsFixtureError {
    /// The DNS name was empty, too long, or contained a forbidden byte.
    InvalidDnsName,
    /// A DER structure exceeded the writer's two-byte length limit.
    Overflow,
}

impl fmt::Display for TlsFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDnsName => formatter.write_str("fixture DNS name is invalid"),
            Self::Overflow => formatter.write_str("fixture DER structure is too long"),
        }
    }
}

impl Error for TlsFixtureError {}

/// A deterministic CA and leaf pair with the leaf's private key.
pub struct TlsFixture {
    ca_certificate: Vec<u8>,
    leaf_certificate: Vec<u8>,
    leaf_private_key_pkcs8: Vec<u8>,
    leaf_spki_sha256: [u8; 32],
    dns_name: String,
}

impl TlsFixture {
    /// Mints the CA and a leaf for `dns_name` from one seed.
    pub fn mint(seed: [u8; 32], dns_name: &str) -> Result<Self, TlsFixtureError> {
        validate_dns_name(dns_name)?;
        let ca_key = SigningKey::from_bytes(&derive_seed(CA_SEED_LABEL, &seed));
        let leaf_key = SigningKey::from_bytes(&derive_seed(LEAF_SEED_LABEL, &seed));
        let ca_name = name(CA_COMMON_NAME)?;
        let ca_spki = subject_public_key_info(&ca_key.verifying_key().to_bytes())?;
        let ca_extensions = sequence(&[
            extension(&OID_BASIC_CONSTRAINTS, true, &sequence(&[boolean_true()])?)?,
            extension(&OID_KEY_USAGE, true, &tlv(TAG_BIT_STRING, &CA_KEY_USAGE)?)?,
        ])?;
        let ca_tbs = tbs_certificate(1, &ca_name, &ca_name, &ca_spki, &ca_extensions)?;
        let ca_certificate = certificate(&ca_tbs, &ca_key)?;

        let leaf_name = name(dns_name.as_bytes())?;
        let leaf_spki = subject_public_key_info(&leaf_key.verifying_key().to_bytes())?;
        let san = sequence(&[tlv(TAG_SAN_DNS_NAME, dns_name.as_bytes())?])?;
        let leaf_extensions = sequence(&[
            extension(&OID_BASIC_CONSTRAINTS, true, &sequence(&[])?)?,
            extension(&OID_KEY_USAGE, true, &tlv(TAG_BIT_STRING, &LEAF_KEY_USAGE)?)?,
            extension(&OID_SUBJECT_ALT_NAME, false, &san)?,
        ])?;
        let leaf_tbs = tbs_certificate(2, &ca_name, &leaf_name, &leaf_spki, &leaf_extensions)?;
        let leaf_certificate = certificate(&leaf_tbs, &ca_key)?;

        Ok(Self {
            ca_certificate,
            leaf_certificate,
            leaf_private_key_pkcs8: pkcs8(&leaf_key.to_bytes())?,
            leaf_spki_sha256: Sha256::digest(&leaf_spki).into(),
            dns_name: dns_name.to_owned(),
        })
    }

    /// Re-issues the `mint` leaf for `dns_name`: the same CA and the same leaf
    /// key, a new certificate with `serial`. This is the certificate renewal a
    /// running listener can reload, since the key identity is unchanged.
    pub fn reissue_leaf(
        seed: [u8; 32],
        dns_name: &str,
        serial: u8,
    ) -> Result<Self, TlsFixtureError> {
        validate_dns_name(dns_name)?;
        let ca_key = SigningKey::from_bytes(&derive_seed(CA_SEED_LABEL, &seed));
        let leaf_key = SigningKey::from_bytes(&derive_seed(LEAF_SEED_LABEL, &seed));
        let ca_name = name(CA_COMMON_NAME)?;
        let ca_spki = subject_public_key_info(&ca_key.verifying_key().to_bytes())?;
        let ca_extensions = sequence(&[
            extension(&OID_BASIC_CONSTRAINTS, true, &sequence(&[boolean_true()])?)?,
            extension(&OID_KEY_USAGE, true, &tlv(TAG_BIT_STRING, &CA_KEY_USAGE)?)?,
        ])?;
        let ca_tbs = tbs_certificate(1, &ca_name, &ca_name, &ca_spki, &ca_extensions)?;
        let ca_certificate = certificate(&ca_tbs, &ca_key)?;
        let leaf_name = name(dns_name.as_bytes())?;
        let leaf_spki = subject_public_key_info(&leaf_key.verifying_key().to_bytes())?;
        let san = sequence(&[tlv(TAG_SAN_DNS_NAME, dns_name.as_bytes())?])?;
        let leaf_extensions = sequence(&[
            extension(&OID_BASIC_CONSTRAINTS, true, &sequence(&[])?)?,
            extension(&OID_KEY_USAGE, true, &tlv(TAG_BIT_STRING, &LEAF_KEY_USAGE)?)?,
            extension(&OID_SUBJECT_ALT_NAME, false, &san)?,
        ])?;
        let leaf_tbs = tbs_certificate(serial, &ca_name, &leaf_name, &leaf_spki, &leaf_extensions)?;
        let leaf_certificate = certificate(&leaf_tbs, &ca_key)?;
        Ok(Self {
            ca_certificate,
            leaf_certificate,
            leaf_private_key_pkcs8: pkcs8(&leaf_key.to_bytes())?,
            leaf_spki_sha256: Sha256::digest(&leaf_spki).into(),
            dns_name: dns_name.to_owned(),
        })
    }

    /// Mints a fresh leaf for `dns_name` under the same CA that `mint` derives
    /// from `seed`, with a distinct leaf key selected by `generation`. Clients
    /// that trust the CA accept the new leaf; a pin on the old leaf's SPKI sees
    /// a new identity. `generation` 0 reproduces `mint`.
    pub fn rotate_leaf(
        seed: [u8; 32],
        dns_name: &str,
        generation: u32,
    ) -> Result<Self, TlsFixtureError> {
        if generation == 0 {
            return Self::mint(seed, dns_name);
        }
        validate_dns_name(dns_name)?;
        let ca_key = SigningKey::from_bytes(&derive_seed(CA_SEED_LABEL, &seed));
        let mut leaf_label = LEAF_SEED_LABEL.to_vec();
        leaf_label.extend_from_slice(b" rotation ");
        leaf_label.extend_from_slice(&generation.to_be_bytes());
        let leaf_key = SigningKey::from_bytes(&derive_seed(&leaf_label, &seed));
        let ca_name = name(CA_COMMON_NAME)?;
        let ca_spki = subject_public_key_info(&ca_key.verifying_key().to_bytes())?;
        let ca_extensions = sequence(&[
            extension(&OID_BASIC_CONSTRAINTS, true, &sequence(&[boolean_true()])?)?,
            extension(&OID_KEY_USAGE, true, &tlv(TAG_BIT_STRING, &CA_KEY_USAGE)?)?,
        ])?;
        let ca_tbs = tbs_certificate(1, &ca_name, &ca_name, &ca_spki, &ca_extensions)?;
        let ca_certificate = certificate(&ca_tbs, &ca_key)?;
        let leaf_name = name(dns_name.as_bytes())?;
        let leaf_spki = subject_public_key_info(&leaf_key.verifying_key().to_bytes())?;
        let san = sequence(&[tlv(TAG_SAN_DNS_NAME, dns_name.as_bytes())?])?;
        let leaf_extensions = sequence(&[
            extension(&OID_BASIC_CONSTRAINTS, true, &sequence(&[])?)?,
            extension(&OID_KEY_USAGE, true, &tlv(TAG_BIT_STRING, &LEAF_KEY_USAGE)?)?,
            extension(&OID_SUBJECT_ALT_NAME, false, &san)?,
        ])?;
        // Serials 1 and 2 belong to the CA and the original leaf.
        let serial = u8::try_from(generation)
            .ok()
            .and_then(|generation| generation.checked_add(2))
            .ok_or(TlsFixtureError::Overflow)?;
        let leaf_tbs = tbs_certificate(serial, &ca_name, &leaf_name, &leaf_spki, &leaf_extensions)?;
        let leaf_certificate = certificate(&leaf_tbs, &ca_key)?;
        Ok(Self {
            ca_certificate,
            leaf_certificate,
            leaf_private_key_pkcs8: pkcs8(&leaf_key.to_bytes())?,
            leaf_spki_sha256: Sha256::digest(&leaf_spki).into(),
            dns_name: dns_name.to_owned(),
        })
    }

    /// Mints the CA and a federation leaf whose only subjectAltName is the
    /// `urn:agenc-chat:server:<id>` URI of `server_id`; the leaf carries no
    /// extended key usage so it serves both link directions.
    pub fn mint_federation(seed: [u8; 32], server_id: ServerId) -> Result<Self, TlsFixtureError> {
        let ca_key = SigningKey::from_bytes(&derive_seed(CA_SEED_LABEL, &seed));
        let leaf_key = SigningKey::from_bytes(&derive_seed(LEAF_SEED_LABEL, &seed));
        let ca_name = name(CA_COMMON_NAME)?;
        let ca_spki = subject_public_key_info(&ca_key.verifying_key().to_bytes())?;
        let ca_extensions = sequence(&[
            extension(&OID_BASIC_CONSTRAINTS, true, &sequence(&[boolean_true()])?)?,
            extension(&OID_KEY_USAGE, true, &tlv(TAG_BIT_STRING, &CA_KEY_USAGE)?)?,
        ])?;
        let ca_tbs = tbs_certificate(1, &ca_name, &ca_name, &ca_spki, &ca_extensions)?;
        let ca_certificate = certificate(&ca_tbs, &ca_key)?;

        let uri = format!("{FEDERATION_URI_PREFIX}{}", server_id.to_base64url());
        let leaf_name = name(uri.as_bytes())?;
        let leaf_spki = subject_public_key_info(&leaf_key.verifying_key().to_bytes())?;
        let san = sequence(&[tlv(TAG_SAN_URI, uri.as_bytes())?])?;
        let leaf_extensions = sequence(&[
            extension(&OID_BASIC_CONSTRAINTS, true, &sequence(&[])?)?,
            extension(&OID_KEY_USAGE, true, &tlv(TAG_BIT_STRING, &LEAF_KEY_USAGE)?)?,
            extension(&OID_SUBJECT_ALT_NAME, false, &san)?,
        ])?;
        let leaf_tbs = tbs_certificate(2, &ca_name, &leaf_name, &leaf_spki, &leaf_extensions)?;
        let leaf_certificate = certificate(&leaf_tbs, &ca_key)?;

        Ok(Self {
            ca_certificate,
            leaf_certificate,
            leaf_private_key_pkcs8: pkcs8(&leaf_key.to_bytes())?,
            leaf_spki_sha256: Sha256::digest(&leaf_spki).into(),
            dns_name: uri,
        })
    }

    /// Returns the self-signed CA certificate in DER form.
    #[must_use]
    pub fn ca_certificate_der(&self) -> &[u8] {
        &self.ca_certificate
    }

    /// Returns the CA-signed leaf certificate in DER form.
    #[must_use]
    pub fn leaf_certificate_der(&self) -> &[u8] {
        &self.leaf_certificate
    }

    /// Returns the leaf private key as PKCS#8 version one DER.
    #[must_use]
    pub fn leaf_private_key_pkcs8_der(&self) -> &[u8] {
        &self.leaf_private_key_pkcs8
    }

    /// Returns SHA-256 of the leaf subjectPublicKeyInfo, the onion pin form.
    #[must_use]
    pub const fn leaf_spki_sha256(&self) -> &[u8; 32] {
        &self.leaf_spki_sha256
    }

    /// Returns the DNS name carried in the leaf subjectAltName.
    #[must_use]
    pub fn dns_name(&self) -> &str {
        &self.dns_name
    }
}

fn validate_dns_name(dns_name: &str) -> Result<(), TlsFixtureError> {
    if dns_name.is_empty() || dns_name.len() > MAX_FIXTURE_DNS_NAME_BYTES {
        return Err(TlsFixtureError::InvalidDnsName);
    }
    let allowed = dns_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.');
    let labels_nonempty = dns_name.split('.').all(|label| !label.is_empty());
    if !allowed || !labels_nonempty {
        return Err(TlsFixtureError::InvalidDnsName);
    }
    Ok(())
}

fn derive_seed(label: &[u8], seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(seed);
    hasher.finalize().into()
}

fn encode_length(length: usize) -> Result<Vec<u8>, TlsFixtureError> {
    if length > MAX_DER_BYTES {
        return Err(TlsFixtureError::Overflow);
    }
    let length = u16::try_from(length).map_err(|_| TlsFixtureError::Overflow)?;
    Ok(match length {
        0..=127 => vec![length.to_be_bytes()[1]],
        128..=255 => vec![0x81, length.to_be_bytes()[1]],
        _ => {
            let [high, low] = length.to_be_bytes();
            vec![0x82, high, low]
        }
    })
}

fn tlv(tag: u8, content: &[u8]) -> Result<Vec<u8>, TlsFixtureError> {
    let mut encoded = vec![tag];
    encoded.extend(encode_length(content.len())?);
    encoded.extend_from_slice(content);
    Ok(encoded)
}

fn sequence(parts: &[Vec<u8>]) -> Result<Vec<u8>, TlsFixtureError> {
    tlv(TAG_SEQUENCE, &parts.concat())
}

fn boolean_true() -> Vec<u8> {
    vec![TAG_BOOLEAN, 0x01, 0xFF]
}

fn small_integer(value: u8) -> Vec<u8> {
    vec![TAG_INTEGER, 0x01, value]
}

fn algorithm_identifier() -> Result<Vec<u8>, TlsFixtureError> {
    sequence(&[OID_ED25519.to_vec()])
}

fn name(common_name: &[u8]) -> Result<Vec<u8>, TlsFixtureError> {
    let attribute = sequence(&[OID_COMMON_NAME.to_vec(), tlv(TAG_UTF8_STRING, common_name)?])?;
    sequence(&[tlv(TAG_SET, &attribute)?])
}

fn subject_public_key_info(public_key: &[u8; 32]) -> Result<Vec<u8>, TlsFixtureError> {
    let mut bits = vec![0x00];
    bits.extend_from_slice(public_key);
    sequence(&[algorithm_identifier()?, tlv(TAG_BIT_STRING, &bits)?])
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Result<Vec<u8>, TlsFixtureError> {
    let mut parts = vec![oid.to_vec()];
    if critical {
        parts.push(boolean_true());
    }
    parts.push(tlv(TAG_OCTET_STRING, value)?);
    sequence(&parts)
}

fn tbs_certificate(
    serial: u8,
    issuer: &[u8],
    subject: &[u8],
    spki: &[u8],
    extensions: &[u8],
) -> Result<Vec<u8>, TlsFixtureError> {
    sequence(&[
        tlv(TAG_EXPLICIT_0, &small_integer(2))?,
        small_integer(serial),
        algorithm_identifier()?,
        issuer.to_vec(),
        sequence(&[
            tlv(TAG_UTC_TIME, NOT_BEFORE)?,
            tlv(TAG_UTC_TIME, NOT_AFTER)?,
        ])?,
        subject.to_vec(),
        spki.to_vec(),
        tlv(TAG_EXPLICIT_3, extensions)?,
    ])
}

fn certificate(tbs: &[u8], signer: &SigningKey) -> Result<Vec<u8>, TlsFixtureError> {
    let mut signature = vec![0x00];
    signature.extend_from_slice(&signer.sign(tbs).to_bytes());
    sequence(&[
        tbs.to_vec(),
        algorithm_identifier()?,
        tlv(TAG_BIT_STRING, &signature)?,
    ])
}

fn pkcs8(seed: &[u8; 32]) -> Result<Vec<u8>, TlsFixtureError> {
    let private_key = tlv(TAG_OCTET_STRING, seed)?;
    sequence(&[
        small_integer(0),
        algorithm_identifier()?,
        tlv(TAG_OCTET_STRING, &private_key)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_deterministic_per_seed_and_name() -> Result<(), TlsFixtureError> {
        let first = TlsFixture::mint([1; 32], "node.test")?;
        let again = TlsFixture::mint([1; 32], "node.test")?;
        let other_seed = TlsFixture::mint([2; 32], "node.test")?;
        let other_name = TlsFixture::mint([1; 32], "other.test")?;
        assert_eq!(first.ca_certificate_der(), again.ca_certificate_der());
        assert_eq!(first.leaf_certificate_der(), again.leaf_certificate_der());
        assert_eq!(first.leaf_spki_sha256(), again.leaf_spki_sha256());
        assert_ne!(first.ca_certificate_der(), other_seed.ca_certificate_der());
        assert_ne!(
            first.leaf_certificate_der(),
            other_name.leaf_certificate_der()
        );
        assert_eq!(first.leaf_spki_sha256(), other_name.leaf_spki_sha256());
        assert_eq!(first.dns_name(), "node.test");
        assert_eq!(first.leaf_private_key_pkcs8_der().len(), 48);
        assert_eq!(
            first.leaf_private_key_pkcs8_der().first(),
            Some(&TAG_SEQUENCE)
        );
        Ok(())
    }

    #[test]
    fn dns_names_are_validated_and_lengths_are_bounded() {
        for invalid in [
            "",
            "bad..name",
            "under_score",
            "trailing.",
            &"a".repeat(254),
        ] {
            assert_eq!(
                TlsFixture::mint([0; 32], invalid).err(),
                Some(TlsFixtureError::InvalidDnsName),
                "{invalid}"
            );
        }
        assert!(TlsFixture::mint([0; 32], &"a".repeat(253)).is_ok());
        assert_eq!(
            encode_length(MAX_DER_BYTES + 1),
            Err(TlsFixtureError::Overflow)
        );
        assert_eq!(encode_length(127), Ok(vec![0x7F]));
        assert_eq!(encode_length(128), Ok(vec![0x81, 0x80]));
        assert_eq!(encode_length(256), Ok(vec![0x82, 0x01, 0x00]));
    }
}
