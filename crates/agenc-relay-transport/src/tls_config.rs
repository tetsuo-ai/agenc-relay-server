//! Shared TLS 1.3 provider, trust anchors, and client configuration.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, cipher_suite, kx_group};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use subtle::ConstantTimeEq as _;

/// ALPN identifier of every client endpoint (spec line 488).
pub const CLIENT_ALPN: &[u8] = b"agenc-chat/1";
/// Bytes of plaintext rustls may buffer for one connection before the
/// writer sees back-pressure; two complete physical lines (spec line 583).
pub const TLS_PLAINTEXT_BUFFER_LIMIT_BYTES: usize = 17_406;
/// Longest certificate chain or key document accepted from disk: 64 KiB,
/// far above any Ed25519 or ECDSA chain the profile allows.
pub const MAX_TLS_DOCUMENT_BYTES: usize = 65_536;
/// Maximum certificates in one chain: leaf plus three intermediates.
pub const MAX_CHAIN_CERTIFICATES: usize = 4;

/// The DER `SEQUENCE` tag that opens every certificate and key document.
const DER_SEQUENCE_TAG: u8 = 0x30;

/// The TLS key-exchange group policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupPolicy {
    /// Offer the hybrid group first and allow the X25519 fallback.
    HybridPreferred,
    /// Require the hybrid group.
    HybridRequired,
}

/// Closed failures of client TLS configuration and trust document parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsConfigError {
    /// A certificate document was empty, malformed, or over its ceiling.
    InvalidCertificate,
    /// A client private key does not match its certificate chain.
    InvalidPrivateKey,
    /// A trust store document held no usable anchor.
    InvalidTrustStore,
    /// The required TLS provider could not be configured.
    ProviderUnavailable,
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCertificate => "TLS certificate document is invalid",
            Self::InvalidPrivateKey => "TLS private key document is invalid",
            Self::InvalidTrustStore => "TLS trust store document is invalid",
            Self::ProviderUnavailable => "TLS provider is unavailable",
        };
        formatter.write_str(message)
    }
}

impl Error for TlsConfigError {}

/// A private trust store for mutual TLS (spec lines 502-505).
#[derive(Clone, Debug)]
pub struct TrustStore {
    roots: Arc<RootCertStore>,
    spki_sha256: Vec<[u8; 32]>,
}

impl TrustStore {
    /// Parses one or more DER or PEM anchors; public WebPKI roots are never
    /// loaded implicitly.
    pub fn parse(document: &[u8]) -> Result<Self, TlsConfigError> {
        let anchors =
            parse_certificates(document).map_err(|_| TlsConfigError::InvalidTrustStore)?;
        let mut roots = RootCertStore::empty();
        let mut spki_sha256 = Vec::new();
        spki_sha256
            .try_reserve_exact(anchors.len())
            .map_err(|_| TlsConfigError::InvalidTrustStore)?;
        for anchor in anchors {
            spki_sha256
                .push(certificate_spki_sha256(&anchor).ok_or(TlsConfigError::InvalidTrustStore)?);
            roots
                .add(anchor)
                .map_err(|_| TlsConfigError::InvalidTrustStore)?;
        }
        if roots.is_empty() {
            return Err(TlsConfigError::InvalidTrustStore);
        }
        Ok(Self {
            roots: Arc::new(roots),
            spki_sha256,
        })
    }

    /// Returns the number of anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Returns whether the store is empty, which parsing forbids.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Borrows the rustls roots for additional endpoint verification policies.
    #[must_use]
    pub fn roots(&self) -> &Arc<RootCertStore> {
        &self.roots
    }

    /// Borrows the SPKI digests of the anchors in document order.
    #[must_use]
    pub fn spki_identities(&self) -> &[[u8; 32]] {
        &self.spki_sha256
    }
}

/// Builds the exact provider: the three TLS 1.3 suites and the hybrid-first
/// key exchange order (spec lines 474-485). The order is fixed here, so the
/// `prefer-post-quantum` feature cannot change it.
#[must_use]
pub fn provider() -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = vec![kx_group::X25519MLKEM768, kx_group::X25519];
    provider
}

/// Builds the exact provider with the given key-exchange group policy.
#[must_use]
pub fn provider_for_group_policy(group_policy: GroupPolicy) -> CryptoProvider {
    let mut provider = provider();
    if group_policy == GroupPolicy::HybridRequired {
        provider.kx_groups = vec![kx_group::X25519MLKEM768];
    }
    provider
}

/// Builds a TLS 1.3 client using explicit WebPKI trust anchors and optional mutual TLS.
///
/// The caller may supply a single ALPN identifier and a leaf-first client
/// certificate chain with its private key. Early data is disabled.
pub fn build_client_config(
    roots: TrustStore,
    alpn: Option<&[u8]>,
    client_certificate: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    group_policy: GroupPolicy,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let builder =
        ClientConfig::builder_with_provider(Arc::new(provider_for_group_policy(group_policy)))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| TlsConfigError::ProviderUnavailable)?
            .with_root_certificates(Arc::clone(&roots.roots));
    let mut config = match client_certificate {
        None => builder.with_no_client_auth(),
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|_| TlsConfigError::InvalidPrivateKey)?,
    };
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct SpkiPinVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    expected: [u8; 32],
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual = certificate_spki_sha256(end_entity)
            .ok_or_else(|| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if !bool::from(actual.ct_eq(&self.expected)) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Builds the native onion-client TLS 1.3 profile around an exact leaf SPKI pin.
///
/// The certificate identity is the SPKI digest. Handshake signatures must
/// verify with the corresponding public key. The configured roots construct
/// the WebPKI signature verifier. The profile requires client ALPN and disables
/// early data.
pub fn build_pinned_client_config(
    roots: TrustStore,
    expected_spki_sha256: [u8; 32],
    group_policy: GroupPolicy,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let crypto = Arc::new(provider_for_group_policy(group_policy));
    let webpki =
        WebPkiServerVerifier::builder_with_provider(Arc::clone(&roots.roots), Arc::clone(&crypto))
            .build()
            .map_err(|_| TlsConfigError::InvalidTrustStore)?;
    let verifier = SpkiPinVerifier {
        inner: webpki,
        expected: expected_spki_sha256,
    };
    let mut config = ClientConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsConfigError::ProviderUnavailable)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![CLIENT_ALPN.to_vec()];
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// Returns the SHA-256 digest of a certificate's DER SubjectPublicKeyInfo.
#[must_use]
pub fn certificate_spki_sha256(certificate: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let parsed = ParsedCertificate::try_from(certificate).ok()?;
    let spki = parsed.subject_public_key_info();
    let suite = cipher_suite::TLS13_AES_128_GCM_SHA256.tls13()?;
    let output = suite.common.hash_provider.hash(spki.as_ref());
    let mut digest = [0_u8; 32];
    if output.as_ref().len() != digest.len() {
        return None;
    }
    digest.copy_from_slice(output.as_ref());
    Some(digest)
}

/// Parses a bounded certificate document as one DER certificate or PEM certificates.
pub fn parse_certificates(document: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    if document.is_empty() || document.len() > MAX_TLS_DOCUMENT_BYTES {
        return Err(TlsConfigError::InvalidCertificate);
    }
    if document.first() == Some(&DER_SEQUENCE_TAG) {
        return Ok(vec![CertificateDer::from(document.to_vec())]);
    }
    let mut certificates = Vec::new();
    for item in CertificateDer::pem_slice_iter(document) {
        let certificate = item.map_err(|_| TlsConfigError::InvalidCertificate)?;
        if certificates.len() >= MAX_CHAIN_CERTIFICATES {
            return Err(TlsConfigError::InvalidCertificate);
        }
        certificates.push(certificate);
    }
    Ok(certificates)
}
