//! Exact TLS 1.3 server and client configuration (spec 8.1 and 8.2, lines
//! 464-513).
//!
//! Every endpoint builds its `ServerConfig` from one explicit aws-lc
//! provider: the three allowed suites, the `[X25519MLKEM768, X25519]` key
//! exchange order, TLS 1.3 only, no early data, no half-RTT data, an
//! in-memory ticketer, and exactly one ALPN identifier per listener purpose.
//! Nothing here reads a secret file; the caller passes certificate and key
//! bytes that the configuration crate already admitted.

use std::error::Error;
use std::fmt;

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, Ticketer, cipher_suite, kx_group};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::RuntimeError;
use crate::purpose::ListenerPurpose;
use crate::sync::Arc;

/// ALPN identifier of every client endpoint (spec line 488).
pub const CLIENT_ALPN: &[u8] = b"agenc-chat/1";
/// ALPN identifier of the federation listener (spec line 488).
pub const FEDERATION_ALPN: &[u8] = b"agenc-chat-fed/1";
/// ALPN identifier of the remote administrative listener (spec line 489).
pub const ADMIN_ALPN: &[u8] = b"agenc-chat-admin/1";
/// Ticket-encryption keys rotate every six hours (spec line 509); the
/// aws-lc ticketer rotates on exactly this schedule.
pub const TLS_TICKET_ROTATION_SECONDS: u64 = 21_600;
/// Tickets expire after 24 hours (spec line 509); the rotator retains the
/// previous key for one further rotation so no ticket outlives this bound.
pub const TLS_TICKET_LIFETIME_SECONDS: u64 = 86_400;
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

/// The ALPN and trust profile of one TLS endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsEndpointProfile {
    /// Direct and onion client endpoints; server authentication only.
    Client,
    /// Federation links; mutual TLS against the federation trust store.
    Federation,
    /// Remote administration; mutual TLS against the admin trust store.
    Admin,
}

impl TlsEndpointProfile {
    /// Maps a listener purpose to its TLS profile; local administration and
    /// the deferred WebSocket listener carry no TLS profile here.
    #[must_use]
    pub const fn for_purpose(purpose: ListenerPurpose) -> Option<Self> {
        match purpose {
            ListenerPurpose::ClientTls | ListenerPurpose::ClientOnion => Some(Self::Client),
            ListenerPurpose::Federation => Some(Self::Federation),
            ListenerPurpose::AdminTls => Some(Self::Admin),
            ListenerPurpose::ClientWss | ListenerPurpose::AdminLocal => None,
        }
    }

    /// Returns the exact ALPN identifier the endpoint requires.
    #[must_use]
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Client => CLIENT_ALPN,
            Self::Federation => FEDERATION_ALPN,
            Self::Admin => ADMIN_ALPN,
        }
    }

    /// Returns whether the profile requires a client certificate.
    #[must_use]
    pub const fn requires_client_certificate(self) -> bool {
        matches!(self, Self::Federation | Self::Admin)
    }
}

/// Closed failures while building a TLS configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsConfigError {
    /// A certificate document was empty, malformed, or over its ceiling.
    InvalidCertificate,
    /// A private key document was malformed or does not match the chain.
    InvalidPrivateKey,
    /// A trust store document held no usable anchor.
    InvalidTrustStore,
    /// The profile requires client certificates but no trust store was given,
    /// or a trust store was given to a server-authentication-only profile.
    ClientAuthMismatch,
    /// The provider or ticketer could not be constructed.
    ProviderUnavailable,
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCertificate => "TLS certificate document is invalid",
            Self::InvalidPrivateKey => "TLS private key document is invalid",
            Self::InvalidTrustStore => "TLS trust store document is invalid",
            Self::ClientAuthMismatch => "TLS client authentication does not match the profile",
            Self::ProviderUnavailable => "TLS provider is unavailable",
        };
        formatter.write_str(message)
    }
}

impl Error for TlsConfigError {}

impl From<TlsConfigError> for RuntimeError {
    fn from(_: TlsConfigError) -> Self {
        Self::InvalidValue
    }
}

/// A validated certificate chain, leaf first.
#[derive(Clone, Debug)]
pub struct CertChain {
    certificates: Vec<CertificateDer<'static>>,
}

impl CertChain {
    /// Parses one DER certificate or a PEM document of one to four
    /// certificates, leaf first.
    pub fn parse(document: &[u8]) -> Result<Self, TlsConfigError> {
        let certificates = parse_certificates(document)?;
        if certificates.is_empty() || certificates.len() > MAX_CHAIN_CERTIFICATES {
            return Err(TlsConfigError::InvalidCertificate);
        }
        Ok(Self { certificates })
    }

    /// Returns the number of certificates in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Returns whether the chain is empty, which parsing forbids.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Borrows the leaf certificate.
    #[must_use]
    pub fn leaf(&self) -> Option<&CertificateDer<'static>> {
        self.certificates.first()
    }
}

/// A validated private key document.
pub struct PrivateKey {
    key: PrivateKeyDer<'static>,
}

impl PrivateKey {
    /// Parses one DER PKCS#8 key or a PEM PKCS#8, PKCS#1, or SEC1 key.
    pub fn parse(document: &[u8]) -> Result<Self, TlsConfigError> {
        if document.is_empty() || document.len() > MAX_TLS_DOCUMENT_BYTES {
            return Err(TlsConfigError::InvalidPrivateKey);
        }
        let key = if document.first() == Some(&DER_SEQUENCE_TAG) {
            PrivateKeyDer::try_from(document.to_vec())
                .map_err(|_| TlsConfigError::InvalidPrivateKey)?
        } else {
            PrivateKeyDer::from_pem_slice(document)
                .map_err(|_| TlsConfigError::InvalidPrivateKey)?
        };
        Ok(Self { key })
    }
}

/// A private trust store for mutual TLS (spec lines 502-505).
#[derive(Clone, Debug)]
pub struct TrustStore {
    roots: Arc<RootCertStore>,
}

impl TrustStore {
    /// Parses one or more DER or PEM anchors; public WebPKI roots are never
    /// loaded implicitly.
    pub fn parse(document: &[u8]) -> Result<Self, TlsConfigError> {
        let anchors =
            parse_certificates(document).map_err(|_| TlsConfigError::InvalidTrustStore)?;
        let mut roots = RootCertStore::empty();
        for anchor in anchors {
            roots
                .add(anchor)
                .map_err(|_| TlsConfigError::InvalidTrustStore)?;
        }
        if roots.is_empty() {
            return Err(TlsConfigError::InvalidTrustStore);
        }
        Ok(Self {
            roots: Arc::new(roots),
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
}

/// Client authentication policy of one endpoint.
pub enum ClientAuth {
    /// Server authentication only.
    None,
    /// Mutual TLS against a separate private trust store.
    MutualTls(TrustStore),
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

/// Builds one endpoint's server configuration synchronously.
///
/// Key parsing and verifier construction are cheap, but callers on a Tokio
/// worker should use [`build_server_config`], which moves this call to the
/// blocking pool (spec 21.7, line 4242).
pub fn build_server_config_blocking(
    profile: TlsEndpointProfile,
    chain: CertChain,
    key: PrivateKey,
    client_auth: ClientAuth,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let provider = Arc::new(provider());
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsConfigError::ProviderUnavailable)?;
    let builder = match (client_auth, profile.requires_client_certificate()) {
        (ClientAuth::None, false) => builder.with_no_client_auth(),
        (ClientAuth::MutualTls(store), true) => {
            let verifier = WebPkiClientVerifier::builder_with_provider(store.roots, provider)
                .build()
                .map_err(|_| TlsConfigError::InvalidTrustStore)?;
            builder.with_client_cert_verifier(verifier)
        }
        _ => return Err(TlsConfigError::ClientAuthMismatch),
    };
    let mut config = builder
        .with_single_cert(chain.certificates, key.key)
        .map_err(|_| TlsConfigError::InvalidPrivateKey)?;
    config.alpn_protocols = vec![profile.alpn().to_vec()];
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.ticketer = Ticketer::new().map_err(|_| TlsConfigError::ProviderUnavailable)?;
    Ok(Arc::new(config))
}

/// Builds one endpoint's server configuration on the blocking pool.
pub async fn build_server_config(
    profile: TlsEndpointProfile,
    chain: CertChain,
    key: PrivateKey,
    client_auth: ClientAuth,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    tokio::task::spawn_blocking(move || {
        build_server_config_blocking(profile, chain, key, client_auth)
    })
    .await
    .map_err(|_| TlsConfigError::ProviderUnavailable)?
}

/// Reads a certificate chain document from disk on the blocking pool.
///
/// Certificate chains are public material, so ordinary file reading applies;
/// private keys go through the configuration crate's secret-file rules.
pub async fn load_certificate_chain(path: std::path::PathBuf) -> Result<CertChain, TlsConfigError> {
    let document = tokio::task::spawn_blocking(move || read_bounded(&path))
        .await
        .map_err(|_| TlsConfigError::InvalidCertificate)??;
    CertChain::parse(&document)
}

/// Reads a private client-CA bundle on the blocking pool and builds the
/// endpoint-specific trust store. Public WebPKI roots are never added.
pub async fn load_trust_store(path: std::path::PathBuf) -> Result<TrustStore, TlsConfigError> {
    let document = tokio::task::spawn_blocking(move || read_bounded(&path))
        .await
        .map_err(|_| TlsConfigError::InvalidTrustStore)??;
    TrustStore::parse(&document)
}

/// A client configuration on the same provider, for tests and native
/// tooling; `alpn` may be absent to reproduce a client that offers none.
pub fn build_client_config(
    roots: TrustStore,
    alpn: Option<&[u8]>,
    client_certificate: Option<(CertChain, PrivateKey)>,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let builder = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsConfigError::ProviderUnavailable)?
        .with_root_certificates(Arc::clone(&roots.roots));
    let mut config = match client_certificate {
        None => builder.with_no_client_auth(),
        Some((chain, key)) => builder
            .with_client_auth_cert(chain.certificates, key.key)
            .map_err(|_| TlsConfigError::InvalidPrivateKey)?,
    };
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

fn parse_certificates(document: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
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

fn read_bounded(path: &std::path::Path) -> Result<Vec<u8>, TlsConfigError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| TlsConfigError::InvalidCertificate)?;
    if !metadata.is_file() || metadata.len() > MAX_TLS_DOCUMENT_BYTES as u64 {
        return Err(TlsConfigError::InvalidCertificate);
    }
    std::fs::read(path).map_err(|_| TlsConfigError::InvalidCertificate)
}

#[cfg(test)]
mod tests {
    use agenc_ircd_testkit::TlsFixture;

    use super::*;

    fn fixture() -> Result<TlsFixture, TlsConfigError> {
        TlsFixture::mint([9; 32], "node.test").map_err(|_| TlsConfigError::InvalidCertificate)
    }

    fn pem(label: &str, der: &[u8]) -> Vec<u8> {
        use base64_free::encode;
        let mut text = format!("-----BEGIN {label}-----\n");
        text.push_str(&encode(der));
        text.push_str(&format!("\n-----END {label}-----\n"));
        text.into_bytes()
    }

    mod base64_free {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        fn symbol(index: u32) -> char {
            ALPHABET
                .get(index as usize)
                .copied()
                .map_or('=', char::from)
        }

        pub(super) fn encode(bytes: &[u8]) -> String {
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let byte = |offset: usize| chunk.get(offset).copied().unwrap_or(0);
                let value =
                    (u32::from(byte(0)) << 16) | (u32::from(byte(1)) << 8) | u32::from(byte(2));
                let symbols = [
                    (value >> 18) & 63,
                    (value >> 12) & 63,
                    (value >> 6) & 63,
                    value & 63,
                ];
                for (index, code) in symbols.iter().enumerate() {
                    out.push(if index <= chunk.len() {
                        symbol(*code)
                    } else {
                        '='
                    });
                }
            }
            out
        }
    }

    #[test]
    fn profiles_map_purposes_and_alpn_identifiers_exactly() {
        assert_eq!(
            TlsEndpointProfile::for_purpose(ListenerPurpose::ClientTls),
            Some(TlsEndpointProfile::Client)
        );
        assert_eq!(
            TlsEndpointProfile::for_purpose(ListenerPurpose::ClientOnion),
            Some(TlsEndpointProfile::Client)
        );
        assert_eq!(
            TlsEndpointProfile::for_purpose(ListenerPurpose::Federation),
            Some(TlsEndpointProfile::Federation)
        );
        assert_eq!(
            TlsEndpointProfile::for_purpose(ListenerPurpose::AdminTls),
            Some(TlsEndpointProfile::Admin)
        );
        assert_eq!(
            TlsEndpointProfile::for_purpose(ListenerPurpose::AdminLocal),
            None
        );
        assert_eq!(
            TlsEndpointProfile::for_purpose(ListenerPurpose::ClientWss),
            None
        );
        assert_eq!(TlsEndpointProfile::Client.alpn(), b"agenc-chat/1");
        assert_eq!(TlsEndpointProfile::Federation.alpn(), b"agenc-chat-fed/1");
        assert_eq!(TlsEndpointProfile::Admin.alpn(), b"agenc-chat-admin/1");
        assert!(!TlsEndpointProfile::Client.requires_client_certificate());
        assert!(TlsEndpointProfile::Admin.requires_client_certificate());
    }

    #[test]
    fn documents_parse_from_der_and_pem_and_reject_bad_shapes() -> Result<(), TlsConfigError> {
        let fixture = fixture()?;
        let der_chain = CertChain::parse(fixture.leaf_certificate_der())?;
        assert_eq!(der_chain.len(), 1);
        assert!(!der_chain.is_empty());
        assert!(der_chain.leaf().is_some());
        let mut pem_chain = pem("CERTIFICATE", fixture.leaf_certificate_der());
        pem_chain.extend(pem("CERTIFICATE", fixture.ca_certificate_der()));
        assert_eq!(CertChain::parse(&pem_chain)?.len(), 2);
        let mut too_many = Vec::new();
        for _ in 0..=MAX_CHAIN_CERTIFICATES {
            too_many.extend(pem("CERTIFICATE", fixture.leaf_certificate_der()));
        }
        assert_eq!(
            CertChain::parse(&too_many).err(),
            Some(TlsConfigError::InvalidCertificate)
        );
        assert_eq!(
            CertChain::parse(b"").err(),
            Some(TlsConfigError::InvalidCertificate)
        );
        assert_eq!(
            CertChain::parse(b"not a certificate").err(),
            Some(TlsConfigError::InvalidCertificate)
        );
        assert_eq!(
            CertChain::parse(&vec![0x41; MAX_TLS_DOCUMENT_BYTES + 1]).err(),
            Some(TlsConfigError::InvalidCertificate)
        );

        assert!(PrivateKey::parse(fixture.leaf_private_key_pkcs8_der()).is_ok());
        assert!(
            PrivateKey::parse(&pem("PRIVATE KEY", fixture.leaf_private_key_pkcs8_der())).is_ok()
        );
        assert_eq!(
            PrivateKey::parse(b"").err(),
            Some(TlsConfigError::InvalidPrivateKey)
        );
        assert_eq!(
            PrivateKey::parse(b"-----BEGIN PRIVATE KEY-----\nAAAA\n").err(),
            Some(TlsConfigError::InvalidPrivateKey)
        );
        assert_eq!(
            PrivateKey::parse(&[DER_SEQUENCE_TAG, 0x01]).err(),
            Some(TlsConfigError::InvalidPrivateKey)
        );

        let store = TrustStore::parse(fixture.ca_certificate_der())?;
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        assert_eq!(
            TrustStore::parse(b"garbage").err(),
            Some(TlsConfigError::InvalidTrustStore)
        );
        assert_eq!(
            TrustStore::parse(&[DER_SEQUENCE_TAG, 0x00]).err(),
            Some(TlsConfigError::InvalidTrustStore)
        );
        Ok(())
    }

    #[test]
    fn server_configs_enforce_the_profile_and_client_auth_pairing() -> Result<(), TlsConfigError> {
        let fixture = fixture()?;
        let chain = || CertChain::parse(fixture.leaf_certificate_der());
        let key = || PrivateKey::parse(fixture.leaf_private_key_pkcs8_der());
        let store = || TrustStore::parse(fixture.ca_certificate_der());

        let client = build_server_config_blocking(
            TlsEndpointProfile::Client,
            chain()?,
            key()?,
            ClientAuth::None,
        )?;
        assert_eq!(client.alpn_protocols, vec![CLIENT_ALPN.to_vec()]);
        assert_eq!(client.max_early_data_size, 0);
        assert!(!client.send_half_rtt_data);

        let admin = build_server_config_blocking(
            TlsEndpointProfile::Admin,
            chain()?,
            key()?,
            ClientAuth::MutualTls(store()?),
        )?;
        assert_eq!(admin.alpn_protocols, vec![ADMIN_ALPN.to_vec()]);

        assert_eq!(
            build_server_config_blocking(
                TlsEndpointProfile::Client,
                chain()?,
                key()?,
                ClientAuth::MutualTls(store()?),
            )
            .err(),
            Some(TlsConfigError::ClientAuthMismatch)
        );
        assert_eq!(
            build_server_config_blocking(
                TlsEndpointProfile::Federation,
                chain()?,
                key()?,
                ClientAuth::None,
            )
            .err(),
            Some(TlsConfigError::ClientAuthMismatch)
        );

        let other = TlsFixture::mint([10; 32], "other.test")
            .map_err(|_| TlsConfigError::InvalidCertificate)?;
        assert_eq!(
            build_server_config_blocking(
                TlsEndpointProfile::Client,
                chain()?,
                PrivateKey::parse(other.leaf_private_key_pkcs8_der())?,
                ClientAuth::None,
            )
            .err(),
            Some(TlsConfigError::InvalidPrivateKey)
        );
        Ok(())
    }

    #[test]
    fn client_configs_accept_optional_alpn_and_client_certificates() -> Result<(), TlsConfigError> {
        let fixture = fixture()?;
        let store = TrustStore::parse(fixture.ca_certificate_der())?;
        let plain = build_client_config(store.clone(), None, None)?;
        assert!(plain.alpn_protocols.is_empty());
        assert!(!plain.enable_early_data);
        let with_alpn = build_client_config(store.clone(), Some(CLIENT_ALPN), None)?;
        assert_eq!(with_alpn.alpn_protocols, vec![CLIENT_ALPN.to_vec()]);
        let mutual = build_client_config(
            store,
            Some(ADMIN_ALPN),
            Some((
                CertChain::parse(fixture.leaf_certificate_der())?,
                PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
            )),
        )?;
        assert_eq!(mutual.alpn_protocols, vec![ADMIN_ALPN.to_vec()]);
        assert_eq!(
            RuntimeError::from(TlsConfigError::ProviderUnavailable),
            RuntimeError::InvalidValue
        );
        for error in [
            TlsConfigError::InvalidCertificate,
            TlsConfigError::InvalidPrivateKey,
            TlsConfigError::InvalidTrustStore,
            TlsConfigError::ClientAuthMismatch,
            TlsConfigError::ProviderUnavailable,
        ] {
            assert!(error.to_string().is_ascii());
        }
        Ok(())
    }

    #[tokio::test]
    async fn async_builders_run_on_the_blocking_pool() -> Result<(), TlsConfigError> {
        let fixture = fixture()?;
        let directory = std::env::temp_dir().join(format!(
            "agenc-tls-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&directory).map_err(|_| TlsConfigError::InvalidCertificate)?;
        let chain_path = directory.join("chain.der");
        std::fs::write(&chain_path, fixture.leaf_certificate_der())
            .map_err(|_| TlsConfigError::InvalidCertificate)?;
        let chain = load_certificate_chain(chain_path.clone()).await?;
        assert_eq!(chain.len(), 1);
        assert_eq!(
            load_certificate_chain(directory.join("missing.der"))
                .await
                .err(),
            Some(TlsConfigError::InvalidCertificate)
        );
        assert_eq!(
            load_certificate_chain(directory.clone()).await.err(),
            Some(TlsConfigError::InvalidCertificate)
        );
        let config = build_server_config(
            TlsEndpointProfile::Client,
            chain,
            PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
            ClientAuth::None,
        )
        .await?;
        assert_eq!(config.alpn_protocols, vec![CLIENT_ALPN.to_vec()]);
        let _ = std::fs::remove_dir_all(directory);
        Ok(())
    }
}
