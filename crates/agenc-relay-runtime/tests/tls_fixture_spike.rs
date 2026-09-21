#![forbid(unsafe_code)]

//! Proves the testkit certificate fixture against the exact Stage 06 TLS
//! profile: explicit aws-lc provider, TLS 1.3 only, the three suites, the
//! `[X25519MLKEM768, X25519]` order, exact ALPN, and no early data (spec
//! 8.1, lines 464-492).

use std::error::Error;
use std::io::Read as _;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use agenc_relay_testkit::TlsFixture;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, cipher_suite, kx_group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
};

const CLIENT_ALPN: &[u8] = b"agenc-chat/1";
const DNS_NAME: &str = "node.test";

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
type ServerResult = Result<ServerOutcome, String>;
type ClientResult = Result<Option<Vec<u8>>, String>;
type HandshakeResult = Result<(ServerResult, ClientResult), Box<dyn Error + Send + Sync>>;

fn provider() -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = vec![kx_group::X25519MLKEM768, kx_group::X25519];
    provider
}

fn server_config(fixture: &TlsFixture) -> Result<Arc<ServerConfig>, Box<dyn Error + Send + Sync>> {
    let chain = vec![CertificateDer::from(
        fixture.leaf_certificate_der().to_vec(),
    )];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        fixture.leaf_private_key_pkcs8_der().to_vec(),
    ));
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![CLIENT_ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Ok(Arc::new(config))
}

fn client_config(
    fixture: &TlsFixture,
    alpn: Option<&[u8]>,
) -> Result<Arc<ClientConfig>, Box<dyn Error + Send + Sync>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(fixture.ca_certificate_der().to_vec()))?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    Ok(Arc::new(config))
}

struct ServerOutcome {
    group: Option<NamedGroup>,
    alpn: Option<Vec<u8>>,
    application_bytes: usize,
}

fn drive_server(config: Arc<ServerConfig>, mut stream: TcpStream) -> ServerResult {
    let mut connection = ServerConnection::new(config).map_err(|error| error.to_string())?;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut stream)
            .map_err(|error| error.to_string())?;
    }
    while connection.wants_write() {
        connection
            .complete_io(&mut stream)
            .map_err(|error| error.to_string())?;
    }
    let mut buffer = [0_u8; 64];
    let application_bytes = connection.reader().read(&mut buffer).unwrap_or(0);
    Ok(ServerOutcome {
        group: connection
            .negotiated_key_exchange_group()
            .map(|group| group.name()),
        alpn: connection.alpn_protocol().map(<[u8]>::to_vec),
        application_bytes,
    })
}

fn drive_client(config: Arc<ClientConfig>, mut stream: TcpStream) -> ClientResult {
    let name = ServerName::try_from(DNS_NAME.to_owned()).map_err(|error| error.to_string())?;
    let mut connection = ClientConnection::new(config, name).map_err(|error| error.to_string())?;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut stream)
            .map_err(|error| error.to_string())?;
    }
    Ok(connection.alpn_protocol().map(<[u8]>::to_vec))
}

fn handshake(server: Arc<ServerConfig>, client: Arc<ClientConfig>) -> HandshakeResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
        drive_server(server, stream)
    });
    let client_result = drive_client(client, TcpStream::connect(address)?);
    let server_result = server_thread.join().map_err(|_| "server thread panicked")?;
    Ok((server_result, client_result))
}

#[test]
fn hybrid_group_is_negotiated_first_and_the_exact_alpn_completes() -> TestResult {
    let fixture = TlsFixture::mint([3; 32], DNS_NAME)?;
    let (server, client) = handshake(
        server_config(&fixture)?,
        client_config(&fixture, Some(CLIENT_ALPN))?,
    )?;
    let server = server?;
    assert_eq!(server.group, Some(NamedGroup::X25519MLKEM768));
    assert_eq!(server.alpn.as_deref(), Some(CLIENT_ALPN));
    assert_eq!(server.application_bytes, 0);
    assert_eq!(client?.as_deref(), Some(CLIENT_ALPN));
    Ok(())
}

#[test]
fn a_mismatched_alpn_fails_the_handshake_before_any_application_byte() -> TestResult {
    let fixture = TlsFixture::mint([4; 32], DNS_NAME)?;
    let (server, client) = handshake(
        server_config(&fixture)?,
        client_config(&fixture, Some(b"wrong/1"))?,
    )?;
    let server_error = server.err().ok_or("server accepted a mismatched ALPN")?;
    // rustls renders `NoApplicationProtocol` as this fixed sentence.
    assert!(
        server_error.contains("doesn't support any known protocol"),
        "{server_error}"
    );
    assert!(client.is_err());
    Ok(())
}

#[test]
fn an_absent_alpn_completes_without_a_protocol_so_the_runtime_must_enforce_it() -> TestResult {
    let fixture = TlsFixture::mint([5; 32], DNS_NAME)?;
    let (server, client) = handshake(server_config(&fixture)?, client_config(&fixture, None)?)?;
    let server = server?;
    assert_eq!(server.alpn, None);
    assert_eq!(client?, None);
    Ok(())
}

#[test]
fn a_leaf_from_another_authority_is_rejected() -> TestResult {
    let trusted = TlsFixture::mint([6; 32], DNS_NAME)?;
    let untrusted = TlsFixture::mint([7; 32], DNS_NAME)?;
    let (server, client) = handshake(
        server_config(&untrusted)?,
        client_config(&trusted, Some(CLIENT_ALPN))?,
    )?;
    assert!(client.is_err());
    assert!(server.is_err());
    Ok(())
}
