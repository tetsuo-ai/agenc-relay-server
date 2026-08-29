#![forbid(unsafe_code)]

//! The TLS endpoint matrix of spec 8.1 through 8.3 (lines 464-526) against
//! the hand-driven server stream: hybrid-first key exchange, X25519
//! fallback, TLS 1.2 refusal, ALPN enforcement before any application byte,
//! certificate authority mismatch, the handshake deadline, a PROXY header on
//! the onion path, and mutual TLS with the SPKI pin and exporter.

use std::error::Error;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use agenc_ircd_runtime::listener::spki_sha256;
use agenc_ircd_runtime::tls::{
    ACCEPT_TO_TLS_DEADLINE, ADMIN_ALPN, CLIENT_ALPN, CertChain, ClientAuth, PrivateKey,
    TlsConfigError, TlsEndpointProfile, TlsHandshakeError, TlsStream, TrustStore,
    build_client_config, build_server_config_blocking, provider,
};
use agenc_ircd_testkit::TlsFixture;
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, NamedGroup, ServerConfig, StreamOwned};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
type ClientOutcome = Result<Vec<u8>, String>;

const DNS_NAME: &str = "node.test";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-agenc-chat-admin-v1";

fn fixture(seed: u8) -> Result<TlsFixture, Box<dyn Error + Send + Sync>> {
    Ok(TlsFixture::mint([seed; 32], DNS_NAME)?)
}

fn server(
    fixture: &TlsFixture,
    profile: TlsEndpointProfile,
    auth: ClientAuth,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    build_server_config_blocking(
        profile,
        CertChain::parse(fixture.leaf_certificate_der())?,
        PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
        auth,
    )
}

fn client(
    trusted: &TlsFixture,
    alpn: Option<&[u8]>,
    certificate: Option<&TlsFixture>,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let auth = match certificate {
        Some(owner) => Some((
            CertChain::parse(owner.leaf_certificate_der())?,
            PrivateKey::parse(owner.leaf_private_key_pkcs8_der())?,
        )),
        None => None,
    };
    build_client_config(TrustStore::parse(trusted.ca_certificate_der())?, alpn, auth)
}

fn connect(
    address: SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let name = ServerName::try_from(DNS_NAME.to_owned()).map_err(|error| error.to_string())?;
    let connection = ClientConnection::new(config, name).map_err(|error| error.to_string())?;
    let socket = TcpStream::connect(address).map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let mut stream = StreamOwned::new(connection, socket);
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|error| error.to_string())?;
    }
    Ok(stream)
}

/// Connects, handshakes, writes `send`, then reads until the server closes.
fn exchange(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    send: &'static [u8],
) -> JoinHandle<ClientOutcome> {
    thread::spawn(move || {
        let mut stream = connect(address, config)?;
        stream.write_all(send).map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
        let mut received = Vec::new();
        let mut buffer = [0_u8; 256];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => received.extend_from_slice(buffer.get(..read).unwrap_or_default()),
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(received)
    })
}

async fn bind() -> Result<(TcpListener, SocketAddr), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    Ok((listener, address))
}

#[tokio::test]
async fn hybrid_key_exchange_and_exact_alpn_carry_bytes_both_ways() -> TestResult {
    let fixture = fixture(31)?;
    let (listener, address) = bind().await?;
    let client = exchange(
        address,
        client(&fixture, Some(CLIENT_ALPN), None)?,
        b"PING :x\r\n",
    );
    let (socket, _) = listener.accept().await?;
    let config = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let mut stream =
        TlsStream::handshake(socket, config, CLIENT_ALPN, ACCEPT_TO_TLS_DEADLINE).await?;
    assert_eq!(stream.negotiated_group(), Some(NamedGroup::X25519MLKEM768));
    assert_eq!(stream.alpn(), Some(CLIENT_ALPN));
    assert!(stream.peer_certificates().is_none());
    let mut line = vec![0_u8; 9];
    stream.read_exact(&mut line).await?;
    assert_eq!(line, b"PING :x\r\n");
    stream.write_all(b"PONG :x\r\n").await?;
    stream.shutdown().await?;
    let received = client.join().map_err(|_| "client thread panicked")??;
    assert_eq!(received, b"PONG :x\r\n");
    Ok(())
}

#[tokio::test]
async fn a_client_offering_only_x25519_falls_back_to_it() -> TestResult {
    let fixture = fixture(32)?;
    let mut fallback_provider = provider();
    fallback_provider.kx_groups = vec![kx_group::X25519];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(
        fixture.ca_certificate_der().to_vec(),
    ))?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(fallback_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![CLIENT_ALPN.to_vec()];
    let (listener, address) = bind().await?;
    let client = exchange(address, Arc::new(config), b"");
    let (socket, _) = listener.accept().await?;
    let server = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let mut stream =
        TlsStream::handshake(socket, server, CLIENT_ALPN, ACCEPT_TO_TLS_DEADLINE).await?;
    assert_eq!(stream.negotiated_group(), Some(NamedGroup::X25519));
    stream.shutdown().await?;
    assert!(client.join().map_err(|_| "client thread panicked")?.is_ok());
    Ok(())
}

/// A TLS 1.2 ClientHello with one AES-GCM suite and no
/// `supported_versions` extension, so the peer can only mean TLS 1.2.
fn tls12_client_hello() -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend(std::iter::repeat_n(0x42, 32));
    body.push(0x00);
    body.extend([0x00, 0x02, 0xC0, 0x2F]);
    body.extend([0x01, 0x00]);
    body.extend([0x00, 0x00]);
    let mut handshake = vec![0x01, 0x00, 0x00];
    handshake.push(u8::try_from(body.len()).unwrap_or(0));
    handshake.extend(body);
    let mut record = vec![0x16, 0x03, 0x01, 0x00];
    record.push(u8::try_from(handshake.len()).unwrap_or(0));
    record.extend(handshake);
    record
}

#[tokio::test]
async fn a_tls_12_only_client_is_refused() -> TestResult {
    assert_eq!(
        rustls::ALL_VERSIONS.len(),
        1,
        "the pinned rustls build compiles only TLS 1.3"
    );
    let fixture = fixture(33)?;
    let (listener, address) = bind().await?;
    let mut raw = TcpStream::connect(address)?;
    raw.write_all(&tls12_client_hello())?;
    raw.flush()?;
    let (socket, _) = listener.accept().await?;
    let server = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let outcome = TlsStream::handshake(socket, server, CLIENT_ALPN, ACCEPT_TO_TLS_DEADLINE).await;
    assert_eq!(outcome.err(), Some(TlsHandshakeError::Protocol));
    Ok(())
}

#[tokio::test]
async fn a_wrong_alpn_is_refused_inside_the_handshake() -> TestResult {
    let fixture = fixture(34)?;
    let (listener, address) = bind().await?;
    let client = exchange(
        address,
        client(&fixture, Some(b"wrong/1"), None)?,
        b"HELLO\r\n",
    );
    let (socket, _) = listener.accept().await?;
    let server = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let outcome = TlsStream::handshake(socket, server, CLIENT_ALPN, ACCEPT_TO_TLS_DEADLINE).await;
    assert_eq!(outcome.err(), Some(TlsHandshakeError::Protocol));
    assert!(
        client
            .join()
            .map_err(|_| "client thread panicked")?
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn an_absent_alpn_completes_the_handshake_and_is_then_refused() -> TestResult {
    let fixture = fixture(35)?;
    let (listener, address) = bind().await?;
    let client = exchange(address, client(&fixture, None, None)?, b"HELLO\r\n");
    let (socket, _) = listener.accept().await?;
    let server = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let outcome = TlsStream::handshake(socket, server, CLIENT_ALPN, ACCEPT_TO_TLS_DEADLINE).await;
    assert_eq!(outcome.err(), Some(TlsHandshakeError::AlpnMissing));
    let received = client.join().map_err(|_| "client thread panicked")?;
    assert!(
        received.map(|bytes| bytes.is_empty()).unwrap_or(true),
        "the peer got close-notify or a reset and never an application byte"
    );
    Ok(())
}

#[tokio::test]
async fn a_leaf_from_another_authority_fails_both_sides() -> TestResult {
    let trusted = fixture(36)?;
    let untrusted = fixture(37)?;
    let (listener, address) = bind().await?;
    let client = exchange(address, client(&trusted, Some(CLIENT_ALPN), None)?, b"");
    let (socket, _) = listener.accept().await?;
    let server = server(&untrusted, TlsEndpointProfile::Client, ClientAuth::None)?;
    let outcome = TlsStream::handshake(socket, server, CLIENT_ALPN, ACCEPT_TO_TLS_DEADLINE).await;
    assert!(outcome.is_err());
    assert!(
        client
            .join()
            .map_err(|_| "client thread panicked")?
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn a_silent_peer_hits_the_handshake_deadline() -> TestResult {
    let fixture = fixture(38)?;
    let (listener, address) = bind().await?;
    let silent = TcpStream::connect(address)?;
    let (socket, _) = listener.accept().await?;
    let server = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let outcome =
        TlsStream::handshake(socket, server, CLIENT_ALPN, Duration::from_millis(200)).await;
    assert_eq!(outcome.err(), Some(TlsHandshakeError::Timeout));
    drop(silent);
    Ok(())
}

#[tokio::test]
async fn a_proxy_header_is_not_a_tls_record() -> TestResult {
    let fixture = fixture(39)?;
    let (listener, address) = bind().await?;
    let mut raw = TcpStream::connect(address)?;
    raw.write_all(b"PROXY TCP4 192.0.2.1 192.0.2.2 1000 6697\r\n")?;
    let (socket, _) = listener.accept().await?;
    let server = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let outcome = TlsStream::handshake(socket, server, CLIENT_ALPN, ACCEPT_TO_TLS_DEADLINE).await;
    assert_eq!(outcome.err(), Some(TlsHandshakeError::Protocol));
    Ok(())
}

#[tokio::test]
async fn a_peer_that_closes_mid_handshake_is_reported_as_closed() -> TestResult {
    let fixture = fixture(40)?;
    let (listener, address) = bind().await?;
    let raw = TcpStream::connect(address)?;
    drop(raw);
    let (socket, _) = listener.accept().await?;
    let server = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let outcome = TlsStream::handshake(socket, server, CLIENT_ALPN, ACCEPT_TO_TLS_DEADLINE).await;
    assert!(matches!(
        outcome.err(),
        Some(TlsHandshakeError::PeerClosed | TlsHandshakeError::Io)
    ));
    Ok(())
}

#[tokio::test]
async fn mutual_tls_exposes_the_peer_spki_and_a_shared_exporter() -> TestResult {
    let fixture = fixture(41)?;
    let (listener, address) = bind().await?;
    let config = client(&fixture, Some(ADMIN_ALPN), Some(&fixture))?;
    let client_thread = thread::spawn(move || -> Result<[u8; 32], String> {
        let mut stream = connect(address, config)?;
        let mut exporter = [0_u8; 32];
        stream
            .conn
            .export_keying_material(&mut exporter, EXPORTER_LABEL, Some(b"context"))
            .map_err(|error| error.to_string())?;
        let mut buffer = [0_u8; 8];
        let _ = stream.read(&mut buffer);
        Ok(exporter)
    });
    let (socket, _) = listener.accept().await?;
    let store = TrustStore::parse(fixture.ca_certificate_der())?;
    let server = server(
        &fixture,
        TlsEndpointProfile::Admin,
        ClientAuth::MutualTls(store),
    )?;
    let mut stream =
        TlsStream::handshake(socket, server, ADMIN_ALPN, ACCEPT_TO_TLS_DEADLINE).await?;
    let leaf = stream
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or("no peer certificate")?;
    assert_eq!(
        spki_sha256(leaf.as_ref()),
        Some(*fixture.leaf_spki_sha256())
    );
    let mut exporter = [0_u8; 32];
    stream.export_keying_material(&mut exporter, EXPORTER_LABEL, b"context")?;
    stream.shutdown().await?;
    let client_exporter = client_thread
        .join()
        .map_err(|_| "client thread panicked")??;
    assert_eq!(exporter, client_exporter);
    assert_ne!(exporter, [0_u8; 32]);
    Ok(())
}

#[tokio::test]
async fn mutual_tls_refuses_a_client_without_a_certificate() -> TestResult {
    let fixture = fixture(42)?;
    let (listener, address) = bind().await?;
    let client = exchange(address, client(&fixture, Some(ADMIN_ALPN), None)?, b"");
    let (socket, _) = listener.accept().await?;
    let store = TrustStore::parse(fixture.ca_certificate_der())?;
    let server = server(
        &fixture,
        TlsEndpointProfile::Admin,
        ClientAuth::MutualTls(store),
    )?;
    let outcome = TlsStream::handshake(socket, server, ADMIN_ALPN, ACCEPT_TO_TLS_DEADLINE).await;
    assert!(outcome.is_err());
    assert!(
        client
            .join()
            .map_err(|_| "client thread panicked")?
            .is_err()
    );
    Ok(())
}
