#![forbid(unsafe_code)]

//! Native-client Tor SOCKS5 transcript and isolation tests.

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agenc_ircd_config::{
    DnsEndpoint, DnsName, OnboardingDescriptor, OnionAddress, OnionEndpoint, SocksEndpoint,
};
use agenc_ircd_runtime::tls::{
    CLIENT_ALPN, CertChain, ClientAuth, PrivateKey, TlsEndpointProfile, TlsStream, TrustStore,
    build_server_config_blocking,
};
use agenc_ircd_runtime::tor_client::{
    TorClientOwner, TorClientProfile, TorClientTls, TorConnectError, TorIsolationContext,
};
use agenc_ircd_testkit::{ScriptedEntropy, TlsFixture};
use agenc_ircd_types::{AccountId, AccountRandomId, NetworkId, RecoveryEpoch};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

const SOCKS_SUCCESS: [u8; 10] = [5, 0, 0, 1, 127, 0, 0, 1, 26, 41];

enum ProxyBehavior {
    TlsSuccess(Arc<ServerConfig>),
    TlsRejection(Arc<ServerConfig>),
    InvalidSelection,
    AuthenticationRefused,
    TargetRefused,
}

#[derive(Debug, Eq, PartialEq)]
struct SocksRequest {
    username: Vec<u8>,
    password: Vec<u8>,
    hostname: String,
    port: u16,
}

fn descriptor(
    onion_spki_sha256: [u8; 32],
) -> Result<OnboardingDescriptor, Box<dyn Error + Send + Sync>> {
    Ok(OnboardingDescriptor {
        network_id: NetworkId::from_bytes([7; 32]),
        server_name: DnsName::parse("chat.example")?,
        dns: Some(DnsEndpoint {
            name: DnsName::parse("chat.example")?,
            port: 6697,
        }),
        onion: Some(OnionEndpoint {
            address: OnionAddress::parse(&format!("{}.onion", "a".repeat(56)))?,
            port: 6697,
            tls_spki_sha256: onion_spki_sha256,
        }),
        recovery_epoch: RecoveryEpoch::from_bytes([9; 16]),
        account_service_hpke_key_id: [10; 32],
        account_service_hpke_public_key: [11; 32],
        sequencer_key_set_generation: 12,
        sequencer_key_set_hash: [13; 32],
    })
}

fn client_tls(fixture: &TlsFixture) -> Result<TorClientTls, Box<dyn Error + Send + Sync>> {
    Ok(TorClientTls::new(TrustStore::parse(
        fixture.ca_certificate_der(),
    )?))
}

fn server_tls(
    fixture: &TlsFixture,
    alpn: &[u8],
) -> Result<Arc<ServerConfig>, Box<dyn Error + Send + Sync>> {
    let mut config = build_server_config_blocking(
        TlsEndpointProfile::Client,
        CertChain::parse(fixture.leaf_certificate_der())?,
        PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
        ClientAuth::None,
    )?;
    Arc::get_mut(&mut config)
        .ok_or_else(|| io::Error::other("test TLS config was unexpectedly shared"))?
        .alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

fn account(byte: u8) -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([byte; 16]))
}

fn entropy_for(contexts: usize) -> Result<ScriptedEntropy, Box<dyn Error + Send + Sync>> {
    let byte_count = contexts
        .checked_mul(64)
        .ok_or_else(|| io::Error::other("entropy fixture size overflow"))?;
    let bytes = (0..byte_count)
        .map(|index| u8::try_from(index % 251))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ScriptedEntropy::new(bytes)?)
}

async fn proxy(
    listener: TcpListener,
    behaviors: Vec<ProxyBehavior>,
) -> io::Result<Vec<SocksRequest>> {
    let mut requests = Vec::new();
    for behavior in behaviors {
        let (mut stream, _source) = listener.accept().await?;
        let Some(request) = serve_connection(&mut stream, behavior).await? else {
            continue;
        };
        requests.push(request);
    }
    Ok(requests)
}

async fn serve_connection(
    stream: &mut TcpStream,
    behavior: ProxyBehavior,
) -> io::Result<Option<SocksRequest>> {
    let mut greeting = [0_u8; 3];
    stream.read_exact(&mut greeting).await?;
    require_bytes(&greeting, &[5, 1, 2])?;
    if matches!(&behavior, ProxyBehavior::InvalidSelection) {
        stream.write_all(&[4, 2]).await?;
        return Ok(None);
    }
    stream.write_all(&[5, 2]).await?;

    let (username, password) = read_authentication(stream).await?;
    if matches!(&behavior, ProxyBehavior::AuthenticationRefused) {
        stream.write_all(&[1, 1]).await?;
        return Ok(None);
    }
    stream.write_all(&[1, 0]).await?;

    let (hostname, port) = read_hostname_request(stream).await?;
    if matches!(&behavior, ProxyBehavior::TargetRefused) {
        stream.write_all(&[5, 5, 0, 1]).await?;
    } else {
        stream.write_all(&SOCKS_SUCCESS).await?;
    }
    let request = SocksRequest {
        username,
        password,
        hostname,
        port,
    };
    let tls = match behavior {
        ProxyBehavior::TlsSuccess(config) => Some((config, true)),
        ProxyBehavior::TlsRejection(config) => Some((config, false)),
        _ => None,
    };
    if let Some((config, expected_success)) = tls {
        let result =
            TlsStream::handshake(stream, config, CLIENT_ALPN, Duration::from_secs(1)).await;
        let succeeded = result.is_ok();
        drop(result);
        if succeeded != expected_success {
            return Err(io::Error::other("unexpected TLS handshake outcome"));
        }
    }
    Ok(Some(request))
}

async fn read_authentication(stream: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 1 || header[1] == 0 {
        return Err(io::Error::other("invalid username/password header"));
    }
    let mut username = vec![0_u8; usize::from(header[1])];
    stream.read_exact(&mut username).await?;
    let mut encoded_password_length = [0_u8; 1];
    stream.read_exact(&mut encoded_password_length).await?;
    if encoded_password_length[0] == 0 {
        return Err(io::Error::other("empty SOCKS password"));
    }
    let mut password = vec![0_u8; usize::from(encoded_password_length[0])];
    stream.read_exact(&mut password).await?;
    Ok((username, password))
}

async fn read_hostname_request(stream: &mut TcpStream) -> io::Result<(String, u16)> {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).await?;
    if header[..4] != [5, 1, 0, 3] || header[4] == 0 {
        return Err(io::Error::other("request was not SOCKS hostname form"));
    }
    let mut hostname = vec![0_u8; usize::from(header[4])];
    stream.read_exact(&mut hostname).await?;
    let mut encoded_port = [0_u8; 2];
    stream.read_exact(&mut encoded_port).await?;
    let hostname = String::from_utf8(hostname)
        .map_err(|_| io::Error::other("SOCKS hostname was not UTF-8"))?;
    Ok((hostname, u16::from_be_bytes(encoded_port)))
}

fn require_bytes(actual: &[u8], expected: &[u8]) -> io::Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::other("unexpected SOCKS transcript bytes"))
    }
}

async fn listener() -> io::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let address = listener.local_addr()?;
    Ok((listener, address))
}

#[tokio::test]
async fn profiles_send_only_the_selected_hostname_through_socks() -> TestResult {
    let direct_fixture = TlsFixture::mint([31; 32], "chat.example")?;
    let onion_name = format!("{}.onion", "a".repeat(56));
    let onion_fixture = TlsFixture::mint([36; 32], &onion_name)?;
    let descriptor = descriptor(*onion_fixture.leaf_spki_sha256())?;
    let tls = client_tls(&direct_fixture)?;
    let context = TorIsolationContext::network(descriptor.network_id);
    let (listener, address) = listener().await?;
    let server = tokio::spawn(proxy(
        listener,
        vec![
            ProxyBehavior::TlsSuccess(server_tls(&direct_fixture, CLIENT_ALPN)?),
            ProxyBehavior::TlsSuccess(server_tls(&onion_fixture, CLIENT_ALPN)?),
        ],
    ));
    let mut entropy = entropy_for(1)?;
    let owner = TorClientOwner::new(
        SocksEndpoint::Loopback(address),
        vec![context],
        Duration::from_secs(1),
        &mut entropy,
    )?;

    let tor_exit = owner
        .connect(context, TorClientProfile::TorExit, &descriptor, &tls)
        .await?;
    assert_eq!(tor_exit.tls_server_name(), "chat.example");
    assert_eq!(tor_exit.tls_spki_sha256(), None);

    let onion = owner
        .connect(context, TorClientProfile::Onion, &descriptor, &tls)
        .await?;
    assert_eq!(onion.profile(), TorClientProfile::Onion);
    assert_eq!(
        onion.tls_spki_sha256(),
        Some(onion_fixture.leaf_spki_sha256())
    );

    let requests = server.await??;
    let [exit_request, onion_request] = requests.as_slice() else {
        return Err(io::Error::other("proxy did not receive two requests").into());
    };
    assert_eq!(exit_request.hostname, "chat.example");
    assert_eq!(exit_request.port, 6697);
    assert_eq!(onion_request.hostname, format!("{}.onion", "a".repeat(56)));
    assert_eq!(onion_request.port, 6697);
    Ok(())
}

#[tokio::test]
async fn account_contexts_never_share_credentials_and_reconnects_reuse_them() -> TestResult {
    let fixture = TlsFixture::mint([32; 32], "chat.example")?;
    let descriptor = descriptor(*fixture.leaf_spki_sha256())?;
    let tls = client_tls(&fixture)?;
    let network = TorIsolationContext::network(descriptor.network_id);
    let account_one = TorIsolationContext::account(descriptor.network_id, account(1));
    let account_two = TorIsolationContext::account(descriptor.network_id, account(2));
    let (listener, address) = listener().await?;
    let server = tokio::spawn(proxy(
        listener,
        vec![
            ProxyBehavior::TlsSuccess(server_tls(&fixture, CLIENT_ALPN)?),
            ProxyBehavior::TlsSuccess(server_tls(&fixture, CLIENT_ALPN)?),
            ProxyBehavior::TlsSuccess(server_tls(&fixture, CLIENT_ALPN)?),
            ProxyBehavior::TlsSuccess(server_tls(&fixture, CLIENT_ALPN)?),
        ],
    ));
    let mut entropy = entropy_for(3)?;
    let owner = TorClientOwner::new(
        SocksEndpoint::Loopback(address),
        vec![network, account_one, account_two],
        Duration::from_secs(1),
        &mut entropy,
    )?;

    for context in [network, account_one, account_two, account_one] {
        let _connection = owner
            .connect(context, TorClientProfile::TorExit, &descriptor, &tls)
            .await?;
    }

    let requests = server.await??;
    let [
        network_request,
        account_one_first,
        account_two_request,
        account_one_second,
    ] = requests.as_slice()
    else {
        return Err(io::Error::other("proxy did not receive four requests").into());
    };
    assert_ne!(network_request.username, account_one_first.username);
    assert_ne!(account_one_first.username, account_two_request.username);
    assert_eq!(account_one_first.username, account_one_second.username);
    assert_eq!(account_one_first.password, account_one_second.password);
    Ok(())
}

#[tokio::test]
async fn malformed_authentication_and_target_refusal_fail_closed() -> TestResult {
    let fixture = TlsFixture::mint([33; 32], "chat.example")?;
    let tls = client_tls(&fixture)?;
    for (behavior, expected) in [
        (
            ProxyBehavior::InvalidSelection,
            TorConnectError::InvalidProxyReply,
        ),
        (
            ProxyBehavior::AuthenticationRefused,
            TorConnectError::AuthenticationRefused,
        ),
        (ProxyBehavior::TargetRefused, TorConnectError::TargetRefused),
    ] {
        let descriptor = descriptor(*fixture.leaf_spki_sha256())?;
        let context = TorIsolationContext::network(descriptor.network_id);
        let (listener, address) = listener().await?;
        let server = tokio::spawn(proxy(listener, vec![behavior]));
        let mut entropy = entropy_for(1)?;
        let owner = TorClientOwner::new(
            SocksEndpoint::Loopback(address),
            vec![context],
            Duration::from_secs(1),
            &mut entropy,
        )?;

        let result = owner
            .connect(context, TorClientProfile::TorExit, &descriptor, &tls)
            .await;
        assert!(matches!(result, Err(error) if error == expected));
        let _requests = server.await??;
    }
    Ok(())
}

#[tokio::test]
async fn onion_refusal_does_not_fall_back_to_the_clearnet_profile() -> TestResult {
    let fixture = TlsFixture::mint([34; 32], "chat.example")?;
    let descriptor = descriptor(*fixture.leaf_spki_sha256())?;
    let tls = client_tls(&fixture)?;
    let context = TorIsolationContext::network(descriptor.network_id);
    let (listener, address) = listener().await?;
    let server = tokio::spawn(proxy(listener, vec![ProxyBehavior::TargetRefused]));
    let mut entropy = entropy_for(1)?;
    let owner = TorClientOwner::new(
        SocksEndpoint::Loopback(address),
        vec![context],
        Duration::from_secs(1),
        &mut entropy,
    )?;

    let result = owner
        .connect(context, TorClientProfile::Onion, &descriptor, &tls)
        .await;
    assert!(matches!(result, Err(TorConnectError::TargetRefused)));
    let requests = server.await??;
    let [request] = requests.as_slice() else {
        return Err(io::Error::other("proxy did not receive one request").into());
    };
    assert_eq!(request.hostname, format!("{}.onion", "a".repeat(56)));
    assert_ne!(request.hostname, "chat.example");
    Ok(())
}

#[tokio::test]
async fn tls_name_pin_and_alpn_failures_end_the_tor_attempt() -> TestResult {
    let trusted = TlsFixture::mint([35; 32], "chat.example")?;
    let onion_name = format!("{}.onion", "a".repeat(56));
    let onion = TlsFixture::mint([35; 32], &onion_name)?;
    let wrong_name = TlsFixture::mint([35; 32], "wrong.example")?;
    let tls = client_tls(&trusted)?;
    let correct = descriptor(*onion.leaf_spki_sha256())?;
    let wrong_pin = descriptor([0xA5; 32])?;
    let cases = [
        (
            TorClientProfile::TorExit,
            correct.clone(),
            server_tls(&wrong_name, CLIENT_ALPN)?,
        ),
        (
            TorClientProfile::Onion,
            wrong_pin,
            server_tls(&onion, CLIENT_ALPN)?,
        ),
        (
            TorClientProfile::TorExit,
            correct,
            server_tls(&trusted, b"agenc-chat-wrong/1")?,
        ),
    ];
    for (profile, descriptor, server_config) in cases {
        let context = TorIsolationContext::network(descriptor.network_id);
        let (listener, address) = listener().await?;
        let server = tokio::spawn(proxy(
            listener,
            vec![ProxyBehavior::TlsRejection(server_config)],
        ));
        let mut entropy = entropy_for(1)?;
        let owner = TorClientOwner::new(
            SocksEndpoint::Loopback(address),
            vec![context],
            Duration::from_secs(1),
            &mut entropy,
        )?;
        let result = owner.connect(context, profile, &descriptor, &tls).await;
        assert!(matches!(result, Err(TorConnectError::TlsRejected)));
        let requests = server.await??;
        assert_eq!(requests.len(), 1);
    }
    Ok(())
}

#[test]
fn context_set_is_unique_and_hard_bounded() -> TestResult {
    let network_id = NetworkId::from_bytes([7; 32]);
    let network = TorIsolationContext::network(network_id);
    let too_many = std::iter::once(network)
        .chain((0_u8..=u8::MAX).map(|byte| TorIsolationContext::account(network_id, account(byte))))
        .collect();
    let proxy = SocksEndpoint::Loopback(SocketAddr::from(([127, 0, 0, 1], 9050)));
    let mut entropy = ScriptedEntropy::new(Vec::new())?;
    let above_ceiling = TorClientOwner::new(
        proxy.clone(),
        too_many,
        Duration::from_secs(1),
        &mut entropy,
    );
    assert!(matches!(
        above_ceiling,
        Err(TorConnectError::InvalidContexts)
    ));

    let duplicate = TorClientOwner::new(
        proxy,
        vec![network, network],
        Duration::from_secs(1),
        &mut entropy,
    );
    assert!(matches!(duplicate, Err(TorConnectError::InvalidContexts)));
    Ok(())
}
