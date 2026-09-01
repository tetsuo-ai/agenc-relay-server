//! Native-client Tor SOCKS5 transport with context-scoped stream isolation.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use agenc_ircd_config::{OnboardingDescriptor, SocksEndpoint};
use agenc_ircd_types::{AccountId, EntropySource, NetworkId};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use zeroize::Zeroizing;

use crate::sync::Arc;
use crate::tls::{
    CLIENT_ALPN, ClientTlsStream, TrustStore, build_client_config, build_pinned_client_config,
};

const SOCKS_VERSION: u8 = 5;
const SOCKS_USERNAME_PASSWORD: u8 = 2;
const SOCKS_CONNECT: u8 = 1;
const SOCKS_HOSTNAME: u8 = 3;
const USERNAME_PASSWORD_VERSION: u8 = 1;
const ISOLATION_CREDENTIAL_BYTES: usize = 32;
const MAX_SOCKS_HOSTNAME_BYTES: usize = 255;
const MAX_SOCKS_REPLY_DOMAIN_BYTES: usize = 255;
const MAX_TOR_CLIENT_CONTEXTS: usize = 256;
const MAX_CREDENTIAL_DRAWS: usize = 4;
const MAX_TOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Explicit native-client profile carried into one SOCKS connection attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TorClientProfile {
    /// Send the descriptor's DNS endpoint to Tor without resolving it locally.
    TorExit,
    /// Send the descriptor's pinned version-3 onion endpoint to Tor.
    Onion,
}

/// One configured network or network/account isolation context.
///
/// The network-only form covers onboarding before an account exists. Once an
/// account is configured, its typed account form is distinct from every other
/// account on the same network.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct TorIsolationContext {
    network_id: NetworkId,
    account_id: Option<AccountId>,
}

impl TorIsolationContext {
    /// Constructs the pre-account context for one configured network.
    #[must_use]
    pub const fn network(network_id: NetworkId) -> Self {
        Self {
            network_id,
            account_id: None,
        }
    }

    /// Constructs one configured account context on a network.
    #[must_use]
    pub const fn account(network_id: NetworkId, account_id: AccountId) -> Self {
        Self {
            network_id,
            account_id: Some(account_id),
        }
    }
}

/// Closed failure classes for native Tor connection attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TorConnectError {
    /// The context list is empty, duplicated, or above its hard ceiling.
    InvalidContexts,
    /// The requested context is not owned by this connector or names another network.
    InvalidContext,
    /// The selected endpoint is absent from the validated descriptor.
    ProfileUnavailable,
    /// The connect timeout is zero or above thirty seconds.
    InvalidTimeout,
    /// Fresh collision-free isolation credentials could not be obtained.
    EntropyUnavailable,
    /// A small bounded allocation could not be reserved.
    ResourceUnavailable,
    /// The configured local Tor proxy could not be reached or stopped responding.
    ProxyUnavailable,
    /// The complete proxy connection and SOCKS handshake exceeded its deadline.
    Timeout,
    /// The proxy returned malformed or unsupported SOCKS bytes.
    InvalidProxyReply,
    /// The proxy refused username/password stream isolation.
    AuthenticationRefused,
    /// Tor refused the requested destination.
    TargetRefused,
    /// TLS 1.3, certificate identity, the onion pin, or the client ALPN failed.
    TlsRejected,
}

impl fmt::Display for TorConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContexts => "invalid Tor isolation contexts",
            Self::InvalidContext => "unknown Tor isolation context",
            Self::ProfileUnavailable => "selected Tor profile is unavailable",
            Self::InvalidTimeout => "invalid Tor connection timeout",
            Self::EntropyUnavailable => "Tor isolation entropy unavailable",
            Self::ResourceUnavailable => "Tor connection resources unavailable",
            Self::ProxyUnavailable => "Tor proxy unavailable",
            Self::Timeout => "Tor connection timed out",
            Self::InvalidProxyReply => "invalid Tor proxy reply",
            Self::AuthenticationRefused => "Tor stream isolation refused",
            Self::TargetRefused => "Tor destination refused",
            Self::TlsRejected => "Tor TLS authentication failed",
        })
    }
}

impl std::error::Error for TorConnectError {}

struct IsolationCredentials {
    username: Zeroizing<[u8; ISOLATION_CREDENTIAL_BYTES]>,
    password: Zeroizing<[u8; ISOLATION_CREDENTIAL_BYTES]>,
}

impl IsolationCredentials {
    fn draw(entropy: &mut impl EntropySource) -> Result<Self, TorConnectError> {
        let mut username = Zeroizing::new([0_u8; ISOLATION_CREDENTIAL_BYTES]);
        let mut password = Zeroizing::new([0_u8; ISOLATION_CREDENTIAL_BYTES]);
        entropy
            .fill_exact(username.as_mut())
            .map_err(|_| TorConnectError::EntropyUnavailable)?;
        entropy
            .fill_exact(password.as_mut())
            .map_err(|_| TorConnectError::EntropyUnavailable)?;
        Ok(Self { username, password })
    }

    fn matches(&self, other: &Self) -> bool {
        self.username.as_ref() == other.username.as_ref()
            && self.password.as_ref() == other.password.as_ref()
    }
}

struct IsolationEntry {
    context: TorIsolationContext,
    credentials: IsolationCredentials,
}

/// Sole owner of bounded native-client Tor contexts and their opaque SOCKS
/// isolation credentials.
///
/// Construct this once for a client's configured contexts and retain it for
/// reconnects. The owner never exposes credential bytes and has no direct-DNS
/// or direct-destination connection method.
pub struct TorClientOwner {
    proxy: SocksEndpoint,
    connect_timeout: Duration,
    contexts: Vec<IsolationEntry>,
}

/// Validated public roots used by the native Tor client for both DNS-name
/// and onion-name certificate validation.
#[derive(Clone)]
pub struct TorClientTls {
    roots: TrustStore,
}

impl TorClientTls {
    /// Retains one already parsed root set; no platform roots are loaded
    /// implicitly by the connection path.
    #[must_use]
    pub const fn new(roots: TrustStore) -> Self {
        Self { roots }
    }

    fn prepare(&self, target: SelectedTarget<'_>) -> Result<Arc<ClientConfig>, TorConnectError> {
        match target.tls_spki_sha256 {
            Some(pin) => build_pinned_client_config(self.roots.clone(), pin),
            None => build_client_config(self.roots.clone(), Some(CLIENT_ALPN), None),
        }
        .map_err(|_| TorConnectError::TlsRejected)
    }
}

impl TorClientOwner {
    /// Creates a connector for at most 256 unique network/account contexts.
    pub fn new(
        proxy: SocksEndpoint,
        mut contexts: Vec<TorIsolationContext>,
        connect_timeout: Duration,
        entropy: &mut impl EntropySource,
    ) -> Result<Self, TorConnectError> {
        validate_timeout(connect_timeout)?;
        validate_contexts(&mut contexts)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(contexts.len())
            .map_err(|_| TorConnectError::ResourceUnavailable)?;
        for context in contexts {
            let credentials = draw_unique_credentials(&entries, entropy)?;
            entries.push(IsolationEntry {
                context,
                credentials,
            });
        }
        Ok(Self {
            proxy,
            connect_timeout,
            contexts: entries,
        })
    }

    /// Opens exactly one SOCKS5 hostname connection through the configured
    /// local Tor proxy. Any failure ends the attempt without DNS, direct TCP,
    /// alternate-profile, or alternate-endpoint fallback.
    pub async fn connect(
        &self,
        context: TorIsolationContext,
        profile: TorClientProfile,
        descriptor: &OnboardingDescriptor,
        tls: &TorClientTls,
    ) -> Result<TorConnection, TorConnectError> {
        let credentials = self.credentials(context, descriptor.network_id)?;
        let target = SelectedTarget::from_descriptor(profile, descriptor)?;
        let tls_config = tls.prepare(target)?;
        match tokio::time::timeout(
            self.connect_timeout,
            connect_once(&self.proxy, credentials, target, tls_config),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(TorConnectError::Timeout),
        }
    }

    fn credentials(
        &self,
        context: TorIsolationContext,
        network_id: NetworkId,
    ) -> Result<&IsolationCredentials, TorConnectError> {
        if context.network_id != network_id {
            return Err(TorConnectError::InvalidContext);
        }
        self.contexts
            .binary_search_by(|entry| entry.context.cmp(&context))
            .ok()
            .and_then(|index| self.contexts.get(index))
            .map(|entry| &entry.credentials)
            .ok_or(TorConnectError::InvalidContext)
    }
}

fn validate_timeout(timeout: Duration) -> Result<(), TorConnectError> {
    if timeout.is_zero() || timeout > MAX_TOR_CONNECT_TIMEOUT {
        Err(TorConnectError::InvalidTimeout)
    } else {
        Ok(())
    }
}

fn validate_contexts(contexts: &mut [TorIsolationContext]) -> Result<(), TorConnectError> {
    if contexts.is_empty() || contexts.len() > MAX_TOR_CLIENT_CONTEXTS {
        return Err(TorConnectError::InvalidContexts);
    }
    contexts.sort_unstable();
    if contexts
        .iter()
        .zip(contexts.iter().skip(1))
        .any(|(first, second)| first == second)
    {
        return Err(TorConnectError::InvalidContexts);
    }
    Ok(())
}

fn draw_unique_credentials(
    entries: &[IsolationEntry],
    entropy: &mut impl EntropySource,
) -> Result<IsolationCredentials, TorConnectError> {
    for _attempt in 0..MAX_CREDENTIAL_DRAWS {
        let candidate = IsolationCredentials::draw(entropy)?;
        if !entries
            .iter()
            .any(|entry| entry.credentials.matches(&candidate))
        {
            return Ok(candidate);
        }
    }
    Err(TorConnectError::EntropyUnavailable)
}

#[derive(Clone, Copy)]
struct SelectedTarget<'a> {
    profile: TorClientProfile,
    hostname: &'a str,
    port: u16,
    tls_spki_sha256: Option<[u8; 32]>,
}

impl<'a> SelectedTarget<'a> {
    fn from_descriptor(
        profile: TorClientProfile,
        descriptor: &'a OnboardingDescriptor,
    ) -> Result<Self, TorConnectError> {
        match profile {
            TorClientProfile::TorExit => {
                let endpoint = descriptor
                    .dns
                    .as_ref()
                    .ok_or(TorConnectError::ProfileUnavailable)?;
                Ok(Self {
                    profile,
                    hostname: endpoint.name.as_str(),
                    port: endpoint.port,
                    tls_spki_sha256: None,
                })
            }
            TorClientProfile::Onion => {
                let endpoint = descriptor
                    .onion
                    .as_ref()
                    .ok_or(TorConnectError::ProfileUnavailable)?;
                Ok(Self {
                    profile,
                    hostname: endpoint.address.as_str(),
                    port: endpoint.port,
                    tls_spki_sha256: Some(endpoint.tls_spki_sha256),
                })
            }
        }
    }
}

async fn connect_once(
    proxy: &SocksEndpoint,
    credentials: &IsolationCredentials,
    target: SelectedTarget<'_>,
    tls_config: Arc<ClientConfig>,
) -> Result<TorConnection, TorConnectError> {
    let mut stream = connect_proxy(proxy).await?;
    negotiate_isolation(&mut stream, credentials).await?;
    request_hostname(&mut stream, target.hostname, target.port).await?;
    let mut tls_server_name = String::new();
    tls_server_name
        .try_reserve_exact(target.hostname.len())
        .map_err(|_| TorConnectError::ResourceUnavailable)?;
    tls_server_name.push_str(target.hostname);
    let server_name =
        ServerName::try_from(tls_server_name.clone()).map_err(|_| TorConnectError::TlsRejected)?;
    let stream = ClientTlsStream::handshake(stream, tls_config, server_name, CLIENT_ALPN)
        .await
        .map_err(|_| TorConnectError::TlsRejected)?;
    Ok(TorConnection {
        stream,
        profile: target.profile,
        tls_server_name,
        tls_spki_sha256: target.tls_spki_sha256,
    })
}

async fn connect_proxy(proxy: &SocksEndpoint) -> Result<ProxyStream, TorConnectError> {
    match proxy {
        SocksEndpoint::Loopback(address) => TcpStream::connect(*address)
            .await
            .map(ProxyStream::Tcp)
            .map_err(|_| TorConnectError::ProxyUnavailable),
        SocksEndpoint::Unix(path) => UnixStream::connect(path)
            .await
            .map(ProxyStream::Unix)
            .map_err(|_| TorConnectError::ProxyUnavailable),
    }
}

async fn negotiate_isolation(
    stream: &mut ProxyStream,
    credentials: &IsolationCredentials,
) -> Result<(), TorConnectError> {
    write_proxy(stream, &[SOCKS_VERSION, 1, SOCKS_USERNAME_PASSWORD]).await?;
    let mut selection = [0_u8; 2];
    read_proxy(stream, &mut selection).await?;
    let [version, method] = selection;
    if version != SOCKS_VERSION {
        return Err(TorConnectError::InvalidProxyReply);
    }
    if method != SOCKS_USERNAME_PASSWORD {
        return Err(TorConnectError::AuthenticationRefused);
    }

    let mut request = Zeroizing::new(Vec::new());
    request
        .try_reserve_exact(3 + (2 * ISOLATION_CREDENTIAL_BYTES))
        .map_err(|_| TorConnectError::ResourceUnavailable)?;
    request.push(USERNAME_PASSWORD_VERSION);
    request.push(
        u8::try_from(ISOLATION_CREDENTIAL_BYTES).map_err(|_| TorConnectError::InvalidProxyReply)?,
    );
    request.extend_from_slice(credentials.username.as_ref());
    request.push(
        u8::try_from(ISOLATION_CREDENTIAL_BYTES).map_err(|_| TorConnectError::InvalidProxyReply)?,
    );
    request.extend_from_slice(credentials.password.as_ref());
    write_proxy(stream, request.as_ref()).await?;

    let mut reply = [0_u8; 2];
    read_proxy(stream, &mut reply).await?;
    let [version, status] = reply;
    if version != USERNAME_PASSWORD_VERSION {
        return Err(TorConnectError::InvalidProxyReply);
    }
    if status != 0 {
        return Err(TorConnectError::AuthenticationRefused);
    }
    Ok(())
}

async fn request_hostname(
    stream: &mut ProxyStream,
    hostname: &str,
    port: u16,
) -> Result<(), TorConnectError> {
    let hostname_bytes = hostname.as_bytes();
    if hostname_bytes.is_empty()
        || hostname_bytes.len() > MAX_SOCKS_HOSTNAME_BYTES
        || !hostname_bytes.is_ascii()
        || port == 0
    {
        return Err(TorConnectError::InvalidProxyReply);
    }
    let hostname_length =
        u8::try_from(hostname_bytes.len()).map_err(|_| TorConnectError::InvalidProxyReply)?;
    let mut request = Vec::new();
    request
        .try_reserve_exact(7 + hostname_bytes.len())
        .map_err(|_| TorConnectError::ResourceUnavailable)?;
    request.extend_from_slice(&[
        SOCKS_VERSION,
        SOCKS_CONNECT,
        0,
        SOCKS_HOSTNAME,
        hostname_length,
    ]);
    request.extend_from_slice(hostname_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    write_proxy(stream, &request).await?;
    read_connect_reply(stream).await
}

async fn read_connect_reply(stream: &mut ProxyStream) -> Result<(), TorConnectError> {
    let mut header = [0_u8; 4];
    read_proxy(stream, &mut header).await?;
    let [version, reply, reserved, address_type] = header;
    if version != SOCKS_VERSION || reserved != 0 || reply > 8 {
        return Err(TorConnectError::InvalidProxyReply);
    }
    if reply != 0 {
        return Err(TorConnectError::TargetRefused);
    }
    match address_type {
        1 => read_reply_tail::<6>(stream).await,
        4 => read_reply_tail::<18>(stream).await,
        SOCKS_HOSTNAME => read_domain_reply_tail(stream).await,
        _ => Err(TorConnectError::InvalidProxyReply),
    }
}

async fn read_reply_tail<const SIZE: usize>(
    stream: &mut ProxyStream,
) -> Result<(), TorConnectError> {
    let mut tail = [0_u8; SIZE];
    read_proxy(stream, &mut tail).await
}

async fn read_domain_reply_tail(stream: &mut ProxyStream) -> Result<(), TorConnectError> {
    let mut encoded_length = [0_u8; 1];
    read_proxy(stream, &mut encoded_length).await?;
    let [encoded_length] = encoded_length;
    let domain_length = usize::from(encoded_length);
    if domain_length == 0 || domain_length > MAX_SOCKS_REPLY_DOMAIN_BYTES {
        return Err(TorConnectError::InvalidProxyReply);
    }
    let tail_length = domain_length
        .checked_add(2)
        .ok_or(TorConnectError::InvalidProxyReply)?;
    let mut tail = [0_u8; MAX_SOCKS_REPLY_DOMAIN_BYTES + 2];
    let body = tail
        .get_mut(..tail_length)
        .ok_or(TorConnectError::InvalidProxyReply)?;
    read_proxy(stream, body).await
}

async fn write_proxy(stream: &mut ProxyStream, bytes: &[u8]) -> Result<(), TorConnectError> {
    stream
        .write_all(bytes)
        .await
        .map_err(|_| TorConnectError::ProxyUnavailable)
}

async fn read_proxy(stream: &mut ProxyStream, bytes: &mut [u8]) -> Result<(), TorConnectError> {
    stream
        .read_exact(bytes)
        .await
        .map(|_read| ())
        .map_err(|_| TorConnectError::ProxyUnavailable)
}

enum ProxyStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Unix(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(context, bytes),
            Self::Unix(stream) => Pin::new(stream).poll_write(context, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(context),
            Self::Unix(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

/// A proxy-established stream plus the exact TLS identity policy selected
/// from the onboarding descriptor.
pub struct TorConnection {
    stream: ClientTlsStream<ProxyStream>,
    profile: TorClientProfile,
    tls_server_name: String,
    tls_spki_sha256: Option<[u8; 32]>,
}

impl TorConnection {
    /// Returns the profile that established this stream.
    #[must_use]
    pub const fn profile(&self) -> TorClientProfile {
        self.profile
    }

    /// Returns the exact hostname the TLS client must authenticate.
    #[must_use]
    pub fn tls_server_name(&self) -> &str {
        &self.tls_server_name
    }

    /// Returns the mandatory onion SPKI pin, or `None` for Tor-exit WebPKI.
    #[must_use]
    pub const fn tls_spki_sha256(&self) -> Option<&[u8; 32]> {
        self.tls_spki_sha256.as_ref()
    }
}

impl AsyncRead for TorConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for TorConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}
