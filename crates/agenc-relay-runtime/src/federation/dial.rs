//! Edge-side dialing of the coordinator over a literal TCP endpoint or a Tor
//! onion service, and the full-jitter reconnect delay (spec 20.2, 20.10).

use std::error::Error;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use agenc_relay_config::{PeerEndpoint, SocksEndpoint};
use agenc_relay_types::EntropySource;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::federation::PeerIdentity;
use crate::tls::FEDERATION_ALPN;
use crate::tls::client_stream::ClientTlsStream;
use crate::tls::stream::TlsHandshakeError;
use crate::tor_client::{ProxyStream, TorConnectError, connect_federation_hostname};

/// The smallest reconnect delay.
pub const RECONNECT_MIN: Duration = Duration::from_secs(1);
/// The fixed largest reconnect delay.
pub const RECONNECT_MAX: Duration = Duration::from_secs(60);

/// Why a dial attempt failed; every value is safe to log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialError {
    /// The TCP connect failed.
    Connect,
    /// The connect deadline expired.
    Timeout,
    /// The TLS handshake or peer identity check failed.
    Tls(TlsHandshakeError),
    /// The Tor proxy path failed.
    Tor(TorConnectError),
    /// The configured name could not be used as a TLS server name.
    ServerName,
}

impl fmt::Display for DialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => formatter.write_str("federation connect failed"),
            Self::Timeout => formatter.write_str("federation connect timed out"),
            Self::Tls(error) => error.fmt(formatter),
            Self::Tor(error) => error.fmt(formatter),
            Self::ServerName => formatter.write_str("federation peer name is not a TLS name"),
        }
    }
}

impl Error for DialError {}

/// An established, authenticated client transport to the coordinator.
pub enum DialedStream {
    /// A direct TCP transport.
    Tcp(ClientTlsStream<TcpStream>),
    /// A transport through the local Tor proxy.
    Onion(ClientTlsStream<ProxyStream>),
}

impl DialedStream {
    /// Derives the federation exporter for this connection.
    pub fn exporter(&self, label: &[u8], context: &[u8]) -> Result<[u8; 32], TlsHandshakeError> {
        let mut output = [0_u8; 32];
        match self {
            Self::Tcp(stream) => stream.export_keying_material(&mut output, label, context),
            Self::Onion(stream) => stream.export_keying_material(&mut output, label, context),
        }
        .map_err(|_| TlsHandshakeError::Protocol)?;
        Ok(output)
    }
}

impl AsyncRead for DialedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Onion(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for DialedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(context, bytes),
            Self::Onion(stream) => Pin::new(stream).poll_write(context, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(context),
            Self::Onion(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Onion(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

/// Everything one dial attempt needs.
pub struct DialPlan<'a> {
    /// The configured endpoint.
    pub endpoint: &'a PeerEndpoint,
    /// The coordinator's expectation.
    pub peer: &'a PeerIdentity,
    /// The federation client configuration bound to that peer.
    pub tls: Arc<ClientConfig>,
    /// The configured connect timeout.
    pub connect_timeout: Duration,
    /// The local Tor proxy, required for an onion endpoint.
    pub tor_proxy: Option<&'a SocksEndpoint>,
}

/// Connects and completes TLS to one endpoint, never falling back between
/// endpoint kinds and never resolving a name.
pub async fn dial<E: EntropySource>(
    plan: DialPlan<'_>,
    entropy: &mut E,
) -> Result<DialedStream, DialError> {
    let server_name = ServerName::try_from(plan.peer.server_name().to_owned())
        .map_err(|_| DialError::ServerName)?;
    match plan.endpoint {
        PeerEndpoint::Tcp(address) => {
            let stream = tokio::time::timeout(plan.connect_timeout, TcpStream::connect(*address))
                .await
                .map_err(|_| DialError::Timeout)?
                .map_err(|_| DialError::Connect)?;
            let tls = tokio::time::timeout(
                plan.connect_timeout,
                ClientTlsStream::handshake(stream, plan.tls, server_name, FEDERATION_ALPN),
            )
            .await
            .map_err(|_| DialError::Timeout)?
            .map_err(DialError::Tls)?;
            Ok(DialedStream::Tcp(tls))
        }
        PeerEndpoint::Onion { address, port } => {
            let proxy = plan
                .tor_proxy
                .ok_or(DialError::Tor(TorConnectError::ResourceUnavailable))?;
            let hostname = format!("{}.onion", address.as_str());
            let stream = tokio::time::timeout(
                plan.connect_timeout,
                connect_federation_hostname(proxy, entropy, &hostname, *port),
            )
            .await
            .map_err(|_| DialError::Timeout)?
            .map_err(DialError::Tor)?;
            let tls = tokio::time::timeout(
                plan.connect_timeout,
                ClientTlsStream::handshake(stream, plan.tls, server_name, FEDERATION_ALPN),
            )
            .await
            .map_err(|_| DialError::Timeout)?
            .map_err(DialError::Tls)?;
            Ok(DialedStream::Onion(tls))
        }
    }
}

/// Draws one full-jitter reconnect delay in `[1 s, cap]` where the cap
/// doubles per attempt up to the fixed maximum.
pub fn reconnect_delay(attempt: u32, entropy: &mut dyn EntropySource) -> Duration {
    let cap_secs = RECONNECT_MIN
        .as_secs()
        .saturating_mul(1_u64 << attempt.min(6))
        .min(RECONNECT_MAX.as_secs());
    let span = cap_secs.saturating_sub(RECONNECT_MIN.as_secs());
    let mut raw = [0_u8; 8];
    let jitter = if span == 0 || entropy.fill_exact(&mut raw).is_err() {
        0
    } else {
        u64::from_be_bytes(raw) % span.saturating_add(1)
    };
    Duration::from_secs(RECONNECT_MIN.as_secs().saturating_add(jitter))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedEntropy(u8);

    impl EntropySource for FixedEntropy {
        fn fill_exact(
            &mut self,
            destination: &mut [u8],
        ) -> Result<(), agenc_relay_types::EntropyError> {
            destination.fill(self.0);
            Ok(())
        }
    }

    struct FailingEntropy;

    impl EntropySource for FailingEntropy {
        fn fill_exact(&mut self, _: &mut [u8]) -> Result<(), agenc_relay_types::EntropyError> {
            Err(agenc_relay_types::EntropyError::Unavailable)
        }
    }

    #[test]
    fn reconnect_delays_stay_within_the_jitter_window() {
        for attempt in 0..10 {
            for fill in [0_u8, 1, 0x7f, 0xff] {
                let delay = reconnect_delay(attempt, &mut FixedEntropy(fill));
                assert!(delay >= RECONNECT_MIN);
                assert!(delay <= RECONNECT_MAX);
            }
        }
        assert_eq!(reconnect_delay(0, &mut FixedEntropy(0xff)), RECONNECT_MIN);
        assert_eq!(reconnect_delay(9, &mut FailingEntropy), RECONNECT_MIN);
        assert!(reconnect_delay(9, &mut FixedEntropy(0xff)) > RECONNECT_MIN);
        assert!(!DialError::Timeout.to_string().is_empty());
        assert!(!DialError::Connect.to_string().is_empty());
        assert!(!DialError::ServerName.to_string().is_empty());
    }
}
