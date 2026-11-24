//! Runtime adapter for the shared client TLS stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::stream::TlsHandshakeError;
use crate::RuntimeError;
use crate::sync::Arc;

/// A TLS-authenticated client stream whose application I/O is unavailable
/// until TLS 1.3 and the exact ALPN complete.
pub struct ClientTlsStream<S>(agenc_relay_transport::ClientTlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> ClientTlsStream<S> {
    /// Completes TLS 1.3 and rejects a missing or different negotiated ALPN.
    pub async fn handshake(
        inner: S,
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        expected_alpn: &[u8],
    ) -> Result<Self, TlsHandshakeError> {
        agenc_relay_transport::ClientTlsStream::handshake(inner, config, server_name, expected_alpn)
            .await
            .map(Self)
            .map_err(TlsHandshakeError::from)
    }

    /// Returns the exact ALPN accepted before the stream was released.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.0.alpn()
    }

    /// Derives RFC 9846 exporter material for the federation hello binding.
    pub fn export_keying_material(
        &self,
        output: &mut [u8; 32],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), RuntimeError> {
        self.0
            .export_keying_material(output, label, context)
            .map_err(|_| RuntimeError::InvalidValue)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(context, buffer)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClientTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(context)
    }
}
