//! Hand-driven rustls client stream over an existing Tokio transport.

use std::error::Error;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::TLS_PLAINTEXT_BUFFER_LIMIT_BYTES;

/// TLS close-notify grace at shutdown (spec line 523).
pub const CLOSE_NOTIFY_GRACE: Duration = Duration::from_secs(1);

/// Closed failures of a client TLS handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsHandshakeError {
    /// The transport failed while the handshake was in progress.
    Io,
    /// The peer sent a record rustls rejected.
    Protocol,
    /// The peer closed the transport before the handshake completed.
    PeerClosed,
    /// The peer offered no ALPN identifier at all.
    AlpnMissing,
    /// The peer negotiated an identifier other than the expected one.
    AlpnMismatch,
}

impl fmt::Display for TlsHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Io => "TLS handshake transport failed",
            Self::Protocol => "TLS handshake was rejected",
            Self::PeerClosed => "peer closed before the TLS handshake completed",
            Self::AlpnMissing => "peer offered no ALPN identifier",
            Self::AlpnMismatch => "peer negotiated the wrong ALPN identifier",
        };
        formatter.write_str(message)
    }
}

impl Error for TlsHandshakeError {}

/// A TLS-authenticated client stream whose application I/O is unavailable
/// until TLS 1.3 and the exact ALPN complete.
pub struct ClientTlsStream<S> {
    inner: S,
    connection: ClientConnection,
    close_notify_sent: bool,
}

struct SyncRead<'a, 'b, S> {
    inner: Pin<&'a mut S>,
    context: &'a mut Context<'b>,
}

impl<S: AsyncRead + Unpin> io::Read for SyncRead<'_, '_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut buffer = ReadBuf::new(bytes);
        match self.inner.as_mut().poll_read(self.context, &mut buffer) {
            Poll::Ready(Ok(())) => Ok(buffer.filled().len()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

struct SyncWrite<'a, 'b, S> {
    inner: Pin<&'a mut S>,
    context: &'a mut Context<'b>,
}

impl<S: AsyncWrite + Unpin> io::Write for SyncWrite<'_, '_, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.inner.as_mut().poll_write(self.context, bytes) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut().poll_flush(self.context) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

fn is_would_block(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

impl<S: AsyncRead + AsyncWrite + Unpin> ClientTlsStream<S> {
    /// Completes TLS 1.3 and rejects a missing or different negotiated ALPN.
    pub async fn handshake(
        inner: S,
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        expected_alpn: &[u8],
    ) -> Result<Self, TlsHandshakeError> {
        let mut connection =
            ClientConnection::new(config, server_name).map_err(|_| TlsHandshakeError::Protocol)?;
        connection.set_buffer_limit(Some(TLS_PLAINTEXT_BUFFER_LIMIT_BYTES));
        let mut stream = Self {
            inner,
            connection,
            close_notify_sent: false,
        };
        poll_fn(|context| stream.poll_handshake(context)).await?;
        let outcome = match stream.connection.alpn_protocol() {
            Some(negotiated) if negotiated != expected_alpn => TlsHandshakeError::AlpnMismatch,
            None => TlsHandshakeError::AlpnMissing,
            Some(_) if stream.connection.protocol_version() == Some(ProtocolVersion::TLSv1_3) => {
                return Ok(stream);
            }
            Some(_) => TlsHandshakeError::Protocol,
        };
        stream.close_after_rejection().await;
        Err(outcome)
    }

    /// Returns the exact ALPN accepted before the stream was released.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.connection.alpn_protocol()
    }

    /// Derives RFC 9846 exporter material for the federation hello binding.
    pub fn export_keying_material(
        &self,
        output: &mut [u8; 32],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), rustls::Error> {
        self.connection
            .export_keying_material(output, label, Some(context))
            .map(|_| ())
    }

    fn poll_handshake(&mut self, context: &mut Context<'_>) -> Poll<Result<(), TlsHandshakeError>> {
        loop {
            ready!(self.poll_write_tls(context)).map_err(|_| TlsHandshakeError::Io)?;
            if !self.connection.is_handshaking() {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.poll_read_tls(context)) {
                Ok(0) => return Poll::Ready(Err(TlsHandshakeError::PeerClosed)),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    let _ = self.poll_write_tls(context);
                    return Poll::Ready(Err(TlsHandshakeError::Protocol));
                }
                Err(_) => return Poll::Ready(Err(TlsHandshakeError::Io)),
            }
        }
    }

    async fn close_after_rejection(&mut self) {
        self.connection.send_close_notify();
        self.close_notify_sent = true;
        let _ = tokio::time::timeout(
            CLOSE_NOTIFY_GRACE,
            poll_fn(|context| self.poll_write_tls(context)),
        )
        .await;
    }

    fn poll_write_tls(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.connection.wants_write() {
            let mut writer = SyncWrite {
                inner: Pin::new(&mut self.inner),
                context,
            };
            match self.connection.write_tls(&mut writer) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(_) => {}
                Err(error) if is_would_block(&error) => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_read_tls(&mut self, context: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = SyncRead {
            inner: Pin::new(&mut self.inner),
            context,
        };
        let read = match self.connection.read_tls(&mut reader) {
            Ok(read) => read,
            Err(error) if is_would_block(&error) => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if let Err(error) = self.connection.process_new_packets() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        Poll::Ready(Ok(read))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let _ = this.poll_write_tls(context);
            match io::Read::read(&mut this.connection.reader(), buffer.initialize_unfilled()) {
                Ok(read) => {
                    buffer.advance(read);
                    return Poll::Ready(Ok(()));
                }
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            match ready!(this.poll_read_tls(context)) {
                Ok(0) => return Poll::Ready(Ok(())),
                Ok(_) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClientTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let accepted = io::Write::write(&mut this.connection.writer(), bytes)?;
            if accepted > 0 || bytes.is_empty() {
                let _ = this.poll_write_tls(context);
                return Poll::Ready(Ok(accepted));
            }
            ready!(this.poll_write_tls(context))?;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_write_tls(context))?;
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_notify_sent {
            this.connection.send_close_notify();
            this.close_notify_sent = true;
        }
        ready!(this.poll_write_tls(context))?;
        Pin::new(&mut this.inner).poll_shutdown(context)
    }
}
