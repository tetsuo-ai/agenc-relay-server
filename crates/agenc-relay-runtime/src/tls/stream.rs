//! The hand-driven rustls server stream over a Tokio transport (spec 8.1
//! and 8.3, lines 464-526).
//!
//! No pinned crate adapts rustls to Tokio, so this module drives
//! `ServerConnection` itself: `read_tls` and `write_tls` run against small
//! adapters that translate `Poll::Pending` into `WouldBlock`, and
//! `process_new_packets` advances the state machine after every read. The
//! handshake completes under the global handshake semaphore and the 10 s
//! accept-to-TLS deadline; the negotiated ALPN is checked before any
//! application byte is handed to the connection owner (TRN-01, spec line
//! 6844).

use std::error::Error;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::{NamedGroup, ServerConfig, ServerConnection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::config::TLS_PLAINTEXT_BUFFER_LIMIT_BYTES;
use crate::RuntimeError;
use crate::sync::Arc;

/// TCP accepted to TLS complete (spec line 517).
pub const ACCEPT_TO_TLS_DEADLINE: Duration = Duration::from_secs(10);
/// TLS complete to registration complete (spec line 518).
pub const TLS_TO_REGISTRATION_DEADLINE: Duration = Duration::from_secs(30);
/// Graceful write stall before the writer closes (spec line 522).
pub const WRITE_STALL_BUDGET: Duration = Duration::from_secs(30);
/// TLS close-notify grace at shutdown (spec line 523).
pub const CLOSE_NOTIFY_GRACE: Duration = Duration::from_secs(1);
/// Default TLS handshakes in progress (spec line 524).
pub const DEFAULT_HANDSHAKES_IN_PROGRESS: usize = 1_024;
/// Hard maximum TLS handshakes in progress (spec line 524).
pub const MAX_HANDSHAKES_IN_PROGRESS: usize = 16_384;

/// Closed failures of one TLS handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsHandshakeError {
    /// The 10 s accept-to-TLS deadline expired.
    Timeout,
    /// The transport failed while the handshake was in progress.
    Io,
    /// The peer sent a record rustls rejected.
    Protocol,
    /// The peer closed the transport before the handshake completed.
    PeerClosed,
    /// The peer offered no ALPN identifier at all.
    AlpnMissing,
    /// The peer negotiated an identifier other than the listener's.
    AlpnMismatch,
}

impl fmt::Display for TlsHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Timeout => "TLS handshake deadline expired",
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

/// The global handshake semaphore (spec lines 524-526).
///
/// Listeners acquire a permit before accepting, so exhaustion pauses accepts
/// instead of growing tasks or queues; the permit is dropped as soon as the
/// handshake completes or fails.
#[derive(Clone)]
pub struct HandshakeLimiter {
    semaphore: Arc<Semaphore>,
    capacity: usize,
}

impl HandshakeLimiter {
    /// Creates a limiter for `capacity` concurrent handshakes within the
    /// configurable range `1..=16_384`.
    pub fn new(capacity: usize) -> Result<Self, RuntimeError> {
        if capacity == 0 || capacity > MAX_HANDSHAKES_IN_PROGRESS {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            capacity,
        })
    }

    /// Returns the configured capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the handshake slots not currently held.
    #[must_use]
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Waits for one handshake slot; the wait is where accepts pause.
    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, RuntimeError> {
        Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| RuntimeError::Cancelled)
    }

    /// Takes one handshake slot without waiting.
    #[must_use]
    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.semaphore).try_acquire_owned().ok()
    }
}

/// A completed TLS 1.3 session over one Tokio transport.
pub struct TlsStream<S> {
    inner: S,
    connection: ServerConnection,
    close_notify_sent: bool,
}

/// Translates a Tokio read into the blocking `Read` rustls expects.
struct SyncRead<'a, 'b, S> {
    inner: Pin<&'a mut S>,
    cx: &'a mut Context<'b>,
}

impl<S: AsyncRead + Unpin> io::Read for SyncRead<'_, '_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match self.inner.as_mut().poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Translates a Tokio write into the blocking `Write` rustls expects.
struct SyncWrite<'a, 'b, S> {
    inner: Pin<&'a mut S>,
    cx: &'a mut Context<'b>,
}

impl<S: AsyncWrite + Unpin> io::Write for SyncWrite<'_, '_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.as_mut().poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut().poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

fn is_would_block(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    /// Completes the server handshake within `deadline` and enforces the
    /// expected ALPN before returning the stream.
    ///
    /// On an ALPN failure the stream sends close-notify and returns the
    /// error; no application byte was read into the caller's view.
    pub async fn handshake(
        inner: S,
        config: Arc<ServerConfig>,
        expected_alpn: &[u8],
        deadline: Duration,
    ) -> Result<Self, TlsHandshakeError> {
        let mut connection =
            ServerConnection::new(config).map_err(|_| TlsHandshakeError::Protocol)?;
        connection.set_buffer_limit(Some(TLS_PLAINTEXT_BUFFER_LIMIT_BYTES));
        let mut stream = Self {
            inner,
            connection,
            close_notify_sent: false,
        };
        let completed = tokio::time::timeout(deadline, poll_fn(|cx| stream.poll_handshake(cx)))
            .await
            .map_err(|_| TlsHandshakeError::Timeout)?;
        completed?;
        let outcome = match stream.connection.alpn_protocol() {
            Some(negotiated) if negotiated == expected_alpn => return Ok(stream),
            Some(_) => TlsHandshakeError::AlpnMismatch,
            None => TlsHandshakeError::AlpnMissing,
        };
        stream.close_after_rejection().await;
        Err(outcome)
    }

    /// Returns the negotiated ALPN identifier.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.connection.alpn_protocol()
    }

    /// Returns the negotiated key-exchange group.
    #[must_use]
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        self.connection
            .negotiated_key_exchange_group()
            .map(|group| group.name())
    }

    /// Borrows the client certificate chain when mutual TLS was required.
    #[must_use]
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.connection.peer_certificates()
    }

    /// Derives RFC 9846 exporter material for the admin session binding.
    pub fn export_keying_material(
        &self,
        output: &mut [u8; 32],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), RuntimeError> {
        self.connection
            .export_keying_material(output, label, Some(context))
            .map(|_| ())
            .map_err(|_| RuntimeError::InvalidValue)
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TlsHandshakeError>> {
        loop {
            ready!(self.poll_write_tls(cx)).map_err(|_| TlsHandshakeError::Io)?;
            if !self.connection.is_handshaking() {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.poll_read_tls(cx)) {
                Ok(0) => return Poll::Ready(Err(TlsHandshakeError::PeerClosed)),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    // Let the alert reach the peer before reporting rejection.
                    let _ = self.poll_write_tls(cx);
                    return Poll::Ready(Err(TlsHandshakeError::Protocol));
                }
                Err(_) => return Poll::Ready(Err(TlsHandshakeError::Io)),
            }
        }
    }

    async fn close_after_rejection(&mut self) {
        self.connection.send_close_notify();
        self.close_notify_sent = true;
        let _ =
            tokio::time::timeout(CLOSE_NOTIFY_GRACE, poll_fn(|cx| self.poll_write_tls(cx))).await;
    }

    /// Writes every pending TLS record; `Pending` leaves the rest buffered.
    fn poll_write_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.connection.wants_write() {
            let mut writer = SyncWrite {
                inner: Pin::new(&mut self.inner),
                cx,
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

    /// Reads one batch of TLS records and advances the state machine; a
    /// protocol rejection surfaces as `InvalidData`.
    fn poll_read_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = SyncRead {
            inner: Pin::new(&mut self.inner),
            cx,
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Alerts and key updates queued by the last record batch go out
            // opportunistically; a stalled write is retried on the next poll.
            let _ = this.poll_write_tls(cx);
            match io::Read::read(&mut this.connection.reader(), buf.initialize_unfilled()) {
                Ok(read) => {
                    buf.advance(read);
                    return Poll::Ready(Ok(()));
                }
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            match ready!(this.poll_read_tls(cx)) {
                Ok(0) => return Poll::Ready(Ok(())),
                Ok(_) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let accepted = io::Write::write(&mut this.connection.writer(), buf)?;
            if accepted > 0 || buf.is_empty() {
                let _ = this.poll_write_tls(cx);
                return Poll::Ready(Ok(accepted));
            }
            // The plaintext buffer is at its limit: drain records first.
            ready!(this.poll_write_tls(cx))?;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_write_tls(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_notify_sent {
            this.connection.send_close_notify();
            this.close_notify_sent = true;
        }
        ready!(this.poll_write_tls(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_bounds_and_permits_follow_the_spec_table() -> Result<(), RuntimeError> {
        assert_eq!(
            HandshakeLimiter::new(0).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            HandshakeLimiter::new(MAX_HANDSHAKES_IN_PROGRESS + 1).err(),
            Some(RuntimeError::InvalidValue)
        );
        let limiter = HandshakeLimiter::new(1)?;
        assert_eq!(limiter.capacity(), 1);
        assert_eq!(limiter.available(), 1);
        let held = limiter.try_acquire().ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(limiter.available(), 0);
        assert!(limiter.try_acquire().is_none());
        drop(held);
        assert_eq!(limiter.available(), 1);
        assert_eq!(DEFAULT_HANDSHAKES_IN_PROGRESS, 1_024);
        assert_eq!(ACCEPT_TO_TLS_DEADLINE, Duration::from_secs(10));
        assert_eq!(TLS_TO_REGISTRATION_DEADLINE, Duration::from_secs(30));
        assert_eq!(WRITE_STALL_BUDGET, Duration::from_secs(30));
        assert_eq!(CLOSE_NOTIFY_GRACE, Duration::from_secs(1));
        Ok(())
    }

    #[tokio::test]
    async fn acquire_waits_for_a_released_slot() -> Result<(), RuntimeError> {
        let limiter = HandshakeLimiter::new(1)?;
        let held = limiter.try_acquire().ok_or(RuntimeError::InvalidValue)?;
        let waiter = tokio::spawn({
            let limiter = limiter.clone();
            async move { limiter.acquire().await.map(|_| ()) }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(held);
        waiter.await.map_err(|_| RuntimeError::Cancelled)??;
        Ok(())
    }

    #[test]
    fn handshake_errors_render_fixed_ascii_text() {
        for error in [
            TlsHandshakeError::Timeout,
            TlsHandshakeError::Io,
            TlsHandshakeError::Protocol,
            TlsHandshakeError::PeerClosed,
            TlsHandshakeError::AlpnMissing,
            TlsHandshakeError::AlpnMismatch,
        ] {
            assert!(error.to_string().is_ascii());
        }
    }
}
