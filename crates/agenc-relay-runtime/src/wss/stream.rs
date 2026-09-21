use std::future::Future as _;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use agenc_relay_client_wire::websocket_transport::{
    ClientFrameHeader, FrameHeaderError, client_header_bytes, decode_client_header,
    server_frame_header,
};
use agenc_relay_client_wire::{
    MAX_WEBSOCKET_MESSAGE_BYTES, WebSocketEvent, WebSocketMessage, WebSocketOpcode,
    WebSocketSubprotocol, WebSocketWire,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroize as _;

use crate::RuntimeError;
use crate::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort as _, MemoryCharge, MemoryPermitBatch,
};
use crate::tls::WRITE_STALL_BUDGET;

const RAW_FRAME_BYTES: usize = MAX_WEBSOCKET_MESSAGE_BYTES + 14;
const OUTPUT_FRAME_BYTES: usize = MAX_WEBSOCKET_MESSAGE_BYTES + 4;

/// Converts one validated message to the existing CRLF reader contract and
/// one rendered IRC line to one unmasked WebSocket message. All writes,
/// including controls produced by reads, use one ordered socket writer.
pub(crate) struct WssStream<T> {
    inner: T,
    wire: WebSocketWire,
    opcode: WebSocketOpcode,
    raw: Vec<u8>,
    filled: usize,
    header: Option<ClientFrameHeader>,
    message: Option<WebSocketMessage>,
    message_offset: usize,
    output: Vec<u8>,
    output_len: usize,
    output_offset: usize,
    control: [u8; 127],
    control_len: usize,
    control_offset: usize,
    control_timer: Pin<Box<Sleep>>,
    closing: bool,
    // Last field: permits outlive the buffers and timer they cover.
    _permits: MemoryPermitBatch,
}

impl<T> WssStream<T> {
    pub(crate) fn new(
        inner: T,
        protocol: WebSocketSubprotocol,
        budget: &MemoryBudget,
    ) -> Result<Self, RuntimeError> {
        // Include both the reassembler's replacement and the emitted message,
        // as well as close parsing's temporary payload and reason allocations.
        let charges = [
            MemoryCharge::allocation(RAW_FRAME_BYTES as u64)?,
            MemoryCharge::allocation(OUTPUT_FRAME_BYTES as u64)?,
            MemoryCharge::allocation(MAX_WEBSOCKET_MESSAGE_BYTES as u64)?,
            MemoryCharge::allocation(MAX_WEBSOCKET_MESSAGE_BYTES as u64)?,
            MemoryCharge::allocation(125)?,
            MemoryCharge::allocation(123)?,
            MemoryCharge::allocation(std::mem::size_of::<Sleep>() as u64)?,
        ];
        let permits = budget.try_acquire_batch(BoundedMemoryCharges::new(&charges)?)?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(RAW_FRAME_BYTES)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        raw.resize(RAW_FRAME_BYTES, 0);
        let mut output = Vec::new();
        output
            .try_reserve_exact(OUTPUT_FRAME_BYTES)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        output.resize(OUTPUT_FRAME_BYTES, 0);
        Ok(Self {
            inner,
            wire: WebSocketWire::new(protocol).map_err(|_| RuntimeError::MemoryExhausted)?,
            opcode: match protocol {
                WebSocketSubprotocol::TextIrcv3 => WebSocketOpcode::Text,
                WebSocketSubprotocol::BinaryIrcv3 => WebSocketOpcode::Binary,
            },
            raw,
            filled: 0,
            header: None,
            message: None,
            message_offset: 0,
            output,
            output_len: 0,
            output_offset: 0,
            control: [0; 127],
            control_len: 0,
            control_offset: 0,
            control_timer: Box::pin(tokio::time::sleep(WRITE_STALL_BUDGET)),
            closing: false,
            _permits: permits,
        })
    }

    fn control(&mut self, opcode: WebSocketOpcode, payload: &[u8]) -> io::Result<()> {
        let (header, count) = server_frame_header(opcode, payload.len()).map_err(|_| invalid())?;
        let end = count.checked_add(payload.len()).ok_or_else(invalid)?;
        self.control
            .get_mut(..count)
            .ok_or_else(invalid)?
            .copy_from_slice(header.get(..count).ok_or_else(invalid)?);
        self.control
            .get_mut(count..end)
            .ok_or_else(invalid)?
            .copy_from_slice(payload);
        self.control_len = end;
        self.control_offset = 0;
        self.control_timer
            .as_mut()
            .reset(Instant::now() + WRITE_STALL_BUDGET);
        Ok(())
    }

    fn close(&mut self, code: u16) -> io::Result<()> {
        self.message = None;
        self.closing = true;
        self.control(WebSocketOpcode::Close, &code.to_be_bytes())
    }

    fn event(&mut self, event: WebSocketEvent) -> io::Result<()> {
        match event {
            WebSocketEvent::Message(message) => {
                self.message = Some(message);
                self.message_offset = 0;
            }
            WebSocketEvent::Ping(mut payload) => {
                let result = self.control(WebSocketOpcode::Pong, &payload);
                payload.zeroize();
                result?;
            }
            WebSocketEvent::Pong(mut payload) => payload.zeroize(),
            WebSocketEvent::Close { code, mut reason } => {
                let mut payload = [0_u8; 125];
                let len = if let Some(code) = code {
                    payload[..2].copy_from_slice(&code.to_be_bytes());
                    let end = 2 + reason.len();
                    payload
                        .get_mut(2..end)
                        .ok_or_else(invalid)?
                        .copy_from_slice(reason.as_bytes());
                    end
                } else {
                    0
                };
                reason.zeroize();
                self.closing = true;
                self.control(
                    WebSocketOpcode::Close,
                    payload.get(..len).ok_or_else(invalid)?,
                )?;
                payload.zeroize();
            }
        }
        Ok(())
    }

    fn emit(&mut self, destination: &mut ReadBuf<'_>) -> io::Result<bool> {
        let Some(message) = self.message.as_ref() else {
            return Ok(false);
        };
        let bytes = message.as_str().as_bytes();
        if self.message_offset < bytes.len() {
            let count = destination
                .remaining()
                .min(bytes.len() - self.message_offset);
            destination.put_slice(
                bytes
                    .get(self.message_offset..self.message_offset + count)
                    .ok_or_else(invalid)?,
            );
            self.message_offset += count;
        }
        while destination.remaining() > 0 && self.message_offset < bytes.len() + 2 {
            let byte = if self.message_offset == bytes.len() {
                b'\r'
            } else {
                b'\n'
            };
            destination.put_slice(&[byte]);
            self.message_offset += 1;
        }
        if self.message_offset == bytes.len() + 2 {
            self.message = None;
            self.message_offset = 0;
        }
        Ok(true)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> WssStream<T> {
    pub(super) async fn write_upgrade(&mut self, response: &[u8]) -> io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        self.inner.write_all(response).await?;
        self.inner.flush().await
    }

    fn receive_bytes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let target = self.header.map_or_else(
            || client_header_bytes(self.raw.get(..self.filled).unwrap_or_default()),
            |header| header.header_bytes() + header.payload_bytes(),
        );
        if self.filled < target {
            let mut received =
                ReadBuf::new(self.raw.get_mut(self.filled..target).ok_or_else(invalid)?);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut received))?;
            let count = received.filled().len();
            if count == 0 {
                return Poll::Ready(Ok(false));
            }
            self.filled += count;
        }
        Poll::Ready(Ok(true))
    }

    fn decode_header(&mut self) -> io::Result<()> {
        if self.header.is_some() {
            return Ok(());
        }

        match decode_client_header(self.raw.get(..self.filled).ok_or_else(invalid)?) {
            Ok(header) => self.header = header,
            Err(error) => {
                self.close(match error {
                    FrameHeaderError::Protocol => 1002,
                    FrameHeaderError::TooLarge => 1009,
                })?;
                return Ok(());
            }
        }
        Ok(())
    }

    fn decode_frame(&mut self) -> io::Result<()> {
        self.decode_header()?;
        let Some(header) = self.header else {
            return Ok(());
        };
        let end = header.header_bytes() + header.payload_bytes();
        if self.filled < end {
            return Ok(());
        }
        let frame = header
            .frame(
                self.raw
                    .get(header.header_bytes()..end)
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
        let event = self.wire.accept(frame);
        self.raw.get_mut(..end).ok_or_else(invalid)?.zeroize();
        self.filled = 0;
        self.header = None;
        match event {
            Ok(Some(event)) => self.event(event)?,
            Ok(None) => {}
            Err(error) => self.close(error.code())?,
        }
        Ok(())
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control_len > 0 && self.control_timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        while self.output_offset < self.output_len {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(
                    cx,
                    self.output
                        .get(self.output_offset..self.output_len)
                        .ok_or_else(invalid)?
                )
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.output_offset += written;
        }
        self.output_len = 0;
        self.output_offset = 0;
        while self.control_offset < self.control_len {
            if self.control_timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(
                    cx,
                    self.control
                        .get(self.control_offset..self.control_len)
                        .ok_or_else(invalid)?
                )
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.control_offset += written;
        }
        if self.control_len > 0 {
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.control.zeroize();
            self.control_len = 0;
            self.control_offset = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for WssStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if destination.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..64 {
            if this.control_len > 0 {
                ready!(this.drain(cx))?;
            }
            if this.closing {
                return Poll::Ready(Ok(()));
            }
            if this.emit(destination)? {
                return Poll::Ready(Ok(()));
            }
            if !ready!(this.receive_bytes(cx))? {
                return Poll::Ready(Ok(()));
            }
            this.decode_frame()?;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WssStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if this.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(payload) = bytes.strip_suffix(b"\r\n") else {
            return Poll::Ready(Err(invalid()));
        };
        let (header, count) =
            server_frame_header(this.opcode, payload.len()).map_err(|_| invalid())?;
        let end = count + payload.len();
        this.output
            .get_mut(..count)
            .ok_or_else(invalid)?
            .copy_from_slice(header.get(..count).ok_or_else(invalid)?);
        this.output
            .get_mut(count..end)
            .ok_or_else(invalid)?
            .copy_from_slice(payload);
        this.output_len = end;
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closing {
            this.close(1000)?;
        }
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<T> Drop for WssStream<T> {
    fn drop(&mut self) {
        self.raw.zeroize();
        self.output.zeroize();
        self.control.zeroize();
    }
}

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

#[cfg(test)]
mod tests;
