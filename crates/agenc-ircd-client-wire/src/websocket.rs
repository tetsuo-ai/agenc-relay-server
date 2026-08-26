//! Socket-independent RFC 6455 semantics for IRC-over-WebSocket messages.

use std::error::Error;
use std::fmt;

use zeroize::Zeroize as _;

use crate::{FramedLine, FramingError, MAX_WEBSOCKET_MESSAGE_BYTES};

/// Negotiated IRCv3 WebSocket subprotocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketSubprotocol {
    /// UTF-8 IRC carried in text messages.
    TextIrcv3,
    /// UTF-8 IRC carried in binary messages.
    BinaryIrcv3,
}

/// RFC 6455 frame opcode supplied by the network adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketOpcode {
    /// Continuation of an active data message.
    Continuation,
    /// Text data.
    Text,
    /// Binary data.
    Binary,
    /// Connection close.
    Close,
    /// Ping control frame.
    Ping,
    /// Pong control frame.
    Pong,
    /// Any reserved or unknown opcode.
    Reserved(u8),
}

/// One client frame after header decoding but before mask removal.
pub struct ClientWebSocketFrame<'a> {
    /// Whether this is the final fragment.
    pub fin: bool,
    /// Whether any RSV bit was set.
    pub reserved_bits: bool,
    /// Decoded frame opcode.
    pub opcode: WebSocketOpcode,
    /// Required client masking key; absence is a protocol error.
    pub mask: Option<[u8; 4]>,
    /// Still-masked payload bytes.
    pub payload: &'a [u8],
}

/// A complete bounded WebSocket event for the caller.
#[derive(Eq, PartialEq)]
pub enum WebSocketEvent {
    /// One complete UTF-8 IRC protocol line without CR or LF.
    Message(WebSocketMessage),
    /// Ping payload to reflect in a Pong.
    Ping(Vec<u8>),
    /// A received Pong payload.
    Pong(Vec<u8>),
    /// Peer-initiated close with an optional code and UTF-8 reason.
    Close {
        /// Present close status code.
        code: Option<u16>,
        /// Validated close reason.
        reason: String,
    },
}

impl fmt::Debug for WebSocketEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Message(_) => "Message",
            Self::Ping(_) => "Ping",
            Self::Pong(_) => "Pong",
            Self::Close { .. } => "Close",
        };
        formatter
            .debug_tuple("WebSocketEvent")
            .field(&name)
            .finish()
    }
}

/// A complete WebSocket IRC message that clears its storage on drop.
#[derive(Eq, PartialEq)]
pub struct WebSocketMessage(String);

impl WebSocketMessage {
    /// Borrows the validated IRC message without a CRLF delimiter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WebSocketMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebSocketMessage([REDACTED])")
    }
}

impl Drop for WebSocketMessage {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// WebSocket close decision produced by semantic validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebSocketClose {
    code: u16,
    reason: &'static str,
}

impl WebSocketClose {
    /// Returns the RFC 6455 close status code.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.code
    }

    /// Returns a fixed public close reason that contains no client bytes.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.reason
    }

    const fn protocol() -> Self {
        Self {
            code: 1002,
            reason: "WebSocket protocol error",
        }
    }

    const fn invalid_utf8() -> Self {
        Self {
            code: 1007,
            reason: "WebSocket payload is not valid UTF-8",
        }
    }

    const fn too_large() -> Self {
        Self {
            code: 1009,
            reason: "WebSocket message is too large",
        }
    }

    const fn internal() -> Self {
        Self {
            code: 1011,
            reason: "WebSocket processing failed",
        }
    }
}

impl fmt::Display for WebSocketClose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} (close {})", self.reason, self.code)
    }
}

impl Error for WebSocketClose {}

/// Bounded data-message reassembler and control-frame validator.
pub struct WebSocketWire {
    subprotocol: WebSocketSubprotocol,
    fragmented_opcode: Option<WebSocketOpcode>,
    message: Vec<u8>,
    closed: bool,
}

impl WebSocketWire {
    /// Creates an adapter for an already negotiated exact subprotocol.
    pub fn new(subprotocol: WebSocketSubprotocol) -> Result<Self, WebSocketClose> {
        let mut message = Vec::new();
        message
            .try_reserve_exact(MAX_WEBSOCKET_MESSAGE_BYTES)
            .map_err(|_| WebSocketClose::internal())?;
        Ok(Self {
            subprotocol,
            fragmented_opcode: None,
            message,
            closed: false,
        })
    }

    /// Accepts one client frame and emits at most one complete event.
    pub fn accept(
        &mut self,
        frame: ClientWebSocketFrame<'_>,
    ) -> Result<Option<WebSocketEvent>, WebSocketClose> {
        if self.closed {
            return Err(WebSocketClose::protocol());
        }
        if frame.reserved_bits || frame.mask.is_none() {
            return self.fail(WebSocketClose::protocol());
        }
        let mask = frame.mask.ok_or_else(WebSocketClose::protocol)?;
        if is_control(frame.opcode) {
            return self.accept_control(frame, mask).map(Some);
        }
        self.accept_data(frame, mask)
    }

    fn accept_data(
        &mut self,
        frame: ClientWebSocketFrame<'_>,
        mask: [u8; 4],
    ) -> Result<Option<WebSocketEvent>, WebSocketClose> {
        match frame.opcode {
            WebSocketOpcode::Continuation => self.continue_message(frame.fin, frame.payload, mask),
            WebSocketOpcode::Text | WebSocketOpcode::Binary => {
                if self.fragmented_opcode.is_some() || !self.matches_subprotocol(frame.opcode) {
                    return self.fail(WebSocketClose::protocol());
                }
                if frame.fin {
                    let payload =
                        match unmask_bounded(frame.payload, mask, MAX_WEBSOCKET_MESSAGE_BYTES) {
                            Ok(payload) => payload,
                            Err(error) => return self.fail(error),
                        };
                    return match validate_message(payload) {
                        Ok(message) => Ok(Some(WebSocketEvent::Message(message))),
                        Err(error) => self.fail(error),
                    };
                }
                self.fragmented_opcode = Some(frame.opcode);
                self.append_fragment(frame.payload, mask)?;
                Ok(None)
            }
            WebSocketOpcode::Close
            | WebSocketOpcode::Ping
            | WebSocketOpcode::Pong
            | WebSocketOpcode::Reserved(_) => self.fail(WebSocketClose::protocol()),
        }
    }

    fn continue_message(
        &mut self,
        final_fragment: bool,
        payload: &[u8],
        mask: [u8; 4],
    ) -> Result<Option<WebSocketEvent>, WebSocketClose> {
        if self.fragmented_opcode.is_none() {
            return self.fail(WebSocketClose::protocol());
        }
        self.append_fragment(payload, mask)?;
        if !final_fragment {
            return Ok(None);
        }
        let mut replacement = Vec::new();
        if replacement
            .try_reserve_exact(MAX_WEBSOCKET_MESSAGE_BYTES)
            .is_err()
        {
            return self.fail(WebSocketClose::internal());
        }
        let payload = std::mem::replace(&mut self.message, replacement);
        self.fragmented_opcode = None;
        match validate_message(payload) {
            Ok(message) => Ok(Some(WebSocketEvent::Message(message))),
            Err(error) => self.fail(error),
        }
    }

    fn append_fragment(&mut self, payload: &[u8], mask: [u8; 4]) -> Result<(), WebSocketClose> {
        let combined = self
            .message
            .len()
            .checked_add(payload.len())
            .ok_or_else(WebSocketClose::too_large)?;
        if combined > MAX_WEBSOCKET_MESSAGE_BYTES {
            return self.fail(WebSocketClose::too_large());
        }
        for (position, byte) in payload.iter().enumerate() {
            let mask_byte = mask
                .get(position % mask.len())
                .copied()
                .ok_or_else(WebSocketClose::protocol)?;
            self.message.push(*byte ^ mask_byte);
        }
        Ok(())
    }

    fn accept_control(
        &mut self,
        frame: ClientWebSocketFrame<'_>,
        mask: [u8; 4],
    ) -> Result<WebSocketEvent, WebSocketClose> {
        if !frame.fin || frame.payload.len() > 125 {
            return self.fail(WebSocketClose::protocol());
        }
        let payload = match unmask_bounded(frame.payload, mask, 125) {
            Ok(payload) => payload,
            Err(error) => return self.fail(error),
        };
        match frame.opcode {
            WebSocketOpcode::Ping => Ok(WebSocketEvent::Ping(payload)),
            WebSocketOpcode::Pong => Ok(WebSocketEvent::Pong(payload)),
            WebSocketOpcode::Close => match parse_close(payload) {
                Ok(event) => {
                    self.clear_message();
                    self.closed = true;
                    Ok(event)
                }
                Err(error) => self.fail(error),
            },
            WebSocketOpcode::Continuation
            | WebSocketOpcode::Text
            | WebSocketOpcode::Binary
            | WebSocketOpcode::Reserved(_) => self.fail(WebSocketClose::protocol()),
        }
    }

    fn matches_subprotocol(&self, opcode: WebSocketOpcode) -> bool {
        matches!(
            (self.subprotocol, opcode),
            (WebSocketSubprotocol::TextIrcv3, WebSocketOpcode::Text)
                | (WebSocketSubprotocol::BinaryIrcv3, WebSocketOpcode::Binary)
        )
    }

    fn fail<T>(&mut self, error: WebSocketClose) -> Result<T, WebSocketClose> {
        self.clear_message();
        self.closed = true;
        Err(error)
    }

    fn clear_message(&mut self) {
        self.message.fill(0);
        self.message.clear();
        self.fragmented_opcode = None;
    }
}

impl Drop for WebSocketWire {
    fn drop(&mut self) {
        self.clear_message();
    }
}

fn is_control(opcode: WebSocketOpcode) -> bool {
    matches!(
        opcode,
        WebSocketOpcode::Close | WebSocketOpcode::Ping | WebSocketOpcode::Pong
    )
}

fn unmask_bounded(
    payload: &[u8],
    mask: [u8; 4],
    maximum: usize,
) -> Result<Vec<u8>, WebSocketClose> {
    if payload.len() > maximum {
        return Err(WebSocketClose::too_large());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(payload.len())
        .map_err(|_| WebSocketClose::internal())?;
    for (position, byte) in payload.iter().enumerate() {
        let mask_byte = mask
            .get(position % mask.len())
            .copied()
            .ok_or_else(WebSocketClose::protocol)?;
        output.push(*byte ^ mask_byte);
    }
    Ok(output)
}

fn validate_message(payload: Vec<u8>) -> Result<WebSocketMessage, WebSocketClose> {
    let mut message = match String::from_utf8(payload) {
        Ok(message) => message,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err(WebSocketClose::invalid_utf8());
        }
    };
    if let Err(error) = FramedLine::new(&message) {
        message.zeroize();
        return Err(map_framing_error(error));
    }
    Ok(WebSocketMessage(message))
}

const fn map_framing_error(error: FramingError) -> WebSocketClose {
    match error {
        FramingError::LineTooLong | FramingError::ClientTagsTooLong => WebSocketClose::too_large(),
        FramingError::BareLineFeed
        | FramingError::BareCarriageReturn
        | FramingError::EmbeddedNul
        | FramingError::InvalidUtf8
        | FramingError::UnexpectedEof
        | FramingError::TimedOut => WebSocketClose::protocol(),
        FramingError::AllocationFailed => WebSocketClose::internal(),
    }
}

fn parse_close(mut payload: Vec<u8>) -> Result<WebSocketEvent, WebSocketClose> {
    if payload.is_empty() {
        return Ok(WebSocketEvent::Close {
            code: None,
            reason: String::new(),
        });
    }
    if payload.len() == 1 {
        payload.zeroize();
        return Err(WebSocketClose::protocol());
    }
    let high = payload
        .first()
        .copied()
        .ok_or_else(WebSocketClose::protocol)?;
    let low = payload
        .get(1)
        .copied()
        .ok_or_else(WebSocketClose::protocol)?;
    let code = u16::from_be_bytes([high, low]);
    if !valid_close_code(code) {
        payload.zeroize();
        return Err(WebSocketClose::protocol());
    }
    let reason_bytes = payload.get(2..).ok_or_else(WebSocketClose::protocol)?;
    let Ok(reason_text) = std::str::from_utf8(reason_bytes) else {
        payload.zeroize();
        return Err(WebSocketClose::invalid_utf8());
    };
    let mut reason = String::new();
    if reason.try_reserve_exact(reason_text.len()).is_err() {
        payload.zeroize();
        return Err(WebSocketClose::internal());
    }
    reason.push_str(reason_text);
    payload.zeroize();
    Ok(WebSocketEvent::Close {
        code: Some(code),
        reason,
    })
}

const fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}
