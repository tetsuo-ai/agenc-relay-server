use crate::{ClientWebSocketFrame, MAX_WEBSOCKET_MESSAGE_BYTES, WebSocketOpcode};

/// Closed failures while decoding a client frame header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameHeaderError {
    /// Malformed length, mask, opcode, control frame, or reserved bits.
    Protocol,
    /// The announced data frame exceeds the complete-message limit.
    TooLarge,
}

/// Validated fixed header. The caller reads exactly `payload_bytes` next.
#[derive(Clone, Copy, Debug)]
pub struct ClientFrameHeader {
    fin: bool,
    opcode: WebSocketOpcode,
    mask: [u8; 4],
    payload_bytes: usize,
    header_bytes: usize,
}

impl ClientFrameHeader {
    /// Encoded header size including the mask.
    #[must_use]
    pub const fn header_bytes(self) -> usize {
        self.header_bytes
    }
    /// Bounded payload size.
    #[must_use]
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
    /// Borrows the still-masked payload for the Stage 02 semantic decoder.
    pub fn frame(self, payload: &[u8]) -> Result<ClientWebSocketFrame<'_>, FrameHeaderError> {
        if payload.len() != self.payload_bytes {
            return Err(FrameHeaderError::Protocol);
        }
        Ok(ClientWebSocketFrame {
            fin: self.fin,
            reserved_bits: false,
            opcode: self.opcode,
            mask: Some(self.mask),
            payload,
        })
    }
}

/// Decodes a complete header without allocating or consuming payload bytes.
pub fn decode_client_header(input: &[u8]) -> Result<Option<ClientFrameHeader>, FrameHeaderError> {
    let Some((&first, rest)) = input.split_first() else {
        return Ok(None);
    };
    let Some(&second) = rest.first() else {
        return Ok(None);
    };
    if first & 0x70 != 0 || second & 0x80 == 0 {
        return Err(FrameHeaderError::Protocol);
    }
    let fin = first & 0x80 != 0;
    let opcode = match first & 0x0f {
        0 => WebSocketOpcode::Continuation,
        1 => WebSocketOpcode::Text,
        2 => WebSocketOpcode::Binary,
        8 => WebSocketOpcode::Close,
        9 => WebSocketOpcode::Ping,
        10 => WebSocketOpcode::Pong,
        _ => return Err(FrameHeaderError::Protocol),
    };
    let code = second & 0x7f;
    if first & 0x08 != 0 && (!fin || code > 125) {
        return Err(FrameHeaderError::Protocol);
    }
    let Some((length, mask_offset)) = payload_length(input, code)? else {
        return Ok(None);
    };
    if length > MAX_WEBSOCKET_MESSAGE_BYTES as u64 {
        return Err(FrameHeaderError::TooLarge);
    }
    let header_bytes = mask_offset + 4;
    let Some(mask) = input.get(mask_offset..header_bytes) else {
        return Ok(None);
    };
    Ok(Some(ClientFrameHeader {
        fin,
        opcode,
        mask: mask.try_into().map_err(|_| FrameHeaderError::Protocol)?,
        payload_bytes: usize::try_from(length).map_err(|_| FrameHeaderError::TooLarge)?,
        header_bytes,
    }))
}

fn payload_length(input: &[u8], code: u8) -> Result<Option<(u64, usize)>, FrameHeaderError> {
    let decoded = match code {
        126 => {
            let Some(bytes) = input.get(2..4) else {
                return Ok(None);
            };
            let value =
                u16::from_be_bytes(bytes.try_into().map_err(|_| FrameHeaderError::Protocol)?);
            if value < 126 {
                return Err(FrameHeaderError::Protocol);
            }
            (u64::from(value), 4)
        }
        127 => {
            let Some(bytes) = input.get(2..10) else {
                return Ok(None);
            };
            let value =
                u64::from_be_bytes(bytes.try_into().map_err(|_| FrameHeaderError::Protocol)?);
            if value < 65_536 || value & (1_u64 << 63) != 0 {
                return Err(FrameHeaderError::Protocol);
            }
            (value, 10)
        }
        value => (u64::from(value), 2),
    };
    Ok(Some(decoded))
}

/// Encodes an unmasked final server frame header in at most four bytes.
pub fn server_frame_header(
    opcode: WebSocketOpcode,
    payload: usize,
) -> Result<([u8; 4], usize), FrameHeaderError> {
    let code = match opcode {
        WebSocketOpcode::Text => 1,
        WebSocketOpcode::Binary => 2,
        WebSocketOpcode::Close => 8,
        WebSocketOpcode::Ping => 9,
        WebSocketOpcode::Pong => 10,
        _ => return Err(FrameHeaderError::Protocol),
    };
    if payload > MAX_WEBSOCKET_MESSAGE_BYTES || (code >= 8 && payload > 125) {
        return Err(FrameHeaderError::TooLarge);
    }
    let mut result = [0_u8; 4];
    result[0] = 0x80 | code;
    if payload <= 125 {
        result[1] = u8::try_from(payload).map_err(|_| FrameHeaderError::TooLarge)?;
        return Ok((result, 2));
    }
    result[1] = 126;
    let bytes = u16::try_from(payload)
        .map_err(|_| FrameHeaderError::TooLarge)?
        .to_be_bytes();
    result[2] = bytes[0];
    result[3] = bytes[1];
    Ok((result, 4))
}

/// Number of header bytes needed next, including the mask. The initial two
/// bytes are decoded before requesting any extended length or payload.
#[must_use]
pub fn client_header_bytes(input: &[u8]) -> usize {
    match input.get(1).map(|byte| byte & 0x7f) {
        None => 2,
        Some(126) => 8,
        Some(127) => 14,
        Some(_) => 6,
    }
}

impl std::fmt::Display for FrameHeaderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Protocol => "invalid WebSocket frame header",
            Self::TooLarge => "WebSocket frame exceeds its limit",
        })
    }
}
impl std::error::Error for FrameHeaderError {}
