#![forbid(unsafe_code)]

//! Executable checks for every checked-in Stage-02 client-wire vector.

use std::error::Error;
use std::io;

use agenc_relay_client_wire::{
    ACCOUNT_REQUEST_CHARACTERS, CanonicalBase64Url, CapabilityProfile, CapabilitySpec,
    CapabilityState, ClientWebSocketFrame, FramedLine, OutputBudget, RenderError,
    SASL_REQUEST_CHARACTERS, StreamFramer, WebSocketEvent, WebSocketOpcode, WebSocketSubprotocol,
    WebSocketWire, WireMessage, parse_client_tags, parse_message, parse_u64_decimal, render_tags,
};

const VECTORS: &str = include_str!("../../../test-data/vectors/client-wire-v1.vectors");

struct Vector {
    surface: String,
    payload: Vec<u8>,
}

struct Permit;

struct ExactBudget(usize);

impl OutputBudget for ExactBudget {
    type Permit = Permit;

    fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
        if bytes != self.0 {
            return Err(RenderError::ReservationFailed);
        }
        Ok(Permit)
    }
}

#[test]
fn every_checked_in_client_wire_vector_executes() -> Result<(), Box<dyn Error>> {
    let vectors = parse_vectors(VECTORS)?;
    assert_eq!(vectors.len(), 10);
    for vector in &vectors {
        execute_vector(vector)?;
    }
    Ok(())
}

fn execute_vector(vector: &Vector) -> Result<(), Box<dyn Error>> {
    match vector.surface.as_str() {
        "empty-line" => {
            let mut framer = StreamFramer::new()?;
            let mut messages = 0usize;
            let progress = framer.feed(&vector.payload, |_line| {
                messages = messages.saturating_add(1);
            })?;
            assert_eq!(messages, 0);
            assert_eq!(progress.empty_lines, 1);
            framer.finish()?;
        }
        "masked-text" => {
            let mask = [1, 2, 3, 4];
            let masked = apply_mask(&vector.payload, mask);
            let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
            let event = wire.accept(ClientWebSocketFrame {
                fin: true,
                reserved_bits: false,
                opcode: WebSocketOpcode::Text,
                mask: Some(mask),
                payload: &masked,
            })?;
            let Some(WebSocketEvent::Message(message)) = event else {
                return Err(io::Error::other("WebSocket vector emitted the wrong event").into());
            };
            assert_eq!(message.as_str(), payload_text(vector)?);
        }
        "ircv3-escape" => {
            let parsed = parse_client_tags(payload_text(vector)?)?;
            let canonical = render_tags(&parsed)?;
            assert_eq!(parse_client_tags(&canonical)?, parsed);
        }
        "trailing-empty" => {
            let parsed = parse_message(FramedLine::new(payload_text(vector)?)?)?
                .ok_or_else(|| io::Error::other("vector unexpectedly parsed as an empty line"))?;
            assert_eq!(parsed.trailing(), Some(""));
        }
        "cap-ls-302" => {
            let parsed = parse_message(FramedLine::new(payload_text(vector)?)?)?
                .ok_or_else(|| io::Error::other("CAP vector parsed as an empty line"))?;
            assert_eq!(parsed.command(), "CAP");
            let advertised =
                CapabilityProfile::new(vec![CapabilitySpec::new("cap-notify", None)?])?;
            let mut state = CapabilityState::default();
            assert_eq!(state.ls(Some("302"), &advertised)?, ["cap-notify"]);
            assert!(state.enabled("cap-notify"));
            assert!(state.blocks_registration());
        }
        "sasl-request-shape" => {
            assert_shape(payload_text(vector)?, SASL_REQUEST_CHARACTERS)?;
        }
        "account-request-shape" => {
            assert_shape(payload_text(vector)?, ACCOUNT_REQUEST_CHARACTERS)?;
        }
        "decimal-u64-max" => {
            assert_eq!(parse_u64_decimal(payload_text(vector)?)?, u64::MAX);
        }
        "base64url-one-byte" => {
            let decoded = CanonicalBase64Url::parse(payload_text(vector)?, 1, 1)?;
            assert_eq!(decoded.as_bytes(), [1]);
        }
        "tag-order" => {
            let advertised =
                CapabilityProfile::new(vec![CapabilitySpec::new("message-tags", None)?])?;
            let mut capabilities = CapabilityState::default();
            capabilities.ls(Some("302"), &advertised)?;
            capabilities.request("message-tags", &advertised)?;
            let mut message = WireMessage::new("server.example", "NOTICE", &["Alice"], None)?;
            message.add_client_only_tag(&capabilities, "+z", Some("last"))?;
            message.add_server_tag("z", Some("two"))?;
            message.add_server_tag("a", Some("one"))?;
            message.add_client_only_tag(&capabilities, "+a", Some("first"))?;
            let measured = message.measure()?;
            let bytes = measured.bytes();
            let mut budget = ExactBudget(bytes);
            let rendered = measured.encode(&mut budget)?;
            let output = std::str::from_utf8(rendered.as_bytes())?;
            assert!(output.starts_with(&format!("@{} ", payload_text(vector)?)));
        }
        other => return Err(io::Error::other(format!("unknown vector surface: {other}")).into()),
    }
    Ok(())
}

fn assert_shape(value: &str, expected: usize) -> Result<(), Box<dyn Error>> {
    let (terms, total) = value
        .split_once('=')
        .ok_or_else(|| io::Error::other("shape vector has no total"))?;
    let (repeated, tail) = terms
        .split_once('+')
        .ok_or_else(|| io::Error::other("shape vector has no tail"))?;
    let (count, width) = repeated
        .split_once('x')
        .ok_or_else(|| io::Error::other("shape vector has no repeated width"))?;
    let calculated = count
        .parse::<usize>()?
        .checked_mul(width.parse::<usize>()?)
        .and_then(|bytes| bytes.checked_add(tail.parse::<usize>().ok()?))
        .ok_or_else(|| io::Error::other("shape vector overflowed"))?;
    assert_eq!(calculated, total.parse::<usize>()?);
    assert_eq!(calculated, expected);
    Ok(())
}

fn parse_vectors(input: &str) -> Result<Vec<Vector>, Box<dyn Error>> {
    let mut vectors = Vec::new();
    for line in input
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<&str> = line.split('|').collect();
        let [_evidence, surface, encoding, payload] = fields.as_slice() else {
            return Err(io::Error::other("vector must have four fields").into());
        };
        let payload = match *encoding {
            "ascii" => payload.as_bytes().to_vec(),
            "hex" => decode_hex(payload)?,
            other => {
                return Err(io::Error::other(format!("unknown vector encoding: {other}")).into());
            }
        };
        vectors.push(Vector {
            surface: (*surface).to_owned(),
            payload,
        });
    }
    Ok(vectors)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) {
        return Err(io::Error::other("hex vector has odd length").into());
    }
    let mut decoded = Vec::new();
    decoded.try_reserve_exact(value.len() / 2)?;
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(io::Error::other("hex vector has odd length").into());
    }
    for pair in pairs {
        let pair = std::str::from_utf8(pair)?;
        decoded.push(u8::from_str_radix(pair, 16)?);
    }
    Ok(decoded)
}

fn payload_text(vector: &Vector) -> Result<&str, Box<dyn Error>> {
    Ok(std::str::from_utf8(&vector.payload)?)
}

fn apply_mask(payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    payload
        .iter()
        .zip(mask.iter().cycle())
        .map(|(byte, mask_byte)| *byte ^ *mask_byte)
        .collect()
}
