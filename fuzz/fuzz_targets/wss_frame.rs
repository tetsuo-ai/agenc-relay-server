#![forbid(unsafe_code)]
#![no_main]

use agenc_ircd_client_wire::websocket_transport::decode_client_header;
use agenc_ircd_client_wire::{MAX_WEBSOCKET_MESSAGE_BYTES, WebSocketSubprotocol, WebSocketWire};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 18_436 {
        return;
    }
    for protocol in [
        WebSocketSubprotocol::TextIrcv3,
        WebSocketSubprotocol::BinaryIrcv3,
    ] {
        let Ok(mut wire) = WebSocketWire::new(protocol) else {
            return;
        };
        let mut remaining = data;
        for _ in 0..64 {
            let Ok(Some(header)) = decode_client_header(remaining) else {
                break;
            };
            assert!(header.payload_bytes() <= MAX_WEBSOCKET_MESSAGE_BYTES);
            let end = header.header_bytes() + header.payload_bytes();
            let Some(payload) = remaining.get(header.header_bytes()..end) else {
                break;
            };
            let Ok(frame) = header.frame(payload) else {
                break;
            };
            if wire.accept(frame).is_err() {
                break;
            }
            let Some(tail) = remaining.get(end..) else {
                break;
            };
            remaining = tail;
        }
    }
});
