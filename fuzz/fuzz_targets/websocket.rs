#![forbid(unsafe_code)]
#![no_main]

use agenc_ircd_client_wire::{
    ClientWebSocketFrame, MAX_WEBSOCKET_MESSAGE_BYTES, WebSocketEvent, WebSocketOpcode,
    WebSocketSubprotocol, WebSocketWire,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 32_768 {
        return;
    }
    let Some(flags) = data.first().copied() else {
        return;
    };
    let protocol = if flags & 1 == 0 {
        WebSocketSubprotocol::TextIrcv3
    } else {
        WebSocketSubprotocol::BinaryIrcv3
    };
    exercise_fragmented_sequence(protocol, data);
    exercise_arbitrary_frame(protocol, data);

    if flags & 0x20 != 0 {
        exercise_oversized_message(protocol);
    }
});

fn exercise_fragmented_sequence(protocol: WebSocketSubprotocol, data: &[u8]) {
    let message = safe_message(data);
    let first_end = usize::from(data.get(1).copied().unwrap_or_default()) % message.len();
    let remaining = message.len().saturating_sub(first_end);
    let second_end = first_end
        .saturating_add(usize::from(data.get(2).copied().unwrap_or_default()) % remaining.max(1))
        .min(message.len());
    let opcode = data_opcode(protocol);
    let masks = [[1, 2, 3, 4], [4, 3, 2, 1], [9, 7, 5, 3]];
    let fragments = [
        apply_mask(&message[..first_end], masks[0]),
        apply_mask(&message[first_end..second_end], masks[1]),
        apply_mask(&message[second_end..], masks[2]),
    ];
    let Ok(mut fragmented) = WebSocketWire::new(protocol) else {
        return;
    };
    let first = fragmented.accept(ClientWebSocketFrame {
        fin: false,
        reserved_bits: false,
        opcode,
        mask: Some(masks[0]),
        payload: &fragments[0],
    });
    assert!(matches!(first, Ok(None)));
    assert_control_event(&mut fragmented, WebSocketOpcode::Ping, WebSocketEvent::Ping);
    let second = fragmented.accept(ClientWebSocketFrame {
        fin: false,
        reserved_bits: false,
        opcode: WebSocketOpcode::Continuation,
        mask: Some(masks[1]),
        payload: &fragments[1],
    });
    assert!(matches!(second, Ok(None)));
    assert_control_event(&mut fragmented, WebSocketOpcode::Pong, WebSocketEvent::Pong);
    let final_event = fragmented.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode: WebSocketOpcode::Continuation,
        mask: Some(masks[2]),
        payload: &fragments[2],
    });

    let whole_mask = [6, 5, 4, 3];
    let whole_payload = apply_mask(&message, whole_mask);
    let Ok(mut whole) = WebSocketWire::new(protocol) else {
        return;
    };
    let whole_event = whole.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode,
        mask: Some(whole_mask),
        payload: &whole_payload,
    });
    assert_eq!(final_event, whole_event);
}

fn assert_control_event(
    wire: &mut WebSocketWire,
    opcode: WebSocketOpcode,
    event: fn(Vec<u8>) -> WebSocketEvent,
) {
    let mask = [8, 6, 4, 2];
    let payload = apply_mask(b"control", mask);
    let result = wire.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode,
        mask: Some(mask),
        payload: &payload,
    });
    assert_eq!(result, Ok(Some(event(b"control".to_vec()))));
}

fn exercise_arbitrary_frame(protocol: WebSocketSubprotocol, data: &[u8]) {
    let flags = data.first().copied().unwrap_or_default();
    let mask = [
        flags,
        flags.rotate_left(1),
        flags.rotate_left(2),
        flags.rotate_left(3),
    ];
    let plain = data.get(1..).unwrap_or_default();
    let plain = &plain[..plain.len().min(1_024)];
    let payload = apply_mask(plain, mask);
    let Ok(mut wire) = WebSocketWire::new(protocol) else {
        return;
    };
    let _event = wire.accept(ClientWebSocketFrame {
        fin: flags & 0x20 != 0,
        reserved_bits: flags & 0x40 != 0,
        opcode: opcode(flags >> 1),
        mask: (flags & 0x80 == 0).then_some(mask),
        payload: &payload,
    });
}

fn exercise_oversized_message(protocol: WebSocketSubprotocol) {
    let Ok(mut wire) = WebSocketWire::new(protocol) else {
        return;
    };
    let payload = vec![0_u8; MAX_WEBSOCKET_MESSAGE_BYTES.saturating_add(1)];
    let close = wire.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode: data_opcode(protocol),
        mask: Some([0, 0, 0, 0]),
        payload: &payload,
    });
    assert_eq!(close.err().map(|error| error.code()), Some(1009));
}

fn safe_message(data: &[u8]) -> Vec<u8> {
    let mut message = b"NOTICE target :".to_vec();
    message.extend(
        data.iter()
            .take(256)
            .map(|byte| b'a'.saturating_add(*byte % 26)),
    );
    message
}

const fn data_opcode(protocol: WebSocketSubprotocol) -> WebSocketOpcode {
    match protocol {
        WebSocketSubprotocol::TextIrcv3 => WebSocketOpcode::Text,
        WebSocketSubprotocol::BinaryIrcv3 => WebSocketOpcode::Binary,
    }
}

fn apply_mask(payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    payload
        .iter()
        .enumerate()
        .map(|(index, byte)| *byte ^ mask[index % mask.len()])
        .collect()
}

fn opcode(value: u8) -> WebSocketOpcode {
    match value % 7 {
        0 => WebSocketOpcode::Continuation,
        1 => WebSocketOpcode::Text,
        2 => WebSocketOpcode::Binary,
        3 => WebSocketOpcode::Close,
        4 => WebSocketOpcode::Ping,
        5 => WebSocketOpcode::Pong,
        other => WebSocketOpcode::Reserved(other),
    }
}
