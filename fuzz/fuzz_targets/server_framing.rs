#![forbid(unsafe_code)]
#![no_main]

use agenc_relay_client_wire::{
    ServerCommand, ServerFramedLine, ServerFramingError, ServerMessageError, ServerStreamFramer,
    parse_server_message, parse_server_tags, unescape_server_tag_value,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 32_768 {
        return;
    }

    let schedule = chunk_schedule(data);
    let whole = run(data, &[data.len().max(1)]);
    assert_eq!(whole, run(data, &schedule));
    assert_eq!(whole, run(data, &[1]));

    // The same bytes as one delimited line, and as a bare tag section.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(line) = ServerFramedLine::new(text) {
            let _ = parse_server_message(line);
        }
        if let Ok(tags) = parse_server_tags(text) {
            assert!(tags.len() >= 1);
            assert_eq!(tags.iter().count(), tags.len());
            for tag in tags.iter() {
                if let Some(raw) = tag.raw_value() {
                    let decoded = unescape_server_tag_value(raw);
                    assert!(decoded.is_ok());
                }
            }
        }
    }

    let fixed = b"@label=a1;msgid=m :server.example PONG :x\r\n:alice!u-abcdefgh23@h-ijklmnopqrstuv67.invalid PRIVMSG #c :hi\r\n";
    assert_eq!(run(fixed, &[fixed.len()]), run(fixed, &schedule));
});

#[derive(Debug, Eq, PartialEq)]
struct Run {
    lines: Vec<ObservedLine>,
    framing: Result<(), ServerFramingError>,
    finish: Option<Result<(), ServerFramingError>>,
}

#[derive(Debug, Eq, PartialEq)]
struct ObservedLine {
    bytes: usize,
    checksum: u64,
    decoded: Result<DecodedShape, ServerMessageError>,
}

#[derive(Debug, Eq, PartialEq)]
struct DecodedShape {
    command: ServerCommand,
    prefix_bytes: Option<usize>,
    parameters: usize,
    trailing_present: bool,
    tags: usize,
    client_only_tags: usize,
    label_bytes: Option<usize>,
    batch_bytes: Option<usize>,
}

fn run(payload: &[u8], schedule: &[usize]) -> Run {
    let Ok(mut framer) = ServerStreamFramer::new() else {
        return Run {
            lines: Vec::new(),
            framing: Err(ServerFramingError::AllocationFailed),
            finish: None,
        };
    };
    let mut lines = Vec::new();
    let mut offset = 0usize;
    let mut schedule_index = 0usize;
    while offset < payload.len() {
        let requested = schedule
            .get(schedule_index % schedule.len().max(1))
            .copied()
            .unwrap_or(1)
            .max(1);
        let end = offset.saturating_add(requested).min(payload.len());
        let result = framer.feed(&payload[offset..end], |line| {
            let text = line.as_str();
            lines.push(ObservedLine {
                bytes: text.len(),
                checksum: checksum(text.as_bytes()),
                decoded: parse_server_message(line).map(|message| DecodedShape {
                    command: message.command(),
                    prefix_bytes: message.prefix().map(|prefix| prefix.as_str().len()),
                    parameters: message.params().len(),
                    trailing_present: message.params().trailing().is_some(),
                    tags: message.tags().len(),
                    client_only_tags: message.tags().client_only_count(),
                    label_bytes: message.tags().label().map(str::len),
                    batch_bytes: message.tags().batch().map(str::len),
                }),
            });
        });
        if let Err(error) = result {
            return Run {
                lines,
                framing: Err(error),
                finish: None,
            };
        }
        offset = end;
        schedule_index = schedule_index.saturating_add(1);
    }
    Run {
        lines,
        framing: Ok(()),
        finish: Some(framer.finish()),
    }
}

fn chunk_schedule(data: &[u8]) -> Vec<usize> {
    let mut chunks: Vec<usize> = data
        .iter()
        .take(32)
        .map(|byte| usize::from(*byte % 64).saturating_add(1))
        .collect();
    if chunks.is_empty() {
        chunks.push(1);
    }
    chunks
}

fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3)
    })
}
