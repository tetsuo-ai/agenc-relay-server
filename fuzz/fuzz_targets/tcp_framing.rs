#![forbid(unsafe_code)]
#![no_main]

use agenc_relay_client_wire::{FramingError, MessageParseError, StreamFramer, parse_message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 32_768 {
        return;
    }

    let schedule = chunk_schedule(data);
    assert_eq!(run(data, &[data.len().max(1)]), run(data, &schedule));

    let fixed = b"PING :seed\r\n\r\nNOTICE target :coalesced\r\n";
    assert_eq!(run(fixed, &[fixed.len()]), run(fixed, &schedule));
});

#[derive(Debug, Eq, PartialEq)]
struct Run {
    lines: Vec<ObservedLine>,
    empty_lines: usize,
    framing: Result<(), FramingError>,
    finish: Option<Result<(), FramingError>>,
}

#[derive(Debug, Eq, PartialEq)]
struct ObservedLine {
    bytes: usize,
    checksum: u64,
    parsed: Result<Option<ParsedShape>, MessageParseError>,
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedShape {
    command_bytes: usize,
    parameters: usize,
    tags: usize,
    trailing_present: bool,
}

fn run(payload: &[u8], schedule: &[usize]) -> Run {
    let Ok(mut framer) = StreamFramer::new() else {
        return Run {
            lines: Vec::new(),
            empty_lines: 0,
            framing: Err(FramingError::AllocationFailed),
            finish: None,
        };
    };
    let mut lines = Vec::new();
    let mut empty_lines = 0usize;
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
            let bytes = text.len();
            let checksum = checksum(text.as_bytes());
            let parsed = parse_message(line).map(|message| {
                message.map(|message| ParsedShape {
                    command_bytes: message.command().len(),
                    parameters: message.parameter_count(),
                    tags: message.tags().len(),
                    trailing_present: message.trailing().is_some(),
                })
            });
            lines.push(ObservedLine {
                bytes,
                checksum,
                parsed,
            });
        });
        let progress = match result {
            Ok(progress) => progress,
            Err(error) => {
                return Run {
                    lines,
                    empty_lines: 0,
                    framing: Err(error),
                    finish: None,
                };
            }
        };
        empty_lines = empty_lines.saturating_add(progress.empty_lines);
        offset = end;
        schedule_index = schedule_index.saturating_add(1);
    }
    Run {
        lines,
        empty_lines,
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
