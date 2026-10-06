#![forbid(unsafe_code)]

//! Hand-written server-to-client vectors (`test-data/vectors/server-wire-v1.vectors`):
//! each accepted line decodes and rebuilds byte for byte from its parts, and
//! each rejected one fails at the named stage with the named error.

use std::error::Error;

use agenc_relay_client_wire::{
    ServerCommand, ServerFramedLine, ServerMessage, ServerMessageError, ServerStreamFramer,
    parse_server_message,
};

const VECTORS: &str = include_str!("../../../test-data/vectors/server-wire-v1.vectors");

type TestResult = Result<(), Box<dyn Error>>;

/// What one stream decoded to: accepted, or the stage and error that refused it.
#[derive(Debug, Eq, PartialEq)]
enum Outcome {
    Accepted,
    Refused(&'static str, String),
}

fn payload(encoding: &str, text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    match encoding {
        "ascii" => Ok(format!("{text}\r\n").into_bytes()),
        "hex" => (0..text.len())
            .step_by(2)
            .map(|index| {
                let pair = text.get(index..index + 2).ok_or("odd hex")?;
                Ok(u8::from_str_radix(pair, 16)?)
            })
            .collect(),
        _ => Err(format!("unknown encoding {encoding}").into()),
    }
}

fn rebuilt(message: &ServerMessage<'_>) -> String {
    let mut line = String::new();
    if !message.tags().is_empty() {
        line.push('@');
        line.push_str(message.tags().raw_section());
        line.push(' ');
    }
    if let Some(prefix) = message.prefix() {
        line.push(':');
        line.push_str(prefix.as_str());
        line.push(' ');
    }
    match message.command() {
        ServerCommand::Named(name) => line.push_str(name),
        ServerCommand::Numeric(code) => line.push_str(&format!("{code:03}")),
    }
    for middle in message.params().middle() {
        line.push(' ');
        line.push_str(middle);
    }
    if let Some(trailing) = message.params().trailing() {
        line.push_str(" :");
        line.push_str(trailing);
    }
    line
}

fn decode(stream: &[u8]) -> Result<Outcome, Box<dyn Error>> {
    let mut framer = ServerStreamFramer::new()?;
    let mut lines = Vec::new();
    let framed = framer
        .feed(stream, |line| lines.push(line.as_str().to_owned()))
        .and_then(|_| framer.finish());
    if let Err(error) = framed {
        return Ok(Outcome::Refused("framing", format!("{error:?}")));
    }
    let [line] = lines.as_slice() else {
        return Err(format!("{} lines framed", lines.len()).into());
    };
    match parse_server_message(ServerFramedLine::new(line)?) {
        Ok(message) => {
            assert_eq!(rebuilt(&message), *line, "not canonical");
            Ok(Outcome::Accepted)
        }
        Err(ServerMessageError::Tags(error)) => Ok(Outcome::Refused("tags", format!("{error:?}"))),
        Err(error) => Ok(Outcome::Refused("message", format!("{error:?}"))),
    }
}

fn expected(surface: &str) -> Result<Outcome, Box<dyn Error>> {
    let parts: Vec<&str> = surface.split('/').collect();
    match parts.as_slice() {
        ["accept", _] => Ok(Outcome::Accepted),
        ["reject", stage, error, _] => {
            let stage = match *stage {
                "framing" => "framing",
                "tags" => "tags",
                "message" => "message",
                other => return Err(format!("unknown stage {other}").into()),
            };
            Ok(Outcome::Refused(stage, (*error).to_owned()))
        }
        _ => Err(format!("unknown surface {surface}").into()),
    }
}

#[test]
fn every_vector_decodes_or_fails_as_recorded() -> TestResult {
    let mut accepted = 0_usize;
    let mut refused = 0_usize;
    let mut names = Vec::new();
    for line in VECTORS.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.splitn(4, '|').collect();
        let [evidence, surface, encoding, text] = fields.as_slice() else {
            return Err(format!("not four fields: {line}").into());
        };
        assert!(evidence.starts_with("EVID-S02-"), "{evidence}");
        let expected = expected(surface)?;
        let actual = decode(&payload(encoding, text)?)?;
        assert_eq!(actual, expected, "{surface}");
        if expected == Outcome::Accepted {
            accepted += 1;
        } else {
            refused += 1;
        }
        names.push(*surface);
    }
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), count, "a surface name repeats");
    assert!(accepted >= 20, "{accepted} accepted vectors");
    assert!(refused >= 30, "{refused} refused vectors");
    Ok(())
}
