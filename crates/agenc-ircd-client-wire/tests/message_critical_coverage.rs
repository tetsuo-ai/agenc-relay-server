//! Closed parser-error reporting and public-boundary decision coverage.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_client_wire::{FramedLine, MessageParseError, TagError, parse_message};

#[test]
fn parser_error_reporting_covers_every_closed_variant() {
    let cases = [
        (
            MessageParseError::ClientPrefix,
            "client messages may not contain a prefix",
        ),
        (
            MessageParseError::UnterminatedTags,
            "message tag section lacks a separating space",
        ),
        (
            MessageParseError::Tags(TagError::InvalidKey),
            "message tags are invalid",
        ),
        (
            MessageParseError::InvalidCommand,
            "client command must contain only ASCII letters",
        ),
        (
            MessageParseError::TooManyParameters,
            "client message has more than 15 parameters",
        ),
        (
            MessageParseError::Overflow,
            "client message backing-capacity calculation overflowed",
        ),
        (
            MessageParseError::AllocationFailed,
            "client message allocation failed",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
    assert!(Error::source(&MessageParseError::Tags(TagError::InvalidKey)).is_some());
    assert!(Error::source(&MessageParseError::ClientPrefix).is_none());
}

#[test]
fn public_parser_exercises_every_input_shape_decision() -> Result<(), Box<dyn Error>> {
    for line in [
        "PING",
        "PING token",
        "PING one two",
        "PING :trailing value",
        "@tag=value PING",
        "@tag=value   PING token",
    ] {
        assert!(parse_message(FramedLine::new(line)?)?.is_some(), "{line:?}");
    }
    for (line, expected) in [
        ("@tag", MessageParseError::UnterminatedTags),
        ("@ PING", MessageParseError::Tags(TagError::InvalidKey)),
        (":prefix PING", MessageParseError::ClientPrefix),
        ("@tag=value   ", MessageParseError::InvalidCommand),
        ("P1NG", MessageParseError::InvalidCommand),
    ] {
        assert_eq!(parse_message(FramedLine::new(line)?).err(), Some(expected));
    }
    assert_eq!(parse_message(FramedLine::new("   ")?)?, None);

    let parameters = (0..16)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let line = format!("NOTICE {parameters}");
    assert_eq!(
        parse_message(FramedLine::new(&line)?).err(),
        Some(MessageParseError::TooManyParameters)
    );
    Ok(())
}
