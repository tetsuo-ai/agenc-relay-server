#![forbid(unsafe_code)]

//! The server-to-client decoder: line bounds by direction, the tag section,
//! and the message grammar and registries (Architecture 9.1, 9.2, 9.5 and
//! Appendix A.2). The boundaries are the specification's: 8,191 and 8,192
//! bytes of tag section, 4,094 and 4,095 bytes of one side, and 510 and 511
//! command bytes after a full tag section.

use std::error::Error;

use agenc_relay_client_wire::{
    ADMIN_ONLY_REPLY_CODES, FORBIDDEN_NUMERICS, FramingError, MAX_CLIENT_TAG_DATA_BYTES,
    MAX_COMBINED_TAG_SECTION_BYTES, MAX_PHYSICAL_LINE_BYTES, MAX_SERVER_TAG_DATA_BYTES,
    ServerCommand, ServerFramedLine, ServerFramingError, ServerMessage, ServerMessageError,
    ServerPrefix, ServerStreamFramer, ServerTagError, StreamFramer, WireDirection,
    parse_server_message, parse_server_tags, unescape_server_tag_value, validate_batch_reference,
    validate_safe_label,
};
use agenc_relay_types::{Nickname, SERVER_NUMERICS, STANDARD_REPLY_CODES, ServerName};

type TestResult = Result<(), Box<dyn Error>>;

const SERVER: &str = "server.example";
const MASK: &str = "alice!u-abcdefgh23@h-ijklmnopqrstuv67.invalid";

/// Frames `stream` in one feed and returns the lines or the failure.
fn frame_all(stream: &[u8]) -> Result<Vec<String>, ServerFramingError> {
    let mut framer = ServerStreamFramer::new()?;
    let mut lines = Vec::new();
    framer.feed(stream, |line| lines.push(line.as_str().to_owned()))?;
    framer.finish()?;
    Ok(lines)
}

fn decode(line: &str) -> Result<ServerMessage<'_>, Box<dyn Error>> {
    Ok(parse_server_message(ServerFramedLine::new(line)?)?)
}

fn decode_error(line: &str) -> Result<ServerMessageError, Box<dyn Error>> {
    match parse_server_message(ServerFramedLine::new(line)?) {
        Ok(_) => Err(format!("accepted {line:?}").into()),
        Err(error) => Ok(error),
    }
}

fn tag_error(raw: &str) -> Result<ServerTagError, Box<dyn Error>> {
    match parse_server_tags(raw) {
        Ok(_) => Err(format!("accepted tags {raw:?}").into()),
        Err(error) => Ok(error),
    }
}

/// Server-added tag data of exactly `bytes` bytes: one `s=` tag.
fn server_side(bytes: usize) -> String {
    format!("s={}", "v".repeat(bytes - 2))
}

/// Client-only tag data of exactly `bytes` bytes: the E2EE tag, which the
/// value and total budgets exempt.
fn client_side(bytes: usize) -> String {
    let key = "+agenc.ag/e2ee=";
    format!("{key}{}", "v".repeat(bytes - key.len()))
}

#[test]
fn each_direction_names_the_bounds_its_framer_applies() -> TestResult {
    let client = WireDirection::ClientToServer;
    let server = WireDirection::ServerToClient;
    assert_eq!(client.max_content_bytes(), MAX_PHYSICAL_LINE_BYTES - 2);
    assert_eq!(server.max_content_bytes(), MAX_PHYSICAL_LINE_BYTES - 2);
    assert_eq!(client.max_tag_data_bytes(), MAX_CLIENT_TAG_DATA_BYTES);
    assert_eq!(
        server.max_tag_data_bytes(),
        MAX_COMBINED_TAG_SECTION_BYTES - 2
    );
    assert!(!client.rejects_empty_lines());
    assert!(server.rejects_empty_lines());

    // The client framer: its tag data stops at the client direction's bound.
    let mut framer = StreamFramer::new()?;
    let at = format!("@{} PING\r\n", "a".repeat(client.max_tag_data_bytes()));
    assert_eq!(framer.feed(at.as_bytes(), |_| {})?.messages, 1);
    let over = format!("@{} PING\r\n", "a".repeat(client.max_tag_data_bytes() + 1));
    assert_eq!(
        StreamFramer::new()?.feed(over.as_bytes(), |_| {}).err(),
        Some(FramingError::ClientTagsTooLong)
    );
    assert_eq!(StreamFramer::new()?.feed(b"\r\n", |_| {})?.empty_lines, 1);

    // The server framer: a tag section a client may not send is legal here.
    let section = format!(
        "{};{}",
        server_side(MAX_SERVER_TAG_DATA_BYTES),
        client_side(MAX_CLIENT_TAG_DATA_BYTES)
    );
    assert_eq!(section.len(), server.max_tag_data_bytes());
    let line = format!("@{section} :{MASK} PRIVMSG #c :hi\r\n");
    assert_eq!(frame_all(line.as_bytes())?.len(), 1);
    assert_eq!(frame_all(b"\r\n"), Err(ServerFramingError::EmptyLine));
    Ok(())
}

#[test]
fn the_combined_tag_section_holds_8191_bytes_and_refuses_8192() -> TestResult {
    let section = format!(
        "{};{}",
        server_side(MAX_SERVER_TAG_DATA_BYTES),
        client_side(MAX_CLIENT_TAG_DATA_BYTES)
    );
    assert_eq!(section.len() + 2, MAX_COMBINED_TAG_SECTION_BYTES);
    let line = format!("@{section} :{MASK} PRIVMSG #c :hi");
    let lines = frame_all(format!("{line}\r\n").as_bytes())?;
    let message = decode(lines.first().ok_or("no line")?)?;
    assert_eq!(
        message.tags().server_data_bytes(),
        MAX_SERVER_TAG_DATA_BYTES
    );
    assert_eq!(
        message.tags().client_data_bytes(),
        MAX_CLIENT_TAG_DATA_BYTES
    );
    assert_eq!(message.tags().len(), 2);

    // One byte more: the framer refuses it as soon as the byte arrives, and
    // the delimited and tag-level checks agree.
    let over = format!("{section}x");
    assert_eq!(over.len() + 2, MAX_COMBINED_TAG_SECTION_BYTES + 1);
    let mut framer = ServerStreamFramer::new()?;
    assert_eq!(
        framer.feed(format!("@{over}").as_bytes(), |_| {}),
        Err(ServerFramingError::TagSectionTooLong)
    );
    assert_eq!(
        ServerFramedLine::new(&format!("@{over} :{SERVER} PING :x")).err(),
        Some(ServerFramingError::TagSectionTooLong)
    );
    assert_eq!(tag_error(&over)?, ServerTagError::SectionTooLong);
    Ok(())
}

#[test]
fn each_tag_side_holds_4094_bytes_and_refuses_4095() -> TestResult {
    let line = |section: &str| format!("@{section} :{MASK} PRIVMSG #c :hi");
    let server_at = line(&server_side(MAX_SERVER_TAG_DATA_BYTES));
    assert_eq!(
        decode(&server_at)?.tags().server_data_bytes(),
        MAX_SERVER_TAG_DATA_BYTES
    );
    assert_eq!(
        decode_error(&line(&server_side(MAX_SERVER_TAG_DATA_BYTES + 1)))?,
        ServerMessageError::Tags(ServerTagError::ServerSideTooLong)
    );
    let client_at = line(&client_side(MAX_CLIENT_TAG_DATA_BYTES));
    assert_eq!(
        decode(&client_at)?.tags().client_data_bytes(),
        MAX_CLIENT_TAG_DATA_BYTES
    );
    assert_eq!(
        decode_error(&line(&client_side(MAX_CLIENT_TAG_DATA_BYTES + 1)))?,
        ServerMessageError::Tags(ServerTagError::ClientSideTooLong)
    );
    // A side's data includes the separators between its own tags, whatever
    // the other side's tags sit between them.
    let split_server = format!(
        "{};+a;t{}",
        server_side(2_000),
        server_side(MAX_SERVER_TAG_DATA_BYTES - 2_001 - 1)
    );
    assert_eq!(
        parse_server_tags(&split_server)?.server_data_bytes(),
        MAX_SERVER_TAG_DATA_BYTES
    );
    let one_over = format!(
        "{};+a;t{}",
        server_side(2_000),
        server_side(MAX_SERVER_TAG_DATA_BYTES - 2_000 - 1)
    );
    assert_eq!(tag_error(&one_over)?, ServerTagError::ServerSideTooLong);
    Ok(())
}

#[test]
fn a_full_tag_section_leaves_510_command_bytes() -> TestResult {
    let section = format!(
        "{};{}",
        server_side(MAX_SERVER_TAG_DATA_BYTES),
        client_side(MAX_CLIENT_TAG_DATA_BYTES)
    );
    let command = |bytes: usize| {
        let head = format!(":{MASK} PRIVMSG #c :");
        format!("{head}{}", "m".repeat(bytes - head.len()))
    };
    let at = format!("@{section} {}", command(510));
    assert_eq!(at.len(), MAX_PHYSICAL_LINE_BYTES - 2);
    assert_eq!(frame_all(format!("{at}\r\n").as_bytes())?.len(), 1);
    assert!(decode(&at).is_ok());
    let over = format!("@{section} {}", command(511));
    assert_eq!(
        frame_all(format!("{over}\r\n").as_bytes()),
        Err(ServerFramingError::LineTooLong)
    );
    assert_eq!(
        ServerFramedLine::new(&over).err(),
        Some(ServerFramingError::LineTooLong)
    );
    // Untagged, the whole 8,701 bytes are command bytes.
    let head = format!(":{SERVER} NOTICE * :");
    let untagged = format!(
        "{head}{}",
        "n".repeat(MAX_PHYSICAL_LINE_BYTES - 2 - head.len())
    );
    assert_eq!(frame_all(format!("{untagged}\r\n").as_bytes())?.len(), 1);
    assert_eq!(
        frame_all(format!("{untagged}n\r\n").as_bytes()),
        Err(ServerFramingError::LineTooLong)
    );
    Ok(())
}

#[test]
fn framing_is_the_same_for_every_split_of_the_stream() -> TestResult {
    let stream = format!(
        ":{SERVER} 001 alice :Welcome \u{e9}\r\n@label=a1 :{SERVER} PONG :x\r\n:{MASK} PRIVMSG #c :\u{1f600}\r\n"
    );
    let whole = frame_all(stream.as_bytes())?;
    assert_eq!(whole.len(), 3);
    for split in 0..=stream.len() {
        let (head, tail) = stream.as_bytes().split_at(split);
        let mut framer = ServerStreamFramer::new()?;
        let mut lines = Vec::new();
        framer.feed(head, |line| lines.push(line.as_str().to_owned()))?;
        framer.feed(tail, |line| lines.push(line.as_str().to_owned()))?;
        framer.finish()?;
        assert_eq!(lines, whole, "split at {split}");
    }
    let mut framer = ServerStreamFramer::new()?;
    let mut count = 0_usize;
    for byte in stream.as_bytes() {
        count += framer.feed(std::slice::from_ref(byte), |_| {})?;
    }
    assert_eq!(count, 3);
    Ok(())
}

#[test]
fn stream_failures_are_typed_and_final() -> TestResult {
    for (stream, expected) in [
        (&b"PING\nPONG\r\n"[..], ServerFramingError::BareLineFeed),
        (&b"PI\rNG\r\n"[..], ServerFramingError::BareCarriageReturn),
        (&b"PI\0NG\r\n"[..], ServerFramingError::EmbeddedNul),
        (&b"PING :\xff\r\n"[..], ServerFramingError::InvalidUtf8),
        (&b"PING :x\r\n\r\n"[..], ServerFramingError::EmptyLine),
        (&b"PING :partial"[..], ServerFramingError::UnexpectedEof),
        (&b"PING :partial\r"[..], ServerFramingError::UnexpectedEof),
        (&b"\r"[..], ServerFramingError::UnexpectedEof),
    ] {
        assert_eq!(frame_all(stream), Err(expected), "{stream:?}");
    }
    let mut framer = ServerStreamFramer::new()?;
    framer.feed(b"PING :part", |_| {})?;
    assert_eq!(framer.timeout(), Err(ServerFramingError::TimedOut));
    assert_eq!(
        framer.feed(b"ial\r\n", |_| {}),
        Err(ServerFramingError::TimedOut)
    );
    assert_eq!(framer.failure(), Some(ServerFramingError::TimedOut));
    let mut idle = ServerStreamFramer::new()?;
    assert_eq!(idle.timeout(), Ok(()));
    assert_eq!(idle.finish(), Ok(()));
    // A delimited line is checked the same way.
    for (line, expected) in [
        ("", ServerFramingError::EmptyLine),
        ("A\0B", ServerFramingError::EmbeddedNul),
        ("A\rB", ServerFramingError::BareCarriageReturn),
        ("A\nB", ServerFramingError::BareLineFeed),
    ] {
        assert_eq!(ServerFramedLine::new(line).err(), Some(expected));
    }
    Ok(())
}

#[test]
fn tag_keys_follow_the_ircv3_grammar() -> TestResult {
    for key in [
        "a",
        "msgid",
        "A-9",
        "+typing",
        "example.com/name",
        "+example.com/x-y",
        "agenc.ag/e2ee-receipt",
        "+a-b.c-d.example/k",
    ] {
        assert!(parse_server_tags(key).is_ok(), "{key}");
    }
    for key in [
        "a_b",
        "+a_b",
        "a.b",
        "+",
        "/name",
        "vendor/",
        "+x/y/z",
        "-vendor.example/n",
        "vendor-.example/n",
        "a..b/n",
        "caf\u{e9}",
    ] {
        assert_eq!(tag_error(key)?, ServerTagError::InvalidKey, "{key}");
    }
    let long_label = format!("{}.example/n", "l".repeat(64));
    assert_eq!(tag_error(&long_label)?, ServerTagError::InvalidKey);
    let longest_label = format!("{}.example/n", "l".repeat(63));
    assert!(parse_server_tags(&longest_label).is_ok());
    let host = |bytes: usize| {
        let mut host = String::new();
        while host.len() + 64 < bytes {
            host.push_str(&"h".repeat(63));
            host.push('.');
        }
        let rest = bytes - host.len();
        host.push_str(&"h".repeat(rest));
        host
    };
    assert!(parse_server_tags(&format!("{}/n", host(253))).is_ok());
    assert_eq!(
        tag_error(&format!("{}/n", host(254)))?,
        ServerTagError::InvalidKey
    );
    Ok(())
}

#[test]
fn tag_values_stay_raw_and_unescape_strictly() -> TestResult {
    let tags = parse_server_tags("a=x\\:y\\sz\\\\w\\r\\n;b=;c;+d=caf\u{e9}=1")?;
    let values: Vec<_> = tags.iter().map(|tag| tag.raw_value()).collect();
    assert_eq!(
        values,
        [
            Some("x\\:y\\sz\\\\w\\r\\n"),
            None,
            None,
            Some("caf\u{e9}=1")
        ]
    );
    let a = tags.get("a").ok_or("a")?;
    assert_eq!(a.unescaped_value()?.as_deref(), Some("x;y z\\w\r\n"));
    assert!(tags.get("d").is_none());
    let keys: Vec<&str> = (&tags).into_iter().map(|tag| tag.key()).collect();
    assert_eq!(keys, ["a", "b", "c", "+d"]);
    assert!(tags.get("+d").ok_or("+d")?.is_client_only());
    assert_eq!(tags.client_only_count(), 1);
    assert_eq!(unescape_server_tag_value("plain")?, "plain");
    for raw in ["a\\x", "a\\", "\\", "a\\\\\\"] {
        assert_eq!(
            unescape_server_tag_value(raw),
            Err(ServerTagError::InvalidEscape),
            "{raw}"
        );
        assert_eq!(
            tag_error(&format!("k={raw}"))?,
            ServerTagError::InvalidEscape
        );
    }
    for raw in ["a b", "a\0b", "a\rb", "a\nb"] {
        assert_eq!(
            unescape_server_tag_value(raw),
            Err(ServerTagError::InvalidValue),
            "{raw:?}"
        );
    }
    for raw in ["", ";", "a;", ";a", "a;;b"] {
        let expected = if raw.is_empty() {
            ServerTagError::EmptySection
        } else {
            ServerTagError::EmptyTag
        };
        assert_eq!(tag_error(raw)?, expected, "{raw:?}");
    }
    Ok(())
}

#[test]
fn duplicate_keys_are_found_in_small_and_large_sections() -> TestResult {
    assert_eq!(tag_error("a=1;a=2")?, ServerTagError::DuplicateKey);
    assert_eq!(parse_server_tags("a;A;+a")?.len(), 3);
    let many: Vec<String> = (0..300).map(|index| format!("k{index}")).collect();
    let mut section = many.join(";");
    assert_eq!(parse_server_tags(&section)?.len(), 300);
    section.push_str(";k299");
    assert_eq!(tag_error(&section)?, ServerTagError::DuplicateKey);
    Ok(())
}

#[test]
fn client_only_tags_keep_their_count_value_and_total_limits() -> TestResult {
    let tags = |count: usize| {
        (0..count)
            .map(|index| format!("+t{index}"))
            .collect::<Vec<_>>()
            .join(";")
    };
    assert_eq!(parse_server_tags(&tags(16))?.client_only_count(), 16);
    assert_eq!(tag_error(&tags(17))?, ServerTagError::TooManyClientOnlyTags);
    assert!(parse_server_tags(&format!("+v={}", "x".repeat(256))).is_ok());
    assert_eq!(
        tag_error(&format!("+v={}", "x".repeat(257)))?,
        ServerTagError::ClientOnlyValueTooLong
    );
    // Escapes count once decoded: 256 escaped spaces are 512 raw bytes.
    assert!(parse_server_tags(&format!("+v={}", "\\s".repeat(256))).is_ok());
    // Keys and values together: four tags of 2 + 254 decoded bytes are
    // exactly 1,024, and one more value byte is over.
    let total = |extra: usize| {
        (0..4)
            .map(|index| {
                let value = if index == 3 { 254 + extra } else { 254 };
                format!("+{index}={}", "x".repeat(value))
            })
            .collect::<Vec<_>>()
            .join(";")
    };
    assert!(parse_server_tags(&total(0)).is_ok());
    assert_eq!(
        tag_error(&total(1))?,
        ServerTagError::ClientOnlyTotalTooLong
    );
    // The E2EE carrier is exempt from both byte limits but counts as a tag.
    let e2ee = format!("+agenc.ag/e2ee={};{}", "f".repeat(3_000), tags(15));
    assert_eq!(parse_server_tags(&e2ee)?.client_only_count(), 16);
    let e2ee_over = format!("+agenc.ag/e2ee=f;{}", tags(16));
    assert_eq!(
        tag_error(&e2ee_over)?,
        ServerTagError::TooManyClientOnlyTags
    );
    // Server-added tags have no such limits.
    let server: Vec<String> = (0..40)
        .map(|index| format!("s{index}={}", "y".repeat(90)))
        .collect();
    assert_eq!(parse_server_tags(&server.join(";"))?.len(), 40);
    Ok(())
}

#[test]
fn correlation_tags_keep_their_bounds() -> TestResult {
    let tags = parse_server_tags("label=req-1_a;batch=b-9")?;
    assert_eq!(tags.label(), Some("req-1_a"));
    assert_eq!(tags.batch(), Some("b-9"));
    assert!(parse_server_tags(&format!("label={}", "l".repeat(64))).is_ok());
    assert_eq!(
        tag_error(&format!("label={}", "l".repeat(65)))?,
        ServerTagError::InvalidLabel
    );
    // An escaped backslash decodes to a byte a label may hold; an escaped
    // delimiter does not.
    assert_eq!(parse_server_tags("label=a\\\\b")?.label(), Some("a\\\\b"));
    for raw in [
        "label",
        "label=",
        "label=a\\sb",
        "label=a\\:b",
        "label=a\\rb",
        "label=a\\nb",
    ] {
        assert_eq!(tag_error(raw)?, ServerTagError::InvalidLabel, "{raw}");
    }
    assert!(parse_server_tags(&format!("batch={}", "b".repeat(64))).is_ok());
    let long_batch = format!("batch={}", "b".repeat(65));
    for raw in [
        "batch",
        "batch=a_b",
        "batch=a.b",
        "batch=a\\\\b",
        long_batch.as_str(),
    ] {
        assert_eq!(
            tag_error(raw)?,
            ServerTagError::InvalidBatchReference,
            "{raw}"
        );
    }
    // The validators: the companion safe label, and the batch reference.
    assert_eq!(validate_safe_label("a_B-9"), Ok(()));
    let long_label = "l".repeat(65);
    for raw in ["", "a b", "a\\sb", "a.b", long_label.as_str()] {
        assert_eq!(validate_safe_label(raw), Err(ServerTagError::InvalidLabel));
    }
    assert_eq!(validate_safe_label(&"l".repeat(64)), Ok(()));
    assert_eq!(validate_batch_reference("A-9"), Ok(()));
    let long_reference = "b".repeat(65);
    for raw in ["", "a_b", long_reference.as_str()] {
        assert_eq!(
            validate_batch_reference(raw),
            Err(ServerTagError::InvalidBatchReference)
        );
    }
    Ok(())
}

#[test]
fn prefixes_are_a_server_name_or_a_framed_cloaked_user() -> TestResult {
    let server_line = format!(":{SERVER} PING :x");
    let server = decode(&server_line)?;
    assert_eq!(server.prefix(), Some(ServerPrefix::Server(SERVER)));
    let user_line = format!(":{MASK} PRIVMSG #c :hi");
    let user = decode(&user_line)?;
    let Some(ServerPrefix::User(user)) = user.prefix() else {
        return Err("no user prefix".into());
    };
    assert_eq!(user.mask(), MASK);
    assert_eq!(user.nickname(), "alice");
    assert_eq!(user.user(), "u-abcdefgh23");
    assert_eq!(user.host(), "h-ijklmnopqrstuv67.invalid");
    assert_eq!(user.cloak().user_component(), b"abcdefgh23");
    assert!(decode("PING :token")?.prefix().is_none());
    for prefix in [
        "Server.Example",
        "server",
        "server..example",
        "alice!alice@host.example",
        "alice!abcdefgh23@ijklmnopqrstuv67",
        "alice!u-abcdefgh23@ijklmnopqrstuv67",
        "alice!abcdefgh23@h-ijklmnopqrstuv67.invalid",
        "alice!u-abcdefgh2@h-ijklmnopqrstuv67.invalid",
        "alice!u-ABCDEFGH23@h-ijklmnopqrstuv67.invalid",
        "alice!u-abcdefgh23@h-ijklmnopqrstuv67.example",
        "1alice!u-abcdefgh23@h-ijklmnopqrstuv67.invalid",
        "alice@h-ijklmnopqrstuv67.invalid",
        "alice!u-abcdefgh23",
    ] {
        assert_eq!(
            decode_error(&format!(":{prefix} PING :x"))?,
            ServerMessageError::InvalidPrefix,
            "{prefix}"
        );
    }
    assert_eq!(
        decode_error(&format!(":{SERVER}"))?,
        ServerMessageError::MissingCommand
    );
    Ok(())
}

#[test]
fn commands_come_from_the_closed_registries() -> TestResult {
    assert_eq!(
        decode(&format!(":{SERVER} PING :x"))?.command(),
        ServerCommand::Named("PING")
    );
    assert_eq!(
        decode(&format!(":{SERVER} 001 alice :Welcome"))?.command(),
        ServerCommand::Numeric(1)
    );
    assert_eq!(ServerCommand::Numeric(5).numeric(), Some(5));
    assert_eq!(ServerCommand::Numeric(5).name(), None);
    assert_eq!(ServerCommand::Named("JOIN").name(), Some("JOIN"));
    assert_eq!(ServerCommand::Named("JOIN").numeric(), None);
    for (command, expected) in [
        ("ping", ServerMessageError::InvalidCommand),
        ("Ping", ServerMessageError::InvalidCommand),
        ("01", ServerMessageError::InvalidCommand),
        ("0001", ServerMessageError::InvalidCommand),
        ("P1NG", ServerMessageError::InvalidCommand),
        ("STATS", ServerMessageError::UnregisteredCommand),
        ("EGROUP", ServerMessageError::UnregisteredCommand),
        ("EOBJECT", ServerMessageError::UnregisteredCommand),
        ("999", ServerMessageError::UnregisteredNumeric),
        ("000", ServerMessageError::UnregisteredNumeric),
    ] {
        assert_eq!(
            decode_error(&format!(":{SERVER} {command} alice :x"))?,
            expected,
            "{command}"
        );
    }
    for code in FORBIDDEN_NUMERICS {
        assert!(!SERVER_NUMERICS.contains(&code));
        assert_eq!(
            decode_error(&format!(":{SERVER} {code:03} alice bob :detail"))?,
            ServerMessageError::ForbiddenNumeric
        );
    }
    for code in SERVER_NUMERICS {
        let line = format!(":{SERVER} {code:03} alice :text");
        assert_eq!(decode(&line)?.command(), ServerCommand::Numeric(*code));
    }
    Ok(())
}

#[test]
fn spacing_is_single_and_parameters_are_at_most_fifteen() -> TestResult {
    for line in [
        format!(" :{SERVER} PING :x"),
        format!(":{SERVER}  PING :x"),
        format!("@a  :{SERVER} PING :x"),
    ] {
        assert_eq!(
            decode_error(&line)?,
            ServerMessageError::MissingCommand,
            "{line:?}"
        );
    }
    for line in [
        format!(":{SERVER} JOIN #c "),
        format!(":{SERVER} JOIN  #c"),
        format!(":{SERVER} MODE #c  +t"),
    ] {
        assert_eq!(
            decode_error(&line)?,
            ServerMessageError::EmptyParameter,
            "{line:?}"
        );
    }
    assert_eq!(decode_error("@a=1")?, ServerMessageError::UnterminatedTags);
    let empty_trailing = format!(":{SERVER} 302 alice :");
    let message = decode(&empty_trailing)?;
    assert_eq!(message.params().trailing(), Some(""));
    assert_eq!(message.params().middle(), ["alice"]);
    let bare_line = format!(":{SERVER} ACK");
    let bare = decode(&bare_line)?;
    assert!(bare.params().is_empty());
    assert_eq!(bare.params().trailing(), None);

    let middles = |count: usize| {
        (0..count)
            .map(|index| format!("m{index}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let fourteen_line = format!(":{SERVER} NOTICE {} :t", middles(14));
    let fourteen = decode(&fourteen_line)?;
    assert_eq!(fourteen.params().len(), 15);
    assert_eq!(fourteen.params().all().len(), 15);
    assert_eq!(fourteen.params().middle().len(), 14);
    assert_eq!(
        decode(&format!(":{SERVER} NOTICE {}", middles(15)))?
            .params()
            .len(),
        15
    );
    assert_eq!(
        decode_error(&format!(":{SERVER} NOTICE {} :t", middles(15)))?,
        ServerMessageError::TooManyParameters
    );
    assert_eq!(
        decode_error(&format!(":{SERVER} NOTICE {}", middles(16)))?,
        ServerMessageError::TooManyParameters
    );
    Ok(())
}

#[test]
fn standard_replies_keep_their_frame_and_closed_codes() -> TestResult {
    for line in [
        "FAIL PRIVMSG INVALID_ARGUMENT :Invalid argument",
        "FAIL JOIN E2EE_REQUIRED #c :Encryption is required",
        "NOTE * RECOVERY_EPOCH AAAAAAAAAAAAAAAAAAAAAA :Current server recovery identity",
        "WARN * SLOW_CONSUMER :Output queue nearing capacity",
        "FAIL EGROUP E2EE_SYNCING :federation route state is not active",
    ] {
        assert!(decode(&format!(":{SERVER} {line}")).is_ok(), "{line}");
    }
    for (line, expected) in [
        ("FAIL :text", ServerMessageError::MalformedStandardReply),
        (
            "FAIL PRIVMSG :text",
            ServerMessageError::MalformedStandardReply,
        ),
        (
            "FAIL PRIVMSG INVALID_ARGUMENT",
            ServerMessageError::MalformedStandardReply,
        ),
        (
            "NOTE * RECOVERY_EPOCH AAAA",
            ServerMessageError::MalformedStandardReply,
        ),
        (
            "FAIL PRIVMSG invalid_argument :x",
            ServerMessageError::InvalidReplyCode,
        ),
        (
            "FAIL PRIVMSG INVALID-ARGUMENT :x",
            ServerMessageError::InvalidReplyCode,
        ),
        (
            "FAIL PRIVMSG MADE_UP :x",
            ServerMessageError::UnregisteredReplyCode,
        ),
        (
            "FAIL EGROUP E2EE_ROUTE_INVALID :x",
            ServerMessageError::UnregisteredReplyCode,
        ),
        (
            "NOTE * SLOW_CONSUMER :x",
            ServerMessageError::InapplicableReplyCode,
        ),
        (
            "WARN PRIVMSG SLOW_CONSUMER :x",
            ServerMessageError::InapplicableReplyCode,
        ),
        (
            "FAIL * SLOW_CONSUMER :x",
            ServerMessageError::InapplicableReplyCode,
        ),
    ] {
        assert_eq!(
            decode_error(&format!(":{SERVER} {line}"))?,
            expected,
            "{line}"
        );
    }
    for code in ADMIN_ONLY_REPLY_CODES {
        assert!(STANDARD_REPLY_CODES.contains(&code));
        assert_eq!(
            decode_error(&format!(":{SERVER} NOTE * {code} :x"))?,
            ServerMessageError::InapplicableReplyCode
        );
    }
    assert!(STANDARD_REPLY_CODES.contains(&"SLOW_CONSUMER"));
    let longest = format!(":{SERVER} FAIL * {} :x", "C".repeat(65));
    assert_eq!(
        decode_error(&longest)?,
        ServerMessageError::InvalidReplyCode
    );
    Ok(())
}

#[test]
fn client_only_tags_ride_only_the_relaying_commands() -> TestResult {
    for command in ["PRIVMSG #c :hi", "NOTICE #c :hi", "TAGMSG #c"] {
        let line = format!("@+typing=active;msgid=m :{MASK} {command}");
        let message = decode(&line)?;
        assert_eq!(message.tags().client_only_count(), 1);
    }
    for line in [
        format!("@+typing=active :{SERVER} 001 alice :Welcome"),
        format!("@+typing=active :{MASK} JOIN #c"),
        format!("@+x :{SERVER} FAIL PRIVMSG INVALID_ARGUMENT :x"),
    ] {
        assert_eq!(
            decode_error(&line)?,
            ServerMessageError::MisplacedClientOnlyTag,
            "{line}"
        );
    }
    assert!(decode(&format!("@msgid=m;time=t :{MASK} JOIN #c")).is_ok());
    Ok(())
}

/// A prefix's server name and nickname follow the shared types' grammars,
/// which own them (`ServerName`, `Nickname`): the decoder accepts exactly
/// the names they accept.
#[test]
fn prefix_names_follow_the_shared_name_grammars() -> TestResult {
    let long_label = format!("{}.example", "l".repeat(63));
    let too_long_label = format!("{}.example", "l".repeat(64));
    let longest = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let too_long = format!("{longest}d");
    let server_names = [
        "server.example",
        "a.b",
        "x-1.example",
        "192.0.2.1",
        "server",
        "Server.example",
        "-a.example",
        "a-.example",
        "a..example",
        ".example",
        "example.",
        "s_v.example",
        long_label.as_str(),
        too_long_label.as_str(),
        longest.as_str(),
        too_long.as_str(),
    ];
    for name in server_names {
        let line = format!(":{name} PING :x");
        let decoded = parse_server_message(ServerFramedLine::new(&line)?);
        assert_eq!(decoded.is_ok(), ServerName::parse(name).is_ok(), "{name}");
    }
    let longest_nickname = "n".repeat(32);
    let too_long_nickname = "n".repeat(33);
    let nicknames = [
        "alice",
        "_a",
        "a-b_c9",
        "A",
        "9a",
        "-a",
        "a.b",
        "caf\u{e9}",
        longest_nickname.as_str(),
        too_long_nickname.as_str(),
    ];
    for nickname in nicknames {
        let line = format!(":{nickname}!u-abcdefgh23@h-ijklmnopqrstuv67.invalid PRIVMSG #c :x");
        let decoded = parse_server_message(ServerFramedLine::new(&line)?);
        assert_eq!(
            decoded.is_ok(),
            Nickname::parse(nickname).is_ok(),
            "{nickname}"
        );
    }
    Ok(())
}
