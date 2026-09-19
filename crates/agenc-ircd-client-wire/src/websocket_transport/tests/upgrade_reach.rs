//! Every request-line, header-field, host, key and token rule of the
//! WebSocket upgrade parser, one violation at a time.
#![forbid(unsafe_code)]

use super::*;

const HOST: &str = "Host: example.org";
const UPGRADE: &str = "Upgrade: websocket";
const CONNECTION: &str = "Connection: Upgrade";
const KEY: &str = "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==";
const VERSION: &str = "Sec-WebSocket-Version: 13";
const PROTOCOL: &str = "Sec-WebSocket-Protocol: text.ircv3.net";

fn request(headers: &[&str]) -> Vec<u8> {
    let mut bytes = b"GET /irc HTTP/1.1\r\n".to_vec();
    for header in headers.iter().chain(&[PROTOCOL]) {
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes
}

fn outcome(input: &[u8]) -> Result<bool, UpgradeError> {
    parse_upgrade(input).map(|request| request.is_some())
}

#[test]
fn complete_requests_parse_and_tolerate_tabs_and_trailing_blanks() -> Result<(), UpgradeError> {
    assert!(outcome(&request(&[
        HOST, UPGRADE, CONNECTION, KEY, VERSION
    ]))?);
    assert!(outcome(&request(&[
        HOST,
        "Upgrade: websocket   ",
        "Connection: keep-alive, Upgrade",
        KEY,
        VERSION,
        "X-Note:\ta\tb"
    ]))?);
    Ok(())
}

#[test]
fn request_lines_are_bounded_and_exact() {
    let mut long = b"GET /irc HTTP/1.1 ".to_vec();
    long.extend(std::iter::repeat_n(b'x', REQUEST_LINE_BYTES + 10));
    long.extend_from_slice(b"\r\n\r\n");
    assert_eq!(outcome(&long), Err(UpgradeError::RequestLine));
    assert_eq!(
        outcome(b"GET /irc HTTP/1.1 extra\r\n\r\n"),
        Err(UpgradeError::Malformed)
    );
}

#[test]
fn header_lines_are_bounded_even_before_their_line_end() {
    let mut partial = b"GET /irc HTTP/1.1\r\nX: ".to_vec();
    partial.extend(std::iter::repeat_n(b'a', HEADER_LINE_BYTES + 10));
    assert_eq!(outcome(&partial), Err(UpgradeError::Headers));
}

#[test]
fn every_required_field_is_checked() {
    assert_eq!(
        outcome(&request(&[UPGRADE, CONNECTION, KEY, VERSION])),
        Err(UpgradeError::Malformed)
    );
    assert_eq!(
        outcome(&request(&[HOST, CONNECTION, KEY, VERSION])),
        Err(UpgradeError::Malformed)
    );
    assert_eq!(
        outcome(&request(&[HOST, UPGRADE, KEY, VERSION])),
        Err(UpgradeError::Malformed)
    );
    assert_eq!(
        outcome(&request(&[HOST, UPGRADE, CONNECTION, KEY])),
        Err(UpgradeError::Version)
    );
}

#[test]
fn hosts_follow_the_name_grammar() {
    let long_name = format!("Host: {}", "a".repeat(254));
    let long_label = format!("Host: {}.org", "a".repeat(64));
    for host in [
        "Host: :80",
        long_name.as_str(),
        long_label.as_str(),
        "Host: -bad.org",
    ] {
        assert_eq!(
            outcome(&request(&[host, UPGRADE, CONNECTION, KEY, VERSION])),
            Err(UpgradeError::Malformed),
            "{host}"
        );
    }
}

#[test]
fn keys_must_decode_to_sixteen_bytes() {
    assert_eq!(
        outcome(&request(&[
            HOST,
            UPGRADE,
            CONNECTION,
            "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAAAA",
            VERSION
        ])),
        Err(UpgradeError::Malformed)
    );
}

#[test]
fn header_names_values_and_token_lists_are_checked() {
    for header in [
        ": value",
        "Na me: value",
        "X-Note: a\u{1}b",
        "X-Note: a\u{7f}b",
        "Connection: upgrade,,",
        "Connection: up@grade",
    ] {
        assert_eq!(
            outcome(&request(&[HOST, UPGRADE, CONNECTION, KEY, VERSION, header])),
            Err(UpgradeError::Malformed),
            "{header:?}"
        );
    }
}
