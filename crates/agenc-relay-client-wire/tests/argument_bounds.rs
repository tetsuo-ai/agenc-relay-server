//! The public Appendix A.1 argument bounds are the values the client-input
//! parser enforces: each is accepted at its exact value and refused one over.

#![forbid(unsafe_code)]

use std::error::Error;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use agenc_relay_client_wire::{
    AccessTokenPolicy, CONFIGURED_PASS_CHARACTERS, FramedLine, MAX_CHANNEL_BYTES,
    MAX_CHANNEL_KEY_BYTES, MAX_CHANNEL_TARGETS, MAX_COMPATIBILITY_PASS_BYTES, MAX_HISTORY_LIMIT,
    MAX_ISON_NICKNAMES, MAX_KICK_TARGETS, MAX_MESSAGE_BODY_BYTES, MAX_MESSAGE_TARGETS,
    MAX_MODE_CHANGES, MAX_MONITOR_NICKNAMES, MAX_NICKNAME_BYTES, MAX_PARAMETERS,
    MAX_PART_KICK_AWAY_BYTES, MAX_PING_PONG_BYTES, MAX_QUIT_REASON_BYTES, MAX_REALNAME_BYTES,
    MAX_SASL_MECHANISM_BYTES, MAX_SERVER_NAME_BYTES, MAX_TOPIC_BYTES, MAX_USERHOST_NICKNAMES,
    MAX_WHOWAS_COUNT, MIN_CHANNEL_KEY_BYTES, ParsedMessage, parse_message,
    parse_registration_command, validate_post_registration_command,
};

type TestResult = Result<(), Box<dyn Error>>;

fn parsed(line: &str) -> Result<ParsedMessage, Box<dyn Error>> {
    parse_message(FramedLine::new(line)?)?.ok_or_else(|| "empty line".into())
}

/// Whether the registration grammar accepts the line under `policy`.
fn registration_accepts(line: &str, policy: AccessTokenPolicy) -> Result<bool, Box<dyn Error>> {
    Ok(parse_registration_command(&parsed(line)?, policy).is_ok())
}

/// Whether the registered-command grammar accepts the line.
fn registered_accepts(line: &str) -> Result<bool, Box<dyn Error>> {
    Ok(validate_post_registration_command(&parsed(line)?).is_ok())
}

/// Requires `at` to be accepted and `over` refused by `accepts`.
fn boundary(
    name: &str,
    accepts: impl Fn(&str) -> Result<bool, Box<dyn Error>>,
    at: &str,
    over: &str,
) -> TestResult {
    assert!(accepts(at)?, "{name}: the exact bound was refused");
    assert!(!accepts(over)?, "{name}: one over the bound was accepted");
    Ok(())
}

fn compatibility(line: &str) -> Result<bool, Box<dyn Error>> {
    registration_accepts(line, AccessTokenPolicy::IgnoreCompatibilityPass)
}

fn nicknames(count: usize, separator: &str) -> String {
    (0..count)
        .map(|index| format!("n{index}"))
        .collect::<Vec<_>>()
        .join(separator)
}

fn channels(count: usize) -> String {
    (0..count)
        .map(|index| format!("#c{index}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn registration_argument_bounds_hold_at_the_exact_value() -> TestResult {
    boundary(
        "PASS",
        compatibility,
        &format!("PASS {}", "p".repeat(MAX_COMPATIBILITY_PASS_BYTES)),
        &format!("PASS {}", "p".repeat(MAX_COMPATIBILITY_PASS_BYTES + 1)),
    )?;
    let token = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    assert_eq!(token.len(), CONFIGURED_PASS_CHARACTERS);
    let configured =
        |line: &str| registration_accepts(line, AccessTokenPolicy::RequireConfiguredToken);
    boundary(
        "configured PASS",
        configured,
        &format!("PASS {token}"),
        &format!("PASS {token}A"),
    )?;
    boundary(
        "QUIT",
        compatibility,
        &format!("QUIT :{}", "q".repeat(MAX_QUIT_REASON_BYTES)),
        &format!("QUIT :{}", "q".repeat(MAX_QUIT_REASON_BYTES + 1)),
    )?;
    boundary(
        "PING",
        compatibility,
        &format!("PING {}", "t".repeat(MAX_PING_PONG_BYTES)),
        &format!("PING {}", "t".repeat(MAX_PING_PONG_BYTES + 1)),
    )?;
    boundary(
        "PONG",
        compatibility,
        &format!("PONG :{}", "t".repeat(MAX_PING_PONG_BYTES)),
        &format!("PONG :{}", "t".repeat(MAX_PING_PONG_BYTES + 1)),
    )?;
    boundary(
        "USER real name",
        compatibility,
        &format!("USER u 0 * :{}", "r".repeat(MAX_REALNAME_BYTES)),
        &format!("USER u 0 * :{}", "r".repeat(MAX_REALNAME_BYTES + 1)),
    )?;
    boundary(
        "AUTHENTICATE mechanism",
        compatibility,
        &format!("AUTHENTICATE {}", "M".repeat(MAX_SASL_MECHANISM_BYTES)),
        &format!("AUTHENTICATE {}", "M".repeat(MAX_SASL_MECHANISM_BYTES + 1)),
    )?;
    boundary(
        "NICK",
        compatibility,
        &format!("NICK {}", "n".repeat(MAX_NICKNAME_BYTES)),
        &format!("NICK {}", "n".repeat(MAX_NICKNAME_BYTES + 1)),
    )
}

#[test]
fn channel_and_target_bounds_hold_at_the_exact_value() -> TestResult {
    let channel = format!("#{}", "c".repeat(MAX_CHANNEL_BYTES - 1));
    boundary(
        "channel name",
        registered_accepts,
        &format!("JOIN {channel}"),
        &format!("JOIN {channel}c"),
    )?;
    for command in ["JOIN", "PART", "NAMES", "LIST"] {
        boundary(
            command,
            registered_accepts,
            &format!("{command} {}", channels(MAX_CHANNEL_TARGETS)),
            &format!("{command} {}", channels(MAX_CHANNEL_TARGETS + 1)),
        )?;
    }
    // Distinct keys of the shortest length: a csv list never repeats a value.
    let keys = |count: usize| {
        (0..count)
            .map(|index| format!("key{index:05}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    assert_eq!(keys(1).len(), MIN_CHANNEL_KEY_BYTES);
    boundary(
        "JOIN keys",
        registered_accepts,
        &format!(
            "JOIN {} {}",
            channels(MAX_CHANNEL_TARGETS),
            keys(MAX_CHANNEL_TARGETS)
        ),
        &format!(
            "JOIN {} {}",
            channels(MAX_CHANNEL_TARGETS),
            keys(MAX_CHANNEL_TARGETS + 1)
        ),
    )?;
    boundary(
        "shortest key",
        registered_accepts,
        &format!("JOIN #c {}", "k".repeat(MIN_CHANNEL_KEY_BYTES)),
        &format!("JOIN #c {}", "k".repeat(MIN_CHANNEL_KEY_BYTES - 1)),
    )?;
    boundary(
        "longest key",
        registered_accepts,
        &format!("JOIN #c {}", "k".repeat(MAX_CHANNEL_KEY_BYTES)),
        &format!("JOIN #c {}", "k".repeat(MAX_CHANNEL_KEY_BYTES + 1)),
    )?;
    boundary(
        "PRIVMSG targets",
        registered_accepts,
        &format!("PRIVMSG {} :hi", nicknames(MAX_MESSAGE_TARGETS, ",")),
        &format!("PRIVMSG {} :hi", nicknames(MAX_MESSAGE_TARGETS + 1, ",")),
    )?;
    boundary(
        "KICK targets",
        registered_accepts,
        &format!("KICK #c {}", nicknames(MAX_KICK_TARGETS, ",")),
        &format!("KICK #c {}", nicknames(MAX_KICK_TARGETS + 1, ",")),
    )?;
    boundary(
        "MONITOR",
        registered_accepts,
        &format!("MONITOR + {}", nicknames(MAX_MONITOR_NICKNAMES, ",")),
        &format!("MONITOR + {}", nicknames(MAX_MONITOR_NICKNAMES + 1, ",")),
    )?;
    let modes = |count: usize| format!("MODE #c +{}", "t".repeat(count));
    boundary(
        "MODE changes",
        registered_accepts,
        &modes(MAX_MODE_CHANGES),
        &modes(MAX_MODE_CHANGES + 1),
    )
}

#[test]
fn text_and_count_bounds_hold_at_the_exact_value() -> TestResult {
    for (command, bound) in [
        ("PRIVMSG #c", MAX_MESSAGE_BODY_BYTES),
        ("NOTICE #c", MAX_MESSAGE_BODY_BYTES),
        ("TOPIC #c", MAX_TOPIC_BYTES),
        ("PART #c", MAX_PART_KICK_AWAY_BYTES),
        ("KICK #c n", MAX_PART_KICK_AWAY_BYTES),
        ("AWAY", MAX_PART_KICK_AWAY_BYTES),
    ] {
        boundary(
            command,
            registered_accepts,
            &format!("{command} :{}", "x".repeat(bound)),
            &format!("{command} :{}", "x".repeat(bound + 1)),
        )?;
    }
    boundary(
        "WHOWAS count",
        registered_accepts,
        &format!("WHOWAS n {MAX_WHOWAS_COUNT}"),
        &format!("WHOWAS n {}", MAX_WHOWAS_COUNT + 1),
    )?;
    boundary(
        "USERHOST",
        registered_accepts,
        &format!("USERHOST {}", nicknames(MAX_USERHOST_NICKNAMES, " ")),
        &format!("USERHOST {}", nicknames(MAX_USERHOST_NICKNAMES + 1, " ")),
    )?;
    // ISON allows 20 nicknames, but the global parameter budget reaches
    // first: 15 parameters are accepted, and a 16th never parses as a line.
    const { assert!(MAX_ISON_NICKNAMES > MAX_PARAMETERS) };
    assert!(registered_accepts(&format!(
        "ISON {}",
        nicknames(MAX_PARAMETERS, " ")
    ))?);
    assert!(
        parse_message(FramedLine::new(&format!(
            "ISON {}",
            nicknames(MAX_PARAMETERS + 1, " ")
        ))?)
        .is_err()
    );
    boundary(
        "server name",
        registered_accepts,
        &format!("MOTD {}", server_name(MAX_SERVER_NAME_BYTES)),
        &format!("MOTD {}", server_name(MAX_SERVER_NAME_BYTES + 1)),
    )?;
    boundary(
        "CHATHISTORY limit",
        registered_accepts,
        &format!("CHATHISTORY LATEST #c * {MAX_HISTORY_LIMIT}"),
        &format!("CHATHISTORY LATEST #c * {}", MAX_HISTORY_LIMIT + 1),
    )
}

/// A dotted DNS-shaped name of exactly `bytes` bytes: full 63-byte labels,
/// then one shorter final label.
fn server_name(bytes: usize) -> String {
    let mut name = String::new();
    while name.len() + 64 < bytes {
        name.push_str(&"a".repeat(63));
        name.push('.');
    }
    let rest = bytes - name.len();
    name.push_str(&"b".repeat(rest));
    name
}
