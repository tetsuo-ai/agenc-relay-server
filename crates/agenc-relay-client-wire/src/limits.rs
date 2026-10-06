//! Closed client-wire resource and framing limits.

/// Traditional IRC message bytes including the terminating CRLF.
pub const MAX_TRADITIONAL_LINE_BYTES: usize = 512;
/// Version-1 command bytes without the terminating CRLF.
///
/// Tags and command bytes still share the complete physical-message budget.
pub const MAX_COMMAND_BYTES: usize = 8_701;
/// Client-provided tag data bytes, excluding `@` and the trailing space.
pub const MAX_CLIENT_TAG_DATA_BYTES: usize = 4_094;
/// Server-provided tag data bytes, excluding `@` and the trailing space.
pub const MAX_SERVER_TAG_DATA_BYTES: usize = 4_094;
/// Combined tag section bytes, including `@` and the trailing space.
pub const MAX_COMBINED_TAG_SECTION_BYTES: usize = 8_191;
/// Complete tagged stream message bytes, including CRLF.
pub const MAX_PHYSICAL_LINE_BYTES: usize = 8_703;
/// Complete WebSocket protocol-message bytes, which omit CRLF.
pub const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 8_701;
/// Maximum parsed IRC parameters, including a trailing parameter.
pub const MAX_PARAMETERS: usize = 15;
/// Maximum number of client-only tags admitted on one client message.
pub const MAX_CLIENT_ONLY_TAGS: usize = 16;
/// Maximum decoded bytes in an ordinary client-only tag value.
pub const MAX_CLIENT_ONLY_VALUE_BYTES: usize = 256;
/// Maximum decoded bytes across ordinary client-only tag keys and values.
pub const MAX_CLIENT_ONLY_TOTAL_BYTES: usize = 1_024;
/// Maximum `label` or `batch` reference bytes.
pub const MAX_CORRELATION_TAG_BYTES: usize = 64;

/// Appendix A.1 `PASS` on a listener without a configured access token: one
/// ignored token of at most this many bytes.
pub const MAX_COMPATIBILITY_PASS_BYTES: usize = 256;
/// Appendix A.1 `PASS` on a listener with a configured access token: exactly
/// one canonical unpadded base64url token of this many characters.
pub const CONFIGURED_PASS_CHARACTERS: usize = 43;
/// Appendix A.1 `QUIT`: an optional trailing reason of at most this many bytes.
pub const MAX_QUIT_REASON_BYTES: usize = 256;
/// Appendix A.1 `PING` and `PONG`: one token of at most this many bytes.
pub const MAX_PING_PONG_BYTES: usize = 64;
/// `USER` real name bytes, counted without control characters.
pub const MAX_REALNAME_BYTES: usize = 64;
/// `AUTHENTICATE` mechanism name bytes.
pub const MAX_SASL_MECHANISM_BYTES: usize = 20;
/// Channel name bytes.
pub const MAX_CHANNEL_BYTES: usize = 64;
/// Nickname bytes.
pub const MAX_NICKNAME_BYTES: usize = 32;
/// Bytes of the local server name an information query may name.
pub const MAX_SERVER_NAME_BYTES: usize = 253;
/// Appendix A.1 `csv(channel,20)` and `csv(key,20)` of `JOIN`, `PART`,
/// `NAMES` and `LIST`.
pub const MAX_CHANNEL_TARGETS: usize = 20;
/// Appendix A.1 `csv(target,4)` of `PRIVMSG` and `NOTICE`.
pub const MAX_MESSAGE_TARGETS: usize = 4;
/// Appendix A.1 `csv(nickname,4)` of `KICK`.
pub const MAX_KICK_TARGETS: usize = 4;
/// Appendix A.1 `MODE`: at most this many changes.
pub const MAX_MODE_CHANGES: usize = 6;
/// Fewest bytes of a channel key.
pub const MIN_CHANNEL_KEY_BYTES: usize = 8;
/// Most bytes of a channel key.
pub const MAX_CHANNEL_KEY_BYTES: usize = 256;
/// Appendix A.1 `PART` and `KICK` reasons and `AWAY` text: at most this many
/// bytes.
pub const MAX_PART_KICK_AWAY_BYTES: usize = 256;
/// `TOPIC` text bytes.
pub const MAX_TOPIC_BYTES: usize = 1_024;
/// `PRIVMSG` and `NOTICE` body bytes.
pub const MAX_MESSAGE_BODY_BYTES: usize = 512;
/// Appendix A.1 `WHOWAS`: the optional count is 1 through this value.
pub const MAX_WHOWAS_COUNT: u64 = 10;
/// Appendix A.1 `ISON`: 1 through this many nickname parameters, inside the
/// global 15-parameter budget.
pub const MAX_ISON_NICKNAMES: usize = 20;
/// Appendix A.1 `USERHOST`: 1 through this many nickname parameters.
pub const MAX_USERHOST_NICKNAMES: usize = 5;
/// Appendix A.1 `MONITOR +` and `MONITOR -`: `csv(nickname,20)`.
pub const MAX_MONITOR_NICKNAMES: usize = 20;
/// `CHATHISTORY` limit: 1 through this value.
pub const MAX_HISTORY_LIMIT: u64 = 100;

/// Returns whether a command may relay validated client-only tags.
#[must_use]
pub fn relays_client_only_tags(command: &str) -> bool {
    matches!(command, "PRIVMSG" | "NOTICE" | "TAGMSG")
}
