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

/// Returns whether a command may relay validated client-only tags.
#[must_use]
pub fn relays_client_only_tags(command: &str) -> bool {
    matches!(command, "PRIVMSG" | "NOTICE" | "TAGMSG")
}
