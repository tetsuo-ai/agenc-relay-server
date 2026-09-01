//! Section 22.4 framing ceilings for administrative input and output.

/// Bytes from `@` through the tag-separating SPACE, inclusive (spec 4429).
pub const MAX_ADMIN_TAG_PREFIX_BYTES: usize = 512;
/// Command bytes after the tag section, without CRLF (spec 4430).
pub const MAX_ADMIN_COMMAND_BYTES: usize = 4_096;
/// A complete administrative input line including CRLF (spec 4430).
pub const MAX_ADMIN_LINE_BYTES: usize = 4_610;
/// Server output keeps the Section 9 physical ceiling so an audit line fits
/// (spec 4431-4432).
pub const MAX_ADMIN_OUTPUT_LINE_BYTES: usize = 8_703;
/// Combined event and checkpoint records one `AUDIT EXPORT` may return
/// (spec 4460-4461).
pub const MAX_AUDIT_EXPORT_RECORDS: usize = 10_000;
/// Bytes one `AUDIT EXPORT` may return (spec 4461).
pub const MAX_AUDIT_EXPORT_BYTES: u64 = 67_108_864;
/// Bounded pre-authentication liveness budget: Section 22.4 permits only
/// "bounded PING/PONG" before OPER, and this crate fixes the bound.
pub const MAX_PRE_AUTH_PINGS: u8 = 8;

#[cfg(test)]
mod tests {
    use super::{MAX_ADMIN_COMMAND_BYTES, MAX_ADMIN_LINE_BYTES, MAX_ADMIN_TAG_PREFIX_BYTES};

    #[test]
    fn the_three_input_bounds_compose_exactly() {
        assert_eq!(
            MAX_ADMIN_TAG_PREFIX_BYTES + MAX_ADMIN_COMMAND_BYTES + 2,
            MAX_ADMIN_LINE_BYTES
        );
    }
}
