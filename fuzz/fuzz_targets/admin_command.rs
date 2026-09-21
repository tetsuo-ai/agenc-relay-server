#![no_main]
#![forbid(unsafe_code)]

//! Stage 06 administrative line fuzzing: the tag parser, the canonical-form
//! check, and the closed command registry must be total over arbitrary bytes,
//! and an accepted tag must re-render to the exact bytes it was parsed from.

use agenc_relay_admin::{
    AdminCommand, CanonicalCommand, MAX_ADMIN_LINE_BYTES, parse_admin_line, render_admin_tag,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_ADMIN_LINE_BYTES + 16 {
        return;
    }
    let Ok(mut line) = parse_admin_line(data) else {
        return;
    };
    let confirmation = line.take_confirmation();
    let rendered = render_admin_tag(line.counter(), &line.signature(), confirmation.as_ref());
    let tag_end = data
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(data.len());
    assert_eq!(
        data.get(..tag_end),
        Some(rendered.as_bytes()),
        "an accepted admin tag must re-render to its own bytes"
    );
    let Ok(canonical) = CanonicalCommand::check(line.command()) else {
        return;
    };
    let _ = AdminCommand::parse(canonical);
});
