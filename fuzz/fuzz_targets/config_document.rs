#![no_main]
#![forbid(unsafe_code)]

//! Stage 06 configuration document fuzz target.
//!
//! The strict parser must be total over arbitrary bytes: it never panics, and any
//! document it accepts re-parses to an identical typed configuration.

use agenc_relay_config::{Config, PathResolver, ValidationDepth};
use libfuzzer_sys::fuzz_target;

/// The fuzz harness admits at most 64 KiB, well inside the 1 MiB file ceiling.
const MAX_INPUT_BYTES: usize = 65_536;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let resolver = PathResolver::none();
    let first = Config::parse_text(text, &resolver, ValidationDepth::Document);
    let second = Config::parse_text(text, &resolver, ValidationDepth::Document);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "parse outcome is not deterministic"
    );
    if let (Ok(first), Ok(second)) = (first, second) {
        assert_eq!(
            first, second,
            "accepted document did not re-parse identically"
        );
    }
});
