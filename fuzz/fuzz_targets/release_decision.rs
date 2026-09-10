#![no_main]
#![forbid(unsafe_code)]

//! Stage 10 release decision document fuzz target.
//!
//! The canonical JSON reader and the PEM trust-anchor reader must be total
//! over arbitrary bytes: they never panic, and any document they accept
//! re-parses to an identical typed decision.

use agenc_ircd_config::{ReleaseDecisionDocument, parse_release_public_key_pem};
use libfuzzer_sys::fuzz_target;

/// One byte beyond the reader's own ceiling, so the limit itself is exercised.
const MAX_INPUT_BYTES: usize = 65_537;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let first = ReleaseDecisionDocument::parse(data);
    let second = ReleaseDecisionDocument::parse(data);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "parse outcome is not deterministic"
    );
    if let (Ok(first), Ok(second)) = (first, second) {
        assert!(
            first == second,
            "accepted decision did not re-parse identically"
        );
        assert!(!first.claims.is_empty());
        assert_eq!(first.artifacts.len(), first.targets.len());
    }
    let _anchor = parse_release_public_key_pem(data);
});
