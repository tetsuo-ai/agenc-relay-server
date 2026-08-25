#![forbid(unsafe_code)]

//! Bounded client framing, parsing, and rendering.
//!
//! Functional wire behavior begins in Stage 01. Stage 00 defines only this
//! ownership boundary.

mod text;

pub use text::{
    CanonicalBase64Url, E2EE_OBJECT_KINDS, E2eeFragment, E2eeObjectKind, E2eeRequestCommand,
    ExactArity, MAX_E2EE_FRAGMENT_BYTES, MAX_E2EE_FRAGMENT_COUNT, MAX_E2EE_OBJECT_BYTES,
    MailboxKind, SafeLabel, TextCarrierError, parse_u16_decimal, parse_u32_decimal,
    parse_u64_decimal, validate_uppercase_token,
};
