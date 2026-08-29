#![no_main]
#![forbid(unsafe_code)]

//! Placeholder for the Stage 06 administrative command fuzz target.
//!
//! The admin fork replaces this body with the total bounded line parser
//! harness once `agenc_ircd_admin` exposes it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = agenc_ircd_types::AdminPermission::parse;
    let _ = data;
});
