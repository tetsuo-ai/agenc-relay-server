#![no_main]
#![forbid(unsafe_code)]

//! Placeholder for the Stage 06 configuration document fuzz target.
//!
//! The config fork replaces this body with the strict document parser
//! harness once `agenc_ircd_config::Config::parse_text` exists.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = agenc_ircd_config::load_maintenance_config;
    let _ = data;
});
