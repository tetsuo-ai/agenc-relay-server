#![no_main]
#![forbid(unsafe_code)]

use agenc_relay_e2ee::DecodeBudget;
use agenc_relay_e2ee::mls_outer::{
    MlsOuterMessage, parse_mls_message, verify_key_package_signatures,
};
use libfuzzer_sys::fuzz_target;

const BUDGET_BYTES: usize = 8 * 1024 * 1024;
const BUDGET_VALUES: usize = 1_000_000;

// Outer MLS framing never panics, never reads past its input, and a parsed
// KeyPackage can always be offered to signature verification.
fuzz_target!(|data: &[u8]| {
    let mut budget = DecodeBudget::new(BUDGET_BYTES, BUDGET_VALUES);
    let Ok(message) = parse_mls_message(data, &mut budget) else {
        return;
    };
    match message {
        MlsOuterMessage::Private(header) => {
            assert!(header.authenticated_data.len() <= data.len());
            assert!(header.ciphertext_len <= data.len());
        }
        MlsOuterMessage::Welcome(header) => {
            assert!(header.new_member_refs.len() <= data.len());
        }
        MlsOuterMessage::KeyPackage(package) => {
            assert!(package.tbs.len() <= data.len());
            assert!(package.leaf_node.tbs.len() <= package.tbs.len());
            let _ = package.has_last_resort_extension();
            let _ = verify_key_package_signatures(&package);
        }
    }
});
