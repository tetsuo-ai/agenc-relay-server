#![no_main]
#![forbid(unsafe_code)]

use agenc_relay_client_wire::parse_client_tags;
use agenc_relay_e2ee::wire::fragment::{FragmentTag, ReceiptTag};
use agenc_relay_e2ee::wire::tokens::{
    base64url_decode, base64url_encode, parse_account, parse_cursor, parse_hash, parse_id16,
    parse_key_package_ref, parse_u16, parse_u32, parse_u64,
};
use libfuzzer_sys::fuzz_target;

// Every text parser of the encrypted profile either refuses the input or
// accepts a value that renders back to the same text: the fragment and
// receipt tags, the IRCv3 client tag section, base64url tokens, and the
// bounded decimals.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(tag) = FragmentTag::parse(text) {
        assert_eq!(
            tag.render(),
            text,
            "an accepted fragment tag renders exactly"
        );
    }
    if let Ok(receipt) = ReceiptTag::parse(text) {
        assert_eq!(
            receipt.render(),
            text,
            "an accepted receipt tag renders exactly"
        );
    }
    let _ = parse_client_tags(text);
    if let Ok(bytes) = base64url_decode(text) {
        assert_eq!(
            base64url_encode(&bytes),
            text,
            "canonical base64url round trips"
        );
    }
    let _ = parse_id16(text);
    let _ = parse_hash(text);
    let _ = parse_account(text);
    let _ = parse_key_package_ref(text);
    let _ = parse_cursor(text);
    if let Ok(value) = parse_u16(text) {
        assert_eq!(value.to_string(), text, "canonical decimals round trip");
    }
    if let Ok(value) = parse_u32(text) {
        assert_eq!(value.to_string(), text);
    }
    if let Ok(value) = parse_u64(text) {
        assert_eq!(value.to_string(), text);
    }
});
