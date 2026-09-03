#![forbid(unsafe_code)]

//! Canonical wire tokens.

use super::*;

#[test]
fn base64url_round_trips_and_matches_known_vectors() -> Result<(), E2eeError> {
    let vectors: [(&[u8], &str); 6] = [
        (b"", ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg"),
        (&[0xff, 0xff], "__8"),
    ];
    for (bytes, text) in vectors {
        assert_eq!(base64url_encode(bytes), text);
        assert_eq!(base64url_decode(text)?, bytes);
    }
    for length in 0..70_usize {
        let bytes: Vec<u8> = (0..length).map(|index| (index * 37 % 251) as u8).collect();
        let text = base64url_encode(&bytes);
        assert_eq!(text.len(), (length * 8).div_ceil(6));
        assert_eq!(base64url_decode(&text)?, bytes, "length {length}");
    }
    Ok(())
}

#[test]
fn base64url_decoding_is_canonical() {
    assert_eq!(base64url_decode("Zg=="), Err(E2eeError::InvalidValue));
    assert_eq!(base64url_decode("Z"), Err(E2eeError::NonCanonical));
    assert_eq!(base64url_decode("Zh"), Err(E2eeError::NonCanonical));
    assert_eq!(base64url_decode("Zm9"), Err(E2eeError::NonCanonical));
    assert_eq!(base64url_decode("Zg+"), Err(E2eeError::InvalidValue));
    assert_eq!(base64url_decode("Zm9v/"), Err(E2eeError::NonCanonical));
    assert_eq!(base64url_decode("Zm 9"), Err(E2eeError::InvalidValue));
}

#[test]
fn fixed_width_tokens_check_their_length() -> Result<(), E2eeError> {
    let id16 = base64url_encode(&[7; 16]);
    assert_eq!(id16.len(), ID16_CHARS);
    assert_eq!(parse_id16(&id16)?, [7; 16]);
    let hash = base64url_encode(&[9; 32]);
    assert_eq!(hash.len(), HASH_CHARS);
    assert_eq!(parse_hash(&hash)?, [9; 32]);
    let account = base64url_encode(&[b'a'; 24]);
    assert_eq!(account.len(), ACCOUNT_CHARS);
    assert_eq!(parse_account(&account)?, [b'a'; 24]);
    assert_eq!(parse_id16(&hash), Err(E2eeError::LengthOutOfRange));
    assert_eq!(parse_hash(&id16), Err(E2eeError::LengthOutOfRange));
    assert_eq!(parse_account(&hash), Err(E2eeError::LengthOutOfRange));
    assert_eq!(
        parse_hash(&format!("{}{}", &hash[..42], "x")),
        Err(E2eeError::NonCanonical)
    );
    assert_eq!(parse_cursor("*")?, None);
    assert_eq!(parse_cursor(&hash)?, Some([9; 32]));
    assert_eq!(parse_cursor("**"), Err(E2eeError::LengthOutOfRange));
    assert_eq!(render_cursor(None), "*");
    assert_eq!(render_cursor(Some(&[9; 32])), hash);
    Ok(())
}

#[test]
fn key_package_references_span_one_to_255_bytes() -> Result<(), E2eeError> {
    assert_eq!(parse_key_package_ref(&base64url_encode(&[1]))?, vec![1]);
    let longest = base64url_encode(&[2; 255]);
    assert_eq!(longest.len(), MAX_KEY_PACKAGE_REF_CHARS);
    assert_eq!(parse_key_package_ref(&longest)?.len(), 255);
    assert_eq!(parse_key_package_ref(""), Err(E2eeError::LengthOutOfRange));
    assert_eq!(
        parse_key_package_ref(&base64url_encode(&[2; 256])),
        Err(E2eeError::LengthOutOfRange)
    );
    Ok(())
}

#[test]
fn decimals_have_no_leading_zero_and_are_range_checked() -> Result<(), E2eeError> {
    assert_eq!(parse_u16("0")?, 0);
    assert_eq!(parse_u16("65535")?, 65_535);
    assert_eq!(parse_u16("65536"), Err(E2eeError::Overflow));
    assert_eq!(parse_u16("123456"), Err(E2eeError::InvalidValue));
    assert_eq!(parse_u16("01"), Err(E2eeError::NonCanonical));
    assert_eq!(parse_u16(""), Err(E2eeError::InvalidValue));
    assert_eq!(parse_u16("1a"), Err(E2eeError::InvalidValue));
    assert_eq!(parse_u16("-1"), Err(E2eeError::InvalidValue));
    assert_eq!(parse_u32("4294967295")?, u32::MAX);
    assert_eq!(parse_u32("4294967296"), Err(E2eeError::Overflow));
    assert_eq!(parse_u64("18446744073709551615")?, u64::MAX);
    assert_eq!(parse_u64("18446744073709551616"), Err(E2eeError::Overflow));
    assert_eq!(
        parse_u64("100000000000000000000"),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn labels_and_batch_ids_are_closed_alphabets() {
    assert!(is_safe_label("abc_-Z9"));
    assert!(is_safe_label(&"a".repeat(MAX_LABEL_CHARS)));
    assert!(!is_safe_label(""));
    assert!(!is_safe_label(&"a".repeat(MAX_LABEL_CHARS + 1)));
    assert!(!is_safe_label("a b"));
    assert!(!is_safe_label("a\\sb"));
    assert!(!is_safe_label("a;b"));
    assert!(is_batch_id("batch-1"));
    assert!(!is_batch_id("batch_1"));
    assert!(!is_batch_id(""));
}
