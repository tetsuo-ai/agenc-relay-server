#![forbid(unsafe_code)]

//! Message-tag parsing and canonical rendering at public limits.

use std::error::Error;

use agenc_relay_client_wire::{
    MAX_CLIENT_ONLY_VALUE_BYTES, MAX_CLIENT_TAG_DATA_BYTES, MAX_CORRELATION_TAG_BYTES, MessageTag,
    TagError, parse_client_tags, render_tags,
};

#[test]
fn raw_tag_parser_distinguishes_key_value_and_length_failures() -> Result<(), Box<dyn Error>> {
    let exact = "a".repeat(MAX_CLIENT_TAG_DATA_BYTES);
    assert_eq!(
        parse_client_tags(&exact)?.first().map(|tag| tag.key()),
        Some(exact.as_str())
    );
    assert_eq!(
        parse_client_tags(&format!("{exact}a")).err(),
        Some(TagError::RawSectionTooLong)
    );

    for invalid_value in ["key=bad value", "key=bad\0value", "key=bad\r", "key=bad\n"] {
        assert_eq!(
            parse_client_tags(invalid_value).err(),
            Some(TagError::InvalidValue),
            "invalid encoded value: {invalid_value:?}"
        );
    }

    let exact_correlation = "x".repeat(MAX_CORRELATION_TAG_BYTES);
    assert!(parse_client_tags(&format!("label={exact_correlation}")).is_ok());
    assert_eq!(
        parse_client_tags(&format!("batch={exact_correlation}x")).err(),
        Some(TagError::CorrelationValueTooLong)
    );

    let exact_client_value = "v".repeat(MAX_CLIENT_ONLY_VALUE_BYTES);
    assert!(parse_client_tags(&format!("+client={exact_client_value}")).is_ok());
    assert_eq!(
        parse_client_tags(&format!("+client={exact_client_value}v")).err(),
        Some(TagError::ClientOnlyValueTooLong)
    );
    Ok(())
}

#[test]
fn canonical_rendering_handles_empty_values_escapes_and_collection_shapes()
-> Result<(), Box<dyn Error>> {
    let empty: Vec<MessageTag> = Vec::new();
    assert_eq!(render_tags(&empty)?, "");

    let parsed = parse_client_tags(r"plain=;escaped=a\:b\sc\\d\r\n\q;tail=last\")?;
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed.get(0).and_then(|tag| tag.value()), None);
    assert_eq!(parsed.get(3), None);
    assert_eq!(
        render_tags(&parsed)?,
        r"plain;escaped=a\:b\sc\\d\r\nq;tail=last"
    );

    let same = parse_client_tags(r"plain;escaped=a\:b\sc\\d\r\nq;tail=last")?;
    let shorter = parse_client_tags("plain;escaped=value")?;
    let different = parse_client_tags("plain;escaped=value;tail=last")?;
    assert_eq!(parsed, same);
    assert_ne!(parsed, shorter);
    assert_ne!(parsed, different);

    let mut tags = parsed.iter();
    assert_eq!(tags.len(), 3);
    assert_eq!(tags.next().map(|tag| tag.key()), Some("plain"));
    assert_eq!(tags.len(), 2);
    assert_eq!(tags.by_ref().count(), 2);
    assert_eq!(tags.next(), None);
    Ok(())
}

#[test]
fn locally_constructed_tag_enforces_the_encoded_section_boundary() -> Result<(), Box<dyn Error>> {
    let exact_key = "k".repeat(MAX_CLIENT_TAG_DATA_BYTES);
    let exact = MessageTag::new(&exact_key, None)?;
    assert!(!exact.is_client_only());
    assert_eq!(render_tags(&[exact])?.len(), MAX_CLIENT_TAG_DATA_BYTES);

    assert_eq!(
        MessageTag::new(&format!("{exact_key}k"), None).err(),
        Some(TagError::RawSectionTooLong)
    );
    let client = MessageTag::new("+client", Some(""))?;
    assert!(client.is_client_only());
    assert_eq!(client.value(), None);
    Ok(())
}
