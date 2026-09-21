#![forbid(unsafe_code)]

//! Cross-tag renderer invariant regressions.

use std::error::Error;

use agenc_relay_client_wire::{MessageTag, TagError, render_tags};

#[test]
fn local_tag_construction_normalizes_empty_values() -> Result<(), Box<dyn Error>> {
    let tag = MessageTag::new("example", Some(""))?;

    assert_eq!(tag.value(), None);
    assert_eq!(render_tags(&[tag])?, "example");
    Ok(())
}

#[test]
fn tag_collection_rendering_rejects_cross_tag_invariant_violations() -> Result<(), Box<dyn Error>> {
    let duplicates = [
        MessageTag::new("example", Some("one"))?,
        MessageTag::new("example", Some("two"))?,
    ];
    assert_eq!(render_tags(&duplicates), Err(TagError::DuplicateKey));

    let mut too_many_client_only = Vec::new();
    too_many_client_only.try_reserve_exact(17)?;
    for index in 0..17 {
        too_many_client_only.push(MessageTag::new(&format!("+example/{index}"), None)?);
    }
    assert_eq!(
        render_tags(&too_many_client_only),
        Err(TagError::TooManyClientOnlyTags)
    );

    let client_only_total = [
        MessageTag::new("+example/one", Some(&"a".repeat(256)))?,
        MessageTag::new("+example/two", Some(&"b".repeat(256)))?,
        MessageTag::new("+example/three", Some(&"c".repeat(256)))?,
        MessageTag::new("+example/four", Some(&"d".repeat(256)))?,
    ];
    assert_eq!(
        render_tags(&client_only_total),
        Err(TagError::ClientOnlyTotalTooLong)
    );
    Ok(())
}

#[test]
fn tag_collection_exact_boundaries_are_enforced_without_scratch_allocation()
-> Result<(), Box<dyn Error>> {
    let mut sixteen = Vec::new();
    sixteen.try_reserve_exact(16)?;
    for index in 0..16 {
        sixteen.push(MessageTag::new(&format!("+x{index}"), None)?);
    }
    assert!(render_tags(&sixteen).is_ok());
    sixteen.push(MessageTag::new("+overflow", None)?);
    assert_eq!(render_tags(&sixteen), Err(TagError::TooManyClientOnlyTags));

    let exact_total = [
        MessageTag::new("+a0", Some(&"a".repeat(253)))?,
        MessageTag::new("+a1", Some(&"b".repeat(253)))?,
        MessageTag::new("+a2", Some(&"c".repeat(253)))?,
        MessageTag::new("+a3", Some(&"d".repeat(253)))?,
    ];
    assert!(render_tags(&exact_total).is_ok());
    let over_total = [
        MessageTag::new("+a0", Some(&"a".repeat(254)))?,
        MessageTag::new("+a1", Some(&"b".repeat(253)))?,
        MessageTag::new("+a2", Some(&"c".repeat(253)))?,
        MessageTag::new("+a3", Some(&"d".repeat(253)))?,
    ];
    assert_eq!(
        render_tags(&over_total),
        Err(TagError::ClientOnlyTotalTooLong)
    );

    let exact_raw = [MessageTag::new(&"a".repeat(4_094), None)?];
    assert_eq!(render_tags(&exact_raw)?.len(), 4_094);
    let over_raw = [
        MessageTag::new(&"a".repeat(2_047), None)?,
        MessageTag::new(&"b".repeat(2_047), None)?,
    ];
    assert_eq!(render_tags(&over_raw), Err(TagError::RawSectionTooLong));

    let case_distinct = [
        MessageTag::new("Example", None)?,
        MessageTag::new("example", None)?,
    ];
    assert_eq!(render_tags(&case_distinct)?, "Example;example");
    Ok(())
}
