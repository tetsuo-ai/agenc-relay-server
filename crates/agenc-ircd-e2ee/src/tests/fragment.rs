#![forbid(unsafe_code)]

//! Fragment and receipt tag values.

use std::error::Error;

use super::*;
use crate::wire::tokens::base64url_encode;

type TestResult = Result<(), Box<dyn Error>>;

fn object(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 253) as u8).collect()
}

#[test]
fn objects_split_into_exact_segments_that_round_trip() -> TestResult {
    let bytes = object(65_536);
    let fragments = fragment_object(&bytes)?;
    assert_eq!(fragments.len(), 23);
    assert_eq!(fragment_count(65_536)?, 23);
    let mut rebuilt = Vec::new();
    for (index, fragment) in fragments.iter().enumerate() {
        assert_eq!(fragment.part, u32::try_from(index)?);
        assert_eq!(fragment.count, 23);
        assert_eq!(fragment.total, 65_536);
        let expected = if fragment.is_final() { 856 } else { 2_940 };
        assert_eq!(fragment.segment.len(), expected);
        assert_eq!(fragment.offset()?, index * 2_940);
        let rendered = fragment.render();
        assert!(rendered.len() <= 3_920 + 60);
        assert_eq!(&FragmentTag::parse(&rendered)?, fragment);
        rebuilt.extend_from_slice(&fragment.segment);
    }
    assert_eq!(rebuilt, bytes);
    assert_eq!(fragment_object(&object(1))?.len(), 1);
    assert_eq!(fragment_object(&object(2_940))?.len(), 1);
    assert_eq!(fragment_object(&object(2_941))?.len(), 2);
    assert_eq!(fragment_count(4_194_304)?, 1_427);
    assert_eq!(fragment_count(0), Err(E2eeError::InvalidValue));
    assert_eq!(fragment_object(&[]), Err(E2eeError::InvalidValue));
    assert_eq!(segment_length(0, 1, 100)?, 100);
    assert_eq!(segment_length(1, 1, 100), Err(E2eeError::InvalidValue));
    Ok(())
}

#[test]
fn every_fragment_grammar_rule_has_a_negative() -> TestResult {
    let good = fragment_object(&object(6_000))?;
    let first = good.first().ok_or("fragment")?;
    let last = good.get(2).ok_or("fragment")?;
    let id = base64url_encode(first.object_id.as_bytes());
    let full = base64url_encode(&first.segment);
    let tail = base64url_encode(&last.segment);
    let cases = [
        ("five fields", format!("v1.{id}.0.3.{full}")),
        ("seven fields", format!("v1.{id}.0.3.6000.{full}.x")),
        ("version", format!("v2.{id}.0.3.6000.{full}")),
        ("part at count", format!("v1.{id}.3.3.6000.{tail}")),
        ("count zero", format!("v1.{id}.0.0.6000.{full}")),
        ("total zero", format!("v1.{id}.0.1.0.{full}")),
        ("count not ceil", format!("v1.{id}.0.4.6000.{full}")),
        ("short middle segment", format!("v1.{id}.0.3.6000.{tail}")),
        ("long final segment", format!("v1.{id}.2.3.6000.{full}")),
        ("leading zero", format!("v1.{id}.01.3.6000.{full}")),
        ("five index digits", format!("v1.{id}.00000.3.6000.{full}")),
        ("eight total digits", format!("v1.{id}.0.3.00006000.{full}")),
        (
            "short object id",
            format!("v1.{}.0.3.6000.{full}", &id[..42]),
        ),
        (
            "bad segment char",
            format!("v1.{id}.0.3.6000.{}+", &full[..3_919]),
        ),
        ("empty segment", format!("v1.{id}.0.3.6000.")),
        ("non canonical segment", format!("v1.{id}.0.1.1.Zh")),
    ];
    for (label, raw) in cases {
        assert!(FragmentTag::parse(&raw).is_err(), "{label}");
    }
    Ok(())
}

#[test]
fn receipt_tags_round_trip() -> TestResult {
    let receipt = ReceiptTag {
        candidate_id: [5; 32],
        receipt: vec![7; 294],
    };
    let rendered = receipt.render();
    assert_eq!(rendered.len(), 3 + 43 + 1 + 392);
    assert_eq!(ReceiptTag::parse(&rendered)?, receipt);
    assert!(ReceiptTag::parse(&format!("v2.{}", &rendered[3..])).is_err());
    assert!(ReceiptTag::parse(&rendered[..47]).is_err());
    assert!(ReceiptTag::parse(&format!("{rendered}.x")).is_err());
    assert!(ReceiptTag::parse(&format!("{rendered}+")).is_err());
    Ok(())
}

#[test]
fn a_frame_carries_at_most_one_fragment_tag() -> TestResult {
    assert_eq!(fragment_tag_of(&[("label", "x")])?, None);
    assert_eq!(
        fragment_tag_of(&[("label", "x"), (CLIENT_FRAGMENT_TAG, "v1.a")])?,
        Some((CLIENT_FRAGMENT_TAG, "v1.a"))
    );
    assert_eq!(
        fragment_tag_of(&[(SERVER_FRAGMENT_TAG, "v1.a"), ("batch", "b")])?,
        Some((SERVER_FRAGMENT_TAG, "v1.a"))
    );
    assert_eq!(
        fragment_tag_of(&[(SERVER_FRAGMENT_TAG, "v1.a"), (CLIENT_FRAGMENT_TAG, "v1.a")]),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        fragment_tag_of(&[(CLIENT_FRAGMENT_TAG, "v1.a"), (CLIENT_FRAGMENT_TAG, "v1.a")]),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        fragment_tag_of(&[(CLIENT_FRAGMENT_TAG, "v1.a\\sb")]),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        fragment_tag_of(&[(CLIENT_FRAGMENT_TAG, "v1.\u{e9}")]),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}
