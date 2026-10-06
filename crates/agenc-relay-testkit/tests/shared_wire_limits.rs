#![forbid(unsafe_code)]

//! The client wire crate restates limits and a registry that other crates
//! own: the IRCv3 tag budgets of the base profile's constant registry, and
//! the E2EE profile's fragment and object limits and its Section 11.7
//! object-kind list. A client that uses the client wire copies must read the
//! same values as the daemon, so every copy is held equal to its owner here
//! and a change to one side alone fails.

use agenc_relay_client_wire::{
    E2EE_OBJECT_KINDS, E2eeObjectKind, MAX_CLIENT_TAG_DATA_BYTES, MAX_COMBINED_TAG_SECTION_BYTES,
    MAX_E2EE_FRAGMENT_BYTES, MAX_E2EE_FRAGMENT_COUNT, MAX_E2EE_OBJECT_BYTES,
    MAX_PHYSICAL_LINE_BYTES, MAX_SERVER_TAG_DATA_BYTES,
};
use agenc_relay_e2ee::ArcWireObjectKind;
use agenc_relay_e2ee::limits::{
    MAX_BATCH_DECODED_BYTES, MAX_BATCH_FRAGMENTS, MAX_CLIENT_TAG_DATA, MAX_COMBINED_TAG_SECTION,
    MAX_FRAGMENT_RAW, MAX_MAILBOX_FRAGMENT_COUNT, MAX_SERVER_TAG_DATA, MAX_WIRE_OBJECT_BODY_BYTES,
    WIRE_OBJECT_ENVELOPE_BYTES,
};
use agenc_relay_types::{
    CLIENT_PHYSICAL_LINE_BYTES, CLIENT_TAG_BYTES, COMBINED_TAG_SECTION_BYTES, SERVER_TAG_BYTES,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Companion Section 11.7: `object-kind` is exactly one of the 37 tokens,
/// which map by ordinal to the Section 11.4 registry. The client wire list
/// holds every token at its ordinal position, and nothing else.
#[test]
fn object_kind_registries_agree() -> TestResult {
    assert_eq!(E2EE_OBJECT_KINDS.len(), ArcWireObjectKind::ALL.len());
    for kind in ArcWireObjectKind::ALL {
        let ordinal = usize::from(kind.value());
        let position = ordinal.checked_sub(1).ok_or("ordinal zero")?;
        assert_eq!(
            E2EE_OBJECT_KINDS.get(position).copied(),
            Some(kind.token()),
            "ordinal {ordinal}"
        );
        assert_eq!(E2eeObjectKind::parse(kind.token())?.as_str(), kind.token());
    }
    for token in E2EE_OBJECT_KINDS {
        assert_eq!(ArcWireObjectKind::from_token(token)?.token(), *token);
    }
    Ok(())
}

/// The tag budgets: each side 4,094 bytes, the combined section 8,191 with
/// its `@` and space, and the physical line 8,703 with its CRLF.
#[test]
fn tag_and_line_limits_agree() -> TestResult {
    for (client_wire, e2ee, registry) in [
        (
            MAX_CLIENT_TAG_DATA_BYTES,
            MAX_CLIENT_TAG_DATA,
            CLIENT_TAG_BYTES,
        ),
        (
            MAX_SERVER_TAG_DATA_BYTES,
            MAX_SERVER_TAG_DATA,
            SERVER_TAG_BYTES,
        ),
        (
            MAX_COMBINED_TAG_SECTION_BYTES,
            MAX_COMBINED_TAG_SECTION,
            COMBINED_TAG_SECTION_BYTES,
        ),
    ] {
        assert_eq!(client_wire, e2ee);
        assert_eq!(u64::try_from(client_wire)?, registry);
    }
    assert_eq!(
        u64::try_from(MAX_PHYSICAL_LINE_BYTES)?,
        CLIENT_PHYSICAL_LINE_BYTES
    );
    Ok(())
}

/// One fragment carries at most 2,940 raw bytes, and a mailbox or control
/// object, the largest a batch holds, at most 1,427 fragments: exactly the
/// fragments the largest object needs.
#[test]
fn fragment_limits_agree() -> TestResult {
    assert_eq!(MAX_E2EE_FRAGMENT_BYTES, MAX_FRAGMENT_RAW);
    assert_eq!(
        u32::from(MAX_E2EE_FRAGMENT_COUNT),
        MAX_MAILBOX_FRAGMENT_COUNT
    );
    assert_eq!(usize::from(MAX_E2EE_FRAGMENT_COUNT), MAX_BATCH_FRAGMENTS);
    let largest = usize::try_from(MAX_E2EE_OBJECT_BYTES)?;
    assert_eq!(
        largest.div_ceil(MAX_FRAGMENT_RAW),
        usize::from(MAX_E2EE_FRAGMENT_COUNT)
    );
    Ok(())
}

/// The largest complete object the carrier grammar admits is the largest
/// any kind may have, the envelope's capacity and a batch's decoded bound.
#[test]
fn object_limits_agree() -> TestResult {
    let largest = usize::try_from(MAX_E2EE_OBJECT_BYTES)?;
    let kinds = ArcWireObjectKind::ALL
        .iter()
        .map(|kind| kind.maximum_object_bytes())
        .max()
        .ok_or("no object kinds")?;
    assert_eq!(largest, kinds);
    assert_eq!(
        largest,
        WIRE_OBJECT_ENVELOPE_BYTES + MAX_WIRE_OBJECT_BODY_BYTES
    );
    assert_eq!(largest, MAX_BATCH_DECODED_BYTES);
    Ok(())
}
