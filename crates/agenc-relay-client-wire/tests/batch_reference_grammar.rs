#![forbid(unsafe_code)]

//! Ratified IRCv3 batch-reference grammar coverage.

use std::error::Error;

use agenc_relay_client_wire::{
    BatchStack, CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState, RenderError,
};

#[test]
fn batch_references_accept_only_ascii_letters_digits_and_hyphens() -> Result<(), Box<dyn Error>> {
    let profile = CapabilityProfile::new(vec![
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("labeled-response", None)?,
    ])?;
    let mut capabilities = CapabilityState::default();
    capabilities.ls(Some("302"), &profile)?;
    assert!(matches!(
        capabilities.request("batch labeled-response", &profile)?,
        CapRequestReply::Ack(_)
    ));

    for invalid in ["", "with_underscore", "vendor/reference", "nonascii-é"] {
        let mut batches = BatchStack::default();
        assert_eq!(
            batches
                .open(&capabilities, "server.example", invalid, "opaque/label")
                .err(),
            Some(RenderError::InvalidCorrelation),
            "{invalid:?}",
        );
        assert_eq!(batches.depth(), 0);
    }

    let mut batches = BatchStack::default();
    let _opening = batches.open(
        &capabilities,
        "server.example",
        "Letters-0123456789",
        "opaque/label",
    )?;
    assert_eq!(batches.depth(), 1);
    Ok(())
}
