#![forbid(unsafe_code)]

//! Application content padding (companion Section 7.5 over Section 10).

use std::error::Error;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

fn content(body_length: usize) -> Result<IrcEncryptedContent, E2eeError> {
    Ok(IrcEncryptedContent {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [2; 32],
        route_binding: [3; 32],
        sender_device_id: [4; 16],
        leaf_credential_generation: 0,
        sender_sequence: 7,
        message_id: [5; 16],
        sequencer_record_chain_head: [6; 32],
        content_type: IrcEncryptedContentType::Text,
        body: Opaque::new(vec![b'a'; body_length])?,
        zero_padding: Opaque::new(Vec::new())?,
    })
}

/// The fixed fields before the body: 2 + 32 + 32 + 32 + 16 + 8 + 8 + 16 +
/// 32 + 1, the two-byte body length, and the two-byte padding length.
const FIXED_BYTES: usize = 179 + 2 + 2;

#[test]
fn every_boundary_vector_pads_the_encoding_onto_its_bucket() -> TestResult {
    for (unpadded, target) in [
        (256, 256),
        (257, 512),
        (4_095, 4_096),
        (4_096, 4_096),
        (4_097, 5_120),
        (5_119, 5_120),
        (5_120, 5_120),
    ] {
        let mut content = content(unpadded - FIXED_BYTES)?;
        assert_eq!(content.unpadded_length()?, unpadded, "L={unpadded}");
        content.pad()?;
        assert_eq!(content.encode()?.len(), target, "L={unpadded}");
        assert_eq!(
            content.zero_padding.as_slice().len(),
            target - unpadded,
            "L={unpadded}"
        );
        content.check_shape()?;
        let mut budget = DecodeBudget::new(1 << 16, 64);
        let decoded = IrcEncryptedContent::decode_checked(&content.encode()?, &mut budget)?;
        assert_eq!(decoded, content);
    }
    Ok(())
}

#[test]
fn a_wrong_length_or_a_nonzero_octet_is_rejected() -> TestResult {
    let mut content = content(10)?;
    content.pad()?;
    let padded = content.zero_padding.as_slice().len();
    let mut short = content.clone();
    short.zero_padding = Opaque::new(vec![0; padded - 1])?;
    assert_eq!(short.check_padding(), Err(E2eeError::InvalidValue));
    let mut long = content.clone();
    long.zero_padding = Opaque::new(vec![0; padded + 1])?;
    assert_eq!(long.check_padding(), Err(E2eeError::InvalidValue));
    let mut dirty = content.clone();
    let mut octets = vec![0; padded];
    if let Some(last) = octets.last_mut() {
        *last = 1;
    }
    dirty.zero_padding = Opaque::new(octets)?;
    assert_eq!(dirty.check_padding(), Err(E2eeError::InvalidValue));
    let mut nul = content.clone();
    nul.body = Opaque::new(vec![0])?;
    nul.pad()?;
    assert_eq!(nul.check_shape(), Err(E2eeError::InvalidValue));
    let mut generation = content;
    generation.leaf_credential_generation = 1;
    assert_eq!(generation.check_shape(), Err(E2eeError::ProfileMismatch));
    Ok(())
}
