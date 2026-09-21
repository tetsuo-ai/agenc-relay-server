#![forbid(unsafe_code)]

//! Independent encoder transactionality and manifest grammar boundaries.

use std::error::Error;

use agenc_relay_testkit::{ReferenceCodecError, ReferenceEncoder, parse_reference_vectors};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn primitive_writers_are_transactional_at_each_output_boundary() -> Result<(), ReferenceCodecError>
{
    let mut u16_encoder = ReferenceEncoder::new(2);
    u16_encoder.write_u16(u16::MAX.into())?;
    assert_eq!(
        u16_encoder.write_u8(1),
        Err(ReferenceCodecError::OutputLimit)
    );
    assert_eq!(u16_encoder.finish(), u16::MAX.to_be_bytes());

    let mut u24_encoder = ReferenceEncoder::new(3);
    u24_encoder.write_u24(0x00ff_ffff)?;
    assert_eq!(
        u24_encoder.write_u8(1),
        Err(ReferenceCodecError::OutputLimit)
    );
    assert_eq!(u24_encoder.finish(), [0xff, 0xff, 0xff]);

    let mut u32_encoder = ReferenceEncoder::new(4);
    u32_encoder.write_u32(u32::MAX.into())?;
    assert_eq!(
        u32_encoder.write_u8(1),
        Err(ReferenceCodecError::OutputLimit)
    );
    assert_eq!(u32_encoder.finish(), u32::MAX.to_be_bytes());

    let mut u64_encoder = ReferenceEncoder::new(8);
    u64_encoder.write_u64(u64::MAX)?;
    assert_eq!(
        u64_encoder.write_u8(1),
        Err(ReferenceCodecError::OutputLimit)
    );
    assert_eq!(u64_encoder.finish(), u64::MAX.to_be_bytes());

    let mut fixed_encoder = ReferenceEncoder::new(3);
    fixed_encoder.write_fixed(&[1, 2, 3])?;
    assert_eq!(
        fixed_encoder.write_fixed(&[4]),
        Err(ReferenceCodecError::OutputLimit)
    );
    assert_eq!(fixed_encoder.finish(), [1, 2, 3]);
    Ok(())
}

#[test]
fn length_prefix_widths_switch_at_their_exact_maximums() -> Result<(), ReferenceCodecError> {
    let cases = [
        (u8::MAX as usize, vec![1]),
        (u8::MAX as usize + 1, vec![0, 1]),
        (u16::MAX as usize, vec![0, 1]),
        (u16::MAX as usize + 1, vec![0, 0, 1]),
        (0x00ff_ffff, vec![0, 0, 1]),
        (0x0100_0000, vec![0, 0, 0, 1]),
    ];
    for (maximum, expected) in cases {
        let mut encoder = ReferenceEncoder::new(4);
        encoder.write_length(1, maximum)?;
        assert_eq!(encoder.finish(), expected, "maximum {maximum}");
    }

    let mut bounded = ReferenceEncoder::new(8);
    bounded.write_opaque(b"ab", 2, 2)?;
    assert_eq!(bounded.finish(), [2, b'a', b'b']);
    let mut too_short = ReferenceEncoder::new(8);
    assert_eq!(
        too_short.write_opaque(b"a", 2, 2),
        Err(ReferenceCodecError::VectorLength)
    );
    assert!(too_short.finish().is_empty());
    Ok(())
}

#[test]
fn manifest_accepts_boundary_identifiers_and_rejects_extra_or_invalid_fields()
-> Result<(), Box<dyn Error>> {
    let valid = format!(
        "# comment\n\n\
         VEC-B-001|a||{EMPTY_SHA256}|frozen-registry-minimum\n\
         VEC-B-999|A0||{EMPTY_SHA256}|frozen-registry-minimum\n\
         VEC-B-1000|a_b.c9||{EMPTY_SHA256}|frozen-registry-minimum\n\
         VEC-B-4096|z9||{EMPTY_SHA256}|frozen-registry-minimum"
    );
    let vectors = parse_reference_vectors(&valid)?;
    let [first, _, third, _] = vectors.as_slice() else {
        return Err(ReferenceCodecError::ManifestShape.into());
    };
    assert_eq!(first.identifier(), "VEC-B-001");
    assert_eq!(third.schema(), "a_b.c9");
    assert!(vectors.iter().all(|vector| vector.bytes().is_empty()));
    assert!(vectors.iter().all(|vector| vector.sha256() == EMPTY_SHA256));

    let invalid_records = [
        format!("VEC-B-001|a||{EMPTY_SHA256}|frozen-registry-minimum|extra"),
        format!("VEC-B-00A|a||{EMPTY_SHA256}|frozen-registry-minimum"),
        format!("VEC-B-0001|a||{EMPTY_SHA256}|frozen-registry-minimum"),
        format!("VEC-B-4097|a||{EMPTY_SHA256}|frozen-registry-minimum"),
        format!("VEC-B-001|9bad||{EMPTY_SHA256}|frozen-registry-minimum"),
        format!("VEC-B-001|bad-name||{EMPTY_SHA256}|frozen-registry-minimum"),
    ];
    for invalid in invalid_records {
        assert!(parse_reference_vectors(&invalid).is_err(), "{invalid:?}");
    }
    Ok(())
}
