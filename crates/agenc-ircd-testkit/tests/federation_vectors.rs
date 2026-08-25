#![forbid(unsafe_code)]

//! Independent golden-vector agreement for every frozen Appendix-B schema.

use std::collections::BTreeSet;
use std::error::Error;

use agenc_ircd_federation_wire::{CanonicalEncode, DecodeBudget, SCHEMA_REGISTRY, SchemaObject};
use agenc_ircd_testkit::{ReferenceCodecError, ReferenceEncoder, parse_reference_vectors};

const VECTORS: &str = include_str!("../../../test-data/vectors/base-federation-v1.vectors");

#[test]
fn every_schema_decodes_and_reencodes_its_independent_vector() -> Result<(), Box<dyn Error>> {
    let vectors = parse_reference_vectors(VECTORS)?;
    assert_eq!(vectors.len(), 128);
    assert_eq!(vectors.len(), SCHEMA_REGISTRY.len());
    let mut identifiers = BTreeSet::new();
    let mut schemas = BTreeSet::new();
    for vector in vectors {
        assert!(identifiers.insert(vector.identifier().to_owned()));
        assert!(schemas.insert(vector.schema().to_owned()));
        assert_eq!(vector.provenance(), "frozen-registry-minimum");
        assert_eq!(vector.sha256().len(), 64);
        let mut budget = DecodeBudget::new(64 * 1024 * 1024, 1_000_000);
        let decoded = SchemaObject::decode_exact(vector.schema(), vector.bytes(), &mut budget)
            .map_err(|error| format!("{} failed semantic decode: {error}", vector.schema()))?;
        assert_eq!(decoded.schema().name, vector.schema());
        assert_eq!(decoded.encode_canonical()?, vector.bytes());
    }
    let registered: BTreeSet<String> = SCHEMA_REGISTRY
        .iter()
        .map(|schema| schema.name.to_owned())
        .collect();
    assert_eq!(schemas, registered);
    Ok(())
}

#[test]
fn independent_primitive_encoder_covers_every_length_width() -> Result<(), ReferenceCodecError> {
    let mut encoder = ReferenceEncoder::new(64);
    encoder.write_u8(0x12)?;
    encoder.write_u16(0x3456)?;
    encoder.write_u24(0x78_9abc)?;
    encoder.write_u32(0xdef0_1234)?;
    encoder.write_u64(0x5678_9abc_def0_1234)?;
    encoder.write_opaque(&[1, 2], 1, 255)?;
    encoder.write_opaque(&[3, 4], 1, 65_536)?;
    assert_eq!(
        encoder.finish(),
        [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x12, 0x34, 2, 1, 2, 0, 0, 2, 3, 4,
        ]
    );
    Ok(())
}

#[test]
fn vector_manifest_rejects_shape_hex_hash_and_output_failures() {
    assert!(matches!(
        parse_reference_vectors("bad-line"),
        Err(ReferenceCodecError::ManifestShape)
    ));
    assert!(matches!(
        parse_reference_vectors("VEC-B-001|x|0|00|frozen-registry-minimum"),
        Err(ReferenceCodecError::ManifestValue)
    ));
    assert!(matches!(
        parse_reference_vectors(
            "VEC-B-001|x|00|0000000000000000000000000000000000000000000000000000000000000000|frozen-registry-minimum"
        ),
        Err(ReferenceCodecError::HashMismatch)
    ));
    let mut encoder = ReferenceEncoder::new(0);
    assert_eq!(encoder.write_u8(1), Err(ReferenceCodecError::OutputLimit));
    assert_eq!(
        ReferenceEncoder::new(8).write_u8(256),
        Err(ReferenceCodecError::IntegerOutOfRange)
    );
}

#[test]
fn independent_encoder_rejects_every_width_and_bound_failure() -> Result<(), ReferenceCodecError> {
    assert_eq!(
        ReferenceEncoder::new(8).write_u16(u64::from(u16::MAX) + 1),
        Err(ReferenceCodecError::IntegerOutOfRange)
    );
    assert_eq!(
        ReferenceEncoder::new(8).write_u24(0x0100_0000),
        Err(ReferenceCodecError::IntegerOutOfRange)
    );
    assert_eq!(
        ReferenceEncoder::new(8).write_u32(u64::from(u32::MAX) + 1),
        Err(ReferenceCodecError::IntegerOutOfRange)
    );

    let mut encoder = ReferenceEncoder::new(32);
    assert_eq!(
        encoder.write_opaque(b"", 1, 2),
        Err(ReferenceCodecError::VectorLength)
    );
    assert_eq!(
        encoder.write_opaque(b"abc", 1, 2),
        Err(ReferenceCodecError::VectorLength)
    );
    assert_eq!(
        encoder.write_length(3, 2),
        Err(ReferenceCodecError::VectorLength)
    );
    encoder.write_length(1, 256)?;
    encoder.write_length(1, 0x00ff_ffff)?;
    encoder.write_length(1, 0x0100_0000)?;
    assert_eq!(encoder.finish(), [0, 1, 0, 0, 1, 0, 0, 0, 1]);
    Ok(())
}

#[test]
fn vector_manifest_rejects_each_string_and_hex_rule() {
    const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let record = |identifier: &str, schema: &str, encoded: &str, hash: &str, provenance: &str| {
        format!("{identifier}|{schema}|{encoded}|{hash}|{provenance}")
    };

    assert!(parse_reference_vectors("").is_ok());
    assert_eq!(
        parse_reference_vectors(&record(
            "BAD",
            "x",
            "",
            EMPTY_HASH,
            "frozen-registry-minimum"
        ))
        .err(),
        Some(ReferenceCodecError::ManifestValue)
    );
    assert_eq!(
        parse_reference_vectors(&record(
            "VEC-B-001",
            "",
            "",
            EMPTY_HASH,
            "frozen-registry-minimum"
        ))
        .err(),
        Some(ReferenceCodecError::ManifestValue)
    );
    assert_eq!(
        parse_reference_vectors(&record("VEC-B-001", "x", "", EMPTY_HASH, "other")).err(),
        Some(ReferenceCodecError::ManifestValue)
    );
    assert_eq!(
        parse_reference_vectors(&record(
            "VEC-B-001",
            "x",
            "",
            "0",
            "frozen-registry-minimum"
        ))
        .err(),
        Some(ReferenceCodecError::ManifestValue)
    );
    assert_eq!(
        parse_reference_vectors(&record(
            "VEC-B-001",
            "x",
            "",
            &"A".repeat(64),
            "frozen-registry-minimum"
        ))
        .err(),
        Some(ReferenceCodecError::ManifestValue)
    );
    assert_eq!(
        parse_reference_vectors(&record(
            "VEC-B-001",
            "x",
            "0",
            EMPTY_HASH,
            "frozen-registry-minimum"
        ))
        .err(),
        Some(ReferenceCodecError::ManifestValue)
    );
    assert_eq!(
        parse_reference_vectors(&record(
            "VEC-B-001",
            "x",
            "g0",
            EMPTY_HASH,
            "frozen-registry-minimum"
        ))
        .err(),
        Some(ReferenceCodecError::ManifestValue)
    );
    assert_eq!(
        parse_reference_vectors(&record(
            "VEC-B-001",
            "x",
            "0g",
            EMPTY_HASH,
            "frozen-registry-minimum"
        ))
        .err(),
        Some(ReferenceCodecError::ManifestValue)
    );
}

#[test]
fn vector_count_limit_and_error_messages_are_closed() {
    const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let line = format!("VEC-B-001|x||{EMPTY_HASH}|frozen-registry-minimum\n");
    let manifest = line.repeat(agenc_ircd_testkit::MAX_REFERENCE_VECTORS + 1);
    assert_eq!(
        parse_reference_vectors(&manifest).err(),
        Some(ReferenceCodecError::OutputLimit)
    );

    let cases = [
        (
            ReferenceCodecError::IntegerOutOfRange,
            "reference integer is outside its wire width",
        ),
        (
            ReferenceCodecError::VectorLength,
            "reference vector is outside its bounds",
        ),
        (
            ReferenceCodecError::OutputLimit,
            "reference output limit exceeded",
        ),
        (
            ReferenceCodecError::ManifestShape,
            "reference vector manifest shape is invalid",
        ),
        (
            ReferenceCodecError::ManifestValue,
            "reference vector manifest value is invalid",
        ),
        (
            ReferenceCodecError::HashMismatch,
            "reference vector hash mismatch",
        ),
        (
            ReferenceCodecError::Overflow,
            "reference codec calculation overflowed",
        ),
        (
            ReferenceCodecError::AllocationFailed,
            "reference codec allocation failed",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}
