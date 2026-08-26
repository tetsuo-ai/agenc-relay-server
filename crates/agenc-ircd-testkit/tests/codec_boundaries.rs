#![forbid(unsafe_code)]

//! Stage-01 codec negatives, truncation coverage, and finite totality corpus.

use std::error::Error;

use agenc_ircd_federation_wire::{
    CanonicalEncode, CodecError, DecodeBudget, SCHEMA_REGISTRY, SchemaObject, WireValue,
};
use agenc_ircd_testkit::{ReferenceCodecError, ReferenceEncoder, parse_reference_vectors};

const VECTORS: &str = include_str!("../../../test-data/vectors/base-federation-v1.vectors");
const LARGE_BUDGET: usize = 64 * 1024 * 1024;

fn decode(schema: &str, bytes: &[u8]) -> Result<SchemaObject, CodecError> {
    let mut budget = DecodeBudget::new(LARGE_BUDGET, 1_000_000);
    SchemaObject::decode_exact(schema, bytes, &mut budget)
}

#[test]
fn every_vector_rejects_every_truncation_and_trailing_byte() -> Result<(), Box<dyn Error>> {
    for vector in parse_reference_vectors(VECTORS)? {
        for length in 0..vector.bytes().len() {
            let truncated = vector
                .bytes()
                .get(..length)
                .ok_or("truncation range escaped vector")?;
            assert!(decode(vector.schema(), truncated).is_err());
        }
        let mut trailing = vector.bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            decode(vector.schema(), &trailing).err(),
            Some(CodecError::TrailingBytes),
            "schema {} accepted a non-trailing error path",
            vector.schema()
        );
    }
    Ok(())
}

#[test]
fn constructors_reject_shape_type_bounds_enum_schema_and_order() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        SchemaObject::new("missing", Vec::new()).err(),
        Some(CodecError::UnknownSchema)
    );
    assert_eq!(
        SchemaObject::new("result.no_content", vec![WireValue::Unsigned(0)]).err(),
        Some(CodecError::FieldCount)
    );
    assert_eq!(
        SchemaObject::new("ChannelSettingsChange", vec![WireValue::Opaque(Vec::new())]).err(),
        Some(CodecError::TypeMismatch)
    );
    assert_eq!(
        SchemaObject::new("ChannelSettingsChange", vec![WireValue::Unsigned(u64::MAX)]).err(),
        Some(CodecError::IntegerOutOfRange)
    );
    assert_eq!(
        SchemaObject::new("ChannelSettingsChange", vec![WireValue::Unsigned(0)]).err(),
        Some(CodecError::UnknownDiscriminant)
    );
    assert_eq!(
        SchemaObject::new("FederationChannelName", vec![WireValue::Opaque(Vec::new())]).err(),
        Some(CodecError::LengthBelowMinimum)
    );
    assert_eq!(
        SchemaObject::new(
            "FederationChannelName",
            vec![WireValue::Opaque(vec![0; 65])]
        )
        .err(),
        Some(CodecError::LengthAboveMaximum)
    );

    let wrong_nested = SchemaObject::new(
        "FederationChannelName",
        vec![WireValue::Opaque(b"#x".to_vec())],
    )?;
    assert_eq!(
        SchemaObject::new(
            "operation.channel_settings",
            vec![
                WireValue::Opaque(vec![0; 16]),
                WireValue::Opaque(vec![0; 16]),
                WireValue::Unsigned(0),
                WireValue::Structure(wrong_nested),
            ]
        )
        .err(),
        Some(CodecError::SchemaMismatch)
    );

    let duplicate = join_target(b"#same")?;
    let duplicate_again = join_target_with_key(b"#same", b"different")?;
    assert_eq!(
        join_operation(vec![duplicate, duplicate_again]).err(),
        Some(CodecError::DuplicateValue)
    );
    let later = join_target(b"#z")?;
    let earlier = join_target(b"#a")?;
    assert_eq!(
        join_operation(vec![later, earlier]).err(),
        Some(CodecError::NonCanonicalOrder)
    );

    let target_one = message_target(1)?;
    let target_same_key = message_target(2)?;
    assert_eq!(
        message_operation(vec![target_one, target_same_key], Vec::new()).err(),
        Some(CodecError::DuplicateValue)
    );
    let tag_one = client_tag(b"+same", b"one")?;
    let tag_same_key = client_tag(b"+same", b"two")?;
    assert_eq!(
        message_operation(vec![message_target(1)?], vec![tag_one, tag_same_key]).err(),
        Some(CodecError::DuplicateValue)
    );
    Ok(())
}

#[test]
fn part_channel_ids_are_accepted_in_canonical_order() -> Result<(), Box<dyn Error>> {
    let first = [1_u8; 16];
    let second = [2_u8; 16];
    let valid = part_operation(&[first, second])?;
    let encoded = valid.encode_canonical()?;
    let reencoded = decode("operation.part", encoded.as_slice())?.encode_canonical()?;
    assert_eq!(reencoded.as_slice(), encoded.as_slice());

    assert_eq!(
        part_operation(&[first, first]).err(),
        Some(CodecError::DuplicateValue)
    );
    assert_eq!(
        part_operation(&[second, first]).err(),
        Some(CodecError::NonCanonicalOrder)
    );

    let duplicate = encode_part_operation(&[first, first])?;
    assert_eq!(
        decode("operation.part", &duplicate).err(),
        Some(CodecError::DuplicateValue)
    );
    let reversed = encode_part_operation(&[second, first])?;
    assert_eq!(
        decode("operation.part", &reversed).err(),
        Some(CodecError::NonCanonicalOrder)
    );
    Ok(())
}

#[test]
fn join_targets_use_canonical_channel_name_keys() -> Result<(), Box<dyn Error>> {
    let valid = join_operation_at_revision(vec![join_target(b"#a")?, join_target(b"#B")?])?;
    let encoded = valid.encode_canonical()?;
    let reencoded = decode("operation.join", encoded.as_slice())?.encode_canonical()?;
    assert_eq!(reencoded.as_slice(), encoded.as_slice());

    assert_eq!(
        join_operation_at_revision(vec![join_target(b"#Room")?, join_target(b"#room")?]).err(),
        Some(CodecError::DuplicateValue)
    );
    assert_eq!(
        join_operation_at_revision(vec![join_target(b"#B")?, join_target(b"#a")?]).err(),
        Some(CodecError::NonCanonicalOrder)
    );

    let duplicate_names: [&[u8]; 2] = [b"#Room", b"#room"];
    let duplicate = encode_join_operation(&duplicate_names)?;
    assert_eq!(
        decode("operation.join", &duplicate).err(),
        Some(CodecError::DuplicateValue)
    );
    let reversed_names: [&[u8]; 2] = [b"#B", b"#a"];
    let reversed = encode_join_operation(&reversed_names)?;
    assert_eq!(
        decode("operation.join", &reversed).err(),
        Some(CodecError::NonCanonicalOrder)
    );
    Ok(())
}

#[test]
fn federation_client_tag_keys_are_opaque_but_renderer_safe() -> Result<(), Box<dyn Error>> {
    let valid_keys: [&[u8]; 4] = [b"+", b"++tag", b"+future?name", b"+vendor.example/name"];
    for key in valid_keys {
        client_tag(key, b"")?;
    }

    let invalid_keys: [&[u8]; 7] = [
        b"tag",
        b"+bad tag",
        b"+bad;tag",
        b"+bad=tag",
        b"+bad\0tag",
        b"+bad\rtag",
        b"+bad\ntag",
    ];
    for key in invalid_keys {
        assert_eq!(client_tag(key, b"").err(), Some(CodecError::CrossReference));
    }
    Ok(())
}

fn channel_id(value: [u8; 16]) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationChannelId",
        vec![WireValue::Opaque(value.to_vec())],
    )
}

fn part_operation(channels: &[[u8; 16]]) -> Result<SchemaObject, CodecError> {
    let channels = channels
        .iter()
        .copied()
        .map(channel_id)
        .collect::<Result<Vec<_>, _>>()?;
    SchemaObject::new(
        "operation.part",
        vec![
            WireValue::Opaque(vec![0; 16]),
            WireValue::Unsigned(1),
            WireValue::Unsigned(0),
            WireValue::Vector(channels),
            WireValue::Opaque(Vec::new()),
        ],
    )
}

fn encode_part_operation(channels: &[[u8; 16]]) -> Result<Vec<u8>, ReferenceCodecError> {
    let mut encoder = ReferenceEncoder::new(LARGE_BUDGET);
    encoder.write_fixed(&[0; 16])?;
    encoder.write_u64(1)?;
    encoder.write_u16(0)?;
    encoder.write_length(channels.len(), 256)?;
    for channel in channels {
        encoder.write_fixed(channel)?;
    }
    encoder.write_opaque(b"", 0, 256)?;
    Ok(encoder.finish())
}

fn join_operation_at_revision(targets: Vec<SchemaObject>) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "operation.join",
        vec![
            WireValue::Opaque(vec![0; 16]),
            WireValue::Unsigned(1),
            WireValue::Vector(targets),
        ],
    )
}

fn encode_join_operation(names: &[&[u8]]) -> Result<Vec<u8>, ReferenceCodecError> {
    let mut encoder = ReferenceEncoder::new(LARGE_BUDGET);
    encoder.write_fixed(&[0; 16])?;
    encoder.write_u64(1)?;
    encoder.write_length(names.len(), 20)?;
    for name in names {
        encoder.write_opaque(name, 2, 64)?;
        encoder.write_opaque(b"", 0, 256)?;
    }
    Ok(encoder.finish())
}

fn join_target(channel: &[u8]) -> Result<SchemaObject, CodecError> {
    join_target_with_key(channel, b"")
}

fn join_target_with_key(channel: &[u8], key: &[u8]) -> Result<SchemaObject, CodecError> {
    let name = SchemaObject::new(
        "FederationChannelName",
        vec![WireValue::Opaque(channel.to_vec())],
    )?;
    SchemaObject::new(
        "FederationJoinTarget",
        vec![WireValue::Structure(name), WireValue::Opaque(key.to_vec())],
    )
}

fn join_operation(targets: Vec<SchemaObject>) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "operation.join",
        vec![
            WireValue::Opaque(vec![0; 16]),
            WireValue::Unsigned(0),
            WireValue::Vector(targets),
        ],
    )
}

fn message_target(revision: u64) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationMessageTarget",
        vec![
            WireValue::Unsigned(1),
            WireValue::Opaque(vec![0; 16]),
            WireValue::Unsigned(revision),
        ],
    )
}

fn client_tag(key: &[u8], value: &[u8]) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationClientTag",
        vec![
            WireValue::Opaque(key.to_vec()),
            WireValue::Opaque(value.to_vec()),
        ],
    )
}

fn message_operation(
    targets: Vec<SchemaObject>,
    tags: Vec<SchemaObject>,
) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "operation.message",
        vec![
            WireValue::Opaque(vec![0; 16]),
            WireValue::Unsigned(2),
            WireValue::Vector(targets),
            WireValue::Vector(tags),
            WireValue::Opaque(Vec::new()),
        ],
    )
}

#[test]
fn semantic_version_padding_and_budget_fail_closed() {
    assert_eq!(
        SchemaObject::new(
            "AccountServiceRequestPlaintext",
            vec![
                WireValue::Unsigned(0),
                WireValue::Opaque(vec![0; 72]),
                WireValue::Opaque(vec![0; 4_321]),
            ]
        )
        .err(),
        Some(CodecError::CrossReference)
    );
    assert_eq!(
        SchemaObject::new(
            "AccountServiceRequestPlaintext",
            vec![
                WireValue::Unsigned(1),
                WireValue::Opaque(vec![0; 72]),
                WireValue::Opaque(vec![1; 4_321]),
            ]
        )
        .err(),
        Some(CodecError::NonzeroPadding)
    );

    let mut budget = DecodeBudget::new(0, 0);
    assert_eq!(
        SchemaObject::decode_exact("FederationChannelName", &[2, b'#', b'x'], &mut budget).err(),
        Some(CodecError::AllocationBudgetExceeded)
    );
    assert_eq!(budget.remaining_bytes(), 0);
    assert_eq!(budget.remaining_values(), 0);

    let oversized = vec![0_u8; 262_145];
    let mut oversized_budget = DecodeBudget::new(oversized.len(), 1);
    assert_eq!(
        SchemaObject::decode_exact("result.no_content", &oversized, &mut oversized_budget).err(),
        Some(CodecError::LengthAboveMaximum)
    );
}

#[test]
fn mode_arguments_and_kick_targets_enforce_exact_inner_grammars() -> Result<(), CodecError> {
    let quiet_mask = SchemaObject::new(
        "FederationTypedMask",
        vec![
            WireValue::Unsigned(3),
            WireValue::Unsigned(1),
            WireValue::Opaque(b"nick*".to_vec()),
        ],
    )?
    .encode_canonical()?;
    assert_eq!(
        SchemaObject::new(
            "FederationModeChange",
            vec![
                WireValue::Unsigned(1),
                WireValue::Unsigned(2),
                WireValue::Opaque(quiet_mask.as_slice().to_vec()),
            ],
        )
        .err(),
        Some(CodecError::CrossReference)
    );
    assert_eq!(
        SchemaObject::new(
            "FederationProjectedModeChange",
            vec![
                WireValue::Unsigned(1),
                WireValue::Unsigned(4),
                WireValue::Opaque(vec![0]),
            ],
        )
        .err(),
        Some(CodecError::CrossReference)
    );
    SchemaObject::new(
        "FederationProjectedModeChange",
        vec![
            WireValue::Unsigned(1),
            WireValue::Unsigned(4),
            WireValue::Opaque(vec![0, 1]),
        ],
    )?;

    let change = || {
        SchemaObject::new(
            "FederationModeChange",
            vec![
                WireValue::Unsigned(1),
                WireValue::Unsigned(6),
                WireValue::Opaque(Vec::new()),
            ],
        )
    };
    assert_eq!(
        SchemaObject::new(
            "operation.channel_mode",
            vec![
                WireValue::Opaque(vec![0; 16]),
                WireValue::Opaque(vec![0; 16]),
                WireValue::Unsigned(1),
                WireValue::Vector(vec![change()?, change()?]),
            ],
        )
        .err(),
        Some(CodecError::DuplicateValue)
    );

    let mut reversed_targets = vec![2_u8; 16];
    reversed_targets.extend_from_slice(&[1_u8; 16]);
    assert_eq!(
        kick_operation(reversed_targets).err(),
        Some(CodecError::CrossReference)
    );
    assert_eq!(
        kick_operation(vec![1_u8; 17]).err(),
        Some(CodecError::CrossReference)
    );
    Ok(())
}

fn kick_operation(targets: Vec<u8>) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "operation.kick",
        vec![
            WireValue::Opaque(vec![0; 16]),
            WireValue::Opaque(vec![0; 16]),
            WireValue::Opaque(targets),
            WireValue::Unsigned(1),
            WireValue::Opaque(Vec::new()),
        ],
    )
}

#[test]
fn finite_hostile_corpus_is_total_for_every_schema() {
    for schema in SCHEMA_REGISTRY {
        for length in 0..=96 {
            let zeros = vec![0_u8; length];
            let ones = vec![0xff_u8; length];
            let ascending: Vec<u8> = (0_u8..=u8::MAX).cycle().take(length).collect();
            for input in [&zeros, &ones, &ascending] {
                let mut budget = DecodeBudget::new(1_048_576, 65_536);
                let _result = SchemaObject::decode_exact(schema.name, input, &mut budget);
                assert!(budget.remaining_bytes() <= 1_048_576);
                assert!(budget.remaining_values() <= 65_536);
            }
        }
    }
}
