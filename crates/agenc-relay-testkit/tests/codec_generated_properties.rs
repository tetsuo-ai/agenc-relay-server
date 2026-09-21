#![forbid(unsafe_code)]

//! Deterministic generated properties for every frozen Appendix-B schema.

use std::collections::TryReserveError;
use std::error::Error;

use agenc_relay_federation_wire::{CanonicalEncode, DecodeBudget, SCHEMA_REGISTRY, SchemaObject};
use agenc_relay_testkit::parse_reference_vectors;
use agenc_relay_types::BASE_OBJECT_BYTES;

const VECTORS: &str = include_str!("../../../test-data/vectors/base-federation-v1.vectors");
const VALUE_BUDGET: usize = 1_000_000;
const FIXED_BOUNDARY_LENGTHS: &[usize] = &[
    0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 95, 96, 255, 256, 257, 4_095, 4_096, 4_097,
    65_535, 65_536, 65_537,
];

#[test]
fn generated_codec_corpus_stays_bounded_and_round_trips() -> Result<(), Box<dyn Error>> {
    let maximum_object_bytes = usize::try_from(BASE_OBJECT_BYTES)?;
    let decode_byte_budget = maximum_object_bytes
        .checked_mul(2)
        .ok_or("decode byte budget overflowed usize")?;
    let boundary_lengths = boundary_lengths(maximum_object_bytes)?;
    let vectors = parse_reference_vectors(VECTORS)?;

    assert_eq!(vectors.len(), SCHEMA_REGISTRY.len());
    for (schema_index, schema) in SCHEMA_REGISTRY.iter().enumerate() {
        let vector = vectors
            .iter()
            .find(|vector| vector.schema() == schema.name)
            .ok_or_else(|| format!("missing reference vector for {}", schema.name))?;
        assert_decode_properties(
            schema.name,
            vector.bytes(),
            decode_byte_budget,
            maximum_object_bytes,
        )?;

        for (length_index, length) in boundary_lengths.iter().copied().enumerate() {
            let input = generated_input(schema_index, length_index, length)?;
            assert_decode_properties(
                schema.name,
                &input,
                decode_byte_budget,
                maximum_object_bytes,
            )?;
        }
    }
    Ok(())
}

fn boundary_lengths(maximum_object_bytes: usize) -> Result<Vec<usize>, Box<dyn Error>> {
    let maximum_plus_one = maximum_object_bytes
        .checked_add(1)
        .ok_or("maximum object length overflowed usize")?;
    let maximum_minus_one = maximum_object_bytes
        .checked_sub(1)
        .ok_or("maximum object length cannot have a lower boundary")?;
    let mut lengths = Vec::new();
    lengths.try_reserve_exact(FIXED_BOUNDARY_LENGTHS.len() + 3)?;
    lengths.extend_from_slice(FIXED_BOUNDARY_LENGTHS);
    lengths.push(maximum_minus_one);
    lengths.push(maximum_object_bytes);
    lengths.push(maximum_plus_one);
    Ok(lengths)
}

fn generated_input(
    schema_index: usize,
    length_index: usize,
    length: usize,
) -> Result<Vec<u8>, TryReserveError> {
    let mut state = 0x6a09_e667_f3bc_c909_u64
        ^ (schema_index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ (length_index as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    let mut input = Vec::new();
    input.try_reserve_exact(length)?;
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        input.push((state >> 32) as u8);
    }
    Ok(input)
}

fn assert_decode_properties(
    schema_name: &str,
    input: &[u8],
    decode_byte_budget: usize,
    maximum_object_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    let mut budget = DecodeBudget::new(decode_byte_budget, VALUE_BUDGET);
    let decoded = SchemaObject::decode_exact(schema_name, input, &mut budget);
    assert_budget_did_not_increase(&budget, decode_byte_budget);

    let Ok(decoded) = decoded else {
        return Ok(());
    };
    let canonical = decoded
        .encode_canonical()
        .map_err(|error| format!("{schema_name} could not re-encode after decode: {error}"))?;
    assert!(canonical.len() <= maximum_object_bytes);

    let mut round_trip_budget = DecodeBudget::new(decode_byte_budget, VALUE_BUDGET);
    let round_trip =
        SchemaObject::decode_exact(schema_name, canonical.as_slice(), &mut round_trip_budget)
            .map_err(|error| format!("{schema_name} rejected its canonical encoding: {error}"))?;
    assert_budget_did_not_increase(&round_trip_budget, decode_byte_budget);
    let reencoded = round_trip
        .encode_canonical()
        .map_err(|error| format!("{schema_name} could not encode twice: {error}"))?;
    assert_eq!(reencoded.as_slice(), canonical.as_slice());
    Ok(())
}

fn assert_budget_did_not_increase(budget: &DecodeBudget, initial_byte_budget: usize) {
    assert!(budget.remaining_bytes() <= initial_byte_budget);
    assert!(budget.remaining_values() <= VALUE_BUDGET);
}
