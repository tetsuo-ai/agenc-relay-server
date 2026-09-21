#![forbid(unsafe_code)]

//! Bounded reassembly: order, budgets, deadlines, and identity checks.

use std::error::Error;

use agenc_relay_types::{BASE_FRAGMENT_BYTES, BASE_INCOMPLETE_OBJECTS_PER_LINK};

use super::*;
use crate::objects::federation_object_id;
use crate::text::FederationFragment;

type TestResult = Result<(), Box<dyn Error>>;

const IDLE_MILLIS: u64 = 15_000;
const TOTAL_MILLIS: u64 = 120_000;

fn key() -> FragmentDescriptorKey {
    FragmentDescriptorKey::derive("FREQUEST", &["a", "b"])
}

fn object(fill: u8, length: usize) -> Vec<u8> {
    vec![fill; length]
}

fn fragments(encoded: &[u8]) -> Result<Vec<FederationFragment>, Box<dyn Error>> {
    Ok(split_fragments(federation_object_id(encoded), encoded)?)
}

fn complete(progress: AssemblyProgress) -> Option<AssembledObject> {
    match progress {
        AssemblyProgress::Complete(object) => Some(object),
        AssemblyProgress::Incomplete { .. } => None,
    }
}

#[test]
fn descriptor_keys_are_length_prefixed_and_distinct() {
    assert_eq!(
        key(),
        FragmentDescriptorKey::derive("FREQUEST", &["a", "b"])
    );
    assert_ne!(key(), FragmentDescriptorKey::derive("FREQUEST", &["ab"]));
    assert_ne!(key(), FragmentDescriptorKey::derive("FRESULT", &["a", "b"]));
    assert_ne!(
        key(),
        FragmentDescriptorKey::derive("FREQUEST", &["a", "b", ""])
    );
}

#[test]
fn single_and_multi_fragment_objects_assemble_in_order() -> TestResult {
    let mut assembler = FragmentAssembler::new();
    let small = object(1, 100);
    let parts = fragments(&small)?;
    assert_eq!(parts.len(), 1);
    let first = parts.first().ok_or("missing fragment")?;
    let done = complete(assembler.admit(key(), first, 0)?).ok_or("expected completion")?;
    assert_eq!(done.as_slice(), small.as_slice());
    assert_eq!(done.len(), 100);
    assert!(!done.is_empty());
    assert_eq!(done.object_id(), federation_object_id(&small));
    assert_eq!(assembler.incomplete_objects(), 0);
    assert_eq!(assembler.reserved_bytes(), 0);

    let fragment_bytes = usize::try_from(BASE_FRAGMENT_BYTES)?;
    let large = object(2, fragment_bytes * 2 + 17);
    let parts = fragments(&large)?;
    assert_eq!(parts.len(), 3);
    let mut result = None;
    for (index, part) in parts.iter().enumerate() {
        let progress = assembler.admit(key(), part, u64::try_from(index)? * 1_000)?;
        match progress {
            AssemblyProgress::Incomplete { received, count } => {
                assert_eq!(received, u32::try_from(index)? + 1);
                assert_eq!(count, 3);
                assert_eq!(assembler.reserved_bytes(), large.len());
            }
            AssemblyProgress::Complete(object) => result = Some(object),
        }
    }
    let done = result.ok_or("expected completion")?;
    assert_eq!(done.as_slice(), large.as_slice());
    assert_eq!(assembler.reserved_bytes(), 0);
    Ok(())
}

#[test]
fn order_duplicate_descriptor_and_header_violations_drop_the_object() -> TestResult {
    let fragment_bytes = usize::try_from(BASE_FRAGMENT_BYTES)?;
    let large = object(3, fragment_bytes * 3);
    let parts = fragments(&large)?;
    let (first, second, third) = (
        parts.first().ok_or("part 0")?,
        parts.get(1).ok_or("part 1")?,
        parts.get(2).ok_or("part 2")?,
    );

    let mut assembler = FragmentAssembler::new();
    assert_eq!(
        assembler.admit(key(), second, 0).err(),
        Some(AssemblyError::OutOfOrder)
    );
    assert_eq!(assembler.incomplete_objects(), 0);

    assembler.admit(key(), first, 0)?;
    assert_eq!(
        assembler.admit(key(), third, 1).err(),
        Some(AssemblyError::OutOfOrder)
    );
    assert_eq!(assembler.incomplete_objects(), 0);
    assert_eq!(assembler.reserved_bytes(), 0);

    assembler.admit(key(), first, 0)?;
    assembler.admit(key(), second, 1)?;
    assert_eq!(
        assembler.admit(key(), second, 2).err(),
        Some(AssemblyError::DuplicatePart)
    );

    assembler.admit(key(), first, 0)?;
    let other_key = FragmentDescriptorKey::derive("FREQUEST", &["a", "c"]);
    assert_eq!(
        assembler.admit(other_key, second, 1).err(),
        Some(AssemblyError::DescriptorMismatch)
    );

    assembler.admit(key(), first, 0)?;
    let object_id = federation_object_id(&large);
    let shorter_total = FederationFragment::new(
        object_id,
        1,
        2,
        u32::try_from(fragment_bytes * 2)?,
        second.segment(),
    )?;
    assert_eq!(
        assembler.admit(key(), &shorter_total, 1).err(),
        Some(AssemblyError::HeaderMismatch)
    );
    assert_eq!(assembler.incomplete_objects(), 0);
    Ok(())
}

#[test]
fn identity_mismatch_is_detected_at_completion() -> TestResult {
    let mut assembler = FragmentAssembler::new();
    let bytes = object(4, 50);
    let wrong_id = federation_object_id(b"something else");
    let parts = split_fragments(wrong_id, &bytes)?;
    let first = parts.first().ok_or("part 0")?;
    assert_eq!(
        assembler.admit(key(), first, 0).err(),
        Some(AssemblyError::ObjectIdMismatch)
    );
    assert_eq!(assembler.reserved_bytes(), 0);
    Ok(())
}

#[test]
fn incomplete_object_count_is_capped_at_the_link_ceiling() -> TestResult {
    let mut assembler = FragmentAssembler::new();
    let fragment_bytes = usize::try_from(BASE_FRAGMENT_BYTES)?;
    let limit = usize::try_from(BASE_INCOMPLETE_OBJECTS_PER_LINK)?;
    let mut leftover = None;
    for index in 0..=limit {
        let fill = u8::try_from(index)?;
        let bytes = object(fill, fragment_bytes + 1);
        let parts = fragments(&bytes)?;
        let first = parts.first().ok_or("part 0")?;
        if index < limit {
            assembler.admit(key(), first, 0)?;
        } else {
            assert_eq!(
                assembler.admit(key(), first, 0).err(),
                Some(AssemblyError::TooManyIncomplete)
            );
            leftover = Some(bytes);
        }
    }
    assert_eq!(assembler.incomplete_objects(), limit);
    assert_eq!(assembler.reserved_bytes(), limit * (fragment_bytes + 1));
    let bytes = leftover.ok_or("missing leftover")?;
    assert!(assembler.abandon(&federation_object_id(&object(0, fragment_bytes + 1))));
    assert!(!assembler.abandon(&federation_object_id(&bytes)));
    assert_eq!(assembler.incomplete_objects(), limit - 1);
    Ok(())
}

#[test]
fn idle_and_total_deadlines_expire_objects() -> TestResult {
    let fragment_bytes = usize::try_from(BASE_FRAGMENT_BYTES)?;
    let large = object(5, fragment_bytes * 14);
    let parts = fragments(&large)?;
    let first = parts.first().ok_or("part 0")?;
    let second = parts.get(1).ok_or("part 1")?;

    let mut assembler = FragmentAssembler::new();
    assembler.admit(key(), first, 0)?;
    assert!(matches!(
        assembler.admit(key(), second, IDLE_MILLIS - 1),
        Ok(AssemblyProgress::Incomplete { .. })
    ));
    assembler.abandon(&federation_object_id(&large));

    assembler.admit(key(), first, 0)?;
    assert_eq!(
        assembler.admit(key(), second, IDLE_MILLIS).err(),
        Some(AssemblyError::Timeout)
    );
    assert_eq!(assembler.incomplete_objects(), 0);

    let mut now = 0;
    assembler.admit(key(), first, now)?;
    let mut failure = None;
    for part in parts.iter().skip(1) {
        now += 10_000;
        match assembler.admit(key(), part, now) {
            Ok(_) => {}
            Err(error) => {
                failure = Some((now, error));
                break;
            }
        }
    }
    assert_eq!(failure, Some((TOTAL_MILLIS, AssemblyError::Timeout)));

    assembler.admit(key(), first, 0)?;
    let other = object(6, fragment_bytes * 2);
    let other_parts = fragments(&other)?;
    assembler.admit(key(), other_parts.first().ok_or("part 0")?, 5_000)?;
    assert_eq!(assembler.expire(IDLE_MILLIS - 1), 0);
    assert_eq!(assembler.expire(IDLE_MILLIS), 1);
    assert_eq!(assembler.incomplete_objects(), 1);
    assert_eq!(assembler.expire(IDLE_MILLIS + 5_000), 1);
    assert_eq!(assembler.reserved_bytes(), 0);
    Ok(())
}

#[test]
fn split_fragments_rejects_oversized_and_empty_objects() {
    let id = FederationHash32::from_bytes([0; 32]);
    assert!(split_fragments(id, &[]).is_err());
    let oversized = vec![0_u8; 262_145];
    assert!(split_fragments(id, &oversized).is_err());
    assert!(!AssemblyError::Timeout.to_string().is_empty());
}
