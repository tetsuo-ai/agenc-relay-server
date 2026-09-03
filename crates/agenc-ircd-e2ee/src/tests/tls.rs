#![forbid(unsafe_code)]

//! Codec conformance: widths, bounds, budgets, and complete consumption.

use std::error::Error;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

tls_struct! {
    /// A structure exercising every field kind.
    pub(super) struct Sample {
        /// Version.
        pub(super) version: u16,
        /// Fixed bytes.
        pub(super) id: [u8; 4],
        /// Short opaque.
        pub(super) name: Opaque<1, 255>,
        /// Wide opaque.
        pub(super) blob: Opaque<0, 70_000>,
        /// Items.
        pub(super) items: TlsVec<u16, 0, 65_535>,
        /// Counter.
        pub(super) counter: u64,
    }
}

tls_enum! {
    /// A two-value enumeration.
    pub(super) enum Kind: u8 {
        /// One.
        One = 1,
        /// Two.
        Two = 2,
    }
}

fn sample() -> Result<Sample, E2eeError> {
    Ok(Sample {
        version: 1,
        id: [9; 4],
        name: Opaque::from_slice(b"abc")?,
        blob: Opaque::new(vec![7; 300])?,
        items: TlsVec::new(vec![1, 2, 3])?,
        counter: u64::MAX,
    })
}

#[test]
fn widths_follow_the_declared_bound() {
    assert_eq!(LengthWidth::for_maximum(255), LengthWidth::U8);
    assert_eq!(LengthWidth::for_maximum(256), LengthWidth::U16);
    assert_eq!(LengthWidth::for_maximum(65_535), LengthWidth::U16);
    assert_eq!(LengthWidth::for_maximum(65_536), LengthWidth::U24);
    assert_eq!(LengthWidth::for_maximum(16_777_215), LengthWidth::U24);
    assert_eq!(LengthWidth::for_maximum(16_777_216), LengthWidth::U32);
}

#[test]
fn a_structure_round_trips_byte_for_byte() -> TestResult {
    let value = sample()?;
    let encoded = value.encode()?;
    // version(2) id(4) name(1+3) blob(3+300) items(2+6) counter(8)
    assert_eq!(encoded.len(), 2 + 4 + 4 + 303 + 8 + 8);
    assert_eq!(encoded.get(6..7), Some(&[3_u8][..]));
    assert_eq!(encoded.get(10..13), Some(&[0_u8, 1, 44][..]));
    let mut budget = DecodeBudget::new(1 << 16, 64);
    let decoded = Sample::decode_exact(&encoded, &mut budget)?;
    assert_eq!(decoded, value);
    assert_eq!(decoded.encode()?, encoded);
    Ok(())
}

#[test]
fn trailing_and_truncated_input_are_refused() -> TestResult {
    let encoded = sample()?.encode()?;
    let mut trailing = encoded.clone();
    trailing.push(0);
    let mut budget = DecodeBudget::new(1 << 16, 64);
    assert_eq!(
        Sample::decode_exact(&trailing, &mut budget),
        Err(E2eeError::TrailingBytes)
    );
    let truncated = encoded.get(..encoded.len() - 1).unwrap_or_default();
    let mut budget = DecodeBudget::new(1 << 16, 64);
    assert_eq!(
        Sample::decode_exact(truncated, &mut budget),
        Err(E2eeError::Truncated)
    );
    Ok(())
}

#[test]
fn bounds_are_enforced_on_both_sides() -> TestResult {
    assert_eq!(
        Opaque::<1, 255>::new(Vec::new()),
        Err(E2eeError::LengthOutOfRange)
    );
    assert_eq!(
        Opaque::<1, 255>::new(vec![0; 256]),
        Err(E2eeError::LengthOutOfRange)
    );
    // A zero-length prefix under a minimum of one is refused on decode.
    let mut budget = DecodeBudget::new(1 << 16, 64);
    assert_eq!(
        Opaque::<1, 255>::decode_exact(&[0], &mut budget),
        Err(E2eeError::LengthOutOfRange)
    );
    Ok(())
}

#[test]
fn vectors_decode_until_their_declared_bytes_are_exhausted() -> TestResult {
    // Three u16 items in six bytes.
    let encoded = [0_u8, 6, 0, 1, 0, 2, 0, 3];
    let mut budget = DecodeBudget::new(1 << 16, 64);
    let items: TlsVec<u16, 0, 65_535> = TlsVec::decode_exact(&encoded, &mut budget)?;
    assert_eq!(items.as_slice(), &[1, 2, 3]);
    // A length that splits an item is truncated inside the vector.
    let odd = [0_u8, 5, 0, 1, 0, 2, 0];
    let mut budget = DecodeBudget::new(1 << 16, 64);
    assert_eq!(
        TlsVec::<u16, 0, 65_535>::decode_exact(&odd, &mut budget),
        Err(E2eeError::Truncated)
    );
    Ok(())
}

#[test]
fn budgets_bound_copies_and_values() -> TestResult {
    let encoded = sample()?.encode()?;
    let mut bytes = DecodeBudget::new(100, 64);
    assert_eq!(
        Sample::decode_exact(&encoded, &mut bytes),
        Err(E2eeError::BudgetExceeded)
    );
    let mut values = DecodeBudget::new(1 << 16, 3);
    assert_eq!(
        Sample::decode_exact(&encoded, &mut values),
        Err(E2eeError::BudgetExceeded)
    );
    let mut enough = DecodeBudget::new(1 << 16, 5);
    assert!(Sample::decode_exact(&encoded, &mut enough).is_ok());
    assert_eq!(enough.remaining_values(), 0);
    assert_eq!(enough.remaining_bytes(), (1 << 16) - 303);
    Ok(())
}

#[test]
fn enumerations_are_closed() -> TestResult {
    assert_eq!(Kind::from_value(2), Ok(Kind::Two));
    assert_eq!(Kind::from_value(3), Err(E2eeError::UnknownDiscriminant));
    assert_eq!(Kind::ALL, &[Kind::One, Kind::Two]);
    let mut budget = DecodeBudget::new(16, 4);
    assert_eq!(Kind::decode_exact(&[1], &mut budget), Ok(Kind::One));
    assert_eq!(Kind::Two.encode()?, vec![2]);
    Ok(())
}

#[test]
fn u24_lengths_encode_and_decode() -> TestResult {
    let value = Opaque::<0, 70_000>::new(vec![1; 65_536])?;
    let encoded = value.encode()?;
    assert_eq!(encoded.get(..3), Some(&[1_u8, 0, 0][..]));
    let mut budget = DecodeBudget::new(1 << 20, 4);
    assert_eq!(
        Opaque::<0, 70_000>::decode_exact(&encoded, &mut budget)?,
        value
    );
    Ok(())
}

#[test]
fn canonical_order_is_strictly_increasing() {
    assert_eq!(ensure_canonical(&[1, 2, 3], |item| *item), Ok(()));
    assert_eq!(
        ensure_canonical(&[1, 1], |item| *item),
        Err(E2eeError::NonCanonical)
    );
    assert_eq!(
        ensure_canonical(&[2, 1], |item| *item),
        Err(E2eeError::NonCanonical)
    );
    assert_eq!(ensure_canonical::<u8, u8>(&[], |item| *item), Ok(()));
}

#[test]
fn fixed_and_optional_shapes_are_checked() -> TestResult {
    let sixteen = Opaque::<0, 16>::new(vec![1; 16])?;
    assert_eq!(sixteen.exactly::<16>()?, [1; 16]);
    assert_eq!(sixteen.empty_or_fixed::<16>()?, Some([1; 16]));
    let empty = Opaque::<0, 16>::new(Vec::new())?;
    assert_eq!(empty.empty_or_fixed::<16>()?, None);
    assert_eq!(empty.exactly::<16>(), Err(E2eeError::InvalidValue));
    let short = Opaque::<0, 16>::new(vec![1; 3])?;
    assert_eq!(short.empty_or_fixed::<16>(), Err(E2eeError::InvalidValue));
    Ok(())
}
