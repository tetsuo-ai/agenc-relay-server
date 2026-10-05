#![forbid(unsafe_code)]

//! Stage-01 canonical client text-carrier boundary tests.

use std::error::Error;

use agenc_relay_client_wire::{
    CanonicalBase64Url, E2EE_OBJECT_KINDS, E2eeFragment, E2eeObjectKind, E2eeRequestCommand,
    ExactArity, MAX_E2EE_FRAGMENT_BYTES, MAX_E2EE_FRAGMENT_COUNT, MAX_E2EE_OBJECT_BYTES,
    MailboxKind, SafeLabel, TextCarrierError, parse_u16_decimal, parse_u32_decimal,
    parse_u64_decimal, validate_uppercase_token,
};

#[test]
fn canonical_base64url_rejects_padding_alphabets_and_unused_bits() -> Result<(), Box<dyn Error>> {
    let token = CanonicalBase64Url::from_bytes(&[0_u8], 1, 1)?;
    assert_eq!(token.to_text()?, "AA");
    assert_eq!(CanonicalBase64Url::parse("AA", 1, 1)?.as_bytes(), &[0]);
    assert!(matches!(
        CanonicalBase64Url::parse("AA==", 1, 1),
        Err(TextCarrierError::TooLong | TextCarrierError::InvalidCharacter)
    ));
    assert!(matches!(
        CanonicalBase64Url::parse("+/", 1, 2),
        Err(TextCarrierError::InvalidCharacter)
    ));
    assert!(matches!(
        CanonicalBase64Url::parse("AB", 1, 1),
        Err(TextCarrierError::NonCanonical)
    ));
    assert!(matches!(
        CanonicalBase64Url::parse("", 1, 1),
        Err(TextCarrierError::Empty)
    ));
    assert_eq!(
        CanonicalBase64Url::parse("A", 0, 3).err(),
        Some(TextCarrierError::NonCanonical)
    );
    assert_eq!(
        CanonicalBase64Url::parse("AA", 2, 3).err(),
        Some(TextCarrierError::WrongLength)
    );
    Ok(())
}

#[test]
fn canonical_decimals_cover_zero_maximum_and_invalid_forms() -> Result<(), TextCarrierError> {
    assert_eq!(parse_u16_decimal("0")?, 0);
    assert_eq!(parse_u16_decimal("65535")?, u16::MAX);
    assert_eq!(parse_u32_decimal("4294967295")?, u32::MAX);
    assert_eq!(parse_u64_decimal("18446744073709551615")?, u64::MAX);
    assert_eq!(parse_u16_decimal("00"), Err(TextCarrierError::NonCanonical));
    assert_eq!(
        parse_u16_decimal("+1"),
        Err(TextCarrierError::InvalidCharacter)
    );
    assert_eq!(
        parse_u16_decimal("-1"),
        Err(TextCarrierError::InvalidCharacter)
    );
    assert_eq!(
        parse_u16_decimal("65536"),
        Err(TextCarrierError::OutOfRange)
    );
    assert_eq!(
        parse_u64_decimal("18446744073709551616"),
        Err(TextCarrierError::OutOfRange)
    );
    Ok(())
}

#[test]
fn uppercase_tokens_and_exact_arity_reject_variants() -> Result<(), TextCarrierError> {
    validate_uppercase_token("REINIT-ACK")?;
    assert_eq!(
        validate_uppercase_token("ReInit"),
        Err(TextCarrierError::InvalidCharacter)
    );
    let arity = ExactArity::new(2);
    arity.validate(&["one", "two"])?;
    assert_eq!(arity.validate(&["one"]), Err(TextCarrierError::WrongArity));
    assert_eq!(
        arity.validate(&["one", "two", "three"]),
        Err(TextCarrierError::WrongArity)
    );
    Ok(())
}

#[test]
fn e2ee_fragment_round_trips_boundaries_and_rejects_inconsistency() -> Result<(), Box<dyn Error>> {
    let first_segment = vec![7_u8; MAX_E2EE_FRAGMENT_BYTES];
    let first = E2eeFragment::new([3_u8; 32], 0, 2, 2_941, &first_segment)?;
    let first_text = first.to_text()?;
    let parsed_first = E2eeFragment::parse(&first_text)?;
    assert_eq!(parsed_first.object_id(), &[3_u8; 32]);
    assert_eq!(parsed_first.part(), 0);
    assert_eq!(parsed_first.count(), 2);
    assert_eq!(parsed_first.total(), 2_941);
    assert_eq!(parsed_first.segment(), first_segment);

    let final_fragment = E2eeFragment::new([3_u8; 32], 1, 2, 2_941, &[9])?;
    assert_eq!(
        E2eeFragment::parse(&final_fragment.to_text()?)?.segment(),
        &[9]
    );
    assert!(matches!(
        E2eeFragment::new([0; 32], 0, 1, 2_941, &first_segment),
        Err(TextCarrierError::FragmentRange)
    ));
    assert!(matches!(
        E2eeFragment::new([0; 32], 2, 2, 2_941, &[0]),
        Err(TextCarrierError::FragmentRange)
    ));
    assert!(matches!(
        E2eeFragment::parse(&first_text.replacen(".0.2.", ".00.2.", 1)),
        Err(TextCarrierError::NonCanonical)
    ));
    assert!(matches!(
        E2eeFragment::parse(&first_text.replacen("v1.", "V1.", 1)),
        Err(TextCarrierError::InvalidFragment)
    ));
    Ok(())
}

#[test]
fn closed_e2ee_tokens_match_the_documented_registry() -> Result<(), TextCarrierError> {
    assert_eq!(E2eeRequestCommand::parse("EGROUP")?.as_str(), "EGROUP");
    assert_eq!(E2eeRequestCommand::parse("EKEY")?.as_str(), "EKEY");
    assert!(E2eeRequestCommand::parse("egroup").is_err());
    assert_eq!(
        MailboxKind::parse("STAGED-REINIT")?.as_str(),
        "STAGED-REINIT"
    );
    assert!(MailboxKind::parse("STAGED_REINIT").is_err());
    for token in E2EE_OBJECT_KINDS {
        assert_eq!(E2eeObjectKind::parse(token)?.as_str(), *token);
    }
    // Companion 11.7 lists 37 kinds; the last four map to ordinals 34 to 37.
    assert_eq!(E2EE_OBJECT_KINDS.len(), 37);
    assert_eq!(
        E2EE_OBJECT_KINDS.get(33..),
        Some(
            &[
                "POLICY",
                "RECOVERY-SUBMISSION",
                "WITNESS-RESOLUTION",
                "LEAF-MEMBERSHIP-PROOF"
            ][..]
        )
    );
    assert!(E2eeObjectKind::parse("FUTURE-KIND").is_err());
    assert_eq!(SafeLabel::parse("a_B-9")?.as_str(), "a_B-9");
    assert!(SafeLabel::parse("escaped\\label").is_err());
    assert!(SafeLabel::parse(&"a".repeat(65)).is_err());
    Ok(())
}

#[test]
fn carrier_primitives_cover_empty_length_and_registry_boundaries() -> Result<(), TextCarrierError> {
    assert_eq!(
        CanonicalBase64Url::parse("", 2, 1).err(),
        Some(TextCarrierError::OutOfRange)
    );
    assert_eq!(CanonicalBase64Url::parse("", 0, 0)?.as_bytes(), b"");
    assert_eq!(
        CanonicalBase64Url::from_bytes(b"a", 2, 3).err(),
        Some(TextCarrierError::WrongLength)
    );
    assert_eq!(
        CanonicalBase64Url::from_bytes(b"abcd", 1, 3).err(),
        Some(TextCarrierError::TooLong)
    );

    assert_eq!(parse_u16_decimal(""), Err(TextCarrierError::Empty));
    assert_eq!(parse_u16_decimal("123456"), Err(TextCarrierError::TooLong));
    assert_eq!(
        parse_u32_decimal("12345678901"),
        Err(TextCarrierError::TooLong)
    );
    assert_eq!(validate_uppercase_token(""), Err(TextCarrierError::Empty));
    validate_uppercase_token("A1-B")?;

    assert_eq!(SafeLabel::parse("").err(), Some(TextCarrierError::Empty));
    assert_eq!(MailboxKind::parse("APPLICATION")?.as_str(), "APPLICATION");
    assert_eq!(MailboxKind::parse("BINDING")?.as_str(), "BINDING");
    assert_eq!(MailboxKind::parse("WELCOME")?.as_str(), "WELCOME");
    Ok(())
}

#[test]
fn fragment_arithmetic_rejects_each_inconsistent_scalar() -> Result<(), TextCarrierError> {
    let full = vec![1_u8; MAX_E2EE_FRAGMENT_BYTES];
    let one = [1_u8];
    assert_eq!(
        E2eeFragment::new([0; 32], 0, 0, 1, &one).err(),
        Some(TextCarrierError::FragmentRange)
    );
    assert_eq!(
        E2eeFragment::new(
            [0; 32],
            0,
            MAX_E2EE_FRAGMENT_COUNT + 1,
            MAX_E2EE_OBJECT_BYTES,
            &full
        )
        .err(),
        Some(TextCarrierError::FragmentRange)
    );
    assert_eq!(
        E2eeFragment::new([0; 32], 0, 2, 1, &one).err(),
        Some(TextCarrierError::FragmentRange)
    );
    assert_eq!(
        E2eeFragment::new([0; 32], 1, 1, 1, &one).err(),
        Some(TextCarrierError::FragmentRange)
    );
    assert_eq!(
        E2eeFragment::new([0; 32], 0, 1, 1, &full).err(),
        Some(TextCarrierError::FragmentRange)
    );
    assert_eq!(
        E2eeFragment::new([0; 32], 0, 1, 0, &one).err(),
        Some(TextCarrierError::FragmentRange)
    );
    assert_eq!(
        E2eeFragment::new([0; 32], 0, 1, MAX_E2EE_OBJECT_BYTES + 1, &one).err(),
        Some(TextCarrierError::FragmentRange)
    );

    let object = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(
        E2eeFragment::parse(&format!("v1.{object}.10000.1.1.AA")).err(),
        Some(TextCarrierError::TooLong)
    );
    assert_eq!(
        E2eeFragment::parse(&format!("v1.{object}.0.1.10000000.AA")).err(),
        Some(TextCarrierError::TooLong)
    );
    assert_eq!(
        E2eeFragment::parse(&format!("v1.{object}.0.1.1.AA.extra")).err(),
        Some(TextCarrierError::InvalidFragment)
    );
    Ok(())
}

#[test]
fn fragment_scalar_validation_precedes_segment_decoding() {
    let object = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(
        E2eeFragment::parse(&format!("v1.{object}.0.2.1.!")).err(),
        Some(TextCarrierError::FragmentRange)
    );
    assert_eq!(
        E2eeFragment::parse(&format!("v1.{object}.0.1.1.!")).err(),
        Some(TextCarrierError::InvalidCharacter)
    );
}

#[test]
fn carrier_errors_have_closed_context_free_messages() {
    let cases = [
        (TextCarrierError::Empty, "text carrier token is empty"),
        (
            TextCarrierError::TooLong,
            "text carrier token exceeds its bound",
        ),
        (
            TextCarrierError::InvalidCharacter,
            "text carrier token contains an invalid character",
        ),
        (
            TextCarrierError::NonCanonical,
            "text carrier token is not canonical",
        ),
        (
            TextCarrierError::WrongLength,
            "text carrier token has the wrong decoded length",
        ),
        (
            TextCarrierError::OutOfRange,
            "text carrier decimal is outside its range",
        ),
        (
            TextCarrierError::WrongArity,
            "text carrier command has the wrong arity",
        ),
        (
            TextCarrierError::UnknownToken,
            "text carrier token is not registered",
        ),
        (
            TextCarrierError::InvalidFragment,
            "E2EE fragment grammar is invalid",
        ),
        (
            TextCarrierError::FragmentRange,
            "E2EE fragment fields are inconsistent",
        ),
        (
            TextCarrierError::Overflow,
            "text carrier calculation overflowed",
        ),
        (
            TextCarrierError::AllocationFailed,
            "text carrier allocation failed",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}
