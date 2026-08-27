#![forbid(unsafe_code)]

//! Stage-01 canonical base-federation text-carrier boundary tests.

use std::error::Error;

use agenc_ircd_federation_wire::{
    FEDERATION_COMMAND_FORMS, FEDERATION_FRAGMENT_TAG_NAME, FederationCommandTag,
    FederationCommandTags, FederationFragment, FederationFragmentText, FederationHash32,
    FederationId16, FederationTextError, FragmentTagPolicy, StarCursor, StarId,
    parse_federation_u32, parse_federation_u64, validate_federation_command,
};
use agenc_ircd_types::{BASE_FRAGMENT_BYTES, BASE_FRAGMENT_COUNT, BASE_OBJECT_BYTES};

#[test]
fn fixed_tokens_and_decimals_reject_noncanonical_forms() -> Result<(), Box<dyn Error>> {
    let identifier = FederationId16::from_bytes([1_u8; 16]);
    assert_eq!(
        FederationId16::parse(&identifier.to_text())?.as_bytes(),
        &[1_u8; 16]
    );
    let digest = FederationHash32::from_bytes([2_u8; 32]);
    assert_eq!(
        FederationHash32::parse(&digest.to_text())?.as_bytes(),
        &[2_u8; 32]
    );
    assert!(FederationId16::parse("AAAAAAAAAAAAAAAAAAAAAA=").is_err());
    assert!(FederationHash32::parse(&format!("{}+", "A".repeat(42))).is_err());
    assert!(FederationHash32::parse(&format!("{}B", "A".repeat(42))).is_err());

    assert_eq!(parse_federation_u32("0")?, 0);
    assert_eq!(parse_federation_u32("4294967295")?, u32::MAX);
    assert_eq!(parse_federation_u64("18446744073709551615")?, u64::MAX);
    assert_eq!(
        parse_federation_u32("01"),
        Err(FederationTextError::NonCanonical)
    );
    assert!(parse_federation_u32("+1").is_err());
    assert!(parse_federation_u32("4294967296").is_err());
    assert_eq!(StarCursor::parse("*")?, StarCursor::Star);
    assert_eq!(StarCursor::parse("9")?, StarCursor::Value(9));
    assert!(matches!(StarId::parse("*")?, StarId::Star));
    assert!(matches!(
        StarId::parse(&identifier.to_text())?,
        StarId::Value(_)
    ));
    Ok(())
}

#[test]
fn every_frozen_command_form_enforces_case_arity_and_tag_policy() -> Result<(), Box<dyn Error>> {
    assert_eq!(FEDERATION_COMMAND_FORMS.len(), 22);
    let fragment_text = valid_fragment_tag_text()?;
    let raw_fragment_tag = [FederationCommandTag::new(
        FEDERATION_FRAGMENT_TAG_NAME,
        Some(fragment_text.as_str()),
    )];
    let fragment_tags = FederationCommandTags::parse(&raw_fragment_tag)?;
    let empty_tags = FederationCommandTags::empty();
    for descriptor in FEDERATION_COMMAND_FORMS {
        let mut parameters = Vec::new();
        if let Some(subcommand) = descriptor.subcommand {
            parameters.push(subcommand);
        }
        parameters.extend(std::iter::repeat_n("x", descriptor.parameter_count));
        let (accepted_tags, rejected_tags) =
            if descriptor.fragment_tag == FragmentTagPolicy::Required {
                (&fragment_tags, &empty_tags)
            } else {
                (&empty_tags, &fragment_tags)
            };
        let selected = validate_federation_command(descriptor.command, &parameters, accepted_tags)?;
        assert_eq!(selected.form, descriptor.form);
        assert_eq!(
            validate_federation_command(descriptor.command, &parameters, rejected_tags),
            Err(FederationTextError::WrongTagPolicy)
        );
        parameters.push("trailing");
        assert_eq!(
            validate_federation_command(descriptor.command, &parameters, accepted_tags),
            Err(FederationTextError::WrongArity)
        );
    }
    assert!(validate_federation_command("fhello", &["x", "x"], &empty_tags).is_err());
    assert!(validate_federation_command("FUTURE", &[], &empty_tags).is_err());
    assert!(validate_federation_command("FORIGIN", &["UNKNOWN"], &empty_tags).is_err());
    Ok(())
}

#[test]
fn federation_command_tags_reject_every_noncanonical_set() -> Result<(), Box<dyn Error>> {
    let fragment_text = valid_fragment_tag_text()?;
    let fragment_tag =
        FederationCommandTag::new(FEDERATION_FRAGMENT_TAG_NAME, Some(fragment_text.as_str()));
    assert_eq!(fragment_tag.name(), FEDERATION_FRAGMENT_TAG_NAME);
    assert_eq!(fragment_tag.value(), Some(fragment_text.as_str()));

    let valid_tags = FederationCommandTags::parse(&[fragment_tag])?;
    assert_eq!(
        valid_tags.fragment().map(FederationFragment::segment),
        Some(&[1_u8][..])
    );
    assert!(
        FederationCommandTags::parse(&[] as &[FederationCommandTag<'_>])?
            .fragment()
            .is_none()
    );

    let duplicate_tags = [fragment_tag, fragment_tag];
    assert_eq!(
        FederationCommandTags::parse(&duplicate_tags).err(),
        Some(FederationTextError::WrongTagPolicy)
    );
    for invalid_tag in [
        FederationCommandTag::new("example.org/extra", Some("value")),
        FederationCommandTag::new("+agenc.ag/fed", Some(fragment_text.as_str())),
        FederationCommandTag::new(FEDERATION_FRAGMENT_TAG_NAME, None),
        FederationCommandTag::new(FEDERATION_FRAGMENT_TAG_NAME, Some("")),
    ] {
        assert_eq!(
            FederationCommandTags::parse(&[invalid_tag]).err(),
            Some(FederationTextError::WrongTagPolicy)
        );
    }
    assert!(
        FederationCommandTags::parse(&[FederationCommandTag::new(
            FEDERATION_FRAGMENT_TAG_NAME,
            Some("not-a-fragment"),
        )])
        .is_err()
    );
    let oversized_value = "x".repeat(4_001);
    assert_eq!(
        FederationCommandTags::parse(&[FederationCommandTag::new(
            FEDERATION_FRAGMENT_TAG_NAME,
            Some(&oversized_value),
        )])
        .err(),
        Some(FederationTextError::TooLong)
    );
    Ok(())
}

fn valid_fragment_tag_text() -> Result<FederationFragmentText, FederationTextError> {
    FederationFragment::new(FederationHash32::from_bytes([9_u8; 32]), 0, 1, 1, &[1])?.to_text()
}

#[test]
fn federation_fragment_round_trips_and_checks_exact_partition() -> Result<(), Box<dyn Error>> {
    let digest = FederationHash32::from_bytes([4_u8; 32]);
    let first_bytes = vec![5_u8; 2_940];
    let first = FederationFragment::new(digest, 0, 2, 2_941, &first_bytes)?;
    let first_text = first.to_text()?;
    let parsed = FederationFragment::parse(first_text.as_str())?;
    assert_eq!(parsed.object_id().as_bytes(), digest.as_bytes());
    assert_eq!(parsed.part(), 0);
    assert_eq!(parsed.count(), 2);
    assert_eq!(parsed.total(), 2_941);
    assert_eq!(parsed.segment(), first_bytes);

    let final_fragment = FederationFragment::new(digest, 1, 2, 2_941, &[6])?;
    let final_text = final_fragment.to_text()?;
    assert_eq!(
        FederationFragment::parse(final_text.as_str())?.segment(),
        &[6]
    );
    assert!(FederationFragment::new(digest, 0, 1, 2_941, &first_bytes).is_err());
    assert!(FederationFragment::new(digest, 2, 2, 2_941, &[6]).is_err());
    assert!(FederationFragment::new(digest, 0, 1, 0, &[6]).is_err());
    assert!(FederationFragment::parse("v2.bad.0.1.1.AA").is_err());
    Ok(())
}

#[test]
fn federation_fragment_rejects_header_before_decoding_segment() {
    let object = FederationHash32::from_bytes([8_u8; 32]).to_text();
    assert_eq!(
        FederationFragment::parse(&format!("v1.{object}.0.0.1.AB")).err(),
        Some(FederationTextError::FragmentRange)
    );
    assert_eq!(
        FederationFragment::parse(&format!("v1.{object}.0.1.1.AB")).err(),
        Some(FederationTextError::NonCanonical)
    );
    assert_eq!(
        FederationFragment::parse(&format!("v1.{object}.0.1.1.AAA")).err(),
        Some(FederationTextError::FragmentRange)
    );
}

#[test]
fn text_boundaries_reject_each_fragment_scalar_independently() -> Result<(), Box<dyn Error>> {
    let digest = FederationHash32::from_bytes([7_u8; 32]);
    let one = [1_u8];
    let maximum_fragment = usize::try_from(BASE_FRAGMENT_BYTES)?;
    let full = vec![1_u8; maximum_fragment];
    let maximum_count = u32::try_from(BASE_FRAGMENT_COUNT)?;
    let maximum_total = u32::try_from(BASE_OBJECT_BYTES)?;

    assert_eq!(
        FederationFragment::new(digest, 0, 1, maximum_total + 1, &one).err(),
        Some(FederationTextError::FragmentRange)
    );
    assert_eq!(
        FederationFragment::new(digest, 0, 0, 1, &one).err(),
        Some(FederationTextError::FragmentRange)
    );
    assert_eq!(
        FederationFragment::new(digest, 0, maximum_count + 1, maximum_total, &full).err(),
        Some(FederationTextError::FragmentRange)
    );
    assert_eq!(
        FederationFragment::new(digest, 1, 1, 1, &one).err(),
        Some(FederationTextError::FragmentRange)
    );
    assert_eq!(
        FederationFragment::new(digest, 0, 2, 1, &one).err(),
        Some(FederationTextError::FragmentRange)
    );
    assert_eq!(
        FederationFragment::new(digest, 0, 1, 1, &full).err(),
        Some(FederationTextError::FragmentRange)
    );

    let object = digest.to_text();
    assert_eq!(
        FederationFragment::parse(&format!("v1.{object}.0.1.1.")).err(),
        Some(FederationTextError::Empty)
    );
    assert_eq!(
        FederationFragment::parse(&format!("v1.{object}.0.1.1.AA.extra")).err(),
        Some(FederationTextError::InvalidFragment)
    );
    assert_eq!(
        FederationFragment::parse(&format!(
            "v1.{object}.0.1.1.{}",
            "A".repeat(maximum_fragment * 2)
        ))
        .err(),
        Some(FederationTextError::TooLong)
    );
    Ok(())
}

#[test]
fn decimals_commands_and_errors_cover_closed_alternatives() {
    assert_eq!(parse_federation_u32(""), Err(FederationTextError::Empty));
    assert_eq!(
        parse_federation_u32("12345678901"),
        Err(FederationTextError::TooLong)
    );
    assert_eq!(
        parse_federation_u64("123456789012345678901"),
        Err(FederationTextError::TooLong)
    );
    assert_eq!(
        validate_federation_command("", &[], &FederationCommandTags::empty()).err(),
        Some(FederationTextError::Empty)
    );

    let cases = [
        (FederationTextError::Empty, "federation text token is empty"),
        (
            FederationTextError::TooLong,
            "federation text token exceeds its bound",
        ),
        (
            FederationTextError::InvalidCharacter,
            "federation text token contains an invalid character",
        ),
        (
            FederationTextError::NonCanonical,
            "federation text token is not canonical",
        ),
        (
            FederationTextError::WrongLength,
            "federation text token has the wrong decoded length",
        ),
        (
            FederationTextError::OutOfRange,
            "federation decimal is outside its range",
        ),
        (
            FederationTextError::UnknownCommandForm,
            "federation command form is not registered",
        ),
        (
            FederationTextError::WrongArity,
            "federation command form has the wrong arity",
        ),
        (
            FederationTextError::WrongTagPolicy,
            "federation fragment-tag policy is violated",
        ),
        (
            FederationTextError::InvalidFragment,
            "federation fragment grammar is invalid",
        ),
        (
            FederationTextError::FragmentRange,
            "federation fragment fields are inconsistent",
        ),
        (
            FederationTextError::Overflow,
            "federation text calculation overflowed",
        ),
        (
            FederationTextError::AllocationFailed,
            "federation text allocation failed",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn fixed_text_boundaries_distinguish_shape_alphabet_and_range_errors() {
    assert_eq!(
        FederationId16::parse(&"A".repeat(21)).err(),
        Some(FederationTextError::WrongLength)
    );
    assert_eq!(
        FederationId16::parse(&"A".repeat(23)).err(),
        Some(FederationTextError::WrongLength)
    );

    let mut invalid_alphabet = "A".repeat(22);
    invalid_alphabet.replace_range(21..22, "!");
    assert_eq!(
        FederationId16::parse(&invalid_alphabet).err(),
        Some(FederationTextError::InvalidCharacter)
    );

    let mut noncanonical_trailing_bits = "A".repeat(22);
    noncanonical_trailing_bits.replace_range(21..22, "B");
    assert_eq!(
        FederationId16::parse(&noncanonical_trailing_bits).err(),
        Some(FederationTextError::NonCanonical)
    );

    assert_eq!(
        parse_federation_u64("1844674407370955161x"),
        Err(FederationTextError::InvalidCharacter)
    );
    assert_eq!(
        parse_federation_u64("18446744073709551616"),
        Err(FederationTextError::OutOfRange)
    );
}

#[test]
fn maximum_fragment_round_trips_through_move_only_text() -> Result<(), Box<dyn Error>> {
    let maximum_fragment = usize::try_from(BASE_FRAGMENT_BYTES)?;
    let maximum_total = u32::try_from(BASE_FRAGMENT_BYTES)?;
    let segment = vec![0xa5; maximum_fragment];
    let fragment = FederationFragment::new(
        FederationHash32::from_bytes([0x5a; 32]),
        0,
        1,
        maximum_total,
        &segment,
    )?;

    let text = fragment.to_text()?;
    assert!(!text.is_empty());
    assert_eq!(text.len(), text.as_str().len());
    assert_eq!(text.as_ref(), text.as_str());

    let parsed = FederationFragment::parse(text.as_str())?;
    assert_eq!(parsed.part(), 0);
    assert_eq!(parsed.count(), 1);
    assert_eq!(parsed.total(), maximum_total);
    assert_eq!(parsed.segment(), segment);

    Ok(())
}
