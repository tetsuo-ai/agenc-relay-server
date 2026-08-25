#![forbid(unsafe_code)]

//! Stage-01 canonical base-federation text-carrier boundary tests.

use std::error::Error;

use agenc_ircd_federation_wire::{
    FEDERATION_COMMAND_FORMS, FederationFragment, FederationHash32, FederationId16,
    FederationTextError, FragmentTagPolicy, StarCursor, StarId, parse_federation_u32,
    parse_federation_u64, validate_federation_command,
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
    for descriptor in FEDERATION_COMMAND_FORMS {
        let mut parameters = Vec::new();
        if let Some(subcommand) = descriptor.subcommand {
            parameters.push(subcommand);
        }
        parameters.extend(std::iter::repeat_n("x", descriptor.parameter_count));
        let tagged = descriptor.fragment_tag == FragmentTagPolicy::Required;
        let selected = validate_federation_command(descriptor.command, &parameters, tagged)?;
        assert_eq!(selected.form, descriptor.form);
        assert_eq!(
            validate_federation_command(descriptor.command, &parameters, !tagged),
            Err(FederationTextError::WrongTagPolicy)
        );
        parameters.push("trailing");
        assert_eq!(
            validate_federation_command(descriptor.command, &parameters, tagged),
            Err(FederationTextError::WrongArity)
        );
    }
    assert!(validate_federation_command("fhello", &["x", "x"], false).is_err());
    assert!(validate_federation_command("FUTURE", &[], false).is_err());
    assert!(validate_federation_command("FORIGIN", &["UNKNOWN"], false).is_err());
    Ok(())
}

#[test]
fn federation_fragment_round_trips_and_checks_exact_partition() -> Result<(), Box<dyn Error>> {
    let digest = FederationHash32::from_bytes([4_u8; 32]);
    let first_bytes = vec![5_u8; 2_940];
    let first = FederationFragment::new(digest, 0, 2, 2_941, &first_bytes)?;
    let parsed = FederationFragment::parse(&first.to_text())?;
    assert_eq!(parsed.object_id().as_bytes(), digest.as_bytes());
    assert_eq!(parsed.part(), 0);
    assert_eq!(parsed.count(), 2);
    assert_eq!(parsed.total(), 2_941);
    assert_eq!(parsed.segment(), first_bytes);

    let final_fragment = FederationFragment::new(digest, 1, 2, 2_941, &[6])?;
    assert_eq!(
        FederationFragment::parse(&final_fragment.to_text())?.segment(),
        &[6]
    );
    assert!(FederationFragment::new(digest, 0, 1, 2_941, &first_bytes).is_err());
    assert!(FederationFragment::new(digest, 2, 2, 2_941, &[6]).is_err());
    assert!(FederationFragment::new(digest, 0, 1, 0, &[6]).is_err());
    assert!(FederationFragment::parse("v2.bad.0.1.1.AA").is_err());
    Ok(())
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
        validate_federation_command("", &[], false).err(),
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
