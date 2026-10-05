#![forbid(unsafe_code)]

//! Capability value and ECAP tuple tests.

use std::error::Error;

use agenc_relay_federation_wire::E2EE_PROFILE_TOKEN;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

const NETWORK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const COORDINATOR: &str = "AAAAAAAAAAAAAAAAAAAAAQ";

#[test]
fn the_capability_value_is_exact() {
    assert_eq!(
        check_capability_value(crate::limits::CAPABILITY_VALUE),
        Ok(())
    );
    assert_eq!(
        check_capability_value("v1,profile=AAAA,seg=2940,obj=262144,parts=90,welcome=4194304"),
        Err(E2eeError::ProfileMismatch)
    );
    assert!(crate::limits::CAPABILITY_VALUE.contains(E2EE_PROFILE_TOKEN));
}

/// The E2EE profile token of release candidate 3, before the ReInit target
/// revision moved the profile hash (`docs/stage-10-reinit-target-revision.md`).
const RC3_PROFILE_TOKEN: &str = "wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U";
/// The release candidate 3 capability value, byte for byte.
const RC3_CAPABILITY_VALUE: &str = "v1,profile=wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U,seg=2940,obj=262144,parts=90,welcome=4194304";
/// The profile tokens of drafts of that revision that were never adopted:
/// the program's superseded first round and the two revisions of its
/// earlier rehearsal.
const DRAFT_PROFILE_TOKENS: [&str; 3] = [
    "wdFNKl0-6lCHsd81UTpS74BG2BGg0yZUURoRCzwEkO8",
    "7IkMThzSxSXro80LOF4RPUlMHJzf1GcDPZDiHxk9U-0",
    "fApHHjGXpxyWRFMLG00LDDpXjORF6u13LPffgT2ALY0",
];

#[test]
fn the_previous_profile_and_its_drafts_are_refused() -> TestResult {
    assert_eq!(
        check_capability_value(RC3_CAPABILITY_VALUE),
        Err(E2eeError::ProfileMismatch)
    );
    let local = EcapTuple::local(NETWORK, COORDINATOR, 0, NETWORK)?;
    for token in std::iter::once(RC3_PROFILE_TOKEN).chain(DRAFT_PROFILE_TOKENS) {
        assert_ne!(token, E2EE_PROFILE_TOKEN);
        let value = crate::limits::CAPABILITY_VALUE.replacen(E2EE_PROFILE_TOKEN, token, 1);
        assert_eq!(
            check_capability_value(&value),
            Err(E2eeError::ProfileMismatch),
            "{token}"
        );
        let mut rendered = local.render();
        if let Some(slot) = rendered.get_mut(1) {
            *slot = token.to_owned();
        }
        let borrowed: Vec<&str> = rendered.iter().map(String::as_str).collect();
        assert_eq!(
            EcapTuple::parse(&borrowed),
            Err(E2eeError::ProfileMismatch),
            "{token}"
        );
        let mut offer = vec!["ARCMLS", "OFFER"];
        offer.extend(borrowed.iter().copied());
        assert_eq!(
            crate::federation::frames::parse_companion_frame("ECAP", &offer, None),
            Err(E2eeError::ProfileMismatch),
            "{token}"
        );
    }
    // The current profile still parses on the same path.
    let current = local.render();
    let mut offer = vec!["ARCMLS", "OFFER"];
    offer.extend(current.iter().map(String::as_str));
    assert!(crate::federation::frames::parse_companion_frame("ECAP", &offer, None).is_ok());
    Ok(())
}

#[test]
fn the_ecap_tuple_renders_and_parses_exactly() -> TestResult {
    let local = EcapTuple::local(NETWORK, COORDINATOR, 0, NETWORK)?;
    let rendered = local.render();
    assert_eq!(rendered.len(), 12);
    assert_eq!(rendered.get(4).map(String::as_str), Some("2940"));
    assert_eq!(rendered.get(9).map(String::as_str), Some("8191"));
    let borrowed: Vec<&str> = rendered.iter().map(String::as_str).collect();
    assert_eq!(EcapTuple::parse(&borrowed)?, local);
    Ok(())
}

#[test]
fn every_tuple_deviation_is_a_profile_mismatch() -> TestResult {
    let local = EcapTuple::local(NETWORK, COORDINATOR, 3, NETWORK)?;
    let rendered = local.render();
    for (index, replacement) in [
        (0, "2"),
        (1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        (2, "short"),
        (3, "AAAAAAAAAAAAAAAAAAAAA"),
        (4, "2939"),
        (9, "8192"),
        (11, "x"),
    ] {
        let mut changed = rendered.clone();
        if let Some(slot) = changed.get_mut(index) {
            *slot = replacement.to_owned();
        }
        let borrowed: Vec<&str> = changed.iter().map(String::as_str).collect();
        assert_eq!(
            EcapTuple::parse(&borrowed),
            Err(E2eeError::ProfileMismatch),
            "field {index}"
        );
    }
    let mut bad_decimal = rendered.clone();
    if let Some(slot) = bad_decimal.get_mut(10) {
        *slot = "01".to_owned();
    }
    let borrowed: Vec<&str> = bad_decimal.iter().map(String::as_str).collect();
    assert_eq!(EcapTuple::parse(&borrowed), Err(E2eeError::InvalidValue));
    let short: Vec<&str> = rendered.iter().take(11).map(String::as_str).collect();
    assert_eq!(EcapTuple::parse(&short), Err(E2eeError::InvalidValue));
    assert_eq!(
        EcapTuple::local("bad", COORDINATOR, 0, NETWORK),
        Err(E2eeError::ProfileMismatch)
    );
    Ok(())
}

#[test]
fn decimals_are_canonical() {
    assert_eq!(canonical_decimal("0"), Ok(0));
    assert_eq!(canonical_decimal("18446744073709551615"), Ok(u64::MAX));
    assert_eq!(canonical_decimal("00"), Err(E2eeError::InvalidValue));
    assert_eq!(canonical_decimal(""), Err(E2eeError::InvalidValue));
    assert_eq!(canonical_decimal("+1"), Err(E2eeError::InvalidValue));
    assert_eq!(
        canonical_decimal("18446744073709551616"),
        Err(E2eeError::InvalidValue)
    );
    assert!(is_hash_token(NETWORK));
    assert!(!is_hash_token("AAAA"));
    assert!(is_id16_token(COORDINATOR));
    assert!(!is_id16_token("AAAAAAAAAAAAAAAAAAAAA+"));
}
