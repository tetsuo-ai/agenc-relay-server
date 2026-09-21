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
