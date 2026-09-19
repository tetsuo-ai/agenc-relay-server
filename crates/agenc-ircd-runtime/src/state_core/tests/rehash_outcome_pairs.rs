//! An audited reload accepts only a success and failure outcome that differ
//! in nothing but their phase and that both record a REHASH.
#![forbid(unsafe_code)]

use agenc_ircd_admin::AdminAuditPhase::{Observed, OutcomeFailure, OutcomeSuccess};

use super::support::{audit_event, audit_event_at};
use super::*;
use crate::state_core::valid_rehash_outcome_pair;

const REHASH: &[u8] = b"REHASH :reload now";

#[test]
fn a_matching_rehash_success_and_failure_pair_is_valid() -> TestResult {
    let success = audit_event(OutcomeSuccess, REHASH)?;
    let failure = audit_event(OutcomeFailure, REHASH)?;
    assert!(valid_rehash_outcome_pair(&success, &failure));
    Ok(())
}

#[test]
fn a_pair_with_either_phase_wrong_is_invalid() -> TestResult {
    let success = audit_event(OutcomeSuccess, REHASH)?;
    let failure = audit_event(OutcomeFailure, REHASH)?;
    let observed = audit_event(Observed, REHASH)?;
    assert!(!valid_rehash_outcome_pair(&observed, &failure));
    assert!(!valid_rehash_outcome_pair(&success, &observed));
    assert!(!valid_rehash_outcome_pair(&failure, &success));
    Ok(())
}

#[test]
fn a_pair_recording_another_command_is_invalid() -> TestResult {
    for command in [&b"MOTD"[..], b"rehash :reload now", b"REHASH"] {
        let success = audit_event(OutcomeSuccess, command)?;
        let failure = audit_event(OutcomeFailure, command)?;
        assert!(
            !valid_rehash_outcome_pair(&success, &failure),
            "{}",
            String::from_utf8_lossy(command)
        );
    }
    Ok(())
}

#[test]
fn a_pair_whose_events_differ_beyond_their_phase_is_invalid() -> TestResult {
    let success = audit_event(OutcomeSuccess, REHASH)?;
    let later_failure = audit_event_at(OutcomeFailure, REHASH, 51)?;
    let other_failure = audit_event(OutcomeFailure, b"REHASH :another reason")?;
    assert!(!valid_rehash_outcome_pair(&success, &later_failure));
    assert!(!valid_rehash_outcome_pair(&success, &other_failure));
    Ok(())
}
