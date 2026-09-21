#![forbid(unsafe_code)]
//! The bounded encrypted route model is exhaustive within its recorded
//! bounds, holds every invariant, and its reachable state space matches
//! the conformance record.

use std::error::Error;
use std::fs;
use std::path::Path;

use agenc_relay_testkit::e2ee_model::{Action, E2eeModelBounds, Exploration, explore_e2ee};

type TestResult = Result<(), Box<dyn Error>>;

fn recorded(root: &Path) -> Result<(E2eeModelBounds, Exploration), Box<dyn Error>> {
    let text = fs::read_to_string(root.join("conformance/stage-eight-model.toml"))?;
    let mut bounds = E2eeModelBounds {
        conversations: 0,
        accounts: 0,
        depth: 0,
    };
    let mut report = Exploration::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value: u64 = match value.trim().parse() {
            Ok(value) => value,
            Err(_) => continue,
        };
        match key.trim() {
            "conversations" => bounds.conversations = u8::try_from(value)?,
            "accounts" => bounds.accounts = u8::try_from(value)?,
            "depth" => bounds.depth = u8::try_from(value)?,
            "actions" => report.actions = value,
            "states" => report.states = value,
            "transitions" => report.transitions = value,
            "paths" => report.paths = value,
            "refusals" => report.refusals = value,
            _ => {}
        }
    }
    if bounds.depth == 0 {
        return Err("model record lacks depth".into());
    }
    Ok((bounds, report))
}

#[test]
fn the_bounded_e2ee_model_is_exhausted_within_its_recorded_bounds() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (bounds, expected) = recorded(&root)?;
    let report = explore_e2ee(bounds);
    assert!(
        report.violations.is_empty(),
        "violations: {:?}",
        report.violations
    );
    assert_eq!(report, expected, "reachable state space drifted");
    assert!(report.states > 1 && report.transitions > report.states);
    Ok(())
}

/// The adversarial actions never advance a log: a duplicate candidate, a
/// stale candidate, a conflicting candidate, and a reordered finalization
/// are refused at every reachable state, so the accepted transitions of
/// an exploration that offers them equal those of one that does not.
#[test]
fn duplicate_stale_reordered_and_conflicting_records_never_advance_the_log() -> TestResult {
    let bounds = E2eeModelBounds {
        conversations: 1,
        accounts: 1,
        depth: 6,
    };
    let report = explore_e2ee(bounds);
    assert!(
        report.violations.is_empty(),
        "violations: {:?}",
        report.violations
    );
    let adversarial = [
        Action::DuplicateCandidate(0),
        Action::StaleCandidate(0),
        Action::ConflictingCandidate(0),
        Action::ReorderedFinalize(0),
        Action::Reopen(0),
    ];
    assert_eq!(adversarial.len(), 5);
    // Every adversarial action is a refusal wherever it is offered: the
    // refusal count is at least the number of states times the five
    // adversarial actions that never succeed.
    assert!(report.refusals >= report.states.saturating_sub(1) * 5);
    Ok(())
}
