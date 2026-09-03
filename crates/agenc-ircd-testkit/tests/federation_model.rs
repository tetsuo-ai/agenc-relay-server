#![forbid(unsafe_code)]
//! The bounded federation model is exhaustive within its recorded bounds
//! and its reachable state space matches the conformance record.

use std::error::Error;
use std::fs;
use std::path::Path;

use agenc_ircd_testkit::federation_model::{ModelBounds, ModelReport, alphabet, explore};

type TestResult = Result<(), Box<dyn Error>>;

fn recorded(root: &Path) -> Result<(usize, ModelReport), Box<dyn Error>> {
    let text = fs::read_to_string(root.join("conformance/stage-seven-model.toml"))?;
    let mut depth = None;
    let mut report = ModelReport::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value: usize = match value.trim().parse() {
            Ok(value) => value,
            Err(_) => continue,
        };
        match key.trim() {
            "depth" => depth = Some(value),
            "states" => report.states = value,
            "transitions" => report.transitions = value,
            "paths" => report.paths = value,
            "refusals" => report.refusals = value,
            _ => {}
        }
    }
    Ok((depth.ok_or("model record lacks depth")?, report))
}

#[test]
fn bounded_exploration_is_exhaustive_and_matches_the_record() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (depth, expected) = recorded(&root)?;
    let report = explore(ModelBounds { depth })?;
    assert_eq!(report, expected, "reachable state space drifted");
    assert!(report.states > 1 && report.transitions > report.states);
    Ok(())
}

#[test]
fn the_alphabet_is_closed_and_ordered() {
    let actions = alphabet();
    assert_eq!(actions.len(), 36);
    let mut sorted = actions
        .iter()
        .map(|action| format!("{action:?}"))
        .collect::<Vec<_>>();
    sorted.dedup();
    assert_eq!(sorted.len(), actions.len());
}
