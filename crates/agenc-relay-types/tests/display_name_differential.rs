#![forbid(unsafe_code)]

//! Differential check of display-name preparation over the generated inputs:
//! the current adapter, the adapter it replaced and an RFC 8266 model.

#[path = "support/name_inputs.rs"]
mod name_inputs;

use std::error::Error;
use std::panic::{self, AssertUnwindSafe};

use agenc_relay_types::{
    DisplayName, MAX_DISPLAY_NAME_BYTES, MAX_PRECIS_INPUT_BYTES, ValidationError,
};
use name_inputs::{SPACE_SEPARATORS, for_each_input, nfkc};
use precis_profiles::Nickname;
use precis_profiles::precis_core::profile::PrecisFastInvocation as _;

type TestResult = Result<(), Box<dyn Error>>;
type Prepared = Result<String, ValidationError>;

const RANDOM_INPUTS: usize = 500_000;

/// The replaced adapter: spaces collapsed once, then the dependency's own
/// enforcement and the display-name bound.
fn previous_prepare(input: &str) -> Prepared {
    if input.len() > MAX_PRECIS_INPUT_BYTES {
        return Err(ValidationError::TooLong);
    }
    let mut canonical = String::new();
    let mut pending_space = false;
    for character in input.chars() {
        if SPACE_SEPARATORS.contains(&character) {
            pending_space = !canonical.is_empty();
            continue;
        }
        if pending_space {
            canonical.push(' ');
            pending_space = false;
        }
        canonical.push(character);
    }
    let prepared = Nickname::enforce(canonical).map_err(|_| ValidationError::PrecisRejected)?;
    if prepared.len() > MAX_DISPLAY_NAME_BYTES {
        return Err(ValidationError::TooLong);
    }
    Ok(prepared.into_owned())
}

/// The RFC 8266 additional mapping rule (Section 2.1, rule 2).
fn model_map_spaces(text: &str) -> String {
    text.split(|character| SPACE_SEPARATORS.contains(&character))
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// RFC 8266 enforcement (Section 2.3): the FreeformClass check of Section
/// 2.2, the additional mapping rule, NFKC and the non-empty check, repeated
/// until stable for at most four applications (Section 2.1 and RFC 8264
/// Section 7), with the adapter's input and result bounds.
fn model_prepare(input: &str) -> Prepared {
    if input.len() > MAX_PRECIS_INPUT_BYTES {
        return Err(ValidationError::TooLong);
    }
    let mut current = input.to_owned();
    for _application in 0..4 {
        Nickname::prepare(current.as_str()).map_err(|_| ValidationError::PrecisRejected)?;
        let next = nfkc(&model_map_spaces(&current));
        if next.is_empty() {
            return Err(ValidationError::PrecisRejected);
        }
        if next == current {
            if current.len() > MAX_DISPLAY_NAME_BYTES {
                return Err(ValidationError::TooLong);
            }
            return Ok(current);
        }
        current = next;
    }
    Err(ValidationError::PrecisRejected)
}

#[derive(Debug, Default)]
struct Tally {
    inputs: usize,
    prepared: usize,
    unchanged: usize,
    changed: usize,
    no_previous_result: usize,
}

#[test]
fn preparation_equals_the_model_and_changes_only_results_the_model_differs_from() -> TestResult {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let mut tally = Tally::default();
    let mut differences = Vec::new();
    for_each_input(RANDOM_INPUTS, |input| {
        tally.inputs += 1;
        let current = DisplayName::prepare(input).map(|prepared| prepared.as_str().to_owned());
        let model = model_prepare(input);
        if current.is_ok() {
            tally.prepared += 1;
        }
        if current != model {
            differences.push(format!("model {input:?}: {current:?} != {model:?}"));
        }
        let previous = panic::catch_unwind(AssertUnwindSafe(|| previous_prepare(input)));
        match &previous {
            Ok(previous) if *previous == current => tally.unchanged += 1,
            Ok(previous) => {
                tally.changed += 1;
                if *previous == model {
                    differences.push(format!("changed {input:?}: {previous:?} -> {current:?}"));
                }
            }
            Err(_) => tally.no_previous_result += 1,
        }
        // A name either revision returned is a name the other accepts
        // unchanged: stored names restore and mixed revisions interoperate.
        if let Ok(Ok(name)) = &previous
            && DisplayName::prepare(name).map(|again| again.as_str() == name) != Ok(true)
        {
            differences.push(format!("previous name {name:?} not kept"));
        }
        if let Ok(name) = &current
            && !matches!(
                panic::catch_unwind(AssertUnwindSafe(|| previous_prepare(name))),
                Ok(Ok(again)) if again == *name
            )
        {
            differences.push(format!(
                "current name {name:?} not kept by the previous adapter"
            ));
        }
    });
    panic::set_hook(hook);
    println!("{tally:?}");
    differences.truncate(20);
    assert!(differences.is_empty(), "{differences:#?}");
    assert_eq!(
        tally.inputs,
        tally.unchanged + tally.changed + tally.no_previous_result
    );
    assert!(tally.inputs > 3_000_000);
    Ok(())
}
