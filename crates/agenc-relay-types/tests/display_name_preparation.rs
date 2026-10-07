#![forbid(unsafe_code)]

//! Display-name preparation prepares or refuses every input without
//! panicking; spaces are collapsed after normalization (RFC 8266 Sections
//! 2.1 to 2.3).

#[path = "support/name_inputs.rs"]
mod name_inputs;

use std::error::Error;

use agenc_relay_types::{
    DisplayName, MAX_DISPLAY_NAME_BYTES, MAX_PRECIS_INPUT_BYTES, NormalizedLogin, ValidationError,
};
use name_inputs::{SPACE_SEPARATORS, for_each_input, nfkc, space_and_marks, space_producing};

type TestResult = Result<(), Box<dyn Error>>;

const RANDOM_INPUTS: usize = 200_000;
const CONTEXT_TEXT: [char; 5] = ['\u{00e9}', '\u{0101}', '\u{4e2d}', '\u{3042}', '\u{1f600}'];

/// Returns why `prepared` is not a stable RFC 8266 result, if it is not one.
fn prepared_form_problem(prepared: &str) -> Option<&'static str> {
    if prepared.is_empty() {
        return Some("empty");
    }
    if prepared.len() > MAX_DISPLAY_NAME_BYTES {
        return Some("longer than the display-name bound");
    }
    if prepared.starts_with(' ') || prepared.ends_with(' ') || prepared.contains("  ") {
        return Some("uncollapsed space");
    }
    if prepared
        .chars()
        .any(|character| character != ' ' && SPACE_SEPARATORS.contains(&character))
    {
        return Some("unmapped space separator");
    }
    if nfkc(prepared) != prepared {
        return Some("not NFKC");
    }
    match DisplayName::prepare(prepared) {
        Ok(again) if again.as_str() == prepared => None,
        Ok(_) => Some("changes when prepared again"),
        Err(_) => Some("refused when prepared again"),
    }
}

#[test]
fn every_generated_display_name_is_prepared_or_refused() -> TestResult {
    let mut visited = 0_usize;
    let mut prepared_count = 0_usize;
    let mut problems = Vec::new();
    for_each_input(RANDOM_INPUTS, |input| {
        visited += 1;
        match DisplayName::prepare(input) {
            Ok(prepared) => {
                prepared_count += 1;
                if let Some(problem) = prepared_form_problem(prepared.as_str()) {
                    problems.push(format!("{input:?} -> {:?}: {problem}", prepared.as_str()));
                }
            }
            Err(ValidationError::TooLong | ValidationError::PrecisRejected) => {}
            Err(error) => problems.push(format!("{input:?}: unexpected {error:?}")),
        }
        match NormalizedLogin::prepare(input) {
            Ok(_)
            | Err(
                ValidationError::TooShort
                | ValidationError::TooLong
                | ValidationError::PrecisRejected,
            ) => {}
            Err(error) => problems.push(format!("{input:?}: login {error:?}")),
        }
    });
    println!("display-name inputs: {visited}, prepared: {prepared_count}");
    problems.truncate(20);
    assert!(problems.is_empty(), "{problems:#?}");
    assert!(visited > 3_000_000 && prepared_count > 400_000);
    Ok(())
}

#[test]
fn spaces_from_normalization_are_collapsed() -> TestResult {
    let producing = space_producing();
    let marked = space_and_marks(&producing);
    assert!(marked.len() >= 20, "{} characters", marked.len());
    for &character in &marked {
        let normalized = nfkc(&character.to_string());
        let rest = normalized
            .strip_prefix(' ')
            .ok_or("normal form lost its space")?;
        for prefix in CONTEXT_TEXT {
            for (input, expected) in [
                (format!("{prefix} {character}"), format!("{prefix} {rest}")),
                (
                    format!("{prefix}{prefix} {character}"),
                    format!("{prefix}{prefix} {rest}"),
                ),
                (
                    format!("{prefix} {character} {prefix}"),
                    format!("{prefix} {rest} {prefix}"),
                ),
                (format!("{character}{prefix}"), format!("{rest}{prefix}")),
                (format!("{prefix}{character}"), format!("{prefix} {rest}")),
            ] {
                assert_eq!(
                    DisplayName::prepare(&input).map(|prepared| prepared.as_str().to_owned()),
                    Ok(expected),
                    "{input:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn every_scalar_value_in_context_is_prepared_or_refused() -> TestResult {
    let mut text = String::new();
    for value in 0_u32..=0x0010_ffff {
        let Some(character) = char::from_u32(value) else {
            continue;
        };
        for prefix in ["\u{4e2d} ", "\u{1f600}\u{00e9} "] {
            text.clear();
            text.push_str(prefix);
            text.push(character);
            for suffix in [None, Some(character)] {
                if let Some(suffix) = suffix {
                    text.push(suffix);
                }
                match DisplayName::prepare(&text) {
                    Ok(prepared) => {
                        if let Some(problem) = prepared_form_problem(prepared.as_str()) {
                            return Err(format!("{text:?}: {problem}").into());
                        }
                    }
                    Err(ValidationError::TooLong | ValidationError::PrecisRejected) => {}
                    Err(error) => return Err(format!("{text:?}: {error:?}").into()),
                }
            }
        }
    }
    Ok(())
}

#[test]
fn the_hostile_input_bound_is_checked_before_preparation() {
    let at_bound = "a".repeat(MAX_PRECIS_INPUT_BYTES);
    assert_eq!(
        DisplayName::prepare(&at_bound).err(),
        Some(ValidationError::TooLong)
    );
    let mut over_bound = "\u{4e2d}".repeat(MAX_PRECIS_INPUT_BYTES / 3);
    over_bound.push('\u{00e9}');
    assert!(over_bound.len() > MAX_PRECIS_INPUT_BYTES);
    assert_eq!(
        DisplayName::prepare(&over_bound).err(),
        Some(ValidationError::TooLong)
    );
}
