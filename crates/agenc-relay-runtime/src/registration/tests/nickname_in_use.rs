//! A nickname another connection holds is refused with 433, so the client can pick another
//! one instead of waiting for its registration deadline.
#![forbid(unsafe_code)]

use super::test_harness::{Harness, Role, TestResult, saw};

#[tokio::test]
async fn a_nickname_held_by_another_connection_answers_433() -> TestResult {
    for role in [Role::Hosted, Role::Plain] {
        let mut harness = Harness::new(role)?;
        let first = harness.open(1, true)?;
        harness.line(1, "NICK taken")?;
        assert!(!saw(&first, " 433 "), "lines: {:?}", first.lines());
        let second = harness.open(2, true)?;
        harness.line(2, "NICK taken")?;
        assert!(
            saw(&second, " 433 * taken :Nickname is already in use"),
            "lines: {:?}",
            second.lines()
        );
        harness.line(2, "NICK free")?;
        assert!(!saw(&second, " 433 * free "), "lines: {:?}", second.lines());
    }
    Ok(())
}
