#![forbid(unsafe_code)]

//! COV-01: the per-argument refusals in the administrative command registry
//! that the Stage 10 report recorded as never executed.
//!
//! Every case parses a canonical line through `AdminCommand::parse`, so each
//! refusal is the one an operator would receive, and every line differs from an
//! accepted line in exactly one argument.

use super::*;

/// A valid identifier argument in the 22-character canonical form.
const ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";

/// Every registry arm that parses an identifier and a reason refuses each of
/// them independently, and the accepted line differs only in that argument.
#[test]
fn each_identifier_and_reason_argument_is_refused_on_its_own() -> Result<(), AdminError> {
    let long_token = "p".repeat(65);
    let refusals = [
        format!("PONG {long_token}"),
        format!("KILL {ID} :"),
        "CHANNEL QUARANTINE not-an-id :reason here".to_owned(),
        format!("CHANNEL QUARANTINE {ID} :"),
        "CHANNEL HISTORY PURGE not-an-id :reason here".to_owned(),
        format!("CHANNEL HISTORY PURGE {ID} :"),
        "CONNECT not-an-id :reason here".to_owned(),
        format!("CONNECT {ID} :"),
        "SQUIT not-an-id :reason here".to_owned(),
        format!("SQUIT {ID} :"),
        "PEER QUARANTINE not-an-id :reason here".to_owned(),
        format!("PEER QUARANTINE {ID} :"),
    ];
    for text in &refusals {
        assert_eq!(parse(text).err(), Some(AdminError::Argument), "{text}");
    }

    // The same verbs accept the same shapes once the refused argument is
    // replaced, so each refusal above rests on that argument alone.
    for text in [
        "PONG abc".to_owned(),
        format!("KILL {ID} :abuse report"),
        format!("CHANNEL QUARANTINE {ID} :reason here"),
        format!("CHANNEL HISTORY PURGE {ID} :reason here"),
        format!("CONNECT {ID} :reason here"),
        format!("SQUIT {ID} :reason here"),
        format!("PEER QUARANTINE {ID} :reason here"),
    ] {
        parse(&text)?;
    }
    Ok(())
}

/// Every confirmed process command reports its own verb in FAIL and NOTE
/// replies, so a refused RESTART is never reported as a DIE.
#[test]
fn the_process_commands_report_their_own_verbs() -> Result<(), AdminError> {
    assert_eq!(parse("RESTART :soon ok")?.verb(), "RESTART");
    assert_eq!(parse("DIE :bye now")?.verb(), "DIE");
    assert!(parse("RESTART :soon ok")?.needs_confirmation());
    assert!(!parse("RESTART :soon ok")?.is_read_only());
    Ok(())
}
