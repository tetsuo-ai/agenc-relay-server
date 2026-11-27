#![forbid(unsafe_code)]

use super::*;
use crate::test_support::{TestResult, negotiated_capabilities};
use agenc_relay_client_wire::{CapabilityState, FramedLine, numeric_reply, parse_message};

fn parsed(line: &str) -> TestResult<ParsedMessage> {
    parse_message(FramedLine::new(line)?)?.ok_or_else(|| "missing command".into())
}

fn requester(absent: u8) -> TestResult<MessageRequester> {
    Ok(MessageRequester {
        origin: ReplyRequester::new("Sam", &negotiated_capabilities(&["standard-replies"])?)?,
        absent,
    })
}

fn numeric(code: u16, nick: &str, args: &[&str], text: &str) -> TestResult<WireMessage> {
    Ok(numeric_reply("hub.example", code, nick, args, Some(text))?)
}

fn committed() -> ResultArm {
    ResultArm::Committed {
        resulting_state_generation: 4,
    }
}
fn failed(code: &str, context: &str) -> ResultArm {
    ResultArm::Failed {
        code: code.to_owned(),
        context: context.to_owned(),
    }
}

#[test]
fn mixed_results_project_original_scope_dialect_and_privacy() -> TestResult {
    let mixed = requester(0b0010)?;
    let message = parsed("PRIVMSG Zed,#Missing,#Bound,Alice :hi")?;
    let mut frames = vec![
        numeric(404, "sam", &["#bound"], "Cannot send to channel")?,
        numeric(481, "sam", &[], "Command is unavailable")?,
    ];
    assert_eq!(
        mixed.project("edge.example", &message, &committed(), &mut frames),
        Ok(())
    );
    assert!(matches!(frames.as_slice(), [locked, missing, denied] if
        locked.middle() == ["PRIVMSG", "E2EE_REQUIRED", "#Bound"] &&
        missing.middle() == ["Sam", "#Missing"] && missing.command()=="403" &&
        denied.middle() == ["Sam"] && denied.command()=="481"));
    let mut frames = vec![
        numeric(482, "sam", &["#bound"], "Permission denied for channel")?,
        numeric(481, "sam", &[], "Command is unavailable")?,
        numeric(401, "sam", &["zed"], "No such nick")?,
    ];
    assert_eq!(
        mixed.project(
            "edge.example",
            &message,
            &failed("NOT_ALLOWED", "#BOUND"),
            &mut frames
        ),
        Ok(())
    );
    assert_eq!(
        frames.iter().map(WireMessage::command).collect::<Vec<_>>(),
        ["482", "403", "481", "401"]
    );
    let single = parsed("TAGMSG #Hidden")?;
    let mut hidden = vec![numeric(403, "sam", &["#hidden"], "No such channel")?];
    let visible = requester(0)?;
    assert_eq!(
        visible.project(
            "edge.example",
            &single,
            &failed("SECRET_UNAVAILABLE", ""),
            &mut hidden
        ),
        Ok(())
    );
    assert_eq!(
        hidden.first().ok_or("no result")?.middle(),
        ["Sam", "#Hidden"]
    );
    Ok(())
}

#[test]
fn silence_and_old_command_level_failures_do_not_invent_a_disposition() -> TestResult {
    let requester = requester(0)?;
    let notice = parsed("NOTICE Absent :hi")?;
    for arm in [ResultArm::NoContent, committed(), failed("STALE_STATE", "")] {
        assert_eq!(
            requester.project("edge.example", &notice, &arm, &mut Vec::new()),
            Ok(())
        );
        let mut unexpected = vec![numeric(401, "sam", &["absent"], "No such nick")?];
        assert_eq!(
            requester.project("edge.example", &notice, &arm, &mut unexpected),
            Err(Violation::Consistency)
        );
    }
    let message = parsed("PRIVMSG Absent :hi")?;
    assert_eq!(
        requester.project(
            "edge.example",
            &message,
            &failed("STALE_STATE", ""),
            &mut Vec::new()
        ),
        Ok(())
    );
    assert_eq!(
        requester.project(
            "edge.example",
            &message,
            &ResultArm::NoContent,
            &mut Vec::new()
        ),
        Err(Violation::Consistency)
    );
    Ok(())
}

#[test]
fn result_must_match_every_original_recipient_target_and_failure() -> TestResult {
    let requester = requester(0b010)?;
    let message = parsed("PRIVMSG #A,#B,Cat :hi")?;
    let unknown = || numeric(401, "Sam", &["Cat"], "No such nick");
    let denied = || numeric(482, "Sam", &["#A"], "Permission denied for channel");
    for (arm, mut invalid) in [
        (
            committed(),
            vec![numeric(
                482,
                "other",
                &["#a"],
                "Permission denied for channel",
            )?],
        ),
        (
            committed(),
            vec![numeric(
                482,
                "Sam",
                &["#other"],
                "Permission denied for channel",
            )?],
        ),
        (
            committed(),
            vec![numeric(
                482,
                "Sam",
                &["#b"],
                "Permission denied for channel",
            )?],
        ),
        (
            committed(),
            vec![numeric(404, "Sam", &["Cat"], "Cannot send to channel")?],
        ),
        (
            committed(),
            vec![numeric(401, "Sam", &["#A"], "No such nick")?],
        ),
        (
            committed(),
            vec![numeric(401, "Sam", &["Cat"], "unregistered description")?],
        ),
        (
            committed(),
            vec![numeric(481, "Sam", &[], "unregistered policy description")?],
        ),
        (committed(), vec![denied()?, unknown()?]),
        (failed("NOT_ALLOWED", ""), vec![unknown()?]),
        (failed("STALE_STATE", ""), vec![unknown()?, denied()?]),
        (failed("NOT_ALLOWED", ""), vec![denied()?, denied()?]),
        (failed("NOT_ALLOWED", "Cat"), vec![denied()?, unknown()?]),
        (failed("STALE_STATE", ""), vec![denied()?, unknown()?]),
    ] {
        assert_eq!(
            requester.project("edge.example", &message, &arm, &mut invalid),
            Err(Violation::Consistency)
        );
    }
    let missing_operand = numeric(401, "Sam", &[], "No such nick")?;
    assert_eq!(covered_error(&missing_operand, "Sam", "Cat"), None);
    let empty = WireMessage::new("hub.example", "ACK", &[], None)?;
    assert_eq!(covered_error(&empty, "Sam", "Cat"), None);
    assert!(ReplyRequester::new(&"X".repeat(33), &CapabilityState::default()).is_err());
    Ok(())
}
