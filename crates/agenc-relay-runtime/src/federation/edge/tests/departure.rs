#![forbid(unsafe_code)]

use super::*;
use crate::test_support::TestResult;
use agenc_relay_client_wire::{FramedLine, parse_message};

fn request() -> TestResult<ParsedMessage> {
    parse_message(FramedLine::new("PART #z,#a,#b")?)?.ok_or_else(|| "missing test request".into())
}

fn refused(nick: &str, name: &str) -> TestResult<WireMessage> {
    Ok(agenc_relay_client_wire::numeric_reply(
        "coordinator.example",
        482,
        nick,
        &[name],
        Some("Permission denied for channel"),
    )?)
}

fn failed(code: &str, context: &str) -> ResultArm {
    ResultArm::Failed {
        code: code.to_owned(),
        context: context.to_owned(),
    }
}

#[test]
fn current_and_legacy_departure_results_preserve_each_original_target() -> TestResult {
    let requester = PartRequester::new("Sam", &CapabilityState::default(), 0b010)?;
    let request = request()?;
    let committed = ResultArm::Committed {
        resulting_state_generation: 7,
    };
    let mut mixed = vec![refused("sam", "#z")?];
    assert_eq!(
        requester.project("edge.example", &request, &committed, &mut mixed),
        Ok(())
    );
    assert!(matches!(mixed.as_slice(), [missing, denied]
        if missing.command() == "403" && missing.middle() == ["Sam", "#b"]
        && denied.command() == "482" && denied.middle() == ["Sam", "#z"]));
    let mut all = vec![refused("Sam", "#a")?, refused("Sam", "#z")?];
    assert_eq!(
        requester.project(
            "edge.example",
            &request,
            &failed("NOT_ALLOWED", "#A"),
            &mut all,
        ),
        Ok(())
    );
    assert!(
        matches!(all.as_slice(), [first, missing, last] if first.middle() == ["Sam", "#a"]
        && missing.middle() == ["Sam", "#b"] && last.middle() == ["Sam", "#z"])
    );
    let mut absent_at_authority = vec![
        agenc_relay_client_wire::numeric_reply(
            "coordinator.example",
            403,
            "Sam",
            &["#a"],
            Some("No such channel"),
        )?,
        refused("Sam", "#z")?,
    ];
    assert_eq!(
        requester.project(
            "edge.example",
            &request,
            &failed("STALE_STATE", ""),
            &mut absent_at_authority
        ),
        Ok(())
    );
    assert!(
        matches!(absent_at_authority.as_slice(), [missing, _, _] if missing.command() == "403" && missing.middle() == ["Sam", "#a"])
    );
    // Both legacy encodings identify the first admitted canonical channel. Only the
    // local absence is independently known for the other targets.
    for context in ["", "#A"] {
        let mut coarse = Vec::new();
        assert_eq!(
            requester.project(
                "edge.example",
                &request,
                &failed("NOT_ALLOWED", context),
                &mut coarse
            ),
            Ok(())
        );
        assert!(matches!(coarse.as_slice(), [first, missing]
            if first.command() == "482" && first.middle() == ["Sam", "#a"]
            && missing.command() == "403" && missing.middle() == ["Sam", "#b"]));
    }
    for general in ["STALE_STATE", "SERVER_BUSY"] {
        let mut unanswered = Vec::new();
        assert_eq!(
            requester.project(
                "edge.example",
                &request,
                &failed(general, ""),
                &mut unanswered,
            ),
            Ok(())
        );
        assert!(unanswered.is_empty());
    }
    Ok(())
}

#[test]
fn a_departure_result_cannot_change_recipient_scope_order_or_coverage() -> TestResult {
    let requester = PartRequester::new("sam", &CapabilityState::default(), 0b010)?;
    let request = request()?;
    let committed = || ResultArm::Committed {
        resulting_state_generation: 7,
    };
    for (arm, mut replies) in [
        (ResultArm::NoContent, Vec::new()),
        (failed("NOT_ALLOWED", "#elsewhere"), Vec::new()),
        (
            failed("STALE_STATE", ""),
            vec![refused("sam", "#a")?, refused("sam", "#z")?],
        ),
        (
            failed("NOT_ALLOWED", "#elsewhere"),
            vec![refused("sam", "#a")?, refused("sam", "#z")?],
        ),
        (committed(), vec![refused("other", "#a")?]),
        (committed(), vec![refused("sam", "#b")?]),
        (committed(), vec![refused("sam", "#foreign")?]),
        (
            committed(),
            vec![refused("sam", "#a")?, refused("sam", "#A")?],
        ),
        (
            committed(),
            vec![refused("sam", "#a")?, refused("sam", "#z")?],
        ),
        (
            failed("NOT_ALLOWED", ""),
            vec![refused("sam", "#z")?, refused("sam", "#a")?],
        ),
        (failed("NOT_ALLOWED", ""), vec![refused("sam", "#a")?]),
        (
            failed("STALE_STATE", ""),
            vec![refused("sam", "#a")?, refused("sam", "#z")?],
        ),
        (
            failed("NOT_ALLOWED", "#z"),
            vec![refused("sam", "#a")?, refused("sam", "#z")?],
        ),
        (failed("NOT_ALLOWED", "#wrong"), Vec::new()),
        (
            committed(),
            vec![agenc_relay_client_wire::numeric_reply(
                "peer.example",
                403,
                "sam",
                &["#a"],
                Some("wrong shape"),
            )?],
        ),
        (
            committed(),
            vec![WireMessage::new("peer.example", "ACK", &[], None)?],
        ),
    ] {
        assert_eq!(
            requester.project("edge.example", &request, &arm, &mut replies),
            Err(Violation::Consistency)
        );
    }
    Ok(())
}
