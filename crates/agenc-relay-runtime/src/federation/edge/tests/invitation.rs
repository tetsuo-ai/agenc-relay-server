#![forbid(unsafe_code)]

use super::*;
use crate::test_support::TestResult;
use agenc_relay_client_wire::{FramedLine, parse_message};

fn parsed(line: &str) -> TestResult<ParsedMessage> {
    parse_message(FramedLine::new(line)?)?.ok_or_else(|| "missing request".into())
}
fn failed(code: &str, context: &str) -> ResultArm {
    ResultArm::Failed {
        code: code.to_owned(),
        context: context.to_owned(),
    }
}
fn refused(nick: &str, target: &str) -> TestResult<WireMessage> {
    Ok(numeric_reply(
        "hub.example",
        401,
        nick,
        &[target],
        Some("No such nick"),
    )?)
}

#[test]
fn original_invitation_needs_the_same_physical_channel_and_nickname() -> TestResult {
    let channel = ChannelInstanceId::from_bytes([17; 16]);
    let original = InviteRequester::new(channel, "Sam", &CapabilityState::default())?;
    let request = parsed("@label=x INVITE Guest #room")?;
    let guest = NicknameValue::parse("GUEST")?;
    assert!(original.matches(channel, &request, &guest));
    assert!(!original.matches(ChannelInstanceId::from_bytes([18; 16]), &request, &guest));
    assert!(!original.matches(channel, &request, &NicknameValue::parse("another")?));
    assert!(!original.matches(channel, &parsed("INVITE")?, &guest));
    Ok(())
}

#[test]
fn a_single_authorized_missing_nickname_is_the_only_target_refusal() -> TestResult {
    let pending = PendingKind::Command {
        echo_channels: Some(EchoChannels::Invite(InviteRequester::new(
            ChannelInstanceId::from_bytes([3; 16]),
            "Sam",
            &CapabilityState::default(),
        )?)),
        message: Box::new(parsed("INVITE Guest #room")?),
    };
    for context in ["", "gUeSt"] {
        let mut reply = [refused("sam", "guest")?];
        assert_eq!(
            project(
                "edge.example",
                &pending,
                &failed("STALE_STATE", context),
                &mut reply
            ),
            Ok(())
        );
        assert_eq!(
            reply.first().ok_or("missing 401")?.middle(),
            ["Sam", "Guest"]
        );
    }
    let committed = || ResultArm::Committed {
        resulting_state_generation: 8,
    };
    for (arm, mut frames) in [
        (failed("NOT_ALLOWED", ""), vec![refused("sam", "guest")?]),
        (
            failed("STALE_STATE", "other"),
            vec![refused("sam", "guest")?],
        ),
        (failed("STALE_STATE", ""), vec![refused("other", "guest")?]),
        (failed("STALE_STATE", ""), vec![refused("sam", "other")?]),
        (
            failed("STALE_STATE", ""),
            vec![numeric_reply(
                "hub.example",
                481,
                "Sam",
                &[],
                Some("Command is unavailable"),
            )?],
        ),
        (
            failed("STALE_STATE", ""),
            vec![numeric_reply(
                "hub.example",
                401,
                "Sam",
                &["Guest"],
                Some("other text"),
            )?],
        ),
        (
            failed("STALE_STATE", ""),
            vec![refused("sam", "guest")?, refused("sam", "guest")?],
        ),
        (committed(), vec![refused("sam", "guest")?]),
        (ResultArm::NoContent, vec![]),
    ] {
        assert_eq!(
            project("edge.example", &pending, &arm, &mut frames),
            Err(Violation::Consistency)
        );
    }
    assert_eq!(
        project(
            "edge.example",
            &pending,
            &failed("STALE_STATE", ""),
            &mut []
        ),
        Ok(())
    );
    assert_eq!(
        project("edge.example", &pending, &committed(), &mut []),
        Ok(())
    );
    Ok(())
}
