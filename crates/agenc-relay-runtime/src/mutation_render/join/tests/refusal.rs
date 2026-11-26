//! Original response dialect, canonical order, old receipts and exact recipient scope.
#![forbid(unsafe_code)]
use super::*;
use agenc_relay_client_wire::{
    CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState, FramedLine, numeric_reply,
    parse_message,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn input() -> Result<(JoinRequester, ParsedMessage)> {
    let profile = CapabilityProfile::new(vec![CapabilitySpec::new("standard-replies", None)?])?;
    let mut caps = CapabilityState::default();
    caps.ls(Some("302"), &profile)?;
    assert!(matches!(
        caps.request("standard-replies", &profile)?,
        CapRequestReply::Ack(_)
    ));
    let requester = JoinRequester {
        nickname: NicknameValue::parse("Ada")?,
        replies: StandardReplies::negotiated(&caps),
    };
    caps.request("-standard-replies", &profile)?;
    assert!(!caps.enabled("standard-replies"));
    let request =
        parse_message(FramedLine::new("JOIN #Third,#First,#Second")?)?.ok_or("missing JOIN")?;
    Ok((requester, request))
}

fn row(code: u16, nick: &str, operands: &[&str]) -> Result<WireMessage> {
    Ok(numeric_reply(
        "edge.test",
        code,
        nick,
        operands,
        Some("public description"),
    )?)
}

#[test]
fn historical_and_interleaved_results_project_the_same_original_refusals() -> Result {
    let (requester, request) = input()?;
    for historical in [false, true] {
        let mut frames = vec![
            row(403, "Ada", &["#first"])?,
            row(331, "Ada", &["#second"])?,
            row(481, "Ada", &[])?,
        ];
        if historical {
            frames.swap(0, 1);
        }
        requester.project_covered("edge.test", &request, &mut frames, None)?;
        let failures: Vec<_> = frames
            .iter()
            .filter(|frame| frame.command() == "FAIL")
            .collect();
        let [secret, full] = failures.as_slice() else {
            return Err("expected both refusals".into());
        };
        assert_eq!(secret.middle(), ["JOIN", "SECRET_UNAVAILABLE", "#First"]);
        assert_eq!(full.middle(), ["JOIN", "SERVER_BUSY"]);
    }
    Ok(())
}

#[test]
fn an_entirely_refused_join_matches_its_first_arm_and_every_requested_target() -> Result {
    let (requester, request) = input()?;
    let denied = || -> Result<Vec<WireMessage>> {
        Ok(vec![
            row(482, "Ada", &["#first"])?,
            row(403, "Ada", &["#second"])?,
            row(481, "Ada", &[])?,
        ])
    };
    for first in ["BAD_STATE", "NOT_ALLOWED"] {
        requester.project_covered("edge.test", &request, &mut denied()?, Some((first, "")))?;
    }
    assert!(
        requester
            .project_covered(
                "edge.test",
                &request,
                &mut denied()?,
                Some(("SECRET_UNAVAILABLE", ""))
            )
            .is_err()
    );
    assert!(
        requester
            .project_covered("edge.test", &request, &mut denied()?, None)
            .is_err()
    );
    for frames in [
        vec![row(482, "Ada", &["#first"])?],
        vec![
            row(482, "Ada", &["#first"])?,
            row(403, "Ada", &["#first"])?,
            row(481, "Ada", &[])?,
        ],
        vec![
            row(482, "Ada", &["#first"])?,
            row(403, "Ada", &["#foreign"])?,
            row(481, "Ada", &[])?,
        ],
        vec![
            row(482, "Ada", &["#first"])?,
            row(403, "other", &["#second"])?,
            row(481, "Ada", &[])?,
        ],
    ] {
        assert!(
            requester
                .project_covered(
                    "edge.test",
                    &request,
                    &mut frames.into_boxed_slice(),
                    Some(("BAD_STATE", ""))
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn an_older_coarse_result_can_identify_only_its_first_canonical_operand() -> Result {
    let (requester, request) = input()?;
    let frame = requester
        .coarse("edge.test", &request, "SECRET_UNAVAILABLE", "")?
        .ok_or("missing original refusal")?;
    assert_eq!(frame.middle(), ["JOIN", "SECRET_UNAVAILABLE", "#First"]);
    assert!(
        requester
            .coarse("edge.test", &request, "BAD_STATE", "#Third")
            .is_err()
    );
    assert!(
        requester
            .coarse("edge.test", &request, "STALE_STATE", "")?
            .is_none()
    );
    Ok(())
}

#[test]
fn refusal_code_and_target_shape_must_match_the_original_operand() -> Result {
    let target = ChannelNameValue::parse("#First")?;
    assert_eq!(
        target_error(
            &row(404, "Ada", &["#first"])?,
            &target,
            Some("E2EE_REQUIRED")
        )?,
        DomainError::EncryptedRoute
    );
    assert!(row(481, "Ada", &["#First"]).is_err());
    assert!(row(403, "Ada", &[]).is_err());
    assert!(row(403, "Ada", &["#First", "#second"]).is_err());
    assert!(target_error(&row(403, "Ada", &["#second"])?, &target, None).is_err());
    assert!(target_error(&row(401, "Ada", &["other"])?, &target, None).is_err());
    assert!(check_context("#FIRST", &target).is_ok());
    Ok(())
}

#[test]
fn a_topic_may_withhold_its_setter_and_a_present_setter_belongs_to_the_preceding_topic() -> Result {
    let (requester, request) = input()?;
    let topic = || row(332, "Ada", &["#first"]);
    let setter = || numeric_reply("edge.test", 333, "Ada", &["#first", "owner", "123"], None);
    let encrypted = || {
        numeric_reply(
            "edge.test",
            332,
            "Ada",
            &["#second"],
            Some("Encrypted channel topic"),
        )
    };
    let refusal = || row(403, "Ada", &["#third"]);
    for mut permitted in [
        vec![topic()?, setter()?, encrypted()?, refusal()?],
        vec![topic()?, setter()?, refusal()?, encrypted()?],
    ] {
        requester.project_covered("edge.test", &request, &mut permitted, None)?;
    }
    for mut malformed in [
        vec![setter()?, topic()?, encrypted()?, refusal()?],
        vec![topic()?, refusal()?, setter()?, encrypted()?],
        vec![topic()?, encrypted()?, setter()?, refusal()?],
        vec![topic()?, setter()?, setter()?, encrypted()?, refusal()?],
    ] {
        assert!(
            requester
                .project_covered("edge.test", &request, &mut malformed, None)
                .is_err()
        );
    }
    Ok(())
}
