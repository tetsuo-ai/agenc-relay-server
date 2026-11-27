#![forbid(unsafe_code)]

use super::*;
use crate::test_support::TestResult;
use agenc_relay_client_wire::{CapabilityState, FramedLine, parse_message};

const ROOM: ChannelInstanceId = ChannelInstanceId::from_bytes([5; 16]);
const FIRST: UserId = UserId::from_bytes([9; 16]);
const LAST: UserId = UserId::from_bytes([2; 16]);

fn request(line: &str) -> TestResult<ParsedMessage> {
    parse_message(FramedLine::new(line)?)?.ok_or_else(|| "missing request".into())
}

fn requester() -> TestResult<KickRequester> {
    Ok(KickRequester {
        channel: ROOM,
        revision: 7,
        origin: ReplyRequester::new("Owner", &CapabilityState::default())?,
        targets: [Some(LAST), None, Some(FIRST), None],
    })
}

fn source(nick: &str, user_id: UserId) -> TestResult<SourceView> {
    Ok(SourceView {
        user_id,
        nickname: NicknameValue::parse(nick)?,
        public_cloak: agenc_relay_testkit::deterministic_cloak(4)?,
        account_label: None,
    })
}

fn refusal(nick: &str, name: &str) -> TestResult<WireMessage> {
    Ok(numeric_reply(
        "core.test",
        401,
        nick,
        &[name],
        Some("No such nick"),
    )?)
}

fn denied(count: usize) -> TestResult<Vec<WireMessage>> {
    (0..count)
        .map(|_| {
            Ok(numeric_reply(
                "core.test",
                481,
                "owner",
                &[],
                Some("Command is unavailable"),
            )?)
        })
        .collect()
}

fn removal(name: &str) -> TestResult<WireMessage> {
    Ok(WireMessage::new(
        "owner!u@h.test",
        "KICK",
        &["#r", name],
        Some("time"),
    )?)
}

fn failed(code: &str, context: &str) -> ResultArm {
    ResultArm::Failed {
        code: code.to_owned(),
        context: context.to_owned(),
    }
}

#[test]
fn an_unresolved_target_uses_the_coordinators_moderator_and_visibility_rules() {
    use agenc_relay_domain::{Role, Visibility};
    for visibility in [Visibility::Listed, Visibility::Unlisted, Visibility::Secret] {
        assert_eq!(
            visibility.authorize_kick_targets(None),
            Err(if visibility == Visibility::Listed {
                DomainError::Forbidden
            } else {
                DomainError::SecretUnavailable
            })
        );
        assert_eq!(
            visibility.authorize_kick_targets(Some(Role::Voice)),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            visibility.authorize_kick_targets(Some(Role::HalfOperator)),
            Ok(())
        );
        assert_eq!(visibility.authorize_kick_targets(Some(Role::Owner)), Ok(()));
    }
}

#[test]
fn physical_ids_sort_by_encoded_identity_and_keep_original_positions() -> TestResult {
    let names = "Last,ABSENT,First";
    let validated = ["absent", "first", "last"]
        .map(NicknameValue::parse)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let (positions, ids) = physical_targets(names, &validated, |n| match n.canonical() {
        "first" => Some(FIRST),
        "last" => Some(LAST),
        _ => None,
    })?;
    assert_eq!(ids, [LAST, FIRST]);
    assert_eq!(positions, [Some(LAST), None, Some(FIRST), None]);
    assert!(matches!(
        physical_targets(names, &validated, |_| Some(FIRST)),
        Err(DomainError::StaleRevision)
    ));
    assert!(physical_targets("first", &validated, |_| Some(FIRST)).is_err());
    Ok(())
}

#[test]
fn a_kick_echo_requires_the_admitted_channel_revision_target_id_name_and_public_reason()
-> TestResult {
    let cut = requester()?;
    let original = request("@label=one KICK #r Last,Absent,First :time")?;
    let other = ChannelInstanceId::from_bytes([3; 16]);
    for (channel, revision, name, id, reason, expected) in [
        (ROOM, 8, "laST", LAST, "time", Some(2)),
        (ROOM, 8, "First", FIRST, "time", Some(2)),
        (other, 8, "First", FIRST, "time", None),
        (ROOM, 7, "First", FIRST, "time", None),
        (ROOM, 8, "First", FIRST, "other", None),
        (ROOM, 8, "First", LAST, "time", None),
        (ROOM, 8, "Absent", FIRST, "time", None),
        (ROOM, 8, "Else", FIRST, "time", None),
    ] {
        assert_eq!(
            cut.echo_targets(&original, channel, revision, &source(name, id)?, reason),
            expected
        );
    }
    assert_eq!(
        cut.echo_targets(&request("KICK")?, ROOM, 9, &source("First", FIRST)?, ""),
        None
    );
    assert_eq!(
        cut.echo_targets(
            &request("KICK #r First,Absent,Last,Extra,First2")?,
            ROOM,
            9,
            &source("First2", FIRST)?,
            ""
        ),
        None
    );
    Ok(())
}

#[test]
fn accepted_targets_and_scoped_or_generic_failures_must_agree_in_either_delivery_order()
-> TestResult {
    let cut = requester()?;
    let original = request("KICK #r Last,Absent,First :time")?;
    let committed = ResultArm::Committed {
        resulting_state_generation: 8,
    };
    let last = removal("Last")?;
    let first = removal("First")?;
    let mut replies = vec![refusal("OWNER", "First")?];
    assert_eq!(
        cut.project("edge.test", &original, &committed, &mut replies),
        Ok(())
    );
    assert_eq!(replies.len(), 2);
    assert_eq!(
        replies
            .first()
            .and_then(|r| r.middle().last())
            .map(String::as_str),
        Some("Absent")
    );
    assert!(
        cut.check_evidence(&original, [&last].into_iter(), &replies)
            .is_ok()
    );
    assert!(
        cut.check_evidence(&original, [&first].into_iter(), &replies)
            .is_err()
    );
    assert!(
        cut.check_evidence(&original, [&last, &last].into_iter(), &[])
            .is_err()
    );
    assert!(
        cut.check_evidence(&original, [&removal("Absent")?].into_iter(), &[])
            .is_err()
    );
    let mut unscoped = denied(1)?;
    assert_eq!(
        cut.project("edge.test", &original, &committed, &mut unscoped),
        Ok(())
    );
    assert!(
        cut.check_evidence(&original, [&first].into_iter(), &unscoped)
            .is_ok()
    );
    assert!(
        cut.check_evidence(&original, [&first, &last].into_iter(), &unscoped)
            .is_err()
    );
    let name = refusal("Owner", "First")?;
    assert!(
        cut.check_evidence(
            &original,
            [].into_iter(),
            &[refusal("Owner", "First")?, name]
        )
        .is_err()
    );
    let wrong = WireMessage::new("owner!u@h.test", "KICK", &["#wrong", "First"], Some("time"))?;
    assert!(
        cut.check_evidence(&original, [&wrong].into_iter(), &[])
            .is_err()
    );
    Ok(())
}

#[test]
fn unrelated_or_malformed_frames_cannot_supply_a_target_decision() -> TestResult {
    let cut = requester()?;
    let original = request("KICK #r Last,Absent,First :time")?;
    for (command, middle, reason) in [
        ("PART", vec!["#r", "First"], Some("time")),
        ("KICK", vec!["#r", "First"], Some("different")),
        ("KICK", vec!["#r", "Else"], Some("time")),
        ("KICK", vec!["#r"], Some("time")),
    ] {
        let unrelated = WireMessage::new("owner!u@h.test", command, &middle, reason)?;
        assert!(
            cut.check_evidence(&original, [&unrelated].into_iter(), &[])
                .is_err()
        );
    }
    let unknown = WireMessage::new("core.test", "ACK", &[], None)?;
    assert!(
        cut.check_evidence(&original, [].into_iter(), &[unknown])
            .is_err()
    );
    assert!(
        cut.check_evidence(&request("KICK")?, [].into_iter(), &[])
            .is_err()
    );
    let too_many = request("KICK #r Last,Absent,First,Four,Five :time")?;
    assert!(
        cut.check_evidence(&too_many, [&removal("Five")?].into_iter(), &[])
            .is_err()
    );
    Ok(())
}

#[test]
fn coordinator_refusals_must_cover_just_the_admitted_physical_users() -> TestResult {
    let cut = requester()?;
    let original = request("KICK #r Last,Absent,First :time")?;
    let mut valid = vec![refusal("Owner", "First")?, refusal("Owner", "Last")?];
    assert_eq!(
        cut.project(
            "edge.test",
            &original,
            &failed("STALE_STATE", "first"),
            &mut valid
        ),
        Ok(())
    );
    assert!(
        cut.check_evidence(&original, [].into_iter(), &valid)
            .is_ok()
    );
    for code in ["NOT_ALLOWED", "BAD_STATE"] {
        let mut generic = denied(2)?;
        assert!(
            cut.project("edge.test", &original, &failed(code, ""), &mut generic)
                .is_ok()
        );
    }
    let committed = || ResultArm::Committed {
        resulting_state_generation: 8,
    };
    for (arm, mut frames) in [
        (
            failed("NOT_ALLOWED", ""),
            vec![refusal("Owner", "Last")?, refusal("Owner", "First")?],
        ),
        (
            failed("STALE_STATE", "else"),
            vec![refusal("Owner", "Last")?, refusal("Owner", "First")?],
        ),
        (failed("STALE_STATE", ""), denied(2)?),
        (failed("NOT_ALLOWED", "other"), denied(2)?),
        (failed("STALE_STATE", ""), vec![refusal("Owner", "First")?]),
        (ResultArm::NoContent, Vec::new()),
        (committed(), vec![refusal("Else", "First")?]),
        (committed(), vec![refusal("Owner", "Absent")?]),
        (committed(), vec![refusal("Owner", "Else")?]),
        (
            committed(),
            vec![WireMessage::new("core.test", "ACK", &[], None)?],
        ),
        (
            committed(),
            vec![numeric_reply(
                "core.test",
                481,
                "other",
                &[],
                Some("Command is unavailable"),
            )?],
        ),
        (committed(), denied(2)?),
    ] {
        assert!(
            cut.project("edge.test", &original, &arm, &mut frames)
                .is_err()
        );
    }
    let mut historical = Vec::new();
    assert_eq!(
        cut.project(
            "edge.test",
            &original,
            &failed("STALE_STATE", ""),
            &mut historical
        ),
        Ok(())
    );
    assert!(historical.is_empty());
    Ok(())
}
