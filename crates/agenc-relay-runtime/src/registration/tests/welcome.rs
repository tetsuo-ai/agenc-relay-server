//! The recovery NOTE of the welcome burst (architecture 10.2 step 5): one
//! `NOTE * RECOVERY_EPOCH` right after the MOTD group, only for a connection
//! that negotiated `agenc.ag/recovery`, carrying the epoch its `CAP LS`
//! advertised, on both the local and the edge registration path.
#![forbid(unsafe_code)]

use super::test_harness::{Harness, Role, TestResult};
use super::*;
use crate::federation::edge::EdgeCompletion;

const NOTE_DESCRIPTION: &str = ":Current server recovery identity";

/// The exact NOTE line for the fixture's recovery epoch.
fn expected_note(harness: &Harness) -> String {
    format!(
        ":server.example NOTE * RECOVERY_EPOCH {} {NOTE_DESCRIPTION}",
        harness.fixture.identity.recovery_epoch.to_base64url()
    )
}

/// The command or numeric of one server line.
fn command(line: &str) -> &str {
    line.split(' ').nth(1).unwrap_or_default()
}

/// Negotiates `request` (no CAP at all when `None`) and sends NICK and USER,
/// ending capability negotiation when it was started.
fn negotiate(harness: &mut Harness, number: u64, nick: &str, request: Option<&str>) -> TestResult {
    if let Some(request) = request {
        harness.line(number, "CAP LS 302")?;
        harness.line(number, &format!("CAP REQ :{request}"))?;
    }
    harness.line(number, &format!("NICK {nick}"))?;
    harness.line(number, &format!("USER {nick} 0 * :Real {nick}"))?;
    if request.is_some() {
        harness.line(number, "CAP END")?;
    }
    Ok(())
}

/// Registers one local guest and returns every line it received.
async fn local_guest(
    harness: &mut Harness,
    number: u64,
    nick: &str,
    request: Option<&str>,
) -> TestResult<Vec<String>> {
    let sink = harness.open(number, true)?;
    negotiate(harness, number, nick, request)?;
    harness.settle().await?;
    Ok(sink.lines())
}

/// The lines from `RPL_WELCOME` to the end.
fn burst(lines: &[String]) -> TestResult<Vec<String>> {
    let first = lines
        .iter()
        .position(|line| command(line) == "001")
        .ok_or_else(|| format!("no welcome in {lines:?}"))?;
    Ok(lines.iter().skip(first).cloned().collect())
}

fn commands(lines: &[String]) -> Vec<&str> {
    lines.iter().map(|line| command(line)).collect()
}

#[tokio::test]
async fn a_recovery_client_gets_the_advertised_epoch_right_after_the_motd_group() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let lines = local_guest(&mut harness, 1, "keeper", Some("agenc.ag/recovery")).await?;
    let note = expected_note(&harness);
    let epoch = harness.fixture.identity.recovery_epoch.to_base64url();
    // The NOTE repeats the value this connection's CAP LS pinned.
    assert!(
        lines.iter().any(|line| command(line) == "CAP"
            && line.contains(&format!("agenc.ag/recovery=v1.{epoch}"))),
        "lines: {lines:?}"
    );
    let welcome = burst(&lines)?;
    assert_eq!(
        commands(&welcome),
        [
            "001", "002", "003", "004", "005", "005", "005", "251", "422", "NOTE"
        ],
        "lines: {lines:?}"
    );
    assert_eq!(welcome.last(), Some(&note));
    assert_eq!(
        lines.iter().filter(|line| command(line) == "NOTE").count(),
        1,
        "lines: {lines:?}"
    );
    Ok(())
}

#[tokio::test]
async fn the_epoch_note_follows_a_published_motd() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    harness
        .fixture
        .context_mut()?
        .set_motd_for_test(Some("first line\nsecond line"));
    let lines = local_guest(&mut harness, 1, "reader", Some("agenc.ag/recovery")).await?;
    let welcome = burst(&lines)?;
    assert_eq!(
        commands(&welcome),
        [
            "001", "002", "003", "004", "005", "005", "005", "251", "375", "372", "372", "376",
            "NOTE"
        ],
        "lines: {lines:?}"
    );
    assert_eq!(welcome.last(), Some(&expected_note(&harness)));
    Ok(())
}

#[tokio::test]
async fn the_epoch_note_needs_only_the_recovery_capability() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let note = expected_note(&harness);
    let both = local_guest(
        &mut harness,
        1,
        "both",
        Some("agenc.ag/recovery standard-replies"),
    )
    .await?;
    assert_eq!(burst(&both)?.last(), Some(&note), "lines: {both:?}");
    let replies_only = local_guest(&mut harness, 2, "replies", Some("standard-replies")).await?;
    let silent = local_guest(&mut harness, 3, "silent", None).await?;
    for lines in [&replies_only, &silent] {
        assert!(
            lines.iter().all(|line| command(line) != "NOTE"),
            "no NOTE without agenc.ag/recovery: {lines:?}"
        );
        assert_eq!(
            burst(lines)?.last().map(|line| command(line)),
            Some("422"),
            "the burst ends with the MOTD group: {lines:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_edge_registration_sends_the_epoch_note_after_the_motd_group() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let note = expected_note(&harness);
    for (number, nick, request) in [
        (1, "remote", Some("agenc.ag/recovery")),
        (2, "quiet", Some("standard-replies")),
    ] {
        let sink = harness.open(number, true)?;
        if let Some(request) = request {
            harness.line(number, "CAP LS 302")?;
            harness.line(number, &format!("CAP REQ :{request}"))?;
        }
        harness.line(number, &format!("NICK {nick}"))?;
        harness.line(number, &format!("USER {nick} 0 * :Real"))?;
        let event_generation = match harness.actions(number, "CAP END")?.into_iter().next() {
            Some(RegistrationAction::CommitRegistration { generation, .. }) => generation,
            other => return Err(format!("expected the registration commit, got {other:?}").into()),
        };
        let context = harness.fixture.context_mut()?;
        harness.router.apply_edge_completion(
            context,
            EdgeCompletion::SessionRegistered {
                generation: ConnectionGeneration::new(number),
                session_id: SessionId::from_bytes(
                    [40_u8.saturating_add(u8::try_from(number)?); 16],
                ),
                user_id: UserId::from_bytes([50_u8.saturating_add(u8::try_from(number)?); 16]),
                event_generation,
                nickname: nick.to_owned(),
            },
        );
        let lines = sink.lines();
        let welcome = burst(&lines)?;
        if number == 1 {
            assert_eq!(
                commands(&welcome),
                [
                    "001", "002", "003", "004", "005", "005", "005", "251", "422", "NOTE"
                ],
                "lines: {lines:?}"
            );
            assert_eq!(welcome.last(), Some(&note));
        } else {
            assert_eq!(
                commands(&welcome),
                [
                    "001", "002", "003", "004", "005", "005", "005", "251", "422"
                ],
                "lines: {lines:?}"
            );
        }
    }
    Ok(())
}
