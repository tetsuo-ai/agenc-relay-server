//! What the edge role finished reaches the right client: registrations,
//! refusals, command failures, reply pages, and forced reconnects.
#![forbid(unsafe_code)]

use super::test_harness::{Harness, Role, TestResult, parsed, saw};
use super::*;
use crate::federation::edge::EdgeCompletion;

const SESSION: SessionId = SessionId::from_bytes([41; 16]);
const USER: UserId = UserId::from_bytes([42; 16]);

fn complete(harness: &mut Harness, completion: EdgeCompletion) -> TestResult {
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completion(context, completion);
    Ok(())
}

/// Brings one edge client to the point where its session open is with the
/// coordinator and returns the commit generation the answer must name.
fn await_session(harness: &mut Harness, number: u64, nick: &str) -> TestResult<u64> {
    harness.line(number, &format!("NICK {nick}"))?;
    let negotiating = harness
        .state(number)?
        .registration
        .capability_state()
        .enabled("standard-replies");
    let user = format!("USER {nick} 0 * :Real");
    let actions = if negotiating {
        harness.line(number, &user)?;
        harness.actions(number, "CAP END")?
    } else {
        harness.actions(number, &user)?
    };
    match actions.into_iter().next() {
        Some(RegistrationAction::CommitRegistration { generation, .. }) => Ok(generation),
        other => Err(format!("expected the registration commit, got {other:?}").into()),
    }
}

fn registered(number: u64, event_generation: u64, nick: &str) -> EdgeCompletion {
    EdgeCompletion::SessionRegistered {
        generation: ConnectionGeneration::new(number),
        session_id: SESSION,
        user_id: USER,
        event_generation,
        nickname: nick.to_owned(),
    }
}

/// One edge client the coordinator registered.
fn edge_client(harness: &mut Harness, number: u64, nick: &str) -> TestResult<Arc<FrameSinkAlias>> {
    let sink = harness.open(number, true)?;
    let event_generation = await_session(harness, number, nick)?;
    complete(harness, registered(number, event_generation, nick))?;
    Ok(sink)
}

type FrameSinkAlias = crate::test_support::FrameSink;

#[tokio::test]
async fn coordinator_registration_binds_the_session_and_welcomes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = edge_client(&mut harness, 1, "remote")?;
    assert!(saw(&sink, " 001 remote "), "lines: {:?}", sink.lines());
    let state = harness.state(1)?;
    assert_eq!(state.bound.map(|bound| bound.user_id), Some(USER));
    assert_eq!(state.nickname.as_deref(), Some("remote"));
    assert!(matches!(state.deadline, DeadlineState::Idle));
    assert!(harness.router.leases.is_empty());
    Ok(())
}

#[tokio::test]
async fn coordinator_registration_for_a_vanished_connection_is_dropped() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    complete(&mut harness, registered(9, 1, "ghost"))?;
    assert!(harness.router.connections.is_empty());
    Ok(())
}

#[tokio::test]
async fn coordinator_refusal_ends_the_registration_and_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    let event_generation = await_session(&mut harness, 1, "refused")?;
    complete(
        &mut harness,
        EdgeCompletion::RegistrationRefused {
            generation: ConnectionGeneration::new(1),
            event_generation,
        },
    )?;
    assert!(
        saw(&sink, "ERROR :Registration rejected"),
        "lines: {:?}",
        sink.lines()
    );
    assert!(harness.sink_gone(1)?);
    assert!(harness.state(1)?.bound.is_none());
    Ok(())
}

#[tokio::test]
async fn coordinator_registration_the_session_table_refuses_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    let event_generation = await_session(&mut harness, 1, "taken")?;
    let occupant = BoundSession {
        session_id: SessionId::from_bytes([7; 16]),
        user_id: UserId::from_bytes([8; 16]),
        capability_hash: [0; 32],
    };
    harness.fixture.context_mut()?.sessions_mut().bind_session(
        ConnectionGeneration::new(1),
        occupant,
        crate::test_support::negotiated_capabilities(&[])?,
    )?;
    complete(&mut harness, registered(1, event_generation, "taken"))?;
    assert!(harness.sink_gone(1)?);
    assert!(harness.state(1)?.bound.is_none());
    assert!(!saw(&sink, " 001 "), "lines: {:?}", sink.lines());
    Ok(())
}

#[tokio::test]
async fn resynchronization_tells_the_client_to_reconnect_and_closes_it() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = edge_client(&mut harness, 1, "resync")?;
    complete(
        &mut harness,
        EdgeCompletion::Resync {
            generation: ConnectionGeneration::new(1),
        },
    )?;
    assert!(
        saw(&sink, "ERROR :Network state resynchronization required"),
        "lines: {:?}",
        sink.lines()
    );
    assert!(harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn revoked_session_closes_its_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let _sink = edge_client(&mut harness, 1, "revoked")?;
    complete(
        &mut harness,
        EdgeCompletion::SessionRevoked {
            generation: ConnectionGeneration::new(1),
        },
    )?;
    assert!(harness.sink_gone(1)?);
    Ok(())
}

fn failed(number: u64, line: &str) -> TestResult<EdgeCompletion> {
    Ok(EdgeCompletion::CommandFailed {
        generation: ConnectionGeneration::new(number),
        message: Box::new(parsed(line)?),
        error: DomainError::NotFound,
    })
}

#[tokio::test]
async fn failed_command_is_rendered_to_its_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = edge_client(&mut harness, 1, "asker")?;
    let before = sink.lines().len();
    complete(&mut harness, failed(1, "PRIVMSG nobody :hello")?)?;
    assert_eq!(sink.lines().len(), before + 1, "lines: {:?}", sink.lines());
    complete(&mut harness, failed(1, "JOIN #nowhere")?)?;
    assert_eq!(sink.lines().len(), before + 2, "lines: {:?}", sink.lines());
    assert!(!harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn failed_command_for_a_vanished_connection_is_dropped() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    complete(&mut harness, failed(9, "PRIVMSG nobody :hello")?)?;
    assert!(harness.router.connections.is_empty());
    Ok(())
}

#[tokio::test]
async fn failure_that_cannot_be_delivered_leaves_the_client_closed() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = edge_client(&mut harness, 1, "deaf")?;
    let before = sink.lines().len();
    harness.drop_transport(1)?;
    complete(&mut harness, failed(1, "PRIVMSG nobody :hello")?)?;
    assert_eq!(sink.lines().len(), before);
    assert!(harness.sink_gone(1)?);
    assert!(harness.state(1).is_ok());
    Ok(())
}

fn topic_frame(channel: &str) -> TestResult<WireMessage> {
    Ok(numeric_reply(
        "server.example",
        331,
        "joiner",
        &[channel],
        Some("No topic is set"),
    )?)
}

#[tokio::test]
async fn committed_join_whose_names_cannot_be_requested_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let _sink = edge_client(&mut harness, 1, "joiner")?;
    complete(
        &mut harness,
        EdgeCompletion::JoinCommitted {
            generation: ConnectionGeneration::new(1),
            frames: vec![topic_frame("#room")?],
            echo_permits: Vec::new(),
            message: Box::new(parsed("JOIN #room")?),
        },
    )?;
    assert!(harness.sink_gone(1)?);
    assert!(harness.state(1)?.join_names.is_none());
    Ok(())
}

fn replies(number: u64, line: &str, cursor: Option<[u8; 32]>) -> TestResult<EdgeCompletion> {
    Ok(EdgeCompletion::Replies {
        generation: ConnectionGeneration::new(number),
        frames: vec![numeric_reply(
            "server.example",
            315,
            "asker",
            &["#room"],
            Some("End of WHO list"),
        )?],
        page_sequence: 0,
        next_cursor: cursor,
        message: Box::new(parsed(line)?),
    })
}

#[tokio::test]
async fn names_page_without_a_join_in_progress_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let _sink = edge_client(&mut harness, 1, "asker")?;
    complete(&mut harness, replies(1, "JOIN #room", None)?)?;
    assert!(harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn final_reply_page_is_delivered_and_the_client_stays_open() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = edge_client(&mut harness, 1, "asker")?;
    complete(&mut harness, replies(1, "WHO #room", None)?)?;
    assert!(saw(&sink, " 315 "), "lines: {:?}", sink.lines());
    assert!(!harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn reply_page_whose_continuation_cannot_be_requested_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let _sink = edge_client(&mut harness, 1, "asker")?;
    complete(&mut harness, replies(1, "WHO #room", Some([4; 32]))?)?;
    assert!(harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn reply_pages_for_a_vanished_or_deaf_client_are_not_delivered() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    complete(&mut harness, replies(9, "WHO #room", None)?)?;
    let sink = edge_client(&mut harness, 1, "asker")?;
    let before = sink.lines().len();
    harness.drop_transport(1)?;
    complete(&mut harness, replies(1, "WHO #room", None)?)?;
    assert_eq!(sink.lines().len(), before);
    assert!(harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn committed_account_deletion_delivers_its_reply_and_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = edge_client(&mut harness, 1, "leaver")?;
    let note = WireMessage::new(
        "server.example",
        "NOTE",
        &["ACCOUNT", "DELETED"],
        Some("Account deleted"),
    )?;
    complete(
        &mut harness,
        EdgeCompletion::AccountDeleted {
            generation: ConnectionGeneration::new(1),
            frames: vec![note],
            message: Box::new(parsed("ACCOUNT DELETE CONFIRM AAAAAAAAAAAAAAAAAAAAAA")?),
        },
    )?;
    assert!(
        saw(&sink, "NOTE ACCOUNT DELETED"),
        "lines: {:?}",
        sink.lines()
    );
    assert!(harness.sink_gone(1)?);
    Ok(())
}

fn completed(number: u64, line: &str) -> TestResult<EdgeCompletion> {
    Ok(EdgeCompletion::CommandCompleted {
        generation: ConnectionGeneration::new(number),
        message: Box::new(parsed(line)?),
    })
}

#[tokio::test]
async fn completed_join_asks_for_names_without_answering_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = edge_client(&mut harness, 1, "joiner")?;
    let before = sink.lines().len();
    complete(&mut harness, completed(1, "JOIN #one,#two")?)?;
    complete(&mut harness, completed(1, "JOIN")?)?;
    complete(&mut harness, completed(1, "PART #one")?)?;
    assert_eq!(sink.lines().len(), before);
    assert!(!harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn completed_channel_setting_is_noted_only_with_standard_replies() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let plain = edge_client(&mut harness, 1, "plain")?;
    let before = plain.lines().len();
    complete(&mut harness, completed(1, "CHANCTL SET #room history on")?)?;
    assert_eq!(plain.lines().len(), before);

    let noted = harness.open(2, true)?;
    harness.line(2, "CAP REQ :standard-replies")?;
    let event_generation = await_session(&mut harness, 2, "noted")?;
    complete(
        &mut harness,
        EdgeCompletion::SessionRegistered {
            generation: ConnectionGeneration::new(2),
            session_id: SessionId::from_bytes([51; 16]),
            user_id: UserId::from_bytes([52; 16]),
            event_generation,
            nickname: "noted".to_owned(),
        },
    )?;
    complete(&mut harness, completed(2, "CHANCTL SET #room history on")?)?;
    assert!(
        saw(&noted, "NOTE CHANCTL UPDATED #room"),
        "lines: {:?}",
        noted.lines()
    );
    let before = noted.lines().len();
    complete(&mut harness, completed(2, "CHANCTL SET notachannel on")?)?;
    complete(&mut harness, completed(9, "CHANCTL SET #room history on")?)?;
    assert_eq!(noted.lines().len(), before);
    Ok(())
}
