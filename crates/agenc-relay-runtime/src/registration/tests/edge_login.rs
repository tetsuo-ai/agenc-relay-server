//! A registered edge client's post-registration login (architecture 11.4):
//! its `903` is followed by `900` once the session projection names the
//! account it logged in to, at once when the replica already does, and never
//! for a login before registration, which the welcome names instead.
#![forbid(unsafe_code)]

use agenc_relay_client_wire::{ACCOUNT_RESPONSE_BYTES, encode_sasl_payload};
use agenc_relay_domain::federation::{ProjectedEvent, SessionEventView, SessionRecord};
use agenc_relay_domain::{AccountLabelValue, DisplayNameValue};
use agenc_relay_types::{AccountId, Generation};

use super::edge_answer_tests::{sasl_waiting_finish, text_chunks};
use super::test_harness::{Harness, Role, TestResult};
use super::*;
use crate::federation::edge::{EdgeCompletion, RemoteCarrierOutcome};

const SESSION: SessionId = SessionId::from_bytes([47; 16]);
const USER: UserId = UserId::from_bytes([48; 16]);
const CLOAK_SEED: u8 = 14;

fn account() -> AccountId {
    agenc_relay_testkit::account_id(49)
}

/// The session projection the coordinator installs on its home edge,
/// naming `account` when the session holds one.
fn record(
    harness: &Harness,
    revision: u64,
    account: Option<AccountId>,
) -> TestResult<SessionRecord> {
    let account_generation = Generation::new(1)?;
    Ok(SessionRecord {
        session_id: SESSION,
        user_id: USER,
        home_server_id: harness.fixture.identity.server_id,
        session_revision: Revision::new(revision)?,
        account: account.map(|account_id| (account_id, account_generation)),
        nickname: NicknameValue::parse("remote")?,
        display_name: DisplayNameValue::prepare("Real")?,
        public_cloak: agenc_relay_testkit::deterministic_cloak(CLOAK_SEED)?,
        account_label: account
            .map(|_| AccountLabelValue::parse("EdgeLabel"))
            .transpose()?,
        user_mode_bits: 1,
        away: None,
    })
}

fn project(harness: &mut Harness, record: SessionRecord) -> TestResult {
    let generation = record.session_revision.get();
    harness
        .router
        .edge
        .as_mut()
        .ok_or("the router has no edge role")?
        .replica_mut()
        .apply(
            &ProjectedEvent::SessionVisible(SessionEventView {
                source: record.source_view(),
                home_projection: Some(record),
            }),
            generation,
        )?;
    Ok(())
}

/// Registers edge client 1 as the guest `remote` whose projection the
/// coordinator installed, and returns its sink.
fn registered_guest(
    harness: &mut Harness,
    projected: Option<AccountId>,
) -> TestResult<Arc<crate::test_support::FrameSink>> {
    let sink = harness.open(1, true)?;
    harness.line(1, "NICK remote")?;
    let event_generation = match harness
        .actions(1, "USER remote 0 * :Real")?
        .into_iter()
        .next()
    {
        Some(RegistrationAction::CommitRegistration { generation, .. }) => generation,
        other => return Err(format!("expected the registration commit, got {other:?}").into()),
    };
    let projection = record(harness, 1, projected)?;
    project(harness, projection)?;
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completion(
        context,
        EdgeCompletion::SessionRegistered {
            generation: ConnectionGeneration::new(1),
            session_id: SESSION,
            user_id: USER,
            event_generation,
            nickname: "remote".to_owned(),
        },
    );
    Ok(sink)
}

/// The coordinator answers the client's SASL finish as authenticated.
fn login_answered(harness: &mut Harness) -> TestResult {
    harness
        .router
        .edge_carriers
        .insert(ConnectionGeneration::new(1), sasl_waiting_finish()?);
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completion(
        context,
        EdgeCompletion::AccountCarrier {
            generation: ConnectionGeneration::new(1),
            carrier_generation: 1,
            sasl: true,
            finish: true,
            outcome: RemoteCarrierOutcome::Authenticated {
                account_id: account(),
                account_session_generation: 1,
                auth_grant_id: [50; 32],
                chunks: text_chunks(&encode_sasl_payload(&[0; ACCOUNT_RESPONSE_BYTES]))?,
            },
        },
    );
    Ok(())
}

fn logged_in_line() -> TestResult<String> {
    let cloak = agenc_relay_testkit::deterministic_cloak(CLOAK_SEED)?;
    Ok(format!(
        ":server.example 900 remote remote!{}@{} EdgeLabel :You are now logged in",
        std::str::from_utf8(cloak.user_component())?,
        std::str::from_utf8(cloak.host_component())?
    ))
}

fn ends_with_903(lines: &[String]) -> bool {
    lines
        .last()
        .is_some_and(|line| line == ":server.example 903 remote :SASL authentication successful")
}

#[tokio::test]
async fn an_edge_login_sends_900_once_the_projection_names_the_account() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = registered_guest(&mut harness, None)?;
    login_answered(&mut harness)?;
    // The coordinator sends the result before the projection: 903 only.
    assert!(ends_with_903(&sink.lines()), "lines: {:?}", sink.lines());
    assert!(
        harness
            .router
            .awaited_logins
            .contains_key(&ConnectionGeneration::new(1))
    );

    // The projection naming the account arrives with the next edge event.
    let projection = record(&harness, 2, Some(account()))?;
    project(&mut harness, projection)?;
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completions(context, Vec::new());
    let lines = sink.lines();
    let tail = lines
        .get(lines.len().saturating_sub(2)..)
        .ok_or("no lines")?;
    assert!(
        ends_with_903(tail.get(..1).ok_or("no 903")?),
        "lines: {lines:?}"
    );
    assert_eq!(tail.get(1), Some(&logged_in_line()?), "lines: {lines:?}");
    assert!(harness.router.awaited_logins.is_empty());
    Ok(())
}

#[tokio::test]
async fn an_edge_reauthentication_sends_900_right_after_903() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    // The session already holds the account it authenticates to again.
    let sink = registered_guest(&mut harness, Some(account()))?;
    login_answered(&mut harness)?;
    let lines = sink.lines();
    let tail = lines
        .get(lines.len().saturating_sub(2)..)
        .ok_or("no lines")?;
    assert!(
        ends_with_903(tail.get(..1).ok_or("no 903")?),
        "lines: {lines:?}"
    );
    assert_eq!(tail.get(1), Some(&logged_in_line()?), "lines: {lines:?}");
    assert!(harness.router.awaited_logins.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_login_before_registration_awaits_no_900() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    login_answered(&mut harness)?;
    let lines = sink.lines();
    assert_eq!(
        lines.last().map(String::as_str),
        Some(":server.example 903 * :SASL authentication successful"),
        "lines: {lines:?}"
    );
    assert!(lines.iter().all(|line| !line.contains(" 900 ")));
    assert!(harness.router.awaited_logins.is_empty());
    Ok(())
}

#[tokio::test]
async fn an_awaited_login_is_forgotten_with_its_connection() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = registered_guest(&mut harness, None)?;
    login_answered(&mut harness)?;
    assert!(!harness.router.awaited_logins.is_empty());
    let context = harness.fixture.context_mut()?;
    harness.router.connection_closed(
        context,
        ConnectionGeneration::new(1),
        CloseReason::ClientQuit,
    );
    assert!(harness.router.awaited_logins.is_empty());
    // A projection arriving afterwards sends nothing to the closed client.
    let projection = record(&harness, 2, Some(account()))?;
    project(&mut harness, projection)?;
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completions(context, Vec::new());
    assert!(ends_with_903(&sink.lines()), "lines: {:?}", sink.lines());
    Ok(())
}

/// An awaited login the router cannot answer when it settles is never
/// forgotten silently. Here a caller holds the connection's state while the
/// projection naming the account is applied, and then the state is present
/// but unbound: each time the router closes the connection instead of
/// leaving its client without the `900`.
#[tokio::test]
async fn an_awaited_login_the_router_cannot_answer_closes_its_connection() -> TestResult {
    for detached in [true, false] {
        let mut harness = Harness::new(Role::Edge)?;
        let sink = registered_guest(&mut harness, None)?;
        login_answered(&mut harness)?;
        let generation = ConnectionGeneration::new(1);
        assert!(harness.router.awaited_logins.contains_key(&generation));
        let held = if detached {
            harness.router.connections.remove(&generation)
        } else {
            let state = harness
                .router
                .connections
                .get_mut(&generation)
                .ok_or("no connection state")?;
            state.bound = None;
            None
        };
        let projection = record(&harness, 2, Some(account()))?;
        project(&mut harness, projection)?;
        let context = harness.fixture.context_mut()?;
        harness.router.apply_edge_completions(context, Vec::new());
        assert!(harness.router.awaited_logins.is_empty());
        assert!(ends_with_903(&sink.lines()), "lines: {:?}", sink.lines());
        assert!(harness.sink_gone(1)?, "the connection must be closed");
        if let Some(state) = held {
            harness.router.connections.insert(generation, state);
        }
    }
    Ok(())
}

/// A router without an edge role never awaits a login; one that somehow
/// holds an awaited login closes that connection rather than forget it.
#[tokio::test]
async fn an_awaited_login_without_an_edge_role_closes_its_connection() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let _sink = harness.open(1, true)?;
    harness
        .router
        .awaited_logins
        .insert(ConnectionGeneration::new(1), account());
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completions(context, Vec::new());
    assert!(harness.router.awaited_logins.is_empty());
    assert!(harness.sink_gone(1)?, "the connection must be closed");
    Ok(())
}

/// A closing path can drop a connection's state, and close its transport,
/// before the transport reports the close. The awaited login is forgotten
/// with the connection all the same.
#[tokio::test]
async fn a_connection_closed_after_its_state_was_dropped_forgets_its_login() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let _sink = registered_guest(&mut harness, None)?;
    login_answered(&mut harness)?;
    let generation = ConnectionGeneration::new(1);
    harness
        .router
        .connections
        .remove(&generation)
        .ok_or("no connection state")?;
    let context = harness.fixture.context_mut()?;
    harness
        .router
        .connection_closed(context, generation, CloseReason::ProtocolError);
    assert!(harness.router.awaited_logins.is_empty());
    Ok(())
}
