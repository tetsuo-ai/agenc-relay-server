//! The authenticated account state of the welcome burst (architecture 10.2
//! step 6): one `900 <nick> <nick>!<user>@<host> <label-or-*> :You are now
//! logged in` after the MOTD group and the recovery NOTE, only for a
//! registration that bound an account. A coordinator or standalone node reads
//! the session from its domain, an edge from the session projection its
//! coordinator installed; a session the router cannot find fails the whole
//! burst closed.
#![forbid(unsafe_code)]

use agenc_relay_domain::federation::{ProjectedEvent, SessionEventView, SessionRecord};
use agenc_relay_domain::{
    AccountCommand, AccountLabelValue, CanonicalCommand, DisplayNameValue, PlanDecision,
};
use agenc_relay_types::{AccountId, Generation};

use super::test_harness::{Harness, Role, TestResult};
use super::*;
use crate::federation::edge::EdgeCompletion;
use crate::state_core::inbox::CloseReason;
use crate::test_support::{
    FrameSink, apply_live_plan, bind_live_session, bound, negotiated_capabilities, plan_live,
    seed_account, seed_session,
};

/// Every step the state machine plans for an authenticated registration
/// that negotiated `agenc.ag/recovery`.
const WITH_RECOVERY: [WelcomeStep; 7] = [
    WelcomeStep::WelcomeThroughMyInfo,
    WelcomeStep::Isupport,
    WelcomeStep::LuserCounters,
    WelcomeStep::Motd,
    WelcomeStep::RecoveryEpoch,
    WelcomeStep::AccountState,
    WelcomeStep::RegistrationBatches,
];

/// The same registration without `agenc.ag/recovery`.
const WITHOUT_RECOVERY: [WelcomeStep; 6] = [
    WelcomeStep::WelcomeThroughMyInfo,
    WelcomeStep::Isupport,
    WelcomeStep::LuserCounters,
    WelcomeStep::Motd,
    WelcomeStep::AccountState,
    WelcomeStep::RegistrationBatches,
];

const SESSION: SessionId = SessionId::from_bytes([43; 16]);
const USER: UserId = UserId::from_bytes([44; 16]);

/// The command or numeric of one server line.
fn command(line: &str) -> &str {
    line.split(' ').nth(1).unwrap_or_default()
}

fn commands(lines: &[String]) -> Vec<&str> {
    lines.iter().map(|line| command(line)).collect()
}

/// Checks a rendered prefix against the deterministic cloak of fixture
/// `seed`, whatever the cloak's visible spelling: the nickname, then a user
/// field holding the cloak's user component and a host field holding its
/// host component.
fn checked_mask(mask: String, nick: &str, seed: u8) -> TestResult<String> {
    let cloak = agenc_relay_testkit::deterministic_cloak(seed)?;
    let (nickname, fields) = mask.split_once('!').ok_or("a mask without a nickname")?;
    let (user, host) = fields.split_once('@').ok_or("a mask without a host")?;
    assert_eq!(nickname, nick);
    assert!(
        user.contains(std::str::from_utf8(cloak.user_component())?),
        "user field {user}"
    );
    assert!(
        host.contains(std::str::from_utf8(cloak.host_component())?),
        "host field {host}"
    );
    Ok(mask)
}

/// The prefix a coordinator or standalone node renders on every line of
/// `user`'s session, which the welcome's `900` repeats.
fn local_mask(harness: &mut Harness, user_id: UserId, nick: &str, seed: u8) -> TestResult<String> {
    let context = harness.fixture.context_mut()?;
    let session = context.domain().session(user_id).ok_or("no session")?;
    checked_mask(
        crate::mutation_render::rendered_prefix(session)?,
        nick,
        seed,
    )
}

/// The prefix an edge renders on every line of the projected session,
/// which the welcome's `900` repeats.
fn edge_mask(record: &SessionRecord, seed: u8) -> TestResult<String> {
    checked_mask(
        crate::federation::edge::EdgeFederation::rendered_prefix(&record.source_view())?,
        record.nickname.presentation(),
        seed,
    )
}

fn logged_in_line(nick: &str, mask: &str, label: &str) -> String {
    format!(":server.example 900 {nick} {mask} {label} :You are now logged in")
}

/// Leaves connection 1 as a committed local registration does: the session
/// of `nick`, with the seed-9 cloak and a fresh account that carries `label`,
/// is bound to the connection, and the router's state names that session and
/// nickname.
fn committed_local(
    harness: &mut Harness,
    nick: &str,
    label: Option<&str>,
) -> TestResult<(Arc<FrameSink>, agenc_relay_testkit::DomainTestIdentity)> {
    let context = harness.fixture.context_mut()?;
    let account = seed_account(context, 9, 1)?;
    let identity = seed_session(context, 9, nick, Some(account))?;
    if let Some(label) = label {
        let PlanDecision::Mutation(plan) = plan_live(context, identity, &|| {
            Ok(CanonicalCommand::account(AccountCommand::Label(Some(
                AccountLabelValue::parse(label)?,
            ))))
        })?
        else {
            return Err("the label command did not plan a mutation".into());
        };
        apply_live_plan(context, plan)?;
    }
    let capabilities = negotiated_capabilities(&["agenc.ag/recovery"])?;
    let sink = bind_live_session(context, 1, identity, capabilities, true)?;
    let generation = ConnectionGeneration::new(1);
    harness.router.connection_opened(context, generation);
    let state = harness
        .router
        .connections
        .get_mut(&generation)
        .ok_or("the router did not open the connection")?;
    state.bound = Some(bound(identity));
    state.nickname = Some(nick.to_owned());
    Ok((sink, identity))
}

#[tokio::test]
async fn an_authenticated_local_burst_ends_with_the_logged_in_state_after_the_note() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let (sink, keeper) = committed_local(&mut harness, "keeper", None)?;
    let outcome = harness.drive(
        1,
        vec![RegistrationAction::WelcomeBurst(WITH_RECOVERY.to_vec())],
    )?;
    assert!(matches!(outcome, RouteOutcome::Continue));
    let lines = sink.lines();
    assert_eq!(
        commands(&lines),
        [
            "001", "002", "003", "004", "005", "005", "005", "251", "422", "NOTE", "900"
        ],
        "lines: {lines:?}"
    );
    // An account without a public label is named `*`.
    let mask = local_mask(&mut harness, keeper.user_id, "keeper", 9)?;
    assert_eq!(lines.last(), Some(&logged_in_line("keeper", &mask, "*")));
    Ok(())
}

#[tokio::test]
async fn the_logged_in_state_names_the_public_label_right_after_the_motd_group() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let (sink, labeled) = committed_local(&mut harness, "labeled", Some("PublicLabel"))?;
    harness.drive(
        1,
        vec![RegistrationAction::WelcomeBurst(WITHOUT_RECOVERY.to_vec())],
    )?;
    let lines = sink.lines();
    assert_eq!(
        commands(&lines),
        [
            "001", "002", "003", "004", "005", "005", "005", "251", "422", "900"
        ],
        "lines: {lines:?}"
    );
    let mask = local_mask(&mut harness, labeled.user_id, "labeled", 9)?;
    assert_eq!(
        lines.last(),
        Some(&logged_in_line("labeled", &mask, "PublicLabel"))
    );
    Ok(())
}

#[tokio::test]
async fn a_local_burst_whose_session_has_no_account_state_fails_closed() -> TestResult {
    // A session the domain does not hold, and one without an account: the
    // router cannot name a logged-in state, so it sends no part of the burst.
    for in_domain in [false, true] {
        let mut harness = Harness::new(Role::Plain)?;
        let context = harness.fixture.context_mut()?;
        let identity = if in_domain {
            seed_session(context, 9, "guest", None)?
        } else {
            agenc_relay_testkit::DomainTestIdentity {
                session_id: SESSION,
                user_id: USER,
                generation: Generation::new(1)?,
                account_id: None,
            }
        };
        let sink = bind_live_session(context, 1, identity, negotiated_capabilities(&[])?, true)?;
        let generation = ConnectionGeneration::new(1);
        harness.router.connection_opened(context, generation);
        let state = harness
            .router
            .connections
            .get_mut(&generation)
            .ok_or("the router did not open the connection")?;
        state.bound = Some(bound(identity));
        state.nickname = Some("guest".to_owned());
        let outcome = harness.drive(
            1,
            vec![RegistrationAction::WelcomeBurst(WITHOUT_RECOVERY.to_vec())],
        )?;
        assert!(
            matches!(outcome, RouteOutcome::Close(CloseReason::ProtocolError)),
            "a missing logged-in state must close the connection"
        );
        assert!(sink.lines().is_empty(), "lines: {:?}", sink.lines());
    }
    Ok(())
}

/// Brings edge client 1 to its registration commit after negotiating
/// `agenc.ag/recovery`, records the pre-registration grant its carrier
/// holds, and returns the commit generation the coordinator's answer names.
fn edge_commit(harness: &mut Harness, nick: &str, account: AccountId) -> TestResult<u64> {
    harness.line(1, "CAP LS 302")?;
    harness.line(1, "CAP REQ :agenc.ag/recovery")?;
    harness.line(1, &format!("NICK {nick}"))?;
    harness.line(1, &format!("USER {nick} 0 * :Real"))?;
    let event_generation = match harness.actions(1, "CAP END")?.into_iter().next() {
        Some(RegistrationAction::CommitRegistration { generation, .. }) => generation,
        other => return Err(format!("expected the registration commit, got {other:?}").into()),
    };
    let mut carrier = EdgeCarrier::new()?;
    carrier.grant = Some((account, 1, [45; 32]));
    harness
        .router
        .edge_carriers
        .insert(ConnectionGeneration::new(1), carrier);
    Ok(event_generation)
}

fn session_registered(event_generation: u64, nick: &str) -> EdgeCompletion {
    EdgeCompletion::SessionRegistered {
        generation: ConnectionGeneration::new(1),
        session_id: SESSION,
        user_id: USER,
        event_generation,
        nickname: nick.to_owned(),
    }
}

#[tokio::test]
async fn an_authenticated_edge_burst_reads_the_logged_in_state_from_the_replica() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    let account = agenc_relay_testkit::account_id(46);
    let event_generation = edge_commit(&mut harness, "remote", account)?;
    // The session projection the coordinator installs on its home edge
    // before the registration completes.
    let record = SessionRecord {
        session_id: SESSION,
        user_id: USER,
        home_server_id: harness.fixture.identity.server_id,
        session_revision: Revision::new(1)?,
        account: Some((account, Generation::new(1)?)),
        nickname: NicknameValue::parse("remote")?,
        display_name: DisplayNameValue::prepare("Real")?,
        public_cloak: agenc_relay_testkit::deterministic_cloak(12)?,
        account_label: Some(AccountLabelValue::parse("EdgeLabel")?),
        user_mode_bits: 1,
        away: None,
    };
    let mask = edge_mask(&record, 12)?;
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
            1,
        )?;
    let context = harness.fixture.context_mut()?;
    harness
        .router
        .apply_edge_completion(context, session_registered(event_generation, "remote"));
    let lines = sink.lines();
    let first = lines
        .iter()
        .position(|line| command(line) == "001")
        .ok_or_else(|| format!("no welcome in {lines:?}"))?;
    let welcome = lines.get(first..).ok_or("no burst")?;
    assert_eq!(
        commands(welcome),
        [
            "001", "002", "003", "004", "005", "005", "005", "251", "255", "422", "NOTE", "900"
        ],
        "lines: {lines:?}"
    );
    assert_eq!(
        welcome.last(),
        Some(&logged_in_line("remote", &mask, "EdgeLabel"))
    );
    Ok(())
}

#[tokio::test]
async fn an_authenticated_edge_burst_without_its_projection_fails_closed() -> TestResult {
    let mut harness = Harness::new(Role::Edge)?;
    let sink = harness.open(1, true)?;
    let event_generation =
        edge_commit(&mut harness, "remote", agenc_relay_testkit::account_id(46))?;
    let context = harness.fixture.context_mut()?;
    harness
        .router
        .apply_edge_completion(context, session_registered(event_generation, "remote"));
    let lines = sink.lines();
    assert!(
        lines.iter().all(|line| command(line) != "001"),
        "no part of the burst may be sent: {lines:?}"
    );
    assert!(harness.sink_gone(1)?, "the connection must be closed");
    Ok(())
}

/// One session's `900` names the prefix every other line of that session
/// carries, so a coordinator and an edge spell it alike. The testkit's
/// transcript model renders the same `900` for its registered session, so
/// its mask must be spelled as this node spells it: a change to the visible
/// cloak spelling changes the renderers here and must change the model too.
#[tokio::test]
async fn the_900_mask_is_spelled_alike_by_both_paths_and_the_transcript_model() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let context = harness.fixture.context_mut()?;
    let identity = seed_session(context, 9, "keeper", None)?;
    let session = context
        .domain()
        .session(identity.user_id)
        .ok_or("no session")?;
    let source = agenc_relay_domain::federation::SourceView {
        user_id: identity.user_id,
        nickname: session.nickname().clone(),
        public_cloak: session.public_cloak(),
        account_label: None,
    };
    let local = crate::mutation_render::rendered_prefix(session)?;
    assert_eq!(
        crate::federation::edge::EdgeFederation::rendered_prefix(&source)?,
        local
    );
    checked_mask(local, "keeper", 9)?;

    // The model's registered session: `Alice` with the fixture-zero cloak.
    let model = agenc_relay_domain::federation::SourceView {
        user_id: USER,
        nickname: NicknameValue::parse("Alice")?,
        public_cloak: agenc_relay_testkit::deterministic_cloak(0)?,
        account_label: None,
    };
    assert_eq!(
        agenc_relay_testkit::transcript_mask("Alice")?,
        crate::federation::edge::EdgeFederation::rendered_prefix(&model)?
    );
    Ok(())
}
