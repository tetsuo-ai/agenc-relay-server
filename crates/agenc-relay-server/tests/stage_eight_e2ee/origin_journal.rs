//! Architecture 20.7 through the production daemons of the Stage 08 network
//! with both profiles active: an edge that restarts before an origin
//! deletion's acknowledgement is durable replays the deletion its link sent,
//! and its link comes up and stays up. A client authenticated as an account
//! registers on edge A, which queues its origin's update, and its connection
//! ends: right after the welcome, while the update usually waits for its
//! journal write, or once the update has gone out on a link that is then cut,
//! so the coordinator never reads it. The relay between edge A and the
//! coordinator holds what the coordinator sends edge A, and the link is cut
//! once the coordinator's count of authenticated sessions drops, which it
//! does when it closes the client's session after committing the deletion,
//! so the deletion's acknowledgement is lost; edge A restarts.
#![forbid(unsafe_code)]

use super::link_faults::{Relay, link_events, relayed_network, wait_for_closures};
use super::stage_ten_capacity::admin_client::AdminSession;
use super::stage_ten_capacity::admin_identity;
use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// How long the relay holds what the coordinator sends edge A while a link
/// comes up: each answer of the handshake waits that long, within the hello
/// deadline.
const ANSWER_HOLD: Duration = Duration::from_millis(1_200);
/// How long the relay holds what the coordinator sends edge A over a link
/// that is up, so a cut drops the acknowledgement of a deletion the
/// coordinator committed.
const LINKED_HOLD: Duration = Duration::from_secs(3);
/// How long the relay holds what edge A sends while its update is to be
/// dropped by a cut.
const UPDATE_HOLD: Duration = Duration::from_secs(2);
/// Time for edge A to journal and send what a closed connection owes, well
/// within either hold.
const SETTLE: Duration = Duration::from_millis(500);
/// How long edge A's restored link must stay up.
const HOLD_UP: Duration = Duration::from_secs(5);
/// The account the client on edge A authenticates as.
const LOGIN: &str = "origin-journal-account";

/// Runs `scenario` over the relayed network with edge A's daemon and an
/// account created through edge B in hand, then stops every daemon.
fn run_restartable(
    scenario: impl FnOnce(&Network, &Relay, &mut DaemonProcess, AccountId) -> TestResult,
) -> TestResult {
    let (network, relay) = relayed_network()?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let outcome = (|| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_link(&network.edge_b, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        wait_for_account_authority(&network.edge_b)?;
        let account = {
            let mut creation = ArcClient::connect(&network.edge_b)?;
            creation.negotiate_sasl()?;
            create_live_account(&mut creation, &network.edge_b, LOGIN, 61)?
        };
        scenario(&network, &relay, &mut edge_a, account)
    })();
    let stopped = [edge_a.stop(), edge_b.stop(), coordinator.stop()];
    drop(relay);
    if let Err(error) = outcome {
        return Err(failure(format!(
            "{error}\n--- coordinator log ---\n{}\n--- edge a log ---\n{}",
            network.coordinator.log_text(),
            network.edge_a.log_text(),
        )));
    }
    for status in stopped {
        if !status?.success() {
            return Err(failure("a daemon exited with a failure"));
        }
    }
    Ok(())
}

/// Registers `nickname` on edge A and returns the connection once its
/// welcome begins.
fn welcomed(network: &Network, nickname: &str) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(&network.edge_a)?;
    register(&mut client, nickname, false)?;
    Ok(client)
}

/// Sends `client`'s registration, ending its capability negotiation when
/// `negotiated`, and reads until its welcome begins.
fn register(client: &mut ArcClient, nickname: &str, negotiated: bool) -> TestResult {
    client.send(&format!("NICK {nickname}"))?;
    client.send(&format!("USER {nickname} 0 * :Origin Journal"))?;
    if negotiated {
        client.send("CAP END")?;
    }
    let _welcome = client.read_until(|line| line.contains(&format!(" 001 {nickname} ")))?;
    Ok(())
}

/// A connection to edge A authenticated as `account` before registration,
/// so the session its registration opens is an authenticated one.
fn logged_in(network: &Network, account: AccountId) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(&network.edge_a)?;
    client.send("CAP LS 302")?;
    let _advertised =
        client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))?;
    let _acknowledged = client.send_until("CAP REQ :sasl", " CAP * ")?;
    authenticate_live_account(
        &mut client,
        &network.edge_a,
        LOGIN,
        ACCOUNT_PASSWORD,
        63,
        account,
    )?;
    Ok(client)
}

/// The authenticated sessions the coordinator holds, network-wide.
fn authenticated_sessions(network: &Network) -> TestResult<u64> {
    AdminSession::connect(&admin_identity(&network.coordinator))?
        .stats("RUNTIME")?
        .into_iter()
        .find(|(name, _)| name == "authenticated_sessions")
        .map(|(_, value)| value)
        .ok_or_else(|| failure("the authenticated session counter is missing"))
}

/// Waits until the coordinator holds no more than `count` authenticated
/// sessions: it closes the deleted origin's session once it has committed
/// the deletion, whose acknowledgement it sent before.
fn sessions_closed_to(network: &Network, count: u64) -> TestResult {
    let deadline = Instant::now() + NETWORK_WAIT;
    while authenticated_sessions(network)? > count {
        if Instant::now() >= deadline {
            return Err(failure("the deleted origin's session never closed"));
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// Cuts edge A's link and waits until the coordinator saw it close.
fn cut(network: &Network, relay: &Relay) -> TestResult {
    let (closures, _) = link_events(network);
    relay.cut();
    wait_for_closures(network, closures + 1)
}

/// With the deletion committed and its acknowledgement held in the relay,
/// cuts the link, restarts edge A and heals the link. Requires that edge A
/// links once, that its link stays up and that a guest then registers on
/// it.
fn restart_before_the_acknowledgement(
    network: &Network,
    relay: &Relay,
    edge_a: &mut DaemonProcess,
) -> TestResult {
    step("cut", cut(network, relay))?;
    relay.hold_inbound(Duration::ZERO);
    if !edge_a.stop()?.success() {
        return Err(failure("edge A did not stop cleanly"));
    }
    let (closures, established) = link_events(network);
    *edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    relay.heal();
    wait_for_link(&network.edge_a, established)?;
    thread::sleep(HOLD_UP);
    if link_events(network) != (closures, established + 1) {
        return Err(failure(format!(
            "edge A's link failed after it restarted: {:?} -> {:?}",
            (closures, established + 1),
            link_events(network)
        )));
    }
    drop(step("guest", welcomed(network, "afterrestart"))?);
    Ok(())
}

/// The connection ends right after the welcome, usually before the update
/// its registration queued has gone out: the live link's deletion then names
/// the acknowledged generation and its next sequence, which the coordinator
/// commits on the ready link. The restarted edge must replay that deletion.
#[test]
fn a_restarted_edge_replays_the_deletion_its_live_link_sent() -> TestResult {
    run_restartable(|network, relay, edge_a, account| {
        let before = authenticated_sessions(network)?;
        let mut client = logged_in(network, account)?;
        register(&mut client, "unsent", true)?;
        relay.hold_inbound(LINKED_HOLD);
        drop(client);
        // Edge A journals and sends the deletion and the coordinator commits
        // it, then closes the session; the acknowledgement is still held.
        step("session closed", sessions_closed_to(network, before))?;
        restart_before_the_acknowledgement(network, relay, edge_a)
    })
}

/// The update goes out on a link that is cut before the coordinator reads
/// it, and the connection ends while the link is down. The next link
/// replays the deletion, naming that update at sequence zero, and the
/// coordinator, which never committed the update, closes the origin at the
/// generation it holds; the restarted edge replays the same deletion to the
/// coordinator, ready again with the origin already deleted.
#[test]
fn a_restarted_edge_replays_the_deletion_of_an_update_the_coordinator_never_read() -> TestResult {
    run_restartable(|network, relay, edge_a, account| {
        let before = authenticated_sessions(network)?;
        let mut client = logged_in(network, account)?;
        relay.hold_outbound(UPDATE_HOLD);
        register(&mut client, "carried", true)?;
        thread::sleep(SETTLE);
        step("cut", cut(network, relay))?;
        relay.hold_outbound(Duration::ZERO);
        drop(client);
        thread::sleep(SETTLE);
        relay.hold_inbound(ANSWER_HOLD);
        let (_, established) = link_events(network);
        relay.heal();
        wait_for_link(&network.edge_a, established)?;
        relay.hold_inbound(LINKED_HOLD);
        // The suspended session stays the coordinator's until the replayed
        // deletion commits and the coordinator closes it; the deletion's
        // acknowledgement is then still held in the relay.
        step("session closed", sessions_closed_to(network, before))?;
        restart_before_the_acknowledgement(network, relay, edge_a)
    })
}
