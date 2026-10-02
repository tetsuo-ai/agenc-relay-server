//! Architecture 11.4 through production edges linked to a production
//! coordinator. A guest that logs in after registration reads its `903` and
//! then the `900` naming its own prefix and the account's public label; a
//! channel peer that negotiated `account-notify` on the guest's own node
//! reads `ACCOUNT <label>` from it, and so does one on the coordinator when
//! an edge homes the guest, while a peer without the capability reads
//! nothing. A same-account reauthentication repeats the `900` alone. The
//! guests share their channel with a member another node homes, so each
//! login recomputes memberships the coordinator projects to that node, and
//! the channel keeps carrying messages afterwards.
#![forbid(unsafe_code)]

use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// The PING whose PONG marks that everything sent before it was read.
const BARRIER: &str = "login-sync";
const LOGIN: &str = "edge-login-account";

/// A fresh connection to `fixture` that negotiated exactly `request`.
fn negotiated(fixture: &NodeFixture, request: &str) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))?;
    let acknowledged = client.send_until(&format!("CAP REQ :{request}"), " CAP * ")?;
    assert_contains(&acknowledged, &format!(" CAP * ACK :{request}"))?;
    Ok(client)
}

/// A client registered as `nickname` after negotiating `request`, in
/// `channel`, and its own prefix from the JOIN echo.
fn joined(
    fixture: &NodeFixture,
    nickname: &str,
    request: &str,
    channel: &str,
) -> TestResult<(ArcClient, String)> {
    let mut client = negotiated(fixture, request)?;
    client.complete_registration(nickname)?;
    let echo = client.send_until(&format!("JOIN {channel}"), " 366 ")?;
    let prefix = echo
        .iter()
        .find(|line| {
            line.ends_with(&format!(" JOIN {channel}"))
                || line.ends_with(&format!(" JOIN :{channel}"))
        })
        .and_then(|line| line.split(' ').next())
        .and_then(|prefix| prefix.strip_prefix(':'))
        .ok_or_else(|| failure(format!("no JOIN echo in {echo:?}")))?
        .to_owned();
    Ok((client, prefix))
}

/// Every line `client` received before the PONG of a fresh PING.
fn drained(client: &mut ArcClient) -> TestResult<Vec<String>> {
    client.send(&format!("PING :{BARRIER}"))?;
    let mut lines = client.read_until(|line| line.ends_with(&format!("PONG :{BARRIER}")))?;
    lines.pop();
    Ok(lines)
}

/// The next line containing `needle`, which must be the only line read.
fn next_line(client: &mut ArcClient, needle: &str) -> TestResult<String> {
    let lines = client.read_until(|line| line.contains(needle))?;
    match lines.as_slice() {
        [line] => Ok(line.clone()),
        _ => Err(failure(format!(
            "expected one {needle:?} line, read {lines:?}"
        ))),
    }
}

/// Creates the account on edge A and gives it the public label `Kestrel`
/// through a session that already holds it; returns both connections.
fn labeled_account(network: &Network) -> TestResult<(AccountId, ArcClient, ArcClient)> {
    let mut creation = ArcClient::connect(&network.edge_a)?;
    creation.negotiate_sasl()?;
    let account_id = create_live_account(&mut creation, &network.edge_a, LOGIN, 81)?;
    let mut holder = negotiated(
        &network.edge_a,
        "sasl standard-replies agenc.ag/account-controls",
    )?;
    authenticate_live_account(
        &mut holder,
        &network.edge_a,
        LOGIN,
        ACCOUNT_PASSWORD,
        83,
        account_id,
    )?;
    holder.complete_registration("holder")?;
    let labeled = holder.send_until("ACCT LABEL Kestrel", " NOTE ACCT UPDATED ")?;
    assert_contains(&labeled, " NOTE ACCT UPDATED ")?;
    Ok((account_id, creation, holder))
}

#[test]
fn an_edge_login_after_registration_sends_900_and_names_the_account() -> TestResult {
    super::encrypted_clients::run_network(edge_login)
}

fn edge_login(
    network: &Network,
    _coordinator: &mut DaemonProcess,
    _edge_a: &mut DaemonProcess,
    _edge_b: &mut DaemonProcess,
) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    wait_for_account_authority(&network.edge_a)?;
    // Every connection stays open until the scenario ends.
    let (account_id, creation, holder) = labeled_account(network)?;
    let (mut local, _) = joined(&network.edge_a, "local", "account-notify", "#login")?;
    let (mut quiet, _) = joined(&network.edge_a, "quiet", "standard-replies", "#login")?;
    let (mut core, _) = joined(&network.coordinator, "core", "account-notify", "#login")?;
    let (mut remote, _) = joined(&network.edge_b, "remote", "account-notify", "#login")?;
    let (mut guest, prefix) = joined(&network.edge_a, "guest", "sasl account-notify", "#login")?;
    for client in [&mut local, &mut quiet, &mut core, &mut remote, &mut guest] {
        drained(client)?;
    }

    // The login: the response chunks and 903, then the 900 naming the
    // guest's own prefix and the account's label.
    authenticate_live_account(
        &mut guest,
        &network.edge_a,
        LOGIN,
        ACCOUNT_PASSWORD,
        85,
        account_id,
    )?;
    let logged_in = format!(":edge-a.test 900 guest {prefix} Kestrel :You are now logged in");
    assert_eq!(guest.account_state.as_deref(), Some(logged_in.as_str()));
    // The account-notify members of the guest's edge, the guest included,
    // and of the coordinator learn the account.
    let named = format!(":{prefix} ACCOUNT Kestrel");
    for client in [&mut guest, &mut local, &mut core] {
        assert_eq!(next_line(client, " ACCOUNT ")?, named);
    }
    // The quiet member shares the local member's edge and its fanout.
    assert_eq!(drained(&mut quiet)?, Vec::<String>::new());
    // Edge B applied the recomputed membership: the channel still carries
    // the logged-in guest's messages to it.
    guest.send("PRIVMSG #login :logged in")?;
    let said = format!(":{prefix} PRIVMSG #login :logged in");
    for client in [&mut remote, &mut core, &mut local, &mut quiet] {
        assert_eq!(next_line(client, " PRIVMSG ")?, said);
    }

    // A reauthentication repeats the 900 and names nothing.
    guest.account_state = None;
    authenticate_live_account(
        &mut guest,
        &network.edge_a,
        LOGIN,
        ACCOUNT_PASSWORD,
        87,
        account_id,
    )?;
    assert_eq!(guest.account_state.as_deref(), Some(logged_in.as_str()));
    for client in [&mut guest, &mut local, &mut quiet, &mut core] {
        assert_eq!(drained(client)?, Vec::<String>::new());
    }
    drop((creation, holder, remote));
    Ok(())
}

#[test]
fn a_coordinator_login_after_registration_sends_900_and_names_the_account() -> TestResult {
    super::encrypted_clients::run_network(coordinator_login)
}

fn coordinator_login(
    network: &Network,
    _coordinator: &mut DaemonProcess,
    _edge_a: &mut DaemonProcess,
    _edge_b: &mut DaemonProcess,
) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    wait_for_account_authority(&network.edge_a)?;
    let (account_id, creation, holder) = labeled_account(network)?;
    let (mut local, _) = joined(&network.coordinator, "local", "account-notify", "#core")?;
    let (mut member, _) = joined(&network.edge_b, "member", "account-notify", "#core")?;
    let (mut guest, prefix) = joined(&network.coordinator, "guest", "sasl", "#core")?;
    for client in [&mut local, &mut member, &mut guest] {
        drained(client)?;
    }
    // The coordinator seals nothing itself: the edge fixtures pin the same
    // coordinator epoch the account requests bind.
    authenticate_live_account(
        &mut guest,
        &network.edge_a,
        LOGIN,
        ACCOUNT_PASSWORD,
        85,
        account_id,
    )?;
    assert_eq!(
        guest.account_state.as_deref(),
        Some(format!(":core.test 900 guest {prefix} Kestrel :You are now logged in").as_str())
    );
    assert_eq!(
        next_line(&mut local, " ACCOUNT ")?,
        format!(":{prefix} ACCOUNT Kestrel")
    );
    // The guest did not negotiate account-notify: nothing follows its 900.
    assert_eq!(drained(&mut guest)?, Vec::<String>::new());
    // Edge B applied the recomputed membership of its channel.
    guest.send("PRIVMSG #core :logged in")?;
    assert_eq!(
        next_line(&mut member, " PRIVMSG ")?,
        format!(":{prefix} PRIVMSG #core :logged in")
    );
    drop((creation, holder, local));
    Ok(())
}
