//! Architecture 11.4 through the production binary: a guest that logs in
//! after registration reads its `903` and then the later `900`, whose mask is
//! its own prefix and whose label is the account's public label; every
//! channel peer that negotiated `account-notify` reads `ACCOUNT <label>` from
//! it, and a peer that did not reads nothing. A reauthentication to the same
//! account repeats the `900` and names nothing to the peers, and a logout
//! still names `ACCOUNT *` to them and answers the client with nothing.
#![forbid(unsafe_code)]

use super::*;

/// The PING whose PONG marks that everything sent before it was read.
const BARRIER: &str = "login-sync";

/// Negotiates exactly `request` on a fresh connection.
fn negotiated(fixture: &LiveFixture, request: &str) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    read_until(&mut client.reader, |line| {
        line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :")
    })?;
    let acknowledged = client.send_until(&format!("CAP REQ :{request}"), " CAP * ")?;
    assert_contains(&acknowledged, &format!(" CAP * ACK :{request}"))?;
    Ok(client)
}

/// A guest registered as `nickname` after negotiating `request`, in
/// `#login`; also returns its own prefix from the JOIN echo, and the server
/// prefix of its replies.
fn joined_guest(
    fixture: &LiveFixture,
    nickname: &str,
    request: &str,
) -> TestResult<(ArcClient, String, String)> {
    let mut client = negotiated(fixture, request)?;
    client.complete_registration(nickname)?;
    let joined = client.send_until("JOIN #login", " 366 ")?;
    let prefix = joined
        .iter()
        .find(|line| line.ends_with(" JOIN #login") || line.ends_with(" JOIN :#login"))
        .and_then(|line| line.split(' ').next())
        .and_then(|prefix| prefix.strip_prefix(':'))
        .ok_or_else(|| failure(format!("no JOIN echo in {joined:?}")))?
        .to_owned();
    let server = joined
        .last()
        .and_then(|line| line.split(' ').next())
        .ok_or_else(|| failure(format!("no 366 in {joined:?}")))?
        .to_owned();
    Ok((client, prefix, server))
}

/// Every line `client` received before the PONG of a fresh PING.
fn drained(client: &mut ArcClient) -> TestResult<Vec<String>> {
    client.send(&format!("PING :{BARRIER}"))?;
    let mut lines = read_until(&mut client.reader, |line| {
        line.ends_with(&format!("PONG :{BARRIER}"))
    })?;
    lines.pop();
    Ok(lines)
}

#[test]
fn a_login_after_registration_follows_903_with_900_and_names_the_account() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let account_id = {
        let mut creation = ArcClient::connect(&fixture)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, &fixture)?
    };
    // A session that already holds the account gives it a public label.
    let mut holder = negotiated(&fixture, "sasl standard-replies agenc.ag/account-controls")?;
    authenticate_live_account(&mut holder, &fixture, ACCOUNT_PASSWORD, 120, account_id)?;
    holder.complete_registration("holder")?;
    let labeled = holder.send_until("ACCT LABEL Kestrel", " NOTE ACCT UPDATED ")?;
    assert_contains(&labeled, " NOTE ACCT UPDATED ")?;

    let (mut notified, _, _) = joined_guest(&fixture, "notified", "account-notify")?;
    let (mut quiet, _, _) = joined_guest(&fixture, "quiet", "standard-replies")?;
    let (mut guest, prefix, server) = joined_guest(&fixture, "guest", "sasl")?;
    for client in [&mut notified, &mut quiet, &mut guest] {
        drained(client)?;
    }

    // The login: chunks and 903, then 900 naming the session and the label.
    authenticate_live_account(&mut guest, &fixture, ACCOUNT_PASSWORD, 122, account_id)?;
    let logged_in = format!("{server} 900 guest {prefix} Kestrel :You are now logged in");
    assert_eq!(guest.account_state.as_deref(), Some(logged_in.as_str()));
    assert_eq!(
        drained(&mut notified)?,
        [format!(":{prefix} ACCOUNT Kestrel")]
    );
    assert_eq!(drained(&mut quiet)?, Vec::<String>::new());
    // The guest did not negotiate account-notify: nothing follows its 900.
    assert_eq!(drained(&mut guest)?, Vec::<String>::new());

    // A reauthentication repeats the 900 and changes nothing public.
    guest.account_state = None;
    authenticate_live_account(&mut guest, &fixture, ACCOUNT_PASSWORD, 124, account_id)?;
    assert_eq!(guest.account_state.as_deref(), Some(logged_in.as_str()));
    assert_eq!(drained(&mut notified)?, Vec::<String>::new());

    // The logout is unchanged: its notify peers read ACCOUNT *, and the
    // client itself reads nothing.
    guest.send("AUTHENTICATE *")?;
    assert_eq!(drained(&mut guest)?, Vec::<String>::new());
    assert_eq!(drained(&mut notified)?, [format!(":{prefix} ACCOUNT *")]);
    assert_eq!(drained(&mut quiet)?, Vec::<String>::new());

    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :login after registration complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}
