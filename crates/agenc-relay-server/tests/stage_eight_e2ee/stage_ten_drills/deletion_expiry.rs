//! Architecture §14.6 and SDK-M2-003. Exercise the issuing relay's own monotonic
//! deletion deadline and the subsequent fresh same-account login on its real TLS listener.
#![forbid(unsafe_code)]

use super::*;

fn registered_expiry_on(select: fn(&Network) -> &NodeFixture) -> TestResult {
    let network = drill_network()?;
    let logs = TestRoot::create()?;
    let mut nodes = DrillNodes::start_capturing(&network, logs.path())?;
    let fixture = select(&network);
    let account = {
        let mut creation = ArcClient::connect(fixture)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, fixture, DELETION_LOGIN, 212)?
    };
    let mut original = open_deletion_session(fixture, account, "expiry-origin", DELETION_CAPS)?;
    let expired = issue_deletion_challenge(&mut original)?;
    let lifetime = Duration::from_millis(agenc_relay_auth::DELETION_CONFIRMATION_TIMEOUT_TICKS);
    let received = Instant::now();
    while let Some(remaining) = lifetime.checked_sub(received.elapsed()) {
        thread::sleep(remaining.min(Duration::from_secs(15)));
        original.send("PING :deletion-expiry")?;
        original.read_until(|line| line.ends_with(" PONG :deletion-expiry"))?;
    }
    original.send(&format!("ACCT DELETE CONFIRM {expired}"))?;
    let refused = acct_reply(&mut original)?;
    assert!(
        refused.contains(" FAIL ACCT BAD_STATE "),
        "an expired confirmation must be refused"
    );
    quit_and_drain(&mut original, "expired")?;
    drop(original);

    let mut fresh = open_deletion_session(fixture, account, "expiry-fresh", DELETION_CAPS)?;
    let current = issue_deletion_challenge(&mut fresh)?;
    assert!(
        current != expired,
        "fresh authentication must issue a distinct challenge"
    );
    fresh.send(&format!("ACCT DELETE CONFIRM {current}"))?;
    let closing = read_deleted_connection_closure(&mut fresh.reader)?;
    assert!(closing.last().is_some_and(|line| is_deletion_note(line)));
    drop(fresh);
    assert_eq!(nodes.stop_all(), [true; 3]);
    Ok(())
}

#[test]
fn registered_deletion_challenge_expires_on_coordinator() -> TestResult {
    registered_expiry_on(|network| &network.coordinator)
}

#[test]
fn registered_deletion_challenge_expires_on_edge() -> TestResult {
    registered_expiry_on(|network| &network.edge_a)
}
