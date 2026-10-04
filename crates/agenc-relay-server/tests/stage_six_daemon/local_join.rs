//! AUD-16: a lone JOIN of a local `&` channel on a core-only node is answered,
//! and the commands behind it on the same connection still run.
#![forbid(unsafe_code)]

use super::*;

/// A `&` channel is never persisted, so the JOIN projects no durable write and
/// the node applies it in the same step that admits it. Before the fix its
/// NAMES snapshot never opened, the JOIN got no reply, and every later
/// registered command on the connection waited behind it; a `PING` was still
/// answered, because it never waits for a JOIN.
#[test]
fn a_lone_local_join_is_answered_and_the_next_command_still_runs() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut client = ArcClient::connect(&fixture)?;
    let registered = client.complete_registration("LocalJoin")?;
    assert_contains(&registered, " 001 LocalJoin ")?;

    let joined = client.send_until("JOIN &plain", " 366 ")?;
    assert_contains(&joined, " JOIN &plain")?;
    assert_contains(&joined, " 353 LocalJoin = &plain :")?;
    assert_contains(&client.send_until("TIME", " 391 ")?, " 391 LocalJoin ")?;

    client.send_until("CAP REQ :message-tags batch labeled-response", " ACK ")?;
    let joined = client.send_until("@label=join JOIN &labeled", " BATCH -")?;
    assert_contains(&joined, "@label=join ")?;
    assert_contains(&joined, " JOIN &labeled")?;
    assert_contains(&joined, " 353 LocalJoin = &labeled :")?;
    assert_contains(&joined, " 366 LocalJoin &labeled ")?;
    let time = client.send_until("@label=time TIME", " 391 ")?;
    assert_contains(&time, "@label=time ")?;

    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :local join regression complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}
