//! RUN-10: pipelined commands are processed in order, never refused for
//! being in flight, and a server-initiated close names its reason.
#![forbid(unsafe_code)]

use super::*;

const CHANNEL: &str = "#pipeline";

/// Registers `nickname` and joins the shared channel.
fn member(fixture: &LiveFixture, nickname: &str) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(fixture)?;
    let registered = client.complete_registration(nickname)?;
    assert_contains(&registered, &format!(" 001 {nickname} "))?;
    client.send_until(&format!("JOIN {CHANNEL}"), " 366 ")?;
    Ok(client)
}

/// Writes every line plus the marker `PING` with one transport write.
fn write_pipelined(client: &mut ArcClient, lines: &[String]) -> TestResult {
    let mut bytes = Vec::new();
    for line in lines {
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"PING :pipelined\r\n");
    client.reader.get_mut().write_all(&bytes)?;
    client.reader.get_mut().flush()?;
    Ok(())
}

fn bodies(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("burst-{index:02}"))
        .collect()
}

/// Raises the two per-sender message buckets to their Appendix C.6 hard
/// values, so the burst sizes below measure the output path and not the
/// specified sender rate limit.
fn fixture_with_wide_message_buckets() -> TestResult<LiveFixture> {
    let fixture = LiveFixture::create()?;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        "\n[limits.rate.preauth_command]",
        "\n[limits.rate.guest_message]\nrefill_tokens = 5\nrefill_seconds = 1\nburst = 20\n\n[limits.rate.account_message]\nrefill_tokens = 20\nrefill_seconds = 1\nburst = 100\n\n[limits.rate.preauth_command]",
    )?;
    fs::write(&fixture.config_path, config)?;
    Ok(fixture)
}

fn privmsgs(expected: &[String]) -> Vec<String> {
    expected
        .iter()
        .map(|body| format!("PRIVMSG {CHANNEL} :{body}"))
        .collect()
}

fn delivered_bodies(received: &[String]) -> Vec<String> {
    received
        .iter()
        .filter_map(|line| line.split_once(" :burst-"))
        .map(|(_, tail)| format!("burst-{tail}"))
        .collect()
}

fn stop(fixture: &LiveFixture, daemon: &mut DaemonProcess) -> TestResult {
    let mut admin = AdminClient::connect(fixture)?;
    admin.confirm_process("DIE :pipelined regression complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}

/// The sender pipelines `count` PRIVMSGs and a marker in one write; the
/// second member receives every message in order, the sender receives only
/// its `PONG`, and nobody is closed.
fn assert_pipelined_delivery(
    fixture: &LiveFixture,
    sender: &mut ArcClient,
    count: usize,
) -> TestResult {
    let mut receiver = member(fixture, "PipeRecv")?;
    read_until(&mut sender.reader, |line| line.contains(" JOIN "))?;
    let expected = bodies(count);
    write_pipelined(sender, &privmsgs(&expected))?;
    let replies = read_leniently(sender, |line| line.ends_with("PONG :pipelined"));
    let last = expected.last().cloned().unwrap_or_default();
    let received = read_leniently(&mut receiver, |line| line.ends_with(&last));
    assert_eq!(
        delivered_bodies(&received),
        expected,
        "sender saw {replies:?}; {}",
        fixture.log_excerpt()
    );
    assert_eq!(replies.len(), 1, "sender saw {replies:?}");
    assert_contains(&replies, "PONG :pipelined")?;
    assert!(
        !fixture.log_excerpt().contains("slow_consumer"),
        "{}",
        fixture.log_excerpt()
    );
    Ok(())
}

fn guest_pipelines(count: usize) -> TestResult {
    let fixture = fixture_with_wide_message_buckets()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut sender = member(&fixture, "PipeSend")?;
    assert_pipelined_delivery(&fixture, &mut sender, count)?;
    stop(&fixture, &mut daemon)
}

#[test]
fn five_pipelined_privmsgs_are_all_delivered_in_order() -> TestResult {
    guest_pipelines(5)
}

#[test]
fn nine_pipelined_privmsgs_are_all_delivered_in_order() -> TestResult {
    guest_pipelines(9)
}

/// Thirty-two exceeds every guest bucket the specification permits, so the
/// sender is an authenticated account under the account-message bucket.
#[test]
fn thirty_two_pipelined_privmsgs_are_all_delivered_in_order() -> TestResult {
    let fixture = fixture_with_wide_message_buckets()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let (mut sender, _) = exercise_account_client(&fixture)?;
    sender.send_until(&format!("JOIN {CHANNEL}"), " 366 ")?;
    assert_pipelined_delivery(&fixture, &mut sender, 32)?;
    stop(&fixture, &mut daemon)
}

/// The issue's exact case under the default buckets. The guest-message
/// bucket (spec 19.1: burst 4) admits four messages and refuses the other
/// five with the legacy `SERVER_BUSY` numeric. Those five one-line refusals
/// used to be counted as five open response batches and closed the sender as
/// a slow consumer with 196 bytes queued; now it stays connected and its
/// marker is answered.
#[test]
fn rate_limited_pipelined_refusals_never_close_the_sender() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut sender = member(&fixture, "PipeSend")?;
    let mut receiver = member(&fixture, "PipeRecv")?;
    read_until(&mut sender.reader, |line| line.contains(" JOIN "))?;
    let expected = bodies(9);
    write_pipelined(&mut sender, &privmsgs(&expected))?;
    let replies = read_leniently(&mut sender, |line| line.ends_with("PONG :pipelined"));
    let refused = replies.iter().filter(|line| line.contains(" 481 ")).count();
    assert_eq!(refused, 5, "sender saw {replies:?}");
    assert_contains(&replies, "PONG :pipelined")?;
    let received = read_leniently(&mut receiver, |line| line.ends_with("burst-03"));
    assert_eq!(
        delivered_bodies(&received),
        expected.get(..4).unwrap_or(&[])
    );
    sender.send_until("PING :alive", "PONG :alive")?;
    stop(&fixture, &mut daemon)
}

/// A client that pipelines several JOINs with its registration, as ordinary
/// clients do on connect, joins every channel.
#[test]
fn pipelined_joins_on_connect_all_succeed() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut client = ArcClient::connect(&fixture)?;
    let names: Vec<String> = (0..8).map(|index| format!("#onconnect{index}")).collect();
    let mut lines = vec![
        "NICK PipeJoin".to_owned(),
        "USER PipeJoin 0 * :Pipelined Join".to_owned(),
    ];
    lines.extend(names.iter().map(|name| format!("JOIN {name}")));
    write_pipelined(&mut client, &lines)?;
    let replies = read_leniently(&mut client, |line| line.ends_with("PONG :pipelined"));
    for name in &names {
        assert_contains(&replies, &format!(" 366 PipeJoin {name} "))?;
    }
    assert_contains(&replies, "PONG :pipelined")?;
    stop(&fixture, &mut daemon)
}
