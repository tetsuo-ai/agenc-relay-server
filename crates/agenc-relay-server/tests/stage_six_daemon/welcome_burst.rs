//! Architecture 10.2 step 5 through the production binary: a guest that
//! negotiated `agenc.ag/recovery` receives `NOTE * RECOVERY_EPOCH` with the
//! epoch its `CAP LS` pinned, right after the MOTD group and as the last line
//! of the burst; a guest that did not negotiate it receives no NOTE.
#![forbid(unsafe_code)]

use super::*;

/// The recovery epoch every live fixture initializes its database with.
const FIXTURE_RECOVERY_EPOCH: [u8; 16] = [6; 16];
/// The PING whose PONG marks the end of the welcome burst.
const BARRIER: &str = "welcome-end";

/// One guest registration: the advertised capability lines and every line
/// from `RPL_WELCOME` up to the barrier PONG, which is excluded.
struct Welcomed {
    advertised: Vec<String>,
    burst: Vec<String>,
}

/// The command or numeric of one server line.
fn command(line: &str) -> &str {
    line.split(' ').nth(1).unwrap_or_default()
}

/// Registers `nickname` on a fresh connection after negotiating `request`
/// (`None` never starts CAP). Input that arrives behind the registration
/// commit runs after the welcome, so the PONG of a PING sent last proves that
/// nothing of the burst is still in flight.
fn welcomed(fixture: &LiveFixture, nickname: &str, request: Option<&str>) -> TestResult<Welcomed> {
    let mut client = ArcClient::connect(fixture)?;
    let mut advertised = Vec::new();
    if let Some(request) = request {
        client.send("CAP LS 302")?;
        advertised = read_until(&mut client.reader, |line| {
            line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :")
        })?;
        let acknowledged = client.send_until(&format!("CAP REQ :{request}"), " CAP * ")?;
        assert_contains(&acknowledged, &format!(" CAP * ACK :{request}"))?;
    }
    client.send(&format!("NICK {nickname}"))?;
    client.send(&format!("USER {nickname} 0 * :Welcome Burst"))?;
    if request.is_some() {
        client.send("CAP END")?;
    }
    client.send(&format!("PING :{BARRIER}"))?;
    let mut lines = read_until(&mut client.reader, |line| {
        line.ends_with(&format!("PONG :{BARRIER}"))
    })?;
    lines.pop();
    let first = lines
        .iter()
        .position(|line| command(line) == "001")
        .ok_or_else(|| failure(format!("no welcome in {lines:?}")))?;
    Ok(Welcomed {
        advertised,
        burst: lines.split_off(first),
    })
}

#[test]
fn production_daemon_sends_the_recovery_note_only_to_a_recovery_client() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let epoch = RecoveryEpoch::from_bytes(FIXTURE_RECOVERY_EPOCH).to_base64url();

    let recovery = welcomed(&fixture, "keeper", Some("agenc.ag/recovery"))?;
    assert_contains(
        &recovery.advertised,
        &format!("agenc.ag/recovery=v1.{epoch}"),
    )?;
    let codes: Vec<&str> = recovery.burst.iter().map(|line| command(line)).collect();
    assert_eq!(
        codes,
        [
            "001", "002", "003", "004", "005", "005", "005", "251", "422", "NOTE"
        ],
        "{:?}",
        recovery.burst
    );
    let server = recovery
        .burst
        .first()
        .and_then(|line| line.split(' ').next())
        .ok_or_else(|| failure("the welcome has no prefix"))?;
    assert_eq!(
        recovery.burst.last().map(String::as_str),
        Some(
            format!("{server} NOTE * RECOVERY_EPOCH {epoch} :Current server recovery identity")
                .as_str()
        )
    );

    // standard-replies neither replaces nor gates the recovery capability.
    let both = welcomed(&fixture, "both", Some("agenc.ag/recovery standard-replies"))?;
    assert_eq!(both.burst.last(), recovery.burst.last());
    for (nickname, request) in [("replies", Some("standard-replies")), ("plain", None)] {
        let quiet = welcomed(&fixture, nickname, request)?;
        assert!(
            quiet.burst.iter().all(|line| command(line) != "NOTE"),
            "no NOTE without agenc.ag/recovery: {:?}",
            quiet.burst
        );
        assert_eq!(
            quiet.burst.last().map(|line| command(line)),
            Some("422"),
            "{:?}",
            quiet.burst
        );
    }

    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :welcome burst complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}
