//! Display-name preparation through the production daemon: every `SETNAME`
//! and `USER` realname is prepared or refused, and spaces are collapsed after
//! normalization (architecture 7.2 and Appendix A, RFC 8266 Sections 2.1 to
//! 2.3).
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_types::DisplayName;

const CONTEXT_TEXT: [&str; 3] = ["\u{00e9}", "\u{4e2d}\u{6587}", "\u{1f600}"];

/// Characters whose normal form contains a space, each with its prepared text
/// after that space.
fn space_producing(limit: usize) -> Vec<(char, String)> {
    (0x00a1_u32..0x3000)
        .filter_map(char::from_u32)
        .filter_map(|character| {
            let prepared = DisplayName::prepare(&format!("a{character}")).ok()?;
            let rest = prepared.as_str().strip_prefix("a ")?;
            (!rest.is_empty()).then(|| (character, rest.to_owned()))
        })
        .take(limit)
        .collect()
}

fn register(client: &mut ArcClient, nickname: &str, realname: &str) -> TestResult<Vec<String>> {
    client.send("CAP LS 302")?;
    client.send("CAP REQ :setname account-notify extended-join")?;
    client.send(&format!("NICK {nickname}"))?;
    client.send(&format!("USER {nickname} 0 * :{realname}"))?;
    client.send("CAP END")?;
    read_until(&mut client.reader, |line| {
        line.contains(" 376 ") || line.contains(" 422 ")
    })
}

fn require_running(daemon: &mut DaemonProcess) -> TestResult {
    let child = daemon
        .child
        .as_mut()
        .ok_or_else(|| failure("daemon was already joined"))?;
    match child.try_wait()? {
        None => Ok(()),
        Some(status) => Err(failure(format!("daemon exited: {status}"))),
    }
}

#[test]
fn display_names_are_prepared_or_refused_through_the_daemon() -> TestResult {
    let producing = space_producing(4);
    if producing.len() != 4 {
        return Err(failure("fewer than four space-producing characters"));
    }
    // Each name with the prepared form RFC 8266 gives it: the character's
    // text after one space, with the context text around it unchanged.
    let mut names = Vec::new();
    for (character, rest) in &producing {
        for prefix in CONTEXT_TEXT {
            names.push((format!("{prefix} {character}"), format!("{prefix} {rest}")));
            names.push((
                format!("{prefix}{prefix} {character} {prefix}"),
                format!("{prefix}{prefix} {rest} {prefix}"),
            ));
        }
    }
    let refused = "\u{4e2d}\u{00ad}";
    if DisplayName::prepare(refused).is_ok() {
        return Err(failure("the refused display name was prepared"));
    }

    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut observer = ArcClient::connect(&fixture)?;
    assert_contains(
        &register(&mut observer, "Observer", "Observer")?,
        " 001 Observer ",
    )?;
    let mut subject = ArcClient::connect(&fixture)?;
    assert_contains(
        &register(&mut subject, "Subject", "Subject")?,
        " 001 Subject ",
    )?;
    assert_contains(&observer.send_until("JOIN #names", " 366 ")?, " 366 ")?;
    assert_contains(&subject.send_until("JOIN #names", " 366 ")?, " 366 ")?;

    // The observer shares the channel and holds `setname`, so it is told of
    // each change the subject makes.
    for (name, expected) in &names {
        subject.send(&format!("SETNAME :{name}"))?;
        let notice = read_until(&mut observer.reader, |line| line.contains(" SETNAME "))?;
        assert_contains(&notice, ":Subject!")?;
        assert_contains(&notice, &format!(" SETNAME :{expected}"))?;
        require_running(&mut daemon)?;
    }
    // A refused name is answered with the grammar refusal the runtime renders
    // and changes nothing the observer can see.
    subject.send(&format!("SETNAME :{refused}"))?;
    read_until(&mut subject.reader, |line| {
        line.contains(" 421 Subject SETNAME ") || line.contains("FAIL SETNAME ")
    })?;
    let synced = observer.send_until("TIME", " 391 ")?;
    assert_contains(&synced, " 391 Observer ")?;
    if synced.iter().any(|line| line.contains(" SETNAME ")) {
        return Err(failure(format!("a refused name was announced: {synced:?}")));
    }

    for (index, (name, expected)) in names.iter().enumerate().take(CONTEXT_TEXT.len()) {
        let nickname = format!("Named{index}");
        let mut named = ArcClient::connect(&fixture)?;
        assert_contains(
            &register(&mut named, &nickname, name)?,
            &format!(" 001 {nickname} "),
        )?;
        // An extended JOIN carries the prepared realname to the observer.
        assert_contains(&named.send_until("JOIN #names", " 366 ")?, " 366 ")?;
        let joined = read_until(&mut observer.reader, |line| {
            line.contains(&format!(":{nickname}!")) && line.contains(" JOIN #names ")
        })?;
        assert_contains(&joined, &format!(" JOIN #names * :{expected}"))?;
        require_running(&mut daemon)?;
    }
    assert_contains(&subject.send_until("TIME", " 391 ")?, " 391 Subject ")?;

    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :display name preparation complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}
