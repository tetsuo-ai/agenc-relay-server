//! AUD-18 (SDK program B-12): every client-visible spelling of a user names
//! its public cloak as Architecture 7.4 frames it,
//! `<nickname>!u-<10 base32>@h-<16 base32>.invalid`, through a real daemon.
//! The checks parse the framing independently of the daemon's formatter.
#![forbid(unsafe_code)]

use super::*;

const CHANNEL: &str = "#cloak-spelling";

/// One user's visible cloak fields as the transcript first showed them.
struct Visible {
    user: String,
    host: String,
}

impl Visible {
    fn mask(&self, nickname: &str) -> String {
        format!("{nickname}!{}@{}", self.user, self.host)
    }

    /// The two random components without the framing; no line may carry
    /// them in the bare `user@host` spelling.
    fn bare(&self) -> TestResult<(&str, &str)> {
        let user = self
            .user
            .strip_prefix("u-")
            .ok_or_else(|| failure("unframed user field"))?;
        let host = self
            .host
            .strip_prefix("h-")
            .and_then(|host| host.strip_suffix(".invalid"))
            .ok_or_else(|| failure("unframed host field"))?;
        Ok((user, host))
    }
}

/// Whether `user` and `host` are a public cloak in the specified framing.
fn is_framed(user: &str, host: &str) -> bool {
    fn base32(text: &str, length: usize) -> bool {
        text.len() == length
            && text
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
    }
    user.strip_prefix("u-").is_some_and(|user| base32(user, 10))
        && host
            .strip_prefix("h-")
            .and_then(|host| host.strip_suffix(".invalid"))
            .is_some_and(|host| base32(host, 16))
}

/// Every `(nickname, user, host)` a line names: its source prefix, the
/// `userhost-in-names` tokens of 353, the entries of 302, and the separate
/// fields of 311, 314 and 352.
fn named_cloaks(line: &str) -> Vec<(String, String, String)> {
    let mut named = Vec::new();
    let fields: Vec<&str> = line.split(' ').collect();
    let mut mask = |token: &str| {
        let token = token.trim_start_matches(['~', '&', '@', '%', '+']);
        if let Some((nickname, address)) = token.split_once('!')
            && let Some((user, host)) = address.split_once('@')
        {
            named.push((nickname.to_owned(), user.to_owned(), host.to_owned()));
        }
    };
    if let Some(source) = fields.first().and_then(|source| source.strip_prefix(':')) {
        mask(source);
    }
    let trailing = line.split_once(" :").map_or("", |(_, trailing)| trailing);
    match fields.get(1).copied() {
        Some("353") => trailing.split(' ').for_each(&mut mask),
        Some("302") => {
            for entry in trailing.split(' ').filter(|entry| !entry.is_empty()) {
                if let Some((nickname, reply)) = entry.split_once('=')
                    && let Some((user, host)) = reply.get(1..).and_then(|rest| rest.split_once('@'))
                {
                    named.push((nickname.to_owned(), user.to_owned(), host.to_owned()));
                }
            }
        }
        Some("311" | "314") => {
            if let [_, _, _, nickname, user, host, ..] = fields.as_slice() {
                named.push((
                    (*nickname).to_owned(),
                    (*user).to_owned(),
                    (*host).to_owned(),
                ));
            }
        }
        Some("352") => {
            if let [_, _, _, _, user, host, _, nickname, ..] = fields.as_slice() {
                named.push((
                    (*nickname).to_owned(),
                    (*user).to_owned(),
                    (*host).to_owned(),
                ));
            }
        }
        _ => {}
    }
    named
}

/// The cloak a line's source prefix names for `nickname`.
fn source_cloak(lines: &[String], nickname: &str, command: &str) -> TestResult<Visible> {
    let needle = format!(" {command} {CHANNEL}");
    let line = lines
        .iter()
        .find(|line| line.starts_with(&format!(":{nickname}!")) && line.contains(&needle))
        .ok_or_else(|| failure(format!("{nickname} {command} missing: {lines:?}")))?;
    let (_, user, host) = named_cloaks(line)
        .into_iter()
        .next()
        .ok_or_else(|| failure(format!("{nickname} source missing: {line}")))?;
    if !is_framed(&user, &host) {
        return Err(failure(format!("{nickname} source is not framed: {line}")));
    }
    Ok(Visible { user, host })
}

/// A guest that negotiated the capabilities whose replies carry user masks.
fn guest(fixture: &LiveFixture, nickname: &str) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    client.send("CAP REQ :echo-message userhost-in-names")?;
    let registered = client.complete_registration(nickname)?;
    assert_contains(&registered, &format!(" 001 {nickname} "))?;
    Ok(client)
}

/// Two guests exchange JOIN, an echoed message, NAMES with
/// `userhost-in-names`, WHO, WHOIS, USERHOST, a rename with WHOWAS, and
/// MONITOR. Every mask and every user and host field in the whole
/// transcript is framed, one user is spelled identically everywhere, and the
/// bare components never appear.
#[test]
fn every_user_mask_in_a_two_guest_transcript_uses_the_framed_cloak() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let outcome = two_guest_transcript(&fixture);
    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :cloak spelling complete")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    outcome
}

// agenc-review: focus owner=tests reviewed=2026-10-01 reason=one linear two-client transcript keeps the order of the joins, the message and each query readable in place
fn two_guest_transcript(fixture: &LiveFixture) -> TestResult {
    let mut alice = guest(fixture, "CloakAlice")?;
    let mut bob = guest(fixture, "CloakBob")?;
    let mut alice_lines = alice.send_until(&format!("JOIN {CHANNEL}"), " 366 ")?;
    let mut bob_lines = bob.send_until(&format!("JOIN {CHANNEL}"), " 366 ")?;
    alice_lines.extend(read_until(&mut alice.reader, |line| {
        line.starts_with(":CloakBob!") && line.contains(" JOIN ")
    })?);
    let alice_cloak = source_cloak(&alice_lines, "CloakAlice", "JOIN")?;
    let bob_cloak = source_cloak(&bob_lines, "CloakBob", "JOIN")?;
    let alice_mask = alice_cloak.mask("CloakAlice");
    let bob_mask = bob_cloak.mask("CloakBob");

    // The message is echoed to its sender and delivered to the member.
    let message = format!("PRIVMSG {CHANNEL} :framed hello");
    alice_lines.extend(alice.send_until(&message, &message)?);
    bob_lines.extend(read_until(&mut bob.reader, |line| {
        line.ends_with(&message)
    })?);
    // NAMES and WHO spend bob's two expensive-query tokens; WHOIS and
    // WHOWAS spend alice's, so the default limits refuse none of them.
    bob_lines.extend(bob.send_until(&format!("NAMES {CHANNEL}"), " 366 ")?);
    bob_lines.extend(bob.send_until(&format!("WHO {CHANNEL}"), " 315 ")?);
    bob_lines.extend(bob.send_until("USERHOST CloakAlice CloakBob", " 302 ")?);
    bob_lines.extend(bob.send_until("MONITOR + CloakAlice,CloakNobody", " 731 ")?);
    alice_lines.extend(alice.send_until("WHOIS CloakBob", " 318 ")?);
    bob_lines.extend(bob.send_until("NICK CloakBob2", " NICK ")?);
    alice_lines.extend(read_until(&mut alice.reader, |line| {
        line.contains(" NICK :CloakBob2")
    })?);
    alice_lines.extend(alice.send_until("WHOWAS CloakBob 1", " 369 ")?);

    for (expected, lines) in [
        (format!(":{alice_mask} JOIN {CHANNEL}"), &alice_lines),
        (format!(":{bob_mask} JOIN {CHANNEL}"), &alice_lines),
        (format!(":{alice_mask} {message}"), &alice_lines),
        (format!(":{alice_mask} {message}"), &bob_lines),
        (format!(":{bob_mask} NICK :CloakBob2"), &alice_lines),
        (
            format!(
                " 302 CloakBob :CloakAlice=+{}@{} CloakBob=+{}@{}",
                alice_cloak.user, alice_cloak.host, bob_cloak.user, bob_cloak.host
            ),
            &bob_lines,
        ),
        (
            format!(
                " 311 CloakAlice CloakBob {} {} * :",
                bob_cloak.user, bob_cloak.host
            ),
            &alice_lines,
        ),
        (
            format!(
                " 314 CloakAlice CloakBob {} {} * :*",
                bob_cloak.user, bob_cloak.host
            ),
            &alice_lines,
        ),
        (
            format!(
                " 352 CloakBob {CHANNEL} {} {} ",
                alice_cloak.user, alice_cloak.host
            ),
            &bob_lines,
        ),
    ] {
        assert_contains(lines, &expected)?;
    }
    // Both of bob's NAMES replies, at JOIN and on request, list the two
    // userhost-in-names tokens; alice's at JOIN lists her own.
    for (lines, expected, count) in [
        (
            &bob_lines,
            vec![bob_mask.clone(), format!("~{alice_mask}")],
            2,
        ),
        (&alice_lines, vec![format!("~{alice_mask}")], 1),
    ] {
        let replies: Vec<Vec<String>> = lines
            .iter()
            .filter(|line| line.contains(" 353 "))
            .map(|line| {
                let mut tokens: Vec<String> = line
                    .split_once(" :")
                    .map_or("", |(_, tokens)| tokens)
                    .split(' ')
                    .map(str::to_owned)
                    .collect();
                tokens.sort_unstable();
                tokens
            })
            .collect();
        assert_eq!(replies, vec![expected; count]);
    }

    let mut named = 0_usize;
    for line in alice_lines.iter().chain(&bob_lines) {
        for (nickname, user, host) in named_cloaks(line) {
            if !is_framed(&user, &host) {
                return Err(failure(format!("unframed cloak in {line}")));
            }
            let expected = match nickname.as_str() {
                "CloakAlice" => &alice_cloak,
                "CloakBob" | "CloakBob2" => &bob_cloak,
                _ => return Err(failure(format!("unexpected user in {line}"))),
            };
            if (user.as_str(), host.as_str()) != (expected.user.as_str(), expected.host.as_str()) {
                return Err(failure(format!("{nickname} respelled in {line}")));
            }
            named += 1;
        }
        for cloak in [&alice_cloak, &bob_cloak] {
            let (user, host) = cloak.bare()?;
            if line.contains(&format!("!{user}@{host}"))
                || line.contains(&format!(" {user} {host} "))
            {
                return Err(failure(format!("bare cloak in {line}")));
            }
        }
    }
    // Alice reads 7: her JOIN and its one NAMES token, bob's JOIN, her echo,
    // bob's rename, 311 and 314. Bob reads 11: his JOIN and its two NAMES
    // tokens, alice's message, two NAMES tokens, two 352 rows, two 302
    // entries and his rename. MONITOR's 730 names nicknames only.
    assert_eq!(named, 18, "masks and field pairs checked");
    Ok(())
}
