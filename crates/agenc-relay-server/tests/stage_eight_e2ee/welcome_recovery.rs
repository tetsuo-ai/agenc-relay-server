//! Architecture 10.2 steps 5 and 6 through a production edge daemon: a
//! client that negotiated `agenc.ag/recovery` and authenticated with SASL
//! before registration receives `NOTE * RECOVERY_EPOCH` with the epoch the
//! edge's `CAP LS` pinned, right after the MOTD group; the same registration
//! without the capability receives no NOTE. Either burst ends with the
//! authenticated account state, a `900` whose mask is the session's own
//! prefix, which the edge reads from the session projection its coordinator
//! installed.
#![forbid(unsafe_code)]

use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// The PING whose PONG marks the end of the welcome burst.
const BARRIER: &str = "welcome-end";

/// One authenticated registration: the advertised capability lines, every
/// line from `RPL_WELCOME` up to the barrier PONG, which is excluded, the
/// session's own prefix as the echo of its first JOIN shows it, and the
/// registered connection, which stays open until the scenario ends.
struct Welcomed {
    advertised: Vec<String>,
    burst: Vec<String>,
    prefix: String,
    _client: ArcClient,
}

/// The command or numeric of one server line.
fn command(line: &str) -> &str {
    line.split(' ').nth(1).unwrap_or_default()
}

/// Creates the account `login` on `fixture`; then, on a fresh connection,
/// negotiates `request`, authenticates to that account with SASL before
/// registration and registers `nickname`. Input that arrives behind the
/// registration commit runs after the welcome, so the PONG of a PING sent
/// last proves that nothing of the burst is still in flight. The connection
/// is returned open, so no registered client leaves before the scenario
/// ends.
fn authenticated_welcome(
    fixture: &NodeFixture,
    nickname: &str,
    login: &str,
    request_seed: u8,
    request: &str,
) -> TestResult<Welcomed> {
    let account_id = {
        let mut creation = ArcClient::connect(fixture)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, fixture, login, request_seed)?
    };
    let mut client = ArcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    let advertised =
        client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))?;
    let acknowledged = client.send_until(&format!("CAP REQ :{request}"), " CAP * ")?;
    assert_contains(&acknowledged, &format!(" CAP * ACK :{request}"))?;
    let auth_seed = request_seed
        .checked_add(2)
        .ok_or_else(|| failure("authentication request seed overflow"))?;
    authenticate_live_account(
        &mut client,
        fixture,
        login,
        ACCOUNT_PASSWORD,
        auth_seed,
        account_id,
    )?;
    client.send(&format!("NICK {nickname}"))?;
    client.send(&format!("USER {nickname} 0 * :Welcome Burst"))?;
    client.send("CAP END")?;
    client.send(&format!("PING :{BARRIER}"))?;
    let mut lines = client.read_until(|line| line.ends_with(&format!("PONG :{BARRIER}")))?;
    lines.pop();
    let first = lines
        .iter()
        .position(|line| command(line) == "001")
        .ok_or_else(|| failure(format!("no welcome in {lines:?}")))?;
    let joined = client.send_until(&format!("JOIN #{nickname}"), " JOIN ")?;
    let prefix = joined
        .last()
        .and_then(|line| line.split(' ').next())
        .and_then(|prefix| prefix.strip_prefix(':'))
        .ok_or_else(|| failure(format!("no JOIN echo in {joined:?}")))?
        .to_owned();
    Ok(Welcomed {
        advertised,
        burst: lines.split_off(first),
        prefix,
        _client: client,
    })
}

#[test]
fn an_edge_sends_the_recovery_note_after_preregistration_sasl() -> TestResult {
    super::encrypted_clients::run_network(recovery_note_on_an_edge)
}

fn recovery_note_on_an_edge(
    network: &Network,
    _coordinator: &mut DaemonProcess,
    _edge_a: &mut DaemonProcess,
    _edge_b: &mut DaemonProcess,
) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_account_authority(&network.edge_a)?;
    let recovery = authenticated_welcome(
        &network.edge_a,
        "keeper",
        "keeper-account",
        61,
        "sasl agenc.ag/recovery",
    )?;
    let quiet = authenticated_welcome(&network.edge_a, "quiet", "quiet-account", 71, "sasl")?;

    // The epoch this connection's CAP LS pinned.
    let epoch = recovery
        .advertised
        .iter()
        .flat_map(|line| line.split([' ', ':']))
        .find_map(|token| token.strip_prefix("agenc.ag/recovery=v1."))
        .ok_or_else(|| failure(format!("no recovery epoch in {:?}", recovery.advertised)))?;
    assert_eq!(epoch.len(), 22, "{:?}", recovery.advertised);

    let server = recovery
        .burst
        .first()
        .and_then(|line| line.split(' ').next())
        .ok_or_else(|| failure("the welcome has no prefix"))?;

    // Without the capability the burst ends with the MOTD group and the
    // account state: the session's own prefix, and `*` for an account
    // without a public label.
    assert!(
        quiet.burst.iter().all(|line| command(line) != "NOTE"),
        "no NOTE without agenc.ag/recovery: {:?}",
        quiet.burst
    );
    let quiet_codes: Vec<&str> = quiet.burst.iter().map(|line| command(line)).collect();
    assert!(
        matches!(
            quiet_codes.get(quiet_codes.len().saturating_sub(2)..),
            Some(["376" | "422", "900"])
        ),
        "{:?}",
        quiet.burst
    );
    assert_eq!(
        quiet.burst.last(),
        Some(&format!(
            "{server} 900 quiet {} * :You are now logged in",
            quiet.prefix
        )),
        "{:?}",
        quiet.burst
    );

    // With it, the same burst gains exactly the NOTE, right after the MOTD
    // group and before the account state, repeating the advertised epoch
    // byte for byte.
    let mut expected = quiet_codes;
    expected.insert(expected.len().saturating_sub(1), "NOTE");
    let codes: Vec<&str> = recovery.burst.iter().map(|line| command(line)).collect();
    assert_eq!(codes, expected, "{:?}", recovery.burst);
    assert_eq!(
        recovery.burst.get(recovery.burst.len().saturating_sub(2)..),
        Some(
            &[
                format!("{server} NOTE * RECOVERY_EPOCH {epoch} :Current server recovery identity"),
                format!(
                    "{server} 900 keeper {} * :You are now logged in",
                    recovery.prefix
                ),
            ][..]
        ),
        "{:?}",
        recovery.burst
    );
    Ok(())
}
