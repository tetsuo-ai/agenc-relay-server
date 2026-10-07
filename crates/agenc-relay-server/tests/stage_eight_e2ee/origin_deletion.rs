//! Architecture 20.7 and companion 12.5 through production edges linked to
//! a production coordinator, with both profiles active: each origin
//! deletion, base and companion, names the generation the coordinator holds
//! and the edge's next unused sequence under it. Guests and clients
//! authenticated as one account register on edge A and end their
//! connections, which deletes their base and companion origins; the
//! coordinator accepts every deletion.
#![forbid(unsafe_code)]

use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// The PING whose PONG marks that the welcome burst was read.
const BARRIER: &str = "origin-deletion";
const WELCOMED_GUESTS: u32 = 24;
const WELCOMED_STEP: Duration = Duration::from_micros(250);
const ANSWERED_GUESTS: u32 = 48;
/// Each authenticated client spends one OPAQUE attempt of the account's
/// burst of five.
const LOGINS: u32 = 4;
const LOGIN_STEP: Duration = Duration::from_millis(2);
/// New direct connections are admitted at 16 a second after a burst of 64
/// from the shared loopback prefix; the guests stay under that rate.
const GUEST_PACE: Duration = Duration::from_millis(70);
const LOGIN: &str = "origin-deletion-account";

/// A guest registers on `fixture`, asks the edge for TIME when `time` is
/// set, and ends its connection.
fn guest_leaves(fixture: &NodeFixture, nickname: &str, time: bool, delay: Duration) -> TestResult {
    let started = Instant::now();
    let mut client = ArcClient::connect(fixture)?;
    client.send(&format!("NICK {nickname}"))?;
    client.send(&format!("USER {nickname} 0 * :Origin Deletion"))?;
    let _welcome = client.read_until(|line| line.contains(&format!(" 001 {nickname} ")))?;
    if time {
        client.send("TIME")?;
        let _answer = client.read_until(|line| line.contains(&format!(" 391 {nickname} ")))?;
    }
    thread::sleep(delay);
    drop(client);
    if let Some(rest) = GUEST_PACE.checked_sub(started.elapsed()) {
        thread::sleep(rest);
    }
    Ok(())
}

/// A client authenticates on `fixture` with SASL before registration,
/// registers, and ends its connection.
fn login_leaves(
    fixture: &NodeFixture,
    nickname: &str,
    account_id: AccountId,
    request_seed: u8,
    delay: Duration,
) -> TestResult {
    let mut client = ArcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    let _advertised =
        client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))?;
    let _acknowledged = client.send_until("CAP REQ :sasl", " CAP * ")?;
    authenticate_live_account(
        &mut client,
        fixture,
        LOGIN,
        ACCOUNT_PASSWORD,
        request_seed,
        account_id,
    )?;
    client.send(&format!("NICK {nickname}"))?;
    client.send(&format!("USER {nickname} 0 * :Origin Deletion"))?;
    client.send("CAP END")?;
    client.send(&format!("PING :{BARRIER}"))?;
    let _burst = client.read_until(|line| line.ends_with(&format!("PONG :{BARRIER}")))?;
    thread::sleep(delay);
    drop(client);
    Ok(())
}

fn step_delay(step: Duration, index: u32) -> TestResult<Duration> {
    step.checked_mul(index)
        .ok_or_else(|| failure("step delay overflow"))
}

#[test]
fn origin_deletions_name_the_generation_the_coordinator_holds() -> TestResult {
    encrypted_clients::run_network(|network, _coordinator, _edge_a, _edge_b| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        let established = links_established(&network.edge_a);
        let account_id = {
            let mut creation = ArcClient::connect(&network.edge_a)?;
            creation.negotiate_sasl()?;
            create_live_account(&mut creation, &network.edge_a, LOGIN, 91)?
        };
        for index in 0..WELCOMED_GUESTS {
            let delay = step_delay(WELCOMED_STEP, index)?;
            guest_leaves(&network.edge_a, &format!("welcomed{index}"), false, delay)?;
        }
        for index in 0..ANSWERED_GUESTS {
            guest_leaves(
                &network.edge_a,
                &format!("answered{index}"),
                true,
                Duration::ZERO,
            )?;
        }
        for index in 0..LOGINS {
            let delay = step_delay(LOGIN_STEP, index)?;
            let seed = u8::try_from(index)?
                .checked_mul(2)
                .and_then(|offset| offset.checked_add(93))
                .ok_or_else(|| failure("login request seed overflow"))?;
            login_leaves(
                &network.edge_a,
                &format!("member{index}"),
                account_id,
                seed,
                delay,
            )?;
        }
        let mut creation = ArcClient::connect(&network.edge_a)?;
        creation.negotiate_sasl()?;
        let _next =
            create_live_account(&mut creation, &network.edge_a, "origin-deletion-next", 121)?;
        let closed = network
            .coordinator
            .log_text()
            .matches("event=federation_link_closed")
            .count();
        if closed != 0 || links_established(&network.edge_a) != established {
            return Err(failure(
                "the coordinator did not accept every origin deletion of edge A",
            ));
        }
        Ok(())
    })
}
