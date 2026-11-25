//! Companion 11.4 through the production daemons: while two accounts hold
//! a live encrypted direct binding, after its authorized close and before
//! the next incarnation binds, and after it binds, a plaintext `PRIVMSG` or
//! `NOTICE` between them is refused with `E2EE_REQUIRED` and reaches no
//! session of the other account, whatever nickname spelling or target list
//! carries it and whichever nodes hold the two sessions: one edge, two
//! edges, or the coordinator's own listener. An unrelated account's
//! plaintext still flows. The coordinator decides every line (companion
//! 12.5); an edge refuses earlier what its own projection shows.
#![forbid(unsafe_code)]

use super::recreated_routes::{Party, bind_direct, close_direct, exchange, pair_held};
use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// The group of the pair's incarnation one.
const NEXT_GROUP: [u8; 32] = [79; 32];

/// The plain channel every session joins, whose messages fence the
/// deliveries a refused line would have made: the coordinator orders a
/// sender's lines, and each node delivers in that order.
const FENCE: &str = "#fence";

fn join_fence(client: &mut ArcClient, nickname: &str) -> TestResult {
    client.send(&format!("JOIN {FENCE}"))?;
    client.read_until(|line| line.contains(&format!(" 366 {nickname} {FENCE} ")))?;
    Ok(())
}

/// One session a line is sent from or must not reach.
struct Session<'a> {
    client: &'a mut ArcClient,
    nickname: &'a str,
}

/// `line` from `sender`, which names `context` as its targets, is refused
/// with `E2EE_REQUIRED`, and none of `targets` receives it before the fence
/// `sender` sends after it.
fn refused(
    sender: Session<'_>,
    targets: &mut [Session<'_>],
    (line, command, context): (&str, &str, &str),
    tag: &str,
) -> TestResult {
    let text = format!("refused-{tag}");
    sender.client.send(&format!("{line} :{text}"))?;
    let reply = sender
        .client
        .read_until(|reply| reply.contains("E2EE_REQUIRED"))?;
    assert_contains(
        &reply,
        &format!("FAIL {command} E2EE_REQUIRED {context} :plaintext is forbidden for the target"),
    )?;
    let fence = format!("fence-{tag}");
    sender.client.send(&format!("PRIVMSG {FENCE} :{fence}"))?;
    sender.client.read_until(|reply| reply.contains(&fence))?;
    for target in targets.iter_mut() {
        let seen = target.client.read_until(|reply| reply.contains(&fence))?;
        assert!(
            seen.iter().all(|reply| !reply.contains(&text)),
            "{} received the refused line: {seen:?}",
            target.nickname
        );
    }
    Ok(())
}

/// Plaintext from `sender` to `target`'s nickname reaches it.
fn delivered(sender: Session<'_>, target: Session<'_>, tag: &str) -> TestResult {
    let text = format!("delivered-{tag}");
    sender
        .client
        .send(&format!("PRIVMSG {} :{text}", target.nickname))?;
    let seen = target.client.read_until(|reply| reply.contains(&text))?;
    assert_contains(&seen, &format!(" PRIVMSG {} :{text}", target.nickname))
}

/// Every form of plaintext between `creator` and `peer` is refused both
/// ways, through each one's sessions, and carol's still flows.
fn pair_refuses_plaintext(
    creator: &mut Party,
    peer: &mut Party,
    carol: &mut ArcClient,
    phase: &str,
) -> TestResult {
    let (creator_nick, peer_nick) = (creator.nickname, peer.nickname);
    let shouted = peer_nick.to_ascii_uppercase();
    let listed = format!("carol,{peer_nick}");
    let lines = [
        (
            format!("PRIVMSG {peer_nick}"),
            "PRIVMSG",
            peer_nick.to_owned(),
        ),
        (
            format!("NOTICE {peer_nick}"),
            "NOTICE",
            peer_nick.to_owned(),
        ),
        (format!("PRIVMSG {shouted}"), "PRIVMSG", shouted.clone()),
        (format!("PRIVMSG {listed}"), "PRIVMSG", listed.clone()),
    ];
    for (index, (line, command, context)) in lines.iter().enumerate() {
        refused(
            Session {
                client: &mut creator.client,
                nickname: creator_nick,
            },
            &mut [
                Session {
                    client: &mut peer.client,
                    nickname: peer_nick,
                },
                Session {
                    client: carol,
                    nickname: "carol",
                },
            ],
            (line, command, context),
            &format!("{phase}-forward-{index}"),
        )?;
    }
    refused(
        Session {
            client: &mut peer.client,
            nickname: peer_nick,
        },
        &mut [Session {
            client: &mut creator.client,
            nickname: creator_nick,
        }],
        (&format!("PRIVMSG {creator_nick}"), "PRIVMSG", creator_nick),
        &format!("{phase}-back"),
    )?;
    delivered(
        Session {
            client: &mut creator.client,
            nickname: creator_nick,
        },
        Session {
            client: carol,
            nickname: "carol",
        },
        &format!("{phase}-unrelated"),
    )
}

/// Registers carol, an account in no encrypted pair and with no device, on
/// `fixture`: her account is created on the coordinator's own listener, as
/// the requester copies test creates a second account of an edge's.
fn carol_on(network: &Network, fixture: &NodeFixture) -> TestResult<(ArcClient, AccountId)> {
    let account = {
        let mut creation = ArcClient::connect(&network.coordinator)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, &network.edge_a, "carol-account", 61)?
    };
    let carol = authenticated_session(fixture, "carol", "carol-account", 63, account)?;
    Ok((carol, account))
}

/// A session of `account` on the coordinator's own listener, which offers
/// no encrypted profile: its plaintext is the coordinator's to refuse.
fn coordinator_session(
    network: &Network,
    nickname: &str,
    login: &str,
    request_seed: u8,
    account: AccountId,
) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(&network.coordinator)?;
    client.send("CAP LS 302")?;
    client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))?;
    client.send_until("CAP REQ :sasl echo-message standard-replies", " CAP * ACK ")?;
    authenticate_live_account(
        &mut client,
        &network.edge_a,
        login,
        ACCOUNT_PASSWORD,
        request_seed,
        account,
    )?;
    let registered = client.complete_registration(nickname)?;
    assert_contains(&registered, &format!(" 001 {nickname} "))?;
    Ok(client)
}

/// alice and bob, bound as the smaller account's creator and its peer.
fn pair(alice: Party, bob: Party) -> (Party, Party) {
    if alice.keys.account <= bob.keys.account {
        (alice, bob)
    } else {
        (bob, alice)
    }
}

/// Binds incarnation zero, then closes it, then binds incarnation one,
/// running `check` while each is live and in the window after the close.
fn live_closed_recreated(
    creator: &mut Party,
    peer: &mut Party,
    mut check: impl FnMut(&mut Party, &mut Party, &str) -> TestResult,
) -> TestResult {
    let first = step(
        "first bind",
        bind_direct(creator, peer, (0, [0; 32]), None, DIRECT_GROUP),
    )?;
    let first_terminal = step(
        "first activation",
        activate_bootstrap_with(
            &mut creator.client,
            &mut creator.keys,
            &first,
            &[&peer.keys],
        ),
    )?;
    step(
        "first traffic",
        exchange(creator, peer, &first, first_terminal, 1),
    )?;
    step("live", check(creator, peer, "live"))?;
    let close_id = step(
        "close",
        close_direct(creator, peer, &first, (1, first_terminal)),
    )?;
    step("closed", check(creator, peer, "closed"))?;
    let second = step(
        "next bind",
        bind_direct(creator, peer, (1, close_id), Some(&first), NEXT_GROUP),
    )?;
    let second_terminal = step(
        "next activation",
        activate_bootstrap_with(
            &mut creator.client,
            &mut creator.keys,
            &second,
            &[&peer.keys],
        ),
    )?;
    step(
        "next traffic",
        exchange(creator, peer, &second, second_terminal, 1),
    )?;
    step("recreated", check(creator, peer, "recreated"))?;
    step("next reservation", pair_held(creator, peer, &second, None)).map(drop)
}

#[test]
fn an_encrypted_pair_on_one_edge_refuses_plaintext_live_closed_and_recreated() -> TestResult {
    super::encrypted_clients::run_network(|network, _coordinator, _edge_a, _edge_b| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_link(&network.edge_b, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        let (alice, alice_account) = step(
            "alice session",
            authenticated_client(&network.edge_a, "alice", "alice-account", 41),
        )?;
        let (bob, bob_account) = step(
            "bob session",
            authenticated_client(&network.edge_a, "bob", "bob-account", 51),
        )?;
        let mut alice = Party {
            client: alice,
            keys: Principal::new(ALICE_ROOT, ALICE_DEVICE, alice_account)?,
            nickname: "alice",
            login: "alice-account",
            account: alice_account,
            rejoin_seed: 47,
        };
        let mut bob = Party {
            client: bob,
            keys: Principal::new(BOB_ROOT, BOB_DEVICE, bob_account)?,
            nickname: "bob",
            login: "bob-account",
            account: bob_account,
            rejoin_seed: 57,
        };
        step(
            "alice attach",
            publish_and_attach(&mut alice.client, &mut alice.keys),
        )?;
        step(
            "bob attach",
            publish_and_attach(&mut bob.client, &mut bob.keys),
        )?;
        let (mut carol, _) = step("carol", carol_on(network, &network.edge_a))?;
        for (client, nickname) in [
            (&mut alice.client, "alice"),
            (&mut bob.client, "bob"),
            (&mut carol, "carol"),
        ] {
            step("fence", join_fence(client, nickname))?;
        }
        let (mut creator, mut peer) = pair(alice, bob);
        live_closed_recreated(&mut creator, &mut peer, |creator, peer, phase| {
            pair_refuses_plaintext(creator, peer, &mut carol, phase)
        })
    })
}

#[test]
fn an_encrypted_pair_across_edges_and_the_coordinator_refuses_plaintext_live_closed_and_recreated()
-> TestResult {
    super::encrypted_clients::run_network(|network, _coordinator, _edge_a, _edge_b| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_link(&network.edge_b, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        wait_for_account_authority(&network.edge_b)?;
        let (alice, alice_account) = step(
            "alice session",
            authenticated_client(&network.edge_a, "alice", "alice-account", 41),
        )?;
        let (bob, bob_account) = step(
            "bob session",
            authenticated_client(&network.edge_b, "bob", "bob-account", 51),
        )?;
        let mut alice = Party {
            client: alice,
            keys: Principal::new(ALICE_ROOT, ALICE_DEVICE, alice_account)?,
            nickname: "alice",
            login: "alice-account",
            account: alice_account,
            rejoin_seed: 47,
        };
        let mut bob = Party {
            client: bob,
            keys: Principal::new(BOB_ROOT, BOB_DEVICE, bob_account)?,
            nickname: "bob",
            login: "bob-account",
            account: bob_account,
            rejoin_seed: 57,
        };
        step(
            "alice attach",
            publish_and_attach(&mut alice.client, &mut alice.keys),
        )?;
        step(
            "bob attach",
            publish_and_attach(&mut bob.client, &mut bob.keys),
        )?;
        // alice's second session, on the coordinator's own listener.
        let mut home = step(
            "alice at the coordinator",
            coordinator_session(network, "alicehome", "alice-account", 45, alice_account),
        )?;
        let (mut carol, _) = step("carol", carol_on(network, &network.edge_b))?;
        for (client, nickname) in [
            (&mut alice.client, "alice"),
            (&mut bob.client, "bob"),
            (&mut home, "alicehome"),
            (&mut carol, "carol"),
        ] {
            step("fence", join_fence(client, nickname))?;
        }
        let (mut creator, mut peer) = pair(alice, bob);
        live_closed_recreated(&mut creator, &mut peer, |creator, peer, phase| {
            pair_refuses_plaintext(creator, peer, &mut carol, phase)?;
            // The session on the coordinator's own listener meets the same
            // refusal both ways: the coordinator decides it.
            let (alice, bob) = if creator.nickname == "alice" {
                (creator, peer)
            } else {
                (peer, creator)
            };
            refused(
                Session {
                    client: &mut home,
                    nickname: "alicehome",
                },
                &mut [Session {
                    client: &mut bob.client,
                    nickname: "bob",
                }],
                ("PRIVMSG bob", "PRIVMSG", "bob"),
                &format!("{phase}-home"),
            )?;
            refused(
                Session {
                    client: &mut bob.client,
                    nickname: "bob",
                },
                &mut [
                    Session {
                        client: &mut home,
                        nickname: "alicehome",
                    },
                    Session {
                        client: &mut alice.client,
                        nickname: "alice",
                    },
                ],
                ("NOTICE alicehome", "NOTICE", "alicehome"),
                &format!("{phase}-to-home"),
            )
        })
    })
}
