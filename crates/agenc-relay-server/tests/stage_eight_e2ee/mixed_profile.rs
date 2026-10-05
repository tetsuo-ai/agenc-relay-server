//! Companion Section 12.5 and the coordinated profile upgrade through the
//! production daemons: an edge that still runs the previous companion profile
//! (release candidate 3) links to a coordinator of this revision. The base
//! hello completes and the coordinator offers this revision's profile; the
//! old edge's OFFER, which names the previous profile hash, is answered with
//! `ERROR :ARC-MLS profile mismatch` and the link closes. The coordinator's
//! clients and its current edge chat before and after.
//!
//! The old edge is the runtime's own dial owner under edge A's identity,
//! driven in this process; its companion layer offers the previous profile's
//! tuple. The runtime's link test checks the answer's exact bytes; here the
//! old edge's link closes on that answer, a line no base grammar admits,
//! rather than on the end of the transport.
#![forbid(unsafe_code)]

use agenc_relay_config::PeerEndpoint;
use agenc_relay_runtime::cancel::CancellationToken;
use agenc_relay_runtime::e2ee::link::{CompanionLinks, CompanionProfile};
use agenc_relay_runtime::federation::owner::{
    DialOwnerPlan, FederationControl, LinkOwnerShared, run_dial_owner,
};
use agenc_relay_runtime::federation::{
    FederationInbound, LinkCloseReason, LinkEvent, LocalIdentity, PeerIdentity,
};
use agenc_relay_runtime::tls::{CertChain, PrivateKey, build_federation_client_config};
use agenc_relay_testkit::e2ee::federation::frames::CompanionFrame;
use agenc_relay_testkit::e2ee::profile::EcapTuple;
use agenc_relay_types::FederationRole;
use tokio::sync::mpsc;

use super::*;

/// The E2EE profile token of release candidate 3, before the ReInit target
/// revision (PC-001) moved the profile hash.
const RC3_PROFILE_TOKEN: &str = "wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U";

/// The channel both base-chat clients join.
const CHANNEL: &str = "#mixed";

/// The log event of any closed link, and of one that closed on a failure.
const LINK_CLOSED: &str = "event=federation_link_closed";
const LINK_FAILED: &str = "event=federation_link_closed severity=warning";

/// The old edge: edge A's identity, dialing the coordinator's federation
/// listener with the previous profile.
struct OldEdge<'a> {
    coordinator: &'a NodeIdentity,
    edge: &'a NodeIdentity,
    address: SocketAddr,
}

/// What the old edge saw on its first link.
struct Refusal {
    /// The coordinator's OFFER tuple.
    offer: EcapTuple,
    /// Why the link closed.
    reason: LinkCloseReason,
}

#[test]
fn an_edge_of_the_previous_profile_is_refused_while_base_chat_continues() -> TestResult {
    let coordinator = NodeIdentity::new(20, NodeRole::Coordinator, "core.test")?;
    let old_edge = NodeIdentity::new(40, NodeRole::Edge, "edge-a.test")?;
    let edge = NodeIdentity::new(60, NodeRole::Edge, "edge-b.test")?;
    let address = reserve_loopback_address()?;
    let core = NodeFixture::create(&NodePlan {
        identity: &coordinator,
        coordinator: &coordinator,
        federation_address: Some(address),
        peers: &[&old_edge, &edge],
        capacity: None,
    })?;
    let current = NodeFixture::create(&NodePlan {
        identity: &edge,
        coordinator: &coordinator,
        federation_address: Some(address),
        peers: &[&coordinator],
        capacity: None,
    })?;
    let mut core_process = DaemonProcess::start(&core.config_path)?;
    let mut edge_process = DaemonProcess::start(&current.config_path)?;
    let old = OldEdge {
        coordinator: &coordinator,
        edge: &old_edge,
        address,
    };
    let outcome = mixed_profiles(&core, &current, &old);
    let stopped_edge = edge_process.stop();
    let stopped_core = core_process.stop();
    if let Err(error) = outcome {
        return Err(failure(format!(
            "{error}\n--- coordinator log ---\n{}\n--- edge b log ---\n{}",
            core.log_text(),
            current.log_text()
        )));
    }
    for (label, status) in [("edge b", stopped_edge), ("coordinator", stopped_core)] {
        let status = status.map_err(|error| failure(format!("{label}: {error}")))?;
        if !status.success() {
            return Err(failure(format!("{label} exited with {status}")));
        }
    }
    Ok(())
}

fn mixed_profiles(core: &NodeFixture, current: &NodeFixture, old: &OldEdge<'_>) -> TestResult {
    wait_for_link(current, 0)?;
    let mut carol = joined(core, "carol")?;
    let mut dave = joined(current, "dave")?;
    carol.read_until(|line| line.starts_with(":dave!") && line.contains(" JOIN "))?;
    chat(&mut carol, &mut dave, "before the old edge")?;
    chat(&mut dave, &mut carol, "before the old edge")?;

    // Edge B's link is up; its log may hold a dial that ran before the
    // coordinator listened.
    let edge_links = (links_established(current), logged(current, LINK_CLOSED));
    let failed = logged(core, LINK_FAILED);
    let refusal = refused(old)?;
    // The coordinator offered this revision's profile: exactly the tuple
    // this build sends for the same network, coordinator and key set.
    let offer = &refusal.offer;
    assert_eq!(
        *offer,
        EcapTuple::local(
            &offer.network_id,
            &offer.coordinator_server_id,
            offer.key_set_generation,
            &offer.key_set_hash,
        )?
    );
    assert_ne!(offer.profile_hash, RC3_PROFILE_TOKEN);
    // The old edge's link closed on the coordinator's answer, which no base
    // grammar admits, rather than on the end of the transport.
    assert_eq!(refusal.reason, LinkCloseReason::Framing);
    wait_for_failed_link(core, failed)?;

    // The coordinator's clients and its current edge never noticed.
    chat(&mut dave, &mut carol, "after the old edge")?;
    chat(&mut carol, &mut dave, "after the old edge")?;
    assert_eq!(
        (links_established(current), logged(current, LINK_CLOSED)),
        edge_links
    );
    Ok(())
}

/// Registers `nickname` on `fixture` and joins the channel.
fn joined(fixture: &NodeFixture, nickname: &str) -> TestResult<ArcClient> {
    let mut client = register_when_available(fixture, nickname)?;
    client.send(&format!("JOIN {CHANNEL}"))?;
    client.read_until(|line| line.contains(&format!(" 366 {nickname} {CHANNEL} ")))?;
    Ok(client)
}

/// `from` says `text` in the channel and `to` reads it.
fn chat(from: &mut ArcClient, to: &mut ArcClient, text: &str) -> TestResult {
    from.send(&format!("PRIVMSG {CHANNEL} :{text}"))?;
    let lines = to.read_until(|line| line.contains(&format!(" PRIVMSG {CHANNEL} ")))?;
    assert_contains(&lines, &format!(" PRIVMSG {CHANNEL} :{text}"))
}

/// How many times `fixture` logged `event`.
fn logged(fixture: &NodeFixture, event: &str) -> usize {
    fixture.log_text().matches(event).count()
}

/// Waits until `fixture` logs one more failed link than `before`.
fn wait_for_failed_link(fixture: &NodeFixture, before: usize) -> TestResult {
    let deadline = Instant::now() + NETWORK_WAIT;
    while logged(fixture, LINK_FAILED) <= before {
        if Instant::now() >= deadline {
            return Err(failure("the coordinator never logged the failed link"));
        }
        thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// Runs the old edge until its first link closes.
fn refused(old: &OldEdge<'_>) -> TestResult<Refusal> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(old_edge(old))
}

/// The runtime's dial owner as edge A, the coordinator its only peer.
async fn old_edge(old: &OldEdge<'_>) -> TestResult<Refusal> {
    let coordinator = old.coordinator;
    let pin = *coordinator.federation_tls.leaf_spki_sha256();
    let peer = PeerIdentity::new(
        coordinator.server_id,
        coordinator.name,
        FederationRole::Coordinator,
        coordinator.recovery_epoch,
        coordinator.signing.public_key(),
        pin,
    );
    let tls = build_federation_client_config(
        TrustStore::parse(coordinator.federation_tls.ca_certificate_der())?,
        (
            CertChain::parse(old.edge.federation_tls.leaf_certificate_der())?,
            PrivateKey::parse(old.edge.federation_tls.leaf_private_key_pkcs8_der())?,
        ),
        pin,
        coordinator.server_id,
    )?;
    let local = LocalIdentity::new(
        NETWORK_ID,
        old.edge.server_id,
        old.edge.name,
        old.edge.incarnation,
        old.edge.recovery_epoch,
        FederationRole::Edge,
        Arc::new(Ed25519SecretKey::from_bytes(old.edge.signing_seed)),
    )?;
    let (inbound, events) = mpsc::channel(64);
    let shared = Arc::new(LinkOwnerShared::new(
        local,
        vec![peer.clone()],
        inbound,
        None,
        1 << 20,
    ));
    let plan = DialOwnerPlan {
        peer,
        endpoints: vec![PeerEndpoint::Tcp(old.address)],
        tls,
        connect_timeout: IO_TIMEOUT,
        reconnect_max: NETWORK_WAIT,
        tor_proxy: None,
    };
    let control = FederationControl::new(FederationRole::Edge, [coordinator.server_id]);
    let token = CancellationToken::root();
    let owner = tokio::spawn(Box::pin(run_dial_owner(
        plan,
        shared,
        control,
        token.clone(),
    )));
    let outcome = tokio::time::timeout(NETWORK_WAIT, first_link(events, old.edge.name)).await;
    token.cancel();
    owner.await??;
    outcome?
}

/// Follows the old edge's first link. On the coordinator's OFFER it sends
/// the OFFER an edge of release candidate 3 sends: the coordinator's tuple
/// with the previous profile hash. Returns when the link closes.
async fn first_link(
    mut events: mpsc::Receiver<FederationInbound>,
    name: &str,
) -> TestResult<Refusal> {
    let mut link = None;
    let mut offer = None;
    while let Some(inbound) = events.recv().await {
        match inbound.event {
            LinkEvent::Established { session, handle } => link = Some((session.link, handle)),
            LinkEvent::Companion(CompanionFrame::EcapOffer(tuple)) => {
                let (id, handle) = link
                    .as_ref()
                    .ok_or_else(|| failure("an OFFER arrived before the link"))?;
                let previous = EcapTuple {
                    profile_hash: RC3_PROFILE_TOKEN.to_owned(),
                    ..tuple.clone()
                };
                let mut companion = CompanionLinks::new(
                    Some(CompanionProfile { local: previous }),
                    name.to_owned(),
                );
                let line = companion
                    .link_established(*id, 0)?
                    .ok_or_else(|| failure("the previous profile rendered no OFFER"))?;
                handle.try_send(line)?;
                offer = Some(tuple);
            }
            LinkEvent::Closed(reason) => {
                let offer = offer.ok_or_else(|| {
                    failure(format!(
                        "the link closed ({reason}) before the coordinator's OFFER"
                    ))
                })?;
                return Ok(Refusal { offer, reason });
            }
            _ => {}
        }
    }
    Err(failure(
        "the old edge's dial owner stopped before its link closed",
    ))
}
