//! Companion 11.8, 12.5 and 16 and Architecture 20.7 through the
//! production daemons of the Stage 08 network with both profiles active:
//! what one peer sends is refused for that request or origin alone, and
//! never fails the federation link. Account sessions ask, and guest
//! connections declare and delete, more companion objects than one
//! recent-object ceiling holds; and while edge A's link is cut, the
//! account's credential change removes a session the edge declares again, or
//! another connection supersedes a device attachment the edge declares again
//! to a restarted coordinator. Each declaration is refused for its origin
//! alone, and the link stays up. Edge A's link is also cut while the
//! acknowledgement of an event it applied is still in flight, and it resumes
//! (companion 12.5).
#![forbid(unsafe_code)]

use std::io::Read;

use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// Guest threads, each from its own loopback prefix so the per-prefix
/// connection and handshake buckets stay out of the way.
const GUEST_THREADS: u8 = 24;
/// Guests per thread; each connection declares its companion origin and
/// deletes it.
const GUESTS_PER_THREAD: u32 = 20;
/// Account sessions on edge A whose `EKEY WHOAMI` requests the coordinator
/// answers.
const READERS: u8 = 4;
/// Requests per session: with the guests' declarations, more companion
/// objects than one recent-object ceiling (`MAX_RECENT_OBJECTS`) holds.
const REQUESTS_PER_READER: u32 = 1_050;
const LOGIN: &str = "link-faults-account";
const ROOT: u8 = 87;
const DEVICE: u8 = 88;

/// Coordinator link closures and edge A link establishments so far.
pub(super) fn link_events(network: &Network) -> (usize, usize) {
    (
        network
            .coordinator
            .log_text()
            .matches("event=federation_link_closed")
            .count(),
        links_established(&network.edge_a),
    )
}

/// A guest registers on `fixture` from `source` and ends its connection.
fn guest(fixture: &NodeFixture, source: Ipv4Addr, nickname: &str) -> TestResult {
    let mut client = ArcClient::connect_from(fixture, Some(source))?;
    client.send(&format!("NICK {nickname}"))?;
    client.send(&format!("USER {nickname} 0 * :Link Faults"))?;
    let _welcome = client.read_until(|line| line.contains(&format!(" 001 {nickname} ")))?;
    drop(client);
    Ok(())
}

/// One account session asks `EKEY WHOAMI` `REQUESTS_PER_READER` times, each
/// answered as its account; a request the edge holds back while its reply
/// budget is full is asked again.
fn reader(mut client: ArcClient, index: u8) -> TestResult {
    let mut answered = 0;
    let mut attempt = 0_u32;
    while answered < REQUESTS_PER_READER {
        attempt += 1;
        let reply = whoami(&mut client, &format!("r{index}n{attempt}"))?;
        if reply.iter().any(|line| line.contains(" EKEY ACCOUNT ")) {
            answered += 1;
        } else if reply
            .iter()
            .any(|line| line.contains(" E2EE_RATE_LIMITED "))
        {
            thread::sleep(Duration::from_millis(5));
        } else {
            return Err(failure(format!(
                "reader {index}: request {answered} was not answered: {reply:?}"
            )));
        }
    }
    Ok(())
}

/// Guests from `worker`'s loopback prefix register on `fixture` one after
/// another and end their connections.
fn guests(fixture: &NodeFixture, worker: u8) -> TestResult {
    let source = Ipv4Addr::new(127, 0, 100 + worker, 1);
    for index in 0..GUESTS_PER_THREAD {
        step(
            &format!("guest {worker}/{index}"),
            guest(fixture, source, &format!("g{worker}x{index}")),
        )?;
    }
    Ok(())
}

#[test]
fn companion_requests_and_guest_origins_past_one_recent_object_ceiling_keep_the_link() -> TestResult
{
    encrypted_clients::run_network(|network, _coordinator, _edge_a, _edge_b| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        // The first guest waits until edge A's link is synchronized.
        drop(register_when_available(&network.edge_a, "firstguest")?);
        let fixture = &network.edge_a;
        let account = {
            let mut creation = ArcClient::connect(fixture)?;
            creation.negotiate_sasl()?;
            create_live_account(&mut creation, fixture, LOGIN, 61)?
        };
        let mut readers = Vec::new();
        // Each authentication spends two account request seeds.
        for index in 0..READERS {
            let mut client = step(
                "reader session",
                authenticated_session(
                    fixture,
                    &format!("reader{index}"),
                    LOGIN,
                    63 + 2 * index,
                    account,
                ),
            )?;
            account_ready(&mut client, &format!("ready{index}x"))?;
            readers.push((client, index));
        }
        let before = link_events(network);
        thread::scope(|scope| -> TestResult {
            let mut workers: Vec<_> = (0..GUEST_THREADS)
                .map(|worker| scope.spawn(move || guests(fixture, worker)))
                .collect();
            workers.extend(
                readers
                    .into_iter()
                    .map(|(client, index)| scope.spawn(move || reader(client, index))),
            );
            for worker in workers {
                worker.join().map_err(|_| failure("a worker panicked"))??;
            }
            Ok(())
        })?;
        // A last guest proves the link still carries the edge's origins.
        guest(fixture, Ipv4Addr::new(127, 0, 99, 1), "lastguest")?;
        if link_events(network) != before {
            return Err(failure(
                "edge A's coordinator link failed while its requests and guests came and went",
            ));
        }
        Ok(())
    })
}

/// Attaches `keys`' device on `client`, whose identity and roster are
/// already published.
fn attach(client: &mut ArcClient, keys: &mut Principal) -> TestResult {
    let label = keys.label();
    client.send(&format!(
        "@label={label} EKEY ATTACH BEGIN {}",
        keys.device_token()
    ))?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EKEY ATTACH-CHALLENGE ")?;
    let bytes = batch_object(&reply)?;
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let object = ArcWireObject::decode_kind(
        &bytes,
        Some(ArcWireObjectKind::DeviceAttachChallenge),
        &mut budget,
    )?;
    let challenge = ArcDeviceAttachChallenge::decode_exact(object.body(), &mut budget)?;
    let device_signature = builders::sign(
        &builders::key(keys.device),
        agenc_relay_crypto::SignatureDomain::DeviceAttachPossession,
        &challenge.tbs,
    )?;
    let attach = wire_object(
        ArcWireObjectKind::DeviceAttach,
        &ArcDeviceAttach {
            challenge,
            device_signature,
        },
    )?;
    let label = keys.label();
    send_object(
        client,
        &label,
        &format!("EKEY ATTACH FINISH {}", keys.device_token()),
        &attach,
    )?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EKEY ATTACHED ")?;
    Ok(())
}

/// One labeled `EKEY WHOAMI` and its reply.
fn whoami(client: &mut ArcClient, label: &str) -> TestResult<Vec<String>> {
    client.send(&format!("@label={label} EKEY WHOAMI"))?;
    labeled_reply(client, label)
}

/// Waits until the edge serves `client`'s encrypted commands as its
/// account: the base and companion declarations of its login are
/// acknowledged.
fn account_ready(client: &mut ArcClient, prefix: &str) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    for attempt in 0_u32.. {
        let reply = whoami(client, &format!("{prefix}{attempt}"))?;
        if reply.iter().any(|line| line.contains(" EKEY ACCOUNT ")) {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(failure(format!(
                "{prefix}: the account never became ready: {reply:?}"
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(failure("unreachable"))
}

/// A TCP relay edge A dials in place of the coordinator's federation
/// listener, which the test cuts and heals.
pub(super) struct Relay {
    address: SocketAddr,
    /// Bytes forwarded so far, both directions together.
    traffic: Arc<std::sync::atomic::AtomicU64>,
    /// Milliseconds the relay holds what edge A sends before forwarding it.
    delay: Arc<AtomicU64>,
    /// Milliseconds the relay holds what the coordinator sends edge A.
    inbound_delay: Arc<AtomicU64>,
    open: Arc<std::sync::atomic::AtomicBool>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    streams: Arc<std::sync::Mutex<Vec<TcpStream>>>,
    acceptor: Option<thread::JoinHandle<()>>,
}

impl Relay {
    fn start(target: SocketAddr) -> TestResult<Self> {
        use std::sync::atomic::{AtomicBool, AtomicU64};
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let open = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let traffic = Arc::new(AtomicU64::new(0));
        let delay = Arc::new(AtomicU64::new(0));
        let inbound_delay = Arc::new(AtomicU64::new(0));
        let streams = Arc::new(std::sync::Mutex::new(Vec::new()));
        let acceptor = {
            let (open, stop, streams) = (open.clone(), stop.clone(), streams.clone());
            let (traffic, delay) = (traffic.clone(), delay.clone());
            let inbound_delay = inbound_delay.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let Ok((inbound, _)) = listener.accept() else {
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    };
                    if !open.load(Ordering::SeqCst) {
                        drop(inbound);
                        continue;
                    }
                    let Ok(outbound) = TcpStream::connect(target) else {
                        continue;
                    };
                    let pipes = (|| -> io::Result<()> {
                        inbound.set_nonblocking(false)?;
                        let (from, to) = (inbound.try_clone()?, outbound.try_clone()?);
                        let (sent, held) = (traffic.clone(), delay.clone());
                        thread::spawn(move || forward_held(from, to, sent, held));
                        let (from, to) = (outbound.try_clone()?, inbound.try_clone()?);
                        let (sent, held) = (traffic.clone(), inbound_delay.clone());
                        thread::spawn(move || forward_held(from, to, sent, held));
                        if let Ok(mut live) = streams.lock() {
                            live.push(inbound.try_clone()?);
                            live.push(outbound.try_clone()?);
                        }
                        Ok(())
                    })();
                    drop(pipes);
                }
            })
        };
        Ok(Self {
            address,
            traffic,
            delay,
            inbound_delay,
            open,
            stop,
            streams,
            acceptor: Some(acceptor),
        })
    }

    /// Closes the relayed link and refuses new ones until healed.
    pub(super) fn cut(&self) {
        self.open.store(false, Ordering::SeqCst);
        if let Ok(mut live) = self.streams.lock() {
            for stream in live.drain(..) {
                let _closed = stream.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    pub(super) fn heal(&self) {
        self.open.store(true, Ordering::SeqCst);
    }

    fn traffic(&self) -> u64 {
        self.traffic.load(Ordering::SeqCst)
    }

    /// Holds what edge A sends for `delay` before forwarding it, so a cut
    /// drops what is still held.
    pub(super) fn hold_outbound(&self, delay: Duration) {
        self.delay.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    /// Holds what the coordinator sends edge A for `delay` before
    /// forwarding it, so a cut drops what is still held.
    pub(super) fn hold_inbound(&self, delay: Duration) {
        self.inbound_delay.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }
}

/// Chunks the relay's holding stage keeps at most; the reader waits beyond.
const HELD_CHUNKS: usize = 256;

/// Copies `from` to `to`, counting every forwarded byte, holding each chunk
/// for the relay's delay in that direction first; when `from` ends, what is
/// still held is written only while `to` stays open, so a cut drops it, and
/// `to` is closed.
fn forward_held(
    mut from: TcpStream,
    mut to: TcpStream,
    traffic: Arc<std::sync::atomic::AtomicU64>,
    delay: Arc<AtomicU64>,
) {
    let (held, release) = std::sync::mpsc::sync_channel::<(Instant, Vec<u8>)>(HELD_CHUNKS);
    let writer = thread::spawn(move || {
        for (due, bytes) in release {
            thread::sleep(due.saturating_duration_since(Instant::now()));
            if to.write_all(&bytes).is_err() {
                break;
            }
            traffic.fetch_add(
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
        }
        let _closed = to.shutdown(std::net::Shutdown::Both);
    });
    let mut buffer = [0_u8; 16 * 1024];
    while let Ok(read) = from.read(&mut buffer) {
        let Some(bytes) = buffer.get(..read).filter(|bytes| !bytes.is_empty()) else {
            break;
        };
        let due = Instant::now() + Duration::from_millis(delay.load(Ordering::SeqCst));
        if held.send((due, bytes.to_vec())).is_err() {
            break;
        }
    }
    drop(held);
    let _joined = writer.join();
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.cut();
        if let Some(acceptor) = self.acceptor.take() {
            let _joined = acceptor.join();
        }
    }
}

/// The Stage 08 network whose edge A dials the coordinator through `Relay`.
pub(super) fn relayed_network() -> TestResult<(Network, Relay)> {
    let coordinator = NodeIdentity::new(20, NodeRole::Coordinator, "core.test")?;
    let edge_a = NodeIdentity::new(40, NodeRole::Edge, "edge-a.test")?;
    let edge_b = NodeIdentity::new(60, NodeRole::Edge, "edge-b.test")?;
    let federation_address = reserve_loopback_address()?;
    let relay = Relay::start(federation_address)?;
    let capacity = Some(CapacityPlan {
        max_connections: 32,
        connections_per_address: 32,
        memory_budget_bytes: STAGE_EIGHT_MEMORY_BUDGET_BYTES,
    });
    let network = Network {
        coordinator: NodeFixture::create(&NodePlan {
            identity: &coordinator,
            coordinator: &coordinator,
            federation_address: Some(federation_address),
            peers: &[&edge_a, &edge_b],
            capacity,
        })?,
        edge_a: NodeFixture::create(&NodePlan {
            identity: &edge_a,
            coordinator: &coordinator,
            federation_address: Some(relay.address),
            peers: &[&coordinator],
            capacity,
        })?,
        edge_b: NodeFixture::create(&NodePlan {
            identity: &edge_b,
            coordinator: &coordinator,
            federation_address: Some(federation_address),
            peers: &[&coordinator],
            capacity,
        })?,
    };
    Ok((network, relay))
}

/// Runs `scenario` over the relayed network and stops every daemon.
fn run_relayed(
    scenario: impl FnOnce(&Network, &Relay, &mut DaemonProcess) -> TestResult,
) -> TestResult {
    let (network, relay) = relayed_network()?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let outcome = scenario(&network, &relay, &mut coordinator);
    let stopped = [edge_a.stop(), edge_b.stop(), coordinator.stop()];
    drop(relay);
    if let Err(error) = outcome {
        return Err(failure(format!(
            "{error}\n--- coordinator log ---\n{}\n--- edge a log ---\n{}\n--- edge b log ---\n{}",
            network.coordinator.log_text(),
            network.edge_a.log_text(),
            network.edge_b.log_text()
        )));
    }
    for status in stopped {
        if !status?.success() {
            return Err(failure("a daemon exited with a failure"));
        }
    }
    Ok(())
}

/// Waits until the coordinator has logged `count` link closures.
pub(super) fn wait_for_closures(network: &Network, count: usize) -> TestResult {
    let deadline = Instant::now() + NETWORK_WAIT;
    while link_events(network).0 < count {
        if Instant::now() >= deadline {
            return Err(failure("the coordinator never saw the cut link close"));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// How long edge A's relayed link must carry nothing before it is cut.
const QUIET: Duration = Duration::from_millis(500);

/// The coordinator's unacknowledged base deliveries, over every peer.
fn unacknowledged_deliveries(network: &Network) -> TestResult<u64> {
    let identity = super::stage_ten_capacity::admin_identity(&network.coordinator);
    super::stage_ten_capacity::admin_client::AdminSession::connect(&identity)?
        .stats("FEDERATION")?
        .into_iter()
        .find(|(name, _)| name == "base_outbox_objects")
        .map(|(_, value)| value)
        .ok_or_else(|| failure("the federation outbox counter is missing"))
}

/// Waits, within the network wait, until the coordinator holds no
/// unacknowledged base delivery and edge A's relayed link has carried
/// nothing for `QUIET`, so the refusal tests cut a link that carries nothing
/// the test does not control and replay only what they arranged. A resume
/// needs no such wait (companion 12.5): the in-flight test cuts without
/// it.
fn settled(network: &Network, relay: &Relay) -> TestResult {
    let deadline = Instant::now() + NETWORK_WAIT;
    let mut seen = relay.traffic();
    let mut quiet_since = Instant::now();
    loop {
        thread::sleep(Duration::from_millis(50));
        let traffic = relay.traffic();
        if traffic != seen {
            seen = traffic;
            quiet_since = Instant::now();
        } else if quiet_since.elapsed() >= QUIET && unacknowledged_deliveries(network)? == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(failure("edge A's link never settled before the cut"));
        }
    }
}

/// Cuts edge A's link once it has settled and waits until the coordinator
/// saw it close.
fn cut(network: &Network, relay: &Relay) -> TestResult {
    settled(network, relay)?;
    let (closures, _) = link_events(network);
    relay.cut();
    wait_for_closures(network, closures + 1)
}

/// Heals edge A's link, waits until edge A links again, lets it replay its
/// origins, and requires that the link then stays up: one establishment and
/// no further closure.
fn heal_and_hold(
    network: &Network,
    relay: &Relay,
    settle: impl FnOnce() -> TestResult,
) -> TestResult {
    let (closures, established) = link_events(network);
    relay.heal();
    wait_for_link(&network.edge_a, established)?;
    thread::sleep(Duration::from_secs(3));
    settle()?;
    thread::sleep(Duration::from_secs(2));
    if link_events(network) != (closures, established + 1) {
        return Err(failure(format!(
            "edge A's link failed after it replayed its origins: {:?} -> {:?}",
            (closures, established + 1),
            link_events(network)
        )));
    }
    Ok(())
}

#[test]
fn a_declaration_naming_a_fenced_session_is_refused_for_its_origin() -> TestResult {
    run_relayed(|network, relay, _coordinator| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_link(&network.edge_b, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        wait_for_account_authority(&network.edge_b)?;
        let account = {
            let mut creation = ArcClient::connect(&network.edge_b)?;
            creation.negotiate_sasl()?;
            create_live_account(&mut creation, &network.edge_b, LOGIN, 41)?
        };
        let mut session_a = step(
            "edge A session",
            authenticated_session(&network.edge_a, "sessiona", LOGIN, 43, account),
        )?;
        step("cut", cut(network, relay))?;
        // While edge A's link is cut, the account's credential change on
        // edge B fences every session of the account, edge A's too.
        let mut changer = ArcClient::connect(&network.edge_b)?;
        changer.negotiate_sasl()?;
        step(
            "changer authentication",
            authenticate_live_account(
                &mut changer,
                &network.edge_b,
                LOGIN,
                ACCOUNT_PASSWORD,
                45,
                account,
            ),
        )?;
        changer.complete_registration("changer")?;
        step(
            "changer reauthentication",
            authenticate_live_account(
                &mut changer,
                &network.edge_b,
                LOGIN,
                ACCOUNT_PASSWORD,
                47,
                account,
            ),
        )?;
        step(
            "credential change",
            super::credential_replacement::replace(&mut changer, &network.edge_b, account),
        )?;
        // Edge A declares its session again on the next link; the
        // coordinator refuses that origin alone, and the session's removal
        // ends its connection.
        heal_and_hold(network, relay, || {
            // The fence reaches edge A with the replayed events and ends the
            // session's connection.
            let mut line = String::new();
            while session_a
                .reader
                .read_line(&mut line)
                .is_ok_and(|read| read != 0)
            {
                line.clear();
            }
            guest(&network.edge_a, Ipv4Addr::new(127, 0, 98, 1), "afterfence")
        })
    })
}

#[test]
fn a_superseded_attachment_declared_to_a_restarted_coordinator_holds_no_device_authority()
-> TestResult {
    run_relayed(|network, relay, coordinator| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_link(&network.edge_b, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        wait_for_account_authority(&network.edge_b)?;
        let (mut session_a, account) = step(
            "edge A session",
            authenticated_client(&network.edge_a, "sessiona", LOGIN, 51),
        )?;
        let mut keys = Principal::new(ROOT, DEVICE, account)?;
        account_ready(&mut session_a, "ready")?;
        step(
            "edge A attach",
            publish_and_attach(&mut session_a, &mut keys),
        )?;
        // Edge A's link is cut, and the coordinator restarts without the
        // companion origins it held in memory.
        step("cut", cut(network, relay))?;
        let links_b = links_established(&network.edge_b);
        if !coordinator.stop()?.success() {
            return Err(failure("the coordinator did not stop cleanly"));
        }
        *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
        wait_for_link(&network.edge_b, links_b)?;
        wait_for_account_authority(&network.edge_b)?;
        // The same device attaches on edge B, which supersedes edge A's
        // attachment.
        let mut session_b = step(
            "edge B session",
            authenticated_session(&network.edge_b, "sessionb", LOGIN, 55, account),
        )?;
        account_ready(&mut session_b, "ready")?;
        step("edge B attach", attach(&mut session_b, &mut keys))?;
        // Edge A's next link declares its session's attachment again; the
        // coordinator mirrors it as it stands, an attachment edge B's
        // superseded: the session is served, and its device-requiring
        // commands are refused with E2EE_DEVICE_REQUIRED.
        heal_and_hold(network, relay, || {
            let answered = step("edge A whoami", whoami(&mut session_a, "a1"))?;
            assert_contains(&answered, " EKEY ACCOUNT ")?;
            session_a.send("@label=a2 EKEY FETCH MAILBOX BINDING *")?;
            let refused = step("edge A mailbox", labeled_reply(&mut session_a, "a2"))?;
            assert_contains(&refused, "E2EE_DEVICE_REQUIRED")?;
            let answered = step("edge B whoami", whoami(&mut session_b, "b1"))?;
            assert_contains(&answered, " EKEY ACCOUNT ")?;
            drop(session_a);
            thread::sleep(Duration::from_secs(1));
            guest(
                &network.edge_a,
                Ipv4Addr::new(127, 0, 97, 1),
                "aftersupersede",
            )
        })
    })
}

/// Cuts of edge A's link in the in-flight test.
const IN_FLIGHT_CUTS: u64 = 4;
/// How long the relay holds what edge A sends in the in-flight test: long
/// enough that each cut drops the acknowledgement edge A wrote just before.
const IN_FLIGHT_HOLD: Duration = Duration::from_millis(300);

/// Publishes the device's capability statement at `generation`, chained to
/// `previous`, and returns its identifier. The coordinator delivers the
/// request's completion event to edge A, which answers the client only
/// after it applied that event and wrote its `EACK`.
fn publish_capabilities(
    client: &mut ArcClient,
    keys: &mut Principal,
    generation: u64,
    previous: [u8; 32],
) -> TestResult<[u8; 32]> {
    let capabilities = builders::capabilities(
        keys.device,
        &keys.keys.roster,
        generation,
        previous,
        (200, 3_600),
        vec![1],
    )?;
    let identifier = semantic_id_of(SemanticHashDomain::CapabilityId, &capabilities.tbs)?;
    let object = wire_object(ArcWireObjectKind::DeviceCapabilities, &capabilities)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let label = keys.label();
        send_object(
            client,
            &label,
            &format!("EKEY PUBLISH CAPABILITIES {}", keys.device_token()),
            &object,
        )?;
        let reply = labeled_reply(client, &label)?;
        if reply
            .iter()
            .any(|line| line.contains(" EKEY STORED CAPABILITIES "))
        {
            return Ok(identifier);
        }
        // Until the coordinator acknowledges the declaration that names the
        // attached device, edge A answers E2EE_SYNCING.
        if Instant::now() > deadline || !reply.iter().any(|line| line.contains("E2EE_SYNCING")) {
            return Err(failure(format!(
                "the capability statement was not stored: {reply:?}"
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_link_cut_while_acknowledgements_are_in_flight_resumes() -> TestResult {
    run_relayed(|network, relay, _coordinator| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_link(&network.edge_b, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        let (mut session, account) = step(
            "edge A session",
            authenticated_client(&network.edge_a, "inflight", LOGIN, 61),
        )?;
        let mut keys = Principal::new(ROOT, DEVICE, account)?;
        account_ready(&mut session, "ready")?;
        step("edge A attach", publish_and_attach(&mut session, &mut keys))?;
        let before = link_events(network);
        relay.hold_outbound(IN_FLIGHT_HOLD);
        let mut previous = [0; 32];
        for round in 0..IN_FLIGHT_CUTS {
            let (closures, established) = link_events(network);
            previous = step(
                "capabilities",
                publish_capabilities(&mut session, &mut keys, round, previous),
            )?;
            // No wait: the acknowledgement of the event behind that reply is
            // still in flight when the link is cut.
            relay.cut();
            wait_for_closures(network, closures + 1)?;
            relay.heal();
            wait_for_link(&network.edge_a, established)?;
            // The link resumes: the session is served again over it, and the
            // link neither closes nor links again meanwhile.
            step(
                "resumed",
                account_ready(&mut session, &format!("round{round}-")),
            )?;
            if link_events(network) != (closures + 1, established + 1) {
                return Err(failure(format!(
                    "edge A's link did not resume after cut {round}: {:?} -> {:?}",
                    (closures + 1, established + 1),
                    link_events(network)
                )));
            }
        }
        thread::sleep(Duration::from_secs(2));
        let cuts = usize::try_from(IN_FLIGHT_CUTS)?;
        let expected = (before.0 + cuts, before.1 + cuts);
        if link_events(network) != expected {
            return Err(failure(format!(
                "edge A's link failed after its last resume: {expected:?} -> {:?}",
                link_events(network)
            )));
        }
        Ok(())
    })
}
