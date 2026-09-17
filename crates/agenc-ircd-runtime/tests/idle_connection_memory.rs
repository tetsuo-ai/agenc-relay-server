#![forbid(unsafe_code)]

//! RUN-04: resident memory of idle client connections (spec 19.2, 28.7).
//!
//! The public listener, TLS endpoint, connection supervisor, reader, writer,
//! and writer queue serve real TLS clients that a child copy of this test
//! binary holds open, so the client side never shares this process's heap.
//! A stub StateCore acknowledges each open and retains its sink, as the real
//! one does. Once every setup increment is released, each idle connection
//! must hold exactly the client base charge, and this process's anonymous
//! resident memory, which includes allocator overhead, must grow by no more
//! than that charge per connection. The repository forbids `unsafe`, so a
//! counting global allocator is not available; `/proc/self/status` is
//! readable by the process itself on every supported Linux target.

use std::error::Error;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agenc_ircd_config::ListenerName;
use agenc_ircd_runtime::budget::{CLIENT_CONNECTION_BASE_BYTES, MemoryBudget, startup_arithmetic};
use agenc_ircd_runtime::cancel::CancellationToken;
use agenc_ircd_runtime::connection::{ClientSink, ConnectionLimits};
use agenc_ircd_runtime::listener::{
    BoundAddress, ConnectionObserver, ListenerContext, ListenerSet, ListenerSource, ListenerSpec,
    PermissiveAdmission,
};
use agenc_ircd_runtime::purpose::ListenerPurpose;
use agenc_ircd_runtime::state_core::inbox::{
    ConnectionOpenOutcome, StateCoreMessage, connection_close_channel,
};
use agenc_ircd_runtime::tls::{
    CLIENT_ALPN, CertChain, ClientAuth, HandshakeLimiter, PrivateKey, TlsEndpointProfile,
    TrustStore, build_client_config, build_server_config_blocking,
};
use agenc_ircd_testkit::TlsFixture;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use tokio::sync::{Semaphore, mpsc};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const DNS_NAME: &str = "node.test";
const FIXTURE_SEED: u8 = 41;
const DRIVER_ADDRESS_ENV: &str = "AGENC_IDLE_DRIVER_ADDRESS";
const READY: &str = "AGENC-IDLE-READY";
const WARM_CONNECTIONS: usize = 32;
const MEASURED_CONNECTIONS: usize = 256;
const LISTENER_CEILING: usize = WARM_CONNECTIONS + MEASURED_CONNECTIONS;
/// Appendix C.2 defaults: the four-GiB budget, four crypto workers, and the
/// 32-KiB parsed arena.
const DEFAULT_BUDGET_BYTES: u64 = 4_294_967_296;
const DEFAULT_CRYPTO_WORKERS: u64 = 4;
const DEFAULT_PARSED_ARENA_BYTES: u64 = 32_768;
/// CAP-01: the population the production idle occupancy measurement opens,
/// and the environment variable that lowers it for a development pilot.
const POPULATION_ENV: &str = "AGENC_IDLE_POPULATION";
/// Section 19.2 default simultaneous client connections of one node.
const DEFAULT_CLIENT_CONNECTIONS: usize = 50_000;
/// Listener sockets the production measurement binds. One loopback
/// destination port can hold only `net.ipv4.ip_local_port_range` connections
/// from one source address, which is fewer than the production population on
/// a default host, so the generator spreads over several ports.
const PRODUCTION_LISTENERS: usize = 8;
/// Handshakes in progress the production measurement admits; the generator is
/// sequential, so this only has to clear one.
const PRODUCTION_HANDSHAKES: usize = 256;
/// How long the production measurement waits for every TLS setup increment to
/// return, per thousand admitted connections.
const SETTLE_PER_THOUSAND: Duration = Duration::from_secs(2);

struct Observer;

impl ConnectionObserver for Observer {}

fn resident_anonymous_bytes() -> TestResult<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let kibibytes = status
        .lines()
        .find_map(|line| line.strip_prefix("RssAnon:"))
        .and_then(|rest| rest.split_ascii_whitespace().next())
        .ok_or("RssAnon is missing from /proc/self/status")?
        .parse::<u64>()?;
    Ok(kibibytes * 1_024)
}

/// The client half: run only as a child with the driver environment. It
/// opens connections on request and holds every handshaken stream idle.
#[test]
fn idle_connection_driver() -> TestResult {
    let Some(address) = std::env::var_os(DRIVER_ADDRESS_ENV) else {
        return Ok(());
    };
    let addresses = parse_addresses(address.to_str().ok_or("driver address")?)?;
    let fixture = TlsFixture::mint([FIXTURE_SEED; 32], DNS_NAME)?;
    let config = build_client_config(
        TrustStore::parse(fixture.ca_certificate_der())?,
        Some(CLIENT_ALPN),
        None,
    )?;
    let mut held = Vec::new();
    let mut stdout = std::io::stdout();
    for request in std::io::stdin().lines() {
        let count: usize = request?.trim().parse()?;
        for _ in 0..count {
            let name = ServerName::try_from(DNS_NAME.to_owned())?;
            let connection = ClientConnection::new(Arc::clone(&config), name)?;
            let address = addresses
                .get(held.len() % addresses.len())
                .ok_or("driver has no listener address")?;
            let socket = TcpStream::connect(address)?;
            socket.set_read_timeout(Some(Duration::from_secs(30)))?;
            let mut stream = StreamOwned::new(connection, socket);
            while stream.conn.is_handshaking() {
                stream.conn.complete_io(&mut stream.sock)?;
            }
            held.push(stream);
        }
        writeln!(stdout, "{READY} {}", held.len())?;
        stdout.flush()?;
    }
    Ok(())
}

/// Parses the comma-separated listener addresses the driver connects to.
fn parse_addresses(text: &str) -> TestResult<Vec<SocketAddr>> {
    let mut addresses = Vec::new();
    for part in text.split(',') {
        addresses.push(part.parse::<SocketAddr>()?);
    }
    if addresses.is_empty() {
        return Err("driver received no listener address".into());
    }
    Ok(addresses)
}

/// Renders listener addresses for the driver's environment.
fn render_addresses(addresses: &[SocketAddr]) -> String {
    addresses
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

struct Driver {
    child: Child,
    requests: std::process::ChildStdin,
    replies: BufReader<std::process::ChildStdout>,
}

impl Driver {
    fn spawn(addresses: &[SocketAddr]) -> TestResult<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "idle_connection_driver",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(DRIVER_ADDRESS_ENV, render_addresses(addresses))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let requests = child.stdin.take().ok_or("driver stdin")?;
        let replies = BufReader::new(child.stdout.take().ok_or("driver stdout")?);
        Ok(Self {
            child,
            requests,
            replies,
        })
    }

    /// Asks the driver for `count` more idle connections and waits for them.
    fn open(&mut self, count: usize, total: usize) -> TestResult {
        writeln!(self.requests, "{count}")?;
        self.requests.flush()?;
        let expected = format!("{READY} {total}");
        let mut line = String::new();
        loop {
            line.clear();
            if self.replies.read_line(&mut line)? == 0 {
                return Err("driver exited before its connections were ready".into());
            }
            // libtest writes `test <name> ... ` without a newline before the
            // driver's first line, so match the line's end.
            if line.trim_end().ends_with(&expected) {
                return Ok(());
            }
        }
    }

    fn finish(self) -> TestResult {
        let Self {
            mut child,
            requests,
            mut replies,
        } = self;
        // Closing the request pipe ends the driver; its libtest summary must
        // still find a reader, so drain the reply pipe before joining.
        drop(requests);
        let mut rest = String::new();
        while replies.read_line(&mut rest)? != 0 {
            rest.clear();
        }
        let status = child.wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("driver failed: {status}").into())
        }
    }
}

/// Waits until the budget holds exactly `expected` bytes: TLS setup
/// increments return once each handshake's allocations are destroyed.
async fn settle(budget: &MemoryBudget, expected: u64) -> TestResult<u64> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let charged = budget.charged();
        if charged == expected || Instant::now() >= deadline {
            tokio::time::sleep(Duration::from_millis(500)).await;
            return Ok(budget.charged());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_tls_connections_hold_the_base_charge_and_no_more_resident_memory() -> TestResult {
    let pool = startup_arithmetic(
        DEFAULT_BUDGET_BYTES,
        DEFAULT_CRYPTO_WORKERS,
        &[ListenerPurpose::ClientTls],
        DEFAULT_PARSED_ARENA_BYTES,
    )?;
    let budget = Arc::new(MemoryBudget::new(pool.protocol_pool_bytes()));
    let fixture = TlsFixture::mint([FIXTURE_SEED; 32], DNS_NAME)?;
    let tls = build_server_config_blocking(
        TlsEndpointProfile::Client,
        CertChain::parse(fixture.leaf_certificate_der())?,
        PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
        ClientAuth::None,
    )?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let spec = ListenerSpec {
        name: ListenerName::parse("idle")?,
        purpose: ListenerPurpose::ClientTls,
        source: ListenerSource::InheritedTcp(listener),
        max_connections: LISTENER_CEILING,
        tls: Some(tls),
        local_admin: None,
    };
    let (inbox, mut receiver) = mpsc::channel(64);
    let (connection_closes, close_inbox) = connection_close_channel();
    let root = CancellationToken::root();
    let context = ListenerContext {
        budget: Arc::clone(&budget),
        handshakes: HandshakeLimiter::new(64)?,
        client_slots: Arc::new(Semaphore::new(LISTENER_CEILING)),
        admission: Arc::new(PermissiveAdmission),
        observer: Arc::new(Observer),
        inbox,
        connection_closes,
        admin: None,
        limits: ConnectionLimits::DEFAULT,
        runtime_config: None,
        federation_accepts: None,
    };
    let set = ListenerSet::start(vec![spec], context, &root)?;
    let Some((_, BoundAddress::Tcp(address))) = set.addresses().first().cloned() else {
        return Err("listener has no TCP address".into());
    };
    // The stub StateCore retains every sink for the connection's life.
    let core = tokio::spawn(async move {
        let mut sinks: Vec<Arc<dyn ClientSink>> = Vec::new();
        while let Some(message) = receiver.recv().await {
            if let StateCoreMessage::Opened {
                sink,
                acknowledgement,
                ..
            } = message
            {
                sinks.push(sink);
                let _sent = acknowledgement.send(ConnectionOpenOutcome::Accepted);
            }
        }
        sinks.len()
    });

    let mut driver = tokio::task::spawn_blocking(move || -> TestResult<Driver> {
        let mut driver = Driver::spawn(&[address])?;
        driver.open(WARM_CONNECTIONS, WARM_CONNECTIONS)?;
        Ok(driver)
    })
    .await??;
    let warm = u64::try_from(WARM_CONNECTIONS)?;
    let charged_before = settle(&budget, warm * CLIENT_CONNECTION_BASE_BYTES).await?;
    let resident_before = resident_anonymous_bytes()?;
    driver = tokio::task::spawn_blocking(move || -> TestResult<Driver> {
        driver.open(MEASURED_CONNECTIONS, LISTENER_CEILING)?;
        Ok(driver)
    })
    .await??;
    let measured = u64::try_from(MEASURED_CONNECTIONS)?;
    let charged_after = settle(
        &budget,
        charged_before + measured * CLIENT_CONNECTION_BASE_BYTES,
    )
    .await?;
    let resident_after = resident_anonymous_bytes()?;
    let per_connection = resident_after.saturating_sub(resident_before) / measured;
    eprintln!(
        "idle TLS connections: charged_before={charged_before} charged_after={charged_after} \
         resident_before={resident_before} resident_after={resident_after} \
         per_connection_resident={per_connection}"
    );
    assert_eq!(charged_before, warm * CLIENT_CONNECTION_BASE_BYTES);
    assert_eq!(
        charged_after - charged_before,
        measured * CLIENT_CONNECTION_BASE_BYTES,
        "an idle connection holds only its base charge: no queue, input, or setup backing"
    );
    assert!(
        per_connection <= CLIENT_CONNECTION_BASE_BYTES,
        "the base charge dominates each idle connection's resident growth ({per_connection} bytes)"
    );

    tokio::task::spawn_blocking(move || driver.finish()).await??;
    set.stop_accepting();
    set.cancel_connections();
    tokio::time::timeout(Duration::from_secs(20), set.join()).await??;
    // Each closed connection's base permit rides its physical-close notice
    // to StateCore; dropping the undrained inbox returns them here.
    drop(close_inbox);
    assert_eq!(
        budget.charged(),
        0,
        "every connection returned its base charge"
    );
    root.cancel();
    core.abort();
    Ok(())
}

/// The population the production occupancy measurement opens. A development
/// pilot lowers it through the environment; its record then says so.
fn measured_population() -> TestResult<usize> {
    match std::env::var(POPULATION_ENV) {
        Ok(text) => Ok(text.trim().parse::<usize>()?),
        Err(_) => Ok(DEFAULT_CLIENT_CONNECTIONS),
    }
}

/// Waits until the budget holds exactly `expected` bytes or `deadline` passes.
async fn settle_until(budget: &MemoryBudget, expected: u64, deadline: Instant) -> u64 {
    while budget.charged() != expected && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    budget.charged()
}

/// Binds `count` loopback client listeners that share one ceiling.
fn client_listeners(
    count: usize,
    ceiling: usize,
    tls: &Arc<rustls::ServerConfig>,
) -> TestResult<Vec<ListenerSpec>> {
    let mut specs = Vec::new();
    for index in 0..count {
        specs.push(ListenerSpec {
            name: ListenerName::parse(&format!("idle{index}"))?,
            purpose: ListenerPurpose::ClientTls,
            source: ListenerSource::InheritedTcp(std::net::TcpListener::bind("127.0.0.1:0")?),
            max_connections: ceiling,
            tls: Some(Arc::clone(tls)),
            local_admin: None,
        });
    }
    Ok(specs)
}

/// Every bound TCP address of a started listener set.
fn bound_addresses(set: &ListenerSet) -> TestResult<Vec<SocketAddr>> {
    let mut addresses = Vec::new();
    for (_, bound) in set.addresses() {
        let BoundAddress::Tcp(address) = bound else {
            return Err("a client listener has no TCP address".into());
        };
        addresses.push(*address);
    }
    if addresses.is_empty() {
        return Err("the listener set bound no address".into());
    }
    Ok(addresses)
}

/// CAP-01: one node admits the Section 19.2 default idle client population
/// inside the unchanged four-GiB budget, and every admitted connection holds
/// exactly its base charge with its queue and input backing composed on
/// demand (spec 19.2, 28.7).
///
/// This is the per-node occupancy measurement: one process, one budget, one
/// live pool `P`, and one simultaneous population. It is ignored by default
/// because it opens the production population; it needs a descriptor limit
/// above twice that population and several gigabytes of free memory, and it
/// runs for minutes. `AGENC_IDLE_POPULATION` selects a smaller development
/// pilot, which demonstrates the same mechanism and closes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "opens the Section 19.2 default idle client population"]
async fn one_node_admits_the_default_idle_population_within_the_default_budget() -> TestResult {
    let population = measured_population()?;
    let ceiling = population
        .checked_add(WARM_CONNECTIONS)
        .ok_or("population overflows its ceiling")?;
    let pool = startup_arithmetic(
        DEFAULT_BUDGET_BYTES,
        DEFAULT_CRYPTO_WORKERS,
        &[ListenerPurpose::ClientTls],
        DEFAULT_PARSED_ARENA_BYTES,
    )?;
    let budget = Arc::new(MemoryBudget::new(pool.protocol_pool_bytes()));
    let fixture = TlsFixture::mint([FIXTURE_SEED; 32], DNS_NAME)?;
    let tls = build_server_config_blocking(
        TlsEndpointProfile::Client,
        CertChain::parse(fixture.leaf_certificate_der())?,
        PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
        ClientAuth::None,
    )?;
    let specs = client_listeners(PRODUCTION_LISTENERS, ceiling, &tls)?;
    let (inbox, mut receiver) = mpsc::channel(1_024);
    let (connection_closes, close_inbox) = connection_close_channel();
    let root = CancellationToken::root();
    let context = ListenerContext {
        budget: Arc::clone(&budget),
        handshakes: HandshakeLimiter::new(PRODUCTION_HANDSHAKES)?,
        client_slots: Arc::new(Semaphore::new(ceiling)),
        admission: Arc::new(PermissiveAdmission),
        observer: Arc::new(Observer),
        inbox,
        connection_closes,
        admin: None,
        limits: ConnectionLimits::DEFAULT,
        runtime_config: None,
        federation_accepts: None,
    };
    let set = ListenerSet::start(specs, context, &root)?;
    let addresses = bound_addresses(&set)?;
    let core = tokio::spawn(async move {
        let mut sinks: Vec<Arc<dyn ClientSink>> = Vec::new();
        while let Some(message) = receiver.recv().await {
            if let StateCoreMessage::Opened {
                sink,
                acknowledgement,
                ..
            } = message
            {
                sinks.push(sink);
                let _sent = acknowledgement.send(ConnectionOpenOutcome::Accepted);
            }
        }
        sinks.len()
    });

    let warm_addresses = addresses.clone();
    let mut driver = tokio::task::spawn_blocking(move || -> TestResult<Driver> {
        let mut driver = Driver::spawn(&warm_addresses)?;
        driver.open(WARM_CONNECTIONS, WARM_CONNECTIONS)?;
        Ok(driver)
    })
    .await??;
    let warm = u64::try_from(WARM_CONNECTIONS)?;
    let settle_budget = SETTLE_PER_THOUSAND * u32::try_from(ceiling.div_ceil(1_000))?;
    let charged_before = settle_until(
        &budget,
        warm * CLIENT_CONNECTION_BASE_BYTES,
        Instant::now() + settle_budget,
    )
    .await;
    let resident_before = resident_anonymous_bytes()?;
    let started = Instant::now();
    driver = tokio::task::spawn_blocking(move || -> TestResult<Driver> {
        driver.open(population, ceiling)?;
        Ok(driver)
    })
    .await??;
    let admitted = u64::try_from(population)?;
    let charged_after = settle_until(
        &budget,
        charged_before + admitted * CLIENT_CONNECTION_BASE_BYTES,
        Instant::now() + settle_budget,
    )
    .await;
    let resident_after = resident_anonymous_bytes()?;
    let elapsed = started.elapsed();
    let per_connection = resident_after.saturating_sub(resident_before) / admitted;
    println!(
        "idle occupancy: population={population} listeners={} pool={} charged={charged_after} \
         charged_per_connection={} resident_before={resident_before} resident_after={resident_after} \
         resident_per_connection={per_connection} admitted_in_ms={}",
        addresses.len(),
        pool.protocol_pool_bytes(),
        (charged_after - charged_before) / admitted,
        elapsed.as_millis()
    );
    assert_eq!(
        charged_after - charged_before,
        admitted * CLIENT_CONNECTION_BASE_BYTES,
        "each admitted idle connection holds exactly its base charge"
    );
    assert!(
        charged_after <= pool.protocol_pool_bytes(),
        "the whole population is charged inside the unchanged live pool"
    );
    assert!(
        per_connection <= CLIENT_CONNECTION_BASE_BYTES,
        "the base charge dominates each idle connection's resident growth ({per_connection} bytes)"
    );

    tokio::task::spawn_blocking(move || driver.finish()).await??;
    set.stop_accepting();
    set.cancel_connections();
    tokio::time::timeout(Duration::from_secs(120), set.join()).await??;
    drop(close_inbox);
    assert_eq!(
        budget.charged(),
        0,
        "every connection returned its base charge"
    );
    root.cancel();
    core.abort();
    Ok(())
}
