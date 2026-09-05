#![forbid(unsafe_code)]

//! The listener accept path and connection owners end to end (spec 19.2
//! lines 2784-2790, spec 21.2 lines 4071-4073, spec 21.3 lines 4077-4106,
//! spec 8.5 lines 548-568): inherited TCP listeners, refusals that close
//! before TLS, ceilings that pause accepts, onion and local administrative
//! Unix sockets with their modes, mutual TLS peer identity, reader pause,
//! protocol-error and slow-consumer closes, and churn without leaks.

use std::error::Error;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use agenc_ircd_client_wire::WireMessage;
use agenc_ircd_config::ListenerName;
use agenc_ircd_runtime::budget::{
    BoundedMemoryCharges, CLIENT_CONNECTION_BASE_BYTES, MemoryBudget, MemoryBudgetPort as _,
    MemoryCharge, PermitCursor,
};
use agenc_ircd_runtime::cancel::CancellationToken;
use agenc_ircd_runtime::connection::{
    AdmittedConnection, BoundedSharedClientFrames, ClientQueueDemand, ClientSink, ConnectionExit,
    ConnectionGeneration, ConnectionLimits, PeerIdentity,
};
use agenc_ircd_runtime::listener::{
    AcceptAdmission, AdmissionVerdict, BoundAddress, ConnectionObserver, ListenerContext,
    ListenerError, ListenerSet, ListenerSource, ListenerSpec, LocalAdminAdmission,
    PermissiveAdmission, RefusalReason, UNIX_SOCKET_MODE,
};
use agenc_ircd_runtime::purpose::ListenerPurpose;
use agenc_ircd_runtime::state_core::inbox::{
    CloseReason, ConnectionCloseInbox, ConnectionOpenOutcome, SourceAddressKey, StateCoreMessage,
    connection_close_channel,
};
use agenc_ircd_runtime::tls::{
    ADMIN_ALPN, CLIENT_ALPN, CertChain, ClientAuth, HandshakeLimiter, PrivateKey, TlsConfigError,
    TlsEndpointProfile, TlsHandshakeError, TrustStore, build_client_config,
    build_server_config_blocking,
};
use agenc_ircd_testkit::TlsFixture;
use agenc_ircd_types::MonotonicTick;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, StreamOwned};
use tokio::sync::{Semaphore, mpsc};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
type ClientOutcome = Result<Vec<u8>, String>;

const DNS_NAME: &str = "node.test";
const BUDGET_BYTES: u64 = 64 * 1_048_576;
const INBOX_CAPACITY: usize = 16;
const SETTLE: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observed {
    Admitted(ListenerPurpose, PeerIdentity),
    Refused(ListenerPurpose, RefusalReason),
    Closed(ConnectionGeneration, CloseReason),
}

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<Observed>>,
}

impl Recorder {
    fn snapshot(&self) -> Vec<Observed> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

impl ConnectionObserver for Recorder {
    fn admitted(&self, connection: &AdmittedConnection) {
        if let Ok(mut events) = self.events.lock() {
            events.push(Observed::Admitted(connection.purpose, connection.peer));
        }
    }

    fn admin_admitted(&self, purpose: ListenerPurpose, peer: PeerIdentity) {
        if let Ok(mut events) = self.events.lock() {
            events.push(Observed::Admitted(purpose, peer));
        }
    }

    fn refused(&self, purpose: ListenerPurpose, reason: RefusalReason) {
        if let Ok(mut events) = self.events.lock() {
            events.push(Observed::Refused(purpose, reason));
        }
    }

    fn closed(&self, exit: &ConnectionExit) {
        if let Ok(mut events) = self.events.lock() {
            events.push(Observed::Closed(exit.generation, exit.reason));
        }
    }
}

struct RefuseAll;

impl AcceptAdmission for RefuseAll {
    fn admit(&self, _: ListenerPurpose, _: SourceAddressKey) -> AdmissionVerdict {
        AdmissionVerdict::Refuse
    }
}

#[derive(Default)]
struct CountingAdmission {
    admitted: AtomicU64,
    released: AtomicU64,
}

impl AcceptAdmission for CountingAdmission {
    fn admit(&self, _: ListenerPurpose, _: SourceAddressKey) -> AdmissionVerdict {
        self.admitted.fetch_add(1, Ordering::Relaxed);
        AdmissionVerdict::Admit
    }

    fn released(&self, _: ListenerPurpose, _: SourceAddressKey) -> Option<MonotonicTick> {
        self.released.fetch_add(1, Ordering::Relaxed);
        Some(MonotonicTick::from_ticks(77))
    }
}

struct Harness {
    budget: Arc<MemoryBudget>,
    handshakes: HandshakeLimiter,
    client_slots: Arc<Semaphore>,
    recorder: Arc<Recorder>,
    inbox: mpsc::Receiver<StateCoreMessage>,
    _connection_closes: ConnectionCloseInbox,
    root: CancellationToken,
    set: ListenerSet,
}

struct HarnessOptions {
    budget_bytes: u64,
    handshakes: usize,
    client_slots: usize,
    admission: Arc<dyn AcceptAdmission>,
    inbox_capacity: usize,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            budget_bytes: BUDGET_BYTES,
            handshakes: 16,
            client_slots: 16,
            admission: Arc::new(PermissiveAdmission),
            inbox_capacity: INBOX_CAPACITY,
        }
    }
}

fn fixture(seed: u8) -> Result<TlsFixture, Box<dyn Error + Send + Sync>> {
    Ok(TlsFixture::mint([seed; 32], DNS_NAME)?)
}

fn server(
    fixture: &TlsFixture,
    profile: TlsEndpointProfile,
    auth: ClientAuth,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    build_server_config_blocking(
        profile,
        CertChain::parse(fixture.leaf_certificate_der())?,
        PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
        auth,
    )
}

fn client(
    fixture: &TlsFixture,
    alpn: &[u8],
    certificate: bool,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let auth = if certificate {
        Some((
            CertChain::parse(fixture.leaf_certificate_der())?,
            PrivateKey::parse(fixture.leaf_private_key_pkcs8_der())?,
        ))
    } else {
        None
    };
    build_client_config(
        TrustStore::parse(fixture.ca_certificate_der())?,
        Some(alpn),
        auth,
    )
}

fn start(specs: Vec<ListenerSpec>, options: HarnessOptions) -> Result<Harness, ListenerError> {
    let budget = Arc::new(MemoryBudget::new(options.budget_bytes));
    let handshakes = HandshakeLimiter::new(options.handshakes).map_err(|_| ListenerError::Bind)?;
    let client_slots = Arc::new(Semaphore::new(options.client_slots));
    let recorder = Arc::new(Recorder::default());
    let (sender, inbox) = mpsc::channel(options.inbox_capacity);
    let (connection_closes, connection_close_inbox) = connection_close_channel();
    let root = CancellationToken::root();
    let context = ListenerContext {
        budget: Arc::clone(&budget),
        handshakes: handshakes.clone(),
        client_slots: Arc::clone(&client_slots),
        admission: options.admission,
        observer: recorder.clone(),
        inbox: sender,
        connection_closes,
        admin: None,
        limits: ConnectionLimits::DEFAULT,
        runtime_config: None,
        federation_accepts: None,
    };
    let set = ListenerSet::start(specs, context, &root)?;
    Ok(Harness {
        budget,
        handshakes,
        client_slots,
        recorder,
        inbox,
        _connection_closes: connection_close_inbox,
        root,
        set,
    })
}

fn tcp_spec(
    purpose: ListenerPurpose,
    max_connections: usize,
    tls: Option<Arc<ServerConfig>>,
) -> Result<ListenerSpec, Box<dyn Error + Send + Sync>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(ListenerSpec {
        name: ListenerName::parse("test")?,
        purpose,
        source: ListenerSource::InheritedTcp(listener),
        max_connections,
        tls,
        local_admin: None,
    })
}

fn tcp_address(
    harness: &Harness,
    index: usize,
) -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    match harness.set.addresses().get(index) {
        Some((_, BoundAddress::Tcp(address))) => Ok(*address),
        _ => Err("listener has no TCP address".into()),
    }
}

/// Handshakes, writes `send`, then reads until the server closes.
fn tls_client(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    send: Vec<u8>,
) -> JoinHandle<ClientOutcome> {
    thread::spawn(move || {
        let name = ServerName::try_from(DNS_NAME.to_owned()).map_err(|error| error.to_string())?;
        let connection = ClientConnection::new(config, name).map_err(|error| error.to_string())?;
        let socket = TcpStream::connect(address).map_err(|error| error.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        let mut stream = StreamOwned::new(connection, socket);
        stream.write_all(&send).map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
        let mut received = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => received.extend_from_slice(buffer.get(..read).unwrap_or_default()),
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(received)
    })
}

/// Joins a client thread off the test runtime; the listeners run on this
/// same current-thread runtime, so a blocking join would stall them.
async fn joined<T: Send + 'static>(
    handle: JoinHandle<T>,
) -> Result<T, Box<dyn Error + Send + Sync>> {
    tokio::task::spawn_blocking(move || handle.join())
        .await?
        .map_err(|_| "client thread panicked".into())
}

async fn next_message(
    inbox: &mut mpsc::Receiver<StateCoreMessage>,
) -> Result<StateCoreMessage, Box<dyn Error + Send + Sync>> {
    Ok(tokio::time::timeout(Duration::from_secs(10), inbox.recv())
        .await?
        .ok_or("inbox closed")?)
}

async fn expect_opened(
    inbox: &mut mpsc::Receiver<StateCoreMessage>,
    purpose: ListenerPurpose,
) -> Result<(ConnectionGeneration, Arc<dyn ClientSink>), Box<dyn Error + Send + Sync>> {
    match next_message(inbox).await? {
        StateCoreMessage::Opened {
            generation,
            purpose: opened,
            sink,
            acknowledgement,
            ..
        } if opened == purpose => {
            let _sent = acknowledgement.send(ConnectionOpenOutcome::Accepted);
            Ok((generation, sink))
        }
        _ => Err("expected an opened message".into()),
    }
}

async fn expect_line(
    inbox: &mut mpsc::Receiver<StateCoreMessage>,
    generation: ConnectionGeneration,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    match next_message(inbox).await? {
        StateCoreMessage::Line {
            generation: line_generation,
            message,
            ..
        } if line_generation == generation => Ok(message.command().to_owned()),
        _ => Err("expected a line".into()),
    }
}

async fn expect_closed(
    recorder: &Recorder,
    generation: ConnectionGeneration,
) -> Result<CloseReason, Box<dyn Error + Send + Sync>> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(reason) = recorder
                .snapshot()
                .iter()
                .rev()
                .find_map(|event| match event {
                    Observed::Closed(closed, reason) if *closed == generation => Some(*reason),
                    _ => None,
                })
            {
                break reason;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?)
}

fn enqueue(
    budget: &MemoryBudget,
    sink: &Arc<dyn ClientSink>,
    text: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let message = WireMessage::new("server.test", "NOTICE", &["*"], Some(text))?;
    let measured = message.measure()?;
    let bytes = u64::try_from(measured.bytes())?;
    let mut batch =
        budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::allocation(
            bytes,
        )?])?)?;
    let rendered = Arc::new(measured.encode(&mut PermitCursor::new(&mut batch))?);
    let demand = ClientQueueDemand::new(vec![rendered.as_bytes().len()])?;
    let tentative = sink.try_reserve(demand)?;
    let prepared = sink.prepare(tentative, None)?;
    let frames = BoundedSharedClientFrames::for_reservation(&prepared, vec![rendered])?;
    sink.commit(prepared, frames);
    Ok(())
}

async fn finish(harness: Harness) -> Result<(u64, u64), Box<dyn Error + Send + Sync>> {
    harness.set.stop_accepting();
    harness.set.cancel_connections();
    let exits = tokio::time::timeout(Duration::from_secs(10), harness.set.join()).await??;
    let admitted = exits.iter().map(|exit| exit.admitted).sum();
    let refused = exits.iter().map(|exit| exit.refused).sum();
    drop(harness._connection_closes);
    assert_eq!(
        harness.budget.available(),
        harness.budget.capacity(),
        "every permit returned"
    );
    assert_eq!(
        harness.handshakes.available(),
        harness.handshakes.capacity()
    );
    harness.root.cancel();
    Ok((admitted, refused))
}

#[tokio::test]
async fn the_accept_barrier_closes_sockets_before_live_connections_are_cancelled() -> TestResult {
    let fixture = fixture(71)?;
    let spec = tcp_spec(
        ListenerPurpose::ClientTls,
        2,
        Some(server(
            &fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )?;
    let mut harness = start(vec![spec], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(
        address,
        client(&fixture, CLIENT_ALPN, false)?,
        b"PING :barrier\r\n".to_vec(),
    );
    let (generation, sink) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    assert_eq!(expect_line(&mut harness.inbox, generation).await?, "PING");

    let control = harness.set.control();
    control.stop_accepting();
    tokio::time::timeout(Duration::from_secs(2), control.wait_accept_stopped()).await?;
    assert!(
        TcpStream::connect(address).is_err(),
        "the listening socket is gone while the accepted connection remains"
    );

    let acknowledgement = sink.shutdown_after_flush();
    tokio::time::timeout(Duration::from_secs(2), acknowledgement.wait()).await?;
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::Shutdown
    );
    assert!(joined(client).await?.is_ok());
    drop(sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 0));
    Ok(())
}

#[tokio::test]
async fn an_inherited_tcp_listener_admits_a_client_and_routes_lines_and_frames() -> TestResult {
    let fixture = fixture(51)?;
    let spec = tcp_spec(
        ListenerPurpose::ClientTls,
        4,
        Some(server(
            &fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )?;
    let mut harness = start(vec![spec], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(
        address,
        client(&fixture, CLIENT_ALPN, false)?,
        b"NICK alice\r\n".to_vec(),
    );

    let (generation, sink) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    assert_eq!(sink.generation(), generation);
    assert_eq!(expect_line(&mut harness.inbox, generation).await?, "NICK");
    enqueue(&harness.budget, &sink, "hello")?;
    tokio::time::sleep(SETTLE).await;
    sink.begin_slow_consumer_close();
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::SlowConsumer
    );
    let received = joined(client).await??;
    assert_eq!(received, b":server.test NOTICE * :hello\r\n");

    drop(sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 0));
    Ok(())
}

#[tokio::test]
async fn refusals_close_the_socket_before_tls() -> TestResult {
    let fixture = fixture(52)?;
    let tls = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let cases: Vec<(HarnessOptions, RefusalReason)> = vec![
        (
            HarnessOptions {
                budget_bytes: 1_000,
                ..HarnessOptions::default()
            },
            RefusalReason::MemoryExhausted,
        ),
        (
            HarnessOptions {
                client_slots: 0,
                ..HarnessOptions::default()
            },
            RefusalReason::GlobalCeiling,
        ),
        (
            HarnessOptions {
                admission: Arc::new(RefuseAll),
                ..HarnessOptions::default()
            },
            RefusalReason::Admission,
        ),
    ];
    for (options, expected) in cases {
        let spec = tcp_spec(ListenerPurpose::ClientTls, 4, Some(Arc::clone(&tls)))?;
        let mut harness = start(vec![spec], options)?;
        let address = tcp_address(&harness, 0)?;
        let client = tls_client(address, client(&fixture, CLIENT_ALPN, false)?, Vec::new());
        assert!(joined(client).await?.is_err());
        tokio::time::sleep(SETTLE).await;
        assert!(harness.inbox.try_recv().is_err(), "nothing was opened");
        assert!(
            harness
                .recorder
                .snapshot()
                .contains(&Observed::Refused(ListenerPurpose::ClientTls, expected)),
            "{expected:?}"
        );
        let (admitted, refused) = finish(harness).await?;
        assert_eq!((admitted, refused), (0, 1));
    }
    Ok(())
}

#[tokio::test]
async fn resource_refusals_happen_before_transport_quota() -> TestResult {
    let fixture = fixture(62)?;
    let tls = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let admission = Arc::new(CountingAdmission::default());
    let options = HarnessOptions {
        budget_bytes: 1_000,
        admission: admission.clone(),
        ..HarnessOptions::default()
    };
    let spec = tcp_spec(ListenerPurpose::ClientTls, 4, Some(tls))?;
    let harness = start(vec![spec], options)?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(address, client(&fixture, CLIENT_ALPN, false)?, Vec::new());
    assert!(joined(client).await?.is_err());
    tokio::time::sleep(SETTLE).await;
    assert_eq!(admission.admitted.load(Ordering::Relaxed), 0);
    assert_eq!(admission.released.load(Ordering::Relaxed), 0);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (0, 1));
    Ok(())
}

#[tokio::test]
async fn tls_refusals_release_transport_quota() -> TestResult {
    let fixture = fixture(63)?;
    let tls = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let admission = Arc::new(CountingAdmission::default());
    let options = HarnessOptions {
        admission: admission.clone(),
        ..HarnessOptions::default()
    };
    let spec = tcp_spec(ListenerPurpose::ClientTls, 4, Some(tls))?;
    let harness = start(vec![spec], options)?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(address, client(&fixture, ADMIN_ALPN, false)?, Vec::new());
    assert!(joined(client).await?.is_err());
    tokio::time::sleep(SETTLE).await;
    assert_eq!(admission.admitted.load(Ordering::Relaxed), 1);
    assert_eq!(admission.released.load(Ordering::Relaxed), 1);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (0, 1));
    Ok(())
}

#[tokio::test]
async fn ceilings_pause_accepts_until_a_slot_frees() -> TestResult {
    let fixture = fixture(53)?;
    let spec = tcp_spec(
        ListenerPurpose::ClientTls,
        1,
        Some(server(
            &fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )?;
    let options = HarnessOptions {
        handshakes: 1,
        ..HarnessOptions::default()
    };
    let mut harness = start(vec![spec], options)?;
    let address = tcp_address(&harness, 0)?;
    let silent = TcpStream::connect(address)?;
    tokio::time::sleep(SETTLE).await;
    let waiting = tls_client(address, client(&fixture, CLIENT_ALPN, false)?, Vec::new());
    tokio::time::sleep(SETTLE).await;
    assert!(
        harness.inbox.try_recv().is_err(),
        "the second socket waits behind the ceiling"
    );
    assert_eq!(harness.handshakes.available(), 0);
    drop(silent);
    let (generation, sink) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    assert!(harness.recorder.snapshot().contains(&Observed::Refused(
        ListenerPurpose::ClientTls,
        RefusalReason::TlsHandshake(TlsHandshakeError::PeerClosed)
    )));
    sink.begin_slow_consumer_close();
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::SlowConsumer
    );
    assert!(joined(waiting).await?.is_ok());
    drop(sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 1));
    Ok(())
}

fn scratch_directory(name: &str) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    let unique = format!(
        "agenc-listener-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let directory = std::env::temp_dir().join(unique);
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o750))?;
    Ok(directory)
}

#[tokio::test]
async fn local_admin_lines_never_enter_the_public_client_inbox() -> TestResult {
    let fixture = fixture(54)?;
    let directory = scratch_directory("unix")?;
    let onion_path = directory.join("onion.sock");
    let admin_path = directory.join("admin.sock");
    let local_uid = std::fs::metadata(&directory)?.uid();
    let local_gid = std::fs::metadata(&directory)?.gid();
    let specs = vec![
        ListenerSpec {
            name: ListenerName::parse("onion")?,
            purpose: ListenerPurpose::ClientOnion,
            source: ListenerSource::Unix(onion_path.clone()),
            max_connections: 2,
            tls: Some(server(
                &fixture,
                TlsEndpointProfile::Client,
                ClientAuth::None,
            )?),
            local_admin: None,
        },
        ListenerSpec {
            name: ListenerName::parse("admin")?,
            purpose: ListenerPurpose::AdminLocal,
            source: ListenerSource::Unix(admin_path.clone()),
            max_connections: 2,
            tls: None,
            local_admin: Some(LocalAdminAdmission::new(vec![local_uid], vec![local_gid])?),
        },
    ];
    let mut harness = start(specs, HarnessOptions::default())?;
    for path in [&onion_path, &admin_path] {
        let mode = std::fs::symlink_metadata(path)?.permissions().mode() & 0o7777;
        assert_eq!(mode, UNIX_SOCKET_MODE);
    }

    let onion_config = client(&fixture, CLIENT_ALPN, false)?;
    let onion_client_path = onion_path.clone();
    let onion_client = thread::spawn(move || -> ClientOutcome {
        let name = ServerName::try_from(DNS_NAME.to_owned()).map_err(|error| error.to_string())?;
        let connection =
            ClientConnection::new(onion_config, name).map_err(|error| error.to_string())?;
        let socket = UnixStream::connect(onion_client_path).map_err(|error| error.to_string())?;
        let mut stream = StreamOwned::new(connection, socket);
        stream
            .write_all(b"CAP LS 302\r\n")
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
        let mut buffer = [0_u8; 64];
        let _ = stream.read(&mut buffer);
        Ok(Vec::new())
    });
    let (onion_generation, onion_sink) =
        expect_opened(&mut harness.inbox, ListenerPurpose::ClientOnion).await?;
    assert_eq!(
        expect_line(&mut harness.inbox, onion_generation).await?,
        "CAP"
    );
    onion_sink.begin_slow_consumer_close();
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), onion_generation).await?,
        CloseReason::SlowConsumer
    );
    assert!(joined(onion_client).await?.is_ok());

    let admin_client_path = admin_path.clone();
    let admin_client = thread::spawn(move || -> ClientOutcome {
        let mut socket =
            UnixStream::connect(admin_client_path).map_err(|error| error.to_string())?;
        socket
            .write_all(b"PING :x\r\n")
            .map_err(|error| error.to_string())?;
        let mut buffer = [0_u8; 64];
        let _ = socket.read(&mut buffer);
        Ok(Vec::new())
    });
    assert!(joined(admin_client).await?.is_ok());
    assert!(
        tokio::time::timeout(SETTLE, harness.inbox.recv())
            .await
            .is_err(),
        "admin plaintext must not produce a public StateCore message"
    );

    let probe = directory.join("probe");
    std::fs::write(&probe, b"x")?;
    let uid = std::fs::metadata(&probe)?.uid();
    let gid = std::fs::metadata(&probe)?.gid();
    let events = harness.recorder.snapshot();
    assert!(events.contains(&Observed::Admitted(
        ListenerPurpose::ClientOnion,
        PeerIdentity::Anonymous
    )));
    let _ = (uid, gid);
    assert!(events.contains(&Observed::Refused(
        ListenerPurpose::AdminLocal,
        RefusalReason::AdminOwner
    )));
    drop(onion_sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 1));
    let _ = std::fs::remove_dir_all(directory);
    Ok(())
}

#[tokio::test]
async fn admin_tls_lines_never_enter_the_public_client_inbox() -> TestResult {
    let fixture = fixture(55)?;
    let store = TrustStore::parse(fixture.ca_certificate_der())?;
    let spec = tcp_spec(
        ListenerPurpose::AdminTls,
        2,
        Some(server(
            &fixture,
            TlsEndpointProfile::Admin,
            ClientAuth::MutualTls(store),
        )?),
    )?;
    let mut harness = start(vec![spec], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(
        address,
        client(&fixture, ADMIN_ALPN, true)?,
        b"PING :a\r\n".to_vec(),
    );
    let _closed_without_public_dispatch = joined(client).await?;
    assert!(
        tokio::time::timeout(SETTLE, harness.inbox.recv())
            .await
            .is_err(),
        "admin plaintext must not produce a public StateCore message"
    );
    assert!(harness.recorder.snapshot().contains(&Observed::Refused(
        ListenerPurpose::AdminTls,
        RefusalReason::AdminOwner
    )));
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (0, 1));
    Ok(())
}

#[tokio::test]
async fn protocol_errors_and_transport_loss_close_with_their_reasons() -> TestResult {
    let fixture = fixture(56)?;
    let spec = tcp_spec(
        ListenerPurpose::ClientTls,
        4,
        Some(server(
            &fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )?;
    let mut harness = start(vec![spec], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let config = client(&fixture, CLIENT_ALPN, false)?;

    let bad = tls_client(address, Arc::clone(&config), b"NICK a\0b\r\n".to_vec());
    let (generation, _) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::ProtocolError
    );
    let _ = joined(bad).await?;

    let leaving = thread::spawn({
        let config = Arc::clone(&config);
        move || -> Result<(), String> {
            let name =
                ServerName::try_from(DNS_NAME.to_owned()).map_err(|error| error.to_string())?;
            let connection =
                ClientConnection::new(config, name).map_err(|error| error.to_string())?;
            let socket = TcpStream::connect(address).map_err(|error| error.to_string())?;
            let mut stream = StreamOwned::new(connection, socket);
            stream
                .write_all(b"NICK bob\r\n")
                .map_err(|error| error.to_string())?;
            stream.flush().map_err(|error| error.to_string())?;
            Ok(())
        }
    });
    let (generation, _) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    assert_eq!(expect_line(&mut harness.inbox, generation).await?, "NICK");
    joined(leaving).await??;
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::TransportLoss
    );
    let (admitted, _) = finish(harness).await?;
    assert_eq!(admitted, 2);
    Ok(())
}

#[tokio::test]
async fn the_reader_pauses_while_the_inbox_is_full_and_loses_nothing() -> TestResult {
    let fixture = fixture(57)?;
    let spec = tcp_spec(
        ListenerPurpose::ClientTls,
        4,
        Some(server(
            &fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )?;
    let options = HarnessOptions {
        inbox_capacity: 1,
        ..HarnessOptions::default()
    };
    let mut harness = start(vec![spec], options)?;
    let address = tcp_address(&harness, 0)?;
    let lines: Vec<u8> = (0..24)
        .flat_map(|index| format!("PRIVMSG #a :{index}\r\n").into_bytes())
        .collect();
    let client = tls_client(address, client(&fixture, CLIENT_ALPN, false)?, lines);
    tokio::time::sleep(SETTLE).await;
    let (generation, sink) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    for _ in 0..24 {
        assert_eq!(
            expect_line(&mut harness.inbox, generation).await?,
            "PRIVMSG"
        );
    }
    sink.begin_slow_consumer_close();
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::SlowConsumer
    );
    assert!(joined(client).await?.is_ok());
    drop(sink);
    finish(harness).await?;
    Ok(())
}

#[tokio::test]
async fn a_state_core_open_refusal_returns_every_unarmed_resource() -> TestResult {
    let fixture = fixture(65)?;
    let spec = tcp_spec(
        ListenerPurpose::ClientTls,
        1,
        Some(server(
            &fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )?;
    let mut harness = start(vec![spec], HarnessOptions::default())?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(address, client(&fixture, CLIENT_ALPN, false)?, Vec::new());
    let StateCoreMessage::Opened {
        generation,
        sink,
        acknowledgement,
        ..
    } = next_message(&mut harness.inbox).await?
    else {
        return Err("expected an opened message".into());
    };
    assert!(acknowledgement.send(ConnectionOpenOutcome::Refused).is_ok());
    drop(sink);
    let _client_outcome = joined(client).await?;
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::Overload
    );
    assert_eq!(harness.budget.available(), harness.budget.capacity());
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 0));
    Ok(())
}

#[tokio::test]
async fn physical_close_releases_admission_before_a_blocked_close_notice() -> TestResult {
    let fixture = fixture(64)?;
    let spec = tcp_spec(
        ListenerPurpose::ClientTls,
        1,
        Some(server(
            &fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )?;
    let admission = Arc::new(CountingAdmission::default());
    let options = HarnessOptions {
        admission: admission.clone(),
        inbox_capacity: 1,
        ..HarnessOptions::default()
    };
    let mut harness = start(vec![spec], options)?;
    let address = tcp_address(&harness, 0)?;
    let client = tls_client(
        address,
        client(&fixture, CLIENT_ALPN, false)?,
        b"NICK bob\r\n".to_vec(),
    );
    let (generation, sink) = expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
    tokio::time::sleep(SETTLE).await;
    sink.begin_slow_consumer_close();
    tokio::time::timeout(Duration::from_secs(10), async {
        while admission.released.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(admission.released.load(Ordering::Relaxed), 1);
    assert_eq!(expect_line(&mut harness.inbox, generation).await?, "NICK");
    assert_eq!(
        expect_closed(harness.recorder.as_ref(), generation).await?,
        CloseReason::SlowConsumer
    );
    assert!(joined(client).await?.is_ok());
    drop(sink);
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (1, 0));
    Ok(())
}

#[tokio::test]
async fn connection_churn_returns_every_permit_slot_and_task() -> TestResult {
    let fixture = fixture(58)?;
    let spec = tcp_spec(
        ListenerPurpose::ClientTls,
        8,
        Some(server(
            &fixture,
            TlsEndpointProfile::Client,
            ClientAuth::None,
        )?),
    )?;
    let options = HarnessOptions {
        client_slots: 8,
        ..HarnessOptions::default()
    };
    let mut harness = start(vec![spec], options)?;
    let address = tcp_address(&harness, 0)?;
    let config = client(&fixture, CLIENT_ALPN, false)?;
    for round in 0..20_u8 {
        let handle = tls_client(
            address,
            Arc::clone(&config),
            format!("NICK n{round}\r\n").into_bytes(),
        );
        let (generation, sink) =
            expect_opened(&mut harness.inbox, ListenerPurpose::ClientTls).await?;
        assert_eq!(expect_line(&mut harness.inbox, generation).await?, "NICK");
        sink.begin_slow_consumer_close();
        assert_eq!(
            expect_closed(harness.recorder.as_ref(), generation).await?,
            CloseReason::SlowConsumer
        );
        assert!(joined(handle).await?.is_ok());
    }
    tokio::time::sleep(SETTLE).await;
    assert_eq!(harness.client_slots.available_permits(), 8);
    assert_eq!(
        harness
            .budget
            .capacity()
            .saturating_sub(harness.budget.available()),
        20 * CLIENT_CONNECTION_BASE_BYTES,
        "the StateCore seam retains one client base charge per pending close"
    );
    assert!(
        harness.root.live_children() <= 2,
        "only the listener tokens remain"
    );
    let (admitted, refused) = finish(harness).await?;
    assert_eq!((admitted, refused), (20, 0));
    Ok(())
}

#[tokio::test]
async fn start_rejects_unsupported_and_mismatched_specs() -> TestResult {
    let fixture = fixture(59)?;
    let tls = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let cases: Vec<(
        ListenerPurpose,
        ListenerSource,
        Option<Arc<ServerConfig>>,
        ListenerError,
    )> = vec![
        (
            ListenerPurpose::ClientWss,
            ListenerSource::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
            None,
            if cfg!(feature = "wss") {
                ListenerError::MissingTls
            } else {
                ListenerError::UnsupportedPurpose
            },
        ),
        (
            ListenerPurpose::ClientTls,
            ListenerSource::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
            None,
            ListenerError::MissingTls,
        ),
        (
            ListenerPurpose::AdminLocal,
            ListenerSource::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
            Some(Arc::clone(&tls)),
            ListenerError::UnexpectedTls,
        ),
        (
            ListenerPurpose::ClientOnion,
            ListenerSource::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
            Some(Arc::clone(&tls)),
            ListenerError::SourceMismatch,
        ),
    ];
    for (purpose, source, tls, expected) in cases {
        let spec = ListenerSpec {
            name: ListenerName::parse("invalid")?,
            purpose,
            source,
            max_connections: 1,
            tls,
            local_admin: None,
        };
        let error = start(vec![spec], HarnessOptions::default()).err();
        assert_eq!(error, Some(expected));
    }
    let root = CancellationToken::root();
    root.cancel();
    let (sender, _inbox) = mpsc::channel(1);
    let (connection_closes, _connection_close_inbox) = connection_close_channel();
    let context = ListenerContext {
        budget: Arc::new(MemoryBudget::new(BUDGET_BYTES)),
        handshakes: HandshakeLimiter::new(1)?,
        client_slots: Arc::new(Semaphore::new(1)),
        admission: Arc::new(PermissiveAdmission),
        observer: Arc::new(Recorder::default()),
        inbox: sender,
        connection_closes,
        admin: None,
        limits: ConnectionLimits::DEFAULT,
        runtime_config: None,
        federation_accepts: None,
    };
    assert_eq!(
        ListenerSet::start(Vec::new(), context, &root).err(),
        Some(ListenerError::Cancelled)
    );
    Ok(())
}

#[tokio::test]
async fn listener_set_cleans_only_unix_paths_it_still_owns() -> TestResult {
    let fixture = fixture(72)?;
    let tls = server(&fixture, TlsEndpointProfile::Client, ClientAuth::None)?;
    let directory = scratch_directory("socket-lifecycle")?;

    let failed_path = directory.join("failed-start.sock");
    let first = ListenerSpec {
        name: ListenerName::parse("failed-first")?,
        purpose: ListenerPurpose::ClientOnion,
        source: ListenerSource::Unix(failed_path.clone()),
        max_connections: 1,
        tls: Some(Arc::clone(&tls)),
        local_admin: None,
    };
    let unsupported = ListenerSpec {
        name: ListenerName::parse("failed-second")?,
        purpose: ListenerPurpose::ClientWss,
        source: ListenerSource::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
        max_connections: 1,
        tls: None,
        local_admin: None,
    };
    assert_eq!(
        start(vec![first, unsupported], HarnessOptions::default()).err(),
        Some(if cfg!(feature = "wss") {
            ListenerError::MissingTls
        } else {
            ListenerError::UnsupportedPurpose
        })
    );
    assert!(
        std::fs::symlink_metadata(&failed_path).is_err(),
        "a later startup failure drops previously bound owned paths"
    );

    let normal_path = directory.join("normal.sock");
    let replaced_path = directory.join("replaced.sock");
    let inherited_path = directory.join("inherited.sock");
    let inherited = std::os::unix::net::UnixListener::bind(&inherited_path)?;
    let specs = vec![
        ListenerSpec {
            name: ListenerName::parse("normal")?,
            purpose: ListenerPurpose::ClientOnion,
            source: ListenerSource::Unix(normal_path.clone()),
            max_connections: 1,
            tls: Some(Arc::clone(&tls)),
            local_admin: None,
        },
        ListenerSpec {
            name: ListenerName::parse("replaced")?,
            purpose: ListenerPurpose::ClientOnion,
            source: ListenerSource::Unix(replaced_path.clone()),
            max_connections: 1,
            tls: Some(Arc::clone(&tls)),
            local_admin: None,
        },
        ListenerSpec {
            name: ListenerName::parse("inherited")?,
            purpose: ListenerPurpose::ClientOnion,
            source: ListenerSource::InheritedUnix(inherited),
            max_connections: 1,
            tls: Some(tls),
            local_admin: None,
        },
    ];
    let harness = start(specs, HarnessOptions::default())?;
    std::fs::remove_file(&replaced_path)?;
    let replacement = std::os::unix::net::UnixListener::bind(&replaced_path)?;
    let replacement_metadata = std::fs::symlink_metadata(&replaced_path)?;

    finish(harness).await?;
    assert!(
        std::fs::symlink_metadata(&normal_path).is_err(),
        "normal shutdown removes a daemon-owned socket"
    );
    let retained_replacement = std::fs::symlink_metadata(&replaced_path)?;
    assert_eq!(
        (retained_replacement.dev(), retained_replacement.ino()),
        (replacement_metadata.dev(), replacement_metadata.ino()),
        "shutdown must preserve a replacement inode"
    );
    assert!(
        std::fs::symlink_metadata(&inherited_path).is_ok(),
        "shutdown must preserve an adopted socket"
    );

    drop(replacement);
    std::fs::remove_file(replaced_path)?;
    std::fs::remove_file(inherited_path)?;
    std::fs::remove_dir(directory)?;
    Ok(())
}
