//! Stage 10 capacity and sustained-operation campaign (S10-007).
//!
//! One coordinator and two edges of the frozen binary serve N TLS clients
//! that measure the six latency classes while the campaign runs every
//! required operational scenario in cycles: reconnect, churn, snapshot,
//! backup, rekey through `storage restore`, login-index transition,
//! disk-pressure transition, and peer loss. Resource samples and queue
//! high-water marks are taken every ten seconds and every cycle ends with a
//! quiescence check against the warm baseline envelope. The driver supplies
//! the campaign directory, duration, and connection count through the
//! environment and measures the elapsed time itself.
//!
//! The daemon is non-dumpable, so no unprivileged observer can read its
//! `/proc/<pid>/fd` table, and hosts that mount `/proc` with `hidepid` hide
//! the whole entry. Memory and task counts therefore come from a cgroup v2
//! leaf per daemon when the test runs alone inside a delegated cgroup (the
//! driver uses `systemd-run --user --scope -p Delegate=yes`), with
//! `/proc/<pid>/status` as the fallback where it is visible. The descriptor
//! class is measured from the kernel socket table: every inbound socket a
//! node holds is listed in `/proc/net/tcp` under its listener ports.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agenc_ircd_storage::{
    BackupDestination, StateDirectory, StorageEngineLimits, StorageOpenConfig, StorageOwner,
};
use rustix::fs::{FallocateFlags, fallocate};

use super::*;

#[path = "stage_ten_capacity/index_transition.rs"]
mod index_transition;

#[path = "stage_ten_capacity/workload.rs"]
mod workload;

use workload::{CLIENT_NODES, DEFAULT_BUDGET_BYTES, MAX_CLIENT_CONNECTIONS, Workload};

#[path = "../support/admin_client.rs"]
pub(super) mod admin_client;

use admin_client::{AdminIdentity, AdminSession};

const DIRECTORY_ENV: &str = "AGENC_STAGE10_CAMPAIGN_DIR";
const SECONDS_ENV: &str = "AGENC_STAGE10_CAMPAIGN_SECONDS";
const CONNECTIONS_ENV: &str = "AGENC_STAGE10_CAMPAIGN_CONNECTIONS";
const MIN_CAMPAIGN_SECONDS: u64 = 60;
const MAX_CAMPAIGN_SECONDS: u64 = 1_209_600;
const DEFAULT_CONNECTIONS: usize = 48;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const QUIESCE_WINDOW: Duration = Duration::from_secs(8);
/// How long a quiescence check waits for the whole population to be back:
/// the paced return after a maintenance window takes up to 400 ms per
/// client, and a client the coordinator refuses while it still hides that
/// client's previous session retries every two seconds.
const POPULATION_WAIT: Duration = Duration::from_secs(90);
const SCENARIO_SETTLE: Duration = Duration::from_secs(12);
const FINAL_RESERVE: Duration = Duration::from_secs(45);
/// Steady-state rest between two cycles when the budget holds another.
const INTER_CYCLE_REST: Duration = Duration::from_secs(60);
/// The most the campaign waits for the federation to drain before stopping.
const FEDERATION_DRAIN_WAIT: Duration = Duration::from_secs(60);
/// Load channels are `#load<n>`; the population is partitioned across them
/// so no channel exceeds the Section 19.2 default member ceiling.
const LOAD_CHANNEL_PREFIX: &str = "#load";
/// Client sockets the controller opens beside the load population: the
/// registration probes, the snapshot probe, and the OPAQUE logins.
const CONTROLLER_PROBES: u64 = 16;
const CHANNEL_MESSAGE_PERIOD: Duration = Duration::from_secs(1);
const DIRECT_MESSAGE_PERIOD: Duration = Duration::from_secs(2);
const TOPIC_PERIOD: Duration = Duration::from_secs(5);
const READ_SLICE: Duration = Duration::from_millis(100);
const MEMORY_HEADROOM_BYTES: u64 = 128 * 1_024 * 1_024;
const SOCKET_HEADROOM: u64 = 16;
const TASK_HEADROOM: u64 = 8;
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const MAX_CGROUP_FILE_BYTES: u64 = 65_536;
const MAX_SOCKET_TABLE_BYTES: u64 = 64 * 1_024 * 1_024;
/// Lines a probe may read through inside `#load` before its reply arrives.
const BUSY_TRANSCRIPT_LINES: usize = 65_536;
const TCP_ESTABLISHED: &str = "01";
const TCP_CLOSE_WAIT: &str = "08";
const MAX_FIXED_RESERVE_BYTES: u64 = 1_099_511_627_776;
const MIN_FIXED_RESERVE_BYTES: u64 = 67_108_864;
const PHYSICAL_GROWTH_BYTES: u64 = 268_435_456;
/// Free space the campaign leaves above the reserve while it runs normally.
const RESERVE_CLEARANCE_BYTES: u64 = 8 * 1_024 * 1_024 * 1_024;
const PRESSURE_MARGIN_BYTES: u64 = 64 * 1_024 * 1_024;
const REGISTRATION_PROBE_WAIT: Duration = Duration::from_secs(10);
/// Spacing between two workers that share one generator source address when
/// they connect or resume after a maintenance window. The per-address
/// pre-authentication bucket admits at most 10 commands per second (its
/// configuration ceiling), which is about 1.25 registrations per second from
/// one address, so 400 ms per slot keeps each source under that rate instead
/// of a herd that the bucket closes and that then retries from scratch. Only
/// the workers on one address wait for each other, so the warm-up scales with
/// the generator's spread and not with the population.
const RESUME_SLOT: Duration = Duration::from_millis(400);
/// The shortest warm-up before the baseline sample.
const MINIMUM_WARM_UP: Duration = Duration::from_secs(20);
const PRESSURE_RECOVERY_WAIT: Duration = Duration::from_secs(45);
/// How long both edges may take to finish synchronization after a restart.
const POST_RESTART_READY_WAIT: Duration = Duration::from_secs(30);
const CAMPAIGN_ACCOUNT_LOGIN: &str = "campaign-account";

/// Campaign inputs read from the environment the driver sets, with the
/// workload matrix the selected population implies.
struct Settings {
    directory: PathBuf,
    seconds: u64,
    connections: usize,
    workload: Workload,
}

impl Settings {
    fn from_environment() -> TestResult<Self> {
        let directory = PathBuf::from(
            std::env::var_os(DIRECTORY_ENV)
                .ok_or_else(|| failure("campaign directory is not configured"))?,
        );
        let seconds: u64 = std::env::var(SECONDS_ENV)?.parse()?;
        if !(MIN_CAMPAIGN_SECONDS..=MAX_CAMPAIGN_SECONDS).contains(&seconds) {
            return Err(failure("campaign duration is outside its bound"));
        }
        let requested = match std::env::var(CONNECTIONS_ENV) {
            Ok(text) => text.parse()?,
            Err(_) => DEFAULT_CONNECTIONS,
        };
        let ceiling = usize::try_from(MAX_CLIENT_CONNECTIONS)?
            .checked_mul(CLIENT_NODES)
            .ok_or_else(|| failure("campaign ceiling overflows"))?;
        if !(4..=ceiling).contains(&requested) {
            return Err(failure("campaign connection count is outside its bound"));
        }
        // The workload is derived from the per-node share, so an aggregate
        // that only sums to the default population is a pilot.
        let workload = Workload::select(u64::try_from(requested)?)?;
        Ok(Self {
            directory,
            seconds,
            connections: usize::try_from(workload.total_connections())?,
            workload,
        })
    }
}

/// Latency samples in nanoseconds per Section 28.7 class.
#[derive(Default)]
struct Latencies {
    admission: Vec<u64>,
    message: Vec<u64>,
    fanout: Vec<u64>,
    durable_mutation: Vec<u64>,
    opaque: Vec<u64>,
    snapshot: Vec<u64>,
}

/// State every load worker and the controller share.
struct Shared {
    epoch: Instant,
    stop: AtomicBool,
    pause: AtomicBool,
    maintenance: AtomicBool,
    reconnect_round: AtomicU64,
    churn_round: AtomicU64,
    /// Bumped after each disruptive scenario; observers clear their stale
    /// per-sender sequence expectations so only steady-state gaps count.
    resync: AtomicU64,
    latencies: Mutex<Latencies>,
    missed_events: AtomicU64,
    reconnects: AtomicU64,
    churns: AtomicU64,
    sent: AtomicU64,
    /// Channel messages the server refused with an explicit FAIL; each is
    /// re-sent under the same sequence so a refusal is never a silent gap.
    refused: AtomicU64,
    /// Refusals by their FAIL code, bounded to a small closed set.
    refused_codes: Mutex<BTreeMap<String, u64>>,
    /// Refusals per ten-second bucket of campaign time.
    refused_buckets: Mutex<BTreeMap<u64, u64>>,
    received: AtomicU64,
    worker_errors: Mutex<Vec<String>>,
}

impl Shared {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            stop: AtomicBool::new(false),
            pause: AtomicBool::new(false),
            maintenance: AtomicBool::new(false),
            reconnect_round: AtomicU64::new(0),
            churn_round: AtomicU64::new(0),
            resync: AtomicU64::new(0),
            latencies: Mutex::new(Latencies::default()),
            missed_events: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            churns: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            refused_codes: Mutex::new(BTreeMap::new()),
            refused_buckets: Mutex::new(BTreeMap::new()),
            received: AtomicU64::new(0),
            worker_errors: Mutex::new(Vec::new()),
        }
    }

    fn nanos(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn record(&self, class: fn(&mut Latencies) -> &mut Vec<u64>, nanos: u64) {
        if let Ok(mut latencies) = self.latencies.lock() {
            class(&mut latencies).push(nanos);
        }
    }

    fn note_error(&self, text: String) {
        if let Ok(mut errors) = self.worker_errors.lock()
            && errors.len() < 256
        {
            errors.push(text);
        }
    }
}

/// One client's place in the load: its nickname, its direct-message peer,
/// the edge that admits it, the load channel it joins, and the generator
/// source address it connects from.
struct WorkerPlan {
    index: usize,
    nick: String,
    peer: String,
    edge: usize,
    load_channel: String,
    source: Ipv4Addr,
    slot_index: u64,
}

/// A worker's live session: the client plus the sequence bookkeeping.
struct Session {
    client: IrcClient,
    partial: String,
    expected: BTreeMap<String, u64>,
    sequence: u64,
    /// Set when the server refused the last channel message; the next
    /// periodic send repeats that sequence instead of advancing.
    resend: bool,
    /// When the last `JOIN #load` was sent; its 366 terminator closes the
    /// paged directory snapshot the coordinator serves (spec FED-13).
    join_sent: Option<u64>,
    next_channel: Instant,
    next_direct: Instant,
    next_topic: Instant,
}

impl Session {
    fn open(fixture: &NodeFixture, plan: &WorkerPlan, shared: &Shared) -> TestResult<Self> {
        let started = Instant::now();
        let mut client = register_worker(fixture, &plan.nick, plan.source)?;
        shared.record(
            |latencies| &mut latencies.admission,
            u64::try_from(started.elapsed().as_nanos())?,
        );
        let join_sent = shared.nanos();
        let load = &plan.load_channel;
        client.send(&format!("JOIN {load}"))?;
        client.read_until(|line| line.contains(&format!(" 366 {} {load} ", plan.nick)))?;
        shared.record(
            |latencies| &mut latencies.snapshot,
            shared.nanos().saturating_sub(join_sent),
        );
        let own = own_channel(plan.index);
        client.send(&format!("JOIN {own}"))?;
        client.read_until(|line| line.contains(&format!(" 366 {} {own} ", plan.nick)))?;
        client
            .reader
            .get_mut()
            .sock
            .set_read_timeout(Some(READ_SLICE))?;
        let now = Instant::now();
        Ok(Self {
            client,
            partial: String::new(),
            expected: BTreeMap::new(),
            sequence: 0,
            resend: false,
            join_sent: None,
            next_channel: now,
            next_direct: now + DIRECT_MESSAGE_PERIOD / 2,
            next_topic: now + TOPIC_PERIOD / 3,
        })
    }

    /// Reads at most one complete line, keeping a partial line across timeouts.
    fn next_line(&mut self) -> TestResult<Option<String>> {
        match self.client.reader.read_line(&mut self.partial) {
            Ok(0) => Err(failure("transport closed")),
            Ok(_) if self.partial.ends_with('\n') => {
                let line = self.partial.trim_end_matches(['\r', '\n']).to_owned();
                self.partial.clear();
                Ok(Some(line))
            }
            Ok(_) => Ok(None),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn send_periodic(&mut self, plan: &WorkerPlan, shared: &Shared) -> TestResult {
        let now = Instant::now();
        if now >= self.next_channel {
            self.next_channel = now + CHANNEL_MESSAGE_PERIOD;
            if self.resend {
                self.resend = false;
            } else {
                self.sequence = self.sequence.wrapping_add(1);
            }
            self.client.send(&format!(
                "PRIVMSG {} :seq={} t={}",
                plan.load_channel,
                self.sequence,
                shared.nanos()
            ))?;
            shared.sent.fetch_add(1, Ordering::Relaxed);
        }
        if now >= self.next_direct {
            self.next_direct = now + DIRECT_MESSAGE_PERIOD;
            self.client
                .send(&format!("PRIVMSG {} :dm t={}", plan.peer, shared.nanos()))?;
        }
        if now >= self.next_topic {
            self.next_topic = now + TOPIC_PERIOD;
            self.client.send(&format!(
                "TOPIC {} :topic t={}",
                own_channel(plan.index),
                shared.nanos()
            ))?;
        }
        Ok(())
    }

    /// Classifies one server line into a latency sample or a sequence check.
    fn observe(&mut self, line: &str, plan: &WorkerPlan, shared: &Shared) -> TestResult {
        let now = shared.nanos();
        if line.starts_with("PING") {
            let token = line.split_once(' ').map_or("", |(_, rest)| rest);
            self.client.send(&format!("PONG {token}"))?;
            return Ok(());
        }
        if line.contains(" 366 ") && line.contains(&plan.load_channel) {
            if let Some(sent) = self.join_sent.take() {
                shared.record(
                    |latencies| &mut latencies.snapshot,
                    now.saturating_sub(sent),
                );
                // Messages committed between the PART and this JOIN were
                // never owed to the session; expectations restart here.
                self.expected.clear();
            }
            return Ok(());
        }
        let Some((prefix, rest)) = line.strip_prefix(':').and_then(|line| line.split_once(' '))
        else {
            return Ok(());
        };
        let sender = prefix.split('!').next().unwrap_or_default().to_owned();
        if let Some(text) = rest.strip_prefix(&format!("PRIVMSG {} :seq=", plan.load_channel)) {
            let (sequence, stamp) = text.split_once(" t=").unwrap_or(("", ""));
            let sequence: u64 = sequence.parse()?;
            let stamp: u64 = stamp.parse()?;
            shared.received.fetch_add(1, Ordering::Relaxed);
            shared.record(|latencies| &mut latencies.fanout, now.saturating_sub(stamp));
            self.check_sequence(plan, &sender, sequence, shared);
        } else if let Some(stamp) = rest.strip_prefix(&format!("PRIVMSG {} :dm t=", plan.nick)) {
            let stamp: u64 = stamp.parse()?;
            shared.record(
                |latencies| &mut latencies.message,
                now.saturating_sub(stamp),
            );
        } else if sender == plan.nick
            && let Some(stamp) =
                rest.strip_prefix(&format!("TOPIC {} :topic t=", own_channel(plan.index)))
        {
            let stamp: u64 = stamp.parse()?;
            shared.record(
                |latencies| &mut latencies.durable_mutation,
                now.saturating_sub(stamp),
            );
        } else if let Some(code) = rest.strip_prefix("FAIL PRIVMSG ") {
            // A side-effect-free refusal (spec 28.7): retry the same sequence.
            shared.refused.fetch_add(1, Ordering::Relaxed);
            let code = code.split(' ').next().unwrap_or_default();
            if let Ok(mut codes) = shared.refused_codes.lock()
                && (codes.contains_key(code) || codes.len() < 16)
            {
                *codes.entry(code.to_owned()).or_insert(0) += 1;
            }
            if let Ok(mut buckets) = shared.refused_buckets.lock() {
                let bucket = shared.epoch.elapsed().as_secs() / 10 * 10;
                *buckets.entry(bucket).or_insert(0) += 1;
            }
            self.resend = true;
            if shared.refused.load(Ordering::Relaxed) <= 8 {
                shared.note_error(format!(
                    "refused at {:.1}s: {} {rest}",
                    shared.epoch.elapsed().as_secs_f64(),
                    plan.nick
                ));
            }
        } else if rest.starts_with("FAIL ") && rest.contains("NETWORK_UNAVAILABLE") {
            self.expected.clear();
        }
        Ok(())
    }

    /// A gap in a sender's sequence outside maintenance is a missed event.
    /// A sequence that restarts means the sender reconnected.
    fn check_sequence(&mut self, plan: &WorkerPlan, sender: &str, sequence: u64, shared: &Shared) {
        let expected = self.expected.entry(sender.to_owned()).or_insert(sequence);
        let rejoining = self.join_sent.is_some();
        if sequence > *expected && !rejoining && !shared.maintenance.load(Ordering::Relaxed) {
            let gap = sequence - *expected;
            shared.missed_events.fetch_add(gap, Ordering::Relaxed);
            shared.note_error(format!(
                "missed at {:.1}s: observer={} edge={} sender={sender} expected={expected} got={sequence} gap={gap}",
                shared.epoch.elapsed().as_secs_f64(),
                plan.nick,
                plan.edge
            ));
        }
        *expected = sequence.wrapping_add(1);
    }
}

/// Registers a load worker with `standard-replies` enabled, so a refused
/// channel message reaches the worker as `FAIL PRIVMSG` instead of a legacy
/// numeric it would not recognize, retrying transient failures like
/// `register_when_available`.
fn register_worker(
    fixture: &NodeFixture,
    nickname: &str,
    source: Ipv4Addr,
) -> TestResult<IrcClient> {
    let deadline = Instant::now() + NETWORK_WAIT;
    loop {
        let attempt = (|| -> TestResult<Option<IrcClient>> {
            let mut client = IrcClient::connect_from(fixture, Some(source))?;
            client.send("CAP LS 302")?;
            client.read_until(|line| {
                line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :")
            })?;
            client.send("CAP REQ :standard-replies")?;
            client.read_until(|line| line.contains(" CAP * ACK "))?;
            client.send("CAP END")?;
            match client.try_register(nickname)? {
                Registration::Welcome(lines) => {
                    if !lines
                        .iter()
                        .any(|line| line.contains(&format!(" 001 {nickname} ")))
                    {
                        return Err(failure(format!("registration lacked 001: {lines:?}")));
                    }
                    Ok(Some(client))
                }
                Registration::Unavailable(_) => Ok(None),
            }
        })();
        match attempt {
            Ok(Some(client)) => return Ok(client),
            Ok(None) | Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_secs(1));
            }
            Ok(None) => return Err(failure("registration stayed unavailable")),
            Err(error) => return Err(error),
        }
    }
}

/// The SASL carrier's own report that an edge's account authority could not
/// answer. RUN-09 (#152) added it ahead of the `904` that a refused credential
/// and an unreachable authority used to share, and every session this module
/// authenticates negotiates `standard-replies`, so it is the first line a
/// failed exchange here reports.
pub(super) const AUTHORITY_UNAVAILABLE: &str = "FAIL AUTHENTICATE UNAVAILABLE";

/// Whether an error is a transient transport failure a node restart can
/// cause: a refused connection, a handshake or read cut short, a broken pipe,
/// or an account authority that named itself unavailable. A `904` the carrier
/// did not precede with that line is a refused credential, and authentication
/// and protocol failures are still not transient.
pub(super) fn transient_transport(error: &TestError) -> bool {
    let text = error.to_string();
    if text.contains(AUTHORITY_UNAVAILABLE) {
        return true;
    }
    if text.contains(" 904 ") {
        return false;
    }
    text.contains("os error 11")
        || [
            "UnexpectedEof",
            "unexpected end of file",
            "Broken pipe",
            "broken pipe",
            "Connection reset",
            "connection reset",
            "Connection refused",
            "connection refused",
            "transport closed",
            "did not start",
            "NETWORK_UNAVAILABLE",
        ]
        .iter()
        .any(|needle| text.contains(needle))
}

#[test]
fn an_authentication_refusal_is_not_a_transient_transport_failure() {
    for detail in [
        "SASL response framing was invalid: :server.test 904 user :Authentication failed",
        "SASL response framing was invalid: :server.test 904 user :Connection reset",
        "authentication returned the wrong challenge",
        "successful authentication omitted numeric 903",
        "InvalidLogin",
    ] {
        assert!(!transient_transport(&failure(detail)), "{detail}");
    }
    assert!(transient_transport(&failure(
        "Connection refused (os error 111)"
    )));
    assert!(transient_transport(&failure(
        "SASL response ended: transport closed"
    )));
    // RUN-09 (#152): the carrier now names the transient authority itself, so
    // the pair it sends is transient while a bare 904 stays a refusal.
    assert!(transient_transport(&failure(concat!(
        "SASL response framing was invalid: :edge-a.test ",
        "FAIL AUTHENTICATE UNAVAILABLE :Account authority unavailable"
    ))));
}

fn own_channel(index: usize) -> String {
    format!("#own{index:04}")
}

/// Runs one worker until the campaign stops, reconnecting after any loss.
fn worker(shared: &Shared, fixtures: [&NodeFixture; 2], plan: &WorkerPlan) {
    let mut seen_reconnect = 0;
    let mut seen_churn = 0;
    let Some(fixture) = fixtures.get(plan.edge % 2).copied() else {
        return;
    };
    let slot = RESUME_SLOT * u32::try_from(plan.slot_index).unwrap_or(0);
    // The population connects in index order at the paced rate, as it does
    // after every maintenance window.
    thread::sleep(slot);
    while !shared.stop.load(Ordering::Relaxed) {
        // Idle through an operator maintenance window so a node restart is not
        // buried under a client reconnection storm, the way a real client
        // backs off during announced maintenance.
        if shared.maintenance.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(250));
            // Resume in index order rather than all at once, as a client
            // population returning from announced maintenance does.
            thread::sleep(slot);
            continue;
        }
        let mut session = match Session::open(fixture, plan, shared) {
            Ok(session) => session,
            Err(error) => {
                shared.note_error(format!("{} connect: {error}", plan.nick));
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let outcome = run_session(
            &mut session,
            shared,
            plan,
            &mut seen_reconnect,
            &mut seen_churn,
        );
        if let Err(error) = outcome {
            shared.note_error(format!("{} session: {error}", plan.nick));
        }
        if shared.stop.load(Ordering::Relaxed) {
            let _ = session.client.send("QUIT :campaign complete");
            break;
        }
        shared.reconnects.fetch_add(1, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(500));
    }
}

/// One connected session: sends load, observes replies, and leaves on a
/// reconnect round it belongs to or on any transport error.
fn run_session(
    session: &mut Session,
    shared: &Shared,
    plan: &WorkerPlan,
    seen_reconnect: &mut u64,
    seen_churn: &mut u64,
) -> TestResult {
    let mut seen_resync = shared.resync.load(Ordering::Relaxed);
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let resync = shared.resync.load(Ordering::Relaxed);
        if resync != seen_resync {
            seen_resync = resync;
            session.expected.clear();
        }
        let reconnect = shared.reconnect_round.load(Ordering::Relaxed);
        if reconnect != *seen_reconnect {
            *seen_reconnect = reconnect;
            if (plan.index as u64 + reconnect).is_multiple_of(4) {
                session.client.send("QUIT :reconnect drill")?;
                return Ok(());
            }
        }
        if shared.maintenance.load(Ordering::Relaxed) {
            return Ok(());
        }
        let churn = shared.churn_round.load(Ordering::Relaxed);
        if churn != *seen_churn {
            *seen_churn = churn;
            if (plan.index as u64 + churn).is_multiple_of(3) {
                session
                    .client
                    .send(&format!("PART {} :churn", plan.load_channel))?;
                session.join_sent = Some(shared.nanos());
                session
                    .client
                    .send(&format!("JOIN {}", plan.load_channel))?;
                shared.churns.fetch_add(1, Ordering::Relaxed);
            }
        }
        if !shared.pause.load(Ordering::Relaxed) {
            session.send_periodic(plan, shared)?;
        }
        if let Some(line) = session.next_line()? {
            session.observe(&line, plan, shared)?;
        }
    }
}

/// Resource facts of one daemon: anonymous memory, kernel tasks, and the
/// inbound sockets it holds (established plus close-wait).
#[derive(Clone, Copy, Default)]
struct Resources {
    anonymous_bytes: u64,
    tasks: u64,
    sockets: u64,
    close_wait: u64,
}

/// Where memory and task counts come from.
enum ResourceSource {
    /// One cgroup v2 leaf per daemon under the delegated root the test owns.
    Cgroup { leaves: [PathBuf; 3] },
    /// `/proc/<pid>/status`, usable only where the hardened daemon is visible.
    Procfs,
}

impl ResourceSource {
    fn label(&self) -> &'static str {
        match self {
            Self::Cgroup { .. } => "cgroup",
            Self::Procfs => "procfs",
        }
    }

    fn leaf(&self, index: usize) -> Option<&Path> {
        match self {
            Self::Cgroup { leaves } => leaves.get(index).map(PathBuf::as_path),
            Self::Procfs => None,
        }
    }

    /// Uses the cgroup the test process starts in when that cgroup is
    /// delegated to this user, offers the memory and pids controllers, and
    /// holds no other process; otherwise falls back to procfs.
    fn detect() -> TestResult<Self> {
        let Some(root) = own_cgroup()? else {
            return Ok(Self::Procfs);
        };
        let controllers = read_bounded(&root.join("cgroup.controllers"), MAX_CGROUP_FILE_BYTES)?;
        let members = read_bounded(&root.join("cgroup.procs"), MAX_CGROUP_FILE_BYTES)?;
        let own_pid = std::process::id().to_string();
        let alone = members.split_ascii_whitespace().all(|pid| pid == own_pid);
        if !has_controllers(&controllers) || !alone {
            return Ok(Self::Procfs);
        }
        let controller = root.join("controller");
        if fs::create_dir(&controller).is_err() {
            return Ok(Self::Procfs);
        }
        fs::write(controller.join("cgroup.procs"), &own_pid)?;
        fs::write(root.join("cgroup.subtree_control"), "+memory +pids")?;
        let leaves = [
            root.join("node-0"),
            root.join("node-1"),
            root.join("node-2"),
        ];
        for leaf in &leaves {
            fs::create_dir(leaf)?;
            let offered = read_bounded(&leaf.join("cgroup.controllers"), MAX_CGROUP_FILE_BYTES)?;
            if !has_controllers(&offered) {
                return Err(failure("cgroup leaf lacks the memory or pids controller"));
            }
        }
        Ok(Self::Cgroup { leaves })
    }

    fn remove_leaves(&self) {
        if let Self::Cgroup { leaves } = self {
            for leaf in leaves {
                let _cleanup = fs::remove_dir(leaf);
            }
        }
    }
}

fn has_controllers(list: &str) -> bool {
    let mut memory = false;
    let mut pids = false;
    for name in list.split_ascii_whitespace() {
        memory |= name == "memory";
        pids |= name == "pids";
    }
    memory && pids
}

/// The cgroup v2 directory of this process, when it is owned by this user.
fn own_cgroup() -> TestResult<Option<PathBuf>> {
    let text = read_bounded(Path::new("/proc/self/cgroup"), MAX_CGROUP_FILE_BYTES)?;
    let Some(relative) = text.lines().find_map(|line| line.strip_prefix("0::")) else {
        return Ok(None);
    };
    let root = PathBuf::from(format!("{CGROUP_MOUNT}{relative}"));
    let Ok(metadata) = fs::metadata(&root) else {
        return Ok(None);
    };
    let owned = metadata.is_dir() && metadata.uid() == rustix::process::getuid().as_raw();
    Ok(owned.then_some(root))
}

fn read_bounded(path: &Path, limit: u64) -> TestResult<String> {
    let mut text = String::new();
    fs::File::open(path)?
        .take(limit)
        .read_to_string(&mut text)?;
    Ok(text)
}

/// Kernel TCP sockets grouped by local port: established and close-wait
/// rows are descriptors their owner holds; listen and time-wait rows are not.
struct SocketTable {
    held: BTreeMap<u16, (u64, u64)>,
}

impl SocketTable {
    fn read() -> TestResult<Self> {
        let text = read_bounded(Path::new("/proc/net/tcp"), MAX_SOCKET_TABLE_BYTES)?;
        let mut held = BTreeMap::new();
        for line in text.lines().skip(1) {
            let mut fields = line.split_ascii_whitespace();
            let (Some(local), Some(_remote), Some(state)) =
                (fields.nth(1), fields.next(), fields.next())
            else {
                continue;
            };
            let Some(port) = local
                .rsplit_once(':')
                .and_then(|(_, hex)| u16::from_str_radix(hex, 16).ok())
            else {
                continue;
            };
            let entry = held.entry(port).or_insert((0, 0));
            if state == TCP_ESTABLISHED {
                entry.0 += 1;
            } else if state == TCP_CLOSE_WAIT {
                entry.1 += 1;
            }
        }
        Ok(Self { held })
    }

    /// (established, close-wait) across the node's listener ports.
    fn inbound(&self, ports: &[u16]) -> (u64, u64) {
        ports.iter().fold((0, 0), |sum, port| {
            let (established, close_wait) = self.held.get(port).copied().unwrap_or((0, 0));
            (sum.0 + established, sum.1 + close_wait)
        })
    }
}

fn resources(source: &ResourceSource, index: usize, pid: u32) -> TestResult<Resources> {
    match source.leaf(index) {
        Some(leaf) => cgroup_resources(leaf)
            .map_err(|error| failure(format!("cgroup sample of node {index}: {error}"))),
        None => procfs_resources(pid).map_err(|error| {
            failure(format!(
                "procfs sample of pid {pid}: {error}; the hardened daemon is invisible to \
unprivileged observers on hosts that hide /proc entries, run the campaign alone inside a \
delegated cgroup (systemd-run --user --scope -p Delegate=yes)"
            ))
        }),
    }
}

fn cgroup_resources(leaf: &Path) -> TestResult<Resources> {
    let stat = read_bounded(&leaf.join("memory.stat"), MAX_CGROUP_FILE_BYTES)?;
    let anonymous_bytes = stat
        .lines()
        .find_map(|line| line.strip_prefix("anon "))
        .ok_or_else(|| failure("memory.stat lacks the anon line"))?
        .trim()
        .parse()?;
    let tasks = read_bounded(&leaf.join("pids.current"), MAX_CGROUP_FILE_BYTES)?
        .trim()
        .parse()?;
    Ok(Resources {
        anonymous_bytes,
        tasks,
        ..Resources::default()
    })
}

fn procfs_resources(pid: u32) -> TestResult<Resources> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let mut resources = Resources::default();
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("RssAnon:") {
            let kib: u64 = value.trim().trim_end_matches("kB").trim().parse()?;
            resources.anonymous_bytes = kib
                .checked_mul(1_024)
                .ok_or_else(|| failure("rss overflow"))?;
        } else if let Some(value) = line.strip_prefix("Threads:") {
            resources.tasks = value.trim().parse()?;
        }
    }
    Ok(resources)
}

/// The three daemons, where their resource counts come from, and the
/// listener ports that identify their inbound sockets.
struct Nodes {
    coordinator: DaemonProcess,
    edge_a: DaemonProcess,
    edge_b: DaemonProcess,
    source: ResourceSource,
    ports: [Vec<u16>; 3],
    federation_port: u16,
    /// Per-node stderr logs under `<campaign>/logs`, appended across restarts.
    stderr_logs: [PathBuf; 3],
}

impl Nodes {
    fn start(network: &Network, source: ResourceSource, directory: &Path) -> TestResult<Self> {
        let logs = directory.join("logs");
        fs::create_dir_all(&logs)?;
        let stderr_logs = [
            logs.join("coordinator.stderr"),
            logs.join("edge-a.stderr"),
            logs.join("edge-b.stderr"),
        ];
        let federation_port = network
            .coordinator
            .federation_listener
            .ok_or_else(|| failure("coordinator has no federation listener"))?
            .port();
        let ports = [
            vec![network.coordinator.public_address.port(), federation_port],
            vec![network.edge_a.public_address.port()],
            vec![network.edge_b.public_address.port()],
        ];
        Ok(Self {
            coordinator: DaemonProcess::start_logged(
                &network.coordinator.config_path,
                source.leaf(0),
                Some(&stderr_logs[0]),
            )?,
            edge_a: DaemonProcess::start_logged(
                &network.edge_a.config_path,
                source.leaf(1),
                Some(&stderr_logs[1]),
            )?,
            edge_b: DaemonProcess::start_logged(
                &network.edge_b.config_path,
                source.leaf(2),
                Some(&stderr_logs[2]),
            )?,
            source,
            ports,
            federation_port,
            stderr_logs,
        })
    }

    fn restart_coordinator(&mut self, config_path: &Path) -> TestResult {
        self.coordinator = DaemonProcess::start_logged(
            config_path,
            self.source.leaf(0),
            Some(&self.stderr_logs[0]),
        )?;
        Ok(())
    }

    fn restart_edge_b(&mut self, config_path: &Path) -> TestResult {
        self.edge_b = DaemonProcess::start_logged(
            config_path,
            self.source.leaf(2),
            Some(&self.stderr_logs[2]),
        )?;
        Ok(())
    }

    fn pids(&self) -> TestResult<[u32; 3]> {
        Ok([
            pid(&self.coordinator)?,
            pid(&self.edge_a)?,
            pid(&self.edge_b)?,
        ])
    }

    fn resources(&self) -> TestResult<([Resources; 3], u64)> {
        let pids = self.pids()?;
        let table = SocketTable::read()?;
        let mut all = [Resources::default(); 3];
        for (index, slot) in all.iter_mut().enumerate() {
            let (Some(pid), Some(ports)) = (pids.get(index), self.ports.get(index)) else {
                return Err(failure("node index out of range"));
            };
            let mut resources = resources(&self.source, index, *pid)?;
            let (established, close_wait) = table.inbound(ports);
            resources.sockets = established + close_wait;
            resources.close_wait = close_wait;
            *slot = resources;
        }
        let (federation_links, _) = table.inbound(&[self.federation_port]);
        Ok((all, federation_links))
    }
}

fn pid(daemon: &DaemonProcess) -> TestResult<u32> {
    daemon
        .child
        .as_ref()
        .map(Child::id)
        .ok_or_else(|| failure("daemon is not running"))
}

pub(super) fn admin_identity(fixture: &NodeFixture) -> AdminIdentity {
    AdminIdentity {
        socket: fixture.admin_socket.clone(),
        network_id: NETWORK_ID,
        server_id: fixture.server_id,
        operator_id: fixture.operator_id,
        // The fixture derives every node key from its seed (seed plus 12 is
        // the operator signing key).
        operator_key: Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(12); 32]),
    }
}

/// One ten-second sample across the three nodes. Occupancy, charged bytes,
/// and the configured budget are per node: an aggregate hides which daemon
/// actually held the population and against which budget (spec 28.7).
struct Sample {
    at_ns: u64,
    resources: [Resources; 3],
    federation_links: u64,
    client_queued_bytes: u64,
    federation_queued_bytes: u64,
    storage_jobs_in_flight: u64,
    live_client_connections: [u64; 3],
    memory_charged_bytes: [u64; 3],
    memory_budget_bytes: [u64; 3],
}

impl Sample {
    /// Clients admitted across the three nodes at this instant.
    fn total_live(&self) -> u64 {
        self.live_client_connections.iter().copied().sum()
    }

    /// The smallest population any client-admitting edge held. Node 0 is the
    /// coordinator, which admits no campaign client, so only the two edges
    /// count towards the per-node occupancy requirement.
    fn edge_minimum_live(&self) -> u64 {
        self.live_client_connections
            .iter()
            .skip(1)
            .copied()
            .min()
            .unwrap_or(0)
    }
}

/// Records one node's `RUNTIME` and `QUEUES` counters into the sample.
fn record_node_stats(
    sample: &mut Sample,
    admin: &mut AdminSession<'_>,
    index: usize,
) -> TestResult<()> {
    for (name, value) in admin.stats("QUEUES")? {
        match name.as_str() {
            "client_queued_bytes" => {
                sample.client_queued_bytes = sample.client_queued_bytes.max(value);
            }
            "federation_queued_bytes" => {
                sample.federation_queued_bytes = sample.federation_queued_bytes.max(value);
            }
            "storage_jobs_in_flight" => {
                sample.storage_jobs_in_flight = sample.storage_jobs_in_flight.max(value);
            }
            _ => {}
        }
    }
    for (name, value) in admin.stats("RUNTIME")? {
        let slot = match name.as_str() {
            "live_client_connections" => sample.live_client_connections.get_mut(index),
            "memory_charged_bytes" => sample.memory_charged_bytes.get_mut(index),
            "memory_budget_bytes" => sample.memory_budget_bytes.get_mut(index),
            _ => None,
        };
        if let Some(slot) = slot {
            *slot = value;
        }
    }
    Ok(())
}

fn take_sample(shared: &Shared, nodes: &Nodes, admins: &[AdminIdentity; 3]) -> TestResult<Sample> {
    let (resources, federation_links) = nodes.resources()?;
    let mut sample = Sample {
        at_ns: shared.nanos(),
        resources,
        federation_links,
        client_queued_bytes: 0,
        federation_queued_bytes: 0,
        storage_jobs_in_flight: 0,
        live_client_connections: [0; 3],
        memory_charged_bytes: [0; 3],
        memory_budget_bytes: [0; 3],
    };
    for (index, identity) in admins.iter().enumerate() {
        let mut admin = AdminSession::connect(identity)
            .map_err(|error| failure(format!("admin session to node {index}: {error}")))?;
        record_node_stats(&mut sample, &mut admin, index)?;
        admin.quit()?;
    }
    Ok(sample)
}

/// Whether a quiescent sample sits inside the warm baseline envelope.
fn within_envelope(baseline: &[Resources; 3], sample: &[Resources; 3]) -> bool {
    baseline.iter().zip(sample).all(|(base, now)| {
        now.anonymous_bytes <= base.anonymous_bytes.saturating_mul(3) / 2 + MEMORY_HEADROOM_BYTES
            && now.sockets <= base.sockets + SOCKET_HEADROOM
            && now.tasks <= base.tasks + TASK_HEADROOM
    })
}

/// A fallocated file that brings free space under the campaign reserve.
struct Ballast(PathBuf);

impl Ballast {
    fn create(path: &Path, bytes: u64) -> TestResult<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let ballast = Self(path.to_path_buf());
        fallocate(&file, FallocateFlags::empty(), 0, bytes)?;
        file.sync_all()?;
        Ok(ballast)
    }
}

impl Drop for Ballast {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn available_bytes(path: &Path) -> TestResult<u64> {
    let statistics = rustix::fs::statvfs(path)?;
    Ok(statistics.f_bavail.saturating_mul(statistics.f_frsize))
}

/// The fixed reserve every campaign node runs under: as close to the free
/// space as the engine allows, so a bounded ballast can cross `R(F) + G`.
fn campaign_reserve(available: u64) -> u64 {
    available
        .saturating_sub(RESERVE_CLEARANCE_BYTES)
        .clamp(MIN_FIXED_RESERVE_BYTES, MAX_FIXED_RESERVE_BYTES)
}

fn set_reserve(fixture: &NodeFixture, reserve: u64) -> TestResult {
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        &format!("disk_reserve_bytes = {DISK_RESERVE_BYTES}\ndisk_reserve_percent = 1"),
        &format!("disk_reserve_bytes = {reserve}\ndisk_reserve_percent = 1"),
    )?;
    fs::write(&fixture.config_path, config)?;
    Ok(())
}

/// The outcome of one attempted durable mutation under storage conditions.
#[derive(Debug)]
enum DurableOutcome {
    Admitted,
    Refused(String),
}

/// Scenario counters and the hardware description the report carries.
#[derive(Default)]
struct Scenarios {
    reconnect: u64,
    churn: u64,
    rekey: u64,
    index_transition: u64,
    snapshot: u64,
    backup: u64,
    disk_pressure: u64,
    peer_loss: u64,
}

struct Campaign<'a> {
    settings: &'a Settings,
    network: &'a Network,
    shared: &'a Shared,
    admins: [AdminIdentity; 3],
    nodes: Nodes,
    account: AccountId,
    requests: u128,
    scenarios: Scenarios,
    samples: Vec<Sample>,
    envelope_violations: u64,
    /// Quiescence checks at which fewer clients were connected than the
    /// campaign configured: a population that did not return.
    population_shortfalls: u64,
    /// Samples skipped after a retried STATS failure.
    sample_failures: u64,
    baseline: [Resources; 3],
    backup_path: Option<PathBuf>,
    /// Backups written so far; each gets a distinct creation time and id.
    backup_sequence: u64,
    reserve: u64,
    log: Vec<String>,
}

impl Campaign<'_> {
    fn note(&mut self, text: impl Into<String>) {
        let text = text.into();
        println!(
            "[{:>7.1}s] {text}",
            self.shared.epoch.elapsed().as_secs_f64()
        );
        self.log.push(format!("{}|{text}", self.shared.nanos()));
    }

    fn fresh_requests(&mut self) -> [RequestId; 2] {
        self.requests += 2;
        let first = self.requests.to_be_bytes();
        let second = (self.requests + 1).to_be_bytes();
        [RequestId::from_bytes(first), RequestId::from_bytes(second)]
    }

    fn sample(&mut self) -> TestResult {
        // A node that is busy recovering may answer STATS late; one sample
        // is retried, then skipped and counted rather than ending the
        // campaign, which keeps the evidence of the scenario that caused it.
        let sample = match take_sample(self.shared, &self.nodes, &self.admins) {
            Ok(sample) => sample,
            Err(first) => {
                thread::sleep(Duration::from_secs(1));
                match take_sample(self.shared, &self.nodes, &self.admins) {
                    Ok(sample) => sample,
                    Err(second) => {
                        self.sample_failures += 1;
                        self.note(format!("sample skipped: {first}; retry: {second}"));
                        return Ok(());
                    }
                }
            }
        };
        let mut violations = Vec::new();
        for (index, (resources, base)) in sample.resources.iter().zip(self.baseline).enumerate() {
            if resources.anonymous_bytes
                > base.anonymous_bytes.saturating_mul(3) + MEMORY_HEADROOM_BYTES
            {
                violations.push(format!(
                    "envelope violation: node {index} anonymous memory {}",
                    resources.anonymous_bytes
                ));
            }
        }
        for violation in violations {
            self.envelope_violations += 1;
            self.note(violation);
        }
        self.samples.push(sample);
        Ok(())
    }

    /// Waits for fresh links and complete base synchronization before the
    /// first account request. Transport establishment alone is insufficient.
    fn wait_relinks(&self, before_a: usize, before_b: usize) -> TestResult {
        wait_for_link(&self.network.edge_a, before_a)?;
        wait_for_link(&self.network.edge_b, before_b)?;
        let deadline = Instant::now() + POST_RESTART_READY_WAIT;
        while Instant::now() < deadline {
            let mut ready = true;
            for identity in self.admins.iter().skip(1) {
                let active = AdminSession::connect(identity)?
                    .stats("FEDERATION")?
                    .into_iter()
                    .find(|(name, _)| name == "active_peers")
                    .ok_or_else(|| failure("federation readiness counter missing"))?
                    .1;
                ready &= active == 1;
            }
            if ready {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(failure(
            "edges did not finish synchronization after coordinator restart",
        ))
    }

    fn settle(&mut self, seconds: u64) -> TestResult {
        // Clear stale per-sender expectations left by the scenario that just
        // ran, so a sequence gap counts only when it happens in this settled
        // window under steady load.
        self.shared.resync.fetch_add(1, Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            thread::sleep(SAMPLE_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
            self.sample()?;
        }
        Ok(())
    }

    fn scenario_reconnect(&mut self) -> TestResult {
        self.shared.reconnect_round.fetch_add(1, Ordering::Relaxed);
        self.note("reconnect round");
        self.settle(SCENARIO_SETTLE.as_secs())?;
        self.scenarios.reconnect += 1;
        Ok(())
    }

    fn scenario_churn(&mut self) -> TestResult {
        self.shared.churn_round.fetch_add(1, Ordering::Relaxed);
        self.note("churn round");
        self.settle(SCENARIO_SETTLE.as_secs())?;
        self.scenarios.churn += 1;
        Ok(())
    }

    /// The snapshot class: a fresh member joins the first load channel and
    /// the paged NAMES snapshot the coordinator serves through the edge
    /// closes with 366. Explicit directory queries at an edge are recorded as
    /// observed: the edge currently refuses them (finding CAP-1), so the
    /// reply numeric is logged rather than assumed.
    fn scenario_snapshot(&mut self) -> TestResult {
        let started = self.shared.nanos();
        let load = self.settings.workload.load_channel(0)?;
        let mut client = register_when_available(&self.network.edge_a, "snapshot-probe")?;
        let sent = self.shared.nanos();
        client.send(&format!("JOIN {load}"))?;
        let joined = client.read_until_within(BUSY_TRANSCRIPT_LINES, |line| {
            line.contains(&format!(" 366 snapshot-probe {load} "))
        })?;
        self.shared.record(
            |latencies| &mut latencies.snapshot,
            self.shared.nanos().saturating_sub(sent),
        );
        let pages = joined.iter().filter(|line| line.contains(" 353 ")).count();
        let mut observed = Vec::new();
        for query in [format!("NAMES {load}"), format!("WHO {load}")] {
            client.send(&query)?;
            let reply = client.read_until_within(BUSY_TRANSCRIPT_LINES, |line| {
                line.contains(" snapshot-probe ")
                    && [" 315 ", " 366 ", " 481 ", " 482 "]
                        .iter()
                        .any(|numeric| line.contains(numeric))
            })?;
            let numeric = reply
                .last()
                .and_then(|line| line.split_ascii_whitespace().nth(1))
                .unwrap_or("none")
                .to_owned();
            let expected = if query.starts_with("NAMES ") {
                "366"
            } else {
                "315"
            };
            if numeric != expected {
                return Err(failure(format!(
                    "explicit directory query {query} returned {numeric}: {reply:?}"
                )));
            }
            observed.push(format!("{query} -> {numeric}"));
        }
        client.send("QUIT :snapshot complete")?;
        self.note(format!(
            "snapshot: join pages={pages} in {} ms; explicit edge queries: {}",
            (self.shared.nanos() - started) / 1_000_000,
            observed.join(", ")
        ));
        self.scenarios.snapshot += 1;
        Ok(())
    }

    /// Authenticates the campaign account on a fresh connection. Transport
    /// loss may be retried within the network bound; an explicit SASL
    /// failure is always a failed authentication probe.
    fn opaque_login(&mut self, fixture_index: usize) -> TestResult<IrcClient> {
        let deadline = Instant::now() + NETWORK_WAIT;
        loop {
            match self.opaque_login_once(fixture_index) {
                Ok(client) => return Ok(client),
                Err(error) if Instant::now() < deadline && transient_transport(&error) => {
                    thread::sleep(Duration::from_secs(1));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn opaque_login_once(&mut self, fixture_index: usize) -> TestResult<IrcClient> {
        let fixture = match fixture_index {
            0 => &self.network.edge_a,
            _ => &self.network.edge_b,
        };
        let requests = self.fresh_requests();
        let started = self.shared.nanos();
        let mut client = IrcClient::connect(fixture)?;
        client.send("CAP LS 302")?;
        client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))?;
        client.send_until(&format!("CAP REQ :{E2EE_CAPS}"), " CAP * ACK ")?;
        authenticate_live_account_with(
            &mut client,
            fixture,
            CAMPAIGN_ACCOUNT_LOGIN,
            ACCOUNT_PASSWORD,
            requests,
            self.account,
        )?;
        client.send("CAP END")?;
        client.send("NICK campaign-account")?;
        client.send("USER campaign 0 * :Campaign Account")?;
        client.read_until(|line| line.contains(" 376 ") || line.contains(" 422 "))?;
        self.shared.record(
            |latencies| &mut latencies.opaque,
            self.shared.nanos() - started,
        );
        Ok(client)
    }

    fn scenario_opaque(&mut self) -> TestResult {
        let mut client = self.opaque_login(0)?;
        client.send("QUIT :opaque complete")?;
        self.note("opaque login");
        Ok(())
    }

    /// Attempts one durable JOIN on an existing registered session. A refusal
    /// must be an explicit FAIL; a lost transport fails the campaign.
    fn durable_join(
        client: &mut IrcClient,
        nick: &str,
        channel: &str,
    ) -> TestResult<DurableOutcome> {
        client.send(&format!("JOIN {channel}"))?;
        let lines = client.read_until_within(BUSY_TRANSCRIPT_LINES, |line| {
            line.contains(&format!(" 366 {nick} {channel} ")) || line.contains("FAIL JOIN")
        })?;
        match lines.iter().find(|line| line.contains("FAIL JOIN")) {
            Some(refusal) => Ok(DurableOutcome::Refused(refusal.clone())),
            None => Ok(DurableOutcome::Admitted),
        }
    }

    /// Requires registration to produce a welcome or an explicit bounded
    /// refusal under the current storage conditions.
    fn registration_probe(&mut self, label: &str) -> TestResult {
        let mut client = IrcClient::connect(&self.network.edge_a)?;
        client
            .reader
            .get_ref()
            .sock
            .set_read_timeout(Some(REGISTRATION_PROBE_WAIT))?;
        let outcome = match client.try_register(&format!("register-{label}"))? {
            Registration::Welcome(_) => "admitted".to_owned(),
            Registration::Unavailable(lines) => {
                let refusal = lines
                    .iter()
                    .find(|line| {
                        line.contains("FAIL ")
                            || line.contains("ERROR ")
                            || line.contains(" 263 ")
                    })
                    .ok_or_else(|| {
                        failure(format!(
                            "registration probe {label} closed without an explicit refusal: {lines:?}"
                        ))
                    })?;
                format!("refused: {refusal}")
            }
        };
        let _ = client.send("QUIT :registration probe");
        self.note(format!("registration probe {label}: {outcome}"));
        Ok(())
    }

    /// Requires the original refused session to recover durable service.
    fn await_durable_recovery(&mut self, client: &mut IrcClient, nick: &str) -> TestResult<bool> {
        let deadline = Instant::now() + PRESSURE_RECOVERY_WAIT;
        let mut attempt = 0_u32;
        while Instant::now() < deadline {
            attempt += 1;
            let outcome = Self::durable_join(client, nick, &format!("#recover-{attempt}"))?;
            if matches!(outcome, DurableOutcome::Admitted) {
                self.note(format!("durable recovery admitted on attempt {attempt}"));
                return Ok(true);
            }
            thread::sleep(Duration::from_secs(2));
        }
        Ok(false)
    }

    fn scenario_disk_pressure(&mut self) -> TestResult {
        let root = self.network.edge_a.data_dir.join("state");
        let available = available_bytes(&root)?;
        let ceiling = self.reserve + PHYSICAL_GROWTH_BYTES;
        if available <= ceiling {
            return Err(failure(
                "free space already sits under the campaign reserve",
            ));
        }
        let ballast_bytes = available - ceiling + PRESSURE_MARGIN_BYTES;
        self.note(format!(
            "disk pressure: ballast {ballast_bytes} bytes against reserve {}",
            self.reserve
        ));
        let mut probe = register_when_available(&self.network.edge_a, "pressure-probe")?;
        self.shared.maintenance.store(true, Ordering::Relaxed);
        let ballast = Ballast::create(
            &self.settings.directory.join("pressure-ballast"),
            ballast_bytes,
        )?;
        thread::sleep(Duration::from_secs(2));
        let under_pressure = Self::durable_join(&mut probe, "pressure-probe", "#pressure-on")?;
        let refused = match under_pressure {
            DurableOutcome::Admitted => None,
            DurableOutcome::Refused(reason) => Some(reason),
        };
        self.note(format!(
            "disk pressure durable mutation under pressure: {}",
            refused.as_deref().unwrap_or("admitted (unexpected)")
        ));
        self.registration_probe("on")?;
        thread::sleep(Duration::from_secs(3));
        probe.send("PING :pressure-session-survives")?;
        probe.read_until_within(BUSY_TRANSCRIPT_LINES, |line| {
            line.contains(" PONG ") && line.ends_with("pressure-session-survives")
        })?;
        drop(ballast);
        thread::sleep(Duration::from_secs(2));
        let recovered = self.await_durable_recovery(&mut probe, "pressure-probe")?;
        probe.send("QUIT :pressure probe complete")?;
        self.registration_probe("off")?;
        self.shared.maintenance.store(false, Ordering::Relaxed);
        self.note(format!(
            "disk pressure: refused={} recovered={recovered}",
            refused.is_some()
        ));
        if !(refused.is_some() && recovered) {
            return Err(failure("disk pressure transition was not observed"));
        }
        self.scenarios.disk_pressure += 1;
        Ok(())
    }

    fn stop_edge_b(&mut self) -> TestResult {
        self.shared.maintenance.store(true, Ordering::Relaxed);
        AdminSession::connect(&self.admins[2])?.confirm_process("DIE :campaign maintenance")?;
        let status = self.nodes.edge_b.wait()?;
        if !status.success() {
            return Err(failure(format!("edge b exited with {status}")));
        }
        Ok(())
    }

    fn start_edge_b(&mut self) -> TestResult {
        let before = links_established(&self.network.edge_b);
        self.nodes
            .restart_edge_b(&self.network.edge_b.config_path)?;
        wait_for_link(&self.network.edge_b, before)?;
        self.shared.maintenance.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Edge b's current storage keys. The rekey scenario rotates the master
    /// and rollback-guard keys and points the config at the new files, so a
    /// later backup must read them from the config; the login-index key is
    /// never rotated by the campaign and stays the fixture's seed-derived key.
    fn edge_b_keys(&self) -> TestResult<([u8; 32], [u8; 32], [u8; 32])> {
        let fixture = &self.network.edge_b;
        let read = |key: &str| -> TestResult<[u8; 32]> {
            let bytes = fs::read(current_key_file(fixture, key)?)?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| failure(format!("{key} is not a 32-byte key file")))
        };
        Ok((
            read("master_key_file")?,
            read("rollback_guard_key_file")?,
            [fixture.seed.wrapping_add(9); 32],
        ))
    }

    /// Writes a signed backup of the stopped edge b through the production
    /// storage owner and returns its path.
    fn write_backup(&mut self, name: &str) -> TestResult<PathBuf> {
        let fixture = &self.network.edge_b;
        self.backup_sequence += 1;
        let mut backup_id = [fixture.seed; 16];
        for (slot, byte) in backup_id
            .iter_mut()
            .skip(8)
            .zip(self.backup_sequence.to_be_bytes())
        {
            *slot = byte;
        }
        let (master, guard, login) = self.edge_b_keys()?;
        let state = current_state_dir(fixture)?;
        let backups = fixture.data_dir.join("backups");
        let limits = StorageEngineLimits {
            redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
            fixed_reserve_bytes: self.reserve,
            reserve_percent: 1,
            database_max_bytes: DATABASE_MAX_BYTES,
            backup_max_bytes: BACKUP_MAX_BYTES,
            integrity_checkpoint_manifests: 10_000,
        };
        let owner = StorageOwner::start(StorageOpenConfig {
            expected_network_id: NETWORK_ID,
            expected_server_id: fixture.server_id,
            state_directory: StateDirectory::open(&state, &embedded_storage_qualifications()?)?,
            storage_master_key: StorageMasterKey::from_bytes(master),
            rollback_guard_root_key: RollbackGuardRootKey::from_bytes(guard),
            login_index_key: LoginIndexKey::from_bytes(login),
            previous_login_index_key: None,
            limits,
        })?;
        let receipt = owner
            .port()
            .try_backup(
                BackupDestination::new(&backups, name)?,
                Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(10); 32]),
                1_700_000_000 + self.backup_sequence,
                backup_id,
            )?
            .wait()?;
        owner.shutdown()?;
        let path = backups.join(name);
        self.backup_path = Some(path.clone());
        self.note(format!(
            "backup {name}: {} bytes, {} rows",
            receipt.stream_bytes, receipt.record_count
        ));
        Ok(path)
    }

    /// Stops edge b, writes a signed backup, and restarts it.
    fn scenario_backup(&mut self) -> TestResult {
        self.stop_edge_b()?;
        let name = format!("campaign-{}.backup", self.scenarios.backup + 1);
        self.write_backup(&name)?;
        self.start_edge_b()?;
        self.scenarios.backup += 1;
        Ok(())
    }

    /// Rekeys edge b through the frozen binary's `storage restore` with a new
    /// master and guard key, re-pins its fresh recovery epoch on the
    /// coordinator, and restarts both.
    fn scenario_rekey(&mut self) -> TestResult {
        // The rekey restores the node's current state, so it takes its own
        // backup of the quiesced directory rather than reusing an older one.
        self.stop_edge_b()?;
        let backup = self.write_backup(&format!("rekey-{}.backup", self.scenarios.rekey + 1))?;
        let fixture = &self.network.edge_b;
        let generation = self.scenarios.rekey + 2;
        let keys = fixture.data_dir.join("keys");
        let old_master = current_key_file(fixture, "master_key_file")?;
        let old_guard = current_key_file(fixture, "rollback_guard_key_file")?;
        let new_master = keys.join(format!("storage-master-g{generation}.key"));
        let new_guard = keys.join(format!("rollback-guard-g{generation}.key"));
        let mut fresh = [[0_u8; 32]; 2];
        for key in &mut fresh {
            OsEntropy::fill(key)?;
        }
        write_private(&new_master, &fresh[0])?;
        write_private(&new_guard, &fresh[1])?;
        let output = fixture.data_dir.join(format!("state-g{generation}"));
        let restore = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
            .args(["storage", "restore", "--config"])
            .arg(&fixture.config_path)
            .arg("--backup")
            .arg(&backup)
            .arg("--source-master-key-file")
            .arg(&old_master)
            .arg("--source-rollback-guard-key-file")
            .arg(&old_guard)
            .arg("--output-state-directory")
            .arg(&output)
            .arg("--target-rollback-guard-key-file")
            .arg(&new_guard)
            .arg("--target-master-key-file")
            .arg(&new_master)
            .arg("--declare-recovery-epoch")
            .output()?;
        let stdout = String::from_utf8_lossy(&restore.stdout).into_owned();
        if !restore.status.success() {
            return Err(failure(format!(
                "storage restore failed: {}\n{stdout}",
                String::from_utf8_lossy(&restore.stderr)
            )));
        }
        let epoch = stdout
            .lines()
            .find_map(|line| line.strip_prefix("recovery epoch changed: "))
            .and_then(|line| line.split(" -> ").nth(1))
            .ok_or_else(|| failure("restore did not report the new recovery epoch"))?
            .trim()
            .to_owned();
        let mut config = fs::read_to_string(&fixture.config_path)?;
        replace_once(
            &mut config,
            &format!(
                "state_dir = \"{}\"",
                protected_path_text(&current_state_dir(fixture)?)?
            ),
            &format!("state_dir = \"{}\"", protected_path_text(&output)?),
        )?;
        replace_once(
            &mut config,
            &format!(
                "master_key_file = \"{}\"",
                protected_path_text(&old_master)?
            ),
            &format!(
                "master_key_file = \"{}\"",
                protected_path_text(&new_master)?
            ),
        )?;
        replace_once(
            &mut config,
            &format!(
                "rollback_guard_key_file = \"{}\"",
                protected_path_text(&old_guard)?
            ),
            &format!(
                "rollback_guard_key_file = \"{}\"",
                protected_path_text(&new_guard)?
            ),
        )?;
        fs::write(&fixture.config_path, config)?;
        repin_peer_epoch(&self.network.coordinator, fixture.server_id, &epoch)?;
        let before_a = links_established(&self.network.edge_a);
        let status = self.nodes.coordinator.stop()?;
        if !status.success() {
            return Err(failure(format!("coordinator exited with {status}")));
        }
        self.nodes
            .restart_coordinator(&self.network.coordinator.config_path)?;
        self.start_edge_b()?;
        wait_for_link(&self.network.edge_a, before_a)?;
        self.note(format!(
            "rekey: restored generation {generation} under epoch {epoch}"
        ));
        self.scenarios.rekey += 1;
        Ok(())
    }

    /// Rotates the stopped coordinator's login-index key, migrates the
    /// existing account through live authentication, and verifies the exact
    /// committed state before and after finishing the transition.
    fn scenario_index_transition(&mut self) -> TestResult {
        index_transition::run(self)
    }

    fn scenario_peer_loss(&mut self) -> TestResult {
        self.shared.maintenance.store(true, Ordering::Relaxed);
        self.nodes.edge_b.kill()?;
        self.note("peer loss: edge b killed");
        thread::sleep(Duration::from_secs(5));
        self.start_edge_b()?;
        self.note("peer loss: edge b back");
        self.scenarios.peer_loss += 1;
        Ok(())
    }

    /// Pauses the load, waits, samples, and reports whether every node sits
    /// inside its warm envelope.
    fn quiesce(&mut self) -> TestResult<bool> {
        self.shared.pause.store(true, Ordering::Relaxed);
        thread::sleep(QUIESCE_WINDOW);
        // The whole population must be back: a client that cannot register
        // again after a scenario is a loss the resource envelope cannot see.
        // It returns paced, so the check waits a bounded time for it.
        let expected = u64::try_from(self.settings.connections).unwrap_or(u64::MAX);
        let per_node = self.settings.workload.per_node_connections();
        let deadline = Instant::now() + POPULATION_WAIT;
        let mut sample = take_sample(self.shared, &self.nodes, &self.admins)?;
        while sample.total_live() != expected && Instant::now() < deadline {
            thread::sleep(Duration::from_secs(2));
            sample = take_sample(self.shared, &self.nodes, &self.admins)?;
        }
        let inside = within_envelope(&self.baseline, &sample.resources);
        let live = sample.total_live();
        // The aggregate alone never satisfies the per-node requirement: each
        // client-admitting edge must hold its own share simultaneously.
        let population = live == expected && sample.edge_minimum_live() >= per_node;
        self.note(format!(
            "quiescence: inside={inside} population={population} live={live}/{expected} per_node={:?}/{per_node} charged={:?} memory={:?} sockets={:?} tasks={:?} links={}",
            sample.live_client_connections,
            sample.memory_charged_bytes,
            sample.resources.map(|r| r.anonymous_bytes),
            sample.resources.map(|r| r.sockets),
            sample.resources.map(|r| r.tasks),
            sample.federation_links
        ));
        self.samples.push(sample);
        let mut counters = Vec::new();
        for (index, identity) in self.admins.iter().enumerate() {
            let mut admin = AdminSession::connect(identity)?;
            for selector in ["FEDERATION", "STORAGE"] {
                let fields: Vec<String> = admin
                    .stats(selector)?
                    .into_iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect();
                counters.push(format!("node {index} {selector}: {}", fields.join(" ")));
            }
        }
        for line in counters {
            self.note(line);
        }
        // A second federation sample after a short rest separates a slow
        // drain from a stalled one.
        thread::sleep(Duration::from_secs(3));
        let mut later = Vec::new();
        for (index, identity) in self.admins.iter().enumerate() {
            let mut admin = AdminSession::connect(identity)?;
            let fields: Vec<String> = admin
                .stats("FEDERATION")?
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            later.push(format!(
                "node {index} FEDERATION after 3 s: {}",
                fields.join(" ")
            ));
        }
        for line in later {
            self.note(line);
        }
        self.shared.pause.store(false, Ordering::Relaxed);
        if !inside {
            self.envelope_violations += 1;
        }
        if !population {
            self.population_shortfalls += 1;
        }
        Ok(inside && population)
    }

    fn cycle(&mut self, number: u64) -> TestResult {
        self.note(format!("cycle {number} start"));
        self.scenario_reconnect()?;
        self.scenario_churn()?;
        self.scenario_snapshot()?;
        self.scenario_opaque()?;
        self.scenario_disk_pressure()?;
        self.settle(SCENARIO_SETTLE.as_secs())?;
        self.scenario_backup()?;
        self.settle(SCENARIO_SETTLE.as_secs())?;
        self.scenario_peer_loss()?;
        self.settle(SCENARIO_SETTLE.as_secs())?;
        self.scenario_index_transition()?;
        self.settle(SCENARIO_SETTLE.as_secs())?;
        self.scenario_rekey()?;
        self.settle(SCENARIO_SETTLE.as_secs())?;
        self.quiesce()?;
        self.note(format!("cycle {number} end"));
        Ok(())
    }
}

pub(super) fn current_state_dir(fixture: &NodeFixture) -> TestResult<PathBuf> {
    Ok(PathBuf::from(current_config_value(fixture, "state_dir")?))
}

pub(super) fn current_key_file(fixture: &NodeFixture, key: &str) -> TestResult<PathBuf> {
    Ok(PathBuf::from(current_config_value(fixture, key)?))
}

pub(super) fn current_config_value(fixture: &NodeFixture, key: &str) -> TestResult<String> {
    let config = fs::read_to_string(&fixture.config_path)?;
    config
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key} = \"")))
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(|| failure(format!("configuration lacks {key}")))
}

/// Replaces the pinned recovery epoch of one peer entry in the coordinator config.
pub(super) fn repin_peer_epoch(
    coordinator: &NodeFixture,
    peer: ServerId,
    epoch: &str,
) -> TestResult {
    let config = fs::read_to_string(&coordinator.config_path)?;
    let marker = format!("server_id = \"{}\"\n", peer.to_base64url());
    let start = config
        .find(&marker)
        .ok_or_else(|| failure("coordinator config lacks the peer"))?;
    let epoch_start = config[start..]
        .find("recovery_epoch = \"")
        .map(|offset| start + offset)
        .ok_or_else(|| failure("peer entry lacks a recovery epoch"))?;
    let line_end = config[epoch_start..]
        .find('\n')
        .map_or(config.len(), |offset| epoch_start + offset);
    let mut updated = config.clone();
    updated.replace_range(
        epoch_start..line_end,
        &format!("recovery_epoch = \"{epoch}\""),
    );
    fs::write(&coordinator.config_path, updated)?;
    Ok(())
}

pub(super) fn hardware() -> TestResult<String> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
    let model = cpuinfo
        .lines()
        .find_map(|line| line.strip_prefix("model name"))
        .map(|rest| rest.trim_start_matches([' ', ':']).trim().to_owned())
        .unwrap_or_else(|| "unknown cpu".to_owned());
    let cores = thread::available_parallelism().map_or(0, |count| count.get());
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let memory = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .map(|rest| rest.trim().to_owned())
        .unwrap_or_default();
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let text = format!("{model}; {cores} cpus; {memory}; linux {}", kernel.trim());
    Ok(text
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
        .collect())
}

/// Renders one per-node triple as a JSON array.
fn values(triple: &[u64; 3]) -> String {
    let rendered: Vec<String> = triple.iter().map(u64::to_string).collect();
    format!("[{}]", rendered.join(","))
}

/// Renders the selected workload matrix, so a record always says which
/// population it ran, whether that population can close production capacity,
/// and every blocker between the two.
fn workload_json(workload: &Workload) -> String {
    let generator = workload.generator();
    let blockers: Vec<String> = workload
        .blockers()
        .iter()
        .map(|blocker| format!("\"{}\"", blocker.label()))
        .collect();
    let budget = workload.budget().parts();
    format!(
        "\"workload\":{{\"profile\":\"{}\",\"qualifying\":{},\"per_node_connections\":{},\
\"total_connections\":{},\"load_channels\":{},\"connections_per_address\":{},\
\"generator_addresses_per_node\":{},\"generator_subnets_per_node\":{},\"blockers\":[{}]}},\
\"node_budget\":{}",
        workload.profile().label(),
        workload.qualifying(),
        workload.per_node_connections(),
        workload.total_connections(),
        workload.load_channels(),
        generator.connections_per_address(),
        generator.addresses_per_node(),
        generator.subnets_per_node(),
        blockers.join(","),
        format_args!(
            "{{\"budget_bytes\":{},\"headroom_bytes\":{},\"storage_handoff_bytes\":{},\
\"crypto_pool_bytes\":{},\"protocol_pool_bytes\":{}}}",
            budget[0], budget[1], budget[2], budget[3], budget[4]
        )
    )
}

fn percentiles(samples: &mut [u64]) -> (u64, u64, u64, usize) {
    samples.sort_unstable();
    let pick = |percent: usize| -> u64 {
        let Some(last) = samples.len().checked_sub(1) else {
            return 0;
        };
        samples.get(last * percent / 100).copied().unwrap_or(0)
    };
    (pick(50), pick(95), pick(99), samples.len())
}

/// Fixed-schema JSON without a serializer dependency; every string is ASCII.
fn write_report(
    settings: &Settings,
    campaign: &Campaign<'_>,
    latencies: &mut Latencies,
    elapsed_ns: u64,
    returned: bool,
    stop_statuses: &[bool; 3],
) -> TestResult {
    let shared = campaign.shared;
    let classes: [(&str, &mut Vec<u64>); 6] = [
        ("admission", &mut latencies.admission),
        ("durable_mutation", &mut latencies.durable_mutation),
        ("fanout", &mut latencies.fanout),
        ("message", &mut latencies.message),
        ("opaque", &mut latencies.opaque),
        ("snapshot", &mut latencies.snapshot),
    ];
    let mut json = String::new();
    json.push_str(&format!(
        "{{\"schema_version\":1,\"elapsed_ns\":{elapsed_ns},\"connections\":{},\"resource_source\":\"{}\",\"samples\":[",
        settings.connections,
        campaign.nodes.source.label()
    ));
    for (index, sample) in campaign.samples.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        let triple = |select: fn(&Resources) -> u64| {
            values(&sample.resources.map(|resources| select(&resources)))
        };
        json.push_str(&format!(
            "{{\"at_ns\":{},\"anonymous_bytes\":{},\"sockets\":{},\"close_wait\":{},\"tasks\":{},\
\"federation_links\":{},\"client_queued_bytes\":{},\"federation_queued_bytes\":{},\
\"storage_jobs_in_flight\":{},\"live_client_connections\":{},\"memory_charged_bytes\":{},\
\"memory_budget_bytes\":{}}}",
            sample.at_ns,
            triple(|r| r.anonymous_bytes),
            triple(|r| r.sockets),
            triple(|r| r.close_wait),
            triple(|r| r.tasks),
            sample.federation_links,
            sample.client_queued_bytes,
            sample.federation_queued_bytes,
            sample.storage_jobs_in_flight,
            values(&sample.live_client_connections),
            values(&sample.memory_charged_bytes),
            values(&sample.memory_budget_bytes)
        ));
    }
    json.push_str("],\"latency_classes\":{");
    for (index, (name, values)) in classes.into_iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        let (p50, p95, p99, count) = percentiles(values.as_mut_slice());
        json.push_str(&format!(
            "\"{name}\":{{\"count\":{count},\"p50_ns\":{p50},\"p95_ns\":{p95},\"p99_ns\":{p99}}}"
        ));
    }
    let scenarios = &campaign.scenarios;
    json.push_str(&format!(
        "}},\"scenario_counts\":{{\"reconnect\":{},\"churn\":{},\"rekey\":{},\"index_transition\":{},\"snapshot\":{},\"backup\":{},\"disk_pressure\":{},\"peer_loss\":{}}},",
        scenarios.reconnect, scenarios.churn, scenarios.rekey, scenarios.index_transition,
        scenarios.snapshot, scenarios.backup, scenarios.disk_pressure, scenarios.peer_loss
    ));
    json.push_str(&format!(
        "\"missed_events\":{},\"envelope_violations\":{},\"population_shortfalls\":{},\"sample_failures\":{},\"returned_to_envelope\":{returned},\"worker_reconnects\":{},\"worker_churns\":{},\"messages_sent\":{},\"messages_received\":{},\"messages_refused\":{},\"refused_by_code\":{{{}}},\"refused_by_time\":{{{}}},\"daemons_stopped_cleanly\":[{},{},{}],\"reserve_bytes\":{},\"hardware\":\"{}\",\"worker_errors\":{},",
        shared.missed_events.load(Ordering::Relaxed),
        campaign.envelope_violations,
        campaign.population_shortfalls,
        campaign.sample_failures,
        shared.reconnects.load(Ordering::Relaxed),
        shared.churns.load(Ordering::Relaxed),
        shared.sent.load(Ordering::Relaxed),
        shared.received.load(Ordering::Relaxed),
        shared.refused.load(Ordering::Relaxed),
        shared.refused_codes.lock().map_or_else(
            |_| String::new(),
            |codes| {
                codes
                    .iter()
                    .map(|(code, count)| format!("\"{code}\":{count}"))
                    .collect::<Vec<_>>()
                    .join(",")
            }
        ),
        shared.refused_buckets.lock().map_or_else(
            |_| String::new(),
            |buckets| {
                buckets
                    .iter()
                    .map(|(bucket, count)| format!("\"{bucket}\":{count}"))
                    .collect::<Vec<_>>()
                    .join(",")
            }
        ),
        stop_statuses[0], stop_statuses[1], stop_statuses[2],
        campaign.reserve,
        hardware()?.replace('"', "'"),
        shared.worker_errors.lock().map_or(0, |errors| errors.len()),
    ));
    json.push_str(&format!("{},\"log\":[", workload_json(&settings.workload)));
    for (index, line) in campaign.log.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        json.push_str(&format!(
            "\"{}\"",
            line.replace('\\', "/").replace('"', "'")
        ));
    }
    json.push_str("]}\n");
    let path = settings.directory.join("campaign.json");
    write_private(&path, json.as_bytes())?;
    write_worker_errors(&settings.directory, shared)
}

fn write_worker_errors(directory: &Path, shared: &Shared) -> TestResult {
    let errors = shared
        .worker_errors
        .lock()
        .map(|errors| errors.join("\n"))
        .unwrap_or_default();
    let path = directory.join("worker-errors.log");
    let _stale = fs::remove_file(&path);
    write_private(&path, errors.as_bytes())
}

/// The controller half of the campaign: warm baseline, cycles until the
/// final reserve, and the closing quiescence check.
#[expect(
    clippy::too_many_arguments,
    reason = "the controller receives every campaign resource exactly once"
)]
fn control<'a>(
    settings: &'a Settings,
    network: &'a Network,
    shared: &'a Shared,
    admins: [AdminIdentity; 3],
    nodes: Nodes,
    account: AccountId,
    reserve: u64,
    deadline: Instant,
    returned: &mut bool,
) -> TestResult<Campaign<'a>> {
    // The warm-up covers the paced connection of every worker plus settling.
    // Workers on distinct generator source addresses connect concurrently, so
    // only one address's queue of workers has to drain.
    let warm_up = MINIMUM_WARM_UP.max(
        RESUME_SLOT * u32::try_from(settings.workload.workers_per_address()).unwrap_or(0)
            + Duration::from_secs(5),
    );
    println!("[controller] warming up for {} seconds", warm_up.as_secs());
    thread::sleep(warm_up);
    let baseline = take_sample(shared, &nodes, &admins)?;
    let mut campaign = Campaign {
        settings,
        network,
        shared,
        admins,
        nodes,
        account,
        requests: 1_000,
        scenarios: Scenarios::default(),
        samples: Vec::new(),
        envelope_violations: 0,
        population_shortfalls: 0,
        sample_failures: 0,
        baseline: baseline.resources,
        backup_path: None,
        backup_sequence: 0,
        reserve,
        log: Vec::new(),
    };
    let live = baseline.total_live();
    let version = AdminSession::connect(&campaign.admins[0])?.version()?;
    campaign.note(format!("coordinator version reply: {version}"));
    campaign.samples.push(baseline);
    campaign.note(format!(
        "baseline source={} memory={:?} sockets={:?} tasks={:?} live={live}",
        campaign.nodes.source.label(),
        campaign.baseline.map(|r| r.anonymous_bytes),
        campaign.baseline.map(|r| r.sockets),
        campaign.baseline.map(|r| r.tasks),
    ));
    let mut number = 0;
    // A cycle starts only when the budget can hold it: the first always, a
    // later one when at least the previous cycle's duration remains beyond
    // the final reserve, so the campaign ends near its deadline instead of
    // running a whole extra cycle past it.
    let mut last_cycle = Duration::ZERO;
    while Instant::now() + FINAL_RESERVE + last_cycle < deadline {
        number += 1;
        let started = Instant::now();
        campaign.cycle(number)?;
        last_cycle = started.elapsed();
        let remaining = deadline.saturating_duration_since(Instant::now());
        // Rest between cycles when another fits; otherwise settle through
        // the rest of the budget up to the final reserve.
        let rest = if remaining > FINAL_RESERVE + last_cycle + INTER_CYCLE_REST {
            INTER_CYCLE_REST
        } else {
            remaining.saturating_sub(FINAL_RESERVE)
        };
        if rest > SAMPLE_INTERVAL {
            campaign.settle(rest.min(Duration::from_secs(600)).as_secs())?;
        }
    }
    *returned = campaign.quiesce()?;
    // The record must show the whole configured duration: the loop stops
    // when another cycle would not fit and the final reserve covers the
    // quiescence check, so the load runs on through whatever remains.
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining > Duration::ZERO {
        campaign.settle(final_wait_seconds(remaining)?)?;
    }
    Ok(campaign)
}

/// Converts the final remainder into whole seconds without shortening it.
fn final_wait_seconds(remaining: Duration) -> TestResult<u64> {
    remaining
        .as_secs()
        .checked_add(u64::from(remaining.subsec_nanos() != 0))
        .ok_or_else(|| failure("campaign wait exceeds the whole-second range"))
}

#[test]
fn the_final_wait_covers_the_remainder_with_the_fewest_whole_seconds() -> TestResult {
    for remaining in [
        Duration::from_millis(1_500),
        Duration::from_nanos(1),
        Duration::from_nanos(999_999_999),
        Duration::ZERO,
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(MAX_CAMPAIGN_SECONDS) - Duration::from_millis(500),
        Duration::from_secs(MAX_CAMPAIGN_SECONDS),
        Duration::from_secs(u64::MAX),
    ] {
        let seconds = final_wait_seconds(remaining)?;
        assert!(
            Duration::from_secs(seconds) >= remaining,
            "a final wait of {seconds}s would end before the remaining {remaining:?}"
        );
        if let Some(previous) = seconds.checked_sub(1) {
            assert!(
                Duration::from_secs(previous) < remaining,
                "the final wait includes an unnecessary whole second"
            );
        }
    }
    assert!(
        final_wait_seconds(Duration::new(u64::MAX, 1)).is_err(),
        "an unrepresentable whole-second wait must fail without wrapping"
    );
    Ok(())
}

/// Polls every node's `STATS FEDERATION` until no base outbox object or
/// pending request remains, or the drain wait elapses; returns what it saw.
fn wait_for_federation_drain(admins: &[AdminIdentity; 3]) -> TestResult<String> {
    let deadline = Instant::now() + FEDERATION_DRAIN_WAIT;
    let started = Instant::now();
    let mut last = String::new();
    while Instant::now() < deadline {
        let mut outstanding = 0_u64;
        let mut parts = Vec::new();
        for (index, identity) in admins.iter().enumerate() {
            let mut admin = AdminSession::connect(identity)?;
            let objects = admin
                .stats("FEDERATION")?
                .into_iter()
                .find(|(name, _)| name == "base_outbox_objects")
                .map_or(0, |(_, value)| value);
            outstanding = outstanding.saturating_add(objects);
            parts.push(format!("node {index}={objects}"));
        }
        last = parts.join(" ");
        if outstanding == 0 {
            return Ok(format!(
                "drained in {:.1}s ({last})",
                started.elapsed().as_secs_f64()
            ));
        }
        thread::sleep(Duration::from_secs(1));
    }
    Ok(format!(
        "still outstanding after {}s ({last})",
        FEDERATION_DRAIN_WAIT.as_secs()
    ))
}

/// Copies each node's log segments into `<campaign>/logs/<node>` so the
/// daemon's own record of every scenario survives fixture cleanup.
fn preserve_logs(network: &Network, directory: &Path) -> TestResult {
    for (name, fixture) in [
        ("coordinator", &network.coordinator),
        ("edge-a", &network.edge_a),
        ("edge-b", &network.edge_b),
    ] {
        let target = directory.join("logs").join(name);
        fs::create_dir_all(&target)?;
        // A node restarted on a transitioned or rekeyed directory logs under
        // that directory, so every segment below the node's data directory
        // is kept, named by its path relative to it.
        let mut copied = 0_u32;
        let mut pending = vec![fixture.data_dir.clone()];
        while let Some(dir) = pending.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    pending.push(path);
                } else if file_type.is_file()
                    && path.extension().is_some_and(|extension| extension == "log")
                {
                    let relative = path
                        .strip_prefix(&fixture.data_dir)
                        .map(|relative| relative.to_string_lossy().replace('/', "__"))
                        .unwrap_or_else(|_| entry.file_name().to_string_lossy().into_owned());
                    fs::copy(&path, target.join(relative))?;
                    copied += 1;
                }
            }
        }
        println!("[controller] preserved {copied} log segments for {name}");
    }
    Ok(())
}

#[test]
#[ignore = "requires the Stage 10 campaign controller"]
fn sustained_operation_campaign() -> TestResult {
    let settings = Settings::from_environment()?;
    fs::create_dir_all(&settings.directory)?;
    let network = build_network_with(Some(CapacityPlan {
        // One edge's own share plus the controller's probes, never above the
        // Section 19.2 hard maximum.
        max_connections: settings.workload.listener_ceiling(CONTROLLER_PROBES)?,
        // The per-/32 ceiling stays at its published hard maximum. The
        // generator spreads its population over enough loopback source
        // addresses to stay under it rather than raising it to pass.
        connections_per_address: settings.workload.generator().connections_per_address(),
        // The advertised claim is about the default node budget, so the
        // campaign restores it over the Stage 08 fixture's lowered one.
        memory_budget_bytes: DEFAULT_BUDGET_BYTES,
    }))?;
    let outcome = run_campaign(&settings, &network);
    preserve_logs(&network, &settings.directory)?;
    outcome
}

fn run_campaign(settings: &Settings, network: &Network) -> TestResult {
    let reserve = campaign_reserve(available_bytes(&network.edge_a.data_dir)?);
    for fixture in [&network.coordinator, &network.edge_a, &network.edge_b] {
        set_reserve(fixture, reserve)?;
    }
    let source = ResourceSource::detect()?;
    println!("[controller] resource source: {}", source.label());
    let shared = Shared::new();
    let deadline = shared.epoch + Duration::from_secs(settings.seconds);
    let mut nodes = Nodes::start(network, source, &settings.directory)?;
    println!("[controller] daemons started; waiting for both edge links");
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    println!("[controller] creating the campaign account");
    let (mut probe, account) = authenticated_client(
        &network.edge_a,
        "campaign-seed",
        CAMPAIGN_ACCOUNT_LOGIN,
        200,
    )?;
    probe.send("QUIT :seeded")?;
    drop(probe);
    let admins = [
        admin_identity(&network.coordinator),
        admin_identity(&network.edge_a),
        admin_identity(&network.edge_b),
    ];
    let plans = (0..settings.connections)
        .map(|index| -> TestResult<WorkerPlan> {
            let edge = index % CLIENT_NODES;
            Ok(WorkerPlan {
                index,
                nick: format!("load{index:04}"),
                peer: format!("load{:04}", (index + 2) % settings.connections),
                edge,
                load_channel: settings.workload.load_channel(index)?,
                source: settings.workload.generator().source_address(edge, index)?,
                slot_index: settings.workload.slot_index(index)?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut returned = false;
    let mut stop_statuses = [false; 3];
    let outcome: TestResult<Campaign<'_>> = thread::scope(|scope| {
        for plan in &plans {
            let shared = &shared;
            let fixtures = [&network.edge_a, &network.edge_b];
            scope.spawn(move || worker(shared, fixtures, plan));
        }
        // Any controller error must release the workers, or the scope never ends.
        let result = control(
            settings,
            network,
            &shared,
            admins,
            nodes,
            account,
            reserve,
            deadline,
            &mut returned,
        );
        shared.stop.store(true, Ordering::Relaxed);
        result
    });
    let mut campaign = match outcome {
        Ok(campaign) => campaign,
        Err(error) => {
            write_worker_errors(&settings.directory, &shared)?;
            return Err(error);
        }
    };
    let elapsed_ns = shared.nanos();
    // The workers have quit; let the federation settle before the stop so a
    // daemon is not shut down while it still acknowledges and answers, the
    // way an operator stops a node after its links go quiet.
    let drained = wait_for_federation_drain(&campaign.admins)?;
    campaign.note(format!("federation drain before stop: {drained}"));
    nodes = campaign.nodes;
    for (status, daemon) in
        stop_statuses
            .iter_mut()
            .zip([&mut nodes.coordinator, &mut nodes.edge_a, &mut nodes.edge_b])
    {
        *status = daemon
            .stop()
            .map(|status| status.success())
            .unwrap_or(false);
    }
    campaign.nodes = nodes;
    campaign.nodes.source.remove_leaves();
    let mut latencies = std::mem::take(
        &mut *shared
            .latencies
            .lock()
            .map_err(|_| failure("latency lock poisoned"))?,
    );
    write_report(
        settings,
        &campaign,
        &mut latencies,
        elapsed_ns,
        returned,
        &stop_statuses,
    )?;
    if !stop_statuses.iter().all(|clean| *clean) {
        return Err(failure(
            "a daemon did not stop cleanly at the end of the campaign",
        ));
    }
    Ok(())
}

/// Campaign directory of the RUN-08 peer-loss kill drill.
const KILL_DIRECTORY_ENV: &str = "AGENC_RUN08_KILL_DIR";
/// How many kill rounds the drill runs.
const KILL_ROUNDS_ENV: &str = "AGENC_RUN08_KILL_ROUNDS";
/// The client population the drill holds while it kills.
const KILL_CONNECTIONS_ENV: &str = "AGENC_RUN08_KILL_CONNECTIONS";
/// Most kill rounds one invocation may run.
const MAX_KILL_ROUNDS: u64 = 4_096;
/// Kill rounds step their phase by this much, so successive kills land at
/// different points of the restarted edge's recovery instead of one fixed
/// instant: the coordinator's post-restart resynchronization, the paced
/// return of the population, and the settled steady state beyond it.
const KILL_PHASE_STEP: Duration = Duration::from_millis(1_500);
/// Distinct phases the step sweeps before it wraps. Twenty-four steps of
/// 1.5 s reach 34.5 s after the link, which covers the whole paced return of
/// a 32-worker edge (12.4 s) and includes `scenario_peer_loss`'s own 12 s.
const KILL_PHASES: u64 = 24;
/// How long edge b stays down between the kill and the restart, exactly the
/// pause `scenario_peer_loss` takes.
const KILL_DOWNTIME: Duration = Duration::from_secs(5);
/// Every second round kills the restarted edge again **during its own
/// startup**, before it has re-established the link, so the start after it
/// reads a state torn inside the startup work rather than inside the live
/// path: the durable reconstruction, the recovered session reconciliation's
/// one committed plan per recovered session, the edge federation restore and
/// the history load. This is the step that sweeps that second kill's own
/// phase.
const STARTUP_KILL_STEP: Duration = Duration::from_millis(1_000);
/// Distinct startup phases the step sweeps before it wraps. Twenty steps of
/// one second reach past the storage open and the whole reconstruction of a
/// warm edge on this host.
const STARTUP_KILL_PHASES: u64 = 20;
/// Bound on the stderr capture kept with a refused restart.
const MAX_STDERR_BYTES: u64 = 1_024 * 1_024;

/// Drill inputs read from the environment.
struct KillDrillSettings {
    directory: PathBuf,
    rounds: u64,
    connections: usize,
    workload: Workload,
}

impl KillDrillSettings {
    fn from_environment() -> TestResult<Self> {
        let directory = PathBuf::from(
            std::env::var_os(KILL_DIRECTORY_ENV)
                .ok_or_else(|| failure("kill drill directory is not configured"))?,
        );
        let rounds: u64 = std::env::var(KILL_ROUNDS_ENV)?.parse()?;
        if !(1..=MAX_KILL_ROUNDS).contains(&rounds) {
            return Err(failure("kill drill round count is outside its bound"));
        }
        let requested: usize = match std::env::var(KILL_CONNECTIONS_ENV) {
            Ok(text) => text.parse()?,
            Err(_) => DEFAULT_CONNECTIONS,
        };
        let ceiling = usize::try_from(MAX_CLIENT_CONNECTIONS)?
            .checked_mul(CLIENT_NODES)
            .ok_or_else(|| failure("kill drill ceiling overflows"))?;
        if !(4..=ceiling).contains(&requested) {
            return Err(failure("kill drill connection count is outside its bound"));
        }
        let workload = Workload::select(u64::try_from(requested)?)?;
        Ok(Self {
            directory,
            rounds,
            connections: usize::try_from(workload.total_connections())?,
            workload,
        })
    }
}

/// What one kill round observed.
struct KillRound {
    number: u64,
    phase_ms: u64,
    startup_kill_ms: Option<u64>,
    live_at_kill: [u64; 3],
    charged_at_kill: [u64; 3],
    budget_at_kill: [u64; 3],
    killed_at_ns: u64,
    back_ms: u64,
    refusal: Option<String>,
}

/// Every node's `STATS RUNTIME` occupancy, charge and budget.
fn runtime_occupancy(admins: &[AdminIdentity; 3]) -> TestResult<([u64; 3], [u64; 3], [u64; 3])> {
    let mut live = [0_u64; 3];
    let mut charged = [0_u64; 3];
    let mut budget = [0_u64; 3];
    for (index, identity) in admins.iter().enumerate() {
        let mut admin = AdminSession::connect(identity)?;
        for (name, value) in admin.stats("RUNTIME")? {
            let slot = match name.as_str() {
                "live_client_connections" => live.get_mut(index),
                "memory_charged_bytes" => charged.get_mut(index),
                "memory_budget_bytes" => budget.get_mut(index),
                _ => None,
            };
            if let Some(slot) = slot {
                *slot = value;
            }
        }
        admin.quit()?;
    }
    Ok((live, charged, budget))
}

/// Copies one directory tree, so a refused restart keeps the exact durable
/// state the killed edge left behind before the fixture is removed.
fn copy_tree(source: &Path, target: &Path) -> TestResult {
    fs::create_dir_all(target)?;
    let mut pending = vec![(source.to_path_buf(), target.to_path_buf())];
    while let Some((from, into)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&from) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let destination = into.join(entry.file_name());
            if file_type.is_dir() {
                fs::create_dir_all(&destination)?;
                pending.push((entry.path(), destination));
            } else if file_type.is_file() {
                fs::copy(entry.path(), &destination)?;
            }
        }
    }
    Ok(())
}

/// The daemon's own stderr since the drill started, which is where a
/// fail-closed startup prints the line an operator reads.
fn edge_b_stderr(directory: &Path) -> String {
    read_bounded(
        &directory.join("logs").join("edge-b.stderr"),
        MAX_STDERR_BYTES,
    )
    .unwrap_or_else(|error| format!("stderr unavailable: {error}"))
}

/// Runs the kill rounds against a warm population.
fn kill_rounds(
    settings: &KillDrillSettings,
    network: &Network,
    shared: &Shared,
    admins: &[AdminIdentity; 3],
    nodes: &mut Nodes,
    rounds: &mut Vec<KillRound>,
) -> TestResult {
    let warm_up = MINIMUM_WARM_UP.max(
        RESUME_SLOT * u32::try_from(settings.workload.workers_per_address()).unwrap_or(0)
            + Duration::from_secs(5),
    );
    println!("[drill] warming up for {} seconds", warm_up.as_secs());
    thread::sleep(warm_up);
    for number in 1..=settings.rounds {
        let phase =
            KILL_PHASE_STEP * u32::try_from(number.saturating_sub(1) % KILL_PHASES).unwrap_or(0);
        thread::sleep(phase);
        let (live_at_kill, charged_at_kill, budget_at_kill) = runtime_occupancy(admins)?;
        shared.maintenance.store(true, Ordering::Relaxed);
        let killed_at_ns = shared.nanos();
        nodes.edge_b.kill()?;
        thread::sleep(KILL_DOWNTIME);
        let mut before = links_established(&network.edge_b);
        let started = Instant::now();
        nodes.restart_edge_b(&network.edge_b.config_path)?;
        // Every second round kills the restart again before it has reached
        // its link, so the start that has to survive reads a state a kill
        // tore inside the startup work itself.
        let startup_kill = (number % 2 == 0).then(|| {
            STARTUP_KILL_STEP
                * u32::try_from(number.saturating_div(2).saturating_sub(1) % STARTUP_KILL_PHASES)
                    .unwrap_or(0)
        });
        if let Some(wait) = startup_kill {
            thread::sleep(wait);
            nodes.edge_b.kill()?;
            thread::sleep(KILL_DOWNTIME);
            before = links_established(&network.edge_b);
            nodes.restart_edge_b(&network.edge_b.config_path)?;
        }
        let back = wait_for_link(&network.edge_b, before);
        let back_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let startup_kill_ms =
            startup_kill.map(|wait| u64::try_from(wait.as_millis()).unwrap_or(u64::MAX));
        let refusal = match back {
            Ok(()) => {
                shared.maintenance.store(false, Ordering::Relaxed);
                None
            }
            Err(error) => Some(format!("{error}")),
        };
        println!(
            "[drill] round {number} phase={} ms startup_kill={startup_kill_ms:?} \
live={live_at_kill:?} charged={charged_at_kill:?} budget={budget_at_kill:?} back={back_ms} ms \
refused={}",
            u64::try_from(phase.as_millis()).unwrap_or(u64::MAX),
            refusal.is_some(),
        );
        rounds.push(KillRound {
            number,
            phase_ms: u64::try_from(phase.as_millis()).unwrap_or(u64::MAX),
            startup_kill_ms,
            live_at_kill,
            charged_at_kill,
            budget_at_kill,
            killed_at_ns,
            back_ms,
            refusal: refusal.clone(),
        });
        if refusal.is_some() {
            // The durable state the kill left is the evidence; keep it and the
            // daemon's own stderr before the fixture directory is removed.
            copy_tree(
                &network.edge_b.data_dir,
                &settings.directory.join("edge-b-durable-state"),
            )?;
            let stderr = edge_b_stderr(&settings.directory);
            write_private(
                &settings.directory.join("edge-b-refusal.log"),
                stderr.as_bytes(),
            )?;
            return Err(failure(format!(
                "edge b refused its restart in round {number}; its stderr ends: {}",
                stderr.lines().rev().take(4).collect::<Vec<_>>().join(" | ")
            )));
        }
    }
    Ok(())
}

/// Writes the drill's own record beside the campaign's.
fn write_kill_record(
    settings: &KillDrillSettings,
    rounds: &[KillRound],
    refused: bool,
) -> TestResult {
    let mut text = format!(
        "{{\"rounds\":{},\"connections\":{},\"memory_budget_bytes\":{},\"refused\":{},\"round\":[",
        rounds.len(),
        settings.connections,
        DEFAULT_BUDGET_BYTES,
        refused
    );
    for (position, round) in rounds.iter().enumerate() {
        if position > 0 {
            text.push(',');
        }
        let refusal = match &round.refusal {
            Some(reason) => format!("\"{}\"", escape_record(reason)),
            None => "null".to_owned(),
        };
        let startup_kill = match round.startup_kill_ms {
            Some(milliseconds) => milliseconds.to_string(),
            None => "null".to_owned(),
        };
        text.push_str(&format!(
            "{{\"number\":{},\"phase_ms\":{},\"startup_kill_ms\":{startup_kill},\
\"live\":{:?},\"charged\":{:?},\"budget\":{:?},\
\"killed_at_ns\":{},\"back_ms\":{},\"refusal\":{refusal}}}",
            round.number,
            round.phase_ms,
            round.live_at_kill,
            round.charged_at_kill,
            round.budget_at_kill,
            round.killed_at_ns,
            round.back_ms,
        ));
    }
    text.push_str("]}");
    let path = settings.directory.join("peer-loss-kill-drill.json");
    let _stale = fs::remove_file(&path);
    write_private(&path, text.as_bytes())
}

/// Escapes the few characters a drill reason can carry into JSON.
fn escape_record(text: &str) -> String {
    let mut escaped = String::new();
    for character in text.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            control if control.is_control() => escaped.push(' '),
            other => escaped.push(other),
        }
    }
    escaped
}

/// The RUN-08 peer-loss kill drill (issue #134).
///
/// `scenario_peer_loss` SIGKILLs edge b under the campaign's load at the
/// published `server.memory_budget_bytes` and restarts it, once per campaign
/// cycle. This drill holds the same population against the same three daemons
/// at the same budget and repeats **only** that kill, stepping the phase of
/// each kill across the restarted edge's paced client return so the rounds
/// sweep the window rather than sampling one instant of it. A refused restart
/// keeps the killed edge's whole durable directory and the daemon's own
/// stderr, and fails the drill naming the line.
#[test]
#[ignore = "requires the Stage 10 peer-loss kill drill controller"]
fn peer_loss_kill_drill() -> TestResult {
    let settings = KillDrillSettings::from_environment()?;
    fs::create_dir_all(&settings.directory)?;
    let network = build_network_with(Some(CapacityPlan {
        max_connections: settings.workload.listener_ceiling(CONTROLLER_PROBES)?,
        connections_per_address: settings.workload.generator().connections_per_address(),
        memory_budget_bytes: DEFAULT_BUDGET_BYTES,
    }))?;
    let outcome = run_kill_drill(&settings, &network);
    preserve_logs(&network, &settings.directory)?;
    outcome
}

fn run_kill_drill(settings: &KillDrillSettings, network: &Network) -> TestResult {
    let shared = Shared::new();
    let mut nodes = Nodes::start(network, ResourceSource::Procfs, &settings.directory)?;
    println!("[drill] daemons started; waiting for both edge links");
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    let admins = [
        admin_identity(&network.coordinator),
        admin_identity(&network.edge_a),
        admin_identity(&network.edge_b),
    ];
    let plans = (0..settings.connections)
        .map(|index| -> TestResult<WorkerPlan> {
            let edge = index % CLIENT_NODES;
            Ok(WorkerPlan {
                index,
                nick: format!("load{index:04}"),
                peer: format!("load{:04}", (index + 2) % settings.connections),
                edge,
                load_channel: settings.workload.load_channel(index)?,
                source: settings.workload.generator().source_address(edge, index)?,
                slot_index: settings.workload.slot_index(index)?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut rounds = Vec::new();
    let outcome: TestResult = thread::scope(|scope| {
        for plan in &plans {
            let shared = &shared;
            let fixtures = [&network.edge_a, &network.edge_b];
            scope.spawn(move || worker(shared, fixtures, plan));
        }
        // Any controller error must release the workers, or the scope never ends.
        let result = kill_rounds(settings, network, &shared, &admins, &mut nodes, &mut rounds);
        shared.stop.store(true, Ordering::Relaxed);
        result
    });
    write_worker_errors(&settings.directory, &shared)?;
    write_kill_record(settings, &rounds, outcome.is_err())?;
    let survived = rounds
        .iter()
        .filter(|round| round.refusal.is_none())
        .count();
    println!(
        "[drill] {survived} of {} kill rounds restarted; budget={DEFAULT_BUDGET_BYTES}",
        rounds.len()
    );
    let mut stopped = true;
    for daemon in [&mut nodes.coordinator, &mut nodes.edge_a, &mut nodes.edge_b] {
        stopped &= daemon
            .stop()
            .map(|status| status.success())
            .unwrap_or(false);
    }
    outcome?;
    if !stopped {
        return Err(failure(
            "a daemon did not stop cleanly at the end of the drill",
        ));
    }
    Ok(())
}
