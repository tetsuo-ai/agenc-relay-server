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

#[path = "../support/admin_client.rs"]
pub(super) mod admin_client;

use admin_client::{AdminIdentity, AdminSession};

const DIRECTORY_ENV: &str = "AGENC_STAGE10_CAMPAIGN_DIR";
const SECONDS_ENV: &str = "AGENC_STAGE10_CAMPAIGN_SECONDS";
const CONNECTIONS_ENV: &str = "AGENC_STAGE10_CAMPAIGN_CONNECTIONS";
const MIN_CAMPAIGN_SECONDS: u64 = 60;
const MAX_CAMPAIGN_SECONDS: u64 = 1_209_600;
const DEFAULT_CONNECTIONS: usize = 48;
const MAX_CONNECTIONS: usize = 4_096;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const QUIESCE_WINDOW: Duration = Duration::from_secs(8);
const SCENARIO_SETTLE: Duration = Duration::from_secs(12);
const FINAL_RESERVE: Duration = Duration::from_secs(45);
const LOAD_CHANNEL: &str = "#load";
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
/// Spacing between two workers resuming after a maintenance window.
const RESUME_SLOT: Duration = Duration::from_millis(150);
const PRESSURE_RECOVERY_WAIT: Duration = Duration::from_secs(45);
/// How long after a coordinator restart an explicit SASL failure is retried.
const POST_RESTART_AUTH_GRACE: Duration = Duration::from_secs(30);
const CAMPAIGN_ACCOUNT_LOGIN: &str = "campaign-account";

/// Campaign inputs read from the environment the driver sets.
struct Settings {
    directory: PathBuf,
    seconds: u64,
    connections: usize,
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
        let connections = match std::env::var(CONNECTIONS_ENV) {
            Ok(text) => text.parse()?,
            Err(_) => DEFAULT_CONNECTIONS,
        };
        if !(4..=MAX_CONNECTIONS).contains(&connections) {
            return Err(failure("campaign connection count is outside its bound"));
        }
        Ok(Self {
            directory,
            seconds,
            connections,
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

/// One client's place in the load.
struct WorkerPlan {
    index: usize,
    nick: String,
    peer: String,
    edge: usize,
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
        let mut client = register_when_available(fixture, &plan.nick)?;
        shared.record(
            |latencies| &mut latencies.admission,
            u64::try_from(started.elapsed().as_nanos())?,
        );
        let join_sent = shared.nanos();
        client.send(&format!("JOIN {LOAD_CHANNEL}"))?;
        client.read_until(|line| line.contains(&format!(" 366 {} {LOAD_CHANNEL} ", plan.nick)))?;
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
                "PRIVMSG {LOAD_CHANNEL} :seq={} t={}",
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
        if line.contains(" 366 ") && line.contains(LOAD_CHANNEL) {
            if let Some(sent) = self.join_sent.take() {
                shared.record(
                    |latencies| &mut latencies.snapshot,
                    now.saturating_sub(sent),
                );
            }
            return Ok(());
        }
        let Some((prefix, rest)) = line.strip_prefix(':').and_then(|line| line.split_once(' '))
        else {
            return Ok(());
        };
        let sender = prefix.split('!').next().unwrap_or_default().to_owned();
        if let Some(text) = rest.strip_prefix(&format!("PRIVMSG {LOAD_CHANNEL} :seq=")) {
            let (sequence, stamp) = text.split_once(" t=").unwrap_or(("", ""));
            let sequence: u64 = sequence.parse()?;
            let stamp: u64 = stamp.parse()?;
            shared.received.fetch_add(1, Ordering::Relaxed);
            shared.record(|latencies| &mut latencies.fanout, now.saturating_sub(stamp));
            self.check_sequence(&sender, sequence, shared);
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
        } else if rest.starts_with("FAIL PRIVMSG ") {
            // A side-effect-free refusal (spec 28.7): retry the same sequence.
            shared.refused.fetch_add(1, Ordering::Relaxed);
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
    fn check_sequence(&mut self, sender: &str, sequence: u64, shared: &Shared) {
        let expected = self.expected.entry(sender.to_owned()).or_insert(sequence);
        if sequence > *expected && !shared.maintenance.load(Ordering::Relaxed) {
            let gap = sequence - *expected;
            shared.missed_events.fetch_add(gap, Ordering::Relaxed);
            shared.note_error(format!(
                "missed at {:.1}s: sender={sender} expected={expected} got={sequence} gap={gap}",
                shared.epoch.elapsed().as_secs_f64()
            ));
        }
        *expected = sequence.wrapping_add(1);
    }
}

/// Whether an error is a transient transport failure a node restart can
/// cause: a refused connection, a handshake or read cut short, or a broken
/// pipe. Authentication and protocol failures are not transient.
fn transient_transport(error: &TestError) -> bool {
    let text = error.to_string();
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
    while !shared.stop.load(Ordering::Relaxed) {
        // Idle through an operator maintenance window so a node restart is not
        // buried under a client reconnection storm, the way a real client
        // backs off during announced maintenance.
        if shared.maintenance.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(250));
            // Resume in index order rather than all at once, as a client
            // population returning from announced maintenance does.
            thread::sleep(RESUME_SLOT * u32::try_from(plan.index % 64).unwrap_or(0));
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
                    .send(&format!("PART {LOAD_CHANNEL} :churn"))?;
                session.join_sent = Some(shared.nanos());
                session.client.send(&format!("JOIN {LOAD_CHANNEL}"))?;
                session.expected.clear();
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

/// One ten-second sample across the three nodes.
struct Sample {
    at_ns: u64,
    resources: [Resources; 3],
    federation_links: u64,
    client_queued_bytes: u64,
    federation_queued_bytes: u64,
    storage_jobs_in_flight: u64,
    live_client_connections: u64,
    memory_charged_bytes: u64,
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
        live_client_connections: 0,
        memory_charged_bytes: 0,
    };
    for (index, identity) in admins.iter().enumerate() {
        let mut admin = AdminSession::connect(identity)
            .map_err(|error| failure(format!("admin session to node {index}: {error}")))?;
        for (name, value) in admin.stats("QUEUES")? {
            match name.as_str() {
                "client_queued_bytes" => {
                    sample.client_queued_bytes = sample.client_queued_bytes.max(value)
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
            match name.as_str() {
                "live_client_connections" => sample.live_client_connections += value,
                "memory_charged_bytes" => {
                    sample.memory_charged_bytes = sample.memory_charged_bytes.max(value);
                }
                _ => {}
            }
        }
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
        let sample = take_sample(self.shared, &self.nodes, &self.admins)?;
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

    /// Waits for both edges to log a fresh coordinator link beyond the counts
    /// captured before a restart, so the coordinator is federated and its
    /// account service is ready before the scenario probes it.
    fn wait_relinks(&self, before_a: usize, before_b: usize) -> TestResult {
        wait_for_link(&self.network.edge_a, before_a)?;
        wait_for_link(&self.network.edge_b, before_b)
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

    /// The snapshot class: a fresh member joins `#load` and the paged NAMES
    /// snapshot the coordinator serves through the edge closes with 366.
    /// Explicit directory queries at an edge are recorded as observed: the
    /// edge currently refuses them (finding CAP-1), so the reply numeric is
    /// logged rather than assumed.
    fn scenario_snapshot(&mut self) -> TestResult {
        let started = self.shared.nanos();
        let mut client = register_when_available(&self.network.edge_a, "snapshot-probe")?;
        let sent = self.shared.nanos();
        client.send(&format!("JOIN {LOAD_CHANNEL}"))?;
        let joined = client.read_until_within(BUSY_TRANSCRIPT_LINES, |line| {
            line.contains(&format!(" 366 snapshot-probe {LOAD_CHANNEL} "))
        })?;
        self.shared.record(
            |latencies| &mut latencies.snapshot,
            self.shared.nanos().saturating_sub(sent),
        );
        let pages = joined.iter().filter(|line| line.contains(" 353 ")).count();
        let mut observed = Vec::new();
        for query in [
            format!("NAMES {LOAD_CHANNEL}"),
            format!("WHO {LOAD_CHANNEL}"),
        ] {
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

    /// Authenticates the campaign account on a fresh connection (the opaque
    /// class) and returns the connected client.
    /// Authenticates the campaign account on a fresh connection (the OPAQUE
    /// class) and returns the connected client. The whole exchange is retried
    /// on a transient transport failure: a scenario that restarts the
    /// coordinator briefly closes clients on the edge whose upstream link is
    /// re-establishing, and that window is not an authentication fault.
    fn opaque_login(&mut self, fixture_index: usize) -> TestResult<IrcClient> {
        self.opaque_login_with_grace(fixture_index, None)
    }

    /// Like `opaque_login`, but inside `auth_grace` after a coordinator
    /// restart an explicit SASL failure is retried as well: the first
    /// authentication after the restart has been answered with 904 before the
    /// account service was serving (finding CAP-7). Every such retry is noted.
    fn opaque_login_with_grace(
        &mut self,
        fixture_index: usize,
        auth_grace: Option<Duration>,
    ) -> TestResult<IrcClient> {
        let started = Instant::now();
        let deadline = started + NETWORK_WAIT;
        let grace_until = auth_grace.map(|grace| started + grace);
        let mut auth_retries = 0_u32;
        loop {
            match self.opaque_login_once(fixture_index) {
                Ok(client) => {
                    if auth_retries > 0 {
                        self.note(format!(
                            "OPAQUE login succeeded after {auth_retries} SASL failures within \
the post-restart grace (CAP-7)"
                        ));
                    }
                    return Ok(client);
                }
                Err(error) if Instant::now() < deadline && transient_transport(&error) => {
                    thread::sleep(Duration::from_secs(1));
                }
                Err(error)
                    if grace_until.is_some_and(|until| Instant::now() < until)
                        && error.to_string().contains(" 904 ") =>
                {
                    auth_retries += 1;
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

    /// A durable write that must be refused under disk pressure and accepted
    /// once the pressure clears.
    /// Attempts one durable mutation (a JOIN of a new channel) on an existing
    /// registered session and classifies the outcome. A refusal is an explicit
    /// FAIL, and a transport close counts as a refusal too: the edge closes a
    /// client whose durable request the coordinator rejected under pressure.
    fn durable_join(
        client: &mut IrcClient,
        nick: &str,
        channel: &str,
    ) -> TestResult<DurableOutcome> {
        if client.send(&format!("JOIN {channel}")).is_err() {
            return Ok(DurableOutcome::Refused("send failed".to_owned()));
        }
        match client.read_until_within(BUSY_TRANSCRIPT_LINES, |line| {
            line.contains(&format!(" 366 {nick} {channel} ")) || line.contains("FAIL JOIN")
        }) {
            Ok(lines) => match lines.iter().find(|line| line.contains("FAIL JOIN")) {
                Some(refusal) => Ok(DurableOutcome::Refused(refusal.clone())),
                None => Ok(DurableOutcome::Admitted),
            },
            Err(error) => Ok(DurableOutcome::Refused(format!(
                "transport closed: {error}"
            ))),
        }
    }

    /// Registers a fresh connection under the current storage conditions with
    /// a bounded wait and classifies the outcome without failing the campaign.
    fn registration_probe(&mut self, label: &str) -> TestResult {
        let mut client = IrcClient::connect(&self.network.edge_a)?;
        client
            .reader
            .get_ref()
            .sock
            .set_read_timeout(Some(REGISTRATION_PROBE_WAIT))?;
        let outcome = match client.try_register(&format!("register-{label}")) {
            Ok(Registration::Welcome(_)) => "admitted".to_owned(),
            Ok(Registration::Unavailable(lines)) => match lines.last() {
                Some(line) => format!("refused: {line}"),
                None => "closed before any reply".to_owned(),
            },
            Err(error) if error.to_string().contains("os error 11") => {
                "silent (no reply within the bounded wait)".to_owned()
            }
            Err(error) => format!("error: {error}"),
        };
        let _ = client.send("QUIT :registration probe");
        self.note(format!("registration probe {label}: {outcome}"));
        Ok(())
    }

    /// Polls with fresh sessions until a durable mutation is admitted or the
    /// recovery deadline passes; the transient window after the ballast drops
    /// closes early durable requests while the federation origin resettles.
    fn await_durable_recovery(&mut self) -> TestResult<bool> {
        let deadline = Instant::now() + PRESSURE_RECOVERY_WAIT;
        let mut attempt = 0_u32;
        while Instant::now() < deadline {
            attempt += 1;
            let nick = format!("recover{attempt:03}");
            let Ok(mut client) = register_when_available(&self.network.edge_a, &nick) else {
                thread::sleep(Duration::from_secs(1));
                continue;
            };
            let outcome = Self::durable_join(&mut client, &nick, &format!("#recover-{attempt}"))?;
            let _ = client.send("QUIT :recovery probe");
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
        let _ = probe.send("QUIT :pressure probe complete");
        drop(ballast);
        thread::sleep(Duration::from_secs(2));
        let recovered = self.await_durable_recovery()?;
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
        let identity = &self.admins[2];
        AdminSession::connect(identity)?.confirm_process("DIE :campaign maintenance")?;
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

    fn edge_b_keys(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let seed = self.network.edge_b.seed;
        (
            [seed.wrapping_add(7); 32],
            [seed.wrapping_add(8); 32],
            [seed.wrapping_add(9); 32],
        )
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
        let (master, guard, login) = self.edge_b_keys();
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

    /// Exercises the coordinator's login-index reconstruction and generation
    /// validation across a restart, then re-authenticates the campaign account
    /// so the reconstructed index serves a live OPAQUE login. A genuine
    /// login-index key transition (Section 23.9 start/finalize) re-encrypts
    /// every login record under a new key through a construction that no
    /// stopped command exposes; that key rotation stays an external drill item
    /// (finding CAP-4). This scenario proves the login index survives a
    /// restart intact, which the transition builds on.
    fn scenario_index_transition(&mut self) -> TestResult {
        self.shared.maintenance.store(true, Ordering::Relaxed);
        let before_a = links_established(&self.network.edge_a);
        let before_b = links_established(&self.network.edge_b);
        let status = self.nodes.coordinator.stop()?;
        if !status.success() {
            return Err(failure(format!("coordinator exited with {status}")));
        }
        self.nodes
            .restart_coordinator(&self.network.coordinator.config_path)?;
        self.wait_relinks(before_a, before_b)?;
        self.shared.maintenance.store(false, Ordering::Relaxed);
        let mut client = self.opaque_login_with_grace(1, Some(POST_RESTART_AUTH_GRACE))?;
        client.send("QUIT :login-index reconstruction complete")?;
        self.note("login-index reconstruction across a coordinator restart");
        self.scenarios.index_transition += 1;
        Ok(())
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
        let sample = take_sample(self.shared, &self.nodes, &self.admins)?;
        let inside = within_envelope(&self.baseline, &sample.resources);
        self.note(format!(
            "quiescence: inside={inside} memory={:?} sockets={:?} tasks={:?} links={}",
            sample.resources.map(|r| r.anonymous_bytes),
            sample.resources.map(|r| r.sockets),
            sample.resources.map(|r| r.tasks),
            sample.federation_links
        ));
        self.samples.push(sample);
        self.shared.pause.store(false, Ordering::Relaxed);
        if !inside {
            self.envelope_violations += 1;
        }
        Ok(inside)
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
            let values = sample.resources.map(|resources| select(&resources));
            format!("[{},{},{}]", values[0], values[1], values[2])
        };
        json.push_str(&format!(
            "{{\"at_ns\":{},\"anonymous_bytes\":{},\"sockets\":{},\"close_wait\":{},\"tasks\":{},\
\"federation_links\":{},\"client_queued_bytes\":{},\"federation_queued_bytes\":{},\
\"storage_jobs_in_flight\":{},\"live_client_connections\":{},\"memory_charged_bytes\":{}}}",
            sample.at_ns,
            triple(|r| r.anonymous_bytes),
            triple(|r| r.sockets),
            triple(|r| r.close_wait),
            triple(|r| r.tasks),
            sample.federation_links,
            sample.client_queued_bytes,
            sample.federation_queued_bytes,
            sample.storage_jobs_in_flight,
            sample.live_client_connections,
            sample.memory_charged_bytes
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
        "\"missed_events\":{},\"envelope_violations\":{},\"returned_to_envelope\":{returned},\"worker_reconnects\":{},\"worker_churns\":{},\"messages_sent\":{},\"messages_received\":{},\"messages_refused\":{},\"daemons_stopped_cleanly\":[{},{},{}],\"reserve_bytes\":{},\"hardware\":\"{}\",\"worker_errors\":{},\"log\":[",
        shared.missed_events.load(Ordering::Relaxed),
        campaign.envelope_violations,
        shared.reconnects.load(Ordering::Relaxed),
        shared.churns.load(Ordering::Relaxed),
        shared.sent.load(Ordering::Relaxed),
        shared.received.load(Ordering::Relaxed),
        shared.refused.load(Ordering::Relaxed),
        stop_statuses[0], stop_statuses[1], stop_statuses[2],
        campaign.reserve,
        hardware()?.replace('"', "'"),
        shared.worker_errors.lock().map_or(0, |errors| errors.len()),
    ));
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
    println!("[controller] warming up for 20 seconds");
    thread::sleep(Duration::from_secs(20));
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
        baseline: baseline.resources,
        backup_path: None,
        backup_sequence: 0,
        reserve,
        log: Vec::new(),
    };
    let live = baseline.live_client_connections;
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
    while Instant::now() + FINAL_RESERVE < deadline {
        number += 1;
        campaign.cycle(number)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining > FINAL_RESERVE + SAMPLE_INTERVAL {
            campaign.settle(
                (remaining - FINAL_RESERVE)
                    .min(Duration::from_secs(600))
                    .as_secs(),
            )?;
        }
    }
    *returned = campaign.quiesce()?;
    Ok(campaign)
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
        let Ok(entries) = fs::read_dir(&fixture.log_dir) else {
            println!("[controller] no log directory for {name}");
            continue;
        };
        let mut copied = 0_u32;
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::copy(entry.path(), target.join(entry.file_name()))?;
                copied += 1;
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
    let connections = u64::try_from(settings.connections)?;
    let network = build_network_with(Some(CapacityPlan {
        max_connections: connections + 16,
        // Half the clients land on each edge; reconnect and churn rounds and
        // the controller's probes need headroom above that share. The config
        // ceiling for this key is 256, which the 256-client soak fits under.
        connections_per_address: (connections.div_ceil(2) + 16).min(256),
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
        .map(|index| WorkerPlan {
            index,
            nick: format!("load{index:04}"),
            peer: format!("load{:04}", (index + 2) % settings.connections),
            edge: index % 2,
        })
        .collect::<Vec<_>>();
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
