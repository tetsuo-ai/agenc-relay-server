//! The closed log event registry, metric label vocabulary, and health model
//! (spec 25.2 6676-6697, 25.3 6699-6712).

use std::fmt;

use agenc_ircd_types::{ServerId, UtcSecond};

use crate::listeners::ListenerPurpose;
use crate::network::NodeRole;

/// The closed set of log events.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LogEventCode {
    /// The process started.
    ProcessStarted,
    /// Configuration was loaded and validated.
    ConfigurationLoaded,
    /// Configuration was rejected.
    ConfigurationRejected,
    /// Process hardening left a control unapplied.
    HardeningWarning,
    /// Storage recovery completed.
    StorageRecovered,
    /// Storage entered indeterminate state.
    StorageIndeterminate,
    /// A listener opened.
    ListenerOpened,
    /// A listener closed.
    ListenerClosed,
    /// Accepts paused because the handshake ceiling was reached.
    AcceptPaused,
    /// A TLS handshake failed.
    TlsHandshakeFailed,
    /// A connection was refused by admission.
    ConnectionRefused,
    /// A slow consumer was closed.
    SlowConsumerClosed,
    /// The overload class changed.
    OverloadClassChanged,
    /// An administrative session authenticated.
    AdminAuthenticated,
    /// An administrative session was closed for a protocol failure.
    AdminRejected,
    /// A reload was applied.
    ReloadApplied,
    /// A reload was rejected.
    ReloadRejected,
    /// A shutdown phase began.
    ShutdownPhase,
    /// Wall-clock time became untrusted.
    WallClockUntrusted,
    /// Wall-clock time was trusted again.
    WallClockTrusted,
    /// A supervised task failed.
    TaskFailed,
    /// The process is terminating after a panic.
    Crash,
}

impl LogEventCode {
    /// Every code in registry order.
    pub const ALL: [Self; 22] = [
        Self::ProcessStarted,
        Self::ConfigurationLoaded,
        Self::ConfigurationRejected,
        Self::HardeningWarning,
        Self::StorageRecovered,
        Self::StorageIndeterminate,
        Self::ListenerOpened,
        Self::ListenerClosed,
        Self::AcceptPaused,
        Self::TlsHandshakeFailed,
        Self::ConnectionRefused,
        Self::SlowConsumerClosed,
        Self::OverloadClassChanged,
        Self::AdminAuthenticated,
        Self::AdminRejected,
        Self::ReloadApplied,
        Self::ReloadRejected,
        Self::ShutdownPhase,
        Self::WallClockUntrusted,
        Self::WallClockTrusted,
        Self::TaskFailed,
        Self::Crash,
    ];

    /// Returns the fixed event name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessStarted => "process-started",
            Self::ConfigurationLoaded => "configuration-loaded",
            Self::ConfigurationRejected => "configuration-rejected",
            Self::HardeningWarning => "hardening-warning",
            Self::StorageRecovered => "storage-recovered",
            Self::StorageIndeterminate => "storage-indeterminate",
            Self::ListenerOpened => "listener-opened",
            Self::ListenerClosed => "listener-closed",
            Self::AcceptPaused => "accept-paused",
            Self::TlsHandshakeFailed => "tls-handshake-failed",
            Self::ConnectionRefused => "connection-refused",
            Self::SlowConsumerClosed => "slow-consumer-closed",
            Self::OverloadClassChanged => "overload-class-changed",
            Self::AdminAuthenticated => "admin-authenticated",
            Self::AdminRejected => "admin-rejected",
            Self::ReloadApplied => "reload-applied",
            Self::ReloadRejected => "reload-rejected",
            Self::ShutdownPhase => "shutdown-phase",
            Self::WallClockUntrusted => "wall-clock-untrusted",
            Self::WallClockTrusted => "wall-clock-trusted",
            Self::TaskFailed => "task-failed",
            Self::Crash => "crash",
        }
    }
}

/// Log severity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// Informational.
    Info,
    /// Degraded but serving.
    Warning,
    /// An operation failed.
    Error,
    /// The process cannot continue.
    Critical,
}

impl Severity {
    /// Returns the fixed name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// Typed public error codes that may accompany an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PublicErrorCode {
    /// Configuration rejected.
    ConfigRejected,
    /// Storage unavailable.
    StorageUnavailable,
    /// TLS handshake failed.
    TlsFailed,
    /// Wrong or missing ALPN.
    AlpnMismatch,
    /// Memory budget exhausted.
    MemoryExhausted,
    /// Connection ceiling reached.
    ConnectionCeiling,
    /// Rate bucket empty.
    RateLimited,
    /// Output queue full.
    QueueFull,
    /// Administrative proof failed.
    AdminProofFailed,
    /// Restart-only field changed.
    RestartOnlyChange,
    /// Host control unavailable.
    HostControl,
    /// Internal invariant violated.
    Internal,
}

impl PublicErrorCode {
    /// Returns the fixed name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigRejected => "config-rejected",
            Self::StorageUnavailable => "storage-unavailable",
            Self::TlsFailed => "tls-failed",
            Self::AlpnMismatch => "alpn-mismatch",
            Self::MemoryExhausted => "memory-exhausted",
            Self::ConnectionCeiling => "connection-ceiling",
            Self::RateLimited => "rate-limited",
            Self::QueueFull => "queue-full",
            Self::AdminProofFailed => "admin-proof-failed",
            Self::RestartOnlyChange => "restart-only-change",
            Self::HostControl => "host-control",
            Self::Internal => "internal",
        }
    }
}

/// Fixed duration histogram buckets in milliseconds (upper bounds).
pub const DURATION_BUCKET_MILLIS: [u64; 8] = [1, 5, 10, 50, 100, 500, 1_000, 5_000];
/// Fixed size histogram buckets in bytes or counts (upper bounds).
pub const SIZE_BUCKET_BYTES: [u64; 8] = [
    64, 512, 4_096, 32_768, 262_144, 1_048_576, 8_388_608, 67_108_864,
];

/// A bounded duration bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DurationBucket(u8);

impl DurationBucket {
    /// Buckets a duration by the fixed upper bounds; the last bucket is open.
    #[must_use]
    pub fn from_millis(millis: u64) -> Self {
        Self(bucket_index(&DURATION_BUCKET_MILLIS, millis))
    }

    /// Returns the upper bound in milliseconds, or `None` for the open bucket.
    #[must_use]
    pub fn upper_millis(self) -> Option<u64> {
        DURATION_BUCKET_MILLIS.get(usize::from(self.0)).copied()
    }
}

/// A bounded byte or count bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CountBucket(u8);

impl CountBucket {
    /// Buckets a count by the fixed upper bounds; the last bucket is open.
    #[must_use]
    pub fn from_count(count: u64) -> Self {
        Self(bucket_index(&SIZE_BUCKET_BYTES, count))
    }

    /// Returns the upper bound, or `None` for the open bucket.
    #[must_use]
    pub fn upper(self) -> Option<u64> {
        SIZE_BUCKET_BYTES.get(usize::from(self.0)).copied()
    }
}

fn bucket_index(bounds: &[u64; 8], value: u64) -> u8 {
    let position = bounds.iter().position(|bound| value <= *bound);
    u8::try_from(position.unwrap_or(bounds.len())).unwrap_or(u8::MAX)
}

/// A fresh process-local correlation number: random base plus a counter, never a
/// protocol identifier (spec 6682-6683).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CorrelationNumber(u64);

impl fmt::Display for CorrelationNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:016x}", self.0)
    }
}

/// Issues correlation numbers from a random process base.
#[derive(Debug)]
pub struct CorrelationSource {
    base: u64,
    counter: u64,
}

impl CorrelationSource {
    /// Starts from a random base drawn once at process start.
    #[must_use]
    pub const fn new(base: u64) -> Self {
        Self { base, counter: 0 }
    }

    /// Issues the next number.
    pub fn issue(&mut self) -> CorrelationNumber {
        let number = CorrelationNumber(self.base.wrapping_add(self.counter));
        self.counter = self.counter.wrapping_add(1);
        number
    }
}

/// The complete set of fields a log event may carry (spec 6678-6683).
#[derive(Clone, Copy)]
pub struct LogEventFields {
    /// Event code.
    pub code: LogEventCode,
    /// Severity.
    pub severity: Severity,
    /// Coarse UTC second.
    pub utc_second: UtcSecond,
    /// Local server identity.
    pub server_id: ServerId,
    /// Software version string from the build.
    pub version: &'static str,
    /// Listener purpose when the event concerns a listener.
    pub listener_purpose: Option<ListenerPurpose>,
    /// Typed public error code.
    pub error_code: Option<PublicErrorCode>,
    /// Bounded duration bucket.
    pub duration: Option<DurationBucket>,
    /// Bounded byte or count bucket.
    pub count: Option<CountBucket>,
    /// Process-local correlation number.
    pub correlation: CorrelationNumber,
}

/// One structured log event whose only fields are the closed allowed set.
///
/// The type deliberately implements `Display` only; it never carries a string
/// and is never formatted through `Debug`.
#[derive(Clone, Copy)]
pub struct LogEvent {
    fields: LogEventFields,
}

impl LogEvent {
    /// Builds one event from the closed field set.
    #[must_use]
    pub const fn new(fields: LogEventFields) -> Self {
        Self { fields }
    }

    /// Returns the event code.
    #[must_use]
    pub const fn code(&self) -> LogEventCode {
        self.fields.code
    }

    /// Returns the severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.fields.severity
    }

    /// Returns the correlation number.
    #[must_use]
    pub const fn correlation(&self) -> CorrelationNumber {
        self.fields.correlation
    }
}

impl fmt::Display for LogEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fields = &self.fields;
        write!(
            formatter,
            "event={} severity={} utc={} server={} version={}",
            fields.code.as_str(),
            fields.severity.as_str(),
            fields.utc_second.get(),
            fields.server_id.to_base64url(),
            fields.version
        )?;
        if let Some(purpose) = fields.listener_purpose {
            write!(formatter, " listener={}", purpose.as_str())?;
        }
        if let Some(error) = fields.error_code {
            write!(formatter, " error={}", error.as_str())?;
        }
        if let Some(duration) = fields.duration {
            write!(formatter, " duration_bucket={}", duration.0)?;
        }
        if let Some(count) = fields.count {
            write!(formatter, " count_bucket={}", count.0)?;
        }
        write!(formatter, " correlation={}", fields.correlation)
    }
}

/// Transport families for metric labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransportFamily {
    /// Direct TCP with TLS.
    Direct,
    /// Onion Unix socket.
    Onion,
    /// Local Unix socket.
    Local,
}

/// Command classes for metric labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CommandClass {
    /// Registration and capability negotiation.
    Registration,
    /// Authentication and account service.
    Authentication,
    /// Channel membership and modes.
    Channel,
    /// Messages.
    Message,
    /// Queries.
    Query,
    /// Administration.
    Admin,
}

/// Bounded result classes for metric labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResultClass {
    /// Accepted.
    Accepted,
    /// Rejected by validation or authorization.
    Rejected,
    /// Refused by admission or overload.
    Busy,
    /// Failed internally.
    Failed,
}

/// Bounded queue names for metric labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum QueueName {
    /// Connection reader to StateCore.
    Inbound,
    /// StateCore to connection writer.
    Outbound,
    /// StateCore to storage.
    Storage,
    /// StateCore to crypto pool.
    Crypto,
    /// Signal and maintenance events.
    Maintenance,
}

/// The fixed metric label vocabulary (spec 6701-6707).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MetricLabel {
    /// Node role.
    Role(NodeRole),
    /// Listener purpose.
    ListenerPurpose(ListenerPurpose),
    /// Transport family.
    TransportFamily(TransportFamily),
    /// Command class.
    CommandClass(CommandClass),
    /// Result class.
    ResultClass(ResultClass),
    /// Queue name.
    QueueName(QueueName),
    /// Peer server identity, only on the private operator endpoint.
    PeerServerId(ServerId),
}

impl MetricLabel {
    /// Returns the fixed label key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Role(_) => "role",
            Self::ListenerPurpose(_) => "listener",
            Self::TransportFamily(_) => "transport",
            Self::CommandClass(_) => "command",
            Self::ResultClass(_) => "result",
            Self::QueueName(_) => "queue",
            Self::PeerServerId(_) => "peer",
        }
    }

    /// Returns the label value drawn from the closed vocabulary.
    #[must_use]
    pub fn value(self) -> String {
        match self {
            Self::Role(role) => role.as_str().to_owned(),
            Self::ListenerPurpose(purpose) => purpose.as_str().to_owned(),
            Self::TransportFamily(family) => match family {
                TransportFamily::Direct => "direct",
                TransportFamily::Onion => "onion",
                TransportFamily::Local => "local",
            }
            .to_owned(),
            Self::CommandClass(class) => match class {
                CommandClass::Registration => "registration",
                CommandClass::Authentication => "authentication",
                CommandClass::Channel => "channel",
                CommandClass::Message => "message",
                CommandClass::Query => "query",
                CommandClass::Admin => "admin",
            }
            .to_owned(),
            Self::ResultClass(class) => match class {
                ResultClass::Accepted => "accepted",
                ResultClass::Rejected => "rejected",
                ResultClass::Busy => "busy",
                ResultClass::Failed => "failed",
            }
            .to_owned(),
            Self::QueueName(queue) => match queue {
                QueueName::Inbound => "inbound",
                QueueName::Outbound => "outbound",
                QueueName::Storage => "storage",
                QueueName::Crypto => "crypto",
                QueueName::Maintenance => "maintenance",
            }
            .to_owned(),
            Self::PeerServerId(server_id) => server_id.to_base64url(),
        }
    }
}

/// Readiness inputs; readiness is false until every required input is ready
/// (spec 6708-6710).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadinessGate {
    /// Configuration validated.
    pub config: bool,
    /// Keys loaded.
    pub keys: bool,
    /// Storage recovery complete.
    pub storage_recovered: bool,
    /// StateCore constructed.
    pub state_core: bool,
    /// Required federation synchronization complete, or not required.
    pub federation_sync: bool,
    /// Required E2EE synchronization complete, or not required.
    pub e2ee_sync: bool,
}

impl ReadinessGate {
    /// Returns whether the node is ready.
    #[must_use]
    pub const fn ready(self) -> bool {
        self.config
            && self.keys
            && self.storage_recovered
            && self.state_core
            && self.federation_sync
            && self.e2ee_sync
    }
}

/// Liveness progress counters for the supervisor and StateCore loops (spec 6710-6711).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Liveness {
    /// Supervisor loop iterations.
    pub supervisor_tick: u64,
    /// StateCore loop iterations.
    pub state_core_tick: u64,
}

impl Liveness {
    /// Returns whether both loops advanced since `previous`.
    #[must_use]
    pub const fn progressed_since(self, previous: Self) -> bool {
        self.supervisor_tick > previous.supervisor_tick
            && self.state_core_tick > previous.state_core_tick
    }
}
