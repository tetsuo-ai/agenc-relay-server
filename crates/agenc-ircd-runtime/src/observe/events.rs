//! The closed log event registry (spec 25.2, lines 6676-6697).
//!
//! A [`LogEvent`] can carry only the allowed common fields: event code,
//! severity, coarse UTC second, server ID, software version, listener
//! purpose, typed public error code, bounded duration bucket, bounded
//! count bucket, and a process-local correlation number. Every field is a
//! closed enum, a bounded number, or the server's own public identity, so no
//! address, login, nickname, channel name, body, or raw input can be logged
//! by construction. The type deliberately implements no `Debug`.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use agenc_ircd_crypto::{CryptoError, OsEntropy};
use agenc_ircd_storage::{FilesystemCause, StorageError};
use agenc_ircd_types::{ServerId, UtcSecond};

use crate::RuntimeError;
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::CloseReason;

/// The software version recorded on every event.
pub const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Closed registry of loggable events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogEventCode {
    /// The process started and read its configuration.
    ProcessStarted,
    /// Configuration validation failed; the daemon does not start.
    ConfigurationRejected,
    /// Storage recovery completed and the seed was accepted.
    StorageRecovered,
    /// The storage owner entered indeterminate state; shutdown follows.
    StorageIndeterminate,
    /// StateCore reconstruction completed; readiness may become true.
    StateCoreReady,
    /// A listener opened.
    ListenerOpened,
    /// A listener closed.
    ListenerClosed,
    /// A connection was admitted after both permits were acquired.
    ConnectionAdmitted,
    /// A connection was refused before any task was spawned.
    ConnectionRefused,
    /// A connection closed.
    ConnectionClosed,
    /// A TLS handshake failed or timed out.
    TlsHandshakeFailed,
    /// The negotiated ALPN did not match the listener purpose.
    AlpnRejected,
    /// The memory overload class changed (spec 19.3).
    OverloadClassChanged,
    /// The memory budget refused a permit batch.
    MemoryExhausted,
    /// A durable storage batch entered the bounded bridge.
    StorageBatch,
    /// An administrative session authenticated.
    AdminAuthenticated,
    /// An administrative proof failed and the connection closed.
    AdminRejected,
    /// A reload was applied at one state revision.
    ReloadApplied,
    /// A reload candidate was rejected; the prior configuration stays.
    ReloadRejected,
    /// One authenticated administrative command completed or was rejected.
    AdminAction,
    /// A shutdown phase began.
    ShutdownPhase,
    /// The shutdown quiesce phase began.
    ShutdownQuiesce,
    /// The shutdown drain phase began.
    ShutdownDrain,
    /// The shutdown flush phase began.
    ShutdownFlush,
    /// The shutdown stop phase began.
    ShutdownStop,
    /// A host hardening control was absent or a lock failed.
    HardeningWarning,
    /// Wall time diverged from monotonic time for five minutes (spec 21.6).
    ClockDistrusted,
    /// Wall time was trusted again after ten continuous minutes.
    ClockTrusted,
    /// One federation link completed its authenticated hello.
    FederationLinkEstablished,
    /// One federation link ended; a failure reason raises the severity.
    FederationLinkClosed,
    /// The peer acknowledged the IRC-MLS companion profile on one link
    /// (companion 12.5); only the count leaves the process.
    E2eeProfileAcknowledged,
    /// Startup accepted a key set that retired a credential some live routes
    /// still pin; the count bucket carries how many routes are blocked
    /// (companion 9.2.1).
    E2eeRoutesBlocked,
    /// A retired credential that a live route or an unfinished receipt still
    /// requires has no configured retired-retained key; those routes stay
    /// blocked and the receipts unfinished (companion 9.2.1).
    E2eeRetiredSignerMissing,
    /// A task panicked; the process terminates after this event.
    Crash,
    /// Events were dropped because the log queue was full; the count bucket
    /// carries how many.
    LogDropped,
}

impl LogEventCode {
    /// Every registered code.
    pub const ALL: [Self; 35] = [
        Self::ProcessStarted,
        Self::ConfigurationRejected,
        Self::StorageRecovered,
        Self::StorageIndeterminate,
        Self::StateCoreReady,
        Self::ListenerOpened,
        Self::ListenerClosed,
        Self::ConnectionAdmitted,
        Self::ConnectionRefused,
        Self::ConnectionClosed,
        Self::TlsHandshakeFailed,
        Self::AlpnRejected,
        Self::OverloadClassChanged,
        Self::MemoryExhausted,
        Self::StorageBatch,
        Self::AdminAuthenticated,
        Self::AdminRejected,
        Self::ReloadApplied,
        Self::ReloadRejected,
        Self::AdminAction,
        Self::ShutdownPhase,
        Self::ShutdownQuiesce,
        Self::ShutdownDrain,
        Self::ShutdownFlush,
        Self::ShutdownStop,
        Self::HardeningWarning,
        Self::ClockDistrusted,
        Self::ClockTrusted,
        Self::FederationLinkEstablished,
        Self::FederationLinkClosed,
        Self::E2eeProfileAcknowledged,
        Self::E2eeRoutesBlocked,
        Self::E2eeRetiredSignerMissing,
        Self::Crash,
        Self::LogDropped,
    ];

    /// Returns the fixed wire label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProcessStarted => "process_started",
            Self::ConfigurationRejected => "configuration_rejected",
            Self::StorageRecovered => "storage_recovered",
            Self::StorageIndeterminate => "storage_indeterminate",
            Self::StateCoreReady => "state_core_ready",
            Self::ListenerOpened => "listener_opened",
            Self::ListenerClosed => "listener_closed",
            Self::ConnectionAdmitted => "connection_admitted",
            Self::ConnectionRefused => "connection_refused",
            Self::ConnectionClosed => "connection_closed",
            Self::TlsHandshakeFailed => "tls_handshake_failed",
            Self::AlpnRejected => "alpn_rejected",
            Self::OverloadClassChanged => "overload_class_changed",
            Self::MemoryExhausted => "memory_exhausted",
            Self::StorageBatch => "storage_batch",
            Self::AdminAuthenticated => "admin_authenticated",
            Self::AdminRejected => "admin_rejected",
            Self::ReloadApplied => "reload_applied",
            Self::ReloadRejected => "reload_rejected",
            Self::AdminAction => "admin_action",
            Self::ShutdownPhase => "shutdown_phase",
            Self::ShutdownQuiesce => "shutdown_quiesce",
            Self::ShutdownDrain => "shutdown_drain",
            Self::ShutdownFlush => "shutdown_flush",
            Self::ShutdownStop => "shutdown_stop",
            Self::HardeningWarning => "hardening_warning",
            Self::ClockDistrusted => "clock_distrusted",
            Self::ClockTrusted => "clock_trusted",
            Self::FederationLinkEstablished => "federation_link_established",
            Self::FederationLinkClosed => "federation_link_closed",
            Self::E2eeProfileAcknowledged => "e2ee_profile_acknowledged",
            Self::E2eeRoutesBlocked => "e2ee_routes_blocked",
            Self::E2eeRetiredSignerMissing => "e2ee_retired_signer_missing",
            Self::Crash => "crash",
            Self::LogDropped => "log_dropped",
        }
    }
}

/// Closed severities.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    /// Operational detail; never enabled on a public listener at runtime.
    Debug,
    /// Normal operation.
    Info,
    /// Degraded but serving.
    Warning,
    /// A request or connection failed.
    Error,
    /// The process is stopping or unsafe to continue.
    Critical,
}

impl Severity {
    /// Returns the fixed wire label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// Closed public error codes; never error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicErrorCode {
    /// Configuration did not validate.
    ConfigurationInvalid,
    /// The storage owner is unavailable or closed.
    StorageUnavailable,
    /// The storage owner reported an indeterminate commit.
    StorageIndeterminate,
    /// The memory budget refused a batch.
    MemoryExhausted,
    /// A bounded ceiling was reached.
    LimitExceeded,
    /// A runtime invariant or arithmetic check failed.
    Internal,
    /// TLS negotiation failed.
    TlsFailure,
    /// ALPN did not match.
    AlpnMismatch,
    /// Admission refused the peer before any expensive work.
    AdmissionRefused,
    /// An authentication proof failed.
    AuthenticationFailed,
    /// The operation was cancelled by its owner.
    Cancelled,
    /// The storage filesystem adapter refused an operation for this closed cause.
    FilesystemRejected(FilesystemCause),
    /// The transport ended without a protocol close.
    TransportLoss,
    /// The reader rejected an over-budget or malformed line.
    ProtocolError,
    /// The output queue reached its hard limit.
    SlowConsumer,
    /// The reader stayed paused past the inbox stall budget.
    ReadStall,
    /// A write stalled past its grace period.
    WriteStall,
    /// A registration, handshake, open-acknowledgement, or keepalive
    /// deadline expired.
    Deadline,
}

impl PublicErrorCode {
    /// Maps a runtime failure to its public code.
    #[must_use]
    pub const fn from_runtime(error: &RuntimeError) -> Self {
        match error {
            RuntimeError::BudgetArithmetic
            | RuntimeError::BudgetBelowWorkingSet
            | RuntimeError::Overflow
            | RuntimeError::InvalidValue => Self::Internal,
            RuntimeError::LimitExceeded => Self::LimitExceeded,
            RuntimeError::CommandRefused(_) => Self::AdmissionRefused,
            RuntimeError::MemoryExhausted => Self::MemoryExhausted,
            RuntimeError::Cancelled => Self::Cancelled,
            RuntimeError::Storage(StorageError::FilesystemRejected(cause)) => {
                Self::FilesystemRejected(*cause)
            }
            RuntimeError::Storage(_) => Self::StorageUnavailable,
        }
    }

    /// Maps a connection close to the closed label a `connection_closed`
    /// event carries, so a close after admission is attributable from the
    /// log alone; an orderly client quit carries none.
    #[must_use]
    pub const fn from_close(reason: CloseReason) -> Option<Self> {
        match reason {
            CloseReason::ClientQuit => None,
            CloseReason::TransportLoss => Some(Self::TransportLoss),
            CloseReason::ProtocolError => Some(Self::ProtocolError),
            CloseReason::SlowConsumer => Some(Self::SlowConsumer),
            CloseReason::ReadStall => Some(Self::ReadStall),
            CloseReason::WriteStall => Some(Self::WriteStall),
            CloseReason::Deadline => Some(Self::Deadline),
            CloseReason::Overload => Some(Self::MemoryExhausted),
            CloseReason::Shutdown => Some(Self::Cancelled),
        }
    }

    /// Returns the fixed wire label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConfigurationInvalid => "configuration_invalid",
            Self::StorageUnavailable => "storage_unavailable",
            Self::StorageIndeterminate => "storage_indeterminate",
            Self::MemoryExhausted => "memory_exhausted",
            Self::LimitExceeded => "limit_exceeded",
            Self::Internal => "internal",
            Self::TlsFailure => "tls_failure",
            Self::AlpnMismatch => "alpn_mismatch",
            Self::AdmissionRefused => "admission_refused",
            Self::AuthenticationFailed => "authentication_failed",
            Self::Cancelled => "cancelled",
            Self::FilesystemRejected(FilesystemCause::MissingState) => "filesystem_missing_state",
            Self::FilesystemRejected(FilesystemCause::PermissionRejected) => {
                "filesystem_permission_rejected"
            }
            Self::FilesystemRejected(FilesystemCause::InsufficientCapacity) => {
                "filesystem_insufficient_capacity"
            }
            Self::FilesystemRejected(FilesystemCause::Unqualified) => "filesystem_unqualified",
            Self::FilesystemRejected(FilesystemCause::IoFailure) => "filesystem_io_failure",
            Self::FilesystemRejected(FilesystemCause::UnsafePath) => "filesystem_unsafe_path",
            Self::FilesystemRejected(FilesystemCause::Unknown) => "filesystem_unknown",
            Self::TransportLoss => "transport_loss",
            Self::ProtocolError => "protocol_error",
            Self::SlowConsumer => "slow_consumer",
            Self::ReadStall => "read_stall",
            Self::WriteStall => "write_stall",
            Self::Deadline => "deadline",
        }
    }
}

/// Fixed duration buckets so timings never form a transcript (spec line
/// 6706).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DurationBucket {
    /// At most one millisecond.
    UpTo1Ms,
    /// At most ten milliseconds.
    UpTo10Ms,
    /// At most one hundred milliseconds.
    UpTo100Ms,
    /// At most one second.
    UpTo1S,
    /// At most ten seconds.
    UpTo10S,
    /// More than ten seconds.
    Over10S,
}

impl DurationBucket {
    /// Buckets a millisecond duration.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        match millis {
            0..=1 => Self::UpTo1Ms,
            2..=10 => Self::UpTo10Ms,
            11..=100 => Self::UpTo100Ms,
            101..=1_000 => Self::UpTo1S,
            1_001..=10_000 => Self::UpTo10S,
            _ => Self::Over10S,
        }
    }

    /// Returns the fixed wire label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UpTo1Ms => "le_1ms",
            Self::UpTo10Ms => "le_10ms",
            Self::UpTo100Ms => "le_100ms",
            Self::UpTo1S => "le_1s",
            Self::UpTo10S => "le_10s",
            Self::Over10S => "gt_10s",
        }
    }
}

/// Fixed byte and count buckets.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CountBucket {
    /// At most one.
    UpTo1,
    /// At most ten.
    UpTo10,
    /// At most one hundred.
    UpTo100,
    /// At most one thousand.
    UpTo1K,
    /// At most ten thousand.
    UpTo10K,
    /// At most one hundred thousand.
    UpTo100K,
    /// More than one hundred thousand.
    Over100K,
}

impl CountBucket {
    /// Buckets a count or byte total.
    #[must_use]
    pub const fn from_count(count: u64) -> Self {
        match count {
            0..=1 => Self::UpTo1,
            2..=10 => Self::UpTo10,
            11..=100 => Self::UpTo100,
            101..=1_000 => Self::UpTo1K,
            1_001..=10_000 => Self::UpTo10K,
            10_001..=100_000 => Self::UpTo100K,
            _ => Self::Over100K,
        }
    }

    /// Returns the fixed wire label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UpTo1 => "le_1",
            Self::UpTo10 => "le_10",
            Self::UpTo100 => "le_100",
            Self::UpTo1K => "le_1k",
            Self::UpTo10K => "le_10k",
            Self::UpTo100K => "le_100k",
            Self::Over100K => "gt_100k",
        }
    }
}

/// A fresh process-local correlation number; never a protocol identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelationNumber(u64);

impl CorrelationNumber {
    /// Returns the primitive number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Random process base plus a counter (spec lines 6681-6683).
pub struct CorrelationSource {
    base: u64,
    counter: AtomicU64,
}

impl CorrelationSource {
    /// Starts the sequence at an explicit base.
    #[must_use]
    pub const fn new(base: u64) -> Self {
        Self {
            base,
            counter: AtomicU64::new(0),
        }
    }

    /// Draws the base from the operating-system entropy authority.
    pub fn from_os_entropy() -> Result<Self, CryptoError> {
        let mut bytes = [0_u8; 8];
        OsEntropy::fill(&mut bytes)?;
        Ok(Self::new(u64::from_be_bytes(bytes)))
    }

    /// Issues the next number; the sum wraps deliberately because only
    /// process-local distinctness matters, never magnitude.
    pub fn next(&self) -> CorrelationNumber {
        let offset = self.counter.fetch_add(1, Ordering::Relaxed);
        CorrelationNumber(self.base.wrapping_add(offset))
    }
}

/// One structured log line holding only the allowed common fields.
pub struct LogEvent {
    code: LogEventCode,
    severity: Severity,
    utc_second: UtcSecond,
    server_id: ServerId,
    listener_purpose: Option<ListenerPurpose>,
    error_code: Option<PublicErrorCode>,
    duration: Option<DurationBucket>,
    count: Option<CountBucket>,
    correlation: CorrelationNumber,
}

impl LogEvent {
    /// Creates an event with the mandatory fields only.
    #[must_use]
    pub const fn new(
        code: LogEventCode,
        severity: Severity,
        utc_second: UtcSecond,
        server_id: ServerId,
        correlation: CorrelationNumber,
    ) -> Self {
        Self {
            code,
            severity,
            utc_second,
            server_id,
            listener_purpose: None,
            error_code: None,
            duration: None,
            count: None,
            correlation,
        }
    }

    /// Attaches the listener purpose.
    #[must_use]
    pub const fn with_purpose(mut self, purpose: ListenerPurpose) -> Self {
        self.listener_purpose = Some(purpose);
        self
    }

    /// Attaches a typed public error code.
    #[must_use]
    pub const fn with_error(mut self, error: PublicErrorCode) -> Self {
        self.error_code = Some(error);
        self
    }

    /// Attaches a bounded duration bucket.
    #[must_use]
    pub const fn with_duration(mut self, duration: DurationBucket) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Attaches a bounded count bucket.
    #[must_use]
    pub const fn with_count(mut self, count: CountBucket) -> Self {
        self.count = Some(count);
        self
    }

    /// Returns the event code.
    #[must_use]
    pub const fn code(&self) -> LogEventCode {
        self.code
    }

    /// Returns the severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the coarse UTC second the event was stamped with.
    #[must_use]
    pub const fn utc_second(&self) -> UtcSecond {
        self.utc_second
    }

    /// Returns the listener purpose, if attached.
    #[must_use]
    pub const fn purpose(&self) -> Option<ListenerPurpose> {
        self.listener_purpose
    }
}

impl fmt::Display for LogEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "event={} severity={} utc={} server={} version={}",
            self.code.label(),
            self.severity.label(),
            self.utc_second.get(),
            self.server_id.to_base64url(),
            SOFTWARE_VERSION,
        )?;
        if let Some(purpose) = self.listener_purpose {
            write!(formatter, " purpose={}", purpose.label())?;
        }
        if let Some(error) = self.error_code {
            write!(formatter, " error={}", error.label())?;
        }
        if let Some(duration) = self.duration {
            write!(formatter, " duration={}", duration.label())?;
        }
        if let Some(count) = self.count {
            write!(formatter, " count={}", count.label())?;
        }
        write!(formatter, " correlation={}", self.correlation.get())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    const FORBIDDEN: [&str; 24] = [
        "198.51.100.77",
        "user-port-49152",
        "clientexampleonion.onion",
        "login-canary-value",
        "keyed-login-digest-canary",
        "password-canary-value",
        "access-token-canary-value",
        "channel-key-canary-value",
        "CN=certificate-subject-canary",
        "account-id-canary-value",
        "opaque-credential-canary",
        "user-id-canary-value",
        "nickname-canary-value",
        "#channel-canary-value",
        "message-body-canary-value",
        "tag-body-canary-value",
        "e2ee-object-canary-value",
        "keypackage-canary-value",
        "welcome-object-canary-value",
        "database-key-canary-value",
        "database-value-canary-value",
        "secret-canary-value",
        "moderation-reason-canary",
        "raw-parser-input-canary",
    ];

    fn server_id() -> ServerId {
        ServerId::from_bytes([7; 16])
    }

    #[test]
    fn every_code_renders_only_the_allowed_fixed_vocabulary() {
        let source = CorrelationSource::new(0);
        for code in LogEventCode::ALL {
            let event = LogEvent::new(
                code,
                Severity::Warning,
                UtcSecond::from_unix_seconds(1_767_225_600),
                server_id(),
                source.next(),
            )
            .with_purpose(ListenerPurpose::ClientOnion)
            .with_error(PublicErrorCode::TlsFailure)
            .with_duration(DurationBucket::UpTo1S)
            .with_count(CountBucket::UpTo10K);
            let text = event.to_string();
            assert_eq!(event.code(), code);
            assert_eq!(event.severity(), Severity::Warning);
            for forbidden in FORBIDDEN {
                assert!(!text.contains(forbidden), "{text}");
            }
            assert!(
                text.bytes().all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'=' | b' ' | b'_' | b'-' | b'.')),
                "{text}"
            );
            assert!(text.starts_with(&format!(
                "event={} severity=warning utc=1767225600 server=",
                code.label()
            )));
            assert!(text.contains(
                " purpose=client_onion error=tls_failure duration=le_1s count=le_10k correlation="
            ));
        }
        let minimal = LogEvent::new(
            LogEventCode::Crash,
            Severity::Critical,
            UtcSecond::from_unix_seconds(0),
            server_id(),
            source.next(),
        )
        .to_string();
        assert!(!minimal.contains("purpose="));
        assert!(!minimal.contains("error="));
        assert!(minimal.ends_with(&format!(" correlation={}", LogEventCode::ALL.len())));
    }

    #[test]
    fn buckets_split_at_their_exact_boundaries() {
        let durations = [
            (0, DurationBucket::UpTo1Ms),
            (1, DurationBucket::UpTo1Ms),
            (2, DurationBucket::UpTo10Ms),
            (10, DurationBucket::UpTo10Ms),
            (11, DurationBucket::UpTo100Ms),
            (100, DurationBucket::UpTo100Ms),
            (101, DurationBucket::UpTo1S),
            (1_000, DurationBucket::UpTo1S),
            (1_001, DurationBucket::UpTo10S),
            (10_000, DurationBucket::UpTo10S),
            (10_001, DurationBucket::Over10S),
            (u64::MAX, DurationBucket::Over10S),
        ];
        for (millis, expected) in durations {
            assert_eq!(DurationBucket::from_millis(millis), expected, "{millis}");
            assert!(!expected.label().is_empty());
        }
        let counts = [
            (0, CountBucket::UpTo1),
            (1, CountBucket::UpTo1),
            (2, CountBucket::UpTo10),
            (10, CountBucket::UpTo10),
            (11, CountBucket::UpTo100),
            (100, CountBucket::UpTo100),
            (101, CountBucket::UpTo1K),
            (1_000, CountBucket::UpTo1K),
            (1_001, CountBucket::UpTo10K),
            (10_000, CountBucket::UpTo10K),
            (10_001, CountBucket::UpTo100K),
            (100_000, CountBucket::UpTo100K),
            (100_001, CountBucket::Over100K),
        ];
        for (count, expected) in counts {
            assert_eq!(CountBucket::from_count(count), expected, "{count}");
            assert!(!expected.label().is_empty());
        }
    }

    #[test]
    fn public_error_codes_cover_every_runtime_error_and_severities_order() {
        let mapping = [
            (RuntimeError::BudgetArithmetic, PublicErrorCode::Internal),
            (
                RuntimeError::BudgetBelowWorkingSet,
                PublicErrorCode::Internal,
            ),
            (RuntimeError::Overflow, PublicErrorCode::Internal),
            (RuntimeError::InvalidValue, PublicErrorCode::Internal),
            (RuntimeError::LimitExceeded, PublicErrorCode::LimitExceeded),
            (
                RuntimeError::MemoryExhausted,
                PublicErrorCode::MemoryExhausted,
            ),
            (RuntimeError::Cancelled, PublicErrorCode::Cancelled),
            (
                RuntimeError::Storage(StorageError::Unavailable),
                PublicErrorCode::StorageUnavailable,
            ),
            (
                RuntimeError::Storage(StorageError::FilesystemRejected(
                    FilesystemCause::InsufficientCapacity,
                )),
                PublicErrorCode::FilesystemRejected(FilesystemCause::InsufficientCapacity),
            ),
        ];
        for cause in FilesystemCause::ALL {
            let label = PublicErrorCode::FilesystemRejected(cause).label();
            assert_eq!(label, format!("filesystem_{}", cause.label()));
        }
        for (error, expected) in mapping {
            assert_eq!(PublicErrorCode::from_runtime(&error), expected);
        }
        for code in [
            PublicErrorCode::ConfigurationInvalid,
            PublicErrorCode::StorageIndeterminate,
            PublicErrorCode::TlsFailure,
            PublicErrorCode::AlpnMismatch,
            PublicErrorCode::AdmissionRefused,
            PublicErrorCode::AuthenticationFailed,
            PublicErrorCode::TransportLoss,
            PublicErrorCode::ProtocolError,
            PublicErrorCode::SlowConsumer,
            PublicErrorCode::ReadStall,
            PublicErrorCode::WriteStall,
            PublicErrorCode::Deadline,
        ] {
            assert!(code.label().is_ascii());
            assert!(
                code.label()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
        assert!(Severity::Debug < Severity::Info);
        assert!(Severity::Error < Severity::Critical);
        assert_eq!(Severity::Info.label(), "info");
    }

    #[test]
    fn every_close_reason_maps_to_one_closed_label_except_an_orderly_quit() {
        let mapping = [
            (CloseReason::ClientQuit, None),
            (
                CloseReason::TransportLoss,
                Some(PublicErrorCode::TransportLoss),
            ),
            (
                CloseReason::ProtocolError,
                Some(PublicErrorCode::ProtocolError),
            ),
            (
                CloseReason::SlowConsumer,
                Some(PublicErrorCode::SlowConsumer),
            ),
            (CloseReason::ReadStall, Some(PublicErrorCode::ReadStall)),
            (CloseReason::WriteStall, Some(PublicErrorCode::WriteStall)),
            (CloseReason::Deadline, Some(PublicErrorCode::Deadline)),
            (
                CloseReason::Overload,
                Some(PublicErrorCode::MemoryExhausted),
            ),
            (CloseReason::Shutdown, Some(PublicErrorCode::Cancelled)),
        ];
        for (reason, expected) in mapping {
            assert_eq!(PublicErrorCode::from_close(reason), expected, "{reason:?}");
        }
        let labels = mapping
            .iter()
            .filter_map(|(_, code)| code.map(PublicErrorCode::label))
            .collect::<Vec<_>>();
        let mut distinct = labels.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), labels.len(), "close labels are distinct");
    }

    #[test]
    fn correlation_numbers_advance_from_the_base_and_wrap_without_panic() -> Result<(), CryptoError>
    {
        let source = CorrelationSource::new(u64::MAX);
        assert_eq!(source.next().get(), u64::MAX);
        assert_eq!(source.next().get(), 0);
        let drawn = CorrelationSource::from_os_entropy()?;
        let first = drawn.next();
        let second = drawn.next();
        assert_eq!(second.get(), first.get().wrapping_add(1));
        Ok(())
    }
}
