//! Closed production adapters for runtime logs, metrics, and STATS windows.

use agenc_ircd_types::{MonotonicClock as _, ServerId, WallClock as _};

use crate::RuntimeError;
use crate::admission::OverloadClass;
use crate::clock::{SystemMonotonicClock, SystemWallClock};
use crate::connection::{AdmittedConnection, ConnectionExit, PeerIdentity};
use crate::listener::{ConnectionObserver, RefusalReason, TlsOutcome};
use crate::observe::events::{
    CorrelationSource, CountBucket, LogEvent, LogEventCode, PublicErrorCode, Severity,
};
use crate::observe::log::{LogEmitOutcome, LogHandle, LogRetention};
use crate::observe::metrics::{
    CommandClass, LabelSet, MetricKey, MetricLabel, MetricName, MetricsRegistry,
    MetricsStatsValues, QueueName, ResultClass, STATS_RATE_FIELDS, StatsRateField, TransportFamily,
};
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::CloseReason;
use crate::supervisor::ShutdownPhase;
use crate::sync::Arc;
use crate::tls::TlsHandshakeError;

/// One process-wide, input-free observer shared by runtime owners.
pub struct RuntimeObserver {
    server_id: ServerId,
    wall: SystemWallClock,
    monotonic: SystemMonotonicClock,
    correlation: Arc<CorrelationSource>,
    log: LogHandle,
    metrics: Arc<MetricsRegistry>,
}

impl RuntimeObserver {
    /// Binds the single process correlation source to logs and metrics.
    #[must_use]
    pub fn new(
        server_id: ServerId,
        monotonic: SystemMonotonicClock,
        correlation: Arc<CorrelationSource>,
        log: LogHandle,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            server_id,
            wall: SystemWallClock,
            monotonic,
            correlation,
            log,
            metrics,
        }
    }

    /// Records process startup without including a configuration path.
    pub fn process_started(&self) {
        self.emit(
            LogEventCode::ProcessStarted,
            Severity::Info,
            None,
            None,
            None,
        );
    }

    /// Records successful storage recovery without exposing its path.
    pub fn storage_recovered(&self) {
        self.emit(
            LogEventCode::StorageRecovered,
            Severity::Info,
            None,
            None,
            None,
        );
    }

    /// Records an indeterminate durable outcome before shutdown.
    pub fn storage_indeterminate(&self) {
        self.emit(
            LogEventCode::StorageIndeterminate,
            Severity::Critical,
            None,
            None,
            None,
        );
    }

    /// Records the StateCore startup acknowledgement.
    pub fn state_core_ready(&self) {
        self.emit(
            LogEventCode::StateCoreReady,
            Severity::Info,
            None,
            None,
            None,
        );
    }

    /// Records one listener lifecycle edge under its closed purpose.
    pub fn listener_lifecycle(&self, purpose: ListenerPurpose, opened: bool) {
        self.emit(
            if opened {
                LogEventCode::ListenerOpened
            } else {
                LogEventCode::ListenerClosed
            },
            Severity::Info,
            Some(purpose),
            None,
            None,
        );
    }

    /// Records one federation link edge under the federation purpose. Only
    /// the closed event code and severity leave the process: never the peer
    /// address, its Server ID, or the frame that ended the link.
    pub fn federation_link(&self, established: bool, failure: bool) {
        let code = if established {
            LogEventCode::FederationLinkEstablished
        } else {
            LogEventCode::FederationLinkClosed
        };
        let severity = if failure {
            Severity::Warning
        } else {
            Severity::Info
        };
        self.emit(
            code,
            severity,
            Some(ListenerPurpose::Federation),
            None,
            None,
        );
    }

    /// Records one transition of the closed wall-clock trust state.
    pub fn clock_trust_changed(&self, trusted: bool) {
        self.emit(
            if trusted {
                LogEventCode::ClockTrusted
            } else {
                LogEventCode::ClockDistrusted
            },
            if trusted {
                Severity::Info
            } else {
                Severity::Warning
            },
            None,
            None,
            None,
        );
    }

    /// Records the fixed warning emitted when ordinary memory locking is unavailable.
    pub fn hardening_warning(&self) {
        self.emit(
            LogEventCode::HardeningWarning,
            Severity::Warning,
            None,
            None,
            None,
        );
    }

    /// Returns the closed metrics registry for authenticated snapshots.
    #[must_use]
    pub fn metrics(&self) -> Arc<MetricsRegistry> {
        Arc::clone(&self.metrics)
    }

    /// Returns process runtime values owned outside StateCore.
    #[must_use]
    pub fn runtime_values(&self) -> [u64; 3] {
        self.metrics.runtime_values(self.monotonic_second())
    }

    /// Returns the exact eight 60-second rate fields.
    pub fn rate_values(&self) -> Result<[u64; STATS_RATE_FIELDS], RuntimeError> {
        self.metrics.rate_values(self.monotonic_second())
    }

    pub(crate) fn stats_values(&self) -> Result<MetricsStatsValues, RuntimeError> {
        let second = self.monotonic_second();
        self.metrics.stats_values(second, second)
    }

    /// Marks one TLS handshake as in progress.
    pub fn tls_started(&self) {
        self.metrics.tls_started();
    }

    /// Marks one TLS handshake as complete or refused.
    pub fn tls_finished(&self, purpose: ListenerPurpose, elapsed_millis: u64, outcome: TlsOutcome) {
        self.metrics.tls_finished();
        self.observe_duration(
            MetricName::HandshakeDuration,
            &[
                MetricLabel::ListenerPurpose(purpose),
                MetricLabel::ResultClass(match outcome {
                    TlsOutcome::Established => ResultClass::Ok,
                    TlsOutcome::Refused => ResultClass::Rejected,
                }),
            ],
            elapsed_millis,
        );
    }

    /// Records one closed command/result classification.
    pub fn command_handled(&self, command: &str, result: ResultClass) {
        self.command_classified(Self::classify_command(command), result);
    }

    /// Reduces a parsed command token to the closed metric vocabulary.
    #[must_use]
    pub fn classify_command(command: &str) -> CommandClass {
        command_class(command)
    }

    /// Records a command already reduced to its closed class.
    pub fn command_classified(&self, class: CommandClass, result: ResultClass) {
        self.increment(
            MetricName::CommandsHandled,
            &[
                MetricLabel::CommandClass(class),
                MetricLabel::ResultClass(result),
            ],
            1,
        );
        let field = if result == ResultClass::Busy {
            StatsRateField::ClientCommandsRateLimited
        } else {
            StatsRateField::ClientCommandsAccepted
        };
        self.metrics.record_rate(self.monotonic_second(), field, 1);
    }

    /// Records an authentication attempt without its account or mechanism.
    pub fn authentication(&self, rejected: bool) {
        let field = if rejected {
            StatsRateField::AuthenticationRejected
        } else {
            StatsRateField::AuthenticationStarted
        };
        self.metrics.record_rate(self.monotonic_second(), field, 1);
    }

    /// Records a federation ingress byte count. Core-v1 never calls this,
    /// so both federation rate fields remain zero while federation is off.
    pub fn federation_ingress(&self, bytes: u64, rejected: bool) {
        let field = if rejected {
            StatsRateField::FederationRejectedBytes
        } else {
            StatsRateField::FederationIngressBytes
        };
        self.metrics
            .record_rate(self.monotonic_second(), field, bytes);
    }

    /// Records a bounded queue depth under a closed queue name.
    pub fn queue_depth(&self, queue: QueueName, depth: u64) {
        self.observe_count(
            MetricName::QueueDepth,
            &[MetricLabel::QueueName(queue)],
            depth,
        );
    }

    /// Records one durable batch byte count in fixed buckets.
    pub fn storage_batch(&self, bytes: u64) {
        self.observe_count(MetricName::BatchBytes, &[], bytes);
        self.emit(
            LogEventCode::StorageBatch,
            Severity::Info,
            None,
            None,
            Some(CountBucket::from_count(bytes)),
        );
    }

    /// Records one reload outcome without a path or rejection detail.
    pub fn reload(&self, applied: bool) {
        let (code, severity, result) = if applied {
            (LogEventCode::ReloadApplied, Severity::Info, ResultClass::Ok)
        } else {
            (
                LogEventCode::ReloadRejected,
                Severity::Warning,
                ResultClass::Rejected,
            )
        };
        self.emit(code, severity, None, None, None);
        self.increment(MetricName::Reloads, &[MetricLabel::ResultClass(result)], 1);
    }

    /// Publishes the validated live log-retention policy.
    pub fn set_log_retention(&self, hours: u64) -> Result<(), RuntimeError> {
        let retention = LogRetention::hours(hours)?;
        self.log.set_retention(retention);
        Ok(())
    }

    /// Records one authenticated administrative command outcome.
    pub fn admin_action(&self, result: ResultClass) {
        let severity = if result == ResultClass::Ok {
            Severity::Info
        } else {
            Severity::Warning
        };
        self.emit(LogEventCode::AdminAction, severity, None, None, None);
        self.increment(
            MetricName::CommandsHandled,
            &[
                MetricLabel::CommandClass(CommandClass::Administration),
                MetricLabel::ResultClass(result),
            ],
            1,
        );
    }

    /// Records an administrative authentication result.
    pub fn admin_authentication(&self, purpose: ListenerPurpose, admitted: bool) {
        let code = if admitted {
            LogEventCode::AdminAuthenticated
        } else {
            LogEventCode::AdminRejected
        };
        let severity = if admitted {
            Severity::Info
        } else {
            Severity::Warning
        };
        let error = (!admitted).then_some(PublicErrorCode::AuthenticationFailed);
        self.emit(code, severity, Some(purpose), error, None);
    }

    /// Records a memory overload class transition.
    pub fn overload_transition(&self, class: OverloadClass) {
        let count = match class {
            OverloadClass::Normal => 0,
            OverloadClass::NoGuests => 1,
            OverloadClass::NoNewConnections => 2,
            OverloadClass::Evict => 3,
        };
        self.emit(
            LogEventCode::OverloadClassChanged,
            Severity::Warning,
            None,
            None,
            Some(CountBucket::from_count(count)),
        );
        self.increment(MetricName::OverloadTransitions, &[], 1);
    }

    /// Records the beginning of one shutdown phase.
    pub fn shutdown_phase(&self, phase: ShutdownPhase) {
        let code = match phase {
            ShutdownPhase::Quiesce => LogEventCode::ShutdownQuiesce,
            ShutdownPhase::Drain => LogEventCode::ShutdownDrain,
            ShutdownPhase::Flush => LogEventCode::ShutdownFlush,
            ShutdownPhase::Stop => LogEventCode::ShutdownStop,
        };
        self.emit(code, Severity::Info, None, None, None);
    }

    fn monotonic_second(&self) -> u64 {
        self.monotonic.now().get() / 1_000
    }

    /// The peer acknowledged the companion profile on one link. Nothing
    /// about the tuple, the peer, or the key set leaves the process.
    pub fn e2ee_profile_acknowledged(&self) {
        self.emit(
            LogEventCode::E2eeProfileAcknowledged,
            Severity::Info,
            Some(ListenerPurpose::Federation),
            None,
            None,
        );
    }

    fn emit(
        &self,
        code: LogEventCode,
        severity: Severity,
        purpose: Option<ListenerPurpose>,
        error: Option<PublicErrorCode>,
        count: Option<CountBucket>,
    ) {
        let Ok(now) = self.wall.utc_now() else {
            return;
        };
        let mut event = LogEvent::new(code, severity, now, self.server_id, self.correlation.next());
        if let Some(purpose) = purpose {
            event = event.with_purpose(purpose);
        }
        if let Some(error) = error {
            event = event.with_error(error);
        }
        if let Some(count) = count {
            event = event.with_count(count);
        }
        if self.log.try_emit_outcome(event) == LogEmitOutcome::Full {
            self.increment(MetricName::LogEventsDropped, &[], 1);
        }
        self.observe_count(
            MetricName::QueueDepth,
            &[MetricLabel::QueueName(QueueName::Log)],
            u64::try_from(self.log.depth()).unwrap_or(u64::MAX),
        );
    }

    fn increment(&self, name: MetricName, labels: &[MetricLabel], by: u64) {
        let Ok(labels) = LabelSet::new(labels) else {
            return;
        };
        let _recorded = self.metrics.increment(MetricKey { name, labels }, by);
    }

    fn observe_count(&self, name: MetricName, labels: &[MetricLabel], value: u64) {
        let Ok(labels) = LabelSet::new(labels) else {
            return;
        };
        let _recorded = self
            .metrics
            .observe_count(MetricKey { name, labels }, value);
    }

    fn observe_duration(&self, name: MetricName, labels: &[MetricLabel], millis: u64) {
        let Ok(labels) = LabelSet::new(labels) else {
            return;
        };
        let _recorded = self
            .metrics
            .observe_duration(MetricKey { name, labels }, millis);
    }
}

impl ConnectionObserver for RuntimeObserver {
    fn listener_opened(&self, purpose: ListenerPurpose) {
        self.listener_lifecycle(purpose, true);
    }

    fn listener_closed(&self, purpose: ListenerPurpose) {
        self.listener_lifecycle(purpose, false);
    }

    fn tls_started(&self, _purpose: ListenerPurpose) {
        self.tls_started();
    }

    fn tls_finished(&self, purpose: ListenerPurpose, elapsed_millis: u64, outcome: TlsOutcome) {
        self.tls_finished(purpose, elapsed_millis, outcome);
    }

    fn admitted(&self, connection: &AdmittedConnection) {
        if is_client(connection.purpose) {
            self.metrics.client_admitted(self.monotonic_second());
        }
        self.increment(
            MetricName::ConnectionsAdmitted,
            &[
                MetricLabel::ListenerPurpose(connection.purpose),
                MetricLabel::TransportFamily(transport_family(connection.purpose)),
            ],
            1,
        );
        self.emit(
            LogEventCode::ConnectionAdmitted,
            Severity::Info,
            Some(connection.purpose),
            None,
            None,
        );
    }

    fn admin_admitted(&self, purpose: ListenerPurpose, _peer: PeerIdentity) {
        self.increment(
            MetricName::ConnectionsAdmitted,
            &[
                MetricLabel::ListenerPurpose(purpose),
                MetricLabel::TransportFamily(transport_family(purpose)),
            ],
            1,
        );
        self.emit(
            LogEventCode::ConnectionAdmitted,
            Severity::Info,
            Some(purpose),
            None,
            None,
        );
    }

    fn refused(&self, purpose: ListenerPurpose, reason: RefusalReason) {
        if is_client(purpose) {
            self.metrics.record_rate(
                self.monotonic_second(),
                StatsRateField::ConnectionsRejected,
                1,
            );
        }
        self.increment(
            MetricName::ConnectionsRefused,
            &[
                MetricLabel::ListenerPurpose(purpose),
                MetricLabel::ResultClass(ResultClass::Rejected),
            ],
            1,
        );
        let (code, error) = refusal_event(reason);
        self.emit(code, Severity::Warning, Some(purpose), Some(error), None);
    }

    fn closed(&self, exit: &ConnectionExit) {
        if is_client(exit.purpose) {
            self.metrics.client_closed();
        }
        self.increment(
            MetricName::ConnectionsClosed,
            &[
                MetricLabel::ListenerPurpose(exit.purpose),
                MetricLabel::ResultClass(close_result(exit.reason)),
            ],
            1,
        );
        self.emit(
            LogEventCode::ConnectionClosed,
            Severity::Info,
            Some(exit.purpose),
            None,
            None,
        );
    }
}

fn is_client(purpose: ListenerPurpose) -> bool {
    matches!(
        purpose,
        ListenerPurpose::ClientTls | ListenerPurpose::ClientWss | ListenerPurpose::ClientOnion
    )
}

const fn transport_family(purpose: ListenerPurpose) -> TransportFamily {
    match purpose {
        ListenerPurpose::ClientOnion | ListenerPurpose::AdminLocal => TransportFamily::Unix,
        ListenerPurpose::ClientTls
        | ListenerPurpose::ClientWss
        | ListenerPurpose::Federation
        | ListenerPurpose::AdminTls => TransportFamily::Tcp,
    }
}

const fn close_result(reason: CloseReason) -> ResultClass {
    match reason {
        CloseReason::ClientQuit | CloseReason::Shutdown => ResultClass::Ok,
        CloseReason::TransportLoss => ResultClass::Closed,
        CloseReason::SlowConsumer | CloseReason::ReadStall | CloseReason::WriteStall => {
            ResultClass::Busy
        }
        CloseReason::ProtocolError | CloseReason::Deadline | CloseReason::Overload => {
            ResultClass::Rejected
        }
    }
}

const fn refusal_event(reason: RefusalReason) -> (LogEventCode, PublicErrorCode) {
    match reason {
        RefusalReason::TlsHandshake(
            TlsHandshakeError::AlpnMissing | TlsHandshakeError::AlpnMismatch,
        ) => (LogEventCode::AlpnRejected, PublicErrorCode::AlpnMismatch),
        RefusalReason::TlsHandshake(_) => (
            LogEventCode::TlsHandshakeFailed,
            PublicErrorCode::TlsFailure,
        ),
        RefusalReason::MemoryExhausted => (
            LogEventCode::MemoryExhausted,
            PublicErrorCode::MemoryExhausted,
        ),
        RefusalReason::Admission => (
            LogEventCode::ConnectionRefused,
            PublicErrorCode::AdmissionRefused,
        ),
        RefusalReason::GlobalCeiling | RefusalReason::TaskTree => (
            LogEventCode::ConnectionRefused,
            PublicErrorCode::LimitExceeded,
        ),
        RefusalReason::PeerCredentials
        | RefusalReason::ClientCertificate
        | RefusalReason::Entropy
        | RefusalReason::AdminOwner => (
            LogEventCode::ConnectionRefused,
            PublicErrorCode::AuthenticationFailed,
        ),
    }
}

fn command_class(command: &str) -> CommandClass {
    match command {
        "CAP" => CommandClass::Capability,
        "NICK" | "USER" | "PASS" => CommandClass::Registration,
        "AUTHENTICATE" | "ACCTCREATE" | "ACCTCRED" => CommandClass::Authentication,
        "AWAY" | "MONITOR" => CommandClass::Session,
        "JOIN" | "PART" | "MODE" | "TOPIC" | "INVITE" | "KICK" | "NAMES" | "LIST" => {
            CommandClass::Channel
        }
        "PRIVMSG" | "NOTICE" | "TAGMSG" => CommandClass::Message,
        "WHO" | "WHOIS" | "WHOWAS" | "ISON" | "USERHOST" | "MOTD" | "VERSION" | "TIME" | "INFO"
        | "LINKS" | "STATS" => CommandClass::Query,
        "KILL" | "ACCOUNT" | "CHANNEL" => CommandClass::Moderation,
        "OPER" | "REHASH" | "CONNECT" | "SQUIT" | "PEER" | "BACKUP" | "AUDIT" | "RESTART"
        | "DIE" => CommandClass::Administration,
        "PING" | "PONG" | "QUIT" => CommandClass::Keepalive,
        _ => CommandClass::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::events::CorrelationSource;
    use crate::observe::log::{LogFilter, LogRetention, LogTarget, LogWriter};
    use crate::observe::metrics::{MetricsView, ResultClass};
    use agenc_ircd_types::UtcSecond;
    use std::io;

    struct MemoryTarget(Vec<String>);

    impl LogTarget for MemoryTarget {
        fn open_segment(&mut self, _hour: u64) -> io::Result<()> {
            Ok(())
        }

        fn write_line(&mut self, line: &str) -> io::Result<()> {
            self.0.push(line.to_owned());
            Ok(())
        }

        fn retire_before(&mut self, _hour: u64, _limit: usize) -> io::Result<bool> {
            Ok(true)
        }
    }

    fn observer() -> (Arc<RuntimeObserver>, LogWriter<MemoryTarget>) {
        let correlation = Arc::new(CorrelationSource::new(10));
        let (writer, log) = LogWriter::start(
            MemoryTarget(Vec::new()),
            LogRetention::DEFAULT,
            LogFilter::new(Severity::Debug),
            ServerId::from_bytes([3; 16]),
            Arc::clone(&correlation),
        );
        let observer = Arc::new(RuntimeObserver::new(
            ServerId::from_bytes([3; 16]),
            SystemMonotonicClock::start(),
            correlation,
            log,
            Arc::new(MetricsRegistry::new()),
        ));
        (observer, writer)
    }

    #[test]
    fn rate_windows_clear_reused_buckets_and_exclude_future_values() -> Result<(), RuntimeError> {
        let metrics = MetricsRegistry::new();
        metrics.record_rate(0, StatsRateField::ConnectionsAdmitted, 2);
        metrics.record_rate(59, StatsRateField::ConnectionsAdmitted, 3);
        assert_eq!(metrics.rate_values(59)?[2], 5);
        assert_eq!(metrics.rate_values(60)?[2], 3);
        metrics.record_rate(60, StatsRateField::ConnectionsAdmitted, 7);
        assert_eq!(metrics.rate_values(60)?[2], 10);
        assert_eq!(
            metrics.rate_values(59)?[2],
            3,
            "a future bucket is excluded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listener_observation_never_formats_source_or_peer_identity() {
        let (observer, writer) = observer();
        let connection = AdmittedConnection {
            generation: crate::connection::ConnectionGeneration::new(1),
            purpose: ListenerPurpose::ClientTls,
            source: crate::state_core::inbox::SourceAddressKey::ipv4([127, 0, 0, 1]),
            peer: PeerIdentity::Anonymous,
        };
        observer.admitted(&connection);
        observer.admin_admitted(
            ListenerPurpose::AdminLocal,
            PeerIdentity::LocalCredentials {
                uid: 4_294_967_000,
                gid: 4_294_966_999,
            },
        );
        observer.command_handled("PRIVMSG", ResultClass::Ok);
        let snapshot = observer.metrics().snapshot(MetricsView::Operator);
        assert!(!snapshot.counters.is_empty());
        drop(observer);
        let (target, failures) = writer.run().await;
        assert_eq!(failures, 0);
        let rendered = target.0.join("\n");
        for forbidden in ["127.0.0.1", "4294967000", "4294966999", "PRIVMSG"] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
        assert!(rendered.contains("event=connection_admitted"));
    }

    #[tokio::test]
    async fn lifecycle_events_use_only_closed_codes_and_purpose() {
        let (observer, writer) = observer();
        observer.storage_recovered();
        observer.storage_indeterminate();
        observer.state_core_ready();
        observer.clock_trust_changed(false);
        observer.clock_trust_changed(true);
        observer.listener_opened(ListenerPurpose::ClientTls);
        observer.listener_closed(ListenerPurpose::ClientTls);
        drop(observer);
        let (target, failures) = writer.run().await;
        assert_eq!(failures, 0);
        let rendered = target.0.join("\n");
        assert!(rendered.contains("event=storage_recovered"));
        assert!(rendered.contains("event=storage_indeterminate"));
        assert!(rendered.contains("event=state_core_ready"));
        assert!(rendered.contains("event=clock_distrusted"));
        assert!(rendered.contains("event=clock_trusted"));
        assert!(rendered.contains("event=listener_opened"));
        assert!(rendered.contains("event=listener_closed"));
        assert!(rendered.contains("purpose=client_tls"));
    }

    #[test]
    fn every_command_maps_to_a_closed_class_without_retaining_input() {
        assert_eq!(command_class("CAP"), CommandClass::Capability);
        assert_eq!(command_class("AUTHENTICATE"), CommandClass::Authentication);
        assert_eq!(command_class("PRIVMSG"), CommandClass::Message);
        assert_eq!(command_class("attacker supplied text"), CommandClass::Other);
        assert_eq!(UtcSecond::from_unix_seconds(0).get(), 0);
    }

    #[test]
    fn command_classification_does_not_count_an_attempt_and_completion_counts_once() {
        let (observer, _writer) = observer();
        let class = RuntimeObserver::classify_command("PRIVMSG");
        let before = observer.metrics().snapshot(MetricsView::Operator);
        assert!(
            before
                .counters
                .iter()
                .all(|(key, _)| key.name != MetricName::CommandsHandled)
        );

        observer.command_classified(class, ResultClass::Rejected);
        let completed = observer.metrics().snapshot(MetricsView::Operator);
        let handled = completed
            .counters
            .iter()
            .filter(|(key, _)| key.name == MetricName::CommandsHandled)
            .collect::<Vec<_>>();
        assert_eq!(handled.len(), 1);
        assert_eq!(handled.iter().map(|entry| entry.1).next(), Some(1));
    }

    #[test]
    fn signal_reload_records_no_fabricated_command() {
        let (observer, _writer) = observer();
        observer.reload(true);

        let snapshot = observer.metrics().snapshot(MetricsView::Operator);
        assert!(
            snapshot
                .counters
                .iter()
                .all(|(key, _)| key.name != MetricName::CommandsHandled)
        );
        assert_eq!(
            counter_value(&snapshot, MetricName::Reloads, ResultClass::Ok),
            1
        );
    }

    #[test]
    fn rehash_reload_and_admin_completion_count_one_command() {
        let (observer, _writer) = observer();
        observer.reload(false);
        observer.admin_action(ResultClass::Rejected);

        let snapshot = observer.metrics().snapshot(MetricsView::Operator);
        assert_eq!(
            counter_value(
                &snapshot,
                MetricName::CommandsHandled,
                ResultClass::Rejected
            ),
            1
        );
        assert_eq!(
            counter_value(&snapshot, MetricName::Reloads, ResultClass::Rejected),
            1
        );
    }

    fn counter_value(
        snapshot: &crate::observe::metrics::MetricsSnapshot,
        name: MetricName,
        result: ResultClass,
    ) -> u64 {
        snapshot
            .counters
            .iter()
            .find(|(key, _)| {
                key.name == name
                    && key
                        .labels
                        .iter()
                        .any(|label| label == MetricLabel::ResultClass(result))
            })
            .map_or(0, |(_, value)| *value)
    }

    #[test]
    fn closed_log_owner_is_not_reported_as_queue_saturation() {
        let (observer, writer) = observer();
        drop(writer);
        observer.process_started();
        let snapshot = observer.metrics().snapshot(MetricsView::Operator);
        assert!(
            snapshot
                .counters
                .iter()
                .all(|(key, _)| key.name != MetricName::LogEventsDropped)
        );
    }

    #[test]
    fn tls_durations_carry_only_the_closed_handshake_outcome() -> Result<(), RuntimeError> {
        let (observer, writer) = observer();
        observer.tls_started();
        observer.tls_finished(ListenerPurpose::ClientTls, 7, TlsOutcome::Established);
        observer.tls_started();
        observer.tls_finished(ListenerPurpose::ClientTls, 7, TlsOutcome::Refused);
        assert_eq!(observer.runtime_values()[2], 0);
        let snapshot = observer.metrics().snapshot(MetricsView::Operator);
        let result_labels = snapshot
            .durations
            .iter()
            .filter(|(key, _)| key.name == MetricName::HandshakeDuration)
            .flat_map(|(key, _)| key.labels.iter())
            .filter_map(|label| match label {
                MetricLabel::ResultClass(result) => Some(result),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(result_labels, vec![ResultClass::Ok, ResultClass::Rejected]);
        drop(writer);
        Ok(())
    }
}
