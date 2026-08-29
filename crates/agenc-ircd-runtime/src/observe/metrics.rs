//! Counters and fixed-bucket histograms with a closed label vocabulary
//! (spec 25.3, lines 6701-6707).
//!
//! Every label is a closed enum value; no nickname, account, channel,
//! message, address prefix, error text, or arbitrary input can become a
//! label by construction. The peer Server ID label is allowed only on the
//! private operator endpoint, so snapshots are taken through a view that
//! strips it for any other reader.

use std::collections::BTreeMap;

use agenc_ircd_types::ServerId;

use crate::RuntimeError;
use crate::observe::events::{CountBucket, DurationBucket};
use crate::purpose::ListenerPurpose;
use crate::sync::{Mutex, lock};

/// Ceiling on distinct series: the closed vocabulary times the 64 peers
/// (spec line 8973) cannot reach it, so reaching it is an invariant
/// violation rather than growth.
pub const MAX_METRIC_SERIES: usize = 4_096;
/// Labels one series may carry.
pub const MAX_LABELS_PER_SERIES: usize = 3;

/// The node role label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NodeRole {
    /// A core-only standalone node.
    Standalone,
    /// The federation coordinator.
    Coordinator,
    /// A federation edge.
    Edge,
}

/// The transport family label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TransportFamily {
    /// A TCP listener.
    Tcp,
    /// A Unix-socket listener.
    Unix,
}

/// The command class label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CommandClass {
    /// CAP negotiation.
    Capability,
    /// NICK, USER, PASS, and registration completion.
    Registration,
    /// AUTHENTICATE, ACCTCREATE, and ACCTCRED.
    Authentication,
    /// Session-level commands such as AWAY and MONITOR.
    Session,
    /// JOIN, PART, MODE, TOPIC, INVITE, KICK, NAMES, LIST.
    Channel,
    /// PRIVMSG, NOTICE, TAGMSG.
    Message,
    /// WHO, WHOIS, and other queries.
    Query,
    /// Moderation commands.
    Moderation,
    /// Administrative commands.
    Administration,
    /// PING, PONG, QUIT.
    Keepalive,
    /// Anything else.
    Other,
}

/// The bounded result class label.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResultClass {
    /// Completed.
    Ok,
    /// Rejected by validation or authorization.
    Rejected,
    /// Refused by admission or a full queue.
    Busy,
    /// The connection closed.
    Closed,
    /// An internal or storage failure.
    Error,
}

/// The bounded queue name label (spec 21.3 table).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum QueueName {
    /// Connection reader to StateCore.
    StateCoreInbox,
    /// StateCore to a connection writer.
    ClientWriter,
    /// StateCore to storage.
    StorageBatches,
    /// Storage to StateCore.
    StorageCompletions,
    /// StateCore to the crypto pool.
    CryptoJobs,
    /// Signal and maintenance to StateCore.
    SignalMaintenance,
    /// Emitters to the log writer.
    Log,
}

/// The closed label vocabulary (spec lines 6703-6705).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricLabel {
    /// The node role.
    Role(NodeRole),
    /// The listener purpose.
    ListenerPurpose(ListenerPurpose),
    /// The transport family.
    TransportFamily(TransportFamily),
    /// The command class.
    CommandClass(CommandClass),
    /// The result class.
    ResultClass(ResultClass),
    /// The queue name.
    QueueName(QueueName),
    /// A peer Server ID; private operator endpoint only.
    PeerServerId(ServerId),
}

impl MetricLabel {
    /// Returns whether the label may leave the private operator endpoint.
    #[must_use]
    pub const fn is_public(self) -> bool {
        !matches!(self, Self::PeerServerId(_))
    }
}

/// The closed metric names.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricName {
    /// Connections admitted after both permits were acquired.
    ConnectionsAdmitted,
    /// Connections refused before any task was spawned.
    ConnectionsRefused,
    /// Connections closed, by result class.
    ConnectionsClosed,
    /// Commands handled, by class and result.
    CommandsHandled,
    /// Current depth of a bounded queue.
    QueueDepth,
    /// TLS handshake duration.
    HandshakeDuration,
    /// Command handling duration.
    CommandDuration,
    /// Durable batch bytes.
    BatchBytes,
    /// Overload class transitions.
    OverloadTransitions,
    /// Log events dropped by a full queue.
    LogEventsDropped,
}

/// At most three labels in canonical order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LabelSet {
    labels: [Option<MetricLabel>; MAX_LABELS_PER_SERIES],
}

impl LabelSet {
    /// The label-free set.
    pub const NONE: Self = Self {
        labels: [None; MAX_LABELS_PER_SERIES],
    };

    /// Sorts and stores at most three distinct labels.
    pub fn new(labels: &[MetricLabel]) -> Result<Self, RuntimeError> {
        if labels.len() > MAX_LABELS_PER_SERIES {
            return Err(RuntimeError::LimitExceeded);
        }
        let mut sorted = labels.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != labels.len() {
            return Err(RuntimeError::InvalidValue);
        }
        let mut set = Self::NONE;
        for (slot, label) in set.labels.iter_mut().zip(sorted) {
            *slot = Some(label);
        }
        Ok(set)
    }

    /// Iterates the present labels.
    pub fn iter(&self) -> impl Iterator<Item = MetricLabel> + '_ {
        self.labels.iter().flatten().copied()
    }

    /// Returns whether every label may leave the private endpoint.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.iter().all(MetricLabel::is_public)
    }
}

/// One series identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MetricKey {
    /// The metric name.
    pub name: MetricName,
    /// The labels.
    pub labels: LabelSet,
}

/// Fixed duration buckets: one counter per [`DurationBucket`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DurationHistogram {
    counts: [u64; 6],
}

impl DurationHistogram {
    fn record(&mut self, millis: u64) {
        let index = match DurationBucket::from_millis(millis) {
            DurationBucket::UpTo1Ms => 0,
            DurationBucket::UpTo10Ms => 1,
            DurationBucket::UpTo100Ms => 2,
            DurationBucket::UpTo1S => 3,
            DurationBucket::UpTo10S => 4,
            DurationBucket::Over10S => 5,
        };
        if let Some(count) = self.counts.get_mut(index) {
            *count = count.saturating_add(1);
        }
    }

    /// Returns the count in each bucket, smallest first.
    #[must_use]
    pub const fn counts(&self) -> [u64; 6] {
        self.counts
    }
}

/// Fixed count buckets: one counter per [`CountBucket`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountHistogram {
    counts: [u64; 7],
}

impl CountHistogram {
    fn record(&mut self, value: u64) {
        let index = match CountBucket::from_count(value) {
            CountBucket::UpTo1 => 0,
            CountBucket::UpTo10 => 1,
            CountBucket::UpTo100 => 2,
            CountBucket::UpTo1K => 3,
            CountBucket::UpTo10K => 4,
            CountBucket::UpTo100K => 5,
            CountBucket::Over100K => 6,
        };
        if let Some(count) = self.counts.get_mut(index) {
            *count = count.saturating_add(1);
        }
    }

    /// Returns the count in each bucket, smallest first.
    #[must_use]
    pub const fn counts(&self) -> [u64; 7] {
        self.counts
    }
}

#[derive(Default)]
struct MetricsState {
    counters: BTreeMap<MetricKey, u64>,
    durations: BTreeMap<MetricKey, DurationHistogram>,
    counts: BTreeMap<MetricKey, CountHistogram>,
}

impl MetricsState {
    fn series(&self) -> usize {
        self.counters
            .len()
            .saturating_add(self.durations.len())
            .saturating_add(self.counts.len())
    }
}

/// Who reads a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricsView {
    /// The private operator endpoint; every label is visible.
    Operator,
    /// Any other reader; peer Server ID series are omitted.
    Public,
}

/// The process-wide registry.
pub struct MetricsRegistry {
    state: Mutex<MetricsState>,
}

impl MetricsRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MetricsState::default()),
        }
    }

    /// Adds `by` to a counter series, creating it under the series ceiling.
    pub fn increment(&self, key: MetricKey, by: u64) -> Result<(), RuntimeError> {
        let mut state = lock(&self.state);
        if !state.counters.contains_key(&key) && state.series() >= MAX_METRIC_SERIES {
            return Err(RuntimeError::LimitExceeded);
        }
        let counter = state.counters.entry(key).or_insert(0);
        *counter = counter.saturating_add(by);
        Ok(())
    }

    /// Records one duration observation in fixed buckets.
    pub fn observe_duration(&self, key: MetricKey, millis: u64) -> Result<(), RuntimeError> {
        let mut state = lock(&self.state);
        if !state.durations.contains_key(&key) && state.series() >= MAX_METRIC_SERIES {
            return Err(RuntimeError::LimitExceeded);
        }
        state.durations.entry(key).or_default().record(millis);
        Ok(())
    }

    /// Records one count or byte observation in fixed buckets.
    pub fn observe_count(&self, key: MetricKey, value: u64) -> Result<(), RuntimeError> {
        let mut state = lock(&self.state);
        if !state.counts.contains_key(&key) && state.series() >= MAX_METRIC_SERIES {
            return Err(RuntimeError::LimitExceeded);
        }
        state.counts.entry(key).or_default().record(value);
        Ok(())
    }

    /// Copies every series the view may see.
    #[must_use]
    pub fn snapshot(&self, view: MetricsView) -> MetricsSnapshot {
        let state = lock(&self.state);
        let visible = |key: &MetricKey| view == MetricsView::Operator || key.labels.is_public();
        MetricsSnapshot {
            counters: state
                .counters
                .iter()
                .filter(|(key, _)| visible(key))
                .map(|(key, value)| (*key, *value))
                .collect(),
            durations: state
                .durations
                .iter()
                .filter(|(key, _)| visible(key))
                .map(|(key, value)| (*key, *value))
                .collect(),
            counts: state
                .counts
                .iter()
                .filter(|(key, _)| visible(key))
                .map(|(key, value)| (*key, *value))
                .collect(),
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// One copy of the registry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetricsSnapshot {
    /// Counter series.
    pub counters: Vec<(MetricKey, u64)>,
    /// Duration histogram series.
    pub durations: Vec<(MetricKey, DurationHistogram)>,
    /// Count histogram series.
    pub counts: Vec<(MetricKey, CountHistogram)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: MetricName, labels: &[MetricLabel]) -> Result<MetricKey, RuntimeError> {
        Ok(MetricKey {
            name,
            labels: LabelSet::new(labels)?,
        })
    }

    #[test]
    fn label_sets_are_sorted_distinct_and_bounded() -> Result<(), RuntimeError> {
        let ordered = LabelSet::new(&[
            MetricLabel::ResultClass(ResultClass::Ok),
            MetricLabel::Role(NodeRole::Standalone),
        ])?;
        let reversed = LabelSet::new(&[
            MetricLabel::Role(NodeRole::Standalone),
            MetricLabel::ResultClass(ResultClass::Ok),
        ])?;
        assert_eq!(ordered, reversed);
        assert_eq!(ordered.iter().count(), 2);
        assert!(ordered.is_public());
        assert_eq!(
            LabelSet::new(&[
                MetricLabel::Role(NodeRole::Edge),
                MetricLabel::Role(NodeRole::Edge)
            ])
            .err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            LabelSet::new(&[
                MetricLabel::Role(NodeRole::Edge),
                MetricLabel::TransportFamily(TransportFamily::Tcp),
                MetricLabel::CommandClass(CommandClass::Other),
                MetricLabel::QueueName(QueueName::Log),
            ])
            .err(),
            Some(RuntimeError::LimitExceeded)
        );
        let peer = LabelSet::new(&[MetricLabel::PeerServerId(ServerId::from_bytes([1; 16]))])?;
        assert!(!peer.is_public());
        assert!(LabelSet::NONE.is_public());
        assert!(MetricLabel::ListenerPurpose(ListenerPurpose::ClientTls).is_public());
        Ok(())
    }

    #[test]
    fn counters_and_histograms_record_under_the_series_ceiling_and_filter_by_view()
    -> Result<(), RuntimeError> {
        let registry = MetricsRegistry::new();
        let admitted = key(
            MetricName::ConnectionsAdmitted,
            &[MetricLabel::ListenerPurpose(ListenerPurpose::ClientTls)],
        )?;
        registry.increment(admitted, 2)?;
        registry.increment(admitted, u64::MAX)?;
        let peer = key(
            MetricName::CommandsHandled,
            &[MetricLabel::PeerServerId(ServerId::from_bytes([2; 16]))],
        )?;
        registry.increment(peer, 1)?;
        let handshake = key(MetricName::HandshakeDuration, &[])?;
        registry.observe_duration(handshake, 0)?;
        registry.observe_duration(handshake, 10)?;
        registry.observe_duration(handshake, 10_001)?;
        let batch = key(
            MetricName::BatchBytes,
            &[MetricLabel::QueueName(QueueName::StorageBatches)],
        )?;
        registry.observe_count(batch, 1)?;
        registry.observe_count(batch, 100_001)?;
        let operator = registry.snapshot(MetricsView::Operator);
        assert_eq!(operator.counters.len(), 2);
        assert!(operator.counters.contains(&(admitted, u64::MAX)));
        let durations = operator
            .durations
            .first()
            .map(|(_, histogram)| histogram.counts());
        assert_eq!(durations, Some([1, 1, 0, 0, 0, 1]));
        let counts = operator
            .counts
            .first()
            .map(|(_, histogram)| histogram.counts());
        assert_eq!(counts, Some([1, 0, 0, 0, 0, 0, 1]));
        let public = registry.snapshot(MetricsView::Public);
        assert_eq!(public.counters.len(), 1, "the peer series is stripped");
        assert_eq!(public.durations.len(), 1);
        assert_eq!(public.counts.len(), 1);
        let defaulted = MetricsRegistry::default().snapshot(MetricsView::Public);
        assert_eq!(defaulted, MetricsSnapshot::default());
        Ok(())
    }

    #[test]
    fn the_series_ceiling_refuses_new_series_but_not_updates() -> Result<(), RuntimeError> {
        let registry = MetricsRegistry::new();
        let purposes = ListenerPurpose::ALL;
        let classes = [
            ResultClass::Ok,
            ResultClass::Rejected,
            ResultClass::Busy,
            ResultClass::Closed,
            ResultClass::Error,
        ];
        let mut inserted = 0;
        let mut refused = None;
        for peer in 0..=255_u8 {
            for purpose in purposes {
                for class in classes {
                    let key = key(
                        MetricName::CommandsHandled,
                        &[
                            MetricLabel::PeerServerId(ServerId::from_bytes([peer; 16])),
                            MetricLabel::ListenerPurpose(purpose),
                            MetricLabel::ResultClass(class),
                        ],
                    )?;
                    match registry.increment(key, 1) {
                        Ok(()) => inserted += 1,
                        Err(error) => {
                            refused = Some((error, key));
                            break;
                        }
                    }
                }
                if refused.is_some() {
                    break;
                }
            }
            if refused.is_some() {
                break;
            }
        }
        assert_eq!(inserted, MAX_METRIC_SERIES);
        let (error, _) = refused.ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(error, RuntimeError::LimitExceeded);
        let existing = key(
            MetricName::CommandsHandled,
            &[
                MetricLabel::PeerServerId(ServerId::from_bytes([0; 16])),
                MetricLabel::ListenerPurpose(ListenerPurpose::ClientTls),
                MetricLabel::ResultClass(ResultClass::Ok),
            ],
        )?;
        assert_eq!(registry.increment(existing, 1), Ok(()));
        assert_eq!(
            registry.observe_duration(existing, 1).err(),
            Some(RuntimeError::LimitExceeded)
        );
        assert_eq!(
            registry.observe_count(existing, 1).err(),
            Some(RuntimeError::LimitExceeded)
        );
        Ok(())
    }
}
