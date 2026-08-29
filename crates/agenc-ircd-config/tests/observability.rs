#![forbid(unsafe_code)]

//! The closed log registry renders only allowed fields, the metric labels are closed,
//! and the health model composes as specified.

use agenc_ircd_config::{
    CommandClass, CorrelationSource, CountBucket, DURATION_BUCKET_MILLIS, DurationBucket,
    ListenerPurpose, Liveness, LogEvent, LogEventCode, LogEventFields, MetricLabel, NodeRole,
    PublicErrorCode, QueueName, ReadinessGate, ResultClass, SIZE_BUCKET_BYTES, Severity,
    TransportFamily,
};
use agenc_ircd_types::{ServerId, UtcSecond};

/// Strings that must never appear in a rendered event: the adversarial context a
/// caller might be tempted to include (spec 6685-6691).
const FORBIDDEN: [&str; 8] = [
    "192.0.2.", "2001:db8", "alice", "#channel", "password", "login@", ".onion", "PRIVMSG",
];

const ALLOWED_KEYS: [&str; 10] = [
    "event",
    "severity",
    "utc",
    "server",
    "version",
    "listener",
    "error",
    "duration_bucket",
    "count_bucket",
    "correlation",
];

#[test]
fn every_event_code_renders_only_closed_key_value_pairs() -> Result<(), Box<dyn std::error::Error>>
{
    let mut source = CorrelationSource::new(0x1234_5678_9abc_def0);
    for code in LogEventCode::ALL {
        let event = LogEvent::new(LogEventFields {
            code,
            severity: Severity::Warning,
            utc_second: UtcSecond::new(1_700_000_000)?,
            server_id: ServerId::from_bytes([2; 16]),
            version: "0.0.0",
            listener_purpose: Some(ListenerPurpose::ClientOnion),
            error_code: Some(PublicErrorCode::TlsFailed),
            duration: Some(DurationBucket::from_millis(7)),
            count: Some(CountBucket::from_count(70_000_000)),
            correlation: source.issue(),
        });
        let rendered = event.to_string();
        for token in rendered.split(' ') {
            let (key, value) = token.split_once('=').ok_or("token without '='")?;
            assert!(ALLOWED_KEYS.contains(&key), "unexpected key {key}");
            assert!(!value.is_empty() && value.is_ascii());
        }
        for forbidden in FORBIDDEN {
            assert!(!rendered.contains(forbidden));
        }
        assert!(rendered.starts_with(&format!(
            "event={} severity=warning utc=1700000000 server=",
            code.as_str()
        )));
        assert!(rendered.contains(
            " listener=client_onion error=tls-failed duration_bucket=2 count_bucket=8 correlation="
        ));
        assert_eq!(event.code(), code);
        assert_eq!(event.severity(), Severity::Warning);
    }
    let minimal = LogEvent::new(LogEventFields {
        code: LogEventCode::ProcessStarted,
        severity: Severity::Info,
        utc_second: UtcSecond::new(0)?,
        server_id: ServerId::from_bytes([2; 16]),
        version: "0.0.0",
        listener_purpose: None,
        error_code: None,
        duration: None,
        count: None,
        correlation: source.issue(),
    });
    let rendered = minimal.to_string();
    assert!(
        !rendered.contains("listener=")
            && !rendered.contains("error=")
            && !rendered.contains("bucket=")
    );
    assert_eq!(rendered.split(' ').count(), 6);
    Ok(())
}

#[test]
fn correlation_numbers_advance_from_the_random_base() {
    let mut source = CorrelationSource::new(u64::MAX - 1);
    let first = source.issue();
    let second = source.issue();
    let third = source.issue();
    assert_ne!(first, second);
    assert_ne!(second, third);
    assert_eq!(third.to_string(), "0000000000000000");
    assert_eq!(first.to_string().len(), 16);
}

#[test]
fn buckets_follow_the_fixed_upper_bounds() {
    for (index, bound) in DURATION_BUCKET_MILLIS.iter().enumerate() {
        assert_eq!(
            DurationBucket::from_millis(*bound).upper_millis(),
            Some(*bound)
        );
        let previous = index
            .checked_sub(1)
            .and_then(|i| DURATION_BUCKET_MILLIS.get(i))
            .copied();
        assert_eq!(
            DurationBucket::from_millis(bound - 1).upper_millis(),
            Some(previous.map_or(*bound, |_| *bound).min(*bound))
        );
    }
    assert_eq!(DurationBucket::from_millis(5_001).upper_millis(), None);
    assert_eq!(DurationBucket::from_millis(0).upper_millis(), Some(1));
    for bound in SIZE_BUCKET_BYTES {
        assert_eq!(CountBucket::from_count(bound).upper(), Some(bound));
    }
    assert_eq!(CountBucket::from_count(u64::MAX).upper(), None);
    assert_eq!(CountBucket::from_count(65).upper(), Some(512));
}

#[test]
fn metric_labels_draw_values_from_closed_vocabularies() {
    let labels = [
        MetricLabel::Role(NodeRole::Edge),
        MetricLabel::ListenerPurpose(ListenerPurpose::AdminTls),
        MetricLabel::TransportFamily(TransportFamily::Onion),
        MetricLabel::CommandClass(CommandClass::Message),
        MetricLabel::ResultClass(ResultClass::Busy),
        MetricLabel::QueueName(QueueName::Storage),
        MetricLabel::PeerServerId(ServerId::from_bytes([3; 16])),
    ];
    let expected = [
        ("role", "edge"),
        ("listener", "admin_tls"),
        ("transport", "onion"),
        ("command", "message"),
        ("result", "busy"),
        ("queue", "storage"),
        ("peer", "AwMDAwMDAwMDAwMDAwMDAw"),
    ];
    for (label, (key, value)) in labels.iter().zip(expected) {
        assert_eq!(label.key(), key);
        assert_eq!(label.value(), value);
    }
    for family in [TransportFamily::Direct, TransportFamily::Local] {
        assert!(
            ["direct", "local"].contains(&MetricLabel::TransportFamily(family).value().as_str())
        );
    }
    for class in [
        CommandClass::Registration,
        CommandClass::Authentication,
        CommandClass::Channel,
        CommandClass::Query,
        CommandClass::Admin,
    ] {
        assert!(
            MetricLabel::CommandClass(class)
                .value()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase())
        );
    }
    for class in [
        ResultClass::Accepted,
        ResultClass::Rejected,
        ResultClass::Failed,
    ] {
        assert!(
            MetricLabel::ResultClass(class)
                .value()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase())
        );
    }
    for queue in [
        QueueName::Inbound,
        QueueName::Outbound,
        QueueName::Crypto,
        QueueName::Maintenance,
    ] {
        assert!(
            MetricLabel::QueueName(queue)
                .value()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase())
        );
    }
}

#[test]
fn readiness_requires_every_input_and_liveness_requires_both_loops() {
    let mut gate = ReadinessGate::default();
    assert!(!gate.ready());
    gate.config = true;
    gate.keys = true;
    gate.storage_recovered = true;
    gate.state_core = true;
    gate.federation_sync = true;
    assert!(!gate.ready());
    gate.e2ee_sync = true;
    assert!(gate.ready());
    let previous = Liveness {
        supervisor_tick: 1,
        state_core_tick: 1,
    };
    assert!(
        Liveness {
            supervisor_tick: 2,
            state_core_tick: 2
        }
        .progressed_since(previous)
    );
    assert!(
        !Liveness {
            supervisor_tick: 2,
            state_core_tick: 1
        }
        .progressed_since(previous)
    );
    assert!(
        !Liveness {
            supervisor_tick: 1,
            state_core_tick: 2
        }
        .progressed_since(previous)
    );
    for error in [
        PublicErrorCode::ConfigRejected,
        PublicErrorCode::StorageUnavailable,
        PublicErrorCode::AlpnMismatch,
        PublicErrorCode::MemoryExhausted,
        PublicErrorCode::ConnectionCeiling,
        PublicErrorCode::RateLimited,
        PublicErrorCode::QueueFull,
        PublicErrorCode::AdminProofFailed,
        PublicErrorCode::RestartOnlyChange,
        PublicErrorCode::HostControl,
        PublicErrorCode::Internal,
    ] {
        assert!(
            error
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        );
    }
    for severity in [Severity::Info, Severity::Error, Severity::Critical] {
        assert!(
            severity
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase())
        );
    }
}
