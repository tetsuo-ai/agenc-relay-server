//! `STATS` selectors, field registries, and exact batch framing (spec 4464-4519).

use crate::AdminError;
use crate::base64::encode_base64url;

/// Number of one-second buckets summed by every `*_60s` field (spec 4511-4513).
pub const STATS_SIXTY_SECOND_BUCKETS: usize = 60;

const RUNTIME_FIELDS: [&str; 9] = [
    "uptime_seconds",
    "live_client_connections",
    "tls_handshakes_in_progress",
    "registered_sessions",
    "authenticated_sessions",
    "local_channels",
    "global_channels",
    "memory_charged_bytes",
    "memory_budget_bytes",
];

// Spec 4487 declares "STORAGE (13)" but 4487-4494 enumerate fourteen names
// and 4507-4510 define semantics for every one of them. The enumerated list is
// normative here and field-count is 14 (plan Decision 7; recorded in
// conformance/stage-six-runtime-profile.toml).
const STORAGE_FIELDS: [&str; 14] = [
    "logical_database_bytes",
    "database_file_bytes",
    "database_max_bytes",
    "backup_stream_bytes",
    "backup_max_bytes",
    "state_generation",
    "manifest_sequence",
    "storage_commit_sequence",
    "account_service_response_count",
    "nonce_draw_high_water",
    "checkpoint_manifest_sequence",
    "filesystem_available_bytes",
    "filesystem_reserve_bytes",
    "pending_storage_constructions",
];

const FEDERATION_FIELDS: [&str; 7] = [
    "configured_peers",
    "active_peers",
    "quarantined_peers",
    "base_outbox_objects",
    "base_outbox_bytes",
    "base_replay_events",
    "open_cross_profile_barriers",
];

const QUEUES_FIELDS: [&str; 10] = [
    "client_queued_bytes",
    "client_queue_capacity_bytes",
    "federation_queued_bytes",
    "federation_queue_capacity_bytes",
    "crypto_jobs_in_flight",
    "crypto_job_capacity",
    "storage_jobs_in_flight",
    "storage_job_capacity",
    "query_snapshots",
    "query_snapshot_rows",
];

const RATES_FIELDS: [&str; 8] = [
    "client_commands_accepted_60s",
    "client_commands_rate_limited_60s",
    "connections_admitted_60s",
    "connections_rejected_60s",
    "authentication_started_60s",
    "authentication_rejected_60s",
    "federation_ingress_bytes_60s",
    "federation_rejected_bytes_60s",
];

const E2EE_FIELDS: [&str; 9] = [
    "enabled",
    "active_conversations",
    "recovery_pending_routes",
    "directory_objects",
    "mailbox_objects",
    "stored_objects",
    "stored_bytes",
    "global_disk_bytes_limit",
    "pending_candidates",
];

/// The closed `STATS` selector set (spec 4442).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatsSelector {
    /// Process and session counts.
    Runtime,
    /// Storage accounting.
    Storage,
    /// Federation peer and outbox counts.
    Federation,
    /// Queue occupancy and capacity.
    Queues,
    /// Sixty-second rate windows.
    Rates,
    /// E2EE companion profile counts.
    E2ee,
}

impl StatsSelector {
    /// Every selector in registry order.
    pub const ALL: [Self; 6] = [
        Self::Runtime,
        Self::Storage,
        Self::Federation,
        Self::Queues,
        Self::Rates,
        Self::E2ee,
    ];

    /// Parses the exact uppercase selector token.
    pub fn parse(text: &str) -> Result<Self, AdminError> {
        match text {
            "RUNTIME" => Ok(Self::Runtime),
            "STORAGE" => Ok(Self::Storage),
            "FEDERATION" => Ok(Self::Federation),
            "QUEUES" => Ok(Self::Queues),
            "RATES" => Ok(Self::Rates),
            "E2EE" => Ok(Self::E2ee),
            _ => Err(AdminError::Argument),
        }
    }

    /// Returns the selector token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "RUNTIME",
            Self::Storage => "STORAGE",
            Self::Federation => "FEDERATION",
            Self::Queues => "QUEUES",
            Self::Rates => "RATES",
            Self::E2ee => "E2EE",
        }
    }

    /// Returns the field names in the exact listed order.
    #[must_use]
    pub const fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Runtime => &RUNTIME_FIELDS,
            Self::Storage => &STORAGE_FIELDS,
            Self::Federation => &FEDERATION_FIELDS,
            Self::Queues => &QUEUES_FIELDS,
            Self::Rates => &RATES_FIELDS,
            Self::E2ee => &E2EE_FIELDS,
        }
    }

    /// Returns the `field-count` rendered in the BATCH line.
    #[must_use]
    pub const fn field_count(self) -> usize {
        self.fields().len()
    }
}

/// One complete snapshot: exactly one `u64` per field in listed order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatsValues {
    selector: StatsSelector,
    values: Vec<u64>,
}

impl StatsValues {
    /// Binds values to a selector, requiring exactly one value per field.
    pub fn new(selector: StatsSelector, values: &[u64]) -> Result<Self, AdminError> {
        if values.len() != selector.field_count() {
            return Err(AdminError::Argument);
        }
        if selector == StatsSelector::E2ee {
            Self::check_e2ee(values)?;
        }
        Ok(Self {
            selector,
            values: values.to_vec(),
        })
    }

    /// `enabled` is exactly zero or one, and a disabled profile reports zero
    /// for the other eight fields (spec 4514-4516).
    fn check_e2ee(values: &[u64]) -> Result<(), AdminError> {
        let Some((enabled, rest)) = values.split_first() else {
            return Err(AdminError::Argument);
        };
        match enabled {
            0 if rest.iter().all(|value| *value == 0) => Ok(()),
            1 => Ok(()),
            _ => Err(AdminError::Argument),
        }
    }

    /// Returns the selector.
    #[must_use]
    pub const fn selector(&self) -> StatsSelector {
        self.selector
    }

    /// Returns the values in field order.
    #[must_use]
    pub fn values(&self) -> &[u64] {
        &self.values
    }
}

/// Checked sum of the current one-second bucket and its predecessors,
/// at most sixty buckets (spec 4511-4513).
pub fn checked_window_sum(buckets: &[u64]) -> Result<u64, AdminError> {
    if buckets.len() > STATS_SIXTY_SECOND_BUCKETS {
        return Err(AdminError::Limit);
    }
    buckets
        .iter()
        .try_fold(0_u64, |total, bucket| total.checked_add(*bucket))
        .ok_or(AdminError::Overflow)
}

/// Renders the exact three-part STATS batch (spec 4474-4478).
#[must_use]
pub fn render_stats_batch(
    batch_id: &[u8; 16],
    sample_unix_seconds: u64,
    values: &StatsValues,
) -> Vec<String> {
    let id = encode_base64url(batch_id);
    let selector = values.selector.as_str();
    let mut lines = Vec::with_capacity(values.values.len() + 2);
    lines.push(format!(
        "BATCH +{id} agenc.ag/stats {selector} {} {sample_unix_seconds}",
        values.selector.field_count()
    ));
    for (name, value) in values.selector.fields().iter().zip(&values.values) {
        lines.push(format!(
            "@batch={id} NOTE STATS VALUE {selector} {name} {value} :Statistic value"
        ));
    }
    lines.push(format!("BATCH -{id}"));
    lines
}

/// The exact collection-failure reply (spec 4471-4472).
#[must_use]
pub fn render_stats_unavailable(selector: StatsSelector) -> String {
    format!(
        "FAIL STATS UNAVAILABLE {} :Statistics unavailable",
        selector.as_str()
    )
}

/// The exact observed-event commit-failure reply (spec 4568-4569).
#[must_use]
pub fn render_stats_storage_unavailable(selector: StatsSelector) -> String {
    format!(
        "FAIL STATS STORAGE_UNAVAILABLE {} :Administrative audit unavailable",
        selector.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::{
        StatsSelector, StatsValues, checked_window_sum, render_stats_batch,
        render_stats_storage_unavailable, render_stats_unavailable,
    };
    use crate::AdminError;

    #[test]
    fn selectors_have_the_listed_counts_and_unique_ordered_fields() -> Result<(), AdminError> {
        let expected = [
            (StatsSelector::Runtime, "RUNTIME", 9),
            (StatsSelector::Storage, "STORAGE", 14),
            (StatsSelector::Federation, "FEDERATION", 7),
            (StatsSelector::Queues, "QUEUES", 10),
            (StatsSelector::Rates, "RATES", 8),
            (StatsSelector::E2ee, "E2EE", 9),
        ];
        for ((selector, token, count), registry) in expected.into_iter().zip(StatsSelector::ALL) {
            assert_eq!(selector, registry);
            assert_eq!(StatsSelector::parse(token)?, selector);
            assert_eq!(selector.as_str(), token);
            assert_eq!(selector.field_count(), count);
            assert_eq!(selector.fields().len(), selector.field_count());
            let mut names = selector.fields().to_vec();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), count, "{token} has a duplicate field");
        }
        assert_eq!(StatsSelector::parse("runtime"), Err(AdminError::Argument));
        assert_eq!(StatsSelector::parse(""), Err(AdminError::Argument));
        assert_eq!(
            StatsSelector::Rates.fields().first().copied(),
            Some("client_commands_accepted_60s")
        );
        assert_eq!(
            StatsSelector::Storage.fields().last().copied(),
            Some("pending_storage_constructions")
        );
        Ok(())
    }

    #[test]
    fn batches_render_exactly_and_reject_wrong_shapes() -> Result<(), AdminError> {
        let values = StatsValues::new(StatsSelector::Federation, &[1, 2, 3, 4, 5, 6, 7])?;
        let lines = render_stats_batch(&[0; 16], 1_700_000_000, &values);
        assert_eq!(lines.len(), 9);
        assert_eq!(
            lines.first().map(String::as_str),
            Some("BATCH +AAAAAAAAAAAAAAAAAAAAAA agenc.ag/stats FEDERATION 7 1700000000")
        );
        assert_eq!(
            lines.get(1).map(String::as_str),
            Some(
                "@batch=AAAAAAAAAAAAAAAAAAAAAA NOTE STATS VALUE FEDERATION configured_peers 1 :Statistic value"
            )
        );
        assert_eq!(
            lines.get(7).map(String::as_str),
            Some(
                "@batch=AAAAAAAAAAAAAAAAAAAAAA NOTE STATS VALUE FEDERATION open_cross_profile_barriers 7 :Statistic value"
            )
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some("BATCH -AAAAAAAAAAAAAAAAAAAAAA")
        );
        assert_eq!(values.selector(), StatsSelector::Federation);
        assert_eq!(values.values().len(), 7);

        assert_eq!(
            StatsValues::new(StatsSelector::Federation, &[1; 6]),
            Err(AdminError::Argument)
        );
        assert_eq!(
            StatsValues::new(StatsSelector::Federation, &[1; 8]),
            Err(AdminError::Argument)
        );
        assert!(StatsValues::new(StatsSelector::E2ee, &[0; 9]).is_ok());
        assert!(StatsValues::new(StatsSelector::E2ee, &[1, 5, 0, 0, 0, 0, 0, 0, 0]).is_ok());
        assert_eq!(
            StatsValues::new(StatsSelector::E2ee, &[0, 5, 0, 0, 0, 0, 0, 0, 0]),
            Err(AdminError::Argument)
        );
        assert_eq!(
            StatsValues::new(StatsSelector::E2ee, &[2, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(AdminError::Argument)
        );
        assert_eq!(
            render_stats_unavailable(StatsSelector::Queues),
            "FAIL STATS UNAVAILABLE QUEUES :Statistics unavailable"
        );
        assert_eq!(
            render_stats_storage_unavailable(StatsSelector::Rates),
            "FAIL STATS STORAGE_UNAVAILABLE RATES :Administrative audit unavailable"
        );
        Ok(())
    }

    #[test]
    fn window_sums_are_checked_and_bounded() {
        assert_eq!(checked_window_sum(&[]), Ok(0));
        assert_eq!(checked_window_sum(&[1; 60]), Ok(60));
        assert_eq!(checked_window_sum(&[1; 61]), Err(AdminError::Limit));
        assert_eq!(
            checked_window_sum(&[u64::MAX, 1]),
            Err(AdminError::Overflow)
        );
    }
}
