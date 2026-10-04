//! The `[limits]` table and its closed `[limits.rate.<name>]` tables (spec C.6 9087-9177).

use toml::Table;

use crate::bounds::{RATE_BURST, RATE_REFILL_SECONDS, RATE_REFILL_TOKENS};
use crate::document::{check_keys, optional_unsigned, table as sub_table, unsigned};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::scalar::Bound;

/// Every resource limit key in registry order (spec 9091-9118).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum LimitKey {
    /// `client_connections`.
    ClientConnections,
    /// `tls_handshakes`.
    TlsHandshakes,
    /// `direct_connections_per_address`.
    DirectConnectionsPerAddress,
    /// `sessions_per_account`.
    SessionsPerAccount,
    /// `channels_per_session`.
    ChannelsPerSession,
    /// `members_per_channel`.
    MembersPerChannel,
    /// `global_channels`.
    GlobalChannels,
    /// `local_channels`.
    LocalChannels,
    /// `invites_per_channel`.
    InvitesPerChannel,
    /// `invites_per_principal`.
    InvitesPerPrincipal,
    /// `invites_global`.
    InvitesGlobal,
    /// `requests_per_connection`.
    RequestsPerConnection,
    /// `response_batches_per_connection`.
    ResponseBatchesPerConnection,
    /// `response_batch_bytes`.
    ResponseBatchBytes,
    /// `client_output_bytes`.
    ClientOutputBytes,
    /// `client_control_output_bytes`.
    ClientControlOutputBytes,
    /// `federation_output_bytes`.
    FederationOutputBytes,
    /// `base_outbox_bytes_per_edge`.
    BaseOutboxBytesPerEdge,
    /// `base_outbox_objects_per_edge`.
    BaseOutboxObjectsPerEdge,
    /// `parsed_arena_bytes`.
    ParsedArenaBytes,
    /// `channel_key_jobs`.
    ChannelKeyJobs,
    /// `opaque_jobs`.
    OpaqueJobs,
    /// `query_snapshot_rows`.
    QuerySnapshotRows,
    /// `query_snapshots_per_session`.
    QuerySnapshotsPerSession,
    /// `query_snapshot_rows_global`.
    QuerySnapshotRowsGlobal,
    /// `query_snapshot_bytes_global`.
    QuerySnapshotBytesGlobal,
}

/// Number of resource limit keys.
pub const LIMIT_COUNT: usize = 26;

/// One resource limit row: key, name, and inclusive bounds with default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitRow {
    /// The typed key.
    pub key: LimitKey,
    /// The configuration key name.
    pub name: &'static str,
    /// Minimum, default, maximum.
    pub bound: Bound,
}

/// The exact C.6 resource table (spec 9091-9118).
pub const LIMIT_ROWS: [LimitRow; LIMIT_COUNT] = [
    row(
        LimitKey::ClientConnections,
        "client_connections",
        1,
        50_000,
        250_000,
    ),
    row(LimitKey::TlsHandshakes, "tls_handshakes", 1, 1_024, 16_384),
    row(
        LimitKey::DirectConnectionsPerAddress,
        "direct_connections_per_address",
        1,
        16,
        256,
    ),
    row(
        LimitKey::SessionsPerAccount,
        "sessions_per_account",
        1,
        8,
        32,
    ),
    row(
        LimitKey::ChannelsPerSession,
        "channels_per_session",
        1,
        64,
        256,
    ),
    row(
        LimitKey::MembersPerChannel,
        "members_per_channel",
        1,
        4_096,
        65_535,
    ),
    row(
        LimitKey::GlobalChannels,
        "global_channels",
        1,
        100_000,
        1_000_000,
    ),
    row(
        LimitKey::LocalChannels,
        "local_channels",
        1,
        10_000,
        100_000,
    ),
    row(
        LimitKey::InvitesPerChannel,
        "invites_per_channel",
        1,
        256,
        4_096,
    ),
    row(
        LimitKey::InvitesPerPrincipal,
        "invites_per_principal",
        1,
        32,
        256,
    ),
    row(
        LimitKey::InvitesGlobal,
        "invites_global",
        1,
        100_000,
        1_000_000,
    ),
    row(
        LimitKey::RequestsPerConnection,
        "requests_per_connection",
        1,
        32,
        128,
    ),
    row(
        LimitKey::ResponseBatchesPerConnection,
        "response_batches_per_connection",
        1,
        4,
        16,
    ),
    row(
        LimitKey::ResponseBatchBytes,
        "response_batch_bytes",
        65_536,
        65_536,
        262_144,
    ),
    row(
        LimitKey::ClientOutputBytes,
        "client_output_bytes",
        262_144,
        1_048_576,
        4_194_304,
    ),
    row(
        LimitKey::ClientControlOutputBytes,
        "client_control_output_bytes",
        16_384,
        65_536,
        262_144,
    ),
    row(
        LimitKey::FederationOutputBytes,
        "federation_output_bytes",
        8_388_608,
        16_777_216,
        67_108_864,
    ),
    row(
        LimitKey::BaseOutboxBytesPerEdge,
        "base_outbox_bytes_per_edge",
        16_777_216,
        268_435_456,
        1_073_741_824,
    ),
    row(
        LimitKey::BaseOutboxObjectsPerEdge,
        "base_outbox_objects_per_edge",
        1_024,
        65_536,
        262_144,
    ),
    row(
        LimitKey::ParsedArenaBytes,
        "parsed_arena_bytes",
        32_768,
        32_768,
        131_072,
    ),
    row(LimitKey::ChannelKeyJobs, "channel_key_jobs", 1, 4, 64),
    row(LimitKey::OpaqueJobs, "opaque_jobs", 1, 8, 128),
    row(
        LimitKey::QuerySnapshotRows,
        "query_snapshot_rows",
        512,
        10_000,
        100_000,
    ),
    row(
        LimitKey::QuerySnapshotsPerSession,
        "query_snapshots_per_session",
        1,
        4,
        16,
    ),
    row(
        LimitKey::QuerySnapshotRowsGlobal,
        "query_snapshot_rows_global",
        512,
        100_000,
        1_000_000,
    ),
    row(
        LimitKey::QuerySnapshotBytesGlobal,
        "query_snapshot_bytes_global",
        1_048_576,
        67_108_864,
        536_870_912,
    ),
];

const fn row(
    key: LimitKey,
    name: &'static str,
    minimum: u64,
    default: u64,
    maximum: u64,
) -> LimitRow {
    LimitRow {
        key,
        name,
        bound: Bound::new(minimum, default, maximum),
    }
}

/// The resolved resource limit values indexed by [`LimitKey`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitValues([u64; LIMIT_COUNT]);

impl LimitValues {
    /// Returns one resolved limit.
    #[must_use]
    pub fn get(&self, key: LimitKey) -> u64 {
        self.0.get(key as usize).copied().unwrap_or(0)
    }

    /// Builds the default table.
    #[must_use]
    pub fn defaults() -> Self {
        let mut values = [0_u64; LIMIT_COUNT];
        for (slot, row) in values.iter_mut().zip(LIMIT_ROWS.iter()) {
            *slot = row.bound.default;
        }
        Self(values)
    }

    /// Returns a copy with one key replaced, for reload diff construction and tests.
    #[must_use]
    pub fn with(mut self, key: LimitKey, value: u64) -> Self {
        if let Some(slot) = self.0.get_mut(key as usize) {
            *slot = value;
        }
        self
    }
}

/// Every rate-limit key in registry order (spec 9148-9159).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum RateKey {
    /// `new_direct`.
    NewDirect,
    /// `new_onion`.
    NewOnion,
    /// `tls_handshake`.
    TlsHandshake,
    /// `preauth_command`.
    PreauthCommand,
    /// `registered_command`.
    RegisteredCommand,
    /// `guest_message`.
    GuestMessage,
    /// `account_message`.
    AccountMessage,
    /// `channel_message`.
    ChannelMessage,
    /// `expensive_query`.
    ExpensiveQuery,
    /// `channel_key_attempt`.
    ChannelKeyAttempt,
    /// `account_creation`.
    AccountCreation,
    /// `opaque_attempt`.
    OpaqueAttempt,
}

/// Number of rate-limit keys.
pub const RATE_COUNT: usize = 12;

/// One rate specification: `refill_tokens` per `refill_seconds` with `burst`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RateSpec {
    /// Tokens refilled per interval.
    pub refill_tokens: u64,
    /// Refill interval in seconds.
    pub refill_seconds: u64,
    /// Bucket capacity.
    pub burst: u64,
}

impl RateSpec {
    /// Builds one specification.
    #[must_use]
    pub const fn new(refill_tokens: u64, refill_seconds: u64, burst: u64) -> Self {
        Self {
            refill_tokens,
            refill_seconds,
            burst,
        }
    }

    /// Returns whether this rate is no faster than `hard` by checked cross
    /// multiplication and no burstier (spec 9145-9146).
    pub fn within(self, hard: Self) -> Result<bool, ConfigError> {
        let lhs = self
            .refill_tokens
            .checked_mul(hard.refill_seconds)
            .ok_or(ConfigError::Overflow)?;
        let rhs = hard
            .refill_tokens
            .checked_mul(self.refill_seconds)
            .ok_or(ConfigError::Overflow)?;
        Ok(lhs <= rhs && self.burst <= hard.burst)
    }
}

/// One rate row: key, name, default, and hard ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateRow {
    /// The typed key.
    pub key: RateKey,
    /// The configuration table name.
    pub name: &'static str,
    /// The default rate.
    pub default: RateSpec,
    /// The hard ceiling.
    pub hard: RateSpec,
}

/// The exact C.6 rate table (spec 9148-9159).
pub const RATE_ROWS: [RateRow; RATE_COUNT] = [
    rate(RateKey::NewDirect, "new_direct", (1, 1, 8), (16, 1, 64)),
    rate(RateKey::NewOnion, "new_onion", (8, 1, 32), (64, 1, 256)),
    rate(
        RateKey::TlsHandshake,
        "tls_handshake",
        (4, 1, 16),
        (32, 1, 128),
    ),
    rate(
        RateKey::PreauthCommand,
        "preauth_command",
        (1, 1, 24),
        (10, 1, 50),
    ),
    rate(
        RateKey::RegisteredCommand,
        "registered_command",
        (4, 1, 20),
        (40, 1, 200),
    ),
    rate(
        RateKey::GuestMessage,
        "guest_message",
        (1, 2, 4),
        (5, 1, 20),
    ),
    rate(
        RateKey::AccountMessage,
        "account_message",
        (2, 1, 10),
        (20, 1, 100),
    ),
    rate(
        RateKey::ChannelMessage,
        "channel_message",
        (10, 1, 40),
        (100, 1, 400),
    ),
    rate(
        RateKey::ExpensiveQuery,
        "expensive_query",
        (1, 5, 2),
        (2, 1, 10),
    ),
    rate(
        RateKey::ChannelKeyAttempt,
        "channel_key_attempt",
        (1, 30, 4),
        (1, 1, 20),
    ),
    rate(
        RateKey::AccountCreation,
        "account_creation",
        (1, 3_600, 2),
        (10, 3_600, 10),
    ),
    rate(
        RateKey::OpaqueAttempt,
        "opaque_attempt",
        (1, 180, 5),
        (1, 10, 10),
    ),
];

const fn rate(
    key: RateKey,
    name: &'static str,
    default: (u64, u64, u64),
    hard: (u64, u64, u64),
) -> RateRow {
    RateRow {
        key,
        name,
        default: RateSpec::new(default.0, default.1, default.2),
        hard: RateSpec::new(hard.0, hard.1, hard.2),
    }
}

/// The resolved rate table indexed by [`RateKey`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateTable([RateSpec; RATE_COUNT]);

impl RateTable {
    /// Returns one resolved rate.
    #[must_use]
    pub fn get(&self, key: RateKey) -> RateSpec {
        self.0
            .get(key as usize)
            .copied()
            .unwrap_or(RateSpec::new(1, 1, 1))
    }

    /// Builds the default table.
    #[must_use]
    pub fn defaults() -> Self {
        let mut values = [RateSpec::new(1, 1, 1); RATE_COUNT];
        for (slot, row) in values.iter_mut().zip(RATE_ROWS.iter()) {
            *slot = row.default;
        }
        Self(values)
    }

    /// Returns a copy with one key replaced.
    #[must_use]
    pub fn with(mut self, key: RateKey, spec: RateSpec) -> Self {
        if let Some(slot) = self.0.get_mut(key as usize) {
            *slot = spec;
        }
        self
    }
}

/// The validated `[limits]` table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitsConfig {
    /// Resource limits.
    pub values: LimitValues,
    /// Rate limits.
    pub rates: RateTable,
}

pub(crate) const LIMIT_KEYS: &[&str] = &[
    "base_outbox_bytes_per_edge",
    "base_outbox_objects_per_edge",
    "channel_key_jobs",
    "channels_per_session",
    "client_connections",
    "client_control_output_bytes",
    "client_output_bytes",
    "direct_connections_per_address",
    "federation_output_bytes",
    "global_channels",
    "invites_global",
    "invites_per_channel",
    "invites_per_principal",
    "local_channels",
    "members_per_channel",
    "opaque_jobs",
    "parsed_arena_bytes",
    "query_snapshot_bytes_global",
    "query_snapshot_rows",
    "query_snapshot_rows_global",
    "query_snapshots_per_session",
    "rate",
    "requests_per_connection",
    "response_batch_bytes",
    "response_batches_per_connection",
    "sessions_per_account",
    "tls_handshakes",
];
pub(crate) const RATE_NAMES: &[&str] = &[
    "account_creation",
    "account_message",
    "channel_key_attempt",
    "channel_message",
    "expensive_query",
    "guest_message",
    "new_direct",
    "new_onion",
    "opaque_attempt",
    "preauth_command",
    "registered_command",
    "tls_handshake",
];
pub(crate) const RATE_KEYS: &[&str] = &["burst", "refill_seconds", "refill_tokens"];

const TABLE: &str = "limits";
const RATE_TABLE: &str = "limits.rate";

pub(crate) fn parse(table: &Table, sink: &mut IssueSink) -> Option<LimitsConfig> {
    sink.field(SchemaKey::new(TABLE, ""), check_keys(table, LIMIT_KEYS))?;
    let mut values = LimitValues::defaults();
    let mut complete = true;
    for row in &LIMIT_ROWS {
        let resolved = sink.field(
            SchemaKey::new(TABLE, row.name),
            optional_unsigned(table, row.name).and_then(|value| row.bound.resolve(value)),
        );
        match resolved {
            Some(value) => values = values.with(row.key, value),
            None => complete = false,
        }
    }
    let rates = parse_rates(table, sink);
    if !complete {
        return None;
    }
    Some(LimitsConfig {
        values,
        rates: rates?,
    })
}

fn parse_rates(table: &Table, sink: &mut IssueSink) -> Option<RateTable> {
    let rate_table = match table.get("rate") {
        None => return Some(RateTable::defaults()),
        Some(_) => sink.field(SchemaKey::new(TABLE, "rate"), sub_table(table, "rate"))?,
    };
    sink.field(
        SchemaKey::new(RATE_TABLE, ""),
        check_keys(rate_table, RATE_NAMES),
    )?;
    let mut rates = RateTable::defaults();
    let mut complete = true;
    for row in &RATE_ROWS {
        let Some(_) = rate_table.get(row.name) else {
            continue;
        };
        match sink.field(
            SchemaKey::new(RATE_TABLE, row.name),
            parse_rate(rate_table, row),
        ) {
            Some(spec) => rates = rates.with(row.key, spec),
            None => complete = false,
        }
    }
    complete.then_some(rates)
}

fn parse_rate(rate_table: &Table, row: &RateRow) -> Result<RateSpec, ConfigError> {
    let entry = sub_table(rate_table, row.name)?;
    // Each rate table carries exactly the three positive fields (spec 9143-9144).
    crate::document::require_exact_keys(entry, RATE_KEYS)?;
    let spec = RateSpec::new(
        RATE_REFILL_TOKENS.resolve(Some(unsigned(entry, "refill_tokens")?))?,
        RATE_REFILL_SECONDS.resolve(Some(unsigned(entry, "refill_seconds")?))?,
        RATE_BURST.resolve(Some(unsigned(entry, "burst")?))?,
    );
    if !spec.within(row.hard)? {
        return Err(ConfigError::InvalidValue);
    }
    Ok(spec)
}
